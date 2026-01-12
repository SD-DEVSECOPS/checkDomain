$InputCsv  = "domains.csv"
$DateStamp = Get-Date -Format "MM-dd"
$RandomCode = Get-Random -Minimum 100000 -Maximum 999999
$OutputFolder = ".\outputs\$DateStamp" + "_$RandomCode"
$ComparedFolder = ".\compared"

# Create directories if they don't exist
if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

if (-not (Test-Path $ComparedFolder)) {
    New-Item -Path $ComparedFolder -ItemType Directory -Force | Out-Null
}

# Output file path
$OutputCsv = "$OutputFolder\domain_inventory_$DateStamp`_$RandomCode.csv"

# CHECK FOR INPUT CSV FIRST
if (-not (Test-Path $InputCsv)) { 
    Write-Host "ERROR: domains.csv not found!" -ForegroundColor Red
    exit 1
}

# Load domains
Write-Host "Reading domains from: $InputCsv" -ForegroundColor Cyan

try {
    # Import CSV
    $domains = Import-Csv $InputCsv -ErrorAction Stop
    
    Write-Host "CSV imported successfully. Found $($domains.Count) rows." -ForegroundColor Green
    
    # Check column names
    $columns = $domains | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
    
    # Look for domain column
    $domainColumn = $null
    foreach ($col in $columns) {
        if ($col -match "domain|host|url|website") {
            $domainColumn = $col
            break
        }
    }
    
    # If not found, use first column
    if (-not $domainColumn -and $columns.Count -gt 0) {
        $domainColumn = $columns[0]
    }
    
    if (-not $domainColumn) {
        Write-Host "ERROR: No suitable column found in CSV!" -ForegroundColor Red
        exit 1
    }
    
    # Extract domains
    $domainList = @()
    foreach ($row in $domains) {
        $domainName = $row.$domainColumn
        if ($domainName -and $domainName.ToString().Trim() -ne "") {
            $cleanDomain = $domainName.ToString().Trim()
            if ($cleanDomain -match "^https?://(.+)$") {
                $cleanDomain = $matches[1]
            }
            $domainList += [PSCustomObject]@{
                Domain = $cleanDomain
            }
        }
    }
    
    $total = $domainList.Count
    
    if ($total -eq 0) {
        Write-Host "ERROR: No valid domains found in CSV!" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Found $total valid domains to process." -ForegroundColor Green
    
} catch {
    Write-Host "ERROR: Cannot read domains.csv!" -ForegroundColor Red
    exit 1
}

Write-Host "`nProcessing $total domains..." -ForegroundColor Cyan
Write-Host "Output: $OutputCsv" -ForegroundColor Cyan

# CDN patterns
$cdnPatterns = @{
    "Fastly" = @("fastly", "54113", "SKYCA")
    "Cloudflare" = @("cloudflare", "13335", "CLOUDFLARENET")
    "Akamai" = @("akamai", "20940", "AKAMAI")
    "AWS" = @("amazon", "aws", "16509", "AMAZON", "cloudfront")
    "Google" = @("google", "15169", "GOOGLE")
    "Microsoft" = @("microsoft", "azure", "8075", "MSFT")
}

# ---------------------------------------------------------------------------
# FIXED: Better base-domain detection for deep subdomains (solar.educacao... etc)
# ---------------------------------------------------------------------------
function Get-BaseDomain {
    param([string]$domain)

    # Clean domain
    $domain = $domain.Trim()
    $domain = $domain -replace '^https?://', ''
    $domain = $domain -replace '/.*$', ''
    $domain = $domain.Split(':')[0]  # Remove port

    if ([string]::IsNullOrWhiteSpace($domain)) { return $domain }

    $parts = $domain.Split('.') | Where-Object { $_ -and $_.Trim() -ne "" }
    if ($parts.Count -le 2) { return $domain }

    function Test-Zone {
        param([string]$name)
        try {
            $ns = Resolve-DnsName -Name $name -Type NS -ErrorAction SilentlyContinue
            if ($ns) { return $true }
        } catch {}
        try {
            $soa = Resolve-DnsName -Name $name -Type SOA -ErrorAction SilentlyContinue
            if ($soa) { return $true }
        } catch {}
        return $false
    }

    $maxParts = [Math]::Min(6, $parts.Count)
    for ($i = 2; $i -le $maxParts; $i++) {
        $candidate = ($parts[-$i..-1] -join '.')
        if ($candidate -match "^\d+\.\d+\.\d+\.\d+$") { continue }
        if ($candidate.Length -lt 4) { continue }

        if (Test-Zone $candidate) { return $candidate }
    }

    return ($parts[-2..-1] -join '.')
}

function Get-IPGeolocation {
    param([string]$ipAddress)
    
    try {
        $geo = Invoke-RestMethod -Uri "https://ipinfo.io/$ipAddress/json" -TimeoutSec 3 -ErrorAction SilentlyContinue
        if ($geo -and $geo.country) {
            return @{
                Country = $geo.country
                City = $geo.city
                Region = $geo.region
                ISP = $geo.org
                Location = "$($geo.city), $($geo.region), $($geo.country)"
            }
        }
        return $null
    } catch {
        return $null
    }
}

function Get-IPWhoisData {
    param([string]$ipAddress)
    
    try {
        $ipwhois = Invoke-RestMethod -Uri "https://ipwhois.app/json/$ipAddress" -TimeoutSec 3 -ErrorAction SilentlyContinue
        if ($ipwhois -and $ipwhois.org) {
            return @{
                Organization = $ipwhois.org
                Handle = $ipwhois.asn
                ASN = $ipwhois.asn
                ISP = $ipwhois.isp
                Country = $ipwhois.country
            }
        }
        return $null
    } catch {
        return $null
    }
}

function Detect-CDN {
    param(
        [string]$organization,
        [string]$handle,
        [string]$asn,
        [string]$isp
    )
    
    if (-not $organization) { return "None" }
    
    $searchString = ($organization + " " + $handle + " " + $asn + " " + $isp).ToLower()
    
    foreach ($cdn in $cdnPatterns.Keys) {
        foreach ($pattern in $cdnPatterns[$cdn]) {
            if ($searchString -match [regex]::Escape($pattern.ToLower())) {
                return $cdn
            }
        }
    }
    
    return "None"
}

# ---------------------------------------------------------------------------
# FIXED: DNS registrar detection now checks BOTH host + base domain
# ---------------------------------------------------------------------------
function Get-RegistrarFromDNS {
    param([string]$domain)
    
    try {
        $domain = $domain.Trim()
        $domain = $domain -replace '^https?://', ''
        $domain = $domain -replace '/.*$', ''
        $domain = $domain.Split(':')[0]

        if ([string]::IsNullOrWhiteSpace($domain)) { return "Unknown" }

        $base = Get-BaseDomain $domain

        $namesToTry = @($domain, $base) | Where-Object { $_ -and $_.Trim() -ne "" } | Select-Object -Unique

        $registrarKeywords = @{
            "markmonitor" = "MarkMonitor"
            "cloudflare" = "Cloudflare"
            "godaddy" = "GoDaddy"
            "namecheap" = "Namecheap"
            "amazonaws" = "Amazon Route53"
            "route53" = "Amazon Route53"
            "googledomains" = "Google Domains"
            "google" = "Google Domains"
            "cscdns" = "CSC"
            "csc" = "CSC"
            "enom" = "eNom"
            "tucows" = "Tucows"
            "networksolutions" = "Network Solutions"
            "dynadot" = "Dynadot"
            "porkbun" = "Porkbun"
            "name.com" = "Name.com"
            "hostinger" = "Hostinger"
            "bluehost" = "Bluehost"
        }

        foreach ($name in $namesToTry) {
            $records = @()

            try { $r = Resolve-DnsName -Name $name -Type SOA -ErrorAction SilentlyContinue; if ($r) { $records += $r } } catch {}
            try { $r = Resolve-DnsName -Name $name -Type NS  -ErrorAction SilentlyContinue; if ($r) { $records += $r } } catch {}
            try { $r = Resolve-DnsName -Name $name -Type MX  -ErrorAction SilentlyContinue; if ($r) { $records += $r } } catch {}

            if (-not $records -or $records.Count -eq 0) { continue }

            foreach ($record in $records) {
                foreach ($prop in @("PrimaryServer","NameAdministrator","NameHost","NameExchange","MailExchange")) {
                    $val = $record.$prop
                    if ($val) {
                        $low = $val.ToString().ToLowerInvariant()
                        foreach ($k in $registrarKeywords.Keys) {
                            if ($low -match $k) { return $registrarKeywords[$k] }
                        }
                    }
                }
            }

            $recordString = ($records | Out-String).ToLowerInvariant()
            foreach ($k in $registrarKeywords.Keys) {
                if ($recordString -match $k) { return $registrarKeywords[$k] }
            }
        }
        
    } catch {
        # Silent fail
    }
    
    return "Unknown"
}

function Get-DomainRegistrar {
    param([string]$domain)
    
    # Clean the domain first
    $domain = $domain.Trim()
    $domain = $domain -replace '^https?://', ''
    $domain = $domain -replace '/.*$', ''
    
    # METHOD 1: Try DNS-based detection first (now tries host + base)
    $dnsRegistrar = Get-RegistrarFromDNS -domain $domain
    if ($dnsRegistrar -ne "Unknown") {
        return $dnsRegistrar
    }
    
    # METHOD 2: Try RDAP with base domain
    $baseDomain = Get-BaseDomain -domain $domain
    try {
        $rdap = Invoke-RestMethod -Uri "https://rdap.org/domain/$baseDomain" -TimeoutSec 5 -ErrorAction SilentlyContinue
        
        if ($rdap -and $rdap.entities) {
            $registrarEntity = $rdap.entities | Where-Object { 
                $_.roles -contains "registrar" 
            } | Select-Object -First 1
            
            if ($registrarEntity) {
                if ($registrarEntity.vcardArray -and $registrarEntity.vcardArray[1]) {
                    foreach ($vcard in $registrarEntity.vcardArray[1]) {
                        if ($vcard[0] -eq "fn" -or $vcard[0] -eq "org") {
                            return $vcard[3].Trim()
                        }
                    }
                }
                return $registrarEntity.name.Trim()
            }
        }
    } catch {
        # RDAP failed
    }
    
    # METHOD 3: Try system WHOIS if available
    if (Get-Command whois -ErrorAction SilentlyContinue) {
        try {
            $whoisOutput = whois $baseDomain 2>&1 | Out-String
            
            $patterns = @(
                "Registrar:\s*(.+)",
                "Registrar\s+Name:\s*(.+)",
                "Sponsoring\s+Registrar:\s*(.+)",
                "Registration\s+Service\s+Provider:\s*(.+)",
                "Registrar\s+Organization:\s*(.+)"
            )
            
            foreach ($pattern in $patterns) {
                if ($whoisOutput -match $pattern) {
                    $found = $matches[1].Trim()
                    if ($found -and $found -ne "" -and $found -notmatch "^\d+$") {
                        $found = $found -replace '\(http[^)]+\)', ''
                        $found = $found -replace 'https?://[^\s]+', ''
                        $found = $found.Trim()
                        return $found
                    }
                }
            }
        } catch {}
    }
    
    # METHOD 4: last try NS patterns (use base domain, not host)
    $commonRegistrars = @{
        "markmonitor" = "MarkMonitor"
        "cloudflare" = "Cloudflare"
        "godaddy" = "GoDaddy"
        "namecheap" = "Namecheap"
        "amazonaws" = "Amazon Route53"
        "route53" = "Amazon Route53"
        "google" = "Google Domains"
        "cscdns" = "CSC"
        "enom" = "eNom"
        "tucows" = "Tucows"
        "networksolutions" = "Network Solutions"
        "dynadot" = "Dynadot"
        "porkbun" = "Porkbun"
        "name.com" = "Name.com"
        "hostinger" = "Hostinger"
        "bluehost" = "Bluehost"
    }
    
    try {
        $nsRecords = Resolve-DnsName -Name $baseDomain -Type NS -ErrorAction SilentlyContinue
        if ($nsRecords) {
            foreach ($record in $nsRecords) {
                $ns = $record.NameHost.ToLower()
                foreach ($key in $commonRegistrars.Keys) {
                    if ($ns -match $key) { return $commonRegistrars[$key] }
                }
            }
        }
    } catch {}
    
    return "Unknown"
}

function Get-DomainExpiryDate {
    param([string]$domain)
    
    # Get base domain for expiry checking
    $baseDomain = Get-BaseDomain -domain $domain
    
    try {
        $rdap = Invoke-RestMethod -Uri "https://rdap.org/domain/$baseDomain" -TimeoutSec 5 -ErrorAction SilentlyContinue
        
        if ($rdap -and $rdap.events) {
            $expiryEvent = $rdap.events | Where-Object { $_.eventAction -eq "expiration" } | Select-Object -First 1
            if ($expiryEvent -and $expiryEvent.eventDate) {
                try {
                    $expiryDate = [DateTime]::Parse($expiryEvent.eventDate)
                    return @{
                        ExpiryDate = $expiryDate
                        DaysUntilExpiry = ($expiryDate - (Get-Date)).Days
                        Status = "Active"
                    }
                } catch {
                    return @{
                        ExpiryDate = $expiryEvent.eventDate
                        DaysUntilExpiry = "N/A"
                        Status = "Active"
                    }
                }
            }
        }
        
        try {
            $whois = Invoke-RestMethod -Uri "https://whois.domaintools.com/$baseDomain" -TimeoutSec 5 -ErrorAction SilentlyContinue
            
            if ($whois -is [string]) {
                $patterns = @(
                    "Expir.*?:(.*?)(?:\n|$)",
                    "Expir.*?Date:(.*?)(?:\n|$)",
                    "Registry Expir.*?:(.*?)(?:\n|$)",
                    "Expiration Date:(.*?)(?:\n|$)",
                    "Expires On:(.*?)(?:\n|$)"
                )
                
                foreach ($pattern in $patterns) {
                    if ($whois -match $pattern) {
                        $dateStr = $matches[1].Trim()
                        try {
                            $expiryDate = [DateTime]::Parse($dateStr)
                            return @{
                                ExpiryDate = $expiryDate
                                DaysUntilExpiry = ($expiryDate - (Get-Date)).Days
                                Status = "Active"
                            }
                        } catch {
                            $formats = @(
                                "yyyy-MM-dd",
                                "dd/MM/yyyy",
                                "MM/dd/yyyy",
                                "yyyy/MM/dd",
                                "dd-MMM-yyyy",
                                "d-MMM-yyyy",
                                "yyyy-MM-ddTHH:mm:ssZ",
                                "yyyy-MM-ddTHH:mm:ss.fffZ"
                            )
                            
                            foreach ($format in $formats) {
                                try {
                                    $expiryDate = [DateTime]::ParseExact($dateStr, $format, [System.Globalization.CultureInfo]::InvariantCulture)
                                    return @{
                                        ExpiryDate = $expiryDate
                                        DaysUntilExpiry = ($expiryDate - (Get-Date)).Days
                                        Status = "Active"
                                    }
                                } catch { continue }
                            }
                        }
                    }
                }
            }
        } catch {}
        
        try {
            if (Get-Command whois -ErrorAction SilentlyContinue) {
                $whoisOutput = whois $baseDomain
                if ($whoisOutput -match "Expir.*?Date:\s*(.+)$") {
                    $dateStr = $matches[1].Trim()
                    try {
                        $expiryDate = [DateTime]::Parse($dateStr)
                        return @{
                            ExpiryDate = $expiryDate
                            DaysUntilExpiry = ($expiryDate - (Get-Date)).Days
                            Status = "Active"
                        }
                    } catch {
                        return @{
                            ExpiryDate = $dateStr
                            DaysUntilExpiry = "N/A"
                            Status = "Active"
                        }
                    }
                }
            }
        } catch {}
        
        return @{
            ExpiryDate = "N/A"
            DaysUntilExpiry = "N/A"
            Status = "Unknown"
        }
        
    } catch {
        return @{
            ExpiryDate = "Error"
            DaysUntilExpiry = "N/A"
            Status = "Error"
        }
    }
}

function Test-HTTPSFirst {
    param([string]$domain)
    
    $httpsUrl = "https://$domain"
    $httpUrl = "http://$domain"
    
    $httpsStatus = "No Response"
    $httpStatus = "Not Attempted"
    $protocol = "https"
    $finalUrl = $httpsUrl
    
    try {
        $response = Invoke-WebRequest -Uri $httpsUrl -Method Head -TimeoutSec 3 -ErrorAction Stop
        $httpsStatus = $response.StatusCode
        $protocol = "https"
        $finalUrl = $httpsUrl
        
        return @{
            FinalURL = $finalUrl
            StatusCode = $httpsStatus
            Protocol = $protocol
            Status_Summary = "HTTPS: $httpsStatus | HTTP: Not Attempted"
        }
    } catch {
        if ($_.Exception.Response) {
            $httpsStatus = $_.Exception.Response.StatusCode
        } else {
            $httpsStatus = "No Response"
        }
        
        try {
            $response = Invoke-WebRequest -Uri $httpUrl -Method Head -TimeoutSec 3 -ErrorAction Stop
            $httpStatus = $response.StatusCode
            $protocol = "http"
            $finalUrl = $httpUrl
            
            return @{
                FinalURL = $finalUrl
                StatusCode = $httpStatus
                Protocol = $protocol
                Status_Summary = "HTTPS: $httpsStatus | HTTP: $httpStatus"
            }
        } catch {
            if ($_.Exception.Response) {
                $httpStatus = $_.Exception.Response.StatusCode
            } else {
                $httpStatus = "No Response"
            }
            
            return @{
                FinalURL = $finalUrl
                StatusCode = $httpStatus
                Protocol = $protocol
                Status_Summary = "HTTPS: $httpsStatus | HTTP: $httpStatus"
            }
        }
    }
}

function Check-Redirect {
    param([string]$url)
    
    try {
        $request = [System.Net.HttpWebRequest]::Create($url)
        $request.Timeout = 3000
        $request.AllowAutoRedirect = $false
        $request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        $response = $request.GetResponse()
        $statusCode = [int]$response.StatusCode
        
        if ($statusCode -ge 300 -and $statusCode -lt 400) {
            $location = $response.Headers["Location"]
            $response.Close()
            
            if (-not [string]::IsNullOrEmpty($location)) {
                if ($location.StartsWith("/")) {
                    $uri = [Uri]$url
                    $location = "$($uri.Scheme)://$($uri.Host)$location"
                }
                
                return @{
                    IsRedirect = $true
                    StatusCode = $statusCode
                    RedirectTo = $location
                    FinalURL = $location
                }
            }
        }
        
        $response.Close()
        return @{
            IsRedirect = $false
            StatusCode = $statusCode
            RedirectTo = $null
            FinalURL = $url
        }
        
    } catch [System.Net.WebException] {
        $webEx = $_.Exception
        if ($webEx.Response) {
            $statusCode = [int]$webEx.Response.StatusCode
            
            if ($statusCode -ge 300 -and $statusCode -lt 400) {
                $location = $webEx.Response.Headers["Location"]
                $webEx.Response.Close()
                
                if (-not [string]::IsNullOrEmpty($location)) {
                    if ($location.StartsWith("/")) {
                        $uri = [Uri]$url
                        $location = "$($uri.Scheme)://$($uri.Host)$location"
                    }
                    
                    return @{
                        IsRedirect = $true
                        StatusCode = $statusCode
                        RedirectTo = $location
                        FinalURL = $location
                    }
                }
            }
            $webEx.Response.Close()
            return @{
                IsRedirect = $false
                StatusCode = $statusCode
                RedirectTo = $null
                FinalURL = $url
            }
        } else {
            return @{
                IsRedirect = $false
                StatusCode = "Unreachable"
                RedirectTo = $null
                FinalURL = $url
            }
        }
    } catch {
        return @{
            IsRedirect = $false
            StatusCode = "Error"
            RedirectTo = $null
            FinalURL = $url
        }
    }
}

# Process each domain
$results = @()
$counter = 0
$successCount = 0
$httpsCount = 0
$cdnCount = 0
$redirectCount = 0
$expiringSoonCount = 0
$expiredCount = 0

foreach ($domainObj in $domainList) {
    $originalDomain = $domainObj.Domain.Trim()
    $counter++
    
    Write-Progress -Activity "Processing Domains" -Status "$counter/$total : $originalDomain" -PercentComplete (($counter / $total) * 100)
    Write-Host "Testing: $originalDomain"
    
    # Test HTTP/HTTPS
    $httpTest = Test-HTTPSFirst -domain $originalDomain
    
    $protocol = $httpTest.Protocol
    $displayDomain = $httpTest.FinalURL
    $statusCode = $httpTest.StatusCode
    $statusSummary = $httpTest.Status_Summary
    
    # Initialize redirect tracking
    $hasRedirects = "No"
    $redirectChain = @()
    $finalUrlAfterRedirects = $displayDomain
    $currentUrl = $displayDomain
    $loopDetected = "No"
    $maxRedirectChecks = 3
    
    if ($statusCode -match "^30[1278]$" -and $statusCode -notmatch "Error|Failed|Unreachable|No Response") {
        $seenUrls = @()
        
        for ($i = 0; $i -lt $maxRedirectChecks; $i++) {
            $redirectCheck = Check-Redirect -url $currentUrl
            
            if ($redirectCheck.StatusCode -match "Error|Failed|Unreachable") { break }
            
            $normalizedUrl = $currentUrl.ToLower().Replace("https://", "").Replace("http://", "").TrimEnd('/')
            
            if ($seenUrls -contains $normalizedUrl) {
                $loopDetected = "Yes"
                break
            }
            $seenUrls += $normalizedUrl
            
            if ($redirectCheck.IsRedirect -and $redirectCheck.StatusCode -match "^30[1278]$") {
                $hasRedirects = "Yes"
                $redirectCount++
                
                $redirectChain += @{
                    From = $currentUrl
                    To = $redirectCheck.RedirectTo
                    Status = $redirectCheck.StatusCode
                }
                
                $currentUrl = $redirectCheck.RedirectTo
                $finalUrlAfterRedirects = $redirectCheck.RedirectTo
                
                $fromHost = try { ([Uri]$redirectChain[-1].From).Host } catch { $redirectChain[-1].From }
                $toHost = try { ([Uri]$redirectChain[-1].To).Host } catch { $redirectChain[-1].To }
                if ($fromHost -eq $toHost) { break }
            } else {
                break
            }
        }
    }
    
    # Count statistics
    if ($protocol -eq "https") { $httpsCount++ }
    if ($statusCode -eq 200) { $successCount++ }
    
    $domainForDNS = $originalDomain
    
    $result = [PSCustomObject]@{
        Domain = $displayDomain
        Original_Domain = $originalDomain
        Protocol = $protocol
        HTTP_Status = $statusCode
        Status_Summary = $statusSummary
        
        IP_Address = "N/A"
        Organization = "N/A"
        Handle = "N/A"
        ASN = "N/A"
        
        Location = "N/A"
        Country = "N/A"
        City = "N/A"
        Region = "N/A"
        
        CDN_Provider = "None"
        Registrar = "N/A"
        ISP = "N/A"
        
        Expiry_Date = "N/A"
        Days_Until_Expiry = "N/A"
        Domain_Status = "N/A"
        
        Has_Redirects = $hasRedirects
        Redirect_Count = $redirectChain.Count
        Loop_Detected = $loopDetected
        Final_URL_After_Redirects = $finalUrlAfterRedirects
        
        Redirect1_From = "N/A"
        Redirect1_To = "N/A"
        Redirect1_Status = "N/A"
        
        Redirect2_From = "N/A"
        Redirect2_To = "N/A"
        Redirect2_Status = "N/A"
        
        Redirect3_From = "N/A"
        Redirect3_To = "N/A"
        Redirect3_Status = "N/A"
        
        Checked_At = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    try {
        # DNS resolution
        $dnsResult = Resolve-DnsName -Name $domainForDNS -Type A -ErrorAction Stop | Select-Object -First 1
        $ipAddress = $dnsResult.IPAddress
        $result.IP_Address = $ipAddress
        
        # Geolocation
        $geoData = Get-IPGeolocation -ipAddress $ipAddress
        if ($geoData) {
            $result.Location = $geoData.Location
            $result.Country = $geoData.Country
            $result.City = $geoData.City
            $result.Region = $geoData.Region
            $result.ISP = $geoData.ISP
        }
        
        # WHOIS (IP)
        $whoisData = Get-IPWhoisData -ipAddress $ipAddress
        
        if ($whoisData) {
            $result.Organization = $whoisData.Organization
            $result.Handle = $whoisData.Handle
            $result.ASN = $whoisData.ASN
            
            if ($whoisData.Country -and $whoisData.Country -ne $result.Country) {
                $result.Country = $whoisData.Country
            }
        }
        
        # CDN Detection
        $cdnProvider = Detect-CDN -organization $result.Organization -handle $result.Handle -asn $result.ASN -isp $result.ISP
        if ($cdnProvider -ne "None") {
            $result.CDN_Provider = $cdnProvider
            $cdnCount++
        }
        
        # Registrar
        $registrar = Get-DomainRegistrar -domain $originalDomain
        $result.Registrar = $registrar
        
        # Domain Expiry Date
        $baseDomain = Get-BaseDomain -domain $originalDomain
        $expiryInfo = Get-DomainExpiryDate -domain $baseDomain
        $result.Expiry_Date = $expiryInfo.ExpiryDate
        $result.Days_Until_Expiry = $expiryInfo.DaysUntilExpiry
        $result.Domain_Status = $expiryInfo.Status
        
        # Count expiry stats
        if ($expiryInfo.DaysUntilExpiry -ne "N/A" -and $expiryInfo.DaysUntilExpiry -ne "Error") {
            if ($expiryInfo.DaysUntilExpiry -lt 0) { $expiredCount++ }
            elseif ($expiryInfo.DaysUntilExpiry -lt 30) { $expiringSoonCount++ }
        }
        
    } catch {
        # Silent error
    }
    
    # Populate redirect details
    for ($i = 0; $i -lt [Math]::Min($redirectChain.Count, 3); $i++) {
        $redirect = $redirectChain[$i]
        $redirectNum = $i + 1
        
        $fromHost = try { ([Uri]$redirect.From).Host } catch { $redirect.From }
        $toHost = try { ([Uri]$redirect.To).Host } catch { $redirect.To }
        
        $result."Redirect${redirectNum}_From" = $fromHost
        $result."Redirect${redirectNum}_To" = $toHost
        $result."Redirect${redirectNum}_Status" = $redirect.Status
    }
    
    $results += $result
    
    if ($counter % 20 -eq 0) { Start-Sleep -Milliseconds 500 }
}

# Export results
if ($results.Count -gt 0) {
    $results | Export-Csv $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Host "`nResults exported to: $OutputCsv" -ForegroundColor Green
}

Write-Host "`n$("=" * 60)" -ForegroundColor Cyan
Write-Host "PROCESSING COMPLETE" -ForegroundColor Green
Write-Host "Domains processed: $counter" -ForegroundColor Yellow
Write-Host "Output file: $OutputCsv" -ForegroundColor Yellow
Write-Host "$("=" * 60)" -ForegroundColor Cyan

if ($counter -gt 0) {
    Write-Host "`nQuick Stats:" -ForegroundColor Cyan
    Write-Host "  HTTPS: $httpsCount/$counter" -ForegroundColor Gray
    Write-Host "  HTTP: $($counter - $httpsCount)/$counter" -ForegroundColor Gray
    Write-Host "  CDN detected: $cdnCount/$counter" -ForegroundColor Gray
    Write-Host "  200 OK: $successCount/$counter" -ForegroundColor Gray
    Write-Host "  Expiring in 30 days: $expiringSoonCount" -ForegroundColor Yellow
    Write-Host "  Already expired: $expiredCount" -ForegroundColor Red
}

# Copy to compared folder
try {
    if ($results.Count -gt 0) {
        $compareFile = "$ComparedFolder\domain_inventory_$DateStamp`_$RandomCode.csv"
        Copy-Item -Path $OutputCsv -Destination $compareFile -Force
    }
} catch {
    # Silent error
}
