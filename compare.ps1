# ============================================================================
# DOMAIN INVENTORY COMPARISON SCRIPT
# ============================================================================
# Compares current domain inventory with previous 2 weeks' data
# Color codes: Red = New, Yellow = Modified, Green = Unchanged, Gray = Deleted
#
# Fixes included:
# - Deleted domains are included
# - HTML filter/sort/search controls
# - Dashboard text readable
# - ASCII sort arrows (A->Z)
# - SIMPLE + CORRECT counting using Measure-Object (no .Count)
# - Dashboard percentages based on CURRENT WEEK domains (deleted excluded)
# - Adds "Total Domain Changes" = New + Modified + Deleted
# ============================================================================

Set-StrictMode -Version Latest

function Normalize-Text {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    $s = [string]$Value
    $s = $s -replace [char]0x00A0, ' '      # NBSP -> normal space
    $s = ($s -replace '\s+', ' ').Trim()
    return $s
}

function Create-HTMLComparisonReport {
    param(
        [array]$ComparisonResults,
        [string]$OutputPath,
        [int]$NewDomains,
        [int]$ChangedDomains,
        [int]$UnchangedDomains,
        [int]$DeletedDomains,
        [int]$CurrentWeekDomains,
        [int]$TotalDomainChanges,
        [array]$LatestFiles,
        [array]$AllColumns
    )

    $den = $CurrentWeekDomains
    $newPercent       = if ($den -gt 0) { [math]::Round(($NewDomains / $den) * 100, 1) } else { 0 }
    $changedPercent   = if ($den -gt 0) { [math]::Round(($ChangedDomains / $den) * 100, 1) } else { 0 }
    $unchangedPercent = if ($den -gt 0) { [math]::Round(($UnchangedDomains / $den) * 100, 1) } else { 0 }

    $deletedDen = $CurrentWeekDomains + $DeletedDomains
    $deletedPercent = if ($deletedDen -gt 0) { [math]::Round(($DeletedDomains / $deletedDen) * 100, 1) } else { 0 }

    # Total field changes: ONLY Modified rows
    $totalFieldChanges = ($ComparisonResults |
        Where-Object { (Normalize-Text $_.Change_Type).ToLowerInvariant() -eq "modified" } |
        Measure-Object -Property Changed_Fields_Count -Sum).Sum
    if ($null -eq $totalFieldChanges) { $totalFieldChanges = 0 }

    # Top changed fields (Modified only)
    $allChangedFields = @()
    foreach ($row in ($ComparisonResults | Where-Object { (Normalize-Text $_.Change_Type).ToLowerInvariant() -eq "modified" })) {
        if ($row.Changed_Fields_List -ne "") {
            $fields = $row.Changed_Fields_List -split '\|' | ForEach-Object { $_.Trim() }
            $allChangedFields += $fields
        }
    }
    $fieldFrequency = $allChangedFields | Group-Object | Sort-Object Count -Descending | Select-Object -First 10

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Domain Comparison Report - $(Get-Date -Format 'yyyy-MM-dd')</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #2c3e50; }
        h1 { border-bottom: 3px solid #3498db; padding-bottom: 10px; margin-top: 0; }

        .summary-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 10px; margin: 25px 0; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px; }

        .stat-box { background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); color: #2c3e50; }
        .stat-box div { color: #2c3e50; }
        .stat-number { font-size: 36px; font-weight: bold; margin: 10px 0; }

        .red-stat { color: #e74c3c; }
        .yellow-stat { color: #f39c12; }
        .green-stat { color: #27ae60; }
        .gray-stat { color: #546e7a; }
        .blue-stat { color: #3498db; }

        .field-frequency { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .field-frequency ul { columns: 2; padding-left: 20px; }
        .field-frequency li { margin-bottom: 8px; }

        table { width: 100%; border-collapse: collapse; margin-top: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); font-size: 14px; }
        th { background-color: #34495e; color: white; padding: 12px; text-align: left; position: sticky; top: 0; font-weight: 600; }
        td { padding: 10px 12px; border-bottom: 1px solid #ddd; vertical-align: top; }
        tr:hover { background-color: #f9f9f9; }

        .red { background-color: #ffebee; }
        .yellow { background-color: #fffde7; }
        .green { background-color: #e8f5e9; }
        .gray { background-color: #eceff1; }

        .legend { display: flex; gap: 30px; margin: 20px 0; flex-wrap: wrap; }
        .legend-item { display: flex; align-items: center; font-weight: 500; }
        .legend-color { width: 20px; height: 20px; margin-right: 8px; border-radius: 3px; }

        .footer { text-align: center; margin-top: 40px; color: #7f8c8d; font-size: 14px; border-top: 1px solid #eee; padding-top: 20px; }

        .change-details { font-size: 12px; color: #666; max-width: 400px; white-space: normal; line-height: 1.4; }

        .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; text-transform: uppercase; white-space: nowrap; }
        .badge-red { background-color: #ffcdd2; color: #c62828; }
        .badge-yellow { background-color: #fff9c4; color: #f57f17; }
        .badge-green { background-color: #c8e6c9; color: #2e7d32; }
        .badge-gray { background-color: #cfd8dc; color: #37474f; }

        .field-count { font-size: 11px; color: #666; background: #eee; padding: 1px 5px; border-radius: 3px; margin-left: 5px; }
        .toggle-details { color: #3498db; cursor: pointer; font-size: 12px; text-decoration: underline; }
        .full-details { display: none; margin-top: 5px; padding: 8px; background: #f8f9fa; border-radius: 4px; font-family: monospace; font-size: 11px; max-height: 200px; overflow-y: auto; }

        .controls { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin: 20px 0; }
        .controls select, .controls input { padding: 6px 10px; border: 1px solid #ccc; border-radius: 6px; font-size: 14px; }
    </style>

    <script>
        function toggleDetails(domain) {
            var details = document.getElementById('details-' + domain);
            var link = document.getElementById('toggle-' + domain);
            if (!details) return;
            if (details.style.display === 'block') { details.style.display = 'none'; link.textContent = 'Show Details'; }
            else { details.style.display = 'block'; link.textContent = 'Hide Details'; }
        }

        function applyFilters() {
            var filter = document.getElementById('filterStatus').value;
            var q = document.getElementById('searchBox').value.toLowerCase().trim();
            var rows = document.querySelectorAll('tbody tr');
            rows.forEach(function(row) {
                var status = (row.getAttribute('data-status') || '').toLowerCase();
                var domain = (row.getAttribute('data-domain') || '').toLowerCase();
                var matchFilter = (filter === 'all') || (status === filter);
                var matchSearch = (!q) || domain.includes(q);
                row.style.display = (matchFilter && matchSearch) ? '' : 'none';
            });
        }

        function applySort() {
            var mode = document.getElementById('sortMode').value;
            var tbody = document.querySelector('tbody');
            var rows = Array.from(tbody.querySelectorAll('tr'));
            rows.sort(function(a, b) {
                var da = (a.getAttribute('data-domain') || '').toLowerCase();
                var db = (b.getAttribute('data-domain') || '').toLowerCase();
                var ca = parseInt(a.getAttribute('data-changes') || '0', 10);
                var cb = parseInt(b.getAttribute('data-changes') || '0', 10);
                switch(mode) {
                    case 'domain_desc':  return db.localeCompare(da);
                    case 'changes_desc': return cb - ca;
                    case 'changes_asc':  return ca - cb;
                    default:             return da.localeCompare(db);
                }
            });
            rows.forEach(function(r){ tbody.appendChild(r); });
            applyFilters();
        }

        document.addEventListener('DOMContentLoaded', function() { applyFilters(); });
    </script>
</head>

<body>
    <div class="container">
        <h1>&#128202; Domain Inventory Comparison Report</h1>
        <p>Generated on: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))</p>
        <p>Comparing <strong>$CurrentWeekDomains</strong> domains (current week) with data from previous 2 weeks</p>

        <div class="summary-card">
            <h2 style="color: white; margin-top: 0;">Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <div>New Domains</div>
                    <div class="stat-number red-stat">$NewDomains</div>
                    <div>$newPercent% of current week</div>
                </div>
                <div class="stat-box">
                    <div>Changed Domains</div>
                    <div class="stat-number yellow-stat">$ChangedDomains</div>
                    <div>$changedPercent% of current week</div>
                </div>
                <div class="stat-box">
                    <div>Unchanged Domains</div>
                    <div class="stat-number green-stat">$UnchangedDomains</div>
                    <div>$unchangedPercent% of current week</div>
                </div>
                <div class="stat-box">
                    <div>Deleted Domains</div>
                    <div class="stat-number gray-stat">$DeletedDomains</div>
                    <div>$deletedPercent% of (current + deleted)</div>
                </div>
                <div class="stat-box">
                    <div>Total Domain Changes</div>
                    <div class="stat-number blue-stat">$TotalDomainChanges</div>
                    <div>New + Modified + Deleted</div>
                </div>
                <div class="stat-box">
                    <div>Total Field Changes</div>
                    <div class="stat-number blue-stat">$totalFieldChanges</div>
                    <div>Fields modified (Modified only)</div>
                </div>
            </div>
        </div>

        $(if ($fieldFrequency.Count -gt 0) {
        "<div class='field-frequency'>
            <h3>Most Frequently Changed Fields</h3>
            <ul>
            " + ($fieldFrequency | ForEach-Object { "<li><strong>$($_.Name)</strong> <span class='field-count'>$($_.Count) times</span></li>" }) + "
            </ul>
        </div>"
        })

        <div class="legend">
            <div class="legend-item"><div class="legend-color" style="background-color:#ffebee;"></div>New Domains (Added this week)</div>
            <div class="legend-item"><div class="legend-color" style="background-color:#fffde7;"></div>Changed Domains (Modified properties)</div>
            <div class="legend-item"><div class="legend-color" style="background-color:#e8f5e9;"></div>Unchanged Domains (No changes detected)</div>
            <div class="legend-item"><div class="legend-color" style="background-color:#eceff1;"></div>Deleted Domains (Missing this week)</div>
        </div>

        <div class="controls">
            <label><strong>Filter:</strong></label>
            <select id="filterStatus" onchange="applyFilters()">
                <option value="all">All</option>
                <option value="new">New Domain</option>
                <option value="modified">Modified</option>
                <option value="unchanged">Unchanged</option>
                <option value="deleted">Deleted</option>
            </select>

            <label style="margin-left:10px;"><strong>Sort:</strong></label>
            <select id="sortMode" onchange="applySort()">
                <option value="domain_asc">Domain (A->Z)</option>
                <option value="domain_desc">Domain (Z->A)</option>
                <option value="changes_desc">Most Changes</option>
                <option value="changes_asc">Least Changes</option>
            </select>

            <input id="searchBox" type="text" placeholder="Search domain..." oninput="applyFilters()" style="min-width:240px;" />
        </div>

        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Status</th>
                    <th>Current IP</th>
                    <th>Current Status</th>
                    <th>Current CDN</th>
                    <th>Changes</th>
                    <th>First Seen</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
"@

    foreach ($row in $ComparisonResults) {
        $rowClass = (Normalize-Text $row.Row_Color).ToLowerInvariant()
        if ($rowClass -notin @("red","yellow","green","gray")) { $rowClass = "green" }

        $badgeClass = "badge-$rowClass"
        $safeDomain = $row.Domain.Replace('.', '-').Replace(' ', '_')

        $ctRaw = Normalize-Text $row.Change_Type
        $ctNorm = $ctRaw.ToLowerInvariant()

        $statusKey = switch ($ctNorm) {
            "new domain" { "new" }
            "modified"   { "modified" }
            "unchanged"  { "unchanged" }
            "deleted"    { "deleted" }
            default      { "all" }
        }

        $domainAttr  = $row.Domain
        $changesAttr = [int]$row.Changed_Fields_Count

        $changesCell = ""
        if ($changesAttr -gt 0) {
            $changesCell = "<span class='field-count'>$changesAttr fields</span><br/>
                            <a class='toggle-details' id='toggle-$safeDomain' onclick='toggleDetails(`"$safeDomain`")'>Show Details</a>
                            <div class='full-details' id='details-$safeDomain'>$($row.Changed_Fields_List.Replace('|', '<br/>'))</div>"
        } else {
            if ($ctNorm -eq "new domain") { $changesCell = "New domain" }
            elseif ($ctNorm -eq "deleted") { $changesCell = "Removed from inventory" }
            else { $changesCell = "No changes" }
        }

        $statusLabel = (Normalize-Text $row.Change_Type)

        $html += @"
                <tr class="$rowClass" data-status="$statusKey" data-domain="$domainAttr" data-changes="$changesAttr">
                    <td><strong>$($row.Domain)</strong></td>
                    <td><span class="badge $badgeClass">$statusLabel</span></td>
                    <td>$($row.Current_IP)</td>
                    <td>$($row.Current_Status)</td>
                    <td>$($row.Current_CDN)</td>
                    <td>$changesCell</td>
                    <td>$($row.First_Seen)</td>
                    <td class="change-details">$($row.Change_Details)</td>
                </tr>
"@
    }

    $html += @"
            </tbody>
        </table>

        <div class="footer">
            <p>Report generated by Domain Inventory Comparison Tool</p>
            <p>Comparison based on data from: $(Get-Date (Get-Item $LatestFiles[0].FullName).LastWriteTime -Format 'yyyy-MM-dd'),
               $(Get-Date (Get-Item $LatestFiles[1].FullName).LastWriteTime -Format 'yyyy-MM-dd'), and
               $(Get-Date (Get-Item $LatestFiles[2].FullName).LastWriteTime -Format 'yyyy-MM-dd')</p>
            <p>Total columns compared per domain: $($AllColumns.Count)</p>
        </div>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

# ============================================================================
# MAIN SCRIPT
# ============================================================================

# Configuration
$OutputsFolder = ".\outputs"
$ComparedFolder = ".\compared"
$ComparisonDate = Get-Date -Format "yyyy-MM-dd"

Write-Host "`n$('=' * 70)" -ForegroundColor Cyan
Write-Host "DOMAIN INVENTORY COMPARISON TOOL" -ForegroundColor Green
Write-Host "$('=' * 70)" -ForegroundColor Cyan

if (-not (Test-Path $OutputsFolder)) {
    Write-Host "ERROR: Outputs folder not found!" -ForegroundColor Red
    Write-Host "Please run the main domain inventory script first." -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $ComparedFolder)) {
    New-Item -Path $ComparedFolder -ItemType Directory -Force | Out-Null
    Write-Host "Created compared folder: $ComparedFolder" -ForegroundColor Yellow
}

Write-Host "`nScanning for domain inventory files..." -ForegroundColor Cyan
$allOutputs = Get-ChildItem -Path $OutputsFolder -Filter "domain_inventory_*.csv" -Recurse |
              Sort-Object LastWriteTime -Descending

if (-not $allOutputs) {
    Write-Host "ERROR: No domain inventory files found!" -ForegroundColor Red
    Write-Host "Please run the main domain inventory script first to generate data." -ForegroundColor Yellow
    exit 1
}

Write-Host "Found $($allOutputs | Measure-Object | Select-Object -ExpandProperty Count) inventory files total" -ForegroundColor Gray

if (($allOutputs | Measure-Object | Select-Object -ExpandProperty Count) -lt 3) {
    Write-Host "`nComparison not triggered: Need at least 3 weekly outputs for comparison" -ForegroundColor Yellow
    Write-Host "Please run the main script for 3 consecutive weeks to enable comparison." -ForegroundColor Yellow
    exit 0
}

$latestFiles = $allOutputs | Select-Object -First 3

Write-Host "`nUsing these 3 most recent files for comparison:" -ForegroundColor Green
$fileNum = 0
foreach ($file in $latestFiles) {
    $fileNum++
    $relativeAge = switch ($fileNum) {
        1 { "CURRENT WEEK" }
        2 { "PREVIOUS WEEK (-1)" }
        3 { "2 WEEKS AGO (-2)" }
    }
    $fileDate = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
    Write-Host "  [$relativeAge]" -ForegroundColor White -NoNewline
    Write-Host " $($file.Name)" -ForegroundColor Gray
    Write-Host "        Modified: $fileDate | Path: $($file.FullName)" -ForegroundColor DarkGray
}

Write-Host "`nImporting data..." -ForegroundColor Cyan
try {
    $currentData = Import-Csv $latestFiles[0].FullName
    $previous1Data = Import-Csv $latestFiles[1].FullName
    $previous2Data = Import-Csv $latestFiles[2].FullName

    Write-Host "  Current week: $($currentData | Measure-Object | Select-Object -ExpandProperty Count) domains" -ForegroundColor Gray
    Write-Host "  Previous week: $($previous1Data | Measure-Object | Select-Object -ExpandProperty Count) domains" -ForegroundColor Gray
    Write-Host "  2 weeks ago: $($previous2Data | Measure-Object | Select-Object -ExpandProperty Count) domains" -ForegroundColor Gray
} catch {
    Write-Host "ERROR: Failed to import CSV files!" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}

$CurrentWeekDomains = [int]($currentData | Measure-Object | Select-Object -ExpandProperty Count)

$allColumns = $currentData[0].PSObject.Properties.Name
Write-Host "`nComparing $($allColumns.Count) columns per domain:" -ForegroundColor Cyan
Write-Host "  Columns: $($allColumns -join ', ')" -ForegroundColor Gray

Write-Host "`nPreparing data for comparison..." -ForegroundColor Cyan

$previousDomains1 = @{}
foreach ($row in $previous1Data) {
    $key = (Normalize-Text $row.Domain).ToLowerInvariant()
    $previousDomains1[$key] = $row
}

$previousDomains2 = @{}
foreach ($row in $previous2Data) {
    $key = (Normalize-Text $row.Domain).ToLowerInvariant()
    $previousDomains2[$key] = $row
}

$currentDomains = @{}
foreach ($row in $currentData) {
    $k = (Normalize-Text $row.Domain).ToLowerInvariant()
    if (-not $currentDomains.ContainsKey($k)) { $currentDomains[$k] = $row }
}

Write-Host "Comparing domains..." -ForegroundColor Cyan
$comparisonResults = @()
$domainCount = 0
$currentCount = ($currentData | Measure-Object | Select-Object -ExpandProperty Count)

foreach ($currentRow in $currentData) {
    $domainCount++
    Write-Progress -Activity "Comparing Domains" -Status "Processing $domainCount/$currentCount" `
                   -PercentComplete (($domainCount / $currentCount) * 100)

    $domain = $currentRow.Domain
    $domainKey = (Normalize-Text $domain).ToLowerInvariant()

    $existedInWeek1 = $previousDomains1.ContainsKey($domainKey)
    $existedInWeek2 = $previousDomains2.ContainsKey($domainKey)

    if (-not $existedInWeek1 -and -not $existedInWeek2) {
        $rowColor = "Red"
        $changeType = "New Domain"
        $changeDetails = "First appearance in inventory"
        $changedFields = @()
    } else {
        $hasChanges = $false
        $changedFields = @()

        if ($existedInWeek1) {
            $prevRow1 = $previousDomains1[$domainKey]
            foreach ($column in $allColumns) {
                if ($column -match "^(Domain|Checked_At|Row_Color|Change_)") { continue }

                $currentValue = $currentRow.$column
                $previousValue = $prevRow1.$column

                $currentValue  = if ([string]::IsNullOrEmpty($currentValue))  { "N/A" } else { $currentValue.ToString().Trim() }
                $previousValue = if ([string]::IsNullOrEmpty($previousValue)) { "N/A" } else { $previousValue.ToString().Trim() }

                if ($column -match "IP|ASN|Handle|StatusCode") { $valuesEqual = ($currentValue -ceq $previousValue) }
                else { $valuesEqual = ($currentValue -ieq $previousValue) }

                if (-not $valuesEqual -and ($currentValue -ne "N/A" -or $previousValue -ne "N/A")) {
                    $hasChanges = $true
                    $changedFields += "${column}: '$previousValue' -> '$currentValue'"
                }
            }
        }

        if ($existedInWeek2) {
            $prevRow2 = $previousDomains2[$domainKey]
            foreach ($column in $allColumns) {
                if ($column -match "^(Domain|Checked_At|Row_Color|Change_)") { continue }

                $currentValue = $currentRow.$column
                $previousValue = $prevRow2.$column

                $currentValue  = if ([string]::IsNullOrEmpty($currentValue))  { "N/A" } else { $currentValue.ToString().Trim() }
                $previousValue = if ([string]::IsNullOrEmpty($previousValue)) { "N/A" } else { $previousValue.ToString().Trim() }

                if ($column -match "IP|ASN|Handle|StatusCode") { $valuesEqual = ($currentValue -ceq $previousValue) }
                else { $valuesEqual = ($currentValue -ieq $previousValue) }

                if (-not $valuesEqual -and ($currentValue -ne "N/A" -or $previousValue -ne "N/A")) {
                    $fieldAlreadyExists = $false
                    foreach ($existingField in $changedFields) {
                        if ($existingField -match "^${column}:") { $fieldAlreadyExists = $true; break }
                    }
                    if (-not $fieldAlreadyExists) {
                        $hasChanges = $true
                        $changedFields += "${column}: '$previousValue' -> '$currentValue'"
                    }
                }
            }
        }

        if ($hasChanges) {
            $rowColor = "Yellow"
            $changeType = "Modified"
            $changeDetails = if ($changedFields.Count -gt 3) {
                "$($changedFields.Count) fields changed: " + ($changedFields[0..2] -join "; ") + "..."
            } else {
                $changedFields -join "; "
            }
        } else {
            $rowColor = "Green"
            $changeType = "Unchanged"
            $changeDetails = "No changes detected in any field"
        }
    }

    $comparisonResults += [PSCustomObject]@{
        Domain = $domain
        Row_Color = $rowColor
        Change_Type = $changeType
        Change_Details = $changeDetails
        Changed_Fields_Count = $changedFields.Count
        Changed_Fields_List = ($changedFields -join " | ")

        Current_IP = $currentRow.IP_Address
        Current_CDN = $currentRow.CDN_Provider
        Current_Status = $currentRow.HTTP_Status
        Current_Registrar = $currentRow.Registrar
        Current_Country = $currentRow.Country

        First_Seen = if ($rowColor -eq "Red") { "This Week" }
                     elseif ($existedInWeek2) { "2+ Weeks Ago" }
                     else { "Last Week" }

        Checked_At = $currentRow.Checked_At
    }
}

Write-Progress -Activity "Comparing Domains" -Completed

# Deleted domains (present in prev weeks but not in current)
$allPrevKeys = @($previousDomains1.Keys + $previousDomains2.Keys) | Select-Object -Unique
foreach ($k in $allPrevKeys) {
    if (-not $currentDomains.ContainsKey($k)) {
        $prev1 = if ($previousDomains1.ContainsKey($k)) { $previousDomains1[$k] } else { $null }
        $prev2 = if ($previousDomains2.ContainsKey($k)) { $previousDomains2[$k] } else { $null }
        $domainName = if ($prev1) { $prev1.Domain } else { $prev2.Domain }

        $comparisonResults += [PSCustomObject]@{
            Domain = $domainName
            Row_Color = "Gray"
            Change_Type = "Deleted"
            Change_Details = "Domain present in previous inventory but missing this week"
            Changed_Fields_Count = 0
            Changed_Fields_List = ""

            Current_IP = "N/A"
            Current_CDN = "N/A"
            Current_Status = "N/A"
            Current_Registrar = "N/A"
            Current_Country = "N/A"

            First_Seen = if ($prev2) { "2+ Weeks Ago" } else { "Last Week" }
            Checked_At = "N/A"
        }
    }
}

# Export CSV
$comparisonCsv = "$ComparedFolder\domain_comparison_$ComparisonDate.csv"
$comparisonResults | Export-Csv $comparisonCsv -NoTypeInformation -Encoding UTF8

# -------------------------------
# SIMPLE COUNTING (NO .Count)
# -------------------------------
$newDomains = ($comparisonResults | Where-Object { (Normalize-Text $_.Change_Type).ToLowerInvariant() -eq "new domain" } | Measure-Object).Count
$changedDomains = ($comparisonResults | Where-Object { (Normalize-Text $_.Change_Type).ToLowerInvariant() -eq "modified" } | Measure-Object).Count
$unchangedDomains = ($comparisonResults | Where-Object { (Normalize-Text $_.Change_Type).ToLowerInvariant() -eq "unchanged" } | Measure-Object).Count
$deletedDomains = ($comparisonResults | Where-Object { (Normalize-Text $_.Change_Type).ToLowerInvariant() -eq "deleted" } | Measure-Object).Count
$totalDomainChanges = $newDomains + $changedDomains + $deletedDomains

# HTML report
Create-HTMLComparisonReport -ComparisonResults $comparisonResults `
                           -OutputPath "$ComparedFolder\domain_comparison_$ComparisonDate.html" `
                           -NewDomains $newDomains `
                           -ChangedDomains $changedDomains `
                           -UnchangedDomains $unchangedDomains `
                           -DeletedDomains $deletedDomains `
                           -CurrentWeekDomains $CurrentWeekDomains `
                           -TotalDomainChanges $totalDomainChanges `
                           -LatestFiles $latestFiles `
                           -AllColumns $allColumns

# Console output
Write-Host "`n$('=' * 70)" -ForegroundColor Cyan
Write-Host "COMPARISON COMPLETE" -ForegroundColor Green
Write-Host "$('=' * 70)" -ForegroundColor Cyan

Write-Host "`nSUMMARY STATISTICS:" -ForegroundColor White
Write-Host "  Current Week Domains: $CurrentWeekDomains" -ForegroundColor Gray
Write-Host "  New Domains (Red): $newDomains" -ForegroundColor Red
Write-Host "  Changed Domains (Yellow): $changedDomains" -ForegroundColor Yellow
Write-Host "  Unchanged Domains (Green): $unchangedDomains" -ForegroundColor Green
Write-Host "  Deleted Domains (Gray): $deletedDomains" -ForegroundColor DarkGray
Write-Host "  Total Domain Changes (New+Modified+Deleted): $totalDomainChanges" -ForegroundColor Cyan

Write-Host "`nCHANGE DETAILS:" -ForegroundColor White
$totalFieldChangesConsole = ($comparisonResults | Where-Object { (Normalize-Text $_.Change_Type).ToLowerInvariant() -eq "modified" } | Measure-Object -Property Changed_Fields_Count -Sum).Sum
if ($null -eq $totalFieldChangesConsole) { $totalFieldChangesConsole = 0 }
Write-Host "  Total fields changed across MODIFIED domains: $totalFieldChangesConsole" -ForegroundColor Gray

Write-Host "`nOUTPUT FILES:" -ForegroundColor White
Write-Host "  Comparison CSV: $comparisonCsv" -ForegroundColor Cyan
Write-Host "  HTML Report: $ComparedFolder\domain_comparison_$ComparisonDate.html" -ForegroundColor Cyan

Write-Host "`nFILES USED FOR COMPARISON:" -ForegroundColor White
foreach ($file in $latestFiles) {
    Write-Host "  - $($file.Name)" -ForegroundColor Gray
}

Write-Host "`n$('=' * 70)" -ForegroundColor Cyan
Write-Host "To view the colored report, open the HTML file in your browser." -ForegroundColor Yellow
Write-Host "$('=' * 70)" -ForegroundColor Cyan

Write-Host "`nComparison script completed successfully!" -ForegroundColor Green
