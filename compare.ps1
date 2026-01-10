# ============================================================================
# DOMAIN INVENTORY COMPARISON SCRIPT
# ============================================================================
# Compares current domain inventory with previous 2 weeks' data
# Color codes: Red = New, Yellow = Changed, Green = Unchanged
# ============================================================================

# HTML Report Generation Function (MUST BE DEFINED BEFORE IT'S CALLED)
function Create-HTMLComparisonReport {
    param(
        [array]$ComparisonResults,
        [string]$OutputPath,
        [int]$NewDomains,
        [int]$ChangedDomains,
        [int]$UnchangedDomains,
        [array]$LatestFiles,
        [array]$AllColumns
    )
    
    # Calculate percentages for summary
    $total = $ComparisonResults.Count
    $newPercent = if ($total -gt 0) { [math]::Round(($NewDomains / $total) * 100, 1) } else { 0 }
    $changedPercent = if ($total -gt 0) { [math]::Round(($ChangedDomains / $total) * 100, 1) } else { 0 }
    $unchangedPercent = if ($total -gt 0) { [math]::Round(($UnchangedDomains / $total) * 100, 1) } else { 0 }
    
    # Get top changed fields
    $allChangedFields = @()
    foreach ($row in $ComparisonResults) {
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
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        h1, h2, h3 { 
            color: #2c3e50; 
        }
        
        h1 { 
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-top: 0;
        }
        
        .summary-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            margin: 25px 0;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .stat-box {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .stat-number {
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .red-stat { color: #e74c3c; }
        .yellow-stat { color: #f39c12; }
        .green-stat { color: #27ae60; }
        
        .field-frequency {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        
        .field-frequency ul {
            columns: 2;
            padding-left: 20px;
        }
        
        .field-frequency li {
            margin-bottom: 8px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 30px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            font-size: 14px;
        }
        
        th {
            background-color: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
            position: sticky;
            top: 0;
            font-weight: 600;
        }
        
        td {
            padding: 10px 12px;
            border-bottom: 1px solid #ddd;
            vertical-align: top;
        }
        
        tr:hover {
            background-color: #f9f9f9;
        }
        
        .red { background-color: #ffebee; }
        .yellow { background-color: #fffde7; }
        .green { background-color: #e8f5e9; }
        
        .legend {
            display: flex;
            gap: 30px;
            margin: 20px 0;
            flex-wrap: wrap;
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            font-weight: 500;
        }
        
        .legend-color {
            width: 20px;
            height: 20px;
            margin-right: 8px;
            border-radius: 3px;
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            color: #7f8c8d;
            font-size: 14px;
            border-top: 1px solid #eee;
            padding-top: 20px;
        }
        
        .change-details {
            font-size: 12px;
            color: #666;
            max-width: 400px;
            white-space: normal;
            line-height: 1.4;
        }
        
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
            white-space: nowrap;
        }
        
        .badge-red { background-color: #ffcdd2; color: #c62828; }
        .badge-yellow { background-color: #fff9c4; color: #f57f17; }
        .badge-green { background-color: #c8e6c9; color: #2e7d32; }
        
        .field-count {
            font-size: 11px;
            color: #666;
            background: #eee;
            padding: 1px 5px;
            border-radius: 3px;
            margin-left: 5px;
        }
        
        .toggle-details {
            color: #3498db;
            cursor: pointer;
            font-size: 12px;
            text-decoration: underline;
        }
        
        .full-details {
            display: none;
            margin-top: 5px;
            padding: 8px;
            background: #f8f9fa;
            border-radius: 4px;
            font-family: monospace;
            font-size: 11px;
            max-height: 200px;
            overflow-y: auto;
        }
    </style>
    <script>
        function toggleDetails(domain) {
            var details = document.getElementById('details-' + domain);
            var link = document.getElementById('toggle-' + domain);
            
            if (details.style.display === 'block') {
                details.style.display = 'none';
                link.textContent = 'Show Details';
            } else {
                details.style.display = 'block';
                link.textContent = 'Hide Details';
            }
        }
    </script>
</head>
<body>
    <div class="container">
         <h1>&#128202; Domain Inventory Comparison Report</h1>
        <p>Generated on: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))</p>
        <p>Comparing <strong>$total</strong> domains (current week) with data from previous 2 weeks</p>
        
        <div class="summary-card">
            <h2 style="color: white; margin-top: 0;">Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <div>New Domains</div>
                    <div class="stat-number red-stat">$NewDomains</div>
                    <div>$newPercent% of total</div>
                </div>
                <div class="stat-box">
                    <div>Changed Domains</div>
                    <div class="stat-number yellow-stat">$ChangedDomains</div>
                    <div>$changedPercent% of total</div>
                </div>
                <div class="stat-box">
                    <div>Unchanged Domains</div>
                    <div class="stat-number green-stat">$UnchangedDomains</div>
                    <div>$unchangedPercent% of total</div>
                </div>
                <div class="stat-box">
                    <div>Total Changes</div>
                    <div class="stat-number" style="color: #3498db;">$(($ComparisonResults | Measure-Object -Property Changed_Fields_Count -Sum).Sum)</div>
                    <div>Fields modified</div>
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
            <div class="legend-item">
                <div class="legend-color" style="background-color: #ffebee;"></div>
                New Domains (Added this week)
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #fffde7;"></div>
                Changed Domains (Modified properties)
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #e8f5e9;"></div>
                Unchanged Domains (No changes detected)
            </div>
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

    $domainId = 0
    foreach ($row in $ComparisonResults) {
        $domainId++
        $rowClass = $row.Row_Color.ToLower()
        $badgeClass = "badge-$rowClass"
        $safeDomain = $row.Domain.Replace('.', '-').Replace(' ', '_')
        
        $html += @"
                <tr class="$rowClass">
                    <td><strong>$($row.Domain)</strong></td>
                    <td><span class="badge $badgeClass">$($row.Change_Type)</span></td>
                    <td>$($row.Current_IP)</td>
                    <td>$($row.Current_Status)</td>
                    <td>$($row.Current_CDN)</td>
                    <td>
                        $(if ($row.Changed_Fields_Count -gt 0) {
                            "<span class='field-count'>$($row.Changed_Fields_Count) fields</span><br/>
                            <a class='toggle-details' id='toggle-$safeDomain' onclick='toggleDetails(`"$safeDomain`")'>Show Details</a>
                            <div class='full-details' id='details-$safeDomain'>$($row.Changed_Fields_List.Replace('|', '<br/>'))</div>"
                        } else {
                            "No changes"
                        })
                    </td>
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

# CHECK FOR OUTPUTS FOLDER
if (-not (Test-Path $OutputsFolder)) { 
    Write-Host "ERROR: Outputs folder not found!" -ForegroundColor Red
    Write-Host "Please run the main domain inventory script first." -ForegroundColor Yellow
    exit 1
}

# CHECK FOR COMPARED FOLDER
if (-not (Test-Path $ComparedFolder)) {
    New-Item -Path $ComparedFolder -ItemType Directory -Force | Out-Null
    Write-Host "Created compared folder: $ComparedFolder" -ForegroundColor Yellow
}

# Get all output files, sorted by date (newest first)
Write-Host "`nScanning for domain inventory files..." -ForegroundColor Cyan
$allOutputs = Get-ChildItem -Path $OutputsFolder -Filter "domain_inventory_*.csv" -Recurse | 
              Sort-Object LastWriteTime -Descending

if ($allOutputs.Count -eq 0) {
    Write-Host "ERROR: No domain inventory files found!" -ForegroundColor Red
    Write-Host "Please run the main domain inventory script first to generate data." -ForegroundColor Yellow
    exit 1
}

Write-Host "Found $($allOutputs.Count) inventory files total" -ForegroundColor Gray

# Check if we have enough data for comparison
if ($allOutputs.Count -lt 3) {
    Write-Host "`nComparison not triggered: Need at least 3 weekly outputs for comparison" -ForegroundColor Yellow
    Write-Host "Current outputs found: $($allOutputs.Count)" -ForegroundColor Gray
    Write-Host "Please run the main script for 3 consecutive weeks to enable comparison." -ForegroundColor Yellow
    exit 0
}

# Get the latest 3 files (current + 2 previous)
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

# Import the data from all 3 weeks
Write-Host "`nImporting data..." -ForegroundColor Cyan
try {
    $currentData = Import-Csv $latestFiles[0].FullName
    $previous1Data = Import-Csv $latestFiles[1].FullName
    $previous2Data = Import-Csv $latestFiles[2].FullName
    
    Write-Host "  Current week: $($currentData.Count) domains" -ForegroundColor Gray
    Write-Host "  Previous week: $($previous1Data.Count) domains" -ForegroundColor Gray
    Write-Host "  2 weeks ago: $($previous2Data.Count) domains" -ForegroundColor Gray
} catch {
    Write-Host "ERROR: Failed to import CSV files!" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}

# Get ALL column names from current data (dynamically)
$allColumns = $currentData[0].PSObject.Properties.Name
Write-Host "`nComparing $($allColumns.Count) columns per domain:" -ForegroundColor Cyan
Write-Host "  Columns: $($allColumns -join ', ')" -ForegroundColor Gray

# Create dictionaries for quick domain lookup in previous weeks
Write-Host "`nPreparing data for comparison..." -ForegroundColor Cyan
$previousDomains1 = @{}
foreach ($row in $previous1Data) {
    $key = $row.Domain.ToLower().Trim()
    $previousDomains1[$key] = $row
}

$previousDomains2 = @{}
foreach ($row in $previous2Data) {
    $key = $row.Domain.ToLower().Trim()
    $previousDomains2[$key] = $row
}

# Create comparison results
Write-Host "Comparing domains..." -ForegroundColor Cyan
$comparisonResults = @()
$domainCount = 0

foreach ($currentRow in $currentData) {
    $domainCount++
    Write-Progress -Activity "Comparing Domains" -Status "Processing $domainCount/$($currentData.Count)" `
                   -PercentComplete (($domainCount / $currentData.Count) * 100)
    
    $domain = $currentRow.Domain
    $domainKey = $domain.ToLower().Trim()
    
    # Check if domain existed in previous weeks
    $existedInWeek1 = $previousDomains1.ContainsKey($domainKey)
    $existedInWeek2 = $previousDomains2.ContainsKey($domainKey)
    
    # Determine row color and change type
    if (-not $existedInWeek1 -and -not $existedInWeek2) {
        $rowColor = "Red"
        $changeType = "New Domain"
        $changeDetails = "First appearance in inventory"
        $changedFields = @()
    } else {
        # Check for changes in ALL fields
        $hasChanges = $false
        $changedFields = @()
        
        # Compare with Week -1 if domain existed
        if ($existedInWeek1) {
            $prevRow1 = $previousDomains1[$domainKey]
            foreach ($column in $allColumns) {
                # Skip Domain column and timestamp columns for comparison
                if ($column -match "^(Domain|Checked_At|Row_Color|Change_)") { continue }
                
                $currentValue = $currentRow.$column
                $previousValue = $prevRow1.$column
                
                # Handle null/empty values
                $currentValue = if ([string]::IsNullOrEmpty($currentValue)) { "N/A" } else { $currentValue.ToString().Trim() }
                $previousValue = if ([string]::IsNullOrEmpty($previousValue)) { "N/A" } else { $previousValue.ToString().Trim() }
                
                # Compare values (case-insensitive for most fields)
                if ($column -match "IP|ASN|Handle|StatusCode") {
                    # Case-sensitive comparison for technical fields
                    $valuesEqual = ($currentValue -ceq $previousValue)
                } else {
                    # Case-insensitive for text fields
                    $valuesEqual = ($currentValue -ieq $previousValue)
                }
                
                if (-not $valuesEqual -and ($currentValue -ne "N/A" -or $previousValue -ne "N/A")) {
                    $hasChanges = $true
                    $arrow = "->"  # Using ASCII arrow instead of special character
                    $changedFields += "${column}: '$previousValue' ${arrow} '$currentValue'"
                }
            }
        }
        
        # Compare with Week -2 if domain existed
        if ($existedInWeek2) {
            $prevRow2 = $previousDomains2[$domainKey]
            foreach ($column in $allColumns) {
                if ($column -match "^(Domain|Checked_At|Row_Color|Change_)") { continue }
                
                $currentValue = $currentRow.$column
                $previousValue = $prevRow2.$column
                
                $currentValue = if ([string]::IsNullOrEmpty($currentValue)) { "N/A" } else { $currentValue.ToString().Trim() }
                $previousValue = if ([string]::IsNullOrEmpty($previousValue)) { "N/A" } else { $previousValue.ToString().Trim() }
                
                if ($column -match "IP|ASN|Handle|StatusCode") {
                    $valuesEqual = ($currentValue -ceq $previousValue)
                } else {
                    $valuesEqual = ($currentValue -ieq $previousValue)
                }
                
                if (-not $valuesEqual -and ($currentValue -ne "N/A" -or $previousValue -ne "N/A")) {
                    # Check if we already have this field in changedFields
                    $fieldAlreadyExists = $false
                    foreach ($existingField in $changedFields) {
                        if ($existingField -match "^${column}:") {
                            $fieldAlreadyExists = $true
                            break
                        }
                    }
                    
                    if (-not $fieldAlreadyExists) {
                        $hasChanges = $true
                        $arrow = "->"
                        $changedFields += "${column}: '$previousValue' ${arrow} '$currentValue'"
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
    
    # Get previous values for important fields
    $prevIP1 = if ($existedInWeek1) { $previousDomains1[$domainKey].IP_Address } else { "N/A" }
    $prevIP2 = if ($existedInWeek2) { $previousDomains2[$domainKey].IP_Address } else { "N/A" }
    
    $prevCDN1 = if ($existedInWeek1) { $previousDomains1[$domainKey].CDN_Provider } else { "N/A" }
    $prevCDN2 = if ($existedInWeek2) { $previousDomains2[$domainKey].CDN_Provider } else { "N/A" }
    
    $prevStatus1 = if ($existedInWeek1) { $previousDomains1[$domainKey].HTTP_Status } else { "N/A" }
    $prevStatus2 = if ($existedInWeek2) { $previousDomains2[$domainKey].HTTP_Status } else { "N/A" }
    
    # Create comparison row
    $comparisonRow = [PSCustomObject]@{
        Domain = $domain
        Row_Color = $rowColor
        Change_Type = $changeType
        Change_Details = $changeDetails
        Changed_Fields_Count = $changedFields.Count
        Changed_Fields_List = $changedFields -join " | "
        
        # Current values
        Current_IP = $currentRow.IP_Address
        Current_CDN = $currentRow.CDN_Provider
        Current_Status = $currentRow.HTTP_Status
        Current_Registrar = $currentRow.Registrar
        Current_Country = $currentRow.Country
        
        # Previous values (Week -1)
        Previous_IP_Week1 = $prevIP1
        Previous_CDN_Week1 = $prevCDN1
        Previous_Status_Week1 = $prevStatus1
        
        # Previous values (Week -2)
        Previous_IP_Week2 = $prevIP2
        Previous_CDN_Week2 = $prevCDN2
        Previous_Status_Week2 = $prevStatus2
        
        # Timeline
        First_Seen = if ($rowColor -eq "Red") { "This Week" } 
                     elseif ($existedInWeek2) { "2+ Weeks Ago" }
                     else { "Last Week" }
        
        Checked_At = $currentRow.Checked_At
    }
    
    $comparisonResults += $comparisonRow
}

Write-Progress -Activity "Comparing Domains" -Completed

# Export comparison results to CSV
$comparisonCsv = "$ComparedFolder\domain_comparison_$ComparisonDate.csv"
$comparisonResults | Export-Csv $comparisonCsv -NoTypeInformation -Encoding UTF8

# Generate summary statistics
$newDomains = ($comparisonResults | Where-Object { $_.Row_Color -eq "Red" }).Count
$changedDomains = ($comparisonResults | Where-Object { $_.Row_Color -eq "Yellow" }).Count
$unchangedDomains = ($comparisonResults | Where-Object { $_.Row_Color -eq "Green" }).Count

# Create HTML report
Create-HTMLComparisonReport -ComparisonResults $comparisonResults `
                           -OutputPath "$ComparedFolder\domain_comparison_$ComparisonDate.html" `
                           -NewDomains $newDomains `
                           -ChangedDomains $changedDomains `
                           -UnchangedDomains $unchangedDomains `
                           -LatestFiles $latestFiles `
                           -AllColumns $allColumns

# Display results
Write-Host "`n$('=' * 70)" -ForegroundColor Cyan
Write-Host "COMPARISON COMPLETE" -ForegroundColor Green
Write-Host "$('=' * 70)" -ForegroundColor Cyan

Write-Host "`nSUMMARY STATISTICS:" -ForegroundColor White
Write-Host "  Total Domains Analyzed: $($comparisonResults.Count)" -ForegroundColor Gray
Write-Host "  New Domains (Red): $newDomains" -ForegroundColor Red
Write-Host "  Changed Domains (Yellow): $changedDomains" -ForegroundColor Yellow
Write-Host "  Unchanged Domains (Green): $unchangedDomains" -ForegroundColor Green

Write-Host "`nCHANGE DETAILS:" -ForegroundColor White
Write-Host "  Total fields changed across all domains: $(($comparisonResults | Measure-Object -Property Changed_Fields_Count -Sum).Sum)" -ForegroundColor Gray

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