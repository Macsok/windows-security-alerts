<#
.SYNOPSIS
Loads CSV, HTML and warning-log export functions.
.DESCRIPTION
Loads CSV, HTML and warning-log export functions.
.EXAMPLE
. .\Generate-Reports.ps1; Export-MonitorReports -State $state -Root .\runtime\demo
#>
. "$PSScriptRoot/Common.ps1"

function ConvertTo-SafeCsvText {
    <#
    .SYNOPSIS
    Escapes spreadsheet formula prefixes in untrusted CSV values.
    .DESCRIPTION
    Escapes spreadsheet formula prefixes in untrusted CSV values.
    .PARAMETER Value
    Value to serialize or encode.
    .EXAMPLE
    ConvertTo-SafeCsvText -Value '=untrusted account'
    #>

    param($Value)
    $text = [string]$Value
    # Protect spreadsheets from formulas in untrusted account names.
    if ($text -match '^\s*[=+@\-]' -or $text -match '^[\t\r\n]') { return "'$text" }
    return $text
}

function ConvertTo-ReportTable {
    <#
    .SYNOPSIS
    Builds an HTML table with encoded cell values.
    .DESCRIPTION
    Builds an HTML table with encoded cell values.
    .PARAMETER Rows
    Objects to display as table rows.
    .PARAMETER Columns
    Property names in the required column order.
    .EXAMPLE
    ConvertTo-ReportTable -Rows @() -Columns @('Account','EventId')
    #>

    param([AllowEmptyCollection()][object[]]$Rows, [string[]]$Columns)
    $html = '<div class="table-wrap"><table><thead><tr>'
    foreach ($column in $Columns) { $html += '<th>' + [Net.WebUtility]::HtmlEncode($column) + '</th>' }
    $html += '</tr></thead><tbody>'
    foreach ($row in $Rows) {
        $css = ''; if ($row.PSObject.Properties['Severity'] -and $row.Severity -eq 'High') { $css = ' class="high"' }
        $html += "<tr$css>"
        foreach ($column in $Columns) { $html += '<td>' + [Net.WebUtility]::HtmlEncode([string]$row.$column) + '</td>' }
        $html += '</tr>'
    }
    if ($Rows.Count -eq 0) { $html += '<tr><td colspan="' + $Columns.Count + '">No data</td></tr>' }
    return $html + '</tbody></table></div>'
}

function Export-MonitorReports {
    <#
    .SYNOPSIS
    Exports incidents, events, dashboard and warning log from saved state.
    .DESCRIPTION
    Exports incidents, events, dashboard and warning log from saved state.
    .PARAMETER State
    Monitoring state containing saved events, alerts and delivery receipts.
    .PARAMETER Root
    Output folder for the selected mode, or source folder for sharing tools.
    .PARAMETER Mode
    Selects DEMO or LIVE, or Test previews versus Send delivery for email functions.
    .PARAMETER Status
    Current collection, notification and refresh status for the dashboard.
    .EXAMPLE
    Export-MonitorReports -State $state -Root .\runtime\demo -Mode DEMO
    #>

    [CmdletBinding()]
    param($State, [Parameter(Mandatory)][string]$Root, [ValidateSet('DEMO','LIVE')][string]$Mode='DEMO', $Status=$null)
    $reportDir = Join-Path $Root 'reports'; [void][IO.Directory]::CreateDirectory($reportDir)
    $columns = @('TimeCreated','IncidentType','EventId','IpAddress','Account','AttemptCount','Severity','AlertId')
    $rows = @($State.Alerts | ForEach-Object {
        [pscustomobject][ordered]@{
            TimeCreated=$_.TimeCreated; IncidentType=$_.Type; EventId=$_.EventId; IpAddress=$_.IpAddress
            Account=$_.Account; AttemptCount=$_.Count; Severity=$_.Severity; AlertId=$_.AlertId
        }
    })
    $csvRows = @($rows | ForEach-Object {
        $copy = [ordered]@{}; foreach ($column in $columns) { $copy[$column] = ConvertTo-SafeCsvText $_.$column }; [pscustomobject]$copy
    })
    if ($csvRows.Count) { $csvRows | Export-Csv -LiteralPath (Join-Path $reportDir 'incidents.csv') -NoTypeInformation -Encoding UTF8 }
    else { Write-Utf8File (Join-Path $reportDir 'incidents.csv') (($columns | ForEach-Object {'"' + $_ + '"'}) -join ',') }
    $eventRows = @($State.Events | ForEach-Object {
        [pscustomobject]@{TimeCreated=$_.TimeCreated;EventId=$_.EventId;RecordId=$_.RecordId;LogName=$_.LogName;IpAddress=$_.IpAddress;Account=(ConvertTo-SafeCsvText $_.Account);LogonType=$_.LogonType}
    })
    if ($eventRows.Count) { $eventRows | Export-Csv -LiteralPath (Join-Path $reportDir 'events.csv') -NoTypeInformation -Encoding UTF8 }
    else { Write-Utf8File (Join-Path $reportDir 'events.csv') '"TimeCreated","EventId","RecordId","LogName","IpAddress","Account","LogonType"' }
    $ips = @($State.Alerts | Where-Object Dimension -eq 'IP' | Group-Object Entity | ForEach-Object { [pscustomobject]@{IpAddress=$_.Name;IncidentCount=$_.Count} })
    $accounts = @($State.Alerts | Where-Object Dimension -eq 'Account' | Group-Object Entity | ForEach-Object { [pscustomobject]@{Account=$_.Name;IncidentCount=$_.Count} })
    $incidentTable = ConvertTo-ReportTable $rows $columns
    $ipTable = ConvertTo-ReportTable $ips @('IpAddress','IncidentCount')
    $accountTable = ConvertTo-ReportTable $accounts @('Account','IncidentCount')
    $failures = @($State.Events | Where-Object EventId -eq 4625).Count
    $generated = [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss UTC')
    $healthSection=''; $lastRun=''; $refreshSeconds=1; $staleSeconds=180
    if ($null -ne $Status) {
        if ($Status.PSObject.Properties['DashboardRefreshSeconds']) { $refreshSeconds=[int]$Status.DashboardRefreshSeconds }
        $refreshSeconds=[Math]::Max(1,[Math]::Min(60,$refreshSeconds))
        if ($Status.PSObject.Properties['PollIntervalSeconds']) { $staleSeconds=[Math]::Max(20,3*[int]$Status.PollIntervalSeconds) }
        $cadence=if ($Status.PSObject.Properties['PollIntervalSeconds']) { "Logs checked every $($Status.PollIntervalSeconds) seconds. " } else { '' }
        $lastRun=[Net.WebUtility]::HtmlEncode([string]$Status.LastAttemptUtc)
        $labels=@{OK='Monitoring is running';DEGRADED='Monitoring needs attention';ERROR='Event logs are unavailable';DEMO='Synthetic demonstration data'}
        $healthLabel=[Net.WebUtility]::HtmlEncode([string]$labels[$Status.Health])
        $healthCss=if ($Status.Health -in @('ERROR','DEGRADED')) {'problem'} else {'healthy'}
        $sourceRows=@($Status.Sources | ForEach-Object { [pscustomobject]@{LogName=$_.Name;Status=$_.Status;ReadEvents=$_.ReadEvents;LastSuccessUtc=$_.LastSuccessUtc;Information=$_.Error} })
        $sourceTable=ConvertTo-ReportTable $sourceRows @('LogName','Status','ReadEvents','LastSuccessUtc','Information')
        $mailInfo=[Net.WebUtility]::HtmlEncode([string]$Status.SmtpMessage)
        $pendingText=[Net.WebUtility]::HtmlEncode([string]$Status.PendingNotifications)
        $healthSection="<section class='$healthCss'><h2 id='health-label'>$healthLabel</h2><p id='freshness' data-last-run='$lastRun'>Last cycle UTC: $lastRun. $cadence Dashboard refreshes every $refreshSeconds seconds.</p>$sourceTable<p><strong>Notifications:</strong> $mailInfo Pending: $pendingText.</p></section>"
    }
    $recentRows=@($State.Events | Sort-Object TimeCreated -Descending | Select-Object -First 50 | ForEach-Object {
        [pscustomobject]@{TimeUtc=$_.TimeCreated;LogName=$_.LogName;EventId=$_.EventId;RecordId=$_.RecordId;Account=$_.Account;IpAddress=$_.IpAddress}
    })
    $recentTable=ConvertTo-ReportTable $recentRows @('TimeUtc','LogName','EventId','RecordId','Account','IpAddress')
    $html = @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="$refreshSeconds">
<title>Windows Security Monitoring System</title>
<style>
body{font-family:Arial,sans-serif;margin:24px;color:#222;background:white}
h1{font-size:24px}h2{font-size:18px}section{margin:24px 0}
.cards{display:flex;gap:32px}.number{font-size:24px;font-weight:bold}
.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:7px;border:1px solid #ccc;text-align:left;overflow-wrap:anywhere}
th{background:#eee}tr.high{background:#fee}.problem,.stale{color:#a00}
.tag,.muted,footer{color:#555}footer{margin-top:24px}
</style></head><body><header><span class="tag">OSO / SECURITY MONITOR / $Mode</span>
<h1>Windows Security Monitoring System</h1><p>Report generated: $generated</p></header>
<main>$healthSection<div class="cards"><div class="card"><span class="muted">Events analyzed</span><div class="number">$(@($State.Events).Count)</div></div>
<div class="card"><span class="muted">Incidents detected</span><div class="number">$(@($State.Alerts).Count)</div></div>
<div class="card"><span class="muted">Failed logons</span><div class="number">$failures</div></div></div>
<section><h2>Incidents and warnings</h2><p class="muted">Red marker: high severity. All times are UTC. Attempt counts reflect the threshold crossing.</p>$incidentTable</section>
<div class="grid"><section><h2>Suspicious IP addresses</h2>$ipTable</section><section><h2>Suspicious accounts</h2>$accountTable</section></div>
<section><h2>Latest 50 events</h2>$recentTable</section>
<footer>Mode: $Mode. History includes saved runs. IP and account alerts are independent. DEMO uses synthetic data only.</footer></main>
<script>
(function(){var node=document.getElementById('freshness');if(!node)return;var last=Date.parse(node.dataset.lastRun);if(!Number.isFinite(last))return;if(Date.now()-last>$($staleSeconds*1000)){node.textContent='NO RECENT UPDATE. Check the monitoring process or Task Scheduler.';node.className='stale';document.getElementById('health-label').textContent='Monitor data is out of date';}})();
</script></body></html>
"@
    Write-TextAtomic (Join-Path $reportDir 'dashboard.html') $html
    # Rebuilding from persistent state preserves history without duplicate lines after a crash.
    $lines = @($State.Alerts | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 })
    Write-TextAtomic (Join-Path $Root 'logs/alerts.log') (($lines -join [Environment]::NewLine) + [Environment]::NewLine)
    [pscustomobject]@{Html=(Join-Path $reportDir 'dashboard.html');Csv=(Join-Path $reportDir 'incidents.csv');AlertLog=(Join-Path $Root 'logs/alerts.log')}
}
