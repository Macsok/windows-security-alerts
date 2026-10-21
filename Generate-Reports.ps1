. "$PSScriptRoot/Common.ps1"

function ConvertTo-SafeCsvText {
    param($Value)
    $text = [string]$Value
    # Protect spreadsheets from formulas in untrusted account names.
    if ($text -match '^\s*[=+@\-]' -or $text -match '^[\t\r\n]') { return "'$text" }
    return $text
}

function ConvertTo-ReportTable {
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
    $healthSection=''; $lastRun=''
    if ($null -ne $Status) {
        $lastRun=[Net.WebUtility]::HtmlEncode([string]$Status.LastAttemptUtc)
        $labels=@{OK='Monitoring is running';DEGRADED='Monitoring needs attention';ERROR='Event logs are unavailable';DEMO='Synthetic demonstration data'}
        $healthLabel=[Net.WebUtility]::HtmlEncode([string]$labels[$Status.Health])
        $healthCss=if ($Status.Health -in @('ERROR','DEGRADED')) {'problem'} else {'healthy'}
        $sourceRows=@($Status.Sources | ForEach-Object { [pscustomobject]@{LogName=$_.Name;Status=$_.Status;ReadEvents=$_.ReadEvents;LastSuccessUtc=$_.LastSuccessUtc;Information=$_.Error} })
        $sourceTable=ConvertTo-ReportTable $sourceRows @('LogName','Status','ReadEvents','LastSuccessUtc','Information')
        $mailInfo=[Net.WebUtility]::HtmlEncode([string]$Status.SmtpMessage)
        $pendingText=[Net.WebUtility]::HtmlEncode([string]$Status.PendingNotifications)
        $healthSection="<section class='$healthCss'><h2 id='health-label'>$healthLabel</h2><p id='freshness' data-last-run='$lastRun'>Last cycle UTC: $lastRun. Refreshes automatically every 5 seconds.</p>$sourceTable<p><strong>Notifications:</strong> $mailInfo Pending: $pendingText.</p></section>"
    }
    $recentRows=@($State.Events | Sort-Object TimeCreated -Descending | Select-Object -First 50 | ForEach-Object {
        [pscustomobject]@{TimeUtc=$_.TimeCreated;LogName=$_.LogName;EventId=$_.EventId;RecordId=$_.RecordId;Account=$_.Account;IpAddress=$_.IpAddress}
    })
    $recentTable=ConvertTo-ReportTable $recentRows @('TimeUtc','LogName','EventId','RecordId','Account','IpAddress')
    $html = @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="5">
<title>Windows Security Monitoring System</title>
<style>
:root{font-family:Segoe UI,Arial,sans-serif;color:#17293a;background:#eef3f8}body{margin:0}header{background:#102b46;color:white;padding:38px max(24px,5vw)}header p{color:#c5d5e5}h1{font-size:30px;max-width:850px;margin:14px 0}h2{font-size:20px}main{padding:28px max(24px,5vw)}.tag{letter-spacing:2px;font-size:12px;color:#80e0c6}.cards,.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px}.card,section{background:white;border:1px solid #d4dfe9;border-radius:12px;padding:22px;margin-bottom:24px}.number{font-size:38px;font-weight:650;margin-top:8px}.muted{color:#597086}section .table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;background:#edf3f8;color:#3b5268}td,th{padding:12px;border-bottom:1px solid #e1e8ef;overflow-wrap:anywhere}tr.high td:first-child{border-left:4px solid #d23b48}tr.high{background:#fff5f5}.grid{grid-template-columns:1fr 1fr}footer{font-size:13px;color:#597086;margin:10px 0 30px}@media(max-width:760px){.cards,.grid{grid-template-columns:1fr}h1{font-size:24px}}@media print{header{background:white;color:black}.card,section{break-inside:avoid}}
.problem{border-left:6px solid #d23b48}.healthy{border-left:6px solid #147d64}.stale{color:#a01928;font-weight:bold}
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
(function(){var node=document.getElementById('freshness');if(!node)return;var last=Date.parse(node.dataset.lastRun);if(!Number.isFinite(last))return;if(Date.now()-last>180000){node.textContent='NO UPDATE FOR OVER 3 MINUTES. Check the monitoring process or Task Scheduler.';node.className='stale';document.getElementById('health-label').textContent='Monitor data is out of date';}})();
</script></body></html>
"@
    Write-TextAtomic (Join-Path $reportDir 'dashboard.html') $html
    # Rebuilding from persistent state preserves history without duplicate lines after a crash.
    $lines = @($State.Alerts | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 })
    Write-TextAtomic (Join-Path $Root 'logs/alerts.log') (($lines -join [Environment]::NewLine) + [Environment]::NewLine)
    [pscustomobject]@{Html=(Join-Path $reportDir 'dashboard.html');Csv=(Join-Path $reportDir 'incidents.csv');AlertLog=(Join-Path $Root 'logs/alerts.log')}
}
