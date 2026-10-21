<#
.SYNOPSIS
Loads the modules and exposes a single monitoring cycle.
.DESCRIPTION
Loads the modules and exposes a single monitoring cycle.
.EXAMPLE
. .\Monitor.ps1; Invoke-MonitorCycle -Mode DEMO -ConfigPath .\config.local.json
#>
Add-Type -AssemblyName System.Net.Http
. "$PSScriptRoot/Get-Logs.ps1"
. "$PSScriptRoot/Detect-Attacks.ps1"
. "$PSScriptRoot/Generate-Reports.ps1"
. "$PSScriptRoot/Send-Notification.ps1"
. "$PSScriptRoot/New-DemoEvents.ps1"

function Invoke-MonitorCycle {
    <#
    .SYNOPSIS
    Runs collection, detection, reports and pending notifications once.
    .DESCRIPTION
    Runs collection, detection, reports and pending notifications once.
    .PARAMETER Mode
    Selects DEMO or LIVE, or Test previews versus Send delivery for email functions.
    .PARAMETER ConfigPath
    Path to local JSON configuration; defaults to config.local.json.
    .PARAMETER SendEmail
    Enables real SMTP delivery of all pending alerts; omitted means local previews.
    .PARAMETER IntervalSeconds
    Effective polling interval for dashboard status; zero uses configuration.
    .EXAMPLE
    Invoke-MonitorCycle -Mode DEMO -ConfigPath .\config.local.json
    #>

    [CmdletBinding()]
    param([ValidateSet('LIVE','DEMO')][string]$Mode='LIVE', [Parameter(Mandatory)][string]$ConfigPath, [switch]$SendEmail,
        [ValidateRange(0,86400)][int]$IntervalSeconds=0)
    $config=Read-MonitorConfig $ConfigPath
    $root=Join-Path ([IO.Path]::GetFullPath($config.OutputRoot)) $Mode.ToLowerInvariant()
    [void][IO.Directory]::CreateDirectory($root)
    $lock=$null
    try {
        try { $lock=[IO.File]::Open((Join-Path $root 'monitor.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None) }
        catch { throw 'Another instance is running or the output directory is inaccessible.' }
        $path=Join-Path $root 'state.json'; $state=Read-MonitorState $path
        $end=[DateTime]::UtcNow
        if ($Mode -eq 'LIVE') {
            $batch=Get-LiveLogBatch -State $state -Config $config -EndTime $end
            $events=@($batch.Events); $sources=@($batch.Sources); $health=$batch.Status
        } else {
            $events=@(Get-DemoEvents); $sources=@([pscustomobject]@{Name='DEMO';Status='SYNTHETIC';ReadEvents=$events.Count;LastSuccessUtc=$end.ToString('o');Error=''})
            $state.LastScanUtc=$end.ToString('o'); $health='DEMO'
        }
        $new=@(Update-MonitorDetection -State $state -Events $events -Threshold $config.Threshold -WindowSeconds $config.WindowSeconds)
        Save-JsonAtomic $path $state

        # Discord: retry saved alerts without delivery receipts.
        $discordOn = $Mode -eq 'LIVE' -and $config.PSObject.Properties['Discord'] -and $config.Discord.PSObject.Properties['Enabled'] -and $config.Discord.Enabled -and $config.Discord.WebhookUrl
        if ($discordOn) {
            $sentToDiscord=@{}; foreach ($delivery in $state.Deliveries) { if ($delivery.Mode -eq 'Discord') { $sentToDiscord[$delivery.AlertId]=$true } }
            $discordAlerts=@($state.Alerts | Where-Object { !$sentToDiscord.ContainsKey($_.AlertId) })
            if ($discordAlerts.Count -gt 0) {
                try {
                    . "$PSScriptRoot/Send-Discord.ps1"
                    $thumb=if ($config.Discord.PSObject.Properties['ThumbnailUrl']) { [string]$config.Discord.ThumbnailUrl } else { '' }
                    Send-DiscordAlert -Alerts $discordAlerts -WebhookUrl ([string]$config.Discord.WebhookUrl) -Mode $Mode -ThumbnailUrl $thumb
                    foreach ($alert in $discordAlerts) { $state.Deliveries=@($state.Deliveries)+[pscustomobject]@{AlertId=$alert.AlertId;Mode='Discord';TimeUtc=[DateTime]::UtcNow.ToString('o')} }
                    Save-JsonAtomic $path $state
                } catch {
                    # Do not log the exception text: it may contain the webhook URL.
                    Write-Diagnostic $root "DISCORD_FAILED ($($_.Exception.GetType().Name)): check the PSDsHook module, webhook URL and network. Alerts will be retried."
                }
            }
        }

        $mailMode=if ($SendEmail) {'Send'} else {'Test'}
        $smtpMessage=if ($SendEmail) {'Waiting to send notifications'} else {'TEST: saving .eml files; email delivery is disabled.'}
        $status=[pscustomobject]@{Mode=$Mode;Health=$health;LastAttemptUtc=$end.ToString('o');Sources=$sources;NotificationMode=$mailMode;SmtpMessage=$smtpMessage;PendingNotifications=0}
        $status | Add-Member -NotePropertyName PollIntervalSeconds -NotePropertyValue $(if ($IntervalSeconds) {$IntervalSeconds} else {$config.PollIntervalSeconds})
        $status | Add-Member -NotePropertyName DashboardRefreshSeconds -NotePropertyValue $config.DashboardRefreshSeconds
        # Write reports and the alert log before contacting SMTP.
        $reports=Export-MonitorReports -State $state -Root $root -Mode $Mode -Status $status
        $canNotify=$true
        if ($SendEmail) {
            $readiness=Get-SmtpReadiness $config.Smtp
            $canNotify=$readiness.Ready; $status.SmtpMessage=$readiness.Message
            if (!$canNotify) { Write-Diagnostic $root 'SMTP_NOT_READY: run the local Gmail setup.' }
        }
        if ($canNotify) { Invoke-PendingNotifications -State $state -Smtp $config.Smtp -Root $root -StatePath $path -Mode $mailMode }
        $delivered=@{}; foreach ($delivery in $state.Deliveries) { if ($delivery.Mode -eq $mailMode) { $delivered[$delivery.AlertId]=$true } }
        $pending=@($state.Alerts | Where-Object { !$delivered.ContainsKey($_.AlertId) }).Count
        $status.PendingNotifications=$pending
        if ($SendEmail -and $canNotify -and $pending -gt 0) { $status.SmtpMessage='SMTP error. Notifications are queued for retry; see diagnostic.log.' }
        elseif ($SendEmail -and $canNotify -and @($state.Alerts).Count -gt 0) { $status.SmtpMessage='SMTP has accepted all saved alerts. Check the recipient inbox.' }
        elseif ($SendEmail -and $canNotify) { $status.SmtpMessage='No pending alerts. SMTP delivery has not been attempted.' }
        if ($SendEmail -and (!$canNotify -or $pending -gt 0) -and $status.Health -ne 'ERROR') { $status.Health='DEGRADED' }
        Save-JsonAtomic (Join-Path $root 'status.json') $status
        $reports=Export-MonitorReports -State $state -Root $root -Mode $Mode -Status $status
        foreach ($source in $sources) { if ($source.Status -eq 'ERROR') { Write-Diagnostic $root "SOURCE_UNAVAILABLE [$($source.Name)]: $($source.Error)" } }
        $code=if ($status.Health -in @('ERROR','DEGRADED')) {2} else {0}
        [pscustomobject]@{Mode=$Mode;Health=$status.Health;ReadEvents=$events.Count;StoredEvents=@($state.Events).Count;NewAlerts=$new.Count;TotalAlerts=@($state.Alerts).Count;NotificationMode=$mailMode;PendingNotifications=$pending;Sources=$sources;SmtpMessage=$status.SmtpMessage;Html=$reports.Html;Csv=$reports.Csv;ExitCode=$code}
    } catch {
        if ($lock) { Write-Diagnostic $root 'RUN_FAILED: configuration, report, or state error. Do not reset state.json.' }
        throw
    } finally { if ($lock) { $lock.Dispose() } }
}
