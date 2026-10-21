<#
.SYNOPSIS
Migrates saved report labels to English without resending notifications.
.DESCRIPTION
Migrates saved report labels to English without resending notifications.
.PARAMETER ConfigPath
Path to local JSON configuration; defaults to config.local.json.
.PARAMETER Mode
Selects DEMO or LIVE, or Test previews versus Send delivery for email functions.
.EXAMPLE
.\tools\Update-EnglishReports.ps1 -Mode DEMO -ConfigPath .\config.local.json
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ConfigPath, [ValidateSet('DEMO','LIVE')][string[]]$Mode=@('DEMO','LIVE'))
$repo=Split-Path $PSScriptRoot
. "$repo/Generate-Reports.ps1"
. "$repo/Send-Notification.ps1"
$config=Read-MonitorConfig $ConfigPath
foreach ($currentMode in $Mode) {
    $root=Join-Path $config.OutputRoot $currentMode.ToLowerInvariant()
    $statePath=Join-Path $root 'state.json'
    if (!(Test-Path -LiteralPath $statePath)) { continue }
    $lock=$null
    try {
        $lock=[IO.File]::Open((Join-Path $root 'monitor.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $state=Read-MonitorState $statePath
        $statusPath=Join-Path $root 'status.json'; $status=$null
        if (Test-Path -LiteralPath $statusPath) {
            $status=Get-Content -LiteralPath $statusPath -Raw -Encoding UTF8 | ConvertFrom-Json
            Update-StatusLanguage $status
            Save-JsonAtomic $statusPath $status
        }
        Save-JsonAtomic $statePath $state
        $report=Export-MonitorReports -State $state -Root $root -Mode $currentMode -Status $status
        foreach ($alert in $state.Alerts) {
            # Rebuild existing local previews only. Never send or change delivery receipts.
            if (Test-Path -LiteralPath (Join-Path $root "mail-test/$($alert.AlertId).eml")) {
                [void](Send-AlertNotification -Alert $alert -Root $root -Mode Test)
            }
        }
        [pscustomobject]@{Mode=$currentMode;Alerts=$state.Alerts.Count;Deliveries=$state.Deliveries.Count;Html=$report.Html;EmailSent=$false}
    } finally { if ($null -ne $lock) { $lock.Dispose() } }
}
