<#
.SYNOPSIS
Demonstrates additional detection rules using synthetic events only.
.DESCRIPTION
Creates reports and local email previews in runtime/rules-demo by default.
Does not read real logs, change accounts, send email or contact Discord.
.PARAMETER OutputRoot
Separate demonstration folder; defaults to runtime/rules-demo in the project.
.EXAMPLE
.\tools\Demo-ExtraRules.ps1
#>
[CmdletBinding()]
param([string]$OutputRoot='')
$repo=Split-Path $PSScriptRoot
. "$repo/Monitor.ps1"
if (!$OutputRoot) { $OutputRoot=Join-Path $repo 'runtime/rules-demo' }
$OutputRoot=[IO.Path]::GetFullPath($OutputRoot)
$statePath=Join-Path $OutputRoot 'state.json'
$lock=$null
try {
    [void][IO.Directory]::CreateDirectory($OutputRoot)
    $lock=[IO.File]::Open((Join-Path $OutputRoot 'monitor.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $state=Read-MonitorState $statePath
    $events=@(Get-ExtraRuleDemoEvents)
    $new=@(Update-MonitorDetection -State $state -Events $events)
    Save-JsonAtomic $statePath $state
    $reports=Export-MonitorReports -State $state -Root $OutputRoot -Mode DEMO
    Invoke-PendingNotifications -State $state -Smtp $null -Root $OutputRoot -StatePath $statePath -Mode Test
    [pscustomobject]@{Mode='DEMO';Events=$events.Count;NewAlerts=$new.Count;TotalAlerts=@($state.Alerts).Count;MessagesSent=0;Html=$reports.Html;Csv=$reports.Csv}
    $state.Alerts | Select-Object Type,Count,Severity
} finally { if ($lock) { $lock.Dispose() } }
