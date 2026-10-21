<#
.SYNOPSIS
Generates shareable reports from synthetic demonstration events.
.DESCRIPTION
Generates shareable reports from synthetic demonstration events.
.EXAMPLE
.\tools\New-ExampleReports.ps1
#>
# Generate synthetic examples for sharing; no SMTP connections or Windows event log access.
$repo=Split-Path $PSScriptRoot
. "$repo/New-DemoEvents.ps1"
. "$repo/Detect-Attacks.ps1"
. "$repo/Generate-Reports.ps1"
. "$repo/Send-Notification.ps1"
$state=New-MonitorState
[void](Update-MonitorDetection -State $state -Events @(Get-DemoEvents))
$root=Join-Path $repo 'examples/demo'
Export-MonitorReports -State $state -Root $root -Mode DEMO
Save-JsonAtomic (Join-Path $root 'events.json') $state.Events
foreach ($alert in $state.Alerts) { [void](Send-AlertNotification -Alert $alert -Root $root -Mode Test) }
