<#
.SYNOPSIS
Runs one DEMO or LIVE monitoring cycle.
.DESCRIPTION
Runs one DEMO or LIVE monitoring cycle.
.PARAMETER Mode
Selects DEMO or LIVE, or Test previews versus Send delivery for email functions.
.PARAMETER ConfigPath
Path to local JSON configuration; defaults to config.local.json.
.PARAMETER SendEmail
Enables real SMTP delivery of all pending alerts; omitted means local previews.
.PARAMETER IntervalSeconds
Polling interval in seconds; zero uses the configured interval where supported.
.EXAMPLE
.\main.ps1 -Mode DEMO
#>
[CmdletBinding()]
param([ValidateSet('LIVE','DEMO')][string]$Mode='LIVE', [string]$ConfigPath='', [switch]$SendEmail,
    [ValidateRange(0,86400)][int]$IntervalSeconds=0)
. "$PSScriptRoot/Monitor.ps1"
if (!$ConfigPath) {
    $ConfigPath=Join-Path $PSScriptRoot 'config.local.json'
    if (!(Test-Path -LiteralPath $ConfigPath)) { $ConfigPath=Join-Path $PSScriptRoot 'config.example.json' }
}
try {
    $result=Invoke-MonitorCycle -Mode $Mode -ConfigPath $ConfigPath -SendEmail:$SendEmail -IntervalSeconds $IntervalSeconds
    $result
    if ($result.ExitCode -ne 0) { exit $result.ExitCode }
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
}
