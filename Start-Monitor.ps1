<#
.SYNOPSIS
Runs monitoring repeatedly until Ctrl+C; email requires SendEmail.
.DESCRIPTION
Runs monitoring repeatedly until Ctrl+C; email requires SendEmail.
.PARAMETER Mode
Selects DEMO or LIVE, or Test previews versus Send delivery for email functions.
.PARAMETER ConfigPath
Path to local JSON configuration; defaults to config.local.json.
.PARAMETER IntervalSeconds
Polling interval in seconds; zero uses the configured interval where supported.
.PARAMETER SendEmail
Enables real SMTP delivery of all pending alerts; omitted means local previews.
.PARAMETER Once
Runs a single cycle and exits.
.PARAMETER OpenDashboard
Opens the generated dashboard in the default browser.
.PARAMETER MaxCycles
Stops after this many cycles; zero keeps running until Ctrl+C.
.EXAMPLE
.\Start-Monitor.ps1 -Mode DEMO -Once
#>
[CmdletBinding()]
param(
    [ValidateSet('LIVE','DEMO')][string]$Mode='LIVE',
    [string]$ConfigPath='',
    [ValidateRange(1,86400)][int]$IntervalSeconds=5,
    [switch]$SendEmail,
    [switch]$Once,
    [switch]$OpenDashboard,
    [ValidateRange(0,1000000)][int]$MaxCycles=0
)
$ErrorActionPreference='Stop'
$intervalOverride=$PSBoundParameters.ContainsKey('IntervalSeconds')
. "$PSScriptRoot/Common.ps1"
if (!$ConfigPath) {
    $ConfigPath=Join-Path $PSScriptRoot 'config.local.json'
    if (!(Test-Path -LiteralPath $ConfigPath)) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'config.example.json') -Destination $ConfigPath }
}
if (!(Test-Path -LiteralPath $ConfigPath)) { throw 'Configuration not found. Copy config.example.json to config.local.json and follow docs/LIVE_SETUP.md.' }
$configFullPath=(Resolve-Path -LiteralPath $ConfigPath).Path
$config=Read-MonitorConfig $configFullPath
if (!$intervalOverride) { $IntervalSeconds=[int]$config.PollIntervalSeconds }
$engine=Join-Path $PSHOME 'powershell.exe'
if (!(Test-Path -LiteralPath $engine)) { $engine=(Get-Command powershell.exe -ErrorAction Stop).Source }
$baseArguments=@('-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $PSScriptRoot 'main.ps1'),'-Mode',$Mode,'-ConfigPath',$configFullPath)
if ($SendEmail) { $baseArguments+='-SendEmail' }
Write-Host "Monitoring $Mode. Cycle interval: approximately $IntervalSeconds seconds. Stop with Ctrl+C."
if ($SendEmail) { Write-Host 'Email delivery is enabled for all pending alerts in this mode.' }
$cycleCount=0; $opened=$false
do {
    if (!$intervalOverride) {
        $config=Read-MonitorConfig $configFullPath
        $IntervalSeconds=[int]$config.PollIntervalSeconds
    }
    $mainArguments=$baseArguments+@('-IntervalSeconds',[string]$IntervalSeconds)
    $timer=[Diagnostics.Stopwatch]::StartNew()
    Write-Host "[$([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))] Starting cycle."
    # Run each cycle in a separate process so main.ps1 failures do not stop the loop.
    # Windows PowerShell 5.1 may represent child process stderr as ErrorRecord.
    $ErrorActionPreference='Continue'
    & $engine @mainArguments
    $runExitCode=$LASTEXITCODE
    $ErrorActionPreference='Stop'
    if ($runExitCode -eq 2) { Write-Warning 'Monitoring is degraded. Check event log and email status on the dashboard.' }
    elseif ($runExitCode -ne 0) { Write-Warning "Cycle exited with code $runExitCode. Check the message and logs/diagnostic.log." }
    if ($OpenDashboard -and !$opened) {
        . "$PSScriptRoot/Common.ps1"
        $config=Read-MonitorConfig $configFullPath
        $dashboard=Join-Path $config.OutputRoot "$($Mode.ToLowerInvariant())/reports/dashboard.html"
        if (Test-Path -LiteralPath $dashboard) { Start-Process -FilePath $dashboard; $opened=$true }
    }
    $cycleCount++
    if ($Once -or ($MaxCycles -gt 0 -and $cycleCount -ge $MaxCycles)) { exit $runExitCode }
    $remaining=[Math]::Max(0,[int](1000*$IntervalSeconds-$timer.ElapsedMilliseconds))
    if ($remaining -gt 0) { Start-Sleep -Milliseconds $remaining }
} while ($true)
