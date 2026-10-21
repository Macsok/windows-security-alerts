[CmdletBinding()]
param([ValidateSet('LIVE','DEMO')][string]$Mode='LIVE', [string]$ConfigPath='', [switch]$SendEmail)
. "$PSScriptRoot/Monitor.ps1"
if (!$ConfigPath) {
    $ConfigPath=Join-Path $PSScriptRoot 'config.local.json'
    if (!(Test-Path -LiteralPath $ConfigPath)) { $ConfigPath=Join-Path $PSScriptRoot 'config.example.json' }
}
try {
    $result=Invoke-MonitorCycle -Mode $Mode -ConfigPath $ConfigPath -SendEmail:$SendEmail
    $result
    if ($result.ExitCode -ne 0) { exit $result.ExitCode }
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
}