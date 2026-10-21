[CmdletBinding()]
param([string]$ConfigPath='', [switch]$SendEmail, [switch]$SetupMail, [switch]$InstallTask,
    [ValidateRange(1,86400)][int]$IntervalSeconds=5)
$ErrorActionPreference='Stop'
$intervalOverride=$PSBoundParameters.ContainsKey('IntervalSeconds')
if (!$ConfigPath) { $ConfigPath=Join-Path $PSScriptRoot 'config.local.json' }
$ConfigPath=[IO.Path]::GetFullPath($ConfigPath)
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$administrator=([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$administrator) {
    $arguments='-NoProfile -ExecutionPolicy Bypass -File "{0}" -ConfigPath "{1}"' -f $PSCommandPath,$ConfigPath
    if ($SendEmail) { $arguments+=' -SendEmail' }; if ($SetupMail) { $arguments+=' -SetupMail' }; if ($InstallTask) { $arguments+=' -InstallTask' }
    if ($intervalOverride) { $arguments+=" -IntervalSeconds $IntervalSeconds" }
    Write-Host 'Windows will request administrator access to read the Security event log.'
    # This interactive console displays setup prompts and lets the user stop monitoring.
    $child=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $arguments -Verb RunAs -WindowStyle Normal -WorkingDirectory $PSScriptRoot -PassThru
    $child.WaitForExit()
    exit $child.ExitCode
}
try {
    . "$PSScriptRoot/Common.ps1"
    . "$PSScriptRoot/Send-Notification.ps1"
    if (!(Test-Path -LiteralPath $ConfigPath)) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'config.example.json') -Destination $ConfigPath }
    $config=Read-MonitorConfig $ConfigPath
    if ($SetupMail -or ($SendEmail -and !(Get-SmtpReadiness $config.Smtp).Ready)) {
        & "$PSScriptRoot/tools/Configure-Gmail.ps1" -ConfigPath $ConfigPath
    }
    if ($InstallTask) {
        & "$PSScriptRoot/tools/Register-MonitorTask.ps1" -ConfigPath $ConfigPath -SendEmail:$SendEmail
        return
    }
    $loopOptions=@{Mode='LIVE';ConfigPath=$ConfigPath;SendEmail=$SendEmail;OpenDashboard=$true}
    if ($intervalOverride) { $loopOptions.IntervalSeconds=$IntervalSeconds }
    & "$PSScriptRoot/Start-Monitor.ps1" @loopOptions
} catch {
    Write-Host "Unable to start LIVE: $($_.Exception.Message)" -ForegroundColor Red
    [void](Read-Host 'Press Enter to close this window')
    exit 1
}
