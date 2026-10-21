[CmdletBinding(SupportsShouldProcess=$true)]
param([string]$ConfigPath='', [switch]$SendEmail, [Management.Automation.PSCredential]$TaskCredential)
$repo=Split-Path $PSScriptRoot
. "$repo/Common.ps1"
if (!$ConfigPath) { $ConfigPath=Join-Path $repo 'config.local.json' }
$configFullPath=(Resolve-Path -LiteralPath $ConfigPath).Path
[void](Read-MonitorConfig $configFullPath)
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if (!$PSCmdlet.ShouldProcess('OSO-Live', 'Create a task that runs every minute, including when logged off')) { return }
if (!([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run Start-Live.ps1 -InstallTask as administrator.' }
if (!$TaskCredential) { $TaskCredential=Get-Credential -UserName $identity.Name -Message 'WINDOWS account password for Task Scheduler (not your Gmail password or PIN). The account needs access to Security and Gmail credentials.' }
if (!$TaskCredential -or $TaskCredential.UserName -ne $identity.Name) { throw 'Use the Windows account used to configure Gmail.' }
$arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Mode LIVE -ConfigPath "{1}" -IntervalSeconds 60' -f (Join-Path $repo 'main.ps1'),$configFullPath
if ($SendEmail) { $arguments+=' -SendEmail' }
$action=New-ScheduledTaskAction -Execute (Join-Path $PSHOME 'powershell.exe') -Argument $arguments -WorkingDirectory $repo
$trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
$settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
$principal=New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Password -RunLevel Highest
$definition=New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal
Register-ScheduledTask -TaskName 'OSO-Live' -InputObject $definition -User $TaskCredential.UserName -Password $TaskCredential.GetNetworkCredential().Password -Force | Out-Null
Start-ScheduledTask -TaskName 'OSO-Live'
Write-Host 'OSO-Live task started. It runs every minute, including when logged off. Do not run the Start-Monitor loop at the same time.'
