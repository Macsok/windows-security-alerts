[CmdletBinding()]
param([string]$ConfigPath='')
$repo=Split-Path $PSScriptRoot
. "$repo/Common.ps1"
. "$repo/Send-Notification.ps1"
if (!$ConfigPath) { $ConfigPath=Join-Path $repo 'config.local.json' }
$ConfigPath=[IO.Path]::GetFullPath($ConfigPath)
if (!(Test-Path -LiteralPath $ConfigPath)) { Copy-Item -LiteralPath (Join-Path $repo 'config.example.json') -Destination $ConfigPath }
$config=Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
$library=Join-Path $repo 'vendor/mailkit'
if (!(Test-Path (Join-Path $library 'MailKit.dll'))) { & "$PSScriptRoot/Install-MailKit.ps1" }
Import-MailKit $library
Write-Host 'Gmail: enable two-step verification and create an app password at https://myaccount.google.com/apppasswords'
Write-Host 'Enter the app password in the credential dialog. It will be stored outside the repository.'
$sender=Read-Host 'Full Gmail sender address'
[void][MimeKit.MailboxAddress]::Parse($sender)
$recipient=Read-Host 'Recipient address (Enter = the same Gmail address)'
if (!$recipient) { $recipient=$sender }
[void][MimeKit.MailboxAddress]::Parse($recipient)
$credential=Get-Credential -UserName $sender -Message 'Enter the Google app password (16 characters, no spaces)'
if ($null -eq $credential) { throw 'Gmail setup cancelled.' }
if ($credential.UserName -ne $sender) { throw 'The credential username must match the Gmail sender address.' }
$credentialFile=Join-Path $env:LOCALAPPDATA 'OSO/smtp.credential.xml'
[void][IO.Directory]::CreateDirectory((Split-Path $credentialFile))
$credential | Export-Clixml -LiteralPath $credentialFile
$config.Smtp.Host='smtp.gmail.com'; $config.Smtp.Port=587; $config.Smtp.Security='StartTls'
$config.Smtp.From=$sender; $config.Smtp.To=@($recipient); $config.Smtp.CredentialPath=$credentialFile; $config.Smtp.LibraryDirectory=$library
# The configuration contains no password. DPAPI binds the credential file to this Windows account.
Write-Utf8File $ConfigPath ($config | ConvertTo-Json -Depth 10)
Write-Host 'Checking TLS and SMTP authentication (no messages will be sent)...'
$resolved=Read-MonitorConfig $ConfigPath
try { Test-SmtpConnection -Smtp $resolved.Smtp }
catch { throw (Get-SmtpFailureDescription -Exception $_.Exception) }
Write-Host 'Gmail configured. Run LIVE with -SendEmail to send alerts.'
