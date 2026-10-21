[CmdletBinding()]
param([string]$ConfigPath = '')

Add-Type -AssemblyName System.Net.Http
# Sends ONE sample message to Discord to verify PSDsHook and the webhook. Touches no state or logs.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
. "$root/Common.ps1"
if (!$ConfigPath) {
    $ConfigPath = Join-Path $root 'config.local.json'
    if (!(Test-Path -LiteralPath $ConfigPath)) { $ConfigPath = Join-Path $root 'config.example.json' }
}
$config = Read-MonitorConfig $ConfigPath
if (!$config.PSObject.Properties['Discord'] -or !$config.Discord.WebhookUrl) {
    throw 'Set Discord.WebhookUrl in config.local.json first.'
}
if (-not (Get-Module -ListAvailable -Name PSDsHook)) {
    throw 'PSDsHook is not installed. Run: Install-Module PSDsHook -Scope CurrentUser'
}
. "$root/Send-Discord.ps1"
$thumb = if ($config.Discord.PSObject.Properties['ThumbnailUrl']) { [string]$config.Discord.ThumbnailUrl } else { '' }
$sample = [pscustomobject]@{ Type = 'TEST: Excessive failed logons: Account'; Entity = 'testowe'; Count = 6; Severity = 'High' }
Send-DiscordAlert -Alerts @($sample) -WebhookUrl ([string]$config.Discord.WebhookUrl) -Mode 'TEST' -ThumbnailUrl $thumb
Write-Host 'Test message sent. Check your Discord channel.' -ForegroundColor Cyan
