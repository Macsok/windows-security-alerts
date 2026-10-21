<#
.SYNOPSIS
Configures Discord locally and installs PSDsHook if needed.
.DESCRIPTION
Preserves other JSON settings. Prompts for a webhook without displaying it and
saves it only in the local configuration. Does not send a test message.
.PARAMETER ConfigPath
Path to an ignored local JSON configuration; defaults to config.local.json.
.EXAMPLE
.\tools\Configure-Discord.ps1
#>
[CmdletBinding()]
param([string]$ConfigPath='')
$repo=Split-Path $PSScriptRoot
. "$repo/Common.ps1"
if (!$ConfigPath) { $ConfigPath=Join-Path $repo 'config.local.json' }
$ConfigPath=[IO.Path]::GetFullPath($ConfigPath)
if ([IO.Path]::GetFileName($ConfigPath) -eq 'config.example.json') {
    throw 'Use config.local.json, not the shared configuration template.'
}
if (!(Test-Path -LiteralPath $ConfigPath)) {
    Copy-Item -LiteralPath (Join-Path $repo 'config.example.json') -Destination $ConfigPath
}
$config=Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (!$config.PSObject.Properties['Discord']) {
    $template=Get-Content (Join-Path $repo 'config.example.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $config | Add-Member -NotePropertyName Discord -NotePropertyValue $template.Discord
}
foreach ($entry in @{Enabled=$false;WebhookUrl='';ThumbnailUrl=''}.GetEnumerator()) {
    if (!$config.Discord.PSObject.Properties[$entry.Key]) {
        $config.Discord | Add-Member -NotePropertyName $entry.Key -NotePropertyValue $entry.Value
    }
}
Write-Host 'Webhook config:'
$answer=Read-Host 'Discord option On? (Y/N)'
if ($answer -notin @('Y','Yes')) {
    $config.Discord.Enabled=$false
    Save-JsonAtomic $ConfigPath $config
    Write-Host 'Discord disabled. Other settings were preserved.'
    return
}
$secret=Read-Host 'Paste your NEW webhook link (hidden; Enter keeps the saved link)' -AsSecureString
$url=[string]$config.Discord.WebhookUrl
if ($secret.Length) {
    $credential=New-Object Management.Automation.PSCredential('webhook',$secret)
    $url=$credential.GetNetworkCredential().Password.Trim()
}
if ($url -notmatch '^https://(?:discord\.com|discordapp\.com)/api/webhooks/\d+/[A-Za-z0-9_-]+/?$') {
    throw 'Invalid webhook link. Configuration was not changed.'
}
if (!(Get-Module -ListAvailable -Name PSDsHook)) {
    Write-Host 'Installing PSDsHook for the current Windows account...'
    $previousProtocol=[Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol=$previousProtocol -bor [Net.SecurityProtocolType]::Tls12
        $provider=Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue
        if (!$provider -or ($provider | Sort-Object Version -Descending | Select-Object -First 1).Version -lt [version]'2.8.5.201') {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force -ErrorAction Stop | Out-Null
        }
        Install-Module -Name PSDsHook -Scope CurrentUser -Repository PSGallery -Force -ErrorAction Stop
    } finally { [Net.ServicePointManager]::SecurityProtocol=$previousProtocol }
}
$config.Discord.Enabled=$true
$config.Discord.WebhookUrl=$url
Save-JsonAtomic $ConfigPath $config
Write-Host 'Discord config saved. No test message was sent.'
Write-Host 'LIVE will send all pending Discord alerts with this configuration.'
