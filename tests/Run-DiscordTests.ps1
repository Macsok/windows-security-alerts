<#
.SYNOPSIS
Tests Discord configuration and failure recovery without sending messages.
.EXAMPLE
.\tests\Run-DiscordTests.ps1
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot
. "$repo/Monitor.ps1"
$testRoot=Join-Path $repo "test-results/discord-$([guid]::NewGuid().ToString('N'))"
$script:passed=0; $script:failed=0
# Construct a synthetic URL only for mocks; never contact this endpoint.
$global:OsoDiscordTestWebhook='https://'+'discord.com/api/webhooks/'+'123456789012345678/'+('test_only_'*4)
function Assert { param([bool]$Value,[string]$Message='Assertion failed') if (!$Value) { throw $Message } }
function Test { param([string]$Name,[scriptblock]$Body)
    try { & $Body; $script:passed++; Write-Host "PASS $Name" }
    catch { $script:failed++; Write-Host "FAIL $Name : $($_.Exception.Message)" }
}
function New-TestConfig { param([string]$Name)
    $config=Get-Content "$repo/config.example.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    $config.OutputRoot=Join-Path $testRoot $Name
    $config.Smtp.Host='smtp.example.invalid'
    $config.Smtp.From='monitor@example.invalid'
    $config.Smtp.To=@('administrator@example.invalid')
    $path=Join-Path $testRoot "$Name/config.local.json"
    Save-JsonAtomic $path $config
    return $path
}
Test 'Setup installs a missing module and preserves SMTP and custom settings' {
    $path=New-TestConfig 'install'
    $config=Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
    $smtpBefore=$config.Smtp | ConvertTo-Json -Compress
    $config.PSObject.Properties.Remove('Discord')
    $config | Add-Member -NotePropertyName CustomSetting -NotePropertyValue 'preserved'
    Save-JsonAtomic $path $config
    $global:OsoDiscordTestInstalls=0
    function Read-Host { param($Prompt,[switch]$AsSecureString)
        if ($AsSecureString) { return ConvertTo-SecureString $global:OsoDiscordTestWebhook -AsPlainText -Force }; return 'Y'
    }
    function Get-Module { param($Name,[switch]$ListAvailable) }
    function Get-PackageProvider { param($Name,[switch]$ListAvailable) [pscustomobject]@{Version=[version]'2.8.5.208'} }
    function Install-Module { param($Name,$Scope,$Repository,[switch]$Force)
        Assert ($Name -eq 'PSDsHook' -and $Scope -eq 'CurrentUser'); $global:OsoDiscordTestInstalls++
    }
    & "$repo/tools/Configure-Discord.ps1" -ConfigPath $path | Out-Null
    $saved=Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert ($saved.Discord.Enabled -and $saved.Discord.WebhookUrl -eq $global:OsoDiscordTestWebhook)
    Assert ($global:OsoDiscordTestInstalls -eq 1 -and $saved.CustomSetting -eq 'preserved')
    Assert (($saved.Smtp | ConvertTo-Json -Compress) -eq $smtpBefore)
}
Test 'Existing module and saved webhook need no reinstall or replacement' {
    $path=New-TestConfig 'reuse'
    $config=Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
    $config.Discord.WebhookUrl=$global:OsoDiscordTestWebhook; Save-JsonAtomic $path $config
    function Read-Host { param($Prompt,[switch]$AsSecureString)
        if ($AsSecureString) { return New-Object Security.SecureString }; return 'Y'
    }
    function Get-Module { param($Name,[switch]$ListAvailable) [pscustomobject]@{Name='PSDsHook'} }
    function Install-Module { throw 'Unexpected installation' }
    & "$repo/tools/Configure-Discord.ps1" -ConfigPath $path | Out-Null
    $saved=Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert ($saved.Discord.Enabled -and $saved.Discord.WebhookUrl -eq $global:OsoDiscordTestWebhook)
}
Test 'Invalid webhook leaves configuration unchanged and hides input in errors' {
    $path=New-TestConfig 'invalid'; $before=(Get-FileHash $path).Hash
    function Read-Host { param($Prompt,[switch]$AsSecureString)
        if ($AsSecureString) { return ConvertTo-SecureString 'INVALID_SECRET_TEST_MARKER' -AsPlainText -Force }; return 'Y'
    }
    function Install-Module { throw 'Unexpected installation' }
    $message=''
    try { & "$repo/tools/Configure-Discord.ps1" -ConfigPath $path | Out-Null }
    catch { $message=$_.Exception.Message }
    Assert ($message -like 'Invalid webhook*' -and !$message.Contains('INVALID_SECRET_TEST_MARKER'))
    Assert ((Get-FileHash $path).Hash -eq $before)
}
Test 'Disabling Discord keeps the saved webhook and installs nothing' {
    $path=New-TestConfig 'disabled'
    $config=Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
    $config.Discord.Enabled=$true; $config.Discord.WebhookUrl=$global:OsoDiscordTestWebhook; Save-JsonAtomic $path $config
    function Read-Host { param($Prompt,[switch]$AsSecureString) return 'N' }
    function Install-Module { throw 'Unexpected installation' }
    & "$repo/tools/Configure-Discord.ps1" -ConfigPath $path | Out-Null
    $saved=Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert (!$saved.Discord.Enabled -and $saved.Discord.WebhookUrl -eq $global:OsoDiscordTestWebhook)
}
Test 'Missing Discord module preserves LIVE reports, alerts and email previews' {
    $path=New-TestConfig 'missing-module'
    $config=Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
    $config.Discord.Enabled=$true; $config.Discord.WebhookUrl=$global:OsoDiscordTestWebhook; Save-JsonAtomic $path $config
    function Get-WindowsLogs { param($LogName,$StartTime,$EndTime)
        if ($LogName -eq 'Security') { Get-DemoEvents }
    }
    function Import-Module { param($Name) throw 'Synthetic missing module error' }
    $result=Invoke-MonitorCycle -Mode LIVE -ConfigPath $path
    $root=Join-Path $config.OutputRoot 'live'
    $state=Read-MonitorState (Join-Path $root 'state.json')
    Assert ($result.ExitCode -eq 0 -and $result.TotalAlerts -eq 2 -and $result.PendingNotifications -eq 0)
    Assert ((Test-Path $result.Html) -and (Test-Path $result.Csv) -and (Test-Path (Join-Path $root 'logs/alerts.log')))
    Assert (@($state.Deliveries | Where-Object Mode -eq 'Discord').Count -eq 0)
    Assert ((Get-Content (Join-Path $root 'logs/diagnostic.log') -Raw).Contains('DISCORD_FAILED'))
}
Write-Host "DISCORD: $script:passed PASS, $script:failed FAIL. No messages sent. Artifacts: $testRoot"
if ($script:failed -gt 0) { exit 1 }
