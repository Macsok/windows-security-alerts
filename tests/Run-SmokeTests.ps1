<#
.SYNOPSIS
Checks PowerShell syntax and a basic offline DEMO run.
.DESCRIPTION
Used by GitHub Actions. Requires no Windows log access, modules or secrets.
Creates an isolated temporary output directory and sends no messages.
.EXAMPLE
.\tests\Run-SmokeTests.ps1
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot

$files=@(Get-ChildItem -LiteralPath $repo -Filter *.ps1 -File)
foreach ($folder in @('tools','tests')) {
    $files+=@(Get-ChildItem -LiteralPath (Join-Path $repo $folder) -Filter *.ps1 -File)
}
foreach ($file in $files) {
    $tokens=$null; $parseErrors=$null
    [void][Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$parseErrors)
    if ($parseErrors.Count) { throw "Syntax error in $($file.Name): $($parseErrors[0].Message)" }
}
Write-Host "PASS: syntax of $($files.Count) PowerShell scripts"

$root=Join-Path ([IO.Path]::GetTempPath()) "oso-smoke-$([guid]::NewGuid().ToString('N'))"
[void][IO.Directory]::CreateDirectory($root)
$config=Get-Content -LiteralPath (Join-Path $repo 'config.example.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$config.OutputRoot=Join-Path $root 'output'
if ($config.PSObject.Properties['Discord']) { $config.Discord.Enabled=$false; $config.Discord.WebhookUrl='' }
$configPath=Join-Path $root 'config.local.json'
$config | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $configPath -Encoding UTF8

# Use the same entry point as a normal installation, in a fresh process.
& (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'main.ps1') -Mode DEMO -ConfigPath $configPath
if ($LASTEXITCODE -ne 0) { throw "DEMO exited with code $LASTEXITCODE" }
$output=Join-Path $config.OutputRoot 'demo'
foreach ($relativePath in @('reports/dashboard.html','reports/incidents.csv','reports/events.csv','logs/alerts.log','state.json')) {
    $path=Join-Path $output $relativePath
    if (!(Test-Path -LiteralPath $path) -or (Get-Item -LiteralPath $path).Length -eq 0) { throw "Missing or empty DEMO output: $relativePath" }
}
$state=Get-Content -LiteralPath (Join-Path $output 'state.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if (@($state.Events).Count -eq 0 -or @($state.Alerts).Count -eq 0) { throw 'DEMO produced no events or alerts' }
if (@(Get-ChildItem -LiteralPath (Join-Path $output 'mail-test') -Filter *.eml -File).Count -eq 0) { throw 'No local email preview generated' }
Write-Host 'PASS: DEMO generated events, alerts, HTML, CSV, alert log and local email previews'
Write-Host "Basic checks passed. Artifacts: $root"
