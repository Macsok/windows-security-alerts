[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot
$dotnetCommand=Get-Command dotnet -ErrorAction SilentlyContinue
$dotnetPath=if ($dotnetCommand) { $dotnetCommand.Source } else { Join-Path $env:ProgramFiles 'dotnet/dotnet.exe' }
if (!(Test-Path -LiteralPath $dotnetPath)) { throw 'Install the .NET SDK, then run this script again.' }
$output = Join-Path $repo 'vendor/mailkit'
$cache = Join-Path $repo 'vendor/nuget-cache'
$previousCliHome=$env:DOTNET_CLI_HOME
$previousTelemetry=$env:DOTNET_CLI_TELEMETRY_OPTOUT
$previousToolsPath=$env:DOTNET_ADD_GLOBAL_TOOLS_TO_PATH
$previousCertificate=$env:DOTNET_GENERATE_ASPNET_CERTIFICATE
try {
    $env:DOTNET_CLI_HOME=Join-Path $repo 'vendor/dotnet-cli'
    $env:DOTNET_CLI_TELEMETRY_OPTOUT='1'
    $env:DOTNET_ADD_GLOBAL_TOOLS_TO_PATH='false'
    $env:DOTNET_GENERATE_ASPNET_CERTIFICATE='false'
    & $dotnetPath build (Join-Path $PSScriptRoot 'MailKitDependencies/MailKitDependencies.csproj') --configuration Release --output $output "-p:RestorePackagesPath=$cache" "-p:RestoreConfigFile=$(Join-Path $PSScriptRoot 'MailKitDependencies/NuGet.Config')" --verbosity minimal
    if ($LASTEXITCODE -ne 0) { throw 'Unable to build MailKit dependencies. Check access to nuget.org and your .NET SDK version.' }
} finally {
    $env:DOTNET_CLI_HOME=$previousCliHome
    $env:DOTNET_CLI_TELEMETRY_OPTOUT=$previousTelemetry
    $env:DOTNET_ADD_GLOBAL_TOOLS_TO_PATH=$previousToolsPath
    $env:DOTNET_GENERATE_ASPNET_CERTIFICATE=$previousCertificate
}
. (Join-Path $repo 'Send-Notification.ps1')
Import-MailKit $output
Write-Host "Loaded MailKit $([MailKit.Net.Smtp.SmtpClient].Assembly.GetName().Version)."
Write-Host "MailKit libraries and dependencies: $output"
