<#
.SYNOPSIS
Loads the source package allowlist function.
.DESCRIPTION
Loads the source package allowlist function.
.EXAMPLE
. .\tools\Get-ShareFiles.ps1; Get-ShareFiles
#>
function Get-ShareFiles {
    <#
    .SYNOPSIS
    Lists the explicit source package allowlist, excluding local secrets and state.
    .DESCRIPTION
    Lists the explicit source package allowlist, excluding local secrets and state.
    .PARAMETER Root
    Output folder for the selected mode, or source folder for sharing tools.
    .EXAMPLE
    Get-ShareFiles
    #>

    param([string]$Root='')
    if (!$Root) { $Root=Split-Path $PSScriptRoot }
    # Explicit package allowlist: local state and credentials are never candidates.
    $relativePaths=@(
        '.gitignore','.gitattributes','.editorconfig','README.md','config.example.json',
        'Common.ps1','Get-Logs.ps1','Detect-Attacks.ps1','Generate-Reports.ps1',
        'Send-Notification.ps1','Send-Discord.ps1','report.ps1','Monitor.ps1','main.ps1','New-DemoEvents.ps1',
        'Start-Live.ps1','Start-Monitor.ps1','START-LIVE.cmd',
        'tools/MailKitDependencies/MailKitDependencies.csproj',
        'tools/MailKitDependencies/NuGet.Config','tools/MailKitDependencies/packages.lock.json'
    )
    foreach ($path in $relativePaths) { Get-Item -LiteralPath (Join-Path $Root $path) -ErrorAction Stop }
    foreach ($folder in @('docs','tools')) {
        $filter=if ($folder -eq 'docs') {'*.md'} else {'*.ps1'}
        Get-ChildItem -LiteralPath (Join-Path $Root $folder) -Filter $filter -File
    }
    foreach ($path in @('events.json','reports/dashboard.html','reports/incidents.csv','reports/events.csv','logs/alerts.log')) {
        Get-Item -LiteralPath (Join-Path $Root "examples/demo/$path") -ErrorAction Stop
    }
    Get-ChildItem -LiteralPath (Join-Path $Root 'examples/demo/mail-test') -Filter *.eml -File
}
