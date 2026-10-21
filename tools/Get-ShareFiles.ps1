function Get-ShareFiles {
    param([string]$Root='')
    if (!$Root) { $Root=Split-Path $PSScriptRoot }
    # Explicit package allowlist: local state and credentials are never candidates.
    $relativePaths=@(
        '.gitignore','.gitattributes','.editorconfig','README.md','config.example.json',
        'Common.ps1','Get-Logs.ps1','Detect-Attacks.ps1','Generate-Reports.ps1',
        'Send-Notification.ps1','Monitor.ps1','main.ps1','New-DemoEvents.ps1',
        'Start-Live.ps1','Start-Monitor.ps1','START-LIVE.cmd',
        'tools/MailKitDependencies/MailKitDependencies.csproj',
        'tools/MailKitDependencies/NuGet.Config','tools/MailKitDependencies/packages.lock.json',
        '.github/workflows/test.yml'
    )
    foreach ($path in $relativePaths) { Get-Item -LiteralPath (Join-Path $Root $path) -ErrorAction Stop }
    foreach ($folder in @('docs','tools','tests')) {
        $filter=if ($folder -eq 'docs') {'*.md'} else {'*.ps1'}
        Get-ChildItem -LiteralPath (Join-Path $Root $folder) -Filter $filter -File
    }
    foreach ($path in @('events.json','reports/dashboard.html','reports/incidents.csv','reports/events.csv','logs/alerts.log')) {
        Get-Item -LiteralPath (Join-Path $Root "examples/demo/$path") -ErrorAction Stop
    }
    Get-ChildItem -LiteralPath (Join-Path $Root 'examples/demo/mail-test') -Filter *.eml -File
}
