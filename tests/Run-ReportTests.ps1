<#
.SYNOPSIS
Checks the adapted group report, offline operation and PowerShell help.
.EXAMPLE
.\tests\Run-ReportTests.ps1
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot
. "$repo/Monitor.ps1"
. "$repo/report.ps1"
$testRoot=Join-Path $repo "test-results/report-$([guid]::NewGuid().ToString('N'))"
$script:passed=0; $script:failed=0
function Assert { param([bool]$Value,[string]$Message='Assertion failed') if (!$Value) { throw $Message } }
function Test { param([string]$Name,[scriptblock]$Body)
    try { & $Body; $script:passed++; Write-Host "PASS $Name" }
    catch { $script:failed++; Write-Host "FAIL $Name : $($_.Exception.Message)" }
}
Test 'Group statistics count warning events separately from detected incidents' {
    $events=@(Get-DemoEvents)
    $summary=Get-TeamReportData -Events $events
    $state=New-MonitorState
    [void](Update-MonitorDetection -State $state -Events $events)
    Assert ($summary.TotalCount -eq 17 -and $summary.WarningCount -eq 15)
    Assert (@($summary.GroupedEvents | Where-Object Name -eq 'Failed logon')[0].Count -eq 15)
    Assert ($state.Alerts.Count -eq 2)
}
Test 'Empty report and additional group account categories' {
    $empty=Get-TeamReportData -Events @()
    Assert ($empty.TotalCount -eq 0 -and $empty.WarningCount -eq 0)
    $events=@(4720,4722,4724,4732 | ForEach-Object { New-SyntheticEvent -RecordId $_ -EventId $_ })
    $summary=Get-TeamReportData -Events $events
    Assert ($summary.TotalCount -eq 4 -and $summary.WarningCount -eq 1 -and $summary.GroupedEvents.Count -eq 4)
}
Test 'DEMO stays offline even with Discord enabled in local configuration' {
    $config=Get-Content "$repo/config.example.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    $config.OutputRoot=$testRoot
    $config.Discord.Enabled=$true
    $config.Discord.WebhookUrl='invalid-test-value'
    $path=Join-Path $testRoot 'config.json'
    Save-JsonAtomic $path $config
    $result=Invoke-MonitorCycle -Mode DEMO -ConfigPath $path -IntervalSeconds 2
    Assert ($result.ExitCode -eq 0 -and $result.PendingNotifications -eq 0)
    Assert (!(Test-Path (Join-Path $testRoot 'demo/logs/diagnostic.log')))
    $status=Get-Content (Join-Path $testRoot 'demo/status.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert ($status.PollIntervalSeconds -eq 2 -and $status.DashboardRefreshSeconds -eq 1)
}
Test 'PowerShell help resolves actual script and function comment help' {
    $scriptHelp=Get-Help "$repo/Start-Live.ps1" -Full
    Assert ($scriptHelp.Synopsis -like '*Starts LIVE*')
    Assert (@($scriptHelp.parameters.parameter | Where-Object name -eq 'IntervalSeconds').Count -eq 1)
    $functionHelp=Get-Help Get-WindowsLogs -Full
    Assert ($functionHelp.Synopsis -like '*Reads selected Security*')
    Assert (@($functionHelp.parameters.parameter | Where-Object name -eq 'StartTime').Count -eq 1)
    Assert ((Get-Help Get-TeamReportData).Synopsis -like '*Groups saved events*')
}
Test 'Production functions contain synopsis and examples without optional dependencies' {
    $files=@(Get-ChildItem $repo -Filter *.ps1 -File)+@(Get-ChildItem "$repo/tools" -Filter *.ps1 -File)
    foreach ($file in $files) {
        $tokens=$null; $errors=$null
        $ast=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
        Assert ($errors.Count -eq 0) "Syntax error in $($file.Name)"
        foreach ($fn in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {
            Assert ($fn.Body.Extent.Text -match '(?s)^\{\s*<#.*?\.SYNOPSIS.*?\.EXAMPLE.*?#>') "Missing help: $($fn.Name)"
        }
    }
}
Write-Host "REPORTS: $script:passed PASS, $script:failed FAIL. Artifacts: $testRoot"
if ($script:failed -gt 0) { exit 1 }
