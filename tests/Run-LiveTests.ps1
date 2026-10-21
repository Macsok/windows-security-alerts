$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot
. "$repo/Monitor.ps1"
$testRoot=Join-Path $repo "test-results/live-$([guid]::NewGuid().ToString('N'))"
[void][IO.Directory]::CreateDirectory($testRoot)
$script:passed=0; $script:failed=0
function Assert { param([bool]$Value,[string]$Message='Assertion failed') if (!$Value) {throw $Message} }
function Test { param([string]$Name,[scriptblock]$Body)
    try { & $Body; $script:passed++; Write-Host "PASS $Name" }
    catch { $script:failed++; Write-Host "FAIL $Name : $($_.Exception.Message)" }
}
function New-TestConfig { param([string]$Name)
    $config=Get-Content "$repo/config.example.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    $config.OutputRoot=Join-Path $testRoot $Name
    $path=Join-Path $testRoot "$Name.json"
    Save-JsonAtomic $path $config
    return $path
}
Test 'LIVE: Security access failure leaves System running and appears on the dashboard' {
    function Get-WindowsLogs { param($LogName,$StartTime,$EndTime)
        if ($LogName -eq 'Security') {throw 'Access denied'}
        $e=New-SyntheticEvent -RecordId 100 -EventId 7045; $e.LogName='System'; return $e
    }
    $cfg=New-TestConfig 'partial'
    $r=Invoke-MonitorCycle -Mode LIVE -ConfigPath $cfg
    $root=Join-Path (Read-MonitorConfig $cfg).OutputRoot 'live'
    $s=Read-MonitorState (Join-Path $root 'state.json')
    Assert ($r.ExitCode -eq 2 -and $r.StoredEvents -eq 1 -and $r.TotalAlerts -eq 1)
    Assert (!$s.SourceState.Security.LastScanUtc -and $s.SourceState.System.LastScanUtc -and !$s.LastScanUtc)
    $html=Get-Content $r.Html -Raw -Encoding UTF8
    Assert ($html.Contains('Monitoring needs attention') -and $html.Contains('Cannot read Security') -and $html.Contains('http-equiv="refresh"') -and $html.Contains('Latest 50'))
    $health=Get-Content (Join-Path $root 'status.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert ($health.Health -eq 'DEGRADED')
}
Test 'LIVE: recovered log catches up across the entire outage' {
    $state=New-MonitorState; $config=Read-MonitorConfig (New-TestConfig 'recovery')
    function Get-WindowsLogs { param($LogName,$StartTime,$EndTime) if ($LogName -eq 'Security') {throw 'Test'} }
    $first=Get-LiveLogBatch $state $config ([datetime]'2026-01-15T10:00:00Z')
    $retry=$state.SourceState.Security.RetryFromUtc
    $second=Get-LiveLogBatch $state $config ([datetime]'2026-01-15T10:40:00Z')
    Assert ($retry -eq $state.SourceState.Security.RetryFromUtc)
    function Get-WindowsLogs { param($LogName,$StartTime,$EndTime)
        if ($LogName -eq 'Security') {
            Assert ($StartTime -eq (ConvertTo-UtcDate $retry)) 'Part of the outage was skipped'
            return New-SyntheticEvent -RecordId 55 -EventId 4625
        }
    }
    $third=Get-LiveLogBatch $state $config ([datetime]'2026-01-15T10:41:00Z')
    Assert ($third.Status -eq 'OK' -and @($third.Events).Count -eq 1 -and $state.LastScanUtc -and !$state.SourceState.Security.RetryFromUtc)
}
Test 'LIVE: both logs unavailable preserves history and reports the error' {
    $cfg=New-TestConfig 'unavailable'; $root=Join-Path (Read-MonitorConfig $cfg).OutputRoot 'live'
    $s=New-MonitorState; [void](Update-MonitorDetection $s @(New-SyntheticEvent -RecordId 1 -EventId 7045))
    Save-JsonAtomic (Join-Path $root 'state.json') $s
    function Get-WindowsLogs {param($LogName,$StartTime,$EndTime) throw 'Test'}
    $r=Invoke-MonitorCycle -Mode LIVE -ConfigPath $cfg
    Assert ($r.Health -eq 'ERROR' -and $r.ExitCode -eq 2 -and $r.StoredEvents -eq 1 -and $r.TotalAlerts -eq 1)
    Assert ([Net.WebUtility]::HtmlDecode((Get-Content $r.Html -Raw -Encoding UTF8)).Contains('Event logs are unavailable'))
}
Test 'LIVE: missing SMTP configuration is not reported as successful delivery' {
    $cfg=New-TestConfig 'no-smtp'
    $r=Invoke-MonitorCycle -Mode DEMO -ConfigPath $cfg -SendEmail
    Assert ($r.ExitCode -eq 2 -and $r.PendingNotifications -eq 2 -and $r.SmtpMessage.Contains('not ready'))
    $state=Read-MonitorState (Join-Path (Read-MonitorConfig $cfg).OutputRoot 'demo/state.json')
    Assert ($state.Deliveries.Count -eq 0 -and $state.Alerts.Count -eq 2)
}
Test 'LIVE: SMTP failure, recovery, and restart deduplication (mock transport)' {
    $cfg=New-TestConfig 'mail-retry'
    function Get-SmtpReadiness {param($Smtp) [pscustomobject]@{Ready=$true;Message='Test'}}
    function Send-AlertNotification {param($Alert,$Smtp,$Root,$Mode) return $false}
    $first=Invoke-MonitorCycle -Mode DEMO -ConfigPath $cfg -SendEmail
    Assert ($first.PendingNotifications -eq 2 -and $first.ExitCode -eq 2)
    $script:deliveries=0
    function Send-AlertNotification {param($Alert,$Smtp,$Root,$Mode) $script:deliveries++; return $true}
    $second=Invoke-MonitorCycle -Mode DEMO -ConfigPath $cfg -SendEmail
    $third=Invoke-MonitorCycle -Mode DEMO -ConfigPath $cfg -SendEmail
    Assert ($second.PendingNotifications -eq 0 -and $third.NewAlerts -eq 0 -and $script:deliveries -eq 2)
}
Test 'SMTP: nested Gmail failure is actionable without revealing server responses' {
    $inner=New-Object System.Exception('5.7.8 Username and Password not accepted: test@example.invalid SECRET_TEST_MARKER')
    $outer=New-Object System.Exception('Exception calling Authenticate', $inner)
    $description=Get-SmtpFailureDescription $outer
    Assert ($description.Contains('SMTP_AUTH_REJECTED') -and $description.Contains('Configure-Gmail.ps1'))
    Assert (!$description.Contains('test@example.invalid') -and !$description.Contains('SECRET_TEST_MARKER'))
    $unknown=Get-SmtpFailureDescription (New-Object System.Exception('SECRET_TEST_MARKER'))
    Assert ($unknown.Contains('SMTP_SEND_FAILED') -and !$unknown.Contains('SECRET_TEST_MARKER'))
}
Test 'SMTP: rejected authentication preserves pending alerts and writes a safe log' {
    $cfg=New-TestConfig 'auth-rejected'; $root=Join-Path (Read-MonitorConfig $cfg).OutputRoot 'demo'
    $state=New-MonitorState
    [void](Update-MonitorDetection $state @(Get-DemoEvents))
    $path=Join-Path $root 'state.json'; Save-JsonAtomic $path $state
    function Connect-MonitorSmtp { param($Smtp) throw '5.7.8 Username and Password not accepted: SECRET_TEST_MARKER' }
    $smtp=[pscustomobject]@{From='monitor@example.invalid';To=@('recipient@example.invalid')}
    Invoke-PendingNotifications -State $state -Smtp $smtp -Root $root -StatePath $path -Mode Send
    $saved=Read-MonitorState $path
    $log=Get-Content (Join-Path $root 'logs/diagnostic.log') -Raw -Encoding UTF8
    Assert ($saved.Deliveries.Count -eq 0 -and $saved.Alerts.Count -eq 2)
    Assert ($log.Contains('SMTP_AUTH_REJECTED') -and !$log.Contains('SECRET_TEST_MARKER'))
}
Test 'LIVE: legacy state compatibility and atomic report refresh' {
    $cfg=New-TestConfig 'old-state'; $root=Join-Path (Read-MonitorConfig $cfg).OutputRoot 'live'
    $s=New-MonitorState; $s.LastScanUtc='2026-01-15T10:00:00Z'
    Save-JsonAtomic (Join-Path $root 'state.json') $s
    function Get-WindowsLogs {param($LogName,$StartTime,$EndTime) Assert ($StartTime -le ([datetime]'2026-01-15T10:00:00Z'))}
    $r=Invoke-MonitorCycle -Mode LIVE -ConfigPath $cfg
    Assert ($r.ExitCode -eq 0)
    $a=Join-Path $root 'atomic.txt'; Write-TextAtomic $a 'Pierwszy'; Write-TextAtomic $a 'Drugi'
    Assert ((Get-Content $a -Raw -Encoding UTF8) -eq 'Drugi')
}
Test 'LIVE: two actual loop cycles using synthetic DEMO data without SMTP' {
    $cfg=New-TestConfig 'loop'
    $previousPreference=$ErrorActionPreference
    try {
        $ErrorActionPreference='Continue'
        $output=(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$repo/Start-Monitor.ps1" -Mode DEMO -ConfigPath $cfg -MaxCycles 2 2>&1 | Out-String)
        $code=$LASTEXITCODE
    } finally {$ErrorActionPreference=$previousPreference}
    Assert ($code -eq 0) $output
    Assert ($output.Contains('Cycle interval: approximately 5 seconds'))
    Assert (([regex]::Matches($output,'Starting cycle')).Count -eq 2)
    $state=Read-MonitorState (Join-Path (Read-MonitorConfig $cfg).OutputRoot 'demo/state.json')
    Assert ($state.Events.Count -eq 17 -and $state.Deliveries.Count -eq 2)
    $html=Get-Content (Join-Path (Read-MonitorConfig $cfg).OutputRoot 'demo/reports/dashboard.html') -Raw -Encoding UTF8
    Assert ($html.Contains('http-equiv="refresh" content="1"') -and $html.Contains('Logs checked every 5 seconds'))
}
Write-Host "LIVE: $script:passed PASS, $script:failed FAIL. Artifacts: $testRoot"
if ($script:failed -gt 0) {exit 1}
