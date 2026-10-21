<#
.SYNOPSIS
Tests additional detection rules using synthetic events and local files.
.EXAMPLE
.\tests\Run-RuleTests.ps1
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot
. "$repo/Monitor.ps1"
$testRoot=Join-Path $repo "test-results/rules-$([guid]::NewGuid().ToString('N'))"
$script:passed=0; $script:failed=0
$base=[datetime]'2026-01-15T12:00:00Z'
function Assert { param([bool]$Value,[string]$Message='Assertion failed') if (!$Value) { throw $Message } }
function Test { param([string]$Name,[scriptblock]$Body)
    try { & $Body; $script:passed++; Write-Host "PASS $Name" }
    catch { $script:failed++; Write-Host "FAIL $Name : $($_.Exception.Message)" }
}
function Failures { param([int]$Count=5,[switch]$DifferentUsers,[string]$Ip='192.0.2.10',[int]$Offset=0)
    for($i=0;$i -lt $Count;$i++) {
        $user=if($DifferentUsers) {"user$i"} else {'student'}
        New-SyntheticEvent -RecordId ($Offset+$i+1) -Time $base.AddSeconds($Offset+$i*10) -Ip $Ip -User $user
    }
}
function Success { param([int]$Seconds=60,[int]$RecordId=100,[string]$Ip='192.0.2.10',[string]$User='student')
    New-SyntheticEvent -RecordId $RecordId -Time $base.AddSeconds($Seconds) -EventId 4624 -Ip $Ip -User $User
}
function Count-Type { param($Events,[string]$Type,$Rules=$null)
    return @(Find-SuspiciousActivity -Events $Events -Rules $Rules | Where-Object Type -eq $Type).Count
}
Test 'Success after five failures; inclusive 120-second boundary' {
    $events=@(Failures)+@(Success -Seconds 120)
    $alert=@(Find-SuspiciousActivity $events | Where-Object Type -eq 'Successful logon after failures')
    Assert ($alert.Count -eq 1 -and $alert[0].EventId -eq 4624 -and $alert[0].Count -eq 5)
}
Test 'Success excludes insufficient, expired and unrelated failures' {
    $type='Successful logon after failures'
    Assert ((Count-Type (@(Failures -Count 4)+@(Success)) $type) -eq 0)
    Assert ((Count-Type (@(Failures)+@(Success -Seconds 121)) $type) -eq 0)
    Assert ((Count-Type (@(Failures)+@(Success -Ip '192.0.2.99')) $type) -eq 0)
    Assert ((Count-Type (@(Failures)+@(Success -User 'another-user')) $type) -eq 0)
    $success=Success; $success.LogonType='2'
    Assert ((Count-Type (@(Failures)+@($success)) $type) -eq 0)
    $success=Success; $success.MachineName='ANOTHER-PC'
    Assert ((Count-Type (@(Failures)+@($success)) $type) -eq 0)
}
Test 'Success clears failures; another success does not repeat the incident' {
    $events=@(Failures)+@(Success)+@(Success -Seconds 61 -RecordId 101)
    Assert ((Count-Type $events 'Successful logon after failures') -eq 1)
    $events=@(Failures -Count 4)+@(Success -Seconds 40)+@(New-SyntheticEvent -RecordId 200 -Time $base.AddSeconds(50))+@(Success -Seconds 60)
    Assert ((Count-Type $events 'Successful logon after failures') -eq 0)
}
Test 'Success supports missing IPs and deterministic ordering of simultaneous records' {
    Assert ((Count-Type (@(Failures -Ip '')+@(Success -Ip '')) 'Successful logon after failures') -eq 1)
    $events=@(1..5 | ForEach-Object { New-SyntheticEvent -RecordId $_ -Time $base })+@(Success -Seconds 0 -RecordId 6)
    Assert ((Count-Type @($events[5..0]+$events) 'Successful logon after failures') -eq 1)
}
Test 'Spraying needs ten distinct accounts and emits one alert during sustained activity' {
    $type='Possible password spraying'
    Assert ((Count-Type @(Failures -Count 9 -DifferentUsers) $type) -eq 0)
    Assert ((Count-Type @(Failures -Count 13 -DifferentUsers) $type) -eq 1)
}
Test 'Spraying ignores repeated account names, missing fields and different IPs' {
    $type='Possible password spraying'
    $rules=[pscustomobject]@{PasswordSprayAccounts=3}
    $events=@(Failures -Count 5)
    $events[1].Account='LAB\STUDENT'
    Assert ((Count-Type $events $type $rules) -eq 0)
    Assert ((Count-Type @(Failures -Count 10 -DifferentUsers -Ip '') $type) -eq 0)
    $events=@(Failures -Count 10 -DifferentUsers)
    foreach($event in $events) { $event.Account=$null }
    Assert ((Count-Type $events $type) -eq 0)
    $events=@(1..10 | ForEach-Object { New-SyntheticEvent -RecordId $_ -Time $base.AddSeconds($_) -User "user$_" -Ip "192.0.2.$_" })
    Assert ((Count-Type $events $type) -eq 0)
}
Test 'Spraying respects window boundary, custom count and domain-qualified accounts' {
    $events=@(Failures -Count 10 -DifferentUsers)
    $events[-1].TimeCreated=$base.AddSeconds(120).ToString('o')
    Assert ((Count-Type $events 'Possible password spraying') -eq 1)
    $events[-1].TimeCreated=$base.AddSeconds(121).ToString('o')
    Assert ((Count-Type $events 'Possible password spraying') -eq 0)
    $events=@(Failures -Count 3 -DifferentUsers)
    $events[0].Account='DOMAIN-A\student'; $events[1].Account='DOMAIN-B\student'
    Assert ((Count-Type $events 'Possible password spraying' ([pscustomobject]@{PasswordSprayAccounts=3})) -eq 1)
}
Test 'Spraying can detect a separate episode after a long pause' {
    $events=@(Failures -Count 10 -DifferentUsers)+@(Failures -Count 10 -DifferentUsers -Offset 500)
    Assert ((Count-Type $events 'Possible password spraying') -eq 2)
}
Test 'Admin membership uses group SID, member SID and actor from event XML' {
    $event=New-SyntheticEvent -RecordId 500 -EventId 4732 -User 'Administratorzy' -Domain 'BUILTIN' -GroupSid 'S-1-5-32-544' -MemberName '-' -MemberSid 'S-1-5-21-111-222-333-1001' -ActorUser 'operator'
    Assert ($event.GroupSid -eq 'S-1-5-32-544' -and !$event.MemberName -and $event.ActorAccount -eq 'LAB\operator')
    $alerts=@(Find-SuspiciousActivity @($event))
    Assert ($alerts.Count -eq 1 -and $alerts[0].Account -eq $event.MemberSid -and $alerts[0].Reason.Contains('LAB\operator'))
}
Test 'Other local groups, missing SID and legacy metadata do not imply admin membership' {
    $event=New-SyntheticEvent -RecordId 501 -EventId 4732 -User 'Administrators' -GroupSid 'S-1-5-32-545'
    Assert (@(Find-SuspiciousActivity @($event)).Count -eq 0)
    $event.GroupSid=''
    Assert (@(Find-SuspiciousActivity @($event)).Count -eq 0)
    $event.PSObject.Properties.Remove('GroupSid')
    Assert (@(Find-SuspiciousActivity @($event)).Count -eq 0)
}
Test 'Admin alert reason and member names stay encoded in HTML and CSV' {
    $event=New-SyntheticEvent -RecordId 502 -EventId 4732 -GroupSid 'S-1-5-32-544' -MemberName '=member<script>test</script>' -ActorUser '<script>actor</script>'
    $state=New-MonitorState; [void](Update-MonitorDetection $state @($event))
    $report=Export-MonitorReports $state (Join-Path $testRoot 'admin-escaping')
    $html=Get-Content $report.Html -Raw -Encoding UTF8
    $row=Import-Csv $report.Csv -Encoding UTF8
    Assert (!$html.Contains('<script>actor</script>') -and !$html.Contains('<script>test</script>'))
    Assert ($html.Contains('&lt;script&gt;actor&lt;/script&gt;') -and $row.Account.StartsWith("'="))
    Assert ($row.Reason.Contains('LAB\<script>actor</script>'))
}
Test 'Rules are configurable; disabling extra rules retains original failed-logon detection' {
    $rules=[pscustomobject]@{SuccessAfterFailures=$false;PasswordSpray=$false;AdminGroupChange=$false}
    $alerts=@(Find-SuspiciousActivity -Events @(Get-ExtraRuleDemoEvents) -Rules $rules)
    Assert ($alerts.Count -eq 3 -and @($alerts | Where-Object Type -notlike 'Excessive failed logons:*').Count -eq 0)
    foreach($bad in @([pscustomobject]@{PasswordSprayAccounts=1},[pscustomobject]@{PasswordSprayAccounts=2.5},[pscustomobject]@{PasswordSprayAccounts='10'},[pscustomobject]@{AdminGroupChange='true'})) {
        $rejected=$false; try { Get-DetectionRules $bad | Out-Null } catch { $rejected=$true }; Assert $rejected
    }
    $config=Get-Content "$repo/config.example.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    $config.PSObject.Properties.Remove('Rules')
    $path=Join-Path $testRoot 'legacy.json'; Save-JsonAtomic $path $config
    $loaded=Read-MonitorConfig $path
    Assert ($loaded.Rules.SuccessAfterFailures -and $loaded.Rules.PasswordSprayAccounts -eq 10)
}
Test 'Restart preserves all additional incidents and notification receipts' {
    $state=New-MonitorState; $events=@(Get-ExtraRuleDemoEvents)
    [void](Update-MonitorDetection $state $events[0..3])
    Assert (@($state.Alerts).Count -eq 0)
    [void](Update-MonitorDetection $state $events[4..16])
    Assert ($state.Alerts.Count -eq 6)
    $root=Join-Path $testRoot 'restart'; $path=Join-Path $root 'state.json'
    Save-JsonAtomic $path $state
    Invoke-PendingNotifications $state $null $root $path -Mode Test
    $state=Read-MonitorState $path
    Assert (@(Update-MonitorDetection $state @($events+$events)).Count -eq 0)
    Invoke-PendingNotifications $state $null $root $path -Mode Test
    Assert ($state.Alerts.Count -eq 6 -and $state.Deliveries.Count -eq 6)
}
Test 'Late failures can complete a success correlation only once' {
    $events=@(Failures); $success=Success
    $state=New-MonitorState
    [void](Update-MonitorDetection $state @($events[0..3]+@($success)))
    $new=@(Update-MonitorDetection $state @($events[4]))
    Assert (@($new | Where-Object Type -eq 'Successful logon after failures').Count -eq 1)
    Assert (@(Update-MonitorDetection $state @()).Count -eq 0)
}
Test 'Late spray evidence does not resend either overlapping IP rule' {
    $state=New-MonitorState; [void](Update-MonitorDetection $state @(Failures -Count 10 -DifferentUsers))
    $late=New-SyntheticEvent -RecordId 999 -Time $base.AddSeconds(-5) -User 'late-user'
    Assert (@(Update-MonitorDetection $state @($late)).Count -eq 0)
    Assert (@($state.Alerts | Where-Object Type -eq 'Possible password spraying').Count -eq 1)
}
Test 'Additional-rule DEMO generates reports and previews without sending; repeat is deduplicated' {
    $root=Join-Path $testRoot 'demo-tool'
    & "$repo/tools/Demo-ExtraRules.ps1" -OutputRoot $root | Out-Null
    $path=Join-Path $root 'state.json'; $first=Read-MonitorState $path
    $receipts=$first.Deliveries | ConvertTo-Json -Compress
    & "$repo/tools/Demo-ExtraRules.ps1" -OutputRoot $root | Out-Null
    $state=Read-MonitorState $path
    Assert ($state.Alerts.Count -eq 6 -and ($state.Deliveries | ConvertTo-Json -Compress) -eq $receipts)
    $csv=@(Import-Csv (Join-Path $root 'reports/incidents.csv') -Encoding UTF8)
    $html=Get-Content (Join-Path $root 'reports/dashboard.html') -Raw -Encoding UTF8
    Assert ($csv.Count -eq 6 -and $html.Contains('Possible password spraying') -and $html.Contains('Member added to local Administrators'))
    Assert (@($csv | Where-Object IncidentType -eq 'Successful logon after failures')[0].Reason.Contains('same account'))
}
Test 'LIVE cycle uses configured switches with a mocked log source' {
    function Get-WindowsLogs { param($LogName,$StartTime,$EndTime) if($LogName -eq 'Security') { Get-ExtraRuleDemoEvents } }
    $config=Get-Content "$repo/config.example.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    $config.OutputRoot=Join-Path $testRoot 'cycle'
    $config.Rules.SuccessAfterFailures=$false; $config.Rules.PasswordSpray=$false; $config.Rules.AdminGroupChange=$false
    $path=Join-Path $testRoot 'cycle.json'; Save-JsonAtomic $path $config
    $result=Invoke-MonitorCycle -Mode LIVE -ConfigPath $path
    Assert ($result.ExitCode -eq 0 -and $result.TotalAlerts -eq 3 -and $result.PendingNotifications -eq 0)
}
Write-Host "RULES: $script:passed PASS, $script:failed FAIL. Synthetic events only. Artifacts: $testRoot"
if($script:failed -gt 0) { exit 1 }
