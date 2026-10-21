param([ValidateRange(1,6)][int]$Stage = 6)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot
. "$repo/New-DemoEvents.ps1"
. "$repo/Detect-Attacks.ps1"
$script:passed = 0; $script:failed = 0
$testRoot = Join-Path $repo "test-results/$([guid]::NewGuid().ToString('N'))"
[void][IO.Directory]::CreateDirectory($testRoot)
function Assert-True { param([bool]$Condition,[string]$Message='Assertion failed') if (!$Condition) { throw $Message } }
function Test { param([string]$Name,[scriptblock]$Body)
    try { & $Body; $script:passed++; Write-Host "PASS $Name" }
    catch { $script:failed++; Write-Host "FAIL $Name : $($_.Exception.Message)" }
}
function Sample { param([int]$Count,[int]$Spacing=20,[switch]$DifferentIPs,[switch]$NoIP,[switch]$DifferentUsers)
    for ($i=0; $i -lt $Count; $i++) {
        $ip='192.0.2.1'; $user='student'
        if ($DifferentIPs) { $ip="192.0.2.$($i+1)" }; if ($NoIP) { $ip=$null }
        if ($DifferentUsers) { $user="user$i" }
        New-SyntheticEvent -RecordId ($i+1) -Time ([datetime]'2026-01-15T10:00:00Z').AddSeconds($i*$Spacing) -Ip $ip -User $user
    }
}
function Invoke-TestMain {
    param([string]$ConfigPath)
    # PowerShell 5.1 represents child process stderr as ErrorRecord.
    $ErrorActionPreference='Continue'
    $output=(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$repo/main.ps1" -Mode DEMO -ConfigPath $ConfigPath 2>&1 | Out-String)
    [pscustomobject]@{ExitCode=$LASTEXITCODE;Output=$output}
}
Test '1: default configuration and atomic state writes' {
    $c = Get-Content "$repo/config.example.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ($c.Threshold -eq 5 -and $c.WindowSeconds -eq 120)
    $p=Join-Path $testRoot 'state.json'; Save-JsonAtomic $p (New-MonitorState); Save-JsonAtomic $p (New-MonitorState)
    Assert-True ((Read-MonitorState $p).Version -eq 1 -and (Test-Path "$p.bak"))
}
if ($Stage -ge 2) {
    Test '2: XML parser, UTC, account, and RecordId' {
        $e=New-SyntheticEvent -RecordId 123
        Assert-True ($e.EventId -eq 4625 -and $e.RecordId -eq 123 -and $e.Account -eq 'LAB\student' -and $e.LogonType -eq '3')
        Assert-True ($e.TimeCreated.EndsWith('Z'))
    }
    Test '2: missing IP and account do not create fictional values' {
        $e=New-SyntheticEvent -RecordId 1 -Ip '-' -User $null
        Assert-True ($null -eq $e.IpAddress -and $null -eq $e.Account)
    }
    Test '2: IPv4-mapped IPv6 and unique identity after a log reset' {
        $a=New-SyntheticEvent -RecordId 1 -Ip '::ffff:192.0.2.1'
        $b=New-SyntheticEvent -RecordId 1 -Time ([datetime]'2026-01-15T10:10:00Z')
        Assert-True ($a.IpAddress -eq '192.0.2.1' -and $a.EventKey -ne $b.EventKey)
    }
    Test '2: UserData for event 1102' {
        $xml='<Event><System><Provider Name="Microsoft-Windows-Eventlog"/><EventID>1102</EventID><TimeCreated SystemTime="2026-01-15T10:00:00Z"/><EventRecordID>7</EventRecordID><Channel>Security</Channel><Computer>PC</Computer></System><UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"><SubjectUserName>jan</SubjectUserName><SubjectDomainName>LAB</SubjectDomainName></LogFileCleared></UserData></Event>'
        Assert-True ((ConvertFrom-WindowsEventXml $xml).Account -eq 'LAB\jan')
    }
    Test '2: adapter permission error (mock)' {
        function Get-WinEvent { throw [UnauthorizedAccessException]::new('test') }
        $caught=$false
        try { Get-WindowsLogs | Out-Null } catch { $caught=$_.Exception.Message -like '*permissions*' }
        Assert-True $caught
    }
    Test '2: accessible log without matching events (mock)' {
        function Get-WinEvent {
            [CmdletBinding()]param($ListLog,$FilterHashtable)
            if ($ListLog) { return [pscustomobject]@{IsEnabled=$true} }
            Write-Error -Message 'No matching events' -ErrorId 'NoMatchingEventsFound'
        }
        Assert-True (@(Get-WindowsLogs).Count -eq 0)
    }
}
if ($Stage -ge 3) {
    Test '3 TEST 1: three attempts produce no alert' { Assert-True (@(Find-SuspiciousActivity -Events @(Sample 3)).Count -eq 0) }
    Test '3 TEST 2: five attempts trigger two independent dimensions' { Assert-True (@(Find-SuspiciousActivity -Events @(Sample 5)).Count -eq 2) }
    Test '3 TEST 3: seven attempts from one IP produce one IP alert' {
        $a=@(Find-SuspiciousActivity -Events @(Sample 7 -Spacing 10 -DifferentUsers))
        Assert-True ($a.Count -eq 1 -and $a[0].Dimension -eq 'IP')
    }
    Test '3 TEST 4: one account targeted from different IP addresses' {
        $a=@(Find-SuspiciousActivity -Events @(Sample 5 -DifferentIPs))
        Assert-True ($a.Count -eq 1 -and $a[0].Dimension -eq 'Account')
    }
    Test '3 TEST 5: five attempts spread over ten minutes' { Assert-True (@(Find-SuspiciousActivity -Events @(Sample 5 -Spacing 150)).Count -eq 0) }
    Test '3 TEST 6: deduplication after saving and reloading state' {
        $s=New-MonitorState; $events=@(Sample 5)
        $a=@(Update-MonitorDetection $s $events); $p=Join-Path $testRoot 'restart.json'; Save-JsonAtomic $p $s
        $s=Read-MonitorState $p; $b=@(Update-MonitorDetection $s $events)
        Assert-True ($a.Count -eq 2 -and $b.Count -eq 0 -and $s.Events.Count -eq 5)
    }
    Test '3: four attempts, 120 and 124 seconds, configurable threshold' {
        Assert-True (@(Find-SuspiciousActivity -Events @(Sample 4)).Count -eq 0)
        Assert-True (@(Find-SuspiciousActivity -Events @(Sample 5 -Spacing 30)).Count -eq 2)
        Assert-True (@(Find-SuspiciousActivity -Events @(Sample 5 -Spacing 31)).Count -eq 0)
        Assert-True (@(Find-SuspiciousActivity -Events @(Sample 3) -Threshold 3 -WindowSeconds 60).Count -eq 2)
    }
    Test '3: missing IP, chronological ordering, and duplicate records' {
        $e=@(Sample 5 -NoIP); $a=@(Find-SuspiciousActivity -Events @($e[4..0]+$e))
        Assert-True ($a.Count -eq 1 -and $a[0].Dimension -eq 'Account')
        Assert-True (@(Find-SuspiciousActivity -Events @(Sample 5 -NoIP -DifferentUsers)).Count -eq 0)
    }
    Test '3: a detection window spanning multiple runs' {
        $s=New-MonitorState; $e=@(Sample 5)
        Assert-True (@(Update-MonitorDetection $s $e[0..2]).Count -eq 0)
        Assert-True (@(Update-MonitorDetection $s $e[3..4]).Count -eq 2)
    }
    Test '3: 4624 context and warnings for 4740, 1102, 104, and 7045' {
        Assert-True (@(Find-SuspiciousActivity -Events @(New-SyntheticEvent -RecordId 1 -EventId 4624)).Count -eq 0)
        foreach ($id in @(4740,1102,104,7045)) { Assert-True (@(Find-SuspiciousActivity -Events @(New-SyntheticEvent -RecordId $id -EventId $id)).Count -eq 1) }
    }
}
if ($Stage -ge 4) {
    . "$repo/Generate-Reports.ps1"
    Test '4: CSV, HTML, alert log, counters, history, and deduplication' {
        $s=New-MonitorState; [void](Update-MonitorDetection $s @(Get-DemoEvents))
        $root=Join-Path $testRoot 'reports'; $r=Export-MonitorReports $s $root
        $csv=@(Import-Csv $r.Csv -Encoding UTF8)
        Assert-True ($csv.Count -eq 2 -and $csv[0].AttemptCount -eq '5')
        $html=Get-Content $r.Html -Raw -Encoding UTF8
        Assert-True ($html.Contains('Windows Security Monitoring System') -and $html.Contains('>17<') -and $html.Contains('>15<'))
        $before=Get-Content $r.AlertLog -Raw -Encoding UTF8
        Export-MonitorReports $s $root | Out-Null
        Assert-True ((Get-Content $r.AlertLog -Raw -Encoding UTF8) -eq $before)
        $lines=@(Get-Content $r.AlertLog -Encoding UTF8 | Where-Object {$_})
        Assert-True ($lines.Count -eq 2 -and ($lines[0] | ConvertFrom-Json).Reason.Contains('120'))
    }
    Test '4: HTML escaping, Unicode data, and CSV formula protection' {
        $s=New-MonitorState; $e=@(Sample 5 -NoIP)
        foreach ($event in $e) { $event.Account='=Żółć<script>alert(1)</script>' }
        [void](Update-MonitorDetection $s $e); $r=Export-MonitorReports $s (Join-Path $testRoot 'escaping')
        $html=Get-Content $r.Html -Raw -Encoding UTF8
        Assert-True (!$html.Contains('<script>alert(1)</script>') -and $html.Contains('&lt;script&gt;') -and [Net.WebUtility]::HtmlDecode($html).Contains('żółć'))
        Assert-True ((Import-Csv $r.Csv -Encoding UTF8).Account.StartsWith("'="))
    }
    Test '4: empty reports retain headers and an empty state' {
        $r=Export-MonitorReports (New-MonitorState) (Join-Path $testRoot 'empty')
        Assert-True ((Get-Content $r.Csv -Raw -Encoding UTF8).Contains('IncidentType'))
        Assert-True ((Get-Content $r.Html -Raw -Encoding UTF8).Contains('No data'))
    }
}
if ($Stage -ge 5) {
    . "$repo/Send-Notification.ps1"
    Test '5: TEST writes EML without SMTP and deduplicates after restart' {
        $s=New-MonitorState; [void](Update-MonitorDetection $s @(Sample 5))
        $root=Join-Path $testRoot 'mail'; $path=Join-Path $root 'state.json'
        Invoke-PendingNotifications $s $null $root $path
        $s=Read-MonitorState $path; Invoke-PendingNotifications $s $null $root $path
        $files=@(Get-ChildItem (Join-Path $root 'mail-test') -Filter *.eml)
        Assert-True ($files.Count -eq 2 -and $s.Deliveries.Count -eq 2)
        $eml=Get-Content $files[0].FullName -Raw -Encoding UTF8
        $body=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($eml -split "`r`n`r`n",2)[1]))
        Assert-True ($body.Contains('Failed logons / events: 5') -and $body.Contains('Severity: High'))
    }
    Test '5: SMTP failure preserves the alert and pending notification' {
        $s=New-MonitorState; [void](Update-MonitorDetection $s @(Sample 5 -DifferentUsers))
        $root=Join-Path $testRoot 'smtp-failure'; $path=Join-Path $root 'state.json'
        Save-JsonAtomic $path $s; $r=Export-MonitorReports $s $root
        $smtp=[pscustomobject]@{Host='smtp.example.invalid';Port=587;From='monitor@example.invalid';To=@('administrator@example.invalid');Security='StartTls';LibraryDirectory='';CredentialPath=''}
        function Connect-MonitorSmtp { param($Smtp) throw [IO.IOException]::new('Simulated connection failure; diagnostics must not contain this text.') }
        Invoke-PendingNotifications $s $smtp $root $path -Mode Send
        Assert-True ($s.Deliveries.Count -eq 0 -and $s.Alerts.Count -eq 1 -and (Test-Path $r.AlertLog))
        Assert-True ((Get-Content (Join-Path $root 'logs/diagnostic.log') -Raw -Encoding UTF8).Contains('SMTP_SEND_FAILED'))
    }
    Test '5: SMTP refuses connections without required TLS' {
        $smtp=[pscustomobject]@{Host='smtp.example.invalid';Port=587;Security='None'}
        $caught=$false
        try { Connect-MonitorSmtp $smtp | Out-Null } catch { $caught=$_.Exception.Message -like '*TLS*' }
        Assert-True $caught
    }
    Test '5: retry after failure and separate TEST/Send confirmations (mock)' {
        $s=New-MonitorState; [void](Update-MonitorDetection $s @(Sample 5 -DifferentUsers))
        $root=Join-Path $testRoot 'smtp-retry'; $path=Join-Path $root 'state.json'
        Invoke-PendingNotifications $s $null $root $path -Mode Test
        function Send-AlertNotification { param($Alert,$Smtp,$Root,$Mode) return $true }
        Invoke-PendingNotifications $s $null $root $path -Mode Send
        Invoke-PendingNotifications $s $null $root $path -Mode Send
        Assert-True ($s.Deliveries.Count -eq 2)
    }
}
if ($Stage -ge 6) {
    Test '6: Windows PowerShell 5.1 syntax' {
        foreach ($file in Get-ChildItem $repo -Filter *.ps1 -Recurse | Where-Object {$_.FullName -notlike '*test-results*' -and $_.FullName -notlike '*\vendor\*'}) {
            $tokens=$null; $errors=$null
            [void][Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
            Assert-True ($errors.Count -eq 0) "Syntax error: $($file.Name) $errors"
        }
    }
    Test '6: main DEMO, persistence across processes, and all artifacts' {
        $config=Get-Content "$repo/config.example.json" -Raw -Encoding UTF8 | ConvertFrom-Json
        $config.OutputRoot=Join-Path $testRoot 'integration'
        $cfgPath=Join-Path $testRoot 'integration.json'; Save-JsonAtomic $cfgPath $config
        $first=Invoke-TestMain $cfgPath
        Assert-True ($first.ExitCode -eq 0) $first.Output
        $root=Join-Path $config.OutputRoot 'demo'
        $state=Read-MonitorState (Join-Path $root 'state.json')
        Assert-True ($state.Events.Count -eq 17 -and $state.Alerts.Count -eq 2 -and $state.Deliveries.Count -eq 2)
        $second=Invoke-TestMain $cfgPath
        Assert-True ($second.ExitCode -eq 0) $second.Output
        $state2=Read-MonitorState (Join-Path $root 'state.json')
        Assert-True ($state2.Events.Count -eq 17 -and $state2.Alerts.Count -eq 2 -and $state2.Deliveries.Count -eq 2)
        Assert-True ($state.Deliveries[0].TimeUtc -eq $state2.Deliveries[0].TimeUtc)
        foreach ($file in @('reports/dashboard.html','reports/incidents.csv','reports/events.csv','logs/alerts.log')) { Assert-True (Test-Path (Join-Path $root $file)) }
        Assert-True (!(Test-Path (Join-Path $config.OutputRoot 'live')))
    }
    Test '6: concurrent process lock and corrupt state without reset' {
        $config=Get-Content "$repo/config.example.json" -Raw -Encoding UTF8 | ConvertFrom-Json
        $config.OutputRoot=Join-Path $testRoot 'locked'
        $cfgPath=Join-Path $testRoot 'locked.json'; Save-JsonAtomic $cfgPath $config
        $root=Join-Path $config.OutputRoot 'demo'; [void][IO.Directory]::CreateDirectory($root)
        $handle=[IO.File]::Open((Join-Path $root 'monitor.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        try {
            $result=Invoke-TestMain $cfgPath
            Assert-True ($result.ExitCode -ne 0 -and !(Test-Path (Join-Path $root 'state.json')))
        } finally {$handle.Dispose()}
        Write-Utf8File (Join-Path $root 'state.json') '{invalid'
        $result=Invoke-TestMain $cfgPath
        Assert-True ($result.ExitCode -ne 0 -and (Get-Content (Join-Path $root 'state.json') -Raw -Encoding UTF8) -eq '{invalid')
    }
    Test '6: another episode after a pause creates a new alert' {
        $a=@(Sample 5 -DifferentUsers); $b=@(Sample 5 -DifferentUsers)
        foreach ($event in $b) {
            $event.TimeCreated=(ConvertTo-UtcDate $event.TimeCreated).AddMinutes(10).ToString('o')
            $event.EventKey=Get-TextHash ($event.EventKey+'second-episode')
        }
        Assert-True (@(Find-SuspiciousActivity -Events @($a+$b)).Count -eq 2)
    }
    Test '6: late events do not duplicate existing incidents' {
        $s=New-MonitorState; [void](Update-MonitorDetection $s @(Sample 5 -DifferentUsers))
        $late=New-SyntheticEvent -RecordId 99 -Time ([datetime]'2026-01-15T09:59:50Z') -Ip '192.0.2.1' -User 'late'
        Assert-True (@(Update-MonitorDetection $s @($late)).Count -eq 0 -and $s.Alerts.Count -eq 1)
    }
    Test '6: Start-Monitor Once runs DEMO and rejects missing configuration' {
        $config=Get-Content "$repo/config.example.json" -Raw -Encoding UTF8 | ConvertFrom-Json
        $config.OutputRoot=Join-Path $testRoot 'continuous-wrapper'
        $cfgPath=Join-Path $testRoot 'continuous-wrapper.json'; Save-JsonAtomic $cfgPath $config
        $previousPreference=$ErrorActionPreference
        try {
            $ErrorActionPreference='Continue'
            $output=(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$repo/Start-Monitor.ps1" -Mode DEMO -ConfigPath $cfgPath -Once 2>&1 | Out-String)
            $successCode=$LASTEXITCODE
            $failureOutput=(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$repo/Start-Monitor.ps1" -Mode DEMO -ConfigPath (Join-Path $testRoot 'missing.json') -Once 2>&1 | Out-String)
            $failureCode=$LASTEXITCODE
        } finally { $ErrorActionPreference=$previousPreference }
        Assert-True ($successCode -eq 0) $output
        Assert-True ($failureCode -ne 0) $failureOutput
        $state=Read-MonitorState (Join-Path $config.OutputRoot 'demo/state.json')
        Assert-True ($state.Events.Count -eq 17 -and $state.Alerts.Count -eq 2 -and $state.Deliveries.Count -eq 2)
    }
}
Write-Host "Result: $script:passed PASS, $script:failed FAIL. Artifacts: $testRoot"
if ($script:failed -gt 0) { exit 1 }
