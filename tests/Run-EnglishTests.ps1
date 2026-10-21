param()
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot
. "$repo/Monitor.ps1"
$testRoot=Join-Path $repo "test-results/english-$([guid]::NewGuid().ToString('N'))"
[void][IO.Directory]::CreateDirectory($testRoot)
$script:passed=0; $script:failed=0
function Assert { param([bool]$Value,[string]$Message='Assertion failed') if (!$Value) { throw $Message } }
function Test { param([string]$Name,[scriptblock]$Body)
    try { & $Body; $script:passed++; Write-Host "PASS $Name" }
    catch { $script:failed++; Write-Host "FAIL $Name : $($_.Exception.Message)" }
}
function New-LegacyState {
    $state=New-MonitorState
    $events=@(1..5 | ForEach-Object { New-SyntheticEvent -RecordId $_ -Time ([datetime]'2026-01-15T10:00:00Z').AddSeconds($_*10) })
    [void](Update-MonitorDetection $state $events)
    foreach ($alert in $state.Alerts) {
        $dimension=if ($alert.Dimension -eq 'Account') {'Konto'} else {'IP'}
        $expected=Get-TextHash "4625|5|120|$dimension|$($alert.Entity)|$($events[-1].EventKey)"
        Assert ($alert.AlertId -eq $expected) 'An alert ID changed with the UI language.'
        $alert.Dimension=$dimension; $alert.Type="Nadmierne nieudane logowania: $dimension"
        $alert.Severity='Wysoki'; $alert.Reason='Co najmniej 5 nieudanych logowań w oknie 120 s.'
        $state.Deliveries+= [pscustomobject]@{AlertId=$alert.AlertId;Mode='Send';TimeUtc='2026-01-15T11:00:00Z'}
    }
    return $state
}
Test 'English migration preserves IDs, receipts, raw events, and restart deduplication' {
    $state=New-LegacyState; $path=Join-Path $testRoot 'legacy.json'
    $ids=@($state.Alerts.AlertId); $receipts=$state.Deliveries | ConvertTo-Json -Compress
    $events=$state.Events | ConvertTo-Json -Compress
    Save-JsonAtomic $path $state; $state=Read-MonitorState $path
    Assert (($state.Deliveries | ConvertTo-Json -Compress) -eq $receipts)
    Assert (($state.Events | ConvertTo-Json -Compress) -eq $events)
    Assert (@($state.Alerts | Where-Object { $_.AlertId -notin $ids -or $_.Severity -ne 'High' }).Count -eq 0)
    Assert (@(Update-MonitorDetection $state $state.Events).Count -eq 0)
    $script:sends=0
    function Send-AlertNotification { param($Alert,$Smtp,$Root,$Mode) $script:sends++; return $true }
    Invoke-PendingNotifications $state $null $testRoot $path -Mode Send
    Assert ($script:sends -eq 0)
    $late=New-SyntheticEvent -RecordId 99 -Time ([datetime]'2026-01-15T10:00:00Z')
    Assert (@(Update-MonitorDetection $state @($late)).Count -eq 0) 'Late-event deduplication failed after translation.'
}
Test 'English reports include account statistics, high severity, and English CSV headers' {
    $state=New-LegacyState; Update-AlertLanguage $state
    $report=Export-MonitorReports $state (Join-Path $testRoot 'reports')
    $html=Get-Content $report.Html -Raw -Encoding UTF8
    $csv=@(Import-Csv $report.Csv -Encoding UTF8)
    Assert ($html.Contains('lang="en"') -and $html.Contains('Windows Security Monitoring System'))
    Assert ($html.Contains('class="high"') -and $html.Contains('Suspicious accounts'))
    Assert ($csv.Count -eq 2 -and $csv[0].AttemptCount -eq '5' -and $csv[0].Severity -eq 'High')
    Assert (@($csv | Where-Object IncidentType -eq 'Excessive failed logons: Account').Count -eq 1)
    Assert (!$html.Contains('Nadmierne') -and !$html.Contains('Wysoki'))
}
Test 'Offline refresh translates old status and reports without changing delivery history' {
    $config=Get-Content "$repo/config.example.json" -Raw -Encoding UTF8 | ConvertFrom-Json
    $config.OutputRoot=Join-Path $testRoot 'refresh'
    $configPath=Join-Path $testRoot 'refresh.json'; Save-JsonAtomic $configPath $config
    $root=Join-Path $config.OutputRoot 'demo'; $path=Join-Path $root 'state.json'
    $state=New-LegacyState; Save-JsonAtomic $path $state
    $status=[pscustomobject]@{Mode='DEMO';Health='DEGRADED';LastAttemptUtc='2026-01-15T11:00:00Z';Sources=@();NotificationMode='Send';PendingNotifications=0;SmtpMessage='SMTP: wszystkie zapisane alerty mają potwierdzenie wysyłki. Sprawdź skrzynkę odbiorcy.'}
    Save-JsonAtomic (Join-Path $root 'status.json') $status
    $receipts=$state.Deliveries | ConvertTo-Json -Compress
    & "$repo/tools/Update-EnglishReports.ps1" -ConfigPath $configPath -Mode DEMO | Out-Null
    $saved=Read-MonitorState $path
    $updated=Get-Content (Join-Path $root 'status.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert (($saved.Deliveries | ConvertTo-Json -Compress) -eq $receipts)
    Assert ($updated.LastAttemptUtc -eq $status.LastAttemptUtc -and $updated.Health -eq $status.Health)
    Assert ($updated.SmtpMessage -eq 'SMTP has accepted all saved alerts. Check the recipient inbox.')
    Assert (Test-Path "$path.bak")
}
Test 'English EML subject and body preserve UTF-8 and stable Message-ID' {
    $state=New-LegacyState; Update-AlertLanguage $state; $alert=$state.Alerts[0]
    [void](Send-AlertNotification -Alert $alert -Root $testRoot -Mode Test)
    $mail=Get-Content (Join-Path $testRoot "mail-test/$($alert.AlertId).eml") -Raw -Encoding UTF8
    $body=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($mail -split "`r`n`r`n",2)[1]))
    Assert ($body.Contains('SECURITY ALERT - Suspicious Windows activity') -and $body.Contains('Severity: High'))
    Assert ($mail.Contains("Message-ID: <$($alert.AlertId)@oso.invalid>"))
}
Test 'Source package allowlist excludes all runtime and local configuration files' {
    . "$repo/tools/Get-ShareFiles.ps1"
    $files=@(Get-ShareFiles -Root $repo)
    Assert ($files.Count -gt 25)
    foreach ($file in $files) {
        $relative=$file.FullName.Substring($repo.Length+1).Replace('\','/')
        Assert ($relative -notmatch '^(runtime|test-results|vendor|dist|\.git)/') $relative
        Assert ($relative -notlike 'config.*' -or $relative -eq 'config.example.json') $relative
        Assert ($relative -notmatch '\.(credential\.xml|jso|bak|evtx)$') $relative
    }
}
Test 'Share checker accepts clean files and rejects populated SMTP settings' {
    . "$repo/tools/Get-ShareFiles.ps1"
    $copyRoot=Join-Path $testRoot 'share-fixture'
    foreach ($file in Get-ShareFiles -Root $repo) {
        $relative=$file.FullName.Substring($repo.Length+1)
        $destination=Join-Path $copyRoot $relative
        [void][IO.Directory]::CreateDirectory((Split-Path $destination))
        Copy-Item -LiteralPath $file.FullName -Destination $destination
    }
    $result=& "$repo/tools/Test-ShareReadiness.ps1" -Root $copyRoot
    Assert ($result.Status -eq 'PASS')
    $templatePath=Join-Path $copyRoot 'config.example.json'
    $template=Get-Content $templatePath -Raw -Encoding UTF8 | ConvertFrom-Json
    $template.Smtp.Host='smtp.example.invalid'; Save-JsonAtomic $templatePath $template
    $rejected=$false
    try { & "$repo/tools/Test-ShareReadiness.ps1" -Root $copyRoot | Out-Null }
    catch { $rejected=$_.Exception.Message -eq 'The configuration template must not contain SMTP account settings.' }
    Assert $rejected 'A configured SMTP template was accepted for sharing.'
}
Test 'Share archive builds on PowerShell 5.1 and contains only allowlisted files' {
    . "$repo/tools/Get-ShareFiles.ps1"
    $archivePath=Join-Path $testRoot 'source.zip'
    & "$repo/tools/Export-SharePackage.ps1" -OutputPath $archivePath | Out-Null
    $archive=[IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        $paths=@($archive.Entries | ForEach-Object {$_.FullName})
        Assert ($paths.Count -eq @(Get-ShareFiles -Root $repo).Count)
        Assert ($paths -contains '.gitignore' -and $paths -contains '.github/workflows/test.yml')
        Assert (@($paths | Where-Object {$_ -match '^(runtime|test-results|vendor|dist)/' -or $_ -like 'config.*local*'}).Count -eq 0)
    } finally { $archive.Dispose() }
}
Write-Host "ENGLISH: $script:passed PASS, $script:failed FAIL. Artifacts: $testRoot"
if ($script:failed -gt 0) { exit 1 }
