# LIVE monitoring and Gmail

## Start and configure

`START-LIVE.cmd` starts LIVE with real email enabled, requests administrator privileges, configures Gmail when needed, and opens the dashboard. For local email previews instead:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Live.ps1
```

The console loop reads logs approximately every **5 seconds** and the dashboard refreshes every **1 second**. A slow query or SMTP operation can extend a cycle. Stop with Ctrl+C. Closing the console or logging out stops this loop; Task Scheduler remains a separate once-per-minute mode.

Change `PollIntervalSeconds` and `DashboardRefreshSeconds` in the local configuration to adjust the timings. The loop reloads configuration between cycles. An explicit command-line interval takes precedence:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Live.ps1 -SendEmail -IntervalSeconds 5
```

After upgrading a previously running 60-second loop, restart that loop once to load the new code. Changing the display refresh does not change the detection rule of five failures within 120 seconds. The dashboard shows the configured log interval and actual last-cycle timestamp; it warns after three missed intervals, with a minimum of 20 seconds.

Enable Google two-step verification and create an [app password](https://myaccount.google.com/apppasswords), then run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Configure-Gmail.ps1 -ConfigPath .\config.local.json
```

Enter the full Gmail sender address and app password without spaces in the local credential dialog. Setup stores DPAPI credentials outside the project and checks TLS/authentication without sending. Expect `Connected=True`, `Secure=True`, and `Authenticated=True`. It uses `smtp.gmail.com:587` with required STARTTLS; install the .NET SDK if building MailKit is required. [Google app-password requirements](https://support.google.com/accounts/answer/185833?hl=en).

Enable actual delivery after setup:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Live.ps1 -SendEmail
```

All pending LIVE alerts become eligible, including those previously saved in TEST. The existence of a credential file does not prove Gmail accepts it.

## Verify Windows logging

Run as the intended monitoring account with permission to read Security and System:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Test-WindowsLogs.ps1
Get-WinEvent -ListLog Security,System | Select-Object LogName,IsEnabled,RecordCount
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddDays(-1)} -MaxEvents 5
auditpol.exe /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}"
```

The adapter checks accessibility before querying events. No matches can mean no failures occurred in that range. Validate permissions using an administrator console or appropriate event-log permissions under local policy; Event Log Readers membership may not be sufficient in every configuration.

An administrator can enable Advanced Audit Policy Configuration > Logon/Logoff > Audit Logon, success and failure. This alternative command **changes audit policy** and should be run deliberately:

```powershell
auditpol.exe /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
```

Enable Audit User Account Management for 4740 where appropriate. Security supplies 4625, 4624, 4740, and 1102. System supplies 104 and 7045 with provider filters. Event 104 identifies the log that was cleared; it does not always mean System. Domain account activity may be recorded on a domain controller; this application reads local logs. No audit settings were changed automatically.

## Diagnose degraded operation

Inspect the configured `live/reports/dashboard.html`, `live/status.json`, and `live/logs/diagnostic.log`. `alerts.log` contains incidents, while `events.csv` contains all retained normalized events. Because the alert log is replaced atomically, reopen `Get-Content -Wait` if it stops following updates.

| Status | Meaning / next step |
|---|---|
| Health=OK | LIVE cycle has no reported source or email problem |
| Health=DEGRADED | One source or email failed; other outputs remain available |
| Health=ERROR | Both log channels are unavailable |
| PendingNotifications > 0 in Send | Saved alerts are still waiting for SMTP acceptance |
| SMTP_AUTH_REJECTED | Correct the sender address and app password with Gmail setup |
| SMTP_NETWORK_FAILED | Check DNS, network, firewall, host, and port |
| SMTP_SEND_FAILED | Check libraries, TLS/certificates, credential permissions, and SMTP settings |
| Security access denied | Validate permissions under the actual task account |

Exit codes: 0 successful cycle, 2 limited operation, 1 fatal error. TEST success is not evidence of email delivery. Verify the inbox and spam folder after SMTP acceptance.

For the existing failed test, retain `config.test.local.json`, its OutputRoot, and state. Run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Configure-Gmail.ps1 -ConfigPath .\config.test.local.json
# Continue only after Authenticated=True:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\main.ps1 -Mode DEMO -ConfigPath .\config.test.local.json -SendEmail
```

Existing alerts can be sent with `NewAlerts=0`. After acceptance expect `PendingNotifications=0`, `Health=DEMO`, and `ExitCode=0`. Configurations sharing the same credential path use the same updated password.

## Safe demonstration beside LIVE

DEMO has separate state and does not inject events or attempt logons. To create a new, isolated show:

```powershell
$config=Get-Content .\config.local.json -Raw -Encoding UTF8 | ConvertFrom-Json
$showId=[guid]::NewGuid().ToString('N')
$config.OutputRoot="runtime/show-$showId"
$configPath="config.show-$showId.local.json"
$config | ConvertTo-Json -Depth 10 | Set-Content $configPath -Encoding UTF8
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\main.ps1 -Mode DEMO -ConfigPath $configPath
Start-Process (Join-Path $config.OutputRoot 'demo/reports/dashboard.html')
```

Expect 17 events, 15 failed logons, 2 alerts, CSV/HTML/log output, and 2 `.eml` previews. To deliberately send two real demonstration messages, rerun with `-SendEmail`. Repeat the same command to show deduplication; do not create new state for an email retry.

Present real ingestion and synthetic detection separately. Real 4625 detection needs existing qualifying records and access to Security. Do not attack accounts, install services, or clear logs for the demonstration.

## Run every minute after logout

Verify a manual LIVE cycle, then run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Live.ps1 -SendEmail -InstallTask
```

The script requests the current Windows account password locally (not a PIN or Gmail password), creates `OSO-Live`, and starts it. It repeats every minute with highest privileges, ignores overlaps, and starts after a missed schedule. Use the account that can read Security and decrypt its DPAPI credential. Preview with `tools/Register-MonitorTask.ps1 -ConfigPath .\config.local.json -SendEmail -WhatIf`.

For manual Task Scheduler setup: run whether logged on or not; choose a daily trigger repeating every minute indefinitely; ignore new instances while running. For a checkout at `C:\Projects\OSO`:

```text
Program: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Arguments: -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\Projects\OSO\main.ps1" -Mode LIVE -ConfigPath "C:\Projects\OSO\config.local.json" -SendEmail -IntervalSeconds 60
Start in: C:\Projects\OSO
```

Do not run the task and loop together for the same state. Check LastTaskResult, timestamps, status, and operation after logout. Stop with `Stop-ScheduledTask -TaskName OSO-Live`; disable with `Disable-ScheduledTask -TaskName OSO-Live`. Monitoring cannot execute during shutdown or sleep; available retained logs are read after resumption.

Sources: [Microsoft Audit Logon](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logon), [Microsoft scheduled triggers](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger).
