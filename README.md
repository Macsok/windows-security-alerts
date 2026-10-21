# Windows Suspicious Activity Alert System

[GitHub repository](https://github.com/Macsok/windows-security-alerts)

A PowerShell project that reads Windows event logs, detects repeated failed logons, exports CSV and HTML reports, writes warnings, and sends email through SMTP.

The main rule is **at least 5 failed logons (event 4625) from one IP address OR targeting one account within a sliding 120-second window**. Thresholds are configurable. A single failure is not an attack.

Application messages, reports, emails, and documentation are in English. Original event data and account names keep their original values. The application does not change the Windows display language.

## Requirements

- Windows 10/11, Windows PowerShell 5.1, and .NET Framework 4.8.
- LIVE needs permission to read Security and System and appropriate audit settings.
- DEMO, reports, and automated tests require no external modules or SMTP.
- Real email needs MailKit, TLS, and an SMTP account supporting username/password authentication. .NET SDK 8 or newer is required once to build dependencies; subsequent runs do not need the SDK.

The starting folder contained no previous source code or concept PDF. The implementation follows the supplied six-stage brief. See [validation results](docs/RESULTS.md) for what was actually tested.

## Safe first run

Open PowerShell in the project folder:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1 -Stage 6
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\main.ps1 -Mode DEMO -ConfigPath .\config.example.json
Start-Process .\runtime\demo\reports\dashboard.html
```

A fresh DEMO creates 17 synthetic events, 15 failed logons, 2 alerts, CSV/HTML reports, an alert log, and 2 local `.eml` previews. It makes no logon attempts and sends no email unless you explicitly add `-SendEmail`. Repeat the same command: `NewAlerts=0` with no duplicate notifications. Successful DEMO health is `DEMO`; it does not prove LIVE ingestion.

`Bypass` applies only to the started process. Follow your organization's script policy where overrides are prohibited. Safe example outputs are in [examples/demo](examples/demo).

## LIVE monitoring

Run `START-LIVE.cmd` to request administrator privileges, configure Gmail if needed, start the continuous loop, and open the dashboard. **This launcher enables real email for pending LIVE alerts.**

For LIVE with local email previews:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Live.ps1
```

The loop starts approximately every 60 seconds, accounting for processing time. The dashboard refreshes every 5 seconds and warns after 3 minutes without a cycle. Stop with Ctrl+C. For operation after logout, install the scheduled task using [LIVE setup](docs/LIVE_SETUP.md).

`main.ps1` runs one cycle and defaults to LIVE. DEMO always requires `-Mode DEMO`.

## Configuration and output

If you have no existing local configuration, copy `config.example.json` to `config.local.json`. Keep your existing configuration when upgrading.

| Setting | Default | Purpose |
|---|---|---|
| Threshold | 5 | Required failed logons, range 2-100000 |
| WindowSeconds | 120 | Inclusive window, range 1-86400 |
| InitialLookbackMinutes | 10 | First log query range |
| OverlapSeconds | 180 | Overlap after the previous successful read |
| OutputRoot | runtime | Parent of separate `demo/` and `live/` output |
| Smtp | Empty account settings | Server, TLS, sender, recipients, library and credential paths |

The initial range and overlap must each cover at least one detection window. Relative paths resolve against the JSON file. Changing thresholds reanalyzes history and can generate alerts under the new rule.

```text
state.json                  Events, alerts, source cursors, delivery receipts
status.json                 Source and email health
reports/dashboard.html      Auto-refreshing dashboard and latest 50 events
reports/incidents.csv       Incident history
reports/events.csv          Normalized events including RecordId
logs/alerts.log              One complete alert per line, UTF-8 JSON
logs/diagnostic.log          Diagnostic codes and safe explanations
mail-test/*.eml              Local email previews in TEST mode
```

Incident CSV headers are `TimeCreated, IncidentType, EventId, IpAddress, Account, AttemptCount, Severity, AlertId`. Event CSV headers are `TimeCreated, EventId, RecordId, LogName, IpAddress, Account, LogonType`. Untrusted HTML is encoded. Text resembling a spreadsheet formula receives an apostrophe.

State writes are atomic, with the previous version in `.bak`. A corrupt state stops processing rather than resetting history. Stop the monitor before reviewing backups; restoring an older receipt may resend an email. Reports and `alerts.log` are rebuilt from state without losing earlier incidents. Do not delete state to repeat a demonstration; use a new OutputRoot.

Exit codes: **0** successful cycle, **2** degraded/source or SMTP error, **1** fatal processing error. A successful TEST run is not evidence of real delivery. Security and System have independent cursors; failure of one channel does not stop the other.

## SMTP and Gmail

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Install-MailKit.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Configure-Gmail.ps1 -ConfigPath .\config.local.json
```

The installer builds pinned MailKit 4.17.0 and dependencies for .NET Framework 4.8 in `vendor/mailkit`. It uses the supplied lock file and public NuGet source. Gmail setup asks locally for the full sender address and a Google app password, then checks TLS and authentication without sending. App passwords require two-step verification: [Google instructions](https://support.google.com/accounts/answer/185833?hl=en).

Credentials are stored outside the project in `%LOCALAPPDATA%\OSO\smtp.credential.xml`, protected by Windows DPAPI for the account and machine. The scheduled task must use the same Windows account. Alternatively, supply `OSO_SMTP_USER` and `OSO_SMTP_PASSWORD` as process environment variables through your secret manager. Never put secrets in Git or command history.

Other servers use local `Smtp.Host`, `Port`, `From`, `To`, `Security`, `LibraryDirectory`, and `CredentialPath` settings. TLS is required: `StartTls` (typically 587) or `SslOnConnect` (typically 465), with certificate validation enabled. OAuth-only servers need additional authentication support. The project does not use `Send-MailMessage`.

Explicit connection/authentication test without sending:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
. .\Send-Notification.ps1
$config=Read-MonitorConfig .\config.local.json
Test-SmtpConnection -Smtp $config.Smtp
```

To send real messages for **all pending alerts in the selected mode**:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\main.ps1 -Mode LIVE -ConfigPath .\config.local.json -SendEmail
```

TEST and Send have independent receipts. SMTP failures preserve alerts for retry. `PendingNotifications=0` in Send mode with saved alerts means SMTP accepted them; check the inbox and spam folder for delivery. A crash between acceptance and saving a receipt can still cause a duplicate despite a stable Message-ID.

## Upgrade existing reports to English

Legacy alert labels are translated when state is loaded. Alert IDs, account identities, timestamps, and delivery receipts are preserved. An internal legacy hash seed remains for compatibility. **CSV headers have changed to English**; update external consumers.

Stop the loop/task and refresh existing reports without reading Windows logs or sending mail:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Update-EnglishReports.ps1 -ConfigPath .\config.local.json
```

Use `config.test.local.json` for the separate existing test. The refresh updates saved reports and existing local email previews. Historical diagnostics, backups, and delivered messages remain intact. The last actual monitoring timestamp and health are preserved.

## Tests and Git sharing

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1 -Stage 6
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-LiveTests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-EnglishTests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Test-ShareReadiness.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Export-SharePackage.ps1
```

Tests use synthetic events and mocked failures, without sending mail or changing audit policy. The share tool creates `dist/OSO-English.zip` from an explicit allowlist: source, docs, tests, and synthetic examples. **Use this archive when sharing the folder manually.** Git ignore rules do not filter an ordinary folder ZIP.

- [LIVE setup, Windows audit settings, and SMTP troubleshooting](docs/LIVE_SETUP.md)
- [Architecture and algorithm](docs/ARCHITECTURE.md)
- [Validation results and acceptance status](docs/RESULTS.md)
- [Ten-minute presentation and 15 questions](docs/PRESENTATION.md)
- [Git publication and sharing instructions](docs/SHARING.md)

History has no automatic retention and is replayed each cycle. Plan archiving before extended high-volume use. This is a local educational monitor, not a centralized SIEM.
