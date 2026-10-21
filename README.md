# Windows Security Alerts

Windows 10/11. Use **64-bit Windows PowerShell 5.1 as administrator**.
Five failed logons (4625), from one IP or for one account within 120 seconds, create an alert.
Logs are checked every 5 seconds; the dashboard refreshes every second.

## 1. Install

Download and extract the repository ZIP, or:

```powershell
git clone https://github.com/Macsok/windows-security-alerts.git
cd windows-security-alerts
```

Open PowerShell in the folder containing `main.ps1`. Run once on each computer:

```powershell
Get-ChildItem -Recurse -Filter *.ps1 | Unblock-File
if (!(Test-Path .\config.local.json)) { Copy-Item .\config.example.json .\config.local.json }
```

Do not copy another computer's local configuration or credentials.

## 2. DEMO (no real logons or messages)

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\main.ps1 -Mode DEMO
Start-Process .\runtime\demo\reports\dashboard.html
```

First run: **17 events, 2 alerts, PendingNotifications=0**. Email previews: `runtime/demo/mail-test/`.
Repeat: **NewAlerts=0**. DEMO and LIVE histories are separate.

## 3. LIVE

Enable logon auditing and check access:

```powershell
auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Test-WindowsLogs.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Live.ps1
```

Dashboard opens automatically. Stop with **Ctrl+C**. Without `-SendEmail`, messages stay in local `.eml` files.
For 2-second polling, add `-IntervalSeconds 2`.

## 4. Gmail

Install the [.NET 10 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/10.0) (**SDK**, not Runtime).
Enable Google two-step verification and create an [app password](https://support.google.com/accounts/answer/185833).
Stop the monitor. Use the same Windows account for setup and monitoring:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Install-MailKit.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Configure-Gmail.ps1
```

Enter your full Gmail address and **app password**. Continue only when `Authenticated=True`.
Credentials are encrypted for this Windows account and computer, outside the repository.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Live.ps1 -SendEmail
```

All pending LIVE alerts will be sent. `PendingNotifications=0` means SMTP accepted them; check inbox/spam.
`START-LIVE.cmd` also enables real email.

## 5. Trigger a real test

Use a disposable local account. In a second administrator PowerShell:

```powershell
net user OSO-Demo * /add
runas.exe /noprofile "/user:$env:COMPUTERNAME\OSO-Demo" cmd.exe
```

The first command sets its password. Run the **second command five times within 120 seconds**,
entering a wrong password each time. Local lockout policy can stop further attempts.
Type a non-empty password manually; no characters appear while typing. Expect error **1326** for a wrong password.
If you get `Unable to acquire user password`, retry in a separate Windows PowerShell window
(Win+R, `powershell.exe -NoProfile`). This message alone does not confirm a failed logon was recorded.
Wait about 5 seconds. Expect an account alert; an IP alert depends on whether Windows records an IP.

Check that Windows recorded failures:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddMinutes(-5)} |
    Select-Object TimeCreated,Id,RecordId -First 10
```

Remove the account afterwards:

```powershell
net user OSO-Demo /delete
```

## Output and settings

Files are in `runtime/live/` (or `runtime/demo/`):

| File | Contents |
|---|---|
| `reports/dashboard.html` | Live status, incidents and recent events |
| `reports/incidents.csv` | Incidents |
| `reports/events.csv` | Events |
| `logs/alerts.log` | Alert history |
| `logs/diagnostic.log` | Errors |
| `state.json` | History and delivery receipts; keep this file |

Edit `Threshold`, `WindowSeconds`, `PollIntervalSeconds` or `DashboardRefreshSeconds` in `config.local.json`.
Initial lookback and overlap must cover the detection window.

## Group member's report

`report.ps1` adapts the supplied group code: categories, `Group-Object`, PSWriteHTML cards,
donut charts, event table and `stats.json`. It reads saved events; it does not send messages.

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
Install-Module PSWriteHTML -Scope CurrentUser
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\report.ps1 -Mode DEMO
Start-Process .\runtime\demo\reports\team-report.html
```

Use `-Mode LIVE` for real events. Includes the last 24 hours of available history
(DEMO uses its fixed sample dates). Charts need internet. The basic dashboard needs no extra modules.
Events 4720, 4722, 4724 and 4732 require the corresponding Windows account-management auditing policies.
[PSWriteHTML documentation](https://github.com/EvotecIT/PSWriteHTML).

## Discord

In Discord: **Server Settings > Integrations > Webhooks**, create a new webhook and copy its URL.
Stop the monitor, then run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Live.ps1 -SetupDiscord
```

Answer `Y` and paste the **new** webhook. Setup installs PSDsHook automatically if missing,
saves the webhook in ignored `config.local.json`, then starts LIVE. Add `-SendEmail` for both channels.
Discord receives all pending LIVE alerts. Configuration and DEMO do not send test messages.
Local configuration stays in the same folder when switching Git branches; it is not stored in either branch.

To deliberately send one real test message:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Test-Discord.ps1
```

The supplied Discord embed code is preserved in `Send-Discord.ps1`. Never commit a webhook.
Email uses MailKit instead of the supplied localhost email example.

## Run after logout (optional, every minute)

Stop the console monitor first:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Live.ps1 -InstallTask -SendEmail
```

Enter the same Windows account's password, not its PIN or Gmail password.
Before returning to the console loop:

```powershell
Disable-ScheduledTask -TaskName OSO-Live
Stop-ScheduledTask -TaskName OSO-Live
```

## Problems

| Problem | Action |
|---|---|
| Security access denied / 0x522 | Run Windows PowerShell as administrator |
| No 4625 events | Check audit policy and the Security log |
| Events but no new alert | Five matching failures must fit in 120 seconds; old incidents are deduplicated |
| Dashboard stopped | Keep monitor console open; check its errors |
| Gmail rejected credentials | Repeat setup using an app password and the same Windows account |
| SMTP pending | Check `logs/diagnostic.log`; sending retries automatically |
| MailKit build fails | Install SDK; check NuGet access and .NET Framework 4.8+ |

## Tests and help

GitHub Actions runs basic syntax and DEMO checks. Run the full test suites locally when needed.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-SmokeTests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1 -Stage 6
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-LiveTests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-EnglishTests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-ReportTests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-DiscordTests.ps1
Get-Help .\Start-Live.ps1 -Detailed
. .\Get-Logs.ps1
Get-Help Get-WindowsLogs -Full
```

Synthetic tests do not prove real Windows log access or SMTP delivery on another PC. Verify LIVE there.
[Presentation and questions](docs/PRESENTATION.md) | [Architecture](docs/ARCHITECTURE.md)
