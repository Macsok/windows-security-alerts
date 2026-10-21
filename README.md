# Windows Suspicious Activity Alert System

[Repository](https://github.com/Macsok/windows-security-alerts) · [Architecture](docs/ARCHITECTURE.md) · [Validation results](docs/RESULTS.md)

A PowerShell application for Windows 10/11 that reads Security and System logs, detects repeated failed logons, writes CSV/HTML reports and a warning log, and sends SMTP email alerts.

**Detection rule:** at least **5 events 4625 from one IP address OR targeting one account within a sliding 120-second window**. A single failed logon does not trigger this rule. The application also reports account lockouts, log clearing, and service installation events.

The console checks logs every **5 seconds** and the dashboard refreshes every **1 second** by default. All application messages and reports are in English; Windows event data keeps its original values.

## 1. Prepare the other computer

Use **64-bit Windows PowerShell 5.1**, started with **Run as administrator**, for the installation and LIVE steps below. Search the Start menu for **Windows PowerShell**. The tested host is Windows 11; the project targets Windows 10/11. PowerShell 7 (`pwsh`), Linux, and macOS are not the documented runtime.

Check the current console:

```powershell
$PSVersionTable.PSVersion
$PSVersionTable.PSEdition
[Environment]::Is64BitProcess
```

Expected: version `5.1`, edition `Desktop`, and `True`.

| Component | When needed | Installation / check |
|---|---|---|
| .NET Framework 4.8 or later 4.x | Application runtime | [Microsoft installation guide](https://learn.microsoft.com/en-us/dotnet/framework/install/installing-the-net-framework) |
| Git | Only for the clone method | [Git for Windows](https://git-scm.com/downloads/win); ZIP download is an alternative |
| .NET SDK | Building the email libraries on this PC | [Windows .NET 10 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/10.0), tested with SDK 10.0.402; choose **SDK**, not only Runtime |
| Browser | Viewing the local HTML dashboard | Edge, Chrome, or another browser |
| SMTP account | Real email delivery | Gmail with an app password, or another server supporting the implemented TLS/password authentication |

Check .NET Framework:

```powershell
Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release
```

A release value of **528040 or greater** meets the .NET Framework 4.8 requirement. If the key is missing or the value is smaller, install the framework first and restart Windows if requested. .NET Framework and the .NET SDK are separate requirements: the SDK builds MailKit, while Windows PowerShell runs on .NET Framework.

**DEMO and LIVE without email do not need the .NET SDK or MailKit.** No Pester, PSWriteHTML, Python, database, or web server is required. MailKit installation needs HTTPS access to NuGet; Gmail delivery needs access to `smtp.gmail.com:587`.

Use the same Windows account for setup and monitoring. If UAC asks you to sign in as a different administrator, configure Gmail from that administrator's console too; DPAPI credentials are tied to the account and computer.

## 2. Download the project

Choose **one** method. These commands assume a first installation and put the project under your own user profile, without depending on the author's folders.

### Option A: Git

After installing Git, reopen Windows PowerShell as administrator, then run:

```powershell
$projectParent = Join-Path $env:USERPROFILE 'source'
New-Item -ItemType Directory -Path $projectParent -Force | Out-Null
git clone https://github.com/Macsok/windows-security-alerts.git (Join-Path $projectParent 'windows-security-alerts')
Set-Location (Join-Path $projectParent 'windows-security-alerts')
```

If you already cloned the project, enter that folder and use `git pull --ff-only` after stopping the monitor. Do not clone over an existing installation or overwrite its local configuration.

### Option B: ZIP, without Git

Download [the main branch ZIP](https://github.com/Macsok/windows-security-alerts/archive/refs/heads/main.zip). If your browser saved the default filename in Downloads, run:

```powershell
$projectParent = Join-Path $env:USERPROFILE 'source'
$zipPath = Join-Path $env:USERPROFILE 'Downloads\windows-security-alerts-main.zip'
Unblock-File -LiteralPath $zipPath
Expand-Archive -LiteralPath $zipPath -DestinationPath $projectParent
Set-Location (Join-Path $projectParent 'windows-security-alerts-main')
```

Adjust `$zipPath` if the browser used another location or filename. Extract into a new folder. A source ZIP made by the project's sharing tool has a different layout; extract it into your chosen project folder and open the folder containing `main.ps1`.

For either method, verify you are in the project root:

```powershell
Get-Item .\main.ps1, .\config.example.json
Get-ChildItem -Path . -Filter *.ps1 -Recurse -File | Unblock-File
```

**All remaining relative commands are run from this folder.** When opening another console, use `Set-Location` to return here. For the clone method, that is:

```powershell
Set-Location (Join-Path $env:USERPROFILE 'source\windows-security-alerts')
```

For the GitHub ZIP method, use `source\windows-security-alerts-main` instead.

## 3. Create this computer's configuration

```powershell
if (!(Test-Path -LiteralPath .\config.local.json)) {
    Copy-Item -LiteralPath .\config.example.json -Destination .\config.local.json
}
```

This is a local file and is intentionally absent from Git. Its defaults are ready for DEMO and LIVE with local email previews. Do not copy the author's configuration, runtime history, credential XML, or absolute paths from another machine. Create this PC's configuration from the template and run Gmail setup on this PC if email is needed.

| Setting | Default | Purpose |
|---|---|---|
| Threshold | 5 | Number of failed logons needed to trigger a rule |
| WindowSeconds | 120 | Inclusive sliding window |
| InitialLookbackMinutes | 10 | First query's history range |
| OverlapSeconds | 180 | Overlap between successful queries |
| PollIntervalSeconds | 5 | Console loop interval |
| DashboardRefreshSeconds | 1 | Browser refresh interval |
| OutputRoot | runtime | Local output directory relative to this JSON file |
| Smtp | Blank account settings | Filled by Gmail setup or configured for another SMTP provider |

Keep the initial lookback and overlap at least as large as the detection window. Relative paths resolve against the configuration file. Changing thresholds reanalyzes saved history and can generate new alerts.

Commands below use a process-only execution-policy override. They do not change the machine's execution policy. Where organizational policy blocks scripts or audit changes, use the approved administrative process rather than bypassing that policy.

## 4. Verify the installation with DEMO

This step needs no email account and makes no real logon attempts:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\main.ps1 -Mode DEMO -ConfigPath .\config.local.json
Start-Process .\runtime\demo\reports\dashboard.html
```

Expected on a fresh configuration/output folder:

```text
Mode                 : DEMO
Health               : DEMO
ReadEvents           : 17
NewAlerts            : 2
TotalAlerts          : 2
NotificationMode     : Test
PendingNotifications : 0
ExitCode             : 0
```

The dashboard shows **15 failed logons** from synthetic data, an IP incident, and an account incident. Reports appear under `runtime/demo/`; two `.eml` previews appear under `runtime/demo/mail-test/`. Nothing is sent.

Repeat the same main.ps1 command. Expected: `NewAlerts=0`, with the same history and no duplicate previews. Use a different OutputRoot for a fresh demonstration; do not erase LIVE state.

## 5. Enable and verify Windows log collection

In the administrator console, inspect the current Audit Logon setting:

```powershell
auditpol.exe /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}"
```

To record successful and failed logons, explicitly enable both:

```powershell
auditpol.exe /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
```

This command changes Windows audit policy. It must succeed; `0x00000522` means the console lacks the required privilege. Verify again with `/get`. The GUID works independently of the Windows display language. Domain/group policy can override a local setting.

Then check channel access:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Test-WindowsLogs.ps1
```

Expected: **Read completed** for both Security and System. Zero matching events is allowed. **Read failed** means you must resolve access or channel availability before claiming full LIVE operation. Inspect the returned rows, not only the process exit code.

The app reads Security 4625, 4624, 4740, 1102 and System 104, 7045. Additional account-management auditing may be needed for 4740. Domain account events can reside on a domain controller; this project reads the local computer. [Microsoft Audit Logon](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logon).

## 6. Start LIVE without sending email

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Live.ps1 -ConfigPath .\config.local.json
```

Leave that window open. The app opens `runtime/live/reports/dashboard.html`, polls approximately every five seconds, and writes local TEST messages for new incidents. Success means `Mode=LIVE`, `Health=OK`, and both sources `OK`. An empty incident list is normal until a rule qualifies. Check that **Last cycle UTC** advances.

The browser refreshes every second, but new data requires a completed polling cycle. Queries, report generation, SMTP, and machine load can extend a cycle. At the default interval the dashboard warns after 20 seconds without an update.

Press **Ctrl+C** in the monitoring window before continuing to email setup. Run only one console loop or scheduled task for the same output folder.

## 7. Set up email on this computer

Skip this section to continue using local previews. For real email, first install the **.NET SDK** from step 1. Reopen administrator Windows PowerShell after installation, return to the project folder, and check:

```powershell
& "$env:ProgramFiles\dotnet\dotnet.exe" --list-sdks
```

At least one SDK must be listed. The project has been built with SDK 10.0.402; the installer supports SDK 8 or newer. Installing only the .NET Runtime does not provide the build command.

### Build MailKit

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Install-MailKit.ps1
Test-Path .\vendor\mailkit\MailKit.dll
Test-Path .\vendor\mailkit\MimeKit.dll
```

Expected: successful build, a `Loaded MailKit` message, and two `True` results. The installer downloads the pinned MailKit 4.17.0 dependency graph from NuGet and builds for .NET Framework 4.8. It does not require Visual Studio. If package restore fails, resolve network/proxy access before continuing. The SDK is not needed for later runs once the libraries are built.

### Configure Gmail

1. Enable Google two-step verification for the sender account.
2. Create an [app password](https://myaccount.google.com/apppasswords). Availability depends on account/security policy; see [Google's requirements](https://support.google.com/accounts/answer/185833?hl=en).
3. Run the setup locally:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Configure-Gmail.ps1 -ConfigPath .\config.local.json
```

Enter the full Gmail sender address, recipient address, and the sender's **Google app password without spaces** in the credential dialog. The credential username is the sender's Gmail address, not the Windows username. Do not enter the password into JSON, source code, or chat.

Setup uses `smtp.gmail.com:587` with required STARTTLS. It stores the credential outside the project in `%LOCALAPPDATA%\OSO\smtp.credential.xml`, protected by Windows DPAPI. It updates local SMTP paths and checks authentication without sending a message.

Expected:

```text
Connected     : True
Secure        : True
Authenticated : True
```

**Do not continue with real sending if authentication failed.** The setup can leave a configuration file present even after a failed connection test. Correct the credentials and rerun it. An existing XML file is not proof of accepted credentials.

On another computer or Windows account, run setup again. Copying the credential XML will not transfer its DPAPI protection, and an old LibraryDirectory may point at the previous checkout. An OAuth-only SMTP server requires authentication support beyond this implementation; ordinary Google account passwords are not the documented Gmail method.

### Verify one real email delivery with synthetic data

The following command **sends actual email** for pending DEMO alerts. On the fresh installation above, expect two messages even if `NewAlerts=0`, because TEST and Send have separate receipts:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\main.ps1 -Mode DEMO -ConfigPath .\config.local.json -SendEmail
```

Expected: `NotificationMode=Send`, `PendingNotifications=0`, `Health=DEMO`, and `ExitCode=0`. Check the recipient inbox and spam folder. SMTP acceptance is not proof of inbox delivery. Repeating the same command normally sends no further messages for those incidents.

## 8. Start continuous LIVE with email

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Live.ps1 -ConfigPath .\config.local.json -SendEmail
```

This enables delivery of **all pending LIVE alerts**, including incidents previously saved with local TEST previews. Keep the console open. `START-LIVE.cmd` is a shortcut for this email-enabled mode; use it after dependencies and credentials are ready.

To override the console interval:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Live.ps1 -ConfigPath .\config.local.json -SendEmail -IntervalSeconds 5
```

Otherwise the loop reloads PollIntervalSeconds from local configuration between cycles. Restart a loop launched by an older code version once after upgrading. Stop with Ctrl+C; closing the console, logging out, sleep, or shutdown interrupts this mode.

## 9. Set up Discord notifications

Skip this section if you do not want chat alerts. To enable real-time Discord alerts, you need a valid Webhook URL from your Discord server. The monitoring script uses the `PSDsHook` module and automatically loads the required `.NET` HTTP assemblies.

**Configure Discord Webhook**
1. In your Discord server, go to **Server Settings > Integrations > Webhooks**.
2. Create a New Webhook, select the target channel, and copy the Webhook URL.
3. Run the setup locally:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Live.ps1 -SetupDiscord
```

Answer `Y` to the prompt and paste the full Webhook URL without spaces. The link must match the standard Discord API format (`https://discord.com/api/webhooks/...` or `https://discordapp.com/api/webhooks/...`).

Setup validates the URL format and stores it directly in `.\config.local.json` under the `"Discord"` property block. Unlike SMTP credentials, it does not require Windows DPAPI protection, but you should treat the URL as a password. Do not commit `config.local.json` to source code or share the URL publicly, as it allows anyone to post messages to your channel.

**Expected:**
```text
Webhook config:
Discord option On? (Y/N): Y
Paste your webhook link: [https://discord.com/api/webhooks/](https://discord.com/api/webhooks/)...
Discord config saved.
```
If you enter an invalid URL, the setup will reject it with `Wrong webhook link, skipped.` Correct the URL and rerun the setup.

**Verify Discord delivery**
The following command sends ONE synthetic message to Discord to verify the module and your webhook configuration. It touches no state or logs:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Test-Discord.ps1
```

**Expected:** `Test message sent. Check your Discord channel.` printed in the console. A red embedded message titled "Security Alert" with synthetic target data will appear in the configured Discord channel.

**Start continuous LIVE with Discord**
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Live.ps1
```

Once configured, the standard LIVE mode automatically enables immediate delivery of all new alerts to Discord as they are detected in the cycle. If you want both Email and Discord deliveries simultaneously, simply append the email switch:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Live.ps1 -SendEmail
```

## 10. Optional: prove detection with real failed logons

Use your own test PC/VM and a disposable **local** account. Repeated failures can lock an account, so do not test against your daily, administrator, or domain account. This procedure is separate from synthetic DEMO. No failed logons are generated automatically by the application.

Leave LIVE running. Open a **second administrator Windows PowerShell** and enter the project folder. Create a new test account; the `*` prompts for a new password without printing it:

```powershell
net.exe user OSO-Demo * /add
$testStart = Get-Date
runas.exe "/user:$env:COMPUTERNAME\OSO-Demo" cmd.exe
```

At the runas prompt, deliberately enter an incorrect password. Repeat **only the runas command** five times within 120 seconds, entering an incorrect password each time. Do not use `/netonly`, `/savecred`, or a Windows Hello PIN. If OSO-Demo already exists, choose another disposable account name instead of changing an existing person's account.

Confirm the records using the project's XML parser:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
. .\Get-Logs.ps1
Get-WindowsLogs -LogName Security -StartTime $testStart |
    Where-Object { $_.EventId -eq 4625 -and $_.UserName -eq 'OSO-Demo' } |
    Format-Table TimeCreated, EventId, RecordId, Account, IpAddress
```

Expect at least five matching 4625 records. After a completed LIVE cycle, expect an **Excessive failed logons: Account** incident with High severity. An IP incident can appear too if Windows supplied the same IP, often loopback `::1`. Missing IPs do not prevent the account rule. Count=5 records the threshold crossing even if you made six or more attempts.

Check the dashboard, CSV, warning log, and recipient inbox. If Windows has no matching records, check Audit Logon and the runas error first. If Windows has records but LIVE does not, check Security source status, the active configuration, timestamps, and that you installed the current code. Times in reports are UTC; Event Viewer can display local time. [Microsoft event 4625](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625).

After the demonstration, remove only the disposable account you created:

```powershell
net.exe user OSO-Demo /delete
```

## 10. Find reports and diagnose problems

With the default configuration:

```powershell
Start-Process .\runtime\live\reports\dashboard.html
Get-Content .\runtime\live\logs\alerts.log -Tail 5 -Encoding UTF8
Get-Content .\runtime\live\logs\diagnostic.log -Tail 10 -Encoding UTF8
```

The diagnostic command is needed only if the file exists; no diagnostic file on a clean successful installation is normal. If you changed OutputRoot, use that directory instead of runtime. Each mode has separate state:

```text
runtime/demo/ or runtime/live/
  state.json                 Events, alerts, cursors, delivery receipts
  status.json                Source and email health
  reports/dashboard.html     Dashboard and latest 50 events
  reports/incidents.csv       Incident history
  reports/events.csv          Events including RecordId
  logs/alerts.log              One complete alert per line, UTF-8 JSON
  logs/diagnostic.log          Safe diagnostic explanations, when needed
  mail-test/*.eml              Local TEST previews
```

| Symptom | Action |
|---|---|
| Script blocked / not digitally signed | Unblock the reviewed download and use the process-only commands above; check organizational policy |
| Security shows Read failed or ERROR | Use an elevated console and verify access under the actual monitoring account |
| No 4625 after wrong passwords | Verify failure auditing, the target account, time range, and runas error |
| Dashboard unchanged | Open the LIVE report, check Last cycle UTC, refresh with Ctrl+F5, and confirm the loop is still running |
| dotnet missing / no SDK listed | Install the SDK, reopen the console, and check the Program Files path above |
| MailKit or MimeKit missing | Complete Install-MailKit.ps1 and verify both DLLs |
| SMTP_AUTH_REJECTED / Gmail 5.7.8 | Rerun Gmail setup with the full sender address and correct app password |
| DPAPI/credential access failure after moving PCs | Reconfigure Gmail on this PC under the account running the monitor |
| PendingNotifications greater than zero in Send | Read diagnostic.log; fix the SMTP problem and retry the same mode/configuration |
| Another instance is running | Stop the other loop/task for this OutputRoot; do not delete state or lock files to bypass it |

Exit codes: **0** successful cycle, **2** degraded/source or mail problem, **1** fatal processing failure. DEMO reports `Health=DEMO`; LIVE should report `Health=OK`. A TEST success never proves real sending. If there are no alerts, an empty Send queue does not itself prove SMTP connectivity.

State writes keep a previous `.bak`. Stop monitoring before recovery and preserve copies. Restoring older receipts can resend a message. A crash between SMTP acceptance and receipt persistence can also cause a duplicate; stable Message-ID cannot guarantee exactly-once delivery. History grows without automatic retention, so plan archiving for extended use.

## 11. Optional: run after logout

The console is the fast five-second mode. The optional Task Scheduler configuration runs **once per minute**, including when logged off. Stop the console first, then run from administrator PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Live.ps1 -ConfigPath .\config.local.json -SendEmail -InstallTask
Get-ScheduledTaskInfo -TaskName OSO-Live | Select-Object LastRunTime, LastTaskResult, NextRunTime
```

The task setup requests the current **Windows account password**, not a Gmail password or PIN. Use the same account that configured Gmail; it needs password-based task logon, event-log access, and access to the project/DPAPI file. Do not choose SYSTEM for a credential created under your user account.

Verify a new report timestamp after a minute and again after logout. To return to console mode, disable future task runs and stop the current task before starting the console:

```powershell
Disable-ScheduledTask -TaskName OSO-Live | Out-Null
Stop-ScheduledTask -TaskName OSO-Live
```

No monitoring executes while the PC is off or asleep. Available retained logs can be read after it resumes. Additional scheduler details are in [LIVE_SETUP.md](docs/LIVE_SETUP.md).

## Tests, updates, and sharing

Run local tests from the project root; they use synthetic data/mocks and do not send email or change audit policy:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1 -Stage 6
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-LiveTests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-EnglishTests.ps1
```

For upgrades, stop monitoring, preserve config.local.json and runtime, pull the code, and restart. Rebuild dependencies if they changed. Legacy English-label migration preserves alert IDs and delivery receipts. See [RESULTS.md](docs/RESULTS.md) for actual checks and remaining limitations; a clean-copy test on the development host is not proof of installation on every Windows version.

For another person, share Git source or a reviewed source archive, not your working folder with credentials and logs:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Test-ShareReadiness.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Export-SharePackage.ps1
```

The exporter excludes local settings, credentials, real history, dependencies, and test output. If its default archive already exists, use a new `-OutputPath`. The recipient follows this README from step 1 and configures their own PC. Never put passwords, tokens, active webhooks, or real logs into Git.

Further documentation: [architecture](docs/ARCHITECTURE.md), [LIVE reference](docs/LIVE_SETUP.md), [presentation and Q&A](docs/PRESENTATION.md), [Git sharing](docs/SHARING.md).
