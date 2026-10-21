# Validation results and acceptance status

## Basic GitHub Actions checks

The workflow now runs Run-SmokeTests.ps1: PowerShell syntax, an isolated DEMO process,
nonempty HTML/CSV/alert-log/state output, detected events and incidents, and a local email preview.
It uses no external modules, event-log permissions, credentials or messaging services.
The full suites remain available for local validation.

Local checks passed in the working directory and a clean source-only copy. A deliberately
broken entry point that exits successfully without producing reports was correctly rejected.
This checks basic startup and outputs; it does not validate real log collection or delivery.

## Discord integration

After fetching origin, all 10 original Discord commits on origin/main were verified as ancestors of
simplify-project. Restored -SetupDiscord and added its previously missing configuration script,
automatic PSDsHook installation, and short setup/test instructions. Existing Discord embed,
batching, retry/delivery receipts, thumbnail configuration and explicit test script remain.
See [DISCORD_CHANGES.md](DISCORD_CHANGES.md) for the file-by-file preservation record.

Tests: **31 core + 9 LIVE/mock + 7 English/share + 5 reporting/help + 5 Discord = 57 PASS, 0 FAIL**.
New Discord checks mock installation, password input, module availability and Windows logs;
they verify SMTP/custom setting preservation, saved webhook reuse, validation, disabling,
and report/email-preview generation when Discord is unavailable. No real message was sent.
Real installation and webhook delivery from the new setup flow were not performed.

## Simplification and group report (branch simplify-project)

- Shortened README to direct installation, DEMO, LIVE, Gmail and test commands; simplified the default dashboard to basic tables.
- Adapted the supplied group report into report.ps1: event categories, grouping, PSWriteHTML cards/charts/table, and JSON statistics. Added collection of its account-management event IDs.
- Added comment-based help to production functions and entry/tool scripts; checked actual Get-Help synopsis and parameter output.
- Repaired IntervalSeconds forwarding and made Discord optional at load time. DEMO never sends Discord webhooks.
- Local Windows PowerShell 5.1 suites: **31 core + 9 LIVE/mock + 7 English/share + 5 reporting/help = 52 PASS, 0 FAIL**.
- Generated the real PSWriteHTML 1.41.0 report from synthetic events: 17 events, 15 warning events, valid HTML and JSON, encoded account text. Both function and command-line generation passed; monitor state was unchanged.
- Built a real DiscordEmbed using PSDsHook 1.0.0 without sending it. The 48-file source share allowlist passed the private-data check.
- No real failed logons, SMTP messages or webhooks were generated for these changes. Real log access, inbox delivery and operation on another computer were not revalidated. Historical checks below describe earlier versions.

## English update: 21 October 2026

All application-owned prompts, reports, CSV headers, email messages, diagnostics, test names, comments, and documentation were converted to English. Legacy labels remain only as migration inputs and identity compatibility data. Raw event/account values are preserved. New tests verify stable alert IDs, unchanged receipts, restart and late-event deduplication, English reports, offline refresh, and share-file exclusions.

Executed on Windows PowerShell 5.1:

| Command | Result |
|---|---|
| `tests/Run-Tests.ps1 -Stage 6` | 30 PASS, 0 FAIL |
| `tests/Run-LiveTests.ps1` | 9 PASS, 0 FAIL |
| `tests/Run-EnglishTests.ps1` | 7 PASS, 0 FAIL |

Total: **46 passing tests**. The LIVE recovery/SMTP tests use mocked sources and transports; the loop test runs two real processes against synthetic DEMO data. No test in these suites sends email or generates failed Windows logons. PowerShell syntax parsing is included. Artifacts stay in ignored test-results directories. Sharing tests also reject populated SMTP settings and exercise the actual archive exporter under PowerShell 5.1. The allowlisted 44-file package passed the content check; it contains no local configuration or runtime history.

The application also avoids claiming an SMTP delivery attempt when Send is configured but no alerts exist. Saved Polish state is translated on read; an offline refresh tool regenerates reports without changing cursor times or delivery receipts. Existing diagnostic history is retained rather than rewritten.

## Prior real-environment checks

- Real System ingestion succeeded during earlier checks, including a 24-hour LIVE run with two 7045 events, two warnings, reports, and local TEST messages.
- Security could not be read under the available execution identity. Partial ingestion reported DEGRADED and retained the failed channel cursor. Full real 4625 detection remains unverified.
- .NET SDK 10.0.402 built the net48 dependency project with no warnings/errors. MailKit 4.17.0 was loaded in Windows PowerShell 5.1. MimeKit message creation and serialization were verified locally.
- A real Gmail STARTTLS connection succeeded. An earlier authentication test was rejected with `5.7.8 Username and Password not accepted`. On 21 October the existing local DEMO state contained two Send receipts, zero pending notifications, and DEMO health, indicating subsequent SMTP acceptance recorded by the application. Inbox delivery was not independently checked, and this update sent no messages.
- Task registration was checked with WhatIf. No task was installed by the agent, no audit policy was changed, and operation after logout has not been tested.

These are separate checks: synthetic success is not evidence of real Windows log ingestion, authentication, or inbox delivery. Offline English refresh preserved the existing event history, alert IDs, receipt contents, and last-scan timestamps in the configured DEMO and LIVE directories.

## LIVE time-filter repair: 21 October 2026

A real local-account test exposed a Windows PowerShell 5.1 time-filter problem: passing UTC DateTime values directly to Get-WinEvent FilterHashtable returned no recent failures, while equivalent local DateTime values returned six real 4625 events. Get-Logs.ps1 now converts UTC query boundaries to local time before querying Windows. Stored event timestamps and processing cursors remain UTC.

Executed `tests/Run-Tests.ps1 -Stage 3`: **18 PASS, 0 FAIL**, including a regression check for all three event queries receiving local-time boundaries representing the original UTC instants. Elevated verification of the real log returned six test failures for both UTC and local input ranges after the fix.

The existing LIVE cursors were rewound to just before the test without deleting events, alerts, or delivery receipts. Reprocessing returned **27 events, 2 new alerts, Health=OK, NotificationMode=Send, PendingNotifications=0, ExitCode=0**. The two alerts matched the account and loopback IPv6 dimensions. SMTP accepted both actual LIVE notifications; inbox receipt has not been independently verified. No additional failed logons were generated by the agent. The earlier request to stop investigating the unrelated GitHub Actions failure remains respected.

## Faster console LIVE refresh: 21 October 2026

The console loop now defaults to a five-second polling interval and the HTML dashboard refreshes every second. Both settings are configurable; older local configurations receive compatible defaults. The effective interval is forwarded to the child cycle and displayed in the report. The console reloads configuration between cycles unless a command-line interval overrides it. Stale-data warnings use three intervals with a minimum of 20 seconds. The separate once-per-minute scheduled task passes an explicit 60-second interval.

Executed the current local suites: **31 core PASS, 9 LIVE PASS, 7 English/share PASS; 0 FAIL**. The two-cycle integration test uses the actual default five-second loop, checks the one-second dashboard refresh, and verifies that state and notifications remain deduplicated. These are local checks; the previously stopped GitHub Actions investigation was not resumed.

The existing console LIVE process was restarted after its current state write completed. Observed actual cycle timestamps were `2026-10-21T10:34:45.9147771Z` and `2026-10-21T10:34:51.0289764Z`, about **5.11 seconds** apart. The resulting status was `Health=OK`, `PollIntervalSeconds=5`, and `DashboardRefreshSeconds=1`. The detection threshold and 120-second window were unchanged. SMTP/network delays and processing time can extend an individual cycle.

## README installation walkthrough: 21 October 2026

The README now documents a complete new-PC installation: prerequisites, Git/ZIP download, a local configuration created from the template, DEMO, auditing and elevated channel checks, LIVE previews, MailKit, Gmail, deliberate email validation, optional real-account demonstration, and scheduling. It does not require the author's profile paths, configuration, or credential files.

Verified the documented setup in an isolated source copy whose path contained spaces, initially without config.local.json, runtime, vendor, or build output. Creating the local configuration and running DEMO twice produced **17 events, 2 alerts, 2 local messages, and no duplicate delivery receipts**. The clean-copy MailKit installer restored dependencies and built successfully with **0 warnings and 0 errors**, then loaded **MailKit 4.17.0.0** using .NET SDK 10.0.402. All **26 PowerShell command blocks** parsed successfully and local documentation links resolved. The source share-content check passed for 44 files.

This walkthrough used the available Windows host with Windows PowerShell 5.1 and an already installed .NET SDK/.NET Framework. It did not provision a separate physical PC, install Windows/.NET from scratch, authenticate a new Gmail account, send test mail, or create another failed-logon test. Those target-machine steps remain explicit in the README.

## Acceptance checklist

| Requirement | Status | Evidence or remaining check |
|---|---|---|
| Read Windows logs and handle access errors | Verified on this Windows host with elevation | Real Security 4625 and prior System reads; permission failures covered separately |
| At least five failures from one IP in 120 seconds | Verified with real local failures and synthetic cases | Six real failures from loopback IPv6 triggered one IP alert; other network addresses covered synthetically |
| At least five failures for one account in 120 seconds | Verified with real local failures and synthetic cases | Six real local-account failures triggered one account alert; distributed-IP case covered synthetically |
| No alert for four attempts or five outside the window | Works with synthetic data | Four attempts, 124 seconds, ten-minute spread |
| Deduplicate incidents and notifications across runs | Works in tests | JSON reload, separate processes, late events, TEST/Send mocks, language migration |
| Write logs/alerts.log | Works in tests and prior System run | Complete JSON Lines with persistent history |
| Export CSV | Works in tests | English headers, counts, formula protection |
| HTML dashboard with summaries | Works in tests | Escaping, counters, source/email health, refresh, recent events |
| SMTP email with safe configuration | Real LIVE SMTP acceptance verified | Two LIVE notifications accepted after the real 4625 test; inbox receipt not independently verified |
| Run every minute | Loop verified with DEMO; task not installed | Scheduler instructions and WhatIf only; verify after logout |
| DEMO and integration | Works in tests | 17 events, two incidents, independent output, restart persistence |
| English docs and presentation | Prepared | README, architecture, LIVE setup, presentation/Q&A, sharing guide |
| Git-ready distribution | Prepared; local review required before upload | Ignore rules, explicit package allowlist, content checker, Windows CI definition |

## Limits

No earlier code or concept presentation PDF was supplied in the starting folder. Original presentation compliance cannot be independently confirmed. Windows 10 and 11 have not both been tested separately. Inbox receipt and scheduled operation after logout remain target-machine acceptance checks. History has no automatic retention, and SMTP cannot guarantee exactly-once delivery across a crash between server acceptance and receipt persistence.
