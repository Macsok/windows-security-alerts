# Validation results and acceptance status

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

## Acceptance checklist

| Requirement | Status | Evidence or remaining check |
|---|---|---|
| Read Windows logs and handle access errors | Partially verified | Real System read; Security access still needs validation |
| At least five failures from one IP in 120 seconds | Works with synthetic data | Five/seven attempts and exact window boundary |
| At least five failures for one account in 120 seconds | Works with synthetic data | Different IPs and absent-IP scenarios |
| No alert for four attempts or five outside the window | Works with synthetic data | Four attempts, 124 seconds, ten-minute spread |
| Deduplicate incidents and notifications across runs | Works in tests | JSON reload, separate processes, late events, TEST/Send mocks, language migration |
| Write logs/alerts.log | Works in tests and prior System run | Complete JSON Lines with persistent history |
| Export CSV | Works in tests | English headers, counts, formula protection |
| HTML dashboard with summaries | Works in tests | Escaping, counters, source/email health, refresh, recent events |
| SMTP email with safe configuration | TEST/TLS verified; local state records SMTP acceptance | Two existing Send receipts preserved; inbox receipt not independently verified |
| Run every minute | Loop verified with DEMO; task not installed | Scheduler instructions and WhatIf only; verify after logout |
| DEMO and integration | Works in tests | 17 events, two incidents, independent output, restart persistence |
| English docs and presentation | Prepared | README, architecture, LIVE setup, presentation/Q&A, sharing guide |
| Git-ready distribution | Prepared; local review required before upload | Ignore rules, explicit package allowlist, content checker, Windows CI definition |

## Limits

No earlier code or concept presentation PDF was supplied in the starting folder. Original presentation compliance cannot be independently confirmed. Windows 10 and 11 have not both been tested separately. The full Security-to-real-email path and scheduled operation after logout remain target-machine acceptance checks. History has no automatic retention, and SMTP cannot guarantee exactly-once delivery across a crash between server acceptance and receipt persistence.
