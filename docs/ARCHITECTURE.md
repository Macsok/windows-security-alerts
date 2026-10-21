# Architecture and detection algorithm

The starting folder contained no previous source code or concept PDF. No PSWriteHTML, TheDashboard, or PSDsHook implementation was available to reuse. Requirements come from the supplied six-stage brief. The application uses PowerShell and .NET without a database, web server, Python, or dashboard module. MailKit is needed only for real SMTP.

## Module flow

```text
main.ps1 -> Monitor.ps1 -> Get-Logs.ps1 (LIVE) / New-DemoEvents.ps1 (DEMO)
                        -> Detect-Attacks.ps1 -> state.json
                        -> Generate-Reports.ps1 -> CSV / HTML / alerts.log
                        -> Send-Notification.ps1 -> TEST files / SMTP
                        -> receipts / status.json / refreshed reports
```

`Common.ps1` supplies UTC conversion, hashes, atomic writes, config, diagnostics, and label migration. Dot-source modules to call their functions; loading a module alone does not read logs or send messages. `Start-Live.ps1` handles interactive elevation/setup, `Start-Monitor.ps1` starts successive processes, and `Register-MonitorTask.ps1` configures operation after logout.

Each mode has separate output and an exclusive file lock. Save events and alerts before reports and SMTP. `SourceState` stores `LastScanUtc` and `RetryFromUtc` independently for Security and System. A failed channel retains its cursor while the healthy channel continues. State without these cursor fields is upgraded on use. Corrupt JSON causes an error, never an automatic reset.

The dashboard is static HTML with five-second refresh and a three-minute stale-data warning. Report generation time is distinct from the last actual monitoring cycle. Exit codes: 0 success, 2 degraded/source or SMTP error, 1 fatal processing failure. A successful synthetic run retains health `DEMO`.

## Data contracts

Events: `EventKey, TimeCreated, EventId, RecordId, LogName, MachineName, ProviderName, UserName, Account, IpAddress, LogonType`. Times are UTC ISO 8601. EventKey hashes machine, channel, provider, record ID, time, and event ID, handling record-number reuse after a cleared log. XML EventData/UserData fields are independent of localized Message text.

Accounts include domains when available and are grouped case-insensitively. IPv4-mapped IPv6 is normalized. Missing, wildcard, or invalid IPs become null and never form a shared unknown-IP group. Missing accounts remain null. Raw account names are not translated.

Alerts: `AlertId, TimeCreated, Type, Dimension, Entity, EventId, IpAddress, Account, Count, WindowStart, WindowEnd, Severity, Reason`. Dimensions are `IP`, `Account`, and `Event`; severities are `High` and `Medium`. Event 4624 supplies context. Events 4740, 1102, 104, and 7045 create review warnings, not assertions of an attack.

## Sliding window

1. Deduplicate by EventKey and sort chronologically.
2. For each 4625, update independent queues for the available IP and account.
3. Remove events more than 120 seconds older than the incoming event.
4. Add the event and emit an alert when the queue reaches five entries in a new episode.
5. Keep that episode active while the threshold is sustained. A later event can start a new episode when fewer than threshold minus one events remain before enqueueing.

Exactly 120 seconds is inside the window. Attempts at 0, 20, 40, 60, and 80 seconds alert; attempts at 0, 150, 300, 450, and 600 seconds do not. One account can trigger across different IPs. Two alerts are intentional if both dimensions qualify.

Count records the threshold crossing, so seven attempts can produce one IP alert with Count=5; all seven remain in event history. Stable AlertId prevents replay duplicates. Overlapping evidence for the same dimension, entity, and rule also suppresses duplicates when late events move the crossing time.

Sorting costs O(n log n) with O(n) memory. Late-event correlation additionally scans saved alerts, so the complete cycle is not guaranteed O(n log n). All history is retained and replayed for simplicity. There is no automatic retention; archive before long-term high-volume use. Changing the rule reanalyzes history and can create new alerts.

## Persistence, email, and migration

Atomic state replacement saves the previous `.bak`. Reports and the alert log are rebuilt from state to retain incidents without appending duplicates. HTML encodes untrusted values and CSV escapes spreadsheet formulas.

Receipts use `Mode + AlertId`, separating TEST and Send. Failed sends stay pending; successful SMTP acceptance is saved immediately. SMTP acceptance and a local JSON write cannot form one atomic transaction, so a crash between them can cause another send. Stable Message-ID alone does not guarantee server-side deduplication.

English migration updates only recognized legacy application labels. The original account-rule hash seed remains internally. Reasons are translated before late-event comparisons. Event data, identifiers, receipts, and timestamps remain unchanged. Offline report refresh uses the same exclusive lock and sends no mail.

## Six implementation stages

1. Configuration, common functions, contracts, and documentation.
2. XML parser and Windows adapter; missing-field and permission tests.
3. Detector; six required scenarios, boundaries, and restart persistence.
4. CSV/HTML/alert log; encoding, counters, and history.
5. MailKit, TEST previews, retry and delivery deduplication.
6. Main cycle, DEMO, integration, continuous loop, scheduling, and presentation.

See [RESULTS.md](RESULTS.md) for actual verification and outstanding real-world checks.
