# Architecture and detection algorithm

The starting folder contained no previous source code or concept PDF. The group member's report.ps1 was supplied later and is now adapted in report.ps1 (PSWriteHTML) and Send-Discord.ps1 (PSDsHook embeds). The monitor itself uses PowerShell and .NET without a database or web server. MailKit is needed only for real SMTP; PSWriteHTML is needed only for the optional team report.

## Module flow

```text
main.ps1 -> Monitor.ps1 -> Get-Logs.ps1 (LIVE) / New-DemoEvents.ps1 (DEMO)
                        -> Detect-Attacks.ps1 -> state.json
                        -> Generate-Reports.ps1 -> CSV / HTML / alerts.log
                        -> Send-Notification.ps1 -> TEST files / SMTP
                        -> receipts / status.json / refreshed reports
```

`Common.ps1` supplies UTC conversion, hashes, atomic writes, config, diagnostics, and label migration. Dot-source modules to call their functions; loading a module alone does not read logs or send messages. `Start-Live.ps1` handles interactive elevation/setup, `Start-Monitor.ps1` starts successive processes, and `Register-MonitorTask.ps1` configures operation after logout.

`report.ps1` reads the selected mode's saved state and generates `reports/team-report.html` plus `reports/stats.json` on request. It retains the supplied categories, Group-Object counts, New-HTML sections/cards/charts/table and JSON statistics. It replaces hardcoded Desktop paths with the configured output folder and Message parsing with normalized XML fields. The original localhost email block is replaced by the existing MailKit notification module. No webhook or personal email address from the supplied snippet is stored in source. Account-management events 4720, 4722, 4724 and 4732 are collected for reporting; individual failed logons are warning events, not automatically incidents. Discord loads only when explicitly configured in LIVE; DEMO does not send webhooks.

Each mode has separate output and an exclusive file lock. Save events and alerts before reports and SMTP. `SourceState` stores `LastScanUtc` and `RetryFromUtc` independently for Security and System. A failed channel retains its cursor while the healthy channel continues. State without these cursor fields is upgraded on use. Corrupt JSON causes an error, never an automatic reset.

The dashboard is static HTML with a configurable refresh (one second by default). Console monitoring polls every five seconds by default; it reloads the configured interval between cycles unless overridden on the command line. Each child cycle receives the effective interval so the report shows the correct cadence. A stale-data warning appears after three intervals, with a minimum of 20 seconds. The once-per-minute scheduled task explicitly reports a 60-second interval. Report generation time is distinct from the last actual monitoring cycle. Exit codes: 0 success, 2 degraded/source or SMTP error, 1 fatal processing failure. A successful synthetic run retains health `DEMO`.

## Data contracts

Events: `EventKey, TimeCreated, EventId, RecordId, LogName, MachineName, ProviderName, UserName, Account, IpAddress, LogonType`. Times are UTC ISO 8601. EventKey hashes machine, channel, provider, record ID, time, and event ID, handling record-number reuse after a cleared log. XML EventData/UserData fields are independent of localized Message text.

New events also retain `GroupSid, MemberSid, MemberName, ActorAccount` from XML. Existing saved events
remain readable without these fields; old 4732 records lacking a group SID cannot be classified as
administrator additions. No account-name lookup or extra network service is required.

Accounts include domains when available and are grouped case-insensitively. IPv4-mapped IPv6 is normalized. Missing, wildcard, or invalid IPs become null and never form a shared unknown-IP group. Missing accounts remain null. Raw account names are not translated.

Alerts: `AlertId, TimeCreated, Type, Dimension, Entity, EventId, IpAddress, Account, Count, WindowStart, WindowEnd, Severity, Reason`. Dimensions are `IP`, `Account`, and `Event`; severities are `High` and `Medium`. Event 4624 can trigger success-after-failures correlation. Events 4740, 1102, 104, and 7045 create review warnings, not assertions of an attack.

## Additional rules

- Success after failures: a queue per computer/account/IP/logon type correlates 4625 with 4624.
  At least Threshold failures and the success must all fit within WindowSeconds. Each success
  clears its queue, including a success below threshold. Both IPs may be missing; a known IP
  is never matched to a missing or different IP. Equal timestamps use record ID ordering.
- Possible password spraying: each computer/IP has a sliding queue and a case-insensitive
  account counter. The default is 10 distinct accounts in WindowSeconds; repeats for the
  same account do not increase this count. Missing IPs or accounts do not qualify. One alert
  covers sustained activity. Count is the number of failed events, not the distinct-account count.
- Local administrator addition: 4732 must identify target group SID S-1-5-32-544, independent
  of the Windows display language. MemberName falls back to MemberSid; the actor is reported
  separately. This requires successful Security Group Management auditing on Windows.

Rules are enabled by default and configurable under Rules; old local configurations receive
defaults in memory. Existing rule IDs are preserved. New rules use separate hash prefixes,
success alerts identify the successful event, and late spray evidence uses the existing overlap
deduplication within the same rule. Saved history is replayed when new rules become available.
The separate Demo-ExtraRules tool uses synthetic data and only local TEST notifications.

References: [4732 XML fields](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732),
[well-known group SIDs](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers).

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
6. Main cycle, DEMO, integration, continuous loop, and scheduling.

See [RESULTS.md](RESULTS.md) for actual verification and outstanding real-world checks.
