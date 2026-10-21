# Ten-minute presentation

## Preparation

Run the tests beforehand. Keep PowerShell, README, Detect-Attacks.ps1, and the dashboard open. Use a new demonstration configuration with a fresh OutputRoot, for example `runtime/show-1`. Do not delete LIVE history. If real SMTP has not been verified, demonstrate `.eml` files and state that they were not sent.

## 0:00-1:00: problem and requirements

Explain: the system reads Windows logs, detects repeated failed logons, exports CSV/HTML, writes warnings, and prepares or sends email. Five events 4625 from one IP OR targeting one account within 120 seconds meet the rule. A single failed logon is not proof of an attack.

## 1:00-2:00: architecture

Show main.ps1 and the modules: XML -> normalized events -> detector -> persistent JSON -> reports and log -> notifications. State is saved before SMTP. DEMO and LIVE use separate directories. The console loop or Task Scheduler runs cycles every minute.

## 2:00-3:15: event ingestion

Show Get-Logs.ps1, time/event filters, XML named fields, RecordId, and EventKey. Mention 4624, 4740, 1102, 104, and 7045. If authorized, run tools/Test-WindowsLogs.ps1. Otherwise show the documented access error and explain that parser tests use separate synthetic XML. Do not generate attacks or clear logs.

## 3:15-4:45: algorithm

Draw attempts at 0, 20, 40, 60, and 80 seconds: the fifth triggers. Attempts at 0, 150, 300, 450, and 600 seconds do not. Explain the moving window, independent IP/account queues, different IPs targeting one account, and why missing IPs never form an unknown group. Four failures are insufficient; exactly 120 seconds is included.

## 4:45-6:15: end-to-end DEMO

Run with the fresh configuration prepared for the presentation:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\main.ps1 -Mode DEMO -ConfigPath .\config.show.local.json
```

Show 17 events, 15 failures, 2 alerts, and IP/account statistics. Explain Count=5 at the crossing even though the IP episode contains seven attempts. The three earlier failures do not trigger. The dataset includes normal successful logons as context.

## 6:15-7:15: reports, warning log, and email

Open incidents.csv, events.csv, and alerts.log. Show UTC time, account/IP, severity, count, and reason. Open a local `.eml` preview and explicitly call it TEST output. Show a received message only if an authorized real delivery was previously verified; hide private addresses and settings.

## 7:15-8:00: persistence and failures

Repeat the same DEMO: NewAlerts=0. Explain state and receipts, SMTP retries, and independent log-channel recovery. Mention the possible duplicate if a crash occurs after SMTP acceptance but before the local receipt is saved.

## 8:00-9:00: testing and scheduling

Show the actual latest test summary, including boundaries, missing IPs, restart, late events, HTML encoding, and English-state migration. Show the scheduler instructions. Do not claim a task is active without verifying it under the configured account.

## 9:00-10:00: acceptance and limitations

Use the results table in RESULTS.md. Separate synthetic tests, real System ingestion, unverified Security access, and SMTP/task limitations. Mention local-only ingestion and unbounded history. Show README so the instructor can reproduce the safe demo.

# Fifteen likely questions

1. **Why 4625?** It records a failed logon. Repetition within a window, rather than one event, triggers the rule.
2. **Why a sliding window?** Fixed clock-minute buckets can split one incident across their boundary. A sliding window follows each event.
3. **What does 120 seconds mean?** The newest and oldest included attempts differ by no more than 120 seconds, including the boundary.
4. **How do you detect distributed attempts against one account?** A separate account queue aggregates different IPs; identity includes the domain and ignores case.
5. **What if the IP is absent?** It stays null and is not grouped by IP. The account rule can still apply.
6. **How are duplicate events identified?** EventKey hashes machine, channel, provider, RecordId, timestamp, and EventId. RecordId alone can be reused after a cleared log.
7. **What happens after restart?** Events, alerts, cursors, and receipts are restored from JSON. Overlapping reads do not increase the attempt count.
8. **Can the same attempts produce two alerts?** Yes, when both the IP and account rules independently qualify.
9. **Why XML instead of Message?** XML supplies named fields independently of the Windows display language and formatted message text.
10. **Do 7045 or 1102 prove an attack?** No. Service installation and log clearing can be legitimate, but need review.
11. **How are passwords protected?** The project uses an external DPAPI credential or process environment variables, required TLS, and standard certificate validation.
12. **What happens when SMTP fails?** Alerts and logs remain saved. No success receipt is written, and a subsequent Send run retries.
13. **Is email exactly once?** Normal runs deduplicate. A crash between SMTP acceptance and a receipt can cause a duplicate; SMTP cannot guarantee an atomic local confirmation.
14. **What are the performance limits?** The detector sorts history in O(n log n) with O(n) memory. Correlation scans old alerts too. Long-term use needs retention/archiving.
15. **What was actually tested?** Refer to RESULTS.md. Synthetic test success, real System reading, Gmail TLS/authentication results, and unverified Security/task operation are separate claims.

# Submission checklist

- [ ] All automated suites pass on the target machine.
- [ ] Fresh DEMO creates two incidents, CSV, HTML, warnings, and two email previews.
- [ ] Repeating DEMO creates no duplicate incidents or notifications.
- [ ] Security and System are readable by the monitoring/task account.
- [ ] Audit policy records failed logons; existing real 4625 records can be read.
- [ ] Real SMTP authentication and inbox receipt are verified with authorization.
- [ ] The scheduled task updates outputs every minute and after logout.
- [ ] English reports have correct counts and safely encode arbitrary Unicode names.
- [ ] English upgrades preserve identifiers, history, and delivery receipts.
- [ ] Share checks pass; credentials, local configurations, and real logs are excluded.
- [ ] If any credential or webhook was previously exposed, its owner has revoked it.
- [ ] Documentation and test claims match the checks actually completed.
