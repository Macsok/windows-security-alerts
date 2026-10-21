# Discord integration

The original Discord commits on main are ancestors of simplify-project. No commits were removed or rewritten.

| Contribution | Current version |
|---|---|
| Monitor.ps1 Discord delivery and receipts | Kept; module loads only when used, DEMO stays offline |
| Send-Discord.ps1 embeds, fields, thumbnail, severity colors and batching | Kept; missing PSDsHook no longer blocks unrelated monitoring |
| tools/Test-Discord.ps1 | Kept; sends one real test message only when explicitly run |
| Start-Live.ps1 -SetupDiscord | Restored, including forwarding through administrator elevation |
| Discord template and thumbnail | Kept; empty webhook and disabled default for new installations |
| README setup, test and LIVE commands | Kept in shorter instructions; setup now actually exists |

Added tools/Configure-Discord.ps1: prompts locally, installs missing PSDsHook, preserves SMTP settings,
and saves the webhook in ignored config.local.json. Setup does not send a test message.

The available local configuration files and main's current template contained no saved webhook.
Use a new webhook; the URL previously pasted into the conversation must be revoked.
Local secrets do not belong to a branch and are not copied into Git.

Differences retained for correctness: default polling remains 5 seconds, dashboard refresh remains
1 second, IntervalSeconds is forwarded correctly, reports work without PSDsHook, and DEMO never posts to Discord.
