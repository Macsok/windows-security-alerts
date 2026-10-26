# Sharing through Git or a source archive

The source package contains English scripts, documentation, a blank SMTP configuration template, the dependency lock file, and synthetic examples. It excludes runtime state, real logs, local SMTP settings, credentials, build output, downloaded libraries, and test artifacts.

## Build a clean package

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Test-ShareReadiness.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Export-SharePackage.ps1
```

Share `dist/OSO-English.zip`. Extract it to obtain a clean project ready for Git. The export uses the explicit allowlist in Get-ShareFiles.ps1. It refuses to overwrite an existing archive; pass another `-OutputPath` to make a new version. Do not ZIP the whole working folder: Git ignore rules do not filter ordinary archives.

The check validates a blank SMTP template, synthetic example events, and common private-key, token, credential-XML, personal-email, and local-profile patterns. It reports filenames rather than matched values. It is a heuristic check, not a guarantee that every possible secret format can be recognized. Review files before publishing.

## Initialize and review Git

The project repository is [Macsok/windows-security-alerts](https://github.com/Macsok/windows-security-alerts). For an existing repository, clone it to retain its history:

```powershell
git clone https://github.com/Macsok/windows-security-alerts.git
cd windows-security-alerts
```

When starting a separate repository from an extracted package, initialize it once. Skip `git init` if the folder already contains a repository:

```powershell
git init -b main
git status --short --untracked-files=all
git add --dry-run .
```

Only source, docs, synthetic examples, and project metadata should appear. When reviewing the existing working folder, verify private and generated paths are ignored:

```powershell
git check-ignore config.local.json config.test.local.json config.test.local.jso runtime/live/state.json vendor/mailkit/MailKit.dll
```

The root rule `/config.*` excludes local configurations even with a mistyped extension; only `/config.example.json` is included. Ignore rules also cover runtime, test-results, vendor, dist, credentials, keys, backups, and editor/agent settings. Ignore rules do not remove a file already tracked in a pre-existing repository; inspect the index if importing into one.

After reviewing the intended files:

```powershell
git add .
git diff --cached --stat
git diff --cached --check
git status --short
git commit -m "Add English Windows security monitoring project"
```

Configure your own Git author identity if requested. Create an empty remote repository, then deliberately publish to its actual URL:

```powershell
git remote add origin https://github.com/YOUR-ACCOUNT/YOUR-REPOSITORY.git
git push -u origin main
```

Authenticate through your Git credential manager. Never embed an access token in the URL, scripts, or repository files. Do not force-add private files. A previously published secret must be revoked; adding an ignore rule does not erase history.

## What recipients do

1. Extract or clone the project and read README.md.
2. Run DEMO using config.example.json.
3. Copy the template to config.local.json for their own deployment.
4. Install MailKit and configure their own SMTP credentials only if sending is needed.
5. Verify Security permissions, auditing, and the scheduled task on their machine.
