[CmdletBinding()]
param([string]$Root='')
$ErrorActionPreference='Stop'
if (!$Root) { $Root=Split-Path $PSScriptRoot }
. "$PSScriptRoot/Get-ShareFiles.ps1"
$files=@(Get-ShareFiles -Root $Root)
$config=Get-Content -LiteralPath (Join-Path $Root 'config.example.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($config.Smtp.Host -or $config.Smtp.From -or @($config.Smtp.To).Count -or $config.Smtp.CredentialPath) {
    throw 'The configuration template must not contain SMTP account settings.'
}
$allowedSmtp=@('Host','Port','Security','From','To','CredentialPath','LibraryDirectory')
foreach ($property in $config.Smtp.PSObject.Properties) {
    if ($property.Name -notin $allowedSmtp) { throw 'Unexpected SMTP template field. Review before sharing.' }
}
# Conservative checks, not a guarantee that arbitrary secrets can be identified.
$patterns=@(
    '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    'https://(?:discord(?:app)?\.com)/api/webhooks/\d+/[A-Za-z0-9_-]+',
    '\bgh[pousr]_[A-Za-z0-9]{20,}\b',
    '\bAKIA[A-Z0-9]{16}\b',
    '<SS\b[^>]*>[^<]+</SS>',
    'C:\\Users\\(?!<|PUBLIC\b|Default\b)[^\\\s"''<>]+\\'
)
$problems=New-Object 'Collections.Generic.List[string]'
foreach ($file in $files) {
    $content=[IO.File]::ReadAllText($file.FullName)
    if ($file.Extension -eq '.eml') {
        $body=($content -split '\r?\n\r?\n',2)[1]
        $content += [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($body))
    }
    foreach ($pattern in $patterns) {
        if ($content -match $pattern) { $problems.Add($file.Name); break }
    }
    foreach ($match in [regex]::Matches($content,'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')) {
        if ($match.Value -notmatch '@(?:[a-z0-9.-]+\.)?(?:example\.(?:invalid|com|org|net)|oso\.invalid)$') {
            $problems.Add($file.Name); break
        }
    }
}
$events=Get-Content -LiteralPath (Join-Path $Root 'examples/demo/events.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if (@($events).Count -ne 17 -or @($events | Where-Object MachineName -ne 'DEMO-PC').Count) {
    throw 'Shared event examples must contain only the 17 synthetic DEMO events.'
}
if ($problems.Count) { throw ('Review possible private data in: '+(($problems | Select-Object -Unique) -join ', ')+'. Values are intentionally hidden.') }
[pscustomobject]@{Status='PASS';ReviewedFiles=$files.Count;Scope='Share package allowlist';RealEmailSent=$false}
