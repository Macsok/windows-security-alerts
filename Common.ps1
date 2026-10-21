Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Utf8File {
    param([string]$Path, [AllowEmptyString()][string]$Text, [switch]$NoBom)
    $parent = Split-Path -Parent $Path
    if ($parent) { [void][IO.Directory]::CreateDirectory($parent) }
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding(!$NoBom)))
}

function Save-JsonAtomic {
    param([string]$Path, $Value)
    $temp = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        Write-Utf8File $temp ($Value | ConvertTo-Json -Depth 30)
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temp, $Path, "$Path.bak") }
        else { [IO.File]::Move($temp, $Path) }
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp } }
}

function Write-TextAtomic {
    param([string]$Path, [AllowEmptyString()][string]$Text)
    $temporary="$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        Write-Utf8File $temporary $Text
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary,$Path,[NullString]::Value) }
        else { [IO.File]::Move($temporary,$Path) }
    } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary } }
}

function Read-MonitorConfig {
    param([string]$Path)
    $full=(Resolve-Path -LiteralPath $Path).Path
    $config=Get-Content -LiteralPath $full -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($config.Threshold -lt 2 -or $config.Threshold -gt 100000 -or $config.Threshold -ne [int]$config.Threshold -or $config.WindowSeconds -lt 1 -or $config.WindowSeconds -gt 86400 -or $config.WindowSeconds -ne [int]$config.WindowSeconds) { throw 'Invalid threshold or time window.' }
    if ($config.OverlapSeconds -lt $config.WindowSeconds -or $config.InitialLookbackMinutes*60 -lt $config.WindowSeconds) { throw 'The initial lookback and overlap must each cover at least one detection window.' }
    if (!$config.OutputRoot) { throw 'OutputRoot is missing from the configuration.' }
    foreach ($setting in @('PollIntervalSeconds','DashboardRefreshSeconds')) {
        $default=if ($setting -eq 'PollIntervalSeconds') {5} else {1}
        $maximum=if ($setting -eq 'PollIntervalSeconds') {86400} else {60}
        if (!$config.PSObject.Properties[$setting]) { $config | Add-Member -NotePropertyName $setting -NotePropertyValue $default }
        if ($config.$setting -lt 1 -or $config.$setting -gt $maximum -or $config.$setting -ne [int]$config.$setting) { throw "Invalid $setting." }
    }
    $base=Split-Path $full
    if (![IO.Path]::IsPathRooted($config.OutputRoot)) { $config.OutputRoot=Join-Path $base $config.OutputRoot }
    foreach ($setting in @('LibraryDirectory','CredentialPath')) {
        if ($config.Smtp.$setting -and ![IO.Path]::IsPathRooted($config.Smtp.$setting)) { $config.Smtp.$setting=Join-Path $base $config.Smtp.$setting }
    }
    return $config
}

function Get-TextHash {
    param([string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function ConvertTo-UtcDate {
    param($Value)
    [DateTimeOffset]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime
}

function New-MonitorState {
    [pscustomobject]@{ Version = 1; LastScanUtc = $null; Events = @(); Alerts = @(); Deliveries = @() }
}

function Update-AlertLanguage {
    param($State)
    # Legacy values are retained only as migration inputs, never as new UI labels.
    # Keep identifiers, event data, delivery receipts, and timestamps unchanged.
    $types = @{
        'Nadmierne nieudane logowania: IP' = 'Excessive failed logons: IP'
        'Nadmierne nieudane logowania: Konto' = 'Excessive failed logons: Account'
        'Blokada konta' = 'Account lockout'
        'Wyczyszczenie Security' = 'Security log cleared'
        'Wyczyszczenie dziennika' = 'Event log cleared'
        'Instalacja usługi' = 'Service installed'
    }
    foreach ($alert in $State.Alerts) {
        if ($alert.Dimension -eq 'Konto') { $alert.Dimension = 'Account' }
        elseif ($alert.Dimension -eq 'Zdarzenie') { $alert.Dimension = 'Event' }
        if ($alert.Severity -eq 'Wysoki') { $alert.Severity = 'High' }
        elseif ($alert.Severity -eq 'Średni') { $alert.Severity = 'Medium' }
        if ($types.ContainsKey([string]$alert.Type)) { $alert.Type = $types[[string]$alert.Type] }
        if ($alert.Reason -match '^Co najmniej (\d+) nieudanych logowań w oknie (\d+) s\.$') {
            $alert.Reason = "At least $($Matches[1]) failed logons within $($Matches[2]) seconds."
        } elseif ($alert.Reason -eq 'Zdarzenie wymagające weryfikacji administratora; samo nie dowodzi ataku.') {
            $alert.Reason = 'This event requires administrator review; it does not prove an attack.'
        }
    }
}

function Update-StatusLanguage {
    param($Status)
    $messages = @{
        'Oczekiwanie na wysyłkę' = 'Waiting to send notifications'
        'TEST: zapisywane są pliki .eml; rzeczywista wysyłka wyłączona.' = 'TEST: saving .eml files; email delivery is disabled.'
        'Błąd SMTP. Wiadomości czekają na ponowienie; szczegóły w diagnostic.log.' = 'SMTP error. Notifications are queued for retry; see diagnostic.log.'
        'SMTP: wszystkie zapisane alerty mają potwierdzenie wysyłki. Sprawdź skrzynkę odbiorcy.' = 'SMTP has accepted all saved alerts. Check the recipient inbox.'
        'Konfiguracja gotowa. Połączenie zostanie sprawdzone przy wysyłce.' = 'Configuration is ready. The connection will be checked when sending.'
        'SMTP niegotowe: uruchom tools/Configure-Gmail.ps1 na koncie monitora; sprawdź MailKit i plik poświadczeń.' = 'SMTP is not ready: run tools/Configure-Gmail.ps1 as the monitoring account; check MailKit and the credential file.'
    }
    if ($messages.ContainsKey([string]$Status.SmtpMessage)) { $Status.SmtpMessage = $messages[[string]$Status.SmtpMessage] }
    foreach ($source in $Status.Sources) {
        if ($source.Error -eq "Brak odczytu $($source.Name). Sprawdź uprawnienia administratora i dostępność dziennika.") {
            $source.Error = "Cannot read $($source.Name). Check administrator permissions and event log availability."
        }
    }
}

function Read-MonitorState {
    param([string]$Path)
    if (!(Test-Path -LiteralPath $Path)) { return New-MonitorState }
    # Corrupt state requires explicit recovery; never reset deduplication automatically.
    $state = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($state.Version -ne 1) { throw 'Unsupported state version.' }
    foreach ($name in @('Events','Alerts','Deliveries','LastScanUtc')) {
        if (!$state.PSObject.Properties[$name]) { throw "Missing state field: $name" }
    }
    Update-AlertLanguage $state
    return $state
}

function Write-Diagnostic {
    param([string]$Root, [string]$Code)
    $path = Join-Path $Root 'logs/diagnostic.log'
    [void][IO.Directory]::CreateDirectory((Split-Path $path))
    # Do not log raw SMTP exceptions: they may contain account or configuration data.
    Add-Content -LiteralPath $path -Encoding UTF8 -Value "$([DateTime]::UtcNow.ToString('o')) $Code"
}
