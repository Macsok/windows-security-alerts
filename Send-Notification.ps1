<#
.SYNOPSIS
Loads MailKit SMTP and local email preview functions.
.DESCRIPTION
Loads MailKit SMTP and local email preview functions.
.EXAMPLE
. .\Send-Notification.ps1; Get-SmtpReadiness -Smtp $config.Smtp
#>
. "$PSScriptRoot/Common.ps1"

function Import-MailKit {
    <#
    .SYNOPSIS
    Loads locally built MimeKit and MailKit libraries.
    .DESCRIPTION
    Loads locally built MimeKit and MailKit libraries.
    .PARAMETER LibraryDirectory
    Folder containing the built MailKit and MimeKit DLLs.
    .EXAMPLE
    Import-MailKit -LibraryDirectory .\vendor\mailkit
    #>

    param([string]$LibraryDirectory = "$PSScriptRoot/vendor/mailkit")
    foreach ($name in @('MimeKit.dll','MailKit.dll')) {
        $path = Join-Path $LibraryDirectory $name
        if (!(Test-Path -LiteralPath $path)) { throw 'MailKit is missing. Run tools/Install-MailKit.ps1 as described in README.' }
        [void][Reflection.Assembly]::LoadFrom([IO.Path]::GetFullPath($path))
    }
}

function Get-SmtpCredential {
    <#
    .SYNOPSIS
    Reads SMTP credentials from local DPAPI storage or process variables.
    .DESCRIPTION
    Reads SMTP credentials from local DPAPI storage or process variables.
    .PARAMETER Smtp
    SMTP settings from the local configuration; never contains a hardcoded password.
    .EXAMPLE
    Get-SmtpCredential -Smtp $config.Smtp
    #>

    param($Smtp)
    if ($Smtp.CredentialPath) {
        $credential = Import-Clixml -LiteralPath $Smtp.CredentialPath
        if ($credential -isnot [Management.Automation.PSCredential]) { throw 'The file does not contain a PSCredential.' }
        return $credential
    }
    if ($env:OSO_SMTP_USER -and $env:OSO_SMTP_PASSWORD) {
        return New-Object Management.Automation.PSCredential($env:OSO_SMTP_USER, (ConvertTo-SecureString $env:OSO_SMTP_PASSWORD -AsPlainText -Force))
    }
    throw 'SMTP credentials are missing. Set CredentialPath or the process environment variables.'
}

function Connect-MonitorSmtp {
    <#
    .SYNOPSIS
    Connects to SMTP with required TLS and optional authentication.
    .DESCRIPTION
    Connects to SMTP with required TLS and optional authentication.
    .PARAMETER Smtp
    SMTP settings from the local configuration; never contains a hardcoded password.
    .PARAMETER SkipAuthentication
    Connects with TLS without authenticating.
    .EXAMPLE
    $client = Connect-MonitorSmtp -Smtp $config.Smtp; $client.Dispose()
    #>

    param($Smtp, [switch]$SkipAuthentication)
    if (!$Smtp.Host -or $Smtp.Port -lt 1 -or $Smtp.Port -gt 65535) { throw 'Set a valid SMTP host and port.' }
    if ($Smtp.Security -notin @('StartTls','SslOnConnect')) { throw 'TLS is required: use StartTls or SslOnConnect.' }
    Import-MailKit $Smtp.LibraryDirectory
    $client = New-Object MailKit.Net.Smtp.SmtpClient
    try {
        $client.Timeout = 15000
        $client.Connect([string]$Smtp.Host, [int]$Smtp.Port, [MailKit.Security.SecureSocketOptions]::$($Smtp.Security))
        if (!$SkipAuthentication) {
            $credential = Get-SmtpCredential $Smtp
            $client.Authenticate($credential.UserName, $credential.GetNetworkCredential().Password)
        }
        return $client
    } catch { $client.Dispose(); throw }
}

function Get-SmtpFailureDescription {
    <#
    .SYNOPSIS
    Classifies SMTP failures without exposing credentials or server responses.
    .DESCRIPTION
    Classifies SMTP failures without exposing credentials or server responses.
    .PARAMETER Exception
    SMTP exception to classify without exposing its raw message.
    .EXAMPLE
    Get-SmtpFailureDescription -Exception ([Exception]::new('Connection failed'))
    #>

    param([Parameter(Mandatory)][System.Exception]$Exception)
    # Inspect the exception chain without logging server responses that may contain account data.
    $authenticationFailure = $false
    $cause = $Exception
    while ($null -ne $cause) {
        if ($cause.Message -match '\b5\.7\.(8|80)\b|Username and Password not accepted' -or
            $cause.GetType().FullName -eq 'MailKit.Security.AuthenticationException') {
            $authenticationFailure = $true
        }
        $leaf = $cause
        $cause = $cause.InnerException
    }
    if ($authenticationFailure) {
        return 'SMTP_AUTH_REJECTED: the server rejected the credentials. For Gmail, use the full sender address and a Google app password; run tools/Configure-Gmail.ps1 with the correct -ConfigPath. The alert is queued for retry.'
    }
    if ($leaf -is [Net.Sockets.SocketException]) {
        return 'SMTP_NETWORK_FAILED: check DNS, network access, and the SMTP host and port. The alert is queued for retry.'
    }
    return 'SMTP_SEND_FAILED: check configuration, libraries, TLS, and credential permissions. The alert is queued for retry.'
}

function Get-SmtpReadiness {
    <#
    .SYNOPSIS
    Checks local SMTP configuration without sending a message.
    .DESCRIPTION
    Checks local SMTP configuration without sending a message.
    .PARAMETER Smtp
    SMTP settings from the local configuration; never contains a hardcoded password.
    .EXAMPLE
    Get-SmtpReadiness -Smtp $config.Smtp
    #>

    param($Smtp)
    try {
        if (!$Smtp.Host -or !$Smtp.From -or @($Smtp.To).Count -eq 0) { throw 'CONFIG' }
        if ($Smtp.Security -notin @('StartTls','SslOnConnect') -or $Smtp.Port -lt 1 -or $Smtp.Port -gt 65535) { throw 'CONFIG' }
        Import-MailKit $Smtp.LibraryDirectory
        [void][MimeKit.MailboxAddress]::Parse([string]$Smtp.From)
        foreach ($recipient in $Smtp.To) { [void][MimeKit.MailboxAddress]::Parse([string]$recipient) }
        $credential=Get-SmtpCredential $Smtp
        if (!$credential.UserName -or $credential.Password.Length -eq 0) { throw 'CREDENTIAL' }
        return [pscustomobject]@{Ready=$true;Message='Configuration is ready. The connection will be checked when sending.'}
    } catch {
        return [pscustomobject]@{Ready=$false;Message='SMTP is not ready: run tools/Configure-Gmail.ps1 as the monitoring account; check MailKit and the credential file.'}
    }
}

function Test-SmtpConnection {
    <#
    .SYNOPSIS
    Tests SMTP TLS and authentication without sending mail.
    .DESCRIPTION
    Tests SMTP TLS and authentication without sending mail.
    .PARAMETER Smtp
    SMTP settings from the local configuration; never contains a hardcoded password.
    .PARAMETER TransportOnly
    Tests TLS connectivity without SMTP authentication.
    .EXAMPLE
    Test-SmtpConnection -Smtp $config.Smtp
    #>

    [CmdletBinding()]
    param([Parameter(Mandatory)]$Smtp, [switch]$TransportOnly)
    # Explicit connection test: TLS and authentication only; sends no messages.
    $client = Connect-MonitorSmtp -Smtp $Smtp -SkipAuthentication:$TransportOnly
    try { [pscustomobject]@{Connected=$client.IsConnected;Secure=$client.IsSecure;Authenticated=$client.IsAuthenticated} }
    finally { $client.Disconnect($true); $client.Dispose() }
}

function Get-AlertMailBody {
    <#
    .SYNOPSIS
    Formats one security incident as a plain-text email body.
    .DESCRIPTION
    Formats one security incident as a plain-text email body.
    .PARAMETER Alert
    One structured detected incident.
    .EXAMPLE
    Get-AlertMailBody -Alert $state.Alerts[0]
    #>

    param($Alert)
    @"
SECURITY ALERT - Suspicious Windows activity
Date UTC: $($Alert.TimeCreated)
Type: $($Alert.Type)
Account: $($Alert.Account)
IP address: $($Alert.IpAddress)
Failed logons / events: $($Alert.Count)
Window: $($Alert.WindowStart) - $($Alert.WindowEnd)
Severity: $($Alert.Severity)
Description: $($Alert.Reason)
Identifier: $($Alert.AlertId)
"@
}

function Send-AlertNotification {
    <#
    .SYNOPSIS
    Writes an email preview or sends one incident through MailKit.
    .DESCRIPTION
    Writes an email preview or sends one incident through MailKit.
    .PARAMETER Alert
    One structured detected incident.
    .PARAMETER Smtp
    SMTP settings from the local configuration; never contains a hardcoded password.
    .PARAMETER Root
    Output folder for the selected mode, or source folder for sharing tools.
    .PARAMETER Mode
    Selects DEMO or LIVE, or Test previews versus Send delivery for email functions.
    .EXAMPLE
    Send-AlertNotification -Alert $state.Alerts[0] -Root .\runtime\demo -Mode Test
    #>

    [CmdletBinding()]
    param($Alert, $Smtp, [Parameter(Mandatory)][string]$Root, [ValidateSet('Test','Send')][string]$Mode='Test')
    $subject = 'SECURITY ALERT - Suspicious Windows activity'
    $body = Get-AlertMailBody $Alert
    if ($Mode -eq 'Test') {
        # RFC 5322/MIME: UTF-8 body and subject, without network connections.
        $encodedSubject = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($subject))
        $encodedBody = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($body), [Base64FormattingOptions]::InsertLineBreaks)
        $mail = @("From: monitor@example.invalid", "To: administrator@example.invalid", "Subject: =?utf-8?B?$encodedSubject`?=", "Date: $([DateTime]::UtcNow.ToString('r', [Globalization.CultureInfo]::InvariantCulture))", "Message-ID: <$($Alert.AlertId)@oso.invalid>", 'MIME-Version: 1.0', 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: base64', '', $encodedBody) -join "`r`n"
        Write-Utf8File (Join-Path $Root "mail-test/$($Alert.AlertId).eml") ($mail + "`r`n") -NoBom
        return $true
    }
    $client = $null
    try {
        if (!$Smtp.From -or @($Smtp.To).Count -eq 0) { throw 'Sender or recipient is missing.' }
        $client = Connect-MonitorSmtp $Smtp
        $message = New-Object MimeKit.MimeMessage
        $message.From.Add([MimeKit.MailboxAddress]::Parse([string]$Smtp.From))
        foreach ($recipient in $Smtp.To) { $message.To.Add([MimeKit.MailboxAddress]::Parse([string]$recipient)) }
        $message.Subject = $subject; $message.MessageId = "$($Alert.AlertId)@oso.invalid"
        $part = New-Object MimeKit.TextPart('plain'); $part.Text = $body; $message.Body = $part
        [void]$client.Send($message)
        return $true
    } catch {
        Write-Diagnostic $Root (Get-SmtpFailureDescription -Exception $_.Exception)
        return $false
    } finally { if ($null -ne $client) { $client.Dispose() } }
}

function Invoke-PendingNotifications {
    <#
    .SYNOPSIS
    Retries pending email alerts and saves successful delivery receipts.
    .DESCRIPTION
    Retries pending email alerts and saves successful delivery receipts.
    .PARAMETER State
    Monitoring state containing saved events, alerts and delivery receipts.
    .PARAMETER Smtp
    SMTP settings from the local configuration; never contains a hardcoded password.
    .PARAMETER Root
    Output folder for the selected mode, or source folder for sharing tools.
    .PARAMETER StatePath
    Persistent JSON state file used to save delivery receipts.
    .PARAMETER Mode
    Selects DEMO or LIVE, or Test previews versus Send delivery for email functions.
    .EXAMPLE
    Invoke-PendingNotifications -State $state -Smtp $config.Smtp -Root .\runtime\demo -StatePath .\runtime\demo\state.json -Mode Test
    #>

    param($State, $Smtp, [string]$Root, [string]$StatePath, [ValidateSet('Test','Send')][string]$Mode='Test')
    $completed = @{}; foreach ($delivery in $State.Deliveries) { $completed["$($delivery.Mode)|$($delivery.AlertId)"]=$true }
    foreach ($alert in $State.Alerts) {
        $key = "$Mode|$($alert.AlertId)"
        if ($completed.ContainsKey($key)) { continue }
        if (Send-AlertNotification -Alert $alert -Smtp $Smtp -Root $Root -Mode $Mode) {
            $State.Deliveries = @($State.Deliveries) + [pscustomobject]@{AlertId=$alert.AlertId;Mode=$Mode;TimeUtc=[DateTime]::UtcNow.ToString('o')}
            Save-JsonAtomic $StatePath $State
            $completed[$key]=$true
        }
    }
}
