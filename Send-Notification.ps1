. "$PSScriptRoot/Common.ps1"

function Import-MailKit {
    param([string]$LibraryDirectory = "$PSScriptRoot/vendor/mailkit")
    foreach ($name in @('MimeKit.dll','MailKit.dll')) {
        $path = Join-Path $LibraryDirectory $name
        if (!(Test-Path -LiteralPath $path)) { throw 'MailKit is missing. Run tools/Install-MailKit.ps1 as described in README.' }
        [void][Reflection.Assembly]::LoadFrom([IO.Path]::GetFullPath($path))
    }
}

function Get-SmtpCredential {
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
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Smtp, [switch]$TransportOnly)
    # Explicit connection test: TLS and authentication only; sends no messages.
    $client = Connect-MonitorSmtp -Smtp $Smtp -SkipAuthentication:$TransportOnly
    try { [pscustomobject]@{Connected=$client.IsConnected;Secure=$client.IsSecure;Authenticated=$client.IsAuthenticated} }
    finally { $client.Disconnect($true); $client.Dispose() }
}

function Get-AlertMailBody {
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
