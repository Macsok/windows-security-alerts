using module PSDsHook

#create Discord Embed - LIVE
function New-DiscordAlertEmbed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Alerts,
        [string]$Mode = 'LIVE',
        [string]$ThumbnailUrl = ''
    )
    $hasHigh = @($Alerts | Where-Object { $_.Severity -eq 'High' }).Count -gt 0
    $embed = [DiscordEmbed]::New('Security Alert', "Detected **$($Alerts.Count)** new incident(s). Mode: $Mode")
    if ($ThumbnailUrl) { [void]$embed.AddThumbnail([DiscordThumbnail]::New($ThumbnailUrl)) }
    $color = if ($hasHigh) { 'red' } else { 'orange' }
    [void]$embed.WithColor([DiscordColor]::New($color))
    [void]$embed.AddFooter([DiscordFooter]::New("Time of scan: $(Get-Date)"))
    foreach ($alert in $Alerts) {
        $target = if ($alert.Entity) { $alert.Entity } else { 'n/a' }
        $value = "Target: **$target**`nCount: **$($alert.Count)** | Severity: **$($alert.Severity)**"
        [void]$embed.AddField([DiscordField]::New("|-> $($alert.Type) <-|", $value, $false))
    }
    return $embed
}

#send webhook
function Send-DiscordAlert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Alerts,
        [Parameter(Mandatory)][string]$WebhookUrl,
        [string]$Mode = 'LIVE',
        [string]$ThumbnailUrl = '',
        # Discord allows at most 25 fields per embed
        [ValidateRange(1,25)][int]$PerMessage = 10
    )
    if ($WebhookUrl -notmatch '^https://([a-z0-9-]+\.)?discord(app)?\.com/api/webhooks/') {
        throw 'The Discord webhook URL is invalid.'
    }
    Invoke-PsDsHook -CreateConfig $WebhookUrl -ErrorAction SilentlyContinue | Out-Null
    for ($i = 0; $i -lt $Alerts.Count; $i += $PerMessage) {
        $last = [Math]::Min($i + $PerMessage, $Alerts.Count) - 1
        $embed = New-DiscordAlertEmbed -Alerts @($Alerts[$i..$last]) -Mode $Mode -ThumbnailUrl $ThumbnailUrl
        Invoke-PSDsHook $embed -ErrorAction Stop | Out-Null
        if ($last -lt ($Alerts.Count - 1)) { Start-Sleep -Seconds 1 }   # stay under Discord rate limits
    }
}
