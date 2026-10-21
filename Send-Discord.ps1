<#
.SYNOPSIS
Loads optional PSDsHook notification functions adapted from the group code.
.DESCRIPTION
Loads optional PSDsHook notification functions adapted from the group code.
.EXAMPLE
. .\Send-Discord.ps1; New-DiscordAlertEmbed -Alerts $state.Alerts
#>
# Discord embed and batching logic contributed by Mewa-zip; loaded on demand.
function New-DiscordAlertEmbed {
    <#
    .SYNOPSIS
    Builds a Discord embed using the supplied group reporting pattern.
    .DESCRIPTION
    Builds a Discord embed using the supplied group reporting pattern.
    .PARAMETER Alerts
    Structured incidents to send.
    .PARAMETER Mode
    Selects DEMO or LIVE, or Test previews versus Send delivery for email functions.
    .PARAMETER ThumbnailUrl
    Optional public thumbnail URL for Discord embeds.
    .EXAMPLE
    New-DiscordAlertEmbed -Alerts $state.Alerts -Mode LIVE
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Alerts,
        [string]$Mode = 'LIVE',
        [string]$ThumbnailUrl = ''
    )
    # Compile module classes only when Discord is actually used.
    $buildEmbed = [scriptblock]::Create(@'
using module PSDsHook
param($Alerts, $Mode, $ThumbnailUrl)
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
'@)
    & $buildEmbed -Alerts $Alerts -Mode $Mode -ThumbnailUrl $ThumbnailUrl
}

#send webhook
function Send-DiscordAlert {
    <#
    .SYNOPSIS
    Sends alert embeds to the explicitly configured Discord webhook.
    .DESCRIPTION
    Sends alert embeds to the explicitly configured Discord webhook.
    .PARAMETER Alerts
    Structured incidents to send.
    .PARAMETER WebhookUrl
    Secret Discord webhook URL from local configuration; never commit it.
    .PARAMETER Mode
    Selects DEMO or LIVE, or Test previews versus Send delivery for email functions.
    .PARAMETER ThumbnailUrl
    Optional public thumbnail URL for Discord embeds.
    .PARAMETER PerMessage
    Maximum number of incident fields per Discord embed, at most 25.
    .EXAMPLE
    Send-DiscordAlert -Alerts $state.Alerts -WebhookUrl $config.Discord.WebhookUrl
    #>

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
    Import-Module PSDsHook -ErrorAction Stop
    Invoke-PsDsHook -CreateConfig $WebhookUrl -ErrorAction Stop | Out-Null
    for ($i = 0; $i -lt $Alerts.Count; $i += $PerMessage) {
        $last = [Math]::Min($i + $PerMessage, $Alerts.Count) - 1
        $embed = New-DiscordAlertEmbed -Alerts @($Alerts[$i..$last]) -Mode $Mode -ThumbnailUrl $ThumbnailUrl
        Invoke-PSDsHook $embed -ErrorAction Stop | Out-Null
        if ($last -lt ($Alerts.Count - 1)) { Start-Sleep -Seconds 1 }   # stay under Discord rate limits
    }
}
