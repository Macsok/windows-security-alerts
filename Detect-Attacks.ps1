<#
.SYNOPSIS
Loads sliding-window detection and persistent deduplication functions.
.DESCRIPTION
Loads sliding-window detection and persistent deduplication functions.
.EXAMPLE
. .\Detect-Attacks.ps1; Find-SuspiciousActivity -Events $events
#>
. "$PSScriptRoot/Common.ps1"

function Find-SuspiciousActivity {
    <#
    .SYNOPSIS
    Detects failed-logon episodes by IP or account in sliding windows.
    .DESCRIPTION
    Detects failed-logon episodes by IP or account in sliding windows.
    .PARAMETER Events
    Normalized Windows events, including synthetic events in DEMO.
    .PARAMETER Threshold
    Minimum failed-logon count per IP or account required for an alert.
    .PARAMETER WindowSeconds
    Length of the inclusive sliding detection window, in seconds.
    .EXAMPLE
    Find-SuspiciousActivity -Events (Get-DemoEvents) -Threshold 5 -WindowSeconds 120
    #>

    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Events = @(), [ValidateRange(2,100000)][int]$Threshold = 5,
        [ValidateRange(1,86400)][int]$WindowSeconds = 120)
    $unique = @{}; foreach ($event in $Events) { $unique[$event.EventKey] = $event }
    $ordered = @($unique.Values | Sort-Object @{Expression={ ConvertTo-UtcDate $_.TimeCreated }}, EventKey)
    $groups = @{}
    foreach ($event in $ordered) {
        $time = ConvertTo-UtcDate $event.TimeCreated
        if ([int]$event.EventId -eq 4625) {
            $dimensions = @()
            if ($event.IpAddress) { $dimensions += @{ Type='IP'; Value=[string]$event.IpAddress } }
            if ($event.Account) { $dimensions += @{ Type='Account'; Value=([string]$event.Account).ToLowerInvariant() } }
            foreach ($dimension in $dimensions) {
                $groupKey = "$($dimension.Type)|$($dimension.Value)"
                # Preserve the original hash seed so English labels do not resend saved alerts.
                $identityDimension = if ($dimension.Type -eq 'Account') { 'Konto' } else { $dimension.Type }
                $identityKey = "$identityDimension|$($dimension.Value)"
                if (!$groups.ContainsKey($groupKey)) { $groups[$groupKey] = @{ Queue=(New-Object 'Collections.Generic.Queue[object]'); Active=$false } }
                $group = $groups[$groupKey]; $queue = $group.Queue
                # Inclusive boundary: a difference of exactly 120 seconds is still within the window.
                while ($queue.Count -gt 0 -and ($time - (ConvertTo-UtcDate $queue.Peek().TimeCreated)).TotalSeconds -gt $WindowSeconds) { [void]$queue.Dequeue() }
                if ($queue.Count -lt ($Threshold - 1)) { $group.Active = $false }
                $queue.Enqueue($event)
                if ($queue.Count -ge $Threshold -and !$group.Active) {
                    $first = $queue.Peek()
                    [pscustomobject]@{
                        AlertId=(Get-TextHash "4625|$Threshold|$WindowSeconds|$identityKey|$($event.EventKey)")
                        TimeCreated=$event.TimeCreated; Type="Excessive failed logons: $($dimension.Type)"
                        Dimension=$dimension.Type; Entity=$dimension.Value; EventId=4625
                        IpAddress=$(if ($dimension.Type -eq 'IP') { $dimension.Value } else { $null })
                        Account=$(if ($dimension.Type -eq 'Account') { $dimension.Value } else { $null })
                        Count=$queue.Count; WindowStart=$first.TimeCreated; WindowEnd=$event.TimeCreated
                        Severity='High'; Reason="At least $Threshold failed logons within $WindowSeconds seconds."
                    }
                    $group.Active = $true
                }
            }
        } elseif ([int]$event.EventId -in @(4740,1102,104,7045)) {
            $names = @{4740='Account lockout';1102='Security log cleared';104='Event log cleared';7045='Service installed'}
            [pscustomobject]@{
                AlertId=(Get-TextHash "event|$($event.EventKey)"); TimeCreated=$event.TimeCreated
                Type=$names[[int]$event.EventId]; Dimension='Event'; Entity=$event.Account
                EventId=[int]$event.EventId; IpAddress=$event.IpAddress; Account=$event.Account; Count=1
                WindowStart=$event.TimeCreated; WindowEnd=$event.TimeCreated
                Severity=$(if ([int]$event.EventId -in @(1102,104)) {'High'} else {'Medium'})
                Reason='This event requires administrator review; it does not prove an attack.'
            }
        }
    }
}

function Update-MonitorDetection {
    <#
    .SYNOPSIS
    Merges events and persists new incidents without duplicating saved alerts.
    .DESCRIPTION
    Merges events and persists new incidents without duplicating saved alerts.
    .PARAMETER State
    Monitoring state containing saved events, alerts and delivery receipts.
    .PARAMETER Events
    Normalized Windows events, including synthetic events in DEMO.
    .PARAMETER Threshold
    Minimum failed-logon count per IP or account required for an alert.
    .PARAMETER WindowSeconds
    Length of the inclusive sliding detection window, in seconds.
    .EXAMPLE
    Update-MonitorDetection -State $state -Events (Get-DemoEvents)
    #>

    param($State, [AllowEmptyCollection()][object[]]$Events = @(), [int]$Threshold = 5, [int]$WindowSeconds = 120)
    Update-AlertLanguage $State
    $knownEvents = @{}; foreach ($event in @($State.Events) + $Events) { $knownEvents[$event.EventKey] = $event }
    $State.Events = @($knownEvents.Values | Sort-Object TimeCreated,EventKey)
    $knownAlerts = @{}; foreach ($alert in $State.Alerts) { $knownAlerts[$alert.AlertId] = $true }
    $new = @(Find-SuspiciousActivity -Events $State.Events -Threshold $Threshold -WindowSeconds $WindowSeconds | Where-Object {
        $candidate = $_
        if ($knownAlerts.ContainsKey($candidate.AlertId)) { return $false }
        # A late event can move the threshold crossing time.
        # Overlapping evidence for the same rule remains a single incident.
        $overlap = @($State.Alerts | Where-Object {
            $_.EventId -eq 4625 -and $candidate.EventId -eq 4625 -and
            $_.Dimension -eq $candidate.Dimension -and $_.Entity -eq $candidate.Entity -and $_.Reason -eq $candidate.Reason -and
            (ConvertTo-UtcDate $_.WindowStart) -le (ConvertTo-UtcDate $candidate.WindowEnd) -and
            (ConvertTo-UtcDate $_.WindowEnd) -ge (ConvertTo-UtcDate $candidate.WindowStart)
        })
        return $overlap.Count -eq 0
    })
    $State.Alerts = @($State.Alerts) + $new
    return $new
}
