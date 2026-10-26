<#
.SYNOPSIS
Loads synthetic event generators; creates no real failed logons.
.DESCRIPTION
Loads synthetic event generators; creates no real failed logons.
.EXAMPLE
. .\New-DemoEvents.ps1; Get-DemoEvents
#>
. "$PSScriptRoot/Get-Logs.ps1"

function New-SyntheticEvent {
    <#
    .SYNOPSIS
    Creates one synthetic Windows event without attempting a real logon.
    .DESCRIPTION
    Creates one synthetic Windows event without attempting a real logon.
    .PARAMETER RecordId
    Synthetic event record identifier.
    .PARAMETER Time
    Timestamp assigned to the synthetic event.
    .PARAMETER EventId
    Windows event identifier assigned to the synthetic event.
    .PARAMETER Ip
    Synthetic source IP address, or an empty value.
    .PARAMETER User
    Synthetic target user name.
    .PARAMETER Domain
    Synthetic target account domain.
    .PARAMETER GroupSid
    Target group SID for synthetic event 4732.
    .PARAMETER MemberSid
    SID of the synthetic member added to the group.
    .PARAMETER MemberName
    Optional member name; Windows commonly records a dash instead.
    .PARAMETER ActorUser
    Synthetic account performing the group change.
    .EXAMPLE
    New-SyntheticEvent -RecordId 1 -EventId 4625
    #>

    param([int]$RecordId, [datetime]$Time = ([datetime]'2026-01-15T10:00:00Z'),
        [int]$EventId = 4625, [AllowNull()][string]$Ip = '192.0.2.10',
        [AllowNull()][string]$User = 'student', [string]$Domain = 'LAB',
        [string]$GroupSid='',[string]$MemberSid='',[string]$MemberName='',[string]$ActorUser='')
    $ipXml = [Security.SecurityElement]::Escape($Ip)
    $userXml = [Security.SecurityElement]::Escape($User)
    $domainXml = [Security.SecurityElement]::Escape($Domain)
    $groupSidXml=[Security.SecurityElement]::Escape($GroupSid)
    $memberSidXml=[Security.SecurityElement]::Escape($MemberSid)
    $memberNameXml=[Security.SecurityElement]::Escape($MemberName)
    $actorXml=[Security.SecurityElement]::Escape($ActorUser)
    $xml = @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
 <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>$EventId</EventID>
 <TimeCreated SystemTime="$($Time.ToUniversalTime().ToString('o'))"/><EventRecordID>$RecordId</EventRecordID><Channel>Security</Channel><Computer>DEMO-PC</Computer></System>
 <EventData><Data Name="TargetUserName">$userXml</Data><Data Name="TargetDomainName">$domainXml</Data><Data Name="IpAddress">$ipXml</Data><Data Name="LogonType">3</Data>
 <Data Name="TargetSid">$groupSidXml</Data><Data Name="MemberSid">$memberSidXml</Data><Data Name="MemberName">$memberNameXml</Data><Data Name="SubjectUserName">$actorXml</Data><Data Name="SubjectDomainName">LAB</Data></EventData>
</Event>
"@
    ConvertFrom-WindowsEventXml $xml
}

function Get-DemoEvents {
    <#
    .SYNOPSIS
    Returns the fixed 17-event demonstration dataset.
    .DESCRIPTION
    Returns the fixed 17-event demonstration dataset.
    .EXAMPLE
    Get-DemoEvents
    #>

    $base = [datetime]'2026-01-15T10:00:00Z'
    New-SyntheticEvent -RecordId 1 -Time $base -EventId 4624 -User 'anna'
    1..3 | ForEach-Object { New-SyntheticEvent -RecordId (10+$_) -Time $base.AddSeconds($_*10) -Ip '192.0.2.20' -User 'piotr' }
    1..7 | ForEach-Object { New-SyntheticEvent -RecordId (20+$_) -Time $base.AddSeconds(200+$_*10) -Ip '192.0.2.50' -User "konto$_" }
    1..5 | ForEach-Object { New-SyntheticEvent -RecordId (40+$_) -Time $base.AddSeconds(400+$_*15) -Ip "198.51.100.$_" -User 'administrator' }
    New-SyntheticEvent -RecordId 60 -Time $base.AddSeconds(500) -EventId 4624 -User 'anna'
}

function Get-ExtraRuleDemoEvents {
    <#
    .SYNOPSIS
    Returns synthetic events demonstrating all three additional rules.
    .DESCRIPTION
    Fixed dates and record IDs allow restart deduplication. Creates no real logons
    and makes no changes to Windows accounts or groups.
    .EXAMPLE
    Get-ExtraRuleDemoEvents
    #>
    $base=[datetime]'2026-01-15T12:00:00Z'
    1..5 | ForEach-Object { New-SyntheticEvent -RecordId (7000+$_) -Time $base.AddSeconds($_*10) -User 'demo-login' -Ip '192.0.2.70' }
    New-SyntheticEvent -RecordId 7006 -Time $base.AddSeconds(60) -EventId 4624 -User 'demo-login' -Ip '192.0.2.70'
    1..10 | ForEach-Object { New-SyntheticEvent -RecordId (7100+$_) -Time $base.AddSeconds(200+$_*5) -User "spray-user$_" -Ip '198.51.100.70' }
    New-SyntheticEvent -RecordId 7200 -Time $base.AddSeconds(400) -EventId 4732 -Ip '' -User 'Administrators' -Domain 'BUILTIN' -GroupSid 'S-1-5-32-544' -MemberSid 'S-1-5-21-111-222-333-1001' -MemberName '-' -ActorUser 'demo-operator'
}
