. "$PSScriptRoot/Common.ps1"

function ConvertFrom-WindowsEventXml {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Xml)
    [xml]$doc = $Xml
    $system = $doc.Event.System
    $fields = @{}
    foreach ($node in $doc.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")) {
        $fields[$node.GetAttribute('Name')] = $node.InnerText
    }
    # Events 1102/104 may use UserData with a custom namespace.
    foreach ($node in $doc.SelectNodes("//*[local-name()='UserData']//*[not(*)]")) {
        $fields[$node.LocalName] = $node.InnerText
    }
    $id = [int]$system.SelectSingleNode("*[local-name()='EventID']").InnerText
    $user = $fields['TargetUserName']; $domain = $fields['TargetDomainName']
    if ((!$user -or $user -eq '-') -and $id -notin @(4624,4625,4740)) { $user = $fields['SubjectUserName']; $domain = $fields['SubjectDomainName'] }
    if (!$user -or $user -eq '-') { $user = $null }
    $account = $null
    if ($user) {
        if ($domain -and $domain -ne '-') { $account = "$domain\$user" } else { $account = $user }
    }
    $ip = $null; $parsed = $null
    if ([Net.IPAddress]::TryParse([string]$fields['IpAddress'], [ref]$parsed)) {
        if ($parsed.IsIPv4MappedToIPv6) { $parsed = $parsed.MapToIPv4() }
        if (!$parsed.Equals([Net.IPAddress]::Any) -and !$parsed.Equals([Net.IPAddress]::IPv6Any)) { $ip = $parsed.ToString() }
    }
    $time = ConvertTo-UtcDate $system.TimeCreated.GetAttribute('SystemTime')
    $channel = [string]$system.Channel; $machine = [string]$system.Computer
    $provider = $system.Provider.GetAttribute('Name'); $record = [long]$system.EventRecordID
    $key = Get-TextHash "$machine|$channel|$provider|$record|$($time.ToString('o'))|$id"
    [pscustomobject]@{
        EventKey = $key; TimeCreated = $time.ToString('o'); EventId = $id
        RecordId = $record; LogName = $channel; MachineName = $machine; ProviderName = $provider
        UserName = $user; Account = $account; IpAddress = $ip; LogonType = $fields['LogonType']
    }
}

function Get-WindowsLogs {
    [CmdletBinding()]
    param([datetime]$StartTime = (Get-Date).AddMinutes(-10), [datetime]$EndTime = (Get-Date),
        [ValidateSet('Security','System')][string[]]$LogName = @('Security','System'))
    if ($StartTime -gt $EndTime) { throw 'The start time is later than the end time.' }
    # FilterHashtable alone may return NoMatchingEventsFound even when access is denied.
    # Check access to each required event log before querying it.
    foreach ($name in $LogName) {
        try {
            $info = Get-WinEvent -ListLog $name -ErrorAction Stop
            if (!$info.IsEnabled) { throw 'The event log is disabled.' }
        } catch {
            throw "Cannot read event log $name. Check permissions and event log availability. $($_.Exception.GetType().Name)"
        }
    }
    $queries = @(
        @{ LogName='Security'; Id=@(4625,4624,4740,1102); ProviderName='Microsoft-Windows-Security-Auditing'; StartTime=$StartTime; EndTime=$EndTime },
        @{ LogName='System'; Id=104; ProviderName='Microsoft-Windows-Eventlog'; StartTime=$StartTime; EndTime=$EndTime },
        @{ LogName='System'; Id=7045; ProviderName='Service Control Manager'; StartTime=$StartTime; EndTime=$EndTime }
    )
    foreach ($query in $queries) {
        if ($LogName -notcontains $query.LogName) { continue }
        # Event 1102 has a different provider, so query Security without a provider filter.
        if ($query.LogName -eq 'Security') { $query.Remove('ProviderName') }
        try {
            Get-WinEvent -FilterHashtable $query -ErrorAction Stop | ForEach-Object {
                ConvertFrom-WindowsEventXml -Xml $_.ToXml()
            }
        } catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { continue }
            throw "Cannot read event log $($query.LogName). Check permissions and event log availability. $($_.Exception.GetType().Name)"
        }
    }
}

function Get-LiveLogBatch {
    param($State, $Config, [datetime]$EndTime=[DateTime]::UtcNow)
    if (!$State.PSObject.Properties['SourceState']) { $State | Add-Member -NotePropertyName SourceState -NotePropertyValue ([pscustomobject]@{}) }
    $events=@(); $sources=@()
    foreach ($name in @('Security','System')) {
        if (!$State.SourceState.PSObject.Properties[$name]) {
            $State.SourceState | Add-Member -NotePropertyName $name -NotePropertyValue ([pscustomobject]@{LastScanUtc=$State.LastScanUtc;RetryFromUtc=$null})
        }
        $cursor=$State.SourceState.$name
        $start=$EndTime.AddMinutes(-[double]$Config.InitialLookbackMinutes)
        if ($cursor.LastScanUtc) { $start=(ConvertTo-UtcDate $cursor.LastScanUtc).AddSeconds(-[double]$Config.OverlapSeconds) }
        elseif ($cursor.RetryFromUtc) { $start=ConvertTo-UtcDate $cursor.RetryFromUtc }
        if ($start -gt $EndTime) { $start=$EndTime.AddSeconds(-[double]$Config.OverlapSeconds) }
        try {
            # Accept the batch only after the entire channel query has completed.
            $channelEvents=@(Get-WindowsLogs -LogName $name -StartTime $start -EndTime $EndTime)
            $events+=$channelEvents
            $cursor.LastScanUtc=$EndTime.ToString('o'); $cursor.RetryFromUtc=$null
            $sources += [pscustomobject]@{Name=$name;Status='OK';ReadEvents=$channelEvents.Count;LastSuccessUtc=$cursor.LastScanUtc;Error=''}
        } catch {
            if (!$cursor.LastScanUtc -and !$cursor.RetryFromUtc) { $cursor.RetryFromUtc=$start.ToString('o') }
            $sources += [pscustomobject]@{Name=$name;Status='ERROR';ReadEvents=0;LastSuccessUtc=$cursor.LastScanUtc;Error="Cannot read $name. Check administrator permissions and event log availability."}
        }
    }
    $errors=@($sources | Where-Object Status -eq 'ERROR').Count
    if ($errors -eq 0) { $State.LastScanUtc=$EndTime.ToString('o') }
    [pscustomobject]@{Events=$events;Sources=$sources;Status=$(if ($errors -eq 0) {'OK'} elseif ($errors -eq 2) {'ERROR'} else {'DEGRADED'})}
}
