<#
.SYNOPSIS
Checks read access to Security and System event logs.
.DESCRIPTION
Checks read access to Security and System event logs.
.PARAMETER LogName
Windows event log channels to read: Security or System.
.PARAMETER LookbackDays
Number of days of Windows log history to inspect.
.EXAMPLE
.\tools\Test-WindowsLogs.ps1 -LogName Security -LookbackDays 1
#>
[CmdletBinding()]
param([ValidateSet('Security','System')][string[]]$LogName=@('Security','System'),
    [ValidateRange(1,3650)][int]$LookbackDays=1)
. "$(Split-Path $PSScriptRoot)/Get-Logs.ps1"
foreach ($name in $LogName) {
    try {
        $events=@(Get-WindowsLogs -LogName $name -StartTime ([DateTime]::UtcNow.AddDays(-$LookbackDays)) -EndTime ([DateTime]::UtcNow))
        [pscustomobject]@{LogName=$name;Status='Read completed';Count=$events.Count;EventIds=(@($events | Select-Object -ExpandProperty EventId -Unique) -join ',');Error=$null}
    } catch {
        [pscustomobject]@{LogName=$name;Status='Read failed';Count=0;EventIds='';Error=$_.Exception.Message}
    }
}
