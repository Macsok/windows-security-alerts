<#
.SYNOPSIS
Creates the group's PSWriteHTML report from saved monitoring events.
.DESCRIPTION
Adapts the group member's report.ps1: event categories, Group-Object statistics,
PSWriteHTML sections, cards, donut charts, table and JSON statistics.
Uses the monitor's saved XML-normalized data instead of querying logs again.
The last 24 hours of stored events are reported; collection starts when the monitor starts.
Does not send email or Discord messages. The monitor handles notifications separately.
.PARAMETER Mode
Selects the separate DEMO or LIVE history.
.PARAMETER ConfigPath
Path to this computer's JSON configuration.
.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\report.ps1 -Mode DEMO
#>
[CmdletBinding()]
param([ValidateSet('LIVE','DEMO')][string]$Mode='LIVE', [string]$ConfigPath='')

. "$PSScriptRoot/Common.ps1"

function Get-TeamReportData {
    <#
    .SYNOPSIS
    Groups saved events using the categories from the group member's report.
    .DESCRIPTION
    Counts monitored events and individual warning events. A warning event is not
    necessarily a detected incident: the failed-logon rule still needs five attempts.
    .PARAMETER Events
    Normalized monitor events for the selected time range.
    .EXAMPLE
    Get-TeamReportData -Events (Get-DemoEvents)
    #>
    param([AllowEmptyCollection()][object[]]$Events=@())
    $EventsToMonitor = @{
        4625 = 'Failed logon'
        4720 = 'New account created'
        4722 = 'User account enabled'
        4724 = 'Password reset attempt'
        4732 = 'Member added to local group'
        1102 = 'Audit log cleared'
        4624 = 'Successful logon'
        4740 = 'Account lockout'
        104 = 'Event log cleared'
        7045 = 'Service installed'
    }
    $ProcessedData = @(foreach ($Event in $Events) {
        if ($EventsToMonitor.ContainsKey([int]$Event.EventId)) {
            [pscustomobject]@{
                DateTime = $Event.TimeCreated
                ID = $Event.EventId
                Category = $EventsToMonitor[[int]$Event.EventId]
                Account = $Event.Account
                IpAddress = $Event.IpAddress
                RecordId = $Event.RecordId
            }
        }
    })
    $warnings = @($ProcessedData | Where-Object { $_.ID -in 4625,4724 })
    [pscustomobject]@{
        ProcessedData = $ProcessedData
        GroupedEvents = @($ProcessedData | Group-Object Category)
        GroupedWarnings = @($warnings | Group-Object Category)
        TotalCount = $ProcessedData.Count
        WarningCount = $warnings.Count
    }
}

function Export-TeamReport {
    <#
    .SYNOPSIS
    Writes the group member's HTML report and JSON statistics.
    .DESCRIPTION
    Requires PSWriteHTML. Writes team-report.html and stats.json under reports.
    Does not modify monitor history or contact SMTP and Discord services.
    .PARAMETER Events
    Normalized events to include in the report.
    .PARAMETER Root
    DEMO or LIVE output folder, containing reports and logs.
    .EXAMPLE
    Export-TeamReport -Events (Get-DemoEvents) -Root .\runtime\demo
    #>
    param([AllowEmptyCollection()][object[]]$Events=@(), [Parameter(Mandatory)][string]$Root)
    Import-Module PSWriteHTML -ErrorAction Stop
    $data = Get-TeamReportData -Events $Events
    $SavePath = Join-Path $Root 'reports/team-report.html'
    [void][IO.Directory]::CreateDirectory((Split-Path $SavePath))
    New-HTML -TitleText 'Windows Security Report' -FilePath $SavePath -Online {
        New-HTMLSection -HeaderText '24h summary - stats' {
            New-HTMLPanel {
                New-HTMLInfoCard -Title 'All Events' -Number $data.TotalCount
                New-HTMLInfoCard -Title 'Warning events (not incidents)' -Number $data.WarningCount
            }
        }
        New-HTMLSection -HeaderText '24h summary - charts' {
            New-HTMLPanel {
                New-HTMLChart -Title 'Events' {
                    foreach ($Group in $data.GroupedEvents) {
                        New-ChartDonut -Name $Group.Name -Value $Group.Count
                    }
                }
                New-HTMLChart -Title 'Warning events' {
                    foreach ($Group in $data.GroupedWarnings) {
                        New-ChartDonut -Name $Group.Name -Value $Group.Count
                    }
                }
            }
        }
        New-HTMLSection -HeaderText 'Specific info' {
            # Event account names are untrusted; encode table values as HTML text.
            $safeRows = @($data.ProcessedData | Select-Object DateTime,ID,Category,RecordId,
                @{Name='Account';Expression={[Net.WebUtility]::HtmlEncode([string]$_.Account)}},
                @{Name='IpAddress';Expression={[Net.WebUtility]::HtmlEncode([string]$_.IpAddress)}})
            if ($safeRows.Count) { New-HTMLTable -DataTable $safeRows -Filtering }
        }
    } | Out-Null
    Save-JsonAtomic (Join-Path $Root 'reports/stats.json') @{
        Date = [DateTime]::UtcNow.ToString('o')
        TotalEvents = $data.TotalCount
        Warnings = $data.WarningCount
    }
    return $SavePath
}

# Dot-sourcing exposes the functions without installing modules or writing reports.
if ($MyInvocation.InvocationName -ne '.') {
    if (!$ConfigPath) { $ConfigPath=Join-Path $PSScriptRoot 'config.local.json' }
    $config=Read-MonitorConfig $ConfigPath
    $root=Join-Path $config.OutputRoot $Mode.ToLowerInvariant()
    $statePath=Join-Path $root 'state.json'
    if (!(Test-Path -LiteralPath $statePath)) { throw 'Run main.ps1 in this mode first.' }
    $state=Read-MonitorState $statePath
    $since=[DateTime]::UtcNow.AddHours(-24)
    # DEMO uses fixed dates so repeat runs have stable identifiers.
    if ($Mode -eq 'DEMO' -and @($state.Events).Count) {
        $latest=$state.Events | Sort-Object TimeCreated | Select-Object -Last 1
        $since=(ConvertTo-UtcDate $latest.TimeCreated).AddHours(-24)
    }
    $events=@($state.Events | Where-Object { (ConvertTo-UtcDate $_.TimeCreated) -ge $since })
    Export-TeamReport -Events $events -Root $root
}
