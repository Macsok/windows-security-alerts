<#
.SYNOPSIS
Creates the group's PSWriteHTML report from saved monitoring events.
#>
[CmdletBinding()]
param([ValidateSet('LIVE','DEMO')][string]$Mode='LIVE', [string]$ConfigPath='')

. "$PSScriptRoot/Common.ps1"

function Get-TeamReportData {
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
    
    $warnings = @($ProcessedData | Where-Object { $_.ID -in 4625, 4724, 4732, 4740, 1102, 104, 7045 })
    
    [pscustomobject]@{
        ProcessedData = $ProcessedData
        GroupedEvents = @($ProcessedData | Group-Object Category)
        GroupedWarnings = @($warnings | Group-Object Category)
        TotalCount = $ProcessedData.Count
        WarningCount = $warnings.Count
    }
}

function Export-TeamReport {
    param([AllowEmptyCollection()][object[]]$Events=@(), [Parameter(Mandatory)][string]$Root)
    Import-Module PSWriteHTML -ErrorAction Stop
    $data = Get-TeamReportData -Events $Events
    $SavePath = Join-Path $Root 'reports/team-report.html'
    [void][IO.Directory]::CreateDirectory((Split-Path $SavePath))
    
    New-HTML -TitleText 'Windows Security Report' -FilePath $SavePath -Online {
        
        New-HTMLSection -HeaderText '24h summary - stats' {
            New-HTMLPanel -Density "Dense" {
                New-HTMLInfoCard -Title 'All Events' -Number $data.TotalCount
                New-HTMLInfoCard -Title 'Warning events (not incidents)' -Number $data.WarningCount
            }
        }
        
        New-HTMLSection -HeaderText '24h summary - charts' {
            New-HTMLPanel -Density "Dense" {
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
        
        New-HTMLSection -HeaderText 'Activity Summary (Zgrupowane ataki i ostrzeżenia)' {
            $summaryRows = @($data.ProcessedData | Where-Object { $_.ID -in 4625, 4724, 4732, 4740, 1102, 104, 7045 } | 
                Where-Object { $_.IpAddress -or $_.Account } | 
                Group-Object IpAddress, Account, Category | ForEach-Object {
                [pscustomobject]@{
                    IP = if ($_.Group[0].IpAddress) { [Net.WebUtility]::HtmlEncode([string]$_.Group[0].IpAddress) } else { "Brak IP" }
                    Account = if ($_.Group[0].Account) { [Net.WebUtility]::HtmlEncode([string]$_.Group[0].Account) } else { "Brak konta/System" }
                    Action = $_.Group[0].Category
                    Attempts = $_.Count
                }
            } | Sort-Object Attempts -Descending)

            if ($summaryRows.Count) { 
                New-HTMLTable -DataTable $summaryRows -Filtering 
            } else {
                New-HTMLText -Text "Brak danych do podsumowania."
            }
        }

        New-HTMLSection -HeaderText 'Specific info (Tylko istotne zdarzenia)' {
            $safeRows = @($data.ProcessedData | Where-Object { $_.ID -ne 4624 } | Select-Object DateTime,ID,Category,RecordId,
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

if ($MyInvocation.InvocationName -ne '.') {
    if (!$ConfigPath) { $ConfigPath=Join-Path $PSScriptRoot 'config.local.json' }
    $config=Read-MonitorConfig $ConfigPath
    $root=Join-Path $config.OutputRoot $Mode.ToLowerInvariant()
    $statePath=Join-Path $root 'state.json'
    if (!(Test-Path -LiteralPath $statePath)) { throw 'Run main.ps1 in this mode first.' }
    $state=Read-MonitorState $statePath
    $since=[DateTime]::UtcNow.AddHours(-24)
    if ($Mode -eq 'DEMO' -and @($state.Events).Count) {
        $latest=$state.Events | Sort-Object TimeCreated | Select-Object -Last 1
        $since=(ConvertTo-UtcDate $latest.TimeCreated).AddHours(-24)
    }
    $events=@($state.Events | Where-Object { (ConvertTo-UtcDate $_.TimeCreated) -ge $since })
    Export-TeamReport -Events $events -Root $root
}
