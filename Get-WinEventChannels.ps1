param (
    [switch]$y,
    [switch]$v,
    [switch]$vv
)

#
# Check for administrator
#
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator to access all event log channels."
    return
}

#
# Set WorkDir
#
$WorkDir = $PSScriptRoot

#
# Get event log channels
#
$channels = Get-WinEvent -ListLog *

#
# Filter for active channels
#
$filtered = $channels | Sort-Object -Property LogName | Where-Object { $_.IsEnabled -eq $true -or $_.RecordCount -gt 0 }

#
# Prep output file
#
$LocalCN = $env:COMPUTERNAME
$outputFile = "$WorkDir\$LocalCN.txt"

#
# Verbose output (if -v or --verbose is used)
#
if ($vv) {
    Foreach ($i in $filtered.LogName) {
        Write-Host "[debug] $i"
    }
}

#
# Write filtered log names to file
#
$filtered.LogName | Out-File -FilePath $outputFile -Encoding UTF8
Write-Host "[info] Output written to: $outputFile"

#
# Build winlogbeat.yml
#
if ($y) {
    ##
    ## Start YML
    ##
    $YML = @()
    $YML += "---"
    $YML += "##"
    $YML += "## Event Logs"
    $YML += "##"
    $YML += "winlogbeat.event_logs:"
    Foreach ($c in $filtered){
        $LogName = $c.LogName
        $Channel = ($LogName -replace "[^A-z0-9-_]", "_").ToLower()
        $CF = $false
        $ChannelFile = "$WorkDir\channels\$Channel.yml"
        if (Test-Path $ChannelFile){
            $CF = $true
            Write-Host "[info] Using custom channel: $ChannelFile"
        }
        else {if ($vv) {Write-Host "[info] Looking for file: $ChannelFile"}}
        $PF = $false
        $ProcessorFile = "$WorkDir\channels\$Channel.processors.yml"
        if (Test-Path $ProcessorFile){
            $PF = $true
            Write-Host "[info] Using custom processors: $ProcessorFile"
        }
        else {if ($vv) {Write-Host "[info] Looking for file: $ProcessorFile"}}
        
        ##
        ## If custom else default
        ##
        if ($CF){
            $lines = (Get-Content -Path $ChannelFile -Encoding UTF8 | Where-Object { $_ -notmatch '^\s*##' })
            $YML += $lines
        }
        else {
            $YML += "  - name: $LogName"
        }
        
        ##
        ## If ProcessorFile
        ##
        if ($PF){
            $lines = (Get-Content -Path $ProcessorFile -Encoding UTF8 | Where-Object { $_ -notmatch '^\s*##' })
            $YML += $lines
        }
    }

    ##
    ## Setup
    ##
    ## https://www.elastic.co/docs/reference/beats/winlogbeat/configuring-howto-winlogbeat
    $YML += "##"
    $YML += "## Setup"
    $YML += "##"
    if (Test-Path "$WorkDir\setup.yml"){
        $YML += (Get-Content -Path "$WorkDir\setup.yml" -Encoding UTF8 | Where-Object { $_ -notmatch '^\s*##' })
    }
    
    ##
    ## Processors
    ##
    ## https://www.elastic.co/docs/reference/beats/winlogbeat/filtering-enhancing-data
    $YML += "##"
    $YML += "## Processors"
    $YML += "##"
    if (Test-Path "$WorkDir\processors.yml"){
        $YML += (Get-Content -Path "$PSScriptRoot\processors.yml" -Encoding UTF8 | Where-Object { $_ -notmatch '^\s*##' })
    }
    
    ##
    ## Output
    ##
    $YML += "##"
    $YML += "## Output"
    $YML += "##"
    if (Test-Path "$WorkDir\output.yml"){
        $YML += (Get-Content -Path "$PSScriptRoot\output.yml" -Encoding UTF8 | Where-Object { $_ -notmatch '^\s*##' })
    }
    else {
        ## https://www.elastic.co/docs/reference/beats/winlogbeat/kafka-output
        $YML += "output.kafka:"
        $YML += "  hosts: [`"localhost:9092`"]"
        $YML += "  topic: `"%{[agent.type]}-%{[agent][version]}`""
        $YML += "  partition.round_robin:"
        $YML += "    reachable_only: true"
        $YML += "    group_events: 2048"
    }
    ##
    ## Logging
    ##
    $YML += "##"
    $YML += "## Logging"
    $YML += "##"
    if (Test-Path "$WorkDir\logging.yml"){
        $YML += (Get-Content -Path "$PSScriptRoot\logging.yml" -Encoding UTF8 | Where-Object { $_ -notmatch '^\s*##' })
    }
    #>
    ##
    ## End YML
    ##
    $YML += "..."

    if ($v){$YML}
    Set-Content -Value $YML -Path "$WorkDir\winlogbeat.yml" -Encoding UTF8
    Write-Host "[info] Output written to: $WorkDir\winlogbeat.yml"
}