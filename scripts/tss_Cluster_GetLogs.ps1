﻿#region    ::::: Help ::::: 

<#  
.SYNOPSIS 
    Script Name:  GetLogs.ps1	
    Purpose:      gather data from Windows Failover Cluster Nodes (default 3 Month back)
    Version:      1.4
    Last Update:  2nd June 2020
    Author:       Josef Holzer 
    Email-Alias:  josefh

.DESCRIPTION
	This script collects data from one or more computers
    If the script runs on a cluster node with cluster service running, it collects data from all cluster nodes

.PARAMETER ComputerNames
	Define on which computers you want to run the script. Default is local host

.PARAMETER LogPathLocal
	Path where we store the data. Default is SystemDrive\MS_DATA\DataTime; e.g. C:\MS_DATA\180925-101214

.PARAMETER HoursBack
	How much hours should we look back in the event data and collect them. Test Default =1 
	
.PARAMETER EventLogNames
	Define the Eventlogs you want to gather; wildcard * is allowed
	Sample: -EventLogNames "System", "Application", "*CSVFS*", "*Smb*", "*winrm*", "*wmi*", "*spaces*" 
    Alternatively define this in the parameter section on top of this script

.EXAMPLE
	GetLogs.ps1  # simply run it without any parameter to collect all data with defaults

.EXAMPLE 
	GetLogs.ps1 -ComputerName H16N4 # run the script data collection on specific computer

.EXAMPLE
    To access the Info´s stored in xml files, do what is done in the following sample
    $Inf= Import-CliXml -path "C:\MS_DATA\190221-121553\H16N1-GeneralInfoPerHost.xml"
    $Inf # lists all Members
    $Inf.Hotfix # Lists installed Hotfixes for example

.EXAMPLE
    checkout 

#>
#endregion ::::: Help :::::

#region    ::::: Changelog - Whats New in this Version :::::
<#
    Changelog started at 20th of April 2020
    Ver 1.3 - What´s new ?
    - Added function CopyFilesInReportsFoldersToLocalComputer -ComputerNames $ComputerNames 
      From each Node additionally collecting all files in "$Env:SystemRoot\Cluster\Reports" (e.g. c:\windows\cluster\reports) to Local MS_DATA Folder 
    - By default collect more "Event Logs"
      - *CSVFS*, *Hyper-V*, "*Smb*", "*spaces*"
    
#>
#endregion ::::: Changelog - Whats New in this Version :::::

#region    ::::: ToDo - Ideas for the future ::::::
<# 
[=== Processing on Customer Site - Data Collection ===]
- Distribute Jobs across Hosts  
- Collect Disk, Volume etc. data
- Create a Map
  - Volume --> Partition --> Disk
  - CSV --> Volume --> Disk --> GUID
- Add most important parts of Get-NetView to GetNetInfoPerHost
- Add Binary Versions - like Get-NetView does this to GetGeneralInfoPerHost

[=== Processing on Engineers Machine ===]
- Extract more simply *.txt files from *.xml files

[=== Data Analysis ===]
  - System Eventlog 
    - find most common events 5120, 1135, 6005 

  - Cluster Log     
    - operational green events
      - Cluster Service started - clussvc.exe started - Mostly you this is due to a reboot
      - The current time is - gives you the local time and the difference to Cluster GMT 
      - The logs were generated using - Tells you if logs were generated in GMT or local time
      - I am the form/join coordinator (offline and lowest number node) - tells you who the coordinator node is 
         
      - GroupMove -Cluster Groups are Moved by cluster service 
      - MoveType::Manual) - Tells you if the Move Group was triggered manually by the customer

    - General Errors, Warnings...
      - ERR  - Errors - Case sensitive
      - WARN - Warnings - Case sensitive
      - critical - Critical Events
      - fatal
      - failed 

    - Critical Events of Clussvc and rhs 
        - terminated, 
        - Cluster service terminated
        - Cluster service has terminated
        - removed from the active failover cluster membership - the node was removed from the active cluster 
        - timeout
        - Timed out
        - STATUS_IO_TIMEOUT
        - deadlock

    - Critical Events - communication Issue
        - as down
        - are down
        - lost communication
        - is broken
        - is no longer accessible
        - Node Disconnected - Node communication to this node does no longer work - Networking issue
        - Disconnected - general look for Disconnected - mostly Physical Disk resource xyz has been disconnected
        - Lost quorum - Lost Cluster Quorum (including votes of witness resource)

    - Critical Events - Isolated, quarantined        
        - isolated - Cluster Node has beem marked as beeing in isolated state 
        - I have been quarantined - The current node says it has been quarantined - node ungracefully leaves cluster 3 times in an hour
        - has been quarantined - Another Node in the cluster has been quarantined
        - 'Start-ClusterNode –ClearQuarantine' - clussvc tried to ClearQuarantine
        - quarantine - General Info on nodes quarantine status 
        
    - Critical Events - Disks
        - SetSharedPRKey: failed - tried to send SCSIReserve Command with Persistent Reservation Shared Key, but failed
        - Reservation.SetPrKey failed - SCSI Persistent Reservation Key failed
        - PR reserve failed, status 170 - SCSI Persistent Reservation failed - so you can´t access the disk
        - Unable to arbitrate - tried to arbitrate a disk - SCSIReserve was sent, but this node could not claim the disk
        
    - Critical Events - CSV
        - is no longer accessible from this cluster node - CSV is no longer accessible from this cluster node
        - is no longer available on this node because of - CSV is no longer available on this node because of - hopefully a reason is mentioned
        - STATUS_CONNECTION_DISCONNECTED - CSV has entered a paused state because of STATUS_CONNECTION_DISCONNECTED
#> 
#endregion ::::: ToDo - Ideas for the future ::::::

#region    ::::: Define Script Input Parameters ::::: 
param(
    $ComputerNames = $env:COMPUTERNAME,	# Pass ComputerNames e.g. H16N1, default is local host name
    [String]$LogPath = "$env:SystemDrive\MS_DATA\" + (Get-Date -Format 'yyMMdd-HHmmss'), # Path where the data on each remote computer will be stored    
    [Int]$HoursBack = 2016,	# Define how much hours we should look back in the eventlogs 1day= 24; 1Week=168, 1Month= 672, 3Month= 2016, 6Month= 4032, 1Year= 8064
    [String]$ClusterName,   # if no ClusterName is passed use local Cluster - implemented in main
    # Define which EventLogNames should be collected; either you pass the full Eventlogname or a mask like "*Hyper*"
    # To check out what the Eventlog names look like for e.g. Hyper-V: Get-WinEvent -ListLog "*Hyper-V*"
    $EventLogNames=(
        "System", 
        #"Application", 
        "*CSVFS*",
        "*Hyper-V*",
        "*Smb*",         
        "*spaces*"        
        #"*winrm*", 
        #"*wmi*", 
        #"Microsoft-Windows-FailoverClustering/Operational" 
    ),

    # Define which cluster validation tests should run on customers Cluster Nodes
    $ClusterValidationTestNames=(
        "Cluster Configuration",
        "Hyper-V Configuration",
        "Inventory","Network",    
        #"Storage",              # Note: Storage Tests will lead to a short interruption of access to disks and should not be run in a production environment 
        "System Configuration"    
    ),

    #region  ::::: Switches ::::: 
    [switch]$NetInfo 		= $True      # If $NetInfo is true, we call GetNetInfoPerHost to collect network related information
    #endregion  ::::: Switches ::::: 
)
#endregion ::::: Define Script Input Parameters :::::

#region    ::::: Define Global Variables ::::: 
    # Section for global variables, which you don´t want to show up in the parameter region        
    [bool]$IsClusSvcRunning = $False	# variable, to save status of cluster service running/stopped 

#endregion ::::: Define Global Variables ::::: 

#region    ::::: Helper Functions :::::

#function Show Progress - Global parameters
$sTimeStampScriptStart= [String](Get-Date -Format 'yyMMdd-HHmmss') # Date as String to be used in Folder Name for Files e.g. MS_DATA\190820-1032
$TimeStampScriptStart = Get-Date				         # get the timestamp, when this script starts
$TimeStampStartSaved  = $Script:TimeStampScriptStart	 # only first time save the script start timestamp

$DebugLogPath         = $LogPath                         # Directory, where the logs are stored
$DebugLogPathFull     = "$DebugLogPath\$sTimeStampScriptStart-ScriptDebug.log"   # FullPath of the Scripts Debug.log
$DebugLogLevel        = 3                                # If DebugLogLevel is 3 everything is logged; 0 is disabled, 1=Light, 2= Medium, 3=All
$DebugLogBuffer       = @()                              # Collect DebugLog Messages in ShowProgress and save them later to a file
$DebugLogCount        = 0                                # Counter for DebugLogs
$DebugLogCountMax     = 50                               # After X Messages Save to file 
$DebugLogToFile       = $True                            # Default is True, so we spew out the Debug Messages to a File 
$RunOnlyOnce          = $True                            # Bool to spew out some Messages only once
$ScriptFullName       = $MyInvocation.InvocationName     # Full Path of the Script Name


<# 
    SYNOPSIS: show what we are doing so far; should be placed on top of all other functions
    Owner: josefh/sergeg
#>
function ShowProgress { 
    param(
        $MessageUser = "",		      # pass your own message
        $ForeColor =  "White"	      # default ForeGroundColor is White        
    )
    
    If ($Script:DebugLogLevel -eq 0 ) { Return } # If DebugLogLevel is 0 exit this function imediately      
    
    # Get the function name, that was calling ShowProgress
    function GetFunctionName ([int]$StackNumber = 1) {
        # https://stackoverflow.com/questions/3689543/is-there-a-way-to-retrieve-a-powershell-function-name-from-within-a-function
        return [string]$(Get-PSCallStack)[$StackNumber].FunctionName
    }
    $TimeDisplay = [String](Get-Date -Format 'yyMMdd-HHmmss') # time stamp to display on each action/function call. eg 'yyMMdd-HHmmss'
    $TimeStampCurrent = Get-Date
    $TimeDiffToStart = $TimeStampCurrent - $TimeStampScriptStart		# overall duration since start of script
    $TimeDiffToLast =  $TimeStampCurrent - $Script:TimeStampStartSaved	# time elapsed since the last action
	$Script:TimeStampStartSaved = $TimeStampCurrent						# update/save timestamp to measure next progress duration
    $FuncName =  GetFunctionName -StackNumber 2							# Last Function Name
    [String]$DurScriptDisplay = "" + $TimeDiffToStart.Minutes + ":" + $TimeDiffToStart.Seconds	# " ;Script ran for Min:Sec  = " # display duration since script start
    [String]$DurFunctionDisplay = "" + $TimeDiffToLast.Minutes +  ":" + $TimeDiffToLast.Seconds	# " ;Last Action took Min:Sec= " # display duration of last action or function call
    if (-not ($TimeDiffToLast.TotalSeconds -ge 1) ) { $DurFunctionDisplay = "0:0" }

    
    If ($RunOnlyOnce){ # Only first time write the head line to explain the columns        
        $Description= "Script Started at $sTimeStampScriptStart ScriptFullName:$ScriptFullName on Host:$($Env:ComputerName) "        
        If (-Not ( Test-Path -Path $DebugLogPath ) ){ # if the DebugLogPath does not already exist, e.g. default is c:\MSDATA, then Create it 
            New-Item -Path $DebugLogPath -ItemType Directory
        }
        write-host -fore Green $Description
        $Description | Out-File -FilePath $DebugLogPathFull -Append

        $Description= "TimeStamp    |TimeSinceScriptStarted Min:Sec|DurationOfLastAction Min:Sec|FunctionName| UserMessage"
        <#
            Sample Output
            "TimeStamp   |TimeSinceScriptStarted Min:Sec|DurationOfLastAction Min:Sec|FunctionName| UserMessage"
            190820-103322|0:0                           |0:0                         |CreateFolder| Enter
            190820-103322|0:0|0:0|CreateFolder| ...On Node:H16N2 creating folder: \\H16N2\C$\MS_DATA\190820-103322
            190820-103322|0:0|0:0|CreateFolder| try:CreateFolder: \\H16N2\C$\MS_DATA\190820-103322
            190820-103322|0:0|0:0|CreateFolder| Folder \\H16N2\C$\MS_DATA\190820-103322 could be created successfully
            190820-103322|0:0|0:0|CreateFolder| Exit
        #>
        write-host $Description
        $Description | Out-File -FilePath $DebugLogPathFull -Append
        $Script:RunOnlyOnce= $False
    }
    $FullString= "$TimeDisplay|$DurScriptDisplay|$DurFunctionDisplay|$FuncName| $MessageUser"
    write-host -Fore $ForeColor $FullString
    
    # if $DebugLogToFile is $Ture store Output in the Logfile
    if ($DebugLogToFile){
        $Script:DebugLogCount++
        $Script:DebugLogBuffer+= $FullString
        if ($Script:DebugLogCount -ge $DebugLogCountMax) {
            write-host -ForegroundColor Yellow "Flushing DebugLogBuffer to $DebugLogPathFull"
            $Script:DebugLogBuffer | Out-File -FilePath $DebugLogPathFull -Append

            $Script:DebugLogCount= 0    # Reset DebugLogCount to 0
            $Script:DebugLogBuffer= @() # Reset DebugLogBuffer to empty String        
        }
    }
} # End of ShowProgress

# Checkout if the script runs as admin
function DoIRunAsAdmin{ 
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal `
                        ( [Security.Principal.WindowsIdentity]::GetCurrent() ) 
    if ($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) { 
        return $true  
    } 
    else { 
       return $false 
    } 
} 

function CreateFolder { 
    # SYNOPSIS: a general function to create any folder, do some checks and do reporting
    Param(
        $HostName,
        $FolderPath
    )
    ShowProgress "Enter"
    $ErrorActionPreferenceSave =  $ErrorActionPreference # Save the current ErrorActionPreference
    $ErrorActionPreference = 'Stop'   # Change ErrorActionPreferrence to stop in order to prevent the cmdlet to handle the error on its own
    
        if (-not (Test-Path $FolderPath) ){ # if the folder does not already exist
        ShowProgress "...On Node:$HostName creating folder: $FolderPath"

        try{
            ShowProgress "try:CreateFolder: $FolderPath"
            If ($Env:ComputerName -eq $HostName){ # if we are on the local host where we run the script
                New-Item -Path $FolderPath -ItemType Directory | Out-Null	# Create folder on the loacal host, to make it faster and prevent issues with WinRM
            }
            else{
                Invoke-Command -ComputerName $HostName -ScriptBlock {		        # Make it all remote capable 
                    New-Item -Path $Using:FolderPath -ItemType Directory | Out-Null	# Create folder, could be remote and suppress output
                }
            }
            ShowProgress "Folder $FolderPath could be created successfully"  
            #ShowProgress "...On Node:$HostName finished creating folder: $FolderPath"    
        }
        Catch{ # since ErrorActionPreference is on 'Stop' we jump into the catch block if New-Item failed 
            ShowProgress -Fore red "Catch: Error during Folder Creation"  # we ran into an issue 
            ShowProgress -Fore red "Unable to create the Folder $FolderPath on $HostName " 
            ShowProgress -Fore Red "FullQualifiedErrorId: $($Error[0].FullyQualifiedErrorId)"
            ShowProgress -Fore Red "Full ErrorMessage:$_"
            If ($Error[0].FullyQualifiedErrorId -like "AccessDenied*"){ 
                ShowProgress -Fore Magenta "Please check if you are running the powershell host (window) with administrative privileges" 
            }
            If ($Error[0].FullyQualifiedErrorId -like "*server name cannot be resolved*"){                 
                $HostNameFQDN= [System.Net.Dns]::GetHostEntry($HostName).HostName  
                ShowProgress -Fore Magenta "Looks like the Server Name could not be resolved. [System.Net.Dns]::GetHostEntry(`$HostName):$HostNameFQDN "
            }
                        
            ShowProgress -ForeColor Yellow -BackColor Black "Aborting this script now " 
            EXIT           
        }        
    }   
    $ErrorActionPreference = $ErrorActionPreferenceSave
    ShowProgress "Exit"
}



function CreateLogFolderOnHosts { 
# SYNOPSIS: could be only one
    param(
        $ComputerNames,
        $LogPath
    )
    ShowProgress "...Start creating Log folder on Hosts: $ComputerNames"                
    foreach($ComputerName in $ComputerNames){
        ShowProgress "...Start creating Log folder on Host:$ComputerName"                
        $LogPathDollar = $LogPath.Replace(":","$")				# e.g. C:\MS-Data --> C$\MS-Data
        $LogPathUNC = "\\$($ComputerName)\$LogPathDollar"		# e.g. \\H16N2\c$\MS-Data                
        CreateFolder -HostName $ComputerName -FolderPath $LogPathUNC        
    }
    ShowProgress "...Finished creating log folder on hosts"
}  

function MoveDataFromAllComputersToLocalComputer { 
# SYNOPSIS: move remotly collected data to local folder, e.g. C:\MS_DATA\180925-101214
    param(
        $ComputerNames        
    )
    ShowProgress "Enter"
    $LocalHost = $env:COMPUTERNAME    
    $LogPathLocal = $Script:LogPath   # LogPath e.g. c:\MS_DATA
    $ErrorActionPreferenceSave =  $ErrorActionPreference # Save the current ErrorActionPreference
    $ErrorActionPreference = 'Stop'   # Change ErrorActionPreferrence to stop in order to prevent the cmdlet to handle the error on its own
    $WaitSec = 10                     # Wait for a couple of seconds; default 10 seconds

    ShowProgress "...Start moving all data files from all Hosts:$ComputerNames to local Host:$LocalHost"                
    foreach($ComputerName in $ComputerNames){
        if (-not ($ComputerName -eq $LocalHost) ){            
            $LogPathDollar = $LogPath.Replace(":","$")                  # e.g. $LogPath = C:\MS_DATA --> C$\MS_DATA
            $LogPathRemoteUNC   = "\\$($ComputerName)\$LogPathDollar"   # e.g. \\H16N2\c$\MS_DATA               
            ShowProgress "...Start moving files from $LogPathRemoteUNC to $LogPathLocal"   

            # Sometimes the remote path is not reachable, so we check out and handle this one time
            # if it becomes a reoccuring issue we should run this in a loop and try several times 
            if ( !(Test-Path -Path $LogPathRemoteUNC) ){
                ShowProgress -Fore DarkMagenta "Catch: Could not reach remote Path: $LogPathRemoteUNC"  # we had an issue - lets wait and do the move then
                ShowProgress -Fore DarkMagenta "Let´s wait for some seconds:$WaitSec ... and try again" 
                Start-Sleep -Seconds $WaitSec # Wait for a couple of seconds if the path is not available immediately               
            } 
            # if the path is available
            ShowProgress "Finally: Moving Remote files to Local Host "                
            ShowProgress "...trying to collect all data files from all Hosts:$ComputerNames and move to local Host:$LocalHost ..."
            Move-Item -Path $LogPathRemoteUNC\* -Destination $LogPathLocal  # Move Files to Local Path   
                                        
        }
    }
    $ErrorActionPreference = $ErrorActionPreferenceSave
    ShowProgress "...Finished moving all data files from all Hosts:$ComputerNames to local Host:$LocalHost"                
    ShowProgress "Exit"
}

function CopyFilesInReportsFoldersToLocalComputer{
    # SYNOPSIS: Copy files in "C:\Windows\Cluster\Reports" from each node to local folder, e.g. C:\MS_DATA\180925-101214
    #Validation Reports, #Cluster\reports, #reports, #test-cluster 
    param(
        $ComputerNames        
    )
    ShowProgress "Enter"
    $LocalHost = $env:COMPUTERNAME    
    $LogPathLocal = $Script:LogPath   # LogPath e.g. c:\MS_DATA
    $ErrorActionPreferenceSave =  $ErrorActionPreference # Save the current ErrorActionPreference
    $ErrorActionPreference = 'Stop'   # Change ErrorActionPreferrence to stop in order to prevent the cmdlet to handle the error on its own
    $WaitSec = 10                     # Wait for a couple of seconds; default 10 seconds

    ShowProgress "...Start Copying all files in '`$Env:SystemRoot\Windows\Cluster\Reports' from each node:$ComputerNames to local Host:$LocalHost"                
    foreach($ComputerName in $ComputerNames){        
        $ReportsPath       = "$Env:SystemRoot\Cluster\Reports"   # Reports Path on the current Node "C:\Windows\Cluster\Reports"
        $ReportsPathDollar = $ReportsPath.Replace(":","$")       # e.g. $ReportsPathDollar= "C$\Windows\Cluster\Reports"
        $ReportsPathUNC= "\\$($ComputerName)\$ReportsPathDollar"       # e.g. = $ReportsPathUNC= "H16N2\C$\Windows\Cluster\Reports"
        ShowProgress "...Start copying files from $ReportsPathUNC to $LogPathLocal"   

        # Sometimes the remote path is not reachable, so we check out and handle this one time
        # if it becomes a reoccuring issue we should run this in a loop and try several times 
        if ( !(Test-Path -Path $ReportsPathUNC) ){
            ShowProgress -Fore DarkMagenta "Catch: Could not reach remote Path: $ReportsPathUNC"  # we had an issue - lets wait and do the move then
            ShowProgress -Fore DarkMagenta "Let´s wait for some seconds:$WaitSec ... and try again" 
            Start-Sleep -Seconds $WaitSec # Wait for a couple of seconds if the path is not available immediately               
        } 
        # if the path is available
        ShowProgress "Finally: Copying Remote files to Local Host "                
        ShowProgress "...trying to copy all files in $ReportsPath to $LogPathLocal"
        $ReportsFolder= "$LogPathLocal\$ComputerName\Reports"
        CreateFolder -HostName $env:COMPUTERNAME -FolderPath $ReportsFolder
        Copy-Item "$ReportsPathUNC\*" -Destination $ReportsFolder            # Copy Reports Folder to e.g. c:\MS_DATA\H16\Reports        
    }
    $ErrorActionPreference = $ErrorActionPreferenceSave
    ShowProgress "...Finished Copying all files in $($ReportsPathUNC) to $($ReportsFolder)"                
    ShowProgress "Exit"
} #Endof CopyFilesInReportsFoldersToLocalComputer
    

#endregion ::::: Helper Functions :::::

#region    ::::: Worker Functions to Collect Computer specific Data for each host  Eventlogs, OSVersion... ::::::

function GetEventLogs {
# SYNOPSIS: collect eventlogs from all machines
    param(
        $ComputerNames,                 # the name or a list of names of the computers, local or remote you want to gather Eventlogs from
        $HoursBack = $Script:HoursBack, # Define how much hours we should look back in the logs; Default is script scope variable $HoursBack
        $LogNames                       # list of event log names; either you pass the full Event Log name like "System" or a mask like "*Hyper*"
                                        # Sample: $EventLogNames=("System", "Application", "*CSVFS*")
    )
    ShowProgress "Enter"
    foreach($ComputerName in $ComputerNames){
        # Gather all EventLogs from current ComputerName, extract only last # of hours
        # Walk through each LogName in LogNames e.g. ("System", "Application", "*CSVFS*")
        foreach($LogName in $LogNames){        
            $LogFamilyNames = Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue  # $LogFamilyNames could be a mask representing several Logs - a LogFamily - e.g. *SMB*

            # if the LogName does not exist on this computer spew out a message
            If ( $Null -eq $LogFamilyNames) {
                ShowProgress -Fore DarkMagenta "Could not find the following Log on this Computer: $LogName"
            }

            # if a Pattern like *SMB* has been passed - walk through each Logname         
            foreach($LogFamilyName in $LogFamilyNames){ # Microsoft-Windows-SmbClient/Audit, Microsoft-Windows-SMBServer/Audit and so on
                $LogFileName = ($LogFamilyName.LogName).Replace("/","_") # Replace Forward Slash in EventLogNames with UnderScore

                $LogPathDollar = $LogPath.Replace(":","$")            # e.g. C:\MS-Data --> C$\MS-Data
                $LogPathUNC   = "\\$($ComputerName)\$LogPathDollar"  # e.g. \\H16N2\c$\MS-Data                
                    
                $LogFileNameXML =  "$LogPathUNC\$ComputerName" + "_" + $LogFileName + ".XML"
                $LogFileNameTXT =  "$LogPathUNC\$ComputerName" + "_" + $LogFileName + ".Log"
                $LogFileNameEvtx = "$LogPathUNC\$ComputerName" + "_" + $LogFileName + ".evtx"
                
                #Gather SystemEventlogs
                ShowProgress "...Start gathering EventLog:$($LogFamilyName.LogName) for Computer:$ComputerName"

                # Collecting EventLogs respecting HoursBack
                $StartTime = (Get-Date).AddHours(-$HoursBack) 
                # Using a Filter Hash Table to filter events that match $MinutesBack
                # More Info:  https://blogs.technet.microsoft.com/heyscriptingguy/2014/06/03/use-filterhashtable-to-filter-event-log-with-powershell/
                $Evts = Get-WinEvent -ComputerName $ComputerName -ErrorAction SilentlyContinue  -FilterHashtable @{Logname=$LogFamilyName.LogName; StartTime=$StartTime}

                #Sorting Events and selecting properties we really need
                $EvtsSorted = $Evts | Sort-Object TimeCreated -Descending | Select-Object MachineName, LevelDisplayName, TimeCreated, ProviderName, Id, LogName, Message 
                                      
                # Export Events to deserialized *.xml file
                $EvtsSorted | Export-CliXml -Path $LogFileNameXML
                # Export Events as simple *.txt file
                $EvtsSorted | Export-Csv -Path $LogFileNameTXT -NoTypeInformation
                            
                # Gathering Eventlogs in old style *.evtx with wevtutil.exe 
                ShowProgress "...Gathering *.evtx with Old-Style-Tool:wevtutil"
                $MilliSecondsBack = $HoursBack * 60 * 60 * 1000
                wevtutil.exe /remote:$ComputerName epl $LogFamilyName.LogName $LogFileNameEvtx /q:"*[System[TimeCreated[timediff(@SystemTime) <=$MilliSecondsBack]]]" /ow:true

                <# Gathering Eventlogs in the old style as *.txt - not fully checked yet
                   wevtutil qe Application /c:3 /rd:true /f:text
                   https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil
                #>
                        
                ShowProgress "...Finished gathering $($LogFamilyName.LogName) for Computer:$ComputerName"
                ShowProgress "-----------------------------"
            }            
        }
    }
    ShowProgress "Exit"
}

#josefh- needs to be overworked
function GetStorageInfoPerHost{
    param(
        $ComputerNames
    )
    ShowProgress "Enter"
    $LogPathLocal = $Script:LogPath

    #Stor physical disks and the StorageNode they are connected to
    $AllStorageNodeDisks=@()
    $NodeDisks=@()
    
    ShowProgress "Enter"    
    $StorageNodes= Get-StorageNode
    foreach($StorageNode in $StorageNodes){
        $Dsks= $StorageNode | Get-PhysicalDisk -PhysicallyConnected
        foreach($Dsk in $Dsks){
            $Dsk | Add-Member -NotePropertyName StorageNodeName         -NotePropertyValue $StorageNode.Name            
            $NodeDisks+=$Dsk                
        }
        $NodeDisks | Export-CliXML -Path "$LogPathLocal\$($StorageNode.Name)-DisksPhysicallyConnected.xml"                    
        $AllStorageNodeDisks+= $NodeDisks 
        $NodeDisks= @()
    }               

    #gather additional data on storage
    foreach($ComputerName in $ComputerNames){           
        $StorSubSysClus      = Get-StorageSubSystem *Cluster*
        
        ShowProgress "$StorSubSysClus | Debug-StorageSubSystem"
        try{   $StorDebugOut= $StorSubSysClus | Debug-StorageSubSystem -ErrorAction Stop } # stop so that the error is not handled by the cmdlet
        catch{ write-host -ForegroundColor Cyan "FullQualifiedErrorId: $($Error[0].Exception)" }

        # Define our own Storage Information Object $StorInf, that takes all Info around Storage 
        $StorInf= [PSCustomObject][ordered]@{  
            #S2D Info
            S2D                   = Get-ClusterS2D
            S2DClusParam          = Get-Cluster | Select-Object S2D* # S2DBusTypes= 134144 -> S2D            
                
            #Physical Disks - # Interessting props Get-PhysicalDisk | select SerialNumber, CanPool, CannotPoolReason, LogicalSectorSize, PhysicalSectorSize | ft
            GetPhysicalDisk          = Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-PhysicalDisk }
            DisksPhysicallyConnected = $AllStorageNodeDisks # Physical Disks Connected to which Node + Node Name                        

            #Storage Subsystem
            StorSubSysClus        = $StorSubSysClus
            StorJob               = $StorSubSysClus | Get-StorageJob           
            StorDebugOut          = $StorDebugOut
        }

        # Check if we have a Health Resource
        $HealthResourceType= Get-ClusterResource | Where-Object {$_.ResourceType -like "*Health*"    }
        if ($Null -ne $HealthResourceType){ # if we have a Health Resource 
            ShowProgress "Found a Health Resource on this cluster - Storing Storage Info"

            #Cluster Health 
            $StorInf | Add-Member -NotePropertyName StorHealthAction  -NotePropertyValue ($StorSubSysClus | Get-StorageHealthAction  )
            $StorInf | Add-Member -NotePropertyName StorHealthSetting -NotePropertyValue ($StorSubSysClus | Get-StorageHealthSetting )
            $StorInf | Add-Member -NotePropertyName StorHealthReport  -NotePropertyValue ($StorSubSysClus | Get-StorageHealthReport  ) # deprecated in 2019 - Use Get-ClusterPerformanceHistory instead. 
            $StorInf | Add-Member -NotePropertyName HealthResParam    -NotePropertyValue (Get-ClusterResource Health | Get-ClusterParameter)
            $StorInf | Add-Member -NotePropertyName HealthResParamVal -NotePropertyValue ((Get-ClusterResource Health | Get-ClusterParameter).Value )            
        }

        # Export Info from each Node in a Separate File
        ShowProgress "Export Storage from Host: $ComputerName"
        $StorInf | Export-CliXML -Path "$LogPathLocal\$ComputerName-StorageInfoPerHost.xml"
        ShowProgress "...Finished Gathering GeneralInfoPerHost - stored in $LogPathLocal\$ComputerName-StorageInfoPerHost.xml"; write-host
    }
    ShowProgress "Exit"
}

function GetClusterPerformanceHistory{
<# $P=Import-CliXml -path "C:\MS_DATA\200204-083456\H19N1-ClusPerf.xml"
   ($P.Disks).Description | Group | Sort Name # To get disks listed on each Node
   ($P.Disks | Where Description -like "H19N1-Disk2001") | ft Desc*, SizeInGB, Time, MetricId,Value # To get values per a special disk
#>
    param(
        $ClusterName,
        $ComputerNames
    )
    ShowProgress "Enter"
    $LogPathLocal = $Script:LogPath

    # Check if it is 2019 Server with CU Oct 2019 or higher 
    $OS= (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion")
    $ReleaseId= [Int]$OS.ReleaseId
    $ReleaseIdMin= 1809 # 1809= 2019 Server + CU Oct 2019 
    if ($ReleaseId -lt $ReleaseIdMin){        
        ShowProgress -ForeColor Magenta "In this OS we did not implement Get-ClusterPerf"
        ShowProgress -ForeColor Magenta "OS:$($OS.ProductName); Build:$($OS.CurrentBuild); ReleaseId:$ReleaseId"
        ShowProgress -ForeColor Magenta "Exiting this function GetClusterPerformanceHistory"
        Return # Exit this function
    }



    if ($ClusterName -eq ""){    # if no cluster name was passed
        $ClusterName= (Get-Cluster).Name  # Get local cluster name on this host
    }
    
    # Define empty arrays to take ClusterPerformanceHistory types 
          
    foreach($ComputerName in $ComputerNames){         
        ShowProgress "Collecting ClusterPerformanceHistory for Computer: $ComputerName"

        ShowProgress "Get-VM | Get-ClusterPerf"
        $VMs= Get-VM -CimSession $ComputerName        
        If ( $Null -ne $VMs ){
            $ClusPerfVMs=@()
            $ClusPerfVHDs=@()
            foreach($VM in $VMs){
                # Get-ClusterPerf Counters for each VM             
                $V= $VM | Get-ClusterPerf
                $V | Add-Member -NotePropertyName VMName         -NotePropertyValue $VM.VMName
                $V | Add-Member -NotePropertyName VMId         -NotePropertyValue $VM.VMId
                $V | Add-Member -NotePropertyName State         -NotePropertyValue $VM.State
                $ClusPerfVMs+= $V

                $VHDs= $VM | Select-Object VMId | Get-VHD -CimSession $ComputerName | Get-ClusterPerf 
                $ClusPerfVHDs+= $VHD | Get-ClusterPerf
            }
        }

        
        ShowProgress "Get-PhysicalDisk | Get-ClusterPerf"
        $PhysicalDisks= Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-PhysicalDisk }
        $ClusPerfDisks=@()
        foreach($PhysicalDisk in $PhysicalDisks){        
            ShowProgress "Get-PhysicalDisk | Get-ClusterPerf - Disk $($PhysicalDisk.Description)"    
            try{
                $Dsk= $PhysicalDisk | Get-ClusterPerf
                $Dsk | Add-Member -NotePropertyName UniqueId         -NotePropertyValue $PhysicalDisk.UniqueId
                $Dsk | Add-Member -NotePropertyName PhysicalLocation -NotePropertyValue $PhysicalDisk.PhysicalLocation
                $Dsk | Add-Member -NotePropertyName Description      -NotePropertyValue $PhysicalDisk.Description
                $Dsk | Add-Member -NotePropertyName SizeInGB         -NotePropertyValue ($PhysicalDisk.Size/1024/1024/1024) # in GB
                $ClusPerfDisks+= $Dsk
            }
            catch{
                write-host -ForegroundColor Cyan "FullQualifiedErrorId: $($Error[0].Exception)"
            }
        }
        
        ShowProgress "Get-NetAdapter | Get-ClusterPerf"
        $NetAdapters= Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-NetAdapter }
        $ClusPerfNetAdapters=@()
        foreach($NetAdapter in $NetAdapters){            
            try{ 
                $Nic= $NetAdapter | Get-ClusterPerf
                $Nic | Add-Member -NotePropertyName Name         -NotePropertyValue $NetAdapter.Name
                $Nic | Add-Member -NotePropertyName LinkSpeed         -NotePropertyValue $NetAdapter.LinkSpeed
                $Nic | Add-Member -NotePropertyName DeviceID         -NotePropertyValue $NetAdapter.DeviceID
                $Nic | Add-Member -NotePropertyName SystemName         -NotePropertyValue $NetAdapter.SystemName                
                $ClusPerfNetAdapters+= $Nic
            }
            catch{
                write-host -ForegroundColor Cyan "FullQualifiedErrorId: $($Error[0].Exception)"
            }
                
        }
                
        ShowProgress "Get-Volume | Get-ClusterPerf"
        $Volumes= Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-Volume }
        $ClusPerfVolumes=@()
        foreach($Volume in $Volumes){            
            try{
                $Vol= $Volume | Get-ClusterPerf
                $Vol | Add-Member -NotePropertyName ObjectId         -NotePropertyValue $NetAdapter.ObjectId
                $Vol | Add-Member -NotePropertyName UniqueId         -NotePropertyValue $NetAdapter.UniqueId
                $Vol | Add-Member -NotePropertyName SizeInGB         -NotePropertyValue ($NetAdapter.Size/1024/1024/1024)
                $Vol | Add-Member -NotePropertyName FileSystemType   -NotePropertyValue $NetAdapter.FileSystemType
                $ClusPerfVolumes+= $Vol
            }            
            Catch{
                write-host -ForegroundColor Cyan "FullQualifiedErrorId: $($Error[0].Exception)"
            }    
        }

        ShowProgress "Get-ClusterNode | Get-ClusterPerf Node: $ComputerName"            
        try{
            $ClusPerfClusterNode= Get-ClusterNode $ComputerName | Get-ClusterPerf 
        }            
        Catch{
            write-host -ForegroundColor Cyan "FullQualifiedErrorId: $($Error[0].Exception)"
        }
 
        ShowProgress "Get-Cluster | Get-ClusterPerf"
        try{
            $ClusPerfCluster= Get-Cluster -Name $ClusterName | Get-ClusterPerf
        }            
        Catch{
            write-host -ForegroundColor Cyan "FullQualifiedErrorId: $($Error[0].Exception)"
        }
        
        $ClusPerf= [PSCustomObject][ordered]@{ 
            Cluster      = $ClusPerfCluster
            ClusterNode  = $ClusPerfClusterNode
            Disks        = $ClusPerfDisks
            NetAdapters  = $ClusPerfNetAdapters
            VMs          = $ClusPerfVMs
            VHDs         = $ClusPerfVHDs
            Volumes      = $ClusPerfVolumes
        }
        # Export all ClusterPerformanceHistory Info in xml File
        ShowProgress "Export ClusterPerformanceHistory: $ComputerName"
        $ClusPerf | Export-CliXML -Path "$LogPathLocal\$ComputerName-ClusPerf.xml"
        ShowProgress "...Finished Gathering ClusterPerformanceHistory - stored in $LogPathLocal\$ComputerName-ClusterPerformanceHistory.xml"; write-host

    } # foreach($ComputerName in $ComputerNames){   
} # function GetClusterPerformanceHistory{

# Gather all FirewallRules with respect to a Firewall Name Filter and return as 1 object $oFirewall
Function GetFirewallRules{
    param(
        $ComputerName,
        $FireWallNameFilter # e.g. "Cluster" # "*" gets all Firewall Rules, but you can add your filter e.g. "cluster"
    )
    ShowProgress "Enter"
    # Gather Infos you need for your object 
    $FireWallRules= Get-NetFirewallRule -CimSession $ComputerName | Where-Object { $_.DisplayName -like "*$FireWallNameFilter*" }
    $FirewallPorts= Get-NetFirewallPortFilter -CimSession $ComputerName

    $oFireWall= @()   # Create an empty array to add your Firewall Objects one by one

    ForEach($FireWallRule in $FireWallRules){        # Walk through each FirewallRule 
        ForEach($FirewallPort in $FirewallPorts){    # Walk through each Firewall Port 
            if ($FireWallPort.InstanceId -eq $FireWallRule.Id){  # check if Id´s do match 
                
                # old way to create your own Powershell Object: $F= New-Object PSObject -Property @{ 
                $F= [PSCustomObject][ordered]@{ # Create your own Object with your properties ordered
                    FWName=         $FireWallRule.Name
                    FWDisplayName=  $FireWallRule.DisplayName
                    FWDirection=    $FireWallRule.Direction
                    FWEnabled=      $FireWallRule.Enabled
                    FWProfile=      $FireWallRule.Profile

                    PTProtol=       $FireWallPort.Protocol
                    PTLocalPort=    $FireWallPort.LocalPort
                    PTRemotePort=   $FirewallPort.RemotePort
                }
                $oFirewall+= $F   # Add the current object to the Array
            }
        }
    }
    ShowProgress "Exit"
    Return $oFirewall #return the whole array to the global scope 
} # End GetFirewallRules
    
function GetMsInfo32nfo{ 
    param(
        $ComputerNames
    )
    ShowProgress "Enter"
    $LogPathLocal = $Script:LogPath
    foreach($ComputerName in $ComputerNames){
        msinfo32.exe /nfo "$LogPathLocal\$ComputerName-msinfo32.nfo" /Computer $ComputerName      
    }
    ShowProgress "Exit"
}


function GetGeneralInfoPerHost{
    param(
        $ComputerNames
    )
    ShowProgress "Enter"
    $LogPathLocal = $Script:LogPath
    foreach($ComputerName in $ComputerNames){       
        # Read Current Windows Version from the Registry 
        $WinNTKey              = Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" }
        $WinVer                = $WinNTKey | Select-Object ProductName, InstallationType, ReleaseId, CurrentMajorVersionNumber, CurrentMinorVersionNumber, CurrentBuild, BuildBranch, BuildLab, UBR
        $WinVerGUI             = "$($WinVer.ProductName) - Microsoft Windows $($WinVer.InstallationType) - Version $($WinVer.ReleaseId) (OS Build $($WinVer.CurrentBuild).$($WinVer.UBR)) "
        $VerifierQuery         = Invoke-Command -ComputerName $ComputerName -ScriptBlock { verifier.exe /query } # 
        $VerifierQuerySettings = Invoke-Command -ComputerName $ComputerName -ScriptBlock { verifier.exe /querysettings } # 
        $CrashControlRegKey    = Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-ItemProperty -path "HKLM:System\CurrentControlSet\Control\CrashControl"} # Read Dump Type from Registry        

        <# $DumpType
            "HKLM:System\CurrentControlSet\Control\CrashControl\CrashDumpEnabled"          
            $DumpType: None 0x0, Complete memory dump 0x1, Kernel memory dump 0x2, Small memory dump 0x3, Automatic Memory Dump 0x7, 
            if CrashDumpEnabled is 0x1 and a Key FilterPages shows up and is 0x1, then the UI shows "Active Memory Dump"
            if CrashDumpEnabled is 0x1 and a Key FilterPages does not show up, then the UI shows "Complete Memory Dump"

            Automatic memory dump 0x7 (Default 2012/ 2012R2 and beyond )
            https://blogs.technet.microsoft.com/askcore/2012/09/12/windows-8-and-windows-server-2012-automatic-memory-dump/
        #>        
        if ($CrashControlRegKey.CrashDumpEnabled -eq 0) { $DumpType= "None" }
        if ($CrashControlRegKey.CrashDumpEnabled -eq 2) { $DumpType= "Kernel Memory Dump" }
        if ($CrashControlRegKey.CrashDumpEnabled -eq 3) { $DumpType= "Small Memory Dump" }
        if ($CrashControlRegKey.CrashDumpEnabled -eq 7) { $DumpType= "Automatic Memory Dump" }
        
        if ( ($CrashControlRegKey.CrashDumpEnabled -eq 1) -and  ($Null -eq $CrashControlRegKey.FilterPages) ) { $DumpType= "Complete Memory Dump" } # Complete Memory Dump
        if ( ($CrashControlRegKey.CrashDumpEnabled -eq 1) -and  ($CrashControlRegKey.FilterPages -eq 1)     ) { $DumpType= "Active Memory Dump" }       # Active Memory Dump
        
        $ComputerInfo          = if ($PSVersionTable.PSVersion.Major -ge 5) { 
                                     Invoke-Command -ComputerName $ComputerName -ScriptBlock {  Get-ComputerInfo }
                                }
                                else{ 
                                     "No ComputerInfo as Get-ComputerInfo only works with PS Ver. > 5" 
                                }

        # Get All Firewall Rules
        ShowProgress "Collecting FirewallRules on Host $ComputerName"
        $oFireWallRules= GetFirewallRules -FireWallNameFilter "*" -ComputerName $ComputerName 


        $Process=  Get-Process
        $Service= Get-Service

        # Store typical Commands that can later be used to analyze data in the Exported *.xml file
        $Commands=
        ("
  `$I= Import-CliXml -path 'FullPathToYourXMLFile' e.g. `$I= Import-CliXML -path `"C:\MS_DATA\191113-113833\H16N1-GeneralInfoPerHost.xml`"
  `$I.Hotfix
  `$I.CrashControlRegKey
  `$I.FirewallRules | sort FWDirection | Select-Object FWDirection, FWName, FWDisplayName, PTProtol, PTLocalPort | Out-GridView
        ")

        # Create the custom Object to put all Info together
        $GenInf= [PSCustomObject][ordered]@{  
            HostName=              $ComputerName
            Hotfix=                Get-Hotfix -ComputerName $ComputerName            
            WinVer=                $WinVer
            WinVerGUI=             $WinVerGUI            
            PSVersionTable=        $PSVersionTable    
            VerifierQuery=         $VerifierQuery
            VerifierQuerySettings= $VerifierQuerySettings 
            CrashControlRegKey=    $CrashControlRegKey
            DumpType=              $DumpType             
            ComputerInfo=          $ComputerInfo
            FirewallRules=         $oFireWallRules
            Process=               $Process
            Service=               $Service
            Commands=              $Commands
        }        
        # Export Info from each Node in a Separate File
        ShowProgress "Export General Info: HostName, Hotfix, Winver, ComputerInfo, PSVersionTable from Host: $ComputerName"
        $GenInf | Export-CliXML -Path "$Script:LogPath\$ComputerName-GeneralInfoPerHost.xml"
        ShowProgress "...Finished Gathering GeneralInfoPerHost - stored in $LogPathLocal\$ComputerName-GeneralInfoPerHost.xml"; write-host
                        
    }    
    ShowProgress "Exit"
}

function GetNetInfoPerHost{
# SYNOPSIS: collect network related info on each host
    param(
            $ComputerNames           
    )
    ShowProgress "Enter"
    if ($Script:NetInfo -eq $false) { RETURN } # if the switch $NetInfo is false exit this function and do not collect any Net-data here
    $LogPathLocal = $Script:LogPath   # LogPath e.g. C:\MS_DATA
    foreach($ComputerName in $ComputerNames){          
        
        ShowProgress "...Start gathering network info on Computer:$ComputerName "

        $net = [PSCustomObject][ordered]@{  
            ComputerName =     $ComputerName
            NetIpconfig =      Get-NetIPConfiguration -CimSession $ComputerName
            Ipconfig =         Ipconfig /all
            IpconfigDNS =      Ipconfig /DisplayDNS

            SmbMultichannelConnection = Get-SmbMultichannelConnection -CimSession $ComputerName
            SmbServerConfiguration = Get-SmbServerConfiguration -CimSession $ComputerName
            SmbConnection = Get-SmbConnection -CimSession $ComputerName
            SmbSession = Get-SmbSession -CimSession $ComputerName
            SmbBandWidthLimit = Get-SmbBandWidthLimit -CimSession $ComputerName -ErrorAction SilentlyContinue
            SmbServerNetworkInterface = Get-SmbServerNetworkInterface -CimSession $ComputerName
            SmbMultichannelConstraint = Get-SmbMultichannelConstraint -CimSession $ComputerName
            SmbWitnessClient = Get-SmbWitnessClient -CimSession $ComputerName

            NIC = Get-NetAdapter -CimSession $ComputerName
            NICAdv = Get-NetAdapterAdvancedProperty -CimSession $ComputerName -Name *
            NICBind = Get-NetAdapterBinding -CimSession $ComputerName –Name *
            NICRxTx = Get-NetAdapterChecksumOffload -CimSession $ComputerName -Name *
            NICHW = Get-NetAdapterHardwareInfo -CimSession $ComputerName -Name *
            NICRIpsec = Get-NetAdapterIPsecOffload -CimSession $ComputerName -Name *
            NICLso = Get-NetAdapterLso -CimSession $ComputerName -Name *
            NICQos = Get-NetAdapterQos -CimSession $ComputerName –Name *

            NICREnc = Get-NetAdapterEncapsulatedPacketTaskOffload -CimSession $ComputerName -Name *
            NICRdma = Get-NetAdapterRdma -CimSession $ComputerName –Name *
            NICRsc = Get-NetAdapterRsc -CimSession $ComputerName –Name *
            NICRss = Get-NetAdapterRss -CimSession $ComputerName –Name *
            NICSriov = Get-NetAdapterSriov -CimSession $ComputerName –Name *
            NICVmqQueue = Get-NetAdapterVmqQueue -CimSession $ComputerName –Name *
            NICVmq = Get-NetAdapterVmq -CimSession $ComputerName –Name *
        }
        
        # Export Info from each Node in a Separate File
        $net | Export-CliXML -Path "$LogPathLocal\$ComputerName-NetInfoPerHost.xml"
        ShowProgress "...Finished gathering network Info per computer and stored in $LogPathLocal\$ComputerName-NetInfoPerHost.xml"        
        ShowProgress "Exit"
    }
}    
#endregion ::::: Workerfunctions to Collect Computer specific Data for each host  Eventlogs, OSVersion... ::::::

#region    ::::: Worker Functions to collect Cluster specific Info :::::: 

function IfClusterGetNodeNames{ 
# SYNOPSIS: Test nodes connection and create a list of reachable nodes
    ShowProgress "Enter"
    $ErrorActionPreferenceNow= $ErrorActionPreference
    $ErrorActionPreference= 'Stop'
	$LocalComputerName = $env:COMPUTERNAME
    # Checkout if the cluster service is answering on this node
    try{ 
        # Check if the cluster service is running 
        if ( (Get-Service -Name ClusSvc).Status -eq "Running"  ){
            ShowProgress -Fore Green "Cluster Service is running on this computer: $LocalComputerName"
            $Script:IsClusSvcRunning = $True
        }
        else { # if we are on a cluster, but the cluster service is not running we land here
            $Script:IsClusSvcRunning= $False
            ShowProgress -Fore DarkMagenta "Cluster Service 'clussvc' is not running on this computer " 
            ShowProgress "Exit" # Exit this loop if cluster service is not running
            RETURN $LocalComputerName # Return local ComputerName, if this computer is not running cluster service to gather Logs from this Host
        }
    } 
    
    catch{ # if we are not on a cluster at all we are landing here 
        ShowProgress -Fore DarkMagenta " 'Get-Service -Name ClusSvc' did not answer - looks if we have no Cluster Service on this computer " 
        ShowProgress "Exit"
        RETURN $LocalComputerName # Return local ComputerName, if this computer is not running cluster service to gather Logs from this Host
    }
    # if cluster service did not answer we do not reach the following code 

    # if cluster service answered we reached this code and will Test Network Connections to all Cluster Nodes
    ShowProgress "...Start testing if we can reach the Cluster Nodes over the network"
    $GoodNodeNames = @()  # Cluster Nodes we can reach over the network
    $BadNodeNames =  @()  # Cluster Nodes we can not reach over the network

    $ClusterNodeNames= (Get-ClusterNode).NodeName
    foreach($ClusterNodeName in $ClusterNodeNames){ 
        if (Test-Connection -ComputerName $ClusterNodeName -Count 1 -Quiet){ # test network connection
            $GoodNodeNames += $ClusterNodeName
        }
        else {
            $BadNodeNames += $ClusterNodeName
        }
    }
    $Nodes = [PSCustomObject]@{
        Good = $GoodNodeNames
        Bad =  $BadNodeNames
    }
        
    ShowProgress -Fore Green   "   - Could connect to Cluster Nodes: $($Nodes.Good)"
    if ( '' -ne ($Nodes.Bad) ){ # if we could not connect to all Nodes and have Bad Nodes...
        ShowProgress -Fore Red "   - Could not connect to Cluster Nodes: $($Nodes.Bad)" # ...show bad nodes
    }
    else{
        ShowProgress "   - Could connect to all Cluster Nodes" -ForeColor "green"

    }
    ShowProgress "...Finished testing network connection to Cluster Nodes"
    $ErrorActionPreference= $ErrorActionPreferenceNow
    ShowProgress "Exit"
    Return $Nodes.Good # Return only the Good Nodes we can reach    
}

Function GetClusterLogs{
    param(
        $ClusterName,                     # could be replaced by the Cluster Name as string to run remotely
        $HoursBack=   $Script:HoursBack   # How much Minutes should we look back in the logs - it´s defined in the main chapter
    )
    ShowProgress "Enter"
    If (!($IsClusSvcRunning)){
         ShowProgress "Exit" 
         RETURN # Exit this function
    }
    if ($ClusterName -eq ""){    # if no cluster name was passed
        $ClusterName= (Get-Cluster).Name  # Get local cluster name on this host
    }

    ShowProgress "...Start Gathering Cluster Logs for Cluster Name:$ClusterName"

    # Gather ClusterLogs from All Nodes
    $MinutesBack= $HoursBack * 60
    Get-ClusterLog -Cluster $ClusterName -TimeSpan $MinutesBack -Destination $Script:LogPath -UseLocalTime
    ShowProgress "...Finished Gathering Cluster Logs for Cluster Name:$ClusterName";write-host
    ShowProgress "Exit"
}

Function GetClusterHealthLogs{
    param(
        $ClusterName,                     # could be replaced by the Cluster Name as string to run remotely
        $HoursBack=   $Script:HoursBack   # How much Minutes should we look back in the logs - it´s defined in the main chapter
    )
    ShowProgress "Enter"
    If (!($IsClusSvcRunning)){
         ShowProgress "Exit" 
         RETURN # Exit this function
    }
    if ($ClusterName -eq ""){    # if no cluster name was passed
        $ClusterName= (Get-Cluster).Name  # Get local cluster name on this host
    }

    ShowProgress "...Start Gathering Cluster Health Logs for Cluster Name:$ClusterName"

    # Gather ClusterLogs from All Nodes
    $MinutesBack= $HoursBack * 60
    Get-ClusterLog -Cluster $ClusterName -TimeSpan $MinutesBack -Destination $Script:LogPath -UseLocalTime -Health
    ShowProgress "...Finished Gathering Cluster Health Logs for Cluster Name:$ClusterName";write-host
    ShowProgress "Exit"
}

function GetClusNet{ # Get all Cluster Network Info and add Livmigration Networks + LM Order and put it in one object
    param(
        $ClusterName
    )
    
    ShowProgress "Enter"
    If (!($IsClusSvcRunning)){
         ShowProgress "Clussvc is not running"
         ShowProgress "Exit" 
         RETURN # Exit this function if clussvc is not running
    }
    if ($ClusterName -eq ""){    # if no cluster name was passed
        $ClusterName= (Get-Cluster).Name  # Get local cluster name on this host
    }

    $ResourceTypeVM= Get-ClusterResourceType -Cluster $ClusterName "Virtual Machine" | Get-ClusterParameter
    $ClusterNetworks=  Get-ClusterNetwork -Cluster $ClusterName
    $LiveMigrationExludeNetworks= Get-ClusterResourceType -Cluster $ClusterName "Virtual Machine" | Get-ClusterParameter MigrationExcludeNetworks
    $LiveMigrationNetworkOrder  = (Get-ClusterResourceType -Cluster $ClusterName "Virtual Machine" | Get-ClusterParameter MigrationNetworkOrder).Value.split(";")


    $ClusNet= @()
    foreach($ClusterNetwork in $ClusterNetworks){
        $i=0
        foreach($LMNetOrder in $LiveMigrationNetworkOrder){
            if ($ClusterNetwork.Id -eq $LMNetOrder){
                $LiveMigrationOrder= $i
                BREAK
            }
            else{
                $LiveMigrationOrder= "no LM"
            }
            $i++
        }
        
        foreach($LiveMigrationExludeNetwork in $LiveMigrationExludeNetworks){
            $UsedForLiveMigration= $True
            if ($ClusterNetwork.Id -eq $LiveMigrationExludeNetwork.value){
                $UsedForLiveMigration= $False
            }
                        
            $L= [PSCustomObject][ordered]@{
                Address               = $ClusterNetwork.Address
                AddressMask           = $ClusterNetwork.AddressMask
                AutoMetric            = $ClusterNetwork.AutoMetric
                Cluster               = $ClusterNetwork.Cluster
                Description           = $ClusterNetwork.Description
                Id                    = $ClusterNetwork.Id
                Ipv4Addresses         = $ClusterNetwork.Ipv4Addresses
                Ipv4PrefixLengths     = $ClusterNetwork.Ipv4PrefixLengths
                Ipv6Addresses         = $ClusterNetwork.Ipv6Addresses
                Ipv6PrefixLengths     = $ClusterNetwork.Ipv6PrefixLengths
                Metric                = $ClusterNetwork.Metric
                Name                  = $ClusterNetwork.Name
                Role                  = $ClusterNetwork.Role
                State                 = $ClusterNetwork.State
                IsUsedForLiveMigration= $UsedForLiveMigration
                LiveMigrationOrder  = $LiveMigrationOrder

            }
            $ClusNet+=$L        
        }
    }
    ShowProgress "Exit"
    Return $ClusNet
}

function GetClusterInfo{
    param(
        $ClusterName        
    )
    $LogPathLocal = $Script:LogPath
    ShowProgress "Enter"
    If (!($IsClusSvcRunning)){
         ShowProgress "Exit" 
         RETURN # Exit this function if clussvc is not running
    }
    if ($ClusterName -eq ""){    # if no cluster name was passed
        $ClusterName= (Get-Cluster).Name  # Get local cluster name on this host
    }

    $C= New-Object PSObject -Property @{ # Create your own Object with your properties 
        Name=           $ClusterName
        CSV=            Get-ClusterSharedVolume
        CSVParm=        Get-ClusterSharedVolume | Get-ClusterParameter
        CSVState=       Get-ClusterSharedVolumeState
        Group=          Get-ClusterGroup
        Net=            Get-ClusterNetwork
        NetplusLM=      GetClusNet -ClusterName $ClusterName
        NIC=            Get-ClusterNetworkInterface
        Node=           Get-ClusterNode
        Param=          Get-Cluster -Name $ClusterName | Format-List *
        Quorum=         Get-ClusterQuorum
        Res=            Get-ClusterResource
    }
    # Export Cluster Info 
    $FileName= "$LogPathLocal\$($ClusterName)_ClusterInfo.XML"
    $C | Export-Clixml -Path $FileName
    
    # Create "$LogPathLocal\DependencyReports"
    ShowProgress "...Start creating folder $LogPathLocal\DependencyReports"                
    $LogPathDollar = $LogPathLocal.Replace(":","$")				# e.g. C:\MS-Data --> C$\MS-Data
    $LogPathUNC = "\\$($ComputerName)\$LogPathDollar"		# e.g. \\H16N2\c$\MS-Data        
    CreateFolder -HostName $Env:ComputerName -FolderPath $DebugLogPath\DependencyReports

    # Create Dependency Reports and save to LogPathLocal    
    $ClusterGroups= $C.Group
    ForEach($ClusterGroup in $ClusterGroups){
        Get-ClusterResourceDependencyReport -Group $ClusterGroup -ErrorAction SilentlyContinue | Copy-Item -Destination "$LogPathLocal\DependencyReports"
        Rename-Item -Path "$LogPathLocal\DependencyReports\$($ClusterGroup.Id).htm" -NewName "$ClusterGroup-ClusGroupDependencyRep.htm" -ErrorAction SilentlyContinue
    }
    ShowProgress "...Finished Gathering ClusterInfo - stored in  $FileName "
    ShowProgress "...Finished Gathering DependencyReports - stored in  $LogPathLocal\DependencyReports" ; write-host
    ShowProgress "Exit"
}

# Collect Cluster Hive and other files you need specific to cluster Nodes
function GetClusterHives{
    param(
        $ClusterName        
    )

    ShowProgress "Enter"
    If (!($IsClusSvcRunning)){
         ShowProgress "Exit" 
         RETURN # Exit this function if clussvc is not running
    }
    if ($ClusterName -eq ""){    # if no cluster name was passed
        $ClusterName= (Get-Cluster).Name  # Get local cluster name on this host
    }

    $ClusterNodes= Get-ClusterNode -Cluster $ClusterName
            
    ForEach($ClusterNode in $ClusterNodes){                     # Walk through each ClusterNode 
        $HiveFileUNCPath= $Script:LogPath.Replace(":","$")        # C:\MS-Data --> C$\MS-Data
        $RemotePath= "\\$($ClusterNode.Name)\$HiveFileUNCPath"  # \\H16N2\c$\MS-Data
                
        # Saving the cluster Hive of the current Node
        $TimeStamp= [String](Get-Date -Format 'yyMMdd-hhmmss')          # Create a Timestamp for the Cluster Hive File
        $ClusterHiveFileName    = "$ClusterNode-Cluster-$TimeStamp.Hiv" # let´s add a time stamp to the cluster Hive File Name to make it unique
        $ClusterHiveFileNameFull= "$RemotePath\$ClusterHiveFileName" # e.g. \\H16N2\c$\MS-Data\H16N2-Cluster-180705-103933.Hiv
                
        # Export Cluster Hive on the remote node
        Invoke-Command -ComputerName $ClusterNode.Name -ScriptBlock { Invoke-Expression "REG SAVE 'HKLM\cluster' $Using:ClusterHiveFileNameFull" }

        # Move Cluster Hive later from remote node to local node we run the script from
        ShowProgress "...Finished Gathering ClusterHives - stored in $Script:LogPath "; write-host

        ShowProgress "Exit"
    }
}

function GetClusterValidationInfo{
    param(
        $ClusterName,
        $TestNames= $ClusterValidationTestNames 
    )
    ShowProgress "Enter"
    If (!($IsClusSvcRunning)){ # if the cluster service is not running on this node where the script runs, exit this function
         ShowProgress "Exit" 
         RETURN # Exit this function
    }
    if ($ClusterName -eq ""){    # if no cluster name was passed
        $ClusterName= (Get-Cluster).Name  # Get local cluster name on this host
    }

    # Extension .htm is added automatically 
    Test-Cluster -Cluster $ClusterName -Include $TestNames -ReportName "$LogPathLocal\$ClusterName-Validation-Report" 
    ShowProgress "Exit"
}

function 5120 {
    # SYNOPSIS:  collect data for symptom System Event ID 5120
    ShowProgress "Enter"    
    # to be defined
    ShowProgress "Exit"
}

#endregion    ::::: Worker Functions to collect Cluster specific Info ::::::

#region    ===== MAIN - Preparations    ==================================================
ShowProgress -Fore Green "Script Start..."

# Checkout if we are running with elevated privileges
$RunningAsAdmin= DoIRunAsAdmin
If ($RunningAsAdmin -eq $False){
    ShowProgress -Fore Red         "The script does not run in privileged (admin) mode"
    ShowProgress -Fore DarkMagenta "so we can´t query the cluster service, can´t create a log folder, debuglogfile and so on... "
    ShowProgress -Fore DarkMagenta "Please run again in privileged mode as admin"
    ShowProgress -Fore Red         "Exiting script now !"
    EXIT # Exit the script now as it doesn´t make sense to run this script in non privileged mode
}

ShowProgress -Fore Green "Running functions that should go quickly now ..."

if ($ClusterName -eq ""){    # if no cluster name was passed
    $ClusterName= (Get-Cluster).Name  # Get local cluster name on this host
}

#josefh - needs to be overworked in order to do the check on a remote cluster as well
$ComputerNames = IfClusterGetNodeNames # Check if Cluster Service answers on the current computer; if yes get the node names we can reach over network else return local computername


ShowProgress "...running data collection on ComputerNames: $ComputerNames"
if ($IsClusSvcRunning) { # if script runs on a cluster create the LogFolder $LogPath on all Cluster Nodes
    CreateLogFolderOnHosts -ComputerNames $ComputerNames -LogPath $LogPath 
}	
else { # else if the cluster service is not running create LogFolder $LogPath on local host
    CreateFolder -HostName "$env:ComputerName" -FolderPath $LogPath
}
#endregion ===== MAIN - Preparations    ==================================================

#region    ===== MAIN - Workerfunctions ==================================================
#    Run ::::: Worker Functions to collect general Info ::::::
#
ShowProgress -Fore Green "Running functions that take longer now ..."
GetEventLogs          -ComputerNames $ComputerNames -HoursBack $HoursBack -LogNames $EventLogNames
GetStorageInfoPerHost -ComputerNames $ComputerNames # Storage, Disk, Volume...
GetGeneralInfoPerHost -ComputerNames $ComputerNames # HostName, Hotfix, Winver etc. 
GetNetInfoPerHost     -ComputerNames $ComputerNames # Ipconfig, Smb*, NIC* etc. 
GetMsInfo32nfo        -ComputerNames $ComputerNames
#    End ::::: Worker Functions to collect general Info ::::::


#    Run ::::: Worker Functions to collect Cluster specific Info ::::::
GetClusterLogs       -ClusterName $ClusterName
GetClusterHealthLogs -ClusterName $ClusterName
GetClusterInfo       -ClusterName $ClusterName
GetClusterHives      -ClusterName $ClusterName
#GetClusterValidationInfo -ClusterName $ClusterName # -TestNames look for $ClusterValidationTestNames in parameter section
#GetClusterPerformanceHistory -ClusterName $ClusterName -ComputerNames $ComputerNames
#    End ::::: Worker Functions to collect Cluster specific Info ::::::


#    Administrative Tasks
MoveDataFromAllComputersToLocalComputer  -ComputerNames $ComputerNames
CopyFilesInReportsFoldersToLocalComputer -ComputerNames $ComputerNames # From each node - copy all files in c:\windows\cluster\reports to Local MS_DATA Folder 
#


#    End of Script Messages
$ScriptDuration= ( (Get-Date) - $TimeStampScriptStart ) # Calculate how long the script ran
ShowProgress -Fore Green "Script ran for Min:Sec - $($ScriptDuration.Minutes):$($ScriptDuration.Seconds) "
$DebugLogCount= $DebugLogCountMax # to flush $DebugLogBuffer to the Logfile
ShowProgress -Fore Green "Exit Script - End of Script Logs can be found in: $LogPath"
#
#endregion ===== MAIN - Workerfunctions ==================================================
# SIG # Begin signature block
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBIbvvVQNwa4mFg
# a9BGGLD5DpbH06bPvgJhk9o0MjGwEqCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
# esGEb+srAAAAAANOMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI5WhcNMjQwMzE0MTg0MzI5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDdCKiNI6IBFWuvJUmf6WdOJqZmIwYs5G7AJD5UbcL6tsC+EBPDbr36pFGo1bsU
# p53nRyFYnncoMg8FK0d8jLlw0lgexDDr7gicf2zOBFWqfv/nSLwzJFNP5W03DF/1
# 1oZ12rSFqGlm+O46cRjTDFBpMRCZZGddZlRBjivby0eI1VgTD1TvAdfBYQe82fhm
# WQkYR/lWmAK+vW/1+bO7jHaxXTNCxLIBW07F8PBjUcwFxxyfbe2mHB4h1L4U0Ofa
# +HX/aREQ7SqYZz59sXM2ySOfvYyIjnqSO80NGBaz5DvzIG88J0+BNhOu2jl6Dfcq
# jYQs1H/PMSQIK6E7lXDXSpXzAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnMc7Zn/ukKBsBiWkwdNfsN5pdwAw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMDUxNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAD21v9pHoLdBSNlFAjmk
# mx4XxOZAPsVxxXbDyQv1+kGDe9XpgBnT1lXnx7JDpFMKBwAyIwdInmvhK9pGBa31
# TyeL3p7R2s0L8SABPPRJHAEk4NHpBXxHjm4TKjezAbSqqbgsy10Y7KApy+9UrKa2
# kGmsuASsk95PVm5vem7OmTs42vm0BJUU+JPQLg8Y/sdj3TtSfLYYZAaJwTAIgi7d
# hzn5hatLo7Dhz+4T+MrFd+6LUa2U3zr97QwzDthx+RP9/RZnur4inzSQsG5DCVIM
# pA1l2NWEA3KAca0tI2l6hQNYsaKL1kefdfHCrPxEry8onJjyGGv9YKoLv6AOO7Oh
# JEmbQlz/xksYG2N/JSOJ+QqYpGTEuYFYVWain7He6jgb41JbpOGKDdE/b+V2q/gX
# UgFe2gdwTpCDsvh8SMRoq1/BNXcr7iTAU38Vgr83iVtPYmFhZOVM0ULp/kKTVoir
# IpP2KCxT4OekOctt8grYnhJ16QMjmMv5o53hjNFXOxigkQWYzUO+6w50g0FAeFa8
# 5ugCCB6lXEk21FFB1FdIHpjSQf+LP/W2OV/HfhC3uTPgKbRtXo83TZYEudooyZ/A
# Vu08sibZ3MkGOJORLERNwKm2G7oqdOv4Qj8Z0JrGgMzj46NFKAxkLSpE5oHQYP1H
# tPx1lPfD7iNSbJsP6LiUHXH1MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGXMwghlvAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIETpWrNC7SmMUFIo5/S6U9Zf
# qNIh7D/OJ6r84pwinL9oMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAAkQQ6quIApU4KA4TlxT0xDVXg/LhvzBvlBdVFoM8z0T4uBlyMSuuWs5/
# Ny23Kged1DFs9nQmV5UQOhO8MB6UMDfEqVoR9qBuuL8mHbysl2e6vxox0s/1Dn6A
# fqpmAb7Gd9lfcVbmEGhEhVvntp5kBAXBM5qCjCJcNB04vOiqrzgvZAjvx7OpPkD0
# 3YdEIwL0bAw8yVNz9QkvkkOqwKXWNIviHOVbLtfc4jrMmrBWsoC7Ewh4CeW01Ycz
# xLYvQLxszrtnN57syfr0XX5AKTgPzFgLTSB0eaMY2Fx/Q76045T8D7qBDwJ5q7fi
# pVTI4HJ2oSK6nKln7h3AmG5W1aCJcqGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCC
# FuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCDqczscI1f38gL7uPIGdyyi5l/mGz6YontarzSqVjQ7jwIGZGzYjFFS
# GBMyMDIzMDYwNjExNDU1MC42MDJaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpBRTJDLUUz
# MkItMUFGQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVQwggcMMIIE9KADAgECAhMzAAABv99uuQQVUihYAAEAAAG/MA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEy
# NFoXDTI0MDIwMjE5MDEyNFowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkFFMkMtRTMyQi0xQUZDMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAuExh0n1UxKMzBvkPHer47nryD4UK2GVy1X6bOVC+hLVh
# DlsIWQ1uX/9a8IRI3zXo/y1oTDuj+rJHyX4OZQn42E0iu7x6swPvM34zIOSPn8lg
# nWzGEAsRtz9zBrLW9+4w/YhWlXI8hvc7ovqupuL3TXte8BbmNOUDSL+Ou2bBfObG
# zsH3yY/BELvqwO13KZ9Z1OxKacnqq1u9E9Rhai90STog22lR2MVRSx55FHi/emnZ
# A/IKvsAtEH2K6JmgOyQ7/mDQrWNEA5roUjhQqLQw1/3wz/CIvc9+FPxX2dxR0nvv
# Ye5VLqv8Q99cOkO6z6V4stGDyFDuO8CwtiSvCC3QrOOugAl33aPD9YZswywWRk+Y
# GyLI+Fw+kCCUY6h1qOjTj5glz0esmds3ue45WaI2hI9usForM8gy//5tDZXj0KKU
# 1BxA04xpfEy91RZUbc6pdAvEkpYrN2jlpXhMvTD7pgdYyxkVSaWZv7kWp5y9NjWP
# /CTDGXTC6DWiGcXwPQO66QdVNWxuiGdpfPaEUnWXcKnDVua1khBAxO4m9wg/1qM6
# f7HwXf/pHifMej+qB7SUZOiJScX+1HmffmZRAFiJXS0qUDk0ZAZW3oX2xLyl0044
# eHI7Y95GPaw8OlSTeNiNAKl+MyH5OaifsUuyVHOf4rsrE+ZyAuS9e9ERqu5H/10C
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBRVAolUT3eV3wK/+Luf/wawCPMYpzAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQAjCREvjT6yXwJYdvkFUqTGGh6RizAY+ciuB6UOBUm0yqq5QC+5pCEa9WSMvbUG
# zxDCEFBgD93gWGnkiyYcHCazlgZK+E7WxtI3bP++Fb4RJZiWLo/IC9hX12hCZZwY
# XIGVzC9BVAcNx/zsFqI/9u8u/bhGjDHPad47C4OQNCHrkNqzGYxb4GQq6Psw6o7c
# Ety3MU3Jd4uzBazaFhPRvmBfSn+Ufd6pTNZLgIX9BjrLmZblc/d2LIAurEr5W29W
# fW5RMRIEZzO9TaMr/zzdmW/cV6VdaDTygy5g4O3UXadt1DraUpn5jcD10TVWNnyz
# /paeleHojrGCCksqexpelMkUsiYP0HX9pFUgNglWU10r1wEzFwZM9aX2Rqq3fFRr
# N3gu8tCX+H1nKK2AobW1vmsKLTH6PyX1LkyvRwTj45a1paeHIR8TGzm3+iY7wpC1
# MHuzqAqAdDeaIVdVlch807VJJ4hDive6AiOQCV9MwiUyhf5v4P8jTGof8CqjDb3P
# nLlNSnFm2BFhMZ35oNTEosc37GZHScM83hTN1E481sLYJrrhhcdtcyNB60juMjqG
# UD6uQ/7DbMvtv93tFj5WjxVhMCkkY66EEYgpfFLOCb2ngJJWFuJCIGsCiDfDxGwE
# 4RVYAnoFzoa2OfSqijYg2drdZfpptRRvKxMsAzu3oxkS/TCCB3EwggVZoAMCAQIC
# EzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoX
# DTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC
# 0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VG
# Iwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP
# 2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/P
# XfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361
# VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwB
# Sru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9
# X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269e
# wvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDw
# wvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr
# 9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+e
# FnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAj
# BgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+n
# FV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBH
# hkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
# BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4Swf
# ZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTC
# j/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu
# 2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/
# GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3D
# YXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbO
# xnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqO
# Cb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I
# 6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0
# zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaM
# mdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNT
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLLMIICNAIBATCB+KGB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046QUUyQy1FMzJCLTFBRkMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVADgEd+JNrp4dpvFKMZi91txbfic3oIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoKSLZMCIYDzIwMjMwNjA2MTExMzI5WhgPMjAyMzA2MDcxMTEzMjlaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOgpItkCAQAwBwIBAAICCLkwBwIBAAICEukw
# CgIFAOgqdFkCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQANguezUMlX9LwO
# vxOPv/pKGStGp8S2Zkp+vjqJzYss9kiFJYB0dIdjoWx/N6oqDBFai2LUtwvD1GAh
# +dra07nAzH4MMAz74U639bIEsW2UpYyyPjVuaSmgrJ0o2Ij/wE/jcJPi/TeHH8e8
# FV+d8MTe0A4XzLozJ7f+fmIGk2mw8zGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABv99uuQQVUihYAAEAAAG/MA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIHpz/8NNieQlC87oj2amYIli+5IsWJRsWFyEDvwncjxFMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQg/Q4tRz63EiRj4K+19yNUwogBIOsp44CIuBfn
# ZHCvBa4wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# Ab/fbrkEFVIoWAABAAABvzAiBCDWIYQuWlyAbMEHueiwK9sVxTJz5LM4Y4cVrfNw
# PvOrAjANBgkqhkiG9w0BAQsFAASCAgCRnTHsRm/Vx6DA5P+yvgvz4avhEXgWH4i0
# sWduXuBPdnFhglfaJmJ0TP66rw7WoDGmo/ukOFim3SXDuVM6AODQmoaX3Fy3EbBE
# ycyQ6ifIK6OB+Q2MubkMnpr/WuuVf/lgxfKdZbk5+TW51cEw5di60R6z9LpSMd/J
# /EkACrcU55Nn/v7YclH996javl5R+oQp93msmh4RsGqUN0j6TFoxrqdBzlj11LdE
# 6zmAWylo/Ay53H430bVlxm2EKm8ZYWnBlAmW14rPY4OH5uDn2hb2WnuWJbeZ3aKD
# 5TMNK1bIXj8Zi2OA6ChNsS1oBhRTzOu1YX4yYoNSiF2YOuWKpxrsgNNpvzEK5M6A
# lQ7UHfkBvmzOmiJoF/PbpbMN+LNsc7Pw6i28u0FskAdB9NwsGOrktOXdPaFVdN5n
# BHpsQLhK9myHYu3KCxHoQMJ0uWp7fxW0ifhDzYGz6Dqb5EzxjoMx0KakroPOOg1l
# bDeWShw62gGV20T98VEITZGj+KLr/9u1HCGDN3C6Ev6j0VX/0qZ0txFQyd+JjkYt
# 8cpW8SpbhUez8lP273XGVlHj6BauW//FqawhOdu+yt3XU5fKe1EtYj1KEX6M4WTc
# mz5qW3r8R7NlqMpgSBeDB52ptZzcxoCyQ6touYcDSUMu/Z/RE/UKW3Wn01ueJYoP
# X8Z60xmH0w==
# SIG # End signature block
