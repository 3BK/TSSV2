<#
.SYNOPSIS
   DEV Components and Scenarios module for learning and demoing TSSv2 Framework usage.
   This is NOT related to any specific POD and not designed for learning and troubleshooting.

.DESCRIPTION
   DEV Components and Scenarios module for learning and demoing TSSv2 Framework usage.
   This is NOT related to any specific POD and not designed for learning and troubleshooting.

.NOTES
	Dev. Lead: milanmil
   Authors     : milanmil, waltere
   Requires   : PowerShell V4(Supported from Windows 8.1/Windows Server 2012 R2)
   Version    : see $global:TssVerDateDEV

.LINK
	TSSv2 https://internal.support.services.microsoft.com/en-us/help/4619187
#>

<# latest changes
  2023.01.23.0 [we] _DEV: added function DevTest
  2022.12.07.0 [we] _DEV: add -Scenario DEV_General
  2022.01.05.0 [we] added FW function calls which were previously defined in _NET
  2021.11.10.0 [we] #_# replaced all 'Get-WmiObject' with 'Get-CimInstance' to be compatible with PowerShell v7
#>

$global:TssVerDateDEV= "2023.01.25.0"

#region --- ETW component trace Providers ---
# Normal trace -> data will be collected in a single file
$DEV_TEST1Providers = @(
	'{CC85922F-DB41-11D2-9244-006008269001}' # LSA
	'{6B510852-3583-4E2D-AFFE-A67F9F223438}' # Kerberos
)

# Normal trace with multi etl files
# Syntax is: GUID!filename!flags!level 
# GUID is mandtory
# if filename is not provided TSSv2 will create etl using Providers name, i.e. dev_test2 
# if flags is not provided, TSSv2 defaults to 0xffffffff
# if level is not provided, TSSv2 defaults to 0xff
$DEV_TEST2Providers = @(
	'{98BF1CD3-583E-4926-95EE-A61BF3F46470}!CertCli!0xffffff!0x05'
	'{6A71D062-9AFE-4F35-AD08-52134F85DFB9}!CertificationAuthority!0xff!0x07'
	'{B40AEF77-892A-46F9-9109-438E399BB894}!CertCli!0xfffffe!0x04'
	'{169EC169-5B77-4A3E-9DB6-441799D5CACB}!lsa!0xfffffffe'
	'{5BBB6C18-AA45-49B1-A15F-085F7ED0AA90}!CertificationAuthority!0xC43EFF!0x06'
	'{D0B639E0-E650-4D1D-8F39-1580ADE72784}!lsa!0xffffffff!0x0f'
)

# Single etl + multi flags
$DEV_TEST3Providers = @(
	'{D0B639E0-E650-4D1D-8F39-1580ADE72784}!lsa!0xC43EFF'
	'{169EC169-5B77-4A3E-9DB6-441799D5CACB}!lsa!0xffffff'
)

$DEV_TEST4Providers = @(
	'{D0B639E0-E650-4D1D-8F39-1580ADE72784}!lsa!0xC43EFF'
	'{169EC169-5B77-4A3E-9DB6-441799D5CACB}!lsa!0xffffff'
	'{D0B639E0-E650-4D1D-8F39-1580ADE72784}!lsa!0xffffffff!0x0f'
	'{5BBB6C18-AA45-49B1-A15F-085F7ED0AA90}!CertificationAuthority!0xC43EFF!0x06'
)


#select basic or full tracing option for the same etl guids using different flags
if ($global:CustomParams){
	Switch ($global:CustomParams[0]){
		"full" {$DEV_TEST5Providers = @(
				'{D0B639E0-E650-4D1D-8F39-1580ADE72784}!lsa!0xffffffff'
				'{169EC169-5B77-4A3E-9DB6-441799D5CACB}!lsa!0xffffffff'
				)
		}
		"basic" {$DEV_TEST5Providers = @(
				'{D0B639E0-E650-4D1D-8F39-1580ADE72784}!lsa!0xC43EFF'
				'{169EC169-5B77-4A3E-9DB6-441799D5CACB}!lsa!0xffffff'
				)
		}
		Default {$DEV_TEST5Providers = @(
				'{D0B639E0-E650-4D1D-8F39-1580ADE72784}!lsa!0xC43EFF'
				'{169EC169-5B77-4A3E-9DB6-441799D5CACB}!lsa!0xfffff!0x12'
				)
		}
	}
}
#endregion --- ETW component trace Providers ---

#region --- Scenario definitions ---
 
$DEV_General_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_Dummy' = $true
	'CommonTask NET' = $True  ## <------ the commontask can take one of "Dev", "NET", "ADS", "UEX", "DnD" and "SHA", or "Full" or "Mini"
	'NetshScenario InternetClient_dbg' = $true
	'Procmon' = $true
	#'WPR General' = $true
	'PerfMon ALL' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
}
 
$DEV_ScenarioTraceList = [Ordered]@{
	'DEV_Scn1' = 'DEV scenario trace 1'
	'DEV_Scn2' = 'DEV scenario trace 2'
}

# DEV_Scn1
$DEV_Scn1_ETWTracingSwitchesStatus = [Ordered]@{
	'DEV_TEST1' = $true
	#'DEV_TEST2' = $true   # Multi etl file trace
	#'DEV_TEST3' = $true   # Single trace
	#'DEV_TEST4' = $true 
	#'DEV_TEST5' = $true
	#'Netsh' = $true
	#'Netsh capturetype=both captureMultilayer=yes provider=Microsoft-Windows-PrimaryNetworkIcon provider={1701C7DC-045C-45C0-8CD6-4D42E3BBF387}' = $true
	#'NetshMaxSize 4096' = $true
	#'Procmon' = $true
	#'ProcmonFilter ProcmonConfiguration.pmc' = $True
	#'ProcmonPath C:\tools' = $True
	#'WPR memory' = $true
	#'WPR memory -onoffproblemdescription "test description"' = $true
	#'skippdbgen' = $true
	#'PerfMon smb' = $true
	#'PerfIntervalSec 20' = $true
	#'PerfMonlong general' = $true
	#'PerfLongIntervalMin 40' = $true
	#'NetshScenario InternetClient_dbg' = $true
	#'NetshScenario InternetClient_dbg,dns_wpp' = $true
	#'NetshScenario InternetClient_dbg,dns_wpp capturetype=both captureMultilayer=yes provider=Microsoft-Windows-PrimaryNetworkIcon provider={1701C7DC-045C-45C0-8CD6-4D42E3BBF387}' = $true
	#'PSR' = $true
	#'WFPdiag' = $true
	#'RASdiag' = $true
	#'PktMon' = $true
	#'AddDescription' = $true
	#'SDP rds' = $True
	#'SDP setup,perf' = $True
	#'SkipSDPList noNetadapters,skipBPA' = $True
	#'xray' = $True
	#'Video' = $True
	#'SysMon' = $True
	#'CommonTask Mini' = $True
	#'CommonTask Full' = $True
	#'CommonTask Dev' = $True
	#'noBasicLog' = $True
	#'noPSR' = $True
	#'noVideo' = $True
	#'Mini' = $True
	#'NoSettingList noSDP,noXray,noBasiclog,noVideo,noPSR' = $True
	#'Xperf Pool' = $True
	#'XPerfMaxFile 4096' = $True
	#'XperfTag TcpE+AleE+AfdE+AfdX' = $True
	#'XperfPIDs 100' = $True
	#'LiveKD Both' = $True
	#'WireShark' = $True
	#'TTD notepad.exe' = $True   # Single process [<processname.exe>|<PID>]
	#'TTD notepad.exe,cmd.exe' = $True   # Multiple processes
	#'TTD tokenbroker' = $True   # Service name
	#'TTD Microsoft.Windows.Photos' = $True  # AppX
	#"TTDPath $env:userprofile\Desktop\PartnerTTDRecorder_x86_x64\amd64\TTD" = $True	# for downlevel OS TTD will find Partner tttracer in \Bin** folder
	#'TTDMode Ring' = $True   # choose [Full|Ring|onLaunch]
	#'TTDMaxFile 2048' = $True
	#'TTDOptions XXX' = $True
	#'CollectComponentLog' = $True
	#'Discard' = $True
	#'ProcDump notepad.exe,mspaint.exe,tokenbroker' = $true
	#'ProcDumpOption Both' = $true
	#'ProcDumpInterval 3:10' = $True
	#'GPResult Both' = $True
	#'PoolMon Both' = $True
	#'Handle Both' = $True
}

# DEV_Scn2
Switch (global:FwGetProductTypeFromReg)
{
	"WinNT" {
		$DEV_Scn2_ETWTracingSwitchesStatus = [Ordered]@{
			'DEV_TEST1' = $true
			'DEV_TEST2' = $true  # Multi etl file trace
			'DEV_TEST3' = $true
			'DEV_TEST4' = $true   # Single trace
			'DEV_TEST5' = $False  # Disabled trace
			'UEX_Task' = $True	 # Outside of this module
		}
	}
	"ServerNT" {
		$DEV_Scn2_ETWTracingSwitchesStatus = [Ordered]@{
			'DEV_TEST1' = $true
			'DEV_TEST2' = $true
		}
	}
	"LanmanNT" {
		$DEV_Scn2_ETWTracingSwitchesStatus = [Ordered]@{
			'DEV_TEST1' = $true
			'DEV_TEST2' = $true
		}
	}
	Default {
		$DEV_Scn2_ETWTracingSwitchesStatus = [Ordered]@{
			'DEV_TEST1' = $true
			'DEV_TEST2' = $true
		}
	}
}

# Dev_Scn3 => Multi etl only
$DEV_Scn3_ETWTracingSwitchesStatus = [Ordered]@{
	'DEV_TEST2' = $true   # Multi etl file trace
}
#endregion --- Scenario definitions ---


#region Functions

#region Components Functions
#region -------------- DevTest -----------
# IMPORTANT: this trace should be used only for development and testing purposes

function DevTestPreStart
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"
	global:FwCollect_BasicLog

	#### Various EVENT LOG  actions ***
	# A simple way for exporting EventLogs in .evtx and .txt format is done by function FwAddEvtLog ($EvtLogsLAPS array is defined at bottom of this file)
	# Ex: ($EvtLogsLAPS) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	
	#Event Log - Set Log - Enable
	$EventLogSetLogListOn = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogSetLogListOn = @(  #LogName, enabled, retention, quiet, MaxSize
		@("Microsoft-Windows-CAPI2/Operational", "true", "false", "true", "102400000"),
		@("Microsoft-Windows-Kerberos/Operational", "true", "", "", "")
	)
	ForEach ($EventLog in $EventLogSetLogListOn)
	{
	 global:FwEventLogsSet $EventLog[0] $EventLog[1] $EventLog[2] $EventLog[3] $EventLog[4]
	}

	#Event Log - Export Log
	$EventLogExportLogList = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogExportLogList = @(  #LogName, filename, overwrite
		@("Microsoft-Windows-CAPI2/Operational", "c:\dev\Capi2_Oper.evtx", "true"),
		@("Microsoft-Windows-Kerberos/Operational", "c:\dev\Kerberos_Oper.evtx", "true")
	)
	ForEach ($EventLog in $EventLogExportLogList)
	{
	 global:FwExportSingleEventLog $EventLog[0] $EventLog[1] $EventLog[2] 
	}
	#Event Log - Set Log - Disable
	$EventLogSetLogListOff = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogSetLogListOff = @(  #LogName, enabled, retention, quiet, MaxSize
		@("Microsoft-Windows-CAPI2/Operational", "false", "", "", ""),
		@("Microsoft-Windows-Kerberos/Operational", "false", "", "", "")
	)
	ForEach ($EventLog in $EventLogSetLogListOff)
	{
	 global:FwEventLogsSet $EventLog[0] $EventLog[1] $EventLog[2] $EventLog[3] $EventLog[4]
	}

	#Event Log - Clear Log
	$EventLogClearLogList = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogClearLogList = @(  #LogName, enabled, retention, quiet, MaxSize
		@("Microsoft-Windows-CAPI2/Operational"),
		@("Microsoft-Windows-Kerberos/Operational")
	)
	ForEach ($EventLog in $EventLogClearLogList)
	{
		global:FwEventLogClear $EventLog[0] 
	}


	#### Various REGISTRY manipulaiton functions ***
	# A simple way for exporting Regisgtry keys is done by function FwAddRegItem with a registry array defined at bottom of this file ($global:KeysWinLAPS)
	# Ex.: FwAddRegItem @("WinLAPS") _Stop_
	
	# RegAddValues
	$RegAddValues = New-Object 'System.Collections.Generic.List[Object]'

	$RegAddValues = @(  #RegKey, RegValue, Type, Data
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key", "my test1", "REG_DWORD", "0x1"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key", "my test2", "REG_DWORD", "0x2")
	)

	ForEach ($regadd in $RegAddValues)
	{
		global:FwAddRegValue $regadd[0] $regadd[1] $regadd[2] $regadd[3]
	}

	# RegExport in TXT
	LogInfo "[$global:TssPhase ADS Stage:] Exporting Reg.keys .. " "gray"
	$RegExportKeyInTxt = New-Object 'System.Collections.Generic.List[Object]'
	$RegExportKeyInTxt = @(  #Key, ExportFile, Format (TXT or REG)
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key", "C:\Dev\regtestexportTXT1.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL", "C:\Dev\regtestexportTXT2.txt", "TXT")
	)
 
	ForEach ($regtxtexport in $RegExportKeyInTxt)
	{
		global:FwExportRegKey $regtxtexport[0] $regtxtexport[1] $regtxtexport[2]
	}

	# RegExport in REG
	$RegExportKeyInReg = New-Object 'System.Collections.Generic.List[Object]'
	$RegExportKeyInReg = @(  #Key, ExportFile, Format (TXT or REG)
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key", "C:\Dev\regtestexportREG1.reg", "REG"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL", "C:\Dev\regtestexportREG2.reg", "REG")
	)
	ForEach ($regregexport in $RegExportKeyInReg)
	{
		global:FwExportRegKey $regregexport[0] $regregexport[1] $regregexport[2]
	}

	# RegDeleteValues
	$RegDeleteValues = New-Object 'System.Collections.Generic.List[Object]'
	$RegDeleteValues = @(  #RegKey, RegValue
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key", "my test1"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key", "my test2")
	)
	ForEach ($regdel in $RegDeleteValues)
	{
		global:FwDeleteRegValue $regdel[0] $regdel[1] 
	}
 

	#### FILE COPY Operations ***
	# Create Dest. Folder
	FwCreateFolder $global:LogFolder\Files_test2
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(  #source (* wildcard is supported) and destination
		@("C:\Dev\my folder\test*", "$global:LogFolder\Files_test2"), 		#this will copy all files that match * criteria into dest folder
		@("C:\Dev\my folder\test1.txt", "$global:LogFolder\Files_test2") 	#this will copy test1.txt to destination file name and add logprefix
	)
	global:FwCopyFiles $SourceDestinationPaths
	EndFunc $MyInvocation.MyCommand.Name
}

function DevTestPostStop
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"
	EndFunc $MyInvocation.MyCommand.Name
}
#endregion -------------- DevTest -----------

### Pre-Start / Post-Stop / Collect / Diag function for Components tracing

##### Pre-Start / Post-Stop function for trace
function DEV_TEST1PreStart
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	# Testing FwSetEventLog
	#FwSetEventLog "Microsoft-Windows-CAPI2/Operational" -EvtxLogSize:100000 -ClearLog
	#FwSetEventLog 'Microsoft-Windows-CAPI2/Catalog Database Debug' -EvtxLogSize:102400000
	#$PowerShellEvtLogs = @("Microsoft-Windows-PowerShell/Admin", "Microsoft-Windows-PowerShell/Operational")
	#FwSetEventLog $PowerShellEvtLogs
	EndFunc $MyInvocation.MyCommand.Name
}
function DEV_TEST1PostStart
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	EndFunc $MyInvocation.MyCommand.Name
}
function DEV_TEST1PreStop
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	#LogWarn "** Will do Forced Crash now" cyan
	#FwDoCrash
	EndFunc $MyInvocation.MyCommand.Name
}

function DEV_TEST1PostStop
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	# Testing FwResetEventLog
	#FwResetEventLog 'Microsoft-Windows-CAPI2/Operational'
	#FWResetEventLog 'Microsoft-Windows-CAPI2/Catalog Database Debug'
	#$PowerShellEvtLogs = @("Microsoft-Windows-PowerShell/Admin", "Microsoft-Windows-PowerShell/Operational")
	#FwResetEventLog $PowerShellEvtLogs
	EndFunc $MyInvocation.MyCommand.Name
}


function DEV_TEST2PreStart
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	EndFunc $MyInvocation.MyCommand.Name
}

function DEV_TEST2PostStop
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	EndFunc $MyInvocation.MyCommand.Name
}

##### Data Collection
function CollectDEV_TEST1Log
{
	EnterFunc $MyInvocation.MyCommand.Name

	$LogPrefix = "Dev_TEST1"
	$LogFolderforDEV_TEST1 = "$Logfolder\Dev_TEST1"
	FwCreateLogFolder $LogFolderforDEV_TEST1

	<#
	<#--- Log functions ---#>
	#LogDebug "This is message from LogDebug."
	#LogInfo "This is message from LogInfo."
	#LogWarn "This is message from LogWarn."
	#LogError "This is message from LogError."
	#Try{
	#	Throw "Test exception"
	#}Catch{
	#	LogException "This is message from LogException" $_
	#}
	#LogInfoFile "This is message from LogInfoFile."
	#LogWarnFile "This is message from LogWarnFile."
	#LogErrorFile "This is message from LogErrorFile."

	<#--- Test ExportEventLog and FwExportEventLogWithTXTFormat ---#>
	#FwExportEventLog 'System' $LogFolderforDEV_TEST1
	#ExportEventLog "Microsoft-Windows-DNS-Client/Operational" $LogFolderforDEV_TEST1
	#FwExportEventLogWithTXTFormat 'System' $LogFolderforDEV_TEST1

	<#--- FwSetEventLog and FwResetEventLog ---#>
	#$EventLogs = @(
	#	'Microsoft-Windows-WMI-Activity/Trace'
	#	'Microsoft-Windows-WMI-Activity/Debug'
	#)
	#FwSetEventLog $EventLogs
	#Start-Sleep 20
	#FwResetEventLog $EventLogs

	<#--- FwAddEvtLog and FwGetEvtLogList ---#>  
	#($EvtLogsBluetooth) | ForEach-Object { FwAddEvtLog $_ _Stop_}	# see #region groups of Eventlogs for FwAddEvtLog
	#_# Note: FwGetEvtLogList should be called in _Start_Common_Tasks and _Start_Common_Tasks POD functions, otherwise it is called in FW FwCollect_BasicLog/FwCollect_MiniBasicLog functions
		
	<#--- FwAddRegItem and FwGetRegList ---#>
	#FwAddRegItem @("SNMP", "Tcp") _Stop_	# see #region Registry Key modules for FwAddRegItem
	#_# Note: FwGetRegList should be called in _Start_Common_Tasks and _Start_Common_Tasks POD functions, otherwise it is called in FW FwCollect_BasicLog/FwCollect_MiniBasicLog functions

	<#--- Test RunCommands --#>
	#$outFile = "$LogFolderforDEV_TEST1\netinfo.txt"
	#$Commands = @(
	#	"IPCONFIG /ALL | Out-File -Append $outFile"
	#	"netsh interface IP show config | Out-File -Append $outFile"
	#)
	#RunCommands "$LogPrefix" $Commands -ThrowException:$False -ShowMessage:$True

	<#--- FwCopyFiles ---#>
	# Case 1: Copy a single set of files
	#$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	#$SourceDestinationPaths.add(@("C:\Temp\*", "$LogFolderforDEV_TEST1"))
	#FwCopyFiles $SourceDestinationPaths

	# Case 2: Copy a single file
	#$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	#$SourceDestinationPaths.add(@("C:\temp\test-case2.txt", "$LogFolderforDEV_TEST1"))
	#FwCopyFiles $SourceDestinationPaths

	# Case 3: Copy multi sets of files
	#$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	#$SourceDestinationPaths = @(
	#	@("C:\temp\*", "$LogFolderforDEV_TEST1"),
	#	@("C:\temp2\test-case3.txt", "$LogFolderforDEV_TEST1")
	#)
	#FwCopyFiles $SourceDestinationPaths

	<#--- FwExportRegistry and FwExportRegToOneFile ---#>
	#LogInfo '[$LogPrefix] testing FwExportRegistry().'
	#$RecoveryKeys = @(
	#	('HKLM:System\CurrentControlSet\Control\CrashControl', "$LogFolderforDEV_TEST1\Basic_Registry_CrashControl.txt"),
	#	('HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management', "$LogFolderforDEV_TEST1\Basic_Registry_MemoryManagement.txt"),
	#	('HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug', "$LogFolderforDEV_TEST1\Basic_Registry_AeDebug.txt"),
	#	('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Option', "$LogFolderforDEV_TEST1\Basic_Registry_ImageFileExecutionOption.txt"),
	#	('HKLM:System\CurrentControlSet\Control\Session Manager\Power', "$LogFolderforDEV_TEST1\Basic_Registry_Power.txt")
	#)
	#FwExportRegistry $LogPrefix $RecoveryKeys
	#
	#$StartupKeys = @(
	#	"HKCU:Software\Microsoft\Windows\CurrentVersion\Run",
	#	"HKCU:Software\Microsoft\Windows\CurrentVersion\Runonce",
	#	"HKCU:Software\Microsoft\Windows\CurrentVersion\RunonceEx"
	#)
	#FwExportRegToOneFile $LogPrefix $StartupKeys "$LogFolderforDEV_TEST1\Basic_Registry_RunOnce_reg.txt"

	<#---FwCaptureUserDump ---#>
	# Service
	#FwCaptureUserDump -Name "Winmgmt" -DumpFolder $LogFolderforDEV_TEST1 -IsService:$True
	# Process
	#FwCaptureUserDump -Name "notepad" -DumpFolder $LogFolderforDEV_TEST1
	# PID
	#FwCaptureUserDump -ProcPID 4524 -DumpFolder $LogFolderforDEV_TEST1
	
	<#---general collect functions - often used in _Start/Stop_common_tasks---#>
	#FwClearCaches _Start_ 
	#FwCopyWindirTracing IPhlpSvc 
	#FwDoCrash 
	#FwGetCertsInfo _Stop_ Basic
	#FwGetEnv 
	#FwGetGPresultAS 
	#FwGetKlist 
	#FwGetMsInfo32 
	#FwGetNltestDomInfo 
	#FwGetPoolmon 
	#FwGetProxyInfo 
	#FwGetQwinsta 
	#FwGetRegHives 
	#FwRestartInOwnSvc WebClient
	#FwGetSVC 
	#FwGetSVCactive 
	#FwGetSysInfo 
	#FwGetTaskList 
	#FwGetWhoAmI
	#FwTest-TCPport -ComputerName "cesdiagtools.blob.core.windows.net" -Port 80 -Timeout 900
	
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectDEV_TEST2Log
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "$($MyInvocation.MyCommand.Name) is called."
	EndFunc $MyInvocation.MyCommand.Name
}

##### Diag function
function RunDEV_TEST1Diag
{
	EnterFunc $MyInvocation.MyCommand.Name
	If($global:BoundParameters.containskey('InputlogPath')){
		$diagpath = $global:BoundParameters['InputlogPath']
		LogInfo "diagpath = $diagpath"
	}
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	EndFunc $MyInvocation.MyCommand.Name
}
<#
function RunDEV_TEST2Diag
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	EndFunc $MyInvocation.MyCommand.Name
}
#>
#endregion Components Functions

#region Scenario Functions

### Pre-Start / Post-Stop / Collect / Diag function for scenario tracing
##### Common tasks
function DEV_Start_Common_Tasks{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "$($MyInvocation.MyCommand.Name) is called."
	#FwGetRegList _Start_
	#FwGetEvtLogList _Start_
	EndFunc $MyInvocation.MyCommand.Name
}

function DEV_Stop_Common_Tasks{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "$($MyInvocation.MyCommand.Name) is called."
	#FwGetRegList _Stop_
	#FwGetEvtLogList _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

##### DEV_Scn1
function DEV_Scn1ScenarioPreStart
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	EndFunc $MyInvocation.MyCommand.Name
}
function DEV_Scn1ScenarioPostStart
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	EndFunc $MyInvocation.MyCommand.Name
}
function DEV_Scn1ScenarioPreStop
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	EndFunc $MyInvocation.MyCommand.Name
}
function DEV_Scn1ScenarioPostStop
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectDEV_Scn1ScenarioLog
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	EndFunc $MyInvocation.MyCommand.Name
}
function RunDEV_Scn1ScenarioDiag
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	EndFunc $MyInvocation.MyCommand.Name
}

##### DEV_Scn2
function DEV_Scn2ScenarioPreStart
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	EndFunc $MyInvocation.MyCommand.Name
}
function DEV_Scn2ScenarioPostStop
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectDEV_Scn2ScenarioLog
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	EndFunc $MyInvocation.MyCommand.Name
}
<#
function RunDEV_Scn2ScenarioDiag
{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	EndFunc $MyInvocation.MyCommand.Name
}
#>
#endregion Scenario Functions

#endregion Functions

#region Registry Key modules for FwAddRegItem
	$global:KeysSNMP = @("HKLM:System\CurrentControlSet\Services\SNMP", "HKLM:System\CurrentControlSet\Services\SNMPTRAP")
	$global:KeysTcp = @("HKLM:System\CurrentControlSet\Services\TcpIp\Parameters", "HKLM:System\CurrentControlSet\Services\Tcpip6\Parameters", "HKLM:System\CurrentControlSet\Services\tcpipreg", "HKLM:System\CurrentControlSet\Services\iphlpsvc")
	$global:KeysWinLAPS = @(
		"HKLM:Software\Microsoft\Policies\LAPS"
		"HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\LAPS"
		"HKLM:Software\Policies\Microsoft Services\AdmPwd"
		"HKLM:Software\Microsoft\Windows\CurrentVersion\LAPS\Config"
		"HKLM:Software\Microsoft\Windows\CurrentVersion\LAPS\State"
		"HKLM:Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}"
	)
	<# Example:
	$global:KeysHyperV = @("HKLM:Software\Microsoft\Windows NT\CurrentVersion\Virtualization", "HKLM:System\CurrentControlSet\Services\vmsmp\Parameters")
	#>
#endregion Registry Key modules

#region groups of Eventlogs for FwAddEvtLog
	$EvtLogsBluetooth 	= @("Microsoft-Windows-Bluetooth-BthLEPrepairing/Operational", "Microsoft-Windows-Bluetooth-MTPEnum/Operational")
#	$EvtLogsLAPS		= @("Microsoft-Windows-LAPS-Operational", "Microsoft-Windows-LAPS/Operational")
	<# Example:
	$global:EvtLogsEFS		= @("Microsoft-Windows-NTFS/Operational", "Microsoft-Windows-NTFS/WHC")
	#>
#endregion groups of Eventlogs

Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *



# SIG # Begin signature block
# MIInpQYJKoZIhvcNAQcCoIInljCCJ5ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDrr6Zz6DTKlJ0j
# aB4et8vfc0O8CLgpwBg6rU3KNG0fe6CCDYUwggYDMIID66ADAgECAhMzAAADTU6R
# phoosHiPAAAAAANNMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI4WhcNMjQwMzE0MTg0MzI4WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDUKPcKGVa6cboGQU03ONbUKyl4WpH6Q2Xo9cP3RhXTOa6C6THltd2RfnjlUQG+
# Mwoy93iGmGKEMF/jyO2XdiwMP427j90C/PMY/d5vY31sx+udtbif7GCJ7jJ1vLzd
# j28zV4r0FGG6yEv+tUNelTIsFmmSb0FUiJtU4r5sfCThvg8dI/F9Hh6xMZoVti+k
# bVla+hlG8bf4s00VTw4uAZhjGTFCYFRytKJ3/mteg2qnwvHDOgV7QSdV5dWdd0+x
# zcuG0qgd3oCCAjH8ZmjmowkHUe4dUmbcZfXsgWlOfc6DG7JS+DeJak1DvabamYqH
# g1AUeZ0+skpkwrKwXTFwBRltAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUId2Img2Sp05U6XI04jli2KohL+8w
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzUwMDUxNzAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# ACMET8WuzLrDwexuTUZe9v2xrW8WGUPRQVmyJ1b/BzKYBZ5aU4Qvh5LzZe9jOExD
# YUlKb/Y73lqIIfUcEO/6W3b+7t1P9m9M1xPrZv5cfnSCguooPDq4rQe/iCdNDwHT
# 6XYW6yetxTJMOo4tUDbSS0YiZr7Mab2wkjgNFa0jRFheS9daTS1oJ/z5bNlGinxq
# 2v8azSP/GcH/t8eTrHQfcax3WbPELoGHIbryrSUaOCphsnCNUqUN5FbEMlat5MuY
# 94rGMJnq1IEd6S8ngK6C8E9SWpGEO3NDa0NlAViorpGfI0NYIbdynyOB846aWAjN
# fgThIcdzdWFvAl/6ktWXLETn8u/lYQyWGmul3yz+w06puIPD9p4KPiWBkCesKDHv
# XLrT3BbLZ8dKqSOV8DtzLFAfc9qAsNiG8EoathluJBsbyFbpebadKlErFidAX8KE
# usk8htHqiSkNxydamL/tKfx3V/vDAoQE59ysv4r3pE+zdyfMairvkFNNw7cPn1kH
# Gcww9dFSY2QwAxhMzmoM0G+M+YvBnBu5wjfxNrMRilRbxM6Cj9hKFh0YTwba6M7z
# ntHHpX3d+nabjFm/TnMRROOgIXJzYbzKKaO2g1kWeyG2QtvIR147zlrbQD4X10Ab
# rRg9CpwW7xYxywezj+iNAc+QmFzR94dzJkEPUSCJPsTFMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGXYwghlyAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAANNTpGmGiiweI8AAAAA
# A00wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEICOg
# LVJgY4v9cL1uAK+883fVDP4lixvExZyf+SzPpO4mMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAc9+rp9pzuYJEWA5iXv++elNS/wso++2SlCCN
# cRGUn7mlh3AEqvahz9P5OgNyNnF4zV6UQmgjiW/L3ufLYxfiPGYzO3mACN5lxLQO
# +lnwj7kaYCIJm1TK2l2fENrUNR2E+4Z5P79qyzLE79kfvxIZnsZv2vfXjQga32ej
# XZptaufYxjSR9Lf9bAMVuXnNe4oMuLpFGCL0ZXZMbX7lTq16WMImTQRJlTfbl8sw
# x7PY3LJSK3rf2BDgD9FhpEhqsgb+zjlJGkHRO5YA+ORT6EiAd76lQGT8H23JAmd3
# x1pEXGX+Azg4HOwuRovDVKcdL1SONCbO20u6yZRZeQj9bgpQ9KGCFwAwghb8Bgor
# BgEEAYI3AwMBMYIW7DCCFugGCSqGSIb3DQEHAqCCFtkwghbVAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCCtGIkRcCle/OZC/pwQ6AtXhZy0W6locwoK
# Z70gM/aCkgIGZGzCbC/VGBMyMDIzMDYwNjExNDQxNS44NjhaMASAAgH0oIHQpIHN
# MIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjpERDhDLUUzMzctMkZBRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEVcwggcMMIIE9KADAgECAhMzAAABxQPNzSGh9O85AAEA
# AAHFMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMTEwNDE5MDEzMloXDTI0MDIwMjE5MDEzMlowgcoxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkREOEMtRTMz
# Ny0yRkFFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAq0hds70eX23J7pappaKXRhz+
# TT7JJ3OvVf3+N8fNpxRs5jY4hEv3BV/w5EWXbZdO4m3xj01lTI/xDkq+ytjuiPe8
# xGXsZxDntv7L1EzMd5jISqJ+eYu8kgV056mqs8dBo55xZPPPcxf5u19zn04aMQF5
# PXV/C4ZLSjFa9IFNcribdOm3lGW1rQRFa2jUsup6gv634q5UwH09WGGu0z89Rbtb
# yM55vmBgWV8ed6bZCZrcoYIjML8FRTvGlznqm6HtwZdXMwKHT3a/kLUSPiGAsrIg
# Ezz7NpBpeOsgs9TrwyWTZBNbBwyIACmQ34j+uR4et2hZk+NH49KhEJyYD2+dOIaD
# GB2EUNFSYcy1MkgtZt1eRqBB0m+YPYz7HjocPykKYNQZ7Tv+zglOffCiax1jOb0u
# 6IYC5X1Jr8AwTcsaDyu3qAhx8cFQN9DDgiVZw+URFZ8oyoDk6sIV1nx5zZLy+hNt
# akePX9S7Y8n1qWfAjoXPE6K0/dbTw87EOJL/BlJGcKoFTytr0zPg/MNJSb6f2a/w
# DkXoGCGWJiQrGTxjOP+R96/nIIG05eE1Lpky2FOdYMPB4DhW7tBdZautepTTuShm
# gn+GKER8AoA1gSSk1EC5ZX4cppVngJpblMBu8r/tChfHVdXviY6hDShHwQCmZqZe
# bgSYHnHl4urE+4K6ZC8CAwEAAaOCATYwggEyMB0GA1UdDgQWBBRU6rs4v1mxNYG/
# rtpLwrVwek0FazAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
# KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4ICAQCMqN58frMHOScciK+Cdnr6dK8fTsgQDeZ9bvQjCuxN
# IJZJ92+xpeKRCf3Xq47qdRykkKUnZC6dHhLwt1fhwyiy/LfdVQ9yf1hYZ/RpTS+z
# 0hnaoK+P/IDAiUNm32NXLhDBu0P4Sb/uCV4jOuNUcmJhppBQgQVhFx/57JYk1LCd
# jIee//GrcfbkQtiYob9Oa93DSjbsD1jqaicEnkclUN/mEm9ZsnCnA1+/OQDp/8Q4
# cPfH94LM4J6X0NtNBeVywvWH0wuMaOJzHgDLCeJUkFE9HE8sBDVedmj6zPJAI+7o
# zLjYqw7i4RFbiStfWZSGjwt+lLJQZRWUCcT3aHYvTo1YWDZskohWg77w9fF2QbiO
# 9DfnqoZ7QozHi7RiPpbjgkJMAhrhpeTf/at2e9+HYkKObUmgPArH1Wjivwm1d7PY
# WsarL7u5qZuk36Gb1mETS1oA2XX3+C3rgtzRohP89qZVf79lVvjmg34NtICK/pMk
# 99SButghtipFSMQdbXUnS2oeLt9cKuv1MJu+gJ83qXTNkQ2QqhxtNRvbE9QqmqJQ
# w5VW/4SZze1pPXxyOTO5yDq+iRIUubqeQzmUcCkiyNuCLHWh8OLCI5mIOC1iLtVD
# f2lw9eWropwu5SDJtT/ZwqIU1qb2U+NjkNcj1hbODBRELaTTWd91RJiUI9ncJkGg
# /jCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQEL
# BQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNV
# BAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4X
# DTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM
# 57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm
# 95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzB
# RMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBb
# fowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCO
# Mcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYw
# XE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW
# /aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/w
# EPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPK
# Z6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2
# BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfH
# CBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYB
# BAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8v
# BO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYM
# KwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEF
# BQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBW
# BgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUH
# AQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# L2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsF
# AAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518Jx
# Nj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+
# iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2
# pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefw
# C2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7
# T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFO
# Ry3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhL
# mm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3L
# wUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5
# m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE
# 0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLOMIICNwIB
# ATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UE
# CxMdVGhhbGVzIFRTUyBFU046REQ4Qy1FMzM3LTJGQUUxJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVACEAGvYXZJK7
# cUo62+LvEYQEx7/noIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwDQYJKoZIhvcNAQEFBQACBQDoKQwjMCIYDzIwMjMwNjA2MDkzNjM1WhgPMjAy
# MzA2MDcwOTM2MzVaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOgpDCMCAQAwCgIB
# AAICC3ECAf8wBwIBAAICE+gwCgIFAOgqXaMCAQAwNgYKKwYBBAGEWQoEAjEoMCYw
# DAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0B
# AQUFAAOBgQDn/AVkinnxoW7oiA6JaC2aH8bU3EddsOkS5TGsob5xe6RIod8OpI8a
# 54rjAfuQhf1qET2KD8WWMLsMShcG8nbA0FcbGWIxShkZXeyzLAnna1i19M5dQVkj
# cXOqMKlDzAVCgDtwKKiyEjHbDPf7aPLNz0n1FfmEDmGOjZ5BhCG3ZzGCBA0wggQJ
# AgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABxQPNzSGh
# 9O85AAEAAAHFMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZI
# hvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIGRP73NgFk+rG0zkGDYtCywmOu9fek19
# aapzUqObJE5wMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgGQGxkfYkd0wK
# +V09wO0sO+sm8gAMyj5EuKPqvNQ/fLEwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMAITMwAAAcUDzc0hofTvOQABAAABxTAiBCAUBiLXb89pWwpW
# fiLt7KCdsFZonG2R84rYVWZMvQb62DANBgkqhkiG9w0BAQsFAASCAgBjl1mqCpqY
# 591EuxDB8FqLHqTce1G5XUBLn7pmtXR3I7YT60UtJC0a5GqHlEijxFbnjnyIlcru
# RTlCS7RS56nRd85N5W0pqyhijVmrr54RsPJHfYeyyU0IdfPLm8oJm2E2WYZSiXsl
# YpkXY25V8EWReIFl/HyVVChn/NBmGO71TRvsnmbI9sjr/1wU/UYCmtxpD9okaAej
# rHT7fpzmrLyZSbTbKjTAhgCErqKHLD8xpraNGaRFCxbcrI1ZzjFfmu978m2syRaK
# iTPGJRmKhZY0FZoh+//OnczVONOrmEl+w8z5O/0mEYOsN6G3UwZWcb+udbe+xdf7
# ejR/9FIaZcza8EIgt7vsvHjzfjOxZnaBUb5bvUMfxoa7OvzVixAnwVCIGkV8zvUJ
# VpzmaHGIcHRgyEsGk3/4YcGUehJhapdbQEDWy8a5L3jEqjX/8zGSZKk2cozTGbMI
# q0y1+OVwP5RUGQmQTNv7d+I2cjjUZjKD53c0ETt/4+kN2qJM3qj49CoBYnd+/ytU
# JHafEYknPEV+Tzq+Fa71hIaJVO+N2KlWkWa96KEuJUlS88rUMMX7LSeVGN61eFQs
# pq6eVUwuzrc+VWDv8zajmLpAPRp3bFfWIQsQYkqb2BdvpfY+sgc9tBOya6GOFwmO
# Cm+d9SEsp30wSqzOSDaqglLlivlut7n0hg==
# SIG # End signature block
