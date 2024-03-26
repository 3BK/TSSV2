<# # File: TSSv2_SEC.psm1

.SYNOPSIS
   SEC module for collecting ETW traces and various custom tracing functionality

.DESCRIPTION
   Define ETW traces for Windows SEC components 
   Add any custom tracing functinaliy for tracing SEC components
   For Developers:
   1. Switch test: 		.\TSSv2.ps1 -Start -SEC_TEST1
   2. Scenario test: 	.\TSSv2.ps1 -start -Scenario SEC_MyScenarioTest
   3. CollectLog test: 	.\TSSv2.ps1 -CollectLog SEC_DefenderGet -DefenderDurInMin 2

.NOTES
	Dev. Lead: ?
   Authors    : WalterE 
   Requires   : PowerShell V4 (Supported from Windows 8.1/Windows Server 2012 R2)
   Version    : see $global:TssVerDateSEC

.LINK
	TSSv2 https://internal.support.services.microsoft.com/en-us/help/4619187

#>

<# latest changes
  2022.12.07.0 [we] _SEC: add -Scenario SEC_General
  2022.07.25.0 [we] add Defender tracing using scripts\MDEClientAnalyzer.ps1
#>

$global:TssVerDateSEC= "2023.04.18.0"

#------------------------------------------------------------
#region ETW component trace Providers
#------------------------------------------------------------

#endregion ETW component trace Providers

#------------------------------------------------------------
#region Scenario definitions
#------------------------------------------------------------
$SEC_General_ETWTracingSwitchesStatus = [Ordered]@{
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
#endregion Scenario definitions


#------------------------------------------------------------
#region Pre-Start / Post-Stop / Collect functions for trace components and scenarios 
#------------------------------------------------------------

#endregion Pre-Start / Post-Stop

#------------------------------------------------------------
#region data collections
#------------------------------------------------------------

#region helper functions
Function StartGet-MSInfo ([boolean]$NFO = $true, [boolean]$TXT = $true, [string]$OutputLocation = $PWD.Path, [string]$Suffix = '') {
	$Process = "msinfo32.exe"
	if (test-path (join-path ([Environment]::GetFolderPath("System")) $Process)) {
		$ProcessPath = (join-path ([Environment]::GetFolderPath("System")) $Process)
	}
 elseif (test-path (join-path ([Environment]::GetFolderPath("CommonProgramFiles")) "Microsoft Shared\MSInfo\$Process")) {
		$ProcessPath = (join-path ([Environment]::GetFolderPath("CommonProgramFiles")) "Microsoft Shared\MSInfo\$Process")
	}
 else {
		FwCheck-Command-verified "cmd.exe"
		$ProcessPath = "cmd.exe /c start /wait $Process"
	}
	if ($TXT) {
		$InfoFile = Join-Path -Path $OutputLocation -ChildPath ("msinfo32" + $Suffix + ".txt")
		FwCheckAuthenticodeSignature $ProcessPath
		&$ProcessPath /report "$InfoFile"
	}
	if ($NFO) {
		$InfoFile = Join-Path -Path $OutputLocation -ChildPath ("msinfo32" + $Suffix + ".nfo")
		FwCheckAuthenticodeSignature $ProcessPath
		&$ProcessPath /nfo "$InfoFile"
	}
}

function EndTimedoutProcess ($process, $ProcessWaitMin) {
	$proc = Get-Process $process -EA SilentlyContinue
	if ($proc) {
		Write-Host "$(Get-Date -f 'yyyyMMdd HH:mm:ss') Waiting max $ProcessWaitMin minutes on $process processes to complete "
		Wait-Process -InputObject $proc -Timeout ($ProcessWaitMin * 60) -EA SilentlyContinue
		$ProcessToEnd = Get-Process | Where-Object { $_.Name -eq "$process" } -EA SilentlyContinue
		if ($null -ne $ProcessToEnd) {
			Write-Host "timeout reached ..."
			foreach ($prc in $ProcessToEnd) { stop-Process $prc -Force -EA SilentlyContinue }
		}
	}
}
function Start-NetTraces {
	if ($NetTraceI) {
		New-Item -ItemType Directory -Path "$resultOutputDir\NetTraces" -ErrorAction SilentlyContinue | out-Null
		$traceFile = "$resultOutputDir\NetTraces\NetTrace.etl"
		Write-Host "$(Get-Date -f 'yyyyMMdd HH:mm:ss') Stopping any running network trace profiles"
		FwCheck-Command-verified "netsh.exe"
		$StopNetCommand = Start-Process -PassThru -WindowStyle minimized netsh.exe -ArgumentList "trace stop"
		FwCheck-Command-verified "netsh.exe"
		$StopWfpCommand = Start-Process -PassThru -WindowStyle minimized netsh.exe -ArgumentList "wfp capture stop"
		start-sleep 1
		$NetshProcess = Get-Process | Where-Object { $_.Name -eq "netsh" } -ErrorAction SilentlyContinue
		if ($null -ne $NetshProcess) {
			foreach ($process in $NetshProcess) { stop-Process $process -Force }
		}
		FwCheck-Command-verified "ipconfig.exe"
		$FlushDns = Start-Process -PassThru -WindowStyle minimized ipconfig.exe -ArgumentList "/flushdns"
		FwCheck-Command-verified "netsh.exe"
		$CleanArpCache = Start-Process -PassThru -WindowStyle minimized netsh.exe -ArgumentList "interface ip delete arpcache"
		start-sleep 1
		Write-Host "$(Get-Date -f 'yyyyMMdd HH:mm:ss') Now starting a new network trace with Duration: $MinutesToRun min - Enter 'q' to stop"
		if ($buildNumber -le 7601) {
			FwCheck-Command-verified "netsh.exe"
			$StartNetCommand = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "trace start overwrite=yes capture=yes scenario=InternetClient report=yes maxSize=500 traceFile=`"$traceFile`" fileMode=circular"
		}
		else {
			FwCheck-Command-verified "netsh.exe"
			$StartNetCommand = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "trace start overwrite=yes capture=yes scenario=InternetClient_dbg report=yes maxSize=500 traceFile=`"$traceFile`" fileMode=circular"
		}
		FwCheck-Command-verified "netsh.exe"
		$StartWFLogging = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging allowedconnections enable"  # enable firewall logging for allowed traffic
		FwCheck-Command-verified "netsh.exe"
		$StartWFLogging = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging droppedconnections enable"  # enable firewall logging for dropped traffic
		FwCheck-Command-verified "netsh.exe"
		$StartWFTraces = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "wfp capture start file=wfpdiag.cab keywords=19" # start capturing  WFP log
		FwCheck-Command-verified "netstat.exe"
		&netstat -anob | Out-File "$resultOutputDir\NetTraces\NetStatOutputAtStart.txt"
		"Netstat output above was taken at: " + (Get-Date) | Out-File "$resultOutputDir\NetTraces\NetStatOutputAtStart.txt" -Append
		if (($OSPreviousVersion) -and (!$MDfWS)) {
			$OMSPath = "$env:ProgramFiles\Microsoft Monitoring Agent\Agent\Tools"
			if (Test-Path -path $OMSPath) {
				$MMAPathExists = "True"
				Get-Service HealthService | Stop-Service -ErrorAction SilentlyContinue
				&$OMSPath\StopTracing.cmd | Out-Null
				&$OMSPath\StartTracing.cmd VER | Out-Null
				Get-Service HealthService | Start-Service -ErrorAction SilentlyContinue
			}
		}
	}
}

function Stop-NetTraces {
	if ($NetTraceI) {
		FwCheck-Command-verified "netstat.exe"
		&netstat -anob | Out-File "$resultOutputDir\NetTraces\NetStatOutputAtStop.txt"
		"Netstat output above was taken at: " + (Get-Date) | Out-File "$resultOutputDir\NetTraces\NetStatOutputAtStop.txt" -Append
		FwCheck-Command-verified "netsh.exe"
		$StartWFLogging = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging allowedconnections disable"  # disable firewall logging for allowed traffic
		FwCheck-Command-verified "netsh.exe"
		$StartWFLogging = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging droppedconnections disable"  # disable firewall logging for dropped traffic
		FwCheck-Command-verified "netsh.exe"
		Start-Process -NoNewWindow netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "wfp capture stop"
		FwCheck-Command-verified "netsh.exe"
		Write-Host "$(Get-Date -f 'yyyyMMdd HH:mm:ss') Note: Stopping network and wfp traces may take a while..."
		Start-Process -WindowStyle Normal netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "trace stop"
		Copy-Item $env:SystemRoot\system32\LogFiles\Firewall\pfirewall.log -Destination "$resultOutputDir\NetTraces\" -ErrorAction SilentlyContinue
		if (($MMAPathExists) -and (!$MDfWS)) { 
			&$OMSPath\StopTracing.cmd | Out-Null
			Copy-Item $env:SystemRoot\Logs\OpsMgrTrace\* -Destination "$resultOutputDir\NetTraces\" -ErrorAction SilentlyContinue
		}	
		# Dump HOSTS file content to file
		Copy-Item $env:SystemRoot\System32\Drivers\etc\hosts -Destination "$resultOutputDir\SystemInfoLogs" -ErrorAction SilentlyContinue
		EndTimedoutProcess "netsh" 10
	}
}

function StartTimer {
	$TraceStartTime = "{0:dd/MM/yyyy h:mm:ss tt zzz}" -f (get-date)
	##Write-Report -section "general" -subsection "traceStartTime" -displayname "Trace StartTime: " -value $TraceStartTime
	$timeout = New-TimeSpan -Minutes $MinutesToRun
	$sw = [diagnostics.stopwatch]::StartNew()
	Create-OnDemandStartEvent
	if ($RemoteRun) {
		Write-Warning "Trace started... Note that you can stop this non-interactive mode by running 'MDEClientAnalyzer.cmd' from another window or session"
		Wait-OnDemandStop
	} else {
		while ($sw.elapsed -lt $timeout) {
			Start-Sleep -Seconds 1
			$rem = $timeout.TotalSeconds - $sw.elapsed.TotalSeconds
			Write-Progress -Activity "Collecting traces, run your scenario now and press 'q' to stop data collection at any time" -Status "Progress:"  -SecondsRemaining $rem -PercentComplete (($sw.elapsed.Seconds / $timeout.TotalSeconds) * 100)
			if ([console]::KeyAvailable) {
				$key = [System.Console]::ReadKey() 
				if ( $key.key -eq 'q') {
					Write-Warning  " $(Get-Date -f 'yyyyMMdd HH:mm:ss') The trace collection action was ended by user exit command"
					break 
				}
			}
		}
	}
	$TraceStopTime = "{0:dd/MM/yyyy h:mm:ss tt zzz}" -f (get-date)
	##Write-Report -section "general" -subsection "traceStopTime" -displayname "Trace StopTime: " -value $TraceStopTime 
}

function Create-OnDemandStopEvent {
	Write-host "Another non-interactive trace is already running... stopping log collection and exiting."
	Write-EventLog -LogName "Application" -Source "MDEClientAnalyzer" -EventID 2 -EntryType Information -Message "MDEClientAnalyzer is stopping a running log set" -Category 1
	[Environment]::Exit(1)
}

function Create-OnDemandStartEvent {
	Write-EventLog -LogName "Application" -Source "MDEClientAnalyzer" -EventID 1 -EntryType Information -Message "MDEClientAnalyzer is starting OnDemand traces" -Category 1	
}
function Write-Report($section, $subsection, $displayName, $value, $alert) { 
	$subsectionNode = $script:xmlDoc.CreateNode("element", $subsection, "")
	$subsectionNode.SetAttribute("displayName", $displayName)

	$eventContext1 = $script:xmlDoc.CreateNode("element", "value", "")
	$eventContext1.psbase.InnerText = $value
	$subsectionNode.AppendChild($eventContext1) | out-Null

	if ($value -eq "Running") {
		$alert = "None"
	} elseif (($value -eq "Stopped" -or $value -eq "StartPending")) {
		$alert = "High"
	}

	if ($alert) {
		$eventContext2 = $script:xmlDoc.CreateNode("element", "alert", "")
		$eventContext2.psbase.InnerText = $alert
		$subsectionNode.AppendChild($eventContext2) | out-Null
	}

	$checkresult = $DisplayName + ": " + $value
	# Write message to the ConnectivityCheckFile
	$checkresult | Out-File $connectivityCheckFile -append

	$xmlRoot = $script:xmlDoc.SelectNodes("/MDEResults")
	$InputNode = $xmlRoot.SelectSingleNode($section)
	$InputNode.AppendChild($subsectionNode) | Out-Null
}

# Initialize XML log - for consumption by external parser
function InitXmlLog {
	$script:xmlDoc = New-Object System.Xml.XmlDocument								 
	$script:xmlDoc = [xml]"<?xml version=""1.0"" encoding=""utf-8""?><MDEResults><general></general><devInfo></devInfo><EDRCompInfo></EDRCompInfo><MDEDevConfig></MDEDevConfig><AVCompInfo></AVCompInfo><events></events></MDEResults>"
}

# Define C# functions to extract info from Windows Security Center (WSC)
# WSC_SECURITY_PROVIDER as defined in Wscapi.h or http://msdn.microsoft.com/en-us/library/bb432509(v=vs.85).aspx
# And http://msdn.microsoft.com/en-us/library/bb432506(v=vs.85).aspx
$wscDefinition = @"
		[Flags]
		public enum WSC_SECURITY_PROVIDER : int
		{
			WSC_SECURITY_PROVIDER_FIREWALL = 1,				// The aggregation of all firewalls for this computer.
			WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS = 2,	// The automatic update settings for this computer.
			WSC_SECURITY_PROVIDER_ANTIVIRUS = 4,			// The aggregation of all antivirus products for this computer.
			WSC_SECURITY_PROVIDER_ANTISPYWARE = 8,			// The aggregation of all anti-spyware products for this computer.
			WSC_SECURITY_PROVIDER_INTERNET_SETTINGS = 16,	// The settings that restrict the access of web sites in each of the Internet zones for this computer.
			WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL = 32,	// The User Account Control (UAC) settings for this computer.
			WSC_SECURITY_PROVIDER_SERVICE = 64,				// The running state of the WSC service on this computer.
			WSC_SECURITY_PROVIDER_NONE = 0,					// None of the items that WSC monitors.
			
			// All of the items that the WSC monitors.
			WSC_SECURITY_PROVIDER_ALL = WSC_SECURITY_PROVIDER_FIREWALL | WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS | WSC_SECURITY_PROVIDER_ANTIVIRUS |
			WSC_SECURITY_PROVIDER_ANTISPYWARE | WSC_SECURITY_PROVIDER_INTERNET_SETTINGS | WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL |
			WSC_SECURITY_PROVIDER_SERVICE | WSC_SECURITY_PROVIDER_NONE
		}

		[Flags]
		public enum WSC_SECURITY_PROVIDER_HEALTH : int
		{
			WSC_SECURITY_PROVIDER_HEALTH_GOOD, 			// The status of the security provider category is good and does not need user attention.
			WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED,	// The status of the security provider category is not monitored by WSC. 
			WSC_SECURITY_PROVIDER_HEALTH_POOR, 			// The status of the security provider category is poor and the computer may be at risk.
			WSC_SECURITY_PROVIDER_HEALTH_SNOOZE, 		// The security provider category is in snooze state. Snooze indicates that WSC is not actively protecting the computer.
			WSC_SECURITY_PROVIDER_HEALTH_UNKNOWN
		}

		
		[DllImport("wscapi.dll")]
		private static extern int WscGetSecurityProviderHealth(int inValue, ref int outValue);

		// code to call interop function and return the relevant result
		public static WSC_SECURITY_PROVIDER_HEALTH GetSecurityProviderHealth(WSC_SECURITY_PROVIDER inputValue)
		{
			int inValue = (int)inputValue;
			int outValue = -1;

			int result = WscGetSecurityProviderHealth(inValue, ref outValue);

			foreach (WSC_SECURITY_PROVIDER_HEALTH wsph in Enum.GetValues(typeof(WSC_SECURITY_PROVIDER_HEALTH)))
				if ((int)wsph == outValue) return wsph;

			return WSC_SECURITY_PROVIDER_HEALTH.WSC_SECURITY_PROVIDER_HEALTH_UNKNOWN;
		}
"@
function Defender-Get-Logs {
	New-Item -ItemType Directory -Path "$resultOutputDir\DefenderAV" -ErrorAction SilentlyContinue | out-Null
	#New-Item -ItemType Directory -Path "$resultOutputDir\SystemInfoLogs" -ErrorAction SilentlyContinue | out-Null
	StartGet-MSInfo -NFO $true -TXT $false -OutputLocation "$resultOutputDir\SystemInfoLogs"
	FwCheck-Command-verified "gpresult.exe"
	&gpresult /SCOPE COMPUTER /H "$resultOutputDir\SystemInfoLogs\GP.html"
	if ($MpCmdRunCommand) {
		Write-Host "Running MpCmdRun -GetFiles..."
		FwCheckAuthenticodeSignature $MpCmdRunCommand
		&$MpCmdRunCommand -getfiles | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		Copy-Item -Path "$MpCmdResultPath\MpSupportFiles.cab" -Destination "$resultOutputDir\DefenderAV" -verbose -ErrorVariable GetFilesErr | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		$GetFilesErr | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		#Copy-Item -path "C:\Users\Public\Downloads\Capture.npcap" -Destination "$resultOutputDir\DefenderAV" -ErrorAction SilentlyContinue -verbose -ErrorVariable CopyNpCap | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		#$CopyNpCap | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		# Dump Defender related polices
		Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -recurse | Out-File "$resultOutputDir\DefenderAV\Policy-DefenderAV.txt"
		Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\" -recurse | Out-File "$resultOutputDir\DefenderAV\Policy-Firewall.txt"
		Get-ChildItem "HKU:\S-1-5-18\SOFTWARE\Microsoft\Windows Defender" -recurse -ErrorAction SilentlyContinue | Out-File "$resultOutputDir\DefenderAV\Policy-SystemService.txt"
		Get-ChildItem "HKU:\S-1-5-20\SOFTWARE\Microsoft\Windows Defender" -recurse -ErrorAction SilentlyContinue | Out-File "$resultOutputDir\DefenderAV\Policy-NetworkService.txt"
	}
	FwCheck-Command-verified "fltmc.exe"
	&fltmc instances -v "$env:SystemDrive" > $resultOutputDir\SystemInfoLogs\filters.txt
	if ($OSProductName.tolower() -notlike ("*server*")) {
		Write-output "`r`n##################### Windows Security Center checks ######################" | Out-File $connectivityCheckFile -Append
		$wscType = Add-Type -memberDefinition $wscDefinition -name "wscType" -UsingNamespace "System.Reflection", "System.Diagnostics" -PassThru
 
		"			Firewall: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_FIREWALL) | Out-File $connectivityCheckFile -Append
		"		 Auto-Update: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS) | Out-File $connectivityCheckFile -Append
		"		  Anti-Virus: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_ANTIVIRUS) | Out-File $connectivityCheckFile -Append
		"		Anti-Spyware: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_ANTISPYWARE) | Out-File $connectivityCheckFile -Append
		"   Internet Settings: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_INTERNET_SETTINGS) | Out-File $connectivityCheckFile -Append
		"User Account Control: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL) | Out-File $connectivityCheckFile -Append
		"		 WSC Service: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_SERVICE) | Out-File $connectivityCheckFile -Append

		if ($wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_FIREWALL) -eq $wscType[2]::WSC_SECURITY_PROVIDER_HEALTH_POOR) {
			Write-output "Windows Defender firewall settings not optimal" | Out-File $connectivityCheckFile -Append
		}
		if ($wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL) -eq $wscType[2]::WSC_SECURITY_PROVIDER_HEALTH_POOR) {
			Write-output "User Account Controller (UAC) is switched off" | Out-File $connectivityCheckFile -Append
		}
		if ($wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_ANTIVIRUS) -eq $wscType[2]::WSC_SECURITY_PROVIDER_HEALTH_GOOD) {
			Write-output "Windows Defender anti-virus is running and up-to-date" | Out-File $connectivityCheckFile -Append
		}
	}
}
#endregion helper functions

function CollectSEC_DefenderGetLog{
	EnterFunc $MyInvocation.MyCommand.Name
	$ProcessWaitMin = 5	# wait max minutes to complete
	$NetTraceI = $True
	If($global:BoundParameters.ContainsKey('DefenderDurInMin')){
		$global:SEC_DefenderDurInMin = $global:DefenderDurInMin
	} else {$global:SEC_DefenderDurInMin = 5}
	$MinutesToRun = $global:SEC_DefenderDurInMin
	InitXmlLog
	LogInfo "[$($MyInvocation.MyCommand.Name)] . running Defender Get-Logs "
	#Store paths for MpCmdRun.exe usage
	if (((FwGet-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Value ImagePath) -and ($OSBuild -ge 14393)) -or ($MDfWS)) {
		$MsMpEngPath = FwGet-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Value ImagePath
		[System.IO.DirectoryInfo]$CurrentMpCmdPath = $MsMpEngPath -replace "MsMpEng.exe" -replace """"
		$MpCmdRunCommand = Join-Path $CurrentMpCmdPath "MpCmdRun.exe"
		$MpCmdResultPath = "$env:ProgramData\Microsoft\Windows Defender\Support"
	}
	elseif (Test-Path -path "$env:ProgramFiles\Microsoft Security Client\MpCmdRun.exe") {
		$CurrentMpCmdPath = "$env:ProgramFiles\Microsoft Security Client\"
		$MpCmdRunCommand = "$env:ProgramFiles\Microsoft Security Client\MpCmdRun.exe"
		$MpCmdResultPath = "$env:ProgramData\Microsoft\Microsoft Antimalware\Support"
	}
	[string]$OSProductName = FwGet-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value ProductName
	
	$resultOutputDir = Join-Path $global:LogFolder "MDEClientAnalyzerResult"
	$SysLogs = Join-Path $resultOutputDir "SystemInfoLogs"
	$connectivityCheckFile = Join-Path $SysLogs "MDEClientAnalyzer.txt"

	#New-PSDrive HKU Registry HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
	New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
	New-Item -ItemType Directory -Path "$resultOutputDir\SystemInfoLogs" -ErrorAction SilentlyContinue | out-Null
	Start-NetTraces
	StartTimer
	Stop-NetTraces
	Defender-Get-Logs
	FwAddRegItem @("ATP") _Stop_ 
	# Check if MSinfo is still running and allow to run until timeout is reached
	EndTimedoutProcess "msinfo32" 5
	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done SEC_DefenderGetLog"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectSEC_DefenderFullLog{
	# invokes external script until fully integrated into TSSv2; requires \BIN\PsExec.exe and MDEClientAnalyzer.exe
	EnterFunc $MyInvocation.MyCommand.Name
	If($global:BoundParameters.ContainsKey('DefenderDurInMin')){
		$global:SEC_DefenderDurInMin = $global:DefenderDurInMin
	} else {$global:SEC_DefenderDurInMin = 5}
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling MDEClientAnalyzer.ps1 with Duration=$global:SEC_DefenderDurInMin min"
	if ($global:IsLiteMode) { Write-Host -ForegroundColor Magenta "[WARNING] psExec.exe and MDEClientAnalyzer.exe are not available in TSS Lite mode; expect reduced/incomplete output"}
	.\scripts\tss_MDEClientAnalyzer.ps1 -DataPath $global:LogFolder -AcceptEula -r -i -m $SEC_DefenderDurInMin
	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done MDEClientAnalyzer.ps1"
	FwAddRegItem @("ATP") _Stop_ 
	EndFunc $MyInvocation.MyCommand.Name
}

#endregion data collections

#region Registry Key modules for FwAddRegItem
	<# Example:
	$global:KeysHyperV = @("HKLM:Software\Microsoft\Windows NT\CurrentVersion\Virtualization", "HKLM:System\CurrentControlSet\Services\vmsmp\Parameters")
	#>
	$global:KeysWinATP = @("HKLM:Software\Microsoft\Windows Advanced Threat Protection\Status")
#endregion Registry Key modules

#region groups of Eventlogs for FwAddEvtLog
	<# Example:
	$global:EvtLogsEFS		= @("Microsoft-Windows-NTFS/Operational", "Microsoft-Windows-NTFS/WHC")
	#>
#endregion groups of Eventlogs

Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *
# SIG # Begin signature block
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCARJ0UqiuFN0lpg
# WqsQlrLp5SLg4Wbc9l1OLXDOkhJClKCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOynsgTq9uq4y/FELZ1TifcK
# XpOZDiC5ptHCh4RBCwmxMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAyWNblJ4zie01e/DkovX85AERhuI1auWDHQFHdA9M1/2p5vTWIzcnEn6a
# 8SHzSlxZ2T0rgLhWRQ5T/p3C5O3k2FSFBPe7w9q/KyYlmd6gwdqL4TBYL6NxJBP/
# nH2Gn2GCDH7lvAjIpgEvLiEKIkR+kaxozMev0eMb48M0RtgE1BCshzbx8z6jlj3g
# r8/dRV3gKkdbunr0Zb+vZ+BUdboihtz0az9TWNmwslpjmmZpOcHiLCiH+RIPz84D
# QW0bST/X4h1MhfkEgQSW+80gZ4taSXI+AE7Cw4Ee1C+XbqkpXImCSDkEjCDYFBW1
# xNd/F+/XiZYvQOg/96rWvC38fYCiiqGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCC
# FuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCA3T1rYsB8frWzGLxrQ27mHVUJ04s1I2oHpuKxYcpCzQAIGZGzQTfRW
# GBMyMDIzMDYwNjExNDQxNS45MTVaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozQkJELUUz
# MzgtRTlBMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVQwggcMMIIE9KADAgECAhMzAAABxjDNLtbTocD0AAEAAAHGMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEz
# NFoXDTI0MDIwMjE5MDEzNFowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNCQkQtRTMzOC1FOUExMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEA770iOr6v4Hk1m3SZj+1BR/iuofv+f6eVb7Hc21YxzAzr
# o4G6kKXF47YAsEgrWWT1ogvp0IroFm8CdRZTf/DlQ0fbNNO9pCA01KJ03zH82Clm
# k9ze9r1jPJ1ZJaMnsZmAy7VpY9mNqX9dhPvnW1/ZxbbiHv7qwwgw9U2ST5mfcpPu
# tsI/Qr/gLC6aTI3UCYziVPZ/Qfag8NQhKkpHZO3Kr5r83cy7jz4OWPy5M2WitWv5
# bJJ5rBTW518QPEzFwzq8e8P722CWKZJFjN8etBgsK05gHeHaN9kmlpYJJL84v9Ji
# aX7NFJkORhApEFZiUIaZoLxJt4pcBDzf+WD9UAjRKCrAseJ/ckzQvOn95X4Ot4as
# nOuNhcCdcQWcrZoykFmEaoYkrsD7n/4nFFHwJDKUaBYZZLwPj7ux48S1Ye+cMccM
# xdRSjuoG4rqJqpEd6gzfz239v36L+LtOlQhfL5cnclhNSWdmKw1THyekH96RNtOp
# IE7c+9Tnsv1aE9hphejLOJxfsXTkyw0FIdilc0CP7zzUsqaCGF2mFXRwL4jfX1Ry
# V7QGKEeOpvGZqQKLHVZbLD32ztW8Lfv99xQ24d/TIxO9LReuHsnwotn+8BsCrzu+
# /24vOcA9Xcpd7kIeW4zmUxhFsv4KCfiqMptZhhMAA0SqDuj23cj10smXROLUnhUC
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBRxX/lHiShECp1n2lMa6G1uLvNglDAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQALzF724jXugDU486PMBYR7Cc6aHr2nJDnGsnkqwZYmjRi28qv6S1Ly772zwm5D
# I189zgAQ99xhEjW6uYkrX5UrtVu7JUQP6bBBBJ98c28FAIPIK3fkQNCv2rxRjfQM
# JSdcwsJeTK7Ld09OuA5hY4PWCBgJpfY71LcaXz3FR8ANPFX6zcKYbgYOZregtpDu
# b34N0QhR7wc/FcmV+g4I3IdTAoMD2/WI5ZsfKTzBUn/U3ApUhNwbOl5YSC+f9S1L
# StbZLwPzMS+fLPXJUSe7SSvspfSsr/VEe0oQhmaR+5vcq+7MLw861WBVhYpJ7TB5
# YBS5ORO9XdIbcpbBFwcHPmb8iZqSIqW9JpgG76+5NQULPVzZ75z5W2R5ZiyQktiH
# pMwjX2OO29Z8+nTw2tOsVCcwzH9LoELedv3PjcpbwOyLjtm1T4XHYd3qbd9DXoBj
# NYkSjdi37pNp58u+rITltLKOjjQCJwj1FpnuBY825B5C0uC/NYESEKsTicEjhS/4
# ujBXLcNGDhVBl2vHE6qY/YW4ky1vcypvUrsG81gpv2+8/ihOwg4wTLO7XqikeIiU
# 3ZWAUAoOpTl14tedQqxbHTDveJYR3OU0yKB2xwf87EWCAb0CJimhDmyQaKEvSV0f
# LW9iVyI0wYcG4V2aVN6TrZ4mr+ffaqDQD9F+HpPhP0plAzCCB3EwggVZoAMCAQIC
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
# U046M0JCRC1FMzM4LUU5QTExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAC01yuYmIVvsokSacJmWe8Mu2QFtoIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoKRoWMCIYDzIwMjMwNjA2MTAzNjA2WhgPMjAyMzA2MDcxMDM2MDZaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOgpGhYCAQAwBwIBAAICAU4wBwIBAAICFDgw
# CgIFAOgqa5YCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQAeWBpbTSYTx/vj
# hix8MD2rFBCHaZt7tY3aIRSiQiOULh8ZFLe8JkEBs8lucqPvgAaOnYWuFZewkNOU
# F9V7KuD62Hk+/RkMYA7NWzAPO/cS2CPzEqBVfWPubsoBJIwrHqTPbpcwWzjtEV0m
# rOKsq+ndrx8O1TBLjXpMz90ikpiCEjGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABxjDNLtbTocD0AAEAAAHGMA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIP6/sflTI4ihMq7Ve83kQeJ+0NKbEDQSbEH/FRFdNSk3MIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQgVjETXFXJvZgpxiZqk/BwDWA5Pxw6hehULpkF
# r9rjry0wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AcYwzS7W06HA9AABAAABxjAiBCB8RSxSlzsbA40cbQhpihyeJJK3ZDpN9wrUcYz2
# DJhDbTANBgkqhkiG9w0BAQsFAASCAgAxe7h0tebcL/HN7ZGxB9m36lFrqJ/NkoLS
# 5FptZwM4Gafg7gSL+XKezyKNj+X8viac+f6sQpbP7qIrqFrTdAhMWXKtTJdukA0k
# gWPt8raZWUUR9Efoi2Si6vgSHBhzRWah97WTUd6aiAiujmPZRxjK/l4UdqPOReQs
# +7Ux9lArNfoghmPKUCXtvwsnqAXZe4FbDIL5o8XfGMhRs7XaedSKGCKEjzJxKUZv
# pNGk9O70EubD1VfoCXusRWgSKgCiC1+mcLrrNNKhR7qMgw6Vp1sSKI+vCXER0RlK
# b3GCYc2Bd8lLMVlz1GrqWffZJGfGHmab9ZdsHvqANEBnFlkEADbfhuCQ59mDjALn
# GefsXsJNEHY/EgOwDOmo+cr0H1yhivPKyV1eFQgChG/pq16FQH+745QqMZhNHjO8
# ZiKV93wQWyay3ePtRwabENoKO6uGZ5Gwmef+IVHskffj0o9ra6bTd4SC0mkJvXLM
# vsoUBM44dXNyTMnvoy/GgxvS0KWjkmRR8TJVrz+JTEkksa+1s4obzwGEhfCCW7Jq
# w/Me++3dHz2ZuaVt2dq6bL7JXbcP9Te5StHmK3zXmjtplvLayww7yE5/EVdhlLq8
# n8IoG7E8WbDMKDyIoX1NZIPR0fN3XcYf6lvRZ5Fe8B/v3mjbU32F+3n9HLPv11EO
# yxiRpYi7aw==
# SIG # End signature block
