# tss_ADPerfDataCollection.ps1
<# 432728 ADPERF: TOOLS: Domain Controller AD Perf Data Collection Script https://internal.evergreen.microsoft.com/en-us/topic/adperf-tools-domain-controller-ad-perf-data-collection-script-d4959f71-e2bd-061e-4acd-a0b48c52d766
# latest changes:

:: 2022.07.27.1 [we] add Warning for ProcDump on Lsass.exe; adjusted for TSS
:: 2022.07.27.0 [wa]Adjustment for Member servers
#>

<#
	.SYNOPSIS
	Microsoft CSS ADPerf data collection script.
	.DESCRIPTION
	The Microsoft CSS ADPerf data collection scripts are used to diagnose Active Directory related issues on Domain Controllers and member servers.

	The output of this data collection will be in C:\ADPerfData

	.PARAMETER Scenario
	Select one of the following scenarios. (0 - 8)
	0: Interactive
	1: High CPU
	2: High CPU Trigger Start
	3: High Memory
	4: High Memory Trigger Start
	5: Out of ATQ threads on Domain Controller (always trigger start)
	6: Baseline performance (5 minutes)
	7: Long Term Baseline performance
	8: Stop tracing providers (run this if you previously cancelled before script completion)
	.PARAMETER DelayStop
	The number of minutes after the triggered condition has been met that the data collection should stop. (0 - 30)

	If parameter not specified the delay will be 5 minutes in trigger scenarios.
	.PARAMETER Threshold
	The % resource utilization by lsass that will trigger the stop condition. (50 - 100)

	- Used in scenario 2 for CPU threshold.
	- Used in scenario 4 for memory threshold.

	This parameter must be specified in scenario 2 or 4.

	.PARAMETER DumpPreference
	Preferrence for procdump collection. (Full, MiniPlus)
	- Full	  : procdump -ma
	- MiniPlus  : procdump -mp

	Use MiniPlus when retrieving Full dumps takes too long. WARNING: You may experience incompleted call stacks with this option.
	.EXAMPLE
	.\ADPerfDataCollection.ps1											  # Interactive
	.EXAMPLE
	.\ADPerfDataCollection.ps1 -Scenario 1								  # High CPU data collection
	.EXAMPLE
	.\ADPerfDataCollection.ps1 -Scenario 4 -DelayStop 5 -Threshold 80	# High Memory Trigger stop at 80% utilization with 5 minute delay
#>
[CmdletBinding()]
Param(
	$DataPath = $global:LogFolder,	# from TSS script
	[ValidateRange(1, 8)]
	[int]$Scenario = 0,				# reset any previous Scenario
	[ValidateRange(0, 30)]
	[int]$DelayStop = 0,
	[ValidateRange(20, 99)]
	[int]$Threshold = 0,
	[ValidateSet("Full", "MiniPlus")]
	[string]$DumpPreference = "Full",
	[int]$BaseLineTimeMinutes = 5,
	[switch]$AcceptEula
)
$ADperfVer = "2022.07.27.1"			# dated version number
if ([String]::IsNullOrEmpty($DataPath)) {$DataPath="c:"}
if ([String]::IsNullOrEmpty($global:ScriptFolder)) {$global:ScriptFolder="C:\TSSv2\"}
$Script:FieldEngineering = "0"
$Script:NetLogonDBFlags = "0"
$Script:ADPerfFolder = $DataPath + "\ADPerfData"	# final output folder
$Script:DataPath = "$Script:ADPerfFolder"
$Script:Custom1644 = $false
$Script:CustomADDSUsed = $false
$Script:TriggerScenario = $false
[int]$Script:TriggeredTimerLength = 5
$Script:TriggerThreshold = 50
$Script:Interactive = $false
$Script:IsDC = $false

[int]$Script:BaseLineTimeMinutes = $BaseLineTimeMinutes
$PerfLogsRoot = "C:\PerfLogs"								# this is also mentioned in ADDS.xml
$ToolsExeDir = Join-Path $global:ScriptFolder "BIN" 		# from TSS script
$Script:ProcDumpCommand = Join-Path $ToolsExeDir "ProcDump.exe"	# from TSS script
if (!(Test-Path -path $PerfLogsRoot)) {FwCreateFolder $PerfLogsRoot}															 

function ADPerf-Menu {
	Write-Host "============AD Perf Data Collection Tool=============="
	Write-Host "1: High CPU"
	Write-Host "2: High CPU Trigger Start"
	Write-Host "3: High Memory"
	Write-Host "4: High Memory Trigger Start"
	Write-Host "5: Out of ATQ threads on Domain Controller (always trigger start)"
	Write-Host "6: Baseline performance ($Script:BaseLineTimeMinutes minutes)"
	Write-Host "7: Long Term Baseline performance (Wait on User)"
	Write-Host "8: Stop tracing providers (run this if you previously cancelled before script completion)"
	Write-Host "q: Press Q  or Enter to quit"
	Write-Host "======================================================"
}

function CommonTasksCollection {
	if (!$Script:Custom1644 -and $Script:IsDC) {
		Write-Host "Enabling 1644 Events...."
		Enable1644RegKeys
		Write-Host "1644 Events Enabled"
	}
	Write-Host "Turning on Netlogon Debug flags"
	$NetlogonParamKey = get-itemproperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
	$Script:NetLogonDBFlags = $NetlogonParamKey.DBFlag
	New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "DBFlag" -Value 0x2080ffff -PropertyType DWORD -Force | Out-Null
	Write-Host "Enabling the AD Data Collector Set...."
	StartADDiagnostics
	StartLSATracing
	StartSamSrvTracing
	Write-Host "SamSrv Tracing Started"
}

function HighCpuDataCollection {
	Write-Host -ForegroundColor Cyan "->1: Gathering Data for High CPU"
	CommonTasksCollection
	Write-Host "Collecting LSASS Process Dumps...."
	GetProcDumps -Count 2 -Seconds 5
	StartWPR "-Start GeneralProfile -Start CPU"
	StartNetTrace
	if ($Script:TriggerScenario) {
		Write-Host "Collecting Data for $Script:TriggeredTimerLength minutes"
		$sleepTime = 60000 * [int]$Script:TriggeredTimerLength
		Start-Sleep -m $sleepTime
	}
	else {
		Write-Host -ForegroundColor Green "HighCpu Data Collection is running..."
		Read-Host "Ensure you have had enough time for the issue to reproduce and then press the [Enter] Key to Stop tracing..."
	}
	StopWPR
	StopNetTrace
	StopADDiagnostics
}

function HighCpuDataCollectionTriggerstart {
	Write-Host -ForegroundColor Cyan "->2: Gathering Data for High CPU Usage Trigger"
	if ($Script:Interactive) {
		while ($true) {
			$CPUThreshold = Read-Host "CPU Percent Threshold(20-99)"
			if ([int]$CPUThreshold -gt 20 -and [int]$CPUThreshold -lt 100) {
				$Script:TriggerThreshold = $CPUThreshold
				break
			}
			else {
				Write-Host "Invalid Input"
			}
		}
		$dataCollectionTime = Read-Host "How long in minutes to collect data after trigger is met?"
		if ([int]$dataCollectionTime -gt 0 -and [int]$dataCollectionTime -lt 31) {
			$Script:TriggeredTimerLength = $dataCollectionTime
		}
		$Script:TriggerScenario = $true
	}
	Write-Host "Waiting for high cpu condition of greater than $Script:TriggerThreshold`0%..."
	While ($true) {
		$CPUValue = get-counter -Counter "\Processor Information(_Total)\% Processor Time" -SampleInterval 5 -MaxSamples 1
		if ($CPUValue.CounterSamples.CookedValue -gt $Script:TriggerThreshold) {
			Write-Host "CPU Usage is Greater than $Script:TriggerThreshold`0% - Starting Data Collection...."
			break
		}
	}
	HighCpuDataCollection
}

function HighMemoryDataCollection {
	Write-Host -ForegroundColor Cyan "->3: Gathering Data for High Memory on a Domain Controller"
	CommonTasksCollection
	StartWPR "-Start GeneralProfile -Start Heap -Start VirtualAllocation"
	Write-Host "Getting Arena Info and Thread State Information..."
	if ($Script:IsDC) { GetRootDSEArenaInfoAndThreadStates }
	Write-Host "Collecting LSASS Process Dump...."
	$lsassProcess = Get-Process "lsass"
	GetProcDumps
	if ($Script:TriggerScenario) {
		Write-Host "Collecting Data for $Script:TriggeredTimerLength minutes"
		$sleepTime = 60000 * [int]$Script:TriggeredTimerLength
		Start-Sleep -m $sleepTime
	}
	else {
		Write-Host -ForegroundColor Green "HighMemory Data Collection is running..."
		Read-Host "Ensure you have had enough time for the issue to reproduce and then press the [Enter] Key to Stop tracing..."
	}
	StopWPR
	StopADDiagnostics
	if ($Script:IsDC) {
		Write-Host "Getting Arena Info and Thread State Information again..."
		GetRootDSEArenaInfoAndThreadStates
	}
}

function HighMemoryDataCollectionTriggerStart {
	Write-Host -ForegroundColor Cyan "->4: Gathering Data for High Memory Usage Trigger"
	if ($Script:Interactive) {
		while ($true) {
			$MemoryThreshold = Read-Host "Memory Percent Threshold(50-99)"
			if ([int]$MemoryThreshold -gt 20 -and [int]$MemoryThreshold -lt 100) {
				$Script:TriggerThreshold = $MemoryThreshold
				break
			}
			else {
				Write-Host "Invalid Input"
			}
		}
		$dataCollectionTime = Read-Host "How long in minutes to collect data after trigger is met?"
		if ([int]$dataCollectionTime -gt 0 -and [int]$dataCollectionTime -lt 31) {
			$Script:TriggeredTimerLength = $dataCollectionTime
		}
		$Script:TriggerScenario = $true
	}
	Write-Host "Attempting to enable RADAR Leak Diag"
	StartRadar
	Write-Host "Waiting for high memory condition of greater than $Script:TriggerThreshold`0%..."
	While ($true) {
		$CommittedBytesInUse = get-counter -Counter "\Memory\% Committed Bytes In Use" -SampleInterval 5 -MaxSamples 1
		if ($CommittedBytesInUse.CounterSamples.CookedValue -gt $Script:TriggerThreshold) {
			Write-Host "Committed Bytes in Use Percentage is Greater than $Script:TriggerThreshold`0% - Starting Data Collection...."
			break
		}
	}
	StopRadar
	HighMemoryDataCollection
}

function ATQThreadDataCollection {
	Write-Host -ForegroundColor Cyan "->5: Gathering Data for ATQ Thread depletion scenario"
	Write-Host ""
	Write-Host "Waiting for ATQ Threads being exhausted..."
	While ($true) {
		$LdapAtqThreads = get-counter -counter "\DirectoryServices(NTDS)\ATQ Threads LDAP" -SampleInterval 5 -MaxSamples 1
		$OtherAtqThreads = Get-Counter -counter "\DirectoryServices(NTDS)\ATQ Threads Other" -SampleInterval 5 -MaxSamples 1
		$TotalAtqThreads = Get-Counter -counter "\DirectoryServices(NTDS)\ATQ Threads Total" -SampleInterval 5 -MaxSamples 1
		if ($LdapAtqThreads.CounterSamples.CookedValue + $OtherAtqThreads.CounterSamples.CookedValue -eq $TotalAtqThreads.CounterSamples.CookedValue) {
			Write-Host ATQ Threads are depleted - Starting Data Collection....
			break
		}
	}
	Write-Host "Collecting LSASS Process Dumps...."
	GetProcDumps -Count 3 -Seconds 5
	CommonTasksCollection
	Write-Host "Please wait around $Script:BaseLineTimeMinutes minutes while we collect traces.  The collection will automatically stop after the time has elapsed"
	$sleepTime = 60000 * $Script:BaseLineTimeMinutes
	Start-Sleep -m $sleepTime
	StopADDiagnostics
}

function BaseLineDataCollection {
	Write-Host -ForegroundColor Cyan "->6: Gathering Baseline Performance Data"
	if ($Script:IsDC) {
		Write-Host "Enabling 1644 Events with Paremeters to collect all requests...."
		Enable1644RegKeys $true 1 0 0
		Write-Host "1644 Events Enabled"
	}
	CommonTasksCollection
	StartWPR "-Start GeneralProfile -Start CPU -Start Heap -Start VirtualAllocation"
	Write-Host "Collecting LSASS Process Dumps...."
	GetProcDumps -Count 3 -Seconds 5
	Write-Host "Please wait around 5 minutes while we collect performance baseline traces.  The collection will automatically stop after the time has elapsed"
	$sleepTime = 60000 * $Script:BaseLineTimeMinutes
	Start-Sleep -m $sleepTime
	StopWPR
	StopADDiagnostics
}

function LongBaseLineCollection {
	Write-Host -ForegroundColor Cyan "->7: Gathering Baseline Performance Data of a Domain Controller"
	GetProcDumps
	if ($Script:IsDC) {
		Write-Host "Enabling 1644 Events with Paremeters to collect all requests...."
		Enable1644RegKeys $true
		Write-Host "1644 Events Enabled"
	}
	StartADDiagnostics
	Write-Host "Starting Short and Long Perflogs"
	StartPerfLog $true
	StartPerfLog $false
	$NetlogonParamKey = get-itemproperty  -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
	$Script:NetLogonDBFlags = $NetlogonParamKey.DBFlag
	Write-Host -ForegroundColor Green "LongBaseLine Data Collection is running..."
	Read-Host "Ensure you have had enough time for a good baseline and then press the [Enter] Key to Stop tracing..."
	StopADDiagnostics
	StopPerfLogs $true
	StopPerfLogs $false
}

function GetRootDSEArenaInfoAndThreadStates {
	Import-Module ActiveDirectory
	$LdapConnection = new-object System.DirectoryServices.Protocols.LdapConnection(new-object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($env:computername, 389))
	$msDSArenaInfoReq = New-Object System.DirectoryServices.Protocols.SearchRequest
	$msDSArenaInfoReq.Filter = "(objectclass=*)"
	$msDSArenaInfoReq.Scope = "Base"
	$msDSArenaInfoReq.Attributes.Add("msDS-ArenaInfo") | Out-Null
	$msDSArenaInfoResp = $LdapConnection.SendRequest($msDSArenaInfoReq)
	(($msDSArenaInfoResp.Entries[0].Attributes["msds-ArenaInfo"].GetValues([string]))[0]) | Out-File $Script:DataPath\msDs-ArenaInfo.txt -Append
	Add-Content -Path $Script:DataPath\msDs-ArenaInfo.txt -Value "=========================================================="
	$msDSArenaInfoReq.Attributes.Clear()
	$msDSArenaInfoReq.Attributes.Add("msds-ThreadStates") | Out-Null
	$msDSThreadStatesResp = $LdapConnection.SendRequest($msDSArenaInfoReq)
	(($msDSThreadStatesResp.Entries[0].Attributes["msds-ThreadStates"].GetValues([string]))[0]) | Out-File $Script:DataPath\msDs-ThreadStates.txt -Append
	Add-Content -Path $Script:DataPath\msDs-ThreadStates.txt -Value "=========================================================="
}

function GetProcDumps {
	#Note: Procdump on lsass will fail with Access Denied, see https://mikesblogs.net/access-denied-when-running-procdump/ + https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs
		param(
		[int]$Count = 1,
		[int]$Seconds
	)
	$PDArgs = "lsass.exe "
	if ($PDArgs -like "*lsass*") {
		LogWarn "Procdump on lsass may fail with Access Denied, see https://mikesblogs.net/access-denied-when-running-procdump/ + https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs" "Magenta"
	}
	if ($Script:DumpType -eq "MiniPlus") {
		$PDArgs += "-mp "
	}
	else {
		$PDArgs += " -ma "
	}
	if ($Count -eq 1) { $PDArgs += " -a -r 3 -AcceptEula $Script:DataPath" }
	else { $PDArgs += "-n $Count -s $Seconds -a -r 3 -AcceptEula $Script:DataPath" }
	$procdump = Test-Path "$Script:ProcDumpCommand"
	if ($procdump) {
		try {
			$ps = new-object System.Diagnostics.Process
			$ps.StartInfo.Filename = "$Script:ProcDumpCommand"
			$ps.StartInfo.Arguments = $PDArgs
			$ps.StartInfo.RedirectStandardOutput = $false
			$ps.StartInfo.UseShellExecute = $false
			$ps.start()
			$ps.WaitForExit()
		}
		catch [System.Management.Automation.MethodInvocationException] {
			LogError "Failed to run $Script:ProcDumpCommand $arg"
			Write-Error $_
			Write-Host -ForegroundColor Yellow "Please check the following"
			Write-Host -ForegroundColor Yellow "1. Is LSASS running as PPL?"
			Write-Host -ForegroundColor Yellow "2. Has Windows Defender have Real-Time protection enabled?"
			Write-Host -ForegroundColor Yellow "3. Do you have 3rd party AV blocking process dumps+"
		}
	}
	else {
		Write-Host -ForegroundColor Magenta "Procdump.exe not found at $Script:ProcDumpCommand - Skipping dump collection"
	}
}

function StartRADAR {
	Write-Host -ForegroundColor Gray "-->Enter StartRADAR"
	$lsassProcess = Get-Process "lsass"
	$lsassPid = $lsassProcess.Id.ToString()
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "rdrleakdiag.exe"
	$ps.StartInfo.Arguments = " -p $lsassPid -enable"
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
	Write-Host -ForegroundColor Gray "<-- Leave StartRADAR"
}

function StopRadar {
	Write-Host -ForegroundColor Gray "-->Enter StopRadar"
	$lsassProcess = Get-Process "lsass"
	$lsassPid = $lsassProcess.Id.ToString()
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "rdrleakdiag.exe"
	$ps.StartInfo.Arguments = " -p $lsassPid -snap -nowatson -nocleanup "
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
	Write-Host -ForegroundColor Gray "<-- Leave StopRadar"
}

function StartWPR([string]$arg) {
	Write-Host -ForegroundColor Yellow "Starting Windows Performance Recording..."
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "wpr.exe"
	$ps.StartInfo.Arguments = "$arg"
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
	Write-Host -ForegroundColor Gray "<-- Leave StartWPR"
}
function StopWPR {
	Write-Host -ForegroundColor Yellow "Stopping Windows Performance Recording (WPR) Tracing"
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "wpr.exe"
	$ps.StartInfo.Arguments = " -Stop $Script:DataPath\WPR.ETL"
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
	Write-Host -ForegroundColor Yellow "Windows Performance Recording Stopped"
}

function StartADDiagnostics {
	Write-Host -ForegroundColor Yellow "Starting AD Data Collector"
	##Import custom data collector set xml if it exists
	$customADDSxml = Test-path "$PSScriptRoot\ADDS.xml"
	$StartArgs = ' start "system\Active Directory Diagnostics" -ets'
	if ($customADDSxml) {
		Write-Host "Custom Data Collector Set Found - Importing..."
		$ps = new-object System.Diagnostics.Process
		$ps.StartInfo.Filename = "logman.exe"
		$ps.StartInfo.Arguments = ' -import -name "Enhanced Active Directory Diagnostics" ' + " -xml `"$PSScriptRoot\ADDS.xml`" "
		$ps.StartInfo.RedirectStandardOutput = $false
		$ps.StartInfo.UseShellExecute = $false
		$ps.start()
		$ps.WaitForExit()
		$Script:CustomADDSUsed = $true
		Write-Host "Customer Data Collector Set Imported"
		$StartArgs = ' start "Enhanced Active Directory Diagnostics"'
	}
	$ps1 = new-object System.Diagnostics.Process
	$ps1.StartInfo.Filename = "logman.exe"
	$ps1.StartInfo.Arguments = $StartArgs
	$ps1.StartInfo.RedirectStandardOutput = $false
	$ps1.StartInfo.UseShellExecute = $false
	$ps1.start()
	$ps1.WaitForExit()
	Write-Host -ForegroundColor Yellow "AD Data Collector Set Started"
}

function StopADDiagnostics {
	Write-Host -ForegroundColor Yellow "Stopping AD Data Collector Set"
	if ($Script:CustomADDSUsed) {
		$StartArgs = ' stop "Enhanced Active Directory Diagnostics" '
	}
	else {
		$StartArgs = ' stop "system\Active Directory Diagnostics" -ets'
	}
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "logman.exe"
	$ps.StartInfo.Arguments = $StartArgs
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
}

function StartPerfLog {
	param(
		[bool]$Long
	)
	if ($Long) {
		Write-Host -ForegroundColor Gray "-->Enter StartPerfLog (Long)"
		[string]$StartArg = ' create counter PerfLogLong -o ' + "$Script:DataPath\PerfLogLong.blg" + " -f bincirc -v mmddhhmm -max 300 -c " + "\LogicalDisk(*)\* " + "\Memory\* \Cache\* " + "\Network Interface(*)\* " + "\NTDS(*)\* " + "\Netlogon(*)\* " + "\Database(lsass)\* " + "\Paging File(*)\* " + "\PhysicalDisk(*)\* " + "\Processor(*)\* " + "\Processor Information(*)\* " + "\Process(*)\* " + "\Redirector\* " + "\Server\* " + "\System\* " + "\Server Work Queues(*)\* " + "-si 00:05:00"
		$StartArg1 = 'start "PerfLogLong"'
	}
	else {
		Write-Host -ForegroundColor Gray "-->Enter StartPerfLog (Short)"
		[string]$StartArg = ' create counter PerfLogShort -o ' + "$Script:DataPath\PerfLogShort.blg" + " -f bincirc -v mmddhhmm -max 300 -c " + "\LogicalDisk(*)\* " + "\Memory\* \Cache\* " + "\Network Interface(*)\* " + "\NTDS(*)\* " + "\Netlogon(*)\* " + "\Database(lsass)\* " + "\Paging File(*)\* " + "\PhysicalDisk(*)\* " + "\Processor(*)\* " + "\Processor Information(*)\* " + "\Process(*)\* " + "\Redirector\* " + "\Server\* " + "\System\* " + "\Server Work Queues(*)\* " + "-si 00:00:05"
		$StartArg1 = ' start "PerfLogShort"'
	}
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "logman.exe"
	$ps.StartInfo.Arguments = $StartArg
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()

	$ps1 = new-object System.Diagnostics.Process
	$ps1.StartInfo.Filename = "logman.exe"
	$ps1.StartInfo.Arguments = $StartArg1
	$ps1.StartInfo.RedirectStandardOutput = $false
	$ps1.StartInfo.UseShellExecute = $false
	$ps1.Start()
	$ps1.WaitForExit()
	Write-Host -ForegroundColor Yellow "Short / Long Perflogs started"
}

function StopPerfLogs([bool]$Long = $false) {
	if ($Long) {
		Write-Host -ForegroundColor Yellow "Stopping Perflogs (Long)"
		$StartArgs = ' stop "PerfLogLong"'
		$StartArgs1 = ' delete "PerfLogLong"'
	}
	else {
		Write-Host -ForegroundColor Yellow "Stopping Perflogs (Short)"
		$StartArgs = ' stop "PerfLogShort"'
		$StartArgs1 = ' delete "PerfLogShort"'
	}
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "logman.exe"
	$ps.StartInfo.Arguments = $StartArgs
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()

	$ps1 = new-object System.Diagnostics.Process
	$ps1.StartInfo.Filename = "logman.exe"
	$ps1.StartInfo.Arguments = $StartArgs1
	$ps1.StartInfo.RedirectStandardOutput = $false
	$ps1.StartInfo.UseShellExecute = $false
	$ps1.start()
	$ps1.WaitForExit()
}

function StartLSATracing {
	Write-Host -ForegroundColor Yellow "Starting LSA/LSP Tracing...."
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "logman.exe"
	$ps.StartInfo.Arguments = " start LsaTrace -p {D0B639E0-E650-4D1D-8F39-1580ADE72784} 0x40141F -o $Script:DataPath\LsaTrace.etl -ets"
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
	$LSA = get-itemproperty  -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA
	if ($null -eq $LSA.LspDbgTraceOptions) {
		#Create the value and then set it to TRACE_OPTION_LOG_TO_FILE = 0x1,
		New-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA -name 'LspDbgTraceOptions' -PropertyType DWord -Value '0x1'
	}
	elseif ($LSA.LspDbgTraceOptions -ne '0x1') {
		#Set the existing value to 1
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA -name 'LspDbgTraceOptions' '0x00320001'
	}
	if ($null -eq $LSA.LspDbgInfoLevel) {
		New-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA -name 'LspDbgInfoLevel' -PropertyType DWord -Value '0xF000800'
	}
	elseif ($LSA.LspDbgInfoLevel -ne '0xF000800') {
		Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA -name 'LspDbgInfoLevel' -Value '0xF000800'
	}
	Write-Host -ForegroundColor Yellow "LSA/LSP Tracing Started"
}
function StopLSATracing {
	Write-Host -ForegroundColor Gray "-->Enter StopLSATracing"
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "logman.exe"
	$ps.StartInfo.Arguments = ' stop LsaTrace -ets'
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
	Set-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA -name 'LspDbgTraceOptions'  -Value '0x0'
	Write-Host -ForegroundColor Gray "<--Leave StopLSATracing"
}

function StartSamSrvTracing {
	Write-Host -ForegroundColor Yellow "Starting SamSrv Tracing...."
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "logman.exe"
	$ps.StartInfo.Arguments = " create trace SamSrv -p {F2969C49-B484-4485-B3B0-B908DA73CEBB} 0xffffffffffffffff 0xff -ow -o $Script:DataPath\SamSrv.etl -ets"
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
}

function StopSamSrvTracing {
	Write-Host -ForegroundColor Gray "-->Enter StopSamSrvTracing"
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "logman.exe"
	$ps.StartInfo.Arguments = ' stop SamSrv -ets'
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
	Write-Host -ForegroundColor Gray "<--Leave StopSamSrvTracing"
}

function StartNetTrace {
	Write-Host -ForegroundColor Yellow "Starting Network Capture"
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "netsh.exe"
	$ps.StartInfo.Arguments = " trace start scenario=netconnection capture=yes tracefile=$Script:DataPath\\nettrace.etl"
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
}

function StopNetTrace {
	Write-Host -ForegroundColor Yellow "Stopping Network Capture"
	$ps = new-object System.Diagnostics.Process
	$ps.StartInfo.Filename = "netsh.exe"
	$ps.StartInfo.Arguments = " trace stop"
	$ps.StartInfo.RedirectStandardOutput = $false
	$ps.StartInfo.UseShellExecute = $false
	$ps.start()
	$ps.WaitForExit()
}

function Enable1644RegKeys([bool]$useCustomValues = $false, $searchTimeValue = "50", $expSearchResultsValue = "10000", $inEfficientSearchResultsValue = "1000") {
	##make sure the Event Log is at least 50MB
	$DirSvcLog = Get-WmiObject -Class Win32_NTEventLogFile -Filter "LogFileName = 'Directory Service'"
	$MinLogSize = 50 * 1024 * 1024
	if ($DirSvcLog.MaxFileSize -lt $MinLogSize) {
		Write-Host "Increasing the Directory Service Event Log Size to 50MB"
		Limit-EventLog -LogName "Directory Service" -MaximumSize 50MB
	}
	$registryPathFieldEngineering = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
	$fieldEngineering = "15 Field Engineering"
	$fieldEngineeringValue = "5"
	$DiagnosticsKey = get-itemproperty -Path $registryPathFieldEngineering
	$Script:FieldEngineering = $DiagnosticsKey."15 Field Engineering"
	##$Script:FieldEngineering = get-itemproperty -Path $registryPathFieldEngineering -Name $fieldEngineering
	New-ItemProperty -Path $registryPathFieldEngineering -Name $fieldEngineering -Value $fieldEngineeringValue -PropertyType DWORD -Force | Out-Null
	if ($useCustomValues) {
		$registryPathParameters = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
		$thresholdsKey = get-itemproperty -Path $registryPathParameters
		##Only set custom thresholds if there are none previously defined by customer
		if (($null -eq $thresholdsKey."Search Time Threshold (msecs)") -and ($null -eq $thresholdsKey."Expensive Search Results Threshold") -and ($null -eq $thresholdsKey."Inefficient Search Results Threshold")) {
			$searchTime = "Search Time Threshold (msecs)"
			New-ItemProperty -Path $registryPathParameters -Name $searchTime -Value $searchTimeValue -PropertyType DWORD -Force | Out-Null
			$expSearchResults = "Expensive Search Results Threshold"
			New-ItemProperty -Path $registryPathParameters -Name $expSearchResults -Value $expSearchResultsValue -PropertyType DWORD -Force | Out-Null
			$inEfficientSearchResults = "Inefficient Search Results Threshold"
			New-ItemProperty -Path $registryPathParameters -Name $inEfficientSearchResults -Value $inEfficientSearchResultsValue -PropertyType DWORD -Force | Out-Null
			$Script:Custom1644 = $true
		}
	}
}

function Disable1644RegKeys {
	$registryPathFieldEngineering = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
	$fieldEngineering = "15 Field Engineering"
	New-ItemProperty -Path $registryPathFieldEngineering -Name $fieldEngineering -Value $Script:FieldEngineering -PropertyType DWORD -Force | Out-Null
	if ($Script:Custom1644) {
		##Safest to just remove these entries so it reverts back to default
		$registryPathParameters = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
		$searchTime = "Search Time Threshold (msecs)"
		Remove-ItemProperty -Path $registryPathParameters -Name $searchTime
		$expSearchResults = "Expensive Search Results Threshold"
		Remove-ItemProperty -Path $registryPathParameters -Name $expSearchResults
		$inEfficientSearchResults = "Inefficient Search Results Threshold"
		Remove-ItemProperty -Path $registryPathParameters -Name $inEfficientSearchResults
	}
}

function CorrelateDataAndCleanup {
	##Copy Directory Services Event Log
	if ($Script:IsDC) {
		Copy-Item -Path "$env:SystemRoot\System32\Winevt\Logs\Directory Service.evtx" -dest "$Script:DataPath" -force
	}
	Copy-Item -Path "$env:SystemRoot\Debug\Netlogon.log" -dest $Script:DataPath -Force
	$NetlogonBakExists = Test-Path "$env:SystemRoot\Debug\Netlogon.bak"
	if ($NetlogonBakExists) {
		Copy-Item -Path "$env:SystemRoot\Debug\Netlogon.bak" -dest $Script:DataPath -Force
	}
	Disable1644RegKeys
	New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "DBFlag" -Value $Script:NetLogonDBFlags -PropertyType DWORD -Force | Out-Null
	StopLSATracing
	Copy-Item -Path "$env:SystemRoot\Debug\lsp.log" -dest $Script:DataPath -Force
	StopSamSrvTracing
	##Do all the AD Data Collector stuff
	$perflogPath =$PerfLogsRoot + "\ADDS"
	if ($Script:CustomADDSUsed) {
		$perflogPath =$PerfLogsRoot + "\Enhanced-ADDS"	
	}
	Write-Host -ForegroundColor Yellow "Waiting for report.html creation to be complete, this process can take a while to complete..."
	$ADDataCollectorPath = Get-ChildItem $perflogPath | Sort-Object CreationTime -Descending | Select-Object -First 1 -ErrorAction SilentlyContinue
	## just a fail safe in case for whatever reason the custom ADDS data collector import failed
	if (!$ADDataCollectorPath) {
		Write-Host -ForegroundColor Red "AD Data Collector path was not found... skipping"
		return
	}
	$Attempts = 0;
	while ($true) {
		$reportcomplete = Test-Path "$perflogPath\$ADDataCollectorPath\Report.html"
		if ($reportcomplete -or [int]$Attempts -eq 120) {
			break
		}
		Start-Sleep -Seconds 30
		$Attempts = [int]$Attempts + 1
	}
	if ([int]$Attempts -eq 120) {
		Write-Host "Waited an hour and the report is still not generated, copying just the raw data that is available"
	}
	else {
		Write-Host "Report.html compile completed"
	}
	Get-ChildItem $perflogPath | Sort-Object CreationTime -Descending | Select-Object -First 1 | Copy-Item -Destination $Script:DataPath -Recurse -Force
	if ($Script:CustomADDSUsed) {
		## have to clean up the source folder otherwise the subsequent runs will fail as it will try to re-use existing folder name
		Get-ChildItem $perflogPath | Sort-Object CreationTime -Descending | Select-Object -First 1 | Remove-Item -Recurse -Force
		$ps1 = new-object System.Diagnostics.Process
		$ps1.StartInfo.Filename = "logman.exe"
		$ps1.StartInfo.Arguments = ' delete "Enhanced Active Directory Diagnostics" '
		$ps1.StartInfo.RedirectStandardOutput = $false
		$ps1.StartInfo.UseShellExecute = $false
		$ps1.start()
		$ps1.WaitForExit()
	}
}
function StopFailedTracing {
	Write-Host -ForegroundColor Cyan "->8:  A previous collection failed or was cancelled prematurely this option will just attempt to stop everything that might still be running"
	StopWPR
	$customADDSxml = Test-path "$PSScriptRoot\ADDS.xml"
	if ($customADDSxml) {
		$Script:CustomADDSUsed = $true
	}
	StopADDiagnostics
	StopLSATracing
	StopSamSrvTracing
	StopPerfLogs $true
	StopPerfLogs $false
	if ($Script:CustomADDSUsed) {
		## have to clean up the source folder otherwise the subsequent runs will fail as it will try to re-use existing folder name
		$perflogPath =$PerfLogsRoot + "\Enhanced-ADDS"
		Get-ChildItem $perflogPath | Sort-Object CreationTime -Descending | Select-Object -First 1 | Remove-Item -Recurse -Force
		$ps1 = new-object System.Diagnostics.Process
		$ps1.StartInfo.Filename = "logman.exe"
		$ps1.StartInfo.Arguments = ' delete "Enhanced Active Directory Diagnostics" '
		$ps1.StartInfo.RedirectStandardOutput = $false
		$ps1.StartInfo.UseShellExecute = $false
		$ps1.start()
		$ps1.WaitForExit()
	}
}

[void][System.Reflection.Assembly]::Load('System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
[void][System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')

function ShowEULAPopup($mode) {
	$EULA = New-Object -TypeName System.Windows.Forms.Form
	$richTextBox1 = New-Object System.Windows.Forms.RichTextBox
	$btnAcknowledge = New-Object System.Windows.Forms.Button
	$btnCancel = New-Object System.Windows.Forms.Button
	$EULA.SuspendLayout()
	$EULA.Name = "EULA"
	$EULA.Text = "Microsoft Diagnostic Tools End User License Agreement"
	$richTextBox1.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
	$richTextBox1.Location = New-Object System.Drawing.Point(12, 12)
	$richTextBox1.Name = "richTextBox1"
	$richTextBox1.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
	$richTextBox1.Size = New-Object System.Drawing.Size(776, 397)
	$richTextBox1.TabIndex = 0
	$richTextBox1.ReadOnly = $True
	$richTextBox1.Add_LinkClicked({ Start-Process -FilePath $_.LinkText })
	$richTextBox1.Rtf = @"
{\rtf1\ansi\ansicpg1252\deff0\nouicompat{\fonttbl{\f0\fswiss\fprq2\fcharset0 Segoe UI;}{\f1\fnil\fcharset0 Calibri;}{\f2\fnil\fcharset0 Microsoft Sans Serif;}}
{\colortbl ;\red0\green0\blue255;}
{\*\generator Riched20 10.0.19041}{\*\mmathPr\mdispDef1\mwrapIndent1440 }\viewkind4\uc1
\pard\widctlpar\f0\fs19\lang1033 MICROSOFT SOFTWARE LICENSE TERMS\par
Microsoft Diagnostic Scripts and Utilities\par
\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}These license terms are an agreement between you and Microsoft Corporation (or one of its affiliates). IF YOU COMPLY WITH THESE LICENSE TERMS, YOU HAVE THE RIGHTS BELOW. BY USING THE SOFTWARE, YOU ACCEPT THESE TERMS.\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}\par
\pard
{\pntext\f0 1.\tab}{\*\pn\pnlvlbody\pnf0\pnindent0\pnstart1\pndec{\pntxta.}}
\fi-360\li360 INSTALLATION AND USE RIGHTS. Subject to the terms and restrictions set forth in this license, Microsoft Corporation (\ldblquote Microsoft\rdblquote ) grants you (\ldblquote Customer\rdblquote  or \ldblquote you\rdblquote ) a non-exclusive, non-assignable, fully paid-up license to use and reproduce the script or utility provided under this license (the "Software"), solely for Customer\rquote s internal business purposes, to help Microsoft troubleshoot issues with one or more Microsoft products, provided that such license to the Software does not include any rights to other Microsoft technologies (such as products or services). \ldblquote Use\rdblquote  means to copy, install, execute, access, display, run or otherwise interact with the Software. \par
\pard\widctlpar\par
\pard\widctlpar\li360 You may not sublicense the Software or any use of it through distribution, network access, or otherwise. Microsoft reserves all other rights not expressly granted herein, whether by implication, estoppel or otherwise. You may not reverse engineer, decompile or disassemble the Software, or otherwise attempt to derive the source code for the Software, except and to the extent required by third party licensing terms governing use of certain open source components that may be included in the Software, or remove, minimize, block, or modify any notices of Microsoft or its suppliers in the Software. Neither you nor your representatives may use the Software provided hereunder: (i) in a way prohibited by law, regulation, governmental order or decree; (ii) to violate the rights of others; (iii) to try to gain unauthorized access to or disrupt any service, device, data, account or network; (iv) to distribute spam or malware; (v) in a way that could harm Microsoft\rquote s IT systems or impair anyone else\rquote s use of them; (vi) in any application or situation where use of the Software could lead to the death or serious bodily injury of any person, or to physical or environmental damage; or (vii) to assist, encourage or enable anyone to do any of the above.\par
\par
\pard\widctlpar\fi-360\li360 2.\tab DATA. Customer owns all rights to data that it may elect to share with Microsoft through using the Software. You can learn more about data collection and use in the help documentation and the privacy statement at {{\field{\*\fldinst{HYPERLINK https://aka.ms/privacy }}{\fldrslt{https://aka.ms/privacy\ul0\cf0}}}}\f0\fs19 . Your use of the Software operates as your consent to these practices.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 3.\tab FEEDBACK. If you give feedback about the Software to Microsoft, you grant to Microsoft, without charge, the right to use, share and commercialize your feedback in any way and for any purpose.\~ You will not provide any feedback that is subject to a license that would require Microsoft to license its software or documentation to third parties due to Microsoft including your feedback in such software or documentation. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 4.\tab EXPORT RESTRICTIONS. Customer must comply with all domestic and international export laws and regulations that apply to the Software, which include restrictions on destinations, end users, and end use. For further information on export restrictions, visit {{\field{\*\fldinst{HYPERLINK https://aka.ms/exporting }}{\fldrslt{https://aka.ms/exporting\ul0\cf0}}}}\f0\fs19 .\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 5.\tab REPRESENTATIONS AND WARRANTIES. Customer will comply with all applicable laws under this agreement, including in the delivery and use of all data. Customer or a designee agreeing to these terms on behalf of an entity represents and warrants that it (i) has the full power and authority to enter into and perform its obligations under this agreement, (ii) has full power and authority to bind its affiliates or organization to the terms of this agreement, and (iii) will secure the permission of the other party prior to providing any source code in a manner that would subject the other party\rquote s intellectual property to any other license terms or require the other party to distribute source code to any of its technologies.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 6.\tab DISCLAIMER OF WARRANTY. THE SOFTWARE IS PROVIDED \ldblquote AS IS,\rdblquote  WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL MICROSOFT OR ITS LICENSORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\par
\pard\widctlpar\qj\par
\pard\widctlpar\fi-360\li360\qj 7.\tab LIMITATION ON AND EXCLUSION OF DAMAGES. IF YOU HAVE ANY BASIS FOR RECOVERING DAMAGES DESPITE THE PRECEDING DISCLAIMER OF WARRANTY, YOU CAN RECOVER FROM MICROSOFT AND ITS SUPPLIERS ONLY DIRECT DAMAGES UP TO U.S. $5.00. YOU CANNOT RECOVER ANY OTHER DAMAGES, INCLUDING CONSEQUENTIAL, LOST PROFITS, SPECIAL, INDIRECT, OR INCIDENTAL DAMAGES. This limitation applies to (i) anything related to the Software, services, content (including code) on third party Internet sites, or third party applications; and (ii) claims for breach of contract, warranty, guarantee, or condition; strict liability, negligence, or other tort; or any other claim; in each case to the extent permitted by applicable law. It also applies even if Microsoft knew or should have known about the possibility of the damages. The above limitation or exclusion may not apply to you because your state, province, or country may not allow the exclusion or limitation of incidental, consequential, or other damages.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 8.\tab BINDING ARBITRATION AND CLASS ACTION WAIVER. This section applies if you live in (or, if a business, your principal place of business is in) the United States.  If you and Microsoft have a dispute, you and Microsoft agree to try for 60 days to resolve it informally. If you and Microsoft can\rquote t, you and Microsoft agree to binding individual arbitration before the American Arbitration Association under the Federal Arbitration Act (\ldblquote FAA\rdblquote ), and not to sue in court in front of a judge or jury. Instead, a neutral arbitrator will decide. Class action lawsuits, class-wide arbitrations, private attorney-general actions, and any other proceeding where someone acts in a representative capacity are not allowed; nor is combining individual proceedings without the consent of all parties. The complete Arbitration Agreement contains more terms and is at {{\field{\*\fldinst{HYPERLINK https://aka.ms/arb-agreement-4 }}{\fldrslt{https://aka.ms/arb-agreement-4\ul0\cf0}}}}\f0\fs19 . You and Microsoft agree to these terms. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 9.\tab LAW AND VENUE. If U.S. federal jurisdiction exists, you and Microsoft consent to exclusive jurisdiction and venue in the federal court in King County, Washington for all disputes heard in court (excluding arbitration). If not, you and Microsoft consent to exclusive jurisdiction and venue in the Superior Court of King County, Washington for all disputes heard in court (excluding arbitration).\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 10.\tab ENTIRE AGREEMENT. This agreement, and any other terms Microsoft may provide for supplements, updates, or third-party applications, is the entire agreement for the software.\par
\pard\sa200\sl276\slmult1\f1\fs22\lang9\par
\pard\f2\fs17\lang2057\par
}
"@
	$richTextBox1.BackColor = [System.Drawing.Color]::White
	$btnAcknowledge.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
	$btnAcknowledge.Location = New-Object System.Drawing.Point(544, 415)
	$btnAcknowledge.Name = "btnAcknowledge";
	$btnAcknowledge.Size = New-Object System.Drawing.Size(119, 23)
	$btnAcknowledge.TabIndex = 1
	$btnAcknowledge.Text = "Accept"
	$btnAcknowledge.UseVisualStyleBackColor = $True
	$btnAcknowledge.Add_Click({ $EULA.DialogResult = [System.Windows.Forms.DialogResult]::Yes })

	$btnCancel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
	$btnCancel.Location = New-Object System.Drawing.Point(669, 415)
	$btnCancel.Name = "btnCancel"
	$btnCancel.Size = New-Object System.Drawing.Size(119, 23)
	$btnCancel.TabIndex = 2
	if ($mode -ne 0) {
		$btnCancel.Text = "Close"
	}
	else {
		$btnCancel.Text = "Decline"
	}
	$btnCancel.UseVisualStyleBackColor = $True
	$btnCancel.Add_Click({ $EULA.DialogResult = [System.Windows.Forms.DialogResult]::No })

	$EULA.AutoScaleDimensions = New-Object System.Drawing.SizeF(6.0, 13.0)
	$EULA.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
	$EULA.ClientSize = New-Object System.Drawing.Size(800, 450)
	$EULA.Controls.Add($btnCancel)
	$EULA.Controls.Add($richTextBox1)
	if ($mode -ne 0) {
		$EULA.AcceptButton = $btnCancel
	}
	else {
		$EULA.Controls.Add($btnAcknowledge)
		$EULA.AcceptButton = $btnAcknowledge
		$EULA.CancelButton = $btnCancel
	}
	$EULA.ResumeLayout($false)
	$EULA.Size = New-Object System.Drawing.Size(800, 650)

	Return ($EULA.ShowDialog())
}

function ShowEULAIfNeeded($toolName, $mode) {
	$eulaRegPath = "HKCU:Software\Microsoft\CESDiagnosticTools"
	$eulaAccepted = "No"
	$eulaValue = $toolName + " EULA Accepted"
	if (Test-Path $eulaRegPath) {
		$eulaRegKey = Get-Item $eulaRegPath
		$eulaAccepted = $eulaRegKey.GetValue($eulaValue, "No")
	}
	else {
		$eulaRegKey = New-Item $eulaRegPath
	}
	if ($mode -eq 2) {
		# silent accept
		$eulaAccepted = "Yes"
		$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
	}
	else {
		if ($eulaAccepted -eq "No") {
			$eulaAccepted = ShowEULAPopup($mode)
			if ($eulaAccepted -eq [System.Windows.Forms.DialogResult]::Yes) {
				$eulaAccepted = "Yes"
				$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
			}
		}
	}
	return $eulaAccepted
}

#region MAIN   =====================================

## EULA
# Show EULA if needed.
If ($AcceptEULA.IsPresent) {
	$eulaAccepted = ShowEULAIfNeeded "AD Perf Data Collection Tool" 2  # Silent accept mode.
}
Else {
	$eulaAccepted = ShowEULAIfNeeded "AD Perf Data Collection Tool" 0  # Show EULA popup at first run.
}
if ($eulaAccepted -eq "No") {
	Write-Error "EULA not accepted, exiting!"
	exit -1
}
$exists = Test-Path $Script:ADPerfFolder
if ($exists) {
	Write-Host "$Script:ADPerfFolder already exists - using existing folder"
}
else {
	New-Item $ADPerfFolder -type directory | Out-Null
	Write-Host "Created AD Perf Data Folder: $ADPerfFolder"
}

Write-Host ""
Write-Host ""

if ($Scenario -eq 0) {
	ADPerf-Menu
	$Script:Interactive = $true
	$Selection = Read-Host "=> Choose the scenario you are troubleshooting"
}
else {
	$Selection = $Scenario
	# Checking for thresholds
	if (($Selection -eq 2 -or $Selection -eq 4) -and $Threshold -eq 0) {
		throw "FATAL: -Threshold must be supplied in scenarios 2 & 4"
	}
	if ($Threshold -ne 0) {
		$Script:TriggerThreshold = $Threshold
		$Script:TriggerScenario = $true
	}
	if ($DelayStop -ne 0) {
		$Script:TriggerScenario = $true
		$Script:TriggeredTimerLength = $DelayStop
	}
}

$DateTime = Get-Date -Format yyyyMMddMMTHHmmss
$Script:DataPath = "$Script:ADPerfFolder\" + $env:computername + "_" + $DateTime + "_Scenario_" + $Selection
if ($Selection -gt 0 -and $Selection -lt 9) {
	New-Item $Script:DataPath -type directory | Out-Null
}
$ComputerInfo = Get-ComputerInfo
if ($ComputerInfo.CsDomainRole -eq "BackupDomainController" -or $ComputerInfo.CsDomainRole -eq "PrimaryDomainController") {
	$Script:IsDC = $true
	Write-Host "Detected running on Domain Controller"
}
else {
	Write-Host "Detected running on Member Server"
}
$Script:DumpType = $DumpPreference
switch ($Selection) {
	1 { HighCpuDataCollection }
	2 { HighCpuDataCollectionTriggerStart }
	3 { HighMemoryDataCollection }
	4 { HighMemoryDataCollectionTriggerStart }
	5 {
		if (!$Script:IsDC) { throw "This scenario is only supported on Domain Controllers" }
		ATQThreadDataCollection
	}
	6 { BaseLineDataCollection }
	7 { LongBaseLineCollection }
	8 { StopFailedTracing }
	'q' {}
}

if ($Selection -gt 0 -and $Selection -lt 8) {
	Write-Host "Copying Data to $ADPerfFolder and performing cleanup"
	if ($Script:IsDC) {
		dcdiag /v | Out-File $Script:DataPath\DCDiag.txt
	}
	tasklist /svc | Out-File $Script:DataPath\tasklist.txt
	tasklist /v /fo csv | Out-File $Script:DataPath\Tasklist.csv
	netstat -anoq | Out-File $Script:DataPath\Netstat.txt
	CorrelateDataAndCleanup
	if ($Script:IsDC) {
		Copy-Item "$env:SystemRoot\system32\ntdsai.dll" -Destination $Script:DataPath
		Copy-Item "$env:SystemRoot\system32\ntdsatq.dll" -Destination $Script:DataPath
	}
	Copy-Item "$env:SystemRoot\system32\samsrv.dll" -Destination $Script:DataPath
	Copy-Item "$env:SystemRoot\system32\lsasrv.dll" -Destination $Script:DataPath
	Copy-Item "$env:Temp\RDR*" -Destination $Script:DataPath -Recurse -Force -ErrorAction SilentlyContinue
	Write-Host -ForegroundColor Green "Data copy is finsihed, please zip the $Script:DataPath folder and upload to DTM"
}

#endregion MAIN   =====================================


# SIG # Begin signature block
# MIInpQYJKoZIhvcNAQcCoIInljCCJ5ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBxRMKRWpq+pn8i
# B10LNvUn9PPN1DQveWXDr5yAP/TOPqCCDYUwggYDMIID66ADAgECAhMzAAADTU6R
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIA+Q
# uLo094ixiKgEr/KLQVxh4wo9iyzGHSzVX7TbQREIMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAEy52prJtkj+FmN8jo/luJku6Bx9gBRXqtAQ/
# Vtv8Whi8xuKLwCer8ntbFLYzh3tG6lDGMzUB8ea+ekuusFhyxoV9iWd5nwtMiAB1
# UVXhcqQ2Rb9RCoftLC3gUDRISxXNb4SBl6zpJ2sFYvRKAXg6OXWmplMyf936UGrk
# E1XlL0epEG7NDFg+YbuSUlaS6Mk7aPGSNJXTnfgMExC6Rg3pQnCxMGbEAXxYPfeD
# K3yFE57jFOmKUsyECo9l8sofbQ4x+ZruwRKkkuWs1QYLqBn8hu9MREE2XqvwxqW2
# 9X5cHZ7o7FQdew1rQUUjEhTdX9rStKPbazSm3pEhprP5Tmd4LqGCFwAwghb8Bgor
# BgEEAYI3AwMBMYIW7DCCFugGCSqGSIb3DQEHAqCCFtkwghbVAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCC51hTJSGmZtnFTNu5C7fJ8ETA1uXjzKAxN
# pXzCSqpm4wIGZGzCbD1BGBMyMDIzMDYwNjExNDU1NS42ODRaMASAAgH0oIHQpIHN
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
# hvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIEQeYWADY6BtKTQZzxEfbGP8DAAVabd6
# j87rP/4/hHpoMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgGQGxkfYkd0wK
# +V09wO0sO+sm8gAMyj5EuKPqvNQ/fLEwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMAITMwAAAcUDzc0hofTvOQABAAABxTAiBCAUBiLXb89pWwpW
# fiLt7KCdsFZonG2R84rYVWZMvQb62DANBgkqhkiG9w0BAQsFAASCAgArROF9vMNG
# 3R1iJ+X2/w+GjrVH4b0zslp+Tkkeja3f3jhxWoqx81tgd3TizX5riYzF92b2ugGf
# Iib42V7uVf3JBOdF1t6RH7bRcyYF4dY/JnjvHWyJMKUpZFX+Nlt+eZFyFWmJEGEK
# SLK8aagPlJMbJHGdOu3KYu+SWNNZYQ2qAGx2NFWjZF4EfxrxLLssItBuGUmM5FpG
# r+UA56rn0/iRB5VDNUna4D8yMzvTEj45hYXJLmFh+AZHOoNC0mKeFBb867RyfAli
# ILmwzpdwQVp6Nmnz0VHYtddHOCQyl3hWlRJ0kcjBh7GsRtGS63sRMLmpLDyo1QIc
# DPbdpnrV+oyzHqMSIe0+Qcks0+9sWIsZ+VSujHOw0/avEWAzVGNbT82oAuZN4D1z
# YIVeQ67QW8CkrIAHJfpABkpA5mn30coLYgAWHsoCS9BWVFlBY5PVijMyxiZnWAaJ
# jceVI5Hikg7K1PZAXLspsJRi0BmlGJNJIHyo2qsdDeTBsa4UWZD4THyNUA17XrUv
# hM9wuvLtdZeCuVVLi3Q4vDmJR694katR6tlPLVslVIqnx84Zf6Cc8JMGrZWkNCYw
# VXeFGSW8Uam5dbB2YyfFj8cU8FibsX/de2mmpbq5H/SbMhJoPi7gICn1nOqQi7Qz
# SvvP6FSUOqXpXMTRa5+mWYbz2RdD5YXPsQ==
# SIG # End signature block
