<# File: tss_MDEClientAnalyzer.ps1
.SYNOPSIS
 
.NOTES
    Author: MDE OPS Team
    Date/Version: See $ScriptVer
#>
param (
	[string]$DataPath, 
	[switch]$AcceptEula,
	[string]$outputDir = $PSScriptRoot, 
	## To collect netsh traces -n 
	[Alias("n")][switch]$netTrace,
	[Alias("w", "wfp")][switch]$wfpTrace,
	##To collect Sense performance traces '-l' or '-h'
	[Alias("l")][switch]$wprpTraceL,
	[Alias("h")][switch]$wprpTraceH,
	##To collect Sense app compatibility traces '-c'
	[Alias("c")][switch]$AppCompatC,
	##To collect Sense dumps '-d'
	[Alias("d")][switch]$CrashDumpD,
	##To collect traces for isolation issues '-i'
	[Alias("i")][switch]$NetTraceI,
	##To collect boot traces issues at startup '-b'
	[Alias("b")][switch]$BootTraceB,
	##To collect traces for WD AntiVirus pref issues '-a'
	[Alias("a")][switch]$WDPerfTraceA,
	##To collect verbose traces for WD AntiVirus issues '-v'
	[Alias("v")][switch]$WDVerboseTraceV,
	##To collect verbose traces for DLP issues '-t'
	[Alias("t")][switch]$DlpT,
	##To collect quick DLP Diagnose run '-q'
	[Alias("q")][switch]$DlpQ,
	##To prepare the device for full dump collection '-z'
	[Alias("z")][switch]$FullCrashDumpZ,
	##To set the device for remote data collection '-r'
	[Alias("r")][switch]$RemoteRun,
	##To set the minutes to run for data collection '-m'
	[Alias("m")][int]$MinutesToRun = "5",
	##To crash the device and create a memory dump immediately '-k'
	[Alias("K")][switch]$NotMyFault
)

# adjustments for running within TSS; ProcMon/ProcDump/NotMyFault exe's are in separate \BIN or \BINARM folders; psExec.exe is in \BIN folder
[string]$arch = (Get-WmiObject -Class Win32_OperatingSystem).OSArchitecture
if ($arch -like "ARM*") {
	$ARM = $true
	$ARMcommand = "-ARM"
}

if (!$DataPath) {$outputDir = $PSScriptRoot} else {$outputDir = $DataPath}

# Global variables
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8  # MDEClientAnalyzer.exe outputs UTF-8, so interpret its output as such
$ProcessWaitMin = 5	# wait max minutes to complete
#$ToolsDir = Join-Path $PSScriptRoot "DefTools"
$ToolsDir = Join-Path $global:ScriptFolder "scripts\DefTools"
$ToolsExeDir = Join-Path $global:ScriptFolder "BIN" 
$ToolsArcExeDir = Join-Path $global:ScriptFolder "BIN" 
if($ARM) {$ToolsArcExeDir = Join-Path $global:ScriptFolder "BINARM"} # based on ARM Arch PromMon/ProcDump/NotMyFaultc will be found in BINARM
$buildNumber = ([System.Environment]::OSVersion).Version.build
#Enforcing default PSModulePath to avoid getting unexpected modules to run instead of built-in modules
$env:PSModulePath = "C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules"

$NotMyFaultCommand = Join-Path $ToolsArcExeDir "NotMyFaultc.exe"
$ProcmonCommand = Join-Path $ToolsArcExeDir "ProcMon.exe"
$ProcDumpCommand = Join-Path $ToolsArcExeDir "ProcDump.exe"
		
# Define outputs
$resultOutputDir = Join-Path $outputDir "MDEClientAnalyzerResult"
$SysLogs = Join-Path $resultOutputDir "SystemInfoLogs"
$psrFile = Join-Path $resultOutputDir "Psr.zip"
$ProcMonlog = Join-Path $resultOutputDir "Procmonlog.pml"
$connectivityCheckFile = Join-Path $SysLogs "MDEClientAnalyzer.txt"
$connectivityCheckUserFile = Join-Path $SysLogs "MDEClientAnalyzer_User.txt"
$MsSenseDump = Join-Path $resultOutputDir "MsSense.dmp"
$MsSenseSDump = Join-Path $resultOutputDir "MsSenseS.dmp"
$outputZipFile = Join-Path $outputDir "MDEClientAnalyzerResult.zip"
$WprpTraceFile = Join-Path  $resultOutputDir "FullSenseClient.etl"
$XmlLogFile = Join-Path $SysLogs "MDEClientAnalyzer.xml"
$XslFile = Join-Path $ToolsDir "MDEReport.xslt"
$RegionsJson = Join-Path $ToolsDir "RegionsURLs.json"
$EndpointList = Join-Path $ToolsDir "endpoints.txt"
$ResourcesJson = Join-Path $ToolsDir "Events.json"
$HtmOutputFile = Join-Path $resultOutputDir "MDEClientAnalyzer.htm"
$CertSignerResults = "$resultOutputDir\SystemInfoLogs\CertSigner.log"
$CertResults = "$resultOutputDir\SystemInfoLogs\CertValidate.log"

$OSPreviousVersion = $false
$AVPassiveMode = $false
$ScriptVer = "28042022"
$AllRegionsURLs = @{}

#region Functions ---------
# function to read Registry Value
function Get-RegistryValue {
	param (
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$Path,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$Value
	)

	if (Test-Path -path $Path) {
		return Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction "SilentlyContinue"
	}
 else {
		return $false
	}
}

# This telnet test does not support proxy as-is
Function TelnetTest($RemoteHost, $port) { 
	[int32]$TimeOutSeconds = 10000
	Try {
		$tcp = New-Object System.Net.Sockets.TcpClient
		$connection = $tcp.BeginConnect($RemoteHost, $Port, $null, $null)
		$connection.AsyncWaitHandle.WaitOne($TimeOutSeconds, $false)  | Out-Null 
		if ($tcp.Connected -eq $true) {
			$ConnectionResult = "Successfully connected to Host: $RemoteHost on Port: $Port"
		}
		else {
			$ConnectionResult = "Could not connect to Host: $RemoteHost on Port: $Port"
		}
	} 
	Catch {
		$ConnectionResult = "Unknown Error"
	}
	return $ConnectionResult
}


function Write-ReportEvent($severity, $id, $category, $check, $checkresult, $guidance) { 
	$checkresult_txtfile = [regex]::replace($checkresult, '<br>', '')
	$guidance_txtfile = [regex]::replace($guidance, '<br>', '')
	# Write Message to the screen
	$descLine = ((Get-Date).ToString("u") + " [$severity]" + " $check" + " $id" + ": " + $checkresult_txtfile + " " + $guidance_txtfile )
	if ($severity -eq "Error") {
		Write-Host -BackgroundColor Red -ForegroundColor Yellow $descLine
	}
 elseif ($severity -eq "Warning") {
		Write-Host -ForegroundColor Yellow $descLine
	}
 else {
		Write-Host $descLine
	}
	# Write message to the ConnectivityCheckFile
	$descLine | Out-File $connectivityCheckFile -append

	# Write Message to XML
	$subsectionNode = $script:xmlDoc.CreateNode("element", "event", "")
	$subsectionNode.SetAttribute("id", $id)

	$eventContext1 = $script:xmlDoc.CreateNode("element", "severity", "")
	$eventContext1.psbase.InnerText = $severity

	$eventContext2 = $script:xmlDoc.CreateNode("element", "category", "")
	$eventContext2.psbase.InnerText = $category

	$eventContext3 = $script:xmlDoc.CreateNode("element", "check", "")
	$eventContext3.psbase.InnerText = $check

	$eventContext4 = $script:xmlDoc.CreateNode("element", "checkresult", "")
	$eventContext4.psbase.InnerText = $checkresult

	$eventContext5 = $script:xmlDoc.CreateNode("element", "guidance", "")
	$eventContext5.psbase.InnerText = $guidance

	$subsectionNode.AppendChild($eventContext1) | out-Null
	$subsectionNode.AppendChild($eventContext2) | out-Null
	$subsectionNode.AppendChild($eventContext3) | out-Null
	$subsectionNode.AppendChild($eventContext4) | out-Null
	$subsectionNode.AppendChild($eventContext5) | out-Null
    
	$xmlRoot = $script:xmlDoc.SelectNodes("/MDEResults")
	$InputNode = $xmlRoot.SelectSingleNode("events")
	$InputNode.AppendChild($subsectionNode) | Out-Null
}
<#
function Write-Report($section, $subsection, $value, $DisplayName) {  
	$subsectionNode = $script:xmlDoc.CreateNode("element", $subsection, "")    
	$subsectionNode.SetAttribute("displayName", $DisplayName)
	$subsectionNode.psbase.InnerText = $value

	$checkresult = $DisplayName + ": " + $Value
	# Write message to the ConnectivityCheckFile
	$checkresult | Out-File $connectivityCheckFile -append

	$xmlRoot = $script:xmlDoc.SelectNodes("/MDEResults")
	$InputNode = $xmlRoot.SelectSingleNode($section)
	$InputNode.AppendChild($subsectionNode) | Out-Null
}
#>

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

function Format-XML ([xml]$xml) {
	$StringWriter = New-Object System.IO.StringWriter
	$XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter
	$xmlWriter.Formatting = [System.Xml.Formatting]::Indented
	$xml.WriteContentTo($XmlWriter)
	Write-Output $StringWriter.ToString()
}

function ShowDlpPolicy($policyName) {
	$byteArray = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection' -Name $policyName
	$memoryStream = New-Object System.IO.MemoryStream(, $byteArray)
	$deflateStream = New-Object System.IO.Compression.DeflateStream($memoryStream, [System.IO.Compression.CompressionMode]::Decompress)
	$streamReader = New-Object System.IO.StreamReader($deflateStream, [System.Text.Encoding]::Unicode)
	$policyStr = $streamReader.ReadToEnd()
	$policy = $policyStr | ConvertFrom-Json
	$policyBodyCmd = ($policy.body | ConvertFrom-Json).cmd
	$policyBodyCmd | Format-List -Property hash, type, cmdtype, id, priority, timestamp, enforce | Out-File "$resultOutputDir\DLP\$policyName.txt"

	$timestamp = [datetime]$policyBodyCmd.timestamp
	"Timestamp: $($timestamp.ToString('u'))" | Out-File "$resultOutputDir\DLP\$policyName.txt" -Append

	# convert from/to json so it's JSON-formatted
	$params = $policyBodyCmd.paramsstr | ConvertFrom-Json
	$params | ConvertTo-Json -Depth 20 > "$resultOutputDir\DLP\$policyName.json"

	if ($params.SensitiveInfoPolicy) {
		foreach ($SensitiveInfoPolicy in $params.SensitiveInfoPolicy) {
			$configStr = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($SensitiveInfoPolicy.Config))
			$config = [xml]$configStr
			Format-XML $config | Out-File "$resultOutputDir\DLP\rule_$($SensitiveInfoPolicy.RulePackageId).xml"
		}
	}
}

function PromptForDLPFile() {
	while ($true) {
		Write-Host -ForegroundColor Green "Please enter the full path to the document that was used during log collection. For example C:\Users\John Doe\Desktop\report.docx"
		[string]$DLPFilePath = (Read-Host)
		if ($DLPFilePath.Length -gt 0) {
			# Handle error cases
			try {
				if ((Test-Path -path ($DLPFilePath -Replace '"', "") -PathType leaf)) {
					return $DLPFilePath
				}
			}
			catch {
				Write-Host "Path is not pointing to a valid file. Exception: $_"
				return $DLPFilePath = $false
			}
		}
		else {
			Write-Host "Empty path was provided"
			return $DLPFilePath = $false
		}

	}
}

function Get-DLPEA {
	if ($DlpT) {
		New-Item -ItemType Directory -Path "$resultOutputDir\DLP" -ErrorAction SilentlyContinue | out-Null
		#$DisplayEA = Join-Path $ToolsDir "DisplayExtendedAttribute.exe"
		$DisplayEA = Join-Path $ToolsExeDir "DisplayExtendedAttribute.exe"
		CheckAuthenticodeSignature $DisplayEA
		$DLPFilePath = $false
		if (!($system -or $RemoteRun)) {
			do {
				$DLPFilePath = PromptForDLPFile
			} while ($DLPFilePath -eq $false)
			Write-Host "Checking Extended Attributes for $DLPFilePath..."
			"Extended attributes for: $DLPFilePath`n" | out-File -Encoding UTF8 "$resultOutputDir\DLP\FileEAs.txt"
			CheckAuthenticodeSignature $DisplayEA
			&$DisplayEA "$DLPFilePath" | out-File -encoding UTF8 -Append "$resultOutputDir\DLP\FileEAs.txt"
		}
	}
}

function Check-WPRError($ExitCode) {
	if (($ExitCode -eq "0") -or ($ExitCode -eq "-984076288")) {
		# -984076288 = There are no trace profiles running.
		return
	} elseif ($ExitCode -eq "-2147023446") {
		# 2147023446 = Insufficient system resources exist to complete the requested service.
		Check-Command-verified "logman.exe"
		[int]$ETSCount = (&logman.exe query -ets).count | Out-File $connectivityCheckFile -Append
		[string]$ETSSessions = (&logman.exe query -ets) | Out-File $connectivityCheckFile -Append
		Write-error "Starting WPR trace has failed because too many trace sessions are already running on this system." | Out-File $connectivityCheckFile -Append
		Write-Warning "If this is the first time you are seeing this error, try restarting the machine and collecting traces from scratch."
		Write-Host "Proceeding anyway without the collection of advanced traces..."
	} else {
		"Error $ExitCode occured when starting WPR trace." | Out-File $connectivityCheckFile -Append
	}
}

function Set-BootTraces {
	Write-Host "Checking if WPR Boot trace is already running"
	$WptState = Check-WptState
	if ((!$OSPreviousVersion) -and ($WptState -eq "Ready")) {
		Check-Command-verified "wpr.exe"
		$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -ArgumentList "-boottrace -stopboot `"$WprpTraceFile`""
		Check-WPRError $StartWPRCommand.ExitCode
	}
	Write-Host "Saving any running ProcMon Boot trace"
	CheckAuthenticodeSignature $ProcmonCommand
	$StartPMTrace = Start-Process -PassThru -wait $ProcmonCommand -ArgumentList "-AcceptEula -ConvertBootLog `"$ProcMonlog`""
	$procmonlogs = Get-Item "$resultOutputDir\*.pml"
	if ($null -eq $procmonlogs) {
		CheckAuthenticodeSignature $ProcmonCommand
		& $ProcmonCommand -AcceptEula -EnableBootLogging -NoFilter -quiet -minimized
		if ((!$OSPreviousVersion) -and ($WptState -eq "Ready")) {
			Check-Command-verified "wpr.exe"
			$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -ArgumentList "-boottrace -addboot `"$ToolsDir\Sense.wprp`" -filemode"
			Check-WPRError $StartWPRCommand.ExitCode
		}
		Write-Host "Boot logging ready"
		Write-Host -BackgroundColor Red -ForegroundColor Yellow "Please run the tool again with '-b' parameter when the device is back online" 
		if ($RemoteRun) {
			Write-Warning "Restarting remote device..."
		}
		else {
			Read-Host "Press ENTER when you are ready to restart..."
		}
		Restart-Computer -ComputerName . -Force
	}
	else {
		Write-Host "Boot logs were collected successfully"
		Get-Logs
	}
}

function Set-FullCrashDump {
	Set-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -name CrashDumpEnabled -Type DWord -Value "1"
	Write-Host "Registry settings for full dump collection have been configured"
}

function Set-CrashOnCtrlScroll {
	Set-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters' -name CrashOnCtrlScroll -Type DWord -Value "1"
	Set-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters' -name CrashOnCtrlScroll -Type DWord -Value "1"
	Set-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\hyperkbd\Parameters' -name CrashOnCtrlScroll -Type DWord -Value "1" -ErrorAction SilentlyContinue
	Write-Host "Registry settings for CrashOnCtrlScroll have been configured as per https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/forcing-a-system-crash-from-the-keyboard"
}

function Start-PSRRecording {
	if ($RemoteRun) {
		"`r`nSkipping PSR recording as it requires an interactive user session." | Out-File $connectivityCheckFile -Append
	} 
	else {
		Check-Command-verified "psr.exe"
		& psr.exe -stop
		Start-Sleep -Seconds 2
		Check-Command-verified "psr.exe"
		& psr.exe -start -output "$resultOutputDir\psr.zip" -gui 0 -maxsc 99 -sc 1
	}
}

function Stop-PSRRecording {
	if ($RemoteRun) {
		"`r`nSkipping PSR recording as it requires an interactive user session." | Out-File $connectivityCheckFile -Append
	} 
	else {
		Check-Command-verified "psr.exe"
		& psr.exe -stop
	}
}

function Start-MDAVTraces {
	if ((!$OSPreviousVersion) -or ($MDfWS)) {
		if (($NetTraceI) -and (!$DlpT) -and (!$WDVerboseTraceV)) {
			CheckAuthenticodeSignature $MpCmdRunCommand
			Start-Process -WindowStyle minimized $MpCmdRunCommand -WorkingDirectory $CurrentMpCmdPath.ToString() -ArgumentList "-trace -grouping 0x1B -level 0x3F"
		}
		elseif ($DlpT) {
			CheckAuthenticodeSignature $MpCmdRunCommand
			Start-Process -WindowStyle minimized $MpCmdRunCommand -WorkingDirectory $CurrentMpCmdPath.ToString() -ArgumentList "-trace -grouping 0x309 -level 0x3F"
		}
		elseif ($WDVerboseTraceV) {
			CheckAuthenticodeSignature $MpCmdRunCommand
			Start-Process -WindowStyle minimized $MpCmdRunCommand -WorkingDirectory $CurrentMpCmdPath.ToString() -ArgumentList "-trace -grouping 0x1FF -level ff"
			&$MpCmdRunCommand -CaptureNetworkTrace -path C:\Users\Public\Downloads\Capture.npcap | Out-File $connectivityCheckFile -Append
			Start-WinEventDebug Microsoft-Windows-SmartScreen/Debug
		}
		if ($WDPerfTraceA) {
			$WPRP = Join-Path $ToolsDir "WD.WPRP"
			Write-Host "Starting WD perf trace"
			Check-Command-verified "wpr.exe"
			$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -WorkingDirectory $resultOutputDir -ArgumentList "-start `"$WPRP`"!WD.Verbose -filemode -instancename AV"
			Check-WPRError $StartWPRCommand.ExitCode
		} 
	} 
	#Downlevel machine with SCEP
	elseif (Test-Path -path "$env:ProgramFiles\Microsoft Security Client\MpCmdRun.exe") {
			CheckAuthenticodeSignature $MpCmdRunCommand
			Start-Process -WindowStyle minimized $MpCmdRunCommand -WorkingDirectory $CurrentMpCmdPath -ArgumentList "-trace -grouping ff -level ff"
	}
}

function Stop-MDAVTraces {
	Write-Host "Stopping and merging Defender Antivirus traces if running"
	if ($WDVerboseTraceV) {
		&$MpCmdRunCommand -CaptureNetworkTrace | Out-File $connectivityCheckFile -Append
		Stop-WinEventDebug Microsoft-Windows-SmartScreen/Debug
	}
	$MpCmdRunProcs = Get-Process | Where-Object { $_.MainWindowTitle -like "*MpCmdRun.ex*" }
	if ($MpCmdRunProcs) {
		foreach ($process in $MpCmdRunProcs) {
			[void][WindowFocus]::SetForeGroundWindow($process.MainWindowHandle) 
			[System.Windows.Forms.SendKeys]::SendWait("~")
		}
	}
	if ($WDPerfTraceA) {
		Check-Command-verified "wpr.exe"
		$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -WorkingDirectory $resultOutputDir -ArgumentList "-stop merged.etl -instancename AV"
		Check-WPRError $StartWPRCommand.ExitCode
	}
	if (Test-Path -Path  $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-SmartScreen%4Debug.evtx') {
		Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-SmartScreen%4Debug.evtx' -Destination $resultOutputDir\EventLogs\SmartScreen.evtx
	}
}

function Get-CrashDumps {
	New-Item -ItemType Directory -Path "$resultOutputDir\CrashDumps" -ErrorAction SilentlyContinue | out-Null
	Write-Host "Attempting to collect a memory dump of the sensor"
	CheckAuthenticodeSignature $ProcDumpCommand
	if ($OSPreviousVersion) {
		$processes = @(Get-Process -Name MsSenseS) + @(Get-Process -Name MonitoringHost)
		if ($null -eq $processes) {
			Write-Host "No running Sensor processes found"
		}
		else {
			foreach ($process in $processes) {
				CheckAuthenticodeSignature $ProcDumpCommand
				& $ProcDumpCommand -accepteula -ma -mk $process.Id "$resultOutputDir\CrashDumps\$($process.name)_$($process.Id).dmp"
			}
		}
	}
	elseif ($buildNumber -ge "15063") {
		Write-Host "The MDEClientAnalyzer does not support capturing a memory dump of a tamper protected process at this time."
		Write-Host "Attempting to capture a memory dump of the DiagTrack service"
		$DiagTrackSvc = (Get-WmiObject Win32_Service -Filter "Name='DiagTrack'")
		$DiagTrackID = $DiagTrackSvc.ProcessId
		if ($null -eq $DiagTrackID) {
			Write-Host "No running processes to capture"
		}
		else {
			$Processes = @(Get-Process -Id $DiagTrackID)
			foreach ($process in $processes) {
				CheckAuthenticodeSignature $ProcDumpCommand
				& $ProcDumpCommand -accepteula -ma -mk $process.Id "$resultOutputDir\CrashDumps\$($process.name)_$($process.Id).dmp"
			}
		}
	}
}

function Start-NetTraces {
	if ($NetTraceI) {
		New-Item -ItemType Directory -Path "$resultOutputDir\NetTraces" -ErrorAction SilentlyContinue | out-Null
		$traceFile = "$resultOutputDir\NetTraces\NetTrace.etl"
		Write-Host "$(Get-Date -f 'yyyyMMdd HH:mm:ss') Stopping any running network trace profiles"
		Check-Command-verified "netsh.exe"
		$StopNetCommand = Start-Process -PassThru -WindowStyle minimized netsh.exe -ArgumentList "trace stop"
		Check-Command-verified "netsh.exe"
		$StopWfpCommand = Start-Process -PassThru -WindowStyle minimized netsh.exe -ArgumentList "wfp capture stop"
		start-sleep 1
		$NetshProcess = Get-Process | Where-Object { $_.Name -eq "netsh" } -ErrorAction SilentlyContinue
		if ($null -ne $NetshProcess) {
			foreach ($process in $NetshProcess) { stop-Process $process -Force }
		}
		Check-Command-verified "ipconfig.exe"
		$FlushDns = Start-Process -PassThru -WindowStyle minimized ipconfig.exe -ArgumentList "/flushdns"
		Check-Command-verified "netsh.exe"
		$CleanArpCache = Start-Process -PassThru -WindowStyle minimized netsh.exe -ArgumentList "interface ip delete arpcache"
		start-sleep 1
		Write-Host "$(Get-Date -f 'yyyyMMdd HH:mm:ss') Now starting a new network trace with Duration: $MinutesToRun min - Enter 'q' to stop"
		if ($buildNumber -le 7601) {
			Check-Command-verified "netsh.exe"
			$StartNetCommand = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "trace start overwrite=yes capture=yes scenario=InternetClient report=yes maxSize=500 traceFile=`"$traceFile`" fileMode=circular"
		}
		else {
			Check-Command-verified "netsh.exe"
			$StartNetCommand = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "trace start overwrite=yes capture=yes scenario=InternetClient_dbg report=yes maxSize=500 traceFile=`"$traceFile`" fileMode=circular"
		}
		Check-Command-verified "netsh.exe"
		$StartWFLogging = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging allowedconnections enable"  # enable firewall logging for allowed traffic
		Check-Command-verified "netsh.exe"
		$StartWFLogging = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging droppedconnections enable"  # enable firewall logging for dropped traffic
		Check-Command-verified "netsh.exe"
		$StartWFTraces = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "wfp capture start file=wfpdiag.cab keywords=19" # start capturing  WFP log
		Check-Command-verified "netstat.exe"
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
		Check-Command-verified "netstat.exe"
		&netstat -anob | Out-File "$resultOutputDir\NetTraces\NetStatOutputAtStop.txt"
		"Netstat output above was taken at: " + (Get-Date) | Out-File "$resultOutputDir\NetTraces\NetStatOutputAtStop.txt" -Append
		Check-Command-verified "netsh.exe"
		$StartWFLogging = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging allowedconnections disable"  # disable firewall logging for allowed traffic
		Check-Command-verified "netsh.exe"
		$StartWFLogging = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging droppedconnections disable"  # disable firewall logging for dropped traffic
		Check-Command-verified "netsh.exe"
		Start-Process -NoNewWindow netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "wfp capture stop"
		Check-Command-verified "netsh.exe"
		Write-Host "$(Get-Date -f 'yyyyMMdd HH:mm:ss') Note: Stopping network and wfp traces may take a while..."
		#we#Start-Process -WindowStyle Maximized netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "trace stop"
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

# Add-type to use SetForegroundWindow api https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setforegroundwindow
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 
Add-Type @"
  using System;
  using System.Runtime.InteropServices;
  public class WindowFocus {
     [DllImport("user32.dll")]
     [return: MarshalAs(UnmanagedType.Bool)]
     public static extern bool SetForegroundWindow(IntPtr hWnd);
  }
"@

function Get-Logs {
	New-Item -ItemType Directory -Path "$resultOutputDir\DefenderAV" -ErrorAction SilentlyContinue | out-Null
	StartGet-MSInfo -NFO $true -TXT $false -OutputLocation "$resultOutputDir\SystemInfoLogs"
	Check-Command-verified "gpresult.exe"
	&gpresult /SCOPE COMPUTER /H "$resultOutputDir\SystemInfoLogs\GP.html"
	if ($MpCmdRunCommand) {
		Write-Host "Running MpCmdRun -GetFiles..."
		CheckAuthenticodeSignature $MpCmdRunCommand
		&$MpCmdRunCommand -getfiles | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		Copy-Item -Path "$MpCmdResultPath\MpSupportFiles.cab" -Destination "$resultOutputDir\DefenderAV" -verbose -ErrorVariable GetFilesErr | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		$GetFilesErr | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		Copy-Item -path "C:\Users\Public\Downloads\Capture.npcap" -Destination "$resultOutputDir\DefenderAV" -ErrorAction SilentlyContinue -verbose -ErrorVariable CopyNpCap | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		$CopyNpCap | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		# Dump Defender related polices
		Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -recurse | Out-File "$resultOutputDir\DefenderAV\Policy-DefenderAV.txt"
		Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\" -recurse | Out-File "$resultOutputDir\DefenderAV\Policy-Firewall.txt"
		Get-ChildItem "HKU:\S-1-5-18\SOFTWARE\Microsoft\Windows Defender" -recurse -ErrorAction SilentlyContinue | Out-File "$resultOutputDir\DefenderAV\Policy-SystemService.txt"
		Get-ChildItem "HKU:\S-1-5-20\SOFTWARE\Microsoft\Windows Defender" -recurse -ErrorAction SilentlyContinue | Out-File "$resultOutputDir\DefenderAV\Policy-NetworkService.txt"
	}
	Check-Command-verified "fltmc.exe"
	&fltmc instances -v "$env:SystemDrive" > $resultOutputDir\SystemInfoLogs\filters.txt
	if ($OSProductName.tolower() -notlike ("*server*")) {
		Write-output "`r`n##################### Windows Security Center checks ######################" | Out-File $connectivityCheckFile -Append
		$wscType = Add-Type -memberDefinition $wscDefinition -name "wscType" -UsingNamespace "System.Reflection", "System.Diagnostics" -PassThru
 
		"            Firewall: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_FIREWALL) | Out-File $connectivityCheckFile -Append
		"         Auto-Update: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS) | Out-File $connectivityCheckFile -Append
		"          Anti-Virus: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_ANTIVIRUS) | Out-File $connectivityCheckFile -Append
		"        Anti-Spyware: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_ANTISPYWARE) | Out-File $connectivityCheckFile -Append
		"   Internet Settings: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_INTERNET_SETTINGS) | Out-File $connectivityCheckFile -Append
		"User Account Control: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL) | Out-File $connectivityCheckFile -Append
		"         WSC Service: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_SERVICE) | Out-File $connectivityCheckFile -Append

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

function StartTimer {
	$TraceStartTime = "{0:dd/MM/yyyy h:mm:ss tt zzz}" -f (get-date)
	Write-Report -section "general" -subsection "traceStartTime" -displayname "Trace StartTime: " -value $TraceStartTime
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
	Write-Report -section "general" -subsection "traceStopTime" -displayname "Trace StopTime: " -value $TraceStopTime 
}

function Get-MinutesValue {
	if ($RemoteRun) {
		"`r`nLog Collection was started from a remote device." | Out-File $connectivityCheckFile -Append
		return $MinutesToRun
	} 
	else {
		do {
			try {
				[int]$MinutesToRun = (Read-Host "Enter the number of minutes to collect traces")
				return $MinutesToRun
			}
			catch {
				Write-Warning  ($_.Exception.Message).split(':')[1]
				$MinutesToRun = $false
			}
		} while ($MinutesToRun -eq $false)
	}
}

function Check-WptState($command) {
	if (!$command) {
		$CheckCommand = (Get-Command "wpr.exe" -ErrorAction SilentlyContinue)
	} else {
		$CheckCommand = (Get-Command $command -ErrorAction SilentlyContinue)
	}
	# This line will reload the path so that a recent installation of wpr will take effect immediately:
	$env:path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
	$SenseWprp7 = Join-Path $ToolsDir "SenseW7.wprp"
	$SenseWprp10 = Join-Path $ToolsDir "SenseW10.wprp"
	$SenseWprp = Join-Path $ToolsDir "Sense.wprp"
	$DlZipFile = Join-Path $ToolsDir "WPT.cab"
	if (($null -eq $CheckCommand) -and ($InteractiveAdmin)) {
		Write-Warning "Performance Toolkit is not installed on this device. It is required for full traces to be collected."
		Write-host -ForegroundColor Green "Please wait while we download WPT installer files (~50Mb) to MDEClientAnalyzer directory. Refer to https://aka.ms/adk for more information about the 'Windows ADK'."
		$WPTURL = "https://aka.ms/MDATPWPT"
		Import-Module BitsTransfer
		$BitsResult = Start-BitsTransfer -Source $WPTURL -Destination "$DlZipFile" -TransferType Download -Asynchronous
		$DownloadComplete = $false
		if (!(Test-Path -path $DlZipFile)) {
			while ($DownloadComplete -ne $true) {
				start-Sleep 1
				$jobstate = $BitsResult.JobState;
				$percentComplete = ($BitsResult.BytesTransferred / $BitsResult.BytesTotal) * 100
				Write-Progress -Activity ('Downloading' + $result.FilesTotal + ' files') -Status "Progress:" -PercentComplete $percentComplete 
				if ($jobstate.ToString() -eq 'Transferred') {
					$DownloadComplete = $true
					Write-Progress -Activity ('Downloading' + $result.FilesTotal + ' files') -Completed close 
				}
				if ($jobstate.ToString() -eq 'TransientError') {
					$DownloadComplete = $true
					Write-host "Unable to download ADK installation package."
				}
			}
			$BitsResult | complete-BitsTransfer
		}
		if (Test-Path -path "$DlZipFile") {
			CheckHashFile "$DlZipFile" "6FE5F8CA7F864560B9715E0C18AA0D839416EDB0B68B4A314FC96DFAFA99733E"
			Check-Command-verified "expand.exe"
			#Expand-Archive CMDlet or System.IO.Compression.ZipFile does not work with some older PowerShell/OS combinations so using the below for backwards compatbility 
			&expand.exe "$DlZipFile" "`"$($ToolsDir.TrimEnd('\'))`"" -F:*
			Write-host -ForegroundColor Green "Download complete. Starting installer..."
			start-Sleep 1
			Write-Host -BackgroundColor Red -ForegroundColor Yellow "Please click through the installer steps to deploy the Microsoft Windows Performance Toolkit (WPT) before proceeding"
			if ($buildNumber -eq 7601) {
				$AdkSetupPath = Join-Path $ToolsDir "8.0\adksetup.exe"
				CheckAuthenticodeSignature $AdkSetupPath
				Start-Process -wait -WindowStyle minimized "$AdkSetupPath" -ArgumentList "/ceip off /features OptionId.WindowsPerformanceToolkit"
				Read-Host "Press ENTER if intallation is complete and you are ready to resume..."	
			}
			elseif ($buildNumber -gt 7601) {
				$AdkSetupPath = Join-Path $ToolsDir "adksetup.exe"
				CheckAuthenticodeSignature $AdkSetupPath
				Start-Process -wait -WindowStyle minimized "$AdkSetupPath" -ArgumentList "/ceip off /features OptionId.WindowsPerformanceToolkit"
				Read-Host "Press ENTER if intallation is complete and you are ready to resume..."
			}
		}
		else {
			Write-host "Please download and install manually from https://aka.ms/adk" 
		}
		# If install is successful we need to refresh environemnt variable and check if command got installed
		$env:path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
		$CheckCommand = (Get-Command $command -ErrorAction SilentlyContinue)
		if ($null -eq $CheckCommand) {
			Write-Host -BackgroundColor Red -ForegroundColor Yellow "WPT was not installed. Only partial data will be collected"
			return $WptState = "Missing"
		}
		elseif ($buildNumber -eq 7601) {
			Write-Warning "Note: Windows7/2008R2 devices also require running 'wpr.exe -disablepagingexecutive on' and rebooting"
			Write-Warning "To disable, run 'wpr.exe -disablepagingexecutive off' once data collection is complete"
			Read-Host "Press ENTER to allow MDEClientAnalyzer to turn on 'disablepagingexecutive' and restart your device automatically"
			$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -ArgumentList "-disablepagingexecutive on"
			Check-WPRError $StartWPRCommand.ExitCode
			Restart-Computer -ComputerName .
		}
	}
 else {
		Write-Host "Stopping any running WPR trace profiles"
		Check-Command-verified "wpr.exe"
		$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe  -ArgumentList "-cancel"
		Check-WPRError $StartWPRCommand.ExitCode
	}
	if ($buildNumber -le 9600) {
		Copy-Item -path $SenseWprp7 -Destination $senseWprp -Force	
	}
	else {
		Copy-Item -path $SenseWprp10 -Destination $senseWprp -Force
	}		
	return $WptState = "Ready"
}

function Start-Wpr {
	Check-Command-verified "wpr.exe"
	if ($wprpTraceH -and $WptState -eq "Ready") {
		Check-Command-verified "wpr.exe"
		$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -ArgumentList "-start GeneralProfile -start CPU -start FileIO -start DiskIO -start `"$ToolsDir\Sense.wprp`" -filemode -instancename Sense"
		Check-WPRError $StartWPRCommand.ExitCode
	}
	elseif ($WptState -eq "Ready") {
		Check-Command-verified "wpr.exe"
		$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -ArgumentList "-start `"$ToolsDir\Sense.wprp`" -filemode -instancename Sense"
		Check-WPRError $StartWPRCommand.ExitCode
	}
}

function Stop-Wpr {
	if ($WptState -eq "Ready") {
		Check-Command-verified "wpr.exe"
		$StartWPRCommand = Start-Process -PassThru -wait -WindowStyle minimized wpr.exe -ArgumentList "-stop `"$WprpTraceFile`" -instancename Sense"
		Check-WPRError $StartWPRCommand.ExitCode
	}
}

function Copy-RecentItems($ParentFolder, $DestFolderName) {
	$ParentFolder = (Get-ChildItem -Path $ParentFolder)
	$ParentFolder = ($ParentFolder | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-2) } -ErrorAction SilentlyContinue)
	if ($null -ne $ParentFolder) {
		foreach ($subfolder in $ParentFolder) {
			Copy-Item -Recurse -Path $subfolder.FullName -Destination $resultOutputDir\$DestFolderName\$subfolder -ErrorAction SilentlyContinue
		}
	}
}

function Start-WinEventDebug($DebugLogName) {
	$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $DebugLogName
	if ($log.IsEnabled -ne $true) {
		$log.IsEnabled = $true
		$log.SaveChanges()
	}
}

function Stop-WinEventDebug($DebugLogName) {
	$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $DebugLogName
	$log.IsEnabled = $false
	$log.SaveChanges()
	$DebugLogPath = [System.Environment]::ExpandEnvironmentVariables($log.LogFilePath)
	Copy-Item -path "$DebugLogPath" -Destination "$resultOutputDir\EventLogs\"
}

function SetLocalDumps() {
	# If already implementing LocalDumps as per https://docs.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps, then backup the current config
	if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps") {
		Check-Command-verified "reg.exe"
		&Reg export "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" "$ToolsDir\WerRegBackup.reg" /y 2>&1 | Out-Null
	}  
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Recurse -ErrorAction SilentlyContinue | out-Null
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "LocalDumps" -ErrorAction SilentlyContinue | out-Null
	New-Item -ItemType Directory -Path "$resultOutputDir\CrashDumps" -ErrorAction SilentlyContinue | out-Null
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpFolder" -Value "$resultOutputDir\CrashDumps" -PropertyType "ExpandString" -ErrorAction SilentlyContinue | out-Null
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpCount" -Value 5 -PropertyType DWord -ErrorAction SilentlyContinue | out-Null
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -Name "DumpType" -Value 2 -PropertyType DWord -ErrorAction SilentlyContinue | out-Null
}

function RestoreLocalDumps() {
	if (Test-Path "$ToolsDir\WerRegBackup.reg") {
		Check-Command-verified "reg.exe"
		$RegImport = (&reg import "$ToolsDir\WerRegBackup.reg" 2>&1)
	}
 else {
		Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" -ErrorAction SilentlyContinue | out-Null
	}
}

# function to download a given cab file and expand it
function Download-WebFile($webfile) {
	$DlZipFile = Join-Path $ToolsDir "webfile.cab"
	Write-host -ForegroundColor Green "Please wait while we download additional required files to MDEClientAnalyzer from: " $webfile
	Import-Module BitsTransfer
	$BitsJob = Start-BitsTransfer -source $webfile -Destination "$DlZipFile" -Description "Downloading additional files" -RetryTimeout 60 -RetryInterval 60 -ErrorAction SilentlyContinue
}

function Start-AppCompatTraces() {
	if ($AppCompatC) {
		if ($InteractiveAdmin) {
		# We can't use bits to fetch symchk if user is not interactive
			if (!$OSPreviousVersion) {
				$SymChkCommand = Join-Path $ToolsDir "\x86\symchk.exe"
				$DlZipFile = Join-Path $ToolsDir "webfile.cab"
				if (!(test-path $SymChkCommand)) {
					Download-WebFile "https://aka.ms/MDATPSYMCHK"
					if (Test-Path -path "$DlZipFile" -ErrorAction SilentlyContinue) {
						Check-Command-verified "expand.exe"
						CheckHashFile "$DlZipFile" "DE3E5338E4EBEBA64250E61E91CAFC86A70EA999C2E2D8E0A769862B2B642168"
						#Expand-Archive CMDlet or System.IO.Compression.ZipFile does not work with some older PowerShell/OS combinations so using the below for backwards compatbility 
						&expand.exe "$DlZipFile" "`"$($ToolsDir.TrimEnd('\'))`"" -F:*
					}
				}
				if (test-path $SymChkCommand) {
					CheckAuthenticodeSignature $SymChkCommand
					&$SymChkCommand /q /r /s "." "$env:ProgramFiles\Windows Defender Advanced Threat Protection" /om "$resultOutputDir\SystemInfoLogs\symbolsManifest.txt"
				}
			}
		}
		CheckAuthenticodeSignature $ProcmonCommand
		&$ProcmonCommand -AcceptEula -Terminate
		Remove-Item $ToolsDir\*.pml -Force -ErrorAction SilentlyContinue
		CheckAuthenticodeSignature $ProcmonCommand
		&$ProcmonCommand -AcceptEula -BackingFile "$resultOutputDir\procmonlog.pml" -NoFilter -Quiet -Minimized 
		Start-WinEventDebug Microsoft-Windows-WMI-Activity/Debug
		SetLocalDumps
	}
}

function Stop-AppCompatTraces() {
	if ($AppCompatC) {
		CheckAuthenticodeSignature $ProcmonCommand
		Write-Host "Stopping procmon trace..."
		&$ProcmonCommand -AcceptEula -Terminate
		if (Test-Path -Path  $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider%4Admin.evtx') {
			Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider%4Admin.evtx' -Destination $resultOutputDir\EventLogs\MdmAdmin.evtx
			Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider%4Operational.evtx' -Destination $resultOutputDir\EventLogs\MdmOperational.evtx -ErrorAction SilentlyContinue
		}
		Stop-WinEventDebug Microsoft-Windows-WMI-Activity/Debug
		Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx' -Destination $resultOutputDir\EventLogs\WMIActivityOperational.evtx
		Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\System.evtx' -Destination $resultOutputDir\EventLogs\System.evtx
		Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Application.evtx' -Destination $resultOutputDir\EventLogs\Application.evtx
		$DestFolderName = "WER"
		Copy-RecentItems $env:ProgramData\Microsoft\Windows\WER\ReportArchive $DestFolderName
		Copy-RecentItems $env:ProgramData\Microsoft\Windows\WER\ReportQueue $DestFolderName
		RestoreLocalDumps
	}
}		

function Stop-PerformanceCounters {
	param (
		$DataCollectorSet,
		$DataCollectorName
	)
	try {
		$DataCollectorSet.Query($DataCollectorName, $null)
		if ($DataCollectorSet.Status -ne 0) {
			$DataCollectorSet.stop($false)
			Start-Sleep 10
		}
           
		$DataCollectorSet.Delete()
	}
	catch [Exception] {
		$_.Exception.Message
	}
}

function Get-PerformanceCounters {
	param (
		[Alias("r")][switch]$RunCounter
	)

	$filePathToXml = "$ToolsDir\PerfCounter.xml"
	if ($RunCounter) {
		if (($buildNumber -eq 9600) -or ($buildNumber -eq 7601)) {
			Copy-Item  -path "$ToolsDir\PerfCounterW7.xml" -Destination  "$ToolsDir\PerfCounter.xml" -Force
		}
		else {
			Copy-Item  -path "$ToolsDir\PerfCounterW10.xml"  -Destination  "$ToolsDir\PerfCounter.xml" -Force
		}   
		$xmlContent = New-Object XML
		$xmlContent.Load($filePathToXml)
		$xmlContent.SelectNodes("//OutputLocation") | ForEach-Object { $_."#text" = $_."#text".Replace('c:\', $ToolsDir) }
		$xmlContent.SelectNodes("//RootPath") | ForEach-Object { $_."#text" = $_."#text".Replace('c:\', $ToolsDir) }
		$xmlContent.Save($filePathToXml)
	}

	$DataCollectorName = "MDE-Perf-Counter"
	$DataCollectorSet = New-Object -COM Pla.DataCollectorSet
	[string]$xml = Get-Content $filePathToXml
	$DataCollectorSet.SetXml($xml)
	Write-Host "Stopping any running perfmon trace profiles"
	Stop-PerformanceCounters -DataCollectorSet  $DataCollectorSet -DataCollectorName $DataCollectorName >$null
	if ($RunCounter) {
		$DataCollectorSet.Commit("$DataCollectorName" , $null , 0x0003) | Out-Null
		$DataCollectorSet.Start($false)
	}
}

function Start-PerformanceTraces() {
	if ($wprpTraceL) {
		Get-PerformanceCounters -r
	}
}

function Stop-PerformanceTraces() {
	if ($wprpTraceL) {
		Get-PerformanceCounters		
	}
	$Perfmonlogs = Get-Item $ToolsDir\*.blg
	if ($null -ne ($Perfmonlogs)) {
		Move-Item -Path $Perfmonlogs -Destination $resultOutputDir
	} 
}

function SetUrlList {
	param (
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$OSPreviousVersion
	)
	$Urls = @{}
	
	$RegionsObj = (Get-Content $RegionsJson -raw) | ConvertFrom-Json
	if ((Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value OnboardedInfo) -or ($ASM)) {
		Clear-Content -Path $EndpointList	

		if ($asm) {
			# Datacenter not relevant at this time
			$Region = "ASM"
		}
		Else {
			$OnboardedInfo = (((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\").OnboardedInfo | ConvertFrom-Json).body | ConvertFrom-Json)
			$Region = $OnboardedInfo.vortexGeoLocation
			$Datacenter = $OnboardedInfo.Datacenter
		}
		$regionURLs = ($RegionsObj | Where-Object { ($_.Region -eq $Region) -and ($Datacenter -like "$($_.datacenterprefix)*") })
		if ($null -ne $regionURLs) {
			Add-Content $EndpointList -value $regionURLs.CnCURLs
			Add-Content $EndpointList -value $regionURLs.CyberDataURLs
			Add-Content $EndpointList -value $regionURLs.AutoIRBlobs
			Add-Content $EndpointList -value $regionURLs.SampleUploadBlobs
			Add-Content $EndpointList -value $regionURLs.MdeConfigMgr

			$Urls['CnCURLs'] = $regionURLs.CnCURLs
			$Urls['CyberDataURLs'] = $regionURLs.CyberDataURLs
			$Urls['AutoIRBlobs'] = $regionURLs.AutoIRBlobs
			$Urls['SampleUploadBlobs'] = $regionURLs.SampleUploadBlobs
			$Urls['MdeConfigMgr'] = $regionURLs.MdeConfigMgr
		}
		
		if (($Region) -notmatch 'FFL') {
			$regionAllURLs = ($RegionsObj | Where-Object { $_.Region -eq "ALL" });
			Add-Content $EndpointList -value $regionAllURLs.CTLDL
			Add-Content $EndpointList -value $regionAllURLs.Settings
			Add-Content $EndpointList -value $regionAllURLs.Events
		}
		$AllRegionsURLs['Region'] = $Region
		$AllRegionsURLs['Urls'] = $Urls
	} 
	elseif ($OSPreviousVersion) {
		Clear-Content -Path $EndpointList
		$Regions = ('US', 'UK', 'EU')
		foreach ($Region in $Regions) {
			Add-Content $EndpointList -value ($RegionsObj | Where-Object { $_.Region -eq $Region }).CnCURLs
			$Urls['CnCURLs'] = ($RegionsObj | Where-Object { $_.Region -eq $Region }).CnCURLs
			$AllRegionsURLs['Region'] = $Region
			$AllRegionsURLs['Urls'] = $Urls
		}
	}
}

function ValidateURLs {
	# Add warning to output if any EDR Cloud checks failed
	# Based on https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/configure-proxy-internet#verify-client-connectivity-to-microsoft-defender-atp-service-urls
	# "If at least one of the connectivity options returns a (200) status, then the Microsoft Defender for Endpoint client can communicate with the tested URL properly using this connectivity method."
	Write-output "`r`n#################### Defender for Endpoint cloud service check #####################" | Out-File $connectivityCheckFile -Append
	$Streamer = New-Object System.IO.StreamReader( $connectivityCheckFile)
	$SuccessCounter = -1

	$AllUrlsErrors = New-Object System.Collections.Generic.List[System.Object]
	while ($null -ne ($Line = $Streamer.ReadLine())) {
		If ($Line -like "*Testing URL :*") {
			$UrlToCheck = $Line.substring(14)
			$SuccessCounter = 0       
			For ($i = 0; $i -le 5; $i++) {
				$Line = $Streamer.ReadLine()
				If (($Line -like "*(200)*") -or ($Line -like "*(400)*") -or ($Line -like "*(404)*")) {
					$SuccessCounter += 1
				}
			}
			If ($SuccessCounter -eq 0) {
				 if (-not [String]::IsNullOrWhiteSpace($currentSection) -and $null -ne $UrlToCheck) {
						Add-Member -InputObject $AllUrlsErrors -MemberType NoteProperty -Name $currentSection -Value $UrlToCheck -ErrorAction SilentlyContinue
				   }
				[void]$AllUrlsErrors.Add($UrlToCheck)
			}
		}
	}
	$Streamer.Dispose()
	if ($SuccessCounter -eq -1) {
		WriteReport 131001 @() @()
	}
	else {
		#Urls connectivity checks by region
		if ($AllRegionsURLs.Region -eq 'ASM') {
			CheckCnCURLs $AllRegionsURLs $AllUrlsErrors
		}
		If ($AllRegionsURLs.Region -eq 'US' -or $AllRegionsURLs.Region -eq 'UK' -or $AllRegionsURLs.Region -eq 'EU') {
			CheckCnCURLs $AllRegionsURLs $AllUrlsErrors
			CheckCyberURLs $AllRegionsURLs $AllUrlsErrors
			CheckAutoIR $AllRegionsURLs $AllUrlsErrors
			CheckSampleUpload $AllRegionsURLs $AllUrlsErrors
			CheckMdeConfigMgr $AllRegionsURLs $AllUrlsErrors
		}
		If ($AllRegionsURLs.Region -like ("FFL*")) {
			CheckCnCURLs $AllRegionsURLs $AllUrlsErrors
			CheckCyberURLs $AllRegionsURLs $AllUrlsErrors
			CheckAutoIR $AllRegionsURLs $AllUrlsErrors
			CheckMdeConfigMgr $AllRegionsURLs $AllUrlsErrors
		}
	}
}

function CountErrors($AllUrlsErrors, $AllConnectivity, $ConnectivityCheck) {
	$CheckURLs = $AllConnectivity.$ConnectivityCheck
	$CountErrors = 0
	$Errors = New-Object System.Collections.Generic.List[System.Object]
	If ($AllUrlsErrors.Count -gt 0 -and $CheckURLs.Count -gt 0) {
		foreach ($url in $CheckURLs) {
			If ($AllUrlsErrors.Contains($url)) {
				$CountErrors += 1
				[void]$Errors.Add($url)
			}
		}
	}
	$ParsedErrors = @()
	foreach ($Error in $Errors) {
		$ParsedErrors += "<a href='" + $Error + "'>" + $Error + "</a>"
	}
	return $CountErrors, $ParsedErrors
}

function CheckCnCURLs($AllRegionsURLs, $AllUrlsErrors) {
	$AllConnectivity = $AllRegionsURLs.Urls
	$CncErrorCnt, $Errors = CountErrors $AllUrlsErrors $AllConnectivity 'CnCURLs'

	If ($CncErrorCnt -gt 1) {
		WriteReport 132021 @(, @($Errors)) @()
	}
	elseif ($CncErrorCnt -eq 0) {
		WriteReport 130017 @() @()
	}
	else {
		WriteReport 131013 @(, @($Errors)) @()
	}
}

function CheckCyberURLs($AllRegionsURLs, $AllUrlsErrors) {
	$AllConnectivity = $AllRegionsURLs.Urls
	$CyberErrorCnt, $Errors = CountErrors $AllUrlsErrors $AllConnectivity 'CyberDataURLs'

	If ($CyberErrorCnt -gt 1) {
		WriteReport 132022 @(, @($Errors)) @()
	}
	elseif ($CyberErrorCnt -eq 0) {
		WriteReport 130018 @() @()
	}
	else {
		WriteReport 131014 @(, @($Errors)) @()
	}
}

function CheckAutoIR($AllRegionsURLs, $AllUrlsErrors) {
	$AllConnectivity = $AllRegionsURLs.Urls
	$AutoIRCnt, $Errors = CountErrors $AllUrlsErrors $AllConnectivity 'AutoIRBlobs'

	If ($AutoIRCnt -gt 1) {
		WriteReport 132023 @(, @($Errors)) @()
	}
	elseif ($AutoIRCnt -eq 0) {
		WriteReport 130019  @() @()
	}
	else {
		WriteReport 131015 @(, @($Errors)) @()
	}
}

function CheckSampleUpload($AllRegionsURLs, $AllUrlsErrors) {
	$AllConnectivity = $AllRegionsURLs.Urls
	$SampleUploadCnt, $Errors = CountErrors $AllUrlsErrors $AllConnectivity 'SampleUploadBlobs'

	If ($SampleUploadCnt -gt 1) {
		WriteReport 132024 @(, @($Errors)) @()
	}
	elseif ($SampleUploadCnt -eq 0) {
		WriteReport 130020 @() @()
	}
	else {
		WriteReport 131016 @(, @($Errors)) @()
	}
}

function CheckMdeConfigMgr($AllRegionsURLs, $AllUrlsErrors) {
	$AllConnectivity = $AllRegionsURLs.Urls
	$MdeConfigMgrCnt, $Errors = CountErrors $AllUrlsErrors $AllConnectivity 'MdeConfigMgr'

	If ($MdeConfigMgrCnt -gt 1) {
		WriteReport 132025 @(, @($Errors)) @()
	}
	elseif ($MdeConfigMgrCnt -eq 0) {
		WriteReport 130021 @() @()
	}
	else {
		WriteReport 131017 @(, @($Errors)) @()
	}
}

function Call-CheckURLs() {
	#$PSExecCommand = Join-Path $ToolsDir "PsExec.exe"
	$PSExecCommand = Join-Path $ToolsExeDir "PsExec.exe"
	#$MDEClientAnalyzerCommand = Join-Path $ToolsDir "MDEClientAnalyzer.exe"
	$MDEClientAnalyzerCommand = Join-Path $ToolsExeDir "MDEClientAnalyzer.exe"
	$URLCheckLog = Join-Path $resultOutputDir "URLCheckLog.txt"
	$psexeclog = Join-Path $resultOutputDir "psexeclog.txt"
	if (test-Path -path $PSExecCommand) {
		CheckAuthenticodeSignature $PSExecCommand
		if (test-Path -path $MDEClientAnalyzerCommand) {CheckAuthenticodeSignature $MDEClientAnalyzerCommand} else {Write-Host -ForegroundColor Magenta "[WARNING] \BIN\MDEClientAnalyzer.exe not found"}
		Start-Process `
			-WorkingDirectory $ToolsDir `
			-FilePath $PSExecCommand `
			-WindowStyle Hidden `
			-RedirectStandardOutput $URLCheckLog `
			-RedirectStandardError $psexeclog `
			-ArgumentList "$ARMcommand -accepteula -nobanner -s -w `"$resultOutputDir`" `"$MDEClientAnalyzerCommand`""
	} else { Write-Host -ForegroundColor Magenta "[WARNING] \BIN\PsExec.exe not found"}
}

function CheckConnectivity {
 param (
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$OSPreviousVersion,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$connectivityCheckFile,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$connectivityCheckUserFile
	)

	[version]$mindotNet = "4.0.30319"
	#$PSExecCommand = Join-Path $ToolsDir "PsExec.exe"
	$PSExecCommand = Join-Path $ToolsExeDir "PsExec.exe"
	if (test-Path -path $PSExecCommand) {
		CheckAuthenticodeSignature $PSExecCommand
	}
	#$MDEClientAnalyzerCommand = Join-Path $ToolsDir "MDEClientAnalyzer.exe"
	$MDEClientAnalyzerCommand = Join-Path $ToolsExeDir "MDEClientAnalyzer.exe"
	if (test-Path -path $MDEClientAnalyzerCommand) {CheckAuthenticodeSignature $MDEClientAnalyzerCommand} else {Write-Host -ForegroundColor Magenta "[WARNING] \BIN\MDEClientAnalyzer.exe not found"}
	#$MDEClientAnalyzerPreviousVersionCommand = Join-Path $ToolsDir "MDEClientAnalyzerPreviousVersion.exe"
	$MDEClientAnalyzerPreviousVersionCommand = Join-Path $ToolsExeDir "MDEClientAnalyzerPreviousVersion.exe"
	$URLCheckLog = Join-Path $resultOutputDir "URLCheckLog.txt"
	$psexeclog = Join-Path $resultOutputDir "psexeclog.txt"

	SetUrlList -OSPreviousVersion $OSPreviousVersion

	if ((Get-RegistryValue -Path  "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Client" -Value Version)) {
		[version]$dotNet = Get-RegistryValue -Path  "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Client" -Value Version
	}
 else {
		[version]$dotNet = "0.0.0000"
	}
	
	if ((!$OSPreviousVersion) -or ($MDfWS)) {		        
		"`r`nImportant notes:" | Out-File $connectivityCheckFile -Append
		"1. If at least one of the connectivity options returns status (200), then Defender for Endpoint sensor can properly communicate with the tested URL using this connectivity method." | Out-File $connectivityCheckFile -Append
		"2. For *.blob.core.*.net URLs, return status (400) is expected. However, the current connectivity test on Azure blob URLs cannot detect SSL inspection scenarios as it is performed without certificate pinning." | Out-File $connectivityCheckFile -Append
		
		
		
		"For more information on certificate pinning, please refer to: https://docs.microsoft.com/en-us/windows/security/identity-protection/enterprise-certificate-pinning" | Out-File $connectivityCheckFile -Append
		# check if running with system context (i.e. script was most likely run remotely via "psexec.exe -s \\device command" or Live Response)
		if ($system) {
			"`r`nConnectivity output, running as System:" | Out-File $connectivityCheckFile -Append
			Set-Location -Path $ToolsDir
			CheckAuthenticodeSignature $MDEClientAnalyzerCommand
			&$MDEClientAnalyzerCommand >> $connectivityCheckFile
			Set-Location -Path $outputDir
		}
		elseif ($eulaAccepted -eq "Yes") {
			"`r`nConnectivity output, using psexec -s:" | Out-File $connectivityCheckFile -Append
			Write-Host "The tool checks connectivity to Microsoft Defender for Endpoint service URLs. This may take longer to run if URLs are blocked."
			Call-CheckURLs
			# Run the tool as interactive user (for authenticated proxy scenario)
			# Start-Process -wait -WindowStyle minimized $MDEClientAnalyzerCommand -WorkingDirectory $ToolsDir -RedirectStandardOutput $connectivityCheckUserFile
		}
		start-sleep 10
		EndTimedoutProcess "MDEClientAnalyzer" 5 
		if (test-path $URLCheckLog) {
			Get-Content -Path $URLCheckLog | Out-File $connectivityCheckFile -Append
			Get-Content -Path $psexeclog | Out-File $connectivityCheckFile -Append
		}
		ValidateURLs
	}
	elseif ($dotNet -ge $mindotNet) {
		Write-Host "The tool checks connectivity to Microsoft Defender for Endpoint service URLs. This may take longer to run if URLs are blocked."
		CheckAuthenticodeSignature $MDEClientAnalyzerPreviousVersionCommand
		# check if running with system context (i.e. script was most likely run remotely via "psexec.exe -s \\device command")
		if ($system) {
			Set-Location -Path $ToolsDir
			CheckAuthenticodeSignature $MDEClientAnalyzerPreviousVersionCommand
			$Global:connectivityresult = (&$MDEClientAnalyzerPreviousVersionCommand)
			Set-Location -Path $outputDir
		}
		elseif ($eulaAccepted -eq "Yes") {
			if (test-Path -path $PSExecCommand) {
				CheckAuthenticodeSignature $PSExecCommand
			}
			#$Global:connectivityresult = (& $PSExecCommand -accepteula -s -nobanner -w "`"$($ToolsDir.TrimEnd('\'))`"" "$MDEClientAnalyzerPreviousVersionCommand" )
			$Global:connectivityresult = (& $PSExecCommand -accepteula -s -nobanner -w "`"$($ToolsExeDir.TrimEnd('\'))`"" "$MDEClientAnalyzerPreviousVersionCommand" )
			# Run the tool as interactive user (for authenticated proxy scenario)
			Start-Process -wait -WindowStyle minimized $MDEClientAnalyzerPreviousVersionCommand -WorkingDirectory $ToolsDir -RedirectStandardOutput $connectivityCheckUserFile
			$Global:connectivityresultUser = (Get-Content $connectivityCheckUserFile)
		}
            
		#Run MMA Connectivity tool
		$MMATestProcess = "$env:ProgramFiles\Microsoft Monitoring Agent\Agent\TestCloudConnection.exe"
		if (Test-Path -path $MMATestProcess) {
			CheckAuthenticodeSignature $MMATestProcess
			$Global:TestOMSResult = &$MMATestProcess
		}
	} else {
		Write-Host -BackgroundColor Red -ForegroundColor Yellow "To run URI validation tool please install .NET framework 4.0  or higher"
		"To run URI validation tool please install .NET framework 4.0 or higher" | Out-File $connectivityCheckFile -Append
		$Global:connectivityresult = $false
		$Global:connectivityresultUser = $false
		$Global:TestOMSResult = $false
	}

	if ($OSPreviousVersion) {
		$HealthServiceDll = "$env:ProgramFiles\Microsoft Monitoring Agent\Agent\HealthService.dll"
		if (Test-Path -path $HealthServiceDll) {
			$healthserviceprops = @{
				Message = ""
				Valid   = $true
				Version = [string]((Get-ItemProperty -Path "$HealthServiceDll").VersionInfo).ProductMajorPart + '.' + [string]((Get-ItemProperty -Path "$HealthServiceDll").VersionInfo).ProductMinorPart + '.' + [string]((Get-ItemProperty -Path "$HealthServiceDll").VersionInfo).ProductBuildPart + '.' + [string]((Get-ItemProperty -Path "$HealthServiceDll").VersionInfo).FilePrivatePart
			}
			$Global:healthservicedll = new-object psobject -Property $healthserviceprops

			If ($OSBuild -eq "7601") {
				<#
				Supported versions for Windows Server 2008 R2 / 2008 / Windows 7
				x64 - 10.20.18029,  10.20.18038, 10.20.18040
				x86 - 10.20.18049
				#>
				if ($arch -like "*64*") {
					[version]$HealthServiceSupportedVersion = '10.20.18029'
				}
				else {
					[version]$HealthServiceSupportedVersion = '10.20.18049'
				}

				If ([version]$Global:healthservicedll.version -lt $HealthServiceSupportedVersion) {
					$Global:healthservicedll.Valid = $false
					$Global:healthservicedll.Message = "The Log Analytics Agent version installed on this device (" + $Global:healthservicedll.version + ") is deprecated as it does not support SHA2 for code signing.`r`n" `
						+ "Note that the older versions of the Log Analytics will no longer be supported and will stop sending data in a future timeframe. More information: https://aka.ms/LAAgentSHA2 `r`n" `
						+ "Please upgrade to the latest version:`r`n" `
						+ "- Windows 64-bit agent - https://go.microsoft.com/fwlink/?LinkId=828603 `r`n"`
						+ "- Windows 32-bit agent - https://go.microsoft.com/fwlink/?LinkId=828604"
				}
				else {
					$Global:healthservicedll.Message = "The version " + $Global:healthservicedll.version + " of HealthService.dll is supported"
				}
			}
		}
	}
	
	if ('$env:SystemRoot\\System32\wintrust.dll') {
		[version]$wintrustMinimumFileVersion = '6.1.7601.23971'
		$wintrustprops = @{
			Message = ""
			Valid   = $true
			Version = [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\wintrust.dll).VersionInfo).ProductMajorPart + '.' + [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\wintrust.dll).VersionInfo).ProductMinorPart + '.' + [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\wintrust.dll).VersionInfo).ProductBuildPart + '.' + [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\wintrust.dll).VersionInfo).FilePrivatePart
		}
		$Global:wintrustdll = new-object psobject -Property $wintrustprops

		if (([version]$Global:wintrustdll.version -lt $wintrustMinimumFileVersion) ) {
			$Global:wintrustdll.Valid = $false
			$Global:wintrustdll.Message = "Environment is not supported: " + [System.Environment]::OSVersion.VersionString + "`r`nMDE can't start - it requires wintrust.dll version $wintrustMinimumFileVersion or higher, while this device has version " + $wintrustdll.version + ". `r`n" `
				+ "You should install one of the following updates:`r`n" `
				+ "* KB4057400 - 2018-01-19 preview of monthly rollup.`r`n" `
				+ "* KB4074598 - 2018-02-13 monthly rollup.`r`n" `
				+ "* A later monthly rollup that supersedes them.`r`n"
		}
		else {
			$Global:wintrustdll.Message = "The version " + $Global:wintrustdll.version + " of wintrust.dll is supported"
		}
	}

	if (('$env:SystemRoot\\System32\tdh.dll')) {
		$tdhprops = @{
			Message = ""
			Valid   = $true
			Version = [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\tdh.dll).VersionInfo).ProductMajorPart + '.' + [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\tdh.dll).VersionInfo).ProductMinorPart + '.' + [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\tdh.dll).VersionInfo).ProductBuildPart + '.' + [string]((Get-ItemProperty -Path $env:SystemRoot\\System32\tdh.dll).VersionInfo).FilePrivatePart
		}
		$Global:tdhdll = new-object psobject -Property $tdhprops
		
		if ($OSBuild -eq "9600") {
			[version]$gdrTdhMinimumFileVersion = '6.3.9600.17958'
		}
		else {
			[version]$gdrTdhMinimumFileVersion = '6.1.7601.18939'
			[version]$ldrMinimumFileVersion = '6.1.7601.22000'
			[version]$ldrTdhMinimumFileVersion = '6.1.7601.23142'
		}
	
		if ([version]$Global:tdhdll.Version -lt $gdrTdhMinimumFileVersion) {
			$Global:tdhdll.Valid = $false
			$Global:tdhdll.Message = "Environment is not supported: " + [System.Environment]::OSVersion.VersionString + "`r`nMDE can't start - it requires tdh.dll version $gdrTdhMinimumFileVersion or higher, while this device has version " + $tdhdll.version + ". `r`n" `
				+ "You should install the following update:`r`n" `
				+ "* KB3080149 - Update for customer experience and diagnostic telemetry.`r`n"
		}
		elseif ($OSBuild -eq "7601" -and [version]$Global:tdhdll.Version -ge $ldrMinimumFileVersion -and [version]$tdhdll.Version -lt $ldrTdhMinimumFileVersion) {
			$Global:tdhdll.Valid = $false
			$Global:tdhdll.Message = "Environment is not supported: " + [System.Environment]::OSVersion.VersionString + "`r`nMDE can't start - it requires tdh.dll version $ldrTdhMinimumFileVersion or higher, while this device has version " + $tdhdll.version + ". `r`n" `
				+ "You should install the following update:`r`n" `
				+ "* KB3080149 - Update for customer experience and diagnostic telemetry.`r`n"
		}
		else {
			$Global:tdhdll.Message = "The version " + $Global:tdhdll.version + " of tdh.dll is supported"
		}
	}

	$protocol = [Enum]::ToObject([System.Net.SecurityProtocolType], 3072)
	[string]$global:SSLProtocol = $null
	try {
		[System.Net.ServicePointManager]::SecurityProtocol = $protocol
	}
 catch [System.Management.Automation.SetValueInvocationException] {
		$global:SSLProtocol = "`r`nEnvironment is not supported , the missing KB must be installed`r`n"`
			+ "" + [System.Environment]::OSVersion.VersionString + ", MDE requires TLS 1.2 support in .NET framework 3.5.1, exception " + $_.Exception.Message + " . You should install the following updates:`n" `
			+ "* KB3154518 - Support for TLS System Default Versions included in the .NET Framework 3.5.1 on Windows 7 SP1 and Server 2008 R2 SP1`n"`
			+ "* .NET framework 4.0 or later.`n"`
			+ "########################################################################################################################" 
	}
 Catch [Exception] {
		$global:SSLProtocol = $_.Exception.Message
	}
}

function TestASRRules() {
	#Taken from: https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction#block-process-creations-originating-from-psexec-and-wmi-commands
	$ASRRuleBlockPsExec = "d1e49aac-8f56-4280-b9ba-993a6d77406c"

	$ASRRules = (Get-MpPreference).AttackSurfaceReductionRules_Ids
	$ASRActions = (Get-MpPreference).AttackSurfaceReductionRules_Actions
	if (($ASRRules) -and ($ASRActions) -and (!$system)) {
		Write-output "############################ ASR rule check ###############################" | Out-File $connectivityCheckFile -Append
		# Check for existance of 'Block' mode ASR rule that can block PsExec from running
		$RuleIndex = $ASRRules::indexof($ASRRules, $ASRRuleBlockPsExec)
		if (($RuleIndex -ne -1) -and ($ASRActions[$RuleIndex] -eq 1)) {
			# Check if exclusions on script path are set
			$ASRRulesExclusions = (Get-MpPreference).AttackSurfaceReductionOnlyExclusions
			if (($ASRRulesExclusions) -and (($ASRRulesExclusions -contains $PSScriptRoot + '\') -or ($ASRRulesExclusions -contains $PSScriptRoot))) {
				"ASR rule 'Block process creations originating from PSExec and WMI commands' exists in block mode, but script path is excluded as needed" | Out-File $connectivityCheckFile -Append
				Write-Host -BackgroundColor Green -ForegroundColor black "Script path is excluded from ASR rules so URL checks can run as expected."
			} 
			else {
				"ASR rule 'Block process creations originating from PSExec and WMI commands' exists on the device and is in Block mode" | Out-File $connectivityCheckFile -Append
				Write-Host -BackgroundColor Red -ForegroundColor Yellow "Please note that ASR rule 'Block process creations originating from PSExec and WMI commands' is enabled and can block this tool from performing network validation if no exclusion is set" 			
			}
		}
	}
}

#This function expects to receive the EventProvider, EventId and Error string and returns the error event if found
function Get-MatchingEvent($EventProvider, $EventID, $ErrorString) {
	$EventResult = Get-WinEvent -ProviderName $EventProvider -MaxEvents 1000 -ErrorAction SilentlyContinue `
	| Where-Object -Property Id -eq $EventID `
	| Where-Object { $_.Properties.Value -like "*$ErrorString*" } `
	| Sort-Object -Property TimeCreated -Unique `
	| Select-Object -L 1
	
	return $EventError = $EventResult;
}

function CheckProxySettings() {		
	$RegPathHKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
	$RegPathHKU = "HKU:\S-1-5-18\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
	$RegPathHKCU = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
	$RegPathDefault = "HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"

	if (Get-RegistryValue -Path $RegPathHKLM -Value "ProxyServer") {
		"Proxy settings in device level were detected" | Out-File $connectivityCheckFile -append
		"The detected Proxy settings in device path (HKLM) are :  " + (Get-RegistryValue -Path $RegPathHKLM -Value "ProxyServer" ) | Out-File $connectivityCheckFile -append
		"ProxyEnable is set to :  " + (Get-RegistryValue -Path $RegPathHKLM -Value "ProxyEnable" ) | Out-File $connectivityCheckFile -append
	} 
	
	if (Get-RegistryValue -Path $RegPathHKU -Value "ProxyServer") {
		"Proxy settings in SYSTEM SID level were detected" | Out-File $connectivityCheckFile -append
		"The detected proxy settings in SYSTEM HKU path (S-1-5-18) are :  " + (Get-RegistryValue -Path $RegPathHKU -Value "ProxyServer" ) | Out-File $connectivityCheckFile -append
		"ProxyEnable is set to :  " + (Get-RegistryValue -Path $RegPathHKU -Value "ProxyEnable" ) | Out-File $connectivityCheckFile -append
	} 

	if (Get-RegistryValue -Path $RegPathHKCU -Value "ProxyServer") {
		"Proxy setting in current user level were detected" | Out-File $connectivityCheckFile -append
		"The detected proxy settings in current user path (HKCU) are :  " + (Get-RegistryValue -Path $RegPathHKCU -Value "ProxyServer" ) | Out-File $connectivityCheckFile -append
		"ProxyEnable is set to :  " + (Get-RegistryValue -Path $RegPathHKCU -Value "ProxyEnable" ) | Out-File $connectivityCheckFile -append
	}
	if (Get-RegistryValue -Path $RegPathDefault -Value "ProxyServer") {
		"Proxy setting in DEFAULT user level were detected" | Out-File $connectivityCheckFile -append
		"The detected proxy settings in the default user path (.DEFAULT) are :  " + (Get-RegistryValue -Path $RegPathDefault -Value "ProxyServer" ) | Out-File $connectivityCheckFile -append
		"ProxyEnable is set to :  " + (Get-RegistryValue -Path $RegPathDefault -Value "ProxyEnable" ) | Out-File $connectivityCheckFile -append
	}
	Check-Command-verified "bitsadmin.exe"
	"Proxy setting detected via bitsadmin: " + (&bitsadmin.exe /Util /GETIEPROXY LOCALSYSTEM) | Out-File $connectivityCheckFile -append
}
function GetAddRemovePrograms($regpath) {
	$programsArray = $regpath | ForEach-Object { New-Object PSObject -Property @{
			DisplayName     = $_.GetValue("DisplayName")
			DisplayVersion  = $_.GetValue("DisplayVersion")
			InstallLocation = $_.GetValue("InstallLocation")
			Publisher       = $_.GetValue("Publisher")
		} }
	$ProgramsArray | Where-Object { $_.DisplayName }
}

function FormatTimestamp($TimeStamp) {
	if ($TimeStamp) {
		return ([DateTime]::FromFiletime([Int64]::Parse($TimeStamp))).ToString("U")
	} 
	else {
		return "Unknown"
	}
}

function Dump-ConnectionStatus {
	"Last SevilleDiagTrack LastNormalUploadTime TimeStamp: " + (FormatTimestamp($LastCYBERConnected)) | Out-File $connectivityCheckFile -append
	"Last SevilleDiagTrack LastRealTimeUploadTime TimeStamp: " + (FormatTimestamp($LastCYBERRTConnected)) | Out-File $connectivityCheckFile -append
	"Last SevilleDiagTrack LastInvalidHttpCode: " + $LastInvalidHTTPcode | Out-File $connectivityCheckFile -append
}

function Get-DeviceInfo {
	Write-Report -section "devInfo" -subsection "deviceName" -displayname "Device name" -value $env:computername 
	Write-Report -section "devInfo" -subsection "OSName" -displayname "Device Operating System" -value $OSProductName 
	Write-Report -section "devInfo" -subsection "OSBuild" -displayname "OS build number" -value (([System.Environment]::OSVersion.VersionString) + "." + $MinorBuild)
	Write-Report -section "devInfo" -subsection "Edition" -displayname "OS Edition" -value $OSEditionName
	Write-Report -section "devInfo" -subsection "Architecture" -displayname "OS Architecture" -value $arch
}

function Collect-RegValues {
	[string]$SenseId = (Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\Windows Advanced Threat Protection" -Value "SenseId")
	[string]$DeviceTag = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging" -Value "Group")
	[string]$GroupIds = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Value "GroupIds") 
	[string]$LastCnCConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Value LastConnected)

	if ($OSPreviousVersion) {
		$sensepr = Get-ChildItem -Path "C:\Program Files\Microsoft Monitoring Agent\Agent\Health Service State\Monitoring Host Temporary File*" -Filter mssenses.exe -Recurse -ErrorAction SilentlyContinue | Sort-Object -Property TimeCreated -Unique
	}
	elseif ($MDfWS) {
		$InstallPath = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value "InstallLocation")
		$sensepr = Join-Path $InstallPath "MsSense.exe"
	} else {
		$sensepr = (Get-item -Path "C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe" -ErrorAction SilentlyContinue)
	}

	Get-DeviceInfo
	if (!$SenseId) {
		# Option to get SenseID from event log as some older OS versions only post Sense Id to log
		$SenseId = (Get-WinEvent -ProviderName Microsoft-Windows-SENSE -ErrorAction SilentlyContinue | Where-Object -Property Id -eq 13 | Sort-Object -Property TimeCreated | Select-Object -L 1).Message			
	}
	if ($SenseId) {
		Write-Report -section "EDRCompInfo" -subsection "DeviceId" -displayname "Device ID" -value $SenseId 

		$OrgId = (Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\Status" -Value "OrgID")
		Write-Report -section "EDRCompInfo" -subsection "OrgId" -displayname "Organization Id" -value $OrgId

		if ($sensepr) {
			[version]$Global:SenseVer = ([string](([System.IO.FileInfo]$sensepr).VersionInfo).ProductMajorPart + '.' + [string](([System.IO.FileInfo]$sensepr).VersionInfo).ProductMinorPart + '.' + [string](([System.IO.FileInfo]$sensepr).VersionInfo).ProductBuildPart + '.' + [string](([System.IO.FileInfo]$sensepr).VersionInfo).FilePrivatePart)
			Write-Report -section "EDRCompInfo" -subsection "SenseVersion" -displayname "Sense version" -value $Global:SenseVer 
		}
		$SenseConfigVer = (Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\Status" -Value "ConfigurationVersion" ) 
		if ($SenseConfigVer -like "*-*") {
			$SenseConfigVer = $SenseConfigVer.split('-')[0] 
		}
		Write-Report -section "EDRCompInfo" -subsection "SenseConfigVersion" -displayname "Sense Configuration version" -value $SenseConfigVer 

		"Sense GUID is: " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection" -Value "senseGuid") | Out-File $connectivityCheckFile -append
		if ($DeviceTag -ne $False) {
			"Optional Sense DeviceTag is: " + $DeviceTag | Out-File $connectivityCheckFile -append
		}		
		if ($GroupIds) {
			"Optional Sense GroupIds is: " + $GroupIds | Out-File $connectivityCheckFile -append
		}
		if (($LastCnCConnected) -and (!$ASM)) {
			"Last Sense Seen TimeStamp is: " + (FormatTimestamp($LastCnCConnected)) | Out-File $connectivityCheckFile -append
		}
	}
	if (!$IsOnboarded) {
		"Device is: not onboarded" | Out-File $connectivityCheckFile -append
	}
}

Function StartGet-MSInfo ([boolean]$NFO = $true, [boolean]$TXT = $true, [string]$OutputLocation = $PWD.Path, [string]$Suffix = '') {
	$Process = "msinfo32.exe"
	
	if (test-path (join-path ([Environment]::GetFolderPath("System")) $Process)) {
		$ProcessPath = (join-path ([Environment]::GetFolderPath("System")) $Process)
	}
 elseif (test-path (join-path ([Environment]::GetFolderPath("CommonProgramFiles")) "Microsoft Shared\MSInfo\$Process")) {
		$ProcessPath = (join-path ([Environment]::GetFolderPath("CommonProgramFiles")) "Microsoft Shared\MSInfo\$Process")
	}
 else {
		Check-Command-verified "cmd.exe"
		$ProcessPath = "cmd.exe /c start /wait $Process"
	}
	if ($TXT) {
		$InfoFile = Join-Path -Path $OutputLocation -ChildPath ("msinfo32" + $Suffix + ".txt")
		CheckAuthenticodeSignature $ProcessPath
		&$ProcessPath /report "$InfoFile"
	}
	if ($NFO) {
		$InfoFile = Join-Path -Path $OutputLocation -ChildPath ("msinfo32" + $Suffix + ".nfo")
		CheckAuthenticodeSignature $ProcessPath
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

function Process-XSLT {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$XmlPath, 
		[Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$XslPath,
		[Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$HtmlOutput )

	Try {
		If ((Test-path($XmlPath)) -and (Test-path($XslPath))) {
			$myXslCompiledTransfrom = new-object System.Xml.Xsl.XslCompiledTransform
			$xsltArgList = New-Object System.Xml.Xsl.XsltArgumentList

			$myXslCompiledTransfrom.Load($XslPath)
			$xmlWriter = [System.Xml.XmlWriter]::Create($HtmlOutput)
		
			$myXslCompiledTransfrom.Transform($XmlPath, $xsltArgList, $xmlWriter)
	
			$xmlWriter.Flush()
			$xmlWriter.Close()

			return $True
		} 
	}
 Catch {
		return $False
	}
}

function GenerateHealthCheckReport() {
	# Save XML log file
	$script:xmlDoc.Save($XmlLogFile)

	CheckHashFile "$XslFile" "7F801B73C2E0D1A43EF9915328881A85D1EE7ADDBC31273CCD72D1C81CB2B258"
	# Transform XML to HTML based using XSLT
	$Result = Process-XSLT -XmlPath $XmlLogFile -XslPath $XslFile -HtmlOutput $HtmOutputfile
	If (!$Result) {
		"Unable to generate HTML file" | Out-File $connectivityCheckFile -append
	}
}

function WriteReport($id, $CheckresultInsertions, $GuidanceRInsertions) {
	$CurrEvent = $ResourcesOfEvents.$id
	$i = 1
	$CurrEvent, $i = UpdateInsertion $CurrEvent $CheckresultInsertions $i "checkresult"
	$CurrEvent, $i = UpdateInsertion $CurrEvent $GuidanceRInsertions $i "guidance"
	$CurrEvent.checkresult = [regex]::replace($CurrEvent.checkresult, '\n', '<br>')
	$CurrEvent.guidance = [regex]::replace($CurrEvent.guidance, '\n', '<br>')
	Write-ReportEvent -section "events" -severity $CurrEvent.severity -category $CurrEvent.category -check $CurrEvent.check -id $id -checkresult $CurrEvent.checkresult -guidance $CurrEvent.guidance
}

function UpdateInsertion($CurrEvent, $Insertions, $i, $id) {
	If ($Insertions.Count -gt 0) {
		Foreach ($insert in $Insertions) {
			$ind = '%' + "$i"
			$CurrEvent.$id = [regex]::replace($CurrEvent.$id, $ind, $insert)
			$i += 1
		}	
	}
	return $CurrEvent, $i
}

function CheckExpirationCertUtil($IsDisabled, $TestName, $RootToCheck) {
	Check-Command-verified "certutil.exe"
	$CertResults = &certutil -verifyctl $TestName $RootToCheck | findstr /i SignerExpiration
	"`n`nCommand:`n`tcertutil -verifyctl $TestName | findstr /i SignerExpiration `nResults:`n`t" + $CertResults | Out-File $CertSignerResults -append

	#Get the number of days from $CertResults: 'SignerExpiration = "12/2/2021 11:25 PM", "273.5 Days"'
	$ExpirationTime = $CertResults.split('"')[3].split(" ")[0]
	#Case there is ',' instead '.'
	$ExpirationTime = [double]($ExpirationTime.replace(',', '.'))
	If ($ExpirationTime -le 0) {
		$days = [string]($ExpirationTime * (-1))
		If ($IsDisabled) {
			#WriteReport 121013 @(@($days, $CertSignerResults)) @()
		}
		else {
			#WriteReport 121014 @(@($days, $CertSignerResults)) @()
		}
	}
}

function CheckAuthenticodeSignature($pathToCheck) {
	if (test-path $resultOutputDir -ErrorAction SilentlyContinue) {
		$issuerInfo = "$resultOutputDir\issuerInfo.txt"
	} else {
		$issuerInfo = "$outputDir\issuerInfo.txt"
	}
	if ($pathToCheck) {
		if (Test-Path -path $pathToCheck -ErrorAction SilentlyContinue) {
			$AuthenticodeSig = (Get-AuthenticodeSignature -FilePath $pathToCheck)
			$cert = $AuthenticodeSig.SignerCertificate
			$FileInfo = (get-command $pathToCheck).FileVersionInfo			
			$issuer = $cert.Issuer
			#OS is older than 2016 and some built-in processes will not be signed
			if (($OSBuild -lt 14393) -and (!$AuthenticodeSig.SignerCertificate)) {
				if (($FileInfo.CompanyName -eq "Microsoft Corporation")) {
					return
				}
				else {
					Write-Error "Script execution terminated because a process or script that does not have any signature was detected" | Out-File $issuerInfo -append
					$pathToCheck | Out-File $issuerInfo -append
					$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
					$cert | Format-List * | Out-File $issuerInfo -append
					[Environment]::Exit(1)
				}
			}
			#check if valid
			if ($AuthenticodeSig.Status -ne "Valid") {
				Write-Error "Script execution terminated because a process or script that does not have a valid Signature was detected" | Out-File $issuerInfo -append
				$pathToCheck | Out-File $issuerInfo -append
				$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
				$cert | Format-List * | Out-File $issuerInfo -append
				[Environment]::Exit(1)
			}
			#check issuer
			if (($issuer -ne "CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Code Signing PCA, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Code Signing PCA 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Development PCA 2014, O=Microsoft Corporation, L=Redmond, S=Washington, C=US")) {
				Write-Error "Script execution terminated because a process or script that is not Microsoft signed was detected" | Out-File $issuerInfo -append
				$pathToCheck | Out-File $issuerInfo -append
				$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
				$cert | Format-List * | Out-File $issuerInfo -append
				[Environment]::Exit(1)
			}	
			if ($AuthenticodeSig.IsOSBinary -ne "True") {
				#If revocation is offline then test below will fail
				$IsOnline = (Get-NetConnectionProfile).IPv4Connectivity -like "*Internet*"
				if ($IsOnline) {
					$IsWindowsSystemComponent = (Test-Certificate -Cert $cert -EKU "1.3.6.1.4.1.311.10.3.6" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -WarningVariable OsCertWarnVar -ErrorVariable OsCertErrVar)
					$IsMicrosoftPublisher = (Test-Certificate -Cert $cert -EKU "1.3.6.1.4.1.311.76.8.1" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -WarningVariable MsPublisherWarnVar -ErrorVariable MsPublisherErrVar)
					if (($IsWindowsSystemComponent -eq $False) -and ($IsMicrosoftPublisher -eq $False)) {
						#Defender AV and some OS processes will have an old signature if older version is installed
						#Ignore if cert is OK and only signature is old
						if (($OsCertWarnVar -like "*CERT_TRUST_IS_NOT_TIME_VALID*") -or ($MsPublisherWarnVar -like "*CERT_TRUST_IS_NOT_TIME_VALID*") -or ($OsCertWarnVar -like "*CERT_TRUST_IS_OFFLINE_REVOCATION*") -or ($MsPublisherWarnVar -like "CERT_TRUST_IS_OFFLINE_REVOCATION")) {
							return
						}
						Write-Error "Script execution terminated because the process or script certificate failed trust check" | Out-File $issuerInfo -append
						$pathToCheck | Out-File $issuerInfo -append
						$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
						$cert | Format-List * | Out-File $issuerInfo -append
						[Environment]::Exit(1)
					}
				}
			}
		}
	 else {
			Write-Error ("Path " + $pathToCheck + " was not found") | Out-File $issuerInfo -append
		}
	}
}

function CheckHashFile($filePath, $hash) {
	if (test-path $filePath) {
		$fileHash = Get-FileHash -Path $filePath
		if ($fileHash.Hash -ne $hash) {
			Write-Error "Script execution terminated because hash did not match expected value. Expected value: $hash"
			[Environment]::Exit(1)
		}
	}
}

function NTFSSecurityAccess($resultOutputDir) {
	Check-Command-verified "takeown.exe"
	#take ownership
	Start-Process -wait -WindowStyle minimized Takeown.exe -ArgumentList "/f `"$resultOutputDir`" /r /d y"
	Check-Command-verified "icacls.exe"
	#Prevent inheritance
	Start-Process -wait -WindowStyle minimized icacls.exe -ArgumentList "`"$resultOutputDir`" /inheritance:r"
	Check-Command-verified "icacls.exe"
	#Allow Access to Administrators
	Start-Process -wait -WindowStyle minimized icacls.exe -ArgumentList "`"$resultOutputDir`" /grant `"Administrators`":(OI)(CI)F /t /q"
	Check-Command-verified "icacls.exe"
	#Allow Access to Creator owner 
	Start-Process -wait -WindowStyle minimized icacls.exe -ArgumentList "`"$resultOutputDir`" /grant `"Creator Owner`":(OI)(CI)F /t /q"
	Check-Command-verified "icacls.exe"
	#Allow Access to SYSTEM
	Start-Process -wait -WindowStyle minimized icacls.exe -ArgumentList "`"$resultOutputDir`" /grant `"NT AUTHORITY\SYSTEM`":(OI)(CI)F /t /q"
	Check-Command-verified "icacls.exe"
	if (!$System) {
		#Allow curent user access
		Start-Process -wait -WindowStyle minimized icacls.exe -ArgumentList "`"$resultOutputDir`" /grant `"$context`":(OI)(CI)F /t /q"
	}
	
}

#gets path of command and check signature
function Check-Command-verified($checkCommand) {
	$command = Get-Command $CheckCommand -ErrorAction SilentlyContinue
	CheckAuthenticodeSignature $command.path
}

function get-MdeConfigMgrLogs() {
	# folder for SIMA logs and info
	New-Item -ItemType Directory -Path "$resultOutputDir\MdeConfigMgrLogs" -ErrorAction SilentlyContinue | out-Null
	$MdeConfigMgrRegInfo = "$resultOutputDir\MdeConfigMgrLogs\MdeConfigMgrRegInfo.txt"
	# reg info collections
	"please find reg info for MdeConfigMgr flow On : " + $ScriptRunTime + "`n" | Out-File $MdeConfigMgrRegInfo
	"EnrollmentStatus : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value EnrollmentStatus) | Out-File $MdeConfigMgrRegInfo -Append
	"TenantId : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value TenantId) | Out-File $MdeConfigMgrRegInfo -Append
	"DeviceId : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value DeviceId) | Out-File $MdeConfigMgrRegInfo -Append
	"EnrollmentPayload : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value EnrollmentPayload) | Out-File $MdeConfigMgrRegInfo -Append
	"MemConfiguration : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value MemConfiguration) | Out-File $MdeConfigMgrRegInfo -Append
	"LastCheckinAttempt : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value LastCheckinAttempt) | Out-File $MdeConfigMgrRegInfo -Append
	"LastCheckinSuccess : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SenseCM\" -Value LastCheckinAttempt) | Out-File $MdeConfigMgrRegInfo -Append
	"SystemManufacturer : " + (Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation\" -Value SystemManufacturer) | Out-File $MdeConfigMgrRegInfo -Append
	"SystemProductName : " + (Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation\" -Value SystemProductName) | Out-File $MdeConfigMgrRegInfo -Append
	"ProductName : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Value ProductName) | Out-File $MdeConfigMgrRegInfo -Append
	"UBR : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Value UBR) | Out-File $MdeConfigMgrRegInfo -Append
	"OnboardedInfo : " | Out-File $MdeConfigMgrRegInfo -Append
	(Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value OnboardedInfo) |  ConvertFrom-Json | Select-Object body | Out-File $MdeConfigMgrRegInfo -Append
	"SenseCmConfiguration : " | Out-File $MdeConfigMgrRegInfo -Append
	(Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value SenseCmConfiguration) |  ConvertFrom-Json | Out-File $MdeConfigMgrRegInfo -Append
	"NextVersion : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value NextVersion) | Out-File $MdeConfigMgrRegInfo -Append
	"InvalidVersion : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value InvalidVersion) | Out-File $MdeConfigMgrRegInfo -Append
	"SwitchStatus : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value SwitchStatus) | Out-File $MdeConfigMgrRegInfo -Append
	"InstallLocation : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value InstallLocation) | Out-File $MdeConfigMgrRegInfo -Append
	"NewPlatform : " + (Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\" -Value NewPlatform) | Out-File $MdeConfigMgrRegInfo -Append
	"MsSensePath : " + ($MsMpEngPath = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\sense" -Value ImagePath) | Out-File $MdeConfigMgrRegInfo -Append
	"MsSecFltPath : " + ($MsMpEngPath = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MsSecFlt" -Value ImagePath) | Out-File $MdeConfigMgrRegInfo -Append

	# collect event logs
	if (Test-Path -Path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-AADRT%4Admin.evtx') {
		Copy-Item -path $env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-AADRT%4Admin.evtx -Destination $resultOutputDir\EventLogs\AADRT-Admin.evtx
	}

	if (Test-Path -Path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-AAD%4Operational.evtx') {
		Copy-Item -path $env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-AAD%4Operational.evtx -Destination $resultOutputDir\EventLogs\AAD-Operational.evtx
	}

	# collect additional files
	if (test-path -Path $env:SystemRoot\Temp\MpSigStub.log) {
		Copy-Item -path $env:SystemRoot\Temp\MpSigStub.log -Destination $resultOutputDir\EventLogs\MpSigStub.log
	}

	#collect sense CM data folder
	if (($eulaAccepted -eq "Yes") -and (!$system)) {
		#$PSExecCommand = Join-Path $ToolsDir "PsExec.exe"
		$PSExecCommand = Join-Path $ToolsExeDir "PsExec.exe"
		if (test-Path -path $PSExecCommand) {
			CheckAuthenticodeSignature $PSExecCommand
		}
		Check-Command-verified "Robocopy.exe"
		$StartCopy = Start-Process -PassThru -wait -WindowStyle minimized $PSExecCommand -ArgumentList "-accepteula -nobanner -s robocopy.exe `"$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\SenseCM`" `"$resultOutputDir\MdeConfigMgrLogs`" /E /ZB /w:1 /r:1  /log:`"$resultOutputDir\MdeConfigMgrLogs\copy.log`""
	}
 elseif ($system) {
		Check-Command-verified "Robocopy.exe"
		$StartCopy = Start-Process -PassThru -wait -WindowStyle minimized Robocopy.exe -ArgumentList "`"$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\SenseCM`" `"$resultOutputDir\MdeConfigMgrLogs`" /E /ZB /w:1 /r:1  /log:`"$resultOutputDir\MdeConfigMgrLogs\copy.log`""
	}
}

# Return the information about Sense Configuration Manager a PSObject.
Function Get-SenseCMInfo () {
	$SenseCMInfoObj = New-Object -TypeName PSObject

	$SenseCMRegPath = "HKLM:\SOFTWARE\Microsoft\SenseCM\"
	
	# Check the device's enrollment status
	$EnrollmentStatusId = (Get-RegistryValue -Path $SenseCMRegPath -Value "EnrollmentStatus" -ErrorAction SilentlyContinue)
	if ($EnrollmentStatusId) {
		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "EnrollmentStatusId" -Value $EnrollmentStatusId -ErrorAction SilentlyContinue
		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "EnrollmentStatusReportId" -Value "" -ErrorAction SilentlyContinue
		switch ($EnrollmentStatusId) {
			1 {$EnrollmentStatusText = "Device is enrolled to AAD and MEM"}
			2 {$EnrollmentStatusText = "Device is not enrolled and was never enrolled"}
			3 {$EnrollmentStatusText = "Device is managed by MDM Agent"}
			4 {$EnrollmentStatusText = "Device is managed by SCCM Agent"}
			10 {$EnrollmentStatusText = "Device failed to perform Hybrid join"; $SenseCMInfoObj.EnrollmentStatusReportId = "121023"} 
			13 {$EnrollmentStatusText = "Device is registered to AAD but not enrolled to MEM"; $SenseCMInfoObj.EnrollmentStatusReportId = "121024"}
			14 {$EnrollmentStatusText = "Device failed to register and enroll"; $SenseCMInfoObj.EnrollmentStatusReportId = "121025"}
			15 {$EnrollmentStatusText = "Device join mismatch between MDE and AAD tenants"; $SenseCMInfoObj.EnrollmentStatusReportId = "121022"}
			16 {$EnrollmentStatusText = "Device registration with AAD failed due to bad SCP"; $SenseCMInfoObj.EnrollmentStatusReportId = "121026"}
			17 {$EnrollmentStatusText = "Device registration failed due to incorrect SCP settings"; $SenseCMInfoObj.EnrollmentStatusReportId = "121017"}
			18 {$EnrollmentStatusText = "Device was not found in Azure AD"; $SenseCMInfoObj.EnrollmentStatusReportId = "121027"}
			{(($_ -eq 21) -or ($_ -eq 22))} {$EnrollmentStatusText = "Device is managed by other MDM authority"}
			23 {$EnrollmentStatusText = "Device was enrolled but is not enrolled now"}
			25 {$EnrollmentStatusText = "Device is managed by SCCM Agent"}
			{(($_ -ge 26) -and ($_ -le 32))} {$EnrollmentStatusText = "Device status in Azure AD incomplete"; $SenseCMInfoObj.EnrollmentStatusReportId = "121028"}
			36 {$EnrollmentStatusText = "Device enrollment failed due to AAD LDAP API error"; $SenseCMInfoObj.EnrollmentStatusReportId = "121029"}
			37 {$EnrollmentStatusText = "Device is not synced with Azure AD"; $SenseCMInfoObj.EnrollmentStatusReportId = "121030"}
			38 {$EnrollmentStatusText = "Device is not enrolled due to domain connectivity issues"; $SenseCMInfoObj.EnrollmentStatusReportId = "121031"}
			40 {$EnrollmentStatusText = "Device clock is not synchronizated with Azure AD time"; $SenseCMInfoObj.EnrollmentStatusReportId = "121032"}
			41 {$EnrollmentStatusText = "Device is not enrolled dur to network name resolution issues"; $SenseCMInfoObj.EnrollmentStatusReportId = "121033"}
			42 {$EnrollmentStatusText = "Device failed to perform Hybrid join"; $SenseCMInfoObj.EnrollmentStatusReportId = "121034"}
			default {
				$EnrollmentStatusText = "Unknown State"
			}
		}

		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "EnrollmentStatusText" -Value $EnrollmentStatusText -ErrorAction SilentlyContinue
		$DeviceId =  (Get-RegistryValue -Path $SenseCMRegPath -Value DeviceId -ErrorAction SilentlyContinue)
		if ($DeviceId) {$DeviceId = $DeviceId.Tolower()}
		
		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "AADDeviceId" -Value $DeviceId -ErrorAction SilentlyContinue
		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "TenantId" -Value (Get-RegistryValue -Path $SenseCMRegPath -Value TenantId) -ErrorAction SilentlyContinue
		
		$IntuneDeviceID = ((Get-RegistryValue -Path $SenseCMRegPath -Value EnrollmentPayload -ErrorAction SilentlyContinue) |  ConvertFrom-Json -ErrorAction SilentlyContinue).intuneDeviceId
		Add-Member -InputObject $SenseCMInfoObj -MemberType NoteProperty -Name "IntuneDeviceID" -Value $IntuneDeviceID -ErrorAction SilentlyContinue
	}

	return $SenseCMInfoObj
}


# Return the output of dsregcmd /status as a PSObject.
Function Get-DsRegStatus () {
	if (test-path -path $env:windir\system32\dsregcmd.exe) {
		Check-Command-verified "dsregcmd.exe"
		$dsregcmd = &dsregcmd /status
		
		# Dump dsregcmd info to results
		$dsregcmd  | Out-File "$resultOutputDir\SystemInfoLogs\dsregcmd.txt"
	
		 $o = New-Object -TypeName PSObject
		 foreach($line in $dsregcmd) {
			  if ($line -like "| *") {
				   if (-not [String]::IsNullOrWhiteSpace($currentSection) -and $null -ne $so) {
						Add-Member -InputObject $o -MemberType NoteProperty -Name $currentSection -Value $so -ErrorAction SilentlyContinue
				   }
				   $currentSection = $line.Replace("|","").Replace(" ","").Trim()
				   $so = New-Object -TypeName PSObject
			  } elseif ($line -match " *[A-z]+ : [A-z0-9\{\}]+ *") {
				   Add-Member -InputObject $so -MemberType NoteProperty -Name (([String]$line).Trim() -split " : ")[0] -Value (([String]$line).Trim() -split " : ")[1] -ErrorAction SilentlyContinue
			  }
		 }
		 if (-not [String]::IsNullOrWhiteSpace($currentSection) -and $null -ne $so) {
			  Add-Member -InputObject $o -MemberType NoteProperty -Name $currentSection -Value $so -ErrorAction SilentlyContinue
		 }
		return $o
	}
}

# Get Windows 10 MDM Enrollment Status.
function Get-MDMEnrollmentStatus {
	#Locate correct Enrollment Key
	$EnrollmentKey = Get-Item -Path HKLM:\SOFTWARE\Microsoft\Enrollments\* | Get-ItemProperty | Where-Object -FilterScript {$null -ne $_.UPN}
	
	if ($EnrollmentKey) {
		# Translate the MDM Enrollment Type in a readable string.
		Switch ($EnrollmentKey.EnrollmentType) {
		0 {$EnrollmentTypeText = "Enrollment was not started"}
		6 {$EnrollmentTypeText = "MDM enrolled"}
		13 {$EnrollmentTypeText = "Azure AD joined"}
		}
		Add-Member -InputObject $EnrollmentKey -MemberType NoteProperty -Name EnrollmentTypeText -Value $EnrollmentTypeText
	} else {
		# Write-Error "Device is not enrolled to MDM."
		$EnrollmentKey = New-Object -TypeName PSObject
		Add-Member -InputObject $EnrollmentKey -MemberType NoteProperty -Name EnrollmentTypeText -Value "Not enrolled"
	}

	# Return 'Not enrolled' if Device is not enrolled to an MDM.
	return $EnrollmentKey
}

# TODO: Report the connectivity failure
function CheckDCConnecvitiy {
	$ErrorActionPreference = "SilentlyContinue"

    $DCName = ""
	Check-Command-verified "nltest.exe"
    $DCTest = nltest /dsgetdc:
    $DCName = $DCTest | Select-String DC | Select-Object -first 1
    $DCName = ($DCName.tostring() -split "DC: \\")[1].trim()

    if (($DCName.length) -eq 0) {
		return $False		
	} else {
		return $True		
	}
}

function Get-SCPConfiguration {
	$SCPConfiguration = New-Object -TypeName PSObject
	Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name ResultID -Value "" -ErrorAction SilentlyContinue

	$CDJReg = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD -ErrorAction SilentlyContinue
	if (((($CDJReg.TenantId).Length) -eq 0) -AND ((($CDJReg.TenantName).Length) -eq 0)) {
		# No client-side registry setting were found for SCP, checking against DC
		if (CheckDCConnecvitiy) {
			$Root = [ADSI]"LDAP://RootDSE"
			$ConfigurationName = $Root.rootDomainNamingContext
			if (($ConfigurationName.length) -eq 0) {
				$SCPConfiguration.ResultID = 121016
			} else {
				$scp = New-Object System.DirectoryServices.DirectoryEntry;
				$scp.Path = "LDAP://CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,CN=Configuration," + $ConfigurationName;
				if ($null -ne $scp.Keywords){
					Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name ConfigType -Value "Domain" -ErrorAction SilentlyContinue
					if ($scp.Keywords -like ("*enterpriseDrsName*")) {
						# Enterprise DRS was found
						$SCPConfiguration.ResultID = 121017
						$SCPConfiguration.TenantName = $scp.Keywords.ToString()
					} else {
						Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name TenantName -Value (($scp.Keywords[0].tostring() -split ":")[1].trim()) -ErrorAction SilentlyContinue
						Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name TenantId -Value (($scp.Keywords[1].tostring() -split ":")[1].trim()) -ErrorAction SilentlyContinue
					}
				} Else {
					$SCPConfiguration.ResultID = 121018
				}
			}
		} Else {
			$SCPConfiguration.ResultID = 121019
		}
	} else {
		# Client-side registry setting were found for SCP
		Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name ConfigType -Value "Client" -ErrorAction SilentlyContinue
		Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name TenantName -Value ($CDJReg.TenantName) -ErrorAction SilentlyContinue
		Add-Member -InputObject $SCPConfiguration -MemberType NoteProperty -Name TenantId -Value ($CDJReg.TenantId) -ErrorAction SilentlyContinue
	}

	return $SCPConfiguration
}
# TODO: Connectivity checks to DRS 


function ConnecttoAzureAD {
    Write-Host ''
    Write-Host "Checking if there is a valid Access Token..." -ForegroundColor Yellow
    Write-Log -Message "Checking if there is a valid Access Token..."
    $headers = @{ 
                'Content-Type'  = "application\json"
                'Authorization' = "Bearer $global:accesstoken"
                }
    $GraphLink = "https://graph.microsoft.com/v1.0/domains"
    $GraphResult=""
    $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json

    if ($GraphResult.value.Count)
    {
            $headers = @{ 
            'Content-Type'  = "application\json"
            'Authorization' = "Bearer $global:accesstoken"
            }
            $GraphLink = "https://graph.microsoft.com/v1.0/me"
            $GraphResult=""
            $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json
            $User_DisplayName=$GraphResult.displayName
            $User_UPN=$GraphResult.userPrincipalName
            Write-Host "There is a valid Access Token for user: $User_DisplayName, UPN: $User_UPN" -ForegroundColor Green
            $msg="There is a valid Access Token for user: $User_DisplayName, UPN: $User_UPN" 
            Write-Log -Message $msg

    } else {
        Write-Host "There no valid Access Token, please sign-in to get an Access Token" -ForegroundColor Yellow
        Write-Log -Message "There no valid Access Token, please sign-in to get an Access Token"
        $global:accesstoken = Connect-AzureDevicelogin
        ''
        if ($global:accesstoken.Length -ge 1){
            $headers = @{ 
            'Content-Type'  = "application\json"
            'Authorization' = "Bearer $global:accesstoken"
            }
            $GraphLink = "https://graph.microsoft.com/v1.0/me"
            $GraphResult=""
            $GraphResult = (Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json").Content | ConvertFrom-Json
            $User_DisplayName=$GraphResult.displayName
            $User_UPN=$GraphResult.userPrincipalName
            Write-Host "You signed-in successfully, and got an Access Token for user: $User_DisplayName, UPN: $User_UPN" -ForegroundColor Green
            $msg="You signed-in successfully, and got an Access Token for user: $User_DisplayName, UPN: $User_UPN" 
            Write-Log -Message $msg
        }
    }
}

function CheckAzureADDeviceHealth ($DeviceID) {
	ConnecttoAzureAD

	$DeviceHealth = New-Object -TypeName PSObject

    $headers = @{ 
                'Content-Type'  = "application\json"
                'Authorization' = "Bearer $global:accesstoken"
                }

    $GraphLink = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$DeviceID'"
    try {
        $GraphResult = Invoke-WebRequest -Headers $Headers -Uri $GraphLink -UseBasicParsing -Method "GET" -ContentType "application/json"
        $AADDevice = $GraphResult.Content | ConvertFrom-Json

        if ($AADDevice.value.Count -ge 1) {
			# Device was found    
			Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name DeviceExists -Value $True -ErrorAction SilentlyContinue
			Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name DeviceEnabled -Value $AADDevice.value.accountEnabled -ErrorAction SilentlyContinue

			# Check if device in Stale state
			$LastLogonTimestamp = $AADDevice.value.approximateLastSignInDateTime
			Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name LastLogonTimestamp -Value $LastLogonTimestamp -ErrorAction SilentlyContinue
	
			$CurrentDate = Get-Date 
			$Diff = New-TimeSpan -Start $LastLogonTimestamp -End $CurrentDate
			$diffDays = $Diff.Days
			if (($diffDays -ge 21) -or ($diffDays.length -eq 0)) {
				Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name DeviceStale -Value $True -ErrorAction SilentlyContinue
			} else {
				Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name DeviceStale -Value $False -ErrorAction SilentlyContinue
			}

			# Check if device in Pending State
			$Cert = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($AADDevice.value.alternativeSecurityIds.key))
            $AltSec = $Cert -replace $cert[1]

            if (-not ($AltSec.StartsWith("X509:"))) {
                $devicePending=$true
            } else {
                $devicePending=$false
            }
			Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name DevicePending -Value $devicePending -ErrorAction SilentlyContinue
        } else {
            # Device was not found
            Add-Member -InputObject $DeviceHealth -MemberType NoteProperty -Name DeviceExists -Value $False -ErrorAction SilentlyContinue
        }
	} catch {
        Write-Host ''
        Write-Host "Operation aborted. Unable to connect to Azure AD, please check you entered a correct credentials and you have the needed permissions" -ForegroundColor red
        Write-Host ''
        Write-Host ''
        Write-Host "Script completed successfully." -ForegroundColor Green
        Write-Host ''
        Write-Host ''
        exit
    }

	return $DeviceHealth
}


function Wait-OnDemandStop {
	$LogName = "Application"
	$Log = [System.Diagnostics.EventLog]$LogName
	$Action = {
		$entry = $event.SourceEventArgs.Entry
		if ($entry.EventId -eq 2 -and $entry.Source -eq "MDEClientAnalyzer")
		{
			Write-Host "Stop event was triggered!" -ForegroundColor Green
			Unregister-Event -SourceIdentifier MDEClientAnalyzer
			Remove-Job -Name MDEClientAnalyzer
		}
	}
	$job = Register-ObjectEvent -InputObject $log -EventName EntryWritten -SourceIdentifier "MDEClientAnalyzer" -Action $Action
	$timeout = New-TimeSpan -Minutes $MinutesToRun
	$sw = [diagnostics.stopwatch]::StartNew()
	try {
		do {
			Wait-Event -SourceIdentifier MDEClientAnalyzer -Timeout 1
			[int]$rem = $timeout.TotalSeconds - $sw.elapsed.TotalSeconds
			Write-Host "Remaining seconds: " ([math]::Round($rem))
		} while ((Get-Job -Name MDEClientAnalyzer -ErrorAction SilentlyContinue) -xor ([int]$rem -lt 1))
	} finally {
		 Unregister-Event -SourceIdentifier MDEClientAnalyzer -ErrorAction SilentlyContinue
		 Remove-Job -Name MDEClientAnalyzer -ErrorAction SilentlyContinue
	}
}

function Create-OnDemandStopEvent {
	Write-host "Another non-interactive trace is already running... stopping log collection and exiting."
	Write-EventLog -LogName "Application" -Source "MDEClientAnalyzer" -EventID 2 -EntryType Information -Message "MDEClientAnalyzer is stopping a running log set" -Category 1
	[Environment]::Exit(1)
}

function Create-OnDemandStartEvent {
	Write-EventLog -LogName "Application" -Source "MDEClientAnalyzer" -EventID 1 -EntryType Information -Message "MDEClientAnalyzer is starting OnDemand traces" -Category 1	
}
#endregion Functions ---------

#Main
###CheckAuthenticodeSignature $MyInvocation.MyCommand.Path
[string]$context = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
[string]$LoggedOnUsers = (Get-Process -Name "Explorer" -IncludeUserName -ErrorAction SilentlyContinue).UserName | Sort-Object UserName -Unique
if ($context -eq "nt authority\system") {
	$system = $true 
} elseif ($LoggedOnUsers -contains $context) {
# This means the user context running the script is also interactively logged on
	$InteractiveAdmin = $true
}

<#
if ($AcceptEula) {
  Write-Log "AcceptEula switch specified, silently continuing"
  $eulaAccepted = ShowEULAIfNeeded "Sched-Collect" 2
} else {
  $eulaAccepted = ShowEULAIfNeeded "Sched-Collect" 0
  if($eulaAccepted -ne "Yes") {
    Write-Log "EULA declined, exiting"
    exit
  }
}
Write-Log "EULA accepted, continuing"
#>
$EULA = Join-Path $ToolsDir "EULA.ps1"
CheckAuthenticodeSignature $EULA
Import-module $EULA

if ($system -or $RemoteRun) {
	# Running in non-interactive mode. I.e. assume EULA accepted by admin who is initiating advanced data collection 
	$eulaAccepted = ShowEULAIfNeeded "MDEClientAnalyzer" 2
} else {
	$eulaAccepted = ShowEULAIfNeeded "MDEClientAnalyzer" 0
}

if ($eulaAccepted -ne "Yes") {
    write-error "MDEClientAnalyzer EULA Declined"
    [Environment]::Exit(1)
}
write-host "MDEClientAnalyzer EULA Accepted"

if ($PSMode -eq "ConstrainedLanguage") {
	Write-Warning "PowerShell is set with 'Constrained Language' mode hardening which can affect script execution and capabilities. To avoid issues while troubleshooting with the analyzer, please temporarly remove the ConstrainedLanguage mode in your policy."
	Write-Host "For more information, refer to: https://docs.microsoft.com/powershell/module/microsoft.powershell.core/about/about_language_modes"
	if (!($system -or $RemoteRun)) {
		Read-Host "Press ENTER to continue anyway..."
	}
}

New-EventLog –LogName Application –Source "MDEClientAnalyzer" -ErrorAction SilentlyContinue
[array]$RunningPS = Get-WmiObject Win32_Process | Where-Object {$_.name -eq 'powershell.exe'}
foreach ($PS in $RunningPS) {
	If ($PID -ne ($PS.ProcessId)) {
		$StringRunningPS = ([string]$PS.CommandLine).ToLower()
		if (($StringRunningPS).contains(" -r") -and (($StringRunningPS).contains("mdeclientanalyzer.ps1'"))) { 
			# This means we have a previous trace already kicked off and running, so signal to stop log collection and exit.
			$OnDemand = $true
			Create-OnDemandStopEvent
		}
	} 
}

InitXmlLog
[string]$PSMode = ($ExecutionContext.SessionState.LanguageMode)
[int]$OSBuild = [system.environment]::OSVersion.Version.Build
[int]$MinorBuild = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Value "UBR" )
[string]$OSEditionID = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value EditionID
[string]$OSProductName = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value ProductName
[string]$OSEditionName = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value InstallationType
[string]$IsOnboarded = Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\Status" -Value OnboardingState 
[int]$PsMjVer = $PSVersionTable.PSVersion.Major
# Below is using WMI instead of $env:PROCESSOR_ARCHITECTURE to avoid getting the PS env instead of the actual OS archecture
[string]$arch = (Get-WmiObject -Class Win32_OperatingSystem).OSArchitecture
[string]$MDfWS = GetAddRemovePrograms (Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall) | Where-Object {$_.DisplayName -like "Microsoft Defender for *"}

if ($arch -like "ARM*") {
	$ARM = $true
	$ARMcommand = "-ARM"
}

if (Get-Process WDATPLauncher -EA silentlycontinue) {
	$SignerInfo = ((Get-AuthenticodeSignature (Get-Process WDATPLauncher).Path).SignerCertificate).Subject
	if ($SignerInfo -like "*Microsoft Corporation*") {
		$ASM = $true
	}
}

# Storing HKU reg path for later use
New-PSDrive HKU Registry HKEY_USERS -ErrorAction SilentlyContinue | Out-Null

if (($OSBuild -le 7601) -And ($PsMjVer -le 2)) { 
	Write-Host -ForegroundColor Yellow "We recommend installing at least 'Windows Management Framework 3.0' (KB2506143) or later for optimal script results: `r`nhttps://www.microsoft.com/en-us/download/details.aspx?id=34595"
}

if ((Test-Path -Path $ToolsDir) -eq $False) {
	Write-Host -ForegroundColor Yellow "Missing 'Tools' directory. Exiting script."
	[Environment]::Exit(1)
}

# Delete previous output if exists
if (Test-Path $resultOutputDir) {
	Remove-Item -Recurse -Force $resultOutputDir -ErrorVariable FileInUse;
	while ($FileInUse) {
		Write-Warning "Please close any opened log files from previous MDEClientAnalyzer run and then try again."
		Read-Host "Press ENTER once you've closed all open files."
		Remove-Item -Recurse -Force $resultOutputDir -ErrorVariable FileInUse
	}
}
if (Test-Path $outputZipFile) {
	Remove-Item -Recurse -Force  $outputZipFile
}

#Check if Evens.Json File not exist
if (-not (Test-Path $ResourcesJson)) {
	Write-Error 'The Events.jsonfile does not exist' -ErrorAction Stop
}
CheckHashFile "$ResourcesJson" "AAD1BE484939A22CFAEA8D332024E5D68CB0442A0CBCEF5D2AB9960C1821D2D9" #Changed whenever new event is added to report
CheckHashFile "$RegionsJson" "31CC06F8F0245AC341CB1613636C57A2B32E023C8FC3D5D43CA0260EFB3B8388"
$ResourcesOfEvents = (Get-Content $ResourcesJson -raw) | ConvertFrom-Json

# Create output folders
New-Item -ItemType directory -Path $resultOutputDir | Out-Null
NTFSSecurityAccess $resultOutputDir

New-Item -ItemType Directory -Path "$resultOutputDir\EventLogs" | out-Null
New-Item -ItemType Directory -Path "$resultOutputDir\SystemInfoLogs" | out-Null

#Store paths for MpCmdRun.exe usage
if (((Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Value ImagePath) -and ($OSBuild -ge 14393)) -or ($MDfWS)) {
	$MsMpEngPath = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Value ImagePath
	[System.IO.DirectoryInfo]$CurrentMpCmdPath = $MsMpEngPath -replace "MsMpEng.exe" -replace """"
	$MpCmdRunCommand = Join-Path $CurrentMpCmdPath "MpCmdRun.exe"
	$MpCmdResultPath = "$env:ProgramData\Microsoft\Windows Defender\Support"
}
elseif (Test-Path -path "$env:ProgramFiles\Microsoft Security Client\MpCmdRun.exe") {
	$CurrentMpCmdPath = "$env:ProgramFiles\Microsoft Security Client\"
	$MpCmdRunCommand = "$env:ProgramFiles\Microsoft Security Client\MpCmdRun.exe"
	$MpCmdResultPath = "$env:ProgramData\Microsoft\Microsoft Antimalware\Support"
}

Write-Report -section "general" -subsection "PSlanguageMode" -displayname "PowerShell Language mode: " -value $PSMode
Write-Report -section "general" -subsection "scriptVersion" -displayname "Script Version: " -value $ScriptVer
$ScriptRunTime = "{0:dd/MM/yyyy h:mm:ss tt zzz}" -f (get-date)
Write-Report -section "general" -subsection "scriptRunTime" -displayname "Script RunTime: " -value $ScriptRunTime 

Write-output "######################## device Info summary #############################" | Out-File $connectivityCheckFile -append
#if ((($OSBuild -ge 7601 -and $OSBuild -le 14393) -and ($OSProductName -notmatch 'Windows 10')) -and (($OSEditionID -match 'Enterprise') -or ($OSEditionID -match 'Pro') -or ($OSEditionID -match 'Ultimate') -or ($OSEditionID -match 'Server'))) {

if (!(Get-Service -Name Sense -ErrorAction SilentlyContinue)) {
	$OSPreviousVersion = $true
	$global:SenseVer=""
	Collect-RegValues
	CheckConnectivity -OSPreviousVersion $OSPreviousVersion -connectivityCheckFile $connectivityCheckFile -connectivityCheckUserFile $connectivityCheckUserFile
      
	if ($Global:tdhdll.Valid -and $Global:wintrustdll.Valid -and !($global:SSLProtocol)) {
		"OS Environment is  supported: " + [System.Environment]::OSVersion.VersionString | Out-File $connectivityCheckFile -append
	}
	else {
		"OS Environment is not  supported: " + [System.Environment]::OSVersion.VersionString + " More information below" | Out-File $connectivityCheckFile -append
	}

	if ($Global:connectivityresult -match "failed" ) {
		"Command and Control channel as System Account : Some of the MDE APIs failed , see details below" | Out-File $connectivityCheckFile -append
	}
	elseif (!$Global:connectivityresult) {
		"Command and Control channel as System Account: Not tested" | Out-File $connectivityCheckFile -append 
	}
	else {
		"Command and Control channel as System Account: Passed validation" | Out-File $connectivityCheckFile -append 
	}

	if ($Global:connectivityresultUser -match "failed" ) {
		"Command and Control channel as User Account : Some of the MDE APIs failed , see details below" | Out-File $connectivityCheckFile -append
	}
	elseif (!$Global:connectivityresultUser) {
		"Command and Control channel as User Account: Not tested" | Out-File $connectivityCheckFile -append 
	}
	else {
		"Command and Control channel as User Account: Passed validation" | Out-File $connectivityCheckFile -append 
	}

	if (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\services\HealthService\Parameters") {
		Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\services\HealthService\Parameters -recurse | Format-table -AutoSize | Out-File "$resultOutputDir\SystemInfoLogs\HealthServiceReg.txt"
		# Test if multiple MMA workspaces are configured
		$AgentCfg = New-Object -ComObject AgentConfigManager.MgmtSvcCfg
		$workspaces = $AgentCfg.GetCloudWorkspaces()
		if ($workspaces.Item(1)) {
			Write-output "`r`n############################ Multiple workspaces check ###############################" | Out-File $connectivityCheckFile -Append
			WriteReport 121001 @() @()
		}
	}
} 

if ((!$OSPreviousVersion) -or ($MDfWS)) {
	if ($IsOnboarded) {
		Collect-RegValues

		$SenseServiceStatus = (Get-Service -Name Sense).Status 
		$UTCServiceStatus = (Get-Service -Name DiagTrack).Status
		$DefenderServiceStatus = (Get-Service -Name WinDefend).Status

		Write-Report -section "EDRCompInfo" -subsection "SenseServiceStatus" -displayname "Sense service Status" -value $SenseServiceStatus
		Write-Report -section "EDRCompInfo" -subsection "UTCServiceStatus" -displayname "DiagTrack (UTC) Service Status" -value $UTCServiceStatus
		Write-Report -section "AVCompInfo" -subsection "DefenderServiceStatus" -displayname "Defender AV Service Status" -value $DefenderServiceStatus
		if (Get-Service -name wscsvc -ErrorAction SilentlyContinue) {
			$WindowsSecurityCenter = (Get-Service -Name wscsvc).Status
			Write-Report -section "AVCompInfo" -subsection "WindowsSecurityCenter" -displayname "Windows Security Center Service Status" -value $WindowsSecurityCenter
		}
		if (Get-Service -name SecurityHealthService -ErrorAction SilentlyContinue) {
			$SecurityHealthService = (Get-Service -Name SecurityHealthService).Status
			Write-Report -section "AVCompInfo" -subsection "SecurityHealthService" -displayname "Windows Security Health Service Status" -value $SecurityHealthService
		}

		if (($OSEditionName -notlike "*core") -and (!$MDfWS)) {
			#"Microsoft Account Sign-in Assistant service start type is: " + (Get-Service -Name wlidsvc).StartType | Out-File $connectivityCheckFile -append
			$WLIDServiceStartType = (Get-Service -Name wlidsvc -ErrorAction SilentlyContinue).StartType
			Write-Report -section "EDRCompInfo" -subsection "WLIDServiceStartType" -displayname "Microsoft Account Sign-in Assistant Start Type" -value $WLIDServiceStartType
		}
		If ($DefenderServiceStatus -eq "Running") {
			if (($OSEditionID -match 'Server') -and (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Value "ForcePassiveMode")) {
				$AVPassiveMode = $true
				Write-Report -section "AVCompInfo" -subsection "DefenderState" -displayname "Defender AV mode" -value "Passive (Forced)"
			}
			elseif (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Value "PassiveMode") {
				$AVPassiveMode = $true
				Write-Report -section "AVCompInfo" -subsection "DefenderState" -displayname "Defender AV mode" -value "Passive"
			}
			else {
				Write-Report -section "AVCompInfo" -subsection "DefenderState" -displayname "Defender AV mode" -value "Active" -alert "None"
			}		
		}

		if (!$ASM) {
			if ($OSBuild -eq 14393) {
				$LastCYBERConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SevilleSettings" -Value LastNormalUploadTime)
				$LastCYBERRTConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\SevilleSettings" -Value LastRealTimeUploadTime)
				$LastInvalidHTTPcode = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\HeartBeats\Seville" -Value LastInvalidHttpCode)
				Dump-ConnectionStatus 
			}
			elseif ($OSBuild -le 17134) {
				$LastCYBERConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\Tenants\P-WDATP" -Value LastNormalUploadTime)
				$LastCYBERRTConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\Tenants\P-WDATP" -Value LastRealTimeUploadTime)
				$LastInvalidHTTPcode = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\HeartBeats\Seville" -Value LastInvalidHttpCode)
				Dump-ConnectionStatus
			}
			elseif ($OSBuild -ge 17763) {
				$LastCYBERConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\TelLib" -Value LastSuccessfulNormalUploadTime)
				$LastCYBERRTConnected = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\TelLib" -Value LastSuccessfulRealtimeUploadTime)
				$LastInvalidHTTPcode = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\TelLib\HeartBeats\Seville" -Value LastInvalidHttpCode)
				Dump-ConnectionStatus
			}
		}


		# Test for events indicating expired OrgID in Sense event logs
		Write-output "`r`n############################ OrgID error check ###############################" | Out-File $connectivityCheckFile -Append
		$OrgId = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" -Value "OrgID" )
		$EventError = (Get-MatchingEvent Microsoft-Windows-SENSE 67 "400")
		if (!$EventError) {
			$EventError = (Get-MatchingEvent Microsoft-Windows-SENSE 5 "400")
		}
		$EventOk = (Get-MatchingEvent Microsoft-Windows-SENSE 50 "*10.*")
		if (!$EventError) {
			"Based on SENSE log, no OrgId mismatch errors were found in events" | Out-File $connectivityCheckFile -Append
		} 		
		if (($EventOk) -and ($EventError)) {
			if ((Get-Date $EventOk.TimeCreated) -gt (Get-Date $EventError.TimeCreated)) {
				"Based on SENSE log, the device is linked to an active Organization ID: $orgID`r`n" | Out-File $connectivityCheckFile -Append
			} 
		}
		elseif ($EventError) {
			Write-output "Event Log error information:" | Out-File $connectivityCheckFile -Append
			$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
			WriteReport 122005 @(, @($OrgId)) @()
		}
	} 

	# Dump Registry OnboardingInfo if exists
	$RegOnboardingInfo = Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\" -Value OnboardingInfo 
	$RegOnboardedInfo = Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\" -Value OnboardedInfo 
	if (($RegOnboardingInfo -eq $False) -or ($null -eq $RegOnboardingInfo)) {
		Get-deviceInfo
		"`r`Note: OnboardingInfo could not be found in the registry. This can be expected if device was offboarded or onboarding was not yet executed." | Out-File $connectivityCheckFile -Append
	} else {
		($RegOnboardingInfo | ConvertFrom-Json).body | Out-File "$resultOutputDir\SystemInfoLogs\RegOnboardingInfoPolicy.Json"
		($RegOnboardedInfo | ConvertFrom-Json).body | Out-File "$resultOutputDir\SystemInfoLogs\RegOnboardedInfoCurrent.Json"
	}
	CheckConnectivity -OSPreviousVersion $OSPreviousVersion -connectivityCheckFile $connectivityCheckFile -connectivityCheckUserFile $connectivityCheckUserFile
}

# Check if MDE for down-level server is installed
if (($OSEditionID -match 'Server') -and ($OSBuild -ge 7601 -and $OSBuild -le 14393)) {
	if ($MDfWS) {
		Write-Report -section "EDRCompInfo" -subsection "MDfWSState" -displayname "Unified agent for downlevel servers installed" -value "YES" 
		[version]$minVer = "10.8048.22439.1065"
		if ([version]$Global:SenseVer -lt [version]$minVer) {
			WriteReport 122038 @() @()
		}
	} else {
		Write-Report -section "EDRCompInfo" -subsection "MDfWSState" -displayname "Unified agent for downlevel servers installed" -value "NO"
		WriteReport 121020 @() @()
	}
}

If ($CurrentMpCmdPath) {
	    $AVSignatureVersion = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates" -Value "AVSignatureVersion" ) 
		$AVEngineVersion = (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates" -Value "EngineVersion" ) 
			
		#Check AV component versions to ensure they are up-to-date and report to Result
		$FilePathEPPversions = Join-Path $ToolsDir "EPPversions.xml"
		CheckHashFile $FilePathEPPversions "BC472B5839F1543967B0E38F7342F3F81E2C9C4C5F48B826252C00F043A535AB"
		$CheckAV = Join-Path $ToolsDir "MDE.psm1"
		CheckAuthenticodeSignature $CheckAV
		Import-Module $CheckAV
		$CheckAVHelper = Join-Path $ToolsDir "MDEHelper.psd1"
		CheckAuthenticodeSignature $CheckAVHelper
		Import-Module $CheckAVHelper			
		$WebRequestAV = [net.WebRequest]::Create("https://www.microsoft.com/security/encyclopedia/adlpackages.aspx?action=info")
		try {
			$WebRequestAV.GetResponse().StatusCode
		}
		catch [System.Net.WebException] {
			$ErrorMessage = $Error[0].Exception.ErrorRecord.Exception.Message;
		}
		$WebRequestAV.Close
		if ($CurrentMpCmdPath.Name -like "*-*") {
				[string]$Platform = $CurrentMpCmdPath.Name.split('-')[0]
		}
		$MoCAMPAlert = "None"; $EngineAlert = "None"; $SigsAlert = "None"; 
		if ($null -eq $ErrorMessage) {
			if (checkeppversion -component MoCAMP -version $Platform) {
				$MoCAMPAlert = "High"
				WriteReport 122010 @() @()
			} 
			if (checkeppversion -component Engine -version $AVEngineVersion) {
				$EngineAlert = "High"
				WriteReport 122011 @() @()
			} 
			if (checkeppversion -component Sigs -version $AVSignatureVersion) {
				$SigsAlert = "Medium"
				WriteReport 121012 @() @()
			} 
		} else {
			[XML]$EPPversions = Get-Content $FilePathEPPversions
			#Option to check the AV state using the included EPPversions.xml ($FilePathEPPversions)
			if (checkeppversion -component MoCAMP -version $Platform -xml $EPPversions) {
				$MoCAMPAlert = "High"
				WriteReport 122010 @() @()
			} 
			if (checkeppversion -component Engine -version $AVEngineVersion -xml $EPPversions) {
				$EngineAlert = "High"
				WriteReport 122011 @() @()
			} 
			if (checkeppversion -component Sigs -version $AVSignatureVersion -xml $EPPversions) {
				$SigsAlert = "Medium"
				WriteReport 121012 @() @()
			} 
		}	
		Write-Report -section "AVCompInfo" -subsection "AVPlatformVersion" -displayname "Defender AV Platform Version" -value $CurrentMpCmdPath.Name -alert $MoCAMPAlert
		Write-Report -section "AVCompInfo" -subsection "AVSignatureVersion" -displayname "Defender AV Security Intelligence Version" -value $AVSignatureVersion -alert $SigsAlert
		Write-Report -section "AVCompInfo" -subsection "AVEngineVersion" -displayname "Defender AV engine Version" -value $AVEngineVersion -alert $EngineAlert 
}

if ((($OSBuild -ge 7601 -and $OSBuild -le 14393) -and ($OSProductName -notmatch 'Windows 10')) -and (($OSEditionID -match 'Enterprise') -or ($OSEditionID -match 'Pro') -or ($OSEditionID -match 'Ultimate') -or ($OSEditionID -match 'Server'))) {
	"`r`n###################### OMS validation details  ###########################" | Out-File $connectivityCheckFile -append
	if ($Global:TestOMSResult -match "Connection failed" -or $Global:TestOMSResult -match "Blocked Host") {
		"OMS channel: Some of the OMS APIs failed , see details below" | Out-File $connectivityCheckFile -append
	}
 elseif (!$Global:TestOMSResult) {
		"OMS channel: Not tested" | Out-File $connectivityCheckFile -append 
	}
 elseif (!$MDfWS) {
		"OMS channel: Passed validation" | Out-File $connectivityCheckFile -append 
		"Service Microsoft Monitoring Agent is " + (Get-Service -Name HealthService -ErrorAction SilentlyContinue).Status | Out-File $connectivityCheckFile -append
		"Health Service DLL version is: " + $Global:healthservicedll.version | Out-File $connectivityCheckFile -append
		If (!$Global:healthservicedll.Valid) {
			"`n" | Out-File $connectivityCheckFile -append
			WriteReport 122002 @(, @($Global:healthservicedll.Message)) @()
		}
	} 
	"`r`n###################### OS validation details  ###########################" | Out-File $connectivityCheckFile -append
	$Global:tdhdll.Message  | Out-File $connectivityCheckFile -append
	$Global:wintrustdll.Message  | Out-File $connectivityCheckFile -append
	$global:SSLProtocol | Out-File $connectivityCheckFile -append
	Write-output "##########################################################################`n" | Out-File $connectivityCheckFile -append  
	"######## Connectivity details for Command and Control  validation  #######" | Out-File $connectivityCheckFile -append
	$connectivityresult | Out-File $connectivityCheckFile -append
	Write-output "##########################################################################`n" | Out-File $connectivityCheckFile -append  
	"################# Connectivity details for OMS  validation  #########" | Out-File $connectivityCheckFile -append
	$Global:TestOMSResult | Out-File $connectivityCheckFile -append
	Write-output "##########################################################################`n" | Out-File $connectivityCheckFile -append  
}

# Checks for MDE Device Configuration
if ((($osbuild -gt 9600) -or (($osbuild -eq 9600) -and ($OSEditionID -match 'Server'))) -and ($IsOnboarded)) {
	$SenseCMConfig = Get-SenseCMInfo

	Write-output "`r`n################# Device Registration and Enrollment ##################" | Out-File $connectivityCheckFile -Append
	# Check SenseCM enrollment Status
	if ($SenseCMConfig.EnrollmentStatusId) {
		$EnrollmentStatusAlert = ""
		If ($SenseCMConfig.EnrollmentStatusReportId) {
			$EnrollmentStatusAlert = "High"
			WriteReport $SenseCMConfig.EnrollmentStatusReportId @() @()
		} 
		If ($SenseCMConfig.EnrollmentStatusId -eq "1") { $EnrollmentStatusAlert = "None" }
		Write-Report -section "MDEDevConfig" -subsection "SenseCMEnrollmentStatus" -displayname "Enrollment Status" -value $SenseCMConfig.EnrollmentStatusText -alert $EnrollmentStatusAlert
		if ($SenseCMConfig.AADDeviceId) {
			Write-Report -section "MDEDevConfig" -subsection "IntuneDeviceID" -displayname "Intune Device ID" -value $SenseCMConfig.IntuneDeviceID
			Write-Report -section "MDEDevConfig" -subsection "AADDeviceID" -displayname "Azure AD Device ID" -value $SenseCMConfig.AADDeviceId 
			Write-Report -section "MDEDevConfig" -subsection "AADTenantId" -displayname "Azure AD Tenant ID" -value $SenseCMConfig.TenantId 
		}
	}

	if ($env:userdnsdomain) {
		Write-Report -section "MDEDevConfig" -subsection "DomainJoined" -displayname "Domain Joined" -value "YES"
		$DomainJoined = $True
	} else {
		Write-Report -section "MDEDevConfig" -subsection "DomainJoined" -displayname "Domain Joined" -value "NO"
		$DomainJoined = $False
	}
	# Collect information about up-level OS
	if ($osbuild -gt "9600") {
		# Check if the October hotfix is installed for supported Windows 10 versions and Windows Server 2019
		if ((($osbuild -eq "19041") -and ([int]$MinorBuild -lt 1320)) -or (($osbuild -eq "19042") -and ([int]$MinorBuild -lt 1320)) -or (($osbuild -eq "19043") -and ([int]$MinorBuild -lt 1320)) -or (($osbuild -eq "17763") -and ([int]$MinorBuild -lt 2268))) {
			WriteReport 111021 @(, @("$OSBuild.$MinorBuild")) @()
		} 

		# Collect Information from DSREGCMD 
		$DSRegState = Get-DsRegStatus		
		# Write-Report -section "MDEDevConfig" -subsection "DomainJoined" -displayname "Domain Joined" -value $DomainJoined
		Write-Report -section "MDEDevConfig" -subsection "AzureADJoined" -displayname "Azure AD Joined" -value $DSRegState.DeviceState.AzureAdJoined
		Write-Report -section "MDEDevConfig" -subsection "WorkplaceJoined" -displayname "Workplace Joined" -value $DSRegState.UserState.WorkplaceJoined
		if ((!$SenseCMConfig.AADDeviceId) -and ($DSRegState.DeviceDetails.DeviceID)) {
			Write-Report -section "MDEDevConfig" -subsection "AADDeviceID" -displayname "Azure AD Device ID" -value $DSRegState.DeviceDetails.DeviceID 
			
			$MDMEnrollmentState = Get-MDMEnrollmentStatus
			Write-Report -section "MDEDevConfig" -subsection "MDMEnrollmentState" -displayname "MDM Enrollment state" -value $MDMEnrollmentState.EnrollmentTypeText
		}
	}

	if ($DomainJoined) {
		$SCPConfiguration = Get-SCPConfiguration
		if ($SCPConfiguration.ResultID -eq "") {
			Write-Report -section "MDEDevConfig" -subsection "SCPClientSide" -displayname "SCP Configuration Type" -value $SCPConfiguration.ConfigType
			Write-Report -section "MDEDevConfig" -subsection "SCPTenantName" -displayname "SCP Tenant Name" -value $SCPConfiguration.TenantName
			Write-Report -section "MDEDevConfig" -subsection "SCPTenantID" -displayname "SCP Tenant ID" -value $SCPConfiguration.TenantId
				
			if ((!$SenseCMConfig.TenantId) -xor (!$SCPConfiguration.TenantId)) {
					WriteReport 120021 @() @()
			} elseif ((((!$SenseCMConfig.TenantId) -and (!$SCPConfiguration.TenantId)) -and ($SenseCMConfig.TenantId -notmatch $SCPConfiguration.TenantId)) -or ($SenseCMConfig.EnrollmentStatusId -eq 15)) {
				WriteReport 121022 @() @()
			}
		} elseif (($SCPConfiguration.ResultID -eq 121017) -or ($SenseCMConfig.EnrollmentStatusId -eq 15)) {
				WriteReport $SCPConfiguration.ResultID @(, @($SCPConfiguration.TenantName)) @()
			} else {
				WriteReport $SCPConfiguration.ResultID  @() @()
			}
	}
}

if ((!$OSPreviousVersion) -or ($MDfWS)) {
	Write-output "`r`n################# Defender AntiVirus cloud service check ##################" | Out-File $connectivityCheckFile -Append
	if ($MpCmdRunCommand) {
		CheckAuthenticodeSignature $MpCmdRunCommand
		$MAPSCheck = &$MpCmdRunCommand -ValidateMapsConnection
		$MAPSErr = $MAPSCheck | Select-String -pattern "ValidateMapsConnection failed"
		if ($MAPSErr) { 
			WriteReport 131007 @(, @($MAPSErr)) @()
		}
		else {
			$MAPSOK = $MAPSCheck | Select-String -pattern "ValidateMapsConnection successfully"
			if ($MAPSOK) {
				WriteReport 130011 @() @()
			}
		}
	}
}

# Dump DLP related policy information from registry
if (($DlpT) -or ($AppCompatC) -or ($DlpQ) -or ($wprpTraceH)) {
	if ((!$OSPreviousVersion) -and ($OSBuild -ge 17763)) {
		New-Item -ItemType Directory -Path "$resultOutputDir\DLP" | out-Null
		<# 
		# The below captures the local AD user UPN. We should also fetch UPN in case of Azure AD
		if ($InteractiveAdmin) {
			[string]$UserUPN = ([ADSI]"LDAP://<SID=$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)>").UserPrincipalName
			$UserUPN | Out-File "$resultOutputDir\DLP\dlpPolicy.txt" -Append
		}
		#>
		if (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value dlpPolicy) {
			ShowDlpPolicy dlpPolicy
			ShowDlpPolicy dlpSensitiveInfoTypesPolicy
			$DLPlogs = Get-Item "$env:SystemDrive\DLPDiagnoseLogs\*.log" -ErrorAction SilentlyContinue
			if ($DLPlogs) {
				Move-Item -Path $DLPlogs -Destination "$resultOutputDir\DLP\"
			}
		}
		else {
			Write-output "No DLP polices found in the registry of this device" | Out-File "$resultOutputDir\DLP\NoDlp.txt"
		}
	}
}

# Dump installed hotfix list via WMI call
$Computer = "LocalHost"
$Namespace = "root\CIMV2"
$InstalledUpdates = Get-WmiObject -class Win32_QuickFixEngineering -computername $Computer -namespace $Namespace
$InstalledUpdates | Out-File "$resultOutputDir\SystemInfoLogs\InstalledUpdates.txt"

<#Collect advanced traces if flagged
1. Start timer
2. Call the relevant function to start traces for various scenarios
3. When timer expires or manually stopped call the functions to stop traces for various scenarios
4. Gather logs common to all scenarios and finish
#>

if ($DlpQ -or $DlpT) {
	$DLPHealthCheck = Join-Path $ToolsDir "DLPDiagnose.ps1"
	CheckAuthenticodeSignature $DLPHealthCheck
	Check-Command-verified "powershell.exe"
	&Powershell.exe "$DLPHealthCheck"
}

if ($wprpTraceL -or $wprpTraceH -or $AppCompatC -or $NetTraceI -or $WDPerfTraceA -or $WDVerboseTraceV -or $DlpT) {
	$AdvancedFlag = $True
	Start-PSRRecording
	$WPtState = Check-WptState
	$MinutesToRun = Get-MinutesValue
	Start-Wpr
	Start-PerformanceTraces
	Start-AppCompatTraces
	Start-MDAVTraces
	start-NetTraces
	StartTimer
	Stop-Wpr
	Stop-PerformanceTraces
	Stop-AppCompatTraces
	Stop-MDAVTraces
	Stop-NetTraces
	Get-DLPEA
	Get-Logs
	Stop-PSRRecording
}

elseif ($BootTraceB) {
	$AdvancedFlag = $True
	Set-BootTraces
}

if ($CrashDumpD) {
	Get-CrashDumps
}

if ($FullCrashDumpZ) {
	Set-CrashOnCtrlScroll
	Set-FullCrashDump
	Write-Host -BackgroundColor Red -ForegroundColor Yellow "Please reboot the device for the change in settings to apply" 
	Write-Host -ForegroundColor Green "To force the system to crash for memory dump collection, hold down the RIGHT CTRL key while pressing the SCROLL LOCK key twice"
	Write-Host "Note: This is not expected to work during Remote Desktop Protocol (RDP). For RDP please use the script with -k parameter instead"
}

if ($notmyfault) {
	Set-FullCrashDump
	if (!$RemoteRun) {
		[string]$notmyfault = (Read-Host "Type 'crashnow' and press ENTER to crash the device and create a full device dump now")
	}
	if (($notmyfault -eq "crashnow") -or ($RemoteRun)) {
		CheckAuthenticodeSignature $NotMyFaultCommand
		& $NotMyFaultCommand /accepteula /Crash 1
	}
}

if (Test-Path -Path  $env:SystemRoot\System32\'Winevt\Logs\Operations Manager.evtx') {
	Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\Operations Manager.evtx' -Destination $resultOutputDir\EventLogs\OperationsManager.evtx
}

if (Test-Path -Path  $env:SystemRoot\System32\'Winevt\Logs\OMS Gateway Log.evtx') {
	Copy-Item -path $env:SystemRoot\System32\'Winevt\Logs\OMS Gateway Log.evtx' -Destination $resultOutputDir\EventLogs\OMSGatewayLog.evtx
}

if (test-path -Path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-UniversalTelemetryClient%4Operational.evtx') {
	Copy-Item -path $env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-UniversalTelemetryClient%4Operational.evtx -Destination $resultOutputDir\EventLogs\utc.evtx
}

if (Test-Path -Path $env:SystemRoot\System32\'Winevt\Logs\Microsoft-Windows-SENSE%4Operational.evtx') {
	Copy-Item -path $env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-SENSE%4Operational.evtx -Destination $resultOutputDir\EventLogs\sense.evtx
	Copy-Item -path $env:SystemRoot\System32\Winevt\Logs\Microsoft-Windows-SenseIR%4Operational.evtx -Destination $resultOutputDir\EventLogs\senseIR.evtx -ErrorAction SilentlyContinue
}


# Test for ASR rule blocking PsExec
if ((!$OSPreviousVersion) -and (!$AVPassiveMode)) {
	TestASRRules    
}

# Check if automatic update of Trusted Root Certificates is blocked
$AuthRootLocal = get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot" -ErrorAction SilentlyContinue
$AuthRootGPO = get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot" -ErrorAction SilentlyContinue
if (($AuthRootLocal.DisableRootAutoUpdate -eq "1") -or ($AuthRootGPO.DisableRootAutoUpdate -eq "1")) {
	Write-output "`r`n######################## Auth Root Policies #########################" | Out-File $connectivityCheckFile -Append
	WriteReport 130009 @(@($AuthRootLocal), @($AuthRootGPO)) @()
	if ($OSPreviousVersion) {
		$EventError = Get-MatchingEvent HealthService 2132 "12175L"
	}
 else {
		$EventError = Get-MatchingEvent Microsoft-Windows-SENSE 5 "12175"
	}
	if ($EventError) {
		WriteReport 132012 @() @()
		$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
	} 
}
else {
	"############## Connectivity Check for ctldl.windowsupdate.com #############" | Out-File $connectivityCheckFile -append
	$urlctldl = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/pinrulesstl.cab"
	$webRequest = [net.WebRequest]::Create("$urlctldl")
	try {
		"StatusCode for " + $urlctldl + " IS : " + $webRequest.GetResponse().StatusCode | Out-File $connectivityCheckFile -append
	}
	catch [System.Net.WebException] {
		$ErrorMessage = $Error[0].Exception.ErrorRecord.Exception.Message;
		"Exception occurred for " + $urlctldl + " :" + $ErrorMessage | Out-File $connectivityCheckFile -append
		$Error[0].Exception.InnerException.Response | Out-File $connectivityCheckFile -append
		WriteReport 131003 @() @()
	}
	$webRequest.Close
}

"############## CertSigner Results #############" | Out-File $CertSignerResults
$RootAutoUpdateDisabled = (($AuthRootLocal.DisableRootAutoUpdate -eq "1") -or ($AuthRootGPO.DisableRootAutoUpdate -eq "1"))
CheckExpirationCertUtil $RootAutoUpdateDisabled "authroot" "$ToolsDir\MsPublicRootCA.cer"
CheckExpirationCertUtil $RootAutoUpdateDisabled "disallowed"


# Check if only domain based trusted publishers are allowed
$AuthenticodeFlagsLocal = get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SystemCertificates\TrustedPublisher\Safer" -ErrorAction SilentlyContinue
$AuthenticodeFlagsGPO = get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\Safer" -ErrorAction SilentlyContinue
if (($AuthenticodeFlagsLocal.AuthenticodeFlags -eq "2") -or ($AuthenticodeFlagsGPO.AuthenticodeFlags -eq "2")) {
	Write-output "`r`n######################## Trusted Publishers Policy #########################" | Out-File $connectivityCheckFile -Append
	WriteReport 121009 @() @(@($AuthenticodeFlagsLocal), @($AuthenticodeFlagsGPO))
}

# Validate certificate revocation
# public .cer file was fetched from the https://winatp-gw-cus.microsoft.com/test this needs to be updated if certificate changes
if (!$OSPreviousVersion) {
	"`r`n##################### certificate validation check ########################" | Out-File $connectivityCheckFile -Append	
	#$certutilcommand = Join-Path $ToolsDir "PsExec.exe"
	$certutilcommand = Join-Path $ToolsExeDir "PsExec.exe"
	if (test-Path -path $certutilcommand) {
		CheckAuthenticodeSignature $certutilcommand
	}
	if (!$system) {
		Check-Command-verified "certutil.exe"
		&$certutilcommand -accepteula -s -nobanner certutil.exe -verify -urlfetch "$ToolsDir\winatp.cer" 2>> $connectivityCheckFile | Out-File $CertResults
	}
 elseif ($system) {
		Check-Command-verified "certutil.exe"
		&certutil.exe -verify -urlfetch "$ToolsDir\winatp.cer" | Out-File $CertResults
	}
	$Certlog = (Get-Content $CertResults)

	if (!$Certlog) {
		WriteReport 131004 @() @()
	}
 else {
		if (($Certlog -like "*Element.dwErrorStatus*") -or ($Certlog -like "*0x8007*")) {
			if ((($osbuild -eq "17763") -and ([int]$MinorBuild -lt 1911)) -or (($osbuild -eq "18363") -and ([int]$MinorBuild -lt 1411)) -or (($osbuild -eq "19041") -and ([int]$MinorBuild -lt 844)) -or (($osbuild -eq "19042") -and ([int]$MinorBuild -lt 964))) {
				WriteReport 131005 @() @(, @($CertResults))
			} 
		}
		else {
			WriteReport 130010 @() @()
		}
	}
}

Write-Host "Evaluating sensor condition..."
"########################### PROXY SETTINGS ################################" | Out-File $connectivityCheckFile -append
CheckProxySettings

(netsh winhttp show proxy) | Out-File $connectivityCheckFile -append

# Check if device was onboarded using VDI script and dump relevant information
If (Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging" -Value "VDI") {
	$IsVDI = $true
	Write-output "`r`n######################## VDI Information #########################" | Out-File $connectivityCheckFile -Append
	$StartupFolder = (get-ChildItem -Recurse -path $env:SystemRoot\system32\GroupPolicy\Machine\Scripts\Startup) 
	WriteReport 110003 @() @(, @($StartupFolder))
}

if ((Get-Process -Name MsSense -ErrorAction SilentlyContinue) -And ($OSProductName -notlike "*LTSB")) {
	if (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value "7DC0B629-D7F6-4DB3-9BF7-64D5AAF50F1A") {
		Write-Report -section "EDRCompInfo" -subsection "AFState" -displayname "Anti-Spoofing capability deployed" -value "YES"
		[string]$SenseId = (Get-RegistryValue -Path "HKLM:\SOFTWARE\\Microsoft\Windows Advanced Threat Protection" -Value "SenseId")
		if ((Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value "C9D38BBB-E9DD-4B27-8E6F-7DE97E68DAB9") -eq ([string]$SenseId)) {
			WriteReport 120037 @() @()
		# VDI has special Anti-Spoofing handling in cloud so only throw this warning if not running a VDI machine
		} elseif (!$IsVDI) {
			WriteReport 121036 @() @()
		}
	} else {
		Write-Report -section "EDRCompInfo" -subsection "AFState" -displayname "Anti-Spoofing capability Deployed" -value "NO"
		WriteReport 121035 @() @()
	}
}

If (!$OSPreviousVersion) {
	# Test for DiagTrack listener on RS4 and earlier Win10 builds or SenseOms for Down-level OS, and export network proxy Registry settings
	Write-output "`r`n#################### Data Collection Registry setting #####################" | Out-File $connectivityCheckFile -Append

	$DiagTrackSvcStartType = (get-service -name diagtrack).StartType 
	If ($DiagTrackSvcStartType -eq "Disabled") {
		WriteReport 141001 @() @()
	}
	Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -ErrorAction SilentlyContinue | Out-File $connectivityCheckFile -Append
}
if ((!$OSPreviousVersion) -and ($buildNumber -le "17134") -and ($OSEditionName -eq "Client")) {
	Write-output "`r`n######################## DiagTrack Listener check #########################" | Out-File $connectivityCheckFile -Append
	Check-Command-verified "logman.exe"
	$DiagTrackListener = &logman Diagtrack-Seville-Listener -ets
	$DiagTrackListener > "$resultOutputDir\SystemInfoLogs\DiagTrackListener.txt"
	$SevilleProv = $DiagTrackListener | Select-String "CB2FF72D-D4E4-585D-33F9-F3A395C40BE7"
	if ($null -eq $SevilleProv) {
		WriteReport 141002 @() @()
	}
	else {
		WriteReport 140004 @() @()
	}	
}
elseif (($OSPreviousVersion) -and (!$ASM)) {
	Write-output "`r`n######################## SenseOms Listener check #########################" | Out-File $connectivityCheckFile -Append
	Check-Command-verified "logman.exe"
	$SenseOmsListener = &logman SenseOms -ets
	$SenseOmsListener > "$resultOutputDir\SystemInfoLogs\SenseOmsListener.txt"
	$OmsProv = $SenseOmsListener | Select-String "CB2FF72D-D4E4-585D-33F9-F3A395C40BE7"
	if ($null -eq $OmsProv) {
		WriteReport 141003 @() @()
	}
	else {
		WriteReport 140006 @() @()
	}	
}

if (!$OSPreviousVersion) {
	"################ Connectivity Check for Live Response URL ################" | Out-File $connectivityCheckFile -append
	$TestLR1 = TelnetTest "global.notify.windows.com" 443
	$TestLR2 = TelnetTest "client.wns.windows.com" 443
	$TestLR1 | Out-File $connectivityCheckFile -append
	$TestLR2 | Out-File $connectivityCheckFile -append
	# the abvoe test does not support proxy configuration as-is
	#if (($TestLR1 -notlike "Successfully connected*") -Or ($TestLR2 -notlike "Successfully connected*")) {
	#	Write-ReportEvent -section "events" -severity "Warning" -check "LRcheckFail" -id XXXXX -checkresult ( `
	#	"Failed to reach Windows Notification Service URLs required for Live Response.`r`n" `
	#	+ "Please ensure Live Response URLs are not blocked.`r`n" `
	#	+ "For more information, see: https://docs.microsoft.com/en-us/windows/uwp/design/shell/tiles-and-notifications/firewall-allowlist-config")
	#} elseif (($TestLR1 -like "Successfully connected*") -and ($TestLR2 -like "Successfully connected*")) {
	#	Write-ReportEvent -section "events" -severity "Informational" -check "LRcheckOK" -id XXXXX -checkresult ( `
	#	"Windows Notification Service URLs required for Live Response are reachable.`r`n")
	#}
}

# Test for existence of unsupported ProcessMitigationOptions and dump IFEO
# Reference https://docs.microsoft.com/en-us/windows/security/threat-protection/override-mitigation-options-for-app-related-security-policies
Get-childItem -Recurse "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue | Out-File "$resultOutputDir\SystemInfoLogs\IFEO.txt"
Get-Item "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\kernel" | Out-File "$resultOutputDir\SystemInfoLogs\SessionManager.txt"
if ((!$OSPreviousVersion) -and ($buildNumber -le "17134") -and ((Get-Service DiagTrack).Status -eq "StartPending")) {
	If (Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Value "MitigationOptions") {
		Write-output "`r`n######################## ProcessMitigations check #########################" | Out-File $connectivityCheckFile -Append
		WriteReport 142007 @() @()
		Check-Command-verified "reg.exe"
		&Reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "$resultOutputDir\SystemInfoLogs\KernelProcessMitigation.reg" /y 2>&1 | Out-Null
		Check-Command-verified "reg.exe"
		&Reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe" "$resultOutputDir\SystemInfoLogs\SvchostProcessMitigation.reg" /y 2>&1 | Out-Null
	}	
}

# Test for existence of faulty EccCurves SSL settings and gather additional useful reg keys for troubleshooting
# Refernce https://docs.microsoft.com/en-us/windows-server/security/tls/manage-tls
$SSLSettings = "$resultOutputDir\SystemInfoLogs\SSL_00010002.txt"
$SCHANNEL = "$resultOutputDir\SystemInfoLogs\SCHANNEL.txt"
Get-ChildItem "HKLM:SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL" -Recurse -ErrorAction silentlycontinue | Out-File $SSLSettings
Get-ChildItem "HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Recurse -ErrorAction silentlycontinue | Out-File $SCHANNEL
if ((Get-Content $SSLSettings) -like "*EccCurves : {}*") {
	WriteReport 132006 @() @()
} 

# Test if running on unsupported Windows 10 or 2012 RTM OS
if ((($OSProductName -match 'Windows 10') -and ($OSBuild -lt "14393")) -or ($OSBuild -eq "9200")) {
	Write-output "`r`n######################## Unsupported Win OS check #########################" | Out-File $connectivityCheckFile -Append
	WriteReport 112002 @(, @($OSBuild)) @()
}

# Test for WSAEPROVIDERFAILEDINIT event related to LSP in netsh winsock catalog
if (!$OSPreviousVersion) {
	$EventError = Get-MatchingEvent Microsoft-Windows-UniversalTelemetryClient 29 "2147952506"
	if ($EventError) {
		Write-output "`r`n############################ Winsock error check ###############################" | Out-File $connectivityCheckFile -Append
		if ((Get-ProcessMitigation -Name MsSense.exe).ExtensionPoint.DisableExtensionPoints -eq "ON") {
			WriteReport 140005 @() @()
			"This disables various extensibility mechanisms that allow DLL injection. No further action required." | Out-File $connectivityCheckFile -Append
		}
  else {
			WriteReport 142008 @() @()
			$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
			Check-Command-verified "netsh.exe"
			$Winsock = &netsh winsock show catalog
			$winsock | Out-File $resultOutputDir\SystemInfoLogs\winsock_catalog.txt
			if ($winsock -like "*FwcWsp64.dll*") {
				WriteReport 142009 @() @()
			}
		}
	}
}

# Dump FSUTIL USN queryjournal output to log
$DriveLetters = (Get-PSDrive -PSProvider FileSystem) | Where-Object { $_.Free -ne $null } | ForEach-Object { $_.Name }
Write-output "`r`n######################## FSUTIL USN journal query #########################" | Out-File $connectivityCheckFile -Append
foreach ($DriveLetter in $DriveLetters) {
	Write-output "USN query journal output for Drive: " $DriveLetter | Out-File $connectivityCheckFile -Append
	Check-Command-verified "fsutil.exe"
	&fsutil usn queryjournal ("$DriveLetter" + ":") |  Out-File $connectivityCheckFile -Append
}

# Dump AddRemovePrograms to file
$uninstallKeys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
$dstfile = "$resultOutputDir\SystemInfoLogs\AddRemovePrograms.csv"
GetAddRemovePrograms $uninstallKeys | Export-Csv -Path $dstfile -NoTypeInformation -Encoding UTF8
$uninstallKeysWOW64 = Get-ChildItem HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall -ErrorAction SilentlyContinue
$dstfileWOW64 = "$resultOutputDir\SystemInfoLogs\AddRemoveProgramsWOW64.csv"
if ($uninstallKeysWOW64) {
	GetAddRemovePrograms $uninstallKeysWOW64 | Export-Csv -Path $dstfileWOW64 -NoTypeInformation -Encoding UTF8
}

# Check for issues with certificate store or time skew
if (($OSPreviousVersion) -and (Test-Path -Path $env:SystemRoot\System32\'Winevt\Logs\Operations Manager.evtx')) {
	$EventError = Get-MatchingEvent "Service Connector" 3009 "80090016"
	if ($EventError) {
		Write-output "`r`n###################### MMA certificate error check #########################" | Out-File $connectivityCheckFile -Append
		WriteReport 122006 @() @()
		$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
	}
	$EventError = Get-MatchingEvent "Service Connector" 4002 "ClockSkew"
	if ($EventError) {
		Write-output "`r`n######################### Client TimeSkew check ############################" | Out-File $connectivityCheckFile -Append	
		WriteReport 122007 @() @()
		$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
	}
}

# Check for issues with Default paths or reg keys
# Taken from amcore/wcd/Source/Setup/Manifest/Windows-SenseClient-Service.man
$DefaultPaths = 
@{
	Name = "Default MDE Policies key"
	Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection"
},
@{
	Name = "Default MDE Sensor Service key"
	Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Sense"
},
@{
	Name = "Default MDE directory path"
	Path = "$env:ProgramFiles\Windows Defender Advanced Threat Protection"
},
@{
	Name = "Default MDE ProgramData directory path"
	Path = "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection"
},
@{
	Name = "Default MDE Cache directory path"
	Path = "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Cache"
},
@{
	Name = "Default MDE Cyber directory path"
	Path = "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Cyber"
},
@{
	Name = "Default MDE Temp directory path"
	Path = "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Temp"
},
@{
	Name = "Defalt MDE Trace directory path"
	Path = "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Trace"
}

if ((!$OSPreviousVersion) -and (!$ARM)) {
	foreach ($item in $DefaultPaths) {
		if (!(Test-Path $item.Path)) {
			$MissingDefaultPath += $("`r`n" + $item.Name)
			$MissingDefaultPath += $("`r`n" + $item.Path + "`n")
		}
	}
	if ($MissingDefaultPath) {
		Write-Host -BackgroundColor Red -ForegroundColor Yellow "Default paths are missing. Please ensure the missing path(s) exist and have not been renamed:"
		Write-Host $MissingDefaultPath
		Write-output "`r`n###################### Missing default path check #########################" | Out-File $connectivityCheckFile -Append
		WriteReport 122003 @(, @($MissingDefaultPath)) @(, @($DefaultPaths[5].Path))
	}
}

# Check if SENSE cannot be started due to crash
if ((!$OSPreviousVersion) -or ($MDfWS)) {
	$EventError = (Get-MatchingEvent "Application Error" 1000 "TelLib.dll")
	if ($EventError) {
		$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
		$Exception = ($EventError.message -split '\n')[2]
		WriteReport 122039 @(, @($Exception)) @()	
	}
}

# Check if onboarding failed with Access denied due to tampering with registry permissions
if ((Test-Path -Path "$env:ProgramFiles\Windows Defender Advanced Threat Protection\MsSense.exe") -and !(Get-Process -Name MsSense -ErrorAction silentlycontinue)) {
	$EventError = (Get-MatchingEvent Microsoft-Windows-SENSE 43 "80070005")
	if ($EventError) {
		$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
		$SenseRegAclList = (Get-Acl -Path HKLM:\System\CurrentControlSet\Services\Sense | Select-Object -ExpandProperty Access) 
		$SenseRegAclSystem = $SenseRegAclList | Where-Object identityreference -eq "NT AUTHORITY\SYSTEM" 
		if (($SenseRegAclSystem.RegistryRights -ne "FullControl") -or ($SenseRegAclSystem.AccessControlType -ne "Allow")) {
			[string]$cleanAclOutput = $SenseRegAclSystem | Out-String -Width 250
			WriteReport 122015 @() @(, @($cleanAclOutput))	
		}
	}
} 

# Check if onboarding via SCCM failed due to registry issues
if (test-path -path $env:windir\ccm\logs\DcmWmiProvider.log) {
	$SCCMErr = Select-String -Path $env:windir\ccm\logs\DcmWmiProvider.log -Pattern 'Unable to update WATP onboarding' | Sort-Object CreationTime -Unique
	if ($SCCMErr) { 
		Write-output "`r`n############################ SCCM onboarding check ###############################" | Out-File $connectivityCheckFile -Append
		Copy-Item -path $env:windir\ccm\logs\DcmWmiProvider.log -Destination "$resultOutputDir\EventLogs\DcmWmiProvider.log"
		WriteReport 122004 @() @(, @($SCCMErr))
	}
}

# Check if onboarding via MMA failed due to unsupported OS env
if (Test-Path -Path $env:SystemRoot\System32\'Winevt\Logs\Operations Manager.evtx') {
	$EventError = Get-MatchingEvent "HealthService" 4509 "NotSupportedException"
	if (($EventError) -And (!$IsOnboarded)) {
		Write-output "`r`n########################## MMA unsupported OS check ##########################" | Out-File $connectivityCheckFile -Append
		WriteReport 112020 @() @()
		$EventError | Format-Table -Wrap | Out-File $connectivityCheckFile -Append
	}
}

# Check if running latest SCEP edition for downlevel OS
$SCEP = GetAddRemovePrograms $uninstallKeys | Where-Object { $_.DisplayName -like "*Endpoint Protection" }
if ($SCEP -And ("$env:ProgramFiles\Microsoft Security Client\")) {	
	if ([version](($SCEP).DisplayVersion) -lt [version]"4.10.209.0") {
		Write-output "`r`n############################ SCEP Client check ###############################" | Out-File $connectivityCheckFile -Append	
		WriteReport 122008 @(, @($SCEP)) @()
	}
}

Write-output "`r`n################## MDE CommandLine usage information ####################"  | Out-File $connectivityCheckFile -Append 
[environment]::GetCommandLineArgs() | Out-File $connectivityCheckFile -Append


Write-Host "Generating HealthCheck report..."
GenerateHealthCheckReport

# Check if MSinfo is still running and allow to run until timeout is reached
EndTimedoutProcess "msinfo32" 5

# collect Mde Configuration Manager logs reg and Events
get-MdeConfigMgrLogs

[version]$PSMinVer = '2.0.1.1'
if ( $PSVersionTable.PSVersion -gt $PSMinVer) {
	Write-Host "Compressing results directory..."
	Add-Type -Assembly "System.IO.Compression.FileSystem";
	[System.IO.Compression.ZipFile]::CreateFromDirectory($resultOutputDir, $outputZipFile)
	Write-Host "Result is available at: " $outputZipFile
}
else {
	Write-Host "Result is available at: " $resultOutputDir
}

# Prompt user to open HTML result file
if (!($system -or $RemoteRun -or $AdvancedFlag) -and ($HtmOutputFile)) {
	<# 
	Write-Host -ForegroundColor Green "Enter ANY key to view a summary of the Client Analyzer results or 'N' to exit"
	$ShowResults = Read-Host
	if ($ShowResults -ne "N") {
		Start-Process -FilePath $HtmOutputFile   
    }
	#>
	Write-Host -ForegroundColor Green "Opening the client analysis results in browser"
	Start-Process -FilePath $HtmOutputFile   
}

# SIG # Begin signature block
# MIInkgYJKoZIhvcNAQcCoIIngzCCJ38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBVqIGxkQfGK/Wc
# 2plCH9WaQtY/ln9Ya9/Qf89pUvYWgqCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXIwghluAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJXthgVEbINuefG6Qo5xmYh1
# FpdYN3GAbeiGLa52I36xMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAMWoR7yF5UpsilFXZBfwtx5ZEGGoCH0XnyqycCDsV1761H+ogloRvtQbp
# AG6lnETCBbbOigHTVVSXStzjuHlcd1hn6b8vMMxnApp/i1bFaFdPYigNBXTfnMix
# /AP+fsSzE2uUHzlVROb9dW/oAqisrXEQ4W5YTKPAMtA5KligN40r4STBwCQGdFpo
# ocnbMcR7MQZBQR/P5jpQZoxpM3ApyGK0VrDh/n/cdb5pUj2zmQfsZq0nvhS6r/ZJ
# ywULk4uQ4Q3q0EgWHQh0LuoI5NPcv5zeFEfmNqaapaUNMHDRN411YKIaA9OZmNca
# UZ7UPjHJr1tklqt/T6ZxhecFoCVEB6GCFvwwghb4BgorBgEEAYI3AwMBMYIW6DCC
# FuQGCSqGSIb3DQEHAqCCFtUwghbRAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFQBgsq
# hkiG9w0BCRABBKCCAT8EggE7MIIBNwIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCBR83jaOMaXWoAQYIV4JDqXgleOwgvJ2G9znlgM0Tz2nwIGZGzVO19J
# GBIyMDIzMDYwNjExNDU1MC41OVowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjdCRjEtRTNF
# QS1CODA4MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIR
# VDCCBwwwggT0oAMCAQICEzMAAAHI+bDuZ+3qa0YAAQAAAcgwDQYJKoZIhvcNAQEL
# BQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkwMTM3
# WhcNMjQwMjAyMTkwMTM3WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEm
# MCQGA1UECxMdVGhhbGVzIFRTUyBFU046N0JGMS1FM0VBLUI4MDgxJTAjBgNVBAMT
# HE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQC5y51+KE+DJFbCeci4kKpzdMK0WTRc6KYVwqNT1tLpYWeD
# aX4WsiJ3SY9nspazoTCPbVf5mQaQzrH6jMeWY22cdJDjymMgV2UpciiHt9KjjUDi
# fS1AiXCGzy4hgihynvbHAMEcpJnEZoRr/TvTuLI7D5pdlc1xPGA2JEQBJv22GUtk
# zvmZ8kiAFW9SZ0tlz5c5RjDP/y6XsgTO080fhyfwKfS0mEgV+nad62vwZg2iLIir
# G54bv6xK3bFeXv+KBzlwc9mdaF+X09oHj5K62sDzMCHNUdOePhF9/EDhHeTgFFs9
# 0ajBB85/3ll5jEtMd/lrAHSepnE5j7K4ZaF/qGnlEZGi5z1t5Vm/3wzV6thrnlLV
# qFmAYNAnJxW0TLzZGWYp9Nhja42aU8ta2cPuwOWlWSFhAYq5Nae7BAqr1lNIT7RX
# ZwfwlpYFglAwi5ZYzze8s+jchP9L/mNPahk5L2ewmDDALBFS1i3C2rz88m2+3VXp
# WgbhZ3b8wCJ+AQk6QcXsBE+oj1e/bz6uKolnmaMsbPzh0/avKh7SXFhLPc9PkSsq
# hLT7Mmlg0BzFu/ZReJOTdaP+Zne26XPrPhedKXmDLQ8t6v4RWPPgb3oZxmArZ30b
# 65jKUdbAGd4i/1gVCPrIx1b/iwSmQRuumIk16ZzFQKYGKlntJzfmu/i62Qnj9QID
# AQABo4IBNjCCATIwHQYDVR0OBBYEFLVcL0mButLAsNOIklPiIrs1S+T1MB8GA1Ud
# IwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRp
# bWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYI
# KwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMv
# TWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1Ud
# EwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIB
# AMPWclLIQ8OpKCd+QWJ8hu14lvs2RkJtGPnIEaJPV/19Ma9RvkJbuTd5Kne7FSqi
# b0tbKRw19Br9h/DSWJsSKb1hGNQ1wvjaggWq2n/uuX2CDrWiIHw8H7q8sSaNeRjF
# RRHxaMooLlDl3H3oHbV9pJyjYw6a+NjEZRHsCf7jnb2VA88upsQpGNw1Bv6n6aRA
# fZd4xuyHkRAKRO5gCKYVOCe6LZk8UsS4GnEErnPYecqd4dQn2LilwpZ0KoXUA5U3
# yBcgfRHQV+UxwKDlNby/3RXDH+Y/doTYiB7W4Twz1g0Gfnvvo/GYDXpn5zaz6Fgj
# 72wlmGFEDxpJhpyuUvPtpT/no68RhERFBm224AWStX4z8n60J4Y2/QZ3vljiUosy
# nn/TGg6+I8F0HasPkL9T4Hyq3VsGpAtVnXAdHLT/oeEnFs6LYiAYlo4JgsZfbPPR
# UBPqZnYFNasmZwrpIO/utfumyAL4J/W3RHVpYKQIcm2li7IqN/tSh1FrN685/pXT
# VeSsBEcqsjttCgcUv6y6faWIkIGM3nWYNagSBQIS/AHeX5EVgAvRoiKxzlxNoZf9
# PwX6IBvP6PYYZW6bzmARBL24vNJ52hg/IRfFNuXB7AZ0DGohloqjNEGjDj06cv7k
# KCihUx/dlKqnFzZALQTTeXpz+8KGRjKoxersvB3g+ceqMIIHcTCCBVmgAwIBAgIT
# MwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJv
# b3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcN
# MzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT
# /e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYj
# DLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/Y
# JlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d
# 9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVU
# j9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFK
# u75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231f
# gLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C
# 89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC
# +hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2
# XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54W
# cmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMG
# CSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cV
# XQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/
# BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2Nz
# L1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcU
# AgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8G
# A1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeG
# RWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jv
# b0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUH
# MAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2Vy
# QXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9n
# ATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP
# +2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27Y
# P0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8Z
# thISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNh
# cy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7G
# dP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4J
# vbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjo
# iV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TO
# PqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ
# 1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NN
# je6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAsswggI0AgEBMIH4oYHQpIHNMIHKMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNy
# b3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# Tjo3QkYxLUUzRUEtQjgwODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaIjCgEBMAcGBSsOAwIaAxUA384TULvGNTQKUgNdAGK5wBjuy7KggYMw
# gYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUF
# AAIFAOgpHvwwIhgPMjAyMzA2MDYxMDU3MDBaGA8yMDIzMDYwNzEwNTcwMFowdDA6
# BgorBgEEAYRZCgQBMSwwKjAKAgUA6Cke/AIBADAHAgEAAgImsTAHAgEAAgIRbjAK
# AgUA6CpwfAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIB
# AAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAFqCoDAOqjckQI/U
# RlBs/kFklZ0WDhdFPeNcf3CgQ8bmJF3IR6qi9qf9cwBvkKhFVQ/DJZN+p+p/aIIP
# hDM8k80yaM04sA0ic40ia4m9cDsKKgVd4M7STVCy5lrNswte8ZermpgUVo8kx/Dx
# TDQGuWqIJiishoxG8rm9sjckKy9UMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTACEzMAAAHI+bDuZ+3qa0YAAQAAAcgwDQYJYIZIAWUD
# BAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0B
# CQQxIgQgelc34+eBBVOPJSIA9Q21rpdPo8C/FvNKmQg/0BQg1hcwgfoGCyqGSIb3
# DQEJEAIvMYHqMIHnMIHkMIG9BCBiAJjPzT9toy/HDqNypK8vQVbhN28DT2fEd+w+
# G4QDZjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB
# yPmw7mft6mtGAAEAAAHIMCIEIHig5dZ03b3xGtYd+4QQ2+QKNLFSD9m2YwKGVilj
# rAHpMA0GCSqGSIb3DQEBCwUABIICABxskpPDrFfvCocJcZMh0x891+2Nd+veKbwj
# 8GZE5CHXVVUuOVD1utzrhoFUkGgtCcm3Ugo3+xUtqyOUGlOhk34k/3gyY27Nm1uN
# U9opOPzi1vmsEMCOCQulhVwLDlPIZL+t30k351n8f/l0y4/hHgfob26I476ZJa14
# vnM/qST/1YfIKHiwXSgMZsB/U7wJoNTmsijS2VmDmYTPfWE+HZdS7/dNpKhn2v4E
# 6erwTVlH/kKhGVqCjHVwkgknT/qjoQkmvet4kqlLZo5Y7jRV4RatZBp4NZzqtIkN
# LNRuoHZK71vJoDdLHbfhqKpTKJuekmpAryEI0BKBsiY00tN3nT6gbtbmoXxcdyaS
# PBLOZygF+prRVPgkGIqAHMwM227fvWvad9stYPajCbKKaLq4rleeife1usQ+dWxl
# whRyTXDJ2nReZETcpFbIDWvCzwjb60ky6Dbgm5JyoNnj/GxoffDM8DfA8chzbwj/
# cQXIcJr8qYrcABPbRp9+vN74XvQL7jbAdnD5yJEqs4fbto5MxxvA/o+dl7LLnZwD
# gNT41lzIoEogi+mpPvXaHYBqxqElV8s+DmlwJ0KpTt1wuU6M+tTILd8nk/LLRo7V
# KZdFlkWTvTdKGtUrsdnySHINKZz5dIS8rZWvubhVH3oTQi/WRh10C+FJydk6/FIV
# KDGF1GQH
# SIG # End signature block
