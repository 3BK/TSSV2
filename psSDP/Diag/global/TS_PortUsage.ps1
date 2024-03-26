#************************************************
# TS_PortUsage.PS1
# Version 1.0.1
# Date: 07-10-2009
# VBScript by Craig Landis (clandis@microsoft.com) and Clint Huffman (clinth@microsoft.com)
# PS1 by Andret Teixeira
# Description: This script outputs the number of unique local TCP ports in use (above the starting 
#              port) for each IP address and process on this computer. High numbers of unique 
#              local ports in use may reveal ephemeral port exhaustion which can cause failures
#              in applications and OS components that use TCP. If a large number of these ports
#              are in use then a warning is displayed. (Current version only writes to text file)
#************************************************
#Last Updated Date: 06-28-2012
#Updated By: Vincent Ke     v-zuke@microsoft.com
#Description: Import the logic of PortUsage.VBS in order to remove the calling to that external VB Script.
#************************************************

Param($Prefix = '', $Suffix = '')
if($debug -eq $true){[void]$shell.popup("Run TS_PortUsage.ps1")}

Import-LocalizedData -BindingVariable PortUsageStrings
Write-DiagProgress -Activity $PortUsageStrings.ID_PortUsage -Status $PortUsageStrings.ID_PortUsageObtaining

$RuleApplicable = $false
$PublicContent = "http://blogs.technet.com/askds/archive/2008/10/29/port-exhaustion-and-you-or-why-the-netstat-tool-is-your-friend.aspx"
$Visibility = "4"
$InformationCollected = new-object PSObject


$OutputFile = join-path $pwd.path ($ComputerName + "_" + $Prefix + "PortUsage" + $Suffix + ".txt")

#******************Variables****************************
$Script:DefaultStartPort = 0
$Script:DefaultNumberOfPorts = 0
$Script:StartPort = 1025
$Script:NumberOfPorts = 0
$Script:IsVistaOr2008 = $false

$Script:MaxUserPort = $null
$Script:MaxUserPortDefined = $true
$Script:TcpTimedWaitDelay = $null
$Script:TcpTimedWaitDelayDefault = 120
$Script:TcpTimedWaitDelayDefined = $true
$Script:ReservedPorts = $null
$Script:TcpipPort = $null
$Script:DcTcpipPort = $null
$Script:RPCTcpipPortAssignment = $null
$Script:top3Processes = $null

$Script:htLocalAddress = @{}
$Script:htProcessName = @{}
$Script:htPortProcess = @{}

$Script:EphemeralPort80 = $false
$Script:EphemeralPort50 = $false

$newline = "`r`n"
$MORE_INFORMATION = " **** Your computer may be running out of ephemeral ports ****" + $newline + $newline +
	" For more information see the following articles: " + $newline + $newline +
	" Avoiding TCP/IP Port Exhaustion" + $newline + 
	" http://msdn2.microsoft.com/en-us/library/aa560610.aspx" + $newline + $newline + 
	" When you try to connect from TCP ports greater than 5000 you receive the error WSAENOBUFS (10055)" + $newline + 
	" http://support.microsoft.com/kb/196271"

$ADDITIONAL_INFORMATION = " Additional Information:" + $newline +
	" =======================" + $newline + $newline + 
	" MaxUserPort" + $newline +
	" http://technet.microsoft.com/en-us/library/cc758002.aspx" + $newline + $newline +
	" TcpTimedWaitDelay" + $newline + 
	" http://technet.microsoft.com/en-us/library/cc757512.aspx" + $newline + $newline + 
	" ReservedPorts" + $newline + 
	" http://support.microsoft.com/kb/812873" + $newline + $newline + 
	" DCTcpipPort & TCP/IP Port" + $newline + 
	" http://support.microsoft.com/kb/224196" + $newline + $newline + 
	" RPC TCP/IP Port Assignment" + $newline + 
	" http://support.microsoft.com/kb/319553" + $newline + $newline + 
	" Port Exhaustion blog post" + $newline + 
	" http://blogs.technet.com/askds/archive/2008/10/29/port-exhaustion-and-you-or-why-the-netstat-tool-is-your-friend.aspx"


#************************************************
# Data Gathering
#************************************************

function AppliesToSystem {
	if ((($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2)) -or	#Windows Server 2003
	    (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 0)) -or 	#Vista, 2008
		(($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 1)) -or	#Win7, 2008 R2
		(($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 2)) -or 	#Win8, 2012
		 ($OSVersion.Major -eq 10)) {
		return $true
	}
	else {
		return $false
	}
}

#check the machine is server media or not
function isServerMedia {
	$Win32OS = Get-CimInstance -Class Win32_OperatingSystem
	
	if (($Win32OS.ProductType -eq 3) -or ($Win32OS.ProductType -eq 2)) { #Server Media
		return $true
	}
	else {
		return $false
	}
}

function GetTcpPortRange() {
	#get default tcp port range
	if( (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 0)) -or    #Vista/Server 2008  
		(($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 1)) -or	#Win7, 2008 R2
		(($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 2)) -or	#Win8, 2012
		 ($OSVersion.Major -eq 10)) {
		$Script:DefaultStartPort = 49152
		$Script:DefaultNumberOfPorts = 16384
		$Script:IsVistaOr2008 = $true
	}
	else {
		$Script:DefaultStartPort = 1025
		$Script:DefaultNumberOfPorts = 3976
		$Script:IsVistaOr2008 = $false
	}
	
	if($Script:IsVistaOr2008) {
		#get actual tcp port range

		$CommandLineToExecute = $Env:windir + "\system32\cmd.exe /c netsh interface ipv4 show dynamicportrange tcp"
		"Running $CommandLineToExecute" | WriteTo-StdOut -shortformat
		$content = Invoke-Expression $CommandLineToExecute
		"Finished $CommandLineToExecute" | WriteTo-StdOut -shortformat

		#because the output of netsh will be localized, so we can't use "Start Port", etc. instead, we use the line number to select string.
		#In english language, the output is like:
		#
		#Protocol tcp Dynamic Port Range
		#---------------------------------
		#Start Port      : 1025
		#Number of Ports : 64510
		#
		if($content.Length -ge 4)	
		{
			$line = $content[3]
			if(($null -ne $line) -and ($line.IndexOf(':') -ge 0)) {
				$Script:StartPort = [int]$line.Split(':')[1].Trim()
			}
			$line = $content[4]
			if(($null -ne $line) -and ($line.IndexOf(':') -ge 0)) {
				$Script:NumberOfPorts = [int]$line.Split(':')[1].Trim()
			}
		}
	}
}

function GetRegistryValues() {
	$tcpParamsKey = "HKLM:SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
	$ntdsParamsKey = "HKLM:SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    $ntfrsParamsKey = "HKLM:SYSTEM\CurrentControlSet\Services\NTFRS\Parameters"
	
	if(Test-Path $tcpParamsKey) {
		$properties = Get-ItemProperty -Path $tcpParamsKey
		$Script:MaxUserPort = $properties.MaxUserPort
		$Script:TcpTimedWaitDelay = $properties.TcpTimedWaitDelay
		$Script:ReservedPorts = $properties.ReservedPorts
	}
	
	if(Test-Path $ntdsParamsKey) {
		$properties = Get-ItemProperty -Path $ntdsParamsKey
		$Script:TcpipPort = $properties.{TCP/IP Port}
		$Script:DcTcpipPort = $properties.{DCTcpipPort}
	}
	
	if(Test-Path $ntfrsParamsKey) {
		$Script:RPCTcpipPortAssignment = (Get-ItemProperty -Path $ntfrsParamsKey).{RPC TCP/IP Port Assignment}
	}
	
	if($null -eq $Script:MaxUserPort) {
		$Script:MaxUserPort = 5000
		$Script:MaxUserPortDefined = $false
	}
	if(-not $Script:IsVistaOr2008) {
		$Script:NumberOfPorts = $Script:MaxUserPort - 1024
	}
	
	if($null -eq $Script:TcpTimedWaitDelay) {
		$Script:TcpTimedWaitDelay = 120
		$Script:TcpTimedWaitDelayDefined = $false
	}

	if($Script:StartPort -eq 0) {
		$Script:StartPort = $Script:DefaultStartPort
	}
	if($Script:NumberOfPorts -eq 0) {
		$Script:NumberOfPorts = $Script:DefaultNumberOfPorts
	}
}

# Get Processes and get the related service names for svchost process 
function GetProcessWithSvcService() {
	"Obtaining win32 service list" | WriteTo-StdOut -shortformat
	$svc = Get-CimInstance win32_service | Sort-Object ProcessId | group-Object ProcessId 

	"Obtaining process list" | WriteTo-StdOut -shortformat
	$ps = @(Get-Process | Sort-Object Id) 

	"Add service group to each process" | WriteTo-StdOut -shortformat
	$i=0
	$j=0
	while($i -lt $ps.count -and $j -lt $svc.count) { 
		if($ps[$i].Id -lt $svc[$j].Name) { 
			$i++;
			continue;
		}
		if($ps[$i].id -gt $svc[$j].Name) {
			$j++;
			continue;
		}
   		if($ps[$i].id -eq $svc[$j].Name) {
			$ps[$i] | add-Member NoteProperty service $Svc[$j].group;
			$i++;
			$j++;
		}
	}
	return $ps;
}

function GetProcessNameWithSvcService($process) {
	$services = ""
	foreach($item in $process.service) {
		if($services -ne "") {
			$services += ", "
		}
		$services += $item.Name
	}
	if($services -ne "") {
		$services = "{" + $services + "}"
	}
	return $process.ProcessName + $services
}

function GetTcpPortUsage() {
	"Running netstat -ano -p tcp" | WriteTo-StdOut -shortformat
	$CommandLineToExecute = $Env:windir + "\system32\cmd.exe /c netstat -ano -p tcp"
	$content = Invoke-Expression $CommandLineToExecute | Select-String "TCP"

	$processes = GetProcessWithSvcService
	
	"Format process information" | WriteTo-StdOut -shortformat
	$regex = [regex]"[^\s]+"
	foreach($line in $content) {
		#data format: 
		# TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1056
		# TCP    [::]:135               [::]:0                 LISTENING       1056
		$arr = $regex.Matches($line) | Select-Object -Property Value
		$localIPAddress = $arr[1].Value
		$localIP = $localIPAddress.Substring(0, $localIPAddress.LastIndexOf(':')).Trim('[', ']')
		$localPort = $localIPAddress.Substring($localIPAddress.LastIndexOf(':') + 1)
		$processid = $arr[4].Value
		$process = $processes | Where-Object { $_.Id -eq $processid }
		if($null -ne $process) {
			if($process.ProcessName -eq "svchost") {
				$processName = GetProcessNameWithSvcService($process)
			}
			else {
				$processName = $process.ProcessName
			}
			$processNameWithPID = $processName + ' [' + $process.Id + ']'
		}
		else {
			$processName = ""
			$processNameWithPID = ""
		}
		
		$Script:htPortProcess[$localPort] = $processName
		if(([int]$localPort) -ge $Script:StartPort) {	#The original VBS use localPort > startPort, I think it's a defect and should be localPort >= startPort, because afterwards it will show data: " Local Address : Number Of Ports Above " & intStartPort - 1
			$Script:htLocalAddress[$localIP]++
			$Script:htProcessName[$processNameWithPID]++
		}
	}
}

function GetDfsrConfigData() {
	"Get DFSR machine configuration data" | WriteTo-StdOut -shortformat
	$content = ""
	$rpcPortAssignments = Get-CimInstance -query "SELECT RpcPortAssignment FROM DfsrMachineConfig" -namespace "root\MicrosoftDFS" -ErrorAction SilentlyContinue
	if($null -ne $rpcPortAssignments) {
		$content += $newline + $newline + " DFSR RPC Port Assignment"
    	$content += $newline + " ===================================================================="
		foreach($item in $rpcPortAssignments) {
			$itemRPCPort = $item.RpcPortAssignment
			if($itemRPCPort -eq 0) {
				$content += $newline+ $newline + " No static RPC port is defined for DFSR (RpcPortAssignment = " + $itemRPCPort + ")."
			}
			elseif($itemRPCPort -eq 5722) {
				$content += $newline + $newline + " DFSR is using the static RPC port " + $itemRPCPort + " (RpcPortAssignment = " + $itemRPCPort + ")."
            	$content += $newline + $newline + " Windows Server 2008 R2 and Windows Server 2008 domain controllers use port 5722 by default for DFSR. See Bemis 2015519 for more information."
			}
			else {
				$content += $newline + $newline + " DFSR is using the static RPC port " + $itemRPCPort + " (RpcPortAssignment = " + $itemRPCPort + ")."
			}
		}
		
		$content += $newline + $newline + " Related registry values:"
		$content += $newline + " ========================"
		$content += $newline + $newline + "  HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
		if($Script:IsVistaOr2008) {
			$content += $newline + "    MaxUserPort = (value has no effect on Vista/2008)"
			$content += $newline + "    ReservedPorts = (value has no effect on Vista/2008)"
		}
		else {
			if($Script:MaxUserPortDefined) {
				$content += $newline + "    MaxUserPort = " + $Script:MaxUserPort + " (default is 5000)"
			}
			else {
				$content += $newline + "    MaxUserPort = <value not set> (default value of 5000 is in effect)"
			}
			if(($null -eq $Script:ReservedPorts) -or ($Script:ReservedPorts.Length -eq 0)) {
				$content += $newline + "    ReservedPorts = <value not set>"
			}
			else {
				$content += $newline + "    ReservedPorts = " + [string]::Join($newline + "                    ", $Script:ReservedPorts)
			}
		}
		if($Script:TcpTimedWaitDelayDefined) {
			$content += $newline + "    TcpTimedWaitDelay = " + $Script:TcpTimedWaitDelay + " (default is " + $Script:TcpTimedWaitDelayDefault + ")"
		}
		else {
			$content += $newline + "    TcpTimedWaitDelay = <value not set> (default of " + $Script:TcpTimedWaitDelayDefault + " is in effect)"
		}
		
		$content += $newline + $newline + "  HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
	    if($null -eq $Script:TcpipPort) {
			$content += $newline + "    TCP/IP Port = <value not set>"
		}
	    else {
	    	$content += $newline + "    TCP/IP Port = " + $Script:TcpipPort
		}
	    if($null -eq $Script:DcTcpipPort) {
			$content += $newline + "    DCTcpipPort = <value not set>"
		}
		else {
	    	$content += $newline + "    DCTcpipPort = " + $Script:DcTcpipPort
	    }
		$content += $newline + $newline + "  HKLM\SYSTEM\CurrentControlSet\Services\NTFRS\Parameters"
	    if($null -eq $Script:RPCTcpipPortAssignment) {
			$content += $newline + "    RPC TCP/IP Port Assignment = <value not set>"
		}
		else {
	    	$content += $newline + "    RPC TCP/IP Port Assignment = " + $Script:RPCTcpipPortAssignment
	    }
	}
	return $content
}

function OutputTCPPortUsageToFile() {
	"Output TCP port information" | WriteTo-StdOut -shortformat
	$content = "This script outputs the number of unique local TCP ports in use (above the starting port) for each IP address and process on this computer. High numbers of unique local ports in use may reveal ephemeral port exhaustion which can cause failures in applications and OS components that use TCP. If a large number of these ports are in use then a warning is displayed." + $newline + $newline
	
	#1: Local Address Information
	$content += " Local Address : Number Of Ports Above " + ($Script:StartPort - 1) + $newline
	$content += " ===========================================" + $newline
	
	# Set thresholds to check for - 50% and 80%
    $fiftyPercentOfEphemeralPorts = $Script:NumberOfPorts * 0.5
    $eightyPercentOfEphemeralPorts = $Script:NumberOfPorts * 0.8
	$criticalMessage = " ** CRITICAL: More than 80% of local ports in use. Possible ephemeral port (outbound port) exhaustion.**"
	$warningMessage = " ** WARNING: More than 50% of local ports in use. Possible high amount of ephemeral port (outbound port) usage.**"
	$localPortCount = 0
	
	foreach($key in $Script:htLocalAddress.Keys) {
		$value = $Script:htLocalAddress[$key]
		$localPortCount += $value
		$content += "  " + $key + " : " + $value
		if($value -gt $eightyPercentOfEphemeralPorts) {
			$Script:EphemeralPort80 = $true
			$content += $criticalMessage
		}
		elseif($value -gt $fiftyPercentOfEphemeralPorts) {
			$Script:EphemeralPort50 = $true
			$content += $warningMessage
		}
		$content += $newline
	}
	
	#2: Process name and number of ports used for each process
	$content += $newline + " Process Name [PID] : Number of Ports Above " + ($Script:StartPort - 1) + " (sorted descending)" + $newline
    $content += " ====================================================================" + $newline
	$sortedProcesses = $Script:htProcessName.GetEnumerator() | Sort-Object Value -descending
	$Script:top3Processes = $sortedProcesses | Select-Object -First 3
	foreach($item in $sortedProcesses) {
		#$value = $Script:htProcessName[$key]
		$content += "  " + $item.key + " : " + $item.value + $newline
	}
	$content += $newline
	$usedPortPercentage = "{0:P1}" -f ($localPortCount / $Script:NumberOfPorts)
	$content += " **** Total local ports in use: " + $localPortCount + " of " + $Script:NumberOfPorts + " (" + $usedPortPercentage + ") ****" + $newline
	if($Script:EphemeralPort80 -or $Script:EphemeralPort50) {
		$content += $newline + $MORE_INFORMATION
	}
	$content +=  $newline + " Start Port      : " + $Script:StartPort + " (default is " + $Script:DefaultStartPort + ")"
	$content +=  $newline + " Number of Ports : " + $Script:NumberOfPorts + " (default is " + $Script:DefaultNumberOfPorts + ")"

	#3: Each port and its using process
	$content +=  $newline + $newline + " Process Name: Listening Port Number (includes all ports 0-65535)"
    $content +=  $newline + " ====================================================================" + $newline
	$sortedPortProcesses = $Script:htPortProcess.GetEnumerator() | Sort-Object Value
	foreach($item in $sortedPortProcesses) {
		$content += "  " + $item.value + " : " + $item.key + $newline
	}
	
	#4 WMI DFSR config info
	if( (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 0)) -or	#Vista, See: http://msdn.microsoft.com/en-us/library/windows/desktop/dd405482(v=vs.85).aspx
		(isServerMedia)) {
		$content += GetDfsrConfigData
	}

	$content += $newline + $newline + $ADDITIONAL_INFORMATION

	"Write info to output file" | WriteTo-StdOut -shortformat
	Set-Content $OutputFile $content
	CollectFiles -filesToCollect $OutputFile -fileDescription "Ephemeral Port usage" -SectionDescription "Port Usage"
}

# **************
# Detection Logic
# **************
if(AppliesToSystem) {
	$RuleApplicable = $true
	
	GetTcpPortRange
	GetRegistryValues
	GetTcpPortUsage
	OutputTCPPortUsageToFile

	if(($Script:EphemeralPort80 -or $Script:EphemeralPort50) -and
	   ($null -ne $Script:top3Processes) -and ($Script:top3Processes.Length -eq 3)) {
		$InformationCollected | add-member -membertype noteproperty -name "Process Name [1]" -value $Script:top3Processes[0].Key
		$InformationCollected | add-member -membertype noteproperty -name "Number of ports [1]" -value $Script:top3Processes[0].Value
		$InformationCollected | add-member -membertype noteproperty -name "Process Name [2]" -value $Script:top3Processes[1].Key
		$InformationCollected | add-member -membertype noteproperty -name "Number of ports [2]" -value $Script:top3Processes[1].Value
		$InformationCollected | add-member -membertype noteproperty -name "Process Name [3]" -value $Script:top3Processes[2].Key
		$InformationCollected | add-member -membertype noteproperty -name "Number of ports [3]" -value $Script:top3Processes[2].Value
	}
}

# *********************
# Root Cause processing
# *********************
if ($RuleApplicable)
{
	if ($Script:EphemeralPort80) {
		$RootCauseName = "RC_EphemeralPort80Check"
		$Verbosity = "Error"
		$Title = $PortUsageStrings.ID_EphemeralPortDesc -replace "%XXX%", "80%"
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL $PublicContent -InformationCollected $InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SolutionTitle $Title -SDPFileReference $OutputFile
	}
	elseif($Script:EphemeralPort50) {
		$RootCauseName = "RC_EphemeralPort50Check"
		$Verbosity = "Warning"
		$Title = $PortUsageStrings.ID_EphemeralPortDesc -replace "%XXX%", "50%"
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL $PublicContent -InformationCollected $InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SolutionTitle $Title -SDPFileReference $OutputFile
	}
	else {	# Green Light
		$RootCauseName = "RC_EphemeralPort50Check"
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}


# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC+gHY4F4c6JmFP
# kDUaIzzhKdjBsIU52qRzWvxNIo7EBqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
# OfsCcUI2AAAAAALLMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NTU5WhcNMjMwNTExMjA0NTU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC3sN0WcdGpGXPZIb5iNfFB0xZ8rnJvYnxD6Uf2BHXglpbTEfoe+mO//oLWkRxA
# wppditsSVOD0oglKbtnh9Wp2DARLcxbGaW4YanOWSB1LyLRpHnnQ5POlh2U5trg4
# 3gQjvlNZlQB3lL+zrPtbNvMA7E0Wkmo+Z6YFnsf7aek+KGzaGboAeFO4uKZjQXY5
# RmMzE70Bwaz7hvA05jDURdRKH0i/1yK96TDuP7JyRFLOvA3UXNWz00R9w7ppMDcN
# lXtrmbPigv3xE9FfpfmJRtiOZQKd73K72Wujmj6/Su3+DBTpOq7NgdntW2lJfX3X
# a6oe4F9Pk9xRhkwHsk7Ju9E/AgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUrg/nt/gj+BBLd1jZWYhok7v5/w4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQ3MDUyODAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAJL5t6pVjIRlQ8j4dAFJ
# ZnMke3rRHeQDOPFxswM47HRvgQa2E1jea2aYiMk1WmdqWnYw1bal4IzRlSVf4czf
# zx2vjOIOiaGllW2ByHkfKApngOzJmAQ8F15xSHPRvNMmvpC3PFLvKMf3y5SyPJxh
# 922TTq0q5epJv1SgZDWlUlHL/Ex1nX8kzBRhHvc6D6F5la+oAO4A3o/ZC05OOgm4
# EJxZP9MqUi5iid2dw4Jg/HvtDpCcLj1GLIhCDaebKegajCJlMhhxnDXrGFLJfX8j
# 7k7LUvrZDsQniJZ3D66K+3SZTLhvwK7dMGVFuUUJUfDifrlCTjKG9mxsPDllfyck
# 4zGnRZv8Jw9RgE1zAghnU14L0vVUNOzi/4bE7wIsiRyIcCcVoXRneBA3n/frLXvd
# jDsbb2lpGu78+s1zbO5N0bhHWq4j5WMutrspBxEhqG2PSBjC5Ypi+jhtfu3+x76N
# mBvsyKuxx9+Hm/ALnlzKxr4KyMR3/z4IRMzA1QyppNk65Ui+jB14g+w4vole33M1
# pVqVckrmSebUkmjnCshCiH12IFgHZF7gRwE4YZrJ7QjxZeoZqHaKsQLRMp653beB
# fHfeva9zJPhBSdVcCW7x9q0c2HVPLJHX9YCUU714I+qtLpDGrdbZxD9mikPqL/To
# /1lDZ0ch8FtePhME7houuoPcMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXUwghlxAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKSUsHoFjA1rk2+Tyy5qqemN
# p3ikCHPZ/4RZ4ZWKBrSvMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCDRHoSI370JXDXpS0PB48EvjTa3Cr0J5S/cwE6HyvlCtuvXr1gvxWd
# WzU6T47E3RdFUVBLK2h0n8UB2Uzazo+4MGkz8etha3ZcrNOyuIZrNeBDo5NiTmMj
# saKWa/GDvINUH0oB0jNeEonPKO8XgdcD+giLA9vYkrkJ5JtVB9SjLSb2TNY8T2W8
# 2D9XzJmzIuMDdQ621YTEb9qNv5hT6p+fmzKNtL9+Zi/0CfRhRRissewT/Vk3DvC7
# 5omrVgfWOdUQRT9t5fGGX7Bj06PTozCmTNztt53wmxxKYmUn93dNayihdbkSMVcd
# lpdb4BTWXZ59+4Uelk590FstZPHuySE4oYIW/TCCFvkGCisGAQQBgjcDAwExghbp
# MIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIEk8WKSdVDdV3orPbF/SCT4viHTiJxYQ6h2dHTSpxNTNAgZi1+uY
# LEYYEzIwMjIwODAxMDc0MjQ3LjM0OVowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjQ5QkMt
# RTM3QS0yMzNDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVDCCBwwwggT0oAMCAQICEzMAAAGXA89ZnGuJeD8AAQAAAZcwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTE0WhcNMjMwMjI4MTkwNTE0WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046NDlCQy1FMzdBLTIzM0MxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDtAErqSkFN8/Ce/csrHVWcv1iSjNTArPKEMqKPUTpY
# JX8TBZl88LNrpw4bEpPimO+Etcli5RBoZEieo+SzYUnb0+nKEWaEYgubgp+HTFZi
# D85Lld7mk2Xg91KMDE2yMeOIH2DHpTsn5p0Lf0CDlfPE5HOwpP5/vsUxNeDWMW6z
# sSuKU69aL7Ocyk36VMyCKjHNML67VmZMJBO7bX1vYVShOvQqZUkxCpCR3szmxHT0
# 9s6nhwLeNCz7nMnU7PEiNGVxSYu+V0ETppFpK7THcGYAMa3SYZjQxGyDOc7J20kE
# ud6tz5ArSRzG47qscDfPYqv1+akex81w395E+1kc4uukfn0CeKtADum7PqRrbRMD
# 7wyFnX2FvyaytGj0uaKuMXFJsZ+wfdk0RsuPeWHtVz4MRCEwfYr1c+JTkmS3n/pv
# Hr/b853do28LoPHezk3dSxbniQojW3BTYJLmrUei/n4BHK5mTT8NuxG6zoP3t8HV
# mhCW//i2sFwxVHPsyQ6sdrxs/hapsPR5sti2ITG/Hge4SeH7Sne942OHeA/T7sOS
# JXAhhx9VyUiEUUax+dKIV7Gu67rjq5SVr5VNS4bduOpLsWEjeGHpMei//3xd8dxZ
# 42G/EDkr5+L7UFxIuBAq+r8diP/D8yR/du7vc4RGKw1ppxpo4JH9MnYfd+zUDuUg
# cQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFG3PAc8o6zBullUL0bG+3X69FQBgMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAARI2GHSJO0zHnshct+Hgu4dsPU0b0yUsDXBhAdAGdH1T+uDeq3c3Hp7v5C4
# QowSEqp0t/eDlFHhH+hkvm8QlVZR8hIf+hJZ3OqtKGpyZPg7HNzYIGzRS2fKilUO
# bhbYK6ajeq7KRg+kGgZ16Ku8N13XncDCwmQgyCb/yzEkpsgF5Pza2etSeA2Y2jy7
# uXW4TSGwwCrVuK9Drd9Aiev5Wpgm9hPRb/Q9bukDeqHihw2OJfpnx32SPHwvu4E8
# j8ezGJ8KP/yYVG+lUFg7Ko/tjl2LlkCeNMNIcxk1QU8e36eEVdRweNc9FEcIyqom
# DgPrdfpvRXRHztD3eKnAYhcEzM4xA0i0k5F6Qe0eUuLduDouemOzRoKjn9GUcKM2
# RIOD7FXuph5rfsv84pM2OqYfek0BrcG8/+sNCIYRi+ABtUcQhDPtYxZJixZ5Q8Vk
# jfqYKOBRjpXnfwKRC0PAzwEOIBzL6q47x6nKSI/QffbKrAOHznYF5abV60X4+TD+
# 3xc7dD52IW7saCKqN16aPhV+lGyba1M30ecB7CutvRfBjxATa2nSFF03ZvRSJLEy
# YHiE3IopdVoMs4UJ2Iuex+kPSuM4fyNsQJk5tpZYuf14S8Ov5A1A+9Livjsv0Brw
# uvUevjtXAnkTaAISe9jAhEPOkmExGLQqKNg3jfJPpdIZHg32MIIHcTCCBVmgAwIB
# AgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1
# WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
# 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZn
# hUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t
# 1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxq
# D89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmP
# frVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSW
# rAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
# 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zb
# r17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
# IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQc
# xWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17a
# j54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3h
# LB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
# 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74p
# y27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1A
# oL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbC
# HcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB
# 9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNt
# yo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
# rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcV
# v7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
# 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lw
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAsswggI0AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjo0OUJDLUUzN0EtMjMzQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAYUDSsI2YSTTNTXYNg0YxTcHWY9Gg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRkxgwIhgPMjAyMjA4MDEwNzQ3MzZaGA8yMDIyMDgwMjA3NDczNlow
# dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5pGTGAIBADAHAgEAAgIeizAHAgEAAgIR
# wzAKAgUA5pLkmAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAF1eQuLWB69l
# cRkwlDC//Q8t6MKhMl4o4Q+GcAYe9w/P1hDjWpsFI3X3Q+q6z8QtX/Q1c4IK5S6G
# JXMlxEbcKpiXknCiQ8r4UssZYTe3qUIeBsh0XohckQUJEbEzUMUAqe474r3Ibf4d
# gwN5gry9881JMrkws7I0ZHaZmL36EBVuMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGXA89ZnGuJeD8AAQAAAZcwDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgOOOvF7rB3bk0aW4yuFaTvrdOOdxfIj7lz8vPZiqffYswgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBbe9obEJV6OP4EDMVJ8zF8dD5vHGSoLDwu
# Qxj9BnimvzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABlwPPWZxriXg/AAEAAAGXMCIEIJ3XeUNIGOGvXHlvVJ8soX+gMgA0CH0mLbWJ
# R46ykrvfMA0GCSqGSIb3DQEBCwUABIICAJ99X7rYLrVjSXLc9o62qInwMoFPoM/P
# Cbd4DE9v2PYV5mkymup8Wpp113OPOCFr2ZyA8rnBFaJ7AWOeKhLTNEf+Aof36jhN
# kRBS9NQm9Yl8JOSYtvPT+hdI84SvLi0Nq84LMqbQMGPzBE99gKSKvVQVOuk9RXh3
# noMjazYfOmZ3x+7YmYlGCVkbPmoTAkIZ3z4ar34VN1+p2nAcgXWyBQPyIn86b9tR
# M06wHX1A8lbxkOJz6dnqavMrvkCTir4cdKJzPQOVNE1WnFo88k5gbCnBHAaJbY/e
# ZA6WSC2+EBZ9GI5IEf/TlIO41etxZJCsSZ7+UeIVN9/8jrydTxsYfGRjIf95ffTQ
# nQs0KfQAZlsa3NPU2JmCNYc7IHj+tmiq8zI8fR1VHELT31GEbSrkJH33g0wJKVIF
# fyjxX5ycxhyvRmUuPa8+JApM/OY6YIH6RfzP7RHZu8dcugfAZbHv3lrM+vsVAXnS
# uPG7aqZ2J1sv6Q9DezF78s/IDJiEfvbkcoGljBHWW9TdXmf4IoxPA52+6goQF07n
# chwXFmoWzUclloBqiy9FPF5KDfpCcmSHrgEM1T9QXSOtEo5YD7NntqlwlcWq7ii4
# pROMdQ4ldIw+Ea/lRb1kNVwszsY4RUKA0XS7HzHQKJHBKWgbDUT3YFFWQaoPyZoy
# uSxb6IGW3Oic
# SIG # End signature block
