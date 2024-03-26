#************************************************
# DC_TCPIP-Component.ps1
# Version 1.0: Collects information from the registry, netsh, arp, ipconfig, etc. 
# Version 1.1: Updated IPv6 Transition Technologies section for SKU checks to clean up exceptions.
# Version 1.2: Altered the runPS function correctly a column width issue.
# Version 1.3: Corrected the code for Get-NetCompartment (only runs in WS2012+)
# Version 1.4.09.10.14: Add additional netsh commands for Teredo and ISATAP. TFS264243
# Date: 2009-2014 /WalterE 2019-2022 - GetNetTcpConnEstablished
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: Collects information about TCPIP.
# Called from: Networking Diags
#*******************************************************


Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}

Import-LocalizedData -BindingVariable ScriptVariable
Write-DiagProgress -Activity $ScriptVariable.ID_CTSTCPIP -Status $ScriptVariable.ID_CTSTCPIPDescription

"[info]:TCPIP-Component:BEGIN" | WriteTo-StdOut


function RunNetSH ([string]$NetSHCommandToExecute="")
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSTCPIP -Status "netsh $NetSHCommandToExecute"
	$NetSHCommandToExecuteLength = $NetSHCommandToExecute.Length + 6
	"-" * ($NetSHCommandToExecuteLength)	| Out-File -FilePath $outputFile -append
	"netsh $NetSHCommandToExecute"			| Out-File -FilePath $outputFile -append
	"-" * ($NetSHCommandToExecuteLength)	| Out-File -FilePath $outputFile -append
	$CommandToExecute = "cmd.exe /c netsh.exe " + $NetSHCommandToExecute + " >> $outputFile "
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
	"`n`n`n" | Out-File -FilePath $outputFile -append
}


function RunPS ([string]$RunPScmd="", [switch]$ft)
{
	$RunPScmdLength = $RunPScmd.Length
	"-" * ($RunPScmdLength)		| Out-File -FilePath $OutputFile -append
	"$RunPScmd"  				| Out-File -FilePath $OutputFile -append
	"-" * ($RunPScmdLength)  	| Out-File -FilePath $OutputFile -append
	
	if ($ft)
	{
		# This format-table expression is useful to make sure that wide ft output works correctly
		Invoke-Expression $RunPScmd	|format-table -autosize -outvariable $FormatTableTempVar | Out-File -FilePath $outputFile -Width 500 -append
	}
	else
	{
		Invoke-Expression $RunPScmd	| Out-File -FilePath $OutputFile -append
	}
	"`n`n`n" | Out-File -FilePath $outputFile -append
}


function RunNetCmd ([string]$NetCmd="", [string]$NetCmdArg="")
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSTCPIP -Status "$NetCmd $NetCmdArg"
	$NetCmdLen = $NetCmd.length
	$NetCmdArgLen = $NetCmdArg.Length
	$NetCmdFullLen = $NetCmdLen + $NetCmdArgLen + 1
	"-" * ($NetCmdFullLen)	| Out-File -FilePath $outputFile -append
	"$NetCmd $NetCmdArg"	| Out-File -FilePath $outputFile -append
	"-" * ($NetCmdFullLen)	| Out-File -FilePath $outputFile -append
	$CommandToExecute = "cmd.exe /c $NetCmd $NetCmdArg >> $outputFile"
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
	"`n`n`n" | Out-File -FilePath $outputFile -append
}


function Heading ([string]$header)
{
	"=" * ($borderLen)	| Out-File -FilePath $outputFile -append
	"$header"			| Out-File -FilePath $outputFile -append
	"=" * ($borderLen)	| Out-File -FilePath $outputFile -append
	"`n`n`n" | Out-File -FilePath $outputFile -append
}

function GetNetTcpConnEstablished ()
{
	#get all TCP established connections and match them with its process. Similar output is thrown by using: netstat -ano
	$AllConnections = @()
	$Connections = Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess
	ForEach($Connection In $Connections) {
		$ProcessInfo = Get-Process -PID $Connection.OwningProcess -IncludeUserName | Select-Object Path,UserName,StartTime,Name,Id
		$Obj = New-Object -TypeName PSObject
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name LocalAddress -Value $Connection.LocalAddress
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name LocalPort -Value $Connection.LocalPort
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name RemoteAddress -Value $Connection.RemoteAddress
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name RemotePort -Value $Connection.RemotePort
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name OwningProcessID -Value $Connection.OwningProcess
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name ProcessName -Value $ProcessInfo.Name
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name UserName -Value $ProcessInfo.UserName
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name CommandLine -Value $ProcessInfo.Path
		Add-Member -InputObject $Obj -MemberType NoteProperty -Name StartTime -Value $ProcessInfo.StartTime
		$AllConnections += $Obj
	}
	$AllConnections #|format-table -autosize
}


$sectionDescription = "TCPIP"
$borderLen = 52

# detect OS version and SKU
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber



####################################################
# General Information
####################################################
#-----MAIN TCPIP INFO  (W2003+)

#----------TCPIP Information from Various Tools
$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_info.TXT")
"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
"TCPIP Networking Information"						| Out-File -FilePath $OutputFile -append
"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
"Overview"											| Out-File -FilePath $OutputFile -append
"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
"TCPIP Networking Information"						| Out-File -FilePath $OutputFile -append
"   1. hostname"									| Out-File -FilePath $OutputFile -append
"   2. ipconfig /allcompartments /all"				| Out-File -FilePath $OutputFile -append
"   3. route print"									| Out-File -FilePath $OutputFile -append
"   4. arp -a"										| Out-File -FilePath $OutputFile -append
"   5. netstat -nato" 								| Out-File -FilePath $OutputFile -append
"   6. netstat -anob"								| Out-File -FilePath $OutputFile -append
"   7. netstat -es" 								| Out-File -FilePath $OutputFile -append
"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
"`n`n`n`n`n" | Out-File -FilePath $outputFile -append

Heading "TCPIP Networking Information"
RunNetCmd "hostname"
# 4/17/14: If WV/WS2008, run "ipconfig /allcompartments /all". If WXP/WS2003 "ipconfig /all".
if ($bn -gt 6000)
{ RunNetCmd "ipconfig" "/allcompartments /all" }
else
{ RunNetCmd "ipconfig" "/all" }
RunNetCmd "route print"
RunNetCmd "arp" "-a"
RunNetCmd "netstat" "-nato"
RunNetCmd "netstat" "-anob"
RunNetCmd "netstat" "-es"
CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP Info" -SectionDescription $sectionDescription

#----------Registry (General)
$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_reg_output.TXT")
$CurrentVersionKeys =	"HKLM\SOFTWARE\Policies\Microsoft\Windows\TCPIP",
						"HKLM\SYSTEM\CurrentControlSet\services\TCPIP",
						"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6",
						"HKLM\SYSTEM\CurrentControlSet\Services\tcpipreg",
						"HKLM\SYSTEM\CurrentControlSet\Services\iphlpsvc"
RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -outputFile $outputFile -fileDescription "TCPIP registry output" -SectionDescription $sectionDescription

#----------TCP OFFLOAD (netsh)
$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_OFFLOAD.TXT")

"=" * ($borderLen)								| Out-File -FilePath $outputFile -append
"TCPIP Offload Information"						| Out-File -FilePath $OutputFile -append
"=" * ($borderLen)								| Out-File -FilePath $outputFile -append
"Overview"										| Out-File -FilePath $OutputFile -append
"-" * ($borderLen)								| Out-File -FilePath $outputFile -append
"TCPIP Offload Information"						| Out-File -FilePath $OutputFile -append
"  1. netsh int tcp show global"				| Out-File -FilePath $outputFile -Append
"  2. netsh int ipv4 show offload"				| Out-File -FilePath $outputFile -Append
"  3. netstat -nato -p tcp"						| Out-File -FilePath $outputFile -Append
"=" * ($borderLen)								| Out-File -FilePath $outputFile -Append
"`n`n`n`n`n" | Out-File -FilePath $outputFile -append
RunNetCmd "netsh" "int tcp show global"
RunNetCmd "netsh" "int ipv4 show offload"
RunNetCmd "netstat" "-nato -p tcp"

CollectFiles -filesToCollect $outputFile -fileDescription "TCP OFFLOAD" -SectionDescription $sectionDescription

#----------Copy the Services File
$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_ServicesFile.TXT")

$servicesfile = "$ENV:windir\system32\drivers\etc\services"
if (test-path $servicesfile)
{
  Copy-Item -Path $servicesfile -Destination $outputFile
  CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP Services File" -SectionDescription $sectionDescription
}
else
{
	"$servicesfile Does not exist" | writeto-stdout
}

# W8/WS2012
if ($bn -gt 9000)
{
	"[info]: TCPIP-Component W8/WS2012+" | WriteTo-StdOut

	####################################################
	# TCPIP Transition Technologies
	####################################################
	$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_info_pscmdlets_net.TXT")

	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"TCPIP Powershell Cmdlets"							| Out-File -FilePath $OutputFile -append
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"Overview"											| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"   1. Get-NetCompartment (WS2012+)"				| Out-File -FilePath $OutputFile -append
	"   2. Get-NetIPAddress"							| Out-File -FilePath $OutputFile -append	
	"   3. Get-NetIPInterface"							| Out-File -FilePath $OutputFile -append
	"   4. Get-NetIPConfiguration"						| Out-File -FilePath $OutputFile -append
	"   5. Get-NetIPv4Protocol"							| Out-File -FilePath $OutputFile -append
	"   6. Get-NetIPv6Protocol"							| Out-File -FilePath $OutputFile -append
	"   7. Get-NetOffloadGlobalSetting"					| Out-File -FilePath $OutputFile -append
	"   8. Get-NetPrefixPolicy"							| Out-File -FilePath $OutputFile -append
	"   9. Get-NetRoute -IncludeAllCompartments"		| Out-File -FilePath $OutputFile -append
	"  10. Get-NetTCPConnection"						| Out-File -FilePath $OutputFile -append
	"  10a. GetNetTCPConnEstablished"					| Out-File -FilePath $OutputFile -append
	"  11. Get-NetTransportFilter"						| Out-File -FilePath $OutputFile -append
	"  12. Get-NetTCPSetting"							| Out-File -FilePath $OutputFile -append
	"  13. Get-NetUDPEndpoint"							| Out-File -FilePath $OutputFile -append
	"  14. Get-NetUDPSetting"							| Out-File -FilePath $OutputFile -append
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"`n`n`n`n`n" | Out-File -FilePath $outputFile -append

	if ($bn -ge 9600)
	{
		RunPS "Get-NetCompartment"							# W8/WS2012, W8.1/WS2012R2	# fl
	}
	else
	{
		$RunPScmd = "Get-NetCompartment"
		$RunPScmdLength = $RunPScmd.Length
		"-" * ($RunPScmdLength)		| Out-File -FilePath $OutputFile -append
		"$RunPScmd"  				| Out-File -FilePath $OutputFile -append
		"-" * ($RunPScmdLength)  	| Out-File -FilePath $OutputFile -append
		"The Get-NetCompartment pscmdlet is only available in WS2012R2+."	| Out-File -FilePath $OutputFile -append
	}
	RunPS "Get-NetIPAddress"							# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetIPInterface"						-ft	# W8/WS2012, W8.1/WS2012R2	# ft
	RunPS "Get-NetIPConfiguration"						# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetIPv4Protocol"							# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetIPv6Protocol"							# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetOffloadGlobalSetting"					# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetPrefixPolicy"						-ft	# W8/WS2012, W8.1/WS2012R2	# ft
	RunPS "Get-NetRoute -IncludeAllCompartments"	-ft	# W8/WS2012, W8.1/WS2012R2	# ft
	RunPS "Get-NetTCPConnection"					-ft	# W8/WS2012, W8.1/WS2012R2	# ft
	RunPS "GetNetTCPConnEstablished"				-ft	# 
	RunPS "Get-NetTransportFilter"						# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetTCPSetting"							# W8/WS2012, W8.1/WS2012R2	# fl
	RunPS "Get-NetUDPEndpoint"						-ft	# W8/WS2012, W8.1/WS2012R2	# ft
	RunPS "Get-NetUDPSetting"							# W8/WS2012, W8.1/WS2012R2	# fl

	CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP Net Powershell Cmdlets" -SectionDescription $sectionDescription
}

# W8/WS2012
if ($bn -gt 9000)
{
	####################################################
	# TCPIP IPv6 Transition Technologies
	####################################################
	$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_info_pscmdlets_IPv6Transition.TXT")
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"IPv6 Transition Technologies Powershell Cmdlets"	| Out-File -FilePath $OutputFile -append
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"Overview"											| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"   1. Get-Net6to4Configuration"					| Out-File -FilePath $OutputFile -append
	"   2. Get-NetDnsTransitionConfiguration"			| Out-File -FilePath $OutputFile -append
	"   3. Get-NetDnsTransitionMonitoring"				| Out-File -FilePath $OutputFile -append
	"   4. Get-NetIPHttpsConfiguration"					| Out-File -FilePath $OutputFile -append
	"   5. Get-NetIsatapConfiguration"					| Out-File -FilePath $OutputFile -append
	"   6. Get-NetNatTransitionConfiguration"			| Out-File -FilePath $OutputFile -append
	"   7. Get-NetNatTransitionMonitoring"				| Out-File -FilePath $OutputFile -append
	"   8. Get-NetTeredoConfiguration"					| Out-File -FilePath $OutputFile -append
	"   9. Get-NetTeredoState"							| Out-File -FilePath $OutputFile -append
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"`n`n`n`n`n" | Out-File -FilePath $outputFile -append

	#Get role, OSVer, hotfix data.
	$cs =  Get-CimInstance -Namespace "root\cimv2" -class win32_computersystem #-ComputerName $ComputerName
	$DomainRole = $cs.domainrole
	
	if ($DomainRole -ge 2)	
	{
		RunPS "Get-Net6to4Configuration"				# W8/WS2012, W8.1/WS2012R2	#fl
		RunPS "Get-NetDnsTransitionConfiguration"		# W8/WS2012, W8.1/WS2012R2	#fl		# server only
		RunPS "Get-NetDnsTransitionMonitoring"			# W8/WS2012, W8.1/WS2012R2	#fl 	# server only
	}
	else
	{
		"------------------------" 									| Out-File -FilePath $outputFile -append
		"Get-Net6to4Configuration"	| Out-File -FilePath $OutputFile -append
		"------------------------" 									| Out-File -FilePath $outputFile -append
		"Not running pscmdlet on non-server SKUs." | Out-File -FilePath $OutputFile -append
		"`n`n`n"	| Out-File -FilePath $OutputFile -append
		"---------------------------------" | Out-File -FilePath $outputFile -append
		"Get-NetDnsTransitionConfiguration" | Out-File -FilePath $OutputFile -append
		"---------------------------------" | Out-File -FilePath $outputFile -append
		"Not running pscmdlet on non-server SKUs."	| Out-File -FilePath $OutputFile -append
		"`n`n`n"	| Out-File -FilePath $OutputFile -append
		"------------------------------" | Out-File -FilePath $outputFile -append
		"Get-NetDnsTransitionMonitoring" | Out-File -FilePath $OutputFile -append
		"------------------------------" | Out-File -FilePath $outputFile -append
		"Not running pscmdlet on non-server SKUs."	| Out-File -FilePath $OutputFile -append
		"`n`n`n"	| Out-File -FilePath $OutputFile -append
	}
	RunPS "Get-NetIPHttpsConfiguration"					# W8/WS2012, W8.1/WS2012R2	#fl
	RunPS "Get-NetIPHttpsState"							# W8/WS2012, W8.1/WS2012R2	#fl
	RunPS "Get-NetIsatapConfiguration"					# W8/WS2012, W8.1/WS2012R2	#fl
	
	if ($cs.DomainRole -ge 2)	
	{
		RunPS "Get-NetNatTransitionConfiguration"		# W8/WS2012, W8.1/WS2012R2	#fl 	#server only
		RunPS "Get-NetNatTransitionMonitoring"		-ft	# W8/WS2012, W8.1/WS2012R2	#ft		#server only
	}
	else
	{
		"---------------------------------" 		| Out-File -FilePath $outputFile -append
		"Get-NetNatTransitionConfiguration"	| Out-File -FilePath $OutputFile -append
		"---------------------------------" 		| Out-File -FilePath $outputFile -append
		"Not running pscmdlet on non-server SKUs." | Out-File -FilePath $OutputFile -append
		"`n`n`n"	| Out-File -FilePath $OutputFile -append
		"------------------------------" 		| Out-File -FilePath $outputFile -append
		"Get-NetNatTransitionMonitoring"			| Out-File -FilePath $OutputFile -append
		"------------------------------" 		| Out-File -FilePath $outputFile -append
		"Not running pscmdlet on non-server SKUs."	| Out-File -FilePath $OutputFile -append
		"`n`n`n"	| Out-File -FilePath $OutputFile -append
	}
	RunPS "Get-NetTeredoConfiguration"					# W8/WS2012, W8.1/WS2012R2	#fl
	RunPS "Get-NetTeredoState"							# W8/WS2012, W8.1/WS2012R2	#fl

	CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP IPv6 Transition Technology Info" -SectionDescription $sectionDescription	
}

#V/WS2008+
if ($bn -gt 6000)
{
	"[info]: TCPIP-Component WV/WS2008+" | WriteTo-StdOut
	$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_netsh_info.TXT")

	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"TCPIP Netsh Commands"								| Out-File -FilePath $OutputFile -append
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"Overview"											| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"TCP Netsh Commands"								| Out-File -FilePath $OutputFile -append
	"   1. netsh int tcp show global"					| Out-File -FilePath $OutputFile -append
	"   2. netsh int tcp show heuristics"						| Out-File -FilePath $OutputFile -append
	"   3. netsh int tcp show chimneyapplications"		| Out-File -FilePath $OutputFile -append
	"   4. netsh int tcp show chimneyports"				| Out-File -FilePath $OutputFile -append
	"   5. netsh int tcp show chimneystats"				| Out-File -FilePath $OutputFile -append
	"   6. netsh int tcp show netdmastats"				| Out-File -FilePath $OutputFile -append
	"   7. netsh int tcp show rscstats"					| Out-File -FilePath $OutputFile -append
	"   8. netsh int tcp show security"					| Out-File -FilePath $OutputFile -append
	"   9. netsh int tcp show supplemental"				| Out-File -FilePath $OutputFile -append
	"  10. netsh int tcp show supplementalports"		| Out-File -FilePath $OutputFile -append
	"  11. netsh int tcp show supplementalsubnets"		| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"IPv4 Netsh Commands"								| Out-File -FilePath $OutputFile -append
	"   1. netsh int show int"							| Out-File -FilePath $OutputFile -append
	"   2. netsh int ipv4 show int"						| Out-File -FilePath $OutputFile -append
	"   3. netsh int ipv4 show addresses"				| Out-File -FilePath $OutputFile -append
	"   4. netsh int ipv4 show ipaddresses"				| Out-File -FilePath $OutputFile -append
	"   5. netsh int ipv4 show compartments"			| Out-File -FilePath $OutputFile -append
	"   6. netsh int ipv4 show dnsservers"				| Out-File -FilePath $OutputFile -append
	"   7. netsh int ipv4 show winsservers"				| Out-File -FilePath $OutputFile -append
	"   8. netsh int ipv4 show dynamicportrange tcp"	| Out-File -FilePath $OutputFile -append
	"   9. netsh int ipv4 show dynamicportrange udp"	| Out-File -FilePath $OutputFile -append
	"  10. netsh int ipv4 show global"					| Out-File -FilePath $OutputFile -append
	"  11. netsh int ipv4 show icmpstats"				| Out-File -FilePath $OutputFile -append
	"  12. netsh int ipv4 show ipstats"					| Out-File -FilePath $OutputFile -append
	"  13. netsh int ipv4 show joins"					| Out-File -FilePath $OutputFile -append
	"  14. netsh int ipv4 show offload"					| Out-File -FilePath $OutputFile -append
	"  15. netsh int ipv4 show route"					| Out-File -FilePath $OutputFile -append
	"  16. netsh int ipv4 show subint"					| Out-File -FilePath $OutputFile -append
	"  17. netsh int ipv4 show tcpconnections"			| Out-File -FilePath $OutputFile -append
	"  18. netsh int ipv4 show tcpstats"				| Out-File -FilePath $OutputFile -append
	"  19. netsh int ipv4 show udpconnections"			| Out-File -FilePath $OutputFile -append
	"  20. netsh int ipv4 show udpstats"				| Out-File -FilePath $OutputFile -append
	"  21. netsh int ipv4 show destinationcache"		| Out-File -FilePath $OutputFile -append
	"  22. netsh int ipv4 show ipnettomedia"			| Out-File -FilePath $OutputFile -append
	"  23. netsh int ipv4 show neighbors"				| Out-File -FilePath $OutputFile -append
	"  24. netsh int ipv4 show excludedportrange TCP"	| Out-File -FilePath $OutputFile -append
	"  25. netsh int ipv4 show excludedportrange UDP"	| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"IPv6 Netsh Commands"								| Out-File -FilePath $OutputFile -append
	"   1. netsh int show int"							| Out-File -FilePath $OutputFile -append	
	"   2. netsh int ipv6 show int"						| Out-File -FilePath $OutputFile -append
	"   3. netsh int ipv6 show addresses"				| Out-File -FilePath $OutputFile -append
	"   4. netsh int ipv6 show compartments"			| Out-File -FilePath $OutputFile -append
	"   5. netsh int ipv6 show destinationcache"		| Out-File -FilePath $OutputFile -append
	"   6. netsh int ipv6 show dnsservers"				| Out-File -FilePath $OutputFile -append
	"   7. netsh int ipv6 show dynamicportrange tcp"	| Out-File -FilePath $OutputFile -append
	"   8. netsh int ipv6 show dynamicportrange udp"	| Out-File -FilePath $OutputFile -append
	"   9. netsh int ipv6 show global"					| Out-File -FilePath $OutputFile -append
	"  10. netsh int ipv6 show ipstats"					| Out-File -FilePath $OutputFile -append
	"  11. netsh int ipv6 show joins"					| Out-File -FilePath $OutputFile -append
	"  12. netsh int ipv6 show neighbors"				| Out-File -FilePath $OutputFile -append
	"  13. netsh int ipv6 show offload"					| Out-File -FilePath $OutputFile -append
	"  14. netsh int ipv6 show potentialrouters"		| Out-File -FilePath $OutputFile -append
	"  15. netsh int ipv6 show prefixpolicies"			| Out-File -FilePath $OutputFile -append
	"  16. netsh int ipv6 show privacy"					| Out-File -FilePath $OutputFile -append
	"  17. netsh int ipv6 show route"					| Out-File -FilePath $OutputFile -append
	"  18. netsh int ipv6 show siteprefixes"			| Out-File -FilePath $OutputFile -append
	"  19. netsh int ipv6 show subint"					| Out-File -FilePath $OutputFile -append
	"  20. netsh int ipv6 show tcpstats"				| Out-File -FilePath $OutputFile -append
	"  21. netsh int ipv6 show teredo"					| Out-File -FilePath $OutputFile -append
	"  22. netsh int ipv6 show udpstats"				| Out-File -FilePath $OutputFile -append
	"  23. netsh int ipv6 show excludedportrange TCP"	| Out-File -FilePath $OutputFile -append
	"  24. netsh int ipv6 show excludedportrange UDP"	| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"IPv6 Transition Technologies"						| Out-File -FilePath $OutputFile -append
	"   1. netsh int ipv6 show int"						| Out-File -FilePath $OutputFile -append
	"   2. netsh int 6to4 show int"						| Out-File -FilePath $OutputFile -append
	"   3. netsh int 6to4 show relay"					| Out-File -FilePath $OutputFile -append
	"   4. netsh int 6to4 show routing"					| Out-File -FilePath $OutputFile -append
	"   5. netsh int 6to4 show state"					| Out-File -FilePath $OutputFile -append
	"   6. netsh int httpstunnel show interfaces"		| Out-File -FilePath $OutputFile -append
	"   7. netsh int httpstunnel show statistics"		| Out-File -FilePath $OutputFile -append
	"   8. netsh int isatap show router"				| Out-File -FilePath $OutputFile -append
	"   9. netsh int isatap show state"					| Out-File -FilePath $OutputFile -append
	"  10. netsh int teredo show state"					| Out-File -FilePath $OutputFile -append
	"  11. netsh int ipv6 show int level=verbose"		| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"NetIO Netsh Commands"								| Out-File -FilePath $OutputFile -append
	"   1. netio show bindingfilters"					| Out-File -FilePath $OutputFile -append
	"-" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"PortProxy"	| Out-File -FilePath $OutputFile -append
	"   1. netsh int portproxy show all"	| Out-File -FilePath $OutputFile -append
	"=" * ($borderLen)									| Out-File -FilePath $outputFile -append
	"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append
	
	Heading "TCP Netsh Commands"
	RunNetCmd "netsh" "int tcp show global"
	RunNetCmd "netsh" "int tcp show heuristics"
	RunNetCmd "netsh" "int tcp show chimneyapplications"
	RunNetCmd "netsh" "int tcp show chimneyports"
	RunNetCmd "netsh" "int tcp show chimneystats"
	RunNetCmd "netsh" "int tcp show netdmastats"
	RunNetCmd "netsh" "int tcp show rscstats"
	RunNetCmd "netsh" "int tcp show security"
	RunNetCmd "netsh" "int tcp show supplemental"
	RunNetCmd "netsh" "int tcp show supplementalports"
	RunNetCmd "netsh" "int tcp show supplementalsubnets"

	Heading "IPv4 Netsh Commands"
	RunNetCmd "netsh" "int show int"
	RunNetCmd "netsh" "int ipv4 show int"
	RunNetCmd "netsh" "int ipv4 show addresses"
	RunNetCmd "netsh" "int ipv4 show ipaddresses"
	RunNetCmd "netsh" "int ipv4 show compartments"
	RunNetCmd "netsh" "int ipv4 show dnsservers"
	RunNetCmd "netsh" "int ipv4 show winsservers"
	RunNetCmd "netsh" "int ipv4 show dynamicportrange tcp"
	RunNetCmd "netsh" "int ipv4 show dynamicportrange udp"
	RunNetCmd "netsh" "int ipv4 show global"
	RunNetCmd "netsh" "int ipv4 show icmpstats"
	RunNetCmd "netsh" "int ipv4 show ipstats"
	RunNetCmd "netsh" "int ipv4 show joins"
	RunNetCmd "netsh" "int ipv4 show offload"
	RunNetCmd "netsh" "int ipv4 show route"
	RunNetCmd "netsh" "int ipv4 show subint"
	RunNetCmd "netsh" "int ipv4 show tcpconnections"
	RunNetCmd "netsh" "int ipv4 show tcpstats"
	RunNetCmd "netsh" "int ipv4 show udpconnections"
	RunNetCmd "netsh" "int ipv4 show udpstats"
	RunNetCmd "netsh" "int ipv4 show destinationcache"
	RunNetCmd "netsh" "int ipv4 show ipnettomedia"
	RunNetCmd "netsh" "int ipv4 show neighbors"
	RunNetCmd "netsh" "int ipv4 show excludedportrange TCP"
	RunNetCmd "netsh" "int ipv4 show excludedportrange UDP"

	Heading "IPv6 Netsh Commands"
	RunNetCmd "netsh" "int show int"
	RunNetCmd "netsh" "int ipv6 show int"
	RunNetCmd "netsh" "int ipv6 show addresses"
	RunNetCmd "netsh" "int ipv6 show compartments"
	RunNetCmd "netsh" "int ipv6 show destinationcache"
	RunNetCmd "netsh" "int ipv6 show dnsservers"
	RunNetCmd "netsh" "int ipv6 show dynamicportrange tcp"
	RunNetCmd "netsh" "int ipv6 show dynamicportrange udp"
	RunNetCmd "netsh" "int ipv6 show global"
	RunNetCmd "netsh" "int ipv6 show ipstats"
	RunNetCmd "netsh" "int ipv6 show joins"
	RunNetCmd "netsh" "int ipv6 show neighbors"
	RunNetCmd "netsh" "int ipv6 show offload"
	RunNetCmd "netsh" "int ipv6 show potentialrouters"
	RunNetCmd "netsh" "int ipv6 show prefixpolicies"
	RunNetCmd "netsh" "int ipv6 show privacy"
	RunNetCmd "netsh" "int ipv6 show route"
	RunNetCmd "netsh" "int ipv6 show siteprefixes"
	RunNetCmd "netsh" "int ipv6 show siteprefixes"
	RunNetCmd "netsh" "int ipv6 show subint"
	RunNetCmd "netsh" "int ipv6 show tcpstats"
	RunNetCmd "netsh" "int ipv6 show teredo"
	RunNetCmd "netsh" "int ipv6 show udpstats"
	RunNetCmd "netsh" "int ipv6 show excludedportrange TCP"
	RunNetCmd "netsh" "int ipv6 show excludedportrange UDP"
	
	Heading "IPv6 Transition Technologies"
	RunNetCmd "netsh" "int ipv6 show int"
	RunNetCmd "netsh" "int 6to4 show int"
	RunNetCmd "netsh" "int 6to4 show relay"
	RunNetCmd "netsh" "int 6to4 show routing"
	RunNetCmd "netsh" "int 6to4 show state"
	RunNetCmd "netsh" "int httpstunnel show interfaces"
	RunNetCmd "netsh" "int httpstunnel show statistics"
	RunNetCmd "netsh int isatap show router"
	RunNetCmd "netsh int isatap show state"	
	RunNetCmd "netsh int teredo show state"	
	RunNetCmd "netsh" "int ipv6 show int level=verbose"

	Heading "NetIO Netsh Commands"
	RunNetCmd "netsh" "netio show bindingfilters"

	Heading "PortProxy"
	RunNetCmd "netsh" "int portproxy show all"
	
	CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP netsh output" -SectionDescription $sectionDescription

	#----------Iphlpsvc EventLog
	#----------WLAN Autoconfig EventLog
	#Iphlpsvc
	$EventLogNames = @()
	$EventLogNames += "Microsoft-Windows-Iphlpsvc/Operational"
	$EventLogNames += "Microsoft-Windows-WLAN-AutoConfig/Operational"

	$Prefix = ""
	$Suffix = "_evt_"
	.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix

}
else # XP/WS2003
{
	"[info]: TCPIP-Component XP/WS2003+" | WriteTo-StdOut
	$outputFile = join-path $pwd.path ($ComputerName + "_TCPIP_netsh_info.TXT")
	
	#----------Netsh for IP (XP/W2003)
	"`n`n`n`n`n" + "=" * (50) + "`r`n[NETSH INT IP]`r`n" + "=" * (50) | Out-File -FilePath $outputFile -Append
	"`n`n"
	"`n" + "-" * (50) + "`r`n[netsh int ipv4 show output]`r`n" + "-" * (50) | Out-File -FilePath $outputFile -Append
	RunNetCmd "netsh" "int show int"
	RunNetCmd "netsh" "int ip show int"
	RunNetCmd "netsh" "int ip show address"
	RunNetCmd "netsh" "int ip show config"
	RunNetCmd "netsh" "int ip show dns"
	RunNetCmd "netsh" "int ip show joins"
	RunNetCmd "netsh" "int ip show offload"
	RunNetCmd "netsh" "int ip show wins"

	# If RRAS is running, run the following commands
	if ((Get-Service "remoteaccess").Status -eq 'Running')
	{
		RunNetCmd "netsh" "int ip show icmp"
		RunNetCmd "netsh" "int ip show interface"
		RunNetCmd "netsh" "int ip show ipaddress"
		RunNetCmd "netsh" "int ip show ipnet"
		RunNetCmd "netsh" "int ip show ipstats"
		RunNetCmd "netsh" "int ip show tcpconn"
		RunNetCmd "netsh" "int ip show tcpstats"
		RunNetCmd "netsh" "int ip show udpconn"
		RunNetCmd "netsh" "int ip show udpstats"
	}
	CollectFiles -filesToCollect $outputFile -fileDescription "TCPIP netsh output" -SectionDescription $sectionDescription
}

"[info]:TCPIP-Component:END" | WriteTo-StdOut



# SIG # Begin signature block
# MIInlgYJKoZIhvcNAQcCoIInhzCCJ4MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBtRdj8JQDW8Yz5
# EIkqgNOjmi+GIFIU5NRXwOp2Lc9yFqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXYwghlyAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIP4wmqkqbbY1aBsofebICMCg
# sM3MDfFJJmrujYnTPjVHMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQApn/c35t6mG+5+Ibl3qimEECdswrKhLFmhzAMrOAGvEwSrkkYSDlRF
# DICLjHTzBv4C6e+++sG8vUI0cO4fbk+YEjYbfpSst98lezLZ28BkzEVGDvSY40nO
# V/tsmEUyefqrpRNBTRJdJID7bK/5mqtCiygdr4ssfKagO9vhta9fMZs4eIG0qf2k
# 8TtdhLcY8aKDkBb440cvy8WNqHELB4lbxj/tQhErQFGG0ouXc4ds6j8lwyfwbTeo
# pF0Jl+fGgQa2ZJ1G7YEgLuA3FH0FSsRPJq5PQbhnnM2woBjGj4eh1mrqWYRCLDiS
# div1voH1QpkvePcgaLh8Lp4NlrEw1GWioYIW/jCCFvoGCisGAQQBgjcDAwExghbq
# MIIW5gYJKoZIhvcNAQcCoIIW1zCCFtMCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIGnz96CaH8adrtEbG559Fagh8COA4x0k+mNbnFOixVRLAgZjbUvl
# 7uoYEzIwMjIxMTExMTcxNTA3LjEyOVowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhBODIt
# RTM0Ri05RERBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVTCCBwwwggT0oAMCAQICEzMAAAHC+n2HDlRTRyQAAQAAAcIwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkw
# MTI4WhcNMjQwMjAyMTkwMTI4WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046OEE4Mi1FMzRGLTlEREExJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC18Qm88o5IWfel62n3Byjb39SgmYMPIemaalGu5FVY
# EXfsHLSe+uzNJw5X8r4u8dZZYLhL1yZ7g/rcSY2HFM3+TYKA+ci3+wN6nIAJKTJr
# i6SpzWxPYj7RSh3TGPL0rb6MsfxQ1v28zfIf+8JidolJSqC2plSXLzamBhIHq0N5
# khhxCg6FMj4zUeFHGbG3xFoApmcOdeAt2SGchgMmtGRAGkiBqG0TG1O46SZWnbLx
# gKgU9pSFQPYlPqE+IMPuoPsDvs8ukXMPZAWY17NPxoceEqxUG4kws9dk7WTXiPT+
# TrwNka2zVgG0Z6Bc2TK+RdKAILG3dDxYXyVoFdsOeEdoMsGEI4FplDyOpwVTHxkl
# JdDyxu8SeZYVmaAz3cH0/8lMVMXqoFUUwN39XQ8FtFALZNy1kfht+/6PJa9k54XP
# nKW08tHFSoGO/gochomAGFTae0zDgfSGmbgHuzosvGROyMuxqOMIkjw+IqL+Y8pg
# RF2ZHK8Uvz9gD892qQjBZaDZOPm3K60YW19VH7oZtwJWGKOPLuXui3Fr/BhVJfro
# ujRqVpOGNz66iNXAfimwv4DWq9tYMH2zCgqVrbR5m5vDt/MKkV7qqz74bTWyy3VJ
# oDQYabO5AJ3ThR7V4fcMVENk+w35pa8DjnlCZ31kksZe6qcGjgFfBXF1Zk2Pr5vg
# /wIDAQABo4IBNjCCATIwHQYDVR0OBBYEFEaxiHvpXjVpQJFcT1a8P76wh8ZqMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBABF27d0KRwss99onetHUzsP2NYe+d59+SZe8Ugm2rEcZYzWioCH5urGkjsdn
# PYx42GHUKj4T0Bps6CP3hKnWx5fF1YhIn2VEZoABbMDzvdpMHf9KPC4apupC4C9T
# MEUI7jRQn1qelq+Smr/ScOotvtcjkf6eyaMXK7zKpfU8yadvizV9tz8XfSKNoBLO
# on6nmuuBhbAOgyKEzlsXRjSuJeKHATt5NKFqT8TBzFGYbeH45P47Hwo4u4urAUWX
# WyJN5AKn5hK3gnW1ZdqmoYkOUJtivdHPz6vJNLwKhkBTS9IcI5ByrXZOHzWntCUd
# m/1xNEOFmDZNXKDwbHdfqaSk05dvnpBSiEjdKff1ZAnCMOfvgnRpVgxqLyZjr9Y6
# 6sowoS5I2EKJ6LRMrry85juwfRcQFadFJtV595K0Oj3hQhRVPB3YeYER9jyR+vKn
# dGUD0DgW99S8McxoX0G29T+krp3UJ0obb1XRY3e5XN9gRMmhGmMtgUarQy8rpBUy
# a43GTdsJF+PVpxJZ57XhQaOCXFbC/I580l7enFw0U53weHKn13gCVAZUs2i1oW+i
# mA8t4nBRPd2XlVoACEzC8gWarCx99DL3eaiuumtye/vivmDd6MLf01ikUSjL6qbM
# tbWMVrVpcTZdv8pnDbJrCqV1KnQe7hUSSMbEU1z4DO0hRbCZMIIHcTCCBVmgAwIB
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
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAswwggI1AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjo4QTgyLUUzNEYtOUREQTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAynU3VUuE8y9ZcShl+YXhqlmWdFSg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOcYcyAwIhgPMjAyMjExMTExNTA3MTJaGA8yMDIyMTExMjE1MDcxMlow
# dTA7BgorBgEEAYRZCgQBMS0wKzAKAgUA5xhzIAIBADAIAgEAAgMBd/4wBwIBAAIC
# Eb0wCgIFAOcZxKACAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAK
# MAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQCEQdJBQUSF
# p2pnIZiNWv682ft9lo+dgGuGUPrZE+tmNlvkVynXLva8KxHFIf1QQRkMt+CQmy9i
# jfaL8iGj2byWAi1FBIWFDmYQTJbFhiNP9aJBAaGU/pAXIg5KvMPpDGf84o4xsmmv
# iQ0YJr9FzogUkgap/XbMox68JZtCA+iCajGCBA0wggQJAgEBMIGTMHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABwvp9hw5UU0ckAAEAAAHCMA0GCWCG
# SAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZI
# hvcNAQkEMSIEIBCXR+7aJzxzqjrLAez7GSm6UyAs5AVDJTtlRl2BTaIkMIH6Bgsq
# hkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgypNgW8fpsMV57r0F5beUuiEVOVe4Bdma
# O+e28mGDUBYwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAIT
# MwAAAcL6fYcOVFNHJAABAAABwjAiBCBkChwVmiwacUZfrCTezt6BJyUFQEYcUP6/
# J+MAnxE46jANBgkqhkiG9w0BAQsFAASCAgAb+Bxpcp6cx02RsfUioiO7aTpLAH0k
# wQBmsLa6Ug4W/RjtEBU94wYqMxklj8md7HZQG9mI2EqZELoVjMhrS99uuzah+lAY
# jyy5jHhX2eFFOwZCLgPssNKfSjBDrbqS+7N6FD9o3rBAGXn9OvgWcujpnF0dopPy
# My739jSQRNglrAD1FFRXj3vKJmHwqsxLP4txy7k6YM9ThzVkJfzG2XmJOGSbKbtj
# dBC1+McKWKyshmSQ1bLG5yMhSkKtriynOZVQsgGe5Z5GOykfKMXwqazm8irlpxwc
# wQNsc714lbhCbJPVpWL6q/omnBV5cPin4akBUrg0pxPx42QXZm0Eoy+yqkTVvipM
# LeSQAxq8wv/hH5M8aklwwmnzhEOHO1ANcjl2HvgYQVKr4Ca3EtC3mpChmCoiNIs4
# 7U+5A75Ului6Tx58kMXphDnFFmIh7svDdVw+3GGWe8jMW7Lj63row0J3tctxS9I0
# EyDmv9Qb2IZVraTXS62txiniZV8fhyZkeeYcUEzb+W76AwHKenyma8dGNVohnjmn
# quqO4+EGerF4a8dtVEHyU11iL44w56dP+S8GTtSVtpz91YVJ7MUFBZ6VlrZUz91j
# taBq5xmcaL0AGATP7tr+DfEDl1itd4LGhGmx8iCkjoaDm+6W2dtY6niopmj9YqXq
# C8cRJlUFcBMWAA==
# SIG # End signature block
