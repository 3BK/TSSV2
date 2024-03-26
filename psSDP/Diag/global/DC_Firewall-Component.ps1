#************************************************
# DC_Firewall-Component.ps1
# Version 1.0
# Version 1.1: Altered the runPS function correctly a column width issue.
# Date: 2009, 2014, 2020/waltere: add NetworkIsolation
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: Collects information about the Windows Firewall.
# Called from: Main Networking Diag
#*******************************************************

param(
		[switch]$before,
		[switch]$after
	)

Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
		 # later use return to return the exception message to an object:   return $Script:ExceptionMessage
	}

Import-LocalizedData -BindingVariable ScriptVariable
Write-DiagProgress -Activity $ScriptVariable.ID_CTSFirewall -Status $ScriptVariable.ID_CTSFirewallDescription

# detect OS version and SKU
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber

function RunNetSH ([string]$NetSHCommandToExecute=""){
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSFirewall -Status "netsh $NetSHCommandToExecute"
	$NetSHCommandToExecuteLength = $NetSHCommandToExecute.Length + 6
	"-" * ($NetSHCommandToExecuteLength)	| Out-File -FilePath $outputFile -append
	"netsh $NetSHCommandToExecute"			| Out-File -FilePath $outputFile -append
	"-" * ($NetSHCommandToExecuteLength)	| Out-File -FilePath $outputFile -append
	$CommandToExecute = "cmd.exe /c netsh.exe " + $NetSHCommandToExecute + " >> $outputFile "
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
	"`n`n`n"	| Out-File -FilePath $OutputFile -append
}

function RunPS ([string]$RunPScmd="", [switch]$ft){
	$RunPScmdLength = $RunPScmd.Length
	"-" * ($RunPScmdLength)		| Out-File -FilePath $OutputFile -append
	"$RunPScmd"  				| Out-File -FilePath $OutputFile -append
	"-" * ($RunPScmdLength)  	| Out-File -FilePath $OutputFile -append
	
	if ($ft)	{
		# This format-table expression is useful to make sure that wide ft output works correctly
		Invoke-Expression $RunPScmd	|format-table -autosize -outvariable $FormatTableTempVar | Out-File -FilePath $outputFile -Width 500 -append
	}
	else	{
		Invoke-Expression $RunPScmd	| Out-File -FilePath $OutputFile -append
	}
	"`n`n`n"	| Out-File -FilePath $OutputFile -append
}

$sectionDescription = "Firewall"

#Handle suffix of file name
	if ($before){
		$suffix = "_BEFORE"
	}
	elseif ($after){
		$suffix = "_AFTER"
	}
	else{
		$suffix = ""
	}

#W8/WS2012+
if ($bn -gt 9000){	
	"[info]: Firewall-Component W8/WS2012+"  | WriteTo-StdOut 

	$outputFile= $Computername + "_Firewall_info_pscmdlets" + $suffix + ".TXT"
	"========================================"			| Out-File -FilePath $OutputFile -append
	"Firewall Powershell Cmdlets"						| Out-File -FilePath $OutputFile -append
	"========================================"			| Out-File -FilePath $OutputFile -append
	"Overview"											| Out-File -FilePath $OutputFile -append
	"----------------------------------------"			| Out-File -FilePath $OutputFile -append
	"Firewall Powershell Cmdlets"						| Out-File -FilePath $OutputFile -append
	"   1. Show-NetIPsecRule -PolicyStore ActiveStore"	| Out-File -FilePath $OutputFile -append
	"   2. Get-NetIPsecMainModeSA"						| Out-File -FilePath $OutputFile -append
	"   3. Get-NetIPsecQuickModeSA"						| Out-File -FilePath $OutputFile -append
	"   4. Get-NetFirewallProfile"						| Out-File -FilePath $OutputFile -append
	"   5. Get-NetFirewallRule"							| Out-File -FilePath $OutputFile -append
	"   6. Show-NetFirewallRule"						| Out-File -FilePath $OutputFile -append
	"========================================"			| Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append
	"========================================"			| Out-File -FilePath $OutputFile -append
	"Firewall Powershell Cmdlets"						| Out-File -FilePath $OutputFile -append
	"========================================"			| Out-File -FilePath $OutputFile -append
	runPS "Show-NetIPsecRule -PolicyStore ActiveStore"		# W8/WS2012, W8.1/WS2012R2	# fl
	runPS "Get-NetIPsecMainModeSA"							# W8/WS2012, W8.1/WS2012R2	# fl
	runPS "Get-NetIPsecQuickModeSA"							# W8/WS2012, W8.1/WS2012R2	# fl				
	runPS "Get-NetFirewallProfile"							# W8/WS2012, W8.1/WS2012R2	# fl
	runPS "Get-NetFirewallRule"								# W8/WS2012, W8.1/WS2012R2	# fl
	runPS "Show-NetFirewallRule"							# W8/WS2012, W8.1/WS2012R2	# fl

	CollectFiles -filesToCollect $outputFile -fileDescription "Firewall Information PS cmdlets" -SectionDescription $sectionDescription
}

#WV/WS2008+
if ($bn -gt 6000){
	"[info]: Firewall-Component WV/WS2008+"  | WriteTo-StdOut 

	#----------Netsh
	$outputFile = $ComputerName + "_Firewall_netsh_advfirewall" + $suffix + ".TXT"
	"========================================"			| Out-File -FilePath $OutputFile -append
	"Firewall Netsh AdvFirewall Output"					| Out-File -FilePath $OutputFile -append
	"========================================"			| Out-File -FilePath $OutputFile -append
	"Overview"											| Out-File -FilePath $OutputFile -append
	"----------------------------------------"			| Out-File -FilePath $OutputFile -append
	"Firewall Netsh AdvFirewall Output"					| Out-File -FilePath $OutputFile -append
	"   1. netsh advfirewall show allprofiles"			| Out-File -FilePath $OutputFile -append
	"   2. netsh advfirewall show allprofiles state"	| Out-File -FilePath $OutputFile -append
	"   3. netsh advfirewall show currentprofile"		| Out-File -FilePath $OutputFile -append
	"   4. netsh advfirewall show domainprofile"		| Out-File -FilePath $OutputFile -append
	"   5. netsh advfirewall show global"				| Out-File -FilePath $OutputFile -append
	"   6. netsh advfirewall show privateprofile"		| Out-File -FilePath $OutputFile -append
	"   7. netsh advfirewall show publicprofile"		| Out-File -FilePath $OutputFile -append
	"   8. netsh advfirewall show store"				| Out-File -FilePath $OutputFile -append
	"========================================"			| Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append
	"========================================"			| Out-File -FilePath $OutputFile -append
	"Firewall Netsh AdvFirewall Output"					| Out-File -FilePath $OutputFile -append
	"========================================"			| Out-File -FilePath $OutputFile -append
	RunNetSH -NetSHCommandToExecute "advfirewall show allprofiles"
	RunNetSH -NetSHCommandToExecute "advfirewall show allprofiles state"
	RunNetSH -NetSHCommandToExecute "advfirewall show currentprofile"
	RunNetSH -NetSHCommandToExecute "advfirewall show domainprofile"
	RunNetSH -NetSHCommandToExecute "advfirewall show global"
	RunNetSH -NetSHCommandToExecute "advfirewall show privateprofile"
	RunNetSH -NetSHCommandToExecute "advfirewall show publicprofile"
	RunNetSH -NetSHCommandToExecute "advfirewall show store"
	CollectFiles -filesToCollect $outputFile -fileDescription "Firewall Advfirewall" -SectionDescription $sectionDescription

	#-----WFAS export
	$filesToCollect = $ComputerName + "_Firewall_netsh_advfirewall-export" + $suffix + ".wfw"
	$commandToRun = "netsh advfirewall export " +  $filesToCollect
	RunCMD -CommandToRun $commandToRun -filesToCollect $filesToCollect -fileDescription "Firewall Export" -sectionDescription $sectionDescription 

	#-----WFAS ConSec rules (all)
	$outputFile = $ComputerName + "_Firewall_netsh_advfirewall-consec-rules" + $suffix + ".TXT"
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh AdvFirewall ConSec Rules Output"					| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Overview"															| Out-File -FilePath $OutputFile -append
	"----------------------------------------------------"				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh AdvFirewall ConSec Rules Output"					| Out-File -FilePath $OutputFile -append
	"   1. netsh advfirewall consec show rule all any dynamic verbose"	| Out-File -FilePath $OutputFile -append
	"   2. netsh advfirewall consec show rule all any static verbose"	| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh AdvFirewall ConSec Rules Output"					| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	# 3/5/2013: Through feedback from Markus Sarcletti, this command has been removed because it is an invalid command:
	#   "advfirewall consec show rule name=all"
	RunNetSH -NetSHCommandToExecute "advfirewall consec show rule all any dynamic verbose"
	RunNetSH -NetSHCommandToExecute "advfirewall consec show rule all any static verbose"
	CollectFiles -filesToCollect $outputFile -fileDescription "Advfirewall ConSec Rules" -SectionDescription $sectionDescription

if ($Global:skipHang -ne $true) {
	"__ value of Switch skipHang: $Global:skipHang  - 'True' will suppress some WFAS output `n`n"        | WriteTo-StdOut
	#-----WFAS ConSec rules (active)
	# 3/5/2013: Through feedback from Markus Sarcletti, adding active ConSec rules
	$outputFile = $ComputerName + "_Firewall_netsh_advfirewall-consec-rules-active" + $suffix + ".TXT"
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh AdvFirewall ConSec Rules (ACTIVE)"					| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Overview"															| Out-File -FilePath $OutputFile -append
	"----------------------------------------------------"				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh AdvFirewall ConSec Rules (ACTIVE)"					| Out-File -FilePath $OutputFile -append
	"   1. netsh advfirewall monitor show consec verbose"				| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh AdvFirewall ConSec Rules (ACTIVE)"					| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	RunNetSH -NetSHCommandToExecute "advfirewall monitor show consec verbose"
	CollectFiles -filesToCollect $outputFile -fileDescription "Advfirewall ConSec Rules" -SectionDescription $sectionDescription

	#-----WFAS Firewall rules (all)
	$outputFile = $ComputerName + "_Firewall_netsh_advfirewall-firewall-rules" + $suffix + ".TXT"
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh AdvFirewall Firewall Rules"							| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Overview"															| Out-File -FilePath $OutputFile -append
	"----------------------------------------------------"				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh AdvFirewall Firewall Rules"							| Out-File -FilePath $OutputFile -append
	"   1. netsh advfirewall monitor show show rule name=all"			| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh AdvFirewall Firewall Rules (all)"					| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	RunNetSH -NetSHCommandToExecute "advfirewall firewall show rule name=all"
	CollectFiles -filesToCollect $outputFile -fileDescription "Advfirewall Firewall Rules" -SectionDescription $sectionDescription

	#-----WFAS Firewall rules all (active)
	# 3/5/2013: Through feedback from Markus Sarcletti, adding active Firewall Rules
	$outputFile = $ComputerName + "_Firewall_netsh_advfirewall-firewall-rules-active" + $suffix + ".TXT"
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh AdvFirewall Firewall Rules (ACTIVE)"				| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Overview"															| Out-File -FilePath $OutputFile -append
	"----------------------------------------------------"				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh AdvFirewall Firewall Rules (ACTIVE)"				| Out-File -FilePath $OutputFile -append
	"   1. netsh advfirewall monitor show firewall verbose"				| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh AdvFirewall Firewall Rules (ACTIVE)"				| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	RunNetSH -NetSHCommandToExecute "advfirewall monitor show firewall verbose"
	CollectFiles -filesToCollect $outputFile -fileDescription "Advfirewall Firewall Rules" -SectionDescription $sectionDescription	
}
	#-----Netsh WFP	

	#-----Netsh WFP show netevents file=
	$outputFile = $ComputerName + "_Firewall_netsh_wfp-show-netevents" + $suffix + ".XML"
	$commandToRun = "netsh wfp show netevents file= " +  $outputFile
	RunCMD -CommandToRun $commandToRun -filesToCollect $outputFile -fileDescription "Netsh WFP Show Netevents" -sectionDescription $sectionDescription 
	
	#-----Netsh WFP show BoottimePolicy file=
	$outputFile = $ComputerName + "_Firewall_netsh_wfp-show-boottimepolicy" + $suffix + ".XML"
	$commandToRun = "netsh wfp show boottimepolicy file= " +  $outputFile
	RunCMD -CommandToRun $commandToRun -filesToCollect $outputFile -fileDescription "Netsh WFP Show BootTimePolicy" -sectionDescription $sectionDescription 

	#-----Netsh wfp show Filters file=
	$outputFile = $ComputerName + "_Firewall_netsh_wfp-show-filters" + $suffix + ".XML"
	$commandToRun = "netsh wfp show filters file= " +  $outputFile
	RunCMD -CommandToRun $commandToRun -filesToCollect $outputFile -fileDescription "Netsh WFP Show Filters" -sectionDescription $sectionDescription 
	
	#-----Netsh wfp show Options optionsfor=keywords
	$outputFile = $ComputerName + "_Firewall_netsh_wfp-show-options" + $suffix + ".TXT"
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh WFP Show Options"									| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Overview"															| Out-File -FilePath $OutputFile -append
	"----------------------------------------------------"				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh WFP Show Options"									| Out-File -FilePath $OutputFile -append
	"   1. netsh wfp show options optionsfor=keywords"					| Out-File -FilePath $OutputFile -append
	"   2. netsh wfp show options optionsfor=netevents"					| Out-File -FilePath $OutputFile -append
	"   3. netsh wfp show options optionsfor=txnwatchdog"				| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh WFP Show Options"									| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	RunNetSH -NetSHCommandToExecute "wfp show options optionsfor=keywords"
	RunNetSH -NetSHCommandToExecute "wfp show options optionsfor=netevents"
	RunNetSH -NetSHCommandToExecute "wfp show options optionsfor=txnwatchdog"
	CollectFiles -filesToCollect $outputFile -fileDescription "Netsh WFP Show Options" -SectionDescription $sectionDescription

	#-----Netsh wfp show Security netevents
	$outputFile = $ComputerName + "_Firewall_netsh_wfp-show-security-netevents" + $suffix + ".TXT"
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh WFP Show Security Netevents"						| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Overview"															| Out-File -FilePath $OutputFile -append
	"----------------------------------------------------"				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh WFP Show Security Netevents"						| Out-File -FilePath $OutputFile -append
	"   1. netsh wfp show security netevents"							| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh WFP Show Security Netevents"						| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	RunNetSH -NetSHCommandToExecute "wfp show security netevents"
	"`n`n`n"	| Out-File -FilePath $OutputFile -append
	CollectFiles -filesToCollect $outputFile -fileDescription "Netsh WFP Show Security NetEvents" -SectionDescription $sectionDescription

	#-----Netsh wfp show State file=
	$outputFile = $ComputerName + "_Firewall_netsh_wfp-show-state" + $suffix + ".XML"
	$commandToRun = "netsh wfp show state file= " +  $outputFile
	RunCMD -CommandToRun $commandToRun -filesToCollect $outputFile -fileDescription "Netsh WFP Show State" -sectionDescription $sectionDescription 
	
	#-----Netsh wfp show Sysports file=
	$outputFile = $ComputerName + "_Firewall_netsh_wfp-show-sysports" + $suffix + ".XML"
	$commandToRun = "netsh wfp show sysports file= " +  $outputFile
	RunCMD -CommandToRun $commandToRun -filesToCollect $outputFile -fileDescription "Netsh WFP Show Sysports" -sectionDescription $sectionDescription 

	#----------Netsh
	$outputFile = $ComputerName + "_Firewall_netsh_firewall.TXT"	
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh Firewall"											| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"Overview"															| Out-File -FilePath $OutputFile -append
	"----------------------------------------------------"				| Out-File -FilePath $OutputFile -append
	"Firewall Netsh Firewall"											| Out-File -FilePath $OutputFile -append
	"   1. netsh firewall show allowedprogram"							| Out-File -FilePath $OutputFile -append
	"   2. netsh firewall show config"									| Out-File -FilePath $OutputFile -append
	"   3. netsh firewall show currentprofile"							| Out-File -FilePath $OutputFile -append
	"   4. netsh firewall show icmpsetting"								| Out-File -FilePath $OutputFile -append
	"   5. netsh firewall show logging"									| Out-File -FilePath $OutputFile -append
	"   6. netsh firewall show multicastbroadcastresponse"				| Out-File -FilePath $OutputFile -append
	"   7. netsh firewall show notifications"							| Out-File -FilePath $OutputFile -append
	"   8. netsh firewall show opmode"									| Out-File -FilePath $OutputFile -append
	"   9. netsh firewall show portopening"								| Out-File -FilePath $OutputFile -append
	"  10. netsh firewall show service"									| Out-File -FilePath $OutputFile -append
	"  11. netsh firewall show state"									| Out-File -FilePath $OutputFile -append
	"===================================================="				| Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append
	RunNetSH -NetSHCommandToExecute "firewall show allowedprogram"
	RunNetSH -NetSHCommandToExecute "firewall show config"
	RunNetSH -NetSHCommandToExecute "firewall show currentprofile"
	RunNetSH -NetSHCommandToExecute "firewall show icmpsetting"
	RunNetSH -NetSHCommandToExecute "firewall show logging"
	RunNetSH -NetSHCommandToExecute "firewall show multicastbroadcastresponse"
	RunNetSH -NetSHCommandToExecute "firewall show notifications"
	RunNetSH -NetSHCommandToExecute "firewall show opmode"
	RunNetSH -NetSHCommandToExecute "firewall show portopening"
	RunNetSH -NetSHCommandToExecute "firewall show service"
	RunNetSH -NetSHCommandToExecute "firewall show state"
	CollectFiles -filesToCollect $outputFile -fileDescription "Firewall" -SectionDescription $sectionDescription

	#----------Registry
	$outputFile= $Computername + "_Firewall_reg_" + $suffix + ".TXT"
	$CurrentVersionKeys =	"HKLM\Software\Policies\Microsoft\WindowsFirewall",
							"HKLM\SYSTEM\CurrentControlSet\Services\BFE",
							"HKLM\SYSTEM\CurrentControlSet\Services\IKEEXT",
							"HKLM\SYSTEM\CurrentControlSet\Services\MpsSvc",
							"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess",
							"HKLM\Software\Policies\Microsoft\Windows\NetworkIsolation"
	$sectionDescription = "Firewall"
	RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -outputFile $outputFile -fileDescription "Firewall Registry Keys" -SectionDescription $sectionDescription


	#----------EventLogs
	if (($suffix -eq "") -or ($suffix -eq "_AFTER")){
		#----------WFAS Event Logs
		$sectionDescription = "Firewall EventLogs"
		#WFAS CSR
		$EventLogNames = "Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurity"
		$Prefix = ""
		$Suffix = "_evt_"
		.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix

		#WFAS CSR Verbose
		$EventLogNames = "Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurityVerbose"
		$Prefix = ""
		$Suffix = "_evt_"
		.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix

		#WFAS FW
		$EventLogNames = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
		$Prefix = ""
		$Suffix = "_evt_"
		.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix

		#WFAS FW Verbose
		$EventLogNames = "Microsoft-Windows-Windows Firewall With Advanced Security/FirewallVerbose"
		$Prefix = ""
		$Suffix = "_evt_"
		.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix
	}
}
#Windows Server 2003
else{
	"[info]: Firewall-Component XP/WS2003"  | WriteTo-StdOut 
	#----------Registry
	$outputFile= $Computername + "_Firewall_reg_.TXT"
	$CurrentVersionKeys =	"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall",
							"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess"
	$sectionDescription = "Firewall"
	RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -outputFile $outputFile -fileDescription "Firewall Registry Keys" -SectionDescription $sectionDescription
	
	#----------Netsh
	$outputFile = $ComputerName + "_Firewall_netsh.TXT"
	RunNetSH -NetSHCommandToExecute "firewall show allowedprogram"
	RunNetSH -NetSHCommandToExecute "firewall show config"
	RunNetSH -NetSHCommandToExecute "firewall show currentprofile"
	RunNetSH -NetSHCommandToExecute "firewall show icmpsetting"
	RunNetSH -NetSHCommandToExecute "firewall show logging"
	RunNetSH -NetSHCommandToExecute "firewall show multicastbroadcastresponse"
	RunNetSH -NetSHCommandToExecute "firewall show notifications"
	RunNetSH -NetSHCommandToExecute "firewall show opmode"
	RunNetSH -NetSHCommandToExecute "firewall show portopening"
	RunNetSH -NetSHCommandToExecute "firewall show service"
	RunNetSH -NetSHCommandToExecute "firewall show state"
	CollectFiles -filesToCollect $outputFile -fileDescription "Firewall" -SectionDescription $sectionDescription
}


# SIG # Begin signature block
# MIInlAYJKoZIhvcNAQcCoIInhTCCJ4ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBHNnKktqwmuxIm
# fgXgrSw17Y5YX3SyGCZrgOKglPglOKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXQwghlwAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDONfKBu52JkeNQCVd0oww1N
# njpV7QqGshvK7zDLZF0nMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAKmpUFDGETwSa19/17u4ZJHlIFgDVNTDoqrZwHOdScE2CV+tkVPs6+
# I9BXO+iuqqPSnV6EhfsrW0sx7BKa4jVfQY+wWaDLd+MB2YhgiTw7XEPS12qIjCGs
# 7QIqYYi1IrGt1l9uCBppSUuAeyPUrnsAHyBvzx2i+VVwMPURUoy37BdUKxBfTeoU
# V2JsT0/FWMuJYPe3Na/jjH5Gz0feWR2k3NT3q/M3AlCiX2KJhj0GRFAoatPy4jxM
# XgF0iLbM2zCofz/32/epx/iiHOkcsXaOVWtOMdX+sA+v7sQPajeAxe7CAsF8mx2q
# Jl40VW7MlgahhaPMkOqN1l8B4VXozBmRoYIW/DCCFvgGCisGAQQBgjcDAwExghbo
# MIIW5AYJKoZIhvcNAQcCoIIW1TCCFtECAQMxDzANBglghkgBZQMEAgEFADCCAVAG
# CyqGSIb3DQEJEAEEoIIBPwSCATswggE3AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIE4oNTvuIcYcXpa+MYrbwc6V48VOuNxDKQYUzLGwUou0AgZi1V2Q
# 978YEjIwMjIwODE2MDg0MDExLjk4WjAEgAIB9KCB0KSBzTCByjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFt
# ZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0U3QS1F
# MzU5LUEyNUQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghFUMIIHDDCCBPSgAwIBAgITMwAAAaDpu4y7DqLRegABAAABoDANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMTEyMDIxOTA1
# MjNaFw0yMzAyMjgxOTA1MjNaMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozRTdBLUUzNTktQTI1RDElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAL/a4g5ocZ0A6PZi+GEjoLyIUCrvCuX/lak+OPR8QcKL
# oi/H8jTYmyz8dWGR8ZMwa21HmNGGGslfJ1YOc6bNFTcHgbnblPunCQU0UFe6Yz/3
# yXmTRTZeJpn5u6Vcd7njHq6P/q/lUYW/7QeHV3KMZRM9pETBLvH3xN7m0UcSKY9r
# 4CwbaYz6f03B9BGN3UuIQJtwJkWSDBuWJD9qSIyvW1maOQNvG27ZpBxeMR8Odrwk
# f7BmZ927RfuTp0nlYZEXDNmIs4lbhCEASl6HZzWaZu0B8GeFI834TnJQt+l9NPbB
# fxFsfpd8CDqxnHzz3rGrT6BQP2YfLxm2l0R4TVkDQeAHINbaskJtMAkCG3vUHtHP
# ak9CaDlHf69IKuLwF5xIH5nybBgve45LdHpt5QEnuITis9L1YLXDV9lHsrjhlKZ7
# Z0j473+eGBvcwtiCbrPHceG0ugaEZU8v5agOQye33cgag7qQ0EIzZf4KzbaqXa0+
# OQhHLHDEXpGxeH9AeeEomAHN8757zgjdNhsjSLb3MBMvrIc6/mwSzXNo0yKHbsjB
# 9aDhDv7jQvt7ry4LrIPwRQSloPazZPn02FJq5PMIScCnlitKxxz0xBUiLuD7kYB0
# LykK/7SJFrtAi9qVT72VaCTIAFT+eIUdY+PIagHjHcrOje1cHpoLfJn91NFekmdp
# AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUcrkuUNgpTpG4kWwUL0TPC2GM0OgwHwYD
# VR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZO
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBc
# BggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYD
# VR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOC
# AgEAMX3GAqv436yUCaVtwSpAGWkvk98EypwuRLrJJ4YmMb4spfdai/mnKCuEp+1d
# n3Q1hZR+0hmnN1izh6FHlGVoTd5i5taVw2XCwqRysZIMkprBtsMZ+87iH/UvXeyD
# rqE+JvruYb3oICpFUXRzkwDXCIqOOX/mB+tt00seC1ERDzMKlsrj7rqXUV3S6n2b
# Fw4QSmGEmvxTfCHAXCgr5An+TFaiAa18OJqrpHKgVaE/y4pItUNX4xMRMdlvenY7
# CcFYTVbrTvVcMp3FGQ3+kARnXkTUsk2/2JijWXU/9F0X4jOkwsYMB/8+VW9NTDdW
# sf25qptiv6tHG2L5szdpvXC/2/fFEtz7A+ieJLFbanr0M3haj3ogMVkiQtH4dxYK
# KodXAVeeCQJR90x7fGa84hdhGRMrQ/rA8t8L46zuh5VF4yPZMDVAwySBn6uE87Tu
# Jbs3nvMAG8yIclB0dEx4rcUGBHh9oS9ONQB0pFCQoVXza4TvDRQyex4l9fsQsNj1
# PhpbHarASpqb2XsYdfgDZmbSefWhpr9jFzMnuAhURFIZI5YvAQzFwWoEY+b1BJDu
# iAwGflYfCR1NOSZqcFv9nZwOnEHF3W86PIibgE4WUuMHimK8KU7ZmSxYofuoFiWh
# hrTtTU7cLyO1vMZR0fIsJpUYFXwN8PmHx46fKOtoEbs801kwggdxMIIFWaADAgEC
# AhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQg
# Um9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVa
# Fw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7V
# gtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeF
# RiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3X
# D9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoP
# z130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+
# tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5Jas
# AUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/b
# fV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuv
# XsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg
# 8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzF
# a/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqP
# nhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEw
# IwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSf
# pxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBB
# MD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0Rv
# Y3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGC
# NxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8w
# HwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmg
# R4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWlj
# Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEF
# BQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29D
# ZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEs
# H2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHk
# wo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinL
# btg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCg
# vxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsId
# w2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2
# zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23K
# jgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beu
# yOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/
# tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjm
# jJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBj
# U02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICyzCCAjQCAQEwgfihgdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjNFN0EtRTM1OS1BMjVEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQATBriNaNpxs5hT773nJ0nuFIKLmKCB
# gzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEB
# BQUAAgUA5qVsqjAiGA8yMDIyMDgxNjA5MDg1OFoYDzIwMjIwODE3MDkwODU4WjB0
# MDoGCisGAQQBhFkKBAExLDAqMAoCBQDmpWyqAgEAMAcCAQACAgKqMAcCAQACAhI0
# MAoCBQDmpr4qAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAI
# AgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAk8E7BoBVdq4F
# /INv/69J8fdIP6S3fTMIJpw77iqhPDThNgrieW0XUB2+sjkkfiHtcYlq5f6Tfgc0
# WuuC4tdtIu4BCGqnnhhPTJGIE9vmONb/LRwGhekCQe5NsH3+aVqmILJgxnjEBWYD
# RJvtN27NXUxzC/2pReMIPcreoVu/EbMxggQNMIIECQIBATCBkzB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAaDpu4y7DqLRegABAAABoDANBglghkgB
# ZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3
# DQEJBDEiBCD/B6jZXr8eDqqoe6ICkF2FfM46IQDtJZEhTIrpZaiqxDCB+gYLKoZI
# hvcNAQkQAi8xgeowgecwgeQwgb0EIC9HijxoZQQiEi3dES+zHT6y+czpaJqBrlI9
# oriDr7TTMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGg6buMuw6i0XoAAQAAAaAwIgQgC4Cdraki9f8ItAlXZt5Wqa5uocZVFSk3fiRS
# 1kwZrzgwDQYJKoZIhvcNAQELBQAEggIAWFL8YTlEu3X6dpRZEsxTls2Q+z2OMgJz
# rpfCjog5iT9IiBq81ehNrghdfWQdFY5T0KNo77Y96f4xoBsfNihJua/MZQsWVv/H
# nsrp8tWD0ezMxL4Rh69lwPG2rDDhiLzEED3BumFTbHR0DhVcfgQTba58Otvc8huU
# Z1ut30lnHKcin9Y13lMU0tE9Lpd3Z1tT0e59MGmhnPiINweWIgmz4hhTOYpg1doY
# McYUZohH/+LXr50jzUB9psD9y5jceGBazuqeqAJHBEU6yDpYgIVoWIWc4eToZ4aL
# 2vTKTVE48Y4IgrMIZqZxx8cBOkusFoN4j8Jc8Uud2dB0Y0A72/KKUi10vb8VGsmR
# O03iocQak7sT4IONUGEipjImdxEmVTTePI2E/rksRHNrmq8Kgt90baSUscfaWjy/
# vR8G9siGKRxIZ3qeGL3wcuWNF5Qvg4IfwMJ0xTdHlJ4J+e9UYi3vLPSJYke8wdeU
# UfLweImiJiHCP/bx3krdOxW8S9a9ZN4IyjDoV4O66FiHFD9kNapyPLv4IY0ijLgV
# VrKMTV2tqpRURaaGPoTk4YGNqDzJxDg8AsFScGajP89ybXL4Tb76D6JHKHeLVJsp
# GkL66MlzKVRP64nGESGtPKKFV7UPG6RVMmjvnzSq+Ee+xzAn2PzaNo8gY5BcTEd/
# KS5a4z+7ko0=
# SIG # End signature block
