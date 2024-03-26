#************************************************
# DC_DirectAccessDiag.ps1
# Version 1.0: Apr2013
# Version 1.5: Jun2013
# Version 1.6: Oct-Nov2013 (added hotfix checking and fixed issues - published Nov 15, 2013)
# Version 1.7: Nov2013 (added ETL tracing for Schannel and DASrvPSLogging - published Nov 19, 2013)
# Version 1.8: Mar2014 (added BasicSystemInformation and output files)
# Version 1.9.11.14.13: Added the DAClientAlerts and DAServerAlerts
# Version 2.1.04.02.14: Added IpHlpSvc logging. TFS264081
# Version 2.2.07.31.14: Added HyperV output for nvspbind info in DASharedNetInfo function; added DiagnosticVersion.TXT
# Version 2.3.08.14.14: Added data collection for windir\inf\netcfg*.etl files, and BasicSystemInformationTXT. TFS264081
# Version 2.4.08.24.14: Within the interactive section, we now enable Ncasvc/Operational and Ncsi/operational eventlogs.
# Date: 2013-2014 / 2020 /waltere
# Authors:
#	Boyd Benson (bbenson@microsoft.com); Joel Christiansen (joelch@microsoft.com DirectAccess SME Lead)
# Description: Collects information about the DirectAccess Client.
# Called from: DirectAccess Diag, Main Networking Diag
#*******************************************************

. ./utils_cts.ps1
. ./utils_Remote.ps1

Trap [Exception] 
	{
		#_# WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("Stopping DataCollectorSet")
		Write-host $_
		continue
	}

Import-LocalizedData -BindingVariable ScriptVariable

function MenuDiagInput_StaticInteractive{
    Write-Host -ForegroundColor Yellow 	"============ 1. DirectAccess Menu ============="
    Write-Host "1: Collect DirectAccess Static"
    Write-Host "2: Collect DirectAccess Interactive"
	Write-Host "q: Press Q  or Enter to skip"
}
function MenuDiagInput_CliSrv{
    Write-Host -ForegroundColor Yellow 	"================ 2. DirectAccess Client Server Menu  =============="
    Write-Host "1: DA Client"
    Write-Host "2: DA Server"
	Write-Host "q: Press Q  or Enter to skip"
}
function DiagInput_ClientServer{
        #$Selection = Read-Host "Choose the DirectAccess Client or Server"
		$Selection = CHOICE /T 20 /C 12q /D 1 /M "Choose the DirectAccess Client or Server: Press 1=Cli,2=Srv,q=quit [Timeout=20sec]"
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): DA datacollection type: $Selection" -shortformat
		switch ($LASTEXITCODE)
		{
			1 {$Script:ResultsClientOrServer = "DirectAccessCli"}
			2 {$Script:ResultsClientOrServer = "DirectAccessSrv"}
			3 {}
		}
}
#_# $ResultsCollectionType = Get-DiagInput -Id "DirectAccessCollectionTypeChoice"
#_# DirectAccessStatic -or- DirectAccessInteractive
		MenuDiagInput_StaticInteractive
        #$Selection = Read-Host "Choose the DirectAccess datacollection type"
		$Selection = CHOICE /T 20 /C 12q /D 1 /M "Choose the DirectAccess datacollection type: Press 1=Static,2=Interactive,q=quit [Timeout=20sec]"
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): DA datacollection type: $Selection" -shortformat
		switch ($LASTEXITCODE)
		{
			1 {$ResultsCollectionType = "DirectAccessStatic"}
			2 {$ResultsCollectionType = "DirectAccessInteractive"}
			3 { }
		}

function DAClientInfo
{
	#-----------
	# DirectAccess Client
		.\DC_DirectAccessClient-Component.ps1
	#-----------
	# DNS Client
		.\DC_DnsClient-Component.ps1
	#-----------
	# NAP Client
		.\DC_NAPClient-Component.ps1
	#-----------
}

function DAServerInfo
{
	#-----------
	# DNS Client
		.\DC_DnsClient-Component.ps1
	#-----------
	# DirectAccess Server
		.\DC_DirectAccessServer-Component.ps1
	#-----------
	# HTTP
		.\DC_HTTP-Component.ps1
	#-----------
	# NAP Server
		.\DC_NAPServer-Component.ps1
	#-----------
	# Network LBFO	
		.\DC_NetLBFO-Component.ps1
	#-----------	
	# NLB Server
		.\DC_NLB-Component.ps1
	#-----------
}

function DASharedNetInfo
{
	#-----------
	# Kerberos
		.\DC_Kerberos-Component.ps1
	# Certificates
		.\DC_Certificates-Component.ps1
	#-----------
	# ProxyConfig
		.\DC_ProxyConfiguration.ps1
	# InternetExplorer
		.\DC_InternetExplorer-Component.ps1
	# SChannel
		.\DC_SChannel-Component.ps1
	# WinHTTP
		.\DC_WinHTTP-Component.ps1
	#-----------
	# TCPIP and Winsock
		.\DC_Winsock-Component.ps1
		.\DC_TCPIP-Component.ps1
	# Firewall and IPsec
		.\DC_Firewall-Component.ps1
		.\DC_PFirewall.ps1
		.\DC_IPsec-Component.ps1
	#-----------
	# Network Adapters
		.\DC_NetworkAdapters-Component.ps1
	# NetworkConnections	
		.\DC_NetworkConnections-Component.ps1
	# NetworkList
		.\DC_NetworkList-Component.ps1
	# NetworkLocationAwareness
		.\DC_NetworkLocationAwareness-Component.ps1
	# NetworkStoreInterface
		.\DC_NetworkStoreInterface-Component.ps1
	#-----------
	#GPClient registry and event logs
		.\DC_GroupPolicyClient-Component.ps1
	#GPResults
		.\DC_RSoP.ps1
	#WhoAmI
		.\DC_Whoami.ps1
	#----------- 
	#BasicSysInfo
		.\DC_BasicSystemInformation.ps1
		.\DC_BasicSystemInformationTXT.ps1
	#ChkSym
		.\DC_ChkSym.ps1
	#-----------
	#Event Logs - System & Application logs
		$sectionDescription = "Event Logs (System and Application)"
		$EventLogNames = "System", "Application"
		Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription
	#-----------
	#Services (running)
		.\DC_Services.ps1
	#TaskListSvc
		.\DC_TaskListSvc.ps1
	#ScheduledTasks
		.\DC_ScheduleTasks.ps1
	#-----------
	# HyperV output file that network binding information (added 7/24/14)
		.\DC_HyperVNetInfo.ps1
	#-----------
}

function DAGeneralInfo
{
	#MSINFO32
		.\DC_MSInfo.ps1
}

function DAClientAlerts
{
	"[info] DirectAccess DAClient Alerts section begin" | WriteTo-StdOut
	$sectionDescription = "DirectAccess Client Alerts"

	#ALERTS FILE
	$OutputFile= $Computername + "_ALERTS.TXT"

	# detect OS version and SKU
	$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
	[int]$bn = [int]$wmiOSVersion.BuildNumber
	$sku = $((Get-CimInstance win32_operatingsystem).OperatingSystemSKU)

	#----------determine OS architecture
	Function GetComputerArchitecture() 
	{ 
		if (($Env:PROCESSOR_ARCHITEW6432).Length -gt 0) #running in WOW 
		{ $Env:PROCESSOR_ARCHITEW6432 }
		else
		{ $Env:PROCESSOR_ARCHITECTURE } 
	}
	$OSArchitecture = GetComputerArchitecture			

"`n`n`n`n" | Out-File -FilePath $OutputFile -append
"=========================================================" | Out-File -FilePath $OutputFile -append
" DirectAccess Client Configuration Issue Detection" | Out-File -FilePath $OutputFile -append
"=========================================================" | Out-File -FilePath $OutputFile -append
"`n`n" | Out-File -FilePath $OutputFile -append

	#----------------------------------------
	# 1
	# DirectAccess Client: Check for "DirectAccess Client has Incorrect SKU"
	#   (W7/WS2008R2 and W8/WS2012)
	#----------------------------------------
	if ($true)
	{
	# This check is to verify that the DirectAccess Client is Enterprise or Ultimate for Win7 or Enterprise for Win8
	"[info] Checking for `"DirectAccess Client: DirectAccess Client has Incorrect SKU`"" | WriteTo-StdOut
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"DirectAccess Client: DirectAccess Client has Incorrect SKU`"" | Out-File -FilePath $OutputFile -append
	if (($bn -gt 9000) -and ($sku -ne 4))
	{
		"*" | Out-File -FilePath $OutputFile -append
		"****************************************" | Out-File -FilePath $OutputFile -append
		"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
		"****************************************" | Out-File -FilePath $OutputFile -append
		"*" | Out-File -FilePath $OutputFile -append
		"The Windows SKU of this Windows 8+ client does NOT support DirectAccess." | Out-File -FilePath $OutputFile -append
		"Please use Windows Enterprise Edition." | Out-File -FilePath $OutputFile -append
	}			
	elseif (($bn -eq 7601) -and (($sku -ne 1) -and ($sku -ne 4)))
	{
		"*" | Out-File -FilePath $OutputFile -append
		"****************************************" | Out-File -FilePath $OutputFile -append
		"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
		"****************************************" | Out-File -FilePath $OutputFile -append
		"*" | Out-File -FilePath $OutputFile -append
		"The Windows SKU of this Windows 7 client does NOT support DirectAccess." | Out-File -FilePath $OutputFile -append
		"Please use Windows Enterprise Edition or Ultimate." | Out-File -FilePath $OutputFile -append
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"The client SKU supports DirectAccess." | Out-File -FilePath $OutputFile -append
	}
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# 2
	# DirectAccess Client: Checking for "Proxy server is configured for WinHTTP"
	#   (W7/WS2008R2)
	#----------------------------------------
	if ($true)
	{
	"[info] Checking for `"DirectAccess Client: Proxy server is configured for WinHTTP`"" | WriteTo-StdOut	
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"DirectAccess Client: Proxy server is configured for WinHTTP`""  | Out-File -FilePath $OutputFile -append
	if ($bn -ge 7601)
	{
		$inetConnections = get-itemproperty -path "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
		$proxyWinHTTP = $inetConnections.WinHttpSettings

		# Offset 8 is the key to knowing if the WinHTTP proxy is set.
		# If it is 1, then there is no proxy. If it is 3, then there is a proxy set.
		[int]$proxyWinHTTPcheck = $proxyWinHTTP[8]
		If ($proxyWinHTTPcheck -ne 1)
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Proxy server is configured for WinHTTP." | Out-File -FilePath $OutputFile -append
			"Refer to the output file named ComputerName_ProxyConfiguration.TXT" | Out-File -FilePath $OutputFile -append
		}
		else
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Proxy server settings for WinHTTP are in the default configuration."  | Out-File -FilePath $OutputFile -append
		}
	}
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}

	#----------------------------------------
	# 3
	# DirectAccess Client: Checking for "Proxy server is configured for Internet Explorer System Context"
	#----------------------------------------
	if ($true)
	{
	"[info] `"DirectAccess Client: Proxy server is configured for Internet Explorer System Context`"" | WriteTo-StdOut
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: `"DirectAccess Client: Proxy server is configured for Internet Explorer in System Context`"" | Out-File -FilePath $OutputFile -append
		#----------
		# Verifying HKU is in the psProviderList. If not, add it
		#----------
		#
		# HKU may not be in the psProviderList, so we need to add it so we can reference it
		#
		$psProviderList = Get-PSDrive -PSProvider Registry
		$psProviderListLen = $psProviderList.length
		for ($i=0;$i -le $psProviderListLen;$i++)
		{
			if (($psProviderList[$i].Name) -eq "HKU")
			{
				$hkuExists = $true
				$i = $psProviderListLen
			}
			else
			{
				$hkuExists = $false
			}
		}
		if ($hkuExists -eq $false)
		{
			"[info]: Creating a new PSProvider to enable access to HKU" | WriteTo-StdOut
			New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS
		}

		#----------
		# Verify "\Internet Settings\Connections" exists, if not display message that IE System Context is not configured.
		#   $ieConnectionsCheck and associated code block added 10/11/2013
		#----------
		$ieConnections = $null
		# Get list of regvalues in "HKEY_USERS\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"		
		$ieConnectionsCheck = Test-path "HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
		$ieProxyConfigProxyEnable   = (Get-ItemProperty -path "HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings").ProxyEnable		
		if ($ieProxyConfigProxyEnable -eq 1)
		{
			#Changed this detection from "-ne 0" to "-eq 1" because if the registry value did NOT exist, "-ne 0" caused a false positive.
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"A proxy server is configured for IE System Settings." | Out-File -FilePath $OutputFile -append
			"Refer to the output file named <ComputerName>_ProxyConfiguration.TXT to confirm." | Out-File -FilePath $OutputFile -append
			"This alert currently checks for ProxyEnable -eq 1." | Out-File -FilePath $OutputFile -append
		}
		else
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Proxy server settings (ProxyEnable) for IE System is not enabled."  | Out-File -FilePath $OutputFile -append
			"Refer to the output file named <ComputerName>_ProxyConfiguration.TXT to confirm." | Out-File -FilePath $OutputFile -append
			"This alert currently checks for ProxyEnable -ne 0." | Out-File -FilePath $OutputFile -append
		}
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append	
	}

	#----------
	# 4
	# DirectAccess Client: Detect if the StaticProxy registry value exists in any subkey of "HKLM:\SYSTEM\CurrentControlSet\services\iphlpsvc\Parameters\ProxyMgr"
	#   RegSubKey example: "HKLM:\SYSTEM\CurrentControlSet\services\iphlpsvc\Parameters\ProxyMgr\{4BB9AF47-8767-4835-899E-08D4230EA18E}"
	#   Added 3/28/14
	#----------	
	if ($true)
	{	
	"[info] Checking for `"DirectAccess Client: Detect if the StaticProxy registry value exists in any subkey of HKLM:\SYSTEM\CurrentControlSet\services\iphlpsvc\Parameters\ProxyMgr`"" | WriteTo-StdOut
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"DirectAccess Client: Detect if the StaticProxy registry value exists in any subkey of HKLM:\SYSTEM\CurrentControlSet\services\iphlpsvc\Parameters\ProxyMgr`""  | Out-File -FilePath $OutputFile -append
	
		$keyPath = "HKLM:\SYSTEM\CurrentControlSet\services\iphlpsvc\Parameters\ProxyMgr"
		if (Test-Path $keyPath)
		{
			$ProxyMgr = Get-ChildItem $keyPath
			$ProxyMgrLen = $ProxyMgr.length
			$StaticProxyCount=0
			for ($i=0;$i -lt $ProxyMgrLen;$i++)
			{
				$subKeyPath = $ProxyMgr[$i].Name
				$subKeyPath = "REGISTRY::" + $subKeyPath
				$StaticProxyValue = (Get-ItemProperty -Path $subKeyPath).StaticProxy
				if ($StaticProxyValue)
				{
					$StaticProxyCount++
				}
			}
			if ($StaticProxyValue)
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"The DirectAccess Client configuration has the StaticProxy regvalue within HKLM:\SYSTEM\CurrentControlSet\services\iphlpsvc\Parameters\ProxyMgr." | Out-File -FilePath $OutputFile -append
				"This registry value may cause connectivity issues." | Out-File -FilePath $OutputFile -append
				"Refer to the output file named <ComputerName>_TCPIP_reg_output.TXT registry value to confirm." | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"The DirectAccess Client configuration does NOT have the StaticProxy regvalue within HKLM:\SYSTEM\CurrentControlSet\services\iphlpsvc\Parameters\ProxyMgr." | Out-File -FilePath $OutputFile -append
				"This registry value has been known to cause connectivity issues." | Out-File -FilePath $OutputFile -append
				"Refer to the output file named <ComputerName>_TCPIP_reg_output.TXT registry value to confirm." | Out-File -FilePath $OutputFile -append
			}
		}
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append	
	}

#----------------------------------------------------
# DirectAccess Client Hotfix Detection
#----------------------------------------------------

"`n`n`n`n" | Out-File -FilePath $OutputFile -append
"=========================================================" | Out-File -FilePath $OutputFile -append
" DirectAccess Client Hotfix Detection: W8/WS2012, W8.1/WS2012R2" | Out-File -FilePath $OutputFile -append
"=========================================================" | Out-File -FilePath $OutputFile -append
"`n`n" | Out-File -FilePath $OutputFile -append

	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 2855269
	#   (W8/WS2012)
	#   (backport for W7/WS2008R2 due Dec2013)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2855269" | WriteTo-StdOut	
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2855269`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9600)
	{
		# W8.1 version of DaOtpCredentialProvider.dll is 6.3.9600.16384
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix does not apply to W8.1/WS2012R2." | Out-File -FilePath $OutputFile -append
	}
	elseif ($bn -eq 9200)
	{
		# "Checking for existence of Daotpauth.dll or Daotpcredentialprovider.dll." | Out-File -FilePath $OutputFile -append
		If (Test-path "$env:windir\system32\Daotpcredentialprovider.dll")
		{
			if ($OSArchitecture -eq "AMD64")
			{
				if (CheckMinimalFileVersion "$env:windir\system32\Daotpcredentialprovider.dll" 6 2 9200 20732)
				{
					"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
					"Hotfix KB 2855269 is installed." | Out-File -FilePath $OutputFile -append
				}
				else
				{
					"*" | Out-File -FilePath $OutputFile -append
					"****************************************" | Out-File -FilePath $OutputFile -append
					"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
					"****************************************" | Out-File -FilePath $OutputFile -append
					"*" | Out-File -FilePath $OutputFile -append
					"Hotfix KB 2855269 is not installed." | Out-File -FilePath $OutputFile -append
				}
			}
			<#
				"Which files exists?" | Out-File -FilePath $OutputFile -append
				If (Test-path "$env:windir\system32\Daotpauth.dll")
				{ "Daotpauth.dll found in windir\system32." | Out-File -FilePath $OutputFile -append }
				else
				{ "Daotpauth.dll NOT found in windir\system32." | Out-File -FilePath $OutputFile -append }
				
				If (Test-path "$env:windir\system32\Daotpcredentialprovider.dll")
				{ "Daotpcredentialprovider.dll found in windir\system32." | Out-File -FilePath $OutputFile -append }
				else
				{ "Daotpcredentialprovider.dll NOT found in windir\system32." | Out-File -FilePath $OutputFile -append }
			#>
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix does not apply to W7/WS2008R2" | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append			
	"2855269 - Error message when you use an account that contains a special character in its DN to connect to a Windows Server 2012-based Direct Access server" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2855269/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 2769240
	#   (W8/WS2012)
	#   (with LDRGDR detection)
	#----------------------------------------
	if ($true)
	{
	# W8 x86
	#  (windir\system32) kerberos.dll; LDR=6.2.9200.16432; GDR=6.2.9200.20533
	# W8 x64
	#  (windir\system32) kerberos.dll; LDR=6.2.9200.16432; GDR=6.2.9200.20533
	#  (x86: windir\syswow64) kerberos.dll; LDR=6.2.9200.16432; GDR=6.2.9200.20533
	#
	"[info] DirectAccess Client: Hotfix verification for KB 2769240" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB2769240`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9600)
	{
		# W8.1 version of DaOtpCredentialProvider.dll is 6.3.9600.16384
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix does not apply to W8.1/WS2012R2." | Out-File -FilePath $OutputFile -append
	}
	elseif ($bn -eq 9200)
	{
		if ($OSArchitecture -eq "AMD64")
		{
			if ((CheckMinimalFileVersion "$env:windir\system32\kerberos.dll" 6 2 9200 16432 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\kerberos.dll" 6 2 9200 20533 -LDRGDR) -and 
			    (CheckMinimalFileVersion "$env:windir\SysWOW64\kerberos.dll" 6 2 9200 16432 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\SysWOW64\kerberos.dll" 6 2 9200 20533 -LDRGDR))
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2769240 is installed." | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2769240 is not installed." | Out-File -FilePath $OutputFile -append
			}
		}
		elseif ($OSArchitecture -eq "x86")
		{
			if ((CheckMinimalFileVersion "$env:windir\system32\kerberos.dll" 6 2 9200 16432 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\kerberos.dll" 6 2 9200 20533 -LDRGDR))
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2769240 is installed." | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2769240 is not installed." | Out-File -FilePath $OutputFile -append
			}
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix does not apply to W7/WS2008R2" | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2769240 - You cannot connect a DirectAccess client to a corporate network in Windows 8 or Windows Server 2012" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2769240/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Client/Server: Hotfix Verification for KB 2795944
	#   (W8/WS2012)
	#----------------------------------------
	if ($true)
	{
	# This is the "W8/WS2012 Cumulative Update Package Feb2013"
	# ton of files in this update...
	"[info] DirectAccess Client: Hotfix verification for KB 2795944" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2795944`"" | Out-File -FilePath $OutputFile -append
	
	if ($bn -eq 9200)
	{
		# file versions identical for x64/x86
		#
		# Iphlpsvc.dll  6.2.9200.16496;  ;6.2.9200.20604  
		# Iphlpsvcmigplugin.dll  6.2.9200.16496;  ;6.2.9200.20604
		# Ncbservice.dll  6.2.9200.16449  
		# Netprofm.dll  6.2.9200.16496;  ;6.2.9200.20604 		
		#
		if ( ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 2 9200 16496 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\syswow64\Iphlpsvc.dll" 6 2 9200 20604 -LDRGDR)) -and
		     ((CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 2 9200 16496) -and (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 2 9200 20604)) -and
		     (CheckMinimalFileVersion "$env:windir\system32\Ncbservice.dll" 6 2 9200 16449) -and
		     ((CheckMinimalFileVersion "$env:windir\system32\Netprofm.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Netprofm.dll" 6 2 9200 20604 -LDRGDR)) )
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2795944 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2795944 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2795944 - Windows 8 and Windows Server 2012 update rollup: February 2013" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2795944/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}

	#----------------------------------------
	# DirectAccess Client/Server: Hotfix Verification for KB 2779768
	#   (W8/WS2012)
	#   Bugcheck due to IPsec; LBFO + MAC Spoofing (MAC flipping) issues
	#----------------------------------------
	if ($true)
	{
	# This is the "W8/WS2012 Cumulative Update Package Dec2013"
	# ton of files in this update...
	"[info] DirectAccess Client: Hotfix verification for KB 2779768" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2779768`"" | Out-File -FilePath $OutputFile -append
	
	if ($bn -eq 9200)
	{
		# x86
		# Checking 3 specific binaries:
		#   Bfe.dll  6.2.9200.16451; 6.2.9200.20555
		#   Http.sys  6.2.9200.16451; 6.2.9200.20555
		#   Ikeext.dll  6.2.9200.16451; 6.2.9200.20555  
		#
		if ( ((CheckMinimalFileVersion "$env:windir\system32\Bfe.dll" 6 2 9200 16451 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Bfe.dll" 6 2 9200 20555 -LDRGDR)) -and
		     ((CheckMinimalFileVersion "$env:windir\system32\drivers\Http.sys" 6 2 9200 16451 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\drivers\Http.sys" 6 2 9200 20555 -LDRGDR)) -and
		     ((CheckMinimalFileVersion "$env:windir\system32\Ikeext.dll" 6 2 9200 16451 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Ikeext.dll" 6 2 9200 20555 -LDRGDR)) )
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2779768 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2779768 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2779768 - Windows 8 and Windows Server 2012 update rollup: December 2012" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2779768/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}

"`n`n`n`n" | Out-File -FilePath $OutputFile -append
"=========================================================" | Out-File -FilePath $OutputFile -append
" DirectAccess Client Hotfix Detection: W7/WS2008R2" | Out-File -FilePath $OutputFile -append
"=========================================================" | Out-File -FilePath $OutputFile -append
"`n`n" | Out-File -FilePath $OutputFile -append
	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 2796313
	#   (W7/WS2008R2 SP1)
	#----------------------------------------
	if ($true)
	{
	# W7/WS2008R2 x86
	#  (windir\system32) iphlpsvc.dll: 6.1.7600.21421; ;6.1.7601.22214
	#  (windir\system32) iphlpsvcmigplugin.dll: 6.1.7600.16385; ;6.1.7601.22214
	#  (windir\system32) Netcorehc.dll:	6.1.7601.22214 
	#
	# W7/WS2008R2 x64
	#  (windir\system32) iphlpsvc.dll: 6.1.7600.21421; ;6.1.7601.22214;
	#  (windir\system32\migration) iphlpsvcmigplugin.dll: 6.1.7600.16385; ;6.1.7601.22214
	#  (x86: windir\syswow64\migration) iphlpsvcmigplugin.dll: 6.1.7600.21421; ;6.1.7601.22214 
	#  (x86: windir\syswow64) netcorehc.dll: 6.1.7600.21421; ;6.1.7601.22214
	#

	"[info] DirectAccess Client: Hotfix verification for KB 2796313" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2796313`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 7601)
	{
		if ($OSArchitecture -eq "AMD64")
		{
			#checking for x64 version of files AND the associated x86 version of files
			if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7601 22214) -and
			    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7601 22214) -and (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 1 7601 22214) -and 
			    (CheckMinimalFileVersion "$env:windir\system32\Netcorehc.dll" 6 1 7601 22214) -and (CheckMinimalFileVersion "$env:windir\SysWOW64\Netcorehc.dll" 6 1 7601 22214))
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2796313 is installed." | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2796313 is not installed." | Out-File -FilePath $OutputFile -append
			}
		}
		elseif ($OSArchitecture -eq "x86")
		{
			if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7601 22214) -and
			    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7601 22214) -and
			    (CheckMinimalFileVersion "$env:windir\system32\Netcorehc.dll" 6 1 7601 22214))
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2796313 is installed." | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2796313 is not installed." | Out-File -FilePath $OutputFile -append
			}			
		}
	}
	elseif ($bn -eq 7600)
	{
		if ($OSArchitecture -eq "AMD64")
		{
			if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7600 21421) -and
			    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7600 16385) -and (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 1 7600 21421))
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2796313 is installed." | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2796313 is not installed." | Out-File -FilePath $OutputFile -append
			}
		}
		elseif ($OSArchitecture -eq "x86")
		{
			if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll " 6 1 7600 21421) -and
			    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7601 16385))
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2796313 is installed." | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2796313 is not installed." | Out-File -FilePath $OutputFile -append
			}
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W7/WS2008R2" | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2796313 - Long reconnection time after a DirectAccess server disconnects a Windows 7-based DirectAccess client" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2796313/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 2758949
	#   (W7/WS2008R2 SP1)
	#----------------------------------------
	if ($true)
	{
	# W7/WS2008R2 x86
	#  (windir\system32) Iphlpsvc.dll 6.1.7601.22130
	#  (windir\system32\migration) Iphlpsvcmigplugin.dll 6.1.7601.22130 
	#  (windir\system32) Netcorehc.dll 6.1.7601.22130 
	#	
	# W7/WS2008R2 x64
	#  (windir\system32) Iphlpsvc.dll 6.1.7601.22130
	#  (windir\system32\migration) Iphlpsvcmigplugin.dll 6.1.7601.22130 
	#  (x86: windir\syswow64\migration) Iphlpsvcmigplugin.dll 6.1.7601.22130
	#  (windir\system32) Netcorehc.dll 6.1.7601.22130 
	#

	"[info] DirectAccess Client: Hotfix verification for KB 2758949" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2758949`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 7601)
	{
		# since the only difference between x86 and x64 was the following, we are skipping this file detection:  -and (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 1 7601 22130)
		if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7601 22130) -and
		    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7601 22130) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Netcorehc.dll" 6 1 7601 22130)) 
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2758949 is installed." | Out-File -FilePath $OutputFile -append
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2758949 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W7/WS2008R2." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2758949 - You cannot build an IP-HTTPS protocol-based connection on a computer that is running Windows 7 or Windows Server 2008 R2" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2758949/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}

	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 2718654
	#   (W7/WS2008R2 RTM and SP1)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2718654" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2718654`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 7601)
	{
		# since the only difference between x86 and x64 was the following, we are skipping this file detection:  -and (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 1 7601 22130)	
		if ((CheckMinimalFileVersion "$env:windir\system32\Dnsapi.dll" 6 1 7601 22011) -and
		    (CheckMinimalFileVersion "$env:windir\syswow64\Dnsapi.dll" 6 1 7601 22011) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Dnscacheugc.exe" 6 1 7601 22011) -and 
		    (CheckMinimalFileVersion "$env:windir\syswow64\Dnscacheugc.exe" 6 1 7601 22011) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Dnsrslvr.dll" 6 1 7601 22011))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2718654 is installed." | Out-File -FilePath $OutputFile -append
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2718654 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	elseif ($bn -eq 7600)
	{
		if ((CheckMinimalFileVersion "$env:windir\system32\Dnsapi.dll" 6 1 7600 21226) -and
		    (CheckMinimalFileVersion "$env:windir\syswow64\Dnsapi.dll" 6 1 7600 21226) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Dnscacheugc.exe" 6 1 7600 21226) -and 
		    (CheckMinimalFileVersion "$env:windir\syswow64\Dnscacheugc.exe" 6 1 7600 21226) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Dnsrslvr.dll" 6 1 7600 21226)) 
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2718654 is installed." | Out-File -FilePath $OutputFile -append
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2718654 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix does not apply to W7/WS2008R2" | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2718654 - Long reconnection time after a DirectAccess server disconnects a Windows 7-based DirectAccess client" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2718654/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 2680464
	#   (W7/WS2008R2 SP1)
	#----------------------------------------
	If ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2680464" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2680464`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 7601)
	{
		if ((CheckMinimalFileVersion "$env:windir\system32\Ncsi.dll" 6 1 7601 21928) -and
		    (CheckMinimalFileVersion "$env:windir\syswow64\Ncsi.dll" 6 1 7601 21928) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Nlaapi.dll" 6 1 7601 21928) -and
		    (CheckMinimalFileVersion "$env:windir\syswow64\Nlaapi.dll" 6 1 7601 21928) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Nlasvc.dll" 6 1 7601 21928)) 
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2680464 is installed." | Out-File -FilePath $OutputFile -append
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2680464 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W7/WS2008R2." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2680464 - Location detection feature in DirectAccess is disabled intermittently in Windows 7 or in Windows Server 2008 R2" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2680464/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 2535133
	#   (W7/WS2008R2 RTM and SP1)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2535133" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2535133`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 7601)
	{
		if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7601 21728) -and
		    (CheckMinimalFileVersion "$env:windir\SysWOW64\migration\Iphlpsvcmigplugin.dll" 6 1 7601 21728)) 
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2535133 is installed." | Out-File -FilePath $OutputFile -append
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2535133 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	elseif ($bn -eq 7600)
	{
		if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7600 20967) -and
		    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7600 16385) -and (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 1 7600 20967)) 
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2535133 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2535133 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W7/WS2008R2." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2535133 - IP-HTTPS clients may disconnect from Windows Server 2008 R2-based web servers intermittently after two minutes of idle time" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2535133/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}

	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 2288297
	#   (W7/WS2008R2 RTM)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2288297" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2288297`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 7600)
	{
		if ($OSArchitecture -eq "AMD64")
		{
			if ((CheckMinimalFileVersion "$env:windir\system32\webclnt.dll" 6 1 7600 20787) -and
			    (CheckMinimalFileVersion "$env:windir\syswow64\webclnt.dll" 6 1 7600 20787))
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2288297 is installed." | Out-File -FilePath $OutputFile -append	
			}
			else
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2288297 is not installed." | Out-File -FilePath $OutputFile -append
			}
		}
		elseif ($OSArchitecture -eq "x86")
		{
			if ((CheckMinimalFileVersion "$env:windir\system32\webclnt.dll" 6 1 7600 20787))
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2288297 is installed." | Out-File -FilePath $OutputFile -append	
			}
			else
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"Hotfix KB 2288297 is not installed." | Out-File -FilePath $OutputFile -append
			}
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W7/WS2008R2." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2288297 - You are unexpectedly prompted to enter your credentials when you try to access a WebDAV resource in a corporate network by using a DirectAccess connection in Windows 7 or in Windows Server 2008 R2" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2288297/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 979373
	#   (W7/WS2008R2 RTM)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 979373" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 979373`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 7600)
	{
		# file versions are identical for x86/x64
		if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7600 20614) -and
		    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7600 16385))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 979373 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 979373 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W7/WS2008R2." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"979373 - The DirectAccess connection is lost on a computer that is running Windows 7 or Windows Server 2008 R2 that has an IPv6 address" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/979373/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Client: Hotfix Verification for KB 978738
	#   (W7/WS2008R2 RTM)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 978738" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 978738`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 7600)
	{
		# file versions are identical for x86/x64
		if ((CheckMinimalFileVersion "$env:windir\system32\Dnsapi.dll" 6 1 7600 20621) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Dnscacheugc.exe" 6 1 7600 20621) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Dnsrslvr.dll" 6 1 7600 20621))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 978738 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 978738 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W7/WS2008R2." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"978738 - You cannot use DirectAccess to connect to a corporate network from a computer that is running Windows 7 or Windows Server 2008 R2" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/978738/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Client: Collect Alerts File
	#----------------------------------------	
	"[info] DirectAccess Client: Collect alerts file" | WriteTo-StdOut			
	# Collect _ALERTS output file
	CollectFiles -filesToCollect $OutputFile -fileDescription "DirectAccess ALERTS" -SectionDescription $sectionDescription
	"[info] DirectAccess DAClient Alerts section end" | WriteTo-StdOut
}


function DAServerAlerts
{
	"[info] DirectAccess DAServer Alerts section begin" | WriteTo-StdOut
	$sectionDescription = "DirectAccess Server Alerts"
	# ALERTS FILE
	$OutputFile= $Computername + "_ALERTS.TXT"
	
	"`n`n" | Out-File -FilePath $OutputFile -append
	"=========================================================" | Out-File -FilePath $OutputFile -append
	" DirectAccess Server Configuration Issue Detection" | Out-File -FilePath $OutputFile -append
	"=========================================================" | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append

	# detect if OS is WS2012+ and is Server SKU
	$OSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
	$OSBuildNumber = $OSVersion.BuildNumber
	$ProductType = (Get-CimInstance -Class Win32_OperatingSystem).ProductType

	# detect OS version and SKU
	$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
	$bn = $wmiOSVersion.BuildNumber
	$sku = $((Get-CimInstance win32_operatingsystem).OperatingSystemSKU)

	#----------determine OS architecture
	function GetComputerArchitecture() 
	{ 
		if (($Env:PROCESSOR_ARCHITEW6432).Length -gt 0) #running in WOW 
		{ $Env:PROCESSOR_ARCHITEW6432 }
		else
		{ $Env:PROCESSOR_ARCHITECTURE } 
	}
	$OSArchitecture = GetComputerArchitecture			

	#----------------------------------------
	# 1
	# DirectAccess Server: Check for "DirectAccess Server with KerberosProxy and ForceTunnel Enabled"
	#----------------------------------------
	if ($true)
	{
		"[info] DirectAccess DAServer: Check for `"DirectAccess Server with KerberosProxy and ForceTunnel Enabled`"" | WriteTo-StdOut
		'--------------------' | Out-File -FilePath $OutputFile -append
		"Rule: KerberosProxy and ForceTunnel check" | Out-File -FilePath $OutputFile -append
		# This functionality is only available in WS2012+
		
		if ($bn -ge 9200)
		{
			# If the OS is a Server SKU
			if (($ProductType -eq 2) -or ($ProductType -eq 3))
			{
				# Add registry check to determine if Get-RemoteAccess is available.
				$regkeyRemoteAccessCheck = "HKLM:\SYSTEM\CurrentControlSet\Services\RaMgmtSvc"
				if (Test-Path $regkeyRemoteAccessCheck) 
				{
					$daRemoteAccess = Get-RemoteAccess
					#This first If statement added 3/20/14 to detect new issue in WS2012 R2. Working with JoelCh.
					If (($bn -ge 9600) -and ($daRemoteAccess.ComputerCertAuthentication -eq "Enabled") -and ($daRemoteAccess.ForceTunnel -eq "Enabled") -and ($daRemoteAccess.Downlevel -eq "Disabled"))
					{
						# Detect if WS2012R2 DA Server has ForceTunnel+ComputerCertAuth enabled and Downlevel disabled. If so, flag it.
						"*" | Out-File -FilePath $OutputFile -append
						"****************************************" | Out-File -FilePath $OutputFile -append
						"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
						"****************************************" | Out-File -FilePath $OutputFile -append
						"*" | Out-File -FilePath $OutputFile -append
						"The DirectAccess Server has both KerberosProxy enabled AND ForceTunnel enabled AND Downlevel disabled. These should never be enabled simultaneously." | Out-File -FilePath $OutputFile -append
						"This needs to be corrected."  | Out-File -FilePath $OutputFile -append
						"For more information:" | Out-File -FilePath $OutputFile -append
						"  Remote Access (DirectAccess) Unsupported Configurations" | Out-File -FilePath $OutputFile -append
						"  http://technet.microsoft.com/en-us/library/dn464274.aspx" | Out-File -FilePath $OutputFile -append
					}
					elseif (($bn -ge 9200) -and ($daRemoteAccess.ComputerCertAuthentication -eq "Disabled") -and ($daRemoteAccess.ForceTunnel -eq "Enabled"))
					{
						# Detect if WS2012R2 DA Server has ComputerCertAuthentication disabled and ForceTunnel enabled. If so, flag it.				
						"*" | Out-File -FilePath $OutputFile -append
						"****************************************" | Out-File -FilePath $OutputFile -append
						"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
						"****************************************" | Out-File -FilePath $OutputFile -append
						"*" | Out-File -FilePath $OutputFile -append
						"The DirectAccess Server has both KerberosProxy AND ForceTunnel enabled. These should never be enabled simultaneously." | Out-File -FilePath $OutputFile -append
						"This needs to be corrected."  | Out-File -FilePath $OutputFile -append
						"For more information:" | Out-File -FilePath $OutputFile -append
						"  Remote Access (DirectAccess) Unsupported Configurations" | Out-File -FilePath $OutputFile -append
						"  http://technet.microsoft.com/en-us/library/dn464274.aspx" | Out-File -FilePath $OutputFile -append
					}
					else
					{
						"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
						"The DirectAccess Server does not have both KerberosProxy AND ForceTunnel enabled. These should never be enabled simultaneously." | Out-File -FilePath $OutputFile -append
						"For more information:" | Out-File -FilePath $OutputFile -append
						"  Remote Access (DirectAccess) Unsupported Configurations" | Out-File -FilePath $OutputFile -append
						"  http://technet.microsoft.com/en-us/library/dn464274.aspx" | Out-File -FilePath $OutputFile -append
					}
				}
			}
		}
		else
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"This check only applies to W8/WS2012 and W8.1/WS2012R2." | Out-File -FilePath $OutputFile -append		
		}
		'--------------------' | Out-File -FilePath $OutputFile -append
		"`n`n" | Out-File -FilePath $OutputFile -append
	}



	#----------------------------------------
	# 2
	# DirectAccess Server: Checking for "Proxy server is configured for WinHTTP"
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Server: Checking for `"Proxy server is configured for WinHTTP`"" | WriteTo-StdOut	
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Proxy server is configured for WinHTTP`"" | Out-File -FilePath $OutputFile -append
	if ($bn -ge 7601)
	{
		$inetConnections = get-itemproperty -path "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
		$proxyWinHTTP = $inetConnections.WinHttpSettings

		# Offset 8 is the key to knowing if the WinHTTP proxy is set.
		# If it is 1, then there is no proxy. If it is 3, then there is a proxy set.
		[int]$proxyWinHTTPcheck = $proxyWinHTTP[8]
		If ($proxyWinHTTPcheck -ne 1)
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Proxy server is configured for WinHTTP." | Out-File -FilePath $OutputFile -append
			"Refer to the output file named ComputerName_ProxyConfiguration.TXT" | Out-File -FilePath $OutputFile -append
		}
		else
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Proxy server settings for WinHTTP are in the default configuration."  | Out-File -FilePath $OutputFile -append
		}
	}
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}

	#----------------------------------------
	# 3-4
	# DirectAccess Server: Checking for "DNS64 State Disabled"
	# DirectAccess Server: Checking for "DNS64 AcceptInterface does not have the DNS64 IP address bound."
	#----------------------------------------
	if ($true)
	{
		$NetDNSTransitionConfiguration = Get-NetDnsTransitionConfiguration
				
		# Checking for "DNS64 State Disabled"
		'--------------------' | Out-File -FilePath $OutputFile -append
		"Rule: Check for `"DNS64 State Disabled`"" | Out-File -FilePath $OutputFile -append
		
		$NetDNSTransitionState = $NetDNSTransitionConfiguration.State
		If ($NetDNSTransitionState -eq "Disabled")
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"NetDNSTransition is Disabled."  | Out-File -FilePath $OutputFile -append
			"This needs to be corrected."  | Out-File -FilePath $OutputFile -append
			'--------------------' | Out-File -FilePath $OutputFile -append
		}
		else
		{
			# Checking for "DNS64 AcceptInterface does not have the DNS64 IP address bound."
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"DNS64 State is Enabled"  | Out-File -FilePath $OutputFile -append
			'--------------------' | Out-File -FilePath $OutputFile -append
			"Rule: Check for `"DNS64 AcceptInterface does not have the DNS64 IP address bound.`"" | Out-File -FilePath $OutputFile -append
			
			$AcceptInterface = $NetDNSTransitionConfiguration.AcceptInterface
			$DNS64Adapter = Get-NetIpAddress -InterfaceAlias $AcceptInterface
			$InterfaceAlias = $DNS64Adapter.InterfaceAlias
			$DNS64AdapterIP = $DNS64Adapter.IPAddress
			$DNS64AdapterIPLen = $DNS64AdapterIP.length
			$DNS64IPExists = $false
			for($DNS64IPCount=0;$DNS64IPCount -lt $DNS64AdapterIPLen;$DNS64IPCount++)
			{
				If ($DNS64AdapterIP[$DNS64IPCount].contains(":3333:") -eq $true)
				{
					$DNS64IPExists = $true
				}
			}	

			If ($DNS64IPExists -eq $false)
			{
				"*" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
				"****************************************" | Out-File -FilePath $OutputFile -append
				"*" | Out-File -FilePath $OutputFile -append
				"Root cause detected." | Out-File -FilePath $OutputFile -append
				"DNS64 AcceptInterface does not have the DNS64 IP address bound." | Out-File -FilePath $OutputFile -append
				"This needs to be corrected."  | Out-File -FilePath $OutputFile -append
				'--------------------' | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
				"DNS64 AcceptInterface has the DNS64 IP address bound." | Out-File -FilePath $OutputFile -append
			}
		}
		'--------------------' | Out-File -FilePath $OutputFile -append
		"`n`n" | Out-File -FilePath $OutputFile -append
	}

	#----------------------------------------
	# 5
	# DirectAccess Server: Checking for "DirectAccess Server with OTP and ForceTunnel Enabled"
	#----------------------------------------
	if ($true)
	{
		"[info] DirectAccess DAServer: Check for `"DirectAccess Server with OTP Authentication Enabled and ForceTunnel Enabled`"" | WriteTo-StdOut
		'--------------------' | Out-File -FilePath $OutputFile -append
		"Rule: OTP and ForceTunnel check" | Out-File -FilePath $OutputFile -append
		# This functionality is only available in WS2012+
		
		if ($bn -ge 9200)
		{
			# If the OS is a Server SKU
			if (($ProductType -eq 2) -or ($ProductType -eq 3))
			{
				# Add registry check to determine if Get-RemoteAccess is available.
				$regkeyRemoteAccessCheck = "HKLM:\SYSTEM\CurrentControlSet\Services\RaMgmtSvc"
				if (Test-Path $regkeyRemoteAccessCheck) 
				{
					$daRemoteAccess = Get-RemoteAccess
					$daOTPAuth = Get-DAOtpAuthentication
					if (($daOTPAuth.OtpStatus -eq "Enabled") -and ($daRemoteAccess.ForceTunnel -eq "Enabled"))
					{
						# Detect if WS2012R2 DA Server has OTP and ForceTunnel Enabled. If so, flag it.
						"*" | Out-File -FilePath $OutputFile -append
						"****************************************" | Out-File -FilePath $OutputFile -append
						"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
						"****************************************" | Out-File -FilePath $OutputFile -append
						"*" | Out-File -FilePath $OutputFile -append
						"The DirectAccess Server has both OTP Authentication enabled AND ForceTunnel enabled." | Out-File -FilePath $OutputFile -append
						"This may cause issues."  | Out-File -FilePath $OutputFile -append
						"Refer to Bemis 2956023 for more information."  | Out-File -FilePath $OutputFile -append
					}
					else
					{
						"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
						"The DirectAccess Server does NOT have both OTP Authentication enabled AND ForceTunnel enabled." | Out-File -FilePath $OutputFile -append
						"Refer to Bemis 2956023 for more information."  | Out-File -FilePath $OutputFile -append
					}
				}
			}
		}
		else
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"This check only applies to W8/WS2012 and W8.1/WS2012R2." | Out-File -FilePath $OutputFile -append		
		}
		'--------------------' | Out-File -FilePath $OutputFile -append
		"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
#----------------------------------------------------
# DirectAccess Server Hotfix Detection
#----------------------------------------------------
"`n`n" | Out-File -FilePath $OutputFile -append
"=========================================================" | Out-File -FilePath $OutputFile -append
" DirectAccess Server Hotfix Detection: W7/WS2008R2, W8/WS2012, and W8.1/WS2012R2" | Out-File -FilePath $OutputFile -append
"=========================================================" | Out-File -FilePath $OutputFile -append
"`n`n" | Out-File -FilePath $OutputFile -append

	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2859347
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2859347" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2859347`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9200)
	{
		if (CheckMinimalFileVersion "$env:windir\system32\Raconfigtask.dll " 6 2 9200 20737)
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2859347 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{						
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2859347 is not installed." | Out-File -FilePath $OutputFile -append
			"Check for the configuration Alert above named `"DirectAccess Server: Checking for `"DNS64 AcceptInterface does not have the DNS64 IP address bound.`" `"." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2859347 - IPv6 address of a DirectAccess server binds to the wrong network interface in Windows Server 2012" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2859347/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2788525
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2788525" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2788525`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9200)
	{
		if ((CheckMinimalFileVersion "$env:windir\system32\wbem\RAMgmtPSProvider.dll" 6 2 9200 20580) -and
		    (CheckMinimalFileVersion "$env:windir\system32\damgmt.dll" 6 2 9200 20580))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2788525 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2788525 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2788525 - You cannot enable external load balancing on a Windows Server 2012-based DirectAccess server" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2788525/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2782560
	#   (with LDRGDR detection)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2782560" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2782560`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9200)
	{
		if ((CheckMinimalFileVersion "$env:windir\system32\Firewallapi.dll" 6 2 9200 16455 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Firewallapi.dll" 6 2 9200 20559 -LDRGDR) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Icfupgd.dll" 6 2 9200 16455 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Icfupgd.dll" 6 2 9200 20559 -LDRGDR) -and
		    (CheckMinimalFileVersion "$env:windir\system32\drivers\Mpsdrv.sys" 6 2 9200 16455 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\drivers\Mpsdrv.sys" 6 2 9200 20559 -LDRGDR)  -and
		    (CheckMinimalFileVersion "$env:windir\system32\Mpssvc.dll" 6 2 9200 16455 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Mpssvc.dll" 6 2 9200 20559 -LDRGDR)  -and
		    (CheckMinimalFileVersion "$env:windir\system32\Wfapigp.dll" 6 2 9200 16455 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Wfapigp.dll" 6 2 9200 20559 -LDRGDR)) 
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2782560 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2782560 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2782560 - Clients cannot connect to IPv4-only resources when you use DirectAccess and external load balancing in Windows Server 2012" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2782560/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2748603 --> NOT A HOTFIX - THIS IS A WORKAROUND
	#----------------------------------------
	# 2748603 - The process may fail when you try to enable Network Load Balancing in DirectAccess in Window Server 2012
	# http://support.microsoft.com/kb/2748603/EN-US

	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2836232
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2836232" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2836232`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9200)
	{
		if (CheckMinimalFileVersion "$env:windir\system32\wbem\Ramgmtpsprovider.dll" 6 2 9200 20682)
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2836232 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2836232 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2836232 - Subnet mask changes to an incorrect value and the server goes offline in DirectAccess in Windows Server 2012" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2836232/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2849568
	#   (with LDRGDR detection)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2849568" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2849568`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9200)
	{
		if ((CheckMinimalFileVersion "$env:windir\system32\drivers\Winnat.sys" 6 2 9200 16654) -and (CheckMinimalFileVersion "$env:windir\system32\drivers\Winnat.sys" 6 2 9200 20762))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2849568 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2849568 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2849568 - MS13-064: Vulnerability in the Windows NAT driver could allow denial of service: August 13, 2013" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2849568/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}

	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2765809
	#   (with LDRGDR detection)
	#   (W7/WS2008R2 and W8/WS2012)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2765809" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2765809`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9200)
	{
		# WS2012 (many files in the fix - checking the following)
		# Adhapi.dll  6.2.9200.16449;				Adhapi.dll  6.2.9200.20553
		# Adhsvc.dll  6.2.9200.16449;				Adhsvc.dll  6.2.9200.20553
		# Httpprxm.dll  6.2.9200.16449;				Httpprxm.dll  6.2.9200.20553  
		# Httpprxp.dll  6.2.9200.16449;				Httpprxp.dll  6.2.9200.20553
		# Iphlpsvc.dll  6.2.9200.16449;				Iphlpsvc.dll  6.2.9200.20553  
		# Iphlpsvcmigplugin.dll  6.2.9200.16449;	Iphlpsvcmigplugin.dll  6.2.9200.20553
		# Keepaliveprovider.dll  6.2.9200.16449;	Keepaliveprovider.dll  6.2.9200.20553  
		# Ncbservice.dll  6.2.9200.16449;			Ncbservice.dll  6.2.9200.20553  
		# Netdacim.dll  6.2.9200.16449;				Netdacim.dll  6.2.9200.20553  
		# Netnccim.dll  6.2.9200.16449;				Netnccim.dll  6.2.9200.20553  
		# Netttcim.dll  6.2.9200.16449;				Netttcim.dll  6.2.9200.20553  
		#
		if ((CheckMinimalFileVersion "$env:windir\system32\Adhapi.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Adhapi.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Adhsvc.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Adhsvc.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Httpprxm.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Httpprxm.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Httpprxp.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Httpprxp.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Keepaliveprovider.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Keepaliveprovider.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Ncbservice.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Ncbservice.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Netdacim.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Netdacim.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Netnccim.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Netnccim.dll" 6 2 9200 20553 -LDRGDR) -and 
		    (CheckMinimalFileVersion "$env:windir\system32\Netttcim.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Netttcim.dll" 6 2 9200 20553 -LDRGDR))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	elseif ($bn -eq 7601)
	{
		#
		# WS2008R2 RTM x64
		# Iphlpsvc.dll 6.1.7600.17157; Iphlpsvc.dll 6.1.7600.21360
		# Iphlpsvcmigplugin.dll 6.1.7600.16385
		#
		# WS2008R2 RTM x86
		# windir\system32\migration\
		#  Iphlpsvcmigplugin.dll 6.1.7600.17157; Iphlpsvcmigplugin.dll 6.1.7600.21360
		# 
		# WS2008R2 SP1 x64
		# Iphlpsvc.dll  6.1.7601.17989; Iphlpsvc.dll  6.1.7601.22150 
		# windir\system32\migration\
		#  Iphlpsvcmigplugin.dll  6.1.7601.17989; Iphlpsvcmigplugin.dll  6.1.7601.22150  
		# windir\SysWOW64\
		#  Netcorehc.dll  6.1.7601.17989; Netcorehc.dll  6.1.7601.22150
		# x86 files
		# windir\system32\migration\
		#  Iphlpsvcmigplugin.dll  6.1.7601.17989; Iphlpsvcmigplugin.dll  6.1.7601.22150 
		# windir\SysWOW64\
		#   Netcorehc.dll  6.1.7601.17989; Netcorehc.dll  6.1.7601.22150
		#

		#x64
		if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7601 17989 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7601 22150 -LDRGDR) -and
		    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7601 17989 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7601 22150 -LDRGDR) -and
		    (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 1 7601 17989 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 1 7601 22150 -LDRGDR) -and	
		    (CheckMinimalFileVersion "$env:windir\system32\Netcorehc.dll" 6 1 7601 17989 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Netcorehc.dll" 6 1 7601 22150 -LDRGDR)) 
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is not installed." | Out-File -FilePath $OutputFile -append
		}	
	}
	elseif ($bn -eq 7600)
	{
		if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7600 17157 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 1 7600 21360 -LDRGDR) -and
		    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 1 7600 16385) -and
		    (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 1 7600 17157 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 1 7600 21360 -LDRGDR))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W7/WS2008R2 and W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2765809 - MS12-083: Vulnerability in IP-HTTPS component could allow security feature bypass: December 11, 2012" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2765809/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2855269
	#  (Backport for W7/WS2008R2 due Dec2013)
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Server: Hotfix verification for KB 2855269" | WriteTo-StdOut	
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2855269`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9600)
	{
		# W8.1 version of DaOtpCredentialProvider.dll is 6.3.9600.16384
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix does not apply to W8.1/WS2012R2." | Out-File -FilePath $OutputFile -append
	}
	elseif ($bn -eq 9200)
	{
		# "Checking for existence of Daotpauth.dll or Daotpcredentialprovider.dll." | Out-File -FilePath $OutputFile -append
		#   DAServer: Daotpauth.dll
		#   DAClient: Daotpcredentialprovider.dll
		
		# If the OS is a Server SKU
		if (($ProductType -eq 2) -or ($ProductType -eq 3))
		{		
			If (Test-path "$env:windir\system32\Daotpauth.dll")
			{
				if ($OSArchitecture -eq "AMD64")
				{
					if (CheckMinimalFileVersion "$env:windir\system32\Daotpauth.dll" 6 2 9200 20732)  
					{
						"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
						"Hotfix KB 2855269 is installed." | Out-File -FilePath $OutputFile -append
					}
					else
					{
						"*" | Out-File -FilePath $OutputFile -append
						"****************************************" | Out-File -FilePath $OutputFile -append
						"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
						"****************************************" | Out-File -FilePath $OutputFile -append
						"*" | Out-File -FilePath $OutputFile -append
						"Hotfix KB 2855269 is not installed." | Out-File -FilePath $OutputFile -append
					}
				}
				<#
					"Which files exists?" | Out-File -FilePath $OutputFile -append
					If (Test-path "$env:windir\system32\Daotpauth.dll")
					{ "Daotpauth.dll found in windir\system32." | Out-File -FilePath $OutputFile -append }
					else
					{ "Daotpauth.dll NOT found in windir\system32." | Out-File -FilePath $OutputFile -append }
					
					If (Test-path "$env:windir\system32\Daotpcredentialprovider.dll")
					{ "Daotpcredentialprovider.dll found in windir\system32." | Out-File -FilePath $OutputFile -append }
					else
					{ "Daotpcredentialprovider.dll NOT found in windir\system32." | Out-File -FilePath $OutputFile -append }
				#>
			}
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix does not apply to W7/WS2008R2" | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append			
	"2855269 - Error message when you use an account that contains a special character in its DN to connect to a Windows Server 2012-based Direct Access server" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2855269/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2845152
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2845152" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2845152`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9200)
	{
		if (CheckMinimalFileVersion "$env:windir\system32\drivers\Winnat.sys" 6 2 9200 20711) 
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2845152 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2845152 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2845152 - DirectAccess server cannot ping a DNS server or a domain controller in Windows Server 2012" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2845152/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2844033
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2844033" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2844033`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9200)
	{
		if ((CheckMinimalFileVersion "$env:windir\system32\Damgmt.dll" 6 2 9200 20708) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Ramgmtui.exe" 6 2 9200 20708))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2844033 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2844033 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2844033 - Add an Entry Point Wizard fails on a Windows Server 2012-based server in a domain that has a disjoint namespace" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2844033/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2796394
	#----------------------------------------
	if ($true)
	{
	"[info] DirectAccess Client: Hotfix verification for KB 2796394" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2796394`"" | Out-File -FilePath $OutputFile -append
	if ($bn -eq 9200)
	{
		if (CheckMinimalFileVersion "$env:windir\system32\Ramgmtpsprovider.dll" 6 2 9200 20588)
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2796394 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2796394 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2796394 - Error when you run the Get-RemoteAccess cmdlet during DirectAccess setup in Windows Server 2012 Essentials" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2796394/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	}

	#----------------------------------------
	# DirectAccess Server: Hotfix Verification for KB 2769240
	#----------------------------------------
	# Implemented in the DirectAccess Server section

	#----------------------------------------
	# DirectAccess Client-Server: Hotfix Verification for KB 2795944
	#----------------------------------------
	if ($true)
	{
	# This is the "W8/WS2012 Cumulative Update Package Feb2013"
	# ton of files in this update...
	"[info] DirectAccess Client: Hotfix verification for KB 2795944" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2795944`"" | Out-File -FilePath $OutputFile -append
	
	if ($bn -eq 9200)
	{
		# file versions identical for x64/x86
		#
		# Iphlpsvc.dll  6.2.9200.16496;  ;6.2.9200.20604  
		# Iphlpsvcmigplugin.dll  6.2.9200.16496;  ;6.2.9200.20604
		# Ncbservice.dll  6.2.9200.16449  
		# Netprofm.dll  6.2.9200.16496;  ;6.2.9200.20604 		
		#
		if ((CheckMinimalFileVersion "$env:windir\system32\Iphlpsvc.dll" 6 2 9200 16496 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\syswow64\Iphlpsvc.dll" 6 2 9200 20604 -LDRGDR) -and
		    (CheckMinimalFileVersion "$env:windir\system32\migration\Iphlpsvcmigplugin.dll" 6 2 9200 16496) -and (CheckMinimalFileVersion "$env:windir\syswow64\migration\Iphlpsvcmigplugin.dll" 6 2 9200 20604) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Ncbservice.dll" 6 2 9200 16449) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Netprofm.dll" 6 2 9200 16449 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Netprofm.dll" 6 2 9200 20604 -LDRGDR))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is not installed." | Out-File -FilePath $OutputFile -append
		}	
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2795944 - Windows 8 and Windows Server 2012 update rollup: February 2013" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2795944/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}

	#----------------------------------------
	# DirectAccess Client/Server: Hotfix Verification for KB 2779768
	#----------------------------------------
	if ($true)
	{
	# This is the "W8/WS2012 Cumulative Update Package Dec2013"
	# ton of files in this update...
	"[info] DirectAccess Client: Hotfix verification for KB 2779768" | WriteTo-StdOut		
	'--------------------' | Out-File -FilePath $OutputFile -append
	"Rule: Checking for `"Hotfix KB 2779768`"" | Out-File -FilePath $OutputFile -append
	
	if ($bn -eq 9200)
	{
		# x86
		# Checking 4 specific fixes:
		#   Bfe.dll  6.2.9200.16451; 6.2.9200.20555
		#   Http.sys  6.2.9200.16451; 6.2.9200.20555
		#   Ikeext.dll  6.2.9200.16451; 6.2.9200.20555  
		#
		if ((CheckMinimalFileVersion "$env:windir\system32\Bfe.dll" 6 2 9200 16451 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Bfe.dll" 6 2 9200 20555 -LDRGDR) -and
		    (CheckMinimalFileVersion "$env:windir\system32\drivers\Http.sys" 6 2 9200 16451 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\drivers\Http.sys" 6 2 9200 20555 -LDRGDR) -and
		    (CheckMinimalFileVersion "$env:windir\system32\Ikeext.dll" 6 2 9200 16451 -LDRGDR) -and (CheckMinimalFileVersion "$env:windir\system32\Ikeext.dll" 6 2 9200 20555 -LDRGDR))
		{
			"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is installed." | Out-File -FilePath $OutputFile -append	
		}
		else
		{
			"*" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"***** ALERT!!! Root cause detected.*****" | Out-File -FilePath $OutputFile -append
			"****************************************" | Out-File -FilePath $OutputFile -append
			"*" | Out-File -FilePath $OutputFile -append
			"Hotfix KB 2765809 is not installed." | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Root cause NOT detected." | Out-File -FilePath $OutputFile -append
		"Hotfix only applies to W8/WS2012." | Out-File -FilePath $OutputFile -append		
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"For more information reference the KB:" | Out-File -FilePath $OutputFile -append
	"2795944 - Windows 8 and Windows Server 2012 update rollup: February 2013" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2795944/EN-US" | Out-File -FilePath $OutputFile -append
	'--------------------' | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	}
	
	#----------------------------------------
	# Collect _ALERTS output file
	#----------------------------------------
	CollectFiles -filesToCollect $OutputFile -fileDescription "DirectAccess Server ALERTS" -SectionDescription $sectionDescription
}


$sectionDescription = "Diagnostic Version"
$OutputFile= "DiagnosticVersion_DA.TXT"
"`n"											| Out-File -FilePath $OutputFile -append
"Diagnostic  : DirectAccess Diagnostic"			| Out-File -FilePath $OutputFile -append
"Publish Date: 10.20.14"						| Out-File -FilePath $OutputFile -append
"`n`n`n"											| Out-File -FilePath $OutputFile -append
CollectFiles -filesToCollect $OutputFile -fileDescription "Diagnostic Version" -SectionDescription $sectionDescription	

$sectionDescription = "DirectAccess Diagnostic"
		
#----------------------------------------
#----- Static Data Collection BEGIN
#-----
#DirectAccessStatic:BEGIN
If ($ResultsCollectionType -eq "DirectAccessStatic"){
	"[info] User chose Static Data Collection" | WriteTo-StdOut
	#_# $ResultsClientOrServer = Get-DiagInput -Id "DirectAccessClientOrServer"
	#_# DirectAccessCli -or- DirectAccessSrv
	if ($Global:RoleType) {$Script:ResultsClientOrServer = $Global:RoleType} else {
		MenuDiagInput_CliSrv
		DiagInput_ClientServer
	}
	write-host "   ResultsClientOrServer:  $Script:ResultsClientOrServer "
	If ($Script:ResultsClientOrServer -eq "DirectAccessCli"){
		"[info] User chose DirectAccess Client for Static Data Collection" | WriteTo-StdOut
		DAClientInfo
		DASharedNetInfo
		DAGeneralInfo
		"[info] DAClientAlerts starting" | WriteTo-StdOut
		DAClientAlerts
	}

	If ($Script:ResultsClientOrServer -eq "DirectAccessSrv"){
		"[info] User chose DirectAccess Server for Static Data Collection" | WriteTo-StdOut
		DAServerInfo
		DASharedNetInfo
		DAGeneralInfo
		"[info] DAServerAlerts starting" | WriteTo-StdOut
		DAServerAlerts
	}	
}
#DirectAccessStatic:END



#----------------------------------------
#----- Interactive Data Collection BEGIN
#-----
#DirectAccessInteractive:BEGIN
If ($ResultsCollectionType -eq "DirectAccessInteractive"){
	"[info] User chose Interactive Data Collection" | WriteTo-StdOut
	"[info] Launching dialog to choose Client or Server." | WriteTo-StdOut	
	#_# $ResultsClientOrServer = Get-DiagInput -Id "DirectAccessClientOrServer"
	#_# DirectAccessCli -or- DirectAccessSrv
	if ($Global:RoleType) {$Script:ResultsClientOrServer = $Global:RoleType} else {
		MenuDiagInput_CliSrv
		DiagInput_ClientServer
	}
	#----------------------------------------
	# DirectAccess Client: Interactive
	#----------------------------------------
	If ($Script:ResultsClientOrServer -eq "DirectAccessCli"){
		"[info] User chose DirectAccess Client" | WriteTo-StdOut
		"[info] Prompting user to start tracing." | WriteTo-StdOut	
		#_# $ResultsDirectAccessClientD1 = Get-DiagInput -Id "DirectAccessCliStart"		# Pause dialog
		Write-Host "`n$(Get-Date -Format "HH:mm:ss") === Press the 's' key to start tracing. ===`n" -ForegroundColor Green
		do {
			$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
		} until ($x.Character -ieq 's')

		
		#----------------------------------------
		# DirectAccess Client: Start Logging (CAPI, SChannel(Verbose), OTP, NCASvc, and NCSI Eventlogs)
		#----------------------------------------
		#
		#-----Enable CAPI2 logging (added 6/5/2013)
		#Detect CAPI2 logging state
			#reg query HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational /v Enabled
			"[info] Reading the CAPI2 EventLogging registry value." | WriteTo-StdOut	
				$capi2RegKeyLocation = "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational"
				$capi2OrigStatus = (Get-ItemProperty $capi2RegKeyLocation).EventLogging
				$capi2NewStatus = $capi2OrigStatus

		# Set CAPI2 logging to enabled
			if ($capi2OrigStatus -ne "1"){
				"[info] Setting CAPI2 Enabled registry value to 1" | WriteTo-StdOut
					#enable CAPI2 logging by setting registry value
					# reg.exe ; reg add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational /v Enabled /f /t REG_DWORD /d 0x1
					# pscmdlet; Set-ItemProperty $capi2RegKeyLocation Enabled 1
				
					#enable CAPI2 logging using wevtutil
					$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true"
					RunCmD -commandToRun $CommandToExecute  -CollectFiles $false

					$capi2NewStatus = (Get-ItemProperty $capi2RegKeyLocation).Enabled
			}

		
		#-----SCHANNEL EVENTLOG: State and Set to 7 (added 11/1/2013)
		#Detect Schannel logging state
			#reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel /v EventLogging 
			"[info] Reading the Schannel EventLogging registry value." | WriteTo-StdOut	
				$schannelRegKeyLocation = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel"
				$schannelOrigStatus = (Get-ItemProperty $schannelRegKeyLocation).EventLogging
				$schannelNewStatus = $schannelOrigStatus
			"[info] schannelOrigStatus: $schannelOrigStatus" | WriteTo-StdOut	

		# Set SChannel logging to verbose
			if ($schannelOrigStatus -ne "7")
			{
				#reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel /v EventLogging /f /t REG_DWORD /d 0x7
				"[info] Setting SChannel EventLogging registry value to 7 for verbose logging" | WriteTo-StdOut
					Set-ItemProperty $schannelRegKeyLocation EventLogging 7
					$schannelNewStatus = (Get-ItemProperty $schannelRegKeyLocation).EventLogging
			}
		
		#
		#-----Enable OTPCredentialProvider event logging (added 5/29/14)
		#Detect OTPCredentialProvider logging state
			#reg query HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational /v Enabled
			"[info] Reading the CAPI2 EventLogging registry value." | WriteTo-StdOut	
				$otpRegKeyLocation = "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational"
				$otpOrigStatus = (Get-ItemProperty $otpRegKeyLocation).Enabled
				$otpNewStatus = $otpOrigStatus

			# Set OTP logging to enabled
			if ($otpOrigStatus -ne "1")
			{
				"[info] Setting CAPI2 Enabled registry value to 1" | WriteTo-StdOut
					#enable OTP logging by setting registry value
					# reg.exe ; reg add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational /v Enabled /f /t REG_DWORD /d 0x1
					# pscmdlet; Set-ItemProperty $otpRegKeyLocation Enabled 1
				
					#enable OTP logging using wevtutil
					$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-OtpCredentialProvider/Operational /e:true"
					RunCmD -commandToRun $CommandToExecute  -CollectFiles $false

					$otpNewStatus = (Get-ItemProperty $capi2RegKeyLocation).Enabled
			}
			
			#Enabling Ncasvc and NCSI logging
			$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-Ncasvc/Operational /e:true"
			RunCmD -commandToRun $CommandToExecute  -CollectFiles $false			
			$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-NCSI/Operational /e:true"
			RunCmD -commandToRun $CommandToExecute  -CollectFiles $false

					
			
		#----------------------------------------
		# DirectAccess Client: Start Logging (Netsh Trace, Netsh WFP, PSR, DNS Cache, Restart IP Helper Service)
		#----------------------------------------
		#
		if ($OSVersion.Build -gt 7000){
			#----------Netsh Trace: DirectAccess Scenario: START logging
				"[info] Starting Netsh Trace logging." | WriteTo-StdOut	
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1StartTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1StartDesc
				$OutputFileNetshTraceETL = "netshtrace.etl"
				$OutputFileNetshTraceCAB = "netshtrace.cab"
				$CommandToExecute = "cmd.exe /c netsh.exe trace start scenario=DirectAccess tracefile=netshtrace.etl capture=yes"
				RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
			#----------Netsh WFP Capture: START logging
				"[info] Starting Netsh WFP logging." | WriteTo-StdOut	
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2StartTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2StartDesc
				$OutputFileWFP = "wfpdiag.cab"
				# For some reason this hangs when running in powershell
					# $CommandToExecute = "cmd.exe /c netsh.exe wfp capture start"
					# RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
				# Therefore, I'm using this method to launch WFP logging in the background.
				$ProcessArgs =  " /c netsh.exe wfp capture start"
				BackgroundProcessCreate -Process "cmd.exe" -Arguments $ProcessArgs			
			#----------PSR: Start Problem Steps Recorder
				"[info] Starting problem steps recorder." | WriteTo-StdOut	
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3StartTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3StartDesc
				$OutputFilePathPSR = join-path $PWD.path "IssueSteps.zip"
				$OutputFilePSR = "IssueSteps.zip"
				$ProcessName = "cmd.exe"
				$Arguments = "/c start /MIN psr /start /output " + $OutputFilePathPSR + " /maxsc 65 /exitonsave 1"
				$Process = ProcessCreate -Process $ProcessName -Arguments $Arguments
				"[info] PSR should be started." | WriteTo-StdOut	
				
			#----------Clearing DNS Cache 
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCli_DnsClientClearCacheTitle -Status $ScriptVariable.ID_CTSDirectAccessCli_DnsClientClearCacheDesc
				$CommandToExecute = "cmd.exe /c ipconfig /flushdns"
				RunCmD -commandToRun $CommandToExecute  -CollectFiles $false

			
			#----------IP Helper Logging: Enable
				Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Tracing\IpHlpSvc" FileTracingMask -Value 0xffffffff -force
				Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Tracing\IpHlpSvc" MaxFileSize -Value 0x10000000 -force
				Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Tracing\IpHlpSvc" EnableFileTracing -Value 1 -force
				
			#----------Restarting the IP Helper service
				# Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCli_RestartingIpHlpSvcTitle -Status $ScriptVariable.ID_CTSDirectAccessCli_RestartingIpHlpSvcDesc
				# Stop-Service iphlpsvc -Force
				# Start-Service iphlpsvc

				# Notes:
				#  Currently the IP Helper service is having issues when it is restarting. On several occasions, we have seen the IP Helper service fail to restart due to hanging in a STOPPING state.
		}

		#----------------------------------------
		# DirectAccess Client: Start Logging: ETLTraceCollector: OTP
		#----------------------------------------
		#		
		if ($OSVersion.Build -gt 7000){
			#----------OTP: Start OTP logging
			"[info] OTP section: if OTP is enabled, start logging." | WriteTo-StdOut	
			$regkeyOtpCredentialProvider = "HKLM:\SOFTWARE\Policies\Microsoft\OtpCredentialProvider"
			if (Test-Path $regkeyOtpCredentialProvider){
				if ((Get-ItemProperty -Path $regkeyOtpCredentialProvider)."Enabled" -eq "1"){
					#----------OTP: Start OTP logging
						# OTP ETL tracing
							# logman create trace "OTP" -ow -o c:\OTPTracing.etl -p {xxx} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets 
							"[info] Starting ETL tracing for OTP using XML file." | WriteTo-StdOut	
								$OTP_outfile = "OTP.etl"
								$OTPOutputFileNames = @($OTP_outfile)
								$OTPFileDescriptions = @("OTP")
								$OTPSectionDescriptions = @("OTP Tracing")
								$OTPETL = .\TS_ETLTraceCollector.ps1 -StartTrace -DataCollectorSetXMLName "OTPTrace.XML" -ComponentName "OTP" -OutputFileName $OTPOutputFileNames -DoNotPromptUser
								RunCmD -commandToRun $OTPETL -CollectFiles $false
							"[info] ETL tracing for OTP should be running." | WriteTo-StdOut	
				}
			}
			else{
				"[info] OTP is not enabled on this client." | WriteTo-StdOut	
			}
		}
		
		#----------------------------------------
		# DirectAccess Client: Start Logging: ETLTraceCollector: SChannel
		#----------------------------------------
		#		
		if ($OSVersion.Build -gt 7000){			
			#----------SChannel: Start SChannel logging
				"[info] SChannel ETL tracing section" | WriteTo-StdOut
				#Enable Schannel ETL tracing
				# logman -start schannel -p {37d2c3cd-c5d4-4587-8531-4696c44244c8} 0x4000ffff 3 -ets
				"[info] Starting ETL tracing for schannel using XML file." | WriteTo-StdOut	
					$schannel_outfile = "schannel.etl"
					$schannelOutputFileNames = @($SChannel_outfile)
					$schannelFileDescriptions = @("SChannel")
					$schannelSectionDescriptions = @("SChannel Component")
					$schannelDCS = .\TS_ETLTraceCollector.ps1 -StartTrace -DataCollectorSetXMLName "schannel.XML" -ComponentName "SChannel" -OutputFileName $SChannelOutputFileNames -DoNotPromptUser
				"[info] ETL tracing for schannel should be running." | WriteTo-StdOut
		}

		#----------------------------------------
		# DirectAccess Client: Prompt to Stop Logging
		#----------------------------------------
		#
		if ($OSVersion.Build -gt 7000){
			# Pause interaction to stop logging
			"[info] Launching dialog prompting the user to Stop tracing." | WriteTo-StdOut	

			#_# $ResultsDirectAccessCliStop = Get-DiagInput -Id "DirectAccessCliStop"
			Write-Host "`n$(Get-Date -Format "HH:mm:ss") === Press the 's' key to stop tracing. ===`n" -ForegroundColor Green
			do {
				$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
			} until ($x.Character -ieq 's')
		}

		#----------------------------------------
		# DirectAccess Client: Stop Logging (Netsh Trace, Netsh WFP, PSR)
		#----------------------------------------
		#
		if ($OSVersion.Build -gt 7000){	
			#----------Netsh Trace DirectAccess Scenario: STOP logging
				"[info] Stopping Netsh Trace logging." | WriteTo-StdOut	
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1StopTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1StopDesc
				$CommandToExecute = "cmd.exe /c netsh.exe trace stop"
				RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
			#----------Netsh WFP Capture: STOP logging
				"[info] Stopping Netsh WFP logging." | WriteTo-StdOut	
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2StopTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2StopDesc
				$CommandToExecute = "cmd.exe /c netsh.exe wfp capture stop"
				RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
			#----------PSR: STOP Problem Steps Recorder
				"[info] Stopping problem steps recorder." | WriteTo-StdOut	
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3StopTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3StopDesc
				$ProcessName = "cmd.exe"
				$Arguments = "/c start /MIN psr.exe /stop"
				$Process = ProcessCreate -Process $ProcessName -Arguments $Arguments
		}

		#----------------------------------------
		# DirectAccess Client: Stop Logging (CAPI2 and Schannel Eventlogs)
		#----------------------------------------
		#
		if ($OSVersion.Build -gt 7000){
			#----------------------------------------
			# DirectAccess Client: Stop Logging (CAPI2 and Schannel)
			#----------------------------------------
			#
			#-----CAPI2 EVENTLOG: Set to original state
			"[info] Setting CAPI2 Eventlog status back to original status." | WriteTo-StdOut
			$capi2RegKeyLocation = "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational"
			if ($capi2OrigStatus -ne "1"){
				#disable CAPI2 logging using wevtutil
				$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-CAPI2/Operational /e:false"
				RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
				
				#disable CAPI2 logging using the registry
				# Set-ItemProperty -path $capi2RegKeyLocation Enabled $capi2OrigStatus
			}
			
			#----------------------------------------
			# DirectAccess Client: Collect Eventlog (CAPI2)
			#----------------------------------------
			#
			$EventLogNames = "Microsoft-Windows-CAPI2/Operational"
			$Prefix = ""
			$Suffix = "_evt_"
			.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription "Certificates Information" -Prefix $Prefix -Suffix $Suffix
			
			#-----SCHANNEL EVENTLOG: Set to original state
			"[info] Setting Schannel Event logging back to original status." | WriteTo-StdOut
			$schannelRegKeyLocation = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel"
			Set-ItemProperty -path $schannelRegKeyLocation EventLogging $schannelOrigStatus
			
			#
			#-----OTP EVENTLOG: Set to original state
			"[info] Setting CAPI2 Eventlog status back to original status." | WriteTo-StdOut
			$otpRegKeyLocation = "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational"
			if ($otpOrigStatus -ne "1"){
				#disable OTP logging using wevtutil
				$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-OtpCredentialProvider/Operational /e:false"
				RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
				
				#disable OTP logging using the registry
				# Set-ItemProperty -path $capi2RegKeyLocation Enabled $otpOrigStatus
			}
		
			#----------------------------------------
			# Collect Eventlog (OTP)
			#----------------------------------------
			#
			$EventLogNames = "Microsoft-Windows-OtpCredentialProvider/Operational"
			$Prefix = ""
			$Suffix = "_evt_"
			.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription "OTP" -Prefix $Prefix -Suffix $Suffix
		}
		
		#----------------------------------------
		# DirectAccess Client: IP Helper Logging: Disable (Added 4/1/14)
		#----------------------------------------
		#
			Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Tracing\IpHlpSvc" EnableFileTracing -Value 0 -force
		
		#----------------------------------------
		# DirectAccess Client: Save DNS Client cache using ipconfig /displaydns
		#----------------------------------------
		#
			Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCli_SaveDnsClientCacheTitle -Status $ScriptVariable.ID_CTSDirectAccessCli_SaveDnsClientCacheDesc
			$OutputFileDnsClientCache = $Computername + "_DirectAccessClient_DnsClientCache_ipconfig-displaydns.TXT"
			$CommandToExecute = "cmd.exe /c ipconfig /displaydns > $OutputFileDnsClientCache"
			RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
			
		#----------------------------------------
		# DirectAccess Client: Stop Logging: ETLTraceCollector: OTP
		#----------------------------------------
		#			
		if ($OSVersion.Build -gt 7000){		
			#----------OTP: Stop OTP logging
			"[info] Stopping OTP ETL logging." | WriteTo-StdOut	
			$regkeyOtpCredentialProvider = "HKLM:\SOFTWARE\Policies\Microsoft\OtpCredentialProvider"
			if (Test-Path $regkeyOtpCredentialProvider){
				if ((Get-ItemProperty -Path $regkeyOtpCredentialProvider)."Enabled" -eq "1"){
					#----------OTP: Stop OTP logging
					# OTP ETL Logging
					# logman stop "OTP" -ets
					"[info] Stopping OTP ETL logging." | WriteTo-StdOut
					Run-DiagExpression .\TS_ETLTraceCollector.ps1 -StopTrace -DataCollectorSetObject $OTPETL -OutputFileName $OTPOutputFileNames -FileDescription $OTPFileDescriptions -SectionDescription $OTPSectionDescriptions -DoNotPromptUser -DisableRootcauseDetected
					"[info] OTP ETL logging should be stopped now." | WriteTo-StdOut			
				}
			}
		}
		
		#----------------------------------------
		# DirectAccess Client: Stop Logging: ETLTraceCollector: Schannel
		#----------------------------------------
		#			
		if ($OSVersion.Build -gt 7000){			
			#-----SCHANNEL ETL Logging
				# logman -stop schannel -ets
				"[info] Stopping Schannel ETL logging." | WriteTo-StdOut
					Run-DiagExpression .\TS_ETLTraceCollector.ps1 -StopTrace -DataCollectorSetObject $SChannelDCS -OutputFileName $SChannelOutputFileNames -FileDescription $SChannelFileDescriptions -SectionDescription $SChannelSectionDescriptions -DoNotPromptUser -DisableRootCauseDetected
				"[info] Schannel ETL logging should be stopped now." | WriteTo-StdOut
		}

		#----------------------------------------
		# DirectAccess Client: Collect Files
		#----------------------------------------
		#
		#----------Netsh Trace DirectAccess Scenario: Collect logging
			"[info] Collecting Netsh Trace output." | WriteTo-StdOut	
			Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1CollectTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1CollectDesc
			$sectionDescription = "Netsh Trace DirectAccess Scenario"
			CollectFiles -filesToCollect $OutputFileNetshTraceETL -fileDescription "Netsh Trace DirectAccess Scenario: ETL" -SectionDescription $sectionDescription
			CollectFiles -filesToCollect $OutputFileNetshTraceCAB -fileDescription "Netsh Trace DirectAccess Scenario: CAB" -SectionDescription $sectionDescription
		#----------Netsh WFP Capture: Collect logging
			"[info] Collecting Netsh WFP output." | WriteTo-StdOut	
			Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2CollectTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2CollectDesc
			$sectionDescription = "WFP Tracing"
			CollectFiles -filesToCollect $OutputFileWFP -fileDescription "WFP tracing" -SectionDescription $sectionDescription
		#----------PSR: Collect Problem Steps Recorder output
			"[info] Collecting problem steps recorder output." | WriteTo-StdOut	
			Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3CollectTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3CollectDesc
			$sectionDescription = "Problem Steps Recorder (PSR)"
			Start-Sleep 15
			CollectFiles -filesToCollect $OutputFilePSR -fileDescription "PSR logging" -SectionDescription $sectionDescription
			Start-Sleep 15
		#----------Collecting DNS Cache output
			"[info] Collecting DNS cache output." | WriteTo-StdOut	
			Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCli_CollectDnsClientCacheTitle -Status $ScriptVariable.ID_CTSDirectAccessCli_CollectDnsClientCacheDesc
			$sectionDescription = "DNS Client"
			CollectFiles -filesToCollect $OutputFileDnsClientCache -fileDescription "DNS Client cache" -SectionDescription $sectionDescription
		#----------IP Helper Logging: Collect (Added 04/01/14)			
			"[info] Collecting IP Helper log files." | WriteTo-StdOut
			$sectionDescription = "IP Helper service logging"
			$tracingdir = join-path $env:windir tracing
			$OutputFileIpHlpSvcLog = join-path $tracingdir "IpHlpSvc.Log"
			$OutputFileIpHlpSvcOld = join-path $tracingdir "IpHlpSvc.Old" 
			CollectFiles -filesToCollect $OutputFileIpHlpSvcLog -fileDescription "DirectAccess IpHlpSvc Log" -SectionDescription $sectionDescription
			CollectFiles -filesToCollect $OutputFileIpHlpSvcOld -fileDescription "DirectAccess IpHlpSvc Log (Old)" -SectionDescription $sectionDescription		
		#----------NetCfg ETL Logs: Collect (Added 08/12/14)
			$sectionDescription = "NetCfg Logs"
			$OutputDirectory = "$env:windir\inf\netcfg*.etl"
			$OutputFileNetCfgCab = "NetCfgETL.cab"
			CompressCollectFiles -DestinationFileName $OutputFileNetCfgCab -filesToCollect $OutputDirectory -sectionDescription $sectionDescription -fileDescription "NetCfg ETL Logs: CAB"

		#----------------------------------------
		# DirectAccess Client: Static Data Collection
		#----------------------------------------
		if ($true){
			DAClientInfo
			DASharedNetInfo
		}
		
		#----------------------------------------
		# DirectAccess Client Alerts
		#----------------------------------------
		if ($true){
			"[info] DAClientAlerts starting" | WriteTo-StdOut
			DAClientAlerts
		}
	} #DirectAccessClient:END
	
	#----------------------------------------
	# DirectAccess Server: Interactive
	#----------------------------------------
	If ($Script:ResultsClientOrServer -eq "DirectAccessSrv"){
		"[info] User chose DirectAccess Server" | WriteTo-StdOut
		"[info] DirectAccess Server section" | WriteTo-StdOut
		$sectionDescription = "DirectAccess Diagnostic"
		"[info] Launching dialog prompting the user to Start tracing." | WriteTo-StdOut	
		
		#_# $ResultsDirectAccessClientD1 = Get-DiagInput -Id "DirectAccessSrvStart"		# Pause Dialog
		Write-Host "`n$(Get-Date -Format "HH:mm:ss") === Press the 's' key to start tracing. ===`n" -ForegroundColor Green
		do {
			$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
		} until ($x.Character -ieq 's')
		
		#----------------------------------------
		# DirectAccess Server: Start Logging (CAPI and SChanne-Verbose Eventlogs)
		#----------------------------------------
		#

		#-----Enable CAPI2 logging (added 6/5/2013)
		#Detect CAPI2 logging state
			#reg query HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational /v Enabled
			"[info] Reading the CAPI2 EventLogging registry value." | WriteTo-StdOut	
				$capi2RegKeyLocation = "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational"
				$capi2OrigStatus = (Get-ItemProperty $capi2RegKeyLocation).EventLogging
				$capi2NewStatus = $capi2OrigStatus

		# Set CAPI2 logging to enabled
			if ($capi2OrigStatus -ne "1"){
				#reg add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational /v Enabled /f /t REG_DWORD /d 0x1
				"[info] Setting CAPI2 Enabled registry value to 1" | WriteTo-StdOut
					#enable CAPI2 logging using the registry
					#  Set-ItemProperty $capi2RegKeyLocation Enabled 1
					
					#enable CAPI2 logging using wevtutil
					$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true"
					RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
					$capi2NewStatus = (Get-ItemProperty $capi2RegKeyLocation).Enabled
			}
		
		#-----SCHANNEL EVENTLOG: State and Set to 7 (added 11/1/2013)
		#Detect Schannel logging state
			#reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel /v EventLogging 
			"[info] Reading the Schannel EventLogging registry value." | WriteTo-StdOut	
				$schannelRegKeyLocation = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel"
				$schannelOrigStatus = (Get-ItemProperty $schannelRegKeyLocation).EventLogging
				$schannelNewStatus = $schannelOrigStatus
			"[info] schannelOrigStatus: $schannelOrigStatus" | WriteTo-StdOut	

		# Set SChannel logging to verbose
			if ($schannelOrigStatus -ne "7"){
				#reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel /v EventLogging /f /t REG_DWORD /d 0x7
				"[info] Setting SChannel EventLogging registry value to 7 for verbose logging" | WriteTo-StdOut
					Set-ItemProperty $schannelRegKeyLocation EventLogging 7
					$schannelNewStatus = (Get-ItemProperty $schannelRegKeyLocation).EventLogging
			}

		#
		#-----Enable OTPCredentialProvider event logging (added 5/29/14)
		#Detect OTPCredentialProvider logging state
			#reg query HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational /v Enabled
			"[info] Reading the CAPI2 EventLogging registry value." | WriteTo-StdOut	
				$otpRegKeyLocation = "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational"
				$otpOrigStatus = (Get-ItemProperty $otpRegKeyLocation).Enabled
				$otpNewStatus = $otpOrigStatus

			# Set OTP logging to enabled
			if ($otpOrigStatus -ne "1"){
				"[info] Setting CAPI2 Enabled registry value to 1" | WriteTo-StdOut
					#enable OTP logging by setting registry value
					# reg.exe ; reg add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational /v Enabled /f /t REG_DWORD /d 0x1
					# pscmdlet; Set-ItemProperty $otpRegKeyLocation Enabled 1
				
					#enable OTP logging using wevtutil
					$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-OtpCredentialProvider/Operational /e:true"
					RunCmD -commandToRun $CommandToExecute  -CollectFiles $false

					$otpNewStatus = (Get-ItemProperty $capi2RegKeyLocation).Enabled
			}

		#Enabling Ncasvc and NCSI logging
		$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-Ncasvc/Operational /e:true"
		RunCmD -commandToRun $CommandToExecute  -CollectFiles $false			
		$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-NCSI/Operational /e:true"
		RunCmD -commandToRun $CommandToExecute  -CollectFiles $false			

		#----------------------------------------
		# DirectAccess Server: Start Logging (Netsh Trace, Netsh WFP, PSR)
		#----------------------------------------
		#
		if ($OSVersion.Build -gt 7000){
			#----------Netsh Trace: DirectAccess Scenario: START logging
				"[info] Starting Netsh Trace logging." | WriteTo-StdOut	
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1StartTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1StartDesc
				$OutputFileNetshTraceETL = "netshtrace.etl"
				$OutputFileNetshTraceCAB = "netshtrace.cab"
				$CommandToExecute = "cmd.exe /c netsh.exe trace start scenario=DirectAccess tracefile=netshtrace.etl capture=yes"
				RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
			#----------Netsh WFP Capture: START logging
				"[info] Starting Netsh WFP logging." | WriteTo-StdOut	
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2StartTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2StartDesc
				$OutputFileWFP = "wfpdiag.cab"
				# For some reason this hangs when running in powershell
					# $CommandToExecute = "cmd.exe /c netsh.exe wfp capture start"
					# RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
				# Therefore, I'm using this method to launch WFP logging in the background.
				$ProcessArgs =  " /c netsh.exe wfp capture start"
				BackgroundProcessCreate -Process "cmd.exe" -Arguments $ProcessArgs			
			#----------PSR: Start Problem Steps Recorder
				"[info] Starting problem steps recorder." | WriteTo-StdOut	
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3StartTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3StartDesc
				$OutputFilePathPSR = join-path $PWD.path "IssueSteps.zip"
				$OutputFilePSR = "IssueSteps.zip"
				$ProcessName = "cmd.exe"
				$Arguments = "/c start /MIN psr /start /output " + $OutputFilePathPSR + " /maxsc 65 /exitonsave 1"
				$Process = ProcessCreate -Process $ProcessName -Arguments $Arguments
			#----------IP Helper Logging: Enable
				Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Tracing\IpHlpSvc" FileTracingMask -Value 0xffffffff -force
				Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Tracing\IpHlpSvc" MaxFileSize -Value 0x10000000 -force
				Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Tracing\IpHlpSvc" EnableFileTracing -Value 1 -force
		}


		#----------------------------------------
		# DirectAccess Server: Start Logging: ETLTraceCollector
		#----------------------------------------
		#		
		if ($OSVersion.Build -gt 7000){
			#----------Kerberos: Start SecurityKerberos logging
				# SecurityKerberos ETL tracing
				# logman create trace "SecurityKerberos" -ow -o c:\SecurityKerberos.etl -p {xxx} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets 
				"[info] Starting ETL tracing for SecurityKerberos using XML file." | WriteTo-StdOut	
					$SecurityKerberos_outfile = "SecurityKerberos.etl"
					$SecurityKerberosOutputFileNames = @($SecurityKerberos_outfile)
					$SecurityKerberosFileDescriptions = @("SecurityKerberos")
					$SecurityKerberosSectionDescriptions = @("SecurityKerberos Tracing")
					$SecurityKerberosETL = .\TS_ETLTraceCollector.ps1 -StartTrace -DataCollectorSetXMLName "SecurityKerberos.XML" -ComponentName "SecurityKerberos" -OutputFileName $SecurityKerberosOutputFileNames -DoNotPromptUser
					# RunCmD -commandToRun $SecurityKerberosETL -CollectFiles $false
				"[info] ETL tracing for SecurityKerberos should be running." | WriteTo-StdOut

			#----------NTLM: Start SecurityNTLM logging
				# SecurityNTLM ETL tracing
				# logman create trace "SecurityNTLM" -ow -o c:\SecurityNTLM.etl -p {xxx} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets 
				"[info] Starting ETL tracing for SecurityNTLM using XML file." | WriteTo-StdOut	
					$SecurityNTLM_outfile = "SecurityNTLM.etl"
					$SecurityNTLMOutputFileNames = @($SecurityNTLM_outfile)
					$SecurityNTLMFileDescriptions = @("SecurityNTLM")
					$SecurityNTLMSectionDescriptions = @("SecurityNTLM Tracing")
					$SecurityNTLMETL = .\TS_ETLTraceCollector.ps1 -StartTrace -DataCollectorSetXMLName "SecurityNTLM.XML" -ComponentName "SecurityNTLM" -OutputFileName $SecurityNTLMOutputFileNames -DoNotPromptUser
					# RunCmD -commandToRun $SecurityNTLMETL -CollectFiles $false
				"[info] ETL tracing for SecurityNTLM should be running." | WriteTo-StdOut

			#----------OTP: Start OTP logging
				"[info] OTP section: if OTP is enabled, start logging." | WriteTo-StdOut
				$regkeyOtpEnabled = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteAccess\Config\Otp"
				if (Test-Path $regkeyOtpEnabled) {
					if ((Get-ItemProperty -Path $regkeyOtpEnabled)."Enabled" -eq "1"){
						"[info] Determining if OTP is enabled" | WriteTo-StdOut	
						$daOTPAuth = get-daotpauthentication
						$daOTPStatus = $daOTPAuth.otpstatus
						if($daOTPStatus -eq "enabled"){
							# OTP ETL tracing
							# logman create trace "OTP" -ow -o c:\OTPTracing.etl -p {xxx} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets 
							"[info] Starting ETL tracing for OTP using XML file." | WriteTo-StdOut	
								$OTP_outfile = "OTP.etl"
								$OTPOutputFileNames = @($OTP_outfile)
								$OTPFileDescriptions = @("OTP")
								$OTPSectionDescriptions = @("OTP Tracing")
								$OTPETL = .\TS_ETLTraceCollector.ps1 -StartTrace -DataCollectorSetXMLName "OTPTrace.XML" -ComponentName "OTP" -OutputFileName $OTPOutputFileNames -DoNotPromptUser
								# RunCmD -commandToRun $OTPETL -CollectFiles $false
							"[info] ETL tracing for OTP should be running." | WriteTo-StdOut	
						}
					}
				}
				else{
					"[info] OTP is not enabled on this server." | WriteTo-StdOut	
				}

			#----------------------------------------
			# DirectAccess Server: Start Logging: ETLTraceCollector: SChannel
			#----------------------------------------
			#		
			if ($OSVersion.Build -gt 7000){			
				#----------SChannel: Start SChannel logging
					"[info] SChannel ETL tracing section" | WriteTo-StdOut
					#Enable Schannel ETL tracing
					# logman -start schannel -p {37d2c3cd-c5d4-4587-8531-4696c44244c8} 0x4000ffff 3 -ets
					"[info] Starting ETL tracing for schannel using XML file." | WriteTo-StdOut	
						$schannel_outfile = "schannel.etl"
						$schannelOutputFileNames = @($SChannel_outfile)
						$schannelFileDescriptions = @("SChannel")
						$schannelSectionDescriptions = @("SChannel Component")
						$schannelDCS = .\TS_ETLTraceCollector.ps1 -StartTrace -DataCollectorSetXMLName "schannel.XML" -ComponentName "SChannel" -OutputFileName $SChannelOutputFileNames -DoNotPromptUser
					"[info] ETL tracing for schannel should be running." | WriteTo-StdOut
			}
			
			#----------------------------------------
			# DirectAccess Server: Start Logging: ETLTraceCollector: DASrvPSLogging
			#----------------------------------------
			#		
			if ($OSVersion.Build -gt 9000){			
				#----------DASrvPSLogging: Start DASrvPSLogging logging
					"[info] DASrvPSLogging ETL tracing section" | WriteTo-StdOut
					#Enable DASrvPSLogging ETL tracing
						#logman create trace ETWTrace -ow -o c:\ETWTrace.etl -p {6B510852-3583-4E2D-AFFE-A67F9F223438} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode 0x2 -max 2048 -ets 
						#logman update trace ETWTrace -p {62DFF3DA-7513-4FCA-BC73-25B111FBB1DB} 0xffffffffffffffff 0xff -ets 
						#logman update trace ETWTrace -p {AAD4C46D-56DE-4F98-BDA2-B5EAEBDD2B04} 0xffffffffffffffff 0xff -ets 
						#
					"[info] Starting ETL tracing for DASrvPSLogging using XML file." | WriteTo-StdOut	
						$DASrvPSLogging_outfile = "DASrvPSLogging.etl"
						$DASrvPSLoggingOutputFileNames = @($DASrvPSLogging_outfile)
						$DASrvPSLoggingFileDescriptions = @("DASrvPSLogging")
						$DASrvPSLoggingSectionDescriptions = @("DASrvPSLogging Section")
						$DASrvPSLoggingDCS = .\TS_ETLTraceCollector.ps1 -StartTrace -DataCollectorSetXMLName "DASrvPSLogging.XML" -ComponentName "DASrvPSLogging" -OutputFileName $DASrvPSLoggingOutputFileNames -DoNotPromptUser
					"[info] ETL tracing for DASrvPSLogging should be running." | WriteTo-StdOut
			}
		}
		
		#----------------------------------------
		# DirectAccess Server: Prompt to Stop Logging
		#----------------------------------------
		#
		if ($OSVersion.Build -gt 7000){
			# Pause interaction to stop logging
			#_# $ResultsDirectAccessCliStop = Get-DiagInput -Id "DirectAccessSrvStop"
			Write-Host "`n$(Get-Date -Format "HH:mm:ss") === Press the 's' key to stop tracing. ===`n" -ForegroundColor Green
			do {
				$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
			} until ($x.Character -ieq 's')
			
			"[info] User clicked Next on the Stop dialog." | WriteTo-StdOut				
		}
		
		#----------------------------------------
		# DirectAccess Server: Stop Logging (Netsh Trace, Netsh WFP, PSR)
		#----------------------------------------
		#		
		if ($OSVersion.Build -gt 7000){
			#----------Netsh Trace DirectAccess Scenario: STOP logging
				"[info] Stopping Netsh Trace logging." | WriteTo-StdOut
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1StopTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1StopDesc
				$CommandToExecute = "cmd.exe /c netsh.exe trace stop"
				RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
			#----------Netsh WFP Capture: STOP logging
				"[info] Stopping Netsh WFP logging." | WriteTo-StdOut
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2StopTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2StopDesc
				$CommandToExecute = "cmd.exe /c netsh.exe wfp capture stop"
				RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
			#----------PSR: STOP Problem Steps Recorder
				"[info] Stopping problem steps recorder." | WriteTo-StdOut
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3StopTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3StopDesc
				$ProcessName = "cmd.exe"
				$Arguments = "/c start /MIN psr.exe /stop"
				$Process = ProcessCreate -Process $ProcessName -Arguments $Arguments
			#----------------------------------------
			# DirectAccess Client: IP Helper Logging: Disable (Added 4/1/14)
			#----------------------------------------
			#
				Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Tracing\IpHlpSvc" EnableFileTracing -Value 0 -force
		}

		#----------------------------------------
		# DirectAccess Server: Stop Logging (CAPI2 and Schannel)
		#----------------------------------------
		#
		#-----CAPI2 EVENTLOG: Set to original state
		"[info] Setting CAPI2 Eventlog status back to original status." | WriteTo-StdOut
		$capi2RegKeyLocation = "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational"

		if ($capi2OrigStatus -ne "1"){
			#disable CAPI2 logging using wevtutil
			$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-CAPI2/Operational /e:false"
			RunCmD -commandToRun $CommandToExecute  -CollectFiles $false

			#disable CAPI2 logging using the registry
			# Set-ItemProperty -path $capi2RegKeyLocation Enabled $capi2OrigStatus
		}
		#----------------------------------------
		# DirectAccess Server: Collect Eventlog (CAPI2)
		#----------------------------------------
		#
		$EventLogNames = "Microsoft-Windows-CAPI2/Operational"
		$Prefix = ""
		$Suffix = "_evt_"
		.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription "Certificates Information" -Prefix $Prefix -Suffix $Suffix		

		#----------------------------------------
		#-----OTP EVENTLOG: Set to original state
		#----------------------------------------
		"[info] Setting CAPI2 Eventlog status back to original status." | WriteTo-StdOut
		$otpRegKeyLocation = "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational"
		if ($otpOrigStatus -ne "1"){
			#disable OTP logging using wevtutil
			$CommandToExecute = "cmd.exe /c wevtutil sl Microsoft-Windows-OtpCredentialProvider/Operational /e:false"
			RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
			
			#disable OTP logging using the registry
			# Set-ItemProperty -path $capi2RegKeyLocation Enabled $otpOrigStatus
		}
	
		#----------------------------------------
		# Collect Eventlog (OTP)
		#----------------------------------------
		#
		$EventLogNames = "Microsoft-Windows-OtpCredentialProvider/Operational"
		$Prefix = ""
		$Suffix = "_evt_"
		.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription "OTP" -Prefix $Prefix -Suffix $Suffix
	
		#-----SCHANNEL EVENTLOG: Set to original state
		"[info] Setting Schannel Event logging back to original status." | WriteTo-StdOut
		$schannelRegKeyLocation = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel"
		Set-ItemProperty -path $schannelRegKeyLocation EventLogging $schannelOrigStatus

		#----------------------------------------
		# DirectAccess Server: Stop Logging: ETLTraceCollector
		#----------------------------------------
		#
		if ($OSVersion.Build -gt 7000){
			#----------Kerberos: Stop SecurityKerberos logging
				# SecurityKerberos ETL Logging
				# logman stop "SecurityKerberos" -ets
				"[info] Stopping SecurityKerberos ETL logging." | WriteTo-StdOut
				Run-DiagExpression .\TS_ETLTraceCollector.ps1 -StopTrace -DataCollectorSetObject $SecurityKerberosETL -OutputFileName $SecurityKerberosOutputFileNames -FileDescription $SecurityKerberosFileDescriptions -SectionDescription $SecurityKerberosSectionDescriptions -DoNotPromptUser -DisableRootcauseDetected
				"[info] SecurityKerberos ETL logging should be stopped now." | WriteTo-StdOut

			#----------NTLM: Stop SecurityNTLM logging
				# SecurityNTLM ETL Logging
				# logman stop "SecurityNTLM" -ets
				"[info] Stopping SecurityNTLM ETL logging." | WriteTo-StdOut
				Run-DiagExpression .\TS_ETLTraceCollector.ps1 -StopTrace -DataCollectorSetObject $SecurityNTLMETL -OutputFileName $SecurityNTLMOutputFileNames -FileDescription $SecurityNTLMFileDescriptions -SectionDescription $SecurityNTLMSectionDescriptions -DoNotPromptUser -DisableRootcauseDetected
				"[info] SecurityNTLM ETL logging should be stopped now." | WriteTo-StdOut

			#----------OTP: Stop OTP logging
				"[info] OTP section: if OTP is enabled, stop logging." | WriteTo-StdOut	
				$regkeyOtpEnabled = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemoteAccess\Config\Otp"
				if (Test-Path $regkeyOtpEnabled) {
					if ((Get-ItemProperty -Path $regkeyOtpEnabled)."Enabled" -eq "1"){
						# OTP ETL Logging
						$daOTPAuth = get-daotpauthentication
						$daOTPStatus = $daOTPAuth.otpstatus
						if($daOTPStatus -eq "enabled"){
							# OTP ETL Logging
							# logman stop "OTP" -ets
							"[info] Stopping OTP ETL logging." | WriteTo-StdOut
							Run-DiagExpression .\TS_ETLTraceCollector.ps1 -StopTrace -DataCollectorSetObject $OTPETL -OutputFileName $OTPOutputFileNames -FileDescription $OTPFileDescriptions -SectionDescription $OTPSectionDescriptions -DoNotPromptUser -DisableRootcauseDetected
							"[info] OTP ETL logging should be stopped now." | WriteTo-StdOut			
						}
					}
				}
				else{
					"[info] OTP is not enabled on this server." | WriteTo-StdOut
				}
			
			#-----SCHANNEL ETL Logging
				# logman -stop schannel -ets
				"[info] Stopping Schannel ETL logging." | WriteTo-StdOut
					Run-DiagExpression .\TS_ETLTraceCollector.ps1 -StopTrace -DataCollectorSetObject $SChannelDCS -OutputFileName $SChannelOutputFileNames -FileDescription $SChannelFileDescriptions -SectionDescription $SChannelSectionDescriptions -DoNotPromptUser -DisableRootCauseDetected
				"[info] Schannel ETL logging should be stopped now." | WriteTo-StdOut
		}

		#----------------------------------------
		# DirectAccess Server: Stop Logging: ETLTraceCollector: DASrvPSLogging
		#----------------------------------------
		#			
		if ($OSVersion.Build -gt 9000){			
			#-----DASrvPSLogging ETL Logging
				# logman -stop DASrvPSLogging -ets
				"[info] Stopping DASrvPSLogging ETL logging." | WriteTo-StdOut
					Run-DiagExpression .\TS_ETLTraceCollector.ps1 -StopTrace -DataCollectorSetObject $DASrvPSLoggingDCS -OutputFileName $DASrvPSLoggingFileNames -FileDescription $DASrvPSLoggingFileDescriptions -SectionDescription $DASrvPSLoggingSectionDescriptions -DoNotPromptUser -DisableRootCauseDetected
				"[info] DASrvPSLogging ETL logging should be stopped now." | WriteTo-StdOut
		}

		#----------------------------------------
		# DirectAccess Server: Collect Files
		#----------------------------------------
		#
		if ($OSVersion.Build -gt 7000){
			#----------Netsh Trace DirectAccess Scenario: STOP logging
				"[info] Collecting Netsh Trace output." | WriteTo-StdOut
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1CollectTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt1CollectDesc
				$sectionDescription = "Netsh Trace DirectAccess Scenario"
				CollectFiles -filesToCollect $OutputFileNetshTraceETL -fileDescription "Netsh Trace DirectAccess Scenario: ETL" -SectionDescription $sectionDescription
				CollectFiles -filesToCollect $OutputFileNetshTraceCAB -fileDescription "Netsh Trace DirectAccess Scenario: CAB" -SectionDescription $sectionDescription
			#----------Netsh WFP Capture: STOP logging
				"[info] Collecting Netsh WFP output." | WriteTo-StdOut
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2CollectTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt2CollectDesc
				$sectionDescription = "WFP Tracing"
				CollectFiles -filesToCollect $OutputFileWFP -fileDescription "WFP tracing" -SectionDescription $sectionDescription
			#----------PSR: STOP Problem Steps Recorder
				"[info] Collecting problem steps recorder output." | WriteTo-StdOut
				Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3CollectTitle -Status $ScriptVariable.ID_CTSDirectAccessCliD1_Opt3CollectDesc
				$sectionDescription = "Problem Steps Recorder (PSR)"
				Start-Sleep 15
				CollectFiles -filesToCollect $OutputFilePSR -fileDescription "PSR logging" -SectionDescription $sectionDescription
				Start-Sleep 15
			#----------IP Helper Logging: Collect (Added 04/01/14)			
				"[info] Collecting IP Helper log files." | WriteTo-StdOut
				$sectionDescription = "IP Helper service logging"
				$tracingdir = join-path $env:windir tracing
				$OutputFileIpHlpSvcLog = join-path $tracingdir "IpHlpSvc.Log"
				$OutputFileIpHlpSvcOld = join-path $tracingdir "IpHlpSvc.Old" 
				CollectFiles -filesToCollect $OutputFileIpHlpSvcLog -fileDescription "DirectAccess IpHlpSvc Log" -SectionDescription $sectionDescription
				CollectFiles -filesToCollect $OutputFileIpHlpSvcOld -fileDescription "DirectAccess IpHlpSvc Log (Old)" -SectionDescription $sectionDescription

			#----------NetCfg ETL Logs: Collect (Added 08.12.14)
				$sectionDescription = "NetCfg Logs"
				$OutputDirectory = "$env:windir\inf\netcfg*.etl"
				$OutputFileNetCfgCab = "NetCfgETL.cab"
				CompressCollectFiles -DestinationFileName $OutputFileNetCfgCab -filesToCollect $OutputDirectory -sectionDescription $sectionDescription -fileDescription "NetCfg ETL Logs: CAB"
		}

		#----------------------------------------
		# DirectAccess Server: Static Data Collection
		#----------------------------------------
		if ($true) {
			"[info] DirectAccess Server: Static Data Collection" | WriteTo-StdOut
			DAServerInfo
			DASharedNetInfo
		}

		#----------------------------------------
		# DirectAccess Server Alerts
		#----------------------------------------
		if ($true) {
			"[info] DirectAccess Server Alerts" | WriteTo-StdOut
			DAServerAlerts
		}
	} #DirectAccessServer:END
} #DirectAccessInteractive:END


# SIG # Begin signature block
# MIInrQYJKoZIhvcNAQcCoIInnjCCJ5oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCSR3zUfiXhOPpW
# 0ECEeSo7CcQ81xO5DKaxasNvYREWDaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGY0wghmJAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBjRntCP31wKfMbjiq69DdUe
# fEbL3D0NdKxFRw0CTKDGMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBYH0AjPm+VmuNXHRzi3ch7BvJcxDIN7suWBf4DJkYnTIL8GG3Obn0p
# 8orLZbG0pSRfFcWvP4mAIevQ2avHVUKYYvMzEzSUBPbqC0+WShEfBequ8J1LMJfk
# L0dK/Xtx8RIO5JCpw1RoymeSO7hkke9cupk62+sP0NsGKaNaGbKGMCj3Jau6QrHn
# 1a0sKg2zlmOT728vWebqzm+Py/6oFCHGlBSBEwhzB5YdmTs9bnjGxktVUoHP7EXS
# nsMFXrwOKGb92IGUHO9RMOjj7Z7pbPQ67otjDrQmsKOqQdc5XxKTyas+8DgmT4YW
# YTg9tMx7KNh1A17EZv63jtEui48RQebeoYIXFTCCFxEGCisGAQQBgjcDAwExghcB
# MIIW/QYJKoZIhvcNAQcCoIIW7jCCFuoCAQMxDzANBglghkgBZQMEAgEFADCCAVgG
# CyqGSIb3DQEJEAEEoIIBRwSCAUMwggE/AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIFUqfcL7glOOGnVG8KcrbTQTlQmzBQtOCr8f/EFLUp2MAgZjJRUD
# 67UYEjIwMjIwOTI3MDY1MDE0LjU4WjAEgAIB9KCB2KSB1TCB0jELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IEly
# ZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# TjowODQyLTRCRTYtQzI5QTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaCCEWUwggcUMIIE/KADAgECAhMzAAABh0IWZgRc8/SNAAEAAAGHMA0G
# CSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIx
# MTAyODE5MjczOVoXDTIzMDEyNjE5MjczOVowgdIxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9w
# ZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MDg0Mi00
# QkU2LUMyOUExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC+aXgZYz0Do9ERCIeBkAA8
# rqf5OHqb4tjApgtpAWVldtOquh2GyeLsdUhGSoEW4byiDUpmvLTbESaZt2nz07jT
# EIhB9bwUpbug7+Vhi1QBBbaSnS4y5gQnVeRnp4eNwy6oQnALjtRqRnHcB6RqQ/4Z
# 8a4MM72RkZBF7wimKInhCSfqZsOFtGmBxQ52wPOY3PqRcbuB8h+ByzmTO4og/qc3
# i2yM+HIXnxVTRl8jQ9IL6fk5fSGxTyF5Z7elSIOvmCo/XprqQiMUkeSA09iAyK8Z
# NApyM3E1xeefKZP8lW42ztm+TU/kpZ/wbVcb8y1lnn+O6qyDRChSZBmNWHRdGS7t
# ikymS1btd8UDfL5gk4bWlXOLMHc/MldQLwxrwBTLC1S5QtaNhPnLv8TDAdaafVFP
# Q+Fin2Sal9Lochh8QFuhhS9QtbYecY1/Hrl/hSRzuSA1JBt4AfrKM7l2DoxTA9/O
# j+sF01pl8nFntGxxMHJO2XFuV9RPjrI8cJcAKJf8GFocRjh50WCn9whvtccUlu7i
# Y0MA/NGUCQiPVIa470bixuSMz1ek0xaCWPZ0L1As3/SB4EVeg0jwX4d8fDgmj6nq
# JI/yGfjeaSRYpIY6JPiEsnOhwSsWe0rmL095tdKrYG8yDNVz4EG8I3fkN8PSaiRE
# rFqba1AzTrRI5HLdLu5x6wIDAQABo4IBNjCCATIwHQYDVR0OBBYEFCJRwBa6QS1h
# gX7dYXOZkD8NpY0gMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8G
# A1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBs
# BggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# DQYJKoZIhvcNAQELBQADggIBALmrflPZEqMAVE3/dxiOc8XO09rsp6okomcqC+JS
# P0gx8Lz8VDajHpTDJ3jRNLvMq+24yXXUUWV9aQSdw3eWqKGJICogM851W+vWgljg
# 0VAE4fMul616kecyDRQvZRcfO+MqDbhU4jNvR210/r35AjLtIOlxWH0ojQRcobZu
# iWkHKmpG20ZMN3QlCQ60x2JKloOk4fCAIw1cTzEi7jyGK5PTvmgiqccmFrfvz8Om
# 6AjQNmNhxkfVwbzgnTq5yrnKCuh32zOvX05sJkl0kunK8lYLLw9EMCRGM8mCVKZ+
# fZRHQq+ejII7OOzMDA0Kn8kmeRGnbTB4i3Ob3uI2D4VkXUn0TXp5YgHWwKvtWP1A
# Poq37PzWs5wtF/GGU7b+wrT1TD4OJCQ9u7o5ndOwO8uyvzIb1bYDzJdyCA2p3hek
# u10SR/nY4g3QaBEtJjUs0MHggpj5mPfgjAxsNuzawKKDkuLYgtYQxX/qDIvfsnvU
# 1tbtXOjt9was2d706rGAULZZfl16DHIndLHZsrDqVt/TgppedME5LPRAL5F8m7Py
# c6kh/bz5aYw+JxfaXuCz8ysLlqebIr+dt4qRo7H4BeHBgvMRM2D7UhzKCN3CdupY
# pp8t0I0p+Gxv+AzlIVuAPkBMRfVsDHBQVXEq9C/R0hECbloOMXcNmmC/LeZKiNKs
# E3/zMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0B
# AQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAG
# A1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAw
# HhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOTh
# pkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xP
# x2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ
# 3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOt
# gFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYt
# cI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXA
# hjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0S
# idb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSC
# D/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEB
# c8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh
# 8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8Fdsa
# N8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkr
# BgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q
# /y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBR
# BgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsG
# AQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
# BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjE
# MFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv
# Y3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEF
# BQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEB
# CwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnX
# wnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOw
# Bb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jf
# ZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ
# 5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+
# ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgs
# sU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6
# OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p
# /cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6
# TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784
# cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtQwggI9
# AgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1p
# dGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjowODQyLTRCRTYtQzI5QTElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIa
# AxUAeHeTVAQoBkSGwsZgYe1//oMbg/OggYMwgYCkfjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAObcwjwwIhgPMjAyMjA5Mjcw
# ODI4NDRaGA8yMDIyMDkyODA4Mjg0NFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA
# 5tzCPAIBADAHAgEAAgIiujAHAgEAAgIRRjAKAgUA5t4TvAIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBBQUAA4GBAJ6J8ckVAr9UPSLW831qSoo5WmJy+7w1sneFVI3VJ3E6
# OIgooEj+aOanbZiKqhOqLYMFSQCNcO8AJgaZRDxecpErLetUGID+W0UCRpprkvo1
# rB0DAag4xYzf/2gnCD1RKFt+2gi3DOYxO65YAF15aeC7ymN6uTgOlKkIR3u//SNf
# MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGHQhZmBFzz9I0AAQAAAYcwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQg1RwpHz/3jytfAJtpEg3v
# 4D2v/oYGQ/9Kum4g2KNtVO8wgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCDE
# LPCgE26gH3bCwLZLFmHPgdUbK8JmfBg25zOkbJqbWDCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABh0IWZgRc8/SNAAEAAAGHMCIEIFj/
# X2F5OiJg3FuaKYO+FScAY3okw+9sXTa/XfSFbNfCMA0GCSqGSIb3DQEBCwUABIIC
# ACySwrozWdX8fWg4B+XbzxS4EBlSwqejUvbf98H1AUNX7w/TpQiJOTp0JL1UuArP
# Ui+d4LeKyFWEmTbF6EU8VAapxCgcEMa2YPAmNi97t/t8e4XK1b2wrF+dNCWS6M7U
# yl6P3AeqsijSUz5sxrC3LMAKLy/Eu5C/iTW0KDi/WAmoQ1M9MESDMnh8Qj0MaSFi
# MI5LBKhpkVPcGdV9Nd3gVroKeV3ujaOvoVesPx9Fwh48lnUc9rlyJL6m29xuFQBn
# 18rnZlm1bIvO4wmPHKnBJ1rKgT0bsW5GGOJ4WqtUpkV8OStUlVLbdZGlhBcWvXdN
# FDrIijjZyKisDTuZpIanHlAokCQ50sM9hVwLR3MGpULtsl7G2EQ2yB4SJDyxwCFk
# JYDtKe5qj/te/VEkzVcJFHVmJHGNWF/ppYCuofRU75mFyuAPrW7CbuHC/0Kn1Dri
# j7yAPFVxUx2gMO1zPKIwSg3gDMoCoCYwRxbAxUvbusm5NDyRqU9nr31rAVgwf3lx
# /JIjZPJ+CU1StRxzTmGq3KvSS+URameV7j/lIZ0m8vNENg/PviJ1NggtzL1aqg6J
# GOOk/6PWVI+bpzMMCIipMx5d5K5KVn/SmsID+yu4udGqEY+SBKovxzicDyWTGNPS
# bAvGztVKVmJTpQIPl/mq4MPtk77GqbgNE0VZypRkuBmA
# SIG # End signature block
