#************************************************
# DC_ProxyConfiguration.ps1
# Version 1.0: Proxy Configuration for IE User, WinHTTP, Firewall Client, PAC Files, Network Isolation
# Version 1.1: Added Proxy Configuration for IE System
# Version 1.2 (4/28/14): Edited table of contents. 
# Create date: 12/5/2012
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: Collects Proxy Configuration information from IE, WinHTTP and Forefront Firewall Client.
# Called from: Networking Diagnostics
#*******************************************************

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
Write-DiagProgress -Activity $ScriptVariable.ID_CTSProxyConfigurationIEUser -Status $ScriptVariable.ID_CTSProxyConfigurationIEUserDescription

$sectionDescription = "Proxy Configuration Information"
$OutputFile= $Computername + "_ProxyConfiguration.TXT"


#INTRO

	"====================================================" 								| Out-File -FilePath $OutputFile -encoding ASCII -append
	"Proxy Configuration" 																| Out-File -FilePath $OutputFile -encoding ASCII -append
	"====================================================" 								| Out-File -FilePath $OutputFile -encoding ASCII -append
	"Overview"			 																| Out-File -FilePath $OutputFile -encoding ASCII -append
	"----------------------------------------------------" 								| Out-File -FilePath $OutputFile -encoding ASCII -append
	"The Proxy Configuration script shows the proxy configuration of the following:"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"  1. IE User Proxy Settings"														| Out-File -FilePath $OutputFile -encoding ASCII -append
	"  2. IE System Proxy Settings" 													| Out-File -FilePath $OutputFile -encoding ASCII -append
	"  3. WinHTTP Proxy Settings"														| Out-File -FilePath $OutputFile -encoding ASCII -append
	"  4. BITS Proxy Settings" 															| Out-File -FilePath $OutputFile -encoding ASCII -append
	"  5. TMG/ISA Firewall Client Settings" 											| Out-File -FilePath $OutputFile -encoding ASCII -append
	"  6. Displays PAC file names and locations"										| Out-File -FilePath $OutputFile -encoding ASCII -append
	"  7. Collects the PAC files on the system into a compressed file."					| Out-File -FilePath $OutputFile -encoding ASCII -append
	"  8. Network Isolation settings" 													| Out-File -FilePath $OutputFile -encoding ASCII -append
	"===================================================="								| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n`n`n`n`n"																		| Out-File -FilePath $OutputFile -encoding ASCII -append

#IE
	#"[info]: Starting Proxy Configuration script" | WriteTo-StdOut
	# Check if ProxySettingsPerUser is set causing the IE settings to be read from HKLM
	if (test-path "HKLM:\Software\Policies\Windows\CurrentVersion\Internet Settings")
	{
		$ieProxyConfigProxySettingsPerUserP = (Get-ItemProperty -path "HKLM:\Software\Policies\Windows\CurrentVersion\Internet Settings").ProxySettingsPerUser
	}
	if (test-path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings")
	{
		$ieProxyConfigProxySettingsPerUserM = (Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings").ProxySettingsPerUser	
	}

	If ( ($ieProxyConfigProxySettingsPerUserP -eq 0) -or ($ieProxyConfigProxySettingsPerUserM -eq 0) )
	{
		#----------determine os architecture
		Function GetComputerArchitecture() 
		{ 
			if (($Env:PROCESSOR_ARCHITEW6432).Length -gt 0) #running in WOW 
			{ 
				$Env:PROCESSOR_ARCHITEW6432 
			} else { 
				$Env:PROCESSOR_ARCHITECTURE 
			} 
		}
		$OSArchitecture = GetComputerArchitecture
		# $OSArchitecture | WriteTo-StdOut

		if ($OSArchitecture -eq "AMD64")
		{
			#IE Proxy Config from HKLM
			$ieProxyConfigAutoConfigURL = (Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings").AutoConfigURL
			$ieProxyConfigProxyEnable   = (Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings").ProxyEnable
			$ieProxyConfigProxyServer   = (Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings").ProxyServer
			$ieProxyConfigProxyOverride = (Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings").ProxyOverride
			# Get list of regvalues in "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
			$ieConnections = (Get-Item -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections") | Select-Object -ExpandProperty Property
			$regHive = "HKLM (x64)"
		}
		if ($OSArchitecture -eq "x86")
		{
			#IE Proxy Config from HKLM
			$ieProxyConfigAutoConfigURL = (Get-ItemProperty -path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings").AutoConfigURL
			$ieProxyConfigProxyEnable   = (Get-ItemProperty -path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings").ProxyEnable
			$ieProxyConfigProxyServer   = (Get-ItemProperty -path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings").ProxyServer
			$ieProxyConfigProxyOverride = (Get-ItemProperty -path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings").ProxyOverride
			
			# Get list of regvalues in "HKLM\Software\WOW6432Node\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
			$ieConnections = (Get-Item -Path "Registry::HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Connections") | Select-Object -ExpandProperty Property
			$regHive = "HKLM (x86)"
		}
	}
	else
	{
		#IE Proxy Config from HKCU
		$ieProxyConfigAutoConfigURL = (Get-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings").AutoConfigURL
		$ieProxyConfigProxyEnable   = (Get-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings").ProxyEnable
		$ieProxyConfigProxyServer   = (Get-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings").ProxyServer
		$ieProxyConfigProxyOverride = (Get-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings").ProxyOverride

		# Get list of regvalues in "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
		$ieConnections = (Get-Item -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections") | Select-Object -ExpandProperty Property
		$regHive = "HKCU"
	}

	#"[info]: ProxyServer array being created" | WriteTo-StdOut	
	#Find all entries in the Proxy Server Array
	if ($null -ne $ieProxyConfigProxyServer)
	{
		$ieProxyConfigProxyServerArray = ($ieProxyConfigProxyServer).Split(';')
		$ieProxyConfigProxyServerArrayLength = $ieProxyConfigProxyServerArray.length
	}
	
	#"[info]: ProxyOverride array being created" | WriteTo-StdOut	
	#Find all entries in Proxy Override Array
	if ($null -ne $ieProxyConfigProxyOverride)
	{
		[array]$ieProxyConfigProxyOverrideArray = ($ieProxyConfigProxyOverride).Split(';')
		$ieProxyConfigProxyOverrideArrayLength = $ieProxyConfigProxyOverrideArray.length
	}
	
	
	


	#"[info]: Starting Proxy Configuration: IE User Settings section" | WriteTo-StdOut
	"`n`n`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"====================================================" 								| Out-File -FilePath $OutputFile -encoding ASCII -append
	" Proxy Configuration: IE User Settings (" + $regHive + ")" 	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"====================================================" 								| Out-File -FilePath $OutputFile -encoding ASCII -append
	
	for($i=0;$null -ne $ieConnections[$i];$i++)
	{
		#IE Proxy Configuration Array: Detection Logic for each Connection
			[string]$ieConnection = $ieConnections[$i]

		
		# Main UI Checkboxes (3)
			$ieProxyConfigArray = (Get-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections").$ieConnection
			[int]$ieProxyConfigUI = $ieProxyConfigArray[8]
			
			
		# Manual Proxy Server setting
			[int]$ieProxyConfigUIManualProxyOffset = 12
			[int]$ieProxyConfigUIManualProxyLength = $ieProxyConfigArray[$ieProxyConfigUIManualProxyOffset]
			[int]$ieProxyConfigUIManualProxyStart = $ieProxyConfigUIManualProxyOffset + 4
			[int]$ieProxyConfigUIManualProxyEnd = $ieProxyConfigUIManualProxyStart + $ieProxyConfigUIManualProxyLength
			# Convert decimal to ASCII string
			[string]$ieProxyConfigUIManualProxyValue = ""
			for ($j=$ieProxyConfigUIManualProxyStart;$j -lt $ieProxyConfigUIManualProxyEnd;$j++)
			{
				[string]$ieProxyConfigUIManualProxyValue = $ieProxyConfigUIManualProxyValue + [CHAR][BYTE]$ieProxyConfigArray[$j]
			}
			# Split on semicolons
			$ieProxyConfigUIManualProxyValueArray = ($ieProxyConfigUIManualProxyValue).Split(';')
			$ieProxyConfigUIManualProxyValueArrayLength = $ieProxyConfigUIManualProxyValueArray.length


		# BypassProxy
			[int]$ieProxyConfigUIBypassProxyOffset = $ieProxyConfigUIManualProxyStart + $ieProxyConfigUIManualProxyLength
			[int]$ieProxyConfigUIBypassProxyLength = $ieProxyConfigArray[$ieProxyConfigUIBypassProxyOffset]
			[int]$ieProxyConfigUIBypassProxyStart  = $ieProxyConfigUIBypassProxyOffset + 4
			[int]$ieProxyConfigUIBypassProxyEnd    = $ieProxyConfigUIBypassProxyStart + $ieProxyConfigUIBypassProxyLength
			# Bypass Proxy Checkbox
			If ($ieProxyConfigUIBypassProxyLength -ne 0)
			{
				#BypassProxy Checked
				$ieProxyConfigUIBypassProxyEnabled = $true
			}
			else
			{
				#BypassProxy Unchecked
				$ieProxyConfigUIBypassProxyEnabled = $false
			}
			# Convert decimal to ASCII string
			[string]$ieProxyConfigUIBypassProxyValue = ""
			for ($j=$ieProxyConfigUIBypassProxyStart;$j -lt $ieProxyConfigUIBypassProxyEnd;$j++)
			{
				[string]$ieProxyConfigUIBypassProxyValue = $ieProxyConfigUIBypassProxyValue + [CHAR][BYTE]$ieProxyConfigArray[$j]
			}
			# Split on semicolons
			$ieProxyConfigUIBypassProxyValueArray = ($ieProxyConfigUIBypassProxyValue).Split(';')
			$ieProxyConfigUIBypassProxyValueArrayLength = $ieProxyConfigUIBypassProxyValueArray.length
			
			
		#AutoConfig
			[int]$ieProxyConfigUIAutoConfigOffset = $ieProxyConfigUIBypassProxyStart + $ieProxyConfigUIBypassProxyLength
			[int]$ieProxyConfigUIAutoConfigLength = $ieProxyConfigArray[$ieProxyConfigUIAutoConfigOffset]
			[int]$ieProxyConfigUIAutoConfigStart  = $ieProxyConfigUIAutoConfigOffset + 4
			[int]$ieProxyConfigUIAutoConfigEnd    = $ieProxyConfigUIAutoConfigStart + $ieProxyConfigUIAutoConfigLength
			# Convert decimal to ASCII string
			[string]$ieProxyConfigUIAutoConfigValue = ""
			for ($j=$ieProxyConfigUIAutoConfigStart;$j -lt $ieProxyConfigUIAutoConfigEnd;$j++)
			{
				[string]$ieProxyConfigUIAutoConfigValue = $ieProxyConfigUIAutoConfigValue + [CHAR][BYTE]$ieProxyConfigArray[$j]
			}
			# Split on semicolons
			$ieProxyConfigUIAutoConfigValueArray = ($ieProxyConfigUIAutoConfigValue).Split(';')
			$ieProxyConfigUIAutoConfigValueArrayLength = $ieProxyConfigUIAutoConfigValueArray.length

			

		If ($ieConnection -eq "DefaultConnectionSettings")
		{

			"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
			"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
			"-----Connection:  " + $ieConnection + "-----"		| Out-File -FilePath $OutputFile -encoding ASCII -append
			"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
			"Local Area Network (LAN) Settings" 	| Out-File -FilePath $OutputFile -encoding ASCII -append
			"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
		}
		elseif ($ieConnection -eq "SavedLegacySettings")
		{
			# skipping SavedLegacySettings to trim output
			$i++
			[string]$ieConnection = $ieConnections[$i]
			"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
			"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
			"-----Connection:  " + $ieConnection + "-----"		| Out-File -FilePath $OutputFile -encoding ASCII -append
			"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
		}
		else
		{
			"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
			"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
			"-----Connection:  " + $ieConnection + "-----"		| Out-File -FilePath $OutputFile -encoding ASCII -append
			"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
		}
		

		" " + "Automatic Configuration"						| Out-File -FilePath $OutputFile -encoding ASCII -append
		# "Automatically detect settings:
			If ( ($ieProxyConfigUI -eq 9) -or ($ieProxyConfigUI -eq 11) -or ($ieProxyConfigUI -eq 13) -or ($ieProxyConfigUI -eq 15) )
			{
				"  " + "[X] Automatically detect settings:" | Out-File -FilePath $OutputFile -encoding ASCII -append
			}
			else
			{
				"  " + "[ ] Automatically detect settings:" | Out-File -FilePath $OutputFile -encoding ASCII -append
			}
		# "Use automatic configuration script:"
			If ( ($ieProxyConfigUI -eq 5) -or ($ieProxyConfigUI -eq 7) -or ($ieProxyConfigUI -eq 13) -or ($ieProxyConfigUI -eq 15) )
			{
				"  " + "[X] Use automatic configuration script:" | Out-File -FilePath $OutputFile -encoding ASCII -append
				"   " + "     " + "Address: "  | Out-File -FilePath $OutputFile -encoding ASCII -append
				# "   " + "            " + $ieProxyConfigAutoConfigURL
				
				"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
				for ($j=0;$j -le $ieProxyConfigUIAutoConfigValueArrayLength;$j++)
				{
					"    " + "            " + $ieProxyConfigUIAutoConfigValueArray[$j]	| Out-File -FilePath $OutputFile -encoding ASCII -append
				}
			}
			else
			{
				"  " + "[ ] Use automatic configuration script:" | Out-File -FilePath $OutputFile -encoding ASCII -append
				"   " + "     " + "Address: " | Out-File -FilePath $OutputFile -encoding ASCII -append
			}
		" " + "Proxy Server"								| Out-File -FilePath $OutputFile -encoding ASCII -append
		# "Use a proxy server for your LAN (These settings will not apply to dial-up or VPN connections)."
			If ( ($ieProxyConfigUI -eq 3) -or ($ieProxyConfigUI -eq 7) -or ($ieProxyConfigUI -eq 11) -or ($ieProxyConfigUI -eq 15) )
			{
				# MANUAL PROXY (from Connection)
				"  " + "[X] Use a proxy server for your LAN (These settings will not apply " | Out-File -FilePath $OutputFile -encoding ASCII -append
				If ($ieConnection -eq "DefaultConnectionSettings")
				{
					"  " + "    to dial-up or VPN connections)."		| Out-File -FilePath $OutputFile -encoding ASCII -append
				}
				else
				{
					"  " + "    to other connections)."					| Out-File -FilePath $OutputFile -encoding ASCII -append
				}
				"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
				"   " + "     Address: and Port:   " | Out-File -FilePath $OutputFile -encoding ASCII -append
				"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
				for ($j=0;$j -le $ieProxyConfigUIManualProxyValueArrayLength;$j++)
				{
					"    " + "            " + $ieProxyConfigUIManualProxyValueArray[$j]	| Out-File -FilePath $OutputFile -encoding ASCII -append
				}

				# BYPASS PROXY (from Connection)
				If ($ieProxyConfigUIBypassProxyEnabled -eq $true)
				{
				"    " + "   [X] Bypass proxy server for local addresses"	| Out-File -FilePath $OutputFile -encoding ASCII -append
				"    " + "        Exceptions: "	| Out-File -FilePath $OutputFile -encoding ASCII -append
					"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
					for ($j=0;$j -le $ieProxyConfigUIBypassProxyValueArrayLength;$j++)
					{
						"    " + "            " + $ieProxyConfigUIBypassProxyValueArray[$j]	| Out-File -FilePath $OutputFile -encoding ASCII -append
					}
				}
				else
				{
				"    " + "   [ ] Bypass proxy server for local addresses"	| Out-File -FilePath $OutputFile -encoding ASCII -append
				"    " + "        Exceptions: "  							| Out-File -FilePath $OutputFile -encoding ASCII -append
				}
			}
			else
			{
				"  " + "[ ] Use a proxy server for your LAN (These settings will not apply to" | Out-File -FilePath $OutputFile -encoding ASCII -append
				"  " + "    dial-up or VPN connections)."					| Out-File -FilePath $OutputFile -encoding ASCII -append
				"   " + "    Address:Port "									| Out-File -FilePath $OutputFile -encoding ASCII -append
				"    " + "   [ ] Bypass proxy server for local addresses"	| Out-File -FilePath $OutputFile -encoding ASCII -append
				"    " + "        Exceptions: "  							| Out-File -FilePath $OutputFile -encoding ASCII -append
			}
	}





Write-DiagProgress -Activity $ScriptVariable.ID_CTSProxyConfigurationIESystem -Status $ScriptVariable.ID_CTSProxyConfigurationIESystemDescription

	#----------Proxy Configuration: IE System Settings: Initialization
		#"[info]: ProxyConfiguration: IE System Settings: Initialization" | WriteTo-StdOut 	
		$regHive = "HKEY_USERS\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

	
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"====================================================" 				| Out-File -FilePath $OutputFile -encoding ASCII -append
	" Proxy Configuration: IE System Settings (" + $regHive + ")" 		| Out-File -FilePath $OutputFile -encoding ASCII -append
	"====================================================" 				| Out-File -FilePath $OutputFile -encoding ASCII -append


	#----------
	# Verifying HKU is in the psProviderList. If not, add it
	#----------
		#
		# HKU may not be in the psProviderList, so we need to add it so we can reference it
		#
		#"[info]: Checking the PSProvider list because we need HKU" | WriteTo-StdOut
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
			#"[info]: Creating a new PSProvider to enable access to HKU" | WriteTo-StdOut
			[void]( New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS)
		}

	#----------
	# Verify "\Internet Settings\Connections" exists, if not display message that IE System Context is not configured.
	#   $ieConnectionsCheck and associated code block added 10/11/2013
	#----------
	#$ieConnections = $null
	# Get list of regvalues in "HKEY_USERS\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"		
	$ieConnectionsCheck = Test-path "HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
	
	if ($ieConnectionsCheck -eq $true)
	{
		$ieConnections = (Get-Item -Path "Registry::HKEY_USERS\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections") | Select-Object -ExpandProperty Property
		
		for($i=0;$null -ne $ieConnections[$i];$i++)
		{
			#IE Proxy Configuration Array: Detection Logic for each Connection
				[string]$ieConnection = $ieConnections[$i]

			#"[info]: Get-ItemProperty on HKU registry location." | WriteTo-StdOut
			# Main UI Checkboxes (3)
				[array]$ieProxyConfigArray = $null
				[array]$ieProxyConfigArray = (Get-ItemProperty -path "HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections").$ieConnection
				[int]$ieProxyConfigUI = $ieProxyConfigArray[8]
				
			#"[info]: Retrieving manual proxy server setting." | WriteTo-StdOut
			# Manual Proxy Server setting
				[int]$ieProxyConfigUIManualProxyOffset = 12
				[int]$ieProxyConfigUIManualProxyLength = $ieProxyConfigArray[$ieProxyConfigUIManualProxyOffset]
				[int]$ieProxyConfigUIManualProxyStart = $ieProxyConfigUIManualProxyOffset + 4
				[int]$ieProxyConfigUIManualProxyEnd = $ieProxyConfigUIManualProxyStart + $ieProxyConfigUIManualProxyLength
				# Convert decimal to ASCII string
				[string]$ieProxyConfigUIManualProxyValue = ""
				for ($j=$ieProxyConfigUIManualProxyStart;$j -lt $ieProxyConfigUIManualProxyEnd;$j++)
				{
					[string]$ieProxyConfigUIManualProxyValue = $ieProxyConfigUIManualProxyValue + [CHAR][BYTE]$ieProxyConfigArray[$j]
				}
				# Split on semicolons
				$ieProxyConfigUIManualProxyValueArray = ($ieProxyConfigUIManualProxyValue).Split(';')
				$ieProxyConfigUIManualProxyValueArrayLength = $ieProxyConfigUIManualProxyValueArray.length

			#"[info]: Retrieving BypassProxy setting." | WriteTo-StdOut
			# BypassProxy
				[int]$ieProxyConfigUIBypassProxyOffset = $ieProxyConfigUIManualProxyStart + $ieProxyConfigUIManualProxyLength
				[int]$ieProxyConfigUIBypassProxyLength = $ieProxyConfigArray[$ieProxyConfigUIBypassProxyOffset]
				[int]$ieProxyConfigUIBypassProxyStart  = $ieProxyConfigUIBypassProxyOffset + 4
				[int]$ieProxyConfigUIBypassProxyEnd    = $ieProxyConfigUIBypassProxyStart + $ieProxyConfigUIBypassProxyLength
				# Bypass Proxy Checkbox
				If ($ieProxyConfigUIBypassProxyLength -ne 0)
				{
					#BypassProxy Checked
					$ieProxyConfigUIBypassProxyEnabled = $true
				}
				else
				{
					#BypassProxy Unchecked
					$ieProxyConfigUIBypassProxyEnabled = $false
				}
				# Convert decimal to ASCII string
				[string]$ieProxyConfigUIBypassProxyValue = ""
				for ($j=$ieProxyConfigUIBypassProxyStart;$j -lt $ieProxyConfigUIBypassProxyEnd;$j++)
				{
					[string]$ieProxyConfigUIBypassProxyValue = $ieProxyConfigUIBypassProxyValue + [CHAR][BYTE]$ieProxyConfigArray[$j]
				}
				# Split on semicolons
				$ieProxyConfigUIBypassProxyValueArray = ($ieProxyConfigUIBypassProxyValue).Split(';')
				$ieProxyConfigUIBypassProxyValueArrayLength = $ieProxyConfigUIBypassProxyValueArray.length
				
			#"[info]: Retrieving AutoConfig setting." | WriteTo-StdOut			
			#AutoConfig
				[int]$ieProxyConfigUIAutoConfigOffset = $ieProxyConfigUIBypassProxyStart + $ieProxyConfigUIBypassProxyLength
				[int]$ieProxyConfigUIAutoConfigLength = $ieProxyConfigArray[$ieProxyConfigUIAutoConfigOffset]
				[int]$ieProxyConfigUIAutoConfigStart  = $ieProxyConfigUIAutoConfigOffset + 4
				[int]$ieProxyConfigUIAutoConfigEnd    = $ieProxyConfigUIAutoConfigStart + $ieProxyConfigUIAutoConfigLength
				# Convert decimal to ASCII string
				[string]$ieProxyConfigUIAutoConfigValue = ""
				for ($j=$ieProxyConfigUIAutoConfigStart;$j -lt $ieProxyConfigUIAutoConfigEnd;$j++)
				{
					[string]$ieProxyConfigUIAutoConfigValue = $ieProxyConfigUIAutoConfigValue + [CHAR][BYTE]$ieProxyConfigArray[$j]
				}
				# Split on semicolons
				$ieProxyConfigUIAutoConfigValueArray = ($ieProxyConfigUIAutoConfigValue).Split(';')
				$ieProxyConfigUIAutoConfigValueArrayLength = $ieProxyConfigUIAutoConfigValueArray.length

				

			If ($ieConnection -eq "DefaultConnectionSettings")
			{

				"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
				"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
				"-----Connection:  " + $ieConnection + "-----"		| Out-File -FilePath $OutputFile -encoding ASCII -append
				"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
				"Local Area Network (LAN) Settings" 	| Out-File -FilePath $OutputFile -encoding ASCII -append
				"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
			}
			elseif ($ieConnection -eq "SavedLegacySettings")
			{
				# skipping SavedLegacySettings to trim output
				$i++
				[string]$ieConnection = $ieConnections[$i]
				"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
				"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
				"-----Connection:  " + $ieConnection + "-----"		| Out-File -FilePath $OutputFile -encoding ASCII -append
				"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
			}
			else
			{
				"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
				"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
				"-----Connection:  " + $ieConnection + "-----"		| Out-File -FilePath $OutputFile -encoding ASCII -append
				"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
			}
			

			" " + "Automatic Configuration"						| Out-File -FilePath $OutputFile -encoding ASCII -append
			# "Automatically detect settings:
				If ( ($ieProxyConfigUI -eq 9) -or ($ieProxyConfigUI -eq 11) -or ($ieProxyConfigUI -eq 13) -or ($ieProxyConfigUI -eq 15) )
				{
					"  " + "[X] Automatically detect settings:" | Out-File -FilePath $OutputFile -encoding ASCII -append
				}
				else
				{
					"  " + "[ ] Automatically detect settings:" | Out-File -FilePath $OutputFile -encoding ASCII -append
				}
			# "Use automatic configuration script:"
				If ( ($ieProxyConfigUI -eq 5) -or ($ieProxyConfigUI -eq 7) -or ($ieProxyConfigUI -eq 13) -or ($ieProxyConfigUI -eq 15) )
				{
					"  " + "[X] Use automatic configuration script:" | Out-File -FilePath $OutputFile -encoding ASCII -append
					"   " + "     " + "Address: "  | Out-File -FilePath $OutputFile -encoding ASCII -append
					# "   " + "            " + $ieProxyConfigAutoConfigURL
					
					"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
					for ($j=0;$j -le $ieProxyConfigUIAutoConfigValueArrayLength;$j++)
					{
						"    " + "            " + $ieProxyConfigUIAutoConfigValueArray[$j]	| Out-File -FilePath $OutputFile -encoding ASCII -append
					}
				}
				else
				{
					"  " + "[ ] Use automatic configuration script:" | Out-File -FilePath $OutputFile -encoding ASCII -append
					"   " + "     " + "Address: " | Out-File -FilePath $OutputFile -encoding ASCII -append
				}
			" " + "Proxy Server"								| Out-File -FilePath $OutputFile -encoding ASCII -append
			# "Use a proxy server for your LAN (These settings will not apply to dial-up or VPN connections)."
				If ( ($ieProxyConfigUI -eq 3) -or ($ieProxyConfigUI -eq 7) -or ($ieProxyConfigUI -eq 11) -or ($ieProxyConfigUI -eq 15) )
				{
					# MANUAL PROXY (from Connection)
					"  " + "[X] Use a proxy server for your LAN (These settings will not apply " | Out-File -FilePath $OutputFile -encoding ASCII -append
					If ($ieConnection -eq "DefaultConnectionSettings")
					{
						"  " + "    to dial-up or VPN connections)."		| Out-File -FilePath $OutputFile -encoding ASCII -append
					}
					else
					{
						"  " + "    to other connections)."					| Out-File -FilePath $OutputFile -encoding ASCII -append
					}
					"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
					"   " + "     Address: and Port:   " | Out-File -FilePath $OutputFile -encoding ASCII -append
					"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
					for ($j=0;$j -le $ieProxyConfigUIManualProxyValueArrayLength;$j++)
					{
						"    " + "            " + $ieProxyConfigUIManualProxyValueArray[$j]	| Out-File -FilePath $OutputFile -encoding ASCII -append
					}

					# BYPASS PROXY (from Connection)
					If ($ieProxyConfigUIBypassProxyEnabled -eq $true)
					{
					"    " + "   [X] Bypass proxy server for local addresses"	| Out-File -FilePath $OutputFile -encoding ASCII -append
					"    " + "        Exceptions: "	| Out-File -FilePath $OutputFile -encoding ASCII -append
						"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
						for ($j=0;$j -le $ieProxyConfigUIBypassProxyValueArrayLength;$j++)
						{
							"    " + "            " + $ieProxyConfigUIBypassProxyValueArray[$j]	| Out-File -FilePath $OutputFile -encoding ASCII -append
						}
					}
					else
					{
					"    " + "   [ ] Bypass proxy server for local addresses"	| Out-File -FilePath $OutputFile -encoding ASCII -append
					"    " + "        Exceptions: "  | Out-File -FilePath $OutputFile -encoding ASCII -append
					}
				}
				else
				{
					"  " + "[ ] Use a proxy server for your LAN (These settings will not apply to" | Out-File -FilePath $OutputFile -encoding ASCII -append
					"  " + "    dial-up or VPN connections)."					| Out-File -FilePath $OutputFile -encoding ASCII -append
					"   " + "    Address:Port "									| Out-File -FilePath $OutputFile -encoding ASCII -append
					"    " + "   [ ] Bypass proxy server for local addresses"	| Out-File -FilePath $OutputFile -encoding ASCII -append
					"    " + "        Exceptions: "  | Out-File -FilePath $OutputFile -encoding ASCII -append
				}
		}
	}
	

	Write-DiagProgress -Activity $ScriptVariable.ID_CTSProxyConfigurationWinHTTP -Status $ScriptVariable.ID_CTSProxyConfigurationWinHTTPDescription
	#"[info]: ProxyConfiguration: WinHTTP" | WriteTo-StdOut 	
#WinHTTP
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"====================================================" 			| Out-File -FilePath $OutputFile -encoding ASCII -append
	" Proxy Configuration: WinHTTP" 								| Out-File -FilePath $OutputFile -encoding ASCII -append
	"====================================================" 			| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	
	
	Function RunNetSH ([string]$NetSHCommandToExecute="")
	{
		$NetSHCommandToExecuteLength = $NetSHCommandToExecute.Length + 6
		"-" * ($NetSHCommandToExecuteLength)	| Out-File -FilePath $OutputFile -encoding ASCII -append
		"netsh $NetSHCommandToExecute"		| Out-File -FilePath $OutputFile -encoding ASCII -append
		"-" * ($NetSHCommandToExecuteLength)	| Out-File -FilePath $OutputFile -encoding ASCII -append
		$CommandToExecute = "cmd.exe /c netsh.exe " + $NetSHCommandToExecute + "| Out-File -FilePath $OutputFile -encoding ASCII -append"
		RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
	}
	RunNetSH -NetSHCommandToExecute "winhttp show proxy"





#BITS
	# update for BITS proxy: Write-DiagProgress -Activity $ScriptVariable.ID_CTSProxyConfigurationWinHTTP -Status $ScriptVariable.ID_CTSProxyConfigurationWinHTTPDescription
	#"[info]: ProxyConfiguration: BITS" | WriteTo-StdOut 	

	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"====================================================" 			| Out-File -FilePath $OutputFile -encoding ASCII -append
	" Proxy Configuration: BITS" 									| Out-File -FilePath $OutputFile -encoding ASCII -append
	"====================================================" 			| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append

	function RunBitsAdmin ([string]$BitsAdminCommandToExecute="")
	{
		$BitsAdminCommandToExecuteLength = $BitsAdminCommandToExecute.Length + 6
		"-" * ($BitsAdminCommandToExecuteLength)	| Out-File -FilePath $OutputFile -encoding ASCII -append
		"bitsadmin $BitsAdminCommandToExecute"		| Out-File -FilePath $OutputFile -encoding ASCII -append
		"-" * ($BitsAdminCommandToExecuteLength)	| Out-File -FilePath $OutputFile -encoding ASCII -append
		$CommandToExecute = "cmd.exe /c bitsadmin.exe " + $BitsAdminCommandToExecute + "| Out-File -FilePath $OutputFile -encoding ASCII -append"
		RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
		"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
		"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
		"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	}
	RunBitsAdmin -BitsAdminCommandToExecute " /util /getieproxy localsystem"
	RunBitsAdmin -BitsAdminCommandToExecute " /util /getieproxy networkservice"
	RunBitsAdmin -BitsAdminCommandToExecute " /util /getieproxy localservice"




	

#Firewall Client
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSProxyConfigurationFirewallClient -Status $ScriptVariable.ID_CTSProxyConfigurationFirewallClientDescription
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"====================================================" 			| Out-File -FilePath $OutputFile -encoding ASCII -append
	" Proxy Configuration: Firewall Client" 						| Out-File -FilePath $OutputFile -encoding ASCII -append
	"====================================================" 			| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append

	#----- Is the Firewall Client installed?
	$processActive = Get-Process fwcagent -ErrorAction SilentlyContinue
	if ($null -ne $processActive)
	{
		"The Firewall Client appears to be installed. Gathering output."	| Out-File -FilePath $OutputFile -encoding ASCII -append
		" "	| Out-File -FilePath $OutputFile -encoding ASCII -append
		" "	| Out-File -FilePath $OutputFile -encoding ASCII -append
		$firewallClientProcessPath = (get-process fwcagent).path
		$firewallClientProcess = $firewallClientProcessPath.substring(0,$firewallClientProcessPath.Length-12) + "fwctool.exe"
		$firewallClientProcess
		$firewallClientArgs  = " printconfig"
		$firewallClientCmd = "`"" + $firewallClientProcess + "`"" + $firewallClientArgs
		$firewallClientCmdLength = $firewallClientCmd.length
		# Output header and command that will be run
		"`n" + "-" * ($firewallClientCmdLength)	| Out-File -FilePath $OutputFile -encoding ASCII -append
		"`n" + "`"" + $firewallClientProcess + " " + $firewallClientArgs + "`""		| Out-File -FilePath $OutputFile -encoding ASCII -append
		"`n" + "-" * ($firewallClientCmdLength)	| Out-File -FilePath $OutputFile -encoding ASCII -append
		# Run the command
		$CommandToExecute = "cmd.exe /c " + $firewallClientCmd + " | Out-File -FilePath $OutputFile -encoding ASCII -append"
		RunCmD -commandToRun $CommandToExecute -CollectFiles $false
	}
	else
	{
		"The Firewall Client is not installed."	| Out-File -FilePath $OutputFile -encoding ASCII -append
	}


	
	
	

#PAC files	
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSProxyConfigurationPACFiles -Status $ScriptVariable.ID_CTSProxyConfigurationPACFilesDescription

	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"====================================================" 			| Out-File -FilePath $OutputFile -encoding ASCII -append
	" Proxy Configuration: PAC Files" 								| Out-File -FilePath $OutputFile -encoding ASCII -append
	"====================================================" 			| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append

	# Where are PAC files referenced?
	# HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad

	#-----PAC files
	#  Outside of SDP    = Inside SDP
	#  "c:\users\bbenson = $env:USERPROFILE + "
	#  "c:\windows       = $env:windir + "
	#
	#-----array*.script and wpad*.dat files in User Profile
	$pacUserProfPath = $env:USERPROFILE + "\AppData\Local\Microsoft\Windows\Temporary Internet Files\*"
	# Added Sort-Object to sort the array on creation
	#   | sort-object -property @{Expression={$_.LastAccessTime}; Ascending=$false}
	if (Test-Path $pacUserProfPath)
	{
		[array]$pacUserProf = Get-ChildItem $pacUserProfPath  -include array*.script,wpad*.dat -force -recurse | sort-object -property @{Expression={$_.LastAccessTime}; Ascending=$false}
		$pacUserProfLen = $pacUserProf.length
		if ($null -eq $pacUserProfLen)  
		{
			$pacUserProfLen = 0
		}
		else
		{
			if ($pacUserProfLen -ne 0)
			{
				[array]$pacArray = [array]$pacUserProf
				$pacArrayLen = $pacArray.length
			}
		}
	}
	#-----array*.script and wpad*.dat files in Windir Sys32
	$pacWindirSys32Path = $env:windir + "\System32\config\systemprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\*"
	# Added Sort-Object to sort the array on creation
	#   | sort-object -property @{Expression={$_.LastAccessTime}; Ascending=$false}
	if (Test-Path $pacWindirSys32Path)
	{
		[array]$pacWindirSys32 = Get-ChildItem $pacWindirSys32Path -include array*.script,wpad*.dat -force -recurse | sort-object -property @{Expression={$_.LastAccessTime}; Ascending=$false}
		$pacWindirSys32Len = $pacWindirSys32.length
		if ($null -eq $pacWindirSys32Len)
		{
			$pacWindirSys32Len = 0
		}
		else
		{
			if ($pacWindirSys32Len -ne 0)
			{
				[array]$pacArray = [array]$pacArray + [array]$pacWindirSys32
				$pacArrayLen = $pacArray.length
			}
		}
	}
	#-----array*.script and wpad*.dat files in Windir Syswow64
	$pacWindirSysWow64Path = $env:windir + "\SysWOW64\config\systemprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\*"
	# Added Sort-Object to sort the array on creation
	#   | sort-object -property @{Expression={$_.LastAccessTime}; Ascending=$false}
	if  (Test-Path $pacWindirSysWow64Path)
	{
		[array]$pacWindirSysWow64 = Get-ChildItem $pacWindirSysWow64Path -include array*.script,wpad*.dat -force -recurse  | sort-object -property @{Expression={$_.LastAccessTime}; Ascending=$false}
		$pacWindirSysWow64Len = $pacWindirSysWow64.length
		if ($null -eq $pacWindirSysWow64Len)
		{
			$pacWindirSysWow64Len = 0
		}
		else
		{
			if ($pacWindirSysWow64Len -ne 0)
			{
				[array]$pacArray = [array]$pacArray + [array]$pacWindirSysWow64
				$pacArrayLen = $pacArray.length
			}
		}
	}
	#-----Engineer message indicating where the script searched for the files.
		"--------------" | Out-File -FilePath $OutputFile -encoding ASCII -append
		"Searching for PAC files named wpad*.dat or array*.script in the following locations: " | Out-File -FilePath $OutputFile -encoding ASCII -append
		"--------------" | Out-File -FilePath $OutputFile -encoding ASCII -append
		"  %userprofile%\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" | Out-File -FilePath $OutputFile -encoding ASCII -append
		"  %windir%\System32\config\systemprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" | Out-File -FilePath $OutputFile -encoding ASCII -append
		"  %windir%\SysWOW64\config\systemprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" | Out-File -FilePath $OutputFile -encoding ASCII -append
		
		# dir "%userprofile%\AppData\Local\Microsoft\Windows\Temporary Internet Files\wpad*.dat" /s
		# dir "%userprofile%\AppData\Local\Microsoft\Windows\Temporary Internet Files\array*.script" /s
		# dir "%windir%\System32\config\systemprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\wpad*.dat" /s
		# dir "%windir%\System32\config\systemprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\array*.script" /s
		# dir "%windir%\SysWOW64\config\systemprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\wpad*.dat" /s
		# dir "%windir%\SysWOW64\config\systemprofile\AppData\Local\Microsoft\Windows\Temporary Internet Files\array*.script" /s


	if ($null -eq $pacArrayLen)
	{
		$pacArrayLen = 0
	}
	#-----Display the array
	if ($pacArrayLen -eq 0)
	{
		" " | Out-File -FilePath $OutputFile -encoding ASCII -append
		" " | Out-File -FilePath $OutputFile -encoding ASCII -append
		"--------------" | Out-File -FilePath $OutputFile -encoding ASCII -append
		"Found " + $pacArrayLen + " PAC files." | Out-File -FilePath $OutputFile -encoding ASCII -append
		"--------------" | Out-File -FilePath $OutputFile -encoding ASCII -append
		"There are " + $pacArrayLen + " PAC files named wpad*.dat or array*.script located within `"Temporary Internet Files`" for the user and/or the system." | Out-File -FilePath $OutputFile -encoding ASCII -append
	}
	elseif ($pacArrayLen -eq 1)
	{
		" " | Out-File -FilePath $OutputFile -encoding ASCII -append
		" " | Out-File -FilePath $OutputFile -encoding ASCII -append
		"--------------" | Out-File -FilePath $OutputFile -encoding ASCII -append
		"Found " + $pacArrayLen + " PAC file." | Out-File -FilePath $OutputFile -encoding ASCII -append
		"--------------" | Out-File -FilePath $OutputFile -encoding ASCII -append
		
		#-----Show FullName, LastWriteTime and LastAccessTime
		for($i=0;$i -lt $pacArrayLen;$i++)
		{
			" " | Out-File -FilePath $OutputFile -encoding ASCII -append
			"[#" + ($i+1) + "]" | Out-File -FilePath $OutputFile -encoding ASCII -append
			"FullName        : " + ($pacArray[$i]).FullName | Out-File -FilePath $OutputFile -encoding ASCII -append
			# "LastWriteTime   : " + ($pacArray[$i]).LastWriteTime | Out-File -FilePath $OutputFile -encoding ASCII -append
			"LastAccessTime  : " + ($pacArray[$i]).LastAccessTime | Out-File -FilePath $OutputFile -encoding ASCII -append
			" " | Out-File -FilePath $OutputFile -encoding ASCII -append
		}
	}
	elseif ($pacArrayLen -gt 1)
	{
		" " | Out-File -FilePath $OutputFile -encoding ASCII -append
		" " | Out-File -FilePath $OutputFile -encoding ASCII -append
		"--------------" | Out-File -FilePath $OutputFile -encoding ASCII -append
		"Found " + $pacArrayLen + " PAC files (in descending showing the most recent LastAccessTime first)" | Out-File -FilePath $OutputFile -encoding ASCII -append
		"--------------" | Out-File -FilePath $OutputFile -encoding ASCII -append
		
		#-----Show FullName, LastWriteTime and LastAccessTime
		for($i=0;$i -lt $pacArrayLen;$i++)
		{
			# Sort the array by LastAccessTime
			$pacArray | Sort-Object LastAccessTime -Descending
			
			# Text Output with no sorting
			" " | Out-File -FilePath $OutputFile -encoding ASCII -append
			"[#" + ($i+1) + "]" | Out-File -FilePath $OutputFile -encoding ASCII -append
			"FullName        : " + ($pacArray[$i]).FullName | Out-File -FilePath $OutputFile -encoding ASCII -append
			#"LastWriteTime   : " + ($pacArray[$i]).LastWriteTime | Out-File -FilePath $OutputFile -encoding ASCII -append
			"LastAccessTime  : " + ($pacArray[$i]).LastAccessTime | Out-File -FilePath $OutputFile -encoding ASCII -append
			" " | Out-File -FilePath $OutputFile -encoding ASCII -append
		}
	}

	If ($pacArrayLen -gt 0)
	{
		" " | Out-File -FilePath $OutputFile -encoding ASCII -append
		" " | Out-File -FilePath $OutputFile -encoding ASCII -append
		"------------------------" | Out-File -FilePath $OutputFile -encoding ASCII -append
		"Collecting PAC files" | Out-File -FilePath $OutputFile -encoding ASCII -append
		"------------------------" | Out-File -FilePath $OutputFile -encoding ASCII -append

		# Initialize array for PAC files with FullName
		for ($i=0;$i -lt $pacArrayLen;$i++)  { $pacFilesArray += @($i) }
		
		# Create array of PAC Files with FullName
		for ($i=0;$i -lt $pacArrayLen;$i++)
		{
			$pacFilesArray[$i] = "`"" + ($pacArray[$i]).FullName + "`""
			$pacFilesArray[$i]	| Out-File -FilePath $OutputFile -encoding ASCII -append
			#copy to temp dir
			$CommandToExecute = "cmd.exe /c copy " + $pacFilesArray[$i] + " " + $PWD
			RunCmD -commandToRun $CommandToExecute -CollectFiles $false
		}
		# This function fails because of file not found, but I know the file exists. Probably because of [] in name.
		# CollectFiles -filesToCollect $pacFilesArray[$i]
		
		#Collect PAC files
		$destFileName = $env:COMPUTERNAME + "_Proxy-PACFiles.zip"
		# CollectFiles -filesToCollect $pacFilesArray
		$pacFilesWpadDat = join-path $PWD "wpad*.dat"
		$pacFilesArrScript = join-path $PWD "array*.script"
		CompressCollectFiles -filestocollect $pacFilesWpadDat -DestinationFileName $destFileName
		CompressCollectFiles -filestocollect $pacFilesArrScript -DestinationFileName $destFileName
	}





#Network Isolation Policies
	"`n`n`n`n`n`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	"====================================================" 			| Out-File -FilePath $OutputFile -encoding ASCII -append
	"Network Isolation Policy Configuration (W8/WS2012+)" 			| Out-File -FilePath $OutputFile -encoding ASCII -append
	"====================================================" 			| Out-File -FilePath $OutputFile -encoding ASCII -append
	"`n`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	
	
	if (test-path HKLM:\Software\Policies\Microsoft\Windows\NetworkIsolation)
	{
		$netIsolationDomainLocalProxies 	= (Get-ItemProperty -path "HKLM:\Software\Policies\Microsoft\Windows\NetworkIsolation").DomainLocalProxies
		$netIsolationDomainProxies 			= (Get-ItemProperty -path "HKLM:\Software\Policies\Microsoft\Windows\NetworkIsolation").DomainProxies
		$netIsolationDomainSubnets 			= (Get-ItemProperty -path "HKLM:\Software\Policies\Microsoft\Windows\NetworkIsolation").DomainSubnets	
		$netIsolationDProxiesAuthoritive 	= (Get-ItemProperty -path "HKLM:\Software\Policies\Microsoft\Windows\NetworkIsolation").DProxiesAuthoritive
		$netIsolationDSubnetsAuthoritive 	= (Get-ItemProperty -path "HKLM:\Software\Policies\Microsoft\Windows\NetworkIsolation").DSubnetsAuthoritive
		
		"RegKey  : HKLM:\Software\Policies\Microsoft\Windows\NetworkIsolation" | Out-File -FilePath $OutputFile -encoding ASCII -append
		"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
		"RegValue: DomainLocalProxies" | Out-File -FilePath $OutputFile -encoding ASCII -append
		"RegData : " + $netIsolationDomainLocalProxies 		| Out-File -FilePath $OutputFile -encoding ASCII -append
		"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
		"RegValue: DomainProxies" | Out-File -FilePath $OutputFile -encoding ASCII -append
		"RegData : " + $netIsolationDomainProxies | Out-File -FilePath $OutputFile -encoding ASCII -append
		"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
		"RegValue: DomainSubnets" | Out-File -FilePath $OutputFile -encoding ASCII -append
		"RegData : " + $netIsolationDomainSubnets 				| Out-File -FilePath $OutputFile -encoding ASCII -append
		"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
		"RegValue: DProxiesAuthoritive" | Out-File -FilePath $OutputFile -encoding ASCII -append
		"RegData : " + $netIsolationDProxiesAuthoritive 		| Out-File -FilePath $OutputFile -encoding ASCII -append
		"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
		"RegValue: DSubnetsAuthoritive" | Out-File -FilePath $OutputFile -encoding ASCII -append
		"RegData : " + $netIsolationDSubnetsAuthoritive 		| Out-File -FilePath $OutputFile -encoding ASCII -append
		"`n"	| Out-File -FilePath $OutputFile -encoding ASCII -append
	}
	else
	{
		"Network Isolation policies are not configured.  This location does not exist: HKLM:\Software\Policies\Microsoft\Windows\NetworkIsolation" | Out-File -FilePath $OutputFile -encoding ASCII -append
	}

CollectFiles -filesToCollect $OutputFile -fileDescription "Proxy Configuration Information" -SectionDescription $sectionDescription


# SIG # Begin signature block
# MIInrQYJKoZIhvcNAQcCoIInnjCCJ5oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAs71Ar5tO5gIX5
# WyBmRAgOLdhK9E9a2l6yJYASIeIFAqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIN++y+YG+6QN0oCgQ5YFIpRZ
# oR3WgtahSznFT3mhTEJPMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBC62Bih6+J6KKjUBmKau4750a16CdIQbky2O+6sBccE5v7sELQo09t
# v9CMebjHmtO8tR5M5UqU3KTGjv5KgJzpAu0y9z+DqydBYcEYT6RdxgWoOJnlX0xx
# YEnobAGSXVmAufARhbCs4XzxpjYn3FQs7iggGLvAGScK0KbMLea8WXqpY0cFrZ8l
# CrcUn2qhIABmn+qcjnmiMuJcutMHL3E4Fbdxx9XjpHwtyGI8QTMMYA/0VAlb4nIM
# 0gxS3epAoBzpiyWB0o3o26Mj+doF6hs45lo2JLCFRRThcBMm2U5s5sHlsKoyroGZ
# DRl6HRgRoGTnGJkIv7KGF8wCoRQ9ozi2oYIXFTCCFxEGCisGAQQBgjcDAwExghcB
# MIIW/QYJKoZIhvcNAQcCoIIW7jCCFuoCAQMxDzANBglghkgBZQMEAgEFADCCAVgG
# CyqGSIb3DQEJEAEEoIIBRwSCAUMwggE/AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIGZGS5d4h0IWMgEOfcQgIeHKY8gnzkNenetDgr3L2v6/AgZi3ohP
# 7IkYEjIwMjIwODAxMDc1MDA3LjQxWjAEgAIB9KCB2KSB1TCB0jELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IEly
# ZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# TjpEMDgyLTRCRkQtRUVCQTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaCCEWUwggcUMIIE/KADAgECAhMzAAABj/NRqOtact3MAAEAAAGPMA0G
# CSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIx
# MTAyODE5Mjc0NloXDTIzMDEyNjE5Mjc0NlowgdIxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9w
# ZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDA4Mi00
# QkZELUVFQkExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCZVz7+tc8XHoWTj4Kkuu5s
# OstNrdC4AdFVe7L7OzFfCSiCRPRr5da4FpvAfKqPxFGJlBC929s6rk1ETE54eJoK
# 2RSxDTYRIB70LP6WgE22x8Krzjq7ei1YcImWqS8OtKvuYwGrBxFjtx+EAZ8u+Wkx
# KiOgCeTtF6P6NwmdjEh43fgXeH0nAA1jfrSgZgIhLuks6ixZX5vG6D26JNlgT9dy
# XJg0Xpd3Nn/MP/hTmnFPgxlCbMEa8Oz7xwN0D+y1l+P+vL6LRdRg0U+G6pz5QqTC
# b9c0cH4IOwZCX5lLQZxtRS6fhU9OEcmbqZEDAvnLzOm1YQihxtN5FJOZmdRraJgf
# YQ4FXt4KPHRJ1vqQtzXF0VFyQN5AZHgnXIXLJu5mxQ/zHR06wQSgtC46G4qUMtAS
# DsPpnGZkmdLwHTd7CT9KlUuqxvrpTarIXgHAO3W5mSMRnt+KcihSBLPgHt9Ytgh4
# 7Y4JjEgTRe/CxWin0+9NdNm0Y/POYdTvncZqsrK4zqhr+ppPNi+sB9RvspiG9VAr
# EZQ+Qv354qIzsbSp6ckIWtfNk/BFahxwBHfc+E0S67PMpkUngN5pMIuD/y4rRDhC
# MVF5/mfgf7YpAgSJtnvMh4FfeOCysgJvPNKbRBfdJFWZkf/8CqnxjGTBygjVYIGL
# O/zjP16rBEF1Dgdhw1tAwwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFPMG5nRrrknO
# 4qHOhZvbl/s3I3G8MB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8G
# A1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBs
# BggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# DQYJKoZIhvcNAQELBQADggIBAM1/06j3PKELmfWMLyJTs0ljf0WLOOHFnAlslj9i
# 3CfremUyVNJoGl6tqfnrp+5GiMYlK/cTBmz5Gu45TZP9lEPHhUd6wse1yUTwaYwz
# WpMxpk8vwjYWtGZ/k6ingapzE100QIEKVVmafQrMV08ypFrn/RHoKaComHSa68ia
# KSAe5u+iGxq88TLIdBr3gcPj8s0p39ghoIoo/P1IDl8BrimFDgS/PZq5j1JSW4h3
# kwr0flyNZXAHEK9gAP7UJb3PsayEmU2OoG9a0o7onQB6Z+DrPbyDupzsb+0K2uUf
# j/LbvL6y27BZc2/B2xJ3WW8HgzrcC4yX1inpq79cWScbMk8Xqf+5ZHomFC/OHjQg
# uB5OEuZiF/zP5oNvivY4EsbU/YHpoJNbZhCS3tOlSfMjRwoavbXcJsq0aT844gdK
# wM7FqyZ4Yn4WJQkKJXXnCHdplP9VP8+Qv0TiEMEDAa3j0bzyBII7TH2N90NlZ1YZ
# sQteVKYDcQ/h5NirtGuiVjTgbx8a0XSnO5m7jcDb3Noj2Uivm6UpHPwShAdTpy7Q
# /FTDQH0fxwCS9DFoy6ZFn/h8Juo1vhNw+Q9xY4jbhBiW+lu1P2nfV+VgSWZznCMa
# mUCTL+eQlxPQdkQ1d6fFa0++3iByiqml4k8DdL/UPnsovfrrt6kivTJXb3QTai1l
# sBbwMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0B
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
# dGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpEMDgyLTRCRkQtRUVCQTElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIa
# AxUAPk0vggR250gHB0agJpXRYFtBmmqggYMwgYCkfjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOaRmDowIhgPMjAyMjA4MDEw
# ODA5MzBaGA8yMDIyMDgwMjA4MDkzMFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA
# 5pGYOgIBADAHAgEAAgIRsDAHAgEAAgIRcTAKAgUA5pLpugIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBBQUAA4GBACGnwCh3giupZLMlEi+F1+yOMnQ0laAD9k5egbG5McE1
# z6fh4P2toTxZXXvbFxCu74FBbh5xstISVfyBDzyoMPSo+vdL8Vj/l2sHjeSmxlve
# yYhGm9HQCFSt9BX+zOCvHv7lME5lKKe904+x+3gocDOxZqF/sF+6axcl22m3r5af
# MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGP81Go61py3cwAAQAAAY8wDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgecdN8cAYVUaKS4WyjQqN
# g60OkP+k1/m2EU3Z0xChnXIwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCX
# cgVP4sbGC5WOIqbbYi2Y7p0UNZbydKG7o7qDzIXHHzCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABj/NRqOtact3MAAEAAAGPMCIEIMrJ
# GCclZZeyGeaDKCIlNmckWkQ0o1XfquXd4oojPRMqMA0GCSqGSIb3DQEBCwUABIIC
# AILAwg7OfE+g0b9eAKQ/iEy/oetnKUXhq9QDjHzm+w52yVShTPy82ZQIolDA15PL
# p6TUJG7PEdmwFzQEKnYhE65NpRNzRUqIsnvywfKQ+0BoH4GeekpfV/OIB+Y0L2hq
# UZYV067oESmefu6VJHXJDwfT6XlMme3pft3V5vY+UVdragYHRpjUvOvEeMXAaNjh
# TVV3Ls/uVsFz14/0tMOoT6b71F/lp9RKT9PJ6J89TxY3T648jjVG1McqCFaWuoi2
# e5YX7Nquvz92GMU7N/fxDoDSqbeFmQtCbsFqIVjoY9CEZHsC5YXhqwTPfbg6pi6y
# ADuOHTkwC57jhVitM3zwsJmUF4tIOl5muhcX3gT82nKFjxLYPWV/tCpn+3g6jr5S
# 6ntIDq/89yWlf0rl+0jHnGMPIMUR2PJn5+zi1qijSZq31xavXcjYpxN1qtWxRPU8
# 2F+90gS7yMP8apKyOThQ8UiZkKLJZcMDGF5zCcKgw28rK/PsXwH1GCRucl/t/GRB
# 3zqiR3zCxNYd//jCTJfMkXcxSPsLqIJBY6kHnqt/NkLb65Ootpm9CPXmZpdJsD+n
# YqEYZXY7u4Z7X2KH2uBnJUZ1QduXMX5e43EgweV1PECMaMjaWDr1BmJlyLj6i0wx
# 80RxLpBMZk1lR43GTdhHkPbxbr9AqrIIi1M1/EwCGZ8D
# SIG # End signature block
