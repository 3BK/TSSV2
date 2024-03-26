#************************************************
# DC_SurfacePro3.ps1
# Version 1.0.09.19.14: Created and tested SurfacePro3 scripts from Sep12-19
# Version 1.1.10.07.14: Added the "Operating System and SKU section"
# Version 1.2.10.08.14: Modified Surface Pro 3 "Wifi Driver Version" detection method since the same file version is used for MP67 and MP107. (Testing with two SP3s)
# Version 1.3.10.09.14: Added Surface Pro 3 "Wifi Driver Power Management Settings"
# Version 1.4.10.10.14: Added Surface Pro 3 Binary Versions section
# Version 1.5.10.15.14: Added Surface Pro 3 Secure Boot Configuration section
# Version 1.6.10.16.14: Added Surface Pro 3 WMI classes output
# Date: 2014
# Author: Boyd Benson (bbenson@microsoft.com) working with Scott McArthur (scottmca) and Tod Edwards (tode)
# Description: Collects information about Surface Pro 3.
# Called from: Networking and Setup Diagnostics
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
Write-DiagProgress -Activity $ScriptVariable.ID_SurfacePro3 -Status $ScriptVariable.ID_SurfacePro3Desc

$sectionDescription = "Surface Pro 3"

# detect OS version and SKU
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber
$sku = $((Get-CimInstance win32_operatingsystem).OperatingSystemSKU)
$domainRole = (Get-CimInstance -Class Win32_ComputerSystem).DomainRole	# 0 or 1: client; >1: server



Function isOSVersionAffected
{
	if ($bn -ge 9600)
	 {
		return $true
	 }
	 else
	 {
		return $false
	 }
}

Function isSurfacePro3
{
	# Check for: "HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS"; SystemSKU = Surface_Pro_3
	$regkeyBIOS = "HKLM:\HARDWARE\DESCRIPTION\System\BIOS"
	If (test-path $regkeyBIOS)
	{
		$regvalueSystemSKUReg = Get-ItemProperty -path $regkeyBIOS -name "SystemSKU" -ErrorAction SilentlyContinue
		$regvalueSystemSKU = $regvalueSystemSKUReg.SystemSKU
		if ($regvalueSystemSKU -eq "Surface_Pro_3")
		{
			return $true
		}
		else
		{
			return $false
		}
	}
}

Function GetOsVerName($bn)
{
	switch ($bn)
	{
		9600  {return "W8.1/WS2012R2"}
		9200  {return "W8/WS2012"}
		7601  {return "W7/WS2008R2 SP1"}
		7600  {return "W7/WS2008R2 RMT"}
	}
}

Function GetOsSkuName($sku)
{
	switch ($sku)
	{
		# GetProductInfo function
		# http://msdn.microsoft.com/en-us/library/ms724358.aspx
		#
		0  {return ""}
		1  {return "Ultimate Edition"}
		2  {return "Home Basic Edition"}
		3  {return "Home Basic Premium Edition"}
		4  {return "Enterprise Edition"}
		5  {return "Home Basic N Edition"}
		6  {return "Business Edition"}
		7  {return "Standard Server Edition"}
		8  {return "Datacenter Server Edition"}
		9  {return "Small Business Server Edition"}
		10 {return "Enterprise Server Edition"}
		11 {return "Starter Edition"}
		12 {return "Datacenter Server Core Edition"}
		13 {return "Standard Server Core Edition"}
		14 {return "Enterprise Server Core Edition"}
		15 {return "Enterprise Server Edition for Itanium-Based Systems"}
		16 {return "Business N Edition"}
		17 {return "Web Server Edition"}
		18 {return "Cluster Server Edition"}
		19 {return "Home Server Edition"}
		20 {return "Storage Express Server Edition"}
		21 {return "Storage Standard Server Edition"}
		22 {return "Storage Workgroup Server Edition"}
		23 {return "Storage Enterprise Server Edition"}
		24 {return "Server For Small Business Edition"}
		25 {return "Small Business Server Premium Edition"} # 0x00000019
		26 {return "Home Premium N Edition"} # 0x0000001a
		27 {return "Enterprise N Edition"} # 0x0000001b
		28 {return "Ultimate N Edition"} # 0x0000001c
		29 {return "Web Server Edition (core installation)"} # 0x0000001d
		30 {return "Windows Essential Business Server Management Server"} # 0x0000001e
		31 {return "Windows Essential Business Server Security Server"} # 0x0000001f
		32 {return "Windows Essential Business Server Messaging Server"} # 0x00000020
		33 {return "Server Foundation"} # 0x00000021
		34 {return "Windows Home Server 2011"} # 0x00000022 not found
		35 {return "Windows Server 2008 without Hyper-V for Windows Essential Server Solutions"} # 0x00000023
		36 {return "Server Standard Edition without Hyper-V (full installation)"} # 0x00000024
		37 {return "Server Datacenter Edition without Hyper-V (full installation)"} # 0x00000025
		38 {return "Server Enterprise Edition without Hyper-V (full installation)"} # 0x00000026
		39 {return "Server Datacenter Edition without Hyper-V (core installation)"} # 0x00000027
		40 {return "Server Standard Edition without Hyper-V (core installation)"} # 0x00000028
		41 {return "Server Enterprise Edition without Hyper-V (core installation)"} # 0x00000029
		42 {return "Microsoft Hyper-V Server"} # 0x0000002a
		43 {return "Storage Server Express (core installation)"} # 0x0000002b
		44 {return "Storage Server Standard (core installation)"} # 0x0000002c
		45 {return "Storage Server Workgroup (core installation)"} # 0x0000002d
		46 {return "Storage Server Enterprise (core installation)"} # 0x0000002e
		47 {return "Starter N"} # 0x0000002f
		48 {return "Professional Edition"} #0x00000030
		49 {return "ProfessionalN Edition"} #0x00000031
		50 {return "Windows Small Business Server 2011 Essentials"} #0x00000032
		51 {return "Server For SB Solutions"} #0x00000033
		52 {return "Server Solutions Premium"} #0x00000034
		53 {return "Server Solutions Premium (core installation)"} #0x00000035
		54 {return "Server For SB Solutions EM"} #0x00000036
		55 {return "Server For SB Solutions EM"} #0x00000037
		55 {return "Windows MultiPoint Server"} #0x00000038
		#not found: 3a
		59 {return "Windows Essential Server Solution Management"} #0x0000003b
		60 {return "Windows Essential Server Solution Additional"} #0x0000003c
		61 {return "Windows Essential Server Solution Management SVC"} #0x0000003d
		62 {return "Windows Essential Server Solution Additional SVC"} #0x0000003e
		63 {return "Small Business Server Premium (core installation)"} #0x0000003f
		64 {return "Server Hyper Core V"} #0x00000040
		 #0x00000041 not found
		 #0x00000042-48 not supported
		76 {return "Windows MultiPoint Server Standard (full installation)"} #0x0000004C
		77 {return "Windows MultiPoint Server Premium (full installation)"} #0x0000004D
		79 {return "Server Standard (evaluation installation)"} #0x0000004F
		80 {return "Server Datacenter (evaluation installation)"} #0x00000050
		84 {return "Enterprise N (evaluation installation)"} #0x00000054
		95 {return "Storage Server Workgroup (evaluation installation)"} #0x0000005F
		96 {return "Storage Server Standard (evaluation installation)"} #0x00000060
		98 {return "Windows 8 N"} #0x00000062
		99 {return "Windows 8 China"} #0x00000063
		100 {return "Windows 8 Single Language"} #0x00000064
		101 {return "Windows 8"} #0x00000065
		102 {return "Professional with Media Center"} #0x00000067
	}	
}



if ((isOSVersionAffected) -and (isSurfacePro3))
{
	$outputFile= $Computername + "_SurfacePro3_info.TXT"
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Surface Pro 3 Configuration Information"				| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Overview" 												| Out-File -FilePath $OutputFile -append
	'----------------------------------------------------'	| Out-File -FilePath $OutputFile -append
	"   1. Operating System and SKU"						| Out-File -FilePath $OutputFile -append
	"   2. Wifi Driver Version"								| Out-File -FilePath $OutputFile -append
	"   3. Wifi Driver Power Management Settings"		 	| Out-File -FilePath $OutputFile -append
	"   4. Firmware Versions"								| Out-File -FilePath $OutputFile -append
	"   5. Connected Standby Status"						| Out-File -FilePath $OutputFile -append
	"   6. Connected Standby Configuration"					| Out-File -FilePath $OutputFile -append
	"   7. Secure Boot Configuration"						| Out-File -FilePath $OutputFile -append
	"   8. WMI Class Information"							| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append



	"[info] Operating System and SKU section" 	| WriteTo-StdOut
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Operating System and SKU"  				| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"`n" 										| Out-File -FilePath $OutputFile -append
	$osVerName = GetOsVerName $bn
	"Operating System Name        : $osVerName" | Out-File -FilePath $OutputFile -append
	"Operating System Build Number: $bn" 		| Out-File -FilePath $OutputFile -append
	$osSkuName = GetOsSkuName $sku
	"Operating System SKU Name    : $osSkuName"	| Out-File -FilePath $OutputFile -append
	"`n`n`n`n" | Out-File -FilePath $OutputFile -append

	$WinCVRegKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion"
	If (test-path $WinCVRegKey)
	{
		$ImageNameReg   = Get-ItemProperty -Path $WinCVRegKey -Name ImageName
		$ImageName = $ImageNameReg.ImageName
	}
	
	$WinNTCVRegKey = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion"
	If (test-path $WinNTCVRegKey)
	{
		$BuildLabReg    = Get-ItemProperty -Path $WinNTCVRegKey -Name BuildLab
		$BuildLab = $BuildLabReg.BuildLab

		$BuildLabExReg  = Get-ItemProperty -Path $WinNTCVRegKey -Name BuildLabEx 
		$BuildLabEx = $BuildLabExReg.BuildLabEx

		$ProductNameReg = Get-ItemProperty -Path $WinNTCVRegKey -Name ProductName 
		$ProductName = $ProductNameReg.ProductName

		$CurrentBuildReg = Get-ItemProperty -Path $WinNTCVRegKey -Name CurrentBuild 
		$CurrentBuild = $CurrentBuildReg.CurrentBuild

		"Image Name    : $ImageName" | Out-File -FilePath $OutputFile -append		
		"BuildLab      : $BuildLab" | Out-File -FilePath $OutputFile -append
		"BuildLabEx    : $BuildLabEx" | Out-File -FilePath $OutputFile -append
		"ProductName   : $ProductName" | Out-File -FilePath $OutputFile -append
		"CurrentBuild  : $CurrentBuild" | Out-File -FilePath $OutputFile -append
	}
	"`n`n`n`n`n`n" | Out-File -FilePath $OutputFile -append



	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Wifi Driver Version" 									| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"`n" 													| Out-File -FilePath $OutputFile -append	
	"[info] Wifi Driver Version section"  | WriteTo-StdOut
	$marvelDriver = join-path $env:windir "\system32\drivers\mrvlpcie8897.sys"
	if (test-path $marvelDriver)
	{
		$marvelDriverInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($marvelDriver)
		$marvelDriverFileBuildPart = $marvelDriverInfo.FileBuildPart
		$marvelDriverProductVersion = $marvelDriverInfo.ProductVersion
		[string]$marvelDriverVersion = [string]$marvelDriverInfo.FileMajorPart + "." + [string]$marvelDriverInfo.FileMinorPart + "." + [string]$marvelDriverInfo.FileBuildPart + "." + [string]$marvelDriverInfo.FilePrivatePart
		# Latest driver (as of 9/9/14): 6.3.9410.0; MP107; DateModified: 8/22/14; Package version online: 15.68.3055.107;
		# Previous driver             : 6.3.9410.0; MP67 ; DateModified: 4/24/14;
		#
		"FileName      : $marvelDriver"					| Out-File -FilePath $OutputFile -append
		"FileVersion   : $marvelDriverVersion"			| Out-File -FilePath $OutputFile -append
		"ProductVersion: $marvelDriverProductVersion"	| Out-File -FilePath $OutputFile -append
		"`n" 											| Out-File -FilePath $OutputFile -append
		
		$marvelDriverProductVersionStartsWithMP = ($marvelDriverProductVersion).StartsWith("MP")
		if ($marvelDriverProductVersionStartsWithMP -eq $true) 
		{
			[int]$marvelDriverProductVersionInt = $marvelDriverProductVersion.Substring(2,$marvelDriverProductVersion.length-2)
		}
		if ($marvelDriverProductVersionInt -gt 107)
		{
			"The driver installed is more recent than the version from 9/9/14." | Out-File -FilePath $OutputFile -append
		}
		elseif ($marvelDriverProductVersionInt -eq 107)
		{
			"The driver installed is the most recent driver (as of 9/9/14)." | Out-File -FilePath $OutputFile -append	
			"Installed: MP107; 6.3.9410.0" | Out-File -FilePath $OutputFile -append
		}
		elseif ($marvelDriverProductVersionInt -eq 67)
		{
			"The driver installed is older than the recommended version." 			| Out-File -FilePath $OutputFile -append
			"The installed driver is MP67 with version 6.3.9410.0." 				| Out-File -FilePath $OutputFile -append
			"The most recent driver (as of 9/9/14) is MP107; 6.3.9410.0." | Out-File -FilePath $OutputFile -append
		}
		else
		{
			"The driver installed is an older version of the driver." 				| Out-File -FilePath $OutputFile -append
		}
		"`n" | Out-File -FilePath $OutputFile -append
		"`n" | Out-File -FilePath $OutputFile -append
		'--------------------------------------' | Out-File -FilePath $OutputFile -append			
		"Please refer to the following article:" 	| Out-File -FilePath $OutputFile -append
		'--------------------------------------' | Out-File -FilePath $OutputFile -append
		"Public Content:"	| Out-File -FilePath $OutputFile -append
		"`"Surface Pro 3 update history`""	| Out-File -FilePath $OutputFile -append
		"http://www.microsoft.com/surface/en-us/support/install-update-activate/pro-3-update-history" 	| Out-File -FilePath $OutputFile -append
	}
	else
	{
		"The driver `"\system32\drivers\mrvlpcie8897.sys`" does not exist on this system." | Out-File -FilePath $OutputFile -append
	}	
	"`n`n`n`n`n`n" | Out-File -FilePath $OutputFile -append



	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Wifi Driver Power Management Settings" 				| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"`n" 									| Out-File -FilePath $OutputFile -append	
	"[info] Wifi Driver Version section"	| WriteTo-StdOut
	
	$deviceFound = $false
	$regkeyNicSettingsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
	if (test-path $regkeyNicSettingsPath) 
	{
		if ($marvelDriverProductVersionInt -ge 107)
		{
			$regkeyNicSettings = Get-ItemProperty -Path $regkeyNicSettingsPath
			$regsubkeysNicSettings = Get-ChildItem -Path $regkeyNicSettingsPath -ErrorAction SilentlyContinue
			# using ErrorAction of SilentlyContinue because one subkey, "Properties", cannot be read.

			foreach ($childNicSettings in $regsubkeysNicSettings)
			{
				$childNicSettingsName = $childNicSettings.PSChildName
				if ($childNicSettingsName -eq "Properties")
				{
				}
				else
				{
					$childNicSettingsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\$childNicSettingsName"
					if (test-path $childNicSettingsPath)
					{
						$networkAdapterComponentId = (Get-ItemProperty -Path $childNicSettingsPath).ComponentId
						if ($networkAdapterComponentId -eq "pci\ven_11ab&dev_2b38&subsys_045e0001")
						{
							$deviceFound = $true
							
							# ConnectedStandby
							$regkeyPower = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"
							If (test-path $regkeyPower)
							{
								"[info] Power regkey exists"  | WriteTo-StdOut 
								$regvaluePowerCsEnabled = Get-ItemProperty -path $regkeyPower -name "CsEnabled" -ErrorAction SilentlyContinue
								if ($null -ne $regvaluePowerCsEnabled)
								{
									$regvaluePowerCsEnabled = $regvaluePowerCsEnabled.CsEnabled
									"[info] Connected Standby registry value exists: $regvaluePowerCsEnabled"  | WriteTo-StdOut 
									if ($regvaluePowerCsEnabled -ne 1)
									{
										"Connected Standby is currently DISABLED. This exposes the Power Management tab in the properties of the Wireless NIC."	| Out-File -FilePath $OutputFile -append
										"`n" | Out-File -FilePath $OutputFile -append

										# Power Management Settings
										#  ENABLED  and ENABLED:  PnPCapabilities = 0x0  (0)
										#  ENABLED  and DISABLED:  PnPCapabilities = 0x10 (16)
										#  DISABLED and DISABLED:  PnPCapabilities = 0x18 (24)
										$networkAdapterPnPCapabilities = (Get-ItemProperty -Path $childNicSettingsPath).PnPCapabilities
										if ($null -eq $networkAdapterPnPCapabilities)
										{
											"Setting Name   : `"Allow the computer to turn off this device to save power`"" | Out-File -FilePath $OutputFile -append
											"Setting Status : ENABLED" | Out-File -FilePath $OutputFile -append
											"`n" | Out-File -FilePath $OutputFile -append	
											"Setting Name   : `"Allow this device to wake the computer`"" | Out-File -FilePath $OutputFile -append
											"Setting Status : ENABLED" | Out-File -FilePath $OutputFile -append
											"`n" | Out-File -FilePath $OutputFile -append	
											"PnPCapabilities registry value: Does not exist." | Out-File -FilePath $OutputFile -append
											"`n" | Out-File -FilePath $OutputFile -append
										}
										if ($networkAdapterPnPCapabilities -eq 0)
										{
											"Setting Name   : `"Allow the computer to turn off this device to save power`"" | Out-File -FilePath $OutputFile -append
											"Setting Status : ENABLED" | Out-File -FilePath $OutputFile -append
											"`n" | Out-File -FilePath $OutputFile -append	
											"Setting Name   : `"Allow this device to wake the computer`"" | Out-File -FilePath $OutputFile -append
											"Setting Status : ENABLED" | Out-File -FilePath $OutputFile -append
											"`n" | Out-File -FilePath $OutputFile -append	
											"PnPCapabilities registry value: $networkAdapterPnPCapabilities" | Out-File -FilePath $OutputFile -append							
										}
										elseif ($networkAdapterPnPCapabilities -eq 16)
										{
											"Setting Name   : `"Allow the computer to turn off this device to save power`"" | Out-File -FilePath $OutputFile -append
											"Setting Status : ENABLED" | Out-File -FilePath $OutputFile -append
											"`n" | Out-File -FilePath $OutputFile -append	
											"Setting Name   : `"Allow this device to wake the computer`"" | Out-File -FilePath $OutputFile -append
											"Setting Status : DISABLED" | Out-File -FilePath $OutputFile -append
											"`n" | Out-File -FilePath $OutputFile -append	
											"PnPCapabilities registry value: $networkAdapterPnPCapabilities" | Out-File -FilePath $OutputFile -append
											"`n" | Out-File -FilePath $OutputFile -append		
										}
										elseif ($networkAdapterPnPCapabilities -eq 24)
										{
											"Setting Name   : `"Allow the computer to turn off this device to save power`"" | Out-File -FilePath $OutputFile -append
											"Setting Status : DISABLED" | Out-File -FilePath $OutputFile -append
											"`n" | Out-File -FilePath $OutputFile -append	
											"Setting Name   : `"Allow this device to wake the computer`"" | Out-File -FilePath $OutputFile -append
											"Setting Status : DISABLED" | Out-File -FilePath $OutputFile -append
											"`n" | Out-File -FilePath $OutputFile -append	
											"PnPCapabilities registry value: $networkAdapterPnPCapabilities" | Out-File -FilePath $OutputFile -append
											"`n" | Out-File -FilePath $OutputFile -append		
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	"`n`n`n`n`n`n" | Out-File -FilePath $OutputFile -append

	



	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Firmware Versions" 									| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"[info] Firmware Versions section"  | WriteTo-StdOut 
	"`n" | Out-File -FilePath $OutputFile -append	
	$regkeySamFirmware = "HKLM:\SYSTEM\CurrentControlSet\Control\FirmwareResources\{512B1F42-CCD2-403B-8118-2F54353A1226}"
	If (test-path $regkeySamFirmware)
	{
		$regvalueSamFirmwareFilename = Get-ItemProperty -path $regkeySamFirmware -name "Filename" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueSamFirmwareFilename)
		{
			$regvalueSamFirmwareFilename = $regvalueSamFirmwareFilename.Filename
			$regvalueSamFirmwareFileNameLatest = "SamFirmware.3.9.350.0.cap"
		}
		$regvalueSamFirmwareVersion = Get-ItemProperty -path $regkeySamFirmware -name "Version" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueSamFirmwareVersion)
		{
			$regvalueSamFirmwareVersion = $regvalueSamFirmwareVersion.Version
			"Surface Pro System Aggregator Firmware"									| Out-File -FilePath $OutputFile -append
			"  SamFirmware Installed Version   : $regvalueSamFirmwareFileName"			| Out-File -FilePath $OutputFile -append
			"  SamFirmware Recommended Version : $regvalueSamFirmwareFileNameLatest"	| Out-File -FilePath $OutputFile -append
			if ($regvalueSamFirmwareVersion -lt 50922320)	# Hex 0x03090350
			{
				"  The installed file version is older than the firmware update from 09.09.14."	| Out-File -FilePath $OutputFile -append
			}
			elseif ($regvalueSamFirmwareVersion -eq 50922320)	# Hex 0x03090350
			{
				"  The installed file version matches the firmware update from 09.09.14."	| Out-File -FilePath $OutputFile -append
			}
			elseif ($regvalueSamFirmwareVersion -gt 50922320)	# Hex 0x03090350
			{
				"  The installed file version is newer than the firmware update from 09.09.14."	| Out-File -FilePath $OutputFile -append
			}
		}
	}
	"`n" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append


	$regkeyECFirmware = "HKLM:\SYSTEM\CurrentControlSet\Control\FirmwareResources\{52D9DA80-3D55-47E4-A9ED-D538A9B88146}"
	If (test-path $regkeyECFirmware)
	{
		$regvalueECFirmwareFileName = Get-ItemProperty -path $regkeyECFirmware -name "FileName" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueECFirmwareFileName)
		{
			$regvalueECFirmwareFileName = $regvalueECFirmwareFileName.FileName
			$regvalueECFirmwareFileNameLatest = "ECFirmware.38.6.50.0.cap"
		}
		$regvalueECFirmwareVersion = Get-ItemProperty -path $regkeyECFirmware -name "Version" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueECFirmwareVersion)
		{
			$regvalueECFirmwareVersion = $regvalueECFirmwareVersion.Version
			"Surface Pro Embedded Controller Firmware"							| Out-File -FilePath $OutputFile -append
			"  ECFirmware Installed Version   : $regvalueECFirmwareFileName"		| Out-File -FilePath $OutputFile -append
			"  ECFirmware Recommended Version : $regvalueECFirmwareFileNameLatest"	| Out-File -FilePath $OutputFile -append
			if ($regvalueECFirmwareVersion -lt 3671632)	# Hex 0x00380650
			{
				"  The installed firmware version is older than the firmware update from 09.09.14."	| Out-File -FilePath $OutputFile -append
			}
			elseif ($regvalueECFirmwareVersion -eq 3671632)	# Hex 0x00380650
			{
				"  The installed firmware version matches the firmware update from 09.09.14."	| Out-File -FilePath $OutputFile -append
			}
			elseif ($regvalueECFirmwareVersion -gt 3671632)	# Hex 0x00380650
			{
				"  The installed firmware version is newer than the firmware update from 09.09.14."	| Out-File -FilePath $OutputFile -append
			}
		}
	}
	"`n`n" | Out-File -FilePath $OutputFile -append

	

	$regkeyUEFI = "HKLM:\SYSTEM\CurrentControlSet\Control\FirmwareResources\{5A2D987B-CB39-42FE-A4CF-D5D0ABAE3A08}"
	If (test-path $regkeyUEFI)
	{
		$regvalueUEFIFileName = Get-ItemProperty -path $regkeyUEFI -name "FileName" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueUEFIFileName)
		{
			$regvalueUEFIFileName = $regvalueUEFIFileName.FileName
			$regvalueUEFIFileNameLatest = "UEFI.3.10.250.0.cap"
		}
		
		$regvalueUEFIVersion = Get-ItemProperty -path $regkeyUEFI -name "Version" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueUEFIVersion)
		{
			$regvalueUEFIVersion  = $regvalueUEFIVersion.Version
			"Surface Pro UEFI"										| Out-File -FilePath $OutputFile -append
			"  UEFI Installed Version   : $regvalueUEFIFileName"		| Out-File -FilePath $OutputFile -append
			"  UEFI Recommended Version : $regvalueUEFIFileNameLatest"	| Out-File -FilePath $OutputFile -append
			if ($regvalueUEFIVersion -lt 50987258)	# Hex 0x030a00fa
			{
				"  The installed firmware version is older than the firmware update from 09.09.14."	| Out-File -FilePath $OutputFile -append
			}
			elseif ($regvalueUEFIVersion -eq 50987258)	# Hex 0x030a00fa
			{
				"  The installed firmware version matches the firmware update from 09.09.14."	| Out-File -FilePath $OutputFile -append
			}
			elseif ($regvalueUEFIVersion -gt 50987258)	# Hex 0x030a00fa
			{
				"  The installed firmware version is newer than the firmware update from 09.09.14."	| Out-File -FilePath $OutputFile -append
			}
		}
	}
	"`n`n" | Out-File -FilePath $OutputFile -append



	$regkeyTouchFirmware = "HKLM:\SYSTEM\CurrentControlSet\Control\FirmwareResources\{E5FFF56F-D160-4365-9E21-22B06F6746DD}"
	$regvalueTouchFirmwareFileName = Get-ItemProperty -path $regkeyTouchFirmware -name "FileName" -ErrorAction SilentlyContinue
	if ($null -ne $regvalueTouchFirmwareFileName)
	{
		$regvalueTouchFirmwareFileName = $regvalueTouchFirmwareFileName.FileName
		$regvalueTouchFirmwareFileNameLatest = "TouchFirmware.426.27.66.0.cap"
	}
	$regvalueTouchFirmwareVersion = Get-ItemProperty -path $regkeyTouchFirmware -name "Version" -ErrorAction SilentlyContinue
	if ($null -ne $regvalueTouchFirmwareVersion)
	{
		$regvalueTouchFirmwareVersion = $regvalueTouchFirmwareVersion.Version
		"Surface Pro Touch Controller Firmware"										| Out-File -FilePath $OutputFile -append
		"  TouchFirmware Installed Version   : $regvalueTouchFirmwareFileName"			| Out-File -FilePath $OutputFile -append
		"  TouchFirmware Recommended Version : $regvalueTouchFirmwareFileNameLatest"	| Out-File -FilePath $OutputFile -append
		if ($regvalueTouchFirmwareVersion -lt 27925314)	# Hex 0x01aa1b42
		{
			"  The installed firmware version is older than the firmware update from 09.09.14."	| Out-File -FilePath $OutputFile -append
		}
		elseif ($regvalueTouchFirmwareVersion -eq 27925314)	# Hex 0x01aa1b42
		{
			"  The installed firmware version matches the firmware update from 09.09.14."	| Out-File -FilePath $OutputFile -append
		}
		elseif ($regvalueTouchFirmwareVersion -gt 27925314)	# Hex 0x01aa1b42
		{
			"  The installed firmware version is newer than the firmware update from 09.09.14."	| Out-File -FilePath $OutputFile -append
		}
	}
	"`n`n" | Out-File -FilePath $OutputFile -append
	'---------------------------------------' | Out-File -FilePath $OutputFile -append	
	"Please refer to the following articles:"	| Out-File -FilePath $OutputFile -append
	'---------------------------------------' | Out-File -FilePath $OutputFile -append	
	"Public Content:"	| Out-File -FilePath $OutputFile -append
	"`"Surface Pro 3, Surface Pro 2, and Surface Pro firmware and driver packs`""	| Out-File -FilePath $OutputFile -append
	"http://www.microsoft.com/en-us/download/details.aspx?id=38826" 	| Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"Internal Content:"	| Out-File -FilePath $OutputFile -append
	"`"2961421 - Surface: How to check firmware versions`""	| Out-File -FilePath $OutputFile -append
	"https://vkbexternal.partners.extranet.microsoft.com/VKBWebService/ViewContent.aspx?scid=B;EN-US;2961421"	| Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n" | Out-File -FilePath $OutputFile -append

	



	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Connected Standby Status" 								| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append	
	"[info] Connected Standby Status section"  | WriteTo-StdOut 
	# Check for HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power "CsEnabled" = dword:00000000
	$regkeyPower = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"
	If (test-path $regkeyPower)
	{
		"[info] Power regkey exists"  | WriteTo-StdOut 
		$regvaluePowerCsEnabled = Get-ItemProperty -path $regkeyPower -name "CsEnabled" -ErrorAction SilentlyContinue
		if ($null -ne $regvaluePowerCsEnabled)
		{
			$regvaluePowerCsEnabled = $regvaluePowerCsEnabled.CsEnabled
			"[info] Connected Standby registry value exists: $regvaluePowerCsEnabled"  | WriteTo-StdOut 
			if ($regvaluePowerCsEnabled -eq 1)
			{
				"Connected Standby is currently: ENABLED"	| Out-File -FilePath $OutputFile -append
				"CsEnabled = 1"								| Out-File -FilePath $OutputFile -append
			}
			else
			{
				"Connected Standby is currently: DISABLED"	| Out-File -FilePath $OutputFile -append
				"CsEnabled = $regvaluePowerCsEnabled"		| Out-File -FilePath $OutputFile -append
				"CsEnabled should be enabled (set to 1)."	| Out-File -FilePath $OutputFile -append
			}
		}
		"`n`n" | Out-File -FilePath $OutputFile -append
		
		
		# Checking for Hyper-V
		#
		# Win32_ComputerSystem class
		# http://msdn.microsoft.com/en-us/library/aa394102(v=vs.85).aspx
		#
		"[info] Checking for Windows Optional Feature (client SKUs) or Hyper-V Role (server SKUs)"  | WriteTo-StdOut 
		if ($domainRole -gt 1) 
		{ #Server
			$HyperV = Get-WindowsFeature | Where-Object {($_.installed -eq $true) -and ($_.DisplayName -eq "Hyper-V")}
			If ($null -ne $HyperV)
			{
				"Hyper-V Role: Installed"	| Out-File -FilePath $OutputFile -append
			}
			else
			{
				"Hyper-V Role: Not Installed"	| Out-File -FilePath $OutputFile -append
			}
		}
		else
		{ #Client
			$HypervClient = Get-WindowsOptionalFeature -online | Where-Object {($_.FeatureName -eq "Microsoft-Hyper-V")}
			if ($HyperVClient.State -eq "Enabled")
			{
				"Windows Optional Feature `"Client Hyper-V`": Installed"	| Out-File -FilePath $OutputFile -append
			}
			else
			{
				"Windows Optional Feature `"Client Hyper-V`": Not Installed"	| Out-File -FilePath $OutputFile -append
			}
		}
	}
	"`n" | Out-File -FilePath $OutputFile -append
	'--------------------------------------' | Out-File -FilePath $OutputFile -append	
	"Please refer to the following article:"	| Out-File -FilePath $OutputFile -append
	'--------------------------------------' | Out-File -FilePath $OutputFile -append	
	"Public Content:" | Out-File -FilePath $OutputFile -append
	"`"2973536 - Connected Standby is not available when the Hyper-V role is enabled`"" | Out-File -FilePath $OutputFile -append
	"http://support.microsoft.com/kb/2973536/EN-US" | Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n" | Out-File -FilePath $OutputFile -append



	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Connected Standby Hibernation Configuration" 			| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append	
	"[info] Connected Standby Hibernation Configuration section"  | WriteTo-StdOut 
	#
	# Connected Standby Battery Saver Timeout
	#
	"Connected Standby: Battery Saver Timeout"	| Out-File -FilePath $OutputFile -append
	$regkeyCsBsTimeout = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\381b4222-f694-41f0-9685-ff5bb260df2e\e73a048d-bf27-4f12-9731-8b2076e8891f\7398e821-3937-4469-b07b-33eb785aaca1"
	If (test-path $regkeyCsBsTimeout)
	{
		$regvalueCsBsTimeoutACSettingIndexRecommended = 14400
		$regvalueCsBsTimeoutACSettingIndex = Get-ItemProperty -path $regkeyCsBsTimeout -name "ACSettingIndex" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueCsBsTimeoutACSettingIndex)
		{
			$regvalueCsBsTimeoutACSettingIndex = $regvalueCsBsTimeoutACSettingIndex.ACSettingIndex
			if ($regvalueCsBsTimeoutACSettingIndex -ne $regvalueCsBsTimeoutACSettingIndexRecommended)
			{
				"  ACSettingIndex (Current Setting: Not Optimal)      = $regvalueCsBsTimeoutACSettingIndex" | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"  ACSettingIndex (Current Setting: No Action Needed) = $regvalueCsBsTimeoutACSettingIndex" | Out-File -FilePath $OutputFile -append				
			}
		}
		else
		{
			"  ACSettingIndex registry value does not exist."	| Out-File -FilePath $OutputFile -append
		}
		
		$regvalueCsBsTimeoutDCSettingIndexRecommended = 14400
		$regvalueCsBsTimeoutDCSettingIndex = Get-ItemProperty -path $regkeyCsBsTimeout -name "DCSettingIndex" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueCsBsTimeoutDCSettingIndex)
		{
			$regvalueCsBsTimeoutDCSettingIndex = $regvalueCsBsTimeoutDCSettingIndex.DCSettingIndex
			if ($regvalueCsBsTimeoutDCSettingIndex -ne $regvalueCsBsTimeoutDCSettingIndexRecommended)
			{
				"  DCSettingIndex (Current Setting: Not Optimal)      = $regvalueCsBsTimeoutDCSettingIndex"			| Out-File -FilePath $OutputFile -append
				#"Connected Standby Battery Saver Timeout: DCSettingIndex (Recommended Setting) = $regvalueCsBsTimeoutDCSettingIndexRecommended"	| Out-File -FilePath $OutputFile -append
			}
			else
			{
				"  DCSettingIndex (Current Setting: No Action Needed) = $regvalueCsBsTimeoutDCSettingIndex"			| Out-File -FilePath $OutputFile -append				
			}
		}
		else
		{
			"Connected Standby Battery Saver Timeout DCSettingIndex registry value does not exist."	| Out-File -FilePath $OutputFile -append
		}
	}
	"`n`n"	| Out-File -FilePath $OutputFile -append



	#
	# Connected Standby Battery Saver Trip Point
	#
	"Connected Standby: Battery Saver Trip Point"	| Out-File -FilePath $OutputFile -append
	$regkeyCsBsTripPoint = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\381b4222-f694-41f0-9685-ff5bb260df2e\e73a048d-bf27-4f12-9731-8b2076e8891f\1e133d45-a325-48da-8769-14ae6dc1170b"
	If (test-path $regkeyCsBsTripPoint)
	{
		$regvalueCsBstpACSettingIndexRecommended = 100
		$regvalueCsBstpACSettingIndex = Get-ItemProperty -path $regkeyCsBsTripPoint -name "ACSettingIndex" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueCsBstpACSettingIndex)	
		{
			$regvalueCsBstpACSettingIndex = $regvalueCsBstpACSettingIndex.ACSettingIndex
			if ($regvalueCsBstpACSettingIndex -ne $regvalueCsBstpACSettingIndexRecommended)
			{
				"  ACSettingIndex (Current Setting: Not Optimal)      = $regvalueCsBstpACSettingIndex" | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"  ACSettingIndex (Current Setting: No Action Needed) = $regvalueCsBstpACSettingIndex" | Out-File -FilePath $OutputFile -append
			}
		}
		else
		{
			"Connected Standby Battery Saver Trip Point: ACSettingIndex registry value does not exist."	| Out-File -FilePath $OutputFile -append
		}
		
		
		$regvalueCsBstpDCSettingIndex = Get-ItemProperty -path $regkeyCsBsTripPoint -name "DCSettingIndex" -ErrorAction SilentlyContinue	
		if ($null -ne $regvalueCsBstpDCSettingIndex)	
		{
			$regvalueCsBstpDCSettingIndexRecommended = 100
			$regvalueCsBstpDCSettingIndex = $regvalueCsBstpDCSettingIndex.DCSettingIndex
			if ($regvalueCsBstpDCSettingIndex -ne $regvalueCsBstpDCSettingIndexRecommended)
			{
				"  DCSettingIndex (Current Setting: Not Optimal)      = $regvalueCsBstpDCSettingIndex"  | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"  DCSettingIndex (Current Setting: No Action Needed) = $regvalueCsBstpDCSettingIndex"  | Out-File -FilePath $OutputFile -append
			}
		}
		else
		{
			"Connected Standby Battery Saver Trip Point DCSettingIndex registry value does not exist."	| Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Connected Standby Battery Saver Trip Point registry key does not exist: $regkeyCsBsTripPoint"	| Out-File -FilePath $OutputFile -append
	}
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append


	
	#
	# Connected Standby Battery Saver Action
	#
	"Connected Standby: Battery Saver Action"	| Out-File -FilePath $OutputFile -append
	$regkeyCsBsAction = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\381b4222-f694-41f0-9685-ff5bb260df2e\e73a048d-bf27-4f12-9731-8b2076e8891f\c10ce532-2eb1-4b3c-b3fe-374623cdcf07"
	If (test-path $regkeyCsBsAction)
	{
		$regvalueCsBsActionACSettingIndex = Get-ItemProperty -path $regkeyCsBsAction -name "ACSettingIndex" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueCsBsActionACSettingIndex)
		{
			$regvalueCsBsActionACSettingIndexRecommended = 1
			$regvalueCsBsActionACSettingIndex = $regvalueCsBsActionACSettingIndex.ACSettingIndex
			if ($regvalueCsBsActionACSettingIndex -ne $regvalueCsBsActionACSettingIndexRecommended)
			{
				"  ACSettingIndex (Current Setting: Not Optimal)      = $regvalueCsBsActionACSettingIndex"		| Out-File -FilePath $OutputFile -append
			}
			else
			{
				"  ACSettingIndex (Current Setting: No Action Needed) = $regvalueCsBsActionACSettingIndex"		| Out-File -FilePath $OutputFile -append
			}
		}
		else
		{
			"  ACSettingIndex registry value does not exist."	| Out-File -FilePath $OutputFile -append
		}

		$regvalueCsBsActionDCSettingIndex = Get-ItemProperty -path $regkeyCsBsAction -name "DCSettingIndex" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueCsBsActionDCSettingIndex)
		{
			$regvalueCsBsActionDCSettingIndexRecommended = 1
			$regvalueCsBsActionDCSettingIndex = $regvalueCsBsActionDCSettingIndex.DCSettingIndex
			if ($regvalueCsBsActionDCSettingIndex -ne $regvalueCsBsActionDCSettingIndexRecommended)
			{
				"  DCSettingIndex (Current Setting: Not Optimal)      = $regvalueCsBsActionDCSettingIndex"  | Out-File -FilePath $OutputFile -append
			}
			else
			{
				"  DCSettingIndex (Current Setting: No Action Needed) = $regvalueCsBsActionDCSettingIndex"  | Out-File -FilePath $OutputFile -append
			}
		}
		else
		{
			"  DCSettingIndex registry value does not exist."	| Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"Connected Standby Battery Saver Action registry key does not exist: $regkeyCsBsAction"	| Out-File -FilePath $OutputFile -append
	}
	"`n`n" | Out-File -FilePath $OutputFile -append
	'--------------------------------------' | Out-File -FilePath $OutputFile -append	
	"Please refer to the following article:"	| Out-File -FilePath $OutputFile -append
	'--------------------------------------' | Out-File -FilePath $OutputFile -append	
	"Internal Content:" | Out-File -FilePath $OutputFile -append
	"`"Surface Pro 3 does not hibernate after 4 hours in connected standby`""	| Out-File -FilePath $OutputFile -append
	"https://vkbexternal.partners.extranet.microsoft.com/VKBWebService/ViewContent.aspx?scid=KB;EN-US;2998588" | Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n" | Out-File -FilePath $OutputFile -append

	
	
	#
	# Secure Boot Overview
	# http://technet.microsoft.com/en-us/library/hh824987.aspx
	#
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Secure Boot Configuration" 							| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append	
	"[info] Secure Boot section"  | WriteTo-StdOut 

	
	'------------------------------'	| Out-File -FilePath $OutputFile -append
	"Secure Boot Status"				| Out-File -FilePath $OutputFile -append
	"  (using Confirm-SecureBootUEFI)"	| Out-File -FilePath $OutputFile -append
	'------------------------------'	| Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	# Determine if SecureBoot is enabled.
	#
	$secureBootEnabled = $false
	If ((Confirm-SecureBootUEFI) -eq $true)
	{
		$secureBootEnabled = $true
		"Secure Boot: ENABLED"	| Out-File -FilePath $OutputFile -append
	}
	else
	{
		"Secure Boot: DISABLED"	| Out-File -FilePath $OutputFile -append		
	}
	"`n`n`n" | Out-File -FilePath $OutputFile -append


	'------------------------------'	| Out-File -FilePath $OutputFile -append
	"Secure Boot Policy UEFI"			| Out-File -FilePath $OutputFile -append
	"  (using Get-SecureBootPolicy)"	 	| Out-File -FilePath $OutputFile -append
	'------------------------------'	| Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append	
	# Determine what policy is in use for SecureBootUEFI with Get-SecureBootPolicy
	#
	if ($secureBootEnabled)
	{
		$GUID = Get-SecureBootPolicy
		$DebugPolicyString = $Guid.Publisher.ToString()
		$DefaultPolicy = "77FA9ABD-0359-4D32-BD60-28F4E78F784B"
		$DefaultPolicyARM = "77FA9ABD-0359-4D32-BD60-28F4E78F784B"
		$DebugPolicy = "0CDAD82E-D839-4754-89A1-844AB282312B"

		"SecureBoot Policy Mode GUID: $DebugPolicyString" | Out-File -FilePath $OutputFile -append
		if($DebugPolicyString -match $DefaultPolicy) {
			"SecureBoot Policy Mode     : PRODUCTION" | Out-File -FilePath $OutputFile -append
		}
		elseif($DebugPolicyString -match $DefaultPolicyARM) {
			"SecureBoot Policy Mode     : PRODUCTION" | Out-File -FilePath $OutputFile -append
		}
		elseif($DebugPolicyString -match $DebugPolicy) {
			"SecureBoot Policy Mode     : DEBUG" | Out-File -FilePath $OutputFile -append
		}
		else {
			"SecureBoot Policy Mode: Invalid Policy $DebugPolicyString" 
		}
	}
	"`n`n`n" | Out-File -FilePath $OutputFile -append	


	'----------------------------------------------------'	| Out-File -FilePath $OutputFile -append
	"Secure Boot Policy UEFI"								| Out-File -FilePath $OutputFile -append
	"  Using `"Get-SecureBootUefi -Name PK | fl *`" "		| Out-File -FilePath $OutputFile -append
	'----------------------------------------------------'	| Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	# Get-SecureBootUEFI
	"Get-SecureBootUefi -Name PK | fl *" | Out-File -FilePath $OutputFile -append
	Get-SecureBootUefi -Name PK | Format-List *	| Out-File -FilePath $OutputFile -append
	"`n`n`n" | Out-File -FilePath $OutputFile -append

	'----------------------------------------------------'	| Out-File -FilePath $OutputFile -append
	"Secure Boot Policy UEFI"								| Out-File -FilePath $OutputFile -append
	"  Using Output of `"Get-SecureBootUEFI -Name PK -OutputFilePath SecureBootPk.tmp`""	| Out-File -FilePath $OutputFile -append
	'----------------------------------------------------'	| Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	Get-SecureBootUEFI -Name PK -OutputFilePath SecureBootPk.tmp
	$pk = (Get-content SecureBootPk.tmp)
	$pk | Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n" | Out-File -FilePath $OutputFile -append
	

	"===================================================="	| Out-File -FilePath $OutputFile -append
	"WMI Class Information" 								| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append	

	'------------------------------'	| Out-File -FilePath $OutputFile -append
	"WMI Class: win32_baseboard"		| Out-File -FilePath $OutputFile -append
	'------------------------------'	| Out-File -FilePath $OutputFile -append
	$baseboard = Get-CimInstance -Class "win32_baseboard"
	$baseboard | Format-List *   | Out-File -FilePath $OutputFile -append
	"`n`n`n" | Out-File -FilePath $OutputFile -append	
	
	'------------------------------'	| Out-File -FilePath $OutputFile -append
	"WMI Class: win32_battery"			| Out-File -FilePath $OutputFile -append
	'------------------------------'	| Out-File -FilePath $OutputFile -append
	$battery = Get-CimInstance -Class "win32_battery"
	$battery | Format-List *   | Out-File -FilePath $OutputFile -append
	"`n`n`n" | Out-File -FilePath $OutputFile -append	

	
	
	'------------------------------'	| Out-File -FilePath $OutputFile -append
	"WMI Class: win32_bios"				| Out-File -FilePath $OutputFile -append
	'------------------------------'	| Out-File -FilePath $OutputFile -append
	$bios = Get-CimInstance -Class "win32_bios"
	$bios | Format-List *   | Out-File -FilePath $OutputFile -append
	"`n`n`n" | Out-File -FilePath $OutputFile -append	
	
	
	'------------------------------'	| Out-File -FilePath $OutputFile -append
	"WMI Class: win32_computersystem"	| Out-File -FilePath $OutputFile -append
	'------------------------------'	| Out-File -FilePath $OutputFile -append
	$computersystem = Get-CimInstance -Class "win32_computersystem"
	$computersystem | Format-List *   | Out-File -FilePath $OutputFile -append
	"`n`n`n" | Out-File -FilePath $OutputFile -append	

	CollectFiles -filesToCollect $outputFile -fileDescription "Surface Pro 3 Information" -SectionDescription $sectionDescription

	$outputFile= $Computername + "_SurfacePro3_binary_versions.TXT"

	function componentSection
	{
		param 
		(
			[string]$component
		)
		$columnWidth = 52
		$componentLen = $component.length
		[int]$headerPrefix = 10
		$buffer = ($columnWidth - $componentLen - $headerPrefix)
		"-" * $headerPrefix + $component + "-" * $buffer	| Out-File -FilePath $OutputFile -append
	}

	function fileVersion
	{
		param
		(
			[string]$filename
		)

		$filenameLen = $filename.length
		$filenameExtPosition = $filenameLen - 4
		
		If ($filename.Substring($filenameExtPosition,4) -match ".sys")
		{
			$wmiQuery = "select * from cim_datafile where name='c:\\windows\\system32\\drivers\\" + $filename + "'" 
		}
		elseif ($filename.Substring($filenameExtPosition,4) -match ".dll")
		{
			$wmiQuery = "select * from cim_datafile where name='c:\\windows\\system32\\" + $filename + "'" 
		}
		elseif ($filename -match "explorer.exe")
		{
			$wmiQuery = "select * from cim_datafile where name='c:\\windows\\" + $filename + "'" 
		}
		elseif ($filename.Substring($filenameExtPosition,4) -match ".exe")
		{
			$wmiQuery = "select * from cim_datafile where name='c:\\windows\\system32\\" + $filename + "'" 
		}

		$fileObj = Get-CimInstance -query $wmiQuery
		$filenameLength = $filename.Length
		$columnLen = 35
		if (($filenameLength + 3) -ge ($columnLen))
		{
			$columnLen = $filenameLength + 3
			$columnDiff = $columnLen - $filenameLength
			$columnPrefix = 3
			$fileLine = " " * ($columnPrefix) + $filename + " " * ($columnDiff) + $fileObj.version
		}
		else
		{
			$columnDiff = $columnLen - $filenameLength
			$columnPrefix = 3
			$fileLine = " " * ($columnPrefix) + $filename + " " * ($columnDiff) + $fileObj.version
		}
		
		return $fileLine
	}


	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Surface Pro 3 Binary Versions"							| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Overview"												| Out-File -FilePath $OutputFile -append
	'----------------------------------------------------'	| Out-File -FilePath $OutputFile -append
	"   1. Bluetooth"										| Out-File -FilePath $OutputFile -append
	"   3. Keyboards"										| Out-File -FilePath $OutputFile -append
	"   4. Network Adapters"								| Out-File -FilePath $OutputFile -append
	"   5. System Devices"									| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n" | Out-File -FilePath $OutputFile -append
	"[info] Surface Pro 3 Binaries"  | WriteTo-StdOut

	"[info] Surface Pro 3 Binaries: Bluetooth"  | WriteTo-StdOut
	#componentSection -component "Bluetooth"
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Bluetooth"												| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"Marvell AVASTAR Bluetooth Radio Adapter"	| Out-File -FilePath $OutputFile -append
	fileVersion -filename Bthport.sys	| Out-File -FilePath $OutputFile -append
	fileVersion -filename Bthusb.sys	| Out-File -FilePath $OutputFile -append
	fileVersion -filename Fsquirt.exe	| Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"Microsoft Bluetooth Enumerator"	| Out-File -FilePath $OutputFile -append
	fileVersion -filename Bthenum.sys	| Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"Microsoft Bluetooth LE Enumerator"	| Out-File -FilePath $OutputFile -append
	fileVersion -filename bthLEEnum.sys	| Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n" | Out-File -FilePath $OutputFile -append

	"[info] Surface Pro 3 Binaries: Human Interface Devices"  | WriteTo-StdOut
	#componentSection -component "Human Interface Devices"
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Human Interface Devices"								| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"Surface Pen Driver"	| Out-File -FilePath $OutputFile -append
	fileVersion -filename "SurfacePenDriver.sys"	| Out-File -FilePath $OutputFile -append
	fileVersion -filename "WdfCoInstaller01011.dll"	| Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n" | Out-File -FilePath $OutputFile -append

	"[info] Surface Pro 3 Binaries: Keyboards"  | WriteTo-StdOut	
	#componentSection -component "Keyboards"
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Keyboards"												| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"Surface Type Cover Filter Device"	| Out-File -FilePath $OutputFile -append
	fileVersion -filename Kbdclass.sys	| Out-File -FilePath $OutputFile -append
	fileVersion -filename Kbdhid.sys	| Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n" | Out-File -FilePath $OutputFile -append

	"[info] Surface Pro 3 Binaries: Network Adapters"  | WriteTo-StdOut
	#componentSection -component "Network Adapters"
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Network Adapters"										| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"ASIX AX88772 USB2.0 to Fast Ethernet Adapter"	| Out-File -FilePath $OutputFile -append
	fileVersion -filename Ax88772.sys				| Out-File -FilePath $OutputFile -append
	fileVersion -filename WdfCoInstaller01011.dll	| Out-File -FilePath $OutputFile -append
	# File versions on SurfacePro3 as of 10.10.14: 
	# Ax88772.sys; 3.16.8.0
	# WdfCoInstaller01011.dll; 1.11.9200.16384
	"`n" | Out-File -FilePath $OutputFile -append
	"Bluetooth Device (Personal Area Network)"	| Out-File -FilePath $OutputFile -append
	fileVersion -filename Bthpan.sys			| Out-File -FilePath $OutputFile -append
	# File versions on SurfacePro3 as of 10.10.14: 
	# Bthpan.sys; 6.3.9600.16384
	"`n" | Out-File -FilePath $OutputFile -append
	"Bluetooth Device (RFCOMM Protocol TDI)"	| Out-File -FilePath $OutputFile -append
	fileVersion -filename bthenum.sys			| Out-File -FilePath $OutputFile -append
	fileVersion -filename rfcomm.sys			| Out-File -FilePath $OutputFile -append
	# File versions on SurfacePro3 as of 10.10.14: 
	# bthenum.sys; 6.3.9600.16384
	# rfcomm.sys; 6.3.9600.16520
	"`n" | Out-File -FilePath $OutputFile -append
	"Marvell AVASTAR Wireless-AC Network Controller"	| Out-File -FilePath $OutputFile -append
	fileVersion -filename Mrvlpcie8897.sys				| Out-File -FilePath $OutputFile -append
	fileVersion -filename Vwifibus.sys					| Out-File -FilePath $OutputFile -append
	fileVersion -filename WiFiCLass.sys					| Out-File -FilePath $OutputFile -append
	# File versions on SurfacePro3 as of 10.10.14: 
	# Mrvlpcie8897.sys; MP107
	# Vwifibus.sys; 6.3.9600.16384
	# WiFiCLass.sys; 6.3.9715
	"`n" | Out-File -FilePath $OutputFile -append
	"Microsoft Kernel Debug Network Adapter"	| Out-File -FilePath $OutputFile -append
	fileVersion -filename Kdnic.sys				| Out-File -FilePath $OutputFile -append
	# File versions on SurfacePro3 as of 10.10.14: 
	# Kdnic.sys; 6.01.00.0000
	"`n" | Out-File -FilePath $OutputFile -append
	"Microsoft Wi-Fi Direct Virtual Adapter"	| Out-File -FilePath $OutputFile -append
	fileVersion -filename Vwifimp.sys			| Out-File -FilePath $OutputFile -append
	# File versions on SurfacePro3 as of 10.10.14: 
	# Vwifimp.sys; 6.3.9600.17111
	"`n`n`n" | Out-File -FilePath $OutputFile -append

	"[info] Surface Pro 3 Binaries: System Devices"  | WriteTo-StdOut
	#componentSection -component "System Devices"
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"System Devices"										| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"Surface Accessory Device"	| Out-File -FilePath $OutputFile -append
	fileVersion -filename SurfaceAccessoryDevice.sys	| Out-File -FilePath $OutputFile -append
	#SurfaceAccessoryDevice.sys; 2.0.1012.0
	"`n" | Out-File -FilePath $OutputFile -append
	"Surface Cover Telemetry"	| Out-File -FilePath $OutputFile -append
	$filename = "SurfaceCoverTelemetry.dll"
	$wmiQuery = "select * from cim_datafile where name='c:\\windows\\system32\\drivers\\umdf\\" + $filename + "'"
	$fileObj = Get-CimInstance -query $wmiQuery
	$filenameLength = $filename.Length
	$columnLen = 35
	$columnDiff = $columnLen - $filenameLength
	$columnPrefix = 3
	$fileLine = " " * ($columnPrefix) + $filename + " " * ($columnDiff) + $fileObj.version
	$fileLine | Out-File -FilePath $OutputFile -append
	#SurfaceCoverTelemetry.dll (windir\system32\drivers\umdf); 2.0.722.0
	fileVersion -filename WUDFRd.sys	| Out-File -FilePath $OutputFile -append
	#WUDFRd.sys; 6.3.9600.17195
	"`n" | Out-File -FilePath $OutputFile -append
	"Surface Display Calibration"	| Out-File -FilePath $OutputFile -append
	fileVersion -filename SurfaceDisplayCalibration.sys	| Out-File -FilePath $OutputFile -append
	#SurfaceDisplayCalibration.sys; 2.0.1002.0
	"`n" | Out-File -FilePath $OutputFile -append
	"Surface Home Button"	| Out-File -FilePath $OutputFile -append
	fileVersion -filename SurfaceCapacitiveHomeButton.sys	| Out-File -FilePath $OutputFile -append
	#SurfaceCapacitiveHomeButton.sys; 2.0.358.0
	"`n" | Out-File -FilePath $OutputFile -append
	"Surface Integration"	| Out-File -FilePath $OutputFile -append
	fileVersion -filename SurfaceIntegrationDriver.sys	| Out-File -FilePath $OutputFile -append
	#SurfaceIntegrationDriver.sys; 2.0.1102.0
	"`n`n`n" | Out-File -FilePath $OutputFile -append

	CollectFiles -filesToCollect $outputFile -fileDescription "Surface Pro 3 Binaries Information" -SectionDescription $sectionDescription

	
	#----------Registry
	$OutputFile= $Computername + "_SurfacePro3_reg_output.TXT"
	$CurrentVersionKeys =   "HKLM\SYSTEM\CurrentControlSet\Enum\UEFI",
							"HKLM\SYSTEM\CurrentControlSet\Control\Power",
							"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
	RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -OutputFile $OutputFile -fileDescription "Surface Pro 3 Registry Output" -SectionDescription $sectionDescription
}


# SIG # Begin signature block
# MIInrQYJKoZIhvcNAQcCoIInnjCCJ5oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCF3BRkS2hRPhNW
# 0Ml/XrR7WP2TSzGY4GE/g97/EVmtRKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIAuoB19sm3kD6RMQjgKj8nYQ
# SiM3EHnhgvoLimXgmSC1MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAyUrf56stYysmt9ea1ECvBmXa7+JVmXGrROzkvH3mdvH1WPpNE6oWA
# cEg+g+xDaVy/AU8Hch+MWgiFwdVV8i+SIkeBr2ahZ3zgN5s9KVU6DTWbIF5s4vdX
# rfTr46ye2VGbqz5LO0S03ZA2SHzEN8kuCDLKeYaAeTyxUQyZQ4bEjFPDdmxSJ6IB
# 5Q7f0tVpk6jkIlYZ6agBFWGp7My2BHlsJu3AWiO5JRU6/wsLPRU0L6/90ia9GZAa
# iPbF4mqAc66yv9Mr5+AcNtoYKcTpmFgcsuygVnZfxujlipemidgjym/j/7Yx4jcF
# e9U9KKAp3JXmjNNs6GLC4rMtSOwsss2+oYIXFTCCFxEGCisGAQQBgjcDAwExghcB
# MIIW/QYJKoZIhvcNAQcCoIIW7jCCFuoCAQMxDzANBglghkgBZQMEAgEFADCCAVgG
# CyqGSIb3DQEJEAEEoIIBRwSCAUMwggE/AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIJoZ/eNdnKhaO/OdnNCVLgfCKKPzgRNt4O33U8CrNoxaAgZi3ohQ
# jVwYEjIwMjIwODAxMTMzMDEyLjIyWjAEgAIB9KCB2KSB1TCB0jELMAkGA1UEBhMC
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
# dGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOaSQPowIhgPMjAyMjA4MDEy
# MDA5MzBaGA8yMDIyMDgwMjIwMDkzMFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA
# 5pJA+gIBADAHAgEAAgIYwzAHAgEAAgIRNzAKAgUA5pOSegIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBBQUAA4GBABDWq1hrYtJ8Nb4ENRSg5+0Nm/3DoXuIMvAH6VDO7pdC
# UchyLUs1kwVJIECShdvJltUZ2SDW5MhYIa1tU193SrW3qzGj3RTwKODrLuk1T+WX
# eIDb9y8oIgY/Uotvvrbo4//x9D2arJP3qTx9PFrTv6QrGpNnlg4nBfembnpn6aXC
# MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGP81Go61py3cwAAQAAAY8wDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgcxyvEvCW6HjoihRILLoG
# d0d6mu6WXT9DQLKAfdXBeBkwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCX
# cgVP4sbGC5WOIqbbYi2Y7p0UNZbydKG7o7qDzIXHHzCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABj/NRqOtact3MAAEAAAGPMCIEIEz+
# g+tewV+v7U9yGRXEOYtphn35ZWjgZPjQ/aKEmltOMA0GCSqGSIb3DQEBCwUABIIC
# ABH+5JlhihkcYECqYwNkZYQyfYaragjknpYoJs3buLgdlGiLNUP4fVzUNzbG6WcS
# piUzL2H9tsq5nO+xVcvD7bw5BuhSuu6exDrHTmxDEdd2agCbJQS+MazQQJb8Y//J
# PH2xOqUplnb3Vk2zYjYrqmveIV9lAW52DU9TSeSOYSaybrKleAXQ94IazxxbsioD
# xza/djAptUtyyrPXaTuW1G8q2fkz+wDWGqfxXr1S0H/G9BxsT0KRT+iCh6BmobQh
# kMhUboDjIGXjb2PXM5lW9nltCv9V1onzbXa8fg/CxtdUYqzXGLYMV10SNHqc+hdK
# A966HO4KrSUbrKCGZuUd3unT2uXdTys+rCDl6tlyq0hOT1IS2x8WY5faKwMkD87k
# yHVpHtEC2rmuW/eS9cPgrUqW8T5ZvZY0WGhcNFdp56yqjGwCcMy7F+677yRNY6aA
# 0KgZbkdWrR8EgoPDH+hXCGFS2JliOqzwqYpZJh+zVNkB5o2v5LdxKdLUihrc08CS
# cnIf7xp08VQ0erlmVX32iL+nnOPoIFLdfohakem2OotsqToWYq/ku4vStS1zjYsz
# fbrkRZ1R2Tw7ITh+S6w4Cv6Bc/bxcfPlP7WYXsuqlcwg9k3XjPQlJJhG96HzW0qJ
# rpkt567x01fl4Vk55u9p+WN/ZdTIqFcygFmhdMz2lJhF
# SIG # End signature block
