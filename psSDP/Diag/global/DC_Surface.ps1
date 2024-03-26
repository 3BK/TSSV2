#************************************************
# DC_Surface.ps1
# Description: Collects information about Surface Devices.
# Called from: Main Setup Diagnostic
#*******************************************************

Import-LocalizedData -BindingVariable ScriptVariable
Write-DiagProgress -Activity $ScriptVariable.ID_Surface -Status $ScriptVariable.ID_SurfaceDesc

Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}

$sectionDescription = "Surface "

# detect OS version and SKU
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber
$sku = $((Get-CimInstance win32_operatingsystem).OperatingSystemSKU)
$domainRole = (Get-CimInstance -Class Win32_ComputerSystem).DomainRole	# 0 or 1: client; >1: server
$Separator1 = "----------------------------------------------------"
function isOSVersionAffected
{
	if ([int]$bn -gt [int](9600))
	{
		return $true
	}
	else
	{
		return $false
	}
}

$surfaceSKU = $null
function isSurface
{
	$regkeyBIOS = "HKLM:\HARDWARE\DESCRIPTION\System\BIOS"
	if (Test-Path $regkeyBIOS)
	{
		$regvalueSystemSKUReg = Get-ItemProperty -Path $regkeyBIOS -Name "SystemSKU" -ErrorAction SilentlyContinue
		$surfaceSKU = $regvalueSystemSKU = $regvalueSystemSKUReg.SystemSKU
		if ($regvalueSystemSKU -like "*Surface*")
		{
			return $true
		}
		else
		{
			return $false
		}
	}
}

function GetOsVerName($bn)
{
	switch ($bn)
	{
		20348 {return "WS2022"}
		22000 {return "Win11"}
		19044 {return "W10v21H2"}
		19043 {return "W10v21H1"}
		19042 {return "W10v20H2"}
		17763 {return "W10v1809/WS2019"}
		14393 {return "W10v1607/WS2016"}
		10586 {return "W10v1511"}
		10240 {return "W10rtm"}		
		9600  {return "W8.1/WS2012R2"}
		default {return "unknown-OS"}
	}
}

function GetOsSkuName($sku)
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

if ((isOSVersionAffected) -and (isSurface))
{
	#collect output of:
	# dxdiag /t computername_dxdiag.txt
	# dispdiag -out computername_dispdiag.dat
	# netsh wlan show all>computername_netsh_wlan_show_all.txt
	#"logman.exe create counter -n $CounterLogName -cf `"$PerfmonConfigPath`" -f bincirc -max 512 -si 3 -rf 00:01:00 -v mmddhhmm -o `"$OutputFileName`""
	
	$dxdiagOutputFileName = Join-Path $pwd.path ($ComputerName + "_dxdiag.txt")
	$CommandToRun = "dxdiag /t $dxdiagoutputFileName"
	RunCMD -commandToRun $CommandToRun -collectFiles $true
	#dxdiag takes some number of seconds to write output after completion.
	$i = 0
	while (-not (Test-Path $dxdiagOutputFileName))
	{
		$i++
		if ($i -ge 30)
		{
			"[error]:  waited for 30 seconds for dxdiag output, giving up." | writeto-stdout
			break
		}
		Start-Sleep 1
	}

	collectfiles -filesToCollect $dxdiagOutputFileName -fileDescription "dxdiag output" -sectionDescription $sectionDescription

	$dispdiagOutputFileName = Join-Path $pwd.path ($ComputerName + "_dispdiag.dat")
	$CommandToRun = "dispdiag -out $dispdiagOutputFileName"
	RunCMD -commandToRun $CommandToRun -collectFiles $true
	collectfiles -filesToCollect $dispdiagOutputFileName -fileDescription "dispdiag output" -sectionDescription $sectionDescription

	$NetshWlanOutputFileName = Join-Path $pwd.path ($ComputerName + "_netsh_wlan_show_all.txt")
	$CommandToRun = "netsh wlan show all > $NetshWlanOutputFileName"
	RunCMD -commandToRun $CommandToRun -collectFiles $true
	collectfiles -filesToCollect $NetshWlanOutputFileName -fileDescription "netsh wlan show all output" -sectionDescription $sectionDescription

	$outputFile= $Computername + '_Surface_Info.TXT'
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"Surface Configuration Information"					    | Out-File -FilePath $OutputFile -Append
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"Overview" 												| Out-File -FilePath $OutputFile -Append
	$Separator1	| Out-File -FilePath $OutputFile -Append
	"   1. Operating System and SKU"						| Out-File -FilePath $OutputFile -Append
	"   2. Wifi Driver Version"								| Out-File -FilePath $OutputFile -Append
	"   3. Wifi Driver Power Management Settings"		 	| Out-File -FilePath $OutputFile -Append
	"   4. Firmware Resources"								| Out-File -FilePath $OutputFile -Append
	#"   Connected Standby Status"						    | Out-File -FilePath $OutputFile -Append
	#"   Connected Standby Hibernation Configuration"	    | Out-File -FilePath $OutputFile -Append # Removed completely. Everything needed is included in other logs.
	"   5. Surface WUDF Services (Dock and others)"		    | Out-File -FilePath $OutputFile -Append
	"   6. Secure Boot Configuration"						| Out-File -FilePath $OutputFile -Append
	"   7. WMI Class Information"							| Out-File -FilePath $OutputFile -Append
	"   8. Display Driver Information"						| Out-File -FilePath $OutputFile -Append
	"   9. IDE Information"								    | Out-File -FilePath $OutputFile -Append
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"`n`n`n`n`n`n"	| Out-File -FilePath $OutputFile -Append

	"[info] Operating System and SKU section" 	| WriteTo-StdOut
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"Operating System and SKU"  							| Out-File -FilePath $OutputFile -Append
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"`n" | Out-File -FilePath $OutputFile -Append
	$osVerName = GetOsVerName $bn
	"Operating System Name        : $osVerName" 			| Out-File -FilePath $OutputFile -Append
	"Operating System Build Number: $bn" 					| Out-File -FilePath $OutputFile -Append
	$osSkuName = GetOsSkuName $sku
	"Operating System SKU Name    : $osSkuName"				| Out-File -FilePath $OutputFile -Append
	$assetTag = (Get-CimInstance -query "Select * from Win32_SystemEnclosure").SMBiosAssetTag
	"Asset Tag                    : $assetTag"				| Out-File -FilePath $OutputFile -Append
	"`n`n`n" | Out-File -FilePath $OutputFile -Append

	$WinCVRegKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion"
	If (test-path $WinCVRegKey)
	{
		$ImageNameReg   = Get-ItemProperty -Path $WinCVRegKey -Name ImageName -ErrorAction SilentlyContinue
		$ImageName = $ImageNameReg.ImageName
	}
	
	$WinNTCVRegKey = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion"
	If (test-path $WinNTCVRegKey)
	{
		$BuildLabReg    = Get-ItemProperty -Path $WinNTCVRegKey -Name BuildLab -ErrorAction SilentlyContinue
		$BuildLab = $BuildLabReg.BuildLab

		$BuildLabExReg  = Get-ItemProperty -Path $WinNTCVRegKey -Name BuildLabEx -ErrorAction SilentlyContinue 
		$BuildLabEx = $BuildLabExReg.BuildLabEx

		$ProductNameReg = Get-ItemProperty -Path $WinNTCVRegKey -Name ProductName -ErrorAction SilentlyContinue 
		$ProductName = $ProductNameReg.ProductName

		$CurrentBuildReg = Get-ItemProperty -Path $WinNTCVRegKey -Name CurrentBuild -ErrorAction SilentlyContinue 
		$CurrentBuild = $CurrentBuildReg.CurrentBuild

		"Image Name    : $ImageName" | Out-File -FilePath $OutputFile -Append		
		"BuildLab      : $BuildLab" | Out-File -FilePath $OutputFile -Append
		"BuildLabEx    : $BuildLabEx" | Out-File -FilePath $OutputFile -Append
		"ProductName   : $ProductName" | Out-File -FilePath $OutputFile -Append
		"CurrentBuild  : $CurrentBuild" | Out-File -FilePath $OutputFile -Append
	}
	"`n`n`n`n`n" | Out-File -FilePath $OutputFile -Append

	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"Wifi Driver Version" 									| Out-File -FilePath $OutputFile -Append
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"`n" 													| Out-File -FilePath $OutputFile -Append	
	"[info] Wifi Driver Version section"  | WriteTo-StdOut

	#****************************************************
	#  Firmware      : Filename            : MPVer / Ver           : Date       : Package version online
	#  --------        --------              -----------             ----         ----------------------
	#  Marvel WiFi   : "mrvlpcie8897.sys"  : "MP135", "          " : "        " : 15.68.3059.135
	#  Marvel WiFi   : "mrvlpcie8897.sys"  : "MP117", "6.3.9410.0" : "10/28/14" : 15.68.3059.117
	#  Marvel WiFi   : "mrvlpcie8897.sys"  : "MP107", "6.3.9410.0" : "8/22/14"  : 15.68.3055.107
	#  Marvel WiFi   : "mrvlpcie8897.sys"  : "MP67",  "6.3.9410.0" : "4/24/14"  : unknown
	#
	#****************************************************	
	$CurrentMarvelDate = "Nov2014"
    $marvelDriverMPVersionLatest = 135
	$marvelDriver = join-path $env:windir "\system32\drivers\mrvlpcie8897.sys"
	if (test-path $marvelDriver)
	{
		$marvelDriverInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($marvelDriver)
		#$marvelDriverFileBuildPart = $marvelDriverInfo.FileBuildPart
		$marvelDriverProductVersion = $marvelDriverInfo.ProductVersion
		[string]$marvelDriverVersion = [string]$marvelDriverInfo.FileMajorPart + "." + [string]$marvelDriverInfo.FileMinorPart + "." + [string]$marvelDriverInfo.FileBuildPart + "." + [string]$marvelDriverInfo.FilePrivatePart
		"FileName      : $marvelDriver"					| Out-File -FilePath $OutputFile -Append
		"FileVersion   : $marvelDriverVersion"			| Out-File -FilePath $OutputFile -Append
		"ProductVersion: $marvelDriverProductVersion"	| Out-File -FilePath $OutputFile -Append
		"`n" 											| Out-File -FilePath $OutputFile -Append
		
		$marvelDriverProductVersionStartsWithMP = ($marvelDriverProductVersion).StartsWith("MP")
#		if ($marvelDriverProductVersionStartsWithMP -eq $true) 
#		{
#			[int]$marvelDriverProductVersionInt = $marvelDriverProductVersion.Substring(2,$marvelDriverProductVersion.length-2)
#			if ($marvelDriverProductVersionInt -gt $marvelDriverMPVersionLatest)
#			{
#				"The driver installed is more recent than the $CurrentMarvelDate update." | Out-File -FilePath $OutputFile -Append
#			}
#			elseif ($marvelDriverProductVersionInt -eq $marvelDriverMPVersionLatest)
#			{
#				"The driver installed is the same version as the $CurrentMarvelDate update." | Out-File -FilePath $OutputFile -Append	
#			}
#			elseif ($marvelDriverProductVersionInt -lt $marvelDriverMPVersionLatest)
#			{
#				"The driver installed is older than the $CurrentMarvelDate update." | Out-File -FilePath $OutputFile -Append
#			}
#		}
#		else
#		{
#				"The driver installed is older than the $CurrentMarvelDate update." | Out-File -FilePath $OutputFile -Append
#		}
		"`n`n" | Out-File -FilePath $OutputFile -Append
	}
	else
	{
		"The driver `"\system32\drivers\mrvlpcie8897.sys`" does not exist on this system." | Out-File -FilePath $OutputFile -Append
	}

	$Separator1| Out-File -FilePath $OutputFile -Append			
	"Please refer to the following content to verify the latest firmware and WiFi driver versions:" | Out-File -FilePath $OutputFile -Append
	$Separator1| Out-File -FilePath $OutputFile -Append			
	"Public Content:"	| Out-File -FilePath $OutputFile -Append

	$surfaceSKU = $null
	$regkeyBIOS = "HKLM:\HARDWARE\DESCRIPTION\System\BIOS"
	if (Test-Path $regkeyBIOS)
	{
		$regvalueSystemSKUReg = Get-ItemProperty -Path $regkeyBIOS -Name "SystemSKU" -ErrorAction SilentlyContinue
		$surfaceSKU = $regvalueSystemSKUReg.SystemSKU
	}

	switch ($surfaceSKU)
	{
		'Surface_Book' 
		{
			"`n" | Out-File -FilePath $OutputFile -Append
			'"Surface Book Update History:"' | Out-File -FilePath $OutputFile -Append
			'https://www.microsoft.com/surface/en-us/support/install-update-activate/surface-book-update-history' | Out-File -FilePath $OutputFile -Append
		
			"`n" | Out-File -FilePath $OutputFile -Append
			'"Download Drivers and Firmware Update:"' | Out-File -FilePath $OutputFile -Append
			'https://www.microsoft.com/en-us/download/confirmation.aspx?id=49497' | Out-File -FilePath $OutputFile -Append
		}

		'Surface_Pro_4' 
		{
			"`n" | Out-File -FilePath $OutputFile -Append
			'"Surface Pro 4 Update History:"' | Out-File -FilePath $OutputFile -Append
			'https://www.microsoft.com/surface/en-us/support/install-update-activate/surface-pro-4-update-history' | Out-File -FilePath $OutputFile -Append
		
			"`n" | Out-File -FilePath $OutputFile -Append
			'"Download Drivers and Firmware Update:"' | Out-File -FilePath $OutputFile -Append
			'https://www.microsoft.com/en-us/download/confirmation.aspx?id=49498' | Out-File -FilePath $OutputFile -Append
		}

		'Surface_Pro_3' 
		{
			"`n" | Out-File -FilePath $OutputFile -Append
			'"Surface Pro 3 Update History:"' | Out-File -FilePath $OutputFile -Append
			'https://www.microsoft.com/surface/en-us/support/install-update-activate/pro-3-update-history' | Out-File -FilePath $OutputFile -Append
		
			"`n" | Out-File -FilePath $OutputFile -Append
			'"Download Drivers and Firmware Update:"' | Out-File -FilePath $OutputFile -Append
			'https://www.microsoft.com/en-us/download/confirmation.aspx?id=38826' | Out-File -FilePath $OutputFile -Append
		}

		'Surface_3' 
		{
			"`n" | Out-File -FilePath $OutputFile -Append
			'"Surface 3 Update History:"' | Out-File -FilePath $OutputFile -Append
			'https://www.microsoft.com/surface/en-us/support/install-update-activate/surface-3-update-history' | Out-File -FilePath $OutputFile -Append
		
			"`n" | Out-File -FilePath $OutputFile -Append
			'"Download Drivers and Firmware Update:"' | Out-File -FilePath $OutputFile -Append
			'https://www.microsoft.com/en-us/download/details.aspx?id=49040' | Out-File -FilePath $OutputFile -Append
		}

		'Surface_Pro_2' 
		{
			"`n" | Out-File -FilePath $OutputFile -Append
			'"Surface Pro 2 Update History:"' | Out-File -FilePath $OutputFile -Append
			'https://www.microsoft.com/surface/en-us/support/install-update-activate/pro-2-update-history' | Out-File -FilePath $OutputFile -Append
		
			"`n" | Out-File -FilePath $OutputFile -Append
			'"Download Drivers and Firmware Update:"' | Out-File -FilePath $OutputFile -Append
			'https://www.microsoft.com/en-us/download/confirmation.aspx?id=49042' | Out-File -FilePath $OutputFile -Append
		}

		'Surface_2' 
		{
			"`n" | Out-File -FilePath $OutputFile -Append
			'"Surface 2 Update History:"' | Out-File -FilePath $OutputFile -Append
			'https://www.microsoft.com/surface/en-us/support/install-update-activate/2-update-history' | Out-File -FilePath $OutputFile -Append
		}

		'Surface_Pro_1' 
		{
			"`n" | Out-File -FilePath $OutputFile -Append
			'"Surface Pro Update History:"' | Out-File -FilePath $OutputFile -Append
			'https://www.microsoft.com/surface/en-us/support/install-update-activate/pro-update-history' | Out-File -FilePath $OutputFile -Append
		
			"`n" | Out-File -FilePath $OutputFile -Append
			'"Download Drivers and Firmware Update:"' | Out-File -FilePath $OutputFile -Append
			'https://www.microsoft.com/en-us/download/confirmation.aspx?id=49038' | Out-File -FilePath $OutputFile -Append
		}

		default 
		{
			"`n" | Out-File -FilePath $OutputFile -Append
			'"Surface Update History:"' | Out-File -FilePath $OutputFile -Append
			'https://www.microsoft.com/surface/en-us/support/install-update-activate/surface-update-history' | Out-File -FilePath $OutputFile -Append

			"`n" | Out-File -FilePath $OutputFile -Append
			'"Download Drivers and Firmware Update:"' | Out-File -FilePath $OutputFile -Append
			'https://www.microsoft.com/surface/en-us/support/performance-and-maintenance/install-software-updates-for-surface' | Out-File -FilePath $OutputFile -Append
		}
	}

	"`n`n`n`n`n" | Out-File -FilePath $OutputFile -Append

	$bandctrlvalue = Get-NetAdapterAdvancedProperty -AllProperties | ForEach-Object{if ($_.RegistryKeyword -eq "Bandctrl") {$_.RegistryValue}}
	if ($null -eq $bandctrlvalue)
	{
		$bandctrlstring = "BandCtrl setting is not available. This can indicate a driver version previous to January 2015 (v .151)."
	}
	else
	{
		switch ($bandctrlvalue)
		{
			1 {$bandctrlstring = "BandCtrl is set to 1(2.4ghz only)"}
			2 {$bandctrlstring = "BandCtrl is set to 2(5ghz only)"}
			3 {$bandctrlstring = "BandCtrl is set to 3(auto)"}
		}
	}

	"================================="  | Out-File -FilePath $OutputFile -Append
	"WiFI Advanced settings"             | Out-File -FilePath $OutputFile -Append
	"================================="  | Out-File -FilePath $OutputFile -Append
	$bandctrlstring                      | Out-File -FilePath $OutputFile -Append

	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"Wifi Driver Power Management Settings" 				| Out-File -FilePath $OutputFile -Append
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"`n" 													| Out-File -FilePath $OutputFile -Append	
	"[info] Wifi Driver Version section" | WriteTo-StdOut

	$deviceFound = $false
	$regkeyNicSettingsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
	if (test-path $regkeyNicSettingsPath) 
	{
		$regkeyNicSettings = Get-ItemProperty -Path $regkeyNicSettingsPath -ErrorAction SilentlyContinue 
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
						# Power Management Settings
						#  ENABLED  and ENABLED:  PnPCapabilities = 0x0  (0)
						#  ENABLED  and DISABLED:  PnPCapabilities = 0x10 (16)
						#  DISABLED and DISABLED:  PnPCapabilities = 0x18 (24)
						$networkAdapterPnPCapabilities = (Get-ItemProperty -Path $childNicSettingsPath).PnPCapabilities

						"`n" | Out-File -FilePath $OutputFile -Append
						$regkeyPower = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"
						If (test-path $regkeyPower)
						{
							$regvaluePowerCsEnabled = Get-ItemProperty -path $regkeyPower -name "CsEnabled" -ErrorAction SilentlyContinue
							if ($null -ne $regvaluePowerCsEnabled)
							{
								$regvaluePowerCsEnabled = $regvaluePowerCsEnabled.CsEnabled
								if ($regvaluePowerCsEnabled -eq 1)	#Connected Standby is ENABLED
								{
									if ($null -ne $networkAdapterPnPCapabilities)
									{
										#$RootCauseDetected = $true
										"PnPCapabilities registry value: $networkAdapterPnPCapabilities" | Out-File -FilePath $OutputFile -Append
									}
									else
									{
										"PnPCapabilities registry value: Does not exist." | Out-File -FilePath $OutputFile -Append
									}
									"Connected Standby             : ENABLED" | Out-File -FilePath $OutputFile -Append
									"`"Power Management`" tab        : NOT VISIBLE" | Out-File -FilePath $OutputFile -Append
									"`n" | Out-File -FilePath $OutputFile -Append
								}
								elseif ($regvaluePowerCsEnabled -ne 1)	#Connected Standby is DISABLED
								{
									if ($null -eq $networkAdapterPnPCapabilities)	# PnPCapabilities does NOT exist.
									{
										"PnPCapabilities registry value: Does not exist." | Out-File -FilePath $OutputFile -Append
										"`n" | Out-File -FilePath $OutputFile -Append
									}
									else	# PnPCapabilities does exist.
									{
										#$RootCauseDetected = $true
										"PnPCapabilities registry value: $networkAdapterPnPCapabilities" | Out-File -FilePath $OutputFile -Append
										"`n" | Out-File -FilePath $OutputFile -Append
									}
									"Connected Standby             : DISABLED (not default)" | Out-File -FilePath $OutputFile -Append
									"`"Power Management`" tab        : VISIBLE  (not default)" | Out-File -FilePath $OutputFile -Append
									"Note: The `"Power Management`" tab for the Marvel Wifi Driver is visible because Connected Standby is currently DISABLED. This is not the default configuration. The default settings have been altered from default."	| Out-File -FilePath $OutputFile -Append
									"`n`n" | Out-File -FilePath $OutputFile -Append
		
									"User Interface Settings for the Marvel Wifi Driver `"Power Management`" tab" | Out-File -FilePath $OutputFile -Append
									"`n" | Out-File -FilePath $OutputFile -Append
									if ($null -eq $networkAdapterPnPCapabilities)
									{
										"Setting Name   : `"Allow the computer to turn off this device to save power`"" | Out-File -FilePath $OutputFile -Append
										"Setting Status : ENABLED" | Out-File -FilePath $OutputFile -Append
										"`n" | Out-File -FilePath $OutputFile -Append	
										"Setting Name   : `"Allow this device to wake the computer`"" | Out-File -FilePath $OutputFile -Append
										"Setting Status : ENABLED" | Out-File -FilePath $OutputFile -Append
										"`n" | Out-File -FilePath $OutputFile -Append
									}
									elseif ($networkAdapterPnPCapabilities -eq 0)
									{
										"Setting Name   : `"Allow the computer to turn off this device to save power`"" | Out-File -FilePath $OutputFile -Append
										"Setting Status : ENABLED" | Out-File -FilePath $OutputFile -Append
										"`n" | Out-File -FilePath $OutputFile -Append	
										"Setting Name   : `"Allow this device to wake the computer`"" | Out-File -FilePath $OutputFile -Append
										"Setting Status : ENABLED" | Out-File -FilePath $OutputFile -Append
									}
									elseif ($networkAdapterPnPCapabilities -eq 16)
									{
										"Setting Name   : `"Allow the computer to turn off this device to save power`"" | Out-File -FilePath $OutputFile -Append
										"Setting Status : ENABLED" | Out-File -FilePath $OutputFile -Append
										"`n" | Out-File -FilePath $OutputFile -Append	
										"Setting Name   : `"Allow this device to wake the computer`"" | Out-File -FilePath $OutputFile -Append
										"Setting Status : DISABLED" | Out-File -FilePath $OutputFile -Append
										"`n" | Out-File -FilePath $OutputFile -Append
									}
									elseif ($networkAdapterPnPCapabilities -eq 24)
									{
										"Setting Name   : `"Allow the computer to turn off this device to save power`"" | Out-File -FilePath $OutputFile -Append
										"Setting Status : DISABLED" | Out-File -FilePath $OutputFile -Append
										"`n" | Out-File -FilePath $OutputFile -Append	
										"Setting Name   : `"Allow this device to wake the computer`"" | Out-File -FilePath $OutputFile -Append
										"Setting Status : DISABLED" | Out-File -FilePath $OutputFile -Append
									}
									else
									{
										"The PnPCapabilities registry value exists but does not match settings available in the user interface configuration." | Out-File -FilePath $OutputFile -Append
										"This is NOT the default configuration." | Out-File -FilePath $OutputFile -Append
									}
								}
							}
						}
						else
						{
							"The Power registry value does not exist: $regkeyPower" | Out-File -FilePath $OutputFile -Append
						}
					}
				}
			}
		}
	}
	"`n`n`n`n`n" | Out-File -FilePath $OutputFile -Append	

	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"Firmware Resources" 									| Out-File -FilePath $OutputFile -Append
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"[info] Firmware Resources section"  | WriteTo-StdOut 

	###
	#  Jasonf - 3-11-15 - based on feedback, some detection is incomplete, make changes to output complete firmware resources registry.
	###

	$regKeyFirmwareResources = 'HKLM:\SYSTEM\CurrentControlSet\Control\FirmwareResources'
	if(Test-Path ($regKeyFirmwareResources))
	{
		Get-ChildItem $regKeyFirmwareResources -Recurse | Out-File -FilePath $OutputFile -Append
	}

	#region "Old Code"
#	#****************************************************
#	#  Firmware         : Filename                        : Version       : Version Hex/Dec        : Date
#	#  --------         : -----------------------           -------         ---------------          ----
#	# Oct2014
#	#  ECFirmware       : "ECFirmware.38.6.50.0.cap"      : "38.6.50.0"   : 0x00380650 = 3671632  : "08/27/2014"
#	#  SAMfirmware      : "SamFirmware.3.9.350.0.cap      : "3.9.350.0"   : 0x03090350 = 50922320 : "08/08/2014"
#	#  TouchFirmware    : "TouchFirmware.426.27.66.0.cap" : "426.27.66.0" : 0x01aa1b42 = 27925314 : "05/15/2014"
#	#  UEFI             : "UEFI.3.10.250.0.cap"           : "3.10.250.0"  : 0x030a00fa = 50987258 : "08/28/2014"
#	#
#	# Nov2014
#	#  ECFirmware       : "ECFirmware.38.7.50.0.cap"      : "38.7.50.0"   :  0x00380750 = 3671888  : "09/18/2014"	#NEW VERSION
#	#  SAMfirmware      : "SamFirmware.3.11.350.0.cap"    : "3.9.350.0"   :  0x03090350 = 50922320 : "08/08/2014"
#	#  TouchFirmware    : "TouchFirmware.426.27.66.0.cap" : "426.27.66.0" :  0x01aa1b42 = 27925314 : "05/15/2014"
#	#  UEFI             : "UEFI.3.11.350.0.cap"           : "3.11.350.0"  :  0x030b00fa = 50987258 : "10/16/2014"	#NEW VERSION
#	#
#	#****************************************************
#	$CurrentFirmwareDate = "Nov2014"
#	$regvalueECFirmwareFileNameLatest    = "ECFirmware.38.7.50.0.cap"
#	$regvalueECFirmwareVersionLatest     = 3671888
#	$regvalueSamFirmwareFileNameLatest   = "SamFirmware.3.9.350.0.cap"
#	$regvalueSamFirmwareVersionLatest    = 50922320
#	$regvalueTouchFirmwareFileNameLatest = "TouchFirmware.426.27.66.0.cap"
#	$regvalueTouchFirmwareVersionLatest  = 27925314 
#	$regvalueUEFIFileNameLatest          = "UEFI.3.10.250.0.cap"
#	$regvalueUEFIVersionLatest           = 50987258
#
#
#
#	# -----------------
#	# Detection Details
#	# -----------------
#	# The current firmware detection method uses this location:
#	# Check for "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FirmwareResources\{512B1F42-CCD2-403B-8118-2F54353A1226}"  Filename = "SamFirmware.3.9.350.0.cap"
#	# Check for "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FirmwareResources\{52D9DA80-3D55-47E4-A9ED-D538A9B88146}"  Filename = "ECFirmware.38.6.50.0.cap"
#	# Check for "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FirmwareResources\{5A2D987B-CB39-42FE-A4CF-D5D0ABAE3A08}"  Filename = "UEFI.3.10.250.0.cap"
#	# Check for "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FirmwareResources\{E5FFF56F-D160-4365-9E21-22B06F6746DD}"  Filename = "TouchFirmware.426.27.66.0.cap"
#	$regkeyECFirmware    = "HKLM:\SYSTEM\CurrentControlSet\Control\FirmwareResources\{52D9DA80-3D55-47E4-A9ED-D538A9B88146}"
#	$regkeySamFirmware   = "HKLM:\SYSTEM\CurrentControlSet\Control\FirmwareResources\{512B1F42-CCD2-403B-8118-2F54353A1226}"
#	$regkeyTouchFirmware = "HKLM:\SYSTEM\CurrentControlSet\Control\FirmwareResources\{E5FFF56F-D160-4365-9E21-22B06F6746DD}"
#	$regkeyUEFI          = "HKLM:\SYSTEM\CurrentControlSet\Control\FirmwareResources\{5A2D987B-CB39-42FE-A4CF-D5D0ABAE3A08}"
#	# The original firmware detection method used this location, but guidance recommended using the FirmwareResources registry value:
#	#  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\UEFI\RES_{GUID}\0\Device Parameters
#
#
#	# ECFirmware
#	If (test-path $regkeyECFirmware)
#	{
#		$regvalueECFirmwareFileName = Get-ItemProperty -path $regkeyECFirmware -name "FileName" -ErrorAction SilentlyContinue
#		if ($regvalueECFirmwareFileName -ne $null)
#		{
#			$regvalueECFirmwareFileName = $regvalueECFirmwareFileName.FileName
#		}
#		$regvalueECFirmwareVersion = Get-ItemProperty -path $regkeyECFirmware -name "Version" -ErrorAction SilentlyContinue
#		if ($regvalueECFirmwareVersion -ne $null)
#		{
#			$regvalueECFirmwareVersion = $regvalueECFirmwareVersion.Version
#			"Surface Embedded Controller Firmware"							| Out-File -FilePath $OutputFile -Append
#			"  ECFirmware Installed Version   : $regvalueECFirmwareFileName"		| Out-File -FilePath $OutputFile -Append
#			"  ECFirmware Recommended Version : $regvalueECFirmwareFileNameLatest"	| Out-File -FilePath $OutputFile -Append
#			if ($regvalueECFirmwareVersion -lt $regvalueECFirmwareVersionLatest)
#			{
#				"  The installed firmware version is older than the firmware update from $CurrentFirmwareDate."	| Out-File -FilePath $OutputFile -Append
#			}
#			elseif ($regvalueECFirmwareVersion -eq $regvalueECFirmwareVersionLatest)
#			{
#				"  The installed firmware version matches the firmware update from $CurrentFirmwareDate."	| Out-File -FilePath $OutputFile -Append
#			}
#			elseif ($regvalueECFirmwareVersion -gt $regvalueECFirmwareVersionLatest)	
#			{
#				"  The installed firmware version is newer than the firmware update from $CurrentFirmwareDate."	| Out-File -FilePath $OutputFile -Append
#			}
#		}
#	}
#	else
#	{
#		"Surface Embedded Controller Firmware"		| Out-File -FilePath $OutputFile -Append
#		"  Embedded Firmware Installed Version   : The following registry key does not exist: $regkeyECFirmware"			| Out-File -FilePath $OutputFile -Append
#	}
#	"`n" | Out-File -FilePath $OutputFile -Append
#	"`n" | Out-File -FilePath $OutputFile -Append
#
#
#	# SamFirmware
#	If (test-path $regkeySamFirmware)
#	{
#		$regvalueSamFirmwareFilename = Get-ItemProperty -path $regkeySamFirmware -name "Filename" -ErrorAction SilentlyContinue
#		if ($regvalueSamFirmwareFilename -ne $null)
#		{
#			$regvalueSamFirmwareFilename = $regvalueSamFirmwareFilename.Filename
#		}
#		$regvalueSamFirmwareVersion = Get-ItemProperty -path $regkeySamFirmware -name "Version" -ErrorAction SilentlyContinue
#		if ($regvalueSamFirmwareVersion -ne $null)
#		{
#			$regvalueSamFirmwareVersion = $regvalueSamFirmwareVersion.Version
#			"Surface System Aggregator Firmware"									| Out-File -FilePath $OutputFile -Append
#			"  SamFirmware Installed Version   : $regvalueSamFirmwareFileName"			| Out-File -FilePath $OutputFile -Append
#			"  SamFirmware Recommended Version : $regvalueSamFirmwareFileNameLatest"	| Out-File -FilePath $OutputFile -Append
#			if ($regvalueSamFirmwareVersion -lt $regvalueSamFirmwareVersionLatest)
#			{
#				"  The installed file version is older than the firmware update from $CurrentFirmwareDate."	| Out-File -FilePath $OutputFile -Append
#			}
#			elseif ($regvalueSamFirmwareVersion -eq $regvalueSamFirmwareVersionLatest)
#			{
#				"  The installed file version matches the firmware update from $CurrentFirmwareDate."	| Out-File -FilePath $OutputFile -Append
#			}
#			elseif ($regvalueSamFirmwareVersion -gt $regvalueSamFirmwareVersionLatest)
#			{
#				"  The installed file version is newer than the firmware update from $CurrentFirmwareDate."	| Out-File -FilePath $OutputFile -Append
#			}
#		}
#	}
#	else
#	{
#		"Surface System Aggregator Firmware"	| Out-File -FilePath $OutputFile -Append
#		"  System Aggregator Firmware : The following registry key does not exist: $regkeySamFirmware"			| Out-File -FilePath $OutputFile -Append
#	}
#	"`n" | Out-File -FilePath $OutputFile -Append
#	"`n" | Out-File -FilePath $OutputFile -Append
#
#
#	# TouchFirmware
#	# This section did not produce output 114101011890961
#	If ($regkeyTouchFirmware -ne $null)
#	{
#		$regvalueTouchFirmwareFileName = Get-ItemProperty -path $regkeyTouchFirmware -name "FileName" -ErrorAction SilentlyContinue
#		if ($regvalueTouchFirmwareFileName -ne $null)
#		{
#			$regvalueTouchFirmwareFileName = $regvalueTouchFirmwareFileName.FileName
#		}
#		$regvalueTouchFirmwareVersion = Get-ItemProperty -path $regkeyTouchFirmware -name "Version" -ErrorAction SilentlyContinue
#		if ($regvalueTouchFirmwareVersion -ne $null)
#		{
#			$regvalueTouchFirmwareVersion = $regvalueTouchFirmwareVersion.Version
#			"Surface Touch Controller Firmware"										| Out-File -FilePath $OutputFile -Append
#			"  TouchFirmware Installed Version   : $regvalueTouchFirmwareFileName"			| Out-File -FilePath $OutputFile -Append
#			"  TouchFirmware Recommended Version : $regvalueTouchFirmwareFileNameLatest"	| Out-File -FilePath $OutputFile -Append
#			if ($regvalueTouchFirmwareVersion -lt $regvalueTouchFirmwareVersionLatest)
#			{
#				"  The installed firmware version is older than the firmware update from $CurrentFirmwareDate."	| Out-File -FilePath $OutputFile -Append
#			}
#			elseif ($regvalueTouchFirmwareVersion -eq $regvalueTouchFirmwareVersionLatest)
#			{
#				"  The installed firmware version matches the firmware update from $CurrentFirmwareDate."	| Out-File -FilePath $OutputFile -Append
#			}
#			elseif ($regvalueTouchFirmwareVersion -gt $regvalueTouchFirmwareVersionLatest)
#			{
#				"  The installed firmware version is newer than the firmware update from $CurrentFirmwareDate."	| Out-File -FilePath $OutputFile -Append
#			}
#		}
#	}
#	else
#	{
#		"Surface Touch Controller Firmware"										| Out-File -FilePath $OutputFile -Append
#		"  TouchFirmware Installed Version   : The following registry key does not exist: $regkeyTouchFirmware"			| Out-File -FilePath $OutputFile -Append
#	}
#	"`n" | Out-File -FilePath $OutputFile -Append
#	"`n" | Out-File -FilePath $OutputFile -Append
#
#
#	# UEFIFirmware
#	If (test-path $regkeyUEFI)
#	{
#		$regvalueUEFIFileName = Get-ItemProperty -path $regkeyUEFI -name "FileName" -ErrorAction SilentlyContinue
#		if ($regvalueUEFIFileName -ne $null)
#		{
#			$regvalueUEFIFileName = $regvalueUEFIFileName.FileName
#			$regvalueUEFIFileNameLatest = "UEFI.3.10.250.0.cap"
#		}
#		
#		$regvalueUEFIVersion = Get-ItemProperty -path $regkeyUEFI -name "Version" -ErrorAction SilentlyContinue
#		if ($regvalueUEFIVersion -ne $null)
#		{
#			$regvalueUEFIVersion  = $regvalueUEFIVersion.Version
#			"Surface UEFI Firmware"									| Out-File -FilePath $OutputFile -Append
#			"  UEFI Installed Version   : $regvalueUEFIFileName"		| Out-File -FilePath $OutputFile -Append
#			"  UEFI Recommended Version : $regvalueUEFIFileNameLatest"	| Out-File -FilePath $OutputFile -Append
#			if ($regvalueUEFIVersion -lt $regvalueUEFIVersionLatest)
#			{
#				"  The installed firmware version is older than the firmware update from $CurrentFirmwareDate."	| Out-File -FilePath $OutputFile -Append
#			}
#			elseif ($regvalueUEFIVersion -eq $regvalueUEFIVersionLatest)
#			{
#				"  The installed firmware version matches the firmware update from $CurrentFirmwareDate."	| Out-File -FilePath $OutputFile -Append
#			}
#			elseif ($regvalueUEFIVersion -gt $regvalueUEFIVersionLatest)
#			{
#				"  The installed firmware version is newer than the firmware update from $CurrentFirmwareDate."	| Out-File -FilePath $OutputFile -Append
#			}
#		}
#	}
#	else
#	{
#		"Surface UEFI Firmware"	| Out-File -FilePath $OutputFile -Append
#		"  UEFI Firmware Installed Version   : The following registry key does not exist: $regkeyUEFI"			| Out-File -FilePath $OutputFile -Append
#	}
	#endregion "Old Code"

	"`n`n" | Out-File -FilePath $OutputFile -Append

	$Separator1 	| Out-File -FilePath $OutputFile -Append	
	"Please refer to the following articles:"	| Out-File -FilePath $OutputFile -Append
	$Separator1 	| Out-File -FilePath $OutputFile -Append	
	#"Public Content:"	| Out-File -FilePath $OutputFile -Append
	#"`"Surface firmware and driver packs`""		| Out-File -FilePath $OutputFile -Append
	#"http://www.microsoft.com/en-us/download/details.aspx?id=38826" 	| Out-File -FilePath $OutputFile -Append
	"`n" | Out-File -FilePath $OutputFile -Append
	"Internal Content:"	| Out-File -FilePath $OutputFile -Append
	"`"2961421 - Surface: How to check firmware versions`""	| Out-File -FilePath $OutputFile -Append
	"https://vkbexternal.partners.extranet.microsoft.com/VKBWebService/ViewContent.aspx?scid=B;EN-US;2961421"	| Out-File -FilePath $OutputFile -Append
	"`n`n`n`n`n" | Out-File -FilePath $OutputFile -Append

	#region "Connected Standby Hibernation Configuration" 
	#"===================================================="	| Out-File -FilePath $OutputFile -Append
	#"Connected Standby Status" 								| Out-File -FilePath $OutputFile -Append
	#"===================================================="	| Out-File -FilePath $OutputFile -Append
	#"`n" | Out-File -FilePath $OutputFile -Append	
	#"[info] Connected Standby Status section"  | WriteTo-StdOut 
	## Check for HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power "CsEnabled" = dword:00000000
	#$regkeyPower = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"
	#If (test-path $regkeyPower)
	#{
	#	"[info] Power regkey exists"  | WriteTo-StdOut 
	#	$regvaluePowerCsEnabled = Get-ItemProperty -path $regkeyPower -name "CsEnabled" -ErrorAction SilentlyContinue
	#	if ($regvaluePowerCsEnabled -ne $null)
	#	{
	#		$regvaluePowerCsEnabled = $regvaluePowerCsEnabled.CsEnabled
	#		"[info] Connected Standby registry value exists: $regvaluePowerCsEnabled"  | WriteTo-StdOut 
	#		if ($regvaluePowerCsEnabled -eq 1)
	#		{
	#			"Connected Standby status                 : ENABLED"	| Out-File -FilePath $OutputFile -Append
	#		}
	#		else
	#		{
	#			"Connected Standby status                 : DISABLED"	| Out-File -FilePath $OutputFile -Append
	#		}
	#	}
		
		
	#	# Checking for Hyper-V
	#	#
	#	# Win32_ComputerSystem class
	#	# http://msdn.microsoft.com/en-us/library/aa394102(v=vs.85).aspx
	#	#
	#	"[info] Checking for Windows Optional Feature (client SKUs) or Hyper-V Role (server SKUs)"  | WriteTo-StdOut 
	#	if ($domainRole -gt 1) 
	#	{ #Server
	#		$HyperV = Get-WindowsFeature | Where-Object {($_.installed -eq $true) -and ($_.DisplayName -eq "Hyper-V")}
	#		If ($HyperV -ne $null)
	#		{
	#			"Hyper-V Role                             : Installed"	| Out-File -FilePath $OutputFile -Append
	#		}
	#		else
	#		{
	#			"Hyper-V Role                             : Not Installed"	| Out-File -FilePath $OutputFile -Append
	#		}
	#	}
	#	else
	#	{ #Client
	#		$HypervClient = Get-WindowsOptionalFeature -online | Where-Object {($_.FeatureName -eq "Microsoft-Hyper-V")}
	#		if ($HyperVClient.State -eq "Enabled")
	#		{
	#			"Windows Optional Feature `"Client Hyper-V`": Installed"	| Out-File -FilePath $OutputFile -Append
	#		}
	#		else
	#		{
	#			"Windows Optional Feature `"Client Hyper-V`": Not Installed"	| Out-File -FilePath $OutputFile -Append
	#		}
	#	}
	#}
	#"`n" | Out-File -FilePath $OutputFile -Append
	#"`n" | Out-File -FilePath $OutputFile -Append
	#$Separator1| Out-File -FilePath $OutputFile -Append	
	#"Please refer to the following article:"	| Out-File -FilePath $OutputFile -Append
	#$Separator1| Out-File -FilePath $OutputFile -Append	
	#"Public Content:" | Out-File -FilePath $OutputFile -Append
	#"`"2973536 - Connected Standby is not available when the Hyper-V role is enabled`"" | Out-File -FilePath $OutputFile -Append
	#"http://support.microsoft.com/kb/2973536/EN-US" | Out-File -FilePath $OutputFile -Append
	#"`n" | Out-File -FilePath $OutputFile -Append
	#"`n" | Out-File -FilePath $OutputFile -Append
	#"`n" | Out-File -FilePath $OutputFile -Append
	#"`n" | Out-File -FilePath $OutputFile -Append
	#"`n" | Out-File -FilePath $OutputFile -Append


	#"===================================================="	| Out-File -FilePath $OutputFile -Append
	#"Connected Standby Hibernation Configuration" 			| Out-File -FilePath $OutputFile -Append
	#"===================================================="	| Out-File -FilePath $OutputFile -Append
	#"`n" | Out-File -FilePath $OutputFile -Append	
	#"[info] Connected Standby Hibernation Configuration section"  | WriteTo-StdOut

	## Find the active power scheme
	#$activePowerSchemeRegkey = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes"
	#If (test-path $activePowerSchemeRegkey)
	#{
	#	$activePowerScheme = Get-ItemProperty -path $activePowerSchemeRegkey -name "ActivePowerScheme" -ErrorAction SilentlyContinue
	#	if ($activePowerScheme -ne $null)
	#	{
	#		$activePowerSchemeGUID = $activePowerScheme.ActivePowerScheme
	#		"Active Profile GUID           : $activePowerSchemeGUID" 	| Out-File -FilePath $OutputFile -Append
	#	}
	#	else
	#	{
	#		"Active Profile GUID           : Unable to Determine" 	| Out-File -FilePath $OutputFile -Append			
	#	}
	#}
	#"`n" | Out-File -FilePath $OutputFile -Append	

	## GUID definitions
	#$batterySettingsGUID       = “e73a048d-bf27-4f12-9731-8b2076e8891f”
	#$batterySaverTimeoutGUID   = “7398e821-3937-4469-b07b-33eb785aaca1”
	#$batterySaverTripPointGUID = “1e133d45-a325-48da-8769-14ae6dc1170b”
	#$batterySaverActionGUID    = “c10ce532-2eb1-4b3c-b3fe-374623cdcf07”

	#"Battery Settings GUID         : $batterySettingsGUID" 	     | Out-File -FilePath $OutputFile -Append
	#"Battery Saver Timeout GUID    : $batterySaverTimeoutGUID" 	 | Out-File -FilePath $OutputFile -Append
	#"Battery Saver Trip Point GUID : $batterySaverTripPointGUID" | Out-File -FilePath $OutputFile -Append
	#"Battery Saver Action GUID     : $batterySaverActionGUID"    | Out-File -FilePath $OutputFile -Append
	#"`n" | Out-File -FilePath $OutputFile -Append

	## default settings for power schemes
	##  Active power scheme
	##   $activePowerScheme ; Regvalue of ActivePowerScheme here HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes
	##
	##  Default Settings of the active Power Scheme:
	##   $regkeyCsBsTimeoutDefault   = "HKLM:\System\CurrentControlSet\Control\Power\PowerSettings\$batterySettingsGUID\$batterySaverTimeoutGUID\DefaultPowerSchemeValues\$activePowerSchemeGUID"
	##   $regkeyCsBsTripPointDefault = "HKLM:\System\CurrentControlSet\Control\Power\PowerSettings\$batterySettingsGUID\$batterySaverTripPointGUID\DefaultPowerSchemeValues\$activePowerSchemeGUID"
	##   $regkeyCsBsActionDefault    = "HKLM:\System\CurrentControlSet\Control\Power\PowerSettings\$batterySettingsGUID\$batterySaverActionGUID\DefaultPowerSchemeValues\$activePowerSchemeGUID"
	##
	##  Current Setting that overrides the default setting:
	##   $regkeyCsBsTimeout = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\$activePowerSchemeGUID\$batterySettingsGUID\$batterySaverTimeoutGUID"
	##	$regkeyCsBsTripPoint = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\$activePowerSchemeGUID\$batterySettingsGUID\$batterySaverTripPointGUID"
	##	$regkeyCsBsAction = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\$activePowerSchemeGUID\$batterySettingsGUID\$batterySaverActionGUID"
	##

	
	##****************************************************
	## Connected Standby Battery Saver Timeout
	##****************************************************
	#"Connected Standby: Battery Saver Timeout"	| Out-File -FilePath $OutputFile -Append
	#$regkeyCsBsTimeoutDefault   = "HKLM:\System\CurrentControlSet\Control\Power\PowerSettings\$batterySettingsGUID\$batterySaverTimeoutGUID\DefaultPowerSchemeValues\$activePowerSchemeGUID"
	#$regkeyCsBsTimeoutCurrent   = "HKLM:\System\CurrentControlSet\Control\Power\User\PowerSchemes\$activePowerSchemeGUID\$batterySettingsGUID\$batterySaverTimeoutGUID"
	#$regvalueCsBsTimeoutACSettingIndexRecommended = 14400	
	#$regvalueCsBsTimeoutDCSettingIndexRecommended = 14400
	##*****************
	## ACSettingIndex
	##*****************
	#if (test-path $regkeyCsBsTimeoutCurrent)
	#{
	#	$regvalueCsBsTimeoutACSettingIndexCurrent = Get-ItemProperty -path $regkeyCsBsTimeoutCurrent -name "ACSettingIndex" -ErrorAction SilentlyContinue
	#}
	#if ($regvalueCsBsTimeoutACSettingIndexCurrent -ne $null)
	#{
	#	$regvalueCsBsTimeoutACSettingIndexCurrent = $regvalueCsBsTimeoutACSettingIndexCurrent.ACSettingIndex
	#	if ($regvalueCsBsTimeoutACSettingIndexCurrent -ne $regvalueCsBsTimeoutACSettingIndexRecommended)
	#	{
	#		"  ACSettingIndex (Current Setting: Not Optimal)      = $regvalueCsBsTimeoutACSettingIndexCurrent" | Out-File -FilePath $OutputFile -Append
	#	}
	#	else
	#	{
	#		"  ACSettingIndex (Current Setting: No Action Needed) = $regvalueCsBsTimeoutACSettingIndexCurrent" | Out-File -FilePath $OutputFile -Append		
	#	}
	#}
	#elseif (test-path $regkeyCsBsTimeoutDefault)
	#{
	#	$regvalueCsBsTimeoutACSettingIndexDefault = Get-ItemProperty -path $regkeyCsBsTimeoutDefault -name "ACSettingIndex" -ErrorAction SilentlyContinue
	#	if ($regvalueCsBsTimeoutACSettingIndexDefault -ne $null)
	#	{
	#		$regvalueCsBsTimeoutACSettingIndexDefault = $regvalueCsBsTimeoutACSettingIndexDefault.ACSettingIndex
	#		if ($regvalueCsBsTimeoutACSettingIndexDefault -ne $regvalueCsBsTimeoutACSettingIndexRecommended)
	#		{
	#			"  ACSettingIndex (Current Setting: Not Optimal)      = $regvalueCsBsTimeoutACSettingIndexDefault" | Out-File -FilePath $OutputFile -Append
	#		}
	#		else
	#		{
	#			"  ACSettingIndex (Current Setting: No Action Needed) = $regvalueCsBsTimeoutACSettingIndexDefault" | Out-File -FilePath $OutputFile -Append		
	#		}
	#	}
	#	else
	#	{
	#		"  ACSettingIndex registry value does not exist."	| Out-File -FilePath $OutputFile -Append
	#	}
	#}
	#else
	#{
	#	"Connected Standby Battery Saver Timeout registry key does not exist: $regkeyCsBsTimeoutDefault"	| Out-File -FilePath $OutputFile -Append
	#}
	##*****************
	## DCSettingIndex
	##*****************
	#if (test-path $regkeyCsBsTimeoutCurrent)
	#{
	#	$regvalueCsBsTimeoutDCSettingIndexCurrent = Get-ItemProperty -path $regkeyCsBsTimeoutCurrent -name "DCSettingIndex" -ErrorAction SilentlyContinue
	#}
	#if ($regvalueCsBsTimeoutDCSettingIndexCurrent -ne $null)
	#{
	#	$regvalueCsBsTimeoutDCSettingIndexCurrent = $regvalueCsBsTimeoutDCSettingIndexCurrent.DCSettingIndex
	#	if ($regvalueCsBsTimeoutDCSettingIndexCurrent -ne $regvalueCsBsTimeoutDCSettingIndexCurrent)
	#	{
	#		"  DCSettingIndex (Current Setting: Not Optimal)      = $regvalueCsBsTimeoutDCSettingIndexCurrent" | Out-File -FilePath $OutputFile -Append
	#	}
	#	else
	#	{
	#		"  DCSettingIndex (Current Setting: No Action Needed) = $regvalueCsBsTimeoutDCSettingIndexCurrent" | Out-File -FilePath $OutputFile -Append		
	#	}
	#}
	#elseif (test-path $regkeyCsBsTimeoutDefault)
	#{
	#	$regvalueCsBsTimeoutDCSettingIndexDefault = Get-ItemProperty -path $regkeyCsBsTimeoutDefault -name "DCSettingIndex" -ErrorAction SilentlyContinue
	#	if ($regvalueCsBsTimeoutDCSettingIndexDefault -ne $null)
	#	{
	#		$regvalueCsBsTimeoutDCSettingIndexDefault = $regvalueCsBsTimeoutDCSettingIndexDefault.DCSettingIndex
	#	}
	#	if ($regvalueCsBsTimeoutDCSettingIndexDefault -ne $regvalueCsBsTimeoutDCSettingIndexRecommended)
	#	{
	#		"  DCSettingIndex (Current Setting: Not Optimal)      = $regvalueCsBsTimeoutDCSettingIndexDefault" | Out-File -FilePath $OutputFile -Append
	#	}
	#	else
	#	{
	#		"  DCSettingIndex (Current Setting: No Action Needed) = $regvalueCsBsTimeoutDCSettingIndexDefault" | Out-File -FilePath $OutputFile -Append		
	#	}
	#}
	#else
	#{
	#	"Connected Standby Battery Saver Timeout registry key does not exist: $regkeyCsBsTimeoutDefault"	| Out-File -FilePath $OutputFile -Append
	#}
	#"`n"	| Out-File -FilePath $OutputFile -Append
	#"`n"	| Out-File -FilePath $OutputFile -Append

	##****************************************************
	## Connected Standby Battery Saver Trip Point
	##****************************************************
	#"Connected Standby: Battery Saver Trip Point"	| Out-File -FilePath $OutputFile -Append
	#$regkeyCsBsTripPointCurrent = "HKLM:\System\CurrentControlSet\Control\Power\User\PowerSchemes\$activePowerSchemeGUID\$batterySettingsGUID\$batterySaverTripPointGUID"
	#$regkeyCsBsTripPointDefault = "HKLM:\System\CurrentControlSet\Control\Power\PowerSettings\$batterySettingsGUID\$batterySaverTripPointGUID\DefaultPowerSchemeValues\$activePowerSchemeGUID"
	#$regvalueCsBstpACSettingIndexRecommended = 100
	#$regvalueCsBstpDCSettingIndexRecommended = 100
	##*****************
	## ACSettingIndex
	##*****************
	#if (test-path $regkeyCsBsTripPointCurrent)
	#{
	#	$regvalueCsBstpACSettingIndexCurrent = Get-ItemProperty -path $regkeyCsBsTripPointCurrent -name "ACSettingIndex" -ErrorAction SilentlyContinue
	#}
	#if ($regvalueCsBstpACSettingIndexCurrent -ne $null)	
	#{
	#	$regvalueCsBstpACSettingIndexCurrent = $regvalueCsBstpACSettingIndexCurrent.ACSettingIndex
	#	if ($regvalueCsBstpACSettingIndexCurrent -ne $regvalueCsBstpACSettingIndexRecommended)
	#	{
	#		"  ACSettingIndex (Current Setting: Not Optimal)      = $regvalueCsBstpACSettingIndexCurrent" | Out-File -FilePath $OutputFile -Append
	#	}
	#	else
	#	{
	#		"  ACSettingIndex (Current Setting: No Action Needed) = $regvalueCsBstpACSettingIndexCurrent" | Out-File -FilePath $OutputFile -Append
	#	}
	#}
	#elseif (test-path $regkeyCsBsTripPointDefault)
	#{
	#	$regvalueCsBsTripPointACSettingIndexDefault = Get-ItemProperty -path $regkeyCsBsTripPointDefault -name "ACSettingIndex" -ErrorAction SilentlyContinue
	#	if ($regvalueCsBsTripPointACSettingIndexDefault -ne $null)
	#	{
	#		$regvalueCsBsTripPointACSettingIndexDefault = $regvalueCsBsTripPointACSettingIndexDefault.ACSettingIndex
	#	}
	#	if ($regvalueCsBsTripPointACSettingIndexDefault -ne $regvalueCsBstpACSettingIndexRecommended)
	#	{
	#		"  ACSettingIndex (Current Setting: Not Optimal)      = $regvalueCsBsTripPointACSettingIndexDefault" | Out-File -FilePath $OutputFile -Append
	#	}
	#	else
	#	{
	#		"  ACSettingIndex (Current Setting: No Action Needed) = $regvalueCsBsTripPointACSettingIndexDefault" | Out-File -FilePath $OutputFile -Append		
	#	}
	#}
	#else
	#{
	#	"  Connected Standby Battery Saver Trip Point registry key does not exist here: $regkeyCsBsTripPointDefault"	| Out-File -FilePath $OutputFile -Append
	#}
	##*****************
	## DCSettingIndex
	##*****************
	#if (test-path $regkeyCsBsTripPointCurrent)
	#{
	#	$regvalueCsBstpDCSettingIndexCurrent = Get-ItemProperty -path $regkeyCsBsTripPointCurrent -name "DCSettingIndex" -ErrorAction SilentlyContinue
	#}
	#if ($regvalueCsBstpDCSettingIndexCurrent -ne $null)	
	#{
	#	$regvalueCsBstpDCSettingIndexCurrent = $regvalueCsBstpDCSettingIndexCurrent.DCSettingIndex
	#	if ($regvalueCsBstpDCSettingIndexCurrent -ne $regvalueCsBstpDCSettingIndexRecommended)
	#	{
	#		"  DCSettingIndex (Current Setting: Not Optimal)      = $regvalueCsBstpDCSettingIndexCurrent"  | Out-File -FilePath $OutputFile -Append
	#	}
	#	else
	#	{
	#		"  DCSettingIndex (Current Setting: No Action Needed) = $regvalueCsBstpDCSettingIndexCurrent"  | Out-File -FilePath $OutputFile -Append
	#	}
	#}
	#elseif (test-path $regkeyCsBsTripPointDefault)
	#{
	#	$regvalueCsBsTripPointDCSettingIndexDefault = Get-ItemProperty -path $regkeyCsBsTripPointDefault -name "DCSettingIndex" -ErrorAction SilentlyContinue
	#	if ($regvalueCsBsTripPointDCSettingIndexDefault -ne $null)
	#	{
	#		$regvalueCsBsTripPointDCSettingIndexDefault = $regvalueCsBsTripPointDCSettingIndexDefault.DCSettingIndex
	#	}
	#	if ($regvalueCsBsTripPointDCSettingIndexDefault -ne $regvalueCsBstpDCSettingIndexRecommended)
	#	{
	#		"  DCSettingIndex (Current Setting: Not Optimal)      = $regvalueCsBsTripPointDCSettingIndexDefault"  | Out-File -FilePath $OutputFile -Append
	#	}
	#	else
	#	{
	#		"  DCSettingIndex (Current Setting: No Action Needed) = $regvalueCsBsTripPointDCSettingIndexDefault"  | Out-File -FilePath $OutputFile -Append
	#	}
	#}
	#else
	#{
	#	"  Connected Standby Battery Saver Trip Point registry key does not exist here: $regkeyCsBsTripPointDefault"	| Out-File -FilePath $OutputFile -Append
	#}
	#"`n`n"	| Out-File -FilePath $OutputFile -Append

	##****************************************************
	## Connected Standby Battery Saver Action
	##****************************************************
	#"Connected Standby: Battery Saver Action"	| Out-File -FilePath $OutputFile -Append
	#$regkeyCsBsActionCurrent = "HKLM:\System\CurrentControlSet\Control\Power\User\PowerSchemes\$activePowerSchemeGUID\$batterySettingsGUID\$batterySaverActionGUID"
	#$regkeyCsBsActionDefault = "HKLM:\System\CurrentControlSet\Control\Power\PowerSettings\$batterySettingsGUID\$batterySaverActionGUID\DefaultPowerSchemeValues\$activePowerSchemeGUID"
	## recommended values
	#$regvalueCsBsActionACSettingIndexRecommended = 1
	#$regvalueCsBsActionDCSettingIndexRecommended = 1
	##*****************
	## ACSettingIndex
	##*****************
	#if (test-path $regkeyCsBsActionCurrent)
	#{
	#	$regvalueCsBsActionACSettingIndexCurrent = Get-ItemProperty -path $regkeyCsBsActionCurrent -name "ACSettingIndex" -ErrorAction SilentlyContinue
	#}
	#if ($regvalueCsBsActionACSettingIndexCurrent -ne $null)
	#{
	#	$regvalueCsBsActionACSettingIndexCurrent = $regvalueCsBsActionACSettingIndexCurrent.ACSettingIndex
	#	if ($regvalueCsBsActionACSettingIndexCurrent -ne $regvalueCsBsActionACSettingIndexRecommended)
	#	{
	#		"  ACSettingIndex (Current Setting: Not Optimal)      = $regvalueCsBsActionACSettingIndexCurrent"		| Out-File -FilePath $OutputFile -Append
	#	}
	#	else
	#	{
	#		"  ACSettingIndex (Current Setting: No Action Needed) = $regvalueCsBsActionACSettingIndexCurrent"		| Out-File -FilePath $OutputFile -Append
	#	}
	#}
	#elseif (test-path $regkeyCsBsActionDefault)
	#{
	#	$regvalueCsBsActionACSettingIndexDefault = Get-ItemProperty -path $regkeyCsBsActionDefault -name "ACSettingIndex" -ErrorAction SilentlyContinue
	#	if ($regvalueCsBsActionACSettingIndexDefault -ne $null)
	#	{
	#		$regvalueCsBsActionACSettingIndexDefault = $regvalueCsBsActionACSettingIndexDefault.ACSettingIndex
	#		if ($regvalueCsBsActionACSettingIndexDefault -ne $regvalueCsBsActionACSettingIndexRecommended)
	#		{
	#			"  ACSettingIndex (Current Setting: Not Optimal)      = $regvalueCsBsActionACSettingIndexDefault"		| Out-File -FilePath $OutputFile -Append
	#		}
	#		else
	#		{
	#			"  ACSettingIndex (Current Setting: No Action Needed) = $regvalueCsBsActionACSettingIndexDefault"		| Out-File -FilePath $OutputFile -Append
	#		}
	#	}
	#}
	#else
	#{
	#	"Connected Standby Battery Saver Action registry key does not exist: $regkeyCsBsActionDefault"	| Out-File -FilePath $OutputFile -Append
	#}
	##*****************
	## DCSettingIndex
	##*****************
	#if (test-path $regkeyCsBsActionCurrent)
	#{
	#	$regvalueCsBsActionDCSettingIndexCurrent = Get-ItemProperty -path $regkeyCsBsActionCurrent -name "DCSettingIndex" -ErrorAction SilentlyContinue
	#}
	#if ($regvalueCsBsActionDCSettingIndexCurrent -ne $null)
	#{
	#	$regvalueCsBsActionDCSettingIndexCurrent = $regvalueCsBsActionDCSettingIndexCurrent.DCSettingIndex
	#	if ($regvalueCsBsActionDCSettingIndexCurrent -ne $regvalueCsBsActionDCSettingIndexRecommended)
	#	{
	#		"  DCSettingIndex (Current Setting: Not Optimal)      = $regvalueCsBsActionDCSettingIndexCurrent"  | Out-File -FilePath $OutputFile -Append
	#	}
	#	else
	#	{
	#		"  DCSettingIndex (Current Setting: No Action Needed) = $regvalueCsBsActionDCSettingIndexCurrent"  | Out-File -FilePath $OutputFile -Append
	#	}
	#}
	#elseif (test-path $regkeyCsBsActionDefault)
	#{
	#	$regvalueCsBsActionDCSettingIndexDefault = Get-ItemProperty -path $regkeyCsBsActionDefault -name "DCSettingIndex" -ErrorAction SilentlyContinue
	#	if ($regvalueCsBsActionDCSettingIndexDefault -ne $null)
	#	{
	#		$regvalueCsBsActionDCSettingIndexDefault = $regvalueCsBsActionDCSettingIndexDefault.DCSettingIndex
	#		if ($regvalueCsBsActionDCSettingIndexDefault -ne $regvalueCsBsActionDCSettingIndexRecommended)
	#		{
	#			"  DCSettingIndex (Current Setting: Not Optimal)      = $regvalueCsBsActionDCSettingIndexDefault"  | Out-File -FilePath $OutputFile -Append
	#		}
	#		else
	#		{
	#			"  DCSettingIndex (Current Setting: No Action Needed) = $regvalueCsBsActionDCSettingIndexDefault"  | Out-File -FilePath $OutputFile -Append
	#		}
	#	}
	#}
	#else
	#{
	#	"Connected Standby Battery Saver Action registry key does not exist: $regkeyCsBsActionDefault"	| Out-File -FilePath $OutputFile -Append
	#}
	#"`n" | Out-File -FilePath $OutputFile -Append
	#"`n" | Out-File -FilePath $OutputFile -Append
	#$Separator1| Out-File -FilePath $OutputFile -Append	
	#"Please refer to the following article:"	| Out-File -FilePath $OutputFile -Append
	#$Separator1| Out-File -FilePath $OutputFile -Append	
	#"Internal Content:" | Out-File -FilePath $OutputFile -Append
	#"`"Surface does not hibernate after 4 hours in connected standby`""	| Out-File -FilePath $OutputFile -Append
	#"https://vkbexternal.partners.extranet.microsoft.com/VKBWebService/ViewContent.aspx?scid=KB;EN-US;2998588" | Out-File -FilePath $OutputFile -Append
	#"`n`n`n`n`n" | Out-File -FilePath $OutputFile -Append
	
	#endregion "Connected Standby Hibernation Configuration" 

	#
	# Surface WUDF Services (Dock and others)
	#
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"Surface WUDF Services (Dock and others)" 				| Out-File -FilePath $OutputFile -Append
	"===================================================="	| Out-File -FilePath $OutputFile -Append

	$regKeyWUDFServices = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF'
	if(Test-Path ($regKeyWUDFServices))
	{
		Get-ChildItem $regKeyWUDFServices -Recurse | Out-File -FilePath $OutputFile -Append
	}

	"`n`n`n`n" | Out-File -FilePath $OutputFile -Append

	#
	# Secure Boot Overview
	# http://technet.microsoft.com/en-us/library/hh824987.aspx
	#
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"Secure Boot Configuration" 							| Out-File -FilePath $OutputFile -Append
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"`n" | Out-File -FilePath $OutputFile -Append

	
	$Separator1	| Out-File -FilePath $OutputFile -Append
	"Secure Boot Status"				| Out-File -FilePath $OutputFile -Append
	"  (using Confirm-SecureBootUEFI)"	| Out-File -FilePath $OutputFile -Append
	$Separator1	| Out-File -FilePath $OutputFile -Append
	"`n" | Out-File -FilePath $OutputFile -Append
	"[info] Secure Boot Status using Confirm-SecureBootUEFI"  | WriteTo-StdOut 
	# Determine if SecureBoot is enabled.
	#
	$secureBootEnabled = $false
	$confirmSecureBootUEFI = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
	If ($confirmSecureBootUEFI)
	{
		$secureBootEnabled = $true
		"Secure Boot: ENABLED"	| Out-File -FilePath $OutputFile -Append
	}
	else
	{
		"Secure Boot: DISABLED"	| Out-File -FilePath $OutputFile -Append		
	}
	"`n`n`n" | Out-File -FilePath $OutputFile -Append
	"`n" | Out-File -FilePath $OutputFile -Append

	$Separator1	| Out-File -FilePath $OutputFile -Append
	"Secure Boot Policy UEFI"			| Out-File -FilePath $OutputFile -Append
	"  (using Get-SecureBootPolicy)"	| Out-File -FilePath $OutputFile -Append
	$Separator1	| Out-File -FilePath $OutputFile -Append
	"`n" | Out-File -FilePath $OutputFile -Append
	"[info] Secure Boot Status using Confirm-SecureBootUEFI"  | WriteTo-StdOut 
	#
	# Determine what policy is in use for SecureBootUEFI with Get-SecureBootPolicy
	#
	if ($secureBootEnabled)
	{
		"[info] Secure Boot section using Get-SecureBootPolicy"  | WriteTo-StdOut
		$GUID = Get-SecureBootPolicy
		$DebugPolicyString = $Guid.Publisher.ToString()
		$DefaultPolicy = "77FA9ABD-0359-4D32-BD60-28F4E78F784B"
		$DefaultPolicyARM = "77FA9ABD-0359-4D32-BD60-28F4E78F784B"
		$DebugPolicy = "0CDAD82E-D839-4754-89A1-844AB282312B"

		"SecureBoot Policy Mode GUID: $DebugPolicyString" | Out-File -FilePath $OutputFile -Append
		if($DebugPolicyString -match $DefaultPolicy) {
			"SecureBoot Policy Mode     : PRODUCTION" | Out-File -FilePath $OutputFile -Append
		}
		elseif($DebugPolicyString -match $DefaultPolicyARM) {
			"SecureBoot Policy Mode     : PRODUCTION" | Out-File -FilePath $OutputFile -Append
		}
		elseif($DebugPolicyString -match $DebugPolicy) {
			"SecureBoot Policy Mode     : DEBUG" | Out-File -FilePath $OutputFile -Append
		}
		else {
			"SecureBoot Policy Mode: Invalid Policy $DebugPolicyString"  | Out-File -FilePath $OutputFile -Append
		}
	}
	"`n`n`n" | Out-File -FilePath $OutputFile -Append	

	$Separator1	| Out-File -FilePath $OutputFile -Append
	"Secure Boot Policy UEFI"								| Out-File -FilePath $OutputFile -Append
	"  Using `"Get-SecureBootUefi -Name PK | fl *`")"		| Out-File -FilePath $OutputFile -Append
	$Separator1	| Out-File -FilePath $OutputFile -Append
	"`n" | Out-File -FilePath $OutputFile -Append
		"[info] Secure Boot section using Get-SecureBootUefi -Name PK | fl *"  | WriteTo-StdOut
	# Get-SecureBootUEFI
	"Get-SecureBootUefi -Name PK | fl *" | Out-File -FilePath $OutputFile -Append
	Get-SecureBootUefi -Name PK | Format-List *	| Out-File -FilePath $OutputFile -Append
	"`n`n`n" | Out-File -FilePath $OutputFile -Append

	$Separator1	| Out-File -FilePath $OutputFile -Append
	"Secure Boot Policy UEFI"								| Out-File -FilePath $OutputFile -Append
	"  Using Output of `"Get-SecureBootUEFI -Name PK -OutputFilePath SecureBootPk.tmp`""	| Out-File -FilePath $OutputFile -Append
	$Separator1	| Out-File -FilePath $OutputFile -Append
	"`n" | Out-File -FilePath $OutputFile -Append
	"[info] Secure Boot section using Get-SecureBootUEFI -Name PK -OutputFilePath SecureBootPk.tmp"  | WriteTo-StdOut
	Get-SecureBootUEFI -Name PK -OutputFilePath SecureBootPk.tmp
	$pk = (Get-content SecureBootPk.tmp)
	$pk | Out-File -FilePath $OutputFile -Append
	"`n`n`n`n`n" | Out-File -FilePath $OutputFile -Append

	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"WMI Class Information" 								| Out-File -FilePath $OutputFile -Append
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"`n" | Out-File -FilePath $OutputFile -Append
	"[info] WMI Class section"  | WriteTo-StdOut

	$Separator1	| Out-File -FilePath $OutputFile -Append
	"WMI Class: win32_baseboard"		| Out-File -FilePath $OutputFile -Append
	$Separator1	| Out-File -FilePath $OutputFile -Append
	$baseboard = Get-CimInstance -Class "win32_baseboard"
	$baseboard | Format-List *   | Out-File -FilePath $OutputFile -Append
	"`n`n`n" | Out-File -FilePath $OutputFile -Append	
	
	$Separator1	| Out-File -FilePath $OutputFile -Append
	"WMI Class: win32_battery"			| Out-File -FilePath $OutputFile -Append
	$Separator1	| Out-File -FilePath $OutputFile -Append
	$battery = Get-CimInstance -Class "win32_battery"
	$battery | Format-List *   | Out-File -FilePath $OutputFile -Append
	"`n`n`n" | Out-File -FilePath $OutputFile -Append	
	
	$Separator1	| Out-File -FilePath $OutputFile -Append
	"WMI Class: win32_bios"				| Out-File -FilePath $OutputFile -Append
	$Separator1	| Out-File -FilePath $OutputFile -Append
	$bios = Get-CimInstance -Class "win32_bios"
	$bios | Format-List *   | Out-File -FilePath $OutputFile -Append
	"`n`n`n" | Out-File -FilePath $OutputFile -Append	
	
	$Separator1	| Out-File -FilePath $OutputFile -Append
	"WMI Class: win32_computersystem"	| Out-File -FilePath $OutputFile -Append
	$Separator1	| Out-File -FilePath $OutputFile -Append
	$computersystem = Get-CimInstance -Class "win32_computersystem"
	$computersystem | Format-List *   | Out-File -FilePath $OutputFile -Append
	"`n`n`n" | Out-File -FilePath $OutputFile -Append	
	
	#Region new section

#	"===================================================="	| Out-File -FilePath $OutputFile -Append
#	"New Section Information" 								| Out-File -FilePath $OutputFile -Append
#	"===================================================="	| Out-File -FilePath $OutputFile -Append
#	"`n" | Out-File -FilePath $OutputFile -Append
#	"[info] New Section Info"  | WriteTo-StdOut

	$dxdiagoutputcontent = Get-Content $dxdiagOutputFileName
	$arrDisplayDevices = @()
	foreach ($line in $dxdiagoutputcontent)
	{
		switch -regex ($line)
		{
			'^(Display Devices)'
			{
				$capture = $true
				break
			}
			'^(Sound Devices)'
			{
				$capture = $false
				break
			}
		}
		if ($capture)
		{
			$arrDisplayDevices += $line
		}
	}

	$arrDisplayDevices = $arrDisplayDevices | Select-Object -Unique
	"==============================="	                                                        | Out-File -FilePath $OutputFile -Append
	"Display Driver Information"	                                                            | Out-File -FilePath $OutputFile -Append
	"==============================="	                                                        | Out-File -FilePath $OutputFile -Append
	(($arrDisplayDevices | Select-String -SimpleMatch "Card Name").ToString()).Trim()	        | Out-File -FilePath $OutputFile -Append
	(($arrDisplayDevices | Select-String -SimpleMatch "Current Mode").ToString()).Trim()	    | Out-File -FilePath $OutputFile -Append
	(($arrDisplayDevices | Select-String -SimpleMatch "Driver Name").ToString()).Trim()	        | Out-File -FilePath $OutputFile -Append
	(($arrDisplayDevices | Select-String -SimpleMatch "Driver File Version").ToString()).Trim()	| Out-File -FilePath $OutputFile -Append
	(($arrDisplayDevices | Select-String -SimpleMatch "Driver Date/Size").ToString()).Trim()	| Out-File -FilePath $OutputFile -Append
	"`n`n`n" | Out-File -FilePath $OutputFile -Append
	$msinfooutputpath = (Get-ChildItem $pwd.path | Where-Object{$_.Name -match "info32.txt"}).FullName
	$msinfooutputcontent = Get-Content $msinfooutputpath
	$arrIDEInfo = @()
	foreach ($line in $msinfooutputcontent)
	{
		switch -regex ($line)
		{
			'^(\[IDE\])'
			{
				$capture = $true
				break
			}
			'^(\[Printing\])'
			{
				$capture = $false
				break
			}
		}
		if ($capture)
		{
			$arrIDEInfo += $line
		}
	}

	$arrIDEInfo = $arrIDEInfo | Select-Object -Unique
	"==============================="  | Out-File -FilePath $OutputFile -Append
	"IDE Information"                  | Out-File -FilePath $OutputFile -Append
	"==============================="  | Out-File -FilePath $OutputFile -Append
	$arrIDEInfo                        | Out-File -FilePath $OutputFile -Append

	#endregion

	CollectFiles -filesToCollect $outputFile -fileDescription "Surface Information" -SectionDescription $sectionDescription

	$outputFile= $Computername + "_Surface_Binary_Versions.TXT"

	function ComponentSection
	{
		param 
		(
			[string]$component
		)
		$columnWidth = 52
		$componentLen = $component.length
		[int]$headerPrefix = 10
		$buffer = ($columnWidth - $componentLen - $headerPrefix)
		"-" * $headerPrefix + $component + "-" * $buffer	| Out-File -FilePath $OutputFile -Append
	}

	function FileVersion
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


	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"Surface Binary Versions"							    | Out-File -FilePath $OutputFile -Append
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"Overview"												| Out-File -FilePath $OutputFile -Append
	$Separator1	| Out-File -FilePath $OutputFile -Append
	"   1. Bluetooth"										| Out-File -FilePath $OutputFile -Append
	"   3. Keyboards"										| Out-File -FilePath $OutputFile -Append
	"   4. Network Adapters"								| Out-File -FilePath $OutputFile -Append
	"   5. System Devices"									| Out-File -FilePath $OutputFile -Append
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"`n`n`n`n`n" | Out-File -FilePath $OutputFile -Append
	"[info] Surface Binaries"  | WriteTo-StdOut

	"[info] Surface Binaries: Bluetooth"  | WriteTo-StdOut
	#ComponentSection -component "Bluetooth"
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"Bluetooth"												| Out-File -FilePath $OutputFile -Append
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"`n" | Out-File -FilePath $OutputFile -Append
	"Marvell AVASTAR Bluetooth Radio Adapter"	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename Bthport.sys	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename Bthusb.sys	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename Fsquirt.exe	| Out-File -FilePath $OutputFile -Append
	"`n" | Out-File -FilePath $OutputFile -Append
	"Microsoft Bluetooth Enumerator"	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename Bthenum.sys	| Out-File -FilePath $OutputFile -Append
	"`n" | Out-File -FilePath $OutputFile -Append
	"Microsoft Bluetooth LE Enumerator"	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename bthLEEnum.sys	| Out-File -FilePath $OutputFile -Append
	"`n`n`n`n`n" | Out-File -FilePath $OutputFile -Append

	"[info] Surface Binaries: Human Interface Devices"  | WriteTo-StdOut
	#componentSection -component "Human Interface Devices"
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"Human Interface Devices"								| Out-File -FilePath $OutputFile -Append
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"`n" | Out-File -FilePath $OutputFile -Append
	"Surface Pen Driver"	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename "SurfacePenDriver.sys"	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename "WdfCoInstaller01011.dll"	| Out-File -FilePath $OutputFile -Append
	"`n`n`n`n`n" | Out-File -FilePath $OutputFile -Append

	"[info] Surface Binaries: Keyboards"  | WriteTo-StdOut	
	#componentSection -component "Keyboards"
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"Keyboards"												| Out-File -FilePath $OutputFile -Append
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"`n" | Out-File -FilePath $OutputFile -Append
	"Surface Type Cover Filter Device"	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename Kbdclass.sys	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename Kbdhid.sys	| Out-File -FilePath $OutputFile -Append
	"`n`n`n`n`n" | Out-File -FilePath $OutputFile -Append

	"[info] Surface Binaries: Network Adapters"  | WriteTo-StdOut
	#componentSection -component "Network Adapters"
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"Network Adapters"										| Out-File -FilePath $OutputFile -Append
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"`n" | Out-File -FilePath $OutputFile -Append
	"ASIX AX88772 USB2.0 to Fast Ethernet Adapter"	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename Ax88772.sys				| Out-File -FilePath $OutputFile -Append
	fileVersion -filename WdfCoInstaller01011.dll	| Out-File -FilePath $OutputFile -Append
	# File versions on Surface as of 10.10.14: 
	# Ax88772.sys; 3.16.8.0
	# WdfCoInstaller01011.dll; 1.11.9200.16384
	"`n" | Out-File -FilePath $OutputFile -Append
	"Bluetooth Device (Personal Area Network)"	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename Bthpan.sys			| Out-File -FilePath $OutputFile -Append
	# File versions on Surface as of 10.10.14: 
	# Bthpan.sys; 6.3.9600.16384
	"`n" | Out-File -FilePath $OutputFile -Append
	"Bluetooth Device (RFCOMM Protocol TDI)"	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename bthenum.sys			| Out-File -FilePath $OutputFile -Append
	fileVersion -filename rfcomm.sys			| Out-File -FilePath $OutputFile -Append
	# File versions on Surface as of 10.10.14: 
	# bthenum.sys; 6.3.9600.16384
	# rfcomm.sys; 6.3.9600.16520
	"`n" | Out-File -FilePath $OutputFile -Append
	"Marvell AVASTAR Wireless-AC Network Controller"	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename Mrvlpcie8897.sys				| Out-File -FilePath $OutputFile -Append
	fileVersion -filename Vwifibus.sys					| Out-File -FilePath $OutputFile -Append
	fileVersion -filename WiFiCLass.sys					| Out-File -FilePath $OutputFile -Append
	# File versions on Surface as of 10.10.14: 
	# Mrvlpcie8897.sys; MP107
	# Vwifibus.sys; 6.3.9600.16384
	# WiFiCLass.sys; 6.3.9715
	"`n" | Out-File -FilePath $OutputFile -Append
	"Microsoft Kernel Debug Network Adapter"	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename Kdnic.sys				| Out-File -FilePath $OutputFile -Append
	# File versions on Surface as of 10.10.14: 
	# Kdnic.sys; 6.01.00.0000
	"`n" | Out-File -FilePath $OutputFile -Append
	"Microsoft Wi-Fi Direct Virtual Adapter"	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename Vwifimp.sys			| Out-File -FilePath $OutputFile -Append
	# File versions on Surface as of 10.10.14: 
	# Vwifimp.sys; 6.3.9600.17111
	"`n`n`n" | Out-File -FilePath $OutputFile -Append

	"[info] Surface Binaries: System Devices"  | WriteTo-StdOut
	#componentSection -component "System Devices"
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"System Devices"										| Out-File -FilePath $OutputFile -Append
	"===================================================="	| Out-File -FilePath $OutputFile -Append
	"`n" | Out-File -FilePath $OutputFile -Append
	"Surface Accessory Device"	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename SurfaceAccessoryDevice.sys | Out-File -FilePath $OutputFile -Append
	#SurfaceAccessoryDevice.sys; 2.0.1012.0
	"`n" | Out-File -FilePath $OutputFile -Append
	"Surface Cover Telemetry"	| Out-File -FilePath $OutputFile -Append
	$filename = "SurfaceCoverTelemetry.dll"
	$wmiQuery = "select * from cim_datafile where name='c:\\windows\\system32\\drivers\\umdf\\" + $filename + "'"
	$fileObj = Get-CimInstance -query $wmiQuery
	$filenameLength = $filename.Length
	$columnLen = 35
	$columnDiff = $columnLen - $filenameLength
	$columnPrefix = 3
	$fileLine = " " * ($columnPrefix) + $filename + " " * ($columnDiff) + $fileObj.version
	$fileLine | Out-File -FilePath $OutputFile -Append
	#SurfaceCoverTelemetry.dll (windir\system32\drivers\umdf); 2.0.722.0
	fileVersion -filename WUDFRd.sys	| Out-File -FilePath $OutputFile -Append
	#WUDFRd.sys; 6.3.9600.17195
	"`n" | Out-File -FilePath $OutputFile -Append
	"Surface Display Calibration"	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename SurfaceDisplayCalibration.sys	| Out-File -FilePath $OutputFile -Append
	#SurfaceDisplayCalibration.sys; 2.0.1002.0
	"`n" | Out-File -FilePath $OutputFile -Append
	"Surface Home Button"	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename SurfaceCapacitiveHomeButton.sys	| Out-File -FilePath $OutputFile -Append
	#SurfaceCapacitiveHomeButton.sys; 2.0.358.0
	"`n" | Out-File -FilePath $OutputFile -Append
	"Surface Integration"	| Out-File -FilePath $OutputFile -Append
	fileVersion -filename SurfaceIntegrationDriver.sys	| Out-File -FilePath $OutputFile -Append
	#SurfaceIntegrationDriver.sys; 2.0.1102.0
	"`n`n`n" | Out-File -FilePath $OutputFile -Append
	"`n" | Out-File -FilePath $OutputFile -Append

	CollectFiles -filesToCollect $outputFile -fileDescription "Surface Binaries Information" -SectionDescription $sectionDescription
	
	#----------Registry
	$OutputFile= $Computername + '_Surface_Registry_Output.TXT'
	$CurrentVersionKeys =   'HKLM\SYSTEM\CurrentControlSet\Control\FirmwareResources',
							'HKLM\SYSTEM\CurrentControlSet\Control\Power',
							'HKLM\SYSTEM\CurrentControlSet\Enum\UEFI',
							'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}',
							'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF'

	RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -OutputFile $OutputFile -fileDescription "Surface Registry Output" -SectionDescription $sectionDescription
}


# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAXnxmGsmHyBX1x
# WT9zmNvi8khJwExfiH0gNN3KBhZuTaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGzOF4HNG2hndhO8Q0t9kj9C
# rZyWcVKG7fMIOcRpLRRSMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBnuoZ04qriS/bVQvAzR6yk1ZNWaEG/rafWRL6tvFCxF+uLYM6AdcPi
# ZrVloe7pvURwZBQd/ga+uKPvqS85BxGV3/9D4MW47Ok2/GjPc9jB4tl56hgwCG3I
# 0c8S9GKNeYNwz9lJKDmiDlgE+1oPzyMvHOffidJWNal1VNmha3NS72He74rldF9l
# gRyAXMEQIRsxB6aFTVnjT6RaKjWNQh3c5760fq5iAhpuNuQ2RaC8ft0mpMomixEn
# accghi1GXoGuZEchCvMAjDJ4m60esfVKNu6yA280bpH3ZBednho9LLZdM771/jAX
# EvwNtFjn0oNBbLeqrG3TmayOgx2KL8F2oYIW/TCCFvkGCisGAQQBgjcDAwExghbp
# MIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEILa8fZya5EV4qWC3DRDPwbtYpEWApvVnrT7FBXpMwK5LAgZi1/U5
# XqcYEzIwMjIwODAxMDc1MTE2LjQ0MlowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjIyNjQt
# RTMzRS03ODBDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVDCCBwwwggT0oAMCAQICEzMAAAGYdrOMxdAFoQEAAQAAAZgwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTE1WhcNMjMwMjI4MTkwNTE1WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MjI2NC1FMzNFLTc4MEMxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDG1JWsVksp8xG4sLMnfxfit3ShI+7G1MfTT+5XvQzu
# AOe8r5MRAFITTmjFxzoLFfmaxLvPVlmDgkDi0rqsOs9Al9jVwYSFVF/wWC2+B76O
# ysiyRjw+NPj5A4cmMhPqIdNkRLCE+wtuI/wCaq3/Lf4koDGudIcEYRgMqqToOOUI
# V4e7EdYb3k9rYPN7SslwsLFSp+Fvm/Qcy5KqfkmMX4S3oJx7HdiQhKbK1C6Zfib+
# 761bmrdPLT6eddlnywls7hCrIIuFtgUbUj6KJIZn1MbYY8hrAM59tvLpeGmFW3Gj
# eBAmvBxAn7o9Lp2nykT1w9I0s9ddwpFnjLT2PK74GDSsxFUZG1UtLypi/kZcg9We
# nPAZpUtPFfO5Mtif8Ja8jXXLIP6K+b5LiQV8oIxFSBfgFN7/TL2tSSfQVcvqX1mc
# SOrx/tsgq3L6YAxI6Pl4h1zQrcAmToypEoPYNc/RlSBk6ljmNyNDsX3gtK8p6c7H
# CWUhF+YjMgfanQmMjUYsbjdEsCyL6QAojZ0f6kteN4cV6obFwcUEviYygWbedaT8
# 6OGe9LEOxPuhzgFv2ZobVr0J8hl1FVdcZFbfFN/gdjHZ/ncDDqLNWgcoMoEhwwzo
# 7FAObqKaxfB5zCBqYSj45miNO5g3hP8AgC0eSCHl3rK7JPMr1B+8JTHtwRkSKz/+
# cwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFG6RhHKNpsg3mgons7LR5YHTzeE3MB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBACT6B6F33i/89zXTgqQ8L6CYMHx9BiaHOV+wk53JOriCzeaLjYgRyssJhmnn
# J/CdHa5qjcSwvRptWpZJPVK5sxhOIjRBPgs/3+ER0vS87IA+aGbf7NF7LZZlxWPO
# l/yFBg9qZ3tpOGOohQInQn5zpV23hWopaN4c49jGJHLPAfy9u7+ZSGQuw14CsW/X
# RLELHT18I60W0uKOBa5Pm2ViohMovcbpNUCEERqIO9WPwzIwMRRw34/LgjuslHJo
# p+/1Ve/CfyNqweUmwepQHJrd+wTLUlgm4ENbXF6i52jFfYpESwLdAn56o/pj+grs
# d2LrAEPQRyh49rWvI/qZfOhtT2FWmzFw6IJvZ7CzT1O+Fc0gIDBNqass5QbmkOkK
# Yy9U7nFA6qn3ZZ+MrZMsJTj7gxAf0yMkVqwYWZRk4brY9q8JDPmcfNSjRrVfpYyz
# EVEqemGanmxvDDTzS2wkSBa3zcNwOgYhWBTmJdLgyiWJGeqyj1m5bwNgnOw6NzXC
# iVMzfbztdkqOdTR88LtAJGNRjevWjQd5XitGuegSp2mMJglFzRwkncQau1BJsCj/
# 1aDY4oMiO8conkmaWBrYe11QCS896/sZwSdnEUJak0qpnBRFB+THRIxIivCKNbxG
# 2QRZ8dh95cOXgo0YvBN5a1p+iJ3vNwzneU2AIC7z3rrIbN2fMIIHcTCCBVmgAwIB
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
# IEVTTjoyMjY0LUUzM0UtNzgwQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA8ywe/iF5M8fIU2aT6yQ3vnPpV5Og
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRnKMwIhgPMjAyMjA4MDEwODI4MTlaGA8yMDIyMDgwMjA4MjgxOVow
# dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5pGcowIBADAHAgEAAgISNDAHAgEAAgIR
# qTAKAgUA5pLuIwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAGW0b6G1nxJf
# Sz+162eIfZKEeCT5UlfEbylGeWHEIa2FOqerhClam6wPRPAJD+i5gmNDLWEXoJhE
# 9mfD/DNtILqESrGPO8DLhy1fGnzIFrHCh+Hmog+1BobdtTTDsZ63lI6Mp6+O44xP
# gtveVE5cjYmTGOZttcbmk0FXsnRiWdbDMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGYdrOMxdAFoQEAAQAAAZgwDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQg+Atw+Yu2rzsbFUTN9uaxpit9Ssb7AU4rMqSxQISbaJ4wgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCC/ps4GOTn/9wO1NhHM9Qfe0loB3slkw1FF
# 3r+bh21WxDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABmHazjMXQBaEBAAEAAAGYMCIEIITB9XHZkmFVJEo8WDGAMhrrxCbnPT0sQRQc
# 2rAtWwOFMA0GCSqGSIb3DQEBCwUABIICACSbmCXJKM0oH+0pUPJN8uNUsGJEZnJw
# Ex/rlFZTAfGckJO9m/xKqMlKdUJazRmG1Cmx/g4E86b74YeF6qBQ/eDydo6ZqSgT
# jymCD00pxymJEjfRPw8Q46iWbnlr4ynGH31KBteugpRtvf8pDr+jBTADVr82V6zi
# 4NaWIgXOEsbmZZLV6mw+8WGj5HnM9WQPKf05iB3UBQRl+00s4StXXJA2g0hgxbLm
# hz8L4KUahFA1oPh6YbzdnYroYT8VbdiSzGLwuMHMkIYvRAUlMzfUyF0x0zoVTdLp
# BgZriltbI54ZGIuxGpjZOajHw0WDCFDJ7EoYVVeuyJYulnpf9zahRJH66guCHBPU
# brF7yWv8LJ+oa5qwqVozSHuPmEE7rpgSZefzeJU1UDoxH4pvbM3NikRSlK3PSy3A
# dEYWHbZEJq7GNUvVHSUOpLuxoUZC8gjuXrURI4xPEkTWgghzw19uNNJVSfLSTkCa
# O2pLiBFcP5rbuKiXrizFg20SrwqsZgjZxL5Gf20zN2Am3OndxdYR+vLDmHvB7JuH
# HYrl3uS3mSwVas5lHu92i9+RIvW0AMB6rYZ/ndNxgE75vpbWrOialdgGiW4Eqx0s
# VLedKszGqxDq+iVEnCoMc9J/QvxPo7Y/o5dK79MgauvgGVR6r2wGlDVArna6bFdX
# lIrigb/YvodC
# SIG # End signature block
