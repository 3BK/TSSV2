#************************************************
# DC_NetworkAdapters-Component.ps1
# Version 1.0 Dumped the registry key where adapter information is stored, and added Powershell Cmdlets (via JoelCh)
# Version 1.1 Added registry output for the CurrentControlSet\Control class ID for Adapters.
# Version 1.2: Altered the runPS function to correct a column width issue.
# Version 1.3.07.31.2014: Added the detailed output for Get-NetAdapterBinding -AllBindings.
# Version 1.4.08.08.2014: Added regkey "HKLM\SYSTEM\CurrentControlSet\Control\Network" to reg output so we can correlate GUIDs to Interface names.
# Version 1.5.08.11.2014: Added "Network Adapter to GUID Mappings" section using output from "HKLM:\SYSTEM\CurrentControlSet\Control\Network"
# Date: 2013-2014
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: 
# Called from: Networking Diags
#*******************************************************
#2019-08-31 WalterE

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


function RunPS ([string]$RunPScmd="", [switch]$ft, [switch]$noHeader)
{
	if ($noHeader)
	{
	}
	else
	{
		$RunPScmdLength = $RunPScmd.Length
		"-" * ($RunPScmdLength)		| Out-File -FilePath $OutputFile -append
		"$RunPScmd"  				| Out-File -FilePath $OutputFile -append
		"-" * ($RunPScmdLength)  	| Out-File -FilePath $OutputFile -append
	}
		
	if ($ft)
	{
		# This format-table expression is useful to make sure that wide ft output works correctly
		Invoke-Expression $RunPScmd	|format-table -autosize -outvariable $FormatTableTempVar | Out-File -FilePath $outputFile -Width 500 -append
	}
	else
	{
		Invoke-Expression $RunPScmd	| Out-File -FilePath $OutputFile -append
	}
	"`n`n`n"	| Out-File -FilePath $OutputFile -append
}


	Import-LocalizedData -BindingVariable ScriptVariable
	Write-DiagProgress -Activity $ScriptVariable.ID_ctsNetAdapters -Status $ScriptVariable.ID_ctsNetAdaptersDescription #_#


$sectionDescription = "Network Adapters"

# detect OS version and SKU
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber

$outputFile = $Computername + "_NetworkAdapters_info_pscmdlets.TXT"
"===================================================="		| Out-File -FilePath $OutputFile -append
"Network Adapter Powershell Cmdlets"						| Out-File -FilePath $OutputFile -append
"===================================================="		| Out-File -FilePath $OutputFile -append
"Overview"													| Out-File -FilePath $OutputFile -append
"----------------------------------------------"			| Out-File -FilePath $OutputFile -append
"Network Adapter Powershell Cmdlets"						| Out-File -FilePath $OutputFile -append
"   1. Get-NetAdapter"										| Out-File -FilePath $OutputFile -append
"   2. Get-NetAdapter -IncludeHidden"						| Out-File -FilePath $OutputFile -append
"   3. Get-NetAdapterAdvancedProperty"						| Out-File -FilePath $OutputFile -append
"   4. Get-NetAdapterBinding -AllBindings -IncludeHidden | select Name, InterfaceDescription, DisplayName, ComponentID, Enabled"	| Out-File -FilePath $OutputFile -append
"   5. Get-NetAdapterChecksumOffload"						| Out-File -FilePath $OutputFile -append
"   6. Get-NetAdapterEncapsulatedPacketTaskOffload"			| Out-File -FilePath $OutputFile -append
"   7. Get-NetAdapterHardwareInfo"							| Out-File -FilePath $OutputFile -append
"   8. Get-NetAdapterIPsecOffload"							| Out-File -FilePath $OutputFile -append
"   9. Get-NetAdapterLso"									| Out-File -FilePath $OutputFile -append
"  10. Get-NetAdapterPowerManagement"						| Out-File -FilePath $OutputFile -append
"  11. Get-NetAdapterQos"									| Out-File -FilePath $OutputFile -append
"  12. Get-NetAdapterRdma"									| Out-File -FilePath $OutputFile -append
"  13. Get-NetAdapterRsc"									| Out-File -FilePath $OutputFile -append
"  14. Get-NetAdapterRss"									| Out-File -FilePath $OutputFile -append
"  15. Get-NetAdapterSriov"									| Out-File -FilePath $OutputFile -append
"  16. Get-NetAdapterSriovVf"								| Out-File -FilePath $OutputFile -append
"  17. Get-NetAdapterStatistics"							| Out-File -FilePath $OutputFile -append
"  18. Get-NetAdapterVmq"									| Out-File -FilePath $OutputFile -append
"  19. Get-NetAdapterVmqQueue"								| Out-File -FilePath $OutputFile -append
"  20. Get-NetAdapterVPort"									| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"		| Out-File -FilePath $OutputFile -append
"Network Adapter Details For NON-HIDDEN Adapters (formatted list, non-hidden)"	| Out-File -FilePath $OutputFile -append
"   1. Get-NetAdapter | fl *"	| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"		| Out-File -FilePath $OutputFile -append
"Network Adapter Details For HIDDEN Adapters (formatted list, ONLY hidden)"	| Out-File -FilePath $OutputFile -append
"   1. Get-NetAdapter -IncludeHidden (parsed to show hidden only)"	| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"			| Out-File -FilePath $OutputFile -append
"Network Adapter to GUID Mappings"								| Out-File -FilePath $OutputFile -append
"  Using regkey HKLM:\SYSTEM\CurrentControlSet\Control\Network"	| Out-File -FilePath $OutputFile -append
"===================================================="			| Out-File -FilePath $OutputFile -append
"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append

"__ value of Switch noNetAdapters: $Global:noNetAdapters  - 'True' will suppress output for Get-NetAdapterStatistics.`n`n"	| Out-File -FilePath $OutputFile -append


if ($bn -gt 9000)
{
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Network Adapter Powershell Cmdlets"					| Out-File -FilePath $OutputFile -append	
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"`n" 	| Out-File -FilePath $OutputFile -append
	"-------------------------------"	| Out-File -FilePath $OutputFile -append
	"Get-NetAdapter (formatted table)"	| Out-File -FilePath $OutputFile -append
	"-------------------------------"	| Out-File -FilePath $OutputFile -append
	$networkAdapters = get-netadapter
	$networkAdaptersLen = $networkAdapters.length
	"Number of Network Adapters (output from get-netadapter; does not include hidden adapters): " + $networkAdaptersLen	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	runPS "Get-NetAdapter"				-ft -noheader	# W8/WS2012, W8.1/WS2012R2	# ft

	"-------------------------------------------------------------------"	| Out-File -FilePath $OutputFile -append
	"Get-NetAdapter -IncludeHidden (formatted table, hidden)"	| Out-File -FilePath $OutputFile -append
	"-------------------------------------------------------------------"	| Out-File -FilePath $OutputFile -append
	$networkAdaptersWithHidden = Get-NetAdapter -IncludeHidden
	$networkAdaptersWithHiddenLen = $networkAdaptersWithHidden.length
	$hiddenNetworkAdaptersLen = 0
	foreach ($adapter in $networkAdaptersWithHidden)
	{
		if ($adapter.Hidden -eq $true)
		{ $hiddenNetworkAdaptersLen++ }
	}
	"Number of Network Adapters (output from get-netadapter; does not include hidden adapters): " + $networkAdaptersLen	| Out-File -FilePath $OutputFile -append
	"Number of Network Adapters (including hidden adapters) : " + $networkAdaptersWithHiddenLen	| Out-File -FilePath $OutputFile -append

	"`n"	| Out-File -FilePath $OutputFile -append
	runPS "Get-NetAdapter -IncludeHidden"						-ft -noheader	# W8/WS2012, W8.1/WS2012R2	# ft
	runPS "Get-NetAdapterAdvancedProperty"						-ft # W8/WS2012, W8.1/WS2012R2	# ft	
	runPS "Get-NetAdapterBinding -AllBindings -IncludeHidden | select Name, InterfaceDescription, DisplayName, ComponentID, Enabled"	-ft # W8/WS2012, W8.1/WS2012R2	# ft
	runPS "Get-NetAdapterChecksumOffload"						-ft # W8/WS2012, W8.1/WS2012R2	# ft	
	runPS "Get-NetAdapterEncapsulatedPacketTaskOffload"			-ft # W8/WS2012, W8.1/WS2012R2	# ft	
	runPS "Get-NetAdapterHardwareInfo"							-ft # W8/WS2012, W8.1/WS2012R2	# ft	
	runPS "Get-NetAdapterIPsecOffload"							-ft # W8/WS2012, W8.1/WS2012R2	# ft	
	runPS "Get-NetAdapterLso"									-ft # W8/WS2012, W8.1/WS2012R2	# ft	
	runPS "Get-NetAdapterPowerManagement"							# W8/WS2012, W8.1/WS2012R2	# fl
	runPS "Get-NetAdapterQos"										# W8/WS2012, W8.1/WS2012R2	# unknown
	runPS "Get-NetAdapterRdma"										# W8/WS2012, W8.1/WS2012R2	# unknown
	runPS "Get-NetAdapterRsc"									-ft # W8/WS2012, W8.1/WS2012R2	# ft
	runPS "Get-NetAdapterRss"										# W8/WS2012, W8.1/WS2012R2	# fl
	runPS "Get-NetAdapterSriov"										# W8/WS2012, W8.1/WS2012R2	# fl
	runPS "Get-NetAdapterSriovVf"									# W8/WS2012, W8.1/WS2012R2	# unknown

	#_# Get-NetAdapterStatistics output hangs the report on some VPN/AoVpn scenarios, e.g. on 'Cisco AnyConnect Secure Mobility Client' or 4G // see bug https://microsoft.visualstudio.com/DefaultCollection/OS/_workitems/edit/27692990
	#----------Check if Cisco AnyConnect is installed, run Get-NetAdapterStatistics only if not detected.
	#_# ToDo: check for Cellular                     Dell Wireless 5809e Gobi™ 4G LTE Mobile Broadband Card       
	$AnyConnectKey = "HKLM:\SYSTEM\CurrentControlSet\Services\vpnagent"
	$cxWmbKey = "HKLM:\SYSTEM\CurrentControlSet\Services\cxwmbclass"
	if (-Not ((Test-Path $AnyConnectKey) -or (Test-Path $cxWmbKey))) 
	{
		if (($Global:noNetAdapters -ne $true) -or ($Global:skipHang -ne $true)) {
			write-host "... running Get-NetAdapterStatistics, hint: use .\Get-psSDP Net -noNetAdapters, if stuck here"
			runPS "Get-NetAdapterStatistics"							-ft # W8/WS2012, W8.1/WS2012R2	# ft

		}#_# end noNetAdapters
	}
	
	runPS "Get-NetAdapterVmq"									-ft # W8/WS2012, W8.1/WS2012R2	# ft
	runPS "Get-NetAdapterVmqQueue"								-ft # W8/WS2012, W8.1/WS2012R2	# ft
	runPS "Get-NetAdapterVPort"										# W8/WS2012, W8.1/WS2012R2	# unknown
	"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Network Adapter Details For NON-HIDDEN Adapters (formatted list, non-hidden)"	| Out-File -FilePath $OutputFile -append
	"   1. Get-NetAdapter | fl *"	| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Number of Network Adapters (output from get-netadapter; does not include hidden adapters): " + $networkAdaptersLen	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	runPS "Get-NetAdapter | fl *"				# W8/WS2012, W8.1/WS2012R2	# fl
	"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append
	
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Network Adapter Details For HIDDEN Adapters (formatted list, ONLY hidden)"	| Out-File -FilePath $OutputFile -append
	"   1. Get-NetAdapter -IncludeHidden (parsed to show hidden only)"	| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Number of Hidden Network Adapters: " + $hiddenNetworkAdaptersLen	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	foreach ($adapter in $networkAdaptersWithHidden)
	{
		if ($adapter.Hidden -eq $true)
		{
			"-------------------------------"	| Out-File -FilePath $OutputFile -append
			$adapter | Format-List * 	| Out-File -FilePath $OutputFile -append
			"`n"	| Out-File -FilePath $OutputFile -append
		}
	}
	"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append

}
else
{
	"The Windows OS version is W2008.R2 or earlier. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append
}


"===================================================="			| Out-File -FilePath $OutputFile -append
"Network Adapter to GUID Mappings"								| Out-File -FilePath $OutputFile -append
"  Using regkey HKLM:\SYSTEM\CurrentControlSet\Control\Network"	| Out-File -FilePath $OutputFile -append
"===================================================="			| Out-File -FilePath $OutputFile -append
if ($bn -ge 6000)
{
	$networkRegKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Network"
	if (test-path $networkRegKeyPath) 
	{
		#$networkNameToGUIDObj = new-object PSObject

		$networkRegKey = Get-ItemProperty -Path $networkRegKeyPath
		$networkGUIDRegKey = Get-ChildItem -Path $networkRegKeyPath

		foreach ($netChildGUID in $networkGUIDRegKey)
		{
			$netChildGUIDName = $netChildGUID.PSChildName
			if ( ($netChildGUIDName.StartsWith("`{4D36E972")) -or ($netChildGUIDName.StartsWith("`{4d36E972")) )
			{
				# "Network Subkey GUID: $netChildGUIDName"
				$netChildGUIDRegKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Network\$netChildGUIDName"
				$netConnectionGUIDs = Get-ChildItem -Path $netChildGUIDRegKeyPath
				foreach ($netConnectionGUID in $netConnectionGUIDs)
				{
					$netConnectionGUIDName = $netConnectionGUID.PSChildName
					if ($netConnectionGUIDName.StartsWith("`{"))
					{
						$netConnectionNameRegkey = "HKLM:\SYSTEM\CurrentControlSet\Control\Network\$netChildGUIDName\$netConnectionGUIDName\Connection"
						if (test-path $netConnectionNameRegkey)
						{
							$netConnectionName = (Get-ItemProperty -Path $netConnectionNameRegkey).Name
							" Connection Name    : " + $netConnectionName	| Out-File -FilePath $OutputFile -append
							" Connection GUID    : " + $netConnectionGUIDName	| Out-File -FilePath $OutputFile -append
							"`n" | Out-File -FilePath $OutputFile -append
						}
					}
				}
			}
		}
	}
}
else
{
	"The Windows OS version is W2003 or earlier. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append
}
"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append

CollectFiles -filesToCollect $OutputFile -fileDescription "Network Adapter Information" -SectionDescription $sectionDescription



#----------Registry
$OutputFile= $Computername + "_NetworkAdapters_reg_output.TXT"
$CurrentVersionKeys =   "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}",
						"HKLM\SYSTEM\CurrentControlSet\Control\Network"
RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -OutputFile $OutputFile -fileDescription "Network Adapter registry information" -SectionDescription $sectionDescription

# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD/cDTRKvHV9rzK
# 2kavuj2DHtnK1gFBuQuRmijXK2tSxqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGY4wghmKAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOPdnDMid8nhCd2q+No4/cUm
# aEmjAYM+t/pPnVdzGpLJMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCNf3Oj8N2M1NR/jO/jOiCoAzWpmoiFqeO5ecIUKVTHdrJ4Dwfzxj6W
# ULHRtWJh1XKqib/UxuLyv2yNWS9Nzn1JGX1ABVhlAtbM7amOn7BIE6SxBmpMSX0W
# M4LkqkuybLtTAwMWbV8Xvs8DKiRIekrgIqH+wYVY1ay6yvK1qYEa4RO6dAxIGVU5
# +MHOhy6LqYLhQQXgWqIGW+ebQM5MgbHjVgozT1wNNxYWuK7UeMxjjdA8Km6psPs1
# RggReV+GSG/UfcspmH2PhDFUQ/ptle6r4yIhaPMblobxsdrswm7gvlvX4uaeuQt8
# 49Y36jSLCJZklHcYAoFYdxPdgqZuhR9poYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIDmIpIA4VUYIEGxWEVT2poS6fyMZ5E2OBS3kO0h7Dl5OAgZi3n80
# 4C4YEzIwMjIwODAxMDc0MTA0LjAwMVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046M0JENC00QjgwLTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAYm0v4YwhBxLjwABAAABiTAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDFaFw0yMzAxMjYxOTI3NDFaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNCRDQt
# NEI4MC02OUMzMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvQZXxZFma6plmuOyvNpV
# 8xONOwcYolZG/BjyZWGSk5JOGaLyrKId5VxVHWHlsmJE4SvnzsdpsKmVx8otONve
# IUFvSceEZp8VXmu5m1fu8L7c+3lwXcibjccqtEvtQslokQVx0r+L54abrNDarwFG
# 73IaRidIS1i9c+unJ8oYyhDRLrCysFAVxyQhPNZkWK7Z8/VGukaKLAWHXCh/+R53
# h42gFL+9/mAALxzCXXuofi8f/XKCm7xNwVc1hONCCz6oq94AufzVNkkIW4brUQgY
# pCcJm9U0XNmQvtropYDn9UtY8YQ0NKenXPtdgLHdQ8Nnv3igErKLrWI0a5n5jjdK
# fwk+8mvakqdZmlOseeOS1XspQNJAK1uZllAITcnQZOcO5ofjOQ33ujWckAXdz+/x
# 3o7l4AU/TSOMzGZMwhUdtVwC3dSbItpSVFgnjM2COEJ9zgCadvOirGDLN471jZI2
# jClkjsJTdgPk343TQA4JFvds/unZq0uLr+niZ3X44OBx2x+gVlln2c4UbZXNueA4
# yS1TJGbbJFIILAmTUA9Auj5eISGTbNiyWx79HnCOTar39QEKozm4LnTmDXy0/KI/
# H/nYZGKuTHfckP28wQS06rD+fDS5xLwcRMCW92DkHXmtbhGyRilBOL5LxZelQfxt
# 54wl4WUC0AdAEolPekODwO8CAwEAAaOCATYwggEyMB0GA1UdDgQWBBSXbx+zR1p4
# IIAeguA6rHKkrfl7UDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQCOtLdpWUI4KwfLLrfaKrLB92DqbAspGWM41TaO
# 4Jl+sHxPo522uu3GKQCjmkRWreHtlfyy9kOk7LWax3k3ke8Gtfetfbh7qH0LeV2X
# OWg39BOnHf6mTcZq7FYSZZch1JDQjc98+Odlow+oWih0Dbt4CV/e19ZcE+1n1zzW
# kskUEd0f5jPIUis33p+vkY8szduAtCcIcPFUhI8Hb5alPUAPMjGzwKb7NIKbnf8j
# 8cP18As5IveckF0oh1cw63RY/vPK62LDYdpi7WnG2ObvngfWVKtwiwTI4jHj2cO9
# q37HDe/PPl216gSpUZh0ap24mKmMDfcKp1N4mEdsxz4oseOrPYeFsHHWJFJ6Aivv
# qn70KTeJpp5r+DxSqbeSy0mxIUOq/lAaUxgNSQVUX26t8r+fcikofKv23WHrtRV3
# t7rVTsB9YzrRaiikmz68K5HWdt9MqULxPQPo+ppZ0LRqkOae466+UKRY0JxWtdrM
# c5vHlHZfnqjawj/RsM2S6Q6fa9T9CnY1Nz7DYBG3yZJyCPFsrgU05s9ljqfsSptp
# FdUh9R4ce+L71SWDLM2x/1MFLLHAMbXsEp8KloEGtaDULnxtfS2tYhfuKGqRXoEf
# DPAMnIdTvQPh3GHQ4SjkkBARHL0MY75alhGTKHWjC2aLVOo8obKIBk8hfnFDUf/E
# yVw4uTCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
# AQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAw
# BgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEw
# MB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk
# 4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9c
# T8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWG
# UNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6Gnsz
# rYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2
# LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLV
# wIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTd
# EonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0
# gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFph
# AXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJ
# YfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXb
# GjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJ
# KwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnP
# EP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMw
# UQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggr
# BgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYw
# DwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoY
# xDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
# L2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYB
# BQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0B
# AQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U5
# 18JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgAD
# sAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo
# 32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZ
# iefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZK
# PmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RI
# LLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgk
# ujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9
# af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzba
# ukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/
# OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLUMIIC
# PQIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JENC00QjgwLTY5QzMxJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVACGlCa3ketyeuey7bJNpWkMuiCcQoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmkY8xMCIYDzIwMjIwODAx
# MDczMDU3WhgPMjAyMjA4MDIwNzMwNTdaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaRjzECAQAwBwIBAAICJRswBwIBAAICEXMwCgIFAOaS4LECAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQArnk4S9bEdxCdv6lvAqDJLnushxbjSdiB7sVOCFegm
# 1hIyiOlgngN4YIZy5wYXFTnbUcThdirf/aWO9Kgq7ym54onCUb8XY9R6vBbJz4h4
# 5T/wMIKNVGo2pIyBEGyYLgmsXSYP5pIvgzFhbGvfTynStAvFB//Ows/cSog4V5qO
# JTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABibS/hjCEHEuPAAEAAAGJMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIKEQFpWlxgdag1ci2Lr5
# 7pMSq6z+ZA2p64WSG7FwtolpMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# ZndHMdxQV1VsbpWHOTHqWEycvcRJm7cY69l/UmT8j0UwgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYm0v4YwhBxLjwABAAABiTAiBCAk
# t45JlrVvo3nFtAGQW8QKtuen+cccumsnztg/aYVKETANBgkqhkiG9w0BAQsFAASC
# AgADG3PgSC9FpeXHsRkPpyTinffDCDYvl240cdL2cies7fniSn14YMaLPt33Y6fG
# RZ7qSMoA5VH9grjx3XS5lDDhoU55iWyybhXMPbrzLQiaZGHsyFhpAhpA2pavgiiO
# 20hp1SK+TKqiEbRbS/MdVn85gHGWn0W7GIACOPqFSdc5cy7WYgbI5G7At4xj5ttW
# p7X42i1QNr5sBOuH9xL+MrdJ6Y3zVi+16vMDPtBqTgtnhZm39extJlkp33Kbbuks
# vTkxahvhPK7ytDzDzGXX3a+3CsGcPRQ/CIqsyf9HBVIYoxYqsQLUcmXqLGDHlAaP
# uYECjxCy8camMpToH7wWfJ8Pj2y0lI0BSfl5Q8Eo8yiLTAadSQ7nxB/K4yDFKZCq
# +nRmOIDOISx5Srap60B7pTAl7tq1D51yfKnRBmby4L0zaJLC8EIJzy4Q8awk/k7+
# 8k/Q1kD54YJ150Pp1Jpju5u1GG/WtmDmHfj7r9vWCoJeiox4eqprN5bfRcX1PLY4
# BxKcDn+pSUuGI7gStxV4GYFT4/a9pTMs0GUtLmLvftoPHyr6ROKkR5EEflapAWOk
# nKDV19An4buwifvcAej32ltQx13s6Dzt0Te2vfCkPMHZ17VkFObNMhgwxKNH6tkv
# uJYk6PP/X38Nd92WkbFT5bPu5LeVsz9yFYiU6TwqrcfDbQ==
# SIG # End signature block
