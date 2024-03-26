#************************************************
# DC_HyperVNetworking.ps1
# Version 1.0.04.22.14: Created script.
# Version 1.1.04.26.14: Corrected formatting issues with PowerShell output using format-table
# Version 1.2.05.23.14: Added Get-SCIPAddress; Added Hyper-V registry output (and placed at the top of the script)
# Version 1.3.07.31.14: Moved the "Hyper-V Network Virtualization NAT Configuration" section into its own code block for WS2012R2+. 
# Date: 2014
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: PS cmdlets
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
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
}



$sectionDescription = "Hyper-V Networking Settings"

#----------Registry
$outputFile = $Computername + "_HyperVNetworking_reg_.TXT"
#grouped registry values together:
#  RegKeys: vmms;
#  RegKeys: vmsmp, smsp, vmsvsf, vmsvsp
#  RegKeys: vmbus, vmbushid, vmbusr
#  RegKeys: vmbusr, vmicguestinterface, vmicheartbeat, vmickvpexchange, vmicrdv, vmicshutdown, vmictimesync, vmicvss

$CurrentVersionKeys = 	"HKLM\SYSTEM\CurrentControlSet\services\vmms",
						"HKLM\SYSTEM\CurrentControlSet\services\vmsmp",
						"HKLM\SYSTEM\CurrentControlSet\services\VMSP",
						"HKLM\SYSTEM\CurrentControlSet\services\VMSVSF",
						"HKLM\SYSTEM\CurrentControlSet\services\VMSVSP",
						"HKLM\SYSTEM\CurrentControlSet\services\vmbus",
						"HKLM\SYSTEM\CurrentControlSet\services\VMBusHID",
						"HKLM\SYSTEM\CurrentControlSet\services\vmbusr",
						"HKLM\SYSTEM\CurrentControlSet\services\vmicguestinterface",
						"HKLM\SYSTEM\CurrentControlSet\services\vmicheartbeat",
						"HKLM\SYSTEM\CurrentControlSet\services\vmickvpexchange",
						"HKLM\SYSTEM\CurrentControlSet\services\vmicrdv",
						"HKLM\SYSTEM\CurrentControlSet\services\vmicshutdown",
						"HKLM\SYSTEM\CurrentControlSet\services\vmictimesync",
						"HKLM\SYSTEM\CurrentControlSet\services\vmicvss"
RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -OutputFile $outputFile -fileDescription "Hyper-V Registry Keys" -SectionDescription $sectionDescription



# detect OS version and SKU
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber

$outputFile = $Computername + "_HyperVNetworking_info_pscmdlets.TXT"
"===================================================="	| Out-File -FilePath $OutputFile -append
"Hyper-V Networking Settings Powershell Cmdlets"		| Out-File -FilePath $OutputFile -append
"===================================================="	| Out-File -FilePath $OutputFile -append
"Overview"												| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
"Hyper-V Server Configuration"							| Out-File -FilePath $OutputFile -append
"  1. Get-VMHost"										| Out-File -FilePath $OutputFile -append
"  2. Get-VMHostNumaNode"								| Out-File -FilePath $OutputFile -append
"  3. Get-VMHostNumaNodeStatus"							| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
"Hyper-V Switch Configuration"							| Out-File -FilePath $OutputFile -append
"  1. Get-VMSwitch *"									| Out-File -FilePath $OutputFile -append
"  2. Get-VMSwitch * | fl"								| Out-File -FilePath $OutputFile -append
#_#"  3. Get-VMSwitchTeam -SwitchName ""vSwitch"" | fl -Property * " | Out-File -FilePath $OutputFile -append
"  3. Get-VMSwitchTeam -EA SilentlyContinue | fl -Property *" | Out-File -FilePath $OutputFile -append
#_#"  4. Get-VMSwitch -Name ""vSwitch"" | Get-VMSwitchExtension | fl -Property * " | Out-File -FilePath $OutputFile -append
"  4. Get-VMSwitch | Get-VMSwitchExtension | fl -Property *" | Out-File -FilePath $OutputFile -append
"  5. Get-VMSystemSwitchExtension | fl -Property * "	| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
"Hyper-V Network Adapter Configuration"					| Out-File -FilePath $OutputFile -append
"  1. Get-VMNetworkAdapter -ManagementOS"				| Out-File -FilePath $OutputFile -append
"  2. Get-VMNetworkAdapter -All"						| Out-File -FilePath $OutputFile -append
"  3. Get-VMNetworkAdapter *"							| Out-File -FilePath $OutputFile -append
"  4. Get-VMNetworkAdapter * | fl"						| Out-File -FilePath $OutputFile -append
"  5. Get-VMNetworkAdapter -ManagementOS | fl -Property *"		| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
"Hyper-V Network Virtualization Configuration"			| Out-File -FilePath $OutputFile -append
"  1. Get-NetVirtualizationCustomerRoute"				| Out-File -FilePath $OutputFile -append
"  2. Get-NetVirtualizationProviderAddress"				| Out-File -FilePath $OutputFile -append
"  3. Get-NetVirtualizationProviderRoute"				| Out-File -FilePath $OutputFile -append
"  4. Get-NetVirtualizationLookupRecord"				| Out-File -FilePath $OutputFile -append
"  4. Get-NetVirtualizationGlobal"						| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
"Hyper-V Network Virtualization SCVMM Configuration"	| Out-File -FilePath $OutputFile -append
"  1. Get-SCIPAddress"									| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
"Hyper-V Network Virtualization NAT Configuration [HNV Gateway]" | Out-File -FilePath $OutputFile -append
"  1. Get-NetNat"										| Out-File -FilePath $OutputFile -append
"  2. Get-NetNatGlobal"									| Out-File -FilePath $OutputFile -append
"  3. Get-NetNatSession"								| Out-File -FilePath $OutputFile -append
"  4. Get-NetNatStaticMapping"							| Out-File -FilePath $OutputFile -append
"  5. Get-NetNatExternalAddress"						| Out-File -FilePath $OutputFile -append	
"===================================================="	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append


$vmmsCheck = Test-path "HKLM:\SYSTEM\CurrentControlSet\Services\vmms"
if ($vmmsCheck)
{
	if ((Get-Service "vmms").Status -eq 'Running')
	{
		if ($bn -gt 9000) 
		{
			"[info] Hyper-V Server Configuration section."  | WriteTo-StdOut	
			"===================================================="	| Out-File -FilePath $OutputFile -append
			"Hyper-V Server Configuration"							| Out-File -FilePath $OutputFile -append	
			"===================================================="	| Out-File -FilePath $OutputFile -append
			"`n"	| Out-File -FilePath $OutputFile -append
			# Hyper-V: Get-VMHost
			runPS "Get-VMHost"		-ft # W8/WS2012, W8.1/WS2012R2	# ft	
			$vmhost = get-vmhost
			runPS "Get-VMHostNumaNode"		-ft # W8/WS2012, W8.1/WS2012R2	# ft
			if ($vmhost.NumaSpanningEnabled -eq $false)
			{
				"NUMA Spanning has been disabled within Hyper-V Settings, running the `"Get-VMHostNumaNodeStatus`" ps cmdlet."		| Out-File -FilePath $OutputFile -append
				"`n"	| Out-File -FilePath $OutputFile -append				
				runPS "Get-VMHostNumaNodeStatus"			# W8/WS2012, W8.1/WS2012R2	# ft	
			}
			else
			{
				"------------------------"	| Out-File -FilePath $OutputFile -append
				"Get-VMHostNumaNodeStatus"	| Out-File -FilePath $OutputFile -append
				"------------------------"	| Out-File -FilePath $OutputFile -append
				"NUMA Spanning is NOT enabled. Not running the `"Get-VMHostNumaNodeStatus`" ps cmdlet."	| Out-File -FilePath $OutputFile -append
				"`n"	| Out-File -FilePath $OutputFile -append
				"`n"	| Out-File -FilePath $OutputFile -append
				"`n"	| Out-File -FilePath $OutputFile -append
			}

			
			"[info] Hyper-V Switch Configuration section."  | WriteTo-StdOut	
			"===================================================="	| Out-File -FilePath $OutputFile -append
			"Hyper-V Switch Configuration"							| Out-File -FilePath $OutputFile -append	
			"===================================================="	| Out-File -FilePath $OutputFile -append
			"`n"	| Out-File -FilePath $OutputFile -append
			# Hyper-V: Get-VMSwitch
			runPS "Get-VMSwitch *"	-ft 							# W8/WS2012, W8.1/WS2012R2	# ft	
			runPS "Get-VMSwitch * | fl"	-ft 						# W8/WS2012, W8.1/WS2012R2	# ft
			#_#runPS "Get-VMSwitchTeam -SwitchName ""vSwitch"" | fl -Property *" #-ft # W8/WS2012, W8.1/WS2012R2
			runPS "Get-VMSwitchTeam -EA SilentlyContinue | fl -Property *"
			#_#runPS "Get-VMSwitch -Name ""vSwitch"" | Get-VMSwitchExtension | fl -Property *"	#-ft # W8/WS2012, W8.1/WS2012R2
			runPS "Get-VMSwitch | Get-VMSwitchExtension | fl -Property *"
			runPS "Get-VMSystemSwitchExtension | fl -Property *" #-ft # W8/WS2012, W8.1/WS2012R2


			"[info] Hyper-V Network Adapter Configuration section."  | WriteTo-StdOut
			"===================================================="	| Out-File -FilePath $OutputFile -append
			"Hyper-V Network Adapter Configuration"					| Out-File -FilePath $OutputFile -append
			"===================================================="	| Out-File -FilePath $OutputFile -append
			"`n"	| Out-File -FilePath $OutputFile -append
			# Hyper-V: Get-VMNetworkAdapter
			runPS "Get-VMNetworkAdapter -ManagementOS"		-ft # W8/WS2012, W8.1/WS2012R2	# ft
			runPS "Get-VMNetworkAdapter -All"				-ft # W8/WS2012, W8.1/WS2012R2	# ft				
			runPS "Get-VMNetworkAdapter *"					-ft # W8/WS2012, W8.1/WS2012R2	# ft	
			runPS "Get-VMNetworkAdapter * | fl"					# W8/WS2012, W8.1/WS2012R2	# fl
			runPS "Get-VMNetworkAdapter -ManagementOS | fl -Property *"	# W8/WS2012, W8.1/WS2012R2	# fl	


			"[info] Hyper-V Network Virtualization Configuration section."  | WriteTo-StdOut	
			"===================================================="	| Out-File -FilePath $OutputFile -append
			"Hyper-V Network Virtualization Configuration"			| Out-File -FilePath $OutputFile -append
			"===================================================="	| Out-File -FilePath $OutputFile -append		
			"`n"	| Out-File -FilePath $OutputFile -append
			# Hyper-V: Get-NetVirtualization
			runPS "Get-NetVirtualizationCustomerRoute"			# W8/WS2012, W8.1/WS2012R2	# fl
			runPS "Get-NetVirtualizationProviderAddress"		# W8/WS2012, W8.1/WS2012R2	# fl	
			runPS "Get-NetVirtualizationProviderRoute"			# W8/WS2012, W8.1/WS2012R2	# unknown
			runPS "Get-NetVirtualizationLookupRecord"			# W8/WS2012, W8.1/WS2012R2	# fl
			runPS "Get-NetVirtualizationGlobal"					# W8/WS2012, W8.1/WS2012R2	# fl		#Added 4/26/14


			"[info] Hyper-V Network Virtualization Configuration section."  | WriteTo-StdOut	
			"===================================================="	| Out-File -FilePath $OutputFile -append
			"Hyper-V Network Virtualization SCVMM Configuration"	| Out-File -FilePath $OutputFile -append
			"===================================================="	| Out-File -FilePath $OutputFile -append		
			"`n"	| Out-File -FilePath $OutputFile -append

			If (Test-path “HKLM:\SYSTEM\CurrentControlSet\Services\SCVMMService”)
			{
				if ($bn -ge 9600) 
				{
					runPS "Get-SCIPAddress"						# W8.1/WS2012R2	# fl
				}
				else
				{
					"This server is not running WS2012 R2. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append
				}
			}
			else
			{
				"SCVMM is not installed."					| Out-File -FilePath $OutputFile -append
				"Not running the Get-SCIPAddress pscmdlet."	| Out-File -FilePath $OutputFile -append			
			}			
			"`n"	| Out-File -FilePath $OutputFile -append
			"`n"	| Out-File -FilePath $OutputFile -append
			"`n"	| Out-File -FilePath $OutputFile -append
		}
		else
		{
			"This server is not running WS2012 or WS2012 R2. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"The `"Hyper-V Virtual Machine Management`" service is not running. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append
	}
}
else
{
	"The `"Hyper-V Virtual Machine Management`" service does not exist. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append
}


"[info] Hyper-V Network Virtualization Configuration section."  | WriteTo-StdOut	
"===================================================="	| Out-File -FilePath $OutputFile -append
"Hyper-V Network Virtualization NAT Configuration"		| Out-File -FilePath $OutputFile -append
"===================================================="	| Out-File -FilePath $OutputFile -append	
"`n"	| Out-File -FilePath $OutputFile -append
#_#if ($bn -ge 9600)
		#Get role, OSVer, hotfix data. #_#
		$cs =  Get-CimInstance -Namespace "root\cimv2" -class win32_computersystem #-ComputerName $ComputerName #_#
		$DomainRole = $cs.domainrole #_#
if (($bn -ge 9600) -and ($DomainRole -ge 2)) #_# not on Win8+,Win10 client
{
	# Hyper-V: Get-NetVirtualization
	runPS "Get-NetNat"						# W8.1/WS2012R2	# unknown		# Added 4/26/14
	runPS "Get-NetNatGlobal"				# W8.1/WS2012R2	# unknown		# Added 4/26/14
	"---------------------------"			| Out-File -FilePath $OutputFile -append
	"Get-NetNatSession"						| Out-File -FilePath $OutputFile -append
	"---------------------------"			| Out-File -FilePath $OutputFile -append
	"Not running Get-NetNatSession currently because of exception."			| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	#runPS "Get-NetNatSession"				# W8.1/WS2012R2	# unknown		# Added 4/26/14 -> commented out because of exception... Need a check in place.
	runPS "Get-NetNatStaticMapping"			# W8.1/WS2012R2	# unknown		# Added 4/26/14
	runPS "Get-NetNatExternalAddress"		# W8.1/WS2012R2	# unknown		# Added 4/26/14
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
}
else
{
	"The Get-NetNat* powershell cmdlets only run on Server WS2012 R2+. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append
}
CollectFiles -filesToCollect $outputFile -fileDescription "Hyper-V Networking Settings" -SectionDescription $sectionDescription




# SIG # Begin signature block
# MIInsAYJKoZIhvcNAQcCoIInoTCCJ50CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA9PfpT3qHpIyVY
# by+eoHrElOsMxVcMv+8Ds2ZOAiPCg6CCDYUwggYDMIID66ADAgECAhMzAAACzfNk
# v/jUTF1RAAAAAALNMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NjAyWhcNMjMwNTExMjA0NjAyWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDrIzsY62MmKrzergm7Ucnu+DuSHdgzRZVCIGi9CalFrhwtiK+3FIDzlOYbs/zz
# HwuLC3hir55wVgHoaC4liQwQ60wVyR17EZPa4BQ28C5ARlxqftdp3H8RrXWbVyvQ
# aUnBQVZM73XDyGV1oUPZGHGWtgdqtBUd60VjnFPICSf8pnFiit6hvSxH5IVWI0iO
# nfqdXYoPWUtVUMmVqW1yBX0NtbQlSHIU6hlPvo9/uqKvkjFUFA2LbC9AWQbJmH+1
# uM0l4nDSKfCqccvdI5l3zjEk9yUSUmh1IQhDFn+5SL2JmnCF0jZEZ4f5HE7ykDP+
# oiA3Q+fhKCseg+0aEHi+DRPZAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQU0WymH4CP7s1+yQktEwbcLQuR9Zww
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzQ3MDUzMDAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AE7LSuuNObCBWYuttxJAgilXJ92GpyV/fTiyXHZ/9LbzXs/MfKnPwRydlmA2ak0r
# GWLDFh89zAWHFI8t9JLwpd/VRoVE3+WyzTIskdbBnHbf1yjo/+0tpHlnroFJdcDS
# MIsH+T7z3ClY+6WnjSTetpg1Y/pLOLXZpZjYeXQiFwo9G5lzUcSd8YVQNPQAGICl
# 2JRSaCNlzAdIFCF5PNKoXbJtEqDcPZ8oDrM9KdO7TqUE5VqeBe6DggY1sZYnQD+/
# LWlz5D0wCriNgGQ/TWWexMwwnEqlIwfkIcNFxo0QND/6Ya9DTAUykk2SKGSPt0kL
# tHxNEn2GJvcNtfohVY/b0tuyF05eXE3cdtYZbeGoU1xQixPZAlTdtLmeFNly82uB
# VbybAZ4Ut18F//UrugVQ9UUdK1uYmc+2SdRQQCccKwXGOuYgZ1ULW2u5PyfWxzo4
# BR++53OB/tZXQpz4OkgBZeqs9YaYLFfKRlQHVtmQghFHzB5v/WFonxDVlvPxy2go
# a0u9Z+ZlIpvooZRvm6OtXxdAjMBcWBAsnBRr/Oj5s356EDdf2l/sLwLFYE61t+ME
# iNYdy0pXL6gN3DxTVf2qjJxXFkFfjjTisndudHsguEMk8mEtnvwo9fOSKT6oRHhM
# 9sZ4HTg/TTMjUljmN3mBYWAWI5ExdC1inuog0xrKmOWVMIIHejCCBWKgAwIBAgIK
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
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGYEwghl9AgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAALN82S/+NRMXVEAAAAA
# As0wDQYJYIZIAWUDBAIBBQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKsa
# ZzrdyCJzVkPbtk8ume3ssHeEYeF7fMTCIJX8G5tjMEQGCisGAQQBgjcCAQwxNjA0
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQu
# Y29tIDANBgkqhkiG9w0BAQEFAASCAQBrcwqD5fZElwsw0nnT3FHXt0sY9aHMd19k
# aKwZkRKapII8vCXoVIipCV6GMIUnKS2Ztgc5JToGj23E4OYlgmy2rvms4RT26z/Q
# H4DUDGCAE9AYX5wmoSKLBfFd21On4og4tdyjGUeK8Z6eZkUtR7TjzB5KSng5NAZq
# bd1R9Vm+u9m7x9wv632/5lfPnxwIutSSbATn+S99YAILE0uNlGJgq/Iaz+yZsiqC
# B0SsZiVKrXS9ptvXzm0gLDPnraQKsuAEQtLmp9Cm2Hm5gM0ODvtURR+s4gJ6mcp2
# gEioxajRXemOLLc9F0vGy0nY7MqKdinuq2WAZK6yjfYDo10fIpFgoYIXCTCCFwUG
# CisGAQQBgjcDAwExghb1MIIW8QYJKoZIhvcNAQcCoIIW4jCCFt4CAQMxDzANBglg
# hkgBZQMEAgEFADCCAVUGCyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEE
# AYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIC3cEnvslWAO6Tg/OlEvOFeS8YWFn+u7
# Rry9jFgsRjrRAgZjTuuGxJkYEzIwMjIxMDI0MDgxNTE1LjIzNFowBIACAfSggdSk
# gdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNV
# BAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjpEOURFLUUzOUEtNDNGRTElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaCCEVwwggcQMIIE+KADAgECAhMzAAABrGa8hyJd
# 3j17AAEAAAGsMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwMB4XDTIyMDMwMjE4NTEyOVoXDTIzMDUxMTE4NTEyOVowgc4xCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29m
# dCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# TjpEOURFLUUzOUEtNDNGRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMd4C1DFF2Lu
# x3HMK8AElMdTF4iG9ROyKQWFehTXe+EX1QOrTBFnhMAKNHIQWoxkK1W62/oQQQmt
# IHo8sphMt1WpkLNvCm3La8sdVL3t/BAx7UWkmfvujJ3KDaSgt3clc5uNPUj7e32U
# 4n/Ep9oOc+Pv/EHc7XGH1fGRvLRYzwoxP1xkKleusbIzT/aKn6WC2BggPzjHXin9
# KE7kriCuqA+JNhskkedTHJQIotblR+rZcsexTSmjO+Z7R0mfeHiU8DntvZvZ/9ad
# 9XUhDwUJFKZ8ZZvxnqnZXwFYkDKNagY8g06BF1vDulblAs6A4huP1e7ptKFppB1V
# ZkLUAmIW1xxJGs3keidATWIVx22sGVyemaT29NftDp/jRsDw/ahwv1Nkv6Wvykov
# K0kDPIY9TCW9cRbvUeElk++CVM7cIqrl8QY3mgEQ8oi45VzEBXuY04Y1KijbGLYR
# FNUypXMRDApV+kcjG8uST13mSCf2iMhWRRLz9/jyIwe7lmXz4zUyYckr+2Nm8GrS
# q5fVAPshIO8Ab/aOo6/oe3G3Y+cil8iyRJLJNxbMYxiQJKZvbxlCIp+pGInaD137
# 3M7KPPF/yXeT4hG0LqXKvelkgtlpzefPrmUVupjYTgeGfupUwFzymSk4JRNO1thR
# B0bDKDIyNMVqEuvV1UxdcricV0ojgeJHAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQU
# WBGfdwTLH0BnSjx8SVqYWsBAjk0wHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacb
# UzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAo
# MSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1w
# JTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggr
# BgEFBQcDCDANBgkqhkiG9w0BAQsFAAOCAgEAedC1AlhVXHCldk8toIzAW9QyITcR
# eyhUps1uD67zCC308fRzYFES/2vMX7o0ObJgzCxT1ni0vkcs8WG2MUIsk91RCPIe
# DzTQItIpj9ZTz9h0tufcKGm3ahknRs1hoV12jRFkcaqXJo1fsyuoKgD+FTT2lOvr
# EsNjJh5wEsi+PB/mVmh/Ja0Vu8jhUJc1hrBUQ5YisQ4N00snZwhOoCePXbdD6HGs
# 1cmsXZbrkT8vNPYV8LnI4lxuJ/YaYS20qQr6Y9DIHFDNYxZbTlsQeXs/KjnhRNdF
# iCGoAcLHWweWeRszh2iUhMfY1/79d7somfjx6ZyJPZOr4fE0UT2l/rBaBTroPpDO
# vpaOsY6E/teLLMfynr6UOQeE4lRiw59siVGyAGqpTBTbdzAFLBFH40ubr7VEldmj
# iHa14EkZxYvcgzKxKqub4yrKafo/j9aUbwLrL2VMHWcpa18Jhv6zIjd01IGkUdj3
# UJ+JKQNAz5eyPyQSZPt9ws8bynodGlM5nYkHBy7rPvj45y+Zz7jrLgjgvZIixGsz
# wqKyKJ47APHxrH8GjCQusbvW9NF4LAYKoZZGj7PwmQA+XmwD5tfUQ0KuzMRFmMpO
# UztiTAgJjQf9TMuc3pYmpFWEr8ksYdwrjrdWYALCXA/IQXEdAisQwj5YzTsh4QxT
# Uq+vRSxs93yB3nIwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0G
# CSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3Jp
# dHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9
# uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZr
# BxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk
# 2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxR
# nOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uD
# RedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGa
# RnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fz
# pk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG
# 4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGU
# lNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLE
# hReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0w
# ggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+
# gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNV
# HSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0l
# BAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0P
# BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9
# lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQu
# Y29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3Js
# MFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJ
# KoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEG
# k5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2
# LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7nd
# n/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSF
# QrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy8
# 7JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8
# x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2f
# pCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz
# /gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQ
# KBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAx
# M328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGby
# oYICzzCCAjgCAQEwgfyhgdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0
# byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpEOURFLUUzOUEtNDNGRTEl
# MCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsO
# AwIaAxUAsRrSE7C4sEn96AMhjNkXZ0Y1iqCggYMwgYCkfjB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOcAqiQwIhgPMjAyMjEw
# MjQxMDA3MzJaGA8yMDIyMTAyNTEwMDczMlowdDA6BgorBgEEAYRZCgQBMSwwKjAK
# AgUA5wCqJAIBADAHAgEAAgIE3zAHAgEAAgIRmjAKAgUA5wH7pAIBADA2BgorBgEE
# AYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYag
# MA0GCSqGSIb3DQEBBQUAA4GBAJcrREwWmhX7CgzuIp2HDqYPuNNBEe+unQlNRcCz
# 3X0yURbmv5UW7am+FcD7kYSXwigaBGRJgi4YMZkclBieXCswk03tFrYCR3aQqtIZ
# LNxG13vD7JciOuqYGJ/K1Y0aCtXFKmPZfdEbftfRx6adQ1U3vfY26WvyU+vR1Ffn
# eLLkMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAC
# EzMAAAGsZryHIl3ePXsAAQAAAawwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3
# DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgB67JzURidvrcB/31
# HHCx9qUC1sjw9xHmeJt1yMjFVygwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9
# BCD5twGSgzgvCXEAcrVz56m79Pp+bQJf+0+Lg2faBCzC9TCBmDCBgKR+MHwxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABrGa8hyJd3j17AAEAAAGsMCIE
# IB7LlPpzd8fBxGq/PdBguer8lxxNGs52fB4DRsIG7q0bMA0GCSqGSIb3DQEBCwUA
# BIICAKdd66QN92Be7ySV4FjJUTHwEmLm61FB6uagQvxeUixS+GSuAv1kstUWTJ1x
# NSoKjgngL/0TGT7G07n088SYDvZ5Rn722xD80V4vJU9RkqahgIcjPeGyUS1fl88f
# iIXlhSyVISOmwMH8Nm1nXx+W3T3NglPuOnJnBoFKItCu8+6iS1soM178U11EP9Ii
# 9fNfoSiwsf5zqVWaWq4k2PsYXgqoryDM2VOKATx8ejsa0BvwzLRm8nLe7M8dFUEi
# xqXgtz8BYeeVHEfRWq6u009K+1m8LILCRjZqlpMXMgkeQcwS5rwz06tpkYACYH5W
# gtqvwLcRfvZHS42Ggtde3dUo6qmYV4eASYPqG1efSN+6x5kohswtnhZ1clyiri5m
# zVIwJr71WmI41Lics9Qt7DvywFRajV8DIQjL1VdjsIC8x8vIJsPHPHig7hCECLZi
# RUN+ZioBiCUYjT22MSYjN/3yeHOslxMM+lIvJRJ1jlfxzTcoSL/hye/KrNvNYGuz
# RNFmr+LqlS84aGBGpuO13KrzEKLLkJAhdWC42a3o7fS1ytvcfD3DP00mPK+zQGFY
# 4yZZU3+zxL9YTJNlmfS4QaPT0LHrW1Uzf4TtVrtJZIUMRk5dyUaN4Gf7DCb6jfEJ
# aYlkNG0FSQbHBZp2NKzFCM5zYp/jTCFbjDu4zc3pyj5HFJEY
# SIG # End signature block
