#************************************************
# DC_HyperVNetworkVirtualization.ps1
# Version 1.0
# Date: May 2014
# Author:  Boyd Benson (bbenson@microsoft.com) with assistance from Tim Quinn (tiquinn@microsoft.com)
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
		 # later use return to return the exception message to an object:   return $Script:ExceptionMessage
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



$sectionDescription = "Hyper-V Networking Virtualization"

# detect OS version and SKU
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber

$outputFile = $Computername + "_HyperVNetworking_HNV.TXT"


"===================================================="	| Out-File -FilePath $OutputFile -append
"Hyper-V Networking Virtualization Settings"			| Out-File -FilePath $OutputFile -append
"===================================================="	| Out-File -FilePath $OutputFile -append
"Overview"												| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
"Hyper-V Network Virtualization Configuration"			| Out-File -FilePath $OutputFile -append
"  1. Overview stats"									| Out-File -FilePath $OutputFile -append
"       Number of VMs"									| Out-File -FilePath $OutputFile -append
"       Number of VM Network Adapters"					| Out-File -FilePath $OutputFile -append
"       Number of Virtual Switches"						| Out-File -FilePath $OutputFile -append
"       Number of NVLookupRecords"						| Out-File -FilePath $OutputFile -append
"  2. HNV Hierarchical View"							| Out-File -FilePath $OutputFile -append
"       RoutingDomainID / VirtualSubnetID / VMs"		| Out-File -FilePath $OutputFile -append
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
			"===================================================="	| Out-File -FilePath $OutputFile -append
			"Stats:"	| Out-File -FilePath $OutputFile -append
			"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
			
			# How many Virtual Machines?
			$vms = Get-VM
			$vmsCount = $vms.length
			"Number of VMs               : " + $vmsCount	| Out-File -FilePath $OutputFile -append

			# How many Virtual Network Adapters?
			$vmNetworkAdapters = get-vmnetworkadapter *
			$vmNetworkAdaptersCount = $vmNetworkAdapters.length
			"Number of VMNetworkAdapters : " + $vmNetworkAdaptersCount	| Out-File -FilePath $OutputFile -append

			# How many Virtual Switches?
			$vmSwitch = get-vmswitch *
			$vmSwitchCount = $vmSwitch.length
			"Number of VMSwitches        : " + $vmSwitchCount	| Out-File -FilePath $OutputFile -append

			# How many Routing Domains (CustomerIDs)?
			# 	Get-NetVirtualizationLookupRecord shows the CustomerID
			#   Get-NetVirtualizationCustomerRoute shows the RoutingDomainID

			$nvLookupRecord = Get-NetVirtualizationLookupRecord
			$nvLookupRecordCount = $nvLookupRecord.length
			"Number of NVLookupRecords   : " + $nvLookupRecordCount		| Out-File -FilePath $OutputFile -append	
			"`n" | Out-File -FilePath $OutputFile -append
			"`n" | Out-File -FilePath $OutputFile -append
			"`n" | Out-File -FilePath $OutputFile -append

			[array]$nvLrCustomerIdsAll = @()
			[array]$nvLrVirtualSubnetIdsAll = @()
			[array]$nvLrProviderAddressesAll = @()
			[array]$nvLrCustomerAddressesAll = @()
			foreach ($lookupRecord in $nvLookupRecord)
			{
				$nvLrCustomerIdsAll       = $nvLrCustomerIdsAll       + $lookupRecord.CustomerID		# example: CustomerID      : {066ADA42-D48D-4104-937F-6FDCFF48B4AB}
				$nvLrVirtualSubnetIdsAll  = $nvLrVirtualSubnetIdsAll  + $lookupRecord.VirtualSubnetID	# example: VirtualSubnetID : 641590
				$nvLrProviderAddressesAll = $nvLrProviderAddressesAll + $lookupRecord.ProviderAddress
				$nvLrCustomerAddressesAll = $nvLrCustomerAddressesAll + $lookupRecord.CustomerAddress
			}

			# find unique values
			#$nvLrCustomerIds       = $nvLrCustomerIdsAll | Sort-Object | Get-Unique	
			#$nvLrVirtualSubnetIds  = $nvLrVirtualSubnetIdsAll | Sort-Object | Get-Unique
			$nvLrProviderAddresses = $nvLrProviderAddressesAll | Sort-Object | Get-Unique
			#$nvLrCustomerAddresses = $nvLrCustomerAddressesAll | Sort-Object | Get-Unique

			#$nvLrCustomerIdsCount       = $nvLrCustomerIds.length
			#$nvLrVirtualSubnetIdsCount  = $nvLrVirtualSubnetIds.length
			#$nvLrProviderAddressesCount = $nvLrProviderAddresses.length
			#$nvLrCustomerAddressesCount = $nvLrCustomerAddresses.length
			
			# How many CustomerRoutes are there?
			$nvCustomerRoute = Get-NetVirtualizationCustomerRoute
			$nvCustomerRouteCount = $nvCustomerRoute.length
			[array]$nvCrRoutingDomainIdsAll = @()
			[array]$nvCrVirtualSubnetIdsAll = @()
			foreach ($customerRoute in $nvCustomerRoute)
			{
				$nvCrRoutingDomainIdsAll = $nvCrRoutingDomainIdsAll + $customerRoute.RoutingDomainId
				$nvCrVirtualSubnetIdsAll = $nvCrVirtualSubnetIdsAll + $customerRoute.VirtualSubnetId
			}

			# find unique CustomerIDs
			$nvCrRoutingDomainIds      = $nvCrRoutingDomainIdsAll | Sort-Object | Get-Unique
			$nvCrRoutingDomainIdsCount = $nvCrRoutingDomainIds.length
			# find unique VirtualSubnetIDs
			$nvCrVirtualSubnetIds      = $nvCrVirtualSubnetIdsAll | Sort-Object | Get-Unique
			$nvCrVirtualSubnetIdsCount = $nvCrVirtualSubnetIdsAll.length

			# How many Provider Addresses are there?
			$nvPa  = Get-NetVirtualizationProviderAddress
			$nvPaCount = $nvPa.length
			[array]$nvPaProviderAddressesAll = @()
			foreach ($pa in $nvPa)
			{
				$nvPaProviderAddressesAll = $nvPaProviderAddressesAll + $pa.ProviderAddress
			}
			$nvPaProviderAddresses = $nvPaProviderAddressesAll | Sort-Object | Get-Unique

			# Build an array that contains just the Provider Addresses from other hosts
			# This array contains only PAs from this host: $nvPaProviderAddresses
			# This array contains all PAs in the HNV scenario: $nvLrProviderAddresses

			[array]$nvProviderAddressesOnOtherHosts = @()
			foreach ($lrpa in $nvLrProviderAddresses)
			{
				if ($nvPaProviderAddresses -notcontains $lrpa)
				{
					$nvProviderAddressesOnOtherHosts = $nvProviderAddressesOnOtherHosts + $lrpa
				}
			}


			"===================================================="		| Out-File -FilePath $OutputFile -append
			"HNV Hierarchical View" 									| Out-File -FilePath $OutputFile -append
			"  RoutingDomainID / VirtualSubnetID / VMs"					| Out-File -FilePath $OutputFile -append
			"===================================================="		| Out-File -FilePath $OutputFile -append
			"`n"														| Out-File -FilePath $OutputFile -append

			foreach ($rdid in $nvCrRoutingDomainIds)
			{
				# All of the following output is from the Get-NetVirtualizationCustomerRoute pscmdlet.
				
				# Show the RDID
				"`n"| Out-File -FilePath $OutputFile -append
				"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append	
				"Routing Domain ID        : " + $rdid 					| Out-File -FilePath $OutputFile -append	
				
				# Show the unique VSID(s) for this RDID
					# [array]$nvPaLocalVms = @()		#	$nvPaLocalVms = $nvPaLocalVms + $lr.VMName
					# [array]$nvPaRemoteVms = @()		#	$nvPaRemoteVms = $nvPaRemoteVms + $lr.VMName
				
				foreach ($vsid in $nvCrVirtualSubnetIds)
				{
					foreach ($cr in $nvCustomerRoute)
					{
						if (($rdid -eq $cr.RoutingDomainID) -and ($vsid -eq $cr.VirtualSubnetID))
						{
							"`n" 										| Out-File -FilePath $OutputFile -append	
							"  VirtualSubnetID        :   " + $vsid 	| Out-File -FilePath $OutputFile -append	
							# Show the VMs per VSID [this host]
							foreach ($lr in $nvLookupRecord)
							{
								if ( (($rdid -eq $cr.RoutingDomainID) -and ($vsid -eq $cr.VirtualSubnetID)) -and (($rdid -eq $lr.CustomerID) -and ($vsid -eq $lr.VirtualSubnetID)) )
								{
									# Only show the VMs with ProviderAddresses on this machine (IPs in this array: $nvPaProviderAddresses)
									foreach ($nvPaProviderAddress in $nvPaProviderAddresses)
									{
										if (($lr.ProviderAddress -eq $nvPaProviderAddress)  -and ($lr.VMName -ne "GW") -and ($lr.VMName -ne "GW-External") -and ($lr.VMName -ne "DHCPExt.sys"))
										{
											"      VM [THIS HOST]     :     " + $lr.VMName + " ; " + $lr.CustomerAddress + " ; " + $lr.ProviderAddress 		| Out-File -FilePath $OutputFile -append	
										}
									}						
								}
							}

							# Show the VMs per VSID [other hosts]
							foreach ($lr in $nvLookupRecord)
							{
								if ( (($rdid -eq $cr.RoutingDomainID) -and ($vsid -eq $cr.VirtualSubnetID)) -and (($rdid -eq $lr.CustomerID) -and ($vsid -eq $lr.VirtualSubnetID)) )
								{
									# Only show the VMs with ProviderAddresses on this machine (IPs in this array: $nvPaProviderAddresses)
									foreach ($addr in $nvProviderAddressesOnOtherHosts)
									{
										if (($lr.ProviderAddress -eq $addr) -and ($lr.VMName -ne "GW") -and ($lr.VMName -ne "GW-External") -and ($lr.VMName -ne "DHCPExt.sys"))
										{
											"      VM                 :     " + $lr.VMName + " ; " + $lr.CustomerAddress + " ; " + $lr.ProviderAddress		 | Out-File -FilePath $OutputFile -append	
										}
									}
								}
							}

							foreach ($lr in $nvLookupRecord)
							{
								if ( (($rdid -eq $cr.RoutingDomainID) -and ($vsid -eq $cr.VirtualSubnetID)) -and (($rdid -eq $lr.CustomerID) -and ($vsid -eq $lr.VirtualSubnetID)) )
								{
									# Only show the VMs with ProviderAddresses on this machine (IPs in this array: $nvPaProviderAddresses)
									foreach ($nvPaProviderAddress in $nvPaProviderAddresses)
									{
										if (($lr.ProviderAddress -eq $nvPaProviderAddress) -and ($lr.VMName -eq "GW"))
										{
											"      HNV GW (Internal)  :     " + $lr.VMName + " ; " + $lr.CustomerAddress + " ; " + $lr.ProviderAddress 		| Out-File -FilePath $OutputFile -append	
										}
										if (($lr.ProviderAddress -eq $nvPaProviderAddress) -and ($lr.VMName -eq "GW-External"))
										{
											"      HNV GW (External)  :     " + $lr.VMName + " ; " + $lr.CustomerAddress + " ; " + $lr.ProviderAddress 		| Out-File -FilePath $OutputFile -append	
										}
									}
								}
							}


							# Show the VMs per VSID [other hosts]
							foreach ($lr in $nvLookupRecord)
							{
								if ( (($rdid -eq $cr.RoutingDomainID) -and ($vsid -eq $cr.VirtualSubnetID)) -and (($rdid -eq $lr.CustomerID) -and ($vsid -eq $lr.VirtualSubnetID)) )
								{
									# Only show the VMs with ProviderAddresses on this machine (IPs in this array: $nvPaProviderAddresses)
									foreach ($addr in $nvProviderAddressesOnOtherHosts)
									{
										if (($lr.ProviderAddress -eq $addr) -and ($lr.VMName -eq "GW"))
										{
											"      HNV GW (Internal)  :     " + $lr.VMName + " ; " + $lr.CustomerAddress + " ; " + $lr.ProviderAddress 		| Out-File -FilePath $OutputFile -append	
										}
										if (($lr.ProviderAddress -eq $addr) -and ($lr.VMName -eq "GW-External"))
										{
											"      HNV GW (External)  :     " + $lr.VMName + " ; " + $lr.CustomerAddress + " ; " + $lr.ProviderAddress 		| Out-File -FilePath $OutputFile -append	
										}
									}
								}
							}
							
						}
					}
				}

				"`n" 						| Out-File -FilePath $OutputFile -append	
				"  SCVMM DHCP Server" 		| Out-File -FilePath $OutputFile -append	
				# Show the SCVMM Software DHCP Server
				foreach ($vsid in $nvCrVirtualSubnetIds)
				{
					foreach ($cr in $nvCustomerRoute)
					{
						if (($rdid -eq $cr.RoutingDomainID) -and ($vsid -eq $cr.VirtualSubnetID))
						{
							# Show the HNV Tenant Gateway (Internal)
							foreach ($lr in $nvLookupRecord)
							{
								if ( (($rdid -eq $cr.RoutingDomainID) -and ($vsid -eq $cr.VirtualSubnetID)) -and (($rdid -eq $lr.CustomerID) -and ($vsid -eq $lr.VirtualSubnetID)) )
								{
									if ($lr.VMName -eq "DHCPExt.sys")
									{
										"      SCVMM DHCP Server  :     " + $lr.VMName + " ; " + $lr.CustomerAddress + " ; " + $lr.ProviderAddress 		| Out-File -FilePath $OutputFile -append	
									}
								}
							}
						}
					}
				}	

			}
			"`n"			| Out-File -FilePath $OutputFile -append
			"`n"			| Out-File -FilePath $OutputFile -append
			"`n"			| Out-File -FilePath $OutputFile -append
			
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

CollectFiles -filesToCollect $outputFile -fileDescription "Hyper-V Networking Settings" -SectionDescription $sectionDescription


# SIG # Begin signature block
# MIInrQYJKoZIhvcNAQcCoIInnjCCJ5oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA6tQGN32CWR13D
# hh9bsxCPKhc+dOFR3Oxqz0iOMu9ZzqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEICI4ARdWq2a59YcdmCx8cDoe
# 31vJ98z89JmlbSJ6InZ+MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCACKtm+Nu3+lX7GzeCIbEnboIkiWGr3Nvpr6op7P5WQSYBYD2bUH5p
# pbqV61xY3jzJGyOIoRLo1v3nigtL6h5DvXBGC+KVJZsQGxrpT6CGSZojTjUXzJPr
# WphsVavpb/6p1ZdItCJZ4LQWWjdIYOqIRIUYjJ9UZYEBDQHxZAB6VUMrhoqPEMew
# 9xlcZ+9nVr3bUkydt5KCIenMEu9NlJBlQjxpjBCpsckNy7Hoa2aKXcQXNco0Ylf1
# hGO2ba/VZWAF4RxFyFfzGlgFecW89YHL2UzTxauTCfIk2USBdddVBpl0297xTeb4
# U0k1I8vNjQ6OjzLAC35IC3xxzKw3N6jcoYIXFTCCFxEGCisGAQQBgjcDAwExghcB
# MIIW/QYJKoZIhvcNAQcCoIIW7jCCFuoCAQMxDzANBglghkgBZQMEAgEFADCCAVgG
# CyqGSIb3DQEJEAEEoIIBRwSCAUMwggE/AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIL9vmFVEyGBnuZsHurjzmbk5Z+0nWzNKSIcPp3mMGMbdAgZi3mQf
# GgEYEjIwMjIwODAxMDc0MDQxLjIzWjAEgAIB9KCB2KSB1TCB0jELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IEly
# ZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# Tjo4NkRGLTRCQkMtOTMzNTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaCCEWUwggcUMIIE/KADAgECAhMzAAABjAGXYkc2dmY7AAEAAAGMMA0G
# CSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIx
# MTAyODE5Mjc0NFoXDTIzMDEyNjE5Mjc0NFowgdIxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9w
# ZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046ODZERi00
# QkJDLTkzMzUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDTSGhMoRP5IaxrLD70EV2b
# 65n6S8Q8Yt3mwXxeVPdTLhgapPzr4OvwbeTqr+VFqCLFEq+f6DYAVEv1W5moLW5O
# 9rt1k30KGKi0ccWbLJBk9qVd0lMLycoituBMxcDCH+ZuGeahrGwj2MaWK9iCLkY0
# 4Tu7pNXhQ62dU/yKiFNR80wqFlol3OZYOOFYLsuM9ciFqb1CFGRXOuTF8kpzn0Cx
# oYPc++JGSAegbF+l1Yc89pbyKIQeNzg8OYIqW5bcn4h1Tfwf4yQo+Z6QLsa1FMtc
# oEK5YpdLxONlj/CQ1zNY0Sj6Xknc5l0d5WKDGnMKd6yRl9wdfGsJfaG57uom9auS
# wVK2Rls4bshiZp9gxCtka6WXvY+dLWgh1B1idHn+eBy9JBvXUZDSQ0wPOIqxJ37m
# J9RphsktnRcTE1XiotcJLrkOP7wXKAKO02+QOIHkez0jsr3PFmxRvt8opIYRn3ID
# QmBNZtwA8Jg+24AdUnxQppP3rukmbv6veGBx7fxVTf2yl54ceBoJLi9et6VMuJQw
# CXQ62TmdwpApzaQae+7A/ZEJLeQQQUDGifAufynJ53Kt5lNsExAGp/WjeSPSKU4n
# v9/8/dzWudpg7TUYMmia/ui2lvnP7WGtKgizy77p6u4koJOKF3SL/xtzrsAoXvrC
# la69b0GFtQxOxaTDDivjZwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFJbOU4apgiFg
# iHlWnT6Iyt1Ai1IjMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8G
# A1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBs
# BggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# DQYJKoZIhvcNAQELBQADggIBANdoxUVYwgmp1uVBkrqiSztx0JTB48CaYQh52zK6
# yBQwhCVCpqN8I/2IbnzI4VJHHaTn2PaEAFJkHEWZuRWPCFgQLXIk9Cb3jriBTPkb
# 645bnWLy5554HeHaL4OahY0o1K6Ug3J9IaBbo8IMKJGo7eqfwphXMvOh6Z8+Kv9R
# XHkICBVwQMAy3FtGtMdcEAFfIJrppDf6O6RYHlpDMvDqqEeHPscg5T2r9D1jY2dU
# Eo9/MiXA+NvY2tAZ9CddOyx8UP3w6lEerTtlTHbWDimzxXfeFJKQna4PCG2nlW0U
# acX4DHMUGUK9zfcs9OZexzOXLr7JCABHCY0d40DbrZaosskzzgjPw5LVV8TU3rJg
# KQuODzX7MZeyO8waaMGWLLFnBdYZYmayi8HpPqHUat+a8wq504T3YPrtJHfNPcN0
# DknAv1MDNfxSGLRoZi2fm41QMVvEijMhEyktWk/9g4ueD6va/yzyXJa/Rp+PBlgc
# EnrgxZU3Edxo22PORi1CN1nluHKRrp1f4O1AP1uHfOOLRKWt9UMgvERvo6PKq18a
# PuJZm8mtvgCohWAdBoPOC6LERL2J60WKQd9/qn3sLmqhtNNsrA3QAQ/erm17Ij00
# g5WUmXSCLkht3nweJ/cks7q+n7nIdeOhIv8yWEWa8a1piZDAPsrNOb24AMXgHM/+
# bHa/MIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0B
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
# dGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4NkRGLTRCQkMtOTMzNTElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIa
# AxUANKLyFOur9DyimnB4bK5ks0Qmr9WggYMwgYCkfjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOaRdCcwIhgPMjAyMjA4MDEw
# NTM1MzVaGA8yMDIyMDgwMjA1MzUzNVowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA
# 5pF0JwIBADAHAgEAAgIYzTAHAgEAAgIRTzAKAgUA5pLFpwIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBBQUAA4GBAIixj0vL7or1L1KGnihFKgtYnTRdFMupQfRgruUqhtbx
# 5Z8iuml1Y4h/gfsGdag7T+0wkkeB5KsmKxLq+ct+VE7/jIn86IbLq1zGhNk995Ir
# mr8Xg0Qhug0sIOFbxHEFMAjgeivm0QDhjgF0aZmX77dOXLtrLCWIt9T+qJUm8qJW
# MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGMAZdiRzZ2ZjsAAQAAAYwwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgEYieT1ySes3od5TK5qP3
# C5FKRzGCk9J2FpM7hCc0K7kwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCDV
# rYv4FSqQzwZ/xOYhBZ2B4pNOthcjA6h864mIGJhpnjCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABjAGXYkc2dmY7AAEAAAGMMCIEIFh4
# LgsRK0rJGiBZgJKvLMFw4SuKTNcYZWLZGwju1hbDMA0GCSqGSIb3DQEBCwUABIIC
# AMing97kMjybVU0tHiFCOxVdA0ttQ439UHauI/dmXNB0ulSzFDNWxDsvdKS/0b3T
# ckG7xDHZMb9nuTF8o937Nkw2AmAK4C/aOgNBQfYsv/V3nAf3pEALRvSnpgFVEw7d
# 2xbDv//4fl3GoOXgyIFd7aYYi/1s+wtkXu3vP0AhJXY/DFBtML79a+qCOoAfyBEs
# O6y5C5KrM7f6eOWA04AAyKX8AntsOoPTa2J82IkhTwVlzz0mm4qZoOfvp8GGf1NT
# oJmIUcX2n5ZyO+ekEZkTRnDtcIM0/sKtQJczoKLqQKIe3ZhURXOvuP3RetZhedmV
# bNM/YH1d0Xr584kaGIRiWC1Pc3xGhz9V7h/rGq9lqNys4EoU+7nyVRrjtYCODKEd
# +LmA6LDSA5aajKBE5SV74IYlvTehga8AYsu9dlVa+nT2XduGGAR7p27HCSkbruo4
# 08WONTQN84cPBuUXVw1qTtCVPrlXQsYzMGn1Xy0d2H9zVhp6BAh7ajbdRfFBsXHf
# egmr2XoBsQIlh4Ln/TQd7UrX6PQI6qeEa+aNh3m7Ws0uc/NoiRH8Jme3whnWs9+F
# HP4LWQisi3JhOQVitPxRyJe8R3ExQnPoA0uUEKzJFMiABzHLYY8moiP2boVIpESr
# hVTJC/3ByRD7orBx/uX3Fy2ey8Sj35c43mHW983eW8jU
# SIG # End signature block
