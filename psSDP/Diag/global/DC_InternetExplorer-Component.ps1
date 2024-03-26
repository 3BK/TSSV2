#***************************************************
# DC_InternetExplorer-Component.ps1
# Version 1.0: HKCU and HKLM locations
# Version 1.1.06.07.13: Added "HKU\.DEFAULT" and "HKU\S-1-5-18" locations. [suggestion:johnfern]
# Version 1.2.07.30.14: Added the parsed output of Trusted Sites and Local Intranet to the new _InternetExplorer_Zones.TXT [suggestion:waltere]
# Version 1.3.08.23.14: Added Protected Mode detection for IE Zones. [suggestion:edb]  TFS264121
# Version 1.4.09.04.14: Fixed exception. Corrected syntax for reading registry value by adding "-ErrorAction SilentlyContinue"
# Date: 2009-2014,2022-11-29,2023-02-04
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: Collects information about Internet Explorer (IE)
# Called from: Networking Diagnostics
#****************************************************

Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}

$sectionDescription = "Internet Explorer"
	
Import-LocalizedData -BindingVariable ScriptVariable
Write-DiagProgress -Activity $ScriptVariable.ID_CTSInternetExplorer -Status $ScriptVariable.ID_CTSInternetExplorerDescription

#----------Registry
$OutputFile= $Computername + "_InternetExplorer_reg_output.TXT"
$CurrentVersionKeys =	"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
						"HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
						"HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
						"HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -OutputFile $OutputFile -fileDescription "Internet Explorer registry output" -SectionDescription $sectionDescription

$isServerSku = (Get-CimInstance -Class Win32_ComputerSystem).DomainRole -gt 1
$OutputFile= $Computername + "_InternetExplorer_Zones.TXT"

"===================================================="	| Out-File -FilePath $OutputFile -append
"Internet Explorer Zone Information"					| Out-File -FilePath $OutputFile -append
"===================================================="	| Out-File -FilePath $OutputFile -append
"Overview"												| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
"   1. IE Enhanced Security Configuration (IE ESC) [Server SKU Only]"		| Out-File -FilePath $OutputFile -append
"   2. IE Protected Mode Configuration for each IE Zone"	| Out-File -FilePath $outputFile -append
"   3. List of Sites in IE Zone2 `"Trusted Sites`""		| Out-File -FilePath $OutputFile -append
"   4. List of Sites in IE Zone1 `"Local Intranet`""	| Out-File -FilePath $OutputFile -append
"===================================================="	| Out-File -FilePath $OutputFile -append
"`n`n`n`n`n"	| Out-File -FilePath $OutputFile -append

"====================================================" 	| Out-File -FilePath $outputFile -append
"IE Enhanced Security Configuration (ESC) [Server SKU Only]" 				| Out-File -FilePath $outputFile -append
"====================================================" 	| Out-File -FilePath $outputFile -append
#detect if IE ESC is enabled/disabled for user/admin
if ($isServerSku -eq $true){
	"`n" | Out-File -FilePath $outputFile -append
	# IE ESC is only used on Server SKUs.
	# Detecting if IE Enhanced Security Configuration is Enabled or Disabled
	#  regkey  : HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}
	#  regvalue: IsInstalled
	$regkey="HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
	$adminIEESC = (Get-ItemProperty -path $regkey).IsInstalled
	if ($adminIEESC -eq '0'){
		"IE ESC is DISABLED for Admin users." | Out-File -FilePath $outputFile -append
	}
	else{
		"IE ESC is ENABLED for Admin users." | Out-File -FilePath $outputFile -append
	}
	#user
	#  regkey  : HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}
	#  regvalue: IsInstalled
	$regkey= "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
	$userIEESC=(Get-ItemProperty -path $regkey).IsInstalled
	if ($userIEESC -eq '0'){
		"IE ESC is DISABLED for non-Admin users." | Out-File -FilePath $outputFile -append
	}
	else{
		"IE ESC is ENABLED for non-Admin users." | Out-File -FilePath $outputFile -append
	}
	"`n`n`n" | Out-File -FilePath $outputFile -append
}
else{
	"IE ESC is only used on Server SKUs. Not checking status." | Out-File -FilePath $outputFile -append
	"`n`n`n" | Out-File -FilePath $outputFile -append
}

#added this section 08.23.14
"====================================================" 	| Out-File -FilePath $outputFile -append
"IE Protected Mode Configuration for each IE Zone" 		| Out-File -FilePath $outputFile -append
"====================================================" 	| Out-File -FilePath $outputFile -append
$zone0 = "Computer"
$zone1 = "Local intranet"
$zone2 = "Trusted sites"
$zone3 = "Internet"
$zone4 = "Restricted sites"
$regkeyZonesHKCU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones"
If(Test-Path $regkeyZonesHKCU){
	$zonesHKCU = Get-ChildItem -path $regkeyZonesHKCU
}
$regkeyZonesHKLM = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones"
If(Test-Path $regkeyZonesHKLM){
	$zonesHKLM = Get-ChildItem -path $regkeyZonesHKLM
}

# Regvalue 2500 exists by default in HKLM in each zone, but may not exist in HKCU.
for($i=0;$i -le 4;$i++)
{
	if ($i -eq 0) {"IE Protected Mode for Zone0 `"$zone0`":" 	| Out-File -FilePath $outputFile -append }
	if ($i -eq 1) {"IE Protected Mode for Zone1 `"$zone1`":" 	| Out-File -FilePath $outputFile -append }
	if ($i -eq 2) {"IE Protected Mode for Zone2 `"$zone2`":" 	| Out-File -FilePath $outputFile -append }
	if ($i -eq 3) {"IE Protected Mode for Zone3 `"$zone3`":" 	| Out-File -FilePath $outputFile -append }
	if ($i -eq 4) {"IE Protected Mode for Zone4 `"$zone4`":" 	| Out-File -FilePath $outputFile -append }
	$regkeyZoneHKCU = join-path $regkeyZonesHKCU $i
	$regkeyZoneHKLM = join-path $regkeyZonesHKLM $i
	$regvalueHKCU2500Enabled = $false
	$regvalueHKLM2500Enabled = $false

	If (test-path $regkeyZoneHKCU){
		#Moved away from this since it exceptions on W7/WS2008R2:   $regvalueHKCU2500 = (Get-ItemProperty -path $regkeyZoneHKCU).2500
		$regvalueHKCU2500 = Get-ItemProperty -path $regkeyZoneHKCU -name "2500" -ErrorAction SilentlyContinue		
		if ($regvalueHKCU2500 -eq 0){
			#"IE Protected Mode is ENABLED in HKCU. (RegValue 2500 is set to 0.)"
			$regvalueHKCU2500Enabled = $true
		}
		if ($regvalueHKCU2500 -eq 3){
			#"IE Protected Mode is DISABLED in HKCU. (RegValue 2500 is set to 3.)"
			$regvalueHKCU2500Enabled = $false
		}
	}
	If (test-path $regkeyZoneHKLM){
		#Moved away from this since it exceptions on W7/WS2008R2:   $regvalueHKCU2500 = (Get-ItemProperty -path $regkeyZoneHKLM).2500
		$regvalueHKLM2500 = Get-ItemProperty -path $regkeyZoneHKLM -name "2500" -ErrorAction SilentlyContinue
		if ($regvalueHKLM2500 -eq 0){
			#"IE Protected Mode is ENABLED in HKCU. (RegValue 2500 is set to 0.)"
			$regvalueHKLM2500Enabled = $true
		}
		if ($regvalueHKLM2500 -eq 3){
			#"IE Protected Mode is DISABLED in HKCU. (RegValue 2500 is set to 3.)"
			$regvalueHKLM2500Enabled = $false
		}
	}

	If (($regvalueHKCU2500Enabled -eq $true) -and ($regvalueHKLM2500Enabled -eq $true)){
		"  ENABLED (HKCU:enabled; HKLM:enabled)" 	| Out-File -FilePath $outputFile -append
		"`n" | Out-File -FilePath $outputFile -append
	}
	elseif (($regvalueHKCU2500Enabled -eq $true) -and ($regvalueHKLM2500Enabled -eq $false)){
		"  DISABLED (HKCU:enabled; HKLM:disabled)" 	| Out-File -FilePath $outputFile -append
		"`n" | Out-File -FilePath $outputFile -append
	}
	elseif (($regvalueHKCU2500Enabled -eq $false) -and ($regvalueHKLM2500Enabled -eq $true)){
		"  ENABLED (HKCU:disabled; HKLM:enabled)" 	| Out-File -FilePath $outputFile -append
		"`n" | Out-File -FilePath $outputFile -append
	}
	elseif (($regvalueHKCU2500Enabled -eq $false) -and ($regvalueHKLM2500Enabled -eq $false)){
		"  DISABLED (HKCU:disabled; HKLM:disabled)" 	| Out-File -FilePath $outputFile -append
		"`n" | Out-File -FilePath $outputFile -append
	}
}
"`n`n`n" | Out-File -FilePath $outputFile -append


#Build an array with all registry subkeys of $regkey 
$regkeyZoneMapDomains = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains"
$regkeyZoneMapEscDomains = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains"
If($regkeyZoneMapDomains) {
	$zoneMapDomains = Get-ChildItem -path $regkeyZoneMapDomains
	#$zoneMapDomainsLength = $zoneMapDomains.length
}

# Creating psobjects
$ieZoneMapDomainsObj = New-Object psobject
$ieZoneMapEscDomainsObj = New-Object psobject
$ieDomainsTrustedSitesObj = New-Object psobject
$ieEscDomainsTrustedSitesObj = New-Object psobject
$ieDomainLocalIntranetObj = New-Object psobject
$ieEscDomainLocalIntranetObj = New-Object psobject

#Loop through each domain and determine what Zone the domain is in using http or https regvalues
$domainCount=0
$trustedSiteCount=0
$localIntranetCount=0
foreach ($domain in $zoneMapDomains){
	$domainCount++
	$domainName = $domain.PSChildName
	
	# Add all domains to $ieZoneMapDomainsObj
	Add-Member -InputObject $ieZoneMapDomainsObj -MemberType NoteProperty -Name "Domain$domainCount" -Value $domainName

	$domainRegkey = $regkeyZoneMapDomains + '\' + $domainName
	$domainHttp     = (Get-ItemProperty -path "$domainRegkey").http
	$domainHttps    = (Get-ItemProperty -path "$domainRegkey").https
	$domainSubkeys = Get-ChildItem -path $domainRegkey

	if ($domain.SubKeyCount -ge 1){
		foreach ($subkey in $domainSubkeys){
			$subkeyName = $subkey.PSChildName
			$domainRegkey = $regkeyZoneMapDomains + '\' + $domainName + '\' + $subkeyName
			$fullDomainName = $subkeyName + "." + $domainName
			$domainHttp     = (Get-ItemProperty -path "$domainRegkey").http
			$domainHttps    = (Get-ItemProperty -path "$domainRegkey").https

			if ($domainHttp -eq 2){
				$trustedSiteCount++
				# Add trusted sites to the $ieDomainsTrustedSitesObj
				Add-Member -InputObject $ieDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTP" -Value $fullDomainName
			}			
			if ($domainHttps -eq 2){
				$trustedSiteCount++
				# Add trusted sites to the $ieDomainsTrustedSitesObj
				Add-Member -InputObject $ieDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTPS" -Value $fullDomainName	
			}

			if ($domainHttp -eq 1){
				$localIntranetCount++
				# Add Local Intranet to the $ieDomainLocalIntranetObj
				Add-Member -InputObject $ieDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTP" -Value $fullDomainName	
			}
			if ($domainHttps -eq 1){
				$localIntranetCount++
				# Add Local Intranet to the $ieDomainLocalIntranetObj
				Add-Member -InputObject $ieDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTPS" -Value $fullDomainName	
			}
		}
	}
	else
	{
		$fullDomainName = $domainName
		$domainHttp     = (Get-ItemProperty -path "$domainRegkey").http
		$domainHttps    = (Get-ItemProperty -path "$domainRegkey").https
		
		if ($domainHttp -eq 2){
			$trustedSiteCount++
			# Add trusted sites to the $ieDomainsTrustedSitesObj
			Add-Member -InputObject $ieDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTP" -Value $fullDomainName				
		}
		if ($domainHttps -eq 2){
			$trustedSiteCount++
			# Add trusted sites to the $ieDomainsTrustedSitesObj
			Add-Member -InputObject $ieDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTPS" -Value $fullDomainName		
		}

		if ($domainHttp -eq 1){
			$localIntranetCount++
			# Add Local Intranet to the $ieDomainLocalIntranetObj
			Add-Member -InputObject $ieDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTP" -Value $fullDomainName	
		}
		if ($domainHttps -eq 1){
			$localIntranetCount++
			# Add Local Intranet to the $ieDomainLocalIntranetObj
			Add-Member -InputObject $ieDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTPS" -Value $fullDomainName	
		}	
	}
}

if ($isServerSku -eq $true){
	#Loop through each domain and determine what Zone the domain is in using http or https regvalues
	$zoneMapEscDomains = Get-ChildItem -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains" -ErrorAction SilentlyContinue
	#$zoneMapEscDomainsLength = $zoneMapEscDomains.length

	$escDomainCount=0
	$trustedSiteCount=0
	$localIntranetCount=0
	if($null -ne $zoneMapEscDomains){ #_#
		foreach ($domain in $zoneMapEscDomains){
			$escDomainCount++
			$domainName = $domain.PSChildName

			# Add domains to $ieZoneMapEscDomainsObj
			Add-Member -InputObject $ieZoneMapEscDomainsObj -MemberType NoteProperty -Name "EscDomain$escDomainCount" -Value $domainName

			$domainRegkey = $regkeyZoneMapEscDomains + '\' + $domainName
			$domainHttp     = (Get-ItemProperty -path "$domainRegkey" -ErrorAction Ignore).http
			$domainHttps    = (Get-ItemProperty -path "$domainRegkey" -ErrorAction Ignore).https
			$domainSubkeys = Get-ChildItem -path $domainRegkey -ErrorAction Ignore

			if ($domain.SubKeyCount -ge 1){
				foreach ($subkey in $domainSubkeys){
					$subkeyName = $subkey.PSChildName
					$domainRegkey = $regkeyZoneMapEscDomains + '\' + $domainName + '\' + $subkeyName
					$fullDomainName = $subkeyName + "." + $domainName
					$domainHttp     = (Get-ItemProperty -path "$domainRegkey" -ErrorAction Ignore).http
					$domainHttps    = (Get-ItemProperty -path "$domainRegkey" -ErrorAction Ignore).https

					if ($domainHttp -eq 2){
						$trustedSiteCount++
						# Add trusted sites to the $ieEscDomainsTrustedSitesObj
						Add-Member -InputObject $ieEscDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTP" -Value $fullDomainName
					}
					if ($domainHttps -eq 2){
						$trustedSiteCount++
						# Add trusted sites to the $ieEscDomainsTrustedSitesObj
						Add-Member -InputObject $ieEscDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTPS" -Value $fullDomainName
					}

					if ($domainHttp -eq 1){
						$localIntranetCount++
						# Add Local Intranet to the $ieEscDomainLocalIntranetObj
						Add-Member -InputObject $ieEscDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTP" -Value $fullDomainName	
					}
					if ($domainHttps -eq 1){
						$localIntranetCount++
						# Add Local Intranet to the $ieEscDomainLocalIntranetObj
						Add-Member -InputObject $ieEscDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTPS" -Value $fullDomainName	
					}		
				}
			}
			else{
				$fullDomainName = $domainName
				$domainHttp     = (Get-ItemProperty -path "$domainRegkey" -ErrorAction Ignore).http
				$domainHttps    = (Get-ItemProperty -path "$domainRegkey" -ErrorAction Ignore).https
				
				if ($domainHttp -eq 2){
					$trustedSiteCount++
					# Add trusted sites to the $ieEscDomainsTrustedSitesObj
					Add-Member -InputObject $ieEscDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTP" -Value $fullDomainName	
				}
				if ($domainHttps -eq 2){
					$trustedSiteCount++
					# Add trusted sites to the $ieEscDomainsTrustedSitesObj
					Add-Member -InputObject $ieEscDomainsTrustedSitesObj -MemberType NoteProperty -Name "Website$trustedSiteCount`t: HTTPS" -Value $fullDomainName	
				}

				if ($domainHttp -eq 1){
					$localIntranetCount++
					# Add Local Intranet to the $ieEscDomainLocalIntranetObj
					Add-Member -InputObject $ieEscDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTP" -Value $fullDomainName	
				}
				if ($domainHttps -eq 1){
					$localIntranetCount++
					# Add Local Intranet to the $ieEscDomainLocalIntranetObj
					Add-Member -InputObject $ieEscDomainLocalIntranetObj -MemberType NoteProperty -Name "Website$localIntranetCount`t: HTTPS" -Value $fullDomainName	
				}		
			}
		}
	}
}

"====================================================" 				| Out-File -FilePath $outputFile -append
"List of Sites in IE Zone2 `"Trusted Sites`""						| Out-File -FilePath $outputFile -append
"====================================================" 				| Out-File -FilePath $outputFile -append
if ($isServerSku -eq $true)
{
	"--------------------" 											| Out-File -FilePath $outputFile -append
	"[ZoneMap\Domains registry location]" 							| Out-File -FilePath $outputFile -append
	  "Used when IE Enhanced Security Configuration is Disabled" 	| Out-File -FilePath $outputFile -append
	"--------------------" 											| Out-File -FilePath $outputFile -append
	$ieDomainsTrustedSitesObj | Format-List							| Out-File -FilePath $outputFile -append
	"`n`n`n" 														| Out-File -FilePath $outputFile -append
	"--------------------" 											| Out-File -FilePath $outputFile -append
	"[ZoneMap\EscDomains registry location]" 						| Out-File -FilePath $outputFile -append
	"Used when IE Enhanced Security Configuration is Enabled" 		| Out-File -FilePath $outputFile -append
	"--------------------" 											| Out-File -FilePath $outputFile -append
	$ieEscDomainsTrustedSitesObj | Format-List						| Out-File -FilePath $outputFile -append
}
else
{
	"--------------------" 											| Out-File -FilePath $outputFile -append
	"[ZoneMap\Domains registry location]" 							| Out-File -FilePath $outputFile -append
	"--------------------" 											| Out-File -FilePath $outputFile -append
	$ieDomainsTrustedSitesObj | Format-List							| Out-File -FilePath $outputFile -append
}
"`n`n`n" | Out-File -FilePath $outputFile -append

"===================================================="				| Out-File -FilePath $outputFile -append
"List of Sites in IE Zone1 `"Local Intranet`"" 						| Out-File -FilePath $outputFile -append
"===================================================="				| Out-File -FilePath $outputFile -append
if ($isServerSku -eq $true){
	"--------------------" 										| Out-File -FilePath $outputFile -append
	"[ZoneMap\Domains registry location]" 						| Out-File -FilePath $outputFile -append
	"Used when IE Enhanced Security Configuration is Disabled" 	| Out-File -FilePath $outputFile -append
	"--------------------" 										| Out-File -FilePath $outputFile -append
	$ieDomainLocalIntranetObj | Format-List						| Out-File -FilePath $outputFile -append
	"`n`n`n" 													| Out-File -FilePath $outputFile -append
	"--------------------" 										| Out-File -FilePath $outputFile -append
	"[ZoneMap\EscDomains registry location]" 					| Out-File -FilePath $outputFile -append
	"Used when IE Enhanced Security Configuration is Enabled" 	| Out-File -FilePath $outputFile -append
	"--------------------" 										| Out-File -FilePath $outputFile -append
	$ieEscDomainLocalIntranetObj | Format-List					| Out-File -FilePath $outputFile -append
}
else{
	"--------------------" 										| Out-File -FilePath $outputFile -append
	"[ZoneMap\Domains registry location]" 						| Out-File -FilePath $outputFile -append
	"--------------------" 										| Out-File -FilePath $outputFile -append
	$ieDomainLocalIntranetObj | Format-List						| Out-File -FilePath $outputFile -append
}
"`n`n`n" | Out-File -FilePath $outputFile -append

CollectFiles -sectionDescription $sectionDescription -fileDescription "IE Zones Information (Trusted Sites and Local Intranet)" -filesToCollect $outputFile


# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAu7xlvH8SoHGSp
# dVddNyaDaSP889+6YhA3IkKGRjzOgaCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
# esGEb+srAAAAAANOMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI5WhcNMjQwMzE0MTg0MzI5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDdCKiNI6IBFWuvJUmf6WdOJqZmIwYs5G7AJD5UbcL6tsC+EBPDbr36pFGo1bsU
# p53nRyFYnncoMg8FK0d8jLlw0lgexDDr7gicf2zOBFWqfv/nSLwzJFNP5W03DF/1
# 1oZ12rSFqGlm+O46cRjTDFBpMRCZZGddZlRBjivby0eI1VgTD1TvAdfBYQe82fhm
# WQkYR/lWmAK+vW/1+bO7jHaxXTNCxLIBW07F8PBjUcwFxxyfbe2mHB4h1L4U0Ofa
# +HX/aREQ7SqYZz59sXM2ySOfvYyIjnqSO80NGBaz5DvzIG88J0+BNhOu2jl6Dfcq
# jYQs1H/PMSQIK6E7lXDXSpXzAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnMc7Zn/ukKBsBiWkwdNfsN5pdwAw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMDUxNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAD21v9pHoLdBSNlFAjmk
# mx4XxOZAPsVxxXbDyQv1+kGDe9XpgBnT1lXnx7JDpFMKBwAyIwdInmvhK9pGBa31
# TyeL3p7R2s0L8SABPPRJHAEk4NHpBXxHjm4TKjezAbSqqbgsy10Y7KApy+9UrKa2
# kGmsuASsk95PVm5vem7OmTs42vm0BJUU+JPQLg8Y/sdj3TtSfLYYZAaJwTAIgi7d
# hzn5hatLo7Dhz+4T+MrFd+6LUa2U3zr97QwzDthx+RP9/RZnur4inzSQsG5DCVIM
# pA1l2NWEA3KAca0tI2l6hQNYsaKL1kefdfHCrPxEry8onJjyGGv9YKoLv6AOO7Oh
# JEmbQlz/xksYG2N/JSOJ+QqYpGTEuYFYVWain7He6jgb41JbpOGKDdE/b+V2q/gX
# UgFe2gdwTpCDsvh8SMRoq1/BNXcr7iTAU38Vgr83iVtPYmFhZOVM0ULp/kKTVoir
# IpP2KCxT4OekOctt8grYnhJ16QMjmMv5o53hjNFXOxigkQWYzUO+6w50g0FAeFa8
# 5ugCCB6lXEk21FFB1FdIHpjSQf+LP/W2OV/HfhC3uTPgKbRtXo83TZYEudooyZ/A
# Vu08sibZ3MkGOJORLERNwKm2G7oqdOv4Qj8Z0JrGgMzj46NFKAxkLSpE5oHQYP1H
# tPx1lPfD7iNSbJsP6LiUHXH1MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
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
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHyOOinxahC8beKbhrZWTBSs
# UmD2WPJb9xulpqJhbweLMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAMTonjHQ8gPY2JpupPYvcjf94QD+Bq+io4fv0If1U5jFCp9bEhUsva
# 6WKsD3//Ek/0nmu63xXLTCnFKNJJWrtq3H/lr6ebM9XqlvHSI7pd4Ep2AEP54CuN
# Xhe4xE32JzKe0/Tqm2zoiU3x9FMVpXsBZTE/yGVlKQWv5Bjbx51jW8wiobyxkiew
# n9Y/1MdUcwbl5siK+nzhN2JpE0QbCUps058gnlINWWiHUpnNkvYGvBW4UcrZhtUD
# PscTCL6d9ZdKlKUG+2iaPF37Vb3TWAheX5GambYjVCAAB0YQx6mX2+0rUycI79x9
# lR1ri3QkdKwdHyy/k7yxrg8pPKf+oiGYoYIW/TCCFvkGCisGAQQBgjcDAwExghbp
# MIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIO+OR9yaHDhzhrLG/sZYDfrqs+MNsjh+pwAqoM8HwvXLAgZkXQO8
# Ev0YEzIwMjMwNTIyMDg0MDA4LjAwNFowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjEyQkMt
# RTNBRS03NEVCMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVDCCBwwwggT0oAMCAQICEzMAAAHKT8Kz7QMNGGwAAQAAAcowDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkw
# MTQwWhcNMjQwMjAyMTkwMTQwWjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MTJCQy1FM0FFLTc0RUIxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDDAZyr2PnStYSRwtKUZkvB5RV/FdFpSOI+zJo1XE90
# xGzcJV7nyyK78SRpW3u3s81M+Sj+zyU226wB4sSfOSLjjLGTZz16SbwTVJDZhX1v
# z8s7F8pqlny1WU/LHDoOYXM0VCOJ9WbwSJnuUVGhjjjy+lxsEPXyqNg0X/ZndJBy
# Fyx1XU31jpXZYaXnlWYuoVFfn52m12Ot4FfOLdZb1OygIRZxgIErnBiBL21PZJJJ
# PNp7eOZ3DjSD4s4jKtU8XYOjORK2/okEM+/BqFdakoak7usesoX6jsQI39WJAUxn
# Kn+/F4+JQAEM2rMRQjyzuSViZ4de+N5A6r8IzcL9jxuPd8k5udkft4Be9EOfFPxH
# pb+4PWYZQm+/0z0Ey7eeEqkqZLHPM7ku1wwSHa0xfGEwYY0xQ/cM4Qrdf7b8sPVn
# Te6wlOTmkc2gf+AMi9unvzsLDjS2wCmIC+2sdjC5vROoi/xnLraXyfyz8y/8/vrg
# JOqvFxfNqUEeH5fLhc+OZp2c+RknJyncpzNuSD1Bu8mnQf/QWzAdL558Wh+kM0nA
# uHWGz9oyLUr+jMS/v9Ysg+wOArXp9T9rHJuowqTQ07GB6VSMBgqXjBTRjpDir03/
# 0/ABLRyyJ9CFjWihB8AjSIMIJIQBOyUPxtM7S1G2p1wh1q85F6rOg928C/cOvVdd
# DwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFPrH/qVLgRJDwpmF3RGBTtFhczx/MB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBANjQeSoJLcq4p58Vfz+ub920P3Trp0oSV42quLBmqwzhibwTDhCKo6o7uZah
# hhjgrnLx5dI4co1c5+k7pFtpiPyMI5wkAHm2ouXmGIyBoxsBUuuXWGWLH2yWg7jk
# s43QmmEq9rcPoBUoDs/vyYD2JEdlhRWtGLJ+9CNbGZSfGGKzx+ib3b79EdwRnUOH
# n6niDN54vzhiXTRbKr0RyAEop+CrSUKNY1KrUBQbWwQuWBc5K8pnj+Vdcf4x+Fwd
# 73VYshpmRL8e73B1NPojXgEL3vKEOxlZcCXQgnzTUjpS0QWkKxN47JkEnsIXSt/m
# XEny0T2iM2zKpckq7BWfR7AIyRmrP9wTC/0UTHxCaxnRk2h1O2yX5X11mb55Sswp
# mTo8qwoCu1D6MeR9WweAo4OWh6Wk6YeqBftRs7Q1WciWk/nmBBOpXvq9TvBFelR/
# PsqETcFlc2DAbTl1GcJcPCuGFjP4i1vOzUrVHwjhgwMmNb3QBIKD0l/7HKBEpkYo
# eOjYGzZfJoq43U/oUUIhVc3sqAeX9tmJqQaruTlNDg5crnGSEIeGN2Ae7GPeErkB
# o7L4ZfE7+NvKoZGp5LF/5NM+5aENa6sijfdEwMZ7kNsiaNxtyPp1WFB6+ocKVHU4
# dJ+v7ybWFZEkaULVq1w5YpqMCvA5RGolJWVOHBWAjLMY2aPOMIIHcTCCBVmgAwIB
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
# IEVTTjoxMkJDLUUzQUUtNzRFQjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAo47nlwxPizI8/qcKWDYhZ9qMyqSg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOgVWJswIhgPMjAyMzA1MjIxMDU3MzFaGA8yMDIzMDUyMzEwNTczMVow
# dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA6BVYmwIBADAHAgEAAgIqgDAHAgEAAgIR
# tDAKAgUA6BaqGwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAEyYg4dLKrzU
# kg94vbzHyqqvl0xShXh8rV6O8PJww2gPL3wUfzMn6okx0MYqwrojeyMfXmVcP3uB
# WyHcefeVjCoT1N+MHlrD94kygUZElXr7BHC+GGzlz0LgJ7kXoa5I6a3wVBg8sb1o
# 60xdAXcjBneyc0MdYl42Ywd576L+cpy4MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHKT8Kz7QMNGGwAAQAAAcowDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgUeo8LvJOVmY5MaR3qNgEcZfMuVikqDXcO40umR0BEz4wgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCATPRvzm+tVTayVkCTiO3VIMSTojNkDBUKh
# bAXcrNwa4DCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAAByk/Cs+0DDRhsAAEAAAHKMCIEIBve4k7EFYs51vLpwiK1T7HX7uT97niicfMS
# TaYCZK+kMA0GCSqGSIb3DQEBCwUABIICAI5WeeLqfFE/d4XqxI1+oYm4a0YclLY3
# 8aSqGC04F5SoZU6bu2gfe8xvI7LSO0pmuH+uFEFcI4FNZ5br2D36De8/9usi1Xcu
# Dfps0uY+D6FfG1e7mfyPUWT0lccg81NUxCtfWP0+0v0TkjAtqh2K9m2HDZEVT10n
# Kzz//UCbGnW9c2BZvHThuv73aBGIRaV7/ZcMcaSkNx2YvfFPfbeQ7hx7AxzNXF7E
# 6tmsJiYPf2nqv4LbXZCc9sHwZoQ1EqQYhYKrjYu0zllUFNe1i7OfE11I2sGtBpqm
# lKP0Tm732kqJPglM36leX7zIjnUmNpJbvDEAvq+X2IpiATgMuVZstb6Gk7jOFvWi
# TnYnobMs1sfXV6ECd/7OXA55fvMYm6X0r0wD8a0a+DQq4RBwTBycsCzmu1wvwJai
# 5e5mmLK9ZeTV/3GrDo5bQbEWlokVJxq/yFlq5hsqZGgCftbr2wyNkpvjXqwr5Eyi
# il6yNYL3bflXrLw0kpbMBSiGH6cwYW2cpFzRpQ3LK9PlufSOeF2xT4962z+SEjKs
# uvxlWHAP+vCCEr/icL93v3lT/kbH++aMtwIlRIHHqwhiaC9Z4KXlFyQaXKuXhZjX
# +qhfECkedibaF0BlrYiOssHRXgaMVhYPuhNQ+rfyqEjfrFCB2kkg5jYsw17n4S6c
# kHx5MmvNSRZ4
# SIG # End signature block
