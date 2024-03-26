#************************************************
# DC_DirectAccessServer-Component.ps1
# Version 1.0.04.03.13: Created script.
# Version 1.1.03.20.14: Multiple updates over time improving formatting, commands run, etc. [worked with JoelCh]
# Version 1.2.04.28.14: Added overview headings showing all commands run in each section.
# Version 1.3.08.24.14: Updated comments, changed script so the file would only be created on server SKUs, and then warn the user if the RaMgmtSvc does not exist. TFS264123
# Date: 2013-2014
# Authors: Boyd Benson (bbenson@microsoft.com); Joel Christiansen (joelch@microsoft.com)
# Description: Collects information about the DirectAccess Client.
# Called from: DirectAccess Diag, Main Networking Diag
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
Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessServer -Status $ScriptVariable.ID_CTSDirectAccessServerDescription


#os version
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber
$isServerSku = (Get-CimInstance -Class Win32_ComputerSystem).DomainRole -gt 1


function RunNetSH ([string]$NetSHCommandToExecute="")
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSDirectAccessClient -Status "netsh $NetSHCommandToExecute"
	$NetSHCommandToExecuteLength = $NetSHCommandToExecute.Length + 6
	"-" * ($NetSHCommandToExecuteLength) + "`r`n" + "netsh $NetSHCommandToExecute" + "`r`n" + "-" * ($NetSHCommandToExecuteLength) | Out-File -FilePath $OutputFile -append
	$CommandToExecute = "cmd.exe /c netsh.exe " + $NetSHCommandToExecute + " >> $OutputFile "
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
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
}


$sectionDescription = "DirectAccess Server"
If ($isServerSku -eq $true)
{
	$outputFile= $Computername + "_DirectAccessServer_info_pscmdlets.TXT"
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"DirectAccess Server Powershell Cmdlets"				| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Overview"												| Out-File -FilePath $OutputFile -append
	"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
	"DirectAccess Server (Get-DA*) Powershell cmdlets"		| Out-File -FilePath $OutputFile -append
	"   1. Get-DAAppServer"									| Out-File -FilePath $OutputFile -append
	"   2. Get-DAClient"									| Out-File -FilePath $OutputFile -append
	"   3. Get-DAClientDnsConfiguration"					| Out-File -FilePath $OutputFile -append
	"   4. Get-DAMgmtServer"								| Out-File -FilePath $OutputFile -append
	"   5. Get-DANetworkLocationServer"						| Out-File -FilePath $OutputFile -append
	"   5. Get-DAOtpAuthentication"							| Out-File -FilePath $OutputFile -append
	"   5. Get-DaServer"									| Out-File -FilePath $OutputFile -append
	"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
	"DirectAccess Server (Get-RemoteAccess*) Powershell cmdlets"		| Out-File -FilePath $OutputFile -append
	"   1. Get-RemoteAccess"								| Out-File -FilePath $OutputFile -append
	"   2. Get-RemoteAccessAccounting"						| Out-File -FilePath $OutputFile -append
	"   3. Get-RemoteAccessConnectionStatistics"			| Out-File -FilePath $OutputFile -append
	"   4. Get-RemoteAccessConnectionStatisticsSummary"		| Out-File -FilePath $OutputFile -append
	"   5. Get-RemoteAccessHealth"							| Out-File -FilePath $OutputFile -append
	"   6. Get-RemoteAccessLoadBalancer"					| Out-File -FilePath $OutputFile -append
	"   7. Get-RemoteAccessRadius"							| Out-File -FilePath $OutputFile -append
	"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
	"DirectAccess Server (Get-Vpn*) Powershell cmdlets"		| Out-File -FilePath $OutputFile -append
	"   1. Get-VpnAuthProtocol"								| Out-File -FilePath $OutputFile -append
	"   2. Get-VpnServerIPsecConfiguration"					| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
		"`n"	| Out-File -FilePath $OutputFile -append
		"`n"	| Out-File -FilePath $OutputFile -append
		"`n"	| Out-File -FilePath $OutputFile -append
		"`n"	| Out-File -FilePath $OutputFile -append
		"`n"	| Out-File -FilePath $OutputFile -append


	# Add registry check to determine if this is a DAServer (with Get-RemoteAccess).
	$regkeyRemoteAccessCheck = "HKLM:\SYSTEM\CurrentControlSet\Services\RaMgmtSvc"
	if (Test-Path $regkeyRemoteAccessCheck) 
	{
		if ($bn -ge 9000)
		{
			"[info] DA ps cmdlets (those that start with Get-DA)" | WriteTo-StdOut

			"===================================================="	| Out-File -FilePath $OutputFile -append
			"DirectAccess Server (Get-DA*) Powershell cmdlets"		| Out-File -FilePath $OutputFile -append
			"===================================================="	| Out-File -FilePath $OutputFile -append
			#----------
			# W8/W2012 Powershell Cmdlets
			#----------
			# RemoteAccess
			runPS "Get-DAAppServer"						# W8/WS2012, W8.1/WS2012R2	# fl
			runPS "Get-DAClient"						# W8/WS2012, W8.1/WS2012R2	# fl
			runPS "Get-DAClientDnsConfiguration"	-ft	# W8/WS2012, W8.1/WS2012R2	# ft	
			runPS "Get-DAMgmtServer"					# W8/WS2012, W8.1/WS2012R2	# fl
			runPS "Get-DANetworkLocationServer"			# W8/WS2012, W8.1/WS2012R2	# fl
			runPS "Get-DAOtpAuthentication"				# W8/WS2012, W8.1/WS2012R2	# fl
			runPS "Get-DaServer"						# W8/WS2012, W8.1/WS2012R2	# fl
		}	
			
		if ($bn -gt 9000)
		{
			"[info] RemoteAccess ps cmdlets section (those that start with Get-RemoteAccess*)" | WriteTo-StdOut
			"[info] If there is nothing in this section, then we cannot reach a DC" | WriteTo-StdOut
			"===================================================="			| Out-File -FilePath $OutputFile -append
			"DirectAccess Server (Get-RemoteAccess*) Powershell cmdlets"	| Out-File -FilePath $OutputFile -append
			"===================================================="			| Out-File -FilePath $OutputFile -append

			runPS "Get-RemoteAccess"								# W8/WS2012, W8.1/WS2012R2	# fl
			runPS "Get-RemoteAccessAccounting"						# W8/WS2012, W8.1/WS2012R2	# fl
			runPS "Get-RemoteAccessConnectionStatistics"		-ft	# W8/WS2012, W8.1/WS2012R2	# ft
			runPS "Get-RemoteAccessConnectionStatisticsSummary"		# W8/WS2012, W8.1/WS2012R2	# fl
			runPS "Get-RemoteAccessHealth"						-ft	# W8/WS2012, W8.1/WS2012R2	# ft
			runPS "Get-RemoteAccessLoadBalancer"					# W8/WS2012, W8.1/WS2012R2	# fl
			runPS "Get-RemoteAccessRadius"						-ft	# W8/WS2012, W8.1/WS2012R2	# ft

			"[info] VPN ps cmdlets section: Verifying the RemoteAccess service is running" | WriteTo-StdOut
			"===================================================="			| Out-File -FilePath $OutputFile -append
			"DirectAccess Server (Get-Vpn*) Powershell cmdlets"				| Out-File -FilePath $OutputFile -append
			"===================================================="			| Out-File -FilePath $OutputFile -append
			# verifying that the RemoteAccess service is running
			if ((Get-Service "RemoteAccess").Status -eq 'Running')
			{	
				"[info] RemoteAccess service is running; running ps cmdlets that start with Get-Vpn" | WriteTo-StdOut
				# Errors if the RemtoteAccess service is not started.
					# The following pscmdlet removed via commented 10/08/13; reason: exception)
					# runPS "Get-VpnS2SInterface" 
					runPS "Get-VpnAuthProtocol"						# W8/WS2012, W8.1/WS2012R2	# default <unknown>	
					runPS "Get-VpnServerIPsecConfiguration"			# W8/WS2012, W8.1/WS2012R2	# default <unknown>	
			}
			else
			{
				"The RemoteAccess service is not running. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append
			}
			

			<#
				#Currently not including these pscmdlets:
				#RemoteAccess
						# Requires the RRAS service to be started (I think this is the service it relies on)
						runPS "Get-RemoteAccessConnectionStatistics"
						# need trap
						runPS "Get-DAMultiSite"
						# need trap
						runPS "Get-DAEntryPoint"
						# need trap
						runPS "Get-DAEntryPointDC"
					# Requires Input - not running.
						# Get-RemoteAccessUserActivity
					# Requires Input - not running.
						# Get-VpnS2SInterfaceStatistics
			#>	
		}

		#_#if ($bn -ge 9000)
		#Get role, OSVer, hotfix data. #_#
		$cs =  Get-CimInstance -Namespace "root\cimv2" -class win32_computersystem #-ComputerName $ComputerName #_#
		$DomainRole = $cs.domainrole #_#
		if (($bn -ge 9000) -and ($DomainRole -ge 2)) #_# not on Win10 client
		{
			# Denial of Service pscmdlet. Added 10.10.13
			# This pscmdlet exceptions on client SKUs.
			"[info]: get-NetIpsecdospSetting" | WriteTo-StdOut
			runPS "get-NetIpsecDospSetting"							# W8/WS2012, W8.1/WS2012R2	# default fl
		}
	}
	else
	{
		"The RaMgmtSvc service does not exist. Not running pscmdlets." | Out-File -FilePath $OutputFile -append
	}
	CollectFiles -sectionDescription $sectionDescription -fileDescription "DirectAccess Server Info PSCmdlets" -filesToCollect $outputFile	


	if (Test-Path $regkeyRemoteAccessCheck) 
	{	
		if ($bn -ge 9000)
		{
			"[info] DirectAccess Event logs" | WriteTo-StdOut
			#----------
			# EventLogs
			#----------
			#
			$EventLogNames = "Microsoft-Windows-RemoteAccess-MgmtClient/Operational"
			$Prefix = ""
			$Suffix = "_evt_"
			.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix

			$EventLogNames = "Microsoft-Windows-RemoteAccess-RemoteAccessServer/Admin"
			$Prefix = ""
			$Suffix = "_evt_"
			.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix

			$EventLogNames = "Microsoft-Windows-RemoteAccess-RemoteAccessServer/Operational"
			$Prefix = ""
			$Suffix = "_evt_"
			.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix

		}

		if ($bn -ge 7600)
		{
			#----------Registry
			$outputFile = $Computername + "_DirectAccessServer_reg_.TXT"
			$CurrentVersionKeys = "HKLM\SOFTWARE\Policies\Microsoft\DirectAccess",
									"HKLM\SOFTWARE\Policies\Microsoft\Windows\RemoteAccess",
									"HKLM\System\CurrentControlSet\Services\RemoteAccess",
									"HKLM\System\CurrentControlSet\Services\RaMgmtSvc"
			$sectionDescription = "DirectAccess Server"
			RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -outputFile $outputFile -fileDescription "DirectAccess Server Registry Keys" -SectionDescription $sectionDescription
		}
	}
}

# SIG # Begin signature block
# MIIn0AYJKoZIhvcNAQcCoIInwTCCJ70CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBqLRzygi/AOkd0
# 5me5jyvt7uin7RyxM+YTy+Ruv4KeC6CCDYUwggYDMIID66ADAgECAhMzAAACzfNk
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
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGaEwghmdAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAALN82S/+NRMXVEAAAAA
# As0wDQYJYIZIAWUDBAIBBQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIN9/
# X0goq/LCGjiWmYKk0tLh2WPR4K5kbi8drDm6YqRcMEQGCisGAQQBgjcCAQwxNjA0
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQu
# Y29tIDANBgkqhkiG9w0BAQEFAASCAQB7djczpxlJKfo5QaoVKGxdf9FEN1+YHqFQ
# cuv4zDk6z2Z7uylFfN0koohncvJSxkp6E47TfPpcU8Zc4rirq73qDSZ5EAbRP2Ep
# saQtc7jxWBqV3C9ni/V8VxI4yBcSm0ks2d5jcN9Hds5oHhLpcnQp/8l/aUw965T3
# Wdm+irFN3dB28FOyc0Ox54vRqsJGotxh5FzT2jGuEBMdjC3pMBC/oXi2in0zEHk5
# JyNu07+S0Fu0USQViSswDMk+8xJukC6i6ojuHEIenurKTVlsOfxhgzw5LQZmoirI
# jRsRmJIktWixssqTFKnZvfqLSh099+rsPe6ISO8lhmTj9n8T8388oYIXKTCCFyUG
# CisGAQQBgjcDAwExghcVMIIXEQYJKoZIhvcNAQcCoIIXAjCCFv4CAQMxDzANBglg
# hkgBZQMEAgEFADCCAVkGCyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEE
# AYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIMGXpBi/in3ZtbfuEjcJ5EDE53rQdQXO
# 2WQIEaGgF2cDAgZjT99IIK4YEzIwMjIxMDI0MDgxNTE0LjcxM1owBIACAfSggdik
# gdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNV
# BAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UE
# CxMdVGhhbGVzIFRTUyBFU046RDA4Mi00QkZELUVFQkExJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghF4MIIHJzCCBQ+gAwIBAgITMwAAAbof
# Pxn3wXW9fAABAAABujANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDAeFw0yMjA5MjAyMDIyMTlaFw0yMzEyMTQyMDIyMTlaMIHSMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNy
# b3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxl
# cyBUU1MgRVNOOkQwODItNEJGRC1FRUJBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# iE4VgzOSNYAT1RWdcX2FEa/TEFHFz4jke7eHFUVfIre7fzG6wRvSkuTCOAa0Oxos
# tuuUzGpfe0Vv/cGAQ8QLcvTBfvqAPzMe37CIFXmarkFainb2pGuAwkooI9ylCdKO
# z0H/hcwUW+ul0+JxkO/jcUuDP18eoyrQskPDkkAcYNLfRMJj04Xjc/h3jhn2UTsJ
# pVLakkwXcvjncxcHnJgr8oNuKWERE/WPGfbKX60YJGC4gCwwbSh46FdrDy5IY6FL
# oAJIdv55uLTTfwwUfKhM2Ep/5Jijg6lJjfE/j6zAEFMoOhg/XAf4J/EbqH1/KYEl
# A9Blqp+XSuKIMuOYO6dC0fUYPrgCKvmT0l3CGrnAuZJZePIVUv4gN86l2LEnp/mj
# 4yETofi3fXD6mvKAeZ3ZQdDrntQbHoU27PAL5KkAeZXvoxlhpzi4CFOBo/js/Z55
# LWhyS/KGX3Jr70nM98yS6DfF6/MUANaItEyvTroQxXurclJECycJL0ZDTwLgUo9t
# KHw48zfcueDR9/EA2ccABf8MTtwdzHuX2NpXcByaSPuiqKvgSHa7ljHCJpMTftdo
# y6ZfYRLc8nk0Fperth0snDJIP5T2mT+2Xh1DW38R6ju4NOWI7JCQPwjvjGlUHRPf
# X/rsod+QGQVW/LrDJ7bVX70gLy5IP75GAPdHC03aQT8CAwEAAaOCAUkwggFFMB0G
# A1UdDgQWBBSKYubxAx4lrbmP0xZ5psjYdK9k5TAfBgNVHSMEGDAWgBSfpxVdAF5i
# XYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRp
# bWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsF
# AAOCAgEAX8jxTqFtmG8Nyf3qdnq2RtISNc+8pnrCuhpdyCy0SGmBp4TCV4u49ccv
# MRa24m5jPh6yGaFeoWvj2VsBxflI3n9wSw/TF0VrJvtTk/3gll3ceMW+lZE2g0GE
# XdIMzQDfywjYf6GOEH9V9fVdxmJ6LVE48DIIdwGAcvJCsS7qadvceFsh2vyHRNrt
# YXKUaEtIVbrCbMq6w/po6WacZJpzk0x+VrqVG9Ngd3byttsKB9KbVGFOChmP5bwN
# Mq2IQzC5scneYg8qajzG0khZc+derpcqCV2svlzKcsxf/RZfrk65ZsdXkZMQt19a
# 8ZXcNpmsc9RD9Q/fUp6pvbGNUJvfQtXCBuMi9hLvs3V0BGQ3wX/2knWA7gi9lYzD
# IyUooUaiM7V/XBuNJZwD/nu2xz63ZuWsxaBI0eDMOvTWNs9K6lGPLce31lmzjE3T
# Z6Jfd4bb3s2u0LqXhz+DOfbR6qipbH+4dbGZOAHQXmiwG5Mc57vsPIQDS6ECsaWA
# o/3WOCGC385UegfrmDRCoK2Bn7fqacISDog6EWgWsJzR8kUZWZvX7XuAR74dEwzu
# MGTg7Ton4iigWsjd7c8mM+tBqej8zITeH7MC4FYYwNFxSU0oINTt0ada8fddbAus
# IIhzP7cbBFQywuwN09bY5W/u/V4QmIxIhnY/4zsvbRDxrOdTg4AwggdxMIIFWaAD
# AgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3Nv
# ZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIy
# MjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5
# vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64
# NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhu
# je3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl
# 3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPg
# yY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I
# 5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2
# ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/
# TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy
# 16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y
# 1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6H
# XtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMB
# AAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQW
# BBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30B
# ATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYB
# BAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMB
# Af8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBL
# oEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMv
# TWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggr
# BgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNS
# b29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1Vffwq
# reEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27
# DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pv
# vinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9Ak
# vUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWK
# NsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2
# kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+
# c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep
# 8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+Dvk
# txW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1Zyvg
# DbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/
# 2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC1DCCAj0CAQEwggEAoYHYpIHV
# MIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOkQwODItNEJGRC1FRUJBMSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQB2o0d7XXeAInzt
# pkgZrlAFSojC8qCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MA0GCSqGSIb3DQEBBQUAAgUA5wBMfTAiGA8yMDIyMTAyNDA3Mjc1N1oYDzIwMjIx
# MDI1MDcyNzU3WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDnAEx9AgEAMAcCAQAC
# AhT7MAcCAQACAhFHMAoCBQDnAZ39AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisG
# AQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQAD
# gYEAn1N/zL83XwaqnU7ay3Xr5IocelnV97J6hBsvgokD0tZe+ifawMxKhe+jag6p
# aHag8epZRArQR2JLaWk3EMsc1hgB41sDYuK1FLlC2jddK2HDzL/rBisa1ZcqNpGG
# C5CvFTHKclyzovip5Kprx3Yf1G/Ie0VWXAFzkq6qfCgonzoxggQNMIIECQIBATCB
# kzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAbofPxn3wXW9fAAB
# AAABujANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJ
# EAEEMC8GCSqGSIb3DQEJBDEiBCC4MMKHRDzSUfNjROFwiLnOL0t7fDEoloaHrlTt
# 3o8TRDCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIClVvTwzbnD61gZayaUa
# 2nWDLWc9ypZ+qAwXeeVZhXMFMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTACEzMAAAG6Hz8Z98F1vXwAAQAAAbowIgQgc9TyKnfa6DLrLUU24BE/
# Utl9ZqDe0SCrnDc7+ecxR1EwDQYJKoZIhvcNAQELBQAEggIAGRoq1q/n4m9HBbre
# qpZH8GdSnZafNVg/dJNzXQCP0zaJsXeck99NqvwT1ezs8eQ/DVDNQ16rhBCR7gdN
# gOC/ozFQOgD5Yd5wnSXMQD9PEbA/SjxWFVPhozEFjewzTnEGvulJ/fWdqg58K2xy
# u9al0hUU+q7GGIx/rK9auQivtRd5YHC9972+l6oEcohPkpQWKPmkMArowHDUs4TN
# dKxcuVW0TMHSq0+5aX8LTUDadlPDK+KxTWLgiReKDLip+kmWqU8x2vIgaRa2iXMI
# PbQYPO+LMplEvThmhV2LO9r9isbL/B22HeRJr2svDMDj0Z7mCFIxiX2n0vS1WMlk
# CSoca+kPSiPL05HGEi1fKlTaif4HXmTIrzPjFa5t1nFyn5UrlBv14+mOvUtiQBEm
# HvMjG2xW0fynpYW3GzD/ss6HbRNQSDY5PCUF1/mruR9oQLZZyq1DDxTLCQj/yKQC
# 9IbTSLBYfE2MmCf7KBKFe6zDztSPJVbODof7eFEpSvsh7pyPae6c8m4NxczNLikS
# aE4YACzYa6DFb+/k6ShFHokANmOncpQfir23DjtYn2bnuS0yQ6M1IthgQoP76hvO
# LgUjQYf16Mz2iAtpZ9CEmhxh6zsqq8Of6TfNRsCQ+B1MjoARt/kYxCrwN0nLyZft
# 3f3FW66tS4qtS++FU83R8DtYekU=
# SIG # End signature block
