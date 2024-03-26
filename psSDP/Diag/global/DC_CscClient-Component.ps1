#************************************************
# DC_CscClient-Component.ps1
# Version x
# Date: 2009-2014, 2020-10-26 WalterE added CscDbDump, run script only for Client SKU
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: Collects information about Client Side Caching (CSC)
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
Write-DiagProgress -Activity $ScriptVariable.ID_CTSCscClient -Status $ScriptVariable.ID_CTSCscClientDescription

function RunNetSH ([string]$NetSHCommandToExecute="")
{
	
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSCscClient -Status "netsh $NetSHCommandToExecute"
	
	$NetSHCommandToExecuteLength = $NetSHCommandToExecute.Length + 6
	"`n`n`n" + "-" * ($NetSHCommandToExecuteLength) + "`r`n" + "netsh $NetSHCommandToExecute" + "`r`n" + "-" * ($NetSHCommandToExecuteLength) | Out-File -FilePath $OutputFile -append

	$CommandToExecute = "cmd.exe /c netsh.exe " + $NetSHCommandToExecute + " >> $OutputFile "
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
}


function cscWMI ([string]$wmiObject)
{
	$cscWmiObject = Get-CimInstance -query "select * from $wmiObject" -EA SilentlyContinue #_# -EA SilentlyContinue
	$cscWmiObjectLen = $cscWmiObject.length
	"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
	"WMI object: " + $wmiObject 						 	| Out-File -FilePath $OutputFile -append
	"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
	if ($cscWmiObjectLen -ne 0)
	{
		foreach ($object in $cscWmiObject)
		{
			$object	| Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"There are no items in this WMI object"	| Out-File -FilePath $OutputFile -append
	}
	"`n`n`n" | Out-File -FilePath $OutputFile -append
}

#_# run on client SKU only
$cs =  Get-CimInstance -Namespace "root\cimv2" -class win32_computersystem #-ComputerName $ComputerName
$DomainRole = $cs.domainrole
if ($DomainRole -lt 2)
{

	$sectionDescription = "CSC Client"

	#----------W8/WS2012 powershell cmdlets
	# detect OS version and SKU
	$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
	[int]$bn = [int]$wmiOSVersion.BuildNumber

	$OutputFile= $Computername + "_CscClient_info_wmi.TXT"

	"===================================================="			| Out-File -FilePath $OutputFile -append
	"Client Side Caching Client WMI Output"							| Out-File -FilePath $OutputFile -append
	"===================================================="			| Out-File -FilePath $OutputFile -append
	"Overview"														| Out-File -FilePath $OutputFile -append
	"----------------------------------------------------"			| Out-File -FilePath $OutputFile -append
	"   1. Win32_UserStateConfigurationControls   (W8/WS2012+)"		| Out-File -FilePath $OutputFile -append
	"   2. Win32_OfflineFilesCache                (WV/WS2008+)"		| Out-File -FilePath $OutputFile -append
	"   3. Win32_OfflineFilesItem                 (WV/WS2008+)"		| Out-File -FilePath $OutputFile -append
	"   4. Win32_OfflineFilesMachineConfiguration (W8/WS2012+)"		| Out-File -FilePath $OutputFile -append
	"===================================================="			| Out-File -FilePath $OutputFile -append
	"`n`n`n`n`n"													| Out-File -FilePath $OutputFile -append

	if ($bn -gt 9000)                               
	{
		#----------------------------------------------------
		# USER PROFILE (W8/WS2012+)
		#----------------------------------------------------
		#cscWMI "Win32_UserProfile"							# shows information about each user profile
		cscWMI "Win32_UserStateConfigurationControls"		# shows on/off state of FolderRedirection, OfflineFiles, and RoamingUserProfile

		#----------------------------------------------------
		# OFFLINE FILES (WV/WS2008+)
		#Reference: http://msdn.microsoft.com/en-us/library/bb309180(v=vs.85).aspx
		#----------------------------------------------------
		cscWMI "Win32_OfflineFilesCache"					# shows Active, Enabled, and Location
		cscWMI "Win32_OfflineFilesItem"						# shows ItemName
		#-----
		#cscWMI "Win32_OfflineFilesAssociatedItems"			# "This class is not supported"
		#cscWMI "Win32_OfflineFilesChangeInfo"				# usefulness unknown
		#cscWMI "Win32_OfflineFilesConnectionInfo"			# usefulness unknown
		#cscWMI "Win32_OfflineFilesFileSysInfo"				# usefulness unknown
		#cscWMI "Win32_OfflineFilesPinInfo"					# usefulness unknown
		#cscWMI "Win32_OfflineFilesSuspendInfo"				# usefulness unknown

		#----------------------------------------------------
		# OFFLINE FILES (W8/WS2012+)
		#----------------------------------------------------
		cscWMI "Win32_OfflineFilesMachineConfiguration"		# shows
		#-----
		#cscWMI "Win32_OfflineFilesBackgroundSync"			# usefulness unknown
		#cscWMI "Win32_OfflineFilesDiskSpaceLimit"			# usefulness unknown
		#cscWMI "Win32_OfflineFilesHealth"					# usefulness unknown
		#cscWMI "Win32_OfflineFilesUserConfiguration"		# usefulness unknown
	}
	elseif ($bn -gt 7000)
	{
		#----------------------------------------------------
		# OFFLINE FILES (WV/WS2008+)
		#Reference: http://msdn.microsoft.com/en-us/library/bb309180(v=vs.85).aspx
		#----------------------------------------------------
		cscWMI "Win32_OfflineFilesCache"					# shows Active, Enabled, and Location
		cscWMI "Win32_OfflineFilesItem"						# shows ItemName
		#-----
		#cscWMI "Win32_OfflineFilesAssociatedItems"			# "This class is not supported"
		#cscWMI "Win32_OfflineFilesChangeInfo"				# usefulness unknown
		#cscWMI "Win32_OfflineFilesConnectionInfo"			# usefulness unknown
		#cscWMI "Win32_OfflineFilesFileSysInfo"				# usefulness unknown
		#cscWMI "Win32_OfflineFilesPinInfo"					# usefulness unknown
		#cscWMI "Win32_OfflineFilesSuspendInfo"				# usefulness unknown
	}
	CollectFiles -filesToCollect $OutputFile -fileDescription "CscClient WMI output" -SectionDescription $sectionDescription



	#----------CscClient Registry

	$OutputFile= $Computername + "_CscClient_reg_output.TXT"
	$CurrentVersionKeys =	"HKCU\SOFTWARE\Policies\Microsoft\Windows\Netcache",
							"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache",
							"HKLM\SOFTWARE\Policies\Microsoft\NetCache",
							"HKLM\SYSTEM\CurrentControlSet\services\CSC",
							"HKLM\SYSTEM\CurrentControlSet\services\CscService"
	RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -OutputFile $OutputFile -fileDescription "CscClient Registry Keys" -SectionDescription $sectionDescription



	#----------CSC Eventlogs
	#WV/WS2008+
	if ($bn -gt 6000)
	{
		#----------CscClient EventLog
		$sectionDescription = "CscClient Eventlogs"
		$EventLogNames = 	"Microsoft-Windows-OfflineFiles/Operational",
							"Microsoft-Windows-OfflineFiles/Analytic",
							"Microsoft-Windows-OfflineFiles/Debug",
							"Microsoft-Windows-OfflineFiles/SyncLog"
		$Prefix = ""
		$Suffix = "_evt_"
		.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix
	}


	#----------Driver Information for CSC Client
	#$OutputFileSym = "_CscClient"

	# Array of file names to pass to checksym
	#[array]$arrFileNames = @("cscapi.dll","cscdll.dll","cscmig.dll","cscobj.dll","cscsvc.dll")
	# Call DC_ChkSym.ps1 with array of files
	#Run-DiagExpression .\DC_ChkSym.ps1 -FolderName "$Env:SystemRoot\System32" -FileMask $arrFileNames -Prefix $OutputFileSym -Suffix "_binaries_dll" -FileDescription "Offline Files and Folders Driver Versions"
	#Run-DiagExpression .\DC_ChkSym.ps1 -FolderName "$Env:SystemRoot\System32\drivers" -FileMask "csc.sys" -Prefix $OutputFileSym -Suffix "_binaries_sys" -FileDescription "Offline Files and Folders Driver Versions"

	#----------CSC Database
	#$ProcArc = $Env:PROCESSOR_ARCHITECTURE
	$fileDescription = $ScriptVariable.ID_CscClientOutput
	$sectionDescription = $ScriptVariable.ID_CscClientOutputDesc
	$OutputFile = $ComputerName + "_CSCdump.txt"
	$CommandToExecute = "cmd.exe /c CscDbDump.exe dump > $OutputFile"

	RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -BackgroundExecution
}



# SIG # Begin signature block
# MIInswYJKoZIhvcNAQcCoIInpDCCJ6ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAfCr0RLd6lCmlQ
# CPJGq+inordFAkYOLnitXaC4N77W4KCCDYUwggYDMIID66ADAgECAhMzAAACzfNk
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
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGYQwghmAAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAALN82S/+NRMXVEAAAAA
# As0wDQYJYIZIAWUDBAIBBQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIN73
# SQling4Qd5PnSlILE+toCw/COY0u2hawqzpyeTaOMEQGCisGAQQBgjcCAQwxNjA0
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQu
# Y29tIDANBgkqhkiG9w0BAQEFAASCAQDUpM0VlP/4qNCrMZnehk9F3b60paWV9h+t
# gghUwFUXl0b/wjf7daMe76h4Zo1bg/4dBmf0HID1ABmo8thQfYxzi6CkkVwE+W01
# pf9YAbylg/Imw7gYpB/mjKXdfPoyXyTzrIwPanwz2yBaenlxYW3ThBzaqpehmjCI
# XXN72L7xi0fh8fA6VPfyDFJjrK6E55iQPqsgalXGVSZ605ELSTTVOkbbSw5wiSMk
# XaVthlyTdjypuU5l4C+HumH5UOIzVqYCjurtTZ0w8kFswnTyUSmgZgiu5EPHYp/K
# UIY0HMlkDTGC9S1LSCwQCV4ibnQv8QakR4qocVimflg1WdE+NgeyoYIXDDCCFwgG
# CisGAQQBgjcDAwExghb4MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglg
# hkgBZQMEAgEFADCCAVUGCyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEE
# AYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIFgJy5zHXMEP1nHRlkX/2VR9Ba/VxN6Q
# FqSYK/MTyAeIAgZjTuAwihwYEzIwMjIxMDI0MDgxNTA5LjQ3OVowBIACAfSggdSk
# gdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNV
# BAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjo4OTdBLUUzNTYtMTcwMTElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaCCEV8wggcQMIIE+KADAgECAhMzAAABqwkJ76tj
# 1OipAAEAAAGrMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwMB4XDTIyMDMwMjE4NTEyOFoXDTIzMDUxMTE4NTEyOFowgc4xCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29m
# dCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# Tjo4OTdBLUUzNTYtMTcwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmdS1o5dehA
# SUsscLqyx2wm/WirNUfqkGBymDItYzEnoKtkhrd7wNsJs4g+BuM3uBX81WnO270l
# krC0e1mmDqQt420Tmb8lwsjQKM6mEaNQIfXDronrVN3aw1lx9bAf7VZEA3kHFql6
# YAO3kjQ6PftA4iVHX3JVv98ntjkbtqzKeJMaNWd8dBaAD3RCliMoajTDGbyYNKTv
# xBhWILyJ8WYdJ/NBDpqPzQl+pxm6ZZVSeBQAIOubZjU0vfpECxHC5vI1ErrqapG+
# 0oBhhON+gllVklPAWZv2iv0mgjCTj7YNKX7yL2x2TvrvHVq5GPNa5fNbpy39t5cv
# iiYqMf1RZVZccdr+2vApk5ib5a4O8SiAgPSUwYGoOwbZG1onHij0ATPLkgKUfgaP
# zFfd5JZSbRl2Xg347/LjWQLR+KjAyACFb06bqWzvHtQJTND8Y0j5Y2SBnSCqV2zN
# HSVts4+aUfkUhsKS+GAXS3j5XUgYA7SMNog76Nnss5l01nEX7sHDdYykYhzuQKFr
# T70XVTZeX25tSBfy3VaczYd1JSI/9wOGqbFU52NyrlsA1qimxOhsuds7Pxo+jO3R
# jV/kC+AEOoVaXDdminsc3PtlBCVh/sgYno9AUymblSRmee1gwlnlZJ0uiHKI9q2H
# FgZWM10yPG5gVt0prXnJFi1Wxmmg+BH/AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQU
# FFvO8o1eNcSCIQZMvqGfdNL+pqowHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacb
# UzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAo
# MSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1w
# JTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggr
# BgEFBQcDCDANBgkqhkiG9w0BAQsFAAOCAgEAykuUgTc1KMszMgsHbhgjgEGv/dCH
# Ff0by99C45SR770/udCNNeqlT610Ehz13xGFU6Hci+TLUPUnhvUnSuz7xkiWRru5
# RjZZmSonEVv8npa3z1QveUfngtyi0Jd6qlSykoEVJ6tDuR1Kw9xU9yvthZWhQs/y
# myOwh+mxt0C9wbeLJ92er2vc9ly12pFxbCNDJ+mQ7v520hAvreWqZ02GOJhw0R4c
# 1iP39iNBzHOoz+DsO0sYjwhaz9HrvYMEzOD1MJdLPWfUFsZ//iTd3jzEykk02Wjn
# ZNzIe2ENfmQ/KblGXHeSe8JYqimTFxl5keMfLUELjAh0mhQ1vLCJZ20BwC4O57Eg
# 7yO/YuBno+4RrV0CD2gp4BO10KFW2SQ/MhvRWK7HbgS6Bzt70rkIeSUto7pRkHMq
# rnhubITcXddky6GtZsmwM3hvqXuStMeU1W5NN3HA8ypjPLd/bomfGx96Huw8Orft
# cQvk7thdNu4JhAyKUXUP7dKMCJfrOdplg0j1tE0aiE+pDTSQVmPzGezCL42slyPJ
# VXpu4xxE0hpACr2ua0LHv/LB6RV5C4CO4Ms/pfal//F3O+hJZe5ixevzKNkXXbxP
# Oa1R+SIrW/rHZM6RIDLTJxTGFDM1hQDyafGu9S/a7umkvilgBHNxZfk0IYE7RRWJ
# cG7oiY+FGdx1cs0wggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0G
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
# oYIC0jCCAjsCAQEwgfyhgdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0
# byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4OTdBLUUzNTYtMTcwMTEl
# MCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsO
# AwIaAxUAW6h6/24WCo7WZz6CEVAeLztcmD6ggYMwgYCkfjB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOcAnskwIhgPMjAyMjEw
# MjQwOTE5MDVaGA8yMDIyMTAyNTA5MTkwNVowdzA9BgorBgEEAYRZCgQBMS8wLTAK
# AgUA5wCeyQIBADAKAgEAAgIJgwIB/zAHAgEAAgIRgTAKAgUA5wHwSQIBADA2Bgor
# BgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAID
# AYagMA0GCSqGSIb3DQEBBQUAA4GBABZziOAoaN8AU5C0JMeb3vE6ZdplPu90whws
# xgWJVbPNqJbgfCl3B5UFoIiFlD3A6dDYgxCdSygHZDrxi9UoxaVtFc1BbLYc2D8h
# /q4pw5caJCLTRxM2BnBcrCuTVkYCgQjtJqNw8SgLiuY6RYLP+G0qlnR8cNNZ/RkA
# tGc8blNyMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTACEzMAAAGrCQnvq2PU6KkAAQAAAaswDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqG
# SIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQghQDgQhtsJm6e
# g8GiJ4jUHeR19IK5qMbDX36IvvS32ckwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHk
# MIG9BCAOHK/6sIVgEVSVD3Arvk6OyQKvRxFHKyraUzbN1/AKVzCBmDCBgKR+MHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABqwkJ76tj1OipAAEAAAGr
# MCIEIApPmeKJTWfspCYG29vw4Cw3IBMBXachoUPQSKqwKEZBMA0GCSqGSIb3DQEB
# CwUABIICAFgoa573ouMPgj66A024IzCi2r0acsTPcvjREci6T3JR5bsMIe7vc2Zx
# KmUXoaeJKuaHOU8jr/Wz+G/45UXbortywx9MSdXm33zDmOSXNnm5t28XDbbuPayn
# v/UKuz/DZrL5JE5iKLA/F0B785EbzPRC1GXgETdHcPc2gN5AfdWp6yHA3Gnw0gHJ
# SgAz1du2M69jtKomJ/PUXH3D21A6pf0wSrAJLmfzeoR5dfUYDQj+fwwYmWwOH8qE
# uRZSmr7aDhjNXigJ723ja8zfR+0VcLMGknMr7SX37awUoDjWJavigC/A1gjSQFVd
# tNAynBSfoa2nVVL43boedgXCjYqe99ROHvTYl8eMJUq+laAI3TKv6BuVAom1Xly8
# fD9LowjiSBlGYrNmaeijvMidQLaxG4UcFP2/vmOZG59YjMNmPpvsc8xo9alY8hNC
# wJsaQ6N2cNcD4/eNrSdvYk7JIR8Mr4U8MiOM8Egh9RkrqoXvMDJ9k/hdUNdzH96c
# nQM/aEOv9TqDoP4N/cewkWcZadX7Eg022TBcjoT5drhYjyLvpKqZxt2KdY6tEMff
# Ln6gtlIEM1HD7m4m/VM2stxmuRTUw8/grx140VdplZQuFHCFDjEGquaI2fQiKgAH
# buVEpqeeS8C8VpO2ZBpURjQq+QxmOgyFQd0c84FKDnx7pvksJhg0
# SIG # End signature block
