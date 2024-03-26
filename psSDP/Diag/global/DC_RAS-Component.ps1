#************************************************
# DC_RAS-Component.ps1
# Version 1.0
#   Collects registry and netsh information.
# Version 1.1
#   Commented out "ras show activeservers". <- On Win7, this caused a Windows Firewall prompt to allow RAS server advertisements
#   Commented out "ras show user" <- This command enumerates all User accounts from the Active Directory and their Dial-in Settings, which can take a very long time in a big enterprise environment.
# Version 1.2
#   Corrected the section that collects RAS Tracing logs.
# Date: 2009, 2013, 2014
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: Collects information about RAS.
# Called from: Main Networking Diag, etc
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

Import-LocalizedData -BindingVariable RasTracingStrings
Write-DiagProgress -Activity $RasTracingStrings.ID_RasTracingLogs -Status $RasTracingStrings.ID_RasTracingLogsDesc

$sectionDescription = "RAS Component"

function RunNetSH ([string]$NetSHCommandToExecute="")
{
	Write-DiagProgress -Activity $RasTracingStrings.ID_RasNetsh -Status "netsh $NetSHCommandToExecute"
	
	$NetSHCommandToExecuteLength = $NetSHCommandToExecute.Length + 6
	"-" * ($NetSHCommandToExecuteLength) + "`r`n" + "netsh $NetSHCommandToExecute" + "`r`n" + "-" * ($NetSHCommandToExecuteLength) | Out-File -FilePath $OutputFile -append

	$CommandToExecute = "cmd.exe /c netsh.exe " + $NetSHCommandToExecute + " >> $OutputFile "
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
	"`n"		| Out-File -FilePath $OutputFile -append
	"`n"		| Out-File -FilePath $OutputFile -append
	"`n"		| Out-File -FilePath $OutputFile -append
}


#----------Log Files
$RasTracing = "$Env:windir\tracing"
if (Test-Path -Path $RasTracing)
{
	if (-not (Test-Path($PWD.Path + "\RasTracingDir"))) {[void](New-Item $Pwd.Path -Name RasTracingDir -ItemType directory | Out-Null )}
	$RasTracingPath =  $Pwd.Path + "\RasTracingDir"
	Copy-Item  -Path "$Env:windir\tracing\*.*" -Destination $RasTracingPath
	$RasTracingFiles = $RasTracingPath + "\*.*"
	$RasTracingLogs = $ComputerName + "_RasTracingLogs.zip" 
	$zipComp = CompressCollectFiles -NumberofDays 10 -filesToCollect $RasTracingFiles -DestinationFileName $RasTracingLogs -renameOutput $false -fileDescription "RAS Tracing Logs" -sectionDescription $sectionDescription
	if ($zipComp) { Write-Verbose "_... zipped $RasTracingFiles"
		Remove-Item  -Path $RasTracingFiles -Recurse
		Remove-Item $Pwd.Path`\RasTracingDir }
}


#----------Registry
$OutputFile= $Computername + "_RAS_reg_.TXT"
$CurrentVersionKeys =   "HKLM\System\CurrentControlSet\services\RasMan"

RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -OutputFile $OutputFile -fileDescription "RAS registry output" -SectionDescription $sectionDescription



#----------Netsh
$OutputFile = $ComputerName + "_RAS_netsh_ras-output.TXT"
"===================================================="	| Out-File -FilePath $OutputFile -append
"RAS Netsh Output"										| Out-File -FilePath $OutputFile -append
"===================================================="	| Out-File -FilePath $OutputFile -append
"Overview"												| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"	| Out-File -FilePath $OutputFile -append
"   1. netsh ras aaaa show accounting"					| Out-File -FilePath $OutputFile -append
"   2. netsh ras aaaa show acctserver"					| Out-File -FilePath $OutputFile -append
"   3. netsh ras aaaa show authentication"				| Out-File -FilePath $OutputFile -append
"   4. netsh ras aaaa show authserver"					| Out-File -FilePath $OutputFile -append
"   5. netsh ras aaaa show ipsecpolicy"					| Out-File -FilePath $OutputFile -append
"   6. netsh ras demanddial show interface"				| Out-File -FilePath $OutputFile -append
"   7. netsh ras demanddial show"						| Out-File -FilePath $OutputFile -append
"   8. netsh ras diagnostics show tracefacilities"		| Out-File -FilePath $OutputFile -append
"   9. netsh ras ip show config"						| Out-File -FilePath $OutputFile -append
"  10. netsh ras ip show preferredadapter"				| Out-File -FilePath $OutputFile -append
"  11. netsh ras ipv6 show config"						| Out-File -FilePath $OutputFile -append
"  12. netsh ras show authmode"							| Out-File -FilePath $OutputFile -append
"  13. netsh ras show authtype"							| Out-File -FilePath $OutputFile -append
"  14. netsh ras show client"							| Out-File -FilePath $OutputFile -append
"  15. netsh ras show conf"								| Out-File -FilePath $OutputFile -append
"  16. netsh ras show ikev2connection"					| Out-File -FilePath $OutputFile -append
"  17. netsh ras show ikev2saexpiry"					| Out-File -FilePath $OutputFile -append
"  18. netsh ras show link"								| Out-File -FilePath $OutputFile -append
"  19. netsh ras show multilink"						| Out-File -FilePath $OutputFile -append
"  20. netsh ras show portstatus"						| Out-File -FilePath $OutputFile -append
"  21. netsh ras show registeredserver"					| Out-File -FilePath $OutputFile -append
"  22. netsh ras show sstp-ssl-cert"					| Out-File -FilePath $OutputFile -append
"  23. netsh ras show status"							| Out-File -FilePath $OutputFile -append
"  24. netsh ras show type"								| Out-File -FilePath $OutputFile -append
"  25. netsh ras show wanports"							| Out-File -FilePath $OutputFile -append
"===================================================="	| Out-File -FilePath $OutputFile -append
"`n`n`n`n`n"											| Out-File -FilePath $OutputFile -append


"__ value of Switch skipHang: $Global:skipHang  - 'True' will suppress output for: NetSh ras show client `n`n"	| Out-File -FilePath $OutputFile -append

RunNetSH -NetSHCommandToExecute "ras aaaa show accounting"
RunNetSH -NetSHCommandToExecute "ras aaaa show acctserver"
RunNetSH -NetSHCommandToExecute "ras aaaa show authentication"
RunNetSH -NetSHCommandToExecute "ras aaaa show authserver"
RunNetSH -NetSHCommandToExecute "ras aaaa show ipsecpolicy"
RunNetSH -NetSHCommandToExecute "ras demanddial show interface"
RunNetSH -NetSHCommandToExecute "ras demanddial show"
RunNetSH -NetSHCommandToExecute "ras diagnostics show tracefacilities"
RunNetSH -NetSHCommandToExecute "ras ip show config"
RunNetSH -NetSHCommandToExecute "ras ip show preferredadapter"
RunNetSH -NetSHCommandToExecute "ras ipv6 show config"
# RunNetSH -NetSHCommandToExecute "ras show activeservers"              <- On Win7, this caused a Windows Firewall prompt to allow RAS server advertisements
RunNetSH -NetSHCommandToExecute "ras show authmode"
RunNetSH -NetSHCommandToExecute "ras show authtype"
if ($Global:skipHang -ne $true) {
	RunNetSH -NetSHCommandToExecute "ras show client"
	}
RunNetSH -NetSHCommandToExecute "ras show conf"
RunNetSH -NetSHCommandToExecute "ras show ikev2connection"
RunNetSH -NetSHCommandToExecute "ras show ikev2saexpiry"
RunNetSH -NetSHCommandToExecute "ras show link"
RunNetSH -NetSHCommandToExecute "ras show multilink"
RunNetSH -NetSHCommandToExecute "ras show portstatus"
RunNetSH -NetSHCommandToExecute "ras show registeredserver"
RunNetSH -NetSHCommandToExecute "ras show sstp-ssl-cert"
RunNetSH -NetSHCommandToExecute "ras show status"
RunNetSH -NetSHCommandToExecute "ras show type"
# RunNetSH -NetSHCommandToExecute "ras show user"                       <- This command enumerates  all User accounts from the Active Directory and their Dial-in Settings, which can take a very long time in a big enterprise environment.
RunNetSH -NetSHCommandToExecute "ras show wanports"

CollectFiles -sectionDescription $sectionDescription -fileDescription "RAS netsh output" -filesToCollect $OutputFile


# SIG # Begin signature block
# MIInpwYJKoZIhvcNAQcCoIInmDCCJ5QCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAnCLTO9PxRtuOv
# 6lKuSR+C7crEVf58guGBbd5ZLGqGQKCCDYUwggYDMIID66ADAgECAhMzAAACU+OD
# 3pbexW7MAAAAAAJTMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjEwOTAyMTgzMzAwWhcNMjIwOTAxMTgzMzAwWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDLhxHwq3OhH+4J+SX4qS/VQG8HybccH7tnG+BUqrXubfGuDFYPZ29uCuHfQlO1
# lygLgMpJ4Geh6/6poQ5VkDKfVssn6aA1PCzIh8iOPMQ9Mju3sLF9Sn+Pzuaie4BN
# rp0MuZLDEXgVYx2WNjmzqcxC7dY9SC3znOh5qUy2vnmWygC7b9kj0d3JrGtjc5q5
# 0WfV3WLXAQHkeRROsJFBZfXFGoSvRljFFUAjU/zdhP92P+1JiRRRikVy/sqIhMDY
# +7tVdzlE2fwnKOv9LShgKeyEevgMl0B1Fq7E2YeBZKF6KlhmYi9CE1350cnTUoU4
# YpQSnZo0YAnaenREDLfFGKTdAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUlZpLWIccXoxessA/DRbe26glhEMw
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzQ2NzU5ODAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AKVY+yKcJVVxf9W2vNkL5ufjOpqcvVOOOdVyjy1dmsO4O8khWhqrecdVZp09adOZ
# 8kcMtQ0U+oKx484Jg11cc4Ck0FyOBnp+YIFbOxYCqzaqMcaRAgy48n1tbz/EFYiF
# zJmMiGnlgWFCStONPvQOBD2y/Ej3qBRnGy9EZS1EDlRN/8l5Rs3HX2lZhd9WuukR
# bUk83U99TPJyo12cU0Mb3n1HJv/JZpwSyqb3O0o4HExVJSkwN1m42fSVIVtXVVSa
# YZiVpv32GoD/dyAS/gyplfR6FI3RnCOomzlycSqoz0zBCPFiCMhVhQ6qn+J0GhgR
# BJvGKizw+5lTfnBFoqKZJDROz+uGDl9tw6JvnVqAZKGrWv/CsYaegaPePFrAVSxA
# yUwOFTkAqtNC8uAee+rv2V5xLw8FfpKJ5yKiMKnCKrIaFQDr5AZ7f2ejGGDf+8Tz
# OiK1AgBvOW3iTEEa/at8Z4+s1CmnEAkAi0cLjB72CJedU1LAswdOCWM2MDIZVo9j
# 0T74OkJLTjPd3WNEyw0rBXTyhlbYQsYt7ElT2l2TTlF5EmpVixGtj4ChNjWoKr9y
# TAqtadd2Ym5FNB792GzwNwa631BPCgBJmcRpFKXt0VEQq7UXVNYBiBRd+x4yvjqq
# 5aF7XC5nXCgjbCk7IXwmOphNuNDNiRq83Ejjnc7mxrJGMIIHejCCBWKgAwIBAgIK
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
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGXgwghl0AgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAAJT44Pelt7FbswAAAAA
# AlMwDQYJYIZIAWUDBAIBBQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJuY
# 55yktfIPMyoYQCgk5rwe61Q2OyY2REn1wnC/jr0bMEQGCisGAQQBgjcCAQwxNjA0
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQu
# Y29tIDANBgkqhkiG9w0BAQEFAASCAQBY1lsyGQgywH9VwQEMuByp/D1Ow9Rjo7Ca
# snd0aAQBAXaSqveoBPh/8/CNDHpKUsJdRpuwWdTHLGqTyLmTHIB8aoYCJaBbMIqO
# sk+3DtRtq+cTq9KKq5LEKbdjsWPN399ipNDFWNYJSNj2vWYYEuhhm6bD9FSaJKak
# Rt3qHHjztULQZzbgv1pp3kFKWr5vqTDbClGwQVRULcOHnjzgVUOWIgtA3hayDbEP
# P+VrWIryQnaVv9/oL8NGTJMpOBhU4fdM7zi9jJ0nJKjxeYbkXZvrgK9t0ICo4eup
# Dl4XUEYxwa5LM5SeUqsWAP3qYVVGn91oUSoUVCdUrgpzaU/iRSrVoYIXADCCFvwG
# CisGAQQBgjcDAwExghbsMIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglg
# hkgBZQMEAgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEE
# AYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIOKLcyPuHJRYRtJRoYbRwIATj3Az0V9z
# pdHTr7dwo0kGAgZigqXS9RUYEzIwMjIwNjAyMTIyMDI2LjIxNFowBIACAfSggdCk
# gc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNV
# BAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxl
# cyBUU1MgRVNOOjhBODItRTM0Ri05RERBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloIIRVzCCBwwwggT0oAMCAQICEzMAAAGZyI+vrbZ9vosA
# AQAAAZkwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwHhcNMjExMjAyMTkwNTE2WhcNMjMwMjI4MTkwNTE2WjCByjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFt
# ZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046OEE4Mi1F
# MzRGLTlEREExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC4E/lXXKMsy9rVa2a8bRb0
# Ar/Pj4+bKiAgMgKayvCMFn3ddGof8eWFgJWp5JdKjWjrnmW1r9tHpcP2kFpjXp2U
# drj55jt5NYi1MERcoIo+E29XuCwFAMJftGdvsWea/OTQPIFsZEWqEteXdRncyVwc
# t5xFzBIC1JWCdmfc7R59RMIyvgWjIz8356mweowkOstN1fe53KIJ8flrYILIQWsN
# RMOT3znAGwIb9kyL54C6jZjFxOSusGYmVQ+Gr/qZQELw1ipx9s5jNP1LSpOpfTEB
# Fu+y9KLNBmMBARkSPpTFkGEyGSwGGgSdOi6BU6FPK+6urZ830jrRemK4JkIJ9tQh
# lGcIhAjhcqZStn+38lRjVvrfbBI5EpI2NwlVIK2ibGW7sWeTAz/yNPNISUbQhGAJ
# se/OgGj/1qz/Ha9mqfYZ8BHchNxn08nWkqyrjrKicQyxuD8mCatTrVSbOJYfQyZd
# HR9a4vgyGeZEXBYQNAlIuB37QCOAgs/VeDU8M4dc/IlrTyC0uV1SS4Gk8zV+5X5e
# Ru+XORN8FWqzI6k/9y6cWwOWMK6aUN1XqLcaF/sm9rX84eKW2lhDc3C31WLjp8UO
# fOHZfPuyy54xfilnhhCPy4QKJ9jggoqqeeEhCEfgDYjy+PByV/e5HDB2xHdtlL93
# wltAkI3aCxo84kVPBCa0OwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFI26Vrg+nGWv
# rvIh0dQPEonENR0QMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8G
# A1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBs
# BggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# DQYJKoZIhvcNAQELBQADggIBAHGzWh29ibBNro3ns8E3EOHGsLB1Gzk90SFYUKBi
# lIu4jDbR7qbvXNd8nnl/z5D9LKgw3T81jqy5tMiWp+p4jYBBk3PRx1ySqLUfhF5Z
# MWolRzW+cQZGXV38iSmdAUG0CpR5x1rMdPIrTczVUFsOYGqmkoUQ/dRiVL4iAXJL
# CNTj4x3YwIQcCPt0ijJVinPIMAYzA8f99BbeiskyI0BHGAd0kGUX2I2/puYnlyS8
# toBnANjh21xgvEuaZ2dvRqvWk/i1XIlO67au/XCeMTvXhPOIUmq80U32Tifw3SSi
# BKTyir7moWH1i7H2q5QAnrBxuyy//ZsDfARDV/Atmj5jr6ATfRHDdUanQpeoBS+i
# ylNU6RARu8g+TMCu/ZndZmrs9w+8galUIGg+GmlNk07fXJ58Oc+qFqgNAsNkMi+d
# SzKkWGA4/klJFn0XichXL8+t7KOayXKGzQja6CdtCjisnyS8hbv4PKhaeMtf68wJ
# WKKOs0tt2AJfYC5vSbH9ck8BGj2e/yQXEZEu88L5/fHK5XUk/IKXx3zaLkxXTSZ4
# 3Ea/WKXVBzMasHZ3Pmny0moEekAXx1UhLNNYv4Vum33VirxSB6r/GKQxFSHu7yFf
# rWQpYyyDH119TmhAedS8T1VabqdtO5ZP2E14TK82Vyxy3xEPelOo4dRIlhm7XY6k
# 9B68MIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0B
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
# cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs4wggI3
# AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYD
# VQQLEx1UaGFsZXMgVFNTIEVTTjo4QTgyLUUzNEYtOUREQTElMCMGA1UEAxMcTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAku/zYujn
# qapN6BJ9MJ5jtgDrlOuggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDANBgkqhkiG9w0BAQUFAAIFAOZC5C0wIhgPMjAyMjA2MDIxNTI0MjlaGA8y
# MDIyMDYwMzE1MjQyOVowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5kLkLQIBADAK
# AgEAAgIC8AIB/zAHAgEAAgISGzAKAgUA5kQ1rQIBADA2BgorBgEEAYRZCgQCMSgw
# JjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3
# DQEBBQUAA4GBAAGiWRGWV4xdHSGUM1zfvPWUH5r11/ukB6J0muvyDcGz5rJJm6zz
# RpaqH3tkkMGtgeu5/FG6KYaVr153u8N165AadlPCB+WDX8rg9xdDpBZAs+BvBcN2
# P3drND4JPHJnnPcgwhsm2RdXtjhxGiRsjLyPHKIpbWoxiJ5hQlc03RnzMYIEDTCC
# BAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGZyI+v
# rbZ9vosAAQAAAZkwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsq
# hkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgRCcOkl2/negUM5DDW72AyIWfXjKi
# PqGXeOqIkex+4q8wgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBmfWn58qKN
# 7WWpBTYOrUO1BSCSnKPLC/G7wCOIc2JsfjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFBDQSAyMDEwAhMzAAABmciPr622fb6LAAEAAAGZMCIEICWQFRzxutOW
# Gl1hsRbYkKkR36D8jdYIqzhIL59olosdMA0GCSqGSIb3DQEBCwUABIICAGC3hh05
# oVBMwgjCT8ojhvNE9QX4ZRDI++Z6chACShdhrkMpefUFIlfx3PKJDGTzgFTwURGk
# VRkjpgliIUgak8Nr1FWrqS9F5Em53q14/TG3n+JSXUfpRYBj3tMnwr/hXt3Vbor3
# 9vrWJmYZDgfo+aF5BbCyX1VLKtnBy9mIQoY3WZEs8VWxw19zw3paaRxAil7acIIl
# /o/ZkQWjPU3Xr/Kz1QNF4ex2JJNPCoTWcLtUjZAmEX+Hn4stV9jjBnp79OyVwl72
# eSgmTI52R3tHuLsGvHW8V6U3fnJgx8lnmw6T4ufxQksyJwp3L/FiGQo4lSR8hmt5
# xXSQRzr9drzLicRx14NdNkvceGIeXPnSedPRtN+flYTMWiyFQSQmtyTrEo/p809/
# vD1vMQxJbqYA/oHrrhZ36YSP655SYG9YzeKVHiiqd8ai8dXaD7bRgBJf4rTbXLPZ
# 8tW21TtRcsSt6yCBIQVyw/V+FNrKOt7wna8MJMaJtLZIy5r6fRj4cFC7WL9lOriJ
# miQSUJKkRMXQw5slx3qNJmfFe6lcIcYEwOUi5srR0niZJs4x3d1KIlZnYqJXEQwk
# o+SJxXnUfRPtcZ5XO5L4VzWhzR7wGwq+X/QhXNotfv93SSMjgKGUMWm7BL4bjX8n
# twUWgxxX0Bt3R73c3FFKTJLmD5LTm1I+Wu8U
# SIG # End signature block
