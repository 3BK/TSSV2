###########################################################################
# DC_Query_Registry
# Version 1.0
# Date: 09-26-2012
# Author: mifannin
# Description: Queries the registry and exports the services hive
###########################################################################

#$SystemRoot = $Env:SystemRoot

Import-LocalizedData -BindingVariable Reg -FileName DC_Query_Registry -UICulture en-us
Write-DiagProgress -Activity $Reg.ID_Reg  -Status $Reg.ID_RegQuery
"Start collecting registry data" | WriteTo-StdOut 

function query_registry ($key)
	{
		$CommandLineToExecute = "cmd.exe /c reg.exe query $key >> $OutputFile"
		$Header = "Querying Registry: " + $key + ":"
		$Header | Out-File $OutputFile -Append
		$Header | WriteTo-StdOut 
		Write-DiagProgress -Activity $Reg.ID_Reg  -Status $key
		RunCMD -commandToRun $CommandLineToExecute
	}


#Querying Registry: HKLM\Software\Microsoft\Windows\CurrentVersion\Policies
$OutputFile = $Computername + "_HKLM_Policies.txt"
$key = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies /s"
query_registry $key 

#Querying Registry: HKLM\Software\Policies
$Key = "HKLM\Software\Policies /s"
query_registry $key 
CollectFiles -filesToCollect $OutputFile -fileDescription "Policies Key" -sectionDescription "Registry Data"

#########################################################################
#Querying Registry: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer 
$OutputFile = $Computername + "_HKEY_Internet_Explorer.txt"
$Key = "`"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer`" /s"
query_registry $key 

#Querying Registry: HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer 
$Key = "`"HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer`" /s"
query_registry $key 
CollectFiles -filesToCollect $OutputFile -fileDescription "Internet Explorer Key" -sectionDescription "Internet Explorer"

#########################################################################
#Querying Registry: HKCU\Software\Policies
$OutputFile = $Computername + "_HKCU_Policies.txt"
$Key = "`"HKCU\Software\Policies`" /s"
query_registry $key 
CollectFiles -filesToCollect $OutputFile -fileDescription "HKCU\Software\Policies Key" -sectionDescription "System Information"

#########################################################################
#Querying Registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings 
$OutputFile = $Computername + "_HKEY_Internet_Settings.txt"
$Key = "`"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`" /s"
query_registry $key 


#Internet Settings from the Local Machine profile: Used by localSystem 
#Querying Registry: HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings 
$Key =  "`"HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings`" /s"
query_registry $key 

#Internet Settings from the .Default profile: Used by localSystem 
#Querying Registry: HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings 
$Key = "`"HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings`" /s"
query_registry $key 
CollectFiles -filesToCollect $OutputFile -fileDescription "Internet Settings Key" -sectionDescription "Internet Explorer"


#########################################################################
#Querying Registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing 
$OutputFile = $Computername + "_HKLM_CBS.txt"
$Key = "`"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing`" /s"
query_registry $key 
CollectFiles -filesToCollect $OutputFile -fileDescription "CBS Key" -sectionDescription "CBS Information"

#########################################################################
#Querying Registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer
$OutputFile = $Computername + "_HKLM_Installer.txt"
$key = "`"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer`" /s"
query_registry $key 
CollectFiles -filesToCollect $OutputFile -fileDescription "Installer Key" -sectionDescription "Registry Data"

#########################################################################
#Querying Registry: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MUI\UILanguages 
$OutputFile = $Computername + "_HKLM_MUILanguagePack.txt"
$key = "HKLM\SYSTEM\CurrentControlSet\Control\MUI\UILanguages /s"
query_registry $key 
CollectFiles -filesToCollect $OutputFile -fileDescription "UI Languages Key" -sectionDescription "Registry Data"

#########################################################################
#Querying Registry: HKLM\Software\Microsoft\OLE 
$OutputFile = $Computername + "_HKLM_OLE.txt"
$Key = "HKLM\Software\Microsoft\OLE /s"
query_registry $key 
CollectFiles -filesToCollect $OutputFile -fileDescription "OLE Key" -sectionDescription "Registry Data"

#########################################################################
#Querying Registry: HKLM\Software\Microsoft\Windows\CurrentVersion\Setup
$OutputFile = $Computername + "_HKLM_Setup.txt"
$Key = "HKLM\Software\Microsoft\Windows\CurrentVersion\Setup /s"
query_registry $key 
CollectFiles -filesToCollect $OutputFile -fileDescription "Setup Key" -sectionDescription "Registry Data"

#########################################################################
#Querying Registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall 
$OutputFile = $Computername + "_HKLM_Uninstall.txt"
$key = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s"
query_registry $key 
CollectFiles -filesToCollect $OutputFile -fileDescription "Uninstall Key" -sectionDescription "Registry Data"

#if (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -lt 2)) #_#
#	{
#########################################################################
#Querying Registry: HKLM\SOFTWARE\Microsoft\Updates 
$OutputFile = $Computername + "_HKLM_Updates.txt"
$key = "HKLM\SOFTWARE\Microsoft\Updates /s"
query_registry $key 
CollectFiles -filesToCollect $OutputFile -fileDescription "Updates Key" -sectionDescription "Registry Data"
#	}

#########################################################################
#Querying Registry: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
$OutputFile = $Computername + "_HKLM_Winlogon.txt"
$key = "`"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`" /s"
query_registry $key 
CollectFiles -filesToCollect $OutputFile -fileDescription "Winlogon Key" -sectionDescription "Registry Data"

#########################################################################
#Querying Registry: HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate 
$OutputFile = $Computername + "_HKLM_WindowsUpdate_Client.txt"
$key = "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate /s"
query_registry $key 
CollectFiles -filesToCollect $OutputFile -fileDescription "Windows Updates Client Key" -sectionDescription "Windows Update Information"

if (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -lt 2)) #_#
	{
	#########################################################################
	#Querying Registry: HKLM\SOFTWARE\Policies\Microsoft\windows\WindowsUpdate 
	$OutputFile = $Computername + "_HKEY_WindowsUpdate_Policies.txt"
	$Key = "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /s"
	query_registry $key 

	$key = "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /s"
	query_registry $key 

	$Key = "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate"
	query_registry $key 
	CollectFiles -filesToCollect $OutputFile -fileDescription "Windows Updates Policies Key" -sectionDescription "Windows Update Information"
	}
#########################################################################
#Gathering PID and Registration information
$OutputFile = $ComputerName + "_PID.txt"
$key = "`"HKLM\SOFTWARE\Microsoft\Internet Explorer\Registration`" /s"
query_registry $key 
if (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -lt 1)) #_#
	{
	$key = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion /v ProductID"
	query_registry $key 
	}
$key = "`"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`" /v ProductID"
query_registry $key 
CollectFiles -filesToCollect $OutputFile -fileDescription "PID Keys" -sectionDescription "Registry Data"

#########################################################################
#Gathering WU Service Information
$OutputFile = $ComputerName + "_svcRegistration.txt"
$key = "`"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost`" /s"
query_registry $key 
$key = "HKLM\SYSTEM\CurrentControlSet\Services\BITS /s"
query_registry $key 
$key = "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv /s"
query_registry $key 
CollectFiles -filesToCollect $OutputFile -fileDescription "Service Registration" -sectionDescription "Windows Update Information"

#########################################################################
#Query Registry for hotfix information
#First check for hidden files in the Windows folder
#If ($OSVersion.Major -lt 6)
#{
	$OutputFile = $ComputerName + "_Hotfix.txt"
	Set-Content $OutputFile "Hidden Files in Windows Folder `n" -Encoding ascii
	Get-ChildItem $Env:windir -force | Where-Object {$_.mode -match "h"} | Out-File $OutputFile -Append 
	$Blocks = "===[Old Hotfix regkey]============================================================ `n"
	if (Test-path "HKLM:Software\Microsoft\Hotfix") {
		Add-Content $OutputFile $Blocks 
		$key = "HKLM\Software\Microsoft\Hotfix /s"
		query_registry $key 
	}
	if (Test-path "HKLM:Software\Microsoft\Windows NT\CurrentVersion\Hotfix") {
		$Blocks = "===[Hotfix regkey]================================================================ `n"
		Add-Content $OutputFile $Blocks
		$key = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Hotfix /s"
		query_registry $key
	}
	CollectFiles -filesToCollect $OutputFile -fileDescription "Hotfix Keys" -sectionDescription "Registry Data"
	query_registry $key
#}

#########################################################################
#Collect Session Manager Key
$OutputFile = $ComputerName + "_SessionManager_Key.txt"
Set-Content $OutputFile "Querying Registry: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager " -Encoding unknown
$key = "`"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`""
query_registry $key 

add-content -Encoding unknown $OutputFile "`n`nQuerying Registry: HKLM\COMPONENTS Key "
Add-Content -Encoding unknown $OutputFile "For Pending restart issues look for existence of: `
RegValue: PendingXmlIdentifier`
RegValue: NextQueueEntryIndex`
RegValue: AdvancedInstallersNeedResolving`
RegValue: ImpactfulTransactionCommitsDisabled`
Filename: C:Windows\winsxs\pending.xml`
======================================================================== `n "
$CommandLineToExecute = "cmd.exe /c reg.exe query HKLM\COMPONENTS >> $OutputFile"
RunCMD commandToRun $CommandLineToExecute 

CollectFiles -filesToCollect $OutputFile -fileDescription "Session Manager Key" -sectionDescription "Registry Data"

#########################################################################
if (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -lt 1)) #_#
	{
	#Gathering CSDVersion
	$OutputFile = $ComputerName + "_CSDVersion.txt"
	$key = "HKLM\SYSTEM\CurrentControlSet\Control\Windows\CSDVersion"
	query_registry $key 

	$key = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CSDVersion"
	query_registry $key 
	}

$key = "`"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`""
query_registry $key 

CollectFiles -filesToCollect $OutputFile -fileDescription "CSD Version" -sectionDescription "Registry Data"

#########################################################################
#Collect Services hive and txt

$OutputFile = $ComputerName + "_Services_Key.txt"
$key = "HKLM\SYSTEM\CurrentControlSet\Services /s"
query_registry $key 
CollectFiles -filesToCollect $OutputFile -fileDescription "Services Key" -sectionDescription "System Information"

Write-DiagProgress -Activity $Reg.ID_Reg  -Status $Reg.ID_RegHiv

$OutputFile = $ComputerName + "_Services_Key.hiv"
$CommandLineToExecute = "cmd.exe /c reg.exe save HKLM\SYSTEM\CurrentControlSet\Services $OutputFile"
RunCMD -commandToRun $CommandLineToExecute 
CollectFiles -filesToCollect $OutputFile -fileDescription "Services Hive" -sectionDescription "System Information"

"Finished collecting registry data" | WriteTo-StdOut 
# SIG # Begin signature block
# MIIjiAYJKoZIhvcNAQcCoIIjeTCCI3UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD8zN7cWSTJxrA6
# PubEHRO8cWjY5/U3L6ow2+YIkgWV76CCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVXTCCFVkCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBpDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgaAHE0PbK
# AVZ39uheThZG5FyJMtOpLKT/TGBArtaJH5swOAYKKwYBBAGCNwIBDDEqMCigCIAG
# AFQAUwBToRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20gMA0GCSqGSIb3DQEB
# AQUABIIBABP3OqkZ/of6bb5bK/pWA4OMwr7XMBT9cZWnrQlwP61uTeT0LU11b9Ym
# IiBQszV4IQP7wA0xmXgkckbOlfTpqcdqxfpo1LAcM/hBjqNtV8JV8tIwInQ59BMS
# OPurE0laqh4wl7nD1Yx4F+1G+9x41sTXXcpHxPmqKncSRSVdmmLaNJI9zN7TJDD/
# 22T2+12V1mML5QQ5v2MrOZbIEoz7Ks/nrRCqCcW0eRcvVf1KXtJ+5Mt38wDhmuEM
# xx7ZIi+Mlj0m07mDnnIgWKwfy0nYKl/RCXLt2IaOw76HqEOauUEUls7OQgNGX4ew
# kd6iifNFgOo7EwcNUvzdlNZevCDE/IChghLxMIIS7QYKKwYBBAGCNwMDATGCEt0w
# ghLZBgkqhkiG9w0BBwKgghLKMIISxgIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBVQYL
# KoZIhvcNAQkQAQSgggFEBIIBQDCCATwCAQEGCisGAQQBhFkKAwEwMTANBglghkgB
# ZQMEAgEFAAQg1lhCVgnKU3sI6QCfhrcUqTEjY5+iAf5hchqC/YgYMxkCBmGB2SqX
# MxgTMjAyMTExMTExNjUzMzYuOTI1WjAEgAIB9KCB1KSB0TCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkY3
# QTYtRTI1MS0xNTBBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloIIORDCCBPUwggPdoAMCAQICEzMAAAFZn/x+Xyzq8kMAAAAAAVkwDQYJKoZI
# hvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjEwMTE0
# MTkwMjE1WhcNMjIwNDExMTkwMjE1WjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVl
# cnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkY3QTYtRTI1MS0xNTBB
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArnjEYclnxIdES00igGj0AboyujyARkK3
# xaBX+Y10i3a0w4/fNVhTj6xGwibFPB/MkQMFZpNzsvGUTL/XfTZ9GZ39HanCdjun
# JP3TK9kCZBAtnoP59oYHDCGLmut7+2YEl1sBcVnyovYkNzi3EGffQyvULwMUF2si
# PBs/6LZF0A5pLAiz/FCwx5kDPe/mP1UR3Crz6IzphwtyoqtgDA/44TnzfvVJPmSP
# Z/uq5Oh5NeFK8NzMpitWiQvdmfT4o0CdumnisfW1fKaaBdByBULPUT8TLw0Sy9nU
# WNXlA/qi8MxPxgCjsrNpi9PgjH7ExW9b7X/UydhpqhHxsudDGZNk4wIDAQABo4IB
# GzCCARcwHQYDVR0OBBYEFPbQqYVGvK365Osn14jCPLLpN2PnMB8GA1UdIwQYMBaA
# FNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8y
# MDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAt
# MDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJ
# KoZIhvcNAQELBQADggEBAI2RVBLoD4GGt8Y4IBajcpy5Rrh6y2nPKf5kuWSHSkmY
# AmngRQOstayJ5gJ/ajKhzwqNUwL40cUVW8cutIyFadHkW1jqXdnpSv0hMFLPriPn
# BNFETy8ilCIdViNFU08ZHa2Kobmco/n6wPStkjjrg4U3Pift6sMk6lXsibUv+wDB
# 9f4YehziPmt+4C5BMVjzax1i+0czgtPHBX33u6GUWznagdql0VbUpe3q8zERedJf
# yyhB9R34z5ircnu51zpH3jUa7F93oDS95xXnomO+akKeDiNGSq4B7J/90qZBRpHV
# 8q8AsFECZmQBS1aKNL/cyR5C/+VS8dWjsY8XMn87fAkwggZxMIIEWaADAgECAgph
# CYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2
# NTVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvt
# fGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzX
# Tbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+T
# TJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9
# ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDp
# mc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIw
# EAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1V
# MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMB
# Af8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1Ud
# HwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3By
# b2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQRO
# MEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2Vy
# dHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIw
# gY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIg
# HQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4g
# HTANBgkqhkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7P
# BeKp/vpXbRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2
# zEBAQZvcXBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95
# gWXZqbVr5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7
# Yl+a21dA6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt
# 0uGc+R38ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2
# onGqBooPiRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA
# 3+cxB6STOvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7
# G4kqVDmyW9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Ki
# yc8ZQU3ghvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5X
# wdHeMMD9zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P
# 3nSISRKhggLSMIICOwIBATCB/KGB1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMg
# UHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkY3QTYtRTI1MS0x
# NTBBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEw
# BwYFKw4DAhoDFQAqdssAjx+E7nxIJaulmde9cRmyEaCBgzCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5TeMLjAiGA8y
# MDIxMTExMTE2MzM1MFoYDzIwMjExMTEyMTYzMzUwWjB3MD0GCisGAQQBhFkKBAEx
# LzAtMAoCBQDlN4wuAgEAMAoCAQACAiZVAgH/MAcCAQACAhF9MAoCBQDlON2uAgEA
# MDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAI
# AgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAPB+o9P5KuWdUoJBXwoX4L87nThTU
# 2S11U5IDYOUcrI26xNl/t9OaqJWivy8rytDWLl0U61OAH/Jw2SxZ3rdAwBepTDZW
# XANDRvwidcy0kqxaIjbS2bRgBXkoflMeDGktaA077jCjC5wtBW+J2FKoHzH3b8ed
# jKupzCxZBxWH66UxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAVmf/H5fLOryQwAAAAABWTANBglghkgBZQMEAgEFAKCCAUow
# GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCC4MLzk
# DQohWzSFJ5H1/hWZoKst4PoLq+82fjIo7CbKrTCB+gYLKoZIhvcNAQkQAi8xgeow
# gecwgeQwgb0EIAFYG8+/MOZ815LOYlPj50YD66P+qrv98qRSffqvE0PoMIGYMIGA
# pH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFZn/x+Xyzq8kMA
# AAAAAVkwIgQgcLVW3bJKbJiHgsAuVX1ytoKPdrXTVrHf9HHAbN3hmOwwDQYJKoZI
# hvcNAQELBQAEggEAmSJtAi+OxaSAnFdUjq8YqHW3bT1EmDH+vz5bGmYsQ8X7tCkT
# YQu5zyPv5AxhhHeEtvuAk989D9u1Y+2wfVqD+uwwwNUpKsagUJGJO0DV3XdJYSCA
# 1EbjjBUGb+DBwF5H9e2/jrl+BQ8jFshEJ+99u2iAhtixjy/Hyh/0JRokXw+1dY3H
# hut6U2OglvURUYUPIkntJaUe1f1WD4EeNJxSwGPlOxSZKy4Vyec6Fhz7q+ptl4ck
# OLjqVX2mhJmi38aqEyWM34qDyc1TFVSxelsSDCz4OeFytuIiPNxyt9oZafCBRYlv
# eiDFMKs6uv9VHkwypTy3buAQYI8WlMjBGfBBqg==
# SIG # End signature block
