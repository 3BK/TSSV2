#************************************************
# DC_WinUpdateCollect.ps1
# Version 1.1
# Date: 2009-2019
# Author: Walter Eder (waltere@microsoft.com)
# Description: Collects WindowsUpdate information.
# Called from: TS_AutoAddCommands_Apps.ps1
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

Write-verbose "$(Get-Date -UFormat "%R:%S") : Start of script DC_WinUpdateCollect.ps1"
"Starting WinUpdateCollect.ps1 script" | WriteTo-StdOut
"============================================================" | WriteTo-StdOut
#_# Import-LocalizedData -BindingVariable ScriptStrings

# Registry keys
"Getting Windows Update Registry Keys." | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_WindowsUpdateRegistryKeys_Title -Status $ScriptStrings.ID_WindowsUpdateRegistryKeys_Status

$Regkeys = "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate"
$OutputFile = $ComputerName + "_reg_WindowsStoreWU_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "WindowsStoreWU Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" 
$OutputFile = $ComputerName + "_reg_WindowsUpdatePolicy_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "WindowsUpdate Policy Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate" 
$OutputFile = $ComputerName + "_reg_WindowsUpdate_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "WindowsUpdate Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx" 
$OutputFile = $ComputerName + "_reg_Appx_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "Appx Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKLM\Software\Microsoft\Windows\CurrentVersion\AppHost" 
$OutputFile = $ComputerName + "_reg_AppHost_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "AppHost Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\PluggableProtocols" 
$OutputFile = $ComputerName + "_reg_PluggableProtocols_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "Pluggable Protocols Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKLM\Software\Microsoft\Windows\Windows Error Reporting\BrokerUp" 
$OutputFile = $ComputerName + "_reg_BrokerUp_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "BrokerUp Registry Key" -SectionDescription "Software Registry keys" 

#_# $Regkeys = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel" 
#_# $OutputFile = $ComputerName + "_reg_AppModel_HKLM.txt"
#_# RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "AppModel Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKLM\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel" 
$OutputFile = $ComputerName + "_reg_Classes_AppModel_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "Classes AppModel Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKLM\Software\Policies\Microsoft\Windows\AppX" 
$OutputFile = $ComputerName + "_reg_Policies_AppX_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "Policies AppX Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" 
$OutputFile = $ComputerName + "_reg_InternetSettings_HKCU.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "InternetSettings Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" 
$OutputFile = $ComputerName + "_reg_AppHost_HKCU.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "HKCU AppHost Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel" 
$OutputFile = $ComputerName + "_reg_AppModel_HKCU.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "HKCU AppModel Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel" 
$OutputFile = $ComputerName + "_reg_Local_Settings_AppModel_HKCU.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "Local Settings AppModel Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer" 
$OutputFile = $ComputerName + "_reg_Local_Settings_AppContainer_HKCU.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "Local Settings AppContainer Registry Key" -SectionDescription "Software Registry keys"

# Saved Directories
"Getting copy of log files" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_Updatelogfiles_Title -Status $ScriptStrings.ID_Updatelogfiles_Status

$sectionDescription = "Update Log Files"
if(test-path "$env:localappdata\Microsoft\Windows\WindowsUpdate.log")
{	$OutputFile = $ComputerName + "_WindowsUpdate-Appdata.log"
	copy-item -Path "$env:localappdata\Microsoft\Windows\WindowsUpdate.log" -Destination $OutputFile -Force
	CollectFiles -filesToCollect $OutputFile -fileDescription "Local Appdata WindowsUpdate.Log" -sectionDescription $sectionDescription
}
if(test-path "$env:windir\windowsupdate.log")
{	$OutputFile = $ComputerName + "_WindowsUpdate-WinDir.log"
	copy-item -Path "$env:windir\windowsupdate.log" -Destination $OutputFile -Force
	CollectFiles -filesToCollect $OutputFile -fileDescription "Windows\WindowsUpdate.Log" -sectionDescription $sectionDescription
}
if(test-path "$env:windir\SoftwareDistribution\ReportingEvents.log")
{	$OutputFile = $ComputerName + "_ReportingEvents.log"
	copy-item -Path "$env:windir\SoftwareDistribution\ReportingEvents.log" -Destination $OutputFile -Force
	CollectFiles -filesToCollect $OutputFile -fileDescription "Windows\SoftwareDistribution\ReportingEvents.log" -sectionDescription $sectionDescription
}

# Directory Listings
"Getting Directory Listing of Windows Update files" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_WindowsUpdateFilesDirectoryListings_Title -Status $ScriptStrings.ID_WindowsUpdateFilesDirectoryListings_Status

$sectionDescription = "Windows Update Files Directory Listings"
if(test-path "$env:windir\SoftwareDistribution")
{	$OutputFile = $ComputerName + "_DirList_SoftwareDistributionDir.txt"
	Get-ChildItem -Recurse "$env:windir\SoftwareDistribution" >> $OutputFile
	CollectFiles -filesToCollect $OutputFile -fileDescription "Software Distribution Directory Listings" -sectionDescription $sectionDescription
}

# Permission Data
#Running BitsAdmin application
"Getting BitsAdmin Output" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_RunningBitsAdmin_Title -Status $ScriptStrings.ID_RunningBitsAdmin_Status
$OutputFile = $ComputerName + "_BitsJobs.log"
$CommandLineToExecute = "cmd.exe /c bitsadmin.exe /list > $OutputFile"
RunCmD -commandToRun $CommandLineToExecute -filesToCollect $OutputFile -fileDescription "BitsJobs log" -sectionDescription "BitsJobs Log Files"

# Event Data
$sectionDescription = "Event Logs"
$EventLogNames = "Microsoft-Windows-Bits-Client/Operational", "Microsoft-Windows-WindowsUpdateClient/Analytic", "Microsoft-Windows-WindowsUpdateClient", "Microsoft-Windows-WindowsUpdateClient/Operational"
Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription

Write-verbose "$(Get-Date -UFormat "%R:%S") :   end of script DC_WinUpdateCollect.ps1"

#Missing Service.txt
#Missing WinHttpProxy.log


# SIG # Begin signature block
# MIInrAYJKoZIhvcNAQcCoIInnTCCJ5kCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBhoBsBEEZLKfy1
# zy5zfzxYWgYCy9tyVLE+diPokoTgnaCCDYEwggX/MIID56ADAgECAhMzAAACzI61
# lqa90clOAAAAAALMMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NjAxWhcNMjMwNTExMjA0NjAxWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCiTbHs68bADvNud97NzcdP0zh0mRr4VpDv68KobjQFybVAuVgiINf9aG2zQtWK
# No6+2X2Ix65KGcBXuZyEi0oBUAAGnIe5O5q/Y0Ij0WwDyMWaVad2Te4r1Eic3HWH
# UfiiNjF0ETHKg3qa7DCyUqwsR9q5SaXuHlYCwM+m59Nl3jKnYnKLLfzhl13wImV9
# DF8N76ANkRyK6BYoc9I6hHF2MCTQYWbQ4fXgzKhgzj4zeabWgfu+ZJCiFLkogvc0
# RVb0x3DtyxMbl/3e45Eu+sn/x6EVwbJZVvtQYcmdGF1yAYht+JnNmWwAxL8MgHMz
# xEcoY1Q1JtstiY3+u3ulGMvhAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUiLhHjTKWzIqVIp+sM2rOHH11rfQw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDcwNTI5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAeA8D
# sOAHS53MTIHYu8bbXrO6yQtRD6JfyMWeXaLu3Nc8PDnFc1efYq/F3MGx/aiwNbcs
# J2MU7BKNWTP5JQVBA2GNIeR3mScXqnOsv1XqXPvZeISDVWLaBQzceItdIwgo6B13
# vxlkkSYMvB0Dr3Yw7/W9U4Wk5K/RDOnIGvmKqKi3AwyxlV1mpefy729FKaWT7edB
# d3I4+hldMY8sdfDPjWRtJzjMjXZs41OUOwtHccPazjjC7KndzvZHx/0VWL8n0NT/
# 404vftnXKifMZkS4p2sB3oK+6kCcsyWsgS/3eYGw1Fe4MOnin1RhgrW1rHPODJTG
# AUOmW4wc3Q6KKr2zve7sMDZe9tfylonPwhk971rX8qGw6LkrGFv31IJeJSe/aUbG
# dUDPkbrABbVvPElgoj5eP3REqx5jdfkQw7tOdWkhn0jDUh2uQen9Atj3RkJyHuR0
# GUsJVMWFJdkIO/gFwzoOGlHNsmxvpANV86/1qgb1oZXdrURpzJp53MsDaBY/pxOc
# J0Cvg6uWs3kQWgKk5aBzvsX95BzdItHTpVMtVPW4q41XEvbFmUP1n6oL5rdNdrTM
# j/HXMRk1KCksax1Vxo3qv+13cCsZAaQNaIAvt5LvkshZkDZIP//0Hnq7NnWeYR3z
# 4oFiw9N2n3bb9baQWuWPswG0Dq9YT9kb+Cs4qIIwggd6MIIFYqADAgECAgphDpDS
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZgTCCGX0CAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBsDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg50Z5y+4A
# MYCTQ8yLOhNtHqLmCymhlNFwi8qqKKslOLMwRAYKKwYBBAGCNwIBDDE2MDSgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20g
# MA0GCSqGSIb3DQEBAQUABIIBAD7OoOTJZK15IZtOTa2TA/W701vKfd4sgemtmIYN
# d4j2MlD3aMpTgv3GezOfuKJ7yltFbyyHg+vMI63Hr76LKnAAYh5RtjngGMmlvJWr
# M9oZZIxHQx+/hg3AA5a0eK+KQ5VBu+QTiHr3urMoYbGTJ/lBTxUiGRdv10UivbRB
# wJTh7K8t4Yc5WE/XEBWcS6uQvDLEfVp25qnxyVDSrC2Q1zgi1yTmK/iLmvx+N1uL
# ZKDVWHEpmncXZdvdWXmfBkbwSo/czh5QMw24+2UWyZ9FZcY9mxXGHrJnMz7O6kr0
# ccwU3yOGW9DuVmQP2uTd8pFnw9TuMw7Cz1nujNbUtPBTF6+hghcJMIIXBQYKKwYB
# BAGCNwMDATGCFvUwghbxBgkqhkiG9w0BBwKgghbiMIIW3gIBAzEPMA0GCWCGSAFl
# AwQCAQUAMIIBVQYLKoZIhvcNAQkQAQSgggFEBIIBQDCCATwCAQEGCisGAQQBhFkK
# AwEwMTANBglghkgBZQMEAgEFAAQg9Ow2PP/hTTltprQq1qyEepvmSjtLPLFNbHIW
# +prXIvQCBmNO64bE5hgTMjAyMjEwMjQwODE1MzYuMjg4WjAEgAIB9KCB1KSB0TCB
# zjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMg
# TWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxl
# cyBUU1MgRVNOOkQ5REUtRTM5QS00M0ZFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloIIRXDCCBxAwggT4oAMCAQICEzMAAAGsZryHIl3ePXsA
# AQAAAawwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwHhcNMjIwMzAyMTg1MTI5WhcNMjMwNTExMTg1MTI5WjCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQ5
# REUtRTM5QS00M0ZFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAx3gLUMUXYu7Hccwr
# wASUx1MXiIb1E7IpBYV6FNd74RfVA6tMEWeEwAo0chBajGQrVbrb+hBBCa0gejyy
# mEy3VamQs28Kbctryx1Uve38EDHtRaSZ++6MncoNpKC3dyVzm409SPt7fZTif8Sn
# 2g5z4+/8QdztcYfV8ZG8tFjPCjE/XGQqV66xsjNP9oqfpYLYGCA/OMdeKf0oTuSu
# IK6oD4k2GySR51MclAii1uVH6tlyx7FNKaM75ntHSZ94eJTwOe29m9n/1p31dSEP
# BQkUpnxlm/GeqdlfAViQMo1qBjyDToEXW8O6VuUCzoDiG4/V7um0oWmkHVVmQtQC
# YhbXHEkazeR6J0BNYhXHbawZXJ6ZpPb01+0On+NGwPD9qHC/U2S/pa/KSi8rSQM8
# hj1MJb1xFu9R4SWT74JUztwiquXxBjeaARDyiLjlXMQFe5jThjUqKNsYthEU1TKl
# cxEMClX6RyMby5JPXeZIJ/aIyFZFEvP3+PIjB7uWZfPjNTJhySv7Y2bwatKrl9UA
# +yEg7wBv9o6jr+h7cbdj5yKXyLJEksk3FsxjGJAkpm9vGUIin6kYidoPXfvczso8
# 8X/Jd5PiEbQupcq96WSC2WnN58+uZRW6mNhOB4Z+6lTAXPKZKTglE07W2FEHRsMo
# MjI0xWoS69XVTF1yuJxXSiOB4kcCAwEAAaOCATYwggEyMB0GA1UdDgQWBBRYEZ93
# BMsfQGdKPHxJWphawECOTTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnp
# cjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5j
# cmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQ
# Q0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMA0GCSqGSIb3DQEBCwUAA4ICAQB50LUCWFVccKV2Ty2gjMBb1DIhNxF7KFSm
# zW4PrvMILfTx9HNgURL/a8xfujQ5smDMLFPWeLS+RyzxYbYxQiyT3VEI8h4PNNAi
# 0imP1lPP2HS259woabdqGSdGzWGhXXaNEWRxqpcmjV+zK6gqAP4VNPaU6+sSw2Mm
# HnASyL48H+ZWaH8lrRW7yOFQlzWGsFRDliKxDg3TSydnCE6gJ49dt0PocazVyaxd
# luuRPy809hXwucjiXG4n9hphLbSpCvpj0MgcUM1jFltOWxB5ez8qOeFE10WIIagB
# wsdbB5Z5GzOHaJSEx9jX/v13uyiZ+PHpnIk9k6vh8TRRPaX+sFoFOug+kM6+lo6x
# joT+14ssx/KevpQ5B4TiVGLDn2yJUbIAaqlMFNt3MAUsEUfjS5uvtUSV2aOIdrXg
# SRnFi9yDMrEqq5vjKspp+j+P1pRvAusvZUwdZylrXwmG/rMiN3TUgaRR2PdQn4kp
# A0DPl7I/JBJk+33CzxvKeh0aUzmdiQcHLus++PjnL5nPuOsuCOC9kiLEazPCorIo
# njsA8fGsfwaMJC6xu9b00XgsBgqhlkaPs/CZAD5ebAPm19RDQq7MxEWYyk5TO2JM
# CAmNB/1My5zeliakVYSvySxh3CuOt1ZgAsJcD8hBcR0CKxDCPljNOyHhDFNSr69F
# LGz3fIHecjCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
# hvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# MjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAy
# MDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25Phdg
# M/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPF
# dvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6
# GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBp
# Dco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50Zu
# yjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3E
# XzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0
# lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1q
# GFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ
# +QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PA
# PBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkw
# EgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxG
# NSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARV
# MFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAK
# BggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMC
# AYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvX
# zpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20v
# cGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYI
# KwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG
# 9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0x
# M7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmC
# VgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449
# xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wM
# nosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDS
# PeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2d
# Y3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxn
# GSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+Crvs
# QWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokL
# jzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL
# 6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLP
# MIICOAIBATCB/KGB1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJp
# Y28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQ5REUtRTM5QS00M0ZFMSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoD
# FQCxGtITsLiwSf3oAyGM2RdnRjWKoKCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5wCqJDAiGA8yMDIyMTAyNDEw
# MDczMloYDzIwMjIxMDI1MTAwNzMyWjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDn
# AKokAgEAMAcCAQACAgTfMAcCAQACAhGaMAoCBQDnAfukAgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJ
# KoZIhvcNAQEFBQADgYEAlytETBaaFfsKDO4inYcOpg+400ER766dCU1FwLPdfTJR
# Fua/lRbtqb4VwPuRhJfCKBoEZEmCLhgxmRyUGJ5cKzCTTe0WtgJHdpCq0hks3EbX
# e8PslyI66pgYn8rVjRoK1cUqY9l90Rt+19HHpp1DVTe99jbpa/JT69HUV+d4suQx
# ggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AaxmvIciXd49ewABAAABrDANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkD
# MQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCBDjFuE/iQCmaRAspswSBdJ
# iwf2u7/KuEczSg4zuWA0hjCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIPm3
# AZKDOC8JcQBytXPnqbv0+n5tAl/7T4uDZ9oELML1MIGYMIGApH4wfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGsZryHIl3ePXsAAQAAAawwIgQgHsuU
# +nN3x8HEar890GC56vyXHE0aznZ8HgNGwgburRswDQYJKoZIhvcNAQELBQAEggIA
# GgauTIeLJHDn9Dt9Ct5VA6hFS5p/ho53OXyzkE5PEbjO13UxdLIQvKoAP2TV3QdD
# 3FHDUM3tpNW62n/AvDyWRuuU0qNj5JsDds211MNJTzyY/aVUOJW/mT/qkbmVzdG8
# UbKABibn8oFrlcgt2AioQOAEJwtEDDX+3e70QiM0mRvGDk4q8JvN0r43niTTdYjs
# NrzIj0ERDq5qsXiXmZqQvgZ5TCT4PgrtIUDkVNJcyboUIKxbhjaIBroguNV3I7KH
# DyZlrOS0yFbcFj2aqnK/Fsa9iRHFVbYDw9V32kMLRdW5wT2LISaX3IuZurNQuLtk
# 7AQkdSMQhpweqrQoc+S1K3+Tjec5qXScxTbjB9UXp+WH/q9OquDVnRPZqtne1jnf
# OhJy0Vl1OUgG71jxQ/A6J4PcHXi58m5UvQ4HPsmmA/Dly2OAVDTJS6X/jkj4zknN
# iHxbpNeG/viob0QqnBoHQS+Jb0UWJpwvrV5u3dO75ufvy0NYZfilqbt6Ul23REpJ
# 0wMvXK/1IJtKOnBajMJzPnXKrRdgJ4zGUj7SZpis3bDtRzrUioUAtmy5j025AlYi
# E1ycqlPmNreGKnULm0SU7BKLKDf5uZCiIaeoTUlJHH00X8Pe+r9VyXTj33kN1rZF
# eH6kN6mQNAfe5KRcBdqkFYOTtOLDo9W78pHLfzmdfEA=
# SIG # End signature block
