#************************************************
# Gather_Secure_Channel_Info.ps1
# Version 1.1
# Date: 3-30-2012
# Author: Tim Springston
# Description: This script queries the currently cached 
#              secure channel information for a domain member
#              or domain controller.
#			   -Added logic to detect OS ver and role and 
#			   reveal information about secure channels 
#			   selectively based on that.
#************************************************

Import-LocalizedData -BindingVariable MaxConcurrentApiLogStrings -FileName DC_SecureChannelInfo -UICulture en-us
Write-DiagProgress -Activity $MaxConcurrentApiLogStrings.ID_CTSMCASecureChannel -Status $MaxConcurrentApiLogStrings.ID_CTSMCAGetSecureChannelLog

#----- Gather Secure Channel Information

#For testing, dump OS version info into file.
#Get-CimInstance Win32_OperatingSystem >> $OutputFileName
$OSVersion = Get-CimInstance -Class Win32_OperatingSystem
#$ComputerName = Get-CimInstance -Class Win32_ComputerSystem
$OutputFileName = Join-Path $Pwd.Path ($ComputerName + "_Secure Channels.txt")

"Secure Channel Information" >> $OutputFileName 
"`n`r" >> $OutputFileName
"This script pulls the current secure channel for workstation computers and member servers, including the domain controller that the computer is looking to at that time." >>   $OutputFileName
"`n`r" >> $OutputFileName
"For domain controllers this script will gather the trust information for which DCs this DC has it's secure channel to at that time." >> $OutputFilename
"`n`r" >> $OutputFileName
"This script also gathers information about the local domain and forest." >> $OutputFileName
"`n`r" >> $OutputFileName
"`n`r" >> $OutputFileName

"This computer's Operating System and domain role (workstation, member server or domain controller)" >>   $OutputFileName
"******************************************************" >>   $OutputFileName
#Determine whether a workstation, server or DC and what OS
$OSVersion = Get-CimInstance -Class Win32_OperatingSystem #-ComputerName localhost
$cs = Get-CimInstance -class win32_computersystem
$DomainRole = $cs.domainrole
"`n`r" >> $OutputFileName
switch -regex ($DomainRole) {
[0-1] { "This computer is a workstation." >>   $OutputFileName
					if ($OSVersion.BuildNumber -eq 3790)
	{ "Operating system is Windows XP." >>   $OutputFileName}
	else
		{ if ($OSVersion.BuildNumber -eq 6002)
			{ "Operating system is Windows Vista." >>   $OutputFileName}
				else 
					{if ($OSVersion.BuildNumber -eq 7600)
						{"Operating system is Windows 7." >>   $OutputFileName}
						else 
							{if ($OSVersion.BuildNumber -eq 7601)
								{"Operating system is Windows 7." >>   $OutputFileName}
								else
									{}

									}}}
		}
[2-3] { "This computer is a member server."  >>   $OutputFileName
			if ($OSVersion.BuildNumber -eq 3790)
	{ "Operating system is Windows Server 2003." >>   $OutputFileName}
	else
		{ if ($OSVersion.BuildNumber -eq 6002)
			{ "Operating system is Windows Server 2008 RTM." >>   $OutputFileName}
				else 
					{if ($OSVersion.BuildNumber -eq 7600)
						{"Operating system is Windows Server 2008 R2." >>   $OutputFileName}
						else 
							{if ($OSVersion.BuildNumber -eq 7601)
								{"Operating system is Windows Server 2008 R2." >>   $OutputFileName}
								else
									{}

									}}}
		}
[4-5] { "This computer is a domain controller." >>   $OutputFileName 
					if ($OSVersion.BuildNumber -eq 3790)
	{ "Operating system is Windows Server 2003." >>   $OutputFileName}
	else
		{ if ($OSVersion.BuildNumber -eq 6002)
			{ "Operating system is Windows Server 2008 RTM." >>   $OutputFileName}
				else 
					{if ($OSVersion.BuildNumber -eq 7600)
						{"Operating system is Windows Server 2008 R2." >>   $OutputFileName}
						else 
							{if ($OSVersion.BuildNumber -eq 7601)
								{"Operating system is Windows Server 2008 R2." >>   $OutputFileName}
								else
									{}

									}}}
		}
default { "Unknown value."}
}

#Determine whether a workstation, server or DC
$cs = Get-CimInstance -class win32_computersystem
$DomainRole = $cs.domainrole

#Get only local domain secure channel info
$v = "select * from win32_ntdomain where domainname = '" + $env:userdomain + "'"
$v2 = Get-CimInstance -query $v

"`n`r" >> $OutputFileName
switch -regex ($DomainRole) {
[0-1] {"This computer's Secure Channel information."  >> $OutputFileName
"******************************************************" >>   $OutputFileName
$v2 >> $OutputFileName
	}
[2-3] {"This computer's Secure Channel information."  >> $OutputFileName
"******************************************************" >>   $OutputFileName
$v2 >> $OutputFileName
		}
[4-5] { "This domain controller's Trust Secure Channel information for all trusted domains." >> $OutputFileName
"******************************************************" >>   $OutputFileName
#Dump all secure channel info, including trusts.
$DCTrusts = Get-CimInstance win32_ntdomain 
$DCTrusts >> $OutputFileName 
		}
default { "Unknown value." >> $Outputfilename}
}

"General Domain Information" >> $OutputFilename
"******************************************************" >>   $OutputFileName
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domain >> $OutputFileName

# Collect Files
$fileDescription = "Cached values for Secure Channel info from Netlogon."
$sectionDescription = "Secure Channel Info"

CollectFiles -filesToCollect $OutputFileName -fileDescription $fileDescription -sectionDescription $sectionDescription -renameOutput $false -noFileExtensionsOnDescription

Trap{WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;Continue}



# SIG # Begin signature block
# MIInzwYJKoZIhvcNAQcCoIInwDCCJ7wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBW7MaxnJSvQ6nW
# tmFapebxs5lcKNnLgiW3PrQpW+ve+aCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZpDCCGaACAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBsDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgrE17zhO8
# Fdi2YUvBCgQNrNa8Q7RDIUO5Aw4GifNIFOkwRAYKKwYBBAGCNwIBDDE2MDSgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20g
# MA0GCSqGSIb3DQEBAQUABIIBAHlq4uTKDq3/irG2zQWR4B+oqnoh4Yt5jLEmCSRY
# 5FshC7LZr8dNmE8Rx16ZzFGA/VSYhkwbhfLObQxzZ4Ssb4ku80cvUG+dIaffYfWJ
# pCD7+dDIXBCT6rZeplNc6zz1ZhKe4IdwVo9EnGGxWAUkvCNNG+CAfTn6eFpnRb+U
# 89m412bU5u6g/8I29EFf5a/e5fuEl9B70piJK3ujVrsZFqT4FAUA6G/6AkhEvvod
# LdGwzspgFltXASjlz8m0AFfmh/6yqLfexOq4bwvRIB0kAnhU1cd7u9cUYz8cHvFd
# U34Qt4z7A9Vu1THgGyRvKKi7ivsKucN1+9/pbBCjqF6IpgGhghcsMIIXKAYKKwYB
# BAGCNwMDATGCFxgwghcUBgkqhkiG9w0BBwKgghcFMIIXAQIBAzEPMA0GCWCGSAFl
# AwQCAQUAMIIBWQYLKoZIhvcNAQkQAQSgggFIBIIBRDCCAUACAQEGCisGAQQBhFkK
# AwEwMTANBglghkgBZQMEAgEFAAQgW2YEC/95AngH0+bwZ7gsiP70qG8xcR+UosPc
# nJVqUGkCBmNP6wjwrRgTMjAyMjEwMjQwODE1MjguODE1WjAEgAIB9KCB2KSB1TCB
# 0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMk
# TWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjo4RDQxLTRCRjctQjNCNzElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaCCEXswggcnMIIFD6ADAgECAhMzAAABs/4lzikb
# G4ocAAEAAAGzMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwMB4XDTIyMDkyMDIwMjIwM1oXDTIzMTIxNDIwMjIwM1owgdIxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29m
# dCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRT
# UyBFU046OEQ0MS00QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0fA+6
# 5hiAriywYIKyvY3t4SUqXPQk8G62v+Cm9nruQ2UeqAoBbQm4oDLjHGN9UJR6/95L
# loRydOZ+Prd++zx6J3Qw28/3VPqvzX10iq9acFNji8pWNLMOd9VWdbFgHcg9hEAh
# M03Sw+CiWwusJgAqJ4iQQKr4Q8l8SdDbr5ZO+K3VRL64m7A2ccwpVhGuL+thDY/x
# 8oglF9zGRp2PwIQ8ms36XIQ1qD+nCYDQkl5h1fV7CYFyeJfgGAIGqgLzfDfhKTft
# ExKwoBTn8GVdtXIO74HpzlePIJhvxDH9C70QHoq8T1LvozQdyUhW1tVlPGecbCxK
# DZXt+YnHRE/ht8AzZnEl5UGLOLfeCFkeeNfj7FE5KtJJnT+P9TuBg+eGbCeXlJy2
# msFzscU9X4G1m/VUYNWeGrKVqbi+YBcB2vFDTEcbCn36K+qq11VUNTnSTktSZXr4
# aWZbLEglQ6HTHN9CN31ns58urTTqH6X2j67cCdLpF3Cw9ck/vPbuLkAf66lCuiex
# 6ZDbtH0eTOcRrTnIfZ8p3DvWpaK8Q34hHW+s3qrQn3G6OOrvv637LJXBkriRc5cB
# DZ1Pr0PiSeoyUVKwfpq+dc1lDIlkyw1ZoS3euv/w2v2AYwNAYtIXGLjv1nLX1pP9
# 8fOwC27ahwG5OotXCfGtnKInro/vQQEko7l5AQIDAQABo4IBSTCCAUUwHQYDVR0O
# BBYEFNAaXcJRZ1IMGIs4SCH/XgXcn8ONMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl
# 0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1T
# dGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4IC
# AQBahrs3zrAJuMACXxEZiYFltLTSyz5OlWI+d/oQZlCArKhoI/aFzTWrYAqvox7d
# NxIk81YcbXilji6EzMd/XAnFCYAzkCB/ho7so2FVXTgmvRcepSOvdPzgWRZc9gw7
# i6VAbqP/793uCp7ONdpjtwOpg0JJ3cXiUrHQUm5CqnHAe0wv5rhToc4N/Zn4oxiA
# nNZGc4iRP+h3SghfKffr7NchlEebs5CKPuvKv5+ZDbd94XWkNt+FRIdMD0hPnQoK
# Skan8YGLAU/+bV2t3vE18iZVaBvY8Fwayp0kG+PpNfYx1Qd8FVH5Z7gDSUSPWs1s
# KmBSg22VpH0PLaTaBXyihUR21qJnKHT9W1Z+5CllAkwPGBtkZUwbb67NwqmN5gA0
# yVIoOHJDfzBugCK/EPgApigRJuDhaTnGTF9HMWrKKXYMTPWknQbrGiX2dyLZd7wu
# Qt0RPe7lEbFQdqbwvgp4xbbfz5GO9ZfVEx81AjvvjOIUhks5H7vsgYVzBngWai15
# fXH34GD3J0RY0E/exm/24OLLCyBbjSTTQCbm/iL8YaJka7VrgeEjfd+aDH7xuXBH
# me3smKQWeA25LzeOGbxEdBB0WpC9sW9a67I+3PCPmrhKmM7VKQ57qugcaQSFAJRd
# 1AydEjBucalv/YSzFp2iQryHqxFkxZuuI7YQItAQzMJwsDCCB3EwggVZoAMCAQIC
# EzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoX
# DTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC
# 0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VG
# Iwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP
# 2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/P
# XfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361
# VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwB
# Sru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9
# X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269e
# wvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDw
# wvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr
# 9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+e
# FnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAj
# BgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+n
# FV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBH
# hkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
# BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4Swf
# ZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTC
# j/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu
# 2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/
# GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3D
# YXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbO
# xnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqO
# Cb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I
# 6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0
# zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaM
# mdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNT
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLXMIICQAIBATCCAQChgdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046OEQ0MS00QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAHGLROiW3R4SpcJCXiqA
# ldSSJA5hoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJ
# KoZIhvcNAQEFBQACBQDnAFf9MCIYDzIwMjIxMDI0MDgxNzAxWhgPMjAyMjEwMjUw
# ODE3MDFaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOcAV/0CAQAwCgIBAAICBQ8C
# Af8wBwIBAAICETwwCgIFAOcBqX0CAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYB
# BAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOB
# gQB71cTruyZHYoeeq/ffubYEZ7UU63JyA+yjc6xH5qYU3psjFpl6dOtIRzBKTG2J
# ownVRkx6H5Wryx1MZuYE4oI1qsDdp6jGFxdyiZVNURnOtqOb2gcV0DlvNWH40lA7
# oEDnkHMhjUrBwus9qXjXJPQ7lkBE2aYvnWdCDdZjUIsV7DGCBA0wggQJAgEBMIGT
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABs/4lzikbG4ocAAEA
# AAGzMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwLwYJKoZIhvcNAQkEMSIEIOvh1ugZERETYRx4ciNlDXTYQAqQqWJmCY68T5ad
# DzSqMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQghqEz1SoQ0ge2RtMyUGVD
# No5P5ZdcyRoeijoZ++pPv0IwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAbP+Jc4pGxuKHAABAAABszAiBCBSGNxkGuSy92AQibmX9odx
# +TerSHa8ID3H1lEX2NCgwjANBgkqhkiG9w0BAQsFAASCAgA875W1gWi9BBiRGtWg
# 2F0q9sOyN/g43JoaoS4plKO/byhE6NWjgmvWORfGTV2+Dho5XubniOFARiQy8JnL
# L88bT+OAq1OkxRN7JA2hlppuV9vNonEeJqNHEz9Zl9oHXoxXH0euRCI7jj9qrkaQ
# yOHdOMTdC3S65B/Sw8jEEFLGpSugT3g0Hjqq96/xXV84Gd4dQ35oIlq5DaQUdYmE
# IB0enetk1MrUguRlBl3cvMxCxGePXbS2t5+XVzKkZlyBqUoSxHvkNFDLPoT1Yq2O
# ArZFbOkrFMHirpzyJXd91fcdqweFbU08floTewwt7JrbJFwqMUSNXoQIS78IWKZQ
# 2O5g48LTSaSu2ZeB8zYkvj4lMl1nPtr99KoF1DQ+x6ui0MkJw6zZeanETcR28oXZ
# 4ijlwjFYFvkzrFwQBgmpvOtIwuBdGBVCdZDPouMOGIM573T/olxe/UZ177og9+fp
# 29adqdlknz3lghjOJ/V2PwPqyImuiPKeaEPtswIeUqSZ/54GGteq0Lc5m1lnjkp8
# oxCTqiuws+OdZpKVbxVTh2MlfQiEerhak4AZkSxfT6sV4Zt9PV2beluyFzdtEYJ7
# gp7CQbJYGRMZqMHRgWHkDrYrSJUULhpI2uGjWD+4DKrJkeRxfmTkgkAT5SaVcDiD
# z5kPQlZPDmQhuaSaFtHEWAYD8g==
# SIG # End signature block
