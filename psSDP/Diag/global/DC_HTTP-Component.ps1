#************************************************
# DC_HTTP-Component.ps1
# Version x
# Date: 2009-2014
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: Collects information about the HTTP service and config.
# Called from: Main Networking Diag
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
Write-DiagProgress -Activity $ScriptVariable.ID_CTSHTTP -Status $ScriptVariable.ID_CTSHTTPDescription

# detect OS version and SKU
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber


function RunNetSH ([string]$NetSHCommandToExecute="")
{
	
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSHTTP -Status "netsh $NetSHCommandToExecute"
	
	$NetSHCommandToExecuteLength = $NetSHCommandToExecute.Length + 6
	"`n`n`n" + "-" * ($NetSHCommandToExecuteLength) + "`r`n" + "netsh $NetSHCommandToExecute" + "`r`n" + "-" * ($NetSHCommandToExecuteLength) | Out-File -FilePath $OutputFile -append

	$CommandToExecute = "cmd.exe /c netsh.exe " + $NetSHCommandToExecute + " >> $OutputFile "
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
}


$sectionDescription = "HTTP"

#WV/WS2008+
if ($bn -gt 6000)
{
	#----------Netsh
	$OutputFile = $ComputerName + "_HTTP_netsh_output.TXT"
	"========================================"		| Out-File -FilePath $OutputFile -append
	"HTTP Netsh Output"								| Out-File -FilePath $OutputFile -append
	"========================================"		| Out-File -FilePath $OutputFile -append
	"Overview"										| Out-File -FilePath $OutputFile -append
	"----------------------------------------"		| Out-File -FilePath $OutputFile -append
	"HTTP Netsh Output"								| Out-File -FilePath $OutputFile -append
	"   1. netsh http show cacheparam"				| Out-File -FilePath $OutputFile -append
	"   2. netsh http show cachestate"				| Out-File -FilePath $OutputFile -append
	"   3. netsh http show iplisten"				| Out-File -FilePath $OutputFile -append
	"   4. netsh http show servicestate"			| Out-File -FilePath $OutputFile -append
	"   5. netsh http show sslcert"					| Out-File -FilePath $OutputFile -append
	"   6. netsh http show timeout"					| Out-File -FilePath $OutputFile -append
	"   7. netsh http show urlacl"					| Out-File -FilePath $OutputFile -append
	"========================================"		| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	"========================================"		| Out-File -FilePath $OutputFile -append
	"HTTP Netsh Output"								| Out-File -FilePath $OutputFile -append
	"========================================"		| Out-File -FilePath $OutputFile -append
	RunNetSH -NetSHCommandToExecute "http show cacheparam"
	RunNetSH -NetSHCommandToExecute "http show cachestate"
	RunNetSH -NetSHCommandToExecute "http show iplisten"
	RunNetSH -NetSHCommandToExecute "http show servicestate"
	RunNetSH -NetSHCommandToExecute "http show sslcert"
	RunNetSH -NetSHCommandToExecute "http show timeout"
	RunNetSH -NetSHCommandToExecute "http show urlacl"
	CollectFiles -filesToCollect $OutputFile -fileDescription "HTTP netsh output" -SectionDescription $sectionDescription


	#----------Registry
	$OutputFile= $Computername + "_HTTP_reg_.TXT"
	$CurrentVersionKeys =	"HKLM\SYSTEM\CurrentControlSet\Services\HTTP"
	RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -OutputFile $OutputFile -fileDescription "HTTP registry output" -SectionDescription $sectionDescription
}




# SIG # Begin signature block
# MIIjhwYJKoZIhvcNAQcCoIIjeDCCI3QCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCChmL5Pzr84pYXK
# c+n9YsSRS/cc4i/1144FaNFmkfdlSKCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVXDCCFVgCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBpDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgBW5JmaQP
# bGIgCEr1piX92F4hGsbRWnvR6vCuQqz2wL4wOAYKKwYBBAGCNwIBDDEqMCigCIAG
# AFQAUwBToRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20gMA0GCSqGSIb3DQEB
# AQUABIIBAJds+PPmrf4TSMN++GOIjNi7Or9ndsEWYXyMGASU7Zun5UQcm4DGxh6+
# euBsLAATucYlhYB7W5eG0YyUZZu3gATDfaa0e7ErI/ZoCIQ4ltR4TXu0iY1lkws5
# oGrvH5G2tZn7GztllwLUtZLtBUPgPgHeTYQVYFUjeO90N81JCCxrhisnEiiFWtz0
# dsZTwtELoyrV+TaxL03VVn77KFYHJ0SL2Y4Txdie9/6kw2HpPCqNCOEv8QhefA+H
# rUvwn6mFtO9gW7dzc6gv5RoQnnG3WKWGLMS62IAgLodZhpDA6FjX89mqDCIZdwuT
# ZIj7Jihv88K3f+HtXCNJrf6H21m0r86hghLwMIIS7AYKKwYBBAGCNwMDATGCEtww
# ghLYBgkqhkiG9w0BBwKgghLJMIISxQIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBVAYL
# KoZIhvcNAQkQAQSgggFDBIIBPzCCATsCAQEGCisGAQQBhFkKAwEwMTANBglghkgB
# ZQMEAgEFAAQgH7J5fFbbfbx632syATLVgofUwrYReDzmkj/ds992BF8CBmGB81FC
# gBgSMjAyMTExMTExNjUzMzQuNjRaMASAAgH0oIHUpIHRMIHOMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3Bl
# cmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046NEQy
# Ri1FM0RELUJFRUYxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZp
# Y2Wggg5EMIIE9TCCA92gAwIBAgITMwAAAV/DrmVW5VNY7AAAAAABXzANBgkqhkiG
# 9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMTAxMTQx
# OTAyMTlaFw0yMjA0MTExOTAyMTlaMIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVy
# dG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046NEQyRi1FM0RELUJFRUYx
# JTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8PXn5gtlkPbmmsO5OIMR0kghKCS5NthUw
# GhfI2GwDJEAug0BdFj5yIXizNREU7kPRVm4JX9Jl2w3dio3s0TZc+d8nCSEXohlE
# Dp8Ob3eE4Iy1MS9e4NytDD9pzYWPy8j/fDJf+NF/dOXoA24iJ3WXbR4g29cX2Ne2
# u79Y/aN5rnPjAoBbfXzvlOAgzVKTDDECRa//UJVOGHSWsI28inyty7b6n6t5b4Ct
# Px6YYg7V+XId23hjQSqMCkk14X7fKcLl0D66LrVoAeT2ZgDfF2YQAqOI1ov2tM4A
# CSXAaqF70uiJ61nB/xKov6lWo/FbOev2f+pGmGWbv9Zksy5+RACzAgMBAAGjggEb
# MIIBFzAdBgNVHQ4EFgQUJezp05XNK4GexXe6pQxYLmE1OPUwHwYDVR0jBBgwFoAU
# 1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENBXzIw
# MTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAxMC0w
# Ny0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkq
# hkiG9w0BAQsFAAOCAQEADoLX2SyWEm7BN1u953dIS56kKh0hZdrKR8c3l8TOLiU9
# rgFZP0i1c8472XplAwXjnnSnlxvIXLaa6aEDKVN4G7DVJ1Gg3rA3JkfnhCwsGGvl
# QZFAqrCBiZkJQ8Lg8DWuu5MghD8j1ufWLtsP3Yza8DVko7bkcH1BaA5I2Mg451w9
# I6LIuu6sSYFvK0ao5fWutoRs5c4BPmlS00+SISuc9l+ti6YfI/X+F47Qj58nhShZ
# oAVhz2NR2241B34PdUrQi8bnh9i42aEBE1jifqcRJYnF8FT+QdMJVpImrsLoN60y
# pw2+VilG9pZbJ0IGnoFfjEIzCOyur/rKb7DIEYz5YTCCBnEwggRZoAMCAQICCmEJ
# gSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmlj
# YXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIxNDY1
# NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF++18
# aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRDDNdN
# uDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSxz5NM
# ksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1rL2K
# Qk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16HgcsOmZ
# zTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB4jAQ
# BgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqFbVUw
# GQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB
# /wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0f
# BE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJv
# ZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4w
# TDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCBkjCB
# jwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQeMiAd
# AEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQALiAd
# MA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUxvs8F
# 4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GASinbM
# QEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1L3mB
# ZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWOM7ti
# X5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4pm3S
# 4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45V3ai
# caoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x4QDf
# 5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEegPsb
# iSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKnQqLJ
# zxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp3lfB
# 0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvTX4/e
# dIhJEqGCAtIwggI7AgEBMIH8oYHUpIHRMIHOMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQ
# dWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046NEQyRi1FM0RELUJF
# RUYxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAH
# BgUrDgMCGgMVAPoH0qo3QJ3ThRGlzkMgQnbqZkKHoIGDMIGApH4wfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDlN6ZjMCIYDzIw
# MjExMTExMTgyNTM5WhgPMjAyMTExMTIxODI1MzlaMHcwPQYKKwYBBAGEWQoEATEv
# MC0wCgIFAOU3pmMCAQAwCgIBAAICGaYCAf8wBwIBAAICEYUwCgIFAOU49+MCAQAw
# NgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgC
# AQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQAL0fqB3dlciSnKV6QD8TXKh1bBC4yy
# wlnwIo1hxjyayFKEBNoa0+D+BKmgaivTWbRfryE/qZ2JNkbmzQILqVslnD9pQamJ
# UCYyr39okMb1Txe1xbkGxACtIhI95ahlIIvvtKEfMYO+X7j5j7G+5g+2J6Gy4VLV
# 66YSryvDTa6GCDGCAw0wggMJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABX8OuZVblU1jsAAAAAAFfMA0GCWCGSAFlAwQCAQUAoIIBSjAa
# BgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIKhw1zdx
# PW7wbnbHRXOlJd7IASNrtvQgIbhZANyt+ceSMIH6BgsqhkiG9w0BCRACLzGB6jCB
# 5zCB5DCBvQQg0M16tSsRrC7o9LM5La55YSEapm8KeW1RnOgbuoYJTFwwgZgwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAV/DrmVW5VNY7AAA
# AAABXzAiBCA3GAuFMIfwEZn+8E8OoL18yDCCdG6+anWCRbl0WCW5+jANBgkqhkiG
# 9w0BAQsFAASCAQAs2jp403f0U9Mkj2nutWqRJjXRyG+eV04MsZ0JioFl6cr0BAUk
# CyUzpTDiULZTt1FTjg8GmZIoHKee9xTzJZrKyk9b1/hhmAZa2VZUvuH6Cd5XJPNc
# NNDyzyMLfHglAy3bNDtc82n7wGjwc0Sxmoe86JvuVWDCko/554k5XPWyxlv8Gne2
# eGKluKFTmSkvUu4mjtcABHTarHvqFpBSIyrSlhvigRBFc5ZTArDcxmcqKsDzOj7R
# DHuclUJW4H4j18zG3swuKTHf1IWIojN5e6E+7VmlOo+rEFQiRUwgPeJkGAsv7c9o
# bgZJpr1QsooHXae9PlbTjm9CSt8C/42iAMw1
# SIG # End signature block
