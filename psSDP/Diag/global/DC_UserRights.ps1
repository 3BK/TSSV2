#************************************************
# DC_UserRights.ps1
# Version 1.1
# Date: 11-29-2011
# Author: David Fisher
# Updated: Andret (removed dependency from batch file)
# Description: This script obtains User Rights (privileges) 
#              via the userrights.exe tool, saving output to a
#              file named $ComputerName_userrights.txt
#************************************************
#Last Updated Date: 05-23-2012
#Updated By: Alec Yao     v-alyao@microsoft.com
#Description: Add two arguments for the script, called $Prefix and $Suffix. It will allow to custermize the filename
#************************************************
Param($Prefix = '', $Suffix = '')

if ($OSArchitecture -eq 'ARM')
{
	'Skipping running {showpriv.exe} since it is not supported in ' + $OSArchitecture + ' architecture.' | WriteTo-StdOut
	return
}

Import-LocalizedData -BindingVariable InboxCommandStrings
	
Write-DiagProgress -Activity $InboxCommandStrings.ID_UserRightsActivity -Status $InboxCommandStrings.ID_UserRightsStatus

$fileDescription = "UserRights Output"
$sectionDescription = "User Rights Assignments"

$OutputFileName = Join-Path $Pwd.Path ($ComputerName + "_" + $Prefix + "UserRights" + $Suffix + ".txt")

"Defined User Rights" >$OutputFileName
"===================" >> $OutputFileName
"" >> $OutputFileName

"Access Credential Manager as a trusted caller" >> $OutputFileName
"=====================================" >> $OutputFileName
.\showpriv.exe SeTakeOwnershipPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Access this computer from the network" >> $OutputFileName
"=====================================" >> $OutputFileName
.\showpriv.exe SeNetworkLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Act as part of the operating system" >> $OutputFileName
"===================================" >> $OutputFileName
.\showpriv.exe SeTcbPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Add workstations to domain" >> $OutputFileName
"==========================" >> $OutputFileName
.\showpriv.exe SeMachineAccountPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Adjust memory quotas for a process" >> $OutputFileName
"==================================" >> $OutputFileName
.\showpriv.exe SeIncreaseQuotaPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Allow log on Locally" >> $OutputFileName
"=============" >> $OutputFileName
.\showpriv.exe SeInteractiveLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Allow logon through Remote Desktop Services" >> $OutputFileName
"=====================================" >> $OutputFileName
.\showpriv.exe SeRemoteInteractiveLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Back up files and directories" >> $OutputFileName
"=============================" >> $OutputFileName
.\showpriv.exe SeBackupPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Bypass Traverse Checking" >> $OutputFileName
"========================" >> $OutputFileName
.\showpriv.exe SeChangeNotifyPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Change the system time" >> $OutputFileName
"======================" >> $OutputFileName
.\showpriv.exe SeSystemTimePrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Change the time zone" >> $OutputFileName
"====================" >> $OutputFileName
.\showpriv.exe SeTimeZonePrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Create a pagefile" >> $OutputFileName
"=================" >> $OutputFileName
.\showpriv.exe SeCreatePagefilePrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Create a token object" >> $OutputFileName
"=====================" >> $OutputFileName
.\showpriv.exe SeCreateTokenPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Create global objects" >> $OutputFileName
"=====================" >> $OutputFileName
.\showpriv.exe SeCreateGlobalPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Create permanent shared objects" >> $OutputFileName
"===============================" >> $OutputFileName
.\showpriv.exe SeCreatePermanentPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Create Symbolic links" >> $OutputFileName
"=====================" >> $OutputFileName
.\showpriv.exe SeCreateSymbolicLinkPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Debug programs" >> $OutputFileName
"==============" >> $OutputFileName
.\showpriv.exe SeDebugPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Deny access to this computer from the network" >> $OutputFileName
"=============================================" >> $OutputFileName
.\showpriv.exe SeDenyNetworkLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Deny log on as a batch job" >> $OutputFileName
"==========================" >> $OutputFileName
.\showpriv.exe SeDenyBatchLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Deny log on as a service" >> $OutputFileName
"========================" >> $OutputFileName
.\showpriv.exe SeDenyServiceLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Deny log on Locally" >> $OutputFileName
"==================" >> $OutputFileName
.\showpriv.exe SeDenyInteractiveLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Deny log on through Remote Desktop Services" >> $OutputFileName
"====================================" >> $OutputFileName
.\showpriv.exe SeDenyRemoteInteractiveLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Enable computer and user accounts to be trusted for delegation" >> $OutputFileName
"==============================================================" >> $OutputFileName
.\showpriv.exe SeEnableDelegationPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Force shutdown from a remote system" >> $OutputFileName
"===================================" >> $OutputFileName
.\showpriv.exe SeRemoteShutdownPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Generate security audits" >> $OutputFileName
"========================" >> $OutputFileName
.\showpriv.exe SeAuditPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Impersonate a client after authentication" >> $OutputFileName
"=========================================" >> $OutputFileName
.\showpriv.exe SeImpersonatePrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Increase a process working set" >> $OutputFileName
"==============================" >> $OutputFileName
.\showpriv.exe SeIncreaseWorkingSetPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Increase scheduling priority" >> $OutputFileName
"============================" >> $OutputFileName
.\showpriv.exe SeIncreaseBasePriorityPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Load and unload device drivers" >> $OutputFileName
"==============================" >> $OutputFileName
.\showpriv.exe SeLoadDriverPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Lock pages in memory" >> $OutputFileName
"====================" >> $OutputFileName
.\showpriv.exe SeLockMemoryPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Log on as a batch job" >> $OutputFileName
"=====================" >> $OutputFileName
.\showpriv.exe SeBatchLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Log on as a service" >> $OutputFileName
"===================" >> $OutputFileName
.\showpriv.exe SeServiceLogonRight >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Manage auditing and security log" >> $OutputFileName
"================================" >> $OutputFileName
.\showpriv.exe SeSecurityPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Modify an object label" >> $OutputFileName
"==================================" >> $OutputFileName
.\showpriv.exe SeRelabelPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Modify firmware environment values" >> $OutputFileName
"==================================" >> $OutputFileName
.\showpriv.exe SeSystemEnvironmentPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Perform volume maintenance tasks" >> $OutputFileName
"================================" >> $OutputFileName
.\showpriv.exe SeManageVolumePrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Profile single process" >> $OutputFileName
"======================" >> $OutputFileName
.\showpriv.exe SeProfileSingleProcessPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Profile system performance" >> $OutputFileName
"==========================" >> $OutputFileName
.\showpriv.exe SeSystemProfilePrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Remove computer from docking station" >> $OutputFileName
"====================================" >> $OutputFileName
.\showpriv.exe SeUndockPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Replace a process-level token" >> $OutputFileName
"=============================" >> $OutputFileName
.\showpriv.exe SeAssignPrimaryTokenPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Restore files and directories" >> $OutputFileName
"=============================" >> $OutputFileName
.\showpriv.exe SeRestorePrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Shut down the system" >> $OutputFileName
"====================" >> $OutputFileName
.\showpriv.exe SeShutdownPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Synchronize directory service data" >> $OutputFileName
"==================================" >> $OutputFileName
.\showpriv.exe SeSynchAgentPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Take ownership of files or other objects" >> $OutputFileName
"========================================" >> $OutputFileName
.\showpriv.exe SeTakeOwnershipPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

"Read unsolicited input from a terminal device" >> $OutputFileName
"=============================================" >> $OutputFileName
.\showpriv.exe SeUnsolicitedInputPrivilege >> $OutputFileName
"" >> $OutputFileName
"" >> $OutputFileName

CollectFiles -sectionDescription $sectionDescription -filesToCollect $OutputFileName -fileDescription $fileDescription

Trap{WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;Continue}

# SIG # Begin signature block
# MIIjiAYJKoZIhvcNAQcCoIIjeTCCI3UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDX7BY1NU1CHeD2
# 2NNev9RzKP289g3g0FFxGSDfoMFOn6CCDYEwggX/MIID56ADAgECAhMzAAAB32vw
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgWz04p0n9
# wK5+LWmOoHs71rWgnYtb9uApZWIayAt1j9gwOAYKKwYBBAGCNwIBDDEqMCigCIAG
# AFQAUwBToRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20gMA0GCSqGSIb3DQEB
# AQUABIIBAA8pn9QT4rjFq7cWbxlGbht2OX8ebX55ZwcytKN/MhScN2o2abwtxxMd
# rgF/uHJ7w1TrP26VSW6NW5wmKz9pTLofoF9X+rEsdmFbtCV7BYlhZsKjPgbJhGfT
# 7xhRe5BNbVGADoffBfkJoA/xzOpEzyKT1hJ2r5/JLozHJkOtW8yawMEKd8fvu3qn
# TkxX8FZtTXJaIZ+/FNaa29bFMC35xYHhPSK9bS06g0InyDf0SeRiGjdOQ6BbUqZF
# +oy4YJa0JYg8pUclB6t+o90e51Os2RCOe5aXi3VxkwIQD+amlyIwD0kAAlZ06dgP
# TUQpIUPdvjquzZmfdORqv3WHvq7/3aihghLxMIIS7QYKKwYBBAGCNwMDATGCEt0w
# ghLZBgkqhkiG9w0BBwKgghLKMIISxgIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBVQYL
# KoZIhvcNAQkQAQSgggFEBIIBQDCCATwCAQEGCisGAQQBhFkKAwEwMTANBglghkgB
# ZQMEAgEFAAQgavxSXrymCQDA9XhOq0+xcKkARlbFfiZ3Mh2q0LBZ8nUCBmGB8A0Q
# SBgTMjAyMTExMTExNjUzMzYuMTk5WjAEgAIB9KCB1KSB0TCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkY3
# N0YtRTM1Ni01QkFFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloIIORDCCBPUwggPdoAMCAQICEzMAAAFenSnHX4cFoeoAAAAAAV4wDQYJKoZI
# hvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjEwMTE0
# MTkwMjE5WhcNMjIwNDExMTkwMjE5WjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVl
# cnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkY3N0YtRTM1Ni01QkFF
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmtMjg5B6GfegqnbO6HpY/ZmJv8PHD+ys
# t57JNv153s9f58uDvMEDTKXqK8XafqVq4YfxbsQHBE8S/tkJJfBeBhnoYZofxpT4
# 6sNcBtzgFdM7lecsbBJtrJ71Hb65Ad0ImZoy3P+UQFZQrnG8eiPRNStc5l1n++/t
# OoxYDiHUBPXD8kFHiQe1XWLwpZ2VD51lf+A0ekDvYigug6akiZsZHNwZDhnYrOrh
# 4wH3CNoVFXUkX/DPWEsUiMa2VTd4aNEGIEQRUjtQQwxK8jisr4J8sAhmdQu7tLOU
# h+pJTdHSlI1RqHClZ0KIHp8rMir3hn73zzyahC6j3lEA+bMdBbUwjQIDAQABo4IB
# GzCCARcwHQYDVR0OBBYEFKpyfLoN3UvlVMIQAJ7OVHjV+B8rMB8GA1UdIwQYMBaA
# FNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8y
# MDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAt
# MDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJ
# KoZIhvcNAQELBQADggEBAH8h/FmExiQEypGZeeH9WK3ht/HKKgCWvscnVcNIdMi9
# HAMPU8avS6lkT++usj9A3/VaLq8NwqacnavtePqlZk5mpz0Gn64G+k9q6W57iy27
# dOopNz0W7YrmJty2kXigc99n4gp4KGin4yT2Ds3mWUfO/RoIOJozTDZoBPeuPdAd
# BLyKOdDn+qG3PCjUChSdXXLa6tbBflod1TNqh4Amu+d/Z57z0p/jJyOPJp80lJSn
# +ppcGVuMy73S825smy11LE62/BzF54c/plphtOXZw6VrhyiSI9T4FSMhkD+38hl9
# ihrMwaYG0tYUll0L0thZaYsuw0nZbbWqR5JKkQDDimYwggZxMIIEWaADAgECAgph
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
# UHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkY3N0YtRTM1Ni01
# QkFFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEw
# BwYFKw4DAhoDFQBWSY9X/yFlVL0XNu2hfbHdnbFjKqCBgzCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5TejBTAiGA8y
# MDIxMTExMTE4MTExN1oYDzIwMjExMTEyMTgxMTE3WjB3MD0GCisGAQQBhFkKBAEx
# LzAtMAoCBQDlN6MFAgEAMAoCAQACAh3fAgH/MAcCAQACAhFyMAoCBQDlOPSFAgEA
# MDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAI
# AgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAxVxDoMDffsH6dhlLg27cadDZ0u08
# b3hcPRrc4tQLyHLLNcf87UdIKyJl5FAEj3QiScbcFGcjJlgoD4NQJMTTnaNOqcKv
# xf8CplhQCXOllJWZl2WMsS4FvNKx2+XBbtaF8lHkR3bIk0lTgoEcaT1YVZr/v5Au
# IsO53Rw+1s05/rAxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAV6dKcdfhwWh6gAAAAABXjANBglghkgBZQMEAgEFAKCCAUow
# GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCBL1qx0
# e1JQq99C1pxYmeJok7B0ztI2fxj9ZeB3CGqWRTCB+gYLKoZIhvcNAQkQAi8xgeow
# gecwgeQwgb0EIH7lhOyU1JeO4H7mZANMpGQzumuR7CFed69eku/xEtPiMIGYMIGA
# pH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFenSnHX4cFoeoA
# AAAAAV4wIgQgDv5rcYpYecV7XG+04htmJ0mViE8lWWlIpUnwA/k2MYMwDQYJKoZI
# hvcNAQELBQAEggEABSlrebsHQIuuA6xIZW0KBTAsB580EDUbwlLU0lUQamPYx3Yw
# yqLz7oUNzmPSmMwU4GFxuZIWGBOq8rTr1ZXCrs+YlRmDbixURi9HzxolO4vzzZLM
# sGfWqYVjRA7BTR69Hu5GjsG92xDS5sf0DP4mAYK7+SEOg065BcXnv8ye8ieP7x+n
# JRFidZ7pLeioNxhFmTa0EKEKWplONNdDsUdR7P563XjbSuUxZ6vtnsFg3FDlUk+m
# g6Ypl/2D4ujD170E/fyw8Htnt9vHbAqXlYnqDOe241PoicSJ9Uw95qfiiMS3y8FS
# lrm9UsExoBiAqhRjycJ+mj/09WhWjx1wfXmt4g==
# SIG # End signature block
