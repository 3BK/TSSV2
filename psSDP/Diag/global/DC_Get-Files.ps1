###########################################################################
# DC_Get-Files
# Version 1.0
# Date: 09-26-2012
# Author: mifannin
# Description: Collects relevant files
###########################################################################


Import-LocalizedData -BindingVariable Files -FileName DC_Get-Files -UICulture en-us

$CBSCabs = Get-ChildItem "$ENV:SystemRoot\Logs\CBS" -Exclude *.log 
Write-DiagProgress -Activity $Files.ID_Files  -Status $Files.ID_FilesCab

logstart 

foreach($cab in $CBSCabs)
    {
        $y = ((Get-Date) - $cab.CreationTime).Days
        if ($y -lt 365)
		{
			"Collecting " + $cab.FullName | WriteTo-StdOut 
			CollectFiles -filesToCollect $cab.FullName -fileDescription "CBS Cab File" -sectionDescription "CBS Information"
		}
    }

#CopyDeploymentFile Function
Function CopyDeploymentFile ($sourceFileName, $destinationFileName, $fileDescription) 
{
	
	if (test-path $sourceFileName) {
		$sourceFile = Get-Item $sourceFileName
		#copy the file only if it is not a 0KB file.
		if ($sourceFile.Length -gt 0) 
		{
			$CommandLineToExecute = "cmd.exe /c copy `"$sourceFileName`" `"$destinationFileName`""
			"Collecting " + $sourceFileName | WriteTo-StdOut 
			RunCmD -commandToRun $CommandLineToExecute -sectionDescription $sectionDescription -filesToCollect $destinationFileName -fileDescription $fileDescription
		}
	}
}

Write-DiagProgress -Activity $Files.ID_Files  -Status $Files.ID_FilesLogs
$sourceFileName = "$Env:windir\setupact.log"
$destinationFileName = $computername + "_setupact.log"
$fileDescription = "Setupact.log on Windows folder"
$sectionDescription = "System Logs"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$Env:windir\panther\setupact.log"
$destinationFileName = $computername + "_setupact-panther.log"
$fileDescription = "Setupact.log on Windows\Panther"
$sectionDescription = "System Logs"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$Env:windir\setupact_dpx.log"
$destinationFileName = $computername + "_setuact_dpx.log"
$fileDescription = "setupact_dpx.log on Windows folder"
$sectionDescription = "System Logs"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$Env:windir\inf\setupapi.app.log"
$destinationFileName = $computername + "_setupapi.app.log"
$fileDescription = "setupapi.log on Windows folder"
$sectionDescription = "System Logs"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$Env:windir\inf\setupapi.epp.log"
$destinationFileName = $computername + "_setupapi.epp.log"
$fileDescription = "setupapi.log on Windows folder"
$sectionDescription = "System Logs"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$Env:windir\inf\setupapi.dev.log"
$destinationFileName = $computername + "_setupapi.dev.log"
$fileDescription = "setupapi.log on Windows\inf"
$sectionDescription = "System Logs"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$Env:windir\setuperr_dpx.log"
$destinationFileName = $computername + "_setuperr_dpx.log"
$fileDescription = "setupapi.log on Windows folder"
$sectionDescription = "System Logs"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$Env:windir\panther\setuperr.log"
$destinationFileName = $computername + "_setuperr_panther.log"
$fileDescription = "Setuperr.log on Windows\Panther"
$sectionDescription = "System Logs"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription


$sourceFileName = "$ENV:LOCALAPPDATA\microsoft\windows\windowsupdate.log"
$destinationFileName = $computername + "_WindowsUpdatePerUser.log"
$fileDescription = "WindowsUpdate.log on $AppData"
$sectionDescription = "Windows Update Information"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$ENV:windir\windowsupdate.log"
$destinationFileName = $computername + "_WindowsUpdate.log"
$fileDescription = "WindowsUpdate.log on Windows folder"
$sectionDescription = "Windows Update Information"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$ENV:windir\SoftwareDistribution\ReportingEvents.log"
$destinationFileName = $computername + "_ReportingEvents.log"
$fileDescription = "ReportingEvents.log on Software Distribution Folder"
$sectionDescription = "Windows Update Information"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$ENV:windir\SchedLgU.txt"
$destinationFileName = $computername + "_SchedLgU.txt"
$fileDescription = "SchedLgU.txt on Windows Folder"
$sectionDescription = "System Logs"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$ENV:windir\tasks\SchedLgU.txt"
$destinationFileName = $computername + "_SchedLgU.txt"
$fileDescription = "SchedLgU.txt on Windows\Tasks Folder"
$sectionDescription = "System Logs"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$ENV:windir\debug\mrt.log"
$destinationFileName = $computername + "_mrt.log"
$fileDescription = "mrt.log on Windows\Debug Folder"
$sectionDescription = "System Logs"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$ENV:windir\Logs\CBS\cbs.log"
$destinationFileName = $computername + "_CBS.log"
$fileDescription = "CBS Log File"
$sectionDescription = "CBS Information"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$ENV:windir\Logs\CBS\CheckSUR.log"
$destinationFileName = $computername + "_CheckSUR.log"
$fileDescription = "mrt.log on Windows\CBS\Logs"
$sectionDescription = "CBS Information"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$ENV:windir\Logs\CBS\CheckSUR.persist.log"
$destinationFileName = $computername + "_CheckSUR.persist.log"
$fileDescription = "mrt.log on Windows\CBS\Logs"
$sectionDescription = "CBS Information"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$ENV:windir\system32\drivers\etc\hosts"
$destinationFileName = $computername + "_Hosts.txt"
$fileDescription = "Windows hosts file"
$sectionDescription = "Network Configuration"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

logstop
# SIG # Begin signature block
# MIIjiAYJKoZIhvcNAQcCoIIjeTCCI3UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCV0M3NP33rdkzm
# wsILnLJPY1XoAOFHbTRpWovxDCVeEKCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgeJT6q0A2
# /OXkU6YsLcRh6BRHAah019kRpeZgpvks064wOAYKKwYBBAGCNwIBDDEqMCigCIAG
# AFQAUwBToRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20gMA0GCSqGSIb3DQEB
# AQUABIIBAFs7fMsFP33/7SWCQpV+HM2YuV8cXPAYmM+9F2uWxOeGMScYWcsu5peY
# LPIonJ5LmgWOnAlPaufavOHIw6NMNm3brlnjRwMQppeRlBPX71eGImEFj7+/tclE
# dliMip7uIICDBLXU1xGqKni/u46HDbf4zVIhgSoFcdhAYG/FTeSx6LEiKtVKnH7q
# 6B4wnKA5oJhserOZw4mz1TruSNu1ggr7A07N89+wIoiVHmBbbVJmMzrosioRaCQ/
# GAcUR7Bxj/bPoFayudPUKciSb0uBo0oUNyNajawaNZkYZVayzEKcdo5i5RvSu9GD
# ZvGfCgnEJ6g9k+nz7G1ziT1w1w8mXF2hghLxMIIS7QYKKwYBBAGCNwMDATGCEt0w
# ghLZBgkqhkiG9w0BBwKgghLKMIISxgIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBVQYL
# KoZIhvcNAQkQAQSgggFEBIIBQDCCATwCAQEGCisGAQQBhFkKAwEwMTANBglghkgB
# ZQMEAgEFAAQgq5fcjPngSjk1hIKo2T8BkU4OoT3/d1QJXl4cErh5oK4CBmGCCja6
# mhgTMjAyMTExMTExNjUzMzYuMzQ0WjAEgAIB9KCB1KSB0TCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkY4
# N0EtRTM3NC1EN0I5MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloIIORDCCBPUwggPdoAMCAQICEzMAAAFji2TGyYWWZXYAAAAAAWMwDQYJKoZI
# hvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjEwMTE0
# MTkwMjIzWhcNMjIwNDExMTkwMjIzWjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVl
# cnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkY4N0EtRTM3NC1EN0I5
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArXEX9hKdyXRikv+o3YWd/CN/SLxr4LgQ
# vPlRnLck5Tnhcf6se/XLcuApga7fCu01IRjgfPnPo9GUQm+/tora2bta8VJ6zuIs
# WFDTwNXiFXHnMXqWXm43a2LZ8k1nokOMxJVi5j/Bph00Wjs3iXzHzv/VJMihvc8O
# JqoCgRnWERua5GvjgQo//dEOCj8BjSjTXMAXiTke/Kt/PTcZokhnoQgiBthsToTY
# tfZwln3rdo1g9kthVs2dO+I7unZ4Ye1oCSfTxCvNb2nPVoYJNSUMtFQucyJBUs2K
# BpTW/w5PO/tqUAidOVF8Uu88hXQknZI+r7BUvE8aGJWzAStf3z+zNQIDAQABo4IB
# GzCCARcwHQYDVR0OBBYEFAk1yvF2cmfuPzFan0bHkD7X3z0pMB8GA1UdIwQYMBaA
# FNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8y
# MDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAt
# MDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJ
# KoZIhvcNAQELBQADggEBAAKIQYIH147iU86OMgJh+xOpqb0ip1G0yPbRQEFUuG5+
# 8/3G+Wgjwtn3A4+riwKglJ2EwtrBRZl3ru8WUz+IE/7teSrXT1Np5BITg1z254zX
# l+US9qjhm3MahZNzGkL5qVhjSRUYiPpLEFLGcKShl6xPjhZUhMFAv/jc+YfFUAUP
# QLVwPPNrme/UJKIO+dnio3Gk/pp/0hh8pskHhsnEGrnYVlVCpHh0Do1rsfixOGHU
# Bj+phzqTOZKmFS8TMKrnE9nz5OWyg01ljPpMBHqqd59PYP/cOyfteY77A2MiLoAR
# ZAkdqrAHtHk5Y7tAnunTtGX/hO+Q0zO9mXwEFJ9ftiMwggZxMIIEWaADAgECAgph
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
# UHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkY4N0EtRTM3NC1E
# N0I5MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEw
# BwYFKw4DAhoDFQDtLGAe3UndKpNNKrMtyswZlAFh76CBgzCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5Te9IjAiGA8y
# MDIxMTExMTIwMDI0MloYDzIwMjExMTEyMjAwMjQyWjB3MD0GCisGAQQBhFkKBAEx
# LzAtMAoCBQDlN70iAgEAMAoCAQACAiM0AgH/MAcCAQACAhEGMAoCBQDlOQ6iAgEA
# MDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAI
# AgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAnqYD8yPvoiw8hILRb1Xu8zXfsM4e
# 3InjK8rlmfNaeQX9PwDsxr7NiWWL1U0ZnZ+7q5hatTb3oyNjyp6aZq2W2oROpP3N
# yfbZMJxTAfvc0u/SLBDAYBRO/K7HBM+bAo3fFFjAugLR3WbsGfb1nyWHzbR+T3Jq
# uGHNhABU8vz1cWExggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAWOLZMbJhZZldgAAAAABYzANBglghkgBZQMEAgEFAKCCAUow
# GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCAHdUoY
# 0U0sbCnN8zH9dpBp4Sec9bR0A/ia7xcmHoP85DCB+gYLKoZIhvcNAQkQAi8xgeow
# gecwgeQwgb0EIJxZ3ZcdoWOhKKQpuLjL0BgEiksHL1FvXqezUasR9CNqMIGYMIGA
# pH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFji2TGyYWWZXYA
# AAAAAWMwIgQgbNyOcP0hXvI1cKvMuGogRKjNurAH+Ok0yUHzs1p6YT0wDQYJKoZI
# hvcNAQELBQAEggEAY7nWD5q315ALVQ+ZzTpCUUzSAdM585fjaRTxaWjAlJAg9ci0
# tulT6gUtTj+1sIL5DJ8rdchx84sHb6bQNO+QAw7TR5Pt4g1dshCcNAADUunJofJO
# PYFHnSHZTGqkdSS7a2KB0vZQ0VGLkzuvyu4HJFGOCKu4LlIkpcPab1IXKUw7IvrT
# fId+lG7PqvY8SMMsdFVDXsEtDFDIFyDPJhNQXThflz/Y9jG2tKRRu5v3m92bBspc
# Bxp+w0TNz3SgjQ465OxkBF4YJsggFzJQr4s/cQVSblSblRNPiKSbAfmrtKxCDbnc
# 7Hk8ElXM9W1/HasmNBYupRX0RE6+62O6mEwn+w==
# SIG # End signature block
