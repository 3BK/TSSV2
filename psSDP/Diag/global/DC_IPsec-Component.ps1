#************************************************
# DC_IPsec-Component.ps1
# Version 1.0
# Version 1.1: Altered the runPS function correctly a column width issue.
# Date: 2009-2014
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: Collects information about the IPsec component.
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
Write-DiagProgress -Activity $ScriptVariable.ID_CTSIPsec -Status $ScriptVariable.ID_CTSIPsecDescription

# detect OS version and SKU
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber


function RunNetSH ([string]$NetSHCommandToExecute="")
{
	
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSIPsec -Status "netsh $NetSHCommandToExecute"
	
	$NetSHCommandToExecuteLength = $NetSHCommandToExecute.Length + 6
	"`n`n`n" + "-" * ($NetSHCommandToExecuteLength) + "`r`n" + "netsh $NetSHCommandToExecute" + "`r`n" + "-" * ($NetSHCommandToExecuteLength) | Out-File -FilePath $OutputFile -append

	$CommandToExecute = "cmd.exe /c netsh.exe " + $NetSHCommandToExecute + " >> $OutputFile "
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
	"`n"													| Out-File -FilePath $OutputFile -append
	"`n"													| Out-File -FilePath $OutputFile -append
	"`n"													| Out-File -FilePath $OutputFile -append
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
	"`n"													| Out-File -FilePath $OutputFile -append
	"`n"													| Out-File -FilePath $OutputFile -append
	"`n"													| Out-File -FilePath $OutputFile -append
}


$sectionDescription = "IPsec"


if ($bn -gt 9000)
{
	$outputFile = join-path $pwd.path ($ComputerName + "_IPsec_info_pscmdlets.TXT")
	"========================================"				| Out-File -FilePath $OutputFile -append
	"IPsec Powershell Cmdlets"								| Out-File -FilePath $OutputFile -append
	"========================================"				| Out-File -FilePath $OutputFile -append
	"Overview"												| Out-File -FilePath $OutputFile -append
	"----------------------------------------"				| Out-File -FilePath $OutputFile -append
	"   1. Get-NetIPsecDospSetting"							| Out-File -FilePath $OutputFile -append
	"   2. Get-NetIPsecMainModeCryptoSet"					| Out-File -FilePath $OutputFile -append
	"   3. Get-NetIPsecMainModeRule"						| Out-File -FilePath $OutputFile -append
	"   4. Get-NetIPsecMainModeSA"							| Out-File -FilePath $OutputFile -append
	"   5. Get-NetIPsecPhase1AuthSet"						| Out-File -FilePath $OutputFile -append
	"   6. Get-NetIPsecPhase2AuthSet"						| Out-File -FilePath $OutputFile -append
	"   7. Get-NetIPsecQuickModeCryptoSet"					| Out-File -FilePath $OutputFile -append
	"   8. Get-NetIPsecQuickModeSA"							| Out-File -FilePath $OutputFile -append
	"========================================"				| Out-File -FilePath $OutputFile -append
	"`n"													| Out-File -FilePath $OutputFile -append
	"`n"													| Out-File -FilePath $OutputFile -append
	"`n"													| Out-File -FilePath $OutputFile -append
	"`n"													| Out-File -FilePath $OutputFile -append
	"`n"													| Out-File -FilePath $OutputFile -append
	# This command exceptions on client skus
	#_#if ($bn -gt 9000)
		#_#if ($bn -ge 9000)
		#Get role, OSVer, hotfix data. #_#
		$cs =  Get-CimInstance -Namespace "root\cimv2" -class win32_computersystem #-ComputerName $ComputerName #_#
		$DomainRole = $cs.domainrole #_#
	if (($bn -gt 9000) -and ($DomainRole -ge 2)) #_# not on Win8+,Win10 client
	{
		runPS "Get-NetIPsecDospSetting"				# W8/WS2012, W8.1/WS2012R2	# fl
	}
	runPS "Get-NetIPsecMainModeCryptoSet"		# W8/WS2012, W8.1/WS2012R2	# unknown
	runPS "Get-NetIPsecMainModeRule"			# W8/WS2012, W8.1/WS2012R2	# unknown
	runPS "Get-NetIPsecMainModeSA"				# W8/WS2012, W8.1/WS2012R2	# fl
	runPS "Get-NetIPsecPhase1AuthSet"			# W8/WS2012, W8.1/WS2012R2	# unknown
	runPS "Get-NetIPsecPhase2AuthSet"			# W8/WS2012, W8.1/WS2012R2	# unknown
	runPS "Get-NetIPsecQuickModeCryptoSet"		# W8/WS2012, W8.1/WS2012R2	# unknown
	runPS "Get-NetIPsecQuickModeSA"				# W8/WS2012, W8.1/WS2012R2	# fl
	CollectFiles -sectionDescription $sectionDescription -fileDescription "IPsec Powershell Cmdlets" -filesToCollect $outputFile 
}


#----------Netsh
$OutputFile = $ComputerName + "_IPsec_netsh_dynamic.TXT"
"========================================"		| Out-File -FilePath $OutputFile -append
"IPsec Netsh Output (DYNAMIC)"					| Out-File -FilePath $OutputFile -append
"========================================"		| Out-File -FilePath $OutputFile -append
"Overview"										| Out-File -FilePath $OutputFile -append
"----------------------------------------"		| Out-File -FilePath $OutputFile -append
"   1. netsh ipsec dynamic show all"			| Out-File -FilePath $OutputFile -append
"========================================"		| Out-File -FilePath $OutputFile -append
"`n"											| Out-File -FilePath $OutputFile -append
"`n"											| Out-File -FilePath $OutputFile -append
"`n"											| Out-File -FilePath $OutputFile -append
"`n"											| Out-File -FilePath $OutputFile -append
"`n"											| Out-File -FilePath $OutputFile -append
RunNetSH -NetSHCommandToExecute "ipsec dynamic show all"
CollectFiles -filesToCollect $OutputFile -fileDescription "IPsec netsh dynamic show all" -SectionDescription $sectionDescription


$OutputFile = $ComputerName + "_IPsec_netsh_static.TXT"
"========================================"		| Out-File -FilePath $OutputFile -append
"IPsec Netsh Output (STATIC)"					| Out-File -FilePath $OutputFile -append
"========================================"		| Out-File -FilePath $OutputFile -append
"Overview"										| Out-File -FilePath $OutputFile -append
"----------------------------------------"		| Out-File -FilePath $OutputFile -append
"   1. netsh ipsec static show all"				| Out-File -FilePath $OutputFile -append
"========================================"		| Out-File -FilePath $OutputFile -append
"`n"											| Out-File -FilePath $OutputFile -append
"`n"											| Out-File -FilePath $OutputFile -append
"`n"											| Out-File -FilePath $OutputFile -append
"`n"											| Out-File -FilePath $OutputFile -append
"`n"											| Out-File -FilePath $OutputFile -append
RunNetSH -NetSHCommandToExecute "ipsec static show all"
CollectFiles -filesToCollect $OutputFile -fileDescription "IPsec netsh static show all" -SectionDescription $sectionDescription


$filesToCollect = $ComputerName + "_IPsec_netsh_LocalPolicyExport.ipsec"
$commandToRun = "netsh ipsec static exportpolicy " +  $filesToCollect
RunCMD -CommandToRun $commandToRun -filesToCollect $filesToCollect -fileDescription "IPsec Local Policy Export" -sectionDescription $sectionDescription 



#----------Registry
$OutputFile= $Computername + "_IPsec_reg_.TXT"
$CurrentVersionKeys =	"HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec",
						"HKLM\SYSTEM\CurrentControlSet\Services\IPsec",
						"HKLM\SYSTEM\CurrentControlSet\Services\IKEEXT",
						"HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent"
RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -OutputFile $OutputFile -fileDescription "IPsec Registry keys" -SectionDescription $sectionDescription



# SIG # Begin signature block
# MIInzAYJKoZIhvcNAQcCoIInvTCCJ7kCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCwI5X2MVP25ueF
# cHJmS75fOdey8/8dl+SeqDNfYqIidKCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZoTCCGZ0CAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBsDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgi+S8kVL4
# 3SuxTkYlQ1fCC6QnqMbR6jIP8wM/QtK11/0wRAYKKwYBBAGCNwIBDDE2MDSgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20g
# MA0GCSqGSIb3DQEBAQUABIIBAIW5dSHLMPekEDDAeAiHT9gchnGvaVoZJD9JB/jG
# uENFUKdWQfHoePk7i52Abm3ngyEuqFQ2Hrh7J6iYKuysAwz3tDIfQOqqwJ7/9Wwa
# XDy8LOa+n8IZtufWNQ4/W2D4PkJJl4tz27gFgcIDpJnv+H0GV+DoJru03Ju9Bgj7
# i8ASTvd8ivlakYRgg8M7/lWsh1mpaInSN6/IZ2QRXhPr0uI4r/oHG9Z3L5fgRCPt
# 2ySGdrt2tHdF6yUyfEk2K7/n1MvgMC1WBMcVcjOvGbCQ2LMug0Lqbk0XiuyUn4jS
# 9oHww+bCF3DK9OUnfUqePNRElw9N1aZQL7W171nM1iUsKpChghcpMIIXJQYKKwYB
# BAGCNwMDATGCFxUwghcRBgkqhkiG9w0BBwKgghcCMIIW/gIBAzEPMA0GCWCGSAFl
# AwQCAQUAMIIBWQYLKoZIhvcNAQkQAQSgggFIBIIBRDCCAUACAQEGCisGAQQBhFkK
# AwEwMTANBglghkgBZQMEAgEFAAQgUST1LutXb7O/bAsreqf5pevfu4XEoMU6rHOW
# mPnDDtcCBmNP9G5DsRgTMjAyMjEwMjQwODE1MjIuMjgxWjAEgAIB9KCB2KSB1TCB
# 0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMk
# TWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjozQkQ0LTRCODAtNjlDMzElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaCCEXgwggcnMIIFD6ADAgECAhMzAAABtPuACEQF
# 0i36AAEAAAG0MA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwMB4XDTIyMDkyMDIwMjIwOVoXDTIzMTIxNDIwMjIwOVowgdIxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29m
# dCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRT
# UyBFU046M0JENC00QjgwLTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0R6ae
# ZQcyQh+86K7bsrzplvBaGSwbBXvYOXW4Z2qvakqb6Z/OhP5ieCSr1osR/5cO0API
# D7YohlTSI7xYbv14mPPPb1+VmkEpsqDzGXY/c712uV65DDdOc1803j5AiCMxekTe
# 3E8XszshEspkyI63cV+QVZWaJckADsTc4jAmCmGDT22HdO/OnwxPz4c60bdt2tF3
# /La7xWtCxBMtmJXBNnqoNgo1Pw9BmXvEWtJI7dDNdr3UuKlmdg6XeyIYkMJ57UFr
# tfWLXd1AUfEqXkV/gnMN244Fnzl7ZWunIXLVrdrIZTMGsjDn2OExuMjD1hVxC32R
# Rae3IKY2TXlbJsJL6FekQMMtWPVflb2yeahbWq7Tf66emtCNZBpW47sF9y9B01V3
# IpKoB4rLV5PYdxzmfVoBV5cWbqxtUmZnM9ARBHcmvtbxhxOOSoLmFPaqti4hxgY5
# /c+Pg6p1ebVCqG7C2yTG+K/vLLdn4/EmnErH7Z7rMZFqhCYiUt+D9rjZc1UdN/pb
# OvmTtDXDu/S4D+wWyDIqYjsfModfTzEMNKYmihcDlu0PoHSXH8uqzpBvgq2GcDs3
# YgR0nmyMwiHIdnAGvt/MOyRT/5KCnZSd+qs3VV1r+Bv6maVsnCLwymG8SVjONPs9
# krYObh6ityPHtPZBV7cQh6Uu4ZvHPJtuVmhFOQIDAQABo4IBSTCCAUUwHQYDVR0O
# BBYEFMtEheXxlLg6nLsSKLdO3jjMMtl+MB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl
# 0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1T
# dGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4IC
# AQAS0Q8FjCm3gmKhKrSOgbPCphfpKg0fthuqmACt2Wet23q7e6QpESW4oRWpLZdq
# NfHHRSRcZzheL12nZtLGm7JCdOSr4hDCSDunV0qvABra92Zo3PPeatJp5QS7jTIJ
# OEfCq5CTB6gbh6pFFl7X061VKYMM0LdlDoiDSrPv2+K9eDLl0VaTienEDkvFIZHj
# AFpdoi5WGgRrTq93/3/ZixD31sKJHtLElG3VetDmQkYdSLQWGDPXnyq9eB+aruo2
# p+p9NKaxBGu1t7hm/9f6o+j+Xpp75KsuRyNF+vQ41XS8VW40rHoJv3QPkuA2lz3H
# xX+ogcSv4ldtZdbqYBFVWo1AKZeVUeNMGOFxfBKZp1HU6i1w3+wqnYQ4z0k9ivzo
# 71j8kBkL3O6D2qWMpOuhlN9gDssh1yY+vr27UVIP/qK8vodEdl3+TYQvsW1nDM1x
# FF0UX9WCmQ7Ech+q+NdqZvCgyhP6+0ZO2qCiu6GFKTRszUX+kGmL+c9m1U0sZM1o
# rxa3qSxxsL0bp/T2DP/AEEk4Ga9Ms845P/e1oIZKgmgMAFacr4N7mmJ7gpfwHHEp
# Bsm/HPu9GxUnlHqYbH4G9q/kCOzG9lnDp5CaQjS89FyTEv1MJUJ9ZLS7IgqbKjpN
# 2iydsE7+iyt7uvSNL0AfyykSpWWEVylA186D8K91LbE1UzCCB3EwggVZoAMCAQIC
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
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLUMIICPQIBATCCAQChgdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046M0JENC00QjgwLTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAGWc2JDzm5f2c3gpEm3+
# AeQnHgkIoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJ
# KoZIhvcNAQEFBQACBQDnAGF6MCIYDzIwMjIxMDI0MDg1NzMwWhgPMjAyMjEwMjUw
# ODU3MzBaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOcAYXoCAQAwBwIBAAICA20w
# BwIBAAICEUcwCgIFAOcBsvoCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGE
# WQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQB2
# 9Eoq2rE/ZXu39z7+0C21mJxFXpKAFS+Z05SfSbiNBrV782bIUjfJdi4FyqFAWXoy
# 6DAK69T8VeYZnLaWw+2W8HOa3G9kjzgQi+dA1LJrFWcZXV6L5WMquKcujTNNO7fy
# mukO/ZNLL7jQEFI1LQCeYil4UtL9tUy/Ct60bINxwzGCBA0wggQJAgEBMIGTMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABtPuACEQF0i36AAEAAAG0
# MA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQw
# LwYJKoZIhvcNAQkEMSIEIGOxBG660bopG8WIGg2G7fd8iZbXWH86SwQnCzifQj89
# MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg08j3e+ajMHAGUXG9+v+sSWt4
# U9Hi7Hu9crHaeLcB9wYwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAbT7gAhEBdIt+gABAAABtDAiBCB7pzAYNk6Bv6DINVDi95N/Qt2m
# nlTpLgDr8d899IEuqDANBgkqhkiG9w0BAQsFAASCAgAAfWfbEDZaA6/WFZKBG/cb
# RzVnVn1mADe+oNvG8hshb8wkPYx1oO/jNwekFMZQ1Cy/vRkNTbOtbWg1IYIEin6f
# ehleY6eCMSDheZ6VyV/663hYxyvmKVylNuom9fKASLYQAHk7jZaFowAEbp8FWXj3
# 2No6wk2isz38qrXWLNRRv9bVXycS+4AklMCGWQQys2vgAmvQk3oeL5fSeZner8jF
# RVjY93JOafiavYjHygi+Fvvod7p/kRMvy6tOLi4YBdSqcDyeFnP3XVO8cwg/gy+D
# eyH5j0VGjldfVGUYr4oVF31evbOSqmUg2+ykJmvL2UY6gVU26Cuyl7zK15iGdyqZ
# /otql0IL0T8gLqtFnoYDT1WaORhNUKkFFcveJrL5w1ynD+0MHnqFNVKnY1Fv5vBZ
# Q/2aoaCkvodlwrh5D83qyQ2lC59+nm5zDs2hOGLlpohc76SYuv7aXuQLzynree6p
# sXZbXwiQUGOVMh29ZP1LBM6v2WN+i7CRtw8JlBImhSVBJdvoZnJFQy3h+jPTS2C3
# a5iNVSKOIGIHMWXf6TKJOytm2IjfkOjHXlK1e5KXygbsfVT4750IJUEI2oC+bBUe
# qQwhBzgLLQWXJulPPm7cGxstCMugmf/OyyeSYmB0gQIZcnnqTUVrBH7or/45SkwN
# 62MqsPvl4gyzuDAKjFW0KQ==
# SIG # End signature block
