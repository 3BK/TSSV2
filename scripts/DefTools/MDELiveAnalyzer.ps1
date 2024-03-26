#Enforcing default PSModulePath to avoid getting unexpected modules to run instead of built-in modules
$env:PSModulePath = "C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules"
$resultOutputDir = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\MDEClientAnalyzerResult"

function CheckAuthenticodeSignature($pathToCheck) {
	If (Test-Path -path $pathToCheck -ErrorAction SilentlyContinue) {
		$AuthenticodeSig = (Get-AuthenticodeSignature -FilePath $pathToCheck)
		$cert = $AuthenticodeSig.SignerCertificate
		$FileInfo = (get-command $pathToCheck).FileVersionInfo
		if (test-path $resultOutputDir -ErrorAction SilentlyContinue) {
		    $issuerInfo = "$resultOutputDir\issuerInfo.txt"
        } else {
            $issuerInfo = "$PSScriptRoot\issuerInfo.txt"
        }
		$issuer = $cert.Issuer

		#OS is older than 2016 and some built-in processes will not be signed
		if (($OSBuild -lt 14393) -and (!$AuthenticodeSig.SignerCertificate)) {
			if (($FileInfo.CompanyName -eq "Microsoft Corporation")) {
				return
			}
			else {
				Write-Error "Script execution terminated because a process or script that does not have any signature was detected" | Out-File $issuerInfo -append
				$pathToCheck | Out-File $issuerInfo -append
				$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
				$cert | Format-List * | Out-File $issuerInfo -append
				[Environment]::Exit(1)
			}
		}
		#check if valid
		if ($AuthenticodeSig.Status -ne "Valid") {
			Write-Error "Script execution terminated because a process or script that does not have a valid Signature was detected" | Out-File $issuerInfo -append
			$pathToCheck | Out-File $issuerInfo -append
			$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
			$cert | Format-List * | Out-File $issuerInfo -append
			[Environment]::Exit(1)
		}
		#check issuer
		if (($issuer -ne "CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Code Signing PCA, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Code Signing PCA 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Development PCA 2014, O=Microsoft Corporation, L=Redmond, S=Washington, C=US")) {
			Write-Error "Script execution terminated because a process or script that is not Microsoft signed was detected" | Out-File $issuerInfo -append
			$pathToCheck | Out-File $issuerInfo -append
			$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
			$cert | Format-List * | Out-File $issuerInfo -append
			[Environment]::Exit(1)
		}	
		if ($AuthenticodeSig.IsOSBinary -ne "True") {
			#If revocation is offline then test below will fail
			$IsOnline = (Get-NetConnectionProfile).IPv4Connectivity -like "*Internet*"
			if ($IsOnline) {
				$IsWindowsSystemComponent = (Test-Certificate -Cert $cert -EKU "1.3.6.1.4.1.311.10.3.6" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -WarningVariable OsCertWarnVar -ErrorVariable OsCertErrVar)
				$IsMicrosoftPublisher = (Test-Certificate -Cert $cert -EKU "1.3.6.1.4.1.311.76.8.1" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -WarningVariable MsPublisherWarnVar -ErrorVariable MsPublisherErrVar)
				if (($IsWindowsSystemComponent -eq $False) -and ($IsMicrosoftPublisher -eq $False)) {
					#Defender AV and some OS processes will have an old signature if older version is installed
					#Ignore if cert is OK and only signature is old
					if (($OsCertWarnVar -like "*CERT_TRUST_IS_NOT_TIME_VALID*") -or ($MsPublisherWarnVar -like "*CERT_TRUST_IS_NOT_TIME_VALID*") -or ($OsCertWarnVar -like "*CERT_TRUST_IS_OFFLINE_REVOCATION*") -or ($MsPublisherWarnVar -like "CERT_TRUST_IS_OFFLINE_REVOCATION")) {
						return
					}
					Write-Error "Script execution terminated because the process or script certificate failed trust check" | Out-File $issuerInfo -append
					$pathToCheck | Out-File $issuerInfo -append
					$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
					$cert | Format-List * | Out-File $issuerInfo -append
					[Environment]::Exit(1)
				}
			}
		}
	}
 else {
		Write-Error ("Path " + $pathToCheck + " was not found") | Out-File $issuerInfo -append
	}
}

function Download-WebFile($ClientAnalyzer) {    
    Write-host -ForegroundColor Green "Downloading MDEClientAnalyzer from: " $ClientAnalyzer
       Import-Module BitsTransfer
       $BitsJob = Start-BitsTransfer -source $ClientAnalyzer -Destination "$DlZipFile" -Description "Downloading additional files" -RetryTimeout 60 -RetryInterval 60 -ErrorAction SilentlyContinue
}
$DownloadDir = "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads"
$DlZipFile = Join-Path $DownloadDir "MDEClientAnalyzerPreview.zip"
$ToolsDir = Join-Path $DownloadDir "Tools"
CheckAuthenticodeSignature $MyInvocation.MyCommand.Path

if (!(test-path –path "$DlZipFile")) {
    Download-WebFile "https://aka.ms/Betamdeanalyzer"    
}
if  (test-path –path "$DlZipFile") {
    Remove-item '$DownloadDir\MDEClientAnalyzer.ps1' -Force -ErrorAction SilentlyContinue
    Remove-Item '$ToolsDir\*.*' -Force -ErrorAction SilentlyContinue
    Expand-Archive -Path $DlZipFile -DestinationPath $DownloadDir -Force -ErrorAction SilentlyContinue
	CheckAuthenticodeSignature "C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\MDEClientAnalyzer.ps1"
    &powershell -ExecutionPolicy Bypass "& 'C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\MDEClientAnalyzer.ps1' -outputDir 'C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads'"
}








# SIG # Begin signature block
# MIInoQYJKoZIhvcNAQcCoIInkjCCJ44CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDY04nM1w89lLj3
# KGBPmvoE5gx5/+kDjcpOYzwAAs0j7qCCDYEwggX/MIID56ADAgECAhMzAAACUosz
# qviV8znbAAAAAAJSMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjEwOTAyMTgzMjU5WhcNMjIwOTAxMTgzMjU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDQ5M+Ps/X7BNuv5B/0I6uoDwj0NJOo1KrVQqO7ggRXccklyTrWL4xMShjIou2I
# sbYnF67wXzVAq5Om4oe+LfzSDOzjcb6ms00gBo0OQaqwQ1BijyJ7NvDf80I1fW9O
# L76Kt0Wpc2zrGhzcHdb7upPrvxvSNNUvxK3sgw7YTt31410vpEp8yfBEl/hd8ZzA
# v47DCgJ5j1zm295s1RVZHNp6MoiQFVOECm4AwK2l28i+YER1JO4IplTH44uvzX9o
# RnJHaMvWzZEpozPy4jNO2DDqbcNs4zh7AWMhE1PWFVA+CHI/En5nASvCvLmuR/t8
# q4bc8XR8QIZJQSp+2U6m2ldNAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUNZJaEUGL2Guwt7ZOAu4efEYXedEw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDY3NTk3MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAFkk3
# uSxkTEBh1NtAl7BivIEsAWdgX1qZ+EdZMYbQKasY6IhSLXRMxF1B3OKdR9K/kccp
# kvNcGl8D7YyYS4mhCUMBR+VLrg3f8PUj38A9V5aiY2/Jok7WZFOAmjPRNNGnyeg7
# l0lTiThFqE+2aOs6+heegqAdelGgNJKRHLWRuhGKuLIw5lkgx9Ky+QvZrn/Ddi8u
# TIgWKp+MGG8xY6PBvvjgt9jQShlnPrZ3UY8Bvwy6rynhXBaV0V0TTL0gEx7eh/K1
# o8Miaru6s/7FyqOLeUS4vTHh9TgBL5DtxCYurXbSBVtL1Fj44+Od/6cmC9mmvrti
# yG709Y3Rd3YdJj2f3GJq7Y7KdWq0QYhatKhBeg4fxjhg0yut2g6aM1mxjNPrE48z
# 6HWCNGu9gMK5ZudldRw4a45Z06Aoktof0CqOyTErvq0YjoE4Xpa0+87T/PVUXNqf
# 7Y+qSU7+9LtLQuMYR4w3cSPjuNusvLf9gBnch5RqM7kaDtYWDgLyB42EfsxeMqwK
# WwA+TVi0HrWRqfSx2olbE56hJcEkMjOSKz3sRuupFCX3UroyYf52L+2iVTrda8XW
# esPG62Mnn3T8AuLfzeJFuAbfOSERx7IFZO92UPoXE1uEjL5skl1yTZB3MubgOA4F
# 8KoRNhviFAEST+nG8c8uIsbZeb08SeYQMqjVEmkwggd6MIIFYqADAgECAgphDpDS
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZdjCCGXICAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAlKLM6r4lfM52wAAAAACUjAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg+CRmgJBe
# kePlAT6AGGLT7MPl+8ThdE4b75AockYjZJAwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQADA+xhyOqkJYV2M/WYlsCKPu5yxXZU4X2XyOnMHHxB
# KvkrpmHiaGMUOjc/pc3lEJ4+aT/2I91o4f8fGScME+1SFu8QDDkfrCyY3KIIrtq/
# oIG9sN+6KC92VMr9Bz7PObbe9Tc1S4iSWubQ1t9Bw2vA0PL6zsO897a4ZDllidss
# MxvqH6AYSDLryaeDfsRtfbL1iWfX/IALOs+YuIeBnWGTSCItyrARWjdvMfaxzg3e
# NEtqTd7xa7PKCE1BeKrSPhKEAU+KNLmg9cjIeC1uci9257mPiK2BL3dGNcCYU4oQ
# v8WwTRLLsJ09lmYqmEPuHEozeitzS0lPnF2ZejT/wo5yoYIXADCCFvwGCisGAQQB
# gjcDAwExghbsMIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEINXNseq6qXEId9IbHLyoQtklb5pny9PqxMKpsj78
# uYKMAgZigjBbizQYEzIwMjIwNTE3MTE1NjQ0LjY0MlowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOkREOEMtRTMzNy0yRkFFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIRVzCCBwwwggT0oAMCAQICEzMAAAGcD6ZNYdKeSygAAQAAAZww
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjExMjAyMTkwNTE5WhcNMjMwMjI4MTkwNTE5WjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046REQ4Qy1FMzM3LTJG
# QUUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDbUioMGV1JFj+s612s02mKu23KPUNs
# 71OjDeJGtxkTF9rSWTiuA8XgYkAAi/5+2Ff7Ck7JcKQ9H/XD1OKwg1/bH3E1qO1z
# 8XRy0PlpGhmyilgE7KsOvW8PIZCf243KdldgOrxrL8HKiQodOwStyT5lLWYpMsuT
# 2fH8k8oihje4TlpWiFPaCKLnFDaAB0Ccy6vIdtHjYB1Ie3iOZPisquL+vNdCx7gO
# hB8iiTmTdsU8OSUpC8tBTeTIYPzmhaxQZd4moNk6qeCJyi7fiW4fyXdHrZ3otmgx
# xa5pXz5pUUr+cEjV+cwIYBMkaY5kHM9c6dEGkgHn0ZDJvdt/54FOdSG61WwHh4+e
# vUhwvXaB4LCMZIdCt5acOfNvtDjV3CHyFOp5AU/qgAwGftHU9brv4EUwcuteEAKH
# 46NufE20l/WjlNUh7gAvt2zKMjO4zXRxCUTh/prBQwXJiUZeFSrEXiOfkuvSlBni
# yAYYZp5kOnaxfCKdGYjvr4QLA93vQJ6p2Ox3IHvOdCPaCr8LsKVcFpyp8MEhhJTM
# +1LwqHJqFDF5O1Z9mjbYvm3R9vPhkG+RDLKoTpr7mTgkaTljd9xvm94Obp8BD9Hk
# 4mPi51mtgLiuN8/6aZVESVZXtvSuNkD5DnIJQerIy5jaRKW/W2rCe9ngNDJadS7R
# 96GGRl7IIE37lwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFLtpCWdTXY5dtddkspy+
# oxjCA/qyMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRY
# MFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01p
# Y3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEF
# BQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAo
# MSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQELBQADggIBAKcAKqYjGEczTWMs9z0m7Yo23sgqVF3LyK6gOMz7TCHAJN+F
# vbvZkQ53VkvrZUd1sE6a9ToGldcJnOmBc6iuhBlpvdN1BLBRO8QSTD1433VTj4XC
# Qd737wND1+eqKG3BdjrzbDksEwfG4v57PgrN/T7s7PkEjUGXfIgFQQkr8TQi+/HZ
# Z9kRlNccgeACqlfb4uGPxn5sdhQPoxdMvmC3qG9DONJ5UsS9KtO+bey+ohUTDa9L
# vEToc4Qzy5fuHj2H1JsmCaKG78nXpfWpwBLBxZYSpfml29onN8jcG7KD8nGSS/76
# PDlb2GMQsvv+Ra0JgL6FtGRGgYmHCpM6zVrf4V/a+SoHcC+tcdGYk2aKU5KOlv+f
# FE3n024V+z54tDAKR9z78rejdCBWqfvy5cBUQ9c5+3unHD08BEp7qP2rgpoD856v
# NDgEwO77n7EWT76nl/IyrbK2kjbHLzUMphFpXKnV1fYWJI2+E/0LHvXFGGqF4OvM
# BRxbrJVn03T2Dy5db6s5TzJzSaQvCrXYqA4HKvstQWkqkpvBHTX8M09+/vyRbVXN
# xrPdeXw6oD2Q4DksykCFfn8N2j2LdixE9wG5iilv69dzsvHIN/g9A9+thkAQCVb9
# DUSOTaMIGgsOqDYFjhT6ze9lkhHHGv/EEIkxj9l6S4hqUQyWerFkaUWDXcnZMIIH
# cTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCB
# iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMp
# TWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEw
# OTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIh
# C3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNx
# WuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFc
# UTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAc
# nVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUo
# veO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyzi
# YrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9
# fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdH
# GO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7X
# KHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiE
# R9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/
# eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3
# FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAd
# BgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEE
# AYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMB
# Af8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1Ud
# HwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3By
# b2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQRO
# MEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2Vy
# dHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4IC
# AQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pk
# bHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gng
# ugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3
# lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHC
# gRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6
# MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEU
# BHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvsh
# VGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+
# fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrp
# NPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHI
# qzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs4wggI3AgEBMIH4
# oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUw
# IwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjpERDhDLUUzMzctMkZBRTElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAzdlp6t3ws/bnErbm
# 9c0M+9dvU0CggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAN
# BgkqhkiG9w0BAQUFAAIFAOYuAEowIhgPMjAyMjA1MTcxOTA2NTBaGA8yMDIyMDUx
# ODE5MDY1MFowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5i4ASgIBADAKAgEAAgIV
# cAIB/zAHAgEAAgIRrzAKAgUA5i9RygIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUA
# A4GBAEFWITEk7nGtGO7RelgjsLIpSJAZLilAtDJhbxy69OU0yr6X7LedFGmA58W5
# Ss7PZFkFTTUgVK/L0ukT8zOvTZMuOKPDSsQfeW9TCOXcKQNP4aGxqyNOImZg30xg
# pk261W0Y/uJZ7p2Empf72E5Ng6GiLfjXBIyLfXW2ISQE9jpiMYIEDTCCBAkCAQEw
# gZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGcD6ZNYdKeSygA
# AQAAAZwwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0B
# CRABBDAvBgkqhkiG9w0BCQQxIgQgvlsywqMi4QO7I7UtlvMtiZbkP4TQxQtmaPTP
# Knif18cwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCA3D0WFII0syjoRd/Xe
# EIG0WUIKzzuy6P6hORrb0nqmvDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABnA+mTWHSnksoAAEAAAGcMCIEIKmCgvviVSQiH3bB4+uB
# wb03JtTzD2sthORx+LU6mW77MA0GCSqGSIb3DQEBCwUABIICAG49PzsmIvkP3v+d
# 6kPr4ISJfarU4JDaT/1BbF65wsLzkGLZPOEEjk4I34n92vbZWkQ6dAIOS2RBGAlm
# KgC8X0tTPYBK3qbbuuMsDT1LY3vF10d1FziHMYzP3nIXt+0py90Q7YcvCMC05EkN
# qQ4x9zXe884VRDaQ81aRJ8xZKyd8lAVqejUEMsxGllQ5Lf/u2lKW1HygrQcFpGIs
# L3ffTCNYL7ZIk73t3mXWMb/O5fCssl+T8zd+PoHnWAu7B8fLbgoTjISkBGH2VeHN
# xibg5n4yZ0/54jt/3XcWxD6vqHkb3g0XL2K6cDaXGFOUsKi2sZhS9j903gwBW0gW
# Vfnpiob9SRT/SOdb/bwYuuUucuOJMkvDokPOmrtKZNz3tW4ykMoTRFHJ7pppfdma
# eUa/JPfAFlWUD2+jmbA/6Z7b/oQ31KQ2JrgK4Qbw97jGCvUjyDzgTcCP2efswNUj
# io58Vyg2OcrKET5Xw5hc3mix5Qw+TgB4fUw/dC0mKOJOlKr7wKyeV1mR4G6lBZ35
# 3bs9KPRqLY3aGhE932U/j9DvnErVfEI4xrq6cSP4AsiEsUvl7eEv0HVKaoaQt0sb
# UcfKqSdgKGWQZG0E1cBsFgTPfsQ6DDoYrrZBlEzeRC+T0onlzulJVO8++rakM9KV
# UJgprvvADkcYSLklY9dUXr4cMfqr
# SIG # End signature block
