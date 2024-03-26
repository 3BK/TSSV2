# Load Common Library
# Load Reporting Utilities
#$debug = $false

. ./utils_cts.ps1
. ./TS_RemoteSetup.ps1

# 2023-02-20 WalterE mod Trap #we#
trap [Exception]{
	WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; continue
	Write-Host "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_"
}

$FirstTimeExecution = FirstTimeExecution

if ($FirstTimeExecution) {
	if (Test-Path 'HKLM:\Cluster'){
		#_#[Array] $NodeNames = .\TS_SelectClusterNodes.ps1
		[Array] $NodeNames = (Get-ClusterNode -ErrorAction SilentlyContinue | where-object {$_.State -match "up"}).Nodename  #_# -EA added 2020-08-20
		if (-not $NodeNames) {$NodeNames = $ComputerName}	#_#added 2020-08-20
	}else{
		$NodeNames = $ComputerName
	}
	if ($Global:localNodeOnly -ne $true) {
		if ($null -ne $NodeNames) {
			$ExpressionArray = @()
			$ItemNumber = 0	
			
			$ExpressionToRunOnMachine = @'
			Run-DiagExpression .\DC_BasicSystemInformation.ps1 -MachineName $Env:COMPUTERNAME
			Run-DiagExpression .\DC_ClusterLogs.ps1 -LocalOnly
			Run-DiagExpression .\TS_DumpCollector.ps1 -CopyWERMinidumps -CopyWERFulldumps -CopyOnlyUserDumpsFrom "vmms.exe" -SkipAlertsForCategories "machinedumpconfig"
			.\TS_AutoAddCommands_HyperV.ps1
			Run-DiagExpression .\DC_SummaryReliability.ps1
'@	

			#_#if (($NodeNames.Count -eq 1) -and ($NodeNames[0] = $ComputerName))
			if (($NodeNames -is [string]) -or (($NodeNames.Count -eq 1) -and ($NodeNames[0] -eq $ComputerName))){
				if ($NodeNames.Count -eq 1){
					$ExpressionToRunOnMachine += "`r`n Run-DiagExpression .\TS_BasicClusterInfo.ps1"
				}
				Invoke-Expression $ExpressionToRunOnMachine
			}else{
				foreach ($MachineName in $NodeNames){
					if ($ItemNumber -eq 0) {
						#Execute TS_BasicClusterInfo only in one node
						$ExpressionArray += ($ExpressionToRunOnMachine + "`r`n Run-DiagExpression .\TS_BasicClusterInfo.ps1")
					}else{
						$ExpressionArray += $ExpressionToRunOnMachine
					}
					$ItemNumber += 1
				}
				"Running package using TS_Remote on $NodeNames" | WriteTo-StdOut -ShortFormat #_#
				#_#ExecuteRemoteExpression -ComputerNames $NodeNames -Expression $ExpressionArray -ShowDialog
				ExecuteRemoteExpression -ComputerNames $NodeNames -Expression $ExpressionArray
			}
			if ($NodeNames -contains $ComputerName){
				#TS_ClusterValidationTests.ps1 can be executed only locally due the issue with double hop authentication.
				"Running ClusterValidationTests on $ComputerName" | WriteTo-StdOut -ShortFormat #_#
				Run-DiagExpression .\TS_ClusterValidationTests.ps1
			}
		}
	}else{ # run on localNodeOnly
		"User/script selected localNodeOnly. Running package locally instead of using TS_Remote" | WriteTo-StdOut -ShortFormat
		"User/script selected localNodeOnly." | Write-host
		Run-DiagExpression .\TS_BasicClusterInfo.ps1
		Run-DiagExpression .\DC_BasicSystemInformation.ps1 -MachineName $Env:COMPUTERNAME
		Run-DiagExpression .\DC_ClusterLogs.ps1 -LocalOnly
		.\TS_AutoAddCommands_HyperV.ps1
		Run-DiagExpression .\DC_SummaryReliability.ps1
		"Running ClusterValidationTests on $ComputerName" | WriteTo-StdOut -ShortFormat #_#
		Run-DiagExpression .\TS_ClusterValidationTests.ps1
		if ($Global:skipNetview -ne $true) {
			Write-Host -BackgroundColor Gray -ForegroundColor Black -Object "--- $(Get-Date -Format 'HH:mm:ss') ...Start of Get-NetView (to skip this step, use skipNetview)"
			& "$global:ToolsPath`\GetNetView.ps1" -OutputDirectory $global:savePathTmp
			Write-Host -BackgroundColor Gray -ForegroundColor Black -Object "--- $(Get-Date -Format 'HH:mm:ss') ...  End of Get-NetView"
		}
		if ($Global:skipSddcDiag -ne $true) {
			if ((test-path variable:psversiontable) -and ($PSVersionTable.PSVersion.Major -ge 5)) {
				#-# PrivateCloud.DiagnosticInfo
				Write-Host -BackgroundColor Gray -ForegroundColor Black -Object "--- $(Get-Date -Format 'HH:mm:ss') ... Start of SddcDiagnostic"
				& "$global:ToolsPath`\GetSddcDiagnosticInfo.ps1" -WriteToPath $($global:savePath + "\HealthTest") -ZipPrefix $($global:savePathTmp + "\_Sddc-Diag")
				Write-Host -BackgroundColor Gray -ForegroundColor Black -Object "--- $(Get-Date -Format 'HH:mm:ss') ...  End of SddcDiagnostic"
			}
		}
	}
	EndDataCollection

}else{
	#2nd execution. Delete the temporary flag file then exit
	EndDataCollection -DeleteFlagFile $True
}


# SIG # Begin signature block
# MIInwQYJKoZIhvcNAQcCoIInsjCCJ64CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCN0Q4axUwT3uyF
# yxYTYwiuQiGAXnsDjUQ60Er3puQ18KCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
# OfsCcUI2AAAAAALLMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NTU5WhcNMjMwNTExMjA0NTU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC3sN0WcdGpGXPZIb5iNfFB0xZ8rnJvYnxD6Uf2BHXglpbTEfoe+mO//oLWkRxA
# wppditsSVOD0oglKbtnh9Wp2DARLcxbGaW4YanOWSB1LyLRpHnnQ5POlh2U5trg4
# 3gQjvlNZlQB3lL+zrPtbNvMA7E0Wkmo+Z6YFnsf7aek+KGzaGboAeFO4uKZjQXY5
# RmMzE70Bwaz7hvA05jDURdRKH0i/1yK96TDuP7JyRFLOvA3UXNWz00R9w7ppMDcN
# lXtrmbPigv3xE9FfpfmJRtiOZQKd73K72Wujmj6/Su3+DBTpOq7NgdntW2lJfX3X
# a6oe4F9Pk9xRhkwHsk7Ju9E/AgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUrg/nt/gj+BBLd1jZWYhok7v5/w4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQ3MDUyODAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAJL5t6pVjIRlQ8j4dAFJ
# ZnMke3rRHeQDOPFxswM47HRvgQa2E1jea2aYiMk1WmdqWnYw1bal4IzRlSVf4czf
# zx2vjOIOiaGllW2ByHkfKApngOzJmAQ8F15xSHPRvNMmvpC3PFLvKMf3y5SyPJxh
# 922TTq0q5epJv1SgZDWlUlHL/Ex1nX8kzBRhHvc6D6F5la+oAO4A3o/ZC05OOgm4
# EJxZP9MqUi5iid2dw4Jg/HvtDpCcLj1GLIhCDaebKegajCJlMhhxnDXrGFLJfX8j
# 7k7LUvrZDsQniJZ3D66K+3SZTLhvwK7dMGVFuUUJUfDifrlCTjKG9mxsPDllfyck
# 4zGnRZv8Jw9RgE1zAghnU14L0vVUNOzi/4bE7wIsiRyIcCcVoXRneBA3n/frLXvd
# jDsbb2lpGu78+s1zbO5N0bhHWq4j5WMutrspBxEhqG2PSBjC5Ypi+jhtfu3+x76N
# mBvsyKuxx9+Hm/ALnlzKxr4KyMR3/z4IRMzA1QyppNk65Ui+jB14g+w4vole33M1
# pVqVckrmSebUkmjnCshCiH12IFgHZF7gRwE4YZrJ7QjxZeoZqHaKsQLRMp653beB
# fHfeva9zJPhBSdVcCW7x9q0c2HVPLJHX9YCUU714I+qtLpDGrdbZxD9mikPqL/To
# /1lDZ0ch8FtePhME7houuoPcMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGaEwghmdAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPoi6VHoqv8CFl+1ZF74nQ18
# R/YSLu3YW13OmYbMoZgiMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQALZbHUB/kNl/pX4J4j9+jAKBnm3YLDwEE6TnnLYvDSrdyI6SDR3xwl
# 8RVAL3TyvBcaFtbcgKXE3zEaQ/Ysb9ZB6dV2vYlw92lR+sLa+hFCtPkFsO7dBtrD
# IOf+5Bc1eIyflX0LMY4dDU1NTVLlqNWjxfXnOlzCNvaKsFyKi4Acw19jclHmEmtd
# Btp+uRj1V+s+6NBfFJmy+YGjU03ZKuvh1F0FzJ245ZP8/ukPg6cuFmGLbO41CRGz
# fv02zY0EvHKYYyplK02oUJByxv2zxy7gi3l6JSiFKyb0vieX2uM7W3+tvAHXeZ/f
# sPrs+i/TweUdneKJtbs71cwM90jMwPlpoYIXKTCCFyUGCisGAQQBgjcDAwExghcV
# MIIXEQYJKoZIhvcNAQcCoIIXAjCCFv4CAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIPhC5Qz2oJhlNjzbwqBVzaIe4U+6AJQSaMY+5YB2i8+aAgZj5ZL5
# 3aEYEzIwMjMwMjIwMTUwNTQ3Ljc1OFowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RDA4Mi00QkZELUVFQkExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF4MIIHJzCCBQ+gAwIBAgITMwAAAbofPxn3wXW9fAABAAABujAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MjA5MjAyMDIyMTlaFw0yMzEyMTQyMDIyMTlaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQwODIt
# NEJGRC1FRUJBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAiE4VgzOSNYAT1RWdcX2F
# Ea/TEFHFz4jke7eHFUVfIre7fzG6wRvSkuTCOAa0OxostuuUzGpfe0Vv/cGAQ8QL
# cvTBfvqAPzMe37CIFXmarkFainb2pGuAwkooI9ylCdKOz0H/hcwUW+ul0+JxkO/j
# cUuDP18eoyrQskPDkkAcYNLfRMJj04Xjc/h3jhn2UTsJpVLakkwXcvjncxcHnJgr
# 8oNuKWERE/WPGfbKX60YJGC4gCwwbSh46FdrDy5IY6FLoAJIdv55uLTTfwwUfKhM
# 2Ep/5Jijg6lJjfE/j6zAEFMoOhg/XAf4J/EbqH1/KYElA9Blqp+XSuKIMuOYO6dC
# 0fUYPrgCKvmT0l3CGrnAuZJZePIVUv4gN86l2LEnp/mj4yETofi3fXD6mvKAeZ3Z
# QdDrntQbHoU27PAL5KkAeZXvoxlhpzi4CFOBo/js/Z55LWhyS/KGX3Jr70nM98yS
# 6DfF6/MUANaItEyvTroQxXurclJECycJL0ZDTwLgUo9tKHw48zfcueDR9/EA2ccA
# Bf8MTtwdzHuX2NpXcByaSPuiqKvgSHa7ljHCJpMTftdoy6ZfYRLc8nk0Fperth0s
# nDJIP5T2mT+2Xh1DW38R6ju4NOWI7JCQPwjvjGlUHRPfX/rsod+QGQVW/LrDJ7bV
# X70gLy5IP75GAPdHC03aQT8CAwEAAaOCAUkwggFFMB0GA1UdDgQWBBSKYubxAx4l
# rbmP0xZ5psjYdK9k5TAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAX8jxTqFtmG8N
# yf3qdnq2RtISNc+8pnrCuhpdyCy0SGmBp4TCV4u49ccvMRa24m5jPh6yGaFeoWvj
# 2VsBxflI3n9wSw/TF0VrJvtTk/3gll3ceMW+lZE2g0GEXdIMzQDfywjYf6GOEH9V
# 9fVdxmJ6LVE48DIIdwGAcvJCsS7qadvceFsh2vyHRNrtYXKUaEtIVbrCbMq6w/po
# 6WacZJpzk0x+VrqVG9Ngd3byttsKB9KbVGFOChmP5bwNMq2IQzC5scneYg8qajzG
# 0khZc+derpcqCV2svlzKcsxf/RZfrk65ZsdXkZMQt19a8ZXcNpmsc9RD9Q/fUp6p
# vbGNUJvfQtXCBuMi9hLvs3V0BGQ3wX/2knWA7gi9lYzDIyUooUaiM7V/XBuNJZwD
# /nu2xz63ZuWsxaBI0eDMOvTWNs9K6lGPLce31lmzjE3TZ6Jfd4bb3s2u0LqXhz+D
# OfbR6qipbH+4dbGZOAHQXmiwG5Mc57vsPIQDS6ECsaWAo/3WOCGC385UegfrmDRC
# oK2Bn7fqacISDog6EWgWsJzR8kUZWZvX7XuAR74dEwzuMGTg7Ton4iigWsjd7c8m
# M+tBqej8zITeH7MC4FYYwNFxSU0oINTt0ada8fddbAusIIhzP7cbBFQywuwN09bY
# 5W/u/V4QmIxIhnY/4zsvbRDxrOdTg4AwggdxMIIFWaADAgECAhMzAAAAFcXna54C
# m0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMy
# MjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51
# yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY
# 6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9
# cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN
# 7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDua
# Rr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74
# kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2
# K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5
# TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZk
# i1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9Q
# BXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3Pmri
# Lq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUC
# BBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9y
# eS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUA
# YgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
# 1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIw
# MTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/yp
# b+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulm
# ZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM
# 9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECW
# OKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4
# FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3Uw
# xTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPX
# fx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVX
# VAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGC
# onsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU
# 5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEG
# ahC0HVUzWLOhcGbyoYIC1DCCAj0CAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OkQwODItNEJGRC1FRUJBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQB2o0d7XXeAInztpkgZrlAFSojC8qCBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA553ovjAiGA8yMDIzMDIyMDIwNDAzMFoYDzIwMjMwMjIxMjA0MDMwWjB0MDoG
# CisGAQQBhFkKBAExLDAqMAoCBQDnnei+AgEAMAcCAQACAgTrMAcCAQACAhJMMAoC
# BQDnnzo+AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEA
# AgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAB/hvj60MbboCIN1a
# b/vaGVc6Wr+wSJNNzolmgfySU32dWOpUNugk31IEPN/V2m3W6+EHkrjijZGfHl6f
# kXc3I+L3RHH7+4Nl9EzGs8m6pZe600Visktdw1nOrZvmBO2RwYx/4JWNGxhiUcGh
# p/zU/aTPV8NtwPz4y3Wlkbn+s+UxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAbofPxn3wXW9fAABAAABujANBglghkgBZQME
# AgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJ
# BDEiBCA+vMovK8TwFFSWggSsxB7L/sL0R1tVIwCAua1vyOk6DDCB+gYLKoZIhvcN
# AQkQAi8xgeowgecwgeQwgb0EIClVvTwzbnD61gZayaUa2nWDLWc9ypZ+qAwXeeVZ
# hXMFMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAG6
# Hz8Z98F1vXwAAQAAAbowIgQgn4XrytHu43wBXS8R9a+b1/BPPbFByYToCc2aeYdS
# GCIwDQYJKoZIhvcNAQELBQAEggIALOdNvF2SvWUxPOcV9X0P9OZVZpguWWC0mcjX
# q8hFYKqIfmLIUBSHquxERUyVjyz+zaxxFKwF+KQ4KEoC31tc3+ij0sJGXks3ukAV
# aQ08+hHnlhiozLoXM7kjXsR6EkKieicq5djJUK8RZz/i1OgJ7rS849dvajHTxYba
# IMFV7Vg4EPL5l5F+sWiufL8HCw/9DCEqzeN5p8z6KvSbm9QeoIC0ZG44yb8Engim
# YKZ/9de156Kn0OqqxxpFK8FP7kxBnvkXKd2Z/4KINDpjY2JOZWj02BRUQ8Ly+vdq
# mk7xGUQUpFQ/BXUPmplqCyHmioH1LlsdXSsg/RTteDDmB3Nz8YlnTrGTbtvFPIl6
# LATJQA5dLiQdhkexWkbE383A0y7KPUpwv87mIMGGRGgiUml7+0YfR6v6+61+jkdp
# GVDjJROBDMSyZdt/rcz/hyfAHfRMU9EzybwRdm7R74awThyUHcr15evxt61KIPGj
# iVru9x8aFQS0EgTiT0aELi0Asv0Yk8AIMGnAk+rToBylziCvbD559Qe12kjrjQXY
# i4V6agmvduCOtEpPwPRMBE53LmVaOmKaSg5L/Bq/pRz9+TXMUd2Qf//SpgP0coga
# lef5+PGYrdZ24+rBIsf/JGh1kNd2mkpMmpYjsKcz224g/uWYuYa5lSDhiqd+NjDD
# +mY56I0=
# SIG # End signature block
