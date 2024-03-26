#************************************************
# utils_Exchange_all_exchange_versions_using_powershell_should_not_be_called_while_loading_powershell.ps1
# Version 2.0.1
# Date: 04-12-2011
# Author: Brian Prince - brianpr@microsoft.com
# Description:  Utility functions for use by Exchange SDP 3.0+ manifests 
#************************************************


#======================================
# This function writes cmdlet output of specified format to file name as specified.
# If no output format is specified, FL is default.
# If no file name is specified, the cmdlet used (minus -Get) to generate the output will be used as file name.
#======================================



# Functions in this ps1 should not be called while loading Exchange powershell ( because they requiere Exchange powershell to be started )

Function ExportResults ($cmdlet = $null, $outformat = $null, $filename = $null, $filedescription = $null, $cmdletDescription = $null, [switch]$Local = $false){
    trap [Exception] {
	    Log-Error $_
		Continue
	}
	
	# Some UM calls here don't actually run cmdlets, they just output variables
	# This breaks the output in the GUI below, so allowing them to pass in a descriptive
	# value instead
	if ([string]::IsNullOrEmpty($cmdletDescription)) {
		$cmdletrun = $cmdlet
	}
	else {
		$cmdletrun = $cmdletDescription
	}
	Update-ActivityProgress -Status $cmdletrun
	$result = Invoke-ExchangeCommand $cmdlet -Local:$Local
	
	if($null -ne $result) {
		if($null -eq $filename){
			#Remove "Get-" from the beginning of each command to use cmdlet as filename if filename was not passed to function.
  	 		if($cmdlet.ToLower().StartsWith("get-")){
				$cmdlet = $cmdlet.Substring(4)
	   		}
			#Split cmdlet string into an array using any space as the delimiter and then use the first index in the array in the filename
			$filename = $cmdlet.ToString().Split(" ")[0]
			
			#Set file description for display if Win7/Win2008R2
			If ($null -eq $filedescription){$filedescription = $cmdletrun.ToString().Split(" ")[0]}
		}
		else{
			#Set file description for display if Win7/Win2008R2
			If ($null -eq $filedescription){
				$filedescription = (($cmdletrun.ToString().Split(" ")[0]) + " " + ($cmdletrun.ToString().Split(" ")[1])).tostring()
			}
		}
		#Set output file path and name prefix.
		$filename = ($script:rootOutFile + "_" + $filename)
		$lFileName = ($filename + "_FL.TXT")
		$tFileName = ($filename + "_FT.TXT")
		$vFileName = ($filename + "_CSV.CSV")
		
		if ($null -ne $outformat){
			#Generate output format(s) specifed when calling this function, either Format-List (FL), 
			#Format-Table (FT) or Comma Separated Values (CSV)
			if ($outformat.ToLower() -match "fl"){
				Out-File -FilePath ($lFileName) -InputObject ("Result from: " + $cmdletrun) -Width 512 -Append
				Out-File -FilePath ($lFileName) -InputObject ($result | Format-List ) -Width 512 -Append
				[array]$filesToCollect += ($lFileName)
			}
			if ($outformat.ToLower() -match "ft"){
				Out-File -FilePath ($tFileName) -InputObject ("Result from: " + $cmdletrun) -Append
				Out-File -FilePath ($tFileName) -InputObject ($result | Format-Table -AutoSize) -Append
				[array]$filesToCollect += ($tFileName)
			}
			if ($outformat.ToLower() -match "csv"){
				$result | Export-Csv -Path ($vFileName)
				[array]$filesToCollect += ($vFileName)
			}
		}
		Else{
			#If no output format was specified, generate only format-list 
			Out-File -FilePath ($lFileName) -InputObject ("Result from: " + $cmdletrun) -Width 512 -Append
			Out-File -FilePath ($lFileName) -InputObject ($result | Format-List) -Width 512 -Append
			[array]$filesToCollect += ($lFileName)
		}
	}
	else{
    	out-file -FilePath ($script:rootOutFile + "__GetExchangeData_No_Result.TXT") -append -InputObject $cmdletrun
   	}
	if ($null -ne $filesToCollect) {
		if ($null -eq $reportsection) { $reportsection = Get-ReportSection }
		CollectFiles -filestocollect $filesToCollect -filedescription $filedescription -sectiondescription $reportsection -noFileExtensionsOnDescription
	}
}


# SIG # Begin signature block
# MIInlwYJKoZIhvcNAQcCoIIniDCCJ4QCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBV9bywLikfigf5
# H8x6hX40rPclaA7dAmosK8h2F3BJvqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXcwghlzAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBVUBE8QvXYCvgG5qVFTQfhT
# mc/gkKMWhQEFQZgxI7fJMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQB5thnnwOEBMdYM11eDdrk4u4w6/7ztmU/aTGFzidLnb/ZjAhSvcV6s
# BE5wyijQhhWVrsAGGAUBrRGR9XDZ3YDFruExgLryQ5/yIzds0XKqsYZv5Pk8vu8f
# 7cLlw2xb9Mm3zKai2N3mo6mfjHUzEkIPIi0Sw6UYJR7xWC+KKMtQ4jsPOq6mI+r4
# ccu/Rztwev2mTe5lRosxNFX//8i+XS2GwpeNRsf2JQo7vM62k1Of7lEWJMZ0GEgK
# 1bFq7DS4nMBBmZIlbuxV4LemUmxc8nUzzpMncbjEcYTtdflFjB74iTvipeJtCmYa
# oVnAvWihria6JECv0Y9RPKMu9FZ9p2/UoYIW/zCCFvsGCisGAQQBgjcDAwExghbr
# MIIW5wYJKoZIhvcNAQcCoIIW2DCCFtQCAQMxDzANBglghkgBZQMEAgEFADCCAVAG
# CyqGSIb3DQEJEAEEoIIBPwSCATswggE3AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIDQh/NVRrx2FTYlowb7laqhMnqnNa0fQSBRh8vTeHE3JAgZi1XtC
# du4YEjIwMjIwODAxMDgxNTA2LjY1WjAEgAIB9KCB0KSBzTCByjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFt
# ZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MTJCQy1F
# M0FFLTc0RUIxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghFXMIIHDDCCBPSgAwIBAgITMwAAAaEBhVWZuVRdigABAAABoTANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMTEyMDIxOTA1
# MjRaFw0yMzAyMjgxOTA1MjRaMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoxMkJDLUUzQUUtNzRFQjElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBANrJPF7la6SStjHFW4cthb0ERYIP2SSOecew4rAZ10g9
# tmUtj6Xmi8sM1/4EQxAoBlAjcNf3WXXIIO4/1fu048LjxlEZcD9t/2qXQUrnjfyA
# iXtxXnbxd4Q4XBz8D5RshR9bb3o6aDxnrbFpC/eOsbhT+muICsX96vVQDUc24gZT
# KqOXKCJI/ArY2cUCmLUkP5R5/lzjuSHulbUqPtGdyGkV5j0x6Q9BGJrtwRpRhTiy
# oKIlV0Mml58u89P0R22GVDHvmV3H4DBl/Zr1Pu5BFIGHy2nE90gMOQqJYzCMpOsB
# jT0Dcj+OJ2o+5zw+9f6yrGrJkQ3aHgYDQR2OaTrieQi6QArXwrmcAsMs71IxPGkD
# BAgdEO1l5MKW8A8ISjLW+08Pt/56oepK2675cKR9GNcSlf36H1+uwHT8GAPkIF/c
# QssBrxN58x8dlYQlFM82ttcwqLNKtRKRW//cc/9mwmnBrPkzLZFvJzcCH1tPvp4E
# mTJ9PkU32/8pDQefGFEyzoceFOY3H4vO1hyL68d/QPdAfV4KNlZlGOnWY7LGk9Ta
# YMwbqB6W8mx7UnNEAOjtgiiT8ncJxubwxsFubzmKiAWW0Ud5wcUQXCuwMYEWc1gc
# yFxtqtA0D6BjZ7aX18CRfcyMjtSSWSjPvj8/ooip7mNx30U8JttJtgf04uy155g5
# AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUFr8gMttjjvlVDIqJlLDjuXT9zKkwHwYD
# VR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZO
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBc
# BggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYD
# VR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOC
# AgEAIMMjESV9eUblgpwqss9JL5/clZmmvAoSIBK+K9odMFGVe0Cz5ORp1ywR6L73
# Dm+YXm0JTNMfhzScIjttnGewv5LpeyI6zdnVXhZf4jChdQnjMu+zT6ZPi+MYO1h8
# pD9uyYkpqvZz32b98e/VabYJNzJp4++LzomHdTIuN1EgtZu3OzigiYUzDApvMd0+
# inGsGGCL4LVhmyGixYuWDPK7GNSX6o2DWbnYwmZ/XWWgjsP0cmhpDN36t/3bxjyu
# 9QuaDaH8bnSj4PRQnUVr9wklod8Hex8rD1foau1dgaOYzf6D4CFpWx+6kpc204W7
# m2csq8Afk4iMQNhXVgqaVe4G6FthqyzKA8UyY2AbYCeTd2sRwNxmEJdeqlGzM2jU
# Xoa7kkKlBlds4kz1R7k+Ukq2YiYBggazD6mcfL+vmCBJg6niDlnWhT0aFUIzdXRP
# 1p157o5RcGTWsTh1lz9Sw+WPSqiKWMv6U3UDmCSabPuTm0g5tUYHt0l3PwnQXBdE
# Tmpi7UB29q5VtnAZCQvXHxor+y+MRBbQ1TInb3OcMeJeXm8uhFOOMWmyFQGLb4hj
# 6Y2psuaPbiPl5P5uMOUTceY20s+ktwwNipnUf7pTpiZqI2ZpzaNFcMBp4QT+6gMy
# 3Z0Ct8k/sz4wO/fPM01Mg1640S0NWCb3PB+AhQJecNm5W2IwggdxMIIFWaADAgEC
# AhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQg
# Um9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVa
# Fw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7V
# gtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeF
# RiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3X
# D9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoP
# z130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+
# tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5Jas
# AUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/b
# fV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuv
# XsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg
# 8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzF
# a/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqP
# nhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEw
# IwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSf
# pxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBB
# MD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0Rv
# Y3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGC
# NxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8w
# HwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmg
# R4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWlj
# Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEF
# BQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29D
# ZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEs
# H2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHk
# wo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinL
# btg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCg
# vxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsId
# w2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2
# zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23K
# jgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beu
# yOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/
# tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjm
# jJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBj
# U02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICzjCCAjcCAQEwgfihgdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjEyQkMtRTNBRS03NEVCMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQAbcXaM7gsQxUvCAoZd1gw3gUGA4KCB
# gzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEB
# BQUAAgUA5pHFATAiGA8yMDIyMDgwMTExMjAzM1oYDzIwMjIwODAyMTEyMDMzWjB3
# MD0GCisGAQQBhFkKBAExLzAtMAoCBQDmkcUBAgEAMAoCAQACAh75AgH/MAcCAQAC
# AhHMMAoCBQDmkxaBAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKg
# CjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAx2D/Yhza
# B1HF0cVQV0kx6orYZDh54l7gpTe4kVlJa0M0yxh2B9EGKhB7AjSMDfpDuf3dTYfY
# RQgwqJ77LLclkYQLdHtE0W9p2x7+VhMf2J2S2d3oH+ctMU/MorM3E0v+zSRgpuwg
# VLvlmFx7yu8prbnorPEDCAM4W8psD8IsV+0xggQNMIIECQIBATCBkzB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAaEBhVWZuVRdigABAAABoTANBglg
# hkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqG
# SIb3DQEJBDEiBCCgupntM/C90zkm6eqi0RAM53ejc7iZjNPd2BjZ5LpRrDCB+gYL
# KoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIOsIVPE6gYJoIIKOhHIF7UlJCswl4IJP
# ISvOKInfjtCEMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAC
# EzMAAAGhAYVVmblUXYoAAQAAAaEwIgQgotHUIzkIT/GmJ14VuRrPFOfIJ+F3D8GS
# tLwn5ZzBO4QwDQYJKoZIhvcNAQELBQAEggIAZyHP5F6Fv5MrdBp93nRfgJ8LNe/4
# pyS8b3RrsDJo2BliGeDvsWtvbVu76cyzJYBmiMGjnDwH55SAPWZwkFiK/uIaUkHV
# TzhfjY6VDh0JB7m6QajjckAXsYUbzDYggmk3G6yWPXOsUnQIo97ziHUKXLZmRLX6
# ELUZHzzyxbdZhflASJriXcILdA4v/nENnPEHIhUtKx6pHfKpPlvSDM4zBXdImDmK
# WkpPcGN4Os4PylxLD/vhhBzQAyoDhRJeVxw0uCuL3LmV3+pYljmSnQ8zlU1Xv5vJ
# J3xkMnsRQ0sR3jD7xEa2e3zSj20hUcdB081tFZNYQ15XR5VghXiZ4KdfXxVrZm5p
# hejBurNu8Dqw4b5KAcFBg3iEOtDHnNDeRfTi+/fcCWSALV8TEZd4zRNBX6rFsTvi
# jpkTa0paGXGMXGJ0yXDDPkum3dZ4FX7Nj0kmf96wDEUFTKj74pPsKpi0zGneB5R+
# //gM4MvVllk55z0AqhHaVfiJYiezTS3hO1vhwzbbOKupoBx7QO5CoTpvTVMwXBkj
# Xjh3tvNwv4O4yV05SL/wboPIoVkzGtG3iFNAAfYRxhIgV124GylX380lvCCHsyBA
# t/bi9RI8PjlB/zyIGzM4j2yZEZtgmEx+tQmkSOuVKXn8yTHCf53wDLZ0m/I/w8VC
# wWBo1gEWkC7kxMI=
# SIG # End signature block
