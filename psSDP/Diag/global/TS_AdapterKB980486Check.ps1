#************************************************
# TS_AdapterKB980486Check.ps1
# Version 1.0
# Date: 11-8-2011
# Author: v-anecho
# Description:  It was detected that the number of 6to4 adapters exceeded the number of physical network adapters on this computer. This may be a symptom of the issue described in KB980486. If affected by KB980486 the system may accrue an excessive number of adapters which can result in slow system startup performance as it tries to initialize each of the adapters. Please install the hotfix KB980486 to resolve this issue.
#************************************************

Import-LocalizedData -BindingVariable ScriptStrings
Write-DiagProgress -Activity $ScriptStrings.ID_AdapterKB980486Check -Status $ScriptStrings.ID_AdapterKB980486CheckDesc

$RootCauseDetected = $false
$RootCauseName = "RC_AdapterKB980486Check"



#Rule ID 1099
#-----------
# http://sharepoint/sites/rules/Rule%20Submissions/Windows%20-%20SBSL%20-%20Detect%20excessive%20number%20of%206to4%20NICs.xml
#Description
#-----------
# It was detected that the number of 6to4 adapters exceeded the number of physical network adapters on this computer. This may be a symptom of the issue described in KB980486. If affected by KB980486 the system may accrue an excessive number of adapters which can result in slow system startup performance as it tries to initialize each of the adapters. Please install the hotfix KB980486 to resolve this issue.
#
#Related KB
#----------
# 980486
#
#Script Author
#-------------
# anecho

	
	
#********************
#Data gathering
#********************
	$InformationCollected = new-object PSObject
	$HasIssue = $false 	

	
	#System 32 folder
	$System32Folder = Join-Path  $env:windir "System32"
	
	Function isOSVersionServer2008R2orWin7
	{	
		#
		#	.SYNOPSIS
		#		Checks if the Machine is the proper OS version
		#	.DESCRIPTION
		#		Pulls the OSVersion and checks it against expected version
		#	.NOTES
		#	.LINK
		#	.EXAMPLE
		#	.OUTPUTS
		#		Boolean value: [true] if the current system is the expected OS
		#		otherwise [false]
		#	.PARAMETER file
		#
		if($OSVersion.Build -eq 7600)
		{
			return $true
		}
		else
		{
			return $false
		}
	}
	
	Function is6to4GreaterThanPhysAdapters()
	{	
		$NetworkAdapter = Get-CimInstance Win32_NetworkAdapter		
		$PhysAdapters = $NetworkAdapter | Where-Object {$_.PhysicalAdapter.CompareTo($TRUE)}
		$6to4Adapters = $NetworkAdapter | Where-Object {$_.name -match "Microsoft 6to4 Adapter"}
		Set-Variable -Name 6to4AdaptersCount -Value $6to4Adapters.Count -Scope 1
		Set-Variable -Name PhysAdaptersCount -Value $PhysAdapters.Count -Scope 1
		
		If (($6to4Adapters -is [System.Array]) -and ($PhysAdapters -is [System.Array]) -and ($6to4AdaptersCount -gt $PhysAdaptersCount))
		{
			return $true				
		}
		Else
		{
			
			return $false
		}
	}
	
	Function isKB980486
	{
			#Now we need to check for the binaries specified @ KB980486
			if (CheckMinimalFileVersion "$System32Folder\Iphlpsvc.dll" 6 1 7600 20795)
			{
				return $true
			}
			else
			{
				return $false
			}

	}
	

#********************
#Detection Logic
#********************
	#Detect if the OS is Windows 7 or Windows Server R2
	#Detect if 6to4 adapter number is greater than physical adapters
	#Detect if KB 980486 is installed
	
	
	if ((isOSVersionServer2008R2orWin7) -and (is6to4GreaterThanPhysAdapters) -and (-not(isKB980486)))
	{
		$currentVersion = (Get-FileVersionString("$System32Folder\Iphlpsvc.dll"))
		add-member -inputobject $InformationCollected -membertype noteproperty -name "Number of 6to4 Adapters" -value $6to4AdaptersCount
		add-member -inputobject $InformationCollected -membertype noteproperty -name "Number of Physical Adapters" -value $PhysAdaptersCount
		add-member -inputobject $InformationCollected -membertype noteproperty -name "Current version: Iphlpsvc.dll" -value $currentVersion
		add-member -inputobject $InformationCollected -membertype noteproperty -name "Required version: Iphlpsvc.dll" -value "6.1.7600.20795"
		$HasIssue = $true		
	}
	
#********************
#Alert Evaluation
#********************

	if($HasIssue)
	{		
		RaiseAlert $AlertType["Error"] $AlertTitle $AlertMessage $KBArticleNumber
		return $InformationCollected
		
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL "http://support.microsoft.com/kb/980486" -Verbosity "Error" -InformationCollected $InformationCollected -Visibility 4 -SupportTopicsID 7988
		
	}
	else
	{
		if(isOSVersionServer2008R2orWin7)
		{
			Update-DiagRootCause -id $RootCauseName -Detected $false
		}
	}



# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA4Dq80OcOg+PdW
# w8BEAQpm9DjFug1ttrlFR07/SKy54KCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXgwghl0AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHoLDHMnSTdh6clhBgV5Z733
# 7nG6HzsQdGTY9lgaGt8ZMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBuN1Zn9WKCZXMII72JmB3Eo/HQMS0cxwqLE5fm0tnoaQv2JqPIxJ6z
# Hm/bNIcTvFukR/X6du4tYNPXqwIgve2fTDEALhFyAiJtSURWg8NydKVaiN0YeOFe
# EBYKrOgIW/GEp06aQ0JQn+I6eNwR27l6FNCNWBWuhvnqcCJEcVRhHWbWj0pmA4B9
# 8oo58YxcrYsMrbSAFPztVjHghmd+XkW4OwR0VoTHYE/5ywMgHd6Q3xzhLPDZFhWy
# S3z2WSCU23/d+rl+lIytja3PeSGXQbjkoUlQx/jlkbxXDYQXF+Hz6LMn/uqJOn0V
# zUTTiIC9k0dEa86lMSWvozZoBc7y21N5oYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIPEmIrJIm+sY8zYScBGd+1dv/UheX7VqfJZv97Kc994gAgZi1tk8
# Wd8YEzIwMjIwODAxMDc1NTQ3LjQ1OVowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkFFMkMt
# RTMyQi0xQUZDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGWSVti4S/d908AAQAAAZYwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTEzWhcNMjMwMjI4MTkwNTEzWjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046QUUyQy1FMzJCLTFBRkMxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDSH2wQC2+t/jzA6jL6LZMhDNJG0nv1cUqe+H4MGKyE
# gRZUwp1YsHl1ITGyi8K9rkPRKKKAi0lT8g0b1GIipkWc8qCtE3wibxoNR4mCyrvg
# EsXutnbxI1obx8cMfa2XgchG/XBGZcFtGd0UQvXkxUYvokfG1TyBMqnIZvQ2Ltcm
# Gj86laPRNuRodkEM7VVUO2oMSHJbaTNj1b2kAC8sqlytH1zmfrQpTA3rZOyEmywT
# 43DRfsNlXmkNKMiW7BafNnHZLGHGacpimE4doDMur3yiH/qCCx2PO4pIqkA6WLGS
# N8yhYavcQZRFVtsl/x/IiuL0fxPGpQmRc84m41yauncveNh/5/14MqsZ7ugY1ix8
# fkOYgJBlLss8myPhaMA6qcEB/RWWqcCfhyARNjCcmBNGNXeMgKyZ/+e3bCOlXmWe
# DtVJDLmOtzEDBLmkg2/etp3T9hOX+LodYwdBkY2noCDEzPWVa834AmkJvR6ynEeB
# Gj6ouWifpXxaobBdasb0+r/9eYr+T00yrLFn16rrTULnVzkW7lLyXWEousvzYnul
# 3HPCQooQS4LY1HBKTyTSftGX56ZgOz7Rk+esvbcr+NjLvBBy7Xeomgkuw1F/Uru7
# lZ9AR+EQbpg2pvCHSarMQQHbf1GXPhlDTHwkeskRiz5jPjTr1Wz/f+9CZx5ovtTF
# 0QIDAQABo4IBNjCCATIwHQYDVR0OBBYEFNLfCNksLmWtIGEsiYuEKprRzXSyMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAK9gCxC4IVbYKVQBHP5ztJc/kfgSubcL5hTReVE1uwSVKp92Sfd/IIvFgGQc
# wVlAZc8DubOhTshlR2fSFfK6+sUzoMOuf9ItKF7m348+SpZ455iITDyTgEjqXhTm
# TTvBfyEHA6gxHGzVo578k2Qsc7qSuXmPr8ZkeuRNHNOxFRQmnUWmdTOLGJlbJq9z
# TH+KYbnJZ2tK5xwT2d2irtBu7U/FruzCxSbnM00y6dpYZcMUCdLuzxHEnX8/epO1
# nQlrpUTpJ6gel2Pv+E+4oktdX8zz0Y0WfwdQOZVbn5gr/wPLvIoceKJJ366AA36l
# bc8Do5h6TSvJbVArNutbg/1JcCT5Tl9peMEmiK1b3z5kRFZffztUe9pNYnhijkGa
# QnRTbsBqXaCCLmPU9i4PEHcOyh8z7t5tzjOAnQYXi7oNBbRXitz8XbPK2XasNB9Q
# aU+01TKZRlVtYlsWrDriN7xCwCcx4bUnyiHGNiV5reIsDMbCKZ7h1sxLIQeg5tW/
# Mg3R30EnzjFV5cq8RPXvoaFj89LpFMlmJbk8+KFmHzwXcl5wS+GVy38VulA+36aE
# M4FADKqMjW10FCUEVVfznFZ3UlGdSS7GqyFeoXBzEqvwaIWxv0BXvLtNPfR+YxOz
# eCaeiMVC3cx0PlDcz+AF/VN2WHKI81dOAmE/qLJkd/EpmLZzMIIHcTCCBVmgAwIB
# AgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1
# WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
# 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZn
# hUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t
# 1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxq
# D89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmP
# frVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSW
# rAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
# 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zb
# r17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
# IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQc
# xWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17a
# j54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3h
# LB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
# 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74p
# y27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1A
# oL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbC
# HcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB
# 9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNt
# yo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
# rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcV
# v7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
# 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lw
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs4wggI3AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjpBRTJDLUUzMkItMUFGQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA0PommlVZaduKtDHghztBZDfmVv6g
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaR0ggwIhgPMjAyMjA4MDExMjE2MDhaGA8yMDIyMDgwMjEyMTYwOFow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pHSCAIBADAKAgEAAgIRSgIB/zAHAgEA
# AgIRoDAKAgUA5pMjiAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAFWP7Lwf
# JzOYAOhhBkOKsLpNH5vQwS9jkU9ldagsZuGQ7NEfvv/Sc7vJrgZva/t65cBfNynH
# +y3tTbwE0hsFkPNkFR28+VsBTDUYhjCte9ZhL4P0XeXQkVlaVDCbWWAjjC395HDP
# mx7tigPZP7yMmQozINjplhfNjn425kVHdXHmMYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGWSVti4S/d908AAQAAAZYwDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgLceD275GkwHjauT/p5bWpXdqSlIdMVQFnGdi3queoT4wgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCB2BNYC+B0105J2Ry6CfnZ0JA8JflZQ
# Q6sLpHI3LbK9kDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABlklbYuEv3fdPAAEAAAGWMCIEIFDFw7NdMrFXapZuUic/4lKxqdqYW/hS
# /yaW03MeeRsDMA0GCSqGSIb3DQEBCwUABIICAGYTMyUMkFOJxUs/atflVu+USVsp
# +Hhg+LgGzHF2b9gmH4wpDr+UgOrenth896qprVdxjrfSfVCRZ+qhfQV7Fy67Mki4
# d5cmBEEX3W6pg5euS+9A4p2eW2Mk7mdavMCIAL3/bFQaAHYTWUUuFH5DTIiFHniw
# R5Kz/Ny3Y1L2mdfsn1NGHOe+4ybIjVWdadloCeR/fw8JrRFGqIxeJWq4sO8rQtQ3
# zKA7s4Z180dhRyldSOakim6WWSBe3WCECmfa2KkubqSkO4QOUfxavKvPB/acsCin
# asmPPIo3Kl9bLXJ5Ap38+9gkIB0cCYcxy6EngmNDKrVYviUk1yXqyH2RNahpJ8Jo
# IgUiu2SK7jQ5/99FyEwnOwNyOM29hNnWCZjTKxPEnAY6ElNvWFYORv+HnqyJNH+S
# lms7JWA1h+oP3N/lPbbaBE873ZgR9SwMBqvj3ywKjnK6/goQVwd5zmWHObuS/yoq
# rKfzgvFFKBqrAKmCwvTISDWA2+E6Z1+MmOLTKBEA6vDiFOBYrwPb+RozRc/RL2MX
# NgYd1cidYh2JBwsoOGMK7Va+1oeF78qQoCxc2dl3Dsk7WZkMkftkK2L0oHG2Lyne
# x8z6nkdE+bVCxkrtOcEujDiCh5Ek2IrsaI4r22/gpNdOlg4bfRmpJxDcSHEaOIUU
# Qk8ohVa2w+ZsXael
# SIG # End signature block
