#************************************************
# TS_PrinterKB2618460Check.ps1
# Version 1.0.1
# Date: 03-27-2011
# Author: v-anecho
# Description:  When Point and Print Restriction Policy enabled, some third party print drivers will fail to download/upgrade or install. Disabling this Policy resolves most print driver install issues.
#************************************************

Import-LocalizedData -BindingVariable PrinterCheck
Write-DiagProgress -Activity $PrinterCheck.ID_PrinterKB2618460Check -Status $PrinterCheck.ID_PrinterKB2618460CheckDesc

$RootCauseDetected = $false
$RootCauseName = "RC_PrinterKB2618460Check"



#Rule ID 1444
#-----------
#http://sharepoint/sites/rules/Rule%20Submissions/Forms/DispForm.aspx?ID=1444
#
#Description
#-----------
# When Point and Print Restriction Policy enabled, some third party print drivers will fail to download/upgrade or install.
#Disabling this Policy resolves most print driver install issues.
#
#Related KB
#----------
#2618460
#
#Script Author
#-------------
# anecho


#********************
#Data gathering
#********************
	$InformationCollected = new-object PSObject
	$HasIssue = $false 
	
	Function Get-RestrictedKeyValue()
	{
##		<#
#			.SYNOPSIS
#				Gets a Restricted key value from HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
#			.DESCRIPTION
#				Uses Get-ItemProperty to pull the value out of the key path
#			.NOTES
#			.LINK
#			.EXAMPLE
#			.OUTPUTS				
#			.PARAMETER file
#		#>
		
		$keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
		$keyName = "Restricted"
		

		if ((Test-Path -Path $keyPath) -eq $true)
		{
			$registryValue = ((Get-ItemProperty -Path $keyPath).$keyName)
			if($null -eq ($registryValue))
			{
				return $null
			}
			else
			{			
				return  ([Convert]::ToString(($registryValue),16))
			}
		}
		else
		{
			return $null
		}		
	}	

	Function QueryFirstEvent($EventLogName, $Query)
	{
		$Error.Clear()
		
		$CommandToRun = "wevtutil.exe qe `"$EventLogName`" /q:`"$Query`" /c:1"
		
		$Results = Invoke-Expression $CommandToRun -ErrorAction Continue
		
		if (($Error.Count -eq 0) -and ($null -ne $Results))
		{
			return [xml] $Results
		}
		else
		{
			return $null
		}
	}

	Function AreAnyEventsPresent
	{
		$ResultXML = QueryFirstEvent -EventLogName "Microsoft-Windows-PrintService/Admin" -Query "*[System[(EventID=215 or EventID=808) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"

		if ($null -eq $ResultXML)
		{
			$ResultXML = QueryFirstEvent -EventLogName "System" -Query "*[System[(Provider[@Name='Microsoft-Windows-TerminalServices-Printers'] and EventID=1111) or (Provider[@Name='Print'] and EventID=23) or (Provider[@Name='Microsoft-Windows-PrintSpooler'] and EventID=22) or (Provider[@Name='Microsoft-Windows-SpoolerWin32SPL'] and EventID=1) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"

			if ($null -eq $ResultXML)
			{
				$ResultXML = QueryFirstEvent -EventLogName "Application" -Query "*[System[Provider[@Name='Group Policy Printers'] and (EventID=8192 or EventID=4098) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"
			}
		}
		
		if ($null -ne $ResultXML)
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

	if ($OSVersion.Build -gt 6000)
	{
		if (($null -ne (Get-RestrictedKeyValue)) -and (AreAnyEventsPresent))
		{
			$HasIssue = $true		
		}
		
	#********************
	#Alert Evaluation
	#********************

		if($HasIssue)
		{				
			Update-DiagRootCause -id $RootCauseName -Detected $true
			Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL "http://support.microsoft.com/kb/2618460" -Verbosity "Error" -Visibility 4 -SupportTopicsID 8060 -Component "Windows Performance"
			
		}
		else
		{
			Update-DiagRootCause -id $RootCauseName -Detected $false
		}
	}

	
# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAElYR43PyhlwZ3
# lhscgO5326hz3y/r5ma/f8WW862kxKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGY4wghmKAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPIRGjo6mRk+fcOl5ovujXMU
# Ogv2K8dfYQgeOFMcHCEhMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQC1kUJBXZJf0DZhZsQikooLt4J/N3C7x/zJoI2x+FqHkRS/fEYugXe2
# jQthtSn+46AJ+yNXO9OLgVFlPBKxS0pGxtATlHFjtp/927GrSrPYsf1VQM9aYBQI
# iCf5z1F6DjRgdusW8Tl4GsEF1vSh18dbEY2DqkhJfY2J7TH3aTpVJxlg+Sf/ju0j
# orx5p9nmda9plFvfFv+kfz2Yil2/Cogy9QZ1Pkmsn6sZlTzs+Rdqa+2Qs7Bkvkbb
# bmQHiilNd8yxVVu1Nan/VtMZ2mvVTTVrM2LjX4Z161xeEgmHqeBd2nmSuOaxiekU
# NnT0a/u8kGMm04uAN1csMUjqpb8e2jmfoYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIP051koMTD2QL6RZB7tUSqtpQght0w7zTiQeQ8m2Zsd0AgZi3mQf
# HWgYEzIwMjIwODAxMDc0MjU4LjE1NVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046ODZERi00QkJDLTkzMzUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAYwBl2JHNnZmOwABAAABjDAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDRaFw0yMzAxMjYxOTI3NDRaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjg2REYt
# NEJCQy05MzM1MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA00hoTKET+SGsayw+9BFd
# m+uZ+kvEPGLd5sF8XlT3Uy4YGqT86+Dr8G3k6q/lRagixRKvn+g2AFRL9VuZqC1u
# Tva7dZN9ChiotHHFmyyQZPalXdJTC8nKIrbgTMXAwh/mbhnmoaxsI9jGlivYgi5G
# NOE7u6TV4UOtnVP8iohTUfNMKhZaJdzmWDjhWC7LjPXIham9QhRkVzrkxfJKc59A
# saGD3PviRkgHoGxfpdWHPPaW8iiEHjc4PDmCKluW3J+IdU38H+MkKPmekC7GtRTL
# XKBCuWKXS8TjZY/wkNczWNEo+l5J3OZdHeVigxpzCneskZfcHXxrCX2hue7qJvWr
# ksFStkZbOG7IYmafYMQrZGull72PnS1oIdQdYnR5/ngcvSQb11GQ0kNMDziKsSd+
# 5ifUaYbJLZ0XExNV4qLXCS65Dj+8FygCjtNvkDiB5Hs9I7K9zxZsUb7fKKSGEZ9y
# A0JgTWbcAPCYPtuAHVJ8UKaT967pJm7+r3hgce38VU39speeHHgaCS4vXrelTLiU
# MAl0Otk5ncKQKc2kGnvuwP2RCS3kEEFAxonwLn8pyedyreZTbBMQBqf1o3kj0ilO
# J7/f/P3c1rnaYO01GDJomv7otpb5z+1hrSoIs8u+6eruJKCTihd0i/8bc67AKF76
# wpWuvW9BhbUMTsWkww4r42cCAwEAAaOCATYwggEyMB0GA1UdDgQWBBSWzlOGqYIh
# YIh5Vp0+iMrdQItSIzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQDXaMVFWMIJqdblQZK6oks7cdCUwePAmmEIedsy
# usgUMIQlQqajfCP9iG58yOFSRx2k59j2hABSZBxFmbkVjwhYEC1yJPQm9464gUz5
# G+uOW51i8ueeeB3h2i+DmoWNKNSulINyfSGgW6PCDCiRqO3qn8KYVzLzoemfPir/
# UVx5CAgVcEDAMtxbRrTHXBABXyCa6aQ3+jukWB5aQzLw6qhHhz7HIOU9q/Q9Y2Nn
# VBKPfzIlwPjb2NrQGfQnXTssfFD98OpRHq07ZUx21g4ps8V33hSSkJ2uDwhtp5Vt
# FGnF+AxzFBlCvc33LPTmXsczly6+yQgARwmNHeNA262WqLLJM84Iz8OS1VfE1N6y
# YCkLjg81+zGXsjvMGmjBliyxZwXWGWJmsovB6T6h1GrfmvMKudOE92D67SR3zT3D
# dA5JwL9TAzX8Uhi0aGYtn5uNUDFbxIozIRMpLVpP/YOLng+r2v8s8lyWv0afjwZY
# HBJ64MWVNxHcaNtjzkYtQjdZ5bhyka6dX+DtQD9bh3zji0SlrfVDILxEb6Ojyqtf
# Gj7iWZvJrb4AqIVgHQaDzguixES9ietFikHff6p97C5qobTTbKwN0AEP3q5teyI9
# NIOVlJl0gi5Ibd58Hif3JLO6vp+5yHXjoSL/MlhFmvGtaYmQwD7KzTm9uADF4BzP
# /mx2vzCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
# AQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAw
# BgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEw
# MB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk
# 4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9c
# T8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWG
# UNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6Gnsz
# rYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2
# LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLV
# wIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTd
# EonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0
# gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFph
# AXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJ
# YfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXb
# GjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJ
# KwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnP
# EP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMw
# UQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggr
# BgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYw
# DwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoY
# xDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
# L2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYB
# BQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0B
# AQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U5
# 18JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgAD
# sAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo
# 32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZ
# iefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZK
# PmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RI
# LLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgk
# ujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9
# af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzba
# ukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/
# OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLUMIIC
# PQIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046ODZERi00QkJDLTkzMzUxJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVADSi8hTrq/Q8oppweGyuZLNEJq/VoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmkXQnMCIYDzIwMjIwODAx
# MDUzNTM1WhgPMjAyMjA4MDIwNTM1MzVaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaRdCcCAQAwBwIBAAICGM0wBwIBAAICEU8wCgIFAOaSxacCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQCIsY9Ly+6K9S9Shp4oRSoLWJ00XRTLqUH0YK7lKobW
# 8eWfIrppdWOIf4H7BnWoO0/tMJJHgeSrJisS6vnLflRO/4yJ/OiGy6tcxoTZPfeS
# K5q/F4NEIboNLCDhW8RxBTAI4Hor5tEA4Y4BdGmZl++3Tly7aywliLfU/qiVJvKi
# VjGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABjAGXYkc2dmY7AAEAAAGMMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIMTL8XSssmPemrF9hvxQ
# q9HAEqFT38vby0kjDzSoQ/+3MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# 1a2L+BUqkM8Gf8TmIQWdgeKTTrYXIwOofOuJiBiYaZ4wgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYwBl2JHNnZmOwABAAABjDAiBCBY
# eC4LEStKyRogWYCSryzBcOErikzXGGVi2RsI7tYWwzANBgkqhkiG9w0BAQsFAASC
# AgCXmrJNIB61G8KTYHNO7TN2IOjkC2Oo3hyC8meAErjdOlrr2MrS5BbOsG0C8NN0
# pZ82qxJPpDlPqf8WBHRTHHoeWArK89qoHP2uspK5lNOFVcE9kwRIRPMFQ4s6eUWE
# tZYMI0UhBrSpx2e3j3AZ2FgSWBoz8liYQxk7C6SFz0suc9ClPC2mdigscNwggc5u
# M/FeTHnHH0GtsK+fuy6EnQro3lUwAGw7Ee+SSDMYzRrn0apFBYL7vonej8I85ts4
# W7lahFP65rjbs9ujyEb7ox0Xx9YUSGqqrOji4xqsZhgNveADLUnTh/NqY8hGjQ5F
# PYAvBEylIj4kZG8ScD0LmAjwnIKat7hJHqU+4jRduX0KRCg2MRXg/vgSoGALBxbB
# i7iU+34oqa6sPjoCTX95ObhBRZ01ifmCzB5C2WbJUdqIC+EVifHRfCkQ+Nt9k2wE
# 9apEcRPCSAmMD2HMwAJENIgGvasOH2WvxgnwKvjuD0MsIuGMwQLfYglfNlChg50l
# u8uLfvLIh9MReTru/bmuAQoTZ/iVMR9uk5tuUs/UdPKqb9IFb/JT9GBvvsyYfOIO
# 6oVZRqQjhuFCVB4nDoiAb+nAAijEhOHRhymjKzpnfYEohY050XWhRCV2yytq6Ss5
# 6pEIIZ09H0fohcN47CWsNgKKohzopL4Jn+sJiLjnWf2NjA==
# SIG # End signature block
