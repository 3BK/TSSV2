#************************************************
# TS_CheckEvtID_KB2475761.ps1
# Version 1.0.1
# Date: 2/27/12
# Author: jasonf
# Description:  KB2475761 - Check for event ID 21203 or 21125 in the Microsoft-Windows-Hyper-V-High-Availability/Admin event log over the past 15 days.
#               And then flag it as a root cause detected
#************************************************

Import-LocalizedData -BindingVariable ScriptStrings
Write-DiagProgress -Activity $ScriptStrings.ID_KB2475761Title -Status $ScriptStrings.ID_KB2475761Description

$RootCauseDetected = $false
$RootCauseName = "RC_CheckEvtID_KB2475761"
$PublicContent = "http://support.microsoft.com/kb/2475761"

# ***************************
# Data Gathering Functions
# ***************************

	Function isOSVersion
	{	
#		
#			.SYNOPSIS
#				Checks if the Machine is Windows Server 2008 R2/Windows 7 SP0 or SP1
#			.DESCRIPTION
#				Pulls the OSVersion and checks it against 7600 (SP0) and 7601 (SP1)
#			.NOTES
#			.LINK
#			.EXAMPLE
#			.OUTPUTS
#				Boolean value: [true] if the current system is Windows Server 2008 R2 
#				otherwise [false]
#			.PARAMETER file
#		
		if(($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 1))
		{
			return $true
		}
		else
		{
			return $false
		}
	}
	

Function checkServicesInstalled ($ServiceNames)
{	
	#		
	#			.SYNOPSIS
	#				Checks to see if all of the Service Names installed (AND detection) 
	#			.DESCRIPTION
	#			.NOTES
	#			.LINK
	#			.EXAMPLE
	#				$Services = "Clussvc", "vmms"
	#				$ServicesInstalled = checkServicesInstalled ($Services)
	#				OR
	#				$ServiceInstalled = CheckServicesInstalled ("Clussvc")
	#			.OUTPUTS
	#				Boolean value: [true] if all od the services exist otherwise [false]
	#			.PARAMETER 
	#		
	$ServicesInstalled = $false
	$arrInstalledServiceNames = @()
	foreach ($svc in get-service) {$arrInstalledServiceNames = $arrInstalledServiceNames + $svc.name}

	ForEach ($name in $ServiceNames) 
		{
			if ($arrInstalledServiceNames -notcontains $name)
				{
					return $ServicesInstalled
				}
			else
				{
					$ServicesInstalled = $true
				}
		}
	return $ServicesInstalled
}	


Function CheckEvtLog ($EvtLogName, [int]$threshold, $evtIDs)
   {
#		
#			.SYNOPSIS
#				Checks the named event log for the presence of an event ID 
#			.DESCRIPTION
#			.NOTES
#               Threshold in days
#				$evtIDs can be a single event, or an array of event IDs (OR detection logic)
#			.LINK
#			.EXAMPLE
#				$evtIDs = "12900", "12800"
#               CheckEvtLog -EvtLogName "Bitlocker-Provisioning-Microsoft-IT" -threshold "30" -evtIDs $evtids
#					or
#				CheckEvtLog -EvtLogName "Bitlocker-Provisioning-Microsoft-IT" -threshold "30" -evtIDs "12900"
#			.OUTPUTS
#				Boolean value: [true] if any of the event IDs are present
#				otherwise [false]
#			.PARAMETER file
#	

	#convert days to ms

	[long]$thresholdinms = $threshold * 86400000

	#build query string

	$strTimeCreated = "TimeCreated[timediff(@SystemTime) <= " + $thresholdinms + "]"

	foreach ($evtID in $evtIDs) {$strevtFilter += "(EventID=" + $evtID + ")"}

	$strevtFilter = $strevtFilter.Replace(")(", ") or (")

	$strQuery = "*[System[" + $strevtFilter + " and " + $strTimeCreated + "]]" 
	
	
	$Error.Clear()
		
	$CommandToRun = "wevtutil.exe qe `"$EvtLogName`" /q:`"$strQuery`" /c:1"

	$Results = Invoke-Expression $CommandToRun -ErrorAction Continue

	if (($Error.Count -eq 0) -and ($null -ne $Results))
	{

		return $true
	}
	else
	{

		return $false
	}

}

	
# **************
# Detection Logic
# **************

	# Detect if OS version is equal to Windows Server 2008 R2 AND
	# Event ID 21203 OR 21125 exist in past 15 days AND
	# Cluster Service AND Hyper-V are installed
	$ServiceNames = "clussvc", "vmms"
	$ServicesPresent = (checkServicesInstalled($ServiceNames))
	$evtIDs = @("21125", "21203")
	
	$threshold = "-15"
	$evtLogName = "Microsoft-Windows-Hyper-V-High-Availability-Admin"

	if ((isOSVersion) -and (($ServicesPresent) -and (CheckEvtLog -EvtLogName $evtLogName -threshold $threshold -evtIDs $evtIDs)))
	{
		$RootCauseDetected = $true	
	}
	
# *********************
# Root Cause processing
# *********************

if ($RootCauseDetected)
{
	# Red/ Yellow Light
	Update-DiagRootCause -id $RootCauseName -Detected $true
	Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL $PublicContent -Verbosity "Error" -Visibility 4
}
else
{
	# Green Light
	if ((isOSVersion) -and ($ServicesPresent))
		{
			Update-DiagRootCause -id $RootCauseName -Detected $false
		}
}


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDYJWnMCUFDDffL
# FFjB/YGznfEUhk8tRXa8ws1p+AG+aaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILgYDRUqbYe/5KKR+JfFJumc
# gsM4UI+ny2D+dglIXAM9MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBAw2FI4+G70zUVCGImAsAwLdro/lpQYnHqzirX6wZtJaIfu7t7Bx3V
# HO/67IdQi+H59AlrrpM+p0EHn8wr06mf33skX1tDpBjRzA7S+pBVAip39sB9yh9K
# WLzIUJbIa9oio0/OqaAXitBmOeqNU4d9LS3lePJpZ9O8tCfmxkopIrdyd79J26tX
# zkLkRIM0YFZ5b5QMcltr6yJSb3gGEUo0kgHVFtCQN3kbhsh70gUwvqINzS6eeiUZ
# fwBD4Uf/EnsPnoPAxg9bbuZD3sQ1mbfc7L7wnsKFfw2UNUn34ydxx/+BZVawoz/u
# cWxXmd/eZRHgZGlkvw4l8pFpEE+fihI8oYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIIHukZdFjtVBTFMiXAotS9dWppy54TH1tKRgzAH20QdOAgZi2BAW
# /+cYEzIwMjIwODAxMDgwMDEyLjg2NVowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkVBQ0Ut
# RTMxNi1DOTFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGawHWixCFtPoUAAQAAAZowDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTE3WhcNMjMwMjI4MTkwNTE3WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RUFDRS1FMzE2LUM5MUQxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDacgasKiu3ZGEU/mr6A5t9oXAgbsCJq0NnOu+54zZP
# t9Y/trEHSTlpE2n4jua4VnadE4sf2Ng8xfUxDQPO4Vb/3UHhhdHiCnLoUIsW3wtE
# 2OPzHFhAcUNzxuSpk667om4o/GcaPlwiIN4ZdDxSOz6ojSNT9azsKXwQFAcu4c9t
# svXiul99sifC3s2dEEJ0/BhyHiJAwscU4N2nm1UDf4uMAfC1B7SBQZL30ssPyiUj
# U7gIijr1IRlBAdBYmiyR0F7RJvzy+diwjm0Isj3f8bsVIq9gZkUWxxFkKZLfByle
# Eo4BMmRMZE9+AfTprQne6mcjtVAdBLRKXvXjLSXPR6h54pttsShKaV3IP6Dp6bXR
# f2Gb2CfdVSxty3HHAUyZXuFwguIV2OW3gF3kFQK3uL6QZvN8a6KB0hto06V98Ote
# y1OTOvn1mRnAvVu4Wj8f1dc+9cOPdPgtFz4cd37mRRPEkAdX2YaeTgpcNExa+jCb
# OSN++VtNScxwu4AjPoTfQjuQ+L1p8SMZfggT8khaXaWWZ9vLvO7PIwIZ4b2SK3/X
# mWpk0AmaTha5QG0fu5uvd4YZ/xLuI/kiwHWcTykviAZOlwkrnsoYZJJ03RsIAWv6
# UHnYjAI8G3UgCFFlAm0nguQ3rIX54pmujS83lgrm1YqbL2Lrlhmi98Mk2ktCHCXK
# RwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFF+2nlnwnNtR6aVZvQqVyK02K9FwMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAAATu4fMRtRH20+nNzGAXFxdXEpRPTfbM0LJDeNe4QCxj0FM+wrJdu6UKrM2
# wQuO31UDcQ4nrUJBe81N6W2RvEa8xNXjbO0qzNitwUfOVLeZp6HVGcNTtYEMAvK9
# k//0daBFxbp04BzMaIyaHRy7y/K/zZ9ckEw7jF9VsJqlrwqkx9HqI/IBsCpJdlTt
# KBl/+LRbD8tWvw6FDrSkv/IDiKcarPE0BU6//bFXvZ5/h7diE13dqv5DPU5Kn499
# HvUOAcHG31gr/TJPEftqqK40dfpB+1bBPSzAef58rJxRJXNJ661GbOZ5e64EuyIQ
# v0Vo5ZptaWZiftQ5pgmztaZCuNIIvxPHCyvIAjmSfRuX7Uyke0k29rSTruRsBVIs
# ifG39gldsbyjOvkDN7S3pJtTwJV0ToC4VWg00kpunk72PORup31ahW99fU3jxBh2
# fHjiefjZUa08d/nQQdLWCzadttpkZvCgH/dc8Mts2CwrcxCPZ5p9VuGcqyFhK2I6
# PS0POnMuf70R3lrl5Y87dO8f4Kv83bkhq5g+IrY5KvLcIEER5kt5uuorpWzJmBNG
# B+62OVNMz92YJFl/Lt+NvkGFTuGZy96TLMPdLcrNSpPGV5qHqnHlr/wUz9UAViTK
# JArvSbvk/siU7mi29oqRxb0ahB4oYVPNuv7ccHTBGqNNGol4MIIHcTCCBVmgAwIB
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
# IEVTTjpFQUNFLUUzMTYtQzkxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAAbquMnUCam/m7Ox1Uv/GNs1jmu+g
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRt4wwIhgPMjAyMjA4MDExMDIzMDhaGA8yMDIyMDgwMjEwMjMwOFow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pG3jAIBADAKAgEAAgIXMgIB/zAHAgEA
# AgIRmjAKAgUA5pMJDAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAJDWOTBH
# wWT7ODdvvwN83fTgmYJaXHNYartsyVF9rpHSxt/MeCzRG3eJuIv7NN6AGwYQ8iSI
# VKoLlWgJQBfdXcpJH9npPTaOFGGOp0CneOrMEDrZALoYvSJOgOCNPuZXjWrPDM0I
# 9TUzezb8sCF5uOFDpiZ7xObT3zfRoTb0Xg+1MYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGawHWixCFtPoUAAQAAAZowDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgisopvRhPq8Vq1txxbb3S7dwvArBHIdHvUArPFKUGM1MwgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCABTkDjOBEUfZnligJiL539Lx+nsr/N
# FVTnKFX030iNYDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABmsB1osQhbT6FAAEAAAGaMCIEILUtm4TpisXoG7kTsxOI51IMkFhuOyD6
# Xm+yAr8gIh09MA0GCSqGSIb3DQEBCwUABIICACMnC5T/5Oq3g+ap0zr0FIkc8+y5
# I3bz4VndeKSSsdNi3RkNH74v5hgsAcFitsOsiAbUzJP3bRBQoylRrL3aTFAzLJvX
# Ht4Rm8eUIOI9/Vjc/GNf3jxrRiJ06WFTXb3nY+6h1VyFk/Uf8mU8mUZxXDDHyF+q
# PIpSHjRbWZc4uh7aP/cgP6WY8zDWsK6ZGwvW1FqDxn8RS1TUenK6JM98cZiiOE07
# oqtoI1B8O6YIXk1acA1GlJwylEyUqagiZrKYV1uCStaf0Aw/7Dqw8BbfYcndkLkR
# Evznt5J/NnRt0JwmSkOBQjyVwTl2wmZ0suYX9o9++q/8cdOLQpMjamLgxmETtKNd
# 5a6/cR5mRBUXR7dNRCs6GhHYRLIHV2AfxHX/zc7bD40VcXJUME7R3gIQvUqoUBZh
# 5sJ+GHpgxqPopGO+3w7qK4Wb09W4N5+3q+9vJ4qMqKuEen4EMZ8kkSBaFhOYb7yk
# vXM7A/cnOoIQ6DoT2PAIjPMBzo5JR42dXGKxLWKdR4RMXmuDEDzTFDjpz96jeyXw
# cbWyyPCs+lfzGQonIZ+SFoZtUjRaIdjpN2aBk+re9tzh8TCtWkLo6B7qszdUc4BH
# izF13HSkNWztzbVeWFf6tYEt3LNu2pMB4D5T1pZ8xx6BAFclNUqXDRSG3kX+pFen
# mJnVvu2f43JO2I9v
# SIG # End signature block
