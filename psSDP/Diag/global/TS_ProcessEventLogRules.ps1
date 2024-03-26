# 2023-02-20 WalterE mod Trap #we#
trap [Exception]{
	WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; continue
	Write-Host "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_"
}

Import-LocalizedData -BindingVariable ScriptStrings

Function GetEventLogAlertGenerated{
      $EventLogAlertXMLFileName = Join-Path $PWD.Path ($Computername + "_EventLogAlerts.XML")
      if ($EventLogAlertXMLFileName){
            "Processing Event Log Alerts from " + (Split-Path $EventLogAlertXMLFileName -Leaf) | WriteTo-StdOut -ShortFormat
            [xml] $XMLEventAlerts = Get-Content -Path $EventLogAlertXMLFileName
            $EventLogAlerts = @()
            if($null -ne $XMLEventAlerts){
                  $XMLEventAlerts.SelectNodes("//Alert") | ForEach-Object -Process {
                        $EventLogAlert = New-Object PSObject
                        $EventLogAlert | Add-Member -MemberType NoteProperty -Name "EventLogName" -Value $_.EventLog
                        $EventLogAlert | Add-Member -MemberType NoteProperty -Name "Id" -Value $_.Id
                        $EventLogAlert | Add-Member -MemberType NoteProperty -Name "Type" -Value $_.Type
                        $EventLogAlert | Add-Member -MemberType NoteProperty -Name "Source" -Value $_.Source
                        $EventLogAlert | Add-Member -MemberType NoteProperty -Name "DaysToMonitor" -Value $_.DaysToMonitor
                        $EventLogAlert | Add-Member -MemberType NoteProperty -Name "EventCount" -Value $_.EventCount
                        $EventLogAlert | Add-Member -MemberType NoteProperty -Name "LastOccurrenceDate" -Value $_.LastOccurrence
                        $EventLogAlert | Add-Member -MemberType NoteProperty -Name "FirstOccurenceDate" -Value $_.FirstOccurence
                        $EventLogAlert | Add-Member -MemberType NoteProperty -Name "LastOccurrenceMessage" -Value $_.LastOccurrenceMessage
                        $EventLogAlerts += $EventLogAlert
                  }
            }
            return $EventLogAlerts
      }else{
            "$EventLogAlertXMLFileName does not exist. No Event Log alerts generated"  | WriteTo-StdOut -ShortFormat
      }
}

$EventLogAlerts = GetEventLogAlertGenerated

Function CheckEventIDExist([string]$EventId,[string]$EventSource,[string]$EventLogName,$EventLogAlertList= $null,[psobject]$EventInformationCollected){
	if($null -ne $EventLogAlertList){
		foreach($EventLogAlert in $EventLogAlertList){
			if(($EventLogAlert.Id -eq $EventId) -and ($EventLogAlert.EventLogName -eq $EventLogName)-and ($EventLogAlert.Source -eq $EventSource)){
				$EventInformationCollected | Add-Member -MemberType NoteProperty -Name "Event Log Name" -Value $EventLogAlert.EventLogName
				$EventInformationCollected | Add-Member -MemberType NoteProperty -Name "Event ID" -Value $EventLogAlert.Id
				$EventInformationCollected | Add-Member -MemberType NoteProperty -Name "Source" -Value $EventLogAlert.Source
				$EventInformationCollected | Add-Member -MemberType NoteProperty -Name "Number of Occurrences" -Value $EventLogAlert.EventCount
				$EventInformationCollected | Add-Member -MemberType NoteProperty -Name "Number of Days" -Value $EventLogAlert.DaysToMonitor
				$EventInformationCollected | Add-Member -MemberType NoteProperty -Name "Last event" -Value $EventLogAlert.LastOccurrenceDate
				$EventInformationCollected | Add-Member -MemberType NoteProperty -Name "Last Event Log Message" -Value $EventLogAlert.LastOccurrenceMessage
				return $true
			}
		}
	}
	return $false
}

#************************************ Functions of Rule 6301************************************#
Function Rule6301AppliesToSystem{
	return ($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2)
}

Function Rule6301CheckEventID333AndHotFix970054([psobject]$InformationCollected){
	$IsFireRule = $false
	if(CheckEventIDExist -EventId 333 -EventLogName 'System' -EventSource 'Application Popup' -EventLogAlertList $EventLogAlerts -EventInformationCollected $InformationCollected){
		$Win32OS= Get-CimInstance Win32_OperatingSystem
		if($null -ne $Win32OS){
			$IsHotFix970054Installed = $false
			$NtoskrnlPath = Join-Path $Env:windir "System32\ntoskrnl.exe"
			if($Win32OS.CSDVersion -eq 'Service Pack 1'){
				$IsHotFix970054Installed = CheckMinimalFileVersion $NtoskrnlPath 5 2 3790 3328
			}
			elseif($Win32OS.CSDVersion -eq 'Service Pack 2'){
				$IsHotFix970054Installed = CheckMinimalFileVersion $NtoskrnlPath 5 2 3790 4497
			}
			if($IsHotFix970054Installed){
				$RegistryFlushErrorSubsideTypeKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
				if(Test-Path $RegistryFlushErrorSubsideTypeKey){
					if($null -eq ((Get-ItemProperty $RegistryFlushErrorSubsideTypeKey).RegistryFlushErrorSubsideType)){
						$IsFireRule = $true
					}
				}
			}else{
				$IsFireRule = $true
			}
		}
	}
	return $IsFireRule
}


# [Idea ID 6301]
Function CheckRule6301{
	$Rule6301RootCauseDetected = $false
	$Rule6301InformationCollected = new-object PSObject
	$Rule6301RootCauseName = "RC_EventID333Check"
	$Rule6301RuleApplicable = Rule6301AppliesToSystem

	# **************
	# Detection Logic
	# **************
	if ($Rule6301RuleApplicable){
		$Rule6301RootCauseDetected = Rule6301CheckEventID333AndHotFix970054 -InformationCollected $Rule6301InformationCollected
	}
		
	# *********************
	# Root Cause processing
	# *********************
	if ($Rule6301RuleApplicable){
		if ($Rule6301RootCauseDetected){
			# Red/ Yellow Light
			Update-DiagRootCause -id $Rule6301RootCauseName -Detected $true
			Add-GenericMessage -Id $Rule6301RootCauseName -InformationCollected $Rule6301InformationCollected
		}else{
			# Green Light
			Update-DiagRootCause -id $Rule6301RootCauseName -Detected $false
		}
	}
}

#************************************ Functions of Rule b2c02cd5-4183-40a8-b25b-ee0597432811************************************#

Function Ruleb2c02cd5418340a8b25bee0597432811AppliesToSystem{
	return ((($OSVersion.Major -eq 5)-and ($OSVersion.Minor -eq 2)) -or # Windows Server 2003
	(($OSVersion.Major -eq 6)-and ($OSVersion.Minor -eq 0))) # Windows Server 2008
}

Function Ruleb2c02cd5418340a8b25bee0597432811CheckEventID4689AndHotFix([psobject]$InformationCollected){
	$IsFireRule = $false
	$ComsvcsdllPath = Join-Path $Env:windir "System32\comsvcs.dll"
	$IsHotFixInstalled = CheckMinimalFileVersion $ComsvcsdllPath 2001 12 4720 4045
	if(!$IsHotFixInstalled){
		if(CheckEventIDExist -EventId 4689 -EventLogName 'Application' -EventSource 'COM+' -EventLogAlertList $EventLogAlerts -EventInformationCollected $InformationCollected){
			$IsFireRule = $true
		}
	}
	return $IsFireRule
}

Function CheckRuleb2c02cd5418340a8b25bee0597432811{
	$Ruleb2c02cd5418340a8b25bee0597432811RuleApplicable = Ruleb2c02cd5418340a8b25bee0597432811AppliesToSystem
	$Ruleb2c02cd5418340a8b25bee0597432811RootCauseDetected = $false
	$Ruleb2c02cd5418340a8b25bee0597432811RootCauseName = "RC_EventID4689Check"
	$Ruleb2c02cd5418340a8b25bee0597432811InformationCollected = new-object PSObject

	# **************
	# Detection Logic
	# **************
	if ($Ruleb2c02cd5418340a8b25bee0597432811RuleApplicable)
	{
		$Ruleb2c02cd5418340a8b25bee0597432811RootCauseDetected = Ruleb2c02cd5418340a8b25bee0597432811CheckEventID4689AndHotFix -InformationCollected $Ruleb2c02cd5418340a8b25bee0597432811InformationCollected
	}
		
	# *********************
	# Root Cause processing
	# *********************
	if ($Ruleb2c02cd5418340a8b25bee0597432811RuleApplicable){
		if ($Ruleb2c02cd5418340a8b25bee0597432811RootCauseDetected){
			# Red/ Yellow Light
			Update-DiagRootCause -id $Ruleb2c02cd5418340a8b25bee0597432811RootCauseName -Detected $true
			Add-GenericMessage -Id $Ruleb2c02cd5418340a8b25bee0597432811RootCauseName -InformationCollected $Ruleb2c02cd5418340a8b25bee0597432811InformationCollected
		}else{
			# Green Light
			Update-DiagRootCause -id $Ruleb2c02cd5418340a8b25bee0597432811RootCauseName -Detected $false
		}
	}
}

#************************************ Functions of Rule 81ad63ea-48df-4066-8051-91f3323672a8************************************#
# Version 1.0.1
# Date: 7/16/2013
# Author: v-maam
# Description:  [KSE Rule] [ Windows V3] WinRM does not accept HTTP authorization requests that are larger than 16 KB
# Rule number:  81ad63ea-48df-4066-8051-91f3323672a8
# Rule URL:  https://kse.microsoft.com/Contribute/Idea/96ad45c3-eb18-4f41-ad94-b36ab175d26b
#************************************************

Function Rule6822AppliesToSystem{
	#Add your logic here to specify on which environments this rule will appy
	return (($OSVersion.Build -eq 6001) -and ($OSVersion.Build -eq 6002)) # Windows Vista sp1/sp2 or Windows Server 2008 sp1/sp2
}

# [Rule 6822]
Function CheckRule6822{
	Display-DefaultActivity -Rule -RuleNumber 81ad63ea-48df-4066-8051-91f3323672a8

	$Rule6822Applicable = $false
	$Rule6822RootCauseDetected = $false
	$Rule6822RootCauseName = "RC_WinRMHTTPRequestSizeCheck"
	$Rule6822InformationCollected = new-object PSObject

	# **************
	# Detection Logic
	# **************
	if(Rule6822AppliesToSystem){
		$Rule6822Applicable = $true
		if(CheckEventIDExist -EventId 6 -EventLogName 'System' -EventSource 'Microsoft-Windows-Security-Kerberos' -EventLogAlertList $EventLogAlerts -EventInformationCollected $Rule6822InformationCollected){
			$IsHotFix971244Installed = $false
			$WSManHttpConfigPath = Join-Path $Env:Windir "System32\WSManHTTPConfig.exe"
			if(Test-Path $WSManHttpConfigPath){
				if($OSVersion.Build -eq 6001){
					$IsHotFix971244Installed = CheckMinimalFileVersion $WSManHttpConfigPath 6 0 6001 22432
				}else{
					$IsHotFix971244Installed = CheckMinimalFileVersion $WSManHttpConfigPath 6 0 6002 22135
				}
			}
			$IsWinRMServiceRunning = $null -ne (Get-Service WinRM | Where-Object {$_.Status -eq "Running"})
			if((-not $IsHotFix971244Installed) -and (-not $IsWinRMServiceRunning)){
				$Rule6822RootCauseDetected = $true
			}
		}
	}

	# *********************
	# Root Cause processing
	# *********************
	if ($Rule6822Applicable){
		if ($Rule6822RootCauseDetected){
			# Red/ Yellow Light
			Update-DiagRootCause -id $Rule6822RootCauseName -Detected $true
			Add-GenericMessage -Id $Rule6822RootCauseName -InformationCollected $Rule6822InformationCollected
		}else{
			# Green Light
			Update-DiagRootCause -id $Rule6822RootCauseName -Detected $false
		}
	}
}

#************************************ End Functions of Rule 81ad63ea-48df-4066-8051-91f3323672a8************************************#

# Check Rule 6301 [Windows] Many events with ID 333 are added to the System log on a Windows Server 2003-based computer
CheckRule6301{}

#Check the comsvcs.dll is lower than 2001.12.4720.4045 and Event Id 4689 is in Application log
CheckRuleb2c02cd5418340a8b25bee0597432811{}

# Start to check the Rule 81ad63ea-48df-4066-8051-91f3323672a8
CheckRule6822{}


# SIG # Begin signature block
# MIInlAYJKoZIhvcNAQcCoIInhTCCJ4ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCASdlXj3VS+C7sT
# Az9I1ZtAoJAVC+bzz2pNweRp3tj+iqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXQwghlwAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIB5OafTkfHtWZROvGLS1lQ5f
# K152ZVF/LeaFxb6xyj3cMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQB7xDvAFZE0qov7WTZtz5ou1ASJQQ1u/FSYjB7pXIbP7v/HtcWnghS7
# 2VWEtX3hwqw8ECHJzP//F3gBpB4vTE9DQpzqm5XMFyaa1BpxGswSEjqKnSxphfCS
# 2mvZK43jCy/jSsc81aC3RnfZXA5Pwe2shn0jdoN40TSwxRJo9vaHSPpysi1z+ZAV
# o/CUCLBhXPqiqyMBXhipTvpiXRaRd1wmb9zaEVmuqu7XY0En+6+mf1eHut8DJo6H
# EemIC04NDHDlfUvvaBNlKaNvOVhqiwdptIThlU67SjVbRH6lSjxjsbNRkg0iZ7RR
# qrbiLQ59agx+ag9FxKbnLRgjWUQznNIWoYIW/DCCFvgGCisGAQQBgjcDAwExghbo
# MIIW5AYJKoZIhvcNAQcCoIIW1TCCFtECAQMxDzANBglghkgBZQMEAgEFADCCAVAG
# CyqGSIb3DQEJEAEEoIIBPwSCATswggE3AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIKf6PtzJL+FTGun2qmhbm7EJF968ONoHasKPAsaXT4eGAgZj7h9/
# XfgYEjIwMjMwMjIwMTUwNjAwLjUyWjAEgAIB9KCB0KSBzTCByjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFt
# ZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JCRC1F
# MzM4LUU5QTExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghFUMIIHDDCCBPSgAwIBAgITMwAAAcYwzS7W06HA9AABAAABxjANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMjExMDQxOTAx
# MzRaFw0yNDAyMDIxOTAxMzRaMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozQkJELUUzMzgtRTlBMTElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAO+9Ijq+r+B5NZt0mY/tQUf4rqH7/n+nlW+x3NtWMcwM
# 66OBupClxeO2ALBIK1lk9aIL6dCK6BZvAnUWU3/w5UNH2zTTvaQgNNSidN8x/Ngp
# ZpPc3va9YzydWSWjJ7GZgMu1aWPZjal/XYT751tf2cW24h7+6sMIMPVNkk+Zn3KT
# 7rbCP0K/4CwumkyN1AmM4lT2f0H2oPDUISpKR2Ttyq+a/N3Mu48+Dlj8uTNlorVr
# +WySeawU1udfEDxMxcM6vHvD+9tglimSRYzfHrQYLCtOYB3h2jfZJpaWCSS/OL/S
# Yml+zRSZDkYQKRBWYlCGmaC8SbeKXAQ83/lg/VAI0SgqwLHif3JM0Lzp/eV+DreG
# rJzrjYXAnXEFnK2aMpBZhGqGJK7A+5/+JxRR8CQylGgWGWS8D4+7sePEtWHvnDHH
# DMXUUo7qBuK6iaqRHeoM389t/b9+i/i7TpUIXy+XJ3JYTUlnZisNUx8npB/ekTbT
# qSBO3PvU57L9WhPYaYXoyzicX7F05MsNBSHYpXNAj+881LKmghhdphV0cC+I319U
# cle0BihHjqbxmakCix1WWyw99s7VvC37/fcUNuHf0yMTvS0Xrh7J8KLZ/vAbAq87
# vv9uLznAPV3KXe5CHluM5lMYRbL+Cgn4qjKbWYYTAANEqg7o9t3I9dLJl0Ti1J4V
# AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUcV/5R4koRAqdZ9pTGuhtbi7zYJQwHwYD
# VR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZO
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBc
# BggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYD
# VR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOC
# AgEAC8xe9uI17oA1OPOjzAWEewnOmh69pyQ5xrJ5KsGWJo0YtvKr+ktS8u+9s8Ju
# QyNfPc4AEPfcYRI1urmJK1+VK7VbuyVED+mwQQSffHNvBQCDyCt35EDQr9q8UY30
# DCUnXMLCXkyuy3dPTrgOYWOD1ggYCaX2O9S3Gl89xUfADTxV+s3CmG4GDma3oLaQ
# 7m9+DdEIUe8HPxXJlfoOCNyHUwKDA9v1iOWbHyk8wVJ/1NwKVITcGzpeWEgvn/Ut
# S0rW2S8D8zEvnyz1yVEnu0kr7KX0rK/1RHtKEIZmkfub3KvuzC8POtVgVYWKSe0w
# eWAUuTkTvV3SG3KWwRcHBz5m/ImakiKlvSaYBu+vuTUFCz1c2e+c+VtkeWYskJLY
# h6TMI19jjtvWfPp08NrTrFQnMMx/S6BC3nb9z43KW8Dsi47ZtU+Fx2Hd6m3fQ16A
# YzWJEo3Yt+6TaefLvqyE5bSyjo40AicI9RaZ7gWPNuQeQtLgvzWBEhCrE4nBI4Uv
# +LowVy3DRg4VQZdrxxOqmP2FuJMtb3Mqb1K7BvNYKb9vvP4oTsIOMEyzu16opHiI
# lN2VgFAKDqU5deLXnUKsWx0w73iWEdzlNMigdscH/OxFggG9AiYpoQ5skGihL0ld
# Hy1vYlciNMGHBuFdmlTek62eJq/n32qg0A/Rfh6T4T9KZQMwggdxMIIFWaADAgEC
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
# U02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICyzCCAjQCAQEwgfihgdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjNCQkQtRTMzOC1FOUExMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQAtNcrmJiFb7KJEmnCZlnvDLtkBbaCB
# gzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEB
# BQUAAgUA553jpzAiGA8yMDIzMDIyMDIwMTg0N1oYDzIwMjMwMjIxMjAxODQ3WjB0
# MDoGCisGAQQBhFkKBAExLDAqMAoCBQDnneOnAgEAMAcCAQACAgpOMAcCAQACAhJ9
# MAoCBQDnnzUnAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAI
# AgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAfwOyN4vYSdvc
# /y8I4CbygzlqVwvfJZUAKleg16zF+a05yzqx4ceQ621BeWkZKZh9/cUr6+h6yP1l
# 9iGesbYC1Iydqbj7m6yCB4EJOtI+t8qA7ToPuA7gdTFsCktQa/pvOvUclXJz9MK8
# /JkDZHHv+EScrl2HROiIqS40j2kOY3ExggQNMIIECQIBATCBkzB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAcYwzS7W06HA9AABAAABxjANBglghkgB
# ZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3
# DQEJBDEiBCCnoCdL8089iv3P7W5kSMoPQXGtPVBGLYekaWmgNbVqvzCB+gYLKoZI
# hvcNAQkQAi8xgeowgecwgeQwgb0EIFYxE1xVyb2YKcYmapPwcA1gOT8cOoXoVC6Z
# Ba/a468tMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAHGMM0u1tOhwPQAAQAAAcYwIgQgv7EiXJX9b+0sDXsELCpVbucLI51dxxXNtDEH
# n0mTzsYwDQYJKoZIhvcNAQELBQAEggIAqAWY1+wUohsj2KiZPQyk+RSYhYQxq/GS
# u0nMQS75O1oODyMLhE9drYBYcsfGsfpFaQ15yvfV8louHFXQFiuTtBd2WqjnR14X
# xeU7CqMO67LRlPwh5OCATOcCJTtD56ekEeCDOGSAm+lZTFQkEECxukpBC+ZYX/x3
# zyWUOm5u2T8XE9PQcElFoO/rkbf5iag7QGkPlK7hIWh+9H2r3PJ91+xnwoDVigU7
# +zv6RdqmJahxrCB54xlsI/+bWp4IOzfgqtghnb0w7u92TeM94WN++xKWyborZi61
# sJIatMY2z3kDkVq7WbJ/iac2Y/SGS1kfsJt15tWwQW8XFRVz50EVJIBL/uiS1baE
# IYPxhILVwfDncNIye7YLN22SH9GvNo9qoa7CBXzZg2oY4tVSAy2Y0iuLjl1qYHhq
# xuHqjKjbJrfTjDu2wozGXwJxdn1HKlBrGeI+5hhIEBoWmSuhTS4iSbgYv/V3yn4Z
# 5uzN+M9hNBxilmhMp7a+UOCCh5nZIFpfmlPF1ENJEcqbhRGCv8FCyR2CFHpHIBBH
# 6c/GPzKr/B3Dd9qtSiYyEZIiW+qTaqZF6a/V/9t1byxDNyRey/Aawq0Rg4BiCCua
# paYPF14S/E41vhtH6Rsa/jLJS64vVJTE+fGJZfIDA2xI81zIBXLyPJ9NBYcq1Ags
# 2MQI+kwoMX4=
# SIG # End signature block
