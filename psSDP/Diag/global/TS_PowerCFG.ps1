#************************************************
# TS_PowerCFG.ps1
# Version 3.0
# Date: 14/03/2013
# Author: v-kaw
# Description: Running powercfg.exe to obtain power settings information 
# Note: This is the third edition of this file. Ideal ID for this edition is 6292.
#       Ideal ID for second edition is 4735. The original ideal id is 1103
#************************************************

#Rule ID 4735,6292
#-----------
# http://sharepoint/sites/rules/Rule Submissions/Forms/DispForm.aspx?ID=4735
# http://sharepoint/sites/rules/Rule Submissions/Forms/DispForm.aspx?ID=6292
#Description
#-----------
# Running powercfg.exe to obtain power settings information 
#Related KB
#----------
# https://vkbexternal.partners.extranet.microsoft.com/VKBWebService/ViewContent.aspx?scid=KB;EN-US;980869
#Script Author
#-------------
# kate wang(v-kaw)

	
Import-LocalizedData -BindingVariable ScriptStrings
Write-DiagProgress -Activity $ScriptStrings.ID_PowerCFG -Status $ScriptStrings.ID_PowerCFGDesc

#********************
#Data gathering
#********************
	$fileDescription = "PowerCFG Output"
	$sectionDescription = "Power Settings"
	
	function Header($Command, $file)
	{
		"-" * ($Command.Length + 35) + "`r`n $Command`r`n" + "-" * ($Command.Length + 35) | Out-File -FilePath $file -Append
		"`n" | Out-File -FilePath $OutputFile -append
	}

    if ((($OSVersion.Major -eq 6) -and ($OSVersion.Minor -ge 2)) -or ($OSVersion.Major -eq 10))     #Win 8, Win10
	{
		if($null -ne (Get-CimInstance -Class Win32_Battery ))   #if system has a battery
		{
			$OutputFile = join-path $PWD.Path "$($computername)_PowerCFG_BatteryReport.htm"
			
			$CommandToExecute = "powercfg -batteryreport -duration 28 -output $OutputFile"      
			RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription "PowerCFG Battery Report"
		}

		
		#
		# PowerCFG /sleepstudy cannot be run if ConnectedStandby -ne 1.
		# Creating an output file called _PowerCFG_SleepstudyReport.TXT with contents indicating that Powercfg /sleepstudy failed to run, etc.
		# Check for HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power "CsEnabled" = dword:00000000
		#
		
		# Run this first with no checks so that non-ConnectedStandby machines are not affected.
		$OutputFile = join-path $PWD.Path "$($computername)_PowerCFG_SleepstudyReport.htm"
		$CommandToExecute = "powercfg -sleepstudy -duration 28 -output $OutputFile"      
		RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription "PowerCFG SleepStudy Report"

		# Now checking for the ConnectedStandby machines		
		$regkeyPower = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"
		If (test-path $regkeyPower)
		{
			"[info] Power regkey exists"  | WriteTo-StdOut 
			$regvaluePowerCsEnabled = Get-ItemProperty -path $regkeyPower -name "CsEnabled" -ErrorAction SilentlyContinue
			if ($null -ne $regvaluePowerCsEnabled)
			{
				$regvaluePowerCsEnabled = $regvaluePowerCsEnabled.CsEnabled
				"[info] Connected Standby registry value exists: $regvaluePowerCsEnabled"  | WriteTo-StdOut 
				if ($regvaluePowerCsEnabled -ne 1)
				{
					$fileDescription = "PowerCFG Output"
					$sectionDescription = "Power Settings"
					$outputFile = $Computername + "_PowerCFG_SleepStudyReport.TXT"
					"===================================================="	| Out-File -FilePath $OutputFile -append
					"PowerCFG /Sleepstudy"									| Out-File -FilePath $OutputFile -append
					"===================================================="	| Out-File -FilePath $OutputFile -append
					"`n" | Out-File -FilePath $OutputFile -append
					"Connected Standby has been DISABLED." | Out-File -FilePath $outputFile -Append
					"The PowerCFG_Sleepstudyreport.htm cannot be generated." | Out-File -FilePath $outputFile -Append
					"PowerCFG /sleepstudy outputs the following message when Connected Standby is disabled:" | Out-File -FilePath $outputFile -Append
					"  `"Connected Standby is not supported on this machine. Cannot run tool.`"" | Out-File -FilePath $outputFile -Append
					"`n`n`n" | Out-File -FilePath $OutputFile -append
					CollectFiles -filesToCollect $outputFile -fileDescription "$fileDescription" -SectionDescription $sectionDescription
				}
			}
		}
	}
	if( (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 1)) -or   #Win 7/ R2
	    (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -ge 2))  )    #Win 8/8.1
	{
		$OutputFile = join-path $PWD.Path "$($computername)_PowerCFG_Energy_Report.htm"
			
		$CommandToExecute = "powercfg -energy -duration 5 -output $OutputFile"     
		RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription "PowerCFG Energy Report" -BackgroundExecution

		$OutputFile = join-path $PWD.Path "$($computername)_PowerCFG.txt"

		$CommandToExecute = "powercfg -list"
		header -Command $CommandToExecute  -file $OutputFile
		RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
		
		$CommandToExecute = "powercfg -qh"
		header -Command $CommandToExecute  -file $OutputFile
		RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
		
		$CommandToExecute = "powercfg -requests"
		header -Command $CommandToExecute  -file $OutputFile
		RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
		
		$CommandToExecute = "powercfg -lastwake"
		header -Command $CommandToExecute  -file $OutputFile
		RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
		
		$CommandToExecute = "powercfg -availablesleepstates"
		header -Command $CommandToExecute  -file $OutputFile
		RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription
	}
	elseif(($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 0)) #Server 2008 / Vista
	{
		$OutputFile = join-path $PWD.Path "$($computername)_PowerCFG.txt"
			
		$CommandToExecute = "powercfg -list"
		header -Command $CommandToExecute -file $OutputFile
		RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
		
		$CommandToExecute = "powercfg -query"
		header -Command $CommandToExecute -file $OutputFile
		RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
		
		$CommandToExecute = "powercfg -devicequery all_devices_verbose"     
		header -Command $CommandToExecute  -file $OutputFile
		RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription
		
	}
	elseif((($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 1)) -or
			(($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2))) #XP/#Server 2003
	{
		$OutputFile = join-path $PWD.Path "$($computername)_PowerCFG.txt"
			
		$CommandToExecute = "powercfg -list"
		header -Command $CommandToExecute -file $OutputFile
		RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
		
		$CommandToExecute = "powercfg -query"
		header -Command $CommandToExecute -file $OutputFile 
		RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription
	}
	

# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBoGXjsiFzEBH5m
# fbxQAo3QVB+SULWpQ3SNrxvVyKdPuqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPoLEqFQBwqW32AKEvrFKWk1
# /bD56lW0dd+yy5scr6nCMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCgLYbL8d2XL8qkLqRelMB7Sy1PxNUJ1OZ5Bq/RseEPqmEQ7+0GXoPv
# A0OtL1jFdibL00t+LG2qLIhVGm4bBkgu1EfCqJ97FeOX3JBjERzgFnPFMmCy0Ts5
# PxL+OC4epMM/MuvdHfbyXbkc6Dx3yEWnVnUD/7Uta97eWi0CriTQuwDku6LkSEDQ
# OldMYcSjc7Ay21G+A0pY93l9SsK+Uo0EYSQADxAWUe3kUZUauc4sJmIxaoe4ojTq
# GjEcTIfxMdpUnjsLHZecg5N8EoWKledesqkzDcMTrcgUkW93EwHKv8q96RpAYEOJ
# HLL4wf4Sje1zLbzMWTv/L0BJRdOIXAY2oYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIHLOdnRyrjMyYIk1QwQ52HsbOtudGpnFMuAVWp/rzHcnAgZi3mrX
# 5LQYEzIwMjIwODAxMDc0MjUwLjY2MlowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046MDg0Mi00QkU2LUMyOUExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAYdCFmYEXPP0jQABAAABhzAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3MzlaFw0yMzAxMjYxOTI3MzlaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjA4NDIt
# NEJFNi1DMjlBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvml4GWM9A6PREQiHgZAA
# PK6n+Th6m+LYwKYLaQFlZXbTqrodhsni7HVIRkqBFuG8og1KZry02xEmmbdp89O4
# 0xCIQfW8FKW7oO/lYYtUAQW2kp0uMuYEJ1XkZ6eHjcMuqEJwC47UakZx3AekakP+
# GfGuDDO9kZGQRe8IpiiJ4Qkn6mbDhbRpgcUOdsDzmNz6kXG7gfIfgcs5kzuKIP6n
# N4tsjPhyF58VU0ZfI0PSC+n5OX0hsU8heWe3pUiDr5gqP16a6kIjFJHkgNPYgMiv
# GTQKcjNxNcXnnymT/JVuNs7Zvk1P5KWf8G1XG/MtZZ5/juqsg0QoUmQZjVh0XRku
# 7YpMpktW7XfFA3y+YJOG1pVzizB3PzJXUC8Ma8AUywtUuULWjYT5y7/EwwHWmn1R
# T0PhYp9kmpfS6HIYfEBboYUvULW2HnGNfx65f4Ukc7kgNSQbeAH6yjO5dg6MUwPf
# zo/rBdNaZfJxZ7RscTByTtlxblfUT46yPHCXACiX/BhaHEY4edFgp/cIb7XHFJbu
# 4mNDAPzRlAkIj1SGuO9G4sbkjM9XpNMWglj2dC9QLN/0geBFXoNI8F+HfHw4Jo+p
# 6iSP8hn43mkkWKSGOiT4hLJzocErFntK5i9PebXSq2BvMgzVc+BBvCN35DfD0mok
# RKxam2tQM060SORy3S7ucesCAwEAAaOCATYwggEyMB0GA1UdDgQWBBQiUcAWukEt
# YYF+3WFzmZA/DaWNIDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQC5q35T2RKjAFRN/3cYjnPFztPa7KeqJKJnKgvi
# Uj9IMfC8/FQ2ox6Uwyd40TS7zKvtuMl11FFlfWkEncN3lqihiSAqIDPOdVvr1oJY
# 4NFQBOHzLpetepHnMg0UL2UXHzvjKg24VOIzb0dtdP69+QIy7SDpcVh9KI0EXKG2
# bolpBypqRttGTDd0JQkOtMdiSpaDpOHwgCMNXE8xIu48hiuT075oIqnHJha378/D
# pugI0DZjYcZH1cG84J06ucq5ygrod9szr19ObCZJdJLpyvJWCy8PRDAkRjPJglSm
# fn2UR0KvnoyCOzjszAwNCp/JJnkRp20weItzm97iNg+FZF1J9E16eWIB1sCr7Vj9
# QD6Kt+z81rOcLRfxhlO2/sK09Uw+DiQkPbu6OZ3TsDvLsr8yG9W2A8yXcggNqd4X
# pLtdEkf52OIN0GgRLSY1LNDB4IKY+Zj34IwMbDbs2sCig5Li2ILWEMV/6gyL37J7
# 1NbW7Vzo7fcGrNne9OqxgFC2WX5degxyJ3Sx2bKw6lbf04KaXnTBOSz0QC+RfJuz
# 8nOpIf28+WmMPicX2l7gs/MrC5anmyK/nbeKkaOx+AXhwYLzETNg+1Icygjdwnbq
# WKafLdCNKfhsb/gM5SFbgD5ATEX1bAxwUFVxKvQv0dIRAm5aDjF3DZpgvy3mSojS
# rBN/8zCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
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
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MDg0Mi00QkU2LUMyOUExJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAHh3k1QEKAZEhsLGYGHtf/6DG4PzoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmkXrqMCIYDzIwMjIwODAx
# MDYwNDI2WhgPMjAyMjA4MDIwNjA0MjZaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaReuoCAQAwBwIBAAICHj8wBwIBAAICES4wCgIFAOaSzGoCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQCF/hfbIZQ0IEk6Kh2lseeEtTISZpszbfBnEeumjmWO
# 0hdqTDaefoW0+b7u5tEPoWvT2Y26R/5PThTeB8JmkwcqCENPZii9O+oZLx+a5Iou
# 6CKUmF9a1B/JSMc0nzpCTZddlgNPs96jeJuJfSrQ0BGHRHmxERqh1JwzqpL2X6pr
# 5TGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABh0IWZgRc8/SNAAEAAAGHMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEINfM/mMJnfgCtb9HKPu4
# RgUdGceabcEmGmnj09ADkvf3MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# xCzwoBNuoB92wsC2SxZhz4HVGyvCZnwYNuczpGyam1gwgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYdCFmYEXPP0jQABAAABhzAiBCDA
# p3m7l8Nc7DlqiRsVc7ZPNSsKmHhdZilO6Ifx7KEsVTANBgkqhkiG9w0BAQsFAASC
# AgAGxbICemvF4Vh8XKYTyQnETiMMhZFQ0xxdoaRA397k6x3az4dJrz1qPnYixjSg
# Ad9JCb9wcwdmueXaAysCU0Llrx9mY52gNnbZRdmgAN8mDKFjg3q1h39jKXm7eATB
# E0mUsrCKQXbEMfbroPB87DLQB56hggvseWuAyaRrH0nzaJHCOQrWfX1yu0sSWF86
# bHZjmp5lRetYtNpJUuyvc0nlSQBR67ERYfTaSpOjnlwXSjN4AYA4Njzc/jcL5AVw
# Gf0cLXmScIW1pHATY51I0tKwYyc2t0ciwqqPf0Py0JsJrX0oAAhN88/X3qHAgvyp
# vMBp5A5ViU2tlfmt77NyW4gEfP2itv/b7zZXVZJfGBRwWVyxz9dgyVc5ywvscFmj
# 8vJn3kp8jhTXF420kEBFZ7W0w5z5br3Npm5dXv2EGnSZyMRHduwv+iKotXSNbvlc
# VKdXTdNo5tXaOyOQaSq18mQtR7En2HH2T47JYvzQJTWnYNV/7cDPiyhsMzNsVuN4
# ED0k9gs4oP6VHGePjbwLkzoERpGzSp3PWzDJV2pnPzkD21Fjl4AFy2u4+2zgT4Xm
# tm1+mJ+/rGfPx16fWd0b2v5hjnBYjU+WyBG8wPd779x6AqSpbH5p6wTXWiAk++pO
# f7TAUIzmNNos6r/fgITgYy8KjJO/ewVNX8xroPpd8KbLgg==
# SIG # End signature block
