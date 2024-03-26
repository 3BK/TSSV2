#************************************************
# DC_DPMVerboseTracing.ps1
# Version 1.0.1
# Date: 12/3/2012
# Author: v-maam
# Description:  [Idea ID 6196] [System Center Data Protection Manager] SDP Request - Verbose logging option (tracing) for DPM
# Rule number:  6196
# Rule URL:  http://sharepoint/sites/rules/Rule Submissions/Forms/DispForm.aspx?ID=6196
#************************************************

$StartTime  = [DateTime]::Now

Import-LocalizedData -BindingVariable ScriptStrings

$Script:DPMRegisoryKeyPath = "HKLM:SOFTWARE\Microsoft\Microsoft Data Protection Manager"
$Script:DPMFolderDir = GetDPMInstallFolder  # GetDPMInstallFolder function from Functions.ps1
 trap [Exception] 
 {
  WriteTo-ErrorDebugReport -ErrorRecord $_ 
  $Error.Clear()
  continue
 }

Function Press_s_key
{
		Write-Host "`n$(Get-Date -Format "HH:mm:ss") === Press the 's' key to stop verbose tracing. ===`n" -ForegroundColor Green
		do {
			$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
		} until ($x.Character -ieq 's')
}
####################################################################################
# Check to be sure the DPM 2010 or 2012 installed on the DPM server
####################################################################################
#Function CheckTheAvailableDPMVersion
#{
#	if(IsDPMInstalled) # IsDPMInstalled function from Functions.ps1
#	{		
#		$DPMVersion = DPMVersion ($Script:DPMFolderDir) 
#		if(($DPMVersion -eq 3) -or ($DPMVersion -eq 4))  # DPM 2010 and DPM 2012
#		{
#			return $true
#		}
#		else
#		{
#			"The current DPM version is " + $DPMVersion + " - rule does not apply." | WriteTo-StdOut 
#		}
#	}
#	return $false
#}

####################################################################################
# Check to be sure the DPM 2010 Agent or 2012 Agent installed on the server
####################################################################################
Function CheckTheAvailableDPMRAVersion
{
	if(IsDPMInstalled)
	{
		$DPMRAVersion = DPMRAVersion ($Script:DPMFolderDir)
		if(($DPMRAVersion -eq 3) -or ($DPMRAVersion -eq 4))  # DPM 2010 agent and DPM 2012 agent
		{
			return $true
		}
		else
		{
			"The current DPM agent version is " + $DPMRAVersion + " - rule does not apply." | WriteTo-StdOut 
		}
	}
	return $false
}

####################################################################################
# Add the TraceLogLevel property to the DPM registory key and restart the dpm related services
####################################################################################
Function AddTheTraceLogLevelRegistryKeyAndRestartServices
{
	if(Test-Path $Script:DPMRegisoryKeyPath)
	{
		$TraceLogLevel = (Get-ItemProperty $Script:DPMRegisoryKeyPath).TraceLogLevel
		if($null -eq $TraceLogLevel)
		{
			New-ItemProperty $Script:DPMRegisoryKeyPath -Name "TraceLogLevel" -Value 0x43e -PropertyType "DWord" 
			"Add the RegitoryKey: HKLM:SOFTWARE\Microsoft\Microsoft Data Protection Manager\TraceLogLevel on " + $ComputerName | WriteTo-StdOut
		}
		else
		{
			Set-ItemProperty $Script:DPMRegisoryKeyPath -Name "TraceLogLevel" -Value 0x43e
			"Set the RegitoryKey: HKLM:SOFTWARE\Microsoft\Microsoft Data Protection Manager\TraceLogLevel value to 0x43e on " + $ComputerName | WriteTo-StdOut
		}
	}

	"Restart the DPM, DPM Access Manager and DPMRA services on " + $ComputerName | WriteTo-StdOut
	if(IsDPMServer)
	{
		Restart-Service "DPM"
		Restart-Service "DPM AccessManager Service"
	}
	else
	{
		"DPM, DPM Access Manager services is not available on " + $ComputerName | WriteTo-StdOut
	}
	Restart-Service "DPMRA"
}

####################################################################################
# Remove the TraceLogLevel property from the DPM registory key and restart the dpm related services
####################################################################################
Function RemoveTheTraceLogLevelRegistryKeyAndRestartServices
{
	if(Test-Path $Script:DPMRegisoryKeyPath)
	{
		$TraceLogLevel = (Get-ItemProperty $Script:DPMRegisoryKeyPath).TraceLogLevel
		if($null -ne $TraceLogLevel)
		{
			Remove-ItemProperty $Script:DPMRegisoryKeyPath -Name "TraceLogLevel"
			"Removed the RegitoryKey: HKLM:SOFTWARE\Microsoft\Microsoft Data Protection Manager\TraceLogLevel on " + $ComputerName | WriteTo-StdOut
		}
	}

	"Restart the DPM, DPM Access Manager and DPMRA services on " + $ComputerName | WriteTo-StdOut
	if(IsDPMServer)
	{
		Restart-Service "DPM"
		Restart-Service "DPM AccessManager Service"
	}
	else
	{
		"DPM, DPM Access Manager services is not available on " + $ComputerName | WriteTo-StdOut
	}
	Restart-Service "DPMRA"
}

####################################################################################
# Record the load dpm console and enumerate the protect server time
####################################################################################
Function RecordScriptRunningTime($StartTime)
{
	$CompletionTime = [DateTime]::Now
	[void][System.Reflection.Assembly]::LoadWithPartialName('System.Core')
	$TimeZone = [System.TimeZoneInfo]::Local | Select-Object -ExpandProperty Id

	$InformationCollected = new-object PSObject
	Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Time Zone" -Value $TimeZone
	Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Start Time" -Value $StartTime
	Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Completion Time" -Value $CompletionTime
	Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Runing Total Seconds" -Value ([timespan]($CompletionTime - $StartTime)).TotalSeconds
	$InformationCollected | ConvertTo-Xml2 | update-diagreport -id "EnumerateServerTimeFor$ComputerName" -name ($ComputerName + " - Execution time information")	
}

####################################################################################
# For Remote server side verbose logging Phase 1 and 2, will create the txt file.
####################################################################################
Function RemoteServerSideVerboseLoggingPhase($Phase)
{
	"Start verbose logging Phase: " + $Phase + " on remote server: " + $ComputerName | WriteTo-StdOut
	$File = "VerbosePhase" + $Phase + ".txt"
	"For verbose logging Phase" + $Phase | Out-File $File -Encoding "utf8"
	$timeout = 15*60
	do
	{
		$VerbosePhaseFileExist = $true
		if(Test-Path (Join-Path $Pwd.Path $File))
		{
			Start-Sleep -Seconds 3
			$timeout = $timeout - 3

			if($timeout -le 0) # time out occurred, and log the information.
			{
				"[Error] A timeout has occurred. The verbose logging phase ("+ $Phase +") file: " + $File + " is still exist on the " + $ComputerName +", this phase will ended." | WriteTo-StdOut
			}
		}
		else
		{
			$VerbosePhaseFileExist = $false
		}
	} while ($VerbosePhaseFileExist -and ($timeout -gt 0))

	"End verbose logging Phase: " + $Phase + " on remote server: " + $ComputerName | WriteTo-StdOut
}

####################################################################################
# For Local server side verbose logging Phase 1 and 2, will delete the txt file.
####################################################################################
Function LocalServerSideVerboseLoggingPhase($ProtectedServerList, $Phase)
{
	"Start verbose logging Phase: " + $Phase + " on Local Server: " + $ComputerName | WriteTo-StdOut
	$FileName = "VerbosePhase" + $Phase + ".txt"
	$DiagnosticsFolderName = [System.IO.Path]::GetFileName($PWD.Path)
	$FoundPhaseFileMachineList = @("$ComputerName")
	$timeout = 15*60
	$timeoutOccurred = $false
	do 
	{
		$VerbosePhaseFileFound = $true	# assume all machine found the VerbosePhase.txt file
		foreach($machine in $ProtectedServerList)
		{			
			if(-not($FoundPhaseFileMachineList -Contains $machine))
			{
				trap [Exception] 
				{
					$ErrorStd = "[LocalServerSideVerboseLoggingPhase] The following error ocurred when checking if the VerbosePhasePhase"+$Phase+".txt file exists" 
					WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText $ErrorStd
					$error.Clear()
					continue
				}

				$Status = (($ScriptStrings.ID_DPM_Activity_VerboseLogs_Syncronizingexecution_Status) -Replace("%machine%", $machine) -Replace("%Phase%",$Phase))
				Write-DiagProgress -Activity $ScriptStrings.ID_DPM_Activity_VerboseLogs -Status $Status

				$FileFullPath = Join-Path -Path "\\$machine\admin$\temp\diagnostics\$DiagnosticsFolderName" -ChildPath $FileName
				"Checking for " + $FileFullPath + " (Phase " + $Phase + " ) on Server: " + $machine | WriteTo-StdOut

				if (-not(Test-Path $FileFullPath)) #Check all machines, once found a machine didnot have the file, always set the flag to false.
				{
					$VerbosePhaseFileFound = $false  
					if($timeoutOccurred  -eq $true) #if time out occurred, add the unable communicate machine to list string.
					{
						$UnableCommunicateMachinesString += " " + $machine + ","
					}
				}
				else # if machine has the file, add the machine to list, and next time will not check this machine.
				{
					$FoundPhaseFileMachineList += $machine 
				}
			}
		}
			
		if(($timeoutOccurred -eq $true) -and ($null -ne $UnableCommunicateMachinesString)) #if time out occurred, log the unable communicate machines.
		{
			"[Error] A timeout has occurred. Unable to communicate to the following machine(s):[" + $UnableCommunicateMachinesString + "]" | WriteTo-StdOut
		}	
				
		if($VerbosePhaseFileFound -eq $false)
		{
			Start-Sleep -Seconds 3
			$timeout = $timeout - 3

			if(($timeout -le 0) -and ($timeoutOccurred -eq $false)) #if time out occurred, add 3 seconds to $timeout, make sure loop one more time to log the unable communicated machines. 
			{
				$timeoutOccurred = $true
				$timeout = $timeout + 3
			}
		}
	} while (($VerbosePhaseFileFound -eq $false) -and ($timeout -gt 0))

	if($Phase -eq 2)
	{
		"Create the sub-key TraceLogLevel in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Data Protection Manager on Local Server: " + $ComputerName | WriteTo-StdOut 
		AddTheTraceLogLevelRegistryKeyAndRestartServices

		#-# Get-DiagInput -Id ID_WaitingForReproduceIssue
		Press_s_key
	}

	foreach($machine in $ProtectedServerList)
	{
		if($machine -ne $ComputerName)
		{
			"Remove "+$FileName+" on server: " + $machine | WriteTo-StdOut
			Remove-Item (Join-Path -Path "\\$machine\admin$\temp\diagnostics\$DiagnosticsFolderName" -ChildPath $FileName)
		}
	}

	"End verbose logging Phase: " + $Phase + " on Local Server: " + $ComputerName | WriteTo-StdOut
}

####################################################################################
# Main Logic for collect the VerboseTracing Data
####################################################################################

Write-DiagProgress -Activity $ScriptStrings.ID_DPM_Activity_VerboseLogs -Status $ScriptStrings.ID_DPM_Activity_VerboseLogs_Status

"here" | out-file C:\temp\function.txt -append

if(CheckTheAvailableDPMRAVersion)
{
	$RuningEnv = Get-TSRemote
	"TS Remote Level: " + $RuningEnv + " on " + $ComputerName | WriteTo-StdOut
	if($RuningEnv -eq 1) #Under TS_Remote environment, but running on the local machine
	{
		$SelectedMachinesPath = Join-Path $Pwd.Path "SelectedMachines.txt"
		if(Test-Path $SelectedMachinesPath)
		{
			$AllProtectedMachines = Get-Content $SelectedMachinesPath

			LocalServerSideVerboseLoggingPhase -ProtectedServerList $AllProtectedMachines -Phase 1

			LocalServerSideVerboseLoggingPhase -ProtectedServerList $AllProtectedMachines -Phase 2
		}
		else
		{
			"Did not found the SelectedMachines.txt" | WriteTo-StdOut
		}

	}
	elseif($RuningEnv -eq 2) #Under TS_Remote environment and running on a remote machine
	{
		RemoteServerSideVerboseLoggingPhase -Phase 1

		"Create the sub-key TraceLogLevel in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Data Protection Manager on " + $ComputerName | WriteTo-StdOut 
		AddTheTraceLogLevelRegistryKeyAndRestartServices

		RemoteServerSideVerboseLoggingPhase -Phase 2
	}
	else  #No TS_Remote environment, local machine runing only.
	{
		"Create the sub-key TraceLogLevel in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Data Protection Manager on " + $ComputerName | WriteTo-StdOut 
		AddTheTraceLogLevelRegistryKeyAndRestartServices

		#_# Get-DiagInput -Id ID_WaitingForReproduceIssue
		Press_s_key
	}
	
	Write-DiagProgress -Activity $ScriptStrings.ID_DPM_Activity_VerboseLogs -Status $ScriptStrings.ID_DPM_VerboseLogging_Desc

	"Collect the files from " + $Script:DPMFolderDir + "\Temp on " + $ComputerName | WriteTo-StdOut
	$OutputBase= "$ComputerName" + "_DPM_Verbose_Logs"
	CompressCollectFiles -filesToCollect (Join-Path $DPMFolderDir "Temp\*.*") -fileDescription "DPM Verbose Tracing file" -sectionDescription "Verbose Logging Information" -DestinationFileName ($OutputBase + ".zip") -renameoutput $false

	"Removed the sub-key TraceLogLevel on " + $ComputerName | WriteTo-StdOut
	RemoveTheTraceLogLevelRegistryKeyAndRestartServices

	RecordScriptRunningTime -StartTime $StartTime
}
else
{
	"This is not a DPM server or a protect server" | WriteTo-StdOut
}


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDP5j3zwwHkmJQc
# nQhh9twqRO3guC5ClxZA3MFulIqfXqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIeHFR8J+UuP7M+mXB1ATszT
# 7Ff9NMJj5hO5iDcvrAaYMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCEzlry8g+7uJI4pHoKeQSO3D+cO3UlwOpda9Vf0mEwWr6RnynNj5kS
# PfbKyY5OzijZKfEsJJ9rjVTI1SVY1cgpVQuExFLMI75Xq4OHbfWJ77C/9ket0ss1
# iAlCAvYDJGQaGvI9DXQIpaUzBgkYCJu4clw2XjaQLMu2eHw2JRVIbP+2efrshx+H
# 689Nk2n0c0mN8usFfcP+8vkdbL+aLj3e8odZnNMK5DcbxK1nJyhtZ4SHri1c5Mgv
# KMxu436sekOVmObs8DIPkM6ltOrazYCxR4I+rfKdKtlSj6JCAUtC9NCu9PdNm1G7
# ezBduuVSQb1Ch0UBdxF/LSAydU+uYH5ZoYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIAZP2hb9mn7Q6HxPdMzTriy+OAYzd7OkmNF+k4+2lbLbAgZi1VDl
# wFwYEzIwMjIwODAxMDczNjUyLjA2OFowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjdCRjEt
# RTNFQS1CODA4MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGfK0U1FQguS10AAQAAAZ8wDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTIyWhcNMjMwMjI4MTkwNTIyWjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046N0JGMS1FM0VBLUI4MDgxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCk9Xl8TVGyiZAvzm8tB4fLP0znL883YDIG03js1/Wz
# CaICXDs0kXlJ39OUZweBFa/V8l27mlBjyLZDtTg3W8dQORDunfn7SzZEoFmlXaSY
# cQhyDMV5ghxi6lh8y3NV1TNHGYLzaoQmtBeuFSlEH9wp6rC/sRK7GPrOn17XAGzo
# +/yFy7DfWgIQ43X35ut20TShUeYDrs5GOVpHp7ouqQYRTpu+lAaCHfq8tr+LFqIy
# jpkvxxb3Hcx6Vjte0NPH6GnICT84PxWYK7eoa5AxbsTUqWQyiWtrGoyQyXP4yIKf
# TUYPtsTFCi14iuJNr3yRGjo4U1OHZU2yGmWeCrdccJgkby6k2N5AhRYvKHrePPh5
# oWHY01g8TckxV4h4iloqvaaYGh3HDPWPw4KoKyEy7QHGuZK1qAkheWiKX2qE0eNR
# WummCKPhdcF3dcViVI9aKXhty4zM76tsUjcdCtnG5VII6eU6dzcL6YFp0vMl7JPI
# 3y9Irx9sBEiVmSigM2TDZU4RUIbFItD60DJYzNH0rGu2Dv39P/0Owox37P3ZfvB5
# jAeg6B+SBSD0awi+f61JFrVc/UZ83W+5tgI/0xcLGWHBNdEibSF1NFfrV0KPCKfi
# 9iD2BkQgMYi02CY8E3us+UyYA4NFYcWJpjacBKABeDBdkY1BPfGgzskaKhIGhdox
# 9QIDAQABo4IBNjCCATIwHQYDVR0OBBYEFGI08tUeExYrSA4u6N/ZasfWHchhMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAB2KKCk8O+kZ8+m9bPXQIAmo+6xbKDaKkMR3/82A8XVAMa9RpItYJkdkta+C
# 6ZIVBsZEARJkKnWpYJiiyGBV3PmPoIMP5zFbr0BYLMolDJZMtH3MifVBD9NknYNK
# g+GbWyaAPs8VZ6UD3CRzjoVZ2PbHRH+UOl2Yc/cm1IR3BlvjlcNwykpzBGUndARe
# fuzjfRSfB+dBzmlFY+dME8+J3OvveMraIcznSrlr46GXMoWGJt0hBJNf4G5JZqyX
# e8n8z2yR5poL2uiMRzqIXX1rwCIXhcLPFgSKN/vJxrxHiF9ByViouf4jCcD8O2mO
# 94toCSqLERuodSe9dQ7qrKVBonDoYWAx+W0XGAX2qaoZmqEun7Qb8hnyNyVrJ2C2
# fZwAY2yiX3ZMgLGUrpDRoJWdP+tc5SS6KZ1fwyhL/KAgjiNPvUBiu7PF4LHx5TRF
# U7HZXvgpZDn5xktkXZidA4S26NZsMSygx0R1nXV3ybY3JdlNfRETt6SIfQdCxRX5
# YUbI5NdvuVMiy5oB3blfhPgNJyo0qdmkHKE2pN4c8iw9SrajnWcM0bUExrDkNqcw
# aq11Dzwc0lDGX14gnjGRbghl6HLsD7jxx0+buzJHKZPzGdTLMFKoSdJeV4pU/t3d
# PbdU21HS60Ex2Ip2TdGfgtS9POzVaTA4UucuklbjZkQihfg2MIIHcTCCBVmgAwIB
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
# IEVTTjo3QkYxLUUzRUEtQjgwODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAdF2umB/yywxFLFTC8rJ9Fv9c9reg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRmxgwIhgPMjAyMjA4MDEwODIxNDRaGA8yMDIyMDgwMjA4MjE0NFow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pGbGAIBADAKAgEAAgIbQwIB/zAHAgEA
# AgIRqjAKAgUA5pLsmAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAEg80CEF
# JzLl8HeAJ/hZbnWQNsuIwu49g6NyKJi5qDBmnp/p+lUYWLzptwQ8IZws+2i1BWTq
# rded+t2dg1o3aCvWO7+8zpJUL+MYbToFai4eHsm4gREbd8MJ20XBPG8dyFA9AHGL
# CNzy86mPSsSureH5EZOyVbA1/999a8cmYWEOMYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGfK0U1FQguS10AAQAAAZ8wDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgurrJsZow265JW9koEwb+xuu1tcZi4eFH20E8hoE3Pp4wgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCG8V4poieJnqXnVzwNUejeKgLJfEH7
# P+jspyw3S3xc2jCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABnytFNRUILktdAAEAAAGfMCIEIOlIiYcAkE7hdl0Wdg0v2Y1xxRsJuCeW
# RwNv6bySR2rrMA0GCSqGSIb3DQEBCwUABIICADxz4EjAPB4FZ+0iFCZ8s0odPtyE
# Slr39v6FnISlWzc5cjwB+etCsIm6z21O0BQSJBOpwXDUdIHtW/YvWY2qR0Yb3S0J
# CUkRuqlSyQQK1VnlzA/utDJVhU13zZ3LS+dwSR6ldXyFMcAzZUZi6lsg6csQ4iX4
# ftyzRbndf9sxPHuZHkyLSEXmHrCBIe5X3v5LqDqBR+rhkeWZQuFloNx89vfjbuWQ
# Ts/hVvgPRcXYMw22FBNi36DQF5rkidBpIDZl9TKgttqgQYx3NZW6AlNRLz0rscqK
# amW7IHSew6G/KZfSzRLeWH1D4dBZeYDt28IVE+SJBNVA5VOZqO+Jphqa2Fj45JQV
# x/CW1GUOB4DAKNOUY5edUAurlyAosEkXlWB88uaC5x7zUFHneQiMc/NQFq8MmTfk
# zX03UxUzIu3wnf6Xoi1Ln8m4Qx8ehxKTbvR8MMK9AC7iZp2GUSOwyKo7bNyXMYTU
# VX5bpz2HW9Mm7qr0+L0Hhc+MEsY6wMv/0EOs8RRaRpl0qyyYUVSs0PJTNrOKhTWN
# fbz4ZzFGns5Sa1kLJvVf0KT+mnFu/4kC5sLiU5org52NiPI5Usa09T8tKLnU5qQN
# w336wWOfKV/2yDUrnUEfPI+yHixZFqasrHsWY9OmCdUC1g4xWmeDftZLyvtkngPv
# WLyvGDQ++BtbZgBk
# SIG # End signature block
