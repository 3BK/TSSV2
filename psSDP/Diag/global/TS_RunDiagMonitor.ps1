# $ConfigXMLPath = $Path ### Do not remove this param line

# 2023-02-20 WalterE mod Trap #we#
trap [Exception]{
	WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; continue
	Write-Host "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_"
}

Function Run-StopActions ([xml] $ConfigXML){
	$DiagPath = $ConfigXML.Root.DiagnosticPath
	$ScriptBlockToRun = $ConfigXML.Root.ScriptBlock
	$SelectArray = @()
	foreach ($PIDToMonitorNode in $ConfigXML.Root.ProcessesToMonitor.SelectNodes("PID")){
		$PIDToMonitor = $PIDToMonitorNode.get_InnerText()
		$ProcessInfo = Get-Process | Where-Object {$_.ID -eq $PIDToMonitor}
		if ($null -ne $ProcessInfo){
			"[MonitorDiagnosticExecution]    - Configuring to terminate process ID $PIDToMonitor [$($ProcessInfo.Name)]" | WriteTo-StdOut -ShortFormat
			$SelectArray += '($_.Id -eq ' + $PIDToMonitor + ') '
		}else{
			"[MonitorDiagnosticExecution]    - Will not terminate process ID $PIDToMonitor as it is not running" | WriteTo-StdOut -ShortFormat
		}
	}
	foreach ($ProcessNameToMonitorNode in $ConfigXML.Root.ProcessesToMonitor.SelectNodes("ProcessName")){
		$ProcessNameToMonitor = $ProcessNameToMonitorNode.get_InnerText()
		"[MonitorDiagnosticExecution]    - Configuring to terminate process [$ProcessNameToMonitor]" | WriteTo-StdOut -ShortFormat
		$SelectArray += '($_.ProcessName -eq ' + "'" + $ProcessNameToMonitor + "'" + ') '
	}
	foreach ($ProcessPathToMonitorNode in $ConfigXML.Root.ProcessesToMonitor.SelectNodes("ProcessPath")){
		$ProcessPathToMonitor = $ProcessPathToMonitorNode.get_InnerText()
		"[MonitorDiagnosticExecution]    - Configuring to terminate process [$ProcessPathToMonitor]" | WriteTo-StdOut -ShortFormat
		$SelectArray += '($_.Path -eq ' + "'" + $ProcessPathToMonitor + "'" + ') '
	}
	if (-not [string]::IsNullOrEmpty($ScriptBlockToRun)){
		if ($ScriptBlockToRun.Length -gt 300){
			$Length = 300
			$Continue = "..."
		}else{
			$Length = $ScriptBlockToRun.Length - 1
			$Continue= ''
		}
		"[MonitorDiagnosticExecution]    - Configuring to run the following Script Block (300 first chars):`n`r`n`r" + ($ScriptBlockToRun.Remove($Length)) + "$Continue`n`r" + ("-" * 40) | WriteTo-StdOut -ShortFormat
	}
	if (($SelectArray.Count -gt 0) -or (-not [string]::IsNullOrEmpty($ScriptBlockToRun))){
		if ($SelectArray.Count -gt 0){
			$ProcessToMonitorScriptBlock = ConvertTo-ScriptBlock -string ([string]::Join(' -or ', $SelectArray))
			$ProcessesToTerminate = Get-Process | Where-Object -FilterScript $ProcessToMonitorScriptBlock
			if ($null -ne $ProcessesToTerminate){
				$ProcessesToTerminate | ForEach-Object -Process {
					$ProcessName = $_.Name
					$ProcessId = $_.Id
					$ProcessStartTime = $_.StartTime
					$RunTimeDisplay = ''
					if ($null -ne $ProcessStartTime){
						$RunTimeDisplay = "[Running for " + (getagedescription -TimeSpan (New-TimeSpan $ProcessStartTime)) +"]"
					}
 					"[MonitorDiagnosticExecution]    -> Terminating process $ProcessId ($ProcessName) $RunTimeDisplay" | WriteTo-StdOut -ShortFormat
					if ($ProcessId -ne $PID){
						if ($_.HasExited -eq $false){
							$_ | Stop-Process -Force
						}
						# "Checking state again..."
						$ElapsedSeconds = 0
						while (($_.HasExited -eq $false) -and ($ElapsedSeconds -lt 5)){
							Start-Sleep -Seconds 1
							$ElapsedSeconds++
						}
						if ($_.HasExited -eq $false){
							"[MonitorDiagnosticExecution]    ERROR: $ProcessId ($ProcessName) did not stop after 5 seconds." | WriteTo-StdOut -ShortFormat -IsError
							$ProcessWMI = (Get-CimInstance -Class Win32_Process -Filter "ProcessId = $ProcessId")
							if ($null -ne $ProcessWMI){
								$Return = $ProcessWMI.Terminate()
								if ($Return.ReturnValue -ne 0){
									"[MonitorDiagnosticExecution]    ERROR (2): Tried to terminate process $ProcessId ($ProcessName) via WMI but it failed with error $($Return.ReturnValue)" | WriteTo-StdOut -ShortFormat -IsError
								}else{
									"[MonitorDiagnosticExecution]    Process $ProcessId ($ProcessName) terminated via WMI successfully!" | WriteTo-StdOut -ShortFormat -IsError
								}
							}
						}
					}else{
						"[MonitorDiagnosticExecution]    Process $ProcessId ($ProcessName) will not be terminated since it is the current process!" | WriteTo-StdOut -ShortFormat
					}
				}
			}else{
				"[MonitorDiagnosticExecution]    No process found to terminate" | WriteTo-StdOut -ShortFormat
			}
		}
		if (-not [string]::IsNullOrEmpty($ScriptBlockToRun)){
			trap [Exception]{
				"[MonitorDiagnosticExecution] An error has occurred while running the script block:`r`n`r`n$ScriptBlockToRun`r`n`r`n---------------------------------`r`n`r`n" + ($_ | Out-String) | WriteTo-StdOut -ShortFormat -IsError
				continue
			}
			"[MonitorDiagnosticExecution]    - Starting script block execution." | WriteTo-StdOut -ShortFormat
			Invoke-Expression $ScriptBlockToRun
		}
		"[MonitorDiagnosticExecution]    - Done running stop actions." | WriteTo-StdOut -ShortFormat
	}else{
		"[MonitorDiagnosticExecution]    ERROR: There are no actions configured to run on diagnostic termination" | WriteTo-StdOut -ShortFormat -IsError
	}
	"[MonitorDiagnosticExecution]    Diagnostic Monitoring Finished." | WriteTo-StdOut -ShortFormat
}

Function Start-Monitoring ([xml] $ConfigXML){
	$DiagProcessId = $ConfigXML.Root.ParentProcessID
	$DiagPath = $ConfigXML.Root.DiagnosticPath
	$ScriptBlockToRun = $ConfigXML.Root.ScriptBlock
	$SessionName = $ConfigXML.Root.SessionName
	
	$NumberOfProcessesToMonitor = $ConfigXML.Root.SelectNodes("ProcessesToMonitor").Count
	
	$FileFlagStop = Join-Path $DiagPath "..\StopMonitoring_$($SessionName)."
	
	$StartedFlagFileName = Join-Path $DiagPath "..\MonitorStarted_$($SessionName)."
	"[MonitorDiagnosticExecution] Starting to Monitor Session $SessionName [" + (Split-Path $StartedFlagFileName -Leaf) + "]" | WriteTo-StdOut -ShortFormat 
	#"Creating $StartedFlagFileName" | WriteTo-StdOut -ShortFormat 
	(Get-Date).ToString() | Out-File -filepath $StartedFlagFileName
	
	if (($NumberOfProcessesToMonitor -gt 0) -or (-not [string]::IsNullOrEmpty($ScriptBlockToRun))){
		$ParentProcess = Get-Process | Where-Object {$_.ID -eq $DiagProcessId}
		$StopMonitoring = $false
		$ExitSucessfully = $false
		if ($null -ne $ParentProcess){
			"[MonitorDiagnosticExecution] Monitoring parent diagnostic process $($DiagProcessId) [$($ParentProcess.Name)] [Session: $SessionName]" | WriteTo-StdOut -ShortFormat
		}else{
			"[MonitorDiagnosticExecution] Parent diagnostic process $($DiagProcessId) has exited" | WriteTo-StdOut -ShortFormat
		}
		do{
			if (-not (Test-Path $FileFlagStop)){
				if (($null -eq $ParentProcess) -or ($ParentProcess.HasExited)){
					"[MonitorDiagnosticExecution] Diagnostic process $($DiagProcessId) has exited. Running Stop Actions: " | WriteTo-StdOut -ShortFormat
					Run-StopActions -ConfigXML $ConfigXML
					$StopMonitoring = $true
				}else{
					Start-Sleep 4
				}
			}else{
				$StopMonitoring = $true
				$ExitSucessfully = $true
				[IO.File]::Delete($FileFlagStop)
				"[MonitorDiagnosticExecution] Received command to stop monitoring diagnostic process $($DiagProcessId) [Session: $SessionName]" | WriteTo-StdOut -ShortFormat
			}
		} while ($StopMonitoring -eq $false)
		"[MonitorDiagnosticExecution] Ending Monitoring Session for [$SessionName]" | WriteTo-StdOut -ShortFormat
	}else{
		"   [MonitorDiagnosticExecution] ERROR: There are no actions configured to run on diagnostic termination [Session: $SessionName]" | WriteTo-StdOut -ShortFormat -IsError
	}
}

function ConvertTo-ScriptBlock{
   param ([string]$string)
   [scriptblock] $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock($string)
   Return $ScriptBlock 
}

#region: MAIN :::::
if (-not [string]::IsNullOrEmpty($ConfigXMLPath)){
	if (Test-Path $ConfigXMLPath){
		[xml] $ConfigXML = Get-Content $ConfigXMLPath -ErrorAction SilentlyContinue
		
		if ($null -ne $ConfigXML.Root){
			$DiagPath = $ConfigXML.Root.DiagnosticPath
			
			if (Test-Path $DiagPath){
				$Utils_CTSPath = Join-Path $DiagPath 'utils_cts.ps1'
				if (Test-Path  $Utils_CTSPath){
					#Load Utils_CTS
					$Utils_CTSContent = Get-Content $Utils_CTSPath -ErrorAction SilentlyContinue | Out-String
					Invoke-Expression $Utils_CTSContent
					#Replace Utils_CTS StdOutFileName:
					$global:StdOutFileName = Join-Path -Path ($DiagPath) -ChildPath "..\stdout.log"
					Start-Monitoring -ConfigXML $ConfigXML
				}else{
					"[MonitorDiagnosticExecution] Warning: Utils_CTS.ps1 [$Utils_CTSPath] cannot be found. Diagnostic Package have been terminated." | Out-Host
				}
			}else{
				"[MonitorDiagnosticExecution] Warning: Diagnostic Path [$DiagPath] cannot be found. It may have been terminated." | Out-Host
			}
		}else{
			"[MonitorDiagnosticExecution] Error: [$ConfigXMLPath] could not be open" | Out-Host
		}
	}else{
		"[MonitorDiagnosticExecution] Error: [$ConfigXMLPath] could not be found" | Out-Host
	}
}else{
	"[MonitorDiagnosticExecution] Error: $ConfigXMLPath could not be found" | Out-Host
}
#endregion: MAIN :::::


# SIG # Begin signature block
# MIInlAYJKoZIhvcNAQcCoIInhTCCJ4ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAL9uJqs4B2S+Ub
# Gwa3qB/ay1Zk20R9XL87G0iB2YjPTaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJY+CQkMyHhzQpfChNIQ4ByG
# v9x3XxgxYj1nAos0oFBEMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAE8Ui0cmOxmWcgCQOi7Awi4dtY+0XrDCMDM1zPPU0vbW+Pd+eq7lt0
# lueXSIGIl9ko6W+PLxoAPcPHee2epeMwnoVywLtwSpQces8KYqyjfalEVegysMNQ
# YgcA9uCqR2UyIx8yjM0EmnxT64jPA5I8YHpXaEEPxe/KiMBQ4zc5GBOCNxjeekZt
# hOtWcOBLu/uCm1JN8wiMoj6U6lIDOvgkICj+7JZJ6FsU3gCqs6Ul7XUPbUx+GGsZ
# e7etv/NcATdqBePqC2GjChkQrDJ6uq392g/EmrYr+LUeGdqqwNHnkRQWKZJHnUNi
# NB6wbPcsLQ5e8njw/mzBFl08cMEqMPsvoYIW/DCCFvgGCisGAQQBgjcDAwExghbo
# MIIW5AYJKoZIhvcNAQcCoIIW1TCCFtECAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEINrxRr4ISRnMhDEaBqShHzSuugwwGerH2WANfeGb33w+AgZj7j3V
# vZAYEzIwMjMwMjIwMTUxMDA0LjU2NVowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNFN0Et
# RTM1OS1BMjVEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRUzCCBwwwggT0oAMCAQICEzMAAAHJ+tWOJSB0Al4AAQAAAckwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkw
# MTM4WhcNMjQwMjAyMTkwMTM4WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0U3QS1FMzU5LUEyNUQxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDWcuLljm/Pwr5ajGGTuoZb+8LGLl65MzTVOIRsU4by
# DtIUHRUyNiCjpOJHOA5D4I3nc4E4qXIwdbNEvjG9pLTdmUiB60ggtiIBKiCwS2WP
# MSVEc7t8MYMVZx3P6UI1iYmjO1sbc8yufFuVQcdSSvgLsQEdvZjTsZ3kYkGA/z7k
# Bk2xOWwcZzMezjmaY/utSBwyf/9zxD8ZhKp1Pg5cQunneH30SfIXjNyx3ZkWPF2P
# WU/xAbBllLgXzYkEZ7akKtJqTIWNPHMUpQ7BxB6vAFH9hpCXLua0Ktrg81zIRCb6
# f8sNx79VWJBrw4zacFkcrDoLIyoTMUknLkeLPPxnrGuqosq2Ly+IlRDQW2qRNdJH
# f//Dw8ArIGW8hhMUX8vLcmHdxtV46BKa5s5XC/ycx6FxBvYC3FxT+V3IRSrLz+2E
# QchY1pvMdfHk70Phu1Lqgl2AuYfGtMG0axxVCrHTPn99QiQsTu1vB+irzhwX9REs
# TLDernspXZTiA6FzfnpdgRVB0lejpUVYFANhvNqdDbnNjbVQKSPzbULIP3SCqs7e
# tA+VxCjp6vBbYMXZ+yaABtWrNCzPpGSZp/Pit7XuSbup7T0+7AfDl7fHlkgYShWV
# 82cm/r7znW7ApfoClkXE/N5Cjtb/kG1pOaRkSHBjkB0I+A+/RpogRCfaoXsy8XAJ
# ywIDAQABo4IBNjCCATIwHQYDVR0OBBYEFAVvnWdGwjyhvng6FMV5UXtELjLLMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBADaoupxm30eKQgdyPsCWceGOi7FKM54FpMT4QrxpdxUub1wDwPb9ljY5Sli8
# 52G4MRX2ESVWbOimIm6T/EFiHp1YlNGGZLuFWOsa2rNIVbQt9+xHKyPGSm6rKEeI
# EPExcwZnoZ3NR+pU/Zl3Y74n8FhAmCz00djP8IzhdpE/5PZUzckTWZI7Wotr6Z8H
# jbtCIuP8kLtNRiCHhFj6gswVW5Alm9diX+MhMV9SmkmgBqQGvRVzavWQ/kOIlo29
# lYn9y5hqJZDiT3GnDrAbPeqrvEBaeUbOxrDAWGO3CrkQf+zfssJ96HK4LDxlEn1b
# e2BIV6kBUzuxQT4+vdS76I+8FXhOxMM0UvQJUg9f7Vc4nphEZgnaQcamgZz/myAD
# YgpByX3tkNgkiqLGDAo1+3I3vQ7QBNulNWGxs3TUVWWLQf6+BwaHLOTqOkDLAc8N
# JD/GgR4ZTj7o8VNcxE798zMZxRx/RkepkybRSGgfy062TXyToHvkoldO1jdkzulN
# +6tK/ZCu/nPMIGLLKy04/D8gkj6T2ilOBq2sLf0vr38rDK0PTHu3SOZNe2Utloa+
# hKWN3LKvpANFWSqwJotRJKwCJZ5q/mqDrhTeYuZ56SjQT1MnnLO03+NyLOUfHRey
# A643qy5vcI9XsAAwyIqil1BiqI9e70jG+pdPsIT9IwLalw3JMIIHcTCCBVmgAwIB
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
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAsowggIzAgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjozRTdBLUUzNTktQTI1RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAfemLy/4eAZuNVCzgbfp1HFYG3Q6g
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOeeAbEwIhgPMjAyMzAyMjAyMjI2NTdaGA8yMDIzMDIyMTIyMjY1N1ow
# czA5BgorBgEEAYRZCgQBMSswKTAKAgUA554BsQIBADAGAgEAAgEXMAcCAQACAhJh
# MAoCBQDnn1MxAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAI
# AgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAtVCRA9VTQkLF
# PsUSSH9QQYriXNmOe7wI/cRd1QOfNEN3+nVc7ZG41rIerX4zfvfkV+ZeFG/dkgSZ
# YaPX7xVqtVd2/9pcHP6E1yJg/ok0mffWf4VsvLZofAxYdwqvPcXHEtCFXhoXwico
# ancM34JvsfgppoNJeeMMD9ALN3S22/wxggQNMIIECQIBATCBkzB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAcn61Y4lIHQCXgABAAAByTANBglghkgB
# ZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3
# DQEJBDEiBCCyFMoerU25f0MmkvPQCVoM47ARmRbR6T7EsYWA2ITSBzCB+gYLKoZI
# hvcNAQkQAi8xgeowgecwgeQwgb0EIIF1zn9S3VFLECd4Kdh/YA0jIYkA/8194V18
# 4dk5dv2BMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAHJ+tWOJSB0Al4AAQAAAckwIgQgY6PUruMoxOu9Usb43fIQWMNnSHJB3d9COTSX
# ykejK7MwDQYJKoZIhvcNAQELBQAEggIA1Vcg/JMb1fpJshEWinzuhrXiaXYO+LrI
# 7dEQOfBaW8FGprTRvdePQ3JFRbvBCZYkRTxmdqbEAEIpVqndZXUmpDgBeG3gZcBe
# XJOueSqC1akQRIJqDE1veQabfuhVjY3xJiLxkV9sP0w1eQU45ZISsMt8qQ0UWbA2
# KKMegQ6powEAFGwdj4OEdkDDcQP6FD1a6CpcvOl5XqymHXIPYkDNC/gWEs91Fiq+
# DoGQAAUupkIm0gdllbRguRL+XBvApkH9ko0lZE8uqA1Bst/5iI7TKAZ2k1t+QnCR
# 37MNuvFJXuH9MY6eok4N5mcfA01BneJK/cpUSfQCZn00/r+ozwThAoAK6NFXH/D7
# 03zHaxxXJEg+G6kMijh7neV2GGqu5nhOpTpxVV8t4PeifM4AJNtwtfqp/PDZjflB
# VEzMt+1CtmngU1ns63NEcLsw5crDnOvoaidj9E+tU39JF2zogR/hhjLaqyM/kr36
# d4I8CWn8ybZSWGxln4lFIjTS2BdAY5a6vk0VK9HSWjrqfMeRKjIjxMKGLMm8HIbA
# VPcZ6T0u8p8G3e7xbmYNhrL8PZhB3HYW9+wZrVCoVczmvcJm3ou8oR15oVRnL/Xz
# 0C7EZUJXwy8wOrfApSfdnUaSupgkGQ0PV2+mnLbZpYo57OHrPjmCfQngREegSIZY
# 8w6iWgvrQ4c=
# SIG # End signature block
