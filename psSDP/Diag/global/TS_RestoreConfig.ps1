trap [Exception] 
{
	"TS_RestoreConfig Error : $_" | WriteTo-StdOut -ShortFormat
	$Error.Clear()
	continue
}

Function CreateWMIProcess($MachineName, $ProcessAndArguments, $CurrentFolder)
{
	trap [Exception] 
	{
		"TS_RestoreConfig [CreateWMIProcess] Error creating process on $MachineName. Process: $ProcessAndArguments Error :$_" | WriteTo-StdOut -ShortFormat
		continue
	}
	$Error.Clear()
	
	$SW_HIDE = 0

	$Startup = ([wmiclass]"Win32_ProcessStartup").CreateInstance()
	$Startup.ShowWindow = $SW_HIDE
	
	#Running PowerShell 1.0
	if ($Host.Version.Major -lt 2) 
	{
		$ManagementPath = New-Object System.Management.ManagementPath
		$ManagementPath.Classname = "Win32_Process"
		$ManagementPath.NamespacePath = 'root/cimv2'
		$ManagementPath.Server = $MachineName
		
		$ManagementScope = New-Object System.Management.ManagementScope
		$ManagementScope.Options.EnablePrivileges = $true
		$ManagementScope.Path = $ManagementPath
		
		$ManagementClass = New-Object System.Management.ManagementClass `
 				$ManagementScope,$ManagementPath,(New-Object System.Management.ObjectGetOptions)
		$Results = $ManagementClass.Create($ProcessAndArguments, $CurrentFolder, $Startup)
	} 
	else
	{
		$Results = (Get-CimInstance -List -Computer $MachineName -class "Win32_Process" -EnableAllPrivileges).Create($ProcessAndArguments, $CurrentFolder, $Startup)
	}
	
	if ($Results.ReturnValue -ne 0)
	{
		switch ($result.ReturnValue) 
		{
			2 {$ProcessCreateErrorDesc = "Access Denied."} 
			3 {$ProcessCreateErrorDesc = "Insufficient Privileges."} 
			8 {$ProcessCreateErrorDesc = "Unknown failure."} 
			9 {$ProcessCreateErrorDesc = "Path Not Found."} 
			21 {$ProcessCreateErrorDesc = "Invalid Parameter."} 
			default {$ProcessCreateErrorDesc = "Error " + $Results.ReturnValue}
		}

		"[WMIProcessCreate] Error running '" + $ProcessAndArguments + "' on machine " + $MachineName + " - Process Create Error: " + $ProcessCreateErrorDesc | WriteTo-StdOut
		return 0
	} else {
		"[WMIProcessCreate] '" + $ProcessAndArguments + "' started on " + $MachineName + " with process ID: " + $Results.ProcessId | WriteTo-StdOut -ShortFormat
		Return $Results.ProcessId
	}		
}

Function RunRemoteComputerProcess($MachineName, $ProcessNameAndArguments, $RemoteOutputFolder, $LocalOutputFolder, [string] $LocalCurrentFolder = "", [switch] $Asynchronous, [switch] $DirectExecution)
{
	trap [Exception] 
	{
		"TS_RestoreConfig Error [RunRemoteComputerProcess] Machine: $MachineName - [$ProcessNameAndArguments] Error : $_" | WriteTo-StdOut -ShortFormat
		continue
	}

	$RemoteStdOut = $RemoteOutputFolder + "\RemoteStdout.out"
	$LocalStdOut = $LocalOutputFolder + "\RemoteStdout.out"
	
	if ($DirectExecution.IsPresent)
	{
		$ProcessNameAndArguments = $ProcessNameAndArguments
	} else {
		$ProcessNameAndArguments = "cmd.exe /c " + $ProcessNameAndArguments + " > `"$LocalStdOut`""
	}

	#"Starting on " + $MachineName + ": '" + $ProcessNameAndArguments + "'" | WriteTo-StdOut -ShortFormat
	
	if ($LocalCurrentFolder -eq "") {$LocalCurrentFolder = $LocalOutputFolder}
	
	$RemoteProcessID = CreateWMIProcess -MachineName $MachineName -ProcessAndArguments $ProcessNameAndArguments -CurrentFolder $LocalCurrentFolder
	if ($RemoteProcessID -ne 0)
	{
		if (-not ($Asynchronous.IsPresent)) 
		{
			#Wait until it ends
			do {
				$RemoteProcessInstance = Get-Process -ComputerName $MachineName -Id $RemoteProcessID -ErrorAction SilentlyContinue
				Start-Sleep -Milliseconds 500
			} while ($null -ne $RemoteProcessInstance)
			
			if (-not $DirectExecution.IsPresent)
			{
				if (Test-Path ($RemoteStdOut))
				{
					"Stdout output for PowerShell Diagnostic execution: " + $RemoteStdOut + ": " | WriteTo-StdOut -ShortFormat
					$StdoutContent = (Get-Content -Path $RemoteStdOut -Encoding UTF8)
					if ($null -ne $StdoutContent) {[String]::Join("`r`n    | ", $StdoutContent) | WriteTo-StdOut}
					Remove-Item $RemoteStdOut -ErrorAction SilentlyContinue
					return $RemoteStdOut
				} else {
					"`r`nWarning: unable to open : $RemoteStdOut" | WriteTo-StdOut -ShortFormat
				}
			}
		}
		else 
		{
			#When running in $Asynchronous mode - return the process ID instead of the stdout file name
			return $RemoteProcessID
		}
	} 
	else 
	{
		return 0
	}
}

Function RestoreComputerReg($MachineName, $LocalOutputFolder, $RemoteOutputFolder)
{
	trap [Exception] 
	{
		"TS_RestoreConfig Error [RestoreComputerReg] Machine: $MachineName - [Restore Excution Policy] Error : $_" | WriteTo-StdOut -ShortFormat
		continue
	}

	$HKLM = 2147483650
	$SkipPSExecutionPolicy = @('Unrestricted', 'Bypass')
	$RemoteReg = Get-CimInstance -List -Computer $MachineName -Namespace "root\DEFAULT" | Where-Object {$_.Name -eq 'StdRegProv'}
	$CurrentExecutionPolicy = ($RemoteReg.GetStringValue($HKLM,"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell","ExecutionPolicy")).sValue
	$PreviousExecutionPolicy = ($RemoteReg.GetStringValue($HKLM,"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell","PreviousExecutionPolicy")).sValue
	$RemotePowerShellPath = ($RemoteReg.GetStringValue($HKLM,"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell","Path")).sValue

	if ($SkipPSExecutionPolicy -notcontains $CurrentExecutionPolicy)
	{
		if ([string]::IsNullOrEmpty($PreviousExecutionPolicy))
		{
			"[ExecutionPolicy] Previous PowerShell Execution Policy on " + $MachineName + ": (Not Defined)" | WriteTo-StdOut -ShortFormat
		} 
		else 
		{
			"[ExecutionPolicy] Previous PowerShell Execution Policy on " + $MachineName + ": $PreviousExecutionPolicy" | WriteTo-StdOut -ShortFormat
		}

		if (($RemotePowerShellPath -match "SysWow64")) #This machine is a 32-bit machine and remote machine is a 64-bit machine. In this case, use reg.exe instead
		{
			"[ExecutionPolicy] Machine $MachineName is 64-bit, while current process is a 32-bit process. Restoring PowerShell Execution Policy via WMI/reg.exe" | WriteTo-StdOut -ShortFormat
			if ($null -ne $PreviousExecutionPolicy)
			{
				$ProcessID = RunRemoteComputerProcess -ProcessNameAndArguments "reg.exe add HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy /d $PreviousExecutionPolicy /f" -LocalCurrentFolder $LocalOutputFolder -RemoteOutputFolder $RemoteOutputFolder -LocalOutputFolder $LocalOutputFolder -MachineName $MachineName
				$ProcessID = RunRemoteComputerProcess -ProcessNameAndArguments "reg.exe add HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy /d $PreviousExecutionPolicy /f" -LocalCurrentFolder $LocalOutputFolder -RemoteOutputFolder $RemoteOutputFolder -LocalOutputFolder $LocalOutputFolder  -MachineName $MachineName
				$ProcessID = RunRemoteComputerProcess -ProcessNameAndArguments "reg.exe delete HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v PreviousExecutionPolicy /f" -LocalCurrentFolder $LocalOutputFolder -RemoteOutputFolder $RemoteOutputFolder -LocalOutputFolder $LocalOutputFolder  -MachineName $MachineName
				$ProcessID = RunRemoteComputerProcess -ProcessNameAndArguments "reg.exe delete HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v PreviousExecutionPolicy /f" -LocalCurrentFolder $LocalOutputFolder -RemoteOutputFolder $RemoteOutputFolder -LocalOutputFolder $LocalOutputFolder  -MachineName $MachineName
			} else {
				$ProcessID = RunRemoteComputerProcess -ProcessNameAndArguments "reg.exe delete HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy /f" -LocalCurrentFolder $LocalOutputFolder -RemoteOutputFolder $RemoteOutputFolder -LocalOutputFolder $LocalOutputFolder -MachineName $MachineName
				$ProcessID = RunRemoteComputerProcess -ProcessNameAndArguments "reg.exe delete HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy /f" -LocalCurrentFolder $LocalOutputFolder -RemoteOutputFolder $RemoteOutputFolder -LocalOutputFolder $LocalOutputFolder -MachineName $MachineName
			}
			
		} 
		else 
		{
			if (-not ([string]::IsNullOrEmpty($PreviousExecutionPolicy)))
			{
				if ($PreviousExecutionPolicy -ne 'RemoteSigned')
				{
					"[ExecutionPolicy] Restoring PowerShell Execution Policy on " + $MachineName + " from $CurrentExecutionPolicy to: $PreviousExecutionPolicy" | WriteTo-StdOut -ShortFormat
					$RemoteReg.SetStringValue($HKLM,"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy", "$PreviousExecutionPolicy")
					$RemoteReg.SetStringValue($HKLM,"SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy", "$PreviousExecutionPolicy")
				}
				else
				{
					"[ExecutionPolicy] Original PowerShell Execution Policy on " + $MachineName + " was already RemoteSigned" | WriteTo-StdOut -ShortFormat
				}
				$RemoteReg.DeleteValue($HKLM,"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "PreviousExecutionPolicy")
			}
			else 
			{
				"[ExecutionPolicy] Restoring PowerShell Execution Policy on " + $MachineName + " from $CurrentExecutionPolicy to: (Not Defined)" | WriteTo-StdOut -ShortFormat
				$RemoteReg.DeleteValue($HKLM,"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy")
			}
		}
	}
	else
	{
		"[ExecutionPolicy] PowerShell Execution Policy on " + $MachineName + " is currently set to [" + $CurrentExecutionPolicy + "] and will not be changed/restored" | WriteTo-StdOut -ShortFormat
		if (-not ([string]::IsNullOrEmpty($PreviousExecutionPolicy)))
		{
			$RemoteReg.DeleteValue($HKLM,"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "PreviousExecutionPolicy")
		}
	}
}

$RemoteMachineRunExpressionInfoPath = Join-Path $Env:TEMP "RemoteMachineRunExpressionInfo.tmp"
if(Test-Path -Path $RemoteMachineRunExpressionInfoPath)
{
	$ServerCoreSKUs = @(12,13,14,42)
	$ComputerName = $Env:computername
	# 1.Get MachineRunExpressionInfo from xml
	$RemoteMachineBuild = @{}
	$RemoteMachineWindowsFolder = @{}
	$RemoteMachineSystemFolder = @{}
	$RemoteMachineRemoteSetupPath = @{}
	$RemoteMachineLocalSetupPath = @{}
	$RemoteMachineProcessIdList = @{}
	$RemoteMachineOSArch= @{}
	$RemoteMachineSKU = @{}
	$RemoteMachineProductType = @{}
	$RemoteMachinePlatform = @{}
	$ComputerNameList = @()
	[xml]$RemoteMachineRunExpressionInfo = Get-Content $RemoteMachineRunExpressionInfoPath
	Remove-Item -Path $RemoteMachineRunExpressionInfoPath -Force -ErrorAction SilentlyContinue
	foreach($Machine in $RemoteMachineRunExpressionInfo.Root.Machine)
	{
		if(($null -ne $Machine) -and ($null -ne $Machine.OSBuildNumber))
		{
			$ComputerNameList += $Machine.Name
			$RemoteMachineBuild.Add($Machine.Name,$Machine.OSBuildNumber)
			$RemoteMachineWindowsFolder.Add($Machine.Name,$Machine.OSWindowsFolder)
			$RemoteMachineSystemFolder.Add($Machine.Name,$Machine.OSSystemFolder)
			$RemoteMachineRemoteSetupPath.Add($Machine.Name,$Machine.RemoteSetupPath)
			$RemoteMachineLocalSetupPath.Add($Machine.Name,$Machine.LocalSetupPath)
			
			if(($null -ne $Machine.ProcessIdList))
			{	
				$ProcessIdList = @()
				foreach($processid in $Machine.ProcessIdList.SelectNodes("ProcessId"))
				{
					if($processid.InnerText.Length -gt 0)
					{
						$ProcessIdList += $processid.InnerText
					}	
				}
				if($ProcessIdList.count -gt 0)
				{
					$RemoteMachineProcessIdList.Add($Machine.Name,$ProcessIdList)
				}
			}
			$RemoteMachineOSArch.Add($Machine.Name,$Machine.OSArch)
			$RemoteMachineSKU.Add($Machine.Name,$Machine.MachineSKU)
			$RemoteMachineProductType.Add($Machine.Name,$Machine.ProductType)
			$RemoteMachinePlatform.Add($Machine.Name,$Machine.OSPL)
		}
	}
	foreach($MachineName in $ComputerNameList)
	{
		$OSBuildNumber = $RemoteMachineBuild.get_Item($MachineName)
			
		$OSArch = $RemoteMachineOSArch.get_Item($MachineName)
		$OSPlat = $RemoteMachinePlatform.get_Item($MachineName)
		$ProductType =  $RemoteMachineProductType.get_Item($MachineName)
		
		# 2. Kill the Powershell process in remote computer
		if($RemoteMachineProcessIdList.ContainsKey($MachineName))
		{
			$ProcessIdListForTerminate = $RemoteMachineProcessIdList.Get_Item($MachineName)
			"Kill the processes $ProcessIdListForTerminate in remote machine $MachineName" | WriteTo-StdOut -ShortFormat
			foreach($ProcessId in $ProcessIdListForTerminate)
			{
				$Process = Get-CimInstance -Class win32_process -Filter ("ProcessId = '" + $ProcessId + "'") -ComputerName $MachineName
				if($null -ne $Process)
				{
					$KillProcessResult = $process.terminate()
					if(($null -eq $KillProcessResult) -or ($KillProcessResult.ReturnValue -ne 0))
					{
						"Can't kill the process $($Process.Name) in Machine $MachineName ,Process status is $($KillProcessResult.ReturnValue)" | WriteTo-StdOut -ShortFormat
					}
				}
			}
		}
			
		# 3.Remove files associated with session
		$LocalTempPath = $RemoteMachineWindowsFolder.Get_Item($MachineName) + "\TEMP"
		if ($MachineName -eq $ComputerName)
		{
			$RemoteTempPath = $LocalSetupPath
		} 
		else
		{
			$RemoteTempPath = "\\" + $MachineName + "\admin$\TEMP"
		}
		if (($OSBuildNumber -ge 2600) -and ($OSBuildNumber -lt 7000)) 
		{
			if ($ServerCoreSKUs -notcontains ($RemoteMachineSKU.Get_Item($MachineName)))
			{
				if (($OSBuildNumber -eq 3790) -or ($OSBuildNumber -eq 2600)) #If Windows Server 2003 or Windows XP
				{
					switch ($OSArch)
					{
						"64-bit"
						{
							If ($OSPlat -eq "IA64")
							{
								$PackageName = "NetFx20SP2_ia64.exe"
							
							} else {					
								$PackageName = "NetFx20SP2_x64.exe"
							}
						}
						"32-bit"
						{
							$PackageName = "NetFx20SP2_x86.exe"
						}
					}
					$PackageFilePath =$RemoteTempPath + "\" + $PackageName
					if (Test-Path -Path $PackageFilePath)
					{
						Remove-Item $PackageFilePath -Force -ErrorAction SilentlyContinue
						"Remove file $PackageFilePath" | WriteTo-StdOut -ShortFormat
					}
					$NetFrameworkInstallLog = $RemoteTempPath + "\NetFrameworkInstall.Log"
					if (Test-Path -Path $NetFrameworkInstallLog)
					{
						Remove-Item $NetFrameworkInstallLog -Force -ErrorAction SilentlyContinue
						"Remove file $NetFrameworkInstallLog" | WriteTo-StdOut -ShortFormat
					}
				}
		
				if ($OSBuildNumber -eq 2600) #Windows XP 32-bit
				{
					$PackageFilePath =$RemoteTempPath + "\" + $PackageName
					if (Test-Path -Path $PackageFilePath)
					{
						Remove-Item $PackageFilePath -Force -ErrorAction SilentlyContinue
						"Remove file $PackageFilePath" | WriteTo-StdOut -ShortFormat
					}
					$PSInstallLogFile = $RemoteTempPath + "\PSInstallLog.Log"
					if (Test-Path -Path $PSInstallLogFile)
					{
						Remove-Item $PSInstallLogFile -Force -ErrorAction SilentlyContinue
						"Remove file $PSInstallLogFile" | WriteTo-StdOut -ShortFormat
					}	
				}
		
				if ($OSBuildNumber -eq 3790) #Windows Server 2003/ XP x64
				{
					Switch ($OSArch)
					{
						"64-bit"
						{
							If ($OSPlat -eq "IA64")
							{
								$PackageName = "WindowsServer2003-KB926139-v2-ia64-ENU.exe"
							} else {
									$PackageName = "WindowsServer2003-KB968930-x64-ENG.exe"
								}
							}
						"32-bit"
						{
							$PackageName = "WindowsServer2003-KB968930-x86-ENG.exe"
						}
					}
					$PackageFilePath = $RemoteTempPath + "\" + $PackageName
					if (Test-Path -Path $PackageFilePath )
					{
						Remove-Item $PackageFilePath -Force -ErrorAction SilentlyContinue
						"Remove file $PackageFilePath" | WriteTo-StdOut -ShortFormat
					}
					$PSInstallLogFile = $RemoteTempPath + "\PSInstallLog.Log"
					if (Test-Path -Path $PSInstallLogFile)
					{
						Remove-Item $PSInstallLogFile -Force -ErrorAction SilentlyContinue
						"Remove file $PSInstallLogFile" | WriteTo-StdOut -ShortFormat
					}
				}
		
				if (($OSBuildNumber -ge 6000) -and ($OSBuildNumber -le 6999)) #Windows Vista or Server 2008
				{
					if ($ProductType -eq 1) #Workstation - Windows Vista
					{
						switch ($OSArch)
						{
							"64-bit" 
							{
								$PackageName = "Windows6.0-KB928439-x64"
								$MSUPackageName = "$PackageName.msu"
								$DestinationFolderName = $RemoteTempPath + "\" + $PackageName
							}
							"32-bit"
							{
								$PackageName = "Windows6.0-KB928439-x86"
								$MSUPackageName = "$PackageName.msu"
								$DestinationFolderName = $RemoteTempPath + "\" + $PackageName
							}
						}
						if (Test-Path -Path $DestinationFolderName)
						{
							Remove-Item $DestinationFolderName -Force -ErrorAction SilentlyContinue
							"Remove $DestinationFolderName" | WriteTo-StdOut -ShortFormat
						}
					}
				}
			}
		}
		
		$RemoteSetupPath = $RemoteMachineRemoteSetupPath.get_Item($MachineName)
		if (Test-Path -Path ($RemoteSetupPath))
		{
			Remove-Item -path ($RemoteSetupPath + "\..\*.*") -Force -Recurse -ErrorAction SilentlyContinue
			$FullRemoteSetupPath = ($RemoteSetupPath + "\..\")
			if(Test-Path $FullRemoteSetupPath)
			{
				$FullRemoteSetupPath = [System.IO.Path]::GetFullPath($FullRemoteSetupPath)
				Remove-Item -path $FullRemoteSetupPath -Force -Recurse -ErrorAction SilentlyContinue
				"Remove folder $FullRemoteSetupPath" | WriteTo-StdOut -ShortFormat
			}
		}		
		
		RestoreComputerReg -MachineName $MachineName -LocalOutputFolder $LocalTempPath -RemoteOutputFolder $RemoteTempPath
		
		$FlagFilePath = "$Env:temp\CTSDiagnostics.txt"
		if (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 0))
		{
			#Replace stdout.log to stdout-wtp.log so it won't conflict with SDP 2.x stdout.log file
			$StdOutFileName = Join-Path -Path ($PWD.Path) -ChildPath "..\stdout-wtp.log"
		}
		else
		{
			$StdOutFileName = "..\stdout.log"	
		}
		
		if(Test-Path $FlagFilePath)
		{
			Remove-Item -path $FlagFilePath -Force -ErrorAction SilentlyContinue
			"Remove folder $FlagFilePath" | WriteTo-StdOut -ShortFormat
		}
		if(Test-Path $StdOutFileName)
		{
			Remove-Item -path $StdOutFileName -Force -ErrorAction SilentlyContinue
			"Remove folder $StdOutFileName" | WriteTo-StdOut -ShortFormat
		}
		$RootCauseArgumentsXMLPath = [System.IO.Path]::GetFullPath("..\DiagnosticRootCauseArguments.xml")
		if(Test-Path $RootCauseArgumentsXMLPath)
		{
			Remove-Item -Path $RootCauseArgumentsXMLPath -Force  -ErrorAction SilentlyContinue
			"Remove folder $RootCauseArgumentsXMLPath" | WriteTo-StdOut -ShortFormat
		}
	}	
}	


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCOx1laa+a9e9xt
# 2bbiznZmOR4yAyAbitGy0lnFkoFslqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMuNUn6x/karOeNFBbrocIBf
# 8lDQBfbquIkygXp7s5ZRMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAkUgio5/Ym4rWWYvJARZq1ns1cRSHIcRKO8ggmcc8dFAAbvyP3sGwn
# 6shWNwaLOqq21vWFWltZPR4VwfBAg/jY1teAhq5h8C7Dm1R1sskG0jSrFpc8iCdE
# +cYoW69MeLW0X4scmALsV4J+ofIZjzx8KWnu0ZYeB3Ejost3yeQRF1VdeQRwmPQu
# RL86ZuCGpA9zuMWWVw24JxD57rtg+9/LjpnzxOuQwEOXL0Qec5TFGWZxfVyuvSjc
# SE83qbsfzvVtEZUm5KCyOhLdQGSRlRhKFBQKeuSE2SQSXTYyTcfJxKksvTnebF7r
# UC5rsvjMegKt+dH9h4YIaefsrHFSxS1/oYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIIMs/xzglHyuJl9GWMCBaAvxTuSBrC3GZV4k3yyvJ6BUAgZi3ohQ
# AfcYEzIwMjIwODAxMDgwNTQ2LjU1N1owBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RDA4Mi00QkZELUVFQkExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAY/zUajrWnLdzAABAAABjzAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDZaFw0yMzAxMjYxOTI3NDZaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQwODIt
# NEJGRC1FRUJBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmVc+/rXPFx6Fk4+CpLru
# bDrLTa3QuAHRVXuy+zsxXwkogkT0a+XWuBabwHyqj8RRiZQQvdvbOq5NRExOeHia
# CtkUsQ02ESAe9Cz+loBNtsfCq846u3otWHCJlqkvDrSr7mMBqwcRY7cfhAGfLvlp
# MSojoAnk7Rej+jcJnYxIeN34F3h9JwANY360oGYCIS7pLOosWV+bxug9uiTZYE/X
# clyYNF6XdzZ/zD/4U5pxT4MZQmzBGvDs+8cDdA/stZfj/ry+i0XUYNFPhuqc+UKk
# wm/XNHB+CDsGQl+ZS0GcbUUun4VPThHJm6mRAwL5y8zptWEIocbTeRSTmZnUa2iY
# H2EOBV7eCjx0Sdb6kLc1xdFRckDeQGR4J1yFyybuZsUP8x0dOsEEoLQuOhuKlDLQ
# Eg7D6ZxmZJnS8B03ewk/SpVLqsb66U2qyF4BwDt1uZkjEZ7finIoUgSz4B7fWLYI
# eO2OCYxIE0XvwsVop9PvTXTZtGPzzmHU753GarKyuM6oa/qaTzYvrAfUb7KYhvVQ
# KxGUPkL9+eKiM7G0qenJCFrXzZPwRWoccAR33PhNEuuzzKZFJ4DeaTCLg/8uK0Q4
# QjFRef5n4H+2KQIEibZ7zIeBX3jgsrICbzzSm0QX3SRVmZH//Aqp8YxkwcoI1WCB
# izv84z9eqwRBdQ4HYcNbQMMCAwEAAaOCATYwggEyMB0GA1UdDgQWBBTzBuZ0a65J
# zuKhzoWb25f7NyNxvDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQDNf9Oo9zyhC5n1jC8iU7NJY39FizjhxZwJbJY/
# Ytwn63plMlTSaBperan566fuRojGJSv3EwZs+RruOU2T/ZRDx4VHesLHtclE8GmM
# M1qTMaZPL8I2FrRmf5Oop4GqcxNdNECBClVZmn0KzFdPMqRa5/0R6CmgqJh0muvI
# mikgHubvohsavPEyyHQa94HD4/LNKd/YIaCKKPz9SA5fAa4phQ4Evz2auY9SUluI
# d5MK9H5cjWVwBxCvYAD+1CW9z7GshJlNjqBvWtKO6J0Aemfg6z28g7qc7G/tCtrl
# H4/y27y+stuwWXNvwdsSd1lvB4M63AuMl9Yp6au/XFknGzJPF6n/uWR6JhQvzh40
# ILgeThLmYhf8z+aDb4r2OBLG1P2B6aCTW2YQkt7TpUnzI0cKGr213CbKtGk/OOIH
# SsDOxasmeGJ+FiUJCiV15wh3aZT/VT/PkL9E4hDBAwGt49G88gSCO0x9jfdDZWdW
# GbELXlSmA3EP4eTYq7RrolY04G8fGtF0pzuZu43A29zaI9lIr5ulKRz8EoQHU6cu
# 0PxUw0B9H8cAkvQxaMumRZ/4fCbqNb4TcPkPcWOI24QYlvpbtT9p31flYElmc5wj
# GplAky/nkJcT0HZENXenxWtPvt4gcoqppeJPA3S/1D57KL3667epIr0yV290E2ot
# ZbAW8DCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
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
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDA4Mi00QkZELUVFQkExJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAD5NL4IEdudIBwdGoCaV0WBbQZpqoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmkZg6MCIYDzIwMjIwODAx
# MDgwOTMwWhgPMjAyMjA4MDIwODA5MzBaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaRmDoCAQAwBwIBAAICEbAwBwIBAAICEXEwCgIFAOaS6boCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQAhp8Aod4IrqWSzJRIvhdfsjjJ0NJWgA/ZOXoGxuTHB
# Nc+n4eD9raE8WV172xcQru+BQW4ecbLSElX8gQ88qDD0qPr3S/FY/5drB43kpsZb
# 3smIRpvR0AhUrfQV/szgrx7+5TBOZSinvdOPsft4KHAzsWahf7BfumsXJdtpt6+W
# nzGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABj/NRqOtact3MAAEAAAGPMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIGfZXbYbwt5UuVDtrQYY
# sN7A5Wo/fd3aJ9aJkxQ6zqtmMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# l3IFT+LGxguVjiKm22ItmO6dFDWW8nShu6O6g8yFxx8wgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY/zUajrWnLdzAABAAABjzAiBCDK
# yRgnJWWXshnmgygiJTZnJFpENKNV36rl3eKKIz0TKjANBgkqhkiG9w0BAQsFAASC
# AgB2ip/53b0bBJmxuYT1Fni5iArq7cyoNbvN9PtvNcnbfAzDbIVD1JcJeX4WlXx9
# Vc/J8l25EijVKMSaMdrD8LrlzZRxWvYgM9Z2jG38WYJjgWe1kfPONH+s+8NYvtQP
# zFmkf8/U4M60fFSj9rgKz7Ntqrp7AogO7dDYorkpIlsVmjaqqn+7CE8cGnTwf2U6
# Vbh21Xp3yLu4G0ZSak66Zdcy8VtcF1YCESQwyxcd2VNIlBqHGFYg9f1h+C95bXCE
# 1Tyx2dFU7tC+fQ5wj9nlGS7LmSajRO3lig3/R12JG7jf6n+7p31XG9Y5oL+5YV6H
# Nz4DDIsCe0n6jsBIVbyBhW2GqiIw+0JbdxA8PDWNe9Ex/u4yCLfbQy1BeL1H1cL8
# o3HG/e8mdXfmGYXdz5U3xgGvomabUfHLCQPOwSn3EpkHI+an3cXl1zFLIzq9KAs4
# hcB/fnODJugZ3e1cPGqM3nEFRkpzR6MwJDVnT5rjftjDMhYa/6bx0FNGHIPcm29n
# hln09coSOkFvCOi0FAuYsH50PFdpyu5HIFTCMf5v8TLHy/2/OUSFp+iWy7OdsRxT
# pfQeKRaRL9AOXKHhdxsCPHt/oy8uSUzorghwiI0HeJGO3wx04Gmq48XVXC/tFcQY
# LuJXAq7hLIKHhFGx9tzn8g+CDbPundzqNXMJumwm9GhlTw==
# SIG # End signature block
