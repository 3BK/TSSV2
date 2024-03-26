#************************************************
# TS_RemoteSetup
# Version 2.4.9
# Date: 02-16-2012
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script connects to one or more remote machines, install required components (PowerShell) and copy diagnostic to remote machine. After that, it executes any PowerShell script remotelly.
#************************************************

trap [Exception] 
{
	WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote Error")
	WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat
	$Error.Clear()
	continue
}


$Error.Clear()

Import-LocalizedData -BindingVariable RemoteSetupStrings

$MachineState=@{"Untouched"=0; "WMIConnected"=1; "PowerShellInstalled"=2; "PowershellExecutionPolicySet"=3; "BuiltRemoteEnvironment"=4; "RunningDiagnosticScript"=5; "FinishedRunningDiagnosticScript"=6; "DataCollected"=7; "ProcessingRootCauseScript"=8; "FinishedRootCauseScript"=9; "ErrorConnectingMachineWMI"=100; "UnsupportedOS"=99; "PowerShellNotInstalled"=98; "UserDeniedPowerShell"=97; "ErrorSettingExecutionPolicy"=96; "ErrorBuildingRemoteEnvironment"=95; "FailedRunningDiagnosticScript"=94; "ErrorProcessingRootCauseScript"=93; "UnableToAccessRemoteRegistry"=92}

Function SetExecutionPolicyOnRemoteSystem($MachineName, $LocalOutputFolder, $RemoteOutputFolder)
{
	#Set Execution Policy to 'RemoteSigned' on remote machine and return $true or $false for the operation. Also write registry key called PreviousExecutionPolicy containing the original Execution Policy

	Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteConfiguringMachine -replace("%Machine%", $MachineName)) -Status $RemoteSetupStrings.ID_TSRemoteConfiguringMachinePSPolicy

    trap 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote Error [SetExecutionPolicyOnRemoteSystem] - Machine Name: $MachineName")
    	get-diaginput -id "ErrorContacting" -Parameter @{"Machine"=$MachineName; "Error"=($RemoteSetupStrings.ID_TSRemoteErrorSettingPSPolicy + " " + $_.Exception.Message)}
		return $null
    }

	$ReturnValue = $false
	$SkipPSExecutionPolicy = @('Unrestricted', 'Bypass', 'RemoteSigned')

	$HKLM = 2147483650
	$RemoteReg = Get-CimInstance -List -Computer $MachineName -Namespace "root\DEFAULT" | Where-Object {$_.Name -eq 'StdRegProv'}
	
	$OriginalExecutionPolicyReg = ($RemoteReg.GetStringValue($HKLM,"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell","ExecutionPolicy"))
	if ($null -ne $OriginalExecutionPolicyReg)
	{
		$OriginalExecutionPolicy = $OriginalExecutionPolicyReg.sValue
	}
	else
	{
		"[ExecutionPolicy] [Warning] Unable to obtain the current PowerShell Execution Policy on " + $MachineName + "" | WriteTo-StdOut
	}
	
	$RemotePowerShellPathReg = ($RemoteReg.GetStringValue($HKLM,"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell","Path"))
	if ($null -ne $RemotePowerShellPathReg)
	{
		$RemotePowerShellPath = $RemotePowerShellPathReg.sValue
	}
	
	$PreviousExecutionPolicyReg = ($RemoteReg.GetStringValue($HKLM,"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell","PreviousExecutionPolicy"))
	if ($null -ne $PreviousExecutionPolicyReg)
	{
		$PreviousExecutionPolicy = $PreviousExecutionPolicyReg.sValue
	}
	
	if ([string]::IsNullOrEmpty($OriginalExecutionPolicy))
	{
		"[ExecutionPolicy] PowerShell Execution Policy on " + $MachineName + ": (Not Defined)" | WriteTo-StdOut -ShortFormat
	} 
	else 
	{
		"[ExecutionPolicy] Original PowerShell Execution Policy on " + $MachineName + ": " + $OriginalExecutionPolicy | WriteTo-StdOut -ShortFormat
		if ([string]::IsNullOrEmpty($PreviousExecutionPolicy))
		{
			$RemoteReg.SetStringValue($HKLM,"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "PreviousExecutionPolicy", $OriginalExecutionPolicy) | Out-Null
		} 
		else 
		{
			"[ExecutionPolicy] [Warning] A value for previous value for PreviousExecutionPolicy on " + $MachineName + " already exists and will not be changed" | WriteTo-StdOut -ShortFormat
			"                            (HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\PreviousExecutionPolicy) is currently set to: $PreviousExecutionPolicy" | WriteTo-StdOut -ShortFormat
		}
	}
	
	if ($SkipPSExecutionPolicy -notcontains $OriginalExecutionPolicy)
	{
		"[ExecutionPolicy] Setting PowerShell Execution Policy on " + $MachineName + " to: RemoteSigned" | WriteTo-StdOut -ShortFormat
		if ($RemotePowerShellPath -match "SysWow64") #This machine is a 32-bit machine and remote machine is a 64-bit machine. In this case, use reg.exe instead
		{
			"[ExecutionPolicy] Machine $MachineName is 64-bit, while current process is a 32-bit process. Setting PowerShell Execution Policy via WMI/reg.exe" | WriteTo-StdOut -ShortFormat
			
			$ProcessID = RunRemoteProcess -MachineName $MachineName -ProcessNameAndArguments "reg.exe add HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy /d RemoteSigned /f" -LocalCurrentFolder $LocalOutputFolder -RemoteOutputFolder $RemoteOutputFolder -LocalOutputFolder $LocalOutputFolder
			
			if ($ProcessID -ne 0)
			{
				$ProcessID = RunRemoteProcess -MachineName $MachineName -ProcessNameAndArguments "reg.exe add HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy /d RemoteSigned /f" -LocalCurrentFolder $LocalOutputFolder -RemoteOutputFolder $RemoteOutputFolder -LocalOutputFolder $LocalOutputFolder
			}
			
			if ($ProcessID -eq 0)
			{
				"[ExecutionPolicy] Error: Unable to create remote process" | WriteTo-StdOut -ShortFormat
			}					
		} 
		else 
		{
			$RemoteReg.SetStringValue($HKLM,"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy", "RemoteSigned") | Out-Null
			$RemoteReg.SetStringValue($HKLM,"SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy", "RemoteSigned") | Out-Null
		}
		
		# Double check execution policy
		$CurrentExecutionPolicy = ($RemoteReg.GetStringValue($HKLM,"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell","ExecutionPolicy"))
		if (($null -ne $CurrentExecutionPolicy) -and ($CurrentExecutionPolicy.sValue -eq "RemoteSigned"))
		{
			$ReturnValue = $true
		}
		else
		{
			"[ExecutionPolicy] Error: PS Execution Policy was not correctly set. Execution Policy on " + $MachineName + " is currently set to [" + $CurrentExecutionPolicy.sValue + "]"  | WriteTo-StdOut -ShortFormat
			$ReturnValue = $false
		}
	}
	else
	{
		"[ExecutionPolicy] PowerShell Execution Policy on " + $MachineName + " is currently set to [" + $OriginalExecutionPolicy + "]. Execution policy will not be changed" | WriteTo-StdOut -ShortFormat
		$ReturnValue = $true
	}
	
	Return ($ReturnValue)
}

Function RestoreExecutionPolicyOnRemoteSystem  ($MachineName, $LocalOutputFolder, $RemoteOutputFolder)
{
	Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteConfiguringMachine -replace("%Machine%", $RemoteMachineName)) -Status $RemoteSetupStrings.ID_TSRemoteRestoringMachinePSPolicy

    trap 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote Error [RestoreExecutionPolicyOnRemoteSystem] - Machine Name: $MachineName")
		## "ERROR: While restoring PowerShell Execution Policy on remote system: " + $_.Exception.Message + "`r`n" + $_.Exception.ErrorRecord.InvocationInfo.PositionMessage | WriteTo-StdOut
    	get-diaginput -id "ErrorContacting" -Parameter @{"Machine"=$MachineName; "Error"=($RemoteSetupStrings.ID_TSRemoteRestoringMachinePSPolicyError + " " + $_.Exception.Message)}
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
				$ProcessID = RunRemoteProcess -ProcessNameAndArguments "reg.exe add HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy /d $PreviousExecutionPolicy /f" -LocalCurrentFolder $LocalOutputFolder -RemoteOutputFolder $RemoteOutputFolder -LocalOutputFolder $LocalOutputFolder -MachineName $MachineName
				$ProcessID = RunRemoteProcess -ProcessNameAndArguments "reg.exe add HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy /d $PreviousExecutionPolicy /f" -LocalCurrentFolder $LocalOutputFolder -RemoteOutputFolder $RemoteOutputFolder -LocalOutputFolder $LocalOutputFolder  -MachineName $MachineName
				$ProcessID = RunRemoteProcess -ProcessNameAndArguments "reg.exe delete HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v PreviousExecutionPolicy /f" -LocalCurrentFolder $LocalOutputFolder -RemoteOutputFolder $RemoteOutputFolder -LocalOutputFolder $LocalOutputFolder  -MachineName $MachineName
				$ProcessID = RunRemoteProcess -ProcessNameAndArguments "reg.exe delete HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v PreviousExecutionPolicy /f" -LocalCurrentFolder $LocalOutputFolder -RemoteOutputFolder $RemoteOutputFolder -LocalOutputFolder $LocalOutputFolder  -MachineName $MachineName
			} else {
				$ProcessID = RunRemoteProcess -ProcessNameAndArguments "reg.exe delete HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy /f" -LocalCurrentFolder $LocalOutputFolder -RemoteOutputFolder $RemoteOutputFolder -LocalOutputFolder $LocalOutputFolder -MachineName $MachineName
				$ProcessID = RunRemoteProcess -ProcessNameAndArguments "reg.exe delete HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell /v ExecutionPolicy /f" -LocalCurrentFolder $LocalOutputFolder -RemoteOutputFolder $RemoteOutputFolder -LocalOutputFolder $LocalOutputFolder -MachineName $MachineName
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
	
	Return ($null -ne $RemoteReg)
}


Function IsPowerShellInstalled($RemoteMachine)
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote Error [IsPowerShellInstalled] Machine: $RemoteMachine")
		continue
	}
	
	$HKLM = 2147483650
	$RemoteReg = Get-CimInstance -List -Computer $RemoteMachine -Namespace "root\DEFAULT" | Where-Object {$_.Name -eq 'StdRegProv'}
	# $RemoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $RemoteMachine)
	if ($null -ne $RemoteReg)
	{
		
		$RemotePSKeyRoot = $RemoteReg.EnumKey($HKLM, "SOFTWARE\Microsoft\PowerShell")
		
		if ($RemotePSKeyRoot.sNames.Count -gt 0)
		{
			$LatestVersionKeyName = ($RemotePSKeyRoot.sNames |  Measure-Object -Maximum).Maximum
			
			$RemotePSKey = $RemoteReg.EnumValues($HKLM, "SOFTWARE\Microsoft\PowerShell\$($LatestVersionKeyName)\PowerShellEngine")
			#$RemotePSKey = $RemoteReg.OpenSubKey("SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine")
			$PowerShellInstalled = $false
			if ($RemotePSKey.sNames.Count -gt 2)
			{	
				#$PSVersion = $RemotePSKey.GetValue("PowerShellVersion")
				
				$PSVersion = $RemoteReg.GetStringValue($HKLM,  "SOFTWARE\Microsoft\PowerShell\$($LatestVersionKeyName)\PowerShellEngine", "PowerShellVersion").sValue
				$PowerShellInstalled = ($null -ne $PSVersion)
				if ($PowerShellInstalled)
				{
					"PowerShell " + $PSVersion + " IS installed on machine " +  $RemoteMachine + "." | WriteTo-StdOut -ShortFormat
				}
			} 
			else 
			{
				"PowerShell IS NOT installed on remote machine " + $RemoteMachine + "." | WriteTo-StdOut -ShortFormat
			}
		}
		else
		{
			"PowerShell IS NOT installed on remote machine " + $RemoteMachine + " (could not find subkeys under HKLM\SOFTWARE\Microsoft\PowerShell)." | WriteTo-StdOut -ShortFormat
		}
	}
	else
	{
		"[IsPowerShellInstalled] Error: Unable to access remote registry of machine $RemoteMachine to check if PowerShell is installed" | WriteTo-StdOut -ShortFormat
		$PowerShellInstalled = $null
	}
	
	Return ($PowerShellInstalled)
}

Function RunRemoteProcess($MachineName, $ProcessNameAndArguments, $RemoteOutputFolder, $LocalOutputFolder, [string] $LocalCurrentFolder = "", [switch] $Asynchronous, [switch] $DirectExecution)
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote Error [RunRemoteProcess] Machine: $MachineName - [$ProcessNameAndArguments]")
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
	
	$RemoteProcessID = WMIProcessCreate -MachineName $MachineName -ProcessAndArguments $ProcessNameAndArguments -CurrentFolder $LocalCurrentFolder
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

Function WMIProcessCreate($MachineName, $ProcessAndArguments, $CurrentFolder)
{

	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote [WMIProcessCreate] Error creating process on $MachineName. Process: $ProcessAndArguments")
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
	
		#$Results = ([WMICLASS]"\\$computer\ROOT\CIMV2:win32_process").Create($ProcessAndArguments, $CurrentFolder, $Startup)
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

Function DownloadPowerShellPackageFromWeb ([string] $PSURL, [string] $PackageFileName, [string] $DestinationFolderName, [string] $OSDescription, [switch] $ExtractPackage)
{	

	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote [DownloadPowerShellPackageFromWeb] URL: $PSURL")
		continue
	}
	
	$Error.Clear()

	#Use a local package cache to avoid having to download a file more than once
	$LocalCachePath = $PWD.Path + "\PowerShellPackages"
	$LocalCachedPSPackagePath = Join-Path -Path $LocalCachePath -ChildPath $PackageFileName
	
	$PackageExistOnCache = $false
	
	if (-not (Test-Path ($LocalCachePath))){ 
		New-Item -ItemType "Directory" -Path $LocalCachePath | Out-Null #_#
	}

	if (-not (Test-Path ($LocalCachedPSPackagePath))) #File does not exist on local cache
	{
		Write-DiagProgress -Activity $RemoteSetupStrings.ID_TSRemoteDownloadingPSPackage -Status ($RemoteSetupStrings.ID_TSRemoteDownloadingPSPackageDesc -replace("%OSDescription%", $OSDescription))
	
		"Downloading [" + $PSURL + "] and saving it to local cache [" + $LocalCachedPSPackagePath + "]" | WriteTo-StdOut -ShortFormat
		$WebClient = new-object System.Net.WebClient
		$WebClient.DownloadFile($PSURL,$LocalCachedPSPackagePath)
		if ($Error.Count -gt 0)
		{
			$ErrorCode = $Error[0].Exception.ErrorRecord.CategoryInfo.Reason
			"[DownloadPowerShellPackageFromWeb] Error " + $ErrorCode + " downloading " + $PSURL + ": " + $Error[0].Exception.Message | WriteTo-StdOut
			$Error.Clear()
		}
	}
	
	if (-not (Test-Path ($LocalCachedPSPackagePath))) #File does not exist on local cache
	{
		"[DownloadPowerShellPackageFromWeb] Error: " + $LocalCachedPSPackagePath + " does not exist" | WriteTo-StdOut -ShortFormat
		return $false
	} else {
		if (-not (Test-Path ($DestinationFolderName))) { New-Item -ItemType "Directory" -Path $DestinationFolderName | Out-Null}

		if ($ExtractPackage.IsPresent)
		{
			#Extract package to the destination machine
			
			Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteExtractingPSPackage -replace("%OSDescription%", $OSDescription)) -Status $RemoteSetupStrings.ID_TSRemoteExtractingPSPackageDesc
			
			RunCMD -commandToRun ("expand -f:* `"" + $LocalCachedPSPackagePath + "`" `"" + $DestinationFolderName + "`"") -collectFiles $false
			
		} else {
			Write-DiagProgress -Activity  ($RemoteSetupStrings.ID_TSRemoteCopyingPSPackage -replace("%OSDescription%", $OSDescription)) -Status $RemoteSetupStrings.ID_TSRemoteCopyingPSPackageDesc
			Copy-Item -Path $LocalCachedPSPackagePath -Destination $DestinationFolderName
		}
		if ($Error.Count -gt 0)
		{
			$ErrorCode = $Error[0].Exception.ErrorRecord.CategoryInfo.Reason
			"[DownloadPowerShellPackageFromWeb] Error " + $ErrorCode + " copying " + $LocalCachedPSPackagePath + " to " + $DestinationPath + ": " + $Error[0].Exception.Message | WriteTo-StdOut
			$Error.Clear()
		} else {
			"[DownloadPowerShellPackageFromWeb] Information: " + $PackageFileName + " copied to " + $DestinationFolderName | WriteTo-StdOut -ShortFormat
		}
		
		if ($ExtractPackage.IsPresent)
		{
			return (([System.IO.Directory]::GetFiles($DestinationFolderName, "*.cab")).Count -gt 0)
		} else {
			return (Test-Path -Path ($DestinationFolderName + "\" + $PackageFileName))
		}
		
	}
}

Function DownloadAndInstallPowerShellonFullSystem ($MachineName, $OSBuildNumber, $OSArch, $RemoteTempPath, $LocalTempPath, $ProductType, $OSPlat)
{	

	trap [Exception]
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote Error [DownloadAndInstallPowerShellonFullSystem]: $MachineName - OS Build $OSBuildNumber $OSArch")
		$Error.Clear()
		continue
	}

	"Installing PowerShell and/ or dependencies on " + $MachineName + ". OS Build Number: " + $OSBuildNumber + ". OS Architecture: " + $OSArch + ". OS Platform: " + $OSPlat | WriteTo-StdOut -ShortFormat
	if (($OSBuildNumber -eq 3790) -or ($OSBuildNumber -eq 2600)) #If Windows Server 2003 or Windows XP, .Net Framework 2.0 needs to be installed. Easiest way - check for the file system
	{
		$NETFrameworkInstalled = $false
		$NetFramework2RemotePath = [System.IO.Directory]::GetDirectories("\\$MachineName\Admin$\Microsoft.NET\Framework", "v2.0*")[0]
		if (($null -ne $NetFramework2RemotePath) -and ([System.IO.Directory]::GetDirectories($NetFramework2RemotePath).Length -gt 0))
		{
			".NET Framework 2.0 IS installed on machine " + $MachineName | WriteTo-StdOut -ShortFormat
			$NETFrameworkInstalled = $true
		} 
		
		if (-not $NETFrameworkInstalled)
		{
			".NET Framework 2.0 is not installed on machine " + $MachineName | WriteTo-StdOut -ShortFormat
			switch ($OSArch)
			{
				"64-bit"
				{
					If ($OSPlat -eq "IA64")
					{
						$PackageName = "NetFx20SP2_ia64.exe"
						$PowerShellPackageURL = "http://download.microsoft.com/download/c/6/e/c6e88215-0178-4c6c-b5f3-158ff77b1f38/$PackageName"
						$DestinationFolderName = $RemoteTempPath
					
					} else {					
						$PackageName = "NetFx20SP2_x64.exe"
						$PowerShellPackageURL = "http://download.microsoft.com/download/c/6/e/c6e88215-0178-4c6c-b5f3-158ff77b1f38/$PackageName"
						$DestinationFolderName = $RemoteTempPath
					}
				}
				"32-bit"
				{
					$PackageName = "NetFx20SP2_x86.exe"
					$PowerShellPackageURL = "http://download.microsoft.com/download/c/6/e/c6e88215-0178-4c6c-b5f3-158ff77b1f38/$PackageName"
					$DestinationFolderName = $RemoteTempPath
				}
			}
			
			if ((DownloadPowerShellPackageFromWeb -PSURL $PowerShellPackageURL -PackageFileName $PackageName -DestinationFolderName $DestinationFolderName -OSDescription (".Net Framework 2.0 $OSArch")) -ne $false)
			{
				"Installing .NET Framework 2.0 on remote system. Package Path: " + $PackageName | WriteTo-StdOut -ShortFormat
				Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteConfiguringMachine -replace("%Machine%", $MachineName)) -Status $RemoteSetupStrings.ID_TSRemoteNetFrameworkInstall
				
				$PkgCommandLine = "`"" + $LocalTempPath + "\" + $PackageName + "`" /q /l `"" + $LocalTempPath + "\NetFrameworkInstall.Log`""
				
				$Results = RunRemoteProcess -ProcessNameAndArguments $PkgCommandLine -LocalOutputFolder $LocalTempPath -RemoteOutputFolder $RemoteTempPath -MachineName $MachineName -DirectExecution
				
				if (Test-Path -Path ($RemoteTempPath + "\" + $PackageName))
				{
					[System.IO.File]::Delete($RemoteTempPath + "\" + $PackageName)
				}

				if (Test-Path -Path ($RemoteTempPath + "\NetFrameworkInstall.Log"))
				{
					".NET Framework 2.0 Install Log from " + $MachineName + ": " | WriteTo-StdOut -ShortFormat
					$StdoutContent = (Get-Content -Path ($RemoteTempPath + "\NetFrameworkInstall.Log"))
					if ($null -ne $StdoutContent) {[String]::Join("`r`n     ", $StdoutContent) | WriteTo-StdOut}
					Remove-Item ($RemoteTempPath + "\NetFrameworkInstall.Log") -ErrorAction SilentlyContinue
				}
				
				$NetFramework2RemotePath = [System.IO.Directory]::GetDirectories("\\$MachineName\Admin$\Microsoft.NET\Framework", "v2.0*")[0]
				if (($null -ne $NetFramework2RemotePath) -and ([System.IO.Directory]::GetDirectories($NetFramework2RemotePath).Length -gt 0))
				{
					$NETFrameworkInstalled = $true
				}  
				
				if (Test-Path -Path ($RemoteTempPath + "\" + $PackageName))
				{
					[System.IO.File]::Delete($RemoteTempPath + "\" + $PackageName)
				}

			}
		}
	}
	
	if ($OSBuildNumber -eq 2600) #Windows XP 32-bit
	{
		if ($NETFrameworkInstalled) 
		{
			$PackageName = "WindowsXP-KB968930-x86-ENG.exe"
			$PowerShellPackageURL = "http://download.microsoft.com/download/E/C/E/ECE99583-2003-455D-B681-68DB610B44A4/$PackageName"
			$DestinationFolderName = $RemoteTempPath
			
			if ((DownloadPowerShellPackageFromWeb -PSURL $PowerShellPackageURL -PackageFileName $PackageName -DestinationFolderName $DestinationFolderName -OSDescription ("Windows XP")) -ne $false)
			{
				"Installing PowerShell on Windows XP 32-bit " + $MachineName + ". Package Path: " + $PackageName | WriteTo-StdOut -ShortFormat
				Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteConfiguringMachine -replace("%Machine%", $MachineName)) -Status $RemoteSetupStrings.ID_TSRemoteInstallPS
				
				$PkgCommandLine = "`"`"" + $LocalTempPath + "\" + $PackageName + "`" /quiet /norestart /log:`"" + $LocalTempPath + "\PSInstallLog.log`""
				
				$Results = RunRemoteProcess -ProcessNameAndArguments $PkgCommandLine -LocalOutputFolder $LocalTempPath -RemoteOutputFolder $RemoteTempPath -MachineName $MachineName
				
				if (Test-Path -Path ($RemoteTempPath + "\" + $PackageName))
				{
					[System.IO.File]::Delete($RemoteTempPath + "\" + $PackageName)
				}

				if (Test-Path -Path ($RemoteTempPath + "\PSInstallLog.Log"))
				{
					"PowerShell Install Log from " + $MachineName + ": " | WriteTo-StdOut -ShortFormat
					$StdoutContent = (Get-Content -Path ($RemoteTempPath + "\PSInstallLog.Log"))
					if ($null -ne $StdoutContent) {[String]::Join("`r`n     ", $StdoutContent) | WriteTo-StdOut}
					Remove-Item ($RemoteTempPath + "\PSInstallLog.Log") -ErrorAction SilentlyContinue
				}
				
				return ($Results -ne 0)
			} else {
				return $false
			}
		} else {
			return $false #.NET Framework is not installed
		}
	}
	
	if ($OSBuildNumber -eq 3790) #Windows Server 2003/ XP x64?
	{
		if ($NETFrameworkInstalled) 
		{
			switch ($OSArch)
			{
				"64-bit"
				{
					If ($OSPlat -eq "IA64")
					{
						$PackageName = "WindowsServer2003-KB926139-v2-ia64-ENU.exe"
						$PowerShellPackageURL = "http://download.microsoft.com/download/4/c/f/4cfd7bcb-823f-47ab-8d22-a2d424896e96/$PackageName"
						$DestinationFolderName = $RemoteTempPath
					} else {
						$PackageName = "WindowsServer2003-KB968930-x64-ENG.exe"
						$PowerShellPackageURL = "http://download.microsoft.com/download/B/D/9/BD9BB1FF-6609-4B10-9334-6D0C58066AA7/$PackageName"
						$DestinationFolderName = $RemoteTempPath
					}
				}
				"32-bit"
				{
					$PackageName = "WindowsServer2003-KB968930-x86-ENG.exe"
					$PowerShellPackageURL = "http://download.microsoft.com/download/1/1/7/117FB25C-BB2D-41E1-B01E-0FEB0BC72C30/$PackageName"
					$DestinationFolderName = $RemoteTempPath
				}
			}
			
			if ((DownloadPowerShellPackageFromWeb -PSURL $PowerShellPackageURL -PackageFileName $PackageName -DestinationFolderName $DestinationFolderName -OSDescription ("Windows Server 2003 $OSArch")) -ne $false)
			{
				"Installing PowerShell on Windows Server 2003 " + $MachineName + ". Package Path: " + $PackageName | WriteTo-StdOut -ShortFormat
				Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteConfiguringMachine -replace("%Machine%", $MachineName)) -Status $RemoteSetupStrings.ID_TSRemoteInstallPS
				$PkgCommandLine = "`"`"" + $LocalTempPath + "\" + $PackageName + "`" /quiet /norestart /log:`"" + $LocalTempPath + "\PSInstallLog.log`""
				
				$Results = RunRemoteProcess -ProcessNameAndArguments $PkgCommandLine -LocalOutputFolder $LocalTempPath -RemoteOutputFolder $RemoteTempPath -MachineName $MachineName
				
				if (Test-Path -Path ($RemoteTempPath + "\" + $PackageName))
				{
					[System.IO.File]::Delete($RemoteTempPath + "\" + $PackageName)
				}
				
				if (Test-Path -Path ($RemoteTempPath + "\PSInstallLog.Log"))
				{
					"PowerShell Install Log: " | WriteTo-StdOut -ShortFormat
					$StdoutContent = (Get-Content -Path ($RemoteTempPath + "\PSInstallLog.Log"))
					if ($null -ne $StdoutContent) {[String]::Join("`r`n     ", $StdoutContent) | WriteTo-StdOut}
					Remove-Item ($RemoteTempPath + "\PSInstallLog.Log") -ErrorAction SilentlyContinue
				}

				return ($Results -ne 0)
			} else {
				return $false
			}
		} else {
			return $false #.NET Framework is not installed
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
					$PowerShellPackageURL = "http://download.microsoft.com/download/c/d/f/cdfb3b08-f9bc-48c2-92fa-214b5e684cff/$MSUPackageName"
					$DestinationFolderName = $RemoteTempPath + "\" + $PackageName
				}
				
				"32-bit"
				{
					$PackageName = "Windows6.0-KB928439-x86"
					$MSUPackageName = "$PackageName.msu"
					$PowerShellPackageURL = "http://download.microsoft.com/download/4/b/8/4b8e4fac-bf73-49d0-8b98-ce1f58ba26b8/$MSUPackageName"
					$DestinationFolderName = $RemoteTempPath + "\" + $PackageName
				}
			}
			if ((DownloadPowerShellPackageFromWeb -PSURL $PowerShellPackageURL -PackageFileName $MSUPackageName -DestinationFolderName $DestinationFolderName -OSDescription ("Windows Vista/ Server 2008 $OSArch") -ExtractPackage) -ne $false)
			{
				"Installing PowerShell on Windows Vista " + $MachineName + ". MSU Path: " + $MSUPackageName | WriteTo-StdOut -ShortFormat
				Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteConfiguringMachine -replace("%Machine%", $MachineName)) -Status $RemoteSetupStrings.ID_TSRemoteInstallPS
				
				$PkgMgrCommandLine = "start /w pkgmgr.exe /n:`"" + $LocalTempPath + "\" + $PackageName + "\" + $PackageName + ".xml`" /quiet /norestart"
				
				$Results = RunRemoteProcess -ProcessNameAndArguments $PkgMgrCommandLine -LocalOutputFolder $LocalTempPath -RemoteOutputFolder $RemoteTempPath -MachineName $MachineName
				
				if (Test-Path -Path $DestinationFolderName)
				{
					[System.IO.Directory]::Delete($DestinationFolderName, $true)
				}
				
				return ($Results -ne 0)
			} else {
				return $false
			}
		}
		else 
		{ #Servers - Windows Server 2008
			"Installing PowerShell on Windows Server 2008 " + $MachineName + "." | WriteTo-StdOut -ShortFormat
			Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteConfiguringMachine -replace("%Machine%", $MachineName)) -Status $RemoteSetupStrings.ID_TSRemoteEnablePS
			
			$CommandToInstallPS = "servermanagercmd.exe -install PowerShell"
			$Results = RunRemoteProcess -ProcessNameAndArguments $CommandToInstallPS -LocalOutputFolder $LocalTempPath -RemoteOutputFolder $RemoteTempPath -MachineName $MachineName
			return ($Results -ne 0)
		}
	}
}

Function InstallPowerShellOnServerCoreR2 ($RemoteMachine, $RemoteTempPath, $LocalTempPath)
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote [InstallPowerShellOnServerCoreR2] Machine: $RemoteMachine")
		continue
	}

	Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteConfiguringMachine -replace("%Machine%", $RemoteMachine)) -Status $RemoteSetupStrings.ID_TSRemoteInstallPS
	
	"[InstallPowerShellOnServerCoreR2] Installing Powershell on $RemoteMachine..." | WriteTo-StdOut -ShortFormat
	
	$StdoutFileName = RunRemoteProcess -RemoteMachineName $RemoteMachine -ProcessNameAndArguments "Dism.exe /online /enable-feature /featurename:NetFx2-ServerCore" -RemoteOutputFolder $RemoteTempPath -LocalCurrentFolder $LocalTempPath
	if ($null -ne $StdoutFileName) 
	{
		Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteConfiguringMachine -replace("%Machine%", $RemoteMachine)) -Status ($RemoteSetupStrings.ID_TSRemoteInstallPS + " (25%)")
		$StdoutFileName = RunRemoteProcess -RemoteMachineName $RemoteMachine -ProcessNameAndArguments "Dism.exe /online /enable-feature /featurename:MicrosoftWindowsPowerShell" -RemoteOutputFolder $RemoteTempPath -LocalCurrentFolder $LocalTempPath
		
		if ($null -ne $StdoutFileName) 
		{
			Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteConfiguringMachine -replace("%Machine%", $RemoteMachine)) -Status ($RemoteSetupStrings.ID_TSRemoteInstallPS + " (50%)")
			$StdoutFileName = RunRemoteProcess -RemoteMachineName $RemoteMachine -ProcessNameAndArguments "Dism.exe /online /enable-feature /featurename:NetFx2-ServerCore-WOW64" -RemoteOutputFolder $RemoteTempPath -LocalCurrentFolder $LocalTempPath
			
			if ($null -ne $StdoutFileName) 
			{
				Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteConfiguringMachine -replace("%Machine%", $RemoteMachine)) -Status ($RemoteSetupStrings.ID_TSRemoteInstallPS + " (100%)")
				$StdoutFileName = RunRemoteProcess -RemoteMachineName $RemoteMachine -ProcessNameAndArguments "Dism.exe /online /enable-feature /featurename:MicrosoftWindowsPowerShell-WOW64" -RemoteOutputFolder $RemoteTempPath -LocalCurrentFolder $LocalTempPath
			}
		}
	}
	
	"[InstallPowerShellOnServerCoreR2] Done" | WriteTo-StdOut -ShortFormat
	
	return ($null -eq $StdoutFileName)
}

Function InstallServerCoreComponents ([string] $RemoteMachine,[string] $RemoteTempPath,[string] $LocalTempPath, [switch] $ShowDialog)
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote [InstallServerCoreComponents] Machine: $RemoteMachine")
		continue
	}
	
	#Install Powershell on R2 machine. If $ShowDialog is present, then show a dialog asking authorization
	#First check if powershell is already installed:

	Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteObtainingInfo -replace("%Machine%", $RemoteMachine)) -Status $RemoteSetupStrings.ID_TSRemoteObtainingPSInfo
	
	$PowerShellInstalled = IsPowerShellInstalled $RemoteMachine
	
	if (-not $PowerShellInstalled) 
	{
		$DiagResponse = "Continue"
		
		if ($ShowDialog.IsPresent)
		{
			$DiagResponse = get-diaginput -id "PowerShellNotInstalledOnRemoteMachine" -Parameter @{"Machine"=$RemoteMachine}
		}	
		
		if ($DiagResponse -eq "Continue") 
		{
			InstallPowerShellOnServerCoreR2 -RemoteMachine $RemoteMachine -LocalTempPath $LocalTempPath -RemoteTempPath $RemoteTempPath
			$PowerShellInstalled = IsPowerShellInstalled $RemoteMachine
			
		} else {
			$PowerShellInstalled = $false
		}
		
	}
	
	if ($PowerShellInstalled)
	{
		return $true
	} else {
		return $false
	}
	
}

Function CollectRemoteData ([string] $MachineName, [string] $RemoteSetupPath)
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote [CollectRemoteData] Machine: $MachineName")
		continue
	}
	
	#This function collect data from remote system.
	#Information about what needs to be collected should be stored $RemoteSetupPath\Output\UpdateDiagReport.xml

	$Error.Clear()
	
	# Obtain Stdout file for PowerShell Execution
	Write-DiagProgress -Activity $RemoteSetupStrings.ID_TSRemoteObtainingData -Status ($RemoteSetupStrings.ID_TSRemoteObtainingDataDesc -replace("%Machine%", $RemoteMachine))
	
	$RemoteStdOut = $RemoteSetupPath + "\Output\RemoteStdout.out"
	$UpdateDiagReportXMLPath = $RemoteSetupPath + "\Output\UpdateDiagReport.xml"

	if (Test-Path ($RemoteStdOut))
	{
		"Stdout output for Powershell Diagnostic execution on " + $MachineName + ": `r`n" + ("-" * 70) | WriteTo-StdOut -ShortFormat
		$StdoutContent = (Get-Content -Path $RemoteStdOut)
		if ($null -ne $StdoutContent) {[String]::Join("`r`n    | ", $StdoutContent) | WriteTo-StdOut}
		Remove-Item $RemoteStdOut -ErrorAction SilentlyContinue		
	}
	else 
	{
		"`r`n [CollectRemoteData] Warning: unable to open : $RemoteStdOut" | WriteTo-StdOut -ShortFormat
	}
	
	$Item = $null
	
	#Process remote UpdateDiagReport XML file
	if (test-path -Path $UpdateDiagReportXMLPath)
	{
		
		trap [Exception] 
		{
		
			"[CollectRemoteData] Error Collecting Remote Data - Message: " + $Error[0].Exception.Message | WriteTo-StdOut -ShortFormat
			if ($null -ne $Item)
			{
				$MSG = "       XML : " +  $UpdateDiagReportXMLPath
				$MSG += "`r`n   Machine : " +  $MachineName
				$MSG += "`r`n      Item : `r`n`r`n" +  ($Item.OuterXML)
				$MSG += "`r`n`r`n     Error : " +  $Error[0].Exception.ErrorRecord.CategoryInfo.Reason + " - " + $Error[0].Exception.Message
				$MSG | WriteTo-StdOut
			}
			
			WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote [CollectRemoteData] Processing $UpdateDiagReportXMLPath - Machine: $MachineName")
			$Error.Clear()
			continue
		}
		
		$Error.Clear()
		[xml] $UpdateDiagReportXML = Get-Content -Path $UpdateDiagReportXMLPath
		
		#Obtain Update-DiagReport information
		foreach ($Item in $UpdateDiagReportXML.SelectNodes("//Root/Item"))
		{
			if (($Item.Type -eq "File") -and (($Item.get_Item("ID").get_InnerText()) -ne ""))
			{
				$FileElement = $Item.get_Item("File")
				If (($null -ne $FileElement) -and ($null -ne $Item.get_Item("File").get_InnerText()))
				{
					if (Test-Path -Path ($RemoteSetupPath + "\" + ($Item.get_Item("File").get_InnerText())))
					{
						CollectFiles -fileDescription ($Item.get_Item("Name").get_InnerText()) -sectionDescription ($Item.get_Item("ID").get_InnerText()) -noFileExtensionsOnDescription -Verbosity ($Item.get_Item("Verbosity").get_InnerText()) -filesToCollect ($RemoteSetupPath + "\" + ($Item.get_Item("File").get_InnerText()))
					}
				}
				else
				{
					"[CollectRemoteData] Error Collecting Remote Data - Message: Unable to locate file for item below" | WriteTo-StdOut -ShortFormat
					if ($null -ne $Item)
					{
						$MSG = "       XML : " +  $UpdateDiagReportXMLPath
						$MSG += "`r`n   Machine : " +  $MachineName
						$MSG += "`r`n      Name : " +  ($Item.get_Item("Name").get_InnerText())
						$MSG += "`r`n        ID : " +  ($Item.get_Item("ID").get_InnerText())
						$MSG += "`r`n      Item : `r`n`r`n" +  ($Item.OuterXML)
						$MSG | WriteTo-StdOut
					}
				}
			} 
			elseif ($Item.Type -eq "XML") 
			{
				#if($debug -eq $true){[void]$shell.popup("-Id " + ($Item.get_Item("ID").get_InnerText()) + " -Name " + ($Item.get_Item("Name").get_InnerText()) + "-Verbosity " + ($Item.get_Item("Verbosity").get_InnerText()))
				[xml] $Item.get_Item("XML").Get_InnerXml() | Update-DiagReport -Id ($Item.get_Item("ID").get_InnerText()) -Name ($Item.get_Item("Name").get_InnerText()) -Verbosity($Item.get_Item("Verbosity").get_InnerText())
			}			
		}
		return $true
	} 
	else 
	{
		"[CollectRemoteData] Information: $UpdateDiagReportXMLPath does not exist"| WriteTo-StdOut  -ShortFormat
		return $false
	}
}

Function DeleteRemoteComponents ([string] $MachineName, [string] $RemoteSetupPath)
{

	trap 
	{
		$errorMessage = "Error [DeleteRemoteComponents]: Category {0}, Error Type {1}, ID: {2}, Message: {3}" -f  $_.CategoryInfo.Category, $_.Exception.GetType().FullName,  $_.FullyQualifiedErrorID, $_.Exception.Message
		$errorMessage | WriteTo-StdOut
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote [DeleteRemoteComponents] Machine: $MachineName")
		continue
	}

	#This function delete all information that is stored on remote machine: Exclude $RemoteSetupPath folder and subfolders

	Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteConfiguringMachine -replace("%Machine%", $MachineName))  -Status $RemoteSetupStrings.ID_TSRemoteRemoving

	if (test-path -Path ($RemoteSetupPath))
	{
		Remove-Item -Path ($RemoteSetupPath + "\*.*") -Recurse -Force

		if (Test-Path ($RemoteSetupPath))
		{
			[System.IO.Directory]::Delete($RemoteSetupPath, $true)
		}
		
		$GMReportFileName = [System.IO.Path]::GetFullPath((Join-Path $RemoteSetupPath "..\GenericMessageUpdateDiagReport.xml"))
		if (Test-Path -Path ($GMReportFileName))
		{
			Remove-Item -Path $GMReportFileName -Force
		}
	}	
}

Function ObtainRemoteStdoutContent([string] $MachineName, [string] $RemoteSetupPath, [string] $From)
{	
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote [ObtainRemoteStdoutContent] Machine: $MachineName - From: $From")
		continue
	}

	$RemoteStdoutContent = $null
	
	if (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 0))
	{
		$RemoteStdoutLogPath = (Join-Path -Path $RemoteSetupPath -ChildPath "..\stdout-wtp.log")
	} 
	else
	{	
		$RemoteStdoutLogPath = (Join-Path -Path $RemoteSetupPath -ChildPath "..\stdout.log")
	}

	$LocalStdoutContentToAdd = "Stdout output from $From on " + $MachineName + ": `r`n---------------------------------------`r`n"
	if (Test-Path -Path $RemoteStdoutLogPath)
	{
		"[{0}] : [INFO] Find the path for: {1}" -f ($Myinvocation.MyCommand,$RemoteStdoutLogPath) | WriteTo-StdOut
		$RemoteStdoutContent = (Get-Content -Path $RemoteStdoutLogPath)
	}
	else 
	{
		"[{0}] : [Error] Cannot find the path for: {1}" -f ($Myinvocation.MyCommand,$RemoteStdoutLogPath) | WriteTo-StdOut	
	}
	
	if ($null -ne $RemoteStdoutContent) 
	{
		"[{0}] : [INFO] Successful to get content for: {1}" -f ($Myinvocation.MyCommand,$RemoteStdoutLogPath) | WriteTo-StdOut
		$LocalStdoutContentToAdd += [String]::Join("`r`n    ! ", $RemoteStdoutContent)
	}
	else
	{
		"[{0}] : [INFO] Unsuccessful to get content for: {1}" -f ($Myinvocation.MyCommand,$RemoteStdoutLogPath) | WriteTo-StdOut
	}
	$LocalStdoutContentToAdd += "`r`n---------------------------------------`r`n"

	WriteTo-StdOut -ObjectToAdd $LocalStdoutContentToAdd -ShortFormat

	Remove-Item $RemoteStdoutLogPath -ErrorAction SilentlyContinue -Force

}

Function GetWin32OSFromRemoteSystem([string] $MachineName)
{
	#Obtain OS From Remote Machine and return the WMI class.
	#If error communicating, return the exeption error code instead of WMI class
	
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote [GetWin32OSFromRemoteSystem] Machine: $MachineName")
		continue
	}
	
	$Error.Clear()
	
	Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteConnectingTo -replace("%Machine%", $MachineName))  -Status $RemoteSetupStrings.ID_TSRemoteObtainingOSInfo
	
	$OS = Get-CimInstance -Class Win32_OperatingSystem -ComputerName $MachineName -ErrorAction SilentlyContinue
	
	if ($Error.Count -gt 0)
	{
		if ($Error[0].Exception.ErrorCode -eq -2147023174) #The RPC server is unavailable. (Exception from HRESULT: 0x800706BA)
		{
			"[GetWin32OSFromRemoteSystem] Error contacting " + $MachineName + ": Error 0x800706BA - The RPC server is unavailable. One of the possible reasons for this error is when machine is offline or firewall is blocking SMB communications." | WriteTo-StdOut  -ShortFormat
		} else {
			$ErrorCode = $Error[0].Exception.ErrorRecord.CategoryInfo.Reason
			"[GetWin32OSFromRemoteSystem] Error $ErrorCode contacting " + $MachineName + ": " + $Error[0].Exception.Message | WriteTo-StdOut
		}
		$Error[0].Exception.ErrorCode
		$Error.Clear()
	} else {
		$OS
	}
}

Function GetWin32Processor([string] $MachineName)
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote [GetWin32Processor] Machine: $MachineName")
		continue
	}
	
	#Obtain Win32_Processor WMI Class From Remote Machine.
	$Error.Clear()
	
	Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteConnectingTo -replace("%Machine%", $MachineName))  -Status $RemoteSetupStrings.ID_TSRemoteObtainingProcessorInfo
	
	$Win32Processor = Get-CimInstance -Class Win32_Processor -ComputerName $MachineName -ErrorAction SilentlyContinue
	
	if ($Error.Count -gt 0)
	{
		if ($Error[0].Exception.ErrorCode -eq -2147023174) #The RPC server is unavailable. (Exception from HRESULT: 0x800706BA)
		{
			"[GetWin32Processor] Error contacting " + $MachineName + ": Error 0x800706BA - The RPC server is unavailable. One of the possible reasons for this error is when machine is offline or firewall is blocking SMB communications." | WriteTo-StdOut  -ShortFormat
		} else {
			$ErrorCode = $Error[0].Exception.ErrorRecord.CategoryInfo.Reason
			"[GetWin32Processor] Error $ErrorCode contacting " + $MachineName + ": " + $Error[0].Exception.Message | WriteTo-StdOut -ShortFormat
		}
		return $null
	} else {
		return $Win32Processor
	}
}

Function ProcessRootCauses([string] $MachineName, [string] $RemoteSetupPath, [string] $LocalSetupPath, [string] $LocalPowerShellPath)
{
	#This function executes the root causes detected on $RemoteMachine
	#Root causes are saved in $global:RemoteSetupPath\Output\UpdateDiagRootCause.xml
	#Function analyzes the Root Cause XML and executes the resolver scripts on remote systems
	
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote [ProcessRootCauses] Machine: $MachineName")
		continue
	}
	
	$RootCauseScriptProcessID = 0
	
	if (Test-Path ($RemoteSetupPath + "\Output\UpdateDiagRootCause.xml"))
	{
		[xml] $RemoteRootCausesXML = Get-Content -Path ($RemoteSetupPath + "\Output\UpdateDiagRootCause.xml")
		[xml] $DiagPackageXML = Get-Content -Path ($RemoteSetupPath + "\DiagPackage.diagpkg")
		
		#Modify the remote utils_cts.ps1 so it would call utils_Remote.ps1:
#		if ($Host.Version.Major -lt 2)
#		{
#			$UtilsCTSPath = (Join-Path -Path $RemoteSetupPath -ChildPath "utils_CTS.ps1")
#			$UtilsCTS = Get-Content	$UtilsCTSPath
#			$UtilsCTS += "`r`n. ./utils_Remote.ps1"
#			$UtilsCTS | Out-File $UtilsCTSPath -Force -Encoding "UTF8"
#		}
#		else
#		{
#			Add-Content -Path (Join-Path -Path $RemoteSetupPath -ChildPath "utils_CTS.ps1") -Value "`r`n. ./utils_Remote.ps1" -Encoding "UTF8"
#		}

		#1st Step: Create a file on file system so utils_cts will know that it needs to run utils_remote.ps1
		$TSRemoteProcessRootCausesPath = (Join-Path -Path $RemoteSetupPath -ChildPath "TSRemoteProcessRootCauses.txt")
		"Processing Root Causes. Creating $TSRemoteProcessRootCausesPath" | WriteTo-StdOut -ShortFormat
		"$MachineName" | Out-File $TSRemoteProcessRootCausesPath -Append
		

		#2nd Step: Navigate Though the Root Causes Detected on remote node
		
		$DiagnosticRootCauseArgumentsPath = [System.IO.Path]::GetFullPath("..\DiagnosticRootCauseArguments.xml")
		if (-not (Test-Path($DiagnosticRootCauseArgumentsPath)))
		{
			$xmlResolverArguments = [xml] "<?xml version=""1.0"" ?><Root></Root>"
		} else 
		{
			[xml] $xmlResolverArguments = Get-Content -Path $DiagnosticRootCauseArgumentsPath
		}
		
		$ARootCauseWasDetected = $false
		$RootCausesPS1 = ""
		
		foreach ($RootCauseItem in $RemoteRootCausesXML.SelectNodes("/Root/Item[ID]"))
		{
			$RootCauseID = $RootCauseItem.ID.get_InnerText()

			#First check if the root cause detected is contained in DiagPackage.diagpkg:
			[xml] $DiagPackageXML = Get-Content -Path (Join-Path $PWD.Path "DiagPackage.diagpkg")
			if ($DiagPackageXML.SelectNodes("//Rootcause[ID = '$RootCauseID']").Count -gt 0)
			{
		
				if ($RootCauseItem.Detected.get_InnerText() -eq "True")
				{				
					$ARootCauseWasDetected = $true
					
					#Obtain Root Cause ID
					#Locate Remote Root CauseID on DiagPackage.diagpkg
					$RootCauseElement = $DiagPackageXML.SelectSingleNode("//Rootcause[ID=`'" + $RootCauseID + "`']")
					
					if ($null -ne $RootCauseElement)
					{
						$ResolverScriptName = $RootCauseElement.Resolvers.Resolver.Script.FileName
					}				
					
					" -- Root Cause Detected: " + $RootCauseItem.ID.get_InnerText() + " on machine " + $MachineName + ". Resolver Script name: $ResolverScriptName" | WriteTo-StdOut -ShortFormat
					
					$ScriptParameters = $null
					
					if ($RootCauseElement.Resolvers.Resolver.Script.Parameters.IsEmpty -eq $false) #there are script parameters
					{
						$ScriptParameters = $RootCauseElement.Resolvers.Resolver.Script.Parameters
					}
					
					#if ($RootCauseElement.Resolvers.Resolver.DisplayInformation.Parameters.IsEmpty -eq $false) #There are Display parameters
					#{
					#	$DisplayParameters = $RootCauseElement.Resolvers.Resolver.DisplayInformation.Parameters
					#}
									
					$RootCausesPS1 = PrepareToRunRemoteRootCause -MachineName $MachineName -ResolverScriptName $ResolverScriptName -RootCauseItem $RootCauseItem -ScriptParameters $ScriptParameters -LocalSetupPath $LocalSetupPath -RemoteSetupPath $RemoteSetupPath #-DisplayParameters $DisplayParameters
					
					#Write data on DiagnosticRootCauseArguments.xml so when the resolver script executes locally it would be able to identify items like remote server name, Root Cause ID and others

					$RootElement = $xmlResolverArguments.SelectSingleNode("/Root")
					$element = $xmlResolverArguments.CreateElement("RootCauseDetected")
					[Void] $element.SetAttribute("Processed", "False")
					[Void] $element.set_InnerXml("<MachineName>$MachineName</MachineName><LocalSetupPath>$LocalSetupPath</LocalSetupPath><RemoteSetupPath>$RemoteSetupPath</RemoteSetupPath><RootCauseID>$RootCauseID</RootCauseID><ScriptFileName>$ResolverScriptName</ScriptFileName>")
					$X = $RootElement.AppendChild($element)
				}
				elseif ($RootCauseItem.Detected.get_InnerText() -eq "False")
				{
					#Locate Remote Root CauseID on DiagPackage.diagpkg
					$RootCauseElement = $DiagPackageXML.SelectSingleNode("//Rootcause[ID=`'" + $RootCauseID + "`']")
					
					" -- Root Cause set to 'Not Detected': " + $RootCauseItem.ID.get_InnerText() + " on machine " + $MachineName + "." | WriteTo-StdOut -ShortFormat
					
					$RootElement = $xmlResolverArguments.SelectSingleNode("/Root")
					$element = $xmlResolverArguments.CreateElement("RootCauseNotDetected")
					[Void] $element.SetAttribute("Processed", "False")
					[Void] $element.set_InnerXml("<MachineName>$MachineName</MachineName><RootCauseID>$RootCauseID</RootCauseID>")				
					$X = $RootElement.AppendChild($element)
				}
			}
			else
			{
				" -- ERROR: Root Cause $RootCauseID does not exist on DiagPackage.DiagPkg. Root cause will not be processed" | WriteTo-StdOut -ShortFormat
			}
		}
		if ($xmlResolverArguments.SelectNodes("//RootCauseID").Count -gt 0)
		{
			[Void] $xmlResolverArguments.Save($DiagnosticRootCauseArgumentsPath)
		}

		if ($RootCausesPS1 -ne "") 
		{ 
			$RootCauseScriptProcessID = StartRemoteRootCausesScript -MachineName $MachineName -RootCausesPS1FileName $RootCausesPS1 -RemoteSetupPath $RemoteSetupPath -LocalSetupPath $LocalSetupPath -LocalPowerShellPath $LocalPowerShellPath
		}
		elseif (-not $ARootCauseWasDetected)
		{
			"  -- No Root Causes Detected on machine " + $MachineName + "." | WriteTo-StdOut 
			$RootCauseScriptProcessID = -1
		}
		else
		{
			$RootCauseScriptProcessID = 0
		}
		return $RootCauseScriptProcessID
	} else {
		"  -- No Root Causes Detected on machine " + $MachineName + "." | WriteTo-StdOut 
		return -1
	}
	
}

Function StartRemoteRootCausesScript($MachineName, $RootCausesPS1FileName, [string] $LocalPowerShellPath, [string] $RemoteSetupPath, [string] $LocalSetupPath)
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote [StartRemoteRootCausesScript] Machine: $MachineName")
		continue
	}
	
	#2.a Run Script
	#$RemotePowerShellCommandLine = "cd `"$LocalSetupPath`" & `"" + $LocalPowerShellPath + "`" `"" + $RootCausesPS1FileName + "`""
	
	$PowerShellStdOut = $LocalSetupPath + "\Output\RemoteStdout.out"
	$RemotePowerShellCommandLine = "`"" + $LocalPowerShellPath + "`" -command `"&{start-transcript -path `"" + $PowerShellStdout + "`"; " + $RootCausesPS1FileName + "; stop-transcript}"
	
	if (Test-Path ($RemoteSetupPath + "\Output\WriteDiagProgress.txt"))
	{
		Remove-Item ($RemoteSetupPath + "\Output\WriteDiagProgress.txt")
	}

	$RemoteProcessID = RunRemoteProcess -MachineName $MachineName -ProcessNameAndArguments $RemotePowerShellCommandLine -Asynchronous -LocalOutputFolder ($LocalSetupPath + "\Output") -RemoteOutputFolder ($RemoteSetupPath  + "\Output") -DirectExecution -LocalCurrentFolder $LocalSetupPath
	Return $RemoteProcessID
}

Function PrepareToRunRemoteRootCause ([string] $MachineName, [string] $ResolverScriptName, [System.Xml.XmlElement] $RootCauseItem, [System.Xml.XmlElement] $ScriptParameters, [string] $RemoteSetupPath, [string] $LocalSetupPath)
{

	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote [PrepareToRunRemoteRootCause] Machine: $MachineName")
		continue
	}

	$RemoteResolverPath = Join-Path -Path $RemoteSetupPath -ChildPath $ResolverScriptName
	$LocalResolverPath = Join-Path -Path $LocalsetupPath -ChildPath $ResolverScriptName
	$LocalMachineResolverPath =  Join-Path -Path $PWD.Path -ChildPath $ResolverScriptName
	$RemoteRemoteRootCausePS1File = Join-Path -Path $RemoteSetupPath -ChildPath "RunResolvers.PS1"
	$LocalRemoteRootCausePS1File = Join-Path -Path $LocalSetupPath -ChildPath "RunResolvers.PS1"
	
	if ((Test-Path -Path $RemoteResolverPath) -and (Test-Path -Path $LocalMachineResolverPath))
	{
		#1st Step: Build command line

		#2.a Obtain script parameters
		$ParameterCommandLine = ""
		if ($ScriptParameters -ne $null)
		{
			foreach ($Parameter in $ScriptParameters.Parameter)
			{	
				$ParameterName = $Parameter.Name
				$ParameterValue = $RootCauseItem.Parameters.Item($ParameterName).get_InnerText()
				
				$ParameterCommandLine += "-" + $ParameterName + " `"" + $ParameterValue + "`" "
			}
		}
		#2.b. Add Command Line on the Remote Root Cause PS1 File
		#     (10/1/2010) - Use a variable called '$RootCauseName' so the script would be able to identify the root cause name

		Add-Content -Path $RemoteRemoteRootCausePS1File -Value ('$RootCauseID="' + $RootCauseItem.ID.get_InnerText() + "`"`r`n.\" + $ResolverScriptName + " " + $ParameterCommandLine) -Encoding UTF8
		
		#3rd Step: Modify Local Root Cause contents to run a generic script
		" -- Replacing $ResolverScriptName with RS_RemoteResolverProcessing.ps1"  | WriteTo-StdOut -ShortFormat
		Copy-Item -Path "RS_RemoteResolverProcessing.ps1" -Destination $ResolverScriptName -Force
		
		#3.c. Build Parameters Hash Table for Update-DiagRootCause
		$UpdateDiagRootCauseParameters = @{}
		if ($null -ne $RootCauseItem.Parameters)
		{
			foreach ($Parameter in $RootCauseItem.Parameters.ChildNodes)
			{	
				$ParameterName = $Parameter.LocalName
				$ParameterValue = $Parameter.get_InnerText()
				
				$UpdateDiagRootCauseParameters += @{$ParameterName=$ParameterValue}
			}
		}
		
		$RootCauseIDText = $RootCauseItem.ID.get_InnerText()
		"Setting Root Cause $RootCauseIDText to `'Detected`'" | WriteTo-StdOut -ShortFormat
		if ($UpdateDiagRootCauseParameters.Count -lt 1)
		{
			trap [Exception] 
			{
				WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote [Update-DiagRootCause] Machine: $MachineName - Root Cause $RootCauseIDText")
				continue
			}
			Update-DiagRootCause -Id $RootCauseIDText -Detected $true
		} 
		else 
		{
			Update-DiagRootCause -Id $RootCauseIDText -Detected $true -Parameter $UpdateDiagRootCauseParameters
		}
		
		Return $LocalRemoteRootCausePS1File
		
	} else {
		"Error Processing Root Cause: Either $RemoteResolverPath or $LocalMachineResolverPath does not exist." | WriteTo-StdOut -ShortFormat
		return ""
	}	
}

Function CopyDiagnosticToRemoteMachine([String] $MachineName, [string] $RemoteFolder)
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote [CopyDiagnosticToRemoteMachine] Machine: $MachineName - RemoteFolder: $RemoteFolder")
		continue
	}
	
	#Create folder structure under %windir%\temp. Folder will be named '%windir%\temp\Diagnostics\SDIAG_GUID'

	$Error.Clear()

	Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteConfiguringMachine -replace("%Machine%", $MachineName))  -Status $RemoteSetupStrings.ID_TSRemoteBuildingDiagEnv

	if (-not (Test-Path $RemoteFolder)) {New-Item -ItemType "Directory" -Path $RemoteFolder | Out-Null}
	if (-not (Test-Path ($RemoteFolder + "\Output"))) {New-Item -ItemType "Directory" -Path ($RemoteFolder + "\Output")  | Out-Null}
	
	Copy-Item -Path ($PWD.Path + "\*.*") -Destination $RemoteFolder
	[System.IO.Directory]::GetDirectories($PWD.Path) | Copy-Item -Destination $RemoteFolder -Recurse
	
	if ($Error.Count -gt 0)
	{
		$ErrorCode = $Error[0].Exception.ErrorRecord.CategoryInfo.Reason
		"[CopyDiagnosticToRemoteMachine] Error $ErrorCode copying diagnostic to machine $MachineName ($RemoteFolder): "  + $Error[0].Exception.Message | WriteTo-StdOut
		$Error.Clear()
		return $false
	} else {
		return $true
	}
}

Function WriteMachinesStatetoStdOut($MachineStateTable, $AdditionalComment)
{
	trap [Exception] { continue }

	$StringToWrite = ""
	foreach ($Machine in $RemoteMachineStateInformation.GetEnumerator())
	{
		$StringToWrite += "    " + $Machine.Name + ": " + (($MachineState.GetEnumerator() | Where-Object {$_.value -eq $Machine.Value}).Name) + "`r`n"
	}
	
	"Machine State Information [" + $AdditionalComment +"]: `r`n" + $StringToWrite  | WriteTo-StdOut
}

#Create TS_Diag.ps1 - which would execute utils_cts.ps1, utils_remote.ps1 and then the Expression to ExecuteRemoteExpression
Function BuildRemoteDiagFile([string] $DiagScriptName, $PowerShellStdoutFileName, [string] $Expression, [int] $TSRemoteLevel)
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote [BuildRemoteDiagFile]")
		continue
	}

	$DiagFileContent = ". ./utils_cts.ps1`r`n"
	$DiagFileContent += ". ./utils_remote.ps1`r`n"
	$DiagFileContent += '$global:TS_RemoteLevel=' + $TSRemoteLevel + "`r`n"
	$DiagFileContent += "start-transcript -path `"" + $PowerShellStdoutFileName + "`"`r`n`r`n"
	
	$DiagFileContent += $Expression + "`r`n`r`n"

	$DiagFileContent += "EndDataCollection`r`n"
	$DiagFileContent += "stop-transcript"

	"Creating script [" + $DiagScriptName + "] with the following contents:`r`n" + $DiagFileContent | WriteTo-StdOut -ShortFormat
	
	$Error.Clear()
	
	Add-Content -Path $DiagScriptName -Value $DiagFileContent -Force -Encoding "UTF8"
	
	if ($Error.Count -eq 0)
	{
		return $true
	} else {
		return $false
	}
}

Function GetProcessStatus([String] $MachineName, [int] $RemoteProcessID)
{
	trap {continue}
	
	if ($Host.Version.Major -lt 2) 
	{
		Get-CimInstance -Class "Win32_Process" -ComputerName $MachineName -Filter "ProcessId = $RemoteProcessID"
	}
	else
	{
		Get-Process -ComputerName $MachineName -Id $RemoteProcessID -ErrorAction SilentlyContinue
	}
}

Function ProcessGetDiagInput ([string] $RemoteSetupPath)
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote [ProcessGetDiagInput]. RemoteSetupPath: $RemoteSetupPath")
		continue
	}
	
	$GetDiagInputXMLPath = Join-Path $RemoteSetupPath "GetDiagInput.xml"

	[xml] $GetDiagInputXML = Get-Content ($GetDiagInputXMLPath)
	Remove-Item $GetDiagInputXMLPath -Force
		
	foreach ($DiagInput in $GetDiagInputXML.SelectNodes("//Item"))
	{
		$RootCauseID = $DiagInput.ID.get_InnerText()
		
		$Parameter = @{}
		$Choice = $null
		
		foreach ($InputParameter in $DiagInput.Parameters.Parameter)
		{
			if ($null -ne $InputParameter)
			{
				$Parameter.Add($InputParameter.Name, $InputParameter.get_InnerText())
			}
		}


		if ($null -ne $DiagInput.Choices)
		{
			#Choices are saved on a separate file
			$Choice = Import-Clixml -Path (Join-Path $RemoteSetupPath "Choices.xml")
			Remove-Item (Join-Path $RemoteSetupPath "Choices.xml") -Force
		}

		if (($null -ne $Choice) -and ($Parameter.Count -ne 0))
		{
			$Answer = Get-DiagInput -Id $RootCauseID -Parameter $Parameter -Choice $Choice
		} 
		elseif (($null -ne $Choice) -and ($Parameter.Count -eq 0)) 
		{
			$Answer = Get-DiagInput -Id $RootCauseID -Choice $Choice
		} elseif (($null -eq $Choice) -and ($Parameter.Count -ne 0)) 
		{
			$Answer = Get-DiagInput -Id $RootCauseID -Parameter $Parameter
		} elseif (($null -eq $Choice) -and ($Parameter.Count -eq 0)) 
		{
			$Answer = Get-DiagInput -Id $RootCauseID 
		}

		$Answer | Export-Clixml -Path (Join-Path $RemoteSetupPath  "GetDiagInputResponse.xml")
	}
}

Function SaveMachineListRunExpressionInfo($ComputerNames,$RemoteMachineRemoteSetupPath,$RemoteMachineLocalSetupPath,$RemoteMachineBuild,$RemoteMachineSystemFolder,$RemoteMachineWindowsFolder,$RemoteMachineOSArch,$RemoteMachineProductType,$RemoteMachineSKU,$RemoteMachinePlatform)
{
	$RemoteMachineListRunExpressionInfo = [xml] "<?xml version=""1.0"" ?><Root></Root>"
	$RootElement = $RemoteMachineListRunExpressionInfo.SelectSingleNode("/Root")
	foreach($MachineName in $ComputerNames)
	{
		$RemoteSetupPath = $RemoteMachineRemoteSetupPath.Get_Item($MachineName)
		$LocalSetupPath = $RemoteMachineLocalSetupPath.Get_Item($MachineName)
		$OSBuildNumber = $RemoteMachineBuild.get_Item($MachineName)
		$OSSystemFolder = $RemoteMachineSystemFolder.get_Item($MachineName)
		$OSWindowsFolder = $RemoteMachineWindowsFolder.get_Item($MachineName)
		$OSArch = $RemoteMachineOSArch.get_Item($MachineName)
		$ProductType = $RemoteMachineProductType.get_Item($MachineName)
		$MachineSKU = $RemoteMachineSKU.get_Item($MachineName)
		$OSPL = $RemoteMachinePlatform.get_Item($MachineName)
		if(($null -ne $OSBuildNumber) -and ($null -ne $OSSystemFolder))
		{
			$Element = $RemoteMachineListRunExpressionInfo.CreateElement("Machine")
			[Void]$Element.SetAttribute("Name",$MachineName.ToString().ToLower())
		    $XmlStr = "<RemoteSetupPath>$RemoteSetupPath</RemoteSetupPath><LocalSetupPath>$LocalSetupPath</LocalSetupPath><OSBuildNumber>$OSBuildNumber</OSBuildNumber><OSSystemFolder>$OSSystemFolder</OSSystemFolder><OSWindowsFolder>$OSWindowsFolder</OSWindowsFolder><OSArch>$OSArch</OSArch><ProductType>$ProductType</ProductType><MachineSKU>$MachineSKU</MachineSKU><OSPL>$OSPL</OSPL>"
			[Void]$Element.set_InnerXml($XmlStr)
			[Void]$RootElement.AppendChild($Element)
		}
	}
	$RemoteMachineRunExpressionInfoPath = Join-Path $Env:TEMP "RemoteMachineRunExpressionInfo.tmp"
	$RemoteMachineListRunExpressionInfo.Save($RemoteMachineRunExpressionInfoPath)
}

Function AddMachineProcessIdInXmlForTerminate($MachineName,$ProcessID)
{
	$RemoteMachineRunExpressionInfoPath = Join-Path $Env:TEMP "RemoteMachineRunExpressionInfo.tmp"
	if(Test-Path $RemoteMachineRunExpressionInfoPath)
	{
		[xml]$RemoteMachineRunExpressionInfo = Get-Content $RemoteMachineRunExpressionInfoPath
		$MachineElement = $RemoteMachineRunExpressionInfo.SelectSingleNode("/Root/Machine[@Name ='" + $MachineName.ToString().ToLower() + "']")
		if($null -ne $MachineElement)
		{
			if($null -eq $MachineElement.ProcessIdList)
			{
				$ProcessIdListElement = $RemoteMachineRunExpressionInfo.CreateElement("ProcessIdList")
				$ProcessIdElement = $RemoteMachineRunExpressionInfo.CreateElement("ProcessId")
				[void]$ProcessIdElement.set_InnerText($ProcessID)
				[void]$ProcessIdListElement.AppendChild($ProcessIdElement)
				[void]$MachineElement.AppendChild($ProcessIdListElement)
			}
			else
			{
				$ProcessIdElement = $RemoteMachineRunExpressionInfo.CreateElement("ProcessId")
				[void]$ProcessIdElement.set_InnerText($ProcessID)
				[void]$MachineElement.SelectSingleNode("ProcessIdList").AppendChild($ProcessIdElement)
			}
		}
		$RemoteMachineRunExpressionInfo.Save($RemoteMachineRunExpressionInfoPath)
		
	}
}

Function ExecuteRemoteExpression($ComputerNames, $Expression, [switch] $ShowDialog)
{	
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote Error [$MachineName] [ExecuteRemoteExpression]")
		continue
	}

	$Error.Clear()
	
	$ServerCoreSKUs = @(12,13,14,42)

	$RemoteMachineStateInformation = @{}
	$RemoteMachineOSName = @{}
	$RemoteMachineProductType = @{}
	$RemoteMachineBuild = @{}
	$RemoteMachineSKU = @{}
	$RemoteMachineWindowsFolder = @{}
	$RemoteMachineSystemFolder = @{}
	$RemoteMachineRemoteSetupPath = @{}
	$RemoteMachineLocalSetupPath = @{}
	$DiagnosticProcessesID = @{}
	$RootCauseScriptsProcessIDTable = @{}
	$RemoteMachineOSArch= @{}
	$RemoteMachinePlatform = @{}
	$ExpressionToRun = @{}

	$ItemNumber = 0
	
	$ComputerNamesDisplay = $ComputerNames
	if ($ComputerNamesDisplay -is [array]) {$ComputerNamesDisplay = [string]::Join($ComputerNames, ', ')}
	
	"Starting TS_Remote... Target Machine(s): " + $ComputerNamesDisplay | WriteTo-StdOut -ShortFormat
	if ((($ComputerNames -is [string]) -or ($ComputerNames -is [array])) -and ($null -ne $Expression))
	{
		foreach ($MachineName in $ComputerNames)
		{
			#Try to connect to every machine in $Computernames Array. It is expected all machines to return $MachineState.WMIConnected from here. Any machine with a different state will not be processed
			#Build Original HashTable
			
			$MachineName = $MachineName.ToUpper().Trim()
			
			$RemoteMachineStateInformation.Add($MachineName, $MachineState["Untouched"])
			
			if ($Expression -is [array])
			{
				$ExpressionToRun.Add($MachineName, $Expression.Get($ItemNumber))
			}
			else
			{
				$ExpressionToRun.Add($MachineName, $Expression)
			}
			
			$RemoteMachineOS = GetWin32OSFromRemoteSystem $MachineName
			
			if ($RemoteMachineOS -is [WMI]) 
			{
					#Build Variables
					
					$RemoteMachineStateInformation.set_Item($MachineName,$MachineState["WMIConnected"])
					$OSName = $RemoteMachineOS.Caption.Replace('Microsoft', '').replace([string]([char] 174), '').replace([string]([char] 8482), '').Replace('(R)', '').Trim()
					$RemoteMachineOSName.Add($MachineName, $OSName)
					$RemoteMachineBuild.Add($MachineName, $RemoteMachineOS.BuildNumber)
					$RemoteMachineSKU.Add($MachineName, $RemoteMachineOS.OperatingSystemSKU)
					$RemoteMachineWindowsFolder.Add($MachineName, $RemoteMachineOS.WindowsDirectory)
					$RemoteMachineSystemFolder.Add($MachineName, $RemoteMachineOS.SystemDirectory)
					$RemoteMachineProductType.Add($MachineName, $RemoteMachineOS.ProductType)
					
					if ($RemoteMachineOS.OSArchitecture -match "32-bit")
					{
						$OSPlat = "i386"
						$OSArchitecture = "32-bit"
					}
					else 
					{
						$Win32Processor = GetWin32Processor $MachineName
						
						if ($null -ne $Win32Processor)
						{
							Switch ($Win32Processor.AddressWidth)
							{
								32 {$OSArchitecture = "32-bit"}
								64 {$OSArchitecture = "64-bit"}
							}
							Switch ($Win32Processor.Architecture)
							{
								0	{$OSPlat = "i386"}
								6   {$OSPlat = "IA64"}
								9   {$OSPlat = "AMD64"}
								default {$OSPlat = "Unknown [" + $Win32Processor.Architecture + "]"}
							}
						}
					}
					$RemoteMachineOSArch.Add($MachineName, $OSArchitecture)
					$RemoteMachinePlatform.Add($MachineName, $OSPlat)
					
					$DiagFolderName = "TEMP\Diagnostics\" + [System.IO.Path]::GetFileName($PWD.Path)
					
					if ($MachineName -ne $Env:COMPUTERNAME) 
					{
						$RemoteMachineRemoteSetupPath.Add($MachineName, "\\" + $MachineName + "\Admin$\$DiagFolderName")
					} else {
						#Local Machine: $RemoteMachineLocalSetupPath and $RemoteMachineRemoteSetupPath points to the same location
						$RemoteMachineRemoteSetupPath.Add($MachineName, $Env:SystemRoot + "\$DiagFolderName")
					}
					$RemoteMachineLocalSetupPath.Add($MachineName, ($RemoteMachineOS.WindowsDirectory + "\$DiagFolderName"))

			} else {
				$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["ErrorConnectingMachineWMI"])
			}
			$ItemNumber += 1
		}

		
		SaveMachineListRunExpressionInfo -ComputerNames $ComputerNames -RemoteMachineBuild $RemoteMachineBuild -RemoteMachineLocalSetupPath $RemoteMachineLocalSetupPath `
		-RemoteMachineOSArch $RemoteMachineOSArch -RemoteMachineProductType $RemoteMachineProductType -RemoteMachineRemoteSetupPath $RemoteMachineRemoteSetupPath `
		-RemoteMachineSKU $RemoteMachineSKU -RemoteMachineSystemFolder $RemoteMachineSystemFolder -RemoteMachineWindowsFolder $RemoteMachineWindowsFolder -RemoteMachinePlatform $RemoteMachinePlatform
		
		
		#Run the TS_MonitorDiagExecution to monitor the execution
		.\TS_MonitorDiagExecution.ps1 -ScriptBlockToExecute (get-content TS_RestoreConfig.ps1 | Out-String) -SessionName "TS_Remote"
		
		#Connect to every machine with sucessfully WMI connection to check if OS is Supported. Then install PowerShell
		foreach ($Machine in $RemoteMachineStateInformation.GetEnumerator() | Where-Object {$_.Value -eq $MachineState["WMIConnected"]})
		{	
			$MachineName = $Machine.Name
			$OSBuildNumber = $RemoteMachineBuild.Get_Item($MachineName)
			$PowerShellInstalled = IsPowerShellInstalled $MachineName
			
			if ($null -ne $PowerShellInstalled)
			{
				if (-not $PowerShellInstalled)
				{
					$DiagResponse = "Continue"
					
					if ($ShowDialog.IsPresent)
					{
						$DiagResponse = (get-diaginput -id "PowerShellNotInstalledOnRemoteMachine" -Parameter @{"Machine"=$MachineName})
						if ($DiagResponse.Count -gt 0)
						{
							$DiagResponse = $DiagResponse[0]
						}
					}	
					
					if ($DiagResponse -eq "Continue") 
					{
						if ($OSBuildNumber -gt 7000)
						{
							#PowerShell is built-in on every Windows 7 SKU, except ServerCoreR2
							
							if ($ServerCoreSKUs -contains $RemoteMachineSKU.Get_Item($MachineName))
							{
								$LocalSetupPath = $RemoteMachineWindowsFolder.Get_Item($MachineName) + "\TEMP"
								
								if ($MachineName -eq $ComputerName)
								{
									$RemoteSetupPath = $LocalSetupPath
								} else {
									$RemoteSetupPath = "\\" + $MachineName + "\admin$\TEMP"
								}
								
								#ServerCore machine. Install PowerShell.
								if ($ShowDialog.IsPresent)
								{
									$PowerShellInstalled = InstallServerCoreComponents -RemoteMachine $MachineName -LocalTempPath $LocalSetupPath -RemoteTempPath $RemoteSetupPath -ShowDialog 
								} 
								else 
								{
									$PowerShellInstalled = InstallServerCoreComponents -RemoteMachine $MachineName -LocalTempPath $LocalSetupPath -RemoteTempPath $RemoteSetupPath
								}
								
								if ($PowerShellInstalled)
								{
									$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["PowershellInstalled"])
								}
								else 
								{
									$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["PowershellNotInstalled"])
								}				
							}
						} 
						else 
						{
							if (($OSBuildNumber -ge 2600) -and ($OSBuildNumber -lt 7000))
							{
								$LocalTempPath = $RemoteMachineWindowsFolder.Get_Item($MachineName) + "\TEMP"
								
								if ($MachineName -eq $ComputerName)
								{
									$RemoteTempPath = $LocalTempPath
								} else {
									$RemoteTempPath = "\\" + $MachineName + "\admin$\TEMP"
								}

								$OSArch = $RemoteMachineOSArch.Get_Item($MachineName)
								$OSPlat = $RemoteMachinePlatform.Get_Item($MachineName)
								$ProductType = $RemoteMachineProductType.Get_Item($MachineName)
								
								if ($ServerCoreSKUs -contains $RemoteMachineSKU.Get_Item($MachineName))
								{
									$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["UnsupportedOS"])
									"Warning: Unable to run Diagnostic on machine " + $MachineName + " since it is running ServerCore Non-R2 Version. Unable to install PowerShell on this OS." | WriteTo-StdOut -ShortFormat
									#Ups - ServerCore from Windows Server 2008 does not support PowerShell
								} else {
								
									if (DownloadAndInstallPowerShellonFullSystem -MachineName $MachineName -LocalTempPath $LocalTempPath -RemoteTempPath $RemoteTempPath -OSArch $OSArch -OSBuildNumber $OSBuildNumber -ProductType $ProductType -OSPlat $OSPlat)
									{
										if (IsPowerShellInstalled $MachineName)
										{
											$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["PowershellInstalled"])
										} 
										else 
										{
											$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["PowershellNotInstalled"])
										}
									} 
									else 
									{
										$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["PowershellNotInstalled"])
									}
									
								}
							} else {
								$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["UnsupportedOS"])
								"Warning: Unable to run Diagnostic on machine " + $MachineName + " since it is running an unsupported OS: [" + $RemoteMachineOSName.Get_Item($MachineName) + "]" | WriteTo-StdOut -ShortFormat
							}
						}		
					} 
					else 
					{
						$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["UserDeniedPowerShell"])
					}
				} 
				else 
				{
					$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["PowershellInstalled"])
				}
			}
			else
			{	
				# $PowerShellInstalled = $null means the remote registry could not be accessed
				$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["UnableToAccessRemoteRegistry"])
			}
		}
		
		#WriteMachinesStatetoStdOut -MachineStateTable $RemoteMachineStateInformation -AdditionalComment "After connecting to machine via WMI"
		
		#Connect to every machine with PowerShell Installed and Set Execution Policy to RemoteSigned
		foreach ($Machine in $RemoteMachineStateInformation.GetEnumerator() | Where-Object {$_.Value -eq $MachineState["PowershellInstalled"]})
		{	
			$MachineName = $Machine.Name
			
			$LocalTempPath = $RemoteMachineWindowsFolder.Get_Item($MachineName) + "\TEMP"
			
			if ($MachineName -eq $ComputerName)
			{
				$RemoteTempPath = $LocalTempPath
			} else {
				$RemoteTempPath = "\\" + $MachineName + "\admin$\TEMP"
			}


			$ExecutionPolicyRemoteSigned = SetExecutionPolicyOnRemoteSystem -MachineName $MachineName -LocalOutputFolder $LocalTempPath -RemoteOutputFolder $RemoteTempPath
			
			if ($ExecutionPolicyRemoteSigned) 
			{
				$RemoteMachineStateInformation.Set_Item($MachineName,$MachineState["PowershellExecutionPolicySet"])
			} else {
				$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["ErrorSettingExecutionPolicy"])
			}
		}
		
		#WriteMachinesStatetoStdOut -MachineStateTable $RemoteMachineStateInformation -AdditionalComment "After setting PowerShell Execution Policy to RemoteSigned"
			
		#Connect to every machine with PowerShell installed and eequired Execution Policy to copy Diagnostic Package to remote machine
		foreach ($Machine in $RemoteMachineStateInformation.GetEnumerator() | Where-Object {$_.Value -eq $MachineState["PowershellExecutionPolicySet"]})
		{
			$MachineName = $Machine.Name
			$RemoteSetupPath = $RemoteMachineRemoteSetupPath.Get_Item($MachineName)
			$LocalSetupPath = $RemoteMachineLocalSetupPath.Get_Item($MachineName)
			$ExpressionString = $ExpressionToRun.Get_Item($MachineName)
			
			$CopyResults = CopyDiagnosticToRemoteMachine -MachineName $MachineName -RemoteFolder $RemoteSetupPath
			if ($CopyResults -eq $true) 
			{
				$DiagScriptName = (Join-Path -Path $RemoteSetupPath -ChildPath "TS_RemoteTroubleshootingScript.ps1")
				$PowerShellStdOut = $LocalSetupPath + "\Output\RemoteStdout.out"

				if ($MachineName -eq $ComputerName)
				{
					$TSRemoteLevel = 1
				}
				else
				{
					$TSRemoteLevel = 2
				}
				
				BuildRemoteDiagFile -DiagScriptName $DiagScriptName -PowerShellStdoutFileName $PowerShellStdOut -Expression $ExpressionString -TSRemoteLevel $TSRemoteLevel
				$RemoteMachineStateInformation.set_Item($MachineName,$MachineState["BuiltRemoteEnvironment"])
			} else {
				$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["ErrorBuildingRemoteEnvironment"])
			}
		}
		
		#WriteMachinesStatetoStdOut -MachineStateTable $RemoteMachineStateInformation -AdditionalComment "After setting Copying diagnostic package to remote machine"
		
		#Start Script Execution on Remote Machines
		
		foreach ($Machine in $RemoteMachineStateInformation.GetEnumerator() | Where-Object {$_.Value -eq $MachineState["BuiltRemoteEnvironment"]})
		{
			$MachineName = $Machine.Name
			$RemoteSetupPath = $RemoteMachineRemoteSetupPath.Get_Item($MachineName)
			$LocalSetupPath = $RemoteMachineLocalSetupPath.Get_Item($MachineName)
			$PSExpressionToRun = $ExpressionToRun.Get_Item($MachineName)
			$OSName = $RemoteMachineOSName.get_Item($MachineName)
			$OSSystemFolder = $RemoteMachineSystemFolder.get_Item($MachineName)
			
			$DiagScriptName = (Join-Path -Path $LocalSetupPath -ChildPath "TS_RemoteTroubleshootingScript.ps1")
			
			if ($MachineName -ne $ComputerName)
			{
				$LocalRemoteDisplay = $RemoteSetupStrings.ID_TSRemoteRemote
			} else {
				$LocalRemoteDisplay = $RemoteSetupStrings.ID_TSRemoteLocal
			}
			
			Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteStarting -replace("%Machine%", $MachineName))  -Status ($RemoteSetupStrings.ID_TSRemoteStartingDesc -replace("%LocalRemote%", $LocalRemoteDisplay) -replace("%OSName%", $OSName))
			
			$LocalPowerShellPath = $OSSystemFolder + "\WindowsPowerShell\v1.0\powershell.exe"
				
			$RemotePowerShellCommandLine = "`"" + $LocalPowerShellPath + "`" -command `"&{" + $DiagScriptName + "}`""
			
			$RemoteProcessID = RunRemoteProcess -MachineName $MachineName -ProcessNameAndArguments $RemotePowerShellCommandLine -Asynchronous -LocalCurrentFolder $LocalSetupPath -LocalOutputFolder ($LocalSetupPath + "\Output") -RemoteOutputFolder ($LocalSetupPath + "\Output") -DirectExecution
			AddMachineProcessIdInXmlForTerminate -MachineName $MachineName -ProcessID $RemoteProcessID
			if ($RemoteProcessID -gt 0)
			{
				$RemoteMachineStateInformation.set_Item($MachineName,$MachineState["RunningDiagnosticScript"])
				$DiagnosticProcessesID.Add($MachineName, $RemoteProcessID)
			} else {
				$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["FailedRunningDiagnosticScript"])
			}
		}
		#Wait for Diagnostic Scripts to Finish on all machines, showing status messages
		do 
		{
			$DiagStillRunning = $False
			foreach ($Machine in $RemoteMachineStateInformation.GetEnumerator() | Where-Object {$_.Value -eq $MachineState["RunningDiagnosticScript"]})
			{
				$Wait3Seconds = $true
				$DiagStillRunning = $true
				$MachineName = $Machine.Name
				$RemoteProcessID = $DiagnosticProcessesID.get_Item($MachineName)
				$RemoteSetupPath = $RemoteMachineRemoteSetupPath.Get_Item($MachineName)
				$OSName = $RemoteMachineOSName.get_Item($MachineName)
				$RemoteDiagnosticInstance = $null
				$RemoteDiagnosticInstance = GetProcessStatus -MachineName $MachineName -RemoteProcessID $RemoteProcessID
				
				if ($null -ne $RemoteDiagnosticInstance)
				{
					#Update Status
					if (Test-Path ($RemoteSetupPath + "\Output\WriteDiagProgress.txt"))
					{
						trap [Exception] {continue}

						$RemoteStatus = Get-Content -Path ($RemoteSetupPath + "\Output\WriteDiagProgress.txt") -ErrorAction SilentlyContinue
						if ($null -ne $RemoteStatus)
						{
							Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteRunningDiag -replace("%Machine%", $MachineName) -replace("%OSName%", $OSName)) -Status $RemoteStatus
						} 
						else 
						{
							Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteRunningDiag -replace("%Machine%", $MachineName) -replace("%OSName%", $OSName)) -Status $RemoteSetupStrings.ID_TSRemoteWaiting
						}
					}
				} 
				else 
				{
					#Diagnostic Script instance is null - meaning the diagnostic execution finished on remote machine
					$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["FinishedRunningDiagnosticScript"])
					$Wait3Seconds = $false
				}
				#Wait three seconds.
				if ($Wait3Seconds) 
				{
					Start-Sleep -Seconds 3
				}
				
				if (Test-Path -Path ($RemoteSetupPath + "\Output\GetDiagInput.xml"))
				{
					ProcessGetDiagInput -RemoteSetupPath ($RemoteSetupPath + "\Output")
				}
				#Go to the next machine.
			}
		} while ($DiagStillRunning)
		
		WriteMachinesStatetoStdOut -MachineStateTable $RemoteMachineStateInformation -AdditionalComment "After Running Diagnostics on all remote machines"

		Write-DiagProgress -Activity $RemoteSetupStrings.ID_TSRemotePreparingData -Status $RemoteSetupStrings.ID_TSRemotePreparingDataDesc

		#Powershell.exe finished execution on remote systems. Next step: Collect data
		foreach ($Machine in $RemoteMachineStateInformation.GetEnumerator() | Where-Object {$_.Value -eq $MachineState["FinishedRunningDiagnosticScript"]})
		{
			$MachineName = $Machine.Name
			$RemoteSetupPath = $RemoteMachineRemoteSetupPath.Get_Item($MachineName)
			
			ObtainRemoteStdoutContent -MachineName $MachineName -RemoteSetupPath $RemoteSetupPath -From "Diagnostic script execution"
			if (CollectRemoteData -MachineName $MachineName -RemoteSetupPath $RemoteSetupPath)
			{
				$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["DataCollected"])
			}
		}

		#Process Root Causes
		foreach ($Machine in $RemoteMachineStateInformation.GetEnumerator() | Where-Object {($_.Value -gt $MachineState["FinishedRunningDiagnosticScript"]) -and ($_.Value -lt $MachineState["ErrorConnectingMachineWMI"])})
		{
			$MachineName = $Machine.Name
			$RemoteSetupPath = $RemoteMachineRemoteSetupPath.Get_Item($MachineName)
			$RemoteSetupPath = $RemoteMachineRemoteSetupPath.Get_Item($MachineName)
			$LocalSetupPath = $RemoteMachineLocalSetupPath.Get_Item($MachineName)
			$OSSystemFolder = $RemoteMachineSystemFolder.get_Item($MachineName)
			$LocalPowerShellPath = $OSSystemFolder + "\WindowsPowerShell\v1.0\powershell.exe"
			
			$RootCauseScriptProcessID = (ProcessRootCauses -MachineName $MachineName -LocalSetupPath $LocalSetupPath -RemoteSetupPath $RemoteSetupPath -LocalPowerShellPath $LocalPowerShellPath)
			AddMachineProcessIdInXmlForTerminate -MachineName $MachineName -ProcessID $RootCauseScriptProcessID
			if ($RootCauseScriptProcessID -gt 0)
			{	
				$RootCauseScriptsProcessIDTable.Add($MachineName, $RootCauseScriptProcessID)
				$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["ProcessingRootCauseScript"])
			} 
			else 
			{
				if ($RootCauseScriptProcessID -eq 0) #This means that a root cause was detected but Root Cause script process could not be initiated
				{
					$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["ErrorProcessingRootCauseScript"])
				}
			}
		}
		
		#WriteMachinesStatetoStdOut -MachineStateTable $RemoteMachineStateInformation -AdditionalComment "After Starting Root Cause Scripts on all remote machines"
		
		#Wait for Root Cause Scripts to Finish on all machines, showing status messages
		do 
		{
			$DiagStillRunning = $False
			$Wait3Seconds = $true
			foreach ($Machine in $RemoteMachineStateInformation.GetEnumerator() | Where-Object {$_.Value -eq $MachineState["ProcessingRootCauseScript"]})
			{
				$DiagStillRunning = $true
				$MachineName = $Machine.Name
				$RemoteProcessID = $RootCauseScriptsProcessIDTable.get_Item($MachineName).ToString()
				$RemoteSetupPath = $RemoteMachineRemoteSetupPath.Get_Item($MachineName)
				
				$RemoteDiagnosticInstance = $null
				$RemoteDiagnosticInstance = GetProcessStatus -MachineName $MachineName -RemoteProcessID $RemoteProcessID
				
				if ($null -ne $RemoteDiagnosticInstance)
				{
					#Update Status
					$RemoteStatus = Get-Content -Path ($RemoteSetupPath + "\Output\WriteDiagProgress.txt") -ErrorAction SilentlyContinue
					if ($null -ne $RemoteStatus)
					{
						Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteProcessingRootCauses  -replace("%Machine%", $MachineName)) -Status $RemoteStatus
					} else {
						Write-DiagProgress -Activity ($RemoteSetupStrings.ID_TSRemoteProcessingRootCauses  -replace("%Machine%", $MachineName)) -Status $RemoteSetupStrings.ID_TSRemoteWaiting
					}
				} else {
					#Diagnostic Script instance is null - meaning the diagnostic execution finished on remote machine
					$RemoteMachineStateInformation.set_Item($MachineName, $MachineState["FinishedRootCauseScript"])
					$Wait3Seconds = $false
				}
				#Wait three seconds. Go to the next machine.
				if ($Wait3Seconds) 
				{
					Start-Sleep -Seconds 3
					#Check for a Get-DiagInput
				}
				
				if (Test-Path -Path ($RemoteSetupPath + "\Output\GetDiagInput.xml"))
				{
					ProcessGetDiagInput -RemoteSetupPath ($RemoteSetupPath + "\Output")
				}
			}
		} while ($DiagStillRunning)
		
		#WriteMachinesStatetoStdOut -MachineStateTable $RemoteMachineStateInformation -AdditionalComment "After Finishing Running Root Cause Scripts on all remote machines"
		
		#Add the RemoteStdout.log from the Remote RootCause execution to the local Stdout.log
		foreach ($Machine in $RemoteMachineStateInformation.GetEnumerator() | Where-Object {$_.Value -eq $MachineState["FinishedRootCauseScript"]})
		{
			$MachineName = $Machine.Name
			$RemoteSetupPath = $RemoteMachineRemoteSetupPath.Get_Item($MachineName)
			$RemoteStdOut = $RemoteSetupPath + "\Output\RemoteStdout.out"
			
			if (Test-Path ($RemoteStdOut))
			{
				$StdoutContent = "Stdout output for PowerShell Root Cause Processing on " + $MachineName + ": `r`n" + ("-" * 70) + "`r`n`r`n"
				$StdoutRawContent = (Get-Content -Path $RemoteStdOut)
				if ($null -ne $StdoutRawContent) {$StdoutContent += [String]::Join("`r`n     | ", $StdoutRawContent)}
				Remove-Item $RemoteStdOut -ErrorAction Continue
				$StdoutContent | WriteTo-StdOut -ShortFormat
			
				ObtainRemoteStdoutContent -MachineName $MachineName -RemoteSetupPath $RemoteSetupPath  -From "Root cause script execution"
				
			} else {
				"`r`n[CollectRemoteData] Warning: unable to open : " + $RemoteStdOut | WriteTo-StdOut
			}
		}
		
		#Remove Remote Components from all machines - Except the ones with root cause detected. In this case, data will be deleted only after root cause processing - see EndDataCollection below
		foreach ($Machine in $RemoteMachineStateInformation.GetEnumerator() | Where-Object {(($_.Value -ge $MachineState["PowershellExecutionPolicySet"]) -and ($_.Value -lt $MachineState["ErrorBuildingRemoteEnvironment"]) -and ($_.Value -ne $MachineState["FinishedRootCauseScript"]))})
		{
			$MachineName = $Machine.Name
			$RemoteSetupPath = $RemoteMachineRemoteSetupPath.Get_Item($MachineName)
			DeleteRemoteComponents -MachineName $MachineName -RemoteSetupPath $RemoteSetupPath
		}

		#And finally, restore PowerShell ExecutionPolicy on all remote machines
		foreach ($Machine in $RemoteMachineStateInformation.GetEnumerator() | Where-Object {(($_.Value -ge $MachineState["PowershellExecutionPolicySet"]) -and ($_.Value -lt $MachineState["ErrorSettingExecutionPolicy"]))})
		{
			$MachineName = $Machine.Name
			$LocalTempPath = $RemoteMachineWindowsFolder.Get_Item($MachineName) + "\TEMP"
			
			if ($MachineName -eq $ComputerName)
			{
				$RemoteTempPath = $LocalTempPath
			} else {
				$RemoteTempPath = "\\" + $MachineName + "\admin$\TEMP"
			}

			RestoreExecutionPolicyOnRemoteSystem -MachineName $MachineName -LocalOutputFolder $LocalTempPath -RemoteOutputFolder $RemoteTempPath 
		}
		
		#Now set the root cases that were not detected
		$RootCauseArgumentsXMLPath = [System.IO.Path]::GetFullPath("..\DiagnosticRootCauseArguments.xml")
		
		if (Test-Path -Path $RootCauseArgumentsXMLPath)
		{	
			[xml] $XMLDiagnosticRootCauseArguments = Get-Content -Path $RootCauseArgumentsXMLPath

			foreach ($MachineArguments in $XMLDiagnosticRootCauseArguments.SelectNodes("/Root/RootCauseDetected"))
			{
				$RootCauseID = $MachineArguments.RootCauseID
				foreach ($RootCauseNotDetectedNode in $XMLDiagnosticRootCauseArguments.SelectNodes("/Root/RootCauseNotDetected[RootCauseID = `'$RootCauseID`']"))
				{
					$RootCauseNotDetectedNode.Processed = "True"
				}
			}

			foreach ($NotDetectedRootCause in $XMLDiagnosticRootCauseArguments.SelectNodes("//RootCauseNotDetected[@Processed = `'False`']") | Select-Object -Property RootCauseID -Unique)
			{
				Update-DiagRootCause -Id $NotDetectedRootCause.RootCauseID -Detected $false
			}
		}
		
		#disable logging and end the TS_MonitorDiagExecution
		.\TS_MonitorDiagExecution.ps1 -EndMonitoring -SessionName "TS_Remote"
		
		$RemoteMachineRunExpressionInfoPath = Join-Path $Env:TEMP "RemoteMachineRunExpressionInfo.tmp"
		if(Test-Path -Path $RemoteMachineRunExpressionInfoPath)
		{
			Remove-Item -Path $RemoteMachineRunExpressionInfoPath -Force -ErrorAction SilentlyContinue
		}
		
		#Now, show information about diagnostic execution status on report
		
		$DiagnosticExecution_Summary = new-object PSObject
		foreach ($Machine in $RemoteMachineStateInformation.GetEnumerator())
		{
			$MachineName = $Machine.Name
			$OSName = $RemoteMachineOSName.get_Item($MachineName)
			
			switch ($Machine.Value)
			{
				$MachineState["ErrorConnectingMachineWMI"] 
				{
					add-member -inputobject $DiagnosticExecution_Summary -membertype noteproperty -name $MachineName -value ("<font face=`"Webdings`" color=`"Red`">n</font> Error connected to machine via WMI")
				}		
				$MachineState["UnsupportedOS"] 
				{
					add-member -inputobject $DiagnosticExecution_Summary -membertype noteproperty -name $MachineName -value ("<font face=`"Webdings`" color=`"Red`">n</font> OS Not supported: $OSName")
				}		
				$MachineState["PowerShellNotInstalled"] 
				{
					add-member -inputobject $DiagnosticExecution_Summary -membertype noteproperty -name $MachineName -value ("<font face=`"Webdings`" color=`"Red`">n</font> PowerShell could not be installed")
				}
				$MachineState["UserDeniedPowerShell"]
				{
					add-member -inputobject $DiagnosticExecution_Summary -membertype noteproperty -name $MachineName -value ("<font face=`"Webdings`" color=`"Red`">n</font> User selected to not install PowerShell")
				}
				$MachineState["ErrorSettingExecutionPolicy"] 
				{
					add-member -inputobject $DiagnosticExecution_Summary -membertype noteproperty -name $MachineName -value ("<font face=`"Webdings`" color=`"Red`">n</font> Unable to set PowerShell execution policy")
				}		
				$MachineState["ErrorBuildingRemoteEnvironment"] 
				{
					add-member -inputobject $DiagnosticExecution_Summary -membertype noteproperty -name $MachineName -value ("<font face=`"Webdings`" color=`"Red`">n</font> Error copying diagnostic package to machine")
				}
				$MachineState["FailedRunningDiagnosticScript"] 
				{
					add-member -inputobject $DiagnosticExecution_Summary -membertype noteproperty -name $MachineName -value ("<font face=`"Webdings`" color=`"Red`">n</font> Unable to start diagnostic scripts")
				}
				$MachineState["ErrorProcessingRootCauseScript"] 
				{
					add-member -inputobject $DiagnosticExecution_Summary -membertype noteproperty -name $MachineName -value ("<font face=`"Webdings`" color=`"Orange`">n</font> Error running root cause detection scripts")
				}		
				$MachineState["FinishedRootCauseScript"] 
				{
					add-member -inputobject $DiagnosticExecution_Summary -membertype noteproperty -name $MachineName -value ("<font face=`"Webdings`" color=`"Green`">n</font> Completed with Root Causes Detected")
				}
				$MachineState["UnableToAccessRemoteRegistry"] 
				{
					add-member -inputobject $DiagnosticExecution_Summary -membertype noteproperty -name $MachineName -value ("<font face=`"Webdings`" color=`"Red`">n</font> Unable to access remote registry")
				}
				Default
				{
					add-member -inputobject $DiagnosticExecution_Summary -membertype noteproperty -name $MachineName -value ("<font face=`"Webdings`" color=`"Green`">n</font> Completed")
				}
			}
		}
		
		$DiagnosticExecution_Summary | ConvertTo-Xml2 | update-diagreport -id zzz_DiagnosticSummary -name "Diagnostic Execution Summary" -verbosity informational

		WriteMachinesStatetoStdOut -MachineStateTable $RemoteMachineStateInformation -AdditionalComment "Finished Running Diagnostic on Remote Machines"
	}
	else
	{
		"TS_Remote Error: An String or Array for -ComputerNames argument is expected and -Expression argument cannot be null. Curent Values: `n`r    -ComputerNames: [$ComputerNames] `n`r    -Expression $Expression" | WriteTo-StdOut
	}
}

Function EndDataCollection([boolean]$DeleteFlagFile=$False)
{
# EndDataCollection function
# ---------------------
# Description:
#        This function should be the last function executed during a CTS Diagnostics.
#        It copies the customized XSL file to the report so it can be visualized when 
#        the ResultsReport.xsl is opened.
#        This function also deletes the file used to flag a first time execution function

	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_Remote Error [EndDataCollection]")
		continue
	}

	Copy-Item .\cts_results.xsl $pwd\result\results.xsl
	
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
	
	if ($DiagProcesses.Count -gt 0)
	{
		Write-DiagProgress -Activity $RemoteSetupStrings.ID_WaitingProcessFinish -Status $RemoteSetupStrings.ID_WaitingProcessFinishDesc
		WaitForBackgroundProcesses 0
	}

	$RootCauseArgumentsXMLPath = [System.IO.Path]::GetFullPath("..\DiagnosticRootCauseArguments.xml")

	if ($DeleteFlagFile -eq $true) 
	{
		#2nd execution
		$DiagFlagFileExist = (Test-Path $FlagFilePath)
		if ($DiagFlagFileExist -eq $true) 
		{
			Remove-Item -path $FlagFilePath
		}

		if (Test-Path -Path $RootCauseArgumentsXMLPath) #There are machines with Root Causes Detected. In this case, delete the diagnostic data
		{	
			[xml] $XMLDiagnosticRootCauseArguments = Get-Content -Path $RootCauseArgumentsXMLPath
	
			foreach ($MachineArguments in $XMLDiagnosticRootCauseArguments.SelectNodes("/Root/RootCauseDetected"))
			{
				$MachineToCleanup = $MachineArguments.MachineName
				$RemoteSetupPath = $MachineArguments.RemoteSetupPath
				DeleteRemoteComponents -Machine $MachineToCleanup -RemoteSetupPath $RemoteSetupPath
			}

			Remove-Item -Path $RootCauseArgumentsXMLPath -Force
		}
		
		if (test-path $StdOutFileName) 
		{
			$ResolverStdoutLog = Join-Path $PWD.Path ([System.IO.Path]::GetFileNameWithoutExtension($StdOutFileName) + "-" + (Get-Random) + ".log")
			Get-Content -Path $StdOutFileName | Out-File $ResolverStdoutLog -Append -Encoding "UTF8"
			Update-DiagReport -Id "stdout file" -Name "Resolvers StdoutFile" -File $ResolverStdoutLog -Verbosity "Debug"
			Remove-Item -Path $StdOutFileName -Force
		}
		
		$GMReportFileName = [System.IO.Path]::GetFullPath((Join-Path $PWD.Path "..\GenericMessageUpdateDiagReport.xml"))
		if (Test-Path -Path ($GMReportFileName))
		{
			Remove-Item -Path $GMReportFileName -Force
		}
		
	} 
	else 
	{
		if (Test-Path -Path $RootCauseArgumentsXMLPath) #There are machines with Root Causes Detected. In this case, delete the diagnostic data
		{
			[xml] $XMLDiagnosticRootCauseArguments = Get-Content -Path $RootCauseArgumentsXMLPath
			
			#Check if there are root causes detected - if not, delete the file once there is not going to be a 2nd time execution.
			if ($XMLDiagnosticRootCauseArguments.SelectNodes("/Root/RootCauseDetected").Count -eq 0)
			{
				Remove-Item -Path $RootCauseArgumentsXMLPath -Force
			}			
		}
	
		if (test-path $StdOutFileName ) 
		{
			Update-DiagReport -Id "stdout file" -Name "stdoutfile" -File $StdOutFileName -Verbosity "Debug"
			Remove-Item -Path $StdOutFileName -Force
		}		
	}
		
	WriteScriptExecutionInformation
}


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAq/CY9w/jwq/sq
# Ys2uCF40lg/iObsN6c4G4zUi74vBAaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPtbsV6fvELNYeJKZbKDHX32
# YqLEmbw7My8u7CYZmjTLMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAzSIHIen1Gqtcz2vUD/y154Z3npWxpaU5icjsZyd8VdytE6+oOemX6
# yozQKgkLGBYz0je78rT6QA/IHWUZISSOhsAZ8yF5bv0uJrJzyBg88YZ4zb23CXVo
# gMTCj5HbWnyNjP8nvq728j5S+n0arg/tr5hcXpmNTqwONmvNXU/96zGIoEomie0e
# eSrS44bSLEVBLTFnXB6TWVz4df/qi6GFRliVJvvbIlbYm36nWTnPBwBXEq3BnHI3
# Ym4+nLnEe9pvCX/n35Vvrmu1XsLHxgZGT1NuPZubCBo81Tife9oPRLsQVRLx/3jb
# R475D+RSqNWnXeKQyMG95h3gxbRO68w9oYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIGoNX5x1WBABVIxFjt1efIJmYFaclDABeTgZvoDBjoKnAgZi3n81
# KjsYEzIwMjIwODAxMDgwNTQyLjU0OFowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046M0JENC00QjgwLTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAYm0v4YwhBxLjwABAAABiTAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDFaFw0yMzAxMjYxOTI3NDFaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNCRDQt
# NEI4MC02OUMzMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvQZXxZFma6plmuOyvNpV
# 8xONOwcYolZG/BjyZWGSk5JOGaLyrKId5VxVHWHlsmJE4SvnzsdpsKmVx8otONve
# IUFvSceEZp8VXmu5m1fu8L7c+3lwXcibjccqtEvtQslokQVx0r+L54abrNDarwFG
# 73IaRidIS1i9c+unJ8oYyhDRLrCysFAVxyQhPNZkWK7Z8/VGukaKLAWHXCh/+R53
# h42gFL+9/mAALxzCXXuofi8f/XKCm7xNwVc1hONCCz6oq94AufzVNkkIW4brUQgY
# pCcJm9U0XNmQvtropYDn9UtY8YQ0NKenXPtdgLHdQ8Nnv3igErKLrWI0a5n5jjdK
# fwk+8mvakqdZmlOseeOS1XspQNJAK1uZllAITcnQZOcO5ofjOQ33ujWckAXdz+/x
# 3o7l4AU/TSOMzGZMwhUdtVwC3dSbItpSVFgnjM2COEJ9zgCadvOirGDLN471jZI2
# jClkjsJTdgPk343TQA4JFvds/unZq0uLr+niZ3X44OBx2x+gVlln2c4UbZXNueA4
# yS1TJGbbJFIILAmTUA9Auj5eISGTbNiyWx79HnCOTar39QEKozm4LnTmDXy0/KI/
# H/nYZGKuTHfckP28wQS06rD+fDS5xLwcRMCW92DkHXmtbhGyRilBOL5LxZelQfxt
# 54wl4WUC0AdAEolPekODwO8CAwEAAaOCATYwggEyMB0GA1UdDgQWBBSXbx+zR1p4
# IIAeguA6rHKkrfl7UDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQCOtLdpWUI4KwfLLrfaKrLB92DqbAspGWM41TaO
# 4Jl+sHxPo522uu3GKQCjmkRWreHtlfyy9kOk7LWax3k3ke8Gtfetfbh7qH0LeV2X
# OWg39BOnHf6mTcZq7FYSZZch1JDQjc98+Odlow+oWih0Dbt4CV/e19ZcE+1n1zzW
# kskUEd0f5jPIUis33p+vkY8szduAtCcIcPFUhI8Hb5alPUAPMjGzwKb7NIKbnf8j
# 8cP18As5IveckF0oh1cw63RY/vPK62LDYdpi7WnG2ObvngfWVKtwiwTI4jHj2cO9
# q37HDe/PPl216gSpUZh0ap24mKmMDfcKp1N4mEdsxz4oseOrPYeFsHHWJFJ6Aivv
# qn70KTeJpp5r+DxSqbeSy0mxIUOq/lAaUxgNSQVUX26t8r+fcikofKv23WHrtRV3
# t7rVTsB9YzrRaiikmz68K5HWdt9MqULxPQPo+ppZ0LRqkOae466+UKRY0JxWtdrM
# c5vHlHZfnqjawj/RsM2S6Q6fa9T9CnY1Nz7DYBG3yZJyCPFsrgU05s9ljqfsSptp
# FdUh9R4ce+L71SWDLM2x/1MFLLHAMbXsEp8KloEGtaDULnxtfS2tYhfuKGqRXoEf
# DPAMnIdTvQPh3GHQ4SjkkBARHL0MY75alhGTKHWjC2aLVOo8obKIBk8hfnFDUf/E
# yVw4uTCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
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
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JENC00QjgwLTY5QzMxJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVACGlCa3ketyeuey7bJNpWkMuiCcQoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmkY8xMCIYDzIwMjIwODAx
# MDczMDU3WhgPMjAyMjA4MDIwNzMwNTdaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaRjzECAQAwBwIBAAICJRswBwIBAAICEXMwCgIFAOaS4LECAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQArnk4S9bEdxCdv6lvAqDJLnushxbjSdiB7sVOCFegm
# 1hIyiOlgngN4YIZy5wYXFTnbUcThdirf/aWO9Kgq7ym54onCUb8XY9R6vBbJz4h4
# 5T/wMIKNVGo2pIyBEGyYLgmsXSYP5pIvgzFhbGvfTynStAvFB//Ows/cSog4V5qO
# JTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABibS/hjCEHEuPAAEAAAGJMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIAHE9zdoh9RVOxW2fiVz
# m2vm4LWdarvE15cNb2+C/pNgMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# ZndHMdxQV1VsbpWHOTHqWEycvcRJm7cY69l/UmT8j0UwgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYm0v4YwhBxLjwABAAABiTAiBCAk
# t45JlrVvo3nFtAGQW8QKtuen+cccumsnztg/aYVKETANBgkqhkiG9w0BAQsFAASC
# AgBjpRJGmm6+wtEXaNz0dL5bDKL28pcLohtiOuajcskQ8ZhPwYlFxX1yHFJRoO7P
# rIEnfQ2+8nIoz9WgCO1xk4Oj+2omsi0Tbu+QstWj7SW0LJSZ1mzRJKwn+tGTEFIu
# jph9il+yQxsq1xa/v43mZynma94RP6rmEATVRvrOvzWWLzqMPhTxd5gf4FhnzuAG
# JakkS85tjtUsrAUCQuh7/VhofwtJVEUglmY8SU0VUQ0HpyhdLeTA5PxHMIc+DgY9
# /bldxKI25hCRM7YNSadaoP4KBh53wzzQEuXXtIk+AsBhiAl7WzcMdlRpqhFvNVsr
# zWl4wT159g7PKESq6Sj/s+qcsFDIU0Wo+o7EBCrpnic1RxluK7Fj6SmwwGUG41Q2
# A4wMucDMt2eykUuxryOJwIuyew0MQcEr9bHxe2GsBb3jLDeCuQDS9jEDN8fkRovA
# eMRwGGIMA4ZbMwuFRvsW7noOaZOuyH7mH7+9+JAffHTt6EUWvbTy8f9UI1mUAmce
# cPrdRMI4tlhLqMDoHb6gjGVOvtWaWX2qV9uxdVZ+UBHD6IF3c6kUh4VTq48gpJGY
# PnajbWwdrOyZ6PtFP759PwowgZ2THrDGO+Q+LqcyFCVwALlDkJYvnwAJe6q2j1pK
# j8jmePeJeOgIwekjBX02BwI3h7hIBdjqR+XNgoTIIthauw==
# SIG # End signature block
