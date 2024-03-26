#************************************************
# DC_Setup_Addons.ps1
# Version 1.1
# Date: 2009-2019
# Author: Walter Eder (waltere@microsoft.com)
# Description: Collects additional Setup information.
# Called from: TS_AutoAddCommands_Setup.ps1
#*******************************************************

Param($MachineName = $Computername, $Path = "")

Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
		 # later use return to return the exception message to an object:   return $Script:ExceptionMessage
	}

Write-verbose "$(Get-Date -UFormat "%R:%S") : Start of script DC_Setup_Addons.ps1"

Import-LocalizedData -BindingVariable ScriptVariable
Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status $ScriptVariable.ID_CTSAddonsDescription


# detect OS version
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber

function isOSVersionAffected
{
	if ([int]$bn -gt [int](9600))
	{
		return $true
	}
	else
	{
		return $false
	}
}

function RunNet ([string]$NetCommandToExecute="")
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSSMBClient -Status "net $NetCommandToExecute"
	
	$NetCommandToExecuteLength = $NetCommandToExecute.Length + 6
	"`n`n`n" + "=" * ($NetCommandToExecuteLength) + "`r`n" + "net $NetCommandToExecute" + "`r`n" + "=" * ($NetCommandToExecuteLength) | Out-File -FilePath $OutputFile -append

	$CommandToExecute = "cmd.exe /c net.exe " + $NetCommandToExecute + " >> $OutputFile "
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
	"`n`n`n" | Out-File -FilePath $OutputFile -append
}


function RunPS ([string]$RunPScmd="", [switch]$ft)
{
	$RunPScmdLength = $RunPScmd.Length
	"-" * ($RunPScmdLength)		| Out-File -FilePath $OutputFile -append
	"$RunPScmd"  				| Out-File -FilePath $OutputFile -append
	"-" * ($RunPScmdLength)  	| Out-File -FilePath $OutputFile -append
	if ($ft)
	{
		# This format-table expression is useful to make sure that wide ft output works correctly
		Invoke-Expression $RunPScmd	|format-table -autosize -outvariable $FormatTableTempVar | Out-File -FilePath $outputFile -Width 500 -append
	}
	else
	{
		Invoke-Expression $RunPScmd	| Out-File -FilePath $OutputFile -append
	}
	"`n`n`n" | Out-File -FilePath $OutputFile -append
}

#--- Section CBS & PNP info, components hive, SideBySide hive, Iemain.log
$sectionDescription = "Windows logs folders"

if(test-path (join-path $Env:windir "Logs"))
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons  -Status "Compress \Logs"
	$DestinationTempFolder = Join-Path ($PWD.Path) ([System.Guid]::NewGuid().ToString())
	Copy-Item "$env:WinDir\Logs" -Destination $DestinationTempFolder -Force -Recurse -ErrorAction SilentlyContinue
	CompressCollectFiles -filesToCollect $DestinationTempFolder -DestinationFileName ($ComputerName + "_Windows-Logs.zip") -fileDescription "Windows Log Folder" -sectionDescription $sectionDescription -Recursive
	Remove-Item $DestinationTempFolder -Force -Recurse
}
if(test-path (join-path $Env:windir "System32\LogFiles"))
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons  -Status "Compress \System32\LogFiles"
	$DestinationTempFolder = Join-Path ($PWD.Path) ([System.Guid]::NewGuid().ToString())
	Copy-Item "$env:WinDir\System32\LogFiles" -Destination $DestinationTempFolder -Force -Recurse -ErrorAction SilentlyContinue
	CompressCollectFiles -filesToCollect $DestinationTempFolder -DestinationFileName ($ComputerName + "_Windows-System32-Logs.zip") -fileDescription "System32 LogFiles Folders" -sectionDescription $sectionDescription -Recursive
	Remove-Item $DestinationTempFolder -Force -Recurse
}

Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons  -Status (join-path $Env:windir "Servicing\Sessions")
$arrWindirLogsFiles = get-childitem -force -path (join-path $Env:windir "Servicing\Sessions") -recurse -exclude *.temp,*.tmp | Where-Object {$_.psIsContainer -eq $false} | ForEach-Object {$_.fullname}
CompressCollectFiles -filesToCollect $arrWindirLogsFiles -fileDescription "Windows\Servicing\Sessions folder" -sectionDescription "Servicing\Sessions Folder" -DestinationFileName ($MachineName + "Windows-Servicing-Sessions.zip") -RenameOutput $true -recursive 

Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons  -Status (join-path $Env:windir "inf")
$arrWindirLogsFiles = get-childitem -force -path (join-path $Env:windir "inf\*") -include *.log | Where-Object {$_.psIsContainer -eq $false} | ForEach-Object {$_.fullname}
CompressCollectFiles -filesToCollect $arrWindirLogsFiles -fileDescription "Windows\inf\*.log" -sectionDescription "inf\*.log" -DestinationFileName ($MachineName + "Windows-Inf-logs.zip") -RenameOutput $true -recursive 

	$filesToCollect = "$env:WinDir\servicing\sessions\sessions.xml"
	$filesDescription = "servicing\sessions\sessions.xml"
	if (test-path $FilesToCollect) {
		CollectFiles -filesToCollect $filesToCollect -fileDescription $filesDescription -sectionDescription $sectionDescription -RenameOutput $true -MachineNamePrefix $ComputerName
	}

	$filesToCollect = "$env:WinDir\Logs\MoSetup\UpdateAgent.log"
	$filesDescription = "MoSetup\UpdateAgent.log"
	if (test-path $FilesToCollect) {
		CollectFiles -filesToCollect $filesToCollect -fileDescription $filesDescription -sectionDescription $sectionDescription -RenameOutput $true -MachineNamePrefix $ComputerName
	}

	$filesToCollect = "$env:WinDir\iemain.log"
	$filesDescription = "iemain.log"
	if (test-path $FilesToCollect) {
		CollectFiles -filesToCollect $filesToCollect -fileDescription $filesDescription -sectionDescription $sectionDescription -RenameOutput $true -MachineNamePrefix $ComputerName
	}

#----------Registry
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Collect Registry files"

	$OutputFile= $MachineName + "_reg_Component_Based_Servicing.HIV"
	RegSave -RegistryKey "HKLM\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing" -OutputFile $OutputFile -fileDescription "Components CBS Hive"

	$OutputFile= $MachineName + "_reg_SideBySide.HIV"
	RegSave -RegistryKey "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide" -OutputFile $OutputFile -fileDescription "SideBySide Hive"

	$OutputFile= $MachineName + "_reg_SideBySide.txt"
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide" -OutputFile $OutputFile -fileDescription "SideBySide Reg key" -Recursive $true
		
#----------Registry Section Misc Registry Info
	$OutputFile= $MachineName + "_reg_Langpack.txt"
	RegQuery -RegistryKeys "HKLM\System\CurrentControlSet\Control\MUI\UILanguages" -OutputFile $OutputFile -fileDescription "Langpack Reg key" -Recursive $true

	$OutputFile= $MachineName + "_reg_services.txt"
	RegQuery -RegistryKeys "HKLM\System\CurrentControlSet\Services" -OutputFile $OutputFile -fileDescription "services Reg key" -Recursive $true
	$OutputFile= $MachineName + "_reg_services.HIV"
	RegSave -RegistryKey "HKLM\System\CurrentControlSet\Services" -OutputFile $OutputFile -fileDescription "services Reg Hive" -Recursive $true
			
	$OutputFile= $MachineName + "_reg_CurrentVersion.txt"
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows NT\CurrentVersion" -OutputFile $OutputFile -fileDescription "Windows NT\CurrentVersion Reg key" -Recursive $true
	$OutputFile= $MachineName + "_reg_CurrentVersion.txt"
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows\CurrentVersion" -OutputFile $OutputFile -fileDescription "Windows\CurrentVersion Reg key" -Recursive $true
	
	$OutputFile= $MachineName + "_reg_BuildInfo.txt"
	$RegKeysValues = "BuildLab", 
					"BuildLabEx", 
					"UBR", 
					"ProductName"
	RegQueryValue -RegistryKeys "HKLM\Software\Microsoft\Windows NT\CurrentVersion" -RegistryValues $RegKeysValues -OutputFile $OutputFile -fileDescription "BuildInfo" -CollectResultingFile $true
	
	$OutputFile= $MachineName + "_reg_AppModelVersion.txt"
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows\CurrentVersion\AppModel" -OutputFile $OutputFile -fileDescription "AppModel Reg key" -Recursive $true

	$OutputFile= $MachineName + "_reg_FirmwareResources.txt"
	RegQuery -RegistryKeys "HKLM\System\CurrentControlSet\Control\FirmwareResources" -OutputFile $OutputFile -fileDescription "FirmwareResources Reg key" -Recursive $true
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows\CurrentVersion\AppModel" -OutputFile $OutputFile -fileDescription "AppModel Reg key" -Recursive $true

	$OutputFile= $MachineName + "_reg_Appx.txt"
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx" -OutputFile $OutputFile -fileDescription "Appx Reg key" -Recursive $true

	$OutputFile= $MachineName + "_reg_Superfetch.txt"
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Superfetch" -OutputFile $OutputFile -fileDescription "Superfetch Reg key" -Recursive $true

	$OutputFile= $MachineName + "_reg_Uninstall.txt"
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" -OutputFile $OutputFile -fileDescription "Uninstall Reg keys" -Recursive $true
	RegQuery -RegistryKeys "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -OutputFile $OutputFile -fileDescription "Uninstall Reg keys" -Recursive $true

	$OutputFile= $MachineName + "_reg_Recovery.txt"
	RegQuery -RegistryKeys "HKLM\System\CurrentControlSet\Control\CrashControl" -OutputFile $OutputFile -fileDescription "Recovery Reg keys" -Recursive $true
	RegQuery -RegistryKeys "HKLM\System\CurrentControlSet\Control\Session Manager" -OutputFile $OutputFile -fileDescription "Recovery Reg keys" -Recursive $true
	RegQuery -RegistryKeys "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" -OutputFile $OutputFile -fileDescription "Recovery Reg keys" -Recursive $true
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" -OutputFile $OutputFile -fileDescription "Recovery Reg keys" -Recursive $true
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -OutputFile $OutputFile -fileDescription "Recovery Reg keys" -Recursive $true
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows\Windows Error Reporting" -OutputFile $OutputFile -fileDescription "Recovery Reg keys" -Recursive $true

	$OutputFile= $MachineName + "_reg_Startup.txt"
	RegQuery -RegistryKeys "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" -OutputFile $OutputFile -fileDescription "Startup Reg keys" -Recursive $true
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce" -OutputFile $OutputFile -fileDescription "Startup Reg keys" -Recursive $true
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad" -OutputFile $OutputFile -fileDescription "Startup Reg keys" -Recursive $true

	$OutputFile= $MachineName + "_reg_TimeZone.txt"
	RegQuery -RegistryKeys "HKLM\System\CurrentControlSet\Control\TimeZoneInformation" -OutputFile $OutputFile -fileDescription "TimeZone Reg keys" -Recursive $true
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Time Zones" -OutputFile $OutputFile -fileDescription "TimeZone Reg keys" -Recursive $true

	$OutputFile= $MachineName + "_reg_TermServices.txt"
	RegQuery -RegistryKeys "HKLM\System\CurrentControlSet\Control\Terminal Server" -OutputFile $OutputFile -fileDescription "TermServices Reg key" -Recursive $true

	$OutputFile= $MachineName + "_reg_SVCHost.txt"
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SvcHost" -OutputFile $OutputFile -fileDescription "SVCHost Reg key" -Recursive $true

	$OutputFile= $MachineName + "_reg_ProfileList.txt"
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList" -OutputFile $OutputFile -fileDescription "ProfileList Reg key" -Recursive $true

	$OutputFile= $MachineName + "_reg_DriverDatabase.HIV"
	RegSave -RegistryKey "HKLM\System\DriverDatabase" -OutputFile $OutputFile -fileDescription "DriverDatabase Hive"
	$OutputFile= $MachineName + "_reg_DriverDatabase.txt"
	RegQuery -RegistryKeys "HKLM\System\DriverDatabase" -OutputFile $OutputFile -fileDescription "DriverDatabase Reg key" -Recursive $true

	$OutputFile= $MachineName + "_reg_.NET-Framework-Setup.txt"
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\NET Framework Setup\NDP" -OutputFile $OutputFile -fileDescription ".NET-Framework-Setup Reg key" -Recursive $true

	$OutputFile= $MachineName + "_reg_Winevt.HIV"
	RegSave -RegistryKey "HKLM\Software\Microsoft\Windows\currentversion\winevt" -OutputFile $OutputFile -fileDescription "Winevt Hive"
	$OutputFile= $MachineName + "_reg_Winevt.txt"
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows\currentversion\winevt" -OutputFile $OutputFile -fileDescription "Winevt Reg key" -Recursive $true

	$OutputFile= $MachineName + "_reg_Setup.txt"
	RegQuery -RegistryKeys "HKLM\System\Setup" -OutputFile $OutputFile -fileDescription "Setup Reg keys" -Recursive $true
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows\CurrentVersion\Setup\OOBE" -OutputFile $OutputFile -fileDescription "Setup Reg keys"
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows\CurrentVersion\Setup\State" -OutputFile $OutputFile -fileDescription "Setup Reg keys"
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows\CurrentVersion\Setup\Sysprep" -OutputFile $OutputFile -fileDescription "Setup Reg keys" -Recursive $true
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows\CurrentVersion\Setup\SysPrepExternal" -OutputFile $OutputFile -fileDescription "Setup Reg keys" -Recursive $true

	$OutputFile= $MachineName + "_reg_WMI.txt"
	RegQuery -RegistryKeys "HKLM\System\CurrentControlSet\Control\WMI" -OutputFile $OutputFile -fileDescription "WMI Reg key" -Recursive $true

	$OutputFile= $MachineName + "_reg_Drivers.HIV"
	RegSave -RegistryKey "HKLM\DRIVERS" -OutputFile $OutputFile -fileDescription "Drivers Hive"

#----------Directory listing 
	$sectionDescription = "Dir $env:WinDir\Winsxs\temp"
	$OutputFile = Join-Path $pwd.path ($ComputerName + "_dir_winsxsTEMP.txt")
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get $sectiondescription"
	$CommandToExecute = 'dir /a /s "$env:WinDir\Winsxs\temp" '
	RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
	collectfiles -filesToCollect $OutputFile -fileDescription $fileDescription -sectionDescription $sectionDescription

	$sectionDescription = "Dir $env:WinDir\Winsxs"
	$OutputFile = Join-Path $pwd.path ($ComputerName + "_dir_winsxs.txt")
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get $sectiondescription"
	$CommandToExecute = 'dir /a /s "$env:WinDir\Winsxs" '
	RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
	collectfiles -filesToCollect $OutputFile -fileDescription $fileDescription -sectionDescription $sectionDescription
	
	$sectionDescription = "Dir $env:WinDir\servicing\packages"
	$OutputFile = Join-Path $pwd.path ($ComputerName + "_dir_servicing-packages.txt")
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get $sectiondescription"
	$CommandToExecute = 'dir /a /s "$env:WinDir\servicing\packages" '
	RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
	collectfiles -filesToCollect $OutputFile -fileDescription $fileDescription -sectionDescription $sectionDescription

#----------Directory listing: Get registry size info including Config and profile info
	$sectionDescription = "Dir $env:WinDir\system32\config"
	$OutputFile = Join-Path $pwd.path ($ComputerName + "_dir_registry_list.txt")
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get $sectiondescription"
	$CommandToExecute = 'dir /a /s "$env:WinDir\system32\config" '
	RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
	$CommandToExecute = 'dir /a /s "c:\users\ntuser.dat" '
	RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
	collectfiles -filesToCollect $OutputFile -fileDescription $fileDescription -sectionDescription $sectionDescription


#---------- Section Windows Store info
	$sectionDescription = "Copying Windows Store logs"
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status $sectionDescription

	$filesToCollect = "$Env:Temp\winstore.log"
	$filesDescription = "$Env:Temp\winstore.log"
	if (test-path $FilesToCollect) {
		CollectFiles -filesToCollect $filesToCollect -fileDescription $filesDescription -sectionDescription $sectionDescription -renameOutput $true -MachineNamePrefix $MachineName
	}

	$filesToCollect = "$Env:Temp\winstore.log"
	$filesDescription = "$Env:Temp\winstore.log"
	if (test-path $FilesToCollect) {
		CollectFiles -filesToCollect $filesToCollect -fileDescription $filesDescription -sectionDescription $sectionDescription -renameOutput $true -MachineNamePrefix $MachineName
	}
	
if (test-path "$env:localappdata\Packages\WinStore_cw5n1h2txyewy\AC\Temp\Winstore.log")
{
	CollectFiles -filesToCollect "$env:localappdata\Packages\WinStore_cw5n1h2txyewy\AC\Temp\Winstore.log" -fileDescription "Winstore log" -sectionDescription $sectionDescription -renameOutput $true -MachineNamePrefix $MachineName
}
if (test-path "$env:localappdata\Temp\WinStore.log")
{
	CollectFiles -filesToCollect "$env:localappdata\Temp\WinStore.log" -fileDescription "Broker log" -sectionDescription $sectionDescription -renameOutput $true -MachineNamePrefix $MachineName
}
	
#---------- MUSE logs for Win10+
if (get-service usosvc -EA SilentlyContinue)
 {
	$sectionDescription = "Copying MUSE logs for Win10"
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status $sectionDescription

		Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons  -Status "Copy UsoPrivate\UpdateStore"
		$DestinationTempFolder = Join-Path ($PWD.Path) ([System.Guid]::NewGuid().ToString())
		Copy-Item "$env:programdata\UsoPrivate\UpdateStore" -Destination $DestinationTempFolder -Force -Recurse -ErrorAction SilentlyContinue
		CompressCollectFiles -filesToCollect $DestinationTempFolder -DestinationFileName ($ComputerName + "_UsoPrivate-UpdateStore.zip") -fileDescription "UsoPrivate-UpdateStore Folder" -sectionDescription $sectionDescription -Recursive
		Remove-Item $DestinationTempFolder -Force -Recurse
		
		Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons  -Status "Copy UsoShared\Logs"
		$DestinationTempFolder = Join-Path ($PWD.Path) ([System.Guid]::NewGuid().ToString())
		Copy-Item "$env:programdata\USOShared\Logs" -Destination $DestinationTempFolder -Force -Recurse -ErrorAction SilentlyContinue
		CompressCollectFiles -filesToCollect $DestinationTempFolder -DestinationFileName ($ComputerName + "_USOShared-Logs.zip") -fileDescription "USOShared-Logs Folder" -sectionDescription $sectionDescription -Recursive
		Remove-Item $DestinationTempFolder -Force -Recurse
		
	  # robocopy %_OLDPROGRAMDATA%\USOPrivate\UpdateStore %_TEMPDIR%\Windows.old\MUSE %_ROBOCOPY_PARAMS% /S > nul
	  # robocopy %_OLDPROGRAMDATA%\USOShared\Logs %_TEMPDIR%\Windows.old\MUSE %_ROBOCOPY_PARAMS% /S > nul

	$sectionDescription = "SCHTASKS /query /v /TN \Microsoft\Windows\UpdateOrchestrator\"
		$OutputFile = Join-Path $pwd.path ($ComputerName + "_MUSE_ScheduledTasks.txt")
		Write-DiagProgress -activity $ScriptStrings.ID_WindowsUpdateLogCollect -Status "MUSE ScheduledTasks"
		$CommandToExecute = 'SCHTASKS /query /v /TN \Microsoft\Windows\UpdateOrchestrator\ '
		RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
		collectfiles -filesToCollect $OutputFile -fileDescription "MUSE: ScheduledTasks" -sectionDescription $sectionDescription
}
#---------- Section Delivery Optimizaton logs and powershell for Win10+
if (get-service dosvc -EA SilentlyContinue) {
	$sectionDescription = "Copying DeliveryOptimization logs"
	if (test-path "$Env:windir\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs" )
	{
		Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons  -Status "Copy DeliveryOptimization\Logs"
		$arrDOlogsFiles = get-childitem -force -path (join-path $Env:windir "ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs") -recurse -include *.log,*.etl | Where-Object {$_.psIsContainer -eq $false} | ForEach-Object {$_.fullname}
		CompressCollectFiles -filesToCollect $arrDOlogsFiles -fileDescription "DeliveryOptimization\Logs folder" -sectionDescription "DeliveryOptimization\Logs Folder" -DestinationFileName ($MachineName + "DeliveryOptimization-logs.zip") -RenameOutput $true -recursive 
	}
	if (test-path "$Env:windir\SoftwareDistribution\DeliveryOptimization\SavedLogs" )
	{
		Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons  -Status "Copy DeliveryOptimization\SavedLogs"
		$arrDOsavedLogsFiles = get-childitem -force -path (join-path $Env:windir "SoftwareDistribution\DeliveryOptimization\SavedLogs") -recurse -include *.log,*.etl | Where-Object {$_.psIsContainer -eq $false} | ForEach-Object {$_.fullname}
		CompressCollectFiles -filesToCollect $arrDOsavedLogsFiles -fileDescription "DeliveryOptimization\SavedLogs folder" -sectionDescription "DeliveryOptimization\SavedLogs Folder" -DestinationFileName ($MachineName + "DeliveryOptimization-SavedLogslogs.zip") -RenameOutput $true -recursive 
	}
}
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons  -Status "Get DeliveryOptimization Registry"
	$OutputFile= $ComputerName + "_reg_DeliveryOptimization.txt"
	RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -OutputFile $OutputFile -fileDescription "DeliveryOptimization Reg key" -Recursive $true
	
	$OutputFile = $ComputerName + "_DeliveryOptimization_info.txt"
	Get-DeliveryOptimizationPerfSnap -Debug -Verbose | Out-File -FilePath $OutputFile -append 
	Get-DeliveryOptimizationStatus -Debug -Verbose | Out-File -FilePath $OutputFile -append 
 
#---------- Windows Upgrade logs, see *.ps1


#W8/WS2012 and later
if ($bn -gt 9000)
{
	#----------Event Logs - Windows Setup 
	$sectionDescription = "Event Logs - Windows Store Apps"
	$EventLogNames = "Setup", "Microsoft-Windows-WMI-Activity/Operational", "Microsoft-Windows-Setup/Analytic", "General Logging", "HardwareEvents", "Microsoft-Windows-Crashdump/Operational", "Microsoft-Windows-Dism-Api/Analytic", "Microsoft-Windows-EventLog-WMIProvider/Debug", "Microsoft-Windows-EventLog/Analytic", "Microsoft-Windows-EventLog/Debug", "Microsoft-Windows-Kernel-Boot/Operational" 
	$Prefix = "_evt_"
	$Suffix = ""
	.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix
}
 
#----------  Disk Info
$OutputFile = Join-Path $pwd.path ($Env:ComputerName + "_Storage_Info.txt")
Get-PhysicalDisk  | Out-File -FilePath $OutputFile -append
$Pdisk= Get-PhysicalDisk 
ForEach ( $LDisk in $PDisk )
                {
                $LDisk.FriendlyName | Out-File -FilePath $OutputFile -append
                $LDisk.HealthStatus | Out-File -FilePath $OutputFile -append
                $LDisk | Get-StorageReliabilityCounter | Select-Object * | Format-List | Out-File -FilePath $OutputFile -append
                "==================" | Out-File -FilePath $OutputFile -append 
                } 

#---------- Running process info
Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons  -Status "Getting Process info"

	$sectionDescription = "Process_and_Service_Tasklist"
		$OutputFile = Join-Path $pwd.path ($ComputerName + "_Process_and_Service_info.txt")
		Write-DiagProgress -activity $ScriptStrings.ID_WindowsUpdateLogCollect -Status "Process_and_Service_Tasklist"
		$CommandToExecute = 'tasklist /svc /fo list'
		RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
		$CommandToExecute = 'tasklist /v'
		RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
		$CommandToExecute = 'tasklist /M'
		RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
		collectfiles -filesToCollect $OutputFile -fileDescription "Process_and_Service_Tasklist" -sectionDescription $sectionDescription

	$sectionDescription = "Process_and_Service_info"
		$OutputFile = Join-Path $pwd.path ($ComputerName + "_Process_and_Service_info.txt")
		Write-DiagProgress -activity $ScriptStrings.ID_WindowsUpdateLogCollect -Status "Process_and_Service_info"
		$CommandToExecute = 'wmic process get * /format:texttable'
		RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
		collectfiles -filesToCollect $OutputFile -fileDescription "Process_and_Service_info" -sectionDescription $sectionDescription


Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons  -Status "Getting app list"
if ($bn -gt 9000) {
	$OutputFile = Join-Path $pwd.path ($Env:ComputerName + "_GetAppxPackage.txt")
	import-module appx;get-appxpackage -allusers | Out-File -FilePath $OutputFile -append
}
if ($bn -gt 9600) {
	$OutputFile = Join-Path $pwd.path ($Env:ComputerName + "_GetAppxPackageBundle.txt")
	get-appxpackage -packagetype bundle | Out-File -FilePath $OutputFile -append
	
	$sectionDescription = "Dism /Get-ProvisionedAppxPackages"
		$OutputFile = Join-Path $pwd.path ($ComputerName + "_GetAppxProvisioned.txt")
		Write-DiagProgress -activity $ScriptStrings.ID_WindowsUpdateLogCollect -Status $sectionDescription
		$CommandToExecute = 'dism /online /Get-ProvisionedAppxPackages'
		RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
		collectfiles -filesToCollect $OutputFile -fileDescription "$CommandToExecute" -sectionDescription $sectionDescription
}


Write-verbose "$(Get-Date -UFormat "%R:%S") :   end of script DC_Setup_Addons.ps1"


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDjXwCIEqd3GHRq
# 3pwwsFpBGpdUUP4Eb/oKaEzfwdruP6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINeqk330LWqWNW2RJqqyIqOe
# AY+rgcnz0CljrWVjSGFEMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBbt+vyt/5GUdRWxKlWHfq1saivgYegriQqOt8v+d+3I/0BwI9GCzYj
# wPVeWiGCtSskmsAA/J7ydGXQSwUXyqfoSBhNWzFLJPTfaPBOjb5Kt8RI6uGZLhVE
# Ho5JwlXR4I6BD/VVmpzSWZqDbS7rT8Rke+XEdMe7ZPnt2zXWSReN6/yUsONT0FBj
# ORcOuFJfY5oAlLGEXsIlXVYruSKZkq/be5Y3My3YfIer8XPSq6TGOVUFXhSzMhqW
# QRNY+A2cHeJxzkP07JPgiEkqJbNy0cQrfBG6a7o5iiJjbCNixMQx1ye6AKRXtvFC
# 2C6hWBqefQ9nDlfMOC4QDhD5GcEnJAKEoYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEICrvcORZ4FTaiYg7Q0Gn4S9XGWxEovCvRdx0ipnFk7y9AgZi1tk8
# Vk8YEzIwMjIwODAxMDc1MTA2LjYxOFowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
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
# hkiG9w0BCQQxIgQgZMpcBswXad9y/whMUgF1dY4rxAy/6QNBxCxwUKS2MzMwgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCB2BNYC+B0105J2Ry6CfnZ0JA8JflZQ
# Q6sLpHI3LbK9kDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABlklbYuEv3fdPAAEAAAGWMCIEIFDFw7NdMrFXapZuUic/4lKxqdqYW/hS
# /yaW03MeeRsDMA0GCSqGSIb3DQEBCwUABIICALN6sAM/ySRt7MJl36zRP+em29Rw
# PHqm9+SMWbIAol4HD6pXZLutm7WLX4TJvjiutvoTC7D0nhR4KBI+QuwlPZ/AOE72
# 3cwTaTKd0ZAQ3hHPAIOUhVs6XrC4NS+Ga0+jNwBquR14BhmkpXPw38OQ6rB1RCTP
# VQIAAxcTgh7olW48x1ijAmtjPllnHleBWmhG3FBUxN+1fHkLZXtUWckUrTvoiyQ3
# Hcwd1UDOb/r+Aq9ry0w5tPn+yeUXi8puutCJ/nsniIXqJaKa9CHfapG6TC7zSGvc
# sfRiTdRr6rRgXuiQb3VNdANONdQ9F93E4zG/bfJnpPOcL2u5XO3ZYOfRqy51BpTy
# IO37KEE04pc/ibZYpqcb1J1x7XAT6yve5vnEIGxGYV0xYk5aP3U8z45T2aAJiXLV
# kbzUzmwaYqqclzXpv7C5aDPVSqTvd2weMkdK8v0Or5oVpOLd9gCUPMmCqlcVGvzK
# HO5nMNdHMWR5G1nQ1CLlw+ePweD+48Sg8WTdj+VSUapRx9TDQJEJmczTPSVGLIo+
# 7uFj8xnlcmh/cuA4u93eQXsovtwcPIOewrB/CW/XGeO1FnJCiwZkUPyKu0/6J3VK
# g571RR4FmbKFofcEuvndJynlUQsjzc7f/gIvF92LKoGeIvQB0c3eZovbozlV2LVB
# /uX1SCSCpCeBALwj
# SIG # End signature block
