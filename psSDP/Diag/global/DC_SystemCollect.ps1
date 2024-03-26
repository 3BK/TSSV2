#************************************************
# DC_SystemCollect.ps1
# Version 1.1
# Date: 2009-2019
# Author: Walter Eder (waltere@microsoft.com)
# Description: Collects additional System information and ETL Logs (tbd).
# Called from: TS_AutoAddCommands_Apps.ps1
#*******************************************************

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

Write-verbose "$(Get-Date -UFormat "%R:%S") : Start of script DC_SystemCollect.ps1"
"==================== Starting DC_SystemCollect.ps1 script ====================" | WriteTo-StdOut
#_# Import-LocalizedData -BindingVariable ScriptStrings

# Registry keys
"Getting System Registry Keys" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_SystemFiles_Title -Status "Registry keys"

$Regkeys = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$OutputFile = $ComputerName + "_reg_SystemPolicies_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "System Policies Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$OutputFile = $ComputerName + "_reg_ImageFileExecutionRegistry.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "ImageFileExecution Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MUI\UILanguages" 
$OutputFile = $ComputerName + "_reg_UILanguages_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "UI Languages Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKEY_LOCAL_MACHINE\SYSTEM\WPA" 
$OutputFile = $ComputerName + "_reg_WPA_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "WPA Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess", "HKLM\Software\Microsoft\Windows\CurrentVersion\DeviceAccess" 
$OutputFile = $ComputerName + "_reg_DeviceAccess.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "Device Access Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKCU\Software\Classes\ActivatableClasses", "HKLM\Software\Classes\ActivatableClasses" 
$OutputFile = $ComputerName + "_reg_ActivatableClasses.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "Activatable Classes Registry Key" -SectionDescription "Software Registry keys"
    
$Regkeys = "HKCU\Software\Classes\Extensions" 
$OutputFile = $ComputerName + "_reg_Extensions_HKCU.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "Extensions Registry Key" -SectionDescription "Software Registry keys"
  
# Licensing
$Regkeys = "HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions" 
$OutputFile = $ComputerName + "_reg_ProductOptions_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "Product Options Registry Key" -SectionDescription "Software Registry keys"

$Regkeys = "HKLM\SYSTEM\CurrentControlSet\Control\FastCache" 
$OutputFile = $ComputerName + "_reg_FastCache_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "FastCache Registry Key" -SectionDescription "Software Registry keys"

# Windows RunTime Key
$Regkeys = "HKLM\Software\Microsoft\WindowsRuntime" 
$OutputFile = $ComputerName + "_reg_WindowsRuntime_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "WindowsRuntime Registry Key" -SectionDescription "Software Registry keys"
  

# Saved Directories
"Getting copies of System Files" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_SystemFiles_Title -Status $ScriptStrings.ID_SystemFiles_Status
$sectionDescription = "System Files"
if(test-path "$env:WinDir\Panther")
{
	$DesinationTempFolder = Join-Path ($PWD.Path) ([System.Guid]::NewGuid().ToString())
	Copy-Item "$env:WinDir\Panther" -Destination $DesinationTempFolder -Force -Recurse -ErrorAction SilentlyContinue
	CompressCollectFiles -filesToCollect $DesinationTempFolder -DestinationFileName "Panther.zip" -fileDescription "Windows\Panther files" -sectionDescription $sectionDescription -Recursive
	Remove-Item $DesinationTempFolder -Force -Recurse
}

if(test-path "$env:SystemDrive\ProgramData\Microsoft\Windows\WER")
{
	$DesinationTempFolder = Join-Path ($PWD.Path) ([System.Guid]::NewGuid().ToString())
	Copy-Item "$env:SystemDrive\ProgramData\Microsoft\Windows\WER" -Destination $DesinationTempFolder -Force -Recurse -ErrorAction SilentlyContinue
	CompressCollectFiles -filesToCollect $DesinationTempFolder -DestinationFileName "WER.zip" -fileDescription "Windows Error Reporting files" -sectionDescription $sectionDescription -Recursive
	Remove-Item $DesinationTempFolder -Force -Recurse
}

if(test-path "$env:WinDir\WinStore")
{
	$DesinationTempFolder = Join-Path ($PWD.Path) ([System.Guid]::NewGuid().ToString())
	Copy-Item "$env:WinDir\WinStore" -Destination $DesinationTempFolder -Force -Recurse -ErrorAction SilentlyContinue
	CompressCollectFiles -filesToCollect $DesinationTempFolder -DestinationFileName "WinStore.zip" -fileDescription "Windows\WinStore files" -sectionDescription $sectionDescription -Recursive
	Remove-Item $DesinationTempFolder -Force -Recurse
}


# Directory Listings
"Getting Directory Listing of System Files" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_SystemFilesDirectoryListings_Title -Status $ScriptStrings.ID_SystemFilesDirectoryListings_Status
$sectionDescription = "System Files Directory Listings"

if(test-path "$env:windir\System32")
{	$OutputFile= $Computername + "_DirList_System32.txt"
	Get-ChildItem "$env:windir\System32"                                  >> $OutputFile
	CollectFiles -filesToCollect $OutputFile -fileDescription "System32 Directory Listings" -sectionDescription $sectionDescription
}

if(test-path "$env:windir\SysWow64")
{	$OutputFile= $Computername + "_DirList_SystemWow64.txt"
	Get-ChildItem "$env:windir\SysWow64"                                  >> $OutputFile
	CollectFiles -filesToCollect $OutputFile -fileDescription "SysWow64 Directory Listings" -sectionDescription $sectionDescription
}
$OutputFile= $Computername + "_DirList_UsageLogs.txt"
Get-ChildItem "$env:LOCALAPPDATA\Packages\*\AC\Microsoft\CLR_v4.0_32\UsageLogs\*.log" >> $OutputFile
CollectFiles -filesToCollect $OutputFile -fileDescription "Usage Logs Directory Listings" -sectionDescription $sectionDescription

# Permission Data
"Getting ACL Listing of System Files" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_SystemFilesACLListings_Title -Status $ScriptStrings.ID_SystemFilesACLListings_Status
$sectionDescription = "System Files ACL Listings"
$OutputFile= $Computername + "_ACLs_WinSxs.txt"
Get-Acl "$env:windir\winsxs"   | Format-List  > $OutputFile
CollectFiles -filesToCollect $OutputFile -fileDescription "WinSxs ACL Listings" -sectionDescription $sectionDescription
$OutputFile= $Computername + "_ACLs_system32.txt"
Get-Acl "$env:windir\System32" | Format-List  > $OutputFile
CollectFiles -filesToCollect $OutputFile -fileDescription "System32 ACL Listings" -sectionDescription $sectionDescription
$OutputFile= $Computername + "_ACLs_SystemApps.txt"
Get-Acl "$env:windir\SystemApps" | Format-List  > $OutputFile
CollectFiles -filesToCollect $OutputFile -fileDescription "SystemApps ACL Listings" -sectionDescription $sectionDescription
$OutputFile= $Computername + "_ACLs_WindowsApps.txt"
Get-Acl "$env:ProgramFiles\WindowsApps" | Format-List  > $OutputFile
CollectFiles -filesToCollect $OutputFile -fileDescription "WindowsApps ACL Listings" -sectionDescription $sectionDescription

# May need additional Work on these two.
$OutputFile= $Computername + "_ACLs.txt"
Get-ACL 'HKLM:\', 'HKCU:\', 'hklm:\software\microsoft\ole', 'hklm:\system\currentcontrolset'| Format-List > $OutputFile
CollectFiles -filesToCollect $OutputFile -fileDescription "ACLs" -sectionDescription $sectionDescription

"Getting DCOM Permissions" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_DCOMPermissions_Title -Status $ScriptStrings.ID_DCOMPermissions_Status
$sectionDescription = "DCOM Permissions"
$OutputFile = $Computername + "_DCOMPerms.txt"
$Reg = [WMIClass]"\\.\root\default:StdRegProv"
 $DCOMMachineLaunchRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction").uValue
 $DCOMMachineAccessRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineAccessRestriction").uValue
 $DCOMDefaultLaunchPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultLaunchPermission").uValue
 $DCOMDefaultAccessPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultAccessPermission").uValue
 $converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
 $CurrentDCOMSDDLMachineLaunchRestriction = $converter.BinarySDToSDDL($DCOMMachineLaunchRestriction)
 $CurrentDCOMSDDLMachineAccessRestriction = $converter.BinarySDToSDDL($DCOMMachineAccessRestriction)
 $CurrentDCOMSDDLDefaultLaunchPermission = $converter.BinarySDToSDDL($DCOMDefaultLaunchPermission)
 $CurrentDCOMSDDLDefaultAccessPermission = $converter.BinarySDToSDDL($DCOMDefaultAccessPermission)

$CurrentDCOMSDDLMachineLaunchRestriction | Format-List | Out-File -FilePath $OutputFile -append
$CurrentDCOMSDDLMachineAccessRestriction | Format-List | Out-File -FilePath $OutputFile -append
$CurrentDCOMSDDLDefaultLaunchPermission  | Format-List | Out-File -FilePath $OutputFile -append
$CurrentDCOMSDDLDefaultAccessPermission  | Format-List | Out-File -FilePath $OutputFile -append
CollectFiles -filesToCollect $OutputFile -fileDescription "List of DCOM permissions" -sectionDescription $sectionDescription


# Event Logs
"Getting System Event Logs" | WriteTo-StdOut
$sectionDescription = "Event Logs"
$EventLogNames = "System", "Application"
Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription

$EventLogNames = "Microsoft-Windows-BitLocker\BitLocker Management", "Microsoft-Windows-BitLocker-DrivePreparationTool\Admin", 
				 "Microsoft-Windows-BitLocker-DrivePreparationTool\Operational"
Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription

$EventLogNames = "Microsoft-Windows-User Profile Service\Operational"
Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription

$EventLogNames = "Microsoft-Windows-Bits-Client/Operational"
Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription

$EventLogNames = "Microsoft-Windows-AppID/Operational"
Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription



# Env Vars
"Getting Environment Variables" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_EnvironmentVariables_Title -Status $ScriptStrings.ID_EnvironmentVariables_Status

$OutputFile = $ComputerName + "_EnvironmentVariables.txt"
get-childitem env: |out-file $OutputFile
$fileDescription = "Environment Variables"
$sectionDescription = "Environment Variables"
CollectFiles -filesToCollect $outfile -fileDescription $fileDescription -sectionDescription $sectionDescription

# ipconfig
"Getting IPConfig" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_IPConfig_Title -Status $ScriptStrings.ID_IPConfig_Status
$OutputFile= $Computername + "_ipconfig.txt"
$CommandToExecute = "ipconfig /all > $OutputFile"
RunCmd -commandToRun $CommandToExecute -filesToCollect $OutputFile -fileDescription "IPConfig" -sectionDescription "IPConfig"

# System Policies
"Getting System Policies" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_SystemPolicies_Title -Status $ScriptStrings.ID_SystemPolicies_Status
$OutputFile= $Computername + "_SystemPolicies.txt"
$CommandToExecute = "GpResult /R > $OutputFile"
RunCmd -commandToRun $CommandToExecute  -filesToCollect $OutputFile -fileDescription "Gpresult /r output" -sectionDescription "System Policies"

# Hosts file
"Getting Hosts File" | WriteTo-StdOut
$HostsFile  = "$ENV:windir\system32\drivers\etc\hosts"
if (test-path $HostsFile)
{	$OutputFile = $ComputerName + "_Dns_Hosts-file.txt"
	copy-item -Path $HostsFile -Destination $OutputFile -Force
  	CollectFiles -filesToCollect $HostsFile -fileDescription "Hosts File" -sectionDescription "Hosts"
}
else
{
  "$Hostsfile Does not exist" | writeto-stdout
}


# Proxy Settings
"Getting Proxy Settings" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_ProxySettings_Title -Status $ScriptStrings.ID_ProxySettings_Status
$OutputFile= $Computername + "_netsh_proxy_settings.txt"
$CommandToExecute = "netsh winhttp show proxy >> $OutputFile"
RunCmd -commandToRun $CommandToExecute -filesToCollect $OutputFile -fileDescription "Proxy Settings" -sectionDescription "Proxy Settings"

# Get FireWall Service Status
"Getting FireWall Service Status" | WriteTo-StdOut
$MpsSvcStatus=(Get-Service -Name MpsSvc).Status
If ($MpsSvcStatus -eq "Running")
{
	"Status of FireWall Service is Running" | WriteTo-StdOut
}
else
{
	"Status of FireWall Service is NOT Running" | WriteTo-StdOut
}

# Root Certificates
Write-Host "$(Get-Date -UFormat "%R:%S") : Root Certificates"
"Getting Root Certificates" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_RootCertificates_Title -Status $ScriptStrings.ID_RootCertificates_Status

$OutputFile = $ComputerName + "_RootCerts.txt"
get-childitem 'cert:\LocalMachine\root' | Format-List |Out-File $OutputFile
CollectFiles -filesToCollect $OutputFile -fileDescription "List of Root Certificates" -sectionDescription "Root Certs"

# Running Services
"Getting Running Services" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_RunningServices_Title -Status $ScriptStrings.ID_RunningServices_Status
$OutputFile = $ComputerName + "_RunningServices.txt"
Get-Service | findstr /i 'running'|Out-File $Outputfile
CollectFiles -filesToCollect $OutputFile -sectionDescription "Running Services" -fileDescription "Running Services"

# Other logs
"Getting Logs" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_OtherLogs_Title -Status $ScriptStrings.ID_OtherLogs_Status

$sectionDescription = "CBS + Setupapi Logs"
	$OutputFile = $ComputerName + "_CBS.log"
	copy-item -Path "$env:windir\Logs\CBS\CBS.log" -Destination $OutputFile -Force
	CollectFiles -filesToCollect $OutputFile  -fileDescription "CBS Log" -sectionDescription $sectionDescription
	$OutputFile = $ComputerName + "_setupapi.dev.log"
	copy-item -Path "$env:windir\inf\setupapi.dev.log" -Destination $OutputFile -Force
	CollectFiles -filesToCollect $OutputFile -fileDescription "Setupapi Log" -sectionDescription $sectionDescription

# Video Display Info
"Getting Video Display Logs" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_OtherLogs_Title -Status "Video Display Info"
$OutputFile = $ComputerName + "_VideoDisplayInfo.txt"
Get-CimInstance win32_displaycontrollerconfiguration |Out-File $Outputfile
CollectFiles -sectionDescription "Display Info" -fileDescription "Display Info" -filesToCollect $OutputFile


# Network Adapter Info
"Getting Network Adapter Logs" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_OtherLogs_Title -Status "Network Adapter Info"
$OutputFile = $ComputerName + "_NetworkAdapterInfo.txt"
Get-CimInstance Win32_NetworkAdapterConfiguration | out-file $Outputfile
CollectFiles -filesToCollect $Outputfile -fileDescription "Network Adapter Info" -sectionDescription "Network Adapter Info"

# OS Version Info
"Getting OS Version Info" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_OtherLogs_Title -Status "OS Version Info"
$OutputFile = $ComputerName + "_WindowsVersionInfo.txt"
Get-CimInstance Win32_OperatingSystem |Out-File $Outputfile
CollectFiles -sectionDescription "OS Version Info" -fileDescription "OS Version Info" -filesToCollect $OutputFile


# Collect ETL Logs
Write-Host "$(Get-Date -UFormat "%R:%S") : Collect ETL Logs (tbd)"
"Getting ETL Logs" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_ETLLogs_Title -Status $ScriptStrings.ID_ETLLogs_Status
if ($Global:runFull -eq $True) { # $False = disabling for now for this long-lasting step
	if(Test-Path "$env:localappdata\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\LocalState")
	{
		$DesinationTempFolder = Join-Path ($PWD.Path) ([System.Guid]::NewGuid().ToString())
		Copy-Item "$env:localappdata\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\LocalState" -Destination $DesinationTempFolder -Force -Recurse -ErrorAction SilentlyContinue
		CompressCollectFiles -filesToCollect $DesinationTempFolder -DestinationFileName "LiveComm.zip" -fileDescription "Windows Live applications ETL" -sectionDescription "ETL Logs" -Recursive
		Remove-Item $DesinationTempFolder -Force -Recurse
	}
}

Write-verbose "$(Get-Date -UFormat "%R:%S") :   end of script DC_SystemCollect.ps1"

# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDZkk5d7o2b1qYM
# GjiNJe8Re8cU3Bi/60sDPkyUrm049qCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMQOGetVecGdsWoXHkoVVzUE
# c5KalL9+yO2uLhtNa7L/MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBhMC1xtCUM0zNPxVjYM/41PRaApLgyDzaVKfRu8nUIiMpO20Kj05X0
# zR3d3PvfHMqCBmRuSe5NVYl4IIReX99klZOyxc8FT04JCQXt2OZfILGKOooehW7O
# kAxBCFwgOXYxPAI1lc3EHg30HTbDNFJmoHAvR0vHoOEeZiRYtFF9ehUTu3KEVbPe
# Pp11NkGe7SVc52f3pcZhEuuDHL5Izudfx3hyJA0o0aw3HT9pgwd0DGVP/Nl54b20
# fafoS/9wvWP9N7dhJuVw1aHqGfGyYHgofca9Xe3t+tcPM3tXPMYE7sl06b/oUVce
# FCtPYP+iKQZj3Kr3mCt7ZjeZVtZXWri4oYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIC5e71scVuE3DJzoBWkrSO9BhA/lJxlbfEkE79cBqjbvAgZi2BAW
# /IUYEzIwMjIwODAxMDc1MTIwLjQyNlowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
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
# hkiG9w0BCQQxIgQgtxa/6hFg9sxDvnwRqji9wJ4q4sdbH679Jsn1NddvnfwwgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCABTkDjOBEUfZnligJiL539Lx+nsr/N
# FVTnKFX030iNYDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABmsB1osQhbT6FAAEAAAGaMCIEILUtm4TpisXoG7kTsxOI51IMkFhuOyD6
# Xm+yAr8gIh09MA0GCSqGSIb3DQEBCwUABIICAAVCOZAMU+2SpvAta0jy4pmvREqi
# vVhv5ocWKo6pyEns8CVhrfaKdk/Ec6+g1rkccPjPSZw0Wq7hgcg7y06XoW85ZZUk
# BUBtkZeXbJHLQ9bwdLkbAEti5TY6clI5w9XR01pCKhZhu1CbRLeEBoDMJqGHc23x
# YkiC9UYRgbkBCzpuDbNongHFLnoC7UZQah1Wc8Jg95sk0AKaNiwBuPGZQB70G8jC
# kLKJMhNLe3qyAtg/fyyaWHkXdl4ZU3yHvFaOg8YsDmUDt2ZX6PLzhEL+Nv47wdyT
# OGR50FXTnCKodAc3YxRgEA6WwF2gafVaKwl1KFPUa3FkJE5hO/0UV7c8r3KrYH/f
# Vjaoy+o9aiaHuznBQU5RdIYtqyrQcBa5YefQnQJbbuUU9k7fT8DTeoFW6CQwG+Jc
# AKD5l0++JzlsI0RzccSThThX10UX74NN8UJQ96okNYp3Zk/Bx9bw+OqGAHpSSoAl
# 0rXZ8XY0RxOgl62vy46B2aIK9ZTL8JIAYTcgznDxgK1dj8niXAHmJ/SnjiteqXYg
# frPuu8joCqRtoAZbkl3o96lwfAU7pzRTSha7aanCom/AYEAH5ri2BbsT9MXBXdoG
# IhdKmbudLkM9qncgxHWNOZqJ9imB01hUbqUkHeaQwcGojj9OSyQ/B/6cvgYrBbZ2
# M5HYxI96FyyyuSGC
# SIG # End signature block
