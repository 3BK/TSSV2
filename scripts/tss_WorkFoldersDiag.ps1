<# Script name: tss_WorkFoldersDiag.ps1

#  Copyright (c) Microsoft Corporation.  All rights reserved.
#  
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER. 
#
# Author:
#     Anu Raghavan (araghav) - August, 2013
# Version: 8.1
#>

#region ::::: Script Input PARAMETERS :::::
[CmdletBinding()]param(
  [Parameter(Mandatory=$true, Position=0)] [String] $DataPath,
  [Parameter(Mandatory=$false, Position=1)] [Switch] $AdvancedMode = $false,
  [Parameter(Mandatory=$false, Position=2)] [Int] $TraceLevel = 255,
  [Parameter(Mandatory=$false, Position=3)] [Switch] $Cleanup = $false,
  [Parameter(Mandatory=$false, Position=4)] [Switch] $RunTrace = $false,
  [Parameter(Mandatory)]
  [ValidateSet("Start","Stop")]
  [string]$Stage
)
$ScriptVer="22.02.04"	#Date: 2022-02-04
$OutputDirectory = $DataPath
$LogSeparator = '################################################################################################################'
#endregion ::::: Script Input PARAMETERS :::::

function Get-EventsTxt($EventLog, $OutFile)
# SYNOPSIS: extract Eventlog content in TXT format
{	$Events = Get-WinEvent $EventLog -MaxEvents 300 -ErrorAction SilentlyContinue
    if($null -eq $Events)
    {   # Error occurred - do nothing
	    Write-Host ' $EventLog : No event log entries found.'
    }
    else
    {   'Number of event log entries collected: ' + $Events.Count | Out-File $OutFile
	    foreach($Event in $Events)
	    {   $LogSeparator | Out-File $OutFile -append
		    $Event | Out-File $OutFile -append
		    'Full message:' | Out-File $OutFile -append
		    $Event.Message | Out-File $OutFile -append
	    }
    }
}

function Get-Registry($Path, $OutFile)
# SYNOPSIS: get the content of Registry keys
{
    if ((Test-Path $Path) -eq $true)
    {
        Get-Item $Path | Out-File $OutFile -append
	    Get-ChildItem $Path -Recurse | Out-File $OutFile -append
    }
}

function Get-WorkFoldersInfo
# SYNOPSIS: collect WorkFolder client and server info
{
	param (
	  [Parameter(Mandatory=$true, Position=0)] [String] $OutputDirectory,
	  [Parameter(Mandatory=$false, Position=1)] [Switch] $AdvancedMode = $false,
	  [Parameter(Mandatory=$false, Position=2)] [Int] $TraceLevel = 255,
	  [Parameter(Mandatory=$false, Position=3)] [Switch] $Cleanup = $True,
	  [Parameter(Mandatory=$false, Position=4)] [Switch] $RunTrace = $false,
	  [Parameter(Mandatory)]
        [ValidateSet("Start","Stop")]
        [string]$Stage
	)

	$OldErrorActionPreference = $ErrorActionPreference
	$ErrorActionPreference = "SilentlyContinue"

	# Validate input
	$Done = $false
	while ($Done -eq $false)
	{
		if ($null -eq $OutputDirectory)	{	$Done = $false	}
		elseif ((Test-Path $OutputDirectory) -eq $false) {	$Done = $false	}
		else {	$Done = $true	}

		if ($Done -eq $false)
		{	Write-Error "Path selected is invalid."
			$OutputDirectory = Read-Host "Specify another path for OutputDirectory [Note that all contents already present in this directory will be erased.]"
		}
	}
	while (($TraceLevel -lt 1) -or ($TraceLevel -gt 255))
	{	$TraceLevel = Read-Host "Invalid trace level specified. Please specify a value between 1 and 255"}

	# Create Temp directory structure to accumulate output + Collect generic info
	$Script:TempOutputPath = $OutputDirectory + '\Temp'
	$Script:GeneralDirectory = $Script:TempOutputPath + '\General'
	$Script:IsServer = Test-Path ($env:Systemroot + '\System32\SyncShareSvc.dll')
	$Script:IsClient = Test-Path ($env:Systemroot + '\System32\WorkFoldersSvc.dll')
	
if ($Stage -eq "Start") 
{ 
	Write-Host "v$ScriptVer Starting collection of debug information for Work Folders on this machine ..." -ForegroundColor White -BackgroundColor DarkGreen
	Write-Host "$(Get-Date -Format 'HH:mm:ss') Setting up WorkFoldersDiag environment ..."
	if ($AdvancedMode) {  	Write-Host "... running in AdvancedMode" }

	New-Item $Script:TempOutputPath -type directory | Out-Null
	New-Item $Script:GeneralDirectory -type directory | Out-Null
	$GeneralInfoFile = $Script:GeneralDirectory + '\' + $env:COMPUTERNAME + '_MachineInfo.txt'
	$LocalVolumesFile = $Script:GeneralDirectory + '\' + $env:COMPUTERNAME + '_LocalVolumes.txt'
	$ClusterVolumesFile = $Script:GeneralDirectory + '\' + $env:COMPUTERNAME + '_ClusterVolumes.txt'
	'VersionString: ' + [System.Environment]::OSVersion.VersionString | Out-File $GeneralInfoFile
	'Version: ' + [System.Environment]::OSVersion.Version | Out-File $GeneralInfoFile -append
	'ServicePack: ' + [System.Environment]::OSVersion.ServicePack | Out-File $GeneralInfoFile -append
	'Platform: ' + [System.Environment]::OSVersion.Platform | Out-File $GeneralInfoFile -append

	$OS = Get-CimInstance -class win32_OperatingSystem
	if ($OS.ProductType -gt 1)
	{	'OS SKU Type: Server' | Out-File $GeneralInfoFile -append
		try { $Cluster = Get-Cluster -EA Ignore}
		catch { 
			#Write-host "...not running on cluster environment"
			}
		$IsCluster = $null -ne $Cluster
		if ($IsCluster) {  'This machine is part of a cluster' | Out-File $GeneralInfoFile -append }
		else {    'This machine is a stand alone machine, it is not part of a cluster' | Out-File $GeneralInfoFile -append }
	}
	else
	{	'OS SKU Type: Client' | Out-File $GeneralInfoFile -append}


	if ($Script:IsServer) {
		'Work Folders server component is installed on this machine.' | Out-File $GeneralInfoFile -append 
		'List of versions of binaries for the Work Folders server component:' | Out-File $GeneralInfoFile -append
		$ServerBinaries = @(
		($env:Systemroot + '\System32\SyncShareSvc.dll'),
		($env:Systemroot + '\System32\SyncShareSrv.dll'),
		($env:Systemroot + '\System32\SyncShareTTLib.dll'),
		($env:Systemroot + '\System32\SyncShareTTSvc.exe')
		)
		Foreach($Binary in $ServerBinaries)
		{ 	[System.Diagnostics.FileVersionInfo]::GetVersionInfo($Binary) | Format-List | Out-File $GeneralInfoFile -append }
		Copy-Item ($env:Systemroot + '\System32\SyncShareSvc.config') $Script:GeneralDirectory
		$WFmode = "Server"
	}
	if ($Script:IsClient) {
		'Work Folders client component is installed on this machine.' | Out-File $GeneralInfoFile -append
		'List of versions of binaries for the Work Folders client component:' | Out-File $GeneralInfoFile -append
		$ClientBinaries = @(
		($env:Systemroot + '\System32\WorkFoldersShell.dll'),
		($env:Systemroot + '\System32\WorkFoldersGPExt.dll'),
		($env:Systemroot + '\System32\WorkFoldersControl.dll'),
		($env:Systemroot + '\System32\WorkFoldersSvc.dll'),
		($env:Systemroot + '\System32\WorkFolders.exe')
		)
		Foreach($Binary in $ClientBinaries)
		{ 	[System.Diagnostics.FileVersionInfo]::GetVersionInfo($Binary) | Format-List | Out-File $GeneralInfoFile -append }
		$WFmode = "Client"
	}
	
	$WFmodeDirectory = $null
	$WFmodeDirectory = $Script:TempOutputPath + '\' + $WFmode
	New-Item $WFmodeDirectory -type directory | Out-Null
		
	"List of local volumes:" | Out-File $LocalVolumesFile -append
	Get-WmiObject Win32_Volume | Out-File $LocalVolumesFile -append

	if ($IsCluster)
	{
		"List of cluster volumes:" | Out-File $ClusterVolumesFile -append
		Get-WmiObject MSCluster_Resource -Namespace root/mscluster | where-object{$_.Type -eq 'Physical Disk'} |
			ForEach-Object{ Get-WmiObject -Namespace root/mscluster -Query "Associators of {$_} Where ResultClass=MSCluster_Disk" } |
			ForEach-Object{ Get-WmiObject -Namespace root/mscluster -Query "Associators of {$_} Where ResultClass=MSCluster_DiskPartition" } |
			Out-File $ClusterVolumesFile -append
	}

	if ($RunTrace) {  	Write-Host "... Start Work Folders tracing" 
		### Start Work Folders tracing
		#Write-Host "$(Get-Date -Format 'HH:mm:ss') Start Work Folders $WFmode tracing ..."
		$TracesDirectory = $Script:TempOutputPath + '\Traces'
		New-Item $TracesDirectory -type directory | Out-Null
		$TracingCommand = 'logman start WorkFoldersTrace -o "$TracesDirectory\WorkFoldersTrace.etl" --max -ets -p "{111157cb-ee69-427f-8b4e-ef0feaeaeef2}" 0xffffffff ' + $TraceLevel
		Invoke-Expression $TracingCommand | Out-Null # start traces
		$TracingCommand = 'logman start WorkFoldersTraceEFS -o "$TracesDirectory\WorkFoldersTraceEFS.etl" --max -ets -p "{C755EF4D-DE1C-4E7D-A10D-B8D1E26F5035}" 0xffffffff ' + $TraceLevel
		Invoke-Expression $TracingCommand | Out-Null # start EFS traces
		$TracingCommand = 'logman start WorkFoldersTraceESE -o "$TracesDirectory\WorkFoldersTraceESE.etl" --max -ets -p "{1284E99B-FF7A-405A-A60F-A46EC9FED1A7}" 0xffffffff ' + $TraceLevel
		Invoke-Expression $TracingCommand | Out-Null # start ESE traces
		Write-Host "$(Get-Date -Format 'HH:mm:ss') Work Folders $WFmode Tracing started."
		
		### Start Interactive Repro
		Write-Host "`n === Please reproduce the WorkFolder problem then press the 's' key to stop tracing. ===`n" -ForegroundColor Green
		do {
			$UserDone = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
		} until ($UserDone.Character -ieq 's')
		###
		Write-Host "$(Get-Date -Format 'HH:mm:ss') Collecting WorkFolder traces with TraceLevel $TraceLevel ..."

		Start-Sleep(5) # Allow time to make sure traces get written

		Invoke-Expression 'logman stop WorkFoldersTrace -ets' | Out-Null # stop traces
		Invoke-Expression 'logman stop WorkFoldersTraceEFS -ets' | Out-Null # stop EFS traces
		Invoke-Expression 'logman stop WorkFoldersTraceESE -ets' | Out-Null # stop ESE traces

		Write-Host "$(Get-Date -Format 'HH:mm:ss') WorkFolder Tracing stopped."
	}
}
if ($Stage -eq "Stop") 
{	
	###
	if ($Script:IsClient) {$WFmode = "Client"}
	if ($Script:IsServer)
	{
		$ServerSetting = Get-SyncServerSetting
		$Shares = Get-SyncShare
		$WFmode = "Server"
	}
	
	$WFmodeDirectory = $Script:TempOutputPath + '\' + $WFmode
	
	if ($AdvancedMode)
	{ #_# Stopping Service WorkFolderssvc
		if ($Script:IsClient) { Write-Host "$(Get-Date -Format 'HH:mm:ss') Stopping Service WorkFolderssvc."
						Stop-Service WorkFolderssvc }
		if ($Script:IsServer) { Write-Host "$(Get-Date -Format 'HH:mm:ss') Stopping Services SyncShareSvc, SyncShareTTSvc."
						Stop-Service SyncShareSvc
						Stop-Service SyncShareTTSvc }
	}

	Write-Host "$(Get-Date -Format 'HH:mm:ss') Saving WorkFolders $WFmode configuration information ..."
	$ConfigDirectory = $WFmodeDirectory + '\Config'
	New-Item $ConfigDirectory -type directory | Out-Null
	$RegConfigFile = $ConfigDirectory + '\' + $env:COMPUTERNAME + '_RegistryConfig.txt'
	$MetadataDirectory = $WFmodeDirectory + '\' + $WFmode + 'Metadata'
	if ($AdvancedMode) { New-Item $MetadataDirectory -type directory | Out-Null   }

	if ($Script:IsServer)
	{
		Get-Registry 'hklm:\SYSTEM\CurrentControlSet\Services\SyncShareSvc' $RegConfigFile
		Get-Registry 'hklm:\SYSTEM\CurrentControlSet\Services\SyncShareTTSvc' $RegConfigFile
		$SyncShareSrvHive = 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\SyncShareSrv'
		if ($IsCluster) { $SyncShareSrvHive = 'hklm:\Cluster\SyncShareSrv' }
		Get-Registry $SyncShareSrvHive $RegConfigFile

		$ConfigFile = $ConfigDirectory + '\' + $env:COMPUTERNAME + '_CmdletConfig.txt'
		$LogSeparator | Out-File $ConfigFile -append
		'Config for sync server:' | Out-File $ConfigFile -append
		$LogSeparator | Out-File $ConfigFile -append
		$ServerSetting | Out-File $ConfigFile -append
		$LogSeparator | Out-File $ConfigFile -append
		'End config for sync server:' | Out-File $ConfigFile -append
		$LogSeparator | Out-File $ConfigFile -append

		foreach ($Share in $Shares)
		{
			$LogSeparator | Out-File $ConfigFile -append
			'Config for sync share ' + $Share.Name | Out-File $ConfigFile -append
			$LogSeparator | Out-File $ConfigFile -append
			$Share | Out-File $ConfigFile -append

			$acl = Get-Acl $Share.Path -EA SilentlyContinue
			'ACLs on ' + $Share.Path + ':' | Out-File $ConfigFile -append
			$acl | Out-File $ConfigFile -append
			$acl.Access | Out-File $ConfigFile -append

			$acl = Get-Acl $Share.StagingFolder -EA SilentlyContinue
			'ACLs on ' + $Share.StagingFolder + ':' | Out-File $ConfigFile -append
			$acl | Out-File $ConfigFile -append
			$acl.Access | Out-File $ConfigFile -append

			$MetadataFolder = $Share.StagingFolder + '\Metadata'
			$acl = Get-Acl $MetadataFolder -EA SilentlyContinue
			'ACLs on ' + $MetadataFolder + ':' | Out-File $ConfigFile -append
			$acl | Out-File $ConfigFile -append
			$acl.Access | Out-File $ConfigFile -append

			if ($AdvancedMode) { Get-ChildItem $MetadataFolder | ForEach-Object{ Copy-Item $_.FullName $MetadataDirectory } }
			
			foreach ($user in $Share.User)
			{
				'Full list of users on this sync share:' | Out-File $ConfigFile -append
				$user | Out-File $ConfigFile -append
			}

			$LogSeparator | Out-File $ConfigFile -append
			'End config for sync share ' + $Share.Name | Out-File $ConfigFile -append
			$LogSeparator | Out-File $ConfigFile -append
		}
	}

	if ($Script:IsClient)
	{
		Get-Registry 'hklm:SOFTWARE\Microsoft\Windows\CurrentVersion\WorkFolders' $RegConfigFile
		Get-Registry 'hkcu:SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\WorkFolders' $RegConfigFile
		Get-Registry 'hkcu:SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' $RegConfigFile
		if ($AdvancedMode) { Get-ChildItem ($env:LOCALAPPDATA + '\Microsoft\Windows\WorkFolders\Metadata') | ForEach-Object{ Copy-Item $_.FullName $MetadataDirectory } }
	}

	### event log entries
	Write-Host "$(Get-Date -Format 'HH:mm:ss') Collecting WorkFolders $WFmode event log entries ..."
	$EventLogDirectory = $WFmodeDirectory + '\' + $WFmode + 'EventLogs'
	New-Item $EventLogDirectory -type directory | Out-Null

	if ($Script:IsServer)
	{
		Get-EventsTxt Microsoft-Windows-SyncShare/Operational ($EventLogDirectory + '\' + $env:COMPUTERNAME + '_SyncShare_Operational.txt')
		#_# ToDo: Get-EventsTxt Microsoft-Windows-SyncShare/Debug ($EventLogDirectory + '\' + $env:COMPUTERNAME + '_SyncShare_Debug.txt')
		Get-EventsTxt Microsoft-Windows-SyncShare/Reporting ($EventLogDirectory + '\' + $env:COMPUTERNAME + '_SyncShare_Reporting.txt')
	}

	if ($Script:IsClient)
	{
		Get-EventsTxt Microsoft-Windows-WorkFolders/Operational ($EventLogDirectory + '\' + $env:COMPUTERNAME + '_WorkFolders_Operational.txt')
		#_# ToDo: Get-EventsTxt Microsoft-Windows-WorkFolders/Debug ($EventLogDirectory + '\' + $env:COMPUTERNAME + '_WorkFolders_Debug.txt')
		#_# ToDo: Get-EventsTxt Microsoft-Windows-WorkFolders/Analytic ($EventLogDirectory + '\' + $env:COMPUTERNAME + '_WorkFolders_Analytic.txt')
		Get-EventsTxt Microsoft-Windows-WorkFolders/WHC ($EventLogDirectory + '\' + $env:COMPUTERNAME + '_WorkFolders_ManagementAgent.txt')
	}
	Write-Host "$(Get-Date -Format 'HH:mm:ss') Collection of WorkFolders $WFmode event log entries done."

	if ($AdvancedMode)
	{ #_# Starting Service WorkFolderssvc
		if ($Script:IsClient) {  Write-Host "$(Get-Date -Format 'HH:mm:ss') Restarting Service WorkFolderssvc"
						Start-Service WorkFolderssvc }
		if ($Script:IsServer) {  Write-Host "$(Get-Date -Format 'HH:mm:ss') Restarting Services SyncShareSvc, SyncShareTTSvc"
						Start-Service SyncShareSvc
						Start-Service SyncShareTTSvc }
	}
	### Compress data
	Write-Host "$(Get-Date -Format 'HH:mm:ss') Finalizing/Zipping output ..."
	# In the output directory, remove the system and hidden attributes from files
	attrib ($Script:TempOutputPath + '\*') -H -S /s
	# Zip the output directory
	Add-Type -AssemblyName System.IO.Compression
	Add-Type -AssemblyName System.IO.Compression.FileSystem
	$OutputZipFile = $OutputDirectory + '\' + $env:COMPUTERNAME + '_WorkFoldersDiagOutput.zip'
	[System.IO.Compression.ZipFile]::CreateFromDirectory($Script:TempOutputPath, $OutputZipFile)
	Write-Host "All information have been saved in $OutputZipFile." -ForegroundColor Green 

	###
	Write-Host "Cleaning up environment ..."
	if ($Cleanup) { Write-Host "$(Get-Date -Format 'HH:mm:ss') Cleaning output directory $Script:TempOutputPath ..."
					Remove-Item $Script:TempOutputPath -Recurse -Force }

	$ErrorActionPreference = $OldErrorActionPreference
	Write-Host "$(Get-Date -Format 'HH:mm:ss') Done - tss_WorkFoldersDiag" -ForegroundColor White -BackgroundColor DarkGreen
	Write-Host " "
}
} # end of function Get-WorkFoldersInfo

#region ::::: MAIN ::::
Get-WorkFoldersInfo -OutputDirectory $dataPath $AdvancedMode -TraceLevel $TraceLevel -Stage $Stage
#endregion ::::: MAIN :::::


# SIG # Begin signature block
# MIInlgYJKoZIhvcNAQcCoIInhzCCJ4MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBO3X5nRSPI+pqT
# fVFpR+EvNb4WJQN5JztzJfBjdAQZ6KCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
# esGEb+srAAAAAANOMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI5WhcNMjQwMzE0MTg0MzI5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDdCKiNI6IBFWuvJUmf6WdOJqZmIwYs5G7AJD5UbcL6tsC+EBPDbr36pFGo1bsU
# p53nRyFYnncoMg8FK0d8jLlw0lgexDDr7gicf2zOBFWqfv/nSLwzJFNP5W03DF/1
# 1oZ12rSFqGlm+O46cRjTDFBpMRCZZGddZlRBjivby0eI1VgTD1TvAdfBYQe82fhm
# WQkYR/lWmAK+vW/1+bO7jHaxXTNCxLIBW07F8PBjUcwFxxyfbe2mHB4h1L4U0Ofa
# +HX/aREQ7SqYZz59sXM2ySOfvYyIjnqSO80NGBaz5DvzIG88J0+BNhOu2jl6Dfcq
# jYQs1H/PMSQIK6E7lXDXSpXzAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnMc7Zn/ukKBsBiWkwdNfsN5pdwAw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMDUxNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAD21v9pHoLdBSNlFAjmk
# mx4XxOZAPsVxxXbDyQv1+kGDe9XpgBnT1lXnx7JDpFMKBwAyIwdInmvhK9pGBa31
# TyeL3p7R2s0L8SABPPRJHAEk4NHpBXxHjm4TKjezAbSqqbgsy10Y7KApy+9UrKa2
# kGmsuASsk95PVm5vem7OmTs42vm0BJUU+JPQLg8Y/sdj3TtSfLYYZAaJwTAIgi7d
# hzn5hatLo7Dhz+4T+MrFd+6LUa2U3zr97QwzDthx+RP9/RZnur4inzSQsG5DCVIM
# pA1l2NWEA3KAca0tI2l6hQNYsaKL1kefdfHCrPxEry8onJjyGGv9YKoLv6AOO7Oh
# JEmbQlz/xksYG2N/JSOJ+QqYpGTEuYFYVWain7He6jgb41JbpOGKDdE/b+V2q/gX
# UgFe2gdwTpCDsvh8SMRoq1/BNXcr7iTAU38Vgr83iVtPYmFhZOVM0ULp/kKTVoir
# IpP2KCxT4OekOctt8grYnhJ16QMjmMv5o53hjNFXOxigkQWYzUO+6w50g0FAeFa8
# 5ugCCB6lXEk21FFB1FdIHpjSQf+LP/W2OV/HfhC3uTPgKbRtXo83TZYEudooyZ/A
# Vu08sibZ3MkGOJORLERNwKm2G7oqdOv4Qj8Z0JrGgMzj46NFKAxkLSpE5oHQYP1H
# tPx1lPfD7iNSbJsP6LiUHXH1MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXYwghlyAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIEvtH5WImO30R+uO3z/vnhj0
# HbkyOaig9CYZOVJtqelQMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAk+InYQPr4Kx2RlBTnmlQIZ1g0eYrc7T4Y4p2tP5QNgu4TVIUAGqTBSkG
# 7+xj0pcm5PlsslTj/dnKgelomNs8edQXtOyWzh0mhYYCFjtD9wXP2T8wahSCuUt/
# c5r20KaSW4PwyL3UpG/e2sf/4ozwnlfRjlrsVNW531l+yxwj1wWLP02Q3Myf0kt8
# c3GYM3xpo5vSu7XjycPcbVUufRs8ycrPisiqQbuO4XW0eBkskqFX3hfW/M2jciYj
# itjjXNjjwaN4kQIHATnGmsrpmaZjJNafNdN0IlEKhfIt/yy46oUYFCgp5F8IasWb
# JItFWT9NmMiYy5cLtS0kpoU01zAVQKGCFwAwghb8BgorBgEEAYI3AwMBMYIW7DCC
# FugGCSqGSIb3DQEHAqCCFtkwghbVAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCL2AhYRYAqQgh02ddcehm/5IjrI8Io1BJMPPMas1qViAIGZGzCbDwX
# GBMyMDIzMDYwNjExNDU1MS44MTdaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpERDhDLUUz
# MzctMkZBRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVcwggcMMIIE9KADAgECAhMzAAABxQPNzSGh9O85AAEAAAHFMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEz
# MloXDTI0MDIwMjE5MDEzMlowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkREOEMtRTMzNy0yRkFFMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAq0hds70eX23J7pappaKXRhz+TT7JJ3OvVf3+N8fNpxRs
# 5jY4hEv3BV/w5EWXbZdO4m3xj01lTI/xDkq+ytjuiPe8xGXsZxDntv7L1EzMd5jI
# SqJ+eYu8kgV056mqs8dBo55xZPPPcxf5u19zn04aMQF5PXV/C4ZLSjFa9IFNcrib
# dOm3lGW1rQRFa2jUsup6gv634q5UwH09WGGu0z89RbtbyM55vmBgWV8ed6bZCZrc
# oYIjML8FRTvGlznqm6HtwZdXMwKHT3a/kLUSPiGAsrIgEzz7NpBpeOsgs9TrwyWT
# ZBNbBwyIACmQ34j+uR4et2hZk+NH49KhEJyYD2+dOIaDGB2EUNFSYcy1MkgtZt1e
# RqBB0m+YPYz7HjocPykKYNQZ7Tv+zglOffCiax1jOb0u6IYC5X1Jr8AwTcsaDyu3
# qAhx8cFQN9DDgiVZw+URFZ8oyoDk6sIV1nx5zZLy+hNtakePX9S7Y8n1qWfAjoXP
# E6K0/dbTw87EOJL/BlJGcKoFTytr0zPg/MNJSb6f2a/wDkXoGCGWJiQrGTxjOP+R
# 96/nIIG05eE1Lpky2FOdYMPB4DhW7tBdZautepTTuShmgn+GKER8AoA1gSSk1EC5
# ZX4cppVngJpblMBu8r/tChfHVdXviY6hDShHwQCmZqZebgSYHnHl4urE+4K6ZC8C
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBRU6rs4v1mxNYG/rtpLwrVwek0FazAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQCMqN58frMHOScciK+Cdnr6dK8fTsgQDeZ9bvQjCuxNIJZJ92+xpeKRCf3Xq47q
# dRykkKUnZC6dHhLwt1fhwyiy/LfdVQ9yf1hYZ/RpTS+z0hnaoK+P/IDAiUNm32NX
# LhDBu0P4Sb/uCV4jOuNUcmJhppBQgQVhFx/57JYk1LCdjIee//GrcfbkQtiYob9O
# a93DSjbsD1jqaicEnkclUN/mEm9ZsnCnA1+/OQDp/8Q4cPfH94LM4J6X0NtNBeVy
# wvWH0wuMaOJzHgDLCeJUkFE9HE8sBDVedmj6zPJAI+7ozLjYqw7i4RFbiStfWZSG
# jwt+lLJQZRWUCcT3aHYvTo1YWDZskohWg77w9fF2QbiO9DfnqoZ7QozHi7RiPpbj
# gkJMAhrhpeTf/at2e9+HYkKObUmgPArH1Wjivwm1d7PYWsarL7u5qZuk36Gb1mET
# S1oA2XX3+C3rgtzRohP89qZVf79lVvjmg34NtICK/pMk99SButghtipFSMQdbXUn
# S2oeLt9cKuv1MJu+gJ83qXTNkQ2QqhxtNRvbE9QqmqJQw5VW/4SZze1pPXxyOTO5
# yDq+iRIUubqeQzmUcCkiyNuCLHWh8OLCI5mIOC1iLtVDf2lw9eWropwu5SDJtT/Z
# wqIU1qb2U+NjkNcj1hbODBRELaTTWd91RJiUI9ncJkGg/jCCB3EwggVZoAMCAQIC
# EzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoX
# DTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC
# 0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VG
# Iwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP
# 2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/P
# XfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361
# VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwB
# Sru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9
# X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269e
# wvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDw
# wvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr
# 9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+e
# FnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAj
# BgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+n
# FV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBH
# hkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
# BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4Swf
# ZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTC
# j/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu
# 2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/
# GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3D
# YXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbO
# xnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqO
# Cb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I
# 6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0
# zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaM
# mdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNT
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLOMIICNwIBATCB+KGB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046REQ4Qy1FMzM3LTJGQUUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVACEAGvYXZJK7cUo62+LvEYQEx7/noIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoKQwjMCIYDzIwMjMwNjA2MDkzNjM1WhgPMjAyMzA2MDcwOTM2MzVaMHcw
# PQYKKwYBBAGEWQoEATEvMC0wCgIFAOgpDCMCAQAwCgIBAAICC3ECAf8wBwIBAAIC
# E+gwCgIFAOgqXaMCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAK
# MAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQDn/AVkinnx
# oW7oiA6JaC2aH8bU3EddsOkS5TGsob5xe6RIod8OpI8a54rjAfuQhf1qET2KD8WW
# MLsMShcG8nbA0FcbGWIxShkZXeyzLAnna1i19M5dQVkjcXOqMKlDzAVCgDtwKKiy
# EjHbDPf7aPLNz0n1FfmEDmGOjZ5BhCG3ZzGCBA0wggQJAgEBMIGTMHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABxQPNzSGh9O85AAEAAAHFMA0GCWCG
# SAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZI
# hvcNAQkEMSIEIG3Js+3wQkyipvY0+n7yJR/4NUVWCaU6VpV5Q+vPAejiMIH6Bgsq
# hkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgGQGxkfYkd0wK+V09wO0sO+sm8gAMyj5E
# uKPqvNQ/fLEwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAIT
# MwAAAcUDzc0hofTvOQABAAABxTAiBCAUBiLXb89pWwpWfiLt7KCdsFZonG2R84rY
# VWZMvQb62DANBgkqhkiG9w0BAQsFAASCAgBp1+m8qVwXvvOcGCg/A3fVc/I3Ejfa
# wLCDSoNfxgwDhyLkbzmmQKsKDtB/p1LE1RbHlyow58f7SHc71NHoZFBhx6lWJD9z
# sdCD7PjqXWnK/wYbWxJjRMivt5EawSsvBOyWNIVnshWAZm26e8DEwf823kn/UmI1
# g1dsoubvvL/86hjWb0Mi1SwYGJn7SKd86Hg/IsLLbkJ2fa9pWO9+a8GQ/9Z9ProF
# 8GJnj9J6npYd0IdRmhfHyhslJYtXD40GiSK4NsGA82tPUKQyMxLVv0FrV1ZmS7R6
# Gb3QHHVg+A1kDNry/nhqISLXr27BFGaBTuBUMgPB+5Ve9nPyD8+WbNhnV75LkwX1
# EVfHFlr40pM9a1oJOu99uAOOy2wJxr4NhdeUtESe9xyL93eJtHNGnSwGsgMo4XHZ
# 2UeH0Tjo5mJ4mu/1v4YzU5D78rJTM9gQz8zqwfF7LW0gnfSkshyumqljHmRS9APn
# CfyW99aRmzldA9O4f4jriy9ZZ/y8XGZWeTCx1vtyoxSbkQZNv+wenHiqggu0g9TI
# QkkyXNR8FEH6m7AKmxmt2Rijd/scHJDU4DUNr6GfNI1RsjkKzq98LU7nhet3PZN9
# v5JBynQDRP3/n9FjdsDRqFnxy1WqwwWeZUsTEXfpAxq9Nv4ardaK93DBmfRZFYEC
# oILYbT3oz4n+5g==
# SIG # End signature block
