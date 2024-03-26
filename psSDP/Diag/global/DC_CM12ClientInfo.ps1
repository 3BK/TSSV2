# *********************************************************************************************************************
# Version 1.0
# Date: 02-29-2012
# Author: Vinay Pamnani - vinpa@microsoft.com
# Description:
# 		Collects Configuration Manager Client Information
#		1. Gets CCMExec service Status, Start time, Install Directory, Assigned Site, MP, Client Version and GUID.
# 		2. Gets Software Distribution Execution History.
#		3. Gets Cache Size, Location and Elements.
#		4. Gets Inventory Timestamps
#		5. Gets Update Installation Status
#		6. Gets State Message Data
#		7. Gets File Versions from Client Install Directory
#		8. Summarizes all data in a PSObject, then dumps to a text file for better readability.
# *********************************************************************************************************************

trap [Exception]
{
	WriteTo-ErrorDebugReport -ErrorRecord $_
	continue
}

If (!$Is_Client) {
	TraceOut "ConfigMgr Client not detected. This script gathers data only from a Client. Exiting."
	exit 0
}

function Get-WmiOutput {
	Param(
		[Parameter(Mandatory=$true)]
	    [string]$Namespace,
		[Parameter(Mandatory=$false)]
	    [string]$ClassName,
		[Parameter(Mandatory=$false)]
	    [string]$Query,
		[Parameter(Mandatory=$false)]
	    [string]$DisplayName,
		[Parameter(Mandatory=$false)]
		[switch]$FormatList,
		[Parameter(Mandatory=$false)]
		[switch]$FormatTable
	)

	if ($DisplayName) {
		$DisplayText = $DisplayName
	}
	else {
		$DisplayText = $ClassName
	}

	$results =  "`r`n=================================`r`n"
	$results += " $DisplayText `r`n"
	$results += "=================================`r`n`r`n"

	if ($ClassName) {
		$Temp = Get-WmiData -Namespace $Namespace -ClassName $ClassName
	}

	if ($Query) {
		$Temp = Get-WmiData -Namespace $Namespace -Query $Query
	}

	if ($Temp) {
		if ($FormatList) {
			$results += ($Temp | Format-List | Out-String -Width 500).Trim()
		}

		if ($FormatTable) {
			$results += ($Temp | Format-Table -AutoSize | Out-String -Width 500).Trim()
		}

		$results += "`r`n"
	}
	else {
		$results += "    No Instances.`r`n"
	}

	return $results
}

function Get-WmiData{
	Param(
		[Parameter(Mandatory=$true)]
	    [string]$Namespace,
	    [Parameter(Mandatory=$false)]
	    [string]$ClassName,
		[Parameter(Mandatory=$false)]
	    [string]$Query
	)

	if ($ClassName) {
		$Temp = Get-CimInstance -Namespace $Namespace -Class $ClassName -ErrorVariable WMIError -ErrorAction SilentlyContinue
	}

	if ($Query) {
		$Temp = Get-CimInstance -Namespace $Namespace -Query $Query -ErrorVariable WMIError -ErrorAction SilentlyContinue
	}

	if ($WMIError.Count -ne 0) {
		if ($WMIError[0].Exception.Message -eq "") {
			$results = $WMIError[0].Exception.ToString()
		}
		else {
			$results = $WMIError[0].Exception.Message
		}
		$WMIError.Clear()
		return $results
	}

	if (($Temp | Measure-Object).Count -gt 0) {
		$results = $Temp | Select-Object * -ExcludeProperty __GENUS, __CLASS, __SUPERCLASS, __DYNASTY, __RELPATH, __PROPERTY_COUNT, __DERIVATION, __SERVER, __NAMESPACE, __PATH, PSComputerName, Scope, Path, Options, ClassPath, Properties, SystemProperties, Qualifiers, Site, Container
	}
	else {
		$results = $null
	}

	return $results
}

TraceOut "Started"

Import-LocalizedData -BindingVariable ScriptStrings
$sectiondescription = "Configuration Manager Client Information"

# ----------------
# Write Progress
# ----------------
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CM07ClientInfo -Status $ScriptStrings.ID_SCCM_CM07ClientInfo_ClientInfo

TraceOut "    Getting Client Information"

# ----------------------
# Current Time:
# ----------------------
AddTo-CMClientSummary -Name "Current Time" -Value $CurrentTime

# -------------
# Computer Name
# -------------
AddTo-CMClientSummary -Name "Client Name" -Value $ComputerName

# ------------------
# Assigned Site Code
# ------------------
$Temp = Get-RegValue ($Reg_SMS + "\Mobile Client") "AssignedSiteCode"
If ($null -ne $Temp) {
	AddTo-CMClientSummary -Name "Assigned Site Code" -Value $Temp}
else {
	AddTo-CMClientSummary -Name "Assigned Site Code" -Value "Error obtaining value from Registry"}

# ------------------------
# Current Management Point
# ------------------------
$Temp = Get-CimInstance -Namespace root\CCM -Class SMS_Authority -ErrorAction SilentlyContinue
If ($Temp -is [WMI]) {
	AddTo-CMClientSummary -Name "Current MP" -Value $Temp.CurrentManagementPoint }
else {
	AddTo-CMClientSummary -Name "Current MP" -Value "Error obtaining value from SMS_Authority WMI Class" }

# --------------
# Client Version
# --------------
$Temp = Get-CimInstance -Namespace root\CCM -Class SMS_Client -ErrorAction SilentlyContinue
If ($Temp -is [WMI]) {
	AddTo-CMClientSummary -Name "Client Version" -Value $Temp.ClientVersion }
else {
	AddTo-CMClientSummary -Name "Client Version" -Value "Error obtaining value from SMS_Client WMI Class" }

# ----------------------------------------------------------
# Installation Directory - defined in utils_ConfigMgr07.ps1
# ----------------------------------------------------------
If ($null -ne $CCMInstallDir) {
	AddTo-CMClientSummary -Name "Installation Directory" -Value $CCMInstallDir }
else {
	AddTo-CMClientSummary -Name "Installation Directory" -Value "Error obtaining value" }

# ------------
# Client GUID
# ------------
$Temp = Get-CimInstance -Namespace root\CCM -Class CCM_Client -ErrorAction SilentlyContinue
If ($Temp -is [WMI]) {
	AddTo-CMClientSummary -Name "Client ID" -Value $Temp.ClientId
	AddTo-CMClientSummary -Name "Previous Client ID (if any)" -Value $Temp.PreviousClientId
	AddTo-CMClientSummary -Name "Client ID Change Date" -Value $Temp.ClientIdChangeDate }
else {
	AddTo-CMClientSummary -Name "Client ID Information" -Value "Error Obtaining value from CCM_Client WMI Class" }

# -----------------------
# CCMExec Service Status
# -----------------------
$Temp = Get-Service | Where-Object {$_.Name -eq 'CCMExec'} | Select-Object Status
If ($null -ne $Temp) {
	if ($Temp.Status -eq 'Running') {
		$Temp2 = Get-Process | Where-Object {$_.ProcessName -eq 'CCMExec'} | Select-Object StartTime
		AddTo-CMClientSummary -Name "CCMExec Status" -Value "Running. StartTime = $($Temp2.StartTime)"
	}
	else {
		AddTo-CMClientSummary -Name "CCMExec Status" -Value $Temp.Status
	}
}
Else {
	AddTo-CMClientSummary -Name "CCMExec Service Status" -Value "ERROR: Service Not found"
}

# ----------------
# Write Progress
# ----------------
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CM07ClientInfo -Status $ScriptStrings.ID_SCCM_CM07ClientInfo_History

TraceOut "    Getting Software Distribution and Application Execution History"

# -----------------------------------------------------
# Software Distribution Execution History from Registry
# -----------------------------------------------------
$Temp = ($Reg_SMS -replace "HKLM\\", "HKLM:\") + "\Mobile Client\Software Distribution\Execution History"
If (Check-RegKeyExists $Temp) {
	$TempFileName = ($ComputerName + "_CMClient_ExecutionHistory.txt")
	$ExecHistory = Join-Path $Pwd.Path $TempFileName
	Get-ChildItem $Temp -Recurse `
	| ForEach-Object {Get-ItemProperty $_.PSPath} `
	| Select-Object @{name="Path";exp={$_.PSPath.Substring($_.PSPath.LastIndexOf("History\") + 8)}}, _ProgramID, _State, _RunStartTime, SuccessOrFailureCode, SuccessOrFailureReason `
	| Out-File $ExecHistory -Append -Width 500
	AddTo-CMClientSummary -Name "ExecMgr History" -Value ("Review $TempFileName") -NoToSummaryReport
	CollectFiles -filesToCollect $ExecHistory -fileDescription "ExecMgr History"  -sectionDescription $sectiondescription -noFileExtensionsOnDescription
}
else {
	AddTo-CMClientSummary -Name "ExecMgr History" -Value "Execution History not found" -NoToSummaryReport
}

# -----------------------------------------------------
# Application Enforce Status from WMI
# -----------------------------------------------------
$Temp = Get-CimInstance -Namespace root\CCM\CIModels -Class CCM_AppEnforceStatus -ErrorVariable WMIError -ErrorAction SilentlyContinue
If ($WMIError.Count -eq 0)
{
	If ($null -ne $Temp) {
		$TempFileName = ($ComputerName + "_CMClient_AppHistory.txt")
		$AppHist = Join-Path $Pwd.Path $TempFileName
		$Temp | Select-Object AppDeliveryTypeId, ExecutionStatus, ExitCode, Revision, ReconnectData `
		| Out-File $AppHist -Append -Width 250
		AddTo-CMClientSummary -Name "App Execution History" -Value ("Review $TempFileName") -NoToSummaryReport
		CollectFiles -filesToCollect $AppHist -fileDescription "Application History"  -sectionDescription $sectiondescription -noFileExtensionsOnDescription
	}
	else {
		AddTo-CMClientSummary -Name "App Execution History" -Value ("Error obtaining data or no data in WMI") -NoToSummaryReport
	}
}
Else {
	AddTo-CMClientSummary -Name "App Execution History" -Value ("ERROR: " + $WMIError[0].Exception.Message) -NoToSummaryReport
	$WMIError.Clear()
}

# -----------------
# Cache Information
# -----------------
$Temp = Get-CimInstance -Namespace root\ccm\softmgmtagent -Class CacheConfig -ErrorVariable WMIError -ErrorAction SilentlyContinue
If ($WMIError.Count -eq 0)
{
	If ($null -ne $Temp) {
		$TempFileName = ($ComputerName + "_CMClient_CacheInfo.txt")
		$CacheInfo = Join-Path $Pwd.Path $TempFileName
		"Cache Config:" | Out-File $CacheInfo
		"==================" | Out-File $CacheInfo -Append
		$Temp | Select-Object Location, Size, NextAvailableId | Format-List * | Out-File $CacheInfo -Append -Width 500
		"Cache Elements:" | Out-File $CacheInfo -Append
		"===============" | Out-File $CacheInfo -Append
		$Temp = Get-CimInstance -Namespace root\ccm\softmgmtagent -Class CacheInfoEx -ErrorAction SilentlyContinue
		$Temp | Select-Object Location, ContentId, CacheID, ContentVer, ContentSize, LastReferenced, PeerCaching, ContentType, ReferenceCount, PersistInCache `
			| Sort-Object -Property Location | Format-Table -AutoSize | Out-File $CacheInfo -Append -Width 500
		AddTo-CMClientSummary -Name "Cache Information" -Value ("Review $TempFileName") -NoToSummaryReport
		CollectFiles -filesToCollect $CacheInfo -fileDescription "Cache Information"  -sectionDescription $sectiondescription -noFileExtensionsOnDescription
	}
	Else {
		AddTo-CMClientSummary -Name "Cache Information" -Value "No data found in WMI." -NoToSummaryReport
	}
}
Else {
	AddTo-CMClientSummary -Name "Cache Information" -Value ("ERROR: " + $WMIError[0].Exception.Message) -NoToSummaryReport
	$WMIError.Clear()
}

# -----------------------------------------------
# Inventory Timestamps from InventoryActionStatus
# -----------------------------------------------
$Temp = Get-CimInstance -Namespace root\ccm\invagt -Class InventoryActionStatus -ErrorVariable WMIError -ErrorAction SilentlyContinue
If ($WMIError.Count -eq 0)
{
	If ($null -ne $Temp) {
		$TempFileName = ($ComputerName + "_CMClient_InventoryVersions.txt")
		$InvVersion = Join-Path $Pwd.Path $TempFileName
		$Temp | Select-Object InventoryActionID, @{name="LastCycleStartedDate(LocalTime)";expression={$_.ConvertToDateTime($_.LastCycleStartedDate)}}, LastMajorReportversion, LastMinorReportVersion, @{name="LastReportDate(LocalTime)";expression={$_.ConvertToDateTime($_.LastReportDate)}} `
		| Out-File $InvVersion -Append
		AddTo-CMClientSummary -Name "Inventory Versions" -Value ("Review $TempFileName") -NoToSummaryReport
		CollectFiles -filesToCollect $InvVersion -fileDescription "Inventory Versions"  -sectionDescription $sectiondescription -noFileExtensionsOnDescription
	}
	else {
		AddTo-CMClientSummary -Name "Inventory Versions" -Value "No data found in WMI." -NoToSummaryReport
	}
}
Else {
	AddTo-CMClientSummary -Name "Inventory Versions" -Value ("ERROR: " + $WMIError[0].Exception.Message) -NoToSummaryReport
	$WMIError.Clear()
}

# ----------------
# Write Progress
# ----------------
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CM07ClientInfo -Status $ScriptStrings.ID_SCCM_CM07ClientInfo_Updates

TraceOut "    Getting Software Update Status and State Messages"

# -----------------------------------
# Update Status from CCM_UpdateStatus
# -----------------------------------
$TempFileName = ($ComputerName + "_CMClient_CCM-UpdateStatus.txt")
$UpdStatus = Join-Path $Pwd.Path $TempFileName
"=================================" | Out-File $UpdStatus
" CCM_UpdateStatus" | Out-File $UpdStatus -Append
"=================================" | Out-File $UpdStatus -Append
$Temp = Get-CimInstance -Namespace root\CCM\SoftwareUpdates\UpdatesStore -Class CCM_UpdateStatus -ErrorVariable WMIError -ErrorAction SilentlyContinue
If ($WMIError.Count -eq 0)
{
	If ($null -ne $Temp) {
		$Temp | Select-Object UniqueID, Article, Bulletin, RevisionNumber, Status, @{name="ScanTime(LocalTime)";expression={$_.ConvertToDateTime($_.ScanTime)}}, ExcludeForStateReporting, Title, SourceUniqueId `
		  | Sort-Object -Property Article, UniqueID -Descending | Format-Table -AutoSize | Out-File $UpdStatus -Append -Width 500
		AddTo-CMClientSummary -Name "CCM Update Status" -Value ("Review $TempFileName") -NoToSummaryReport
		CollectFiles -filesToCollect $UpdStatus -fileDescription "CCM Update Status"  -sectionDescription $sectiondescription -noFileExtensionsOnDescription
	}
	else {
		AddTo-CMClientSummary -Name "CCM Update Status" -Value ("No data in WMI") -NoToSummaryReport
	}
}
Else {
	AddTo-CMClientSummary -Name "CCM Update Status" -Value ("ERROR: " + $WMIError[0].Exception.Message) -NoToSummaryReport
	$WMIError.Clear()
}

# --------------------------------
# State Messages from CCM_StateMsg
# --------------------------------
$TempFileName = ($ComputerName + "_CMClient_CCM-StateMsg.txt")
$StateMsg = Join-Path $Pwd.Path $TempFileName
"=================================" | Out-File $StateMsg
" CCM_StateMsg " | Out-File $StateMsg -Append
"=================================" | Out-File $StateMsg -Append
$Temp = Get-CimInstance -Namespace root\CCM\StateMsg -Class CCM_StateMsg -ErrorVariable WMIError -ErrorAction SilentlyContinue
If ($WMIError.Count -eq 0)
{
	If ($null -ne $Temp) {
		$Temp | Select-Object TopicID, TopicType, TopicIDType, StateID, Priority, MessageSent, @{name="MessageTime(LocalTime)";expression={$_.ConvertToDateTime($_.MessageTime)}} `
		 | Sort-Object -Property TopicType, TopicID | Format-Table -AutoSize | Out-File $StateMsg -Append -Width 500
		AddTo-CMClientSummary -Name "CCM State Messages" -Value ("Review $TempFileName") -NoToSummaryReport
		CollectFiles -filesToCollect $StateMsg -fileDescription "State Messages"  -sectionDescription $sectiondescription -noFileExtensionsOnDescription
	}
	else {
		AddTo-CMClientSummary -Name "CCM State Messages" -Value ("No data in WMI") -NoToSummaryReport
	}
}
Else {
	AddTo-CMClientSummary -Name "CCM State Messages" -Value ("ERROR: " + $WMIError[0].Exception.Message) -NoToSummaryReport
	$WMIError.Clear()
}

TraceOut "    Getting WMI Data from Client"
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CM07ClientInfo -Status $ScriptStrings.ID_SCCM_CM07ClientInfo_WMIData

# --------------------------------
# Deployments
# --------------------------------
$TempFileName = ($ComputerName + "_CMClient_CCM-MachineDeployments.TXT")
$OutputFile = join-path $pwd.path $TempFileName
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -DisplayName "Update Deployments" -Query "SELECT AssignmentID, AssignmentAction, AssignmentName, StartTime, EnforcementDeadline, SuppressReboot, NotifyUser, OverrideServiceWindows, RebootOutsideOfServiceWindows, UseGMTTimes, WoLEnabled FROM CCM_UpdateCIAssignment" `
  -FormatTable | Sort-Object -Property AssignmentID | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -DisplayName "Application Deployments (Machine only)" -Query "SELECT AssignmentID, AssignmentAction, AssignmentName, StartTime, EnforcementDeadline, SuppressReboot, NotifyUser, OverrideServiceWindows, RebootOutsideOfServiceWindows, UseGMTTimes, WoLEnabled FROM CCM_ApplicationCIAssignment" `
  -FormatTable | Sort-Object -Property AssignmentID | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -DisplayName "DCM Deployments (Machine only)" -Query "SELECT AssignmentID, AssignmentAction, AssignmentName, StartTime, EnforcementDeadline, SuppressReboot, NotifyUser, OverrideServiceWindows, RebootOutsideOfServiceWindows, UseGMTTimes, WoLEnabled FROM CCM_DCMCIAssignment" `
  -FormatTable | Sort-Object -Property AssignmentID | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -DisplayName "Package Deployments (Machine only)" -Query "SELECT PKG_PackageID, ADV_AdvertisementID, PRG_ProgramName, PKG_Name, PRG_CommandLine, ADV_MandatoryAssignments, ADV_ActiveTime, ADV_ActiveTimeIsGMT, ADV_RCF_InstallFromLocalDPOptions, ADV_RCF_InstallFromRemoteDPOptions, ADV_RepeatRunBehavior, PRG_MaxDuration, PRG_PRF_RunWithAdminRights, PRG_PRF_AfterRunning FROM CCM_SoftwareDistribution" `
  -FormatTable | Sort-Object -Property AssignmentID | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -DisplayName "Task Sequence Deployments" -Query "SELECT PKG_PackageID, ADV_AdvertisementID, PRG_ProgramName, PKG_Name, TS_BootImageID, TS_Type, ADV_MandatoryAssignments, ADV_ActiveTime, ADV_ActiveTimeIsGMT, ADV_RCF_InstallFromLocalDPOptions, ADV_RCF_InstallFromRemoteDPOptions, ADV_RepeatRunBehavior, PRG_MaxDuration FROM CCM_TaskSequence" `
  -FormatTable | Sort-Object -Property AssignmentID | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -ClassName CCM_ServiceWindow -FormatTable | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -ClassName CCM_RebootSettings -FormatTable | Out-File $OutputFile -Append

AddTo-CMClientSummary -Name "Machine Deployments" -Value ("Review $TempFileName") -NoToSummaryReport
CollectFiles -filesToCollect $OutputFile -fileDescription "Machine Deployments" -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# --------------------------------
# Client Agent Configs
# --------------------------------
$TempFileName = ($ComputerName + "_CMClient_CCM-ClientAgentConfig.TXT")
$OutputFile = join-path $pwd.path $TempFileName

Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -ClassName CCM_ClientAgentConfig -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -ClassName CCM_SoftwareUpdatesClientConfig -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -ClassName CCM_ApplicationManagementClientConfig -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -ClassName CCM_SoftwareDistributionClientConfig -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -ClassName CCM_Logging_GlobalConfiguration -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -ClassName CCM_PolicyAgent_Configuration -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -ClassName CCM_Service_ResourceProfileConfiguration -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -ClassName CCM_ConfigurationManagementClientConfig -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -ClassName CCM_HardwareInventoryClientConfig -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -ClassName CCM_SoftwareInventoryClientConfig -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -ClassName CCM_SuperPeerClientConfig -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -ClassName CCM_EndpointProtectionClientConfig -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\Policy\Machine\ActualConfig -ClassName CCM_AntiMalwarePolicyClientConfig -FormatList | Out-File $OutputFile -Append

AddTo-CMClientSummary -Name "Client Agent Configs" -Value ("Review $TempFileName") -NoToSummaryReport
CollectFiles -filesToCollect $OutputFile -fileDescription "Client Agent Configs" -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# --------------------------------
# Various WMI classes
# --------------------------------

$TempFileName = ($ComputerName + "_CMClient_CCM-ClientMPInfo.TXT")
$OutputFile = join-path $pwd.path $TempFileName

Get-WmiOutput -Namespace root\CCM -ClassName SMS_Authority -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM -ClassName CCM_Authority -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM -ClassName SMS_LocalMP -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM -ClassName SMS_LookupMP -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM -ClassName SMS_MPProxyInformation -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM -ClassName CCM_ClientSiteMode -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM -ClassName SMS_Client -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM -ClassName ClientInfo -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM -ClassName SMS_PendingReRegistrationOnSiteReAssignment -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM -ClassName SMS_PendingSiteAssignment -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\LocationServices -ClassName SMS_ActiveMPCandidate -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -Namespace root\CCM\LocationServices -DisplayName "SMS_MPInformation" -Query "SELECT MP, MPLastRequestTime, MPLastUpdateTime, SiteCode, Reserved2 FROM SMS_MPInformation" -FormatList | Out-File $OutputFile -Append

AddTo-CMClientSummary -Name "MP Information" -Value ("Review $TempFileName") -NoToSummaryReport
CollectFiles -filesToCollect $OutputFile -fileDescription "MP Information" -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# ----------------
# Write Progress
# ----------------
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CM07ClientInfo -Status $ScriptStrings.ID_SCCM_CM07ClientInfo_FileVer
TraceOut "    Getting File Versions"

# ---------------------
# Binary Versions List
# ---------------------
$TempFileName = ($ComputerName + "_CMClient_FileVersions.TXT")
$OutputFile = join-path $pwd.path $TempFileName
Get-ChildItem ($CCMInstallDir) -recurse -include *.dll,*.exe -ErrorVariable DirError -ErrorAction SilentlyContinue | `
	ForEach-Object {[System.Diagnostics.FileVersionInfo]::GetVersionInfo($_)} | `
	Select-Object FileName, FileVersion, ProductVersion | Format-Table -AutoSize | `
	Out-File $OutputFile -Width 1000
If ($DirError.Count -eq 0) {
	CollectFiles -filesToCollect $OutputFile -fileDescription "Client File Versions" -sectionDescription $sectiondescription -noFileExtensionsOnDescription
	AddTo-CMClientSummary -Name "File Versions" -Value ("Review $TempFileName") -NoToSummaryReport
}
else {
	AddTo-CMClientSummary -Name "File Versions" -Value ("ERROR: " + $DirError[0].Exception.Message) -NoToSummaryReport
	$DirError.Clear()
}

# ---------------------------
# Collect Client Information
# ---------------------------
# Moved to DC_FinishExecution

Traceout "Completed"


# SIG # Begin signature block
# MIInrQYJKoZIhvcNAQcCoIInnjCCJ5oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA5jqcjT92EI31b
# 6XX1YFoyKGq8a0/JmU6HCmaZcPIPSKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGY0wghmJAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEID+5a97OjDPG9YHc6vH1Pt7n
# S/qL3KQDmBSe99YirwGnMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCFOB3Iuxig3ZWUG8VRMluEssCF4gOzAT2qWSTRlN19XXR2xdRzKXUg
# l78I1wj3tFhxIr74/9YUtHrYTJXfQjeTyK69qbq0oSzyNW8P4tzPwOyObhil83JV
# uECVpvsPrbko75ax4N3RIM2RQREL+fK8s0Pa/kmltA8AxWXU9aQdcn6/4F8zcaMp
# 14W64b9NXld5JMkvU7viXw4Ye35Kgoq/OBNONpX5mXCun94X66npaw85G5W6NOp4
# /jOpIuw+ctx29drdUTjgwDRPtAuRdoOWCw7X7M477CPzpTiQJFAKnLBYu1GDuH/9
# 06gv7iTrJcjcKsT+9Fa+IFIv2VTrD64ToYIXFTCCFxEGCisGAQQBgjcDAwExghcB
# MIIW/QYJKoZIhvcNAQcCoIIW7jCCFuoCAQMxDzANBglghkgBZQMEAgEFADCCAVgG
# CyqGSIb3DQEJEAEEoIIBRwSCAUMwggE/AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIAHaXRisrswVWGuJK28cn0Eb+ZTVmK+jQ4+S6wWku9VSAgZi3n80
# 0owYEjIwMjIwODAxMDczNTQyLjAxWjAEgAIB9KCB2KSB1TCB0jELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IEly
# ZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# TjozQkQ0LTRCODAtNjlDMzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaCCEWUwggcUMIIE/KADAgECAhMzAAABibS/hjCEHEuPAAEAAAGJMA0G
# CSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIx
# MTAyODE5Mjc0MVoXDTIzMDEyNjE5Mjc0MVowgdIxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9w
# ZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JENC00
# QjgwLTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC9BlfFkWZrqmWa47K82lXz
# E407BxiiVkb8GPJlYZKTkk4ZovKsoh3lXFUdYeWyYkThK+fOx2mwqZXHyi04294h
# QW9Jx4RmnxVea7mbV+7wvtz7eXBdyJuNxyq0S+1CyWiRBXHSv4vnhpus0NqvAUbv
# chpGJ0hLWL1z66cnyhjKENEusLKwUBXHJCE81mRYrtnz9Ua6RoosBYdcKH/5HneH
# jaAUv73+YAAvHMJde6h+Lx/9coKbvE3BVzWE40ILPqir3gC5/NU2SQhbhutRCBik
# Jwmb1TRc2ZC+2uilgOf1S1jxhDQ0p6dc+12Asd1Dw2e/eKASsoutYjRrmfmON0p/
# CT7ya9qSp1maU6x545LVeylA0kArW5mWUAhNydBk5w7mh+M5Dfe6NZyQBd3P7/He
# juXgBT9NI4zMZkzCFR21XALd1Jsi2lJUWCeMzYI4Qn3OAJp286KsYMs3jvWNkjaM
# KWSOwlN2A+TfjdNADgkW92z+6dmrS4uv6eJndfjg4HHbH6BWWWfZzhRtlc254DjJ
# LVMkZtskUggsCZNQD0C6Pl4hIZNs2LJbHv0ecI5Nqvf1AQqjObgudOYNfLT8oj8f
# +dhkYq5Md9yQ/bzBBLTqsP58NLnEvBxEwJb3YOQdea1uEbJGKUE4vkvFl6VB/G3n
# jCXhZQLQB0ASiU96Q4PA7wIDAQABo4IBNjCCATIwHQYDVR0OBBYEFJdvH7NHWngg
# gB6C4DqscqSt+XtQMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8G
# A1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBs
# BggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# DQYJKoZIhvcNAQELBQADggIBAI60t2lZQjgrB8sut9oqssH3YOpsCykZYzjVNo7g
# mX6wfE+jnba67cYpAKOaRFat4e2V/LL2Q6TstZrHeTeR7wa19619uHuofQt5XZc5
# aDf0E6cd/qZNxmrsVhJllyHUkNCNz3z452WjD6haKHQNu3gJX97X1lwT7WfXPNaS
# yRQR3R/mM8hSKzfen6+RjyzN24C0Jwhw8VSEjwdvlqU9QA8yMbPApvs0gpud/yPx
# w/XwCzki95yQXSiHVzDrdFj+88rrYsNh2mLtacbY5u+eB9ZUq3CLBMjiMePZw72r
# fscN788+XbXqBKlRmHRqnbiYqYwN9wqnU3iYR2zHPiix46s9h4WwcdYkUnoCK++q
# fvQpN4mmnmv4PFKpt5LLSbEhQ6r+UBpTGA1JBVRfbq3yv59yKSh8q/bdYeu1FXe3
# utVOwH1jOtFqKKSbPrwrkdZ230ypQvE9A+j6mlnQtGqQ5p7jrr5QpFjQnFa12sxz
# m8eUdl+eqNrCP9GwzZLpDp9r1P0KdjU3PsNgEbfJknII8WyuBTTmz2WOp+xKm2kV
# 1SH1Hhx74vvVJYMszbH/UwUsscAxtewSnwqWgQa1oNQufG19La1iF+4oapFegR8M
# 8Aych1O9A+HcYdDhKOSQEBEcvQxjvlqWEZModaMLZotU6jyhsogGTyF+cUNR/8TJ
# XDi5MIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0B
# AQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAG
# A1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAw
# HhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOTh
# pkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xP
# x2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ
# 3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOt
# gFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYt
# cI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXA
# hjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0S
# idb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSC
# D/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEB
# c8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh
# 8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8Fdsa
# N8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkr
# BgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q
# /y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBR
# BgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsG
# AQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
# BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjE
# MFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv
# Y3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEF
# BQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEB
# CwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnX
# wnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOw
# Bb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jf
# ZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ
# 5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+
# ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgs
# sU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6
# OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p
# /cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6
# TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784
# cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtQwggI9
# AgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1p
# dGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozQkQ0LTRCODAtNjlDMzElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIa
# AxUAIaUJreR63J657Ltsk2laQy6IJxCggYMwgYCkfjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOaRjzEwIhgPMjAyMjA4MDEw
# NzMwNTdaGA8yMDIyMDgwMjA3MzA1N1owdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA
# 5pGPMQIBADAHAgEAAgIlGzAHAgEAAgIRczAKAgUA5pLgsQIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBBQUAA4GBACueThL1sR3EJ2/qW8CoMkue6yHFuNJ2IHuxU4IV6CbW
# EjKI6WCeA3hghnLnBhcVOdtRxOF2Kt/9pY70qCrvKbniicJRvxdj1Hq8FsnPiHjl
# P/Awgo1UajakjIEQbJguCaxdJg/mki+DMWFsa99PKdK0C8UH/87Cz9xKiDhXmo4l
# MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGJtL+GMIQcS48AAQAAAYkwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgZU4AzCgQ0ttbgVLSsFxz
# eOSQbcjWhzqoTgBrMA6bNOMwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBm
# d0cx3FBXVWxulYc5MepYTJy9xEmbtxjr2X9SZPyPRTCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABibS/hjCEHEuPAAEAAAGJMCIEICS3
# jkmWtW+jecW0AZBbxAq256f5xxy6ayfO2D9phUoRMA0GCSqGSIb3DQEBCwUABIIC
# AIGDhR5LySVuUcIrhbvEw/bJxZ3fmPCota553vfZnGDXuFJ1zZYilvkrOgjkp4vM
# uaYtDulnYLDVM6CsVgEl7HOmiyj5SzJvIaRNxSJbsNeWs6jR25+UKgKAj9gH1qc4
# ic+N/UFUIjc4WpzbQHWSS5wYIt2TXycAX4XxWx7w9w5Ec3eBUme0AWSu2SMdCi5g
# xO8Ywvp7Bvs5AKPVCFcUkWwEbuyyqhxemKPSKWbmSsFjBZzSlUAvaOQEV+4WHu7B
# WgHC86XQPFmdn5bSPm8h9UqpNNZ0DbL8kH2dX3oLp45I1sw+gMiWbuTBYm27l4rE
# GX+w1bheZY/Dvu5pPW9NAKoLgrbNbWCMdQ5ygHqks91CZIcqPboqMPJfodrdLmLQ
# m9Apnkj08a//GOdc7VFEl3duvtlmHUXgHeOuVX0o0AxznZpMQ+Mm3vHlIkYEhicK
# rWMcVzJhVai0V03RA/SHfNxv4JP9PtGK5oWuisMRBa43SYf7/us531jqTiPhYg5f
# lqPjXr1ssUBrwjB6I+XHsgMuent9OXdtKIaOl8gQZs4PDxBZdSwy6fUMCbkDuzn9
# BowKTj6WQcsC05T6PqHP+TyexeTVQVoBwkmhlTIiV8zEzNpSQnBz9spbUL+UnTSL
# aQ0tSoKSm76ihPhU0SnWyN28hFbtae5D+8AvFYCXEtBq
# SIG # End signature block
