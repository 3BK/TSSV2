# ***********************************************************************************************
# File: utils_ConfigMgr12-ps1
# Version 1.0
# Date: 02-17-2012 - Last edit 2022-06-01
# Author: Vinay Pamnani - vinpa@microsoft.com
# Description:  Utility Script to load common variables/functions. View utils_ConfigMgr07_ReadMe.txt for details.
# 		1. Defines commonly used functions in the Troubleshooter
# 		2. Defines global variables
# 		3. Detects Configuration Manager Client and Server Roles Installation Status
#		4. Detects Install and Log Locations for Client, Server, Admin Console and WSUS
#		5. Executes WSUSutil.exe checkhealth, if WSUS is installed.
# ***********************************************************************************************

trap [Exception]
{
	WriteTo-ErrorDebugReport -ErrorRecord $_
	continue
}

# Manifest Name - Used for Logging
Set-Variable -Name ManifestName -Value "CM12" -Scope Global
Set-Variable -Name ManifestLog -Value (Join-Path -Path ($PWD.Path) -ChildPath "..\_SDPExecution_log.txt") -Scope Global

if (Test-Path $ManifestLog) {
	Remove-Item -Path $ManifestLog -Force
}

##########################
## Function Definitions ##
##########################

function TraceOut{
	# To standardize Logging to StdOut.log
    param (
		$WhatToWrite
		)
	process
	{
			$SName = ([System.IO.Path]::GetFileName($MyInvocation.ScriptName))
			$SName = $SName.Substring(0, $SName.LastIndexOf("."))
			$SLine = $MyInvocation.ScriptLineNumber.ToString()
			$STime =Get-Date -Format G
			WriteTo-StdOut "	$STime [$ManifestName][$ComputerName][$SName][$SLine] $WhatToWrite"
			"$STime [$ManifestName][$ComputerName][$SName][$SLine] $WhatToWrite" | Out-File -FilePath $ManifestLog -Append -ErrorAction SilentlyContinue
	}
}

function AddTo-CMClientSummary (){
	# Adds the specified name/value to the appropriate CMClient PS Objects so that they can be dumped to File & Report in DC_FinishExecution.
	param (
		$Name,
		$Value,
		[switch]$NoToSummaryFile,
		[switch]$NoToSummaryReport
	)

	process {
		if(-not($NoToSummaryFile)) {
			Add-Member -InputObject $global:CMClientFileSummaryPSObject -MemberType NoteProperty -Name $Name -Value $Value
		}

		if (-not($NoToSummaryReport)) {
			Add-Member -InputObject $global:CMClientReportSummaryPSObject -MemberType NoteProperty -Name $Name -Value $Value
		}
	}
}

function AddTo-CMServerSummary (){
	# Adds the specified name/value to the appropriate CMServer PS Objects so that they can be dumped to File & Report in DC_FinishExecution.
	param (
		$Name,
		$Value,
		[switch]$NoToSummaryFile,
		[switch]$NoToSummaryReport
	)

	process {
		if(-not($NoToSummaryFile)) {
			Add-Member -InputObject $global:CMServerFileSummaryPSObject -MemberType NoteProperty -Name $Name -Value $Value
		}

		if (-not($NoToSummaryReport)) {
			Add-Member -InputObject $global:CMServerReportSummaryPSObject -MemberType NoteProperty -Name $Name -Value $Value
		}
	}
}

function AddTo-CMDatabaseSummary (){
	# Adds the specified name/value to the appropriate CMDatabase PS Objects so that they can be dumped to File & Report in DC_FinishExecution.
	param (
		$Name,
		$Value,
		[switch]$NoToSummaryFile,
		[switch]$NoToSummaryReport,
		[switch]$NoToSummaryQueries
	)

	process {
		if(-not($NoToSummaryFile)) {
			Add-Member -InputObject $global:CMDatabaseFileSummaryPSObject -MemberType NoteProperty -Name $Name -Value $Value
		}

		if (-not($NoToSummaryReport)) {
			Add-Member -InputObject $global:CMDatabaseReportSummaryPSObject -MemberType NoteProperty -Name $Name -Value $Value
		}

		if (-not($NoToSummaryQueries)) {
			Add-Member -InputObject $global:CMDatabaseQuerySummaryPSObject -MemberType NoteProperty -Name $Name -Value $Value
		}
	}
}

function Get-ADKVersion (){
	process {
		TraceOut "Get-ADKVersion: Entering"

		$UninstallKey = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
		$ADKKey = Get-ChildItem $UninstallKey -Recurse | ForEach-Object {Get-ItemProperty $_.PSPath} | Where-Object {$_.DisplayName -like '*Assessment and Deployment Kit*'}

		if ($ADKKey) {
			return $ADKKey.DisplayVersion
		}
		else {
			return "ADK Version Not Found."
		}

		TraceOut "Get-ADKVersion: Leaving"
	}
}

#########################################
## SMS Provider and Database Functions ##
#########################################

function Get-DBConnection (){
	param (
		$DatabaseServer,
		$DatabaseName
	)

	process {
		TraceOut "Get-DBConnection: Entering"
		try {
			# Get NetBIOS name of the Database Server
			If ($DatabaseServer.Contains(".")) {
				$DatabaseServer = $DatabaseServer.Substring(0,$DatabaseServer.IndexOf("."))
			}

			# Prepare a Connection String
			If ($DatabaseName.Contains("\")) {
				$InstanceName = $DatabaseName.Substring(0,$DatabaseName.IndexOf("\"))
				$DatabaseName = $DatabaseName.Substring($DatabaseName.IndexOf("\")+1)
				$strConnString = "Integrated Security=SSPI; Application Name=ConfigMgr Diagnostics; Server=$DatabaseServer\$InstanceName; Database=$DatabaseName"
			}
			Else {
				$strConnString = "Integrated Security=SSPI; Application Name=ConfigMgr Diagnostics; Server=$DatabaseServer; Database=$DatabaseName"
			}

			$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
			$SqlConnection.ConnectionString = $strConnString
			TraceOut "SQL Connection String: $strConnString"

			$Error.Clear()
			$SqlConnection.Open()
			TraceOut "Get-DBConnection: Successful"

			# Reset Error Variable only when we're connecting to SCCM database and the connection is successful.
			# If SCCM database connection failed, TS_CheckSQLConfig will retry connection to MASTER, but we don't want to reset Error Variable in that case, if connection succeeds.
			if ($DatabaseName.ToUpper() -ne "MASTER") {
				$global:DatabaseConnectionError = $null
			}
		}
		catch [Exception] {
			$global:DatabaseConnectionError = $_
			$SqlConnection = $null
			TraceOut "Get-DBConnection: Failed with Error: $global:DatabaseConnectionError"
		}

		TraceOut "Get-DBConnection: Leaving"
		return $SqlConnection
	}
}

######################
## Global Variables ##
######################

TraceOut "Script Started"
TraceOut "Setting Global Variables..."

# Get Current Time
Set-Variable -Name CurrentTime -Scope Global
$Temp = Get-CimInstance -Namespace root\cimv2 -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
If ($Temp -is [WMI]) {
	$CurrentTime = ($Temp.ConvertToDateTime($Temp.LocalDateTime)).ToString()
	$Temp = Get-CimInstance -Namespace root\cimv2 -Class Win32_TimeZone -ErrorAction SilentlyContinue
	If ($Temp -is [WMI]) {
		$CurrentTime += " $($Temp.Description)"
		if ((Get-Date).IsDayLightSavingTime()) {
			$CurrentTime += " - Daylight Saving Time"
		}
	}
}
else {
	$CurrentTime = Get-Date -Format G
}

# Remote Execution Status
Set-Variable RemoteStatus -Scope Global

# Set Software\Microsoft Registry Key path
Set-Variable Reg_MS -Value "HKLM\SOFTWARE\Microsoft" -Scope Global
Set-Variable Reg_MS6432 -Value "HKLM\SOFTWARE\Wow6432Node\Microsoft" -Scope Global

# Set SMS, CCM and WSUS Registry Key Path
Set-Variable -Name Reg_CCM -Value ($REG_MS + "\CCM") -Scope Global
Set-Variable -Name Reg_SMS -Value ($REG_MS + "\SMS") -Scope Global
Set-Variable -Name Reg_WSUS -Value "HKLM\Software\Microsoft\Update Services" -Scope Global

# Log Collection Variables and Flags
Set-Variable -Name GetCCMLogs -Value $false -Scope Global
Set-Variable -Name GetSMSLogs -Value $false -Scope Global

# CCMLogPaths is defined as an array since CCM Log Path could be at various locations depending on Client/Role install status
# We'll get all possible locations and parse through Get-Unique to a single value stored in CCMLogPath later since there will only be one CCM Log Location
Set-Variable -Name CCMLogPaths -Value @() -Scope Global
Set-Variable -Name CCMLogPath -Scope Global
Set-Variable -Name CCMInstallDir -Scope Global
Set-Variable -Name CCMSetupLogPath -Scope Global

# Set Variables for Logs for CM12 Roles
Set-Variable -Name Is_SiteSystem -Scope Global
Set-Variable -Name SMSLogPath -Scope Global
Set-Variable -Name AdminUILogPath -Scope Global
Set-Variable -Name EnrollPointLogPath -Scope Global
Set-Variable -Name EnrollProxyPointLogPath -Scope Global
Set-Variable -Name AppCatalogLogPath -Scope Global
Set-Variable -Name AppCatalogSvcLogPath -Scope Global
Set-Variable -Name CRPLogPath -Scope Global
Set-Variable -Name SMSSHVLogPath -Scope Global
Set-Variable -Name DPLogPath -Scope Global
Set-Variable -Name SMSProvLogPath -Scope Global
Set-Variable -Name SQLBackupLogPathUNC -Scope Global

# Site Server Globals
Set-Variable -Name SMSInstallDir -Scope Global
Set-Variable -Name SMSSiteCode -Scope Global
Set-Variable -Name SiteType -Scope Global
Set-Variable -Name SiteBuildNumber -Scope Global
Set-Variable -Name ConfigMgrDBServer -Scope Global
Set-Variable -Name ConfigMgrDBName -Scope Global
Set-Variable -Name ConfigMgrDBNameNoInstance -Scope Global
Set-Variable -Name SMSProviderServer -Scope Global
Set-Variable -Name SMSProviderNamespace -Scope Global

# Database Connection Globals
Set-Variable -Name DatabaseConnection -Scope Global
Set-Variable -Name DatabaseConnectionError -Scope Global

###############################
## Summary Files and Objects ##
###############################
# Summary Objects
Set-Variable -Name SummarySectionDescription -Scope Global -Value "ConfigMgr Data Collection Summary"
Set-Variable -Name CMClientFileSummaryPSObject -Scope Global -Value (New-Object PSObject)
Set-Variable -Name CMClientReportSummaryPSObject -Scope Global -Value (New-Object PSObject)
Set-Variable -Name CMServerFileSummaryPSObject -Scope Global -Value (New-Object PSObject)
Set-Variable -Name CMServerReportSummaryPSObject -Scope Global -Value (New-Object PSObject)
Set-Variable -Name CMDatabaseFileSummaryPSObject -Scope Global -Value (New-Object PSObject)
Set-Variable -Name CMDatabaseReportSummaryPSObject -Scope Global -Value (New-Object PSObject)
Set-Variable -Name CMDatabaseQuerySummaryPSObject -Scope Global -Value (New-Object PSObject)
Set-Variable -Name CMRolesStatusFilePSObject -Scope Global -Value (New-Object PSObject)
Set-Variable -Name CMInstalledRolesStatusReportPSObject -Scope Global -Value (New-Object PSObject)

#####################
## Start Execution ##
#####################

Import-LocalizedData -BindingVariable ScriptStrings
Write-DiagProgress -Activity $ScriptStrings.ID_ACTIVITY_Utils -Status $ScriptStrings.ID_Utils_Init

# Print Variable values
TraceOut "Global Variable - OSArchitecture: $OSArchitecture" # $OSArchitecture is defined in utils_CTS.ps1
TraceOut "Global Variable - Reg_SMS: $Reg_SMS"
TraceOut "Global Variable - Reg_CCM: $Reg_CCM"
TraceOut "Global Variable - Reg_WSUS: $Reg_WSUS"

# --------------------------------------------------------------------------------------------
# Get Remote Execution Status from Get-TSRemote. The following return values can be returned:
#    0 - No TS_Remote environment
#    1 - Under TS_Remote environment, but running on the local machine
#    2 - Under TS_Remote environment and running on a remote machine
# --------------------------------------------------------------------------------------------
$RemoteStatus = (Get-TSRemote)
TraceOut "Global Remote Execution Status: $RemoteStatus"

# -----------------------
# Set CCM Setup Log Path
# -----------------------
$CCMSetupLogPath = Join-Path $Env:windir "ccmsetup"
TraceOut "Global Variable - CCMSetupLogPath: $CCMSetupLogPath"

# ---------------------------------
# Set Site System Global Variables
# ---------------------------------
#$InstalledRolesStatus = New-Object PSObject # For Update-DiagReport
#$RolesStatus = New-Object PSObject
$RolesArray = @{
"Client" = "Configuration Manager Client";
"SiteServer" = "Configuration Manager Site Server";
"SMSProv" = "SMS Provider Server";
"AdminUI" = "Configuration Manager Admin Console";
"AWEBSVC" = "Application Catalog Web Service Point";
"PORTALWEB" = "Application Catalog Website Point";
"AIUS" = "Asset Intelligence Synchronization Point";
"AMTSP" = "Out of Band Service Point";
"CRP" = "Certificate Registration Point";
"DP" = "Distribution Point";
"DWSS" = "Data Warehouse Service Point";
"ENROLLSRV" = "Enrollment Point";
"ENROLLWEB" = "Enrollment Proxy Point";
"EP" = "Endpoint Protection Point";
"FSP" = "Fallback Status Point";
"IIS" = "IIS Web Server";
"MCS" = "Distribution Point - Multicast Enabled";
"MP" = "Management Point";
"PullDP" = "Distribution Point - Pull Distribution Point";
"PXE" = "Distribution Point - PXE Enabled";
"SMP" = "State Migration Point";
"SMS_CLOUD_PROXYCONNECTOR" = "CMG Connection Point";
"SMSSHV" = "System Health Validator Point";
"SRSRP" = "Reporting Services Point";
"WSUS" = "Software Update Point"
}

foreach ($Role in ($RolesArray.Keys | Sort-Object))
{
	Switch ($Role)
	{
		"Client"
		{
			$Installed = Check-RegValueExists ($Reg_SMS + "\Mobile Client") "ProductVersion"
			If ($Installed) {
				$GetCCMLogs = $true
				$CCMLogPaths += (Get-RegValue ($Reg_CCM + "\Logging\@Global") "LogDirectory") + "\"
			}
		}

		"SiteServer"
		{
			$Installed = Check-RegValueExists ($Reg_SMS + "\Setup") "Full Version"
			If ($Installed) {
				$GetSMSLogs = $true ; $Is_SiteSystem = $true
			}
		}

		"SMSProv"
		{
			$Installed = Check-RegKeyExists ($Reg_SMS + "\Providers")
			If ($Installed) {
				$SMSProvLogPath = (Get-RegValue ($Reg_SMS + "\Providers") "Logging Directory")
			}
		}

		"AdminUI"
		{
			$Installed = Check-RegKeyExists ($Reg_MS6432 + "\ConfigMgr10\AdminUI")
			If ($Installed) {$AdminUILogPath = (Get-RegValue ($Reg_MS6432 + "\ConfigMgr10\AdminUI") "AdminUILog")}
		}

		"AWEBSVC"
		{
			$Installed = Check-RegKeyExists ($Reg_SMS + "\" + $Role)
			If ($Installed) {
				$AppCatalogSvcLogPath = (Get-RegValue ($Reg_SMS + "\" + $Role + "\Logging") "AdminUILog")
				$Is_SiteSystem = $true
			}
		}

		"PORTALWEB"
		{
			$Installed = Check-RegKeyExists ($Reg_SMS + "\" + $Role)
			If ($Installed) {
				$AppCatalogLogPath = (Get-RegValue ($Reg_SMS + "\" + $Role + "\Logging") "AdminUILog")
				$Is_SiteSystem = $true
			}
		}

		"AIUS"
		{
			$Installed = Check-RegKeyExists ($Reg_SMS + "\" + $Role)
			If ($Installed) {
				$GetSMSLogs = $true ; $Is_SiteSystem = $true
			}
		}

		"AMTSP"
		{
			$Installed = Check-RegKeyExists ($Reg_SMS + "\" + $Role)
			If ($Installed) {
				$GetSMSLogs = $true ; $Is_SiteSystem = $true
			}
		}

		"CRP"
		{
			$Installed = Check-RegKeyExists ($Reg_SMS + "\" + $Role)
			If ($Installed) {
				$CRPLogPath = (Get-RegValue ($Reg_SMS + "\" + $Role + "\Logging") "AdminUILog")
				$Is_SiteSystem = $true
			}
		}

		"DP"
		{
			$Installed = Check-RegValueExists ($Reg_SMS + "\" + $Role) "NALPath"
			If ($Installed) { $GetSMSLogs = $true ; $Is_SiteSystem = $true }
		}

		"ENROLLSRV"
		{
			$Installed = Check-RegKeyExists ($Reg_SMS + "\" + $Role)
			If ($Installed) {
				$EnrollPointLogPath = (Get-RegValue ($Reg_SMS + "\" + $Role + "\Logging") "AdminUILog")
				$Is_SiteSystem = $true
			}
		}

		"ENROLLWEB"
		{
			$Installed = Check-RegKeyExists ($Reg_SMS + "\" + $Role)
			If ($Installed) {
				$EnrollProxyPointLogPath = (Get-RegValue ($Reg_SMS + "\" + $Role + "\Logging") "AdminUILog")
				$Is_SiteSystem = $true
			}
		}

		"EP"
		{
			$Installed = Check-RegKeyExists ($Reg_SMS + "\Operations Management\Components\SMS_ENDPOINT_PROTECTION_CONTROL_MANAGER")
		}

		"FSP"
		{
			$Installed = Check-RegKeyExists ($Reg_SMS + "\" + $Role)
			If ($Installed) {
				$GetCCMLogs = $true ; $GetSMSLogs = $true
				$CCMLogPaths += Get-RegValue ($Reg_SMS + "\" + $Role +"\Logging\@Global") "LogDirectory"
				$Is_SiteSystem = $true
			}
		}

		"MCS"
		{
			$Installed = Check-RegKeyExists ($Reg_SMS + "\" + $Role)
			If ($Installed) {
				$GetCCMLogs = $true ; $GetSMSLogs = $true ;
				$CCMLogPaths += Get-RegValue ($Reg_SMS + "\" + $Role +"\Logging\@Global") "LogDirectory"
				$Is_SiteSystem = $true
			}
		}

		"MP"
		{
			$Installed = Check-RegValueExists ($Reg_SMS + "\" + $Role) "MP Hostname"
			If ($Installed) {
				$GetCCMLogs = $true ; $GetSMSLogs = $true ;
				$Is_SiteSystem = $true
				$CCMLogPaths += (Get-RegValue ($Reg_CCM + "\Logging\@Global") "LogDirectory") + "\"
			}
		}

		"PullDP"
		{
			$Temp = Get-RegValue ($Reg_SMS + "\DP") "IsPullDP"
			If ($Temp) { $Installed = $true } Else { $Installed = $false }
			If ($Installed) {
				$GetCCMLogs = $true
				$Is_SiteSystem = $true
				$CCMLogPaths += (Get-RegValue ($Reg_CCM + "\Logging\@Global") "LogDirectory") + "\"
			}
		}

		"PXE"
		{
			$Temp = Get-RegValue ($Reg_SMS + "\DP") "IsPXE"
			If ($Temp) { $Installed = $true } Else { $Installed = $false }
			If ($Installed) {
				$GetCCMLogs = $true ; $GetSMSLogs = $true ;
				$Is_SiteSystem = $true
				$CCMLogPaths += Get-RegValue ($Reg_SMS + "\" + $Role +"\Logging\@Global") "LogDirectory"
			}
		}

		"SMP"
		{
			$Installed = Check-RegKeyExists ($Reg_SMS + "\" + $Role)
			If ($Installed) {
				$GetCCMLogs = $true ; $GetSMSLogs = $true ;
				$CCMLogPaths += Get-RegValue ($Reg_SMS + "\" + $Role +"\Logging\@Global") "LogDirectory"
				$Is_SiteSystem = $true
			}
		}

		"SMSSHV"
		{
			$Installed = Check-RegKeyExists ($Reg_MS + "\" + $Role)
			If ($Installed) {
				$GetSMSLogs = $true
				$SMSSHVLogPath = (Get-RegValue ($Reg_MS + "\" + $Role + "\Logging\@Global") "LogDirectory")
				$Is_SiteSystem = $true
			}
		}

		"SRSRP"
		{
			$Installed = Check-RegKeyExists ($Reg_SMS + "\" + $Role)
			If ($Installed) {
				$GetSMSLogs = $true ; $Is_SiteSystem = $true
			}
		}

		"WSUS"
		{
			$Installed = Check-RegKeyExists ($Reg_SMS + "\" + $Role)
			If ($Installed) {
				$GetSMSLogs = $true ; $Is_SiteSystem = $true
			}
		}

		Default
		{
			$Installed = Check-RegKeyExists ($Reg_SMS + "\" + $Role)
		}
	}

	# Set a Variable for each Role and it's Install Status
	Set-Variable -Name ("Is_" + $Role) -Value $Installed -Scope Global
	Add-Member -InputObject $global:CMRolesStatusFilePSObject -MemberType NoteProperty -Name ($RolesArray.Get_Item($Role)) -Value (Get-Variable ("Is_" + $Role) -ValueOnly)
	TraceOut ("Global Role Variable - Is_" + $Role + ": " + (Get-Variable ("Is_" + $Role) -ValueOnly))

	if ($Installed) {
		Add-Member -InputObject $global:CMInstalledRolesStatusReportPSObject -MemberType NoteProperty -Name ($RolesArray.Item($Role)) -Value (Get-Variable ("Is_" + $Role) -ValueOnly)
	}
}

# Mark IIS installed, if WSUS is installed on CAS, since SMS\IIS registry is not set on CAS
if ($Is_WSUS) {
	$Is_IIS = $true
}

# -----------------------------------------------------------------------------------------------------------------------------
# Parse CCMLogPaths, and get a unique path
# To handle collection of CCM Logs even if Client is not installed, but a Role is installed which stores logs in CCM directory
# -----------------------------------------------------------------------------------------------------------------------------
$CCMLogPath = $CCMLogPaths | Sort-Object | Get-Unique

# Error Handling if Get-RegValue failed to obtain a valid CCMLogPath and returned null instead
If (($CCMLogPath -eq "\") -or ($null -eq $CCMLogPath)) {
	$CCMLogPath = $null
	If ($GetCCMLogs) {
		TraceOut "ERROR: CCM Logs need to be collected but CCM Directory not found."
	}
	Else {
		TraceOut "WARNING: GetCCMLogs is set to False. CCM Log Path Not Required."
	}
}
Else {
	$CCMInstallDir = $CCMLogPath.Substring(0, $CCMLogPath.LastIndexOf("\Logs"))
	TraceOut "Global Variable - CCMInstallDir: $CCMInstallDir"
	TraceOut "Global Variable - CCMLogPath: $CCMLogPath"
}

If ($Is_Client) {
	Set-Variable -Name Is_Lantern -Scope Global -Value $true
	Set-Variable -Name LanternLogPath -Scope Global
	$LanternLogPath = Join-Path (Get-RegValue ($Reg_MS + "\PolicyPlatform\Client\Trace") "LogDir") (Get-RegValue ($Reg_MS + "\PolicyPlatform\Client\Trace") "LogFile")
	TraceOut "Global Variable - LanternLogPath: $LanternLogPath"
}

# -----------------------------
# Get SMSLogPath from Registry
# -----------------------------
If ($GetSMSLogs) {
	$SMSInstallDir = (Get-RegValue ($Reg_SMS + "\Identification") "Installation Directory")

	If ($null -ne $SMSInstallDir) {
		$SMSLogPath = $SMSInstallDir + "\Logs"
		TraceOut "Global Variable - SMSInstallDir: $SMSInstallDir"
		TraceOut "Global Variable - SMSLogPath: $SMSLogPath"
	}
	Else {
		$SMSLogPath = $null
		TraceOut "ERROR: SMS Logs need to be collected but SMS Install Directory not Found"
	}
}

# -------------------------------
# Get Site Server Info From Registry
# -------------------------------
If ($Is_SiteServer) {
	# Database Server and name
	$ConfigMgrDBServer = Get-RegValue ($Reg_SMS + "\SQL Server\Site System SQL Account") "Server"			# Stored as FQDN
	$ConfigMgrDBName = Get-RegValue ($Reg_SMS + "\SQL Server\Site System SQL Account") "Database Name"		# Stored as INSTANCE\DBNAME or just DBNAME if on Default instance

	# Get the database name without the Instance Name
	If ($ConfigMgrDBName.Contains("\")) {
		$ConfigMgrDBNameNoInstance = $ConfigMgrDBName.Substring($ConfigMgrDBName.IndexOf("\")+1)
	}
	Else {
		$ConfigMgrDBNameNoInstance = $ConfigMgrDBName
	}

	# Get Database connection.
	# If connection fails, DatabaseConnectionError will have the error. If connection is successful, DatabaseConnectionError will be $null.
	# Connection is closed in FinishExecution
	$global:DatabaseConnection = Get-DBConnection -DatabaseServer $ConfigMgrDBServer -DatabaseName $ConfigMgrDBName

	# Site Type
	$global:SiteType = Get-RegValue ($Reg_SMS + "\Setup") "Type"
	$global:SiteBuildNumber = Get-RegValue ($Reg_SMS + "\Setup") "Version"

	# Site Code and Provider Namespace
	$global:SMSProviderServer = Get-RegValue ($Reg_SMS + "\Setup") "Provider Location"
	$global:SMSSiteCode = Get-RegValue ($Reg_SMS + "\Identification") "Site Code"
	If (($null -ne $global:SMSSiteCode) -and ($null -ne $global:SMSProviderServer)) {
		$global:SMSProviderNamespace = "root\sms\site_$SMSSiteCode"
	}

	# Site Server FQDN
	$SiteServerFQDN = [System.Net.Dns]::GetHostByName(($ComputerName)).HostName

	# SQLBackup Log Location (SqlBkup.log)
	$RegKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $ConfigMgrDBServer)
	$Key = $RegKey.OpenSubKey("SOFTWARE\Microsoft\SMS\Tracing\SMS_SITE_SQL_BACKUP_$SiteServerFQDN")
	if ($Key -ne $null) {
		$SQLBackupLogPath = $Key.GetValue("TraceFileName")
		$SQLBackupLogPathUNC = $SQLBackupLogPath -replace ":","$"
		$SQLBackupLogPathUNC = "\\$ConfigMgrDBServer\$SQLBackupLogPathUNC"
		$SQLBackupLogPathUNC = Split-Path $SQLBackupLogPathUNC
	}

	TraceOut "Global Variable - SiteType: $SiteType"
	TraceOut "Global Variable - SQLBackupLogPathUNC: $SQLBackupLogPathUNC"
	TraceOut "Global Variable - ConfigMgrDBServer: $ConfigMgrDBServer"
	TraceOut "Global Variable - ConfigMgrDBName: $ConfigMgrDBName"
}

# --------------------------------------------------------------------------------------------------------------------------
# Set WSUS Install Directory, if WSUS is installed.
# Execute WSUSutil checkhealth. Running it now would ensure that it's finished by the time we collect Event Logs
# Fails to run remotely, because it runs under Anonymous. Using psexec to execute, to ensure that it runs remotely as well.
# --------------------------------------------------------------------------------------------------------------------------
If ($Is_WSUS) {
	$WSUSInstallDir = Get-RegValue ($Reg_WSUS + "\Server\Setup") "TargetDir"

	If ($null -ne $WSUSInstallDir) {
		TraceOut "Global Variable - WSUSInstallDir: $WSUSInstallDir"
		TraceOut "Running WSUSutil.exe checkhealth..."
		$CmdToRun = "psexec.exe /accepteula -s `"" + $WSUSInstallDir + "Tools\WSUSutil.exe`" checkhealth"
		RunCmd -commandToRun $CmdToRun -collectFiles $false
	}
	Else {
		TraceOut "ERROR: WSUS Role detected but WSUS Install Directory not found"
	}
}

# -----------------------------------------------------------------------
# Get DP Logs Directory, if DP is installed and remote from Site Server.
# -----------------------------------------------------------------------
If ($Is_DP) {
	If ($Is_SiteServer -eq $false) {
		$DPLogPath = (Get-CimInstance Win32_Share -filter "Name LIKE 'SMS_DP$'").path + "\sms\Logs"
		TraceOut "Global Variable - DPLogPath = $DPLogPath"
	}
}

# ----------------------
# Remove Temp Variables
# ----------------------
Remove-Variable -Name Role
Remove-Variable -Name Installed

TraceOut "Completed"


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB1MkzSXK4bnyOn
# VTGgWQ8DeDRnqPDVRHuoh3B1qeMFgKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEICyLz3c/YBvgXSl7TCd8i4F7
# JJcT7PhBr7vEEnhA41zgMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQA4KoRmN2UKdr1iBKt+Jnm6NLQg7t29QdZU9BdrMO/+z1tqyD3VBzIP
# gY9WZQlnJMh3HO50k3Dhj1VmbA63SEJZJn9bBiPrOyWBj7Ae8wRAcPWVEwGvIS9/
# /cD93X9+2JgsCRoibYv46FofdyX35kcXPIVDuSWUuTZ6ka6JHZIhATxdxwcI/Y1+
# RQ+lXoE7Eqbynje5g/UQb8rh8KkYozakGzBAQ0+j1StUI6mn4MUFuyoigVC38W3f
# SLHeZlfVZDtET9zXw1I/nrlJLTbNebp5v+sbziBaQJ+n69Pq7iiP8hD28DWa64wn
# hE8wQiPVIZwqPG0vLNq1sO2n/say3OE2oYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIObZPJtpqeDydpQB1uyQe59NoGOFoLqYbmBTD+c34sA4AgZi1XtC
# b4kYEzIwMjIwODAxMDgxMDU5Ljg4MVowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjEyQkMt
# RTNBRS03NEVCMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGhAYVVmblUXYoAAQAAAaEwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTI0WhcNMjMwMjI4MTkwNTI0WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MTJCQy1FM0FFLTc0RUIxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDayTxe5WukkrYxxVuHLYW9BEWCD9kkjnnHsOKwGddI
# PbZlLY+l5ovLDNf+BEMQKAZQI3DX91l1yCDuP9X7tOPC48ZRGXA/bf9ql0FK5438
# gIl7cV528XeEOFwc/A+UbIUfW296Omg8Z62xaQv3jrG4U/priArF/er1UA1HNuIG
# UyqjlygiSPwK2NnFApi1JD+Uef5c47kh7pW1Kj7RnchpFeY9MekPQRia7cEaUYU4
# sqCiJVdDJpefLvPT9EdthlQx75ldx+AwZf2a9T7uQRSBh8tpxPdIDDkKiWMwjKTr
# AY09A3I/jidqPuc8PvX+sqxqyZEN2h4GA0Edjmk64nkIukAK18K5nALDLO9SMTxp
# AwQIHRDtZeTClvAPCEoy1vtPD7f+eqHqStuu+XCkfRjXEpX9+h9frsB0/BgD5CBf
# 3ELLAa8TefMfHZWEJRTPNrbXMKizSrUSkVv/3HP/ZsJpwaz5My2Rbyc3Ah9bT76e
# BJkyfT5FN9v/KQ0HnxhRMs6HHhTmNx+LztYci+vHf0D3QH1eCjZWZRjp1mOyxpPU
# 2mDMG6gelvJse1JzRADo7YIok/J3Ccbm8MbBbm85iogFltFHecHFEFwrsDGBFnNY
# HMhcbarQNA+gY2e2l9fAkX3MjI7Uklkoz74/P6KIqe5jcd9FPCbbSbYH9OLsteeY
# OQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFBa/IDLbY475VQyKiZSw47l0/cypMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBACDDIxElfXlG5YKcKrLPSS+f3JWZprwKEiASvivaHTBRlXtAs+TkadcsEei+
# 9w5vmF5tCUzTH4c0nCI7bZxnsL+S6XsiOs3Z1V4WX+IwoXUJ4zLvs0+mT4vjGDtY
# fKQ/bsmJKar2c99m/fHv1Wm2CTcyaePvi86Jh3UyLjdRILWbtzs4oImFMwwKbzHd
# PopxrBhgi+C1YZshosWLlgzyuxjUl+qNg1m52MJmf11loI7D9HJoaQzd+rf928Y8
# rvULmg2h/G50o+D0UJ1Fa/cJJaHfB3sfKw9X6GrtXYGjmM3+g+AhaVsfupKXNtOF
# u5tnLKvAH5OIjEDYV1YKmlXuBuhbYassygPFMmNgG2Ank3drEcDcZhCXXqpRszNo
# 1F6Gu5JCpQZXbOJM9Ue5PlJKtmImAYIGsw+pnHy/r5ggSYOp4g5Z1oU9GhVCM3V0
# T9adee6OUXBk1rE4dZc/UsPlj0qoiljL+lN1A5gkmmz7k5tIObVGB7dJdz8J0FwX
# RE5qYu1AdvauVbZwGQkL1x8aK/svjEQW0NUyJ29znDHiXl5vLoRTjjFpshUBi2+I
# Y+mNqbLmj24j5eT+bjDlE3HmNtLPpLcMDYqZ1H+6U6YmaiNmac2jRXDAaeEE/uoD
# Mt2dArfJP7M+MDv3zzNNTINeuNEtDVgm9zwfgIUCXnDZuVtiMIIHcTCCBVmgAwIB
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
# IEVTTjoxMkJDLUUzQUUtNzRFQjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAG3F2jO4LEMVLwgKGXdYMN4FBgOCg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRxQEwIhgPMjAyMjA4MDExMTIwMzNaGA8yMDIyMDgwMjExMjAzM1ow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pHFAQIBADAKAgEAAgIe+QIB/zAHAgEA
# AgIRzDAKAgUA5pMWgQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAMdg/2Ic
# 2gdRxdHFUFdJMeqK2GQ4eeJe4KU3uJFZSWtDNMsYdgfRBioQewI0jA36Q7n93U2H
# 2EUIMKie+yy3JZGEC3R7RNFvadse/lYTH9idktnd6B/nLTFPzKKzNxNL/s0kYKbs
# IFS75Zhce8rvKa256KzxAwgDOFvKbA/CLFftMYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGhAYVVmblUXYoAAQAAAaEwDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQg3yL0DmnGv/P5ULfOdDE8YBfjoWxvT3M8nKocRKyWxTwwgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCDrCFTxOoGCaCCCjoRyBe1JSQrMJeCC
# TyErziiJ347QhDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABoQGFVZm5VF2KAAEAAAGhMCIEIKLR1CM5CE/xpideFbkazxTnyCfhdw/B
# krS8J+WcwTuEMA0GCSqGSIb3DQEBCwUABIICANg0kdS8/PNIt6bfMVy+sfSBvBEX
# UtDDdI5R41oD5pyWh+q218drGgyD+UGMEY3YMyMmYlrvxogJkI6Svu/QF2sH/VY3
# K7HA/kWcmrb/BfAs1QNzrxVKEt7q1aSBoAGjGD//OOSbMQ2PVwB3oqyfYMEaLXku
# hdIiWa9MSAEPU1aOL9b5B1W4Gno9bXpMQx1BvgHATvS/gnk+80ANhJoxznXb5gLk
# TMH/bvvC3pMFMWQ02zELEWQzhP6ddxsKqZYAyk5LAimYeQt+FRL2TkbvUDQRl1sq
# 4JRq+b/nlRCjPLPaFSyLq6untxD9PW/omPSrGayW5JIfkb3nGmeGMocC1SiXKRjq
# i+xxhFC6xgSq16ET8SuMYEfvRPcxVzkck+iM47E21ge7nMFXU8ntengjKU6J1oVj
# zjRpG1t1acPHrF+zjs3MmKzC5tVuc46jILQcUPH/+jtYYwLNpgEfiiQmSEweHTO9
# UlY32kRjXMl64xVtNlexZz6Scf2rTA+0vREnnzwLcPUOXUxezMA3llcyxBqZT/8k
# WwqsED71WNVCM6PEjP+c++j8ZKh+TUu+eOuBo4/iBP8nbUuROcvQOKMXvsgPwRC+
# exJi3B9bukzqPu2Zr7xz8xx2wGBmnIQRe2tRuu4teBLozuQJ8os9hZXTG+UNG16C
# zPGw1xG+uxEfXhbp
# SIG # End signature block
