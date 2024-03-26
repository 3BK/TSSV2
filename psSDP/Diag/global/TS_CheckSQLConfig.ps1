#************************************************
# Version 1.0
# Date: 12-12-2012
# Author: Vinay Pamnani - vinpa@microsoft.com
# Description:
#************************************************

trap [Exception]
{
	WriteTo-ErrorDebugReport -ErrorRecord $_
	continue
}

Function Check-SQLValue
{
	Param(
		[string]$Query,
	    [string]$ColumnName,
		[string]$CompareOperator="eq",
		$DesiredValue,
		[string]$RootCauseName,
		[string]$ColumnDisplayName=$ColumnName
	)

	# InformationCollected for Update-DiagRootcause
	Set-Variable -Name InformationCollected -Scope Local
	$InformationCollected = New-Object PSObject

	# InfoSummary for $ComplianceSummary
	Set-Variable -Name InfoSummary -Scope Script
	$InfoSummary = New-Object PSObject
	Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Name" -Value $ColumnDisplayName

	$Result = Get-SQLValue -SqlQuery $Query -ColumnName $ColumnName -ColumnDisplayName $ColumnDisplayName
	If ($null -ne $Result.Error) {
		TraceOut "    Value of $ColumnName is Unknown. SQL Query Failed with ERROR: $($Result.Error)"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Actual Value" -Value "Unknown"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Desired Value" -Value $DesiredValue
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "N/A"
		$script:ComplianceSummary += $InfoSummary
		return
	}

	$ActualValue = $Result.Value

	If ($null -ne $ActualValue) { # TODO: Replace this with [string]::IsNullOrEmpty() ???

		Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name $ColumnDisplayName -Value "$ActualValue. Desired Value: $DesiredValue"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Actual Value" -Value $ActualValue
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Desired Value" -Value $DesiredValue

		# Check whether Actual Value of specified column is equal to the Desired Value
		If ($CompareOperator -eq "eq") {
		    If ($ActualValue -eq $DesiredValue) {
				TraceOut "    $ColumnName = $ActualValue. Compliant."
				Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "Compliant"
		    }
		    Else {
				TraceOut "    $ColumnName = $ActualValue. Desired Value = $DesiredValue. Not Compliant!"
				Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "Not-Compliant"
		        Update-DiagRootCause -id $RootCauseName -Detected $true
				Add-GenericMessage -Id $RootCauseName -InformationCollected $InformationCollected
		    }
		}

		# Check whether Actual Value of specified column is greater than the Desired Value. Used to check counts of rows in specific tables.
		If ($CompareOperator -eq "gt") {
			If ($ActualValue -gt $DesiredValue) {
				TraceOut "    $ColumnName is $ActualValue which is greater than the Desired Value $DesiredValue. Not Compliant!"
				Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "Not-Compliant"
				Update-DiagRootCause -id $RootCauseName -Detected $true
				Add-GenericMessage -Id $RootCauseName -InformationCollected $InformationCollected
		    }
		    Else {
				TraceOut "    $ColumnName is $ActualValue which is less than the Desired Value $DesiredValue. Compliant."
				Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "Compliant"
		    }
		}
	}
	Else {
		# Actual Value was null
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Actual Value" -Value $null
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Desired Value" -Value $DesiredValue
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "N/A"
		TraceOut "    SQL Query succeeded but the value of $ColumnName is Null."
	}

	# Add InfoSummary to ComplianceSummary array
	$script:ComplianceSummary += $InfoSummary
}

Function Get-SQLValue
{
	Param(
		[string]$SqlQuery,
	    [string]$ColumnName,
		[string]$ColumnDisplayName
	)

	Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_CheckSQLConfig -Status ($ScriptStrings.ID_SCCM_CheckSQLValue + ": " + $ColumnDisplayName)

	$Result = New-Object -TypeName PSObject

	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlCmd.CommandText = $SqlQuery
	$SqlCmd.Connection = $global:DatabaseConnection

	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$SqlAdapter.SelectCommand = $SqlCmd

	TraceOut "Getting the value of $ColumnDisplayName"
	$SqlTable = New-Object System.Data.DataTable
	try {
		$SqlAdapter.Fill($SqlTable) | out-null
		$ActualValue = $SqlTable | Select-Object -ExpandProperty $ColumnName -ErrorAction SilentlyContinue
		$Result | Add-Member -MemberType NoteProperty -Name "Value" -Value $ActualValue
		$Result | Add-Member -MemberType NoteProperty -Name "Error" -Value $null
	}
	catch [Exception] {
		$Result | Add-Member -MemberType NoteProperty -Name "Value" -Value $null
		$Result | Add-Member -MemberType NoteProperty -Name "Error" -Value $_
	}

	# Return column value
	return $Result
}

function Parse-DRSBacklogResult
{
	Param ($DRSBacklogResult)

	$RootCauseName = "RC_DRSBacklog"

	# InformationCollected for Update-DiagRootcause
	Set-Variable -Name InformationCollected -Scope Local
	$InformationCollected = New-Object PSObject

	# InfoSummary for $ComplianceSummary
	Set-Variable -Name InfoSummary -Scope Script
	$InfoSummary = New-Object PSObject
	Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Name" -Value "Change Tracking Backlog"

	if ($null -ne $DRSBacklogResult.Error) {
		TraceOut "    ChangeTrackingBacklog Result is Unknown. SQL Query Failed with ERROR: $($DRSBacklogResult.Error)"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Actual Value" -Value "Unknown"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Desired Value" -Value "Less Than RetentionPeriod + 5 days"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "Unknown"
		$script:ComplianceSummary += $InfoSummary
		return
	}

	if ($null -eq $DRSBacklogResult.Value) {
		TraceOut "    ChangeTrackingBacklog Result is Unknown. Value returns was null!"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Actual Value" -Value "Unknown"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Desired Value" -Value "Less Than RetentionPeriod + 5 days"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "Unknown"
		$script:ComplianceSummary += $InfoSummary
		return
	}

	$ActualValue = $DRSBacklogResult.Value

	if ($ActualValue -eq 0) {
		TraceOut "    ChangeTrackingBacklog Result value is 0. Not Applicable!"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "Not Applicable"
		$script:ComplianceSummary += $InfoSummary
		return
	}

	if ($ActualValue -eq -1) {
		TraceOut "    ChangeTrackingBacklog result = -1. This means we did not find the row for ConfigMgr database in sys.change_tracking_databases"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "N/A. Did not find the row for ConfigMgr database in sys.change_tracking_databases"
		$DRSBacklogDescription = "Change Tracking Backlog detection was aborted, because there was no row found for the ConfigMgr database in the sys.change_tracking_databases table, and this should be investigated."
		Update-DiagRootCause -id $RootCauseName -Detected $true	-Parameter @{"DRSBacklogDescription" = $DRSBacklogDescription}
		Add-GenericMessage -Id $RootCauseName -InformationCollected $InformationCollected
		$script:ComplianceSummary += $InfoSummary
		return
	}

	if ($ActualValue -eq -2) {
		TraceOut "    ChangeTrackingBacklog result = -2. This means retention unit is not set to DAYS. ConfigMgr UI does not allow changing the retention unit."
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "N/A. Retention Unit in sys.change_tracking_databases is not set to DAYS. ConfigMgr UI does not allow changing the retention unit."
		$DRSBacklogDescription = "Change Tracking Backlog detection was aborted, because retention unit in sys.change_tracking_databases table is not set to DAYS. ConfigMgr console does not allow changing the retention unit. Please ensure that retention unit is set to DAYS in SQL."
		Update-DiagRootCause -id $RootCauseName -Detected $true	-Parameter @{"DRSBacklogDescription" = $DRSBacklogDescription}
		Add-GenericMessage -Id $RootCauseName -InformationCollected $InformationCollected
		$script:ComplianceSummary += $InfoSummary
		return
	}

	if ($ActualValue -eq -3) {
		TraceOut "    ChangeTrackingBacklog result = -3. This means period is greater than 14 days. ConfigMgr UI only allows setting retention period between 1 and 14."
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "N/A. Retention Period in sys.change_tracking_databases is greater than 14 days. ConfigMgr UI only allows setting retention period between 1 and 14."
		$DRSBacklogDescription = "Change Tracking Backlog detection was aborted, because Retention Period in sys.change_tracking_databases is greater than 14 days. ConfigMgr console only allows setting retention period between 1 and 14. Please set the retention period to a supported value from the ConfigMgr console."
		Update-DiagRootCause -id $RootCauseName -Detected $true	-Parameter @{"DRSBacklogDescription" = $DRSBacklogDescription}
		Add-GenericMessage -Id $RootCauseName -InformationCollected $InformationCollected
		$script:ComplianceSummary += $InfoSummary
		return
	}

	if (-not $ActualValue.Contains(".")) {
		TraceOut "    ChangeTrackingBacklog result = $ActualValue. This value is unexpected."
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "Unknown!"
		$script:ComplianceSummary += $InfoSummary
	}

	$BacklogDays = $ActualValue.Substring(0, $ActualValue.IndexOf("."))
	$RetentionPeriod = $ActualValue.Substring($ActualValue.IndexOf(".") + 1)

	Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Change Tracking Backlog Result" -Value "Backlog Days = $BacklogDays, Retention Period = $RetentionPeriod. Desired Value: Less than Retention Period + 5 days"
	Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Actual Value" -Value "Backlog Days = $BacklogDays, Retention Period = $RetentionPeriod"
	Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Desired Value" -Value "Less Than RetentionPeriod + 5 days"

	# We are here, which means result value is in format x.x and issue was detected - Major means Backlog Days, Minor means Retention Period
	if ([int]$BacklogDays -gt [int]$RetentionPeriod + 5) {
		TraceOut "    ChangeTrackingBacklog result = $ActualValue. This means we detected a backlog of $BacklogDays days with current retention period of $RetentionPeriod days. Not Compliant!"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "Not-Compliant!"
		$DRSBacklogDescription = "Change Tracking Backlog of $BacklogDays days was detected, which is greater than $([int]$RetentionPeriod + 5) days (Current Retention Period ($RetentionPeriod) + 5 days)."
		Update-DiagRootCause -id $RootCauseName -Detected $true	-Parameter @{"DRSBacklogDescription" = $DRSBacklogDescription}
		Add-GenericMessage -Id $RootCauseName -InformationCollected $InformationCollected
		$script:ComplianceSummary += $InfoSummary
	}
	else {
		TraceOut "    ChangeTrackingBacklog result = $ActualValue. This means we detected a backlog of $BacklogDays days with current retention period of $RetentionPeriod days. Compliant!"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "Compliant"
		$script:ComplianceSummary += $InfoSummary
	}
}

function Parse-DBSchemaChangeHistoryResult
{
	Param ($DBSchemaChangeHistoryResult)

	$RootCauseName = "RC_DBSchemaChangeHistory"

	# InformationCollected for Update-DiagRootcause
	Set-Variable -Name InformationCollected -Scope Local
	$InformationCollected = New-Object PSObject

	# InfoSummary for $ComplianceSummary
	Set-Variable -Name InfoSummary -Scope Script
	$InfoSummary = New-Object PSObject
	Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Name" -Value "DBSchemaChangeHistory Size"

	if ($null -ne $DBSchemaChangeHistoryResult.Error) {
		TraceOut "    DBSchemaChangeHistorySize Result is Unknown. SQL Query Failed with ERROR: $($DRSBacklogResult.Error)"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Actual Value" -Value "Unknown"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Desired Value" -Value "Less Than 5% of DB Size OR Less Than 10GB"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "N/A"
		$script:ComplianceSummary += $InfoSummary
		return
	}

	if ($null -eq $DBSchemaChangeHistoryResult.Value) {
		TraceOut "    DBSchemaChangeHistorySize Result is Unknown. Value returned was null!"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Actual Value" -Value "Unknown"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Desired Value" -Value "Less Than 5% of DB Size OR Less Than 10GB"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "Unknown"
		$script:ComplianceSummary += $InfoSummary
		return
	}

	$ActualValue = $DBSchemaChangeHistoryResult.Value

	if ($ActualValue -eq 0) {
		TraceOut "    DBSchemaChangeHistorySize result = $ActualValue. Not Applicable!"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "Not Applicable."
		$script:ComplianceSummary += $InfoSummary
		return
	}

	if (-not $ActualValue.Contains(".")) {
		TraceOut "    DBSchemaChangeHistory result = $ActualValue. This value is unexpected."
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "Unknown."
		$script:ComplianceSummary += $InfoSummary
		return
	}

	$DBSize = $ActualValue.Substring(0, $ActualValue.IndexOf(".")) -as [int]
	$TableSize = $ActualValue.Substring($ActualValue.IndexOf(".") + 1) -as [int]

	Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "DBSchemaChangeHistorySize Result" -Value "Table Size = $($TableSize)MB, Database Size = $($DBSize)MB. Desired Value: Less Than 5% of DB Size OR Less Than 10GB"
	Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Actual Value" -Value "Table Size = $($TableSize)MB, Database Size = $($DBSize)MB"
	Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Desired Value" -Value "Less Than 5% of DB Size OR Less Than 10GB"

	$percentage = ($TableSize/$DBSize) * 100

	if (($percentage -gt 5) -or ($TableSize -gt 10240)) {
		TraceOut "    DBSchemaChangeHistorySize Result: Table Size = $($TableSize)MB, Database Size = $($DBSize)MB. Table size exceeds threshold. Not Compliant!"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "Not-Compliant!"
		$DBSchemaChangeHistoryDescription = "DBSChemaChangeHistory table size is greater than 5% of Database Size or 10GB. Table Size = $($TableSize)MB, Database Size = $($DBSize)MB"
		Update-DiagRootCause -id $RootCauseName -Detected $true	-Parameter @{"DBSchemaChangeHistoryDescription" = $DBSchemaChangeHistoryDescription}
		Add-GenericMessage -Id $RootCauseName -InformationCollected $InformationCollected
		$script:ComplianceSummary += $InfoSummary
	}
	else {
		TraceOut "    DBSchemaChangeHistorySize result = $ActualValue. Compliant!"
		Add-Member -InputObject $InfoSummary -MemberType NoteProperty -Name "Result State" -Value "Compliant"
		$script:ComplianceSummary += $InfoSummary
	}
}

# ------------------------------
# Script Execution Starts Here
# ------------------------------

If (!$Is_SiteServer) {
	TraceOut "ConfigMgr Site Server not detected. This script gathers data only from a Site Server. Exiting."
	exit 0
}

TraceOut "Started"

Import-LocalizedData -BindingVariable ScriptStrings
$sectiondescription = "Configuration Manager SQL Data"
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_CheckSQLConfig -Status $ScriptStrings.ID_SCCM_CheckSQLConfigDesc

Set-Variable -Name ComplianceSummary -Scope Script
$ComplianceSummary = @()

$SQLTestStatus = Join-Path $Pwd.Path ($ComputerName + "_SQL_ConfigCompliance.txt")
"===========================================================================================================" | Out-File $SQLTestStatus
"SQL Configuration Checks Performed (Check UDE Messages for More Information if a Property is Not Compliant)" | Out-File $SQLTestStatus -Append
"===========================================================================================================" | Out-File $SQLTestStatus -Append

# Falling back to MASTER in case database is offline.
if ($null -eq $global:DatabaseConnection) {
	TraceOut "DatabaseConnection is null. Trying to connect to MASTER database."
	$global:DatabaseConnection = Get-DBConnection -DatabaseServer $ConfigMgrDBServer -DatabaseName "MASTER"
}

if ($null -eq $global:DatabaseConnection) {
	TraceOut "SQL Connection to ConfigMgr and MASTER databases on $ConfigMgrDBServer failed with ERROR: $DatabaseConnectionError"
	"SQL Connection to ConfigMgr and MASTER databases on $ConfigMgrDBServer failed with ERROR: $DatabaseConnectionError" | Out-File $SQLTestStatus -Append
	"All tests were skipped!" | Out-File $SQLTestStatus -Append
	CollectFiles -filesToCollect $SQLTestStatus -fileDescription "SQL Tests Performed"  -sectionDescription $sectiondescription -noFileExtensionsOnDescription
	return
}

# ------------------
# Tests start here
# ------------------
$dbname = $ConfigMgrDBNameNoInstance

$RootCauseName = "RC_DbOnline"
$sQuery = "SELECT name, state_desc FROM sys.databases WHERE name = '$dbname'"
# Check-SQLValue $sQuery "state_desc" "eq" "ONLINE" $RootCauseName
Check-SQLValue -Query $sQuery -ColumnName "state_desc" -CompareOperator "eq" -DesiredValue "ONLINE" -RootCauseName $RootCauseName -ColumnDisplayName "Database Online"

$RootCauseName = "RC_DbOwner"
$sQuery = "SELECT name, SUSER_NAME(owner_sid) AS DbOwner FROM sys.databases WHERE name = '$dbname'"
Check-SQLValue -Query $sQuery -ColumnName "DbOwner" -CompareOperator "eq" -DesiredValue "sa" -RootCauseName $RootCauseName -ColumnDisplayName "Database Owner"

$RootCauseName = "RC_UserAccess"
$sQuery = "SELECT name, user_access_desc FROM sys.databases WHERE name = '$dbname'"
Check-SQLValue -Query $sQuery -ColumnName "user_access_desc" -CompareOperator "eq" -DesiredValue "MULTI_USER" -RootCauseName $RootCauseName -ColumnDisplayName "User Access"

$RootCauseName = "RC_ReadOnly"
$sQuery = "SELECT name, is_read_only FROM sys.databases WHERE name = '$dbname'"
Check-SQLValue -Query $sQuery -ColumnName "is_read_only" -CompareOperator "eq" -DesiredValue $false -RootCauseName $RootCauseName -ColumnDisplayName "Database Read Only"

$RootCauseName = "RC_RecoveryModel"
$sQuery = "SELECT name, recovery_model_desc FROM sys.databases WHERE name = '$dbname'"
Check-SQLValue -Query $sQuery -ColumnName "recovery_model_desc" -CompareOperator "eq" -DesiredValue "SIMPLE" -RootCauseName $RootCauseName -ColumnDisplayName "Recovery Model"

$RootCauseName = "RC_RecursiveTriggers"
$sQuery = "SELECT name, is_recursive_triggers_on FROM sys.databases WHERE name = '$dbname'"
Check-SQLValue -Query $sQuery -ColumnName "is_recursive_triggers_on" -CompareOperator "eq" -DesiredValue $true -RootCauseName $RootCauseName -ColumnDisplayName "Recursive Triggers"

$RootCauseName = "RC_BrokerEnabled"
$sQuery = "SELECT name, is_broker_enabled FROM sys.databases WHERE name = '$dbname'"
Check-SQLValue -Query $sQuery -ColumnName "is_broker_enabled" -CompareOperator "eq" -DesiredValue $true -RootCauseName $RootCauseName -ColumnDisplayName "Broker Enabled"

$RootCauseName = "RC_Trustworthy"
$sQuery = "SELECT name, is_trustworthy_on FROM sys.databases WHERE name = '$dbname'"
Check-SQLValue -Query $sQuery -ColumnName "is_trustworthy_on" -CompareOperator "eq" -DesiredValue $true -RootCauseName $RootCauseName -ColumnDisplayName "Trustworthy"

$RootCauseName = "RC_HonorBrokerPriority"
$sQuery = "SELECT name, is_honor_broker_priority_on FROM sys.databases WHERE name = '$dbname'"
Check-SQLValue -Query $sQuery -ColumnName "is_honor_broker_priority_on" -CompareOperator "eq" -DesiredValue $true -RootCauseName $RootCauseName -ColumnDisplayName "Honor Broker Priority"

$RootCauseName = "RC_SnapshotIsolation"
$sQuery = "SELECT name, snapshot_isolation_state_desc FROM sys.databases WHERE name = '$dbname'"
Check-SQLValue -Query $sQuery -ColumnName "snapshot_isolation_state_desc" -CompareOperator "eq" -DesiredValue "ON" -RootCauseName $RootCauseName -ColumnDisplayName "Snapshot Isolation"

$RootCauseName = "RC_ReadCommittedSnapshot"
$sQuery = "SELECT name, is_read_committed_snapshot_on FROM sys.databases WHERE name = '$dbname'"
Check-SQLValue -Query $sQuery -ColumnName "is_read_committed_snapshot_on" -CompareOperator "eq" -DesiredValue $true -RootCauseName $RootCauseName -ColumnDisplayName "Read Committed Snapshot"

$RootCauseName = "RC_NestedTriggers"
$sQuery = "EXEC sp_configure 'nested triggers'"
Check-SQLValue -Query $sQuery -ColumnName "run_value" -CompareOperator "eq" -DesiredValue 1 -RootCauseName $RootCauseName -ColumnDisplayName "Nested Triggers"

$sQuery = "
DECLARE @RetentionPeriod INT
DECLARE @RetentionUnit VARCHAR(10)
DECLARE @OldestSCTRowDate DATETIME
DECLARE @OldestSCTRowDelta INT

DECLARE @CountOfSites INT
SELECT @CountOfSites = COUNT(1) FROM sites

IF (@CountOfSites <= 1) BEGIN SELECT 0 AS ChangeTrackingBacklogResult; RETURN; END

SELECT @RetentionPeriod = CTD.retention_period ,@RetentionUnit = CTD.retention_period_units_desc
FROM sys.change_tracking_databases AS CTD
JOIN sys.databases AS D ON D.database_id = CTD.database_id
WHERE D.NAME = '$dbname'

IF @@rowcount < 1 BEGIN SELECT -1 AS ChangeTrackingBacklogResult; RETURN; END -- This means we did not find the CM DB
IF @RetentionUnit <> N'DAYS' BEGIN SELECT -2 AS ChangeTrackingBacklogResult; RETURN; END -- UI does not allow for configuring the unit
IF @RetentionPeriod > 14 BEGIN SELECT -3 AS ChangeTrackingBacklogResult; RETURN; END -- UI allows for values between 1 and 14 days

SELECT @OldestSCTRowDate = MIN(commit_time) FROM sys.dm_tran_commit_table
SELECT @OldestSCTRowDelta = DATEDIFF(DAY, @OldestSCTRowDate, GetDate())

SELECT CAST(@OldestSCTRowDelta AS VARCHAR(10)) + '.' + CAST(@RetentionPeriod AS VARCHAR(2)) AS ChangeTrackingBacklogResult; RETURN; -- Major = Backlog, Minor = Retention Days
"

$DRSBacklogResult = Get-SQLValue -SqlQuery $sQuery -ColumnName "ChangeTrackingBacklogResult" -ColumnDisplayName "Change Tracking Backlog"
Parse-DRSBacklogResult $DRSBacklogResult

$sQuery = "
DECLARE @tablesizeMB float
DECLARE @dbsizeMB float

IF NOT EXISTS(SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'DBSchemaChangeHistory')
BEGIN
	SELECT '0'
	RETURN
END

SELECT @dbsizeMB = CAST(SUM(size) * 8. / 1024 AS DECIMAL(8,0))
FROM sys.master_files SMF WITH(NOWAIT)
JOIN sys.databases SD on SD.database_id = SMF.database_id
WHERE SD.name = '$dbname'

DECLARE @InputBuffer TABLE ([name] NVARCHAR(100), [rows] INT, [reserved] NVARCHAR(100), [data] NVARCHAR(100), [index_size] NVARCHAR(100), [unused] NVARCHAR(100))
  INSERT INTO @InputBuffer EXEC sp_spaceused 'DBSchemaChangeHistory'

SELECT @tablesizeMB = CONVERT(bigint,left(reserved,len(reserved)-3))/1024 FROM @InputBuffer

SELECT CAST(@dbsizeMB AS VARCHAR(100)) + '.' + CAST(@tablesizeMB AS VARCHAR(100)) AS Result
"

$DBSchemaChangeHistoryResult = Get-SQLValue -SqlQuery $sQuery -ColumnName "Result" -ColumnDisplayName "DBSchemaChangeHistory Size"
Parse-DBSchemaChangeHistoryResult $DBSchemaChangeHistoryResult

$ComplianceSummary | Format-Table -Auto | Out-File $SQLTestStatus -Append -Width 200
CollectFiles -filesToCollect $SQLTestStatus -fileDescription "SQL Configuration"  -sectionDescription $sectiondescription -noFileExtensionsOnDescription

TraceOut "Completed"


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBAgKQomv+UXiL/
# XB0SRBO3rWL7lmmO8DiKk9paNSuIl6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEICi6t3Wy2vh8f6SZAxEaDUun
# vrUROnUw2hrZRopNuOc6MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCGEZNNprOoZswTEDM2AzsWyvXqFPAbCXZ8Sh9oESN4vuFkkfmfVLz4
# CXmHpcCmGOgEfw0xoFIPKxIoRit34i+CsTmT3z2QDS6kgYrZDuXaUEM1cGH7jp3W
# udW8FWcRLLc8lk1BDkzbzx41RReRJLW/sZIUOcFX+QNAZeSXO4wJ0fkh4qr5Zc8u
# ERqkaREigUuLsY5b9/FUCe2OnMJE9H8er7Y7bjuD8aCmA0DzE+XWvqshrubSV0Ex
# oWLuQxtopNXutFU2cCo8jfVqcKCAfCQfdZ58VEE0KF7X1bQclSyv2bH7ECbpeTzQ
# moc9AFn3KkZNUgcTi0JnmQn91XFkphWEoYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIIB8hEO2sy1riicmrvw28HDoEHmsQzs+XIf3YaGUb3KPAgZi1XtC
# ZVQYEzIwMjIwODAxMDgwMDE4LjQ0OVowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
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
# hkiG9w0BCQQxIgQgCjJxSx0zdXXMCIziF9NGyVcJunDFW5/QI9aoGBmhEPMwgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCDrCFTxOoGCaCCCjoRyBe1JSQrMJeCC
# TyErziiJ347QhDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABoQGFVZm5VF2KAAEAAAGhMCIEIKLR1CM5CE/xpideFbkazxTnyCfhdw/B
# krS8J+WcwTuEMA0GCSqGSIb3DQEBCwUABIICABpod1khmXOnRWI3SvEb56kXj7PL
# SCdaRli1ugJIwJ2B5UpHRIe1Q0OyyxI8k6/Zdz3rzrk1kMaGk+I7lmCEEJ1i3Rwy
# Sw3wXgN6W/PG1CCt3a8JiV7I1wt67OBnvaHnsgyx2TbXWtZ2QaCxFWYplylMObNW
# iG+UBmIqe514KNLZ8wwYRTn1svHpJKV61e06AulrYs/oI9TiqcNldmmOFqxL7gxp
# yR+jhtNuSYJupKGjdyQ4Qy/TsfZNgldFb5EHXHfChfT3o+CZ6aqKMY8Nu7YcqBSt
# iqDP2yg7JyzZU6gnEJ6SZ6rJj6p6or6EpaC4tA1Q3j3u0CT2TaVEIA9tXsbIAfQF
# +gYSBegCtC64QK7WJkedCj36yK0Zsp8AgbmvVHHdqgdxkIWdkMy51oaFZu1kfXnW
# dJu9eZOn/U6DwbIgKmpSXYmiTxcWNlg+FWEM+45gaguehaQUboaoUbG9D59nr2ZQ
# Dx6bmL5ayDxosZn31S72PxW7dxJk9JOBkW4T9AgxEUSVkQbNwYGg2OfXJDF2Aeq/
# mFLcZXNiBHbZ4lglraLkSf/p3eqaspLo1Ff8mxAdLyW1m+2c3kjCAycACNnpAb0Q
# F81PEb6zwBjCirHe0YVaWRiRkmTrtMJXUFfI3iG/9O+kv8Gf6qgmG1t+1CtTQmsw
# 1QEvrsnePAh1fwRG
# SIG # End signature block
