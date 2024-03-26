# ***********************************************************************************************************
# Version 1.0
# Date: 03-01-2012
# Author: Vinay Pamnani - vinpa@microsoft.com
# Description:
# 		Collects Configuration Manager SQL Server Information.
# ***********************************************************************************************************

trap [Exception]
{
	WriteTo-ErrorDebugReport -ErrorRecord $_
	$_ | Out-File -FilePath $OutputBase -Append
	continue
}

# ===============================================================
# Function Definitions
# Taken from DC_CollectSQL.ps1 from OpsMgr
# ===============================================================

function WriteConnectionEvents($currentEventID) {
     Get-Event | ForEach-Object {
        if ($_.SourceIdentifier -eq $currentEventID) {
             $CurrentEventIdentifier = $_.EventIdentifier;
            $info = $_.SourceEventArgs
            Remove-Event -EventIdentifier $CurrentEventIdentifier
             $info.Message
         }
     }
}

function Run-SQLCommandtoFile
{
    param (
		$SqlQuery,
		$outFile,
		$DisplayText,
		$collectFiles=$false,
		$fileDescription="",
		$ZipFile="",
		$OutputWidth = 1024,
		[switch]$HideSqlQuery,
		[switch]$NoSecondary
		)
	process
	{
		# Reset DisplayText to SqlQuery if it's not provided
		if ($null -eq $DisplayText) {
			$DisplayText = $SqlQuery
		}

		# Skip secondary site
		if ($NoSecondary -and ($SiteType -eq 2)) {
			AddTo-CMDatabaseSummary -NoToSummaryReport -NoToSummaryFile -Name $DisplayText -Value "Not available on a Secondary Site"
			return
		}

		# Standardize text added to summary file "Review $outFileName"
		if ($ZipFile -eq "") {
			$outFileName = $outFile
		}
		else {
			$outFileName = $ZipFile + $outFile.Substring($outFile.LastIndexOf("\"))
		}

		# Hide SQL Query from output if specified
		if ($HideSqlQuery) {
			"=" * ($DisplayText.Length + 4) + "`r`n-- " + $DisplayText + "`r`n" + "=" * ($DisplayText.Length + 4) + "`r`n" | Out-File -FilePath $outFile -Append
			TraceOut "  Current Query = $DisplayText"
		}
		else {
			"=" * ($SqlQuery.Length + 2) + "`r`n-- " + $DisplayText + "`r`n" + $SqlQuery + "`r`n" + "=" * ($SqlQuery.Length + 2) + "`r`n" | Out-File -FilePath $outFile -Append
			TraceOut "  Current Query = $SqlQuery"
		}

		Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CM12SQL -Status $DisplayText

		$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
		$SqlCmd.CommandText = $SqlQuery
		$SqlCmd.Connection = $global:DatabaseConnection

		$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
		$SqlAdapter.SelectCommand = $SqlCmd

		$SqlTable = New-Object System.Data.DataTable
		try {
			$SqlAdapter.Fill($SqlTable) | out-null

			$results = ($SqlTable | Select-Object * -ExcludeProperty RowError, RowState, HasErrors, Table, ItemArray | Format-Table -AutoSize -Wrap -Property * `
				| Out-String -Width $OutputWidth).Trim()
			$results += "`r`n`r`n"
			$results | Out-File -FilePath $outFile -Append

			AddTo-CMDatabaseSummary -NoToSummaryReport -NoToSummaryFile -Name $DisplayText -Value "Review $outFileName"

			If ($collectFiles -eq $true) {
				CollectFiles -filesToCollect $outFile -fileDescription $fileDescription -sectionDescription $sectiondescription -noFileExtensionsOnDescription
			}
		}
		catch [Exception] {
			AddTo-CMDatabaseSummary -NoToSummaryReport -NoToSummaryFile -Name $DisplayText -Value "ERROR: $_"
		}
	}
}

function Run-SQLCommandtoFileWithInfo
{
    param (
		$SqlQuery,
		$outFile,
		$DisplayText,
		$collectFiles=$false,
		$ZipFile="",
		[switch]$HideSqlQuery,
		[switch]$SkipEvents
		)
	process
	{
		# Reset DisplayText to SqlQuery if it's not provided
		if ($null -eq $DisplayText) {
			$DisplayText = $SqlQuery
		}

		# Standardize text added to summary file "Review $outFileName"
		if ($ZipFile -eq "") {
			$outFileName = $outFile
		}
		else {
			$outFileName = $ZipFile + $outFile.Substring($outFile.LastIndexOf("\"))
		}

		# Hide SQL Query from output if specified
		if ($HideSqlQuery) {
			"=" * ($DisplayText.Length + 4) + "`r`n-- " + $DisplayText + "`r`n" + "=" * ($DisplayText.Length + 4) + "`r`n" | Out-File -FilePath $outFile -Append
			TraceOut "  Current Query = $DisplayText"
		}
		else {
			"=" * ($SqlQuery.Length + 2) + "`r`n-- " + $DisplayText + "`r`n" + $SqlQuery + "`r`n" + "=" * ($SqlQuery.Length + 2) + "`r`n" | Out-File -FilePath $outFile -Append
			TraceOut "  Current Query = $SqlQuery"
		}

		Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CM12SQL -Status $DisplayText

		If (-not $SkipEvents) {
			$eventID = $outFile
			Register-ObjectEvent -inputObject $global:DatabaseConnection -eventName InfoMessage -sourceIdentifier $eventID
		}

		$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
		$SqlCmd.Connection = $global:DatabaseConnection
		$SqlCmd.CommandText = $SqlQuery
		$SqlCmd.CommandTimeout = 0

		$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
		$SqlAdapter.SelectCommand = $SqlCmd

		$DataSet = New-Object System.Data.DataSet

		try {
			$SqlAdapter.Fill($DataSet)

			If ($DataSet.Tables.Count -gt 0) {
				foreach ($table in $DataSet.Tables)
				{
					$table | Format-Table -AutoSize | Out-String -width 2048 | Out-File -FilePath $outFile -Append
				}
			}

			If (-not $SkipEvents) {
				If (($RemoteStatus -eq 0) -or ($RemoteStatus -eq 1)) {
					WriteConnectionEvents $eventID | Out-String -width 2048 | Out-File -FilePath $outFile -Append
				}
				Else {
					"Message Information Events cannot be obtained Remotely. Run Diagnostics locally on a Primary or Central Site to obtain this data." | Out-File -FilePath $outFile -Append
				}
			}

			If ($collectFiles -eq $true) {
				CollectFiles -filesToCollect $outFile -fileDescription "$DisplayText" -sectionDescription $sectionDescription -noFileExtensionsOnDescription
			}

			AddTo-CMDatabaseSummary -NoToSummaryReport -NoToSummaryFile -Name $DisplayText -Value "Review $outFileName"
		}
		catch [Exception] {
			AddTo-CMDatabaseSummary -NoToSummaryReport -NoToSummaryFile -Name $DisplayText -Value "ERROR: $_"
		}
	}
}

function Get-SQLValue
{
	Param(
		[string]$SqlQuery,
	    [string]$ColumnName,
		[string]$DisplayText
	)

	Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CM12SQL -Status $DisplayText

	$Result = New-Object -TypeName PSObject

	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlCmd.CommandText = $SqlQuery
	$SqlCmd.Connection = $global:DatabaseConnection

	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$SqlAdapter.SelectCommand = $SqlCmd

	TraceOut "Current Query = $SqlQuery"
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

function Get-SQLValueWithError
{
	Param(
		[string]$SqlQuery,
	    [string]$ColumnName,
		[string]$DisplayText
	)

	$ResultValue = Get-SQLValue -SqlQuery $SqlQuery -ColumnName $ColumnName -DisplayText $DisplayText
	if ($null -eq $ResultValue.Error) {
		return $ResultValue.Value
	}
	else {
		return $ResultValue.Error
	}
}

function Format-XML ([xml]$xml, $indent=2)
{
    $StringWriter = New-Object System.IO.StringWriter
    $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter
    $xmlWriter.Formatting = "indented"
    $xmlWriter.Indentation = $Indent
    $xml.WriteContentTo($XmlWriter)
    $XmlWriter.Flush()
    $StringWriter.Flush()
    return $StringWriter.ToString()
}

#function RunSQLCommandtoCSV
#{
#    param (
#		$cmd,
#		$outfile
#		)
#	process
#	{
#		$out = $ComputerName + "_SQL_" + $outfile + ".csv"

#		Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CM12SQL -Status $cmd
#		$da = new-object System.Data.SqlClient.SqlDataAdapter ($cmd, $connnectionstring)
#		$dt = new-object System.Data.DataTable
#		$da.fill($dt) | out-null

#		$dt | Export-CSV -Path $out
#		CollectFiles -filesToCollect $out -fileDescription "$cmd" -sectionDescription $sectiondescription

#	}
#}

# ===========================
# Script Execution
# ===========================

If (!$Is_SiteServer) {
	TraceOut "ConfigMgr Site Server not detected. This script gathers data only from a Site Server. Exiting."
	exit 0
}

TraceOut "Started"
Import-LocalizedData -BindingVariable ScriptStrings
$sectiondescription = "Configuration Manager SQL Data"

TraceOut "ConfigMgr SQL Server: $ConfigMgrDBServer"
TraceOut "ConfigMgr SQL Database: $ConfigMgrDBName"

if ($null -ne $global:DatabaseConnectionError) {
	TraceOut "SQL Connection Failed With Error: $global:DatabaseConnectionError"
	return
}

$Temp = Get-SQLValueWithError -SqlQuery "SELECT name, value_in_use FROM sys.configurations WHERE name = 'max server memory (MB)'" -ColumnName "value_in_use" -DisplayText "Max Server Memory (MB)"
AddTo-CMDatabaseSummary -Name "Max Memory (MB)" -Value $Temp -NoToSummaryQueries

$Temp = Get-SQLValueWithError -SqlQuery "SELECT name, value_in_use FROM sys.configurations WHERE name = 'max degree of parallelism'" -ColumnName "value_in_use" -DisplayText "MDOP"
AddTo-CMDatabaseSummary -Name "MDOP" -Value $Temp -NoToSummaryQueries

# ------------------
# Basic SQL Queries
# ------------------
$OutFile= $ComputerName +  "_SQL_Basic.txt"
Run-SQLCommandtoFile -SqlQuery "SELECT @@SERVERNAME AS [Server Name], @@VERSION AS [SQL Version]" -outFile $OutFile -DisplayText "SQL Version"
Run-SQLCommandtoFile -SqlQuery "SELECT servicename, process_id, startup_type_desc, status_desc,
last_startup_time, service_account, is_clustered, cluster_nodename, [filename]
FROM sys.dm_server_services WITH (NOLOCK) OPTION (RECOMPILE)" -outFile $OutFile -DisplayText "SQL Services" -HideSqlQuery
Run-SQLCommandtoFile -SqlQuery "SELECT cpu_count AS [Logical CPU Count], scheduler_count, hyperthread_ratio AS [Hyperthread Ratio],
cpu_count/hyperthread_ratio AS [Physical CPU Count],
physical_memory_kb/1024 AS [Physical Memory (MB)], committed_kb/1024 AS [Committed Memory (MB)],
committed_target_kb/1024 AS [Committed Target Memory (MB)],
max_workers_count AS [Max Workers Count], affinity_type_desc AS [Affinity Type],
sqlserver_start_time AS [SQL Server Start Time], virtual_machine_type_desc AS [Virtual Machine Type]
FROM sys.dm_os_sys_info WITH (NOLOCK) OPTION (RECOMPILE)" -outFile $OutFile -DisplayText "SQL Server Hardware Info" -HideSqlQuery
Run-SQLCommandtoFile -SqlQuery "EXEC sp_helpdb" -outFile $OutFile -DisplayText "Databases"
Run-SQLCommandtoFile -SqlQuery "EXEC sp_helprolemember" -outFile $OutFile -DisplayText "Role Members"
Run-SQLCommandtoFile -SqlQuery "SELECT uid, status, name, createdate, islogin, hasdbaccess, updatedate FROM sys.sysusers" -outFile $OutFile -DisplayText "Sys Users"
Run-SQLCommandtoFile -SqlQuery "SELECT status, name, loginname, createdate, updatedate, accdate, dbname, denylogin, hasaccess, sysadmin, securityadmin, serveradmin, setupadmin, processadmin, diskadmin, dbcreator, bulkadmin, isntname, isntgroup, isntuser FROM [master].sys.syslogins" `
	-outFile $OutFile -DisplayText "Sys Logins ([master].sys.syslogins)" -HideSqlQuery
Run-SQLCommandtoFile -SqlQuery "SELECT certificate_id, principal_id, name, subject, pvt_key_encryption_type_desc, expiry_date, start_date, is_active_for_begin_dialog, issuer_name, string_sid, thumbprint, attested_by  FROM [master].sys.certificates" `
	-outFile $OutFile -DisplayText "Certificates ([master].sys.certificates)" -HideSqlQuery
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM sys.dm_os_loaded_modules WHERE company <> 'Microsoft Corporation' OR company IS NULL"	`
	-outFile $OutFile -DisplayText "Loaded Modules"

CollectFiles -filesToCollect $OutFile -fileDescription "Basic SQL Information" -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# ------------------------------------
# Top SP's by CPU, Elapsed Time, etc.
# ------------------------------------
#$OutFile= $ComputerName +  "_SQL_TopQueries.txt"
#Run-SQLCommandtoFile -SqlQuery "SELECT TOP(50) DB_NAME(t.[dbid]) AS [Database Name], qs.creation_time AS [Creation Time],
#qs.total_worker_time AS [Total Worker Time], qs.min_worker_time AS [Min Worker Time],
#qs.total_worker_time/qs.execution_count AS [Avg Worker Time],
#qs.max_worker_time AS [Max Worker Time],
#qs.total_elapsed_time/qs.execution_count AS [Avg Elapsed Time],
# qs.execution_count AS [Execution Count],
#qs.total_logical_reads/qs.execution_count AS [Avg Logical Reads],
#qs.total_physical_reads/qs.execution_count AS [Avg Physical Reads],
#rtrim(t.[text]) AS [Query Text]
#FROM sys.dm_exec_query_stats AS qs WITH (NOLOCK)
#CROSS APPLY sys.dm_exec_sql_text(plan_handle) AS t
#ORDER BY qs.total_worker_time DESC OPTION (RECOMPILE)" -outFile $OutFile -DisplayText "Top 50 Queries by CPU" -HideSqlQuery
#Run-SQLCommandtoFile -SqlQuery "SELECT TOP(50) DB_NAME(t.[dbid]) AS [Database Name], qs.creation_time AS [Creation Time],
#qs.total_elapsed_time  AS [Total Elapsed Time],
#qs.total_elapsed_time/qs.execution_count AS [Avg Elapsed Time],
#qs.total_worker_time AS [Total Worker Time],
#qs.total_worker_time/qs.execution_count AS [Avg Worker Time],
#qs.execution_count AS [Execution Count],
#qs.total_logical_reads/qs.execution_count AS [Avg Logical Reads],
#qs.total_physical_reads/qs.execution_count AS [Avg Physical Reads],
#rtrim(t.[text]) AS [Query Text]
#FROM sys.dm_exec_query_stats AS qs WITH (NOLOCK)
#CROSS APPLY sys.dm_exec_sql_text(plan_handle) AS t
#ORDER BY qs.total_elapsed_time/qs.execution_count DESC OPTION (RECOMPILE)" -outFile $OutFile -DisplayText "Top 50 Queries by Average Elapsed Time" -HideSqlQuery

$OutFile= $ComputerName +  "_SQL_TopQueries.txt"
Run-SQLCommandtoFile -SqlQuery "SELECT TOP(50) p.name AS [SP Name], qs.total_worker_time AS [TotalWorkerTime],
qs.total_worker_time/qs.execution_count AS [AvgWorkerTime],
qs.execution_count,
ISNULL(qs.execution_count/DATEDIFF(Minute, qs.cached_time, GETDATE()), 0) AS [Calls/Minute],
qs.total_elapsed_time,
qs.total_elapsed_time/qs.execution_count AS [avg_elapsed_time],
qs.cached_time
FROM sys.procedures AS p WITH (NOLOCK)
INNER JOIN sys.dm_exec_procedure_stats AS qs WITH (NOLOCK)
ON p.[object_id] = qs.[object_id]
WHERE qs.database_id = DB_ID() AND qs.execution_count > 0
ORDER BY qs.total_worker_time DESC OPTION (RECOMPILE)" -outFile $OutFile -DisplayText "Top 50 SPs by CPU" -HideSqlQuery
Run-SQLCommandtoFile -SqlQuery "SELECT TOP(50) p.name AS [SP Name], qs.total_elapsed_time/qs.execution_count AS [avg_elapsed_time],
qs.total_elapsed_time, qs.execution_count, ISNULL(qs.execution_count/DATEDIFF(Minute, qs.cached_time,
GETDATE()), 0) AS [Calls/Minute], qs.total_worker_time/qs.execution_count AS [AvgWorkerTime],
qs.total_worker_time AS [TotalWorkerTime], qs.cached_time
FROM sys.procedures AS p WITH (NOLOCK)
INNER JOIN sys.dm_exec_procedure_stats AS qs WITH (NOLOCK)
ON p.[object_id] = qs.[object_id]
WHERE qs.database_id = DB_ID() AND qs.execution_count > 0
ORDER BY avg_elapsed_time DESC OPTION (RECOMPILE)" -outFile $OutFile -DisplayText "Top 50 SPs by Average Elapsed Time" -HideSqlQuery
Run-SQLCommandtoFile -SqlQuery "SELECT TOP(50) p.name AS [SP Name], qs.execution_count,
ISNULL(qs.execution_count/DATEDIFF(Minute, qs.cached_time, GETDATE()), 0) AS [Calls/Minute],
qs.total_worker_time/qs.execution_count AS [AvgWorkerTime], qs.total_worker_time AS [TotalWorkerTime],
qs.total_elapsed_time, qs.total_elapsed_time/qs.execution_count AS [avg_elapsed_time],
qs.cached_time
FROM sys.procedures AS p WITH (NOLOCK)
INNER JOIN sys.dm_exec_procedure_stats AS qs WITH (NOLOCK)
ON p.[object_id] = qs.[object_id]
WHERE qs.database_id = DB_ID() AND qs.execution_count > 0
ORDER BY qs.execution_count DESC OPTION (RECOMPILE)" -outFile $OutFile -DisplayText "Top 50 SPs by Execution Count" -HideSqlQuery
Run-SQLCommandtoFile -SqlQuery "SELECT TOP(50) p.name AS [SP Name], ISNULL(qs.execution_count/DATEDIFF(Minute, qs.cached_time, GETDATE()), 0) AS [Calls/Minute],
qs.total_elapsed_time/qs.execution_count AS [avg_elapsed_time],
qs.total_elapsed_time, qs.total_worker_time/qs.execution_count AS [AvgWorkerTime],
qs.total_worker_time AS [TotalWorkerTime], qs.execution_count, qs.cached_time
FROM sys.procedures AS p WITH (NOLOCK)
INNER JOIN sys.dm_exec_procedure_stats AS qs WITH (NOLOCK)
ON p.[object_id] = qs.[object_id]
WHERE qs.database_id = DB_ID() AND ISNULL(qs.execution_count/DATEDIFF(Minute, qs.cached_time, GETDATE()), 0) > 0  AND qs.execution_count > 0
ORDER BY [Calls/Minute] DESC OPTION (RECOMPILE)" -outFile $OutFile -DisplayText "Top 50 SPs by Calls Per Minute" -HideSqlQuery

CollectFiles -filesToCollect $OutFile -fileDescription "Top Queries" -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# ------------------
# SQL Transactions
# ------------------
$OutFile= $ComputerName +  "_SQL_Transactions.txt"
Run-SQLCommandtoFile -SqlQuery "SELECT sp.spid, rtrim(sp.status) [status], rtrim(sp.loginame) [Login], rtrim(sp.hostname) [hostname],
sp.blocked BlkBy, sd.name DBName, rtrim(sp.cmd) Command, sp.open_tran, sp.cpu CPUTime, sp.physical_io DiskIO, sp.last_batch LastBatch, rtrim(sp.program_name) [ProgramName], rtrim(qt.text) [Text]
FROM master.dbo.sysprocesses sp
JOIN master.dbo.sysdatabases sd ON sp.dbid = sd.dbid
OUTER APPLY sys.dm_exec_sql_text(sp.sql_handle) AS qt
WHERE sp.blocked <> 0
ORDER BY sp.spid" -outFile $OutFile -DisplayText "Blocked SPIDs" -HideSqlQuery
Run-SQLCommandtoFile -SqlQuery "SELECT sp.spid, rtrim(sp.status) [status], rtrim(sp.loginame) [Login], rtrim(sp.hostname) [hostname],
sp.blocked BlkBy, sd.name DBName, rtrim(sp.cmd) Command, sp.open_tran, sp.cpu CPUTime, sp.physical_io DiskIO, sp.last_batch LastBatch, rtrim(sp.program_name) [ProgramName], rtrim(qt.text) [Text]
FROM master.dbo.sysprocesses sp
JOIN master.dbo.sysdatabases sd ON sp.dbid = sd.dbid
OUTER APPLY sys.dm_exec_sql_text(sp.sql_handle) AS qt
WHERE sp.spid IN (SELECT blocked FROM master.dbo.sysprocesses) AND sp.blocked = 0
ORDER BY sp.spid" -outFile $OutFile -DisplayText "Head Blockers" -HideSqlQuery
Run-SQLCommandtoFile -SqlQuery "SELECT T.*, S.blocked, rtrim(E.text) [Text]
	FROM sys.dm_tran_active_snapshot_database_transactions T
	JOIN sys.dm_exec_requests R ON T.Session_ID = R.Session_ID
	INNER JOIN sys.sysprocesses S on S.spid = T.Session_ID
	OUTER APPLY sys.dm_exec_sql_text(R.sql_handle) AS E
	ORDER BY elapsed_time_seconds DESC" -outFile $OutFile -DisplayText "Active Snapshot Database Transactions" -HideSqlQuery
Run-SQLCommandtoFile -SqlQuery "EXEC sp_who2" -outFile $OutFile -DisplayText "sp_who2"
CollectFiles -filesToCollect $OutFile -fileDescription "SQL Transactions" -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# ----------------------
# List of Site Systems
# ----------------------
$OutFile = $ComputerName + "_SQL_SiteSystems.txt"
Run-SQLCommandtoFile -SqlQuery "SELECT SMSSiteCode, COUNT(1) AS [Number Of DPs] FROM DistributionPoints GROUP BY SMSSiteCode UNION SELECT 'Total' AS SMSSiteCode, COUNT(1) AS [Number Of DPs] FROM DistributionPoints" `
	-outFile $OutFile -DisplayText "Count of All Available Distribution Points by Site"
Run-SQLCommandtoFile -SqlQuery "SELECT SiteCode, ServerName, COUNT(ServerName) AS [Number Of Site System Roles] FROM SysResList GROUP BY SiteCode, ServerName" `
	-outFile $OutFile -DisplayText "Count of All Available Site Systems by Server Name"
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM DistributionPoints ORDER BY SMSSiteCode, ServerName" `
	-outFile $OutFile -DisplayText "List of Distribution Points"
Run-SQLCommandtoFile -SqlQuery "SELECT SiteCode, RoleName, ServerName, ServerRemoteName, PublicDNSName, InternetEnabled, Shared, SslState, DomainFQDN, ForestFQDN, IISPreferredPort, IISSslPreferredPort, IsAvailable FROM SysResList ORDER BY SiteCode, ServerName, RoleName" `
	-outFile $OutFile -DisplayText "List of Site Systems"

CollectFiles -filesToCollect $OutFile -fileDescription "List of Site Systems" -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# ------------------------
# CM Database Information
# ------------------------
$OutFile = $ComputerName + "_SQL_CMDBInfo.txt"
Run-SQLCommandtoFile -SqlQuery "SELECT SiteNumber, SiteCode, TaskName, TaskType, IsEnabled, NumRefreshDays, DaysOfWeek, BeginTime, LatestBeginTime, BackupLocation, DeleteOlderThan FROM vSMS_SC_SQL_Task ORDER BY SiteCode" `
	-outFile $OutFile -DisplayText "ConfigMgr Maintenance Tasks Configuration"
Run-SQLCommandtoFile -SqlQuery "SELECT *, DATEDIFF(S, LastStartTime, LastCompletionTime) As TimeTakenInSeconds, DATEDIFF(MI, LastStartTime, LastCompletionTime) As TimeTakenInMinutes FROM SQLTaskStatus ORDER BY TimeTakenInMinutes DESC" `
	-outFile $OutFile -DisplayText "ConfigMgr Maintenance Tasks Status ($global:SMSSiteCode)"
Run-SQLCommandtoFile -SqlQuery "SELECT *, DATEDIFF(S, LastStartTime, LastSuccessfulCompletionTime) As TimeTakenInSeconds, DATEDIFF(MI, LastStartTime, LastSuccessfulCompletionTime) As TimeTakenInMinutes FROM vSR_SummaryTasks ORDER BY TimeTakenInMinutes DESC" `
	-outFile $OutFile -DisplayText "State System Summary Tasks ($global:SMSSiteCode)" -NoSecondary

Run-SQLCommandtoFile -SqlQuery "SELECT BoundaryType, CASE WHEN BoundaryType = 0 THEN 'IPSUBNET' WHEN BoundaryType = 1 THEN 'ADSITE' WHEN BoundaryType = 2 THEN 'IPV6PREFIX' WHEN BoundaryType = 3 THEN 'IPRANGE' END AS [Type], COUNT(BoundaryType) AS [Count] FROM BoundaryEx GROUP BY BoundaryType" `
	-outFile $OutFile -DisplayText "Boundary Counts"

CollectFiles -filesToCollect $OutFile -fileDescription "ConfigMgr DB Info" -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# ------------------------
# Site Control File
# ------------------------
$OutFile = $ComputerName + "_SQL_SiteControlFile.xml.txt"
$ResultValue = Get-SQLValue -SqlQuery "SELECT * FROM vSMS_SC_SiteControlXML WHERE SiteCode = '$SMSSiteCode'" -ColumnName "SiteControl" -DisplayText "Site Control File (XML)"

if ($null -eq $ResultValue.Error) {
	try {
		$ScfXml = Format-XML -xml $ResultValue.Value
		$ScfXml | Out-String -Width 4096 | Out-File -FilePath $OutFile -Force
	}
	catch [Exception] {
		$_ | Out-File -FilePath $OutFile -Force
	}
}
else {
	$ResultValue.Error | Out-File -FilePath $OutFile -Force
}

CollectFiles -filesToCollect $OutFile -fileDescription "Site Control File" -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# ---------------------
# SUP Sync information
# ---------------------
$OutFile = $ComputerName + "_SQL_SUPSync.txt"

Run-SQLCommandtoFile -SqlQuery "SELECT CI.CategoryInstance_UniqueID, CI.CategoryTypeName, LCI.CategoryInstanceName FROM CI_CategoryInstances CI
JOIN CI_LocalizedCategoryInstances LCI ON CI.CategoryInstanceID = LCI.CategoryInstanceID
JOIN CI_UpdateCategorySubscription UCS ON CI.CategoryInstanceID = UCS.CategoryInstanceID
WHERE UCS.IsSubscribed = 1
ORDER BY CI.CategoryTypeName, LCI.CategoryInstanceName" -outFile $OutFile -DisplayText "SUM Products/Classifications" -NoSecondary -HideSqlQuery
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM  vSMS_SUPSyncStatus"-outFile $OutFile -DisplayText "SUP Sync Status" -NoSecondary
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM WSUSServerLocations" -outFile $OutFile -DisplayText "WSUSServerLocations"
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM Update_SyncStatus" -outFile $OutFile -DisplayText "Update_SyncStatus"
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM CI_UpdateSources" -outFile $OutFile -DisplayText "CI_UpdateSources"

CollectFiles -filesToCollect $OutFile -fileDescription "SUP Sync Status" -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# ---------------------
# OSD Information
# ---------------------
$OutFile = $ComputerName + "_SQL_BootImages.txt"

Run-SQLCommandtoFile -SqlQuery "SELECT * FROM vSMS_OSDeploymentKitInstalled"-outFile $OutFile -DisplayText "ADK Version from Database" -NoSecondary -HideSqlQuery
"========================================" | Out-File $OutFile -Append
"-- ADK Version from Add/Remove Programs " | Out-File $OutFile -Append
"========================================" | Out-File $OutFile -Append
"" | Out-File $OutFile -Append
($global:ADKVersion).Trim() | Out-File $OutFile -Append
"`r`n" | Out-File $OutFile -Append
Run-SQLCommandtoFile -SqlQuery "SELECT PkgID, Name, ImageOSVersion, Version, Architecture, DefaultImage, SourceSite, SourceVersion, LastRefresh, SourceDate, SourceSize, Action, Source, ImagePath FROM vSMS_BootImagePackage_List"-outFile $OutFile -DisplayText "Boot Images" -NoSecondary
Run-SQLCommandtoFile -SqlQuery "SELECT ImageId, Architecture, Name, MsiComponentID, Size, IsRequired, IsManageable FROM vSMS_WinPEOptionalComponentInBootImage ORDER BY ImageId, Architecture"-outFile $OutFile -DisplayText "Optional Components" -NoSecondary
CollectFiles -filesToCollect $OutFile -fileDescription "Boot Images" -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# ----------
# DRS Data
# ----------
$ZipName = $ComputerName + "_SQL_DRSData.zip"
$Destination = Join-Path $Env:windir ("\Temp\" + $ComputerName + "_SQL_DRSData")
If (Test-Path $Destination) {
	Remove-Item -Path $Destination -Recurse -Force
}
New-Item -ItemType "Directory" $Destination | Out-Null #_#

$OutFile = Join-Path $Destination "spDiagDRS.txt"
Run-SQLCommandtoFileWithInfo -SqlQuery "EXEC spDiagDRS" -outFile $OutFile -DisplayText "spDiagDRS" -ZipFile $ZipName

# Removed spDiagGetSpaceUsed as it takes a long time, and is not absolutely necessary
# $OutFile = Join-Path $Destination "spDiagGetSpaceUsed.txt"
# Run-SQLCommandtoFileWithInfo -SqlQuery "EXEC spDiagGetSpaceUsed" -outFile $OutFile -DisplayText "spDiagGetSpaceUsed" -ZipFile $ZipName

$OutFile = Join-Path $Destination "Sites.txt"
Run-SQLCommandtoFile -SqlQuery "SELECT SiteKey, SiteCode, SiteName, ReportToSite, Status, DetailedStatus, SiteType, BuildNumber, Version, SiteServer, InstallDir, ReplicatesReservedRanges FROM Sites" -outFile $OutFile -DisplayText "Sites Output" -ZipFile $ZipName
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM ServerData" -outFile $OutFile -DisplayText "ServerData Output" -ZipFile $ZipName
Run-SQLCommandtoFile -SqlQuery "SELECT SiteKey, SiteCode, ReportToSite, SiteServer, Settings FROM Sites" -OutputWidth 2048 -outFile $OutFile -DisplayText "Client Operational Settings" -ZipFile $ZipName

$OutFile = Join-Path $Destination "RCM_Tables.txt"
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM RCM_ReplicationLinkStatus" -outFile $OutFile -DisplayText "RCM_ReplicationLinkStatus Table Output" -ZipFile $ZipName
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM RCM_DrsInitializationTracking" -outFile $OutFile -DisplayText "RCM_DrsInitializationTracking Table Output" -ZipFile $ZipName
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM RCM_RecoveryTracking" -outFile $OutFile -DisplayText "RCM_RecoveryTracking" -ZipFile $ZipName
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM RCM_RecoveryPostAction" -outFile $OutFile -DisplayText "RCM_RecoveryPostAction" -ZipFile $ZipName

$OutFile = Join-Path $Destination "vReplicationLinkStatus.txt"
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM vReplicationLinkStatus" -outFile $OutFile -DisplayText "vReplicationLinkStatus Output" -ZipFile $ZipName

$OutFile = Join-Path $Destination "DRS_Tables.txt"
Run-SQLCommandtoFile -SqlQuery "SELECT COUNT (ConflictType) [Count], TableName, ConflictType, ConflictLoserSiteCode FROM DrsConflictInfo GROUP BY TableName, ConflictType, ConflictLoserSiteCode ORDER BY [Count] DESC" -outFile $OutFile -DisplayText "DRS Conflicts Summary (All time)" -ZipFile $ZipName
Run-SQLCommandtoFile -SqlQuery "SELECT COUNT (ConflictType) [Count], TableName, ConflictType, ConflictLoserSiteCode FROM DrsConflictInfo WHERE ConflictTime > DATEAdd(dd,-5,GETDate()) GROUP BY TableName, ConflictType, ConflictLoserSiteCode ORDER BY [Count] DESC" -outFile $OutFile -DisplayText "DRS Conflicts Summary (Past 5 days)" -ZipFile $ZipName
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM DrsConflictInfo WHERE ConflictTime > DATEAdd(dd,-5,GETDate()) ORDER BY ConflictTime DESC" -outFile $OutFile -DisplayText "DRS Conflicts (Past 5 days)" -ZipFile $ZipName
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM DRSReceiveHistory WHERE ProcessedTime IS NULL" -outFile $OutFile -DisplayText "DRSReceiveHistory Table Output" -ZipFile $ZipName
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM DRSSendHistory WHERE ProcessedTime IS NULL" -outFile $OutFile -DisplayText "DRSSendHistory Table Output" -ZipFile $ZipName

$OutFile = Join-Path $Destination "vLogs.txt"
Run-SQLCommandtoFile -SqlQuery "SELECT TOP 1000 * FROM vLogs WHERE LogText NOT LIKE 'INFO:%' AND LogText NOT LIKE 'Not sending changes to sites%' AND LogText <> 'Web Service heartbeat' AND LogText NOT LIKE 'SYNC%'ORDER BY LogLine DESC" -outFile $OutFile -DisplayText "vLogs Output" -ZipFile $ZipName

$OutFile = Join-Path $Destination "TransmissionQueue.txt"
Run-SQLCommandtoFile -SqlQuery "SELECT COUNT (to_service_name) [Count], to_service_name FROM sys.transmission_queue GROUP BY to_service_name" -outFile $OutFile -DisplayText "Transmission Queue Summary" -ZipFile $ZipName
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM sys.transmission_queue WHERE conversation_handle NOT IN (SELECT handle FROM SSB_DialogPool)" -outFile $OutFile -DisplayText "Orphaned Messages" -ZipFile $ZipName
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM sys.transmission_queue" -outFile $OutFile -DisplayText "Transmission Queue" -ZipFile $ZipName

$OutFile = Join-Path $Destination "EndPointsAndQueues.txt"
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM sys.tcp_endpoints" -outFile $OutFile -DisplayText "TCP Endpoints" -ZipFile $ZipName
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM sys.service_broker_endpoints" -outFile $OutFile -DisplayText "Service Broker Endpoints" -ZipFile $ZipName
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM sys.service_queues" -outFile $OutFile -DisplayText "Service Queues" -ZipFile $ZipName
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM sys.conversation_endpoints" -outFile $OutFile -DisplayText "Conversation Endpoints" -ZipFile $ZipName
Run-SQLCommandtoFile -SqlQuery "SELECT * FROM SSB_DialogPool" -outFile $OutFile -DisplayText "SSB Dialog Pool" -ZipFile $ZipName

$OutFile = Join-Path $Destination "DRS_Config.txt"
# Run-SQLCommandtoFile -SqlQuery "SELECT * FROM ServerData" -outFile $OutFile -DisplayText "Server Data Table" -ZipFile $ZipName
Run-SQLCommandtoFile -SqlQuery "SELECT SD.SiteCode,
MAX(CASE WHEN vRSCP.Name = 'Degraded' THEN vRSCP.Value END) AS Degraded,
MAX(CASE WHEN vRSCP.Name = 'Failed' THEN vRSCP.Value END) AS Failed,
MAX(CASE WHEN vRSCP.Name = 'DviewForHINV' THEN vRSCP.Value END) AS DviewForHINV,
MAX(CASE WHEN vRSCP.Name = 'DviewForSINV' THEN vRSCP.Value END) AS DviewForSINV,
MAX(CASE WHEN vRSCP.Name = 'DviewForStatusMessages' THEN vRSCP.Value END) AS DviewForStatusMessages,
MAX(CASE WHEN vRSCP.Name = 'SQL Server Service Broker Port' THEN vRSCP.Value END) AS BrokerPort,
MAX(CASE WHEN vRSCP.Name = 'Send History Summarize Interval' THEN vRSCP.Value END) AS SendHistorySummarizeInterval,
MAX(CASE WHEN vRSCP.Name = 'SQL Server Service Broker Port' THEN vRSCP.Value END) AS SSBPort,
MAX(CASE WHEN vRSCP.Name = 'Retention Period' THEN vRSCP.Value END) AS RetentionPeriod,
MAX(CASE WHEN vRSCP.Name = 'IsCompression' THEN vRSCP.Value END) AS IsCompression
FROM vRcmSqlControlProperties vRSCP
JOIN RCMSQlControl RSC ON vRSCP.ID = RSC.ID
JOIN ServerData SD ON RSC.SiteNumber = SD.ID
GROUP BY SD.SiteCode" -outFile $OutFile -DisplayText "RCM Control Properties" -ZipFile $ZipName -HideSqlQuery
Run-SQLCommandtoFile -SqlQuery "SELECT D.name, CTD.* FROM sys.change_tracking_databases AS CTD JOIN sys.databases AS D ON D.database_id = CTD.database_id WHERE D.name = '$ConfigMgrDBNameNoInstance'" -outFile $OutFile -DisplayText "DRS Data Retention Settings" -ZipFile $ZipName

# Compress and Collect
compressCollectFiles -DestinationFileName $ZipName -filesToCollect ($Destination + "\*.*") -sectionDescription $sectionDescription -fileDescription "DRS Data" -Recursive -ForegroundProcess -noFileExtensionsOnDescription
Remove-Item -Path $Destination -Recurse -Force
# CollectFiles -filesToCollect $OutFile -fileDescription "DRS Troubleshooting Data" -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# ----------------------
# Update Servicing Data
# ----------------------
$ZipName = $ComputerName + "_SQL_UpdateServicing.zip"
$Destination = Join-Path $Env:windir ("\Temp\" + $ComputerName + "_SQL_UpdateServicing")
If (Test-Path $Destination) {
	Remove-Item -Path $Destination -Recurse -Force
}
New-Item -ItemType "Directory" $Destination | Out-Null #_#

if ($global:SiteBuildNumber -gt 8325) {
	# CM_UpdatePackages
	$OutFile = Join-Path $Destination "CM_UpdatePackages.txt"
	Run-SQLCommandtoFile -SqlQuery "SELECT * FROM CM_UpdatePackages" -outFile $OutFile -DisplayText "CM_UpdatePackages" -ZipFile $ZipName
	Run-SQLCommandtoFile -SqlQuery "SELECT * FROM CM_UpdatePackages_Hist ORDER BY RecordTime DESC" -outFile $OutFile -DisplayText "CM_UpdatePackages_Hist" -ZipFile $ZipName

	# CM_UpdatePackageSiteStatus
	$OutFile = Join-Path $Destination "CM_UpdatePackageSiteStatus.txt"
	Run-SQLCommandtoFile -SqlQuery "SELECT * FROM CM_UpdatePackageSiteStatus" -outFile $OutFile -DisplayText "CM_UpdatePackageSiteStatus" -ZipFile $ZipName
	Run-SQLCommandtoFile -SqlQuery "SELECT * FROM CM_UpdatePackageSiteStatus_HIST ORDER BY RecordTime DESC" -outFile $OutFile -DisplayText "CM_UpdatePackageSiteStatus_HIST" -ZipFile $ZipName

	# CM_UpdatePackageInstallationStatus
	$OutFile = Join-Path $Destination "CM_UpdatePackageInstallationStatus.txt"
	Run-SQLCommandtoFile -SqlQuery "SELECT * FROM CM_UpdatePackageInstallationStatus ORDER BY MessageTime DESC" -outFile $OutFile -DisplayText "CM_UpdatePackageInstallationStatus" -ZipFile $ZipName

	# CM_UpdateReadiness
	$OutFile = Join-Path $Destination "CM_UpdateReadiness.txt"
	Run-SQLCommandtoFile -SqlQuery "SELECT * FROM CM_UpdateReadiness" -outFile $OutFile -DisplayText "CM_UpdateReadiness" -ZipFile $ZipName
	Run-SQLCommandtoFile -SqlQuery "SELECT * FROM CM_UpdateReadinessSite ORDER BY LastUpdateTime DESC" -outFile $OutFile -DisplayText "CM_UpdateReadinessSite" -ZipFile $ZipName

	# CM_UpdatePackagePrereqStatus
	$OutFile = Join-Path $Destination "CM_UpdatePackagePrereqStatus.txt"
	Run-SQLCommandtoFile -SqlQuery "SELECT * FROM CM_UpdatePackagePrereqStatus" -outFile $OutFile -DisplayText "CM_UpdatePackagePrereqStatus" -ZipFile $ZipName

	# EasySetupSettings
	$OutFile = Join-Path $Destination "EasySetupSettings.txt"
	Run-SQLCommandtoFile -SqlQuery "SELECT * FROM EasySetupSettings" -outFile $OutFile -DisplayText "EasySetupSettings" -ZipFile $ZipName
	Run-SQLCommandtoFile -SqlQuery "SELECT PkgID, Name, SourceVersion, StoredPkgVersion, SourceSite, SourceSize, UpdateMask, Action, Source, StoredPkgPath, StorePkgFlag, ShareType, LastRefresh, PkgFlags, SourceDate, HashVersion FROM SMSPackages WHERE PkgID = (SELECT PackageID FROM EasySetupSettings)" -outFile $OutFile -DisplayText "EasySetup Package" -ZipFile $ZipName
	Run-SQLCommandtoFile -SqlQuery "SELECT * FROM PkgStatus WHERE Type = 1 AND ID = (SELECT PackageID FROM EasySetupSettings)" -outFile $OutFile -DisplayText "EasySetup Package Status" -ZipFile $ZipName

	# Compress and Collect
	compressCollectFiles -DestinationFileName $ZipName -filesToCollect ($Destination + "\*.*") -sectionDescription $sectionDescription -fileDescription "Update Servicing Data" -Recursive -ForegroundProcess -noFileExtensionsOnDescription
	Remove-Item -Path $Destination -Recurse -Force
}
else {
	TraceOut "    Update Servicing Data not collected because Site Build Number $global:SiteBuildNumber is less than 8325."
}

# ---------------------------
# Collect Server Information
# ---------------------------
# Moved to DC_FinishExecution

TraceOut "Completed"


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAbKrGDRy/mgbYc
# b665IWZi14AJzhrLvptAl4OdCRnhbaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIAmNRcxKo9tAqlCW2OxQoUsq
# 3hs8s66UjZL2dnYh1YLmMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBFLAhVcN0uXoEqDYfVbRK67R6CZKLo1mh8VOvUzdJlq3hgOCl+tKht
# AjDMnasCWn5dhVb3xwisKjRtl5988LPcLgUooR/93MdB+VjeES/hyqlcAFH05tNp
# JAGxUV5PrQkGvbgsY0Zn+11WF022EK2VTPOcmGGjeA/S6gYk+WCixwOVvoAyUtGo
# caEBC/UDlo3Ula6yYLkeHQzksJnpNTPKokA1+fPBF53HfQfj4f89VwEO6JIa7/Z1
# XmN4VmnK/XjdfDAwnMuFshD5I7nubN+/0OmrrPeYCceTbP9lanzEd82YcpAEqd8E
# gYgcJu9K7ACqQjySpjl9lmIf8UZkGv0IoYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIDQ1sv2FM1oIwwnI0kOrGKWCM3i3u47KkzmoquuMvBJpAgZi3ohP
# 3nsYEzIwMjIwODAxMDczNTUxLjQ5N1owBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
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
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIGpgKsZzpTCTxAHvTkAt
# rIxV7V/flA5Au51UPZ07z7n2MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# l3IFT+LGxguVjiKm22ItmO6dFDWW8nShu6O6g8yFxx8wgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY/zUajrWnLdzAABAAABjzAiBCDK
# yRgnJWWXshnmgygiJTZnJFpENKNV36rl3eKKIz0TKjANBgkqhkiG9w0BAQsFAASC
# AgAUL5VPYZC/rnE6eCs2dKoVF5xuWxTJolzG3zd2fdaGf7KNU3dS5IGruHyQvU92
# EWGYb9ekp1EFJxnPRJpSQOwF3HWpNDKV69thFn/4u1sFZMUIWybEoK+rHj8HWUEW
# t+usNjMn+HXdlcuF4CWSs6xNVMVmToFZjlo1gGu/JYju+amUMFCRkm6r7Vci1IR4
# USUE3NF76qvIWLip7gxjSHhBocAc9JQ52O6/n6O+JULzJHELMSVwOAd3EkeD/a1d
# iCG4P9gX3AY8xRn6KZRRwqoY7LOKdaaBTN4JolEdTmvysjjvH7VCc4akhFV54gKj
# hx/AP2tgvqMkhYbwSQcMzW0p7Z3AcU4Id4wU7H5h2RppdcS1J32pEsdFyWhKEjdt
# zxXaHB/JwYAkiUN9zKzQHurAwHbT7dyq8AV0Nc99CjdfuHMhDuxnGDlD9cyPS2zt
# 654bI1tz+k4FEWkPMAE3EgkwgvsBl4fCZi1grS5SRCxacB7hT33K0U6hxrlhFfs6
# oP7buXTVsMJUguis+xSiejhTHuGnBT6EKl4SqQtas/oGUgKoGGhryKs3+DYDHU9G
# tlhnl4p1ZrVjGffIlXdrsGKPKxvxDIy+5ObAHECqygPkcVEb3lhrjlvMUYpz/ryz
# aXn+x6x/cGf2+t7nwTXVNvOAj3FRvfYkysWvxGpEpZAxvw==
# SIG # End signature block
