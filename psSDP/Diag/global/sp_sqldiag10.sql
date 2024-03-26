PRINT 'NOTE:  It''s completely normal for some errors to be generated by this script'
GO

USE tempdb
GO
SET LANGUAGE us_english
GO
SET NOCOUNT ON
GO

IF OBJECT_ID('dbo.sp_sqldiag10','P') IS NOT NULL drop proc dbo.sp_sqldiag10
GO 
PRINT ''
RAISERROR ('===== Creating sp_sqldiag10', 0, 1) WITH NOWAIT
GO
CREATE PROC dbo.sp_sqldiag10 @bGetQueryStats int = 0 
AS

/*
PRINT 'Errorlogs'
PRINT '---------'

declare @i tinyint, @res int
set @i=0
while (@i<255) begin
	if (0=@i) begin
		print 'ERRORLOG'
		exec @res=master.dbo.xp_readerrorlog 
	end	else begin
		print 'ERRORLOG.'+cast(@i as varchar(3))
		exec @res=master.dbo.xp_readerrorlog @i
	end
	if (@@error<>0) OR (@res<>0) break
	set @i=@i+1
end
*/

PRINT ''

PRINT '-> sp_configure'
if (select value from sys.sysconfigures where config = 518) = 1 
begin
    exec sp_configure	
end
else 
begin
    exec sp_configure 'show advanced option',1 
    reconfigure with override
    exec sp_configure	
    exec sp_configure 'show advanced option',0 
    reconfigure with override
end

PRINT '-> sp_who'
exec sp_who
PRINT ''

PRINT '-> sp_lock'
exec sp_lock
PRINT ''

PRINT '-> sp_helpdb'
exec sp_helpdb
PRINT ''

PRINT '-> xp_msver'
exec master.dbo.xp_msver
PRINT ''

PRINT '-> sp_helpextendedproc'
exec sp_helpextendedproc
PRINT ''

PRINT '-> sysprocesses'
select * from sys.sysprocesses
PRINT ''

PRINT '-> sys.dm_exec_sessions'
select * from sys.dm_exec_sessions
PRINT ''

PRINT '-> ::fn_virtualservernodes()'
SELECT * FROM ::fn_virtualservernodes()
PRINT ''

PRINT '-> sysdevices'
select * from sys.sysdevices
PRINT ''

PRINT '-> sys.databases'
SELECT * from master.sys.databases
PRINT ''

PRINT '-> sys.master_files'
select * from sys.master_files
PRINT ''

--Input buffers
PRINT '-> Non-NULL input buffers by SPID'
SELECT 
p.spid,
(select SUBSTRING (REPLACE (REPLACE (text, char(13), ' '), char(10), ' '), 1, 8000) FROM sys.dm_exec_sql_text(p.sql_handle)) AS query_text 
FROM sys.sysprocesses p
WHERE p.spid>10 AND (select text FROM sys.dm_exec_sql_text(p.sql_handle)) IS NOT NULL
PRINT ''

--Query stats
PRINT '-> Stats for currently running queries'
select TOP 10000
    r.*, 
    t.dbid, 
    t.objectid, 
    t.encrypted,
    substring(t.text, statement_start_offset / 2, (case when statement_end_offset = -1 then datalength(t.text) else statement_end_offset end - statement_start_offset) / 2) as query_text
from sys.dm_exec_requests as r outer apply sys.dm_exec_sql_text(r.sql_handle) as t
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> Head blockers'
select *
from sys.sysprocesses 
where spid in (select blocked from sys.sysprocesses)
and blocked=0
PRINT ''

PRINT '-> SELECT @@version:'
PRINT @@VERSION
PRINT ''

PRINT '-> Current login (SUSER_SNAME):'
PRINT SUSER_SNAME ()
PRINT ''

PRINT '-> SQL Server name (@@SERVERNAME):'
PRINT @@SERVERNAME
PRINT ''

PRINT '-> Host (client) machine name (HOST_NAME):'
PRINT HOST_NAME()
PRINT ''

PRINT '-> @@LANGUAGE:'
PRINT @@LANGUAGE
PRINT ''

PRINT '-> DBCC TRACESTATUS (-1):'
DBCC TRACESTATUS (-1)
PRINT ''

PRINT '-> sys.dm_tran_database_transactions'
select TOP 10000 db_name(database_id), * from sys.dm_tran_database_transactions 
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_tran_active_transactions'
select TOP 10000 * from sys.dm_tran_active_transactions 
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''


PRINT '-> sys.dm_os_sys_info'
select TOP 10000 * from sys.dm_os_sys_info
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_os_schedulers'
select * from sys.dm_os_schedulers
PRINT ''

PRINT '-> sys.dm_os_threads'
select TOP 10000 * from sys.dm_os_threads
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_os_workers'
select TOP 10000 * from sys.dm_os_workers
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_os_tasks'
select TOP 10000 * from sys.dm_os_tasks
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_io_pending_io_requests'
select TOP 10000 * from sys.dm_io_pending_io_requests
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_io_virtual_file_stats'
SELECT TOP 10000 * FROM sys.dm_io_virtual_file_stats(NULL, NULL)
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_os_latch_stats'
select TOP 10000 * from sys.dm_os_latch_stats
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

-- New DMV in SQL Server 2008
PRINT '-> sys.dm_os_spinlock_stats'
select TOP 10000 * from sys.dm_os_spinlock_stats
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_os_sublatches'
select TOP 10000 * from sys.dm_os_sublatches
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_os_memory_pools'
select TOP 10000 * from sys.dm_os_memory_pools
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_os_memory_clerks'
select TOP 10000 * from sys.dm_os_memory_clerks
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

-- New DMV in SQL Server 2008
PRINT '-> sys.dm_os_memory_brokers'
select TOP 10000 * from sys.dm_os_memory_brokers
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

-- New DMV in SQL Server 2008
PRINT '-> sys.dm_os_memory_nodes'
select TOP 10000 * from sys.dm_os_memory_nodes
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_os_wait_stats'
select TOP 10000 * from sys.dm_os_wait_stats
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_os_waiting_tasks'
select TOP 10000 * from sys.dm_os_waiting_tasks
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_os_loaded_modules'
select TOP 10000 * from sys.dm_os_loaded_modules
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_os_cluster_nodes'
select * from sys.dm_os_cluster_nodes
PRINT ''

-- New DMV in SQL Server 2008
PRINT '-> sys.dm_os_nodes'
select TOP 10000 * from sys.dm_os_nodes
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

-- New DMV in SQL Server 2008
PRINT '-> sys.dm_os_process_memory'
select TOP 10000 * from sys.dm_os_process_memory
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

-- New DMV in SQL Server 2008
PRINT '-> sys.dm_os_sys_memory'
select TOP 10000 * from sys.dm_os_sys_memory
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_io_cluster_shared_drives'
select TOP 10000 * from sys.dm_io_cluster_shared_drives
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

/*
PRINT '-> sys.dm_clr_appdomains'
select TOP 10000 * from sys.dm_clr_appdomains
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_clr_loaded_assemblies'
select TOP 10000 * from sys.dm_clr_loaded_assemblies
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_clr_properties'
select TOP 10000 * from sys.dm_clr_properties
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_clr_tasks'
select TOP 10000 * from sys.dm_clr_tasks
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.assemblies'
select TOP 10000 * from sys.assemblies
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.assembly_modules'
select TOP 10000 * from sys.assembly_modules
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.assembly_types'
select TOP 10000 * from sys.assembly_types
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''
*/

PRINT '-> sys.database_files'
select TOP 10000 * from sys.database_files 
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_db_file_space_usage'
select TOP 10000 * from sys.dm_db_file_space_usage
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_db_session_space_usage'
select TOP 10000 * from sys.dm_db_session_space_usage
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_db_task_space_usage'
select TOP 10000 * from sys.dm_db_task_space_usage
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_exec_query_optimizer_info'
select TOP 10000 * from sys.dm_exec_query_optimizer_info
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

-- New DMV in SQL Server 2008
PRINT '-> sys.dm_exec_query_memory_grants'
select TOP 10000 * from sys.dm_exec_query_memory_grants
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

-- New DMV in SQL Server 2008
PRINT '-> sys.dm_exec_query_resource_semaphores'
select TOP 10000 * from sys.dm_exec_query_resource_semaphores
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

-- New DMV in SQL Server 2008
PRINT '-> sys.dm_exec_query_transformation_stats'
select TOP 10000 * from sys.dm_exec_query_transformation_stats
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_broker_activated_tasks'
select TOP 10000 * from sys.dm_broker_activated_tasks
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_broker_connections'
select TOP 10000 * from sys.dm_broker_connections
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

PRINT '-> sys.dm_broker_queue_monitors'
select TOP 10000 * from sys.dm_broker_queue_monitors
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

-- New DMV in SQL Server 2008
PRINT '-> sys.dm_resource_governor_configuration'
select TOP 10000 * from sys.dm_resource_governor_configuration
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

-- New DMV in SQL Server 2008
PRINT '-> sys.dm_resource_governor_resource_pools'
select TOP 10000 * from sys.dm_resource_governor_resource_pools
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

-- New DMV in SQL Server 2008
PRINT '-> sys.dm_resource_governor_workload_groups'
select TOP 10000 * from sys.dm_resource_governor_workload_groups
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

-- New DMV in SQL Server 2008
PRINT '-> sys.dm_database_encryption_keys'
select TOP 10000 * from sys.dm_database_encryption_keys
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

-- New DMV in SQL Server 2008
PRINT '-> sys.dm_filestream_file_io_handles'
select TOP 10000 * from sys.dm_filestream_file_io_handles
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

-- New DMV in SQL Server 2008
PRINT '-> sys.dm_filestream_file_io_requests'
select TOP 10000 * from sys.dm_filestream_file_io_requests
IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
PRINT ''

-- This is potentially too large to capture by default. 
IF @bGetQueryStats = 1
BEGIN
  PRINT '-> sys.dm_exec_query_stats'
  SELECT TOP 10000 * FROM sys.dm_exec_query_stats 
  IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
  PRINT ''
END

PRINT '-> sysperfinfo snapshot #1'
PRINT CONVERT (varchar, GETDATE(), 109)
SELECT * FROM sys.sysperfinfo
WAITFOR DELAY '0:0:05'
PRINT '-> sysperfinfo snapshot #2'
PRINT CONVERT (varchar, GETDATE(), 109)
SELECT * FROM sys.sysperfinfo
PRINT ''

DECLARE @IsFullTextInstalled int
PRINT '-> Full-text information'
PRINT '-> FULLTEXTSERVICEPROPERTY (IsFulltextInstalled)'
SET @IsFullTextInstalled = FULLTEXTSERVICEPROPERTY ('IsFulltextInstalled')
PRINT CASE @IsFullTextInstalled 
    WHEN 1 THEN '1 - Yes' 
    WHEN 0 THEN '0 - No' 
    ELSE 'Unknown'
  END
IF (@IsFullTextInstalled = 1)
BEGIN
  PRINT '-> FULLTEXTSERVICEPROPERTY (ResourceUsage)'
  PRINT CASE FULLTEXTSERVICEPROPERTY ('ResourceUsage')
      WHEN 0 THEN '0 - MSSearch not running'
      WHEN 1 THEN '1 - Background'
      WHEN 2 THEN '2 - Low'
      WHEN 3 THEN '3 - Normal'
      WHEN 4 THEN '4 - High'
      WHEN 5 THEN '5 - Highest'
      ELSE CONVERT (varchar, FULLTEXTSERVICEPROPERTY ('ResourceUsage'))
    END

  PRINT '-> FULLTEXTSERVICEPROPERTY (ConnectTimeout)'
  PRINT CONVERT (varchar, FULLTEXTSERVICEPROPERTY ('ConnectTimeout')) + ' sec'
  PRINT ''

  PRINT '-> sys.dm_fts_active_catalogs'
  select TOP 10000 * from sys.dm_fts_active_catalogs
  IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
  PRINT ''

  PRINT '-> sys.dm_fts_index_population'
  select TOP 10000 * from sys.dm_fts_index_population
  IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
  PRINT ''

  PRINT '-> sys.dm_fts_memory_pools'
  select TOP 10000 * from sys.dm_fts_memory_pools
  IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
  PRINT ''

  PRINT '-> sys.dm_fts_population_ranges'
  select TOP 10000 * from sys.dm_fts_population_ranges
  IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
  PRINT ''

  PRINT '-> msdb..suspect_pages'
  select TOP 10000 * from msdb..suspect_pages
  IF @@rowcount >= 10000 PRINT '<<<<< LIMIT OF 10000 ROWS EXCEEDED, SOME RESULTS NOT SHOWN >>>>>'
  PRINT ''

  DECLARE @dbn varchar(31)
  DECLARE @cm varchar(8000)
  DECLARE db_cursor CURSOR FOR
  SELECT name FROM master.dbo.sysdatabases WHERE DATABASEPROPERTYEX (name, 'IsFulltextEnabled') = 1
  FOR READ ONLY
  IF 0 = @@ERROR
  BEGIN
    OPEN db_cursor
    IF 0 = @@ERROR
    BEGIN
      FETCH db_cursor INTO @dbn
      WHILE @@FETCH_STATUS <> -1 AND 0 = @@ERROR
      BEGIN
        SELECT @cm = '
USE ' + + @dbn + '
PRINT ''-> sp_help_fulltext_catalogs''
EXEC sp_help_fulltext_catalogs
PRINT ''-> sp_help_fulltext_tables''
EXEC sp_help_fulltext_tables
PRINT ''-> sp_help_fulltext_columns''
EXEC sp_help_fulltext_columns
PRINT ''-> Catalog properties''
SELECT name, FULLTEXTCATALOGPROPERTY (name, ''ItemCount'') AS ItemCount, 
  CONVERT (varchar, FULLTEXTCATALOGPROPERTY (name, ''IndexSize'')) + ''MB'' AS IndexSize, 
  FULLTEXTCATALOGPROPERTY (name, ''UniqueKeyCount'') AS [Unique word count] 
FROM sysfulltextcatalogs 
USE tempdb'
        PRINT '-> Full text information for db [' + @dbn + ']'
        EXEC(@cm)
        FETCH db_cursor INTO @dbn
      END
      CLOSE db_cursor
    END
    DEALLOCATE db_cursor
  END
END
PRINT ''

PRINT '-> Relative time spent on I/O, CPU, and idle since server start'
SELECT @@CPU_BUSY AS [@@CPU_BUSY], @@IDLE AS [@@IDLE], @@IO_BUSY AS [@@IO_BUSY], 
  CONVERT (varchar(8), CONVERT (numeric (6, 4), (100.0 * @@CPU_BUSY / (@@CPU_BUSY + @@IDLE + @@IO_BUSY)))) + '%' AS Pct_CPU_BUSY, 
  CONVERT (varchar(8), CONVERT (numeric (6, 4), (100.0 * @@IDLE / (@@CPU_BUSY + @@IDLE + @@IO_BUSY)))) + '%' AS Pct_IDLE, 
  CONVERT (varchar(8), CONVERT (numeric (6, 4), (100.0 * @@IO_BUSY / (@@CPU_BUSY + @@IDLE + @@IO_BUSY)))) + '%' AS Pct_IO_BUSY
PRINT ''

PRINT '-> Misc network and I/O stats'
SELECT @@PACK_RECEIVED AS [@@PACK_RECEIVED], @@PACK_SENT AS [@@PACK_SENT], 
  @@PACKET_ERRORS AS [@@PACKET_ERRORS (network errors e.g. 17824)]
SELECT @@TOTAL_READ AS [@@TOTAL_READ], @@TOTAL_WRITE AS [@@TOTAL_WRITE], 
  @@TOTAL_ERRORS AS [@@TOTAL_ERRORS (disk read/write I/O errors)] 
PRINT ''

PRINT '-> GETDATE()'
PRINT CONVERT (varchar, GETDATE(), 109)
PRINT ''
PRINT 'Done.'
GO

/*
The board chagned the Product Version format in Katmai. The current foramt starting from Katmai will be single zero for minor version instead of two zeros in previous sql versions. " 10.m.bbbb.rr "
*/
IF (CHARINDEX('10.0.',@@VERSION)<>0) AND (OBJECT_ID('dbo.sp_sqldiag10','P') IS NULL) 
	RAISERROR('Error creating sp_sqldiag10',16,127)
ELSE
	EXEC sp_sqldiag10	
GO

