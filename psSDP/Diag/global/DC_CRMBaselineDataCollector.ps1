#**************************************************************************
# DC_CRMBaselineDataCollector.ps1
# Version 1.0
# Date: 07-27-2010
# Author: Jonathan Randall
# Description: Collects Microsoft Dynamics CRM Configuration Information
#**************************************************************************
# Date: 10-06-2010
# Description: Fixing issue with incorrect SQL Server name when SQL is installed on separate machine
#**************************************************************************
# Date: 12-06-2011
# Description: Updating Baseline script to change report to HTML as well as handle Dynamics CRM 2011
#******************************************************************************************************
# Date 01-03-2012
# Description:  Added query for collecting AsyncOperation Types and Statuses
#*************************************************************************************************************
# Date: 10-01-2012
# Description: Implementation of Rule Id: 5200 - Include Database Version of Organizations in Organization Information
#********************************************************************************************************************
# Date: 11-12-2012
# Description: Modified script to be more fault tolerant and to work with Windows Server 2012 once CRM supports it
#*********************************************************************************************************************
# Last Modified: 2023-02-18 by #we#
#*********************************************************************************************************************

#region Baseline Collection Functions
##############################################################################################################
#						FUNCTIONS
##############################################################################################################
function Get-CustomCRMHTML ($Header){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$Report = @"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN" "http://www.w3.org/TR/html4/frameset.dtd">
<html><head><title>$($Header)</title>
<META http-equiv=Content-Type content='text/html; charset=utf8'>

<meta name="save" content="history">

<style type="text/css">
DIV .expando {DISPLAY: block; FONT-WEIGHT: normal; FONT-SIZE: 8pt; RIGHT: 8px; COLOR: #ffffff; FONT-FAMILY: Segoe UI; POSITION: absolute; TEXT-DECORATION: underline}
TABLE {TABLE-LAYOUT: auto; FONT-SIZE: 100%; WIDTH: 100%; white-space:normal;}
*{margin:0}
.dspcont { display:none; BORDER-RIGHT: #B1BABF 1px solid; BORDER-TOP: #B1BABF 1px solid; PADDING-LEFT: 16px; FONT-SIZE: 8pt;MARGIN-BOTTOM: -1px; PADDING-BOTTOM: 5px; MARGIN-LEFT: 0px; BORDER-LEFT: #B1BABF 1px solid; WIDTH: 95%; COLOR: #000000; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #B1BABF 1px solid; FONT-FAMILY: Segoe UI; POSITION: relative; BACKGROUND-COLOR: #f9f9f9}
.filler {BORDER-RIGHT: medium none; BORDER-TOP: medium none; DISPLAY: block; BACKGROUND: none transparent scroll repeat 0% 0%; MARGIN-BOTTOM: -1px; FONT: 100%/8px Segoe UI; MARGIN-LEFT: 43px; BORDER-LEFT: medium none; COLOR: #ffffff; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: medium none; POSITION: relative}
.save{behavior:url(#default#savehistory);}
.dspcont1{ display:none}
a.dsphead0 {BORDER-RIGHT: #B1BABF 1px solid; PADDING-RIGHT: 5em; BORDER-TOP: #B1BABF 1px solid; DISPLAY: block; PADDING-LEFT: 5px; FONT-WEIGHT: bold; FONT-SIZE: 11pt; MARGIN-BOTTOM: -1px; MARGIN-LEFT: 0px; BORDER-LEFT: #B1BABF 1px solid; CURSOR: hand; COLOR: #FFFFFF; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #B1BABF 1px solid; FONT-FAMILY: Segoe UI Semibold; POSITION: relative; HEIGHT: 2.25em; WIDTH: 95%; BACKGROUND-COLOR: #CC0000}
a.dsphead1 {BORDER-RIGHT: #B1BABF 1px solid; PADDING-RIGHT: 5em; BORDER-TOP: #B1BABF 1px solid; DISPLAY: block; PADDING-LEFT: 5px; FONT-WEIGHT: bold; FONT-SIZE: 11pt; MARGIN-BOTTOM: -1px; MARGIN-LEFT: 0px; BORDER-LEFT: #B1BABF 1px solid; CURSOR: hand; COLOR: #ffffff; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #B1BABF 1px solid; FONT-FAMILY: Segoe UI Semibold; POSITION: relative; HEIGHT: 2.25em; WIDTH: 95%; BACKGROUND-COLOR: #7BA7C7}
a.dsphead2 {BORDER-RIGHT: #B1BABF 1px solid; PADDING-RIGHT: 5em; BORDER-TOP: #B1BABF 1px solid; DISPLAY: block; PADDING-LEFT: 5px; FONT-WEIGHT: bold; FONT-SIZE: 11pt; MARGIN-BOTTOM: -1px; MARGIN-LEFT: 0px; BORDER-LEFT: #B1BABF 1px solid; CURSOR: hand; COLOR: #ffffff; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #B1BABF 1px solid; FONT-FAMILY: Segoe UI Semibold; POSITION: relative; HEIGHT: 2.25em; WIDTH: 95%; BACKGROUND-COLOR: #7BA7C7}
a.dsphead1 span.dspchar{font-family:monospace;font-weight:normal;}
th {VERTICAL-ALIGN: TOP; FONT-FAMILY: Segoe UI Semibold; COLOR: #CC0000; TEXT-ALIGN: left}
BODY {margin-left: 4pt} 
BODY {margin-right: 4pt} 
BODY {margin-top: 6pt} 
BODY {font-family: "Segoe UI"}
DIV .Notifications {background-color: #ececec; border: 1px solid #c5c5c5; padding: 2px; overflow:auto;font-family:Segoe UI; FONT-SIZE: 9pt;}
</style>

<script type="text/javascript">
function dsp(loc){
   if(document.getElementById){
      var foc=loc.firstChild;
      foc=loc.firstChild.innerHTML?
         loc.firstChild:
         loc.firstChild.nextSibling;
      foc.innerHTML=foc.innerHTML=='hide'?'show':'hide';
      foc=loc.parentNode.nextSibling.style?
         loc.parentNode.nextSibling:
         loc.parentNode.nextSibling.nextSibling;
      foc.style.display=foc.style.display=='block'?'none':'block';}}  

if(!document.getElementById)
   document.write('<style type="text/css">\n'+'.dspcont{display:block;}\n'+ '</style>');
</script>

</head>
<body>
<font face="Segoe UI Semibold" size="5">$($Header)</font><hr size="6" color="#d6e8ff">
<font face="Segoe UI Semibold" size="2">Version 1.07  | Microsoft Dynamics CRM Support</font><br>
<font face="Segoe UI Light" size="1">Report created on $(Get-Date)</font>
<div class="filler"></div>
<div class="filler"></div>
<div class="filler"></div>
<div class="save">

"@
	Return $Report
}
function GetSubKeys($regKey){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	if ($regKey.SubKeyCount -ne 0){
		$colSubKeys = $regKey.GetSubKeyNames()
		foreach ($subKey in $colSubKeys){
			$sk = $regKey.OpenSubKey($subKey)
			if ($sk -ne $null){
				GetSubKeys $sk
			}
		}
	}else{
		if ($regKey -ne $null){
			$tempstring += Get-Header "2" $regKey.Name
			foreach ($prop in $regKey.GetValueNames()){
				$tempstring += Get-HTMLDetail $prop $regKey.GetValue($prop)
			} 
			$tempstring += Get-HeaderClose
		}
	}
	return $tempstring
}
function GetIISVersion(){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}	
    if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters){
	  $parameters = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters
      $majorVersion = $parameters.MajorVersion
	  return $majorVersion;
	}else{
	   return $null
	}
}
function GetAuthFlagsText([int]$authflag){
	switch($authflag){
	   1 {return "Anonymous Access Authentication Method is being used.";break}
	   2 {return "Basic Authentication Method is being used.";break}
	   3 {return "Anonymous and Basic Authentication methods are being used.";break}
	   4 {return "Integrated Windows Authentication Method is being used.";break}
	   5 {return "Anonymous and Integrated Windows Authentication methods are being used.";break}
	   6 {return "Basic and Integrated Windows Authentication methods are being used.";break}
	   7 {return "Anonymous, Basic, and Integrated Windows Authentication methods are being used.";break}
	   10 {return "Digest Authentication Method is being used";break}
	   11 {return "Anonymous and Digest Authentication methods are being used.";break}
	   12 {return "Basic and Digest Authentication methods are being used.";break}
	   13 {return "Anonymous,Basic,and Digest Authentication methods are being used.";break}
	   15 {return "Anonymous, Digest, and Integrated Windows Authentication methods are being used.";break}
	   16 {return "Basic, Digest, and Integrated Windows Authentication methods are being used.";break}
	   17 {return "Anonymous,Basic,Digest, and Integrated Windows Authentication is being used.";break}
	   20 {return "Digest and Integrated Windows Authentication methods are being used.";break}
	   default {return "Unknown AuthFlag";break}
	}
}

Function Convert-ToProperties ($p){
    $p.Split(';') | % {
      $key, $value = $_.split('=')
      $p = $p |
       Add-Member -PassThru Noteproperty ($key -Replace " ", "") $value
    }
    $p
} 

function checkinstance([string] $servername){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = "Server=$servername;Database=master;Integrated Security=True"
	$SqlCmd.CommandText = "
create table #serverproperty (Property varchar(100), 
  Value varchar(100))
insert into #serverproperty values
  ('MachineName',convert(varchar(100),
  SERVERPROPERTY ('Machinename')))
insert into #serverproperty values
  ('Servername',convert(varchar(100),
  SERVERPROPERTY ('ServerName') ))
insert into #serverproperty values
  ('InstanceName',convert(varchar(100),
  SERVERPROPERTY ('ServerName') ))
insert into #serverproperty values
  ('Edition',convert(varchar(100),SERVERPROPERTY ('Edition')  ))
insert into #serverproperty values
  ('EngineEdition',convert(varchar(100),
  SERVERPROPERTY ('EngineEdition'))  )
insert into #serverproperty values
  ('BuildClrVersion',convert(varchar(100),
  SERVERPROPERTY ('Buildclrversion'))  )
insert into #serverproperty values
  ('Collation', convert(varchar(100),SERVERPROPERTY ('Collation'))  )
insert into #serverproperty values
  ('ProductLevel',convert(varchar(100),
  SERVERPROPERTY ('ProductLevel')) )
insert into #serverproperty values
  ('IsClustered',convert(varchar(100),SERVERPROPERTY ('IsClustered') ))
insert into #serverproperty values
  ('IsFullTextInstalled',convert(varchar(100),SERVERPROPERTY 
  ('IsFullTextInstalled ') ))
insert into #serverproperty values
  ('IsSingleuser',convert(varchar(100),
  SERVERPROPERTY ('IsSingleUser ') ))
set nocount on
select * from #serverproperty
drop table #serverproperty
"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$DataSet.Tables[0]
	$SqlConnection.Close()
}

function checkconfiguration([string] $servername){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = "Server=$servername;Database=master;Integrated Security=True"
	$SqlCmd.CommandText = "
	exec master.dbo.sp_configure 'show advanced options',1  
	reconfigure
	"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlCmd.CommandText = "
	set nocount on
	create table #config (name varchar(100), minimum bigint, maximum bigint, config_value bigint, run_value bigint)
	insert #config exec ('master.dbo.sp_configure')
	set nocount on
	select * from #config as mytable
	drop table #config
	"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	$DataSet.Tables[0].rows
}

function getsqlversion([string] $servername){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = "Server=$servername;Database=master;Integrated Security=True"
	$SqlCmd.CommandText="SELECT @@Version"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	$DataSet.Tables[0].rows
}

function GetOrganizationData([string] $conn_string){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = $conn_string
	$SqlCmd.CommandText = "SELECT * FROM Organization"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	$DataSet.Tables[0].rows
}

function GetServerTableData([string] $conn_string){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = $conn_string
	$SqlCmd.CommandText = "SELECT *,'ServerRoles' As ServerRoles FROM Server"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	foreach($dr in $DataSet.Tables[0].rows)
	{
		$dr.ServerRoles = convert_role_mask $dr.Roles
	}
	$DataSet.Tables[0].rows
}

function GetV4ServerTableData([string] $conn_string){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = $conn_string
	$SqlCmd.CommandText = "SELECT *,'ServerRoles' As ServerRoles FROM Server"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	foreach($dr in $DataSet.Tables[0].rows)
	{
		$dr.ServerRoles = convert_role_mask $dr.Roles
	}
	$DataSet.Tables[0].rows
}

function GetConfigSettingsTableData([string] $conn_string){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = $conn_string
	$SqlCmd.CommandText = "SELECT * FROM ConfigSettings"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	$DataSet.Tables[0].rows
}

function GetDeploymentPropertiesTableData([string] $conn_string){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = $conn_string
	$SqlCmd.CommandText = "SELECT ColumnName, IntColumn, BitColumn, FloatColumn, NVarCharColumn FROM DeploymentProperties"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	$DataSet.Tables[0]
}


function GetADGroupMemberShip([string] $conn_string){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = $conn_string
	$SqlCmd.CommandText = "SELECT * From ConfigSettings"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	$DataSet.Tables[0]
}

function GetDirectoryEntry([string] $strGUID){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	if ($strGUID -ne $null){
		return New-Object DirectoryServices.DirectoryEntry("LDAP://<GUID=" + $strGUID +">")
	}
	else{
		return $null
	}
}
function GetOrganizations(){
	param ([string] $conn_string, [switch] $selectActive)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = $conn_string
	if ($selectActive){
		$SqlCmd.CommandText = "SET NOCOUNT ON;SELECT DatabaseName,FriendlyName,ConnectionString FROM Organization WHERE State='1'"
	}else{
		$SqlCmd.CommandText = "SET NOCOUNT ON;SELECT DatabaseName,FriendlyName,ConnectionString FROM Organization"
	}
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	$DataSet.Tables[0]
}
function GetBuildNumber{
	param (
		[string] $orgid,
		[string] $connstring)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = $connstring
	$SqlCmd.CommandText = "SELECT IntColumn FROM OrganizationProperties WHERE ColumnName='BuildNumber' AND id='$($orgid)'"
	$SqlCmd.Connection = $SqlConnection
	$SqlConnection.Open()			
	$buildNumber=$SqlCmd.ExecuteScalar()
	$SqlCmd.CommandText = "SELECT IntColumn FROM OrganizationProperties WHERE ColumnName='MajorVersion'  AND id='$($orgid)'"
	$majorVersion = $SqlCmd.ExecuteScalar()
	$SqlCmd.CommandText = "SELECT IntColumn FROM OrganizationProperties WHERE ColumnName='MinorVersion'  AND id='$($orgid)'"
	$minorVersion = $SqlCmd.ExecuteScalar()
	$SqlCmd.CommandText = "SELECT IntColumn FROM OrganizationProperties WHERE ColumnName='Revision'  AND id='$($orgid)'"
	$revision = $SqlCmd.ExecuteScalar()
	$SqlConnection.Close()
	$databaseVersion = [System.String]::Format("{0}.{1}.{2}.{3}",$majorVersion,$minorVersion,$buildNumber,$revision)
	return $databaseVersion
}

function GetTopTableRowCounts([string] $conn_string){
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = $conn_string
	$SqlCmd.CommandText = "SELECT TOP 10 OBJECT_NAME(id) as TableName,rowcnt As 'RowCount' FROM sysindexes WHERE indid < 2 AND OBJECTPROPERTY(id, 'IsUserTable') = 1 order by rowcnt desc"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	$DataSet.Tables[0].rows
}
function GetV4TopTableRowCounts([string] $conn_string){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$SqlConnection = New-Object System.Data.OleDb.OleDbConnection
	$SqlCmd = New-Object System.Data.OleDb.OleDbCommand
	$SqlAdapter = New-Object System.Data.OleDb.OleDbDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = $conn_string
	$SqlCmd.CommandText = "SELECT TOP 10 OBJECT_NAME(id) as TableName,rowcnt As 'RowCount' FROM sysindexes WHERE indid < 2 AND OBJECTPROPERTY(id, 'IsUserTable') = 1 order by rowcnt desc"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	$DataSet.Tables[0].rows
}
function GetTableSizes([string] $conn_string){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = $conn_string
	$SqlCmd.CommandText = "SELECT 
so.object_id AS ObjectID,
so.name AS ObjectName,        
(CONVERT(decimal(20,4),(SUM (ps.reserved_page_count) * 8))) / 1024 As Reserved_MB,
(CONVERT(decimal(20,4),SUM (
            CASE
                  WHEN (ps.index_id < 2) THEN (ps.in_row_data_page_count + ps.lob_used_page_count + ps.row_overflow_used_page_count)
                  ELSE ps.lob_used_page_count + ps.row_overflow_used_page_count
            END
            ) * 8)) / 1024 As Data_MB,
(CONVERT(decimal(20,4),(CASE WHEN (SUM(used_page_count)) > 
            (SUM(CASE
                  WHEN (ps.index_id < 2) THEN (ps.in_row_data_page_count + ps.lob_used_page_count + ps.row_overflow_used_page_count)
                  ELSE ps.lob_used_page_count + ps.row_overflow_used_page_count
            END
            )) THEN (SUM(used_page_count) -           
            (SUM(CASE
                  WHEN (ps.index_id < 2) THEN (ps.in_row_data_page_count + ps.lob_used_page_count + ps.row_overflow_used_page_count)
                  ELSE ps.lob_used_page_count + ps.row_overflow_used_page_count
            END
            ))) ELSE 0 END) * 8)) / 1024 As Index_MB,
(SUM (
            CASE
                  WHEN (ps.index_id < 2) THEN ps.row_count
                  ELSE 0
            END
            )) AS [RowCount]
FROM sys.dm_db_partition_stats AS ps
INNER JOIN sys.objects AS so ON so.object_id = ps.object_id
WHERE so.object_id > 100 
GROUP BY so.object_id, so.name
ORDER BY [Reserved_MB]Desc"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	$DataSet.Tables[0].rows
}
function GetV4TableSizes([string] $conn_string){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$SqlConnection = New-Object System.Data.OleDb.OleDbConnection
	$SqlCmd = New-Object System.Data.OleDb.OleDbCommand
	$SqlAdapter = New-Object System.Data.OleDb.OleDbDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = $conn_string
	$SqlCmd.CommandText = "SELECT 
so.object_id AS ObjectID,
so.name AS ObjectName,        
(CONVERT(decimal(20,4),(SUM (ps.reserved_page_count) * 8))) / 1024 As Reserved_MB,
(CONVERT(decimal(20,4),SUM (
            CASE
                  WHEN (ps.index_id < 2) THEN (ps.in_row_data_page_count + ps.lob_used_page_count + ps.row_overflow_used_page_count)
                  ELSE ps.lob_used_page_count + ps.row_overflow_used_page_count
            END
            ) * 8)) / 1024 As Data_MB,
(CONVERT(decimal(20,4),(CASE WHEN (SUM(used_page_count)) > 
            (SUM(CASE
                  WHEN (ps.index_id < 2) THEN (ps.in_row_data_page_count + ps.lob_used_page_count + ps.row_overflow_used_page_count)
                  ELSE ps.lob_used_page_count + ps.row_overflow_used_page_count
            END
            )) THEN (SUM(used_page_count) -           
            (SUM(CASE
                  WHEN (ps.index_id < 2) THEN (ps.in_row_data_page_count + ps.lob_used_page_count + ps.row_overflow_used_page_count)
                  ELSE ps.lob_used_page_count + ps.row_overflow_used_page_count
            END
            ))) ELSE 0 END) * 8)) / 1024 As Index_MB,
(SUM (
            CASE
                  WHEN (ps.index_id < 2) THEN ps.row_count
                  ELSE 0
            END
            )) AS [RowCount]
FROM sys.dm_db_partition_stats AS ps
INNER JOIN sys.objects AS so ON so.object_id = ps.object_id
WHERE so.object_id > 100 
GROUP BY so.object_id, so.name
ORDER BY [Reserved_MB]Desc"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	$DataSet.Tables[0].rows
}
function GetPluginData(){
	param ([string] $conn_string, [switch]$isV4)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	if ($isV4){
		$SqlConnection = New-Object System.Data.OleDb.OleDbConnection
		$SqlCmd = New-Object System.Data.OleDb.OleDbCommand
		$SqlAdapter = New-Object System.Data.OleDb.OleDbDataAdapter
		$DataSet = New-Object System.Data.DataSet
	}else{
		$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
		$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
		$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
		$DataSet = New-Object System.Data.DataSet
	}
	$SqlConnection.ConnectionString = $conn_string
	$SqlCmd.CommandText = "SET NOCOUNT ON;SELECT pt.TypeName, pt.IsWorkflowActivity, smps.Description, smps.Stage, smps.Mode, smps.SupportedDeployment,smps.InvocationSource,e.Name AS 'EntityName', sm.Name AS 'MessageName' FROM PluginType pt
			LEFT OUTER JOIN SdkMessageProcessingStep smps on pt.PluginTypeId = smps.PluginTypeId
			LEFT OUTER JOIN SdkMessageFilter sf ON sf.SdkMessageFilterId = smps.SdkMessageFilterId
			LEFT OUTER JOIN SdkMessage sm ON sm.SdkMessageId = sf.SdkMessageId
			LEFT OUTER JOIN EntityView e ON sf.PrimaryObjectTypeCode = e.ObjectTypeCode
			WHERE pt.TypeName = 'Microsoft.Crm.Extensibility.V3CalloutProxyPlugin' OR pt.PublicKeyToken <> '31bf3856ad364e35'
			Group BY pt.TypeName, sm.Name, e.Name, smps.Stage, smps.Mode, smps.SupportedDeployment,smps.Description,smps.InvocationSource,pt.IsWorkflowActivity"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	$DataSet.Tables[0].rows
}
function GetV4PluginData([string] $conn_string){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$SqlConnection = New-Object System.Data.OleDb.OleDbConnection
	$SqlCmd = New-Object System.Data.OleDb.OleDbCommand
	$SqlAdapter = New-Object System.Data.OleDb.OleDbDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = $conn_string
	$SqlCmd.CommandText = "SELECT pt.TypeName, pt.IsWorkflowActivity, smps.Description, smps.Stage, smps.Mode, smps.SupportedDeployment,smps.InvocationSource,e.Name AS 'EntityName', sm.Name AS 'MessageName' FROM PluginType pt
			LEFT OUTER JOIN SdkMessageProcessingStep smps on pt.PluginTypeId = smps.PluginTypeId
			LEFT OUTER JOIN SdkMessageFilter sf ON sf.SdkMessageFilterId = smps.SdkMessageFilterId
			LEFT OUTER JOIN SdkMessage sm ON sm.SdkMessageId = sf.SdkMessageId
			LEFT OUTER JOIN EntityView e ON sf.PrimaryObjectTypeCode = e.ObjectTypeCode
			WHERE pt.TypeName = 'Microsoft.Crm.Extensibility.V3CalloutProxyPlugin' OR pt.PublicKeyToken <> '31bf3856ad364e35'
			Group BY pt.TypeName, sm.Name, e.Name, smps.Stage, smps.Mode, smps.SupportedDeployment,smps.Description,smps.InvocationSource,pt.IsWorkflowActivity"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	$DataSet.Tables[0].rows
}
function GetAsyncOperationTypes([string] $conn_string){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = $conn_string
	$SqlCmd.CommandText = "SELECT 
CASE OperationType
        WHEN 2 THEN 'BulkEmail'
        WHEN 3 THEN 'Parse'
        WHEN 4 THEN 'Transform'
        WHEN 5 THEN 'Import'
        WHEN 6 THEN 'ActivityPropagation'
        WHEN 7 THEN 'PublishDuplicateRule'
        WHEN 8 THEN 'BulkDetectDuplicates'
        WHEN 9 THEN 'CollectSqmData'
        WHEN 10 THEN 'Workflow'
        WHEN 11 THEN 'QuickCampaign'
        WHEN 12 THEN 'PersistMatchCode'
		WHEN 13 THEN 'BulkDelete'
		WHEN 14 THEN 'DeletionService'
		WHEN 15 THEN 'IndexManagement'
		WHEN 16 THEN 'CollectOrgStats'
		WHEN 17 THEN 'ImportingFile'
		WHEN 18 THEN 'CalculateOrgStorageSize'
		WHEN 19 THEN 'CollectOrgDbStats'
		WHEN 20 THEN 'CollectOrgSizeStats'
		WHEN 21 THEN 'Database Tuning'
		WHEN 22 THEN 'CalculateOrgMaxStorageSize'
		WHEN 23 THEN 'BulkDeleteChild'
		WHEN 24 THEN 'UpdateStatisticIntervals'
		WHEN 25 THEN 'FullTextCatalogIndex'
		WHEN 26 THEN 'DatabaseLogBackup'
		WHEN 27 THEN 'UpdateContractStates'
		WHEN 28 THEN 'ShrinkDatabase'
		WHEN 29 THEN 'ShrinkLogFile'
		WHEN 30 THEN 'ReindexAll'
		WHEN 31 THEN 'StorageLimitNotification'
		WHEN 32 THEN 'CleanupInactiveWorkflowAssemblies'
		WHEN 38 THEN 'ImportSampleData'
		ELSE 'Other'
	END
AS OperationType, 
 
 CASE StatusCode
    WHEN 0 THEN 'Waiting For Resources'
    WHEN 10 THEN 'Waiting'
    WHEN 20 THEN 'In Progress'
    WHEN 21 THEN 'Pausing'
    WHEN 22 THEN 'Cancelling'
    WHEN 30 THEN 'Succeeded'
    WHEN 31 THEN 'Failed'
    WHEN 32 THEN 'Cancelled'	
    ELSE 'Other'
 END AS StatusCode, COUNT(*) AS Total
FROM AsyncOperationBase 
GROUP BY OperationType, StatusCode
ORDER BY Total desc"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	$DataSet.Tables[0].rows
}
function GetV4AsyncOperationTypes([string] $conn_string){
	$SqlConnection = New-Object System.Data.OleDb.OleDbConnection
	$SqlCmd = New-Object System.Data.OleDb.OleDbCommand
	$SqlAdapter = New-Object System.Data.OleDb.OleDbDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = $conn_string
	$SqlCmd.CommandText = "SELECT 
	CASE OperationType
        WHEN 2 THEN 'BulkEmail'
        WHEN 3 THEN 'Parse'
        WHEN 4 THEN 'Transform'
        WHEN 5 THEN 'Import'
        WHEN 6 THEN 'ActivityPropagation'
        WHEN 7 THEN 'PublishDuplicateRule'
        WHEN 8 THEN 'BulkDetectDuplicates'
        WHEN 9 THEN 'CollectSqmData'
        WHEN 10 THEN 'Workflow'
        WHEN 11 THEN 'QuickCampaign'
        WHEN 12 THEN 'PersistMatchCode'
		WHEN 13 THEN 'BulkDelete'
		WHEN 14 THEN 'DeletionService'
		WHEN 15 THEN 'IndexManagement'
		WHEN 16 THEN 'CollectOrgStats'
		WHEN 17 THEN 'ImportingFile'
		WHEN 18 THEN 'CalculateOrgStorageSize'
		WHEN 19 THEN 'CollectOrgDbStats'
		WHEN 20 THEN 'CollectOrgSizeStats'
		WHEN 21 THEN 'Database Tuning'
		WHEN 22 THEN 'CalculateOrgMaxStorageSize'
		WHEN 23 THEN 'BulkDeleteChild'
		WHEN 24 THEN 'UpdateStatisticIntervals'
		WHEN 25 THEN 'FullTextCatalogIndex'
		WHEN 26 THEN 'DatabaseLogBackup'
		WHEN 27 THEN 'UpdateContractStates'
		WHEN 28 THEN 'ShrinkDatabase'
		WHEN 29 THEN 'ShrinkLogFile'
		WHEN 30 THEN 'ReindexAll'
		WHEN 31 THEN 'StorageLimitNotification'
		WHEN 32 THEN 'CleanupInactiveWorkflowAssemblies'
		WHEN 38 THEN 'ImportSampleData'
		ELSE 'Other'
	END
AS OperationType, 
 
 CASE StatusCode
    WHEN 0 THEN 'Waiting For Resources'
    WHEN 10 THEN 'Waiting'
    WHEN 20 THEN 'In Progress'
    WHEN 21 THEN 'Pausing'
    WHEN 22 THEN 'Cancelling'
    WHEN 30 THEN 'Succeeded'
    WHEN 31 THEN 'Failed'
    WHEN 32 THEN 'Cancelled'	
    ELSE 'Other'
 END AS StatusCode, COUNT(*) AS Total
FROM AsyncOperationBase 
GROUP BY OperationType, StatusCode
ORDER BY Total desc"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	$DataSet.Tables[0].rows
}
function IsCRMOrganizationDBUsingRCSI{
	param([string] $servername,
				[string] $databasename)
	trap [Exception]{
	   WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
	   return ""
	}
	# Rule ID: 4799 Display RCSI setting for each database
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = "Server=$servername;Database=master;Integrated Security=True"
	$SqlCmd.CommandText="select  is_read_committed_snapshot_on from sys.databases where name='$databasename'"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet) | Out-Null
	$SqlConnection.Close()
		
	foreach ($dr in $DataSet.Tables[0].rows){
		if ($dr.GetType() -ne [System.Int32]){
		    if ($dr.Item(0)){
				return  Get-HTMLNotificationTable "Red" "RCSI is enabled on this database."
			}else{
				return Get-HTMLNotificationTable "Green" "RCSI is not enabled on this database"
			}
		}else{
			continue
		}
	}
}
function Get-CRMOrgDbOrgSettings{
	param ([string] $conn_string)
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = $conn_string
	$SqlCmd.CommandText = "SET NOCOUNT ON;select orgdborgsettings from OrganizationBase"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)| Out-Null
	$SqlConnection.Close()
	return $DataSet.Tables[0].Rows
}

####################################################################################################################
#
#
#			Code obtained from http://poshcode.org/720
#
####################################################################################################################
function New-Type {
   param([string]$TypeDefinition,[string[]]$ReferencedAssemblies)
   
   ## Obtains an ICodeCompiler from a CodeDomProvider class.
   $provider = New-Object Microsoft.CSharp.CSharpCodeProvider
   ## Get the location for System.Management.Automation DLL
   $dllName = [PsObject].Assembly.Location
   ## Configure the compiler parameters
   $compilerParameters = New-Object System.CodeDom.Compiler.CompilerParameters
 
   $assemblies = @("System.dll", $dllName)
   $compilerParameters.ReferencedAssemblies.AddRange($assemblies)
   if($ReferencedAssemblies) { 
      $compilerParameters.ReferencedAssemblies.AddRange($ReferencedAssemblies) 
   }
 
   $compilerParameters.IncludeDebugInformation = $true
   $compilerParameters.GenerateInMemory = $true
 
   $compilerResults = $provider.CompileAssemblyFromSource($compilerParameters, $TypeDefinition)
   if($compilerResults.Errors.Count -gt 0) {
     $compilerResults.Errors | % { Write-Error ("{0}:`t{1}" -f $_.Line,$_.ErrorText) }
   }
}

New-Type @"
public class Shift {
   public static int   Right(int x,   int count) { return x >> count; }
   public static uint  Right(uint x,  int count) { return x >> count; }
   public static long  Right(long x,  int count) { return x >> count; }
   public static ulong Right(ulong x, int count) { return x >> count; }
   public static int    Left(int x,   int count) { return x << count; }
   public static uint   Left(uint x,  int count) { return x << count; }
   public static long   Left(long x,  int count) { return x << count; }
   public static ulong  Left(ulong x, int count) { return x << count; }
}                    
"@



#.Example 
#  Shift-Left 16 1        ## returns 32
#.Example 
#  8,16 |Shift-Left       ## returns 16,32
function Shift-Left {
PARAM( $x=1, $y )
BEGIN {
   if($y) {
      [Shift]::Left( $x, $y )
   }
}
PROCESS {
   if($_){
      [Shift]::Left($_, $x)
   }
}
}


#.Example 
#  Shift-Right 8 1        ## returns 4
#.Example 
#  2,4,8 |Shift-Right 2   ## returns 0,1,2
function Shift-Right {
PARAM( $x=1, $y )
BEGIN {
   if($y) {
      [Shift]::Right( $x, $y )
   }
}
PROCESS {
   if($_){
      [Shift]::Right($_, $x)
   }
}
}

#############################################################################################################
#						End of contribution from http://poshcode.org/720
#############################################################################################################
function convert_role_mask([int] $role_mask_value){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$mask = $role_mask_value
	$temp_role_string=""
	$arrOfValues = @("AppServer","AsyncService","SrsDataConnector","DiscoveryService","EmailService","WebService","SqlGovernor","WitnessServer","SqlServer","Portal","Provisioning","LivePlatform","Support","AdminWebService","Dns","ApiServer","ConfigSqlServer","ConfigWitnessServer","HelpServer","StatsSqlServer","TuningSqlServer","DeploymentService","SrsSqlServer")
	for ($i=0;$i -lt 23;$i++)
	{	
		if (($mask -band 0x0001) -eq 1)
		{
			$temp_role_string += $arrOfValues[$i].ToString() 
			$temp_role_string += ", "
		}
		$mask = Shift-Right $mask 1
		
	}
	return $temp_role_string
}

function Get-AppPoolState([int] $app_pool_state_value){
	switch ($app_pool_state_value)	{
		1 {$status="Starting";break}
		2 {$status="Started";break}
		3 {$status="Stopping";break}
		4 {$status="Stopped";break}
		default {$status="Starting";Unknown}
	}
   return $status
}
function Get-AppPoolAuthType([object] $app_pool_obj,[string] $iis_ver){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	if ($iis_ver -ne "7" -and $iis_ver -ne "8")	{
		switch ($app_pool_obj.AppPoolIdentityType)
		{
			1 {$authtype="LocalSystem";break}
			2 {$authtype="NetworkService";break}
			3 {$authtype=$app_pool_obj.WAMUserName;break}
		}
	}else{
		switch ($app_pool_obj.ProcessModel.IdentityType){
			"LocalSystem" {$authtype="LocalSystem";break}
			"LocalService" {$authtype="LocalService";break}
			"NetworkService" {$authtype="NetworkService";break}
			"SpecificUser" {$authtype=$app_pool_obj.ProcessModel.Username;break}
			"ApplicationPoolIdentity" {$authtype="ApplicationPoolIdentity";break}
		}
	}
	return $authtype
}
Function Get-CustomHTMLHeading ($Heading1, $Heading2, $Heading3)
{
$Report = @"
<TABLE>
	<TR>
	<TH width='50%'><b>$($Heading1)</b></font></th>
	<th width='25%'><b>$($Heading2)</b></font></th>
	<th width='25%'><b>$($Heading3)</b></font></th>
	</TR>
"@
Return $Report
}
Function Get-CustomHTMLDetail ($Detail1, $Detail2, $Detail3)
{
$Report = @"
<TABLE>
	<TR>
	<TD width='50%'>$($Detail1)</TD>
	<TD width='25%'>$($Detail2)</TD>
	<TD width='25%'>$($Detail3)</TD>
	</TR>
"@
Return $Report
}
Function Get-CustomHTMLDetailClose
{
	$Report = "</TABLE>"	
	Return $Report
}


#############################################################################################################
Function Get-HTMLNotificationTable ($Color, $Message){
$Report = @"
 <TABLE cellSpacing='0' cellPadding='0'>
 	<TBODY>
		<TR>
			<TD vAlign='top'></TD>
			<TD><SPAN><font face="Webdings" color='$($Color)'>n</font>&nbsp;$($Message)</SPAN></TD>
		</TR>
	</TBODY>
  </TABLE>
"@
Return $Report
}
Function Test-RegistryValue($regkey, $name) {
	Get-ItemProperty $regkey $name -ErrorAction SilentlyContinue | Out-Null
	$?
}
function IsDisableLoopbackCheckEnabled(){
	"--> Entered IsDisableLoopbackCheckEnabled" | WriteTo-StdOut
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'){
		$dlbkKey = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
		if ($dlbkKey -ne $null){
			if (Test-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' "DisableLoopbackCheck"){
				$loopback_value = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\DisableLoopbackCheck'
				if ($loopback_value -eq 1){
					return Get-HTMLNotificationTable "Green" ("DisableLoopbackCheck is enabled on this computer.")
				}
			}else{
				return Get-HTMLNotificationTable "Orange" ("DisableLoopbackCheck is not present or enabled on this computer.")
			}
		}else{
			return Get-HTMLNotificationTable "Orange" ("DisableLoopbackCheck is not present or enabled on this computer.")
		}
		"<-- Exited IsDisableLoopbackCheckEnabled" | WriteTo-StdOut
	}
}
function IsBackConnectionHostNames(){
	"--> Entered IsBackConnectionHostNames" | WriteTo-StdOut
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'){
		if (Test-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' "BackConnectionHostNames"){
			$connection_names = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
			if ($connection_names -ne [System.String]::Empty){
				return  Get-HTMLNotificationTable "Green" ("BackConnectionHostNames is enabled on this computer.")
			}
		}else{
			return Get-HTMLNotificationTable "Orange" ("BackConnectionHostNames is not present or enabled on this computer. Refer to <a href='http://support.microsoft.com/kb/896861/en-us' target='_blank'>http://support.microsoft.com/kb/896861/en-us</a> for more information")
		}
	}else{
		return Get-HTMLNotificationTable "Orange" ("BackConnectionHostNames is not present or enabled on this computer. Refer to <a href='http://support.microsoft.com/kb/896861/en-us' target='_blank'>http://support.microsoft.com/kb/896861/en-us</a> for more information")
	}
	"<-- Exited IsBackConnectionHostNames" | WriteTo-StdOut
}
function CustomPluginPresenceCheck(){
	"--> Entered CustomPluginPresenceCheck" | WriteTo-StdOut
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	if (Test-CRMServerKey){
	    $temp_table_string = [System.String]::Empty
		$crm_srv_version = Get-Item 'HKLM:\Software\Microsoft\MSCRM'
		$major_part = [System.Convert]::ToInt16($crm_srv_version.GetValue("CRM_Server_Version").Substring(0,1))
		$orgCollection = GetOrganizations $crm_srv_version.GetValue("configdb") -selectActive
		
		if ($orgCollection -ne $null){
			foreach ($organization in $orgCollection)
			{
				if ($organization.GetType() -ne [System.Int32] -and [System.Data.DataRow]$organization){
					#RBJC if ($major_part -eq 5){
						$plugins = GetPluginData (ScrubCRMConnectionString $organization.ConnectionString)
					#RBJC }else{
					#RBJC	$plugins = GetPluginData (ScrubCRMConnectionString $organization.ConnectionString) -isV4
					#RBJC}
					if ($plugins -ne $null){				
						foreach($plugin in $plugins){
							if  ($plugin.GetType() -ne [System.Int32] -and [System.Data.DataRow]$plugin -and $plugin.TypeName -ne "Microsoft.Crm.Extensibility.V3CalloutProxyPlugin"){
								if (-not $plugin.IsWorkflowActivity -and ($plugin.EntityName.Length -gt 0 -and $plugin.MessageName.Length -gt 0)){
									$msg = [System.String]::Format("The organization {0} has a plugin registered on the {1} Message for the {2} entity.", $organization.FriendlyName,$plugin.MessageName,$plugin.EntityName)
									$temp_table_string += Get-HTMLNotificationTable "Orange" $($msg)
								}
							}
						}
					}
				}
			}
			if ($temp_table_string -ne [System.String]::Empty){
				return $temp_table_string
			}
		}
	}
	return Get-HTMLNotificationTable "Green" ("No custom plugins were located in this deployment.")
	"<-- Exited CustomPluginPresenceCheck" | WriteTo-StdOut
}
function IsPowerPlanSetToHighPerformance(){
	"--> Entered IsPowerPlanSetToHighPerformance" | WriteTo-StdOut
	trap [Exception]{
	   WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
	   return ""
	}
	$active_plan = Get-WindowsPowerPlan
	if ($active_plan.toLower() -eq "high performance"){
		return  Get-HTMLNotificationTable "Green" ("The power plan for this computer is set to High Performance.")
	}else{
		return  Get-HTMLNotificationTable "Orange" ([System.String]::Format("The power plan for this computer is set to {0}.  Refer to <a href='http://support.microsoft.com/kb/2207548/en-us' target='_blank'>http://support.microsoft.com/kb/2207548/en-us</a> for more information",$active_plan))
	}
	"<-- Exited IsPowerPlanSetToHighPerformance" | WriteTo-StdOut	
}
function CheckTempFileCount{
     #Rule ID: 4884  implementation for SDP
     trap [Exception]{
	   WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
	   return ""
	}
	   $file_count = Get-TempDirectoryFileCount
	   if ($file_count -ge 50000){
	   		return Get-HTMLNotificationTable "Red" "Some temp files should be deleted to prevent performance problems or potential crashes if you reach the limit of 65535 files in the Temp folder at $env:windir\temp."
	   }else{
	   		return ""
	   }
}
function Get-MSCRMRegistryKeys{
	param ([string] $Report)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
		return $originalReport 
	}
	
	$originalReport = $Report
	if (Test-Path HKLM:\Software\Microsoft\MSCRM){
		
		$Report += Get-Header "2" "Microsoft Dynamics CRM Registry Key Settings"
		$MSCRMKey = Get-Item HKLM:\Software\Microsoft\MSCRM
		if ($MSCRMKey -ne $null)		{
			$Report += Get-Header "2" $MSCRMKey.Name
			$regInfo = GetRegistryProperties $MSCRMKey
			$Report += Get-HTMLTable ($regInfo | select Name, DataType,Value)
			$Report += Get-HeaderClose
		}
		#Handle the subkeys
		$childItems = Get-ChildItem -Path $MSCRMKey.PSPath -Recurse 
		foreach ($item in $childItems){
			if ($item.ValueCount -gt 0){
				$Report += Get-Header "2"  $item.Name
				$childRegInfo = GetRegistryProperties $item
				$Report += Get-HTMLTable ($childRegInfo | select Name,DataType,Value)
				$Report += Get-HeaderClose
			}
		}
		$Report += Get-HeaderClose
	}
	return $Report	
}
function GetRegistryDataType([string] $type){
		switch ($type){
			"Binary" {return "REG_BINARY"}
			"Dword" {return "REG_DWORD"}
			"String" {return "REG_SZ"}
			"Qword" {return "REG_QWORD"}
			"ExpandString" {return "REG_EXPAND_SZ"}
			"MultiString" {return "REG_MULTI_SZ"}
			default {return $type}
		}
}
function GetRegistryProperties{
	param ([Object]$key	)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$PropertiesCollected=@()	
	$valueNames = $key.GetValueNames()
	foreach ($valueName in $valueNames){
	    $RegistryValueObj = new-object PSObject
		$RegistryValueObj | add-member -membertype noteproperty -name "Name" -value $valueName
		$RegistryValueObj | Add-Member -MemberType NoteProperty -Name "DataType" -Value (GetRegistryDataType $key.GetValueKind($valueName).ToString())
		$RegistryValueObj | Add-Member -MemberType NoteProperty -Name "Value" -Value $key.GetValue($valueName)
		$PropertiesCollected += $RegistryValueObj
	}
	return $PropertiesCollected
}
function GetInstalledProgramHotfixInformation{
	param ([string] $Report)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
		return $originalReport 
	}
	
	$originalReport = $Report
	"--> Entered CRM Product and Hotfix Information" | WriteTo-StdOut
	$crm = "CRM"
	$uninstallers = get-childitem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
	$founditems = $uninstallers | ? {(Get-ItemProperty -path (“HKLM:\”+$_.name) -name Displayname -erroraction silentlycontinue) -match $crm}
	if ($founditems -eq $null) {“None found”} else {
		$crmfounditems = ($founditems) | %{ Get-ItemProperty $_.PSPath}
		$crmfounditems = $crmfounditems | ? {(Get-ItemProperty -Path ($_.PSPath) -Name Contact -ErrorAction SilentlyContinue) -notmatch " "}
		$Report += Get-Header "2" "Microsoft Dynamics CRM Installed Product and Hotfix Information"
		$Report += Get-HTMLTable ($crmfounditems | select DisplayName,DisplayVersion,HelpLink,Contact)
		$Report += Get-HeaderClose

	}
	"Exiting CRM Product and Hotfix Information" | WriteTo-StdOut
	return $Report	
}
function GetCRMProgramFileInformation{
	param ([string] $Report)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
		return $originalReport 
	}
	$originalReport = $Report
	"--> Entered CRM Program Files Information" | WriteTo-StdOut
	if (Test-Path $InstallLocation){
		$Report += Get-Header "2" "Microsoft Dynamics CRM Program File Information"
		$CRMFileList = Dir "$InstallLocation" -Recurse -Include *.dll,*.exe, *.html, *.aspx, *.js, *.htc 
		$crm_file_list = ($CRMFileList) | ForEach-Object {Add-Member -InputObject $_ -MemberType NoteProperty -Name Version -Value ([system.diagnostics.fileversioninfo]::GetVersionInfo($_.FullName).ProductVersion) -Force -PassThru}
		$Report += Get-HTMLTable ($crm_file_list | select DirectoryName, Name, LastWriteTime,Length,Version )
		$Report += Get-HeaderClose
	}else{
		#No files found in the Install Directory indicated in the MSCRM registry hive
		"No CRM Program Files Information was found in the $($InstallLocation) folder" | WriteTo-StdOut
		"No CRM Program Files Information was found in the $($InstallLocation) folder" | ConvertTo-Xml2 | Update-DiagReport -Id  CRM_Program_Files -Name "CRM Program Files Location Missuing" -Verbosity informational
	}
	"<-- Exited CRM Program Files Information" | WriteTo-StdOut
	return $Report
}
function Generate-OrgDbOrgSettings{
	PARAM ([string]$conn_string)
	trap [Exception]{
	   WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
	   return ""
	}
	$orgDbOrgSettingsDataRows = Get-CRMOrgDbOrgSettings $org_ConnectionString 
	if ($orgDbOrgSettingsDataRows -ne $null){
		foreach ($orgsettingrow in $orgDbOrgSettingsDataRows){
			$orgdborgsettingxml = [xml]$orgsettingrow.orgdborgsettings
	        return (Get-HTMLTable ($orgdborgsettingxml.OrgSettings.ChildNodes | ForEach-Object {$_ |Select-Object Name,@{Name="Value";Expression={$_.InnerText}}}))
		}
	}
	return ""	
}
function GetCRMGACFileInformation{
	param ([string] $Report)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
		return $originalReport 
	}
	
	$originalReport = $Report
	"--> Entered CRM GAC Information" | WriteTo-StdOut
	Write-DiagProgress -Activity $CRMStrings.ID_CRMGlobalAssemblyInformation -Status $CRMStrings.ID_CRMGlobalAssemblyObtaining
	$Report += Get-Header "2" "Microsoft Dynamics CRM Global Assembly Cache File Listing"
	$gac_paths = @()
	$gac_paths += "$env:windir\assembly"
	$gac_paths += "$env:windir\Microsoft.Net\Assembly\GAC_MSIL"

		
	$crmgacfilelist = Dir -Path $gac_paths -Recurse -Include Microsoft.?rm*.dll 
	$crm_file_list = ($crmgacfilelist) | ForEach-Object {Add-Member -InputObject $_ -MemberType NoteProperty -Name Version -Value ([system.diagnostics.fileversioninfo]::GetVersionInfo($_.FullName).ProductVersion) -Force -PassThru}
	if ($crm_file_list.Count -gt 4){
		$message = "There are non-standard Microsoft Dynamics CRM Assemblies installed in the Global Assembly Cache"
		$notificationTable = '<TABLE cellSpacing="0" cellPadding="0"><TBODY><TR><TD vAlign="top"></TD><TD><SPAN><font face="Webdings" color="Red">ê</font>' + $message + '</SPAN></TD></TR></TBODY></TABLE>'
		$notificationHTML = '<DIV class="Notifications" ID="GACNotificationDiv">' + $notificationTable + '</DIV><div class="filler"></div>'
		$Report+=$notificationHTML		
	}	
	$Report += Get-HTMLTable ($crm_file_list | select Name, Length, LastWriteTime,Version,Directory)
	$Report += Get-HeaderClose
	"<-- Exited CRM GAC Information" | WriteTo-StdOut
	return $Report
}

function GetRunningServicesInformation{
	param ([string] $Report)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
		return $originalReport 
	}
	
	$originalReport = $Report
	"--> Entered Running Services Information" | WriteTo-StdOut
	Write-DiagProgress -Activity $CRMStrings.ID_CRMServicesInformation -Status $CRMStrings.ID_CRMServicesObtaining
	$Report += Get-Header "2" "Windows Services Information"
	$colItems = Get-CimInstance -class "Win32_Service" -namespace "root\CIMV2" -computername $Target
	$Report += Get-HTMLTable ($colItems | Sort-Object -Property Caption | select Caption,Name,StartMode,ProcessId,State,StartName)
	$Report += Get-HeaderClose
	"<-- Exited Running Services Information" | WriteTo-StdOut
	return $Report
}
function GetRunningProcessInformation{
	param ([string] $Report)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
		return $originalReport 
	}
	$originalReport = $Report
	"--> Entered Running Processes Information" | WriteTo-StdOut
	Write-DiagProgress -Activity $CRMStrings.ID_CRMProcessInformation -Status $CRMStrings.ID_CRMProcessObtaining
	$Report += Get-Header "2" "Running Processes Information"
	$colItems = Get-CimInstance -class "Win32_Process" -namespace "root\CIMV2" -computername $Target
	$Report += Get-HTMLTable ($colItems |Sort-Object -Property Name | select Name,ProcessId,WorkingSetSize,PeakWorkingSetSize,ThreadCount,VirtualSize)
	$Report += Get-HeaderClose
	"<-- Exited Running Processes Information" | WriteTo-StdOut
	return $Report
}
function GetEventLogInformation{
	param ([string] $Report)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
		return $originalReport 
	}
	$originalReport = $Report
	"--> Entered Event Logs" | WriteTo-StdOut
	Write-DiagProgress -Activity $CRMStrings.CRM_EVENTLOGS -Status $CRMStrings.CRM_EVENTLOGS_DESC
	$eventLogs=[System.Diagnostics.EventLog]::GetEventLogs($Target) | where {($_.Log -eq "Application") -OR ($_.Log -eq "System")} #Fix to workaround localization issue
	$tmperrEvents = @()
	$tmpwarnEvents = @()
	$warningEvents = @()
	$errorEvents = @()
	foreach ($eventLog in $eventLogs)	{
		if ($eventLog.Entries -ne $null){
			$tmpwarnEvents += ($eventLog.Entries) | ForEach-Object { Add-Member -inputobject $_ -Name LogName -MemberType NoteProperty -Value $eventLog.LogDisplayName -Force -PassThru} | where {$_.TimeWritten -gt ((Get-Date).AddDays(-7))} |where {($_.EntryType -eq "Warning")} | Sort-Object -property  @{Expression="TimeWritten";Descending=$true} 
			$tmperrEvents += ($eventLog.Entries) | ForEach-Object { Add-Member -inputobject $_ -Name LogName -MemberType NoteProperty -Value $eventLog.LogDisplayName -Force -PassThru} | where {$_.TimeWritten -gt ((Get-Date).AddDays(-7))} |where {($_.EntryType -eq "Error")} | Sort-Object -Property @{Expression="TimeWritten";Descending=$true}
		}
	}
	#Need to trim the events to make the report more manageable.
	foreach ($l in $tmpwarnEvents){
		if ($warningEvents.Count -le 100){
			$warningEvents += $l
		}else{
			break;
		}
	}
	foreach ($l in $tmperrEvents){
		if ($errorEvents.Count -le 100){
			$errorEvents += $l
		}else{
			break;
		}
	}
	$Report += Get-Header "2" "Event Logs - last 7 days"
	if (($tmpwarnEvents.Length -gt 100) -or ($tmperrEvents.Length -gt 100)){
		$message = "There are a high number of warning and error events in the Event Logs. A partial list is below. See the attached log files for a complete listing"
		$notificationTable = '<TABLE cellSpacing="0" cellPadding="0"><TBODY><TR><TD vAlign="top"></TD><TD><SPAN><font face="Webdings" color="Red">ê</font>' + $message + '</SPAN></TD></TR></TBODY></TABLE>'
		$notificationHTML = '<DIV class="Notifications" ID="EVNotificationDiv">' + $notificationTable + '</DIV><div class="filler"></div>'
		$Report+=$notificationHTML		
	}
	$Report += Get-Header "2" "Warning Events"
	$Report += Get-HTMLTable ($warningEvents | select EventID, Source, TimeWritten, LogName, Message)
	$Report += Get-HeaderClose
	$Report += Get-Header "2" "Error Events"
	$Report += Get-HTMLTable ($errorEvents | select EventID, Source, TimeWritten, LogName, Message)
	$Report += Get-HeaderClose
	$Report += Get-HeaderClose
	
	"End of Powershell Event Log Collector Code" | WriteTo-StdOut
	return $Report
}
function GetIISAppPoolInformation{
	param ([string] $Report)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
		return $originalReport 
	}
	$originalReport = $Report
	"--> Entered IIS Application Information" | WriteTo-StdOut
	Write-DiagProgress -Activity $CRMStrings.ID_IISAppPoolInformation -Status $CRMStrings.ID_IISAppPoolObtaining
	if ($iis_version -eq '6'){
		$Report += Get-Header "2" "Microsoft Dynamics CRM Server Internet Information Server Application Pool Information"
		$colAppPools = Get-CimInstance -class "IIsApplicationPoolSetting" -namespace "root\MicrosoftIISv2" -comp $Target
		($colAppPools) | ForEach-Object {
		  Add-Member -InputObject $_ -MemberType NoteProperty -Name Status -Value (Get-AppPoolState $_.AppPoolState) -Force -PassThru
		  Add-Member -InputObject $_  -MemberType NoteProperty -Name AuthType -Value (Get-AppPoolAuthType $_ $iis_version) -Force -PassThru
		}
		$Report += Get-HTMLTable ($colAppPools | select Name,Status,AuthType)
		$Report += Get-HeaderClose
	}
	else{
		#This is a 7.x IIS Server
		$Report += Get-Header "2" "Microsoft Dynamics CRM Server Internet Information Server Application Pool Information"
		[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Web.Administration") | Out-Null
		$iis = new-object Microsoft.Web.Administration.ServerManager
		$colAppPools = $iis.ApplicationPools
		$Report += Get-CustomHTMLHeading "Name" "Status" "Authentication Type"
		foreach ($cap in $colAppPools)
		{
			 $Report += Get-CustomHTMLDetail $cap.Name $cap.State (Get-AppPoolAuthType $cap $iis_version)
		}
		$Report += Get-CustomHTMLDetailClose
		$Report += Get-HeaderClose
	}
	"<-- Exited IIS Application Information" | WriteTo-StdOut
	return $Report
}
function GetCRMWebSiteInformation{
	param ([string] $Report)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
		return $originalReport 
	}
	$originalReport = $Report
	"--> Entered CRM Website Information" | WriteTo-StdOut
	$iis_version = GetIISVersion
	if (($iis_version -ne 7) -and ($iis_version -ne 8)){
		Write-DiagProgress -Activity $CRMStrings.ID_CRMWebsiteInformation -Status $CRMStrings.ID_CRMWebsiteObtaining
		$Report += Get-Header "2" "Microsoft Dynamics CRM Web Site Settings"
		if (Test-Path HKLM:\Software\Microsoft\MSCRM){
			$MSCRMKey = Get-Item HKLM:\Software\Microsoft\MSCRM
			if ($MSCRMKey -ne $null){
			   $sites = ([adsi]"IIS://localhost/W3SVC").psbase.children 
			   foreach ($objSite in $sites){
			   		if ($objSite.Path.Substring(16) -eq $MSCRMKey.GetValue("website").Substring(4)){
						$website = $objSite.ServerComment.Value
			   			$Report += Get-Header "2" ([System.String]::Format("Binding Information for Site {0}", $website))
						$Report += Get-HTMLDetail "<u>IP Address</u>" "<u>HostName : Port</u>"
						foreach ($binding in $objSite.ServerBindings){
							$arrBindings = @{}
							$arrBindings = $binding.Split(":")							
							if ($arrBindings[0] -eq ""){
								$ip_string = "All Assigned"
							}else{
								$ip_string = $arrBindings[0]
							}
							$Report += Get-HTMLDetail $ip_string ([System.String]::Format("{0}:{1}", $arrBindings[2], $arrBindings[1]))
						}
						$Report += Get-HeaderClose
						$Report += Get-Header "2" ([System.String]::Format("Authentication Information for Site {0}", $website))
						$Report += Get-HTMLBasic ("{0} has its NTAuthenticationProviders set to {1}" -f $website, $objSite.NTAuthenticationProviders.Value)
						#$colComputer = Get-CimInstance -class "IIsWebVirtualDirSetting" -namespace "root\MicrosoftIISv2" -comp $Target  #RBJC_To_DO
						#foreach($comp in $colcomputer){
						#	if ($comp.Name.StartsWith($MSCRMKey.GetValue("website").Substring(4))){
						#		$authFlagsText = GetAuthFlagsText $comp.AuthFlags
						#		$Report += Get-HTMLBasic ("{0} : {1}" -f $comp.Name, $authFlagsText)
						#	}
						#}
						$Report += Get-HeaderClose	
						}
			   }
				  
			}
		}
		$Report += Get-HeaderClose
	}else{
	}
		
	#Running IIS 7 so we need to query for sites differently
	#Write-DiagProgress -Activity $CRMStrings.ID_CRMWebsiteInformation -Status $CRMStrings.ID_CRMWebsiteObtaining
	$Report += Get-Header "2" "Microsoft Dynamics CRM Web Site Settings"
		
	#Get IIS ServerManager object
	[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Web.Administration") | Out-Null
	$iis = new-object Microsoft.Web.Administration.ServerManager
	# $iis7sites = Get-CimInstance -namespace “root\WebAdministration” -Class Site  #RBJC_To_DO $iis7sites not used...
	foreach ($site in $iis.Sites){
			$Report += Get-Header "2" $site.name
			
			#Create Bindings Table
			$Report += Get-Header "2" ([System.String]::Format("Binding Information for Site {0}", $site.Name))
			$Report += Get-HTMLTable ($site.Bindings | select Protocol, BindingInformation)
			$Report += Get-HeaderClose
			
			#Create Authentication Table
			$Report += Get-Header "2" ([System.String]::Format("Authentication Information for Site {0}", $site.Name))
			
			#To-do: Move to a function
			# I'm sure there is an easier way to get this. I haven't found it yet.
			$iisHost = $iis.GetApplicationHostConfiguration()
			$iisWeb = $iis.GetWebConfiguration($site.Name);
			$basic_auth = $iisHost.GetSection("system.webServer/security/authentication/basicAuthentication", $site.Name).GetAttributeValue("enabled")
			$windows_auth = $iisHost.GetSection("system.webServer/security/authentication/windowsAuthentication",$site.Name).GetAttributeValue("enabled")
			$anon_auth = $iisHost.GetSection("system.webServer/security/authentication/anonymousAuthentication",$site.Name).GetAttributeValue("enabled")
			$digest_auth = $iisHost.GetSection("system.webServer/security/authentication/digestAuthentication",$site.Name).GetAttributeValue("enabled")
			$forms_auth = $iisHost.GetSection("system.webServer/security/authentication/clientCertificateMappingAuthentication",$site.Name).GetAttributeValue("enabled")
			$asp_impersonate = $iisWeb.GetSection("system.web/identity").GetAttributeValue("impersonate")
			
			$Report += Get-HTMLDetail "Anonymous Authentication" $anon_auth
			$Report += Get-HTMLDetail "ASP.NET Impersonation" $asp_impersonate
			$Report += Get-HTMLDetail "Basic Authentication" $basic_auth
			$Report += Get-HTMLDetail "Digest Authentication" $digest_auth
			$Report += Get-HTMLDetail "Forms Authentication" $forms_auth
			$Report += Get-HTMLDetail "Windows Authentication" $windows_auth		
			$Report += Get-HeaderClose		
			$Report += Get-HeaderClose
	}
		
	$Report += Get-HeaderClose
		
	#Adding Check for httpCompression if CRM 2011 or greater
	#RBJC if ($server_version -ne '4' -or $server_version -ne '3'){
	#RBJC 	$Report += Get-Header "2" "IIS httpCompression Setting Information"
	#RBJC 		if ($iis_version -eq 7 -or $iis_version -eq 8){
	#RBJC 			"--> Entered httpCompression Check" | WriteTo-StdOut
	#RBJC 			#[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Web.Administration") | Out-Null
	#RBJC 			#$iis = new-object Microsoft.Web.Administration.ServerManager
	#RBJC 			$config = $iis.GetApplicationHostConfiguration()								
	#RBJC 			$http_compression_section = $config.GetSection("system.webServer/httpCompression")
	#RBJC 			$http_compression_section | WriteTo-StdOut
	#RBJC 			$dynamic_types_collection = $http_compression_section.GetCollection("dynamicTypes")
	#RBJC 			$found = $false
	#RBJC 			foreach ($dynamic_type in $dynamic_types_collection){
	#RBJC 				$mime_type=$dynamic_type.GetAttribute("mimeType")
	#RBJC 				if ($mime_type.Value -eq "application/soap+xml;charset=utf-8" -or $mime_type.Value -eq "application/soap+xml; charset=utf-8"){
	#RBJC 					$Report += Get-HTMLBasic "httpCompression is enabled on the IIS Server. Refer to Optimizing and Maintaining the Performance of a Microsoft Dynamics CRM 2011 Server Infrastructure - http://www.microsoft.com/download/en/details.aspx?id=27139 for more information"
	#RBJC 					$found=$true
	#RBJC 				}
	#RBJC 			}
	#RBJC 			"httpCompression Check: $($found)" | WriteTo-StdOut
	#RBJC 			if (-not $found){
	#RBJC 				$Report += Get-HTMLBasic "httpCompression is not enabled on the IIS Server.  This may impact performance of the clients over a WAN."
	#RBJC 			}
	#RBJC 		}
	#RBJC 		$Report += Get-HeaderClose
	#RBJC }
	"<-- Exited CRM Website Information" | WriteTo-StdOut
	return $Report 
}
function GetBootIniInformation{
	param ([string] $Report)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
		return $originalReport 
	}
	$originalReport = $Report 
	"--> Entered Boot.ini Information" | WriteTo-StdOut
	Write-DiagProgress -Activity $CRMStrings.ID_BootIniInformation -Status $CRMStrings.ID_BootIniObtaining
	$bootini = $objOSItem.SystemDrive + "\boot.ini"
	if (Test-Path $bootini){
		$Report += Get-Header "2" "Boot.ini Content"
		$boot_ini_content = Get-Content -Path $bootini
		foreach ($element in $boot_ini_content){	
			$Report += Get-HTMLBasic $element
		}
		$Report += Get-HeaderClose	
	}
	"<-- Exited Boot.ini Information" | WriteTo-StdOut
	return $Report 
}
function GetTCPIPInformation{
	param ([string] $Report)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
		return $originalReport 
	}
	$originalReport = $Report
	"--> Entered TCP/IP Information" | WriteTo-StdOut
	Write-DiagProgress -Activity $CRMStrings.ID_NetBasicInfoTCPOutput -Status $CRMStrings.ID_CRM_NetBasicInfoObtaining
	$Report += Get-Header "2" "TCP/IP Settings"
	
	if (Test-Path HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters){
		$TCPIPKey = Get-Item HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters
		if ($TCPIPKey -ne $null){
			$Report += Get-Header "2" $TCPIPKey.Name
			foreach ($prop in $TCPIPKey.GetValueNames()){
				$Report += Get-HTMLDetail $prop $TCPIPKey.GetValue($prop)
			}
			$Report += Get-HeaderClose	
		}
		$Report += GetSubKeys $TCPIPKey 
	}
	$Report += Get-HeaderClose
	
	Write-DiagProgress -Activity $CRMStrings.CRM_TCP_IP -Status $CRMStrings.CRM_TCP_IP_DESC
	$Report += Get-Header "2" "TCP/IP General Information"
	
	$arguments = "/all"
	$Filename = $Env:COMPUTERNAME + "_ipconfig.txt"
	$cmdToRun = "cmd.exe /c ipconfig.exe $arguments >> $Filename" 
	RunCMD -commandToRun $cmdToRun -fileDescription "Ipconfig.txt" -sectionDescription "IP configuration Information" | Out-Null
	Get-Content $Filename | % {$Report += ($_+ "<br>")}
	$Report += Get-HeaderClose
	"<-- Exited TCP/IP Information" | WriteTo-StdOut
	return $Report
}
function GetSQLServerInformation{
	param ([string] $Report,[string]$conn_string,[string] $sql_version)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
		return $originalReport 
	}
	$originalReport = $Report 
	"--> Entered SQL Server Information" | WriteTo-StdOut
	Write-DiagProgress -Activity $CRMStrings.ID_CRMSQLServerInformation -Status $CRMStrings.ID_CRMSQLServerObtaining
	$Report += Get-Header "2" "SQL Server General Information"
	$SQLHTML = '<DIV class="Notifications" ID="SqlNotificationDiv">' + $sql_version + '</DIV><div class="filler"></div>'
	$Report+=$SQLHTML
	
	$sql_general_setting = checkinstance $conn_string.DataSource
	$Report += Get-HTMLTable ($sql_general_setting | Select Property, Value)
		
	$Report += Get-Header "2" "SQL Server Advanced Setting Information"
	$sql_advanced_options = checkconfiguration $conn_string.DataSource
	$Report+= Get-HTMLTable ($sql_advanced_options | Select Name, Config_Value,Run_Value)
	$Report += Get-HeaderClose
	$Report += Get-HeaderClose
	
	"<-- Exited SQL Server Information" | WriteTo-StdOut
	return $Report
}
function GetCRMConfigurationDatabaseInformation{
	param ([string] $Report, [string] $conn_string)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
		return $originalReport 
	}
	$originalReport = $Report 
	"--> Entered CRM Configuration Database Information" | WriteTo-StdOut
	## Retrieved CRM Version from registry. 
	
	#if ($server_version -eq '4' -or $server_version -eq '5'){
	# 10/7/13 Changing code to handle v4.0, CRM 2011 and CRM 2013
	if ($server_version -ne '3'){
		Write-DiagProgress -Activity $CRMStrings.ID_CRMConfigDbInformation -Status $CRMStrings.ID_CRMConfigDbObtaining
		$Report += Get-Header "2"  "Microsoft Dynamics CRM Configuration Database Settings"
		$Report += Get-Header "2" "Organization SQL Table Information"
		$crm_organization_details = GetOrganizationData $conn_string
		foreach ($detail in $crm_organization_details){
			#Implementation of Rule Id: 5200 
		 	if ($detail.GetType() -ne [System.Int32]){
				$db_value = GetBuildNumber $detail.Id $conn_string
				$Report += Get-HTMLTable ($detail | Select UniqueName,DatabaseName,@{Name="Database Version";Expression={"$db_value"}},ConnectionString,SqlServerName,SrsUrl,State,IsDeleted)
			}
		}
		$Report += Get-HeaderClose
		
		# Server Table information
		#Dump out Server table details
		
		$Report += Get-Header "2" "Server SQL Table Information"
		#RBJC if ($server_version -eq '4'){
		#RBJC 	$crm_server_details = GetV4ServerTableData $conn_string
		#RBJC }else {
			$crm_server_details = GetServerTableData $conn_string
		#RBJC }
		$Report += Get-HTMLTable ($crm_server_details | Select Name,Version,ServerRoles,ScaleGroupId,State)
		$Report += Get-HeaderClose
		
		$Report += Get-Header "2" "ConfigSettings SQL Table Information"
		$crm_config_settings_details = GetConfigSettingsTableData $conn_string
		$Report += Get-HTMLTable ($crm_config_settings_details | Select InstallOn,IsRegistered,LicenseKey,LicenseKeyV5,LicenseKeyV5RTM,PrivilegeReportGroupId,PrivilegeUserGroupId,ReportingGroupId,SqlAccessGroupId,HelpServerUrl)
		$Report += Get-HeaderClose
		
		$Report += Get-Header "2" "AD Group Membership Information"
		$crm_ad_group_member_details = GetADGroupMemberShip $conn_string
		foreach ($ad_row in $crm_ad_group_member_details){
			if ($ad_row.GetType() -ne [System.Int32] -and [System.Data.DataRow]$ad_row){
				#SQLAccessGroup
				$sag = GetDirectoryEntry $ad_row.SqlAccessGroupId.ToString()
				if ($sag -ne $null){
					$Report += Get-Header "2" $sag.distinguishedName
					$m=1
					foreach ($member in $sag.member.Value){
						$Report += Get-HTMLDetail ([System.String]::Format("Member {0}:",$m)) $member
						$m++
					}
					$Report += Get-HeaderClose
				}
				#PrivilegeReportGroup
				$prg = GetDirectoryEntry $ad_row.PrivilegeReportGroupId.ToString()
				if ($prg -ne $null){
					$Report += Get-Header "2" $prg.distinguishedName
					$m=1
					foreach ($member in $prg.member.Value){
						$Report += Get-HTMLDetail ([System.String]::Format("Member {0}:",$m)) $member
						$m++
					}
					$Report += Get-HeaderClose
				}
				#PrivilegeUserGroup
				$pug = GetDirectoryEntry $ad_row.PrivilegeUserGroupId.ToString()
				if ($pug -ne $null){
					$Report += Get-Header "2" $pug.distinguishedName
					$m=1
					foreach ($member in $pug.member.Value){
						$Report += Get-HTMLDetail ([System.String]::Format("Member {0}:",$m)) $member
						$m++
					}
					$Report += Get-HeaderClose
				}
				#ReportingGroup
				$rg = GetDirectoryEntry $ad_row.ReportingGroupId.ToString()
				if ($rg -ne $null){
					$Report += Get-Header "2" $rg.distinguishedName
					$m=1
					foreach ($member in $rg.member.Value){
						$Report += Get-HTMLDetail ([System.String]::Format("Member {0}:",$m)) $member
						$m++
					}
					$Report += Get-HeaderClose
				}
			}
			
		}
		$Report += Get-HeaderClose
		
		$Report += Get-Header "2" "Deployment Properties SQL Table Information"
		$crm_deployment_properties = GetDeploymentPropertiesTableData $conn_string
		foreach($dp_row in $crm_deployment_properties){
			if ($dp_row.GetType() -ne [System.Int32] -and [System.Data.DataRow]$dp_row){
				for($i=1;$i -lt 5;$i++){
					if (![System.String]::IsNullOrEmpty($dp_row.Item($i).ToString())){
						$Report += Get-HTMLDetail $dp_row.Item(0) $dp_row.Item($i)
					}
				}
			} 
		}
		$Report += Get-HeaderClose
	$Report+= Get-HeaderClose
	}else{
		#This is a V3 deployment...flag as a rule
	}
	"<-- Exited CRM Configuration Database Information" | WriteTo-StdOut
	return $Report
}
function ScrubCRMConnectionString{
	PARAM([string] $org_connectionstring)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
		return $org_connectionstring 
	}
	$org_connectionstring = $org_connectionstring.Replace("MultiSubnetFailover=True","")
	$conn_string = $org_connectionstring.replace("Provider=SQLOLEDB;","")
	return $conn_string	
}
function GetCRMOrganizationDetails{
	param ([string] $Report, [string] $conn_string)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
		return $originalReport 
	}
	
	$originalReport = $Report

	"--> Entered CRM Organization Statistics Information" | WriteTo-StdOut
	# Section : Top Ten Tables by Row Count
	$crm_organizations = GetOrganizations $conn_string
	if ($crm_organizations.Count -gt 0){	
		$Report += Get-Header "2" "Organization Statistics" 
		foreach($org in $crm_organizations){
		    if (![System.String]::IsNullOrEmpty($org.ConnectionString)){
				$org_connectionString = ScrubCRMConnectionString $org.ConnectionString
				$RCSIHTML = '<DIV class="Notifications" ID="$org.DatabaseNameRcsiNotificationDiv">' +( IsCRMOrganizationDBUsingRCSI -servername $Target -databasename $org.DatabaseName) + '</DIV><div class="filler"></div>'
				$Report+=$RCSIHTML
				$Report += Get-Header "2" ("{0} Statistics" -f $org.FriendlyName)
				#region Top Ten By Row Count
				$Report += Get-Header "2" ("Top Ten Tables By Row Count for Organization {0}" -f $org.FriendlyName)
				#RBJC if ($server_version -eq '5' -or $server_version -eq '6'){  #Need to handle different SQL Connection Objects
					$org_table_row_counts = GetTopTableRowCounts $org_connectionString
					$Report += Get-HTMLTable ($org_table_row_counts | Select TableName,RowCount)				
				#RBJC }else{
					#This is a V4 Deployment
				#RBJC 	$org_table_row_counts = GetV4TopTableRowCounts $org.ConnectionString
				#RBJC 	$Report += Get-HTMLTable ($org_table_row_counts | Select TableName,RowCount)	
				#RBJC }
				$Report += Get-HeaderClose
				#endregion Top Ten By Row Count
				
				#region Organization Table Size Information
				$Report += Get-Header "2" ("Table Size Information for Organization {0}" -f $org.FriendlyName)
				#RBJC if ($server_version -eq '5' -or $server_version -eq '6'){
					$org_table_sizes = GetTableSizes $org_connectionString
					$Report += Get-HTMLTable ($org_table_sizes | select ObjectID,ObjectName, Reserved_MB, Data_MB, Index_MB,RowCount)
				#RBJC }else{
				#RBJC 	$org_table_sizes = GetV4TableSizes $org_connectionString
				#RBJC 	$Report += Get-HTMLTable ($org_table_sizes | select ObjectID,ObjectName, Reserved_MB, Data_MB, Index_MB,RowCount)
				#RBJC }
				$Report += Get-HeaderClose
				#endregion
				
				#region Custom Entity Counts
				#RBJC if ($server_version -eq '5' -or $server_version -eq '6'){
					$org_conn = New-Object System.Data.SqlClient.SqlConnection($org_connectionString)
					$org_db_cmd = New-Object System.Data.SqlClient.SqlCommand
				#RBJC }else{
					# This is V4, so need to use OleDbConnection objects
				#RBJC 	$org_conn = New-Object System.Data.OleDb.OleDbConnection($org_connectionString)
				#RBJC 	$org_db_cmd = New-Object System.Data.OleDb.OleDbCommand
				#RBJC }
				
				$org_db_cmd.CommandText = "SELECT Count(*)as Total_Custom_Entities From MetadataSchema.Entity WHERE IsCustomEntity <> 0"
				$org_db_cmd.Connection = $org_conn
				$org_conn.Open()
				$entity_count = $org_db_cmd.ExecuteScalar()
				if ($entity_count -gt 0){	
				    $Report += Get-Header "2" ("This organization has a total of {0} custom entities." -f $entity_count)
					$Report += Get-HeaderClose
				}
				#endregion Custom Entity Counts
				
				#region Custom Attribute Counts
				#Change CommandText to select custom Attributes
				$org_db_cmd.Connection = $org_conn
				$org_db_cmd.CommandText = "SELECT ent.Name, count(*) as Total_Custom_Attributes FROM MetadataSchema.Attribute a join MetadataSchema.Entity ent on a.entityid=ent.entityid where a.IsCustomField=1 GROUP BY ent.Name"
				$rdr = $org_db_cmd.ExecuteReader()
				if ($rdr.HasRows){
					$Report += Get-Header "2" "Custom Attribute Counts By Entity"
					$Report += Get-HTMLDetail "Entity Name" "# of Custom Attributes"
					while ($rdr.Read()){
						$Report += Get-HTMLDetail $rdr.GetValue(0) $rdr.GetValue(1)
					}
					$Report += Get-HeaderClose				
				}
				
				$org_conn.Close()
				#endregion Custom Attribute Counts
				
				#region AsyncOperation Status and Type Information
				$Report += Get-Header "2" ("Async Operation Status Information for Organization {0}" -f $org.FriendlyName)
				#RBJC if ($server_version -eq '5' -or $server_version -eq '6'){
					$async_table_types = GetAsyncOperationTypes $org_connectionString			
				#RBJC }else{
				#RBJC   	$async_table_types = GetV4AsyncOperationTypes $org_connectionString
				#RBJC }
				$Report += Get-HTMLTable ($async_table_types | select OperationType,StatusCode,Total)
				$Report += Get-HeaderClose
				#endregion AsyncOperation Status and Type Information

				#region OrgDbOrgDbSettings Information
				"--> Entered CRM OrgDbOrgSettings Information" | WriteTo-StdOut
				[System.String]::Format("The server version is set to {0}",[System.Convert]::ToInt16($server_version))| WriteTo-StdOut
				#RBJC if ([System.Convert]::ToInt16($server_version) -gt 4){
					#only run this for CRM 2011/2013 Organizations
					$Report += Get-Header "2" ("OrgDbOrgSettings Information for Organization {0}" -f $org.FriendlyName)
					$Report += Generate-OrgDbOrgSettings $org_connectionString
					$Report += Get-HeaderClose					
				#RBJC }
				
				#region Get Plugin Data
				$Report += Get-Header "2" "CRM Plugin Information"
				#RBJCif ($server_version -eq '5' -or $server_version -eq '6'){
					$crm_plugins = GetPluginData $org_connectionString
				#RBJC}else{
				#RBJC  	$crm_plugins = GetV4PluginData $org_connectionString
				#RBJC}
				$Report += Get-HTMLTable ($crm_plugins | select TypeName,IsWorkflowActivity,Stage,Mode,SupportedDeployment,InvocationSource,EntityName,MessageName)
				$Report += Get-HeaderClose
				#endregion Plugins
				
				$Report += Get-HeaderClose
			}
		}
	}
	"Exiting CRM Organization Statistics Information" | WriteTo-StdOut
	return $Report
}
function GetCRMCalloutConfigInformation{
	param ([string] $Report)
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
		return $originalReport 
	}
	
	$originalReport = $Report
	"--> Entered CRM Callout.config.xml Information" | WriteTo-StdOut
	Write-DiagProgress -Activity $CRMStrings.ID_CRMCalloutConfigInformation -Status $CRMStrings.ID_CRMCalloutConfigObtaining
	$crm_callout_location = $InstallLocation + "\server\bin\assembly"
	$callout_config_xml = $crm_callout_location + "\callout.config.xml"
	if (Test-Path $callout_config_xml){
		$callout_content = Get-Content -Path $callout_config_xml
		if ($callout_content -ne ""){
			$Report += Get-Header "2" "Callout.Config.xml Contents"
			foreach ($element in $callout_content){	
				$Report += Get-HTMLBasic $element
			}
			$Report += Get-HeaderClose
		}
	}
	return $Report	
}
function GetCRMWebConfig{
	trap [Exception]{
			WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}	
	"--> Entered web.config collection" | WriteTo-StdOut
	$fileToCollect = $website_path + '\web.config' 
	$fileDescription = "Microsoft Dynamics CRM web.config file"
	$sectionDescription = "Microsoft Dynamics CRM Web Configuration File"
	$fileToCollect | WriteTo-StdOut
	if (test-path $fileToCollect) {
		"Located web.config file" | WriteTo-StdOut
		CollectFiles -filesToCollect $fileToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -verbosity debug
	}
	"<-- Exited web.config collection" | WriteTo-StdOut
}
#endregion Baseline Collection Functions

##############################################################################################################
#									General Processing
##############################################################################################################
. ./utils_CTS.ps1
. ./utils_mbs.ps1
. ./utils_CRM.ps1

trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
}

$MyReport = ""
$Target = $Env:COMPUTERNAME
$MyReport = Get-CustomCRMHTML "$Target Microsoft Dynamics CRM Server Information Report"

WriteTo-StdOut "Got to here in the script" -shortformat

Import-LocalizedData -BindingVariable CRMStrings

#region Virtualization Check
"--> Entered Virtualization Check" | WriteTo-StdOut
$CommandToExecute = "cscript.exe GetVirtualEnv.VBS /GenerateScriptedDiagAlertXML"
$OutputFiles = $Target + "_Virtualization.*"
RunCmD -commandToRun $CommandToExecute -sectionDescription "Virtualization Check" -filesToCollect $OutputFiles -fileDescription "Virtualization Check" 

$VirtualizationAlertXMLFileName = $Computername + "_VirtualizationAlerts.XML"
if (test-path $VirtualizationAlertXMLFileName) {
	#Found that this is virtualized environment. Load the document
	$xml = New-Object "System.Xml.XmlDocument"
	$xml.load([System.String]::Format("{0}\{1}",$PWD,$VirtualizationAlertXMLFileName))
	$nodes = $xml.SelectNodes("/Root/Alert/Objects/Object/Property[@Name='Message']")
	if ($nodes.Count -eq 1){
		$message = $nodes.Item(0).InnerText
		$notificationTable = '<TABLE cellSpacing="0" cellPadding="0"><TBODY><TR><TD vAlign="top"></TD><TD><SPAN><font face="Webdings" color="Red">ê</font>' + $message + '</SPAN></TD></TR></TBODY></TABLE>'
		$notificationHTML = '<DIV class="Notifications" ID="NotificationDiv">' + $notificationTable + '</DIV><div class="filler"></div>'
		$MyReport+=$notificationHTML
	}
	
}
"<-- Exited Virtualization Check" | WriteTo-StdOut
#endregion Virtualization Check
#region Warnings Banner
$warningTable = [System.String]::Empty
$warningTable += IsDisableLoopbackCheckEnabled
$warningTable += IsBackConnectionHostNames
$warningTable += CustomPluginPresenceCheck
$warningTable += IsPowerPlanSetToHighPerformance
$warningTable += CheckTempFileCount
$warningsHTML = '<DIV class="Notifications" ID="WarningDiv">' + $warningTable + '</DIV><div class="filler"></div>'
$MyReport += $warningsHTML

#endregion


#region Operating System Information
"--> Entered Operating System Information" | WriteTo-StdOut
Write-DiagProgress -Activity $CRMStrings.ID_OperatingSystemInformation -Status $CRMStrings.ID_OperatingSystemObtaining
$MyReport += Get-Header "2" "Operating System Information"
$objWin32OS = Get-CimInstance -Class Win32_OperatingSystem -namespace "root\CIMV2" -computername $Target
$colRAM = Get-CimInstance -Class "win32_PhysicalMemory" -namespace "root\CIMV2" -computerName $Target

foreach ($objRAM in $colRAM) {	 	
	 	 $installedRAM =  ($objRAM.Capacity / 1GB) 
}

$OperatingSystems = Get-CimInstance -computername $Target Win32_OperatingSystem
$ComputerSystem = Get-CimInstance -ComputerName $Target Win32_ComputerSystem

foreach ($objOSItem in $objWin32OS){
  $MyReport += Get-HTMLDetail "Build Number" $objOSItem.BuildNumber 
  $MyReport += Get-HTMLDetail "Build Type" $objOSItem.BuildType
  $MyReport += Get-HTMLDetail "Caption" $objOSItem.Caption
  $MyReport += Get-HTMLDetail "CSDVersion" $objOSItem.CSDVersion
  $MyReport += Get-HTMLDetail "CSName" $objOSItem.CSName
  $MyReport += Get-HTMLDetail "CurrentTimeZone" $objOSItem.CurrentTimeZone
  $MyReport += Get-HTMLDetail "EncryptionLevel" $objOSItem.EncryptionLevel
  $MyReport += Get-HTMLDetail "FreePhysicalMemory (MB)" $([Math]::Round(($objOSItem.FreePhysicalMemory / 1024),2))
  $MyReport += Get-HTMLDetail "FreeSpaceInPagingFiles" $objOSItem.FreeSpaceInPagingFiles
  $MyReport += Get-HTMLDetail "FreeVirtualMemory (MB)" $([Math]::Round(($objOSItem.FreeVirtualMemory / 1024),2))
  $MyReport += Get-HTMLDetail "InstallDate" $objOSItem.ConvertToDateTime($objOSItem.InstallDate) #we#
  $MyReport += Get-HTMLDetail "LargeSystemCache" $objOSItem.LargeSystemCache
  $MyReport += Get-HTMLDetail "LastBootUpTime" $objOSItem.ConvertToDateTime($objOSItem.LastBootUpTime)
  $MyReport += Get-HTMLDetail "LocalDateTime" $objOSItem.ConvertToDateTime($objOSItem.LocalDateTime)
  $MyReport += Get-HTMLDetail "MaxNumberOfProcesses" $objOSItem.MaxNumberOfProcesses
  $MyReport += Get-HTMLDetail "MaxProcessMemorySize" $objOSItem.MaxProcessMemorySize
  $MyReport += Get-HTMLDetail "Name" $objOSItem.Name
  $MyReport += Get-HTMLDetail "NumberOfLicensedUsers" $objOSItem.NumberOfLicensedUsers
  $MyReport += Get-HTMLDetail "NumberOfProcesses" $objOSItem.NumberOfProcesses
  $MyReport += Get-HTMLDetail "NumberOfUsers" $objOSItem.NumberOfUsers
  $MyReport += Get-HTMLDetail "Options" $objOSItem.Options
  $MyReport += Get-HTMLDetail "Organization" $objOSItem.Organization
  $MyReport += Get-HTMLDetail "OSLanguage" $objOSItem.OSLanguage
  $MyReport += Get-HTMLDetail "SystemDirectory" $objOSItem.SystemDirectory
  $MyReport += Get-HTMLDetail "SystemDrive" $objOSItem.SystemDrive
  $MyReport += Get-HTMLDetail "TotalSwapSpaceSize" $objOSItem.TotalSwapSpaceSize
  $MyReport += Get-HTMLDetail "TotalVirtualMemorySize (GB)" $($objOSItem.TotalVirtualMemorySize / 1MB)
  $MyReport += Get-HTMLDetail "TotalVisibleMemorySize (GB)" $($objOSItem.TotalVisibleMemorySize / 1MB)
  $MyReport += Get-HTMLDetail "Total Installed Memory (RAM)" $installedRAM
  $MyReport += Get-HTMLDetail "Version" $objOSItem.Version
  $MyReport += Get-HTMLDetail "WindowsDirectory" $objOSItem.WindowsDirectory
  $MyReport += Get-HeaderClose
}
"<-- Exited Operating System Information" | WriteTo-StdOut
#endregion

$OSVersion = $OperatingSystems.Version
$iis_version = GetIISVersion
$temp_sql_ver = getsqlversion $Target
$sql_version = $temp_sql_ver[1].Column1

#region CRM Registry Keys
"--> Entered Registry Information" | WriteTo-StdOut
Write-DiagProgress -Activity $CRMStrings.ID_CRMRegistryKeyInformation -Status $CRMStrings.ID_CRMRegistryKeyObtaining
if (Test-Path HKLM:\Software\Microsoft\MSCRM){
	$MyReport = Get-MSCRMRegistryKeys $MyReport
}else{
	$MyReport += Get-Header "2" "Microsoft Dynamics CRM Registry Key Settings"
	$MyReport += Get-HTMLBasic "Unable to retrieve Microsoft Dynamics CRM registry values."
	$MyReport += Get-HeaderClose
}
"<-- Exited Registry Information" | WriteTo-StdOut
#endregion

#region CRM Server Version Variables
if (Test-CRMServerKey){
	$MSCRMKey = Get-ItemProperty 'HKLM:\Software\Microsoft\MSCRM'
	$server_version = $MSCRMKey.CRM_Server_Version.Substring(0,1)
	$InstallLocation = $MSCRMKey.CRM_Server_InstallDir
	$website_path = $MSCRMKey.WebSitePath
	$cnn = $MSCRMKey.configdb
}
#endregion

#region Microsoft CRM Installed Product and Hotfix Information
$MyReport = GetInstalledProgramHotfixInformation $MyReport
#endregion Product and Hotfix Information

#region CRM Program Files
$MyReport = GetCRMProgramFileInformation $MyReport
#endregion

#region CRM File Listing Installed in Global Assembly Cache
$MyReport = GetCRMGACFileInformation $MyReport
#endregion

#region Running Services Information
$MyReport = GetRunningServicesInformation $MyReport
#endregion

#region Running Processes Information
$MyReport = GetRunningProcessInformation $MyReport
#endregion

#region Event Logs
$MyReport = GetEventLogInformation $MyReport 
"Start of VBS Code for Event Logs"| WriteTo-StdOut
#EME added all events for the last 7 days for UDE analaysis mostly - since the html report below will not be picked up correctly by UDE for analysis
$EventLogNames = "Application", "System"
.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -days 7 -SectionDescription "Event Fog Files with events for the last 7 days"
"End of VBS Code for Event Logs"| WriteTo-StdOut
#endregion

#region IIS Application Pool Information
$MyReport = GetIISAppPoolInformation $MyReport
#endregion

#region Microsoft Dynamics CRM WebSite information
$MyReport = GetCRMWebSiteInformation $MyReport
#endregion 

#region Boot.ini settings
$MyReport = GetBootIniInformation $MyReport
#endregion

#region TCP/IP Information
$MyReport = GetTCPIPInformation $MyReport
#endregion TCP/IP Information

#region SQL Server Instance Information
$MyReport = GetSQLServerInformation -Report $MyReport  -conn_string $cnn $sql_version
#endregion

#region Microsoft Dynamics CRM  Configuration Information
$MyReport = GetCRMConfigurationDatabaseInformation $MyReport -conn_string $cnn
#endregion
#region Organization Statistics
$MyReport = GetCRMOrganizationDetails $MyReport $cnn
#endregion	

#region Dump out Callout.Config.xml if present
# Skip this if this is not V4
#RBJC if ($server_version -eq '4'){
#RBJC 	$MyReport = GetCRMCalloutConfigInformation -Report $MyReport
#RBJC }
#endregion callout.config.xml

#region Collect Files
GetCRMWebConfig
#endregion

# End of Report
#region Close Report and Save to Disk
$MyReport += Get-CustomHTMLClose
$Date = Get-Date
$Filename = ".\" + $Target + "_" + $date.Hour + $date.Minute + "_" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + ".htm"
$MyReport | Out-File -Encoding "UTF8" -FilePath $Filename
#endregion

Function CollectFiles1($filesToCollect, 
				[string]$fileDescription="File", 
				[string]$sectionDescription="Section",
				[boolean]$renameOutput=$false,
				[switch]$noFileExtensionsOnDescription,
				[string]$Verbosity="Informational",
				[System.Management.Automation.InvocationInfo] $InvokeInfo = $MyInvocation){
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
	}
	$AddToStdout = "[CollectFiles] Collecting File(s):`r`n"
	if ($sectionDescription -ne "Section"){
		$AddToStdout += "`r`n          Section    : $sectionDescription" 
	}
	if ($fileDescription -ne "File"){
		$AddToStdout += "`r`n          Description: $fileDescription" 
	}

	$AddToStdout += "`r`n          Files      : $filesToCollect`r`n"
	
	$AddToStdout | WriteTo-StdOut -InvokeInfo $InvokeInfo -ShortFormat

	ForEach ($pathFilesToCollect in $filesToCollect){
		if (($pathFilesToCollect -ne $null) -and (test-path $pathFilesToCollect -ErrorAction SilentlyContinue)){
			$FilestobeCollected = Get-ChildItem  $pathFilesToCollect
			$FilestobeCollected | ForEach-object -process {
				$FileName = Split-Path $_.Name -leaf
				$FileNameFullPath = $_.FullName
				$FileExtension = $_.extension.ToLower()
				if ($noFileExtensionsOnDescription.IsPresent) {
					$ReportDisplayName = $fileDescription
				} else {
					$ReportDisplayName = "$fileDescription ($FileExtension)"
				}
				if($debug -eq $true){"CollectFiles:`r`nFile being collected:`r`n    " + $FileNameFullPath + "`r`nSectionDescription:`r`n    $sectionDescription `r`nFileDescription:`r`n    " + $ReportDisplayName | WriteTo-StdOut -DebugOnly}
				if (Test-Path $FileNameFullPath){
					$m = (Get-Date).ToString()
					if (($renameOutput -eq $true) -and (-not $FileName.StartsWith($ComputerName))) {
							$FileToCollect = $ComputerName + "_" + $FileName
	                		"                         [$m] : $FileName to $FileToCollect"  | Out-File -Encoding "UTF8" -filepath $StdOutFileName -append
							Copy-Item -Path $FileNameFullPath -Destination $FileToCollect 
					} else {
							$FileToCollect = $FileNameFullPath
						"                         [$m] : $FileName" | Out-File -Encoding "UTF8" -filepath $StdOutFileName -append
					}
					#**** Test only
					#$ReportDisplayName += " [" + (FormatBytes -Bytes (Get-Item $FileToCollect).Length) + "]"
									
					$FileToCollectInfo = Get-Item $FileToCollect
					
					if (($FileToCollectInfo.Length) -ge 2147483648){
						$InfoSummary = New-Object PSObject
						$InfoSummary | Add-Member -membertype noteproperty -name $fileDescription -value ("Not Collected. File is too large - " + (FormatBytes -bytes $FileToCollectInfo.Length) + "")
						$InfoSummary | ConvertTo-Xml2 | update-diagreport -id ("CompFile_" + (Get-Random).ToString())  -name $ReportDisplayName -Verbosity "Error"
						"[CollectFiles] Error: $FileToCollect ($fileDescription) will not be collected once it is larger than 2GB. Current File size: " + (FormatBytes -bytes $FileToCollectInfo.Length) | WriteTo-StdOut -InvokeInfo $MyInvocation
					}else{
						Update-DiagReport -Id $sectionDescription -Name $ReportDisplayName -File $FileToCollect -Verbosity $Verbosity
					}
				}else{
					(" " * 31) + "[CollectFiles] " + $FileNameFullPath + " could not be found" | WriteTo-StdOut -InvokeInfo $InvokeInfo -ShortFormat
				}
			}
		} else {
			(" " * 31) + "[CollectFiles] " + $pathFilesToCollect + ": The system cannot find the file(s) specified" | Out-File  -Encoding "UTF8" -filepath $StdOutFileName -append
		}
	}
	"                         -----------------------------------" | Out-File  -Encoding "UTF8" -filepath $StdOutFileName -append
}

$Filename | WriteTo-StdOut
CollectFiles -filesToCollect $Filename -fileDescription "CRM Baseline Data Report" -sectionDescription "CRM Baseline Data Report" -verbosity debug
Update-DiagReport -Id "Microsoft Dynamics CRM Baseline Data Report" -Name "CRM Baseline Data Report" -File $Filename



# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBhRdJu/ld4cQ5e
# CpVotir1AK9PfY+gfGNM2P2a/uI7n6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXUwghlxAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJQAHn4o20TfieTIaE0V9XUh
# cl3hx9cju5excNUbgsfvMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAM+4bws2q4J/5p9aqtJHRMPdeerTavSVKJGvR/HS109yT0+1INTlB2
# jRzV0P7v390pHkBVLGzqPcKV4fAkmxaioRK3fSU27NRd5FX5ZitaJ2cy8hMRylsB
# rhTk8Z3zzxlrTyuCDQCSBgM38FrDGn6qeTAYcS7Oas3zoGrah0ZOlIFQynxajCCF
# E0HWuuQvCOdYcgQxi7ji+EtKpsgHkp7eWBeOnbxMA4d2UXshzPdtRDc/QdeUukH3
# 4tOCsnMQVRHKeZFmiY8nZhOPJUalhVsgYTVrBPZLtVoqZU5wSytgCEpY0YVAXoP+
# OCMTzUimkTXGcHHgBOJpifbeIkB9TVmIoYIW/TCCFvkGCisGAQQBgjcDAwExghbp
# MIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEILV/gVogpVLFd4GhEfoDMuILzSOrQQrHg4zT4mKvMP2tAgZj7jMq
# akAYEzIwMjMwMjI3MDkxMDMxLjQ2NVowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjdCRjEt
# RTNFQS1CODA4MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVDCCBwwwggT0oAMCAQICEzMAAAHI+bDuZ+3qa0YAAQAAAcgwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkw
# MTM3WhcNMjQwMjAyMTkwMTM3WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046N0JGMS1FM0VBLUI4MDgxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC5y51+KE+DJFbCeci4kKpzdMK0WTRc6KYVwqNT1tLp
# YWeDaX4WsiJ3SY9nspazoTCPbVf5mQaQzrH6jMeWY22cdJDjymMgV2UpciiHt9Kj
# jUDifS1AiXCGzy4hgihynvbHAMEcpJnEZoRr/TvTuLI7D5pdlc1xPGA2JEQBJv22
# GUtkzvmZ8kiAFW9SZ0tlz5c5RjDP/y6XsgTO080fhyfwKfS0mEgV+nad62vwZg2i
# LIirG54bv6xK3bFeXv+KBzlwc9mdaF+X09oHj5K62sDzMCHNUdOePhF9/EDhHeTg
# FFs90ajBB85/3ll5jEtMd/lrAHSepnE5j7K4ZaF/qGnlEZGi5z1t5Vm/3wzV6thr
# nlLVqFmAYNAnJxW0TLzZGWYp9Nhja42aU8ta2cPuwOWlWSFhAYq5Nae7BAqr1lNI
# T7RXZwfwlpYFglAwi5ZYzze8s+jchP9L/mNPahk5L2ewmDDALBFS1i3C2rz88m2+
# 3VXpWgbhZ3b8wCJ+AQk6QcXsBE+oj1e/bz6uKolnmaMsbPzh0/avKh7SXFhLPc9P
# kSsqhLT7Mmlg0BzFu/ZReJOTdaP+Zne26XPrPhedKXmDLQ8t6v4RWPPgb3oZxmAr
# Z30b65jKUdbAGd4i/1gVCPrIx1b/iwSmQRuumIk16ZzFQKYGKlntJzfmu/i62Qnj
# 9QIDAQABo4IBNjCCATIwHQYDVR0OBBYEFLVcL0mButLAsNOIklPiIrs1S+T1MB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAMPWclLIQ8OpKCd+QWJ8hu14lvs2RkJtGPnIEaJPV/19Ma9RvkJbuTd5Kne7
# FSqib0tbKRw19Br9h/DSWJsSKb1hGNQ1wvjaggWq2n/uuX2CDrWiIHw8H7q8sSaN
# eRjFRRHxaMooLlDl3H3oHbV9pJyjYw6a+NjEZRHsCf7jnb2VA88upsQpGNw1Bv6n
# 6aRAfZd4xuyHkRAKRO5gCKYVOCe6LZk8UsS4GnEErnPYecqd4dQn2LilwpZ0KoXU
# A5U3yBcgfRHQV+UxwKDlNby/3RXDH+Y/doTYiB7W4Twz1g0Gfnvvo/GYDXpn5zaz
# 6Fgj72wlmGFEDxpJhpyuUvPtpT/no68RhERFBm224AWStX4z8n60J4Y2/QZ3vlji
# Uosynn/TGg6+I8F0HasPkL9T4Hyq3VsGpAtVnXAdHLT/oeEnFs6LYiAYlo4JgsZf
# bPPRUBPqZnYFNasmZwrpIO/utfumyAL4J/W3RHVpYKQIcm2li7IqN/tSh1FrN685
# /pXTVeSsBEcqsjttCgcUv6y6faWIkIGM3nWYNagSBQIS/AHeX5EVgAvRoiKxzlxN
# oZf9PwX6IBvP6PYYZW6bzmARBL24vNJ52hg/IRfFNuXB7AZ0DGohloqjNEGjDj06
# cv7kKCihUx/dlKqnFzZALQTTeXpz+8KGRjKoxersvB3g+ceqMIIHcTCCBVmgAwIB
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
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAsswggI0AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjo3QkYxLUUzRUEtQjgwODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA384TULvGNTQKUgNdAGK5wBjuy7Kg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOemiMcwIhgPMjAyMzAyMjcwOTQxMjdaGA8yMDIzMDIyODA5NDEyN1ow
# dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA56aIxwIBADAHAgEAAgINujAHAgEAAgIR
# sDAKAgUA56faRwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAKW3V9AZi35O
# WbxkbMwyIGRRw8ZnI9c92/00JrQfeiZRjiqlRNjklju2mXOiU6tvnpUzNUaduOf0
# YvvrM4OA7Q+lLf3jMrMiSfXP7+0Uuq19fu5TxfsbvHmKBQc3pvf6S4AEVQk/fJds
# TQ+OLJTVFbCm0evEbDbQq6W49yV77E9NMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHI+bDuZ+3qa0YAAQAAAcgwDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgW6B9hfF1NKQNwlmg9A7VNssq5gqpJOJdwhOj6Vm92JMwgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBiAJjPzT9toy/HDqNypK8vQVbhN28DT2fE
# d+w+G4QDZjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAAByPmw7mft6mtGAAEAAAHIMCIEIPKVoPJYCkL/IioH4stpiXArxuGiLS3Cu78u
# dQvFtpC1MA0GCSqGSIb3DQEBCwUABIICAGBaWBzpIesgJpxyEZ94IlrNFPlYM0Jf
# vukHY7GLMWF/zLh+nZnmOtLQ007hz0nFAdxj8BxWLhROIuqSUfskWEtRCs5gX4vW
# 7X+fCIr7Jof6H7NBIJJh+yuxt4JsJ3rcpB8HMeohkNX34rTbASqFeS5STkBTnlln
# 6tayrvadIMHwfDWkDp8LwnAYnA7/OW5eDy327Sc3kGIrt3dCj6kSee0ff+D7sUeP
# FFa4fqDOKnpOYbFDDUHRkjCF90H+AJKZJ/Qo7cVUiWjsbaYUipx6jddBQdEc0ZF4
# CTWoC1SyfwtDaW0+wmIAHkMMHkEKvzEbi3RzDITU4fMNiARlavdrX3aG0JiXl5wd
# mHLeWcgP+f4O4Dm6bDhr6Q1sywBDWpiIMemxJonKmzqHdQJJZh+WO9Wer8fPZr4T
# 1KY/bY1lUPbfNG1jsopjkU0AmJ6bkfThpCQFUGrDZOIcAvHoylsA+26pIPO6YOoN
# IshjbVxSopmH6CDhU9D6KdMMQaFgZMhdD8FWxZSjJMRyc239Jp/S7zywfIEa0+X0
# 5XE5aJYJtZ1e+WEbaQntbzTkHtCcHOzm/kL/SJe7EN1AESKbGUjKADtxdorKIw+W
# OuhDboUsyjPK1A8xao/XCwwKc31bQhKKrfTLrEl1y+MXkK+wa2KwC/fY0kdzk3BX
# rzhEbj3Kx1JI
# SIG # End signature block
