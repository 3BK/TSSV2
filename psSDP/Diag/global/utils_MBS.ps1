
$ComputerName = $Env:computername
$OSMajorVersion = [Environment]::OSVersion.Version
$shell = New-Object -comobject WScript.Shell

Import-LocalizedData -BindingVariable LocalizedMessages1 

#region SQL Connection and ADO functions
function get-SqlServerList{
	#This function lists the available sql servers based on the Sql browser service and return the list of servers
	[System.Data.Sql.SqlDataSourceEnumerator]::Instance.GetDataSources() | Sort-Object -Property @{Expression='ServerName'}
}

function Verify-ADO-Connection{
	#This function is used to verify an SQL server connection (i.e... that we can connect to sql successfully)
	param(	$SQLNamePlusInstance = '.') 

	$SQLNamePlusInstance | WriteTo-StdOut
	$Error.Clear()

	Write-DiagProgress -Activity $LocalizedMessages1.ID_SystemServiceDiagnostic_SQLConnect -Status $LocalizedMessages1.ID_SystemServiceDiagnostic_SQLConnectDesc 
	#$Shell.Popup($SQLNamePlusInstance)
	
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection 
	$SqlConnection.ConnectionString = 'Server=' + $SQLNamePlusInstance + ';Persist Security Info=False;Integrated Security=SSPI' + ';DataBase=master'
	$SqlConnection.Open()
	trap [Exception] 
   	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("ADODB errors")
		$Error.Clear()
		continue
   	}
	if ($SqlConnection.State -eq 'Open'){
		"SQL Connection is open" | WriteTo-StdOut
		$SqlConnection.close()
		if ($SQLNamePlusInstance){
			return $SQLNamePlusInstance
		}
		else{
			$SQLNamePlusInstance = Get-DiagInput -Id 'SQLServer'  #jc jclauzel Verify-ADO-Connection is never called 
			Verify-ADO-Connection ($SQLNamePlusInstance)
		}
	}
	else{
		"SQL Connection couldn't be opened" | WriteTo-StdOut
		$SQLNamePlusInstance = Get-DiagInput -Id 'SQLServerErr'
		Verify-ADO-Connection ($SQLNamePlusInstance)
	}		
}

function Call-ADO{
#Use this function to create a SQL Data connection and return a dataset from sql.
param
	([string]$SqlCmdTxt,
	 [string]$SQLNamePlusInstance = '.',
	 [string]$DatabaseName = 'master') 

	$Global:SQLError = $null
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlCmd.Commandtext = $SqlCmdTxt
		
	("Sql Server Instance Name = " + $SQLNamePlusInstance) | WriteTo-StdOut
	("Database = " + $DatabaseName)  | WriteTo-Stdout
	("Sql Command Text =" + $SqlCmdTxt) | WriteTo-StdOut

	#[void]$Shell.Popup($DatabaseName)
	#[void]$Shell.Popup($SqlCmdTxt)


	$Error.Clear()

	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection 
	$SqlConnection.ConnectionString = 'Server=' + $SQLNamePlusInstance + ';Persist Security Info=False;Integrated Security=SSPI' + ';DataBase=' + $databasename
	$SqlCmd.Connection = $SqlConnection

	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$SqlAdapter.SelectCommand = $SqlCmd
	$DataSet = New-Object System.Data.DataSet
	$RowCount = $SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()

	trap [Exception] 
   	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("ADODB errors")
		$Error.Clear()
		$Global:SQLError = $_
		continue
   	}
	return $DataSet
}
	
function Call-ADO-With-Parms{
	#Use this function to create a SQL Data connection and return a dataset from sql with parameters.
	param(
	[string]$SqlCmdTxt,
	[string]$SQLNamePlusInstance = '.',
	[string]$DatabaseName = 'master',
	[hashtable]$Parmaters=$null) 

	"--> Entered function Call-ADO-With-Parms" | WriteTo-StdOut
	("Sql Server Instance Name = " + $SQLNamePlusInstance) | WriteTo-StdOut
	("Database = " + $DatabaseName)  | WriteTo-Stdout
	("Sql Command Text =" + $SqlCmdTxt) | WriteTo-StdOut
	
	$Global:SQLError = $null
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlCmd.Commandtext = $SqlCmdTxt

	$Error.Clear()

	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection 
	$SqlConnection.ConnectionString = 'Server=' + $SQLNamePlusInstance + ';Persist Security Info=False;Integrated Security=SSPI' + ';DataBase=' + $databasename
	$SqlCmd.Connection = $SqlConnection
	
	if ($Parmaters){
		$Parmaters.GetEnumerator() | ForEach-Object -Process { 
			$SqlCmd.Parameters.AddWithValue($_.Key, $_.Value)
			("Sql Command Parameter = " + $_.Key) | WriteTo-StdOut
			("Sql Command Value = " + $_.Value) | WriteTo-StdOut
		}
	}
	
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$SqlAdapter.SelectCommand = $SqlCmd
	
	$DataSet = New-Object System.Data.DataSet
	$RowCount = $SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()

	trap [Exception] 
   	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("ADODB errors")
		$Error.Clear()
		continue
   	}
   	"<-- Exited function Call-ADO-With-Parms" | WriteTo-StdOut
	return $DataSet
}

function Call-ADO-Delete{
	#Use this function to create a SQL Data connection and return a dataset from sql.
	param(
	[string]$SqlCmdTxt,
	[string]$SQLNamePlusInstance = '.',
	[string]$DatabaseName = 'master') 

	$Global:SQLError = $null
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlCmd.Commandtext = $SqlCmdTxt
		
	("Sql Server Instance Name = " + $SQLNamePlusInstance) | WriteTo-StdOut
	("Database = " + $DatabaseName)  | WriteTo-Stdout
	("Sql Command Text =" + $SqlCmdTxt) | WriteTo-StdOut

	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection 
	$SqlConnection.ConnectionString = 'Server=' + $SQLNamePlusInstance + ';Persist Security Info=False;Integrated Security=SSPI' + ';DataBase=' + $databasename
	$SqlConnection.Open()
	$SqlCmd.Connection = $SqlConnection
	[int] $results = $SqlCmd.ExecuteNonQuery()
	
	$SqlConnection.Close()
	return $results

	trap [Exception]{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("ADODB errors")
		$Error.Clear()
		$Global:SQLError = $_
		continue
   	}
}

function Call-ADO-SQLCMD{ 
	#works the same as above but is passed a built SqlCommand object instead of just the text query.  Needed if we are building parameters up.
	param(
	[System.Data.SqlClient.SqlCommand]$SqlCmd,
	[string]$SQLNamePlusInstance = '.',
	[string]$DatabaseName = 'master') 

#	("Sql Server Instance Name = " + $SQLNamePlusInstance) | WriteTo-StdOut
#	("Database = " + $DatabaseName)  | WriteTo-Stdout
#	("Sql Command Text =" + $SqlCmd.Commandtext) | WriteTo-StdOut
	
	if ($SqlCmd.Parameters.Count -gt 0){
		foreach($parm in $SqlCmd.Parameters){
			("Sql Command Text Parmater Name = " + $parm.ParameterName) | WriteTo-StdOut
			("Sql Command Text Parmater Value = " + $parm.Value) | WriteTo-StdOut
		}
	}

	#$Error.Clear()

	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection 
	$SqlConnection.ConnectionString = 'Server=' + $SQLNamePlusInstance + ';Persist Security Info=False;Integrated Security=SSPI' + ';DataBase=' + $databasename
	$SqlCmd.Connection = $SqlConnection

	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$SqlAdapter.SelectCommand = $SqlCmd
	$DataSet = New-Object System.Data.DataSet
	$RowCount = $SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	
	trap [Exception]{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("ADODB errors")
		$Error.Clear()
		continue
   	}
	return $DataSet
}

function Call-ADO-WithConnectionString{ 
	#ADO function that takes a Connection String and a Command.
	param( 
		[string]$ConnectionString,
		[string]$cmd
		) 
		$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
		#took out try catch logic to make PS 1.0 compliant
		#clear the error collection so hopefully we only will be examining 1 error at a time in this function
		#$Error.Clear()

		#Write-DiagProgress -Activity $SQLServerNetBiosNames.ID_SQLConnect -Status ($SQLServerNetBiosNames.ID_SQLConnectDesc -replace("%Computer%", $SQLNamePlusInstance))

		("Sql Command Text =" + $cmd) | WriteTo-StdOut
		("Connection =" + $ConnectionString) | WriteTo-StdOut

		$SqlConnection = New-Object System.Data.SqlClient.SqlConnection 
		$SqlConnection.ConnectionString = $ConnectionString
		$SqlCmd.Connection = $SqlConnection
		$SqlCmd.CommandText = $cmd

		$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
		$SqlAdapter.SelectCommand = $SqlCmd
		$DataSet = New-Object System.Data.DataSet
		$RowCount = $SqlAdapter.Fill($DataSet)
		$SqlConnection.Close()

		trap [Exception]{
			WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("ADODB errors")
			$Error.Clear()
			continue
		}
		return $DataSet
}
#endregion

#region Hashtables for Dynamic Interaction windows.
function CreateHashTableForDynamicInteractions{
	#Builds up dynamic hashtable that will be returned for use with Get-Diaginput commandlet
	#Only uses the first column of each record to populate the hashtable.
	PARAM(	[System.Data.DataSet]$DataSetToRead,
			[string]$DescriptionOfDataSet=""
	)
	if ($DataSetToRead.Tables[0].rows.count -lt 1){
		$message = 'No rows in Dataset: ' + $DescriptionOfDataSet
		$message | WriteTo-Stdout
		return
	}	
	$MyHashTable = New-Object System.Collections.Hashtable[] ($DataSetToRead.Tables[0].rows.count)
	$x = 0
	$DataSetToRead.Tables | foreach-object {$_ | foreach-object{
		#will only use the first column of the dataset.
		#builds up dynamic hashtable that will be returned for use with Get-Diaginput commandlet
		$MyHashTable[$x] = @{"Name"=$_[0]; "Value"=$_[0]; "Description"="Company ID = " + $_[0]; "ExtensionPoint"="<Default/>"}
		$x++
		}
	}
	return $MyHashTable
}
#endregion Hashtables for Dynamic Interaction windows.

#region Misc Functions
function is64bit() {    
   if ([IntPtr]::Size -eq 4){ 
   	return $false 
   }else{ 
   	return $true 
   }
}
#endregion Misc Functions

#region Find Product, Version, MachineType
function Get-ProductAndVersion{
	#function checks for the existance of any MBS product, Version, and type of Machine(Client,Server, etc...) then returns a hashtable 
	#since the Hashtable can't have duplicate key we are creating a key based on Product_Version_MachineType, since multiple products could be installed on the same machine.
	#For example: GP and CRM could have clients on the same machine...
	#####################################
	#Dynamics AX releated registry checks
	if(Test-Path("registry::\HKLM\SOFTWARE\Microsoft\Dynamics\6.0")){ 
		$MyHashTable += @{"DynamicsAX_6_Client" = "DynamicsAX_6_Client";}
	}
	
	if(Test-Path("registry::\HKLM\SYSTEM\CurrentControlSet\services\Dynamics Server\6.0")){
		$MyHashTable += @{"DynamicsAX_6_Server" = "DynamicsAX_6_Server";} 
	}		
		
	if(Test-Path("registry::\HKLM\SYSTEM\CurrentControlSet\services\Dynamics Server\5.0")){
		$MyHashTable += @{"DynamicsAX_5_Server" = "DynamicsAX_5_Server";} 
	}
	
	if(Test-Path("registry::\HKLM\SOFTWARE\Microsoft\Dynamics\5.0")){ 
		$MyHashTable += @{"DynamicsAX_5_Client" = "DynamicsAX_5_Client";}
	}
	
	
	if(Test-Path("registry::\HKLM\SYSTEM\CurrentControlSet\services\Dynamics Server\4.0")){
		$MyHashTable += @{"DynamicsAX_4_Server" = "DynamicsAX_4_Server";} 
	}
	
	if(Test-Path("registry::\HKLM\SOFTWARE\Microsoft\Dynamics\4.0")){ 
		$MyHashTable += @{"DynamicsAX_4_Client" = "DynamicsAX_4_Client";}
	}
	
	######################################
	#Dynamics CRM releated registry checks
	if(Test-Path("registry::\HKLM:\SOFTWARE\Microsoft\MSCRM")){
		$MyHashTable += @{"DynamicsCRM_4_Server" = "DynamicsCRM_4_Server";} 
	}	
	
	if(Test-Path("registry::\HKLM:\SOFTWARE\Microsoft\MSCRMClient")){
		$MyHashTable += @{"DynamicsCRM_4_Server" = "DynamicsCRM_4_Client";} 
	}	
	
	#####################################
	#Dynamics GP releated registry checks
	if (is64bit -eq $true){
		if(Test-Path("registry::\HKLM:\SOFTWARE\Wow6432Node\Microsoft\Business Solutions\Great Plains")){
			$MyHashTable += @{"DynamicsGP_10_ClientWOW" = "DynamicsGP_10_ClientWOW";} 
		}
    }else{
	if(Test-Path("registry::\HKLM:\SOFTWARE\Microsoft\Business Solutions\Great Plains")){
		$MyHashTable += @{"DynamicsGP_10_Client" = "DynamicsGP_10_Client";} 
	}
    }

	#######################################
	#Dynamics NAV releated registry checks

	return $MyHashTable
}
#endregion Find Product, Version, MachineType

#region SQL Rules Engine Functions
function Run-SqlRulesEngine{
	#This script engine is a SQL Query engine that runs SQL Queries against any given SQL Server, SQL DB, and Company.
	#The engine takes a parameter called -QueriesPath that is a string for the sql queries file that holds all the queries per/product to run.
	#TO Run script pass the following: For example:
	#	.\TS_SQLRuleProcessor.ps1 -Product "DynamicsAX" -SqlServer "MySqlServer" -Database "MySQLDB" -Version "5.0" -Company "CEU" -QueriesPath "AX_SQLQueries.xml" 

	#Product = product name
	#SQLServer = Name of Sql Server to connect to
	#Database = Name of Db to connect to 
	#Version = version of Product
	#Company = Company to run sql statements against
	#QueriesPath = QueryFile that contains queries to run.
PARAM(	[string]$Product="DynamicsAX",
		[string]$SQLServer="",
		[string]$Database="",
		[string]$Version="5.0",
		[string]$Company="",
		[string]$QueriesPath="")
			
	("Product=" + $Product)  | WriteTo-Stdout
	("SQLServer=" + $SQLServer)  | WriteTo-Stdout
	("Database=" + $Database)  | WriteTo-Stdout
	("Version=" + $Version) | WriteTo-Stdout
	("Company=" + $Company) | WriteTo-Stdout
	("Queryfile=" + $QueriesPath)  | WriteTo-Stdout
		
	#TODO may have adapt code for NAV - Check with String on this...
	$DataAreaID = $Company
	
	#Run rules - pull the sqlqueries from sqlqueries.xml
	$xmlQueryFile = get-content -path $QueriesPath
    $xmlQueryFileXML = [xml]$xmlQueryFile
	
	#using xPath query for issue with cdata-section and PS 1.0
	foreach($query in $xmlQueryFileXML.SelectNodes("//SqlQueries/SQLQuery")){
	#foreach($query in $xmlQueryFileXML.Element.SqlQueries.SQLQuery){
		$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
		$Parameters = $query.Parameters
		if ($Parameters -ne ""){
			$Parameters = $query.Parameters.split(" ")
			#add each key as a parameter in the where clause
			foreach ($Parameter in $Parameters){
				if ($Parameter -eq "@DBName"){
					$SqlCmd.Parameters.AddWithValue($Parameter, $Database.ToString().Trim())
				}
				elseif($Parameter -eq "@DATAAREAID"){
					$SqlCmd.Parameters.AddWithValue($Parameter, $DataAreaID.ToString().Trim())
				}
			}
		}	
		
		$SqlCmd.CommandText = $query.Get_InnerText()
		#if ($query.TSQLQuery."#cdata-section"){
		#	$SqlCmd.CommandText = $query.TSQLQuery."#cdata-section"
		#}
		#else{
		#	$SqlCmd.CommandText = $query.TSQLQuery	
		#}
	
		$DataSet = Call-ADO-SQLCMD -SqlCmd $SqlCmd -SQLNamePlusInstance $SQLServer -DatabaseName $Database
		
		#if ($query.DataCollector -eq "True"){
		#	if ($DataSet.Tables.count -gt 0){
		#		if($DataSet.Tables[0].rows.count -gt 0){
		#			$DataSet.Tables[0] | export-csv -path ($query.SectionDescription + ".csv")
		#			CollectFiles -filesToCollect ($query.SectionDescription + ".csv") -fileDescription $query.SectionDescription -sectionDescription $query.SectionDescription
		#			if ($query.UpdateDiagReport -eq "True"){
		#				$PS_Info_Summary = new-object PSObject
		#				$Columns = $query.ColumnsToDisplay.split(" ")
		#				foreach($Column in $Columns){
		#					add-member -inputobject $PS_Info_Summary -membertype noteproperty -name $Column -value $DataSet.Tables[0].rows[0].$Column
		#				}
		#				$PS_Info_Summary | convertto-xml2 | update-diagreport -id $query.SectionDescription -name $query.SectionDescription -verbosity informational
		#			}	
		#		}
		#	}
		#}
		if ($query.DataCollector -eq "True"){
			Write-DiagProgress -Activity ($LocalizedMessages1.ID_AXSQLDataEngine -replace("%Server%", $Global:SqlServer)) -Status ($LocalizedMessages1.ID_AXSQLDataEngineDesc -replace("%DC_Name%", $query.FileName))
			#$MyReport += Get-Header $query.SectionDescription
			if ($DataSet.Tables.count -gt 0){
				if($DataSet.Tables[0].rows.count -gt 0){
					$filepathCSV = ($Env:COMPUTERNAME + "_" + $query.FileName + ".csv")
					$filepathTXT = ($Env:COMPUTERNAME + "_" + $query.FileName + ".txt")
					$DataSet.Tables[0] | export-csv -path $filepathCSV
					#$DataSet.Tables[0] | format-table -auto -wrap | out-file -filepath $filepathTXT -width 2000
					
					#Array so we can get around limit of format-table and HTML gets rid of extra columns
					$arrayProperty = @()
		            foreach($column in $DataSet.Tables[0].Columns)
		            {
						$arrayProperty += $column.Caption
		            }
					
					#*.TXT Output
					$DataSet.Tables[0] | format-table -auto -wrap -Property $arrayProperty | out-file -filepath $filepathTXT -width 15000
					#$DataSet.Tables[0] | Export-Clixml -Path ($query.FileName + '.xml')
					
 					CollectFiles -filesToCollect $filepathCSV -fileDescription $query.SectionDescription -sectionDescription $query.SectionDescription
					CollectFiles -filesToCollect $filepathTXT -fileDescription $query.SectionDescription -sectionDescription $query.SectionDescription
					if ($query.UpdateDiagReport -eq "True"){
						$PS_Info_Summary = new-object PSObject
						$Columns = $query.ColumnsToDisplay.split(" ")
						foreach($Column in $Columns){
							if ($Column -ne ""){
								add-member -inputobject $PS_Info_Summary -membertype noteproperty -name $Column -value $DataSet.Tables[0].rows[0].$Column
							}
						}
						$PS_Info_Summary | convertto-xml2 | update-diagreport -id $query.SectionDescription -name $query.SectionDescription -verbosity informational
					}
				}
			}
			trap [Exception] 
	       	{
				WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("Function Run-SqlRulesEngine:" + $query.SectionDescription )
				$Error.Clear()
				continue
	       	}
		}
		
		#Execute Rules
		if (($query.RC_Name -ne $null) -and ($query.RC_Name -ne "")){
			Write-DiagProgress -Activity ($LocalizedMessages1.ID_AXSQLRulesEngine -replace("%Server%", $Global:SqlServer)) -Status ($LocalizedMessages1.ID_AXSQLRulesEngineDesc -replace("%RC_Name%", $query.RC_Name))
			if ($DataSet.Tables.count -gt 0){
				if($DataSet.Tables[0].rows.count -gt 0){
					$DataSet.Tables[0] | export-csv -path ($query.RC_Name + ".csv")
					$arrayProperty = @()
		            foreach($column in $DataSet.Tables[0].Columns){
						$arrayProperty += $column.Caption
		            }					
					
					#You need to add the attributes DataCollector and UpdateDiagReport to your Rule if you want data to be collected and to update the html report above.
					#$filepathCSV = ($Env:COMPUTERNAME + "_" + $query.FileName + ".csv")
					#$filepathTXT = ($Env:COMPUTERNAME + "_" + $query.FileName + ".txt")
					#$DataSet.Tables[0] | export-csv -path $filepathCSV
					#$DataSet.Tables[0] | format-table -auto -wrap -Property $arrayProperty | out-file -filepath $filepathTXT -width 15000
					#CollectFiles -filesToCollect ($query.RC_Name + ".csv") -fileDescription $query.RC_Name -sectionDescription $query.SectionDescription
					#CollectFiles -filesToCollect $filepathTXT -fileDescription $query.SectionDescription -sectionDescription $query.SectionDescription

					if($query.ColumnsToDisplay){
						$Columns = $query.ColumnsToDisplay.split(" ")
						$ExtraInfo = @{}						
						foreach($Column in $Columns){
							$ExtraInfo += @{$Column=$DataSet.Tables[0].rows[0].$Column}
						}
					}else{
						$ExtraInfo = @{}
					}
											
					#$ExtraInfo += @{"ErrorInfo"=$DataSet.Tables[0].rows[0].ErrorString}
					#$ExtraInfo += @{"Records affected"=$DataSet.Tables[0].rows.count}
					$ExtraInfo += @{"CheckPointName"=$query.ProcessName}
					$ExtraInfo += @{"Company Name"=$Company}
					$ExtraInfo += @{"SQL Server"=$Global:SqlServer}
					$ExtraInfo += @{"SQL Database"=$Global:Database}
					#$x = New-Object -TypeName xml
					#$cData = $x.CreateCDataSection($SqlCmd.Commandtext)
					#$ExtraInfo += @{"SQL Query Ran"= $cData.OuterXml}

					Write-GenericMessage -RootCauseID $query.RC_Name -Component $query.ProcessName  -ProcessName $query.ProcessName -PublicContentURL $query.KBLink -Verbosity $query.Verbosity  -InformationCollected $ExtraInfo -SupportTopicsID $query.SupportTopic -MessageVersion $query.MessageVersion
					$updateRootCause = $true
					
					trap [Exception] {
						WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("Function Run-SqlRulesEngine:" + $query.RC_Name )
						$Error.Clear()
						continue
			       	}
				}else{
					$updateRootCause = $false
				}
			}else{#Green light
				$updateRootCause = $false
			}
			
			if ($updateRootCause -eq $false){
				Update-DiagRootCause -Id $query.RC_Name -InstanceId $Env:COMPUTERNAME -Detected $false 
			}else{
				Update-DiagRootCause -Id $query.RC_Name -InstanceId $Env:COMPUTERNAME -Detected $true 
			}
			trap [Exception] {
				WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("Function Run-SqlRulesEngineAX:" + $query.RC_Name )
				$Error.Clear()
				continue
		   	}
		}
	}		
}
#endregion SQL Rules Engine Functions

#region WMI and Application Pools
	function global:Get-AppPoolAccount{
		param( 	[string]$ServerName,
				[string]$ApplicationPoolName
				#[string]$FileName
				) 
 		#Get app pool from wmi, this is the name that is needed to setup the service principal names for kerberos
        $objWMI = [WmiSearcher] "Select * From IIsApplicationPoolSetting"  
        $objWMI.Scope.Path = "\\$ServerName\root\microsoftiisv2"  
        $objWMI.Scope.Options.Authentication = [System.Management.AuthenticationLevel]::PacketPrivacy  
        $pools = $objWMI.Get()
        foreach ($pool in $pools)
        {
			#have to do a match in the case of SharePoint - 
            if ($pool.name -match "W3SVC/APPPOOLS/$ApplicationPoolName")
            {
				$pool
                
                #"Configured Application pool name = $poolname  " | Out-File -FilePath $Filename -append
                #"Configured Application pool Identity = $poolidentity " | Out-File -FilePath $Filename -append
            }
        }
	}
	function global:get-AppPoolPID([string]$name, [string]$ComputerName){
		#SQL2008 Service info
	#	1 MSSQLSERVER is the SQL Server service.
	#	2 SQLSERVERAGENT is the SQL Server Agent service.
	#	3 MSFTESQL is the SQL Server Full-text Search Engine service.
	#	4 MsDtsServer is the Integration Services service.
	#	5 MSSQLServerOLAPService is the Analysis Services service.
	#	6 ReportServer is the Reporting Services service.
	#	7 SQLBrowser is the SQL Server Browser service.
   		$list = get-process -ComputerName $ComputerName -name "w3wp"
		if($list){
			foreach($p in $list){ 
			  $filter = "Handle='" + $p.Id + "'"
			  $wmip = Get-CimInstance Win32_Process -filter $filter -ComputerName $ComputerName

			  if($wmip.CommandLine -match "-ap `"(.+)`"")
			  {
			     $appName = $matches[1]
			     $p | add-member NoteProperty AppPoolName $appName
				 #we found the app pool lets return the process.
				 return $p
			  }
			}
		}
	}
	function global:get-WMISQLServiceProperties{
		param( 	[String]$ServerName,
				[int]$ServiceType
			 ) 
	
		$filter = "SQLServiceType = '" + $ServiceType + "'"
		Get-CimInstance -ComputerName $ServerName -namespace root\Microsoft\SqlServer\ComputerManagement10 -class SqlService -Filter $filter
	}
	function global:Get-SSRSIdentityConfigured{ 
		param( 	[string]$ServerName,
				[string]$RSInstanceName
				) 
				
		#$rs = Get-CimInstance -computer $ServerName -namespace "root\Microsoft\SqlServer\ReportServer\$RSInstanceName\v10\Admin" MSReportServer_ConfigurationSetting
				
 		#Get the configured WindowsServiceIdentityConfigured from wmi for SSRS for SQL 2008 server.
        $objWMI = [WmiSearcher] "Select * From MSReportServer_ConfigurationSetting"  
        $objWMI.Scope.Path = "\\$ServerName\root\Microsoft\SqlServer\ReportServer\$RSInstanceName\v10\Admin"  
		#$objWMI.Scope.Path = "\\$ServerName\root\Microsoft\SqlServer"  
        $objWMI.Scope.Options.Authentication = [System.Management.AuthenticationLevel]::PacketPrivacy  
        $SSRSWMIConfig = $objWMI.Get()
		foreach($prop in $SSRSWMIConfig){
			 $prop
		}
        
	}
#endregion WMI and Application Pools

#region Eventlog Functions
Function Get-DynamicsEvents{
	PARAM(
		[Int32]$EventID,
		[string]$LogName = "Application",
		[string]$Source = "Dynamics*",
		[string]$Age = 10,
		[string]$Server = $Env:COMPUTERNAME		
	)
	$events = $null
	
	$events = Get-EventCache -Logname $LogName -EntryType $EntryType -Server $Server -Age $Age | `
				? {$_.EventID -eq $EventID -and $_.Source -like $Source}
	$events
}
Function Get-EventCache{
	PARAM(
		[string]$LogName = "Application",
		[Int32]$Age = 10,
		[string]$Server = $Env:COMPUTERNAME
	)
	if ($eventCaches[$LogName] -eq $null)
	{
		# We don't already have this cached. Let's go do it
		"Caching $($LogName) event logs for last $($Age) days on $($Server)" | WriteTo-StdOut
		$eventCaches[$LogName] = Get-EventLog -LogName $LogName -ComputerName $Server `
									-After (Get-Date).AddDays(-$Age) -ErrorAction SilentlyContinue
		"$(($eventCaches[$LogName]).Count) items cached" | WriteTo-StdOut
	}
	$eventCaches[$LogName]
}
#endregion Eventlog Functions

#region NAV specific Functions
 function GetNAVVersion{
 PARAM(
		[string]$SqlServer = "",
		[string]$Database = ""
	)
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlCmd.CommandText = @'
	select
		case
			when databaseversionno = 1 then '2.50 (1)'
			when databaseversionno = 2 then '2.50 (2)'
			when databaseversionno = 3 then '2.50 (3)'
			when databaseversionno = 4 then '2.50 (4)'
			when databaseversionno = 5 then '2.60 A-C (5)'
			when databaseversionno = 6 then '2.60 D-F (6)'
			when databaseversionno = 7 then '3.00 (7)'
			when databaseversionno = 8 then '3.00 (8)'
			when databaseversionno = 9 then '3.00 (9)'
			when databaseversionno = 10 then '3.00 (10)'
			when databaseversionno = 11 then '3.00 (11)'
			when databaseversionno = 12 then '3.01 Base, A,B (12)'
			when databaseversionno = 13 then '3.10 Base, A (13)'
			when databaseversionno = 14 then '3.60 (14)'
			when databaseversionno = 15 then '3.70 (15)'
			when databaseversionno = 16 then '3.70 HF 5 (16)'
			when databaseversionno = 17 then '3.70 HF 12 (17)'
			when databaseversionno = 18 then '3.70 B (18)'
			when databaseversionno = 20 then '4.00 (20)'
			when databaseversionno = 30 then '4.00 (30)'
			when databaseversionno = 40 then '4.10 (40)'
			when databaseversionno = 50 then '4.20 (50)'
			when databaseversionno = 60 then '4.20 (60)'
			when databaseversionno = 61 then '4.20 (61)'
			when databaseversionno = 62 then '4.20 (62)'
			when databaseversionno = 63 then '4.30 (63)'
			when databaseversionno = 80 then '5.00 (80)'
			when databaseversionno = 81 then '5.00 (81)'
			when databaseversionno = 82 then '5.00 (82)'
			when databaseversionno = 95 then '5.00 SP1 (95)'
			when databaseversionno = 100 then '5.00 SP1 Update 1 (100)'
			when databaseversionno = 105 then '5.00 SP1 Update 2 (105)'
			when databaseversionno = 120 then '6.00 CTP1 (120)'
			when databaseversionno = 130 then '6.00 CTP2 (130)'
			when databaseversionno = 140 then '6.00 (140)'
			when databaseversionno = 150 then '6.00 SP1 (150)'
			when databaseversionno = 60200 then '6.00 R2 (60200)'
            when databaseversionno = 60210 then '6.00 R2 (60210)'
			when databaseversionno = 60220 then '6.00 R2 (60220)'
            when databaseversionno = 70340 then '7.00 (70340)'
		end 'DB Version'
		from [$ndo$dbproperty] (nolock)
'@

	$DataSet = Call-ADO-SQLCMD -SqlCmd $SqlCmd -SQLNamePlusInstance $SqlServer -DatabaseName $Database
	$Content = $DataSet.Tables[0] | format-table -auto | out-string
	$os_path = $SqlServer.split('\')[0] + "_DBVersion.txt"
	$Content | out-file $os_path
	CollectFiles -filesToCollect $os_path -fileDescription '' -sectionDescription 'NAV Database Version'

	if($DataSet.Tables[0].rows.count -gt 0){
		foreach($row in $DataSet.Tables[0]){
			("Version from Utils = " + $row.'DB Version') | WriteTo-StdOut
			$Version = $row.'DB Version'.ToString()
			return $Version
		}
	}
}
#endregion NAV specific Functions

#region Custom HTML Report Functions
##############################################################################################################
#						FUNCTIONS
##############################################################################################################
function Get-CustomHTML ($Header){
$Report = @"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN" "http://www.w3.org/TR/html4/frameset.dtd">
<html><head><title>$($Header)</title>
<META http-equiv=Content-Type content='text/html; charset=utf8'>

<meta name="save" content="history">

<style type="text/css">
DIV .expando {DISPLAY: block; FONT-WEIGHT: normal; FONT-SIZE: 8pt; RIGHT: 8px; COLOR: #ffffff; FONT-FAMILY: Arial; POSITION: absolute; TEXT-DECORATION: underline}
TABLE {TABLE-LAYOUT: auto; FONT-SIZE: 100%; WIDTH: 100%; white-space:nowrap;}
*{margin:0}
.dspcont { display:none; BORDER-RIGHT: #B1BABF 1px solid; BORDER-TOP: #B1BABF 1px solid; PADDING-LEFT: 16px; FONT-SIZE: 8pt;MARGIN-BOTTOM: -1px; PADDING-BOTTOM: 5px; MARGIN-LEFT: 0px; BORDER-LEFT: #B1BABF 1px solid; WIDTH: 95%; COLOR: #000000; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #B1BABF 1px solid; FONT-FAMILY: Tahoma; POSITION: relative; BACKGROUND-COLOR: #f9f9f9}
.filler {BORDER-RIGHT: medium none; BORDER-TOP: medium none; DISPLAY: block; BACKGROUND: none transparent scroll repeat 0% 0%; MARGIN-BOTTOM: -1px; FONT: 100%/8px Tahoma; MARGIN-LEFT: 43px; BORDER-LEFT: medium none; COLOR: #ffffff; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: medium none; POSITION: relative}
.save{behavior:url(#default#savehistory);}
.dspcont1{ display:none}
a.dsphead0 {BORDER-RIGHT: #B1BABF 1px solid; PADDING-RIGHT: 5em; BORDER-TOP: #B1BABF 1px solid; DISPLAY: block; PADDING-LEFT: 5px; FONT-WEIGHT: bold; FONT-SIZE: 8pt; MARGIN-BOTTOM: -1px; MARGIN-LEFT: 0px; BORDER-LEFT: #B1BABF 1px solid; CURSOR: hand; COLOR: #FFFFFF; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #B1BABF 1px solid; FONT-FAMILY: Tahoma; POSITION: relative; HEIGHT: 2.25em; WIDTH: 95%; BACKGROUND-COLOR: #CC0000}
a.dsphead1 {BORDER-RIGHT: #B1BABF 1px solid; PADDING-RIGHT: 5em; BORDER-TOP: #B1BABF 1px solid; DISPLAY: block; PADDING-LEFT: 5px; FONT-WEIGHT: bold; FONT-SIZE: 8pt; MARGIN-BOTTOM: -1px; MARGIN-LEFT: 0px; BORDER-LEFT: #B1BABF 1px solid; CURSOR: hand; COLOR: #ffffff; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #B1BABF 1px solid; FONT-FAMILY: Tahoma; POSITION: relative; HEIGHT: 2.25em; WIDTH: 95%; BACKGROUND-COLOR: #7BA7C7}
a.dsphead2 {BORDER-RIGHT: #B1BABF 1px solid; PADDING-RIGHT: 5em; BORDER-TOP: #B1BABF 1px solid; DISPLAY: block; PADDING-LEFT: 5px; FONT-WEIGHT: bold; FONT-SIZE: 8pt; MARGIN-BOTTOM: -1px; MARGIN-LEFT: 0px; BORDER-LEFT: #B1BABF 1px solid; CURSOR: hand; COLOR: #ffffff; MARGIN-RIGHT: 0px; PADDING-TOP: 4px; BORDER-BOTTOM: #B1BABF 1px solid; FONT-FAMILY: Tahoma; POSITION: relative; HEIGHT: 2.25em; WIDTH: 95%; BACKGROUND-COLOR: #7BA7C7}
a.dsphead1 span.dspchar{font-family:monospace;font-weight:normal;}
td {VERTICAL-ALIGN: TOP; FONT-FAMILY: Tahoma}
th {VERTICAL-ALIGN: TOP; COLOR: #CC0000; TEXT-ALIGN: left}
BODY {margin-left: 4pt} 
BODY {margin-right: 4pt} 
BODY {margin-top: 6pt} 
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
<b><font face="Tahoma,Verdana" size="5">$($Header)</font></b><hr size="6" color="#d6e8ff">
<font face="Tahoma,Verdana" size="1"><b>Version 1.0  | Microsoft Dynamics Support</b></font><br>
<font face="Tahoma,Verdana" size="1">Report created on $(Get-Date)</font>
<div class="filler"></div>
<div class="filler"></div>
<div class="filler"></div>
<div class="save">
"@
Return $Report
}
function Get-Header ($Num, $Title){
$Report = @"
	<h2><a href="javascript:void(0)" class="dsphead$($Num)" onclick="dsp(this)">
	<span class="expando">show</span>$($Title)</a></h2>
	<div class="dspcont">
"@
	Return $Report
}
Function Get-HTMLDetail ($Heading, $Detail){
$Report = @"
<TABLE>
	<tr>
	<th width='25%'><b>$($Heading)</b></font></th>
	<td width='75%'>$($Detail)</td>
	</tr>
</TABLE>
"@
Return $Report
}
Function Get-HeaderClose{
	$Report = @"
		</DIV>
		<div class="filler"></div>
"@
	Return $Report
}
function Get-CustomHTMLClose{
	$Report = @"
</div>

</body>
</html>
"@
	Return $Report
}
Function Get-HTMLTable{
	param([array]$Content)
	$HTMLTable = $Content | ConvertTo-Html
	$HTMLTable = $HTMLTable -replace '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">', ""
	$HTMLTable = $HTMLTable -replace '<html xmlns="http://www.w3.org/1999/xhtml">', ""
	$HTMLTable = $HTMLTable -replace '<head>', ""
	$HTMLTable = $HTMLTable -replace '<title>HTML TABLE</title>', ""
	$HTMLTable = $HTMLTable -replace '&lt;', "<"
	$HTMLTable = $HTMLTable -replace '&gt;', ">"
	$HTMLTable = $HTMLTable -replace '</head><body>', ""
	$HTMLTable = $HTMLTable -replace '</body></html>', ""
	Return $HTMLTable
}
Function Get-HTMLBasic ($Detail){
$Report = @"
<TABLE>
	<tr>
		<td width='75%'>$($Detail)</td>
	</tr>
</TABLE>
"@
Return $Report
}
function Html-Encode( [string] $value ){
    $value = $value -replace "&(?![\w#]+;)", "&amp;"
    $value = $value -replace "<(?!!--)", "&lt;"
    $value = $value -replace "(?<!--)>", "&gt;"
    $value = $value -replace "’", "&#39;"
    $value = $value -replace '["“”]', "&quot;"
    $value = $value -replace "\n", "<br />"
    $value
}
Function Get-HTMLFile ([string]$Content){	$HTMLTable = $Content #| ConvertTo-Html
	$HTMLTable = $HTMLTable -replace '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">', ""
	$HTMLTable = $HTMLTable -replace '<html xmlns="http://www.w3.org/1999/xhtml">', ""
	$HTMLTable = $HTMLTable -replace '<head>', ""
	$HTMLTable = $HTMLTable -replace '<title>HTML TABLE</title>', ""
	$HTMLTable = $HTMLTable -replace '&lt;', "<"
	$HTMLTable = $HTMLTable -replace '&gt;', ">"
	$HTMLTable = $HTMLTable -replace '</head><body>', ""
	$HTMLTable = $HTMLTable -replace '</body></html>', ""
	Return $HTMLTable
}
#endregion
 	
#region NetBIOS name verify
function global:VerifyNetBIOSName{ 
	param( 	[string]$ServerName
			) 
	Write-DiagProgress -Activity $LocalizedMessages1.ID_GetNetBIOSName -Status ($LocalizedMessages1.ID_GetNetBIOSNameStatus -replace("%ComputerName%",$ServerName))
	#Write-DiagProgress -Activity $GetOverLayerStrings.ID_AOTLayers -Status ($GetOverLayerStrings.ID_AOTLayersDesc -replace("%AOTLAYER%",$AOTpath))
	$pingStatus = Test-Connection $ServerName -ErrorAction SilentlyContinue
	if ($pingStatus){
		return $true
	}else{
		return $false
	}
}
#endregion

#region WCF
function Compile-Code {
    param (
        [string] $code       = $(throw "The parameter -code is required.")
      , [string[]] $references = @()
      , [switch]   $asString   = $false
      , [switch]   $showOutput = $false
      , [switch]   $csharp     = $true
      , [switch]   $vb         = $false
    )
    $options    = New-Object "System.Collections.Generic.Dictionary``2[System.String,System.String]";
    $options.Add( "CompilerVersion", "v3.5")
    if ( $vb ) {
        $provider = New-Object Microsoft.VisualBasic.VBCodeProvider $options
    } else {
        $provider = New-Object Microsoft.CSharp.CSharpCodeProvider $options
    }
    $parameters = New-Object System.CodeDom.Compiler.CompilerParameters
	
	$ref = @("mscorlib.dll", "System.dll", "System.Core.dll", "System.Xml.dll",
	[Reflection.Assembly]::LoadWithPartialName("System.ServiceModel").Location,
	[Reflection.Assembly]::LoadWithPartialName("System.Runtime.Serialization").Location,
	([System.Reflection.Assembly]::GetAssembly( [PSObject] ).Location) ) + $references | Sort -unique |% { $parameters.ReferencedAssemblies.Add( $_ ) } | Out-Null
    
    $parameters.GenerateExecutable = $false
    $parameters.GenerateInMemory   = !$asString
    $parameters.CompilerOptions    = "/optimize"
	
    if ( $asString ) {
        $parameters.OutputAssembly = [System.IO.Path]::GetTempFileName()
    }
	$parameters 
	$code 
    $results = $provider.CompileAssemblyFromFile( $parameters, $code )
    if ( $results.Errors.Count -gt 0 ) {
        if ( $output ) {
            $results.Output |% { Write-Output $_ }
        } else {
            $results.Errors |% { Write-Error $_.ToString() }
        }
    } else {
        if ( $asString ) {
            $content = [System.IO.File]::ReadAllBytes( $parameters.OutputAssembly )
            $content = [Convert]::ToBase64String( $content )
            [System.IO.File]::Delete( $parameters.OutputAssembly );
            return $content
        } else {
            return $results.CompiledAssembly
        }        
    }
}
#endregion WCF

$eventCaches = @{}

Function ExecuteXMLSqlQueryFile($Path){
	# Running the XML sql query.
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "Error on Execute XML Sql Query File"
		continue
	}
	#Check the XML Query file is existing or not, if not existing, exit the function
	If(-not(Test-Path $Path))
	{
		"[Error][ExecuteXMLSqlQueryFile] Can not find the XML Sql Query File:" + $Path | WriteTo-StdOut
		return		
	}
	#Run rules - pull the sqlqueries from xml file passed
	$xmlQueryFile = get-content -path $Path
	$xmlQueryFileXML = [xml]$xmlQueryFile
	foreach($query in $xmlQueryFileXML.Element.SqlQueries.SQLQuery){
		$HasRootCauseName = (($query.RC_Name -ne $null) -and ($query.RC_Name -ne ""))
		$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
		$Parameters = $query.Parameters
		if ($Parameters -ne ""){
			$Parameters = $query.Parameters.split(" ")
			#add each key as a parameter in the where clause
			#change this if parameters are added to where clause @item = "101"
			#add each key as a parameter in the where clause
			foreach ($Parameter in $Parameters){
				if ($Parameter -eq "@DBName"){
					$SqlCmd.Parameters.AddWithValue($Parameter, $Database.ToString().Trim())
				}
				elseif($Parameter -eq "@DATAAREAID"){
					$SqlCmd.Parameters.AddWithValue($Parameter, $DataAreaID.ToString().Trim())
				}
				elseif($Parameter -eq "@FANo_"){
					$SqlCmd.Parameters.AddWithValue($Parameter,  $Global:FANO.ToString().Trim())
					("Fix Assets No for @FANo_ Parmater = " +  $Global:FANO.ToString().Trim())  | WriteTo-Stdout
				}
			}
		}	
		if ($query.TSQLQuery."#cdata-section"){
			if ($query.TSQLQuery.ReplaceText -ne ""){
				$ReplacementQuery = ($query.TSQLQuery."#cdata-section" -replace('@Company', $CompanyNameConverted))
				$SqlCmd.CommandText = $ReplacementQuery
			}else{
				$SqlCmd.CommandText = $query.TSQLQuery."#cdata-section"
		    }
		}
		else{
			if ($query.TSQLQuery.ReplaceText -ne ""){
				$ReplacementQuery = ($query.TSQLQuery -replace('@Company', $CompanyNameConverted))
				$SqlCmd.CommandText = $ReplacementQuery
			}
			else{
				$SqlCmd.CommandText = $query.TSQLQuery	
			}
		}	

		if($HasRootCauseName){
			Write-DiagProgress -Activity ($LocalizedMessages1.ID_SQLRulesEngine -replace('%Server%', $SQLServer)) -Status ($LocalizedMessages1.ID_SQLRulesEngineDesc -replace('%RC_Name%', $query.RC_Name))
		}
		$DataSet = Call-ADO-SQLCMD -SqlCmd $SqlCmd -SQLNamePlusInstance $SqlServerPlusInstance -DatabaseName $Database
		
		if ($DataSet.Tables.count -gt 0){
			if($DataSet.Tables[0].rows.count -gt 0){
				# Remove the timestamp column if table has this column
				if($DataSet.Tables[0].Columns.Contains("timestamp"))
				{
					$DataSet.Tables[0].Columns.Remove("timestamp")
				}
				$DataSet.Tables[0] | export-csv -path ($query.FileName + ".csv") -NoTypeInformation
				#[void]$shell.popup($query.SectionDescription)
				CollectFiles -filesToCollect ($query.FileName + ".csv") -fileDescription $query.fileDescription -sectionDescription $query.SectionDescription  
				if ($Error.Count -gt 0){
					("ERROR=" + $Error) | WriteTo-StdOut
				}
				#Rule 1 : NAV Version
				if ($query.RuleID -eq "1"){
					("Global:NAVVersion = " + $Global:NAVVersion) | WriteTo-StdOut
					$Global:NAVVersion = $DataSet.Tables[0].Rows[0]["DB_Version"]
					$ExtraInfo =  @{"CheckPointName"=$query.ProcessName}
					$ExtraInfo += @{"NAV Version"=$($DataSet.Tables[0].Rows[0]["DB_Version"])}
					$ExtraInfo += @{"Company Name"=$CompanyNameConverted}
					$ExtraInfo += @{"SQL Server"=$SqlServerPlusInstance}
					$ExtraInfo += @{"SQL Database"=$DatabaseName}
					$ExtraInfo += @{"Records affected"=$DataSet.Tables[0].rows.count}
					$ExtraInfo += @{"Record Details"=($query.FileName + ".csv")}
						
					$VersionInfo_Summary = new-object PSObject
					add-member -inputobject $VersionInfo_Summary -membertype noteproperty -name "Version" -value $Global:NAVVersion
					$VersionInfo_Summary | convertto-xml2 | update-diagreport -id 01_Hotfix_Summary -name ($env:computername + " - NAV Version information") -verbosity informational
						
					#[void]$shell.popup($DataSet.Tables[0].rows.count)
					#Create a warning if unsupported
					if ($DataSet.Tables[0].Rows[0]["DB_Version"] -match 'Unsupported'){
						#Create Warning Message Yellow 
						if($HasRootCauseName){
							Update-DiagRootCause -Id $query.RC_Name -Detected $true 
							Write-GenericMessage -RootCauseID $query.RC_Name -Verbosity "Warning" -Component $query.SupportTopic  -ProcessName $query.ProcessName -PublicContentURL $query.KBLink -InformationCollected $ExtraInfo		
						}											
					}else{
							#Create informational Message White
							if($HasRootCauseName){
								Update-DiagRootCause -Id $query.RC_Name -Detected $false
								Write-GenericMessage -RootCauseID $query.RC_Name -Verbosity "Informational" -Component $query.SupportTopic  -ProcessName $query.ProcessName -PublicContentURL $query.KBLink -InformationCollected $ExtraInfo					
							}								
					}
					#[void]$shell.popup($ExtraInfo)
				}
			}
		}else{
				#Green light
				if($HasRootCauseName)
				{
					Update-DiagRootCause -Id $query.RC_Name -Detected $false
				}
		}
	}
}

Function Is64BitMachine{
	if($OSArchitecture -eq "X86"){
		return $false
	}else{
		return $true
	}
}

Function PrintFileVersionInfoToCSVFile($Files, [string]$OutPutFileName, [string]$FileDescription){
	$HasOutPut = $false
	$StringBuilder = New-Object -TypeName System.Text.StringBuilder
	[void]$StringBuilder.Append("Create:,"+[DateTime]::Now+"`r`n")
	[void]$StringBuilder.Append("Computer:,"+ $ComputerName+"`r`n`r`n")
	[void]$StringBuilder.Append("[$FileDescription]`r`n")
	[void]$StringBuilder.Append(",,,FileName,ProductVersion,FileVersion,CompanyName,FileDescription,File Size,LastWriteTime`r`n")
	Foreach($file in $Files){
		if(Test-Path $file){
			$HasOutPut = $true
			[void]$StringBuilder.Append(",,," +$File+",")
			$FileItem = Get-ItemProperty $file
			if($FileItem.VersionInfo.ProductVersion -ne $null){
				[void]$StringBuilder.Append("("+$FileItem.VersionInfo.ProductVersion.Replace(",",".")+"	),("+$FileItem.VersionInfo.FileVersion.Replace(",",".")+"	),"+$FileItem.VersionInfo.CompanyName.Replace(",",".")+","+$FileItem.VersionInfo.FileDescription.Replace(",",".")+","+$FileItem.Length+","+$FileItem.LastWriteTime+"`r`n")
			}else{
				[void]$StringBuilder.Append(",,,,"+$FileItem.Length+",,,"+$FileItem.LastWriteTime+",,,,,`r`n")
			}
		}else{
			"[PrintFileVersionInfoToCSVFile] The file ($file) is not existing" | WriteTo-StdOut -ShortFormat
		}
	}
	if($HasOutPut){
		$StringBuilder.ToString() | Out-File $OutPutFileName -Encoding "UTF8"
	}
}


# SIG # Begin signature block
# MIInwwYJKoZIhvcNAQcCoIIntDCCJ7ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCNHfg4V073mkhp
# I2MNN328j6l+AMDHMWtFnFIkAX4mfKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGaMwghmfAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHvPIyhk/fSDs3YQ2O+qkjJN
# bxq9caE27TYGKeLAjY+YMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBXBXtdASk75Ku2HLwPYMVL1f4fXHlS/akezBd/uEW2u5+HSPkVGLEe
# rvxD+Bm58nstzhN6bdsCClRn1uIIIfLbcoUW2HwpM0Do7ES1IKstjXt5yFeuvG0c
# xDddXy9hjtj2AVZNuKvN6xAT20vBpKmy6AzrnZRG+XybjkD6B9u4YcYhJElD/zB+
# RJKS14pf62WaGS+NJ7cmbpKLuyAceS6XNEeQ0BsiJRGaybB4hG9pW80Pj4z5k/qD
# joDw/pVQuPhbVm4MqvGiUiJsOw+fCVa1kCzZ93RUZB9scQQzRRwN6299Y3x6o1YX
# Rp0QSAj3RTidbuKCsDFi3TWVm66b2jn2oYIXKzCCFycGCisGAQQBgjcDAwExghcX
# MIIXEwYJKoZIhvcNAQcCoIIXBDCCFwACAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIAl7kBWEU//CBo3KWyWMGCNRiyuzuZYdp1Pys8vD5UWdAgZj91lq
# R6gYEzIwMjMwMjI3MDkyMTU3LjUwOFowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046OEQ0MS00QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF6MIIHJzCCBQ+gAwIBAgITMwAAAbP+Jc4pGxuKHAABAAABszAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MjA5MjAyMDIyMDNaFw0yMzEyMTQyMDIyMDNaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhENDEt
# NEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHwPuuYYgK4ssGCCsr2N
# 7eElKlz0JPButr/gpvZ67kNlHqgKAW0JuKAy4xxjfVCUev/eS5aEcnTmfj63fvs8
# eid0MNvP91T6r819dIqvWnBTY4vKVjSzDnfVVnWxYB3IPYRAITNN0sPgolsLrCYA
# KieIkECq+EPJfEnQ26+WTvit1US+uJuwNnHMKVYRri/rYQ2P8fKIJRfcxkadj8CE
# PJrN+lyENag/pwmA0JJeYdX1ewmBcniX4BgCBqoC83w34Sk37RMSsKAU5/BlXbVy
# Du+B6c5XjyCYb8Qx/Qu9EB6KvE9S76M0HclIVtbVZTxnnGwsSg2V7fmJx0RP4bfA
# M2ZxJeVBizi33ghZHnjX4+xROSrSSZ0/j/U7gYPnhmwnl5SctprBc7HFPV+BtZv1
# VGDVnhqylam4vmAXAdrxQ0xHGwp9+ivqqtdVVDU50k5LUmV6+GlmWyxIJUOh0xzf
# Qjd9Z7OfLq006h+l9o+u3AnS6RdwsPXJP7z27i5AH+upQronsemQ27R9HkznEa05
# yH2fKdw71qWivEN+IR1vrN6q0J9xujjq77+t+yyVwZK4kXOXAQ2dT69D4knqMlFS
# sH6avnXNZQyJZMsNWaEt3rr/8Nr9gGMDQGLSFxi479Zy19aT/fHzsAtu2ocBuTqL
# VwnxrZyiJ66P70EBJKO5eQECAwEAAaOCAUkwggFFMB0GA1UdDgQWBBTQGl3CUWdS
# DBiLOEgh/14F3J/DjTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAWoa7N86wCbjA
# Al8RGYmBZbS00ss+TpViPnf6EGZQgKyoaCP2hc01q2AKr6Me3TcSJPNWHG14pY4u
# hMzHf1wJxQmAM5Agf4aO7KNhVV04Jr0XHqUjr3T84FkWXPYMO4ulQG6j/+/d7gqe
# zjXaY7cDqYNCSd3F4lKx0FJuQqpxwHtML+a4U6HODf2Z+KMYgJzWRnOIkT/od0oI
# Xyn36+zXIZRHm7OQij7ryr+fmQ23feF1pDbfhUSHTA9IT50KCkpGp/GBiwFP/m1d
# rd7xNfImVWgb2PBcGsqdJBvj6TX2MdUHfBVR+We4A0lEj1rNbCpgUoNtlaR9Dy2k
# 2gV8ooVEdtaiZyh0/VtWfuQpZQJMDxgbZGVMG2+uzcKpjeYANMlSKDhyQ38wboAi
# vxD4AKYoESbg4Wk5xkxfRzFqyil2DEz1pJ0G6xol9nci2Xe8LkLdET3u5RGxUHam
# 8L4KeMW238+RjvWX1RMfNQI774ziFIZLOR+77IGFcwZ4FmoteX1x9+Bg9ydEWNBP
# 3sZv9uDiywsgW40k00Am5v4i/GGiZGu1a4HhI33fmgx+8blwR5nt7JikFngNuS83
# jhm8RHQQdFqQvbFvWuuyPtzwj5q4SpjO1SkOe6roHGkEhQCUXdQMnRIwbnGpb/2E
# sxadokK8h6sRZMWbriO2ECLQEMzCcLAwggdxMIIFWaADAgECAhMzAAAAFcXna54C
# m0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMy
# MjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51
# yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY
# 6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9
# cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN
# 7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDua
# Rr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74
# kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2
# K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5
# TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZk
# i1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9Q
# BXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3Pmri
# Lq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUC
# BBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9y
# eS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUA
# YgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
# 1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIw
# MTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/yp
# b+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulm
# ZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM
# 9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECW
# OKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4
# FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3Uw
# xTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPX
# fx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVX
# VAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGC
# onsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU
# 5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEG
# ahC0HVUzWLOhcGbyoYIC1jCCAj8CAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjhENDEtNEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBxi0Tolt0eEqXCQl4qgJXUkiQOYaCBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA56Z0VzAiGA8yMDIzMDIyNzA4MTQxNVoYDzIwMjMwMjI4MDgxNDE1WjB2MDwG
# CisGAQQBhFkKBAExLjAsMAoCBQDnpnRXAgEAMAkCAQACASACAf8wBwIBAAICEs4w
# CgIFAOenxdcCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQDCQx5FNe3BH69o
# AdAbIZSEI1lawH0EIHqMHn9ipDmOJwzOGzMPjQ7l4UjXjlOIJ899pm7erozh0d6l
# L8TRM39CSqM3+P+SppQFvXMQ7A9ZnEmnHPS8/hy/8L2M2KAgl/n37Zbwni6WpPzk
# ZJACUKV3SI+2SMsyH5v0H/BA0e0aIjGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABs/4lzikbG4ocAAEAAAGzMA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIC5mlTSjLKciI3UZANWeMeZiQnEpH9DygcHLMlfwrvvSMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQghqEz1SoQ0ge2RtMyUGVDNo5P5ZdcyRoeijoZ
# ++pPv0IwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AbP+Jc4pGxuKHAABAAABszAiBCBrsLleqTugnLR/kAuojsM4pQ0CKJ2mpaT6PIyB
# IMDM0DANBgkqhkiG9w0BAQsFAASCAgAgiFEdyPyf5ZPsctdITXDaNFrV7bvKNMcU
# 92yOxK4AKb9JiSph1GCAjz4NOC93UtJ0yxIvIJT+rNgrsUsDxQDdNLvsvlpJ88PD
# nBuJBOJdwF3VC9ihwSSdxJYXf2wi3Q33uvE9xGwy1futWsBMedjSdMQoDKTWx7bf
# sbJFjlQBzFessDzdVokFkTGsMhqVhmwy3oRI9etoh6IkYj1mvULo5zsFafMM/e5i
# L9AzBZs4NmjlehcMCBkmed2rv4xwLmj9TdZ2crfD1lbtVqu9VdqSx/PTYpDnLKBv
# dn0PaESLhEB9ptf+GG0oyDeMB3zWX1rRi1mmXF81oKA6OgnZlDs5itllkgQBK+m5
# +Re/WHzMc9IDmgGvD6FeVj/Vx9blmieVjKTq4a7CstwBX/1No05w69KdRGZKhTji
# +1H5r5Nk53S028XemjC+XNgq6Y5Jc5/pWObH+Tn8nkC5BYxtuh48bj1ZhqASoxve
# PusMkz+8J0EoxCg/qX39xLoZqzNAX0Uctl4+3pT5f9A54/hM9MKflBSVwlxnGvKA
# G3yHNymv79n++pFRYgeqmM4F89GVwndq2U+ES74RJlSk5H1/WXp451QJ3dtAhRiv
# KbVhA1xHsyMfAdhgzm7ZvHy+VTCGxiM579KWmh06oUTANeaKzZKlKQWEjrXQO6dl
# TPouwZh6zg==
# SIG # End signature block
