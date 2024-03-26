# This script has dependencies on utils_CTS and utils_DSD
#
param ( [Object[]] $instances, [switch]$CollectSqlDefaultDiagnosticXeLogs ,[switch]$CollectFailoverClusterDiagnosticXeLogs ,[switch]$CollectAlwaysOnDiagnosticXeLogs )  

# Certain properties of the SQL 2012 Failover Cluster and Always On XE logs can be customized.  
# The custom values are stored in registry values under key:
# HKLM:\Software\Microsoft\Microsoft SQL Server\<instance root>\MSSQLServer key
#
New-Variable LogFileRolloverCount		-Value "LogFileRolloverCount"   -Option ReadOnly
New-Variable LogMaxFileSizeINMBytes		-Value "LogMaxFileSizeINMBytes" -Option ReadOnly
New-Variable LogPath					-Value "LogPath"                -Option ReadOnly
New-Variable LogIsEnabled				-Value "LogIsEnabhled"          -Option ReadOnly


#
# Function : Get-XeDirectoryPathDefault
# -------------------------------------
#
# PowerShell Version:
#			Written to be compatible with PowerShell 1.0
#
# Visibility:
#			Private/Internal - Do not call this function from your PowerShell scripts.  
#
# Description:
# 			This function is used to find the path to the SQL Server errorlog for a given instance of SQL Server
# 
# Arguments:
#			$InstanceName
#			Function will find the default path to the SQL Server XE Health logs
# 
# Owner:
#			DanSha 
#
function Get-XeDirectoryPathDefault([string]$SqlInstance )
{
	$Error.Clear()           
	trap 
	{
		'[Get-XeDirectoryPathDefault] : [ERROR] Trapped exception ...' | WriteTo-StdOut
		Report-Error
	}

	return (Get-SqlServerLogPath -SqlInstance $SqlInstance)
}

#function CollectAndCompress-XeLogFiles ( [string]$XeLogDir, [bool] $IsClustered, [string]$instance, [string]$FileFilter )
#{     
#    trap 
#    {
#    	'[CollectAndCompress-XeLogFiles] : [ERROR] Trapped exception ...' | WriteTo-StdOut
#    	Report-Error 
#    }
#    
#    if ($FileFilter.Contains("SQLDIAG"))
#    {
#        $XeType = "Failover_Cluster_Diagnostics_health"
#    } 
#    elseif ($FileFilter.Contains("system_health"))
#    {
#        $XeType = "System_health"
#    }
#    elseif ($FileFilter.Contains("AlwaysOn"))
#    {
#        $XeType = "AlwaysOn_health"
#    }   
#    
#    if (Test-Path -Path $XeLogDir -Type "Container")
#    {
#        # Collect specified XE log files.  Have 90+ percent compression ratio so not worried about number and size
#        $XeLogfiles = get-childitem -Path (Join-Path $XeLogDir "*") -Include $FileFilter | foreach-object { Join-Path $_.DirectoryName $_.Name }
#        
#         if ($null -ne $XeLogfiles)
#         {
#            if (0 -lt $XeLogfiles.Count)
#    		{	
#				"[CollectAndCompress-XeLogFiles] : Found {0} {1} XE logs" -f $XeLogFiles.Count, $XeType | WriteTo-StdOut
#						
#    			# Compress and collect the XE files for this instance
#    			$ArchiveOut = "{0}_{1}_{2}_XeFiles.zip" -f $ComputerName, $instance, $XeType
#    			CompressCollectFiles -FilesToCollect $XeLogfiles -DestinationFileName $ArchiveOut -SectionDescription ("SQL Server {0} health files for instance: {1}" -f $XeType, $instance)
#    		}
#         }
#		 else
#		 {
#			"[CollectAndCompress-XeLogFiles] : Found 0 {1} XE logs" -f $XeType | WriteTo-StdOut
#		 }
#    }
#    else 
#	{
#		# Here is where we should do the check to see if this is a cluster and whether the drive is offline
#		"[CollectAndCompress-XeLogFiles] : Path to SQL XE logs: [{0}] for instance: {1} is invalid" -f $XeLogDir, $InstanceToCollect | WriteTo-StdOut
#			
#		# Check if drive that errorlogs are stored on is a cluster resource if the instance is clustered
#		if ($IsClustered)
#		{
#			$ParsedPath = $SqlErrorLogPath.Path.Split("\")
#			$ClusterDrive = $ParsedPath[0]
#			# Call function FindSqlDiskResource to see if the cluster resource is unavailable
#			#
#			if ($false -eq (FindSQLDiskResource($ClusterDrive)))
#			{
#				"[CollectAndCompress-XeLogFiles] : The cluster resource: [{0}] that the XE log files for instance: {1} are stored on is not available at this time" -f $ClusterDrive, $InstanceToCollect | WriteTo-StdOut
#			}
#		}
#	}
#    
#}

# Checks to see if customer set a custom diagnostics log location using ALTER SERVER CONFIGURATION DIAGNOSTICS LOG
function Get-XeDirectoryPathCustom ([string] $InstanceName)
{   
    trap 
    {
    	"[Get-XeDirectoryPathCustom] : [ERROR] Trapped exception ..." | WriteTo-StdOut
    	Report-Error 
    }  

    if ($null -ne $InstanceName)
    {
    	$SqlRootKey =  Get-SqlInstanceRootKey $InstanceName   
        
        # First make sure we have a valid "root" key for this instance
        if (Test-Path -Path $SqlRootKey)
        {
            if ($null -ne $SqlRootKey)
            {
                 if ($true -eq (Test-RegistryValueExists (Join-Path -Path $SqlRootKey -ChildPath "MSSQLSERVER") $LogPath))
                 {
                    #Customer has modified the default XE log path with the ALTER SERVER 
                    [System.IO.Path]::GetDirectoryName((Get-ItemProperty (Join-Path $SqlRootKey "MSSQLSERVER")).$LogPath)
                 }
             }
         }
    } # if ($null -eq $InstanceName)
    else
    {
        '[Get-XeDirectoryPathCustom] : [ERROR] Required parameter -InstanceName not specified' | WriteTo-StdOut
    }
}


# This function retrieves the directory path for the Failover Cluster XE logs and Always On 
function Get-XeDirectoryPath ([string] $InstanceName)
{
    trap 
    {
    	"[Get-XeDirectoryPath] : [ERROR] Trapped exception ..." | WriteTo-StdOut
    	Report-Error
    }
    
	# Validate required parameter was supplied
	if ($null -ne $InstanceName)
	{
	    # The XE log path can be customized using the ALTER SERVER DIAGNOSTICS command for FCI and AlwaysOn (but not default system health)
	    # so try to retrieve custom path first. If found, we will use that instead of the default path.
	    $XeLogPath = Get-XeDirectoryPathCustom $InstanceName
	    
	    if ($null -eq $XeLogPath )
	    {
	        # Custom path not set; retrieve default XE log path
	        $XeLogPath = Get-XeDirectoryPathDefault $InstanceName
	    }
    }
	else
	{
		'[Get-XeDirectoryPath] : [ERROR] Required parameter -InstanceName was not supplied' | WriteTo-StdOut
	}
    return $XeLogPath
}

function Collect-SqlXeGeneralHealthSessionLogs ([string]$InstanceName, [bool]$IsClustered)
{
    $Error.Clear()           
    trap 
    {
    	"[Collect-SqlXeHealthSessionLogs] : [ERROR] Trapped exception ..." | WriteTo-StdOut
    	Report-Error 
    }
    
	if ($null -ne $InstanceName)
    {
        if (($true -eq $IsClustered) -or ($false -eq $IsClustered))
        {
            # Post progress message to dialog visible to user
        	Write-DiagProgress -Activity $xeHealthLogsCollectorStrings.ID_SQL_CollectSqlXeGeneralHealthLogs -Status ($xeHealthLogsCollectorStrings.ID_SQL_CollectSqlXeGeneralHealthalLogDesc + ": " + $InstanceName)

            # SQL Health sessions are always in default log folder. Not configurable
            $XeHealthSessionLogDir = Get-XeDirectoryPathDefault $InstanceName 
            
            if ($null -ne $XeHealthSessionLogDir)
            {
                # Valid path?
                if ($true -eq (Test-Path -Path $XeHealthSessionLogDir))
                {
                    $FciFiles = @()
    				$FciFiles = Copy-FileSql -SourcePath $XeHealthSessionLogDir `
                             -FileFilters @('system_health*.XEL') `
                             -FilePolicy $global:SQL:FILE_POLICY_SQL_SERVER_SYSTEM_HEALTH_XELOGS  `
                             -InstanceName $InstanceName `
    						 -SectionDescription ("'General System Health logs for instance {0}" -f $InstanceName) `
                             -CompressCollectedFiles `
                             -ZipArchiveName ("{0}_{1}_system_health_XeLogs.zip" -f $ComputerName, $InstanceName)
                }
                else
                {
                    # Does the log path reference a cluster disk that is offline from this node at this time?
                    if ($true -eq (Check-IsSqlDiskResourceOnline -InstanceName $InstanceName -PathToTest $XeHealthSessionLogDir))
        	        {
        	            "[Collect-SqlXeGeneralHealthSessionLogs] : [ERROR] No Sql General System Health logs will be collected. Path to General Health XE logs: [{0}] for instance: [{1}] is invalid" -f $XeHealthSessionLogDir, $InstanceName | WriteTo-StdOut
        	        } 
                }
            }
            else
            {
                '[Collect-SqlXeGeneralHealthSessionLogs] : [ERROR] Get-XeDirectoryPathDefault returned a null path to Sql Server general system health Xe logs' | WriteTo-StdOut
            }
        
        } #if (($true -eq $IsClustered) -or ($false -eq $IsClustered))
        else
        {
            '[Collect-SqlXeGeneralHealthSessionLogs] : [ERROR] Required parameter -IsClustered was not specified or contains an incorrect value' | WriteTo-StdOut
        }
        
    } # if ($null -ne $InstanceName)
    else
    {
        '[Collect-SqlXeGeneralHealthSessionLogs] : [ERROR] Required parameter -InstanceName was not specified' | WriteTo-StdOut
    }
	
}

#
# Function : Collect-SqlFailoverClusterDiagnosticXeLogs
# -----------------------------------------------------
#
# PowerShell Version:
#			Written to be compatible with PowerShell 1.0
#
# Visibility:
#			Private/Internal - Do not call this function from your PowerShell scripts.  
#
# Description:
# 			This function enumerates the Failover Cluster Diagnostic Xel files and calls the CollectAndCompress-XeLogFiles
#           to collect the log files from the customer machine.
#           Note that there can be quite a large number of these files present on a server at any given time.
#           We do not limit the number or age of the files we collect because they compress at better than 90% compression ratio
# 
# Arguments:
#			$InstanceName
#			Instance that Xe logs will be collected for
#           $IsClustered
#           Is the instance clustered?  Only really needed to detect if the drive we need to collect the logs from is offline from the node we are collecting on
# 
# Owner:
#			DanSha 
#
function Collect-SqlFailoverClusterDiagnosticXeLogs ( [string]$InstanceName, [bool]$IsClustered )
{
    $Error.Clear()           
    trap 
    {
    	'[Collect-SqlXeFailoverClusterLogs] : [ERROR] Trapped exception ...' | WriteTo-StdOut
    	Report-Error
    }
    
	# Post progress message to dialog visible to user
	Write-DiagProgress -Activity $xeHealthLogsCollectorStrings.ID_SQL_CollectSqlXeFailoverClusterlHealthLogs -Status ($xeHealthLogsCollectorStrings.ID_SQL_CollectSqlXeFailoverClusterlHealthLogsDesc + ": " + $InstanceName)

    if ($null -ne $InstanceName) 
    {
        if (($true -eq $IsClustered) -or ($false -eq $IsClustered))
        {
            $XeFailoverClusterLogPath = Get-XeDirectoryPath $InstanceName 

        	if ($null -ne $XeFailoverClusterLogPath)
            {
                if ($true -eq (Test-Path -Path $XeFailoverClusterLogPath))
            	{
                    # FCI XEL Filename Format: <COMPUTER_NAME>_<INSTANCE_NAME>_SQLDIAG_*  
                    # Actual Example:          215126NEWNODE2_MSSQLSERVER_SQLDIAG_0_129719944456780000.xel
                    # Search Mask:             *<INSTANCE_NAME>_SQLDIAG*.XEL
                    #
                    # These files are created on a shared drive (cluster resource) and the file name includes the name of the node where the file was created.  
                    # As such, we cannot include the COMPUTER_NAME in the -FileFilter argument as this part of the file name will be determined by 
                    # the NETBIOS computer name of the node SQL Server was executing on at the time the file was created
                   	                    # Enumerate and then copy the files
                                                
    				$FciFiles = @()
    				$FciFiles = Copy-FileSql -SourcePath $XeFailoverClusterLogPath `
                             -FileFilters @("*_{0}_SQLDIAG*.XEL" -f $InstanceName) `
                             -FilePolicy $global:SQL:FILE_POLICY_SQL_SERVER_FAILOVER_CLUSTER_XELOGS `
                             -InstanceName $InstanceName `
    						 -SectionDescription ("'Failover Cluster Health logs for instance {0}" -f $InstanceName) `
                             -CompressCollectedFiles `
                             -ZipArchiveName ("{0}_{1}_FailoverCluster_health_XeLogs.zip" -f $ComputerName, $InstanceName)
                             
                   # Report outcome of collection to stdout.log
                   if (($null -ne $FciFiles) -and (0 -lt $FciFiles.Count))
                   {
                        "[Collect-SqlXeFailoverClusterHealthLogs] : [INFO] [{0}] Sql Failover Cluster diagnostic logs collected for instance: [{0}]" -f $InstanceName | WriteTo-StdOut
                   }
                   else
                   {
                        "[Collect-SqlXeFailoverClusterHealthLogs] : [INFO] No Sql Failover Cluster diagnostic logs collected for instance: [{0}]" -f $InstanceName | WriteTo-StdOut
                   }
                   
            	} #if ($true -eq (Test-Path -Path $XeFailoverClusterLogPath))
                else
                {
        			if ($true -eq (Check-IsSqlDiskResourceOnline -InstanceName $InstanceName -PathToTest $XeFailoverClusterLogPath))
        	        {
        	            "[Collect-SqlXeFailoverClusterHealthLogs] : [ERROR] No SQL Sql Failover Cluster diagnostic logs will be collected. Path to failover cluster diagnositcs logs: [{0}] for instance: {1} is invalid" -f $XeFailoverClusterLogPath, $InstanceName | WriteTo-StdOut
        	        }      
                }
            
            } # if ($null -ne $XeFailoverClusterLogPath)
            else
            {
                "[Collect-SqlFailoverClusterDiagnosticXeLogs] : [ERROR] Get-XeDirectoryPath returned a null log path for instance: [{0}]" -f $InstanceName | WriteTo-StdOut
            }
            
            
        }  # if (($true -eq $IsClustered) -or ($false -eq $IsClustered))
        else
        {
            '[Collect-SqlFailoverClusterDiagnosticXeLogs] : [ERROR] Required parameter -IsClustered was not specified' | WriteTo-StdOut
        }

    } # if ($null -ne $InstanceName)
    else
    {
        '[Collect-SqlFailoverClusterDiagnosticXeLogs] : [ERROR] Required parameter -InstanceName was not specified' | WriteTo-StdOut
    }
}

#
# Function : Collect-SqlAlwaysOnDiagnosticXeLogs
# ----------------------------------------------
#
# PowerShell Version:
#			Written to be compatible with PowerShell 1.0
#
# Visibility:
#			Private/Internal - Do not call this function from your PowerShell scripts.  
#
# Description:
# 			This function drives logic to collect the AlwaysOn Diagnostic logs
# 
# Arguments:
#			$InstanceName
#			Instance that Xe logs will be collected for
#           $IsClustered
#           Is the instance clustered?  Only really needed to detect if the drive we need to collect the logs from is offline from the node we are collecting on
# 
# Owner:
#			DanSha 
#
# Sample AlwaysOn file name:
#           AlwaysOn_health_0_129736303650760000.xel
#
function Collect-SqlAlwaysOnDiagnosticXeLogs( [string] $Instance, [bool] $IsClustered )
{
    $Error.Clear()           
    trap 
    {
    	'[Collect-SqlAlwaysOnDiagnosticXeLogs] : [ERROR] Trapped exception ...' | WriteTo-StdOut
    	Report-Error
    }  
    
    If ($null -ne $Instance)
    {
        if (($true -eq $IsClustered) -or ($false -eq $IsClustered))
        {
        	# Post progress message to dialog visible to user
        	Write-DiagProgress -Activity $xeHealthLogsCollectorStrings.ID_SQL_CollectSqlXeGeneralHealthLogs -Status ($xeHealthLogsCollectorStrings.ID_SQL_CollectSqlXeGeneralHealthalLogDesc + ": " + $Instance)
            
        	$XeAlwaysOnLogPath = Get-XeDirectoryPath -InstanceName $Instance 
            
        	if ($null -ne $XeAlwaysOnLogPath)
            {
                if ($true -eq (Test-Path -Path $XeAlwaysOnLogPath))
            	{
                                
                    # Enumerate and then copy the files
    				$Files = @()
    				$Files = Copy-FileSql -SourcePath $XeAlwaysOnLogPath `
                             -FileFilters @('AlwaysOn_health*.XEL') `
                             -FilePolicy $global:SQL:FILE_POLICY_SQL_SERVER_ALWAYSON_XELOGS `
                             -InstanceName $Instance `
    						 -SectionDescription ("'AlwaysOn Health logs for instance {0}" -f $Instance) `
                             -CompressCollectedFiles `
                             -ZipArchiveName ("{0}_{1}_AlwaysOn_health_XeLogs.zip" -f $ComputerName, $Instance)
                    
                    # Report number of logs enumerated and copied
                    if (($null -ne $Files) -and (0 -lt $Files.Count))
                    {
                        "[Collect-SqlXeAlwaysOnHealthLogs] : [INFO] Collected [{0}] AlwaysOn diagnostic logs for instance: [{1}]" -f $Files.Count, $Instance | WriteTo-StdOut
                    }
                    else
                    {
                        "[Collect-SqlXeAlwaysOnHealthLogs] : [INFO] No AlwaysOn diagnostic logs were collected for instance: [{0}]" -f $Instance | WriteTo-StdOut
                    }
                    
                }
                else
                {
                    # Does the log path reference a cluster disk that is offline from this node at this time?
                    if ($true -eq (Check-IsSqlDiskResourceOnline -InstanceName $Instance -PathToTest $XeAlwaysOnLogPath))
        	        {
        	            "[Collect-SqlXeAlwaysOnHealthLogs] : [ERROR] No SQL Server AlwaysOn diagnostic logs will be collected. Path to AlwaysOn Diagnostic logs: [{0}] for instance: [{1}] is invalid" -f $XeAlwaysOnLogPath, $Instance | WriteTo-StdOut
        	        }
                      
                }
                
            } # if ($null -ne $XeAlwaysOnLogPath)
            else
            {
                "[Collect-SqlXeAlwaysOnHealthLogs] : [ERROR] Get-XeDirectoryPath returned a null path to the AlwaysOn Xe logs for instance: [{0}]" -f $Instance | WriteTo-StdOut
            }
            
        } # if ($null -ne $IsClustered)
        else
        {
            "[Collect-SqlXeAlwaysOnHealthLogs] : [ERROR] Required parameter -IsClustered was not specified" | WriteTo-StdOut
        }
        
    } # If ($null -ne $Instance)
    else
    {
        "[Collect-SqlXeAlwaysOnHealthLogs] : [ERROR] Required parameter -Instance was not specified" | WriteTo-StdOut
    }
}

#
# Function : Collect-SqlXeLogs
# ----------------------------
#
# PowerShell Version:
#			Written to be compatible with PowerShell 1.0
#
# Visibility:
#			Private/Internal - Do not call this function from your PowerShell scripts.  
#
# Description:
# 			This function is a wrapper that drives Xe log collection based on switch parameters that the script is called with
# 
# Arguments:
#			$InstanceName
#			Instance that Xe logs will be collected for
#           $IsClustered
#           Is the instance clustered?  Only really needed to detect if the drive we need to collect the logs from is offline from the node we are collecting on
# 
# Owner:
#			DanSha 
#
function Collect-SqlXeLogs ( [string] $InstanceName, [bool] $IsClustered )
{
    $Error.Clear()           
    trap 
    {
    	'[DC-GetSqlXeLogs] : [ERROR] Trapped exception ...' | WriteTo-StdOut
    	Report-Error
    }    
    
    if ($null -ne $InstanceName)
    {
        if (($true -eq $IsClustered) -or ($false -eq $IsClustered))
        {
            # Collect Sql Server General/Default Diagnostic Session Xe Log files?    
            if ($true -eq $CollectSqlDefaultDiagnosticXeLogs)
            {
                # Collect the Health Session XE files that are on by default
                Collect-SqlXeGeneralHealthSessionLogs -InstanceName $InstanceName -IsClustered $IsClustered
            }
            else
            {
                # Echo collection option to stdout.log
                '[Collect-SqlXeLogs] : [INFO] Sql Default Health Session Xe log collection bypassed. $CollectSqlHealthXeLogs: {0}' -f $CollectSqlDefaultDiagnosticXeLogs | WriteTo-StdOut
            }
            
            # Collect failover cluster diagnostic Xe log files?
            if ($true -eq $CollectFailoverClusterDiagnosticXeLogs)
            {
                # Collect the SQL Server failover cluster diagnostic log files
                Collect-SqlFailoverClusterDiagnosticXeLogs -InstanceName $InstanceName -IsClustered $IsClustered 
            }
            else
            {
                # Echo collection option to stdout.log
                '[Collect-SqlXeLogs] : [INFO] Sql Failover Cluster Diagnostic Xe log collection bypassed. $CollectFailoverClusterDiagnosticXeLogs: {0}' -f $CollectFailoverClusterDiagnosticXeLogs | WriteTo-StdOut
            }
            
            # Collect Always On Diagnostic Xe logs?
            if ($true -eq $CollectAlwaysOnDiagnosticXeLogs)
            {
                # Collect the Always On diagnostic log files
                Collect-SqlAlwaysOnDiagnosticXeLogs -Instance $InstanceName -IsClustered $IsClustered 
            }
            else
            {
                # Echo collection option to stdout.log
                '[Collect-SqlXeLogs] : [INFO] Sql AlwaysOn Diagnostic Xe log collection bypassed. $CollectAlwaysOnHealthXeLogs: {0}' -f $CollectAlwaysOnHealthXeLogs | WriteTo-StdOut
            }
                
        } # if ($null =ne $IsClustered)
        else
        {
            '[Collect-SqlXeLogs] : [ERROR] Required parameter -IsClustered was not secified' | WriteTo-StdOut
        }
        
    } # if ($null -eq $InstanceName)
    else
    {
          '[Collect-SqlXeLogs] : [ERROR] Required parameter -InstanceName was not secified' | WriteTo-StdOut
    }
}
	
$Error.Clear()           
trap 
{
   	'[DC_GetSqlXeLogs] : [ERROR] Trapped exception ...' | WriteTo-StdOut
   	Report-Error
}  

Import-LocalizedData -BindingVariable xeHealthLogsCollectorStrings

# Check to be sure that there is at least one SQL Server installation on target machine before proceeding
#
if ($true -eq (Check-SqlServerIsInstalled))
{
	# If $instance is null, get errorlogs for all instances installed on machine
	#
	if ($null -eq $instances)
	{
		$instances = Enumerate-SqlInstances -Offline
	}
    
    if (($null -ne $instances) -and (0 -lt $instances.count))
    {
        foreach ($instance in $instances)
        {
			# Only try to collect these logs on SQL Sever 2012 or later
            if ($global:SQL:SQL_VERSION_MAJOR_SQL2012 -le $instance.SqlVersionMajor)
			{
				if ('DEFAULT' -eq $instance.InstanceName.ToUpper() ) {$instance.InstanceName = 'MSSQLSERVER'}
                
				Collect-SqlXeLogs -InstanceName $instance.InstanceName -IsClustered $instance.IsClustered 
			}
			else
			{
				"[DC-GetSqlXeLogs] : No SQL Server system health logs were collected for instance {0}" -f $instance.InstanceName | WriteTo-StdOut
				"[DC-GetSqlXeLogs] : SQL instance must be SQL Server 2012 or later.  Major version for instance {0} is {1}" -f $instance.InstanceName, $instance.SqlVersionMajor | WriteTo-StdOut
			}
            
        } # foreach ($instance in $instances)
        
    } # if (($null -ne $instances) -and (0 -lt $instances.count))
    else
    {
        'DC-GetSqlXeLogs] : [ERROR] Enumerate-SqlInstances returned a null instance array' | WriteTo-StdOut
    }
}
else
{
    "[DC-GetSqlXeLogs] : [INFO] SQL Server is not installed on computer: [{0}]" -f $env:ComputerName | WriteTo-StdOut
}


# SIG # Begin signature block
# MIInoQYJKoZIhvcNAQcCoIInkjCCJ44CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBLKRe+zvefKO33
# 92ruBchjPOKGI5wydOxi+D0ufH+RGaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGYEwghl9AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHg0ukq5pnFvILba2adr5/Ev
# d/3PUMgnY3OoT7Cx1p6VMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAoz/Untx43ZD31vZNxqgp9bs9dWLRogIgvZRPiWLc/pNMnx9wWIbA0
# nHvzhs1/AK/x3TLh7xaaLFSLVSsfC7ya/vHHTmsTdjW5ugD+C7zpC2LNP3uEGsif
# xGSBu5Wu1iqNeNQfNeCv6LJuZ1+3tpjM6fv9dbJJHDXAIsEpMOhCaJl/F2g0aNz4
# wieujB7Pnoln5SpRtP/IOtNd0pjzPtUuyaBX2ndQ0xpQ2t4cYS1LD5Aq2tvII9J5
# VgRnqhIosdzbRk7kclb8Kj8Kr+LXkEcFE5s2ERUK5l7/OECqhlslXb4PsT52etCM
# w6JSejx9WpxXiJw03grestvO+bTWBiehoYIXCTCCFwUGCisGAQQBgjcDAwExghb1
# MIIW8QYJKoZIhvcNAQcCoIIW4jCCFt4CAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEILi43d2OLeEtXz+tFCERrZg5JCUhLfuulgk2+BGygK17AgZi2xAP
# SaEYEzIwMjIwODAxMDc0MDI3Ljg0MVowBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4
# OTdBLUUzNTYtMTcwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaCCEVwwggcQMIIE+KADAgECAhMzAAABqwkJ76tj1OipAAEAAAGrMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMDMw
# MjE4NTEyOFoXDTIzMDUxMTE4NTEyOFowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4OTdBLUUzNTYtMTcw
# MTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmdS1o5dehASUsscLqyx2wm/WirNUfq
# kGBymDItYzEnoKtkhrd7wNsJs4g+BuM3uBX81WnO270lkrC0e1mmDqQt420Tmb8l
# wsjQKM6mEaNQIfXDronrVN3aw1lx9bAf7VZEA3kHFql6YAO3kjQ6PftA4iVHX3JV
# v98ntjkbtqzKeJMaNWd8dBaAD3RCliMoajTDGbyYNKTvxBhWILyJ8WYdJ/NBDpqP
# zQl+pxm6ZZVSeBQAIOubZjU0vfpECxHC5vI1ErrqapG+0oBhhON+gllVklPAWZv2
# iv0mgjCTj7YNKX7yL2x2TvrvHVq5GPNa5fNbpy39t5cviiYqMf1RZVZccdr+2vAp
# k5ib5a4O8SiAgPSUwYGoOwbZG1onHij0ATPLkgKUfgaPzFfd5JZSbRl2Xg347/Lj
# WQLR+KjAyACFb06bqWzvHtQJTND8Y0j5Y2SBnSCqV2zNHSVts4+aUfkUhsKS+GAX
# S3j5XUgYA7SMNog76Nnss5l01nEX7sHDdYykYhzuQKFrT70XVTZeX25tSBfy3Vac
# zYd1JSI/9wOGqbFU52NyrlsA1qimxOhsuds7Pxo+jO3RjV/kC+AEOoVaXDdminsc
# 3PtlBCVh/sgYno9AUymblSRmee1gwlnlZJ0uiHKI9q2HFgZWM10yPG5gVt0prXnJ
# Fi1Wxmmg+BH/AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUFFvO8o1eNcSCIQZMvqGf
# dNL+pqowHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgw
# VjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWlj
# cm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUF
# BwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
# KS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQsFAAOCAgEAykuUgTc1KMszMgsHbhgjgEGv/dCHFf0by99C45SR770/udCN
# NeqlT610Ehz13xGFU6Hci+TLUPUnhvUnSuz7xkiWRru5RjZZmSonEVv8npa3z1Qv
# eUfngtyi0Jd6qlSykoEVJ6tDuR1Kw9xU9yvthZWhQs/ymyOwh+mxt0C9wbeLJ92e
# r2vc9ly12pFxbCNDJ+mQ7v520hAvreWqZ02GOJhw0R4c1iP39iNBzHOoz+DsO0sY
# jwhaz9HrvYMEzOD1MJdLPWfUFsZ//iTd3jzEykk02WjnZNzIe2ENfmQ/KblGXHeS
# e8JYqimTFxl5keMfLUELjAh0mhQ1vLCJZ20BwC4O57Eg7yO/YuBno+4RrV0CD2gp
# 4BO10KFW2SQ/MhvRWK7HbgS6Bzt70rkIeSUto7pRkHMqrnhubITcXddky6GtZsmw
# M3hvqXuStMeU1W5NN3HA8ypjPLd/bomfGx96Huw8OrftcQvk7thdNu4JhAyKUXUP
# 7dKMCJfrOdplg0j1tE0aiE+pDTSQVmPzGezCL42slyPJVXpu4xxE0hpACr2ua0LH
# v/LB6RV5C4CO4Ms/pfal//F3O+hJZe5ixevzKNkXXbxPOa1R+SIrW/rHZM6RIDLT
# JxTGFDM1hQDyafGu9S/a7umkvilgBHNxZfk0IYE7RRWJcG7oiY+FGdx1cs0wggdx
# MIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGI
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylN
# aWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5
# MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciEL
# eaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa
# 4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxR
# MTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEByd
# Uv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi9
# 47SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJi
# ss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+
# /NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY
# 7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtco
# dgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH
# 29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94
# q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcV
# AQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0G
# A1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQB
# gjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# GQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB
# /wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0f
# BE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJv
# ZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4w
# TDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIB
# AJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRs
# fNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6
# Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveV
# tihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKB
# GUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoy
# GtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQE
# cb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFU
# a2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+
# k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0
# +CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cir
# Ooo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICzzCCAjgCAQEwgfyh
# gdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAn
# BgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjo4OTdBLUUzNTYtMTcwMTElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAW6h6/24WCo7W
# Zz6CEVAeLztcmD6ggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQUFAAIFAOaRa9gwIhgPMjAyMjA4MDEwMTAwMDhaGA8yMDIy
# MDgwMjAxMDAwOFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5pFr2AIBADAHAgEA
# AgIG1DAHAgEAAgIRNzAKAgUA5pK9WAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUA
# A4GBAAEU+pL+fVXcuqgydyRS2xu0KXbaAiTD3MltCnjkn3ekNvFgcP+4OrTJe4DA
# punTRCb4bvJrYifK/egPCUPI67+Obaj9M50cuVtH9NzEUFs8QheQObEU6tG04X/B
# v0cqzEG3yZKdp0O0h1k6MMtIrIccKN3JPMbdFmEHAeb7w1TAMYIEDTCCBAkCAQEw
# gZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGrCQnvq2PU6KkA
# AQAAAaswDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0B
# CRABBDAvBgkqhkiG9w0BCQQxIgQgG2JGa2E/lVO5Ho2zN4Oha8U9PbvEmj7I+gez
# GhznU34wgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAOHK/6sIVgEVSVD3Ar
# vk6OyQKvRxFHKyraUzbN1/AKVzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABqwkJ76tj1OipAAEAAAGrMCIEIHI+RQKHTZ2Id7/ufvKq
# /DQk+dqQy1YkmvsPNzOkpL0iMA0GCSqGSIb3DQEBCwUABIICAJ9fNrGa5d96EWSD
# LUD47Jts+G2s0OUoQdlBRgTsIyUUU7flycQW7hUMcRPqSrS1o3zdI2MnGvabFPnD
# Ho2y7DVcx2tRjQQn9B8A0Svbf4utWXRCFckrmcBEPYFNQ611HJ4I41oyqUlmegZe
# 7achCvn41zFHL58Ww2YwnpGQ0ZhGdMgj3ZujGjQZ3giaor0r0f5VsKAALWNDj2TT
# 16iOy6XWDvlWD9l25EbmhdKjDDOgT+6bo2VGIG3N6J4U7Y71+pYWM2DUp30PuCD/
# KegfUUjZmReHSgIn1t+fEe2Xj6Gf+Q5MaXN4mZdTTf2HuL8HxaJcgqQ4BjWB2n7g
# OwobgrzqPG+vE7tgT/7EPPAFyYmPLdhFEk0d3g1MIEYcLd7WjYk2MWy98R1fNgZb
# pLNH7Y+6oTITdvMCFU8ZhYnLfrNinL3rtaLo2vfTZ/aXEHYbRYwzHaQ0UhLJfq+a
# VLl9ltboceY2/JOXfW5Ip6bj1xvtHIsBVFhbkrfCzcWVunFfkgBNJxLzrts5lY6/
# muPJIwvPcV3HTzL0LqtEBepTLZygdNqtlH+dYFzKVybJVDfR6f6V0rZJkjcR4MU7
# qKnXR8FpC9YjfmXSuj9Jco6b5p79j4iSxBkr6IWWyTuqsIdPJUHSHELL0xlqRFR6
# CwDq7DhbDT8tvw0rPxSUbvo7jd+i
# SIG # End signature block
