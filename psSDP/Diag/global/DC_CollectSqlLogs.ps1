#************************************************
# DC_CollectSqllogs.ps1
# Version 1.0.0
# Date: 10-2011
#
# Description: 
#			Collects SQL Server errorlogs and SQL Server Agent logs for all installed instances passed to script via the $Instances parameter
#			Can operate in "offline" mode where errorlog files are located using the registry or "online" mode
#			where errorlogs are enmerated and collected via xp_readerrorlog.
#
# Visibility:
#			Public - You should call this script to collect SQL Server errorlogs
#
# PowerShell Version:
#			Written to be compatible with PowerShell 1.0
#
# Script Parameters:
#			$Instances
#				Array of instances to collect errorlogs for
#           $CollectSqlErrorlogs
#               Switch parameter that indicates whether to collect SQL Server errorlogs 
#           $CollectSqlAgentLogs
#               Switch parameter that indicates whether to collect SQL Server Agent logs
#
# NOTE: This script expects the $Instances array to have been populated by the Enumerate-SqlInstances
#		function stored in "DSD\Scripts\SQL Server\Shared\Utilities\utils_DSD.ps1" and relies upon that format 
#       to function properly
#
# Author: Dan Shaver - dansha@microsoft.com
#
# Revision History:
#
#           1.0 11/2011    DanSha
#               Original Version
#			1.1 01/18/2012 DanSha
#				Eliminated $Offline switch parameter as we no longer support "online" collection
#
#_# Date: 5-26-2021 added Get-SqlWriterLogs

# This script has dependencies on utils_CTS and utils_DSD
#
param( [Object[]] $instances, [switch]$CollectSqlErrorlogs, [switch] $CollectSqlAgentLogs) 

Import-LocalizedData -BindingVariable errorlogsCollectorStrings

#
# Function : Get-SqlAgentLogPath
# ----------------------------
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
#			Function will find the path to the errorlogs for the instance passed 
# 
# Owner:
#			DanSha 
#
# Revision History:
#
#           1.0 11/2011    DanSha
#               Original Version
#			1.1 01/18/2012 DanSha
#				Replaced double quotes with single quotes when variable expansion not desired.
#               Removed logic for "online" collection
#               Added parameter metadata to prevent null, missing and empty parameters
#
function Get-SqlAgentLogPath([string]$SqlInstance)
{
	trap 
	{
		'[Get-SqlAgentLogPath] : [ERROR] Trapped exception ...' | WriteTo-StdOut
		Report-Error 
	}

    # Check if required parameter specified
	if ($null -ne $SqlInstance)
    {
        # Get instance folder name under SQL Root directory
        $InstanceKey = Get-SqlInstanceRootKey -SqlInstanceName $SqlInstance
    	
        if (($null -ne $InstanceKey) -and (0 -lt $InstanceKey.Length))
    	{
    		$SqlAgentKey = Join-Path -Path $InstanceKey -ChildPath '\SqlServerAgent'								
    								
    		# Test for valid Sql Agent registry key.  
    		if ($true -eq (Test-Path -Path $SqlAgentKey))
    		{	
                
                if ($false -eq (Test-RegistryValueIsNull -RegistryKey $SqlAgentKey -RegistryValueName 'ErrorLogFile'))
                {			
        			# Get the Sql Agent Errorlog path
        			$SqlAgentLogPath = [System.IO.Path]::GetDirectoryName((Get-ItemProperty -Path $SqlAgentKey).ErrorLogFile)
                                 
                    # Command Fail?
                    if ($false -eq $?)
                    {
                        "[Get-SqlAgentLogPath] : [ERROR] Failed to retrieve SQL Agent log path from [{0}\ErrorLogFile]" -f $SqlAgentKey | WriteTo-StdOut
                        Report-Error
                    }
                }
                else
                {
                    "[Get-SqlAgentLogPath] : [ERROR] Failed to retrieve SQL Agent log path from [{0}\ErrorLogFile] because the 'ErrorlogFile' registry value is null" -f $SqlAgentKey | WriteTo-StdOut
                }
    		}
    		else
    		{
    			# Report that we could not locate the SQL Agent log path
    			"[Get-SqlAgentLogPath] : Unable to locate SQL Agent log path for SQL Instance: [{0}]" -f $SqlInstance | WriteTo-StdOut
                "[Get-SqlAgentLogPath] : Registry key: [{0}] is invalid" -f $SqlAgentKey | WriteTo-StdOut
                Report-Error                            
    		}
            
    	} # if ($null -ne $InstanceKey)
    	else
    	{
    		"[Get-SqlAgentLogPath] : Failed to retrieve Instance Root key [{0}]" -f $InstanceKey | WriteTo-StdOut
    		Report-Error
    	}

    } # if ($null -eq $SqlInstance)
    else
    {
        '[Get-SqlAgentLogPath] : Required parameter: -SqlInstance was not specified' | WriteTo-StdOut
    }
    
	return $SqlAgentLogPath
}



#
# Function : Get-SqlAgentLogsOffline
# ----------------------------------
#
# PowerShell Version:
#			Written to be compatible with PowerShell 1.0
#
# Visibility:
#			Private/Internal - Do not call this function from your PowerShell scripts.  
#
# Description:
# 			This function finds and collects all Sql Agent logs for the instance passed to the function
#			This is an "offline" collector in that it does not rely on making a connection to the SQL Server instance to
#			find and collect the Sql Agent log files (via xp_readerrorlog). 
#			Finds the location of the Sql Agent logs from the registry and collects the files from the \log folder for the install
# 
# Arguments:
#			$InstanceName
#			Function will find the path to the Sql Agent errorlog for the instance passed 
# 
# Owner:
#			DanSha 
#
# Revision History:
#
#           1.0 11/2011    DanSha
#               Original Version
#			1.1 01/18/2012 DanSha
#				Replaced double quotes with single quotes when variable expansion not desired.
#               Removed logic for "online" collection
#               Added parameter metadata to prevent null, missing and empty parameters
#

function Get-SqlAgentLogsOffline ([string]$InstanceToCollect )
{
	trap 
	{
		'[Get-SqlAgentLogsOffline] : [ERROR] Trapped exception ...' | WriteTo-StdOut
		Report-Error  
	}
	
    if ($null -ne $InstanceToCollect)
    {
        # Send a status message to stdout.log
    	"[Get-SqlAgentLogsOffline] : [INFO] Attempting to collect Sql Agent logs for instance: {0}" -f $InstanceToCollect | WriteTo-StdOut

    	# Set the SectionDescription to the instance name that errorlogs were collected from
    	$SectionDescription = 'SQL Server Agent Logs for instance: ' + $InstanceToCollect

		# Get path to SQL Server Agent log files from registry
		$SqlAgentLogPath = Get-SqlAgentLogPath -SqlInstance $InstanceToCollect
    		
    	if (($null -ne $SqlAgentLogPath) -and (0 -lt $SqlAgentLogPath.Length))
    	{		
    		
            if ($true -eq (Test-Path -Path $SqlAgentLogPath))
    		{
            	
                # Enumerate and then copy the files
				$Files = @()
                $Files = Copy-FileSql -SourcePath $SqlAgentLogPath `
                         -FileFilters @('SQLAGENT.*') `
                         -FilePolicy $global:SQL:FILE_POLICY_SQL_SERVER_ERRORLOGS `
                         -InstanceName $InstanceToCollect `
						 -SectionDescription $SectionDescription `
						 -LCID (Get-LcidForSqlServer -SqlInstanceName $InstanceToCollect) `
						 -RenameCollectedFiles
                 
    			if (0 -eq $Files.Count)
    			{
                    #SQL Agent Log path is valid but no SQLAget log files exists ...
                    "[Get-SqlAgentLogsOffline] : [INFO] There are no Sql Agent log files for instance: {0}" -f $InstanceToCollect | WriteTo-StdOut
                }
    		} 
    		else 
    		# Invalid path to SQL Agent log files retrieved from registry.  
    		{
				# Does the log path reference a cluster disk that is offline from this node at this time?
                if ($true -eq (Check-IsSqlDiskResourceOnline -InstanceName $InstanceToCollect -PathToTest $SqlAgentLogPath)) 
				{
    				# If above function returns true the drive is online but the path is bad
                    "[Get-SqlAgentLogsOffline] : [ERROR] Path to Sql Agent Log Files: [{0}] for instance: {1} is invalid" -f $SqlAgentLogPath, $InstanceToCollect | WriteTo-StdOut
                }              
    		}
    	} 
    	else 
    	{
    		"[Get-SqlAgentLogsOffline] : [ERROR] Could not locate errorlog path in the registry for instance: [{0}]. No Sql Agent log files will be collected. " -f $InstanceToCollect | WriteTo-StdOut
    	}
        
    } #if ($null -eq $InstanceToCollect)
    else
    {
        '[Get-SqlAgentLogsOffline] : [ERROR] Required parameter: -InstanceToCollect was not specified' | WriteTo-StdOut
    }
} 

#
# Function : Get-ErrorlogsOffline
# -------------------------------
#
# PowerShell Version:
#			Written to be compatible with PowerShell 1.0
#
# Visibility:
#			Private/Internal - Do not call this function from your PowerShell scripts.  
#
# Description:
# 			This function finds and collects all errorlogs for the instance passed to the function
#			This is an "offline" collector in that it does not rely on making a connection to the SQL Server instance to
#			find and collect the errorlog files. 
#			Finds the location of the errorlogs from the registry and collects the files from the \log folder for the install
# 
# Arguments:
#			$InstanceName
#				Function will find the path to the errorlogs for the instance passed 
#			$IsClustered
#				This variable tells the collector whether to run an additional check if a drive appears offline preventing collection
# 
# Owner:
#			DanSha 
#
# Revision History:
#
#           1.0 11/2011    DanSha
#               Original Version
#			1.1 01/18/2012 DanSha
#				Replaced double quotes with single quotes when variable expansion not desired.
#               Removed logic for "online" collection
#               Added parameter metadata to prevent null, missing and empty parameters
#

function Get-ErrorlogsOffline ([string]$InstanceToCollect)
{
	trap 
	{
		"[Get-ErrorlogsOffline] : [ERROR] Trapped exception ..." | WriteTo-StdOut
		Report-Error
	}
	
	if ($null -ne $InstanceToCollect)
    {
        # Write status message to stdout.log
        "[Get-ErrorlogsOffline] : [INFO] Attempting to collect errorlogs for instance: {0}" -f $InstanceToCollect | WriteTo-StdOut
    	
    	$SqlErrorLogPath = Get-SqlServerLogPath -SqlInstance $InstanceToCollect
    	
    	if ($null -ne $SqlErrorLogPath)
    	{		
    		if ( $true -eq (Test-Path -Path $SqlErrorLogPath) )
    		{
    			
                # Set the SectionDescription to the instance name that errorlogs were collected from
    			$SectionDescription = 'SQL Server Errorlogs for instance: ' + $InstanceToCollect 
             
                # Enumerate and then copy the files
				$Files = @()
				$Files = Copy-FileSql -SourcePath $SqlErrorLogPath `
                         -FileFilters @('ERRORLOG*') `
                         -FilePolicy $global:SQL:FILE_POLICY_SQL_SERVER_ERRORLOGS `
                         -InstanceName $InstanceToCollect `
						 -SectionDescription $SectionDescription `
						 -LCID (Get-LcidForSqlServer -SqlInstanceName $InstanceToCollect) `
						 -RenameCollectedFiles
                 
    			if (0 -eq $Files.Count)
    			{
                    "[Get-ErrorlogsOffline] : [INFO] There are no Sql errorlog files for instance: {0}" -f $InstanceToCollect | WriteTo-StdOut
                }
                
    		} # if ( $true -eq (Test-Path -Path $SqlErrorLogPath) )
    		# Errorlog path is invalid
    		else 
    		{
    			if ($true -eq (Check-IsSqlDiskResourceOnline -InstanceName $InstanceToCollect -PathToTest $SqlErrorLogPath))
    	        {
    	            "[Get-ErrorlogsOffline] : [ERROR] No SQL errorlogs will be collected. Path to errorlogs: [{0}] for instance: {1} is invalid" -f $SqlErrorLogPath, $InstanceToCollect | WriteTo-StdOut
    	        }
    		}
    	}
    	# Couldn't locate errorlog path
    	else
    	{
    		"[Get-ErrorlogsOffline] : [ERROR] No SQL errorlogs will be collected. Could not locate the errorlog path in the registry for instance: {0} is invalid" -f $InstanceToCollect | WriteTo-StdOut
    	}
    } #if ($null -ne $InstanceToCollect)
    else
    {
        "[Get-ErrorlogsOffline] : [ERROR] Required parameter -InstanceToCollect was not specified" -f $InstanceToCollect | WriteTo-StdOut
    }
} 

#
# Function : Get-ErrorlogsOnline
# -------------------------------
#
# PowerShell Version:
#			Written to be compatible with PowerShell 1.0
#
# Visibility:
#			Private/Internal - Do not call this function from your PowerShell scripts.  
#
# Description:
# 			This function finds and collects all errorlogs for the instance passed to the function
#			This is an "online" collector that utilizes SQLCMD and xp_readerrorlog to collect the SQL Server errorlogs
#			This collector uses the same exact scrip that PSSDiag uses in order to maintain compatibility with any 
#			post-processing of errorlogs performed by SqlNexus
# 
# Arguments:
#			$InstanceName
#				Function will find the path to the errorlogs for the instance passed 
#			$NetName
#				This is the server or virtual SQL network name to connect to
# 
# Owner:
#			DanSha 
#
#function Get-ErrorlogsOnline ( [string]$InstanceName
#                             , [string]$NetName )
#{
#	trap 
#	
#		'[Get-ErrorlogsOnline] : Trapped error ...' | WriteTo-StdOut
#		Show-ErrorDetails -ErrorRecord $error[0] 
#
#		# Now clear all errors since we reported them
#		$Error.Clear() 
#	}
#	
#	New-Variable ERRORLOG_COLLECTOR_SCRIPT -Value 'collecterrorlog.sql' -Option ReadOnly
#	
#	if (('DEFAULT' -eq $InstanceName) -or ( 'MSSQLSERVER' -eq $InstanceName))
#	{
#		$ConnectToName = $NetName
#		$ErrorlogOutFileName = "{0}__SQL_Base_Errorlog_Shutdown.out" -f $NetName
#	} else {
#		$ConnectToName = $NetName+'\'+$InstanceName
#		$ErrorlogOutFileName = "{0}_{1}_SQL_Base_Errorlog_Shutdown.out" -f $NetName, $InstanceName
#	}
#
#	Execute-SqlScript -ConnectToName $ConnectToName `
#                     -ScriptToExecute $ERRORLOG_COLLECTOR_SCRIPT `
#                      -OutputFileName $ErrorlogOutFileName `
#                      -SectionDescription ("SQL Server Errorlogs for instance: {0}" -f $ConnectToName) `
#                      -FileDescription 'ERRORLOGS'
#}

#
# Function : Get-SqlErrorlogs
# ------------------------
#
# PowerShell Version:
#			Written to be compatible with PowerShell 1.0
#
# Visibility:
#			Private/Internal - Do not call this function from your PowerShell scripts.  
#
# Description:
# 			This function is a wrapper that calls Get-ErrorlogsOffline
#           This script used to support online and offline collection modes 
#           The "online" collector utilized SQLCMD and xp_readerrorlog to collect the SQL Server errorlogs
#			However, xp_readerrorlog wraps lines and this caused issues for loading the files in UDE so we no longer collect in this format
# 
# Arguments:
#			$InstanceName
#				Function will find the path to the errorlogs for the instance passed 
#			$NetName
#				This is the server or virtual SQL network name to connect to
# 
# Owner:
#			DanSha 
#
# Revision History:
#
#           1.0 11/2011    DanSha
#               Original Version
#			1.1 01/18/2012 DanSha
#				Replaced double quotes with single quotes when variable expansion not desired.
#               Removed logic for "online" collection
#               Added parameter metadata to prevent null, missing and empty parameters
#
#

function Get-SqlErrorLogs ([object]$Instance)
{
	trap 
	{
		# Handle and report any exceptions that occur in this function, and then allow execution to resume 
		# Since this is only a wrapper function and doesn't do much to setup the excution of Get-ErrorlogsOffline, 
		# the called function may still succeed
		#
		'[Get-SqlErrorLogs] : [ERROR] Trapped exception ...' | WriteTo-StdOut
		Report-Error
	}
	
    # Check if required parameter was passed
    if ($null -ne $Instance)
    {
       	# Update msdt dialog with progress message
    	Write-DiagProgress -Activity $errorlogsCollectorStrings.ID_SQL_CollectSqlErrorlogs -Status ($errorlogsCollectorStrings.ID_SQL_CollectSqlErrorlogsDesc + ": " + $instance.InstanceName)
    	
        if ($null -ne $Instance.InstanceName)
        {
        	"[Get-SqlErrorLogs] : [INFO] Collecting logs for instance {0}" -f $Instance.InstanceName | WriteTo-StdOut
        	Get-ErrorlogsOffline -InstanceToCollect $Instance.InstanceName 	
        }
        else
        {
            '[Get-SqlErrorLogs] : [ERROR] Passed instance name ($Instance.InstanceName) is null' | WriteTo-StdOut
        }
	}
    else
    {
        if ($null -eq $Instance)
        {
            '[Get-SqlErrorLogs] : [ERROR] Required parameter: -Instance was not specified' | WriteTo-StdOut
        }
    }	
	
}

#
# Function : Get-SqlAgentLogs
# ------------------------
#
# PowerShell Version:
#			Written to be compatible with PowerShell 1.0
#
# Visibility:
#			Private/Internal - Do not call this function from your PowerShell scripts.  
#
# Description:
# 			This function is a wrapper that calls Get-SqlAgentLogsOffline
#			Wrapper exists in case we want to add offline and online (via xp_readerrorlog) collection modes.  This is the function
#			
# 
# Arguments:
#			$InstanceName
#				Function will find the path to the errorlogs for the instance passed 
#			$NetName
#				This is the server or virtual SQL network name to connect to
# 
# Owner:
#			DanSha 
#
# Revision History:
#
#           1.0 11/2011    DanSha
#               Original Version
#			1.1 01/18/2012 DanSha
#				Replaced double quotes with single quotes when variable expansion not desired.
#               Removed logic for "online" collection
#               Added parameter metadata to prevent null, missing and empty parameters
#
#
function Get-SqlAgentLogs ([object]$Instance)
{
	trap 
	{
		'[Get-SqlAgentLogs] : [ERROR] Trapped exception ...' | WriteTo-StdOut
		Report-Error 
	}
	
	# Update msdt dialog with progress message
	Write-DiagProgress -Activity $errorlogsCollectorStrings.ID_SQL_CollectSqlAgentlogs -Status ($errorlogsCollectorStrings.ID_SQL_CollectSqlAgentlogsDesc + ": " + $instance.InstanceName)
	
    # Check if required parameter specified
    if ($null -ne $Instance)
    {
        # Write to debug log
    	"[Get-SqlAgentLogs] : [INFO] Collecting Sql Agent logs for instance {0}" -f $Instance.InstanceName | WriteTo-StdOut
    	Get-SqlAgentLogsOffline -InstanceToCollect $Instance.InstanceName 
    }
    else
    {
        '[Get-SqlAgentLogs] : [ERROR] Required parameter -Instance was not specified' | WriteTo-StdOut
    }
}

#_# add function for collecting SQL Server 2019 SqlWriterLogger
function Get-SqlWriterLogs([string]$SqlVersion)
{
	$SQLPath = (join-path ([Environment]::GetFolderPath("ProgramFiles")) "Microsoft SQL Server\$SqlVersion\Shared")
	if($debug -eq $true){[void]$shell.popup($SQLPath)}

	if ((test-path $SQLPath) -eq $true)
		{
			if($debug -eq $true){[void]$shell.popup("Valid Path")}
			
			$OutputFileName= $ComputerName + "_SQL" + $SqlVersion + "_SqlWriterLogger.Cab"
			if($debug -eq $true){[void]$shell.popup($OutputFileName)}

			#Create Array of Files to Collect
			[Array] $DC_GetSQLWriterLoggerOutputFiles = $SQLPath + "\SqlWriterLogger*.txt"

			CompressCollectFiles -filesToCollect $DC_GetSQLWriterLoggerOutputFiles -DestinationFileName $OutputFileName -fileDescription "SQL $SqlVersion SqlWriterLogger Logs" -sectionDescription "Additional Data" -Recursive -ForegroundProcess
		}
		else
			{
				if($debug -eq $true){[void]$shell.popup("Invalid Path")}
			}
}

# Clear errors at entry to script
#
$Error.Clear()           
trap 
{
	'[DC-CollectSqllogs] : [ERROR] Trapped exception ...' | WriteTo-StdOut
	Report-Error 
}

if ($true -eq $global:SQL:debug)
{
    $CollectSqlErrorlogs=$true
    $CollectSqlAgentLogs=$true
}

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
	
	if ($null -ne $instances)
    {
    
		foreach ($instance in $instances)
		{
			if ('DEFAULT' -eq $instance.InstanceName) {$instance.InstanceName='MSSQLSERVER'}
        
			if ($true -eq $CollectSqlErrorlogs)
			{
				Get-SqlErrorlogs -Instance $instance
			}
            
			if ($true -eq $CollectSqlAgentLogs)
			{
				Get-SqlAgentLogs -Instance $instance
			}
            
		}
        
	} # if ($null -ne $instances)
    else
    {
        "[DC_CollectSqllogs] : [WARN] No sql server instances were found on: [{0}] yet SQL Server appears to be installed" -f $ComputerName | WriteTo-StdOut 
    }
} # if ($true -eq (Check-SqlServerIsInstalled))

else 
{
    "[DC_CollectSqllogs] : No sql server instances are installed on: [{0}]" -f $ComputerName | WriteTo-StdOut 
}



#_# Collect SQL 90 SqlWriter Logs
Write-DiagProgress -Activity $GetSQLSetupLogs.ID_SQL_setup_collect_writer_logs -Status $GetSQLSetupLogs.ID_SQL_writer_Collect_2019_Logs
Get-SqlWriterLogs -SqlVersion "90"

# SIG # Begin signature block
# MIIjiAYJKoZIhvcNAQcCoIIjeTCCI3UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDYydYx/HIwdLAS
# Y7ejB8Ja87sz5IBcoIZvGTLytTb586CCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVXTCCFVkCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBpDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQghaMEZYy/
# xRNYLx8tn4BAXMf19f+ex4Dc73EBhIHObh0wOAYKKwYBBAGCNwIBDDEqMCigCIAG
# AFQAUwBToRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20gMA0GCSqGSIb3DQEB
# AQUABIIBAIRVt+qfHWPY00I4ho7ntAMGNpLLYslmwUvAy4Q9FiPGm6ONAKqkfmGE
# YNfWbH6rSHIvYDUW5jMRvX4+T19VwVG/642KzL68zu721TAMnGaiyKzPU/Ri5kh6
# L09JwK26Llpo8UmRx+EGu5QT8CjkkHBjENAqrftunmTeGGkL7AegI+qo/frFICJG
# g42iZNG3EVxVtFyMmTqE60nt7VZhT6Fyg0sbaLQ77oqfqLBREbEUP2DzitZ3Ay5U
# frVd4+poHqEAuj+xmXMUi6XycskgAhBLiHXsy050CI/Eiwi7noLrIM6VKhL60gH8
# 9ziCie7zG0qyvNMObhexvTwVWsy4Fy2hghLxMIIS7QYKKwYBBAGCNwMDATGCEt0w
# ghLZBgkqhkiG9w0BBwKgghLKMIISxgIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBVQYL
# KoZIhvcNAQkQAQSgggFEBIIBQDCCATwCAQEGCisGAQQBhFkKAwEwMTANBglghkgB
# ZQMEAgEFAAQgGdeVJ87wbjgEKyZI0PcXm0DoNgWBlPmt+g9kEEEPhqgCBmGBshkU
# vBgTMjAyMTExMTExNjUzMzcuMjUxWjAEgAIB9KCB1KSB0TCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkM0
# QkQtRTM3Ri01RkZDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloIIORDCCBPUwggPdoAMCAQICEzMAAAFXRAdi3G/ovioAAAAAAVcwDQYJKoZI
# hvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjEwMTE0
# MTkwMjEzWhcNMjIwNDExMTkwMjEzWjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVl
# cnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkM0QkQtRTM3Ri01RkZD
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3m0Dp1Rm+efAv2pC1dzA8A2EHh7P7kJC
# t4+n9nxMfg0Gvm8B8YyjSVX+WJ0Fq0pOAcSs64ofXXFUB8F6Ecm8f1P86E5zzcIm
# z1vMOGuV3Ql3Ld4nILTIF3FV65xL7ZrZkF3nTAGD/n/ZiNDbKV8PR3Eorq1AvF04
# NO5p1Axt1rTmU8adYbBneeJKAgpVGCqoJWWEfPA21GHUAf5nFt9J7u3zPegQoB1M
# DLtKw/zKSG3eyuN2HQHKQ8V2loCCrBYIkkmYaTSACtK8cLz69e0ajcwmFZBF7km3
# N0PmR1oof25z2CdKGxfIMSEZmPHf5vxy6oQ7xse/RY9f0xER+t/G+QIDAQABo4IB
# GzCCARcwHQYDVR0OBBYEFF0xe7voOCGdT+Q9Mwp0WRH2gKnZMB8GA1UdIwQYMBaA
# FNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8y
# MDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAt
# MDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJ
# KoZIhvcNAQELBQADggEBACV3eQCAbpdaJnK92JstGZavvJvpFLJyNUODy1wKK1LT
# WxNWnhPwB3ZB5h8lZ8roMwSTtBEF8qB03ugTx1e2ZBUv4lzEuPSlS7Lg0HlFyFy1
# 4Pl1GdN8qVGLy+ApRrENygUjM0RTPUQemil5qANvj+4j1SPm0i7CWKT+qu/+wcDD
# uQziAQss06B16/1n/vGjUkjB97R6hAzfDFwIUu5/xL06dy21oUBYe0QRHwi+BECA
# sn9aeW4XPrz6GsN9HJf+qpZI8gTS+gTqoXHXPxS8vAqmbrlA3I0NEyn9WYKmpFmv
# EHWjRFjs/6fiNI0a9uTZtHvSQq392iAUVEEdVW5TF/4wggZxMIIEWaADAgECAgph
# CYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2
# NTVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvt
# fGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzX
# Tbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+T
# TJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9
# ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDp
# mc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIw
# EAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1V
# MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMB
# Af8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1Ud
# HwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3By
# b2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQRO
# MEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2Vy
# dHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIw
# gY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIg
# HQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4g
# HTANBgkqhkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7P
# BeKp/vpXbRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2
# zEBAQZvcXBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95
# gWXZqbVr5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7
# Yl+a21dA6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt
# 0uGc+R38ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2
# onGqBooPiRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA
# 3+cxB6STOvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7
# G4kqVDmyW9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Ki
# yc8ZQU3ghvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5X
# wdHeMMD9zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P
# 3nSISRKhggLSMIICOwIBATCB/KGB1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMg
# UHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkM0QkQtRTM3Ri01
# RkZDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEw
# BwYFKw4DAhoDFQARLfhJYnsN9tIb+BshDBOvOBnw8qCBgzCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5TdlHjAiGA8y
# MDIxMTExMTEzNDcxMFoYDzIwMjExMTEyMTM0NzEwWjB3MD0GCisGAQQBhFkKBAEx
# LzAtMAoCBQDlN2UeAgEAMAoCAQACAhSBAgH/MAcCAQACAhFZMAoCBQDlOLaeAgEA
# MDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAI
# AgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAQwP/FLlP0S6Lacsq9xG2lBweZT5R
# ezSzHoLThU+4k2RT3bM+CAmABoNt/6nLHOgeJDHXhbgW9wJjT60FbnvPSBIAC7ja
# kyZ5OdxjwglYEo4kHJio7o8ZXZyE9IEWHDeSGCEcQt2SWYRtbpf7LY7RkG9eF7Ot
# Oh851qk29jGksuAxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAVdEB2Lcb+i+KgAAAAABVzANBglghkgBZQMEAgEFAKCCAUow
# GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCB+DR2Z
# LR9fgQyjVUkv4zjNcWIJacVDxzw/RkVWiwFgJDCB+gYLKoZIhvcNAQkQAi8xgeow
# gecwgeQwgb0EICxajQ1Dq/O666lSxkQxInhSxGO1DDZ0XFlaQe2pHKATMIGYMIGA
# pH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFXRAdi3G/ovioA
# AAAAAVcwIgQgUNTL42zabPo8iEdkSC2WiPOhDovoZWUW0VMosB1AYt0wDQYJKoZI
# hvcNAQELBQAEggEAf/MyQfHDBJIju5iZ8LvUEXXv/BPl2xRlr0pT50z5JNWtNHoC
# QlIxITfpNa9v37Wk76VTV4UFe4iOCcDe+oMFMswiWN8+xxohHr3zITIEElncixQr
# mRd0rL7VXV17KO0FPmKxny7KHaI9ePUlh978A5A/eeN9EiWoINfCrOKPeAY3BQrU
# ES0rBUt/mH7lDyR5WTh+oynQ8v4UKkslwxHBeO0aEaGOHr4oLmRaMSd8Ret5EcqJ
# jA8zYXPrUCkAyKmHzG+WMLiqzUKM9Gby/V1mks1FRQTheunWGBVT6lV5n4f+t3go
# ki33ftDNR8623kd2qRysmbZc1zn0eON+Jn7H6g==
# SIG # End signature block
