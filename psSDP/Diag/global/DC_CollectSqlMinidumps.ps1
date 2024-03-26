
# This script has dependencies on utils_CTS and utils_DSD
#
param ( [Object[]] $instances ) 

# 2023-02-20 WalterE mod Trap #we#
trap [Exception]{
	WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; continue
	Write-Host "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_"
}

$LOGvars= Get-Variable LOG*
if (!($LOGvars.name -contains "LOGFILE_PATH")) {
	New-Variable LOGFILE_PATH      -Scope "Global" #_# only set new var if LOGFILE_PATH does not exits
}

#
# Function : WriteTo-LogFile
# ---------------------
#
# PowerShell Version:
#			Written to be compatible with PowerShell 1.0
#
# Visibility:
#			Private/Internal - Do not call this function from your PowerShell scripts.  
#
# Description:
# 			This function should is used to log progress and error messages to the ErrorloLogCollectorResults.log 
#			file and the test harness executes
# 
# Arguments:
#			String to write to file
# 
# Owner:
#			DanSha 
#
function WriteTo-LogFile($StringToWrite)
{
	$Error.Clear()           
    trap 
    {
    	"[WriteTo-LogFile] : [ERROR] Trapped exception ..." | WriteTo-StdOut
    	Report-Error 
	}

	"[{0:yyyy-MM-dd HH:mm:ss.fff}] : {1}" -f (Get-Date), $StringToWrite |  Out-File -FilePath $global:LOGFILE_PATH -Append
}

#
# Function : Write-DumpInventory
# ------------------------------
#
# PowerShell Version:
#			Written to be compatible with PowerShell 1.0
#
# Visibility:
#			Private/Internal - Do not call this function from your PowerShell scripts.  
#
# Description:
#		    Writes an inventory of all dump files found for target instance
# 
# Arguments:
#			String to write to file
# 
# Owner:
#			DanSha 
#   
function Write-DumpInventory([string]$InstanceName, [string]$DumpDir)
{
    $Error.Clear()           
    trap 
    {
    	"[Write-DumpInventory] : [EROR] Trapped exception ..." | WriteTo-StdOut
    	Report-Error
    }
   
    if ($null -ne $InstanceName)
    {
        if ($null -ne $DumpDir)
        {
            # This collector can be configured to collect a subset of the minidumps on a given machine.  
            # As such, for debugging purposes the collector writes a dump inventory that's collected with the dump files  
            $DumpInventoryFile = "{0}_{1}_DumpInventory.log" -f $env:ComputerName, $InstanceName
            New-Item -ItemType file -Name $DumpInventoryFile -Path $PWD.Path -Force | Out-Null
            $global:LOGFILE_PATH = Join-Path -Path $PWD.Path -ChildPath $DumpInventoryFile 
            
            # Is path passed to function in $DumpDir valid?
            if ($true -eq (Test-Path -Path $DumpDir -PathType "Container"))
            {
                # Collect (up to) 10 most recent minidump files for this instance
                $Dumpfiles = get-childitem -Path (Join-Path $Dumpdir "*") -Include "*.mdmp" | sort-object -Property Length -Descending
                
                if ($true -eq (Test-Path -Path $global:LOGFILE_PATH -PathType "Leaf"))
                {
                    WriteTo-LogFile ("Dump inventory for instance: {0}" -f $InstanceName)
                    WriteTo-LogFile ("Dump directory: {0}" -f $DumpDir)
                    
                    if ($null -ne $Dumpfiles) 
                    {
                        if (0 -lt $Dumpfiles.Count) 
                        {
                            WriteTo-LogFile ("Total number of dumps discovered is: {0}" -f $Dumpfiles.Count)
                            
                            foreach($DumpFile in $Dumpfiles)
                            {
                                WriteTo-LogFile ("{0} Creation Time: {1} Size: {2}" -f $DumpFile.Name, $DumpFile.CreationTime, $DumpFile.Length)
                            }
                        }
                    }
                    else
                    {
                        WriteTo-LogFile "No minidumps found ..." 
                    }
            		# Now collect the file so that it will be included in CAB that's uploaded
                	CollectFiles -FilesToCollect $global:LOGFILE_PATH -SectionDescription ("SQL Server minidumps and related files for instance {0}" -f $InstanceName)
                }
            }
            else
            {
                "[Write-DumpInventory] : [ERROR] Invalid path [{0}] passed by caller" -f $DumpDir | WriteTo-StdOut        
            }
            
        } # if ($null -eq $DumpDir)
        else
        {
             '[Write-DumpInventory] : [ERROR] Required parameter -DumpDir was not specified' | WriteTo-StdOut        
        }
        
    } # if ($null -eq $InstanceName)
    else
    {
        '[Write-DumpInventory] : [ERROR] Required parameter -InstanceName was not specified' | WriteTo-StdOut        
    }
}


# This function works with and returns the dump directory as a string so not susceptible to issues caused by
# cluster drive being offline to the node the collector is run against
function Get-DumpDirectory ([string] $SqlInstance)
{
    $Error.Clear()           
	trap 
	{
		"[Get-DumpDirectory] : [ERROR] Trapped exception ..." | WriteTo-Stdout
		Report-Error
	}
    
    if ($null -ne $SqlInstance)
    {
    	$InstanceKey = Get-SqlInstanceRootKey -SqlInstanceName $SqlInstance
        
        if ($null -ne $InstanceKey)
        {
        								
        	if ($true -eq (Test-Path -Path (Join-Path -Path $InstanceKey -ChildPath '\CPE')))
        	{				
        		$CpeRegKey = Join-Path -Path $InstanceKey -ChildPath '\CPE'
        		
                # Test to be sure CpeRegKey is valid
                if ($true -eq (Test-Path -Path $CpeRegKey))
                {
                    # Get the MSSQLServer\Parameters Key
            		$SqlDumpDir = (Get-ItemProperty -Path $CpeRegKey ).ErrorDumpDir
                    
                    if ($true -ne $?)
                    {
                        "[Get-DumpDirectory] : [ERROR] Failed to retrieve ErrorDumpDir registry value from key: [{0}]" -f $CpeRegKey | WriteTo-StdOut
                        Report-Error
                    }
                }  
                else
                {
                    "[Get-DumpDirectory] : [ERROR] Cpe registry key: [{0}] is invalid or does not exist" -f $CpeRegKey | WriteTo-StdOut
                    Report-Error
                }              
                
        	}
        	else
        	{
        		# Report that we could not locate the SQL Server dump directory
        		"[Get-DumpDirectory] : [ERROR] Unable to locate dump directory for SQL Instance: [{0}]" -f $SqlInstance | WriteTo-StdOut
        		"[Get-DumpDirectory] : [ERROR] Registry key: [{0}] is invalid" -f ($InstanceKey + "\CPE") | WriteTo-StdOut
        	}
            
        } # if ($null -ne $InstanceKey)
        else
        {
            '[Get-DumpDirectory] : [ERROR] Get-SqlInstanceRootKey returned a null value' | WriteTo-StdOut
        }
    } 
    else
    {
        '[Get-DumpDirectory] : [ERROR] Required parameter -SqlInstance was not specified' | WriteTo-StdOut
    }
    
	return $SqlDumpDir
}

#
# Function : Collect-SqlServerMinidumps
# --------------------------------------
#
# PowerShell Version:
#			Written to be compatible with PowerShell 1.0
#
# Visibility:
#			Private/Internal - Do not call this function directly. Instead, call the top-level script and pass args
#			indicating which instances to collect dumps for  
#
# Description:
# 			This function enumerates the minidump files for a given SQL Server installation and 
# 
# Arguments:
#			String to write to file
# 
# Owner:
#			DanSha 
#
function Collect-SqlServerMinidumps ([string]$InstanceToCollect, [bool]$IsClustered )
{
    $Error.Clear()           
    trap 
    {
    	"[Collect-SqlServerMinidumps] : [ERROR] Trapped error ..." | WriteTo-StdOut
    	Report-Error 
    }
	
    If ($null -ne $InstanceToCollect)
    {
        if ($null -ne $IsClustered)
        {
            $DumpDir = Get-DumpDirectory -SqlInstance $InstanceToCollect

        	if ($null -ne $DumpDir)
            {
                # Make sure the dump directory path is valid. 
                # When SQL Server is clustered, the instance could be online to another cluster node
                # If so, the drive where the dumps are stored may be offline from the node where the collector is running
                #
                if (Test-Path -Path $DumpDir -PathType "Container")
                {
                    #$DumpCount = get-childitem -Path (Join-Path -Path $Dumpdir -ChildPath "*") -Include "*.mdmp" | Get-Count
                    
                    # Create the dump inventory report ... even if there are no dumps present ... report will indicate this
                    Write-DumpInventory -InstanceName $InstanceToCollect -DumpDir $DumpDir
                    
                    $FileFilters = @('*.mdmp')
                    
                    # First pass, enumerate the files but to not copy
				    $DumpFiles = @()
				    $DumpFiles = Copy-FileSql -SourcePath $DumpDir `
                         -FileFilters $FileFilters `
                         -FilePolicy $global:SQL:FILE_POLICY_SQL_SERVER_MINIDUMPS `
                         -InstanceName $InstanceToCollect `
						 -EnumerateOnly
                                            
                    #Since forcing an array to be created with above syntax need to check the length to see if there are any entries in array
                    if (($null -ne $DumpFiles) -and (0 -ne $Dumpfiles.Length))
                    {
                        # Need to go get the SQLDUMP*.log and SQLDUMP*.txt files associated with the dumps we just collected
                        foreach ($file in $dumpfiles)
                        {
                           $LogFileFullPath = $file.Replace("mdmp", "log")
                           # Add the .log file to the list of filefilters to enumerate.  No need to test-path as the enumerate/copy routine does this
                           $FileFilters += split-path -Leaf -Path $LogFileFullPath
                           
                           $TxtFileFullPath = $file.Replace("mdmp", "txt")
                           $FileFilters += split-path -Leaf -Path $TxtFileFullPath
                        } 
                        
                        # Add SQLDUMPER_ERRORLOG
                        $FileFilters += "SQLDUMPER_ERRORLOG.log" 
                       
                        # Add exception.log if present
                        $FileFilters += "exception.log" 
                        
                        $MiniDumpArchiveName = "{0}_{1}_{2}_SqlMiniDumps.zip" -f $env:ComputerName, $InstanceToCollect, (Get-LcidForSqlServer -SqlInstanceName $InstanceToCollect)
                    
                        # Re-enumerate, this time copy and compress since we should have all files we want.  FilePolicy is applied "by filter" so no need
                        # to adjust it to account for additional files for this subsequent call
                        $DumpFiles = @()
				        $DumpFiles = Copy-FileSql -SourcePath $DumpDir `
                         -FileFilters $FileFilters `
                         -FilePolicy $global:SQL:FILE_POLICY_SQL_SERVER_MINIDUMPS `
                         -InstanceName $InstanceToCollect `
                         -SectionDescription ("SQL Server minidumps and related files for instance {0}" -f $InstanceToCollect) `
                         -ZipArchiveName $MiniDumpArchiveName `
                         -CompressCollectedFiles
                         #-RenameCollectedFiles
                         
         
					} # if (($null -ne $DumpFiles) -and (0 -ne $Dumpfiles.Length))
                    else
                    {
                        "[Collect-SqlServerMinidumps] : [INFO] No minidumps found for instance: [{0}]" -f $InstanceToCollect | WriteTo-StdOut
                    }  
                }
                # Test-path failed for $DumpDir ... could be because the cluster resource where the dumpfiles are stored is offline to this cluster node
                else 
            	{
                    if ($true -eq (Check-IsSqlDiskResourceOnline $InstanceToCollect $DumpDir))
                    {
                        "[Check-IsSqlDiskResourceOffline] : [ERROR] Path to minidumps: [{0}] for instance: {1} is invalid" -f $DumpDir, $InstanceToCollect | WriteTo-StdOut
                    }
            	}
                
            } #if ($null -ne $DumpDir)
            else
            {
                '[Collect-SqlServerMinidumps] : [ERROR} Get-Dumpdirectory returned a null dump directory path for instance: [{0}]' -f $InstanceToCollect  | WriteTo-StdOut
            }
            
        } # if ($null -ne $IsClustered)
        else
        {
            '[Collect-SqlServerMinidumps] : [ERROR} Required parameter -IsClustered was not specified' | WriteTo-StdOut
        }
        
    } # If ($null -ne $InstanceToCollect)
    else
    {
        '[Collect-SqlServerMinidumps] : [ERROR} Required parameter -InstanceToCollect was not specified' | WriteTo-StdOut
    }
} 

#
# Script entry point
#
#region: MAIN ::::: 
$Error.Clear()           
trap 
{
	"[DC-CollectSqlSqlMinidumps] : [ERROR] Trapped error ..." | WriteTo-StdOut
	Report-Error
}
	
Import-LocalizedData -BindingVariable minidumpCollectorStrings

# Check to be sure that there is at least one SQL Server installation on target machine before proceeding
#
if ($true -eq (Check-SqlServerIsInstalled))
{
	# If $instance parameter is null, collect minidumps for all instances installed on machine
	#
	if ($null -eq $instances)
	{
		$instances = Enumerate-SqlInstances -Offline
	}
    
    if ($null -ne $instances)
    {
    
        foreach ($instance in $instances)
        {
			"[DC-CollectSqlSqlMinidumps] : Attempting to collect minidumps for SQL instance: [{0}]" -f $instance.InstanceName | WriteTo-StdOut
            Write-DiagProgress -Activity $minidumpCollectorStrings.ID_SQL_CollectSqlMinidumps -Status ($minidumpCollectorStrings.ID_SQL_CollectSqlMinidumpsDesc + ": " + $instance.InstanceName)
			
            # DEFAULT instance name is MSSQLSERVER in registry and filesystem.  Translate it here before doing any work
            if ('DEFAULT' -eq $instance.InstanceName.ToUpper()) {$instance.InstanceName='MSSQLSERVER'}
            
			Collect-SqlServerMinidumps -InstanceToCollect $instance.InstanceName -IsClustered $instance.IsClustered
        }
    }
} # if ($true -eq (Check-SqlServerIsInstalled))
else
{
    "[DC-CollectSqlSqlMinidumps] : [INFO] No SQL Server installation(s) were found on server: [{0}]" -f $env:ComputerName | WriteTo-StdOut
}
#endregion: MAIN ::::: 


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCARVDwBdPAJYKa1
# o4scqKsDf/nBQMHYTvcO56tdcSexU6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMphLa7vKsz8GEe2ZnvoywbQ
# 9ySl+ApudBAo6aSIPgJbMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAYvbEihRaBBdpOIstsV2uAJZRnlLt6Xgn436gp0uzdKO5eak+kwYwF
# p3L0xsk6RDB+3U3/uHwI/pZzg77qPwS1WNJQq/SHiorJIYC6HeYlubNqvDjWsXS5
# OzuL+eDAlybHj1iYWZRe03to+7MIMuizTS+tDGmHHp40HHQV1mQO+oJD1zVdMKDq
# U6O1yU4U5CvgPULL+zayRszSf9KwuIumDFDpTMSZP2nfvccR7ERJG6+gETFqNyNU
# ltDXPF25B1QWB9nQNmER0rAWrARCD2C+14DFC8Mei15nrH1+QMz/m71xWz4Tznmq
# IkuWLkmHNfgMni0rC91XJYaToGsH1tA/oYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIATyorSMJ6H/dmjpqZ2R+AFtPkOKMrXRUiYL8E4t7YOPAgZj7jLu
# kBUYEzIwMjMwMjIwMTUwMDE5LjUzMlowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjdCRjEt
# RTNFQS1CODA4MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAHI+bDuZ+3qa0YAAQAAAcgwDQYJKoZIhvcN
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
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs4wggI3AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjo3QkYxLUUzRUEtQjgwODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA384TULvGNTQKUgNdAGK5wBjuy7Kg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOed9wYwIhgPMjAyMzAyMjAyMTQxMjZaGA8yMDIzMDIyMTIxNDEyNlow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5533BgIBADAKAgEAAgIUpQIB/zAHAgEA
# AgISRjAKAgUA559IhgIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAIGAA7ug
# iBU8AQv6I4Dnk1l0iYHo8fQsU2Larmcu4JX+xdI6ml3NdIx8925D5vvNdgEa6HvZ
# JE/1hwG8p6MUfMuHBzayQSI4IQNkvUoeD61XQymmmrQYQtuUb7EF88sUxo6dqhpB
# GZeVM4YuqiooNbir7fUahPwV8OELS3CFrWzrMYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHI+bDuZ+3qa0YAAQAAAcgwDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgtNPGtqkeuvvz10o/UaERvOugLTnwDcFV4La9HPch9rowgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBiAJjPzT9toy/HDqNypK8vQVbhN28D
# T2fEd+w+G4QDZjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAAByPmw7mft6mtGAAEAAAHIMCIEID3Z68dUpflDxkxrGEm9uVZsI3zW4dvs
# h3j8VeBIBJxTMA0GCSqGSIb3DQEBCwUABIICALeUcxjPoCERrDCaebJey1wch5Cy
# GnnHUT2hWyot2poqKi0iXQBKGXaGjfqQWdNVI4glL+zUGk/k2FD4mWFvzlVYD9gk
# g2zuTHkH8m5mD1yz8OSDr8a5aRJgbV8RVK7/TJu9r32ncDrVlBiYTABj/Om/C2ch
# s5xb3nFYLQHcxrih/hKhh4jAE6CuERgm9C+v+4se3imFU01fWx+BNMK8OwnGLDzD
# QFjTABe5p9QmyF0rk1DCoChgxblEvGPO9TH1Gnvz2mLaD4GrLBFCkB0g9mgxL6Rc
# cA4GQNABHVu7bbNU4bwVY8fHqzD97wJQaJzgHJYSNb/dGiCdDAgV0ZIyFcGLU8YR
# 7l/8zAgvcb94v2Jv1CjHNXs2hS9UwRqxSK8C7RtxpKAE2u50Pm5Ox2dL7X6pg8XA
# wsQFMIRUEpvXSQ3FXIkdovryfDKmMmvMJeY3L1OWUugTbh3pUNs2FsrYL72KPGNF
# SBfx5tbFUmrZx6qDWMB2eC790B1tPeulIt3/6yXYEsvtmIApuK3Vf/Fi4jv02Igf
# mcv4+rEekK5T2RPjSlRuHO6vMr9asbRmfrq2ewhBRYLkcPgAsWVej8WDwXzU2ISg
# ruiQwuUvnjSLI37S0ES1Mco/sMyNIcCzixbdn3XnBadm57bh4Qrt7xcrrnFbLfgK
# qXWnRHR7oY6eCtDZ
# SIG # End signature block
