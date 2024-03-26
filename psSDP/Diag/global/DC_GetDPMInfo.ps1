#************************************************
# GetDPMInfo.ps1
# Version 2.0.0
# Date: 09-27-2011
# Author: Patrick Lewis - patlewis@microsoft.com
# Description: This script gathers info on the DPM server
#************************************************

####################################################################################
# Check to be see if DPM is installed
####################################################################################
function IsDPMInstalled
{
	$IsDPMInstalled = $false
	if (Test-Path "HKLM:SOFTWARE\Microsoft\Microsoft Data Protection Manager\Setup")
	{
		$IsDPMInstalled =(get-itemproperty "HKLM:\SOFTWARE\Microsoft\Microsoft Data Protection Manager\Setup").InstallPath 
		if(!([string]::IsNullOrEmpty($IsDPMInstalled)))
		{
			$IsDPMInstalled = $true
		}
	}
	return $IsDPMInstalled
}

####################################################################################
# Check to be sure the DPM namespace is loaded, if not then load it
####################################################################################
function LoadDPMNamespace ()
{	
	$DPMFolder = GetDPMInstallFolder	
	$DPMVersion = DPMVersion ($DPMFolder)
	Switch ($DPMVersion)
	{	
		2	{
				if (!(get-PSSnapin | Where-Object { $_.name -eq 'Microsoft.DataProtectionManager.PowerShell'}))
				{
					Add-PSSnapin -name Microsoft.DataProtectionManager.PowerShell
				}
			}
		3	{
				if (!(get-PSSnapin | Where-Object { $_.name -eq 'Microsoft.DataProtectionManager.PowerShell'}))
				{
					Add-PSSnapin -name Microsoft.DataProtectionManager.PowerShell
				}
			}
		4	{
				Import-Module -name dataprotectionmanager
			}
	}
} 

####################################################################################
# Check the command line arguments passed in
####################################################################################
function GetDPMServerName()
{
	if(!$args[0])
	{
		if(!$DPMServerName)
		{
			$DPMServerName = $Env:COMPUTERNAME
		}
	}
  
	$DPMServerName = $DPMServerName.Trim(" ")
	return $DPMServerName
}
####################################################################################
# PrintInfo
####################################################################################
function PrintInfo([string]$ServerName)
{
	"**************************************************" | out-file $OutputBase 
	"*          DPM Server Report Version 1.0         *" | out-file $OutputBase -Append
	"**************************************************" | out-file $OutputBase -Append

	$Server = Get-CimInstance win32_operatingsystem
	$ds = Connect-DPMServer -DPMServerName $ServerName
   
	if (!$ds) 
	{
		"Unable to connect to DPM Server or service not running on: " + $ServerName | Out-File $OutputBase -Append
		$error[-1]                                                                  | Out-File $OutputBase -Append
		whoami                                                                      | Out-File $OutputBase -Append
		return
	}

	$dpmVersion = $ds.GetProductInformation().ProductName
	$Serverobj = New-Object PSObject
	$Serverobj | Add-Member NoteProperty -name "DPM Server" -value $ServerName
	$Serverobj | Add-Member NoteProperty -name "OS Version" -value $Server.Caption
	$Serverobj | Add-Member NoteProperty -name "Architecture" -value $Server.OSArchitecture
	$Serverobj | Add-Member NoteProperty -name "SP Level" -value $Server.ServicePackMajorVersion
	## TODO: Add entry for Total memory
	## TODO: Add pagefile size 1.5* Total memory
	$Serverobj | Add-Member NoteProperty -name "Available Memory" -value $Server.FreePhysicalMemory
	$Serverobj | Add-Member NoteProperty -name "DPM Version" -value $dpmVersion
	$Serverobj | Add-Member NoteProperty -name "DPM Build" -value $ds.GetProductInformation().Version.ToString()

	$Serverobj | Out-File $OutputBase -append

	#Now that we have a valid connect let's get the disk information for the dpmServer
	[System.Array]$dpmDisk = Get-DPMDisk $ServerName 

	#Gather tape library info
	$dpmLibrary = Get-DPMLibrary -DPMServerName $ServerName

	#Build list of datasources and protection groups
	$dpmPG = Get-ProtectionGroup -DPMServerName $ServerName
	
	"**************************************************" | Out-File $OutputBase -append
	"*          STORAGE POOL DISK INFORMATION         *" | Out-File $OutputBase -append
	"**************************************************" | Out-File $OutputBase -append
	$dpmDisk | Format-List | Out-File $OutputBase -append

	"**************************************************" | Out-File $OutputBase -append
	"*          TAPE LIBRARY INFORMATION              *" | Out-File $OutputBase -append
	"**************************************************" | Out-File $OutputBase -append
	# We have to check to be sure a tape library is present...
	if ($dpmLibrary)
	{   
		$dpmLibrary | Format-List |  Out-File $OutputBase -append
		"**************************************************" | Out-File $OutputBase -append
		"*          TAPE DRIVE INFORMATION                *" | Out-File $OutputBase -append
		"**************************************************" | Out-File $OutputBase -append
		$TDobj = New-Object PSObject
			foreach ($TapeLib in $dpmLibrary)
			{
				$TDobj | Add-Member NoteProperty -Force -name "Name" -value $TapeLib.UserFriendlyName
				$TDobj | Add-Member NoteProperty -Force -name "Product ID" -value $TapeLib.ProductId
				$TDobj | Add-Member NoteProperty -Force -name "Serial #" -value $TapeLib.SerialNumber
				$TDobj | Add-Member NoteProperty -Force -name "Tape Drive Enabled?" -value $TapeLib.IsEnabled
				$TDobj | Add-Member NoteProperty -Force -name "Tape Drive offline?" -value $TapeLib.IsOffline
				$TDobj | Out-File $OutputBase -append
			}
	} else {
		"WARNING: NO TAPE LIBRARIES FOUND" | Out-File $OutputBase -append
	}

	"**************************************************" | Out-File $OutputBase -append
	"*          PROTECTION GROUPS                     *" | Out-File $OutputBase -append
	"**************************************************" | Out-File $OutputBase -append
    ""                                                   | Out-File $OutputBase -append

	if ($dpmPG)
	{
#-------------------------------------------------- NEW CHANGE START -------------------
		add-pssnapin sqlservercmdletsnapin100 -ErrorAction SilentlyContinue
		Push-Location; Import-Module SQLPS -ErrorAction SilentlyContinue ; Pop-Location

        function recovery ($Datasource)
        {
            $RPList = @(Get-RecoveryPoint $Datasource)
            if ($RPList.count -gt 0)
            {
                "             Backup Time              Location   Generation" | Out-File $OutputBase -append
                "             ----------------------   --------   ----------" | Out-File $OutputBase -append
                foreach ($RP in $RPList)
                {
                    ("             {0,22}   {1,8}   {2}" -f $rp.BackupTime, $RP.Location, $RP.RecoverySourceLocations.generation) | Out-File $OutputBase -append
                }     
            }
            else
            {
                "             No recovery point found for this datasource" | Out-File $OutputBase -append
            }
        }

        # Get DPM server FQDN and DPM Database
        $DPMServerConnection = (Connect-DPMServer (&hostname))
        $DPMServer = $DPMServerConnection.name

        # Find out where DPMDB is located for he local DPM Server
        $DPMDB = $dpmserverconnection.dpmdatabaselogicalpath.substring($dpmserverconnection.DPMDatabaseLogicalPath.LastIndexOf('\') + 1,$dpmserverconnection.DPMDatabaseLogicalPath.Length - $dpmserverconnection.DPMDatabaseLogicalPath.LastIndexOf('\') -1 )
        $DPM   = $dpmserverconnection.dpmdatabaselogicalpath.substring(0,$dpmserverconnection.DPMDatabaseLogicalPath.LastIndexOf('\'))

        $DPMMajorVersion = (Get-ChildItem ((get-itemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft Data Protection Manager\setup\").installpath + "bin\msdpm.exe")).VersionInfo.fileversion.split('.')[0]
        
        $PGList = @(Get-ProtectionGroup (&hostname) | Sort-Object name)
        foreach ($pg in $PGList)
        {
            if ($DPMMajorVersion -eq '3') # DPM 2010
            {
               "Protection Group............: " + $pg.friendlyname | out-file $OutputBase -append
            }
            else
            {
              "Protection Group............: " + $pg.name             | out-file $OutputBase -append
              "Protection Method...........: " + $pg.ProtectionMethod | out-file $OutputBase -append
              if ($pg.IsDiskShortTerm)
              {
                    "Short-Term Disk Backup time.: " + (Get-DPMPolicySchedule -ProtectionGroup $PG -ShortTerm).ScheduleDescription | out-file $OutputBase -append
                    "Short-Term Disk Retention...: " + (Get-DPMPolicyObjective -ProtectionGroup $pg -ShortTerm).retentionrange.range + " " + (Get-DPMPolicyObjective -ProtectionGroup $pg -ShortTerm).retentionrange.unit | out-file $OutputBase -append
              }
              if ($pg.IsTapeShortTerm)
              {
                    "Short-Term Tape Backup time.: " + (Get-DPMPolicySchedule -ProtectionGroup $PG -ShortTerm).ScheduleDescription | out-file $OutputBase -append
                    "Short-Term Tape Retention...: " + $pg.ArchiveIntent.RetentionPolicy.OnsiteFather.ToString() | out-file $OutputBase -append
            }
              if ($pg.IsTapeLongTerm)
              {
                    "Long-Term Backup time Goal 1: " + @((Get-DPMPolicySchedule -ProtectionGroup $pg -LongTerm Tape) | sort-object jobtype -Descending)[0].ScheduleDescription  | out-file $OutputBase -append
                    "Long_term Retention Goal 1..: " + $pg.ArchiveIntent.RetentionPolicy.OffsiteFather.ToString() | out-file $OutputBase -append
                    if ($pg.ArchiveIntent.RetentionPolicy.OffsiteGrandfather.Enabled)
                    {
                        "Long-Term Backup time Goal 2: " + @((Get-DPMPolicySchedule -ProtectionGroup $pg -LongTerm Tape) | sort-object jobtype -Descending)[1].ScheduleDescription | out-file $OutputBase -append
                        "Long_term Retention Goal 2..: " + $pg.ArchiveIntent.RetentionPolicy.OffsiteGrandfather.ToString() | out-file $OutputBase -append
                        if ($pg.ArchiveIntent.RetentionPolicy.OffsiteGreatGrandfather.Enabled)
                        {
                            "Long-Term Backup time Goal 3: " + @((Get-DPMPolicySchedule -ProtectionGroup $pg -LongTerm Tape) | sort-object jobtype -Descending)[2].ScheduleDescription | out-file $OutputBase -append
                            "Long_term Retention Goal 3..: " + $pg.ArchiveIntent.RetentionPolicy.OffsiteGreatGrandfather.ToString() | out-file $OutputBase -append
                        }
                    }
              }
              if ($pg.IsCloudLongTerm)
            {
                    "Online Backup time..........: " + (Get-DPMPolicySchedule -ProtectionGroup $pg -LongTerm online).scheduledescription | out-file $OutputBase -append
                    if ((Get-DPMPolicyObjective $PG -LongTerm Online).RetentionRangeDaily.range)
                    {
                        "Daily Retention Range.......: " + (Get-DPMPolicyObjective $PG -LongTerm Online).RetentionRangeDaily.range + " "  + (Get-DPMPolicyObjective $PG -LongTerm Online).RetentionRangeDaily.unit | out-file $OutputBase -append
                    }
                    if ((Get-DPMPolicyObjective $PG -LongTerm Online).RetentionRangeWeekly.range)
                    {
                        "Weekly Retention Range......: " + (Get-DPMPolicyObjective $PG -LongTerm Online).RetentionRangeWeekly.range + " "  + (Get-DPMPolicyObjective $PG -LongTerm Online).RetentionRangeWeekly.unit | out-file $OutputBase -append
                    }
                    if ((Get-DPMPolicyObjective $PG -LongTerm Online).RetentionRangeMonthly.range)
                    {
                        "Monthly Retention Range.....: " + (Get-DPMPolicyObjective $PG -LongTerm Online).RetentionRangeMonthly.range + " "  + (Get-DPMPolicyObjective $PG -LongTerm Online).RetentionRangeMonthly.unit | out-file $OutputBase -append
                    }
                    if ((Get-DPMPolicyObjective $PG -LongTerm Online).RetentionRangeYearly.range)
                    {
                        "Yearly Retention Range......: " + (Get-DPMPolicyObjective $PG -LongTerm Online).RetentionRangeYearly.range + " "  + (Get-DPMPolicyObjective $PG -LongTerm Online).RetentionRangeYearly.unit | out-file $OutputBase -append
                    }
              }

              "Performance Optimization....: " + $pg.PerformanceSettings | out-file $OutputBase -append
            }
            $DSList = @(Get-Datasource $pg | Sort-Object ProductionServerName, name)
            $ComputerName = $DSList[0].ProductionServerName
            "   Computer: " + $ComputerName | out-file $OutputBase -append
            foreach ($DS in $DSList)
            {
                if ($ds.ProductionServerName -ne $ComputerName)
                {
                    $ComputerName = $DS.ProductionServerName
                    "   Computer: " + $ComputerName | out-file $OutputBase -append
                }
                ("       type: {0,-20} - Datasource Name: {1}" -f $ds.ObjectType, $ds.DisplayPath ) 
                ("       type: {0,-20} - Datasource Name: {1}" -f $ds.ObjectType, $ds.DisplayPath ) | out-file $OutputBase -append
        	    if ($DPMMajorVersion -eq '3') # DPM 2010
                {
                   $ObjectType = $ds.type.name
                }
                else
                {
                   $ObjectType = $ds.ObjectType
                }

                switch ($ObjectType)
                {
                    'System Protection' {   $query = "select ComponentName 
                                                      from tbl_IM_ProtectedObject 
                                                      where ProtectedInPlan = 1 and 
	                                                  (ComponentName like 'Bare Metal Recovery' or ComponentName like 'System State') and 
	                                                  DataSourceId like '"+ $ds.DatasourceId + "'"
                                            $DSTypeList = @(Invoke-Sqlcmd -ServerInstance $DPM -Database $DPMDB -Query $query)
                                            foreach ($DSType in $DSTypeList)
                                            {                                        
                                                "            " + $DSType.ComponentName | out-file $OutputBase -append
                                            }
                                        }
                    'SharePoint Farm'   {   $query = "select ComponentName 
                                                      from tbl_IM_ProtectedObject 
                                                      where ProtectedInPlan = 1 and
	                                                  ReferentialDataSourceId like '"+ $ds.DatasourceId + "' order by convert(varchar(max),LogicalPath)"
                                            $DSTypeList = @(Invoke-Sqlcmd -ServerInstance $DPM -Database $DPMDB -Query $query)
                                            foreach ($DSType in $DSTypeList)
                                            {                                        
                                                 "         " + $DSType.ComponentName | out-file $OutputBase -append
                                           }
                                        }
                    'Volume'            {   $query = "select LogicalPath
                                                      from tbl_IM_ProtectedObject 
                                                      where ProtectedInPlan = 1 and
	                                                  DataSourceId like '"+ $ds.DatasourceId + "' order by convert(varchar(max),LogicalPath)"
                                            $DSTypeList = @(Invoke-Sqlcmd -ServerInstance $DPM -Database $DPMDB -Query $query)
                                            Foreach ($DSType in $DSTypeList)
                                            {
                                                [xml]$xml = $DSType.LogicalPath
                                                $type = ($xml.ArrayOfInquiryPathEntryType.InquiryPathEntryType)[-1]
                                                if ($type.type -eq 'NonRootTargetShare')
                                                {
                                                    "             Share  - " +  $Type.value | out-file $OutputBase -append
                                                }
                                                else
                                                {
                                                    "             " + $type.type + " - " + $Type.value | out-file $OutputBase -append
                                                }
                                            }
                                        }
                }
            }
            "" | out-file $OutputBase -append
        }
#-------------------------------------------------- NEW CHANGE END   -------------------
<#
		$dpmPG | Format-List | Out-File $OutputBase -append
		"--------------------------------------------------" | Out-File $OutputBase -append
		"Shorterm Retention Range: " | Out-File $OutputBase -append
		$dpmPG.OnsiteRecoveryrange | fl | Out-File $OutputBase -append
		"--------------------------------------------------" | Out-File $OutputBase -append
		"Longterm Retention Range: " | Out-File $OutputBase -append
		$dpmPG.OffsiteRecoveryRange | fl | Out-File $OutputBase -append

		foreach ($pgName in $dpmPG)
		{
			"**************************************************" | Out-File $OutputBase -append
			"Protection Group: " + $pgName.FriendlyName | Out-File $OutputBase -append
			"**************************************************" | Out-File $OutputBase -append
			"--------------------------------------------------" | Out-File $OutputBase -append
			"*          DATA SOURCES SUMMARY                  *" | Out-File $OutputBase -append
			"--------------------------------------------------" | Out-File $OutputBase -append
			$dpmDS = Get-Datasource -ProtectionGroup $pgName
			$dpmDS | format-list -property ProductionServerName, Name | Out-File $OutputBase -append
 
			#Now go through each datasource and print additional info
			"--------------------------------------------------" | Out-File $OutputBase -append
			"*          DATA SOURCE DETAILS                   *" | Out-File $OutputBase -append
			"--------------------------------------------------" | Out-File $OutputBase -append
			#Setup an event since Get-DataSource is async
			$global:DSCount = 0
			$LoopCounter = 0
			foreach ($dsName in $dpmDS)
			{
				if ($dsName.TotalRecoveryPoints -eq 0) {
					Register-ObjectEvent -InputObject $dsName -EventName DatasourceChangedEvent -SourceIdentifier "EVENT$LoopCounter" -Action {$global:DSCount++} 
					$LoopCounter++
				} else {
					$global:DSCount++
				}
			}

			#trigger the event to signal
			$dpmDS.TotalRecoveryPoints > $null

			#Check to see if signaled yet
			if ($dpmDS.TotalRecoveryPoints -eq 0)
			{
				$begin = get-date
				$m = Measure-Command {
					while (((Get-Date).subtract($begin).seconds -lt 120) -and ($global:DSCount -ne 0))
					{
						sleep -Milliseconds 100
					}
				}
			}

			#Event has been signaled or we reached the 120 second timeout. Now update the datasources
			$dpmDS = Get-Datasource -ProtectionGroup $pgName
			$DSObj = New-Object PSObject

			foreach ($dsName in $dpmDS)
			{
				$DSobj | Add-Member NoteProperty -Force -name "Computer" -value $dsName.ProductionServerName
				$DSobj | Add-Member NoteProperty -Force -name "Datasource Name" -value $dsName.Name
				$DSobj | Add-Member NoteProperty -Force -name "Disk allocation" -value  $dsName.DiskAllocation
				$DSobj | Add-Member NoteProperty -Force -name "Total recovery points" -value $dsName.TotalRecoveryPoints

				if ($dsName.TotalRecoveryPoints -ne 0) 
				{
					$DSobj | Add-Member NoteProperty -Force -name "Latest recovery point" -value $dsName.LatestRecoveryPoint
					$DSobj | Add-Member NoteProperty -Force -name "Oldest recovery point" -value $dsName.OldestRecoveryPoint
				} else {
					if ($dsName.TotalRecoveryPoints -eq 0)
					{
						$DSobj | Add-Member NoteProperty -Force -name "Latest recovery point" -value "NO VALID RECOVERY POINTS"
						$DSobj | Add-Member NoteProperty -Force -name "Oldest recovery point" -value "NO VALID RECOVERY POINTS"
					} else {
						$DSobj | Add-Member NoteProperty -Force -name "Latest recovery point" -value $dsName.LatestRecoveryPoint
						$DSobj | Add-Member NoteProperty -Force -name "Oldest recovery point" -value $dsName.OldestRecoveryPoint
					}
				}
			}
			# Unregister-Event *
			$DSObj | Out-File $OutputBase -append

			#Now add longterm backup info

			"--------------------------------------------------" | Out-File $OutputBase -append
			"*              LONG TERM - TAPE                  *" | Out-File $OutputBase -append
			"--------------------------------------------------" | Out-File $OutputBase -append
			switch ($dpmversion)
			{
				"Microsoft System Center Data Protection Manager 2010" {
					$policySchedule = @(Get-PolicySchedule -ProtectionGroup $pgName -longterm tape)
					}
				default {
					"NOT TESTED ON THIS DPM VERSION" | Out-File $OutputBase -append
					 }
			}

			$tb = Get-TapeBackupOption $pgName;$tb.labelinfo
			$label = @($tb.label);
			$count = $policySchedule.count -1
			while ($count -ne -1)
			{
				if ($label[$count].length -eq 0 -or $label[$count].length -eq $null)
				{ 
					"Default Label Name" | Out-File $OutputBase -append
				}
				else
				{
					"Tape Label: " + $label[$count] | Out-File $OutputBase -append
				}
				$policyschedule[$count] | fl * | Out-File $OutputBase -append
				$count--
			}
		}
		"--------------------------------------------------" | Out-File $OutputBase -append
		"* TAPES LOADED INTO SLOTS THAT ARE OFFLINE READY *" | Out-File $OutputBase -append
		"--------------------------------------------------" | Out-File $OutputBase -append
		$count = 0
		$dpmLibrary = @($dpmlibrary | ? { $_.Isoffline -eq $false })
		if ($dpmlibrary)
		{
			foreach ($library in $dpmlibrary)
			{
				$tapelist = get-tape $library
				foreach ($tape in $tapelist)
				{
					if ($tape.IsOffsiteReady -eq $true)
					{
						("{0,-30} | {1,-9} | {2,-25} | {3,-50}" -f $tape.libraryname, $tape.location, $tape.barcode, $tape.Label) | Out-File $OutputBase -append
						$count++
					}
				}
			}
			if ($count -eq 0)
			{
				"No Tapes are marked as offsite ready"  | Out-File $OutputBase -append
			}
		}
		else
		{
			"No online library was found on this system"  | Out-File $OutputBase -append
		}
	}
#>  
}
else {
		"WARNING: NO PROTECTION GROUPS FOUND" | Out-File $OutputBase -append
	}

	return
}

####################################################################################
# Main
####################################################################################
Import-LocalizedData -BindingVariable LocalizedGetDPMInfo -FileName DC_GetDPMInfo -UICulture en-us

Write-DiagProgress -Activity $LocalizedGetDPMInfo.ID_DPM_ACTIVITY -Status $LocalizedGetDPMInfo.ID_DPM_STATUS_GetDPMInfo

# Check first to be sure DPM is installed otherwise exit
if (IsDPMInstalled)
{
	$LocalizedGetDPMInfo.ID_DPM_INSTALLED | ConvertTo-Xml | Update-DiagReport -Id $LocalizedGetDPMInfo.ID_DPM_INFO -Name $LocalizedGetDPMInfo.ID_DPM_INFORMATION
} else {
	$LocalizedGetDPMInfo.ID_DPM_NOT_INSTALLED | ConvertTo-Xml | Update-DiagReport -Id $LocalizedGetDPMInfo.ID_DPM_INFO -Name $LocalizedGetDPMInfo.ID_DPM_INFORMATION -verbosity "Warning"
	exit 1
}

$DPMVersion = DPMVersion (GetDPMInstallFolder)
if($null -ne $DPMVersion)
{
	$DPMServerName = GetDPMServerName
	$OutputBase= $DPMServerName + "_DPM_Info.txt"
	LoadDPMNamespace

	# Prints the info
	PrintInfo $DPMServerName

	Disconnect-DPMServer -DPMServer $DPMServername
	CollectFiles -filesToCollect $OutputBase -fileDescription $LocalizedGetDPMInfo.ID_DPM_SETTINGS -sectionDescription $LocalizedGetDPMInfo.ID_DPM_INFORMATION

	exit 0
}
else
{
	"Script DC_GetDPMInfo.ps1 running on a Protected Server, no data will be collected" | WriteTo-StdOut -ShortFormat
}


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAJWfdLwPOMn3Wy
# sAiYKI+2M5R8EJBSgzPaeM8gYUjdnqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPyxCdO7ze4+OwxXC2DVt3ec
# yNe8+wfk/4lDbHD5ZcvvMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAlVolAXegl5B026czS7yiSoVMorL9YLgyIlIYBoHp0qQ2Ory7GSs+E
# Bsm2PaxDsPXhzSh5bM452yPpWVYlZA8U2Qp4KTMLRtTWjnDFPqN0WhMgv7FCzvqH
# BPhNRrZAUqYC1ecdK/W4ApnET4PqYb4gB02jQFxW6dgVZRG7xdOB+rQPzLDWUdM4
# bHvD7m38JEuJ6l8GFN236GXhtojzXqkdL2Gk0dC9abtjh5PrVGiNcdSKQ/NBMRBF
# MvgsfKBJQuwfLZ0mY727IhSUKO5wEeq5Ic5M64D94MfChPlZXECh2CWWvKunhg5n
# xD6mvQsgcxFTxSihnOJ2orjgdgYbIqn9oYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIB5AZec6PUCj2/2rAevXH5zmiWwosvynDxAJORNCVVPcAgZi0AB1
# L68YEzIwMjIwODAxMDc0MDE4LjA0N1owBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNCQkQt
# RTMzOC1FOUExMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGd/onl+Xu7TMAAAQAAAZ0wDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTE5WhcNMjMwMjI4MTkwNTE5WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JCRC1FMzM4LUU5QTExJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDgEWh60BxJFuR+mlFuFCtG3mR2XHNCfPMTXcp06Yew
# AtS1bbGzK7hDC1JRMethcmiKM/ebdCcG6v6k4lQyLlSaHmHkIUC5pNEtlutzpsVN
# +jo+Nbdyu9w0BMh4KzfduLdxbda1VztKDSXjE3eEl5Of+5hY3pHoJX9Nh/5r4tc4
# Nvqt9tvVcYeIxpchZ81AK3+UzpA+hcR6HS67XA8+cQUB1fGyRoVh1sCu0+ofdVDc
# WOG/tcSKtJch+eRAVDe7IRm84fPsPTFz2dIJRJA/PUaZR+3xW4Fd1ZbLNa/wMbq3
# vaYtKogaSZiiCyUxU7mwoA32iyTcGHC7hH8MgZWVOEBu7CfNvMyrsR8Quvu3m91D
# qsc5gZHMxvgeAO9LLiaaU+klYmFWQvLXpilS1iDXb/82+TjwGtxEnc8x/EvLkk7U
# kj4uKZ6J8ynlgPhPRqejcoKlHsKgxWmD3wzEXW1a09d1L2Io004w01i31QAMB/GL
# hgmmMIE5Z4VI2Jlh9sX2nkyh5QOnYOznECk4za9cIdMKP+sde2nhvvcSdrGXQ8fW
# O/+N1mjT0SIkX41XZjm+QMGR03ta63pfsj3g3E5a1r0o9aHgcuphW0lwrbBA/TGM
# o5zC8Z5WI+Rwpr0MAiDZGy5h2+uMx/2+/F4ZiyKauKXqd7rIl1seAYQYxKQ4SemB
# 0QIDAQABo4IBNjCCATIwHQYDVR0OBBYEFNbfEI3hKujMnF4Rgdvay4rZG1XkMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAIbHcpxLt2h0LNJ334iCNZYsta2Eant9JUeipwebFIwQMij7SIQ83iJ4Y4OL
# 5YwlppwvF516AhcHevYMScY6NAXSAGhp5xYtkEckeV6gNbcp3C4I3yotWvDd9KQC
# h7LdIhpiYCde0SF4N5JRZUHXIMczvNhe8+dEuiCnS1sWiGPUFzNJfsAcNs1aBkHI
# taSxM0AVHgZfgK8R2ihVktirxwYG0T9o1h0BkRJ3PfuJF+nOjt1+eFYYgq+bOLQs
# /SdgY4DbUVfrtLdEg2TbS+siZw4dqzM+tLdye5XGyJlKBX7aIs4xf1Hh1ymMX24Y
# Jlm8vyX+W4x8yytPmziNHtshxf7lKd1Pm7t+7UUzi8QBhby0vYrfrnoW1Kws+z34
# uoc2+D2VFxrH39xq/8KbeeBpuL5++CipoZQsd5QO5Ni81nBlwi/71JsZDEomso/k
# 4JioyvVAM2818CgnsNJnMZZSxM5kyeRdYh9IbjGdPddPVcv0kPKrNalPtRO4ih0G
# VkL/a4BfEBtXDeEUIsM4A00QehD+ESV3I0UbW+b4NTmbRcjnVFk5t6nuK/FoFQc5
# N4XueYAOw2mMDhAoFE+2xtTHk2ewd9xGkbFDl2b6u/FbhsUb5+XoP0PdJ3FTNP6G
# /7Vr4sIOxar4PpY674aQCiMSywwtIWOoqRS/OP/rSjF9E/xfMIIHcTCCBVmgAwIB
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
# IEVTTjozQkJELUUzMzgtRTlBMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAt+lDSRX92KFyij71Jn20CoSyyuCg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRkLAwIhgPMjAyMjA4MDEwNzM3MjBaGA8yMDIyMDgwMjA3MzcyMFow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pGQsAIBADAKAgEAAgIiFAIB/zAHAgEA
# AgIRwzAKAgUA5pLiMAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAG0flC5o
# 3nfbeONYN62eVFhoaQPRqngb9jI5nmRcDbs2f0QoDM1cx+8dFgju7DbN6BIbJwAc
# f8ARFUTKHsdJugPVgt0AStfK+Jh24+0PWnxyRymIZAnN/Ufm5SVCFqS5+sJUf4uP
# BZiAnxw4bEUCPNX44mKs1oM1/bpMplvknhriMYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGd/onl+Xu7TMAAAQAAAZ0wDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgs0OzdcVOhJm3524lCeyFfMahHr37D7JRUBEv6zSzHqIwgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCD1HmOt4IqgT4A0n4JblX/fzFLyEu4O
# BDOb+mpMlYdFoTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABnf6J5fl7u0zAAAEAAAGdMCIEIPC6k4XcrTRcOe8jIhqeQlXoooW1cr3v
# 1A2paYqNVWNdMA0GCSqGSIb3DQEBCwUABIICAGZWIzmiaCYqNW5vKdgnthWpytWQ
# 0Y4Y1c5pRsox7Vu6+1RH4bex7DxyCn8h4LHLl4gjFi5OK98c//7gaqezvMdG9gUa
# r/HCDVeAV6xWXYvP5PsVHnVEQfRwtXrA4yd4tX+Z/jITWIwWdAP1elNtR5bjLTVG
# //adoksGYqXuI0xwlUkEIcaCjwN5eL6uS/iCgfnkn4z/jTCmkpY15pm94L5YKdw0
# tXzZshuvMztgm739WRBqiHqJ1WE0PKmTZN2tX+9vBCKZ5q034PSw2W6CZybCi/4s
# Bhd1ZlvH1XOFnMJgB19AHwOEVhFMtoFK2icLFOkEScRrHquoeWKwlRACmLkBelsM
# Uz7E/QSNr8lOzzMyEdqseTAfKGm0Q73Ja7jWJ5uWniV2ino8moX+PjEoPSiGHbIz
# PR1z1Zg58sBCL9PZ8X/dKrv3bS985Z6C5S24i+nBhMLwImQ4u1GTODGoZUe3o8qC
# gHvKb6b36dIm6aElFI+iL3wllkeo9+ic/vuzaYkY8Xed+i2V5l48MG4thsOgnJNQ
# d9qj7/LuVI+xuywxgwsyNODtjOzz/37JRDVsRm2+oloCAaGK4b6CERjz1D/5TNtH
# ovFwr21syrBsHOwxWmGIN4QHyxnK59tHyvlEgsCW91k3QOGWtwXRZ0Z4lm5N4t7w
# Eaut8XRekm5tdHMX
# SIG # End signature block
