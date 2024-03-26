# *****************************************************************************************
# Version 1.0
# Date: 02-23-2012
# Author: Vinay Pamnani - vinpa@microsoft.com
# Description:
# 		Collects all Configuration Manager Logs
#		Log Collection flags are pre-set in appropriate utils script.
#		1. Collects CCM Logs.
#		2. Collects SMS Logs.
#		3. Collects most recent copy of CrashDumps and Crash.log for previous 9 crashes.
#		4. Collects Admin Console Logs.
#		5. Collects Site Setup Logs.
#		6. Collects CCMSetup Logs.
#		7. Collects WSUS Logs.
#		8. Collects logs for new CM12 Roles
#		9. Collects Lantern Logs for CM12 Client
#		10. Compresses all logs to ConfigMgrLogs.zip
# *****************************************************************************************

trap [Exception]
{
	WriteTo-ErrorDebugReport -ErrorRecord $_
	continue
}

TraceOut "Started"
TraceOut "GetCCMLogs: $GetCCMLogs"
TraceOut "GetSMSLogs: $GetSMSLogs"
TraceOut "CCMSetup Logs Directory = $CCMSetupLogPath"
TraceOut "AdminUI Logs Directory: $AdminUILogPath"

Import-LocalizedData -BindingVariable ScriptStrings

$Destination = Join-Path $Env:windir ("\Temp\" + $ComputerName + "_Logs_ConfigMgr")
$ZipName = "Logs_ConfigMgr.zip"
$Compress = $false
$fileDescription = "ConfigMgr Logs"
$sectionDescription = "Configuration Manager Logs"

# Remove temp destination directory if it exists
If (Test-Path $Destination){
	Remove-Item -Path $Destination -Recurse
}

# ---------
# CCM Logs
# ---------

TraceOut "    Getting CCM Logs"
If ($null -ne $CCMLogPath)
{
	# CCM Logs
	If (Test-Path ($CCMLogPath))
	{
		Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectConfigMgrLogs -Status $ScriptStrings.ID_SCCM_CCM_CollectConfigMgrLogs
		$TempDestination = Join-Path $Destination "CCM_Logs"
		New-Item -ItemType "Directory" $TempDestination | Out-Null #_#

		# Copy-Item ($CCMLogPath + "\*.lo*") ($TempDestination) -ErrorAction SilentlyContinue -Force
		Copy-FilesWithStructure -Source $CCMLogPath -Destination $TempDestination -Include *.lo*

		if (Test-Path (Join-Path $Env:windir "\WindowsUpdate.log")) {
			Copy-Item ($Env:windir + "\WindowsUpdate.log") ($TempDestination) -ErrorAction SilentlyContinue
		}
		$Compress = $true
	}
	Else
	{
		TraceOut "      $CCMLogPath does not exist. CCM Logs not collected. Check Logging\@Global\LogDirectory Registry Key Value."
	}

	if ($GetCCMLogs) {
		# Software Catalog Logs
		TraceOut "    Getting Software Catalog Logs for all users"
		$TempDestination = Join-Path $Destination "CCM_SoftwareCatalog_Logs"
		New-Item -ItemType "Directory" $TempDestination | Out-Null #_#
		if ($OSVersion.Major -lt 6) {
			$ProfilePath = Join-Path $env:systemdrive "Documents and Settings"
			$SLPath = "\Local Settings\Application Data\Microsoft\Silverlight\is"
		}
		else {
			$ProfilePath = Join-Path $env:systemdrive "Users"
			$SLPath = "\AppData\LocalLow\Microsoft\Silverlight\is"
		}

		Get-ChildItem $ProfilePath | `
			ForEach-Object {
				if (!$_.Name.Contains("All Users") -and !$_.Name.Contains("Default") -and !$_.Name.Contains("Public") -and !$_.Name.Contains("LocalService") -and !$_.Name.Contains("NetworkService") -and !$_.Name.Contains("Classic .NET AppPool")) {
					$currentUserName = $_.Name
					TraceOut "      Checking user $currentUserName"
					Get-ChildItem -Path (Join-Path $_.FullName $SLpath) -Recurse -Filter *ConfigMgr*.lo* -ErrorAction SilentlyContinue | `
						ForEach-Object {
							TraceOut "        Copying ConfigMgr Silverlight logs for $currentUserName"
							Copy-Item -Path $_.FullName -Destination "$TempDestination\$($currentUserName)_$($_)" -Force
							$Compress = $true
						}
				}
			}
	}
}
Else
{
	TraceOut "    Client detected but CCMLogPath is set to null. CCM Logs not collected. Check Logging\@Global\LogDirectory Registry Key Value."
}

# ----------
# SMS Logs
# ----------
TraceOut "    Getting SMS Logs"
If ($null -ne $SMSLogPath)
{
	If (Test-Path ($SMSLogPath))
	{
		Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectConfigMgrLogs -Status $ScriptStrings.ID_SCCM_SMS_CollectConfigMgrLogs

		# SMS Logs
		$SubDestination =Join-Path $Destination "SMS_Logs"
		New-Item -ItemType "Directory" $SubDestination | Out-Null #_#
		# Copy-Item ($SMSLogPath + "\*.lo*") $SubDestination
		Copy-Files -Source $SMSLogPath -Destination $SubDestination -Filter *.lo*

		# CrashDumps
		If (Test-Path ($SMSLogPath + "\CrashDumps"))
		{
			Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectConfigMgrLogs -Status $ScriptStrings.ID_SCCM_CrashDumps_CollectConfigMgrLogs
			$CrashDumps = Get-ChildItem ($SMSLogPath + "\CrashDumps") | Sort-Object CreationTime -Descending | Select-Object -first 10
			$i = 0
			for ($i = 0 ; $i -lt $CrashDumps.Length ; $i++)
			{
				if ($i -eq 0)
				{
					Copy-Item $CrashDumps[$i].PSPath ($Destination + "\CrashDumps\" + $CrashDumps[$i] + "_Full") -Recurse
				}
				else
				{
					New-Item -ItemType "Directory" ($Destination + "\CrashDumps\" + $CrashDumps[$i]) -Force | Out-Null #_#
					Copy-Item ($CrashDumps[$i].PSPath + "\crash.log") ($Destination + "\CrashDumps\" + $CrashDumps[$i] + "\crash.log") -ErrorAction SilentlyContinue
				}
			}
		}

		$Compress = $true
	}
	Else
	{
		TraceOut "      $SMSLogPath does not exist. SMS Logs not collected. Check $Reg_SMS\Identification\Installation Directory Registry Key Value."
	}
}
Else
{
	TraceOut "      SMSLogPath is set to null. SMS Logs not collected. Check $Reg_SMS\Identification\Installation Directory Registry Key Value."
}

# Collect SQL Backup Logs. Not implemented for CM07.
If ($Is_SiteServer)
{
	TraceOut "    Getting SQLBackup Logs"
	if ($null -ne $SQLBackupLogPathUNC) {
		if (Test-Path $SQLBackupLogPathUNC) {
			$SubDestination = Join-Path $Destination ("SMSSqlBackup_" + $ConfigMgrDBServer + "_Logs")
			New-Item -ItemType "Directory" $SubDestination | Out-Null #_#

			TraceOut "SubDestination = $SubDestination"
			#Copy-Item ($SQLBackupLogPathUNC + "\*.lo*") $SubDestination
			Copy-Files -Source $SQLBackupLogPathUNC -Destination $SubDestination -Filter *.lo*
			$Compress = $true
		}
		else {
			TraceOut "      $SQLBackupLogPathUNC does not exist or Access Denied. SMS SQL Backup Logs not collected."
		}
	}
	else {
		TraceOut "      SQLBackupLogPathUNC is set to null. SMS SQL Backup Logs not collected."
	}
}

# Collect DP Logs. For CM07, DPLogPath should be null.
TraceOut "    Getting DP Logs"
If ($null -ne $DPLogPath)
{
	If (Test-Path ($DPLogPath))
	{
		New-Item -ItemType "Directory" ($Destination + "\DP_Logs") | Out-Null #_#
		# Copy-Item ($DPLogPath + "\*.lo*") ($Destination + "\DP_Logs")
		Copy-Files -Source $DPLogPath -Destination ($Destination + "\DP_Logs") -Filter *.lo*
		$Compress = $true
	}
	Else
	{
		TraceOut "      $DPLogPath does not exist. DP Logs not collected."
	}
}
Else
{
	TraceOut "      DPLogPath is set to null. DP Logs not collected."
}

# Collect SMSProv Log(s) if SMS Provider is installed on Remote Server.
If ($Is_SMSProv)
{
	If ($Is_SiteServer -eq $false)
	{
		TraceOut "    Getting SMSProv Logs"
		If (Test-Path ($SMSProvLogPath))
		{
			New-Item -ItemType "Directory" ($Destination + "\SMSProv_Logs") | Out-Null #_#
			# Copy-Item ($SMSProvLogPath + "\*.lo*") ($Destination + "\SMSProv_Logs")
			Copy-Files -Source $SMSProvLogPath -Destination ($Destination + "\SMSProv_Logs") -Filter *.lo*

			$Compress = $true
		}
		Else
		{
			TraceOut "      $SMSProvLogPath does not exist. SMS Provider Logs not collected."
		}
	}
}

# Collect AdminUI Logs
If ($Is_AdminUI -and ($RemoteStatus -ne 2))
{
	If ($null -ne $AdminUILogPath)
	{
		TraceOut "    Getting AdminUI Logs"
		If (Test-Path ($AdminUILogPath))
		{
			Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectConfigMgrLogs -Status $ScriptStrings.ID_SCCM_AdminUI_CollectConfigMgrLogs
			New-Item -ItemType "Directory" ($Destination + "\AdminUI_Logs") | Out-Null #_#
			#$FilesToCopy = Get-ChildItem ($AdminUILogPath + "\*.log") | Where-Object -FilterScript {$_.Name -notlike "*-*"}
			#Copy-Item $FilesToCopy ($Destination + "\AdminUI_Logs")
			Copy-Files -Source $AdminUILogPath -Destination ($Destination + "\AdminUI_Logs") -Filter *.lo*
			$Compress = $true
		}
		Else
		{
			TraceOut "      $AdminUILogPath does not exist. AdminUI Logs not collected."
		}
	}
	Else
	{
		TraceOut "      AdminUI detected but AdminUILogPath is set to null. AdminUI Logs not collected."
	}
}

# Collect Setup logs
If (Test-Path ("$Env:SystemDrive\ConfigMgr*.log"))
{
	If ($RemoteStatus -ne 2) {
		TraceOut "    Getting ConfigMgr Setup Logs"
		Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectConfigMgrLogs -Status $ScriptStrings.ID_SCCM_Setup_CollectConfigMgrLogs
		New-Item -ItemType "Directory" ($Destination + "\ConfigMgrSetup_Logs") | Out-Null #_#
		Copy-Item ($Env:SystemDrive + "\Config*.lo*") ($Destination + "\ConfigMgrSetup_Logs") -Force -ErrorAction SilentlyContinue
		Copy-Item ($Env:SystemDrive + "\Comp*.lo*") ($Destination + "\ConfigMgrSetup_Logs") -Force -ErrorAction SilentlyContinue
		Copy-Item ($Env:SystemDrive + "\Ext*.lo*") ($Destination + "\ConfigMgrSetup_Logs") -Force -ErrorAction SilentlyContinue
		$Compress = $true
	}
}

# Collect CCM Setup Logs
If (Test-Path ($CCMSetupLogPath))
{
	TraceOut "    Getting CCMSetup Logs"
	Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectConfigMgrLogs -Status $ScriptStrings.ID_SCCM_CCMSetup_CollectConfigMgrLogs
	New-Item -ItemType "Directory" ($Destination + "\CCMSetupRTM_Logs") | Out-Null #_#
	New-Item -ItemType "Directory" ($Destination + "\CCMSetup_Logs") | Out-Null #_#
	Copy-Item ($CCMSetupLogPath + "\*.log") ($Destination + "\CCMSetupRTM_Logs") -Recurse -Force -ErrorAction SilentlyContinue
	Copy-Item ($CCMSetupLogPath + "\Logs\*.log") ($Destination + "\CCMSetup_Logs") -Recurse -Force -ErrorAction SilentlyContinue

	$Compress = $true
}

# Collect WSUS Logs
#If ($Is_WSUS -and ($RemoteStatus -ne 2))
#{
#	$WSUSLogPath = $WSUSInstallDir + "LogFiles"
#	TraceOut "WSUS Logs Directory: $WSUSLogPath"
#	New-Item -ItemType "Directory" ($Destination + "\WSUS_Logs")
#	Copy-Item ($WSUSLogPath + "\*.log") ($Destination + "\WSUS_Logs") -Force -ErrorAction SilentlyContinue
#	$Compress = $true
#}

# Collect App Catalog Service Logs
If ($Is_AWEBSVC -and ($RemoteStatus -ne 2))
{
	TraceOut "    Getting AppCatalogSvc Logs"
	If ($null -ne $AppCatalogSvcLogPath)
	{
		If (Test-Path ($AppCatalogSvcLogPath))
		{
			Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectConfigMgrLogs -Status $ScriptStrings.ID_SCCM_AppCat_CollectConfigMgrLogs
			New-Item -ItemType "Directory" ($Destination + "\AppCatalogSvc_Logs") | Out-Null #_#
			$FilesToCopy = Get-ChildItem ($AppCatalogSvcLogPath + "\*.*")
			Copy-Item $FilesToCopy ($Destination + "\AppCatalogSvc_Logs")
			$Compress = $true
		}
		Else
		{
			TraceOut "      $AppCatalogSvcLogPath does not exist. App Catalog Service Logs not collected."
		}
	}
	Else
	{
		TraceOut "      App Catalog Service Role detected but App Catalog Service Log Path is set to null. Logs not collected."
	}
}

# Collect App Catalog Website Logs
If ($Is_PORTALWEB -and ($RemoteStatus -ne 2))
{
	TraceOut "    Getting App Catalog Logs"
	If ($null -ne $AppCatalogLogPath)
	{
		If (Test-Path ($AppCatalogLogPath))
		{
			Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectConfigMgrLogs -Status $ScriptStrings.ID_SCCM_AppCatSvc_CollectConfigMgrLogs
			New-Item -ItemType "Directory" ($Destination + "\AppCatalog_Logs") | Out-Null #_#
			$FilesToCopy = Get-ChildItem ($AppCatalogLogPath + "\*.*")
			Copy-Item $FilesToCopy ($Destination + "\AppCatalog_Logs")
			$Compress = $true
		}
		Else
		{
			TraceOut "      $AppCatalogLogPath does not exist. App Catalog Logs not collected."
		}
	}
	Else
	{
		TraceOut "      App Catalog Role detected but App Catalog Log Path is set to null. Logs not collected."
	}
}

# Collect Enrollment Point Logs
If ($Is_ENROLLSRV -and ($RemoteStatus -ne 2))
{
	TraceOut "    Getting Enrollment Point Logs"
	If ($null -ne $EnrollPointLogPath)
	{
		If (Test-Path ($EnrollPointLogPath))
		{
			Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectConfigMgrLogs -Status $ScriptStrings.ID_SCCM_EnrollPoint_CollectConfigMgrLogs
			New-Item -ItemType "Directory" ($Destination + "\EnrollPoint_Logs") | Out-Null #_#
			$FilesToCopy = Get-ChildItem ($EnrollPointLogPath + "\*.*")
			Copy-Item $FilesToCopy ($Destination + "\EnrollPoint_Logs")
			$Compress = $true
		}
		Else
		{
			TraceOut "      $EnrollPointLogPath does not exist. Enrollment Point Logs not collected."
		}
	}
	Else
	{
		TraceOut "      Enrollment Point Role detected but Enrollment Point Log Path is set to null. Logs not collected."
	}
}

# Collect Enrollment Proxy Point Logs
If ($Is_ENROLLWEB -and ($RemoteStatus -ne 2))
{
	TraceOut "    Getting Enrollment Proxy Point Logs"
	If ($null -ne $EnrollProxyPointLogPath)
	{
		If (Test-Path ($EnrollProxyPointLogPath))
		{
			Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectConfigMgrLogs -Status $ScriptStrings.ID_SCCM_EnrollProxy_CollectConfigMgrLogs
			New-Item -ItemType "Directory" ($Destination + "\EnrollProxyPoint_Logs") | Out-Null #_#
			$FilesToCopy = Get-ChildItem ($EnrollProxyPointLogPath + "\*.*")
			Copy-Item $FilesToCopy ($Destination + "\EnrollProxyPoint_Logs")
			$Compress = $true
		}
		Else
		{
			TraceOut "      $EnrollProxyPointLogPath does not exist. Enrollment Proxy Point Logs not collected."
		}
	}
	Else
	{
		TraceOut "      Enrollment Proxy Point Role detected but Enrollment Proxy Point Log Path is set to null. Logs not collected."
	}
}

# Collect Certificate Registration Point Logs
If ($Is_CRP -and ($RemoteStatus -ne 2))
{
	TraceOut "    Getting Certificate Registration Point Logs"
	If ($null -ne $CRPLogPath)
	{
		If (Test-Path ($CRPLogPath))
		{
			Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectConfigMgrLogs -Status $ScriptStrings.ID_SCCM_CRP_CollectConfigMgrLogs
			New-Item -ItemType "Directory" ($Destination + "\CRP_Logs") | Out-Null #_#
			$FilesToCopy = Get-ChildItem ($CRPLogPath + "\*.*")
			Copy-Item $FilesToCopy ($Destination + "\CRP_Logs")
			$Compress = $true
		}
		Else
		{
			TraceOut "      $CRPLogPath does not exist. Certificate Registration Point Logs not collected."
		}
	}
	Else
	{
		TraceOut "      Certificate Registration Point Role detected but Certificate Registration Point Log Path is set to null. Logs not collected."
	}
}

If ($Is_Lantern) {
	TraceOut "    Getting Policy Platform Logs"
	If ($null -ne $LanternLogPath)
	{
		If (Test-Path ($LanternLogPath))
		{
			Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectConfigMgrLogs -Status $ScriptStrings.ID_SCCM_Lantern_CollectConfigMgrLogs
			New-Item -ItemType "Directory" ($Destination + "\PolicyPlatform_Logs") | Out-Null #_#
			Copy-Item $LanternLogPath ($Destination + "\PolicyPlatform_Logs")
			$Compress = $true
		}
		Else
		{
			TraceOut "      $LanternLogPath does not exist. Microsoft Policy Platform Logs not collected."
		}
	}
	Else
	{
		TraceOut "      Microsoft Policy Platform is Installed but Log Path is set to null. Logs not collected."
	}
}

If ($Is_PXE) {
	TraceOut "    Getting WDS Logs"
	New-Item -ItemType "Directory" ($Destination + "\WDS_Logs") | Out-Null #_#
	Copy-Item ("$Env:windir\tracing\wds*.log") ($Destination + "\WDS_Logs") -Recurse -Force -ErrorAction SilentlyContinue
	$Compress = $true
}

# Collect System Health Validator Point Logs
If ($Is_SMSSHV -and ($RemoteStatus -ne 2))
{
	TraceOut "    Getting System Health Validator Point Logs"
	If ($null -ne $SMSSHVLogPath)
	{
		If (Test-Path ($SMSSHVLogPath))
		{
			#Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectConfigMgrLogs -Status $ScriptStrings.ID_SCCM_EnrollProxy_CollectConfigMgrLogs
			New-Item -ItemType "Directory" ($Destination + "\SMSSHV_Logs") | Out-Null #_#
			$FilesToCopy = Get-ChildItem ($SMSSHVLogPath + "\*.*")
			Copy-Item $FilesToCopy ($Destination + "\SMSSHV_Logs")
			$Compress = $true
		}
		Else
		{
			TraceOut "      $SMSSHVLogPath does not exist. System Health Validator Point Logs not collected."
		}
	}
	Else
	{
		TraceOut "      System Health Validator Point Role detected but System Health Validator Point Log Path is set to null. Logs not collected."
	}
}

# Compress and Collect Logs if something was copied
If ($Compress)
{
	TraceOut "    Compressing and collecting logs"
	Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectConfigMgrLogs -Status $ScriptStrings.ID_SCCM_Compress_CollectConfigMgrLogs
	compressCollectFiles -DestinationFileName $ZipName -filesToCollect ($Destination + "\*.*") -sectionDescription $sectionDescription -fileDescription $fileDescription -Recursive -ForegroundProcess -noFileExtensionsOnDescription
	Remove-Item -Path $Destination -Recurse
}


# SIG # Begin signature block
# MIInrQYJKoZIhvcNAQcCoIInnjCCJ5oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCJq00SFtiUN0Py
# mnicEJAABUZrd2Q/K5JzTEh8zbHe6qCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGY0wghmJAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIwnO7eQJcoarxlpUIXkUP8f
# bHo4BXFjO3Fnz7Grl7K7MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBPbzRx69htJb/Xdwq5184fBzK/sH187i5Z1yJGAcTnIqYg2gWR3xkz
# S5l6ONRPrID+ypH6lIoF7ITvZCKvEEnraPnBXNsYvv+ZUCW610b2kK2+GgUQXX4M
# JtGmUVmB9so0rq0cObae2qhuXR8SVBFdLhY7HGqPPrxYdPDvouFqZNs1+IExFtfb
# NdePQ8AKOskKj23M4G62bx6sF84BAC4GL6FBTf19TqCgU1k+Hr9Xo0TiVlaYSg5M
# OJVZ9msZBjhIu4ee/7A/0mqZkCH70WC+Le7w8TKzgs5Vw/Yi4CnfjpZ8sd6FaJ7i
# RZDkpDYFdYl61YC2dPhbHyTuqW+Ww8+ZoYIXFTCCFxEGCisGAQQBgjcDAwExghcB
# MIIW/QYJKoZIhvcNAQcCoIIW7jCCFuoCAQMxDzANBglghkgBZQMEAgEFADCCAVgG
# CyqGSIb3DQEJEAEEoIIBRwSCAUMwggE/AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIB1Zb3vWvOX5zzLe0eNJYReFW7Rt3NScE/3GGWHj1qzjAgZi3ohP
# 3poYEjIwMjIwODAxMDczNTU0LjgyWjAEgAIB9KCB2KSB1TCB0jELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IEly
# ZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# TjpEMDgyLTRCRkQtRUVCQTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaCCEWUwggcUMIIE/KADAgECAhMzAAABj/NRqOtact3MAAEAAAGPMA0G
# CSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIx
# MTAyODE5Mjc0NloXDTIzMDEyNjE5Mjc0NlowgdIxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9w
# ZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDA4Mi00
# QkZELUVFQkExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCZVz7+tc8XHoWTj4Kkuu5s
# OstNrdC4AdFVe7L7OzFfCSiCRPRr5da4FpvAfKqPxFGJlBC929s6rk1ETE54eJoK
# 2RSxDTYRIB70LP6WgE22x8Krzjq7ei1YcImWqS8OtKvuYwGrBxFjtx+EAZ8u+Wkx
# KiOgCeTtF6P6NwmdjEh43fgXeH0nAA1jfrSgZgIhLuks6ixZX5vG6D26JNlgT9dy
# XJg0Xpd3Nn/MP/hTmnFPgxlCbMEa8Oz7xwN0D+y1l+P+vL6LRdRg0U+G6pz5QqTC
# b9c0cH4IOwZCX5lLQZxtRS6fhU9OEcmbqZEDAvnLzOm1YQihxtN5FJOZmdRraJgf
# YQ4FXt4KPHRJ1vqQtzXF0VFyQN5AZHgnXIXLJu5mxQ/zHR06wQSgtC46G4qUMtAS
# DsPpnGZkmdLwHTd7CT9KlUuqxvrpTarIXgHAO3W5mSMRnt+KcihSBLPgHt9Ytgh4
# 7Y4JjEgTRe/CxWin0+9NdNm0Y/POYdTvncZqsrK4zqhr+ppPNi+sB9RvspiG9VAr
# EZQ+Qv354qIzsbSp6ckIWtfNk/BFahxwBHfc+E0S67PMpkUngN5pMIuD/y4rRDhC
# MVF5/mfgf7YpAgSJtnvMh4FfeOCysgJvPNKbRBfdJFWZkf/8CqnxjGTBygjVYIGL
# O/zjP16rBEF1Dgdhw1tAwwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFPMG5nRrrknO
# 4qHOhZvbl/s3I3G8MB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8G
# A1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBs
# BggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# DQYJKoZIhvcNAQELBQADggIBAM1/06j3PKELmfWMLyJTs0ljf0WLOOHFnAlslj9i
# 3CfremUyVNJoGl6tqfnrp+5GiMYlK/cTBmz5Gu45TZP9lEPHhUd6wse1yUTwaYwz
# WpMxpk8vwjYWtGZ/k6ingapzE100QIEKVVmafQrMV08ypFrn/RHoKaComHSa68ia
# KSAe5u+iGxq88TLIdBr3gcPj8s0p39ghoIoo/P1IDl8BrimFDgS/PZq5j1JSW4h3
# kwr0flyNZXAHEK9gAP7UJb3PsayEmU2OoG9a0o7onQB6Z+DrPbyDupzsb+0K2uUf
# j/LbvL6y27BZc2/B2xJ3WW8HgzrcC4yX1inpq79cWScbMk8Xqf+5ZHomFC/OHjQg
# uB5OEuZiF/zP5oNvivY4EsbU/YHpoJNbZhCS3tOlSfMjRwoavbXcJsq0aT844gdK
# wM7FqyZ4Yn4WJQkKJXXnCHdplP9VP8+Qv0TiEMEDAa3j0bzyBII7TH2N90NlZ1YZ
# sQteVKYDcQ/h5NirtGuiVjTgbx8a0XSnO5m7jcDb3Noj2Uivm6UpHPwShAdTpy7Q
# /FTDQH0fxwCS9DFoy6ZFn/h8Juo1vhNw+Q9xY4jbhBiW+lu1P2nfV+VgSWZznCMa
# mUCTL+eQlxPQdkQ1d6fFa0++3iByiqml4k8DdL/UPnsovfrrt6kivTJXb3QTai1l
# sBbwMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0B
# AQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAG
# A1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAw
# HhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOTh
# pkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xP
# x2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ
# 3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOt
# gFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYt
# cI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXA
# hjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0S
# idb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSC
# D/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEB
# c8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh
# 8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8Fdsa
# N8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkr
# BgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q
# /y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBR
# BgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsG
# AQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
# BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjE
# MFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv
# Y3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEF
# BQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEB
# CwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnX
# wnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOw
# Bb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jf
# ZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ
# 5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+
# ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgs
# sU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6
# OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p
# /cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6
# TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784
# cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtQwggI9
# AgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1p
# dGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpEMDgyLTRCRkQtRUVCQTElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIa
# AxUAPk0vggR250gHB0agJpXRYFtBmmqggYMwgYCkfjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOaRmDowIhgPMjAyMjA4MDEw
# ODA5MzBaGA8yMDIyMDgwMjA4MDkzMFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA
# 5pGYOgIBADAHAgEAAgIRsDAHAgEAAgIRcTAKAgUA5pLpugIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBBQUAA4GBACGnwCh3giupZLMlEi+F1+yOMnQ0laAD9k5egbG5McE1
# z6fh4P2toTxZXXvbFxCu74FBbh5xstISVfyBDzyoMPSo+vdL8Vj/l2sHjeSmxlve
# yYhGm9HQCFSt9BX+zOCvHv7lME5lKKe904+x+3gocDOxZqF/sF+6axcl22m3r5af
# MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGP81Go61py3cwAAQAAAY8wDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgh6Ax2lj+PpAr5Ar5VKpI
# nPvDsmjzizB6P4arG9PQpS4wgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCX
# cgVP4sbGC5WOIqbbYi2Y7p0UNZbydKG7o7qDzIXHHzCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABj/NRqOtact3MAAEAAAGPMCIEIMrJ
# GCclZZeyGeaDKCIlNmckWkQ0o1XfquXd4oojPRMqMA0GCSqGSIb3DQEBCwUABIIC
# AANgno4ZufGK8RRGLV3ntUxqDLf3G92j7Rmld9efNViv6iD6KUyrmpHxArjvbuot
# qGZZgWr5qeJDJAn3IwUR8LnRrru0CHnYjgwUWCGxqYIQBoL+95MHUArr04GldUXI
# jsY5D8d1/UloZalVpsls37Lv2N4FmTJIJPiLbhjN9otJyJbkGp62r3NcK0gtzJ4n
# fqHgSjCSrIVDOmeCPyMSjAyzBu1QTY/vjScGtV65JNXO6RSDptINp5wFYwwv/DWc
# 1uju2m/VdNi7DxQpD2uFLSqcbxGq52iko4hVbnUpgMhCPtsI8QmBUgnzESAYUr54
# 3eeqyBq6X9YsbIM0OR6WBTKGPdpIo3Nn0aRvhkbZD9GzKpeRmTw6+V7l4W9glPI6
# Fm2iW7H3PHibw+Uu754EKBRppEHGv6FfSVowTTO6xwQznLNsb0q4Nx/sxpz/wEWK
# 4+WU+H4OCwcu5XNkZjjSJxx32clUkBthWS3TOW58ZxA9oWR9SaAFRtm6vL+li//I
# kMs+lzCALwAABvfwDAHFi7gm1tlPSkkHqz2b0EC408zcH3WFumwZsprl4yj6uSht
# iwvBcRe5a82OEnn1iBoMvN4GlqzEA97wEWTd8FhxbYWCmKP27oTkkUgkBEp5Ue+p
# pCAHnbNZdjWVyqu7K+ri63hM8T+D0u7TU1gakS4pXwFR
# SIG # End signature block
