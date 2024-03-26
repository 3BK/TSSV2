# *****************************************************************************************
# Version 1.0
# Date: 06-12-2013, 2021 -- Last edit; 2022-06-01
# Author: Vinay Pamnani - vinpa@microsoft.com
# Description:
# 		Collects Windows Logs WSUS
#		Collects Windows and ConfigMgr OSD Logs
# *****************************************************************************************

trap [Exception]
{
	WriteTo-ErrorDebugReport -ErrorRecord $_
	continue
}

TraceOut "Started"

Import-LocalizedData -BindingVariable ScriptStrings

If ($ManifestName -eq "WSUS") {
	$sectionDescription = "Windows Logs"
	Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectWindowsLogs -Status $ScriptStrings.ID_SCCM_Windows_OSD_CollectConfigMgrLogs
}
else {
	$sectionDescription = "Configuration Manager Logs"
	Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectConfigMgrLogs -Status $ScriptStrings.ID_SCCM_Windows_OSD_CollectConfigMgrLogs
}

# --------------
# Getting Ready
# --------------

$Destination = Join-Path $Pwd.Path ($ComputerName + "_Logs_Windows+OSD")
$ZipName = "Logs_Windows+OSD.zip"
$fileDescription = "Windows & OSD Logs"

# Remove temp destination directory if it exists
If (Test-Path $Destination) {
	Remove-Item -Path $Destination -Recurse
}

################
# WINDOWS LOGS #
################
Write-DiagProgress -Activity "WINDOWS LOGS"
# --------------------
#  Windows\Temp logs
# --------------------
$TempLogPath = Join-Path $Env:windir "Temp"
$TempDestination = Join-Path $Destination "Temp_Logs"
Copy-FilesWithStructure -Source $TempLogPath -Destination $TempDestination -Include *.lo*

# ----------------
# User Temp Logs
# ----------------
$TempLogPath = (Get-Item $env:temp).FullName
$TempDestination = Join-Path $Destination ("Temp_Logs_User_" + "$env:username")
Copy-FilesWithStructure -Source $TempLogPath -Destination $TempDestination -Include *.lo*

# ----------------------------
# Windows Update ETL Traces (Win 10)
# Cannot use Get-WindowsUpdateLog because it presents a prompt to accept Terms for Public Symbol Server and there doesn't appear to be a way to skip the prompt, which is absolutely stupid
# and prevents use of this CmdLet for automation. https://connect.microsoft.com/PowerShell/Feedback/Details/1690411
# ----------------------------
$TempLogPath = Join-Path $Env:windir "Logs\WindowsUpdate"
$TempDestination = Join-Path $Destination "WindowsUpdate_ETL"
Copy-FilesWithStructure -Source $TempLogPath -Destination $TempDestination -Include *.etl
# Verbose WindowsUpdate ETL Log
Copy-Files -Source $env:SystemDrive -Destination $TempDestination -Filter WindowsUpdateVerbose.etl

# -------------------------------
# Setup Clean Task Logs (Win 10)
# -------------------------------
$TempLogPath = Join-Path $Env:windir "Logs\SetupCleanupTask"
$TempDestination = Join-Path $Destination "SetupCleanupTask_Logs"
Copy-FilesWithStructure -Source $TempLogPath -Destination $TempDestination -Include *.xml, *log

# ---------
# CBS Log
# ---------
$TempLogPath = Join-Path $Env:windir "Logs\CBS"
$TempDestination = Join-Path $Destination "CBS_Logs"
Copy-FilesWithStructure -Source $TempLogPath -Destination $TempDestination -Include CBS.log, *.cab

# --------------------------
# WindowsUpdate.log (AGAIN!)
# --------------------------
$TempLogPath = Join-Path $Env:windir "SoftwareDistribution"
Copy-Files -Source $TempLogPath -Destination $Destination -Filter ReportingEvents.log
Copy-Files -Source $Env:windir -Destination $Destination -Filter WindowsUpdate.log

############
# OSD LOGS #
############
Write-DiagProgress -Activity "OSD LOGS"
# ------------
# SMSTS Logs
# ------------
Write-DiagProgress -Activity " OSD LOGS" -Status "SMSTS Logs"
$SMSTSLocation1 = if ($null -ne $CCMLogPath) { $CCMLogPath } else { Join-Path $Env:windir "CCM\Logs" }
$SMSTSLocation2 = $SMSTSLocation1 + "\SMSTSLog"
$SMSTSLocation3 = Join-Path $env:SystemDrive "_SMSTaskSequence"
$SMSTSLocation4 = Join-Path $env:SystemDrive "SMSTSLog"
$SMSTSLocation5 = Join-Path $env:windir "Temp"

$TempDestination = $Destination + "\SMSTS_Logs"
New-Item -ItemType "Directory" $TempDestination | Out-Null #_#

Copy-Files -Source $SMSTSLocation1 -Destination $TempDestination -Filter *SMSTS*.lo* -Recurse -RenameFileToPath
Copy-Files -Source $SMSTSLocation1 -Destination $TempDestination -Filter ZTI*.lo* -Recurse -RenameFileToPath
Copy-Files -Source $SMSTSLocation2 -Destination $TempDestination -Filter *.lo* -Recurse -RenameFileToPath
Copy-Files -Source $SMSTSLocation3 -Destination $TempDestination -Filter *.lo* -Recurse -RenameFileToPath
Copy-Files -Source $SMSTSLocation4 -Destination $TempDestination -Filter *.lo* -Recurse -RenameFileToPath
Copy-Files -Source $SMSTSLocation5 -Destination $TempDestination -Filter *SMSTS*.lo* -RenameFileToPath

# --------------
# Panther logs
# --------------
Write-DiagProgress -Activity " OSD LOGS" -Status "Panther Logs"

#Write-verbose "\Windows\Panther"
# \Windows\Panther directory
$PantherLocation = Join-Path $Env:windir "Panther"
$PantherDirNewName = ($PantherLocation -replace "\\","_") -replace ":",""
$PantherDirDestination = Join-Path $Destination $PantherDirNewName
Copy-FilesWithStructure -Source $PantherLocation -Destination $PantherDirDestination -Include *.xml,*.lo*,*.etl

#Write-verbose "\System32\sysprep\Panther"
# \Windows\System32\Panther directory
$PantherLocation = Join-Path $Env:windir "System32\sysprep\Panther"
$PantherDirNewName = ($PantherLocation -replace "\\","_") -replace ":",""
$PantherDirDestination = Join-Path $Destination $PantherDirNewName
Copy-FilesWithStructure -Source $PantherLocation -Destination $PantherDirDestination -Include *.xml,*.log,*.etl

#Write-verbose "\Windows.~BT\Sources\Panther"
# \$Windows.~BT\Sources\Panther directory (Win 10)
$PantherLocation = Join-Path $Env:systemdrive "`$Windows.~BT\Sources\Panther"
$PantherDirNewName = ($PantherLocation -replace "\\","_") -replace ":",""
$PantherDirDestination = Join-Path $Destination $PantherDirNewName
# Try using psexec to copy these files, since the user may not have taken ownership of the folder
$CmdToRun = "psexec.exe /accepteula -s robocopy /S /NP /NC /NFL /NDL /W:5 $PantherLocation $PantherDirDestination *.xml *.log *.etl *.evt *.evtx"
RunCmd -commandToRun $CmdToRun -collectFiles $false -useSystemDiagnosticsObject | Out-Null #_#

#Write-verbose "\$Windows.~BT\Sources\Rollback\ (Win 10)"
# \$Windows.~BT\Sources\Rollback\ (Win 10)
$RollbackLocation = Join-Path $Env:systemdrive "`$Windows.~BT\Sources\Rollback"
$RollbackLocationNewName = ($RollbackLocation -replace "\\","_") -replace ":",""
$RollbackLocationDestination = Join-Path $Destination $RollbackLocationNewName
# Try using psexec to copy these files, since the user may not have taken ownership of the folder
$CmdToRun = "psexec.exe /accepteula -s robocopy /S /NP /NC /NFL /NDL /W:5 $RollbackLocation $RollbackLocationDestination *.xml *.log *.etl *.txt *.evt *.evtx"
RunCmd -commandToRun $CmdToRun -collectFiles $false -useSystemDiagnosticsObject | Out-Null #_#

# ----------
# INF Logs
# ----------
Write-DiagProgress -Activity " OSD LOGS" -Status "INF Logs"
# \Windows\inf\*.log's
$InfLogLocation = Join-Path $Env:windir "INF"
$TempDestination = $Destination + "\INF_Logs"
New-Item -ItemType "Directory" $TempDestination | Out-Null #_#
Copy-Files -Source $InfLogLocation -Destination $TempDestination -Filter *.lo* -Recurse

# ---------------------------
# \Windows\Logs\DISM\*.log's
# ---------------------------
Write-DiagProgress -Activity " OSD LOGS" -Status "DISM Logs"
$DismLogPath = Join-Path $Env:windir "Logs\DISM"
$TempDestination = $Destination + "\DISM_Logs"
New-Item -ItemType "Directory" $TempDestination | Out-Null #_#
Copy-Files -Source $DismLogPath -Destination $TempDestination -Filter *.lo*

# -------------------------------
# DPX Logs (Win 10)
# -------------------------------
Write-DiagProgress -Activity " OSD LOGS" -Status "DPX Logs"
$TempLogPath = Join-Path $Env:windir "Logs\DPX"
$TempDestination = $Destination + "\DPX_Logs"
Copy-FilesWithStructure -Source $TempLogPath -Destination $TempDestination -Include *.xml, *lo*

# -------------------------------
# MOSETUP Logs (Win 10)
# -------------------------------
Write-DiagProgress -Activity " OSD LOGS" -Status "MOSETUP Logs"
$TempLogPath = Join-Path $Env:windir "Logs\MoSetup"
$TempDestination = $Destination + "\MoSetup_Logs"
Copy-FilesWithStructure -Source $TempLogPath -Destination $TempDestination -Include *.xml, *lo*

# ----------------------
# \Windows\UDI\*.log's
# ----------------------
Write-DiagProgress -Activity " OSD LOGS" -Status "UDI Logs"
$UdiLogLocation = Join-Path $Env:windir "UDI"
$TempDestination = $Destination + "\UDI_Logs"
New-Item -ItemType "Directory" $TempDestination | Out-Null #_#
Copy-FilesWithStructure -Source $UdiLogLocation -Destination $TempDestination -Include *.lo*,*.xml,*.config,*.app,*.reg

# -------------
# Netsetup.log
# -------------
$TempLogPath = Join-Path $Env:windir "debug"
Copy-FilesWithStructure -Source $TempLogPath -Destination $Destination -Include Netsetup.log

#################
# DEVCON OUTPUT #
#################
Write-DiagProgress -Activity "DEVCON LOGS" 
If ($ManifestName -ne "WSUS") {
	Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectWindowsLogs -Status $ScriptStrings.ID_SCCM_Windows_OSD_CollectDevCon

	$TempFileName = "DevCon_Output.txt"
	$OutputFile = Join-Path $Destination $TempFileName
	Write-DiagProgress -Activity " DEVCON LOGS" -Status "DEVCON drivernodes"
	"__ DRIVER NODE INFORMATION`r`n" + "-" * 23 + "`r`n" | Out-File -FilePath $OutputFile
	$CommandToExecute = "cmd.exe /c devcon.exe drivernodes * >> $OutputFile"
	RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -collectFiles $false

	"`r`n__ HARDWARE ID INFORMATION `r`n" + "-" * 23 + "`r`n" | Out-File -FilePath $OutputFile -append
	$CommandToExecute = "cmd.exe /c devcon.exe hwids * >> $OutputFile"
	RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -collectFiles $false

	"`r`n__ HARDWARE RESOURCE USAGE INFORMATION `r`n" + "-" * 35 + "`r`n" | Out-File -FilePath $OutputFile -append
	$CommandToExecute = "cmd.exe /c devcon.exe resources * >> $OutputFile"
	RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -collectFiles $false

	"`r`n__ HARDWARE STACK INFORMATION `r`n" + "-" * 35 + "`r`n" | Out-File -FilePath $OutputFile -append
	$CommandToExecute = "cmd.exe /c devcon.exe stack * >> $OutputFile"
	RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -collectFiles $false

	"`r`n__ HARDWARE STATUS INFORMATION `r`n" + "-" * 35 + "`r`n" | Out-File -FilePath $OutputFile -append
	$CommandToExecute = "cmd.exe /c devcon.exe status * >> $OutputFile"
	RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -collectFiles $false

	"`r`n__ DRIVER FILES INFORMATION `r`n" + "-" * 35 + "`r`n" | Out-File -FilePath $OutputFile -append
	$CommandToExecute = "cmd.exe /c devcon.exe driverfiles * >> $OutputFile"
	RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -collectFiles $false

	Write-DiagProgress -Activity " DEVCON LOGS" -Status "DEVCON devcon.exe classes"
	"`r`n__ CLASSES INFORMATION `r`n" + "-" * 35 + "`r`n" | Out-File -FilePath $OutputFile -append
	$CommandToExecute = "cmd.exe /c devcon.exe classes * >> $OutputFile"
	RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -collectFiles $false

	Write-DiagProgress -Activity " DEVCON LOGS" -Status "DEVCON devcon.exe findall"
	"`r`n__ FIND ALL INFORMATION `r`n" + "-" * 35 + "`r`n" | Out-File -FilePath $OutputFile -append
	$CommandToExecute = "cmd.exe /c devcon.exe findall * >> $OutputFile"
	RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -collectFiles $false
}

# --------------------------------------------------
# Compress and Collect Logs if something was copied
# --------------------------------------------------
If (Test-Path $Destination)
{
	If ($ManifestName -eq "WSUS") {
		Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectWindowsLogs -Status $ScriptStrings.ID_SCCM_Compress_CollectConfigMgrLogs
	}
	else {
		Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CollectConfigMgrLogs -Status $ScriptStrings.ID_SCCM_Compress_CollectConfigMgrLogs
	}
	compressCollectFiles -DestinationFileName $ZipName -filesToCollect ($Destination + "\*.*") -sectionDescription $sectionDescription -fileDescription $fileDescription -Recursive -ForegroundProcess -noFileExtensionsOnDescription
	Remove-Item -Path $Destination -Recurse -Force
}

Traceout "DC_CollectWindowsLogs Completed"


# SIG # Begin signature block
# MIInoQYJKoZIhvcNAQcCoIInkjCCJ44CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAGm7Oktdf40+q/
# Q4c+pNbapGEZsiGUqClg2iFnyCsupKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIuuE1gsoHl/Wt4hNyKl5G12
# g8I15LGf8gjVgwoU7H5qMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAAjoc5u/SDlV8rNH9yHkXHhaKc3Y8TufpHOwvrropTtnblYY2ppq3Y
# P68Xcz2a94Omn66zd44gk0DM3OEJaoldoXyeRfC43A0P5lbr76idsjDK/e4f+obG
# AOEUdogshQL1Z4jT/9T51N0CACTUyLIHuQGlyfXSCaqsixyFgZXqJ8pXR2Y2sTl5
# 248/j8xJLrRuL9uHOKreYAWQS8ni2e0jRer+XuKwWsuYzC6u5wxsq/Uy8WzzaZ59
# EtVnAGh+00ymHXAq6hBkwjDrWgSABmXGehykJxrrt2b66W1mqpKQqmBxZN3SaTlo
# MdzgQQSUaYeogDd0JQUQiXMQod4fRFDPoYIXCTCCFwUGCisGAQQBgjcDAwExghb1
# MIIW8QYJKoZIhvcNAQcCoIIW4jCCFt4CAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIDdl0cWWTVWXDF9fEQbxwFbNoM9oS5JvC0VMZKo3ppgKAgZi2xAP
# QXsYEzIwMjIwODAxMDczNjEyLjk3NVowBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
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
# CRABBDAvBgkqhkiG9w0BCQQxIgQgDZRraM8PCmiIq2raWaOPvuUs+08i4QRi6Qeq
# mwRS32QwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAOHK/6sIVgEVSVD3Ar
# vk6OyQKvRxFHKyraUzbN1/AKVzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABqwkJ76tj1OipAAEAAAGrMCIEIHI+RQKHTZ2Id7/ufvKq
# /DQk+dqQy1YkmvsPNzOkpL0iMA0GCSqGSIb3DQEBCwUABIICACdi+qNQbYAjY8Km
# eW1BFR+e8lFFROcqmmfHv3UkyRQsmpH8NPzpPO6Fp++WC718XKdF2TrXobX7Byx1
# eZYutHp3mwNe1eN0LpgC8dZ+KovqOwE35elWiO90oYaS7wnzh8xzIfNR2pnul2h/
# Xm1mcjgsIQdW+j/eEHAMQ+NfBRCiNK7tzbtQfZ9Au8r9Dq9OAD6ojWmmUZx/DnBC
# HDGH1a6yClYYx7Ah3SPpLeliwm4c5pYsS8RaNoCTKwzNeaatxzm9FlHF4yFAk7Z6
# 90yrggS8cMgQ4souFYwMPfYpy3rWn/5HkEFyZXgqX9RmHhQ8J4i2EZNfJV+9o7od
# lGh0lV4nG52jh/ZLj1vO2NgFEdA+GZTWXmC4IaFmOmIEM6U3GzJ/wRxLygmDaTEc
# Uc5gLa3gPlcfrH6EG3wdBviyIM7ko2knZoLHDauoKvonSrLkNif/8WSPOXE61dCV
# WUwu4196c0jNXXXZvuliVWHQeZ2uQgoj+FUXWh13I4euYzJ/oidIHbK5QqpzyzY2
# Chrc+NiXGSPpZiRvaoGu4M4+cqMFCqEqjwtPNCUkLijQllvh0TOoqIDS6WcVb+b+
# NWgwrCz0UjEaC/EUrST8Stzw14ergurv2k6dKKSA/vPlQp670CfxIKb3CBvs5VXS
# hs/h8Iu4sskvoojT5OaQ1xl19Ty+
# SIG # End signature block
