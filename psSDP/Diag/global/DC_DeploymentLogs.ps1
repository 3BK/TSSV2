# Copyright 2008, Microsoft Corporation. All rights reserved.


PARAM([string]$MachineName = $ComputerName,[string]$Path= $null)

if($debug -eq $true){[void]$shell.popup("Run DC_DeploymentLogsLogs.ps1")}

Import-LocalizedData -BindingVariable DeploymentLogsStrings

Write-DiagProgress -Activity $DeploymentLogsStrings.ID_DeploymentLogs -Status $DeploymentLogsStrings.ID_DeploymentLogsObtaining

Function CopyDeploymentFile ($sourceFileName, $destinationFileName, $fileDescription){
	Write-DiagProgress -Activity $DeploymentLogsStrings.ID_DeploymentLogsObtaining -Status $sourceFileName
	$sectionDescription = "Deployment Logs"
	
	if (test-path $sourceFileName){
		$sourceFile = Get-Item $sourceFileName
		#copy the file only if it is not a 0KB file.
		if ($sourceFile.Length -gt 0){
			$CommandLineToExecute = "cmd.exe /c copy `"$sourceFileName`" `"$destinationFileName`""
			RunCmD -commandToRun $CommandLineToExecute -sectionDescription $sectionDescription -filesToCollect $destinationFileName -fileDescription $fileDescription
		}
	}
}

$PathNotPresent = [string]::IsNullOrEmpty($Path)
 
if($PathNotPresent){ 
	$LogPath = $Env:windir
}
else{
	$LogPath = $Path
}

Write-DiagProgress -Activity $DeploymentLogsStrings.ID_DeploymentLogsObtaining -Status (join-path $LogPath "System32\sysprep")
$arrSysprepFiles = get-childitem -force -path (join-path $LogPath "System32\sysprep") -recurse -exclude *.exe,*.mui,*.dll | Where-Object {$_.psIsContainer -eq $false} | ForEach-Object {$_.fullname}
CompressCollectFiles -filesToCollect $arrSysprepFiles -fileDescription "Sysprep Folder" -sectionDescription "Sysprep Folder" -DestinationFileName ($MachineName + "_sysprep.zip") -renameoutput $false -recursive

Write-DiagProgress -Activity $DeploymentLogsStrings.ID_DeploymentLogsObtaining -Status (join-path $LogPath "Panther")
$arrPantherFiles = get-childitem -force -path (join-path $LogPath "Panther") -recurse -exclude *.exe,*.mui,*.dll,*.png,*.ttf | Where-Object {$_.psIsContainer -eq $false} | ForEach-Object {$_.fullname}
CompressCollectFiles -filesToCollect $arrPantherFiles -fileDescription "Panther Folder" -sectionDescription "Panther Folder" -DestinationFileName ($MachineName + "_panther.zip") -renameoutput $false -recursive 

#CompressCollectFiles -filesToCollect (join-path $LogPath "System32\sysprep") -recursive -fileDescription "Sysprep Folder" -sectionDescription "Sysprep Folder" -DestinationFileName ($MachineName + "_sysprep.zip") -renameoutput $false

#CompressCollectFiles -filesToCollect (join-path $LogPath "Panther") -recursive -fileDescription "Panther Folder" -sectionDescription "Panther Folder" -DestinationFileName ($MachineName + "_panther.zip") -renameoutput $false

$sourceFileName = "$LogPath\setupact.log"
$destinationFileName = $MachineName + "_setupact-windows.log"
$fileDescription = "Setupact.log on Windows folder"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$LogPath\setuperr.log"
$destinationFileName = $MachineName + "_setuperr-windows.log"
$fileDescription = "Setuperr.log on Windows folder"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$LogPath\logs\dism\DISM.log"
$destinationFileName = $MachineName + "_DISM-Windows-Logs.log"
$fileDescription = "DISM.log on Windows\logs\DISM"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

$sourceFileName = "$LogPath\ccm\smsts.log"
$destinationFileName = $MachineName + "_smsts_ccm_logs.log"
$fileDescription = "Task Sequencer Log on System32\ccm\logs"
CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription

#_# ----- added: 2019-07-15 #_#
if (test-path "$LogPath\logs\mosetup\bluebox.log"){
	$sourceFileName = "$LogPath\logs\mosetup\bluebox.log"
	$destinationFileName = $MachineName + "_bluebox.log"
	$fileDescription = "bluebox.log on on Windows\logs\mosetup folder"
	CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription
	}
if (test-path "$Env:systemdrive\windows.old\windows\logs\mosetup\bluebox.log"){
	$sourceFileName = "$Env:systemdrive\windows.old\windows\logs\mosetup\bluebox.log"
	$destinationFileName = $MachineName + "_bluebox_windowsold.log"
	$fileDescription = "bluebox.log on on Windows.old\windows\logs\mosetup folder"
	CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription
	}

$BT_folder = (join-path $Env:systemdrive '\$Windows.~BT')
if  (-not (test-path $BT_folder)) {$BT_folder = 'D:\$Windows.~BT'}
if (test-path $BT_folder)	{
	if (test-path (join-path $BT_folder "Sources\Panther")){
		Write-DiagProgress -Activity $DeploymentLogsStrings.ID_DeploymentLogsObtaining -Status (join-path $BT_folder "Sources\Panther")
		$arrBTPantherFiles = get-childitem -force -path (join-path $BT_folder "Sources\Panther") -recurse -exclude *.exe,*.mui,*.dll,*.png,*.ttf | Where-Object {$_.psIsContainer -eq $false} | ForEach-Object {$_.fullname}
		CompressCollectFiles -filesToCollect $arrBTPantherFiles -fileDescription "~BT Panther Folder" -sectionDescription "~BT Panther Folder" -DestinationFileName ($MachineName + "_~bt_Panther.zip") -renameoutput $false -recursive
	}
	if (test-path (join-path $BT_folder "Sources\Rollback")){
		Write-DiagProgress -Activity $DeploymentLogsStrings.ID_DeploymentLogsObtaining -Status (join-path $BT_folder "Sources\Rollback")
		$arrBTPantherFiles = get-childitem -force -path (join-path $BT_folder "Sources\Rollback") -recurse -exclude *.exe,*.mui,*.dll,*.png,*.ttf | Where-Object {$_.psIsContainer -eq $false} | ForEach-Object {$_.fullname}
		CompressCollectFiles -filesToCollect $arrBTPantherFiles -fileDescription "~BT Rollback Folder" -sectionDescription "~BT Rollback Folder" -DestinationFileName ($MachineName + "_~bt_Rollback.zip") -renameoutput $false -recursive
	}
	$sectionDescription = "Dir $BT_folder"
	$OutputFile = Join-Path $pwd.path ($MachineName + "_Dir_WindowsBT.txt")
	Write-DiagProgress -Activity $DeploymentLogsStrings.ID_DeploymentLogsObtaining -Status "Get $sectiondescription"
	$CommandToExecute = 'dir /a /s "$BT_folder" '
	RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
	collectfiles -filesToCollect $OutputFile -fileDescription "WinDeploy: $sectionDescription output" -sectionDescription $sectionDescription
}

$WebSetupPantherFolder = (join-path $Env:userprofile "Local Settings\Application Data\Microsoft\WebSetup\Panther")
if (test-path $WebSetupPantherFolder){
		Write-DiagProgress -Activity $DeploymentLogsStrings.ID_DeploymentLogsObtaining -Status "$WebSetupPantherFolder"
		$arrWebPantherFiles = get-childitem -force -path $WebSetupPantherFolder -recurse -exclude *.exe,*.tmp,*.js,*.png | Where-Object {$_.psIsContainer -eq $false} | ForEach-Object {$_.fullname}
		CompressCollectFiles -filesToCollect $arrWebPantherFiles -fileDescription "UpgradeSetup\WebSetup-Panther Folder" -sectionDescription "UpgradeSetup\WebSetup-Panther Folder" -DestinationFileName ($MachineName + "_WebSetup-Panther.zip") -renameoutput $false -recursive
	}
if (test-path "$Env:localappdata\Microsoft\Windows\PurchaseWindowsLicense"){
	$sourceFileName = "$Env:localappdata\Microsoft\Windows\PurchaseWindowsLicense\PurchaseWindowsLicense.log"
	$destinationFileName = $MachineName + "_PurchaseWindowsLicense.log"
	$fileDescription = "Log on Microsoft\Windows\PurchaseWindowsLicense"
	CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription
	}
if (test-path "$Env:localappdata\Microsoft\Windows\Windows Anytime Upgrade"){
	$sourceFileName = "$Env:localappdata\Microsoft\Windows\Windows Anytime Upgrade\PurchaseWindowsLicense.log"
	$destinationFileName = $MachineName + "_Windows-Anytime-Upgrade.log"
	$fileDescription = "Log on Microsoft\Windows\Windows Anytime Upgrade"
	CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription
	}

Write-DiagProgress -Activity $DeploymentLogsStrings.ID_DeploymentLogsObtaining -Status "$Env:WinDir\Setup\"
$arrSetupFiles = get-childitem -force -path (join-path $Env:WinDir "Setup") -recurse | Where-Object {$_.psIsContainer -eq $false} | ForEach-Object {$_.fullname}
CompressCollectFiles -filesToCollect $arrSetupFiles -fileDescription "$Env:WinDir\Setup Folder" -sectionDescription "$Env:WinDir\Setup Folder" -DestinationFileName ($MachineName + "_Win_Setup.zip") -renameoutput $false -recursive

if (test-path "$LogPath\setupact.log"){
	$sourceFileName = "$LogPath\setupact.log"
	$destinationFileName = $MachineName + "_setupact.log"
	$fileDescription = "setupact.log on Windows folder"
	CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription
	}
if (test-path "$LogPath\System32\LogFiles\setupcln\setupact.log"){
	$sourceFileName = "$LogPath\System32\LogFiles\setupcln\setupact.log"
	$destinationFileName = $MachineName + "_setupact-setupcln.log"
	$fileDescription = "setupact.log on Windows\System32\LogFiles\setupcln folder"
	CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription
	}

Write-DiagProgress -Activity $DeploymentLogsStrings.ID_DeploymentLogsObtaining -Status "CCM Logs"
if (Test-Path $Env:WinDir\ccm\logs){
	$CCMlogFiles = get-childitem -force -path $Env:WinDir\ccm\logs -recurse -include execmgr.log,scheduler.log,StatusAgent.log,ccmnotificationagent.log,ccmexec.log,rebootcoordinator.log,wua*.*,updates*.*,deltaDownload.log | Where-Object {$_.psIsContainer -eq $false} | ForEach-Object {$_.fullname}
	CompressCollectFiles -filesToCollect $CCMlogFiles -fileDescription "$Env:WinDir\ccm\logs" -sectionDescription "$Env:WinDir\ccm\logs" -DestinationFileName ($MachineName + "_SCCM-Logs.zip") -renameoutput $false -recursive
}

$ccmActualConfig = Get-CimInstance -Namespace ROOT\ccm\Policy\Machine\ActualConfig -Class CCM_SoftwareUpdatesClientConfig -EA SilentlyContinue
if ($ccmActualConfig){
	$OutputFile = $MachineName + "_SCCM_SoftwareUpdatesClientConfig.txt"
	$ccmActualConfig |out-file $OutputFile
	$fileDescription = "SoftwareUpdatesClientConfig"
	$sectionDescription = "SoftwareUpdatesClientConfig"
	CollectFiles -filesToCollect $outfile -fileDescription $fileDescription -sectionDescription $sectionDescription
}


if($PathNotPresent){
	$sourceFileName = "$Env:TEMP\smsts.log"
	$destinationFileName = $MachineName + "_smsts_temp.log"
	$fileDescription = "Task Sequencer Log on Temp folder"
	CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription
	
	$sourceFileName = "$Env:SystemDrive\_SMSTaskSequence\smsts.log"
	$destinationFileName = $MachineName + "_smsts_SMSTaskSequence.log"
	$fileDescription = "Task Sequencer Log on C:\_SMSTaskSequence"
	CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription
	
	$sourceFileName = "$Env:SystemDrive\SMSTSLog\smsts.log"
	$destinationFileName = $MachineName + "_smsts_SMSTSLog.log"
	$fileDescription = "Task Sequencer Log on C:\SMSTSLog"
	CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription
	
	$sourceFileName = "$Env:systemdrive\minint\*"
	$destinationFileName = $MachineName + "_Minint_SystemDrive.zip"
	$fileDescription = "Deployment Logs on SystemDrive\Minint"
	CompressCollectFiles -fileDescription $fileDescription -DestinationFileName $destinationFileName -filesToCollect $sourceFileName -sectionDescription "Logs"

	if (test-path "$Env:SystemDrive\users\administrator\appdata\local\temp\smstslog\smsts.log"){
		$sourceFileName = "$Env:SystemDrive\users\administrator\appdata\local\temp\smstslog\smsts.log"
		$destinationFileName = $MachineName + "_smsts_Admin_temp.log"
		$fileDescription = "Task Sequencer Log on C:\SMSTSLog"
		CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription
		}
}

$sourceFileName = "$LogPath\temp\deploymentlogs\*"
$destinationFileName = $MachineName + "_DeploymentLogs_Windows_Temp.zip"
$fileDescription = "Deployment Logs on \windows\temp"
Write-DiagProgress -Activity $DeploymentLogsStrings.ID_DeploymentLogsObtaining -Status $sourceFileName
CompressCollectFiles -fileDescription $fileDescription -DestinationFileName $destinationFileName -filesToCollect $sourceFileName -sectionDescription "deployment Logs"

if ((!$PathNotPresent) -or ($OSVersion.Major -lt 6)){
	$sourceFileName = join-path $LogPath "SVCPack.Log"
	$destinationFileName = $MachineName + "_SVCPack.Log"
	$fileDescription = "Service Pack Installation Log"
	CopyDeploymentFile -sourceFileName $sourceFileName -destinationFileName $destinationFileName -fileDescription $fileDescription
}


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAF33ORKD5rkU1k
# E4m8KTkuWKZcI3IIx6FgO3beGJJe7qCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIH8EYIlAO9Xl/PpE8+bttrLm
# BnBI0YqtO2OiSPHBQMfOMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCpYp9SlgyLeX3otnUXHnC/r8hhBDXIz3M6QZFGf1CpjWF4LgP9BABr
# x77tzwLTJNujQttM1oP3bH+DlpEWV3jNd3VTx3jkSFV7+4LOJ2+5iv9wQHImiXfq
# lamsfOtDMbqFfDmHXC8qPVH0YMIAudJmWqz49rYmn58aeepIDxCQgVvzYJepaT3m
# 3qDbT4psbQJhktrokQeFwO5Hc1pd0KgACSxxDxsLJO2oJHUmtq77VUMTxoTFI8VI
# ARXE1kEO3aZnU1Slk6j/Nxuwuotwkd4NvoeRV+6c8lirK9MvFmEx48JWwMdF+yyn
# x6fquHZqpr7c5Vi1UKNSn4HqRZV1zwY9oYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIMZa8Cr7dcfcnh0X3wftXTHcXPk8saIwA765g6ZJrZdrAgZi2AZn
# 47UYEzIwMjIwODE2MDg0MDA1LjczNlowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhBODIt
# RTM0Ri05RERBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGZyI+vrbZ9vosAAQAAAZkwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTE2WhcNMjMwMjI4MTkwNTE2WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046OEE4Mi1FMzRGLTlEREExJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC4E/lXXKMsy9rVa2a8bRb0Ar/Pj4+bKiAgMgKayvCM
# Fn3ddGof8eWFgJWp5JdKjWjrnmW1r9tHpcP2kFpjXp2Udrj55jt5NYi1MERcoIo+
# E29XuCwFAMJftGdvsWea/OTQPIFsZEWqEteXdRncyVwct5xFzBIC1JWCdmfc7R59
# RMIyvgWjIz8356mweowkOstN1fe53KIJ8flrYILIQWsNRMOT3znAGwIb9kyL54C6
# jZjFxOSusGYmVQ+Gr/qZQELw1ipx9s5jNP1LSpOpfTEBFu+y9KLNBmMBARkSPpTF
# kGEyGSwGGgSdOi6BU6FPK+6urZ830jrRemK4JkIJ9tQhlGcIhAjhcqZStn+38lRj
# VvrfbBI5EpI2NwlVIK2ibGW7sWeTAz/yNPNISUbQhGAJse/OgGj/1qz/Ha9mqfYZ
# 8BHchNxn08nWkqyrjrKicQyxuD8mCatTrVSbOJYfQyZdHR9a4vgyGeZEXBYQNAlI
# uB37QCOAgs/VeDU8M4dc/IlrTyC0uV1SS4Gk8zV+5X5eRu+XORN8FWqzI6k/9y6c
# WwOWMK6aUN1XqLcaF/sm9rX84eKW2lhDc3C31WLjp8UOfOHZfPuyy54xfilnhhCP
# y4QKJ9jggoqqeeEhCEfgDYjy+PByV/e5HDB2xHdtlL93wltAkI3aCxo84kVPBCa0
# OwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFI26Vrg+nGWvrvIh0dQPEonENR0QMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAHGzWh29ibBNro3ns8E3EOHGsLB1Gzk90SFYUKBilIu4jDbR7qbvXNd8nnl/
# z5D9LKgw3T81jqy5tMiWp+p4jYBBk3PRx1ySqLUfhF5ZMWolRzW+cQZGXV38iSmd
# AUG0CpR5x1rMdPIrTczVUFsOYGqmkoUQ/dRiVL4iAXJLCNTj4x3YwIQcCPt0ijJV
# inPIMAYzA8f99BbeiskyI0BHGAd0kGUX2I2/puYnlyS8toBnANjh21xgvEuaZ2dv
# RqvWk/i1XIlO67au/XCeMTvXhPOIUmq80U32Tifw3SSiBKTyir7moWH1i7H2q5QA
# nrBxuyy//ZsDfARDV/Atmj5jr6ATfRHDdUanQpeoBS+iylNU6RARu8g+TMCu/Znd
# Zmrs9w+8galUIGg+GmlNk07fXJ58Oc+qFqgNAsNkMi+dSzKkWGA4/klJFn0XichX
# L8+t7KOayXKGzQja6CdtCjisnyS8hbv4PKhaeMtf68wJWKKOs0tt2AJfYC5vSbH9
# ck8BGj2e/yQXEZEu88L5/fHK5XUk/IKXx3zaLkxXTSZ43Ea/WKXVBzMasHZ3Pmny
# 0moEekAXx1UhLNNYv4Vum33VirxSB6r/GKQxFSHu7yFfrWQpYyyDH119TmhAedS8
# T1VabqdtO5ZP2E14TK82Vyxy3xEPelOo4dRIlhm7XY6k9B68MIIHcTCCBVmgAwIB
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
# IEVTTjo4QTgyLUUzNEYtOUREQTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAku/zYujnqapN6BJ9MJ5jtgDrlOug
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOalc4owIhgPMjAyMjA4MTYwOTM4MThaGA8yMDIyMDgxNzA5MzgxOFow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5qVzigIBADAKAgEAAgIDmwIB/zAHAgEA
# AgIRujAKAgUA5qbFCgIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAHIJEwI0
# 0rGyhf+OC9unLcVezULr1fsnwwMrGlPxVUMOh3s9vdJrk4ZzqdTJ9HOovOrH4VzX
# 8x56kKzL7vvyevUQFpZF2RMZF09T4VbF/uPOsLO9HWfkxvQpTQSveyx6luaT3FHt
# X48Qrs42oVm+NeBCVv3N/I63vrtF2mKhNQZLMYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGZyI+vrbZ9vosAAQAAAZkwDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgycdG2DcnqqQtCndz+pcjYAQwpyBpdsgLbh3dSTw/yrwwgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBmfWn58qKN7WWpBTYOrUO1BSCSnKPL
# C/G7wCOIc2JsfjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABmciPr622fb6LAAEAAAGZMCIEIKiKjyFnYIEd+jc5ynjnHREUfBJ6I6np
# NlthQqr4X2vNMA0GCSqGSIb3DQEBCwUABIICAHGIFqMPTReQJe9c0zEGiat1vD0m
# v1A+r8hD69L6DU3yoCLh4DUaeOkmcaFsegZZRPUlKn5bTT2jucXO2rK1O0uU1CVc
# xLjflakbjyK4LsQr9qqFSyTws8MarOZ+T1lz+tSeKcPVRHLOokuEhrUkZsN2qkKV
# z7Nbkv/T2zsPHkGLJ5CVZRsG0ssNPHvFc+wl+CrYqi1Jb1hvj5wXJWK3IuFOaXVP
# 3c3+KFY5/Yic7kNM2EtNQgYWqPitt8yp6js7YmsCczIxtgkG+eJ0CJ6PUo0VEDKQ
# etAFciM9GLdkLtteFu9ioIfqG99xUNI9cXckvYJk5sJw7nYBXpveEFHeTvLXo3aP
# /CYIWr9o4111+/CuQN5OAP4cm7mncuD+3W4ux0EC9y8RlTcWHmyyvIFfTZf+Mgdz
# ZZqRvFbRC6viBF8BoO3URHReWvvbGZwO/xibwVW3rGVoelWFi+eGJfz3TrKJXVQL
# mrv+DYxytR7rj+ifFpyeaxSNYHkYzmw3vyXjEQQ/hhwkRN3mubys2oT9LayyGi47
# wwT3UegfMPUI9frZE49I0FkbGM5i29JFPXAeFsFVinK/uaAbsnpn6X6rsC2pH3y9
# 7SqvrFxxLVqEKvTCslDqe/COWDIc+l92oI1Tk0U1gRxOCxTfmOPseqz+tAhGXrTP
# HypRoado0mx66ENh
# SIG # End signature block
