#************************************************
# TS_WDSFiles.ps1
# Version 1.0.1
# Date: 04-21-2014
# Author: jasonf
# Description: Obtain information from WDS such as logs and wdsutil output
#************************************************

Import-LocalizedData -BindingVariable WDSFilesStrings
Write-DiagProgress -Activity $WDSFilesStrings.ID_WDSInfo -Status $WDSFilesStrings.ID_WDSInfoDesc
if ($OSVersion.Major -ge 6)
{
	if (test-path "HKLM:\SYSTEM\CurrentControlSet\Services\WDSServer")
	{
		$sectiondescription = "Windows Deployment Services information"
		$WDSInformationCollected = New-Object PSobject
		
		$arrWDSUtilOutput = @()
		$arrWDSUtilOutput = wdsutil /get-server /show:all /detailed
		
		$WDSServerServiceStatus = (get-service WDSServer).status
		Add-Member -InputObject $WDSInformationCollected -MemberType NoteProperty -Name "WDSServer Status" -Value $WDSServerServiceStatus
		$WDSOperationalmode = $arrWDSUtilOutput | ForEach-Object{if ($_ -match "WDS Operational Mode"){$_}}
		Add-Member -InputObject $WDSInformationCollected -MemberType NoteProperty -Name "Operational Mode" -Value $WDSOperationalmode
		$WDSAnswerClients = $arrWDSUtilOutput | ForEach-Object{if ($_ -match "Answer Clients"){$_}}
		Add-Member -InputObject $WDSInformationCollected -MemberType NoteProperty -Name "Answer Clients" -Value $WDSAnswerClients
		$WDSAnswerOnlyKnownClients = $arrWDSUtilOutput | ForEach-Object{if ($_ -match "Answer only known clients"){$_}}
		Add-Member -InputObject $WDSInformationCollected -MemberType NoteProperty -Name "Answer Only Known Clients" -Value $WDSAnswerOnlyKnownClients
		$WDSPXEProviders = $arrWDSUtilOutput | ForEach-Object{if ($_ -match "WDS PXE Providers"){$_}}
		Add-Member -InputObject $WDSInformationCollected -MemberType NoteProperty -Name "PXE Providers" -Value $WDSPXEProviders
		$WDSBootImageCount = ($arrWDSUtilOutput | ForEach-Object{if ($_ -match "Total number of boot images"){$_}})[0]
		Add-Member -InputObject $WDSInformationCollected -MemberType NoteProperty -Name "Boot Images" -Value $WDSBootImageCount
		$WDSInstallImageCount = ($arrWDSUtilOutput | ForEach-Object{if ($_ -match "Total number of install images"){$_}})[0]
		Add-Member -InputObject $WDSInformationCollected -MemberType NoteProperty -Name "Install Images" -Value $WDSInstallImageCount
		$remoteInstallRoot = (get-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Services\WDSServer\Providers\WDSTFTP").RootFolder
		Add-Member -InputObject $WDSInformationCollected -MemberType NoteProperty -Name "Remote Install Root" -Value $remoteInstallRoot
		$sectionDisplayOrder = 1
		$WDSInformationCollected | ConvertTo-Xml2 | update-diagreport -id $sectionDescription -name $sectionDescription
		
		$sectiondescription = "Windows Deployment Services files"
		#		Command: All logs in %windir%\tracing\wds*.log 
		#		OutputFileName: wds_tracing_logs.zip 
		compresscollectfiles -filesToCollect (join-path $env:SystemRoot "tracing\wds*.log") -Recursive -fileDescription "WDS Tracing Logs" -sectionDescription $sectiondescription -DestinationFileName "wds_tracing_logs.zip" -RenameOutput $true
	
		#		Event Logs
		#		Microsoft-Windows-Deployment-Services-Diagnostics/Admin
		#		Microsoft-Windows-Deployment-Services-Diagnostics/Debug
		#		Microsoft-Windows-Deployment-Services-Diagnostics/Metadata
		#		Microsoft-Windows-Deployment-Services-Diagnostics/Operational
		#		Microsoft-Windows-Deployment-Services-Diagnostics/Packet
		#		Microsoft-Windows-Deployment-Services-Diagnostics/Verbose
		$EventLogNames = wevtutil.exe el | Select-String "(Deployment-Services-Diagnostic/*)"
		if ($null -ne $EventLogNames)
		{
			Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames
		}
		
		#		Command:  Directory listing of RemoteInstall\Boot folder.  
		#		OutputFileName:  Directory_Listing_RemoteInstall_boot.txt
		$remoteinstallbootfolder = Join-Path $remoteInstallRoot "boot"
		$OutputFile = $PWD.Path + "\Directory_Listing_RemoteInstall_boot.txt"
		$fileDescription = "Directory listing of RemoteInstall\Boot folder"
		$CommandToExecute = 'cmd.exe /c dir /s $remoteinstallbootfolder >> ' + $OutputFile
		RunCmD -commandToRun $CommandToExecute 
		collectfiles -filestocollect $OutputFile -filedescription $fileDescription -sectiondescription $sectionDescription -noFileExtensionsOnDescription -RenameOutput $true 	
		
		#		Command: wdsutil /get-server /show:all /detailed. 
		#		Outputfilename: WDSUTIL_GET_SERVER_ALL.txt 
		$outputfile = Join-Path $PWD.Path "\WDSUTIL_GET_SERVER_ALL.txt"
		$arrWDSUtilOutput | Out-File $OutputFile -Append
		$fileDescription = "wdsutil /get-server /show:all /detailed output"
		collectfiles -filestocollect $OutputFile -filedescription $fileDescription -sectiondescription $sectionDescription -noFileExtensionsOnDescription -RenameOutput $true 	

		#		Command: Wdsutil /get-allmulticasttransmissions /Show:all
		#		OutputFilename: wdsutil_get_all_multicast.txt 
		$fileDescription = "wdsutil /get-allmulticasttransmissions /Show:all output"
		$OutputFile = join-path $pwd.path "\wdsutil_get_all_multicast.txt"
		$CommandToExecute = "cmd.exe /c Wdsutil /get-allmulticasttransmissions /Show:all >> " + $OutputFile
		RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -RenameOutput $true
		
		#		Command: Wdsutil /get-allnamespaces 
		#		OutputFileName: wdsutil_get_all_namespaces.txt 
		$fileDescription = "wdsutil /get-allnamespaces output"
		$OutputFile = join-path $pwd.path "\wdsutil_get_all_namespaces.txt >> " + $OutputFile
		$CommandToExecute = "cmd.exe /c Wdsutil /get-allnamespaces"
		RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -RenameOutput $true
		
		#		Command: Wdsutil /verbose /get-alldevices 
		#		OutputFileName: wdsutil_get_alldevices 
		$fileDescription = "wdsutil /verbose /get-alldevices output"
		$OutputFile = join-path $pwd.path "\wdsutil_get_alldevices.txt"
		$CommandToExecute = "cmd.exe /c Wdsutil /verbose /get-alldevices >> " + $OutputFile
		RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -RenameOutput $true
		
		#		Command:  WDSUTIL /Get-AllServers /Show:Config
		#		OutputFileName: wdsutil_get_all_wds_servers.txt
		$fileDescription = "wdsutil /Get-AllServers /Show:Config output"
		$OutputFile = join-path $pwd.path "\wdsutil_get_all_wds_servers.txt"
		$CommandToExecute = "cmd.exe /c Wdsutil /Get-AllServers /Show:Config >> " + $OutputFile
		RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -RenameOutput $true
		
		#		Command:  WDSUTIL /Get-AutoAddDevices /DeviceType:ApprovedDevices
		#		OutputFileName: wdsutil_approved_devices.txt
		$fileDescription = "wdsutil /Get-AutoAddDevices /DeviceType:ApprovedDevices output"
		$OutputFile = join-path $pwd.path "\wdsutil_approved_devices.txt"
		$CommandToExecute = "cmd.exe /c Wdsutil /Get-AutoAddDevices /DeviceType:ApprovedDevices >> " + $OutputFile
		RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -RenameOutput $true

		#		Command:  WDSUTIL /Get-AutoAddDevices /DeviceType:RejectedDevices
		#		OutputFileName: wdsutil_rejected_devices.txt
		$fileDescription = "wdsutil /Get-AutoAddDevices /DeviceType:RejectedDevices output"
		$OutputFile = join-path $pwd.path "\wdsutil_rejected_devices.txt"
		$CommandToExecute = "cmd.exe /c Wdsutil /Get-AutoAddDevices /DeviceType:RejectedDevices >> " + $OutputFile
		RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -RenameOutput $true
		
		#		Command: WDSUTIL /Get-AutoAddDevices /DeviceType:PendingDevices
		#		OutputFileName:  wdsutil_pending_devices.txt
		$fileDescription = "wdsutil /Get-AutoAddDevices /DeviceType:PendingDevices output"
		$OutputFile = join-path $pwd.path "\wdsutil_pending_devices.txt"
		$CommandToExecute = "cmd.exe /c Wdsutil /Get-AutoAddDevices /DeviceType:PendingDevices >> " + $OutputFile
		RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -RenameOutput $true
		
		#		On 2008R2/2012/2012R2 only get the following additional 2 command outputs 
		if ($OSVersion.Minor -ge 1)
		{
			#		Command: wdsutil /get-alldrivergroups /show:all 
			#		OutputFileName: wdsutil_get_alldrivergroups.txt 
			$fileDescription = "wdsutil /get-alldrivergroups /show:all output"
			$OutputFile = join-path $pwd.path "\wdsutil_get_alldrivergroups.txt"
			$CommandToExecute = "cmd.exe /c Wdsutil /get-alldrivergroups /show:all >> " + $OutputFile
			RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -RenameOutput $true
			
			#		Command: wdsutil /get-alldriverpackages /show:all 
			#		OutputFileName: wdsutil_get_all_driver_packages.txt 
			$fileDescription = "wdsutil /get-alldriverpackages /show:all output"
			$OutputFile = join-path $pwd.path "\wdsutil_get_all_driver_packages.txt"
			$CommandToExecute = "cmd.exe /c Wdsutil /get-alldriverpackages /show:all >> " + $OutputFile
			RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription -RenameOutput $true
		}
	
	#	Command: Registry dump HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\WDSServer reg key 
	#	OutputFileName: WDSServer_Registry_Keys 
	$OutputFile = $PWD.Path + "\WDSServer_Registry_Key.txt"
	$fileDescription = "HKLM\SYSTEM\CurrentControlSet\services\WDSServer - registry key export"
	$CommandToExecute = 'cmd.exe /c REG EXPORT "HKLM\SYSTEM\CurrentControlSet\services\WDSServer" ' + $OutputFile
	RunCmD -commandToRun $CommandToExecute 
	collectfiles -filestocollect $OutputFile -filedescription $fileDescription -sectiondescription $sectionDescription -noFileExtensionsOnDescription -RenameOutput $true 	
	
	#	Command: Registry dump HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Tracing\WDSServer 
	#	OutputFilenName: WDSServer_Tracing_Registry_Keys 
	$OutputFile = $PWD.Path + "\WDSServer_Tracing_Registry_Key.txt"
	$fileDescription = "HKLM\SOFTWARE\Microsoft\Tracing\WDSServer - registry key export"
	$CommandToExecute = 'cmd.exe /c REG EXPORT "HKLM\SOFTWARE\Microsoft\Tracing\WDSServer" ' + $OutputFile
	RunCmD -commandToRun $CommandToExecute 
	collectfiles -filestocollect $OutputFile -filedescription $fileDescription -sectiondescription $sectionDescription -noFileExtensionsOnDescription -RenameOutput $true 	

	#	Command: Registry dump HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\wdsmc 
	#	OutputFileName: WDSMC_Registry_Keys 
	$OutputFile = $PWD.Path + "\WDSMC_Registry_Key.txt"
	$fileDescription = "HKLM\SYSTEM\CurrentControlSet\services\wdsmc - registry key export"
	$CommandToExecute = 'cmd.exe /c REG EXPORT "HKLM\SYSTEM\CurrentControlSet\services\wdsmc" ' + $OutputFile
	RunCmD -commandToRun $CommandToExecute 
	collectfiles -filestocollect $OutputFile -filedescription $fileDescription -sectiondescription $sectionDescription -noFileExtensionsOnDescription -RenameOutput $true 	
	
	#	Command: Registry dump HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\wdstfp 
	#	OutputFileName: WDSTFP_Registry_Keys 
	$OutputFile = $PWD.Path + "\WDSTFP_Registry_Key.txt"
	$fileDescription = "HKLM\SYSTEM\CurrentControlSet\services\wdstfp - registry key export"
	$CommandToExecute = 'cmd.exe /c REG EXPORT "HKLM\SYSTEM\CurrentControlSet\services\wdstfp" ' + $OutputFile
	RunCmD -commandToRun $CommandToExecute 
	collectfiles -filestocollect $OutputFile -filedescription $fileDescription -sectiondescription $sectionDescription -noFileExtensionsOnDescription -RenameOutput $true 	

	}
}


# SIG # Begin signature block
# MIInoQYJKoZIhvcNAQcCoIInkjCCJ44CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDqLqH4WMREP6wG
# N9dHOZFqEpheKDnTuuN1b108T2qxoqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIhj42JITLTcHyvs0DkxDYQs
# Tsri3DcWmSQyXc2isVzjMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCiXTkbs6GPBsuCdZRdPcTzyibigtGu5xNRHeCALtLFAU/DxBosL8GJ
# /+k5Jrft83gWwY7V880gYr4W+13cm3T8tU8LC3js4o7gR2HirTdbnoDK90D2kcsG
# 2pNe854cCeVnxD+wCVQlyeYsbM8KU+D3mFFwVxHA8Bdf6moj6dLZ0HvX38hXmSuH
# 52VMXJCFjkeTLDr8kvIsyv3bGqQ6csVrY21oXsZwN2XInZay8E9sqE5cpuC0Z4M8
# +N26OX8KQw0odabh+HWI8sOI+UIjtsm4/6TujotBWv+ZCv7AXkrJ+CDWm4DMpmqu
# RzItlZ8KzW59yJYhSV07hHVz/5FKCv/koYIXCTCCFwUGCisGAQQBgjcDAwExghb1
# MIIW8QYJKoZIhvcNAQcCoIIW4jCCFt4CAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIMyM1YYtoG8VPNEV17tDKe2sOu2TXSqhfgG31mAjWPLMAgZi2xAP
# VZQYEzIwMjIwODAxMDc1MTQwLjcwMlowBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
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
# CRABBDAvBgkqhkiG9w0BCQQxIgQg8taeyKm5aJ1oefjbBlrVC6GlrNo2Ixm7zWpB
# gGKoiT8wgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAOHK/6sIVgEVSVD3Ar
# vk6OyQKvRxFHKyraUzbN1/AKVzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABqwkJ76tj1OipAAEAAAGrMCIEIHI+RQKHTZ2Id7/ufvKq
# /DQk+dqQy1YkmvsPNzOkpL0iMA0GCSqGSIb3DQEBCwUABIICAB9zMD6XLsMHL6Nu
# w+lDbnZ3w1LGaoVH6xaYU2CD3fJveoXBrkEtfzNd2SuZLst848flCPKS0QtRyOQN
# lknQYOF56P5QNlODnvzNQzbhCYzm24/QNqMaiSv4ulKg4lDDT9XioQVoOSaWNkhe
# HvsAqFGGHOdWOJ2crlXs/2/sDC3B8QDSkIybWIbdxxdKdC6pKgggeXbmryLyR+UC
# N0vyaVBrS1yNrPqiNKjQzMoKxOzv5MuaEaFYKmyFVlLRZMIRSTrg+LOBVRCj0mDp
# 7PwmnVEdKtTXMD13uJp6LWw5dODXKlEceey5j116IRrdex3wkuTOpIaF3o1oYbgp
# 1h18D0/Cbw1wzFDBJWtF3osMfuF16ZGqwIapO821zZp6iqOS4Iw71z5qAsSsp1rL
# SpHjZj+uV84M8u6dbLPrm4E150gTBhqEoi8wblEnlLaBmomNrP5oODiXd1yale/t
# fmcqPZT9dQjyeEW8jTS+NtODDTYVpbegddAKNCSeGc6tQwxD6r2Dt3O8oyk/2r8E
# 8vab6+tUN04O9ITg4A66v1pu3RTm/UZEeDyS1nEgj5zmZbwByh3fFCmk+tfq/L6Z
# 8ySkmf7tBSsOyi0Xf9J86qnYDcqKZgi/Uc2t+hDvZ5XUeBZ3K07DZqx138/3MBwk
# z1uWw6sHTAtKD1d4f3d8b4eVGSRY
# SIG # End signature block
