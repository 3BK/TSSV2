<#
.SYNOPSIS
	SharePoint module for collecting traces

.DESCRIPTION
	Define ETW traces for SharePoint components 
	Add any custom tracing functinaliy for tracing SharePoint components
	For Developers:
	1. Component test: .\TSSv2.ps1 -Start -SPS_TEST1
	2. Scenario test: .\TSSv2.ps1 -start -Scenario SPS_MyScenarioTest

.NOTES
	Dev. Lead: 
	Authors	 : waltere
	Requires   : PowerShell V4 (Supported from Windows 8.1/Windows Server 2012 R2)
	Version    : see $global:TssVerDateSPS

.LINK
	TSSv2 https://internal.support.services.microsoft.com/en-us/help/4619187
	INT https://internal.support.services.microsoft.com/en-us/help/1234567 -todo
#>

<# latest changes (reverse chronological order)

::  2023.04.20.0 [we] SPS_ULS: allow omitting -startTime/-endTime and use New-SPLogFile; add Merge-SPLogFile
::  2023.04.06.0 [we] add Add-PSSnapin only for SPS_ULS
::  2023.04.04.0 [we] SPS_ULS: add -Mode <Medium|Verbose|VerboseEx>
::	2023.03.29.0 [we] add SPS_ULS component 
#>

#region --- Define local INT Variables
$global:TssVerDateSPS= "2023.04.20.0"

$BinArch = "\Bin" + $global:ProcArch
#endregion --- Define local INT Variables

	
#------------------------------------------------------------
#region --- ETW component trace Providers ---
#------------------------------------------------------------

#---  Dummy Providers ---# #for components without a tracing GUID
#$SPS_ULSProviders = @()
#$SPS_DummyProviders = @(	#for components without a tracing GUID
#	'{eb004a05-9b1a-11d4-9123-0050047759bc}' # Dummy tcp for switches without tracing GUID (issue #70)
#)

#---  Mobile Providers ---#
$SPS_ULSProviders = @(
	'{42CF61CF-8F2B-476D-ACEA-1003ACE7E046}' # Microsoft-WindowsMobile-SharePoint-Notification-Provider
	'{1FB45244-B12B-472C-81FB-4AF537E8A56A}' # Microsoft-WindowsMobile-OfficeMobile-Provider
)
#endregion --- ETW component trace Providers ---


#------------------------------------------------------------
#region --- Scenario definitions ---  
#------------------------------------------------------------
$SPS_General_ETWTracingSwitchesStatus = [Ordered]@{
	#'SPS_Dummy' = $true
	#'CommonTask NET' = $True  ## <------ the commontask can take one of "Dev", "NET", "ADS", "UEX", "DnD" and "SHA", or "Full" or "Mini"
	'NetshScenario InternetClient_dbg' = $true
	'Procmon' = $true
	'WPR General' = $true
	'PerfMon ALL' = $true
	'PSR' = $true
	'Video' = $true
	'SDP Net' = $True
	'xray' = $True
	'CollectComponentLog' = $True
}

#endregion --- Scenario definitions ---  

#region ### Pre-Start / Post-Stop / Collect functions for trace components and scenarios 
#------------------------------------------------------------
#--- Platform Trace ---#
function SPS_ULSPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	Write-Host -ForegroundColor Gray "Usage: .\TSSv2ps1 -CollectLog SPS_ULS [-startTime `"01/25/2023 11:30`" -endTime `"01/26/2023 14:30`" [-Servers `"server1`",`"server2`"]] [-Merge]"
	Write-Host -ForegroundColor Gray " -or-: .\TSSv2ps1 -SPS_ULS -Mode <Medium|Verbose|VerboseEx> [-Merge]"
	if([String]::IsNullOrEmpty($global:Servers)){$ServerList ="all SP servers in the farm"}else{$ServerList = "$global:Servers"}
	Write-Host "Running ULS collect with parameters:"
	Write-Host "`tVerbosity : $Mode"
	if(![String]::IsNullOrEmpty($global:SPSStartTime)){
		Write-Host "
		`tStartTime : $(get-date $global:SPSStartTime)
		`tEndTime   : $(get-date $global:SPSEndTime)
		`tServers   : $ServerList"
	}
	Try {
		# adding snapin for Microsoft.SharePoint.PowerShell
		[Void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SharePoint")
		#[Reflection.Assembly]::LoadWithPartialName( "System.IO.Compression.FileSystem" )
		Add-PSSnapin Microsoft.SharePoint.PowerShell -EA SilentlyContinue
		Start-SPAssignment -Global
		LogInfo "Setting verbosity log level: Set-SPLogLevel -TraceSeverity $Mode" "Cyan"
		if ($Mode -match "Medium|Verbose|VerboseEx"){
			Set-SPLogLevel -TraceSeverity $Mode
		}else{
			Set-SPLogLevel -TraceSeverity Medium
		}
	}Catch{ LogError "Unable to load Microsoft.SharePoint.PowerShell' snapin"}
	if([String]::IsNullOrEmpty($global:SPSStartTime)){
		New-SPLogFile
	}
	EndFunc $MyInvocation.MyCommand.Name
}
function SPS_ULSPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	#noop
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectSPS_ULSLog{
	# Description : This function will collect individual ULS logs from specified servers or all servers in the farm.
	# Usage       : .\TSSv2ps1 -CollectLog SPS_ULS -startTime "01/25/2023 11:30" -endTime "01/26/2023 14:30" [-Servers "server1","server2"]
	#        -or- : .\TSSv2ps1 -CollectLog SPS_ULS -Mode <Medium|Verbose|VerboseEx>
	# Notes       :  If no '-Servers' switch is passed, it will grab ULS from all SP servers in the farm..
<#	param(
		[Parameter(Mandatory=$false)][AllowNull()]
		[string[]]$global:Servers,
		[Parameter(Mandatory=$true, HelpMessage='Enter time format like: "01/15/2023 20:30" ')]
		[string] $startTime,
		[Parameter(Mandatory=$true, HelpMessage='Enter time format like: "01/15/2023 22:30" ')]
		[string] $endTime
	)
	#>
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		$spDiag = Get-SPDiagnosticConfig
		$global:ulsPath = $spDiag.LogLocation
		$global:LogCutInterval = $spDiag.LogCutInterval

		#Get SharePoint Servers and SP Version
		$spVersion = (Get-PSSnapin Microsoft.Sharepoint.Powershell).Version.Major
		if($spVersion -eq 15) {LogWarn "SharePoint 2013 reached end of support: April 11, 2023"}
		if((($spVersion -ne 15) -and ($spVersion -ne 16) -and ($spVersion -ne 17))){
			LogWarn "Supported version of SharePoint was not detected"
			LogWarn "Script is supported for SharePoint 2013, 2016, or 2019"
			LogInfo "Exiting Script"
			Return
		}else{
			$defLogPath = (Get-SPDiagnosticConfig).LogLocation -replace "%CommonProgramFiles%", "C$\Program Files\Common Files"
			$defLogPath = $defLogPath -replace ":", "$"
			"Default ULS Log Path:  " + $defLogPath
			""
			LogInfo " **We will copy files from each server into a subfolder of the TSS Output Folder and then compress those files into a .zip file. This can take several minutes to complete depending on network speed, number of files and size of files." "Cyan"
			""
		}
	}catch{ LogWarn "This is likely not a SharePoint server ($Env:Computername)"}

	if($null -eq $global:Servers){
		$Servers = Get-SPServer | ?{$_.Role -ne "Invalid"} | % {$_.Address}
	}
	foreach($server in $Servers){
		$serverName = $server
		$tempSvrPath = $global:LogFolder + "\" +$servername
		FwCreateFolder $tempSvrPath
		grabULS2 $serverName
	}
	LogInfo ".. clearing log level, using command: Clear-SPLogLevel" "Cyan"
	Clear-SPLogLevel
	LogInfo "`nFinished Copying\Zipping ULS files.." "Green"
	EndFunc $MyInvocation.MyCommand.Name
}
#endregion ### Pre-Start / Post-Stop / Collect functions for trace components and scenarios 

#region --- HelperFunctions ---
function SPS_start_common_tasks {
	#collect info for all tss runs at _Start_
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "___switch Mini: $global:Mini" "cyan"
	if ($global:Mini -ne $true) {
		#LogInfoFile "PATH: $Env:Path"
		FwGetSysInfo _Start_
		FwGetSVC _Start_
		FwGetSVCactive _Start_ 
		FwGetTaskList _Start_
		FwGetSrvWkstaInfo _Start_
		FwGetNltestDomInfo _Start_
		FwGetKlist _Start_ 
		FwGetBuildInfo
		if ($global:noClearCache -ne $true) { FwClearCaches _Start_ } else { LogInfo "[$($MyInvocation.MyCommand.Name) skip FwClearCaches" }
		FwGetRegList _Start_
		FwGetPoolmon _Start_
		FwGetSrvRole
	}
	FwGetLogmanInfo _Start_
	LogInfoFile "___ SPS_start_common_tasks DONE"
	EndFunc $MyInvocation.MyCommand.Name
}
function SPS_stop_common_tasks {
	#collect info for all tss runs at _Stop_
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:Mini -ne $true) {
		FwGetDFScache _Stop_
		FwGetSVC _Stop_
		FwGetSVCactive _Stop_ 
		FwGetTaskList _Stop_
		FwGetKlist _Stop_
		FwGetWhoAmI _Stop_
		FwGetDSregCmd
		FwGetHotfix
		FwGetPoolmon _Stop_
		FwGetLogmanInfo _Stop_
		FwGetNltestDomInfo _Stop_
		FwListProcsAndSvcs _Stop_
		FwGetRegList _Stop_
		writeTesting "___ FwGetEvtLogList"
		("System", "Application") | ForEach-Object { FwAddEvtLog $_ _Stop_}
		FwGetEvtLogList _Stop_
	}
	FwGetSrvWkstaInfo _Stop_
	FwGetRegHives _Stop_
	FwCopyMemoryDump -DaysBack 2
	LogInfoFile "___ SPS_stop_common_tasks DONE"
	EndFunc $MyInvocation.MyCommand.Name
}

function grabULS2{
	# This function will collect ULS logs from remote Sharepoint server
	param(
		[Parameter(Mandatory=$True)]
		[String]$SPserverName
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$localPath = "\\" + $SPserverName + "\" + $defLogPath
	LogInfo ("Getting ready to copy logs from: " + $localPath)
	if(![String]::IsNullOrEmpty($global:SPSStartTime)){
		LogInfo "Time range: $SPSStartTime till $SPSEndTime" "Gray"
		Write-Host ""
		# subtracting the 'LogCutInterval' value to ensure that we grab enough ULS data 
		$startTm = $SPSStartTime.Replace('"', "")
		$startTm = $startTm.Replace("'", "")
		$sTime = (Get-Date $startTm).AddMinutes(-$LogCutInterval)
		# setting the endTime variable 
		$endTm = $SPSEndTime.Replace('"', "")
		$endTm = $endTm.Replace("'", "")
		$eTime = Get-Date $endTm

		If (Test-Path $localPath){
			$files = get-childitem -path $localPath -EA SilentlyContinue | ?{$_.Extension -eq ".log"} | select Name, CreationTime
		}else{LogError "Path $localPath is not reachable"}
		If ($files){
			$specfiles = $files | ?{$_.CreationTime -lt $eTime -and $_.CreationTime -ge $sTime}
		}
		if($specfiles.Length -lt 1){
			LogInfo ("We did not find any ULS logs for server " + $SPserverName + " within the given time range $SPSStartTime till $SPSEndTime.") "Magenta"
			$rmvDir = $global:LogFolder + "\" + $SPserverName
			rmdir $rmvDir -Recurse -Force
			return;
		}else{
			foreach($file in $specfiles){
				$filename = $file.name
				"Copying file:  " + $filename
				copy-item "$localpath\$filename" $global:LogFolder\$SPserverName
			}
			if($global:SPSmerge){
				$MergedFile = $global:LogFolder + "\FarmMergedLog.log"
				LogInfo "merging Time range: $SPSStartTime till $SPSEndTime. Please be patient..."
				Merge-SPLogFile -Path $MergedFile -Overwrite -StartTime $SPSStartTime -EndTime $SPSEndTime
			}
		}
	}else{
		# case of New-SPLogFile
		If (Test-Path $localPath){
			$files = get-childitem -path $localPath -EA SilentlyContinue | ?{$_.Extension -eq ".log"} | select Name, CreationTime
			foreach($file in $files){
				$filename = $file.name
				"Copying file:  " + $filename
				copy-item "$localpath\$filename" $global:LogFolder\$SPserverName
			}
		}else{LogError "LogFile Path $localPath is not reachable"}	
	}
	<# skip, as TSS will zip all data finally
	$timestamp = $(Get-Date -format "yyyyMMdd_HHmm")
	$sourceDir = $tempSvrPath
	$zipfilename = $tempSvrPath + "_" + $timestamp + ".zip"
	""
	Write-Host ("Compressing ULS logs to location: " + $zipfilename) -ForegroundColor DarkYellow
	
	$compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
	[System.IO.Compression.ZipFile]::CreateFromDirectory( $tempSvrPath, $zipfilename, $compressionLevel, $false )
	Write-Host ("Cleaning up the ULS logs and temp directory at: " + $tempSvrPath) -ForegroundColor DarkYellow
	rmdir $sourcedir -Recurse -Force
	#>
	EndFunc $MyInvocation.MyCommand.Name
 }

#endregion --- HelperFunctions ---

#region Registry Key modules for FwAddRegItem
	# $global:KeysULS = @("HKLM:Software\Microsoft\ULS")
#endregion Registry Key modules

#region groups of Eventlogs for FwAddEvtLog
	<# Example:
	$global:EvtLogsEFS		= @("Microsoft-Windows-NTFS/Operational", "Microsoft-Windows-NTFS/WHC")
	#>
#endregion groups of Eventlogs

Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *
# SIG # Begin signature block
# MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBDp+V6OAPREmMn
# D7hm51I/q9DRUZ96RiNZNHE5kUXQ9aCCDYUwggYDMIID66ADAgECAhMzAAADTU6R
# phoosHiPAAAAAANNMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI4WhcNMjQwMzE0MTg0MzI4WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDUKPcKGVa6cboGQU03ONbUKyl4WpH6Q2Xo9cP3RhXTOa6C6THltd2RfnjlUQG+
# Mwoy93iGmGKEMF/jyO2XdiwMP427j90C/PMY/d5vY31sx+udtbif7GCJ7jJ1vLzd
# j28zV4r0FGG6yEv+tUNelTIsFmmSb0FUiJtU4r5sfCThvg8dI/F9Hh6xMZoVti+k
# bVla+hlG8bf4s00VTw4uAZhjGTFCYFRytKJ3/mteg2qnwvHDOgV7QSdV5dWdd0+x
# zcuG0qgd3oCCAjH8ZmjmowkHUe4dUmbcZfXsgWlOfc6DG7JS+DeJak1DvabamYqH
# g1AUeZ0+skpkwrKwXTFwBRltAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUId2Img2Sp05U6XI04jli2KohL+8w
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzUwMDUxNzAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# ACMET8WuzLrDwexuTUZe9v2xrW8WGUPRQVmyJ1b/BzKYBZ5aU4Qvh5LzZe9jOExD
# YUlKb/Y73lqIIfUcEO/6W3b+7t1P9m9M1xPrZv5cfnSCguooPDq4rQe/iCdNDwHT
# 6XYW6yetxTJMOo4tUDbSS0YiZr7Mab2wkjgNFa0jRFheS9daTS1oJ/z5bNlGinxq
# 2v8azSP/GcH/t8eTrHQfcax3WbPELoGHIbryrSUaOCphsnCNUqUN5FbEMlat5MuY
# 94rGMJnq1IEd6S8ngK6C8E9SWpGEO3NDa0NlAViorpGfI0NYIbdynyOB846aWAjN
# fgThIcdzdWFvAl/6ktWXLETn8u/lYQyWGmul3yz+w06puIPD9p4KPiWBkCesKDHv
# XLrT3BbLZ8dKqSOV8DtzLFAfc9qAsNiG8EoathluJBsbyFbpebadKlErFidAX8KE
# usk8htHqiSkNxydamL/tKfx3V/vDAoQE59ysv4r3pE+zdyfMairvkFNNw7cPn1kH
# Gcww9dFSY2QwAxhMzmoM0G+M+YvBnBu5wjfxNrMRilRbxM6Cj9hKFh0YTwba6M7z
# ntHHpX3d+nabjFm/TnMRROOgIXJzYbzKKaO2g1kWeyG2QtvIR147zlrbQD4X10Ab
# rRg9CpwW7xYxywezj+iNAc+QmFzR94dzJkEPUSCJPsTFMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGXMwghlvAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAANNTpGmGiiweI8AAAAA
# A00wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPD/
# VuTOIXfFAyFrAKoNY8+VOQrniAFrauYW5XCH5ixcMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAO/ptK7RxBJOW6pTgTZybt1x7bCidGaHwkGrG
# 4QdHXsbrLO+rlt9WtslL1c/NcX5L+0weKUC4NLOtv/S0FTste8J5VYnbs5hvbHDW
# wPmUT+TWmv6N7yQaNC/IAkGXigWRaR7pEitlrn5U42IW4llofvOR8f5dDChtYACZ
# EvLsZmVRKh3pDGINEpBJ1bG78pxCDfEu4LsLdMKWDQ3hZ9gEDLsl9wrPRvzFhIN1
# c4evcEB9LoyTPFFrZN7YyqIGC77NhEyUGH1ExX48aZ3KtcFGKSLJsHjtOvrYO8ch
# PJjFvtn7XffbPIINQOsbyC1N+KYW0v3zh1r8c0gbd7YTeAhKmqGCFv0wghb5Bgor
# BgEEAYI3AwMBMYIW6TCCFuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCDPFxmFOLUfsyOQV7bIQdro3YBNaWPd8RW1
# kEENmpSV6wIGZGzWaf2hGBMyMDIzMDYwNjExNDQxNi45OThaMASAAgH0oIHQpIHN
# MIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjozRTdBLUUzNTktQTI1RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEVQwggcMMIIE9KADAgECAhMzAAAByfrVjiUgdAJeAAEA
# AAHJMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMTEwNDE5MDEzOFoXDTI0MDIwMjE5MDEzOFowgcoxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNFN0EtRTM1
# OS1BMjVEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1nLi5Y5vz8K+Woxhk7qGW/vC
# xi5euTM01TiEbFOG8g7SFB0VMjYgo6TiRzgOQ+CN53OBOKlyMHWzRL4xvaS03ZlI
# getIILYiASogsEtljzElRHO7fDGDFWcdz+lCNYmJoztbG3PMrnxblUHHUkr4C7EB
# Hb2Y07Gd5GJBgP8+5AZNsTlsHGczHs45mmP7rUgcMn//c8Q/GYSqdT4OXELp53h9
# 9EnyF4zcsd2ZFjxdj1lP8QGwZZS4F82JBGe2pCrSakyFjTxzFKUOwcQerwBR/YaQ
# ly7mtCra4PNcyEQm+n/LDce/VViQa8OM2nBZHKw6CyMqEzFJJy5Hizz8Z6xrqqLK
# ti8viJUQ0FtqkTXSR3//w8PAKyBlvIYTFF/Ly3Jh3cbVeOgSmubOVwv8nMehcQb2
# AtxcU/ldyEUqy8/thEHIWNabzHXx5O9D4btS6oJdgLmHxrTBtGscVQqx0z5/fUIk
# LE7tbwfoq84cF/URLEyw3q57KV2U4gOhc356XYEVQdJXo6VFWBQDYbzanQ25zY21
# UCkj821CyD90gqrO3rQPlcQo6erwW2DF2fsmgAbVqzQsz6Rkmafz4re17km7qe09
# PuwHw5e3x5ZIGEoVlfNnJv6+851uwKX6ApZFxPzeQo7W/5BtaTmkZEhwY5AdCPgP
# v0aaIEQn2qF7MvFwCcsCAwEAAaOCATYwggEyMB0GA1UdDgQWBBQFb51nRsI8ob54
# OhTFeVF7RC4yyzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
# KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4ICAQA2qLqcZt9HikIHcj7AlnHhjouxSjOeBaTE+EK8aXcV
# Lm9cA8D2/ZY2OUpYvOdhuDEV9hElVmzopiJuk/xBYh6dWJTRhmS7hVjrGtqzSFW0
# LffsRysjxkpuqyhHiBDxMXMGZ6GdzUfqVP2Zd2O+J/BYQJgs9NHYz/CM4XaRP+T2
# VM3JE1mSO1qLa+mfB427QiLj/JC7TUYgh4RY+oLMFVuQJZvXYl/jITFfUppJoAak
# Br0Vc2r1kP5DiJaNvZWJ/cuYaiWQ4k9xpw6wGz3qq7xAWnlGzsawwFhjtwq5EH/s
# 37LCfehyuCw8ZRJ9W3tgSFepAVM7sUE+Pr3Uu+iPvBV4TsTDNFL0CVIPX+1XOJ6Y
# RGYJ2kHGpoGc/5sgA2IKQcl97ZDYJIqixgwKNftyN70O0ATbpTVhsbN01FVli0H+
# vgcGhyzk6jpAywHPDSQ/xoEeGU4+6PFTXMRO/fMzGcUcf0ZHqZMm0UhoH8tOtk18
# k6B75KJXTtY3ZM7pTfurSv2Qrv5zzCBiyystOPw/IJI+k9opTgatrC39L69/Kwyt
# D0x7t0jmTXtlLZaGvoSljdyyr6QDRVkqsCaLUSSsAiWeav5qg64U3mLmeeko0E9T
# J5yztN/jcizlHx0XsgOuN6sub3CPV7AAMMiKopdQYqiPXu9IxvqXT7CE/SMC2pcN
# yTCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQEL
# BQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNV
# BAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4X
# DTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM
# 57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm
# 95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzB
# RMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBb
# fowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCO
# Mcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYw
# XE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW
# /aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/w
# EPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPK
# Z6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2
# BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfH
# CBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYB
# BAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8v
# BO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYM
# KwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEF
# BQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBW
# BgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUH
# AQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# L2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsF
# AAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518Jx
# Nj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+
# iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2
# pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefw
# C2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7
# T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFO
# Ry3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhL
# mm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3L
# wUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5
# m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE
# 0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLLMIICNAIB
# ATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UE
# CxMdVGhhbGVzIFRTUyBFU046M0U3QS1FMzU5LUEyNUQxJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAH3pi8v+HgGb
# jVQs4G36dRxWBt0OoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwDQYJKoZIhvcNAQEFBQACBQDoKR8aMCIYDzIwMjMwNjA2MTA1NzMwWhgPMjAy
# MzA2MDcxMDU3MzBaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOgpHxoCAQAwBwIB
# AAICFicwBwIBAAICEeMwCgIFAOgqcJoCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYK
# KwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUF
# AAOBgQAwd+aEcACrJansvBLpKWf51UWV4An/sKpNi4fkqX7jijcQD0SZ3ZM9qgkG
# H/fFPOikMesIWe6O9orTwm4rV1kTB7WYQL/XTx8gO6iUi0KBT0QZL12QBeP7jpCA
# nKddXAjb86uHrVO7ZZUMVM3vibO190xOWGPWu0cgpVxTCsKEkTGCBA0wggQJAgEB
# MIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAByfrVjiUgdAJe
# AAEAAAHJMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwLwYJKoZIhvcNAQkEMSIEINtJFwH6NzyMirIEHhW16YxCjsaO1iaHfx/h
# k/izlXpqMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQggXXOf1LdUUsQJ3gp
# 2H9gDSMhiQD/zX3hXXzh2Tl2/YEwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAcn61Y4lIHQCXgABAAAByTAiBCBLGLI4zWV3F5jZP8Na
# XN3MMvXjnRy2BkvxARRPxfD72jANBgkqhkiG9w0BAQsFAASCAgBfc+adIKZMywaG
# sS0PDNevg5Fviv0ZhRHz3+pZJowAEvpGzv5WsIBKMW1dt8v2gwpjxFXQ/764IcnF
# kD3KdPEBHotutIvzQXYDA97xyG6ISrsdNQZ3Sv/CgYIwQN6jqtraHxRYs/X+Vnvb
# KAkY0Z0GZrIgrnK06YQc0jCxP0cpNd2LqH56RtHsUr8Mln0ETKr1niDuESyt4M/E
# tTXbB8ZCPd+hdQQ7FxkTi20Ya/4TGn309nqXlTf686c/bMSJ7M/9zxuB7Sin+7Zb
# Xzvy7pPPowoWROzYEimQwi/XPk99OZX1lQZE+ooFfai7yMT9Ga5tDgkmpSePrinu
# IeAv2pYQtw7jqqAkZT9eO7QhKHZmIt+ChVsIy1M0j4+gI8Kqlp1jJhjUwthw88av
# UM0uPfNvmw2NrWL0MGC3iLZxeWbxNE+cWRMAMD2XFDQ2rjf9JAa4kLHeNTyMnHHb
# /qTs6/yXWTJDCKLZm2KVFKsSCd7lKFKWBIg3E6MZ40QgT6x2xqT+51dJpqU72M9t
# TUp2vuMoj2L3pwfnTr7OqEpFZuzne6UGu17RwA8a1tsNxtvhWjPs/w8T42dIb7cV
# TWYR0LIH1+UQL+7bTKXz+QMYex0CCDvm15bZn75MxDtydUz6SOxIYqsHvcpIE1rt
# YWvbSQdMN/HZkeBxMDdpVV/0eMfA3w==
# SIG # End signature block
