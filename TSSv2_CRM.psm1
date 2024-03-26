<#
.SYNOPSIS
	CRM module for collecting traces

.DESCRIPTION
	Define ETW traces for Windows CRM components 
	Add any custom tracing functinaliy for tracing CRM components
	For Developers:
	1. Component test: .\TSSv2.ps1 -Start -CRM_TEST1
	2. Scenario test: .\TSSv2.ps1 -start -Scenario CRM_MyScenarioTest

.NOTES
	Dev. Lead: Julien.Clauzel
	Authors    : Julien.Clauzel@microsoft.com; remib@microsoft.com
	Requires   : PowerShell V4 (Supported from Windows 8.1/Windows Server 2012 R2)
	Version    : see $global:TssVerDateCRM

.LINK
	TSSv2 https://internal.support.services.microsoft.com/en-us/help/4619187
	CRM https://internal.support.services.microsoft.com/en-us/help/1234567
#>

<# latest changes (reverse chronological order)
::	2023.02.23.0 [we] upd psSDP for CRMbase; add CRM_IISdump scenario (tbd soon)
::	2023.02.21.0 [we] add FwGet-SummaryVbsLog for CRM_Platform
::	2023.02.18.0 [we] add CRM_Platform component and scenario
#>

#region --- Define local CRM Variables
$global:TssVerDateCRM= "2023.02.24.0"

#endregion --- Define local CRM Variables
#------------------------------------------------------------
#region --- ETW component trace Providers ---
#------------------------------------------------------------

#---  Dummy Providers ---# #for components without a tracing GUID
#$CRM_PlatformProviders = @()
$CRM_DummyProviders = @(	#for components without a tracing GUID
	'{eb004a05-9b1a-11d4-9123-0050047759bc}' # Dummy tcp for switches without tracing GUID (issue #70)
)
$CRM_PlatformProviders = $CRM_DummyProviders
$CRM_IISdumpProviders = $CRM_DummyProviders
#endregion --- ETW component trace Providers ---


#------------------------------------------------------------
#region --- Scenario definitions ---
#------------------------------------------------------------
$CRM_General_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_Dummy' = $true
	#'CommonTask NET' = $True  ## <------ the commontask can take one of "Dev", "NET", "ADS", "UEX", "DnD" and "SHA", or "Full" or "Mini"
	'NetshScenario InternetClient_dbg' = $true
	'Procmon' = $true
	'WPR General' = $true
	'PerfMon ALL' = $true
	'PSR' = $true
	'Video' = $true
	'SDP CRMBase' = $True
	'xray' = $True
	'CollectComponentLog' = $True
}

$CRM_Platform_ETWTracingSwitchesStatus = [Ordered]@{
	'CRM_Platform' = $true
	#'CommonTask NET' = $True
#	'NetshScenario InternetClient_dbg' = $true
#	'Procmon' = $true
#	'WPR General' = $true
#	'PerfMon ALL' = $true
	'PSR' = $true
	'Video' = $true
#	'SDP CRMbase' = $True
	'noBasicLog' = $true
	'xray' = $True
	'CollectComponentLog' = $True
}
$CRM_IISdump_ETWTracingSwitchesStatus = [Ordered]@{
	'CRM_IISdump' = $true
	#'CommonTask NET' = $True
#	'NetshScenario InternetClient_dbg' = $true
#	'Procmon' = $true
#	'WPR General' = $true
#	'PerfMon ALL' = $true
	'PSR' = $true
	'Video' = $true
#	'SDP CRMbase' = $True
	'noBasicLog' = $true
	'xray' = $True
	'CollectComponentLog' = $True
}

#endregion --- Scenario definitions ---

#region ### Pre-Start / Post-Stop / Collect functions for trace components and scenarios 
#------------------------------------------------------------
#--- Platform Trace ---#
function CRM_PlatformPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "enable Debug Registry settings for CMR Platform tracing."
	$RegPathMSCRM = "HKCU:\Software\Microsoft\MSCRMClient"
	if (Test-Path $RegPathMSCRM){
		$CRMRole = "Client"
		EnableCRMRegKeys -RegPathMSCRM $RegPathMSCRM -CRMRole $CRMRole
	}else{
		LogInfo "the reg key 'HKEY_CURRENT_USER\Software\Microsoft\MSCRMClient' was not found on this machine make sure this is the CRM client machine" "Gray"
	}
	$RegPathMSCRM = "HKLM:\Software\Microsoft\MSCRM"
	if (Test-Path $RegPathMSCRM ){
		$CRMRole = "Server"
		EnableCRMRegKeys -RegPathMSCRM $RegPathMSCRM -CRMRole $CRMRole
	}
	else{
		LogInfo "the reg key 'HKEY_LOCAL_MACHINE\Software\MICROSOFT\MSCRM'  was not found on this machine make sure this is the CRM server machine" "Gray"
	}
	LogInfo "see KB How to enable tracing in Microsoft Dynamics CRM https://support.microsoft.com/en-us/topic/how-to-enable-tracing-in-microsoft-dynamics-crm-818e8774-e123-4995-417d-7ea02395c6d0" "Cyan"
	EndFunc $MyInvocation.MyCommand.Name
}
function EnableCRMRegKeys{
	param(
		[String]$RegPathMSCRM,
		[String]$CRMRole
	)
	EnterFunc $MyInvocation.MyCommand.Name
	[int]$TraceEnabled = 1
	[int]$TraceCallStack = 1
	[string]$TraceCategories = "*:Verbose"
	[int]$TraceFileSizeLimit = 100
	$CRMCliSrv = get-Item -path $RegPathMSCRM
	$TraceRefresh = $CRMCliSrv.GetValue("TraceRefresh")
	if($null -ne $TraceRefresh){
		$TraceRefresh = $TraceRefresh + 1
	}else{
		$TraceRefresh = 1
	}
	switch($CRMRole){
		"Client" {
			$Global:TraceRefreshClient = $TraceRefresh
			$RegistryKey = "HKCU\Software\Microsoft\MSCRMClient"}
		"Server" {
			$Global:TraceRefreshServer = $TraceRefresh
			$RegistryKey = "HKLM\Software\Microsoft\MSCRM"}
	}
	FwAddRegValue "$RegistryKey" "TraceEnabled" "REG_DWORD" $TraceEnabled
	FwAddRegValue "$RegistryKey" "TraceCallStack" "REG_DWORD" $TraceCallStack 
	FwAddRegValue "$RegistryKey" "TraceFileSizeLimit" "REG_DWORD" $TraceFileSizeLimit 
	FwAddRegValue "$RegistryKey" "TraceRefresh" "REG_DWORD" $TraceRefresh
	FwAddRegValue "$RegistryKey" "TraceCategories"  "REG_SZ" $TraceCategories
	LogInfoFile "Platforms registry keys set at $RegistryKey"
	LogInfoFile "TraceEnabled      =$TraceEnabled"
	LogInfoFile "TraceCallStack    =$TraceCallStack"
	LogInfoFile "TraceRefresh      =$TraceRefresh"
	LogInfoFile "TraceCategories   =$TraceCategories"
	LogInfoFile "TraceFileSizeLimit=$TraceFileSizeLimit"
	EndFunc $MyInvocation.MyCommand.Name
}
function CRM_PlatformPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	#turn off client trace
	if (Test-Path "HKCU:\Software\Microsoft\MSCRMClient"){
		set-itemproperty -path "HKCU:\Software\Microsoft\MSCRMClient" -type DWORD -name "TraceEnabled" -value 0
		set-itemproperty -path "HKCU:\Software\Microsoft\MSCRMClient" -type DWORD -name "TraceRefresh" -value ($Global:TraceRefreshClient -1)
		LogInfo "Turned off CRM trace for Client"
	}
	#turn off server trace
	if (Test-Path "HKLM:\Software\Microsoft\MSCRM"){
		set-itemproperty -path "HKLM:\Software\Microsoft\MSCRM" -type DWORD -name "TraceEnabled" -value 0
		set-itemproperty -path "HKLM:\Software\Microsoft\MSCRM" -type DWORD -name "TraceRefresh" -value ($Global:TraceRefreshServer -1)
		LogInfo "Turned off CRM trace for Server"
		#Forcing tracing cache to update
		$installDir =(Get-ItemProperty HKLM:\Software\Microsoft\MSCRM).CRM_Server_InstallDir
		$xml = [xml](Get-Content "$($installDir)\CRMWeb\web.config")
		$xml.Save("$($installDir)\CRMWeb\web.config")
	}
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectCRM_PlatformLog{
	EnterFunc $MyInvocation.MyCommand.Name
	# aka SDP: Get-CRMPlatformTrace
	[string]$Clientpath = ($Env:USERPROFILE + "\Local Settings\Application Data\Microsoft\MSCRM\Traces")
	[string]$Serverpath = ($Env:ProgramFiles + "\Microsoft Dynamics CRM\Trace")
	#get client logs
	LogInfo "The client path is being set to $($Clientpath)"
	if (Test-Path $Clientpath){
		$file_count = (dir $Clientpath).count
		LogInfo "There are $($file_count) files located in the $($Clientpath) folder"
		$Platformslogs = Get-ChildItem -Path $Clientpath -Filter *.log | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)} | Sort-Object -property @{Expression="LastWriteTime";Descending=$true}
		if ($null -ne $Platformslogs){
			LogInfo "Client: copying recent $($Platformslogs.count) log files from $($Clientpath)"
			$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
			$SourceDestinationPaths = @( $Platformslogs, "$global:LogFolder" )
			FwCopyFiles $SourceDestinationPath -ShowMessage:$False
		}
	}else{ LogInfo "Path $Clientpath not found on this machine" "Magenta"}
	#get server logs
	LogInfo "The server path is being set to $($Serverpath)"
	if (Test-Path $Serverpath){
		$file_count = (dir $Serverpath).count
		LogInfo "There are $($file_count) files located in the $($Serverpath) folder"
		$ServerPlatformslogs = Get-ChildItem -Path $Serverpath -Filter *.log | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)} | Sort-Object -property @{Expression="LastWriteTime";Descending=$true}
		if ($null -ne $ServerPlatformslogs){
			LogInfo "Server: copying recent $($ServerPlatformslogs.count) *.log files from $($Serverpath)"
			$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
			$SourceDestinationPaths = @( $ServerPlatformslogs, "$global:LogFolder" )
			FwCopyFiles $SourceDestinationPath -ShowMessage:$False
		}
	}else{ LogInfo "Path $Serverpath not found on this machine" "Magenta"}
	FwGet-SummaryVbsLog
	EndFunc $MyInvocation.MyCommand.Name
}

#--- CRM IIS dump ---#
function CRM_IISdumpPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "...Not implemented - Coming soon" "Cyan"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectCRM_IISdumpLog{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "...Not implemented - Coming soon" "Cyan"
	EndFunc $MyInvocation.MyCommand.Name
}

#endregion ### Pre-Start / Post-Stop / Collect functions for trace components and scenarios 

#region Registry Key modules for FwAddRegItem
	<# Example:
	$global:KeysHyperV = @("HKLM:Software\Microsoft\Windows NT\CurrentVersion\Virtualization", "HKLM:System\CurrentControlSet\Services\vmsmp\Parameters")
	#>
#endregion Registry Key modules

#region groups of Eventlogs for FwAddEvtLog
	<# Example:
	$global:EvtLogsEFS		= @("Microsoft-Windows-NTFS/Operational", "Microsoft-Windows-NTFS/WHC")
	#>
#endregion groups of Eventlogs

Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *
# SIG # Begin signature block
# MIInzgYJKoZIhvcNAQcCoIInvzCCJ7sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCRDpklj2+J6bKp
# nhbCg6H14Zz8JpK1+InoomdVYuBda6CCDYUwggYDMIID66ADAgECAhMzAAADTU6R
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
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGZ8wghmbAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAANNTpGmGiiweI8AAAAA
# A00wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIAs9
# 5GGb7b2in8faSyoudOHy7GnW07EjA25NJ7fi1HIXMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAldb31hAsaA9yZ6P4u8lNfa8XT6/yxekxrFDJ
# tQaBDadG2kQ6GJay27xqvi4j3eO+273/l6aLFHJXa2tB/ydkks4On1u5hmkOabkX
# +YXzNz0H47AILUhiAKp5OpmwxeVGTYUJQTHk9I6l5VG1EeyObF460Reqbr/q3Rrs
# 8jWRaNLXU2RCQ5aPlC3j8j6vikPWjT3kCus3+BwYhhjrWeB7UUpS5+LoXXpaCI/r
# wEMajjGlxSBaaBqXMu+NUt5D9sD1vJQF/SJsWYmexGJSXMo/nQziL+pDBktlq3cg
# XKAkLZDNAcgw4V4hrEFR8y+Id+pmyriIo2juFocrrQxN+TmUwKGCFykwghclBgor
# BgEEAYI3AwMBMYIXFTCCFxEGCSqGSIb3DQEHAqCCFwIwghb+AgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCDVp8Ze9ZVOXFPkNKrHov2DOJRQCVGjiaTX
# C0HeFhtyuwIGZGzvHZgWGBMyMDIzMDYwNjExNDQxNS42NDFaMASAAgH0oIHYpIHV
# MIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOjJBRDQtNEI5Mi1GQTAxMSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIReDCCBycwggUPoAMCAQICEzMAAAGxypBD
# 7gvwA6sAAQAAAbEwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwHhcNMjIwOTIwMjAyMTU5WhcNMjMxMjE0MjAyMTU5WjCB0jELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9z
# b2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjoyQUQ0LTRCOTItRkEwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIai
# qz7V7BvH7IOMPEeDM2UwCpM8LxAUPeJ7Uvu9q0RiDBdBgshC/SDre3/YJBqGpn27
# a7XWOMviiBUfMNff51NxKFoSX62Gpq36YLRZk2hN1wigrCO656z5pVTjJp3Q8jdY
# AJX3ruJea3ccfTgxAgT3Uv/sP4w0+yZAYa2JZalV3MBgIFi3VwKFA4ClQcr+V4Sp
# Gzqz8faqabmYypuJ35Zn8G/201pAN2jDEOu7QaDC0rGyDdwSTVmXcHM46EFV6N2F
# 69nwfj2DZh74gnA1DB7NFcZn+4v1kqQWn7AzBJ+lmOxvKrURlV/u19Mw1YP+zVQy
# zKn5/4r/vuYSRj/thZr+FmZAUtTAacLzouBENuaSBuOY1k330eMp8nndSNUsUjj/
# nn7gcdFqzdQNudJb+XxmRwi9LwjA0/8PlOsKTZ8Xw6EEWPVLfNojSuWpZMTaMzz/
# wzSPp5J02kpYmkdl50lwyGRLO5X7iWINKmoXySdQmRdiGMTkvRStXKxIoEm/EJxC
# aI+k4S3+BWKWC07EV5T3UG7wbFb4LfvgbbaKM58HytAyjDnO9fEi0vrp8JFTtGhd
# twhEEkraMtGVt+CvnG0ZlH4mvpPRPuJbqE509e6CqmHwzTuUZPFMFWvJn4fPv0d3
# 2Ws9jv2YYmE/0WR1fULs+TxxpWgn1z0PAOsxSZRPAgMBAAGjggFJMIIBRTAdBgNV
# HQ4EFgQU9Jtnke8NrYSK9fFnoVE0pr0OOZMwHwYDVR0jBBgwFoAUn6cVXQBeYl2D
# 9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1l
# LVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUB
# Af8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQAD
# ggIBANjnN5JqpeVShIrQIaAQnNVOv1cDEmCkD6oQufX9NGOX28Jw/gdkGtMJyagA
# 0lVbumwQla5LPhBm5LjIUW/5aYhzSlZ7lxeDykw57wp2AqoMAJm7bXcXtJt/HyaR
# lN35hAhBV+DmGnBIRcE5C2bSFFY3asD50KUSCPmKl/0NFadPeoNqbj5ZUna8VAfM
# SDsdxeyxjs8r/9Vpqy8lgIVBqRrXtFt6n1+GFpJ+2AjPspfPO7Y+Y/ozv5dTEYum
# 5eDLDdD1thQmHkW8s0BBDbIOT3d+dWdPETkf50fM/nALkMEdvYo2gyiJrOSG0a9Z
# 2S/6mbJBUrgrkgPp2HjLkycR4Nhwl67ehAhWxJGKD2gRk88T2KKXLiRHAoYTZVpH
# bgkYLspBLJs9C77ZkuxXuvIOGaId7EJCBOVRMJygtx8FXpoSu3jWEdau0WBMXxhV
# AzEHTu7UKW3Dw+KGgW7RRlhrt589SK8lrPSvPM6PPnqEFf6PUsTVO0bOkzKnC3TO
# gui4JhlWliigtEtg1SlPMxcdMuc9uYdWSe1/2YWmr9ZrV1RuvpSSKvJLSYDlOf6a
# JrpnX7YKLMRoyKdzTkcvXw1JZfikJeGJjfRs2cT2JIbiNEGK4i5srQbVCvgCvdYV
# EVZXVW1Iz/LJLK9XbIkMMjmECJEsa07oadKcO4ed9vY6YYBGMIIHcTCCBVmgAwIB
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
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtQwggI9AgEBMIIBAKGB2KSB1TCB
# 0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMk
# TWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjoyQUQ0LTRCOTItRkEwMTElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA7WSxvqQDbA7vyy69
# Tn0wP5BGxyuggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAN
# BgkqhkiG9w0BAQUFAAIFAOgpOREwIhgPMjAyMzA2MDYxMjQ4MTdaGA8yMDIzMDYw
# NzEyNDgxN1owdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA6Ck5EQIBADAHAgEAAgII
# 5DAHAgEAAgIRfjAKAgUA6CqKkQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEE
# AYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GB
# ADmhOzdmJq9dHw7abEDIu+0GB+wKouLKWS1Ocl7Z3RaYwwVKaaVvQGuCyxpDnofJ
# O+T7UAOgebAjkFG+GR5Wx08JV9ftdTTHdCkYPzhVIAegz8tRakLBe7zughYhPmA/
# 8FKJxBc4rFzfuF/yMt9jfLRlGiTHTce+G8sQTafWvX8SMYIEDTCCBAkCAQEwgZMw
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGxypBD7gvwA6sAAQAA
# AbEwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAvBgkqhkiG9w0BCQQxIgQg4fcaV+PiLNuGCZOVWyzQySZpfK+jShn3Oh5SQj+9
# 0pswgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCD7Q2LFFvfqeDoy9gpu35t
# 6dYerrDO0cMTlOIomzTPbDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABscqQQ+4L8AOrAAEAAAGxMCIEIHpdEv8OItnRQW3IDRC9wGsY
# FXVG7a1OGmwtijOyePZbMA0GCSqGSIb3DQEBCwUABIICAHwK0lGLvEKILb3/e8lg
# 6OlVX4tAgNezcJKVFxP6fx954hkVYcCxfH8NEFh8GrbxkGyn/05FT0XSVm7BbSqu
# LiSS2zLMOx90xsbbElVUBilHjocXuoGbbknOIjVlk+TYRwJbg7NyW+9yLxYrwAYp
# vzChgXs+cKhQHOIZ3MDPR56+orfibeDBm4RO88MOWcbLQ7PtAo+JwAeruEkF1FLr
# XF74NRle7nC2+YTEIfMSV90njKj67gnfcqhy0Abys5iHcZIqOmDtc61mNfcwgr0X
# swsqUgKFJ/Urb4ysDM8A2dssMIgjBBBi9SF3yPRdGCp57pd1eqJ0T82gKUrzXZYh
# Xy9PDM0WFYGMyPNEXogd1VQD38JM+5vSGvaxnwcPuysgD6zhxXXTWTkjwmhdChKp
# RYRcOeWSGxkkP5l8qEH3UPjEvLuEwtZPSVsil+Ld8Zi4VoOzyY6xJlTF1d7f4pAQ
# pFsrP2ubkLd/abJLCohDl+fq25vpDLgHQL8IiSP3tdP3lc3IRJ3F5gabtolW9GD8
# GoyaSq2VfHN6Tlha7m8ew5+sJo6OkokJFEUSPq6zIsRv9huLl3oqyaHJaf7H2SAi
# 7YtTciNFLi5Iqh5/FwX5CGfGJ23+6cmQPJmxECtUEYEHBfAnqqTalLllknK5p5mj
# utMrlXkZ4X7v7Lwiu7YBIGq3
# SIG # End signature block
