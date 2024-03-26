<#
.SYNOPSIS
	Biztalk Integration module for collecting traces

.DESCRIPTION
	Define ETW traces for Windows Biztalk Integration components 
	Add any custom tracing functinaliy for tracing Biztalk components
	For Developers:
	1. Component test: .\TSSv2.ps1 -Start -INT_TEST1
	2. Scenario test: .\TSSv2.ps1 -start -Scenario INT_MyScenarioTest

.NOTES
	Dev. Lead: niklase
	Authors	 : Niklas Engfelt <niklase@microsoft.com>
	Requires   : PowerShell V4 (Supported from Windows 8.1/Windows Server 2012 R2)
	Version    : see $global:TssVerDateINT

.LINK
	TSSv2 https://internal.support.services.microsoft.com/en-us/help/4619187
	INT https://internal.support.services.microsoft.com/en-us/help/1234567 -todo
#>

<# latest changes (reverse chronological order)
::	2023.02.22.0 [we] add INT_MSMQ component and scenario
#>

#region --- Define local INT Variables
$global:TssVerDateINT= "2023.02.23.0"

$BinArch = "\Bin" + $global:ProcArch
$global:TMQexePath = $global:ScriptFolder + $BinArch + "\TMQ.exe"
#endregion --- Define local INT Variables

#------------------------------------------------------------
#region --- ETW component trace Providers ---
#------------------------------------------------------------

#---  Dummy Providers ---# #for components without a tracing GUID
#$INT_PlatformProviders = @()
#$INT_DummyProviders = @(	#for components without a tracing GUID
#	'{eb004a05-9b1a-11d4-9123-0050047759bc}' # Dummy tcp for switches without tracing GUID (issue #70)
#)

#---  MSMQ Providers ---#
$INT_MSMQProviders = @(
	'{CE18AF71-5EFD-4F5A-9BD5-635E34632F69}' # Microsoft-Windows-MSMQ
	'{2787CC62-2654-4227-9B35-B53F838507AE}' # Microsoft-Windows-MSMQTriggers
	'{45033C79-EA31-4776-9BCD-94DB89AF3149}' # MSMQ: General
	'{322E0B22-0527-456E-A5EF-E5B591046A63}' # MSMQ: AC
	'{6E2C0612-BCF3-4028-8FF2-C60C288F1AF3}' # MSMQ: Networking
	'{DA1AF236-FAD6-4DA6-BD94-46395D8A3CF5}' # MSMQ: SRMP
	'{F8354C74-DE9F-48A5-8139-4ED1E9F20A1B}' # MSMQ: RPC
	'{5DC62C8C-BDF2-45A1-A06F-0C38CD5AF627}' # MSMQ: DS
	'{90E950BB-6ACE-4676-98E0-F6CDC1403670}' # MSMQ: Security
	'{8753D150-950B-4774-AC14-9C6CBFF56A50}' # MSMQ: Routing
	'{8FDA2BBD-347E-493C-B7D1-6B6FED88CE04}' # MSMQ: XACT_General
	'{485C37B0-9A15-4A2E-82E0-8E8C3A7B8234}' # MSMQ: XACT_Send
	'{7C916009-CF80-408B-9D91-9C2960118BE9}' # MSMQ: XACT_Receive
	'{1AC9B316-5B4E-4BBD-A2C9-1E70967A6FE1}' # MSMQ: XACT_Log
	'{A13EC7BB-D592-4B93-80DA-C783F9708BD4}' # MSMQ: Log
	'{71625F6D-559A-49C6-BA21-0AEB260DB97B}' # MSMQ: Profiling
	'{F707F440-AD58-47F8-93D3-BEA2F9E82FD2}' # MSMQ: ERRORLOGGING
)
#endregion --- ETW component trace Providers ---


#------------------------------------------------------------
#region --- Scenario definitions ---
#------------------------------------------------------------
$INT_General_ETWTracingSwitchesStatus = [Ordered]@{
	#'INT_Dummy' = $true
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

$INT_MSMQ_ETWTracingSwitchesStatus = [Ordered]@{
	'INT_MSMQ' = $true
	'CommonTask INT' = $True
#	'NetshScenario InternetClient_dbg' = $true
#	'Procmon' = $true
#	'WPR General' = $true
#	'PerfMon ALL' = $true
	'PSR' = $true
	'Video' = $true
#	'SDP Net' = $True
#	'noBasicLog' = $true
	'xray' = $True
	'CollectComponentLog' = $True
}
#endregion --- Scenario definitions ---

#region ### Pre-Start / Post-Stop / Collect functions for trace components and scenarios 
#------------------------------------------------------------
#--- Platform Trace ---#
function INT_MSMQPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	#noop
	EndFunc $MyInvocation.MyCommand.Name
}
function INT_MSMQPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	#noop
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectINT_MSMQLog{
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("MSMQ") _Stop_
	LogInfo "[$($MyInvocation.MyCommand.Name)] collecting MSMQInfo at $TssPhase"
	$outFile = $PrefixTime + "MSMQInfo" + $TssPhase + ".txt"
	$Commands = @(
		"Get-WindowsFeature | ? Name -match `"msmq`" | ft -AutoSize | Out-File -Append $outFile"
		"Get-WindowsOptionalFeature -Online | ? FeatureName -match `"msmq`" | select FeatureName,State | ft -AutoSize | Out-File -Append $outFile"
		"Get-WinSystemLocale | Out-File -Append $outFile"
		"Get-WinUserLanguageList | Out-File -Append $outFile"
		"(dir C:\windows\system32\mqqm.dll).VersionInfo | fl | Out-File -Append $outFile"
		"(dir C:\windows\system32\drivers\mqac.sys).VersionInfo | fl | Out-File -Append $outFile"
		"(Get-Acl 'HKLM:\Software\Microsoft\MSMQ').Access | fl | Out-File -Append $outFile"
		"(Get-Acl 'C:\Windows\System32\MSMQ').Access | fl | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False

	If($IsServerSKU){
		if (Get-WindowsFeature | Where-Object {($_.Name -eq "RSAT-AD-PowerShell") -and ($_.installed -eq $true)}){
			LogInfo "RSAT AD tools are installed" "Green"
			$fRSATinst=$True
		}else{ 
			LogWarn "[$($MyInvocation.MyCommand.Name)] RSAT AD tools are missing. 'RSAT-AD-PowerShell' module is not installed."
			LogInfo "Please run: Install-WindowsFeature RSAT-AD-PowerShell" "Cyan"
		}
	} else {
		If($OSBuild -ge 9200) {
			if (Get-WindowsOptionalFeature -Online | Where-Object {($_.Name -eq "RSAT-AD-PowerShell") -and ($_.installed -eq $true)}){
				LogInfo "RSAT AD tools are installed" "Green"
				$fRSATinst=$True
			}else{ 
				LogWarn "[$($MyInvocation.MyCommand.Name)] RSAT AD tools are missing."
				LogInfo "Please run:`
		Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
		Import-Module -Name ActiveDirectory" "Cyan"
			}
		}
	}
	If($fRSATinst -eq "True"){
		# Get local computer object
		$cnObj = Get-ADComputer -Identity $env:COMPUTERNAME
		$ou = $cnObj.DistinguishedName		  # $ou = (Get-ADComputer $env:COMPUTERNAME).DistinguishedName	# $ou = "CN=MYCOMPUTERxxxx,CN=Computers,DC=mydomain,DC=local"
		$outFile = $PrefixTime + "MSMQ.Computer.objects" + $TssPhase + ".txt"
		$Commands = @(
			"AD-object properties: $ou | Out-File -Append $outFile"
			"Get-ADObject -Identity $ou -Properties * | fl | Out-File -Append $outFile"
			"Get-ADObject -Identity `"CN=msmq,$ou`" -Properties * | fl | Out-File -Append $outFile"
			)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}
	FwGet-SummaryVbsLog
	getTMQinfo
	EndFunc $MyInvocation.MyCommand.Name
}
#endregion ### Pre-Start / Post-Stop / Collect functions for trace components and scenarios 

#region --- HelperFunctions ---
function INT_start_common_tasks {
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
	LogInfoFile "___ INT_start_common_tasks DONE"
	EndFunc $MyInvocation.MyCommand.Name
}
function INT_stop_common_tasks {
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
	LogInfoFile "___ INT_stop_common_tasks DONE"
	EndFunc $MyInvocation.MyCommand.Name
}

function getTMQinfo{
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	if (!$global:IsLiteMode){
		if (Test-Path $global:TMQexePath){
			LogInfo "[$($MyInvocation.MyCommand.Name)] collecting TMQ.exe info at $TssPhase"
			$ClusterServiceKey="HKLM:\SYSTEM\CurrentControlSet\Services\ClusDisk"
			if (Test-Path $ClusterServiceKey){
				#In case of clustered MSMQ, we need to know the MSMQ cluster name (perhaps as optional input -clustername {MSMQClusteredServiceName} ), or if more advanced get all clustered resources and check if of type MSMQ and then issue following commands per MSMQ resource found. 
				$MSMQClusteredServiceName = Read-Host -Prompt "Please enter the MSMQClusteredServiceName, or hit ENTER to skip this step"
				LogInfoFile "[MSMQClusteredServiceName: User provided answer:] $MSMQClusteredServiceName"
				If(!([String]::IsNullOrEmpty($MSMQClusteredServiceName))) {
					$Commands = @(
						"$global:TMQexePath  state -s $MSMQClusteredServiceName -v -f -r | Out-File $PrefixTime`TMQ-state-cluster.txt"
						"$global:TMQexePath  site -s $MSMQClusteredServiceName -v -d | Out-File -Append $PrefixTime`TMQ-site-cluster.txt"
						"$global:TMQexePath  store -d -v -s $MSMQClusteredServiceName | Out-File -Append $PrefixTime`TMQ-store-cluster.txt"
					)
				}
			}else{
				$outFile = $PrefixTime + "tmqstate" + $TssPhase + ".txt"
				$Commands = @(
					"$global:TMQexePath  state -d -v | Out-File -Append $outFile"
					"$global:TMQexePath  site -d -v | Out-File -Append $outFile"
					"$global:TMQexePath  store -d -v | Out-File -Append $outFile"
				)
			}
			if($Commands){RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False}
		}else{LogWarn "[$($MyInvocation.MyCommand.Name)] 'TMQ.exe' not found in PATH"}
	}else{ LogInfo "Skipping TMQ.exe info in Lite mode"}
	EndFunc $MyInvocation.MyCommand.Name
}
#endregion --- HelperFunctions ---

#region Registry Key modules for FwAddRegItem
	$global:KeysMSMQ = @("HKLM:Software\Microsoft\MSMQ")
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCcV7tI+s3H7nXn
# kWdistkSxkNSu+8rLFWDQ/zR1OK79KCCDYUwggYDMIID66ADAgECAhMzAAADTU6R
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOem
# TsO4Dl+f0hEQsZBG8eH5zyyf5UeksWMk/j6ivxVhMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAjM4IMfNLUfvWSMiWtKMdv9DHogvEbY2nTm9W
# Dm0L0MNIqMwrgCOUy8v58VQbwoPMDU6lfSKlqJ1CL3JQ3aQC1kxr3KYFNdTjMMeV
# 2q6MFpHQZpoIisNcs22hdeRCZRqVQlINObtb27Xtpkf1M5EcO5WBOYjH9rhrFjQD
# h8ou2Zsi4Pkc4M5qeF8ZzljNzKxvmEIMOGVjJLKw59Eg3GLILkEfct9LOBCdVk8W
# z35ih/2tyM6okEjVwwQnjd/U7m1988SUW6kytM5h2d0HPUdtLq3MUDcT1tAeOztU
# G2q5duappAkk4lgrwISjjOrrP5ik/+dr6LvFy0Ra8MxH2DRZMqGCFykwghclBgor
# BgEEAYI3AwMBMYIXFTCCFxEGCSqGSIb3DQEHAqCCFwIwghb+AgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCCk/PbKVTlUrvSl80SKzBa3FvoGqmT3Ahzr
# EdG7GkIJWgIGZGzyr5giGBMyMDIzMDYwNjExNDQxOS44NThaMASAAgH0oIHYpIHV
# MIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
# EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOkZDNDEtNEJENC1EMjIwMSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIReDCCBycwggUPoAMCAQICEzMAAAG59gAN
# ZVRPvAMAAQAAAbkwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwHhcNMjIwOTIwMjAyMjE3WhcNMjMxMjE0MjAyMjE3WjCB0jELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9z
# b2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjpGQzQxLTRCRDQtRDIyMDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAONJ
# Pslh9RbHyQECbUIINxMF5uQkyN07VIShITXubLpWnANgBCLvCcJl7o/2HHORnsRc
# mSINJ/qclAmLIrOjnYnrbocAnixiMEXC+a1sZ84qxYWtEVY7VYw0LCczY+86U/8s
# hgxqsaezKpWriPOcpV1Sh8SsOxf30yO7jvld/IBA3T6lHM2pT/HRjWk/r9uyx0Q4
# atx0mkLVYS9y55/oTlKLE00h792S+maadAdy3VgTweiwoEOXD785wv3h+fwH/wTQ
# tC9lhAxhMO4p+OP9888Wxkbl6BqRWXud54RTzqp2Vr+yen1Q1A6umyMB7Xq0snIY
# G5B1Acc4UgJlPQ/ZiMkqgxQNFCWQvz0G9oLgSPD8Ky0AkX22PcDOboPuNT4RceWP
# X0UVZUsX9IUgs7QF41HiQSwEeOOHGyrfQdmSslATrbmH/18M5QrsTM5JINjct9G4
# 2xqN8VF9Z8WOiGMjNbvlpcEmmysYl5QyhrEDoFnQTU7bFrD3JX0fIfu1sbLWeBqX
# wbp4Z8yACTtphK2VbzOvi4vc0RCmRNzvYQQ2PjZ7NaTXE4Gu3vggAJ+rtzUTAfJo
# tvOSqcMgNwLZa1Y+ET/lb0VyjrYwFuHtg0QWyQjP5350LTpv086pyVUh4A3w/Os5
# hTGFZgFe5bCyMnpY09M0yPdHaQ/56oYUsSIcyKyVAgMBAAGjggFJMIIBRTAdBgNV
# HQ4EFgQUt7A4cdtYQ5oJjE1ZqrSonp41RFIwHwYDVR0jBBgwFoAUn6cVXQBeYl2D
# 9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1l
# LVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUB
# Af8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQAD
# ggIBAM3cZ7NFUHRMsLKzjl7rJPIkv7oJ+s9kkut0hZif9WSt60SzYGULp1zmdPqc
# +w8eHTkhqX0GKCp2TTqSzBXBhwHOm8+p6hUxNlDewGMZUos952aTXblAT3OKBnfV
# BLQyUavrSjuJGZAW30cNY3rjVDUlGD+VygQHySaDaviJQbK6/6fQvUUFoqIk3ldG
# fjnAtnebsVlqh6WWamVc5AZdpWR1jSzN/oxKYqc1BG4SxxlPtcfrAdBz/cU4bxVX
# qAAf02NZscvJNpRnOALf5kVo2HupJXCsk9TzP5PNW2sTS3TmwhIQmPxr0E0UqOoj
# UrBJUOhbITAxcnSa/IMluL1HXRtLQZI+xs2eRtuPOUsKUW71/1YeqsYCLHLvu82c
# eDVQQvP7GHEEkp2kEjiofbjYErBo2iCEaxxeX4Z9HvAgA4MsQkbn6e4EFQf13sP+
# Kn3XgMIvJbqLJeFcQja+SUeOXu5cfkxe0GzTNojdyIwzaHlhOflVRZNrxee3B+yZ
# wd3JHDIvv71uSI/SIzzt9cU2GyHQVqxBSrRtKW6W8Vw7zpVvoVsIv3ljxg+7NiGS
# lXX1s7zbBNDMUj9OnzOlHK/3mrOU8YEuRf6RwakW5UCeGamy5MiKu2YuyKiGBCv4
# OGhPstNe7ALkEOh8BX12t4ntuYu+gw9L6yCPY0jWYaQtzAP9MIIHcTCCBVmgAwIB
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
# aGFsZXMgVFNTIEVTTjpGQzQxLTRCRDQtRDIyMDElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAx2IeGHhk58MQkzzS
# WknGcLjfgTqggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAN
# BgkqhkiG9w0BAQUFAAIFAOgpPGIwIhgPMjAyMzA2MDYxMzAyMjZaGA8yMDIzMDYw
# NzEzMDIyNlowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA6Ck8YgIBADAHAgEAAgIC
# JDAHAgEAAgISVDAKAgUA6CqN4gIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEE
# AYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GB
# AMKree/ijHEHZB2qMHdkyaekxx0PB6Reb/u36NIGhCYhfhJhEykfmfkoRvT2Vlnr
# fCqRWEA24gsCeMr4WL/PlsBUxSMekzadDorNsAiPlDk3ABW7EpI4A94ZgP8K3jRn
# tPw0WvJnhLfX2pROW+/vqgdbuOhpZZqNmW2bN4MG2IHcMYIEDTCCBAkCAQEwgZMw
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAG59gANZVRPvAMAAQAA
# AbkwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAvBgkqhkiG9w0BCQQxIgQg4JIv2pMy7xtstEXS7B0wwkA6bisBut5N/TleiMEx
# 4jYwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBk60bO8W85uTAfJVEO3vX2
# aLaQFcgcGpdwsOoi+foP9DCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABufYADWVUT7wDAAEAAAG5MCIEIIiUQFOD/DfPKzh2HUCNc6L4
# hy56TKlgS0d/vmUR/IOeMA0GCSqGSIb3DQEBCwUABIICABNTjO384GJtXVdMVIvR
# YCACOMa1TYN9UKD0zyyn4y8/WUgay2ztlgFrEoorMnoyhIbwQf3tvKPC3W1vgOUG
# D1OEXwcKgmj9Gyw5soMRiIATCBhf+dlQI4L4DKJysVfsOMwlQ/4pbD1aIi/Z34RX
# r0pZ40Ackcl3E6Sm0t8foSdTD7tSIWcnsFXXXBEtI89Ae5ZjPg8mXLoFeHqasPmG
# 7noBP920n5qiJluQMulbFR787QvZJqsGdZfbOzQrcdr3ZH4LyeivAbTqx39DmVn0
# wVJvieXi+H9ulM9jftXcPNlBdIShGx3SzY6vUqoTRaNC1SeJrFkugBorIkO78nTP
# bHPe7kJxZLrzYeAlUhlQzrfGkHiQJz03Ea8mDi8//3Dz5k0i5BlEbpllOHP+tpX/
# uN9NwuGbcd8HroyLdlWYHJjGa0Tga7A2bl0sjykahC714ctuvnDVi78bcMhOF+tF
# tbo4toMoL1XLROo7ihb+9lYFi9e02sssvZki2wFgVqB87RQV+QukIra3BO/3KrpD
# nuh+BhI2kY62jAO7pFpE8ByNq6dnUO/UoL7xWXpzY2uu0eAgXs4V1MrNROwgkmmE
# 1YyixUXXTY0rTU5a/h6PhaXg6P/gy2uboHu1v1IOkKEShG7zvUu537NAhFm+D+wJ
# Z6a38/5x/2DA1IVN7wyPXL+K
# SIG # End signature block
