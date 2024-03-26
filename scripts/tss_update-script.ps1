# Name: tss_update-script.ps1 for TSS (TSSv2)

<# 
.SYNOPSIS
	Script to [auto-]update TSS to latest version or download latest zip from CesdiagTools/GitHub.

.DESCRIPTION
	Script will search on "https://microsoft.githubenterprise.com/css-windows/WindowsCSSToolsDevRep/releases/tag" for latest TSS version
	If local version does not match the remote CesdiagTools/GitHub version, it will download and replace TSS with latest version
	Script gets the current version from $global:TssVerDate or by running ".\TSS -ver" and compares to version 'https://cesdiagtools.blob.core.windows.net/windows/TSSv2.ver'.

.PARAMETER tss_action
	choose action from allowed values: "Download" or "Update" or "Version"
		Download	= download latest CesdiagTools/GitHub version
		Update		= update current local version
		Version		= decide based on local version, try AutoUpdate if local version is lower than CesdiagTools/GitHub version
	Ex: -tss_action "Download"
	
.PARAMETER tss_file
	Specify filename from allowed values: "TSSv2.zip" , "TSSv2_ttd.zip" , "TSSv2_diff.zip" or "TSSv2Lite.zip"
	Ex: -tss_file "TSSv2.zip"
	
.PARAMETER TSS_path
	Specify the local path where TSS.ps1 is located.
	Ex: -TSS_path "C:\TSS"

.PARAMETER UpdMode
	Specify the mode: 
		Online  = complete package (TSSv2.zip) from aka.ms/getTSS
		Full    = complete package (TSSv2.zip) from CesdiagTools/GitHub
		Quick   = differential package only (TSSv2_diff.zip): replace only TSSv2.ps1, TSSv2_[POD].psm1 and config\tss_config.cfg files; will not update \BIN* folders
		Force   = run a Full update, regardless of current installed version

.PARAMETER tss_arch
	Specify the System Architecture.
	Allowed values:
		x64 - For 64-bit systems
		x86 - For 32-bit systems
	Ex: -tss_arch "x64"

.EXAMPLE
	.\tss_update-script.ps1 -tss_action "Update" -TSS_path "C:\TSSv2" -tss_file "TSSv2.zip"
	Example 1: Update TSSv2 in folder C:\TSSv2
	
.LINK
	https://microsoft.githubenterprise.com/css-windows/WindowsCSSToolsDevRep/releases/tag
	Public Download: TSSv2: https://cesdiagtools.blob.core.windows.net/windows/TSSv2.zip -or- https://aka.ms/getTSSv2 or aka.ms/getTSS
#>


param(
	[ValidateSet("download","update","version")]
	[Parameter(Mandatory=$False,Position=0,HelpMessage='Choose from: download|update|version')]
	[string]$tss_action 	= "download"
	,
	[string]$TSS_path 		= (Split-Path $MyInvocation.MyCommand.Path -Parent | Split-Path -Parent),
	[ValidateSet("Online","Full","Quick","Force","Lite")]
	[string]$UpdMode 		= "Online"
	,
	$verOnline
	,
	[ValidateSet("TSSv2.zip","TSSv2_diff.zip","TSSv2Lite.zip","TSSv2_ttd.zip")]
	[string]$tss_file 		= "TSSv2.zip"
	,
	[ValidateSet("x64","x86")]
	[string]$tss_arch 		= "x64",
	[string]$CentralStore	= "",								# updating from Central Enterprise Store
	[switch]$AutoUpd		= $False,							# 
	[switch]$UseExitCode 	= $true								# This will cause the script to bail out after the error is logged if an error occurs.
)

#region  ::::: [Variables] -----------------------------------------------------------#
$updScriptVersion	= "2022.05.22"
$UpdLogfile 		= $TSS_path + "\_tss_Update-Log.txt"
$script:ChkFailed	= $FALSE
$invocation 		= (Get-Variable MyInvocation).Value
$ScriptGrandParentPath 	= $MyInvocation.MyCommand.Path | Split-Path -Parent | Split-Path -Parent
$scriptName 		= $invocation.MyCommand.Name
if ($UpdMode -match 'Online') {
	$TssReleaseServer = "cesdiagtools.blob.core.windows.net"
	$tss_release_url  = "https://cesdiagtools.blob.core.windows.net/windows"
} else {
	$TssReleaseServer = "api.Github.com"
	$tss_release_url  = "https://api.github.com/repos/walter-1/TSSv2/releases"
}
$NumExecutable = (Get-ChildItem "$global:ScriptFolder\BIN\" -Name "*.exe" -ErrorAction Ignore).count 
If($NumExecutable -lt 20){
	$LiteMode=$True
}Else{
	$LiteMode=$False
}
#endregion  ::::: [Variables] --------------------------------------------------------#

$ScriptBeginTimeStamp = Get-Date

# Check if last "\" was provided in $TSS_path, if it was not, add it
if (-not $TSS_path.EndsWith("\")){
	$TSS_path = $TSS_path + "\"
}

#region  ::::: [Functions] -----------------------------------------------------------#
function ExitWithCode ($Ecode) {
	# set ErrorLevel to be picked up by invoking CMD script
	if ( $UseExitCode ) {
		Write-Verbose "[Update] Return Code: $Ecode"
		#error.clear()	# clear script errors
		exit $Ecode
		}
}

function get_local_tss_version {
	<#
	.SYNOPSIS
		Function returns current or LKG TSSv2 version locally from "$TSSv2_ps1_script -ver" command.
	#>
	param($type="current")
	switch ($type) {
        "current"  	{ $TSSv2_ps1_script = "TSSv2.ps1" }
        "LKG" 		{ $TSSv2_ps1_script = "TSSv2-LKG.ps1" }
	}
	if ( -not (Test-Path $TSSv2_ps1_script)) {
		$TSSv2_ps1_script = "TSSv2.ps1"
	}  
	Get-Content ..\$TSSv2_ps1_script | Where-Object {$_ -match 'global:TssVerDate ='} | ForEach-Object { $v2version=($_ -Split '\s+')[3] }
	$TSSv2version = $v2version.Replace("""","")
	Write-verbose "[get_local_tss_version] TSSv2version= $TSSv2version"
	return [version]$TSSv2version
}

function get_latest_tss_version {
	<#
	.SYNOPSIS
		Function will get latest version from CesdiagTools/GitHub Release page
	.LINK
		https://github.com/walter-1/TSSv2/releases
		https://cesdiagtools.blob.core.windows.net/windows/TSSv2.zip
	#>
	EnterFunc ($MyInvocation.MyCommand.Name + "(URL: $RFL_release_url)" )
	if ($UpdMode -match 'Online') {
		return $verOnline # = TSSv2.ver
	} else {
		# GitHub: Get web content and convert from JSON
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		try { $web_content = Invoke-WebRequest -Uri $tss_release_url -UseBasicParsing | ConvertFrom-Json } catch { "`n*** Failure during TSSv2 update. Exception Message:`n $($_.Exception.Message)" | Out-File $UpdLogfile -Append }
		if ($web_content.tag_name) {
			[version]$expected_latest_tss_version = $web_content.tag_name.replace("v","")
			write-verbose "$UpdateSource Version of '$tss_release_url': --> $expected_latest_tss_version"
			return $expected_latest_tss_version
		}
		else 
		{ Write-Host -ForegroundColor Red "[ERROR] cannot securely access $TssReleaseServer. Please download https://aka.ms/getTSS"
			"`n $ScriptBeginTimeStamp [ERROR] cannot securely access $TssReleaseServer. Please download https://aka.ms/getTSS" | Out-File $UpdLogfile -Append
			$script:ChkFailed=$TRUE
			return 2022.0.0.0
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function DownloadFileFromGitHubRelease {
	param(
		$action = "download", 
		$file, 
		$installedTSSver)
	# Download latest TSSv2 release from CesdiagTools/GitHub
	$repo = "walter-1/TSSv2"
	$releases = "https://api.github.com/repos/$repo/releases"
	#Determining latest release , Set TLS to 1.2
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	$tag = (Invoke-WebRequest $releases -UseBasicParsing | ConvertFrom-Json)[0].tag_name
	$downloadURL = "https://github.com/$repo/releases/download/$tag/$file"
	Write-Verbose "downloadURL: $downloadURL"
	$name = $file.Split(".")[0]
	$zip = "$name-$tag.zip"
	$TmpDir = "$name-$tag"
	Write-Verbose "Name: $name - Zip: $zip - Dir: $TmpDir - Tag/version: $tag"
	
	#_# faster Start-BitsTransfer $downloadURL -Destination $zip # is not allowed for GitHub
	Write-Host ".. Secure download of latest release: $downloadURL"
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Invoke-WebRequest $downloadURL -OutFile $zip

	if ($action -match "download") {
		Write-Host -ForegroundColor Green "[Info] Downloaded version to folder: $TSS_path`scripts\$tss_file"
		}
	if ($action -match "update") {
		#save current script and expand
		Write-Host "... saving a copy of current installed TSSv2.ps1 to $($TSS_path + "TSSv2.ps1_v" + $installedTSSver)"
		Copy-Item ($TSS_path + "TSSv2.ps1") ($TSS_path + "TSSv2.ps1_v" + $installedTSSver) -Force -ErrorAction SilentlyContinue
		Write-Host "... saving a copy of current \config\tss_config.cfg to $($TSS_path + "config\tss_config.cfg_backup")"
		Copy-Item ($TSS_path + "config\tss_config.cfg") ($TSS_path + "config\tss_config.cfg_backup") -Force -ErrorAction SilentlyContinue
		Write-Host "[Expand-Archive] Extracting release files from $zip"
		Expand-Archive  -Path $zip -DestinationPath $ENV:temp\$TmpDir -Force
		Write-Host ".. Cleaning up .."
		Write-Verbose "Cleaning up target dir: Remove-Item $name -Recurse"
		Write-Verbose "Copying from temp dir: $ENV:temp\$TmpDir to target dir: $TSS_path"
		Copy-Item $ENV:temp\$TmpDir\* -Destination $TSS_path -Recurse -Force
		Write-Verbose "Removing temp file: $zip and folder $TmpDir"
		Remove-Item $zip -Force
		Write-Verbose "Remove-Item $ENV:temp\$TmpDir -Recurse"
		Remove-Item $ENV:temp\$TmpDir -Recurse -Force -ErrorAction SilentlyContinue
		Write-Host -ForegroundColor Gray "[Info] Updated with latest TSSv2 version $script:expected_latest_tss_version"
	}
}

function DownloadTssZipFromCesdiagRelease {
	param(
		$file	# TSSv2.zip or TSSv2Lite.zip
	)
	switch ($file) {
        "TSSv2.zip"  	{ $downloadURL = $tss_release_url + "/TSSv2.zip" }
        "TSSv2Lite.zip" { $downloadURL = $tss_release_url + "/TSSv2Lite.zip"  }
	}
	
	# faster Start-BitsTransfer
	Write-Host ".. Secure download of latest release: $downloadURL"
	Start-BitsTransfer $downloadURL -Destination "$ENV:temp\TSSv2_download.zip"
	#save current script and expand
	Write-Host "... saving a copy of current installed TSSv2.ps1 to $($TSS_path + "TSSv2.ps1_v" + $installedTSSver)"
	Copy-Item ($TSS_path + "TSSv2.ps1") ($TSS_path + "TSSv2.ps1_v" + $installedTSSver) -Force -ErrorAction SilentlyContinue
	Write-Host "... saving a copy of current \config\tss_config.cfg to $($TSS_path + "config\tss_config.cfg_backup")"
	Copy-Item ($TSS_path + "config\tss_config.cfg") ($TSS_path + "config\tss_config.cfg_backup") -Force -ErrorAction SilentlyContinue
	Write-Host "[Expand-Archive] Extracting release files from $ENV:temp\TSSv2_download.zip"
	expand-archive -LiteralPath "$ENV:temp\TSSv2_download.zip" -DestinationPath $TSS_path -force
	#ToDo
}
#endregion  ::::: [Functions] --------------------------------------------------------#


#region  ::::: [MAIN] ----------------------------------------------------------------#
# detect OS version and SKU # Note: gwmi / Get-WmiObject is no more supportd in PS v7 -> use Get-CimInstance
If($Host.Version.Major -ge 7){
	[Reflection.Assembly]::LoadWithPartialName("System.ServiceProcess.servicecontroller") | Out-Null
	$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
} else {$wmiOSVersion = Get-WmiObject -Namespace "root\cimv2" -Class Win32_OperatingSystem}
[int]$bn = [int]$wmiOSVersion.BuildNumber
#Write-verbose "installed-version: $(get_local_tss_version current) - Build: $bn"
$installedTSSver = New-Object System.Version([version]$(get_local_tss_version "current"))
Write-verbose "installedTSSver: $installedTSSver"

## :: Criteria to use Quick vs. Online update: Quick if UpdMode = Quick; Online = if updates in xray or psSDP are needed, ...
# Choose download file based on $UpdMode (and current installed TSSv2 build)
If($LiteMode) {$tss_file = "TSSv2Lite.zip"} else {$tss_file = "TSSv2.zip" }
switch ($UpdMode) {
        "Quick"	{ 	$tss_file = "TSSv2_diff.zip"
					$UpdateSource= "GitHub"}
        "Lite"	{ 	$tss_file = "TSSv2Lite.zip"
					$UpdateSource= "GitHub"}
		"Online"{ 	#$tss_file = "TSSv2.zip"
					$UpdateSource= "CesdiagTools"}
#		"Force" { 	$tss_file = "TSSv2.zip" }	# always perform a Full update
        default	{ 	$tss_file = "TSSv2.zip"
					$UpdateSource= "CesdiagTools"}
}
		
# Check for Internet connectivity // Test-NetConnection does not work for Win7
$checkConn = FwTestConnWebSite $TssReleaseServer -ErrorAction SilentlyContinue
if ( $checkConn -eq "True") {
	# Determine which edition we need, ? based on existence of .\x64\TTTracer.exe # + ToDo Lite based on existence/number of *.exe in \BIN folder
	if ($UpdMode -Notmatch "Online") {
		$script:expectedVersion = New-Object System.Version(get_latest_tss_version)
	}
	if ("$($script:expectedVersion)" -eq "0.0") { Write-Verbose "Bail out: $script:expectedVersion"; ExitWithCode 20}
	# Check if TSSv2 exists in $TSS_path
	if (-not (Test-Path ($TSS_path + "TSSv2.ps1"))){
		Write-Host -ForegroundColor Red "[Warning] TSSv2.ps1 could not be located in $TSS_path"
		DownloadFileFromGitHubRelease "update" $tss_file $installedTSSver
	}

	if (Test-Path ($TSS_path + "TSSv2.ps1")){
		if ($UpdMode -match "Online") {
			DownloadTssZipFromCesdiagRelease -File "TSSv2.zip"
		}
		elseif ($UpdMode -match "Force") {	# update regardless of current local version
		Write-Host -ForegroundColor Cyan "[Forced update:] to latest version $script:expectedVersion from $UpdateSource`n"
		 if (Test-Path ($TSS_path + "x64\TTTracer.exe")) { Write-Host -ForegroundColor Yellow "[note:] This procedure will not refresh iDNA part"}
									DownloadFileFromGitHubRelease "update" $tss_file $installedTSSver
		} else {
			Write-Host "[Info] checking current version $installedTSSver in $TSS_path against latest released $UpdateSource version $script:expectedVersion."
			if ($($installedTSSver.CompareTo($script:expectedVersion)) -eq 0) { 		# If versions match, display message
				"`n [Info] Latest TSSv2 version $script:expectedVersion is installed. " | Out-File $UpdLogfile -Append
				Write-Host -ForegroundColor Cyan "[Info] Latest TSSv2 version $script:expectedVersion is installed.`n"}
			elseif ($($installedTSSver.CompareTo($script:expectedVersion)) -lt 0) {	# if installed current version is lower than latest $UpdateSource Release version
				"`n [Action: $tss_action -[Warning] Actually installed TSSv2 version $installedTSSver is outdated] " | Out-File $UpdLogfile -Append
				Write-Host -ForegroundColor red "[Warning] Actually installed TSSv2 version $installedTSSver is outdated"
				Write-Host "[Info] Expected latest TSSv2 version on $($UpdateSource) = $script:expectedVersion"
				Write-Host -ForegroundColor yellow "[Warning] ** Update will overwrite customized configuration, latest \config\tss_config.cfg is preserved in \config\tss_config.cfg_backup. ** "
				switch($tss_action)
					{
					"download"		{ 	Write-Host "[download:] latest $tss_file"
										DownloadFileFromGitHubRelease "download" $tss_file $installedTSSver
									}
					"update"		{ 	Write-Host "[update:] to latest version $script:expectedVersion from $UpdateSource " 
										 if (Test-Path ($TSS_path + "x64\TTTracer.exe")) { Write-Host -ForegroundColor Yellow "[note:] This procedure will not refresh iDNA/TTD part"}
										DownloadFileFromGitHubRelease "update" $tss_file $installedTSSver
									}
					"version"		{ 	Write-Host -background darkRed "[version:] installed TSSv2 version is outdated, please run 'TSS Update', trying AutoUpate" # or answer next question with 'Yes'"
										Write-Host -ForegroundColor Cyan "[Info] running AutoUpdate now... (to avoid updates, append TSSv2 switch 'noUpdate')"
										DownloadFileFromGitHubRelease "update" $tss_file $installedTSSver
									}
					}
					"`n [Action: $tss_action - OK] " | Out-File $UpdLogfile -Append
			}
			else {	# if installed current version is greater than latest CesdiagTools/GitHub Release version
				if ($script:ChkFailed) {Write-Host -ForegroundColor Gray "[Info] Version check failed! Expected version on $($UpdateSource) = $script:expectedVersion. Please download https://aka.ms/getTSS `n"}
				Write-Verbose "Match: Current installed TSSv2 version:  $installedTSSver"
				Write-Verbose "Expected latest TSSv2 version on $($UpdateSource) = $script:expectedVersion"
			}
		}
	}
} else {
	Write-Host -ForegroundColor Red "[failed update] Missing secure internet connection to $TssReleaseServer. Please download https://aka.ms/getTSS `n"
							"`n [failed update] Missing secure internet connection to $TssReleaseServer. Please download https://aka.ms/getTSS `n" | Out-File $UpdLogfile -Append
}

$ScriptEndTimeStamp = Get-Date
$Duration = $(New-TimeSpan -Start $ScriptBeginTimeStamp -End $ScriptEndTimeStamp)

Write-Host -ForegroundColor Black -background gray "[Info] Script $scriptName v$updScriptVersion execution finished. Duration: $Duration"
if ($AutoUpd) { Write-Host -ForegroundColor Yellow  "[AutoUpdate done] .. Please repeat your TSSv2 command now."}
#endregion  ::::: [MAIN] -------------------------------------------------------------#

#region  ::::: [ToDo] ----------------------------------------------------------------#
<# 
 ToDo: 
 - save any CX changed file like \config\tss_config.cfg into a [backup_v...] subfolder with prev. version, --> easy restoration, if there is no schema change
	see "...saving a copy of installed TSSv2.ps1  ..."
 - allow TSSv2 to update from CX Central Enterprise store \\server\share\tss defined in \config\tss_config.cfg, if update from CesdiagTools/GitHub fails
 
- Implement a scheduled task for periodic update check
Example one-line command: schtasks.exe /Create /SC DAILY /MO 1 /TN "tss Updater" /TR "powershell \path\to\script\get-latest-tss.ps1 -TSS_path 'path\to\where\tss\is' -tss_arch 'x64'" /ST 12:00 /F
	[/SC DAILY]: Run daily
	[/MO 1]: Every Day
	[/TN "tss Updater"]: Task Name
	[/TR "powershell \path\to\script\get-latest-tss.ps1 -TSS_path 'path\to\where\tss\is' -tss_arch 'x64'"]: Command to run
	[/ST 12:00]: Run at 12 PM
	[/F]: Force update
#>
#endregion  ::::: [ToDo] ----------------------------------------------------------------#


# SIG # Begin signature block
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDyW/a+zMf4KVrc
# DsSfw7eCcjz4qb6vi5nOxVfMBwbrJaCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
# esGEb+srAAAAAANOMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI5WhcNMjQwMzE0MTg0MzI5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDdCKiNI6IBFWuvJUmf6WdOJqZmIwYs5G7AJD5UbcL6tsC+EBPDbr36pFGo1bsU
# p53nRyFYnncoMg8FK0d8jLlw0lgexDDr7gicf2zOBFWqfv/nSLwzJFNP5W03DF/1
# 1oZ12rSFqGlm+O46cRjTDFBpMRCZZGddZlRBjivby0eI1VgTD1TvAdfBYQe82fhm
# WQkYR/lWmAK+vW/1+bO7jHaxXTNCxLIBW07F8PBjUcwFxxyfbe2mHB4h1L4U0Ofa
# +HX/aREQ7SqYZz59sXM2ySOfvYyIjnqSO80NGBaz5DvzIG88J0+BNhOu2jl6Dfcq
# jYQs1H/PMSQIK6E7lXDXSpXzAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnMc7Zn/ukKBsBiWkwdNfsN5pdwAw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMDUxNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAD21v9pHoLdBSNlFAjmk
# mx4XxOZAPsVxxXbDyQv1+kGDe9XpgBnT1lXnx7JDpFMKBwAyIwdInmvhK9pGBa31
# TyeL3p7R2s0L8SABPPRJHAEk4NHpBXxHjm4TKjezAbSqqbgsy10Y7KApy+9UrKa2
# kGmsuASsk95PVm5vem7OmTs42vm0BJUU+JPQLg8Y/sdj3TtSfLYYZAaJwTAIgi7d
# hzn5hatLo7Dhz+4T+MrFd+6LUa2U3zr97QwzDthx+RP9/RZnur4inzSQsG5DCVIM
# pA1l2NWEA3KAca0tI2l6hQNYsaKL1kefdfHCrPxEry8onJjyGGv9YKoLv6AOO7Oh
# JEmbQlz/xksYG2N/JSOJ+QqYpGTEuYFYVWain7He6jgb41JbpOGKDdE/b+V2q/gX
# UgFe2gdwTpCDsvh8SMRoq1/BNXcr7iTAU38Vgr83iVtPYmFhZOVM0ULp/kKTVoir
# IpP2KCxT4OekOctt8grYnhJ16QMjmMv5o53hjNFXOxigkQWYzUO+6w50g0FAeFa8
# 5ugCCB6lXEk21FFB1FdIHpjSQf+LP/W2OV/HfhC3uTPgKbRtXo83TZYEudooyZ/A
# Vu08sibZ3MkGOJORLERNwKm2G7oqdOv4Qj8Z0JrGgMzj46NFKAxkLSpE5oHQYP1H
# tPx1lPfD7iNSbJsP6LiUHXH1MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXMwghlvAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPPEgckeEAG+fFqMY64mUA7w
# 3htQWx3hfPcQjRa28WjqMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAChINUzF0yDfP8Ofp1s6jFRDw/fvoKqwkKVWUGEVT01UPYyf8v3ztrCSa
# nnLpF7+bcK/IxOkXTiLFpQjnfVWtEHsIwGV5mvmdLfzHgAlt0TvAQrl3qQAGHGvj
# Lu7tRSR2tsm6ZB8WaZEmDxXU864Yxn0SlxFp93UhLOh13PRStAB7ceIYVLr8U/0R
# pM4po34yqZJ5GSJ9SmNgOAikIHkxwl5DqG+QKyMs2lwW7mv3zvyRQcSuPZJvSE2m
# Fb6s7AvzQ+GulWedoOTVEEBC5taBNk7FfYYAMf4etvlFV7bHMSdF2QlAH+uUuM9H
# YbeYH6gZAuJGgPTy5eI6gzpNy7FG5KGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCC
# FuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCJtqfzeoFf2LoqXmUAAUABgot8bOWd5itKi8TkL3mqmQIGZGzVO19d
# GBMyMDIzMDYwNjExNDU1MC44NjRaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo3QkYxLUUz
# RUEtQjgwODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVQwggcMMIIE9KADAgECAhMzAAAByPmw7mft6mtGAAEAAAHIMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEz
# N1oXDTI0MDIwMjE5MDEzN1owgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjdCRjEtRTNFQS1CODA4MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAucudfihPgyRWwnnIuJCqc3TCtFk0XOimFcKjU9bS6WFn
# g2l+FrIid0mPZ7KWs6Ewj21X+ZkGkM6x+ozHlmNtnHSQ48pjIFdlKXIoh7fSo41A
# 4n0tQIlwhs8uIYIocp72xwDBHKSZxGaEa/0707iyOw+aXZXNcTxgNiREASb9thlL
# ZM75mfJIgBVvUmdLZc+XOUYwz/8ul7IEztPNH4cn8Cn0tJhIFfp2netr8GYNoiyI
# qxueG7+sSt2xXl7/igc5cHPZnWhfl9PaB4+SutrA8zAhzVHTnj4RffxA4R3k4BRb
# PdGowQfOf95ZeYxLTHf5awB0nqZxOY+yuGWhf6hp5RGRouc9beVZv98M1erYa55S
# 1ahZgGDQJycVtEy82RlmKfTYY2uNmlPLWtnD7sDlpVkhYQGKuTWnuwQKq9ZTSE+0
# V2cH8JaWBYJQMIuWWM83vLPo3IT/S/5jT2oZOS9nsJgwwCwRUtYtwtq8/PJtvt1V
# 6VoG4Wd2/MAifgEJOkHF7ARPqI9Xv28+riqJZ5mjLGz84dP2ryoe0lxYSz3PT5Er
# KoS0+zJpYNAcxbv2UXiTk3Wj/mZ3tulz6z4XnSl5gy0PLer+EVjz4G96GcZgK2d9
# G+uYylHWwBneIv9YFQj6yMdW/4sEpkEbrpiJNemcxUCmBipZ7Sc35rv4utkJ4/UC
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBS1XC9JgbrSwLDTiJJT4iK7NUvk9TAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQDD1nJSyEPDqSgnfkFifIbteJb7NkZCbRj5yBGiT1f9fTGvUb5CW7k3eSp3uxUq
# om9LWykcNfQa/Yfw0libEim9YRjUNcL42oIFqtp/7rl9gg61oiB8PB+6vLEmjXkY
# xUUR8WjKKC5Q5dx96B21faSco2MOmvjYxGUR7An+4529lQPPLqbEKRjcNQb+p+mk
# QH2XeMbsh5EQCkTuYAimFTgnui2ZPFLEuBpxBK5z2HnKneHUJ9i4pcKWdCqF1AOV
# N8gXIH0R0FflMcCg5TW8v90Vwx/mP3aE2Ige1uE8M9YNBn5776PxmA16Z+c2s+hY
# I+9sJZhhRA8aSYacrlLz7aU/56OvEYRERQZttuAFkrV+M/J+tCeGNv0Gd75Y4lKL
# Mp5/0xoOviPBdB2rD5C/U+B8qt1bBqQLVZ1wHRy0/6HhJxbOi2IgGJaOCYLGX2zz
# 0VAT6mZ2BTWrJmcK6SDv7rX7psgC+Cf1t0R1aWCkCHJtpYuyKjf7UodRazevOf6V
# 01XkrARHKrI7bQoHFL+sun2liJCBjN51mDWoEgUCEvwB3l+RFYAL0aIisc5cTaGX
# /T8F+iAbz+j2GGVum85gEQS9uLzSedoYPyEXxTblwewGdAxqIZaKozRBow49OnL+
# 5CgooVMf3ZSqpxc2QC0E03l6c/vChkYyqMXq7Lwd4PnHqjCCB3EwggVZoAMCAQIC
# EzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoX
# DTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC
# 0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VG
# Iwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP
# 2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/P
# XfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361
# VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwB
# Sru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9
# X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269e
# wvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDw
# wvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr
# 9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+e
# FnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAj
# BgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+n
# FV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBH
# hkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
# BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4Swf
# ZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTC
# j/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu
# 2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/
# GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3D
# YXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbO
# xnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqO
# Cb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I
# 6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0
# zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaM
# mdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNT
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLLMIICNAIBATCB+KGB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046N0JGMS1FM0VBLUI4MDgxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAN/OE1C7xjU0ClIDXQBiucAY7suyoIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoKR78MCIYDzIwMjMwNjA2MTA1NzAwWhgPMjAyMzA2MDcxMDU3MDBaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOgpHvwCAQAwBwIBAAICJrEwBwIBAAICEW4w
# CgIFAOgqcHwCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQBagqAwDqo3JECP
# 1EZQbP5BZJWdFg4XRT3jXH9woEPG5iRdyEeqovan/XMAb5CoRVUPwyWTfqfqf2iC
# D4QzPJPNMmjNOLANInONImuJvXA7CioFXeDO0k1QsuZazbMLXvGXq5qYFFaPJMfw
# 8Uw0BrlqiCYorIaMRvK5vbI3JCsvVDGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAByPmw7mft6mtGAAEAAAHIMA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIBC2W4fg54ak2/JghqQ0PHdPYZAvZv8D2q24vPUnBt7qMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQgYgCYz80/baMvxw6jcqSvL0FW4TdvA09nxHfs
# PhuEA2YwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# Acj5sO5n7eprRgABAAAByDAiBCB4oOXWdN298RrWHfuEENvkCjSxUg/ZtmMChlYp
# Y6wB6TANBgkqhkiG9w0BAQsFAASCAgBk3Wy2hYrvQMdh9RAIDFfK7s3bojDlKZsW
# +f8YfRP+AdlX2vOQ53vpcSnIBg348Gge2ehy6wC0kjFxruxL6TmDuJGRojcVIW9g
# lo4r2Cp35CRPzVUJDR5/oOD+D4Zzm0qli4JxdtKZ440kV6vHsY6Onxbx9vtAIHWH
# 9MZZ9TFo0s/avDiIGuQaVNzplHAVrPfItOsaaaTgLL+pumbgOY5EV4MlP9ycoThx
# nH887BurDqqyO/EJNhDdd01RzJRN7g5BBwp+TVnOPMYpFJVguYvs4Jcl0a74JN5l
# TwUi7vRLOzTlBhSXbXOnjiAP22MzN7KF7BSYjWIGIjZNbHxEkZTcHvkcVz5hfGu8
# 3gpW8ClT4TgQjkTsCzTKpCepwlPQ6s11gDa8IwzYHdZRwHR5GKMObYMsqpKrU4bJ
# Mbo85sOjcwmQwVxzg8SyIWaWF/CJxymMm2iQCBHhpiCGwZ9USXjR1dT5g9H3xNoi
# XJSzqt0Srr7UJTYinFXMNjo5NKV8qUBKwtrT7TdbIolpRG2zUtLcfpb66Z7OgbUV
# 5mKhx4PukyQ/jTm8rvW0ruPD8U7P/yZMWRLyLbPJhkXKJkxIC63HuITD7yaBjYID
# yzDyQOCeEgD0O46W5ipw0XBWYs80qawWtOg27Lh4aKh5KRsz8V8MuRA4poHUQnjb
# DY0x3b+I/g==
# SIG # End signature block
