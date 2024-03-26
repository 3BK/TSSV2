trap [Exception]
{
	WriteTo-ErrorDebugReport -ErrorRecord $_
	continue
}

If (!$Is_SiteServer) {
	TraceOut "ConfigMgr Site Server not detected. This script gathers data only from a Site Server. Exiting."
	exit 0
}

TraceOut "Started"

Import-LocalizedData -BindingVariable ScriptStrings
$sectiondescription = "Configuration Manager Server Information"

# ----------------
# Write Progress
# ----------------
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CM07ServerInfo -Status $ScriptStrings.ID_SCCM_CM07ServerInfo_ServerInfo
TraceOut "    Getting Server Information"

# ----------------------
# Current Time:
# ----------------------
AddTo-CMServerSummary -Name "Current Time" -Value $CurrentTime

# -------------
# Computer Name
# -------------
AddTo-CMServerSummary -Name "Server Name" -Value $ComputerName

# ----------
# Site Code
# ----------
$Temp = Get-RegValueWithError ($Reg_SMS + "\Identification") "Site Code"
AddTo-CMServerSummary -Name "Site Code" -Value $Temp

# ----------
# Site Code
# ----------
$Temp = Get-RegValueWithError ($Reg_SMS + "\Identification") "Parent Site Code"
AddTo-CMServerSummary -Name "Parent Site Code" -Value $Temp

# ----------
# Site Type
# ----------
# $SiteType = Get-RegValueWithError ($Reg_SMS + "\Setup") "Type"
If ($SiteType -eq 8) {
	AddTo-CMServerSummary -Name "Site Type" -Value "Central Administration Site" }
ElseIf ($SiteType -eq 1) {
	AddTo-CMServerSummary -Name "Site Type" -Value "Primary Site" }
ElseIf ($SiteType -eq 2) {
	AddTo-CMServerSummary -Name "Site Type" -Value "Secondary Site" }
else {
	AddTo-CMServerSummary -Name "Site Type" -Value $SiteType
}

# -------------
# Site Version
# -------------
$Temp = Get-RegValueWithError ($Reg_SMS + "\Setup") "Full Version"
AddTo-CMServerSummary -Name "Site Version" -Value $Temp

# ----------------
# Monthly Version
# ----------------
if ($global:SiteType -eq 2) {
	AddTo-CMServerSummary -Name "MonthlyReleaseVersion" -Value "Not Available on a Secondary Site"
}
else {
	$Temp = Get-CimInstance -Computer $SMSProviderServer -Namespace $SMSProviderNamespace -Class SMS_Identification -ErrorAction SilentlyContinue
	If ($Temp -is [WMI]) {
		AddTo-CMServerSummary -Name "MonthlyReleaseVersion" -Value $Temp.MonthlyReleaseVersion }
	else {
		AddTo-CMServerSummary -Name "MonthlyReleaseVersion" -Value "Not Available" }
}

# -------------
# CU Level
# -------------
$Temp = Get-RegValueWithError ($Reg_SMS + "\Setup") "CULevel"
AddTo-CMServerSummary -Name "CU Level" -Value $Temp

# -------------
# ADK Version
# -------------
$global:ADKVersion = Get-ADKVersion
AddTo-CMServerSummary -Name "ADK Version" -Value $global:ADKVersion

# ----------------------------------------------------------
# Installation Directory - defined in utils_ConfigMgr12.ps1
# ----------------------------------------------------------
If ($null -ne $SMSInstallDir) {
	AddTo-CMServerSummary -Name "Installation Directory" -Value $SMSInstallDir }
else {
	AddTo-CMServerSummary -Name "Installation Directory" -Value "Error obtaining value from Registry" }

# -----------------
# Provider Location
# -----------------
if ($global:SiteType -eq 2) {
	AddTo-CMServerSummary -Name "Provider Location" -Value "Not available on a Secondary Site"
}
else {
	If ($null -ne $global:SMSProviderServer) {
		AddTo-CMServerSummary -Name "Provider Location" -Value $SMSProviderServer }
	else {
		AddTo-CMServerSummary -Name "Provider Location" -Value "Error obtaining value from Registry" }
}

# -----------
# SQL Server
# -----------
$Temp = Get-RegValue ($Reg_SMS + "\SQL Server\Site System SQL Account") "Server"
AddTo-CMDatabaseSummary -Name "SQL Server" -Value $Temp -NoToSummaryQueries

# --------------
# Database Name
# --------------
$Temp = Get-RegValueWithError ($Reg_SMS + "\SQL Server\Site System SQL Account") "Database Name"
AddTo-CMDatabaseSummary -Name "Database Name" -Value $Temp -NoToSummaryQueries

# ----------------
# SQL Ports
# ----------------
$Temp = Get-RegValueWithError ($Reg_SMS + "\SQL Server\Site System SQL Account") "Port"
AddTo-CMDatabaseSummary -Name "SQL Port" -Value $Temp -NoToSummaryQueries

$Temp = Get-RegValueWithError ($Reg_SMS + "\SQL Server\Site System SQL Account") "SSBPort"
AddTo-CMDatabaseSummary -Name "SSB Port" -Value $Temp -NoToSummaryQueries

# -----------------------
# SMSExec Service Status
# -----------------------
$Temp = Get-Service | Where-Object {$_.Name -eq 'SMS_Executive'} | Select-Object Status
If ($null -ne $Temp) {
	if ($Temp.Status -eq 'Running') {
		$Temp2 = Get-Process | Where-Object {$_.ProcessName -eq 'SMSExec'} | Select-Object StartTime
		AddTo-CMServerSummary -Name "SMS_Executive Status" -Value "Running. StartTime = $($Temp2.StartTime)"
	}
	else {
		AddTo-CMServerSummary -Name "SMS_Executive Status" -Value $Temp.Status
	}
}
Else {
	AddTo-CMServerSummary -Name "SMS_Executive Status" -Value "ERROR: Service Not found"
}

# -----------------------
# SiteComp Service Status
# -----------------------
$Temp = Get-Service | Where-Object {$_.Name -eq 'SMS_SITE_COMPONENT_MANAGER'} | Select-Object Status
If ($null -ne $Temp) {
	if ($Temp.Status -eq 'Running') {
		$Temp2 = Get-Process | Where-Object {$_.ProcessName -eq 'SiteComp'} | Select-Object StartTime
		AddTo-CMServerSummary -Name "SiteComp Status" -Value "Running. StartTime = $($Temp2.StartTime)"
	}
	else {
		AddTo-CMServerSummary -Name "SiteComp Status" -Value $Temp.Status
	}
}
Else {
	AddTo-CMServerSummary -Name "SiteComp Status" -Value "ERROR: Service Not found"
}

# ----------------------
# SMSExec Thread States
# ----------------------
$TempFileName = $ComputerName + "_CMServer_SMSExecThreads.TXT"
$OutputFile = join-path $Env:windir ("TEMP\" + $TempFileName)
Get-ItemProperty HKLM:\Software\Microsoft\SMS\Components\SMS_Executive\Threads\* -ErrorAction SilentlyContinue -ErrorVariable DirError `
	| Select-Object PSChildName, 'Current State', 'Startup Type', 'Requested Operation', DLL `
	| Sort-Object @{Expression='Current State';Descending=$true}, @{Expression='PSChildName';Ascending=$true} `
	| Format-Table -AutoSize | Out-String -Width 200 | Out-File -FilePath $OutputFile
If ($DirError.Count -eq 0) {
	CollectFiles -filesToCollect $OutputFile -fileDescription "SMSExec Thread States" -sectionDescription $sectiondescription -noFileExtensionsOnDescription
	AddTo-CMServerSummary -Name "SMSExec Thread States" -Value "Review $TempFileName" -NoToSummaryReport
	Remove-Item $OutputFile -Force
}
else {
	AddTo-CMServerSummary -Name "SMSExec Thread States" -Value ("ERROR: " + $DirError[0].Exception.Message) -NoToSummaryReport
	$DirError.Clear()
}

# -----------------
# SQL Server SPN's
# -----------------
#TraceOut "    Getting SQL SPNs"
#$TempFileName = ($ComputerName + "_CMServer_SQLSPN.TXT")
#$FileToCollect = join-path $pwd.Path $TempFileName
#$CmdToRun = ".\psexec.exe /accepteula -s $pwd\ldifde2K3x86.exe -f $FileToCollect -l serviceprincipalname -r `"(serviceprincipalname=MSSQLSvc/$ConfigMgrDBServer*)`" -p subtree"

#RunCmD -commandToRun $CmdToRun -collectFiles $false
#If (Test-Path $FileToCollect) {
#	If ((Get-Content $FileToCollect) -ne $null) {
#		If ((Get-Content $FileToCollect) -ne "") {
#			CollectFiles -filesToCollect $FileToCollect -fileDescription "SQL SPNs"  -sectionDescription $sectiondescription -noFileExtensionsOnDescription
#			AddTo-CMServerSummary -Name "SQL Server SPNs" -Value ("Review $TempFileName") -NoToSummaryReport
#		}
#		Else {
#			TraceOut "    No SPN's found. Output file was null."
#			# AddTo-CMServerSummary -Name "SQL Server SPNs" -Value ("Error. No SPNs found!") -NoToSummaryReport
#		}
#	}
#	Else {
#		TraceOut "    No SPN's found. Output file was empty."
#		# AddTo-CMServerSummary -Name "SQL Server SPNs" -Value ("Error. No SPNs found!") -NoToSummaryReport
#	}
#}
#Else {
#	TraceOut "    No SPN's found. Output file was not found."
#	AddTo-CMServerSummary -Name "SQL Server SPNs" -Value ("Error. SPN Query Failed!") -NoToSummaryReport
#}

# ----------------
# Write Progress
# ----------------
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CM07ServerInfo -Status $ScriptStrings.ID_SCCM_CM07ServerInfo_Hierarchy
TraceOut "    Getting Site Hierarchy"

# ------------------
# Hierarchy Details
# ------------------
$TempFileName = $ComputerName + "_CMServer_Hierarchy.TXT"
$OutputFile = join-path $Env:windir ("TEMP\" + $TempFileName)
$CommandLineToExecute = $Env:windir + "\system32\cscript.exe GetCM12Hierarchy.VBS"

If (($RemoteStatus -eq 0) -or ($RemoteStatus -eq 1)) {
	# Local Execution
	If ($null -eq $global:DatabaseConnectionError) {
		RunCmD -commandToRun $CommandLineToExecute -sectionDescription $sectiondescription -filesToCollect $OutputFile -fileDescription "Hierarchy Details" -noFileExtensionsOnDescription
		AddTo-CMServerSummary -Name "Hierarchy Details" -Value ("Review $TempFileName") -NoToSummaryReport
		Remove-Item $OutputFile -Force
	}
	Else {
		AddTo-CMServerSummary -Name "Hierarchy Details" -Value $DatabaseConnectionError -NoToSummaryReport
	}
}

# ----------------
# Write Progress
# ----------------
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CM07ServerInfo -Status $ScriptStrings.ID_SCCM_CM07ServerInfo_FileVer
TraceOut "    Getting File Versions"

# ---------------------
# Binary Versions List
# ---------------------
$TempFileName = ($ComputerName + "_CMServer_FileVersions.TXT")
$OutputFile = join-path $pwd.path $TempFileName
Get-ChildItem ($SMSInstallDir + "\bin") -recurse -include *.dll,*.exe -ErrorVariable DirError -ErrorAction SilentlyContinue | `
	ForEach-Object {[System.Diagnostics.FileVersionInfo]::GetVersionInfo($_)} | `
	Select-Object FileName, FileVersion, ProductVersion | Format-Table -AutoSize | `
	Out-File $OutputFile -Width 1000
If ($DirError.Count -eq 0) {
	CollectFiles -filesToCollect $OutputFile -fileDescription "Server File Versions" -sectionDescription $sectiondescription -noFileExtensionsOnDescription
	AddTo-CMServerSummary -Name "File Versions" -Value ("Review $TempFileName") -NoToSummaryReport
}
else {
	AddTo-CMServerSummary -Name "File Versions" -Value ("ERROR: " + $DirError[0].Exception.Message) -NoToSummaryReport
	$DirError.Clear()
}

# --------------------
# RCM Inbox File List
# --------------------
TraceOut "    Getting File List for RCM.box"
$TempFileName = ($ComputerName + "_CMServer_RCMFileList.TXT")
$OutputFile = join-path $pwd.path $TempFileName
Get-ChildItem ($SMSInstallDir + "\inboxes\RCM.box") -Recurse -ErrorVariable DirError -ErrorAction SilentlyContinue | `
	Select-Object CreationTime, LastAccessTime, FullName, Length, Mode | Sort-Object FullName | Format-Table -AutoSize | `
	Out-File $OutputFile -Width 1000
If ($DirError.Count -eq 0) {
	AddTo-CMServerSummary -Name "RCM.box File List" -Value ("Review $TempFileName") -NoToSummaryReport
	CollectFiles -filesToCollect $OutputFile -fileDescription "RCM.box File List" -sectionDescription $sectiondescription -noFileExtensionsOnDescription
}
else {
	AddTo-CMServerSummary -Name "RCM.box File List" -Value ("ERROR: " + $DirError[0].Exception.Message) -NoToSummaryReport
	$DirError.Clear()
}

# Server Info File is collected in DC_CM12SQLInfo.ps1. Need to make sure this script runs before that.
# $ServerInfo | Out-File $ServerInfoFile -Append -Width 200

TraceOut "Completed"


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAoF1PLA7Um9LCz
# AgJHlJ2EwOneIl8198TlxdaDPq4FAKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGY4wghmKAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIICOBiDFUUjX6vybQP0DglgX
# CgFqvOKhvS5icsuLV7zFMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAnOgFG8sAhjxPPnUWnBoBB4ffn/ltQo92q1xWq0HD4+/3Jq3zw+PXC
# BsNH6UTGLzT4elasHtxNf8P9Oi0dHl5sAmICSOUxb6sNNns1h2eFpCstYc1uI0pC
# AFC5NgQtQOsm8ixd+aC0JWM3yiyR7kHq7KVuk+xa6XrFlfA+8sKOgXRJlBPoMCpy
# GeVgAMuulDIboqwP3tuJwT7ftBv6UmRj48oMzmyF8bFGwiG1NIurJJgEvLEEpFRS
# KQSpo50aKAd2+JkHRQfDzI5SrF55yIfpO7OXpZPLLbitn0x4BukxrDtNkFSQVE2s
# xJceiioRohH9XHzTmbzB84dFFj9XKP+poYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIPebR/qjU2CWBx4qrN4N9iv3jvkRMOvhfMRUsSEZN30lAgZi3ohP
# 3m8YEzIwMjIwODAxMDczNTQ0LjE2OVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RDA4Mi00QkZELUVFQkExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAY/zUajrWnLdzAABAAABjzAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDZaFw0yMzAxMjYxOTI3NDZaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQwODIt
# NEJGRC1FRUJBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmVc+/rXPFx6Fk4+CpLru
# bDrLTa3QuAHRVXuy+zsxXwkogkT0a+XWuBabwHyqj8RRiZQQvdvbOq5NRExOeHia
# CtkUsQ02ESAe9Cz+loBNtsfCq846u3otWHCJlqkvDrSr7mMBqwcRY7cfhAGfLvlp
# MSojoAnk7Rej+jcJnYxIeN34F3h9JwANY360oGYCIS7pLOosWV+bxug9uiTZYE/X
# clyYNF6XdzZ/zD/4U5pxT4MZQmzBGvDs+8cDdA/stZfj/ry+i0XUYNFPhuqc+UKk
# wm/XNHB+CDsGQl+ZS0GcbUUun4VPThHJm6mRAwL5y8zptWEIocbTeRSTmZnUa2iY
# H2EOBV7eCjx0Sdb6kLc1xdFRckDeQGR4J1yFyybuZsUP8x0dOsEEoLQuOhuKlDLQ
# Eg7D6ZxmZJnS8B03ewk/SpVLqsb66U2qyF4BwDt1uZkjEZ7finIoUgSz4B7fWLYI
# eO2OCYxIE0XvwsVop9PvTXTZtGPzzmHU753GarKyuM6oa/qaTzYvrAfUb7KYhvVQ
# KxGUPkL9+eKiM7G0qenJCFrXzZPwRWoccAR33PhNEuuzzKZFJ4DeaTCLg/8uK0Q4
# QjFRef5n4H+2KQIEibZ7zIeBX3jgsrICbzzSm0QX3SRVmZH//Aqp8YxkwcoI1WCB
# izv84z9eqwRBdQ4HYcNbQMMCAwEAAaOCATYwggEyMB0GA1UdDgQWBBTzBuZ0a65J
# zuKhzoWb25f7NyNxvDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQDNf9Oo9zyhC5n1jC8iU7NJY39FizjhxZwJbJY/
# Ytwn63plMlTSaBperan566fuRojGJSv3EwZs+RruOU2T/ZRDx4VHesLHtclE8GmM
# M1qTMaZPL8I2FrRmf5Oop4GqcxNdNECBClVZmn0KzFdPMqRa5/0R6CmgqJh0muvI
# mikgHubvohsavPEyyHQa94HD4/LNKd/YIaCKKPz9SA5fAa4phQ4Evz2auY9SUluI
# d5MK9H5cjWVwBxCvYAD+1CW9z7GshJlNjqBvWtKO6J0Aemfg6z28g7qc7G/tCtrl
# H4/y27y+stuwWXNvwdsSd1lvB4M63AuMl9Yp6au/XFknGzJPF6n/uWR6JhQvzh40
# ILgeThLmYhf8z+aDb4r2OBLG1P2B6aCTW2YQkt7TpUnzI0cKGr213CbKtGk/OOIH
# SsDOxasmeGJ+FiUJCiV15wh3aZT/VT/PkL9E4hDBAwGt49G88gSCO0x9jfdDZWdW
# GbELXlSmA3EP4eTYq7RrolY04G8fGtF0pzuZu43A29zaI9lIr5ulKRz8EoQHU6cu
# 0PxUw0B9H8cAkvQxaMumRZ/4fCbqNb4TcPkPcWOI24QYlvpbtT9p31flYElmc5wj
# GplAky/nkJcT0HZENXenxWtPvt4gcoqppeJPA3S/1D57KL3667epIr0yV290E2ot
# ZbAW8DCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
# AQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAw
# BgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEw
# MB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk
# 4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9c
# T8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWG
# UNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6Gnsz
# rYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2
# LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLV
# wIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTd
# EonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0
# gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFph
# AXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJ
# YfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXb
# GjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJ
# KwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnP
# EP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMw
# UQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggr
# BgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYw
# DwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoY
# xDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
# L2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYB
# BQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0B
# AQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U5
# 18JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgAD
# sAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo
# 32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZ
# iefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZK
# PmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RI
# LLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgk
# ujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9
# af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzba
# ukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/
# OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLUMIIC
# PQIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDA4Mi00QkZELUVFQkExJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAD5NL4IEdudIBwdGoCaV0WBbQZpqoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmkZg6MCIYDzIwMjIwODAx
# MDgwOTMwWhgPMjAyMjA4MDIwODA5MzBaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaRmDoCAQAwBwIBAAICEbAwBwIBAAICEXEwCgIFAOaS6boCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQAhp8Aod4IrqWSzJRIvhdfsjjJ0NJWgA/ZOXoGxuTHB
# Nc+n4eD9raE8WV172xcQru+BQW4ecbLSElX8gQ88qDD0qPr3S/FY/5drB43kpsZb
# 3smIRpvR0AhUrfQV/szgrx7+5TBOZSinvdOPsft4KHAzsWahf7BfumsXJdtpt6+W
# nzGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABj/NRqOtact3MAAEAAAGPMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIJ24qUpz+p7kJn0YBwAM
# t5eFPDEbGos3Z+yocxXg1H9kMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# l3IFT+LGxguVjiKm22ItmO6dFDWW8nShu6O6g8yFxx8wgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY/zUajrWnLdzAABAAABjzAiBCDK
# yRgnJWWXshnmgygiJTZnJFpENKNV36rl3eKKIz0TKjANBgkqhkiG9w0BAQsFAASC
# AgBPOn6fYEVY6BFi0vSn4zSGOxM1cITb8B7RpL9rGUf6hqLIKnHbU6rxI1M65NJm
# 8bO3dfu1isIX4s4XrmNOPDhFz7D56B8mV1byshIv1TmJrYahSR5BIyVzmFcFcRvi
# nzfA+5AKEhYGx4B1S8VKEmHLdfkk6f99+9kJ2+M3B6dtxvr0eFyW65J6aeJBWFcV
# wKmqJhPLTETErFvFARRMnmbgaiHGu8mV3AgaLOCXIeX+6T5CWJlV98gZhYBuqJdV
# O7Np/WGI73e2dUlL4r7JWPonlNyqTyK1akmfGB2+dUElGxpGk8eHSJdVg/W6IOXB
# gVVqdZpOO6f6+MUjkd+mzI/RRZi/kjE6v0TEKKPABnBckm1QpGiVv2h8SdweSZYv
# Xdw6K2m76BjTRdV3Cj7EyDkRlCEzh9fcm6FOiVJmnA5kavv1to3zerlatz/ugMIJ
# lrWgE9PWA7qjNfMlnezi9hhyOSV1uhy+1LTEVL1l5ysH67v2+oiyT+47XsE47i2P
# fsMnmJiL+ckgARs7zgVEdYosdfjGItFfmBfRac3VFnwEgJOtBYIo2BdmXxPZ4OVb
# 6aH4jOx1gBzNHMB0fCHlxQ/6VXZCK0+paH4OE/Q+Aot2jEBiV5jD1u84DBYSkM7K
# GtMv1o1uEPHN5BwO7I4iuG3zyfIl9oCz7o7+s4xv6xK5pw==
# SIG # End signature block
