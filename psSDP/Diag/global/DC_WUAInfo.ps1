# ********************************************************************************************
# Version 1.0
# Date: 03-20-2012
# Author: Vinay Pamnani - vinpa@microsoft.com
# Description:
# 		Collects Windows Update Agent Information.
#		1. Gets WUA Service Status and Start Time
#		2. Gets WUA Version
#		3. Gets WUA DLL Versions
#		4. Exports HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate Registry Key
#		5. Exports HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate Registry Key
#		6. Gets Windows Update Log
#		7. Summarizes all data to a text file for better readability.
# ********************************************************************************************

trap [Exception]
{
	WriteTo-ErrorDebugReport -ErrorRecord $_
	continue
}

TraceOut "Started"

Import-LocalizedData -BindingVariable ScriptStrings
$sectiondescription = "Windows Update Agent"

# ----------------
# Write Progress
# ----------------
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_WUAInfo -Status $ScriptStrings.ID_SCCM_WUAInfo_WUA

$WUAInfo = New-Object PSObject

# Summary File Header
$WUAFile = Join-Path $Pwd.Path ($ComputerName + "__WUA_Summary.txt")
"===========================================" | Out-File $WUAFile
"Windows Update Agent Configuration Summary:" | Out-File $WUAFile -Append
"===========================================" | Out-File $WUAFile -Append

# -------------
# Computer Name
# -------------
Add-Member -InputObject $WUAInfo -MemberType NoteProperty -Name "Computer Name" -Value $ComputerName

# ----------------------
# Time zone information:
# ----------------------
$Temp = Get-CimInstance -Namespace root\cimv2 -Class Win32_TimeZone -ErrorAction SilentlyContinue
If ($Temp -is [WMI]) {
	Add-Member -InputObject $WUAInfo -MemberType NoteProperty -Name "Time Zone" -Value $Temp.Description }
else {
	Add-Member -InputObject $WUAInfo -MemberType NoteProperty -Name "Time Zone" -Value "Error obtaining value from Win32_TimeZone WMI Class" }

$Temp = Get-CimInstance -Namespace root\cimv2 -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
If ($Temp -is [WMI]) {
	Add-Member -InputObject $WUAInfo -MemberType NoteProperty -Name "Daylight In Effect" -Value $Temp.DaylightInEffect }
else {
	Add-Member -InputObject $WUAInfo -MemberType NoteProperty -Name "Daylight In Effect" -Value "Error obtaining value from Win32_ComputerSystem WMI Class" }

# -----------------------
# WUA Service Status
# -----------------------
$Temp = Get-Service | Where-Object {$_.Name -eq 'WuAuServ'} | Select-Object Status
If ($null -ne $Temp) {
	Add-Member -InputObject $WUAInfo -MemberType NoteProperty -Name "WUA Service Status" -Value $Temp.Status
}
Else {
	Add-Member -InputObject $WUAInfo -MemberType NoteProperty -Name "WUA Service Status" -Value "ERROR: Service Not found"
}

# --------------------------
# WUA Service StartTime
# --------------------------
$Temp = Get-Process | Where-Object {($_.ProcessName -eq 'SvcHost') -and ($_.Modules -match 'wuaueng.dll')} | Select-Object StartTime
If ($null -ne $Temp) {
	Add-Member -InputObject $WUAInfo -MemberType NoteProperty -Name "WUA Service StartTime" -Value $Temp.StartTime
}
Else {
	Add-Member -InputObject $WUAInfo -MemberType NoteProperty -Name "WUA Service StartTime" -Value "ERROR: Service Not running"
}

# ------------
# WUA Version
# ------------
trap [Exception]
{
	Add-Member -InputObject $WUAInfo -MemberType NoteProperty -Name "WUA Version" -Value -Value ("ERROR: " + ($_.Exception.Message))
}
$WUA = New-Object -com "Microsoft.Update.AgentInfo" -ErrorAction SilentlyContinue -ErrorVariable WUAError
If ($WUAError.Count -eq 0) {
	$Temp = $WUA.GetInfo("ProductVersionString")
	Add-Member -InputObject $WUAInfo -MemberType NoteProperty -Name "WUA Version" -Value $Temp
}

# ----------------
# Write Progress
# ----------------
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_WUAInfo -Status $ScriptStrings.ID_SCCM_WUAInfo_SoftDist

# --------------------------------------------
# File List in SoftwraeDistribution Directory
# --------------------------------------------
$TempFileName = ($ComputerName + "_WUA_FileList.txt")
$OutputFile = join-path $pwd.path $TempFileName
Get-ChildItem (Join-Path $env:windir "SoftwareDistribution") -Recurse -ErrorVariable DirError -ErrorAction SilentlyContinue | `
	Select-Object CreationTime, LastAccessTime, FullName, Length, Mode | Sort-Object FullName | Format-Table -AutoSize | `
	Out-File $OutputFile -Width 1000
If ($DirError.Count -eq 0) {
	Add-Member -InputObject $WUAInfo -MemberType NoteProperty -Name "SoftwareDistribution Directory List" -Value "Review $TempFileName"
	CollectFiles -filesToCollect $OutputFile -fileDescription "WUA File List" -sectionDescription $sectiondescription -noFileExtensionsOnDescription
}
else {
	$DirError.Clear()
}

# ----------------
# Write Progress
# ----------------
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_WUAInfo -Status $ScriptStrings.ID_SCCM_WUAInfo_FileVer

# -----------------
# WUA DLL Versions
# -----------------
$TempFileName = ($ComputerName + "_WUA_FileVersions.txt")
$VersionFile  = Join-Path $Pwd.Path $TempFileName
Add-Member -InputObject $WUAInfo -MemberType NoteProperty -Name "WUA Related File Versions" -Value "Review $TempFileName"
"-----------------------------------" | Out-File $VersionFile -Append
"Windows Update Agent DLL Versions: " | Out-File $VersionFile -Append
"-----------------------------------" | Out-File $VersionFile -Append
Get-ChildItem (Join-Path $Env:windir "system32\wu*.dll") -Exclude WUD*.dll -ErrorAction SilentlyContinue | `
	foreach-object {[System.Diagnostics.FileVersionInfo]::GetVersionInfo($_)} | `
	Select-Object FileName,FileVersion,ProductVersion | Format-Table -AutoSize -HideTableHeaders | `
	Out-File $VersionFile -Append -Width 1000

# ------------------
# BITS DLL Versions
# ------------------
"-------------------" | Out-File $VersionFile -Append
"BITS DLL Versions: " | Out-File $VersionFile -Append
"-------------------" | Out-File $VersionFile -Append
Get-ChildItem (Join-Path $Env:windir "system32\bits*.dll"), (Join-Path $Env:windir "system32\winhttp*.dll"), (Join-Path $Env:windir "system32\qmgr*.dll") -ErrorAction SilentlyContinue | `
	foreach-object {[System.Diagnostics.FileVersionInfo]::GetVersionInfo($_)} | `
	Select-Object FileName,FileVersion,ProductVersion | Format-Table -AutoSize -HideTableHeaders | `
	Out-File $VersionFile -Append -Width 1000

# -----------------
# MSI DLL Versions
# -----------------
"--------------------------------" | Out-File $VersionFile -Append
"Windows Installer DLL Versions: " | Out-File $VersionFile -Append
"--------------------------------" | Out-File $VersionFile -Append
Get-ChildItem (Join-Path $Env:windir "system32\msi*.*") -ErrorAction SilentlyContinue | `
	foreach-object {[System.Diagnostics.FileVersionInfo]::GetVersionInfo($_)} | `
	Select-Object FileName,FileVersion,ProductVersion | Format-Table -AutoSize -HideTableHeaders | `
	Out-File $VersionFile -Append -Width 1000

# -----------------
# MSXML DLL Versions
# -----------------
"--------------------" | Out-File $VersionFile -Append
"MSXML DLL Versions: " | Out-File $VersionFile -Append
"--------------------" | Out-File $VersionFile -Append
Get-ChildItem (Join-Path $Env:windir "system32\msxml*.dll") -ErrorAction SilentlyContinue | `
	foreach-object {[System.Diagnostics.FileVersionInfo]::GetVersionInfo($_)} | `
	Select-Object FileName,FileVersion,ProductVersion | Format-Table -AutoSize -HideTableHeaders | `
	Out-File $VersionFile -Append -Width 1000

CollectFiles -filesToCollect $VersionFile -fileDescription "WUA File Versions"  -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# ----------------
# Write Progress
# ----------------
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_WUAInfo -Status $ScriptStrings.ID_SCCM_WUAInfo_SecDesc

# ---------------------
# Security Descriptors
# ---------------------
$TempFileName = ($ComputerName + "_WUA_SecurityDesc.txt")
$SDFile  = Join-Path $Pwd.Path $TempFileName
Add-Member -InputObject $WUAInfo -MemberType NoteProperty -Name "WUA Related Security Descriptors" -Value "Review $TempFileName"
"----------------------------------------------" | Out-File $SDFile -Append
"Security Descriptors for WU Related Services: " | Out-File $SDFile -Append
"----------------------------------------------" | Out-File $SDFile -Append
"" | Out-File $SDFile -Append
"WUAUServ: " | Out-File $SDFile -Append
$CmdToRun = "cmd /c sc sdshow wuauserv >> $SDFile"
RunCmd -commandToRun $CmdToRun -collectFiles $false
"" | Out-File $SDFile -Append
"BITS: " | Out-File $SDFile -Append
$CmdToRun = "cmd /c sc sdshow bits >> $SDFile"
RunCmd -commandToRun $CmdToRun -collectFiles $false
"" | Out-File $SDFile -Append
"Windows Installer: " | Out-File $SDFile -Append
$CmdToRun = "cmd /c sc sdshow msiserver >> $SDFile"
RunCmd -commandToRun $CmdToRun -collectFiles $false
"" | Out-File $SDFile -Append
"Task Scheduler: " | Out-File $SDFile -Append
$CmdToRun = "cmd /c sc sdshow Schedule >> $SDFile"
RunCmd -commandToRun $CmdToRun -collectFiles $false

CollectFiles -filesToCollect $SDFile -fileDescription "WUA Security Descriptors"  -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# ---------------------------
# Collect WU Registry keys
# ---------------------------
$TempFileName = $ComputerName + "_RegistryKey_WU.txt"
$RegFileWU = Join-Path $Pwd.Path $TempFileName

$TempKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
Export-RegKey -RegKey $TempKey -outFile $RegFileWU -fileDescription "WU Registry Key" -collectFiles $false

$TempKey = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate"
Export-RegKey -RegKey $TempKey -outFile $RegFileWU -fileDescription "WU Registry Key" -collectFiles $false

Add-Member -InputObject $WUAInfo -MemberType NoteProperty -Name "WU Registry Keys" -Value "Review $TempFileName"
CollectFiles -filesToCollect $RegFileWU -fileDescription "WU Registry Keys"  -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# ---------------------------
# Collect WUFB Registry keys
# ---------------------------
$TempFileName = $ComputerName + "_RegistryKey_WUFB.txt"
$RegFileWUFB = Join-Path $Pwd.Path $TempFileName

$TempKey = "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX"
Export-RegKey -RegKey $TempKey -outFile $RegFileWUFB -fileDescription "WUFB Registry Keys" -collectFiles $false

$TempKey = "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy"
Export-RegKey -RegKey $TempKey -outFile $RegFileWUFB -fileDescription "WUFB Registry Keys" -collectFiles $false

$TempKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
Export-RegKey -RegKey $TempKey -outFile $RegFileWUFB -fileDescription "WUFB Registry Keys" -collectFiles $false

$TempKey = "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Update"
Export-RegKey -RegKey $TempKey -outFile $RegFileWUFB -fileDescription "WUFB Registry Keys" -collectFiles $false

Add-Member -InputObject $WUAInfo -MemberType NoteProperty -Name "WUFB Registry Keys" -Value "Review $TempFileName"
CollectFiles -filesToCollect $RegFileWUFB -fileDescription "WUFB Registry Keys"  -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# ----------------------------------------
# Output WUAInfo PSObject to Summary File
# ----------------------------------------
$WUAInfo | Out-File $WUAFile -Append -Width 500

# --------------------
# Collect WUA Summary
# --------------------
CollectFiles -filesToCollect $WUAFile -fileDescription "WUA Summary"  -sectionDescription $global:SummarySectionDescription -noFileExtensionsOnDescription

TraceOut "Completed"


# SIG # Begin signature block
# MIInoQYJKoZIhvcNAQcCoIInkjCCJ44CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBnObIB/dUDYDPh
# GoAelo8yg1lbYnj1ObRVAznssJ9QbKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIEeFVNNWBtLD31I4APgcCpF3
# QX3p52ka8irK7gTmGdypMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCP+mQX7d+nc77JZ027ZWzASY/IcoVjohTHRKijoWHdyKp6sFLXkqlB
# n1AImJITakTlD4WK4lV1ay5UZaUKZMMwBneK2375pfk16j1A4wbj/3OAsxZk7Lkw
# OnQvTmB+8+NBMrgb5J3g80/7xrE32AAY4sRznDnRk18k/FDS+Pv6DkckdWBPSKqH
# 0UH2IQSogtTdUFk1nDE77Mtsl55ULMtHvejdtf3MMu5uytzaLLyPLzKK3r7WSegL
# +7gUyjb5I7nZsV3BhnxrR3QAtR2IoIcYJu10mQqdRUux8lEC+cRwmDhNxBJ8F4H+
# lBQWAL1ctbjXkSHny8bPTN4+l5i6E2scoYIXCTCCFwUGCisGAQQBgjcDAwExghb1
# MIIW8QYJKoZIhvcNAQcCoIIW4jCCFt4CAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIGqL203Kn4F1cUoNpcG+jrJ4Y287sDLRQiirAjxnQOSsAgZi2xAP
# VusYEzIwMjIwODAxMDc1MjAxLjk5NlowBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
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
# CRABBDAvBgkqhkiG9w0BCQQxIgQg+ltvhmZdjSjp1JzDfHpAtqtWYEUutTMLbQBs
# j0KAs0gwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAOHK/6sIVgEVSVD3Ar
# vk6OyQKvRxFHKyraUzbN1/AKVzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABqwkJ76tj1OipAAEAAAGrMCIEIHI+RQKHTZ2Id7/ufvKq
# /DQk+dqQy1YkmvsPNzOkpL0iMA0GCSqGSIb3DQEBCwUABIICAFI9nPgoL8CS6+J8
# lJMl73Ru5t3DPnE8HUtb24xPK3S+xnrZaVDrVqTuJKVpELGT0K7NPR5fWG3Sl3Z0
# iWdZUoCAXHOk0mSJc9dtgXy8QchkzVWl0eGs4EaElArAlUxo5DTa39WvOPUmIhwo
# I0Y2pKH/B9idg/Q3fyWtMySY6xpztCwqs0KCB6cZzlNqFC9+tdY8RLGZ2fnPS0EQ
# bhQH0VF5xsGJA5HG+CgUAO1Nj9kC5I08ex91w9CeQPkwN0jT9n2Yr0gAJ76M3PeG
# OuACiqaHEVGeAhCm+Sr6/H/TiHDCDKjXhHqanVgo8lJ84sBFztH+yAOfhNtBMpKg
# lRGNvcP/92pE74qcUAc+yyV14xiAHfB91dc/N/k7KBj0r1gADvvQKn58nLcY1x/s
# 8wRYB30z2TrwD6Pfk6WskicHCBT6cVM9SQrq71uRFxqiqoh4WTshh9mzNpWbCPdu
# SWBjwTZQ9ux948tmiXyadCPR4XA4rVL8uyR64juCz6WvYg7wwFF9lPr66Hed68+Z
# jV03yxaFsGdmelf0c5lGcaEOTNjeTIzUv73qMiWtyQZ6UWW9EZOeO1xglCjnUE1P
# gaa8HddLnJlbE/GTbL1EGgRlAYjg2iW2IRnJQXQwz+O+p96NloNsXNVLvA1mTfuB
# Q+NyJ0xaKrSwByeFRq5ESdNCx2oa
# SIG # End signature block
