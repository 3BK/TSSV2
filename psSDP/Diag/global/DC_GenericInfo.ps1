trap [Exception]
{
	WriteTo-ErrorDebugReport -ErrorRecord $_
	continue
}

TraceOut "Started"
$sectionDescription = "System Information"

Import-LocalizedData -BindingVariable ScriptStrings

# ----------------
# Write Progress
# ----------------
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_GenericInfo -Status $ScriptStrings.ID_SCCM_GenericInfo_OSInfo

# Header for Client Summary File
$OSInfoFile = Join-Path $Pwd.Path ($ComputerName + "__OS_Summary.txt")
"=====================================" | Out-File $OSInfoFile
"Operating System Information Summary:" | Out-File $OSInfoFile -Append
"=====================================" | Out-File $OSInfoFile -Append

# PSObject to store Client information
$OSInfo = New-Object PSObject

TraceOut "    Getting OS information..."

# -------------
# Computer Name
# -------------
Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Computer Name" -Value $ComputerName

# ----------------------
# OS information:
# ----------------------
$Temp = Get-CimInstance -Namespace root\cimv2 -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
If ($Temp -is [WMI]) {
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Operating System" -Value $Temp.Caption
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Service Pack" -Value $Temp.CSDVersion
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Version" -Value $Temp.Version
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Architecture" -Value $OSArchitecture
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Last Boot Up Time" -Value ($Temp.ConvertToDateTime($Temp.LastBootUpTime))
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Current Time" -Value ($Temp.ConvertToDateTime($Temp.LocalDateTime))
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Total Physical Memory" -Value  ([string]([math]::round($($Temp.TotalVisibleMemorySize/1MB), 2)) + " GB")
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Free Physical Memory" -Value  ([string]([math]::round($($Temp.FreePhysicalMemory/1MB), 2)) + " GB")
}
else {
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "OS Details" -Value "Error obtaining data from Win32_OperatingSystem WMI Class" }

# ----------------------
# Computer System Information:
# ----------------------
$Temp = Get-CimInstance -Namespace root\cimv2 -Class Win32_TimeZone -ErrorAction SilentlyContinue
If ($Temp -is [WMI]) {
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Time Zone" -Value $Temp.Description }
else {
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Time Zone" -Value "Error obtaining value from Win32_TimeZone WMI Class" }

$Temp = Get-CimInstance -Namespace root\cimv2 -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
If ($Temp -is [WMI]) {
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Daylight In Effect" -Value $Temp.DaylightInEffect
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Domain" -Value $Temp.Domain
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Model" -Value $Temp.Model
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Number of Processors" -Value $Temp.NumberOfProcessors
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Number of Logical Processors" -Value $Temp.NumberOfLogicalProcessors
}
else {
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Computer System Details" -Value "Error obtaining value from Win32_ComputerSystem WMI Class" }

# ----------------
# Write Progress
# ----------------
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_GenericInfo -Status $ScriptStrings.ID_SCCM_GenericInfo_SysInfo

# --------------------------
# Get SystemInfo.exe output
# --------------------------
$TempFileName = $ComputerName + "_OS_SysInfo.txt"
$SysInfoFile = Join-Path $Pwd.Path $TempFileName
$CmdToRun = "cmd.exe /c SystemInfo.exe /S $ComputerName > $SysInfoFile"
RunCmd -commandToRun $CmdToRun -filesToCollect $SysInfoFile -fileDescription "SysInfo Output"  -sectionDescription $sectionDescription -BackgroundExecution -noFileExtensionsOnDescription
Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "SysInfo Output" -Value "Review $TempFileName"

TraceOut "    Getting Processes and Services..."

# -----------------------
# Get Running Tasks List
# -----------------------
$TempFileName = $ComputerName + "_OS_TaskList.txt"
$TaskListFile = Join-Path $Pwd.Path $TempFileName
$CmdToRun = "cmd.exe /c TaskList.exe /v /FO TABLE /S $ComputerName > $TaskListFile"
RunCmd -commandToRun $CmdToRun -filesToCollect $TaskListFile -fileDescription "Running Tasks List"  -sectionDescription $sectionDescription -noFileExtensionsOnDescription
Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Running Tasks List" -Value "Review $TempFileName"

# ----------------
# Services Status
#-----------------
$TempFileName = $ComputerName + "_OS_Services.txt"
$ServicesFile = Join-Path $Pwd.Path $TempFileName
$Temp = Get-CimInstance Win32_Service -ErrorVariable WMIError -ErrorAction SilentlyContinue  | Select-Object DisplayName, Name, State, @{name="Log on As";expression={$_.StartName}}, StartMode | `
			Sort-Object DisplayName | `
			Format-Table -AutoSize
If ($WMIError.Count -eq 0) {
	$Temp | Out-File $ServicesFile -Width 1000
	CollectFiles -filesToCollect $ServicesFile -fileDescription "Services Status" -sectionDescription $sectionDescription -noFileExtensionsOnDescription
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Services Status" -Value "Review $TempFileName"
}
Else {
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Services Status" -Value "Error obtaining Services Status: $WMIError[0].Exception.Message"
	$WMIError.Clear()
}

# ----------------
# Write Progress
# ----------------
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_GenericInfo -Status $ScriptStrings.ID_SCCM_GenericInfo_MSInfo

# ------------------
# Get MSInfo output
# ------------------
$TempFileName = $ComputerName + "_OS_MSInfo.NFO"
$MSInfoFile = Join-Path $Pwd.Path $TempFileName
$CmdToRun = "cmd.exe /c start /wait MSInfo32.exe /nfo $MSInfoFile /computer $ComputerName"
RunCmd -commandToRun $CmdToRun -filesToCollect $MSInfoFile -fileDescription "MSInfo Output"  -sectionDescription $sectionDescription -BackgroundExecution
Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "MSInfo Output" -Value "Review $TempFileName"

# ----------------
# Write Progress
# ----------------
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_GenericInfo -Status $ScriptStrings.ID_SCCM_GenericInfo_RSoP

# --------------------
# Get GPResult Output
# --------------------
TraceOut "    Getting GPResult..."
$CommandToExecute = "$Env:windir\system32\cmd.exe"

$OutputFileZ = $ComputerName + "_OS_GPResult.txt"
$Arg =  "/c $Env:windir\system32\gpresult.exe /Z > `"" + $PWD.Path + "\$OutputFileZ`""
Runcmd -fileDescription "GPResult /Z output" -commandToRun ($CommandToExecute + " " + $Arg) -filesToCollect $OutputFileZ -sectionDescription $sectionDescription -noFileExtensionsOnDescription
Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "GPResult /Z Output" -Value "Review $OutputFileZ"

If ($OSVersion.Major -ge 6) {
	$OutputFileH = $ComputerName + "_OS_GPResult.htm"
	$Arg =  "/c $Env:windir\system32\gpresult.exe /H `"" + $PWD.Path + "\$OutputFileH`" /F"
	Runcmd -fileDescription "GPResult /H output" -commandToRun ($CommandToExecute + " " + $Arg) -filesToCollect $OutputFileH -sectionDescription $sectionDescription -noFileExtensionsOnDescription
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "GPResult /H Output" -Value "Review $OutputFileH"
}

# ----------------
# Write Progress
# ----------------
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_GenericInfo -Status $ScriptStrings.ID_SCCM_GenericInfo_EnvVar

# ----------------------
# Environment Variables
# ----------------------
TraceOut "    Getting environment variables..."
$TempFileName = $ComputerName + "_OS_EnvironmentVariables.txt"
$OutputFile = join-path $pwd.path $TempFileName
"-----------------" | Out-File $OutputFile
"SYSTEM VARIABLES" | Out-File $OutputFile -Append
"-----------------" | Out-File $OutputFile -Append
 [environment]::GetEnvironmentVariables("Machine") | Out-File $OutputFile -Append -Width 250
"" | Out-File $OutputFile -Append
"-----------------" | Out-File $OutputFile -Append
"USER VARIABLES" | Out-File $OutputFile -Append
"-----------------" | Out-File $OutputFile -Append
 [environment]::GetEnvironmentVariables("User") | Out-File $OutputFile -Append -Width 250
 CollectFiles -filesToCollect $OutputFile -fileDescription "Environment Variables"  -sectionDescription $sectionDescription -noFileExtensionsOnDescription
 Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Environment Variables" -Value "Review $TempFileName"

# ----------------------
# Pending Reboot
# ----------------------
TraceOut "    Determining if reboot is pending..."
$TempFileName = $ComputerName + "_OS_RebootPending.txt"
$OutputFile = join-path $pwd.path $TempFileName
Get-PendingReboot -ComputerName $ComputerName | Out-File $OutputFile
CollectFiles -filesToCollect $OutputFile -fileDescription "Reboot Pending"  -sectionDescription $sectionDescription -noFileExtensionsOnDescription
Add-Member -InputObject $OSInfoFile -MemberType NoteProperty -Name "Reboot Pending" -Value "Review $TempFileName"

# ---------------------------------
# Get event logs
# ---------------------------------
TraceOut "    Getting Event Logs..."
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_GenericInfo -Status ($ScriptStrings.ID_SCCM_GenericInfo_EventLog)

$ZipName = $ComputerName + "_OS_EventLogs.zip"
$Destination = Join-Path $Env:windir ("\Temp\" + $ComputerName + "_OS_EventLogs")
$fileDescription = "Event Logs"

If (Test-Path $Destination) {
	Remove-Item -Path $Destination -Recurse -Force
}
New-Item -ItemType "Directory" $Destination | Out-Null #_#

# Copy files directly, it's much much faster this way. User can convert to TXT or CSV offline, as needed.
$TempLogPath = Join-Path $Env:windir "system32\winevt\logs"
Copy-Files -Source $TempLogPath -Destination $Destination -Filter Application.evtx
Copy-Files -Source $TempLogPath -Destination $Destination -Filter System.evtx
Copy-Files -Source $TempLogPath -Destination $Destination -Filter Security.evtx
Copy-Files -Source $TempLogPath -Destination $Destination -Filter Setup.evtx

compressCollectFiles -DestinationFileName $ZipName -filesToCollect ($Destination + "\*.*") -sectionDescription $sectionDescription -fileDescription $fileDescription -Recursive -ForegroundProcess -noFileExtensionsOnDescription
Remove-Item -Path $Destination -Recurse -Force

# --------------------------------
# Get WMI Provider Configuration
# --------------------------------
TraceOut "    Getting WMI Configuration..."
$TempFileName = $ComputerName + "_OS_WMIProviderConfig.txt"
$OutputFile = join-path $pwd.path $TempFileName
$Temp1 = Get-CimInstance -Namespace root -Class __ProviderHostQuotaConfiguration -ErrorAction SilentlyContinue
If ($Temp1 -is [WMI]) {
	TraceOut "      Connected to __ProviderHostQuotaConfiguration..."
	"------------------------" | Out-File $OutputFile
	"WMI Quota Configuration " | Out-File $OutputFile -Append
	"------------------------" | Out-File $OutputFile -Append
	$Temp1 | Select-Object MemoryPerHost, MemoryAllHosts, ThreadsPerHost, HandlesPerHost, ProcessLimitAllHosts | Out-File $OutputFile -Append
}

$Temp2 = Get-CimInstance -Namespace root\cimv2 -Class MSFT_Providers -ErrorAction SilentlyContinue
if (($Temp2 | Measure-Object).Count -gt 0) {
	TraceOut "      Connected to MSFT_Providers..."
	"------------------------" | Out-File $OutputFile -Append
	"WMI Providers " | Out-File $OutputFile -Append
	"------------------------`r`n" | Out-File $OutputFile -Append
	foreach($provider in $Temp2) {
		"Process ID $($provider.HostProcessIdentifier)" | Out-File $OutputFile -Append
		"  - Used by Provider $($provider.provider)" | Out-File $OutputFile -Append
		"  - Associated with Namespace $($provider.Namespace)" | Out-File $OutputFile -Append

		if (-not [string]::IsNullOrEmpty($provider.User)) {
			"  - By User $($provider.User)" | Out-File $OutputFile -Append
		}

		if (-not [string]::IsNullOrEmpty($provider.HostingGroup)) {
			"  - Under Hosting Group $($provider.HostingGroup)" | Out-File $OutputFile -Append
		}

		"" | Out-File $OutputFile -Append
	}
}

if ($Temp1 -is [wmi] -or $Temp2 -is [wmi]) {
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "WMI Provider Config" -Value "Review $TempFileName"
	CollectFiles -filesToCollect $OutputFile -fileDescription "WMI Provider Config" -sectionDescription $sectiondescription -noFileExtensionsOnDescription }
else {
	Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "WMI Provider Config" -Value "Error obtaining data from WMI" }

# --------------------------------
# Collect Certificate Information
# --------------------------------
TraceOut "    Getting Certificates..."
$TempFileName = ($ComputerName + "_OS_Certificates.txt")
$OutputFile = join-path $pwd.path $TempFileName

"##############" | Out-File $OutputFile
"## COMPUTER ##" | Out-File $OutputFile -Append
"##############`r`n`r`n" | Out-File $OutputFile -Append

"MY" | Out-File $OutputFile -Append
"==================" | Out-File $OutputFile -Append
Get-CertInfo Cert:\LocalMachine\My | Out-File $OutputFile -Append

"SMS" | Out-File $OutputFile -Append
"==================" | Out-File $OutputFile -Append
Get-CertInfo Cert:\LocalMachine\SMS | Out-File $OutputFile -Append

"Trusted People" | Out-File $OutputFile -Append
"==================" | Out-File $OutputFile -Append
Get-CertInfo Cert:\LocalMachine\TrustedPeople | Out-File $OutputFile -Append

"Trusted Publishers" | Out-File $OutputFile -Append
"==================" | Out-File $OutputFile -Append
Get-CertInfo Cert:\LocalMachine\TrustedPublisher | Out-File $OutputFile -Append

"Trusted Root CA's" | Out-File $OutputFile -Append
"==================" | Out-File $OutputFile -Append
Get-CertInfo Cert:\LocalMachine\Root | Out-File $OutputFile -Append

"##############" | Out-File $OutputFile -Append
"##   USER   ##" | Out-File $OutputFile -Append
"##############`r`n`r`n" | Out-File $OutputFile -Append

"MY" | Out-File $OutputFile -Append
"==================" | Out-File $OutputFile -Append
Get-CertInfo Cert:\CurrentUser\My | Out-File $OutputFile -Append

"Trusted People" | Out-File $OutputFile -Append
"==================" | Out-File $OutputFile -Append
Get-CertInfo Cert:\CurrentUser\TrustedPeople | Out-File $OutputFile -Append

"Trusted Publishers" | Out-File $OutputFile -Append
"==================" | Out-File $OutputFile -Append
Get-CertInfo Cert:\CurrentUser\TrustedPublisher | Out-File $OutputFile -Append

"Trusted Root CA's" | Out-File $OutputFile -Append
"==================" | Out-File $OutputFile -Append
Get-CertInfo Cert:\CurrentUser\Root | Out-File $OutputFile -Append

Add-Member -InputObject $OSInfo -MemberType NoteProperty -Name "Certificates" -Value "Review $TempFileName"
CollectFiles -filesToCollect $OutputFile -fileDescription "Certificates" -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# ---------------------------
# Collect OS Information
# ---------------------------
$OSInfo | Out-File $OSInfoFile -Append -Width 500
CollectFiles -filesToCollect $OSInfoFile -fileDescription "OS Summary"  -sectionDescription $global:SummarySectionDescription -noFileExtensionsOnDescription

TraceOut "Completed"


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDeRWDtPv1EC8/G
# fi3f1alov3CmuYv7HF/T6hvUjCyk/qCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHab4EXufnOUwn/mWvNW/H4U
# FR4FlgHLAKxD2NezvjdKMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCdermY97eHXjsFPaKVPeKtsqQ5LiOwLOoEZti4kGK1zr0O52rNNs2D
# /SHXr4dJyWXMVpCztH7i9uYTtV0XvXu7h4pyYIAhHUer4zU7b659VG66RNYPfQgE
# /Ww49E7cIXu0Kzh4t2hN3bHaeIu9dhI5TY25N1JeT7kmG8Jumavx6Z8uU0tUIPdg
# qRV0crw/IPVmFb8bCiQLFW0Krigx5yLV5g6FP/2w4RJSTgJbb+LdHlCcso1q0xLV
# lWEUlH7+MzX5x/kdce4m4XwSwd1b/vDsHrQDElv5l7Ps2US/gUbzwjF/lTxXX1vX
# UGvQUoRqgF6pFs02WUeY45tWa41vrq/PoYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIN3PvIYTCrZ/CwCnS0YEegYTweKRaYCU4BeNDlUY9sFlAgZi2BAW
# 93gYEzIwMjIwODAxMDc0MDExLjcxNFowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkVBQ0Ut
# RTMxNi1DOTFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGawHWixCFtPoUAAQAAAZowDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTE3WhcNMjMwMjI4MTkwNTE3WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RUFDRS1FMzE2LUM5MUQxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDacgasKiu3ZGEU/mr6A5t9oXAgbsCJq0NnOu+54zZP
# t9Y/trEHSTlpE2n4jua4VnadE4sf2Ng8xfUxDQPO4Vb/3UHhhdHiCnLoUIsW3wtE
# 2OPzHFhAcUNzxuSpk667om4o/GcaPlwiIN4ZdDxSOz6ojSNT9azsKXwQFAcu4c9t
# svXiul99sifC3s2dEEJ0/BhyHiJAwscU4N2nm1UDf4uMAfC1B7SBQZL30ssPyiUj
# U7gIijr1IRlBAdBYmiyR0F7RJvzy+diwjm0Isj3f8bsVIq9gZkUWxxFkKZLfByle
# Eo4BMmRMZE9+AfTprQne6mcjtVAdBLRKXvXjLSXPR6h54pttsShKaV3IP6Dp6bXR
# f2Gb2CfdVSxty3HHAUyZXuFwguIV2OW3gF3kFQK3uL6QZvN8a6KB0hto06V98Ote
# y1OTOvn1mRnAvVu4Wj8f1dc+9cOPdPgtFz4cd37mRRPEkAdX2YaeTgpcNExa+jCb
# OSN++VtNScxwu4AjPoTfQjuQ+L1p8SMZfggT8khaXaWWZ9vLvO7PIwIZ4b2SK3/X
# mWpk0AmaTha5QG0fu5uvd4YZ/xLuI/kiwHWcTykviAZOlwkrnsoYZJJ03RsIAWv6
# UHnYjAI8G3UgCFFlAm0nguQ3rIX54pmujS83lgrm1YqbL2Lrlhmi98Mk2ktCHCXK
# RwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFF+2nlnwnNtR6aVZvQqVyK02K9FwMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAAATu4fMRtRH20+nNzGAXFxdXEpRPTfbM0LJDeNe4QCxj0FM+wrJdu6UKrM2
# wQuO31UDcQ4nrUJBe81N6W2RvEa8xNXjbO0qzNitwUfOVLeZp6HVGcNTtYEMAvK9
# k//0daBFxbp04BzMaIyaHRy7y/K/zZ9ckEw7jF9VsJqlrwqkx9HqI/IBsCpJdlTt
# KBl/+LRbD8tWvw6FDrSkv/IDiKcarPE0BU6//bFXvZ5/h7diE13dqv5DPU5Kn499
# HvUOAcHG31gr/TJPEftqqK40dfpB+1bBPSzAef58rJxRJXNJ661GbOZ5e64EuyIQ
# v0Vo5ZptaWZiftQ5pgmztaZCuNIIvxPHCyvIAjmSfRuX7Uyke0k29rSTruRsBVIs
# ifG39gldsbyjOvkDN7S3pJtTwJV0ToC4VWg00kpunk72PORup31ahW99fU3jxBh2
# fHjiefjZUa08d/nQQdLWCzadttpkZvCgH/dc8Mts2CwrcxCPZ5p9VuGcqyFhK2I6
# PS0POnMuf70R3lrl5Y87dO8f4Kv83bkhq5g+IrY5KvLcIEER5kt5uuorpWzJmBNG
# B+62OVNMz92YJFl/Lt+NvkGFTuGZy96TLMPdLcrNSpPGV5qHqnHlr/wUz9UAViTK
# JArvSbvk/siU7mi29oqRxb0ahB4oYVPNuv7ccHTBGqNNGol4MIIHcTCCBVmgAwIB
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
# IEVTTjpFQUNFLUUzMTYtQzkxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAAbquMnUCam/m7Ox1Uv/GNs1jmu+g
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRt4wwIhgPMjAyMjA4MDExMDIzMDhaGA8yMDIyMDgwMjEwMjMwOFow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pG3jAIBADAKAgEAAgIXMgIB/zAHAgEA
# AgIRmjAKAgUA5pMJDAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAJDWOTBH
# wWT7ODdvvwN83fTgmYJaXHNYartsyVF9rpHSxt/MeCzRG3eJuIv7NN6AGwYQ8iSI
# VKoLlWgJQBfdXcpJH9npPTaOFGGOp0CneOrMEDrZALoYvSJOgOCNPuZXjWrPDM0I
# 9TUzezb8sCF5uOFDpiZ7xObT3zfRoTb0Xg+1MYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGawHWixCFtPoUAAQAAAZowDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgUhBXGLJ7LL+uaOJnlDVw2K5+15sxiW8bBSz2klXLFQYwgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCABTkDjOBEUfZnligJiL539Lx+nsr/N
# FVTnKFX030iNYDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABmsB1osQhbT6FAAEAAAGaMCIEILUtm4TpisXoG7kTsxOI51IMkFhuOyD6
# Xm+yAr8gIh09MA0GCSqGSIb3DQEBCwUABIICANRqGLPhjGSRBVcBuIgReTaIAQWi
# GuAEoGMaEge+IEulaURScUUrnuDnNAJ8/XDGXpa9ETETBGNbAly0rEfpAVl5mPCW
# 7xAYWbyJ6Xweg7mLq7xJzfxLOFKIlEneXnzghdOmgjQC6bmVdOxRWbFVuJ00jc3A
# y+piyPLCjhpseNo/vtfe6USGFz7NBg6BY7+QsLnnctXw1pLO6RL01l9SRuNAsbjB
# fAegEgV3ozMLpsiMAzMvOqFQ1hxkuwT/DaobJerZ/1bsaWyULnXtqLv1JiAMgKGe
# PBnvoIsfVLCjoMGSEsaXdEEKX/qoWHGuSaidPIiOSM7BpZhxEMD5QAnj03WUskij
# SWSd0sdFpcOAunnTZCUgIqR17mukunzR+hxtWHbWKPBLp4xe2j/l/gIX6Is7WBex
# sCovAhqVTuujo2lQIl0vl9kBCbCIArZuQfI0p9J/eQoN/fUvvxUa7M76jWZtE9mH
# XcH7uHCBsH5nsUypPiIBKlyF6CDaKGLuJCM6ZOEF6GuTPMsvwYZuGzXZtFFEQfDd
# ELfZgujnvpzsKUpTTK1DOtuIdOqoGb/9SSUrUodOga2np9338Wn0+u2HLgKtdWAR
# nQf8DY6PunJK2xzMEzAK1QLd5VHNupmnA3t0jFtnmobP/E4PTOq/1EIWO7sk2hNg
# 104TWHrnX9+sEizU
# SIG # End signature block
