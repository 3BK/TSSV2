
#************************************************
# DC_W32Time.ps1
# Version 1.0
# Date: 12-22-2010
# Author: clandis
# Description: Collects W32Time information
#************************************************

Import-LocalizedData -BindingVariable W32TimeStrings -FileName DC_W32Time -UICulture en-us

Write-DiagProgress -Activity $W32TimeStrings.ID_W32TimeOutput -Status $W32TimeStrings.ID_W32TimeObtaining

# If you specify a file name but not a full path for FileLogName, W32Time will try to write to %windir%\system32 but will fail with Access is Denied.
# So there is no point in checking for a file name but no full path, since it wouldn't allow debugging to actually be enabled anyway since the file wouldn't get written.

# Read the FileLogName value into the $FileLogName variable

$FileLogName = (get-itemproperty HKLM:\SYSTEM\CurrentControlSet\services\W32Time\Config\).FileLogName

# If $FileLogName is null (because FileLogName is not set) then throw an error.
If ($null -eq $FileLogName)	{
	"FileLogName registry value is not set. W32Time debug logging is not enabled." | Out-Host 
	} 
# If $FileLogName is populated, check if the path exists and if so, copy the file to current directory, prepending the computer name.
Else {
	"FileLogName = $FileLogName" | Out-Host 
	If (Test-Path $FileLogName) {
		"Copying $FileLogName to .\" + ($ComputerName + "_W32Time.log") | Out-Host
		Copy-Item $FileLogName (".\" + $ComputerName + "_W32Time.log")
		If (Test-Path (".\" + $ComputerName + "_W32Time.log")) {
			"File copy succeeded." | Out-Host 
			}
		Else {
			"File copy failed." | Out-Host 
			}
	Else {
		"File not found." | Out-Host 
		}
	}
}

# w32tm /query /status for local machine, PDC, and authenticating DC.
$OutputFile = $ComputerName + "_W32TM_Query_Status.TXT"	#_#

$Domain = [adsi]("LDAP://RootDSE")
$AUTHDC_DNSHOSTNAME = $Domain.dnshostname
$DomainDN = $Domain.defaultNamingContext
if ($DomainDN) {
	$PDC_NTDS_DN = ([adsi]("LDAP://"+ $DomainDN)).fsmoroleowner
	$PDC_NTDS = [adsi]("LDAP://"+ $PDC_NTDS_DN)
	$PDC = $PDC_NTDS.psbase.get_parent() #_# -ErrorAction SilentlyContinue
} else { " could not resolve DomainDN ($DomainDN) via LDAP://RootDSE" | Out-File -FilePath $OutputFile -append}
if ($null -ne $PDC) { $PDC_DNSHOSTNAME = $PDC.dnshostname }

"This output is best viewed in the Support Diagnostic Console (SDC) or Internet Explorer. `n " | Out-File -FilePath $OutputFile -append

"[INFO] The following errors are expected to occur under the following conditions: " | Out-File -FilePath $OutputFile -append
"   -  'Access is Denied' is expected if MSDT was run with an account that does not have local administrative rights on the target machine. " | Out-File -FilePath $OutputFile -append
"   -  'The procedure is out of range' is expected if the target machine is not running Windows Server 2008 or later. " | Out-File -FilePath $OutputFile -append
"   -  'The RPC server is unavailable' is expected if Windows Firewall is enabled on the target machine, or the target machine is otherwise unreachable. `n `n " | Out-File -FilePath $OutputFile -append
"Output of 'w32tm /query /status /verbose' " | Out-File -FilePath $OutputFile -append
"=========================================" | Out-File -FilePath $OutputFile -append
cmd /d /c w32tm /query /status /verbose | Out-File -FilePath $OutputFile -append

"Output of 'w32tm /query /configuration' " | Out-File -FilePath $OutputFile -append
"=========================================" | Out-File -FilePath $OutputFile -append
cmd /d /c w32tm /query /configuration | Out-File -FilePath $OutputFile -append
"Output of 'w32tm /query /peers' " | Out-File -FilePath $OutputFile -append
"=========================================" | Out-File -FilePath $OutputFile -append
cmd /d /c w32tm /query /peers | Out-File -FilePath $OutputFile -append

if ($Global:skipHang -ne $true) {  #_#
	If ($null -ne $PDC_DNSHOSTNAME) {
		"`n[INFO] The PDC Emulator for this computer's domain is $PDC_DNSHOSTNAME `n " | Out-File -FilePath $OutputFile -append

		"Output of 'w32tm /query /computer:$PDC_DNSHOSTNAME /status /verbose' - " | Out-File -FilePath $OutputFile -append
		"=========================================================================== "  | Out-File -FilePath $OutputFile -append
		cmd /d /c w32tm /query /computer:$PDC_DNSHOSTNAME /status /verbose | Out-File -FilePath $OutputFile -append
		}
	Else {
		"[Error] Unable to determine the PDC Emulator for the domain. `n " | Out-File -FilePath $OutputFile -append
		}

	If ($null -ne $AUTHDC_DNSHOSTNAME) {
		"`n[INFO] This computer's authenticating domain controller is $AUTHDC_DNSHOSTNAME `n " | Out-File -FilePath $OutputFile -append

		"Output of 'w32tm /query /computer:$AUTHDC_DNSHOSTNAME' /status /verbose" | Out-File -FilePath $OutputFile -append
		"=========================================================================== "  | Out-File -FilePath $OutputFile -append
		cmd /d /c w32tm /query /computer:$AUTHDC_DNSHOSTNAME /status /verbose | Out-File -FilePath $OutputFile -append
		}
	Else {
		"[Error] Unable to determine this computer's authenticating domain controller." | Out-File -FilePath $OutputFile -append
		}

	$outStripchart = ".\" + $ComputerName + "_W32TM_Stripchart.txt"
	If ($null -ne $PDC_DNSHOSTNAME) {
		"[INFO] The PDC Emulator for this computer's domain is $PDC_DNSHOSTNAME `n " | Out-File $outStripchart -append

		"Output of 'w32tm /stripchart /computer:$PDC_DNSHOSTNAME /samples:5 /dataonly' " | Out-File $outStripchart -append
		"=========================================================================== "  | Out-File $outStripchart -append
		cmd /d /c w32tm /stripchart /computer:$PDC_DNSHOSTNAME /samples:5 /dataonly | Out-File $outStripchart -append

		}
	Else {
		"[Error] Unable to determine the PDC Emulator for the domain." | Out-File $outStripchart -append
		}

	If ($null -ne $AUTHDC_DNSHOSTNAME) {
		"`n`n[INFO] This computer's authenticating domain controller is $AUTHDC_DNSHOSTNAME `n " | Out-File $outStripchart -append

		"Output of 'w32tm /stripchart /computer:$AUTHDC_DNSHOSTNAME /samples:5 /dataonly" | Out-File $outStripchart -append
		"=========================================================================== "  | Out-File $outStripchart -append
		cmd /d /c w32tm /stripchart /computer:$AUTHDC_DNSHOSTNAME /samples:5 /dataonly | Out-File $outStripchart -append
		}
	Else {
		"[Error] Unable to determine this computer's authenticating domain controller." | Out-File $outStripchart -append
		}
} #_#
$OutputFile1 = join-path $pwd.path ($ComputerName + "_W32Time_Service_Status.txt")
$command1 = $Env:windir + "\system32\cmd.exe /d /c sc query w32time > `"$OutputFile1`""

$OutputFile2 = join-path $pwd.path ($ComputerName + "_W32Time_Service_Perms.txt")
$command2 = $Env:windir + "\system32\cmd.exe /d /c sc sdshow w32time > `"$OutputFile2`""

if ($Global:skipHang -ne $true) {
	Write-DiagProgress -Activity $W32TimeStrings.ID_W32TimeOutput -Status "w32tm /monitor"
	$OutputFile3 = join-path $pwd.path ($ComputerName + "_W32TM_Monitor.txt")
	$command3 = $Env:windir + "\system32\cmd.exe /d /c w32tm /monitor > `"$OutputFile3`""

	Write-DiagProgress -Activity $W32TimeStrings.ID_W32TimeOutput -Status "w32tm /testif /qps"
	$OutputFile4 = join-path $pwd.path ($ComputerName + "_W32TM_TestIf_QPS.txt")
	$command4 = $Env:windir + "\system32\cmd.exe /d /c w32tm /testif /qps > `"$OutputFile4`""
}

$OutputFile5 = join-path $pwd.path ($ComputerName + "_W32TM_TZ.txt")
$command5 = $Env:windir + "\system32\cmd.exe /d /c w32tm /tz > `"$OutputFile5`""

CollectFiles -filesToCollect ($ComputerName + "_W32Time.log") -fileDescription "W32Time Debug Log" -sectionDescription "W32Time" -noFileExtensionsOnDescription
RegQuery -RegistryKeys "HKLM\SYSTEM\CurrentControlSet\Services\W32Time" -OutputFile ($ComputerName + "_W32Time_Reg_Key.txt") -fileDescription "W32Time Reg Key" -sectionDescription "W32Time" -recursive $true #_# removed .\ /WalterE

Get-Acl HKLM:\SYSTEM\CurrentControlSet\services\W32Time | Format-List | Out-File (".\" + $ComputerName + "_W32Time_Reg_Key_Perms.txt")
CollectFiles -filesToCollect ($ComputerName + "_W32Time_Reg_Key_Perms.txt") -fileDescription "W32Time Reg Key Perms" -sectionDescription "W32Time" -noFileExtensionsOnDescription
RunCmD -commandToRun $command1 -sectionDescription "W32Time" -filesToCollect $OutputFile1 -fileDescription "W32Time Service Status" -noFileExtensionsOnDescription
RunCmD -commandToRun $command2 -sectionDescription "W32Time" -filesToCollect $OutputFile2 -fileDescription "W32Time Service Perms" -noFileExtensionsOnDescription
if ($Global:skipHang -ne $true) {
	"__ value of Switch skipHang: $Global:skipHang  - 'True' will suppress some W32TM /Monitor output `n`n"        | WriteTo-StdOut
	RunCmD -commandToRun $command3 -sectionDescription "W32Time" -filesToCollect $OutputFile3 -fileDescription "W32TM /Monitor" -noFileExtensionsOnDescription
}
RunCmD -commandToRun $command4 -sectionDescription "W32Time" -filesToCollect $OutputFile4 -fileDescription "W32TM /TestIf /QPS" -noFileExtensionsOnDescription
### (Andret) Removed due http://bugcheck/Bugs/WindowsOSBugs/1879349 and http://bugcheck/bugs/Windows7/35226
RunCmD -commandToRun $command5 -sectionDescription "W32Time" -filesToCollect $OutputFile5 -fileDescription "W32TM /TZ" -noFileExtensionsOnDescription

CollectFiles -filesToCollect ($ComputerName + "_W32TM_Query_Status.txt") -fileDescription "W32TM Query Status" -sectionDescription "W32Time" -noFileExtensionsOnDescription
CollectFiles -filesToCollect ($ComputerName + "_W32TM_Stripchart.txt") -fileDescription "W32TM Stripchart" -sectionDescription "W32Time" -noFileExtensionsOnDescription

Trap{WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;Continue}


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBgLB3CkGfo1uw2
# ZlzWIEGbaa0nQ8FXMezvg2JdlLDn26CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILZ25uFUXx0GagqSbTnlDGY4
# tJzSbkVUua5+ELkJMyYfMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCuBWba+IFtzgTU053v65CMN1yPLOIa0JKEtX34+jKkdS7WMziHbHfR
# dZkkwT2yFEbJd3U7HyoNLXvIVwKPp7tyqKFrRw+kB5GQrbeGm4QBtzYtjps+79y8
# Q5U8bNm94cFkSCFu9IItmHxdtCDN+O4yPDu4l7fQBWa3v8PALePJccTUTmDLZS1D
# fNRnfrTrB5WWFPWk/NnJvvWsiUq5GSzxa5ckvlgxWvvvNNimEl2nmjdMgu1ZEv8q
# vEUtfXeXJjFyCJHu7a4WrimUa/s00P4Sd0MRBEsU+pzDBMtivr/tOYlnyY7grG4Q
# dLZ9SwUMcVwnQo7NAjGlJiZlE3k/5H8OoYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIN2kx6o2ScxLczwrYytv21CG0YUjAzIg6cgyeJ8Hit0KAgZjI0s8
# ceEYEzIwMjIxMDA0MTYwMDE3LjU2MlowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkU1QTYt
# RTI3Qy01OTJFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGVt/wN1uM3MSUAAQAAAZUwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTEyWhcNMjMwMjI4MTkwNTEyWjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RTVBNi1FMjdDLTU5MkUxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCfbUEMZ7ZLOz9aoRCeJL4hhT9Q8JZB2xaVlMNCt3bw
# hcTI5GLPrt2e93DAsmlqOzw1cFiPPg6S5sLCXz7LbbUQpLha8S4v2qccMtTokEaD
# QS+QJErnAsl6VSmRvAy0nlj+C/PaZuLb3OzY0ARw7UeCZLpyWPPH+k5MdYj6NUDT
# NoXqbzQHCuPs+fgIoro5y3DHoO077g6Ir2THIx1yfVFEt5zDcFPOYMg4yBi4A6Xc
# 3hm9tZ6w849nBvVKwm5YALfH3y/f3n4LnN61b1wzAx3ZCZjf13UKbpE7p6DYJrHR
# B/+pwFjG99TwHH6uXzDeZT6/r6qH7AABwn8fpYc1TmleFY8YRuVzzjp9VkPHV8Vz
# vzLL7QK2kteeXLL/Y4lvjL6hzyOmE+1LVD3lEbYho1zCt+F7bU+FpjyBfTC4i/wH
# sptb218YlbkQt1i1B6llmJwVFwCLX7gxQ48QIGUacMy8kp1+zczY+SxlpaEgNmQk
# fc1raPh9y5sMa6X48+x0K7B8OqDoXcTiECIjJetxwtuBlQseJ05HRfisfgFm09kG
# 7vdHEo3NbUuMMBFikc4boN9Ufm0iUhq/JtqV0Kwrv9Cv3ayDgdNwEWiL2a65InEW
# SpRTYfsCQ03eqEh5A3rwV/KfUFcit+DrP+9VcDpjWRsCokZv4tgn5qAXNMtHa8Ni
# qQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFKuX02ICFFdXgrcCBmDJfH5v/KkXMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAOCzNt4fJ+jOvQuq0Itn37IZrYNBGswAi+IAFM3YGK/wGQlEncgjmNBuac95
# W2fAL6xtFVfMfkeqSLMLqoidVsU9Bm4DEBjaWNOT9uX/tcYiJSfFQM0rDbrl8V4n
# M88RZF56G/qJW9g5dIqOSoimzKUt/Q7WH6VByW0sar5wGvgovK3qFadwKShzRYcE
# qTkHH2zip5e73jezPHx2+taYqJG5xJzdDErZ1nMixRjaHs3KpcsmZYuxsIRfBYOJ
# vAFGymTGRv5PuwsNps9Ech1Aasq84H/Y/8xN3GQj4P3MiDn8izUBDCuXIfHYk39b
# qnaAmFbUiCby+WWpuzdk4oDKz/sWwrnsoQ72uEGVEN7+kyw9+HSo5i8l8Zg1Ymj9
# tUgDpVUGjAduoLyHQ7XqknKmS9kJSBKk4okEDg0Id6LeKLQwH1e4aVeTyUYwcBX3
# wg7pLJQWvR7na2SGrtl/23YGQTudmWOryhx9lnU7KBGV/aNvz0tTpcsucsK+cZFK
# DEkWB/oUFVrtyun6ND5pYZNj0CgRup5grVACq/Agb+EOGLCD+zEtGNop4tfKvsYb
# 64257NJ9XrMHgpCib76WT34RPmCBByxLUkHxHq5zCyYNu0IFXAt1AVicw14M+czL
# YIVM7NOyVpFdcB1B9MiJik7peSii0XTRdl5/V/KscTaCBFz3MIIHcTCCBVmgAwIB
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
# IEVTTjpFNUE2LUUyN0MtNTkyRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA0Y+CyLezGgVHWFNmKI1LuE/hY6ug
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAObm1Y8wIhgPMjAyMjEwMDQyMzUzNTFaGA8yMDIyMTAwNTIzNTM1MVow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5ubVjwIBADAKAgEAAgIX/wIB/zAHAgEA
# AgITzTAKAgUA5ugnDwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAA6rM8cj
# 1f5MfeL6mUaqBkBZ1D7LQRTjpEr3DQnPXuCPSZJkWpebEbAIn21tVjfsJBoB4jPp
# lHNdktlvfhD0BhJwNZw/cqYMQUJoeBN/bU8lucsfHQhQ2RGpLZZ/y+VBC6VwNhEA
# VrUloUhehrKLTFz2ry7iW3h7WGG4gF6R0HWaMYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGVt/wN1uM3MSUAAQAAAZUwDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQg0WDxIK4Ge0sou5+4FM/1zyvhvAsvDX/T5TkSXP9IFB0wgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBc5kvhjZALe2mhIz/Qd7keVOmA/cC1
# dzKZT4ybLEkCxzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABlbf8DdbjNzElAAEAAAGVMCIEIPAO2nVmaBU9W6JGpOto2hblAnBFfKbx
# bG131FU3SHOjMA0GCSqGSIb3DQEBCwUABIICAHvpo9irAktTGQ75iLp6VLUqDhTT
# 6MXBK8vAFTBOn2qJfhdJPNv7x0iDTzbBWmmvahqNBP1eQH6ooSKoPFySBFooexhF
# E5AiTkshz9dQRaeuMY1G1yhAvmSm9akNQqgyb4bYUf1DeVQcCfNqjcUCveljv16S
# xROtTaYdAKFTMUkrYUt1Srdk0+lEDqGs38eE7/Xyx1w7O3KFFPxxODmsdeeHvE5P
# CXhF33V0f7AtKjOkoU77azjpdkywXVXYRjJD7ZsHDy5coUwZ10LQ52XPj5V/biaw
# 80MF59HmeeO3al9ES2ON3aOi3VBFdTz3JDD9JjnRdA3xZosJfD7NtV8XnQVX7rG0
# gigblUVpYKjqBR9+2qv0Hwuaag6KmJW9X9Cee99/n2nr42oBwcNrOMYoZypZ34DF
# yoEIfO+boYsSAd1OHKsPPq1UzhSCzX2S4iG76PXttJuaWgsrwUCXWX2u1l0wb45y
# HpokxoyCy9NrH5SavxlTeEA8VWFUU0GJxDkQsiqBD0doajWzy28He8C+OUUTqOCt
# LYfgNKJ+qfnEZrYaYZ8XmeKnOmSQgy0LlXjBgLcUcaSlqmce1WMBEnbUDjZ1MWB/
# Uga9Iv2XdqMfAnyUrEUYCMq36VlfNSBZ8qwlKTevj6VXYKimQNSXDJpeFmRZU43p
# x4gx61EKw90Pm21f
# SIG # End signature block
