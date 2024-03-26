# File: DC_WindowsUpdateLog.ps1
# Date: 2009-2019
# Author: + Walter Eder (waltere@microsoft.com)
# Description: Collects additional WindowsUpdate information.
#*******************************************************

PARAM([string]$MachineName = $ComputerName,[string]$Path= $null)

Function CopyWindowsupdateLog($sourceFileName, $destinationFileName, $fileDescription) 
{

	$sectionDescription = "Windows Update"
	
	if (test-path $sourceFileName) {
		$sourceFile = Get-Item $sourceFileName
		#copy the file only if it is not a 0KB file.
		if ($sourceFile.Length -gt 0) 
		{
			$CommandLineToExecute = "cmd.exe /c copy `"$sourceFileName`" `"$destinationFileName`""
			RunCmD -commandToRun $CommandLineToExecute -sectionDescription $sectionDescription -filesToCollect $destinationFileName -fileDescription $fileDescription
		}
	}
}

function RunPS ([string]$RunPScmd="", [switch]$ft)
{
	$RunPScmdLength = $RunPScmd.Length
	"-" * ($RunPScmdLength)		| Out-File -FilePath $OutputFile -append
	"$RunPScmd"  				| Out-File -FilePath $OutputFile -append
	"-" * ($RunPScmdLength)  	| Out-File -FilePath $OutputFile -append
	
	if ($ft)
	{
		# This format-table expression is useful to make sure that wide ft output works correctly
		Invoke-Expression $RunPScmd	|format-table -autosize -outvariable $FormatTableTempVar | Out-File -FilePath $outputFile -Width 500 -append
	}
	else
	{
		Invoke-Expression $RunPScmd	| Out-File -FilePath $OutputFile -append
	}
	"`n`n`n"	| Out-File -FilePath $OutputFile -append
}

Import-LocalizedData -BindingVariable ScriptStrings

# detect OS version
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber

#---------- Win10 Get-WindowsUpdateLog ETL
if ([int]$bn -gt [int](9600))
	{
		"__ value of Switch skipHang: $Global:skipHang  - 'True' will suppress Get-WindowsUpdateLog `n`n"        | WriteTo-StdOut
		if ($Global:skipHang -ne $true) {	#_# 2021-03-17
			$sectionDescription = "Windows Update ETW W10"
			#$OutputFile = Join-Path $pwd.path ($ComputerName + "_WindowsUpdate.txt")
			$OutputFileW10 = Join-Path $pwd.path ($ComputerName + "_WindowsUpdate.ETW_Converted.txt")
			Write-DiagProgress -Activity $ScriptStrings.ID_WindowsUpdateLogCollect -Status "Converting Windows Update ETW log"
			Write-Host -ForegroundColor Yellow -BackgroundColor Gray " ** Note: This step can take some time, please be patient!... - or use skipHang"
				PowerShell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass -command "Set-Alias Out-Default Out-Null; Get-WindowsUpdateLog -LogPath $OutputFileW10"
			collectfiles -filesToCollect $OutputFileW10 -fileDescription "Windows Update ETW log" -sectionDescription $sectionDescription
			
			if (test-path "$env:windir.old\Windows\Logs\WindowsUpdate")
			{
				$sectionDescription = "Old Windows ETL Update"		
				Write-DiagProgress -Activity $ScriptStrings.ID_WindowsUpdateLogCollect -Status "Get Old Windows Update ETL logs"
				compresscollectfiles -filesToCollect (join-path $env:systemdrive "Windows.old\Windows\Logs\WindowsUpdate\*.ETL") -Recursive -fileDescription "Old Windows Update ETW Files" -sectionDescription $sectiondescription -DestinationFileName "Windows.old_WU-ETW.zip" -RenameOutput $true
				}
		}
	}
else {
	$FileToCollect = $null
	if([string]::IsNullOrEmpty($Path))
	{
		$FileToCollect = Join-Path $Env:windir "windowsupdate.log"
	}
	else
	{
		$FileToCollect = Join-Path $Path "windowsupdate.log"

	}
	
	Write-DiagProgress -activity $ScriptStrings.ID_WindowsUpdateLogCollect -status $ScriptStrings.ID_WindowsUpdateLogCollectDesc
	$FileDescription = "Windows update log"
	$destinationFileName = $MachineName + "_windowsupdate.log"
	CopyWindowsupdateLog -sourceFileName $FileToCollect -destinationFileName $destinationFileName -fileDescription $FileDescription
	#CollectFiles -filesToCollect $FileToCollect -fileDescription $FileDescription -sectionDescription $SectionDescription -renameOutput $true
}



if ($Global:runFull -eq $True) { # $False = disabling for now for this long-lasting step
# --------------------------------------------------------------- added 2019-07-15 #_#
# SECTION - Windows Update
<# done already in DC_ServicingLogs.ps1
Write-DiagProgress -activity $ScriptStrings.ID_WindowsUpdateLogCollect -status "Get \SoftwareDistribution\ReportingEvents.log"
$FileDescription = "Windows update SoftwareDistribution\ReportingEvents.log"
$FileToCollect = Join-Path $Env:windir "SoftwareDistribution\ReportingEvents.log"
$destinationFileName = $MachineName + "_WindowsUpdate_ReportingEvents.log"
CopyWindowsupdateLog -sourceFileName $FileToCollect -destinationFileName $destinationFileName -fileDescription $FileDescription
#>
if (test-path $env:localappdata\microsoft\windows\windowsupdate.log)
	{
	$FileDescription = "Windows update $Env:localappdata\microsoft\windows\"
	$FileToCollect = Join-Path $Env:localappdata "microsoft\windows\windowsupdate.log"
	$destinationFileName = $MachineName + "_WindowsUpdatePerUser.log"
	CopyWindowsupdateLog -sourceFileName $FileToCollect -destinationFileName $destinationFileName -fileDescription $FileDescription
	}

if (test-path "$env:windir\microsoft\windows\windowsupdate (1).log")
	{
	$FileDescription = "Windows update WindowsUpdate.Old.log"
	$FileToCollect = Join-Path $Env:windir "windowsupdate (1).log"
	$destinationFileName = $MachineName + "_WindowsUpdate.Old.log"
	CopyWindowsupdateLog -sourceFileName $FileToCollect -destinationFileName $destinationFileName -fileDescription $FileDescription
	}

if (test-path "$env:systemdrive\Windows.old\Windows\SoftwareDistribution\ReportingEvents.log")
	{
	$FileDescription = "Windows update WindowsUpdate.Old.log"
	$FileToCollect = Join-Path $Env:systemdrive "Windows.old\Windows\SoftwareDistribution\ReportingEvents.log"
	$destinationFileName = $MachineName + "_Old.ReportingEvents.log"
	CopyWindowsupdateLog -sourceFileName $FileToCollect -destinationFileName $destinationFileName -fileDescription $FileDescription
	}

if (test-path "$env:windir\SoftwareDistribution\Plugins\7D5F3CBA-03DB-4BE5-B4B36DBED19A6833\TokenRetrieval.log")
	{
	$FileDescription = "Windows update WindowsUpdate.Old.log"
	$FileToCollect = Join-Path $Env:windir "SoftwareDistribution\Plugins\7D5F3CBA-03DB-4BE5-B4B36DBED19A6833\TokenRetrieval.log"
	$destinationFileName = $MachineName + "_WindowsUpdate_TokenRetrieval.log"
	CopyWindowsupdateLog -sourceFileName $FileToCollect -destinationFileName $destinationFileName -fileDescription $FileDescription
	}

 
#----------Registry
		$OutputFile= $ComputerName + "_WindowsUpdate_reg_wu.txt"
		Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get WindowsUpdate_reg_wu TXT"
		RegQuery -RegistryKeys "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate" -OutputFile $OutputFile -fileDescription "Windows WindowsUpdate Reg key" -Recursive $true

		$OutputFile= $ComputerName + "_WindowsUpdate_reg_wupolicy.txt"
		Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get WindowsUpdate_reg_wupolicy TXT"
		RegQuery -RegistryKeys "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" -OutputFile $OutputFile -fileDescription "Policy WindowsUpdate Reg key" -Recursive $true

		$OutputFile= $ComputerName + "_WindowsUpdate_reg_wuhandlers.txt"
		Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get WindowsUpdate_reg_wuhandlers TXT"
		RegQuery -RegistryKeys "HKLM\Software\Microsoft\WindowsUpdate" -OutputFile $OutputFile -fileDescription "WindowsUpdate Reg key" -Recursive $true
		
		$OutputFile= $ComputerName + "_WindowsUpdate_reg_SIH.txt"
		Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get _WindowsUpdate_reg_SIH TXT"
		RegQuery -RegistryKeys "HKLM\Software\Microsoft\sih" -OutputFile $OutputFile -fileDescription "Software\Microsoft\sih TXT Reg key" -Recursive $true

		$OutputFile= $MachineName + "_WindowsUpdate_reg_SIH.HIV"
		Write-DiagProgress -Activity $ScriptVariable.ID_CTSAddons -Status "Get _WindowsUpdate_reg_SIH HIV"
		RegSave -RegistryKey "HKLM\Software\Microsoft\sih" -OutputFile $OutputFile -fileDescription "Software\Microsoft\sih Hive"


#----------Service status, BitsAdmin, SchTasks
	#$OutputFile1 = join-path $pwd.path ($ComputerName + "_WindowsUpdate_wuauserv-state.txt")
	#$command1 = $Env:windir + "\system32\cmd.exe /d /c sc query wuauserv > `"$OutputFile1`""

	$sectionDescription = "sc query wuauserv"
	$OutputFile = Join-Path $pwd.path ($ComputerName + "_WindowsUpdate_wuauserv-state.txt")
	Write-DiagProgress -activity $ScriptStrings.ID_WindowsUpdateLogCollect -Status "WUauserv Service Status"
	$CommandToExecute = 'sc query wuauserv '
	RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
	collectfiles -filesToCollect $OutputFile -fileDescription "WinUpdate: WUauserv Service Status" -sectionDescription $sectionDescription

	$sectionDescription = "BitsAdmin /list /allusers /verbose"
	$OutputFile = Join-Path $pwd.path ($ComputerName + "_bitsadmin.txt")
	Write-DiagProgress -activity $ScriptStrings.ID_WindowsUpdateLogCollect -Status "BitsAdmin Status"
	$CommandToExecute = 'bitsadmin /list /allusers /verbose '
	RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
	collectfiles -filesToCollect $OutputFile -fileDescription "WinUpdate: BitsAdmin Status" -sectionDescription $sectionDescription

	$sectionDescription = "SCHTASKS /query /v /TN \Microsoft\Windows\WindowsUpdate\"
	$OutputFile = Join-Path $pwd.path ($ComputerName + "_WindowsUpdate_ScheduledTasks.txt")
	Write-DiagProgress -activity $ScriptStrings.ID_WindowsUpdateLogCollect -Status "ScheduledTasks"
	$CommandToExecute = 'SCHTASKS /query /v /TN \Microsoft\Windows\WindowsUpdate\ '
	RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
	collectfiles -filesToCollect $OutputFile -fileDescription "WinUpdate: ScheduledTasks" -sectionDescription $sectionDescription
	
#----------Dir Outputs
	$sectionDescription = "Dir %windir%\SoftwareDistribution"
	$OutputFile = Join-Path $pwd.path ($ComputerName + "_WindowsUpdate_dir_SoftwareDistribution.txt")
	Write-DiagProgress -Activity $ScriptStrings.ID_WindowsUpdateLogCollect -Status "Get $sectiondescription"
	$CommandToExecute = 'dir /a /s "$Env:windir\SoftwareDistribution" '
	RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
	collectfiles -filesToCollect $OutputFile -fileDescription "WinUpdate: $sectionDescription output" -sectionDescription $sectionDescription
	
#----------Windows Update file versions
	$sectionDescription = "Windows Update file versions"
	$OutputFile = Join-Path $pwd.path ($ComputerName + "_WindowsUpdate_FileVersions.txt")
	Write-DiagProgress -Activity $ScriptStrings.ID_WindowsUpdateLogCollect -Status "Get $sectiondescription"
	"===================================================="			| Out-File -FilePath $OutputFile -append
	"Windows Update file versions in $env:windir\system32\"			| Out-File -FilePath $OutputFile -append
	"===================================================="			| Out-File -FilePath $OutputFile -append
	$binaries = @("wuaext.dll", "wuapi.dll", "wuaueng.dll", "wucltux.dll", "wudriver.dll", "wups.dll", "wups2.dll", "wusettingsprovider.dll", "wushareduxresources.dll", "wuwebv.dll", "wuapp.exe", "wuauclt.exe", "storewuauth.dll", "wuuhext.dll", "wuuhmobile.dll", "wuau.dll", "wuautoappupdate.dll")
	foreach($file in $binaries)
	{
		if(test-path "$env:windir\system32\$file") 
		{ 
		   $version = (Get-Command "$env:windir\system32\$file").FileVersionInfo
		   "$file : $($version.FileMajorPart).$($version.FileMinorPart).$($version.FileBuildPart).$($version.FilePrivatePart)" | Out-File -FilePath $OutputFile -append
		} 
	}
	"`n `n"	| Out-File -FilePath $OutputFile -append
	"===================================================="			| Out-File -FilePath $OutputFile -append
	"Windows Update file versions in $env:windir\system32\en-US\"	| Out-File -FilePath $OutputFile -append
	"===================================================="			| Out-File -FilePath $OutputFile -append
	$muis = @("wuapi.dll.mui", "wuaueng.dll.mui", "wucltux.dll.mui", "wusettingsprovider.dll.mui", "wushareduxresources.dll.mui")
	foreach($file in $muis)
	{
		if(test-path "$env:windir\system32\en-US\$file") 
		{ 
		   $version = (Get-Command "$env:windir\system32\en-US\$file").FileVersionInfo
		   "$file : $($version.FileMajorPart).$($version.FileMinorPart).$($version.FileBuildPart).$($version.FilePrivatePart)" | Out-File -FilePath $OutputFile -append
		} 
	}
} #end runFull

# SIG # Begin signature block
# MIIjiAYJKoZIhvcNAQcCoIIjeTCCI3UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAMgE7hJSkTztJU
# jdWlIUIcaJ12jR52Px9s5hXzrYjCD6CCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVXTCCFVkCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBpDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgGpRTuFZZ
# CA73i6/aaTLNtYsnAHXoKHdHnD8KJNwoHMMwOAYKKwYBBAGCNwIBDDEqMCigCIAG
# AFQAUwBToRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20gMA0GCSqGSIb3DQEB
# AQUABIIBAHRL45X4w1Da+jGbnQZ/SUVG7dzAgwL7EAOwrRcKaUoZPIzPD/KVwwG1
# dN3mXoN7Yz6xT2oT5gkyu0TFEw28gfneDHwdh7rwhisRXodzg6Ps95buZHnGUKMO
# 2ez7ItW7sT7kILiokMkzWMp+zhEYFhaC68u+sAfpHtn1o7FVk45XYtgGrz69ecC/
# un2QJ42AJnjZ2UiJEjCeRvqXK216aAGYd6pu911wYf3r+qRn4XqbLB+e0UEFQ6QT
# 2BAzFmjImohSRDaZ/j1NjJRjw/TNC4L/nN6kVkcYRUVs4GthylRyj1g8dS+qHXno
# fcw11J5kM2T3DpUU0VXcf+owQoHM7ZOhghLxMIIS7QYKKwYBBAGCNwMDATGCEt0w
# ghLZBgkqhkiG9w0BBwKgghLKMIISxgIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBVQYL
# KoZIhvcNAQkQAQSgggFEBIIBQDCCATwCAQEGCisGAQQBhFkKAwEwMTANBglghkgB
# ZQMEAgEFAAQgxC5XO43CvtB2jr57k+iCIY0nyB1dXWpsCtFUADnIFwACBmGCCja6
# iBgTMjAyMTExMTExNjUzMzQuNDE5WjAEgAIB9KCB1KSB0TCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkY4
# N0EtRTM3NC1EN0I5MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloIIORDCCBPUwggPdoAMCAQICEzMAAAFji2TGyYWWZXYAAAAAAWMwDQYJKoZI
# hvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjEwMTE0
# MTkwMjIzWhcNMjIwNDExMTkwMjIzWjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVl
# cnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkY4N0EtRTM3NC1EN0I5
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArXEX9hKdyXRikv+o3YWd/CN/SLxr4LgQ
# vPlRnLck5Tnhcf6se/XLcuApga7fCu01IRjgfPnPo9GUQm+/tora2bta8VJ6zuIs
# WFDTwNXiFXHnMXqWXm43a2LZ8k1nokOMxJVi5j/Bph00Wjs3iXzHzv/VJMihvc8O
# JqoCgRnWERua5GvjgQo//dEOCj8BjSjTXMAXiTke/Kt/PTcZokhnoQgiBthsToTY
# tfZwln3rdo1g9kthVs2dO+I7unZ4Ye1oCSfTxCvNb2nPVoYJNSUMtFQucyJBUs2K
# BpTW/w5PO/tqUAidOVF8Uu88hXQknZI+r7BUvE8aGJWzAStf3z+zNQIDAQABo4IB
# GzCCARcwHQYDVR0OBBYEFAk1yvF2cmfuPzFan0bHkD7X3z0pMB8GA1UdIwQYMBaA
# FNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8y
# MDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAt
# MDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJ
# KoZIhvcNAQELBQADggEBAAKIQYIH147iU86OMgJh+xOpqb0ip1G0yPbRQEFUuG5+
# 8/3G+Wgjwtn3A4+riwKglJ2EwtrBRZl3ru8WUz+IE/7teSrXT1Np5BITg1z254zX
# l+US9qjhm3MahZNzGkL5qVhjSRUYiPpLEFLGcKShl6xPjhZUhMFAv/jc+YfFUAUP
# QLVwPPNrme/UJKIO+dnio3Gk/pp/0hh8pskHhsnEGrnYVlVCpHh0Do1rsfixOGHU
# Bj+phzqTOZKmFS8TMKrnE9nz5OWyg01ljPpMBHqqd59PYP/cOyfteY77A2MiLoAR
# ZAkdqrAHtHk5Y7tAnunTtGX/hO+Q0zO9mXwEFJ9ftiMwggZxMIIEWaADAgECAgph
# CYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2
# NTVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvt
# fGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzX
# Tbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+T
# TJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9
# ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDp
# mc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIw
# EAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1V
# MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMB
# Af8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1Ud
# HwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3By
# b2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQRO
# MEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2Vy
# dHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIw
# gY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIg
# HQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4g
# HTANBgkqhkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7P
# BeKp/vpXbRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2
# zEBAQZvcXBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95
# gWXZqbVr5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7
# Yl+a21dA6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt
# 0uGc+R38ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2
# onGqBooPiRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA
# 3+cxB6STOvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7
# G4kqVDmyW9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Ki
# yc8ZQU3ghvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5X
# wdHeMMD9zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P
# 3nSISRKhggLSMIICOwIBATCB/KGB1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMg
# UHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkY4N0EtRTM3NC1E
# N0I5MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEw
# BwYFKw4DAhoDFQDtLGAe3UndKpNNKrMtyswZlAFh76CBgzCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5Te9IjAiGA8y
# MDIxMTExMTIwMDI0MloYDzIwMjExMTEyMjAwMjQyWjB3MD0GCisGAQQBhFkKBAEx
# LzAtMAoCBQDlN70iAgEAMAoCAQACAiM0AgH/MAcCAQACAhEGMAoCBQDlOQ6iAgEA
# MDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAI
# AgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAnqYD8yPvoiw8hILRb1Xu8zXfsM4e
# 3InjK8rlmfNaeQX9PwDsxr7NiWWL1U0ZnZ+7q5hatTb3oyNjyp6aZq2W2oROpP3N
# yfbZMJxTAfvc0u/SLBDAYBRO/K7HBM+bAo3fFFjAugLR3WbsGfb1nyWHzbR+T3Jq
# uGHNhABU8vz1cWExggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAWOLZMbJhZZldgAAAAABYzANBglghkgBZQMEAgEFAKCCAUow
# GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCCvHC6c
# mxIUSz8+Q1dpfHnPqmNUBDn2az3Mv15f7/uDSTCB+gYLKoZIhvcNAQkQAi8xgeow
# gecwgeQwgb0EIJxZ3ZcdoWOhKKQpuLjL0BgEiksHL1FvXqezUasR9CNqMIGYMIGA
# pH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFji2TGyYWWZXYA
# AAAAAWMwIgQgbNyOcP0hXvI1cKvMuGogRKjNurAH+Ok0yUHzs1p6YT0wDQYJKoZI
# hvcNAQELBQAEggEAYZqUXGCETBdHEO8n3KPNloqTHY0PJe9K5GHyR5vusek6uSXP
# MKPvbh+JjphtqBZ8Qg+sUEGWM5tiObbq9JyPfgLjJpYefCfYVLR/QqUPQV1N5fC3
# 0g1wwEwKwElFuf67F2GGIbal5VN/2o+rTBfbbz4Uv7faVic5+RkaZjSrPRdsoaxt
# 0wphvWKi3xL1Em1B3K4ieapg/0HT/CAvsQxgFCkr1Z/18hakdq06wsryHEf+SWUN
# +qUWqSRtbdCu9FSSXd+D5DXSvi6iEuAIAnvGgDy81ZSgwpazA6sFvflusZ92QfLr
# AnmeRsbFUpKtYtnmNrPO/S2y4MiWBzQ5Z8pb4Q==
# SIG # End signature block
