#************************************************
# DC_ChkSym_DPM.ps1
# Version 1.0.0
# Date: 12-07-2010
# Author: Patrick Lewis - patlewis@microsoft.com
# Description: This script calls chksym to get file version information from DPM files and other files
#************************************************
PARAM($range="All", $prefix="_sym", $FolderName=$null, $FileMask=$null, $Suffix=$null, $FileDescription = $null, [switch] $Recursive)

$ProcArc = $Env:PROCESSOR_ARCHITECTURE
$ChkSymExe = "Checksym" + $ProcArc + ".exe"

$Error.Clear

Import-LocalizedData -BindingVariable LocalsCheckSym -FileName DC_ChkSym

trap [Exception] 
{
	$errorMessage = $Error[0].Exception.Message
	$errorCode = $Error[0].Exception.ErrorRecord.FullyQualifiedErrorId
	$line = $Error[0].InvocationInfo.PositionMessage
	"[DC_ChkSym] Error " + $errorCode + " on line " + $line + ": $errorMessage running dc_chksym.ps1" | WriteTo-StdOut -ShortFormat
	$error.Clear
}

function GetExchangeInstallFolder
{
	If ((Test-Path "HKLM:SOFTWARE\Microsoft\ExchangeServer\v14") -eq $true){
		[System.IO.Path]::GetDirectoryName((get-itemproperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup).MsiInstallPath)
	} ElseIf ((Test-Path "HKLM:SOFTWARE\Microsoft\Exchange\v8.0") -eq $true) {
		[System.IO.Path]::GetDirectoryName((get-itemproperty HKLM:\SOFTWARE\Microsoft\Exchange\Setup).MsiInstallPath)
	} Else { 
		$null
	}
}

# function GetDPMInstallFolder
# {
#	if ((Test-Path "HKLM:SOFTWARE\Microsoft\Microsoft Data Protection Manager\Setup") -eq $true)
#	{
#		(get-itemproperty HKLM:\SOFTWARE\Microsoft\"Microsoft Data Protection Manager"\Setup).InstallPath
#	} Else {
#		$null
#	}
# }

Function FileExistOnFolder($PathToScan, $FileMask, [switch] $Recursive) 
{
	trap [Exception] {
	
		$ErrorStd = "[FileExistOnFolder] The following error ocurred when checking if a file exists on a folder:`n" 
		$errorMessage = $Error[0].Exception.Message
		$errorCode = $Error[0].Exception.ErrorRecord.FullyQualifiedErrorId
		$line = $Error[0].InvocationInfo.PositionMessage
		"$ErrorStd Error " + $errorCode + " on line " + $line + ": $errorMessage`n   Path: $PathToScan`n   FileMask: $FileMask" | WriteTo-StdOut -ShortFormat
		 $error.Clear
		 continue
	}
	
	$AFileExist = $false
	
	foreach ($mask in $FileMask) {
		if ($AFileExist -eq $false) {
			if ([System.IO.Directory]::Exists($PathToScan)) {
				if ($Recursive.IsPresent)
				{
					$Files = [System.IO.Directory]::GetFiles($PathToScan, $mask,[System.IO.SearchOption]::AllDirectories)
				} else {
					$Files = [System.IO.Directory]::GetFiles($PathToScan, $mask,[System.IO.SearchOption]::TopDirectoryOnly)
				}
				$AFileExist = ($Files.Count -ne 0)
			}
		}
	}
	return $AFileExist
}

Function RunChkSym ([string]$PathToScan="", [array]$FileMask = "*.*", [string]$Output="", [boolean]$Recursive=$false, [string]$Arguments="", [string]$Description="")
{
	if (($Arguments -ne "") -or (Test-Path ($PathToScan))) 
	{
		if ($PathToScan -ne "")
		{
			$eOutput = $Output
			ForEach ($scFileMask in $FileMask){ #
				$eFileMask = ($scFileMask.replace("*.*","")).toupper()
				$eFileMask = ($eFileMask.replace("*.",""))
				$eFileMask = ($eFileMask.replace(".*",""))
				if (($eFileMask -ne "") -and (Test-Path ("$eOutput.*") )) {$eOutput += ("_" + $eFileMask)}
				$symScanPath += ((Join-Path -Path $PathToScan -ChildPath $scFileMask) + ";")
			}
		}
		
		if ($Description -ne "") 
		{
			$FileDescription = $Description
		} else {
			$fdFileMask = [string]::join(";",$FileMask)
			if ($fdFileMask -contains ";") { 
				$FileDescription = $PathToScan + " [" + $fdFileMask + "]"
			} else {
				$FileDescription = (Join-Path $PathToScan $fdFileMask)
			}
		}
	

		if ($Arguments -ne "") {
			$eOutput = $Output
			Write-DiagProgress -Activity $LocalsCheckSym.ID_FileVersionInfo -Status $Description
			$CommandToExecute = "cmd.exe /c $ChkSymExe $Arguments"
			}
		else {
			Write-DiagProgress -Activity $LocalsCheckSym.ID_FileVersionInfo -Status ($FileDescription)# + " Recursive: " + $Recursive)
			if ($Recursive -eq $true) {
				$F = "-F2"
				$AFileExistOnFolder = (FileExistOnFolder -PathToScan $PathToScan -FileMask $scFileMask -Recursive) 
			} else {
				$F = "-F"
				$AFileExistOnFolder = (FileExistOnFolder -PathToScan $PathToScan -FileMask $scFileMask)
			}
			if ($AFileExistOnFolder) {
				
				$CommandToExecute = "cmd.exe /c $ChkSymExe $F `"$symScanPath`" -R -S -O2 `"$eOutput.CSV`" > `"$eOutput.TXT`""
			} else {
				"Chksym did not run against path '$PathToScan' since there are no files with mask ($scFileMask) on system" | WriteTo-StdOut -ShortFormat
				$CommandToExecute = ""
			}
		}
		if ($CommandToExecute -ne "") {
			RunCmD -commandToRun $CommandToExecute -sectionDescription "File Version Information (ChkSym)" -filesToCollect ("$eOutput.*") -fileDescription $FileDescription -BackgroundExecution
		}
	}
	else {
		"Chksym did not run against path '$PathToScan' since path does not exist" | WriteTo-StdOut -ShortFormat
	}
}


#Check if using $FolderName or $RangeString
if (($null -ne $FolderName) -and ($null -ne $FileMask) -and ($null -ne $Suffix)) {
	$OutputBase = $ComputerName + $Prefix + $Suffix
	$IsRecursive = ($Recursive.IsPresent)
	RunChkSym -PathToScan $FolderName -FileMask $FileMask -Output $OutputBase  -Description $FileDescription -Recursive $IsRecursive
} else {
	[array] $RunChkSym = $null
	Foreach ($RangeString in $range) 
	{
		if ($RangeString -eq "All")	
		{
			$RunChkSym += "ProgramFilesSys", "Drivers", "System32DLL", "System32Exe", "System32SYS", "Spool", "iSCSI", "Process", "RunningDrivers", "Cluster"
		} else {
			$RunChkSym += $RangeString
		}
	}

	switch ($RunChkSym)	{
		"ProgramFilesSys" {
			$OutputBase="$ComputerName$Prefix" + "_ProgramFiles_SYS"
			RunChkSym -PathToScan "$Env:ProgramFiles" -FileMask "*.sys" -Output $OutputBase -Recursive $true
			if (($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") -or $Env:PROCESSOR_ARCHITECTURE -eq "IA64")  {
				$OutputBase="$ComputerName$Prefix" + "_ProgramFilesx86_SYS"
				RunChkSym -PathToScan (${Env:ProgramFiles(x86)}) -FileMask "*.sys" -Output $OutputBase -Recursive $true
			}
			}
		"Drivers" {
			$OutputBase="$ComputerName$Prefix" + "_Drivers"
			RunChkSym -PathToScan "$Env:SystemRoot\System32\drivers" -FileMask "*.*" -Output $OutputBase -Recursive $false
			}
		"System32DLL" {
			$OutputBase="$ComputerName$Prefix" + "_System32_DLL"
			RunChkSym -PathToScan "$Env:SystemRoot\System32" -FileMask "*.DLL" -Output $OutputBase -Recursive $false
			if (($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") -or $Env:PROCESSOR_ARCHITECTURE -eq "IA64")  {
				$OutputBase="$ComputerName$Prefix" + "_SysWOW64_DLL"
				RunChkSym -PathToScan "$Env:SystemRoot\SysWOW64" -FileMask "*.dll" -Output $OutputBase -Recursive $true
			}
			}
		"System32Exe" {
			$OutputBase="$ComputerName$Prefix" + "_System32_EXE"
			RunChkSym -PathToScan "$Env:SystemRoot\System32" -FileMask "*.EXE" -Output $OutputBase -Recursive $false
			if (($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") -or $Env:PROCESSOR_ARCHITECTURE -eq "IA64")  {
				$OutputBase="$ComputerName$Prefix" + "_SysWOW64_EXE"
				RunChkSym -PathToScan "$Env:SystemRoot\SysWOW64" -FileMask "*.exe" -Output $OutputBase -Recursive $true
			}
			}
		"System32SYS" {
			$OutputBase="$ComputerName$Prefix" + "_System32_SYS"
			RunChkSym -PathToScan "$Env:SystemRoot\System32" -FileMask "*.SYS" -Output $OutputBase -Recursive $false
			if (($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") -or $Env:PROCESSOR_ARCHITECTURE -eq "IA64")  {
				$OutputBase="$ComputerName$Prefix" + "_SysWOW64_SYS"
				RunChkSym -PathToScan "$Env:SystemRoot\SysWOW64" -FileMask "*.sys" -Output $OutputBase -Recursive $true
			}
			}
		"Spool" {
			$OutputBase="$ComputerName$Prefix" + "_PrintSpool"
			RunChkSym -PathToScan "$Env:SystemRoot\System32\Spool" -FileMask "*.*" -Output $OutputBase -Recursive $true
			}
		"Cluster" {
			$OutputBase="$ComputerName$Prefix" + "_Cluster"
			RunChkSym -PathToScan "$Env:SystemRoot\Cluster" -FileMask "*.*" -Output $OutputBase -Recursive $false
			}
		"iSCSI" {
			$OutputBase="$ComputerName$Prefix" + "_MS_iSNS"
			RunChkSym -PathToScan "$Env:ProgramFiles\Microsoft iSNS Server" -FileMask "*.*" -Output $OutputBase -Recursive $true
			$OutputBase="$ComputerName$Prefix" + "_MS_iSCSI"
			RunChkSym -PathToScan "$Env:SystemRoot\System32" -FileMask "iscsi*.*" -Output $OutputBase -Recursive $false
			}
		"Process" {
			$OutputBase="$ComputerName$Prefix" + "_Process"
			get-process | Out-File "$OutputBase.txt"
			"--------------------------------" | Out-File "$OutputBase.txt" -append
			tasklist -svc | Out-File "$OutputBase.txt" -append
			"--------------------------------" | Out-File "$OutputBase.txt" -append
			RunChkSym -Output $OutputBase -Arguments "-P * -R -O2 `"$OutputBase.CSV`" >> `"$OutputBase.TXT`"" -Description "Running Processes"
			}
		"RunningDrivers" {
			$OutputBase="$ComputerName$Prefix" + "_RunningDrivers"
			RunChkSym -Output $OutputBase -Arguments "-D -R -S -O2 `"$OutputBase.CSV`" > `"$OutputBase.TXT`"" -Description "Running Drivers"
			}
		"InetSrv" {
			$inetSrvPath = (join-path $env:systemroot "system32\inetsrv")
			$OutputBase = "$ComputerName$Prefix" + "_InetSrv"
			RunChkSym -PathToScan $inetSrvPath -FileMask ("*.exe","*.dll") -Output $OutputBase -Recursive $true
		}
		"Exchange" {
			$ExchangeFolder = GetExchangeInstallFolder
			if ($null -ne $ExchangeFolder){
				$OutputBase = "$ComputerName$Prefix" + "_Exchange"
				RunChkSym -PathToScan $ExchangeFolder -FileMask ("*.exe","*.dll") -Output $OutputBase -Recursive $true
			} else {
				"Chksym did not run against Exchange since it could not find Exchange server installation folder" | WriteTo-StdOut -ShortFormat
			}
		}
		"DPM" 
		{
			$DPMFolder= GetDPMInstallFolder # This function can be found on file Functions.ps1
			If ($null -ne $DPMFolder)
			{
				$DPMFolder = Join-Path $DPMFolder "bin"
				$OutputBase= "$ComputerName$Prefix" + "_DPM"
				RunChkSym -PathToScan $DPMFolder -FileMask("*.exe","*.dll") -Output $OutputBase -Recursive $true
			} else {
				"Chksym did not run against DPM since it could not find the DPM installation folder" | WriteTo-StdOut -ShortFormat
			}
		}	
	}
}


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAXz2t+QWE+inbQ
# VizcvZEWseY8wlZ2S/M19D5CDeKw8aCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBP7tsnCQnHC85p6PYbMX1GW
# 3Pu35NCXtGcKQK7OgIq/MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAepIAxebTfx0yaoMggHFFHHgHUZ8n7aRwvJJNAJTf6FgtaAWTBwsV/
# cIAx+HwG/ZETo/Tbf6ttbUXzfb5yK0tIuonr2xnpRpnbbwlJQQq/17K1LZJyNi69
# QVJfJWwwH+AamplRitE2qGxx6wbzyOqOTa9rp4jtZVjhNz7M5e6oY/s+tEGHsozP
# AjCWMiYt8HZK+Fi5LiAG21nCeM2LXkJtBT/az0gi6rBZfWIistkcMBCK8/FpiTxQ
# Gc5u1YaNOkihxUPredPsJX2LMvMwqc7+EltNly8bX2tZGwzp0gh347jCcQb8eLB9
# FlCldAs9BHP5w18jS6eyoR3JebPKv8zeoYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIPcsJP/duNv3emk4YbJ47W5DjCcJNVvtO1yOZHfCpnzJAgZi3mrX
# yNYYEzIwMjIwODAxMDczNTI5LjQ0NFowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046MDg0Mi00QkU2LUMyOUExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAYdCFmYEXPP0jQABAAABhzAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3MzlaFw0yMzAxMjYxOTI3MzlaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjA4NDIt
# NEJFNi1DMjlBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvml4GWM9A6PREQiHgZAA
# PK6n+Th6m+LYwKYLaQFlZXbTqrodhsni7HVIRkqBFuG8og1KZry02xEmmbdp89O4
# 0xCIQfW8FKW7oO/lYYtUAQW2kp0uMuYEJ1XkZ6eHjcMuqEJwC47UakZx3AekakP+
# GfGuDDO9kZGQRe8IpiiJ4Qkn6mbDhbRpgcUOdsDzmNz6kXG7gfIfgcs5kzuKIP6n
# N4tsjPhyF58VU0ZfI0PSC+n5OX0hsU8heWe3pUiDr5gqP16a6kIjFJHkgNPYgMiv
# GTQKcjNxNcXnnymT/JVuNs7Zvk1P5KWf8G1XG/MtZZ5/juqsg0QoUmQZjVh0XRku
# 7YpMpktW7XfFA3y+YJOG1pVzizB3PzJXUC8Ma8AUywtUuULWjYT5y7/EwwHWmn1R
# T0PhYp9kmpfS6HIYfEBboYUvULW2HnGNfx65f4Ukc7kgNSQbeAH6yjO5dg6MUwPf
# zo/rBdNaZfJxZ7RscTByTtlxblfUT46yPHCXACiX/BhaHEY4edFgp/cIb7XHFJbu
# 4mNDAPzRlAkIj1SGuO9G4sbkjM9XpNMWglj2dC9QLN/0geBFXoNI8F+HfHw4Jo+p
# 6iSP8hn43mkkWKSGOiT4hLJzocErFntK5i9PebXSq2BvMgzVc+BBvCN35DfD0mok
# RKxam2tQM060SORy3S7ucesCAwEAAaOCATYwggEyMB0GA1UdDgQWBBQiUcAWukEt
# YYF+3WFzmZA/DaWNIDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQC5q35T2RKjAFRN/3cYjnPFztPa7KeqJKJnKgvi
# Uj9IMfC8/FQ2ox6Uwyd40TS7zKvtuMl11FFlfWkEncN3lqihiSAqIDPOdVvr1oJY
# 4NFQBOHzLpetepHnMg0UL2UXHzvjKg24VOIzb0dtdP69+QIy7SDpcVh9KI0EXKG2
# bolpBypqRttGTDd0JQkOtMdiSpaDpOHwgCMNXE8xIu48hiuT075oIqnHJha378/D
# pugI0DZjYcZH1cG84J06ucq5ygrod9szr19ObCZJdJLpyvJWCy8PRDAkRjPJglSm
# fn2UR0KvnoyCOzjszAwNCp/JJnkRp20weItzm97iNg+FZF1J9E16eWIB1sCr7Vj9
# QD6Kt+z81rOcLRfxhlO2/sK09Uw+DiQkPbu6OZ3TsDvLsr8yG9W2A8yXcggNqd4X
# pLtdEkf52OIN0GgRLSY1LNDB4IKY+Zj34IwMbDbs2sCig5Li2ILWEMV/6gyL37J7
# 1NbW7Vzo7fcGrNne9OqxgFC2WX5degxyJ3Sx2bKw6lbf04KaXnTBOSz0QC+RfJuz
# 8nOpIf28+WmMPicX2l7gs/MrC5anmyK/nbeKkaOx+AXhwYLzETNg+1Icygjdwnbq
# WKafLdCNKfhsb/gM5SFbgD5ATEX1bAxwUFVxKvQv0dIRAm5aDjF3DZpgvy3mSojS
# rBN/8zCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
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
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MDg0Mi00QkU2LUMyOUExJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAHh3k1QEKAZEhsLGYGHtf/6DG4PzoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmkXrqMCIYDzIwMjIwODAx
# MDYwNDI2WhgPMjAyMjA4MDIwNjA0MjZaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaReuoCAQAwBwIBAAICHj8wBwIBAAICES4wCgIFAOaSzGoCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQCF/hfbIZQ0IEk6Kh2lseeEtTISZpszbfBnEeumjmWO
# 0hdqTDaefoW0+b7u5tEPoWvT2Y26R/5PThTeB8JmkwcqCENPZii9O+oZLx+a5Iou
# 6CKUmF9a1B/JSMc0nzpCTZddlgNPs96jeJuJfSrQ0BGHRHmxERqh1JwzqpL2X6pr
# 5TGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABh0IWZgRc8/SNAAEAAAGHMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIM2xZ8UFQjhARIt+YwSd
# S5N2NYrN/8IHmY+O9Z7XQq81MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# xCzwoBNuoB92wsC2SxZhz4HVGyvCZnwYNuczpGyam1gwgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYdCFmYEXPP0jQABAAABhzAiBCDA
# p3m7l8Nc7DlqiRsVc7ZPNSsKmHhdZilO6Ifx7KEsVTANBgkqhkiG9w0BAQsFAASC
# AgAiZlxS/QZoOH0Exbxk5QxJHfa1+XoYn5QFkKMYKuSGLm4PO+dgiyCu24NJ4ewH
# BUtODSfDzpgjZQocOlX9JOl9DqoZpwgQ/tbE61xGQ2DI79b6sOIqVWmbYRJOAAC1
# brzfXlwtxzGGtX5XKi2yW/XET/SbS/x15CEd/6nqymj+VOsMdNWGA2VwKar3ia9a
# QH3hSp6K+jAtyygiwaMpRNTeW153eJBCCRUZo/HeWOCkdm4HYH0M8vTM8dh6X5dw
# h9nJ5XNDQYSkg49aHXNcDdEaNjy8J+WO58YihnVyMM8zGPRQR9QC8GPbcIXfU4oW
# m39eiSwnUgya6Yh8p4qcmcBm2NqfrNCbRHA5rnFB6ydjYuHP6PBpRXefpJVd3eLj
# CwMSitqB0Lnit6Cz0mDdiJhmzykbIn0YyfxG6vE437ErbhLRQBQT2oyr3Rvzx7ki
# fAFiyqDYXD4es+hjhT7XCpNI0QTIb3usN4ms6tIWj3BGLuzgirNZggDK/TKYu/DM
# AD+0hcTv9d54/mz7MB9EtffixLkb/QpkoqACr1YfM3yrL/t2S6H5tS04TMbrTZcw
# dLb2oHc5V7/+EivizD9xg+s+L6epECS+RgPB16MpasJ0/gNs60Bxk1tg8CIGywYn
# oVKx9u89MnW+tQ4hw1k+Uugf4tk/o2HXBA+FtBMuZlOrTg==
# SIG # End signature block
