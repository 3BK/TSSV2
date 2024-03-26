#************************************************
# DC_DfsrInfo.ps1
# Version 1.2.0
# Date: 4/19/2010
# By Craig Landis (clandis@microsoft.com)
#************************************************
# 2019-03-17 WalterE added Trap #_# nneds check for DFSrDiag.exe / OSversion?
# 2023-02-08 fix 'CHOICE /T 20 /C 123q'

# 2023-02-20 WalterE mod Trap #we#
trap [Exception]{
	WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; continue
	Write-Host "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_"
}

function MenuDiagInput-CollectDFSR{
    Write-Host -ForegroundColor Yellow 	"============AD Collect DFSR Information =============="
    Write-Host "1: Collect All (=default)"
    Write-Host "2: Collect All But Health-Reports"
    Write-Host "3: Collect Minimal"
	Write-Host "q: Press Q to skip"
}

If ((Get-CimInstance -query "Select ProductType from Win32_OperatingSystem").ProductType -ne 1) {
	$DFSRkey = "HKLM:\SYSTEM\CurrentControlSet\Services\DFSR"
            
	If (Test-Path $DFSRkey){ 
		Import-LocalizedData -BindingVariable DfsrInfoStrings -FileName DC_DfsrInfo -UICulture en-us
		Write-DiagProgress -Activity $DfsrInfoStrings.ID_DfsrInfo -Status $DfsrInfoStrings.ID_DfsrInfoObtaining
		$sectionDescription = "DFSR Miscellaneous"
		$OutputFile = "DFSR__Progress.txt"

		#_#$CollectDFSRInformation_Answer = get-diaginput -id "CollectDFSRInformation"
		MenuDiagInput-CollectDFSR
        #$Selection = Read-Host "Choose the DFSR Information level"
		#$Selection = 
		CHOICE /T 20 /C 123q /D 1 /M "Choose the DFSR Information level: Press 1,2,3,q=quit [Timeout=20sec]"
		#WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): DFSR Selection: $Selection" -shortformat
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): DFSR Selection: $LASTEXITCODE" -shortformat
		switch ($LASTEXITCODE)
			{
				1 {$CommandToExecute = "cscript.exe DfsrInfo.vbs /msdt"}
				2 {$CommandToExecute = "cscript.exe DfsrInfo.vbs /msdt /noreports"}
				3 {$CommandToExecute = "cscript.exe DfsrInfo.vbs /msdt /noreports /nodbguids /nodebuglogs"}
				4 {}
				default {$CommandToExecute = "cscript.exe DfsrInfo.vbs /msdt"}
			}
		<#
		switch ($CollectDFSRInformation_Answer) 
				{
					"CollectAll"					{$CommandToExecute = "cscript.exe DfsrInfo.vbs /msdt"}
					"CollectAllButHealthReports"	{$CommandToExecute = "cscript.exe DfsrInfo.vbs /msdt /noreports"}
					"CollectMinimal"				{$CommandToExecute = "cscript.exe DfsrInfo.vbs /msdt /noreports /nodbguids /nodebuglogs"}
				}
		#>

		RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription "Progress Log"

		CollectFiles -filesToCollect "Dfsr*.log" -fileDescription "DFSR Current Log File" -sectionDescription "DFSR Debug Log Files" -renameOutput $false
		CollectFiles -filesToCollect "Dfsr*.gz" -fileDescription "DFSR Previous Log file" -sectionDescription "DFSR Debug Log Files" -renameOutput $false
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_ConflictAndDeleted.xls") -fileDescription "DFSR Conflicts and Deletes" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_Events_Last_72_Hours.xls") -fileDescription "DFSR Events Last 3 Days" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_File_Versions.txt") -fileDescription "DFSR File Versions" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_Hotfixes.txt") -fileDescription "DFSR Hotfixes" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_Info.txt") -fileDescription "DFSR Configuration Information" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_Performance_Data.txt") -fileDescription "DFSR Performance Data" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_DBGUIDs.txt") -fileDescription "DFSR Database GUIDs" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_DfsrMachineConfig.XML") -fileDescription "XML File" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_RegKey_DFSR.txt") -fileDescription "DFSR Registry Key" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_RegKey_TCPIP.txt") -fileDescription "TCPIP Registry Key" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_Replica*.xml") -fileDescription "XML File" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_Volume*.xml") -fileDescription "XML File" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_Dfsmgmt*.log") -fileDescription "DFS Management Trace Log" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_FSRM_File_Screens.txt") -fileDescription "FSRM File Screens" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect ($ComputerName + "_DFSR_FSRM_Quotas.txt") -fileDescription "FSRM Quotas" -sectionDescription "DFSR Miscellaneous"
		CollectFiles -filesToCollect "*HealthReport*" -fileDescription "Health Report" -sectionDescription "DFSR Health Reports"
	}
}



# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA3XQppCIcPWskT
# F5FaHmfo0K67pJpbAnun/w4/3VC+naCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXUwghlxAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDVYJ3DS+UK1PHeyFdg/GMR9
# uTZdLEal0GiV0kMQLW7OMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAS2BG9Px2pZCGcLMxHecPJAfuFFY78k3j/I0LE9EPnBquNEKNcVhRp
# 9lEA1ws7wPQfr04uYjk+PKAGLQ8D1bxzb7Hw8SKuwwaQ2RBPRcMCqp9QjvtN9na6
# +o9hXO3MCVYaKFNYq9f4Dr1BKk6LELb4pRijIRxezAytdv4BFwJo5RTy24WiMjef
# Rgr2cN+TTrOsknEDC1c9O31Kd+PG74Wl+BYRyHqQn35PvsojJTcBa2QRYEMsxnS5
# OsDrYFYVFIA3pbdyWxL+63m2Od187ViILXcEZXn8Pb01eihJW7Yeo3VCf7JF98FU
# DMLPPvwkTUvA7GleZN+ILHT77rUGagp6oYIW/TCCFvkGCisGAQQBgjcDAwExghbp
# MIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIMP1b2dr2BO0ZW2WgtQ1UO7uDzu+XXBZuruflPmNEFbyAgZj7k8Y
# ZKgYEzIwMjMwMjIwMTUwMDI4Ljg1M1owBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjEyQkMt
# RTNBRS03NEVCMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVDCCBwwwggT0oAMCAQICEzMAAAHKT8Kz7QMNGGwAAQAAAcowDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkw
# MTQwWhcNMjQwMjAyMTkwMTQwWjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MTJCQy1FM0FFLTc0RUIxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDDAZyr2PnStYSRwtKUZkvB5RV/FdFpSOI+zJo1XE90
# xGzcJV7nyyK78SRpW3u3s81M+Sj+zyU226wB4sSfOSLjjLGTZz16SbwTVJDZhX1v
# z8s7F8pqlny1WU/LHDoOYXM0VCOJ9WbwSJnuUVGhjjjy+lxsEPXyqNg0X/ZndJBy
# Fyx1XU31jpXZYaXnlWYuoVFfn52m12Ot4FfOLdZb1OygIRZxgIErnBiBL21PZJJJ
# PNp7eOZ3DjSD4s4jKtU8XYOjORK2/okEM+/BqFdakoak7usesoX6jsQI39WJAUxn
# Kn+/F4+JQAEM2rMRQjyzuSViZ4de+N5A6r8IzcL9jxuPd8k5udkft4Be9EOfFPxH
# pb+4PWYZQm+/0z0Ey7eeEqkqZLHPM7ku1wwSHa0xfGEwYY0xQ/cM4Qrdf7b8sPVn
# Te6wlOTmkc2gf+AMi9unvzsLDjS2wCmIC+2sdjC5vROoi/xnLraXyfyz8y/8/vrg
# JOqvFxfNqUEeH5fLhc+OZp2c+RknJyncpzNuSD1Bu8mnQf/QWzAdL558Wh+kM0nA
# uHWGz9oyLUr+jMS/v9Ysg+wOArXp9T9rHJuowqTQ07GB6VSMBgqXjBTRjpDir03/
# 0/ABLRyyJ9CFjWihB8AjSIMIJIQBOyUPxtM7S1G2p1wh1q85F6rOg928C/cOvVdd
# DwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFPrH/qVLgRJDwpmF3RGBTtFhczx/MB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBANjQeSoJLcq4p58Vfz+ub920P3Trp0oSV42quLBmqwzhibwTDhCKo6o7uZah
# hhjgrnLx5dI4co1c5+k7pFtpiPyMI5wkAHm2ouXmGIyBoxsBUuuXWGWLH2yWg7jk
# s43QmmEq9rcPoBUoDs/vyYD2JEdlhRWtGLJ+9CNbGZSfGGKzx+ib3b79EdwRnUOH
# n6niDN54vzhiXTRbKr0RyAEop+CrSUKNY1KrUBQbWwQuWBc5K8pnj+Vdcf4x+Fwd
# 73VYshpmRL8e73B1NPojXgEL3vKEOxlZcCXQgnzTUjpS0QWkKxN47JkEnsIXSt/m
# XEny0T2iM2zKpckq7BWfR7AIyRmrP9wTC/0UTHxCaxnRk2h1O2yX5X11mb55Sswp
# mTo8qwoCu1D6MeR9WweAo4OWh6Wk6YeqBftRs7Q1WciWk/nmBBOpXvq9TvBFelR/
# PsqETcFlc2DAbTl1GcJcPCuGFjP4i1vOzUrVHwjhgwMmNb3QBIKD0l/7HKBEpkYo
# eOjYGzZfJoq43U/oUUIhVc3sqAeX9tmJqQaruTlNDg5crnGSEIeGN2Ae7GPeErkB
# o7L4ZfE7+NvKoZGp5LF/5NM+5aENa6sijfdEwMZ7kNsiaNxtyPp1WFB6+ocKVHU4
# dJ+v7ybWFZEkaULVq1w5YpqMCvA5RGolJWVOHBWAjLMY2aPOMIIHcTCCBVmgAwIB
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
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAsswggI0AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjoxMkJDLUUzQUUtNzRFQjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAo47nlwxPizI8/qcKWDYhZ9qMyqSg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOedasswIhgPMjAyMzAyMjAxMTQzMDdaGA8yMDIzMDIyMTExNDMwN1ow
# dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA551qywIBADAHAgEAAgInljAHAgEAAgIR
# qzAKAgUA5568SwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBABE4uFgk5z5U
# LwrTCr76tHEElOEfvGK1hpvlKszbVa/CVUg2oRekUzHUkl05+rJMciNotjSO2Q8P
# fTSrBvCfxyKzYMl1cSoPKFKVfwWIbt2WR/qwXqkJ5iAXRXI1Xj0hklT1HEO0T1Dw
# hOXwpfwIIsAQEqrkdMDaOFV8pVbNMUY9MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHKT8Kz7QMNGGwAAQAAAcowDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQg1qJSzVVlB3R5h/u8aXfRBOopZIS7G2/nnXDOPntMp4EwgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCATPRvzm+tVTayVkCTiO3VIMSTojNkDBUKh
# bAXcrNwa4DCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAAByk/Cs+0DDRhsAAEAAAHKMCIEIIZKNW8rK20jbK1NDV2CWMYd9WW+bBVIuhEQ
# rseCWyC6MA0GCSqGSIb3DQEBCwUABIICAGNBkXflTVzxsrLLahqP8WYqJwvsP/eo
# SmRUwFelt6rOEgloKS+qPKVIc7JbPQZFWkxZ8TQBaYps5JZ2WUb5N1b+snu6QdlK
# 2GYRi643vpt/0Mj4m8SPzLd0NfKx6cPsaWwzTm3lUT8wWCE3vKsHafiyWNFgcu05
# mABxS/v3+11bGbgDSPiwNZ0brSIolbRIDt7IL3/UG7XVY/8hdpJXwKU1qnrKoFdv
# qk4SwHqxvM6IrM+CYMEUVUb6I5niB2w/Nll/Xy4dNbeeBO1xdUQliWBfotjPYm1N
# PtX9uFicM94+FIeCyozhUfupCsIM3JIP3u4o9gol28nVUq3HrDSDRC9FFzkTQd5B
# BFAoEL0SywZ43qeh1cz4+7VJv61DWUfXb8oc6M42DygdzA0jzTok1ZLRdiqky/MC
# 60IazW8j5exGTXeilxSuO1WfanvdieVf5eL0AKkVzaQ1ZrNqFTAdlN+q8QwN6oy1
# gQ7/v9BGU4O364p4bWd/hFkttecgVzOix3ouljd6nxeb1uBPelXZXucchDlNIyra
# 6vmOulTSH8W6WVdG9ATa+XEGQZXHBpKOAo0NYa1iSL5UkImgYuWt9l809a00cpt9
# q/Dz8+LXFzyLLFmBVnrXWAzxBMxItVfWkXqfCkGIY0SEtKDBThYezMvA4baOpwLc
# VIIchtQpmhl9
# SIG # End signature block
