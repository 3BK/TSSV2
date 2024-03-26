#************************************************
# .ps1
# Version 1.0
# Date: 2009-2019
# Author: Walter Eder (waltere@microsoft.com)
# Description: Collects Windows Store information.
# Called from: TS_AutoAddCommands_Apps.ps1
#*******************************************************

Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
		 # later use return to return the exception message to an object:   return $Script:ExceptionMessage
	}

Write-verbose "$(Get-Date -UFormat "%R:%S") : Start of script DC_WinStoreCollect.ps1"

"Starting WinStoreCollect.ps1 script" | WriteTo-StdOut
"============================================================" | WriteTo-StdOut
#_# Import-LocalizedData -BindingVariable ScriptStrings

# Registry keys
"Getting Windows Store Registry Keys." | WriteTo-StdOut

$Regkeys = "HKLM\Software\Policies\Microsoft\WindowsStore"
$OutputFile = $ComputerName + "_Regkeys_WindowsStorePolicies_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "WindowsStore Policies Registry Key" -SectionDescription "Software Registry keys" 

$Regkeys = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WSService\Packages" 
$OutputFile = $ComputerName + "_Regkeys_WSServicePackages_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "WSService Packages Registry Key" -SectionDescription "Software Registry keys"

# Saved Directories
"Getting Copies of Windows Store files" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_WindowsStorefiles_Title -Status $ScriptStrings.ID_WindowsStorefiles_Status
$sectionDescription = "Windows Store files"
if(test-path "$env:windir\ImmersiveControlPanel")
{
	$DesinationTempFolder = Join-Path ($PWD.Path) ([System.Guid]::NewGuid().ToString())
	Copy-Item "$env:windir\ImmersiveControlPanel" -Destination $DesinationTempFolder -Force -Recurse -ErrorAction SilentlyContinue
	CompressCollectFiles -filesToCollect $DesinationTempFolder -DestinationFileName "ImmersiveControlPanel.zip" -fileDescription "Files under \Windows\ImmersiveControlPanel" -sectionDescription $sectionDescription -Recursive
	Remove-Item $DesinationTempFolder -Force -Recurse
}
if(test-path "$env:localappdata\Packages\WinStore_cw5n1h2txyewy\AC\Temp\Winstore.log")
{
	CollectFiles -filesToCollect "$env:localappdata\Packages\WinStore_cw5n1h2txyewy\AC\Temp\Winstore.log" -fileDescription "Winstore log" -sectionDescription $sectionDescription
}
if(test-path "$env:localappdata\Temp\WinStore.log")
{
	CollectFiles -filesToCollect "$env:localappdata\Temp\WinStore.log" -fileDescription "Broker log" -sectionDescription $sectionDescription
}

# Directory Listings
"Getting Directory Listing of Windows Store files" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_WindowsStoreDirectoryListings_Title -Status $ScriptStrings.ID_WindowsStoreDirectoryListings_Status
$sectionDescription = "Windows Store Directory Listings"
if(test-path "$env:localappdata\Microsoft\Windows Store\Checkpoints")
{
	Get-ChildItem -Recurse "$env:localappdata\Microsoft\Windows Store\Checkpoints" >> "DirList_CheckPointDir.txt"
	CollectFiles -filesToCollect "DirList_CheckPointDir.txt" -fileDescription "CheckPoint Directory Listings" -sectionDescription $sectionDescription
}
if(test-path "$env:windir\Winstore")
{
	Get-ChildItem -Recurse "$env:windir\Winstore"                                  >> "DirList_WinStoreDir.txt"
	CollectFiles -filesToCollect "DirList_WinStoreDir.txt" -fileDescription "WinStore Directory Listings" -sectionDescription $sectionDescription
}

# Event Logs
"Getting Windows Store Event Logs" | WriteTo-StdOut
$sectionDescription = "Event Logs"
$EventLogNames = "Microsoft-WS-Licensing/Admin"
Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription

# Running WSRun application:
if ($Global:skipHang -ne $true) {
	"__ value of Switch skipHang: $Global:skipHang  - 'True' will suppress some WSRun output `n`n"        | WriteTo-StdOut
	$sectionDescription = "WinStore package and licensing information"
	$OSProcessorArch = $Env:PROCESSOR_ARCHITECTURE
	$ToolName = "wsrun" + $OSProcessorArch + ".exe"
	$OutputFile = $ComputerName + "_WSRunResults.log"
	$CommandLineToExecute = "cmd.exe /c $ToolName WSRunCommand.wsrun > $OutputFile"
	"Executing $CommandLineToExecute to get WinStore package and licensing information" | WriteTo-StdOut
	Write-DiagProgress -Activity $ScriptStrings.ID_WSRuntool_Title -Status $ScriptStrings.ID_WSRuntool_Status
	RunCmD -commandToRun $CommandLineToExecute	-filesToCollect "WSRunResults.log" -fileDescription "WinStore package and licensing information" -sectionDescription $sectionDescription
}else{ "skip the WSRun step because of -SkipHang" | WriteTo-StdOut}
Write-verbose "$(Get-Date -UFormat "%R:%S") :   end of script DC_WinStoreCollect.ps1"



# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBELYFElPsBmO4T
# RN6MpHEhGwcl30zzg6iNaQy0aSC2u6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBRV5ybHGbqXifzQHRlUMVRq
# WpodB161Gix7NVxZVBtrMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCz4BYFapuf7oSt+FntoUkEhm6XfMx1QBvv/4vbeDUbj4UIrZcoAkTg
# ftHwOlx75ALbJmqU9PKNJhWbiyL8sd2swVQSpEhwgycqb61SHKo5t5sBmQVkSzMs
# frsRGOzj23cqc390ESD9KpD5zru8qzQ2f+DuIhh9zKNAPt/Ll0JZoVBatMwlo/EM
# s/nXR/+34gzg4L7XsALnze9EGCdQ7+MmzSmFZovpg6OJMT8c+mgHmjL5GJKvNBNx
# /GuoKh0kWgSu+Wc0h2LbHjdS2I2lIVYL9exgHOQb0Bucd7r3LNNI/wDbEAOnFAGz
# 5Twzc1zhVVymkJfqr2rNXzRc/toCDlFkoYIW/TCCFvkGCisGAQQBgjcDAwExghbp
# MIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEICivSUQPNKTrsqZ0yUMVSSEbaEpFF/tcrQ4fpqo6d+Y9AgZkN+l/
# 310YEzIwMjMwNDI2MTk1NTA5LjAyNVowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkVBQ0Ut
# RTMxNi1DOTFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVDCCBwwwggT0oAMCAQICEzMAAAHDi2/TSL8OkV0AAQAAAcMwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkw
# MTI5WhcNMjQwMjAyMTkwMTI5WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RUFDRS1FMzE2LUM5MUQxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC767zqzdH+r6KSizzRoPjZibbU0M5m2V01HEwVTGbi
# j2RVaRKHZzyM4LElfBXYoWh0JPGkZCz2PLmdQj4ur9u3Qda1Jg8w8+163jbSDPAz
# USxHbqRunCUEfEVjiGTfLcAf7Vgp/1uG8+zuQ9tdsfuB1pyK14H4XsWg5G317QP9
# 2wF4bzQZkAXbLotYCPoLaYyqVp9eTBt9PJBqe5frli77EynInV8BESm5Hvrqt4+u
# qUTQppp4PSeo6AatORJl4IwM8fo60nTSNczBsgPIfuXh9hF4ixN/M3kZ/dRqKuyN
# 5r4oXLbaVTx6WcheOh7LHelx6wf6rlqtjVzoc995KeR4yiT+DGcHs/UyO3sj0Qj2
# 2FC0y/L/VJSYsbXasFH8N+F4T9Umlyb9Nh6hXXU19BCeX+MFs9tJEGnQcapMhxYO
# ljoyBJ0GhARPUO+kTg9fiyd00ZzXAbKDjmkfrZkx9QX8LMZnuJXrftG2dAVcPNPG
# hIQSR1cx1YMkb6OPGgLXqVGTXEWd+QDi6iZriYqyjuq8Tp3bv4rrLMhJZDtOO61g
# somdLM29+I2K7K//THEIBJIBG85De/1x6C8z+me5T1zqz7iCYrf7mOFy+dYZCokT
# S2lgeaTduaYEvWAeb1OMEnPmb/yu8czdHDc5SFXj/CYAvfYqY9HlRtvjDDkc0aK5
# jQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFBwYvs3Y128BorxNwuvExOxrxoHWMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAN3yplscGp0EVEPEYbAOiWWdHJ3RaZSeOqg/7lAIfi8w8G3i6YdWEm7J5GQM
# QuRNZm5aordTXPYecZq1ucRNwdSXLCUf7cjtHt9TTMpjDY8sD5VrAJyuewgKATfb
# jYSwQL9nRhTvjQ0n/Fu7Osa1MS1QiJC+vYAI8nKGw+i17wi1N/i41bgxujVA/S2N
# wEoKAR7MgLgNhQzQFgJYKZ5mY3ACXF+lOWI4UQoH1RpKodKznVwfwljSCovcvAj0
# th+MQ7vv74dj+cypcIyL2KFQqginZN+N/N2bk2DlX7LDz7BeXb1FxbhDgK8ee018
# rFP2hDcntgFBAQdYk+DxM1H3DgHzYXOasN3ywvoRO8a7HmEVzCYX5DatPkxrx1hR
# J0JKD+KGgRhQYlmdkv2fIOnWyd+VJVfsWkvIAvMMOUcFbUImFhV98lGirPUPiRGi
# ipEE1FowUw+KeDLDBsSCEyF4ko2h1rsAaCr7UcfVp9GUT72phb0Uox7PF5CZ/yBy
# 4C6Gv0gBfJoX0MXQ8nl/i6HM5K8gLUGQm3MXqinjlRhojtX71fx1zBdtkmcggAfV
# yNU7woQKHEoiSmThCDLQ+hyBTBoZaqYtZG7WFDVYladBe+8Fh5gMZZuP8+1KXLC/
# qbya6Mt6l8y8lxTbkpaSVI/YW43Hpo5V96N76mBvAhAhVDWdMIIHcTCCBVmgAwIB
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
# IEVTTjpFQUNFLUUzMTYtQzkxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA8R0v4+z6HTd75Itd0bO5ju0u7s6g
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOfziw0wIhgPMjAyMzA0MjYxOTM1NDFaGA8yMDIzMDQyNzE5MzU0MVow
# dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5/OLDQIBADAHAgEAAgIJcDAHAgEAAgIR
# tDAKAgUA5/TcjQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAFm7Z/xZM4KJ
# cwCGG+FL7aUYyCouBcbkMq8FJ0Le8dN9PouwGpciM2UhLZULqQQEledlO8rKt8xX
# IeRnE4ysKZORBgmQOojLzZfyrkoEH11LEid8bfrBsXc+K7IYDKMksMsYvAnkgfen
# vPFFIRV1mEWNcbDPZOR+46OXOJ7rYmIYMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHDi2/TSL8OkV0AAQAAAcMwDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgFiIMlkgB7mjE3rQ0yy89iodeqIHt2dXx95I2jcxyN/owgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCDS+1Obb5JJ6uHUqICTCslMAvFN8mi2U9wN
# nZlKfvwqSTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABw4tv00i/DpFdAAEAAAHDMCIEIJxL8W2ZWUiPeEj//l8ZeBHMDLIOsXt6UGDb
# DuScEICvMA0GCSqGSIb3DQEBCwUABIICAFLZUoFtdlM24G14/rLJO/QFa0X2GSU2
# r/Cf9+hd8CJpniksn1sXqdpuAo4ZGsILwtwI1YxpkSILQuwZ9Sy+GQ5335SMJ0i/
# iOrEvV4fx4Fa8DlwMbHDTcTr3zRkX0MLHy2Sthb4YuFYPIVnhsOYS1KCLJmWsn0x
# AbpIkEcz/5nPO0273YxaMw2twfEfMzrVaeX5CAycKRHudj3IzTHqpHI6UdPFLP7f
# ePBI354O/uRV+UnCjxfhXD1L1FVRc4PHU+6Uak2GUPMQtu60dZW2AxNKG0QgEMHC
# gkpfZt3QcyXZmkLIeeARJlYgkwNAkaALKCUN8exFUWw8kdwbbNl/oGCLoZxsjmu8
# xcaNrbTCrgmhviQYgz9PEv7V/hsXNrxg1Y+sXLNv+IBojYjUeXRKKbmmLzTkaMPu
# JoTKXWP/FFhf8BCgx6vM8/1RKSs44fHPces3VKYnHifPT2wpIhV4ND8DptTkinee
# uOKTSPrNbqPcQfD9SM4K1ytSzIB2j7VDbujCgQ79yeNDtanB1dKpY2Zj8M97qRgG
# YtlY0z6mriqCaMm7LFygdBAl6dJmhBD9Mitm46RCnCLi30EYv6ndHfqj4UhbnIHW
# /NJauHF4rkY2MuI4sAkBQothaID1d9AFmzTstLYlPMnXuvKAOJ5PKYFse7BuQCXs
# tir85yd5BiuN
# SIG # End signature block
