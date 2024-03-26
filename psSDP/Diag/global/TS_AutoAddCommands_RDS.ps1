# 2023-02-24 WalterE mod Trap #we#
$startTime_AutoAdd = Get-Date
trap [Exception]{
	WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; continue
	Write-Host "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_"
}


Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: common ---"
	# version of the psSDP Diagnostic - "_psSDP_DiagnosticVersion.TXT"
	Run-DiagExpression .\DC_NetworkingDiagnostic.ps1

	Run-DiagExpression .\DC_MSInfo.ps1

	# Obtain pstat output
	Run-DiagExpression .\DC_PStat.ps1

	Run-DiagExpression .\DC_ChkSym.ps1

	Run-DiagExpression .\DC_Autoruns.ps1

	# Collects Windows Server 2008/R2 Server Manager Information
	Run-DiagExpression .\DC_ServerManagerInfo.ps1

	# List Schedule Tasks using schtasks.exe utility
	Run-DiagExpression .\DC_ScheduleTasks.ps1

	# Collects System and Application Event Logs / done in DC_RDSEventLog.ps1
	#_#  Run-DiagExpression .\DC_SystemAppEventLogs.ps1
	
	# GPResults.exe Output
	Run-DiagExpression .\DC_RSoP.ps1

	Run-DiagExpression .\DC_BasicSystemInformation.ps1
	Run-DiagExpression .\DC_BasicSystemInformationTXT.ps1
	Run-DiagExpression .\DC_Services.ps1
	Run-DiagExpression .\DC_TaskListSvc.ps1
	Run-DiagExpression .\DC_Whoami.ps1
	Run-DiagExpression .\DC_PoolMon.ps1

	# Collect Machine Registry Information for Setup and Performance Diagnostics
	Run-DiagExpression .\DC_RegistrySetupPerf.ps1
	
	# Collects registry entries for KIR (for 2019) and RBC (for 2016) 
	Run-DiagExpression .\DC_KIR-RBC-RegEntries.ps1
	
	#_# Collect summary report 
	Run-DiagExpression .\DC_SummaryReliability.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: RDS ---"
	Run-DiagExpression .\DC_RDSServerInfo.ps1
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Net ---"
	#_# Run-DiagExpression .\DC_Firewall-Component.ps1
	# Capture pfirewall.log 
	Run-DiagExpression .\DC_PFirewall.ps1

	Run-DiagExpression .\DC_SMBClient-Component.ps1
	Run-DiagExpression .\DC_SMBServer-Component.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: DOM ---"
	# Collects registry entries for Directory Services support
	Run-DiagExpression .\DC_DSRegEntries.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Setup ---"
	# Fltmc
	Run-DiagExpression .\DC_Fltmc.ps1

	# Obtain information about Upper and lower filters Information fltrfind.exe utility
	Run-DiagExpression .\DC_Fltrfind.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Update ---"
	# Update History
	Run-DiagExpression .\DC_UpdateHistory.ps1

	# Collect WindowsUpdate.Log
	Run-DiagExpression .\DC_WindowsUpdateLog.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Performance Data ---"
	# Performance Monitor - System Performance Data Collector
	Run-DiagExpression .\TS_PerfmonSystemPerf.ps1 -NumberOfSeconds 60 -DataCollectorSetXMLName "SystemPerformance.xml"

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase: Done ---"

Write-Host "...Next step: Troubleshooting section, if it hangs, run script with parameter SkipTS"
if ($Global:skipTS -ne $true) {
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_common ---"

	Run-DiagExpression .\TS_DumpCollector.ps1 -CopyWERMinidumps -CopyMachineMiniDumps -MaxFileSize 300 -CopyUserDumps -CopyWERFulldumps

	# Information about Processes resource usage and top Kernel memory tags
	Run-DiagExpression .\TS_ProcessInfo.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Print ---"
	Run-DiagExpression .\TS_PrintDevModes2CountCheck.ps1
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_RDS ---"
	Run-DiagExpression .\TS_KernelAuthRPCCheck.ps1

	# Checking the presence of Citrix AppSense 8.1
	Run-DiagExpression .\TS_CitrixAppSenseCheck.ps1

	# Check for large number of Inactive Terminal Server ports
	Run-DiagExpression .\TS_KB2655998_InactiveTSPorts.ps1

	# [Idea ID 2285] [Windows] Windows Server 2003 TS Licensing server does not renew new versions of TS Per Device CALs
	Run-DiagExpression .\TS_RemoteDesktopLServerKB2512845.ps1

	if (test-path $env:Windir\System32\BestPractices\v1.0\Models\Microsoft\Windows\TerminalServices) {
		# BPA RDP
		if ($Global:skipBPA -ne $true) {
		Run-DiagExpression .\TS_BPAInfo.ps1 -BPAModelID "Microsoft/Windows/TerminalServices" -OutputFileName ($Computername + "_TS_BPAInfo.HTM") -ReportTitle "Terminal Services Best Practices Analyzer"
		}
	}
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Net ---"
	# Check for ephemeral port usage
	Run-DiagExpression .\TS_PortUsage.ps1
	Run-DiagExpression .\RC_HTTPRedirectionTSGateway.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_HyperV ---"
	# Hyper-V Info
	Run-DiagExpression .\TS_HyperVInfo.ps1
}
	# Hotfix Rollups
	Run-DiagExpression .\DC_HotfixRollups.ps1

$stopTime_AutoAdd = Get-Date
$duration = $(New-TimeSpan -Start $startTime_AutoAdd -End $stopTime_AutoAdd)

Write-Host "*** $(Get-Date -UFormat "%R:%S") DONE (Dur: $duration) TS_AutoAddCommands_RDS.ps1 SkipTS: $Global:skipTS - SkipBPA: $Global:skipBPA"


# SIG # Begin signature block
# MIInwwYJKoZIhvcNAQcCoIIntDCCJ7ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDkB9dPXj/CJLCj
# g2QXkXyURMiF+eBUFpUh/dpyWcTjw6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGaMwghmfAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEICW62k2Pq1L6zamc6P29CYva
# 6AwYdGs+ukNAmy7pUzx3MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAh5s7P3hEiw1u1iPt5bsigNY03xyqszpBlPQCOTUWcWlLzbHbyprcG
# 80D/ryqHmvpXCdr7TDmXAsZLHNmal5w/VmzTWkuzTraYrWxi+bX3ehBEkRYv+x+2
# nGbsEw8/tQpH/OTYVwihinb9wFqp+OSoIl9Ll0GyBL2L6al4VzGQb6wg7L/q5RM+
# L7o6GK1HlAKuJ5VYxFc2yl7cVAp7PwF5GGgqMTfPRRspedpbLe8BZqs7FS0JBBvU
# AzQKDwPgqpsXg+uaaIOk7LNRvW6uc0rOwGImPJRt5PlRMogOTlO5GFew13MczZL8
# wAWTevVlVb51Q0m2dqEa40svhEE9+Re4oYIXKzCCFycGCisGAQQBgjcDAwExghcX
# MIIXEwYJKoZIhvcNAQcCoIIXBDCCFwACAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIFNRoT8sW4vsZQneTKDMRLhdsKkHsKCfvULGTO8Wmo/8AgZj91lp
# znYYEzIwMjMwMjI3MDkxMTA2LjgyOVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046OEQ0MS00QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF6MIIHJzCCBQ+gAwIBAgITMwAAAbP+Jc4pGxuKHAABAAABszAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MjA5MjAyMDIyMDNaFw0yMzEyMTQyMDIyMDNaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhENDEt
# NEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHwPuuYYgK4ssGCCsr2N
# 7eElKlz0JPButr/gpvZ67kNlHqgKAW0JuKAy4xxjfVCUev/eS5aEcnTmfj63fvs8
# eid0MNvP91T6r819dIqvWnBTY4vKVjSzDnfVVnWxYB3IPYRAITNN0sPgolsLrCYA
# KieIkECq+EPJfEnQ26+WTvit1US+uJuwNnHMKVYRri/rYQ2P8fKIJRfcxkadj8CE
# PJrN+lyENag/pwmA0JJeYdX1ewmBcniX4BgCBqoC83w34Sk37RMSsKAU5/BlXbVy
# Du+B6c5XjyCYb8Qx/Qu9EB6KvE9S76M0HclIVtbVZTxnnGwsSg2V7fmJx0RP4bfA
# M2ZxJeVBizi33ghZHnjX4+xROSrSSZ0/j/U7gYPnhmwnl5SctprBc7HFPV+BtZv1
# VGDVnhqylam4vmAXAdrxQ0xHGwp9+ivqqtdVVDU50k5LUmV6+GlmWyxIJUOh0xzf
# Qjd9Z7OfLq006h+l9o+u3AnS6RdwsPXJP7z27i5AH+upQronsemQ27R9HkznEa05
# yH2fKdw71qWivEN+IR1vrN6q0J9xujjq77+t+yyVwZK4kXOXAQ2dT69D4knqMlFS
# sH6avnXNZQyJZMsNWaEt3rr/8Nr9gGMDQGLSFxi479Zy19aT/fHzsAtu2ocBuTqL
# VwnxrZyiJ66P70EBJKO5eQECAwEAAaOCAUkwggFFMB0GA1UdDgQWBBTQGl3CUWdS
# DBiLOEgh/14F3J/DjTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAWoa7N86wCbjA
# Al8RGYmBZbS00ss+TpViPnf6EGZQgKyoaCP2hc01q2AKr6Me3TcSJPNWHG14pY4u
# hMzHf1wJxQmAM5Agf4aO7KNhVV04Jr0XHqUjr3T84FkWXPYMO4ulQG6j/+/d7gqe
# zjXaY7cDqYNCSd3F4lKx0FJuQqpxwHtML+a4U6HODf2Z+KMYgJzWRnOIkT/od0oI
# Xyn36+zXIZRHm7OQij7ryr+fmQ23feF1pDbfhUSHTA9IT50KCkpGp/GBiwFP/m1d
# rd7xNfImVWgb2PBcGsqdJBvj6TX2MdUHfBVR+We4A0lEj1rNbCpgUoNtlaR9Dy2k
# 2gV8ooVEdtaiZyh0/VtWfuQpZQJMDxgbZGVMG2+uzcKpjeYANMlSKDhyQ38wboAi
# vxD4AKYoESbg4Wk5xkxfRzFqyil2DEz1pJ0G6xol9nci2Xe8LkLdET3u5RGxUHam
# 8L4KeMW238+RjvWX1RMfNQI774ziFIZLOR+77IGFcwZ4FmoteX1x9+Bg9ydEWNBP
# 3sZv9uDiywsgW40k00Am5v4i/GGiZGu1a4HhI33fmgx+8blwR5nt7JikFngNuS83
# jhm8RHQQdFqQvbFvWuuyPtzwj5q4SpjO1SkOe6roHGkEhQCUXdQMnRIwbnGpb/2E
# sxadokK8h6sRZMWbriO2ECLQEMzCcLAwggdxMIIFWaADAgECAhMzAAAAFcXna54C
# m0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMy
# MjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51
# yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY
# 6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9
# cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN
# 7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDua
# Rr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74
# kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2
# K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5
# TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZk
# i1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9Q
# BXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3Pmri
# Lq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUC
# BBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9y
# eS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUA
# YgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
# 1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIw
# MTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/yp
# b+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulm
# ZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM
# 9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECW
# OKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4
# FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3Uw
# xTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPX
# fx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVX
# VAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGC
# onsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU
# 5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEG
# ahC0HVUzWLOhcGbyoYIC1jCCAj8CAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjhENDEtNEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBxi0Tolt0eEqXCQl4qgJXUkiQOYaCBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA56Z0VzAiGA8yMDIzMDIyNzA4MTQxNVoYDzIwMjMwMjI4MDgxNDE1WjB2MDwG
# CisGAQQBhFkKBAExLjAsMAoCBQDnpnRXAgEAMAkCAQACASACAf8wBwIBAAICEs4w
# CgIFAOenxdcCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQDCQx5FNe3BH69o
# AdAbIZSEI1lawH0EIHqMHn9ipDmOJwzOGzMPjQ7l4UjXjlOIJ899pm7erozh0d6l
# L8TRM39CSqM3+P+SppQFvXMQ7A9ZnEmnHPS8/hy/8L2M2KAgl/n37Zbwni6WpPzk
# ZJACUKV3SI+2SMsyH5v0H/BA0e0aIjGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABs/4lzikbG4ocAAEAAAGzMA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIJJMwGxpAhvpIQgoR7pKF5EcQuFewkwre91l5wYZMuK+MIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQghqEz1SoQ0ge2RtMyUGVDNo5P5ZdcyRoeijoZ
# ++pPv0IwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AbP+Jc4pGxuKHAABAAABszAiBCBrsLleqTugnLR/kAuojsM4pQ0CKJ2mpaT6PIyB
# IMDM0DANBgkqhkiG9w0BAQsFAASCAgCh39iQrBN8dDABDAYiQ1BRPIDhoKFqEbHv
# oEPpuEJ15GepXT9jIkhNkRcIzl0YkJGp+X1wc0J5BOj3L1Kc8cI1k/jeqJMYZ+D1
# FX9/Diua10E3ntLyb1hLd+/CDsBSxOebc+AHmym2Wq/VJpdEJ5VjfyG+FBQEsgTV
# Qv7xvjnUqceAtJ0rTyR7krHbJbVko1GTAI9qze+xxWkIydp9am0GxfewH5BlB3FV
# /yocd7ruGeOsKlHG+ZmeH+Ef/OmMguHEnwf6AoIdCO+LitI+pZbX2PbSjEhReUR6
# OEHR2BKoQTsCDHUwPHL+NS6bOfFfjuFVPoWPLIwfRcb3cycTEvEGWuT+mMjmY8tc
# SuclOHXm4nPjQdpBJv39UpP496Ebvd8Y1CCzUwEWm8QwXA+n2uev+JpPXZLBcIZ0
# 2WsNEvkSqlPIssEU185RYoB8g9VNcwjj81krDcRtYMQcF3JqDTwbwfhjYZC264rD
# 1+jyY59pTDXBcATYh62Vv/vj448d3JcpT+O8ASjC4zXEiqpoPa2IoJLDUCXZtqwP
# tTmfft78vV/3RMe8GsLzgmuvpsd/JiHXpn9i4TlBhHF38wreXI7NqV6cGjXMOQ13
# M7KUZERjcC6JeVMaiyLuVDtELo5xKoe2ej0clG9KkaY7xj4euCqdCiu0vy9Wy+1O
# jt4hZII50Q==
# SIG # End signature block
