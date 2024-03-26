# 2023-02-24 WalterE mod Trap #we#
$startTime_AutoAdd = Get-Date
trap [Exception]{
	WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; continue
	Write-Host "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_"
}

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Common ---"
	# version of the psSDP Diagnostic
	Run-DiagExpression .\DC_NetworkingDiagnostic.ps1

	# MSInfo
	Run-DiagExpression .\DC_MSInfo.ps1

	# Obtain pstat output
	Run-DiagExpression .\DC_PStat.ps1

	# CheckSym
	Run-DiagExpression .\DC_ChkSym.ps1

	# AutoRuns Information
	Run-DiagExpression .\DC_Autoruns.ps1

	# Collects Windows Server 2008/R2 Server Manager Information
	Run-DiagExpression .\DC_ServerManagerInfo.ps1

	# List Schedule Tasks using schtasks.exe utility
	Run-DiagExpression .\DC_ScheduleTasks.ps1

	# Collects System and Application Event Logs 
	Run-DiagExpression .\DC_SystemAppEventLogs.ps1

	# Collect Machine Registry Information for Setup and Performance Diagnostics
	Run-DiagExpression .\DC_RegistrySetupPerf.ps1

	# GPResults.exe Output
	Run-DiagExpression .\DC_RSoP.ps1

	# Basic System Information
	Run-DiagExpression .\DC_BasicSystemInformation.ps1

	# Collects information about Driver Verifier (verifier.exe utility)
	Run-DiagExpression .\DC_Verifier.ps1

	# Collects BCD information via BCDInfo tool or boot.ini
	Run-DiagExpression .\DC_BCDInfo.ps1

	# Obtain information about Devices and connections using devcon.exe utility
	Run-DiagExpression .\DC_Devcon.ps1

	# User Rights (privileges) via the userrights.exe tool
	Run-DiagExpression .\DC_UserRights.ps1

	# List Schedule Tasks using schtasks.exe utility
	Run-DiagExpression .\DC_TaskScheduler.ps1

	# WhoAmI
	Run-DiagExpression .\DC_Whoami.ps1

	# PoolMon
	Run-DiagExpression .\DC_PoolMon.ps1
	
	#_# Collect summary report 
	Run-DiagExpression .\DC_SummaryReliability.ps1

	# Collects registry entries for KIR (for 2019) and RBC (for 2016) 
	Run-DiagExpression .\DC_KIR-RBC-RegEntries.ps1

	# TaskListSvc
	Run-DiagExpression .\DC_TaskListSvc.ps1
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: HyperV  ---"
	# Hyper-V Info
	Run-DiagExpression .\DC_HyperVBasicInfo.ps1

	# Collect the VMGuestSetup.Log file
	Run-DiagExpression .\DC_VMGuestSetupLogCollector.ps1

	# Information about Hyper-V, including Virtual Machine Files and Hyper-V Event Logs
	Run-DiagExpression .\DC_HyperVFiles.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: DOM ---"
	# Kerberos tickets and TGT via klist utility
	Run-DiagExpression .\DC_KList.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Net ---"
	# SMB Server Component
	Run-DiagExpression .\DC_SMBServer-Component.ps1
	
	# TCPIP Component
	Run-DiagExpression .\DC_TCPIP-Component.ps1

	# RPC
	Run-DiagExpression .\DC_RPC-Component.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Print ---"
	# Collect Print Registry Keys
	Run-DiagExpression .\DC_RegPrintKeys.ps1

	# Perf/Printing Event Logs
	Run-DiagExpression .\DC_PerfPrintEventLogs.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Storage ---"
	# Parse Storage related event logs on System log using evParse.exe and dump to a HTML file
	Run-DiagExpression .\DC_EvParser.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: WinRM ---"
	# Collects Windows Remote Management Event log
	Run-DiagExpression .\DC_WinRMEventLogs.ps1

	# Collects WSMAN and WinRM binary details info
	Run-DiagExpression .\DC_WSMANWinRMInfo.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Update ---"
	# Update History
	Run-DiagExpression .\DC_UpdateHistory.ps1

	# Collect WindowsUpdate.Log
	Run-DiagExpression .\DC_WindowsUpdateLog.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Cluster ---"
	# Collects Cluster Logs
	Run-DiagExpression .\DC_ClusterLogs.ps1

	# Export cluster resources properties to a file (2K8 R2 and newer)
	Run-DiagExpression .\DC_ClusterResourcesProperties.ps1

	# Collects Cluster Groups Resource Dependency Report (Win2K8R2)
	Run-DiagExpression .\DC_ClusterDependencyReport.ps1

	# Collects Cluster - related Event Logs for Cluster Diagnostics
	Run-DiagExpression .\DC_ClusterEventLogs.ps1

	# Collects \windows\cluster\reports contents (MHT, XML and Validate*.LOG)
	Run-DiagExpression .\DC_ClusterReportsFiles.ps1

	# Collects Cluster - related registry keys
	Run-DiagExpression .\DC_RegistryCluster.ps1

	# Information about Windows 2008 R2 Cluster Shared Volumes
	Run-DiagExpression .\DC_CSVInfo.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Performance Data ---"
	# Performance Monitor - System Performance Data Collector
	Run-DiagExpression .\TS_PerfmonSystemPerf.ps1 -NumberOfSeconds 60 -DataCollectorSetXMLName "SystemPerformance.xml"
	
	# NetworkAdapters
	Run-DiagExpression .\DC_NetworkAdapters-Component.ps1
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase: Done ---"	
Write-Host "...Next step: Troubleshooting section, if it hangs, run script with parameter SkipTS"

if ($Global:skipTS -ne $true) {
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_common ---"

	Run-DiagExpression .\TS_DumpCollector.ps1 -CopyWERMinidumps -CopyMachineMiniDumps -MaxFileSize 300 -CopyUserDumps -CopyWERFulldumps

	# Detects and alerts evaluation media
	Run-DiagExpression .\TS_EvalMediaDetection.ps1

	# Debug/GFlags check
	Run-DiagExpression .\TS_DebugFlagsCheck.ps1

	# Information about Processes resource usage and top Kernel memory tags
	Run-DiagExpression .\TS_ProcessInfo.ps1

	# Checking if Registry Size Limit setting is present on the system
	Run-DiagExpression .\TS_RegistrySizeLimitCheck.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Net ---"
	# Check for ephemeral port usage
	Run-DiagExpression .\TS_PortUsage.ps1

	# [Idea ID 6530] [Windows] Check for any configured RPC port range which may cause issues with DCOM or DTC components
	Run-DiagExpression .\TS_RPCPortRangeCheck.ps1

	# [Idea ID 2387] [Windows] Verify if RPC connection a configured to accept only Authenticated sessions
	Run-DiagExpression .\TS_RPCUnauthenticatedSessions.ps1

	# Checks files in the LamnServer, if any at .PST files a file is created with listing all of the files in the directory
	Run-DiagExpression .\TS_NetFilePSTCheck.ps1

	# Checks if Windows Server 2008 R2 SP1, Hyper-V, and Tunnel.sys driver are installed if they are generate alert
	Run-DiagExpression .\TS_ServerCoreKB978309Check.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_HyperV ---"
	# Hyper-V Info 2008R2
	Run-DiagExpression .\TS_HyperVInfo.ps1

	# Detect Virtualization
	Run-DiagExpression .\TS_Virtualization.ps1

	if (test-path $env:Windir\System32\BestPractices\v1.0\Models\Microsoft\Windows\Hyper-V) {
		# Hyper-V BPA
		if ($Global:skipBPA -ne $true) {
		Run-DiagExpression .\TS_BPAInfo.ps1 -BPAModelID "Microsoft/Windows/Hyper-V" -OutputFileName ($Computername + "_HyperV_BPAInfo.HTM") -ReportTitle "Hyper-V Best Practices Analyzer"
		}
	}

	# [Idea ID 6134] [Windows] You cannot start Hyper-V virtual machines after you enable the IO verification option on a HyperV
	Run-DiagExpression .\TS_HyperVCheckVerificationKB2761004.ps1

	# Check for event ID 21203 or 21125
	Run-DiagExpression .\TS_CheckEvtID_KB2475761.ps1

	# [Idea ID 5438] [Windows] Windows 2012 Hyper-V SPN and SCP not registed if customer uses a non default dynamicportrange
	Run-DiagExpression .\TS_HyperVEvent14050Check.ps1

	# [Idea ID 5752] [Windows] BIOS update may be required for some computers before starting Hyper-V on 2012
	Run-DiagExpression .\TS_HyperV2012-CS-BIOS-Check.ps1

	# Hyper-V KB 982210 check
	Run-DiagExpression .\TS_HyperVSCSIDiskEnum.ps1

	# Hyper-V KB 975530 check (Xeon Processor Errata)
	Run-DiagExpression .\TS_HyperVXeon5500Check.ps1

	# Checks if Windows Server 2008 R2 SP1, Hyper-V, and Hotfix 2263829 are installed if they are generate alert
	Run-DiagExpression .\TS_HyperVKB2263829Check.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Print ---"
	# [KSE Rule] [ Windows V3] Presence of lots of folders inside \spool\prtprocs\ causes failure to install print queues
	Run-DiagExpression .\TS_PrtprocsSubfolderBloat.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_RDP ---"
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
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Storage ---"
	# Detect 4KB Drives (Disk Sector Size)
	Run-DiagExpression .\TS_DriveSectorSizeInfo.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Setup ---"
	# [Idea ID 1911] [Windows] NTFS metafile cache consumes most of RAM in Win2k8R2 Server
	Run-DiagExpression .\TS_NTFSMetafilePerfCheck.ps1

	# [Idea ID 2346] [Windows] high cpu only on one processor
	Run-DiagExpression .\TS_2K3ProcessorAffinityMaskCheck.ps1

	# [Idea ID 3989] [Windows] STACK MATCH - Win2008R2 - Machine hangs after shutdown, caused by ClearPageFileAtShutdown setting
	Run-DiagExpression .\TS_SBSLClearPageFileAtShutdown.ps1

	# [Idea ID 2753] [Windows] HP DL385 G5p machine cannot generate dump file
	Run-DiagExpression .\TS_ProLiantDL385NMICrashDump.ps1

	# [Idea ID 3253] [Windows] Windows Search service does not start immediately after the machine is booted
	Run-DiagExpression .\TS_WindowsSearchLenovoRapidBootCheck.ps1

	# [Idea ID 2334] [Windows] W2K3 x86 SP2 server running out of paged pool due to D2d tag
	Run-DiagExpression .\TS_KnownKernelTags.ps1

	# [Idea ID 3317] [Windows] DisableEngine reg entry can cause app install or registration failure
	Run-DiagExpression .\TS_AppCompatDisabledCheck.ps1

	# [Idea ID 2357] [Windows] the usage of NPP is very large for XTE.exe
	Run-DiagExpression .\TS_XTENonPagedPoolCheck.ps1

	# [Idea ID 4368] [Windows] Windows Logon Slow and Explorer Slow
	Run-DiagExpression .\TS_2K3CLSIDUserACLCheck.ps1

	# [Idea ID 4649] [Windows] Incorrect values for HeapDecomitFreeBlockThreshold  causes high Private Bytes in multiple processes
	Run-DiagExpression .\TS_HeapDecommitFreeBlockThresholdCheck.ps1

	# [Idea ID 2056] [Windows] Consistent Explorer crash due to wsftpsi.dll
	Run-DiagExpression .\TS_WsftpsiExplorerCrashCheck.ps1

	# [Idea ID 3250] [Windows] Machine exhibits different symptoms due to Confliker attack
	Run-DiagExpression .\TS_Netapi32MS08-067Check.ps1

	# [Idea ID 5194] [Windows] Unable to install vcredist_x86.exe with message (Required file install.ini not found. Setup will now exit)
	Run-DiagExpression .\TS_RegistryEntryForAutorunsCheck.ps1

	# [Idea ID 5452] [Windows] The “Red Arrow” issue in Component Services caused by registry keys corruption
	Run-DiagExpression .\TS_RedArrowRegistryCheck.ps1

	# [Idea ID 5603] [Windows] Unable to start a service due to corruption in the Event Log key
	Run-DiagExpression .\TS_EventLogServiceRegistryCheck.ps1

	# [Idea ID 4783] [Windows] eEye Digital Security causing physical memory depletion
	Run-DiagExpression .\TS_eEyeDigitalSecurityCheck.ps1

	# [Idea ID 5091] [Windows] Super Rule-To check if both 3GB and PAE switch is present in boot.ini for a 32bit OS (Pre - Win 2k8)
	Run-DiagExpression .\TS_SwithesInBootiniCheck.ps1

	# [Idea ID 7018] [Windows] Event Log Service won't start
	Run-DiagExpression .\TS_EventLogStoppedGPPCheck.ps1

	# [Idea ID 8012] [Windows] SDP-UDE check for reg key DisablePagingExecutive
	Run-DiagExpression .\TS_DisablePagingExecutiveCheck.ps1

	# [KSE Rule] [ Windows V3] Server Manager refresh issues and SDP changes reqd for MMC Snapin Issues in 2008, 2008 R2
	Run-DiagExpression .\TS_ServerManagerRefreshKB2762229.ps1

	# [KSE Rule] [ Windows V3] Handle leak in Svchost.exe when a WMI query is triggered by using the Win32_PowerSettingCapabilities
	Run-DiagExpression .\TS_WMIHandleLeakKB2639077.ps1

	# Checks 32 bit windows server 2003 / 2008 to see is DEP is disabled, if so it might not detect more than 4 GB of RAM.
	Run-DiagExpression .\TS_DEPDisabled4GBCheck.ps1

	# [Idea ID 2695] [Windows] Check the Log On account for the Telnet service to verify it's not using the Local System account
	Run-DiagExpression .\TS_TelnetSystemAccount.ps1

	# [Idea ID 2389] [Windows] Hang caused by kernel memory depletion due 'SystemPages' reg key with wrong value
	Run-DiagExpression .\TS_MemoryManagerSystemPagesCheck.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_WinRM ---"
	# Check if hotfix 2480954 installed
	Run-DiagExpression .\TS_KB2480954AndWinRMStateCheck.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Cluster ---"
if ($Global:skipTScluster -ne $true) {
	# FailoverCluster Cluster Name Object AD check
	Run-DiagExpression .\TS_ClusterCNOCheck.ps1
	
	# Collect Basic Cluster System Information
	Run-DiagExpression .\TS_BasicClusterInfo.ps1

	# [Idea ID 2169] [Windows] Xsigo network host driver can cause Cluster disconnects
	Run-DiagExpression .\TS_ClusterXsigoDriverNetworkCheck.ps1

	# [Idea ID 2251] [Windows] Cluster 2003 - Access denied errors during a join, heartbeat, and Cluster Admin open
	Run-DiagExpression .\TS_Cluster2K3NoLmHash.ps1

	# [Idea ID 2513] [Windows] IPv6 rules for Windows Firewall can cause loss of communications between cluster nodes
	Run-DiagExpression .\TS_ClusterIPv6FirewallCheck.ps1

	# [Idea ID 5258] [Windows] Identifying Cluster Hive orphaned resources located in the dependencies key
	Run-DiagExpression .\TS_Cluster_OrphanResource.ps1

	# [Idea ID 6519] [Windows] Invalid Class error on 2012 Clusters (SDP)
	Run-DiagExpression .\TS_ClusterCAUWMINamespaceCheck.ps1

	# [Idea ID 6500] [Windows] Invalid Namespace error on 2008 and 2012 Clusters
	Run-DiagExpression .\TS_ClusterMSClusterWMINamespaceCheck.ps1

	# Cluster Validation Report Troubleshooter
	Run-DiagExpression .\TS_ClusterValidationTests.ps1
}

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_3rd party ---"
	# [Idea ID 986] [Windows] SBSL McAfee Endpoint Encryption for PCs may cause slow boot or delay between CTRL+ALT+DEL and Cred
	Run-DiagExpression .\TS_SBSL_MCAfee_EEPC_SlowBoot.ps1

	# [Idea ID 3181] [Windows] Symantec Endpoint Protection's smc.exe causing handle leak
	Run-DiagExpression .\TS_SEPProcessHandleLeak.ps1

	# Check for Sophos BEFLT.SYS version 5.60.1.7
	Run-DiagExpression .\TS_B2693877_Sophos_BEFLTCheck.ps1

	# [KSE Rule] [ Windows V3] HpCISSs2 version 62.26.0.64 causes 0xD1 or 0x9E
	Run-DiagExpression .\TS_HpCISSs2DriverIssueCheck.ps1

	# check for WMI corruption on HP systems
	Run-DiagExpression .\TS_HPWMICheck.ps1

	# [Idea ID 2842] [Windows] Alert Engineers if they are working on a Dell machine models R910, R810 and M910
	Run-DiagExpression .\TS_DellPowerEdgeBiosCheck.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- Diag Phase:TS_obsolete W2K3/XP ---"
	# [Idea ID 2446] [Windows] Determining the trimming threshold set by the Memory Manager
	Run-DiagExpression .\TS_2K3PoolUsageMaximum.ps1

	# [Idea ID 7065] [Windows] Alert users about Windows XP EOS
	#_# Run-DiagExpression .\TS_WindowsXPEOSCheck.ps1
}
	# Hotfix Rollups
	Run-DiagExpression .\DC_HotfixRollups.ps1

$stopTime_AutoAdd = Get-Date
$duration = $(New-TimeSpan -Start $startTime_AutoAdd -End $stopTime_AutoAdd)

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object "*** $(Get-Date -UFormat "%R:%S") DONE (Dur: $duration) TS_AutoAddCommands_Perf.ps1 SkipTS: $Global:skipTS - SkipBPA: $Global:skipBPA"


# SIG # Begin signature block
# MIInwwYJKoZIhvcNAQcCoIIntDCCJ7ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB7UWVHwFdf98oh
# K7jrnMr2swRvWZuJg2L3V5/HMEF/c6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILG4fDb5mwZZ7LDvDjUAlZKu
# BRZDjskC+iGLB5uzri9eMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAKgxhOQCR32D+kQUmfro4OXdrIYiPjXWmQgy7NOTyHgWcLjumuKUKM
# x6BH3PH+tCUV7wBIJJJQGHe8PRj6PcdfSKyZeDkWN5M/CeEbIInKHasYHWy34/cp
# njlDrVg/gWouozYCcyZ9bQ/1Wr949MGdH8kfP3NQsw6jMbmqBQuIZCiJWBVTH+QM
# D0EivWerd5MElbK0dso0nhxG6bR7UUPX+zhjbJ0+/5zec/QnwJsWPwn/C6uXucnA
# bYJoHB1XiBqGohOqdfdm16ApR1YyyqwBrAPKlklxDjWEeHhrIfl15VPjKpSqkbsP
# PPcM33FbcA3+Yeam8mJ8QKbJDRlhyh5foYIXKzCCFycGCisGAQQBgjcDAwExghcX
# MIIXEwYJKoZIhvcNAQcCoIIXBDCCFwACAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIJM8IDCjTvCoCS+5h+iXhNUE7dJBshFpAdj7Jo1TUZBZAgZj91lp
# zbcYEzIwMjMwMjI3MDkxMTA0LjI5M1owBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
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
# AQkEMSIEIGzvHp5psdKdH6MwaWz+mKXmeX9xLku3u9+4zL4dSPKfMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQghqEz1SoQ0ge2RtMyUGVDNo5P5ZdcyRoeijoZ
# ++pPv0IwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AbP+Jc4pGxuKHAABAAABszAiBCBrsLleqTugnLR/kAuojsM4pQ0CKJ2mpaT6PIyB
# IMDM0DANBgkqhkiG9w0BAQsFAASCAgAoe7HaY0BMjRwxGfAu8yOHZ9WHw3vw6ym4
# poiD8UolgUXdsxlPrZu3y2x9hqZB2s2OKp2gurka/sHGBwtH5PtvWYsa4Y0zFCMd
# mDb1mJKCA8GQkGcJ4znOvppZGpNDLJwRVtqV6PFukI6s2Ol7twZ+DWsVwwvHZPdx
# 5ux2S4SjALUcTVNsL1WCeAeHtVv4FZgJLq609MQ+Ge2XF4CoiRYWQdXGEwJMoxpX
# XJJgnqmw1Qltoes0wbwwW7+nvSHAs9nY92D0+L9kpPz8hnLwGMoIlhwc/6fEfKdy
# W1l5swDoFbIXL/Nh05OXlG/ynUIZ3i8rBZ2VRBUzhMwlRs5qDdssWCp60WxJ8j/E
# lIIyAg5TnfDn4DkUFBiGavckvjCWma4VsRzxgsg8ZyKfhDM7es95VmF6izGHsQh5
# Rlav7X7jlBHb4ity5ykAScFnHj1QoVbzivAIU8Sv/ITbQKyjdKEYDoYzPnEw+yr8
# Y4401z5/HVVsAfW/BDhfs0ktMK3W8Z4K+SK/EORTFNPbAATFQ4nluzRvw358IhbL
# 97sm7Ewg9THDogkENBCi9WnH/ZN1uGQgnsRZicjcAT/adi7mXIAJ3+ElCboz0Jl1
# u0LFgB9FCyYsh8yQwEbjO+IS9+5Ymu78Y9sEJgHBHPyTM3DQd8fCBJKpBnbB8YqM
# is+GuyIUog==
# SIG # End signature block
