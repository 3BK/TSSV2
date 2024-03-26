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

	# Collects information about Driver Verifier (verifier.exe utility)
	Run-DiagExpression .\DC_Verifier.ps1

	# Collects BCD information via BCDInfo tool or boot.ini
	Run-DiagExpression .\DC_BCDInfo.ps1

	# Obtain information about Devices and connections using devcon.exe utility
	Run-DiagExpression .\DC_Devcon.ps1

	# DBErr Data Collector
	Run-DiagExpression .\DC_DBErr.ps1

	# User Rights (privileges) via the userrights.exe tool
	Run-DiagExpression .\DC_UserRights.ps1

	# WhoAmI
	Run-DiagExpression .\DC_Whoami.ps1
	
	# PoolMon
	Run-DiagExpression .\DC_PoolMon.ps1

	# Collects registry entries for KIR (for 2019) and RBC (for 2016) 
	Run-DiagExpression .\DC_KIR-RBC-RegEntries.ps1

	# TaskListSvc
	Run-DiagExpression .\DC_TaskListSvc.ps1
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Net ---"
	# DHCP Client Component
	Run-DiagExpression .\DC_DhcpClient-Component.ps1

	# DNS Client Component
	Run-DiagExpression .\DC_DNSClient-Component.ps1

	# Firewall
	Run-DiagExpression .\DC_Firewall-Component.ps1

	# IPsec
	Run-DiagExpression .\DC_IPsec-Component.ps1

	# NetLBFO
	Run-DiagExpression .\DC_NetLBFO-Component.ps1

	# RPC
	Run-DiagExpression .\DC_RPC-Component.ps1

	# SMB Client Component
	Run-DiagExpression .\DC_SMBClient-Component.ps1

	# SMB Server Component
	Run-DiagExpression .\DC_SMBServer-Component.ps1

	# TCPIP Component
	Run-DiagExpression .\DC_TCPIP-Component.ps1

	# WINSClient
	Run-DiagExpression .\DC_WINSClient-Component.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: HyperV  ---"
	# Hyper-V Info 2008R2
	Run-DiagExpression .\DC_HyperVBasicInfo.ps1

	# Hyper-V Networking Settings
	Run-DiagExpression .\DC_HyperVNetworking.ps1

	# Hyper-V Network Virtualization
	Run-DiagExpression .\DC_HyperVNetworkVirtualization.ps1
	
	# Collect the VMGuestSetup.Log file
	Run-DiagExpression .\DC_VMGuestSetupLogCollector.ps1

	# Information about Hyper-V, including Virtual Machine Files and Hyper-V Event Logs
	Run-DiagExpression .\DC_HyperVFiles.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Print ---"
	# Collect Print Registry Keys
	Run-DiagExpression .\DC_RegPrintKeys.ps1

	# Perf/Printing Event Logs
	Run-DiagExpression .\DC_PerfPrintEventLogs.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Storage ---"
	# By adding San.exe to the SDP manifest we should be able to solve cases that have a 512e or Advanced Format (4K) disk in it faster.
	Run-DiagExpression .\DC_SanStorageInfo.ps1

	# Collects Fiber Channel information using fcinfo utility
	Run-DiagExpression .\DC_FCInfo.ps1

	# Obtain information about MS-DOS device names (symbolic links) via DOSDev utility
	Run-DiagExpression .\DC_DOSDev.ps1

	# Collects Information about iSCSI though the iscsicli utility
	Run-DiagExpression .\DC_ISCSIInfo.ps1

	# Parse Storage related event logs on System log using evParse.exe and dump to a HTML file
	Run-DiagExpression .\DC_EvParser.ps1

	# Collects VSS information via VSSAdmin tool
	Run-DiagExpression .\DC_VSSAdmin.ps1

	# Collect Machine Registry Information for Storage Related Diagnostics
	Run-DiagExpression .\DC_RegistryStorage.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Setup ---"
	# Collects information about MPIO configuration (mpclaim.exe utility)
	Run-DiagExpression .\DC_MpClaim.ps1
	
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

	#_# Information about Windows 2008 R2 Cluster Shared Volumes
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

	Run-DiagExpression .\TS_DumpCollector.ps1 -CopyWERMinidumps -CopyMachineMiniDumps -MaxFileSize 300 -CopyMachineMemoryDump

	# Detects and alerts evaluation media
	Run-DiagExpression .\TS_EvalMediaDetection.ps1

	# Debug/GFlags check
	Run-DiagExpression .\TS_DebugFlagsCheck.ps1

	# Information about Processes resource usage and top Kernel memory tags
	Run-DiagExpression .\TS_ProcessInfo.ps1

	# RC_32GBMemoryKB2634907
	Run-DiagExpression .\RC_32GBMemoryKB2634907.ps1

	# Checking if Registry Size Limit setting is present on the system
	Run-DiagExpression .\TS_RegistrySizeLimitCheck.ps1
	
	# Running powercfg.exe to obtain power settings information
	Run-DiagExpression .\TS_PowerCFG.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Net ---"
	# Check for ephemeral port usage
	Run-DiagExpression .\TS_PortUsage.ps1

	# RC_KB2647170_CnameCheck
	Run-DiagExpression .\RC_KB2647170_CnameCheck.ps1

	# FirewallCheck
	Run-DiagExpression .\RC_FirewallCheck.ps1

	# IPv66To4Check
	Run-DiagExpression .\RC_IPv66To4Check.ps1

	# RC_HTTPRedirectionTSGateway
	Run-DiagExpression .\RC_HTTPRedirectionTSGateway.ps1

	# [Idea ID 6530] [Windows] Check for any configured RPC port range which may cause issues with DCOM or DTC components
	Run-DiagExpression .\TS_RPCPortRangeCheck.ps1

	# [Idea ID 2387] [Windows] Verify if RPC connection a configured to accept only Authenticated sessions
	Run-DiagExpression .\TS_RPCUnauthenticatedSessions.ps1

	# Checks files in the LanmanServer, if any at .PST files a file is created with listing all of the files in the directory
	Run-DiagExpression .\TS_NetFilePSTCheck.ps1

	# Checks if Windows Server 2008 R2 SP1, Hyper-V, and Tunnel.sys driver are installed if they are generate alert
	Run-DiagExpression .\TS_ServerCoreKB978309Check.ps1
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_HyperV ---"
	# Hyper-V Info
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
	# Print Information Report
	Run-DiagExpression .\TS_PrintInfo.ps1

	# [KSE Rule] [ Windows V3] Presence of lots of folders inside \spool\prtprocs\ causes failure to install print queues
	Run-DiagExpression .\TS_PrtprocsSubfolderBloat.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_RDP ---"
	# Checking the presence of Citrix AppSense 8.1
	Run-DiagExpression .\TS_CitrixAppSenseCheck.ps1

	# Check for large number of Inactive Terminal Server ports
	Run-DiagExpression .\TS_KB2655998_InactiveTSPorts.ps1

	# [Idea ID 2285] [Windows] Windows Server 2003 TS Licensing server does not renew new versions of TS Per Device CALs
	Run-DiagExpression .\TS_RemoteDesktopLServerKB2512845.ps1

	# BPA Terminal Services
	if ($Global:skipBPA -ne $true) {
	Run-DiagExpression .\TS_BPAInfo.ps1 -BPAModelID "Microsoft/Windows/TerminalServices" -OutputFileName ($Computername + "_TS_BPAInfo.HTM") -ReportTitle "Terminal Services Best Practices Analyzer"
	}

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Storage ---"
	# Detect 4KB Drives (Disk Sector Size)
	Run-DiagExpression .\TS_DriveSectorSizeInfo.ps1

	#_# [Idea ID 7345] [Windows] Perfmon - Split IO Counter
	Run-DiagExpression .\TS_DetectSplitIO.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Setup ---"
	# Enumerate minifilter drivers via Fltmc.exe command
	Run-DiagExpression .\DC_Fltmc.ps1
	
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

	# [Idea ID 3317] [Windows] DisableEngine reg entry can cause app install or registration failure
	Run-DiagExpression .\TS_AppCompatDisabledCheck.ps1

	# [Idea ID 2357] [Windows] the usage of NPP is very large for XTE.exe
	Run-DiagExpression .\TS_XTENonPagedPoolCheck.ps1

	# [Idea ID 4368] [Windows] Windows Logon Slow and Explorer Slow
	Run-DiagExpression .\TS_2K3CLSIDUserACLCheck.ps1

	# [Idea ID 4649] [Windows] Incorrect values for HeapDecomitFreeBlockThreshold  causes high Private Bytes in multiple processes
	Run-DiagExpression .\TS_HeapDecommitFreeBlockThresholdCheck.ps1

	# [Idea ID 2056] [Windows] Consistent Explorer crash due to wsftpsi.dll
	#_# Run-DiagExpression .\TS_WsftpsiExplorerCrashCheck.ps1

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

	# [Idea ID 1922] [Windows] On Windows 2008 R2 and Windows 7 System state backup fails with event id 5 and error 2155347997
	Run-DiagExpression .\TS_BackupSystemStateKB2182466.ps1

	# [Idea ID 3059] [Windows] Ntbackup high CPU and hang
	Run-DiagExpression .\TS_FilesNotToBackup2K3Check.ps1

	# [Idea ID 2004] [Windows] Bitlocker Drive Preparation fails with Error 'The new active drive cannot be formatted.'
	Run-DiagExpression .\TS_BitlockerDenyWriteFixedPolicy.ps1

	# [Idea ID 6711] [Windows] MSI package fails to install with error code HRESULT -2147319780
	Run-DiagExpression .\TS_MSIPackageInstallationCheck.ps1

	Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_WinRM ---"
	# Check if hotfix 2480954 installed
	Run-DiagExpression .\TS_KB2480954AndWinRMStateCheck.ps1
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Cluster ---"
if ($Global:skipTScluster -ne $true) {
	# FailoverCluster Cluster Name Object AD check
	Run-DiagExpression .\TS_ClusterCNOCheck.ps1

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

	#_# Cluster Validation Report Troubleshooter
	#_# Run-DiagExpression .\TS_ClusterValidationTests.ps1
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

	# [Idea ID 2842] [Windows] Alert Engineers if they are working on a Dell machine models R910, R810 and M910
	Run-DiagExpression .\TS_DellPowerEdgeBiosCheck.ps1

	# [Idea ID 3919] [Windows] Create Shadow Copy fail only on VERTIAS storage foundation volume
	Run-DiagExpression .\TS_VeritasVXIOBadConfigFlags.ps1

	# [Idea ID 5327] [Windows] Machine imaged using vlite 1.2 will fail to install SP1
	Run-DiagExpression .\TS_MachineImageVliteCheck.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- Diag Phase:TS_obsolete W2K3/XP ---"
	# [Idea ID 2446] [Windows] Determining the trimming threshold set by the Memory Manager
	Run-DiagExpression .\TS_2K3PoolUsageMaximum.ps1

	# [Idea ID 2334] [Windows] W2K3 x86 SP2 server running out of paged pool due to D2d tag
	Run-DiagExpression .\TS_KnownKernelTags.ps1

	# [Idea ID 7065] [Windows] Alert users about Windows XP EOS
	#_# Run-DiagExpression .\TS_WindowsXPEOSCheck.ps1
}

	# Hotfix Rollups
	Run-DiagExpression .\DC_HotfixRollups.ps1

$stopTime_AutoAdd = Get-Date
$duration = $(New-TimeSpan -Start $startTime_AutoAdd -End $stopTime_AutoAdd)

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object "*** $(Get-Date -UFormat "%R:%S") DONE (Dur: $duration) TS_AutoAddCommands_Cluster.ps1 SkipTS: $Global:skipTS - SkipBPA: $Global:skipBPA"


# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDE23VtMV1wubba
# bn8bE+TlvqcTApUWfSn5Qd9GkWnPcaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGVjWlL01Ja5AylfjYlUvNqb
# k00zZFr/0mh9IxIcY2xMMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQB4cTG4mNut8xuTRHarHJsG6SJ/gkASdxksI8p2qM4ojBHxH67tNlm9
# lhPQs7NnPd17iW2xI631O5+dywD6+pQU/JSj6OmTSXw+d7Hs1er0QOfd5SqJULg8
# F7hST6efuVlLfVQINdmw04+6hSJgrbaEsGsS/GZa3ZPz/TBUbLHQJ7DfW7Jzz3aF
# keEGcTEFid3YoTDEMnvggQR4HBFg7jNiSlC9j+cp2ZTUYPizk4DXwb5zcz8zliSW
# WLQsaIJ0lXewiu8Xvoq1NhIZvg916Ws2Sts6aIHmZxsv7sXE79sd3Zl5mheNObI0
# W8x4c0j8tJW5BrmlSH/8WXdT72FY8lF8oYIW/TCCFvkGCisGAQQBgjcDAwExghbp
# MIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIJuuERAz5yHzIWphZXZHrJ4m7+y/YQsrA4Pr/FOjTLNIAgZj7j47
# rpkYEzIwMjMwMjI3MDkxMDMzLjI3M1owBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNFN0Et
# RTM1OS1BMjVEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVDCCBwwwggT0oAMCAQICEzMAAAHJ+tWOJSB0Al4AAQAAAckwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkw
# MTM4WhcNMjQwMjAyMTkwMTM4WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0U3QS1FMzU5LUEyNUQxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDWcuLljm/Pwr5ajGGTuoZb+8LGLl65MzTVOIRsU4by
# DtIUHRUyNiCjpOJHOA5D4I3nc4E4qXIwdbNEvjG9pLTdmUiB60ggtiIBKiCwS2WP
# MSVEc7t8MYMVZx3P6UI1iYmjO1sbc8yufFuVQcdSSvgLsQEdvZjTsZ3kYkGA/z7k
# Bk2xOWwcZzMezjmaY/utSBwyf/9zxD8ZhKp1Pg5cQunneH30SfIXjNyx3ZkWPF2P
# WU/xAbBllLgXzYkEZ7akKtJqTIWNPHMUpQ7BxB6vAFH9hpCXLua0Ktrg81zIRCb6
# f8sNx79VWJBrw4zacFkcrDoLIyoTMUknLkeLPPxnrGuqosq2Ly+IlRDQW2qRNdJH
# f//Dw8ArIGW8hhMUX8vLcmHdxtV46BKa5s5XC/ycx6FxBvYC3FxT+V3IRSrLz+2E
# QchY1pvMdfHk70Phu1Lqgl2AuYfGtMG0axxVCrHTPn99QiQsTu1vB+irzhwX9REs
# TLDernspXZTiA6FzfnpdgRVB0lejpUVYFANhvNqdDbnNjbVQKSPzbULIP3SCqs7e
# tA+VxCjp6vBbYMXZ+yaABtWrNCzPpGSZp/Pit7XuSbup7T0+7AfDl7fHlkgYShWV
# 82cm/r7znW7ApfoClkXE/N5Cjtb/kG1pOaRkSHBjkB0I+A+/RpogRCfaoXsy8XAJ
# ywIDAQABo4IBNjCCATIwHQYDVR0OBBYEFAVvnWdGwjyhvng6FMV5UXtELjLLMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBADaoupxm30eKQgdyPsCWceGOi7FKM54FpMT4QrxpdxUub1wDwPb9ljY5Sli8
# 52G4MRX2ESVWbOimIm6T/EFiHp1YlNGGZLuFWOsa2rNIVbQt9+xHKyPGSm6rKEeI
# EPExcwZnoZ3NR+pU/Zl3Y74n8FhAmCz00djP8IzhdpE/5PZUzckTWZI7Wotr6Z8H
# jbtCIuP8kLtNRiCHhFj6gswVW5Alm9diX+MhMV9SmkmgBqQGvRVzavWQ/kOIlo29
# lYn9y5hqJZDiT3GnDrAbPeqrvEBaeUbOxrDAWGO3CrkQf+zfssJ96HK4LDxlEn1b
# e2BIV6kBUzuxQT4+vdS76I+8FXhOxMM0UvQJUg9f7Vc4nphEZgnaQcamgZz/myAD
# YgpByX3tkNgkiqLGDAo1+3I3vQ7QBNulNWGxs3TUVWWLQf6+BwaHLOTqOkDLAc8N
# JD/GgR4ZTj7o8VNcxE798zMZxRx/RkepkybRSGgfy062TXyToHvkoldO1jdkzulN
# +6tK/ZCu/nPMIGLLKy04/D8gkj6T2ilOBq2sLf0vr38rDK0PTHu3SOZNe2Utloa+
# hKWN3LKvpANFWSqwJotRJKwCJZ5q/mqDrhTeYuZ56SjQT1MnnLO03+NyLOUfHRey
# A643qy5vcI9XsAAwyIqil1BiqI9e70jG+pdPsIT9IwLalw3JMIIHcTCCBVmgAwIB
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
# IEVTTjozRTdBLUUzNTktQTI1RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAfemLy/4eAZuNVCzgbfp1HFYG3Q6g
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOemk3AwIhgPMjAyMzAyMjcxMDI2NTZaGA8yMDIzMDIyODEwMjY1Nlow
# dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA56aTcAIBADAHAgEAAgIL+zAHAgEAAgIR
# wDAKAgUA56fk8AIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBADHxDHf4DAJE
# mOC89BKOc1JGOSaarHfpCxUqjjTeIild3vVHO3Pdex+YS5hSWfYqhSPW27Wz00Nq
# ItCcBDai//3tZskEdgx3rjLLA8LzO1cTwdf71pAlhGRFr0yk7pAnebs21Wc8G0ME
# w30KJ5Ink4X11CNe2kZ543bXD+juce0BMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHJ+tWOJSB0Al4AAQAAAckwDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgV/Np/5LUtv77MN4OyKmVIj2xCysjXd4sfL15gJBWzqEwgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCBdc5/Ut1RSxAneCnYf2ANIyGJAP/NfeFd
# fOHZOXb9gTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAAByfrVjiUgdAJeAAEAAAHJMCIEIKv5oSIFpRd1aqSDbIzKoEmddxQUde7EVXpb
# IF1wPlF4MA0GCSqGSIb3DQEBCwUABIICADydbNzQxCZF/Gduvh6bbVdXVlzQFswb
# UNG9r723xDmaOFSf98tzFl5/t5faYKCkLI6PxrOCBxgMlc9BJ+oJnFYnTQ3+xfk0
# 4MFiOjiR+QE+0NsXJrK1qQVrTuWXg4zTv5r/i51y0a+McLZYIPqTWoMl/En0rOzu
# SwBtLdO44QemClsBI1nFX8CUEUBQs7wP3ChzXPI+4dUjY1Fk931ixqahKZvS+aqn
# 7Bjy2OmLHCqEOB7lYfCazLnrPhqhOY6gpbmV/vBfMvLLHSXNyy9SkKMc0135r1Jc
# crQBNqSUrBa3E3V6mjniDc2JYY+asSSCkZHEFDofYw2mLczPFw76NEFEiPALXFm6
# byurzBHIthizDbuaq4Z1DwP2rJvNU7gmgCxXAmuFVu6yXxHb/Dg0hBbVav/ocrTn
# oZce5D/ANfK9H5Xrvp9a1cf8pIoewcL7vwYaJArckv3lK9+KDBhfzWxDOMHZ2pdz
# jg37w96/zutVHYAgNSLBRdDBQ6qJ8JKyuJGWO32X5uvYR8ObWaAUrHxeKvQR9sAY
# 3GV3n+Y4eQGTadJCQ538hXWnc7dUxBiorAwMVhqQCN6SXIO6KZqnpjcnBPCKF4Qo
# yDS1gS4MUtiVW1Ho0rnvoQI2FeauRkqOsBT/TwrwvlTR6+JHxYkhQz5DAlW522lC
# fftDEKubevxu
# SIG # End signature block
