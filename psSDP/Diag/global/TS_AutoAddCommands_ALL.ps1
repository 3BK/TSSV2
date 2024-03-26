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

	# Basic System Information TXT output
	Run-DiagExpression .\DC_BasicSystemInformationTXT.ps1

	# Collects information about Driver Verifier (verifier.exe utility)
	Run-DiagExpression .\DC_Verifier.ps1

	# Collects BCD information via BCDInfo tool or boot.ini
	Run-DiagExpression .\DC_BCDInfo.ps1

	# Obtain information about Devices and connections using devcon.exe utility
	Run-DiagExpression .\DC_Devcon.ps1

	# Collects Windows Server 2008/R2 Server Manager Information
	Run-DiagExpression .\DC_ServerManagerLogs.ps1

	# DBErr Data Collector
	Run-DiagExpression .\DC_DBErr.ps1

	# User Rights (privileges) via the userrights.exe tool
	Run-DiagExpression .\DC_UserRights.ps1

	# Services
	Run-DiagExpression .\DC_Services.ps1

	# TaskListSvc
	Run-DiagExpression .\DC_TaskListSvc.ps1

	# List Schedule Tasks using schtasks.exe utility
	Run-DiagExpression .\DC_TaskScheduler.ps1

	# WhoAmI
	Run-DiagExpression .\DC_Whoami.ps1
	
	# PoolMon
	Run-DiagExpression .\DC_PoolMon.ps1
	
	# Collects registry entries for KIR (for 2019) and RBC (for 2016) 
	Run-DiagExpression .\DC_KIR-RBC-RegEntries.ps1

	# Collect summary report 
	Run-DiagExpression .\DC_SummaryReliability.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Net ---"
	# 802.1x Client Component
	Run-DiagExpression .\DC_8021xClient-Component.ps1

	# BITS Client Component
	Run-DiagExpression .\DC_BitsClient-Component.ps1

	# BITS Server Component
	Run-DiagExpression .\DC_BitsServer-Component.ps1

	# Bluetooth Component
	Run-DiagExpression .\DC_Bluetooth-Component.ps1

	# BranchCache
	Run-DiagExpression .\DC_BranchCache-Component.ps1

	# Bridge
	Run-DiagExpression .\DC_Bridge-Component.ps1

	# Certificates Component
	Run-DiagExpression .\DC_Certificates-Component.ps1

	# CscClient
	Run-DiagExpression .\DC_CscClient-Component.ps1

	# DFS Client Component
	Run-DiagExpression .\DC_DFSClient-Component.ps1
	# DFS Server Component
	Run-DiagExpression .\DC_DFSServer-Component.ps1
	
	# DHCP Client Component
	Run-DiagExpression .\DC_DhcpClient-Component.ps1
	# DHCP Server Component
	Run-DiagExpression .\DC_DhcpServer-Component.ps1

	# DirectAccess Client Component
	Run-DiagExpression .\DC_DirectAccessClient-Component.ps1
	# DirectAccess Server Component
	Run-DiagExpression .\DC_DirectAccessServer-Component.ps1

	# DNS Client Component
	Run-DiagExpression .\DC_DNSClient-Component.ps1
	# DNS Server Component
	Run-DiagExpression .\DC_DNSServer-Component.ps1

	# DNS DHCP Dynamic Updates
	Run-DiagExpression .\DC_DnsDhcpDynamicUpdates.ps1

	# Firewall
	Run-DiagExpression .\DC_Firewall-Component.ps1

	# Capture pfirewall.log 
	Run-DiagExpression .\DC_PFirewall.ps1

	# FolderRedirection
	Run-DiagExpression .\DC_FolderRedirection-Component.ps1

	# GroupPolicyClient
	Run-DiagExpression .\DC_GroupPolicyClient-Component.ps1

	# HTTP
	Run-DiagExpression .\DC_HTTP-Component.ps1

	# InternetExplorer
	Run-DiagExpression .\DC_InternetExplorer-Component.ps1

	# IPAM Component
	Run-DiagExpression .\DC_IPAM-Component.ps1

	# IPsec
	Run-DiagExpression .\DC_IPsec-Component.ps1

	# MUP Component
	Run-DiagExpression .\DC_MUP-Component.ps1

	# NAP Client Component
	Run-DiagExpression .\DC_NAPClient-Component.ps1

	# NAP Server Component
	Run-DiagExpression .\DC_NAPServer-Component.ps1

	# NetLBFO
	Run-DiagExpression .\DC_NetLBFO-Component.ps1

	# NetworkAdapters
	Run-DiagExpression .\DC_NetworkAdapters-Component.ps1

	# NetworkConnections
	Run-DiagExpression .\DC_NetworkConnections-Component.ps1

	# NetworkList
	Run-DiagExpression .\DC_NetworkList-Component.ps1

	# NetworkLocationAwareness
	Run-DiagExpression .\DC_NetworkLocationAwareness-Component.ps1

	# Network Shortcuts (Network Locations)
	Run-DiagExpression .\DC_NetworkShortcuts.ps1

	# NetworkStoreInterface
	Run-DiagExpression .\DC_NetworkStoreInterface-Component.ps1

	# NFS Client Component
	Run-DiagExpression .\DC_NfsClient-Component.ps1

	# NFS Server Component
	Run-DiagExpression .\DC_NfsServer-Component.ps1

	# NLB Component
	Run-DiagExpression .\DC_NLB-Component.ps1

	# NPS
	Run-DiagExpression .\DC_NPS-Component.ps1

	# P2P
	Run-DiagExpression .\DC_P2P-Component.ps1

	# Proxy Configuration
	Run-DiagExpression .\DC_ProxyConfiguration.ps1

	# RAS
	Run-DiagExpression .\DC_RAS-Component.ps1

	# RDG Component
	Run-DiagExpression .\DC_RDG-Component.ps1

	# Remote File Systems Client Component
	Run-DiagExpression .\DC_RemoteFileSystemsClient-Component.ps1

	# Remote File Systems Server Component
	Run-DiagExpression .\DC_RemoteFileSystemsServer-Component.ps1

	# RPC
	Run-DiagExpression .\DC_RPC-Component.ps1

	# SChannel
	Run-DiagExpression .\DC_SChannel-Component.ps1

	# SMB Client Component
	Run-DiagExpression .\DC_SMBClient-Component.ps1

	# SMB Server Component
	Run-DiagExpression .\DC_SMBServer-Component.ps1

	# SNMP
	Run-DiagExpression .\DC_SNMP-Component.ps1

	# TCPIP Component
	Run-DiagExpression .\DC_TCPIP-Component.ps1

	# WebClient
	Run-DiagExpression .\DC_WebClient-Component.ps1

	# WinHTTP
	Run-DiagExpression .\DC_WinHTTP-Component.ps1

	# WINSClient
	Run-DiagExpression .\DC_WINSClient-Component.ps1

	# WinSock
	Run-DiagExpression .\DC_WinSock-Component.ps1

	# WINSServer
	Run-DiagExpression .\DC_WINSServer-Component.ps1
	
	# Collects W32Time information
	Run-DiagExpression .\DC_W32Time.ps1

	# Collects Basic Networking Information (TCP/IP - SMB)
	Run-DiagExpression .\DC_NetBasicInfo.ps1
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: HyperV  ---"
	# Hyper-V Info
	Run-DiagExpression .\DC_HyperVBasicInfo.ps1

	# Hyper-V Networking Info
	Run-DiagExpression .\DC_HyperVNetInfo.ps1

	# Hyper-V Networking Settings
	Run-DiagExpression .\DC_HyperVNetworking.ps1

	# Hyper-V Network Virtualization
	Run-DiagExpression .\DC_HyperVNetworkVirtualization.ps1

	# Hyper-V Replica Information
	if ($Global:skipHVreplica -ne $true) {
	 Run-DiagExpression .\DC_HyperVReplica.ps1
	}

	# Collect the VMGuestSetup.Log file
	Run-DiagExpression .\DC_VMGuestSetupLogCollector.ps1

	# Information about Hyper-V, including Virtual Machine Files and Hyper-V Event Logs
	Run-DiagExpression .\DC_HyperVFiles.ps1

	Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: DOM ---"
	# Applied Security Templates
	Run-DiagExpression .\DC_AppliedSecTempl.ps1

	# Collects functional level and local group membership information (DSMisc)
	Run-DiagExpression .\DC_DSMisc.ps1

	# Kerberos Component
	Run-DiagExpression .\DC_Kerberos-Component.ps1
	
	# Obtain Netlogon Log
	Run-DiagExpression .\DC_NetlogonLog.ps1

	# Collects NetSetup.Log from %windir%\debug
	Run-DiagExpression .\DC_NetSetupLog.ps1

	# Collects winlogon Log from %windir%\security\logs\winlogon.log 
	Run-DiagExpression .\DC_WinlogonLog.ps1

	# Run Repadmin tool with showrepl argument and obtain output
	Run-DiagExpression .\DC_Repadmin.ps1

	# Collects system security settings (INF) via secedit utility
	Run-DiagExpression .\DC_SystemSecuritySettingsINF.ps1

	# Collects registry entries for Directory Services support
	Run-DiagExpression .\DC_DSRegEntries.ps1

	# auditpol output
	Run-DiagExpression .\DC_AuditPol.ps1

	# Kerberos tickets and TGT via klist utility
	Run-DiagExpression .\DC_KList.ps1

	# DCPromo Logs
	Run-DiagExpression .\DC_DCPromoLogs.ps1

	# Determines FSMO role owners
	Run-DiagExpression .\DC_NetdomFSMO.ps1

	# Copies Userenv Log files
	Run-DiagExpression .\DC_UserenvLogs.ps1

	# Collects environment variables (output of SET command)
	Run-DiagExpression .\DC_EnvVars.ps1

	# Collecting Secure Channel Info
	Run-DiagExpression .\DC_SecureChannelInfo.ps1

	# Directory Services related Event Logs
	Run-DiagExpression .\DC_ADEventLogs.ps1

	# Dfsr Informaton
	Run-DiagExpression .\DC_DfsrInfo.ps1

	# BPA DS
	if ($Global:skipBPA -ne $true) {
		Run-DiagExpression .\DC_BPA-DS.ps1
	}

	# Active Directory environment data collection scripts.
	Run-DiagExpression .\DC_CurrentDomainInfo.ps1
	Run-DiagExpression .\DC_DCSiteInfo.ps1
	Run-DiagExpression .\DC_ForestInfo.ps1
	Run-DiagExpression .\DC_TrustList.ps1
	Run-DiagExpression .\DC_UserLogonInfo.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Print ---"
	# Collect Print Registry Keys
	Run-DiagExpression .\DC_RegPrintKeys.ps1

	# Perf/Printing Event Logs
	Run-DiagExpression .\DC_PerfPrintEventLogs.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: RDS ---"
	Run-DiagExpression .\DC_RDSServerInfo.ps1

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
	# Collect Deployment-related Logs (setupact.log, unattended.xml, setuperr.log)
	Run-DiagExpression .\DC_DeploymentLogs.ps1

	# KMS/ MAK activation information using inbox slmgr.vbs
	Run-DiagExpression .\DC_SLMGR.ps1

	# Windows Servicing Logs (CBS logs and others)
	Run-DiagExpression .\DC_ServicingLogs.ps1

	# Collects Cluster - related Event Logs for Cluster Diagnostics
	Run-DiagExpression .\DC_MBAMEventLogs.ps1

	# KB Installation Logs
	Run-DiagExpression .\DC_KBInstallLogs.ps1

	# Collects Windows Setup API Logs
	Run-DiagExpression .\DC_SetupAPILogs.ps1

	# Collect Appx event logs for tshooting application deployment, sideloading, and execution
	Run-DiagExpression .\DC_WindowsStoreAppEvtLogs.ps1

	# Startup repair Diagnostics Data Collection
	Run-DiagExpression .\DC_StartupRepairProcessLog.ps1

	# Enumerate minifilter drivers via Fltmc.exe command
	Run-DiagExpression .\DC_Fltmc.ps1

	# Obtain information about Upper and lower filters Information fltrfind.exe utility
	Run-DiagExpression .\DC_Fltrfind.ps1

	# DC_WDS
	Run-DiagExpression .\DC_WDSFiles.ps1

	if ($Global:runFull -eq $True) {
		#_# newer Setup_Addons
		Run-DiagExpression .\DC_Setup_Addons.ps1
	}
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: SQL ---"
	# Get_System_Info
	Run-DiagExpression .\SQL_Get_SystemInfo.ps1

	# Get_All_Services
	Run-DiagExpression .\SQL_Get_All_Services.ps1

	# Reg_Debug_Keys
	Run-DiagExpression .\SQL_Debug_Registry.ps1

	# SQL Server Log Collector
	Run-DiagExpression .\DC_CollectSqlLogs.ps1 -Instances $null -CollectSqlErrorlogs -CollectSqlAgentLogs

	# SQL Server XE System Health Collector
	Run-DiagExpression .\DC_GetSqlXeLogs.ps1 -Instances $null -CollectSqlDefaultDiagnosticXeLogs -CollectFailoverClusterDiagnosticXeLogs -CollectAlwaysOnDiagnosticXeLogs

	# SQL Server minidump files Collector
	Run-DiagExpression .\DC_CollectSqlMinidumps.ps1 -Instances $null

	# SQL Server Log Collector
	Run-DiagExpression .\DC_RunSqlDiagScripts.ps1 -Instances $null -CollectSqlDiag -CollectAlwaysOnInfo

	# Misc_SQL_Keys
	Run-DiagExpression .\DC_SQL_Registries.ps1

	# SQL Server Analysis Services Registry Key Collector
	Run-DiagExpression .\DC_GetOlapServerConfigFiles.ps1

	# SQL Server Analysis Services Registry Key Collector
	Run-DiagExpression .\DC_CollectSsasRegKeys.ps1

	# SQL Server Analysis Services MiniDump Collector
	Run-DiagExpression .\DC_CollectASMinidumps.ps1 -Instances $null

	# SQL Server Analysis Services Log and Trace Collector
	Run-DiagExpression .\DC_GetOlapLogAndTraces.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: WinRM ---"
	# Collects Windows Remote Management Event log
	Run-DiagExpression .\DC_WinRMEventLogs.ps1

	# Collects WSMAN and WinRM binary details info
	Run-DiagExpression .\DC_WSMANWinRMInfo.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Update ---"
	# Update History / Hotfixes
	Run-DiagExpression .\DC_UpdateHistory.ps1

	# Collect WindowsUpdate.Log
	Run-DiagExpression .\DC_WindowsUpdateLog.ps1


Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Surface ---"
	# Surface 
	Run-DiagExpression .\DC_Surface.ps1

	# Surface Pro 3
	Run-DiagExpression .\DC_SurfacePro3.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Exchange ---"
	# ExchDump
	Run-DiagExpression .\DC_Ex2003_ExchDump.ps1

	# ExBPA_2003
	if ($Global:skipBPA -ne $true) {
		Run-DiagExpression .\DC_Ex2003_ExBPAcmd.ps1
	}

	# Collects PowerShell - related Event Logs for Exchange Server Diagnostics
	Run-DiagExpression .\DC_ExchangeServerEventLogs.ps1

	# ExchDump
	Run-DiagExpression .\DC_Exchange_RegKeys.ps1

	# ExBPAcmd
	if ($Global:skipBPA -ne $true) {
		Run-DiagExpression .\DC_Ex_ExBPAcmd.ps1
	}

	# Exchange Server 2007-2010 Comprehensive Data Collection
	Run-DiagExpression .\DC_GetExchange2007_2010Data.ps1

	# Exchange Server 2013 Comprehensive Data Collection
	Run-DiagExpression .\DC_GetExchange2013Data.ps1

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

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: Remote ---"
	# ServerCore R2 Setup
	#Run-DiagExpression .\DC_ServerCoreR2Setup.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase module: DC_WinStore ---"
	# Windows Store Inbox Applications Interactive [AutoAdded]
	Run-DiagExpression .\DC_WinStoreMain.ps1
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Collect Phase: Done ---"	
Write-Host "...Next step: Troubleshooting section, if it hangs, run script with parameter SkipTS"

if ($Global:skipTS -ne $true) {
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_common ---"

	Run-DiagExpression .\TS_DumpCollector.ps1 -CopyWERMinidumps -CopyMachineMiniDumps -MaxFileSize 300 -CopyMachineMemoryDump -CopyTDRDumps

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

	Run-DiagExpression .\RC_KB2647170_CnameCheck.ps1

	Run-DiagExpression .\RC_FirewallCheck.ps1

	Run-DiagExpression .\RC_IPv66To4Check.ps1

	Run-DiagExpression .\RC_HTTPRedirectionTSGateway.ps1

	# [Idea ID 6530] [Windows] Check for any configured RPC port range which may cause issues with DCOM or DTC components
	Run-DiagExpression .\TS_RPCPortRangeCheck.ps1

	# [Idea ID 2387] [Windows] Verify if RPC connection are configured to accept only Authenticated sessions
	Run-DiagExpression .\TS_RPCUnauthenticatedSessions.ps1

	# SMB2ClientDriverStateCheck
	Run-DiagExpression .\TS_SMB2ClientDriverStateCheck.ps1

	# SMB2ServerDriverStateCheck
	Run-DiagExpression .\TS_SMB2ServerDriverStateCheck.ps1

	# Opportunistic Locking has been disabled and may impact performance.
	Run-DiagExpression .\TS_LockingKB296264Check.ps1

	# Evaluates whether InfocacheLevel should be increased to 0x10 hex. To resolve slow logon, slow boot issues.
	Run-DiagExpression .\TS_InfoCacheLevelCheck.ps1

	# RSASHA512 Certificate TLS 1.2 Compat Check
	Run-DiagExpression .\TS_DetectSHA512-TLS.ps1

	# IPv6Check
	Run-DiagExpression .\TS_IPv6Check.ps1

	# PMTU Check
	Run-DiagExpression .\TS_PMTUCheck.ps1

	# Detect MTU of 1514
	Run-DiagExpression .\TS_DetectMTU1514.ps1
	
	# Checks for modified TcpIP Reg Parameters and recommend KB
	Run-DiagExpression .\TS_TCPIPSettingsCheck.ps1

	# Checks if the number of 6to4 adapters is larger than the number of physical adapters
	Run-DiagExpression .\TS_AdapterKB980486Check.ps1

	# Checks files in the LanmanServer, if any at .PST files a file is created with listing all of the files in the directory
	Run-DiagExpression .\TS_NetFilePSTCheck.ps1

	# Checks if Windows Server 2008 R2 SP1, Hyper-V, and Tunnel.sys driver are installed if they are generate alert
	Run-DiagExpression .\TS_ServerCoreKB978309Check.ps1

	#_# Run-DiagExpression .\TS_DetectLowPathMTU.ps1
	TS_DetectLowPathMTU.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_HyperV ---"
	# Hyper-V Info 2008R2
	Run-DiagExpression .\TS_HyperVInfo.ps1

	# Detect Virtualization
	Run-DiagExpression .\TS_Virtualization.ps1

	# Missing Hotfix 
	Run-DiagExpression .\TS_HyperVEvent106Check.ps1

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

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_DOM ---"
	# DCDiag information
	Run-DiagExpression .\TS_DCDiag.ps1
	
	# Check AD Replication Status
	Run-DiagExpression .\TS_ADReplCheck.ps1

	# Checks if CrashOnAuditFail is either 1 or 2
	Run-DiagExpression .\TS_CrashOnAuditFailCheck.ps1

	# SYSVOL and/or NETLOGON shares are missing on domain controller
	Run-DiagExpression .\TS_LSASSHighCPU.ps1

	# SYSVOL and/or NETLOGON shares are missing on domain controller
	Run-DiagExpression .\TS_SysvolNetLogonShareCheck.ps1

	# Missing Rid Set reference attribute detected
	Run-DiagExpression .\TS_ADRidSetReferenceCheck.ps1

	# AD Integrated DNS Server should not point only to itself if it has replica partners.
	Run-DiagExpression .\TS_DCCheckDnsExclusiveToSelf.ps1

	# [Idea ID 3768] [Windows] New rule to verify USN Roll Back
	Run-DiagExpression .\TS_USNRollBackCheck.ps1

	# [Idea ID 2882] [Windows] The stop of Intersite Messaging service on ISTG causes DFSN cannot calculate site costs
	Run-DiagExpression .\TS_IntersiteMessagingStateCheck.ps1

	# [Idea ID 2831] [Windows] DFSR Reg setting UpdateWorkerThreadCount = 64 may cause hang
	Run-DiagExpression .\TS_DfsrUpdateWorkerThreadCountCheck.ps1

	# [Idea ID 2593] [Windows] UDP 389 on DC does not respond
	Run-DiagExpression .\TS_IPv6DisabledonDCCheck.ps1

	# [Idea ID 4724] [Windows] W32Time and time skew
	Run-DiagExpression .\TS_Win32TimeTimeSkewRegCheck.ps1

	# [Idea ID 4796] [Windows] MaxConcurrentApi Problem Detection Lite
	Run-DiagExpression .\TS_MCALite.ps1

	# [Idea ID 5009] [Windows] Weak Key Block Detection
	Run-DiagExpression .\TS_DetectWeakKeys.ps1

	# [Idea ID 6816] [Windows] Detect Certificate Root Store Size Problems
	Run-DiagExpression .\TS_DetectRootSize.ps1
	
	# Check DFSR configuration
	Run-DiagExpression .\TS_DFSRRootCausesCheck.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Print ---"
	# Print Information Report
	Run-DiagExpression .\TS_PrintInfo.ps1

	# [KSE Rule] [ Windows V3] Presence of lots of folders inside \spool\prtprocs\ causes failure to install print queues
	Run-DiagExpression .\TS_PrtprocsSubfolderBloat.ps1

	# Checks if machine is server 2008 R2 sp0 or sp1, and event log 602 exists, and hotfix kb 2457866 is installed if true generate alert
	Run-DiagExpression .\TS_PrinterKB2457866Check.ps1

	# Checks if a Kyocera print driver is installed then checks if KB982728 is installed
	Run-DiagExpression .\TS_PrinterKB982728Check.ps1

	# Checks if Point and Print Restriction Policy and then look for specifc events on event logs
	Run-DiagExpression .\TS_PrinterKB2618460Check.ps1

	# Checks to see if HP Standard TCP/IP Port key is present on the system
	Run-DiagExpression .\TS_PrintingHPTCPMonCheck.ps1

	# Checking if 'Net Driver HPZ12' or 'Pml Driver HPZ12' is one of the installed services and startup type is something different than Disabled
	Run-DiagExpression .\TS_HPZ12ServiceCheck.ps1

	# Detect the OEM HP driver hpzui4wm.DLL
	Run-DiagExpression .\TS_PrintHpzui4wmCheck.ps1

	# Check for the presence of Zenographics Device Manager User Interface
	Run-DiagExpression .\TS_Check_ZenographicsUI.ps1

	# Check for upgrade from HP UPD 5.2 to 5.3
	Run-DiagExpression .\TS_2628581_HPUPDUpgrade.ps1

	# [Idea ID 2226] [Windows] Old SHD and SPL files residual in the Spool directory cause issues
	Run-DiagExpression .\TS_PrintSpoolerOldSPLSHD.ps1

	# [Idea ID 1872] [Windows] Detecting bloated HKEY_USERS\.default\printers\Devmodes2 registry key on Terminal servers
	Run-DiagExpression .\TS_PrintDevModes2CountCheck.ps1

	# [Idea ID 3462] [Windows] Printing issue - multiple SETxnnn.tmp files
	Run-DiagExpression .\TS_PrintSetTMPSystem32Check.ps1

	# [Idea ID 4091] [Windows] frequent spooler crash due to zsdnt5ui.dll
	Run-DiagExpression .\TS_PrintZSDDMUICheck.ps1

	# [Idea ID 4168] [Windows] Check for existence of 2647753  for printing issues
	Run-DiagExpression .\TS_Win7PrintUpdateRollupCheck.ps1

	# [Idea ID 2374] [Windows] Spooler service hangs since CSR exhausts the 512 threads in thread pool
	Run-DiagExpression .\TS_PrintCSRBloatingCheck.ps1

	# [Idea ID 4805] [Windows] Printers show Offline on Windows 7 clients
	Run-DiagExpression .\TS_PrinterShowOffline.ps1

	# [Idea ID 5470] [Windows] GPP printer fails to add with error code 0x80070704
	Run-DiagExpression .\TS_GPPDeployPrinterCheck.ps1

	# [Idea ID 6863] [Windows] GPP printer fails to be added since LocalEnumForms returns error 8007007a
	Run-DiagExpression .\TS_GPPMapPrinterKB2797136.ps1

	# [KSE Rule] [ Windows V3] HKCU\Software\Hewlett-Packard registry hive increases in size on Citrix servers
	Run-DiagExpression .\TS_HPPrinterDriverVersionCheck.ps1

	# List Schedule Tasks using schtasks.exe utility
	Run-DiagExpression .\TS_SpoolerDumpInfo.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_RDS ---"
	# Checking the presence of Citrix AppSense 8.1
	Run-DiagExpression .\TS_CitrixAppSenseCheck.ps1

	# Check for large number of Inactive Terminal Server ports
	Run-DiagExpression .\TS_KB2655998_InactiveTSPorts.ps1

	# [Idea ID 2285] [Windows] Windows Server 2003 TS Licensing server does not renew new versions of TS Per Device CALs
	Run-DiagExpression .\TS_RemoteDesktopLServerKB2512845.ps1
	
	Run-DiagExpression .\TS_KernelAuthRPCCheck.ps1

	if (test-path $env:Windir\System32\BestPractices\v1.0\Models\Microsoft\Windows\TerminalServices) {
		# BPA RDP
		if ($Global:skipBPA -ne $true) {
		Run-DiagExpression .\TS_BPAInfo.ps1 -BPAModelID "Microsoft/Windows/TerminalServices" -OutputFileName ($Computername + "_TS_BPAInfo.HTM") -ReportTitle "Terminal Services Best Practices Analyzer"
		}
	}
	
Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Storage ---"
	# Detect 4KB Drives (Disk Sector Size)
	Run-DiagExpression .\TS_DriveSectorSizeInfo.ps1

	# [Idea ID 7345] [Windows] Perfmon - Split IO Counter
	Run-DiagExpression .\TS_DetectSplitIO.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Setup ---"
	# Collect Setup Event Log for Servicing
	Run-DiagExpression .\TS_ServicingEventLogs.ps1

	# check for WMI corruption on HP systems
	Run-DiagExpression .\TS_HPWMICheck.ps1

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

	# [Idea ID 5452] [Windows] The �Red Arrow� issue in Component Services caused by registry keys corruption
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

	# [Idea ID 3474] [Windows] Pending Trans Rule - PendingXmlIdentifier, NextQueueEntryIndex, AdvancedInstallersNeedResolving
	Run-DiagExpression .\TS_ServicingComponentsReg.ps1

	# [Idea ID 3472] [Windows] Pending Transactions Rule Idea - Pending.xml
	Run-DiagExpression .\TS_ServicingPendingXml.ps1

	# [Idea ID 5712] [Windows] Run Dism checkhealth on Win8 or 2012 to detect possible servicing corruption
	Run-DiagExpression .\TS_ServicingCorruptionCheck.ps1

	# [Idea ID 1922] [Windows] On Windows 2008 R2 and Windows 7 System state backup fails with event id 5 and error 2155347997
	Run-DiagExpression .\TS_BackupSystemStateKB2182466.ps1

	# [Idea ID 3059] [Windows] Ntbackup high CPU and hang
	Run-DiagExpression .\TS_FilesNotToBackup2K3Check.ps1

	# [Idea ID 2004] [Windows] Bitlocker Drive Preparation fails with Error 'The new active drive cannot be formatted.'
	Run-DiagExpression .\TS_BitlockerDenyWriteFixedPolicy.ps1

	# [Idea ID 6711] [Windows] MSI package fails to install with error code HRESULT -2147319780
	Run-DiagExpression .\TS_MSIPackageInstallationCheck.ps1

	# [Idea ID 3002] [Windows] SP1 installation on Windows 7 and Windows Server 2008 R2 fails with the error 0x800F0826
	Run-DiagExpression .\TS_UsbstorSystemPermissionsSPCheck.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_WinRM ---"
	# Check if hotfix 2480954 installed
	Run-DiagExpression .\TS_KB2480954AndWinRMStateCheck.ps1

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - Diag Phase module: TS_Surface ---"
	# SurfaceDetectWifiDriverVersion
	Run-DiagExpression .\TS_SurfaceDetectWifiDriverVersion.ps1

	# SurfaceDetectFirmwareVersions
	Run-DiagExpression .\TS_SurfaceDetectFirmwareVersions.ps1

	# SurfacePro3DetectWifiDriverVersion
	Run-DiagExpression .\TS_SurfacePro3DetectWifiDriverVersion.ps1

	# SurfacePro3DetectFirmwareVersions
	Run-DiagExpression .\TS_SurfacePro3DetectFirmwareVersions.ps1

	# SurfaceDetectConnectedStandbyStatus
	Run-DiagExpression .\TS_SurfaceDetectConnectedStandbyStatus.ps1
	
	# SurfacePro3DetectConnectedStandbyStatus
	Run-DiagExpression .\TS_SurfacePro3DetectConnectedStandbyStatus.ps1

	# SurfacePro3DetectConnectedStandbyHibernationConfig
	Run-DiagExpression .\TS_SurfacePro3DetectConnectedStandbyHibernationConfig.ps1

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
	# [Idea ID 7521] [Windows] McAfee HIPS 7.0 adds numerous extraneous network adapter interfaces to registry
	Run-DiagExpression .\TS_McAfeeHIPS70Check.ps1

	# [Idea ID 986] [Windows] SBSL McAfee Endpoint Encryption for PCs may cause slow boot or delay between CTRL+ALT+DEL and Cred
	Run-DiagExpression .\TS_SBSL_MCAfee_EEPC_SlowBoot.ps1

	# [Idea ID 3181] [Windows] Symantec Endpoint Protection's smc.exe causing handle leak
	Run-DiagExpression .\TS_SEPProcessHandleLeak.ps1

	# Symantec Endpoint Protection MR1 or MR2 check
	Run-DiagExpression .\TS_SymantecEPCheck.ps1
	
	# Check for Sophos BEFLT.SYS version 5.60.1.7
	Run-DiagExpression .\TS_B2693877_Sophos_BEFLTCheck.ps1

	# [KSE Rule] [ Windows V3] HpCISSs2 version 62.26.0.64 causes 0xD1 or 0x9E
	Run-DiagExpression .\TS_HpCISSs2DriverIssueCheck.ps1

	# check for WMI corruption on HP systems
	Run-DiagExpression .\TS_HPWMICheck.ps1

	# Symantec Intrusion Prevenstion System Check
	Run-DiagExpression .\TS_SymantecIPSCheck.ps1

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

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object " --- $(Get-Date -Format 'yy-mm-dd HH:mm:ss') $Global:SDPtech - TS Phase module: ModernApps ---"
	# [Idea ID 7524] [Windows] WinStore -Modern applications fail to start if 'Audit the access of global system object' is enabled [AutoAdded]
	Run-DiagExpression .\TS_ModernAppsFailureForAuditOptionCheck.ps1

	# [Idea ID 7723] [Windows] WinStore - Modern applications fail to start if incompatible security - av software installed [AutoAdded]
	Run-DiagExpression .\TS_ModernAppsFailureForWindDefenderCheck.ps1

	# [Idea ID 7727] [Windows] WinStore - Cannot install Windows Store Apps [AutoAdded]
	Run-DiagExpression .\TS_ModernAppsFailureForTrustedPathCredentialsCheck.ps1

	# [Idea ID 7712] [Windows] WinStore - Modern Apps fail to run if the UAC File Virtualization driver is not running [AutoAdded]
	Run-DiagExpression .\TS_ModernAppsFailureForUACFileVirtualizationCheck.ps1

	# [Idea ID 7508] [Windows] WinStore - This app cannot open while the User Account Control is turned off [AutoAdded]
	Run-DiagExpression .\TS_ModernAppsFailureForUACDisabledCheck.ps1

	# [Idea ID 6253] [Windows] Win8:APP - Store Apps do not launch due to video resolution [AutoAdded]
	Run-DiagExpression .\TS_StoreAppsFailureForVideoResolutionCheck.ps1

	# [Idea ID 7499] [Windows] Win8:APP - Skype fails to start [AutoAdded]
	Run-DiagExpression .\TS_SkypeFailureForMissingKB2703761Check.ps1

	# [Idea ID 7544] [Windows] WinStore - Apps do not launch, because 'ALL APPLICATIONS PACKAGES' removed from DCOM ACL [AutoAdded]
	Run-DiagExpression .\TS_StoreAppsFailureForDCOMErrorCheck.ps1

	# [Idea ID 7510] [Windows] WinStore - Apps fail to start if default registry permissions modified [AutoAdded]
	Run-DiagExpression .\TS_ModernAppsFailureForRegistryPermissionCheck.ps1

	# [Idea ID 7546] [Windows] WinStore - Modern Apps Fail to Start if the User Profile directory is Moved from default [AutoAdded]
	Run-DiagExpression .\TS_ModernAppsFailureForUserProfileDirCheck.ps1

	# [Idea ID 7547] [Windows] WinStore - Modern Apps Fail to Start if the ProgramData directory is Moved from default [AutoAdded]
	Run-DiagExpression .\TS_ModernAppsFailureForProgramDataDirCheck.ps1

	# [Idea ID 7512] [Windows] WinStore - Apps fail to start if default file permissions modified [AutoAdded]
	Run-DiagExpression .\TS_ModernAppsFailureForFolderPermissionCheck.ps1
}

if ($Global:runFull -eq $True) {
	#_# newer Setup_Addons, DC_Setup_AppCompat.ps1 long lasting REG task
	Run-DiagExpression .\DC_Setup_Addons.ps1
	Run-DiagExpression .\DC_Setup_AppCompat.ps1
}

# Hotfix Rollups
Run-DiagExpression .\DC_HotfixRollups.ps1

$stopTime_AutoAdd = Get-Date
$duration = $(New-TimeSpan -Start $startTime_AutoAdd -End $stopTime_AutoAdd)

Write-Host -BackgroundColor Gray -ForegroundColor Black -Object "*** $(Get-Date -UFormat "%R:%S") DONE (Dur: $duration) TS_AutoAddCommands_ALL.ps1 SkipTS: $Global:skipTS - SkipBPA: $Global:skipBPA"


# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA52kvvGtsSt3Cu
# nZXI01gzt76kc0TgayNskC72sfskRqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIEaZUcNBZFRRNVnSCWXdost5
# TyxIG8341kBdXYg0pzsCMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCMMBDiWLdQZ9fYKkZy2n06gX79FMfTr+3rBiUi43bVTbRPGM39JZds
# 4X+pTM8ZimmmuhDRQ/M2CSIdpvDEkX6fi2qfmhj2Xa3MB8efLgUQyzEkOuriAen5
# z0oax11+xdCkt/YGBRKX0X3WWlxRRuDDN4kCfJ2nXpy/QGja4kQHa3Flb5ibPVo/
# mzqAJF6e89Wn/XjkpXhBzR8ljK0qKuE3vvkpeTfwUJDy+Nzz7r6Jen/IShrzyw7g
# Z6oNqh+e6zgGRwyhhS0CpFsiU7i11tQLE8JLJ/qRwQZ2d7GIc++xy9wIVvLK4mYE
# YqDiVbejA0NJLjZfsBfiaZmlmmWVn/bioYIW/TCCFvkGCisGAQQBgjcDAwExghbp
# MIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIB5JaEUFLtQ8HH7TXGDMj5+TYFaE300765pX1Doy1KQmAgZj7hXf
# ch4YEzIwMjMwMjI3MDkxMDM0Ljk5NlowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkREOEMt
# RTMzNy0yRkFFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVDCCBwwwggT0oAMCAQICEzMAAAHFA83NIaH07zkAAQAAAcUwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkw
# MTMyWhcNMjQwMjAyMTkwMTMyWjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046REQ4Qy1FMzM3LTJGQUUxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCrSF2zvR5fbcnulqmlopdGHP5NPsknc69V/f43x82n
# FGzmNjiES/cFX/DkRZdtl07ibfGPTWVMj/EOSr7K2O6I97zEZexnEOe2/svUTMx3
# mMhKon55i7ySBXTnqaqzx0GjnnFk889zF/m7X3OfThoxAXk9dX8LhktKMVr0gU1y
# uJt06beUZbWtBEVraNSy6nqC/rfirlTAfT1YYa7TPz1Fu1vIznm+YGBZXx53ptkJ
# mtyhgiMwvwVFO8aXOeqboe3Bl1czAodPdr+QtRI+IYCysiATPPs2kGl46yCz1OvD
# JZNkE1sHDIgAKZDfiP65Hh63aFmT40fj0qEQnJgPb504hoMYHYRQ0VJhzLUySC1m
# 3V5GoEHSb5g9jPseOhw/KQpg1BntO/7OCU598KJrHWM5vS7ohgLlfUmvwDBNyxoP
# K7eoCHHxwVA30MOCJVnD5REVnyjKgOTqwhXWfHnNkvL6E21qR49f1LtjyfWpZ8CO
# hc8TorT91tPDzsQ4kv8GUkZwqgVPK2vTM+D8w0lJvp/Zr/AORegYIZYmJCsZPGM4
# /5H3r+cggbTl4TUumTLYU51gw8HgOFbu0F1lq616lNO5KGaCf4YoRHwCgDWBJKTU
# QLllfhymlWeAmluUwG7yv+0KF8dV1e+JjqENKEfBAKZmpl5uBJgeceXi6sT7grpk
# LwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFFTquzi/WbE1gb+u2kvCtXB6TQVrMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAIyo3nx+swc5JxyIr4J2evp0rx9OyBAN5n1u9CMK7E0glkn3b7Gl4pEJ/der
# jup1HKSQpSdkLp0eEvC3V+HDKLL8t91VD3J/WFhn9GlNL7PSGdqgr4/8gMCJQ2bf
# Y1cuEMG7Q/hJv+4JXiM641RyYmGmkFCBBWEXH/nsliTUsJ2Mh57/8atx9uRC2Jih
# v05r3cNKNuwPWOpqJwSeRyVQ3+YSb1mycKcDX785AOn/xDhw98f3gszgnpfQ200F
# 5XLC9YfTC4xo4nMeAMsJ4lSQUT0cTywENV52aPrM8kAj7ujMuNirDuLhEVuJK19Z
# lIaPC36UslBlFZQJxPdodi9OjVhYNmySiFaDvvD18XZBuI70N+eqhntCjMeLtGI+
# luOCQkwCGuGl5N/9q3Z734diQo5tSaA8CsfVaOK/CbV3s9haxqsvu7mpm6TfoZvW
# YRNLWgDZdff4LeuC3NGiE/z2plV/v2VW+OaDfg20gIr+kyT31IG62CG2KkVIxB1t
# dSdLah4u31wq6/Uwm76AnzepdM2RDZCqHG01G9sT1CqaolDDlVb/hJnN7Wk9fHI5
# M7nIOr6JEhS5up5DOZRwKSLI24IsdaHw4sIjmYg4LWIu1UN/aXD15auinC7lIMm1
# P9nCohTWpvZT42OQ1yPWFs4MFEQtpNNZ33VEmJQj2dwmQaD+MIIHcTCCBVmgAwIB
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
# IEVTTjpERDhDLUUzMzctMkZBRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAIQAa9hdkkrtxSjrb4u8RhATHv+eg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOemay8wIhgPMjAyMzAyMjcwNzM1MTFaGA8yMDIzMDIyODA3MzUxMVow
# dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA56ZrLwIBADAHAgEAAgIcNjAHAgEAAgIR
# bTAKAgUA56e8rwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAKZsso+sF6xH
# 5ZlEJ2hx0PcaOqrJRFPIWIYCbkhhL2bsVwWNhAiH9V/mVHkMzfWVkSMn6O19g0oi
# Ek94fT+SFHIjtbCmGy8tFZuv8PDq1LC6Ambm9ByGEGK6xPUKoSjy0EXyHMS2XqD/
# 4TOZ8XgMc+QT2f0GmlIlQ2FvfbvqX4XrMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHFA83NIaH07zkAAQAAAcUwDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgiQ+cAkAonojvbxXVZpr2oPuEsul7XnztPbc+nmwoO6QwgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAZAbGR9iR3TAr5XT3A7Sw76ybyAAzKPkS4
# o+q81D98sTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABxQPNzSGh9O85AAEAAAHFMCIEIJ4sPPdzRQcMIOpHsMWgy1AWEA5gDZY/e906
# gfbRZmjgMA0GCSqGSIb3DQEBCwUABIICAJIxzMhIF2gjlVfdn0JU2rdh5TzAb5RU
# 5LjLmn0qTr5nVfcl2TSl4JiMSH8OKQZi0JL6fRdK3c8RGsxk1gIozdFBLFWznyn0
# x/6nx2zplKmIv3rEInIMvdsBr2qN/C+iLo9kDAimDmn4umGGktB9bdx2uay4L7c6
# i0l8LcoCfx6jqobhan8cvbCibI6/tLtqRLm7RFA+6OMKr7TYCshCZR66ax+zBSLA
# InUBQwnOXoGimRpyc1uyJ573KschbASlRKjOiYaygra5i2SfsVKyH5BNjSm298/y
# ZcNaWB4nKmndd5/OYDbHDjxItQJ5ueF6BqikpEkLuOgujQ+WXD3EXaNFdOKP9Mbl
# dTGP7wDOUgCTJ5YCcGOMMPcsKKKtPLTGG9/FYR2InJRpe0j5QUMk1PXf4lzA2Awc
# 7tiv9HVwccb5gQSBhgFVG7H58OgL1uJi65ZYbGXDD986iT2EXl/9S9IOlwFvGWbG
# g36nH//aYoz9MWT2/eo8+G6F9Xckbx1DfY3ayudDlqEeGfmanvSxjuJO/gychRom
# JK5zoQjNDLw2CJ0HHkYHij/z18DNUmLNFe9lr0yg6A62OapWmFe9s4/8q6GLRcM2
# 4iV03uXqDhfO04sooscWNBhJLu5GaiscYyTIs0wmyoYvWRpE83AkGO9o5zfTmyJ1
# nODEHHqCkEL6
# SIG # End signature block
