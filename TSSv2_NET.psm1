<# File: TSSv2_NET.psm1
.SYNOPSIS
	NET module for collecting ETW traces and various custom tracing functionality

.DESCRIPTION
	Define ETW traces for Windows NET components 
	Add any custom tracing functinaliy for tracing NET components
	For Developers:
	1. Switch test: .\TSSv2.ps1 -Start -NET_NDIS
	2. Scenario test: .\TSSv2.ps1 -start -Scenario NET_TestMe -mini -noZip -noSDP -noXray -noBasicLog

.NOTES
	Dev. Lead: WalterE
	Authors  : WalterE; MuratK; Sergey.Akinshin; Tfairman
	Requires : PowerShell V4 (Supported from Windows 8.1/Windows Server 2012 R2)
	Version	 : see $global:TssVerDateNET

.LINK
	TSSv2 https://internal.support.services.microsoft.com/en-us/help/4619187
	NET https://internal.support.services.microsoft.com/en-US/help/4648588
#>

<# latest changes
ToDo: replace (Get-TimeZone).DisplayName with [System.TimeZoneInfo]::Local.DisplayName

::  2023.05.22.0 [we] _NET: fix duplicate CollectNET_MBNLog()
::  2023.05.19.3 [tfairman] _NET: Move SCM component to TSSv2_PRF
::  2023.05.18.0 [tfairman] _NET: Deprecate SDN component / point user to URL in help listing
::  2023.05.17.0 [tfairman] _NET: Remove non-important console messages (poststop / collect / helper routines), redirect to file
::  2023.05.17.0 [we] _NET: deprecate NET_iSCSI
::  2023.05.16.0 [tfairman] _NET: Remove non-important console messages (prestart routines), redirect to file
::  2023.05.15.0 [we] _NET: reduce some spew (getNetcfg, getNetFiles, getNetSh-http-show-UrlAcl)
::  2023.05.07.0 [we] _NET: fix Eventlog names for DHCP-Client/*
::  2023.04.20.0 [we] _NET: fix NET_VPN NetshScenario for Srv2016 (scenario=VpnClient* not supported)
::  2023.04.18.1 [we] _NET: add NET_NDIScap; modify NET_fskm
::  2023.04.18.0 [we] _NET: move NET_PerfLib to PRF_PerfLib
::  2023.04.17.0 [we] _NET: activate "Microsoft-Windows-DHCP Client Events/Operational"
::  2023.04.12.0 [we] _NET: add FWgetFltMcInfo to NET_stop_common_tasks
::  2023.04.07.0 [we] _NET: consolidate, moved NET_PnP to DND_PnP
::  2023.04.06.0 [we] _NET: moved NET_PrintSvc into UEX_Print
::  2023.04.03.0 [we] _FW: fix define global:FwSetMCF; _NET: NET_NPS providers: remove provider which is included in ADS_SSL
::	2023.03.23.0 [we] _NET: fix NET_DHCPsrv Guid for Srv2012R2
::	2023.03.16.1 [we] _NET: NET_SMBsrv: run getNetFiles() only at _start_
::	2023.03.16.0 [we] _NET: add -Width 999 for some PS outputs
::	2023.03.14.0 [we] _NET: mod Reg.keys UNChard1; add correlation=disabled to NET_HypHost NetSh (kb5025648)
::	2023.03.08.1 [we] _NET: add NET_NPS provider for EapHost
::	2023.03.08.0 [we] _NET add CAPI2 Evt to NET_VPN
::	2023.03.07.0 [we] _NET add Reg. DefenderATP to NET_SMBsrv and NET_WorkFolders
::	2023.03.04.0 [we] _NET enhance RunNET_SMBsrvPerm()
::	2023.03.02.0 [we] _NET add Reg. DefenderATP to NET_SMBcli
::	2023.02.21.0 [we] _NET WebIO add EvtLog "Microsoft-Windows-WebIO/Diagnostic"
::	2023.02.20.0 [we] _NET removed '-Encoding ascii' for NFS commands; for file IP_Srv_Wks_Info: SMB Server/Workstation info was moved to files SMB_Server_Info/SMB_Workstation_Info; use FW functions FwGetArp,FwGetIPconfig,FwGetNetstat,FwGetSMBserverInfo,FwGetSMBwkstaInfo
::	2023.02.15.0 [we] _NET enhance getWLANinfo() output; add NET_Wlan component, add FwGetWhoAmI() to NET_stop_common_tasks; add getNICinfo()
::	2023.02.14.0 [we] _NET FwExportRegistry "UNC hardening" $KeysUNChard1; add Arp-table to NET_NLB
::	2023.02.13.1 [we] _NET add Reg "SMBsrv","LSA", move "DotNETFramework" reg keys to -noRecursive
::	2023.02.08.0 [we] _NET replaced reg "NETFramework" with "DotNETFramework"
::	2023.02.04.0 [we] _NET robustify copyMachineUserProfiles() and copyWLANProfiles()
::	2023.02.03.0 [we] _NET adjust NET_Auth (after _ADS: integrated Auth-start/-stop scripts (v4.7) into component/scenario ADS_Auth)
::	2023.01.31.0 [we] _NET fix -StartAutologger NET_FireWall, NET_BFE, NET_Wfp, NET_NetProfM
::	2023.01.19.1 [we] _NET add NET_WinNAT to NET_HypHost
::	2023.01.18.0 [we] _NET use FwCreateFolder if folder does not exist
::	2023.01.18.0 [we] _NET moved function setMCF() to _FW: FwSetMCF; $NET_DummyProviders = @()
::	2023.01.17.0 [we] _NET included Srv2019 again in setMCF
::	2023.01.13.0 [we] _NET exclude MdmDiagnosticsTool on SrvCore or PreW10
::	2023.01.11.0 [we] _NET add Reg Multimedia\SystemProfile to KeysSMB
::	2022.12.30.0 [we] _NET remove ServicesForNFS-ONCRPC from Net_NDFcli; add getSMBsrvBinding() for -Collect NET_SMBsrvBinding, add \scripts\Tss_SMB_Fix-SmbBindings.ps1
::	2022.12.28.0 [we] _NET replaced ADS_GroupPolicy with ADS_GPO
  2022.12.27.0 [we] _NET: remove components NET_SBSL,NET_UNChard
  2022.12.24.1 [we] _NET: remove NET_AfdTcpFull from NET_WFP scen., as providers are now included in NET_WFP comp; remove NET_NetIO comp 
  2022.12.24.0 [we] _NET: add NET_WinInet and consolidate WinInet
  2022.12.23.1 [we] _NET: Docker: check for Hyper-V to decide for NetShScenario; add getBFEregPerm(); Marcussa: add Component NET_MBN, upd MBN scenario, add IPsec scenario
  2022.12.15.0 [we] _NET: add LLDP LinkLayerDiscoveryProtocol
  2022.12.13.0 [we] _NET: add LLTDIO (Link-Layer Topology Discovery Mapper I/O Driver)
  2022.12.12.0 [we] _NET: fix NET_WebCliTTD; re-enable NET_HTTPsys description
  2022.12.09.0 [we] _NET: fix RaMgmtSvc status for setMCF(), added FwListProcsAndSvcs
  2022.12.07.0 [we] _NET: add $ADS_Netlogon to -NET_Auth
  2022.12.04.0 [we] _NET: mod getBCInfo; replace $OSVER3
  2022.12.02.0 [we] _NET: mod PS Cmdlet for BranchCache to count *.tmp files
  2022.11.28.0 [we] _NET: consolidating NET_WMI with UEX_WMI, NET_AppV with UEX_AppV
  2022.11.22.1 [we] _NET: add VmsNicProxy,VmsProxyCtrlGuid to VMswitch
  2022.11.22.0 [mm] _NET: replaced ssl etl traces in NET_TLS with ADS SSL module 
  2022.11.17.0 [we] _NET: add SmbCA (SMB Direct), mod NET_RDMA to include SmbCA + Perfmon ALL
  2022.11.17.0 [we] _NET: add SmbCA (SMB Direct), mod NET_RDMA to include SmbCA + Perfmon ALL
  2022.11.15.0 [we] _NET: Dis-/Enable MulticastForwarding based on Servcie status of RemoteAccess -or RaMgmtSvc
  2022.11.14.0 [we] _NET: NET_BFE get BFE_Registry_permissions
  2022.11.03.1 [we] _NET: fix path with possible blank characters for robocopy (i.e. $Env:LocalAppData); add -NetProfM to scenarios NCSI and Firewall 
  2022.10.22.0 [we] _NET: add query SMBsrv Share/NTFS permissions with '-Mode Permission'
  2022.10.19.0 [we] [psSDP] DFSsrv Evt-logs/reg.keys
  2022.10.14.0 [we] _NET: add "Rpc" reg collection to SMBcli
  2022.10.06.0 [we] _NET: move Microsoft-Windows-Ras-NdisWanPacketCapture into NetSh packetcapture
  2022.09.01.0 [we] _NET: add NET_SSTP
  2022.08.31.0 [we] _NET: add NetProfM
  2022.08.28.0 [we] _NET: fix CollectNet_IIS/IPAM
  2022.08.20.0 [we] _NET: add SMB reg keys to SMB*scenarios
  2022.08.18.0 [we] _NET: add NET_LDAPsrv
  2022.08.17.0 [we] _NET: add Microsoft-Windows-EQoS to NET_QoS
  2022.08.16.1 [we] _NET: add NET_Quic; adding QUIC to SMBcli and SMBsrv scenarios
  2022.08.12.0 [we] _NET: add NET_NPS provider GUIDS
  2022.08.11.2 [we] _NET: mod OpenSSH; add sshd_config_default; for DHCPcli: add EvtLogsDHCPcli
  2022.08.10.1 [we] _NET: add "FwCopyMemoryDump -DaysBack 2" to stop_common_task
  2022.08.10.0 [we] _NET: corrected typo in itatap (=isatap ), add $EvtLogsNcsiAnalytic
  2022.08.08.1 [we] _NET: add OpenSSH
  2022.08.03.0 [we] _NET: DNSsrv: check if DNS server is running; mod LDAPcli
  2022.08.02.0 [we] _NET: mod NET_NFSsrv, add NFS commands for downlevel OS
  2022.08.01.0 [we] _NET: add var $TLStestSite to make PSScriptAnalyzer happy
  2022.07.28.0 [we] _NET: NET_GeoLocation
  2022.07.27.0 [we] _NET: removed Get-DnsServerResourceRecord in getDNSsrvInfo()
  2022.07.26.0 [we] _NET: add getWfpShow for NET_WFP; add DNS server Policy infos; add $EvtLogsQoSAnalytic to NET_QoS
  2022.07.20.0 [we] _NET: add 'PowerCfg.exe /sleepstudy'
  2022.07.14.0 [we] _NET: add TLS to Branchcache
  2022.07.13.0 [we] _NET: removed '-Encoding ascii' for NCSI Get-NetConnectionProfile
  2022.07.11.0 [we] _NET: add 'NET_Firewall' and FwGetGPresultAS to Branchcache
  2022.07.07.0 [we] _NET: add output of PowerCfg /a (#662)
  2022.07.05.0 [we] _NET: mod NET_VPN to include AzureVpn log files (#657)
  2022.06.20.0 [we] _NET: add RASdiag to VPN
  2022.06.10.0 [we] _NET: add NFScli GUIDs (#issue #646), add NDIS to LBFoProviders (#issue #636)
  2022.06.08.0 [we] _NET: removing component -WebCliTTD but keeping -Scenario
  2022.06.07.0 [we] _NET: add NET_SQLcheck, also added to psSDP
  2022.06.06.0 [we] _NET: fix partially WebCliTTD 
  2022.06.03.0 [we] _NET: fix WebClient, add WebCliTTD, use GUIDs for FwAuditPolSet() calls
  2022.05.31.0 [we] _NET: add NET_WLAN again; obey global:IsLiteMode
  2022.05.25.0 [mk] _NET: add Afdtcpfull to NET_hyphost scenario, removed smbcli and smbsrv from NET_hyphost
  2022.05.24.0 [we] _NET: add Win32_DeviceGuard to VPN/808.1x scenario
  2022.05.19.2 [we] _NET: avoid NFScli for SMB/SMBcli/DFScli; fix DFScli,NFScli,RDMA,DFSsrv; add *SMBshare_Info*.txt
  2022.05.13.0 [we] _NET: check for DFS-N server
  2022.05.12.0 [we] _NET: mod NFScli; upd getDFSsrvInfo()
  2022.05.11.0 [we] _NET: timeout for DFSnRoot; upd NFScli for NfsMappedIdentity
  2022.05.09.0 [we] _NET: upd WIP fixes, upd EFS
  2022.05.06.1 [we] _NET: upd NET_AppV; add WIP
  2022.05.05.0 [we] _NET: add -Mode NFSperm/Permission; NPS srv check
  2022.04.22.0 [we] _NET: add RunNET_DFSnDiag, getDFSsrvInfo
  2022.04.13.0 [we] _NET: replace WMIC commands; add FwGetGPresultAS to SMBsrv
  2022.04.12.0 [we] _NET: fix DnsCmd outputs
  2022.04.08.0 [we] _NET: upd Net_printSvc
  2022.04.01.0 [we] _NET:  add for Firewall: FwAuditpolSet '"Filtering Platform Packet Drop","Filtering Platform Connection"'
  2022.03.31.0 [we] _NET: IPsec (#552) Enabling IPsec related Events in Security Eventlog via AuditPol.exe
  2022.03.28.0 [we] _NET: dont run 'netstat -anoq' on OS<9600
  2022.03.23.0 [we] _NET: add Procmon to NET_Auth
  2022.03.21.0 [we] _NET: upd Miracast
  2022.03.07.0 [we] _NET: fix Net_CSC
  2022.03.01.0 [we] _NET: fix PktMon for _Firewall on downlevel OS
  2022.02.22.0 [we] _NET: fix missing SMB analystic logs depending on OS
  2022.02.17.0 [we] _NET: remove "Microsoft-Windows-WLAN-AutoConfig/Operational" on ServerSKU
  2022.02.14.0 [we] _NET: fix $DirRepro variable
  2022.02.11.0 [we] _NET: upd NET_NCSI provider
  2022.02.10.0 [we] _NET: upd DHCPcli help
  2022.02.06.0 [we] _FW: added missing NET_RDS* and DNS_Setup* descriptions
  2022.02.04.0 [we] _NET: if (!Mode -eq "Basic") {VpnClient_dbg}, fix Workfolders
  2022.02.03.0 [we] _FW: ignore errors for "Get-WinEvent -Oldest ..", add FwGetSrvSKU(),FwGetSrvRole(); _NET add FwGetSrvRole to Start_common
  2022.02.01.0 [we] _NET: add NET_Auth,NET_Proxy as component tracing; Providers must not have '_' or '-' in name
  2022.01.31.0 [we] _FW: mod. update-script
  2022.01.29.2 [we] _FW: full NotMyFaultPath + /AcceptEula, mod. display of Test_* functions i.e. Test_File
  2022.01.28.0 [we] _NET: add RD Licensing server providers to RdsSrv
  2022.01.27.1 [we] _FW: fixed missing folder $PreviousError for -Help/-Version & $Error exists
  2022.01.25.0 [we] _NET: add Container
  2022.01.24.0 [we] _FW: upd ListSupportedCommands
  2022.01.22.5 [we] _FW: minor cleanup and help changes; mod -LiveKd Start; swapped string "Running" with [System.ServiceProcess.ServiceControllerStatus]::Running; added helper functions ProcessBasicLog, FwTest-TCPport
  2022.01.18.0 [we] _FW: add Function FwTestConnWebSite, upd tss_update-script.ps1
  2022.01.16.0 [we] _FW: upd minor help lines; _NET: add RdsBrokerMan to NET_RDSsrv
  2022.01.14.0 [we] fix psSDP TS_MCAlite.ps1
  2022.01.13.1 [we] _NET:  upd PrintSvc, add NET_UNChard,SBSL
  2022.01.13.0 [we] _NET: add NET_RDScli,NET_RDSsrv
	_FW: add FwGetEnv(), FwQwinsta()
  2022.01.12.0 [we] _NET: add "Microsoft-Windows-VPN-Client" to VPN, add IPsec to VPN/WFP scenario
  2022.01.10.0 [we] _NET: add NET_Netsetup,NET_Netlogon; moved Start/Stop_Netlogon to NET_Netlogon
  2022.01.07.0 [we] _FW: ren Fw functions CreateLogFolder,EvtLogDetails,ExecWMIQuery,ExportRegistry,ExportRegToOneFile,IsElevated,IsSupportedOSVersion,ResolveDesktopPath to Fw*
  2022.01.06.0 [we] _FW: add ListSupportedNoOptions, sort CONTROLS aphabetically, fix global:FwGetCertsInfo
  2022.01.05.0 [we] _FW: fix typos; fix ProcmonPreStart/ProcmonPostStop; FwGetCertsInfo(); upd -Help with SDP; _NET: fix WebClient
  2022.01.04.2 [we] _FW: moving more helper functions of general interest from _NET to _FW: global: FwClearCaches, FwCopyWindirTracing, FwDoCrash, FwGetGPresultAS, FwGetKlist, FwGetMsInfo32, FwGetNltestDomInfo, FwGetPoolmon, FwGetProxyInfo, FwGetRegHives, FwRestartInOwnSvc, FwGetSVC, FwGetSVCactive, FwGetSysInfo, FwGetTaskList, FwGetWhoAmI
  2022.01.04.0 [we] _FW: for MiniBasicLogs Folder=BasicLogs_Mini; fix Issue#405: add App/Sys Evtlogs in CSV,TXT format; add WireShark ex); add FwGetHandle()
  2022.01.03.0 [we] _NET: re-add NET_HypHost/HypVM, _FW: revoked preliminary changes for Issue#396, fixed typos
  2021.12.31.1 [we] _FW: add FwAddRegItem/FwGetRegList and FwAddEvtLog/FwGetEvtLogList as FW functions; sorted no* options
	moved NET_ components to ADS: GPedit GPmgmt GPsvc GroupPolicy Profile 
	_NET: moved Poolmon to FW; renamed addReg -> FwAddRegItem, addEvtLog -> FwAddEvtLog
	_NET: moved NET_ components to SHA: HypHost, HypVM, ShieldedVM; made some $EvtLogs to global:EvtLogs*; moved FwGetNetAdapter and FwGetVMNetAdapter to FW
	_NET: moved NET_ '_WinUpd' to _DND
  2021.12.31.1 [we] _FW: rename FwEventLogExport rename to FwExportSingleEventLog (#327)
  2021.12.31.0 [we] _FW: fix typos, extend -Help, add -ListSupportedCommands, sorting items alphabetically, replace "    " with <Tab>,..
  2021.12.30.0 [we] _NET: add FwGetCertsInfo to SMBcli
  2021.12.29.0 [we] _FW: fix '-PerfMon ALL' for Srv2022 & Win11 (Issue#383); fix Get-TimeZone (Issue#381); Issue#380 -PktMon is only supported on RS5+; fixing (partly?) PktMon output
  2021.12.27.0 [we] _NET: fix doTCPrundown(),CollectNET_VPNLog; _FW: mod. Procdump helpmsg
  2021.12.18.0 [rh] _FW: change variable name to $global:StartAutologger from $global:SetAutoLogger to refect the change happened in FW
				[we] mod tss_update-script, Help on Syntax
  2021.12.17.1 [we] _FW: cosmetic changes; report Get-Culture and Get-UICulture in info log
  2021.12.17.0 [we] _SHA: fix SHA_SDDC based on RobertVi; _NET: fix NET_Capture
  2021.12.16.2 [we] _NET: workaround for #362
	_FW added help: -WaitEvent Evt:<EventID>:<Eventlog Name>[:<CheckIntInSec>:<StopWaitTimeInSec>:<StopEventData>:<EvtDataPartial>:<OR|AND>]
		add Function FwRunAdminCheck, fix #355; change "Reproduce the issue and enter 'Y' key .." to avoid stopping immediatelly when user entered Y<RETURN> for PSR/Video
		replaced some Read-Host with CHOICE
		upd \BIN\sysmon,procmon
		bail out on outdated version > 30days
  2021.12.15.0 [we] _NET: cosmetic upd
	_FW: cosmetic upd; tbd: issues #354, #355
  2021.12.14.0 [we] _FW: add Repro output + Recording declined, psSDP -skipQEdit
  	_NET: add SMB/SMBcli/SMBsrv/SMBcluster component tracing; fix NET_SMB function
  2021.12.13.1 [we] _NET: re. Localized OS: replaced "-eq 'Running'" with "-eq [System.ServiceProcess.ServiceControllerStatus]::Running" (find TypeName: functionName | Get-Member) 
  2021.12.13.0 [we] _FW: correction on PS command syntax, fix typos, homogenized Lower-/Upper-Case parameters/functions
	_NET: moved Dedup/DdpFlt to _SHA, marked some NET components for SHA_/ADS_
  2021.12.12.1 [rh] _FW: add -NetshMaxSize and more no* switches
  2021.12.10.0 [we] _FW: global replaced #LogError$ErrorMessage -> LogError $ErrorMessage, fix Netsh AutoLoggerStartOption
  2021.12.09.1 [we] _SHA: fix SHA_SDDC; _FW: don't run AutoUpdate, $Xray = $True => always run xray unless -noXray
  2021.12.08.0 [we] #_# _UEX: add collect -UEX_PrintEx -> change later to UEX_Print, once SME's decide to remove current UEX_Print component
  2021.12.07.0 [we] _FW: updated -Help messages; fixed HKEY_CLASS_ROOT -> HKEY_CLASSES_ROOT; add $TssPhase to distinguish _Start/_Stop appendices for filenames; 
	avoid UpdateTSS if online check fUpToDate=True; added -Help 0 Common: Help on unexpected PowerShell errors
	_NET: fix WebClient -Mode Advanced
  2021.12.05.0 [we] _SHA: add SHA_SMS: _FW: cleanup, granular reusable FwBasicLog functions
  2021.12.01.0 [we] _NET: add NET_Auth scenario
  2021.11.29.0 [we] _NET: add RAS -Mode Hang
  _FW:  add option -Mode Hang, add check $noUpdate for online check; add switches -noPerfMon, -noNetsh, -noXperf, -noWPR (could be necessary avoiding PerfMon issues on localized OS); adding PerfMon '\Process V2' counters for Win11
	moving NET_ADcore, NET_ADsam, NET_BadPwd, NET_DFSR, NET_LDAPsrv, NET_LockOut to ADS
	moving NET_CSVspace, NET_MPIO, NET_msDSM to SHA
  2021.11.25.2 [we] _FW: automated public online version checking
  2021.11.25.0 [we] _NET move FwResetEventLog into Collect function, add 'CollectComponentLog' to scenarios
		_FW: fix typos
  2021.11.24.0 [we] _NET run 'TCP rundown' at PreStop, correct NET -Help; add CollectComponentLog to all scenarios
		_FW: fix WireShark (#294)
  2021.11.23.1 [we] _FW: fix Wireshark #294; _NET: add CollectComponentLog to Scenario(s) WebClient; fix $global:WS_TraceBufferSizeInMB
  2021.11.22.1 [we] _NET add RASdialer,MediaManager,VPNplugin GUIDs to RasMan; upd Webclient -Mode Adv;
		_FW: add global:FwNew-TemporaryFolder(), fix typos; upd Tss_config; replace global:GetProductTypeFromReg with global:FwGetProductTypeFromReg
  2021.11.17.0 [we] _NET add Workfolders -Mode Advanced
 	_FW: cleanup + typos
  2021.11.15.0 [we] _NET preparing for -Scenario NET_WebClient -Mode Advanced
	_FW: add -Mode Restart, fix typos
  2021.11.10.0 [we] _FW: replaced gwmi/Get-WmiObject with Get-CimInstance to be compatible with PS v7
  2021.11.08.0 [we] _NET: mod Print, TLS; FW: mod -noUpdate
  2021.11.03.0 [we] _NET: mod RAmgmt, mod Workfolders
	TSSv2.ps1: fix ProcessListSupportedNetshScenario(), add HyperVCounters, replaced \MSDATA with \MS_DATA, replace switch -Perf with -PerfMon in .ps*, renamed *Netsh.etl to *Netsh_packetcapture.etl 
  2021.10.30.0 [we] upd SysMon, _NET: mod DNSsrv Miracast, add MFAext MDM; fix PrefixT; $Global:StartAutologger in .psm1
	TSSv2.ps1: replaced  New-Variable with Set-Variable for global no-switches
  2021.10.26.0 [we] _NET add noEvtSec; add SHA_SDDC, SHA_MSCluster
	[we] _SHA add MSCluster; add CollectSHA_SDDCLog by calling external psSDP scripts
  2021.10.22.0 [we] FW: introduced Close_Transcript(); sorted UEX switches alphabetically; fixed ProcDump path; for UEX: call external \scripts\*-collect.ps1 for UEX_DSC, UEX_Evt, UEX_TSched
  2021.10.20.0 [we] fix for #259: moving Netview collection to \psSDP\Diag\global\*Netview.*
  2021.10.18.0 [we] moving \BIN86\ProcMon to \BIN, removing \BIN64\ProcMon
  2021.10.13.0 [we] fixing $SMB*OptEventlogs for Win2012*
	TSSv2.ps1 :  fix for Win2012* version check; [Beta-Phase] for Win7, adjusted Netsh tracing for +Win7
  2021.10.11.0 [we] fixing some typos in FW and modules
  2021.10.08.0 [we] _NET  fix NLTEST for not-domain-joined systems
  2021.10.06.0 [we] _NET adjusted FwSetEventLog calls
  2021.10.05.0 [we] _NET 
  	TSSv2.ps1 : better Help descr.
  2021.10.01.0 [we] upd COM,Workfolders,NFSsrv,NPS,GPedit,Profile,LDAPcli
  2021.09.20.1 [rh] Moved list of scenario trace descriptions to pod module(i.e. $NET_ScenarioTraceList was added in this modue).
  2021.09.19.0 [we] NA
	TSSv2.ps1 : -Update -UdpMode Quick|Full|Force; add noUpdate, changed 'ver' to 'version', changed $script:FwEvtxLogSize to global, added tss_config.cfg parameters
  2021.09.16.0 [we] SdnNC; Capturetype=both for Docker/Container,HypHost,SdnNC,WNV
	TSSv2.ps1 : -Update feature
  2021.09.13.1 [we] moved PerfCounter into main, 802Dot1x/WLAN,Miracast,MPIO,msDSM,SQLtrace,Winsock,WorkFolders; fix 'Perf SQL'
  2021.09.12.1 [we] _NET SCM,SDDC,ShieldedVM,Tapi,TaskSch,Winlogon,WmbClass,WWAN; disableEvtLog->FwResetEventLog
	TSSv2.ps1 renamed -sample to \Config\tss_config.cfg; add $Mode [Basic|Advanced|Full]
  2021.09.09.1 [we] _NET SCM part #1
  2021.09.09.0 [we] _NET re-adding Proxy, fix FwAddEvtLog, add -beta switch in TSSv2 for a kind of KIR/Feature-preTesting
	TSSv2.ps1 #_# moved ----- begin _Stop_common_task block down after: data collection function for scenario. #161
  2021.09.08.1 [we] _NET: Proxy, fix FwAddEvtLog, replaced enableEvtLog with FwSetEventLog
	TSSv2.ps1:  
	- add -beta switch in TSSv2 for a kind of KIR/preTesting
	- add -Beta , # hidden switch = Testing/newFeature mode 
  2021.09.07.1 [we] _NET: adopt enhanced FW functions like FwSetEventLog; 
  2021.09.06.0 [we] _NET: WebClient, most NET scenarios have 'CommonTask NET' = $True 
	TSSv2.ps1/tss-clock.ps1 change for #154
  2021.09.03.0 [we] _NET: GPresult, NFC,NFScli,NFSsrv,NLB,NPS,PCI,RDMA,RPC,SCCM,SNMP
  2021.09.02.0 [we] _NET: IPAM,MUX,LDAPsrv,LockOut,MBAM,MBN,NetworkUX,WCM,VPN
  2021.09.01.1 [we] _NET: add NTFS,PerfLib,PnP,PortProxy,PowerShell,WinRM,WSMan, PrintSvc,Profile,Proxy,Winsock,QoS,RadioManager,RAS,RasMan; IPsec,KernelIO; ICS,IIS
  2021.08.30.0 [we] _NET: DFScli,DFSsrv 
  2021.08.29.0 [we] _NET: HypVmBus,HypVmms,HypVmWp,VMM,VmConfig,HypVM
  2021.08.28.0 [we] _NET: ADcore,ADsam,AppLocker,AppV,BadPwd,Crash,CsvSpace,DFSmgmt,DHCPsrv,Firewall,FltMgr,FSRM,FWmgr,GPedit,GPmgmt,GPsvc,GroupPolicy,Handle,HttpSys - TSSv2 updating Sysinterals tools
  2021.08.26.0 [we] _NET: add DFSr,EFS
  2021.08.23.0 [we] _NET: add CSC,Docker/Container,HNS,WinNAT,WNV,NCHA,DAcli,NCA,TLS,WMI,DAsrv,Netlogon,LDAPcli,RAmgmt,Dedup
	TSSv2.ps1: fix noXray, start PSR minimized
  2021.08.13.0 [we] _NET: upd SQL Perfcounter, add Bluetooth,BranchCache, SCCM
  2021.08.10.0 [we] _NET: add 'xray' and 'SDP NET' to all scenarios; add BITS
  2021.07.21.0 [we] _NET: add WFP,BFE, fixed disableEvtLog
  2021.07.20.0 [we] _NET: add DNScli,DNSsrv; moved NET_start_common_tasks into *ScenarioPostStart"
  2021.06.23.0 [we] _NET: add NDISwan, RNDIS, VMswitch, Perf definitions
  2021.06.22.0 [we] _NET: add NCSI, added TestMe trace/scenario
	TSSv2.ps1
	- fix handling space in EvtLog in function FwExportEventLog
  2021.06.20.0 [we] _NET: modified SMB* scenarios, add DCLocator, DHCPcli, NET_IPhlpSvc, add more Helper-functions
	TSSv2.ps1
	- added -noZip,
	- fixed typos, filed #70, #71, #72, #73
	- replaced all LogMessage $LogLevel.Info with LogInfo (same for Debug)
	- added optional parameter $BootRequired to function global:FwAddRegValue
	- commented in global:FwResetEventLog: #we# Remove-Item -Path "HKLM:\Software\Microsoft\TSSv2" -ErrorAction SilentlyContinue | Out-Null #we# in order to keep EulaAccepted
	- grouped FW Event and Registry functions in sequential order
  2021.06.18.1 [mk] _NET: add NET_WebIO switch; add NET_WebIO scenario
  2021.06.18.0 [we] _NET: add FwGetWhoAmI, FwGetGPresultAS; add NET_SMB* (cli/srv), NFSsrv; changed order in all Trace providers to: '{GUID}' # 'Name of provider'  - as name may not exist on system / client OS - resulting in Logman (Error=0x80070490), also makes -FindGUID work
  2021.06.17.0 [we] add more TssV1 HelperFunctions, add NET_LBFO, iSCSI, BGP, (partly: COM, HTTP, NFS)
  2021.06.15.0 [we] TSSv2: fixed regressions from #62 (changed to $global:ProcArch); _NET.psm1: moved #NET_stop_common_tasks into Collect<scenarioName>ScenarioLog, add NET HelperFunctions FwAddRegItem/global:FwGetRegList + FwAddEvtLog/FwGetEvtLogList
  2021.06.14.0 [we] changed $global:ProcArch, moved #NET_stop_common_tasks into Collect<scenarioName>ScenarioLog, add HelperFunctions FwAddRegItem + add Evt
  2021.06.13.0 [we] add normal NetSh scenarios to $SupportedScenarios list; change for speeaking zipNames, replaced NetSH names to packetcapture for LogRaker consumption, fixed duplicate $Env:PATH entries, added InfoLogFileOnly, minor typo corrections, changes some $LogSuffix to $LogPrefix, initialize global parameters, place and lookup all config files in \config folder; find all external/supporting scripts in \scripts folder, add folders \config and \scripts with defaults/samples for TSSv2,ProcMon,Sysmon 
  2021.06.12.0 [we] Added NET Capture & NetView scenario, added -Ver and -Mini switch in Tssv2 script
  2021.06.11.0 [we] add Helper-functions, renamed NET_Scn_NETIO to NET_NETIO, add NET_General scenario, added BIN folders - TSSv2 will skip if folder does not exist 


### ToDO's
 see all #ToDo:
 - change files names for _Evtx_ and corresponding .txt files
 - # analytical/debug/diagnostic event channels can not be captured live, if any are encountered (not normal), disable them temporarily for export (see sddc*.ps1) => OK, done
 - substitute some 'writeTesting' messages to 'LogDebug'

### @Dev: FYI: some TSSv1 translations to TSSv2:
 TSSv1 <module>_start and <module>_stop actions need to be executend in TssV2 <switch/trace> Pre/Post/Collect functions (not in senarioPre/Post!)

 !_OSVER3! 	= $OSVER3
 !_DirRepro!	= $DirRepro = $global:LogFolder
 !_DirScript!	= $DirScript = $global:ScriptFolder
 !_PrefixT!	= $PrefixTime` = $global:LogFolder\$($LogPrefix) 
 !_Prefix!	= $PrefixCn`	= $global:LogFolder + "\" + $Env:Computername + "_"
 call :logNoTimeItem	= LogInfoFile "Your message"
 call :logOnlyItem	= LogInfoFile "Your message"
 call :addReg	= FwAddRegItem $AddToRegKeyModules -- example: FwAddRegItem @("Tcp", "Rpc") _Stop_
 call :FwAddEvtLog	= ($EvtLogsDNScli, "Microsoft-Windows-CAPI2/Operational") | ForEach-Object { FwAddEvtLog $_ _Stop_}
 call :DoRegPreRequSet [RegLoc RegKeyName RegValue BootRequired] = FwAddRegValue "$RegistryKey" "$RegistryValue" "$RegistryValueType" "$RegistryValueData" $True (if boot is required)
 ADD REG = FwAddRegValue
 call :DoRegDelete [RegLoc RegKeyName] = FwDeleteRegValue "$RegistryKey" "$RegistryValue"
 call :enableEvtLog -> FwSetEventLog in NET_<switch>PreStart function, add corresponding 'disableEvtLog' in NET_<switch>PostStop (or collect*Log)
 call :addEvtAndDisable -> invoke a) DisableEvtLog, b) FwAddEvtLog
 call :logShowItem = LogInfo "[$($MyInvocation.MyCommand.Name)] <infoText>"
 call :logitem = LogInfo "[$($MyInvocation.MyCommand.Name)] .."
 call :Stop_SysInfo = FwGetMsInfo32
 call :doCmd ... =
  if output should be saved in file:
	$outFile = $PrefixT + "WhoAmI" + $TssPhase + ".txt"
	$Commands = @(
		"... | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
  else:
	$Commands = @(
			"..."
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
 
 call :InitTxtFile filename !mode!			= $outFile = $PrefixT + "filename" + $TssPhase + ".txt"
		call :logCmd !_filenameFile! 		= $Commands = @(  ... see above
		
 call :PSrunCommand <file> "ps-command" = "ps-command |Outfile <file>"
 call :PSrunScriptBlock OutName PScommand =:  $outFile = $PrefixT + "OutName.txt"
											  PScommand | Out-File -Append $outFile
 call :PSrunScriptBlckFL OutName PScommand =: $outFile = $PrefixT + "OutName.txt"
											  PScommand | fl * |Out-file -Append $outFile -Encoding ascii -Width 500

 call :enableEvtLog %%i /ms:!_EvtxLogSize! = FwSetEventLog $xxxEvtLogs -EvtxLogSize $global:EvtxLogSize
 - when you use the FwSetEventLog in pre-start function, please don't forget to call FwResetEventLog that restores previous settings of the event log in post-stop function.

 call :DoRegPreRequCheck	= ...
 
 call #NET_start_common_tasks in all <ScenarioName>ScenarioPostStart	#	2021.09.06.0 [we] add 'CommonTask NET' 
 call #NET_stop_common_tasks in all  Collect<scenarioName>ScenarioLog

- if switch and scenario have same name, prefer/consider doing collect*log in scenario ?
#_# - if a tssv1 switch Start_xxx has no ETL provider (issue #70), start a Dummy: $NET_xxxProviders = $NET_DummyProviders 



### Order of FW function calls, see https://microsoft.githubenterprise.com/css-windows/WindowsCSSToolsDevRep/wiki/Order-of-FrameWork-function-calls
 Note: Scenario PreStart functions are called before switch functions 
 Note: Scenario PostStop functions are called after switch functions
	1. ScenarioPreStart function for Scenario	
		[PSR] starting
	2. Pre-Start function for trace components
		[ETW] LogMan start
 		[WPR] starting
 		[Perf] starting
		[RASdiag]
 		[NetSh] starting
		[PktMon]
		[WFPdiag]
 		[Procmon] starting
	3a. PostStart function for ETW trace
	3b. ScenarioPostStart function for Scenario
-repro- ---
 		[PSR] stopping
 		[ETW] Logman stop
	4. Post-Stop function for trace components -> long-lasting call should be better in Collect function
 		[WPR] stopping
 		[Perf] stopping
		[WFPdiag]
		[NetSh] stopping
		[PktMon]
		[RASdiag]
		[Procmon] stopping 
	5. ScenarioPostStop function for Scenario
	6. Collect  function for trace components
	7. Run Diag function for trace components
	8. Collect  function for Scenarios
	9. Run Diag function for Scenarios
	10. xray
#>

#region --- Define local NET Variables
#[switch]$beta = $True	# hidden switch; set to $False = normal Production mode, $True =Testing/newFeature mode, will also output writeTesting messages // in TSSv2.ps1

$global:TssVerDateNET = "2023.05.22.0"

#$OSVER3 				= $global:OSVersion.Build
$DirRepro				= $global:LogFolder

$BinArch				= "\Bin" + $global:ProcArch
$cscDBdumpPath 			= $global:ScriptFolder + $BinArch + "\cscDBdump.exe"
#$ovsdbPath 			= $global:ScriptFolder + $BinArch + "\ovsdb-client.exe"

#$TLStestSite = "www.ssllabs.com" #

#_# more parameters are defined in \config\tss_config.cfg

#endregion --- Define local NET Variables

#region --- init NET Variables

#endregion --- init NET Variables


#region --- ETW component trace Providers ---

# Type#1 switch (single ETL)
$NET_DummyProviders = @(	#for components without a tracing GUID
	#'{eb004a05-9b1a-11d4-9123-0050047759bc}' # Dummy tcp for switches without tracing GUID (issue #70)
)
$NET_AccessChkProviders = $NET_DummyProviders
$NET_ContainerProviders = $NET_DummyProviders
$NET_CSCProviders 		= $NET_DummyProviders
$NET_DFSmgmtProviders 	= $NET_DummyProviders
$NET_IISProviders 		= $NET_DummyProviders
$NET_MDMProviders 		= $NET_DummyProviders
$NET_OutlookProviders 	= $NET_DummyProviders
$NET_PCIProviders 		= $NET_DummyProviders
$NET_SCCMProviders 		= $NET_DummyProviders
#$NET_SBSLProviders 		= $NET_DummyProviders
#$NET_UNChardProviders 	= $NET_DummyProviders
$NET_TestMeProviders 	= $NET_DummyProviders

$NET_WlanProviders = @(
	'{1AC55562-D4FF-4BC5-8EF3-A18E07C4668E}' # Wlan AutoConfig
	'{36DFF693-C097-438B-B3CA-62E80D15D227}' # LanSettingsGuid
	'{8A3CF0B5-E0BC-450B-AE4B-61728FFA1D58}' # WlanGPClientGuid
	'{E2EB5B52-08B1-4391-B670-F58317376247}' # IHVServiceFrameworkCtlGuid
	'{F860141E-94E0-418E-A8A6-2321623C3018}' # VlibGuid
	'{D905AC1D-65E7-4242-99EA-FE66A8355DF8}' # Native WIFI MSM Trace
	'{0C5A3172-2248-44FD-B9A6-8389CB1DC56A}' # WLAN AutoConfig Trace
	'{6DA4DDCA-0901-4BAE-9AD4-7E6030BAB531}' # WLanDiagCtlGuid
	'{2E8D9EC5-A712-48C4-8CE0-631EB0C1CD65}' # DiagL2SecCtlGuid
	'{637A0F36-DFF5-4B2F-83DD-B106C1C725E2}' # WDiagCoreCtlGuid
	'{253F4CD1-9475-4642-88E0-6790D7A86CDE}' # Layer 2 Authentication Utilities
	'{20644520-D1C2-4024-B6F6-311F99AA51ED}' # MSMSecCtlGuid
	'{ED092A80-0125-4403-92AC-4C06632420F8}' # WlanUtilCtlGuid
	'{1BF7FE18-A798-4FF3-A054-4A31A959D381}' # KeyExtCtlGuid
	'{D905AC1C-65E7-4242-99EA-FE66A8355DF8}' # NwfDrvCtlGuid
	'{4CEAB604-4A19-48C9-B9FD-43A7465AAAC7}' # Wlan Wdiag
	'{520319A9-B932-4EC7-943C-61E560939101}' # WlanDlgTraceGuid
	'{1F6C35EE-9294-4721-9413-FB3394247DAC}' # ConverterGuid
	'{F96AFBA0-22D3-4EB7-9E3D-53A79C0135C4}' # WLAN Mediamanager
)

$NET_AfdTcpFullProviders = @(
	'{E53C6823-7BB8-44BB-90DC-3F86090D48A6}' # Microsoft-Windows-Winsock-AFD
	'{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}' # Microsoft-Windows-TCPIP
	'{EB004A05-9B1A-11D4-9123-0050047759BC}' # NETIO
	'{D5C25F9A-4D47-493E-9184-40DD397A004D}' # Microsoft-Windows-Winsock-WS2HELP
	'{B40AEF77-892A-46F9-9109-438E399BB894}' # AFD Trace
	'{64F77AD3-710C-4C2C-ABCB-A7B682D07B81}' # AfdWppGuid
)

# Type#2 switch (multi ETL)
$NET_AfdTcpBasicProviders = @(
	'{E53C6823-7BB8-44BB-90DC-3F86090D48A6}!Afd!0x800000000000003f' 		# 'Microsoft-Windows-Winsock-AFD' 
	'{B40AEF77-892A-46F9-9109-438E399BB894}!Afd!0x800000000000003f' 		# AFD Trace
	'{64F77AD3-710C-4C2C-ABCB-A7B682D07B81}!Afd!0x800000000000003f'			# AfdWppGuid
	'{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}!TcpIp!0x80007fff000000ff' 		# Microsoft-Windows-TCPIP 
	'{EB004A05-9B1A-11D4-9123-0050047759BC}!NetIoBasic!0x800000000003ffff' 	# NETIO
)

$NET_AppLockerProviders = @(
	'{CBDA4DBF-8D5D-4F69-9578-BE14AA540D22}' # Microsoft-Windows-AppLocker
	'{77FE4532-3F5C-5786-632B-FB3201BCE29B}' # Microsoft.Windows.Security.AppIdLogger
	'{1C15C3C7-20B4-446C-8D5E-3BBEC6461664}' # AppIDLog
	'{3CB2A168-FE19-4A4E-BDAD-DCF422F13473}' # "Microsoft-Windows-AppID" 
	'{D02A9C27-79B8-40D6-9B97-CF3F8B7B5D60}' # "Microsoft-Windows-AppIDServiceTrigger" 
	'{CF84DA43-F447-42DE-AD48-4FEEEA03247D}' # Microsoft.Windows.Security.EDPPolicyMgrApplockerTask
	'{63665931-A4EE-47B3-874D-5155A5CFB415}' # AuthzTraceProvider
	'{B997E40D-0880-4ED6-B7DF-84DF3305FE2B}' # 
	'{76df1e7b-74d9-547f-1f87-affa9542809a}' #
	'{5AF61464-71AD-4419-A92A-7766E9A5ABC3}' # Microsoft-Windows-AppID-AppRep
)

#$NET_AppVProviders = @( # = UEX_AppV

$NET_BFEProviders = @(
	'{106B464A-8043-46B1-8CB8-E92A0CD7A560}!BFE!0xffffffff!0xff' # BaseFirewallEngine				# 0xffffffff for -StartAutologger
	'{D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85}!BFE!0xffffffff!0xff' # Microsoft-Windows-Windows Firewall With Advanced Security
)

$NET_BGPProviders = @(
	'{2E67FCF3-C48E-4B2D-A689-A91D07EDB910}' # 'Microsoft-Windows-RasRoutingProtocols-BGP'
	'{9FD2B528-8D3D-42D0-8FDF-5B1998004278}' # 'Microsoft.Windows.Networking.RAS.Routing.BGP'
	'{9B322459-4AD9-4F81-8EEA-DC77CDD18CA6}' # 'nathlp CtlGuid'
	'{EB171376-3B90-4169-BD76-2FB821C4F6FB}' # 'BGPProvider'
)

$NET_BITsProviders = @(
	'{C07ED46C-F60B-479A-8DF9-AC892A6CFC70}!BITSlog' 				# 'Microsoft-Windows-Bits-CompactServer'
	'{38398B57-93F3-4C42-AC26-DB3F5998745B}!BITSlog' 				# BITS Server Extensions
	'{1965FED6-D154-46B7-BCFA-E7A1D16BAD29}!BITSlog' 				# BitsPerfGuid
	'{EF1CC15B-46C1-414E-BB95-E76B077BD51E}!BITSlog!0x18DF!0xff' 	# 'Microsoft-Windows-Bits-Client'
	'{4A8AAA94-CFC4-46A7-8E4E-17BC45608F0A}!BITSlog!0x18DF!0xff' 	# Drizzle QmgrLib
	'{599071ED-D475-497C-9E40-FC7283A1249B}!BITSlog!0x18DF!0xff' 	# Drizzle LightWeight
)

$NET_BluetoothProviders = @(
	'{D88ACE07-CAC0-11D8-A4C6-000D560BCBA5}' # bthport
	'{FF9D953D-86CD-4A4F-B8DF-B7236CB640A8}' # bthusb
	'{F0CB5D88-0C28-475A-8AE9-D3331ED861DE}' # bthmini
	'{F1CD3858-7EE7-43C4-B86A-DCD1BC873269}' # BthEnumTraceGuid
	'{1a973eb5-9862-46f0-a54b-ad8a6221654e}' # 
	'{F1B0EC6A-87CB-4EAA-BFBA-82770400A80B}' # 
	'{1C5221CB-C1F6-4999-8136-501C2023E4CD}' # 
	'{8bbe74b4-d9fc-4052-905e-92d01579e3f1}' # DAFBTH
	'{CA95AC21-E6FD-4A1B-81BE-ACF16FCFC0FC}' # 
	'{EB3B6950-120C-4575-AF39-2F713248E8A3}' # BTHPRINT
	'{8E1871AF-671E-43A2-907A-8ADF4BF687EE}' # 
	'{71b7bd28-4894-4eaa-8399-a7944423936c}' # 
	'{a5ac3157-27d5-4418-8510-c8f0dc1fe098}' # 
	'{7fc34c90-0657-4fdf-960b-702abb741e24}' # 
	'{c872ff32-5a0c-4736-bdf2-334c9b8d429f}' # 
	'{07699FF6-D2C0-4323-B927-2C53442ED29B}' # 
	'{0107cf95-313a-473e-9078-e73cd932f2fe}' # 
	'{47c779cd-4efd-49d7-9b10-9f16e5c25d06}' # 
	'{8a1f9517-3a8c-4a9e-a018-4f17a200f277}' # 
	'{9EBD1710-E5B9-4213-A8F3-9B015FD615C1}' # 
	'{DFE2ECB4-536B-44AE-8011-67A8E2C3CA96}' # 
	'{BF94D329-C5F9-4deb-AD29-2C6682D485F0}' # 
	'{B79B9C1F-2626-4d0c-9574-5CFCE4E793E6}' # 
	'{a8e3e135-780c-4e4a-8410-f4da062e5981}' # 
	'{565D84DC-23F7-400a-B2FA-23580731F09F}' # 
	'{DDB6DA39-08A7-4579-8D0C-68011146E205}' # 
	'{75509D47-E67D-48B4-A346-6FEAB02E51BD}' # 
	'{5C836296-6C1A-48F4-90E2-28CC25423518}' # 
	'{842B43E3-F833-40B3-958A-5535B3251EE3}' # 
	'{F2A442CB-6CDE-44D0-ACEF-2B01CEB56A30}' # 
	'{5acbeb5b-fd8c-45d4-83f1-c8ce2303763c}' # 
	'{797E4878-22CF-452A-86FF-3872D880F93B}' # 
	'{fd35e984-9dee-4011-9eae-5c135b050261}' # 
	'{d2440861-bf3e-4f20-9fdc-e94e88dbe1f6}' # 
	'{e8109b99-3a2c-4961-aa83-d1a7a148ada8}' # SEBWPP
	'{AE4BD3BE-F36F-45b6-8D21-BDD6FB832853}' # 
	'{e27950eb-1768-451f-96ac-cc4e14f6d3d0}' # 
	'{9502CBC6-AA74-4eff-BA91-D9329BCCE758}' # 
	'{A6A00EFD-21F2-4A99-807E-9B3BF1D90285}' # 
	'{71E0AC1E-CFA2-447C-91C7-4F307030F2FC}' # 
	'{6F34C0F0-D9F6-40D3-A94C-419B50FD8407}' # 
	'{1B42986F-288F-4DD7-B7F9-120297715C1E}' # DeviceEnumeration WPP
	'{9c1d5e55-2ff9-41a5-9402-40bd9e6f812b}' # 
	'{ac23ebce-f06e-4a75-b07b-7cc1defa2388}' # 
	'{56297848-CA78-4AA1-A2C2-29015EC7E498}' # 
	'{6ae9ebb4-66cf-4598-9abd-8d223d187301}' # 
	'{FCEB1377-EEAF-4A4F-A26A-1E5E0D4C53A4}' # 
	'{FE440530-3881-4354-A8FF-BCEC2C488533}' # 
	'{9E470B06-C3EB-496C-9CD2-24ACC293DC9A}' # 
	'{E71924CF-117B-427C-9E22-BD72021F06BA}' # 
	'{378B1AED-30D9-4C8B-92C6-A093D44F0AAB}' # 
	'{C01D7B34-43D0-439D-95AC-975645E4535F}' # 
	'{D951CB3F-2CBA-4A1C-9436-6CF2E904DDE8}' # 
	'{ad8fe36a-0581-4571-a143-5a3f93e30160}' # 
	'{9f30c07c-57ce-5ec3-bb5e-476dd25c2742}' # 
	'{82CAD26A-2DC1-4020-A4F2-0897AA48ED5A}' # 
)

$NET_BranchCacheProviders = @(
	'{7EAFCF79-06A7-460B-8A55-BD0A0C9248AA}' 	# Microsoft-Windows-BranchCache
	'{1F8B121D-45B3-4022-A9FB-3857177A65C1}' 	# Torino
	'{28FCAB19-3975-45CD-9E8C-5BE612D60007}' 	# BranchCacheDiag
	'{4A933674-FB3D-4E8D-B01D-17EE14E91A3E}' 	# Microsoft-Windows-BranchCacheSMB
	'{DD85457F-4E2D-44A5-A7A7-6253362E34DC}' 	# Microsoft-Windows-BranchCacheEventProvider
	'{E837619C-A2A8-4689-833F-47B48EBD2442}' 	# Microsoft-Windows-BranchCacheClientEventProvider
	'{A2F55524-8EBC-45FD-88E4-A1B39F169E08}' 	# Microsoft-Windows-BranchCacheMonitoring
)

$NET_CAPIProviders = @(
	'{5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB}' 	# Microsoft-Windows-CAPI2
	'{B8A3BF0D-21C1-48CD-855B-92C4AE6CCB11}' 	# ControlGuid
	'{52BF9EC6-69F5-49E6-9ECC-D3B994C40142}' 	# NTCryto KeyRoam2 Storage WinCred CAPI
	'{E80E62CA-B2A0-4D95-822D-D4E8D27A2857}' 	# NTCryto KeyRoam2 Storage WinCred CNG
	'{F01B7774-7ED7-401E-8088-B576793D7841}' 	# NTCrypto DIMS Job
	'{9C61B35B-A7F4-4C25-83AA-2F452582A1F5}' 	# NTCryto KeyRoam2 Storage WinCred DPAPI
)

#---  COM/DCOM/WinRT/RPC PROVIDERS ---#
$NET_COMProviders = @(	#from UEX / ToDo:
	'{9474a749-a98d-4f52-9f45-5b20247e4f01}' # DCOMSCM
	'{bda92ae8-9f11-4d49-ba1d-a4c2abca692e}' # OLE32(combase.dll)
	'{d4263c98-310c-4d97-ba39-b55354f08584}' # Microsoft-Windows-COM(advapi32.dll)
	'{0f177893-4a9c-4709-b921-f432d67f43d5}' # Microsoft-Windows-Complus(comres.dll)
	'{1B562E86-B7AA-4131-BADC-B6F3A001407E}' # Microsoft-Windows-DistributedCOM(combase.dll)
	'{B46FA1AD-B22D-4362-B072-9F5BA07B046D}' # COMSVCS(COM+)
	'{A0C4702B-51F7-4ea9-9C74-E39952C694B8}' # COMADMIN(COM+)
	'{1AFF6089-E863-4D36-BDFD-3581F07440BE}' # CombaseTraceLoggingProvider 
	'{6AD52B32-D609-4BE9-AE07-CE8DAE937E39}' # Microsoft-Windows-RPC(rpcrt4.dll)
	'{F4AED7C7-A898-4627-B053-44A7CAA12FCD}' # Microsoft-Windows-RPC-Events(rpcrt4.dll)
	'{d8975f88-7ddb-4ed0-91bf-3adf48c48e0c}' # Microsoft-Windows-RPCSS(RpcEpMap.dll)
	'{097d1686-4038-46be-b551-10fda0387165}' # CLBCATQ
	'{A86F8471-C31D-4FBC-A035-665D06047B03}' # Microsoft-Windows-WinRT-Error
	'{bf406804-6afa-46e7-8a48-6c357e1d6d61}' # Microsoft-Windows-COMRuntime
	'{7913ac64-a5cd-40cd-b096-4e8c4028eaab}' # Microsoft-Windows-WinTypes-Perf
	'{f0558438-f56a-5987-47da-040ca757ef05}' # Microsoft.Windows.WinRtClassActivation
	'{53201895-60E8-4fb0-9643-3F80762D658F}' # COM+ Services
	'{272A979B-34B5-48EC-94F5-7225A59C85A0}' # Microsoft-Windows-RPC-Proxy-LBS
	'{879b2576-39d1-4c0f-80a4-cc086e02548c}' # Microsoft-Windows-RPC-Proxy
	'{536caa1f-798d-4cdb-a987-05f79a9f457e}' # Microsoft-Windows-RPC-LBS
)
<# in TssV1
DCOM {9474A749-A98D-4F52-9F45-5B20247E4F01} {C44219D0-F344-11DF-A5E2-B307DFD72085} {B46FA1AD-B22D-4362-B072-9F5BA07B046D} {BDA92AE8-9F11-4D49-BA1D-A4C2ABCA692E} {A0C4702B-51F7-4EA9-9C74-E39952C694B8 }
OLE32 {BDA92AE8-9F11-4D49-BA1D-A4C2ABCA692E}
RPC "Microsoft-Windows-RPC", "Microsoft-Windows-RPCSS", "Microsoft-Windows-RPC-Events", "Microsoft-Windows-RPC-LBS", "Microsoft-Windows-RPC-Proxy", "Microsoft-Windows-RPC-Proxy-LBS" {F997CD11-0FC9-4AB4-ACBA-BC742A4C0DD3} "Microsoft-Windows-RPC-FirewallManager", "Microsoft-Windows-EndpointTriggerProvider", "Microsoft-Windows-ServiceTriggerPerfEventProvider" 
#>

$NET_DAcliProviders = @(
	'{66A5C15C-4F8E-4044-BF6E-71D896038977}' # Microsoft-Windows-Iphlpsvc
	'{6600E712-C3B6-44A2-8A48-935C511F28C8}' # Microsoft-Windows-Iphlpsvc-Trace
)

$NET_DAsrvProviders = @(
	'{214609E4-72CC-4E0E-95F8-1D503FC4AD7F}' # Microsoft-Windows-RemoteAccess-RemoteAccessServer
	'{0C478C5B-0351-41B1-8C58-4A6737DA32E3}' # Microsoft-Windows-WFP
	'{4EDBE902-9ED3-4CF0-93E8-B8B5FA920299}' # Microsoft-Windows-TunnelDriver
	'{A67075C2-3E39-4109-B6CD-6D750058A732}' # Microsoft-Windows-IPNAT
	'{B0261971-F607-458E-8D89-02FE7E846129}' # Microsoft-Windows-RemoteAccess-MgmtClient
)

$NET_DAmgmtProviders = @(
	'{c4163695-ce82-4486-89ac-2d05b6e35e77}' #
	'{D6126663-A055-45A1-B0E9-7C68B74DB252}' # Microsoft-Windows-RemoteAccess
	'{8ADF1EAB-B733-48D6-918D-AAC9933BF85F}' # Microsoft-Windows-RaMgmtSvcEvt
)

$NET_DCLocatorProviders = @(
	'{CFAA5446-C6C4-4F5C-866F-31C9B55B962D}' # Microsoft-Windows-DCLocator
	'{CA030134-54CD-4130-9177-DAE76A3C5791}' # NETLOGON/ NETLIB
)

$NET_DFSsrvProviders = @(
	'{B6C4E17A-2CAC-4273-A390-6F6B8C8C9F01}' # Microsoft-Windows-DFSN-Server	
	'{5407BAEA-A563-4E56-819F-7DEAA72807CE}' # Microsoft-Windows-DFSN-ServerFilter
	'{8F74445D-84F4-426D-9BE1-25AAC1A2B959}' # Microsoft Dfs V5
	'{27246E9D-B4DF-4F20-B969-736FA49FF6FF}' # DfsFilter # see NET_DFSn
	'{7DA4FE0E-FD42-4708-9AA5-89B77A224885}' # Microsoft-Windows-DfsSvc
)

$NET_DHCPcliProviders = @(
	'{15A7A4F8-0072-4EAB-ABAD-F98A4D666AED}' # Microsoft-Windows-Dhcp-Client
	'{6A1F2B00-6A90-4C38-95A5-5CAB3B056778}' # Microsoft-Windows-DHCPv6-Client
	'{F6DA35CE-D312-41C8-9828-5A2E173C91B6}' # Microsoft-Windows-Dhcp-Nap-Enforcement-Client
	'{CC3DF8E3-4111-48D0-9B21-7631021F7CA6}' # v4 CtlGuid
	'{07A29C3D-26A4-41E2-856A-095B3EB8B6EF}' # v6 CtlGuid
	'{F230B1D5-7DFD-4DA7-A3A3-7E87B4B00EBF}' # DNS Resolver
	'{5855625E-4BD7-4B85-B3A7-9307BAB0B813}' # traceIdentifier
	'{55404E71-4DB9-4DEB-A5F5-8F86E46DDE56}' # Microsoft-Windows-Winsock-NameResolution
)

$NET_DHCPsrvProviders = @(
	'{6D64F02C-A125-4DAC-9A01-F0555B41CA84}!DHCPsrv' # Microsoft-Windows-DHCP-Server
	'{BA405734-9379-42CD-B447-40C249D354A2}!DHCPsrv' # CtlGuid
	'{15A7A4F8-0072-4EAB-ABAB-F98A4D666AED}!DHCPsrv' # Microsoft.Windows.Networking.DHCP
	'{6FCDF39A-EF67-483D-A661-76D715C6B008}!DHCPsrv' # CtlGuid
	'{9B1DD39A-2779-40A0-AA7D-C4427208626E}!DHCPsrv' # Extensible Storage Engine
	)
if ($global:OSVersion.Build -ge 9600) {	#fix bug#348
	$NET_DHCPsrvProviders += @( 
		'{91EFB500-642D-42A5-9822-F15C73064FBF}!DHCPsrv!0xFF7FFFFF!0xff' # DhcpServerTrace
	)
}
	 
$NET_DNScliProviders = @(
	'{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}' # Microsoft-Windows-DNS-Client
	'{1540FF4C-3FD7-4BBA-9938-1D1BF31573A7}' # DNS Trace
	'{9CA335ED-C0A6-4B4D-B084-9C9B5143AFF0}' # Microsoft.Windows.Networking.DNS
	'{609151DD-04F5-4DA7-974C-FC6947EAA323}' # DNSAPI Dnslib
	'{563A50D8-3536-4C8A-A361-B37AF04094EC}' # CtlGuid
	'{76325CAB-83BD-449E-AD45-A6D35F26BFAE}' # CtlGuid
	'{F230B1D5-7DFD-4DA7-A3A3-7E87B4B00EBF}' # DNS Resolver
	'{A7B8B859-D00E-45CC-85B8-89EA5D015C62}' # CtlGuid
)

$NET_DNSsrvProviders = @(
	'{71A551F5-C893-4849-886B-B5EC8502641E}!DNSsrv' # Microsoft-Windows-DNS-Server-Service
	'{EB79061A-A566-4698-9119-3ED2807060E7}!DNSsrv' # Microsoft-Windows-DNSServer
	'{57840C25-FA99-4F0D-928D-D81D1851E3DD}!DNSsrv' # DNS Server Trace Provider
	'{9CA335ED-C0A6-4B4D-B084-9C9B5143AFF0}!DNSsrv' # Microsoft.Windows.Networking.DNS
	'{609151DD-04F5-4DA7-974C-FC6947EAA323}!DNSsrv' # DNSAPI Dnslib
	'{501DD790-B342-479D-A20D-5E8518D365E4}!DNSsrv' # DnsValidator
	'{FA01E324-3485-4533-BDBC-68D36832AC23}!DNSsrv' # DnsServerPSProvider
	'{367B7A5F-319C-4E40-A9F8-8856095389C7}!DNSsrv' # Dnscmd
)
if ($global:Mode -iMatch "Verbose") {
	$NET_DNSsrvProviders += @( 
		'{406F31B6-E81C-457A-B5C3-62C1BE5778C1}!DNSsrv' # DnsServer
		'{282895CD-F507-4B3A-9E1D-93B514F8DD86}!DNSsrv' # DnsServerWmiProvider
	)
} else {
	$NET_DNSsrvProviders += @( 
		'{406F31B6-E81C-457A-B5C3-62C1BE5778C1}!DNSsrv!0x3FFE57!0xff' # DnsServer -- if /i "%_DNSSpec%" -ne "verbose"
	)
}

$NET_DockerProviders = @(
	'{662abf07-6dda-5b25-c2c5-345236dbb2d2}' # 
	'{564368D6-577B-4af5-AD84-1C54464848E6}' # 
	'{0BACF1D2-FB51-549A-6119-04DAA7180DC8}' # 
	'{9D911DDB-D45F-41C3-B766-D566D2655C4A}' # Microsoft-Windows-Guest-Network-Service
)

$NET_EFSProviders = $ADS_EFSProviders
<#@(
	'{3663A992-84BE-40EA-BBA9-90C7ED544222}' # Microsoft-Windows-EFS
	'{6863E644-DD5D-43A2-A8B5-7A81B46672E6}' # Microsoft-Windows-EFSTriggerProvider
	'{318BBC33-CDFD-42C0-B5E5-57ED92E8935F}' # Microsoft.Windows.Security.EFS.EfsWrt
	'{2CD58181-0BB6-463E-828A-056FF837F966}' # Microsoft-Windows-Security-EnterpriseData-FileRevocationManager
	'{82B5AD62-B453-481A-B838-CA1EEAE6E472}' # Microsoft.Windows.Security.EFS.EfsCore
	'{7A688F0E-F39B-4A7A-BBBB-066E2C1FCB04}' # Microsoft.Windows.Security.EFS.EfsLib
	'{4E04241F-30F8-5111-A04E-DF3C9C867433}' # Microsoft.Windows.Security.EFS
	'{7B3B9D0A-AC64-4CBD-B658-E1EC8B4CB416}' # Microsoft.Windows.EFS.EFSRPC
	'{C755EF4D-DE1C-4E7D-A10D-B8D1E26F5035}' # EFSWRT_WPP
	'{B2FC00C4-2941-4D11-983B-B16E8AA4E25D}' # NtfsLog
	'{287D59B6-79BA-4741-A08B-2FEDEEDE6435}' # Microsoft-Windows-EDP-Audit-TCB
	'{50F99B2D-96D2-421F-BE4C-222C4140DA9F}' # Microsoft-Windows-EDP-Audit-Regular
	'{9803DAA0-81BA-483A-986C-F0E395B9F8D1}' # Microsoft-Windows-EDP-AppLearning
	'{0C017B8D-7629-4AD6-A268-578A14E9DD65}' # Microsoft-Windows-Security-EFS-EDPAudit
	'{6F14D881-64EA-449D-96D7-34E9C966082B}' # Microsoft-Windows-Security-EFS-EDPAudit-ApplicationLearning
	'{225D7337-6538-4C12-9418-B37C558C50F2}' # Microsoft-Windows-Security-EFS-EDPAudit-ApplicationGenerated
	'{6AF820A5-6E4F-4558-8D7D-F7D6A2ED7195}' # Microsoft-Windows-Security-EFS-EDPAudit-CopyData
)
#>

$NET_FirewallProviders = @(
	'{0C478C5B-0351-41B1-8C58-4A6737DA32E3}!Firewall!0xffffffff!0xff' # Microsoft-Windows-WFP							# 0xffffffff for -StartAutologger
	'{106B464A-8043-46B1-8CB8-E92A0CD7A560}!Firewall!0xffffffff!0xff' # BaseFirewallEngine KernelFilterDriver 			# = NET_BFE
	'{4E7A902B-5E4E-5209-668D-86090D23E202}!Firewall!0xffffffff!0xff' # Microsoft.Windows.Networking.WFP
	'{E595F735-B42A-494B-AFCD-B68666945CD3}!Firewall!0xffffffff!0xff' # Microsoft-Windows-Firewall
	'{10B149A5-436F-4799-A2AF-BE5268F8DBF1}!Firewall!0xffffffff!0xff' # MPSSVCUI
	'{95910355-64B6-4A73-AB64-F32C868B9BA8}!Firewall!0xffffffff!0xff' # MpssvcNLAv2
	'{D5E09122-D0B2-4235-ADC1-C89FAAAF1069}!Firewall!0xffffffff!0xff' # MpsDrvTrace 
	'{D8FA2E77-A77C-4494-9297-ACE3C12907F6}!Firewall!0xffffffff!0xff' # FwPolicyIoMgr
	'{B6A0EFDB-2676-4355-A626-A2618B2BA031}!Firewall!0xffffffff!0xff' # WindowsFirewallWMI
	'{5EEFEBDB-E90C-423A-8ABF-0241E7C5B87D}!Firewall!0xffffffffffffffff!0xff' # Mpssvc
	'{5444519F-2484-45A2-991E-953E4B54C8E0}!Firewall!0xffffffff!0xff' # Microsoft-Windows-MPS-SRV
	'{50BD1BFD-936B-4DB3-86BE-E25B96C25898}!Firewall!0xffffffff!0xff' # Microsoft-Windows-MPS-DRV
	'{37945DC2-899B-44D1-B79C-DD4A9E57FF98}!Firewall!0xffffffff!0xff' # Microsoft-Windows-MPS-CLNT
	'{546549BE-9D63-46AA-9154-4F6EB9526378}!Firewall!0xffffffff!0xff' # Microsoft-Windows-Firewall-CPL
	'{3CE641BB-155B-451D-A23A-D59CE0A2E9C9}!Firewall!0xffffffff!0xff' # FIREWALL_CPL
	'{28C9F48F-D244-45A8-842F-DC9FBC9B6E92}!Firewall!0xffffffff!0xff' # FirewallAPI
	'{F997CD11-0FC9-4AB4-ACBA-BC742A4C0DD3}!Firewall!0xffffffff!0xff' # Microsoft-Windows-RPC-FirewallManager
	'{147E266B-7154-4163-9D20-2F386237831F}!Firewall!0xffffffff!0xff' # SCW_FIREWALL_EXTENSION							#Win7/Win 8 only 
	'{0EFF663F-8B6E-4E6D-8182-087A8EAA29CB}!Firewall!0xffffffff!0xff' # WFAPIGP
	'{C293005F-6705-449E-B0F3-A3AE121ED3A8}!Firewall!0xffffffff!0xff' # ICFUPGD_DLL
	'{B83F20C9-622B-49B2-97C4-FEFE7B1F3FCA}!Firewall!0xffffffff!0xff' # SCW_REGISTRY_EXTENSION							#Win7/Win 8 only 
	'{098F2470-BAE0-11CD-B579-08002B30BFEB}!Firewall!0xffffffff!0xff' # Microsoft-Windows-Security-Configuration-Wizard	#Win7/Win 8 only 
	'{28C9F48F-D244-45A8-842F-DC9FBC9B6E94}!Firewall!0xffffffff!0xff' # WFMGR
	'{5AD8DAF3-405C-4FD8-BCC5-5ABE20B3EDD6}!Firewall!0xffffffff!0xff' # FW
	'{D76203C4-8C1B-4E53-AFAB-C22865594F3F}!Firewall!0xffffffff!0xff' # Microsoft.Windows.Firewall
	'{D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85}!Firewall!0xffffffff!0xff' # Microsoft-Windows-Windows Firewall With Advanced Security 	# = NET_BFE
	'{935F4AE6-845D-41C6-97FA-380DAD429B72}!Firewall!0xffffffff!0xff' # AUTHFWCFG
	'{E90CB4C0-C7B6-4F18-A53A-187934AD4B55}!Firewall!0xffffffff!0xff' # Microsoft.Windows.Firewall.PolicyIoManager
	'{702BB771-F6F6-4B08-ADAF-42ABE09B4FD1}!Firewall!0xffffffff!0xff' # Microsoft.Windows.Firewall.Aggregate
	'{0998DFB7-59D7-4E82-92CE-8A83E7C0BB3E}!Firewall!0xffffffff!0xff' # Microsoft.Windows.Firewall.API
	#'{EA2E4E95-2B14-462D-BB78-DEE94170804F}!Firewall!0xffffffff!0xff' # Microsoft-Windows-NetworkController-FirewallService	# that is for virtualization 
	'{FFDB0CFD-833C-4F16-AD3F-EC4BE3CC1AF5}!Firewall!0xffffffff!0xff' # Microsoft.Windows.EnterpriseManagement.PolicyManager
	'{76FA08A3-6807-48DB-855D-2C12702630EF}!Firewall!0xffffffff!0xff' # Microsoft.Windows.EnterpriseManagement.ConfigManagerHook
	'{F058515F-DBB8-4C0D-9E21-A6BC2C422EAB}!Firewall!0xffffffff!0xff' # Microsoft.Windows.DeviceManagement.SecurityPolicyCsp
)
 $NET_FirewallProviders += $ADS_GPOProviders

$NET_FltMgrProviders = @(
	'{4F5D14A2-97BB-454B-B848-6F3CE0DF80F1}!FltMgr!$global:FltMgrFlags!0x4' # FltMgr	- $global:FltMgrFlags="0x08810800" in tss_config.cfg
)

$NET_FSRMProviders = @(
	'{3201C659-D580-4833-B17D-1ADAF643C64C}' # FSRM Tracing Provider
	'{1214600F-DF79-4A03-94F5-65D7CAB4FD16}' # Quota
	'{1C7BC728-8199-48BE-BD4D-406A63303C8D}' # Cbafilt
	'{F3C5E28E-63F6-49C7-A204-E48A1BC4B09D}' # Microsoft-Windows-FilterManager
)

$NET_FWmgrProviders = @(
	'{28C9F48F-D244-45A8-842F-DC9FBC9B6494}' # WFMGR
	'{A8351B7A-57BE-4388-8843-08DE1E321B7F}' # FwPolicyIoMgr
	'{A487F25A-2C11-43B7-9050-527F0D6117F2}' # FWUtil NcaUtilAdhUtil VpnUtil
	'{95910355-64B6-4A73-AB64-F32C868B9BA8}' # MpssvcNLAv2
	'{0D78C116-50F4-416C-AC97-589EB943DF49}' # FW_PLUMBER
	'{94335EB3-79EA-44D5-8EA9-306F49B3A040}' # MpsIpsecPolicyAgent
	'{E4FF10D8-8A88-4FC6-82C8-8C23E9462FE5}' # NSHIPSEC
)

$NET_GeoLocationProviders = @(
	'{BCCE86FC-FEBD-4F2D-8E42-E277BA2B524C}' # TzautoupdateProvider
	'{89DFBDE8-86E8-489B-9867-EEFDC5E8879B}' # LOCATION_TRACE_ID
	'{6F111213-BEF8-415D-8AB5-C0FD27687118}' # LocationRuntimeTraceControl
	'{3E06F325-C807-4A4B-B2BC-C6A7C0C010E5}' # GeofenceMonitor
	'{FF7B0CAD-42BB-4657-A578-64CD6CB2819B}' # LocationApi
	'{C3511D74-0E47-4341-9F10-DF76F6823E06}' # Microsoft-Windows-LocationService
	'{CB671458-AD15-40E8-A65A-753EA62D853A}' # Microsoft.Geolocation.Api
	'{0CB61430-077E-4E88-AD37-F88A4687B44D}' # LocationApiTraceControl
	'{4D13548F-C7B8-4174-BB7A-D7F64BF22D29}' # Microsoft-WindowsPhone-LocationServiceProvider
)

$NET_HNSProviders = @(
	'{0c885e0d-6eb6-476c-a048-2457eed3a5c1}' # Microsoft-Windows-Host-Network-Service
	'{80CE50DE-D264-4581-950D-ABADEEE0D340}' # 
	'{D0E4BC17-34C7-43fc-9A72-D89A59D6979A}' # 
	'{93f693dc-9163-4dee-af64-d855218af242}' # Microsoft-Windows-Host-Network-Management
)

$NET_WinInetProviders = @( 		# !Caution! list this first, before any reference to it, i.e. $NET_HTTPProviders += $NET_WinInetProviders
	'{1a211ee8-52db-4af0-bb66-fb8c9f20b0e2}' # Microsoft.OSG.Web.WinInet
	'{43D1A55C-76D6-4f7e-995C-64C711E5CAFE}' # Microsoft-Windows-WinINet
	'{4E749B6A-667D-4c72-80EF-373EE3246B08}' # WinInet
	'{5402E5EA-1BDD-4390-82BE-E108F1E634F5}' # Microsoft-Windows-WinINet-Config
	'{A70FF94F-570B-4979-BA5C-E59C9FEAB61B}' # Microsoft-Windows-WinINet-Capture
)

$NET_HTTPProviders = @(		#from UEX / ToDo: consolidate with HttpSys
	'{7D44233D-3055-4B9C-BA64-0D47CA40A232}' # Microsoft-Windows-WinHttp
	'{1070f044-721c-504b-c01c-671dadcbc77d}' # WinHTTP(Tracelogging)
	'{B3A7698A-0C45-44DA-B73D-E181C9B5C8E6}' # WinHttp(WPP)
)
 $NET_HTTPProviders += $NET_WinInetProviders

$NET_HttpSysProviders = @(
	'{7D44233D-3055-4B9C-BA64-0D47CA40A232}' # Microsoft-Windows-WinHttp
	'{DD5EF90A-6398-47A4-AD34-4DCECDEF795F}' # Microsoft-Windows-HttpService
	'{72B18662-744E-4A68-B816-8D562289A850}' # Windows HTTP Services
	'{20F61733-57F1-4127-9F48-4AB7A9308AE2}' # HttpSysGuid
	'{C42A2738-2333-40A5-A32F-6ACC36449DCC}' # Microsoft-Windows-HttpLog
	'{7B6BC78C-898B-4170-BBF8-1A469EA43FC5}' # Microsoft-Windows-HttpEvent
	'{F5344219-87A4-4399-B14A-E59CD118ABB8}' # Microsoft-Windows-Http-SQM-Provider
	'{B1945E15-4933-460F-8103-AA611DDB663A}' # HttpSysProvider
)
$NET_HttpSysProviders += $NET_WinInetProviders

$NET_HypVMProviders = @(
	'{0A18FF18-5362-4739-9671-78023D747B70}' # Microsoft-Windows-Hyper-V-Network
	'{152FBE4B-C7AD-4F68-BADA-A4FCC1464F6C}' # Microsoft-Windows-Hyper-V-Netvsc
	#'{064F02D0-A6C4-4924-841A-F3BADC2675F6}' # NDIS Trace Provider
	'{DA2473F4-3E39-4565-A6D0-BA8F0D1D7D61}' # NdisVirtualBusWPPGuid
	'{C29C4FB7-B60E-4FFF-9AF9-CF21F9B09A34}' # Microsoft-Windows-Hyper-V-SynthNic
	'{CD079D47-329D-4DC5-881C-CB28BB80A9A0}' # NetworkVsc
)

$NET_ICSProviders = @(
	'{A6F32731-9A38-4159-A220-3D9B7FC5FE5D}' # Microsoft-Windows-SharedAccess_NAT
	'{8F3C64A5-69C2-4CDA-93CB-B1031E362B8F}' # Microsoft.Windows.Networking.SharedAccess
)

$NET_IPAMProviders = @(
	'{AB636BAA-DFF3-4CB0-ABF0-56E192DAC2B3}' # Microsoft-Windows-IPAM
)

$NET_IPhlpSvcProviders = @(
	'{6600E712-C3B6-44A2-8A48-935C511F28C8}' # Microsoft-Windows-Iphlpsvc-Trace
	'{66A5C15C-4F8E-4044-BF6E-71D896038977}' # Microsoft-Windows-Iphlpsvc
	'{3EB875EB-8F4A-4800-A00B-E484C97D7551}' # Microsoft-Windows-Network-Connection-Broker
	'{70F18147-06E6-497B-BBC4-58D60B4760E2}' # Microsoft.Windows.Networking.Teredo
	'{4EDBE902-9ED3-4CF0-93E8-B8B5FA920299}' # Microsoft-Windows-TunnelDriver
	'{4214DCD2-7C33-4F74-9898-719CCCEEC20F}' # Microsoft-Windows-TunnelDriver-SQM-Provider
	'{444943B7-3A0F-45C9-B7CB-D2A2DE9EB852}' # Microsoft.Windows.Networking.Tunnel
	'{B80A3EE8-4ECE-4DF5-9BBB-B26B60AC983D}' # NcaApi AdhApi VpnApi
	'{8FC438F1-00EF-4F07-B68E-08A9A9B55ADB}' # NcaApiServer AdhApiServer VpnProtoEngApiServer VpnWinRTSrc 
	'{29F60C6B-8C09-449F-9979-082591D09318}' # NcaSvc AdhSvc
	'{A487F25A-2C11-43B7-9050-527F0D6117F2}' # FWUtil Ncatil AdhUtil VpnUtil
	'{794FE1C3-CDC4-45D4-AF07-120A69B1B6B6}' # KAProvider
	'{A14CAFA7-A31F-4993-AD02-279F410A19D7}' # NCBSVC
	'{2AB7ABE2-FD6B-49DD-931E-D3339832676A}' # NcbService
)

$NET_IPsecProviders = @(
	'{C91EF675-842F-4FCF-A5C9-6EA93F2E4F8B}' # Microsoft-Windows-IPSEC-SRV
	'{94335EB3-79EA-44D5-8EA9-306F49B3A040}' # MpsIpsecPolicyAgent
	'{94335EB3-79EA-44D5-8EA9-306F4FFFA070}' # IpsecPAStore
	'{94335EB3-79EA-44D5-8EA9-306F49B3A070}' # IpsecPolStore
	'{AEA1B4FA-97D1-45F2-A64C-4D69FFFD92C9}' # Microsoft-Windows-GroupPolicy
	'{2588030D-920F-4AD6-ACC0-8AA2CD761DDC}' # IPsecGWWPPGuid
	'{12D06DF7-58EB-4642-9FB2-6D50D008900C}' # RRAS IpSecFirewall				#Win7/Win 8 only 
	'{E4FF10D8-8A88-4FC6-82C8-8C23E9462FE5}' # NSHIPSEC
	'{5EEFEBDB-E90C-423A-8ABF-0241E7C5B87D}' # Mpssvc
	'{94335EB3-79EA-44D5-8EA9-306F49B3A041}' # MpsIpsecClient
	'{3BEEDE59-FC7D-5057-CE28-BABAD0B27181}' # HCSRVEXT							# NAP- Win7/Win 8 only 
	'{2BEEDE59-EC7D-4057-BE28-C9EAD0B27180}' # NAPIPSEC							# NAP- Win7/Win 8 only 
	'{8115579E-2BEA-4C9E-9AB1-821CC2C98AB0}' # Microsoft-Windows-NAPIPSecEnf	# NAP- Win7/Win 8 only 
	#'{3AD15A04-74F1-4DCA-B226-AFF89085A05A}' # Microsoft-Windows-Wnv
	'{D8FA2E77-A77C-4494-9297-ACE3C12907F6}' # FwPolicyIoMgr
	#'{49D6AD7B-52C4-4F79-A164-4DCD908391E4}' # NisDrvWFP Provider				#WFP only - not related to IPsec
	'{5AD8DAF3-405C-4FD8-BCC5-5ABE20B3EDD6}' # FW
	#'{B40AEF77-892A-46F9-9109-438E399BB894}' # AFD Trace
	'{106B464D-8043-46B1-8CB8-E92A0CD7A560}' # KernelFilterDriver				# IKEEXT
	'{7B702970-90BC-4584-8B20-C0799086EE5A}' # Microsoft-Windows-NetworkSecurity
)

$NET_iSCSIProviders = @(
	'{1babefb4-59cb-49e5-9698-fd38ac830a91}' # iScsi
	'{13953C6E-C594-414E-8BA7-DEB4BA1878E3}' # Microsoft-Windows-iSCSITarget-Service
	'{07ABD211-DA70-4F8F-B3EF-BF825FD7B189}' # Microsoft-Windows-iSCSITarget-VSSProvider
	'{82FB2F8C-A21C-453B-ACBD-7EF49493D727}' # WinTargetWPP
	'{7D758B3E-E29E-43DA-8683-9860A1C19362}' # Microsoft-Windows-iSCSITarget-VDSProvider
	'{BBF8051F-1F47-44CA-AC73-92658CD4E4F8}' # WTLmDrvCtrlGuid
	'{B5E70289-982D-4109-BC5E-BF554BAD08F5}' # WTSmisProviderWPP
	'{81C84CFA-C80B-47A1-BECE-5CA0F1851FEB}' # WTVssProviderWPP
)

$NET_KernelIOProviders = @(
	'{A103CABD-8242-4A93-8DF5-1CDF3B3F26A6}' # Microsoft-Windows-Kernel-IoTrace
	'{ABF1F586-2E50-4BA8-928D-49044E6F0DB7}' # Microsoft-Windows-Kernel-IO
)


$NET_LBFoProviders = @(
	'{B72C6994-9FE0-45AD-83B3-8F5885F20E0E}!LBFO' #'Microsoft-Windows-MsLbfoEventProvider'		# - may not exist on client OS
	'{387ED463-8B1B-42C9-9EF0-803FDFD5D94E}!LBFO' # Microsoft-Windows-MsLbfoSysEvtProvider 		# - may not exist on client OS
	'{11C5D8AD-756A-42C2-8087-EB1B4A72A846}!LBFO' # Microsoft-Windows-NdisImPlatformEventProvider
	'{62DE9E48-90C6-4755-8813-6A7D655B0802}!LBFO' # Microsoft-Windows-NdisImPlatformSysEvtProvider
	'{A781472C-CFC9-42CB-BCEA-A00B916AD1BE}!LBFO' # NDISIMPLAT
	'{B1809D25-B84D-4E40-8D1B-C9978D8946AB}!LBFO' # LBFOProviderGUID
	'{9B5CB64B-6166-4369-98CA-986AE578E216}!LBFO' # NdisImPlatformWPPGuid
	'{41E8E8F3-7B6D-488E-B350-F696DD24AFB6}!LBFO' # NETCFG
	# '{6CC2405D-817F-4886-886F-D5D1643210F0}!ndis!0xFFFFFFFFFFFFFFFF!0x5' 	# NDISWMI
)
 $NET_LBFoProviders += @(
	'{064F02D0-A6C4-4924-841A-F3BADC2675F6}!LBFO' 						 # NDIS Trace Provider
	'{CDEAD503-17F5-4A3E-B7AE-DF8CC2902EB9}!LBFO!0xFFFFFFFFFFFFFFFF!0x5' # Microsoft-Windows-NDIS - Added flags 0x5
	'{DD7A21E6-A651-46D4-B7C2-66543067B869}!LBFO!0xFFFFFFFFFFFFFFFF!0x5' # NDISTraceGuid
	'{6CC2405D-817F-4886-886F-D5D1643210F0}!LBFO!0xFFFFFFFFFFFFFFFF!0x5' # NDISWMI
	) #issue #636

$NET_LDAPcliProviders = @(
	'{099614A5-5DD7-4788-8BC9-E29F43DB28FC}!LDAPcli!$global:LDAPcliFlags!0xff' # Microsoft-Windows-LDAP-Client - $global:LDAPcliFlags="0x1a59afa3" in tss_config.cfg
)
$NET_LDAPsrvProviders = @(
	'{90717974-98DB-4E28-8100-E84200E22B3F}!LDAPsrv!0xFFFFFFFFFFFFFFFF!0xff' # NTDSA
	'{3e7da688-9a79-4dd5-81c9-54d74c456890}!LDAPsrv!0xFFFFFFFFFFFFFFFF!0xff' # NTDSA_PROV2
)
 
$NET_LLTDIOProviders = @(
	'{0741C7BE-DAAC-4A5B-B00A-4BD9A2D89D0E}' # Microsoft-Windows-LLTD-MapperIO
	'{E159FC63-02FE-42F3-A234-028B9B8561CB}' # RSPNDR
	'{CCC64809-6B5F-4C1B-AB39-336904DA9B3B}' # LLTDSVC
)
$NET_LLDPProviders = @(
	'{DCBFB8F0-CD19-4F1C-A27D-23AC706DED72}' # Microsoft-Windows-LinkLayerDiscoveryProtocol
	'{4C5CD317-6946-A09F-9F5C-C31B1281D5F0}' # LLDPWMI
	'{DCBFB8F7-CD19-4F1C-A27D-23AC706DED72}' # MSDCN
)

$NET_MBAMProviders = @(
	'{632F767E-0EC3-47B9-BA1C-A0E62A74728A}' # Microsoft-Windows-BitLocker-DrivePreparationTool
	'{5D674230-CA9F-11DA-A94D-0800200C9A66}' # Microsoft-Windows-BitLocker-API
	'{651DF93B-5053-4D1E-94C5-F6E6D25908D0}' # Microsoft-Windows-BitLocker-Driver
	'{1DE130E1-C026-4CBF-BA0F-AB608E40AEEA}' # Microsoft-Windows-BitLocker-Driver-Performance
	'{7140345F-B491-497C-98DE-0072D12D0FE1}' # FveCtlGuid
)

$NET_MBNProviders = @(
	'{3A07E1BA-3A6B-49BF-8056-C105B54DD7FB}' # WwanControlGuid
	'{3CB40AAA-1145-4FB8-B27B-7E30F0454316}' # Microsoft-Windows-WWAN-SVC-EVENTS
	'{7839BB2A-2EA3-4ECA-A00F-B558BA678BEC}' # Microsoft-Windows-WWAN-MM-EVENTS
	'{78168022-ECA5-41E8-9E17-E8C7FD77AAE1}' # Microsoft-Windows-WWAN-UI-EVENTS
	'{D086235D-48B9-4E49-ADED-5304BF8F636D}' # WwanProtoControlGuid
	'{71C993B8-1E28-4543-9886-FB219B63FDB3}' # Microsoft-Windows-WWAN-CFE
	'{F4C9BE26-414F-42D7-B540-8BFF965E6D32}' # Microsoft-Windows-WWAN-MediaManager
	'{2DD11DE3-FDDE-4DA9-B57A-AF6585F74233}' # WlanRadioManager
	'{0255BB48-E574-488A-8348-AE2C7652AFC5}' # microsoft-windows-wwan-hlk
	'{681E3481-7510-4053-8C87-A6305EAFC4FA}' # Microsoft-WindowsPhone-Connectivity-WwanExt
	'{B3EEE223-D0A9-40CD-ADFC-50F1888138AB}' # Microsoft-Windows-WWAN-NDISUIO-EVENTS
	'{D58C1268-B309-11D1-969E-0000F875A532}' # CommonWppTrace
	'{F3F14AC7-64BC-4A44-A190-807189ED2918}' # Microsoft-WindowsPhone-Net-CellCore-WwanFilter
	'{9A6615A6-902A-4705-804B-57B8813089B8}' # Microsoft-WindowsPhone-Net-Cellcore-CellManager
)

$NET_MFAextProviders = @(
	'{7237ED00-E119-430B-AB0F-C63360C8EE81}' # 
	'{EC2E6D3A-C958-4C76-8EA4-0262520886FF}' # 
)

$NET_MiracastProviders = @(
	'{802EC45B-1E99-4B83-9920-87C98277BA9D}' # MiracastWppControlGuid
	'{1F930301-F484-4E01-A8A7-264354C4B8E3}' # Microsoft.Windows.Cast.Miracast
	'{1F930302-F484-4E01-A8A7-264354C4B8E3}' # Microsoft.Windows.Cast.MiracastLogging
	'{569A031F-3540-46E0-96D4-FB94164A99C7}' # Microsoft.Windows.Cast.MiracastReceiver
	'{802EC45A-1E99-4B83-9920-87C98277BA9D}' # Microsoft-Windows-DxgKrnl
)

$NET_MUXProviders = @(
	'{6C2350F8-F827-4B74-AD0C-714A92E22576}' # Microsoft-Windows-SlbMux
	'{645B8679-5451-4C36-9857-A90E7DBF97BC}' # Microsoft-Windows-SlbMuxDriver
)

$NET_NCAProviders = @(
	'{126DED58-A28D-4113-8E7A-59D7444B2AF1}' # Microsoft-Windows-Ncasvc
	'{29F60C6B-8C09-449F-9979-082591D09318}' # NcaSvc
	'{A487F25A-2C11-43B7-9050-527F0D6117F2}' # NcaUtil
	'{63AC12D9-F21B-402D-BD67-8E415AA896AA}' # Microsoft.Windows.Networking.NCA
)

$NET_NCHAProviders = @(
	'{28F7FB0F-EAB3-4960-9693-9289CA768DEA}' # 
	'{A6527853-5B2B-46E5-9D77-A4486E012E73}' # 
	'{DBC217A8-018F-4D8E-A849-ACEA31BC93F9}' # 
	'{41DC7652-AAF6-4428-BBBB-CFBDA322F9F3}' # 
	'{F2605199-8A9B-4EBD-B593-72F32DEEC058}' #
)

$NET_NCSIProviders = @(
	'{8CE93926-BDAE-4409-9155-2FE4799EF4D3}!ncsi!0xFFFFFFFFFFFFFFFF!0x5' # Microsoft-Windows-PrimaryNetworkIcon
	'{1701C7DC-045C-45C0-8CD6-4D42E3BBF387}!ncsi!0xFFFFFFFFFFFFFFFF!0x5' # NCSI
	'{7868B0D4-1423-4681-AFDF-27913575441E}!ncsi!0xFFFFFFFFFFFFFFFF!0x5' # Microsoft-Windows-NetworkStatus
	'{5A8A94F3-249F-49F8-86D1-E6527C80622B}!ncsi!0xFFFFFFFFFFFFFFFF!0x5' # Microsoft.Windows.NetworkInformation
	'{339817CF-D7A8-4114-94B2-A240843D77EE}!ncsi!0xFFFFFFFFFFFFFFFF!0x5' # htelemetryNetworkUxHandlerProvider
	'{111FFC99-3987-4BF8-8398-61853120CB3D}!ncsi!0xFFFFFFFFFFFFFFFF!0x5' # PNIandNetcenterGUID
)

$NET_NDISProviders = @(
	'{064F02D0-A6C4-4924-841A-F3BADC2675F6}!ndis' 						 # NDIS Trace Provider
	'{CDEAD503-17F5-4A3E-B7AE-DF8CC2902EB9}!ndis!0xFFFFFFFFFFFFFFFF!0x5' # Microsoft-Windows-NDIS - Added flags 0x5
	'{DD7A21E6-A651-46D4-B7C2-66543067B869}!ndis!0xFFFFFFFFFFFFFFFF!0x5' # NDISTraceGuid
	'{6CC2405D-817F-4886-886F-D5D1643210F0}!ndis!0xFFFFFFFFFFFFFFFF!0x5' # NDISWMI
)
$NET_NDIScapProviders = @(
	'{2ED6006E-4729-4609-B423-3EE7BCD678EF}' 							 # Microsoft-Windows-NDIS-PacketCapture 
)

$NET_NDISwanProviders = @(
	'{96AAE65F-EAA3-4FE8-A400-87A916C1A82E}' 							 # RRAS NdisWan / CtlGuid
)

$NET_NetProfMProviders = @(
 if (!$global:StartAutologger.IsPresent) {
	'{D9131565-E1DD-4C9E-A728-951999C2ADB5}' # NetworkProfileManagerTraceGUID
	'{FBCFAC3F-8460-419F-8E48-1F0B49CDB85E}' # Microsoft-Windows-NetworkProfileTriggerProvider
	'{ED795972-60E8-4815-8634-CFAA21A89DE7}' # Microsoft.Windows.NetworkProfileService
	'{EA289C62-8C36-4904-9726-15ECD282AED5}' # Microsoft.Windows.NetworkListManager
 }
)

$NET_NetsetupProviders = @(
	'{A111F1C0-5923-47C0-9A68-D0BAFB577901}' # NETSETUP
	'{94DEB9D1-0A52-449B-B368-41E4426B4F36}' # Microsoft.Windows.Hyper.V.NetSetupHelper
	'{A111F1C2-5923-47C0-9A68-D0BAFB577901}' # Microsoft-Windows-Network-Setup
	'{A111F1CB-5923-47C0-9A68-D0BAFB577901}' # Microsoft.Windows.Networking.NetworkSetupShim
	'{A111F1CC-5923-47C0-9A68-D0BAFB577901}' # Microsoft.Windows.Networking.NetworkSetupSvc
	'{A111F1C3-5923-47C0-9A68-D0BAFB577901}' # Microsoft.Windows.Networking.NetworkSetup
	'{3FF1D341-0EE4-4617-A924-79B1DAD316F2}' # VMSNETSETUPPLUGIN
	'{4DC1CD72-9D11-45E2-B954-FD27BDA0DE06}' # Microsoft.NetCfg.Diagnostics
)

$NET_NetworkUXProviders = @(
	'{90BBBABB-255B-4FE3-A06F-685A15E93A4C}' # 
	'{0879871C-E412-4C6A-87A6-74581B0AFAC5}' # 
	'{e6dec100-4e0f-4927-92be-e69d7c15c821}' # WlanMM
)

$NET_NetlogonProviders = @(
	'{CA030134-54CD-4130-9177-DAE76A3C5791}' # NETLOGON/ NETLIB
	'{E5BA83F6-07D0-46B1-8BC7-7E669A1D31DC}' # Microsoft-Windows-Security-Netlogon
)

$NET_NFCProviders = @(
	'{1B208304-26F2-433D-8781-0512D91B101C}' # NfcI2CTraceGuid
	'{35DF99C2-B4AE-431C-B46C-62FFDD50BFE8}' # NfcAbendTraceGuid
	'{696D4914-12A4-422C-A09E-E7E0EB25806A}' # NfcCoreLibTraceControl
	'{03162B40-C068-478F-8F8D-11279331E7C9}' # CtlGuid
	'{85C070E6-F9AE-481F-AACB-BC550BFD35A1}' # Microsoft-Windows-NFC-ClassExtension
	'{351734B9-8706-4CEE-9247-04ACCD448C76}' # NfcCxTraceControl
	'{D976D933-B88B-4227-95F8-00513C0986DE}' # NfcSmartCardTraceControl
	'{6E6BACF6-5635-4670-BEDF-93F55A822F4B}' # Microsoft.Windows.Nfc.NfcCx
	'{E79E077F-E35E-4263-B44B-FDBEE03D2C24}' # CtlGuid
	'{A92C0AD8-6373-4758-A65D-8D0C934C4D09}' # Microsoft-WindowsPhone-NfcController
	'{9D97CB90-8DEE-42B8-B553-D1816BE6FB9E}' # NciParsersTraceControl
	'{4EB7CC58-145C-4A79-9418-68CD290DD9D4}' # NfcProximityTraceControl
)

$NET_NFScliProviders = @(
	'{355C2284-61CB-47BB-8407-4BE72B5577B0}' # nfsrdr -- also in fskm
	'{6361F674-C2C0-4F6B-AE19-8C62F47AE3FB}' # NfsClientGuid -- also in fskm
	'{C4C52165-AD74-4B70-B62F-A8D35A135E7A}' # NfsClientGuid
	'{746A1133-BC1E-47C7-8C95-3D52C39114F9}' # Microsoft-Windows-ServicesForNFS-Client -- also in fskm
	#'{3D888EE4-5A93-4633-91E7-FFF8AFD89A7B}' # Microsoft-Windows-ServicesForNFS-ONCRPC https://learn.microsoft.com/en-us/windows-server/storage/nfs/nfs-overview#windows-and-windows-server-versions
)

$NET_NFSsrvProviders = @(
	'{3c33d8b3-66fa-4427-a31b-f7dfa429d78f}' # NfsSvrNfsGuid
	'{fc33d8b3-66fa-4427-a31b-f7dfa429d78f}' # NfsSvrNfsGuid2
	'{57294EFD-C387-4e08-9144-2028E8A5CB1A}' # NfsSvrNlmGuid
	'{CC9A5284-CC3E-4567-B3F6-3EB24E7CFEC5}' # MsNfsFltGuid
	'{f3bb9731-1d9f-4b8e-a42e-203bf1a32300}' # Nfs4SvrGuid
	'{53c16bac-175c-440b-a266-1e5d5f38313b}' # OncRpcXdrGuid	/ also in rpcxdr
	'{94B45058-6F59-4696-B6BC-B23B7768343D}' # rpcxdr 			/ also in rpcxdr
	'{e18a05dc-cce3-4093-b5ad-211e4c798a0d}' # PortMapGuid
	'{6E1CBBE9-8C4B-4003-90E2-0C2D599A3EDC}' # Microsoft-Windows-ServicesForNFS-Portmapper
	'{F450221A-07E5-403A-A396-73923DFB2CAD}' # Microsoft-Windows-ServicesForNFS-NFSServerService
	'{3D888EE4-5A93-4633-91E7-FFF8AFD89A7B}' # Microsoft-Windows-ServicesForNFS-ONCRPC
	'{A0CC474A-06CA-427C-BDFF-84733163E262}' # Microsoft-Windows-ServicesForNFS-Cluster
)

$NET_NLBProviders = @(
	'{B40AEF77-892A-46F9-9109-438E399BB894}' # AFD Trace
	'{0C478C5B-0351-41B1-8C58-4A6737DA32E3}' # Microsoft-Windows-WFP
	'{E1F65B93-F32A-4ED6-AA72-B039E28F1574}' # NLB Standard Trace
	'{F498B9F5-9E67-446A-B9B8-1442FFAEF434}' # NLB Packet Trace
	'{DEF02E30-3290-4B2D-BC28-D2B0EDADF411}' # Microsoft-Windows-NLB-Diagnostic
	'{F22AF71F-C4C3-425D-9653-B2F47B85DD30}' # Microsoft-Windows-NLB
	'{2CC71B61-AF58-4847-8CD0-C65D5B0C8F55}' # DAF
)

$NET_NPSProviders = @(
	#'{91CC1150-71AA-47E2-AE18-C96E61736B6F}' # Microsoft-Windows-Schannel-Events	#2023-04-03 included in ADS_SSL
	'{F6578502-DF4E-4a67-9661-E3A2F05D1D9B}' # EapAuthenticator
	'{B2CBF6DC-392A-43AE-98D2-1AA66DFCB2C3}' # napnps
	'{997590EF-d144-4d41-b7fb-7028ae295b04}' # 
	'{822BEC9E-660F-4f9d-96b5-ead6874cb0bd}' # 
	'{574450B9-c7f9-4c05-a01e-b90f8f7744e3}' # 
	'{54E83B5A-a7df-473e-9d9a-620628c3a613}' # 
	'{A2B83C30-4c50-4562-ac07-7b89461fe720}' # 
	'{C124EF85-9447-4a75-be21-3a97fdda3e81}' # 
	'{EA500216-dc45-4f41-a1dc-e37ea5df188e}' # 
	'{BAE49237-f9d2-4eea-b660-1aa0f1f5637f}' # 
	'{C2300092-f475-42ae-9ea9-66c268bef2c6}' # 
	'{6EB8DB94-FE96-443F-A366-5FE0CEE7FB1C}' # Microsoft-Windows-EapHost
)

$NET_NTFSProviders = @(
	'{3FF37A1C-A68D-4D6E-8C9B-F79E8B16C482}' # Microsoft-Windows-Ntfs
	'{B2FC00C4-2941-4D11-983B-B16E8AA4E25D}' # NtfsLog
	'{DD70BC80-EF44-421B-8AC3-CD31DA613A4E}' # Ntfs
	'{E9B319E4-0030-40A7-91CB-04D6A8EF7E09}' # Microsoft-Windows-Ntfs-SQM
	'{8E6A5303-A4CE-498F-AFDB-E03A8A82B077}' # Microsoft-Windows-Ntfs-UBPM
	'{FFD1D811-6488-4D44-82AF-C31D372609A9}' # NtfsTelemetryProvider
	'{740F3C34-57DF-4BAD-8EEA-72AC69AD5DF5}' # Ntfs_ProtogonWmiLog
)

$NET_OLE32Providers = @(
	'{BDA92AE8-9F11-4D49-BA1D-A4C2ABCA692E}' # OLE32
)

$NET_OpenSSHProviders = @(
	'{C4B57D35-0636-4BC3-A262-370F249F9802}' # OpenSSH
	'{9EDC1E34-F571-4374-871C-B87CC742017B}' # SshpTelemetryHandle
)

$NET_PerfLibProviders = @(
	'{BC44FFCD-964B-5B85-8662-0BA87EDAF07A}' # Microsoft.Windows.PerfLib
	'{C9BF4A07-D547-4D11-8242-E03A18B5BE01}' # PERFLIB
	'{13B197BD-7CEE-4B4E-8DD0-59314CE374CE}' # Microsoft-Windows-Perflib
	'{970407AD-6485-45DA-AA30-58E0037770E4}' # PerfLib
)

$NET_PnPProviders = @(
	'{9C205A39-1250-487D-ABD7-E831C6290539}' # Microsoft-Windows-Kernel-PnP
	'{D5EBB80C-4407-45E4-A87A-015F6AF60B41}' # Microsoft-Windows-Kernel-PnPConfig
	'{B3A0C2C8-83BB-4DDF-9F8D-4B22D3C38AD7}' # Microsoft-Windows-Kernel-PnP-Rundown
	'{84051B98-F508-4E54-82FA-8865C697C3B1}' # Microsoft-Windows-PnPMgrTriggerProvider
	'{96F4A050-7E31-453C-88BE-9634F4E02139}' # Microsoft-Windows-UserPnp"
	'{A676B545-4CFB-4306-A067-502D9A0F2220}' # PlugPlay
	'{F52E9EE1-03D4-4DB3-B2D4-1CDD01C65582}' # PnpInstal
)

$NET_PortProxyProviders = @(
	'{6600E712-C3B6-44A2-8A48-935C511F28C8}' # Microsoft-Windows-Iphlpsvc-Trace
)

$NET_PrintSvcProviders = @( 
	# from PrintTrace.cmd
	'{747EF6FD-E535-4D16-B510-42C90F6873A1}' # "Microsoft-Windows-PrintService"
	'{C9BF4A02-D547-4D11-8242-E03A18B5BE01}' # WINSPOOL
	'{C9BF4A03-D547-4D11-8242-E03A18B5BE01}' # WIN32SPL
	'{C9BF4A9F-D547-4D11-8242-E03A18B5BE01}' # SPOOLSS
	'{C9BF4A9E-D547-4D11-8242-E03A18B5BE01}' # SPOOLSV
	'{C9BF4A05-D547-4D11-8242-E03A18B5BE01}' # SPLWOW64
	'{C9BF4A01-D547-4D11-8242-E03A18B5BE01}' # LOCALSPL
	'{301CCC25-D58B-4C5E-B6A5-15BCF8B0077F}' # INETPPUI
	'{C9BF4A9E-D547-4D11-8242-E03A18B5BEEE}' # INET3PP
	'{04160794-60B6-4EC7-96FF-4953691F94AA}' # SetupIPP
	'{99F5F45C-FD1E-439F-A910-20D0DC759D28}' # USBMon
	'{B795C7DF-07BC-4362-938E-E8ABD81A9A01}' # NTPRINT
	'{D2E1BAB2-EB9B-4BA7-9123-19C01DDC4F78}' # SPOOLERPLM
	'{D2E1BAB1-EB9B-4BA7-9123-19C01DDC4F78}' # LOCALSPLPLM
	'{B48AE058-218A-4338-9B97-9F5F9E4EB5D2}' # UsbJScript
	'{B4D2914C-FF23-403B-BABF-F0755FB060FE}' # Microsoft.Windows.Print.SpoolerService
	'{DDF2CC14-A470-4449-AB03-F8B95FC8294B}' # Microsoft.Windows.Print.XpsPrint
	'{C59DA080-9CCE-4415-A77D-08457D7A059F}' # JScriptLib
	'{C69CB70A-3133-4CCA-AB0E-046848EFFCDA}' # Microsoft.Windows.Print.Winspool
	'{BA4936A1-31DB-4EDC-89CE-9190E3C0653B}' # Microsoft.Windows.Print.LocalSpooler
	'{AEFE45F4-8548-42B4-B1C8-25673B07AD8B}' # PIPELINE PrintFilterPipelinesvc
	'{7F812073-B28D-4AFC-9CED-B8010F914EF6}' # Microsoft-Windows-PrintService-USBMon
	'{5ED940EB-18F9-4227-A454-8EF1CE5B3272}' # SetupLPR
	'{27239FD0-425E-11D8-9E39-000039252FD8}' # COMMONGuid
	'{19E93940-A1BD-497F-BC58-CA333880BAB4}' # PrintExtension
	'{DD6A31CB-C9C6-4EF9-B738-F306C29352F4}' # MODERNPRINT
	'{3FB15E5D-DF1A-46FC-BEFE-27A4B82D75EE}' # PREFDLG
	'{02EA8EB9-9811-46d6-AEEE-430ADCC2AA18}' # DLGHOST
	'{D3A10B55-1EAD-453d-8FC7-35DA3D6A04D2}' # TCPMIB
	'{C9BF4A04-D547-4d11-8242-E03A18B5BE01}' # BIDISPL
	'{C9BF4A06-D547-4d11-8242-E03A18B5BE01}' # SPLLIB
	'{C9BF4A07-D547-4D11-8242-E03A18B5BE01}' # PERFLIB
	'{C9BF4A08-D547-4d11-8242-E03A18B5BE01}' # ASYNCNTFY
	'{C9BF4A09-D547-4d11-8242-E03A18B5BE01}' # REMNTFY
	'{C9BF4A0A-D547-4d11-8242-E03A18B5BE01}' # GPPRNEXT
	'{C9BF4A0B-D547-4d11-8242-E03A18B5BE01}' # SANDBOX
	'{C9BF4A0C-D547-4d11-8242-E03A18B5BE01}' # SANDBOXHOST
	'{9e6d0d9b-1ce5-44b5-8b98-f32ed89077ec}' # LPRHELP
	'{f30fab8e-84bb-48d4-8e80-f8967ef0fe6a}' # LPRMON
	'{62A0EB6C-3E3E-471d-960C-7C574A72534C}' # TCPMON
	'{9558985e-3bc8-45ef-a2fd-2e6ff06fb886}' # WSDPRINT
	'{836767A6-AF31-4938-B4C0-EF86749A9AEF}' # WSDMON
	'{6D1E0446-6C52-4b85-840D-D2CB10AF5C63}' # WSDPPROXY
	'{4ea56ff9-fc2a-4f0c-8d6e-c345bc452c80}' # DAFWSD
	'{7e2dbfc7-41e8-4987-bca7-76cadfad765f}' # FDWSD
	'{79b3b0b7-f082-4cec-91bc-5e4b9cc3033a}' # FDPrint
	'{A1607A05-8D8A-4d74-82C7-460DD790648E}' # FindNetPrinters
	'{CA478AB1-8B38-451D-90E4-8534EB50B9D3}' # XPSPRINT
	'{A6D25EF4-A3B3-4E5F-A872-24E71103FBDC}' # MicrosoftRenderFilter
	'{eb3b6950-120c-4575-af39-2f713248e8a3}' # BTHPRINT
	'{8bbe74b4-d9fc-4052-905e-92d01579e3f1}' # DAFBTH
	'{afa85d6c-0ea6-4c6a-99b7-5be1c9f3c7a1}' # BTHUSER
	'{0dc96237-bbd4-4bc9-8184-46df83b1f1f0}' # DOXXPS
	'{986de178-ea3f-4e27-bbee-34e0f61535dd}' # XpsRchVw
	'{64f02056-afd9-42d9-b221-6c94733b09b1}' # XpsIFilter
	'{2beade0b-84cd-44a5-90a7-5b6fb2ff83c8}' # XpsShellExt
	'{aaacb431-6067-4a42-8883-3c01526dd43a}' # XpsRender
	'{A83C80B9-AE01-4981-91C6-94F00C0BB8AA}' # PRINTUI
	'{09737B09-A25E-44D8-AA75-07F7572458E2}' # PRNNTFY
	'{3048407B-56AA-4D41-82B2-7d5F4b1CDD39}' # DAFPRINT
	'{19E464A4-7408-49BD-B960-53446AE47820}' # DAS
	'{9B4A618C-07B8-4182-BA5A-5B1943A92EA1}' # MSXpsFilters
	'{FCA72EBA-CBB3-467c-93BC-1DB4978C398D}' # MXDC
	'{EC08D605-5A20-4ED0-AE54-E8C4BFFF2EEB}' # PrinterExtensions
	'{556045FD-58C5-4A97-9881-B121F68B79C5}' # AAD Cloud AP
	'{4a743cbb-3286-435c-a674-b428328940e4}' # PSMWPP
	'{9C6FC32A-E17A-11DF-B1C4-4EBADFD72085}' # PLMWPP
	'{e8109b99-3a2c-4961-aa83-d1a7a148ada8}' # SEBWPP
	'{E6F8A5FC-7FCE-4095-8661-B8E0CB7D9410}' # ScanRT WPP
	'{E6F8A5FC-7FCE-4095-8661-B8E0CB7D9410}' # DeviceEnumeration WPP
	'{744372de-ba26-443b-ba10-712c1a041234}' # Microsoft.Windows.Print.Workflow.API
	'{1bf554be-03c5-4f49-9b57-f3c0cbad589a}' # Microsoft.Windows.Print.Workflow.Broker
	'{08fad69b-3394-5632-97ef-ff9c5a842b1f}' # Microsoft.Windows.Print.Workflow.PrintSupport
	'{be5f8487-3a5d-4477-b0c2-020679b81e56}' # Microsoft.Windows.Print.Workflow.Source
	'{7faee4d5-95c1-5987-54c6-a7c3dfb6e56e}' # Microsoft.Windows.Print.PrintSupport
	'{F69D3E6C-298B-466C-B84F-486E1F21E347}' # Microsoft.Windows.Print.WorkFlowBroker
	'{cae6f32b-2553-5c24-f999-e63dde138b9f}' # Microsoft.Windows.Print.WorkFlowRT
	'{a4f32eea-babb-59b2-3828-ce92e4e20765}' # Microsoft.Windows.PrintCore
	'{6de9ba0e-9e72-53d2-229a-dc09205a27ea}' # Microsoft-Windows-Mobile-Print-Plugins
	'{fd6b6ae4-7563-550d-46a4-da9fe46cad57}' # Microsoft-Windows-Print-Platform
	'{fdcab703-6402-4959-b618-f5c3c279ef3d}' # Microsoft.Windows.Print.PrintConfig
	'{3d9d790d-fb07-539d-b66e-5a2ffb7899ca}' # Microsoft.Windows.Print.PrintCoreConfig
	'{b0f40491-9ea6-5fd5-ccb1-0ec63be8b674}' # Microsoft.Windows.Shell.PrintDialog
	'{c6dba857-03f1-5c5b-350c-ef08dbd04572}' # Microsoft.Windows.Shell.PrintManager
	'{ab4d9355-341e-435d-b3d2-4b0e46354e2c}' # Microsoft.Windows.Das
	'{e4d412ab-4c22-49ef-83ca-eafb90768512}' # Microsoft-Windows-WSD-DafProvider
	'{BC2DAB59-AC78-487A-903E-DB3C343C0BE3}' # Microsoft.Windows.Print.WSDMon
	'{29b47072-00ff-4d9d-852d-0eafc181a9a3}' # Microsoft-Windows-WSD-WSDApi
	'{cb730350-b8b7-56d7-6fa4-90e0ea74a9bb}' # Microsoft.Windows.Print.PrintScanService
	'{15584c9b-7d86-5fe0-a123-4a0f438a82c0}' # Microsoft.Windows.Shell.ServiceProvider
	'{8BFE6B98-510E-478D-B868-142CD4DEDC1A}' # indows.Internal.Shell.ModalExperience
	'{97ff6b54-144c-524b-5fec-82b610461390}' # Microsoft.Windows.Mobile.Shell.ServiceProvider
	'{73cf4d38-21a5-41dc-93d5-c8ec31d84b70}' # Microsoft.Windows.Print.XpsPrint
	'{095da8da-2182-5c9a-53cd-07eca93a04ef}' # Microsoft.Windows.Print.XpsDocumentTargetPrint
	'{6fb61ac3-3455-4da4-8313-c1a855ee64c5}' # Microsoft.Windows.Print.IppMon
	'{e73d49d6-9eda-5059-74d1-b879b18cf9ae}' # Microsoft.Windows.Print.APMon
	'{6d5ca4bb-df8e-41bc-b554-8aeab241f206}' # Microsoft.Windows.Print.DafIpp
	'{dd212385-31e6-541c-5587-3c469bb6470a}' # Microsoft.Windows.Print.DafIppUsb
	'{acf1e4a7-9241-4fbf-9555-c27638434f8d}' # Microsoft.Windows.Print.IppCommon
	'{a08e69ca-2172-5c18-fe96-a2ac30857b97}' # Microsoft.Windows.Print.IppOneCore
	'{6184BC1F-417E-4443-BCCE-9F65BF844AA7}' # Microsoft.Windows.Print.IppConfigConverter
	'{49868e3d-77fb-5083-9e09-61e3f37e0309}' # Microsoft.Windows.Print.HttpRest
	'{05af8001-5e28-5ebb-0329-a20fab346b76}' # Microsoft.Windows.Print.IppEmulator
	'{38ae712f-fad1-528e-9721-6ebefea1ab2b}' # Microsoft.Windows.Print.Mopria.Service
	'{ec5b420f-d2ec-50b4-5119-083a4da63982}' # Microsoft.Windows.Print.Ecp.Service
	'{7e247d3c-42fa-5e08-6427-f98478081d24}' # Microsoft.Windows.Print.GetPrinterConfig
	'{9594011E-FE68-4D05-9F06-C68A0EBE4822}' # Microsoft.Windows.Print.GetIppAttributes
	'{2974da9a-e1f3-5c5f-2abe-f7f20f6448bc}' # Microsoft.Windows.Print.JScriptLib
	#'{077b8c4a-e425-578d-f1ac-6fdf1220ff68}' # Microsoft.Windows.Security.TokenBroker
	#'{bfed9100-35d7-45d4-bfea-6c1d341d4c6b}' # Microsoft.AAD.TokenBrokerPlugin.Provider
	'{e98cb748-3d93-4719-8209-95e0bc46eec7}' # Microsoft.Windows.Print.PwgRenderFilter
	'{15fc363b-e2b4-5e55-f1d3-3b0ff726203d}' # Microsoft.Windows.Print.PCLmRenderFilter
	'{63a87ca3-6662-4925-a0a8-f7bb94ef104e}' # Microsoft.Windows.Print.PrintToPDF
	'{ac521649-5ec6-5397-d1c5-749cbf5ea79b}' # Microsoft.Windows.Print.RenderFilterCommon
	'{3fc887c9-c23f-59cd-88b5-a6086f4bbc9e}' # Microsoft.Windows.Print.USBMon
	'{bf3eac2a-65ca-5ecc-2076-e23c6420a687}' # Microsoft.Windows.Print.DAFMCP
	'{44050ea2-419d-5526-923b-b038e0f1e715}' # Microsoft.Windows.Print.CloudPrintHelper
	'{48111f99-b3d5-5f69-587d-be4ed8e22647}' # Microsoft.Windows.Print.IppAdapterCore
	'{fbfbd628-251d-551d-c4dd-c7820af723e4}' # Microsoft.Windows.Print.IppAdapterCommon
	'{e0d2f15a-3875-5388-2239-23f2538b7636}' # Microsoft.Windows.Print.PrintScanDiscoveryManagement
	'{0aef9116-5ab8-5c05-0eb3-c0721ba93354}' # Microsoft.Windows.Print.PDMUtilities
	'{81d45b93-a5ff-5459-26ff-c092864200c6}' # Microsoft.Windows.Print.WinspoolCore
	'{d758d01c-7402-5923-6a27-44bdcc59a5c5}' # Microsoft.Windows.Print.ApMonPortMig
	'{201eb0f8-12f0-5b34-c99b-75c1541f3479}' # Microsoft.Windows.Print.UsbPortMig
	'{7cdc2341-4d44-54aa-2899-ddb05ecf0adb}' # Microsoft.Windows.Print.McpManagement
	'{402d7aed-ded3-5536-3112-a2ce8baa1fdc}' # Microsoft.Windows.Print.McpManagementUtil
	'{ee8c758e-2e70-574f-8149-266b77c8d56a}' # Microsoft.Windows.Print.McpIppChannel
	'{b145b5c6-1a9d-50c5-7f76-39f208ed09c9}' # Microsoft.Windows.Print.McpEvtSrc
	'{e604ec58-ad08-5a2c-3ecb-704c8c024881}' # Microsoft.Windows.Print.ProxyApp
	'{bad46242-e75f-541f-c2d2-ab35489f27e4}' # Microsoft.Windows.Print.GDI
	'{2e008da9-e1b6-5cb5-0607-82066afcfff4}' # Microsoft.Windows.Scan.EsclScan
	'{93603fbe-a752-550d-b87e-f202b0f27f9e}' # Microsoft.Windows.Scan.EsclWiaDriver
	'{27a7ea23-db5c-5487-b775-89c06c43039b}' # Microsoft.Windows.Scan.EsclProtocol
	'{f25e0650-deff-5306-ca0d-40abb8b107dd}' # Microsoft.Windows.Scan.DafEscl
	'{3e617461-4ad0-5bb1-ce2d-796bf4794fbf}' # Microsoft.Windows.Scan.EsclEmulator
	'{4e880362-c4e8-5c62-7a2e-db0ee6a8f9a8}' # Microsoft.Windows.Scan.Plugins
	'{c7c2a97e-3d49-5f78-bd33-22d8c22a7cf3}' # Microsoft.Windows.Scan.EsclWiaCore
	'{df6dca70-9918-455f-86fe-983adc74fa0d}' # Microsoft.Windows.Scan.Runtime
	'{4a892232-6efc-54c1-1f0a-1b916a719612}' # Microsoft.Windows.Scan.WindowsImageAcquisition
	'{27E76321-1E5B-4a82-BA0C-26E978F15072}' # Microsoft-Windows-PrintDialogs
	'{0E173F13-4266-4EFD-883C-79B24789B1BC}' # Microsoft-Windows-PrintDrivers 
	'{7f812073-b28d-4afc-9ced-b8010f914ef6}' # Microsoft-windows-printservice-usbmon
	'{747EF6FD-E535-4d16-B510-42C90F6873A1}' # Microsoft-Windows-PrintService
	'{d49918cf-9489-4bf1-9d7b-014d864cf71f}' # Microsoft-Windows-ProcessStateManager 
	'{B6BFCC79-A3AF-4089-8D4D-0EECB1B80779}' # Microsoft-Windows-SystemEventsBroker
)


$NET_QuicProviders = @(
	'{FF15E657-4F26-570E-88AB-0796B258D11C}' # Microsoft-Quic/MsQuic - QUIC 1.0 compliant
	'{2BCFEFE5-5026-536B-1686-B249CB49CAE3}' # Microsoft-Windows-WinQuic - legacy QUIC driver is NOT QUIC 1.0 (RFC 9000) compliant and will not work with SMB over QUIC
	'{F40AF494-46C8-464A-BDAC-47D9BD57E7D1}' # MsQuicTraceLogProvider
	'{620FD025-BE51-42EF-A5C0-50F13F183AD9}' # quicGUID
)

$NET_QoSProviders = @(
	'{914ED502-B70D-4ADD-B758-95692854F8A3}' # Microsoft-Windows-QoS-Pacer
	'{725BA9B3-C1F3-4518-AF1B-C8D669191E15}' # QOSWMI
	'{FFF596F3-F3D8-4F81-912C-AF7D01AEE98D}' # NetworkQoSPolicy
	'{6BA132C4-DA49-415B-A7F4-31870DC9FE25}' # Microsoft-Windows-QoS-qWAVE
	'{54CB22FF-26B4-4393-A8C2-6B0715912C5F}' # Microsoft-Windows-EQoS
	'{65D341F3-BAAA-4C6E-8B20-23D4F1574004}' # Microsoft-Windows-Eqos-SQM-Provider
)

$NET_RadioManagerProviders = @(	#AirPlane Mode 
	'{92061E3D-21CD-45BC-A3DF-0E8AE5E8580A}' # Microsoft-Windows-RadioManager
	'{E46B2BFB-824E-4262-84B5-8CB29C169FC6}' # HIDRADIO
	'{1EE4093E-D437-4847-8312-ACFC2F05E6EC}' # RMAPI
	'{38265D1C-6C72-4697-847B-CE511F999DCF}' # SHHWDTCT
)

$NET_RAmgmtProviders = @(
	'{6B510852-3583-4E2D-AFFE-A67F9F223438}' # Security: Kerberos Authentication
	'{62DFF3DA-7513-4FCA-BC73-25B111FBB1DB}' # CtlGuid
	'{AAD4C46D-56DE-4F98-BDA2-B5EAEBDD2B04}' # CtlGuid
)

$NET_RASProviders = @( 
	#'{B40AEF77-892A-46F9-9109-438E399BB894}' # AFD Trace
	#'{0C478C5B-0351-41B1-8C58-4A6737DA32E3}' # Microsoft-Windows-WFP
	'{E1F65B93-F32A-4ED6-AA72-B039E28F1574}' # wlbs / NLB Standard Trace
	'{F498B9F5-9E67-446A-B9B8-1442FFAEF434}' # NLB Packet Trace
	'{4EDBE902-9ED3-4CF0-93E8-B8B5FA920299}' # Microsoft-Windows-TunnelDriver
	'{B9F181E1-E221-43C6-9EE4-7F561315472F}' # VpnProfile
	'{53254D45-6DBF-4089-9FAE-CABFCAF50552}' # RRAS IP Fltrdrvr
	'{4214DCD2-7C33-4F74-9898-719CCCEEC20F}' # Microsoft-Windows-TunnelDriver-SQM-Provider
)

$NET_RasManProviders = @(
	'{7794A8F9-8482-4396-AA2C-2AB8EF51B6B0}' # Microsoft.Windows.Networking.RAS.Manager
	'{542F2110-2C0F-40D7-AA35-3309FE74B8AE}' # Microsoft.Windows.Networking.VPNPlugin.Manager
	'{B9F181E1-E221-43C6-9EE4-7F561315472F}' # VpnProfile
	'{8B21F870-7815-4CF6-8491-6CC879D4CD01}' # Microsoft-WindowsPhone-CmCspVpnPlus
	'{79EEBE3E-AAB1-4639-94C8-05A1706A6417}' # Microsoft.Windows.Networking.RAS.Dialer
	'{C6F68DC2-8899-4011-B91F-817ADAD30372}' # Microsoft.Windows.Networking.RAS.MediaManager
	'{45902DE3-6D95-4A35-A37E-862215252640}' # Microsoft.Windows.Networking.VPNPlugin
)

$NET_RDMAProviders = @(
	'{A7C8D6F2-1088-484B-A516-1AE0C3BF8216}' # SchedWmiGuid
)

$NET_RPCProviders = @(
	'{6AD52B32-D609-4BE9-AE07-CE8DAE937E39}' # Microsoft-Windows-RPC
	'{D8975F88-7DDB-4ED0-91BF-3ADF48C48E0C}' # Microsoft-Windows-RPCSS
	'{F4AED7C7-A898-4627-B053-44A7CAA12FCD}' # Microsoft-Windows-RPC-Events
	'{536CAA1F-798D-4CDB-A987-05F79A9F457E}' # Microsoft-Windows-RPC-LBS
	'{879B2576-39D1-4C0F-80A4-CC086E02548C}' # Microsoft-Windows-RPC-Proxy
	'{272A979B-34B5-48EC-94F5-7225A59C85A0}' # Microsoft-Windows-RPC-Proxy-LBS
	'{F997CD11-0FC9-4AB4-ACBA-BC742A4C0DD3}' # Microsoft-Windows-RPC-FirewallManager
	'{92AAB24D-D9A9-4A60-9F94-201FED3E3E88}' # Microsoft-Windows-EndpointTriggerProvider
	'{6545939F-3398-411A-88B7-6A8914B8CEC7}' # Microsoft-Windows-ServiceTriggerPerfEventProvider
	'{b0ca1d82-539d-4fb0-944b-1620c6e86231}' # WMI EventLogTrace
)

$NET_RNDISProviders = @(
	'{CD079D47-329D-4DC5-881C-CB28BB80A9A0}' # NetworkVsc / netvsc
	'{3FF1D341-0EE4-4617-A924-79B1DAD316F2}' # VMSNETSETUPPLUGIN
)

# --- RDS ---
$NET_RDSHProviders = @(
	'{D33E545F-59C3-423F-9051-6DC4983393A8}!RDSH' 				# 
	'{0046a6b4-a24c-40d5-b0e6-c8ec031bd82a}!RDSH' 				# 
	'{40423FDC-C9EC-4D34-9E72-8DE793CDB22E}!RDSH!0xffffffff!0xf' # 
)
If(!($ParameterArray -contains 'RDSsrv')){ # ToDo: verify if this works
	$NET_RDSHProviders += @( 
		'{D2E990DA-8504-4702-A5E5-367FC2F823BF}!RDSH!0xffffffff!0xff' # 
		'{C0C89C53-DD3F-4782-00A7-8F537811A835}!RDSH!0xffffffff!0xff' # 
		'{557D257B-180E-4AAE-8F06-86C4E46E9D00}!RDSH!0xffffffff!0xf' #
		'{5283D5F6-65B5-425F-A30B-F16C057D6B57}!RDSH!0xffffffff!0xf' #
		'{40423FDC-C9EC-4D34-9E72-8DE793CDB22E}!RDSH!0xffffffff!0xf' #
		'{449E4E69-329E-4EB1-9DDF-809D17A2E0C1}!RDSH!0xffffffff!0xf' #
		'{986CC918-7434-4FAB-B37F-C4BA7AD1E293}!RDSH!0xffffffff!0xf' #
		'{9ed727c4-4ab6-4b66-92d7-2072e87c9124}!RDSH!0x1ff!0xf' 		#
		'{ae8ab061-654e-4d72-9f4b-c799ba919ec8}!RDSH!0x1ff!0xf' 		#
		'{9EA2030F-DB66-47EF-BF2C-619CC76F3E1B}!RDSH!0x1ff!0xf' 		#
		'{59de359d-ec83-445c-9323-b75e2056d5a5}!RDSH!0xffff!0xf' 	#
	)
}

$NET_RdsAuthProviders = @(
	'{6165F3E2-AE38-45D4-9B23-6B4818758BD9}!RdsAuth!0xffffffff!0xff' 	# 
	'{37D2C3CD-C5D4-4587-8531-4696C44244C8}!RdsAuth!0xffffffff!0xff' 	# 
	'{52BF9EC6-69F5-49E6-9ECC-D3B994C40142}!RdsAuth!0x1f!0xff' 			# 
	'{6B510852-3583-4E2D-AFFE-A67F9F223438}!RdsAuth!0x3fffffff!0xff' 	# 
	'{60A7AB7A-BC57-43E9-B78A-A1D516577AE3}!RdsAuth!0xffffff!0xff' 		# 
	'{FACB33C4-4513-4C38-AD1E-57C1F6828FC0}!RdsAuth!0xffffffff!0xff' 	# 
	'{97A38277-13C0-4394-A0B2-2A70B465D64F}!RdsAuth!0xff!0xff' 			# 
	'{5AF52B0D-E633-4EAD-828A-4B85B8DAAC2B}!RdsAuth!0xff!0xff' 			# 
	'{5BBB6C18-AA45-49B1-A15F-085F7ED0AA90}!RdsAuth!0x7ffff!0xff' 		# 
	'{D0B639E0-E650-4D1D-8F39-1580ADE72784}!RdsAuth!0x3ffffff!0xff' 	# 
)
$NET_RdsAuthManProviders = @(
	'{5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB}!RdsAuthMan!0x0!0xff' 		#
	'{98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1}!RdsAuthMan!0x0!0xff' 		# 
	'{AC43300D-5FCC-4800-8E99-1BD3F85F0320}!RdsAuthMan!0x0!0xff' 		# 
	'{91CC1150-71AA-47E2-AE18-C96E61736B6F}!RdsAuthMan!0x0!0xff' 		# 
	'{1f678132-5938-4686-9fdc-c8ff68f15c85}!RdsAuthMan!0x0!0xff' 		# 
)
$NET_RdsCoreProviders = @(
	'{D4199645-41BE-4FD5-9D73-A612C508FDC6}!RdsCore' #
	'{140C2428-F60D-43F9-9B07-3E5F622438A0}!RdsCore' #
	'{97e97a1e-c0a9-4b8d-87c4-42105a957d7b}!RdsCore' #
	'{C5615DDA-2DAC-479B-83AB-F18C95601774}!RdsCore' #
)
$NET_RdsRDclientProviders = @(
	'{DAA6CAF5-6678-43F8-A6FE-B40EE096E06E}!RdsRDclient' #
	'{0C51B20C-F755-48A8-8123-BF6DA2ADC727}!RdsRDclient' #
	'{936FF90C-7CC4-40d8-8A04-77B281C73AB9}!RdsRDclient' #
	'{70DB53D8-B6F3-428D-AA33-5B2CE56718C5}!RdsRDclient' #
	'{fac7fcce-62fc-4be0-bd67-311750b5bcff}!RdsRDclient' #
	'{D4197645-41DE-4ad5-9D71-A612C508FDD8}!RdsRDclient' #
)
$NET_RdsRDclientManProviders = @(
	'{28AA95BB-D444-4719-A36F-40462168127E}!RdsRDclientMan!0x0!0xff' 	#
	'{1B8B402D-78DC-46FB-BF71-46E64AEDF165}!RdsRDclientMan!0x0!0xff' 	#
	'{6E400999-5B82-475F-B800-CEF6FE361539}!RdsRDclientMan!0x0!0xff' 	#
)
$NET_RdsWRKSPCProviders = @(
	'{70A43AE8-E131-42BD-89E0-23704FB27C6A}!RdsWRKSPC!0xffffffff!0xf' 	#
	'{070f54b9-7eb0-4c99-8dfa-2aa8d8ab0d89}!RdsWRKSPC!0xffffffff!0xf' 	#
	'{3D3E7039-99CF-4446-8C81-4AD5A8560E7B}!RdsWRKSPC!0xffffffff!0xf' 	#
)

$NET_RdsHManProviders = @(
	'{5D896912-022D-40AA-A3A8-4FA5515C76D7}!RdsHMan!0x0!0xff' 		#
	'{27A8C1E2-EB19-463E-8424-B399DF27A216}!RdsHMan!0x0!0xff' 		#
	'{952773BF-C2B7-49BC-88F4-920744B82C43}!RdsHMan!0x0!0xff' 		#
	'{C76BAA63-AE81-421C-B425-340B4B24157F}!RdsHMan!0x0!0xff' 		#
	'{2184B5C9-1C83-4304-9C58-A9E76F718993}!RdsHMan!0x0!0xff' 		#
	'{4199EE71-D55D-47D7-9F57-34A1D5B2C904}!RdsHMan!0x0!0xff' 		#
	'{32817E55-7BFE-45E0-AF68-A413FA6E0083}!RdsHMan!0x0!0xff' 		#
	'{f1394de0-32c7-4a76-a6de-b245e48f4615}!RdsHMan!0x0!0xff' 		#
	'{1139c61b-b549-4251-8ed3-27250a1edec8}!RdsHMan!0x0!0xff' 		#
	'{741c6be3-f74b-4e4d-88e7-5ce3a35faeb3}!RdsHMan!0x0!0xff' 		#
	'{127e0dc5-e13b-4935-985e-78fd508b1d80}!RdsHMan!0x0!0xff' 		#
	'{8d83aec0-01de-4772-a317-2093b6dc3bab}!RdsHMan!0x0!0xff' 		#
	'{DCBE5AAA-16E2-457C-9337-366950045F0A}!RdsHMan!0x0!0xff' 		#
	'{6BA29EDF-A2F4-4212-B06B-6D5712210652}!RdsHMan!0xffffffff!0xf' #
)
$NET_RdsRAILProviders = @(
	'{C127C1A8-6CEB-11DA-8BDE-F66BAD1E3F3A}!RdsRAIL!0xffffffff!0xf' 	#
	'{BFA655DC-6C51-11DA-8BDE-F66BAD1E3F3A}!RdsRAIL!0xffffffff!0xf' 	#
)
$NET_RdsRDPDRProviders = @(
	'{73C5EC49-C807-489D-9E45-D36D72235F84}!RdsRDPDR!0xffffffff!0xf' 	#
	'{82A94E1C-C1B3-4E4A-AC87-43BD802E458E}!RdsRDPDR!0xffffffff!0xf' 	#
	'{73BFB78F-12B5-4738-A66C-A77BCD55FA12}!RdsRDPDR!0xffffffff!0xf' 	#
	'{600be610-f0e8-4912-b397-d2cc76060114}!RdsRDPDR!0xffffffff!0xf' 	#
)
$NET_RdsAudioProviders = @(
	'{5A966D1C-6B48-11DA-8BDE-F66BAD1E3F3A}!RdsAudio!0xffffffff!0xf' 	#
	'{e27950eb-1768-451f-96ac-cc4e14f6d3d0}!RdsAudio!0xffffffff!0xf' 	#
)
$NET_RdsVIPProviders = @(
	'{508371b1-7651-4b33-4b33-5884f824bd1b}!RdsVIP!0xffffffff!0xf' 	#
	'{AE4C5843-A9A3-4EB9-81F3-65D57D250180}!RdsVIP!0xffffffff!0xf' 	#
)
$NET_RdsRDMSProviders = @(
	'{1B9B72FC-678A-41C1-9365-824658F887E9}!RdsRDMS!0xffffffff!0xf' 	#
	'{9F58B00C-09C7-4cbc-8D19-969DCD5D5A6D}!RdsRDMS!0xffffffff!0xf' 	#
)
$NET_RdsRDMSManProviders = @(
	'{05da6b40-219e-4f17-92e6-d663fd87cba8}!RdsRDMSMan!0x0!0xff' 	#
	'{fb750ad9-8544-427f-b284-8ed9c6c221ae}!RdsRDMSMan!0x0!0xff' 	#
)
$NET_RdsRDPCLIPProviders = @(
	'{796F204A-44FC-47DF-8AE4-77C210BD5AF4}!RdsRDPCLIP' #
)
$NET_RdsPrintSpoolProviders = @(
	'{FCA72EBA-CBB3-467C-93BC-1DB4978C398D}!RdsPrintSpool!0xffffffff!0xf' # MXDC
)
$NET_RdsUsrLogonProviders = @(
	'{301779E2-227D-4FAF-AD44-664501302D03}!RdsUsrLogon' 			# 
	'{D451642C-63A6-11D7-9720-00B0D03E0347}!RdsUsrLogon' 			# 
	'{d9391d66-ee23-4568-b3fe-876580b31530}!RdsUsrLogon' 			# 
	'{A789EFEB-FC8A-4C55-8301-C2D443B933C0}!RdsUsrLogon' 			# 
	'{19D78D7D-476C-47B6-A484-285D1290A1F3}!RdsUsrLogon' 			# 
	'{C2BA06E2-F7CE-44AA-9E7E-62652CDEFE97}!RdsUsrLogon' 			# 
	'{d138f9a7-0013-46a6-adcc-a3ce6c46525f}!RdsUsrLogon' 			# 
	'{EB7428F5-AB1F-4322-A4CC-1F1A9B2C5E98}!RdsUsrLogon' 			# 
	'{2AC96968-C174-4cd5-A2E5-D86495DDB4F2}!RdsUsrLogon' 			# 
	'{D1D7D72D-00D5-4E56-8BAC-23FAC0F9ED4E}!RdsUsrLogon' 			# 
	'{CEC2553A-8961-4D34-92CA-AB2ECEF646C5}!RdsUsrLogon' 			# 
	'{012616AB-FF6D-4503-A6F0-EFFD0523ACE6}!RdsUsrLogon' 			# 
	'{A323CDC2-81B0-48B2-80C8-B749A221478A}!RdsUsrLogon' 			# 
	'{6B510852-3583-4E2D-AFFE-A67F9F223438}!RdsUsrLogon' 			#
	'{2955E23C-4E0B-45CA-A181-6EE442CA1FC0}!RdsUsrLogon!0x2f!0xff' 	#
	'{169CC90F-317A-4CFB-AF1C-25DB0B0BBE35}!RdsUsrLogon!0x2f!0xff' 	#
)
$NET_RdsUsrLogonManProviders = @(
	'{89B1E9F0-5AFF-44A6-9B44-0A07A7CE5845}!RdsUsrLogonMan!0x0!0xff' # 
	'{DB00DFB6-29F9-4A9C-9B3B-1F4F9E7D9770}!RdsUsrLogonMan!0x0!0xff' # 
	'{DBE9B383-7CF3-4331-91CC-A3CB16A3B538}!RdsUsrLogonMan!0x0!0xff' # 
	'{AEA1B4FA-97D1-45F2-A64C-4D69FFFD92C9}!RdsUsrLogonMan!0x0!0xff' # 
	'{63D2BB1D-E39A-41B8-9A3D-52DD06677588}!RdsUsrLogonMan!0x0!0xff' # 
)
$NET_RdsRDGWProviders = @(
	'{6F539394-F34F-45FD-B4CA-BD5C547B0BCB}!RdsRDGW' # 
	'{909ED641-D5EF-4299-B898-F13451A59F50}!RdsRDGW' # 
)
$NET_RdsRDGWManProviders = @(
	'{4D5AE6A1-C7C8-4E6D-B840-4D8080B42E1B}!RdsRDGWMan' # Microsoft-Windows-TerminalServices-Gateway
)
$NET_RdsBrokerProviders = @(
	'{C10870A3-617D-42E9-80C7-1C4BE2709E06}!RdsBroker!0xffffffff!0xf' # Connection Broker VDI/VM
	'{3C3E7089-99CF-4446-8D81-4AC5A8560E6A}!RdsBroker!0xffffffff!0xf' # Connection Broker VDI/VM
	'{FA801570-83A9-11DF-B3A9-8C26DFD72085}!RdsBroker!0xffff!0xff' 	  # Connection Broker Service DB Layer
)
$NET_RdsBrokerManProviders = @(
	'{D1737620-6A25-4BEF-B07B-AAC3DF44EFC9}!RdsBrokerMan' # Microsoft-Windows-TerminalServices-SessionBroker
	'{77B0D57B-97B8-4F42-83B0-4FDA12D3D79A}!RdsBrokerMan' # Microsoft-Windows-RemoteApp and Desktop Connection Management
)
$NET_RdsLserverProviders = @(
	'{A489F3D1-F149-4968-BDCE-4F7D93516DA8}!RdsLserver'	# License Service
)
$NET_RdsLserverManProviders = @(
	'{4D99F017-0EB1-4B52-8419-14AEBD13D770}!RdsLserverMan' # Microsoft-Windows-TerminalServices-Licensing
)

$NET_RDScommonProviders = @(
	$NET_RDSHProviders
	$NET_RdsAuthProviders
	$NET_RdsAuthManProviders
	$NET_RdsCoreProviders
) 
$NET_RDScliProviders = @(
	$NET_RdsRDclientProviders
	$NET_RdsRDclientManProviders
	$NET_RdsWRKSPCProviders
)
$NET_RDSsrvProviders = @(
	$NET_RdsHManProviders
	$NET_RdsRAILProviders
	$NET_RdsAudioProviders
	$NET_RdsRDPDRProviders
	$NET_RdsVIPProviders
	$NET_RdsRDMSProviders
	$NET_RdsRDMSManProviders
	$NET_RdsRDPCLIPProviders
	$NET_RdsPrintSpoolProviders
	$NET_RdsUsrLogonProviders
	$NET_RdsUsrLogonManProviders
	$NET_RdsRDGWProviders
	$NET_RdsRDGWManProviders
	$NET_RdsBrokerProviders
	$NET_RdsBrokerManProviders
	$NET_RdsLserverProviders
	$NET_RdsLserverManProviders
)

$NET_SMBCAProviders = @(
	'{17EFB9CE-8CAB-4F19-8B96-0D021D9C76F1}!SMB_CA' 				# CCFWmiGuid
	'{DB66EA65-B7BB-4CA9-8748-334CB5C32400}!SMB_CA!0xffffffff!0xFF' # Microsoft-Windows-SMBDirect
	'{62BC0382-07D2-4C2E-B2C8-3DE3ED67DF13}!SMB_CA!0x000003BF 0x7'	# SmbdTraceCtrlGuid
)

$NET_SMBcliBasicProviders = @(	#_# see also $NET_fskmProviders
	'{988C59C5-0A1C-45B6-A555-0C62276E327D}!SMBcliBasic!0x00000045!0x3' 	# smb20Evt #Microsoft-Windows-SMBClient
	'{DB66EA65-B7BB-4CA9-8748-334CB5C32400}!SMBcliBasic!0x4000000001F!0x4' 	# Microsoft-Windows-SMBDirect
	'{62BC0382-07D2-4C2E-B2C8-3DE3ED67DF13}!SMBcliBasic!0x000001BF!0x4' 	# SmbdTraceCtrlGuid
	'{f818ebb3-fbc4-4191-96d6-4e5c37c8a237}!SMBcliBasic!0x00000085!0x4' 	# mrxsmb
	'{e4ad554c-63b2-441b-9f86-fe66d8084963}!SMBcliBasic!0x00000004!0x4' 	# smb20
	'{20c46239-d059-4214-a11e-7d6769cbe020}!SMBcliBasic!0x07000706!0x4' 	# Microsoft-Windows-Remote-FileSystem-Log
)

$NET_dnsProviders = @(
	'{609151dd-04f5-4da7-974c-fc6947eaa323}!dns!0x00797fc0!0x7' 		# dnsapi
	'{f230b1d5-7dfd-4da7-a3a3-7e87b4b00ebf}!dns!0xffffffff!0x7' 		# dns
)
$NET_frProviders = @(
	'{2955e23c-4e0b-45ca-a181-6ee442ca1fc0}!fr!0x1f!0x4' 				# fr
	'{6b6c257f-5643-43e8-8e5a-c66343dbc650}!fr!0x0fffffff!0x7' 			# UstCommon
)
$NET_fskmProviders = @(
	'{20c46239-d059-4214-a11e-7d6769cbe020}!fskm!0x8fffffff!0x7' 		# Microsoft-Windows-Remote-FileSystem-Log csckm/dav/dfsc/mup/rdbss/smb  // verbose + If($global:OSVersion.Major -lt 10) // Flags=0xffff0f0 for (OS -ge 10)
	'{0086eae4-652e-4dc7-b58f-11fa44f927b4}!fskm!0xffffffff!0x5' 		# rdbss // changed from 0x4
	'{f818ebb3-fbc4-4191-96d6-4e5c37c8a237}!fskm!0xffffffff!0x4' 		# mrxsmb
	'{e4ad554c-63b2-441b-9f86-fe66d8084963}!fskm!0xffffffff!0x4' 		# smb20
	'{988C59C5-0A1C-45B6-A555-0C62276E327D}!fskm!0xc403c00003ff!0x4' 	# smb20Evt #Microsoft-Windows-SMBClient
	'{47eba62c-87e6-4564-9946-0dd4e361ed9b}!fskm!0xffffffff!0x4' 		# witnesscli
	'{17efb9ce-8cab-4f19-8b96-0d021d9c76f1}!fskm!0xffffffff!0x4' 		# ccffilter
	'{89d89015-c0df-414c-bc48-f50e114832bc}!fskm!0xffffffff!0x4' 		# cscservice
	'{791cd79c-65b5-48a3-804c-786048994f47}!fskm!0xffffffff!0x4' 		# fastsync
	'{d5418619-c167-44d9-bc36-765beb5d55f3}!fskm!0xffffffff!0x4' 		# dcluser
	'{1f8b121d-45b3-4022-a9fb-3857177a65c1}!fskm!0xffffffff!0x4' 		# peerdist
	'{355c2284-61cb-47bb-8407-4be72b5577b0}!fskm!0xffffffff!0x4' 		# nfsrdr
	'{6361F674-C2C0-4F6B-AE19-8C62F47AE3FB}!fskm!0xffffffff!0x4' 		# NfsClientGuid
	'{746A1133-BC1E-47c7-8C95-3D52C39114F9}!fskm!0xffffffff!0x4' 		# Microsoft-Windows-ServicesForNFS-Client
	'{1A870028-F191-4699-8473-6FCD299EAB77}!fskm!0xffffffffffffffff!0xff'		# Microsoft-Windows-Remotefs-Rdbss
	'{76334FD1-D9FD-4DB5-B554-D356BD7C58BE}!fskm!0xffffffffffffffff!0xff'		# Microsoft.Windows.SMB.MRXSMB10
	'{52134415-75C1-4DF9-9118-8B2BD00CC6E2}!fskm!0xffffffffffffffff!0xff'		# Microsoft.Windows.SMB.MRXSMB20
)

$NET_fsumProviders = @(
	'{361f227c-aa14-4d19-9007-0c8d1a8a541b}!fsum!0xffffffff!0x4' 		# cscnet
	'{0999b701-3e5d-4998-bc58-a775590a55d9}!fsum!0xffffffff!0x4' 		# cscdll
	'{19ee4cf9-5322-4843-b0d8-bab81be4e81e}!fsum!0xffffffff!0x4' 		# cscapi
	'{66418a2a-72af-4c1a-9c84-42f6865563bd}!fsum!0xffffffff!0x4' 		# cscui
	'{5e23b838-5b71-47e6-b123-6fe02ef573ef}!fsum!0xffffffff!0x4' 		# cscum
	'{91efb5a1-642d-42a4-9821-f15c73064fb5}!fsum!0xffffffff!0x4' 		# WebClnt
	'{81F307DB-F5FB-4C3E-9B9D-8B39A9CB6198}!fsum!0xffffffff!0x4' 		# LmhSvc
)
$NET_nbtProviders = @(
	'{bca7bd7f-b0bf-4051-99f4-03cfe79664c1}!nbt!0xffffffff!0x7' 		# nbtsmb
)
$NET_rpcxdrProviders = @(
	'{94b45058-6f59-4696-b6bc-b23b7768343d}!rpcxdr!0xffffffff!0x4' 		# rpcxdr
	'{53c16bac-175c-440b-a266-1e5d5f38313b}!rpcxdr!0xffffffff!0x4' 		# OncRpcXdrGuid
)
$NET_secProviders = @(
	'{6b510852-3583-4e2d-affe-a67f9f223438}!sec!0x43!0x7'				# kerberos
	'{5bbb6c18-aa45-49b1-a15f-085f7ed0aa90}!sec!0x15003!0x7'			# ntlm
	'{5af52b0d-e633-4ead-828a-4b85b8daac2b}!sec!0x73!0x7'				# negoexts
	'{2a6faf47-5449-4805-89a3-a504f3e221a6}!sec!0x1f3!0x7'				# pku2u
)

$NET_tcpProviders = @(
	'{eb004a05-9b1a-11d4-9123-0050047759bc}!tcp!0x1080!0x7' 			# tcp
)

$NET_SMBcliProviders = @(
	$NET_fskmProviders
	$NET_fsumProviders
	$NET_dnsProviders
	$NET_frProviders
	$NET_nbtProviders
	#$NET_NFScliProviders
	$NET_rpcxdrProviders
	$NET_secProviders
	$NET_tcpProviders
	$NET_QuicProviders													#  adding Quic #2022.08.16.0
)

$NET_srvProviders = @(
	'{3121cf5d-c5e6-4f37-be86-57083590c333}!srv!0xffffffff!0x4' 		# srvdl
	'{2744f0b7-8455-44f8-9b64-5f589f9d163a}!srv!0xffffffff!0x7' 		# srv2
	'{c0183094-fdc6-493f-a3e8-697224f83f6f}!srv!0xffffffff!0x7' 		# srvnet
	'{d8e0c67b-7d87-48b6-9290-42126e66faee}!srv!0xffffffff!0x7' 		# srvsvc
	'{D48CE617-33A2-4BC3-A5C7-11AA4F29619E}!srv!0x108403c0001fff!0x7'	# srvV2Evt
	'{c5a38574-9827-4c24-b8fb-d6635475566f}!srv!0xffffffff!0x7' 		# resumekeyfilter
	'{c73e561f-c5b4-4a82-9b63-34bde5718e61}!srv!0xffffffff!0x7' 		# witnesssvc
)
$NET_smbhashProviders = @(
	'{48be2803-12c0-4932-aa80-93372d5a9114}!smbhash!0xffffffff!0x7' 	# smbhash
)
$NET_srProviders = @(
	'{8e37fc9c-8656-46da-b40d-34d97a532d09}!sr!0xffffffff!0x7' 			# wvrfGuid #volume replication
	'{634af965-fe67-49cf-8268-af99f62d1a3e}!sr!0xffffffff!0x7' 			# wvrSvcGuid
	'{fadca505-ad5e-47a8-9047-b3888ba4a8fc}!sr!0xffffffff!0x7' 			# wvrCimprov
)
$NET_DFSnProviders = @(
	'{27246e9d-b4df-4f20-b969-736fa49ff6ff}!DFSn!0xffffffff!0x7' 		# DFSn / DfsFilter
)

$NET_csvfsProviders = @(
	'{d82dba12-8b70-49ee-b844-44d0885951d2}!csvfs!0xffff!0x5' 			# csvfs #Cluster
)
$NET_csvfltProviders = @(
	'{b421540c-1fc8-4c24-90cc-c5166e1de302}!csvflt!0xffff!0x5' 			# csvflt
)
$NET_csvvbusProviders = @(
	'{4e6177a5-c0a7-4d9b-a686-56ed5435a904}!csvvbus!0xffff!0x5' 		# csvvbus
)
$NET_csvnfltProviders = @(
	'{4e6177a5-c0a7-4d9b-a686-56ed5435a908}!csvnflt!0xffc3!0x5' 		# csvnflt
)
$NET_SMBsrvProviders = @(
	$NET_DFSnProviders
	$NET_srvProviders
	$NET_smbhashProviders
	$NET_NFSsrvProviders
	$NET_srProviders
	$NET_secProviders
	$NET_QuicProviders													#  adding Quic #2022.08.16.0
)
$NET_SMBProviders = @(
	$NET_SMBcliProviders
	$NET_SMBsrvProviders
)
$NET_SMBclusterProviders = @(
	$NET_csvfsProviders
	$NET_csvfltProviders
	$NET_csvvbusProviders
	$NET_csvnfltProviders
)

<# $NET_SdnNCProviders = @(
	'{6C28C7E5-331B-4437-9C69-5352A2F7F296}!NCvm_dv' 	# Microsoft.Windows.Hyper.V.VmsIf
	'{C651F5F6-1C0D-492E-8AE1-B4EFD7C9D503}!NCPerf' 	# Microsoft-Windows-Application Server-Applications
	'{3916d60d-9c9c-5fe9-75f2-bd8d15e4ed36}!NCnet_ovs' 	# 
	'{93E14AC2-289B-45B7-B654-DB51E293BF52}!NCdeploy' 	# Microsoft-Windows-NetworkController-Deployment
	'{2380c5ee-ab89-4d14-b2e6-142200cb703c}!NCslbha' 	# Microsoft-Windows-SoftwareLoadBalancer-HostPlugin
) #>

$NET_SNMPProviders = @(
	'{76661966-7798-48C4-AFC5-67BAA2E9A3FD}' # Microsoft-Windows-SNMP-Agent-Service
	'{F36F2AF0-F7F1-4457-87A4-AC15800CB512}' # Microsoft-Windows-SNMP-Evntagnt-Extension-Agent
)

$NET_SSTPProviders = @(
	'{FF5E7768-8EF5-48B1-9998-61FC841D124F}' # RRAS sstp
	'{1E81AD7A-603A-4C44-B3B6-C99BB22F13BF}' # Microsoft.Windows.Networking.RAS.Routing.SSTP
	'{6C260F2C-049A-43D8-BF4D-D350A4E6611A}' # Microsoft-Windows-RasSstp
	'{24989972-0967-4E21-A926-93854033638E}' # Microsoft-Windows-RRAS
)

$NET_TAPIProviders = @(
	'{8E0E93FB-76AD-42EE-8770-B9DFEA596F65}' # Print FaxSrv
)

$NET_TaskSchProviders = @(
 	'{077E5C98-2EF4-41D6-937B-465A791C682E}' # Microsoft-Windows-DesktopActivityBroker
 	'{6A187A25-2325-45F4-A928-B554329EBD51}' # Scheduler
 	'{047311A9-FA52-4A68-A1E4-4E289FBB8D17}' # TaskEng_JobCtlGuid
 	'{10FF35F4-901F-493F-B272-67AFB81008D4}' # UBPM
 	'{19043218-3029-4BE2-A6C1-B6763CECB3CC}' # EventAggregation
 	'{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}' # Microsoft-Windows-TaskScheduler
	 '{E8F90FE5-8C92-4146-A764-305AAF12B066}' # Microsoft-WindowsPhone-TaskScheduler
	 '{9E03F75A-BCBE-428A-8F3C-D46F2A444935}' # Microsoft-Windows-IdleTriggerProvider
	 '{F230D19A-5D93-47D9-A83F-53829EDFB8DF}' # Microsoft-Windows-TriggerEmulatorProvider
 	'{6966FE51-E224-4BAA-99BC-897B3ED3B823}' # Microsoft.Windows.BrokerBase
 	'{0657ADC1-9AE8-4E18-932D-E6079CDA5AB3}' # Microsoft-Windows-TimeBroker
 	'{E8109B99-3A2C-4961-AA83-D1A7A148ADA8}' # System/TimeBroker WPP
)

#$NET_TLSProviders = @(
#	'{37D2C3CD-C5D4-4587-8531-4696C44244C8}!Ssl!0x7fffffff!0xff'		# Ssl / Microsoft-Windows-CAPI2
#	'{A74EFE00-14BE-4ef9-9DA9-1484D5473304}!NcryptSslp!0x7fffffff!0xff' # NcryptSslp
#	'{1F678132-5938-4686-9FDC-C8FF68F15C85}!Schannel'					# Schannel
#	'{91CC1150-71AA-47E2-AE18-C96E61736B6F}!Schannel'					# Microsoft-Windows-Schannel-Events	
#	'{44492B72-A8E2-4F20-B0AE-F1D437657C92}!Schannel'					# Microsoft.Windows.Security.Schannel
#)

$NET_VMswitchProviders = @(
	'{67DC0D66-3695-47C0-9642-33F76F7BD7AD}' # Microsoft-Windows-Hyper-V-VmSwitch
	'{9F2660EA-CFE7-428F-9850-AECA612619B0}' # Microsoft-Windows-Hyper-V-VfpExt
	'{1F387CBC-6818-4530-9DB6-5F1058CD7E86}' # vmswitch
	'{C0DDAFB5-16EB-470B-BF17-24ED39A9E8BA}' # VmsNicProxy
	'{3B7922BB-C097-495D-BF47-D7003FD40A1A}' # VmsProxyCtrlGuid
)

$NET_VPNProviders = @(
	'{3C088E51-65BE-40D1-9B90-62BFEC076737}' # Microsoft-Windows-VPN-Client
	'{E5FC4A0F-7198-492F-9B0F-88FDCBFDED48}' # Microsoft-Windows Networking VPN Plugin Platform
	'{114c0ac9-df95-450f-b769-e9d85e783a64}' # CtlGuid
	'{39C9F48F-D244-45A8-842F-DC9FBC9B6E92}' # WindowsNetworkingVpn
	'{5F31090B-D990-4e91-B16D-46121D0255AA}' # EapPeer
	'{6349C0AC-E412-4894-8C32-F988181C00E5}' # VpnIkeApi
	'{8A40BA3E-4ECE-4df5-9BBB-B26B60AC983D}' # VpnExecEng
	'{8c895036-d65a-4865-9768-5b8778c30fc9}' # VpnProfile
	'{8FC438F1-00EF-4f07-B68E-08A9A9B55ADB}' # NcaApiServer / AdhApiServer
	'{96c46403-0dfc-4824-812c-bc6b582dd933}' # 
	'{A1EB8080-C13E-425C-8E9A-25D4749F9F86}' # VpnIke
	'{A487F25A-2C11-43B7-9050-527F0D6117F2}' # FWUtil/NcaUtil/AdhUtil/VpnUtil
	'{B9F181E1-E221-43C6-9EE4-7F561315472F}' # VpnProfile
	'{9CA335ED-C0A6-4B4D-B084-9C9B5143AFF0}' # Microsoft.Windows.Networking.DNS
	'{1540FF4C-3FD7-4BBA-9938-1D1BF31573A7}' # DNS Trace
	'{7D44233D-3055-4B9C-BA64-0D47CA40A232}' # Microsoft-Windows-WinHttp
	'{72B18662-744E-4A68-B816-8D562289A850}' # Windows HTTP Services
	'{B3A7698A-0C45-44DA-B73D-E181C9B5C8E6}' # WinHttp
	'{BA94F3F7-601D-4B72-B228-224206FC3293}' # WSDDSMPROXY
	'{272A979B-34B5-48EC-94F5-7225A59C85A0}' # Microsoft-Windows-RPC-Proxy-LBS
	'{879B2576-39D1-4C0F-80A4-CC086E02548C}' # Microsoft-Windows-RPC-Proxy
	'{59588B82-78EB-4E72-842C-370D62334AAE}' # WSDScPrx
	'{6D1E0446-6C52-4B85-840D-D2CB10AF5C63}' # WSDPrPxy
	'{ABE47285-C002-46D1-95E4-C4AEC3C78F50}' # WfdProvProxyCtlGuid
	'{B80A3EE8-4ECE-4df5-9BBB-B26B60AC983D}' # NcaApi/AdhApi/VpnApi
	#'{D84521F7-2235-4237-A7C0-14E3A9676286}' # Microsoft-Windows-Ras-NdisWanPacketCapture --> move to netsh packetcapture
	'{B40AEF77-892A-46F9-9109-438E399BB894}' # AFD Trace
)
 $NET_VPNProviders += $NET_WinInetProviders

$NET_WCMProviders = @(
	'{67D07935-283A-4791-8F8D-FA9117F3E6F2}' # Microsoft-Windows-Wcmsvc 
	'{499F891B-A7CE-48AD-A593-38BD85A73F41}' # WcmConfigSPControlGuid
	'{988CE33B-DDE5-44EB-9816-EE156B443FF1}' # WcmsvcCtlGuid
	'{B6A9C8BA-70DE-42E4-88DE-001A041B0768}' # Microsoft.Windows.ConnectionManager.WcmApi
	'{0616F7DD-722A-4DF1-B87A-414FA870D8B7}' # Microsoft.Windows.ConnectionManager
	'{D59ECDFB-4A73-4A02-9A72-2A201A80D238}' # CtlGuid
	'{538F38B5-23E0-4173-99DD-81255F680DDC}' # CtlGuid
	'{E5FC4A0F-7198-492F-9B0F-88FDCBFDED48}' # Microsoft-Windows Networking VPN Plugin Platform
	'{B9F181E1-E221-43C6-9EE4-7F561315472F}' # VpnProfile
	'{3A07E1BA-3A6B-49BF-8056-C105B54DD7FB}' # WwanControlGuid
)

$NET_WebClientProviders = $NET_SMBcliProviders

$NET_WebIOProviders = @(
	'{7D44233D-3055-4B9C-BA64-0D47CA40A232}' # Microsoft-Windows-WinHTTP
	'{50B3E73C-9370-461D-BB9F-26F32D68887D}' # Microsoft-Windows-WebIO
	'{08F93B14-1608-4A72-9CFA-457EECEDBBA7}' # WebIO
	'{B3A7698A-0C45-44DA-B73D-E181C9B5C8E6}' # WinHTTP
	'{72B18662-744E-4A68-B816-8D562289A850}' # Windows HTTP Services
)
 $NET_WebIOProviders += $NET_WinInetProviders
 
$NET_WFPProviders = @(
	'{0C478C5B-0351-41B1-8C58-4A6737DA32E3}!Wfp!0xffffffff' # Microsoft-Windows-WFP		# 0xffffffff for -StartAutologger
	'{4E7A902B-5E4E-5209-668D-86090D23E202}!Wfp!0xffffffff' # Microsoft.Windows.Networking.WFP
	'{AD33FA19-F2D2-46D1-8F4C-E3C3087E45AD}!Wfp!0xffffffff' # FWPKCLNT
	#'{106B464D-8043-46B1-8CB8-E92A0CD7A560}!Wfp!0xffffffff' # KernelFilterDriver
	'{5A1600D2-68E5-4DE7-BCF4-1C2D215FE0FE}!Wfp!0xffffffff' # FWPUCLNT
	'{92765247-03A9-4AE3-A575-B42264616E78}!Wfp!0xffffffff' # Microsoft-Windows-Base-Filtering-Engine-Resource-Flows
	#'{7B702970-90BC-4584-8B20-C0799086EE5A}!Wfp!0xffffffff' # Microsoft-Windows-NetworkSecurity
	'{121D3DA8-BAF1-4DCB-929F-2D4C9A47F7AB}!Wfp!0xffffffff' # Microsoft-Windows-Base-Filtering-Engine-Connections
	#'{C22D1B14-C242-49DE-9F17-1D76B8B9C458}!Wfp!0xffffffff' # Microsoft-Pef-WFP-MessageProvider
	#'{54732EE5-61CA-4727-9DA1-10BE5A4F773D}!Wfp!0xffffffff' # Microsoft-Windows-BfeTriggerProvider	#_# ToDo: re-enable? Error: Access is denied. Try running this command as an administrator.
	'{E53C6823-7BB8-44BB-90DC-3F86090D48A6}!Wfp!0xffffffff' # Microsoft-Windows-Winsock-AFD		# same as AfdTcpFull, but should be in same file
	'{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}!Wfp!0xffffffff' # Microsoft-Windows-TCPIP				# same as AfdTcpFull
	'{EB004A05-9B1A-11D4-9123-0050047759BC}!Wfp!0xffffffff' # NETIO								# same as AfdTcpFull
	'{106B464A-8043-46B1-8CB8-E92A0CD7A560}!Wfp!0xffffffff' # BaseFirewallEngine											# = NET_BFE
	'{D1BC9AFF-2ABF-4D71-9146-ECB2A986EB85}!Wfp!0xffffffff' # Microsoft-Windows-Windows Firewall With Advanced Security	# = NET_BFE
	'{49D6AD7B-52C4-4F79-A164-4DCD908391E4}!Wfp!0xffffffff' # NisDrvWFP Provider
)
if (!$global:StartAutologger.IsPresent) {
	$NET_WFPProviders += @( 
		'{2588030C-920E-4AD5-ACBF-8AA2CD761DDB}' # WfpLwfsWPPGuid 		#_# if "!_persistent!" equ "0"
		'{84A119DA-9DFB-4876-A6E5-BEFA4194DBF4}' # UMStream				#_# if "!_persistent!" equ "0"
	)
} 

$NET_WinLogonProviders = @(
	'{DBE9B383-7CF3-4331-91CC-A3CB16A3B538}' # Microsoft-Windows-Winlogon
	'{D451642C-63A6-11D7-9720-00B0D03E0347}' # WinLogon
	'{D9391D66-EE23-4568-B3FE-876580B31530}' # StateMachine
	'{855ED56A-6120-4564-B083-34CB9D598A22}' # SetupLib
	'{D138F9A7-0013-46A6-ADCC-A3CE6C46525F}' # WMsgSrv
	'{63665931-A4EE-47B3-874D-5155A5CFB415}' # AuthzTraceProvider
	'{C127C1A8-6CEB-11DA-8BDE-F66BAD1E3F3A}' # TSRdpInitTrace
	'{BFA655DC-6C51-11DA-8BDE-F66BAD1E3F3A}' # TSRDPShellTrace
	'{301779E2-227D-4FAF-AD44-664501302D03}' # WlClNtfy
	'{19D78D7D-476C-47B6-A484-285D1290A1F3}' # SysNtfy
	'{A789EFEB-FC8A-4C55-8301-C2D443B933C0}' # UmsHlpr
	'{C2BA06E2-F7CE-44AA-9E7E-62652CDEFE97}' # WinInit
	'{63D2BB1D-E39A-41B8-9A3D-52DD06677588}' # Microsoft-Windows-Shell-AuthUI
	'{169CC90F-317A-4cfb-AF1C-25DB0B0BBE35}' # 
)

$NET_WinNATProviders = @(
	'{66C07ECD-6667-43FC-93F8-05CF07F446EC}' # Microsoft-Windows-WinNat
	'{A6F32731-9A38-4159-A220-3D9B7FC5FE5D}' # Microsoft-Windows-SharedAccess_NAT
	'{AA7387CF-3639-496A-B3BF-DC1E79A6fc5A}' # WIN NAT WPP
	'{AE3F6C6D-BF2A-4291-9D07-59E661274EE3}' # IP NAT WPP
)

$NET_WinRMProviders = @(
	'{A7975C8F-AC13-49F1-87DA-5A984A4AB417}' # Microsoft-Windows-WinRM
	'{04C6E16D-B99F-4A3A-9B3E-B8325BBC781E}' # Windows Remote Management Trace - WinRM(WPP)
)


$NET_WinsockProviders = @(
	'{D5C25F9A-4D47-493E-9184-40DD397A004D}!Winsock!0xFFFFFFFFFFFFFFFF!0x5' # Microsoft-Windows-Winsock-WS2HELP
	'{093DA50C-0BB9-4D7D-B95C-3BB9FCDA5EE8}!Winsock!0xFFFFFFFFFFFFFFFF!0x5' # Microsoft-Windows-Winsock-SQM
	'{55404E71-4DB9-4DEB-A5F5-8F86E46DDE56}!Winsock!0xFFFFFFFFFFFFFFFF!0x5' # Microsoft-Windows-Winsock-NameResolution
	'{196A230F-7C17-4019-B2D9-71862D8F48C9}!Winsock!0xFFFFFFFFFFFFFFFF!0x5' # NamingShimGeneral
	'{EBAD5978-C172-4AD7-A2FB-1DBD779684A5}!Winsock!0xFFFFFFFFFFFFFFFF!0x5' # NamingStubGeneral
	'{4E887BED-1002-41E4-BA74-5AAF7C0EBC68}!Winsock!0xFFFFFFFFFFFFFFFF!0x5' # NamingProvGeneral
	'{C8F7689F-3692-4D66-B0C0-9536D21082C9}!Winsock!0xFFFFFFFFFFFFFFFF!0x5' # Microsoft-Windows-Tcpip-SQM-Provider
	'{1D44957B-7181-4835-B70A-D0B16112A4DE}!Winsock!0xFFFFFFFFFFFFFFFF!0x5' # winsock2 CtlGuid
	#_#'{9B307223-4E4D-4BF5-9BE8-995CD8E7420B}!Winsock!0xFFFFFFFFFFFFFFFF!0x5' # Microsoft-Windows-NetworkManagerTriggerProvider #_# Access is Denied
	#'{B40AEF77-892A-46F9-9109-438E399BB894}!Winsock!0xFFFFFFFFFFFFFFFF!0x5' # AFD Trace
	#'{064F02D0-A6C4-4924-841A-F3BADC2675F6}!Winsock!0xFFFFFFFFFFFFFFFF!0x5' # NDIS Trace Provider
)

$NET_WIPProviders = @(
	'{77FE4532-3F5C-5786-632B-FB3201BCE29B}!AppLocker!0xFFFFFFFFFFFFFFFF!0x5'			# ToDo:
	#'{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}!TcpIp!0x80007fff000000ff' 		# Microsoft-Windows-TCPIP 
	#'{EB004A05-9B1A-11D4-9123-0050047759BC}!NetIoBasic!0x800000000003ffff' 	# NETIO
)

$NET_WmbClassProviders = @(
	'{C5AA495B-8432-4DE5-9D7C-8AFC7D3B522A}' # WMBCLASS
	'{12D25187-6C0D-4783-AD3A-84CAA135ACFD}' # Microsoft-Windows-wmbclass
	'{A42FE227-A7BF-4483-A502-6BCDA428CD96}' # Microsoft-Windows-Wmbclass-Opn"
	'{31463556-E3F6-4DDB-9ECE-7BF5B8339C6F}' # Microsoft.Windows.CellCore.MobileBroadband.WMBClass
	'{6C0EBBBB-C292-457D-9675-DFCC1C0D58B0}' # PnpTraceLoggingEventHandleCore
	'{C8BDE9FF-F31F-59DC-6C27-CA37C516ADA5}' # PnpTraceLoggingConfigHandle
	'{0E0FE12B-E926-44D2-8CF1-8A62A6D44036}' # PROVIDER_NAME_DRVSTORE
	'{139299BB-9394-5058-DD33-9422E5903FC3}' # PROVIDER_NAME_SETUPAPI
	'{B3EEE223-D0A9-40CD-ADFC-50F1888138AB}' # Microsoft-Windows-WWAN-NDISUIO-EVENTS 
	'{D086235D-48B9-4E49-ADED-5304BF8F636D}' # WwanProtoControlGuid
	'{6CC2405D-817F-4886-886F-D5D1643210F0}' # Microsoft-Windows-NetAdapterCim-Diag
	'{3A07E1BA-3A6B-49BF-8056-C105B54DD7FB}' # WwanControlGuid
	'{9C205A39-1250-487D-ABD7-E831C6290539}' # Microsoft-Windows-Kernel-PnP
)
	
#$NET_WMIProviders = @(	# replaced with UEX_WMI

$NET_WMIadminProviders = @(
	'{1EDEEE53-0AFE-4609-B846-D8C0B2075B1F}' # Microsoft-Windows-WMI
	'{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}' # Microsoft-Windows-WMI-Activity
	'{224DB5A0-BE14-4BC2-8A6A-CBEC1E24E0BE}' # WMIEventLogProvider
	'{1FF6B227-2CA7-40F9-9A66-980EADAA602E}' # WMI_Tracing_Guid WBEMCOMM
)
$NET_WMIadminProviders += $NET_WinRMProviders

$NET_WNVProviders = @(
	'{0C885E0D-6EB6-476C-A048-2457EED3A5C1}' # Microsoft-Windows-Host-Network-Service
	'{0C478C5B-0351-41B1-8C58-4A6737DA32E3}' # Microsoft-Windows-Wfp
	'{3AD15A04-74F1-4DCA-B226-AFF89085A05A}' # Microsoft-Windows-Wnv
	'{6066F867-7CA1-4418-85FD-36E3F9C0600C}' # Microsoft-Windows-Hyper-V-VMMS
	'{6C28C7E5-331B-4437-9C69-5352A2F7F296}' # Microsoft.Windows.Hyper.V.VmsIf
	'{A67075C2-3E39-4109-B6CD-6D750058A731}' # Microsoft-Windows-NetworkBridge
	'{B72C6994-9FE0-45AD-83B3-8F5885F20E0E}' # Microsoft-Windows-MsLbfoEventProvider
	'{66C07ECD-6667-43FC-93F8-05CF07F446EC}' # Microsoft-Windows-WinNat
	'{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}' # Microsoft-Windows-Kernel-Process
	'{A111F1C0-5923-47C0-9A68-D0BAFB577901}' # NETSETUP
	'{66A5C15C-4F8E-4044-BF6E-71D896038977}' # Microsoft-Windows-Iphlpsvc
	'{6600E712-C3B6-44A2-8A48-935C511F28C8}' # Microsoft-Windows-Iphlpsvc-Trace
)

$NET_WSManProviders = @(
	'{c0a36be8-a515-4cfa-b2b6-2676366efff7}' # 
	'{f1cab2c0-8beb-4fa2-90e1-8f17e0acdd5d}' # RemoteShellClient
	'{03992646-3dfe-4477-80e3-85936ace7abb}' # RemoteShell
	'{651d672b-e11f-41b7-add3-c2f6a4023672}' # IPMI Provider Trace
	'{D5C6A3E9-FA9C-434e-9653-165B4FC869E4}' # IPMI Driver Trace
	'{6e1b64d7-d3be-4651-90fb-3583af89d7f1}' # 
	'{6FCDF39A-EF67-483D-A661-76D715C6B008}' # CtlGuid
)

$NET_WorkFoldersProviders = @(
	'{34A3697E-0F10-4E48-AF3C-F869B5BABEBB}' # Microsoft-Windows-WorkFolders
	'{111157cb-ee69-427f-8b4e-ef0feaeaeef2}' # 
	'{1284E99B-FF7A-405A-A60F-A46EC9FED1A7}' # MsfMdsESEControlGuid	# Todo: seperate into METL ? #_#
	'{C755EF4D-DE1C-4E7D-A10D-B8D1E26F5035}' #  #_#
	'{d8de3faf-8a2e-4a80-aedb-c86c7cc02a73}' # Windows Cloud Files (OneDrive) #_#
)

$NET_WWANProviders = $NET_MBNProviders	 # for TSS ver downlevel compat

$NET_ProxyProviders = @( # all Providers need to be defined already above
	$NET_AfdTcpBasicProviders
	$NET_NDISProviders
	$NET_NCSIProviders
	$NET_WebIOProviders
	$NET_WinsockProviders
)

$NET_AuthProviders = @( 
	$ADS_NetlogonProviders
	$ADS_NGCProviders
	$ADS_BioProviders
	$ADS_LSAProviders
	$ADS_NtLmCredSSPProviders
	$ADS_KerbProviders
	$ADS_SAMProviders
	$ADS_SSLProviders
	$ADS_CryptoDPAPIProviders
	$ADS_WebAuthProviders
	$ADS_SmartCardProviders
	$ADS_CredprovAuthuiProviders
)

#endregion --- ETW component trace Providers ---


#region --- Scenario definitions ---
$NET_ScenarioTraceList = [Ordered]@{
	"NET_802Dot1x"   = "PSR,SDP,Video,ProcMon, wired LAN 802.1x, Afd,TcpIp,NDIS,RadioManager,RASdiag,ADS_SSL,WCM ETL log(s), Netsh scenario=dot3_wpp,wireless_dbg; for WiFi wireless please choose WLAN"
	"NET_Auth"       = "PSR,SDP,ProcMon, ADS_AUTH + PerfMon DC, Netsh scenario=NetConnection"
	"NET_BITS"       = "PSR,SDP, Background Intelligent Transfer Service (BITS) client logs, Netsh scenario=InternetClient_dbg"
	"NET_Bluetooth"  = "PSR,SDP, Bluetooth client logs, Netsh scenario=InternetClient_dbg"
	"NET_BranchCache" = "PSR,SDP, BranchCache client logs, Firewall,GPresult, Netsh scenario=InternetClient_dbg"
	"NET_Capture"    = "PSR,SDP,Video, plain Netsh trace (packet capture)"
	"NET_Container"  = "Docker/Container/HNS ETL log(s), trace NetEventSession; -Mode <Swarm|Kube>"
	"NET_CSC"        = "PSR,SDP,Video,ProcMon, OfflineFiles infos, SMBcli, CSC database dump, Netsh scenario=NetConnection"
	"NET_DAcli"      = "PSR,SDP, DirectAccess client info,DA client config, WFPdiag, NCA, ADS_SSL, tss_DAclient-collector.ps1, scenario=DirectAccess,Netconnection"
	"NET_DAsrv"      = "PSR,SDP, DirectAccess Server RASdiag,WfpDiag ETL log(s), get netlogon.log, ADS_SSL, RAmgmt, Netsh scenario=DirectAcces,WFP-IPsec"
	"NET_DFScli"     = "PSR,SDP,ProcMon, DFS/SMBclient, RDR, GPresult, Netsh scenario=NetConnection"
	"NET_DFSsrv"     = "PSR,SDP,ProcMon, DFS Server ETL log(s) and Eventlog, Perfmon:SMB, Netsh scenario=NetConnection"
	"NET_DHCPcli"    = "PSR,SDP,Video,ProcMon, DHCP client ETL log(s), Netsh scenario=InternetClient_dbg"
	"NET_DHCPsrv"    = "PSR,SDP, DHCP Server Eventlog, ETL log(s) PsCmdlets 'netsh dhcp server' info, includes DNScli, Perfmon:NET, Netsh scenario=NetConnection"
	"NET_DNScli"     = "PSR,SDP, DNS client ETL log(s), Netsh scenario=InternetClient_dbg"
	"NET_DNSsrv"     = "PSR,SDP, DNS Server ETL log(s), Netsh scenario=NetConnection; can be used with -Mode Verbose"
	"NET_Docker"     = "PSR,SDP, Docker/Container/HNS ETL log(s), Netsh scenario=Virtualization"
	"NET_Firewall"   = "PSR,SDP,ProcMon, Firewall,NetProfM,WFP ETL log(s), Firewall REG settings and Eventlog, PktMon, Netsh scenario=InternetClient_dbg"
	"NET_General"    = "PSR,SDP,Video,ProcMon, General purpose logs, Netsh scenario=InternetClient_dbg"
	"NET_HypHost"    = "PSR, SDP:HyperV, LBFO,NDIS,VmSwitch,WinNAT,VMM,HyperV-Host,VMbus,Vmms,VmWp,VmConfig ETL log(s), VMM-debug, PerfMon:SMB, Netsh scenario=NetConnection"
	"NET_HypVM"      = "PSR,SDP, NDIS,HypVM,HyperV-VirtualMachine ETL log(s), Netsh scenario=InternetClient_dbg"
	"NET_IIS"        = "PSR,SDP, IIS Server logs, HttpSys ETL log(s), Netsh scenario=NetConnection"
	"NET_IPAM"       = "PSR,SDP, IPAM ETL log(s) and IPAM specific EventLogs, Netsh scenario=NetConnection"
	"NET_IPsec"      = "PSR,SDP,ProcMon, AfdTcpFull,IPsec,Firewall,WFP ETL log(s), WFPdiag,IKEEXT, Netsh scenario=InternetClient_dbg"
	"NET_MBN"        = "PSR,SDP,ProcMon, Mobile Broadband, AfdTcp,DNScli,MBN,NetworkUX,RadioManager,Rpc,WCM,WFP ETL log(s), WFPdiag, Netsh scenario= wcn_dbg,wwan_dbg; wireless_dbg can be added with -Mode Verbose"
	"NET_MDM"        = "PSR,SDP,Video,ProcMon, DeviceManagement, Netsh scenario=NetConnection"
	"NET_Miracast"   = "PSR,SDP,Video,ProcMon, Miracast or 'Wi-Fi Direct' ETL log(s), GPresult, WFPdiag, Netsh scenario=WirelessDisplay,wlan_dbg,netconnection"
	"NET_NCSI"       = "PSR,SDP,ProcMon, NCSI,NLA,NetProfM ETL log(s), GPresult, Netsh scenario= wireless_dbg,InternetClient_dbg"
	"NET_NETIO"      = "PSR,SDP, Afd,TcpIp,NetIO/NDIS ETL log(s), Netsh scenario=InternetClient_dbg"
	"NET_NetView"    = "PSR,SDP,ProcMon, NetView, PerfMon SMB, Netsh scenario=NetConnection"
	"NET_NFScli"     = "PSR,SDP,Video,ProcMon, NFS/SMBclient, GPresult,WhoAmI, Netsh scenario=NetConnection"
	"NET_NFSsrv"     = "PSR,SDP, NFS Server cmds PsCmdlets, ETL log(s) and EventLogs, Perfmon:NET, Netsh scenario=NetConnection; add '-Mode Permission' to collect NFS/NTFS permissions for shared folder and/or file"
	"NET_NLB"        = "PSR,SDP, Afd,TcpIp,NetIO,NLB ETL log(s), NLB/Diagnostic Events, WLBS display, msinfo32, Netsh scenario=NetConnection"
	"NET_NPS"        = "PSR,SDP, NPS RASdiag ETL log(s), netsh nps tracing, ADS_SSL, Securtiy EvtLog, Netsh scenario=NetConnection"
	"NET_Proxy"      = "PSR,SDP,Video,ProcMon, AfdTcpFull,NCSI,NDIS,WebIO,WinInet,WinHTTP,Winsock ETL log(s), Proxy settings and related Registry settings, Netsh scenario=wireless_dbg,InternetClient_dbg; consider .\BIN\WinHTTPDiag.exe /?"
	"NET_RAS"        = "PSR,SDP, Remote Access Server RASdiag,WFPdiag,IPfltdrv ETL log(s),IKEEXT, ADS_SSL, Perfmon:NET, Netsh scenario=VpnServer"
	"NET_RDMA"       = "PSR,SDP,ProcMon, SMBclient, SmbCA, RDMA ETL log(s), EventLogs, Netsh scenario=NetConnection, PerfMon ALL"
	"NET_RDScli"     = "PSR,SDP,Video, Remote Desktop (RDP) client ETL log(s), QWinSta, REG settings, Env-var, GPresult, EventLogs; consider collecting Security Eventlog"
	"NET_RDSsrv"     = "PSR,SDP, Remote Desktop (RDP) Server ETL log(s), QWinSta, REG settings, Env-var, GPresult, EventLogs incl. Security Eventlog; -Mode GetFarmdata ='collect Farmdata on RDS Server'"
	"NET_RPC"        = "PSR,SDP,ProcMon, RPC, RpcSs services and DCOM ETL log(s), Perfmon SMB, Netsh scenario=NetConnection"
	"NET_SBSL"       = "Slow Boot/Slow Logon: Profile,Netlogon,WinLogon,GPO GroupPolicy,DCLocator,GPresult,GPsvc,Auth ETL log(s), WhoAmI, -Xperf SBSLboot, Netsh scenario=NetConnection; for Boot use with -StartAutologger; def. XperfMaxFileMB=16384"
	"NET_SMB"        = "PSR,SDP,ProcMon, SMBclient, SMBserver, PerfMon SMB, Netsh scenario=NetConnection"
	"NET_SMBcli"     = "PSR,SDP,ProcMon, SMBclient, RDR, Netsh scenario=NetConnection"
	"NET_SMBsrv"     = "PSR,SDP,ProcMon, SMBserver, PerfMon SMB, Netsh scenario=NetConnection; add '-Mode Permission' to collect SMB/NTFS permissions permissions for shared folder and/or file"
	"NET_SQLtrace"   = "SQL Server related logs, PerfMon SQL, SDP SQLbase, Netsh scenario=NetConnection"
	"NET_VPN"        = "PSR,SDP,Video,ProcMon, Afd,TcpIp,NetIO,IPsec,RASdiag,VPN,WFP,WFPdiag ETL log(s), Netsh scenario=VpnClient_dbg, -Mode Basic will switch to scenario=VPNclient"
	"NET_UNChard"    = "PSR,SDP,Video,ProcMon, UNC-hardening: Profile,Netlogon,WinLogon,GPO GroupPolicy,DCLocator,GPresult,GPsvc,Auth ETL log(s), Netsh trace"
	"NET_WebClient"  = "PSR,SDP,Video,ProcMon, WebClient logs, SMBcli,WebIO,ADS_SSL ETL log(s), GPresult, Proxy, Netsh scenario=NetConnection, for restarting WebClient service, use -Mode Restart"
	"NET_WebCliTTD"  = "PSR,SDP,Video,ProcMon, WebClient logs, SMBcli,WebIO,ADS_SSL ETL log(s), GPresult, Proxy, Netsh scenario=NetConnection, for restarting WebClient service, use -Mode Restart, for downlevel OS use TSSv2_TTD.zip"
	"NET_WebIO"      = "PSR,SDP,ProcMon, WinInet,WinHTTP,WebIO ETL log(s), PerfMon SMB, Netsh scenario=InternetClient_dbg"
	"NET_WFP"        = "PSR,SDP,ProcMon, Afd,TcpIp,NetIO,IPsec,WFP Windows Filtering Platform,BFE (Base Filtering Engine) ETL log(s), WFPdiag,IKEEXT, Netsh scenario=InternetClient_dbg"
	"NET_WIP"        = "PSR,SDP,Video,ProcMon, AppLocker,Firewall,WFP ETL log(s), WFPdiag, Windows Information Protection, WhoAmI, WPR WIP_WprProfile, Netsh scenario=InternetClient_dbg"
	"NET_Winsock"    = "PSR,SDP,Video,ProcMon, Afd,TcpIp,NetIO,NDIS,Winsock ETL log(s), Netsh scenario=NetConnection"
	"NET_WLAN"       = "PSR,SDP,Video,ProcMon, WiFi wireless 802.1x ,Afd,TcpIp,NDIS,NetworkUX,RadioManager,RASdiag,ADS_SSL,WCM ETL log(s), Netsh scenario=dot3_wpp,wireless_dbg"
	"NET_WNV"        = "PSR,SDP, Network Virtualization (WNV) ETL log(s), Afd,TcpIp,LBFo,NCHA,VmSwitch, Netsh scenario=Virtualization,InternetClient"
	"NET_Workfolders" = "PSR,SDP,Video, WorkFolders,WinHTTPsys ETL log(s) on Server and Client, Perfmon ALL, Netsh scenario=NetConnection; add '-Mode Advanced' to restart service"
}

# Scenario trace
# by default, we are adding PSR and NetSH or NetshScenario to all NET scenarios

$NET_802Dot1x_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_AfdTcpFull' = $true
	'NET_NDIS' = $true
	'NET_RadioManager' = $true
	'ADS_SSL' = $true
	'NET_WCM' = $true
	'NET_NetworkUX' = $true
	'CommonTask NET' = $True 
	'NetshScenario dot3_wpp,wireless_dbg globallevel=0xff provider="Microsoft-Windows-CAPI2"' = $true
	'RASdiag' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
$NET_WLAN_ETWTracingSwitchesStatus = $NET_802Dot1x_ETWTracingSwitchesStatus
# $NET_WLAN_ETWTracingSwitchesStatus.add('NET_NetworkUX',"$True")

#NET_Auth Scenario
$NET_Auth_ETWTracingSwitchesStatus = [Ordered]@{
	'ADS_Netlogon' = $true
	'ADS_NGC' = $true 
	'ADS_Bio' = $true 
	'ADS_LSA' = $true 
	'ADS_NtLmCredSSP' = $true 
	'ADS_Kerb' = $true 
	'ADS_SAM' = $true 
	'ADS_SSL' = $true 
	'ADS_CryptoDPAPI' = $true 
	'ADS_WebAuth' = $true 
	'ADS_SmartCard' = $true 
	'ADS_CredprovAuthui' = $true 
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'Procmon' = $true
	'PSR' = $true
	#'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
	switch ($global:ProductType)
	{
		"WinNT" {
			#$NET_Auth_ETWTracingSwitchesStatus.add('ADS_kernel',"$True")			#_# will produce ERROR
			#$NET_Auth_ETWTracingSwitchesStatus.add('ADS_NTKernelLogger',"$True")	#_# will produce ERROR
			$NET_Auth_ETWTracingSwitchesStatus.add('PerfMon SMB',"$True")
		}
		"ServerNT" {
			$NET_Auth_ETWTracingSwitchesStatus.add('PerfMon SMB',"$True")
		}
		"LanmanNT" {
			$NET_Auth_ETWTracingSwitchesStatus.add('ADS_KDC',"$True")	#only for KDC/LanmanNT
			$NET_Auth_ETWTracingSwitchesStatus.add('PerfMon DC',"$True")
		}
		Default {
			$NET_Auth_ETWTracingSwitchesStatus.add('PerfMon SMB',"$True")
		}
	}

$NET_BITS_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_BITS' = $true
	'CommonTask NET' = $True 
	'NetshScenario InternetClient_dbg' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

$NET_Bluetooth_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_Bluetooth' = $true
	'CommonTask NET' = $True 
	'NetshScenario InternetClient_dbg' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

$NET_BranchCache_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_BranchCache' = $true
	'NET_BITS' = $true
	'NET_Firewall' = $true
	'ADS_SSL' = $true
	'CommonTask NET' = $True 
	'NetshScenario InternetClient_dbg' = $true
	'PerfMon BC' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

$NET_Capture_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_Dummy' = $true
	'Netsh' = $true
	#'NetshScenario NetConnection' = $true	# workaround for #362
	'PSR' = $true
	'Video' = $true
	#'SDP NET' = $True
	'xray' = $True
	'noBasicLog' = $True
	'CollectComponentLog' = $True
 }

$NET_DAcli_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_DAcli' = $true
	'NET_CAPI' = $true
	'NET_DNScli' = $true
	'NET_NCA' = $true
	'ADS_SSL' = $true
	'CommonTask NET' = $True 
	'NetshScenario DirectAccess,WFP-IPsec,Netconnection' = $true
	'WFPdiag' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 
 $NET_DAsrv_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_AfdTcpFull' = $true
	'NET_NDIS' = $true
	'NET_Netlogon' = $true
	'NET_DAsrv' = $true
	'NET_DAcli' = $true
	'NET_DAmgmt' = $true
	'NET_RAmgmt' = $true
	'NET_WMIadmin' = $true
	'NET_LDAPcli' = $true
	'ADS_SSL' = $true
	'NET_WFP' = $true
	'NET_WinNAT' = $true
	'CommonTask NET' = $True 
	'NetshScenario DirectAccess,WFP-IPsec' = $true
	'RASdiag' = $true
	'WFPdiag' = $true
	'Procmon' = $true
	'PSR' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

$NET_DHCPcli_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_DHCPcli' = $true
	'NET_DNScli' = $true
	'CommonTask NET' = $True
	'NetshScenario InternetClient_dbg' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

$NET_DHCPsrv_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_DHCPsrv' = $true
	'NET_DNScli' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'PerfMon NET' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
$NET_DNScli_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_DNScli' = $true
	'NET_DCLocator' = $true
	'CommonTask NET' = $True 
	'NetshScenario InternetClient_dbg' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

$NET_DNSsrv_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_DNSsrv' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	#'Procmon' = $true
	'PerfMon NET' = $true
	'PSR' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

$NET_Docker_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_AfdTcpFull' = $true
	'NET_Docker' = $true
	'NET_HNS' = $true
	'NET_VMswitch' = $true
	'NET_WFP' = $true
	'NET_WinNAT' = $true
	'CommonTask NET' = $True 
	#'NetshScenario Virtualization capturetype=both' = $true
	'Procmon' = $true
	#'PerfMon NET' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 If($IsServerSKU -and (Get-WindowsFeature | Where-Object {($_.Name -eq "Hyper-V") -and ($_.installed -eq $true)}) ){
	$NET_Docker_ETWTracingSwitchesStatus.add('NetshScenario Virtualization capturetype=both',"$True")
 }
 else {
	$NET_Docker_ETWTracingSwitchesStatus.add('NetshScenario NetConnection',"$True")
 }
 
$NET_Container_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_Container' = $true
	#'CommonTask NET' = $True 
	#'Procmon' = $true
	#'PerfMon NET' = $true
	#'PSR' = $true
	#'Video' = $true
	#'SDP NET' = $True
	'CollectComponentLog' = $True
 }
 
 $NET_Firewall_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_BFE' = $true
	'NET_Firewall' = $true
	'NET_NetProfM' = $true
	'NET_WFP' = $true
	'CommonTask NET' = $True 
	'NetshScenario InternetClient_dbg' = $true
	'WFPdiag' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 If ($global:OSVersion.Build -ge 17763) { $NET_Firewall_ETWTracingSwitchesStatus.add('PktMon',"$True") }
 
$NET_General_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_Dummy' = $true
	'CommonTask NET' = $True  ## <------ the commontask can take one of "Dev", "NET", "ADS", "UEX", "DnD" and "SHA", or "Full" or "Mini"
	'NetshScenario InternetClient_dbg' = $true
	'Procmon' = $true
	#'WPR memory' = $true
	#'PerfMon SMB' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
  
$NET_HypHost_ETWTracingSwitchesStatus = [Ordered]@{
	'SHA_HypVMBus' = $true
	'SHA_HypVmms' = $true
	'SHA_HypVmWp' = $true
	'SHA_VMM' = $true
	'SHA_VmConfig' = $true
	'NET_LBFo' = $true	# now with #636 includes NDIS
	'NET_NDIS' = $true
	'NET_VmSwitch' = $true
	'NET_WinNAT' = $true
	#'NET_SMBcli' = $true	# consider removing? Commented out by muratka on 25th May
	#'NET_SMBsrv' = $true	# consider removing? Commented out by muratka on 25th May
	'NET_AfdTcpFull' = $True # added by muratka on 25th May
	'CommonTask NET' = $True 
	'NetshScenario NetConnection,Virtualization capturetype=both correlation=disabled' = $true
	'PerfMon SMB' = $true
	'PSR' = $true
	'SDP HyperV' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 
 $NET_HypVM_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_HypVM' = $true
	'NET_NDIS' = $true
	'CommonTask NET' = $True 
	'NetshScenario InternetClient_dbg' = $true
	'PSR' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 
$NET_IIS_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_HttpSys' = $true
	'ADS_SSL' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

$NET_IPAM_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_IPAM' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'PSR' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 
 $NET_IPsec_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_AfdTcpFull' = $true
	'NET_IPsec' = $true
	'NET_Firewall' = $true
	'NET_WFP' = $true
	'WFPdiag' = $true 
	'CommonTask NET' = $True 
	'NetshScenario InternetClient_dbg' = $true
	'Procmon' = $true
	'PSR' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

$NET_MBN_ETWTracingSwitchesStatus = [Ordered]@{   
	#'NET_AfdTcpFull' = $true
	'NET_DNScli' = $true
	'NET_MBN' = $true
	'NET_NetworkUX' = $true
	'NET_Rpc' = $true
	'NET_RadioManager' = $true
	'NET_WCM' = $true
	'NET_WFP' = $true
	'NET_WmbClass' = $true
	'CommonTask NET' = $True 
	#'NetshScenario wcn_dbg,wwan_dbg,wireless_dbg' = $true
	'WFPdiag' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 if ($global:Mode -iMatch "Verbose") {
	$NET_MBN_ETWTracingSwitchesStatus.add('NetshScenario wcn_dbg,wwan_dbg,wireless_dbg',"$True") 
 } else {
	$NET_MBN_ETWTracingSwitchesStatus.add('NetshScenario wcn_dbg,wwan_dbg',"$True") 
 }

$NET_MDM_ETWTracingSwitchesStatus = [Ordered]@{   
	#'NET_MDM' = $True	# ToDo: should work now, if (only) -Scenario NET_MDM is invoked
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $True
	'Procmon' = $True
	'PSR' = $True
	'Video' = $True
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 
$NET_Miracast_ETWTracingSwitchesStatus = [Ordered]@{ #- \\gesoem\team\betatracing\miracast.zip 
	'NET_Miracast' = $true
	'CommonTask NET' = $True 
	'WFPdiag' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 if ($global:OSVersion.Build -ge 10586) {
	$NET_Miracast_ETWTracingSwitchesStatus['NetshScenario WirelessDisplay,wlan_dbg,netconnection'] = $true
 } else {
	$NET_Miracast_ETWTracingSwitchesStatus['NetshScenario wlan_dbg,netconnection'] = $true
 }

$NET_NCSI_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_NCSI' = $true
	'NET_NetProfM' = $true
	'CommonTask NET' = $True 
	'NetshScenario wireless_dbg,InternetClient_dbg provider=Microsoft-Windows-PrimaryNetworkIcon provider={1701C7DC-045C-45C0-8CD6-4D42E3BBF387}' = $true
	'WFPdiag' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 
$NET_NETIO_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_AfdTcpFull' = $true
	#'NET_NETIO' = $true
	'NET_NDIS' = $true
	'CommonTask NET' = $True 
	'NetshScenario InternetClient_dbg' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
 }

$NET_Netview_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_Dummy' = $true
	#'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'Procmon' = $true
	'PerfMon SMB' = $true
	'PSR' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

$NET_NLB_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_AfdTcpFull' = $true
	'NET_NLB' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	#'Procmon' = $true
	'PSR' = $true
	#'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

$NET_NPS_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_NPS' = $true
	'NET_LDAPcli' = $true
	'NET_Netlogon' = $true
	'ADS_SSL' = $true
	'NET_WFP' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'RASdiag' = $true
	'WFPdiag' = $true
	#'Procmon' = $true
	'PSR' = $true
	#'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }



$NET_Proxy_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_AfdTcpFull' = $true
	'NET_NDIS' = $true
	'NET_WebIO' = $true
	'NET_Winsock' = $true
	'NET_NCSI' = $true
	'CommonTask NET' = $True 
	'NetshScenario wireless_dbg,InternetClient_dbg provider=Microsoft-Windows-PrimaryNetworkIcon' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

$NET_RAS_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_AfdTcpFull' = $true
	#'NET_NetIO' = $true
	'ADS_SSL' = $true
	'NET_WFP' = $true
	'CommonTask NET' = $True 
	'NetshScenario VpnServer' = $true
	'RASdiag' = $true
	'WFPdiag' = $true
	'Procmon' = $true
	'PerfMon NET' = $true
	'PSR' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
if ($global:Mode -iMatch "Hang") {
	$NET_RAS_ETWTracingSwitchesStatus['ProcDump RaMgmtui.exe,Rasman,RemoteAccess,RaMgmtSvc,IKEEXT,BFE'] = $true
	$NET_RAS_ETWTracingSwitchesStatus['ProcDumpOption Both'] = $true
	$NET_RAS_ETWTracingSwitchesStatus['ProcDumpInterval 3:50'] = $True
 }

$NET_RDScli_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_RDScommon' = $true
	'NET_RDScli' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

$NET_RDSsrv_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_RDScommon' = $true
	'NET_RDSsrv' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'PSR' = $true
	'SDP RDS' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

$NET_RPC_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_RPC' = $true
	'NET_OLE32' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'Procmon' = $true
	'PerfMon SMB' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 
$NET_SBSL_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_SBSL' = $true
	'NET_SMBcli' = $true
	'NET_DCLocator' = $true
	'ADS_Auth' = $true
	'ADS_Profile' = $true
	'ADS_GPO' = $true
	'ADS_GPsvc' = $true
	'NET_Netlogon' = $true
	'NET_WinLogon' = $true
	'Xperf SBSLboot' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'PerfMon SMB' = $true
	#'PSR' = $true
	#'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 
<# $NET_SdnNC_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_SdnNC' = $true
	'NET_HttpSys' = $true
	'NET_LBFo' = $true
	'NET_MUX' = $true
	'NET_NCHA' = $true
	'ADS_SSL' = $true
	'NET_VmSwitch' = $true
	'CommonTask NET' = $True 
	'NetshScenario Virtualization,InternetClient capturetype=both captureMultilayer=yes' = $true
	'Procmon' = $true
	'PerfMon NC' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 } #>

$NET_SMBcli_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_SMBcli' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'Procmon' = $true
	'PerfMon SMB' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
$NET_DFScli_ETWTracingSwitchesStatus = $NET_SMBcli_ETWTracingSwitchesStatus 
<#
$NET_CSC_ETWTracingSwitchesStatus = $NET_SMBcli_ETWTracingSwitchesStatus
	$NET_CSC_ETWTracingSwitchesStatus.add('NET_CSC',"$True")
$NET_NFScli_ETWTracingSwitchesStatus = $NET_SMBcli_ETWTracingSwitchesStatus
	$NET_NFScli_ETWTracingSwitchesStatus.add('NET_NFScli',"$True")
$NET_RDMA_ETWTracingSwitchesStatus   = $NET_SMBcli_ETWTracingSwitchesStatus
	$NET_RDMA_ETWTracingSwitchesStatus.add('NET_AfdTcpFull',"$True")
	$NET_RDMA_ETWTracingSwitchesStatus.add('NET_NDIS',"$True")
	$NET_RDMA_ETWTracingSwitchesStatus.add('NET_NetIO',"$True")
	$NET_RDMA_ETWTracingSwitchesStatus.add('NET_RDMA',"$True")
#>
$NET_CSC_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_SMBcli' = $true
	'NET_CSC' = $True
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'Procmon' = $true
	'PerfMon SMB' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
$NET_NFScli_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_NFScli' = $True
	'NET_SMBcli' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'Procmon' = $true
	'PerfMon SMB' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 $NET_RDMA_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_AfdTcpFull' = $True
	'NET_NDIS' = $True
	#'NET_NetIO' = $True
	'NET_RDMA' = $True
	'NET_SmbCA' = $true
	'NET_SMBcli' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'Procmon' = $true
	'PerfMon ALL' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

$NET_SMBsrv_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_SMBsrv' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'Procmon' = $true
	'PerfMon SMB' = $true
	'PSR' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
  }
#  $NET_DFSsrv_ETWTracingSwitchesStatus = $NET_SMBsrv_ETWTracingSwitchesStatus
#   $NET_DFSsrv_ETWTracingSwitchesStatus.add('NET_DFSsrv',"$True")
#   $NET_NFSsrv_ETWTracingSwitchesStatus = $NET_SMBsrv_ETWTracingSwitchesStatus
$NET_NFSsrv_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_NFSsrv' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'Procmon' = $true
	#'PerfMon SMB' = $true
	'PSR' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
  }

$NET_DFSsrv_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_SMBsrv' = $true
	'NET_DFSsrv' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'Procmon' = $true
	'PerfMon SMB' = $true
	'PSR' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
  }
  
$NET_SMB_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_SMBcli' = $true
	'NET_SMBsrv' = $true
	# -- both cli/srv
	#'NET_sec' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'Procmon' = $true
	'PerfMon SMB' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

$NET_SQLtrace_ETWTracingSwitchesStatus = [Ordered]@{
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'PerfMon SQL' = $true
	'SDP SQLbase' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 
$NET_UNChard_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_UNChard' = $true
	'NET_SMBcli' = $true
	'NET_DCLocator' = $true
	'ADS_Auth' = $true
	'ADS_Profile' = $true
	'ADS_GPO' = $true
	'ADS_GPsvc' = $true
	'NET_Netlogon' = $true
	'NET_WinLogon' = $true
	'CommonTask NET' = $True 
	'Netsh' = $true
	'Procmon' = $true
	'PerfMon SMB' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 
$NET_VPN_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_AfdTcpFull' = $true
	'NET_IPsec' = $true
	#'NET_NetIO' = $true
	'NET_NetworkUX' = $true
	'NET_VPN' = $true
	'NET_WFP' = $true
	'CommonTask NET' = $True 
	#'NetshScenario VpnClient' = $true # see below for Basic/Full
	'RASdiag' = $true
	'WFPdiag' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 if ($global:OSVersion.Build -ge 17763){
	 if ($global:Mode -iMatch "Basic"){
		 $NET_VPN_ETWTracingSwitchesStatus.add('NetshScenario VpnClient provider={D84521F7-2235-4237-A7C0-14E3A9676286}',"$True")
	 }else{
		 $NET_VPN_ETWTracingSwitchesStatus.add('NetshScenario VpnClient_dbg provider={D84521F7-2235-4237-A7C0-14E3A9676286}',"$True")
	 }
 }else{
	 # NetSh scenario VpnClient_dbg/VpnClient are not supported on Srv2016
	 $NET_VPN_ETWTracingSwitchesStatus.add('NetshScenario InternetClient_dbg provider={D84521F7-2235-4237-A7C0-14E3A9676286}',"$True")
 }
 
$NET_WebClient_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_Webclient' = $true	# =$NET_SMBcli
	'ADS_SSL' = $true
	'NET_WebIO' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection provider=Microsoft-Windows-WinHttp provider=Microsoft-Windows-WebIO level=5' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 #$NET_WebCliTTD_ETWTracingSwitchesStatus = $NET_WebClient_ETWTracingSwitchesStatus
$NET_WebCliTTD_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_Webclient' = $true	# =$NET_SMBcli
	'ADS_SSL' = $true
	'NET_WebIO' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection provider=Microsoft-Windows-WinHttp provider=Microsoft-Windows-WebIO level=5' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 # check if -Scenario matches 'NET_WebCliTTD'
 If($global:BoundParameters.ContainsKey('Scenario')){ #fix for #638
	$ScenarioName = $global:BoundParameters['Scenario']
	If($ScenarioName -eq 'NET_WebCliTTD'){
		 $TTDlist = @()
		 $ExplorerRuns = (Get-Process -IncludeUserName -Name Explorer -ErrorAction SilentlyContinue).Name |Sort-Object -Unique; if ($ExplorerRuns) {$TTDlist = $ExplorerRuns + ".exe"}
		 $iExploreRuns = (Get-Process -IncludeUserName -Name iExplore -ErrorAction SilentlyContinue).Name |Sort-Object -Unique ; if ($iExploreRuns) {$TTDlist = $TTDlist + "," + $iExploreRuns + ".exe"}
		 $msedgeRuns =   (Get-Process -IncludeUserName -Name msedge -ErrorAction SilentlyContinue).Name |Sort-Object -Unique ; if ($msedgeRuns) {$TTDlist = $TTDlist + "," + $msedgeRuns + ".exe"}
		 $WebCliSvcStatus = (Get-Service -Name "WebClient" -ErrorAction SilentlyContinue).Status
		 $WebClientRuns = (Get-Service -Name "WebClient" -ErrorAction SilentlyContinue).Name ; if ($WebClientRuns -and ($WebCliSvcStatus -eq [System.ServiceProcess.ServiceControllerStatus]::Running)) {$TTDlist = $TTDlist + "," + $WebClientRuns}else{ LogWarn "Status of WebClient Service: $WebCliSvcStatus"}
		 $TTDstring = 'TTD {0}' -f $TTDlist 
		 $NET_WebCliTTD_ETWTracingSwitchesStatus.add( $TTDstring,"$True")
		 #$ExplorerRuns,$iExploreRuns,$msedgeRuns,$WebClientRuns | ForEach-Object { if ($_) {$TTDlist += $_ }}
		 # ($TTDlist) -join ", "
		 #$NET_WebCliTTD_ETWTracingSwitchesStatus.add('TTD Explorer.exe,iExplore.exe,msedge.exe,WebClient',"$True")
	 }
 }
	 
$NET_WebIO_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_AfdTcpFull' = $true
	#'NET_NETIO' = $true
	'NET_NDIS' = $true
	'NET_WebIO' = $true
	'CommonTask NET' = $True 
	'NetshScenario InternetClient_dbg' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 
$NET_WFP_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_AfdTcpFull' = $true
	'NET_BFE' = $true
	'NET_IPsec' = $true
	#'NET_NETIO' = $true
	'NET_WFP' = $true
	'CommonTask NET' = $True 
	'NetshScenario InternetClient_dbg' = $true
	'WFPdiag' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

$NET_Winsock_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_AfdTcpFull' = $true
	'NET_NDIS' = $true
	#'NET_NetIO' = $true
	'NET_Winsock' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 
$NET_WIP_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_AfdTcpFull' = $true
	'NET_AppLocker' = $true
	'NET_Firewall' = $true
	'NET_WFP' = $true
	'NET_WIP' = $true
	'CommonTask NET' = $True 
	'NetshScenario InternetClient_dbg' = $true
	'WFPdiag' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 
$NET_WNV_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_AfdTcpFull' = $true
	'NET_LBFo' = $true
	'NET_NCHA' = $true
	'NET_VMswitch' = $true
	'CommonTask NET' = $True 
	'NetshScenario Virtualization,InternetClient capturetype=both captureMultilayer=yes' = $true
	#'Procmon' = $true
	#'PerfMon NET' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 
$NET_WorkFolders_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_WorkFolders' = $true
	'NET_HttpSys' = $true
	'CommonTask NET' = $True 
	'NetshScenario NetConnection' = $true
	'Procmon' = $true
	'PerfMon ALL' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

#endregion --- Scenario definitions ---

#region performance counters
 # moved to FW TSSv2.ps1
#endregion performance counters

## NET_TestMe Test suite; to start: .\TSSv2.ps1 -start -Scenario NET_TestMe
$NET_TestMe_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_TestMe' = $true
	#'CommonTask NET' = $True 
	'Netsh' = $true
	#'NetshScenario wireless_dbg,InternetClient_dbg provider=Microsoft-Windows-PrimaryNetworkIcon provider={1701C7DC-045C-45C0-8CD6-4D42E3BBF387}' = $true
	#'WFPdiag' = $true
	#'RASdiag' = $true #_# RASdiag needs 14 sessions, it may fail, if number of sessions exceed 55, should be resolved by issue #83
	#'Procmon' = $true
	#'WPR memory' = $true
	#'PerfMon ALL' = $true
	#'PSR' = $true
	#'Video' = $true
	#'SDP Rfl' = $True
	#'SkipSDPList noNetadapters,skipBPA' = $True #we# for testing only
	#'xray' = $True
 }
 
#region ### Pre-Start / Post-Stop / Collect functions for trace components and scenarios 
#region ---NET_TestMe Test suite
function NET_TestMePreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	writeTesting "____ in trace function NET_TestMePreStart"
	if (!$global:StartAutologger.IsPresent) { writeTesting "____ StartAutologger is NOT present"}
	if ($global:noRestart) { writeTesting "____ Global:noRestart is present: value: $global:noRestart"}
	writeTesting "____ global:Mode:		 $global:Mode"
	writeTesting "____ global:noClearCache: $global:noClearCache"
	writeTesting "____ global:noGPresult: $global:noGPresult"
	writeTesting "____ global:NetLogonFlag: $global:NetLogonFlag"
	writeTesting "____ global:FwEvtxLogSize $global:FwEvtxLogSize"
	writeTesting "____ global:noPoolMon:	$global:noPoolMon"
	writeTesting "____ global:noRestart:	$global:noRestart"
	writeTesting "____ PrefixTime: $PrefixTime - DirRepro: $DirRepro - LogFolder: $LogFolder - LogPrefix: $LogPrefix"
	writeTesting "____ PrefixCn: $PrefixCn "
##	FwAddRegItem @("TestMe", "Tcp") _Start_
	#getDHCPlease _Start_
	FwGetDFScache _Start_
	#FwSetEventLog "Microsoft-Windows-CAPI2/Operational" -EvtxLogSize $global:EvtxLogSize  -ClearLog
	FwGetBuildInfo
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_TestMePostStart {
	EnterFunc $MyInvocation.MyCommand.Name
	writeTesting "___ in trace function NET_TestMePostStart"
	EndFunc $MyInvocation.MyCommand.Name
}	
function NET_TestMePreStop {
	EnterFunc $MyInvocation.MyCommand.Name
	writeTesting "___ in trace function NET_TestMePreStop"
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_TestMePostStop {
	EnterFunc $MyInvocation.MyCommand.Name
	writeTesting "___ in trace function NET_TestMePostStop"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_TestMeLog {
	EnterFunc $MyInvocation.MyCommand.Name
	writeTesting "___ in trace function CollectNET_TestMeLog"
	#FwResetEventLog @("Microsoft-Windows-CAPI2/Operational")
##	FwAddRegItem @("TestMe", "Auth", "Crypt", "TLS", "UNChard") _Stop_
	#getWfpShow _Stop_
	#getDHCPlease _Stop_
#	($EvtLogsDNScli, "Microsoft-Windows-CAPI2/Operational") | ForEach-Object { FwAddEvtLog $_ _Stop_}
	#RunNET_NFSsrvPerm
	#CollectNET_NFScliLog
	#FwGetMsInfo32 "nfo"
	#FwWaitForProcess $global:msinfo32NFO 10
	EndFunc $MyInvocation.MyCommand.Name
}
<#
function RunNET_TestMeDiag{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "$($MyInvocation.MyCommand.Name) is called."
	writeTesting "___ in Diag function RunNET_TestMeDiag"
	EndFunc $MyInvocation.MyCommand.Name
}
#>
function NET_TestMeScenarioPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	writeTesting "___ in Scen function NET_TestMeScenarioPreStart"
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_TestMeScenarioPostStart {
	EnterFunc $MyInvocation.MyCommand.Name
	writeTesting "___ in Scen function NET_TestMeScenarioPostStart"
	#NET_start_common_tasks
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_TestMeScenarioPreStop {
	EnterFunc $MyInvocation.MyCommand.Name
	writeTesting "___ in trace function NET_TestMeScenarioPreStop"
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_TestMeScenarioPostStop {
	EnterFunc $MyInvocation.MyCommand.Name
	writeTesting "___ in Scen function NET_TestMeScenarioPostStop"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_TestMeScenarioLog {
	EnterFunc $MyInvocation.MyCommand.Name
	writeTesting "___ in Scen function CollectNET_TestMeScenarioLog"
		#xyz # - now for helper function testing only
##		FwFwGetEnv
		<#getNetcfg _Stop_
		FwGetQwinsta _Stop_
		if ($global:Mini -ne $true) {
			getFWrules _Stop_
			getAdvFWmonitor _Stop_
			getFWlogs _Stop_
			FwGetWhoAmI _Stop_
			FwGetGPresultAS _Stop_
			getNetSh-http-show-UrlAcl _Stop_
		}
		FwGetNetAdapter _Stop_
		#FwGetVMNetAdapter _Stop_
		FwGetProxyInfo _Stop_
		#>
		#end xyz
	#NET_stop_common_tasks
	#CollectNET_TestMeLog
	EndFunc $MyInvocation.MyCommand.Name
}
<#
function RunNET_TestMeScenarioDiag {
	EnterFunc $MyInvocation.MyCommand.Name
	writeTesting "___ in Scen function RunNET_TestMeScenarioDiag"
	EndFunc $MyInvocation.MyCommand.Name
}
#>
#endregion ---NET_TestMe Test suite


function NET_802Dot1xScenarioPreStart {
	#[alias("NET_WLANScenarioPreStart")]
	EnterFunc $MyInvocation.MyCommand.Name
	# To get Surface wifi specific logging including Marvel, you must manually set these 3 registry keys and Restart Windows/Reboot
	if (Test-Path "HKLM:\System\CurrentControlSet\Services\mrvlpcie8897") {
		LogWarn "[Info] Surface WiFi detected, adding debug REG keys, one reboot is required after having them set first time!" cyan
		$RegistryKey = "HKLM\System\CurrentControlSet\Services\mrvlpcie8897"
		FwAddRegValue "$RegistryKey" "AllowFWDump" "REG_DWORD" "0xF"
		FwAddRegValue "$RegistryKey" "EnableTracing" "REG_DWORD" "0x1"
		FwAddRegValue "$RegistryKey" "DebugMask" "REG_DWORD" "0x2800003f" $True
	}
	getWLANinfo _Start_
	EndFunc $MyInvocation.MyCommand.Name
}
#set-alias -name NET_WLANScenarioPreStart -value NET_802Dot1xScenarioPreStart -Scope Global

function CollectNET_802Dot1xScenarioLog {
	#[alias("CollectNET_WLANScenarioLog")]
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("802Dot1x", "TLS","WinHTTP") _Stop_
	FwAddRegItem @("DotNETFramework") _Stop_ -noRecursive
	copyMachineUserProfiles
	copyWLANProfiles
	LoginfoFile "... copying $env:SystemRoot\dot3svc\Policies\POL*.tmp"
	$Commands = @(
		"xcopy /s/e/i/q/y $env:SystemRoot\dot3svc\Policies\Pol*.tmp $DirRepro\dot3_Policies"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	($EvtLogs802dot1x) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	getWLANinfo _Stop_
	FwGetCertsInfo _Stop_ Basic
	if ($global:OSVersion.Build -ge 16299) {
		$Commands = @(
			"netsh wlan show wlanreport"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		if (Test-Path $env:ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html) { xCopy /y $env:ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html $DirRepro 1>> $ErrorLogFile }
	}
	LogInfo "** [Hint] for troubleshooting:" "Cyan"
	LogInfo "**  https://docs.microsoft.com/en-us/windows/client-management/data-collection-for-802-authentication" "Cyan"
	LogInfo "**  https://docs.microsoft.com/en-us/windows/client-management/advanced-troubleshooting-802-authentication" "Cyan"
	LogInfo "**  https://docs.microsoft.com/en-us/windows/client-management/advanced-troubleshooting-wireless-network-connectivity" "Cyan"
	LogInfo "**  https://rscciew.wordpress.com/2014/05/07/timeout-setting-on-wireless-lan-controller/" "Cyan"
	if (Test-Path "HKLM:\System\CurrentControlSet\Services\mrvlpcie8897") {
		LogWarn "[Info] Surface WiFi detected, once isse is solved remember to remove the debug REG keys: AllowFWDump, EnableTracing, DebugMask under HKLM\System\CurrentControlSet\Services\mrvlpcie8897" cyan
		$RegistryKey = "HKLM\System\CurrentControlSet\Services\mrvlpcie8897"
		"AllowFWDump","EnableTracing","DebugMask" | ForEach-Object { FwDeleteRegValue "$RegistryKey" $_ }
	}
	$outFile = $PrefixTime + "CredentialGuard" + $TssPhase + ".txt"
	$Commands = @(
		"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows/DeviceGuard | Out-File -Append -Encoding ascii $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	getNICinfo _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}
#set-alias -name CollectNET_WLANScenarioLog -value CollectNET_802Dot1xScenarioLog -Scope Global
function NET_WLANScenarioPreStart {
	NET_802Dot1xScenarioPreStart
}
function CollectNET_WLANScenarioLog {
	CollectNET_802Dot1xScenarioLog
}
function CollectNET_WlanLog {
	($EvtLogsWlan) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	FwAddRegItem @("Wlan") _Stop_
	$Commands = @(
		"REG export HKEY_LOCAL_MACHINE\Software\Microsoft\PolicyManager $PrefixTime`Reg_PolicyManager.Txt"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	copyMachineUserProfiles
	copyWLANProfiles
	getWLANinfo _Stop_
	FwCreateFolder $global:LogFolder\files_ProgramData_WlanSvc
	FwCreateFolder $global:LogFolder\files_Windows_WlanSvc
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(
		@("$env:ProgramData\Microsoft\WlanSvc\*", "$global:LogFolder\files_ProgramData_WlanSvc"),
		@("$env:Windir\wlansvc\*", "$global:LogFolder\files_Windows_WlanSvc")
	)
	FwCopyFiles $SourceDestinationPaths -ShowMessage:$False
	getNICinfo _Stop_
	FWgetDriverQuery
}

function NET_AfdTcpFullPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	doTCPrundown
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_AfdTcpFullPreStop {
	EnterFunc $MyInvocation.MyCommand.Name
	doTCPrundown
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_AfdTcpBasicPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	doTCPrundown
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_AfdTcpBasicPreStop {
	EnterFunc $MyInvocation.MyCommand.Name
	doTCPrundown
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_AuthPreStart {
	ADS_AUTHScenarioPreStart
}
function CollectNET_AuthLog {
	CollectADS_AuthScenarioLog
}
function NET_AuthScenarioPreStart {
	ADS_AUTHScenarioPreStart
}
function CollectNET_AuthScenarioLog {
	CollectADS_AuthScenarioLog
}

function CollectNET_BFELog {
	getBFEregPerm
}

function NET_BITsPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	getBITSInfo _Start_
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_BITsPostStart {
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:BITSLOG_RESET -eq $True) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] . bitsadmin /Reset /AllUsers"
		$Commands = @(
			"bitsadmin /Reset /AllUsers"	#_# /Reset : Deletes all jobs in the manager
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}
	if ($global:BITSLOG_RESTART -eq $True) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] .. configuring BITS debug registry keys"
		$BitsKey="HKLM\Software\Microsoft\Windows\CurrentVersion\BITS"
		FwAddRegValue $BitsKey "LogFileFlags" "REG_DWORD" "0xfbcf"
		FwAddRegValue $BitsKey "LogFileSize" "REG_DWORD" "0x20"
		if ($global:noRestart -ne $True) {
			LogInfo "[$($MyInvocation.MyCommand.Name)] . Restarting BITS service after configuring verbose Logging"
			Restart-Service -Name "BITS" -Force
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_BITsLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("BITS", "NlaNCSI") _Stop_ 
	getBITsInfo _Stop_
	if ($global:BITSLOG_RESTART -eq $True) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] copying verbose BITS.log at _Stop_"
		$Commands = @(
			"xcopy /s/i/q/y/H $Sys32\bits.* $global:LogFolder\Bits"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		Remove_BITS
	}
	("Microsoft-Windows-Bits-Client/Operational") | ForEach-Object { FwAddEvtLog $_ _Stop_}
	getNetSh-http-show-UrlAcl _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_BluetoothPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. defining VerboseOn Reg setting for Bluetooth BTHUSB and BTHPort, plus enable SSP Debug Mode" -ShowMsg
	FwSetEventLog "Microsoft-Windows-Bluetooth-Policy/Operational" -EvtxLogSize $global:EvtxLogSize
	FwAddRegValue "HKLM\System\CurrentControlSet\Services\BTHUSB\Parameters" "VerboseOn" "REG_DWORD" "0x1"
	FwAddRegValue "HKLM\System\CurrentControlSet\Services\BTHPort\Parameters" "VerboseOn" "REG_DWORD" "0x1"
	FwAddRegValue "HKLM\System\CurrentControlSet\Services\BTHPort\Parameters" "SimplePairingDebugEnabled" "REG_DWORD" "0x1"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_BluetoothLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("Bluetooth") _Stop_ 
	LogInfo "[$($MyInvocation.MyCommand.Name)] .. removing VerboseOn Reg setting for Bluetooth"
	FwDeleteRegValue "HKLM\System\CurrentControlSet\Services\BTHUSB\Parameters" "VerboseOn"
	FwDeleteRegValue "HKLM\System\CurrentControlSet\Services\BTHPort\Parameters" "VerboseOn"
	FwDeleteRegValue "HKLM\System\CurrentControlSet\Services\BTHPort\Parameters" "SimplePairingDebugEnabled"
	($EvtLogsBluetooth) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	FwResetEventLog "Microsoft-Windows-Bluetooth-Policy/Operational"
	.\scripts\tss_GetBluetoothRadioInfo.ps1 -DataPath $global:LogFolder
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_BranchCachePreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwSetEventLog $EvtLogsBranchcacheAnalytic
	getBCInfo _Start_
	if ($global:noRestart -ne $True) {
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] . PeerdistSvc Service Restart should be avoided for high CPU issues" -ShowMsg
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] . Restarting BranchCache PeerdistSvc service" -ShowMsg
		Restart-Service -Name "PeerdistSvc" -Force
	} else { NET_SCCMPreStart } 
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_BranchCacheLog {
	EnterFunc $MyInvocation.MyCommand.Name
	getBCInfo _Stop_
	FwAddRegItem @("BranchCache", "Tcp") _Stop_ 
	($EvtLogsBranchcache, $EvtLogsBranchcacheAnalytic) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	FwResetEventLog $EvtLogsBranchcacheAnalytic
	#getFWlogs _Stop_	#incuded in NET_Firewall
	FwGetCertsInfo _Stop_ Basic
	LogInfo "** Deploy BC: see https://docs.microsoft.com/en-us/windows-server/networking/BranchCache/deploy/BranchCache-deployment-guide" "Cyan"
	LogInfo "** [Info] configuring FW rules for BC: see https://technet.microsoft.com/en-us/library/dd837649(v=ws.10).aspx" "Cyan"
	LogInfo "**  https://docs.microsoft.com/en-us/windows-server/networking/BranchCache/deploy/install-content-servers-that-use-the-BranchCache-feature" "Cyan"
	LogInfo "** Note: SCCM 2012R2 Software Update configures BranchCache Peer mode on Win8.1 clients" "Cyan"
	LogInfo "** Defragmentation of BC catalog files while PeerdistSvc service is stopped: Use ESENTUTL /d 'database name'" "Cyan"
	LogInfo "** https://sccmnotes.wordpress.com/2018/11/06/BranchCache-using-lots-of-memory-esent-warning-event-id-445-and-resource-exhaustion/" "Cyan"
	if ($global:noRestart -eq $True) { 
		NET_SCCMPostStop
		CollectNET_SCCMLog } 
	FwGetGPresultAS _Stop_
	getNetSh-http-show-UrlAcl _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

Function NET_COMPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	If($EnableCOMDebug.IsPresent){
		$COMDebugRegKey = "HKLM:Software\Microsoft\OLE\Tracing"
		If(!(Test-Path -Path "$COMDebugRegKey")){
			Try{
				LogInfoFile ("[COM] Creating `'HKLM\Software\Microsoft\OLE\Tracing`' key.") -ShowMsg
				New-Item $COMDebugRegKey -ErrorAction Stop | Out-Null
			}Catch{
				LogError ("Unable to create `'HKLM\Software\Microsoft\OLE\Tracing`' key.")
				Return
			}
		}
		Try{
			LogInfoFile "[COM] Enabling COM debug and setting `'ExecutablesToTrace`' to `'*`'." cyan -ShowMsg
			Set-Itemproperty -path $COMDebugRegKey -Name 'ExecutablesToTrace' -value '*' -Type String -ErrorAction Stop
		}Catch{
			LogException ("Unable to set `'ExecutablesToTrace`' registry.") $_
			LogWarn "[COM] COM trace will continue with normal level."
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function NET_COMPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	$COMDebugRegKey = "HKLM:Software\Microsoft\OLE\Tracing"
	If(Test-Path -Path "$COMDebugRegKey"){
		$TracingKey = Get-ItemProperty -Path "HKLM:Software\Microsoft\OLE\Tracing" -ErrorAction Stop
		If($Null -ne $TracingKey.ExecutablesToTrace){
			Try{
				LogInfoFile "[COM] Deleting `'ExecutablesToTrace`' registry." cyan -ShowMsg
				Remove-ItemProperty -Path $COMDebugRegKey -Name 'ExecutablesToTrace' -ErrorAction Stop
			}Catch{
				LogException ("Unable to delete `'ExecutablesToTrace`' registry.") $_
				LogWarn "[COM] Please remove `'ExecutablesToTrace`' under HKLM\Software\Microsoft\OLE\Tracing key manually."
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_CSCPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwSetEventLog $EvtLogsCscAnalytic
	getCSCdump _Start_
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_CSCLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwResetEventLog $EvtLogsCscAnalytic
	FwAddRegItem @("CSC", "SMB", "DefenderATP") _Stop_ 
	FwExportRegistry "UNC hardening" $KeysUNChard1 -ShowMessage:$False
	("Microsoft-Windows-OfflineFiles/Operational", $EvtLogsCscAnalytic) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	getCSCdump _Stop_
	LogInfo "** Hint #1 For deleting the CSC OfflineFiles database at next reboot, run the following command: "
	LogInfo "**  REG ADD 'HKLM\System\CurrentControlSet\Services\CSC\Parameters' /v FormatDatabase /t REG_DWORD /d 1 /f"
	LogInfo "** #2 To bypass CSC for server shares you can use syntax '\\FileserverName`$noCSC$\ShareName'"
	LogInfo "** #3 Demystify Offline Files https://blogs.technet.microsoft.com/filecab/2015/08/12/demystify-offline-files/"
	LogInfo "** #4 in combi with DFS: https://docs.microsoft.com/en-gb/archive/blogs/askds/slow-link-with-windows-7-and-dfs-namespaces"
	LogInfo "** #5 in combi with UE-V https://docs.microsoft.com/en-us/microsoft-desktop-optimization-pack/uev-v2/sync-methods-for-ue-v-2x-both-uevv2"
	FwGetGPresultAS _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_DAcliPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	getDA_Netsh _Start_
	FwSetEventLog $EvtLogsDAcliOpt
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_DAcliLog {
	EnterFunc $MyInvocation.MyCommand.Name
	.\scripts\tss_DAclient-collector.ps1 -DataPath $global:LogFolder
	getWfpShow _Stop_
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. get DA client config info with PowerShell commands at _Stop_" -ShowMsg
	$outFile = $PrefixTime + "DA_client_config.txt"
	$Commands = @(
		"Get-DnsClientNrptPolicy 						| Out-File -Append $outFile"
		"Get-NCSIPolicyConfiguration 					| Out-File -Append $outFile"
		"Get-DAConnectionStatus 						| Out-File -Append $outFile"
		"Get-DAClientExperienceConfiguration 			| Out-File -Append $outFile"
		"Get-NetIPsecMainModeSA 						| Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	$outFile = $PrefixTime + "IPv6_config.txt"
	$Commands = @(
		"Get-Net6to4Configuration 						| Out-File -Append $outFile"
		"Get-NetTeredoState 							| Out-File -Append $outFile"
		"Get-NetIPHTTPSConfiguration 					| Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	getDA_Netsh _Stop_
	($EvtLogsDAcliOpt) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	FwResetEventLog $EvtLogsDAcliOpt
	FwGetGPresultAS _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_DAsrvPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	getDA_Netsh _Start_
	FwSetMCF disable
	LogInfoFile "*** .. collecting PowerShell `"Get-DAEntryPointDC`", use PS command to set the DC: Set-DAEntryPointDC *** " -ShowMsg
	$outFile = $PrefixTime + "DAEntryPointDC_Start_.txt"
	$Commands = @(
		"Get-DAEntryPointDC -ErrorAction SilentlyContinue | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	LogInfoFile "*** for best results: Please use PowerShell command to set the DC: Set-DAEntryPointDC ***" -ShowMsg
	#Start_Netlogon
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_DAsrvLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwSetMCF enable
	#Stop_Netlogon
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. collecting RAS dump 'netsh ras dump' " -ShowMsg
	$outFile = $PrefixTime + "RAS-Dump.txt"
	$Commands = @(
		"netsh ras dump 					| Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	$outFile = $PrefixTime + "DA_IPhttps-state.txt"
	$Commands = @(
		"netsh interface iphttps show state	| Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	$outFile = $PrefixTime + "DA_dynamicportrange.txt"
	$Commands = @(
		"netsh interface ipv4 show dynamicportrange tcp	| Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	($EvtLogsDAsrv) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	FwAddRegItem @("DAsrv", "LDAPcli", "TLS","WinHTTP") _Stop_
	FwAddRegItem @("DotNETFramework") _Stop_ -noRecursive
	if ($global:OSVersion.Build -ge 9200) { 
		$outFile = $PrefixTime + "DAentryPointDC_Stop_.txt"
		$Commands = @(
			"Get-DAEntryPointDC | Out-File -Append $outFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}
	getDA_Netsh _Stop_
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. get DA server info with PowerShell commands at _Stop_" -ShowMsg
	$outFile = $PrefixTime + "DA_server_info.txt"
	$Commands = @(
		"Get-DAServer 				| Out-File -Append $outFile"
		"Get-RemoteAccess 			| Out-File -Append $outFile"
		"Get-RemoteAccessHealth 	| Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	getWfpShow _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

function RunNET_DFSnDiag{	# see :delayed_Stop_DFSsrv
	EnterFunc $MyInvocation.MyCommand.Name
	if ($IsServerSKU -and (Get-WindowsFeature | Where-Object {($_.Name -eq "FS-DFS-Namespace") -and ($_.installed -eq $true)})){
		writeTesting "___ in Diag function RunNET_DFSnDiag"
		LogInfo " Running DFSdiag.exe will take a long time in huge DFS environments, so better run it separately."
		# get DFSdiag.exe outputs for DfsnRoot
		If ((Get-DfsnRoot -ComputerName $env:Computername).count -eq 1) {
			$DFSnRoot = (Get-DfsnRoot -ComputerName $env:Computername).path
		}else{	
			FwPlaySound
			LogInfo "[DFSnRoot] Next step will ask for DFSnRoot, please answer Y or N to collect DFSdiag.exe outputs" "Cyan"
			FwDisplayPopUp 5 "[DFSnRoot]"
			$Answer = FwRead-Host-YN -Message "Press Y for Yes = collect DFSdiag, N for No (timeout=30s)" -Choices 'yn' -TimeOut 30
			If($Answer){
				Write-Host "configured DFSnRoots on this server:"
				(Get-DfsnRoot -ComputerName $env:Computername).Path
				$DFSnRoot = Read-Host -Prompt "Please specify DFS root, i.e. \\contoso.com\your_DFSroot_name  - no subfolders, or hit ENTER to skip this step"
				LogInfoFile "[DFS root: User provided answer:] $DFSnRoot"
			}
		}				
		If(!([String]::IsNullOrEmpty($DFSnRoot))) {
			#ToDo: better run longlasting tasks as parallel jobs
			LogInfo " running DFSdiag.exe /TestDFSConfig /dfsroot:$DFSnRoot - please be patient..."
			$Commands = @(
				"DFSdiag.exe /TestDFSConfig /dfsroot:$DFSnRoot					 | Out-File -Append $PrefixTime`DFSdiag_TestDFSconfig.txt"
			)
			RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
			LogInfo " running DFSdiag.exe /TestDFSIntegrity /dfsroot:$DFSnRoot /recurse /full"
			$Commands = @(
				"DFSdiag.exe /TestDFSIntegrity /dfsroot:$DFSnRoot /recurse /full | Out-File -Append $PrefixTime`DFSdiag_TestDFSIntegrity.txt"
			)
			RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
			LogInfo " running DFSdiag.exe /TestReferral /dfspath:$DFSnRoot - please be patient..."
			$Commands = @(
				"DFSdiag.exe /TestReferral /dfspath:$DFSnRoot /full				 | Out-File -Append $PrefixTime`DFSdiag_TestReferral.txt"
			)
			RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		}else{ LogInfo "*** Note: no DFSnRoot was entered ***" "Magenta"}
		# assuming Domain based DFS
		LogInfo " running DFSdiag.exe /TestDCs /domain:$Env:USERDNSDOMAIN"
		$Commands = @(
			"DFSdiag.exe /TestDCs /domain:$Env:USERDNSDOMAIN | Out-File -Append $PrefixTime`DFSdiag_TestDCs.txt"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}else{ LogInfo "[$($MyInvocation.MyCommand.Name)] This server is not part of DFSn namespace" "Cyan" }
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_DFSsrvPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] ** [Hint]For DFSmgmt tracing, see 2802186 How to enable DFS Management console tracing" "Cyan" -ShowMsg
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_DFSsrvLog {
	EnterFunc $MyInvocation.MyCommand.Name
	($EvtLogsDFSsrv) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	FwAddRegItem @("DFS", "Rpc") _Stop_
	getDFSsrvInfo
	LogInfo "[$($MyInvocation.MyCommand.Name)] *** [Hint] Consider running DFSdiag.exe commands as an extra (longlasting) step." "Cyan"
	LogInfo " .\TSSv2.ps1 -StartDiag NET_DFSn" "Gray"
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_DFSmgmtPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] enable DFSmgmt console tracing." -ShowMsg
	LogInfo "[$($MyInvocation.MyCommand.Name)] PreReq: all MMC consoles need to be closed before repro"
	$MMCProcess = Get-Process -Name 'MMC' -ErrorAction SilentlyContinue
		If($Null -ne $MMCProcess){
			LogInfo "[DfsMgmt] If DFS console is open, plz close and reopen DfsMgmt.msc"
		}
	$Commands = @(
			"Copy-Item  $Sys32\Dfsmgmt.dll.config -Destination $Sys32\Dfsmgmt.dll.config.orig -Force"
			"Copy-Item  $DirScript\config\Dfsmgmt.dll.config -Destination $Sys32\Dfsmgmt.dll.config -Force"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_DFSmgmtPostStop {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] disable DFSmgmt console tracing, collecting DfsMgmt.current.log" -ShowMsg
	$Commands = @(
			"Copy-Item  $Sys32\Dfsmgmt.dll.config.orig -Destination $Sys32\Dfsmgmt.dll.config -Force"
			"Copy-Item  $env:WinDir\debug\DfsMgmt\DfsMgmt.current.log -Destination $PrefixCn`DfsMgmt.current.log -Force"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_DHCPcliPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("DHCPcli", "Tcp") _Start_
	FwSetEventLog $EvtLogsDHCPcliOpt
	getDHCPlease _Start_
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_DHCPcliLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("DHCPcli", "Tcp") _Stop_
	getWfpShow _Stop_
	getDHCPlease _Stop_
	($EvtLogsDHCPcli) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	FwResetEventLog $EvtLogsDHCPcliOpt
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_DHCPsrvLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("DHCP") _Stop_
	($EvtLogsDHCPsrv) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	$DhcpLogsPath		= (Get-DhcpServerAuditLog).Path
	$DhcpDBbackupPath 	= (Get-DhcpServerDatabase).BackupPath
	$DhcpDBPath			= (Get-DhcpServerDatabase).BackupPath | Split-Path -Parent
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] dump all 'NetSH DHCP server show' commands at _stop_" -ShowMsg
	$outFile = $PrefixTime + "DHCPsrvInfo_stop_.txt"
	$Commands = @(
		"netsh dhcp show server 					| Out-File -Append $outFile"
		"Dir -s $DhcpLogsPath						| Out-File -Append $outFile"
		"Dir -s $DhcpDBbackupPath					| Out-File -Append $outFile"
		"Dir -s $DhcpDBPath							| Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	"all","version","auditlog","dbproperties","bindings","detectconflictretry","server","serverstatus","scope","superscope","class","dnsconfig","dnscredentials","mibinfo","mscope","optionvalue","userclass","vendorclass","optiondef","napstate","napdeffail" | ForEach-Object { 
		$Commands = @("netsh dhcp server show $_ | Out-File -Append $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] dump all PowerShell 'Get-DhcpServer*' commands at _stop_" -ShowMsg
	$outFile = $PrefixTime + "DHCPsrvInfo_PScmdlets_stop_.txt"
	"Get-DhcpServerSetting","Get-DhcpServerDatabase","Get-DhcpServerDnsCredential","Get-DhcpServerv4DnsSetting" | ForEach-Object { 
		$Commands = @("$_ | Out-File -Append $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
	LogInfoFile "collecting DHCP database and Audit logs \dhcp\Dhcp*.log" -ShowMsg
	$Commands = @(
		"xcopy /s/e/i/q/y/H $DhcpLogsPath\DHCP*.log $global:LogFolder\dhcp"
		"xcopy $DhcpDBbackupPath\DhcpCfg $global:LogFolder\dhcp\backup\"
		"xcopy /s/e/i/q/y/H $DhcpDBbackupPath\new\dhcp.mdb $global:LogFolder\dhcp\backup\new\"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	if (!$global:IsLiteMode){ # ToDo: try icacls.exe instead
		LogInfo "[$($MyInvocation.MyCommand.Name)] collecting Folder and underlying files permission for Dhcp folders and Audit Logs at _stop_"
		$outFile = $PrefixTime + "DHCP_AccessChk_stop_.txt"
		$Commands = @(
			"AccessChk.exe -nobanner /AcceptEula -s -ld $DhcpLogsPath	| Out-File -Append $outFile"
			"AccessChk.exe -nobanner -v $DhcpLogsPath\Dhcp*.log			| Out-File -Append $outFile"
			"AccessChk.exe -nobanner -v $DhcpDBbackupPath\DhcpCfg		| Out-File -Append $outFile"
			"AccessChk.exe -nobanner -s -ld $DhcpDBPath					| Out-File -Append $outFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}else{ LogInfo "Skipping AccessChk in Lite mode"}
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_DNScliPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwSetEventLog "Microsoft-Windows-DNS-Client/Operational"
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_DNScliPreStop {
	EnterFunc $MyInvocation.MyCommand.Name
	writeTesting "[$($MyInvocation.MyCommand.Name)] .. sending Ping markers after repro at _Stop_"
	LogInfoFile ".. sending Ping markers after repro at _Stop_" -ShowMsg
	$Commands = @(
		"PING www.microsoft.de -n 1	| Out-File -Append $global:ErrorLogFile"
		"PING www.google.de -n 1	| Out-File -Append $global:ErrorLogFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_DNScliLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwResetEventLog @("Microsoft-Windows-DNS-Client/Operational")
	FwAddRegItem @("Auth", "Crypt", "TLS","WinHTTP") _Stop_
	FwAddRegItem @("DotNETFramework") _Stop_ -noRecursive
	getDNScliInfo _Stop_
	($EvtLogsDNScli) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_DNSsrvLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("DNS") _Stop_
	getDNSsrvInfo _Stop_
	($EvtLogsDNSsrv) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_ContainerPostStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] configuring Containers trace ..." -ShowMsg
	$outFile = $PrefixTime + "Containers_NetTrace.etl"
	$outFileLog = $PrefixTime + "Containers_TraceLog.txt"
	# Cleaning up old sessions
	Stop-NetEventSession "MSFT_Containers" -ErrorAction Ignore | Out-File $outFileLog 
	Remove-NetEventSession "MSFT_Containers" -ErrorAction Ignore | Out-File $outFileLog -Append
	
	New-NetEventSession -Name "MSFT_Containers" -MaxFileSize $ETLMaxSize -LocalFilePath $outFile | Out-File $outFileLog -Append

	# Control Plane
	Add-NetEventProvider "{564368D6-577B-4af5-AD84-1C54464848E6}" -Level 6 -SessionName "MSFT_Containers" | Out-File $outFileLog -Append # Microsoft-Windows-Overlay-HNSPlugin
	Add-NetEventProvider "{0c885e0d-6eb6-476c-a048-2457eed3a5c1}" -Level 6 -SessionName "MSFT_Containers" | Out-File $outFileLog -Append # Microsoft-Windows-Host-Network-Service
	Add-NetEventProvider "{80CE50DE-D264-4581-950D-ABADEEE0D340}" -Level 6 -SessionName "MSFT_Containers" | Out-File $outFileLog -Append # Microsoft.Windows.HyperV.Compute
	Add-NetEventProvider "{D0E4BC17-34C7-43fc-9A72-D89A59D6979A}" -Level 6 -SessionName "MSFT_Containers" | Out-File $outFileLog -Append # Microsoft.Windows.HostNetworkingService.PrivateCloudPlugin
	Add-NetEventProvider "{93f693dc-9163-4dee-af64-d855218af242}" -Level 6 -SessionName "MSFT_Containers" | Out-File $outFileLog -Append # Microsoft-Windows-Host-Network-Management
	Add-NetEventProvider "{6C28C7E5-331B-4437-9C69-5352A2F7F296}" -Level 6 -SessionName "MSFT_Containers" | Out-File $outFileLog -Append # Microsoft.Windows.Hyper.V.VmsIf

	# VmSwitch Enable ETW and WPP Events - Control Path Only
	Add-NetEventProvider "{1F387CBC-6818-4530-9DB6-5F1058CD7E86}" -Level 6 -SessionName "MSFT_Containers" -MatchAnyKeyword 4292870139 | Out-File $outFileLog -Append # 0xFFDFFFFB 
	Add-NetEventProvider "{67DC0D66-3695-47c0-9642-33F76F7BD7AD}" -Level 6 -SessionName "MSFT_Containers" -MatchAnyKeyword 4294967261 | Out-File $outFileLog -Append # 0xFFFFFFDD

	# Protocols
	Add-NetEventProvider "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}" -Level 6 -SessionName "MSFT_Containers" | Out-File $outFileLog -Append # Microsoft-Windows-TCPIP
	Add-NetEventProvider "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}" -Level 6 -SessionName "MSFT_Containers" | Out-File $outFileLog -Append # Microsoft-Windows-DNS-Client
	Add-NetEventProvider "{15A7A4F8-0072-4EAB-ABAD-F98A4D666AED}" -Level 6 -SessionName "MSFT_Containers" | Out-File $outFileLog -Append # Microsoft-Windows-Dhcp-Client
	Add-NetEventProvider "{6A1F2B00-6A90-4C38-95A5-5CAB3B056778}" -Level 6 -SessionName "MSFT_Containers" | Out-File $outFileLog -Append # Microsoft-Windows-DHCPv6-Client

	# NAT
	Add-NetEventProvider "{66C07ECD-6667-43FC-93F8-05CF07F446EC}" -Level 6 -SessionName "MSFT_Containers" | Out-File $outFileLog -Append # Microsoft-Windows-WinNat
	Add-NetEventProvider "{AA7387CF-3639-496A-B3BF-DC1E79A6fc5A}" -Level 6 -SessionName "MSFT_Containers" | Out-File $outFileLog -Append # WIN NAT WPP
	Add-NetEventProvider "{AE3F6C6D-BF2A-4291-9D07-59E661274EE3}" -Level 6 -SessionName "MSFT_Containers" | Out-File $outFileLog -Append # IP NAT WPP

	# Shared Access
	Add-NetEventProvider "{9B322459-4AD9-4F81-8EEA-DC77CDD18CA6}" -Level 6 -SessionName "MSFT_Containers" | Out-File $outFileLog -Append # Shared Access Service WPP Provider
	Add-NetEventProvider "{A6F32731-9A38-4159-A220-3D9B7FC5FE5D}" -Level 6 -SessionName "MSFT_Containers" | Out-File $outFileLog -Append # Microsoft-Windows-SharedAccess_NAT

	# VmSwitch Enable ETW and WPP Events
	##Add-NetEventProvider "{1F387CBC-6818-4530-9DB6-5F1058CD7E86}" -Level 6 -SessionName "MSFT_Containers" | Out-File $outFileLog -Append
	##Add-NetEventProvider "{67DC0D66-3695-47c0-9642-33F76F7BD7AD}" -Level 6 -SessionName "MSFT_Containers" | Out-File $outFileLog -Append

	if ([environment]::OSVersion.Version.Build -igt 19041)
	{
		Add-NetEventProvider "{94DEB9D1-0A52-449B-B368-41E4426B4F36}" -Level 6 -SessionName "MSFT_Containers" | Out-File $outFileLog -Append # Microsoft.Windows.Hyper.V.NetSetupHelper
	}

	# VFPEXT is an optional component
	Add-NetEventProvider "Microsoft-Windows-Hyper-V-VfpExt" -Level 6 -SessionName "MSFT_Containers" -ErrorAction Ignore | Out-File $outFileLog -Append # Microsoft-Windows-Hyper-V-VfpExt

	# Capture packets on all interfaces
	Add-NetEventPacketCaptureProvider -Level 5 -SessionName "MSFT_Containers" -CaptureType BothPhysicalAndSwitch -TruncationLength 8000 -MultiLayer $true | Out-File $outFileLog -Append # Start the session and optionally wait for the user to stop the session
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] starting Containers trace" -ShowMsg
	Start-NetEventSession "MSFT_Containers"

	EndFunc $MyInvocation.MyCommand.Name
}
function NET_ContainerPreStop {
	EnterFunc $MyInvocation.MyCommand.Name
	Stop-NetEventSession "MSFT_Containers" -ErrorAction SilentlyContinue
	Remove-NetEventSession "MSFT_Containers" -ErrorAction SilentlyContinue
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_ContainerLog {
	EnterFunc $MyInvocation.MyCommand.Name
	# from https://supportability.visualstudio.com/WindowsNetworking/_wiki/wikis/WindowsNetworking/453879/Container-Networking-Training $Script:Vers = "2021.04.4"
	$OutDir = $global:LogFolder
	Push-Location $OutDir
	#Write-Host "Starting data collection in $OutDir `t" -NoNewLine
	$DockerCmd = Get-Command -All docker -ErrorAction ignore
	If ($DockerCmd) {
		Try{
			$Commands = @(
			"docker ps > ($PrefixCn + `"containers.txt`")"
			"docker inspect $(docker ps -q) > ($PrefixCn + `"containers_detailed.txt`")"
			"docker network ls > ($PrefixCn + `"docker_network.txt`")"
			"docker network inspect $(docker network ls -q) > ($PrefixCn + `"docker_networkdetailed.txt`")"
			)
			RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		}Catch{
			LogWarn "Failed to run Docker commands"
			Continue
		}
	}else{LogInfo "This computer is not running Docker" "Magenta"}
	
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting Firewall rules and profiles" -ShowMsg
	Show-NetFirewallRule | Out-File ($PrefixCn + "firewall_rules.txt")
	Get-NetConnectionProfile | Out-File ($PrefixCn + "network_profile.txt")
	Get-NetFirewallProfile | Format-Table | Out-File ($PrefixCn + "firewall_profiles.txt")
	Get-NetFirewallProfile | Out-File ($PrefixCn + "firewall_profiles.txt") -Append
	Get-NetFirewallProfile | ForEach-Object {
		xcopy $_.LogFileName . /y | out-Null
	}
	
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting WFP filters and state" -ShowMsg
	$Commands = @(
	"netsh wfp show filters file=wfpfilters.xml"
	"netsh wfp show state file=wfpstate.xml"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False

	##if($Swarm){
	if ($global:Mode -iMatch "Swarm"){
		If ($DockerCmd) {
			Try{
				$Commands = @(
				"docker service ls > ($PrefixCn + `"services.txt`")"
				"docker service ps $(docker service ls -q) >> ($PrefixCn + `"services.txt`")"
				"docker service inspect $(docker service ls -q) >> ($PrefixCn + `"services_detailed.txt`")"
				"docker nodes ls > ($PrefixCn + `"nodes.txt`")"
				"docker nodes ps $(docker nodes ls -q) >> ($PrefixCn + `"nodes.txt`")"
				"docker nodes inspect $(docker node ls -q) >> ($PrefixCn + `"nodes_detailed.txt`")"
				)
				RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
			}Catch{
				LogWarn "Failed to run Docker 'Swarm' commands"
				Continue
			}
		}else{LogInfo "Swarm: This computer is not running Docker" "Magenta"}
	}
	##elseif($Kube){
	elseif($global:Mode -iMatch "Kube"){
		If ($DockerCmd) {
			Try{
				$Commands = @(
				"kubectl get pods --all-namespaces > ($PrefixCn + `"pods.txt`")"
				"kubectl get nodes > ($PrefixCn + `"nodes.txt`")"
				"kubectl get service > ($PrefixCn + `"services.txt`")"
				)
				RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
			}Catch{
				LogWarn "Failed to run Docker 'Kubectl' commands"
				Continue
			}
		}else{LogInfo "Kube: This computer is not running Docker/kubectl" "Magenta"}
	}

	LogInfo "[$($MyInvocation.MyCommand.Name)] collecting Docker Events from Application Evtlog"
	Get-EventLog -LogName Application -Source Docker -After (Get-Date).AddMinutes(-30) -ErrorAction SilentlyContinue | Sort-Object Time | Export-CSV ($PrefixCn + "Evt_Last30min_Application.csv") 
	If ($DockerCmd) {
		Try{
			Invoke-WebRequest "https://raw.githubusercontent.com/microsoft/SDN/master/Kubernetes/windows/debug/collectlogs.ps1" -Outfile _Kube_collectlogs.ps1
			(Get-Content "_Kube_collectlogs.ps1").Replace('$outDir = [io.Path]::Combine($ScriptPath, [io.Path]::GetRandomFileName())',"`$outDir = '$OutDir'") | Set-Content "_Kube_collectlogs.ps1"
			##"Read-Host 'Press enter to close'" | Add-Content "_Kube_collectlogs.ps1"
			Start-Process "powershell" -ArgumentList ".\_Kube_collectlogs.ps1" -NoNewWindow
		}Catch{
			LogWarn "Failed to run _Kube_collectlogs.ps1"
			Continue
		}
	}else{LogInfo "Kube_collectlogs: This computer is not running Docker" "Magenta"}

	##Write-Host "DONE"
	Pop-Location
	LogInfoFile "*** more TS: https://github.com/Microsoft/Virtualization-Documentation/tree/master/windows-server-container-tools/CleanupContainerHostNetworking " -ShowMsg
	LogInfoFile "   https://docs.microsoft.com/en-us/virtualization/windowscontainers/troubleshooting#docker-container-logs " -ShowMsg
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_DockerPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] running 'docker -v' 'docker version' 'docker info' 'docker network ls' 'docker ps' .. at _Start_"
	$outFile = $PrefixTime + "Docker.txt"
	"Get-ComputerInfo" ,"Get-Service Docker" ,"docker -v" ,"Docker version" ,"docker info" ,"Docker image ls" ,"docker network ls" ,"Docker network inspect nat" ,"docker ps" ,"docker node ls" ,"Get-NetIPAddress -IncludeAllCompartments" ,"ipconfig /allcompartments" | ForEach-Object { 
		$Commands = @("$_ | Out-File -Append $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
	LogInfo "[$($MyInvocation.MyCommand.Name)] running Get-HNSNetwork, Get-HNSEndpoint, docker network inspect"
	$Commands = @(
		"Get-HNSNetwork | Convertto-JSON -depth 20 |Out-file -Append -Encoding ascii -Width 500 $PrefixCn`Get-HNSNetwork.txt"
		"Get-HNSEndpoint | Convertto-JSON -depth 20 |Out-file -Append -Encoding ascii -Width 500 $PrefixCn`Get-HNSEndpoint.txt"
		"docker network ls -q | ForEach-Object { docker network inspect $_ } |Out-file $PrefixCn`docker-network-inspect.txt -Append -Encoding ascii -Width 500"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	LogInfo "*** [Action] Plz run PowerShell command: docker inspect 'first 2 characters of a container ID' "
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_DockerLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("HNS") _Stop_ 
	($global:EvtLogsDocker) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	LogInfoFile "*** more TS: https://github.com/Microsoft/Virtualization-Documentation/tree/master/windows-server-container-tools/CleanupContainerHostNetworking " -ShowMsg
	LogInfoFile "   https://docs.microsoft.com/en-us/virtualization/windowscontainers/troubleshooting#docker-container-logs " -ShowMsg
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_EFSPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwSetEventLog $global:EvtLogsEFSopt
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_EFSLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwResetEventLog $global:EvtLogsEFSopt
	($global:EvtLogsEFS, $global:EvtLogsEFSopt) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_FirewallPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwSetEventLog $EvtLogsFirewallOpt -EvtxLogSize $global:EvtxLogSize
	FwAddRegItem @("Firewall") _Start_
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] enabling Adv Firewall logging 'netsh advfirewall set currentprofile logging ... '" -ShowMsg
	"filename $Sys32\LogFiles\Firewall\pfirewall.log","maxfilesize 4096","droppedconnections ENABLE","allowedconnections ENABLE" | ForEach-Object { 
		$Commands = @("netsh advfirewall set currentprofile logging $_ "); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
	if (($((Get-Culture).name)) -match "en-US") {
		FwAuditPolSet "Firewall" @('"Filtering Platform Packet Drop","Filtering Platform Connection"')
	}else{
		# auditing categories are localized. On non-English systems the above command fails, so lets use GUIDs for AuditSettingsList
		FwAuditPolSet "IPsec" @('{0CCE9225-69AE-11D9-BED3-505054503030},{0cce9226-69ae-11d9-bed3-505054503030}')
	}
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_FirewallPostStop {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAuditPolUnSet
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_FirewallLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwResetEventLog $EvtLogsFirewallOpt
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] disabling Adv Firewall logging" -ShowMsg
	"droppedconnections disable","allowedconnections disable" | ForEach-Object { 
		$Commands = @("netsh advfirewall set currentprofile logging $_ "); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
	FwAddRegItem @("Firewall") _Stop_
	($EvtLogsFirewall, $EvtLogsFirewallOpt, "Security") | ForEach-Object { FwAddEvtLog $_ _Stop_}
	getFWRules _Stop_
	getFWlogs _Stop_
	getWfpShow _Stop_
	getBFEregPerm _Stop_
	$outFile = $PrefixTime + "FirewallState_Stop_.txt"
	"global","currentprofile","allprofiles" | ForEach-Object { 
		$Commands = @("Netsh advfirewall show $_ | Out-File -Append $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_GeoLocationPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collect Geolocation BSSSID" -ShowMsg
	$outFile = $PrefixTime + "Geolocation_wlan_Start_.txt"
	$Commands = @(
		"netsh wlan show network mode=bssid | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_GeoLocationPostStart {
	# 'BSSID GPS Geolocation tracing on WiFi or Cellular network when changing location/timezones, Orion DB'
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] deleting Geolocation 'lfsvc' Cache" -ShowMsg
	$Commands = @(
		"del C:\ProgramData\Microsoft\Windows\LfSvc\Cache"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] restarting Geolocation Service 'lfSvc'" -ShowMsg
	Restart-Service -Name "lfsvc" -Force
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_GeoLocationLog {
	EnterFunc $MyInvocation.MyCommand.Name
	$outFile = $PrefixTime + "Geolocation_wlan_Stop_.txt"
	$Commands = @(
		"netsh wlan show network mode=bssid | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	FwAddRegItem @("GeoLocation") _Stop_ 
	LogInfoFile "[Info] Latitude and Longitude Finder: https://www.latlong.net/" "Cyan" -ShowMsg
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_HttpSysPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LoginfoFile "*** [Hint] see https://docs.microsoft.com/en-us/windows/win32/wsdapi/capturing-winhttp-logs" "Cyan" -ShowMsg
	FwSetEventLog "Microsoft-Windows-CAPI2/Operational" -EvtxLogSize $global:EvtxLogSize -ClearLog
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_HttpSysLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwResetEventLog @("Microsoft-Windows-CAPI2/Operational")
	("Microsoft-Windows-CAPI2/Operational") | ForEach-Object { FwAddEvtLog $_ _Stop_}
	getNetSh-http-show-UrlAcl _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_HypHostPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwGetNetAdapter _Start_
	FwFwGetVMNetAdapter _Start_
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_HypHostLog {
	EnterFunc $MyInvocation.MyCommand.Name
	($EvtLogsNetHypHost, $global:EvtLogsSMBcli ) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	if ($global:OSVersion.Build -gt 9600) { $global:EvtLogsSMBcliOpt | ForEach-Object { FwAddEvtLog $_ _Stop_} }
	FwAddRegItem @("HyperV") _Stop_
	FwGetNetAdapter _Stop_
	FwGetVMNetAdapter _Stop_
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] exporting the Hyper-V configuration" -ShowMsg
	Invoke-Command -ScriptBlock { Get-VMHost | Export-Clixml -LiteralPath $PrefixTime`HyperV_Config.xml }
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_HypVMPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwSetEventLog "Microsoft-Windows-Hyper-V-NETVSC/Diagnostic"
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] *** [Hint] Consider running FRUTI.exe for Hyper-V replication issues." "Cyan" -ShowMsg
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_HypVMLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwResetEventLog @("Microsoft-Windows-Hyper-V-NETVSC/Diagnostic")
	("Microsoft-Windows-Hyper-V-NETVSC/Diagnostic") | ForEach-Object { FwAddEvtLog $_ _Stop_}
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_ICSLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("ICS") _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_IISLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] copying HTTPERR and InetPub logs" -ShowMsg
	FwCreateFolder $global:LogFolder\HTTPERR
	FwCreateFolder $global:LogFolder\InetPub_Logs
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(
		@("$Sys32\LogFiles\HTTPERR\*", "$global:LogFolder\HTTPERR"),
		@("$env:systemdrive\inetpub\logs\logfiles\*", "$global:LogFolder\InetPub_Logs")
	)
	FwCopyFiles $SourceDestinationPaths -ShowMessage:$False
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] dump all 'NetSH http show' commands at _Stop_" -ShowMsg
	$outFile = $PrefixTime + "IISsrvInfo_Stop_.txt"
	"servicestate","sslcert","urlacl" | ForEach-Object { 
		$Commands = @("Netsh http show $_ | Out-File -Append $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
	If(Test-Path $Sys32\inetsrv\appcmd.exe){ 
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] dump all 'appcmd list' commands at _Stop_" -ShowMsg
		$outFile = $PrefixTime + "IISappcmdList_Stop_.txt"
		"config","wp","module","vdirs","request","trace" | ForEach-Object { 
			$Commands = @("$Sys32\inetsrv\appcmd.exe list $_ | Out-File -Append $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
		"site","apppool","app" | ForEach-Object { 
			$Commands = @("$Sys32\inetsrv\appcmd.exe list $_ /config:* /xml| Out-File -Append $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
	}
	FwAddRegItem @("HTTP","TLS","WinHTTP") _Stop_
	FwAddRegItem @("DotNETFramework") _Stop_ -noRecursive
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_IPAMPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)]defining registry keys for IPAM debug logging" -ShowMsg
	FwAddRegValue "HKLM\Software\Microsoft\IPAM" "EnableLogging" "REG_DWORD" "0x1"
	FwAddRegValue "HKLM\Software\Microsoft\IPAM" "IpamServer" "REG_DWORD" "0xffffffff"
	FwAddRegValue "HKLM\Software\Microsoft\IPAM" "IpamApi" "REG_DWORD" "0xffffffff"
	FwAddRegValue "HKLM\Software\Microsoft\IPAM" "Microsoft.Windows.Servermanager.Plugins.Ipam" "REG_DWORD" "0xffffffff"
	FwSetEventLog $EvtLogsIPAMAnalytic
	LogWarn "*** DO NOT LEAVE THIS IPAM LOGGING RUNNING LONG TERM! ***" cyan
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_IPAMLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwResetEventLog $EvtLogsIPAMAnalytic
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] resetting IPAM Reg Keys to default" -ShowMsg
	FwDeleteRegValue "HKLM\Software\Microsoft\IPAM" "EnableLogging"
	FwDeleteRegValue "HKLM\Software\Microsoft\IPAM" "IpamServer"
	FwDeleteRegValue "HKLM\Software\Microsoft\IPAM" "IpamApi"
	FwDeleteRegValue "HKLM\Software\Microsoft\IPAM" "Microsoft.Windows.Servermanager.Plugins.Ipam"
	($EvtLogsIPAMAnalytic) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	LogInfo "[$($MyInvocation.MyCommand.Name)]  [Info] ... Converting IPAM.etl using  command: netsh trace convert input=IPAM.etl output=IPAM.txt"
	if (Test-Path $PrefixTime`IPAM.etl) {
		$Commands = @(
			"netsh trace convert input=$PrefixTime`IPAM.etl"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}
	$Commands = @(
		"xcopy /s/e/i/q/y/H $env:SystemRoot\Temp\Ipam_IpamServer.svclog $global:LogFolder\Ipam\"
		"xcopy /s/e/i/q/y/H $env:temp\Ipam_ipamapi.svclog $global:LogFolder\Ipam\"
		"xcopy /s/e/i/q/y/H $env:temp\Ipam_Microsoft.Windows.ServerManager.plugins.ipam.svclog $global:LogFolder\Ipam\"
		"xcopy /s/e/i/q/y/H $env:SystemRoot\serviceprofiles\networkservice\appdata\local\Ipam_IpamServer.svclog $global:LogFolder\Ipam_serviceprofiles\"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_IPhlpSvcPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] enabling IPhlpSvc process tracing" -ShowMsg
	FwAddRegValue "HKLM\Software\Microsoft\Tracing\IpHlpSvc" "EnableFileTracing" "REG_DWORD" "0x1"
	FwAddRegValue "HKLM\Software\Microsoft\Tracing\IpHlpSvc" "FileTracingMask" "REG_DWORD" "0xffffffff"
	FwAddRegValue "HKLM\Software\Microsoft\Tracing\IpHlpSvc" "MaxFileSize" "REG_DWORD" "0x10000000"
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_IPhlpSvcPostStop {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] resetting IPhlpSvc Reg Keys to default" -ShowMsg
	$RegistryKey = "HKLM\Software\Microsoft\Tracing\IpHlpSvc"
	"EnableFileTracing","FileTracingMask","MaxFileSize" | ForEach-Object { FwDeleteRegValue "$RegistryKey" $_ }
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_IPhlpSvcLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwCopyWindirTracing IPhlpSvc
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_IPsecPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	<#
	#Note: use /r to get a csv-formatted table: AuditPol /get /category:* /r | ConvertFrom-Csv | Format-Table 'Policy Target',Subcategory,'Inclusion Setting'
	LogInfofile "[$($MyInvocation.MyCommand.Name)] Backup current AuditPol settings to $PrefixCn`AuditPol_backup.csv"
	$Commands = @("AuditPol /backup /file:$PrefixCn`AuditPol_backup.csv")
	LogInfo "[$($MyInvocation.MyCommand.Name)] Enabling IPsec related Events in Security Eventlog via AuditPol.exe"
	$Commands += @(
		"AuditPol.exe /get /category:* | Out-File -Append $global:LogFolder\$($LogPrefix)AuditPol$TssPhase.txt"
		"AuditPol.exe /set /SubCategory:""MPSSVC rule-level Policy Change"",""Filtering Platform policy change"",""IPsec Main Mode"",""IPsec Quick Mode"",""IPsec Extended Mode"",""IPsec Driver"",""Other System Events"",""Filtering Platform Packet Drop""  /success:enable /failure:enable"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	#>
	if (($((Get-Culture).name)) -match "en-US") {
		FwAuditPolSet "IPsec" @('"MPSSVC rule-level Policy Change","Filtering Platform policy change","IPsec Main Mode","IPsec Quick Mode","IPsec Extended Mode","IPsec Driver","Other System Events","Filtering Platform Packet Drop"')
	}else{
		# auditing categories are localized. On non-English systems the above command fails, so lets use GUIDs for AuditSettingsList
		FwAuditPolSet "IPsec" @('{0CCE9232-69AE-11D9-BED3-505054503030},{0CCE9233-69AE-11D9-BED3-505054503030},{0CCE9218-69AE-11D9-BED3-505054503030},{0CCE9219-69AE-11D9-BED3-505054503030},{0CCE921A-69AE-11D9-BED3-505054503030},{0CCE9213-69AE-11D9-BED3-505054503030},{0CCE9214-69AE-11D9-BED3-505054503030},{0CCE9225-69AE-11D9-BED3-505054503030}')
	}
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_IPsecPostStop {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAuditPolUnSet
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_IPsecLog {
	EnterFunc $MyInvocation.MyCommand.Name
	("Security") | ForEach-Object { FwAddEvtLog $_ _Stop_}
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_LBFOLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("LBFO") _Stop_
	FwGetCertsInfo _Stop_ Full
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_LDAPcliPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. enabling LDAP process tracing: REG ADD HKLM\System\CurrentControlSet\Services\ldap\Tracing\$global:LDAPcliProcess /f - see https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/ldap-and-etw " -ShowMsg
	REG ADD HKLM\System\CurrentControlSet\Services\ldap\Tracing\$global:LDAPcliProcess /f 2>&1 | Out-Null
	#FwAddRegValue "HKLM\System\CurrentControlSet\Services\ldap\Tracing" "$global:LDAPcliProcess" "REG_SZ"	# ToDo: asks in FwAddRegValue for RegistryValueData ->i.e. Svchost.exe ? -- needs FW change?
	FwAddRegItem @("LDAPcli") _Start_
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_LDAPcliLog {
	EnterFunc $MyInvocation.MyCommand.Name
	REG DELETE HKLM\System\CurrentControlSet\Services\ldap\Tracing\$global:LDAPcliProcess /f 2>&1 | Out-Null
	#FwDeleteRegValue "HKLM\System\CurrentControlSet\Services\ldap\Tracing" "$global:LDAPcliProcess"
	FwAddRegItem @("LDAPcli") _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_LLTDIOLog { 
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] running 'GPresult /Z'"
	$Commands = @(
		"GPresult.exe /Z | Out-File $global:LogFolder\$($LogPrefix)GPresult-Z.txt"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_MBAMLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("Auth", "Crypt", "TLS","WinHTTP") _Stop_
	FwAddRegItem @("DotNETFramework") _Stop_ -noRecursive
	($EvtLogsMBAM) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_MBNPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] enabling tracing for Mobile Broadband" -ShowMsg
	$Commands = @(
		"Netsh MBN set tracing mode=yes"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	GetMBNInfo _Start_
	getAdvFWmonitor _Start_
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_MBNPostStop {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] disabling tracing for Mobile Broadband" -ShowMsg
	$Commands = @(
		"Netsh MBN set tracing mode=no"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_MBNLog {
	EnterFunc $MyInvocation.MyCommand.Name
	GetMBNInfo _Stop_
	$Commands = @(
		"xcopy /s/e/i/q/y/H $Sys32\LogFiles\WMI $global:LogFolder\wwan"
		"xcopy /s/e/i/q/y/H $env:ProgramData\Microsoft\WwanSvc\Profiles $global:LogFolder\WwanSvc-Profiles"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	copyMachineUserProfiles
	getAdvFWmonitor _Stop_
	getNetcfg _Stop_
	FwAddRegItem @("802Dot1x", "MBN", "Tcp", "TLS","WinHTTP") _Stop_
	($EvtLogsMBN) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_MdmLog {
	EnterFunc $MyInvocation.MyCommand.Name
	$MDM_LOG_DIR = $DirRepro + "\DeviceManagement_and_MDM"
	FwCreateFolder $MDM_LOG_DIR 
	$RegExportKeyInTxt = @(  #Key, ExportFile, Format (TXT or REG)
		@("HKLM\Software\Microsoft\Enrollments", "$PrefixTime`reg_MDMEnrollments.txt", "TXT"),
		@("HKLM\Software\Microsoft\EnterpriseResourceManager", "$PrefixTime`reg_MDMEnterpriseResourceManager.txt", "TXT"),
		@("HKLM\Software\Microsoft\PolicyManager", "$PrefixTime`reg_MDMPolicyManager.txt", "TXT"),
		@("HKCU\Software\Microsoft\SCEP", "$PrefixTime`reg_MDMSCEP-User.txt", "TXT"),
		@("HKU\S-1-5-18\Software\Microsoft\SCEP", "$PrefixTime`reg_MDMSCEP-SystemUser.txt", "TXT")
	)
	ForEach ($regTxtExport in $RegExportKeyInTxt){
		global:FwExportRegKey $regTxtExport[0] $regTxtExport[1] $regTxtExport[2]
	}
	FwAddRegItem @("MDM") _Stop_
	($EvtLogsMDManalytic) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	If(($OperatingSystemInfo.OSVersion -eq 10) -and !($global:IsServerCore)){
		LogInfo "[$($MyInvocation.MyCommand.Name)] .. running `'MdmDiagnosticsTool -out $MDM_LOG_DIR`' at _Stop_"
		$Commands = @(
			"wevtutil query-events Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin /format:text >$MDM_LOG_DIR\DevMgmtEventLog.txt"
			"MdmDiagnosticsTool.exe -out $MDM_LOG_DIR"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_MdmScenarioLog {
	if (!$MDM_LOG_DIR) {
		EnterFunc $MyInvocation.MyCommand.Name
		CollectNET_MdmLog
		EndFunc $MyInvocation.MyCommand.Name
	}
}

function NET_MFAextPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("MFAext") _Start_
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] enabling tracing for MFAext" -ShowMsg
	FwAddRegValue "HKLM\Software\Microsoft\AzureMfa" "VERBOSE_LOG" "REG_SZ" "TRUE"
#	if (!$global:noRestart.IsPresent -or $global:noRestart -ne $True) { 
	if ($global:noRestart -ne $True) {
		$IASsvcStatus = (Get-Service -Name "IAS" -ErrorAction Ignore).status
		writeTesting "___Status IAS: $IASsvcStatus"
		if ($IASsvcStatus -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
			LogWarn "*** re-starting NPS - IAS service ***" "Cyan"
			Restart-Service -Name "IAS" -Force
		} else { LogWarn "*** NPS - IAS service is not running on this system ***"}
	}
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] *** [Hint] https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-nps-extension#troubleshooting" "Cyan" -ShowMsg
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_MFAextPostStop {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] disabling tracing for MFAext" -ShowMsg
	FwAddRegValue "HKLM\Software\Microsoft\AzureMfa" "VERBOSE_LOG" "REG_SZ" "FALSE"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_MFAextLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("MFAext") _Stop_
	($EvtLogsMFAext) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	$Commands = @(
		"wevtutil.exe epl System /q:'*[System[TimeCreated[timediff(@SystemTime) <= 7200000]]]' $PrefixTime`evt_System_SRV.evtx /ow"
		"wevtutil.exe epl /sq:true $DirScript\config\tss_nps-filter.txt $PrefixTime`evt_NPS.evtx /ow"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
	
}
function CollectNET_MiracastLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("802Dot1x", "Miracast", "Firewall") _Stop_ 
	($EvtLogs802dot1x) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting 'netsh wlan show Driver' at $TssPhase" -ShowMsg
	$Commands = @(
		"Netsh Wlan Show Driver | Out-File -Append $PrefixTime`WlanShowDriver_$TssPhase.xml"
	)
	copyWLANProfiles
	getFWRules _Stop_
	FwGetGPresultAS _Stop_
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_NCSIPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "*** [Hint] NCSI: when collecting iDNA, you need to take both Nlasvc and WinHttpAutoProxySvc (for Win11: use NetProfM)" "Cyan"
	FwSetEventLog $EvtLogsNcsiNla
	FwSetEventLog $EvtLogsNcsiAnalytic
	getNCSIinfo _Start_
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_NCSILog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwResetEventLog $EvtLogsNcsiNla
	FwResetEventLog $EvtLogsNcsiAnalytic
	($EvtLogsNcsiNla, $EvtLogsNcsiAnalytic, "Security") | ForEach-Object { FwAddEvtLog $_ _Stop_}
	getFWlogs _Stop_
	FwAddRegItem @("NlaNCSI", "LDAPcli") _Stop_
	getNCSIinfo _Stop_
	FwGetProxyInfo _Stop_
	FwGetCertsInfo _Stop_ Basic
	FwGetGPresultAS _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_NetlogonPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. Enabling Netlogon service debug log DbFlag:$global:NetLogonFlag" -ShowMsg
	FwAddRegValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" "DbFlag" "REG_DWORD" "$global:NetLogonFlag"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_NetlogonLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. Disabling Netlogon service debug log, copying $env:SystemRoot\debug" -ShowMsg
	FwAddRegValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" "DbFlag" "REG_DWORD" "0x0"
	$Commands = @(
			"xcopy /s/e/i/q/y $env:SystemRoot\debug $global:LogFolder\WinDir-debug"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_NetsetupLog {
	EnterFunc $MyInvocation.MyCommand.Name
	$Commands = @(
		"xcopy /y $env:SystemRoot\logs\NetSetup\* $global:LogFolder\NetSetup\"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_NetViewScenarioLog {
	EnterFunc $MyInvocation.MyCommand.Name
	if (($PSVersionTable.psversion.ToString() -ge "5.0") -and ($global:skipNetview -ne $true)) {
		if (Test-Path -path "$global:ScriptFolder\psSDP\Diag\global\GetNetView.ps1") {
			LogInfoFile "--- $(Get-Date -Format 'HH:mm:ss') ...Collecting Get-NetView Diagnostics Data"
			& "$global:ScriptFolder`\psSDP\Diag\global\GetNetView.ps1" -OutputDirectory $global:LogFolder
			# Scrub out #ToDo# remove folder or zip after successful run?
			#ToDo# Write-Host " ____ Remove-Item $global:LogFolder\msdgb.*.zip"
			#ToDo# Remove-Item $global:LogFolder\msdgb.*.zip -Force -ErrorAction SilentlyContinue
			LogInfoFile "--- $(Get-Date -Format 'HH:mm:ss') ...Finished Get-NetView Diagnostics Data" -ShowMsg
		} else { LogWarn "Script GetNetView.ps1 not found!" cyan} 
	} else { LogWarn "Get-NetView requires PowerShell v5.0 for proper data collection!" cyan}
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_NFScliLog {
	EnterFunc $MyInvocation.MyCommand.Name
	($global:EvtLogsNFScli, $global:EvtLogsNFScliW8) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	$outFile = $PrefixTime + "NfsClientConfiguration_pscmdlets.txt"
	$Commands = @(
		"Get-NfsClientConfiguration | fl * |Out-file -Append -Encoding ascii -Width 500 $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	FwGetGPresultAS _Stop_
	FwPlaySound
	LogInfo "[NfsMappedIdentity] Next step will ask for Windows AccountName to test, please enter a valid SAMAccountName" "Cyan"
	FwDisplayPopUp 5 "[NfsMappedIdentity]"
	$Answer = FwRead-Host-YN -Message "Press Y for Yes = asks for NfsMappedIdentity AccountName, N for No (timeout=60s)" -Choices 'yn' -TimeOut 60
	LogInfoFile "[NfsMappedIdentity]: User provided answer: YN] $Answer" -ShowMsg
	If($Answer){
		LogInfo "AccountName specifies the SAMAccountName of the Windows user account or group account of a mapped identity." "Gray"
		$nfs_user = Read-Host -Prompt "Please enter AccountName, or hit ENTER to skip this step"
		LogInfoFile "[NfsMappedIdentity AccountName]: User provided answer:] $nfs_user" -ShowMsg
		$outFile = $PrefixTime + "NfsMappedIdentity_pscmdlets_Stop_.txt"
		$Commands = @(
			"Test-NfsMappedIdentity -AccountName `"$nfs_user`" -AccountType `"User`"  -Verbose -ErrorAction SilentlyContinue 2>&1 >> $outFile "
			"Test-NfsMappedIdentity -AccountName `"$nfs_user`" -AccountType `"Group`" -Verbose -ErrorAction SilentlyContinue 2>&1 >> $outFile "
			)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_NFSsrvPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	if (Test-path "HKLM:\System\CurrentControlSet\Services\NfsServer") {
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] Set-NfsServerConfiguration -LogActivity All" -ShowMsg
		$Commands = @(
			"Set-NfsServerConfiguration -LogActivity All"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	} else {LogInfo "[$($MyInvocation.MyCommand.Name)] NFS server is not running on this machine" "Magenta"}
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_NFSsrvLog {
	EnterFunc $MyInvocation.MyCommand.Name
	if (Test-path "HKLM:\System\CurrentControlSet\Services\NfsServer") { # only run if role=NFS server
		($global:EvtLogsNFScli, $global:EvtLogsNFSsrv) | ForEach-Object { FwAddEvtLog $_ _Stop_}
		if ($global:OSVersion.Build -lt 10240) { # downlevel OS
			$outFile = $PrefixTime + "NfsServer_NfsAdmin_cmds_Stop_.txt"
			$Commands = @(
				"nfsadmin server config 	| Out-File -Append $outFile"
				"nfsadmin mapping config 	| Out-File -Append $outFile"
				"nfsadmin server listgroups | Out-File -Append $outFile"
				"nfsadmin server listmembers | Out-File -Append $outFile"
				"nfsadmin server -l 		| Out-File -Append $outFile"
				"nfsstat 		| Out-File -Append $PrefixTime`NfsStat.txt"
				"nfsshare 		| Out-File -Append $PrefixTime`NfsShare.txt"
				"showmount -a	| Out-File -Append $PrefixTime`Showmount-a.txt"
				"showmount -e	| Out-File -Append $PrefixTime`Showmount-e.txt"
				"showmount -d 	| Out-File -Append $PrefixTime`Showmount-d.txt"
				)
			RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		}
		else { #Win10+
			LogInfoFile "[$($MyInvocation.MyCommand.Name)] Set-NfsServerConfiguration -LogActivity None" -ShowMsg
			$Commands = @(
				"Set-NfsServerConfiguration -LogActivity None"
			)
			RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
			$outFile = $PrefixTime + "NfsServer_pscmdlets_Stop_.txt"
			"Get-NfsServerConfiguration","Get-NfsStatistics","Get-NfsMappingStore","Get-NfsShare","Get-NfsOpenFile","Get-NfsSession","Get-NfsMountedClient","Get-NfsClientgroup","Get-NfsClientLock" | ForEach-Object {
				$Commands = @("$_ | fl * | Out-File -Append -Width 500 $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
			$outFile = $PrefixTime + "NfsMappedIdentity-AccountType-Group_Stop_.txt"
			$Commands = @("Get-NfsMappedIdentity -AccountType Group | fl * | Out-File -Append -Width 500 $outFile")
			RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
			$outFile = $PrefixTime + "NfsSharePermission_Stop_.txt"
			$Commands = @("Get-NfsShare | Get-NfsSharePermission | fl * | Out-File -Append -Width 500 $outFile")
			RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		}
		RunNET_NFSsrvPerm
	} else {LogInfo "[$($MyInvocation.MyCommand.Name)] NFS server is not running on this machine" "Magenta"}
	EndFunc $MyInvocation.MyCommand.Name
}
function RunNET_NFSsrvPerm{
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:Mode -iMatch "Permission") {
		FwPlaySound
		LogInfo "*** Next two steps: Please enter first a NFS-FOLDER-path then second a FILE-path - or hit [ENTER] to skip Permission step" "Cyan"
		$NFSfolder = Read-Host -Prompt "Please enter location of NFS FOLDER, i.e. C:\NFSshare , or hit ENTER to skip this step"
		if(Test-Path $NFSfolder) { LogInfoFile " Folder $NFSfolder exists"}else{ LogInfoFile " Folder $NFSfolder does not exist"}
		LogInfoFile "[NFS FOLDER: User provided answer:] $NFSfolder" -ShowMsg
		$NFSfile = Read-Host -Prompt "Please enter NFS FILE-name, i.e. C:\NFSshare\file1.txt , or hit ENTER to skip this step"
		if(Test-Path $NFSfile) { LogInfoFile " File $NFSfile exists"}else{ LogInfoFile " File $NFSfile does not exist"}
		LogInfoFile "[NFS FILE-name: User provided answer:] $NFSfile" -ShowMsg
		($NFSfolder, $NFSfile) | ForEach-Object { 
			LogInfoFile "... collecting permission settings for $_ " -ShowMsg
			If(!([String]::IsNullOrEmpty($_))) {
				$outFile = $PrefixTime + "NFS_permissions_stop_.txt"
				$Commands = @(
					"icacls.exe $_		| Out-File -Append $outFile"
				)
				if (Test-path "HKLM:\System\CurrentControlSet\Services\NfsServer") {$Commands += @("nfsfile.exe /v $_	| Out-File -Append $outFile")}
				if (!$global:IsLiteMode){ # ToDo: try icacls.exe instead
					if ($NFSfolder -eq $_) { $Commands += @("AccessChk.exe -nobanner /AcceptEula -ld $_ | Out-File -Append $outFile")}
					if ($NFSfile -eq $_)   { $Commands += @("AccessChk.exe -nobanner -v $_ | Out-File -Append $outFile")}
				}else{ LogInfoFile "Skipping AccessChk in Lite mode" -ShowMsg}
				RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_NLBPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwSetEventLog "Microsoft-Windows-NLB/Diagnostic"
	$Commands = @("Arp.exe -a | Out-File -Append $PrefixTime`Arp-table_Start_.txt")
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_NLBLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwGetMsInfo32 "nfo" _Stop_
	FwResetEventLog "Microsoft-Windows-NLB/Diagnostic"
	FwAddRegItem @("WLBS") _Stop_
	$outFile = $PrefixTime + "WLBS-display_Stop_.txt"
	$Commands = @(
		"WLBS display | Out-File -Append $outFile"
		"Arp.exe -a | Out-File -Append $PrefixTime`Arp-table_Stop_.txt"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	FwWaitForProcess $global:msinfo32NFO 300
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_NPSPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	if (Get-Service -Name "IAS"  -ErrorAction Ignore) {
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] [Info] Process/Service name for NPS service is 'IAS'" -ShowMsg
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] . enabling NPS logging 'netsh NPS set tracing *=verbose'" -ShowMsg
		$Commands = @("netsh nps set tracing *=verbose")
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		FwSetMCF disable
		#Start_Netlogon
	} else { LogWarn "[$($MyInvocation.MyCommand.Name)] [Info] This is not an NPS server,Service 'IAS' not found"}
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_NPSPostStop {
	EnterFunc $MyInvocation.MyCommand.Name
	("Security") | ForEach-Object { FwAddEvtLog $_ _Stop_}
	if (Get-Service -Name "IAS"  -ErrorAction Ignore) {
		#Stop_Netlogon
	}
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_NPSLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("NPS","RAS","LDAPcli","TLS","WinHTTP") _Stop_
	if (Get-Service -Name "IAS"  -ErrorAction Ignore) {
		$Commands = @(
			"netsh nps set tracing *=none"
			"netsh nps show config | Out-File -Append $PrefixTime`NPS-config.txt"
			"netsh nps export filename=$PrefixTime`NPS-export.xml exportPSK=YES "
			"xcopy /s/e/i/q/y $Sys32\LogFiles\NPS $global:LogFolder\NPS"
			)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}
	FwSetMCF enable
	FwGetCertsInfo _Stop_ Basic
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_OutlookPreStart{ 
	EnterFunc $MyInvocation.MyCommand.Name
	If(Test-Path "$env:temp\Outlook Logging") {Get-ChildItem "$env:temp\Outlook Logging\*" -Recurse | Remove-Item }
	If(!($global:BoundParameters.ContainsKey('NET_LDAPcli'))){
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] ** [Info] consider to add tracing: -NET_LDAPcli (_LDAPcliProcess=Outlook.exe)" "Cyan" -ShowMsg
	}
	LogInfoFile " . defining registry key EnableETWLogging=1 for Outlook 16.0 OL2016, OL2019, o365; (reqires restarting Outlook)" -ShowMsg
	LogInfoFile "For manual config: Outlook: File -> Options -> Advanced -> tick the [x] 'Enable troubleshooting logging (requires restarting Outlook)' option in Other section"
	"16.0","15.0" | ForEach-Object {
		FwAddRegValue "HKCU\Software\Microsoft\Office\$_\Outlook\Options\Mail" "EnableLogging" "REG_DWORD" "1"
		FwAddRegValue "HKCU\Software\Microsoft\Office\$_\Outlook\Options\Mail" "EnableETWLogging" "REG_DWORD" "1"
		FwAddRegValue "HKCU\Software\Policies\Microsoft\Office\$_\Outlook\Options\Shutdown" "FastShutdownBehavior" "REG_DWORD" "2"
	}
	FwPlaySound
	LogInfo "*** Next Step: Please do a manual RESTART of Outlook - required now for activating ETW logging before Repro" "Cyan"
	LogInfo "Note if you see an error starting Outlook .ost, wait a minute and try again." "Gray"
	$Answer = FwRead-Host-YN -Message "Did you restart Outlook now? " -Choices 'yn'
	If(!$Answer) {
		LogWarn "* ... continue without OL logging"
	} else {
		LogInfo "*** OL logging will be enabled after OL restart" "Green"
	}
	LogInfoFile "--- $(Get-Date -Format 'HH:mm:ss') [User provided Outlook-Restart Answer: Y=True N=False : $Answer ]"
	## call :DoLogmanStartUpd ms_Outlook {4B845F60-45F7-4D75-9D48-C52DA75395A6}
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_OutlookLog{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[Info] ... resetting Outlook Debug Reg Keys to default" -ShowMsg
	"16.0","15.0" | ForEach-Object {
		FwDeleteRegValue "HKCU\Software\Microsoft\Office\$_\Outlook\Options\Mail" "EnableLogging"
		FwDeleteRegValue "HKCU\Software\Microsoft\Office\$_\Outlook\Options\Mail" "EnableETWLogging"
		FwDeleteRegValue "HKCU\Software\Policies\Microsoft\Office\$_\Outlook\Options\Shutdown" "FastShutdownBehavior"
	}
	LogInfo " .. copying $env:temp\Outlook Logging\ folder"
	$Commands = @(
		"xcopy /i/q/y ""$env:temp\Outlook Logging"" $DirRepro\OutlookLogging"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	# Future consider: Engineer will never think to look in logfile to get this message.
	#                  Customer will never tell engineer about it even if displayed on console
	#                  Think about another way to alert engineer about this
	LogInfoFile "*** Hint for engineer: Decode Outlook ETL with Timber" -ShowMsg
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_OpenSSHPostStart { 
	EnterFunc $MyInvocation.MyCommand.Name
	("sshd") | ForEach-Object {
		if (Get-Service -Name $_ -ErrorAction SilentlyContinue){
			LogInfoFile "... collecting sshd_Service info and running PsGetSID $_ at $global:TssPhase" -ShowMsg
			$Commands = @(
			 "Get-Service -Name $_ | fl * | Out-File -Append $PrefixCn`sshd_Service_$global:TssPhase.txt"
			 "PsGetSID.exe $_ /AcceptEula | Out-File -Append $PrefixCn`sshd_PsGetSID_$global:TssPhase.txt"
			 )
			RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		}
	}	
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_OpenSSHLog{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. Copy sshd_config and ssh config files" -ShowMsg
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(
		@("$Env:ProgramData\ssh\sshd_config", "$PrefixCn`sshd_config"),
		@("$Env:ProgramData\ssh\sshd_config_default", "$PrefixCn`sshd_config_default"),
		@("$Env:ProgramData\ssh\administrators_authorized_keys", "$PrefixCn`ssh_administrators_authorized_keys"),
		@("$Env:userprofile\.ssh\config", "$PrefixCn`SshUserProfile_config"),
		@("$Env:userprofile\.ssh\authorized_keys", "$PrefixCn`SshUserProfile_authorized_keys")
	)
	FwCopyFiles $SourceDestinationPaths -ShowMessage:$False

	("$Env:ProgramData\ssh\administrators_authorized_keys") | ForEach-Object {
		LogInfoFile "... collecting permission settings for $_ " -ShowMsg
		If(!([String]::IsNullOrEmpty($_))) {
			$outFile = $PrefixTime + "ssh_administrators_authorized_keys_permissions.txt"
			$Commands = @(
				"icacls.exe $_		| Out-File -Append $outFile"
			)
			if (!$global:IsLiteMode){
				$Commands += @("AccessChk.exe -nobanner -v $_ | Out-File -Append $outFile")
			}else{ LogInfoFile "Skipping AccessChk in Lite mode" -ShowMsg}
			RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		}
	}
	("sshd","ssh-agent") | ForEach-Object {
		if (Get-Service -Name $_ -ErrorAction SilentlyContinue){
			LogInfoFile "... collecting ssh_Services info and running PsGetSID $_ at $global:TssPhase" -ShowMsg
			$Commands = @(
			 "Get-Service -Name $_ | fl * | Out-File -Append $PrefixCn`ssh_Services_$global:TssPhase.txt"
			 "PsGetSID.exe sshd /AcceptEula | Out-File -Append $PrefixCn`sshd_PsGetSID_$global:TssPhase.txt"
			 )
			RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		}
	}
	FwAddRegItem @("OpenSSH") _Stop_
	($global:EvtLogsOpenSSH) | ForEach-Object { FwAddEvtLog $_ _Stop_}

	if(Test-Path "$Env:ProgramData\ssh") {
		LogInfoFile ".. copying files from $Env:ProgramData\ssh\" -ShowMsg
		$Commands = @(
			"robocopy $Env:ProgramData\ssh $global:LogFolder\SSH_folder /S /E /R:0 /MT /NP /LOG:$global:LogFolder\SSHfolder_Robocopy.log"
			)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	} else {LogInfoFile "No files found in $Env:ProgramData\ssh\Logs"}
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_PCILog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] collecting PCI, setupapi and msinfo32 infos"
	FwAddRegItem @("PCI") _Stop_
	$Commands = @(
		"xcopy /y $env:SystemRoot\inf\setupapi* $global:LogFolder\setupapi\"
		"xcopy /y $env:SystemRoot\logs\pci* $global:LogFolder\pci\"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	FwGetMsInfo32 "nfo" _Stop_
	FwGetNetAdapter _Stop_
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting PowerShell 'Get-Hotfix'" -ShowMsg
	Get-Hotfix | Export-Csv "$global:LogFolder\$env:COMPUTERNAME`_$([environment]::_OSVERsion.Version -join '.')`_hotfixes.csv" -NoTypeInformation -Force
	LogInfo "[$($MyInvocation.MyCommand.Name)] collecting PoSh System File Versions"
	$result = Get-ChildItem "$Sys32\drivers\*" -Include @('*.sys') | foreach-object { New-Object psobject -Property @{Name = $_.Name; BaseName = $_.BaseName; FullName = $_.FullName; DateModified = $_.LastWriteTime; Version = $_.VersionInfo.FileVersion; Length = $_.length; } }
	$result | Export-Csv "$global:LogFolder\$env:COMPUTERNAME`_$([environment]::_OSVERsion.Version -join '.')`_FileVer-Sys.csv" -NoTypeInformation -Force

	$result = Get-ChildItem "$Sys32\*" -Include @('*.dll','*.sys','*.exe') | foreach-object { New-Object psobject -Property @{Name = $_.Name; BaseName = $_.BaseName; FullName = $_.FullName; DateModified = $_.LastWriteTime; Version = $_.VersionInfo.FileVersion; Length = $_.length; } }
	$result | Export-Csv "$global:LogFolder\$env:COMPUTERNAME`_$([environment]::_OSVERsion.Version -join '.')`_FileVer-exe-dll.csv" -NoTypeInformation -Force
	# wait for completion, if -collectLog NET_PCI
	FwWaitForProcess $global:msinfo32NFO 300
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_PerflibLog {
	EnterFunc $MyInvocation.MyCommand.Name
	.\scripts\tss_Perf-Collect.ps1 -Folderpath $global:LogFolder
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_PnPLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] exporting PNP info"
	$outFile = $PrefixTime + "PnP_info_Stop_.txt"
	"/enum-devices /problem","/enum-devices" | ForEach-Object { 
		$Commands = @("pnputil.exe $_ | Out-File -Append $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_PortProxyPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] Consider collecting ProcDump:IpHlpSvc as well" -ShowMsg
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_PortProxyLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("PortProxy") _Stop_
	$outFile = $PrefixTime + "PortProxy_Stop_.txt"
	$Commands = @(
		"netsh interface portproxy show all | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

<#function CollectNET_PowerShellLog {
	EnterFunc $MyInvocation.MyCommand.Name
	($global:EvtLogsPowerShell) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	EndFunc $MyInvocation.MyCommand.Name
}
## Garabier : Moved to UEX
#>

function NET_PrintSvcPreStart {
	UEX_PrintPreStart 
<#	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo " .. collecting BuildLab Registry settings"
	$RegKeys = @(
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'BuildLab', "$PrefixCn`Reg_BuildInfo.txt"),
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'BuildLabEx', "$PrefixCn`Reg_BuildInfo.txt"),
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'EditionId', "$PrefixCn`Reg_BuildInfo.txt"),
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'InstallationType', "$PrefixCn`Reg_BuildInfo.txt"),
		('HKLM:Software\Microsoft\SQMClient', 'MachineId', "$PrefixCn`Reg_BuildInfo.txt"),
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'UBR', "$PrefixCn`Reg_BuildInfo.txt"),
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'ProductName', "$PrefixCn`Reg_BuildInfo.txt"),
		('HKLM:Software\Microsoft\Windows\CurrentVersion\AppModel', 'Version', "$PrefixCn`Reg_BuildInfo.txt"),
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion\Print\PrinterExtensionAssociations', "$PrefixCn`Reg_BuildInfo.txt")
	)
	FwExportRegistry "BuildInfo" $RegKeys -ShowMessage:$False
	$outFile = $PrefixTime + "Printerdriver_Start_.txt"
	$Commands = @(
		"REG QUERY `"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\PrinterExtensionAssociations`" /s | Out-File -Append $outFile"
		"get-printer -full |fl; get-printerdriver |fl | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
	#>
}

function CollectNET_PrintSvcLog {
	CollectUEX_PrintLog
<#	EnterFunc $MyInvocation.MyCommand.Name
	$outFile = $PrefixTime + "Printerdriver_Stop_.txt"
	$Commands = @(
	"get-printer -full |fl; get-printerdriver |fl | Out-File -Append $outFile"
	"REG QUERY `"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\PrinterExtensionAssociations`" /s | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. Copy WiaTrace"
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths.add(@("$Env:windir\debug\WIA\wiatrace.log", "$PrefixCn`wiatrace.log"))
	FwCopyFiles $SourceDestinationPaths -ShowMessage:$False
	LogInfo " .. collecting inf\setupapi*.log"
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. Copy upgrade logs"
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(
		@("$Env:windir\inf\setupapi.app.log", "$PrefixCn`setupapi.app.log"),
		@("$Env:windir\inf\setupapi.dev.log", "$PrefixCn`setupapi.dev.log"),
		@("$Env:windir\inf\setupapi.offline.log", "$PrefixCn`setupapi.offline.log"),
		@("$Env:windir\inf\setupapi.setup.log", "$PrefixCn`setupapi.setup.log"),
		@("$Env:windir\inf\setupapi.upgrade.log", "$PrefixCn`setupapi.upgrade.log")
	)
	FwCopyFiles $SourceDestinationPaths -ShowMessage:$False
	FwAddRegItem @("Print") _Stop_
	($global:EvtLogsPrintSvc) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	EndFunc $MyInvocation.MyCommand.Name
	#>
}

function NET_ProxyPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwSetEventLog $EvtLogsProxyAnalytic
	FwGetProxyInfo _Start_
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_ProxyLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwResetEventLog $EvtLogsProxyAnalytic
	("Microsoft-Windows-WinHttp/ProxyConfigChanged") | ForEach-Object { FwAddEvtLog $_ _Stop_}
	($EvtLogsProxyAnalytic)  | ForEach-Object { FwAddEvtLog $_ _Stop_}
	FwGetProxyInfo _Stop_
	FwGetCertsInfo _Stop_ Basic
	getNetSh-http-show-UrlAcl _Stop_
	# Future consider: Engineer will never think to look in logfile to get this message.
	#                  Customer will never tell engineer about it even if displayed on console
	#                  Think about another way to alert engineer about this
	LogInfo "*** Hint: consider using \BIN\WinHTTPDiag.exe for more Proxy troubleshooting ***" "Cyan"
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_QoSPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwSetEventLog $EvtLogsQoSAnalytic
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_QoSLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwResetEventLog $EvtLogsQoSAnalytic
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting NetQosPolicy info, using PS command: Get-NetQosPolicy" -ShowMsg
	FwAddRegItem @("QoS") _Stop_
	$outFile = $PrefixTime + "NetQosPolicy.txt"
	$Commands = @(
		"Get-NetQosPolicy | Out-File -Append -Encoding ascii -Width 500 $outFile" # Get-NetQosPolicy -PolicyStore "ActiveStore"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	($EvtLogsQoSAnalytic) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_RAmgmtPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)]  . defining Debug Flags for DAsrv/RaMgmtSvc" -ShowMsg
	FwAddRegValue "HKLM\System\CurrentControlSet\Services\RaMgmtSvc\Parameters" "DebugFlag" "REG_DWORD" "0xffffffff"
	FwAddRegValue "HKLM\System\CurrentControlSet\Services\RaMgmtSvc\Parameters" "EnableTracing" "REG_DWORD" "0x5"
	LogInfo "*** RaMgmtSvc SERVICE RESTART may be NEEDED. Attention, this can cause DA client interruptions for 60 sec ***"
	if ($global:noRestart -ne $True) {
		FwPlaySound
		$RaMgmtSvcStatus = (Get-Service -Name "RaMgmtSvc" -ErrorAction SilentlyContinue).status
		writeTesting "___Status RaMgmtSvc: $RaMgmtSvcStatus"
		if ($RaMgmtSvcStatus -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
			Write-Host "[Action] Do you want to RESTART the RaMgmtSvc now, please answer Y or N"
			CHOICE /T 30 /C yn /D n /M " Press Y for Yes = do RESTART, N for No"
			If($LASTEXITCODE -eq 1){
				LogInfoFile "--- $(Get-Date -Format 'HH:mm:ss') ...continue with Restart of RaMgmtSvc"
				LogWarn "*** re-starting RaMgmtSvc service now ***" cyan
				Restart-Service -Name "RaMgmtSvc" -Force
			} else { LogInfo " ...continue WITHOUT Restart of RaMgmtSvc" }
		} else { LogWarn "*** RaMgmtSvc service is not running on this system now ***" cyan}
	}
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_RAmgmtLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)]  [Info] ... resetting RaMgmtSvc Reg Keys to default" -ShowMsg
	FwDeleteRegValue "HKLM\System\CurrentControlSet\Services\RaMgmtSvc\Parameters" "DebugFlag"
	FwDeleteRegValue "HKLM\System\CurrentControlSet\Services\RaMgmtSvc\Parameters" "EnableTracing"
	LogInfo "[$($MyInvocation.MyCommand.Name)] [Info] ... Converting RaMgmtSvc.etl using  command: netsh trace convert input=RaMgmtSvc.etl output=RaMgmtSvc.txt"
	$Commands = @(
		"netsh trace convert input=$env:SystemRoot\tracing\RaMgmtSvc.etl output=$env:SystemRoot\tracing\RaMgmtSvc.txt"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	FwCopyWindirTracing RaMgmt
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_RASPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	getIProuting _Start_
	FwSetMCF disable
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_RASLog {
	EnterFunc $MyInvocation.MyCommand.Name
	getIProuting _Stop_
	FwSetMCF enable
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting RAS dump 'netsh ras dump'" -ShowMsg
	$outFile = $PrefixTime + "RAS-Dump.txt"
	$Commands = @(
		"netsh ras dump | Out-File -Append $outFile "
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	($EvtLogsRAS) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	FwAddRegItem @("RAS", "LDAPcli", "TLS","WinHTTP") _Stop_
	if ($global:OSVersion.Build -ge 10240) {
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] PScmdlets for AlwaysOn VPN: Get-VpnAuthProtocol info at _Stop_" -ShowMsg
		$outFile = $PrefixTime + "Vpn_info_pscmdlets.txt"
		$Commands = @(
			"Get-VpnAuthProtocol | Out-File -Append $outFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}
	FwGetCertsInfo _Stop_ Basic
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_RDMALog {
	EnterFunc $MyInvocation.MyCommand.Name
	$outFile = $PrefixTime + "Netstat-xan_Stop_.txt"
	$Commands = @(
		"NETSTAT -xan | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_RDScommonPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwGetQwinsta
	FwSetEventLog "Microsoft-Windows-CAPI2/Operational" -EvtxLogSize $global:EvtxLogSize -ClearLog
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_RDScommonLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwResetEventLog @("Microsoft-Windows-CAPI2/Operational")
	("Microsoft-Windows-CAPI2/Operational") | ForEach-Object { FwAddEvtLog $_ _Stop_}
	($global:EvtLogsRDS) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	FwGetQwinsta
	FwGetEnv
	FwAddRegItem @("RDS_HKCU_SW_POL", "RDS_HKCU_SW_TSC", "RDS_HKLM_LSA", "RDS_HKLM_PRINT", "RDS_HKLM_SECPROV", "RDS_HKLM_SVC", "RDS_HKLM_SW_POL", "RDS_HKLM_SW_TS", "RDS_HKLM_SW_TSC", "RDS_HKLM_SW_TSL", "RDS_HKLM_TS", "RDS_HKLM_TSCAL") _Stop_
	FwGetGPresultAS
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_RDScliLog {
	EnterFunc $MyInvocation.MyCommand.Name
	($global:EvtLogsRDScli) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_RDSsrvLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddEvtLog "Security" _Stop_
	if ($global:Mode -iMatch "GetFarmdata") {
		$outFile = $PrefixTime + "RDS_GetFarmData" + $global:TssPhase + ".txt"
		.\scripts\tss_GetFarmData.ps1 | Out-file -Append -Encoding ascii $outFile
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_RPCLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting RPC Reg settings at _Stop_" -ShowMsg
	FwAddRegItem @("Rpc") _Stop_
	if (!$global:IsLiteMode){
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting 'RPCdump.exe /v /i, RPCcfg.exe /l, /q' infos at _Stop_" -ShowMsg
		$Commands = @(
			"RPCcfg.exe /l		| Out-File -Append $PrefixTime`RPC-config_Stop_.txt"
			"RPCcfg.exe /q		| Out-File -Append $PrefixTime`RPC-config_Stop_.txt"
			"RPCdump.exe /v /i	| Out-File -Append $PrefixTime`RPC-dump_Stop_.txt"
			)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		# Future consider: Engineer will never think to look in logfile to get this message.
		#                  Customer will never tell engineer about it even if displayed on console
		#                  Think about another way to alert engineer about this
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] [RPC-info} *** [Hint] see https://osgwiki.com/wiki/Rpc_debugging" "Cyan" -ShowMsg
	}else{ LogInfoFile "Skipping RPCcfg.exe,RPCdump.exe in Lite mode" -ShowMsg}
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] ** consider also tests using PortQry.exe" -ShowMsg
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_SBSLScenarioLog { #ToDo remove dummy component NET_SBSL and rename this function to Scenario function
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("CSC", "Tcp", "TLS","WinHTTP") _Stop_
	FwExportRegistry "UNC hardening" $KeysUNChard1 -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_SCCMPreStart { # ToDo: compare with $global:noRestart=1 
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] enable SCCM debug logging" -ShowMsg
	#Get-CimInstance -Namespace root\ccm -class sms_client
	#get-wmiobject -Namespace root\ccm -class sms_client -list | gm
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM\Logging\@GLOBAL" -Name LogEnabled -PropertyType DWORD -Value 1 -Force | Out-Null
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM\Logging\@GLOBAL" -Name LogLevel -PropertyType DWORD -Value 1 -Force | Out-Null
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM\Logging\@GLOBAL" -Name LogMaxHistory -PropertyType DWORD -Value 10 -Force | Out-Null
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM\Logging\@GLOBAL" -Name LogMaxSize -PropertyType DWORD -Value 1024000 -Force | Out-Null
	#$Commands = @("WMIC /NAMESPACE:\\root\ccm PATH SMS_Client CALL SetGlobalLoggingConfiguration TRUE,0,10,1024000 | Out-Null")
	#RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_SCCMPostStop {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] disable SCCM debug logging" -ShowMsg
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM\Logging\@GLOBAL" -Name LogEnabled -PropertyType DWORD -Value 0 -Force | Out-Null
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM\Logging\@GLOBAL" -Name LogLevel -PropertyType DWORD -Value 1 -Force | Out-Null
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM\Logging\@GLOBAL" -Name LogMaxHistory -PropertyType DWORD -Value 5 -Force | Out-Null
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM\Logging\@GLOBAL" -Name LogMaxSize -PropertyType DWORD -Value 250000 -Force | Out-Null
	#$Commands = @("WMIC /NAMESPACE:\\root\ccm PATH SMS_Client CALL ResetGlobalLoggingConfiguration | Out-Null")
	#RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_SCCMLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] copying SCCM debug logs" -ShowMsg
	$Commands = @(
		"xcopy /s/e/i/q/y $Env:SystemRoot\CCM\Logs $global:LogFolder\CCM\Logs\"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

<#function CollectNET_SdnNCLog {
	EnterFunc $MyInvocation.MyCommand.Name
# Deprecating SDN collection.  Main script to alert user to use public scripts
 	getWfpShow _Stop_
#	if (Test-Path $ovsdbPath) {
		$outFile = $PrefixTime + "ovsdb.txt"
		$Commands = @(
			"ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep | Out-File -Append $outFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
#	} else {LogWarn "[$($MyInvocation.MyCommand.Name)] 'ovsdb-client.exe' not found in PATH"}
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] run PowerShell commands: 'Get-NetIPAddress' .. " -ShowMsg
	$outFile = $PrefixTime + "Sdn_NetIP_Stop_.txt"
	"Get-NetIPAddress -IncludeAllCompartments","ipconfig /allcompartments" |ForEach-Object { 
		$Commands = @("$_ | Out-File -Append $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False } 
	EndFunc $MyInvocation.MyCommand.Name
}#>


function NET_SMBcliPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:OSVersion.Build -gt 17763) { FwSetEventLog ($global:EvtLogsSMBcliOpt + $global:EvtLogsSMBcliAnalytic) }
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_SMBcliLog {
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:OSVersion.Build -gt 17763) { FwResetEventLog ($global:EvtLogsSMBcliOpt + $global:EvtLogsSMBcliAnalytic) }
	FwAddRegItem @("CSC", "Rpc", "SMB", "Tcp", "DefenderATP") _Stop_
	FwAddRegItem @("LSA", "MultiMedia") _Stop_ -noRecursive
	FwExportRegistry "UNC hardening" $KeysUNChard1 -ShowMessage:$False
	($global:EvtLogsSMBcli) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	if ($global:OSVersion.Build -gt 17763) { ($global:EvtLogsSMBcliOpt + $global:EvtLogsSMBcliAnalytic) | ForEach-Object { FwAddEvtLog $_ _Stop_}}
	FwGetGPresultAS _Stop_
	FwGetCertsInfo _Stop_ Basic
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] ** [Hint] DFS in combi with CSC: https://docs.microsoft.com/en-gb/archive/blogs/askds/slow-link-with-windows-7-and-dfs-namespaces" "Cyan" -ShowMsg
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_SMBsrvPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:OSVersion.Build -gt 17763) { FwSetEventLog ($global:EvtLogsSMBsrvOpt + $global:EvtLogsSMBsrvAnalytic) }
	getNetFiles _Start_
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_SMBsrvLog {
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:OSVersion.Build -gt 17763) { FwResetEventLog ($global:EvtLogsSMBsrvOpt + $global:EvtLogsSMBsrvAnalytic) }
	#getNetFiles _Stop_
	FwGetGPresultAS _Stop_
	getSMBsrvBinding
	$global:EvtLogsSMBsrv | ForEach-Object { FwAddEvtLog $_ _Stop_}
	if ($global:OSVersion.Build -gt 17763) { $global:EvtLogsSMBsrvOpt | ForEach-Object { FwAddEvtLog $_ _Stop_} }
	FwAddRegItem @("SMBsrv","DefenderATP") _Stop_
	FwAddRegItem @("LSA") _Stop_ -noRecursive
	if (!$global:IsLiteMode){
		# get AccessChk.exe /AcceptEula -nobanner -h -v * (for all Shares)
		$outFile = $PrefixTime + "SMB_SharePermissions.txt"
		$Commands = @("AccessChk.exe -AcceptEula -nobanner -h -v * | Out-File -Append $outFile")
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		RunNET_SMBsrvPerm
	}else{ LogInfoFile "Skipping AccessChk in Lite mode" -ShowMsg}
	EndFunc $MyInvocation.MyCommand.Name
}
function RunNET_SMBsrvPerm{
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:Mode -iMatch "Permission") {
		FwPlaySound
		LogInfo "*** Next two steps: 1. Please enter first a SMB-FOLDER-path then step#2. a FILE-path - or hit [ENTER] to skip Permission step" "Cyan"
		$SMBfolder = Read-Host -Prompt "Please enter location of SMB FOLDER, i.e. C:\SMBshare , or hit ENTER to skip this step"
		LogInfoFile "[RunNET_SMBsrvPerm - SMB FOLDER: User provided answer:] $SMBfolder" -ShowMsg
		If(![String]::IsNullOrEmpty($SMBfolder)){
			if(Test-Path $SMBfolder) { LogInfoFile " Folder $SMBfolder exists"}else{ LogInfoFile " Folder $SMBfolder does not exist"}
			$SMBfile = Read-Host -Prompt "Please enter SMB FILE-name, i.e. C:\SMBshare\file1.txt , or hit ENTER to skip this step"
			LogInfoFile "[RunNET_SMBsrvPerm - SMB FILE-name: User provided answer:] $SMBfile" -ShowMsg
			if(Test-Path $SMBfile) { LogInfoFile " File $SMBfile exists"}else{ LogInfoFile " File $SMBfile does not exist"}
			($SMBfolder, $SMBfile) | ForEach-Object {
				LogInfoFile "... collecting permission settings for $_ " -ShowMsg
				If(!([String]::IsNullOrEmpty($_))) {
					$outFile = $PrefixTime + "SMB_permissions_stop_.txt"
					$Commands = @(
						"icacls.exe $_		| Out-File -Append $outFile"
					)
					if (!$global:IsLiteMode){ # ToDo: try icacls.exe instead
						if ($SMBfolder -eq $_) { $Commands += @("AccessChk.exe -nobanner /AcceptEula -s -ld $_ | Out-File -Append $outFile")}
						if ($SMBfile -eq $_)   { $Commands += @("AccessChk.exe -nobanner -v $_ | Out-File -Append $outFile")}
					}else{ LogInfoFile "Skipping AccessChk in Lite mode" -ShowMsg}
					RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
				}
			}
		}else{
			LogInfoFile "[RunNET_SMBsrvPerm] User did not enter a SMBfolder path."
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_SMBPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	NET_SMBcliPreStart
	NET_SMBsrvPreStart
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_SMBLog {
	EnterFunc $MyInvocation.MyCommand.Name
	CollectNET_SMBcliLog
	CollectNET_SMBsrvLog
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_SMBsrvBindingLog {
	EnterFunc $MyInvocation.MyCommand.Name
	getSMBsrvBinding
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_SNMPLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("SNMP") _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_SQLcheckLog {
	# see https://github.com/microsoft/CSS_SQL_Networking_Tools/wiki/SQLCHECK
	EnterFunc $MyInvocation.MyCommand.Name
	if (!$global:IsLiteMode){
		LogInfo "[$($MyInvocation.MyCommand.Name)] running 'SQL Connectivity Settings Check' (SQLcheck.exe)"
		$outfile = $PrefixTime + "SQLCHECK.log"
		$Commands = @("SQLcheck.exe | Out-File -Append $outFile")
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}else{ LogInfoFile "Skipping SQLcheck.exe in Lite mode" -ShowMsg}
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_TAPILog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwCopyWindirTracing TAPI
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_UNChardScenarioPostStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] ** for -StartAutoLogger: After Reboot wait up to 4 minutes to collect a Good case data-set(?)" Cyan
	LogInfo "[$($MyInvocation.MyCommand.Name)] **  and then Login with same username, and run in elevated PowerShell: '.\TSSv2.ps1 -StopAutoLogger'" Cyan
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_UNChardScenarioLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("CSC", "Tcp", "TLS","WinHTTP") _Stop_
	FwExportRegistry "UNC hardening" $KeysUNChard1 -ShowMessage:$False
	#FwGetGPresultAS _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_VPNPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:Mode -iMatch "Basic"){ LogInfoFile "..running in Mode: $global:Mode - NetshScenario=VPNclient" "Gray" -ShowMsg}
	FwSetEventLog $EvtLogsVPNopt
	FwSetEventLog "Microsoft-Windows-CAPI2/Operational" -EvtxLogSize $global:EvtxLogSize -ClearLog
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_VPNLog {
	EnterFunc $MyInvocation.MyCommand.Name
	#FwResetEventLog $EvtLogsVPNopt
	FwResetEventLog @("Microsoft-Windows-CAPI2/Operational", $EvtLogsVPNopt)
	("Microsoft-Windows-CAPI2/Operational", $EvtLogsVPN, $EvtLogsVPNopt) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	FwAddRegItem @("VPN") _Stop_
	copyMachineUserProfiles
	#($EvtLogsVPN) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	#FwAddEvtLog $EvtLogsVPNopt _Stop_
	if ($global:OSVersion.Build -ge 10240) {
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] PScmdlets for AlwaysOn VPN device/User tunnel: Get-VpnConnection info at _Stop_" -ShowMsg
		$outFile = $PrefixTime + "VpnConnection_info_pscmdlets" + $TssPhase + ".txt"		
		$PScmds = @("Get-VpnConnection","Get-VpnConnection -AllUserConnection","Get-DnsClientNrptRule")
		if ($IsServerSKU) { $PScmds += "Get-NetNatTransitionMonitoring" } # Get-NetNatTransitionMonitoring : This functionality is not supported on client SKUs.
		$PScmds | ForEach-Object { 
		$Commands = @("$_ | Out-File -Append $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
	}
	$outFile = $PrefixTime + "CredentialGuard" + $TssPhase + ".txt"
	$Commands = @(
		"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows/DeviceGuard | Out-File -Append -Encoding ascii $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	if(Test-Path "$Env:LocalAppData\Packages\Microsoft.AzureVpn_8wekyb3d8bbwe\LocalState\LogFiles") {
		LogInfo ".. copying AzureVpn log files"
		FwCreateFolder $global:LogFolder\AzureVpn_log
		$Commands = @(
			"robocopy `"$Env:LocalAppData\Packages\Microsoft.AzureVpn_8wekyb3d8bbwe\LocalState\LogFiles`" $global:LogFolder\AzureVpn_log /E /R:0 /MT /NP /LOG:$global:LogFolder\AzureVpn_Robocopy.log"
			)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	} else {LogInfoFile "No files found in `"$Env:LocalAppData\Packages\Microsoft.AzureVpn_8wekyb3d8bbwe\LocalState\LogFiles`""}
	FwGetCertsInfo _Stop_ Basic
	FwGetProxyInfo _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_WebClientPostStart {
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:Mode -iMatch "Restart") {
		FwRestartInOwnSvc WebClient
	}
	FwPlaySound
	LogWarn "*** Please have open only ONE IE or Edge instance window or Tab and only ONE Windows Explorer instance. ***"
	LogInfo " see also https://techcommunity.microsoft.com/t5/sharepoint-support-blog/troubleshooting-explorer-view-and-mapped-drives-to-sharepoint/ba-p/1185909" "Cyan"
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_WebClientLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwGetProxyInfo _Stop_
	FwAddRegItem @("WebClient", "TLS","WinHTTP") _Stop_
	if (Test-Path $PrefixTime`packetcapture_*.etl) { Move-Item -Path $PrefixTime`packetcapture_*.etl -Destination $DirRepro\nettrace-winhttp-webio.etl}
	FwGetGPresultAS _Stop_
	$WebCliSvcStatus = (get-Service -Name "WebClient" -ErrorAction SilentlyContinue).Status
	if ($WebCliSvcStatus -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
		FwPlaySound
		FwDisplayPopUp 5 "[WebClient]"
		LogWarn "*** Next, Please enter in pop-up window the Web Address of the http target web folder ***" 	#_# TodDo: use TopMost popup-Window!
		LogInfo "This is the http address of SharePoint folder or whatever DAV server http endpoint you are troubleshooting." "Gray"
		LogInfo "Note: InputBox window may be hidden behind other open windows." "Gray"
		.\scripts\tss_MSDavConnection.ps1 -DataPath $global:LogFolder
	}
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_WebCliTTDScenarioLog {
	CollectNET_WebClientLog
}

function NET_WebIOPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwSetEventLog ($global:EvtLogsWebIOAnalytic)
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_WebIOLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwResetEventLog @($global:EvtLogsWebIOAnalytic)
	$global:EvtLogsWebIOAnalytic | ForEach-Object { FwAddEvtLog $_ _Stop_}
	FwGetProxyInfo _Stop_
	getNetSh-http-show-UrlAcl _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_WFPPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwSetEventLog "Microsoft-Windows-WFP/Operational"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_WFPLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwResetEventLog @("Microsoft-Windows-WFP/Operational")
	("Microsoft-Windows-WFP/Operational") | ForEach-Object { FwAddEvtLog $_ _Stop_}
	getFWlogs _Stop_
	getWfpShow _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_WinRMPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwSetEventLog "Microsoft-Windows-WinRM/Analytic"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_WinRMLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwResetEventLog @("Microsoft-Windows-WinRM/Analytic")
	("Microsoft-Windows-WinRM/Operational") | ForEach-Object { FwAddEvtLog $_ _Stop_}
	#FwAddEvtLog "Microsoft-Windows-WinRM/Analytic" _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_WIPPostStart {
	EnterFunc $MyInvocation.MyCommand.Name
	$WIP_DiagRoot = $DirRepro + "\EdpDiagnostics"
	FwCreateFolder $WIP_DiagRoot
	Do_WIP _Start_
	$Commands = @(
		"reg query `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`" /t REG_SZ | Out-File $WIP_DiagRoot\_reg_version.txt"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False	
	$RegKeys = @(
		('HKLM:Software\Microsoft\Windows NT\Currentversion', 'BuildLabEx', "$WIP_DiagRoot\$Env:COMPUTERNAME`_reg_build.txt"),
		('HKLM:Software\Microsoft\Windows NT\Currentversion', 'EditionID', "$WIP_DiagRoot\$Env:COMPUTERNAME`_reg_build.txt")
	)
	FwExportRegistry "WIP-PostStart" $RegKeys
	LogInfo "starting: WPR.exe -start $DirScript\config\WIP_WprProfile.xml!EDPProfile.verbose -filemode"
	$Commands = @("WPR.exe -start $DirScript\config\WIP_WprProfile.xml!EDPProfile.verbose -filemode")
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False	
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_WIPLog {
	EnterFunc $MyInvocation.MyCommand.Name
	$WIP_DiagRoot = $DirRepro + "\EdpDiagnostics"
	$WIPetlpath = $WIP_DiagRoot + "\WPR_EdpProfile_Events.etl"
	LogInfo "stopping: WPR.exe -stop $WIPetlpath"
	$Commands = @("	WPR.exe -stop $WIPetlpath")
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False	
	Do_WIP _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}
function Do_WIP {
	param(
		[Parameter(Mandatory=$True)]
		[String]$TssPhase				# _Start_ or _Stop_
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile ".. running WIP LogPackages $global:TssPhase"
	("AppLocker", "EDP", "EFS", "HTTP", "MDM", "NGC", "Perf", "SMB", "VPN", "WFP") | ForEach-Object {
		$ModuleDir=$WIP_DiagRoot + "\" + $_ 
		$DestDir=$ModuleDir + "\" + $global:TssPhase
		FwCreateFolder $ModuleDir
		if (( $_ -match "AppLocker|EFS|MDM|VPN") -and (!(Test-Path -Path $DestDir ))) { FwCreateFolder $DestDir}
		Write-Host "== WIP $_ $global:TssPhase =================================================================="
		switch ($_)
			{
			"AppLocker" {
				$TMPdir = $Env:Temp +"\" + $_
				$Commands = @(
					"robocopy $Env:Windir\System32\AppLocker $TMPdir\PolicyFiles /E /R:0 /MT /NP /LOG:$DestDir\AppLocker_Robocopy.log"
					"Add-Type -A 'System.IO.Compression.FileSystem'; [IO.Compression.ZipFile]::CreateFromDirectory('$TMPdir\PolicyFiles', '$DestDir\PolicyFiles.zip');"
					"Remove-Item -Recurse -Force $TMPdir\PolicyFiles"
				)
				RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
			}
			"EDP" {
				$DpmCmdPath 			= $global:ScriptFolder + $BinArch + "\DpmCmd.exe"
				$Commands = @("$DpmCmdPath qe all-procs-v | Out-File $ModuleDir\$global:TssPhase`ProcList.txt")
				RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
			}
			"EFS" {
				$Commands = @("$Sys32\certutil.exe -v -silent -user -store my | Out-File -Append $DestDir\UserCertStore-My.txt")
				RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
				LogInfo "======== Exporting EFS Registry settings might take some minutes ... =================="
				$RegKeysOneFile = @(
					'HKLM:Software\Microsoft\Windows NT\CurrentVersion',
					'HKCU:Software\Microsoft\Windows NT\CurrentVersion\EFS\UnenlightenedEnterpriseAppLaunch\corp.microsoft.com',
					'HKCU:System\CurrentControlSet\Services\NTFS\EFS\Parameters',
					'HKCU:Software\Classes\Local Settings\Software\Microsoft\WinMSIPC',
					'HKLM:Software\Microsoft\WinMSIPC',
					'HKLM:Software\Wow6432Node\Microsoft\WinMSIPC',
					'HKLM:Software\Microsoft\EnterpriseDataProtection',
					'HKLM:Software\Microsoft\PolicyManager\current',
					'HKLM:Software\Microsoft\SecurityManager\DeveloperUnlock',
					'HKLM:Software\Microsoft\Windows NT\CurrentVersion\EFS\EdpPolicyFilter',
					'HKLM:Software\Policies\Microsoft\Windows NT\DNSClient',
					'HKLM:Software\Policies\Microsoft\Windows\Appx',
					'HKLM:Software\Policies\Microsoft\Windows\NetworkIsolation ',
					'HKLM:Software\Policies\Microsoft\Windows NT\DNSClient\DNSConfig',
					'HKLM:System\CurrentControlSet\Control\AppID\Configuration\EDP',
					'HKLM:System\CurrentControlSet\Services\Lanmanworkstation\Parameters',
					'HKLM:System\CurrentControlSet\Services\NTFS\EFS\Parameters',
					'HKCU:Software\Microsoft\OneDrive',
					'HKLM:Software\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers',
					'HKCU:Software\Microsoft\Windows NT\CurrentVersion\EFS',
					'HKLM:Software\Microsoft\Windows NT\CurrentVersion\EFS',
					'HKLM:System\CurrentControlSet\Control\Lsa\DPL'
				)
				FwExportRegToOneFile "WIP-EFS" $RegKeysOneFile "$DestDir\_reg_EdpRegKeys.txt"
				$RegKeys = @(
					('HKLM:Software\Microsoft\Windows\CurrentVersion\Internet Setting', 'EdpEnforcementOverride', "$DestDir\_reg_EdpRegKeys.txt"),
					('HKLM:Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Setting', 'EdpEnforcementOverride', "$DestDir\_reg_EdpRegKeys.txt")
				)
				If(FwTestRegistryValue "HKLM:System\CurrentControlSet\Services\EFS" "OefsFlags") {$RegKeys += @( ('HKLM:System\CurrentControlSet\Services\EFS', 'OefsFlags', "$DestDir\_reg_EdpRegKeys.txt") )}
				If(FwTestRegistryValue "HKLM:System\CurrentControlSet\Services\EFS" "OefsTestPoint") {$RegKeys += @( ('HKLM:System\CurrentControlSet\Services\EFS', 'OefsTestPoint', "$DestDir\_reg_EdpRegKeys.txt") )}		
				FwExportRegistry "WIP-EFS" $RegKeys -ShowMessage:$False
				
				if ($global:TssPhase -eq "_Stop_") {
					LogInfo ".. copying WinMSIPC and OneDrive files"
					FwCreateFolder $DestDir\WinMSIPC
					$Commands = @(
						"robocopy `"$Env:LocalAppData\Microsoft\WinMSIPC`" $DestDir\WinMSIPC /E /R:0 /MT /NP /LOG:$DestDir\WinMSIPC_Robocopy.log"
						"robocopy `"$Env:LocalAppData\Microsoft\OneDrive\logs`" $DestDir\OneDrive /E /R:0 /MT /NP /LOG:$DestDir\OneDrive_Robocopy.log"
						)
					RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
					LogInfo ".. copying EDP event logs"
					FwCreateFolder $DestDir\EventLogs
					$Commands = @(
						"copy $Env:WinDir\System32\Winevt\Logs\Microsoft-Windows-EDP-Application-Learning%4Admin.evtx $DestDir\EventLogs"
						"copy $Env:WinDir\System32\Winevt\Logs\Microsoft-Windows-EDP-Audit-Regular%4Admin.evtx $DestDir\EventLogs"
						"copy $Env:WinDir\System32\Winevt\Logs\Microsoft-Windows-EDP-Audit-TCB%4Admin.evtx $DestDir\EventLogs"
						)
					RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
				}
			}

			"HTTP" {
				if ($global:TssPhase -eq "_Start_") {
					Write-Output "$global:TssPhase : NetSh trace is located in TSS main data folder as *packetCapture*.etl" | Out-File -Append "$ModuleDir\netsh.txt"
				}
			}
				
			"MDM" {
				$RegKeysOneFile = @(
					'HKLM:Software\Microsoft\EDPCSP',
					'HKLM:Software\Microsoft\Enrollment',
					'HKLM:Software\Microsoft\Enrollments',
					'HKLM:Software\Microsoft\EnterpriseResourceManager',
					'HKLM:Software\Microsoft\PolicyManager',
					'HKLM:Software\Microsoft\Provisioning',
					'HKCU:Software\Microsoft\SCEP',
					'HKCU:Software\Microsoft\Windows\CurrentVersion\MDM',
					'HKU:S-1-5-21-2702878673-795188819-444038987-2781\Software\Microsoft\SCEP',
					'HKU:S-1-5-21-2702878673-795188819-444038987-2781\Software\Microsoft\EnterpriseModernAppManagement',
					'HKLM:Software\Microsoft\EnterpriseDataProtection'
				)
				FwExportRegToOneFile "WIP-MDM" $RegKeysOneFile "$DestDir\_reg_TraceRegistry.txt"
				$RegKeys = @(
					('HKLM:Software\Microsoft\Windows NT\Currentversion', 'BuildLabEx', "$DestDir\_reg_TraceRegistry.txt"),
					('HKLM:Software\Microsoft\Windows NT\Currentversion', 'EditionID', "$DestDir\_reg_TraceRegistry.txt")
				)
				FwExportRegistry "WIP-MDM" $RegKeys
				If(($OperatingSystemInfo.OSVersion -eq 10) -and !($global:IsServerCore)){
					LogInfo "[MDM] Dump schedule tasks and details for EDP and NetworkIsolation scheduled tasks"
					$Commands = @(
						"wevtutil query-events Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin /format:text >$DestDir\DevMgmtEventLog.txt"
						"MdmDiagnosticsTool.exe -out $DestDir"
						#"MdmDiagnosticsTool.exe -xml $DestDir\TraceDiagnosticsReport.xml -zip $DestDir"
						"schtasks /HRESULT | Out-File $DestDir\scheduletasks.log"
					)
				}
				$taskExists = Get-ScheduledTask | Where-Object {$_.TaskPath -match "EnterpriseDataProtection"}
				if($taskExists) {
					$Commands += @(
						"schtasks /query /tn `"\Microsoft\Windows\EnterpriseMgmt\EnterpriseDataProtection\Enterprise data protection enforcement level change`" /xml one | Out-File $DestDir\EdpConfigurationTaskDetails.log"
						"schtasks /query /tn `"\Microsoft\Windows\EnterpriseMgmt\EnterpriseDataProtection\Enterprise data protection network isolation policy change`" /xml one | Out-File -Append $DestDir\EdpConfigurationTaskDetails.log"
						"schtasks /query /tn `"\Microsoft\Windows\EnterpriseMgmt\EnterpriseDataProtection\Evaluate enterprise data protection configuration`" /xml one | Out-File -Append $DestDir\EdpConfigurationTaskDetails.log"				
						)
				}
				RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
				
				if ($global:TssPhase -eq "_Stop_") {
					$EventLogList=((Get-winevent -ListLog Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider*).LogName)
					FwExportEventLog $EventLogList $ModuleDir
					FwCreateFolder $ModuleDir\CCMLogs
					$Commands = @(
						"robocopy /S $Env:windir\CCM\Logs $ModuleDir\CCMLogs /E /R:0 /MT /NP /LOG:$DestDir\CCMLogs_Robocopy.log"
						"copy `"$Env:programfiles\Microsoft Policy Platform\PolicyPlatformClient.log`" $ModuleDir\PolicyPlatformClient.log"
						)
					RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
				}
				
				LogInfo "Querying current EDP configuration WNFs by running WIP_EDPconfig.ps1 ..."
				.\scripts\WIP_EDPconfig.ps1 -scriptOutputPath $ModuleDir -scriptmode $global:TssPhase
			}
			"NGC" {
				if ($global:TssPhase -eq "_Start_") {
					$RegKeys = @(
						('HKLM:Software\Microsoft\Windows NT\Currentversion', 'BuildLabEx', "$ModuleDir\_reg_build.txt"),
						('HKLM:Software\Microsoft\Windows NT\Currentversion', 'EditionID', "$ModuleDir\_reg_build.txt")
					)
					FwExportRegistry "WIP-NGC" $RegKeys
					if(!(Test-Path "$Env:windir\system32\phone.dll")) {
						$Commands = @(
							"certutil -setreg -f Enroll\Debug 0xffffffe3"
							"certutil -setreg ngc\Debug 1"	
						)
						RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
						#("Microsoft-Windows-Biometrics/Operational", "Microsoft-Windows-Kerberos/Operational", "Microsoft-Windows-AAD/Analytic", "Microsoft-Windows-User Device Registration/Debug") | ForEach-Object { FwEventLogsSet $_ -Enabled:$True -Retention:$True -Quiet:$True -MaxSize:$EvtxLogSize}
						FwSetEventLog $global:EventlogsNGCopt
						$wbiosrvcStatus = (Get-Service -Name "wbiosrvc" -ErrorAction SilentlyContinue).status
						if ($wbiosrvcStatus -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {	Stop-Service -Name "wbiosrvc"}
					}
				}
				if ($global:TssPhase -eq "_Stop_") {
					if(!(Test-Path "$Env:windir\system32\phone.dll")) {
						$Commands = @(
							"certutil -delreg Enroll\Debug"
							"certutil -delreg ngc\Debug"
							"certutil -scinfo -silent | Out-File $ModuleDir\scinfo.txt"
						)
						RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False		
						FwResetEventLog $global:EventlogsNGCopt
						FwExportEventLog ($global:EventlogsNGCopt, "Microsoft-Windows-User Device Registration/Admin", "Microsoft-Windows-AAD/Operational") $ModuleDir
						if(Test-Path "$Env:windir\CertEnroll.log") { Copy-Item $Env:windir\CertEnroll.log $ModuleDir\CertEnrollWindir.log}
						if(Test-Path "$Env:USERPROFILE\CertEnroll.log") { Copy-Item $Env:USERPROFILE\CertEnroll.log $ModuleDir\CertEnrollUserProfile.log}
						if(Test-Path "$Env:LocalAppData\CertEnroll.log") { Copy-Item $Env:LocalAppData\CertEnroll.log $ModuleDir\CertEnrollLocalAppData.log}
						
						$RegKeys = @(
							('HKLM:Software\Microsoft\Windows\CurrentVersion\Authentication', "$ModuleDir\_reg_authentication.txt"),
							('HKLM:Software\Microsoft\Windows\CurrentVersion\Winbio', "$ModuleDir\_reg_winbio.txt"),
							('HKLM:System\CurrentControlSet\Services\WbioSrvc', "$ModuleDir\_reg_wbiosrvc.txt"),
							('HKLM:System\CurrentControlSet\Control\EAS\Policies', "$ModuleDir\_reg_eas.txt"),
							('HKLM:Software\Policies\Microsoft\Biometrics', "$ModuleDir\_reg_policies.txt"),
							('HKCU:Software\Microsoft\SCEP', "$ModuleDir\_reg_scep.txt"),
							('HKLM:Software\Microsoft\SQMClient', "$ModuleDir\_reg_MachineId.txt"),
							('HKLM:Software\Microsoft\Policies\PassportForWork', "$ModuleDir\_reg_NgcPolicyIntune.txt"),
							('HKLM:Software\Policies\Microsoft\PassportForWork', "$ModuleDir\_reg_NgcPolicyGp.txt")
						)
						FwExportRegistry "WIP-NGC" $RegKeys
						
						$SCCM_LOG_DIR="$Env:windir\CCM\Logs"
						if(Test-Path $SCCM_LOG_DIR) {
							$Commands = @(
								"xcopy $SCCM_LOG_DIR\CertEnrollAgent.log $ModuleDir\"
								"xcopy $SCCM_LOG_DIR\StateMessage.log $ModuleDir\"
								)
							RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
						}
						$SCCM_SetupLOG_DIR="$Env:windir\CCMsetup\Logs"
						if(Test-Path $SCCM_SetupLOG_DIR) {
							$Commands = @(
								"xcopy $SCCM_SetupLOG_DIR\ccmsetup.log $ModuleDir\"
								)
							RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False			
						}
						if(Test-Path "$Env:windir\ngc*.log") {
							$Commands = @(
								"xcopy $Env:windir\ngc*.log $ModuleDir\"
								)
							RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False			
						}
						FwGetDSregCmd
					}
				}
			}
			"SMB" {
				if ($global:TssPhase -eq "_Stop_") {
					FwExportEventLog ($global:EvtLogsSMBcli, "WitnessClientAdmin") $ModuleDir
					$Commands = @(
						"reg query `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`" /t REG_SZ | Out-File $ModuleDir\_reg_version.txt"
						"get-date | Out-File $ModuleDir\timestamp.txt"
						)
					RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False	
					Write-Output "$global:TssPhase : services and tasklist outout can be found in TSS main data" | Out-File -Append "$ModuleDir\services_tasklist.txt"
				}
			}
			"VPN" {
				if(Test-Path "$Env:windir\system32\phone.dll") {
					LogInfoFile ".. copy $Env:systemdrive\data" -ShowMsg
					$Commands = @(
						"xcopy /S /H $Env:systemdrive\data\programdata\*.pbk $DestDir"
						"xcopy /S /H $Env:systemdrive\data\Users\*.pbk $DestDir"
					)
					RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
				}
				if(!(Test-Path "$Env:windir\system32\phone.dll")) {
					if(Test-Path "$Env:ProgramData\Microsoft\Network\Connections\Pbk\Rasphone.pbk") {
						LogInfoFile ".. copy $Env:ProgramData\Microsoft\Network\Connections\Pbk\Rasphone.pbk" -ShowMsg
						$Commands = @("Copy-Item  $Env:ProgramData\Microsoft\Network\Connections\Pbk\Rasphone.pbk -Destination $DestDir\AllUserRasphone.pbk -Force")
						RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
						}
					if(Test-Path "$Env:AppData\Microsoft\Network\Connections\Pbk\Rasphone.pbk") {
						LogInfoFile ".. copy $Env:AppData\Microsoft\Network\Connections\Pbk\Rasphone.pbk" -ShowMsg
						$Commands = @("Copy-Item $Env:AppData\Microsoft\Network\Connections\Pbk\Rasphone.pbk -Destination $DestDir\PerUserRasphone.pbk -Force")
						RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
						}
				}
				
				if ($global:TssPhase -eq "_Start_") {
					if(Test-Path "$Env:windir\system32\phone.dll") {
						FwAddRegValue "HKLM\Software\Microsoft\Tracing\svchost_RASAPI32" "EnableFileTracing" "REG_DWORD" "0x1"
						FwAddRegValue "HKLM\Software\Microsoft\Tracing\NetworkUXBroker_RASAPI32" "EnableFileTracing" "REG_DWORD" "0x1"
						FwAddRegValue "HKLM\Software\Microsoft\Tracing\RasMan" "EnableFileTracing" "REG_DWORD" "0x1"
						FwAddRegValue "HKLM\Software\Microsoft\Tracing\RasTapi" "EnableFileTracing" "REG_DWORD" "0x1"
					} else {
						$Commands = @( "NetSh.exe RAS Diagnostics Set RASTracing * Enabled")
						RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
					}
				}
				
				if ($global:TssPhase -eq "_Stop_") {
					if(Test-Path "$Env:windir\system32\phone.dll") {
						FwDeleteRegValue "HKLM\Software\Microsoft\Tracing\svchost_RASAPI32" "EnableFileTracing"
						FwDeleteRegValue "HKLM\Software\Microsoft\Tracing\NetworkUXBroker_RASAPI32" "EnableFileTracing"
						FwDeleteRegValue "HKLM\Software\Microsoft\Tracing\RasMan" "EnableFileTracing"
						FwDeleteRegValue "HKLM\Software\Microsoft\Tracing\RasTapi" "EnableFileTracing"
					} else {
						$Commands = @( "NetSh.exe RAS Diagnostics Set RASTracing * Disabled")
						RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
					}
					$Commands = @( "robocopy /S $Env:windir\Tracing $ModuleDir /E /R:0 /MT /NP /LOG:$ModuleDir\Win-Tracing_Robocopy.log")
					RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
				}
			}
			"WFP" {
				if ($global:TssPhase -eq "_Start_") {
					Write-Output "WFP-data and WFPdiag for scenario NET_WIP are located in TSS main data folder" | Out-File -Append "$ModuleDir\WFP-data.txt"
				}
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function NET_WorkfoldersPrestart{
	EnterFunc $MyInvocation.MyCommand.Name
	if ($IsServerSKU) {
		FwSetEventLog $EvtLogsWorkFoldersSrvAnalytic
	} else {
		FwSetEventLog $EvtLogsWorkFoldersCliAnalytic
	}
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_WorkfoldersScenarioPostStart {
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:Mode -iMatch "Advanced") {
		$WFmode = '-AdvancedMode'
		LogInfoFile " . calling tss_WorkFoldersDiag.ps1 -DataPath $global:LogFolder -Stage 'Start' $WFmode"
		.\scripts\tss_WorkFoldersDiag.ps1 -DataPath $global:LogFolder -Stage "Start" -AdvancedMode
	} else { 
		LogInfoFile " . calling tss_WorkFoldersDiag.ps1 -DataPath $global:LogFolder -Stage 'Start'"
		.\scripts\tss_WorkFoldersDiag.ps1 -DataPath $global:LogFolder -Stage "Start"}
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectNET_WorkfoldersScenarioLog {
	EnterFunc $MyInvocation.MyCommand.Name
	if ($IsServerSKU) {
		FwResetEventLog $EvtLogsWorkFoldersSrvAnalytic
		($EvtLogsWorkFoldersSrv) | ForEach-Object { FwAddEvtLog $_ _Stop_}
		$Commands = @(
			"xcopy /s/e/i/q/y $Sys32\LogFiles\HTTPERR $global:LogFolder\HTTPERR"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	} else { #WF client
		FwResetEventLog $EvtLogsWorkFoldersCliAnalytic
		($EvtLogsWorkFoldersCli + $EvtLogsWorkFoldersCliAnalytic) | ForEach-Object { FwAddEvtLog $_ _Stop_}
		FwAddRegItem @("DefenderATP") _Stop_
	}
	if ($global:Mode -iMatch "Advanced") {
		$WFmode = '-AdvancedMode'
		LogInfoFile " . calling tss_WorkFoldersDiag.ps1 -DataPath $global:LogFolder -Stage 'Stop' $WFmode"
		.\scripts\tss_WorkFoldersDiag.ps1 -DataPath $global:LogFolder -Stage "Stop" -AdvancedMode
	} else { 
		LogInfoFile " . calling tss_WorkFoldersDiag.ps1 -DataPath $global:LogFolder -Stage 'Stop'"
		.\scripts\tss_WorkFoldersDiag.ps1 -DataPath $global:LogFolder -Stage "Stop"}
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectNET_WWANLog { # for TSS ver downlevel compat
	CollectNET_MBNLog
} 

#endregion ### Pre-Start / Post-Stop / Collect functions for trace components and scenarios 


#region --- HelperFunctions ---
function writeTesting {
	param(
		[Parameter(Mandatory=$True)]
		[String]$Message
	)
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:beta.IsPresent -or $global:beta -eq $True) {
		Write-host -ForegroundColor Magenta -BackgroundColor Gray $Message
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function logLine {
	param(
		[Parameter(Mandatory=$True)]
		[String]$ToFileName	
	)
	"==================================================================================" | Out-File $ToFileName -Append
}

function NET_start_common_tasks {
	#collect info for all tss runs at _Start_
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "___switch Mini: $global:Mini" "cyan"
	if ($global:Mini -ne $true) {
		#LogInfoFile "PATH: $Env:Path"
		FwGetSysInfo _Start_
		FwGetSVC _Start_
		FwGetSVCactive _Start_ 
		FwGetTaskList _Start_
		FwGetSrvWkstaInfo _Start_
		FwGetNltestDomInfo _Start_
		FwGetDFScache _Start_
		FwGetKlist _Start_ 
		FwGetBuildInfo
		if ($global:noClearCache -ne $true) { FwClearCaches _Start_ } else { LogInfoFile "[$($MyInvocation.MyCommand.Name) skip FwClearCaches" -ShowMsg}
		FwGetRegList _Start_
		FwGetPoolmon _Start_
		FwGetSrvRole
	}
	FwGetLogmanInfo _Start_
	LogInfoFile "___ NET_start_common_tasks DONE" -ShowMsg
	EndFunc $MyInvocation.MyCommand.Name
}
function NET_stop_common_tasks {
	#collect info for all tss runs at _Stop_
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:Mini -ne $true) {
		FwGetDFScache _Stop_
		FwGetSVC _Stop_
		FwGetSVCactive _Stop_ 
		FwGetTaskList _Stop_
		FwGetKlist _Stop_
		FwGetWhoAmI _Stop_
		FwGetDSregCmd
		FwGetPowerCfg
		FwGetHotfix
		#if exist "$global:ScriptFolder\_tss_Update-Log.txt" ( move "$global:ScriptFolder\_tss_Update-Log.txt" "$global:LogFolder\_tss_Update-Log.txt" >NUL)
		FwGetPoolmon _Stop_
		FwGetLogmanInfo _Stop_
		FWgetFltMcInfo _Stop_
		FwGetNltestDomInfo _Stop_
		FwListProcsAndSvcs _Stop_
		FwGetRegList _Stop_
		writeTesting "___ FwGetEvtLogList"
		("System", "Application") | ForEach-Object { FwAddEvtLog $_ _Stop_}
		FwGetEvtLogList _Stop_
	}
	FwGetSrvWkstaInfo _Stop_
	FwGetRegHives _Stop_
	FwCopyMemoryDump -DaysBack 2
	LogInfoFile "___ NET_stop_common_tasks DONE" -ShowMsg
	EndFunc $MyInvocation.MyCommand.Name
}

function copyMachineUserProfiles {
	EnterFunc ($MyInvocation.MyCommand.Name)
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting 1. per-machine Profiles, 2. per-user profiles *.pbk" -ShowMsg
	$Commands = @()
	If(Test-Path $Env:ProgramData\Microsoft\Network\Connections){
		$Commands += @("xcopy /s/e/i/q/y $Env:ProgramData\Microsoft\Network\Connections $global:LogFolder\ConnProgramData")
	}else{LogInfoFile "Folder '$Env:ProgramData\Microsoft\Network\Connections' does not exist." -ShowMsg}
	If(Test-Path $Env:AppData\Microsoft\Network\Connections){
		$Commands += @("xcopy /s/e/i/q/y $Env:AppData\Microsoft\Network\Connections $global:LogFolder\ConnAppData")
	}else{LogInfoFile "Folder '$Env:AppData\Microsoft\Network\Connections' does not exist." -ShowMsg}
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function copyWLANProfiles {
	EnterFunc ($MyInvocation.MyCommand.Name)
	If((Test-Path $Env:SystemRoot\wlansvc\policies) -or (Test-Path $Env:ProgramData\Microsoft\wlansvc\Profiles)){
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting wlansvc\Policies and wlansvc\Profiles" -ShowMsg
		$Commands = @()
		If (Test-Path $Env:SystemRoot\wlansvc\policies){
			$Commands += @("xcopy /s/e/i/q/y $Env:SystemRoot\wlansvc\policies $global:LogFolder\wlansvc_Policies")
		}else{LogInfoFile "Folder '$Env:SystemRoot\wlansvc\policies' does not exist." -ShowMsg}
		If (Test-Path $Env:ProgramData\Microsoft\wlansvc\Profiles){
			$Commands += @("xcopy /s/e/i/q/y $Env:ProgramData\Microsoft\wlansvc\Profiles $global:LogFolder\wlansvc_Profiles")
		}else{LogInfoFile "Folder '$Env:ProgramData\Microsoft\wlansvc\Profiles' does not exist." -ShowMsg}
		If($Commands) {RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function DoRegPreRequCheck { #_# not called by now
	param(
		[Parameter(Mandatory=$True)]
		[String]$RegLoc,
		[String]$RegKeyName,
		[String]$ExpectedRegValue,
		[Bool]$BootRequired = $False
	)
	EnterFunc $MyInvocation.MyCommand.Name
<# ToDo:
	if ($RegKeyName -ne '') {
		( for /f "tokens=3" %%a in ('reg query "$RegLoc" /V $RegKeyName  ^| findstr /ri "REG_DWORD"') do @set _RegKeyValue=%%a ) 2>NUL
		set _RegKeyLoc="$RegLoc"
		set _ExpectedRegValue=$ExpectedRegValue
		set _RegKeyIsSet=1
	} else 	( ( for /f "tokens=1 delims=\" %%i in ('reg query "$RegLoc" /ve') do @set _RegKeyIsSet=1) 2>NUL )
	if defined _RegKeyIsSet ( call :logitem [Info] RegKeyLoc !_RegKeyLoc! detected.) else ( call :logitem [Info] RegKey $RegLoc is missing.)
	if not defined _RegKeyValue ( call :DoRegPreRequSet !_RegKeyLoc! $RegKeyName !_ExpectedRegValue! $BootRequired
								)
	if defined _RegKeyValue ( set _RegKeyValue=!_RegKeyValue: =!
			call :logitem [Info] current value of RegKeyName '$RegKeyName' = '!_RegKeyValue!'
			if "!_RegKeyValue!" neq "0x!_ExpectedRegValue!" (
											call :DoRegPreRequSet !_RegKeyLoc! $RegKeyName !_ExpectedRegValue! $BootRequired
											))
	for %%i in (_RegKeyLoc _RegKeyIsSet _RegKeyValue) do ( set %%i=)
#>
	EndFunc $MyInvocation.MyCommand.Name
}

function doTCPrundown {
	EnterFunc $MyInvocation.MyCommand.Name
	if (($global:OSVersion.Build -gt 14393) -and ($global:RunDown = $True)) {
		LogDebug "[$($MyInvocation.MyCommand.Name)]  .. [Build: $global:OSVersion.Build] running 'netsh int TCP rundown'"
		$Commands = @(
		"netsh int TCP rundown | Out-File -Append $global:ErrorLogFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function getAdvFWmonitor {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)] running 'netsh advfirewall monitor show firewall verbose' at $TssPhase  ...may take some minutes"
	$outFile = $PrefixTime + "FW-Adv-Info.txt"
	$Commands = @(
		"netsh advfirewall monitor show firewall verbose | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function getBFEregPerm {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collect BFE Registry permissions at $global:TssPhase" -ShowMsg
	$outFile = $PrefixTime + "BFE_Registry_permissions" + $TssPhase + ".txt"
	$Commands = @(
		"Get-Acl HKLM:\SYSTEM\CurrentControlSet\services\BFE | format-list 						| Out-File -Append $outFile"
		"Get-Acl HKLM:\SYSTEM\CurrentControlSet\services\BFE\Parameters\ | format-list			| Out-File -Append $outFile"
		"Get-Acl HKLM:\SYSTEM\CurrentControlSet\services\BFE\Parameters\Policy\ | format-list	| Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function getBITsInfo { 
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting BITS infos at $TssPhase" -ShowMsg
	$outFile = $PrefixTime + "BITS-Info" + $TssPhase + ".txt"
	$Commands = @(
		"bitsadmin /list /AllUsers /verbose | Out-File -Append $outFile"
		"bitsadmin /util /version /verbose | Out-File -Append $outFile"
		"bitsadmin /PEERS /LIST | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	$outFile = $PrefixTime + "NetConnProfile_info_pscmdlets.txt"
	Get-NetConnectionProfile | Format-List * |Out-file -Append -Width 500 $OutFile
	EndFunc $MyInvocation.MyCommand.Name
}

function getBCInfo { 
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. collecting BranchCache infos at $TssPhase" -ShowMsg
	$outFile = $PrefixTime + "BranchCache" + $TssPhase + ".txt"
	$Commands = @(
		"netsh BranchCache show hostedcache 		| Out-File -Append $outFile"
		"netsh BranchCache show localcache 			| Out-File -Append $outFile"
		"netsh BranchCache show publicationcache 	| Out-File -Append $outFile"
		"netsh BranchCache show status all		 	| Out-File -Append $outFile"
		"netsh BranchCache smb show latency		 	| Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	if ($global:OSVersion.Build -ge 9200) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] .. fetching BranchCache infos using PowerShell at $TssPhase"
		if ($global:RunPS_BCstatus -eq $True) {
			$Commands = @(
				"Get-BCStatus | Out-File -Append $outFile"
				"Get-BCNetworkConfiguration | Select * | Out-File -Append $outFile"
				"(Get-ChildItem -Path (Get-BCHashCache).CacheFileDirectoryPath -Filter *.tmp -Recurse | Measure-Object ).Count | Out-File -Append $outFile"
			)
			RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
			If (Test-Path "$Env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\PeerDistRepub\Store\0"){
				Invoke-Command -ScriptBlock { $NrOfDatFiles  = ((Get-ChildItem $Env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\PeerDistRepub\Store\0\*.dat -Recurse ).count) ; 'Total RePub *.dat files: ' + $($NrOfDatFiles) | Out-file $outFile -Append -Encoding ascii ; if ($NrOfDatFiles -ge 1024) { '[INFO] The nr of RePub *.dat files in a subfolder exceeding 1024 could indicate a problem kb4565457.' | Out-file $outFile -Append -Encoding ascii} }
			}
		}
	}
	$Commands = @(
		"cmd.exe /c DIR /A/B/S %SystemRoot%\ServiceProfiles\NetworkService\AppData\Local\PeerDistpub 	| Out-File -Append $outFile"
		"cmd.exe /c DIR /A/B/S %SystemRoot%\ServiceProfiles\NetworkService\AppData\Local\PeerDistRepub	| Out-File -Append $outFile"
		"'Total PeerDistRepub folders size:' | Out-File -Append $outFile"
		"cmd.exe /c DIR /S %SystemRoot%\ServiceProfiles\NetworkService\AppData\Local\PeerDistRepub | findstr /i /c:""File(s)"" | Out-File -Append $outFile"
		"'Total PeerDistPub folders size:'   | Out-File -Append $outFile"
		"cmd.exe /c DIR /S %SystemRoot%\ServiceProfiles\NetworkService\AppData\Local\PeerDistPub   | findstr /i /c:""File(s)"" | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function getCSCdump {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	if (!$global:IsLiteMode){
		if (Test-Path $cscDBdumpPath) {
			LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting OfflineFiles CSC database dump at $TssPhase" -ShowMsg
			$outFile = $PrefixTime + "CscDBdump" + $TssPhase + ".txt"
			$Commands = @(
				"cscDBdump.exe dump | Out-File -Append $outFile"
			)
			RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		}  else {LogWarn "[$($MyInvocation.MyCommand.Name)] 'cscDBdump.exe' not found in PATH"}
	}else{ LogInfo "Skipping cscDBdump.exe in Lite mode"}
	EndFunc $MyInvocation.MyCommand.Name
}

function getDA_Netsh {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. collecting IPv6 'netsh interface ...' info at $TssPhase" -ShowMsg
	$outFile = $PrefixTime + "DA_IPv6_Netsh" + $TssPhase + ".txt"
	"interface 6to4 show state","interface 6to4 show relay","interface teredo show state","interface teredo show state","interface httpstunnel show int","namespace show effectivepolicy","namespace show policy","interface isatap show state","interface isatap show router","advfirewall monitor show mmsa","advfirewall monitor show qmsa","advfirewall monitor show consec rule name=all","advfirewall monitor show currentprofile","interface ipv6 show interfaces","interface ipv6 show interfaces level=verbose","interface ipv6 show route" | ForEach-Object { 
		$Commands = @("Netsh $_ | Out-File -Append $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }	 
	EndFunc $MyInvocation.MyCommand.Name
}

function getDFSsrvInfo {
	EnterFunc ($MyInvocation.MyCommand.Name)
	if ($IsServerSKU -and (Get-WindowsFeature | Where-Object {($_.Name -eq "FS-DFS-Namespace") -and ($_.installed -eq $true)})){
		if (!$global:IsLiteMode){ # ToDo: try icacls.exe instead of AccessChk
			# get AccessChk.exe for \DFSroots folder
			$FolderPaths="C:\DFSroots"
			If(!(Test-Path -Path $FolderPaths)){
				FwPlaySound
				LogInfo "'C:\DFSroots' does not exist, please enter the new location" "Cyan"
				LogInfo "[DFSRoots] Next step will ask for location of DFSRoots folder, please answer Y or N to collect Folder permissions" "Cyan"
				FwDisplayPopUp 5 "[DFSRoots folder]"
				$Answer = FwRead-Host-YN -Message "Press Y for Yes = collect Folder permissions, N for No (timeout=30s)" -Choices 'yn' -TimeOut 30
				If($Answer){
					$DFSRootsPath = Read-Host -Prompt "Please enter full path to DFSroots, i.e. D:\Data\DFSroots, or hit ENTER to skip this step"
					LogInfoFile "[Location of DFSroots: User provided answer:] $DFSRootsPath"
					If(!([String]::IsNullOrEmpty($DFSRootsPath))) {
						$FolderPaths = $DFSRootsPath
					}
				}
			}
			If(Test-Path -Path $FolderPaths){
				$outFile = $PrefixTime + "DFS_AccessChk" + $TssPhase + ".txt"
				LogInfo "[$($MyInvocation.MyCommand.Name)] collecting Folder permission for $FolderPaths at _stop_"
				$Commands = @(
					"AccessChk.exe -nobanner /AcceptEula -s -ld $FolderPaths	| Out-File -Append $outFile"
				)
				RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
			}
			# get DFSutil outputs for DfsnRoot
			If ((Get-DfsnRoot -ComputerName $env:Computername).count -eq 1) {
				$DFSnRoot = (Get-DfsnRoot -ComputerName $env:Computername).path
			}else{
				FwPlaySound
				LogInfo "[DFSnRoot] Next step will ask for DFSnRoot to investigate, please answer Y or N to collect DFSutil outputs" "Cyan"
				FwDisplayPopUp 5 "[DFSnRoot]"
				$Answer = FwRead-Host-YN -Message "Press Y for Yes = collect DFSutil, N for No (timeout=30s)" -Choices 'yn' -TimeOut 30
				If($Answer){
					Write-Host " configured DFSnRoots on this server are:"
					(Get-DfsnRoot -ComputerName $env:Computername).Path
					$DFSnRoot = Read-Host -Prompt "Please specify DFS root, i.e. \\contoso.com\your_DFSroot_name  - no subfolders, or hit ENTER to skip this step"
					LogInfoFile "[DFS root: User provided answer:] $DFSnRoot"
				}
			}
			If(!([String]::IsNullOrEmpty($DFSnRoot))) {
				LogInfo "[$($MyInvocation.MyCommand.Name)] collecting 'DFSutil.exe' infos"
				LogInfo "[$($MyInvocation.MyCommand.Name)] exporting DFS root info for $DFSnRoot"
				$Commands = @(
					"$global:DFSutilPath root export $DFSnRoot $PrefixTime`DFS-N_root.txt 2>&1"
					"$global:DFSutilPath /root:$DFSnRoot /export:$PrefixTime`DFS-N_fsRoot.txt /verbose  2>&1"
				)
				RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
				LogInfo "[$($MyInvocation.MyCommand.Name)] running DFSutil /ViewDfsDirs:C: /verbose"
				$outfile = $PrefixTime + "DFS-N_infoFile" + $TssPhase + ".txt"
				$Commands = @(
					"$global:DFSutilPath /ViewDfsDirs:C: /verbose 			| Out-File -Append $outfile"
				)
				RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
				LogInfo "[$($MyInvocation.MyCommand.Name)] running DFSutil /domain:$Env:USERDNSDOMAIN /view"
				$Commands = @(
					"$global:DFSutilPath /domain:$Env:USERDNSDOMAIN /view	| Out-File -Append $outfile"
				)
				RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
			}else{ LogInfo "*** Note: no DFSnRoot was entered ***" "Magenta"}
		}else{ LogInfo "Skipping AccessChk and DFSutil in Lite mode"}
	}else{ LogInfo "[$($MyInvocation.MyCommand.Name)] This server is not part of DFSn namespace" "Cyan" }
	EndFunc $MyInvocation.MyCommand.Name
}

function getDHCPlease {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	$outFile = $PrefixTime + "DHCPlease" + $TssPhase + ".txt"
	Get-CimInstance Win32_NetworkAdapterConfiguration | Select-Object index,Description,DHCPLeaseExpires,DHCPLeaseObtained | Out-File -Append $outFile -Encoding ascii
	EndFunc $MyInvocation.MyCommand.Name
}	

function getDNScliInfo {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] running 'Get-DnsClient*' at $TssPhase" -ShowMsg
	$outFile = $PrefixTime + "DNScli_info_pscmdlets" + $TssPhase + ".txt"
	$Commands = @(
		"Get-DnsClientGlobalSetting | Out-File -Append $outFile"
		"Get-DnsClientServerAddress | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	$outFile = $PrefixTime + "DnsCli-state" + $TssPhase + ".txt"
	$Commands = @(
		"netsh dnsclient show state | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function getDNSsrvInfo {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	if (Get-Service dns -ErrorAction SilentlyContinue) {
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] Dnscmd: dump DNS server info and statistics at $TssPhase" -ShowMsg
		$outFile = $PrefixTime + "DNSsrv_Info_Dnscmd" + $TssPhase + ".txt"
		$Commands = @(
			"Dnscmd /Info 					| Out-File -Append $outFile"
			"Dnscmd /EnumDirectoryPartitions | Out-File -Append $outFile"
			"Dnscmd /EnumZones 				| Out-File -Append $outFile"
			"Dnscmd /Statistics 			| Out-File -Append $outFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] PScmdlets: dump DNS server info at $TssPhase" -ShowMsg
		$outFile = $PrefixTime + "DNSsrv_info_pscmdlets" + $TssPhase + ".txt"
		"Get-DnsServer","Get-DnsServerSetting","Get-DnsServerStatistics","Get-DnsServerDsSetting","Get-DnsServerScavenging","Get-DnsServerRecursion","Get-DnsServerDiagnostics","Get-DnsServerGlobalNameZone","Get-DnsServerCache","Get-DnsServerGlobalQueryBlockList","Get-DnsServerEdns","Get-DnsServerForwarder","Get-DnsServerRootHint","Get-DnsServerZone" | ForEach-Object { 
			$Commands = @("$_ | Out-File -Append -FilePath $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
		$outFile = $PrefixTime + "DNSsrv_info_PsCommands" + $TssPhase + ".txt"
		"Get-DnsServerQueryResolutionPolicy","Get-DnsServerClientSubnet","Get-DnsServerRecursionScope","Get-DnsServerZoneTransferPolicy","Get-DnsServerResponseRateLimiting" | ForEach-Object { 
			$Commands = @("$_ | Format-List * | Out-File -Append -FilePath $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] PScmdlets: DNS server Policy at $TssPhase" -ShowMsg
		$outFile = $PrefixTime + "DNSsrv_info_Policy_PsCommands" + $TssPhase + ".txt"
		"Get-DnsServerQueryResolutionPolicy -ComputerName $Env:ComputerName",,"Get-DnsServerClientSubnet","Get-DnsServerRecursionScope","Get-DnsServerZoneTransferPolicy" | ForEach-Object { 
			$Commands = @("$_ | Format-List * | Out-File -Append -FilePath $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
		$ZonNames=(Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones').Name | Split-Path -Leaf
		ForEach ($Zone in $ZonNames) {
			if (($Zone -notlike "*TrustAnchors*") -and ($Zone -notlike "*arpa*") -and ($Zone -notlike "*_msdcs*")){
				"Get-DnsServerQueryResolutionPolicy -ZoneName $Zone","Get-DnsServerZoneScope -ZoneName $Zone -ErrorAction Ignore" | ForEach-Object { 
				$Commands = @("$_ | Format-List * | Out-File -Append -FilePath $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
			}
		}
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] Registry settings for DNS server Policy at $TssPhase" -ShowMsg
		$Commands = @(
			"REG SAVE `"HKLM\Software\Microsoft\Windows NT\CurrentVersion\DNS Server`" $PrefixCn`RegHive_DNSServer.hiv /Y"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False

		$RegExportKeyInTxt = New-Object 'System.Collections.Generic.List[Object]'
		$RegExportKeyInTxt = @(  #Key, ExportFile, Format (TXT or REG)
			@("HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\DNS Server\Policies", "$($PrefixTime)reg_DNSsrv_Policies.txt", "TXT"),
			@("HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\DNS Server\Policies", "$($PrefixTime)reg_DNSsrv_Policies.reg", "REG"),
			@("HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\DNS Server\ClientSubnets", "$($PrefixTime)reg_DNSsrv_ClientSubnets.txt", "TXT"),
			@("HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\DNS Server\ClientSubnets", "$($PrefixTime)reg_DNSsrv_ClientSubnets.reg", "REG"),
			@("HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones", "$($PrefixTime)reg_DNSsrv_ZonePolicies.txt", "TXT"),
			@("HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones", "$($PrefixTime)reg_DNSsrv_ZonePolicies.reg", "REG")
		)
		ForEach ($regtxtexport in $RegExportKeyInTxt){
			global:FwExportRegKey $regtxtexport[0] $regtxtexport[1] $regtxtexport[2]
		}

		LogInfo "[$($MyInvocation.MyCommand.Name)] collecting $Sys32\dns\*.log"
		$Commands = @(
			"xcopy /s/i/q/y/H $Sys32\dns\*.log $global:LogFolder\dns"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	} else {LogInfo "[$($MyInvocation.MyCommand.Name)] DNS server is not running on this system"}
	EndFunc $MyInvocation.MyCommand.Name
}

function getFWlogs {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] Get Firewall logs at $TssPhase"
	#FwAddEvtLog @("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall") $TssPhase
	("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall") | ForEach-Object { FwAddEvtLog $_ Phase}
	$outFile = $PrefixTime + "pFirewall.log"
	if ( Test-Path "$Sys32\LogFiles\Firewall\pfirewall.log" ) {
	$Commands = @(
		"Copy-Item $Sys32\LogFiles\Firewall\pfirewall.log -Destination $outFile  -Force"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function getFWrules {
		# Note: $error will show 8x "Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.DynamicTransport". Reason see Prio4: investigate $error ErrorVariable w/ -Scenario NET_Firewall #403
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name)
	LogInfo "[$($MyInvocation.MyCommand.Name)] dump all Firewall Rules Information at $TssPhase ...may take some minutes"
	if ($global:OSVersion.Build -ge 9200) {
		$outFile = $PrefixTime + "FirewallRules.txt"
		"Show-NetFirewallRule","Show-NetIPsecRule","Get-NetIPsecRule","Get-NetFirewallRule","Get-NetFirewallSetting","Get-NetFirewallProfile" | ForEach-Object { 
		$Commands = @("$_ | Out-File -Append $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
	} else { getAdvFWmonitor $TssPhase }
	EndFunc $MyInvocation.MyCommand.Name
}

function getNICinfo {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name)
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collect NIC Information at $TssPhase" -ShowMsg
	$Commands = @(
		"wmic nic get * /format:htable | Out-File -Append $PrefixTime`NIC.html"	#ToDo replace with Get-CimInstance
		"wmic nicconfig get * /format:htable | Out-File -Append $PrefixTime`NICconfig.html"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}	

function getIProuting {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)]  collecting RRAS - Remote Access Server details at $TssPhase" -ShowMsg
	$outFile = $PrefixTime + "IProuting" + $TssPhase + ".txt"
	$Commands = @(
		"netsh routing ip show filter | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function GetMBNInfo {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$outFile = $PrefixTime + "WwanSvc-Profiles-Dir" + $global:TssPhase + ".txt"
	$Commands = @(
		"DIR $env:ProgramData\Microsoft\WwanSvc\Profiles | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting 'Netsh MBN show interfaces / profiles / ready int' at $TssPhase" -ShowMsg
	$outFile = $PrefixTime + "MBN-Info" + $TssPhase + ".txt"
	"interfaces","profiles","ready int=*" | ForEach-Object {
		$Commands = @("Netsh MBN show $_ | Out-File -Append $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
	EndFunc $MyInvocation.MyCommand.Name
}	

function getNCSIinfo {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting NCSI infos at $TssPhase" -ShowMsg
	cscript //NoLogo "$global:ScriptFolder\scripts\tss_DumpAdapterInfo.vbs" "$global:LogFolder" $TssPhase
	$outFile = $PrefixTime + "NetConnectionProfile" + $TssPhase + ".txt"
	$Commands = @(
		"Get-NetConnectionProfile | fl * | Out-File -Append -Width 500 $outFile"
	)
	$outFile = $PrefixTime + "NCSI_client_config" + $TssPhase + ".txt"
	$Commands += @(
		"Get-NCSIPolicyConfiguration | Out-File -Append $outFile"
		"Get-DnsClientNrptPolicy | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}
	
function getNetcfg {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting 'Netcfg -s n' at $TssPhase" -ShowMsg
	$outFile = $PrefixTime + "Netcfg" + $TssPhase + ".txt"
	$Commands = @(
		"Netcfg -s n | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}
function getNetFiles {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting 'Get-SmbOpenFile' at $TssPhase" -ShowMsg
	$outFile = $PrefixTime + "SmbOpenFile" + $TssPhase + ".txt"
	if ($global:OSVersion.Build -ge 9200) {
		$Commands = @(
			"Get-SmbOpenFile | select FileId,SessionId,Path,ShareRelativePath,ClientComputername,ClientUserName,Permissions | ft * | Out-File -Append -Width 999 $outFile"
		)
	}else{ 
		$Commands = @(
			"NET FILES | Out-File -Append $outFile"
		)
	}
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function getNetSh-http-show-UrlAcl {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] running 'netsh http show UrlAcl' at $TssPhase" -ShowMsg
	$outFile = $PrefixTime + "Http-UrlAcl" + $TssPhase + ".txt"
	$Commands = @(
		"netsh http show UrlAcl | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function getSMBsrvBinding {
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] running SMB LanmanServer bindings check" -ShowMsg
	$outFile = $PrefixTime + "_SvrBindings.txt"

	# get the LanmanServer Bind value
	$bndPath = "HKLM:\System\CurrentControlSet\Services\Lanmanserver\Linkage"
	$bndName = "Bind"
	$bndLinkage = Get-ItemProperty -Path $bndPath -Name $bndName

	FwWrite-Log -LogFilePath $outFile -text "All bindings:`n$(($bndLinkage.Bind | Sort-Object) -join "`n")`n"

	<#
		Tcpip_ = TCP/IPv4 bindings
		Tcpip6_ = TCP/IPv6 bindings
		NetBT_Tcpip_ = NetBt over TCP/IPv4
		NetBT_Tcpip6_ = NetBt over TCP/IPv6
		We only care about Tcpip_ and Tcpip6_ in this case.
	#>

	# collect the TCP/IPv4 and TCP/IPv4 specific bindings
	$tcpip4Bnd = $bndLinkage.Bind | Where-Object {$_ -match "\\Tcpip_"}
	FwWrite-Log -LogFilePath $outFile -text "tcpip[4] bindings:`n$(($tcpip4Bnd | Sort-Object) -join "`n")`n"

	$tcpip6Bnd = $bndLinkage.Bind | Where-Object {$_ -match "\\Tcpip6_"}
	FwWrite-Log -LogFilePath $outFile -text "tcpip6 bindings:`n$(($tcpip6Bnd | Sort-Object) -join "`n")`n"

	# get all net adapters, excluding adapters that are not bound to ms_server (Enabled = False)
	$svrBingings = Get-NetAdapterBinding -ComponentID ms_server | Where-Object Enabled
	$netAdptrs =  Get-NetAdapter | Where-Object {$svrBingings.InterfaceAlias -contains $_.InterfaceAlias}
	FwWrite-Log -LogFilePath $outFile -text "Net adapters bound to ms_server:`n$(($netAdptrs | Sort-Object | Select-Object Name,InterfaceDescription,InterfaceAlias,InterfaceIndex,DeviceID) | Out-String)`n"

	# write SMB Server network interface details to log - requires admin rights
	#$srvNet = Get-SmbServerNetworkInterface
	#FwWrite-Log -LogFilePath $outFile -text "SMB Server network interface details: `n$($srvNet | Out-String)`n"

	foreach ($adapter in $netAdptrs)
	{
		FwWrite-Log -LogFilePath $outFile -text "Checking bindings for $($adapter.Name)`nDescription: $($adapter.InterfaceDescription)`nGUID: $($adapter.DeviceID) `nStatus: $($adapter.Status)" -tee
		
		# is the DeviceID in the binding lists
		$tmpBnd4 = $tcpip4Bnd | Where-Object {$_ -match $adapter.DeviceID}
		if (-not $tmpBnd4) {
			FwWrite-Log -LogFilePath $outFile -text "$($adapter.Name) was not found on the SMB Server binding list for TCP/IPv4." -tee -foreColor Red
		} else {
			FwWrite-Log -LogFilePath $outFile -text "$($adapter.Name) was found on the SMB Server binding list for TCP/IPv4." -tee -foreColor Green
		}

		$tmpBnd6 = $tcpip6Bnd | Where-Object {$_ -match $adapter.DeviceID}
		if (-not $tmpBnd4) {
			FwWrite-Log -LogFilePath $outFile -text "$($adapter.Name) was not found on the SMB Server binding list for TCP/IPv6." -tee -foreColor Red
		} else {
			FwWrite-Log -LogFilePath $outFile -text "$($adapter.Name) was found on the SMB Server binding list for TCP/IPv6." -tee -foreColor Green
		}

		$tmpBnd = $bndLinkage.Bind | Where-Object {$_ -match $adapter.DeviceID}
		if (-not $tmpBnd4) {
			FwWrite-Log -LogFilePath $outFile -text "$($adapter.Name) was not found anywhere on the SMB Server binding list.`n" -tee -foreColor Red
		} else {
			FwWrite-Log -LogFilePath $outFile -text "$($adapter.Name) was found on the SMB Server binding lists.`n" -tee -foreColor Green
		}
	}
	FwWrite-Log -LogFilePath $outFile -text "Results: $outFile" -tee -foreColor Cyan
	FwWrite-Log -LogFilePath $outFile -text "Note: If corrupted SMB Bindings were detected, they could be fixed by running script $global:ScriptFolder\scripts\TSS_SMB_Fix-SmbBindings.ps1" -tee -foreColor Gray
	EndFunc $MyInvocation.MyCommand.Name
}

function getWfpShow {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting 'netsh wfp show' *.xlm files at $TssPhase" -ShowMsg
	$Commands = @(
		"netsh wfp show netevents file=$PrefixTime`wfpNetevents_$TssPhase.xml"
		"netsh wfp show state file=$PrefixTime`wfpState_$TssPhase.xml"
		"netsh wfp show boottimepolicy file=$PrefixTime`wfpBoottimePolicy_$TssPhase.xml"
		"netsh wfp show filters file=$PrefixTime`wfpFilters_$TssPhase.xml"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function getWLANinfo {
	param(
		#[Parameter(Mandatory=$True)]
		#[String]$802Dot1xSpec,		# LAN or WLAN
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	writeTesting "_______ CmdLine InvocationLine: $global:InvocationLine"
	if ($global:InvocationLine -match "WLAN") {$802Dot1xSpec = "WLAN"}
	if ($global:InvocationLine -match "802Dot1x") {$802Dot1xSpec = "LAN"}
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting 'netsh wlan show all' at $TssPhase" -ShowMsg
	$Commands = @(
		"netsh wlan show all | Out-File -Append $PrefixTime`WlanInfo_$TssPhase.xml"
		"netsh wlan show allowexplicitcreds | Out-File -Append $PrefixTime`Netsh-wlan-show-allowexplicitcreds.txt"
		"netsh wlan show autoconfig | Out-File -Append $PrefixTime`Netsh-wlan-show-autoconfig.txt"
		"netsh wlan show blockednetworks | Out-File -Append $PrefixTime`Netsh-wlan-show-blockednetworks.txt"
		"netsh wlan show createalluserprofile | Out-File -Append $PrefixTime`Netsh-wlan-show-createalluserprofile.txt"
		"netsh wlan show drivers | Out-File -Append $PrefixTime`Netsh-wlan-show-drivers.txt"
		"netsh wlan show filters | Out-File -Append $PrefixTime`Netsh-wlan-show-filters.txt"
		"netsh wlan show hostednetwork | Out-File -Append $PrefixTime`Netsh-wlan-show-hostednetwork.txt"
		"netsh wlan show interfaces | Out-File -Append $PrefixTime`Netsh-wlan-show-interfaces.txt"
		"netsh wlan show networks | Out-File -Append $PrefixTime`Netsh-wlan-show-networks.txt"
		"netsh wlan show onlyUseGPProfilesforAllowedNetworks | Out-File -Append $PrefixTime`Netsh-wlan-show-onlyUseGPProfilesforAllowedNetworks.txt"
		"netsh wlan show settings | Out-File -Append $PrefixTime`Netsh-wlan-show-settings.txt"
		"netsh wlan show wirelesscapabilities | Out-File -Append $PrefixTime`Netsh-wlan-show-wirelesscapabilities.txt"
		"netsh wlan show wlanreport | Out-File -Append $PrefixTime`Netsh-wlan-show-wlanreport.txt"
		)
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] collecting 'netsh $802Dot1xSpec export profile' at $TssPhase" -ShowMsg
	FwCreateFolder $DirRepro\Profile_$TssPhase
	$Commands += @(
		"netsh $802Dot1xSpec export profile folder=$DirRepro\Profile_$TssPhase"	# encrypted key
		#"netsh $802Dot1xSpec export profile folder=$DirRepro\Profile_$TssPhase key=clear"	# for key in plain text
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function Remove_BITS {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] ... resetting BITS Reg Keys to default" -ShowMsg
	Stop-Service -Name "BITS" -Force
	$BitsKey="HKLM\Software\Microsoft\Windows\CurrentVersion\BITS"
	FwAddRegValue $BitsKey "LogFileFlags" "REG_DWORD" "0x0"
	FwAddRegValue $BitsKey "LogFileSize" "REG_DWORD" "0x1"
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] ... Restarting BITS service" -ShowMsg
	Start-Service -Name "BITS"
	EndFunc $MyInvocation.MyCommand.Name
}

function Start_Netlogon { # obsolete, was only used for DAsrv and NPS
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. Enabling Netlogon service debug log DbFlag:$global:NetLogonFlag" -ShowMsg
	$Commands = @(
			"NLTEST /DbFlag:$global:NetLogonFlag | Out-Null"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	#if not ERRORLEVEL 0 ( call :doCmd REG ADD HKLM\System\CurrentControlSet\Services\Netlogon\Parameters /v DbFlag /t REG_DWORD /d $global:NetLogonFlag /f )
	EndFunc $MyInvocation.MyCommand.Name
}
function Stop_Netlogon { # obsolete, was only used for DAsrv and NPS
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. Disabling Netlogon service debug log, copying $env:SystemRoot\debug" -ShowMsg
	FwAddRegValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" "DbFlag" "REG_DWORD" "0x0"
	$Commands = @(
			#"REG ADD HKLM\System\CurrentControlSet\Services\Netlogon\Parameters /v DbFlag /t REG_DWORD /d 0x0 /f"
			"xcopy /s/e/i/q/y $env:SystemRoot\debug $global:LogFolder\WinDir-debug"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}
<#
function Remove_Netlogon { # obsolete, was only used for DAsrv and NPS
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] .. Disabling Netlogon service debug log DbFlag:$global:NetLogonFlag"
	FwAddRegValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" "DbFlag" "REG_DWORD" "0x0"
	EndFunc $MyInvocation.MyCommand.Name
}
#>

#endregion --- HelperFunctions ---

#region groups of Eventlogs for FwAddEvtLog
$EvtLogsBluetooth 	= @("Microsoft-Windows-Bluetooth-BthLEPrepairing/Operational","Microsoft-Windows-Bluetooth-MTPEnum/Operational")
$EvtLogsBranchcache = @("Microsoft-Windows-BranchCache/Operational","Microsoft-Windows-BranchCacheSMB/Operational")
$EvtLogsBranchcacheAnalytic = @("Microsoft-Windows-BranchCacheMonitoring/Analytic","Microsoft-Windows-BranchCacheSMB/Analytic")
$EvtLogsCscAnalytic	= @("Microsoft-Windows-OfflineFiles/Analytic","Microsoft-Windows-OfflineFiles/Debug","Microsoft-Windows-OfflineFiles/SyncLog")
$EvtLogsDAcliOpt	= @("Microsoft-Windows-Ncasvc/Operational","Microsoft-Windows-NCSI/Operational")
if (!$IsServerSKU) {$EvtLogsDAcliOpt += "Microsoft-Windows-OtpCredentialProvider/Operational"} #_# Todo: is this Evt available in 2012R2 /ServerSKU?
$EvtLogsDAsrv		= @("Microsoft-Windows-RemoteAccess-MgmtClient/Operational","Microsoft-Windows-RemoteAccess-MgmtClientPerf/Operational","Microsoft-Windows-VPN-Client/Operational","Microsoft-Windows-RemoteAccess-RemoteAccessServer/Admin","Microsoft-Windows-RemoteAccess-RemoteAccessServer/Operational","Windows Networking Vpn Plugin Platform/Operational","Windows Networking Vpn Plugin Platform/OperationalVerbose","Security")
$EvtLogsDFSsrv		= @("Microsoft-Windows-DFSN-Server/Admin","Microsoft-Windows-DFSN-Server/Operational")
$EvtLogsDHCPsrv		= @("Microsoft-Windows-Dhcp-Server/Operational","DhcpAdminEvents","Microsoft-Windows-Dhcp-Server/FilterNotifications")
$EvtLogsDHCPcliOpt	= @("Microsoft-Windows-DHCP-Client/Operational")
$EvtLogsDHCPcli		= @("Microsoft-Windows-DHCP-Client/Admin")
$EvtLogsDNScli		= @("Microsoft-Windows-DNS-Client/Operational","Microsoft-Windows-NCSI/Operational")
$EvtLogsDNSsrv		= @("DNS Server","Microsoft-Windows-DNSServer/Audit")
$global:EvtLogsDocker		= @("Microsoft-Windows-Host-Network-Service-Admin","Microsoft-Windows-Host-Network-Service-Operational","Microsoft-Windows-Containers-Wcifs/Operational","Microsoft-Windows-Containers-Wcnfs/Operational","Microsoft-Windows-Hyper-V-Compute-Admin","Microsoft-Windows-Hyper-V-Compute-Operational")
$global:EvtLogsEFS		= @("Microsoft-Windows-NTFS/Operational","Microsoft-Windows-NTFS/WHC")
$global:EvtLogsEFSopt		= @("Microsoft-Windows-NTFS/Performance","Microsoft-Windows-EFS/Debug")
$EvtLogsFirewall	= @("Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurity","Microsoft-Windows-Windows Firewall With Advanced Security/Firewall","Microsoft-Windows-Windows Firewall With Advanced Security/FirewallDiagnostics")
$EvtLogsFirewallOpt	= @("Network Isolation Operational","Microsoft-Windows-Windows Firewall With Advanced Security/FirewallVerbose")
$EvtLogsNetHypHost		= @("Microsoft-Windows-Hyper-V-VMMS-Admin","Microsoft-Windows-Hyper-V-VMMS-operational","Microsoft-Windows-Hyper-V-Worker-Admin","Microsoft-Windows-Hyper-V-VMMS-Networking","Microsoft-Windows-Hyper-V-EmulatedNic-Admin","Microsoft-Windows-Hyper-V-Hypervisor-Admin","Microsoft-Windows-Hyper-V-Hypervisor-Operational","Microsoft-Windows-Hyper-V-SynthNic-Admin","Microsoft-Windows-Hyper-V-VmSwitch-Operational","Microsoft-Windows-MsLbfoProvider/Operational")
$EvtLogsIPAMAnalytic = @("Microsoft-Windows-IPAM/Debug","Microsoft-Windows-IPAM/Analytic")
$EvtLogsMBAM		= @("Microsoft-Windows-MBAM/Admin","Microsoft-Windows-MBAM/Operational")
$EvtLogsMBN			= @("Microsoft-Windows-Wcmsvc/Operational","Microsoft-Windows-GroupPolicy/Operational","Microsoft-Windows-WWAN-SVC-Events/Operational")
$EvtLogsMDManalytic	= @("Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin","Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Debug","Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational")
$EvtLogsMFAext		= @("AuthNOptCh","AuthZOptCh","AuthZAdminCh")
$EvtLogsMiracast 	= @("Microsoft-Windows-WLAN-AutoConfig/Operational")
$EvtLogsNcsiNla		= @("Microsoft-Windows-GroupPolicy/Operational","Microsoft-Windows-NetworkProfile/Operational","Microsoft-Windows-NlaSvc/Operational","Microsoft-Windows-NCSI/Operational","Microsoft-Windows-Wired-AutoConfig/Operational","Microsoft-Windows-Iphlpsvc/Operational","Microsoft-Windows-NetworkLocationWizard/Operational")
$EvtLogsNcsiAnalytic = @("Microsoft-Windows-NCSI/Operational")
if (!$IsServerSKU) { $EvtLogsNcsiNla += "Microsoft-Windows-WLAN-AutoConfig/Operational"} 
$EvtLogs802dot1x	= @("Microsoft-Windows-WFP/Operational","Microsoft-Windows-VPN-Client/Operational","Microsoft-Windows-GroupPolicy/Operational","Microsoft-Windows-Wired-AutoConfig/Operational","Microsoft-Windows-CertificateServicesClient-CredentialRoaming/Operational","Microsoft-Windows-CertPoleEng/Operational","Microsoft-Windows-Wcmsvc/Operational","Security")
if (!$IsServerSKU) { $EvtLogs802dot1x += "Microsoft-Windows-WLAN-AutoConfig/Operational"} 
$global:EventlogsNGCopt =  @("Microsoft-Windows-Biometrics/Operational","Microsoft-Windows-Kerberos/Operational","Microsoft-Windows-AAD/Analytic","Microsoft-Windows-User Device Registration/Debug")
$global:EvtLogsNFScli		= @("Security","Microsoft-Windows-GroupPolicy/Operational","Microsoft-Windows-NetworkProfile/Operational","Microsoft-Windows-NlaSvc/Operational")
$global:EvtLogsNFScliW8	= @("Microsoft-Windows-ServicesForNFS-Client/IdentityMapping","Microsoft-Windows-ServicesForNFS-Client/Operational")
if ($global:OSVersion.Build -lt 10240) { 
	$global:EvtLogsNFSsrv		= @("Microsoft-Windows-Server For NFS/Operational")
}else{	
	$global:EvtLogsNFSsrv		= @("Microsoft-Windows-ServicesForNFS-Portmapper/Admin","Microsoft-Windows-ServicesForNFS-Server/Admin","Microsoft-Windows-ServicesForNFS-Server/IdentityMapping","Microsoft-Windows-ServicesForNFS-Server/Notifications","Microsoft-Windows-ServicesForNFS-Server/Operational")
}
$global:EvtLogsOpenSSH = @("OpenSSH/Admin","OpenSSH/Operational")
$EvtLogsProxyAnalytic = @("Microsoft-Windows-WinHttp/Diagnostic","Microsoft-Windows-WinHTTP-NDF/Diagnostic")
#$global:EvtLogsPowerShell 	= @("Microsoft-Windows-PowerShell/Admin","Microsoft-Windows-PowerShell/Operational")
$global:EvtLogsPrintSvc 	= @("Microsoft-Windows-PrintBRM/Admin","Microsoft-Windows-PrintService/Admin","Microsoft-Windows-PrintService/Operational")
$EvtLogsQoSAnalytic = @("Microsoft-Windows-QoS-Pacer/Diagnostic","Microsoft-Windows-QoS-qWAVE/Debug")
$EvtLogsRAS			= $EvtLogsDAsrv
$global:EvtLogsRDS 		= @("Microsoft-Windows-TerminalServices-LocalSessionManager/Admin","Microsoft-Windows-TerminalServices-LocalSessionManager/Operational","Microsoft-Windows-TerminalServices-PnPDevices/Admin","Microsoft-Windows-TerminalServices-PnPDevices/Operational","Microsoft-Windows-TerminalServices-ServerUSBDevices/Admin","Microsoft-Windows-TerminalServices-ServerUSBDevices/Operational","Microsoft-Windows-TerminalServices-Printers/Admin","Microsoft-Windows-TerminalServices-Printers/Operational","Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin","Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational","Microsoft-Windows-TerminalServices-TSAppSrv-TSMSI/Admin","Microsoft-Windows-TerminalServices-TSAppSrv-TSMSI/Operational","Microsoft-Windows-TerminalServices-TSAppSrv-TSVIP/Admin","Microsoft-Windows-TerminalServices-TSAppSrv-TSVIP/Operational","Microsoft-Windows-TerminalServices-TSFairShare-Events/Admin","Microsoft-Windows-TerminalServices-TSFairShare-Events/Operational","Microsoft-Windows-TerminalServices-SessionBroker-Client/Admin","Microsoft-Windows-TerminalServices-SessionBroker-Client/Operational","Microsoft-Windows-Remote-Desktop-Management-Service/Admin","Microsoft-Windows-Remote-Desktop-Management-Service/Operational","Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin","Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational","Microsoft-Windows-RemoteDesktopServices-SessionServices/Operational","Microsoft-Windows-TerminalServices-SessionBroker/Admin","Microsoft-Windows-TerminalServices-SessionBroker/Operational")
$global:EvtLogsRDScli 	= @("Microsoft-Windows-RemoteApp and Desktop Connections/Admin","Microsoft-Windows-RemoteApp and Desktop Connections/Operational","Exported Microsoft-Windows-TerminalServices-ClientUSBDevices/Admin","Exported Microsoft-Windows-TerminalServices-ClientUSBDevices/Operational")
$global:EvtLogsSMBcli	= @("Microsoft-Windows-SMBClient/Connectivity","Microsoft-Windows-SMBClient/Operational","Microsoft-Windows-SMBClient/Security")
$global:EvtLogsSMBcliOpt 	= @("Microsoft-Windows-SMBWitnessClient/Admin","Microsoft-Windows-SMBWitnessClient/Informational","Microsoft-Windows-SMBDirect/Admin")
if ($global:OSVersion.Build -ge 17763) { $global:EvtLogsSMBcliOpt += "Microsoft-Windows-SMBClient/Audit" }
$global:EvtLogsSMBcliAnalytic = @("Microsoft-Windows-SMBClient/Diagnostic","Microsoft-Windows-SMBClient/HelperClassDiagnostic","Microsoft-Windows-SMBClient/ObjectStateDiagnostic")
$global:EvtLogsSMBsrv		= @("Microsoft-Windows-SMBServer/Connectivity","Microsoft-Windows-SMBServer/Operational","Microsoft-Windows-SMBServer/Security")
$global:EvtLogsSMBsrvOpt 	= @("Microsoft-Windows-SMBServer/Audit","Microsoft-Windows-SMBDirect/Admin")
$global:EvtLogsSMBsrvAnalytic = @("Microsoft-Windows-SMBServer/Performance","Microsoft-Windows-SMBServer/Analytic","Microsoft-Windows-SMBServer/Diagnostic")
$EvtLogsVPN			= @("Microsoft-Windows-DNS-Client/Operational","Windows Networking Vpn Plugin Platform/Operational","Windows Networking Vpn Plugin Platform/OperationalVerbose")
$EvtLogsVPNopt		= @("Microsoft-Windows-RasAgileVpn/Operational","Microsoft-Windows-RasAgileVpn/Debug")
$EvtLogsWebIOAnalytic = @("Microsoft-Windows-WebIO/Diagnostic")
$EvtLogsWlan = @("Microsoft-Windows-GroupPolicy/Operational","Microsoft-Windows-NetworkProfile/Operational","Microsoft-Windows-NlaSvc/Operational","Microsoft-Windows-NCSI/Operational","Microsoft-Windows-Dhcp-Client/Admin","Microsoft-Windows-Dhcp-Client/Operational","Microsoft-Windows-TaskScheduler/Operational","Microsoft-Windows-WLAN-AutoConfig/Operational")
$EvtLogsWorkFoldersCli	= @("Microsoft-Windows-WorkFolders/Operational","Microsoft-Windows-WorkFolders/ManagementAgent")
$EvtLogsWorkFoldersCliAnalytic	= @("Microsoft-Windows-WorkFolders/Debug","Microsoft-Windows-WorkFolders/Analytic")
$EvtLogsWorkFoldersSrv	= @("Microsoft-Windows-SyncShare/Operational","Microsoft-Windows-SyncShare/Reporting")
$EvtLogsWorkFoldersSrvAnalytic	= @("Microsoft-Windows-SyncShare/Debug")
#endregion groups of Eventlogs

#region Registry Key modules for FwAddRegItem
<# Todo:
	:GetReg_Hives-Cluster
			call :logitem ... collecting Cluster Registry Hives
			call :doCmd REG SAVE HKLM\cluster $PrefixCn`Cluster_%~2.hiv /Y
#>
	$global:KeysUNChard1 = @(	# FwExportRegistry "UNC hardening" $KeysUNChard1
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'BuildLabEx', "$($PrefixTime)Reg_UNChard1.txt"),
		('HKLM:System\CurrentControlSet\Services\Netlogon\Parameters', 'ExpectedDialupDelay', "$($PrefixTime)Reg_UNChard1.txt"),
		('HKLM:System\CurrentControlSet\Services\Netlogon\Parameters', 'NegativeCachePeriod', "$($PrefixTime)Reg_UNChard1.txt"),
		('HKLM:System\CurrentControlSet\Services\TcpIp\Parameters', 'ArpRetryCount', "$($PrefixTime)Reg_UNChard1.txt"),
		('HKLM:System\CurrentControlSet\Services\Mup', 'DisableDfs', "$($PrefixTime)Reg_UNChard1.txt"),
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion\Winlogon', 'GpNetworkStartTimeoutPolicyValue', "$($PrefixTime)Reg_UNChard1.txt"),
		('HKLM:System\CurrentControlSet\Control\Lsa', 'LmCompatibilityLevel', "$($PrefixTime)Reg_UNChard1.txt")
	)
 # A) section of recursive lists
	$global:KeysTestMe = @("HKLM:System\CurrentControlSet\services\Dhcp","HKLM:System\CurrentControlSet\services\Non_Exist")
	$global:KeysUNChard = @("HKLM:System\CurrentControlSet\Services\Netlogon","HKLM:Software\Microsoft\Windows NT\CurrentVersion\Winlogon","HKLM:System\CurrentControlSet\Control\Lsa\Kerberos\Parameters","HKLM:System\CurrentControlSet\Services\ProfSvc\Parameters","HKCU:Network","HKCU:Printers","HKLM:Software\Microsoft\Windows\CurrentVersion\Policies","HKLM:System\CurrentControlSet\Services\LanmanServer","HKLM:System\CurrentControlSet\Services\LanmanWorkstation","HKLM:System\CurrentControlSet\Control\Computername","HKLM:System\CurrentControlSet\Control\Cryptography","HKLM:Software\Policies\Microsoft\Cryptography\Configuration\SSL")		
	$global:Keys802Dot1x = @("HKLM:System\CurrentControlSet\Services\VMSMP\Parameters\SwitchList","HKLM:System\CurrentControlSet\Services\WlanSvc","HKLM:System\CurrentControlSet\Services\dot3svc","HKLM:System\CurrentControlSet\Services\EapHost","HKLM:System\CurrentControlSet\Services\WwanSvc","HKLM:System\CurrentControlSet\Services\Rasman","HKLM:Software\Microsoft\WlanSvc","HKLM:Software\Microsoft\dot3svc","HKLM:Software\Policies\Microsoft\Windows\Wireless\GPTWirelessPolicy","HKLM:Software\Policies\Microsoft\Windows\WiredL2\GP_Policy","HKLM:Software\Microsoft\Wwansvc\profiles","HKLM:Software\Microsoft\Wlansvc\GroupPolicy\Profiles")
	$global:KeysAppV = @("HKLM:Software\Microsoft\AppV")
	$global:KeysATP = @("HKLM:Software\Microsoft\Windows Advanced Threat Protection","HKLM:Software\Microsoft\Windows Defender","HKLM:Software\Policies\Microsoft\Windows Defender")
	$global:KeysDefenderATP = @("HKLM:Software\Microsoft\Windows Advanced Threat Protection\Status")
	$global:KeysAuth = @("HKLM:System\CurrentControlSet\Control\Lsa","HKLM:System\CurrentControlSet\Control\Lsa\Kerberos\Parameters","HKLM:Software\Microsoft\Windows\CurrentVersion\Policies","HKLM:Software\Policies\Microsoft\Windows\System","HKLM:System\CurrentControlSet\Services\LanmanServer","HKLM:System\CurrentControlSet\Services\LanmanWorkstation","HKLM:System\CurrentControlSet\Services\Netlogon","HKLM:Software\Microsoft\Windows\CurrentVersion\Authentication","HKLM:Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Authentication","HKLM:Software\Microsoft\Windows NT\CurrentVersion\Winlogon","HKLM:System\CurrentControlSet\Control\Winlogon","HKLM:Software\Microsoft\IdentityStore","HKLM:Software\Microsoft\IdentityCRL","HKU:.Default\Software\Microsoft\IdentityCRL","HKLM:System\CurrentControlSet\Services\Kdc","HKLM:System\CurrentControlSet\Control\CloudDomainJoin","HKCU:Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin","HKCU:Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\AADNGC","HKLM:Software\Microsoft\Windows\CurrentVersion\Winbio","HKLM:System\CurrentControlSet\Services\WbioSrvc","HKLM:Software\Policies\Microsoft\Biometrics","HKLM:System\CurrentControlSet\Control\EAS\Policies","HKCU:Software\Microsoft\SCEP","HKLM:Software\Microsoft\SQMClient","HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management","HKLM:Software\Policies\Microsoft\Windows\SmartCardCredentialProvider","HKLM:Software\Microsoft\Policies\PassportForWork","HKLM:Software\Policies\Microsoft\PassportForWork","HKCU:Software\Policies\Microsoft\PassportForWork","HKLM:Software\Microsoft\Policies\PassportForWork\SecurityKey","HKLM:System\CurrentControlSet\Control\Cryptography\Ngc","HKLM:Software\Microsoft\PolicyManager\current\device\DeviceLock","HKLM:Software\Policies\Microsoft\FIDO","HKLM:Software\Microsoft\CCMSetup","HKLM:Software\Microsoft\CCM")
	$global:KeysBITS = @("HKLM:Software\Policies\Microsoft\Windows\BITS","HKLM:System\CurrentControlSet\Services\BITS","HKLM:Software\Microsoft\Windows\CurrentVersion\BITS")
	$global:KeysBluetooth = @("HKLM:Software\Microsoft\PolicyManager\current\device","HKLM:System\CurrentControlSet\Services\BTHUSB\Parameters","HKLM:System\CurrentControlSet\Services\BTHPort\Parameters")
	$global:KeysBranchCache = @("HKLM:Software\Policies\Microsoft\PeerDist","HKLM:System\CurrentControlSet\services\PeerDistSvc","HKLM:Software\Microsoft\Windows NT\CurrentVersion\PeerDist","HKLM:Software\Policies\Microsoft\Windows\LanmanServer","HKLM:Software\Policies\Microsoft\WindowsFirewall\FirewallRules")
	$global:KeysCSC = @("HKCU:Software\Policies\Microsoft\Windows\Netcache","HKCU:Software\Microsoft\Windows\CurrentVersion\NetCache","HKLM:Software\Policies\Microsoft\NetCache","HKLM:Software\Microsoft\Windows\CurrentVersion\NetCache","HKLM:System\CurrentControlSet\services\CSC","HKLM:System\CurrentControlSet\services\CscService","HKCU:Network")
	$global:KeysCrypt = @("HKLM:System\CurrentControlSet\Control\Cryptography","HKLM:Software\Microsoft\Cryptography","HKCU:Software\Microsoft\Cryptography","HKLM:Software\Policies\Microsoft\Cryptography","HKCU:Software\Policies\Microsoft\Cryptography","HKLM:System\CurrentControlSet\Services\CertSvc","HKLM:Software\Policies\Microsoft\Windows\SmartCardCredentialProvider")
	$global:KeysDAsrv = @("HKU:S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings",	"HKLM:System\CurrentControlSet\services\raMgmt","HKLM:Software\Policies\Microsoft\Windows\RemoteAccess")
	$global:KeysDAcli = @("HKLM:Software\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig","HKLM:Software\Policies\Microsoft\Windows NT\tcp\ipv6Transition","HKLM:Software\Policies\Microsoft\Windows\WindowsFirewall")
	$global:KeysDeviceGuard = @("HKLM:System\CurrentControlSet\Control\DeviceGuard")
	$global:KeysDFS = @("HKLM:Software\Microsoft\Dfs","HKLM:System\CurrentControlSet\Services\DFS")
	$global:KeysDCOM = @("HKLM:System\CurrentControlSet\Control\LSA","HKLM:Software\Policies\Microsoft\Windows NT\DCOM","HKLM:Software\Microsoft\COM3","HKLM:Software\Microsoft\Rpc","HKLM:Software\Microsoft\OLE")
	$global:KeysDHCP = @("HKLM:System\CurrentControlSet\services\Dhcp","HKLM:System\CurrentControlSet\services\DHCPServer\Parameters")
	$global:KeysDHCPcli = @("HKLM:System\CurrentControlSet\services\Dhcp")
	$global:KeysDNS = @("HKLM:System\CurrentControlSet\services\DNS")
	$global:KeysFirewall = @("HKLM:System\CurrentControlSet\Services\MpsSvc","HKLM:System\CurrentControlSet\Services\MpsDrv","HKLM:System\CurrentControlSet\Services\BFE","HKLM:Software\Policies\Microsoft\WindowsFirewall\FirewallRules")
	$global:KeysFSLogix = @("HKLM:Software\FSLogix")
	#$global:KeysGPsvc = @("HKLM:Software\Policies\Microsoft")
	$global:KeysGeoLocation = @("HKLM:System\CurrentControlSet\Services\lfsvc\Settings","HKLM:System\CurrentControlSet\Services\lfsvc\TriggerInfo\3")
	$global:KeysHNS = @("HKLM:System\CurrentControlSet\Services\HNS","HKLM:System\CurrentControlSet\Services\vmsmp")
	$global:KeysHttp = @("HKLM:System\CurrentControlSet\Services\HTTP\Parameters")
	$global:KeysICS = @("HKLM:System\CurrentControlSet\Services\SharedAccess")
	#$global:KeysKIRMyKnobs = @("HKLM:Software\Microsoft\Windows\CurrentVersion\QualityCompat","HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management","HKLM:System\CurrentControlSet\Policies")
	$global:KeysLBFo = @("HKLM:System\CurrentControlSet\Control\Network","HKLM:System\CurrentControlSet\Services\NdisImPlatform","HKLM:System\CurrentControlSet\Services\MsLbfoProvider")
	$global:KeysLDAP = @("HKLM:System\CurrentControlSet\Services\ldap")
	$global:KeysLDAPcli = @("HKLM:System\CurrentControlSet\Services\ldap\Tracing")
	$global:KeysMBN = @("HKLM:System\CurrentControlSet\Services\Rasman","HKLM:System\CurrentControlSet\Services\RemoteAccess","HKLM:Software\Microsoft\WwanSvc","HKLM:Software\Microsoft\Wcmsvc","HKLM:Software\Policies")
	$global:KeysMDM = @("HKLM:Software\Microsoft\PolicyManager")
	$global:KeysMFAext = @("HKLM:Software\Microsoft\AzureMfa","HKLM:System\CurrentControlSet\Services\AuthSrv\Parameters")
	$global:KeysMiracast = @("HKLM:System\CurrentControlSet\Services\DeviceAssociationService")
	$global:KeysMountMgr = @("HKLM:System\CurrentControlSet\Services\MountMgr")
	$global:KeysNlaNCSI = @("HKLM:System\CurrentControlSet\services\NlaSvc\Parameters","HKLM:Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator","HKLM:Software\Policies\Microsoft\WindowsFirewall\FirewallRules")
	$global:KeysNPS = @("HKLM:System\CurrentControlSet\Services\RemoteAccess\Policy","HKLM:System\CurrentControlSet\Control\Lsa","HKLM:Software\Microsoft\Windows\CurrentVersion\Policies","HKLM:System\CurrentControlSet\Services\Netlogon")
	$global:KeysNTDS = @("HKLM:System\CurrentControlSet\Services\NTDS","HKLM:System\CurrentControlSet\Control\Lsa","HKLM:System\CurrentControlSet\Services\Netlogon")
	$global:KeysOle = @("HKLM:Software\Microsoft\Ole")
	$global:KeysOpenSSH = @("HKLM:Software\OpenSSH")
	$global:KeysPCI = @("HKLM:System\CurrentControlSet\Control\PnP\Pci","HKLM:System\CurrentControlSet\Enum\PCI","HKLM:System\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}","HKLM:System\CurrentControlSet\Control\Network\Uninstalled")
	$global:KeysPortProxy = @("HKLM:System\CurrentControlSet\Services\PortProxy")
	#$global:KeysPrint = @("HKLM:Software\Microsoft\Windows NT\CurrentVersion\Ports","HKLM:Software\Policies\Microsoft\Windows NT\Printers","HKLM:System\CurrentControlSet\Control\Print\Printers")
	$global:KeysProxy = @("HKLM:Software\Microsoft\Windows\CurrentVersion\Internet Settings","HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings","HKU:S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings")
	$global:KeysQoS= @("HKLM:System\CurrentControlSet\Services\Tcpip\QoS","HKLM:System\CurrentControlSet\Services\Tcpip\Parameters\QoS","HKLM:Software\Policies\Microsoft\Windows\QoS","HKCU:Software\Policies\Microsoft\Windows\QoS" )
	$global:KeysRAS = @("HKLM:System\CurrentControlSet\Services\IAS","HKU:S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings")
	$global:KeysRDS = @("HKLM:System\CurrentControlSet\Control\Terminal Server","HKLM:System\CurrentControlSet\Control\Print","HKLM:System\CurrentControlSet\Control\LSA","HKLM:System\CurrentControlSet\Control\SecurityProviders","HKLM:Software\Microsoft\Windows NT\CurrentVersion\Terminal Server","HKLM:Software\Microsoft\TermServLicensing","HKLM:Software\Microsoft\Terminal Server Client","HKCU:Software\Microsoft\Terminal Server Client","HKLM:Software\Policies","HKCU:Software\Policies","HKLM:Software\Microsoft\MSLicensing")
	$global:KeysRDS_HKCU_SW_POL = @("HKCU:Software\Policies")
	$global:KeysRDS_HKLM_SW_POL = @("HKLM:Software\Policies")
	$global:KeysRDS_HKCU_SW_TSC = @("HKCU:Software\Microsoft\Terminal Server Client")
	$global:KeysRDS_HKLM_SW_TSC = @("HKLM:Software\Microsoft\Terminal Server Client")
	$global:KeysRDS_HKLM_LSA = @("HKLM:System\CurrentControlSet\Control\LSA")
	$global:KeysRDS_HKLM_PRINT = @("HKLM:System\CurrentControlSet\Control\Print")
	$global:KeysRDS_HKLM_SECPROV = @("HKLM:System\CurrentControlSet\Control\SecurityProviders")
	$global:KeysRDS_HKLM_SVC = @("HKLM:System\CurrentControlSet\Services")
	$global:KeysRDS_HKLM_SW_TS = @("HKLM:Software\Microsoft\Windows NT\CurrentVersion\Terminal Server")
	$global:KeysRDS_HKLM_TS = @("HKLM:System\CurrentControlSet\Control\Terminal Server")
	$global:KeysRDS_HKLM_SW_TSL = @("HKLM:Software\Microsoft\TermServLicensing")
	$global:KeysRDS_HKLM_TSCAL = @("HKLM:Software\Microsoft\MSLicensing")
	$global:KeysRpc = @("HKLM:Software\Microsoft\Rpc","HKLM:System\CurrentControlSet\Services\RpcEptMapper","HKLM:System\CurrentControlSet\Services\RpcLocator","HKLM:System\CurrentControlSet\Services\RpcSs","HKLM:Software\Policies\Microsoft\Windows NT\Rpc")
	$global:KeysSMB = @(
		"HKLM:System\CurrentControlSet\services\LanManWorkstation"
		"HKLM:System\CurrentControlSet\services\lmhosts"
		"HKLM:System\CurrentControlSet\services\MrxSmb"
		"HKLM:System\CurrentControlSet\services\MrxSmb10"
		"HKLM:System\CurrentControlSet\services\MrxSmb20"
		"HKLM:System\CurrentControlSet\services\MUP"
		"HKLM:System\CurrentControlSet\services\NetBIOS"
		"HKLM:System\CurrentControlSet\services\NetBT"
		"HKCU:Network"
		"HKLM:System\CurrentControlSet\Control\NetworkProvider"
		"HKLM:System\CurrentControlSet\services\Rdbss"
		"HKLM:System\CurrentControlSet\Control\SMB"
	)
	$global:KeysSMBSrv = @(
		"HKLM:System\CurrentControlSet\services\LanManServer"
		"HKLM:System\CurrentControlSet\services\SRV"
		"HKLM:System\CurrentControlSet\services\SRV2"
		"HKLM:System\CurrentControlSet\services\SRVNET"
	)
	$global:KeysSNMP = @("HKLM:System\CurrentControlSet\Services\SNMP","HKLM:System\CurrentControlSet\Services\SNMPTRAP")
	$global:KeysTcp = @(
		#"HKLM:Software\Policies\Microsoft\Windows\TCPIP"
		"HKLM:System\CurrentControlSet\Services\TcpIp\Parameters"
		"HKLM:System\CurrentControlSet\Services\Tcpip6\Parameters",
		"HKLM:System\CurrentControlSet\Services\tcpipreg",
		"HKLM:System\CurrentControlSet\Services\iphlpsvc"
	)
	$global:KeysUEV = @("HKLM:Software\Microsoft\UEV")
	$global:KeysUSB = @("HKLM:System\CurrentControlSet\Control\Compatibility\Device","HKLM:System\CurrentControlSet\Enum")
	$global:KeysVPN = @("HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad","HKLM:System\CurrentControlSet\Services\Sstpsvc\Parameters")
	$global:KeysWebClient = @("HKLM:System\CurrentControlSet\Services\WebClient","HKLM:System\CurrentControlSet\Services\MRxDAV","HKLM:System\CurrentControlSet\Control\NetworkProvider","HKCU:Network","HKCU:Software\Microsoft\Office\16.0\Common\Internet","HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings","HKLM:Software\Microsoft\Windows\CurrentVersion\Internet Settings")
	$global:KeysWlan = @("HKLM:Software\Microsoft\WlanSvc","HKLM:Software\Policies\Microsoft\Windows\Wireless\GPTWirelessPolicy")
	$global:KeysWLBS = @("HKLM:System\CurrentControlSet\Services\WLBS")

 # B) section of FwAddRegItem -norecursive lists
	#$global:KeysDotNETFramework = @("HKLM:Software\WOW6432Node\Microsoft\.NETFramework","HKLM:Software\Microsoft\.NETFramework")	# now defined in _ADS
 	$global:KeysLSA = @("HKLM:System\CurrentControlSet\Control\LSA")
	$global:KeysMultiMedia = @("HKLM:Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile")

#endregion Registry Key modules

# Deprecated parameter list. Property array of deprecated/obsoleted params.
#   DeprecatedParam: Parameters to be renamed or obsoleted in the future
#   Type           : Can take either 'Rename' or 'Obsolete'
#   NewParam       : Provide new parameter name for replacement only when Type=Rename. In case of Type='Obsolete', put null for the value.
$NET_DeprecatedParamList = @(
	@{DeprecatedParam='NET_PrintSvc';Type='Rename';NewParam='UEX_Print'}
	@{DeprecatedParam='NET_PnP';Type='Rename';NewParam='DND_PnP'}
	@{DeprecatedParam='NET_PerfLib';Type='Rename';NewParam='PRF_PerfLib'}
	@{DeprecatedParam='NET_iSCSI';Type='Rename';NewParam='SHA_iSCSI'}
	@{DeprecatedParam='NET_SdnNC';Type='Obsolete';NewParam=''}
	@{DeprecatedParam='NET_SCM';Type='Rename';NewParam='PRF_SCM'}
)
Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *


# SIG # Begin signature block
# MIInvwYJKoZIhvcNAQcCoIInsDCCJ6wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDT8bfhOqPkWFcb
# 69kU661gm2/83UUYhm2mi3UVS3M8xaCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
# esGEb+srAAAAAANOMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI5WhcNMjQwMzE0MTg0MzI5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDdCKiNI6IBFWuvJUmf6WdOJqZmIwYs5G7AJD5UbcL6tsC+EBPDbr36pFGo1bsU
# p53nRyFYnncoMg8FK0d8jLlw0lgexDDr7gicf2zOBFWqfv/nSLwzJFNP5W03DF/1
# 1oZ12rSFqGlm+O46cRjTDFBpMRCZZGddZlRBjivby0eI1VgTD1TvAdfBYQe82fhm
# WQkYR/lWmAK+vW/1+bO7jHaxXTNCxLIBW07F8PBjUcwFxxyfbe2mHB4h1L4U0Ofa
# +HX/aREQ7SqYZz59sXM2ySOfvYyIjnqSO80NGBaz5DvzIG88J0+BNhOu2jl6Dfcq
# jYQs1H/PMSQIK6E7lXDXSpXzAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnMc7Zn/ukKBsBiWkwdNfsN5pdwAw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMDUxNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAD21v9pHoLdBSNlFAjmk
# mx4XxOZAPsVxxXbDyQv1+kGDe9XpgBnT1lXnx7JDpFMKBwAyIwdInmvhK9pGBa31
# TyeL3p7R2s0L8SABPPRJHAEk4NHpBXxHjm4TKjezAbSqqbgsy10Y7KApy+9UrKa2
# kGmsuASsk95PVm5vem7OmTs42vm0BJUU+JPQLg8Y/sdj3TtSfLYYZAaJwTAIgi7d
# hzn5hatLo7Dhz+4T+MrFd+6LUa2U3zr97QwzDthx+RP9/RZnur4inzSQsG5DCVIM
# pA1l2NWEA3KAca0tI2l6hQNYsaKL1kefdfHCrPxEry8onJjyGGv9YKoLv6AOO7Oh
# JEmbQlz/xksYG2N/JSOJ+QqYpGTEuYFYVWain7He6jgb41JbpOGKDdE/b+V2q/gX
# UgFe2gdwTpCDsvh8SMRoq1/BNXcr7iTAU38Vgr83iVtPYmFhZOVM0ULp/kKTVoir
# IpP2KCxT4OekOctt8grYnhJ16QMjmMv5o53hjNFXOxigkQWYzUO+6w50g0FAeFa8
# 5ugCCB6lXEk21FFB1FdIHpjSQf+LP/W2OV/HfhC3uTPgKbRtXo83TZYEudooyZ/A
# Vu08sibZ3MkGOJORLERNwKm2G7oqdOv4Qj8Z0JrGgMzj46NFKAxkLSpE5oHQYP1H
# tPx1lPfD7iNSbJsP6LiUHXH1MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGZ8wghmbAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDnq04yTfMo3QLkr8iOFwphe
# xaD9Rg/CrXD/uhVx9bTeMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAfL/J1RM8Kik1GDpTvS/FV6BrbPlUv6IKb2a27aGzbWnLUWD7Q2rWfjGn
# wUq/YB58ui1mGSUxm426E4Kxv6l8YC18U99PMQ4YleXOWeLnBaa9DN+/xl1AtFfM
# Hkurbe6mqxIlavtz44dL4Z3r8ILeMxzeNDvz3OjSgcBR8Ac7G+iyNhdJnxuGf7/Y
# KyxwiDWMSq0tVTvN0VaklaCeDrhJRY6OnG0F2ethoRe0IWiDZG3SJkUTwEeejNml
# lX6KBQ8SMJaq8r5sBzzaK5kznry6ux8nGgPfpBvq3npCHZKVvh+Lht0ky7sWb5Sm
# uwBomLIUOIvDZCwkZLJkn5XjViKfdqGCFykwghclBgorBgEEAYI3AwMBMYIXFTCC
# FxEGCSqGSIb3DQEHAqCCFwIwghb+AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsq
# hkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCK3UhseM9SiBr+UADPVUshsQ7NoIfAqQMvSTbjkIS5IAIGZGzyr5fM
# GBMyMDIzMDYwNjExNDQxOC4yOTFaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OkZDNDEtNEJENC1EMjIwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloIIReDCCBycwggUPoAMCAQICEzMAAAG59gANZVRPvAMAAQAAAbkwDQYJ
# KoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIw
# OTIwMjAyMjE3WhcNMjMxMjE0MjAyMjE3WjCB0jELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3Bl
# cmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpGQzQxLTRC
# RDQtRDIyMDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAONJPslh9RbHyQECbUIINxMF
# 5uQkyN07VIShITXubLpWnANgBCLvCcJl7o/2HHORnsRcmSINJ/qclAmLIrOjnYnr
# bocAnixiMEXC+a1sZ84qxYWtEVY7VYw0LCczY+86U/8shgxqsaezKpWriPOcpV1S
# h8SsOxf30yO7jvld/IBA3T6lHM2pT/HRjWk/r9uyx0Q4atx0mkLVYS9y55/oTlKL
# E00h792S+maadAdy3VgTweiwoEOXD785wv3h+fwH/wTQtC9lhAxhMO4p+OP9888W
# xkbl6BqRWXud54RTzqp2Vr+yen1Q1A6umyMB7Xq0snIYG5B1Acc4UgJlPQ/ZiMkq
# gxQNFCWQvz0G9oLgSPD8Ky0AkX22PcDOboPuNT4RceWPX0UVZUsX9IUgs7QF41Hi
# QSwEeOOHGyrfQdmSslATrbmH/18M5QrsTM5JINjct9G42xqN8VF9Z8WOiGMjNbvl
# pcEmmysYl5QyhrEDoFnQTU7bFrD3JX0fIfu1sbLWeBqXwbp4Z8yACTtphK2VbzOv
# i4vc0RCmRNzvYQQ2PjZ7NaTXE4Gu3vggAJ+rtzUTAfJotvOSqcMgNwLZa1Y+ET/l
# b0VyjrYwFuHtg0QWyQjP5350LTpv086pyVUh4A3w/Os5hTGFZgFe5bCyMnpY09M0
# yPdHaQ/56oYUsSIcyKyVAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUt7A4cdtYQ5oJ
# jE1ZqrSonp41RFIwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYD
# VR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# cmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwG
# CCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIw
# MjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcD
# CDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBAM3cZ7NFUHRMsLKz
# jl7rJPIkv7oJ+s9kkut0hZif9WSt60SzYGULp1zmdPqc+w8eHTkhqX0GKCp2TTqS
# zBXBhwHOm8+p6hUxNlDewGMZUos952aTXblAT3OKBnfVBLQyUavrSjuJGZAW30cN
# Y3rjVDUlGD+VygQHySaDaviJQbK6/6fQvUUFoqIk3ldGfjnAtnebsVlqh6WWamVc
# 5AZdpWR1jSzN/oxKYqc1BG4SxxlPtcfrAdBz/cU4bxVXqAAf02NZscvJNpRnOALf
# 5kVo2HupJXCsk9TzP5PNW2sTS3TmwhIQmPxr0E0UqOojUrBJUOhbITAxcnSa/IMl
# uL1HXRtLQZI+xs2eRtuPOUsKUW71/1YeqsYCLHLvu82ceDVQQvP7GHEEkp2kEjio
# fbjYErBo2iCEaxxeX4Z9HvAgA4MsQkbn6e4EFQf13sP+Kn3XgMIvJbqLJeFcQja+
# SUeOXu5cfkxe0GzTNojdyIwzaHlhOflVRZNrxee3B+yZwd3JHDIvv71uSI/SIzzt
# 9cU2GyHQVqxBSrRtKW6W8Vw7zpVvoVsIv3ljxg+7NiGSlXX1s7zbBNDMUj9OnzOl
# HK/3mrOU8YEuRf6RwakW5UCeGamy5MiKu2YuyKiGBCv4OGhPstNe7ALkEOh8BX12
# t4ntuYu+gw9L6yCPY0jWYaQtzAP9MIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJ
# mQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1
# WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjK
# NVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhg
# fWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJp
# rx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/d
# vI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka9
# 7aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKR
# Hh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9itu
# qBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyO
# ArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItb
# oKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6
# bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6t
# AgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQW
# BBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacb
# UzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYz
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnku
# aHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIA
# QwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2
# VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwu
# bWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEw
# LTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYt
# MjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/q
# XBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6
# U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVt
# I1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis
# 9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTp
# kbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0
# sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138e
# W0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJ
# sWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7
# Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0
# dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQ
# tB1VM1izoXBm8qGCAtQwggI9AgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxh
# bmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpG
# QzQxLTRCRDQtRDIyMDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaIjCgEBMAcGBSsOAwIaAxUAx2IeGHhk58MQkzzSWknGcLjfgTqggYMwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIF
# AOgpPGIwIhgPMjAyMzA2MDYxMzAyMjZaGA8yMDIzMDYwNzEzMDIyNlowdDA6Bgor
# BgEEAYRZCgQBMSwwKjAKAgUA6Ck8YgIBADAHAgEAAgICJDAHAgEAAgISVDAKAgUA
# 6CqN4gIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAID
# B6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAMKree/ijHEHZB2qMHdk
# yaekxx0PB6Reb/u36NIGhCYhfhJhEykfmfkoRvT2VlnrfCqRWEA24gsCeMr4WL/P
# lsBUxSMekzadDorNsAiPlDk3ABW7EpI4A94ZgP8K3jRntPw0WvJnhLfX2pROW+/v
# qgdbuOhpZZqNmW2bN4MG2IHcMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTACEzMAAAG59gANZVRPvAMAAQAAAbkwDQYJYIZIAWUDBAIB
# BQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQx
# IgQgfvMuAaipFIIeSJFfy9+HZbzDCkwdyonMkePKvXjZKeUwgfoGCyqGSIb3DQEJ
# EAIvMYHqMIHnMIHkMIG9BCBk60bO8W85uTAfJVEO3vX2aLaQFcgcGpdwsOoi+foP
# 9DCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABufYA
# DWVUT7wDAAEAAAG5MCIEIIiUQFOD/DfPKzh2HUCNc6L4hy56TKlgS0d/vmUR/IOe
# MA0GCSqGSIb3DQEBCwUABIICALMPLZUdx7zl0tRMxS35vQV/hoPU61Kv0Co4Fl28
# zOYTt+5L5eeOSeEWSXAMMZS8YJ67sr5WdkPcrx+NOBmbozNTmCQe9n4sFJP3Y+Zz
# BAnEJeT1IfLtFgwsHeRVhi+H0ZqVqQWaGpmzsyTMXh+ADa4vb0EVYihBLs6DLr4T
# Iw2ipYr/xN3griXhs2vbErlH/J/bBQ+OCfPVhe/Q096b2KGWXR5KrxkHQqzdert5
# eDsLtgpqk7DyJsep5LeYrbnfO6Zg+mVrnuuIQVLr4IoqO5ED4OVfHJCexAXJVa3a
# iLggxQxTlfuAVsDmxiQA6Gr4h1vPMbSwNB1V10Mj6gsyky2qXmIeiFpUZUAxPemb
# fPOCasD7Yz+fpCKft5aFmUOq4O76o+6ETdgCMam69LdbgURqVTZB3zNHyRDkr4th
# M9zCZSfshMOJSTzPr1714Lg7Z4/3gY2FxwXdMWUO4f+y4JIiMevUnrFCujrctmSt
# 9DT6wmSpZA8alhliud60FKON+DbnhIgw4v8PXkOBO0uH69fcqGL3UHPmznVE7NHe
# cgMcE3ksOCu32c6zfZP5GSVhdXbPdSPvjfWnxDWxtPmF+HgwM385Mr72GGw/sYg7
# dht2TwyG4pFZIGJ/kqOyd+Z/8gBLMxt566zYheiOHXPto77NGQfVkkxHv5Wr68q4
# koE1
# SIG # End signature block
