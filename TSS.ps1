# Helper script skeleton to allow both TSS.ps1 and TSSv2.ps1
# Script will start original TSSv2.ps1

#Requires -Version 3

#region ### All switches - for enabling PS auto-complete #2023-04-18
[CmdletBinding(DefaultParameterSetName='Start')]
Param(
	[Parameter(ParameterSetName='Start', Position=0)]
	[Switch]$Start,
	[Parameter(ParameterSetName='StartAutoLogger', Position=0)]
	[Switch]$StartAutoLogger,
	[Parameter(ParameterSetName='StartDiag', Position=0)]
	[String[]]$StartDiag,
	[Parameter(ParameterSetName='Start')]
	[Switch]$StartNoWait,	# do not wait at stage: Press ANY-Key to stop
	[Parameter(ParameterSetName='Stop', Position=0)]
	[Switch]$Stop,
	[Switch]$StopAutologger, # For compatibility.
	[Parameter(ParameterSetName='RemoveAutoLogger', Position=0)]
	[Switch]$RemoveAutoLogger,
	[Parameter(ParameterSetName='Find', Position=0)] 
	#[ValidateNotNullorEmpty()]
	[String]$Find,	# -> ProcessFindKeyword
	[Parameter(ParameterSetName='ListETWProviders', Position=0)]
	[String]$ListETWProviders,
	[Parameter(ParameterSetName='FindGUID', Position=0)]
	[String]$FindGUID,
	[Parameter(ParameterSetName='Help', Position=0)]
	[Switch]$Help,
	[Parameter(ParameterSetName='CollectLog', Position=0)]
	[String[]]$CollectLog,
	[Parameter(ParameterSetName='List', Position=0)]
	[Switch]$List,
	[Parameter(ParameterSetName='List')]
	[Parameter(ParameterSetName='ListSupportedCommands')]
	[Parameter(ParameterSetName='ListSupportedControls')]
	[Parameter(ParameterSetName='ListSupportedDiag')]
	[Parameter(ParameterSetName='ListSupportedLog')]
	[Parameter(ParameterSetName='ListSupportedNetshScenario')]
	[Parameter(ParameterSetName='ListSupportedNoOptions')]
	[Parameter(ParameterSetName='ListSupportedPerfCounter')]
	[Parameter(ParameterSetName='ListSupportedScenarioTrace')]
	[Parameter(ParameterSetName='ListSupportedSDP')]
	[Parameter(ParameterSetName='ListSupportedTrace')]
	[Parameter(ParameterSetName='ListSupportedWPRScenario')]
	[Parameter(ParameterSetName='ListSupportedXperfProfile')]
	[Switch]$ExportGUIcsv,
	[Parameter(ParameterSetName='ListSupportedCommands', Position=0)]
	[Switch]$ListSupportedCommands,
	[Parameter(ParameterSetName='ListSupportedControls', Position=0)]
	[Switch]$ListSupportedControls,
	[Parameter(ParameterSetName='ListSupportedDiag', Position=0)]
	[Switch]$ListSupportedDiag,
	[Parameter(ParameterSetName='ListSupportedLog', Position=0)]
	[Switch]$ListSupportedLog,
	[Parameter(ParameterSetName='ListSupportedNetshScenario', Position=0)]
	[Switch]$ListSupportedNetshScenario,
	[Parameter(ParameterSetName='ListSupportedNoOptions', Position=0)]
	[Switch]$ListSupportedNoOptions,
	[Parameter(ParameterSetName='ListSupportedPerfCounter', Position=0)]
	[Switch]$ListSupportedPerfCounter,
	[Parameter(ParameterSetName='ListSupportedScenarioTrace', Position=0)]
	[Switch]$ListSupportedScenarioTrace,
	[Parameter(ParameterSetName='ListSupportedSDP', Position=0)]
	[Switch]$ListSupportedSDP,
	[Parameter(ParameterSetName='ListSupportedTrace', Position=0)]
	[Switch]$ListSupportedTrace,
	[Parameter(ParameterSetName='ListSupportedWPRScenario', Position=0)]
	[Switch]$ListSupportedWPRScenario,
	[Parameter(ParameterSetName='ListSupportedXperfProfile', Position=0)]
	[Switch]$ListSupportedXperfProfile,
	[Parameter(ParameterSetName='Set', Position=0)]
	[String]$Set,
	[Parameter(ParameterSetName='Unset', Position=0)]
	[String]$Unset,
	[Parameter(ParameterSetName='Status', Position=0)]
	[Switch]$Status,
	[Parameter(ParameterSetName='TraceInfo', Position=0, HelpMessage='Choose one from: all|switch-name|command|scenario')]
	[ValidateNotNullOrEmpty()]
	[String]$TraceInfo,
	[Parameter(ParameterSetName='Version', Position=0)]
	[Switch]$Version,  		# This will show current TSS script version

#region ### All POD Trace provider component-names
#region ----- ADS POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_ADCS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_Basic,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_AccountLockout,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_ESR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_Auth,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_ADDS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_ADsam,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_BadPwd,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_LDAPsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_LockOut,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_DFSR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_EESummitDemo,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_GPedit,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_GPmgmt,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_GPsvc, 
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_Perf,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_UserInfo,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_PKICLIENT,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_NGC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_Bio,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_LSA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_NtLmCredSSP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_Kerb,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_KDC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_Netlogon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_Profile,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_SAM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_SSL,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_CryptNcryptDpapi,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_CryptoPrimitives,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_EFS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_WebAuth,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_SmartCard,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_CredprovAuthui,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_Appx,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_kernel,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_NTKernelLogger,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_ShellRoaming,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_CDP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_WinHTTP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_CEPCES,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_IIS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_GPO,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_TEST,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_W32Time,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_WinLAPS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$ADS_OCSP,
#endregion ----- ADS POD providers -----

#region ----- INT POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$INT_MSMQ,
#endregion ----- CRM POD providers -----

#region ----- CRM POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$CRM_Platform,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$CRM_IISdump,
#endregion ----- CRM POD providers -----

#region ----- Sharepoint SPS POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SPS_ULS,
#endregion ----- CRM POD providers -----

#region ----- DND POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DND_AudioETW,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DND_AudioWPR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DND_CBS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DND_CodeIntegrity,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DND_PNP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DND_Servicing,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DND_TPM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DND_WU,
#endregion ----- DND POD providers -----

#region ----- NET POD providers ----- 
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_TestMe,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_AfdTcpFull,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_AfdTcpBasic,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_AppLocker,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Auth,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_BFE,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_BGP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_BITS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Bluetooth,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_BranchCache,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_CAPI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_COM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Container,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_CSC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_DAcli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_DAmgmt,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_DAsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_DCLocator,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_DHCPcli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_DHCPsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_DNScli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_DNSsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Docker,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_EFS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Firewall,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_FltMgr,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_FSRM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_GeoLocation,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_HNS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_HTTP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_HttpSys,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_HypVmBus,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_HypVmms,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_HypVmWp,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_ICS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_IPAM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_IPhlpSvc,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_IPsec,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_iSCSI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_KernelIO,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_LBFO,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_LDAPcli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_LDAPsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_LLTDIO,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_LLDP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_MBAM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_MBN,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_MDM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_MFAext,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Miracast,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_MUX,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NCA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NCHA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NCSI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NDIS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NDIScap,	#packetCapture
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NDISwan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Netlogon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NetProfM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Netsetup,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NetworkUX,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NFC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NFScli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NFSsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NLB,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NPS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_NTFS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_OLE32,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_OpenSSH,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Outlook,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_PCI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_PerfLib,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_PnP,				#Deprecated: Please use DND
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_PortProxy,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_PrintSvc,			#Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Proxy,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_QoS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Quic,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RadioManager,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RAmgmt,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RAS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RasMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RDMA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RNDIS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsAuth,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsAuthMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsAudio,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsBroker,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsCore,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsRDclient,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsRDclientMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsH,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsHMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsPrintSpool,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsRAIL,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsRDGW,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsRDGWMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsRDMS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsRDMSMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsRDPCLIP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsRDPDR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsUsrLogon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsUsrLogonMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsVIP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RdsWRKSPC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RDScommon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RDScli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RDSsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_RPC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SCCM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SCM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SdnNC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SMB,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SmbCA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SMBcli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SMBsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SMBcluster,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_fskm,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_fsum,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_dns,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_fr,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_nbt,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_tcp,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_DFSmgmt,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_dfsn,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_srv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_smbhash,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_sr,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_rpcxdr,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_sec,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SNMP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SSTP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_SQLcheck,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_TAPI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_TaskSch,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_VMswitch,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_VPN,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WCM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WebClient,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WebIO,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WinInet,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WFP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WinNAT,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Winlogon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Winsock,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WinRM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WIP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Wlan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WmbClass,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WNV,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WSman,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_WWAN,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$NET_Workfolders,
#endregion ----- NET POD providers -----

#region ----- PRF POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Alarm,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_AppX,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Calc,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Camera,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Clipboard,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Cortana,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_DM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_DWM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Font,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_IME,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_ImmersiveUI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Media,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_NLS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Perflib,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Photo,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_RADAR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Shell,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Shutdown,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Speech,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_StartMenu,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Store,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_Sysmain,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_SystemSettings,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_UWP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$PRF_XAML,
#endregion ----- PRF POD providers -----

#region ----- SEC POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SEC_Defender,
#endregion ----- SEC POD providers -----

#region ----- SHA POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_ATAPort,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_CDROM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_CSVFS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_CSVspace,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_Dedup,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_FSRM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_HyperV,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_ISCSI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_MPIO,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_MsCluster,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_msDSM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_NFS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_ShieldedVM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_ReFS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_Storage,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_StorageReplica,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_StorageSense,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_StorageSpace,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_Storport,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_Storsvc,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_USB,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_VDS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_VHDMP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_VmConfig,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_VML,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_VMM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_VSS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SHA_WSB,
#endregion ----- SHA POD providers -----

#region ----- UEX POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Alarm,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_AppCompat,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_AppID,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_AppV,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_AppX, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Auth,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Calc,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Camera, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_CldFlt,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_ClipBoard,  # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_CloudSync,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_COM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_ContactSupport,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Cortana, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_CRYPT,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_DeviceStore,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_DM, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_DSC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_DWM, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_ESENT,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_EVT,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_EventLog,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Font, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_FSLogix,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Fusion,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_IME, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_ImmersiveUI, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_LicenseManager,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Logon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_LSA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_MDAG,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Media, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_MMC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_MMCSS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_MSRA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Nls, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Photo,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Print,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_PrintEx,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_QuickAssist,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_RDS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_RDWebRTC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_RestartManager,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_TSched,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_SCM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Search,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_ServerManager,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Shell, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Shutdown, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Speech, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_StartMenu, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Store, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_SystemSettings, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Task,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Telemetry,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_UEV,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_UserDataAccess,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_VAN,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_WER,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_Win32k,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_WinRM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_WMI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_WMIActivity,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_WMIBridge,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_WPN,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_WSC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_WVD,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_XAML, # Deprecated
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$UEX_PowerShell,
#endregion ----- UEX POD providers -----

#region ----- DEV POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DEV_TEST1,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DEV_TEST2,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DEV_TEST3,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DEV_TEST4,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$DEV_TEST5,
#endregion ----- DEV POD providers -----

#region ----- CustomETL providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$WIN_CustomETL,
#endregion ----- CustomETL providers -----

#endregion ### All POD Trace provider component-names

#region ### Command/Tool switches
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String[]]$CustomETL,
	[Parameter(ParameterSetName='Start')]
	[Switch]$Fiddler,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[ValidateSet("Start", "Stop", "Both")]
	[String]$GPresult,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[ValidateSet("Start", "Stop", "Both")]
	[String]$Handle,
	[Parameter(ParameterSetName='Start')]
	[ValidateSet("Start", "Stop", "Both")]
	[String]$LiveKD,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$Netsh,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String[]]$NetshScenario,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='PerfTCP')]
	[ValidateSet("Sender", "Receiver")]
	[String]$PerfTCP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='PerfTCP')]
	[String]$PerfTCPAddr,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='PerfTCP')]
	[Int]$Duration,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='PerfTCP')]
	[Int]$BufferLength,
	[Parameter(ParameterSetName='Start')]
	[String]$PerfMon,
	[Parameter(ParameterSetName='Start')]
	[String]$PerfMonLong,
	[Parameter(ParameterSetName='Start')]
	[Switch]$PktMon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[ValidateSet("Start", "Stop", "Both")]
	[String]$PoolMon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$Procmon,
	[Parameter(ParameterSetName='Start')]
	[Switch]$PSR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String[]]$Radar,
	[Parameter(ParameterSetName='Start')]
	[Switch]$RASdiag,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(Mandatory=$False,HelpMessage='Choose one technology from: Apps|CRMbase|Cluster|S2D|SCCM|CTS|DA|Dom|DPM|HyperV|Net|Perf|Print|RDS|Setup|SQLbase|SQLconn|SQLmsdtc|SQLsetup|SUVP|VSS|Mini|Nano|Remote|Repro|RFL|All')]
	[ValidateSet("Apps","CRMbase","Net","DA","Dom","DPM","CTS","Print","HyperV","Setup","Perf","Cluster","S2D","SCCM","RDS","Remote","SQLbase","SQLconn","SQLmsdtc","SQLsetup","SUVP","VSS","mini","nano","Repro","RFL","All")]
	[String[]]$SDP,
	[ValidateSet("noNetadapters","skipBPA","skipHang","skipNetview","skipSddc","skipTS","skipHVreplica","skipCsvSMB")]
	[Parameter(Mandatory=$False,HelpMessage='Choose technologies you want to skip from: noNetadapters|skipBPA|skipHang|skipNetview|skipSddc|skipTS|skipHVreplica|skipCsvSMB')]
	[String[]]$SkipSDPList,
	[Parameter(ParameterSetName='Start')]
	[Switch]$SysMon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='TTD')]
	[String[]]$TTD,
	[Parameter(ParameterSetName='Start')]
	[Switch]$Video,
	[Parameter(ParameterSetName='Start')]
	[Switch]$WFPdiag,
	[Parameter(ParameterSetName='Start')]
	[Switch]$WireShark,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[ValidateSet("BootGeneral", "General", "CPU", 'Device', 'Memory', 'Network', 'Registry', 'Storage', 'Wait', 'SQL', 'Graphic', 'Xaml', 'VSOD_CPU', 'VSOD_Leak')]
	[String]$WPR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[ValidateSet("General", "CPU", "Disk", 'Memory', "Network", "Pool", "PoolNPP", "Registry", "SMB2", "SBSL", "SBSLboot", "Leak")]
	[String]$Xperf,
#endregion ### Command/Tool switches

#region ### Control switches
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$BasicLog,
	[Switch]$CreateBatFile,
	[Parameter(ParameterSetName='Start')]
	#[Parameter(ParameterSetName='StartAutoLogger')]
	[Array]$CustomParams,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='CollectLog')]
	[Int]$DefenderDurInMin,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[string]$EtlOptions,	#  circular|newfile:<ETLMaxSize>:<ETLNumberToKeep>:<ETLFileMax>
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Int]$EvtDaysBack = 30,		# used for Eventlog conversion to csv and txt
	[Parameter(ParameterSetName='Start')]
	#[Parameter(ParameterSetName='StartAutoLogger')]
	[string]$ExternalScript,
	[Parameter(ParameterSetName='Start')]
	[Int]$PerfIntervalSec,
	[Parameter(ParameterSetName='Start')]
	[Int]$PerfLongIntervalMin,
	[Parameter(ParameterSetName='Start')]
	[Int]$PerfMonMaxMB,
	[string]$PerfMonCNF,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[String]$LogFolderPath,
	[Switch]$Merge,
	[Switch]$Mini,			# This will skip some data collections, see in Tss_NET.psm1
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[Parameter(ParameterSetName='ListETWProviders')]
	[ValidateSet("Basic","Medium","Advanced","Full","Verbose","VerboseEx","Hang","Restart","GetFarmdata","Swarm","Kube","Permission","traceMS","Server","Client","WinPE")]
	[Parameter(Mandatory=$False,HelpMessage='Choose script mode from: Basic|Medium|Advanced|Full|Verbose|VerboseEx|Hang|Restart|Swarm|Kube|GetFarmdata|Permission|traceMS|Server|Client|WinPE')]
	[String]$Mode,			# Run script in special mode, actual meaning depends on POD module (.psm1) implementation for this $global:Mode setting
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='Stop')]
	[String]$ProcmonAltitude,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String]$ProcmonFilter,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='Stop')]
	[String]$ProcmonPath,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Switch]$RemoteRun,		# use for TSS remote execution, renamed from switch name $Remote to avoid AmbiguousParameter
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[string[]]$Scenario,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='TTD')]
	[Int]$TTDMaxFile,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='TTD')]
	[ValidateSet("Full","Ring","Onlaunch")]
	[String]$TTDMode,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='TTD')]
	[String]$TTDOptions,	# '<Option string>' in single quotes
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='TTD')]
	[String]$TTDPath,
	[Switch]$Update,	# This will update current TSS script version to latest from GitHub
	[ValidateSet("Online","Quick","Full","Force","Lite")]
	[Parameter(Mandatory=$False,HelpMessage='Choose update mode from: Online|Lite')]
	[String]$UpdMode = "Online",  	
	[Parameter(ParameterSetName='Start')]
	[String]$WaitEvent,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[Switch]$xray = $True,	# Run always (for Telemetry), unless -noXray 
	[Switch]$beta = $False,	# hidden switch; set to $False = normal Production mode, $True = Testing/newFeature mode enabled
	[Switch]$Assist,		# Accessibility Mode
	[Switch]$noAdminChk,	# skip Admin check, which verifies elevated Admin rights
	[Switch]$noArgCheck,	# do not validate input command-line arguments
	[Switch]$noAsk,			# do not ask about good/failing scenario text input before compressing data
	[Switch]$noCab,			# Same as noZip. This will skip Compress phase. This switch is for having a comaptibility with TSSv1.
	[Switch]$noClearCache,	# do not clear DNS,NetBios,Kerberos,DFS chaches at start
	[Switch]$noCrash,		# do not run Crash after reboot again when using 'TSSv2 -stop -noCrash'
	[Switch]$noEventConvert,# do not convert Eventlogs to .CSV or .TXT format
	[Switch]$noExpire,		# allow TSS script to run even if its version is older then 30 days
	[Switch]$noFiddler,		# do not start Fiddler
	[Switch]$noGPresult,	# do not run GPresult, used to override setting in preconfigured TS scenarios
	[Switch]$noHandle,		# do not collect Handle.exe
	[Switch]$noHang,		# do not wait forever when data collection seems to hang 
	[Switch]$noLiveKD,		# do not capture LiveKD
	[Switch]$noNetsh,		# do not run Netsh, used to override setting in preconfigured TS scenarios
	[Switch]$noPerfMon,		# do not run PerfMon, used to override setting in preconfigured TS scenarios
	[Switch]$noPktMon,		# do not start PktMon
	[Switch]$noPoolMon,		# do not run PoolMon at start and stop
	[Switch]$noPrereqC,		# do not run PreRequisiteCheckInStage1/2() and PreRequisiteCheckForStart()
	[Switch]$noProcmon,		# do not run Procmon, used to override setting in preconfigured TS scenarios
	[Switch]$noQuickEdit,	# do not try to disable Quick Edit Mode
	[Switch]$noRASdiag,		# do not start RASdiag
	[Switch]$noRecording,	# do not ask about consent for performing PSR or Video recording, and do not start these recordings
	[Switch]$noRepro,		# skip stage waiting for repro
	[Switch]$noRestart,		# do not restart associated service
	[Switch]$noSDP,			# do not gather SDP report, i.e. when using script in scheduled tasks
	[Switch]$noSound,		# do not play attention sound
	[Switch]$noSysMon,		# do not start SysMon
	[Switch]$noTTD,			# do not start TTD (Time Travel Debugging)
	[Switch]$noVersionChk,	# skip online TSS version check 
	[Switch]$noWFPdiag,		# do not start WFPdiag
	[Switch]$noWireShark,	# do not start WireShark
	[Switch]$noWPR,			# do not run WPR, used to override setting in preconfigured TS scenarios
	[Switch]$noXperf,		# do not run xPerf, used to override setting in preconfigured TS scenarios
	[Switch]$noXray,		# do not start xray troubleshooter
	[Switch]$noZip,			# This will skip Compress phase
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[Switch]$noUpdate,		# do not AutoUpdate from cesdiagtools.blob.core.windows.net
	[Parameter(ParameterSetName='Start')]
	[Switch]$noPSR,
	[Parameter(ParameterSetName='Start')]
	[Switch]$noVideo,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='NetshScenario')]
	[Switch]$noPacket,		# prevent packets from being captured with Netsh (only ETW traces in the ScenarioName will be captured)
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[Switch]$noBasicLog,
	[Switch]$DebugMode,
	[Switch]$VerboseMode,
	[Switch]$AcceptEula,
	[Switch]$AddDescription,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Int]$NetshMaxSizeMB,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String]$NetshOptions,	# '<Option string>'
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String]$WPROptions,	# '<Option string>'
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Int]$XperfMaxFileMB,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String]$XperfOptions,	# '<Option string>'
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Int]$XperfPIDs,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String]$XperfTag,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SkipPdbGen,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[String]$CommonTask,
	[Switch]$EnableCOMDebug,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[Switch]$NewSession,
	[Switch]$Discard,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Switch]$CollectComponentLog,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[String[]]$ProcDump,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Switch]$ProcDumpAppCrash,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[String]$ProcDumpInterval,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[ValidateSet("Start","Stop","Both")]
	[String]$ProcDumpOption,	#="Both" #we# removed, as it would not obey setting in config.cfg
	[String]$InputlogPath,
	[Parameter(ParameterSetName='Start')]
	[Int]$StopWaitTimeInSec,
	[Parameter(ParameterSetName='Start')]
	[Int]$CheckIntInSec,	#poll Interval (for -WaitEvent)
	[Parameter(ParameterSetName='Start')]
	[Int]$HighCPUTimeInSec,
	[Parameter(ParameterSetName='Start')]
	[Int]$HighMemUsageInSec,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Switch]$Crash,
	[Parameter(ParameterSetName='Start')]
	[ValidateSet("Full", "Kernel","active","automatic","mini")]
	[String]$CrashMode,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[ValidateSet("Info","Warning","Error")]
	[String]$ETWlevel,		# in code $TraceLevel
	[Parameter(ParameterSetName='Start')]
	[String[]]$RemoteHosts,
	[Parameter(ParameterSetName='Start')]
	[String]$RemoteLogFolder,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='CollectLog')]
	[String[]]$Servers,
	[String]$StartTime,
	[String]$EndTime,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Switch]$CollectDump,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[String[]]$CollectEventLog,
	[Parameter(ParameterSetName='Start')]
	[Int]$MaxEvents,

	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$v,				# more verbose logging for ADS_Auth
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='Stop')]
	[string]$containerId,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='Stop')]
	[switch]$slowlogon,		# for ADS_Auth
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[switch]$noISECheck
#endregion ### Control switches
)
#endregion ### All switches


#region define variables/functions called in *.psm1 modules 
$global:BoundParameters = $MyInvocation.BoundParameters
Function global:FwGetProductTypeFromReg{
	switch ((Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\ProductOptions).ProductType)
	{
	  "WinNT"	 { return "WinNT"}
	  "ServerNT" { return "ServerNT"}
	  "LanmanNT" { return "LanmanNT"}
	  Default	 {"EmptyProductType"}
	}
}
#endregion define variables/functions calloed in *.psm1 modules 

#region MAIN
#$global:TssScriptName = $MyInvocation.MyCommand.Name
#Write-Host "ScriptName:         $global:TssScriptName"
#Write-Host "Line: $($MyInvocation.Line)"

#Loading all POD modules
foreach($file in Get-ChildItem){
	$extension = [IO.Path]::GetExtension($file)
	if ($extension -eq ".psm1" ){
		$modName = ($file.Name).substring(0, ($file.Name).length - 5)
		$modPath = ".\$($file.Name)"
		Remove-Module $modName -ErrorAction Ignore
		Import-Module $modPath -DisableNameChecking
	}
}
# pass input parameters/arguments to TSSv2.ps1
$CommandArg = $MyInvocation.Line -replace "^.*ps1.",""  # & 'C:\temp\tssv2 (1)\TSSv2.ps1' -Dev_TEST1 => -Dev_TEST1
# Replacing double quote(") with single quote(') - Issue#595
$CommandArg = $CommandArg -replace "`"","`'"
#Write-Host "Run: .\TSSv2.ps1 $CommandArg"
PowerShell.exe -c '.\TSSv2.ps1' $CommandArg
#endregion MAIN
# SIG # Begin signature block
# MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA7ny+XcpuNZNRH
# vRJU8g6yJsyXM51UKha1i7v2CZ6EK6CCDYUwggYDMIID66ADAgECAhMzAAADTU6R
# phoosHiPAAAAAANNMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI4WhcNMjQwMzE0MTg0MzI4WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDUKPcKGVa6cboGQU03ONbUKyl4WpH6Q2Xo9cP3RhXTOa6C6THltd2RfnjlUQG+
# Mwoy93iGmGKEMF/jyO2XdiwMP427j90C/PMY/d5vY31sx+udtbif7GCJ7jJ1vLzd
# j28zV4r0FGG6yEv+tUNelTIsFmmSb0FUiJtU4r5sfCThvg8dI/F9Hh6xMZoVti+k
# bVla+hlG8bf4s00VTw4uAZhjGTFCYFRytKJ3/mteg2qnwvHDOgV7QSdV5dWdd0+x
# zcuG0qgd3oCCAjH8ZmjmowkHUe4dUmbcZfXsgWlOfc6DG7JS+DeJak1DvabamYqH
# g1AUeZ0+skpkwrKwXTFwBRltAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUId2Img2Sp05U6XI04jli2KohL+8w
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzUwMDUxNzAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# ACMET8WuzLrDwexuTUZe9v2xrW8WGUPRQVmyJ1b/BzKYBZ5aU4Qvh5LzZe9jOExD
# YUlKb/Y73lqIIfUcEO/6W3b+7t1P9m9M1xPrZv5cfnSCguooPDq4rQe/iCdNDwHT
# 6XYW6yetxTJMOo4tUDbSS0YiZr7Mab2wkjgNFa0jRFheS9daTS1oJ/z5bNlGinxq
# 2v8azSP/GcH/t8eTrHQfcax3WbPELoGHIbryrSUaOCphsnCNUqUN5FbEMlat5MuY
# 94rGMJnq1IEd6S8ngK6C8E9SWpGEO3NDa0NlAViorpGfI0NYIbdynyOB846aWAjN
# fgThIcdzdWFvAl/6ktWXLETn8u/lYQyWGmul3yz+w06puIPD9p4KPiWBkCesKDHv
# XLrT3BbLZ8dKqSOV8DtzLFAfc9qAsNiG8EoathluJBsbyFbpebadKlErFidAX8KE
# usk8htHqiSkNxydamL/tKfx3V/vDAoQE59ysv4r3pE+zdyfMairvkFNNw7cPn1kH
# Gcww9dFSY2QwAxhMzmoM0G+M+YvBnBu5wjfxNrMRilRbxM6Cj9hKFh0YTwba6M7z
# ntHHpX3d+nabjFm/TnMRROOgIXJzYbzKKaO2g1kWeyG2QtvIR147zlrbQD4X10Ab
# rRg9CpwW7xYxywezj+iNAc+QmFzR94dzJkEPUSCJPsTFMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGXMwghlvAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAANNTpGmGiiweI8AAAAA
# A00wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIH0m
# PSKTbtF0EhuNB9LLaeCy2wMhPWlfd+A2eFaBOJ8dMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEABKIsPTQhPbyLnBU3+0gQLJGRAM3+9biHILa6
# fyyf8tD0cpi6FDnnNSgNOjVJlHt/389sf4FQvW4mBzMZcPqVhYSFghGCBRyPtWIQ
# 3lNOZ5GE82H6JR0gmEtAK8eJMxQ3vXwi1mCcl7yvOcyAxBDyb6VEIAWQnPZ4+pPa
# yRWGncbYmq9x8k0+5Ph/F4N42XXoAR3NSnTHuEP0WHJA+zq/vefM61u4P61nUn72
# lzXnYSkFXAZFUQtJ1hA8VEh2zDViS50g2q8XlgoKmXqz0QcSxa++a6Pliqi1iAAg
# 5vBX2uB8/ch49U/TW5AlKeiP5wSw0TtP1LAxQebuogM8ME5rg6GCFv0wghb5Bgor
# BgEEAYI3AwMBMYIW6TCCFuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCBLYR1TauKx24PvS0XOaji2s3++82sLHX35
# SWgYttF6BwIGZGzRLta6GBMyMDIzMDYwNjExNDQxNS45MjZaMASAAgH0oIHQpIHN
# MIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjpENkJELUUzRTctMTY4NTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEVQwggcMMIIE9KADAgECAhMzAAABx/sAoEpb8ifcAAEA
# AAHHMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMTEwNDE5MDEzNVoXDTI0MDIwMjE5MDEzNVowgcoxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQ2QkQtRTNF
# Ny0xNjg1MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr0LcVtnatNFMBrQTtG9P8ISA
# PyyGmxNfhEzaOVlt088pBUFAIasmN/eOijE6Ucaf3c2bVnN/02ih0smSqYkm5P3Z
# wU7ZW202b6cPDJjXcrjJj0qfnuccBtE3WU0vZ8CiQD7qrKxeF8YBNcS+PVtvsqhd
# 5YW6AwhWqhjw1mYuLetF5b6aPif/3RzlyqG3SV7QPiSJends7gG435Rsy1HJ4Xnq
# ztOJR41I0j3EQ05JMF5QNRi7kT6vXTT+MHVj27FVQ7bef/U+2EAbFj2X2AOWbvgl
# YaYnM3m/I/OWDHUgGw8KIdsDh3W1eusnF2D7oenGgtahs+S1G5Uolf5ESg/9Z+38
# rhQwLgokY5k6p8k5arYWtszdJK6JiIRl843H74k7+QqlT2LbAQPq8ivQv0gdclW2
# aJun1KrW+v52R3vAHCOtbUmxvD1eNGHqGqLagtlq9UFXKXuXnqXJqruCYmfwdFMD
# 0UP6ii1lFdeKL87PdjdAwyCiVcCEoLnvDzyvjNjxtkTdz6R4yF1N/X4PSQH4Flgs
# lyBIXggaSlPtvPuxAtuac/ITj4k0IRShGiYLBM2Dw6oesLOoxe07OUPO+qXXOcJM
# VHhE0MlhhnxfN2B1JWFPWwQ6ooWiqAOQDqzcDx+79shxA1Cx0K70eOBplMog27gY
# oLpBv7nRz4tHqoTyvA0CAwEAAaOCATYwggEyMB0GA1UdDgQWBBQFUNLdHD7BAF/V
# U/X/eEHLiUSSIDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
# KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4ICAQDQy5c8ogP0y8xAsLVca07wWy1mT+nqYgAFnz2972kN
# O+KJ7AE4f+SVbvOnkeeuOPq3xc+6TS8g3FuKKYEwYqvnRHxX58tjlscZsZeKnu7f
# GNUlpNT9bOQFHWALURuoXp8TLHhxj3PEq9jzFYBP2YNMLol70ojY1qpze3nMMJfp
# durdBBpaOLlJmRNTLhxd+RJGJQbY1XAcx6p/FigwqBasSDUxp+0yFPEBB9uBE3KI
# LAtq6fczGp4EMeon6YmkyCGAtXMKDFQQgdP/ITe7VghAVbPTVlP3hY1dFgc+t8YK
# 2obFSFVKslkASATDHulCMht+WrIsukclEUP9DaMmpq7S0RLODMicI6PtqqGOhdna
# RltA0d+Wf+0tPt9SUVtrPJyO7WMPKbykCRXzmHK06zr0kn1YiUYNXCsOgaHF5ImO
# 2ZwQ54UE1I55jjUdldyjy/UPJgxRm9NyXeO7adYr8K8f6Q2nPF0vWqFG7ewwaAl5
# ClKerzshfhB8zujVR0d1Ra7Z01lnXYhWuPqVZayFl7JHr6i6huhpU6BQ6/VgY0cB
# iksX4mNM+ISY81T1RYt7fWATNu/zkjINczipzbfg5S+3fCAo8gVB6+6A5L0vBg39
# dsFITv6MWJuQ8ZZy7fwlFBZE4d5IFbRudakNwKGdyLGM2otaNq7wm3ku7x41UGAm
# kDCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQEL
# BQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNV
# BAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4X
# DTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM
# 57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm
# 95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzB
# RMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBb
# fowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCO
# Mcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYw
# XE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW
# /aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/w
# EPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPK
# Z6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2
# BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfH
# CBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYB
# BAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8v
# BO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYM
# KwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEF
# BQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBW
# BgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUH
# AQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# L2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsF
# AAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518Jx
# Nj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+
# iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2
# pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefw
# C2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7
# T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFO
# Ry3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhL
# mm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3L
# wUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5
# m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE
# 0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLLMIICNAIB
# ATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UE
# CxMdVGhhbGVzIFRTUyBFU046RDZCRC1FM0U3LTE2ODUxJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAOIASP0JSbv5
# R23wxciQivHyckYooIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwDQYJKoZIhvcNAQEFBQACBQDoKRpeMCIYDzIwMjMwNjA2MTAzNzE4WhgPMjAy
# MzA2MDcxMDM3MThaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOgpGl4CAQAwBwIB
# AAICG7EwBwIBAAICEg0wCgIFAOgqa94CAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYK
# KwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUF
# AAOBgQAN/sbdqt6Euw5+b1xA9b0gSFo2L0qCNsSxqd5mDpaOYz0+yO7c9VQjBiOD
# 193NMF3+mCcFPpeL8pfyULP82YxAQdIC/WB/lJvq6TIW1MA6JfBgVLH3nmNcq5Rx
# jdsZcevX5/Uin8j+EnQTGzhcCCPwFJL5KHT4rTuCPILqmPNWAzGCBA0wggQJAgEB
# MIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABx/sAoEpb8ifc
# AAEAAAHHMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwLwYJKoZIhvcNAQkEMSIEINfNNHS2k+RQhS2pgjQG/OLylrwZ9TEm/Azc
# PHOr2vIhMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgR+fl2+JSskULOeVY
# LbeMgk7HdIbREmAsjwtcy6MJkskwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAcf7AKBKW/In3AABAAABxzAiBCBw0BsC2W4cUKa1LQsP
# 5LlDtvdkG/ilOXoncaeUUhzlXjANBgkqhkiG9w0BAQsFAASCAgBCiHnzxgQpBgev
# fmfw+3OgfxD2d/dEata1/WNRwScBubxBTp+1rz606QVT74ZNmBs1G+RLvqIEoos1
# IXwElKQtvydyo3tdim3Jd7KVVsb1GLVhQhAWVi10lU7RnLE4kcYLMkVSfJkHWeE7
# qDjVJoZ7S0Sxp7urAnARcwILjRRH8Q+kprQ5PEb2Ekvyz2fXgE0om44XxXx1lQ15
# DOR0nBHfyou8WDfS7mxIT0Nv7BryKcx1ukSWmtKDwy+qSlIOe1As+GEOJIq38W9x
# gQcYio1mM+RoE3zr2NbGiKD8oMXxWkNIpOHMVByCACLyVboT/YC46S+YlZ+rgK41
# SoGXfWFkcIIXJ1w7diTd274YsmWF/DExS0GcJrtbNCQc7i7/KaFWKbJrIqiKccYl
# Ui/3fJhH/tjx/BnSnXJKrSuVaj3KnG77fXT78/XW3sdhJ1wGNzF3xMnLeT/dJkNF
# Er4YZMCW9KzkyJK5fPXHz+CUGAa+l6/TApNiGZjrSVYOJP15aBui7ktPYfOyRO90
# dDRm53hn9pjaHoRKhMLw0pG+lOnCqYxV10ztOFrpMLbr8c+CFMDdtx20g0aeyuCX
# bg/Mfv8M+prZS36M3Cml+37BCCcBAH6d/kzXX+uQzqXmS6G6YQdj1SYfGRCz4I23
# Qorfg0y+pEaCaOX7eSx56T9/UiEnJw==
# SIG # End signature block
