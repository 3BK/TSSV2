<# File: TSSv2_UEX.psm1
.SYNOPSIS
   UEX module for collecting ETW traces and various custom tracing functionality

.DESCRIPTION
   Define ETW traces for Windows UEX components 
   Add any custom tracing functinaliy for tracing PRF components

.NOTES
   Dev. Lead  : ryhayash (acting)
   Authors	: Ryutaro Hayashi (ryhayash@microsoft.com); milanmil; Yasuhiro Takahashi; Garabier; cnaudy; Robert Klemencz
   Requires   : PowerShell V4 (Supported from Windows 8.1/Windows Server 2012 R2)
   Version	: see $global:TssVerDateUEX

.LINK
	TSSv2 https://internal.support.services.microsoft.com/en-us/help/4619187
	UEX : https://internal.support.services.microsoft.com/en-us/help/5013201
#>

<# latest changes
  2023.06.01.0 [gr] _UEX: UEX_Telemetry : update RegKey names depending on the function called
  2023.05.29.0 [gbrag] _UEX: Updated calls to WinRM-Collect and Sched-Collect
  2023.05.19.3 [tfairman] _NET: Move SCM component to TSSv2_PRF
  2023.05.19.0 [rk] _UEX: Added MSRD-Collect for 'AVD host' data collection (UEX_AVDCore, UEX_AVDProfiles, UEX_AVDActivation, UEX_AVDMSRA, UEX_AVDSCard, UEX_AVDIME, UEX_AVDTeams, UEX_AVDMSIXAA, UEX_AVDHCI, UEX_AVDDiag)
  2023.05.18.1 [hk] _UEX: UEX_Print : added GUID
  2023.05.18.0 [hk] _UEX: UEX_AppCompat : added GUID
  2023.05.10.0 [gr] _UEX: Telemetry: Added Appcompat folder,Use of the FW function to add/Remove registry values
  2023.04.24.0 [cn] _UEX: MDAG: Adding more providers and added some collection
  2023.04.19.0 [gr] _UEX: UEX_Telemetry : PostOp : Modified AppRaiser, add as is M365HandlerLog, DisableAppRaiserVerboseMode and RestartDiagTrack
  2023.04.18.0 [gr] _UEX: UEX_Telemetry : Appraiser in PostOp
  2023.04.14.0 [cn] _UEX: paths with space bug fixes
  2023.04.13.1 [gr] _UEX: UEX_Telemetry : added census
  2023.04.13.0 [cn] _UEX: Adding MDAG Containers data collection and fixed few bugs (reg size exported)
  2023.04.12.0 [yn] _UEX: UEX_AppId : added GUID and CollectLogs
  2023.04.11.0 [gr] _UEX: UEX_Telemetry : added the ConnectivityDiagnosis
  2023.04.07.0 [rh] _UEX: Move previou UEX components to PERF and add deprecated param list to show friendly error message 
  2023.04.05.0 [cn] _UEX: Adding more etl and solving minor bugs.  
  2023.04.04.1 [gr] _UEX: UEX_Telemetry : Improved the function
  2023.04.04.0 [cn] _UEX: Adding MDAG collection
  2023.04.03.1 [gr] _UEX: UEX_Telemetry : Added the registry keys to export
  2023.04.02.0 [rh] _UEX: Merge NET_PrintSvc functions into UEX_Print(Feature#362)
  2023.03.31.2 [gr] _UEX: UEX_Telemetry : Started the Function Telemetry with the add of the ETL Tracing Providers
  2023.03.31.1 [gr] _UEX: UEX_WMIHighCPU : Removed UEX_Kernel trace and use ADS_Kernel one
  2023.03.31.0 [rh] _UEX: Merge GUIDs in PrintTrace.cmd into UEX_Print(Feature#362)
  2023.03.30.0 [gr] _UEX: UEX_WMIHighCPU : Added the WMIK instead of WMI provider + NoBasicLogs
  2023.03.27.0 [cn] _UEX: Adding MDAG Host ETL tracing
  2023.03.20.0 [gr] _UEX: Adding the WMI HighCPU Scenario
  2023.03.17.0 [gr] _UEX: Adding UEX_Fusion and adding UEX_MMC Scenario
  2023.03.15.0 [rh] _UEX: merge UEX_Mgmt to UEX module
  2023.02.23.0 [rh] _UEX: comment out CollectUEX_WMILog and CollectUEX_WinRMLog to avoid duplication with UEX_Mgmt module
  2023.02.21.0 [gr] _UEX: Add WinRM collect to UEX_Winrm scenario + MMC Collect
  2023.02.07.0 [we] _UEX: add UEX_MMCSS
  2022.12.07.0 [we] _UEX: add -Scenario UEX_General
  2022.11.28.0 [we] consolidating NET/UEX *_WMI and *_AppV tracing
  2022.07.27.0 [rh] add Get-StartApps to -UEX_Logon
  2022.06.08.0 [rh] add AssignedAccess registries to -UEX_Logon
  2022.05.31.0 [we] #_# fixed typos, replaced FileVersion with FwFileVersion
  2022.05.29.0 [rh] remove CollectUEX_BasicLog() as it was replaced with -Basiclog
  2022.05.16.0 [we] use FW functions like FwGetMsInfo32, FwCollect_BasicLog
  2022.04.28.0 [rh] add shell CSP provider to UEX_Shell and UEX_DM
  2022.04.19.0 [we] add UEX_PrintEx, UEX_DSC, UEX_Evt, UEX_Tsched dummy providers
  2021.12.29.0 [we] fix #381 for Get-Timezone on Srv2012
  2021.12.08.0 [we] add collect -UEX_PrintEx -> change later to UEX_Print, once SME's decide to remove current UEX_Print component
  2021.10.22.0 [we] call external \scripts\*-collect.ps1 for UEX_DSC, UEX_Evt, UEX_TSched
#>

#Requires -Version 4

$global:TssVerDateUEX = "2023.06.01.0"

#region --- ETW component trace Providers ---
$UEX_DummyProviders = @(
	'{eb004a05-9b1a-11d4-9123-0050047759bc}' ## Dummy tcp for switches without tracing GUID (issue #70)
)
$UEX_PrintExProviders = $UEX_DummyProviders
$UEX_DSCProviders = $UEX_DummyProviders
$UEX_EvtProviders = $UEX_DummyProviders
$UEX_TSchedProviders = $UEX_DummyProviders

$UEX_AVDCoreProviders = $UEX_DummyProviders
$UEX_AVDProfilesProviders = $UEX_DummyProviders
$UEX_AVDActivationProviders = $UEX_DummyProviders
$UEX_AVDMSIXAAProviders = $UEX_DummyProviders
$UEX_AVDTeamsProviders = $UEX_DummyProviders
$UEX_AVDSCardProviders = $UEX_DummyProviders
$UEX_AVDMSRAProviders = $UEX_DummyProviders
$UEX_AVDIMEProviders = $UEX_DummyProviders
$UEX_AVDHCIProviders = $UEX_DummyProviders
$UEX_AVDDiagProviders = $UEX_DummyProviders

#---  MDAG PROVIDERS ---#
$UEX_MDAGProviders = @(
	# RDP
	'{0C51B20C-F755-48a8-8123-BF6DA2ADC727}!MDAGHost!0xF000FFFFFFFF!0xff' #mstsc.exe
	'{DAA6CAF5-6678-43f8-A6FE-B40EE096E06E}!MDAGHost!0xF000FFFFFFFF!0xff' #mstscax.dll
	'{ea605ac7-d9de-434a-8271-682fee6d59ca}!MDAGHost!0xF000FFFFFFFF!0xff' #TSClientTrace
	'{D4197645-41DE-4ad5-9D71-A612C508FDD8}!MDAGHost!0xF000FFFFFFFF!0xff' #rdpxclient.exe
	'{8C74CED2-9899-4E01-A6D2-F924045DE932}!MDAGHost!0xF000FFFFFFFF!0xff' #rendrdp.dll
	'{70DB53D8-B6F3-428d-AA33-5B2CE56718C5}!MDAGHost!0xF000FFFFFFFF!0xff' #aaclient.dll
	'{936FF90C-7CC4-40d8-8A04-77B281C73AB9}!MDAGHost!0xF000FFFFFFFF!0xff' #aaclient.dll
	'{070f54b9-7eb0-4c99-8dfa-2aa8d8ab0d89}!MDAGHost!0xF000FFFFFFFF!0xff' #tsworkspace.dll
	'{3D3E7039-99DF-4446-8C81-4AD5A8560E7B}!MDAGHost!0xF000FFFFFFFF!0xff' #wkspbroker.exe
	'{3E3E7039-99DF-4446-8C81-4AD5A8560E7B}!MDAGHost!0xF000FFFFFFFF!0xff' #wkspbrokerAx.dll
	'{3C3E7039-99CF-4446-8D81-4AC5A8560E7B}!MDAGHost!0xF000FFFFFFFF!0xff' #wksprt.exe
	'{70A43AE8-E131-42bd-89E0-23704FB27C6A}!MDAGHost!0xF000FFFFFFFF!0xff' #tswbprxy.exe
	'{43471865-f3ee-5dcf-bf8b-193fcbbe0f37}!MDAGHost!0xffffffff!0x05'	 #Microsoft.Windows.RemoteDesktopServices.RailPlugin
	'{080656c2-c24f-4660-8f5a-ce83656b0e7c}!MDAGHost!0xffffffff!0x05'	 #Microsoft.Windows.RemoteDesktop.ClientCore
	'{cbdedbe0-b5c2-4ff6-905b-7a5ec0ebf8ed}!MDAGHost!0xffffffff!0x05'	 # radcui.dll
	'{7b919abb-998b-46a9-b8f3-d4a49e8074da}!MDAGHost!0xffffffff!0x05'	 # rdpnano.dll

	#HVSI
	'{b29d9185-a1eb-4740-84c3-b06f85d89341}!MDAGHost!0xffffffff!0xff'	 #hvsi service WPP
	'{7061B8A0-53F0-481D-9B10-BA98EFB69436}!MDAGHost!0xffffffff!0xff'	 #hvsi manager WPP
	'{483705FD-030A-4F15-8333-1B6BEF8E41CB}!MDAGHost!0xffffffff!0xff'	 #HvsiSettingsProvider WPP
	'{31a02453-ca69-48d4-a17e-97d08518f45c}!MDAGHost!0xffffffff!0xff'	 #Microsoft.Windows.HVSI.ContainerService
	'{5e3f60ef-a60f-45a9-84ae-e224f761baa3}!MDAGHost!0xffffffff!0xff'	 #Microsoft.Windows.HVSI.Manager
	'{c4ded72b-549f-4c21-8470-cb218a625a9e}!MDAGHost!0xffffffff!0x06'	 #Microsoft.Windows.Hvsi.Filter
	'{106e9835-2e81-5341-fd84-ab263098e7d3}!MDAGHost!0xffffffff!0xff'	 #Microsoft.Windows.HVSI.Settings
	'{372e8999-7d93-5961-0479-d472d9fe23f7}!MDAGHost!0x00000000!0xff'	 #Microsoft.Windows.HVSI.AppLauncher
	'{594ed7cb-28c9-4720-92d5-83e18518e364}!MDAGHost!0xffffffff!0xff'	 #Microsoft.Windows.HVSI.AuditSettings
	'{c76678a6-e4d0-4c49-b276-fb31d83f9b68}!MDAGHost!0x00000000!0x00'	 #Microsoft.Windows.HVSI.ChromeExtension
	'{3686a7c1-8c7a-442d-ae1c-b498470968c2}!MDAGHost!0xffffffff!0xff'	 #Microsoft.Windows.HVSI.CSP
	'{0b8d083d-254e-56d3-34df-d2134ce309e6}!MDAGHost!0x00000000!0xff'	 #Microsoft.Windows.HVSI.FileTrustFilter
	'{a2a602d5-1865-4a1f-bcd7-d67847deb021}!MDAGHost!0xffffffff!0xff'	 #Microsoft.Windows.HVSI.HvsiTask
	'{12a9c970-7843-482a-9c1b-fd39d4f3533a}!MDAGHost!0x00000000!0xff'	 #Microsoft.Windows.HVSI.PolicyEvaluator
	'{50134cdd-5fe1-4315-8c8d-50900921acce}!MDAGHost!0x00000000!0xff'	 #Microsoft.Windows.HVSI.RDP
	'{afc8a033-e28a-415c-acff-030e4b113a35}!MDAGHost!0xffffffff!0x05'	 #Microsoft.Streaming.Basix

	#Containers and VM
	'{9498441b-f0e0-4331-a5ad-a3e77e0ff2f4}!MDAGHost!0x0fffffff!0x07'	 #VMUSRV
	'{cb5b2c18-ad73-4ebf-8af1-73b30b885030}!MDAGHost!0x01100000!0x05'	 #VMBusDriverTraceGuid
	'{22267b1c-b979-5c81-9e24-0db386a62dd1}!MDAGHost!0xffffffff!0xff'	 #Microsoft.Windows.Containers.Setup
	'{80ce50de-d264-4581-950d-abadeee0d340}!MDAGHost!0x7fffffff!0x06'	 #Microsoft.Windows.HyperV.Compute - also used in netsh
	'{67eb0417-9297-42ae-a1d9-98bfeb359059}!MDAGHost!0x7fffffff!0xff'	 #Microsoft.Windows.Containers.Library
	'{6e31f252-a41c-41d7-a9e2-3a20162247ec}!MDAGHost!0xffffffff!0xff'	 #Microsoft.Windows.Containers.Wcifs
	'{AEC5C129-7C10-407D-BE97-91A042C61AAA}!MDAGHost!0xffffffff!0xff'	 #Microsoft-Windows-Containers-Wcifs
	'{8ce2286c-3705-4a2a-8e36-134eae9ca147}!MDAGHost!0x00000000!0x00'	 #Microsoft.Windows.Containers.DynamicImage
	'{74c975b8-6693-4aef-a440-13a4def639a6}!MDAGHost!0x00000000!0x00'	 #Microsoft.Windows.Containers.ImageWorker
	'{9d911ddb-d45f-41c3-b766-d566d2655c4a}!MDAGHost!0x00000000!0x00'	 #Microsoft.Windows.Containers.Manager
	'{1111450b-dacc-40a3-84ab-f7dba4a6e63a}!MDAGHost!0x00000000!0x00'	 #Microsoft.Windows.HyperV.VID
	'{b2ed3bdb-cd74-5b2c-f660-85079ca074b3}!MDAGHost!0x00000000!0x00'	 #Microsoft.Windows.HyperV.Socket
	'{06c601b3-6957-4f8c-a15f-74875b24429d}!MDAGHost!0xffffffff!0x05'	 #Microsoft.Windows.HyperV.Worker

	#Network 
	'{66c07ecd-6667-43fc-93f8-05cf07f446ec}!MDAGNetComponents!0xffffffff!0x05'	  #Microsoft-Windows-WinNat
	'{aa7387cf-3639-496a-b3bf-dc1e79a6fc5a}!MDAGNetComponents!0xffffffff!0x06'	  #WinNat WPP
	'{07b7592c-a848-4520-89da-1ab26bc4629f}!MDAGNetComponents!0xffffffff!0xff'	  #Microsoft.Windows.Networking.EDP
	'{0c885e0d-6eb6-476c-a048-2457eed3a5c1}!MDAGNetComponents!0xffffffff!0x06'	  #Microsoft-Windows-Host-Network-Service
	'{93f693dc-9163-4dee-af64-D855218af242}!MDAGNetComponents!0xffffffff!0x05'	  #Microsoft-Windows-Host-Network-Management
	'{564368D6-577B-4af5-AD84-1C54464848E6}!MDAGNetComponents!0xffffffff!0x06'	  # Microsoft-Windows-Overlay-HNSPlugin
	'{D0E4BC17-34C7-43fc-9A72-D89A59D6979A}!MDAGNetComponents!0xffffffff!0x06'    # Microsoft.Windows.HostNetworkingService.PrivateCloudPlugin
	'{A6F32731-9A38-4159-A220-3D9B7FC5FE5D}!MDAGNetComponents!0xffffffff!0x06'	  # Microsoft-Windows-SharedAccess_NAT
	'{6C28C7E5-331B-4437-9C69-5352A2F7F296}!MDAGNetComponents!0xffffffff!0x06'	  # Microsoft.Windows.Hyper.V.VmsIf
	'{C29C4FB7-B60E-4FFF-9AF9-CF21F9B09A34}!MDAGNetComponents!0xffffffff!0x06'	  # Microsoft-Windows-Hyper-V-SynthNic
	# VmSwitch Enable ETW and WPP Events - Control Path Only
	'{1F387CBC-6818-4530-9DB6-5F1058CD7E86}!MDAGNetComponents!0xFFDFFFFB!0x06'	  # vmswitch 
	'{67DC0D66-3695-47c0-9642-33F76F7BD7AD}!MDAGNetComponents!0xFFFFFFDD!0x06'	  # Microsoft-Windows-Hyper-V-VmSwitch
	'{9F2660EA-CFE7-428F-9850-AECA612619B0}!MDAGNetComponents!0x00410000!0x06'	  # Microsoft-Windows-Hyper-V-VfpExt
	# available starting in build 19041. Will check later
	#'{9F2660EA-CFE7-428F-9850-AECA612619B0}!MDAGNetComponents!0x00410000!0x06'    # Microsoft.Windows.Hyper.V.NetSetupHelper

	#Others
	'{d82215e3-bddf-54fa-895b-685099453b1c}!MDAGHost!0xffffffff!0xff'	 #Microsoft.Windows.BackgroundActivityModerator
	'{4e2b1375-f519-50a6-bfae-8c8a1a82d708}!MDAGHost!0xffffffff!0xff'	 #Microsoft.Windows.Shell.BackgroundActivityModerator

	#Firewall
	'{5EEFEBDB-E90C-423A-8ABF-0241E7C5B87D}!HostFirewall!0xffffffff!0xff'
	'{D8FA2E77-A77C-4494-9297-ACE3C12907F6}!HostFirewall!0xffffffff!0xff'
	'{28C9F48F-D244-45A8-842F-DC9FBC9B6494}!HostFirewall!0xffffffff!0xff'
	'{106B464A-8043-46B1-8CB8-E92A0CD7A560}!HostFirewall!0xffffffff!0xff'
	'{0C478C5B-0351-41B1-8C58-4A6737DA32E3}!HostFirewall!0xffffffff!0xff'
	'{AD33FA19-F2D2-46D1-8F4C-E3C3087E45AD}!HostFirewall!0xffffffff!0xff'
	'{5A1600D2-68E5-4DE7-BCF4-1C2D215FE0FE}!HostFirewall!0xffffffff!0xff'

	#Too verbose
	#'{7e9e8b9c-406c-5d73-e566-0f50ea3ade3e}!MDAGHost!0xffffffff!0x05'	 #EventProvider-Microsoft-Windows-Kernel-MemoryManager
	#'{D1D93EF7-E1F2-4F45-9943-03D245FE6C00}!MDAGHost!0xffffffff!0x05'	 #Microsoft-Windows-Kernel-Memory
)

#---  RDS PROVIDERS ---#
$UEX_RDSProviders = @(
	'{82A94E1C-C1B3-4E4A-AC87-43BD802E458E}' # KernVC
	'{FA801570-83A9-11DF-B3A9-8C26DFD72085}' # RdCentralDbPlugin
	'{D4199645-41BE-4FD5-9D71-A612C508FDC6}' # RDPApiTrace
	'{D4199645-41BE-4FD5-9D73-A612C508FDC6}' # RDPApiTraceTS
	'{796F204A-44FC-47DF-8AE4-77C210BD5AF4}' # RdpClip
	'{D4199645-41BE-4FD5-9D71-A612C508FDC7}' # RDPEncComTrace
	'{8A99FD17-7D82-45D9-A965-F9A3F9FA85E5}' # RdpFilterTrace
	'{C5615DDA-2DAC-479B-83AB-F18C95601774}' # rdpInput
	'{15D9261C-EFDF-4C4A-8D3C-098A15DC483D}' # RdpNetEmu
	'{6CDD992D-B35C-40A6-AF1E-D727C11DECFD}' # RdvgKmdTrace
	'{84214511-602B-4456-9CB9-7800ED3432F6}' # RdvgmTrace
	'{6AABAEA6-DF19-4528-97D8-3A420CEE69A0}' # RdvgUmd11Trace
	'{2A11472B-451F-4FCA-8590-9724D41C604E}' # RDVVGHelper
	'{C29D637F-AFB5-43F9-96F8-936429371F32}' # RdvVmCore
	'{482F83D3-E8CB-4727-8A28-FC51544C5A28}' # RdvVmTransport
	'{80342309-054F-4E2E-9D3D-FCCFBDCAA92F}' # CtVmtLibTraceGuid
	'{5283D5F6-65B5-425F-A30B-F16C057D6B57}' # termsrv
	'{0B938561-4D72-4312-ACF6-109D34C26148}' # CMProxyGuest
	'{5CE9C675-02A0-4B9D-89E6-77C13EF68E75}' # CMProxyHost
	'{7ADA0B31-F4C2-43F4-9566-2EBDD3A6B604}' # CentralPublishingTrace
	'{1FD4C5A9-27B7-418B-8DFC-216E7FA7B990}' # TSCPubStubTrace
	'{81B84BCE-06B4-40AE-9840-8F04DD7A8DF7}' # TSCPubWmiProvider
	'{BF936B9C-DA45-4494-A236-101FE5A2A51D}' # TSPublishingAppFilteringTrace
	'{0CEA2AEE-1A4C-4DE7-B11F-161F3BE94669}' # TSPublishingIconHelperTrace
	'{E43CAB68-0AB4-4F47-BF30-E61CAC7BBD8A}' # TSPublishingWmiProvider
	'{D2B9C1C5-0C37-47EB-AA79-CD0CF0CE2FA6}' # TSFairShare
	'{4199EE71-D55D-47D7-9F57-34A1D5B2C904}' # TerminalServer-MediaFoundationPlugin
	'{0ED38D2B-4ACC-4E23-A8EC-D0DACBC34637}' # tsprint
	'{FAC7FCCE-62FC-4BE0-BD67-311750B5BCFF}' # XPSClientPlgin
	'{5A966D1C-6B48-11DA-8BDE-F66BAD1E3F3A}' # RDPENDPTrace
	'{C127C1A8-6CEB-11DA-8BDE-F66BAD1E3F3A}' # RDPINITTrace
	'{BFA655DC-6C51-11DA-8BDE-F66BAD1E3F3A}' # RDPSHELLTrace
	'{A1F3B16A-C510-41C1-8B58-E695880F3A80}' # tsscan
	'{ECA5427C-F28F-4942-A54B-7E86DA46BDBE}' # TSUrbUtils
	'{7211AE02-1EB0-454A-88FA-EA16632DCB45}' # TSUsbBusFilter
	'{39A585FF-6C36-492B-93C0-35B71E65A345}' # TSUsbGenericDriver
	'{A0674FB6-BA0D-456F-B079-A2B029D8342C}' # TSUsbHubTrace
	'{48738267-0545-431D-8087-7349127811D0}' # TSUsbRedirectionServiceTrace
	'{600BE610-F0E8-4912-B397-D2CC76060114}' # USBDRTrace
	'{6E530C0D-677F-488B-B163-0415CB65883D}' # VMMWSFilterPluginTrace
	'{70A43AE8-E131-42BD-89E0-23704FB27C6A}' # TSWebProxyTrace
	'{070F54B9-7EB0-4C99-8DFA-2AA8D8AB0D89}' # WorkspaceTrace
	'{3C3E7039-99CF-4446-8D81-4AC5A8560E7B}' # WorkspaceRuntimeTrace(wksprt.exe)
	'{3E3E7039-99DF-4446-8C81-4AD5A8560E7B}' # WorkspaceBrokerAxTrace(wkspbrokerAx.dll)
	'{449E4E69-329E-4EB1-9DDF-809D17A2E0C1}' # sdclient(WS2016 or earlier)
	'{ae8ab061-654e-4d72-9f4b-c799ba919ec8}' # sessionmsg
	'{73BFB78F-12B5-4738-A66C-A77BCD55FA12}' # rdpdr
	'{C14F3000-0B2D-4464-99AC-FA764AF708CF}' # rdpbus
	'{4BDD50B0-BF12-4991-8B11-C455F14289DB}' # rdpvideominiport
	'{73C5EC49-C807-489D-9E45-D36D72235F84}' # UMRDPTrace
	'{2A0A7EC8-5E2B-47AB-B553-32E1C7AEF0EF}' # VmHostAgentTrace
	'{C10870A3-617D-42E9-80C7-1C4BE2709E06}' # VmPluginTrace
	'{0046A6B4-A24C-40D5-B0E6-C8EC031BD82A}' # tsrpc (WS2016 or earlier)
	'{9ED727C4-4AB6-4B66-92D7-2072E87C9124}' # tssrvlic (WS2016 or earlier)
	'{508371B1-7651-4B33-4B33-5884F824BD1B}' # TSVIPCli (WS2016 or earlier)
	'{AE4C5843-A9A3-4EB9-81F3-65D57D250180}' # TSVIPPool(WS2016 or earlier)
	'{432EEF91-C605-482B-83BE-0963604F1397}' # RDVGSMSTrace (WS2012R2 or earlier)
	'{0C38D54D-EF5F-4179-95FA-6D4EDA073000}' # RDVVGHelperSerivce (WS2012R2 or earlier)
	'{3C3E7089-99CF-4446-8D81-4AC5A8560E6A}' # SessionBrokerTrace
	'{59DE359D-EC83-445C-9323-B75E2056D5A5}' # SessionEnv
	'{986CC918-7434-4FAB-B37F-C4BA7AD1E293}' # TSSdJetTrace
	'{70DB53D8-B6F3-428D-AA33-5B2CE56718C5}' # Gateway Client Trace
	'{6F539394-F34F-45FD-B4CA-BD5C547B0BCB}' # Gateway Edge Trace
	'{909ED641-D5EF-4299-B898-F13451A59F50}' # AaTsPPTrace
	'{588F5E4C-6853-4FCB-BD7D-75F926276C20}' # TSAllowTrace
	'{28711274-D721-465E-9C7E-D359422E96CD}' # lsclientservice
	'{9EA2030F-DB66-47EF-BF2C-619CC76F3E1B}' # LSCSHostPolicy
	'{26C7EAC9-9675-43CB-9EF1-B9CD4564595F}' # lscspolicyloader
	'{97166ECD-4F97-442F-A909-9EB9AE6D2458}' # lscsvmbuspipechannel
	'{A489F3D1-F149-4968-BDCE-4F7D93516DA8}' # lserver
	'{F8FCF9E0-535A-4BA6-975F-7AC82FBDC631}' # TLSBrandTrace
	'{5F328364-2E3D-4F73-B099-0D5C839E32A0}' # CredentialsPlugin
	'{DAA6CAF5-6678-43F8-A6FE-B40EE096E00E}' # mstscax.dll
	'{DAA6CAF5-6678-43F8-A6FE-B40EE096E06E}' # mstscax.dll
	'{0C51B20C-F755-48A8-8123-BF6DA2ADC727}' # mstsc.exe
	'{62F277AE-2CCF-4AA9-A8AA-32752200BC18}' # CtDwm
	'{97E97A1E-C0A9-4B8D-87C4-42105A957D7B}' # RdpDwmDirect
	'{6165F3E2-AE38-45D4-9B23-6B4818758BD9}' # TSPkg
	'{37D2C3CD-C5D4-4587-8531-4696C44244C8}' # schannel(schannel.dll)
	'{DC1A94A6-0A1A-433E-B470-3C72353B7309}' # Microsoft.Windows.RemoteDesktop.RAIL.Server.Diagnostics(From RS5)
	'{3ec987dd-90e6-5877-ccb7-f27cdf6a976b}' # Microsoft.Windows.LogonUI.WinlogonRPC
	'{c0ac3923-5cb1-5e37-ef8f-ce84d60f1c74}' # Microsoft.Windows.TSSessionUX
	'{302383D5-5DC2-4BEA-AC7E-4154A1272583}' # Microsoft.Windows.RemoteDesktop.MultiPoint
	'{26771A7F-04D4-4597-BBF6-3AF9F7818B25}' # Microsoft.Windows.RemoteDesktop.Virtualization
	'{F115DDAF-E07E-4B15-9721-427134B41EBA}' # RDP(RDPEncryption)
	'{a8f457b8-a2b8-56cc-f3f5-3c00430937bb}' # RDP(RDPEmulation)
	'{C6FDD8E3-770B-4964-9F0C-227457146B49}' # RDP(SessEnvRpcTelemetry)
	'{89d48904-939f-4177-aad4-2fdb26b8329f}' # Microsoft.Windows.RemoteDesktop.RDSHFarm.UVhd
	'{D9F94C5A-94F8-4CD0-A054-A1EE67A2DA6B}' # Microsoft.Windows.RemoteDesktop.SessionHost
	'{da539211-d525-422a-8a92-bcbe4367159c}' # Microsoft.Windows.RemoteDesktop.RDSLSTelemetry
	'{76de1e7b-74d9-585f-1f85-affa9242808c}' # RDWin32ClientAxTelemetryProvider
	'{61dd194a-b8cb-4de5-a018-4c7f6f9e9988}' # RDP.MSTSCTelemetry
	'{76de1e7b-74d5-575e-1f81-4ffe6a42777b}' # RDWin32ClientAxTelemetryProvider
	'{7756e5a6-21b2-4c40-855e-88cf2b13c7cb}' # RDP.MSTSCAXTelemetry
	'{204AE8F0-42F7-4A13-97CD-B490927CB725}' # Microsoft.Windows.VGPU.RDVGM
	'{EB4AC9D0-AE00-4963-8435-5163ABD35572}' # Microsoft.Windows.RemoteDesktop.Gateway
	'{660cfa71-2a70-4e80-bdf3-f1424919d01c}' # Microsoft.RDS.RdClient.Client.FeedSubscription
	'{55184039-1cbe-4d35-9f9e-85d0075943df}' # Microsoft.RDS.RADC.FeedSubscription
	'{00508371-7651-4b33-4b33-5884f824bd1b}' # TSVIPCli
	'{32817e55-7bfe-45e0-af68-a413fa6e0083}' # TSMSISrv
	'{AE4C5843-A9A3-4EB9-81F3-65D57D250180}' # TSVIPPool
	'{0ba29edf-a2f4-4212-b06b-6d5712210652}' # TSVIPSrv
	'{c0c89c53-dd3f-4782-a78f-5378111a8305}' # RDSNetFairshare
	'{D2E990DA-8504-4702-A5E5-367FC2F823BF}' # AUInstallAgent(From WS2019)
	'{FB1A70CC-BE28-40C1-BD6A-47671538383A}' # Microsoft.Windows.RemoteDesktop.CertManager(From WS2019)
	'{997FB36F-0208-4ED7-865B-E19816C3782D}' # Microsoft.Windows.RemoteDesktop.SessionConfig(From WS2019)
	'{E80ADCF1-C790-4108-8BB9-8A5CA3466C04}' # Microsoft-Windows-TerminalServices-RDP-AvcSoftwareDecoder(From WS2019)
	'{D953B8D8-7EA7-44B1-9EF5-C34AF653329D}' # RDP.Graphics(From WS2019)
	'{78be48bd-5d52-4e39-823d-226cd5551f37}' # RDP.ServerStack(From WS2019)
	'{9512fdbc-24e6-44fa-a8a3-af44d3447216}' # RDP.Graphics(From WS2019)
	'{CA341B3C-B9D2-4D0F-9BD3-D88183596DB9}' # RDP.ServerStack.Diagnostics(From WS2019)
	'{8A633D91-8B07-4AAE-9A00-D07E2AFD29D6}' # RDP.Transport
	'{fdff33ec-70aa-46d3-ba65-7210009fa2a7}' # Microsoft-Windows-Hyper-V-Integration-RDV(vmicrdv.dll)
	'{77B0D57B-97B8-4f42-83B0-4FDA12D3D79A}' # Microsoft-Windows-RemoteApp and Desktop Connection Management
	'{1B8B402D-78DC-46fb-BF71-46E64AEDF165}' # Microsoft-Windows-RemoteApp and Desktop Connections(TSWorkspace.dll)
	'{1139C61B-B549-4251-8ED3-27250A1EDEC8}' # Microsoft-Windows-RemoteDesktopServices-RdpCoreTS(RdpCoreTS.dll)
	'{10d520e2-205c-4c22-b25c-ac7a779c55b2}' # Microsoft-Windows-RemoteDesktopServices-RemoteFX-Manager(rdvgm.exe)
	'{10AB3154-C36A-4F24-9D91-FFB5BCD331EF}' # Microsoft-Windows-RemoteDesktopServices-RemoteFX-SessionLicensing(LSClientService.dll)
	'{1B4F0E96-6876-49c8-BFBA-072DAE6543B3}' # Microsoft-Windows-RemoteDesktopServices-vGPU-KModeDriver(rdvgkmd.sys)
	'{5AE63087-6A35-40b0-AE15-CEA95A71A8C0}' # Microsoft-Windows-RemoteDesktopServices-vGPU-UModeDriver(rdvgumd32.dll)
	'{1deb930f-e136-4b08-9761-d7e3a5d14faa}' # Microsoft-Windows-RemoteDesktopServices-vGPU-UModeDriver64(rdvgumd64.dll)
	'{6e400999-5b82-475f-b800-cef6fe361539}' # Microsoft-Windows-TerminalServices-ClientUSBDevices(tsusbflt.sys)
	'{3f7b2f99-b863-4045-ad05-f6afb62e7af1}' # Microsoft-Windows-TerminalServices-MediaRedirection(tsmf.dll)
	'{27a8c1e2-eb19-463e-8424-b399df27a216}' # Microsoft-Windows-TerminalServices-PnPDevices(umrdp.dll)
	'{952773BF-C2B7-49BC-88F4-920744B82C43}' # Microsoft-Windows-TerminalServices-Printers(umrdp.dll)
	'{C76BAA63-AE81-421C-B425-340B4B24157F}' # Microsoft-Windows-TerminalServices-RemoteConnectionManager(termsrv.dll)
	'{dcbe5aaa-16e2-457c-9337-366950045f0a}' # Microsoft-Windows-TerminalServices-ServerUSBDevices(tsusbhub.sys)
	'{4d5ae6a1-c7c8-4e6d-b840-4d8080b42e1b}' # Microsoft-Windows-TerminalServices-Gateway(aaedge.dll)
	'{4D99F017-0EB1-4B52-8419-14AEBD13D770}' # Microsoft-Windows-TerminalServices-Licensing(lserver.dll)
	'{5d896912-022d-40aa-a3a8-4fa5515c76d7}' # Microsoft-Windows-TerminalServices-LocalSessionManager(lsm.dll)
	'{D1737620-6A25-4BEF-B07B-AAC3DF44EFC9}' # Microsoft-Windows-TerminalServices-SessionBroker(tssdis.exe)
	'{2184B5C9-1C83-4304-9C58-A9E76F718993}' # Microsoft-Windows-TerminalServices-SessionBroker-Client(tssdjet.dll)
	'{32817e55-7bfe-45e0-af68-a413fa6e0083}' # Microsoft-Windows-TerminalServices-TSAppSrv-TSMSI(TSMSISrv.dll)
	'{6ba29edf-a2f4-4212-b06b-6d5712210652}' # Microsoft-Windows-TerminalServices-TSAppSrv-TSVIP(TSVIPSrv.dll)
	'{8d83aec0-01de-4772-a317-2093b6dc3bab}' # Microsoft-Windows-TerminalServices-TSFairShare-Events(TSFairShare.sys)
	'{92618A87-2F6A-4B75-9AE2-E77BE7EAF43C}' # Microsoft-Windows-TerminalServices-TSV-VmHostAgent(tsvmhasvc.dll)
	'{28aa95bb-d444-4719-a36f-40462168127e}' # Microsoft-Windows-TerminalServices-ClientActiveXCore(mstscax.dll)
	'{8bddcf41-9630-47e8-914a-d4952112ea19}' # Microsoft-Windows-RemoteDesktopServices-RemoteFX-SessionManager(rdvgsm.dll)(WS2012R2 or earlier)
	'{7bfcf102-7378-431c-9284-0b968258991a}' # Microsoft-Windows-RemoteDesktopServices-RemoteDesktopSessionManager(RDPWD.sys)(WS2012 or ealier)
	'{b1c94ed9-ac9b-410e-aa48-4ffc5e45f4e3}' # Microsoft-Windows-TerminalServices-MediaRedirection-DShow(DShowRdpFilter.dll) (WS2008R2)
	'{D2E990DA-8504-4702-A5E5-367FC2F823BF}' # Microsoft-Windows-All-User-Install-Agent(RDSAppXHelper.dll)
	#'{127e0dc5-e13b-4935-985e-78fd508b1d80}' # Microsoft-Windows-TerminalServices-RdpSoundDriver(rdpendp.dll) => Too many logs will be recorded.
	'{1B9B72FC-678A-41C1-9365-824658F887E9}' # RDMSTrace
	'{9F58B00C-09C7-4CBC-8D19-969DCD5D5A6D}' # TSMMCTrace
	'{FB750AD9-8544-427F-B284-8ED9C6C221AE}' # Microsoft-Windows-Rdms-UI(Manifest)
	'{05da6b40-219e-4f17-92e6-d663fd87cba8}' # Microsoft-Windows-Remote-Desktop-Management-Service(rdms.dll)
	'{43471865-f3ee-5dcf-bf8b-193fcbbe0f37}' # Microsoft.Windows.RemoteDesktopServices.RailPlugin
	'{48EF6C18-022B-4394-BEE5-7B822B42AE4C}' # Microsoft.RDS.Windows.Client.MSRDC
	'{335934AA-6DD9-486C-88A5-F8D6A7D2BAEF}' # Microsoft.RDS.Windows.Client.AX
	'{4A49AFE3-776E-467A-ACA0-71F9C6C8499F}' # Microsoft.Windows.RemoteDesktop.RAIL.RdpInit
	'{39825FFA-F1B4-41B7-8221-20D4B8DBE57E}' # Microsoft.Windows.RemoteDesktop.RAIL.RdpShell
	'{48DAB7B6-34F4-44C8-8355-35124FE39BFF}' # RdpXTraceProvider
	'{CC3716F0-0336-44FB-A442-86276F4B712C}' # RdpWinTraceProvider
	'{59906E55-0817-4CDA-BA3B-D34E33ED4EE7}' # TokenValTrace
	'{5795AAB9-B0E3-419E-B0EF-7AEF943CFFA8}' # Microsoft.Windows.RemoteDesktop.Base
	'{8375996D-5801-4FE9-B0AE-F5C428758960}' # Microsoft.Windows.RemoteDesktop.ServerBase
	'{c8e6dc53-660c-44ee-8d00-e47f189db87f}' # Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV
	'{E7C53BC0-EFF4-4DEE-993B-D48CB69766BD}' # Microsoft-Windows-DesktopSharing-Sharer
	'{642DF441-8193-4514-869F-7815DCA48372}' # Microsoft-Windows-DesktopSharing-Viewer
	'{080656C2-C24F-4660-8F5A-CE83656B0E7C}' # Microsoft.Windows.RemoteDesktop.ClientCore
	'{3EF15ADF-1300-44A1-B85C-2A83549F5B9E}' # Microsoft.Windows.RemoteDesktop.Legacy
)

$UEX_AppVProviders = @(
	'{E4F68870-5AE8-4E5B-9CE7-CA9ED75B0245}' # Microsoft-AppV-Client
	'{0D21725F-A0BD-4D1D-AE8E-6910F1093419}' # Microsoft-AppV-Sequencer
	'{7561449A-FC50-469B-B76E-88F43CF79ECF}' # Microsoft-AppV-Sequencer-Debug
	'{9CC69D1C-7917-4ACD-8066-6BF8B63E551B}' # Microsoft-AppV-ServiceLog
	'{FB4A19EE-EB5A-47A4-BC52-E71AAC6D0859}' # Microsoft-AppV-SharedPerformance
	'{C901E37D-B5F4-4582-AE6E-C1459F358B30}' # Microsoft-AppV-Sequencer-PRS
	'{271aebf7-e83b-580f-7525-5e9563fe161a}' # Microsoft.Windows.AppMan.AppV
	'{582C6A21-F5B4-4E52-B592-0E8229BF1737}' # Microsoft.Windows.AppMan.Shared.Logging
	'{df9b8c8f-ed83-5cd0-acec-4790d087c32b}' # Microsoft.Windows.AppMan.AppV.Sequencer
	'{28CB46C7-4003-4E50-8BD9-442086762D12}' # Microsoft-AppV-Client-StreamingUX
	'{34BEC984-F11F-4F1F-BB9B-3BA33C8D0132}' # this is ADS Bio provider, just for testing guid conflicts
	'{86f50c0c-6a4c-4b9c-a370-62b45ebe6e85}' # Microsoft-AppV-Server-Management
	'{84D85C22-6552-4A3F-BC85-C525B952861B}' # Microsoft-AppV-Server-Management-Private
	'{825C7963-9E32-4E3B-B74A-DF2CC3B6822B}' # Microsoft-AppV-Server-Publishing
	'{213B8D98-9A5E-4453-A2AB-A9B68A3C3EEA}' # Microsoft-AppV-Server-Publishing-Private
	'{1BEAA11B-B9C8-4D95-B567-D12C799C7D6E}' # Microsoft-AppV-Server-Reporting
	'{ECE17739-6097-4CC6-9B1C-FE40258A442B}' # Microsoft-AppV-Server-Reporting-Private
)

#---  LOGON PROVIDERS ---#
$UEX_LogonProviders = @(
	'{D451642C-63A6-11D7-9720-00B0D03E0347}' # WinLogon
	'{a789efeb-fc8a-4c55-8301-c2d443b933c0}' # UmsHlpr
	'{301779e2-227d-4faf-ad44-664501302d03}' # WlClNtfy
	'{5B4F9E61-4334-409F-B8F8-73C94A2DBA41}' # Userinit
	'{c2ba06e2-f7ce-44aa-9e7e-62652cdefe97}' # WinInit
	'{855ed56a-6120-4564-b083-34cb9d598a22}' # SetupLib
	'{d138f9a7-0013-46a6-adcc-a3ce6c46525f}' # WMsgSrv
	'{19d78d7d-476c-47b6-a484-285d1290a1f3}' # SysNtfy
	'{557D257B-180E-4AAE-8F06-86C4E46E9D00}' # LSM
	'{EB7428F5-AB1F-4322-A4CC-1F1A9B2C5E98}' # UserProfileService
	'{9891e0a7-f966-547f-eb21-d98616bf72ee}' # Microsoft.Windows.Shell.UserProfiles
	'{9959adbd-b5ac-5758-3ffa-ee0da5b8fe4b}' # Microsoft.Windows.ProfileService
	'{40654520-7460-5c90-3c10-e8b6c8b430c1}' # Microsoft.Windows.ProfExt
	'{D33E545F-59C3-423F-9051-6DC4983393A8}' # winsta
	'{b39b8cea-eaaa-5a74-5794-4948e222c663}' # Microsoft.Windows.Security.Winlogon
	'{8db3086d-116f-5bed-cfd5-9afda80d28ea}' # Microsoft-OSG-OSS-CredProvFramework
	'{5AA2DC10-E0E7-4BB2-A186-D230D79442D7}' # Microsoft.CAndE.ADFabric.CDJ.Recovery
	'{7ae961f7-1262-48e2-b237-acba331cc970}' # Microsoft.CAndE.ADFabric.CDJ.AzureSecureVMJoin
	'{fb3cd94d-95ef-5a73-b35c-6c78451095ef}' # Microsoft.Windows.CredProvDataModel
	'{a6c5c84d-c025-5997-0d82-e608d1abbbee}' # Microsoft.Windows.CredentialProvider.PicturePassword
	'{41ad72c3-469e-5fcf-cacf-e3d278856c08}' # Microsoft.Windows.BlockedShutdown
	'{df350158-0f8f-555d-7e4f-f1151ed14299}' # Microsoft.Windows.BioFeedback
	'{D33E545F-59C3-423F-9051-6DC4983393A8}' # winsta
	'{557D257B-180E-4AAE-8F06-86C4E46E9D00}' # LSM(From WS2019)
	'{4f7c073a-65bf-5045-7651-cc53bb272db5}' # Microsoft.Windows.LogonController
	'{3ec987dd-90e6-5877-ccb7-f27cdf6a976b}' # Microsoft.Windows.LogonUI.WinlogonRPC
	'{c0ac3923-5cb1-5e37-ef8f-ce84d60f1c74}' # Microsoft.Windows.TSSessionUX
	'{DBE9B383-7CF3-4331-91CC-A3CB16A3B538}' # Microsoft-Windows-Winlogon(Manifest)
	'{63D2BB1D-E39A-41b8-9A3D-52DD06677588}' # Microsoft-Windows-Shell-AuthUI(credprovhost.dll)
	'{DB00DFB6-29F9-4A9C-9B3B-1F4F9E7D9770}' # Microsoft-Windows-User Profiles General
	'{89B1E9F0-5AFF-44A6-9B44-0A07A7CE5845}' # Microsoft-Windows-User Profiles Service
	'{B059B83F-D946-4B13-87CA-4292839DC2F2}' # Microsoft-Windows-User-Loader
	'{EEA178E3-E9D4-41CA-BB56-CEDE1A476629}' # Microsoft-Windows-User-PnP
	'{1941DE80-2226-413B-AFA4-164FD76914C1}' # Microsoft.Windows.Desktop.Shell.WindowsUIImmersive.LockScreen
	'{176cd9c5-c90c-5471-38ba-0eeb4f7e0bd0}' # Microsoft.Windows.UI.Logon
	'{74cc4a0b-f577-5929-abcb-aa4bea374cb3}' # Microsoft.Windows.Shell.LockAppHost
	'{f8e28969-b1df-57fa-23f6-42260c77135c}' # Microsoft.Windows.ImageSanitization
	'{1915117c-a61c-54d4-6548-56cac6dbfede}' # Microsoft.Windows.Shell.AboveLockActivationManager
	'{e58f5f9c-3abb-5fc1-5ae5-dbe956bdbd33}' # Microsoft.Windows.Shell.AboveLockShellComponent
	'{b2149bc3-9dfd-5866-92a7-b556b3a6aed0}' # Microsoft.Windows.Shell.DefaultLockApp
	'{9ca921e3-25a4-5d34-39da-a59bd8bdf7a2}' # Microsoft.Windows.Shell.LockAppBroker
	'{b93d4107-dc22-5d11-c2e1-afba7a88d694}' # Microsoft.Windows.Shell.Tracing.LockAppBroker
	'{96319132-2f52-5969-f14c-0d0a171b357a}' # Microsoft.Windows.Shell.LockFrameworkUAP
	'{4191edaf-80c5-5ae3-49aa-325bd25cab2e}' # Microsoft.Windows.ComposableShell.Components.LockScreenHost.LockScreenShow
	'{355d4f62-3d5b-5372-213f-6d9d804c75df}' # Microsoft.Windows.AssignedAccess.MdmAlert
	'{94097d3d-2a5a-5b8a-cdbd-194dd2e51a00}' # Microsoft.Windows.AssignedAccess
	'{8530DB6E-51C0-43D6-9D02-A8C2088526CD}' # Microsoft-Windows-AssignedAccess
	'{F2311B48-32BE-4902-A22A-7240371DBB2C}' # Microsoft-Windows-AssignedAccessBroker
	'{5e85651d-3ff2-4733-b0a2-e83dfa96d757}' # UserMgrSvcTraceLoggingProvider
	'{077b8c4a-e425-578d-f1ac-6fdf1220ff68}' # Microsoft.Windows.Security.TokenBroker
	'{7acf487e-104b-533e-f68a-a7e9b0431edb}' # Microsoft.Windows.Security.TokenBroker.BrowserSSO
	'{BB86E31D-F955-40F3-9E68-AD0B49E73C27}' # Microsoft-Windows-User-UserManager-Events
	'{076a2c5c-40e9-5a75-73b0-8d7697c282b2}' # Microsoft.Windows.Security.Vault.RoamingSecurity
	'{a15c1ac4-a508-59ae-3158-275f96f30cb8}' # Microsoft.Windows.Security.Vault.Roaming
	'{98177d7f-7d3a-51ef-2d41-2414bb2c0bdb}' # Microsoft.Windows.Security.Wininit
	'{1ef1b3bd-ba20-5fd6-68c1-beb652b5d0c2}' # Microsoft.Windows.Shell.LockScreenContent
	'{b45275fa-3b9c-40f2-aaad-10060f77f0c0}' # Microsoft.Windows.Shell.CloudExperienceHost.DatVPrep
	'{F1C13488-91AC-4350-94DE-5F060589C584}' # Microsoft.Windows.Shell.LockScreenBoost
	'{3D14CA27-6EB2-4789-9B52-33EC88ECF5B0}' # Microsoft.Windows.Shell.LockScreenData
	'{1f44367c-cd89-5c01-ad03-bf60b9588564}' # Microsoft.Windows.LockAppBroker
	'{be69781c-b63b-41a1-8e24-a4fc7b3fc498}' # Microsoft-Windows-Sens
	'{A0CA1D82-539D-4FB0-944B-1620C6E86231}' # Microsoft-Windows-Sens/Debug
	'{2D710779-B24B-4ADB-81EF-CD6DED5A9B2A}' # Microsoft.Windows.Shell.LockScreenController
	'{75816B5C-ECD1-4DBC-B38A-47A9646E60BE}' # Microsoft.Windows.Shell.LockScreenExperienceManager
	'{68767976-7ddc-57d7-4318-9a6db4625165}' # Microsoft.Windows.Shell.WelcomeScreen
)

$UEX_KerberosProviders = @(
	'{6B510852-3583-4E2D-AFFE-A67F9F223438}' # Kerberos
	)


$UEX_AuthProviders = @(
	'{6165F3E2-AE38-45D4-9B23-6B4818758BD9}' # TSPkg
	'{37D2C3CD-C5D4-4587-8531-4696C44244C8}' # schannel(schannel.dll)
	'{5BBB6C18-AA45-49B1-A15F-085F7ED0AA90}' # NTLM
	'{6B510852-3583-4E2D-AFFE-A67F9F223438}' # Kerberos
	'{BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4}' # Kerberos Client
	'{CC85922F-DB41-11D2-9244-006008269001}' # LSA
	'{F33959B4-DBEC-11D2-895B-00C04F79AB69}' # NetLogon
	'{C5D1EB66-79E9-47C3-A578-A6F25DA14D49}' # SpapiWBLog
	'{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}' # Microsoft-Windows-CAPI2(crypt32.dll)
	'{1f678132-5938-4686-9fdc-c8ff68f15c85}' # Schannel(lsasrv.dll)
	'{91CC1150-71AA-47E2-AE18-C96E61736B6F}' # Microsoft-Windows-Schannel-Events(Manifest)
	'{4C88AF3D-5D47-458A-8624-515C122B7188}' # Microsoft.Windows.OneCoreUap.Shell.Auth.CredUX
	'{4b8b1947-ae4d-54e2-826a-1aee78ef05b2}' # Microsoft.Windows.WinBioDataModel
	'{a55d5a23-1a5b-580a-2be5-d7188f43fae1}' # Microsoft.Windows.Shell.BioEnrollment
	'{DC3B5BCF-BF7B-42CE-803C-71AF48F0F546}' # Microsoft.Windows.CredProviders.PasswordProvider
	'{fb3cd94d-95ef-5a73-b35c-6c78451095ef}' # Microsoft.Windows.CredProvDataModel
	'{5a4dad98-5dce-5efb-a9b2-54e8de8af594}' # Microsoft.Windows.Shell.Auth.LocalServiceCredUIBroker
	'{3bb1472f-46dc-5a12-4916-25706f703352}' # Microsoft.Windows.CredDialogBroker
	'{f2018623-63ac-5837-7cfb-f67ec5c39961}' # Microsoft.Windows.Shell.CredDialogHost
	'{d30325be-5b5e-508c-d76a-2d5e5fe60a5c}' # Microsoft.Windows.CredentialEnrollmentManager
	'{f245121c-b6d1-5f8a-ea55-498504b7379e}' # Microsoft.Windows.DeviceLockSettings
	'{350b80a3-32c3-47b3-9e58-32e5a48ce66f}' # Microsoft.Windows.SuggestedUsersDataModel
	'{c11d96bf-1615-4d64-ada3-5803cdbac698}' # Microsoft.Windows.Shell.Auth.CredUI
	'{1D86A602-D4EE-48FA-94B1-59EE686D07D0}' # MicrosoftWindowsShellAuthCredUI
	'{04063501-1c04-5e01-5e72-4e2400121550}' # Microsoft-Windows-UserTrustedSignals-CredProv
	'{5512152d-88f8-5f1e-ed9f-6412175a39dc}' # Microsoft.Windows.UI.PicturePassword
	'{462a094c-fc89-4378-b250-de552c6872fd}' # Microsoft.Windows.Shell.Auth.CredUIBroker
	'{24532ca4-409f-5d6c-3ded-e11946573f56}' # Microsoft.Windows.CredUXController
	'{4f7c073a-65bf-5045-7651-cc53bb272db5}' # Microsoft.Windows.LogonController
	'{9a7b2945-e29a-5477-e857-794ae72a85d9}' # Microsoft.Windows.AuthExt
	'{f0c781fb-3451-566e-121c-9020159a5306}' # Microsoft.Windows.SharedPC.AccountManager
	'{80B3FF7A-BAB0-4ED1-958C-E89A6D5557B3}' # Microsoft.Windows.Shell.SystemSettings.WorkAccessHandlers
	'{7fdd167c-79e5-4403-8c84-b7c0bb9923a1}' # VaultGlobalDebugTraceControlGuid
)

#---  LSA PROVIDERS ---#
$UEX_LSAProviders = @(
	'{D0B639E0-E650-4D1D-8F39-1580ADE72784}' # LsaTraceControlGuid
	'{DAA76F6A-2D11-4399-A646-1D62B7380F15}' # LsaAuditTraceControlGuid
	'{169EC169-5B77-4A3E-9DB6-441799D5CACB}' # LsaDsTraceControlGuid
	'{0D4FDC09-8C27-494A-BDA0-505E4FD8ADAE}' # Microsoft-Windows-Directory-Services-SAM
	'{BD8FEA17-5549-4B49-AA03-1981D16396A9}' # Microsoft-Windows-Directory-Services-SAM-Utility
	'{9A7D7195-B713-4092-BDC5-58F4352E9563}' # SamLib
	'{44415D2B-56DC-437D-AEB2-482A480183A5}' # OFFLINESAM
	'{F2969C49-B484-4485-B3B0-B908DA73CEBB}' # SamSrv
	'{548854b9-da55-403e-b2c7-c3fe8ea02c3c}' # SamSrv2
	'{8e598056-8993-11d2-819e-0000f875a064}' # SampControlGuid
)

#---  CRYPT PROVIDERS ---#
$UEX_CRYPTProviders = @(
	'{5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB}' # Microsoft-Windows-CAPI2
	'{80DF111F-178D-44FB-AFB4-5D179DE9D4EC}' # WPP_CRYPT32_CONTROL_GUID
	'{EAC19293-76ED-48C3-97D3-70D75DA61438}' # WPP_CRYPTTPMEKSVC_CONTROL_GUID
	'{9B52E09F-0C58-4eaf-877F-70F9B54A7946}' # WPP_CHAT_CONTROL_GUID
	'{A74EFE00-14BE-4ef9-9DA9-1484D5473301}' # CNGTraceControlGuid
	'{A74EFE00-14BE-4ef9-9DA9-1484D5473302}' # CNGTraceControlGuid
	'{A74EFE00-14BE-4ef9-9DA9-1484D5473303}' # CNGTraceControlGuid
	'{A74EFE00-14BE-4ef9-9DA9-1484D5473304}' # CNGTraceControlGuid
	'{EA3F84FC-03BB-540e-B6AA-9664F81A31FB}' # DPAPIGlobalDebugTraceControlGuid
	'{9D2A53B2-1411-5C1C-D88C-F2BF057645BB}' # Microsoft.Windows.Security.Dpapi
	'{89FE8F40-CDCE-464E-8217-15EF97D4C7C3}' # Microsoft-Windows-Crypto-DPAPI
)

#---  WMI PROVIDERS ---#
$UEX_WMIProviders = @(
	'{1FF6B227-2CA7-40F9-9A66-980EADAA602E}' # WMI_Tracing_Guid WBEMCOMM
	'{8E6B6962-AB54-4335-8229-3255B919DD0E}' # WMI_Tracing_Client_Operations_Info_Guid
	'{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}' # Microsoft-Windows-WMI-Activity
	'{2CF953C0-8DF7-48E1-99B9-6816A2FBDC9F}' # Microsoft-Windows-WMIAdapter
	'{1EDEEE53-0AFE-4609-B846-D8C0B2075B1F}' # Microsoft-Windows-WMI
)

#---  UE-V PROVIDERS ---#
$UEX_UEVProviders = @(
	"{1ED6976A-4171-4764-B415-7EA08BC46C51}" # Microsoft-User Experience Virtualization-App Agent
	"{21D79DB0-8E03-41CD-9589-F3EF7001A92A}" # Microsoft-User Experience Virtualization-IPC
	"{57003E21-269B-4BDC-8434-B3BF8D57D2D5}" # Microsoft-User Experience Virtualization-SQM Uploader
	"{61BC445E-7A8D-420E-AB36-9C7143881B98}" # Microsoft-User Experience Virtualization-Admin
	"{e4dda0af-d7b4-5d40-4174-4d0be05ae338}" # Microsoft.Windows.AppMan.UEV
)

#---  COM/DCOM/WinRT/RPC PROVIDERS ---#
$UEX_COMProviders = @(
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

$UEX_WinRMProviders = @(
	'{A7975C8F-AC13-49F1-87DA-5A984A4AB417}' # Microsoft-Windows-WinRM
	'{04C6E16D-B99F-4A3A-9B3E-B8325BBC781E}' # WinRM(WPP)
	'{72B18662-744E-4A68-B816-8D562289A850}' # Windows HTTP Services
	'{7D44233D-3055-4B9C-BA64-0D47CA40A232}' # Microsoft-Windows-WinHttp
	'{B3A7698A-0C45-44DA-B73D-E181C9B5C8E6}' # WinHttp(WPP)
	'{4E749B6A-667D-4C72-80EF-373EE3246B08}' # WinInet(WPP)
	'{DD5EF90A-6398-47A4-AD34-4DCECDEF795F}' # Microsoft-Windows-HttpService
	'{20F61733-57F1-4127-9F48-4AB7A9308AE2}' # UxWppGuid(HTTP.sys - WPP)
	'{C42A2738-2333-40A5-A32F-6ACC36449DCC}' # Microsoft-Windows-HttpLog
	'{DD5EF90A-6398-47A4-AD34-4DCECDEF795F}' # Microsoft-Windows-HttpService
	'{7B6BC78C-898B-4170-BBF8-1A469EA43FC5}' # Microsoft-Windows-HttpEvent
	'{F5344219-87A4-4399-B14A-E59CD118ABB8}' # Microsoft-Windows-Http-SQM-Provider
	'{c0a36be8-a515-4cfa-b2b6-2676366efff7}' # WinRSMgr
	'{f1cab2c0-8beb-4fa2-90e1-8f17e0acdd5d}' # WinRSexe
	'{03992646-3dfe-4477-80e3-85936ace7abb}' # WinRSCmd
	'{651d672b-e11f-41b7-add3-c2f6a4023672}' # IPMIPrv
	'{D5C6A3E9-FA9C-434e-9653-165B4FC869E4}' # IpmiDrv
	'{6e1b64d7-d3be-4651-90fb-3583af89d7f1}' # WSManProvHost
	'{D5C6A3E9-FA9C-434e-9653-165B4FC869E4}' # IpmiDrv
	'{6FCDF39A-EF67-483D-A661-76D715C6B008}' # Event Forwarding
)

$UEX_EventLogProviders = @(
	'{FC65DDD8-D6EF-4962-83D5-6E5CFE9CE148}' # Microsoft-Windows-Eventlog
	'{B0CA1D82-539D-4FB0-944B-1620C6E86231}' # WMI EventLogTrace
	'{565BBECA-5B04-49BB-81C6-3E21527FCC8A}' # Microsoft-Windows-Eventlog-ForwardPlugin
	'{35AC6CE8-6104-411D-976C-877F183D2D32}' # Microsoft-Windows-EventLog-WMIProvider
	'{899DAACE-4868-4295-AFCD-9EB8FB497561}' # Microsoft-Windows-EventSystem
)

$UEX_CldFltProviders = @(
	'{d8de3faf-8a2e-4a80-aedb-c86c7cc02a73}' # CldFltLogGuid
)

$UEX_PrintProviders = @(
	# From NET_PrintSvc
	'{05af8001-5e28-5ebb-0329-a20fab346b76}' # Microsoft.Windows.Print.IppEmulator
	#'{077b8c4a-e425-578d-f1ac-6fdf1220ff68}' # Microsoft.Windows.Security.TokenBroker
	#'{bfed9100-35d7-45d4-bfea-6c1d341d4c6b}' # Microsoft.AAD.TokenBrokerPlugin.Provider
	'{08fad69b-3394-5632-97ef-ff9c5a842b1f}' # Microsoft.Windows.Print.Workflow.PrintSupport
	'{095da8da-2182-5c9a-53cd-07eca93a04ef}' # Microsoft.Windows.Print.XpsDocumentTargetPrint
	'{0aef9116-5ab8-5c05-0eb3-c0721ba93354}' # Microsoft.Windows.Print.PDMUtilities
	'{0E173F13-4266-4EFD-883C-79B24789B1BC}' # Microsoft-Windows-PrintDrivers 
	'{15584c9b-7d86-5fe0-a123-4a0f438a82c0}' # Microsoft.Windows.Shell.ServiceProvider
	'{15fc363b-e2b4-5e55-f1d3-3b0ff726203d}' # Microsoft.Windows.Print.PCLmRenderFilter
	'{19E464A4-7408-49BD-B960-53446AE47820}' # DAS
	'{1bf554be-03c5-4f49-9b57-f3c0cbad589a}' # Microsoft.Windows.Print.Workflow.Broker
	'{201eb0f8-12f0-5b34-c99b-75c1541f3479}' # Microsoft.Windows.Print.UsbPortMig
	'{27a7ea23-db5c-5487-b775-89c06c43039b}' # Microsoft.Windows.Scan.EsclProtocol
	'{2974da9a-e1f3-5c5f-2abe-f7f20f6448bc}' # Microsoft.Windows.Print.JScriptLib
	'{29b47072-00ff-4d9d-852d-0eafc181a9a3}' # Microsoft-Windows-WSD-WSDApi
	'{2e008da9-e1b6-5cb5-0607-82066afcfff4}' # Microsoft.Windows.Scan.EsclScan
	'{38ae712f-fad1-528e-9721-6ebefea1ab2b}' # Microsoft.Windows.Print.Mopria.Service
	'{3d9d790d-fb07-539d-b66e-5a2ffb7899ca}' # Microsoft.Windows.Print.PrintCoreConfig
	'{3e617461-4ad0-5bb1-ce2d-796bf4794fbf}' # Microsoft.Windows.Scan.EsclEmulator
	'{3fc887c9-c23f-59cd-88b5-a6086f4bbc9e}' # Microsoft.Windows.Print.USBMon
	'{402d7aed-ded3-5536-3112-a2ce8baa1fdc}' # Microsoft.Windows.Print.McpManagementUtil
	'{44050ea2-419d-5526-923b-b038e0f1e715}' # Microsoft.Windows.Print.CloudPrintHelper
	'{48111f99-b3d5-5f69-587d-be4ed8e22647}' # Microsoft.Windows.Print.IppAdapterCore
	'{49868e3d-77fb-5083-9e09-61e3f37e0309}' # Microsoft.Windows.Print.HttpRest
	'{4a743cbb-3286-435c-a674-b428328940e4}' # PSMWPP
	'{4a892232-6efc-54c1-1f0a-1b916a719612}' # Microsoft.Windows.Scan.WindowsImageAcquisition
	'{4e880362-c4e8-5c62-7a2e-db0ee6a8f9a8}' # Microsoft.Windows.Scan.Plugins
	'{4ea56ff9-fc2a-4f0c-8d6e-c345bc452c80}' # DAFWSD
	'{556045FD-58C5-4A97-9881-B121F68B79C5}' # AAD Cloud AP
	'{6184BC1F-417E-4443-BCCE-9F65BF844AA7}' # Microsoft.Windows.Print.IppConfigConverter
	'{63a87ca3-6662-4925-a0a8-f7bb94ef104e}' # Microsoft.Windows.Print.PrintToPDF
	'{6d5ca4bb-df8e-41bc-b554-8aeab241f206}' # Microsoft.Windows.Print.DafIpp
	'{6de9ba0e-9e72-53d2-229a-dc09205a27ea}' # Microsoft-Windows-Mobile-Print-Plugins
	'{6fb61ac3-3455-4da4-8313-c1a855ee64c5}' # Microsoft.Windows.Print.IppMon
	'{73cf4d38-21a5-41dc-93d5-c8ec31d84b70}' # Microsoft.Windows.Print.XpsPrint
	'{744372de-ba26-443b-ba10-712c1a041234}' # Microsoft.Windows.Print.Workflow.API
	'{7cdc2341-4d44-54aa-2899-ddb05ecf0adb}' # Microsoft.Windows.Print.McpManagement
	'{7e247d3c-42fa-5e08-6427-f98478081d24}' # Microsoft.Windows.Print.GetPrinterConfig
	'{7e2dbfc7-41e8-4987-bca7-76cadfad765f}' # FDWSD
	'{7faee4d5-95c1-5987-54c6-a7c3dfb6e56e}' # Microsoft.Windows.Print.PrintSupport
	'{81d45b93-a5ff-5459-26ff-c092864200c6}' # Microsoft.Windows.Print.WinspoolCore
	'{8bbe74b4-d9fc-4052-905e-92d01579e3f1}' # DAFBTH
	'{8BFE6B98-510E-478D-B868-142CD4DEDC1A}' # indows.Internal.Shell.ModalExperience
	'{93603fbe-a752-550d-b87e-f202b0f27f9e}' # Microsoft.Windows.Scan.EsclWiaDriver
	'{9594011E-FE68-4D05-9F06-C68A0EBE4822}' # Microsoft.Windows.Print.GetIppAttributes
	'{97ff6b54-144c-524b-5fec-82b610461390}' # Microsoft.Windows.Mobile.Shell.ServiceProvider
	'{9C6FC32A-E17A-11DF-B1C4-4EBADFD72085}' # PLMWPP
	'{a08e69ca-2172-5c18-fe96-a2ac30857b97}' # Microsoft.Windows.Print.IppOneCore
	'{A1607A05-8D8A-4d74-82C7-460DD790648E}' # FindNetPrinters
	'{a4f32eea-babb-59b2-3828-ce92e4e20765}' # Microsoft.Windows.PrintCore
	'{ab4d9355-341e-435d-b3d2-4b0e46354e2c}' # Microsoft.Windows.Das
	'{ac521649-5ec6-5397-d1c5-749cbf5ea79b}' # Microsoft.Windows.Print.RenderFilterCommon
	'{acf1e4a7-9241-4fbf-9555-c27638434f8d}' # Microsoft.Windows.Print.IppCommon
	'{afa85d6c-0ea6-4c6a-99b7-5be1c9f3c7a1}' # BTHUSER
	'{b0f40491-9ea6-5fd5-ccb1-0ec63be8b674}' # Microsoft.Windows.Shell.PrintDialog
	'{b145b5c6-1a9d-50c5-7f76-39f208ed09c9}' # Microsoft.Windows.Print.McpEvtSrc
	'{B4D2914C-FF23-403B-BABF-F0755FB060FE}' # Microsoft.Windows.Print.SpoolerService
	'{B6BFCC79-A3AF-4089-8D4D-0EECB1B80779}' # Microsoft-Windows-SystemEventsBroker
	'{BA4936A1-31DB-4EDC-89CE-9190E3C0653B}' # Microsoft.Windows.Print.LocalSpooler
	'{bad46242-e75f-541f-c2d2-ab35489f27e4}' # Microsoft.Windows.Print.GDI
	'{BC2DAB59-AC78-487A-903E-DB3C343C0BE3}' # Microsoft.Windows.Print.WSDMon
	'{be5f8487-3a5d-4477-b0c2-020679b81e56}' # Microsoft.Windows.Print.Workflow.Source
	'{bf3eac2a-65ca-5ecc-2076-e23c6420a687}' # Microsoft.Windows.Print.DAFMCP
	'{C69CB70A-3133-4CCA-AB0E-046848EFFCDA}' # Microsoft.Windows.Print.Winspool
	'{c6dba857-03f1-5c5b-350c-ef08dbd04572}' # Microsoft.Windows.Shell.PrintManager
	'{c7c2a97e-3d49-5f78-bd33-22d8c22a7cf3}' # Microsoft.Windows.Scan.EsclWiaCore
	'{CA478AB1-8B38-451D-90E4-8534EB50B9D3}' # XPSPRINT
	'{cae6f32b-2553-5c24-f999-e63dde138b9f}' # Microsoft.Windows.Print.WorkFlowRT
	'{cb730350-b8b7-56d7-6fa4-90e0ea74a9bb}' # Microsoft.Windows.Print.PrintScanService
	'{D2E1BAB1-EB9B-4BA7-9123-19C01DDC4F78}' # LOCALSPLPLM
	'{D2E1BAB2-EB9B-4BA7-9123-19C01DDC4F78}' # SPOOLERPLM
	'{d49918cf-9489-4bf1-9d7b-014d864cf71f}' # Microsoft-Windows-ProcessStateManager 
	'{d758d01c-7402-5923-6a27-44bdcc59a5c5}' # Microsoft.Windows.Print.ApMonPortMig
	'{dd212385-31e6-541c-5587-3c469bb6470a}' # Microsoft.Windows.Print.DafIppUsb
	'{DDF2CC14-A470-4449-AB03-F8B95FC8294B}' # Microsoft.Windows.Print.XpsPrint
	'{df6dca70-9918-455f-86fe-983adc74fa0d}' # Microsoft.Windows.Scan.Runtime
	'{e0d2f15a-3875-5388-2239-23f2538b7636}' # Microsoft.Windows.Print.PrintScanDiscoveryManagement
	'{e4d412ab-4c22-49ef-83ca-eafb90768512}' # Microsoft-Windows-WSD-DafProvider
	'{e604ec58-ad08-5a2c-3ecb-704c8c024881}' # Microsoft.Windows.Print.ProxyApp
	'{E6F8A5FC-7FCE-4095-8661-B8E0CB7D9410}' # ScanRT/DeviceEnumeration WPP
	'{e73d49d6-9eda-5059-74d1-b879b18cf9ae}' # Microsoft.Windows.Print.APMon
	'{e8109b99-3a2c-4961-aa83-d1a7a148ada8}' # SEBWPP
	'{e98cb748-3d93-4719-8209-95e0bc46eec7}' # Microsoft.Windows.Print.PwgRenderFilter
	'{eb3b6950-120c-4575-af39-2f713248e8a3}' # BTHPRINT
	'{EC08D605-5A20-4ED0-AE54-E8C4BFFF2EEB}' # PrinterExtensions
	'{ec5b420f-d2ec-50b4-5119-083a4da63982}' # Microsoft.Windows.Print.Ecp.Service
	'{ee8c758e-2e70-574f-8149-266b77c8d56a}' # Microsoft.Windows.Print.McpIppChannel
	'{f25e0650-deff-5306-ca0d-40abb8b107dd}' # Microsoft.Windows.Scan.DafEscl
	'{F69D3E6C-298B-466C-B84F-486E1F21E347}' # Microsoft.Windows.Print.WorkFlowBroker
	'{fbfbd628-251d-551d-c4dd-c7820af723e4}' # Microsoft.Windows.Print.IppAdapterCommon
	'{FCA72EBA-CBB3-467c-93BC-1DB4978C398D}' # MXDC
	'{fd6b6ae4-7563-550d-46a4-da9fe46cad57}' # Microsoft-Windows-Print-Platform
	'{fdcab703-6402-4959-b618-f5c3c279ef3d}' # Microsoft.Windows.Print.PrintConfig
	# Original UEX_Print
	'{C9BF4A01-D547-4D11-8242-E03A18B5BE01}' # LOCALSPL
	'{C9BF4A02-D547-4D11-8242-E03A18B5BE01}' # WINSPOOL
	'{C9BF4A03-D547-4D11-8242-E03A18B5BE01}' # WIN32SPL
	'{C9BF4A04-D547-4D11-8242-E03A18B5BE01}' # BIDISPL
	'{C9BF4A05-D547-4D11-8242-E03A18B5BE01}' # SPLWOW64
	'{C9BF4A06-D547-4D11-8242-E03A18B5BE01}' # SPLLIB
	'{C9BF4A07-D547-4D11-8242-E03A18B5BE01}' # PERFLIB
	'{C9BF4A08-D547-4D11-8242-E03A18B5BE01}' # ASYNCNTFY
	'{C9BF4A09-D547-4D11-8242-E03A18B5BE01}' # REMNTFY
	'{C9BF4A0A-D547-4D11-8242-E03A18B5BE01}' # GPPRNEXT
	'{C9BF4A0B-D547-4D11-8242-E03A18B5BE01}' # SANDBOX
	'{C9BF4A0C-D547-4D11-8242-E03A18B5BE01}' # SANDBOXHOST
	'{C9BF4A0D-D547-4d11-8242-E03A18B5BE01}' # MSW3PRT
	'{C9BF4A9E-D547-4D11-8242-E03A18B5BE01}' # SPOOLSV
	'{C9BF4A9F-D547-4D11-8242-E03A18B5BE01}' # SPOOLSS
	'{09737B09-A25E-44D8-AA75-07F7572458E2}' # PRNNTFY
	'{301CCC25-D58B-4C5E-B6A5-15BCF8B0077F}' # INETPPUI
	'{34F7D4F8-CD95-4B06-8BF6-D929DE4AD9DE}' # PRNCACHE
	'{528F557E-A4D4-4063-A17A-9F45FAF8C042}' # HGPRINT
	'{3EA31F33-8F51-481D-AEB7-4CA37AB12E48}' # LPDSVC
	'{62A0EB6C-3E3E-471D-960C-7C574A72534C}' # TCPMon
	'{6D1E0446-6C52-4B85-840D-D2CB10AF5C63}' # WSDPrPxy
	'{836767A6-AF31-4938-B4C0-EF86749A9AEF}' # WSDMON
	'{9558985E-3BC8-45EF-A2FD-2E6FF06FB886}' # WSDPRINT
	'{9677DFEF-EACF-4173-8977-FFB0086B11E6}' # BridgeGuid
	'{99F5F45C-FD1E-439F-A910-20D0DC759D28}' # USBMon
	'{9E6D0D9B-1CE5-44B5-8B98-F32ED89077EC}' # LPRHelp
	'{A83C80B9-AE01-4981-91C6-94F00C0BB8AA}' # printui
	'{AAED978E-5B0C-4F71-B35C-16E9C0794FF9}' # CommonGuid
	'{B42BD277-C2BA-468B-AB3D-05B1A1714BA3}' # PRINTLIB
	'{B795C7DF-07BC-4362-938E-E8ABD81A9A01}' # NTPRINT
	'{C9BF4A9E-D547-4D11-8242-E03A18B5BEEE}' # INETPP
	'{CE444D6A-F287-4977-BBBD-89A0DD65B71D}' # CDIGuid
	'{D34AE79A-15FB-44F9-9FD8-3098E6FFFD49}' # D34AE79A
	'{EB4C6075-0B67-4A79-A0A3-7CD9DF881194}' # XpsRasFilter
	'{EE7E960D-5E42-4C28-8F61-D8FA8B0DD84D}' # ServerGuid
	'{F30FAB8E-84BB-48D4-8E80-F8967EF0FE6A}' # LPRMon
	'{F4DF4FA4-66C2-4C14-ABB1-19D099D7E213}' # COMPONENTGuid
	'{34F7D4F8-CD95-4B06-8BF6-D929DE4AD9DE}' # PRNCACHE
	'{883DFB21-94EE-4C9B-9922-D5C42B552E09}' # PRNFLDR
	'{3048407B-56AA-4D41-82B2-7D5F4B1CDD39}' # DAFPRINT
	'{2F6A026F-D4C4-41B8-A59E-2EC834419B67}' # PUIOBJ
	'{79B3B0B7-F082-4CEC-91BC-5E4B9CC3033A}' # FDPRINT
	'{CAC16EB2-12D0-46B8-B484-F179C900772B}' # PMCSNAP
	'{0DC96237-BBD4-4BC9-8184-46DF83B1F1F0}' # DOXXPS
	'{0675CF90-F2B8-11DB-BB42-0013729B82C4}' # DOXPKG
	'{986DE178-EA3F-4E27-BBEE-34E0F61535DD}' # XpsRchVw
	'{64F02056-AFD9-42D9-B221-6C94733B09B1}' # XpsIFilter
	'{2BEADE0B-84CD-44A5-90A7-5B6FB2FF83C8}' # XpsShellExt
	'{AAACB431-6067-4A42-8883-3C01526DD43A}' # XpsRender
	'{12DC38E3-E395-4C8E-9156-B5642057F5FA}' # Microsoft-Windows-PrintDialogs3D
	'{27E76321-1E5B-4A82-BA0C-26E978F15072}' # Microsoft-Windows-PrintDialogs
	'{747EF6FD-E535-4D16-B510-42C90F6873A1}' # Microsoft-Windows-PrintService
	'{7F812073-B28D-4AFC-9CED-B8010F914EF6}' # Microsoft-Windows-PrintService-USBMon
	'{952773BF-C2B7-49BC-88F4-920744B82C43}' # Microsoft-Windows-TerminalServices-Printers
	'{0ED38D2B-4ACC-4E23-A8EC-D0DACBC34637}' # tsprint
	'{9B4A618C-07B8-4182-BA5A-5B1943A92EA1}' # MSXpsFilters
	'{A6D25EF4-A3B3-4E5F-A872-24E71103FBDC}' # MicrosoftRenderFilter
	'{AEFE45F4-8548-42B4-B1C8-25673B07AD8B}' # PrintFilterPipelinesvc
	'{BE967569-E3C8-425B-AD0E-4F2C790B1848}' # Microsoft-Windows-Graphics-Printing3D
	'{CF3F502E-B40D-4071-996F-00981EDF938E}' # Microsoft-Windows-PrintBRM
	'{E7AA32FB-77D0-477F-987D-7E83DF1B7ED0}' # Microsoft-Windows-Graphics-Printing
	'{7672778D-86FE-41D0-85C8-82CAA8CE6168}' # ESUPDATE(Maybe not used now)
	'{7663DA2F-1594-4C33-83DD-D5C64BBED68A}' # ObjectsGuid
	'{5ED940EB-18F9-4227-A454-8EF1CE5B3272}' # SetupLPR
	'{27239FD0-425E-11D8-9E39-000039252FD8}' # COMMONGuid
	'{04160794-60B6-4EC7-96FF-4953691F94AA}' # SetupIPP
	'{C59DA080-9CCE-4415-A77D-08457D7A059F}' # JScriptLib
	'{19E93940-A1BD-497F-BC58-CA333880BAB4}' # PrintExtension
	'{DD6A31CB-C9C6-4EF9-B738-F306C29352F4}' # MODERNPRINT
	'{3FB15E5D-DF1A-46FC-BEFE-27A4B82D75EE}' # PREFDLG
	'{02EA8EB9-9811-46d6-AEEE-430ADCC2AA18}' # DLGHOST
	'{D3A10B55-1EAD-453d-8FC7-35DA3D6A04D2}' # TCPMIB
	'{B48AE058-218A-4338-9B97-9F5F9E4EB5D2}' # USBJSCRIPT
    # Function Discovery
    '{2A1B2634-D069-4A57-B465-EB75B413E495}' # SyncTraceGuid
    '{B0CF9782-1FDF-4E2E-B00D-B0437E36C9A2}' # RingtoneTraceGuid
    '{F7155847-D7FA-413A-809F-CFB02894905C}' # DevCtrTraceGuid
    '{4244C025-536E-4A36-9D92-5D67F3C1FF44}' # Microsoft.Windows.DSM.DeviceMetadataRetrievalClient
    '{888DC41F-CC0C-49F8-A2A5-7809F155F197}' # Microsoft.Windows.DSM.FdDDO
    '{9DB0FDB5-3B21-440E-A94B-63738A4BE5DE}' # Microsoft-Windows-FunctionDiscovery
    '{538CBBAD-4877-4EB2-B26E-7CAEE8F0F8CB}' # Microsoft-Windows-FunctionDiscoveryHost
)

$UEX_TaskProviders = @(
 	'{077E5C98-2EF4-41D6-937B-465A791C682E}' # Microsoft-Windows-DesktopActivityBroker
 	'{6A187A25-2325-45F4-A928-B554329EBD51}' # Scheduler
 	'{047311A9-FA52-4A68-A1E4-4E289FBB8D17}' # TaskEng_JobCtlGuid
 	'{10FF35F4-901F-493F-B272-67AFB81008D4}' # UBPM
 	'{19043218-3029-4BE2-A6C1-B6763CECB3CC}' # EventAggregation
 	'{0dd85d84-97cd-4710-903f-3b28bacbcbd2}' # Microsoft.Windows.TaskScheduler
 	'{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}' # Microsoft-Windows-TaskScheduler
 	'{6966FE51-E224-4BAA-99BC-897B3ED3B823}' # Microsoft.Windows.BrokerBase
 	'{0657ADC1-9AE8-4E18-932D-E6079CDA5AB3}' # Microsoft-Windows-TimeBroker
 	'{E8109B99-3A2C-4961-AA83-D1A7A148ADA8}' # System/TimeBroker WPP
)

$UEX_SearchProviders = @(
	'{44e18db2-6cfd-4a07-8fe7-6073794c531a}' # Microsoft.Windows.Search.Indexer
	'{CA4E628D-8567-4896-AB6B-835B221F373F}' # Microsoft-Windows-Search(tquery.dll)
	'{dab065a9-620f-45ba-b5d6-d6bb8efedee9}' # Microsoft-Windows-Search-ProtocolHandlers
	'{49c2c27c-fe2d-40bf-8c4e-c3fb518037e7}' # Microsoft-Windows-Search-Core
	'{FC6F77DD-769A-470E-BCF9-1B6555A118BE}' # Microsoft-Windows-Search-ProfileNotify
)

$UEX_ContactSupportProviders = @(
	'{B6CC0D55-9ECC-49A8-B929-2B9022426F2A}' # Microsoft-Client-Licensing-Platform-Instrumentation
	'{8127F6D4-59F9-4ABF-8952-3E3A02073D5F}' # Microsoft-Windows-AppXDeployment
	'{3F471139-ACB7-4A01-B7A7-FF5DA4BA2D43}' # Microsoft-Windows-AppXDeployment-Server
	'{8FD4B82B-602F-4470-8577-CBB56F702EBF}' # Microsoft.Windows.AppXDeploymentClient.WPP
	'{FE762FB1-341A-4DD4-B399-BE1868B3D918}' # Microsoft.Windows.AppXDeploymentServer
	'{BA44067A-3C4B-459C-A8F6-18F0D3CF0870}' # DEPLOYMENT_WPP_GUID
	'{B9DA9FE6-AE5F-4F3E-B2FA-8E623C11DC75}' # Microsoft-Windows-SetupPlatform-AutoLogger
	'{9213C3E1-0D6C-52DD-78EA-F3B082111406}' # Microsoft-Windows-PriResources-Deployment
	'{06184C97-5201-480E-92AF-3A3626C5B140}' # Microsoft-Windows-Services-Svchost
	'{89592015-D996-4636-8F61-066B5D4DD739}' # Microsoft.Windows.StateRepository
	'{551FF9B3-0B7E-4408-B008-0068C8DA2FF1}' # Microsoft.Windows.StateRepository.Service
	'{DB00DFB6-29F9-4A9C-9B3B-1F4F9E7D9770}' # Microsoft-Windows-User Profiles General
	'{6AF9E939-1D95-430A-AFA3-7526FADEE37D}' # ClipSvcProvider
	'{B94D76C5-9D56-454A-8D1B-6CA30898160E}' # Microsoft.ClipSvc
	'{9A2EDB8F-5883-499F-ACED-6E4B69D43DDF}' # WldpTraceLoggingProvider
	'{A323CDC2-81B0-48B2-80C8-B749A221478A}' # Castle(WPP)
	'{A74EFE00-14BE-4EF9-9DA9-1484D5473302}' # CNGTraceControlGuid
	'{F0558438-F56A-5987-47DA-040CA75AEF05}' # Microsoft.Windows.WinRtClassActivation
	'{F25BCD2E-2690-55DC-3BC4-07B65B1B41C9}' # Microsoft.Windows.User32
	'{30336ED4-E327-447C-9DE0-51B652C86108}' # Microsoft-Windows-Shell-Core 
	'{1AFF6089-E863-4D36-BDFD-3581F07440BE}' # ComBaseTraceLoggingProvider
	'{6AD52B32-D609-4BE9-AE07-CE8DAE937E39}' # Microsoft-Windows-RPC
	'{F4AED7C7-A898-4627-B053-44A7CAA12FCD}' # Microsoft-Windows-RPC-Events 
	'{A86F8471-C31D-4FBC-A035-665D06047B03}' # Microsoft-Windows-WinRT-Error
	'{BDA92AE8-9F11-4D49-BA1D-A4C2ABCA692E}' # Microsoft-Windows-COMbase
)

$UEX_WPNProviders = @(
	'{F0AE506B-805E-434A-A005-7971D555179C}' # Wpn(WPP)
	'{4ff58fbe-3d4d-447a-ac26-7da2c51f4b7d}' # WpnSrum(WPP)
	'{2FDB1F25-8DE1-4BC1-BAC2-E445E5B38743}' # Microsoft.Windows.Notifications.WpnApps
	'{B92D1FF0-92EC-444D-B7EC-C016F971C000}' # Microsoft.Windows.Notifications.WpnCore
	'{EE845016-EBE1-41EB-BE52-5E3AE58339F2}' # WNSCP
	'{833c9bbd-6422-59cb-83bb-c695934a0cf5}' # Microsoft.Windows.PerProcessSystemDpi
	'{5cad3597-5fec-4c62-9ce1-9d7abc723d3a}' # Microsoft-Windows-PushNotifications-Developer
	'{815a1f4a-3f8d-4b37-9b31-5142f9d724a5}' # Microsoft-Windows-PushNotifications-InProc
	'{88cd9180-4491-4640-b571-e3bee2527943}' # Microsoft-Windows-PushNotifications-Platform
	'{eb3540f2-1909-5d51-b72d-a3ecb0b9bf08}' # Microsoft.Windows.Shell.NotificationController
	'{33b3eaa6-d8dd-5096-8687-6f520d32fc9e}' # Microsoft.Windows.Shell.NotificationSettings
	'{4bfe0fde-99d6-5630-8a47-da7bfaefd876}' # Microsoft-Windows-Shell-NotificationCenter
	'{7145ABF9-99F5-4CCF-A2B6-C9B2E05BA8B3}' # Microsoft.Windows.Shell.NotificationQuietHours
	'{ce575084-01be-5ef2-75f2-2d822e70cec9}' # Microsoft.Windows.Internal.Shell.Session.WnfPolicy
	'{1870FBB0-2247-44D8-BF46-B02130A8A477}' # Microsoft.Windows.Notifications.WpnApis
)

$UEX_Win32kProviders = @(
	'{e75a83ec-ef30-4e3c-a5fb-1e7626e48f43}' # Win32kPalmMetrics
	'{72a4952f-db5c-4d90-8f9d-0ed3465b315e}' # Win32kDeadzonePalmTelemetryProvider
	'{7e6b69b9-2aec-4fb3-9426-69a0f2b61a86}' # Microsoft.Windows.Win32kBase.Input
	'{ce20d1cc-faee-4ef6-9bf2-2837cef71258}' # Win32kSyscallLogging
	'{deb96c0a-d2d9-5868-a5d5-50ee13513c8b}' # Microsoft.Windows.Graphics.Display
	'{703fcc13-b66f-5868-ddd9-e2db7f381ffb}' # Microsoft.Windows.TlgAggregateInternal
	'{aad8d3a1-0ce4-4c7e-bf32-15b2836659b7}' # Microsoft.Windows.WER.MTT
	'{6d1b249d-131b-468a-899b-fb0ad9551772}' # TelemetryAssert
	'{03914E49-F3DD-40B9-BB7F-9445BF46D43E}' # Microsoft.Windows.Win32kMin.WPP
	'{0F81EC00-9E52-48E6-B899-EB3BBEEDE741}' # Microsoft.Windows.Win32kBase.WPP
	'{335D5E04-5638-4E58-AA36-7ED1CFE76FD6}' # Microsoft.Windows.Win32kFull.WPP
	'{9C648335-6987-470C-B588-3DE7A6A1FDAC}' # Microsoft.Windows.Win32kNs.WPP
	'{487D6E37-1B9D-46D3-A8FD-54CE8BDF8A53}' # Microsoft.Windows.Win32k.TraceLogging
	'{8C416C79-D49B-4F01-A467-E56D3AA8234C}' # Microsoft.Windows.Win32k.UIF
)

$UEX_AppCompatProviders = @(
	'{EEF54E71-0661-422d-9A98-82FD4940B820}' # Microsoft-Windows-Application-Experience
	'{4CB314DF-C11F-47d7-9C04-65FB0051561B}' # Microsoft-Windows-Program-Compatibility-Assistant
	'{DD17FA14-CDA6-7191-9B61-37A28F7A10DA}' # Microsoft.Windows.Appraiser.General
	'{03A70C9D-084B-4905-B341-F6377E734858}' # Microsoft.Windows.Appraiser.Instrumentation
	'{CAEA06A5-D164-4AFA-8CDF-444E3AE008A0}' # Microsoft.Windows.Appraiser.Critical
	'{F5647876-050D-4CF0-BA2F-C498B41C152A}' # DPIScalingProvider
	'{1f87779d-1ad0-45cd-8d2e-0ac9406bc878}' # Microsoft.Windows.Compatibility.Inventory.Agent
	'{32c3bee9-e3f4-4757-95a3-90e6d43299ec}' # Microsoft.Windows.Compatibility.Inventory.WMI
	'{9EFCB348-D13C-4B3A-8AB1-869AAB424C34}' # Microsoft.Windows.Inventory.General
	'{45D5CCD7-6E27-4318-82DD-69BD83A8F672}' # Microsoft.Windows.Inventory.Indicators
	'{407C75AC-661F-4C74-A4B0-ACDD9A643E42}' # Microsoft.Windows.PCA.PushApphelp
	'{95ABB8AF-1790-48BD-85AC-5FEED398DD9E}' # Microsoft.Windows.PCA.Siuf
	'{511A5C98-B374-446E-9625-108624A3CCAA}' # Microsoft.Windows.Compatibility.PCA
	'{74791F71-8F1E-4D6A-AA73-AE7FB15B0D24}' # Microsoft.Windows.AppHelp.Dialog
	'{E7558269-3FA5-46ed-9F4D-3C6E282DDE55}' # Microsoft-Windows-UAC
	'{b059b83f-d946-4b13-87ca-4292839dc2f2}' # Microsoft-Windows-User-Loader 
	'{c02afc2b-e24e-4449-ad76-bcc2c2575ead}' # Microsoft-Windows-UAC-FileVirtualization
	'{AD8AA069-A01B-40A0-BA40-948D1D8DEDC5}' # Microsoft-Windows-WER-Diagnostics
	'{A0EF609D-0A14-424C-9270-3B2691A0A394}' # ErcLuaSupportTracingGuid
	'{996D3F20-43BD-40FF-9CC9-D67E5FFFD964}' # LUA
	'{CBB61B6D-A2CF-471A-9A58-A4CD5C08FFBA}' # UACLog
	'{A868CF57-6875-4EF9-8B42-C3CB590CA756}' # Microsoft.Windows.Compatibility.Luafv
	'{DAB3B18C-3C0F-43E8-80B1-E44BC0DAD901}' # Microsoft-Windows-AxInstallService
	'{0F81EC00-9E52-48E6-B899-EB3BBEEDE741}' # Microsoft.Windows.Win32kBase.WPP
	'{335D5E04-5638-4E58-AA36-7ED1CFE76FD6}' # Microsoft.Windows.Win32kFull.WPP
)

$UEX_VANProviders = @(
	'{111FFC99-3987-4bf8-8398-61853120CB3D}' # PNIandNetcenterGUID
	'{9A59814D-6DF5-429c-BD0D-2D41B4A5E9D3}' # PNIandNetcenterGUID
	'{2c929297-cd5c-4187-b508-51a2754a95a3}' # VAN WPP
	'{e6dec100-4e0f-4927-92be-e69d7c15c821}' # WlanMM WPP
)

$UEX_UserDataAccessProviders = @(
	'{D1F688BF-012F-4AEC-A38C-E7D4649F8CD2}' # Microsoft-Windows-UserDataAccess-UserDataUtils
	'{fb19ee2c-0d22-4a2e-969e-dd41ae0ce1a9}' # Microsoft-Windows-UserDataAccess-UserDataService
	'{56f519ab-9df6-4345-8491-a4ba21ac825b}' # Microsoft-Windows-UserDataAccess-UnifiedStore
	'{99C66BA7-5A97-40D5-AA01-8A07FB3DB292}' # Microsoft-Windows-UserDataAccess-PimIndexMaintenance
	'{B9B2DE3C-3FBD-4F42-8FF7-33C3BAD35FD4}' # Microsoft-Windows-UserDataAccess-UserDataApis
	'{0BD19909-EB6F-4b16-8074-6DCE803F091D}' # Microsoft-Windows-UserDataAccess-Poom
	'{83A9277A-D2FC-4b34-BF81-8CEB4407824F}' # Microsoft-Windows-UserDataAccess-CEMAPI
	'{f5988abb-323a-4098-8a34-85a3613d4638}' # Microsoft-Windows-UserDataAccess-CallHistoryClient
	'{15773AD5-AA2F-422A-9129-4A83F4C19DB0}' # Microsoft.Windows.UserDataAccess.UserDataService
	'{cb76d769-a1ed-4fb1-98c3-266951610fd8}' # Microsoft.Windows.UserDataAccess.Unistore
	'{0a0a7808-8dda-4ba0-a656-b2c740ab9108}' # Microsoft.Windows.UserDataAccess.UserDataApisBase
	'{553ebe04-ceb2-47ee-b394-bb83b97de219}' # Microsoft.Windows.UserDataAccess.UserDataAccounts
	'{d6eac963-c24f-434d-be23-4aa21904148f}' # Microsoft.Windows.UserDataAccess.TaskApis
	'{ee3112cb-4b76-49eb-a73b-712ad05e18cb}' # Microsoft.Windows.UserDataAccess.EmailApis
	'{3f7fafe6-1dd2-4720-b75b-e3268a0e6120}' # Microsoft.Windows.UserDataAccess.ContactApis
	'{412f73f7-ebf9-466f-90e7-606accdbcd15}' # Microsoft.Windows.UserDataAccess.Cemapi
	'{a94f431e-5460-465f-bf2e-6245b56d6ce9}' # Microsoft.Windows.UserDataAccess.AppointmentApis
	'{E0A18F5C-07F3-4A44-B149-0F8F13EF6887}' # Microsoft.Windows.ApplicationModel.Chat.ChatMessageBlocking
	'{FCC174D3-8890-434A-812D-BDED72EDE356}' # Microsoft.Windows.Unistack.FailureTrigger
	'{870ac05a-7777-5c66-c3f0-c1f6b7129ef6}' # Microsoft.Windows.Messaging.Service
	'{1e2462be-b025-48da-8c1f-7b60b8ccae53}' # microsoft-windows-appmodel-messagingdatamodel
	'{3da5aa05-5152-551f-a243-80a4e743c70e}' # Microsoft.Windows.Messaging.App
)

$UEX_WMIBridgeProviders = @(
	'{A76DBA2C-9683-4BA7-8FE4-C82601E117BB}' # Microsoft.Windows.DeviceManagement.WmiBridge
)

$UEX_WERProviders = @(
	'{E46EEAD8-0C54-4489-9898-8FA79D059E0E}' # Microsoft-Windows-Feedback-Service-TriggerProvider
	'{2E4201B6-4891-4912-A139-23268D5EB46E}' # WerFaultTracingGuid
	'{31EC0DFD-E734-4181-9C80-C9974C40BCEB}' # TpClientWppGuid
	'{36082273-7635-44A5-8D35-D2A266538B00}' # WerMgrTracingGuid
	'{3E19A300-75D9-4027-86BA-948B70416220}' # WerConsoleTracingGuid
	'{5EF9EC44-FB87-4F51-AF4E-CED084013281}' # FaultRepTracingGuid
	'{6851ADEB-79DA-4250-A440-F1F52D28711D}' # WerSvcTracingGuid
	'{75638A28-E9ED-42B2-9F8F-C2B1F89CF5EE}' # InfraTracingGuid
	'{7930F74B-E328-4350-89C6-11FD93771488}' # WerFaultTracingGuid
	'{9760D9C2-2FBF-4CDA-889F-8DAB2BDD98B0}' # DWTracingGuid
	'{A0EF609D-0A14-424C-9270-3B2691A0A394}' # ErcLuaSupportTracingGuid
	'{DC02AB24-0AA6-4499-8D86-A8E5F83741F5}' # HangRepTracingGuid
	'{E2821408-C59D-418F-AD3F-AA4E792AEB79}' # SqmClientTracingGuid
	'{F904D5CC-2CCA-47B0-A3CE-A05944692545}' # WerFaultSilentProcessExitLibTracingGuid
	'{FCD00FEF-04FA-41C0-889E-AE613D97602B}' # WerUITracingGuid
	'{1377561D-9312-452C-AD13-C4A1C9C906E0}' # FaultReportingTracingGuid
	'{CC79CF77-70D9-4082-9B52-23F3A3E92FE4}' # WindowsErrorReportingTracingGuid
	'{97945555-b04c-47c0-b399-e453d509a5f0}' # WERSecureVerticalTracingGuid
	'{2b87e57e-7bd0-43a3-a278-02e62d59b2b1}' # WERVerticalTracingGuid
	'{3E0D88DE-AE5C-438A-BB1C-C2E627F8AECB}' # HangReporting
	'{4A743CBB-3286-435C-A674-B428328940E4}' # PSMTracingGuid
	'{D2440861-BF3E-4F20-9FDC-E94E88DBE1F6}' # BrokerInfrastructureWPP
	'{9C6FC32A-E17A-11DF-B1C4-4EBADFD72085}' # PLM WPP tracing
	'{EB65A492-86C0-406A-BACE-9912D595BD69}' # Microsoft-Windows-AppModel-Exec
)

$UEX_MMCProviders = @(
	'{9C88041D-349D-4647-8BFD-2C0A167BFE58}' # MMC
)

$UEX_QuickAssistProviders = @(
	'{91558F59-B78A-4994-8B64-8067B33BDD71}' # Microsoft.RemoteAssistance
)

$UEX_FSLogixProviders = @(
	'{9a2c09eb-fbd6-5127-090f-402799cb18a2}' # Microsoft.FSLogix.Frxsvc
	'{5f7d6ea0-7bfa-5c0a-4674-acce76757f19}' # Microsoft.FSLogix.Frxccds
	'{83afe79f-c9c6-5152-3636-05de47c1fa72}' # Microsoft.FSLogix.Search
	'{65fa0e9f-db27-5053-a4e0-e40c42ba5271}' # Microsoft.FSLogix.UsermodeDll
	'{578c4cac-e98c-5315-f3e6-fbc0a97b286f}' # Microsoft.FSLogix.ConfigurationTool
	'{048a4a25-ff60-5d27-8f58-71c0f9d3fc92}' # Microsoft.FSLogix.RuleEditor
	'{f1a8d80a-2d4d-5dfc-7c26-88b5cce761c9}' # Microsoft.FSLogix.JavaRuleEditor
	'{6d14bf0a-be6f-592f-cbcc-61b5e8d18c5c}' # Microsoft.FSLogix.IE_Plugin
	'{f9317b16-badc-55b3-a0cf-9a0a126e12fd}' # Microsoft.FSLogix.FrxLauncher
	'{220d0827-a763-50ac-6999-a59a7ca5d316}' # Microsoft.FSLogix.TrayTool
	'{e5cd7d19-e708-5957-ba97-11858c57eb80}' # Microsoft.FSLogix.Frxdrvvt
	'{6352de6a-8fc2-5afe-a709-fb70e825dc24}' # Microsoft.FSLogix.Frxdrv
	'{becf2b11-c4a9-5e4c-e0d2-c22092799316}' # Microsoft.FSLogix.Diagnostic
	'{5d97526b-4987-550f-4bee-347e84c5a5c6}' # Microsoft.FSLogix.Frxccd
	'{EE5D17C5-1B3E-4792-B0F9-F8C5FC6AC22A}' # Azure Storage
)

$UEX_FusionProviders = @()

$UEX_WSCProviders = @(
	'{1B0AC240-CBB8-4d55-8539-9230A44081A5}' # SecurityCenter
	'{9DAC2C1E-7C5C-40eb-833B-323E85A1CE84}' # WSCInterop
	'{e6b5b34f-bd4d-5cdc-8346-ef4dc6cf1927}' # Microsoft.Windows.Security.WSC
	'{6d357dbe-57a2-5317-7970-19192e402ae6}' # Microsoft.Windows.Defender.Shield
	'{3a47280f-ef8d-41af-9288-64db7a9890d3}' # Microsoft.Windows.Defender.SecurityHealthAgent
	'{7a01e7fb-b6a4-4585-b1a8-ea2094ecb4c5}' # Microsoft.Antimalware.Scan.Interface
)

$UEX_LicenseManagerProviders = @(
	'{5e30c57a-8730-4809-945e-0d5df7aa58e5}' # Microsoft.ClientLicensing.InheritedActivation
	'{CFBEA673-BF20-4BD8-B595-29B82D43DF39}' # Microsoft.ClipUp
	'{466F3B39-9929-45E6-B891-D867BD20B738}' # Microsoft.Windows.Licensing.UpgradeSubscription
	'{B94D76C5-9D56-454A-8D1B-6CA30898160E}' # Microsoft.ClipSvc
	'{4b0cf5b8-5962-479b-9635-7dfb7c8265bc}' # ClipCLoggingProvider
	'{961d7772-0a35-4869-89ad-056fbfc0e51f}' # Microsoft.Windows.LicensingCSP
	'{B4B126DE-32FE-4591-9AC5-B0778D79A0E7}' # Microsoft.ClipSp
	'{ED0C10A5-5396-4A96-9EE3-6F4AA0D1120D}' # Microsoft.ClipC
)

$UEX_ServerManagerProviders = @(
	'{C2E6D0D9-5DF8-4C77-A82B-C96C84579543}' # Microsoft-Windows-ServerManager-ManagementProvider
	'{D8D37081-10BD-4A89-A971-1CDA6899BDB3}' # Microsoft-Windows-ServerManager-MultiMachine
	'{66AF9A38-2D94-11E0-A076-8534E0D72085}' # Microsoft-Windows-ServerManager-DeploymentProvider
	'{6e27f02d-8a55-477e-88b5-6f1ba07e14b4}' # Microsoft-Windows-ServerManager-ConfigureSMRemoting
)

$UEX_WVDProviders = @(
	'{C3B02229-FF93-4D28-ACFC-4FB28AC6CDB5}' # RdClientWinRT
	'{97A820E5-5F64-4573-8114-99B450D0B067}' # RDCoreApp
	'{6FA2A01C-9F89-474B-A71A-A783925EFE45}' # RDCoreNanoCom
	'{CA341B3C-B9D2-4D0F-9BD3-D88183596DB9}' # RDP.ServerStack.Diagnostics
	'{6CBE573A-121B-4E02-A09D-6C0B6B96D676}' # RDP.ServerStack.QOE
	'{50134CDD-5FE1-4315-8C8D-50900921ACCE}' # Microsoft.Windows.HVSI.RDP
	'{080656C2-C24F-4660-8F5A-CE83656B0E7C}' # Microsoft.Windows.RemoteDesktop.ClientCore
	'{48EF6C18-022B-4394-BEE5-7B822B42AE4C}' # Microsoft.RDS.Windows.Client.MSRDC
	'{335934AA-6DD9-486C-88A5-F8D6A7D2BAEF}' # Microsoft.RDS.Windows.Client.AX
	'{43471865-f3ee-5dcf-bf8b-193fcbbe0f37}' # Microsoft.Windows.RemoteDesktopServices.RailPlugin
	'{FB9FF164-54F0-43DD-BF86-1C761FAB3052}' # msrdcsh
	'{E80ADCF1-C790-4108-8BB9-8A5CA3466C04}' # Microsoft-Windows-TerminalServices-RDP-AvcSoftwareDecoder
	'{eb6594d8-6fad-53f7-350e-f4e4c531f68c}' # Microsoft.Windows.RDP.NamedPipe
	'{7756e5a6-21b2-4c40-855e-88cf2b13c7cb}' # RDP.MSTSCAXTelemetry
	'{76de1e7b-74d5-575e-1f81-4ffe6a42777b}' # RDWin32ClientAxTelemetryProvider
	'{D953B8D8-7EA7-44B1-9EF5-C34AF653329D}' # RDP.Graphics
	'{8A633D91-8B07-4AAE-9A00-D07E2AFD29D6}' # RDP.Transport
	'{a8f457b8-a2b8-56cc-f3f5-3c00430937bb}' # RDPEmulationTraceLogging
	'{93C56D9B-7FDB-4E06-8DED-26000EEE0F60}' # MSTSCFeedbackHub
	'{4f50731a-89cf-4782-b3e0-dce8c90476ba}' # Microsoft Telemetry provider group
	'{140C2428-F60D-43F9-9B07-3E5F622438A0}' # CacNxTraceGuid(WPP)
	'{eca5427c-f28f-4942-a54b-7e86da46bdbe}' # TSUrbUtils(WPP)
	'{7211ae02-1eb0-454a-88fa-ea16632dcb45}' # TSUsbBusFilter(WPP)
	'{39a585ff-6c36-492b-93c0-35b71e65a345}' # TSUsbGenericDriver(WPP)
	'{a0674fb6-ba0d-456f-b079-a2b029d8342c}' # TSUsbHubTrace(WPP)
	'{48738267-0545-431d-8087-7349127811d0}' # TSUsbRedirectionServiceTrace(WPP)
)

$UEX_MSRAProviders = @(
	'{5b0a651a-8807-45cc-9656-7579815b6af0}' # Microsoft-Windows-RemoteAssistance
	'{BBBC81CF-E219-469C-A405-F820EE496194}' # Microsoft-Windows-P2P-PNRP
)

$UEX_ESENTProviders = @(
	'{478EA8A8-00BE-4BA6-8E75-8B9DC7DB9F78}' # Microsoft-ETW-ESE
	'{02f42b1b-4b78-48ce-8cdf-d98f8b443b93}' # Microsoft.Windows.ESENT.TraceLogging
)

$UEX_CloudSyncProviders = @(
	'{278c595e-310c-5d49-0cca-546ce8745f9e}' # Microsoft.Windows.Shell.SyncOperation
	'{c906ed7b-d3d9-435b-97cd-22f4e7445f2a}' # Microsoft.Windows.WorkFolders
	'{885735DA-EFA7-4042-B9BC-195BDFA8B7E7}' # Microsoft.Windows.BackupAndRoaming.AzureSyncEngine
	'{95EA8EB8-6F34-45BC-8FA3-BAFEAF6C9915}' # Microsoft.Windows.BackupAndRoaming.SyncEngine
	'{49B5ED52-D5A9-47A6-9BFB-4C6C6AA200CE}' # Microsoft.Windows.BackupAndRoaming.Diagnostics
	'{40BA871E-4C49-41BC-A90C-753FF294F160}' # Microsoft.Windows.BackupAndRoaming.SyncOperations
	'{06ee5c69-51c7-5ebe-0c8f-a049cc071d3f}' # Microsoft.Windows.BackupAndRoaming.AzureWilProvider
	'{D84556B5-1EBE-5073-BCBE-F34AFDF8094D}' # Microsoft.Windows.SettingSync.AzureTracingProvide
	'{3c1be35c-79fd-55ec-2d51-2d7b19e1d377}' # Microsoft.Windows.BackupAndRoaming.WilProvider
	'{83D6E83B-900B-48a3-9835-57656B6F6474}' # Microsoft-Windows-SettingSync
	'{1284e99b-ff7a-405a-a60f-a46ec9fed1a7}' # MSF_MDS_ESE_WPP_CONTROL_GUID
	'{111157cb-ee69-427f-8b4e-ef0feaeaeef2}' # ECS_WPP_CONTROL_GUID
)

$UEX_DeviceStoreProviders = @(
	'{F7155847-D7FA-413A-809F-CFB02894905C}' # Microsoft\Shell\DeviceCenter
)

$UEX_RDWebRTCProviders = @(
	'{E75983D3-3045-49D7-9E5D-6E7EECC45261}' # RDPWebRTCRedirectorClient
	'{AAA1F55E-F99C-45CB-B318-FAEB798DB8E0}' # RDPWebRTCRedirectorHost
	'{2EFD4CDE-32FD-4A55-A310-2DB9A49D4262}' # CTRLGUID_RDC_WEBRTC_REDIRECTOR
)

$UEX_AppIDProviders = @(
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

$UEX_RestartManagerProviders = @(
	'{0888E5EF-9B98-4695-979D-E92CE4247224}' # Microsoft-Windows-RestartManager
)

$UEX_PowerShellProviders = @(
	'{A0C1853B-5C40-4B15-8766-3CF1C58F985A}' # Microsoft-Windows-PowerShell
	'{EAD6595B-5613-414C-A5EE-069BB1ECA485}' # Microsoft-Windows-PowerShellWebAccess
)

$UEX_MMCSSProviders = @(
	'{36008301-E154-466C-ACEC-5F4CBD6B4694}' # Microsoft-Windows-MMCSS
	'{F64BF471-CBDE-4203-8974-AFC7381A2862}' # MmcssTrace
	'{F8F10121-B617-4A56-868B-9DF1B27FE32C}' # MMCSS
)

$UEX_TelemetryProviders = @(
	'{43AC453B-97CD-4B51-4376-DB7C9BB963A}'  # Microsoft.Windows.DiagTrack
	'{56DC463B-97E8-4B59-E836-AB7C9BB96301}' # Microsoft-Windows-DiagTrack
)

$UEX_WMIActivityProviders = @(
	'{1FF6B227-2CA7-40F9-9A66-980EADAA602E}' # WMI_Tracing
	'{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}' # Microsoft-Windows-WMI-Activity
)
#endregion --- ETW component trace Providers ---

#region --- Scenario definitions ---  
$UEX_General_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_Dummy' = $true
	'CommonTask NET' = $True  ## <------ the commontask can take one of "Dev", "NET", "ADS", "UEX", "DnD" and "SHA", or "Full" or "Mini"
	'NetshScenario InternetClient_dbg' = $true
	'Procmon' = $true
	#'WPR General' = $true
	'PerfMon ALL' = $true
	'PSR' = $true
	'Video' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
}

$UEX_Logon_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_Logon' = $True
	'PRF_Shell' = $True
	'UEX_RDS' = $True
	'ADS_LSA' = $True
}

# Contact Garabier for the MMC scenario
$UEX_MMC_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_MMC' = $True
	'UEX_Fusion' = $True
	'Procmon' = $True
	'CollectComponentLog' = $True
	'PSR' = $true
}

$UEX_Task_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_Task' = $True
	'PRF_Shell' = $True
	'UEX_Logon' = $True
	'WPR General' = $true
	'Procmon' = $true
	'PSR' = $true
}

$UEX_QuickAssist_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_QuickAssist' = $True
	'NetshScenario InternetClient_dbg' = $true
	'PSR' = $true
}

$UEX_Search_ETWTracingSwitchesStatus = [Ordered]@{
	'PRF_Shell' = $True
	'UEX_Search' = $True
	'WPR General' = $true
	'Procmon' = $true
	'PSR' = $true
}

$UEX_ServerManager_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_WinRM' = $True
	'UEX_WMI' = $True
	'UEX_ServerManager' = $True
	'Netsh' = $true
	'PSR' = $true
}

$UEX_WinRM_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_WinRM' = $True
	'UEX_WMI' = $True
	'Netsh' = $true
	'PSR' = $true
	'CollectComponentLog' = $True
}

$UEX_WMI_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_WMI' = $True
	'UEX_COM' = $True
	'Netsh' = $true
	#'WPR General' = $true
	'PSR' = $true
	'CollectComponentLog' = $True
}

# Contact garabier for any change
$UEX_WMIHighCPU_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_WMIActivity' = $True
	'ADS_Kernel' = $True
	'WPR CPU' = $true
	'PSR' = $true
	'CollectComponentLog' = $True
	'noBasicLog' = $True
}

$UEX_PowerShell_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_PowerShell' = $true
	'UEX_WinRM' = $true
	'NetshScenario NetConnection' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'CollectComponentLog' = $True
 }

 $UEX_MDAG_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_MDAG' = $True
	'NET_HNSProviders' = $True
	'NET_FirewallProviders' = $True
	'NetshScenario dot3_wpp,wireless_dbg globallevel=0xff provider="Microsoft-Windows-CAPI2"' = $true
	'Procmon' = $true
	'PSR' = $true
	'Video' = $true
	'CollectComponentLog' = $True
}
 
 $UEX_MSRA_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_MSRA' = $True
	'UEX_COM' = $True
	'Netsh' = $True
	'ADS_Auth' = $true
	'Procmon' = $true
	'PSR' = $true
}

#region AVD host scenarios
$UEX_AVDCore_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_AVDCore' = $True
	'UEX_AVDDiag' = $True
	'noRepro' = $true
	'CollectComponentLog' = $True
	'noBasicLog' = $True
}

$UEX_AVDProfiles_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_AVDCore' = $True
	'UEX_AVDProfiles' = $True
	'UEX_AVDDiag' = $True
	'noRepro' = $true
	'CollectComponentLog' = $True
	'noBasicLog' = $True
}

$UEX_AVDActivation_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_AVDCore' = $True
	'UEX_AVDActivation' = $True
	'UEX_AVDDiag' = $True
	'noRepro' = $true
	'CollectComponentLog' = $True
	'noBasicLog' = $True
}

$UEX_AVDMSRA_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_AVDCore' = $True
	'UEX_AVDMSRA' = $True
	'UEX_AVDDiag' = $True
	'noRepro' = $true
	'CollectComponentLog' = $True
	'noBasicLog' = $True
}

$UEX_AVDSCard_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_AVDCore' = $True
	'UEX_AVDSCard' = $True
	'UEX_AVDDiag' = $True
	'noRepro' = $true
	'CollectComponentLog' = $True
	'noBasicLog' = $True
}

$UEX_AVDIME_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_AVDCore' = $True
	'UEX_AVDIME' = $True
	'UEX_AVDDiag' = $True
	'noRepro' = $true
	'CollectComponentLog' = $True
	'noBasicLog' = $True
}

$UEX_AVDTeams_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_AVDCore' = $True
	'UEX_AVDTeams' = $True
	'UEX_AVDDiag' = $True
	'noRepro' = $true
	'CollectComponentLog' = $True
	'noBasicLog' = $True
}

$UEX_AVDMSIXAA_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_AVDCore' = $True
	'UEX_AVDMSIXAA' = $True
	'UEX_AVDDiag' = $True
	'noRepro' = $true
	'CollectComponentLog' = $True
	'noBasicLog' = $True
}

$UEX_AVDHCI_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_AVDCore' = $True
	'UEX_AVDHCI' = $True
	'UEX_AVDDiag' = $True
	'noRepro' = $true
	'CollectComponentLog' = $True
	'noBasicLog' = $True
}

$UEX_AVDDiag_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_AVDDiag' = $True
	'noRepro' = $true
	'CollectComponentLog' = $True
	'noBasicLog' = $True
}
#endregion AVD host scenarios

#endregion --- Scenario definitions ---  

#region --- performance counters --- 
$UEX_SupportedPerfCounter = @{
	'UEX_RDS' = 'General counters + counter for RDCB'
	'UEX_Print' = 'General counters + Print related counters'
}

$UEX_RDSCounters = @(
	$global:GeneralCounters
	'\Terminal Services\*'
	'\Remote Desktop Connection Broker Counterset(*)\*'
	'\Remote Desktop Connection Broker Redirector Counterset(*)\*'
)

$UEX_PrintCounters = @(
	$global:GeneralCounters
	'\Paging File(*)\*'
	'\Cache(*)\*'
	'\Network Adapter(*)\*'
	'\Network Interface(*)\*'
	'\Server(*)\*'
	'\Server Work Queues(*)\*'
	'\Print Queue(*)\*'
)
#endregion --- performance counters --- 

#region ### Pre-Start / Post-Stop / Collect functions for trace components and scenarios
Function CollectUEX_AppCompatLog{
	EnterFunc $MyInvocation.MyCommand.Name
	$AppCompatLogFolder = "$LogFolder\AppCompatLog$LogSuffix"
	$LogPrefix = 'AppCompat'
	Try{
		FwCreateLogFolder $AppCompatLogFolder
	}Catch{
		LogException ("Unable to create $AppCompatLogFolder.") $_
		Return
	}
	$AppCompatRegistries = @(
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags', "$AppCompatLogFolder\AppCompatFlags-HKLM-Reg.txt"),
		('HKCU:Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags', "$AppCompatLogFolder\AppCompatFlags-HKCU-Reg.txt")
	)
	FwExportRegistry $LogPrefix $AppCompatRegistries
	REG SAVE 'HKLM\System\CurrentControlSet\Control\Session Manager\AppCompatCache' "$AppCompatLogFolder\AppCompatCache.HIV" 2>&1 | Out-Null
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectUEX_AppVLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("AppV") _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_AppIdLog{
	EnterFunc $MyInvocation.MyCommand.Name
	$LogPrefix = "AppID"
	$AppIdLogFolder = "$LogFolder\AppIDLog$LogSuffix"

	Try{
		FwCreateLogFolder $AppIdLogFolder
		Get-AppLockerPolicy -Effective -Xml | Out-File "$AppIdLogFolder\AppLockerPolicy.xml"
		xcopy $env:SystemRoot\System32\AppLocker "$AppIdLogFolder\$LogPrefix-System32_AppLocker" /I /E /Y /H /C /Q
		(Get-Item -Path Registry::HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\SystemCertificates\CA).GetAccessControl() | Format-List -Property * | Out-File "$AppIdLogFolder\$LogPrefix-ACL-SystemCertificates_CA.txt"
		(Get-Item -Path Registry::HKEY_USERS\S-1-5-19\SOFTWARE\Microsoft\SystemCertificates\CA).GetAccessControl().Access | Format-List -Property * | Out-File "$AppIdLogFolder\$LogPrefix-ACL-Access-SystemCertificates_CA.txt"
	}Catch{
		LogException ("Error Collect UEX_AppIdLog.") $_
		Return
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_COMPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	If($EnableCOMDebug.IsPresent){
		$COMDebugRegKey = "HKLM:Software\Microsoft\OLE\Tracing"
		If(!(Test-Path -Path "$COMDebugRegKey")){
			Try{
				LogInfo ("[COM] Creating `'HKLM\Software\Microsoft\OLE\Tracing`' key.")
				New-Item $COMDebugRegKey -ErrorAction Stop | Out-Null
			}Catch{
				LogMessage $LogLevel.Error ("Unable to creat `'HKLM\Software\Microsoft\OLE\Tracing`' key.")
				Return
			}
		}

		Try{
			LogInfo ("[COM] Enabling COM debug and setting `'ExecutablesToTrace`' to `'*`'.")
			Set-Itemproperty -path $COMDebugRegKey -Name 'ExecutablesToTrace' -value '*' -Type String -ErrorAction Stop
		}Catch{
			LogException ("Unable to set `'ExecutablesToTrace`' registry.") $_
			LogMessage $LogLevel.Warning ("[COM] COM trace will continue with normal level.")
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}
Function UEX_COMPostStop{
	$COMDebugRegKey = "HKLM:Software\Microsoft\OLE\Tracing"
	If(Test-Path -Path "$COMDebugRegKey"){
		$TracingKey = Get-ItemProperty -Path "HKLM:Software\Microsoft\OLE\Tracing" -ErrorAction Stop
		If($Null -ne $TracingKey.ExecutablesToTrace){
			Try{
				LogInfo ("[COM] Deleting `'ExecutablesToTrace`' registry.")
				Remove-ItemProperty -Path $COMDebugRegKey -Name 'ExecutablesToTrace' -ErrorAction Stop
			}Catch{
				LogException ("Unable to delete `'ExecutablesToTrace`' registry.") $_
				LogMessage $LogLevel.Warning ("[COM] Please remove `'ExecutablesToTrace`' under HKLM\Software\Microsoft\OLE\Tracing key manually.")
			}
		}
	}
}

Function CollectUEX_WMIActivityLog{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling WMI-Collect.ps1"
	.\scripts\WMI-Collect.ps1 -DataPath $global:LogFolder -AcceptEula -Logs
	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done WMI-Collect.ps1"
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_DSCLog{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling DSC-Collect.ps1"
	.\scripts\DSC-Collect.ps1 -DataPath $global:LogFolder -AcceptEula
	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done DSC-Collect.ps1"
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_EventLogLog{
	EnterFunc $MyInvocation.MyCommand.Name
	$EventLogFolder = "$LogFolder\EventLog$LogSuffix"
	$EventLogDumpFolder = "$EventLogFolder\Process dump"
	$EventLogSubscriptionFolder = "$EventLogFolder\WMISubscriptions"

	Try{
		FwCreateLogFolder $EventLogFolder
		FwCreateLogFolder $EventLogDumpFolder
		FwCreateLogFolder $EventLogSubscriptionFolder
	}Catch{
		LogException ("Unable to create $EventLogFolder.") $_
		Return
	}

	# Process dump
	FwCaptureUserDump "EventLog" $EventLogDumpFolder -IsService:$True

	# Settings and registries
	$Commands =@(
		"auditpol /get /category:* | Out-File -Append $EventLogFolder\auditpol.txt",
		"reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger $EventLogFolder\WMI-Autologger.reg.txt",
		"reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels $EventLogFolder\WINEVT-Channels.reg.txt",
		"reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers $EventLogFolder\WINEVT-Publishers.reg.txt",
		"reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog $EventLogFolder\EventLog-Policies.reg.txt",
		"reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog $EventLogFolder\EventLogService.reg.txt",
		"cacls C:\Windows\System32\winevt\Logs | Out-File -Append $EventLogFolder\Permissions.txt",
		"cacls C:\Windows\System32\LogFiles\WMI\RtBackup | Out-File -Append $EventLogFolder\Permissions.txt",
		"Copy-Item C:\Windows\System32\LogFiles\WMI\RtBackup -Recurse $EventLogFolder",
		"Get-ChildItem $env:windir\System32\winevt\Logs -Recurse | Out-File -Append $EventLogFolder\WinEvtLogs.txt",
		"logman -ets query `"EventLog-Application`" | Out-File -Append $EventLogFolder\EventLog-Application.txt",
		"logman -ets query ""EventLog-System"" | Out-File -Append $EventLogFolder\EventLog-System.txt",
		"logman query providers | Out-File -Append $EventLogFolder\QueryProviders.txt",
		"logman query -ets | Out-File -Append $EventLogFolder\QueryETS.txt",
		"wevtutil el | Out-File -Append $EventLogFolder\EnumerateLogs.txt",
		"Get-ChildItem $env:windir\System32\LogFiles\WMI\RtBackup -Recurse | Out-File -Append $EventLogFolder\RTBackup.txt"

	)
	RunCommands "Eventlog" $Commands -ThrowException:$False -ShowMessage:$True

	FwExecWMIQuery -Namespace "root\subscription" -Query "select * from ActiveScriptEventConsumer" | Export-Clixml -Path ($EventLogSubscriptionFolder + "\ActiveScriptEventConsumer.xml")
	FwExecWMIQuery -Namespace "root\subscription" -Query "select * from __eventfilter" | Export-Clixml -Path ($EventLogSubscriptionFolder + "\__eventfilter.xml")
	FwExecWMIQuery -Namespace "root\subscription" -Query "select * from __IntervalTimerInstruction" | Export-Clixml -Path ($EventLogSubscriptionFolder + "\__IntervalTimerInstruction.xml")
	FwExecWMIQuery -Namespace "root\subscription" -Query "select * from __AbsoluteTimerInstruction" | Export-Clixml -Path ($EventLogSubscriptionFolder + "\__AbsoluteTimerInstruction.xml")
	FwExecWMIQuery -Namespace "root\subscription" -Query "select * from __FilterToConsumerBinding" | Export-Clixml -Path ($EventLogSubscriptionFolder + "\__FilterToConsumerBinding.xml")

	If((Get-Service EventLog).Status -eq "Running"){
		$EventLogs = @(
			"System",
			"Application",
			"Microsoft-Windows-Kernel-EventTracing/Admin"
		)
		FwExportEventLog $EventLogs $EventLogFolder
		FwEvtLogDetails "Application" $EventLogFolder
		FwEvtLogDetails "System" $EventLogFolder
		FwEvtLogDetails "Security" $EventLogFolder
		FwEvtLogDetails "HardwareEvents" $EventLogFolder
		FwEvtLogDetails "Internet Explorer" $EventLogFolder
		FwEvtLogDetails "Key Management Service" $EventLogFolder
		FwEvtLogDetails "Windows PowerShell" $EventLogFolder
	}Else{
		$Commands =@(
			"Copy-Item C:\Windows\System32\winevt\Logs\Application.evtx $EventLogFolder\$env:computername-Application.evtx"
			"Copy-Item C:\Windows\System32\winevt\Logs\System.evtx $EventLogFolder\$env:computername-System.evtx"
		)
		RunCommands "Eventlog" $Commands -ThrowException:$False -ShowMessage:$True
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_EvtLog{
	# using external script
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling Evt-Collect.ps1"
	.\scripts\Evt-Collect.ps1 -DataPath $global:LogFolder -AcceptEula
	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done Evt-Collect.ps1"
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_FSLogixLog{
	EnterFunc $MyInvocation.MyCommand.Name
	$FSLogixLogFolder = "$global:LogFolder\FSLogix$global:LogSuffix"
	$LogPrefix = "FSLogix"

	Try{
		FwCreateLogFolder "$FSLogixLogFolder\Logs"
	}Catch{
		LogException "Unable to create $FSLogixLogFolder." $_
		Return
	}

	# Eveng logs
	$EventLogsWithTextFmt = @(
		"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
		"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin",
		"Microsoft-FSLogix-Apps/Admin",
		"Microsoft-FSLogix-Apps/Operational",
		"Microsoft-FSLogix-CloudCache/Admin",
		"Microsoft-FSLogix-CloudCache/Operational",
		"Microsoft-Windows-GroupPolicy/Operational",
		"Microsoft-Windows-User Profile Service/Operational"
	)
	FwExportEventLog $EventLogsWithTextFmt $FSLogixLogFolder

	$EventLogsEvtxOnly = @(
		"Microsoft-Windows-VHDMP-Operational",
		"Microsoft-Windows-SMBClient/Operational",
		"Microsoft-Windows-SMBClient/Connectivity",
		"Microsoft-Windows-SMBClient/Security",
		"Microsoft-Windows-SMBServer/Operational",
		"Microsoft-Windows-SMBServer/Connectivity",
		"Microsoft-Windows-SMBServer/Security"
	)
	FwExportEventLog $EventLogsEvtxOnly $FSLogixLogFolder -NoExportWithText

	# frx
	$frxcmd = "c:\program files\fslogix\apps\frx.exe"
	If(Test-Path $frxcmd){
		# As command path contains space, we need to use '&' operator to run the command
		$Commands = @(
			"& '$frxcmd' version | Out-File -Append -FilePath $FSLogixLogFolder\frx-list.txt",
			"& '$frxcmd' list-redirects | Out-File -Append -FilePath $FSLogixLogFolder\frx-list.txt",
			"& '$frxcmd' list-rules | Out-File -Append -FilePath $FSLogixLogFolder\frx-list.txt"
		)
		RunCommands $LogPrefix $Commands -ShowMessage:$True
	}

	# Log files
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths.add(@("C:\ProgramData\FSLogix\Logs\*", "$FSLogixLogFolder/Logs"))
	FwCopyFiles $SourceDestinationPaths

	# Registry
	$RegKeys = @(
		('HKLM:SOFTWARE\FSLogix', "$FSLogixLogFolder\Reg-SW-FSLogix.txt"),
		('HKLM:SOFTWARE\Policies\FSLogix', "$FSLogixLogFolder\Reg-SW-Policies-FSLogix.txt"),
		('HKLM:SOFTWARE\Microsoft\Windows Defender\Exclusions', "$FSLogixLogFolder\Reg-SW-MS-WinDef-Exclusions.txt"),
		('HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions', "$FSLogixLogFolder\Reg-SW-GPO-MS-WinDef-Exclusions.txt"),
		('HKCU:SOFTWARE\Microsoft\Office', "$FSLogixLogFolder\Reg-SW-MS-Office.txt"),
		('HKCU:Software\Policies\Microsoft\office', "$FSLogixLogFolder\Reg-SW-Policies-MS-Office.txt"),
		('HKCU:SOFTWARE\Microsoft\OneDrive', "$FSLogixLogFolder\Reg-SW-MS-OneDrive.txt"),
		('HKLM:SOFTWARE\Microsoft\OneDrive', "$FSLogixLogFolder\Reg-SW-MS-OneDrive.txt"),
		('HKLM:SOFTWARE\Policies\Microsoft\OneDrive', "$FSLogixLogFolder\Reg-SW-Pol-MS-OneDrive.txt"),
		('HKLM:SOFTWARE\Microsoft\Windows Search', "$FSLogixLogFolder\Reg-SW-MS-WindowsSearch.txt"),
		('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList', "$FSLogixLogFolder\Reg-SW-MS-WinNT-CV-ProfileList.txt"),
		('HKCU:Volatile Environment', "$FSLogixLogFolder\Reg-VolatileEnvironment.txt"),
		('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers', "$FSLogixLogFolder\Reg-SW-MS-Win-CV-Auth-CredProviders.txt")
	)
	FwExportRegistry "FSLogix" $RegKeys
	
	# Below registies have binary data. So exporting them as hive format
	REG SAVE 'HKCU\SOFTWARE\Microsoft\Office' "$FSLogixLogFolder\Reg-SW-MS-Office.hiv" 2>&1 | Out-Null
	REG SAVE 'HKLM\SOFTWARE\Microsoft\Windows Search' "$FSLogixLogFolder\Reg-SW-MS-WindowsSearch.hiv" 2>&1 | Out-Null
	REG SAVE 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' "$FSLogixLogFolder\Reg-SW-MS-WinNT-CV-ProfileList.hiv" 2>&1 | Out-Null

	#Collecting user/profile information
	RunCommands $LogPrefix "Whoami /all 2>&1 | Out-File -Append $FSLogixLogFolder\WhoAmI-all.txt" -ShowMessage:$True

	#Collecting FSLogix group memberships
	$Commands = @()
	if ([ADSI]::Exists("WinNT://localhost/FSLogix ODFC Exclude List")) {
		$Commands += "& net localgroup 'FSLogix ODFC Exclude List' 2>&1 | Out-File -Append -FilePath $FSLogixLogFolder\LocalGroupsMembership.txt"
	} else {
		LogWarnFile "[$LogPrefix] 'FSLogix ODFC Exclude List' group not found."
	}

	if ([ADSI]::Exists("WinNT://localhost/FSLogix ODFC Include List")) {
		$Commands += "net localgroup 'FSLogix ODFC Include List' 2>&1 | Out-File -Append -FilePath $FSLogixLogFolder\LocalGroupsMembership.txt"
	} else {
		LogWarnFile "[$LogPrefix] 'FSLogix ODFC Include List' group not found."
	}

	if ([ADSI]::Exists("WinNT://localhost/FSLogix Profile Exclude List")) {
		$Commands += "net localgroup 'FSLogix Profile Exclude List' 2>&1 | Out-File -Append -FilePath $FSLogixLogFolder\LocalGroupsMembership.txt"
	} else {
		LogWarnFile "[$LogPrefix] 'FSLogix Profile Exclude List' group not found."
	}

	if ([ADSI]::Exists("WinNT://localhost/FSLogix Profile Include List")) {
		$Commands += "net localgroup 'FSLogix Profile Include List' 2>&1 | Out-File -Append -FilePath $FSLogixLogFolder\LocalGroupsMembership.txt"
	} else {
		LogWarnFile "[$LogPrefix] 'FSLogix Profile Include List' group not found."
	}

	If($Commands.count -gt 0){
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$False
	}
}

function UEX_FusionPreStart{
	# Contact Garabier for the Fusion Functions
	EnterFunc $MyInvocation.MyCommand.Name
	FwCreateFolder $global:LogFolder\FusionLogs
	
	$RegistryKey = "HKLM\SOFTWARE\Microsoft\Fusion"
		FwAddRegValue "$RegistryKey" "ForceLog" "REG_DWORD" "0x1"
		FwAddRegValue "$RegistryKey" "LogFailures" "REG_DWORD" "0x1"
		FwAddRegValue "$RegistryKey" "LogResourceBinds" "REG_DWORD" "0x1"
		FwAddRegValue "$RegistryKey" "EnableLog" "REG_DWORD" "0x1"
		FwAddRegValue "$RegistryKey" "LogPath" "REG_SZ" "$global:LogFolder\FusionLogs"
		Write-Host -ForegroundColor cyan "Please close and reopen the executable for which you want to collect Fusion logs."
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectUEX_FusionLog {
	EnterFunc $MyInvocation.MyCommand.Name
	$RegistryKey = "HKLM\SOFTWARE\Microsoft\Fusion"
	"ForceLog","LogFailures","LogResourceBinds","EnableLog","LogPath" | ForEach-Object { FwDeleteRegValue "$RegistryKey" $_ }
	Remove-Item "$global:LogFolder\*_UEX_FusionTrace.etl" -Force
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_LogonLog{
	EnterFunc $MyInvocation.MyCommand.Name
	$LogonLogFolder = "$LogFolder\LogonLog$LogSuffix"
	$LogPrefix = 'Logon'
	Try{
		FwCreateLogFolder $LogonLogFolder
	}Catch{
		LogException  ("Unable to create $LogonLogFolder.") $_
		Return
	}

	$LogonRegistries = @(
		('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication', "$LogonLogFolder\Logon_Reg.txt"),
		('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', "$LogonLogFolder\Winlogon_Reg.txt"),
		('HKLM:SOFTWARE\Microsoft\Windows\AssignedAccessConfiguration', "$LogonLogFolder\AssignedAccess_Reg.txt"),
		('HKLM:SOFTWARE\Microsoft\Windows\AssignedAccessCsp', "$LogonLogFolder\AssignedAccessCsp_Reg.txt"),
		('HKLM:SOFTWARE\Microsoft\Windows Embedded\Shell Launcher', "$LogonLogFolder\ShellLauncher_Reg.txt"),
		('HKLM:SOFTWARE\Microsoft\Provisioning\Diagnostics\ConfigManager\AssignedAccess', "$LogonLogFolder\ConfigManager_AssignedAccess_Reg.txt"),
		('HKLM:SOFTWARE\Microsoft\Windows\EnterpriseResourceManager\AllowedNodePaths\CSP\AssignedAccess', "$LogonLogFolder\CSP_AssignedAccess_Reg.txt"),
		('HKLM:SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc', "$LogonLogFolder\AssignedAccessManagerSvc_Reg.txt")
	)
	FwExportRegistry $LogPrefix $LogonRegistries

	Try{
		Get-AssignedAccess -ErrorAction Stop| Out-File -Append "$LogonLogFolder\Get-AssignedAccess.txt"
		Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-File -Append "$LogonLogFolder\Get-AppxPackage-AllUsers.txt"
		(Get-StartApps -ErrorAction SilentlyContinue).AppId | Out-File -Append "$LogonLogFolder\Get-StartApps.txt"
	}Catch{
		LogException  ("An error happened in Get-AssignedAccess") $_ $fLogFileOnly
	}
	EndFunc $MyInvocation.MyCommand.Name
}

##MDAG
function enableContainer()
{
	$containerList = Invoke-Expression "hcsdiag.exe list"
	$foundValidContainer = $false
	if ($null -ne $containerList){
		$containerListSplit = $containerList.split("`n");
		for($i = 1; $i -lt $containerListSplit.Count; $i++){
			if(($containerListSplit[$i] -match "HVSI" -or $containerListSplit[$i] -match "CmService") -and -not($containerListSplit[$i] -match "SavedAs")){
				$foundValidContainer = $true
				$ValidContainerId = $containerListSplit[$i - 1]
				$containerState = $containerListSplit[$i].split(",").trim()[1]
				break
			}
		}
	}

	if ($foundValidContainer){
		LogInfo "[MDAG] Container is in $containerState state"
		if($containerState -ne "Running"){
			$resumeContainer = "C:\Windows\System32\wdagtool.exe resume $ValidContainerId"
			LogInfo "[MDAG] Running command: $resumeContainer "
			Invoke-Expression $resumeContainer
			LogInfo "[MDAG] $resumeContainer Done"
		}	  
		return $ValidContainerId
	} else{
		LogInfoFile "[MDAG] Error: Can not collect Container trace because container is not setup yet."
		return $null
	}
}
Function UEX_MDAGPreStart{
	EnterFunc $MyInvocation.MyCommand.Name

	#Get Containers List at start
	$GetContainersListCmd = "hcsdiag.exe list"
	Invoke-Expression $GetContainersListCmd | Out-File $global:LogFolder\HcsdiagList_Sart.txt

	#set DisableResetContainer regkey to 1
	$setDisableResetContainer = 'reg.exe add HKLM\Software\Microsoft\HVSI /v DisableResetContainer /t REG_DWORD /d 1 /f'
	Runcommands "MDAG" $setDisableResetContainer -ThrowException:$False -ShowMessage:$True	

	# start container trace
	$SharedFolderInContainer = "C:\SharedFolderInContainer"
	#$containerUser = "NT AUTHORITY\SYSTEM"

	#Get containerId
	$containerId = enableContainer

	if($null -ne $containerId){
		#Share host folder to the container
		$SharedFolderInContainerCmd = "C:\Windows\System32\hcsdiag.exe share $containerId '$global:LogFolder' '$SharedFolderInContainer'"

		LogInfo "[MDAG] Running command: $SharedFolderInContainerCmd"
		Runcommands "MDAG" $SharedFolderInContainerCmd -ThrowException:$False -ShowMessage:$True

		if ($lastexitcode -eq '-2147024809'){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode): Probably already shared before with same query: $SharedFolderInContainerCmd"
		}

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode): $SharedFolderInContainerCmd"
		} else{
			LogInfo "[MDAG] Succeeded: $SharedFolderInContainerCmd"
		}

		#Copy container providers to container
		$copyContainerProvidersFilesCmd = "C:\Windows\System32\hcsdiag.exe write  -user 'NT AUTHORITY\SYSTEM' $containerId '$global:ScriptFolder\Config\ContainerProviders.wprp' c:\programdata\Microsoft\Windows\ContainerProviders_customized.wprp"
		LogInfo "[MDAG] Running command: $copyContainerProvidersFilesCmd "
		Runcommands "MDAG" $copyContainerProvidersFilesCmd -ThrowException:$False -ShowMessage:$True
		
		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode): $copyContainerProvidersFilesCmd"
		} else{
			LogInfo "[MDAG] Succeeded: $copyContainerProvidersFilesCmd"
		}

		#Start container trace
		$startContainerTracecmd = "hcsdiag.exe exec -user 'NT AUTHORITY\SYSTEM' $containerId wpr.exe -start c:\programdata\Microsoft\Windows\ContainerProviders_customized.wprp -instancename ContainerLogger"
		LogInfo "[MDAG] Running command: $startContainerTracecmd "
		Runcommands "MDAG" $startContainerTracecmd -ThrowException:$False -ShowMessage:$True

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode): $startContainerTracecmd"
		} else{
			LogInfo "[MDAG] Succeeded: $startContainerTracecmd "
		}	

		#Start COntainer net trace
		$startContainerTraceNetworkCmd = "hcsdiag.exe exec -user 'NT AUTHORITY\SYSTEM' $containerId netsh.exe trace start overwrite=yes maxSize=64 Capture=yes traceFile=C:\windows\temp\ContainerNetTrace.etl report=disabled"
		LogInfo "[MDAG] Running command: $startContainerTraceNetworkCmd "
		Runcommands "MDAG" $startContainerTraceNetworkCmd -ThrowException:$False -ShowMessage:$True

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode): $startContainerTraceNetworkCmd"
		} else{
			LogInfo "[MDAG] Succeeded: $startContainerTraceNetworkCmd "
		}		
	}

	EndFunc $MyInvocation.MyCommand.Name
}
Function UEX_MDAGPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	
	 ## stop Container trace
	$containerId = enableContainer
	if( $null -ne $containerId){		
		#Stop wpr trace in container
		$stopContainerTraceCmd = "hcsdiag.exe exec -user 'NT AUTHORITY\SYSTEM' $containerId wpr.exe -stop C:\windows\temp\ContainerTrace.etl -instancename ContainerLogger"
		LogInfo "[MDAG] Running command: $stopContainerTraceCmd "
		Runcommands "MDAG" $stopContainerTraceCmd -ThrowException:$False -ShowMessage:$True

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode):  $stopContainerTraceCmd"
		} else{
			LogInfo "[MDAG] Succeeded: $stopContainerTraceCmd "
		}	

		#Get File from container
		$readContainerTraceEtlCmd = "hcsdiag.exe read -user 'NT AUTHORITY\SYSTEM' $containerId C:\windows\temp\ContainerTrace.etl '$global:LogFolder\ContainerTrace.etl'"
		LogInfo "[MDAG] Running command: $readContainerTraceEtlCmd "
		Runcommands "MDAG" $readContainerTraceEtlCmd -ThrowException:$False -ShowMessage:$True

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode):  $readContainerTraceEtlCmd"
		}else{
			LogInfo "[MDAG] Succeeded: $readContainerTraceEtlCmd "
		}
		
		#Stop container Net Trace
		$stopContainerNetTraceCmd = "hcsdiag.exe exec -user 'NT AUTHORITY\SYSTEM' $containerId netsh.exe trace stop"
		LogInfo "[MDAG] Running command: $stopContainerNetTraceCmd "
		Runcommands "MDAG" $stopContainerNetTraceCmd -ThrowException:$False -ShowMessage:$True

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode):  $stopContainerNetTraceCmd"
		} else{
			LogInfo "[MDAG] Succeeded: $stopContainerNetTraceCmd "
		}

		#Get Container Net Trace
		$readContainerNetTraceCmd = "hcsdiag.exe read -user 'NT AUTHORITY\SYSTEM' $containerId C:\windows\temp\ContainerNetTrace.etl '$global:LogFolder\ContainerNetTrace.etl'"
		LogInfo "[MDAG] Running command: $readContainerNetTraceCmd "
		Runcommands "MDAG" $readContainerNetTraceCmd -ThrowException:$False -ShowMessage:$True

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode):  $readContainerNetTraceCmd"
		} else{
			LogInfo "[MDAG] Succeeded: $readContainerNetTraceCmd "
		}

		#Get Ipconfig from the container
		$containerIpconfigCmd = "hcsdiag.exe exec -user 'NT AUTHORITY\SYSTEM' $containerId ipconfig.exe -allcompartments -all 2>&1 > '$global:LogFolder\Container_ipconfig.log'"
		LogInfo "[MDAG] Running command: $containerIpconfigCmd "
		Runcommands "MDAG" $containerIpconfigCmd -ThrowException:$False -ShowMessage:$True

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode):  $containerIpconfigCmd"
		} else{
			LogInfo "[MDAG] Succeeded: $containerIpconfigCmd "
		}

		#Get tasklist flavors from the container
		$containerTaskListconfigCmd = "hcsdiag.exe exec -user 'NT AUTHORITY\SYSTEM' $containerId tasklist 2>&1 > '$global:LogFolder\Container_TaskList.log'"
		LogInfo "[MDAG] Running command: $containerTaskListconfigCmd "
		Runcommands "MDAG" $containerTaskListconfigCmd -ThrowException:$False -ShowMessage:$True

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode):  $containerTaskListconfigCmd"
		} else{
			LogInfo "[MDAG] Succeeded: $containerTaskListconfigCmd "
		}

		$containerTaskListsvcconfigCmd = "hcsdiag.exe exec -user 'NT AUTHORITY\SYSTEM' $containerId tasklist /svc 2>&1 > '$global:LogFolder\Container_TaskListsvc.log'"
		LogInfo "[MDAG] Running command: $containerTaskListsvcconfigCmd "
		Runcommands "MDAG" $containerTaskListsvcconfigCmd -ThrowException:$False -ShowMessage:$True

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode):  $containerTaskListsvcconfigCmd"
		} else{
			LogInfo "[MDAG] Succeeded: $containerTaskListsvcconfigCmd "
		}

		$containerTaskListappsconfigCmd = "hcsdiag.exe exec -user 'NT AUTHORITY\SYSTEM' $containerId tasklist /apps 2>&1 > '$global:LogFolder\Container_TaskListapps.log'"
		LogInfo "[MDAG] Running command: $containerTaskListappsconfigCmd "
		Runcommands "MDAG" $containerTaskListappsconfigCmd -ThrowException:$False -ShowMessage:$True

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode):  $containerTaskListappsconfigCmd"
		} else{
			LogInfo "[MDAG] Succeeded: $containerTaskListappsconfigCmd "
		}

		#Generate System evtx in container
		$containerEvtxSystemCmd = "hcsdiag.exe exec -user 'NT AUTHORITY\SYSTEM' $containerId wevtutil.exe epl System '$env:ProgramData\Microsoft\Diagnosis\container_evtx_system.evtx' /ow:true"
		LogInfo "[MDAG] Running command: $containerEvtxSystemCmd "
		Runcommands "MDAG" $containerEvtxSystemCmd -ThrowException:$False -ShowMessage:$True

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode):  $containerEvtxSystemCmd"
		} else{
			LogInfo "[MDAG] Succeeded: $containerEvtxSystemCmd "
		}

		#Get System evtx from container
		$GetContainerEvtxSystemCmd = "hcsdiag.exe read -user 'NT AUTHORITY\SYSTEM' $containerId '$env:ProgramData\Microsoft\Diagnosis\container_evtx_system.evtx'  '$global:LogFolder\container_evtx_system.evtx'"
		LogInfo "[MDAG] Running command: $GetContainerEvtxSystemCmd "
		Runcommands "MDAG" $GetContainerEvtxSystemCmd -ThrowException:$False -ShowMessage:$True

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode):  $GetContainerEvtxSystemCmd "
		} else{
			LogInfo "[MDAG] Succeeded: $GetContainerEvtxSystemCmd  "
		}

		#Generate Application evtx in container
		$ContainerEvtxApplicationCmd = "hcsdiag.exe exec -user 'NT AUTHORITY\SYSTEM' $containerId wevtutil.exe epl Application '$env:ProgramData\Microsoft\Diagnosis\container_evtx_application.evtx' /ow:true"
		LogInfo "[MDAG] Running command: $ContainerEvtxApplicationCmd "
		Runcommands "MDAG" $ContainerEvtxApplicationCmd -ThrowException:$False -ShowMessage:$True

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode):  $ContainerEvtxApplicationCmd "
		} else{
			LogInfo "[MDAG] Succeeded: $ContainerEvtxApplicationCmd  "
		}

		#Get Application evtx from container
		$GetContainerEvtxApplicationCmd = "hcsdiag.exe read -user 'NT AUTHORITY\SYSTEM' $containerId '$env:ProgramData\Microsoft\Diagnosis\container_evtx_application.evtx'  '$global:LogFolder\container_evtx_application.evtx'"
		LogInfo "[MDAG] Running command: $GetContainerEvtxApplicationCmd "
		Runcommands "MDAG" $GetContainerEvtxApplicationCmd -ThrowException:$False -ShowMessage:$True

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode):  $GetContainerEvtxApplicationCmd "
		} else{
			LogInfo "[MDAG] Succeeded: $GetContainerEvtxApplicationCmd  "
		}

		#Generate AppXDeploymentServer evtx in container
		$ContainerEvtxAppXDeploymentServerCmd = "hcsdiag.exe exec -user 'NT AUTHORITY\SYSTEM' $containerId wevtutil.exe epl Microsoft-Windows-AppXDeploymentServer/Operational '$env:ProgramData\Microsoft\Diagnosis\container_evtx_AppXDeploymentServer.evtx' /ow:true"
		LogInfo "[MDAG] Running command: $ContainerEvtxAppXDeploymentServerCmd "
		Runcommands "MDAG" $ContainerEvtxAppXDeploymentServerCmd -ThrowException:$False -ShowMessage:$True

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode):  $ContainerEvtxAppXDeploymentServerCmd "
		} else{
			LogInfo "[MDAG] Succeeded: $ContainerEvtxAppXDeploymentServerCmd  "
		}

		#Get AppXDeploymentServer evtx from container
		$GetContainerEvtxAppXDeploymentServerCmd = "hcsdiag.exe read -user 'NT AUTHORITY\SYSTEM' $containerId '$env:ProgramData\Microsoft\Diagnosis\container_evtx_AppXDeploymentServer.evtx'  '$global:LogFolder\container_evtx_AppXDeploymentServer.evtx'"
		LogInfo "[MDAG] Running command: $GetContainerEvtxAppXDeploymentServerCmd "	
		Runcommands "MDAG" $GetContainerEvtxAppXDeploymentServerCmd -ThrowException:$False -ShowMessage:$True
		
		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode):  $GetContainerEvtxAppXDeploymentServerCmd "
		} else{
			LogInfo "[MDAG] Succeeded: $GetContainerEvtxAppXDeploymentServerCmd  "
		}

		#Generate CodeIntegrity evtx in container
		$ContainerEvtxCodeIntegrityCmd= "hcsdiag.exe exec -user 'NT AUTHORITY\SYSTEM' $containerId wevtutil.exe epl Microsoft-Windows-CodeIntegrity/Operational '$env:ProgramData\Microsoft\Diagnosis\container_evtx_CodeIntegrity.evtx' /ow:true"
		LogInfo "[MDAG] Running command: $ContainerEvtxCodeIntegrityCmd "
		Runcommands "MDAG" $ContainerEvtxCodeIntegrityCmd -ThrowException:$False -ShowMessage:$True

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode):  $ContainerEvtxCodeIntegrityCmd "
		} else{
			LogInfo "[MDAG] Succeeded: $ContainerEvtxCodeIntegrityCmd  "
		}
		
		#Get CodeIntegrity evtx from container
		$GetContainerEvtxCodeIntegrityCmd= "hcsdiag.exe read -user 'NT AUTHORITY\SYSTEM' $containerId '$env:ProgramData\Microsoft\Diagnosis\container_evtx_CodeIntegrity.evtx'  '$global:LogFolder\container_evtx_CodeIntegrity.evtx'"
		LogInfo "[MDAG] Running command: $GetContainerEvtxCodeIntegrityCmd "
		Runcommands "MDAG" $GetContainerEvtxCodeIntegrityCmd -ThrowException:$False -ShowMessage:$True	
		
		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode):  $GetContainerEvtxCodeIntegrityCmd "
		} else{
			LogInfo "[MDAG] Succeeded: $GetContainerEvtxCodeIntegrityCmd  "
		}
		
		<# Failing at the moment on my box...
		#Generate wscollect.cab from container
		$wscollectContainerCmd = "hcsdiag.exe exec -user 'NT AUTHORITY\SYSTEM' $containerId wscollect.exe C:\programdata\Microsoft\Windows\WsCollect.cab"
		LogInfo "[MDAG] Running command: $wscollectContainerCmd "
		Runcommands "MDAG" $wscollectContainer -ThrowException:$False -ShowMessage:$True	

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735'))
		{
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode): $wscollectContainer"
		}
		else
		{
			LogInfo "[MDAG] Succeeded: $wscollectContainer "
		}	
		#>

		#Generate LicensingLogs.cab in container
		$licensingdiagContainerCmd = "hcsdiag.exe exec -user 'NT AUTHORITY\SYSTEM' $containerId licensingdiag.exe /cab C:\programdata\Microsoft\Windows\LicensingLogs.cab /q"
		LogInfo "[MDAG] Running command: $licensingdiagContainerCmd "
		Runcommands "MDAG" $licensingdiagContainerCmd -ThrowException:$False -ShowMessage:$True	

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode): $licensingdiagContainerCmd"
		} else{
			LogInfo "[MDAG] Succeeded: $licensingdiagContainerCmd "
		}

		#Get LicensingLogs.cab from container
		$readContainerlicensingdiagCmd = "hcsdiag.exe read -user 'NT AUTHORITY\SYSTEM' $containerId C:\programdata\Microsoft\Windows\LicensingLogs.cab '$global:LogFolder\LicensingLogs.cab'"
		LogInfo "[MDAG] Running command: $readContainerlicensingdiagCmd "
		Runcommands "MDAG" $readContainerlicensingdiagCmd -ThrowException:$False -ShowMessage:$True

		if(($lastexitcode -ne '0') -and ($lastexitcode -ne '-2147022882') -and ($lastexitcode -ne '-2147024735')){
			LogInfoFile "[MDAG] Failed (Error Code $lastexitcode):  $readContainerlicensingdiagCmd"
		} else{
			LogInfo "[MDAG] Succeeded: $readContainerlicensingdiagCmd "
		}
	}

	#set DisableResetContainer regkey to 1
	$setEnableResetContainer = 'reg.exe add HKLM\Software\Microsoft\HVSI /v DisableResetContainer /t REG_DWORD /d 0 /f'
	Runcommands "MDAG" $setEnableResetContainer -ThrowException:$False -ShowMessage:$True	

	#Get Containers List at stop
	$GetContainersListstopCmd = "hcsdiag.exe list"
	Invoke-Expression $GetContainersListstopCmd | Out-File $global:LogFolder\HcsdiagList_Stop.txt

	EndFunc $MyInvocation.MyCommand.Name
}
Function CollectUEX_MDAGLog{
	EnterFunc $MyInvocation.MyCommand.Name

	# Event log
	($EvtLogsDocker,$EvtLogsWDAG) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	
	# Commands
	$scQueryLog = "$PrefixTime`Service_Query.log"
	$Commands = @(
			"sc.exe query winnat | Out-File -Append $scQueryLog",
			"sc.exe query hns | Out-File -Append $scQueryLog",
			"sc.exe query vfpext | Out-File -Append $scQueryLog",
			"sc.exe query iphlpsvc | Out-File -Append $scQueryLog",
			"sc.exe query vmcompute | Out-File -Append $scQueryLog",
			"sc.exe query dnscache | Out-File -Append $scQueryLog",
			"sc.exe query sharedaccess | Out-File -Append $scQueryLog",
			"sc.exe query BFE | Out-File -Append $scQueryLog",
			"sc.exe query Dhcp | Out-File -Append $scQueryLog",
			"sc.exe query NetSetupSvc | Out-File -Append $scQueryLog",
			"sc.exe query mpssvc | Out-File -Append $scQueryLog",
			"sc.exe query nvagent | Out-File -Append $scQueryLog",
			"sc.exe query nsi | Out-File -Append $scQueryLog",
			"sc.exe query CmService | Out-File -Append $scQueryLog",
			"sc.exe query vmms | Out-File -Append $scQueryLog",
			"sc.exe query hvsics | Out-File -Append $scQueryLog"
	)
	Runcommands "MDAG" $Commands -ThrowException:$False -ShowMessage:$True	

	# Registries
	FwAddRegItem @("MDAG_HKLM_SW_MS_HVSI", "MDAG_HKLM_SW_POL_MS", "MDAG_HKLM_SW_Browsers_LookAside", "MDAG_HKLM_SW_MS_EDP_Policies", "MDAG_HKLM_SW_MS_Enrollments", "MDAG_HKLM_SW_MS_PolicyManager_NetworkIsolation", "MDAG_HKLM_System_CCS_Services", "MDAG_HKLM_System_CCS_Control_GraphicsAndGpu", "MDAG_HKLM_System_CCS_HNS") _Stop_
	#For later
	#FwAddRegItem @("") _Stop_ -noRecursive

	#Get HNS CollectLogs
	$OutDir = $global:LogFolder
	Try{
		Invoke-WebRequest "https://raw.githubusercontent.com/microsoft/SDN/master/Kubernetes/windows/debug/collectlogs.ps1" -Outfile HNS_collectlogs.ps1
		(Get-Content "HNS_collectlogs.ps1").Replace('$outDir = [io.Path]::Combine($ScriptPath, [io.Path]::GetRandomFileName())',"`$outDir = '$OutDir'") | Set-Content "HNS_collectlogs.ps1"
		Start-Process "powershell" -ArgumentList ".\HNS_collectlogs.ps1" -NoNewWindow
	}Catch{
		LogWarn "Failed to run HNS_collectlogs.ps1"
		Continue
	}

	EndFunc $MyInvocation.MyCommand.Name
}

function CollectUEX_MMCLog {
	# Function CollectUEX_MMC : Contact Garabier for any change
  EnterFunc $MyInvocation.MyCommand.Name
	
	# SnapIns
  $outFile = $PrefixTime + "MMC_Snapins.txt"
  LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting SnapIns information"
  Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\MMC\SnapIns > $outFile

 # .NET Files
  $outFile = $PrefixTime + "MMC_DotNetFiles.txt"
  LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting .NET files information"
  Get-ChildItem -Path C:\Windows\Microsoft.NET -Recurse | Select * > $outFile

 # .NET Versions installed
  $outFile = $PrefixTime + "MMC_DotNetVersions.txt"
  LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting .NET Version installation information"
  Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" > $outFile
}

function CollectUEX_PowerShellLog {
	#Contact Garabir for the Powershell Collect
  EnterFunc $MyInvocation.MyCommand.Name
  ($global:EvtLogsPowerShell) | ForEach-Object { FwAddEvtLog $_ _Stop_}

  # Get installed Modules
  $outFile = $PrefixTime + "Powershell_InstalledModules.txt"
  LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting installed modules information"
  get-installedmodule | Select-Object Name,Version,InstalledDate,PublishedDate,InstalledLocation,RepositorySourceLocation,Repository,PackageManagementProvider > $outFile

  # Get Modules
  $outFile = $PrefixTime + "Powershell_Modules.txt"
  LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting modules information"
  get-module | Select-Object Name,Version,RootModule,PowerShellVersion,ClrVersion,AccessMode,ModuleType,RepositorySourceLocation,ModuleBase,Path > $outFile

  # Repositories
  $outFile = $PrefixTime + "Powershell_Repositories.txt"
  LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting repositories information"
  Get-PSRepository | Select-Object * > $outFile

  # PSVersionTable
  $outFile = $PrefixTime + "Powershell_PSVersionTable.txt"
  LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting PSVersionTable"
  $psversiontable > $outFile

  # Variables
  $outFile = $PrefixTime + "Powershell_Variables.txt"
  LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting variables"
  get-variable > $outFile

  # Profile Script
  $outFile = $PrefixTime + "Powershell_ProfileScript.txt"
  LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting Profile Script if existing"
  If (Test-Path $Profile) {get-content $Profile > $outFile}

  # PSDrives
  $outFile = $PrefixTime + "Powershell_PSdrives.txt"
  LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting PSDrives information"
  Get-PSDrive > $outFile

  # PSHost Process Info
  $outFile = $PrefixTime + "Powershell_PSHostProcessInfo.txt"
  LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting PS Process information"
  Get-PSHostProcessInfo > $outFile

  # Provider
  $outFile = $PrefixTime + "Powershell_Provider.txt"
  LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting Providers information"
  Get-PSProvider > $outFile

  # Execution Context
  $outFile = $PrefixTime + "Powershell_ExecutionContext.txt"
  LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting Execution Context"
  Write-Output "Host" > $outFile
  $ExecutionContext.Host >> $outFile
  Write-Output "" >> $outFile
  Write-Output "Events" >> $outFile
  $ExecutionContext.Events >> $outFile
  Write-Output "" >> $outFile
  Write-Output "InvokeProvider" >> $outFile
  $ExecutionContext.InvokeProvider >> $outFile
  Write-Output "" >> $outFile
  Write-Output "SessionState" >> $outFile
  $ExecutionContext.SessionState >> $outFile
  Write-Output "" >> $outFile
  Write-Output "InvokeCommand" >> $outFile
  $ExecutionContext.InvokeCommand >> $outFile

  # Powershell Configuration
  $outFile = $PrefixTime + "Powershell_Configuration.json"
  LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting Powershell Config"
  If (Test-Path $PSHOME\powershell.config.json) {Get-Content $PSHOME\powershell.config.json > $outFile}
  
  # Execution Policy
  $outFile = $PrefixTime + "Powershell_ExecutionPolicy.txt"
  LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting Powershell Execution Policy"
  Get-ExecutionPolicy -List > $outFile

  # Powershell Commands
  $outFile = $PrefixTime + "Powershell_Commands.txt"
  LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting all Powershell commands"
  Get-Command > $outFile
  
  EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_PrintPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		FwSetEventLog 'Microsoft-Windows-PrintService/Admin'
		FwSetEventLog 'Microsoft-Windows-PrintService/Operational'
		FwSetEventLog 'Microsoft-Windows-PrintService/Debug'
	}Catch{
		$ErrorMessage = 'An exception happened in FwSetEventLog'
		LogException $ErrorMessage $_ $fLogFileOnly
		Throw ($ErrorMessage)
	}

	LogInfo " .. collecting BuildLab Registry settings"
	$RegKeys = @(
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'BuildLab', "$global:PrefixCn`Reg_BuildInfo.txt"),
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'BuildLabEx', "$global:PrefixCn`Reg_BuildInfo.txt"),
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'EditionId', "$global:PrefixCn`Reg_BuildInfo.txt"),
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'InstallationType', "$global:PrefixCn`Reg_BuildInfo.txt"),
		('HKLM:Software\Microsoft\SQMClient', 'MachineId', "$global:PrefixCn`Reg_BuildInfo.txt"),
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'UBR', "$global:PrefixCn`Reg_BuildInfo.txt"),
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'ProductName', "$global:PrefixCn`Reg_BuildInfo.txt"),
		('HKLM:Software\Microsoft\Windows\CurrentVersion\AppModel', 'Version', "$global:PrefixCn`Reg_BuildInfo.txt"),
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion\Print\PrinterExtensionAssociations', "$global:PrefixCn`Reg_BuildInfo.txt")
	)
	FwExportRegistry "BuildInfo" $RegKeys -ShowMessage:$False
	$outFile = $PrefixTime + "Printerdriver_Start_.txt"
	$Commands = @(
		"REG QUERY `"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\PrinterExtensionAssociations`" /s | Out-File -Append $outFile"
		"get-printer -full |fl; get-printerdriver |fl | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_PrintPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $True
	Try{
		FwResetEventLog 'Microsoft-Windows-PrintService/Admin'
		FwResetEventLog 'Microsoft-Windows-PrintService/Operational'
		FwResetEventLog 'Microsoft-Windows-PrintService/Debug'
	}Catch{
		$ErrorMessage = 'An exception happened in FwResetEventLog'
		LogException $ErrorMessage $_ $fLogFileOnly
		Throw ($ErrorMessage)
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_PrintLog{
	EnterFunc $MyInvocation.MyCommand.Name
	$PrintLogFolder = "$LogFolder\PrintLog$global:LogSuffix"
	$PrintLogDumpFolder = "$PrintLogFolder\Process dump"
	$PrintLogInfFolder = "$PrintLogFolder\inf"
	$PrintLogPrefixCn = "$PrintLogFolder\$Env:Computername" + "_"
	Try{
		FwCreateLogFolder $PrintLogFolder
		FwCreateLogFolder $PrintLogDumpFolder
		FwCreateLogFolder $PrintLogInfFolder
	}Catch{
		LogException ("Unable to create $PrintLogFolder.") $_
		Return
	}

	# Event log
	$EventLogs = @(
		"System",
		"Application",
		"Microsoft-Windows-DeviceSetupManager/Admin",
		"Microsoft-Windows-DeviceSetupManager/Operational",
		"Microsoft-Windows-PrintService/Admin",
		"Microsoft-Windows-PrintService/Operational"
		"Microsoft-Windows-PrintBRM/Admin"  # From NET_PrintSvc
	)
	FwExportEventLog $EventLogs $PrintLogFolder

	# File version
	LogInfo ("[Printing] Getting file version of printing modules")
	FwFileVersion -FilePath "$env:windir\System32\localspl.dll" | Out-File -Append "$($PrintLogPrefixCn)FilesVersion.csv"
	FwFileVersion -FilePath "$env:windir\system32\spoolsv.exe" | Out-File -Append "$($PrintLogPrefixCn)FilesVersion.csv"
	FwFileVersion -FilePath "$env:windir\system32\win32spl.dll" | Out-File -Append "$($PrintLogPrefixCn)FilesVersion.csv"
	FwFileVersion -FilePath "$env:windir\system32\spoolss.dll" | Out-File -Append "$($PrintLogPrefixCn)FilesVersion.csv"
	FwFileVersion -FilePath "$env:windir\system32\PrintIsolationProxy.dll" | Out-File -Append "$($PrintLogPrefixCn)FilesVersion.csv"
	FwFileVersion -FilePath "$env:windir\system32\winspool.drv" | Out-File -Append "$($PrintLogPrefixCn)FilesVersion.csv"

	# Other commands
	$Commands = @(
		"reg export `'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Providers\Client Side Rendering Print Provider`' $($PrintLogPrefixCn)reg-HKLM-Csr.txt",
		"reg query `'HKCU\Printers`' /s | Out-File $($PrintLogPrefixCn)reg-HKCU-Printers.txt",
		"reg query `'HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`' /s | Out-File $($PrintLogPrefixCn)reg-HKCU-Windows.txt",
		"reg query `'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print`' /s | Out-File $($PrintLogPrefixCn)reg-HKLM-Software-Print.txt",
		"reg query `'HKLM\SYSTEM\CurrentControlSet\Control\Print`' /s | Out-File $($PrintLogPrefixCn)reg-HKLM-System-Print.txt",
		"reg query `'HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses`' /s | Out-File $($PrintLogPrefixCn)reg-HKLM-System-DeviceClasses.txt",
		"reg query `'HKLM\SYSTEM\CurrentControlSet\Control\DeviceContainers`' /s | Out-File $($PrintLogPrefixCn)reg-HKLM-System-DeviceContainers.txt",
		"reg query `'HKLM\SYSTEM\CurrentControlSet\Enum\SWD`' /s | Out-File $($PrintLogPrefixCn)reg-HKLM-System-SWD.txt",
		"reg query `'HKLM\SYSTEM\DriverDatabase`' /s | Out-File $($PrintLogPrefixCn)reg-HKLM-System-DriverDatabase.txt",
		"reg export `'HKEY_CURRENT_USER\Printers\Connections`' $($PrintLogPrefixCn)reg-HKCU-User_Print_connections.reg.txt",
		"sc.exe queryex spooler | Out-File -Append $($PrintLogPrefixCn)Spooler_ServiceConfig.txt",
		"cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\prndrvr.vbs -l | Out-File -Append $($PrintLogPrefixCn)prndrvr_en.txt",
		"cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\prnmngr.vbs -l | Out-File -Append $($PrintLogPrefixCn)prnmngr_en.txt",
		"cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\prnjobs.vbs -l | Out-File -Append $($PrintLogPrefixCn)prnjobs_en.txt",
		"cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\prnport.vbs -l | Out-File -Append $($PrintLogPrefixCn)prnport_en.txt",
		"cscript C:\Windows\System32\Printing_Admin_Scripts\ja-JP\prndrvr.vbs -l | Out-File -Append $($PrintLogPrefixCn)prndrvr_ja.txt",
		"cscript C:\Windows\System32\Printing_Admin_Scripts\ja-JP\prnmngr.vbs -l | Out-File -Append $($PrintLogPrefixCn)prnmngr_ja.txt",
		"cscript C:\Windows\System32\Printing_Admin_Scripts\ja-JP\prnjobs.vbs -l | Out-File -Append $($PrintLogPrefixCn)prnjobs_ja.txt",
		"cscript C:\Windows\System32\Printing_Admin_Scripts\ja-JP\prnport.vbs -l | Out-File -Append $($PrintLogPrefixCn)prnport_ja.txt",
		"tree C:\Windows\Inf /f | Out-File -Append $($PrintLogPrefixCn)tree_inf.txt",
		"tree C:\Windows\System32\DriverStore /f | Out-File -Append $($PrintLogPrefixCn)tree_DriverStore.txt",
		"tree C:\Windows\System32\spool /f | Out-File -Append $($PrintLogPrefixCn)tree_spool.txt",
		"Copy-Item `"C:\Windows\Inf\oem*.inf`" $PrintLogInfFolder",
		"pnputil /export-pnpstate $($PrintLogPrefixCn)pnputil_pnpstate.pnp",
		"pnputil -e | Out-File -Append $($PrintLogPrefixCn)pnputil_e.txt",
		"reg query `"HKLM\DRIVERS\DriverDatabase`" /s | Out-File $($PrintLogPrefixCn)reg-HKLM-Drivers-DriverDatabase.txt"
	)
	RunCommands "Printing" $Commands -ThrowException:$False -ShowMessage:$True

	# Process dump
	FwCaptureUserDump "spoolsv" $PrintLogDumpFolder -IsService:$False
	FwCaptureUserDump "splwow64" $PrintLogDumpFolder -IsService:$False
	FwCaptureUserDump "PrintIsolationHost" $PrintLogDumpFolder -IsService:$False

	# From NET_PrintSvc
	$outFile = $PrefixTime + "Printerdriver_Stop_.txt"
	$Commands = @(
	"get-printer -full |fl; get-printerdriver |fl | Out-File -Append $outFile"
	"REG QUERY `"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\PrinterExtensionAssociations`" /s | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. Copy WiaTrace"
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths.add(@("$Env:windir\debug\WIA\wiatrace.log", "$($PrintLogPrefixCn)wiatrace.log"))
	FwCopyFiles $SourceDestinationPaths -ShowMessage:$False
	LogInfo " .. collecting inf\setupapi*.log"
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. Copy upgrade logs"
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(
		@("$Env:windir\inf\setupapi.app.log", "$($PrintLogPrefixCn)setupapi.app.log"),
		@("$Env:windir\inf\setupapi.dev.log", "$($PrintLogPrefixCn)setupapi.dev.log"),
		@("$Env:windir\inf\setupapi.offline.log", "$($PrintLogPrefixCn)setupapi.offline.log"),
		@("$Env:windir\inf\setupapi.setup.log", "$($PrintLogPrefixCn)setupapi.setup.log"),
		@("$Env:windir\inf\setupapi.upgrade.log", "$($PrintLogPrefixCn)setupapi.upgrade.log")
	)
	FwCopyFiles $SourceDestinationPaths -ShowMessage:$False
	# Note: This will not be collected in case of -Collectlog
	FwAddRegItem @("Print") _Stop_ # Registries will be saved in XXX_Reg_Print_Stop_.txt in $global:LogFolder.
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_PrintExLog{
	# invokes external script until fully integrated into TSSv2
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling Print-Collect.ps1"
	.\scripts\Print-Collect.ps1 -DataPath $global:LogFolder -AcceptEula
	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done Print-Collect.ps1"
	EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_RDSPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMS /t REG_DWORD /v EnableDeploymentUILog /d 1 /f | Out-Null
	reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMS  /t REG_DWORD /v EnableUILog /d 1 /f | Out-Null
	EndFunc $MyInvocation.MyCommand.Name
}
Function UEX_RDSPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	If(Test-Path -Path "C:\Windows\Logs\RDMSDeploymentUI.txt"){
		LogInfo ('[RDS] Copying RDMS-Deplyment log')
		Copy-Item "C:\Windows\Logs\RDMSDeploymentUI.txt" $LogFolder -Force -ErrorAction SilentlyContinue
	}
	If(Test-Path -Path "$env:temp\RdmsUI-trace.log"){
		LogInfo ('[RDS] Copying RDMS-UI log')
		Copy-Item "$env:temp\RdmsUI-trace.log" $LogFolder -Force -ErrorAction SilentlyContinue
	}
	reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMS /F | Out-Null
	EndFunc $MyInvocation.MyCommand.Name
}
Function CollectUEX_RDSLog{
	EnterFunc $MyInvocation.MyCommand.Name
	$RDSLogFolder = "$LogFolder\RDSLog$LogSuffix"
	Try{
		FwCreateLogFolder $RDSLogFolder
	}Catch{
		LogException  ("Unable to create $RDSLogFolder.") $_
		Return
	}
	# For future use
	#$RDSobject = Get-CimInstance -Class Win32_TerminalServiceSetting -Namespace root\cimv2\TerminalServices -ErrorAction SilentlyContinue
	#$RDSGateWay = Get-CimInstance -Class Win32_TSGatewayServer -Namespace root\cimv2\TerminalServices -ErrorAction SilentlyContinue
	#$RDSCB = Get-CimInstance -Class Win32_SessionDirectoryServer -Namespace root\cimv2 -ErrorAction SilentlyContinue
	#$RDSLS = Get-CimInstance -Class Win32_TSLicenseServer -Namespace root\cimv2 -ErrorAction SilentlyContinue

	# Event log
	$RDSEventLogs = Get-WinEvent -ListLog "*TerminalServices*" -ErrorAction SilentlyContinue
	$RDSEventLogs += Get-WinEvent -ListLog "*RemoteApp*" -ErrorAction SilentlyContinue
	$RDSEventLogs += Get-WinEvent -ListLog "*RemoteDesktop*" -ErrorAction SilentlyContinue
	$RDSEventLogs += Get-WinEvent -ListLog "*Rdms*" -ErrorAction SilentlyContinue
	$RDSEventLogs += Get-WinEvent -ListLog "*Hyper-V-Guest-Drivers*" -ErrorAction SilentlyContinue
	$EventLogs = @()
	ForEach($RDSEventLog in $RDSEventLogs){
		$EventLogs += $RDSEventLog.LogName
	}
	FwExportEventLog $EventLogs $RDSLogFolder

	# Registries
	$RDSRegistries = @(
		("HKCU:Software\Microsoft\Terminal Server Client", "$RDSLogFolder\Reg-HKCU-Terminal_Server_Client.txt"),
		("HKLM:Software\Microsoft\Terminal Server Client", "$RDSLogFolder\Reg-HKLM-Terminal_Server_Client.txt"),
		("HKLM:SOFTWARE\Policies\Microsoft\SystemCertificates", "$RDSLogFolder\Reg-HKLM-SystemCertificates.txt"),
		("HKLM:SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings", "$RDSLogFolder\Reg-HKLM-Internet_Settings.txt"),
		("HKLM:SYSTEM\CurrentControlSet\Control\Keyboard Layouts", "$RDSLogFolder\Reg-HKLM-Keyboard_Layouts.txt"),
		("HKLM:SYSTEM\CurrentControlSet\Services\i8042prt", "$RDSLogFolder\Reg-HKLM-i8042prt.txt"),
		("HKLM:SYSTEM\CurrentControlSet\Control\terminal Server", "$RDSLogFolder\Reg-HKLM-terminal_Server.txt"),
		("HKLM:Softwar\Microsoft\Windows NT\CurrentVersion\TerminalServerGateway", "$RDSLogFolder\Reg-HKLM-TerminalServerGateway.txt"),
		("HKCU:Software\Microsoft\Terminal Server Gateway", "$RDSLogFolder\Reg-HKCU-Terminal_Server_Gateway.txt"),
		("HKLM:Software\Policies\Microsoft\Windows NT\Terminal Services", "$RDSLogFolder\Reg-HKLM-Terminal_Services.txt"),
		("HKCU:Software\Policies\Microsoft\Windows NT\Terminal Services", "$RDSLogFolder\Reg-HKCU-Terminal_Services.txt"),
		("HKLM:SOFTWARE\Microsoft\MSLicensing", "$RDSLogFolder\Reg-HKLM-MSLicensing.txt")
	)
	FwExportRegistry "RDS" $RDSRegistries

	# Commands
	$Commands = @(
		"certutil -store `"Remote Desktop`" | Out-File -Append $RDSLogFolder\RDPcert.txt",
		"qwinsta  | Out-File -Append $RDSLogFolder\qwinsta.txt"
	)
	Runcommands "RDS" $Commands -ThrowException:$False -ShowMessage:$True

	# !!! Below section only work on RDCB !!!
	# Get Servers of the farm:
	Try{
		$RDDeploymentServer = Get-RDServer -ErrorAction Stop
	}Catch{
		LogInfo ("[RDS] This system would not be RD Conection Broker and skipping collecting data for RD deployment.")
		Return
	}

	LogInfo ("[RDS] Getting RD deployment info. This may take a while.")
	$LogFile = "$RDSLogFolder\RDDeployment-info.txt"
	$BrokerServers = @()
	$WebAccessServers = @()
	$RDSHostServers = @()
	$GatewayServers = @()

	ForEach($Server in $RDDeploymentServer){
		Switch($Server.Roles){
			"RDS-CONNECTION-BROKER" {$BrokerServers += $Server.Server}
			"RDS-WEB-ACCESS" {$WebAccessServers += $Server.Server}
			"RDS-RD-SERVER" {$RDSHostServers += $Server.Server}
			"RDS-GATEWAY" {$GatewayServers += $Server.Server}
		}
	}
	Write-Output ("Machines involved in the deployment : " + $servers.Count) | Out-File -Append $LogFile
	Write-Output ("	-Broker(s) : " + $BrokerServers.Count) | Out-File -Append $LogFile

	ForEach($BrokerServer in $BrokerServers){
		$ServicesStatus = Get-CimInstance -ComputerName $BrokerServer -Query "Select * from Win32_Service where Name='rdms' or Name='tssdis' or Name='tscpubrpc'"
		ForEach ($stat in $ServicesStatus){
			Write-Output ("			  - " + $stat.Name + " service is " + $stat.State) | Out-File -Append $LogFile
		}
	}

	Write-Output ("`n	-RDS Host(s) : " + $RDSHostServers.Count) | Out-File -Append $LogFile
	ForEach($RDSHostServer in $RDSHostServers){
		Write-Output ("		" +	$RDSHostServer) | Out-File -Append $LogFile
		$ServicesStatus = Get-CimInstance -ComputerName $RDSHostServer -Query "Select * from Win32_Service where Name='TermService'"
		ForEach($stat in $ServicesStatus){
			Write-Output ("			  - " + $stat.Name +  "service is " + $stat.State) | Out-File -Append $LogFile
		}
	}

	Write-Output ("`n	-Web Access Server(s) : " + $WebAccessServers.Count) | Out-File -Append $LogFile
	ForEach($WebAccessServer in $WebAccessServers){
		Write-Output ("		" +	$WebAccessServer) | Out-File -Append $LogFile
	}

	Write-Output ("`n	-Gateway server(s) : " + $GatewayServers.Count) | Out-File -Append $LogFile
	ForEach($GatewayServer in $GatewayServers){
		Write-Output ("		" +	$GatewayServer) | Out-File -Append $LogFile
		$ServicesStatus = Get-CimInstance -ComputerName $GatewayServer -Query "Select * from Win32_Service where Name='TSGateway'"
		ForEach($stat in $ServicesStatus){
			Write-Output ("			  - " + $stat.Name + " service is " + $stat.State) | Out-File -Append $LogFile
		}
	}

	#Get active broker server.
	$ActiveBroker = Invoke-WmiMethod -Path ROOT\cimv2\rdms:Win32_RDMSEnvironment -Name GetActiveServer
	$ConnectionBroker = $ActiveBroker.ServerName
	Write-Output ("`nActiveManagementServer (broker) : " +	$ActiveBroker.ServerName) | Out-File -Append $LogFile

	# Deployment Properties
	Write-Output ("`nDeployment details : ") | Out-File -Append $LogFile
	# Is Broker configured in High Availability?
	$HighAvailabilityBroker = Get-RDConnectionBrokerHighAvailability
	$BoolHighAvail = $false
	If($null -eq $HighAvailabilityBroker)
	{
		$BoolHighAvail = $false
		Write-Output ("	Is Connection Broker configured for High Availability : " + $BoolHighAvail) | Out-File -Append $LogFile
	}Else{
		$BoolHighAvail = $true
		Write-Output ("	Is Connection Broker configured for High Availability : " + $BoolHighAvail) | Out-File -Append $LogFile
		Write-Output ("		- Client Access Name (Round Robin DNS) : " + $HighAvailabilityBroker.ClientAccessName) | Out-File -Append $LogFile
		Write-Output ("		- DatabaseConnectionString : " + $HighAvailabilityBroker.DatabaseConnectionString) | Out-File -Append $LogFile
		Write-Output ("		- DatabaseSecondaryConnectionString : " + $HighAvailabilityBroker.DatabaseSecondaryConnectionString) | Out-File -Append $LogFile
		Write-Output ("		- DatabaseFilePath : " + $HighAvailabilityBroker.DatabaseFilePath) | Out-File -Append $LogFile
	}
	
	#Gateway Configuration
	$GatewayConfig = Get-RDDeploymentGatewayConfiguration -ConnectionBroker $ConnectionBroker
	Write-Output ("`n	Gateway Mode : " + $GatewayConfig.GatewayMode) | Out-File -Append $LogFile
	If($GatewayConfig.GatewayMode -eq "custom"){
		Write-Output ("		- LogonMethod : " + $GatewayConfig.LogonMethod) | Out-File -Append $LogFile
		Write-Output ("		- GatewayExternalFQDN : " + $GatewayConfig.GatewayExternalFQDN) | Out-File -Append $LogFile
		Write-Output ("		- GatewayBypassLocal : " + $GatewayConfig.BypassLocal) | Out-File -Append $LogFile
		Write-Output ("		- GatewayUseCachedCredentials : " + $GatewayConfig.UseCachedCredentials) | Out-File -Append $LogFile
	}
	
	# RD Licencing
	$LicencingConfig = Get-RDLicenseConfiguration -ConnectionBroker $ConnectionBroker
	Write-Output ("`n	Licencing Mode : " + $LicencingConfig.Mode) | Out-File -Append $LogFile
	If($LicencingConfig.Mode -ne "NotConfigured"){
		Write-Output ("		- Licencing Server(s) : " + $LicencingConfig.LicenseServer.Count) | Out-File -Append $LogFile
		foreach ($licserver in $LicencingConfig.LicenseServer)
		{
			Write-Output ("			   - Licencing Server : " + $licserver) | Out-File -Append $LogFile
		}
	}
	# RD Web Access
	Write-Output ("`n	Web Access Server(s) : " + $WebAccessServers.Count) | Out-File -Append $LogFile
	ForEach($WebAccessServer in $WebAccessServers){
		Write-Output ("		 - Name : " + $WebAccessServer) | Out-File -Append $LogFile
		Write-Output ("		 - Url : " + "https://" + $WebAccessServer + "/rdweb") | Out-File -Append $LogFile
	}
	
	# Certificates
	#Get-ChildItem -Path cert:\LocalMachine\my -Recurse | Format-Table -Property DnsNameList, EnhancedKeyUsageList, NotAfter, SendAsTrustedIssuer
	Write-Output ("`n	Certificates ") | Out-File -Append $LogFile
	$certificates = Get-RDCertificate -ConnectionBroker $ConnectionBroker
	ForEach($certificate in $certificates){
	Write-Output ("		- Role : " + $certificate.Role) | Out-File -Append $LogFile
	Write-Output ("			- Level : " + $certificate.Level) | Out-File -Append $LogFile
	Write-Output ("			- Expires on : " + $certificate.ExpiresOn) | Out-File -Append $LogFile
	Write-Output ("			- Issued To : " + $certificate.IssuedTo) | Out-File -Append $LogFile
	Write-Output ("			- Issued By : " + $certificate.IssuedBy) | Out-File -Append $LogFile
	Write-Output ("			- Thumbprint : " + $certificate.Thumbprint) | Out-File -Append $LogFile
	Write-Output ("			- Subject : " + $certificate.Subject) | Out-File -Append $LogFile
	Write-Output ("			- Subject Alternate Name : " + $certificate.SubjectAlternateName) | Out-File -Append $LogFile
	}

	#RDS Collections
	$collectionnames = Get-RDSessionCollection 
	$client = $null
	$connection = $null
	$loadbalancing = $null 
	$Security = $null
	$UserGroup = $null
	$UserProfileDisks = $null

	Write-Output ("`nRDS Collections : ") | Out-File -Append $LogFile
	ForEach($Collection in $collectionnames){
		$CollectionName = $Collection.CollectionName
		Write-Output ("	Collection : " +  $CollectionName) | Out-File -Append $LogFile
		Write-Output ("		Resource Type : " + $Collection.ResourceType) | Out-File -Append $LogFile
		If($Collection.ResourceType -eq "RemoteApp programs"){
			Write-Output ("			Remote Apps : ")
			$remoteapps = Get-RDRemoteApp -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName
			foreach ($remoteapp in $remoteapps){
				Write-Output ("			- DisplayName : " + $remoteapp.DisplayName) | Out-File -Append $LogFile
				Write-Output ("				- Alias : " + $remoteapp.Alias) | Out-File -Append $LogFile
				Write-Output ("				- FilePath : " + $remoteapp.FilePath) | Out-File -Append $LogFile
				Write-Output ("				- Show In WebAccess : " + $remoteapp.ShowInWebAccess) | Out-File -Append $LogFile
				Write-Output ("				- CommandLineSetting : " + $remoteapp.CommandLineSetting) | Out-File -Append $LogFile
				Write-Output ("				- RequiredCommandLine : " + $remoteapp.RequiredCommandLine) | Out-File -Append $LogFile
				Write-Output ("				- UserGroups : " + $remoteapp.UserGroups) | Out-File -Append $LogFile
			}
		}

		# $rdshServers
		$rdshservers = Get-RDSessionHost -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName
		Write-Output ("`n		Servers in that collection : ") | Out-File -Append $LogFile
		ForEach ($rdshServer in $rdshservers){
			Write-Output ("			- SessionHost : " + $rdshServer.SessionHost) | Out-File -Append $LogFile
			Write-Output ("				- NewConnectionAllowed : " + $rdshServer.NewConnectionAllowed) | Out-File -Append $LogFile
		}
		
		$client = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -Client 
		Write-Output ("		Client Settings : ") | Out-File -Append $LogFile
		Write-Output ("			- MaxRedirectedMonitors : " + $client.MaxRedirectedMonitors) | Out-File -Append $LogFile
		Write-Output ("			- RDEasyPrintDriverEnabled : " + $client.RDEasyPrintDriverEnabled) | Out-File -Append $LogFile
		Write-Output ("			- ClientPrinterRedirected : " + $client.ClientPrinterRedirected) | Out-File -Append $LogFile
		Write-Output ("			- ClientPrinterAsDefault : " + $client.ClientPrinterAsDefault) | Out-File -Append $LogFile
		Write-Output ("			- ClientDeviceRedirectionOptions : " + $client.ClientDeviceRedirectionOptions) | Out-File -Append $LogFile
		
		$connection = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -Connection
		Write-Output ("`n		Connection Settings : ") | Out-File -Append $LogFile
		Write-Output ("			- DisconnectedSessionLimitMin : " + $connection.DisconnectedSessionLimitMin) | Out-File -Append $LogFile
		Write-Output ("			- BrokenConnectionAction : " + $connection.BrokenConnectionAction) | Out-File -Append $LogFile
		Write-Output ("			- TemporaryFoldersDeletedOnExit : " + $connection.TemporaryFoldersDeletedOnExit) | Out-File -Append $LogFile
		Write-Output ("			- AutomaticReconnectionEnabled : " + $connection.AutomaticReconnectionEnabled) | Out-File -Append $LogFile
		Write-Output ("			- ActiveSessionLimitMin : " + $connection.ActiveSessionLimitMin) | Out-File -Append $LogFile
		Write-Output ("			- IdleSessionLimitMin : " + $connection.IdleSessionLimitMin) | Out-File -Append $LogFile
		
		$loadbalancing = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -LoadBalancing
		Write-Output ("`n		Load Balancing Settings : ") | Out-File -Append $LogFile
		ForEach($SessHost in $loadbalancing){
			Write-Output ("			- SessionHost : " + $SessHost.SessionHost) | Out-File -Append $LogFile
			Write-Output ("				- RelativeWeight : " + $SessHost.RelativeWeight) | Out-File -Append $LogFile
			Write-Output ("				- SessionLimit : " + $SessHost.SessionLimit) | Out-File -Append $LogFile
		}
		
		$Security = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -Security
		Write-Output ("`n		Security Settings : ") | Out-File -Append $LogFile
		Write-Output ("			- AuthenticateUsingNLA : " + $Security.AuthenticateUsingNLA) | Out-File -Append $LogFile
		Write-Output ("			- EncryptionLevel : " + $Security.EncryptionLevel) | Out-File -Append $LogFile
		Write-Output ("			- SecurityLayer : " + $Security.SecurityLayer) | Out-File -Append $LogFile
		
		$UserGroup = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -UserGroup 
		Write-Output ("`n		User Group Settings : ") | Out-File -Append $LogFile
		Write-Output ("			- UserGroup  : " + $UserGroup.UserGroup) | Out-File -Append $LogFile
		
		$UserProfileDisks = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -UserProfileDisk
		Write-Output ("		User Profile Disk Settings : ") | Out-File -Append $LogFile
		Write-Output ("			- EnableUserProfileDisk : " + $UserProfileDisks.EnableUserProfileDisk) | Out-File -Append $LogFile
		Write-Output ("			- MaxUserProfileDiskSizeGB : " + $UserProfileDisks.MaxUserProfileDiskSizeGB) | Out-File -Append $LogFile
		Write-Output ("			- DiskPath : " + $UserProfileDisks.DiskPath) | Out-File -Append $LogFile
		Write-Output ("			- ExcludeFilePath : " + $UserProfileDisks.ExcludeFilePath) | Out-File -Append $LogFile
		Write-Output ("			- ExcludeFolderPath : " + $UserProfileDisks.ExcludeFolderPath) | Out-File -Append $LogFile
		Write-Output ("			- IncludeFilePath : " + $UserProfileDisks.IncludeFilePath) | Out-File -Append $LogFile
		Write-Output ("			- IncludeFolderPath : " + $UserProfileDisks.IncludeFolderPath) | Out-File -Append $LogFile
		
		$CustomRdpProperty = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName		
		Write-Output ("`n		Custom Rdp Properties : " + $CustomRdpProperty.CustomRdpProperty) | Out-File -Append $LogFile
		
		$usersConnected = Get-RDUserSession -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName
		Write-Output ("`n		Users connected to this collection : ") | Out-File -Append $LogFile
		Foreach($userconnected in $usersConnected){
			Write-Output ("			User : " + $userConnected.DomainName + "\" + $userConnected.UserName) | Out-File -Append $LogFile
			Write-Output ("				- HostServer : " + $userConnected.HostServer) | Out-File -Append $LogFile
			Write-Output ("				- UnifiedSessionID : " + $userConnected.UnifiedSessionID) | Out-File -Append $LogFile
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_SchedLog{
	EnterFunc $MyInvocation.MyCommand.Name
	$LogPrefix = "Task"
	$TaskLogFolder = "$LogFolder\TaskLog$LogSuffix"
	$TaskLogTaskFolder = "$LogFolder\TaskLog$LogSuffix\Windows-Tasks"
	$TaskLogSystem32Folder = "$LogFolder\TaskLog$LogSuffix\System32-Tasks"
	$TaskLogDumpFolder = "$LogFolder\TaskLog$LogSuffix\Process dump"

	Try{
		FwCreateLogFolder $TaskLogFolder
		FwCreateLogFolder $TaskLogTaskFolder
		FwCreateLogFolder $TaskLogSystem32Folder
		FwCreateLogFolder $TaskLogDumpFolder
	}Catch{
		LogException ("Unable to create $TaskLogFolder.") $_
		Return
	}

	# Eventlogs
	$EventLogs = @(
		"System",
		"Application",
		"Microsoft-Windows-TaskScheduler/Maintenance",
		"Microsoft-Windows-TaskScheduler/Operational"
	)
	FwExportEventLog $EventLogs $TaskLogFolder

	$Commands = @(
		"schtasks.exe /query /xml | Out-File -Append $TaskLogFolder\schtasks_query.xml",
		"schtasks.exe /query /fo CSV /v | Out-File -Append $TaskLogFolder\schtasks_query.csv",
		"schtasks.exe /query /v | Out-File -Append $TaskLogFolder\schtasks_query.txt",
		"powercfg /LIST | Out-File -Append $TaskLogFolder\powercfg_list.txt",
		"powercfg /QUERY SCHEME_CURRENT | Out-File -Append $TaskLogFolder\powercfg_query_scheme_current.txt",
		"powercfg /AVAILABLESLEEPSTATES | Out-File -Append $TaskLogFolder\powercfg_availablesleepstates.txt",
		"powercfg /LASTWAKE | Out-File -Append $TaskLogFolder\powercfg_lastwake.txt",
		"powercfg /WAKETIMERS | Out-File -Append $TaskLogFolder\powercfg_waketimers.txt",
		"reg query `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule`" /s | Out-File $TaskLogFolder\Schedule.reg.txt",
		"sc.exe queryex Schedule | Out-File -Append $TaskLogFolder\ScheduleServiceConfig.txt",
		"sc.exe qc Schedule | Out-File -Append $TaskLogFolder\ScheduleServiceConfig.txt",
		"sc.exe enumdepend Schedule 3000 | Out-File -Append $TaskLogFolder\ScheduleServiceConfig.txt",
		"sc.exe sdshow Schedule | Out-File -Append $TaskLogFolder\ScheduleServiceConfig.txt",
		"Get-ScheduledTask | Out-File -Append $TaskLogFolder\Tasks.txt",
		"Copy-Item C:\Windows\Tasks -Recurse $TaskLogTaskFolder",
		"Copy-Item C:\Windows\System32\Tasks -Recurse $TaskLogSystem32Folder"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

	# Process dump for Schedule service
	FwCaptureUserDump "Schedule" $TaskLogDumpFolder -IsService:$True

	EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_TaskPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		FwSetEventLog 'Microsoft-Windows-TaskScheduler/Operational'
		FwSetEventLog 'Microsoft-Windows-TaskScheduler/Maintenance'
	}Catch{
		$ErrorMessage = 'An exception happened in FwSetEventLog'
		LogException $ErrorMessage $_ $fLogFileOnly
		Throw ($ErrorMessage)
	}
	EndFunc $MyInvocation.MyCommand.Name
}
Function UEX_TaskPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		FwResetEventLog 'Microsoft-Windows-TaskScheduler/Operational'
		FwResetEventLog 'Microsoft-Windows-TaskScheduler/Maintenance'
	}Catch{
		$ErrorMessage = 'An exception happened in FwResetEventLog'
		LogException $ErrorMessage $_ $fLogFileOnly
		Throw ($ErrorMessage)
	}
	EndFunc $MyInvocation.MyCommand.Name
}
Function CollectUEX_TaskLog{
	EnterFunc $MyInvocation.MyCommand.Name
	$LogPrefix = "Task"
	$TaskLogFolder = "$LogFolder\TaskLog$LogSuffix"
	$TaskLogTaskFolder = "$LogFolder\TaskLog$LogSuffix\Windows-Tasks"
	$TaskLogSystem32Folder = "$LogFolder\TaskLog$LogSuffix\System32-Tasks"
	$TaskLogDumpFolder = "$LogFolder\TaskLog$LogSuffix\Process dump"

	Try{
		FwCreateLogFolder $TaskLogFolder
		FwCreateLogFolder $TaskLogTaskFolder
		FwCreateLogFolder $TaskLogSystem32Folder
		FwCreateLogFolder $TaskLogDumpFolder
	}Catch{
		LogException ("Unable to create $TaskLogFolder.") $_
		Return
	}

	# Eventlogs
	$EventLogs = @(
		"System",
		"Application",
		"Microsoft-Windows-TaskScheduler/Maintenance",
		"Microsoft-Windows-TaskScheduler/Operational"
	)
	FwExportEventLog $EventLogs $TaskLogFolder

	$Commands = @(
		"schtasks.exe /query /xml | Out-File -Append $TaskLogFolder\schtasks_query.xml",
		"schtasks.exe /query /fo CSV /v | Out-File -Append $TaskLogFolder\schtasks_query.csv",
		"schtasks.exe /query /v | Out-File -Append $TaskLogFolder\schtasks_query.txt",
		"powercfg /LIST | Out-File -Append $TaskLogFolder\powercfg_list.txt",
		"powercfg /QUERY SCHEME_CURRENT | Out-File -Append $TaskLogFolder\powercfg_query_scheme_current.txt",
		"powercfg /AVAILABLESLEEPSTATES | Out-File -Append $TaskLogFolder\powercfg_availablesleepstates.txt",
		"powercfg /LASTWAKE | Out-File -Append $TaskLogFolder\powercfg_lastwake.txt",
		"powercfg /WAKETIMERS | Out-File -Append $TaskLogFolder\powercfg_waketimers.txt",
		"reg query `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule`" /s | Out-File $TaskLogFolder\Schedule.reg.txt",
		"sc.exe queryex Schedule | Out-File -Append $TaskLogFolder\ScheduleServiceConfig.txt",
		"sc.exe qc Schedule | Out-File -Append $TaskLogFolder\ScheduleServiceConfig.txt",
		"sc.exe enumdepend Schedule 3000 | Out-File -Append $TaskLogFolder\ScheduleServiceConfig.txt",
		"sc.exe sdshow Schedule | Out-File -Append $TaskLogFolder\ScheduleServiceConfig.txt",
		"Get-ScheduledTask | Out-File -Append $TaskLogFolder\Tasks.txt",
		"Copy-Item C:\Windows\Tasks -Recurse $TaskLogTaskFolder",
		"Copy-Item C:\Windows\System32\Tasks -Recurse $TaskLogSystem32Folder"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

	# Process dump for Schedule service
	FwCaptureUserDump "Schedule" $TaskLogDumpFolder -IsService:$True
	EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_TelemetryPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	$RegistryKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser"
	FwAddRegValue "$RegistryKey" "VerboseMode" "REG_DWORD" "0x1"
	FwAddRegValue "$RegistryKey" "TestHooksEnabled" "REG_DWORD" "0x1"
	EndFunc $MyInvocation.MyCommand.Name
}
function UEX_TelemetryPostStart
{
	EnterFunc $MyInvocation.MyCommand.Name
	Stop-Service diagtrack
	LogInfo "[$($MyInvocation.MyCommand.Name)] Stopping Service diagtrack"
	$RegistryKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\currentversion\diagnostics\diagtrack\testhooks"
	FwAddRegValue "$RegistryKey" "ResetEventStore" "REG_DWORD" "0x1"
	Start-Service diagtrack
	LogInfo "[$($MyInvocation.MyCommand.Name)] Starting Service diagtrack"
	FwDeleteRegValue "$RegistryKey" "ResetEventStore"
	#Census
	$CensusRunRegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Census"
	if($(Test-Path $CensusRunRegKey) -eq $false)
	{
	New-Item -Path $CensusRunRegKey -ItemType Key | Out-Null
	}
	# Turn Census FullSync mode on
	LogInfo "[$($MyInvocation.MyCommand.Name)]Setting property: FullSync to value 1 at registry key path $censusRunRegKey to turn on Census FullSync mode"
    $CensusRunRegKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Census"
	FwAddRegValue $CensusRunRegKey 'FullSync' "REG_DWORD" "1"
    $CensusRunRegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Census"
	If ( $(FwGet-RegistryValue -Path $CensusRunRegKey -Value RunCounter) -eq $null)
	{
		FwAddRegValue $CensusRunRegKey "RunCounter" "REG_DWORD" "0"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_TelemetryPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	#AppRaiser : Code posted as is. Need to improve it later on
	LogInfo "[$($MyInvocation.MyCommand.Name)]Start: RunAppraiser"
	LogInfo "[$($MyInvocation.MyCommand.Name)]Attempting to run inventory...This may take a few minutes to complete, please do not cancel the script."
	do
	{
		& CompatTelRunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun ent | out-null
		$appraiserLastExitCode = $LASTEXITCODE
		$appraiserLastExitCodeHex = "{0:X}" -f $appraiserLastExitCode
		if($appraiserLastExitCode -eq 0x80070021)
		{
			LogInfo "[$($MyInvocation.MyCommand.Name)]RunAppraiser needs to run CompatTelRunner.exe, but it is already running. Waiting for 60 seconds before retry."
			If ($NoOfAppraiserRetries -eq 3)
				{
					LogInfo "[$($MyInvocation.MyCommand.Name)]Last attempt."
				}
			Start-Sleep -Seconds 60
			$NoOfAppraiserRetries+=1
		}
		else
		{
			$NoOfAppraiserRetries-=1
		}
	}While(($NoOfAppraiserRetries -gt 0) -and ($NoOfAppraiserRetries -lt 4))

	if ($appraiserLastExitCode -ne 0x0)
	{
		if ($appraiserLastExitCode -lt 0x0)
		{
			LogInfo "[$($MyInvocation.MyCommand.Name)]RunAppraiser failed. CompatTelRunner.exe exited with last error code: 0x$appraiserLastExitCodeHex."
		}
		else
		{
			LogInfo "[$($MyInvocation.MyCommand.Name)]RunAppraiser succeeded with a return code: 0x$appraiserLastExitCodeHex."
		}
	}
	else
	{
		LogInfo "[$($MyInvocation.MyCommand.Name)]Passed: RunAppraiser"
	}
	
	# M365AHandlerLog
	LogInfo "[$($MyInvocation.MyCommand.Name)]Start: CollectM365AHandlerLog"
	Try
	{
		$propertyPath = "HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global"
		if(Test-Path -Path $propertyPath)
		{
			if ((Get-ItemProperty -Path $propertyPath -Name LogDirectory -ErrorAction SilentlyContinue) -eq $null)
			{
				LogInfo "[$($MyInvocation.MyCommand.Name)]Could not find registry key LogDirectory at path HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global"
			}
			else
			{
				Try
				{
			$logDirectoryKeyM365 = Get-ItemProperty -Path $propertyPath -Name LogDirectory
					$logDirectoryM365 = $logDirectoryKeyM365.LogDirectory
					Copy-Item "$logDirectoryM365\M365AHandler.log" -Destination $global:logFolder | Out-Null
					LogInfo "[$($MyInvocation.MyCommand.Name)]Passed: CollectM365AHandlerLog"
			}
			Catch
				{
					LogInfo "[$($MyInvocation.MyCommand.Name)]Error getting logs at registry key LogDirectory at path HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global" "Warning" $null "CollectM365AHandlerLog" $_.Exception.HResult $_.Exception.Message
					return
			}
			}
		}
	}
	Catch
	{
		LogInfo "[$($MyInvocation.MyCommand.Name)]Error getting logs at registry key LogDirectory at path HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global" "Warning" $null "CollectM365AHandlerLog" $_.Exception.HResult $_.Exception.Message
	}

	#DisableAppRaiserVerboseMode 
	LogInfo "[$($MyInvocation.MyCommand.Name)]Start: DisableAppraiserVerboseMode"
    Try
    {
		if (FwTestRegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser" "VerboseMode" )
        {
	    Try
            {
				global:FwDeleteRegValue "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser" "VerboseMode"
	    }
	    Catch
            {
				LogInfo "[$($MyInvocation.MyCommand.Name)]DisableAppraiserVerboseMode failed deleting VerboseMode property at registry key path: $vAppraiserPath. This is not fatal, script will continue." "Warning" $null "DisableAppraiserVerboseMode" $_.Exception.HResult $_.Exception.Message
	    }
        }
        else
        {
			LogInfo "[$($MyInvocation.MyCommand.Name)]Appraiser VerboseMode key already deleted"
        }

        LogInfo "[$($MyInvocation.MyCommand.Name)]Passed: DisableAppraiserVerboseMode"
    }
    Catch
    {
		LogInfo "[$($MyInvocation.MyCommand.Name)]DisableAppraiserVerboseMode failed with unexpected exception. This is not fatal, script will continue." "Warning" $null "DisableAppraiserVerboseMode" $_.Exception.HResult $_.Exception.Message
    }
	#RestartDiagTrack
	LogInfo "[$($MyInvocation.MyCommand.Name)]Start: RestartDiagtrack"
    Try
    {
        & Net stop diagtrack | Out-Null
		FwAddRegValue "HKEY_LOCAL_MACHINE\software\microsoft\windows\currentversion\diagnostics\diagtrack\testhooks" "ResetEventStore" "REG_DWORD" "0x1"
        & Net start diagtrack | Out-Null
		global:FwDeleteRegValue "HKEY_LOCAL_MACHINE\software\microsoft\windows\currentversion\diagnostics\diagtrack\testhooks" "ResetEventStore"
        LogInfo "[$($MyInvocation.MyCommand.Name)]Passed: RestartDiagtrack"
    }    
    Catch
    {
        LogInfo "[$($MyInvocation.MyCommand.Name)]RestartDiagtrack failed to execute - script will continue." "Warning" $null "RestartDiagtrack" $_.Exception.HResult $_.Exception.Message
        return
    }
	EndFunc $MyInvocation.MyCommand.Name
}
Function CollectUEX_TelemetryLog{  
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("AppCompatFlags", "Census", "SQM", "DiagTrack", "PoliciesDataCollection", "DataCollection") _Start_ #Export of useful reg keys
	$outFile = $PrefixTime + "Telemetry_SMSClientVersion.txt"
	LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting SMS Client Version" # Export SCCM Client Version
	FwGet-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client" -Value "SmsClientVersion" > $outFile
	$RegistryKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser"
	"VerboseMode","TestHooksEnabled" | ForEach-Object { FwDeleteRegValue "$RegistryKey" $_ }
	$ConnectivityDiagnosisTool = Join-Path $global:ScriptFolder "BIN\ConnectivityDiagnosis.exe"
	Try {
		& $ConnectivityDiagnosisTool -verbose > "$PrefixTime`_Telemetry_ConnectivityDiagnosis.txt"
	}
	Catch {
		LogError "Error running RunConnectivityDiagnosis"
	}
	# Copy AppCompat Folder
	LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting AppCompatFolder"
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths.add(@("$env:windir\appcompat*", "$global:LogFolder\AppCompat"))
	FwCopyFiles $SourceDestinationPaths

	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_TSchedLog{ # CollectUEX_SchedLog is already defined in TSSv2_UEX_Mgmt.psm1
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling Sched-Collect.ps1"
	.\scripts\Sched-Collect.ps1 -DataPath $global:LogFolder -AcceptEula -Logs
	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done Sched-Collect.ps1"
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_UEVLog{
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		$Status = Get-UevStatus -ErrorAction SilentlyContinue
	}Catch{
		LogInfo ("Get-UevStatus failed. Probably this system does not have UE-V feature.")
		Return
	}
	If($Null -ne $Status -and !$Status.UevEnabled){
		LogMessage $LogLevel.Warning ("UEV is not enabled.")
		Return
	}

	$UEVTasks =@(
		"Monitor Application Settings",
		"Sync Controller Application",
		"Synchronize Settings at Logoff",
		"Template Auto Update"
	)

	$UEVLogFolder = "$LogFolder\UEVLog$LogSuffix"
	Try{
		FwCreateLogFolder $UEVLogFolder
	}Catch{
		LogException  ("Unable to create $UEVLogFolder.") $_
		Return
	}

	Try{
		$RegistryFolder = Join-Path $UEVLogFolder "Registry" 
		New-Item $RegistryFolder -ItemType Directory -ErrorAction Stop | Out-Null
		$SchedulerFolder = Join-Path $UEVLogFolder "TaskScheduler" 
		New-Item $SchedulerFolder -ItemType Directory -ErrorAction Stop | Out-Null
		$TemplateFolder = Join-Path $UEVLogFolder "UEV-Templates" 
		New-Item $TemplateFolder -ItemType Directory -ErrorAction Stop | Out-Null
		$PackageFolder = Join-Path $UEVLogFolder "UEV-Packages" 
		New-Item $PackageFolder -ItemType Directory -ErrorAction Stop | Out-Null
		#$EventLogFolder = Join-Path $UEVLogFolder "EventLogs" 
		#New-Item $EventLogFolder -ItemType Directory | Out-Null
	}Catch{
		LogException ("An exception happened during creation of logfoler") $_
		Return
	}

	LogInfo ("[UEV] Exporting UE-V regstries.")
	reg export "HKLM\SOFTWARE\Microsoft\UEV" (Join-Path $RegistryFolder "UEV.reg") | Out-Null
	reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule" (Join-Path $RegistryFolder "Schedule.reg")| Out-Null
	reg save "HKLM\SYSTEM" (Join-Path $RegistryFolder "SYSTEM.hiv")| Out-Null
	reg save "HKLM\Software" (Join-Path $RegistryFolder "Software.hiv")| Out-Null

	# UEV Tasks
	LogInfo ("[UEV] Exporting UE-V tasks.")
	ForEach($UEVTask in $UEVTasks){
		schtasks /query /xml /tn ("\Microsoft\UE-V\" + $UEVTask) > ($SchedulerFolder + "\" + $UEVTask + ".xml")
	}

	# UEV configuration
	LogInfo ("[UEV] Running UE-V commandlets")
	Get-UEVStatus | Out-File (Join-Path $UEVLogFolder "Get-UevStatus.txt")
	Get-UEVConfiguration | Out-File (Join-Path $UEVLogFolder "Get-UEVConfiguration.txt")
	Get-UEVTemplate  | Out-File (Join-Path $UEVLogFolder "Get-UEVTemplate.txt")

	# UEV template
	LogInfo ("[UEV] Copying all templates to log folder.")
	Copy-Item  ("C:\ProgramData\Microsoft\UEV\Templates\*") $TemplateFolder -Recurse

	# UEV package
	$UEVConfig = Get-UEVConfiguration

	If($UEVConfig.SettingsStoragePath.Length -ne 0){
		$PackagePath = [System.Environment]::ExpandEnvironmentVariables($UEVConfig.SettingsStoragePath + "\SettingsPackages")

		If($PackagePath -ne $Null){
			LogInfo ("[UEV] Found package path: $PackagePath")
			If(Test-Path -Path $PackagePath){
				$PackageFiles = Get-ChildItem $PackagePath "*.pkgx" -Recurse -Depth 5
				If($PackageFiles.Length -ne 0 -and $Null -ne $PackageFiles){
					LogInfo ('[UEV] Copying UE-V packages')
					ForEach($PackageFile in $PackageFiles){
						Copy-Item  $PackageFile.fullname $PackageFolder -Recurse
					}
				}
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function RunUEX_WinRMDiag{
	# to avoid duplicate efforts: see external script WinRM-Collect.ps1
	EnterFunc $MyInvocation.MyCommand.Name
	$WinRMDiagFolder = "$LogFolder\WinRMLog$LogSuffix\Diag"
	$WinRMDiagFile = "$WinRMDiagFolder\WinRM-Diag.txt"
	Try{
		FwCreateLogFolder $WinRMDiagFolder
	}Catch{
		LogMessage ("Unable to create $WMILogFolder.") $_ 
		Return
	}
	LogInfo ("[WinRM] Checking if WinRM is running")
	$WinRMService = Get-Service | Where-Object {$_.Name -eq 'WinRM'}
	If($Null -ne $WinRMService){
		If($WinRMService.Status -eq 'Stopped'){
			LogDebug ('[WinRM] Starting WinRM service as it is not running.')
			Start-Service $WinRMService.Name
		}
		$Service = Get-Service $WinRMService.Name
		$Service.WaitForStatus('Running','00:00:10')
		If($Service.Status -ne 'Running'){
			LogMessage $LogLevel.ErrorLogFileOnly ('[WinRM] Starting WinRM service failed.')
		}
	}
	$Global:tbCert = New-Object system.Data.DataTable
	$col = New-Object system.Data.DataColumn Store,([string]); $tbCert.Columns.Add($col)
	$col = New-Object system.Data.DataColumn Thumbprint,([string]); $tbCert.Columns.Add($col)
	$col = New-Object system.Data.DataColumn Subject,([string]); $tbCert.Columns.Add($col)
	$col = New-Object system.Data.DataColumn Issuer,([string]); $tbCert.Columns.Add($col)
	$col = New-Object system.Data.DataColumn NotAfter,([DateTime]); $tbCert.Columns.Add($col)
	$col = New-Object system.Data.DataColumn IssuerThumbprint,([string]); $tbCert.Columns.Add($col)
	$col = New-Object system.Data.DataColumn EnhancedKeyUsage,([string]); $tbCert.Columns.Add($col)
	$col = New-Object system.Data.DataColumn SerialNumber,([string]); $tbCert.Columns.Add($col)
	$col = New-Object system.Data.DataColumn SubjectKeyIdentifier,([string]); $tbCert.Columns.Add($col)
	$col = New-Object system.Data.DataColumn AuthorityKeyIdentifier,([string]); $tbCert.Columns.Add($col)
	Write-Diag "[INFO] Retrieving certificates from LocalMachine\My store" $WinRMDiagFile
	FwGetCertStore "My"
	Write-Diag "[INFO] Retrieving certificates from LocalMachine\CA store" $WinRMDiagFile
	FwGetCertStore "CA"
	Write-Diag "[INFO] Retrieving certificates from LocalMachine\Root store" $WinRMDiagFile
	FwGetCertStore "Root"
	Write-Diag "[INFO] Matching issuer thumbprints" $WinRMDiagFile
	$aCert = $Global:tbCert.Select("Store = 'My' or Store = 'CA'")
	foreach ($cert in $aCert) {
	  $aIssuer = $Global:tbCert.Select("SubjectKeyIdentifier = '" + ($cert.AuthorityKeyIdentifier).tostring() + "'")
	  if ($aIssuer.Count -gt 0) {
		$cert.IssuerThumbprint = ($aIssuer[0].Thumbprint).ToString()
	  }
	}
	Write-Diag "[INFO] Exporting certificates.tsv" $WinRMDiagFile
	$Global:tbcert | Export-Csv "$WinRMDiagFolder\certificates.tsv" -noType -Delimiter "`t"

	# Diag start
	$OSVer = [environment]::OSVersion.Version.Major + [environment]::OSVersion.Version.Minor * 0.1
	$subDom = $false
	$subWG = $false
	$Subscriptions = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions"
	foreach ($sub in $Subscriptions) {
		Write-Diag ("[INFO] Found subscription " + $sub.PSChildname) $WinRMDiagFile
		$SubProp = ($sub | Get-ItemProperty)
		Write-Diag ("[INFO]   SubscriptionType = " + $SubProp.SubscriptionType + ", ConfigurationMode = " + $SubProp.ConfigurationMode) $WinRMDiagFile
		Write-Diag ("[INFO]   MaxLatencyTime = " + (GetSubVal $sub.PSChildname "MaxLatencyTime") + ", HeartBeatInterval = " + (GetSubVal $sub.PSChildname "HeartBeatInterval")) $WinRMDiagFile
		if ($SubProp.Locale) {
			if ($SubProp.Locale -eq "en-US") {
			  Write-Diag "[INFO]   The subscription's locale is set to en-US" $WinRMDiagFile
			} else {
			  Write-Diag ("[WARNING] The subscription's locale is set to " + $SubProp.Locale) $WinRMDiagFile
			}
		} else {
		   Write-Diag "[INFO]   The subscription's locale is not set, the default locale will be used." $WinRMDiagFile
		}
		if ($SubProp.AllowedSubjects) {
			$subWG = $true
			Write-Diag "[INFO]   Listed non-domain computers:" $WinRMDiagFile
			$list = $SubProp.AllowedSubjects -split ","
			foreach ($item in $list) {
			  Write-Diag ("[INFO]   " + $item) $WinRMDiagFile
			}
		} else {
			Write-Diag "[INFO]   No non-domain computers listed, that's ok if this is not a collector in workgroup environment" $WinRMDiagFile
		}
		if ($SubProp.AllowedIssuerCAs) {
			$subWG = $true
			Write-Diag "[INFO]   Listed Issuer CAs:" $WinRMDiagFile
			$list = $SubProp.AllowedIssuerCAs -split ","
			foreach ($item in $list) {
			  Write-Diag ("[INFO]   " + $item) $WinRMDiagFile
			  ChkCert -cert $item -store "(Store = 'CA' or Store = 'Root')" -descr "Issuer CA" -diagfile $WinRMDiagFile
			}
		} else {
			Write-Diag "[INFO]   No Issuer CAs listed, that's ok if this is not a collector in workgroup environment" $WinRMDiagFile
		}
		$RegKey = (($sub.Name).replace("HKEY_LOCAL_MACHINE\","HKLM:\") + "\EventSources")
		if (Test-Path -Path $RegKey) {
			$sources = Get-ChildItem -Path $RegKey
			if ($sources.Count -gt 4000) {
			  Write-Diag ("[WARNING] There are " + $sources.Count + " sources for this subscription") $WinRMDiagFile
			} else {
			  Write-Diag ("[INFO]   There are " + $sources.Count + " sources for this subscription") $WinRMDiagFile
			}
		} else {
			Write-Diag ("[INFO]   No sources found for the subscription " + $sub.Name) $WinRMDiagFile
		}
	}
	if ($OSVer -gt 6.1) {
	  Write-Diag "[INFO] Retrieving machine's IP addresses" $WinRMDiagFile
	  $iplist = Get-NetIPAddress
	}
	Write-Diag "[INFO] Browsing listeners" $WinRMDiagFile
	$listeners = Get-ChildItem WSMan:\localhost\Listener
	foreach ($listener in $listeners) {
	  Write-Diag ("[INFO] Inspecting listener " + $listener.Name) $WinRMDiagFile
	  $prop = Get-ChildItem $listener.PSPath
	  foreach ($value in $prop) {
		if ($value.Name -eq "CertificateThumbprint") {
		  if ($listener.keys[0].Contains("HTTPS")) {
			Write-Diag "[INFO] Found HTTPS listener" $WinRMDiagFile
			$listenerThumbprint = $value.Value.ToLower()
			Write-Diag "[INFO] Found listener certificate $listenerThumbprint" $WinRMDiagFile
			if ($listenerThumbprint) {
			  ChkCert -cert $listenerThumbprint -descr "listener" -store "Store = 'My'" -diagfile $WinRMDiagFile
			}
		  }
		}
		if ($value.Name.Contains("ListeningOn")) {
		  $ip = ($value.value).ToString()
		  Write-Diag "[INFO] Listening on $ip" $WinRMDiagFile
		  if ($OSVer -gt 6.1) {
			if (($iplist | Where-Object {$_.IPAddress -eq $ip } | measure-object).Count -eq 0 ) {
			  Write-Diag "[ERROR] IP address $ip not found" $WinRMDiagFile
			}
		  }
		}
	  } 
	} 
	$svccert = Get-Item WSMan:\localhost\Service\CertificateThumbprint
	if ($svccert.value ) {
	  Write-Diag ("[INFO] The Service Certificate thumbprint is " + $svccert.value) $WinRMDiagFile
	  ChkCert -cert $svccert.value -descr "Service" -store "Store = 'My'" -diagfile $WinRMDiagFile
	}
	$ipfilter = Get-Item WSMan:\localhost\Service\IPv4Filter
	if ($ipfilter.Value) {
	  if ($ipfilter.Value -eq "*") {
		Write-Diag "[INFO] IPv4Filter = *" $WinRMDiagFile
	  } else {
		Write-Diag ("[WARNING] IPv4Filter = " + $ipfilter.Value) $WinRMDiagFile
	  }
	} else {
	  Write-Diag ("[WARNING] IPv4Filter is empty, WinRM will not listen on IPv4") $WinRMDiagFile
	}
	$ipfilter = Get-Item WSMan:\localhost\Service\IPv6Filter
	if ($ipfilter.Value) {
	  if ($ipfilter.Value -eq "*") {
		Write-Diag "[INFO] IPv6Filter = *" $WinRMDiagFile
	  } else {
		Write-Diag ("[WARNING] IPv6Filter = " + $ipfilter.Value) $WinRMDiagFile
	  }
	} else {
	  Write-Diag ("[WARNING] IPv6Filter is empty, WinRM will not listen on IPv6") $WinRMDiagFile
	}
	if (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager") {
	  $isForwarder = $True
	  $RegKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager')
	  Write-Diag "[INFO] Enumerating SubscriptionManager URLs at HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager" $WinRMDiagFile
	  $RegKey.PSObject.Properties | ForEach-Object {
		If($_.Name -notlike '*PS*'){
		  Write-Diag ("[INFO] " + $_.Name + " " + $_.Value) $WinRMDiagFile
		  $IssuerCA = (FindSep -FindIn $_.Value -Left "IssuerCA=" -Right ",").ToLower()
		  if (-not $IssuerCA) {
			$IssuerCA = (FindSep -FindIn $_.Value -Left "IssuerCA=" -Right "").ToLower()
		  }
		  if ($IssuerCA) {
			if ("0123456789abcdef".Contains($IssuerCA[0])) {
			  Write-Diag ("[INFO] Found issuer CA certificate thumbprint " + $IssuerCA) $WinRMDiagFile
			  $aCert = $tbCert.Select("Thumbprint = '" + $IssuerCA + "' and (Store = 'CA' or Store = 'Root')")
			  if ($aCert.Count -eq 0) {
				Write-Diag "[ERROR] The Issuer CA certificate was not found in CA or Root stores" $WinRMDiagFile
			  } else {
				Write-Diag ("[INFO] Issuer CA certificate found in store " + $aCert[0].Store + ", subject = " + $aCert[0].Subject) $WinRMDiagFile
				if (($aCert[0].NotAfter) -gt (Get-Date)) {
				  Write-Diag ("[INFO] The Issuer CA certificate will expire on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") ) $WinRMDiagFile
				} else {
				  Write-Diag ("[ERROR] The Issuer CA certificate expired on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") ) $WinRMDiagFile
				}
			  }
			  $aCliCert = $tbCert.Select("IssuerThumbprint = '" + $IssuerCA + "' and Store = 'My'")
			  if ($aCliCert.Count -eq 0) {
				Write-Diag "[ERROR] Cannot find any certificate issued by this Issuer CA" $WinRMDiagFile
			  } else {
				if ($PSVersionTable.psversion.ToString() -ge "3.0") {
				  Write-Diag "[INFO] Listing available client certificates from this IssuerCA" $WinRMDiagFile
				  $num = 0
				  foreach ($cert in $aCliCert) {
					if ($cert.EnhancedKeyUsage.Contains("Client Authentication")) {
					  Write-Diag ("[INFO]   Found client certificate " + $cert.Thumbprint + " " + $cert.Subject) $WinRMDiagFile
					  if (($Cert.NotAfter) -gt (Get-Date)) {
						Write-Diag ("[INFO]   The client certificate will expire on " + $cert.NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") ) $WinRMDiagFile
					  } else {
						Write-Diag ("[ERROR]   The client certificate expired on " + $cert.NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") ) $WinRMDiagFile
					  }
					  $certobj = Get-Item ("CERT:\Localmachine\My\" + $cert.Thumbprint)
					  $keypath = [io.path]::combine("$env:ProgramData\microsoft\crypto\rsa\machinekeys", $certobj.privatekey.cspkeycontainerinfo.uniquekeycontainername)
					  if ([io.file]::exists($keypath)) {
						$acl = ((get-acl -path $keypath).Access | Where-Object {$_.IdentityReference -eq "NT AUTHORITY\NETWORK SERVICE"})
						if ($acl) {
						  $rights = $acl.FileSystemRights.ToString()
						  if ($rights.contains("Read") -or $rights.contains("FullControl") ) {
							Write-Diag ("[INFO]   The NETWORK SERVICE account has permissions on the private key of this certificate: " + $rights) $WinRMDiagFile
						  } else {
							Write-Diag ("[ERROR]  Incorrect permissions for the NETWORK SERVICE on the private key of this certificate: " + $rights) $WinRMDiagFile
						  }
						} else {
						  Write-Diag "[ERROR]  Missing permissions for the NETWORK SERVICE account on the private key of this certificate" $WinRMDiagFile
						}
					  } else {
						Write-Diag "[ERROR]  Cannot find the private key" $WinRMDiagFile
					  } 
					  $num++
					}
				  }
				  if ($num -eq 0) {
					Write-Diag "[ERROR] Cannot find any client certificate issued by this Issuer CA" $WinRMDiagFile
				  } elseif ($num -gt 1) {
					Write-Diag "[WARNING] More than one client certificate issued by this Issuer CA, the first certificate will be used by WinRM" $WinRMDiagFile
				  }
				}
			  }
			} else {
			 Write-Diag "[ERROR] Invalid character for the IssuerCA certificate in the SubscriptionManager URL" $WinRMDiagFile
			}
		  }
		} 
	  }
	} else {
	  $isForwarder = $false
	  Write-Diag "[INFO] No SubscriptionManager URL configured. It's ok if this machine is not supposed to forward events." $WinRMDiagFile
	}
	if ((Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain) {
	  $search = New-Object DirectoryServices.DirectorySearcher([ADSI]"GC://$env:USERDNSDOMAIN") # The SPN is searched in the forest connecting to a Global catalog
	  $SPNReg = ""
	  $SPN = "HTTP/" + $env:COMPUTERNAME
	  Write-Diag ("[INFO] Searching for the SPN $SPN") $WinRMDiagFile
	  $search.filter = "(servicePrincipalName=$SPN)"
	  $results = $search.Findall()
	  if ($results.count -gt 0) {
		foreach ($result in $results) {
		  Write-Diag ("[INFO] The SPN HTTP/$env:COMPUTERNAME is registered for DNS name = " + $result.properties.dnshostname + ", DN = " + $result.properties.distinguishedname + ", Category = " + $result.properties.objectcategory) $WinRMDiagFile
		  if ($result.properties.objectcategory[0].Contains("Computer")) {
			if (-not $result.properties.dnshostname[0].Contains($env:COMPUTERNAME)) {
			  Write-Diag ("[ERROR] The The SPN $SPN is registered for different DNS host name: " + $result.properties.dnshostname[0]) $WinRMDiagFile
			  $SPNReg = "OTHER"
			}
		  } else {
			Write-Diag "[ERROR] The The SPN $SPN is NOT registered for a computer account" $WinRMDiagFile
			$SPNReg = "OTHER"
		  }
		}
		if ($results.count -gt 1) {
		  Write-Diag "[ERROR] The The SPN $SPN is duplicate" $WinRMDiagFile
		}
	  } else {
		Write-Diag "[INFO] The The SPN $SPN was not found. That's ok, the SPN HOST/$env:COMPUTERNAME will be used" $WinRMDiagFile
	  }
	  $SPN = "HTTP/" + $env:COMPUTERNAME + ":5985"
	  Write-Diag ("[INFO] Searching for the SPN $SPN") $WinRMDiagFile
	  $search.filter = "(servicePrincipalName=$SPN)"
	  $results = $search.Findall()
	  if ($results.count -gt 0) {
		foreach ($result in $results) {
		  Write-Diag ("[INFO] The SPN HTTP/$env:COMPUTERNAME is registered for DNS name = " + $result.properties.dnshostname + ", DN = " + $result.properties.distinguishedname + ", Category = " + $result.properties.objectcategory) $WinRMDiagFile
		  if ($result.properties.objectcategory[0].Contains("Computer")) {
			if (-not $result.properties.dnshostname[0].Contains($env:COMPUTERNAME)) {
			  Write-Diag ("[ERROR] The The SPN $SPN is registered for different DNS host name: " + $result.properties.dnshostname[0]) $WinRMDiagFile
			}
		  } else {
			Write-Diag "[ERROR] The The SPN $SPN is NOT registered for a computer account" $WinRMDiagFile
		  }
		}
		if ($results.count -gt 1) {
		  Write-Diag "[ERROR] The The SPN $SPN is duplicate" $WinRMDiagFile
		}
	  } else {
		if ($SPNReg -eq "OTHER") {
		  Write-Diag "[WARNING] The The SPN $SPN was not found. It is required to accept WinRM connections since the HTTP/$env:COMPUTERNAME is reqistered to another name" $WinRMDiagFile
		}
	  }
	  Write-Diag "[INFO] Checking the WinRMRemoteWMIUsers__ group" $WinRMDiagFile
	  $search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")  # This is a Domain local group, therefore we need to collect to a non-global catalog
	  $search.filter = "(samaccountname=WinRMRemoteWMIUsers__)"
	  $results = $search.Findall()
	  if ($results.count -gt 0) {
		Write-Diag ("[INFO] Found " + $results.Properties.distinguishedname) $WinRMDiagFile
		if ($results.Properties.grouptype -eq  -2147483644) {
		  Write-Diag "[INFO] WinRMRemoteWMIUsers__ is a Domain local group" $WinRMDiagFile
		} elseif ($results.Properties.grouptype -eq -2147483646) {
		  Write-Diag "[WARNING] WinRMRemoteWMIUsers__ is a Global group" $WinRMDiagFile
		} elseif ($results.Properties.grouptype -eq -2147483640) {
		  Write-Diag "[WARNING] WinRMRemoteWMIUsers__ is a Universal group" $WinRMDiagFile
		}
		if (Get-CimInstance -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
		  Write-Diag "[INFO] The group WinRMRemoteWMIUsers__ is also present as machine local group" $WinRMDiagFile
		}
	  } else {
		Write-Diag "[ERROR] The WinRMRemoteWMIUsers__ was not found in the domain"  $WinRMDiagFile
		if (Get-CimInstance -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
		  Write-Diag "[INFO] The group WinRMRemoteWMIUsers__ is present as machine local group" $WinRMDiagFile
		} else {
		  Write-Diag "[ERROR] The group WinRMRemoteWMIUsers__ is not even present as machine local group" $WinRMDiagFile
		}
	  }
	  if ((Get-ChildItem WSMan:\localhost\Service\Auth\Kerberos).value -eq "true") {
		Write-Diag "[INFO] Kerberos authentication is enabled for the service" $WinRMDiagFile
	  }  else {
		Write-Diag "[WARNING] Kerberos authentication is disabled for the service" $WinRMDiagFile
	  }
	} else {
	  Write-Diag "[INFO] The machine is not joined to a domain" $WinRMDiagFile
	  if (Get-CimInstance -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
		Write-Diag "[INFO] The group WinRMRemoteWMIUsers__ is present as machine local group" $WinRMDiagFile
	  } else {
		Write-Diag "[ERROR] The group WinRMRemoteWMIUsers__ is not present as machine local group" $WinRMDiagFile
	  }
	  if ((Get-ChildItem WSMan:\localhost\Service\Auth\Certificate).value -eq "false") {
		Write-Diag "[WARNING] Certificate authentication is disabled for the service" $WinRMDiagFile
	  }  else {
		Write-Diag "[INFO] Certificate authentication is enabled for the service" $WinRMDiagFile
	  }
	}
	$iplisten = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" | Select-Object -ExpandProperty "ListenOnlyList" -ErrorAction SilentlyContinue)
	if ($iplisten) {
	  Write-Diag ("[WARNING] The IPLISTEN list is not empty, the listed addresses are " + $iplisten) $WinRMDiagFile
	} else {
	  Write-Diag "[INFO] The IPLISTEN list is empty. That's ok: WinRM will listen on all IP addresses" $WinRMDiagFile
	}
	$binval = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name WinHttpSettings).WinHttPSettings			
	$proxylength = $binval[12]			
	if ($proxylength -gt 0) {
	  $proxy = -join ($binval[(12+3+1)..(12+3+1+$proxylength-1)] | ForEach-Object {([char]$_)})			
	  Write-Diag ("[WARNING] A NETSH WINHTTP proxy is configured: " + $proxy) $WinRMDiagFile
	  $bypasslength = $binval[(12+3+1+$proxylength)]			
	  if ($bypasslength -gt 0) {			
		$bypasslist = -join ($binval[(12+3+1+$proxylength+3+1)..(12+3+1+$proxylength+3+1+$bypasslength)] | ForEach-Object {([char]$_)})			
		Write-Diag ("[WARNING] Bypass list: " + $bypasslist) $WinRMDiagFile
	   } else {			
		Write-Diag "[WARNING] No bypass list is configured" $WinRMDiagFile
	  }			
	  Write-Diag "[WARNING] WinRM does not work very well through proxies, make sure that the target machine is in the bypass list or remove the proxy" $WinRMDiagFile
	} else {
	  Write-Diag "[INFO] No NETSH WINHTTP proxy is configured" $WinRMDiagFile
	}
	$th = (get-item WSMan:\localhost\Client\TrustedHosts).value
	if ($th) {
	  Write-Diag ("[INFO] TrustedHosts contains: $th") $WinRMDiagFile
	} else {
	  Write-Diag ("[INFO] TrustedHosts is not configured, it's ok it this machine is not supposed to connect to other machines using NTLM") $WinRMDiagFile
	}
	$psver = $PSVersionTable.PSVersion.Major.ToString() + $PSVersionTable.PSVersion.Minor.ToString()
	if ($psver -eq "50") {
	  Write-Diag ("[WARNING] Windows Management Framework version " + $PSVersionTable.PSVersion.ToString() + " is no longer supported") $WinRMDiagFile
	} else { 
	  Write-Diag ("[INFO] Windows Management Framework version is " + $PSVersionTable.PSVersion.ToString() ) $WinRMDiagFile
	}
	$clientcert = Get-ChildItem WSMan:\localhost\ClientCertificate
	if ($clientcert.Count -gt 0) {
	  Write-Diag "[INFO] Client certificate mappings" $WinRMDiagFile
	  foreach ($certmap in $clientcert) {
		Write-Diag ("[INFO] Certificate mapping " + $certmap.Name) $WinRMDiagFile
		$prop = Get-ChildItem $certmap.PSPath
		foreach ($value in $prop) {
		  Write-Diag ("[INFO]   " + $value.Name + " " + $value.Value) $WinRMDiagFile
		  if ($value.Name -eq "Issuer") {
			ChkCert -cert $value.Value -descr "mapping" -store "(Store = 'Root' or Store = 'CA')" -diagfile $WinRMDiagFile
		  } elseif ($value.Name -eq "UserName") {
			$usr = Get-CimInstance -class Win32_UserAccount | Where-Object {$_.Name -eq $value.value}
			if ($usr) {
			  if ($usr.Disabled) {
				Write-Diag ("[ERROR]	The local user account " + $value.value + " is disabled") $WinRMDiagFile
			  } else {
				Write-Diag ("[INFO]	 The local user account " + $value.value + " is enabled") $WinRMDiagFile
			  }
			} else {
			  Write-Diag ("[ERROR]	The local user account " + $value.value + " does not exist") $WinRMDiagFile
			}
		  } elseif ($value.Name -eq "Subject") {
			if ($value.Value[0] -eq '"') {
			  Write-Diag "[ERROR]	The subject does not have to be included in double quotes" $WinRMDiagFile
			}
		  }
		}
	  }
	} else {
	  if ($subWG) {
		Write-Diag "[ERROR] No client certificate mapping configured" $WinRMDiagFile
	  }
	}
	$aCert = $tbCert.Select("Store = 'Root' and Subject <> Issuer")
	if ($aCert.Count -gt 0) {
	  Write-Diag "[ERROR] Found for non-Root certificates in the Root store" $WinRMDiagFile
	  foreach ($cert in $acert) {
		Write-Diag ("[ERROR]  Misplaced certificate " + $cert.Subject) $WinRMDiagFile
	  }
	}
	if ($isForwarder) {
	  $evtLogReaders = (Get-CimInstance -Query ("Associators of {Win32_Group.Domain='" + $env:COMPUTERNAME + "',Name='Event Log Readers'} where Role=GroupComponent") | Where-Object {$_.Name -eq "NETWORK SERVICE"} | Measure-Object)
	  if ($evtLogReaders.Count -gt 0) {
		Write-Diag "[INFO] The NETWORK SERVICE account is member of the Event Log Readers group" $WinRMDiagFile
	  } else {
		Write-Diag "[WARNING] The NETWORK SERVICE account is NOT member of the Event Log Readers group, the events in the Security log cannot be forwarded" $WinRMDiagFile
	  }
	}
	$fwrules = (Get-NetFirewallPortFilter -Protocol TCP | Where-Object { $_.localport -eq 986} | Get-NetFirewallRule)
	if ($fwrules.count -eq 0) {
	  Write-Diag "[INFO] No firewall rule for port 5986" $WinRMDiagFile
	} else {
	  Write-Diag "[INFO] Found firewall rule for port 5986" $WinRMDiagFile
	}
	$dir = $env:windir + "\system32\logfiles\HTTPERR"
	if (Test-Path -path $dir) {
	  $httperrfiles = Get-ChildItem -path ($dir)
	  if ($httperrfiles.Count -gt 100) {
		Write-Diag ("[WARNING] There are " + $httperrfiles.Count + " files in the folder " + $dir) $WinRMDiagFile
	  } else {
	   Write-Diag ("[INFO] There are " + $httperrfiles.Count + " files in the folder " + $dir) $WinRMDiagFile
	  }
	  $size = 0 
	  foreach ($file in $httperrfiles) {
		$size += $file.Length
	  }
	  $size = [System.Math]::Ceiling($size / 1024 / 1024) # Convert to MB
	  if ($size -gt 100) {
		Write-Diag ("[WARNING] The folder " + $dir + " is using " + $size.ToString() + " MB of disk space") $WinRMDiagFile
	  } else {
		Write-Diag ("[INFO] The folder " + $dir + " is using " + $size.ToString() + " MB of disk space") $WinRMDiagFile
	  }
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_WinRMLog{
	# using external script WinRM-Collect.ps1
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling WinRM-Collect.ps1"
	.\scripts\WinRM-Collect.ps1 -DataPath $global:LogFolder -AcceptEula -Logs
	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done WinRM-Collect.ps1"
	EndFunc $MyInvocation.MyCommand.Name
}

Function UEX_WMIPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug ('Enabling analytic logs for WMI')
	Try{
		FwSetEventLog 'Microsoft-Windows-WMI-Activity/Trace'
		FwSetEventLog 'Microsoft-Windows-WMI-Activity/Debug'
	}Catch{
		$ErrorMessage = 'An exception happened in FwSetEventLog.'
		LogException $ErrorMessage $_ $fLogFileOnly
		Throw ($ErrorMessage)
	}
	EndFunc $MyInvocation.MyCommand.Name
}
Function UEX_WMIPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug ('Disabling analytic logs for WMI')

	Try{
		FwResetEventLog 'Microsoft-Windows-WMI-Activity/Trace'
		FwResetEventLog 'Microsoft-Windows-WMI-Activity/Debug'
	}Catch{
		$ErrorMessage = 'An exception happened in FwResetEventLog.'
		LogException $ErrorMessage $_ $fLogFileOnly
		Throw ($ErrorMessage)
	}
	EndFunc $MyInvocation.MyCommand.Name
}
Function CollectUEX_WMILog{  
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling WMI-Collect.ps1"
	.\scripts\WMI-Collect.ps1 -DataPath $global:LogFolder -AcceptEula -Logs
	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done WMI-Collect.ps1"
	EndFunc $MyInvocation.MyCommand.Name
}

#region AVD Data Collection using MSRD-Collect
Function CollectUEX_AVDCoreLog{

	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling MSRD-Collect.ps1 -Machine isAVD -Core"
	.\scripts\MSRD-Collect\MSRD-Collect.ps1 -isTSS -Machine isAVD -Core -msrdSkipDiag -DataPath $global:LogFolder -AcceptEula -Logs

	$msrdFilePattern = "*UEX_AVD*Trace.etl"
	$msrdFilesToDelete = Get-ChildItem -Path $global:LogFolder -Filter $msrdFilePattern
	if ($msrdFilesToDelete) {
		foreach ($msrdFile in $msrdFilesToDelete) {
			Remove-Item -Path $msrdFile.FullName -Force
		}
	}

	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done MSRD-Collect.ps1 -Machine isAVD -Core"
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_AVDProfilesLog{

	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling MSRD-Collect.ps1 -Machine isAVD -Profiles"
	.\scripts\MSRD-Collect\MSRD-Collect.ps1 -isTSS -Machine isAVD -Profiles -msrdSkipCore -msrdSkipDiag -DataPath $global:LogFolder -AcceptEula -Logs

	$msrdFilePattern = "*UEX_AVD*Trace.etl"
	$msrdFilesToDelete = Get-ChildItem -Path $global:LogFolder -Filter $msrdFilePattern
	if ($msrdFilesToDelete) {
		foreach ($msrdFile in $msrdFilesToDelete) {
			Remove-Item -Path $msrdFile.FullName -Force
		}
	}

	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done MSRD-Collect.ps1 -Machine isAVD -Profiles"
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_AVDActivationLog{

	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling MSRD-Collect.ps1 -Machine isAVD -Activation"
	.\scripts\MSRD-Collect\MSRD-Collect.ps1 -isTSS -Machine isAVD -Activation -msrdSkipCore -msrdSkipDiag -DataPath $global:LogFolder -AcceptEula -Logs

	$msrdFilePattern = "*UEX_AVD*Trace.etl"
	$msrdFilesToDelete = Get-ChildItem -Path $global:LogFolder -Filter $msrdFilePattern
	if ($msrdFilesToDelete) {
		foreach ($msrdFile in $msrdFilesToDelete) {
			Remove-Item -Path $msrdFile.FullName -Force
		}
	}

	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done MSRD-Collect.ps1 -Machine isAVD -Activation"
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_AVDMSRALog{

	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling MSRD-Collect.ps1 -Machine isAVD -MSRA"
	.\scripts\MSRD-Collect\MSRD-Collect.ps1 -isTSS -Machine isAVD -MSRA -msrdSkipCore -msrdSkipDiag -DataPath $global:LogFolder -AcceptEula -Logs

	$msrdFilePattern = "*UEX_AVD*Trace.etl"
	$msrdFilesToDelete = Get-ChildItem -Path $global:LogFolder -Filter $msrdFilePattern
	if ($msrdFilesToDelete) {
		foreach ($msrdFile in $msrdFilesToDelete) {
			Remove-Item -Path $msrdFile.FullName -Force
		}
	}

	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done MSRD-Collect.ps1 -Machine isAVD -MSRA"
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_AVDSCardLog{

	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling MSRD-Collect.ps1 -Machine isAVD -SCard"
	.\scripts\MSRD-Collect\MSRD-Collect.ps1 -isTSS -Machine isAVD -SCard -msrdSkipCore -msrdSkipDiag -DataPath $global:LogFolder -AcceptEula -Logs

	$msrdFilePattern = "*UEX_AVD*Trace.etl"
	$msrdFilesToDelete = Get-ChildItem -Path $global:LogFolder -Filter $msrdFilePattern
	if ($msrdFilesToDelete) {
		foreach ($msrdFile in $msrdFilesToDelete) {
			Remove-Item -Path $msrdFile.FullName -Force
		}
	}

	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done MSRD-Collect.ps1 -Machine isAVD -SCard"
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_AVDIMELog{

	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling MSRD-Collect.ps1 -Machine isAVD -IME"
	.\scripts\MSRD-Collect\MSRD-Collect.ps1 -isTSS -Machine isAVD -IME -msrdSkipCore -msrdSkipDiag -DataPath $global:LogFolder -AcceptEula -Logs

	$msrdFilePattern = "*UEX_AVD*Trace.etl"
	$msrdFilesToDelete = Get-ChildItem -Path $global:LogFolder -Filter $msrdFilePattern
	if ($msrdFilesToDelete) {
		foreach ($msrdFile in $msrdFilesToDelete) {
			Remove-Item -Path $msrdFile.FullName -Force
		}
	}

	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done MSRD-Collect.ps1 -Machine isAVD -IME"
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_AVDTeamsLog{

	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling MSRD-Collect.ps1 -Machine isAVD -Teams"
	.\scripts\MSRD-Collect\MSRD-Collect.ps1 -isTSS -Machine isAVD -Teams -msrdSkipCore -msrdSkipDiag -DataPath $global:LogFolder -AcceptEula -Logs

	$msrdFilePattern = "*UEX_AVD*Trace.etl"
	$msrdFilesToDelete = Get-ChildItem -Path $global:LogFolder -Filter $msrdFilePattern
	if ($msrdFilesToDelete) {
		foreach ($msrdFile in $msrdFilesToDelete) {
			Remove-Item -Path $msrdFile.FullName -Force
		}
	}

	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done MSRD-Collect.ps1 -Machine isAVD -Teams"
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_AVDMSIXAALog{

	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling MSRD-Collect.ps1 -Machine isAVD -MSIXAA"
	.\scripts\MSRD-Collect\MSRD-Collect.ps1 -isTSS -Machine isAVD -MSIXAA -msrdSkipCore -msrdSkipDiag -DataPath $global:LogFolder -AcceptEula -Logs

	$msrdFilePattern = "*UEX_AVD*Trace.etl"
	$msrdFilesToDelete = Get-ChildItem -Path $global:LogFolder -Filter $msrdFilePattern
	if ($msrdFilesToDelete) {
		foreach ($msrdFile in $msrdFilesToDelete) {
			Remove-Item -Path $msrdFile.FullName -Force
		}
	}

	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done MSRD-Collect.ps1 -Machine isAVD -MSIXAA"
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_AVDHCILog{

	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling MSRD-Collect.ps1 -Machine isAVD -HCI"
	.\scripts\MSRD-Collect\MSRD-Collect.ps1 -isTSS -Machine isAVD -HCI -msrdSkipCore -msrdSkipDiag -DataPath $global:LogFolder -AcceptEula -Logs

	$msrdFilePattern = "*UEX_AVD*Trace.etl"
	$msrdFilesToDelete = Get-ChildItem -Path $global:LogFolder -Filter $msrdFilePattern
	if ($msrdFilesToDelete) {
		foreach ($msrdFile in $msrdFilesToDelete) {
			Remove-Item -Path $msrdFile.FullName -Force
		}
	}

	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done MSRD-Collect.ps1 -Machine isAVD -HCI"
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_AVDDiagLog{

	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling MSRD-Collect.ps1 -Machine isAVD -DiagOnly"
	.\scripts\MSRD-Collect\MSRD-Collect.ps1 -isTSS -Machine isAVD -DiagOnly -DataPath $global:LogFolder -AcceptEula -Logs

	$msrdFilePattern = "*UEX_AVD*Trace.etl"
	$msrdFilesToDelete = Get-ChildItem -Path $global:LogFolder -Filter $msrdFilePattern
	if ($msrdFilesToDelete) {
		foreach ($msrdFile in $msrdFilesToDelete) {
			Remove-Item -Path $msrdFile.FullName -Force
		}
	}

	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done MSRD-Collect.ps1 -Machine isAVD -DiagOnly"
	EndFunc $MyInvocation.MyCommand.Name
}
#endregion AVD Data Collection using MSRD-Collect

<# Comment out CollectUEX_WMILog and CollectUEX_WinRMLog as there are duplicate functions in TSSv2_UEX_Mgmt.psm1. 
	The functions in UEX_Mgmt module are the latest and the functions in UEX module are no longer needed.

Function CollectUEX_WMILog{
	EnterFunc $MyInvocation.MyCommand.Name
	$WMILogFolder = "$LogFolder\WMILog$LogSuffix"
	$WMISubscriptions = "$WMILogFolder\Subscriptions"
	$WMIProcDumpFolder = "$WMILogFolder\Process dump"
	$LogPrefix = "WMI"

	Try{
		FwCreateLogFolder $WMILogFolder
		FwCreateLogFolder $WMISubscriptions
		FwCreateLogFolder $WMIProcDumpFolder
	}Catch{
		LogMessage ("Unable to create $WMILogFolder.") $_ 
		Return
	}

	# Process dump
	FwCaptureUserDump "WinMgmt" $WMIProcDumpFolder -IsService:$True
	FwCaptureUserDump "WMIPrvse" $WMIProcDumpFolder -IsService:$False
	ForEach($DecoupledProvider in $DecoupledProviders){
		FwCaptureUserDump $DecoupledProvider.ProcessName $WMIProcDumpFolder -IsService:$False
	}

	$WMIActivityLogs = @(
		'Microsoft-Windows-WMI-Activity/Trace'
		'Microsoft-Windows-WMI-Activity/Debug'
	)

	LogInfo ('[WMI] Exporting WMI analysitic logs.')
	[reflection.assembly]::loadwithpartialname("System.Diagnostics.Eventing.Reader") 
	$Eventlogsession = New-Object System.Diagnostics.Eventing.Reader.EventLogSession

	ForEach($WMIActivityLog in $WMIActivityLogs){
		Try{
			$EventLogConfig = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration -ArgumentList $WMIActivityLog,$Eventlogsession -ErrorAction Stop
		}Catch{
			LogException ("Error happened in creating EventLogConfiguration.") $_ $fLogFileOnly
			Continue
		}

		Try{
			$LogPath = [System.Environment]::ExpandEnvironmentVariables($Eventlogconfig.LogFilePath)
			# This is the case where ResetEventLog did nothing as the log already enabled. In this case, 
			# we need to disable it and copy the etl and then re-enable the log as it was orginally enabled.
			If($EventLogConfig.IsEnabled -eq $True){
				$EventLogConfig.IsEnabled=$False
				$EventLogConfig.SaveChanges()
				LogDebug "Copying $LogPath to $WMILogFolder"
				Copy-Item $LogPath $WMILogFolder  -ErrorAction Stop
				LogDebug ('Re-enabling ' + $Eventlogconfig.LogName)
				$EventLogConfig.IsEnabled=$True
				$EventLogConfig.SaveChanges()
			}Else{
				If(Test-path -path $LogPath){
					LogDebug ('Copying ' + $Eventlogconfig.LogFilePath + " to $WMILogFolder")
					Copy-Item $LogPath $WMILogFolder -ErrorAction Stop
				}
			}
		}Catch{
			LogException ('An exception happened in CollectWMILog.') $_ $fLogFileOnly
		}
	}

	# Get subscription info
	FwExecWMIQuery -Namespace "root\subscription" -Query "select * from ActiveScriptEventConsumer" | Export-Clixml -Path ("$WMISubscriptions\ActiveScriptEventConsumer.xml")
	FwExecWMIQuery -Namespace "root\subscription" -Query "select * from __eventfilter" | Export-Clixml -Path ("$WMISubscriptions\__eventfilter.xml")
	FwExecWMIQuery -Namespace "root\subscription" -Query "select * from __IntervalTimerInstruction" | Export-Clixml -Path ("$WMISubscriptions\__IntervalTimerInstruction.xml")
	FwExecWMIQuery -Namespace "root\subscription" -Query "select * from __AbsoluteTimerInstruction" | Export-Clixml -Path ("$WMISubscriptions\__AbsoluteTimerInstruction.xml")
	FwExecWMIQuery -Namespace "root\subscription" -Query "select * from __FilterToConsumerBinding" | Export-Clixml -Path ("$WMISubscriptions\__FilterToConsumerBinding.xml")

	# MOFs
	LogInfo ('[WMI] Collecting Autorecover MOFs content') 
	$mof = (Get-Itemproperty -ErrorAction SilentlyContinue -literalpath ("HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM")).'Autorecover MOFs'
	If ($mof.length -ne 0) {
		$mof | Out-File ("$WMILogFolder\Autorecover MOFs.txt")
	}

	# COM Security
	LogInfo ("[WMI] Getting COM Security info")
	$Reg = [WMIClass]"\\.\root\default:StdRegProv"
	$DCOMMachineLaunchRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction").uValue
	$DCOMMachineAccessRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineAccessRestriction").uValue
	$DCOMDefaultLaunchPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultLaunchPermission").uValue
	$DCOMDefaultAccessPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultAccessPermission").uValue
	
	$converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
	"Default Access Permission = " + ($converter.BinarySDToSDDL($DCOMDefaultAccessPermission)).SDDL | Out-File -FilePath ("$WMILogFolder\COMSecurity.txt") -Append
	"Default Launch Permission = " + ($converter.BinarySDToSDDL($DCOMDefaultLaunchPermission)).SDDL | Out-File -FilePath ("$WMILogFolder\COMSecurity.txt") -Append
	"Machine Access Restriction = " + ($converter.BinarySDToSDDL($DCOMMachineAccessRestriction)).SDDL | Out-File -FilePath ("$WMILogFolder\COMSecurity.txt") -Append
	"Machine Launch Restriction = " + ($converter.BinarySDToSDDL($DCOMMachineLaunchRestriction)).SDDL | Out-File -FilePath ("$WMILogFolder\COMSecurity.txt") -Append

	# File version
	LogInfo ("[WMI] Getting file version of WMI modules")
	FwFileVersion -Filepath ("$env:windir\system32\wbem\wbemcore.dll") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append
	FwFileVersion -Filepath ("$env:windir\system32\wbem\repdrvfs.dll") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append
	FwFileVersion -Filepath ("$env:windir\system32\wbem\WmiPrvSE.exe") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append
	FwFileVersion -Filepath ("$env:windir\system32\wbem\WmiPerfClass.dll") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append
	FwFileVersion -Filepath ("$env:windir\system32\wbem\WmiApRpl.dll") | Out-File -FilePath ("$WMILogFolder\FilesVersion.csv") -Append

	# Quota info
	LogInfo ("[WMI] Collecting quota details")
	$quota = FwExecWMIQuery -Namespace "Root" -Query "select * from __ProviderHostQuotaConfiguration"
	if ($quota) {
		("ThreadsPerHost : " + $quota.ThreadsPerHost + "`r`n") + `
		("HandlesPerHost : " + $quota.HandlesPerHost + "`r`n") + `
		("ProcessLimitAllHosts : " + $quota.ProcessLimitAllHosts + "`r`n") + `
		("MemoryPerHost : " + $quota.MemoryPerHost + "`r`n") + `
		("MemoryAllHosts : " + $quota.MemoryAllHosts + "`r`n") | Out-File -FilePath ("$WMILogFolder\ProviderHostQuotaConfiguration.txt")
	}

	# Details of decoupled providers
	LogInfo ("[WMI] Collecting details of decoupled providers")
	$list = Get-Process
	$DecoupledProviders = @()
	foreach ($proc in $list) {
		$prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmidcprv.dll"} 
		if (($prov | Measure-Object).count -gt 0) {
			$DecoupledProviders += $proc

			if (-not $hdr) {
				"Decoupled providers" | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
				" " | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
				$hdr = $true
			}
			
			$prc = FwExecWMIQuery -Namespace "root\cimv2" -Query ("select ProcessId, CreationDate, HandleCount, ThreadCount, PrivatePageCount, ExecutablePath, KernelModeTime, UserModeTime from Win32_Process where ProcessId = " +  $proc.id)
			$ut= New-TimeSpan -Start $prc.ConvertToDateTime($prc.CreationDate)
			
			$uptime = ($ut.Days.ToString() + "d " + $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00"))
			
			$ks = $prc.KernelModeTime / 10000000
			$kt = [timespan]::fromseconds($ks)
			$kh = $kt.Hours.ToString("00") + ":" + $kt.Minutes.ToString("00") + ":" + $kt.Seconds.ToString("00")
			
			$us = $prc.UserModeTime / 10000000
			$ut = [timespan]::fromseconds($us)
			$uh = $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00")
			
			$svc = FwExecWMIQuery -Namespace "root\cimv2" -Query ("select Name from Win32_Service where ProcessId = " +  $prc.ProcessId)
			$svclist = ""
			if ($svc) {
			  foreach ($item in $svc) {
				$svclist = $svclist + $item.name + " "
			  }
			  $svc = " Service: " + $svclist
			} else {
			  $svc = ""
			}
			
			($prc.ExecutablePath + $svc) | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
			"PID " + $prc.ProcessId  + " (" + [String]::Format("{0:x}", $prc.ProcessId) + ")  Handles: " + $prc.HandleCount + " Threads: " + $prc.ThreadCount + " Private KB: " + ($prc.PrivatePageCount/1kb) + " KernelTime:" + $kh + " UserTime:" + $uh + " Uptime:" + $uptime | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
			
			$Keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Wbem\Transports\Decoupled\Client
			$Items = $Keys | Foreach-Object {Get-ItemProperty $_.PsPath }
			ForEach ($key in $Items) {
			  if ($key.ProcessIdentifier -eq $prc.ProcessId) {
				($key.Scope + " " + $key.Provider) | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
			  }
			}
			" " | Out-File -FilePath ("$WMILogFolder\ProviderHosts.txt") -Append
		}
	}

	# Service configuration
	LogInfo ("[WMI] Exporting service configuration")
	$Commands = @(
		"sc.exe queryex winmgmt | Out-File $WMILogFolder\WinMgmtServiceConfig.txt -Append"
		"sc.exe qc winmgmt | Out-File $WMILogFolder\WinMgmtServiceConfig.txt -Append"
		"sc.exe enumdepend winmgmt 3000  | Out-File $WMILogFolder\WinMgmtServiceConfig.txt -Append"
		"sc.exe sdshow winmgmt | Out-File $WMILogFolder\WinMgmtServiceConfig.txt -Append"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

	# WMI class keys
	LogInfo ("[WMI] Exporting WMIPrvSE AppIDs and CLSIDs registration keys")
	$Commands = @(
		"reg query ""HKEY_CLASSES_ROOT\AppID\{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}"" | Out-File $WMILogFolder\WMIPrvSE.reg.txt -Append"
		"reg query ""HKEY_CLASSES_ROOT\AppID\{1F87137D-0E7C-44d5-8C73-4EFFB68962F2}"" | Out-File $WMILogFolder\WMIPrvSE.reg.txt -Append"
		"reg query ""HKEY_CLASSES_ROOT\Wow6432Node\AppID\{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}"" | Out-File $WMILogFolder\WMIPrvSE.reg.txt -Append"
		"reg query ""HKEY_CLASSES_ROOT\Wow6432Node\AppID\{1F87137D-0E7C-44d5-8C73-4EFFB68962F2}"" | Out-File $WMILogFolder\WMIPrvSE.reg.txt -Append"
		"reg query ""HKEY_CLASSES_ROOT\CLSID\{4DE225BF-CF59-4CFC-85F7-68B90F185355}"" | Out-File $WMILogFolder\WMIPrvSE.reg.txt -Append"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

	$Commands = @(
		"wevtutil epl Application $WMILogFolder\Application.evtx",
		"wevtutil al $WMILogFolder\Application.evtx /l:en-us",
		"wevtutil epl System $WMILogFolder\System.evtx",
		"wevtutil al $WMILogFolder\System.evtx /l:en-us",
		"wevtutil epl Microsoft-Windows-WMI-Activity/Operational $WMILogFolder\Microsoft-Windows-WMI-Activity-Operational.evtx",
		"wevtutil al $WMILogFolder\Microsoft-Windows-WMI-Activity-Operational.evtx /l:en-us"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

	# WMI-Activity log
	LogInfo ('[WMI] Exporting WMI Operational log.')
	$actLog = Get-WinEvent -logname "Microsoft-Windows-WMI-Activity/Operational" -Oldest -ErrorAction SilentlyContinue
	If(($actLog | Measure-Object).count -gt 0) {
		$actLog | Out-String -width 1000 | Out-File "$WMILogFolder\Microsoft-Windows-WMI-Activity-Operational.txt"
	}

	LogInfo ('[WMI] Collecting WMI repository and registry.')
	$Commands = @(
		"Get-ChildItem $env:SYSTEMROOT\System32\Wbem -Recurse -ErrorAction SilentlyContinue | Out-File -Append $WMILogFolder\wbemfolder.txt"
		"REG QUERY 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\wbem' /s 2>&1 | Out-File -Append $WMILogFolder\wbem.reg"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectUEX_WinRMLog{
	EnterFunc $MyInvocation.MyCommand.Name
	$LogPrefix = "WinRM"
	$WinRMLogFolder = "$LogFolder\WinRMLog$LogSuffix"
	$WinRMEventFolder = "$LogFolder\WinRMLog$LogSuffix\Eventlog"
	$WinRMDumpFolder = "$LogFolder\WinRMLog$LogSuffix\Process dump"
	$fqdn = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName

	Try{
		FwCreateLogFolder $WinRMLogFolder
		FwCreateLogFolder $WinRMEventFolder
		FwCreateLogFolder $WinRMDumpFolder
	}Catch{
		LogException ("Unable to create $WinRMLogFolder.") $_
		Return
	}

	If(!(FwIsElevated)){
		LogMessage $LogLevel.Warning ("[WinRM] Collecting WinRM log needs administrative privilege.")
		Return
	}

	# process dump for WinRM Service
	FwCaptureUserDump "WinRM" $WinRMDumpFolder -IsService $True
	FwCaptureUserDump "WecSvc" $WinRMDumpFolder -IsService $True
	FwCaptureUserDump "wsmprovhost.exe" $WinRMDumpFolder -IsService $False
	FwCaptureUserDump "SME.exe" $WinRMDumpFolder -IsService $False

	# Eventlog
	LogInfo ("[WinRM] Collecting WinRM configuration.")
	$EventLogs = @(
		"System",
		"Application",
		"Microsoft-Windows-CAPI2/Operational",
		"Microsoft-Windows-WinRM/Operational",
		"Microsoft-Windows-EventCollector/Operational",
		"Microsoft-Windows-Forwarding/Operational",
		"Microsoft-Windows-PowerShell/Operational",
		"`"Windows PowerShell`"",
		"Microsoft-Windows-GroupPolicy/Operational",
		"Microsoft-Windows-Kernel-EventTracing/Admin",
		"Microsoft-ServerManagementExperience",
		"Microsoft-Windows-ServerManager-ConfigureSMRemoting/Operational",
		"Microsoft-Windows-ServerManager-DeploymentProvider/Operational",
		"Microsoft-Windows-ServerManager-MgmtProvider/Operational",
		"Microsoft-Windows-ServerManager-MultiMachine/Operational",
		"Microsoft-Windows-FileServices-ServerManager-EventProvider/Operational"
	)
	FwExportEventLog $EventLogs $WinRMEventFolder

	FwEvtLogDetails "Application" $WinRMLogFolder
	FwEvtLogDetails "System" $WinRMLogFolder
	FwEvtLogDetails "Security" $WinRMLogFolder
	FwEvtLogDetails "ForwardedEvents" $WinRMLogFolder

	# Certifications
	LogInfo "[WinRM] Matching issuer thumbprints"
	$Global:tbCert = New-Object system.Data.DataTable
	$col = New-Object system.Data.DataColumn Store,([string]); $tbCert.Columns.Add($col)
	$col = New-Object system.Data.DataColumn Thumbprint,([string]); $tbCert.Columns.Add($col)
	$col = New-Object system.Data.DataColumn Subject,([string]); $tbCert.Columns.Add($col)
	$col = New-Object system.Data.DataColumn Issuer,([string]); $tbCert.Columns.Add($col)
	$col = New-Object system.Data.DataColumn NotAfter,([DateTime]); $tbCert.Columns.Add($col)
	$col = New-Object system.Data.DataColumn IssuerThumbprint,([string]); $tbCert.Columns.Add($col)
	$col = New-Object system.Data.DataColumn EnhancedKeyUsage,([string]); $tbCert.Columns.Add($col)
	$col = New-Object system.Data.DataColumn SerialNumber,([string]); $tbCert.Columns.Add($col)
	$col = New-Object system.Data.DataColumn SubjectKeyIdentifier,([string]); $tbCert.Columns.Add($col)
	$col = New-Object system.Data.DataColumn AuthorityKeyIdentifier,([string]); $tbCert.Columns.Add($col)
	FwGetCertStore "My"
	FwGetCertStore "CA"
	FwGetCertStore "Root"
	$aCert = $Global:tbCert.Select("Store = 'My' or Store = 'CA'")
	foreach ($cert in $aCert) {
	  $aIssuer = $Global:tbCert.Select("SubjectKeyIdentifier = '" + ($cert.AuthorityKeyIdentifier).tostring() + "'")
	  if ($aIssuer.Count -gt 0) {
		$cert.IssuerThumbprint = ($aIssuer[0].Thumbprint).ToString()
	  }
	}
	$Global:tbcert | Export-Csv "$WinRMLogFolder\certificates.tsv" -noType -Delimiter "`t"
	
	# Process and service info
	$proc = FwExecWMIQuery -Namespace "root\cimv2" -Query "select Name, CreationDate, ProcessId, ParentProcessId, WorkingSetSize, UserModeTime, KernelModeTime, ThreadCount, HandleCount, CommandLine, ExecutablePath, ExecutionState from Win32_Process"
	if ($PSVersionTable.psversion.ToString() -ge "3.0") {
	  $StartTime= @{e={$_.CreationDate.ToString("yyyyMMdd HH:mm:ss")};n="Start time"}
	  $Owner = @{N="User";E={(GetOwnerCim($_))}}
	} else {
	  $StartTime= @{n='StartTime';e={$_.ConvertToDateTime($_.CreationDate)}}
	  $Owner = @{N="User";E={(GetOwnerWmi($_))}}
	}
	
	if ($proc) {
		$proc | Sort-Object Name |
		Format-Table -AutoSize -property @{e={$_.ProcessId};Label="PID"}, @{e={$_.ParentProcessId};n="Parent"}, Name,
		@{N="WorkingSet";E={"{0:N0}" -f ($_.WorkingSetSize/1kb)};a="right"},
		@{e={[DateTime]::FromFileTimeUtc($_.UserModeTime).ToString("HH:mm:ss")};n="UserTime"}, @{e={[DateTime]::FromFileTimeUtc($_.KernelModeTime).ToString("HH:mm:ss")};n="KernelTime"},
		@{N="Threads";E={$_.ThreadCount}}, @{N="Handles";E={($_.HandleCount)}}, @{N="State";E={($_.ExecutionState)}}, $StartTime, $Owner, CommandLine |
		Out-String -Width 500 | Out-File "$WinRMLogFolder\processes.txt"
		
		LogInfo "[WinRM] Retrieving file version of running binaries"
		$binlist = $proc | Group-Object -Property ExecutablePath
		foreach ($file in $binlist) {
			if ($file.Name) {
				FwFileVersion -Filepath $file.name | Out-File -Append "$WinRMLogFolder\FilesVersion.csv"
			}
		}
	
		LogInfo "[WinRM] Collecting services details"
		$svc = FwExecWMIQuery -NameSpace "root\cimv2" -Query "select  ProcessId, DisplayName, StartMode,State, Name, PathName, StartName from Win32_Service"
		
		if($svc){
			$svc | Sort-Object DisplayName | Format-Table -AutoSize -Property ProcessId, DisplayName, StartMode,State, Name, PathName, StartName |
			Out-String -Width 400 | Out-File "$WinRMLogFolder\services.txt"
		}
	}

	# Event subscripion
	If (Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions") {
		LogInfo "[WinRM] Retrieving subscriptions configuration"
		$cmd = "wecutil es 2>> $ErrorLogFile"
		LogInfo ("[WinRM] Running $cmd")
		$subList = Invoke-Expression $cmd
		
		If(![string]::IsNullOrEmpty($subList)){
			ForEach($sub in $subList){
				LogInfo ("[WinRM] Subsription: " + $sub)
				("Subsription: " + $sub) | out-file -FilePath ("$WinRMLogFolder\Subscriptions.txt") -Append
				"-----------------------" | out-file -FilePath ("$WinRMLogFolder\Subscriptions.txt") -Append
				$cmd = "wecutil gs `"$sub`" /f:xml 2>> $ErrorLogFile"
				LogInfo ("[WinRM] Running " + $cmd)
				Invoke-Expression ($cmd) | out-file -FilePath ("$WinRMLogFolder\Subscriptions.txt") -Append
				$cmd = "wecutil gr `"$sub`" 2>> $ErrorLogFile"
				LogInfo ("[WinRM] Running " + $cmd)
				Invoke-Expression ($cmd) | out-file -FilePath ("$WinRMLogFolder\Subscriptions.txt") -Append
				" " | out-file -FilePath ("$WinRMLogFolder\Subscriptions.txt") -Append
			}
		}
	}

	# Start WinRM Service
	LogInfo ("[WinRM] Checking if WinRM is running")
	$WinRMService = Get-Service | Where-Object {$_.Name -eq 'WinRM'}
	If($Null -ne $WinRMService){

		If($WinRMService.Status -eq 'Stopped'){
			LogDebug ('[WinRM] Starting WinRM service as it is not running.')
			Start-Service $WinRMService.Name
		}

		$Service = Get-Service $WinRMService.Name
		$Service.WaitForStatus('Running','00:00:05')

		If($Service.Status -ne 'Running'){
			LogMessage $LogLevel.ErrorLogFileOnly ('[WinRM] Starting WinRM service failed.')
		}
	}

	LogInfo "[WinRM] Listing members of Event Log Readers group"
	$Commands = @(
		"net localgroup `"Event Log Readers`" | Out-File -Append $WinRMLogFolder\Groups.txt",
		"net localgroup WinRMRemoteWMIUsers__ | Out-File -Append $WinRMLogFolder\Groups.txt"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

	LogInfo "[WinRM] Finding SID of WinRMRemoteWMIUsers__ group"
	Try{
		$objUser = New-Object System.Security.Principal.NTAccount("WinRMRemoteWMIUsers__") -ErrorAction Stop
		$strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]).value
		$objSID = New-Object System.Security.Principal.SecurityIdentifier($strSID) -ErrorAction Stop
		$group = $objSID.Translate( [System.Security.Principal.NTAccount]).Value
		" " | Out-File -Append "$WinRMLogFolder\Groups.txt"
		($group + " = " + $strSID) | Out-File -Append "$WinRMLogFolder\Groups.txt"
	}Catch{
		LogMessage $LogLevel.ErrorLogFileOnly ("An exception happened in group info")
	}

	LogInfo "[WinRM] Getting locale info"
	"Get-Culture:" | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
	Get-Culture | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
	"Get-WinSystemLocale:" | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
	Get-WinSystemLocale | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
	"Get-WinHomeLocation:" | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
	Get-WinHomeLocation | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
	"Get-WinUILanguageOverride:" | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
	Get-WinUILanguageOverride | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
	"Get-WinUserLanguageList:" | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
	Get-WinUserLanguageList | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
	"Get-WinAcceptLanguageFromLanguageListOptOut:" | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
	Get-WinAcceptLanguageFromLanguageListOptOut | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
	"Get-Get-WinCultureFromLanguageListOptOut:" | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
	Get-WinCultureFromLanguageListOptOut | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
	"Get-WinDefaultInputMethodOverride:" | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
	Get-WinDefaultInputMethodOverride | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
	"Get-WinLanguageBarOption:" | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
	Get-WinLanguageBarOption | Out-File -FilePath ("$WinRMLogFolder\LanguageInfo.txt") -Append
	
	$PSVersionTable | Out-File -Append "$WinRMLogFolder\PSVersion.txt"

	# Http Proxy
	LogInfo "[WinRM] WinHTTP proxy configuration"
	netsh winhttp show proxy 2>> $ErrorLogFile | Out-File -Append "$WinRMLogFolder\WinHTTP-Proxy.txt"
	"------------------" | Out-File -Append "$WinRMLogFolder\WinHTTP-Proxy.txt"
	"NSLookup WPAD:" | Out-File -Append "$WinRMLogFolder\WinHTTP-Proxy.txt"
	"" | Out-File -Append "$WinRMLogFolder\WinHTTP-Proxy.txt"
	nslookup wpad 2>> $ErrorLogFile | Out-File -Append "$WinRMLogFolder\WinHTTP-Proxy.txt"

	# WinRM Configuration
	LogInfo "[WinRM] Retrieving WinRM configuration"
	Try{
		$config = Get-ChildItem WSMan:\localhost\ -Recurse -ErrorAction Stop
		If(!$config){
			LogMessage $LogLevel.ErrorLogFileOnly ("Cannot connect to localhost, trying with FQDN " + $fqdn)
			Connect-WSMan -ComputerName $fqdn -ErrorAction Stop
			$config = Get-ChildItem WSMan:\$fqdn -Recurse -ErrorAction Stop
			Disconnect-WSMan -ComputerName $fqdn -ErrorAction Stop
		}
	}Catch{
		LogException ("An error happened during getting WinRM configuration") $_ $fLogFileOnly
	}
	
	If($Null -ne $config){
		$config | out-string -Width 500 | Out-File -Append "$WinRMLogFolder\WinRM-config.txt"
	}
	$Commands = @(
		 "winrm get winrm/config | Out-File -Append $WinRMLogFolder\WinRM-config.txt"
		 "winrm e winrm/config/listener | Out-File -Append $WinRMLogFolder\WinRM-config.txt"
		 "winrm enum winrm/config/service/certmapping | Out-File -Append $WinRMLogFolder\WinRM-config.txt"
		 "WinRM get 'winrm/config/client' | Out-File -Append $WinRMLogFolder/WinRMconfig-client.txt",
		 "WinRM enumerate 'winrm/config/listener' | Out-File -Append $WinRMLogFolder/WinRMconfig-listener.txt"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

	# Other commands
	$Commands = @(
		"reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials $WinRMLogFolder\AllowFreshCredentials.reg.txt /y",
		"reg export HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP $WinRMLogFolder\HTTP.reg.txt /y",
		"reg export `"HKEY_USERS\S-1-5-20\Control Panel\International`" $WinRMLogFolder\InternationalNetworkService.reg.txt",
		"reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN /s  | Out-File -Append $WinRMLogFolder/reg-winrm.txt",
		"netsh advfirewall firewall show rule name=all  | Out-File -Append $WinRMLogFolder\FirewallRules.txt",
		"netstat -anob  | Out-File -Append $WinRMLogFolder\netstat.txt",
		"ipconfig /all  | Out-File -Append $WinRMLogFolder\ipconfig_all.txt",
		"ipconfig /displaydns  | Out-File -Append $WinRMLogFolder\ipconfig_displaydns.txt",
		"Get-NetConnectionProfile | Out-File -Append $WinRMLogFolder\NetConnectionProfile.txt",
		"Get-WSManCredSSP | Out-File -Append $WinRMLogFolder\WSManCredSSP.txt",
		"gpresult /h $WinRMLogFolder\gpresult.html",
		"gpresult /r | Out-File -Append $WinRMLogFolder\gpresult.txt"
		"Copy-Item $env:windir\system32\logfiles\HTTPERR\* $WinRMLogFolder -ErrorAction Stop",
		"Copy-Item C:\Windows\system32\drivers\etc\hosts $WinRMLogFolder\hosts.txt -ErrorAction Stop",
		"Copy-Item C:\Windows\system32\drivers\etc\lmhosts $WinRMLogFolder\lmhosts.txt -ErrorAction Stop",
		"reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM $WinRMLogFolder\WinRM.reg.txt /y",
		"reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN $WinRMLogFolder\WSMAN.reg.txt /y",
		"reg export HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM $WinRMLogFolder\WinRM-Policies.reg.txt /y",
		"reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System $WinRMLogFolder\System-Policies.reg.txt /y",
		"reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector $WinRMLogFolder\EventCollector.reg.txt /y",
		"reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventForwarding $WinRMLogFolder\EventForwarding.reg.txt /y",
		"reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog $WinRMLogFolder\EventLog-Policies.reg.txt /y",
		"reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL $WinRMLogFolder\SCHANNEL.reg.txt /y",
		"reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography $WinRMLogFolder\Cryptography.reg.txt /y",
		"reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography $WinRMLogFolder\Cryptography-Policy.reg.txt /y",
		"reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa $WinRMLogFolder\LSA.reg.txt /y",
		"reg export HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP $WinRMLogFolder\HTTP.reg.txt /y",
		"reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials $WinRMLogFolder\AllowFreshCredentials.reg.txt /y",
		"reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache $WinRMLogFolder\ServerComponentCache.reg.txt /y",
		"netsh http show sslcert | Out-File -Append $WinRMLogFolder\netsh-http.txt",
		"netsh http show urlacl | Out-File -Append $WinRMLogFolder\netsh-http.txt",
		"netsh http show servicestate | Out-File -Append $WinRMLogFolder\netsh-http.txt",
		"netsh http show iplisten | Out-File -Append $WinRMLogFolder\netsh-http.txt",
		"setspn -L $env:computername | Out-File -Append $WinRMLogFolder\SPN.txt",
		"setspn -Q HTTP/$env:computername | Out-File -Append $WinRMLogFolder\SPN.txt",
		"setspn -Q HTTP/$fqdn | Out-File -Append $WinRMLogFolder\SPN.txt",
		"setspn -F -Q HTTP/$env:computername | Out-File -Append $WinRMLogFolder\SPN.txt",
		"setspn -F -Q HTTP/$fqdn | Out-File -Append $WinRMLogFolder\SPN.txt",
		"setspn -Q WSMAN/$env:computername | Out-File -Append $WinRMLogFolder\SPN.txt",
		"setspn -Q WSMAN/$fqdn | Out-File -Append $WinRMLogFolder\SPN.txt",
		"setspn -F -Q WSMAN/$env:computername | Out-File -Append $WinRMLogFolder\SPN.txt",
		"setspn -F -Q WSMAN/$fqdn | Out-File -Append $WinRMLogFolder\SPN.txt",
		"Certutil -verifystore -v MY | Out-File -Append $WinRMLogFolder\Certificates-My.txt",
		"Certutil -verifystore -v ROOT | Out-File -Append $WinRMLogFolder\Certificates-Root.txt",
		"Certutil -verifystore -v CA | Out-File -Append $WinRMLogFolder\Certificates-Intermediate.txt"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

	If(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\InetStp"){
		$Commands = @(
			"$env:SystemRoot\system32\inetsrv\APPCMD list app | Out-File -Append $WinRMLogFolder\iisconfig.txt",
			"$env:SystemRoot\system32\inetsrv\APPCMD list apppool | Out-File -Append $WinRMLogFolder\iisconfig.txt",
			"$env:SystemRoot\system32\inetsrv\APPCMD list site | Out-File -Append $WinRMLogFolder\iisconfig.txt",
			"$env:SystemRoot\system32\inetsrv\APPCMD list module | Out-File -Append $WinRMLogFolder\iisconfig.txt",
			"$env:SystemRoot\system32\inetsrv\APPCMD list wp | Out-File -Append $WinRMLogFolder\iisconfig.txt",
			"$env:SystemRoot\system32\inetsrv\APPCMD list vdir | Out-File -Append $WinRMLogFolder\iisconfig.txt",
			"$env:SystemRoot\system32\inetsrv\APPCMD list config | Out-File -Append $WinRMLogFolder\iisconfig.txt"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True
	}Else{
		LogDebug ("[WinRM] IIS is not installed")
	}
	EndFunc $MyInvocation.MyCommand.Name
}
#>

#endregion ### Pre-Start / Post-Stop / Collect functions for trace components and scenarios


#region example special Functions - not used so far
ForEach ($UEX_ETWSwitchStatus in $ETWTracingSwitchesStatus){
	switch ($UEX_ETWSwitchStatus){
		"UEX_Scenario1" {Start-UEX_Scenario1 ('1', '2')}
		"UEX_Scenario2" {Start-UEX_Scenario2 ('dummy parameter')}
		"UEX_Robert" {Start-UEX_Robert ('dummy parameter')}
		default{Write-Host "No match found in Start-UEX* module functions of TSSv2_UEX.psm1."}
	}
}
#Implementations of the specific data collection scenario
function Start-UEX_Scenario1{
	# -------------- UEX_Scenario1 ---------------
	[CmdletBinding(DefaultParameterSetName = 'None')]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullorEmpty()]
		[Array]$UEX_Scenario1_params
	)
	#register stop function
	$global:StopModuleCallbackFunctions += 'Stop-UEX_Scenario1'
	#add your custom code
}
function Stop-UEX_Scenario1{
	#add your custom code
	Write-Host "Stop UEX_Scenario_1"
}
function Start-UEX_Scenario2{
	[CmdletBinding(DefaultParameterSetName = 'None')]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullorEmpty()]
		[Array]$UEX_Scenario2_params
	)

	#register stop function
	$global:StopModuleCallbackFunctions += 'Stop-UEX_Scenario2'
	#add your custom code
}
function Stop-UEX_Scenario2{
	#add your custom code
	Write-Host "Stop UEX_Scenario_2"
}
function Start-UEX_Robert{
	[CmdletBinding(DefaultParameterSetName = 'None')]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullorEmpty()]
		[Array]$UEX_Rober_params
	)
	#register stop function
	$global:StopModuleCallbackFunctions += 'Stop-UEX_Scenario2'
	#add your custom code
}
function Stop-UEX_Robert{
	#add your custom code
	Write-Host "Stop UEX_Robert"
}
#endregion example special Functions - not used so far

#region Registry Key modules for FwAddRegItem
#	$global:KeysAppV = @("HKLM:Software\Microsoft\AppV")
	$global:KeysFSLogix = @("HKLM:Software\FSLogix", "HKLM:Software\Policies\Fslogix")

	# RegKeys Telemetry
	$global:KeysAppCompatFlags = @("HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags")
	$global:KeysCensus = @("HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Census")
	$global:KeysSQM = @("HKLM:SOFTWARE\Microsoft\SQMClient")
	$global:KeysDiagTrack = @("HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack")
	$global:KeysPoliciesDataCollection = @("HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection")
	$global:KeysDataCollection = @("HKLM:SOFTWARE\Policies\Microsoft\Windows\DataCollection")
	
	# RegKeys MDAG
	$global:KeysMDAG_HKLM_SW_Browsers_LookAside = @("HKLM:SOFTWARE\Google\Chrome\NativeMessagingHosts\com.microsoft.wdagcore", "HKLM:SOFTWARE\Mozilla\NativeMessagingHosts\com.microsoft.wdagcore","HKLM:SOFTWARE\Microsoft\Edge", "HKLM:SOFTWARE\Microsoft\Edge Beta", "HKLM:SOFTWARE\Microsoft\Edge Dev", "HKLM:SOFTWARE\Microsoft\Edge SxS")
	$global:KeysMDAG_HKLM_SW_MS_EDP_Policies = @("HKLM:SOFTWARE\Microsoft\EnterpriseDataProtection\Policies") 
	$global:KeysMDAG_HKLM_SW_MS_Enrollments = @("HKLM:SOFTWARE\Microsoft\Enrollments")
	$global:KeysMDAG_HKLM_SW_MS_HVSI = @("HKLM:SOFTWARE\Microsoft\HVSI", "HKLM:SOFTWARE\Microsoft\HVSICSP", "HKLM:SOFTWARE\Microsoft\HVSIGP", "HKLM:SOFTWARE\Microsoft\HvsiDeployment")
	$global:KeysMDAG_HKLM_SW_MS_PolicyManager_NetworkIsolation =@("HKLM:SOFTWARE\Microsoft\PolicyManager\current\device\")
	$global:KeysMDAG_HKLM_SW_POL_MS = @("HKLM:SOFTWARE\Policies\Microsoft\AppHVSI", "HKLM:SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions", "HKLM:SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation")
	$global:KeysMDAG_HKLM_System_CCS_Services = @("HKLM:SYSTEM\CurrentControlSet\Services\WinNat", "HKLM:SYSTEM\CurrentControlSet\Services\hns", "HKLM:SYSTEM\CurrentControlSet\Services\vmsmp\parameters\SwitchList", "HKLM:SYSTEM\CurrentControlSet\Services\vmsmp\parameters\NicList" )
	$global:KeysMDAG_HKLM_System_CCS_Control_GraphicsAndGpu = @("HKLM:SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HKLM:SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}")
	$global:KeysMDAG_HKLM_System_CCS_HNS = @("HKLM:SYSTEM\CurrentControlSet\Services\HNS")

#endregion Registry Key modules

#region groups of Eventlogs for FwAddEvtLog
	$global:EvtLogsPowerShell = @("Microsoft-Windows-PowerShell/Admin", "Microsoft-Windows-PowerShell/Operational")
	$global:EvtLogsWDAG=("Microsoft-Windows-WDAG-Manager/Operational", "Microsoft-Windows-WDAG-PolicyEvaluator-CSP/Operational","Microsoft-Windows-WDAG-PolicyEvaluator-GP/Operational","Microsoft-Windows-WDAG-Service/Operational")
#endregion groups of Eventlogs

#region common functions for UEX_Mgmt - overlapping with \scripts\Collect-Commons.psm1
<#
$DefinitionOfNetGetJoin = @"
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint NetApiBufferFree(IntPtr Buffer);
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int NetGetJoinInformation(
  string server,
  out IntPtr NameBuffer,
  out int BufferType);
"@

If(!("Win32Api.NetApi32" -as [type])){
	Try{
		Add-Type -MemberDefinition $DefinitionOfNetGetJoin -Namespace Win32Api -Name NetApi32 -ErrorAction Stop
	}Catch{
		LogWarn "Add-Type for NetGetJoinInformation failed."
	}
}Else{
	LogDebug "[Win32Api.NetApi32] has been already added. Skipping adding definition of NetGetJoinInformation." "Gray"
}

Function GetNBDomainName {
  $pNameBuffer = [IntPtr]::Zero
  $joinStatus = 0
  $apiResult = [Win32Api.NetApi32]::NetGetJoinInformation(
	$null,			   # lpServer
	[Ref] $pNameBuffer,  # lpNameBuffer
	[Ref] $joinStatus	# BufferType
  )
  if ( $apiResult -eq 0 ) {
	[Runtime.InteropServices.Marshal]::PtrToStringAuto($pNameBuffer)
	[Void] [Win32Api.NetApi32]::NetApiBufferFree($pNameBuffer)
  }
}
#>

Function FindSep {
  param( [string]$FindIn, [string]$Left,[string]$Right )
  if ($left -eq "") {
	$Start = 0
  } else {
	$Start = $FindIn.IndexOf($Left) 
	if ($Start -gt 0 ) {
	  $Start = $Start + $Left.Length
	} else {
	   return ""
	}
  }
  if ($Right -eq "") {
	$End = $FindIn.Substring($Start).Length
  } else {
	$End = $FindIn.Substring($Start).IndexOf($Right)
	if ($end -le 0) {
	  return ""
	}
  }
  $Found = $FindIn.Substring($Start, $End)
  return $Found
}
Function GetSubVal {
  param( [string]$SubName, [string]$SubValue)
  $SubProp = (Get-Item -Path ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions\" + $SubName) | Get-ItemProperty)
  if ($SubProp.($SubValue)) {
	return $SubProp.($SubValue)
  } else {
	$cm = $SubProp.ConfigurationMode
	$subVal = (Get-Item -Path ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\ConfigurationModes\" + $cm) | Get-ItemProperty)
	return $SubVal.($SubValue)
  }
}
Function ChkCert($cert, $store, $descr, $diagfile) {
  $cert = $cert.ToLower()
  if ($cert) {
	if ("0123456789abcdef".Contains($cert[0])) {
	  $aCert = $tbCert.Select("Thumbprint = '" + $cert + "' and $store")
	  if ($aCert.Count -gt 0) {
		Write-Diag ("[INFO] The $descr certificate was found, the subject is " + $aCert[0].Subject) $diagfile
		if (($aCert[0].NotAfter) -gt (Get-Date)) {
		  Write-Diag ("[INFO] The $descr certificate will expire on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") ) $diagfile
		} else {
		  Write-Diag ("[ERROR] The $descr certificate expired on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") ) $diagfile
		}
	  }  else {
		Write-Diag "[ERROR] The certificate with thumbprint $cert was not found in $store" $diagfile
	  }
	} else {
	  Write-Diag "[ERROR] Invalid character in the $cert certificate thumbprint $cert" $diagfile
	}
  } else {
	Write-Diag "[ERROR] The thumbprint of $descr certificate is empty" $diagfile
  }
}
Function Write-Diag{
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String] $msg,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String] $FileName
	)
	$msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
	Write-Host $msg -ForegroundColor Yellow
	$msg | Out-File -FilePath $FileName -Append
}
#endregion common functions for UEX_Mgmt - overlapping with \scripts\Collect-Commons.psm1


#region Deprecated parameter list. Property array of deprecated/obsoleted params.
#   DeprecatedParam: Parameters to be renamed or obsoleted in the future
#   Type		   : Can take either 'Rename' or 'Obsolete'
#   NewParam	   : Provide new parameter name for replacement only when Type=Rename. In case of Type='Obsolete', put null for the value.
$UEX_DeprecatedParamList = @(
	@{DeprecatedParam='UEX_Clipboard';Type='Rename';NewParam='PRF_Clipboard'}
	@{DeprecatedParam='UEX_Photo';Type='Rename';NewParam='PRF_Photo'}
	@{DeprecatedParam='UEX_Store';Type='Rename';NewParam='PRF_Store'}
	@{DeprecatedParam='UEX_Alarm';Type='Rename';NewParam='PRF_Alarm'}
	@{DeprecatedParam='UEX_Calc';Type='Rename';NewParam='PRF_Calc'}
	@{DeprecatedParam='UEX_Camera';Type='Rename';NewParam='PRF_Camera'}
	@{DeprecatedParam='UEX_DWM';Type='Rename';NewParam='PRF_DWM'}
	@{DeprecatedParam='UEX_ImmersiveUI';Type='Rename';NewParam='PRF_ImmersiveUI'}
	@{DeprecatedParam='UEX_Media';Type='Rename';NewParam='PRF_Media'}
	@{DeprecatedParam='UEX_Speech';Type='Rename';NewParam='PRF_Speech'}
	@{DeprecatedParam='UEX_SystemSettings';Type='Rename';NewParam='PRF_SystemSettings'}
	@{DeprecatedParam='UEX_XAML';Type='Rename';NewParam='PRF_XAML'}
	@{DeprecatedParam='UEX_Shutdown';Type='Rename';NewParam='PRF_Shutdown'}
	@{DeprecatedParam='UEX_DM';Type='Rename';NewParam='PRF_DM'}
	@{DeprecatedParam='UEX_AppX';Type='Rename';NewParam='PRF_AppX'}
	@{DeprecatedParam='UEX_StartMenu';Type='Rename';NewParam='PRF_StartMenu'}
	@{DeprecatedParam='UEX_Shell';Type='Rename';NewParam='PRF_Shell'}
	@{DeprecatedParam='UEX_IME';Type='Rename';NewParam='PRF_IME'}
	@{DeprecatedParam='UEX_Font';Type='Rename';NewParam='PRF_Font'}
	@{DeprecatedParam='UEX_NLS';Type='Rename';NewParam='PRF_NLS'}
	@{DeprecatedParam='UEX_Cortana';Type='Rename';NewParam='PRF_Cortana'}
	@{DeprecatedParam='UEX_SCM';Type='Rename';NewParam='PRF_SCM'}
)
#endregion Deprecated parameter list.

Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *



# SIG # Begin signature block
# MIInvwYJKoZIhvcNAQcCoIInsDCCJ6wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB+uK/CBFJhXsJX
# SDXPdb3/NrI7oYbGuPuj12rekbKhWqCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGEmlFQ5GfjKXr/2u9hrfnxg
# B0/7rBzLi3ejWn9uSCpBMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAmnAnXfOBk3O/tsWo3yehi6moGwkeXfjmDUQunDdMHve5/SNc5zCtfkz2
# /9H1QkLLsH1YsnASx5TsFjzoHe3fcR1/j3sveCf8hUHHRe/3K4SCcKyIlL2WRAeV
# bWXC7xSLYGywMaJaTsbE8nr1T154+yRglNwfJ+GGuaork/mwnHXkd0IAvMS16Jkd
# I5JqB5Sy6FaMTfx+J4CdlEKOgfhhLX0ZEvFtF1t9JbW+k/3hxMQ1VM69dmz9gLOF
# eK5wbDNrukKwbWNmRq1xBHeVDz+hdHBu0bM3QHSklc4S1Us5ozPCgleZR5Fz6eG/
# IZ1dLH6O1aCQN8usVNX00tkoSzmRyaGCFykwghclBgorBgEEAYI3AwMBMYIXFTCC
# FxEGCSqGSIb3DQEHAqCCFwIwghb+AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsq
# hkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCBoVP9g0FYZShwkA2mwU2gxO5hpnkRpLh2TNyIInYFt1QIGZGzybO6D
# GBMyMDIzMDYwNjExNDQxNi40OTRaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# Ojg2REYtNEJCQy05MzM1MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloIIReDCCBycwggUPoAMCAQICEzMAAAG3IScaB6IqhkYAAQAAAbcwDQYJ
# KoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIw
# OTIwMjAyMjE0WhcNMjMxMjE0MjAyMjE0WjCB0jELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3Bl
# cmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4NkRGLTRC
# QkMtOTMzNTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMf9z1dQNBNkTBq3HJclypjQ
# cJIlDAgpvsw4vHJe06n532RKGkcn0V7p65OeA1wOoO+8NsopnjPpVZ8+4s/RhdMC
# MNPQJXoWdkWOp/3puIEs1fzPBgTJrdmzdyUYzrAloICYx722gmdpbNf3P0y5Z2gR
# O48sWIYyYeNJYch+ZfJzXqqvuvq7G8Nm8IMQi8Zayvx+5dSGBM5VYHBxCEjXF9EN
# 6Qw7A60SaXjKjojSpUmpaM4FmVec985PNdSh8hOeP2tL781SBan92DT19tfNHv9H
# 0FAmE2HGRwizHkJ//mAZdS0s6bi/UwPMksAia5bpnIDBOoaYdWkV0lVG5rN0+ltR
# z9zjlaH9uhdGTJ+WiNKOr7mRnlzYQA53ftSSJBqsEpTzCv7c673fdvltx3y48Per
# 6vc6UR5e4kSZsH141IhxhmRR2SmEabuYKOTdO7Q/vlvAfQxuEnJ93NL4LYV1IWw8
# O+xNO6gljrBpCOfOOTQgWJF+M6/IPyuYrcv79Lu7lc67S+U9MEu2dog0MuJIoYCM
# iuVaXS5+FmOJiyfiCZm0VJsJ570y9k/tEQe6aQR9MxDW1p2F3HWebolXj9su7zrr
# ElNlHAEvpFhcgoMniylNTiTZzLwUj7TH83gnugw1FCEVVh5U9lwNMPL1IGuz/3U+
# RT9wZCBJYIrFJPd6k8UtAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUs/I5Pgw0JAVh
# DdYB2yPII8l4tOwwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYD
# VR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# cmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwG
# CCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIw
# MjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcD
# CDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBAA2dZMybhVxSXTbJ
# zFgvNiMCV5/Ayn5UuzJU495YDtcefold0ehR9QBGBhHmAMt10WYCHz2WQUyM3mQD
# 4IsHfEL1JEwgG9tGq71ucn9dknLBHD30JvbQRhIKcvFSnvRCCpVpilM8F/YaWXC9
# VibSef/PU2GWA+1zs64VFxJqHeuy8KqrQyfF20SCnd8zRZl4YYBcjh9G0GjhJHUP
# AYEx0r8jSWjyi2o2WAHD6CppBtkwnZSf7A68DL4OwwBpmFB3+vubjgNwaICS+fkG
# VvRnP2ZgmlfnaAas8Mx7igJqciqq0Q6An+0rHj1kxisNdIiTzFlu5Gw2ehXpLrl5
# 9kvsmONVAJHhndpx3n/0r76TH+3WNS9UT9jbxQkE+t2thif6MK5krFMnkBICCR/D
# VcV1qw9sg6sMEo0wWSXlQYXvcQWA65eVzSkosylhIlIZZLL3GHZD1LQtAjp2A5F7
# C3Iw4Nt7C7aDCfpFxom3ZulRnFJollPHb3unj9hA9xvRiKnWMAMpS4MZAoiV4O29
# zWKZdUzygp7gD4WjKK115KCJ0ovEcf92AnwMAXMnNs1o0LCszg+uDmiQZs5eR7jz
# dKzVfF1z7bfDYNPAJvm5pSQdby3wIOsN/stYjM+EkaPtUzr8OyMwrG+jpFMbsB4c
# fN6tvIeGtrtklMJFtnF68CcZZ5IAMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJ
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
# bmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4
# NkRGLTRCQkMtOTMzNTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaIjCgEBMAcGBSsOAwIaAxUAyGdBGMObODlsGBZmSUX2oWgfqcaggYMwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIF
# AOgpPE0wIhgPMjAyMzA2MDYxMzAyMDVaGA8yMDIzMDYwNzEzMDIwNVowdDA6Bgor
# BgEEAYRZCgQBMSwwKjAKAgUA6Ck8TQIBADAHAgEAAgIHnTAHAgEAAgIRgTAKAgUA
# 6CqNzQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAID
# B6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBACLl102WEkK3Dd6MAeDW
# BS9ABOM2pyKlJY05AQwnU7FjpIy9DV9Mu+okKOMLVSNXk19NRNwzGlbEp4aUNdFO
# aYzPivtlHMCWAwLoQ/QLRV8Pz64SggzWQ3h/xP1IIIAHSEhSsWyRP3mg/iWKo4f4
# qbLz3waIqhkGtmHjVBC0A2YJMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTACEzMAAAG3IScaB6IqhkYAAQAAAbcwDQYJYIZIAWUDBAIB
# BQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQx
# IgQg83KHuG2/sHHNUbB25OQgntWTh1G6bwUT8rZuW8PwhV0wgfoGCyqGSIb3DQEJ
# EAIvMYHqMIHnMIHkMIG9BCBsJ3jTsh7aL8hNeiYGL5/8IBn8zUfr7/Q7rkM8ic1w
# QTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABtyEn
# GgeiKoZGAAEAAAG3MCIEIPOsUWfmWdIHLgaDbkUHkxu5CNz9CZaukkAFfy6Ko1YB
# MA0GCSqGSIb3DQEBCwUABIICAK/eeafLb9aa8R44S9pG1c8POZsqa0AWxfK0W52r
# ic/BpEFTFKv9NwbKIaQMTP5qrF5hZgKcQ+IjBTEPozCT1tbj3OF3Ryjbm+v4rKdN
# PxGMi+Zf0YGYUXD5bK32P+xVs3nhnv7YharCbwioDOa48ARpN45PFZbfC6JNMnyP
# MKDyTIFpU4uAJIiTbqkhoku4+Xzt8Rj2ADACt1oA1gENpzBqK5L4MUaUDtj2tmGG
# o18k7ezlzsVSQG9d43HjWXEa3kiDFdq5G2AzYZXy9q+fNgaSwhJvCaTqr6KGEwPi
# 8zZk73pCLiL8u09L6oRbC/8f4gVw63w8hipsUMKzLXoU83cpH53MaWK8A0ce65m1
# cKIbkxfEpEP1xvpsm7BQw99VHbvC2Zqi3vkpN/cf1ceVZPkxlHOqP/Iy//ghTdIS
# RyJgFd+YfXzUwYfgrkXdj8JR/g4RJrNy9z7Qte+tprKtgWCso1+CPLopdjaJ+lEO
# HERGoYhAaR6bNJaRMI5E18E5AZHHd1vNg/OdOD18wFAZmRj+WBSroNwBf28W4Wrd
# j/URBfcdhE98MMjkJRFlnOeSJDd7XZzMkLDzfw9DEPeFDOyZrdEq9mm4FNThaZyV
# yRqsIOxOEJRAC7TegCeG1SQrG68PVR5Q0ZvUiHxKHDbELzJgaHWpz5lXe1+KRBG4
# /zvQ
# SIG # End signature block
