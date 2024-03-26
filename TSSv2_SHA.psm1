<#
.SYNOPSIS
   SHA module for collecting ETW traces and various custom tracing functionality

.DESCRIPTION
   Define ETW traces for Windows SHA components 
   Add any custom tracing functinaliy for tracing SHA components
   For Developers:
   1. Component test: .\TSSv2.ps1 -Start -SHA_TEST1
   2. Scenario test:  .\TSSv2.ps1 -start -Scenario SHA_MyScenarioTest

.NOTES
	Dev. Lead: ?
   Authors    : <your_alias>;WalterE; RobertVi; Kojii
   Requires   : PowerShell V4 (Supported from Windows 8.1/Windows Server 2012 R2)
   Version	: see $global:TssVerDateSHA

.LINK
	TSSv2 https://internal.support.services.microsoft.com/en-us/help/4619187
	SHA https://internal.support.services.microsoft.com/en-us/help/5009525
#>

<# latest changes 
::	2023.05.17.0 [we] _SHA: upd SHA_iSCSI providers
::	2023.04.07.0 [we] _SHA: removed un-used SHA_PnP
::	2023.03.14.0 [we] _SHA: add correlation=disabled to NET_HypHost NetSh (kb5025648)
::	2023.01.18.0 [we] _SHA: $SHA_DummyProviders = @()
::	2023.01.03.0 [we] _SHA: removed duplicate SHA_StorPort: sorting Providers alphabetically
::	2022.12.12.0 [we] _SHA: upd SHA_VSS
::	2022.12.07.0 [we] _SHA: add -Scenario SHA_General
::	2022.11.27.1 [rvi] Adding GetLogs to SHA_MSCluster 
::	2022.10.30.1 [rvi] modify $FrutiExe to Stop on end of trace
::	2022.10.24.2 [we] modify $VmlTrace_exe and $FrutiExe invocation
::	2022.10.14.0 [we] add SHA_StorageSense
::	2022.08.22.0 [rvi] SpaceDB Chkspace collection
::	2022.07.21.0 [we] SHA_fix MsCluster definition
::	2022.06.10.0 [we] add SHA_VML (use -Mode verbose to restart the Hyper-V service and get FRUTI log); upd SHA_MSCluster
::	2022.04.15.0 [ki] add ETW from shacollector
::	2022.01.24.0 [we] add SHA_ReFS
::	2022.01.24.0 [we] update SHA_Storage with all aka SAN Shotgun from Insightweb
::	2022.01.03.0 [we] mod SHA_HypHost/HypVM/ShieldedVM
::	2021.12.31.1 [we] #_# _SHA: moved NET_ ShieldedVM,HypHost,HypVM to SHA_
::	2021.12.16.0 [rvi] _SHA: fix SHA_SDDC when command was never installed
::	2021.12.09.0 [we] _SHA: fix SHA_SDDC
::	2021.12.05.0 [we] #_# _SHA: add SHA_SMS per GetSmsLogs.psm1
::	2021.11.29.0 [we] #_# moving NET_CSVspace, NET_MPIO, NET_msDSM to SHA
::	2021.11.10.0 [we] #_# replaced all 'Get-WmiObject' with 'Get-CimInstance' to be compatible with PowerShell v7
::	2021.10.26.0 [we] #_# add MSCluster; add CollectSHA_SDDCLog by calling external psSDP scripts
	ex.1: .\TSSv2.ps1 -Start -Scenario SHA_MSCluster
	ex.2: .\TSSv2.ps1 -CollectLog SHA_SDDC
#>

#region --- Define local SHA Variables
$global:TssVerDateSHA= "2023.05.17.0"
#$OSVER3 		= $global:OSVersion.build
if ($global:OSVersion.Build -ge 18362) {$FrutiExe = $global:ScriptFolder + "\BIN\fruti_1903.exe"} else {$FrutiExe = $global:ScriptFolder + "\BIN\fruti_RS1.exe"}
if ($global:OSVersion.Build -eq 9200) {$VmlTrace_exe = $global:ScriptFolder + "\BIN\VmlTrace_2012.exe"}else{$VmlTrace_exe = $global:ScriptFolder + "\BIN\VmlTrace.exe"}
#endregion --- Define local SHA Variables

#region --- ETW component trace Providers ---

<# Normal trace -> data will be collected in a sign
 $SHA_TEST1Providers = @(
 	'{CC85922F-DB41-11D2-9244-006008269001}' # LSA
 	'{6B510852-3583-4E2D-AFFE-A67F9F223438}' # Kerberos
 )

# Normal trace with multi etl files
$SHA_TEST3Providers = @(
	'{98BF1CD3-583E-4926-95EE-A61BF3F46470}!CertCli'
	'{6A71D062-9AFE-4F35-AD08-52134F85DFB9}!CertificationAuthority'
)
#>

$SHA_DummyProviders = @(	#for components without a tracing GUID
	#'{eb004a05-9b1a-11d4-9123-0050047759bc}' # Dummy tcp for switches without tracing GUID (issue #70)
)
$SHA_VMLProviders 	= $SHA_DummyProviders

$SHA_ATAPortProviders = @(
	'{cb587ad1-cc35-4ef1-ad93-36cc82a2d319}' # Microsoft-Windows-ATAPort
	'{d08bd885-501e-489a-bac6-b7d24bfe6bbf}' # ataport guid
)

$SHA_CDROMProviders = @(
	'{9b6123dc-9af6-4430-80d7-7d36f054fb9f}' # Microsoft-Windows-CDROM
	'{A4196372-C3C4-42D5-87BF-7EDB2E9BCC27}' # cdrom.sys
	'{944a000f-5f60-4e5a-86fd-d55b84b543e9}' # WPP_GUID_UDFD
	'{6B1DB052-734F-4E23-AF5E-6CD8AE459F98}' # WPP_GUID_UDFS
	'{F8036571-42D9-480A-BABB-DE7833CB059C}' # IMAPI2FS Tracing
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9D}' # IMAPI2 Concatenate Stream
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E91}' # IMAPI2 Disc Master
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E93}' # IMAPI2 Disc Recorder
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E92}' # IMAPI2 Disc Recorder Enumerator
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E90}' # IMAPI2 dll
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9E}' # IMAPI2 Interleave Stream
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E97}' # IMAPI2 Media Eraser
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9F}' # IMAPI2 MSF
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7EA0}' # IMAPI2 Multisession Sequential
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9C}' # IMAPI2 Pseudo-Random Stream
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9A}' # IMAPI2 Raw CD Writer
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E98}' # IMAPI2 Standard Data Writer
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E99}' # IMAPI2 Track-at-Once CD Writer
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E94}' # IMAPI2 Utilities
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E96}' # IMAPI2 Write Engine
	'{0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9B}' # IMAPI2 Zero Stream
)

$SHA_COMProviders = @(
	'{B46FA1AD-B22D-4362-B072-9F5BA07B046D}' # COMSVCS
	'{BDA92AE8-9F11-4D49-BA1D-A4C2ABCA692E}' # OLE32
	'{9474A749-A98D-4F52-9F45-5B20247E4F01}' # DCOMSCM
	'{9474A749-A98D-4F52-9F45-5B20247E4F01}' # DCOMSCM
	'{A0C4702B-51F7-4EA9-9C74-E39952C694B8}' # COMADMIN
)

$SHA_CSVFSProviders = @(
	'{0cfda7f5-7549-575e-d095-dcc1e4fbaa3f}' # Microsoft.Windows.Server.CsvFsCritical
	'{4e6177a5-c0a7-4d9b-a686-56ed5435a908}' # nflttrc
	'{B421540C-1FC8-4c24-90CC-C5166E1DE302}' # CSVFLT
	'{d82dba12-8b70-49ee-b844-44d0885951d2}' # CSVFLT
	'{4e6177a5-c0a7-4d9b-a686-56ed5435a904}' # VBus
	'{af14af06-a558-4ff0-a061-9080e33212d6}' # CsvCache
	'{151D3C03-E442-4C4F-AF20-BD48FF41F793}' # Microsoft-Windows-FailoverClustering-CsvFlt-Diagnostic
	'{6a86ae90-4e9b-4186-b1d1-9ce0e02bcbc1}' # Microsoft-Windows-FailoverClustering-CsvFs-Diagnostic
)

$SHA_CSVspaceProviders = @(
	'{595F7F52-C90A-4026-A125-8EB5E083F15E}' # "Microsoft-Windows-StorageSpaces-Driver"
	'{929C083B-4C64-410A-BFD4-8CA1B6FCE362}' # Spaceport
	'{E7D0AD21-B086-406D-BE46-A701A86A5F0A}' # SpTelemetry
)

$SHA_DedupProviders = @(
	'{F9FE3908-44B8-48D9-9A32-5A763FF5ED79}' # Microsoft-Windows-Deduplication
	'{1D5E499D-739C-45A6-A3E1-8CBE0A352BEB}' # Microsoft-Windows-Deduplication-Change
	'{5ebb59d1-4739-4e45-872d-b8703956d84b}' # SrmTracingProviderGuid
	'{c503ed7b-d3d1-421b-97cd-22f4e7445f2a}' # Microsoft.Windows.Deduplication.Service
	'{c503ed7b-d3d1-421b-97cd-22f4e7455f2a}' # Microsoft.Windows.Deduplication.Pipeline/Store/DataPort/Scanner
	'{611b641a-8c01-449b-ab5b-a9f18adc4e3c}' # DdpFltLogGuid
	'{767c881e-f7f5-418e-a428-a113c3a8630a}' # DdpFltTraceGuid
)

$SHA_FltmgrProviders = @(
	'{4F5D14A2-97BB-454B-B848-6F3CE0DF80F1}' # FltMgr
	'{FD66A680-C052-4375-8CC9-225F923CEF88}' # FltMgrTelemetryProvider
	'{F3C5E28E-63F6-49C7-A204-E48A1BC4B09D}' # Microsoft-Windows-FilterManager
)

$SHA_FSRMProviders = @(
	'{39af31ab-064d-494b-a0f7-cc90215bdac0}' # Microsoft.Windows.FSRM
	'{3201c659-d580-4833-b17d-1adaf643c64c}' # SrmTracingProviderGuid
	'{6e82d70f-403d-4194-b724-85109b2f2028}' # SrmTracingEventGuid
	'{1214600f-df79-4a03-94f5-65d7cab4fd16}' # Quota
	'{DB4A5343-AC92-4B83-9D84-7ED8FADD7AA5}' # Datascrn
	'{1C7BC728-8199-48BE-BD4D-406A63303C8D}' # Cbafilt
	'{F3C5E28E-63F6-49C7-A204-E48A1BC4B09D}' # Microsoft-Windows-FilterManager
)

$SHA_HyperVProviders = @(
	'{AE7E4D1D-16C7-4807-A2E4-980EDF16D031}' # Microsoft.Windows.HyperV.SysprepProvider
	'{949B9EDC-ADDA-4712-A3E7-D2DCA33E84E8}' # Microsoft.Windows.HyperV.UpgradeComplianceCheck
	'{4DDF50D0-75DE-4FBE-8F08-F8936638E7A1}' # Microsoft.Windows.HyperV.Management
	'{85A7888C-4EF7-5C56-643F-FBD6DC10FEBE}' # Microsoft.Windows.HyperV.KvpExchange
	'{d90b9468-67f0-5b3b-42cc-82ac81ffd960}' # Microsoft.Windows.Subsystem.Lxss
	'{b99cdb5a-039c-5046-e672-1a0de0a40211}' # Microsoft.Windows.Lxss.Manager
	'{06C601B3-6957-4F8C-A15F-74875B24429D}' # Microsoft.Windows.HyperV.Worker
	'{7568b40b-dc66-5a30-55a1-d0ef61b56ac8}' # Microsoft.Windows.HyperV.Worker.Intercepts
	'{5e01db5e-1944-5314-c040-c90b965ea3d3}' # Microsoft.Windows.HyperV.Worker.MemoryManager
	'{1111450B-DACC-40A3-84AB-F7DBA4A6E63A}' # Microsoft.Windows.HyperV.VID
	'{5931D877-4860-4ee7-A95C-610A5F0D1407}' # Microsoft-Windows-Hyper-V-VID
	'{f83552c4-a4e8-50f7-b2d4-a9705c474490}' # Microsoft.Windows.HyperV.TimeSync
	'{a20b1fd7-ac6e-4e79-81c9-23b3c5e97444}' # Microsoft.Windows.HyperV.PCIProxy
	'{b2ed3bdb-cd74-5b2c-f660-85079ca074b3}' # Microsoft.Windows.HyperV.Socket
	'{544d0787-9f6d-432e-8414-e035a8b0541d}' # Microsoft.Windows.HyperV.Storvsp
	'{8dfb8c22-55c0-494d-8c75-a4cc35b0c535}' # Microsoft.Windows.HyperV.Vsmb
	'{2174371b-d5f6-422b-bfc4-bb6f97ddaa84}' # Microsoft.Windows.HyperV.Storage
	'{D0E4BC17-34C7-43fc-9A72-D89A59D6979A}' # Microsoft.Windows.HostNetworkingService.PrivateCloudPlugin
	'{6C28C7E5-331B-4437-9C69-5352A2F7F296}' # Microsoft-Windows-Hyper-V-VmsIf
	'{67DC0D66-3695-47C0-9642-33F76F7BD7AD}' # Microsoft.Windows.Hyper-V.VmSwitch
	'{152FBE4B-C7AD-4f68-BADA-A4FCC1464F6C}' # Microsoft.Windows.Hyper-V.NetVsc
	'{93f693dc-9163-4dee-af64-d855218af242}' # Microsoft-Windows-Hyper-V-NetMgmt
	'{0b4745b0-c990-4780-965a-391afd9424b8}' # Microsoft.Windows.HyperV.NetworkMigrationPlugin
	'{F20F4146-DB1D-4FE8-8C86-49BF5CF7390D}' # L2BridgeTraceLoggingProvider
	'{0c885e0d-6eb6-476c-a048-2457eed3a5c1}' # Microsoft-Windows-Host-Network-Service
	'{f5bf2dc5-fd9c-546d-f37b-9cbe631a065b}' # Microsoft.Windows.HyperV.DynamicMemory
	'{4f542162-e9cf-5eca-7f74-1fb63a59a6c2}' # Microsoft.Windows.HyperV.GuestCrashDump
	'{a572eeb4-c3f7-5b0e-b669-bb200931d134}' # Microsoft.Windows.HyperV.Worker.VmbusPipeIO
	'{51ddfa29-d5c8-4803-be4b-2ecb715570fe}' # Microsoft-Windows-Virtualization-Worker
	'{e5ea3ca6-5eb0-597d-504a-2fd09ccdefda}' # ICVdevDeviceEtwTrace
	'{339aad0a-4124-4968-8147-4cbbb1f8b3d5}' # Microsoft-Windows-Virtualization-UiDevices
	'{13eae551-76ca-4ddc-b974-d3a0f8d44a03}' # Microsoft-Windows-Virtualization-Tpm
	'{7b0ea079-e3bc-424a-b2f0-e3d8478d204b}' # Microsoft-Windows-VStack-VSmb
	'{4D20DF22-E177-4514-A369-F1759FEEDEB3}' # Microsoft-Windows-VIRTDISK
	'{EDACD782-2564-4497-ADE6-7199377850F2}' # Microsoft-Windows-VStack-SynthStor
	'{6c3e21aa-36c0-5476-818a-3d71fc67c9e8}' # Microsoft-Windows-Hyper-V-NvmeDirect
	'{8f9df503-1d12-49ec-bb28-f6ec42d361d4}' # Microsoft-Windows-Virtualization-serial
	'{c29c4fb7-b60e-4fff-9af9-cf21f9b09a34}' # Microsoft-Windows-VStack-SynthNic
	'{a86e166e-7d3c-402d-8fe0-2a3e62c93864}' # Microsoft-Windows-Virtualization-Worker-GPUP
	'{B1D080A6-F3A5-42F6-B6F1-B9FD86C088DA}' # Microsoft-Windows-Hyper-V-DynMem
	'{c7c9e4f7-c41d-5c68-f104-d72a920016c7}' # Microsoft-Windows-Hyper-V-CrashDump
	'{de9ba731-7f33-4f44-98c9-6cac856b9f83}' # Microsoft-Windows-Virtualization-Chipset
	'{02f3a5e3-e742-4720-85a5-f64c4184e511}' # Microsoft-Windows-Virtualization-Config
	'{17103E3F-3C6E-4677-BB17-3B267EB5BE57}' # Microsoft-Windows-Hyper-V-Compute
	'{45F54D37-2377-4B64-B396-370E31ACB204}' # Microsoft-Windows-Hyper-V-ComputeCExec
	'{AF7FD3A7-B248-460C-A9F5-FEC39EF8468C}' # Microsoft-Windows-Hyper-V-ComputeLib
	'{6066F867-7CA1-4418-85FD-36E3F9C0600C}' # Microsoft-Windows-Hyper-V-VMMS
	'{0461BE3C-BC15-4BAD-9A9E-51F3FADFEC75}' # Microsoft-Windows-FailoverClustering-WMIProvider
	'{FF3E7036-643F-430F-B015-2933466FF0FD}' # Microsoft-Windows-FailoverClustering-WMI
	'{177D1599-9764-4E3A-BF9A-C86887AADDCE}' # Microsoft-Windows-Hyper-V-VmbusVdev
	'{09242393-1349-4F4D-9FD7-59CC79F553CE}' # Microsoft-Windows-Hyper-V-EmulatedNic
	'{2ED5C5DF-6026-4E25-9FB1-9A08701125F3}' # Microsoft.Windows.HyperV.VMBus
	'{2B74A015-3873-4C56-9928-EA80C58B2787}' # Heartbeat VDEV (vmicheartbeat)
	'{1CEB22B1-97FF-4703-BEB2-333EB89B522A}' # Microsoft-Windows-Hyper-V-VMSP (VM security process implementation)
	'{AE3F5BF8-AB9F-56D6-29C8-8C312E2FAEC2}' # Microsoft-Windows-Hyper-V-Virtual-PMEM
	'{DA5A028B-B248-4A75-B60A-024FE6457484}' # Microsoft-Windows-Hyper-V-EmulatedDevices
	'{6537FFDF-5765-517E-C03C-55A8E5A97C10}' # Microsoft-Windows-Hyper-V-KernelInt
	'{52FC89F8-995E-434C-A91E-199986449890}' # Microsoft-Windows-Hyper-V-Hypervisor
	'{82DA50E7-D261-4BD1-BBB9-3213E0EFE360}' # Microsoft.Windows.HyperV.MigrationPlugin
	'{C3A331B2-AF4F-5472-FD2F-4313035C4E77}' # Microsoft.Windows.HyperV.GpupVDev
	'{06C601B3-6957-4F8C-A15F-74875B24429D}' # VmwpTelemetryProvider (VmWpStateChange)
	'{8B0287F8-755D-4BC8-BD76-4CE327C4B78B}' # Microsoft-Windows-Hyper-V-WorkerManager
	'{9193A773-E60D-4171-8468-05C000581B71}' # Image Management Service (vhdsvc)
	'{0A18FF18-5362-4739-9671-78023D747B70}' # Virtual Network Management Service (nvspwmi)
	'{86E15E01-EDF1-4AC7-89CF-B19563FD6894}' # Emulated Storage VDEV (emulatedstor)
	'{82D60869-5ADA-4D49-B76A-309B09666584}' # KVP Exchange VDEV (vmickvpexchange)
	'{BC714241-8EDC-4CE3-8714-AA0B51F98FDF}' # Shutdown VDEV (vmicshutdown)
	'{F152DC14-A3A0-4258-BECE-69A3EE4C2DE8}' # Time Synchronization VDEV (vmictimesync)
	'{67E605EE-A4D8-4C46-AE50-893F31E13963}' # VSS VDEV (vmicvss)
	'{64E92ABC-910C-4770-BD9C-C3C54699B8F9}' # Clustering Resource DLL (vmclusres)
	'{5B621A17-3B58-4D03-94F0-314F4E9C79AE}' # Synthetic Fibre Channel VDEV (synthfcvdev)
	'{6357c13a-2eb3-4b91-b580-79682eb76986}' # Virtual FibreChannel Management Service (fcvspwmi)
	'{2ab5188c-5915-4629-9f8f-b3b20c78d1b0}' # VM Memory-Preserving Host Update DLL (vmphu)
	'{573a8439-2c0f-450b-bf98-51a86843d700}' # Dynamic Memory (guest)
	'{F96ABC17-6A5E-4A49-A3F4-A2A86FA03846}' # storvsc (guest)
	'{CB5B2C18-AD73-4EBF-8AF1-73B30B885030}' # VMBus (guest)
)

$SHA_HypVmBusProviders = @(
	'{F2E2CE31-0E8A-4E46-A03B-2E0FE97E93C2}' # Microsoft-Windows-Hyper-V-Guest-Drivers-Vmbus
	'{CB5B2C18-AD73-4EBF-8AF1-73B30B885030}' # VMBusDriverTraceGuid
	'{FA3F78FF-BA6D-4EDE-96B2-9C5BB803E3BA}' # Microsoft-Windows-Hyper-V-KMCL
)

$SHA_HypVmmsProviders = @(
	'{6066F867-7CA1-4418-85FD-36E3F9C0600C}' # Microsoft-Windows-Hyper-V-VMMS
)

$SHA_HypVmWpProviders = @(
	'{51ddfa29-d5c8-4803-be4b-2ecb715570fe}' # Microsoft-Windows-Hyper-V-Worker
	'{06C601B3-6957-4F8C-A15F-74875B24429D}' # VmwpTelemetryProvider
	'{5E01DB5E-1944-5314-C040-C90B965EA3D3}' # WorkerMemManagerProvider
)
	
$SHA_iSCSIProviders = @(
	'{1babefb4-59cb-49e5-9698-fd38ac830a91}' # iScsi
	'{13953C6E-C594-414E-8BA7-DEB4BA1878E3}' # Microsoft-Windows-iSCSITarget-Service
	'{07ABD211-DA70-4F8F-B3EF-BF825FD7B189}' # Microsoft-Windows-iSCSITarget-VSSProvider
	'{82FB2F8C-A21C-453B-ACBD-7EF49493D727}' # WinTargetWPP
	'{7D758B3E-E29E-43DA-8683-9860A1C19362}' # Microsoft-Windows-iSCSITarget-VDSProvider
	'{BBF8051F-1F47-44CA-AC73-92658CD4E4F8}' # WTLmDrvCtrlGuid
	'{B5E70289-982D-4109-BC5E-BF554BAD08F5}' # WTSmisProviderWPP
	'{81C84CFA-C80B-47A1-BECE-5CA0F1851FEB}' # WTVssProviderWPP
)

$SHA_MPIOProviders = @(
	'{8E9AC05F-13FD-4507-85CD-B47ADC105FF6}' # Storage - MPIO
	'{8B86727C-E587-4B89-8FC5-D1F24D43F69C}' # StorPort
	'{FA8DE7C4-ACDE-4443-9994-C4E2359A9EDB}' # Storage - ClassPnP
)

$SHA_MsClusterProviders = @(	# was $UEX_FailoverClusteringProviders
	'{9F7FE238-9505-4B84-8B33-268C9204268E}' # Microsoft.Windows.Clustering.ClusterResource
	'{50d577a6-b3e7-4642-9e4d-05200376a5cf}' # Microsoft.Windows.Server.FailoverClustering.Failure
	'{f40422bd-f483-449a-99c7-c4546950112c}' # Microsoft.Windows.Server.FailoverClusteringDevelop
	'{3122168f-2432-45f0-b91c-3af363c14999}' # ClusApiTraceLogProvider
	'{8bdb2a89-5d40-4a5f-afd8-8b1e0ce3abc9}' # Microsoft-Windows-WSDR
	'{baf908ea-3421-4ca9-9b84-6689b8c6f85f}' # Microsoft-Windows-FailoverClustering
	'{a82fda5d-745f-409c-b0fe-18ae0678a0e0}' # Microsoft-Windows-FailoverClustering-Client
	'{0DAD9561-2E3B-49BB-93D7-B49603BA6173}' # DVFLT
	'{b529c110-72ba-4e7f-8ba7-366e3f5faeb0}' # Microsoft.Windows.Clustering.WmiProvider
	'{282968B4-215F-4568-B4A5-C2E5467C301E}' # Microsoft.Windows.Clustering.ClusterService
	'{60431de6-ecae-4926-8e10-0918d219a0a1}' # Microsoft.Windows.Server.FailoverClustering.Set.Critical
	'{49F59745-7F56-4082-A01A-83BC089D1ADD}' # Microsoft.Windows.Health
	'{372968B4-215F-4568-B4A5-C2E5467C301E}' # Microsoft.Windows.Clustering.EbodTargetMgr
	'{1de9cea2-60ce-49fa-a8b7-84139ac12b31}' # Microsoft.Windows.Clustering.S2DCache
	'{0461be3c-bc15-4bad-9a9e-51f3fadfec75}' # Microsoft-Windows-FailoverClustering-WMIProvider	# included in SHA_HyperV
	'{ff3e7036-643f-430f-b015-2933466ff0fd}' # Microsoft-Windows-FailoverClustering-WMI			# included in SHA_HyperV
	'{11B3C6B7-E06F-4191-BBB9-7099FFF55614}' # Microsoft-Windows-FailoverClustering-Manager
	'{f0a43898-4017-4d3b-acac-ff7fb8ac63cd}' # Microsoft-Windows-Health
	'{C1FCCEB3-3F19-42A9-95B9-27B550FA1FBA}' # Microsoft-Windows-FailoverClustering-NetFt
	'{10629806-46F2-4366-9092-53025E067E8C}' # Microsoft-Windows-ClusterAwareUpdating
	'{9B9E93D6-5569-4179-8C8A-5201CB2B9536}' # Microsoft-Windows-ClusterAwareUpdating-Management
	'{7FEF367F-E76C-4592-9912-E12B36A99780}' # Microsoft-Windows-FailoverClustering-ClusDisk-Diagnostic
	'{5d9e8ca1-8634-457b-8d0b-3ba944bc2ff0}' # Microsoft-Windows-FailoverClustering-TargetMgr-Diagnostic
	'{6F0771DD-4096-4E5E-A549-FC1238F5A1B2}' # Microsoft-Windows-FailoverClustering-ClusTflt-Diagnostic
	'{29c07d0e-e5a0-4e85-a004-1f668531ce22}' # Microsoft-Windows-FailoverClustering-Clusport-Diagnostic
	'{4339CD79-93D6-4F55-A96A-F7762E8AF2DE}' # Microsoft-Windows-FailoverClustering-ClusPflt-Diagnostic
	'{40CB8729-8896-4CAB-90E0-2A3AEBA730C2}' # Microsoft-Windows-FailoverClustering-ClusHflt-Diagnostic
	'{E68AB9C0-49F4-4786-A6E0-F323E0BE590C}' # Microsoft-Windows-FailoverClustering-ClusDflt-Diagnostic
	'{53A840C4-8E2B-4D39-A3F6-708834AA4620}' # Microsoft-Windows-FailoverClustering-ClusCflt-Diagnostic
	'{923BCB94-58D2-42BE-BBA9-B1315F363838}' # Microsoft-Windows-FailoverClustering-ClusBflt-Diagnostic
	'{0ac0708a-a44e-49ef-aa7e-fbe8ccc603a6}' # Microsoft-Windows-FailoverClustering-SoftwareStorageBusTarget
	'{7F8DA3B5-A58F-481E-9637-D41435AE6D8B}' # Microsoft-Windows-SDDC-Management
	'{6e580567-c67c-4b96-934e-fc2996e103ae}' # ClusDiskLogger									# included in SHA_Storage
	'{BBB672F4-E56A-4529-90C0-1421E27DE4BE}' # svhdxpr
	'{b6c164c7-4152-4b94-af14-0dac3d0556a3}' # StorageQoSTraceGuid
	'{7e66368d-b895-45f2-811f-fb37940421a6}' # NETFT
	'{8a391cc0-6303-4a25-833f-e7db345941d6}' # VBus
	'{f8f6ae53-b3b3-451f-b204-6b62550efb5c}' # cbflt
	'{EB94F195-9596-49EC-825D-6329F48BD6E9}' # cdflt
	'{7ba7dbd4-e7a9-47db-ac47-4ac1182a82f5}' # cbflt
	'{88AE0E2D-0377-48A1-85C5-FBCC32ACB6BA}' # SddcResGuid
	'{4FA1102E,CC1D,4509,A69F,121E2CC96F9C}' # SddcWmiGuid
	'{FEBD78F8-DDC5-484D-848C-982F1F483278}' # Microsoft-Windows-FailoverClustering-Replication
)
<#
#separated: 
$SHA_MsClusterProviders += @(
	$SHA_iSCSIProviders
	$SHA_MPIOProviders 	# included in SHA_StorageProvider
	$SHA_msDSMProviders 
	$SHA_StorageReplicaProviders 
	$SHA_StorageSpaceProviders 
	$SHA_StorportProviders 
	$SHA_StorageProviders # includes SHA_iSCSI, SHA_MPIO
)
#>

$SHA_MSDSMProviders = @(
	'{DEDADFF5-F99F-4600-B8C9-2D4D9B806B5B}' # Storage - MSDSM
	'{C9C5D896-6FA9-49CD-9BFD-BF5C232C1124}' # MsdsmTraceLoggingProvider
	'{CBC7357A-D802-4950-BB14-817EAD7E0176}' # Reliability DataVerFilter
)

$SHA_NFSProviders = @(	# NET_NFScli + NET_NFSsrv
	'{3c33d8b3-66fa-4427-a31b-f7dfa429d78f}' # NfsSvrNfsGuid
	'{fc33d8b3-66fa-4427-a31b-f7dfa429d78f}' # NfsSvrNfsGuid2
	'{57294EFD-C387-4e08-9144-2028E8A5CB1A}' # NfsSvrNlmGuid
	'{CC9A5284-CC3E-4567-B3F6-3EB24E7CFEC5}' # MsNfsFltGuid
	'{f3bb9731-1d9f-4b8e-a42e-203bf1a32300}' # Nfs4SvrGuid
	'{53c16bac-175c-440b-a266-1e5d5f38313b}' # OncRpcXdrGuid
	'{94B45058-6F59-4696-B6BC-B23B7768343D}' # rpcxdr
	'{e18a05dc-cce3-4093-b5ad-211e4c798a0d}' # PortMapGuid
	'{355c2284-61cb-47bb-8407-4be72b5577b0}' # NfsRdrGuid
	'{6361f674-c2c0-4f6b-ae19-8c62f47ae3fb}' # NfsClientGuid
	'{c4c52165-ad74-4b70-b62f-a8d35a135e7a}' # NfsClientGuid
	'{746A1133-BC1E-47c7-8C95-3D52C39114F9}' # Microsoft-Windows-ServicesForNFS-Client
	'{6E1CBBE9-8C4B-4003-90E2-0C2D599A3EDC}' # Microsoft-Windows-ServicesForNFS-Portmapper
	'{F450221A-07E5-403A-A396-73923DFB2CAD}' # Microsoft-Windows-ServicesForNFS-NFSServerService
	'{3D888EE4-5A93-4633-91E7-FFF8AFD89A7B}' # Microsoft-Windows-ServicesForNFS-ONCRPC
	'{A0CC474A-06CA-427C-BDFF-84733163E262}' # Microsoft-Windows-ServicesForNFS-Cluster
)

$SHA_NTFSProviders = @(
	'{B2FC00C4-2941-4D11-983B-B16E8AA4E25D}' # NtfsLog
	'{DD70BC80-EF44-421B-8AC3-CD31DA613A4E}' # Ntfs
	'{E9B319E4-0030-40A7-91CB-04D6A8EF7E09}' # Microsoft-Windows-Ntfs-SQM
	'{8E6A5303-A4CE-498F-AFDB-E03A8A82B077}' # Microsoft-Windows-Ntfs-UBPM
)

$SHA_RPCProviders = @(
	'{272A979B-34B5-48EC-94F5-7225A59C85A0}' # Microsoft-Windows-RPC-Proxy-LBS
	'{879B2576-39D1-4C0F-80A4-CC086E02548C}' # Microsoft-Windows-RPC-Proxy
	'{536CAA1F-798D-4CDB-A987-05F79A9F457E}' # Microsoft-Windows-RPC-LBS
	'{6AD52B32-D609-4BE9-AE07-CE8DAE937E39}' # Microsoft-Windows-RPC 
	'{F4AED7C7-A898-4627-B053-44A7CAA12FCD}' # Microsoft-Windows-RPC-Events
	'{D8975F88-7DDB-4ED0-91BF-3ADF48C48E0C}' # Microsoft-Windows-RPCSS
)

$SHA_ReFSProviders = @(
	'{CD9C6198-BF73-4106-803B-C17D26559018}' # Microsoft-Windows-ReFS
	'{740F3C34-57DF-4BAD-8EEA-72AC69AD5DF5}' # RefsWppTrace
	'{059F0F37-910E-4FF0-A7EE-AE8D49DD319B}' # Microsoft-Windows-ReFS-v1
	'{6D2FD9C5-8BD8-4A5D-8AA8-01E5C3B2AE23}' # Refsv1WppTrace
	'{F9A81F79-369B-443C-9428-FC1DD98316F6}' # Microsoft.Windows.FileSystem.ReFSUtil
	'{61D5C496-C69B-5B72-DE0A-29248A17CACE}' # RefsTelemetryProvider
	'{036647D2-2FB0-4E32-8349-3F5C19C16E5E}' # ReFS
	'{740F3C34-57DF-4BAD-8EEA-72AC69AD5DF5}' # Ntfs_ProtogonWmiLog
	'{AF20A152-62E5-4AA3-A264-48EB87549B75}' # Microsoft-Windows-Minstore-v1
)

$SHA_ShieldedVMProviders = @(
	'{7DEE1FDC-FFA8-4087-912A-95189D6A2D7F}' # Microsoft-Windows-HostGuardianService-Client
	'{0F39F1F2-65CC-4164-83B9-9BCADEDBAF18}' # Microsoft-Windows-ShieldedVM-ProvisioningService
	'{5D0B0AB2-1640-40E4-81F6-05403AF6C38B}' # Microsoft-Windows-ShieldedVM-ProvisioningSecureProcess
	'{5D487FAD-104B-5CA6-CA4E-14C206850501}' # Microsoft-Windows-HostGuardianClient-Service
)

$SHA_StorageProviders = @(
	'{F96ABC17-6A5E-4A49-A3F4-A2A86FA03846}' # StorVspDriverTraceGuid (SAN shotgun)
	'{8B86727C-E587-4B89-8FC5-D1F24D43F69C}' # StorPort (SAN shotgun)
	'{8E9AC05F-13FD-4507-85CD-B47ADC105FF6}' # Storage - MPIO (SAN shotgun)
	'{DEDADFF5-F99F-4600-B8C9-2D4D9B806B5B}' # Storage - MSDSM (SAN shotgun)
	'{1BABEFB4-59CB-49E5-9698-FD38AC830A91}' # iScsi (SAN shotgun)
	'{945186BF-3DD6-4F3F-9C8E-9EDD3FC9D558}' # Storage - Disk Class Driver Tracing Provider (SAN shotgun)
	'{FA8DE7C4-ACDE-4443-9994-C4E2359A9EDB}' # Storage - ClassPnP Driver Tracing Provider (SAN shotgun)
	#'{13953C6E-C594-414E-8BA7-DEB4BA1878E3}' # Microsoft-Windows-iSCSITarget-Service (SAN shotgun) # excluded on purpose?
	'{467C1914-37F0-4C7D-B6DB-5CD7DFE7BD5E}' # Mountmgr
	'{E3BAC9F8-27BE-4823-8D7F-1CC320C05FA7}' # Microsoft-Windows-MountMgr
	'{F5204334-1420-479B-8389-54A4A6BF6EF8}' # VolMgr
	'{9f7b5df4-b902-48bc-bc94-95068c6c7d26}' # Microsoft-Windows-Volume
	'{0BEE3BC5-A50C-4EC3-A0E0-5AD11F2455A3}' # Partmgr
	'{da58fbef-c209-4bee-84ed-027c421f31bf}' # Volsnap(wpp)
	'{67FE2216-727A-40CB-94B2-C02211EDB34A}' # Microsoft-Windows-VolumeSnapshot-Driver
	'{CB017CD2-1F37-4E65-82BC-3E91F6A37559}' # Volsnap(manifest based)
	'{6E580567-C67C-4B96-934E-FC2996E103AE}' # ClusDiskLogger
	'{C9C5D896-6FA9-49CD-9BFD-BF5C232C1124}' # Microsoft.Windows.Storage.Msdsm
	'{2CC00407-E9D9-4B5E-A760-F4217C9B0170}' # Microsoft.Windows.Storage.Mpio
	'{cc7b00d3-75c9-42cc-ae56-bf6d66a9d15d}' # Microsoft-Windows-MultipathIoControlDriver
	'{9282168F-2432-45F0-B91C-3AF363C149DD}' # StorageWMI
	'{1B992FD1-0CDD-4D6A-B55E-08C61E78D2C2}' # Microsoft.Windows.Storage.MiSpace
)

$SHA_StorageSenseProviders = @(
	'{3A245D5A-F00F-48F6-A94B-C51CDD290F18}' # 
	'{830A1F34-7797-4E31-9B75-C82056330051}' # 
	'{AEA3A1A8-EA43-4802-B750-2DD678910779}' # StorageServiceProvider
	'{B7AFA6AF-AAAB-4F50-B7DC-B61D4DDBE34F}' # Microsoft.Windows.Analog.Shell.SystemSettings.SettingsAppActivity
	'{057597DF-6FD8-438B-BF6D-190CBF0A914C}' # 
)

$SHA_StorageSpaceProviders = @(
	'{595f7f52-c90a-4026-a125-8eb5e083f15e}' # Microsoft-Windows-StorageSpaces-Driver
	'{aa4c798d-d91b-4b07-a013-787f5803d6fc}' # Microsoft-Windows-StorageSpaces-ManagementAgent
	'{69c8ca7e-1adf-472b-ba4c-a0485986b9f6}' # Microsoft-Windows-StorageSpaces-SpaceManager
	'{A9C7961E-96A0-4E3F-9066-7734A13101C1}' # Microsoft.Windows.Storage.SpaceControl
	'{0254f21f-4809-477e-ad36-c812a8c631a1}' # Microsoft.Windows.Storage.Spaceman
	'{e7d0ad21-b086-406d-be46-a701a86a5f0a}' # Microsoft.Windows.Storage.Spaceport
	'{929c083b-4c64-410a-bfd4-8ca1b6fce362}' # Spaceport
)

$SHA_StorageReplicaProviders = @(
	'{35a2925c-30a3-43eb-b737-03e9659955e2}' # Microsoft-Windows-StorageReplica-Cluster
	'{f661b376-6e59-4483-89f8-d5aca1816ead}' # Microsoft-Windows-StorageReplica
	'{ce171fd7-a5ba-4d95-926b-6dc4d89e8171}' # Microsoft-Windows-StorageReplica-Service
	'{fadca505-ad5e-47a8-9047-b3888ba4a8fc}' # WvrCimGuid
	'{634af965-fe67-49cf-8268-af99f62d1a3e}' # WvrFltGuid
	'{8e37fc9c-8656-46da-b40d-34d97a532d09}' # WvrFltGuid
	'{0e0d5a31-e93f-40d6-83bb-e7663a4f54e3}' # Microsoft.Windows.Server.StorageReplicaCritical
)

$SHA_StorportProviders = @(
	'{8B86727C-E587-4B89-8FC5-D1F24D43F69C}' # storport
	'{4EEB8774-6C4C-492F-8F2F-5EE4721B7BF7}' # Microsoft.Windows.Storage.Storport
	'{C4636A1E-7986-4646-BF10-7BC3B4A76E8E}' # Microsoft-Windows-StorPort
)

$SHA_StorsvcProviders = @(
	'{AEA3A1A8-EA43-4802-B750-2DD678910779}' # StorageServiceProvider
	'{A963A23C-0058-521D-71EC-A1CCE6173F21}' # Microsoft-Windows-Storsvc	
)

$SHA_USBProviders = @(
	'{C88A4EF5-D048-4013-9408-E04B7DB2814A}' # Microsoft-Windows-USB-USBPORT
	'{7426a56b-e2d5-4b30-bdef-b31815c1a74a}' # Microsoft-Windows-USB-USBHUB
	'{D75AEDBE-CFCD-42B9-94AB-F47B224245DD}' # usbport
	'{B10D03B8-E1F6-47F5-AFC2-0FA0779B8188}' # usbhub
	'{30e1d284-5d88-459c-83fd-6345b39b19ec}' # Microsoft-Windows-USB-USBXHCI
	'{36da592d-e43a-4e28-af6f-4bc57c5a11e8}' # Microsoft-Windows-USB-UCX
	'{AC52AD17-CC01-4F85-8DF5-4DCE4333C99B}' # Microsoft-Windows-USB-USBHUB3
	'{6E6CC2C5-8110-490E-9905-9F2ED700E455}' # USBHUB3
	'{6fb6e467-9ed4-4b73-8c22-70b97e22c7d9}' # UCX
	'{9F7711DD-29AD-C1EE-1B1B-B52A0118A54C}' # USBXHCI
	'{04b3644b-27ca-4cac-9243-29bed5c91cf9}' # UsbNotificationTask
	'{468D9E9D-07F5-4537-B650-98389559206E}' # UFX01000
	'{8650230d-68b0-476e-93ed-634490dce145}' # SynopsysWPPGuid
	'{B83729F3-8D84-4BEA-897B-CD9FD667BA01}' # UsbFnChipidea
	'{0CBB6922-F6B6-4ACA-8BF0-81624B491364}' # UsbdTraceGuid
	'{bc6c9364-fc67-42c5-acf7-abed3b12ecc6}' # USBCCGP
	'{3BBABCCA-A210-4570-B501-0E34D88A88FB}' # SDFUSBXHCI
	'{f3006b12-1d83-48d2-948d-6bcd002c14dc}' # UDEHID
	# There are too many GUIDs for USB. So need review on which GUIDs is helpful.
)

$SHA_VDSProviders = @(
	'{012F855E-CC34-4DA0-895F-07AF2826C03E}' # VDS
	'{EAD10F56-E9D4-4B29-A44F-C97299DE5085}' # Microsoft.Windows.Storage.VDS.Service
	'{F5204334-1420-479B-8389-54A4A6BF6EF8}' # volmgr
	'{945186BF-3DD6-4F3F-9C8E-9EDD3FC9D558}' # WPP_GUID_DISK
	'{467C1914-37F0-4C7D-B6DB-5CD7DFE7BD5E}' # Mount Manager Trace
	'{A8169755-BD1C-49a4-B346-4602BCB940AA}' # DISKMGMT
	'{EAD10F56-E9D4-4B29-A44F-C97299DE5086}' # Microsoft.Windows.Storage.DiskManagement
	'{EAD10F56-E9D4-4B29-A44F-C97299DE5088}' # Microsoft.Windows.Storage.DiskRaid
	'{EAD10F56-E9D4-4B29-A44F-C97299DE5090}' # Microsoft.Windows.Storage.VDS.BasicDisk
)

$SHA_VHDMPProviders = @(
	'{A9AB8791-8619-4FFF-9F24-E1BB60075972}' # Microsoft-Windows-Hyper-V-VHDMP(WinBlue)
	'{3C70C3B0-2FAE-41D3-B68D-8F7FCAF79ADB}' # Microsoft-Windows-Hyper-V-VHDMP
	'{e14dcdd9-d1ec-4dc3-8395-a606df8ef115}' # virtdisk
	'{9193A773-E60D-4171-8468-05C000581B71}' # Image Management Service (vhdsvc)
	'{f96abc17-6a5e-4a49-a3f4-a2a86fa03846}' # storvsp
	'{52323364-b587-4b4c-9293-ca9904a5c04f}' # storqosflt
)

$SHA_VmConfigProviders = @(
	'{02f3a5e3-e742-4720-85a5-f64c4184e511}' # Microsoft-Windows-Hyper-V-Config
)

$SHA_VMMProviders = @(
	'{43526B7E-9EE3-41A7-B023-D586F355C00B}' # Microsoft-VirtualMachineManager-Debug
)

$SHA_VSSProviders = @(
	'{9138500E-3648-4EDB-AA4C-859E9F7B7C38}' # VSS tracing provider
	'{77D8F687-8130-4A14-B8A6-3B922E05B99C}' # VSS tracing event
	'{f3625a85-421c-4a1e-a54f-6b65c0276c1c}' # VirtualBus
	'{6407345b-94f2-44c8-b3db-4e076be46816}' # WPP_GUID_ASR
	'{89300202-3cec-4981-9171-19f59559e0f2}' # Microsoft-Windows-FileShareShadowCopyProvider
	'{a0d45273-3386-4f3a-b344-0d8fee74e06a}' # Microsoft-Windows-FileShareShadowCopyAgent
	'{67FE2216-727A-40CB-94B2-C02211EDB34A}' # Microsoft-Windows-VolumeSnapshot-Driver
	'{CB017CD2-1F37-4E65-82BC-3E91F6A37559}' # Volsnap(manifest based)
	'{060172E8-4F15-45D3-9774-0BD258DF6AB4}' # FileShareSnapshotLog
	'{07ABD211-DA70-4F8F-B3EF-BF825FD7B189}' # Microsoft-Windows-iSCSITarget-VSSProvider
	'{9122168F-2432-45F0-B91C-3AF363C149DD}' # VSSTraceLogProvider
	'{C8723CFF-B58C-4D16-89CF-FE45B0505CD7}' # DPS: VssArchivalAgent
	'{B4660A01-86A0-56A2-525D-595CDCC0DC4D}' # Microsoft.Windows.Wintarget.VSSProvider
	'{67E605EE-A4D8-4C46-AE50-893F31E13963}' # Microsoft-Windows-Hyper-V-Integration-VSS
)

$SHA_WSBProviders = @(
	'{6B1DB052-734F-4E23-AF5E-6CD8AE459F98}' # WPP_GUID_UDFS
	'{944a000f-5f60-4e5a-86fd-d55b84b543e9}' # WPP_GUID_UDFD
	'{6407345b-94f2-44c8-b3db-4e076be46816}' # WPP_GUID_ASR
	'{7e9fb43e-a801-430c-9f36-c1146a51ed07}' # WPP_GUID_DSM
	'{4B966436-6781-4906-8035-9AF94B32C3F7}' # WPP_GUID_SPP
	'{1DB28F2E-8F80-4027-8C5A-A11F7F10F62D}' # Microsoft-Windows-Backup
	'{5602c36e-b813-49d1-a1aa-a0c2d43b4f38}' # BLB
	'{864d2d93-276f-4a88-8bce-d8d174e39c4d}' # Microsoft.Windows.SystemImageBackup.Engine
	'{9138500E-3648-4EDB-AA4C-859E9F7B7C38}' # VSS tracing provider
	'{67FE2216-727A-40CB-94B2-C02211EDB34A}' # Microsoft-Windows-VolumeSnapshot-Driver
	'{CB017CD2-1F37-4E65-82BC-3E91F6A37559}' # Volsnap(manifest based)
)

#endregion --- ETW component trace Providers


#region --- Scenario definitions ---  
$SHA_ScenarioTraceList = [Ordered]@{
	"SHA_HypHost"   = "PSR, SDP:HyperV, LBFO,NDIS,VmSwitch,SMBcli,SMBsrv,VMM,HyperV-Host,VMbus,Vmms,VmWp,VmConfig, ETL log(s), VMM-debug, PerfMon:SMB, trace scenario=NetConnection"
	"SHA_HypVM"     = "PSR, SDP:Net, NET_NDIS,HypVM,HyperV-VirtualMachine ETL log(s), trace scenario=InternetClient_dbg"
	"SHA_MScluster" = "PSR, SDP:Cluster, MsCluster,CSVFS,StorPort,AfdTcp,LBFo,iSCSI,-MPIO,-msDSM,-StorageReplica,-StorageSpace,-Storport,-Storage ETL log(s), Perfmon:ALL, trace scenario=NetConnection"
}

$SHA_General_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_Dummy' = $true
	'CommonTask NET' = $True  ## <------ the commontask can take one of "Dev", "NET", "ADS", "UEX", "DnD" and "SHA", or "Full" or "Mini"
	'NetshScenario InternetClient_dbg' = $true
	'Procmon' = $true
	#'WPR General' = $true
	'PerfMon ALL' = $true
	'PSR' = $true
	'Video' = $true
	'SDP Cluster' = $True
	'xray' = $True
	'CollectComponentLog' = $True
}

$SHA_HypHost_ETWTracingSwitchesStatus = [Ordered]@{
	'SHA_HypVmBus' = $true
	'SHA_HypVmms' = $true
	'SHA_HypVmWp' = $true
	'SHA_VMM' = $true
	'SHA_VmConfig' = $true
	'NET_LBFo' = $true
	'NET_NDIS' = $true
	'NET_VmSwitch' = $true
	'NET_SMBcli' = $true
	'NET_SMBsrv' = $true
	'CommonTask SHA' = $True 
	'NetshScenario NetConnection capturetype=both correlation=disabled' = $true
	'PerfMon SMB' = $true
	'PSR' = $true
	'SDP HyperV' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 
 $SHA_HypVM_ETWTracingSwitchesStatus = [Ordered]@{
	'NET_HypVM' = $true
	'NET_NDIS' = $true
	'CommonTask SHA' = $True 
	'NetshScenario InternetClient_dbg' = $true
	'PSR' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
 
$SHA_MScluster_ETWTracingSwitchesStatus = [Ordered]@{
	'SHA_MsCluster' = $true
	'SHA_iSCSI' = $true
	'SHA_MPIO' = $true
	'SHA_msDSM' = $true
	'SHA_StorageReplica' = $true
	'SHA_StorageSpace' = $true
	'SHA_CSVFS' = $true
	'SHA_StorPort' = $true
	'SHA_Storage' = $true
	'NET_LBFo' = $true
	'CommonTask SHA' = $True 
	'NetshScenario NetConnection' = $true
	'PerfMon ALL' = $true
	#'Procmon' = $true
	'PSR' = $true
	#'Video' = $true
	'SDP Cluster' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }
#endregion --- Scenario definitions ---

#region --- performance counters ---
$SHA_SupportedPerfCounter = @{
	'SHA_HyperV' = 'General counters + counter for Hyper-V'
}
$SHA_HyperVCounters = @(
	$global:HyperVCounters
	# Others => Comment out when you want to add
	#'\Hyper-V Dynamic Memory Integration Service(*)\*'
	#'\Hyper-V Hypervisor(*)\*'
	#'\Hyper-V Replica VM(*)\*'
	#'\Hyper-V Virtual Machine Bus(*)\*'
	#'\Hyper-V Virtual Machine Health Summary(*)\*'
	#'\Hyper-V VM Remoting(*)\*'
	#'\Hyper-V VM Save, Snapshot, and Restore(*)\*'
)
#endregion --- performance counters ---

<#
Switch (FwGetProductTypeFromReg)
{
	"WinNT" {
		$SHA_MyScenarioTest_ETWTracingSwitchesStatus = [Ordered]@{
			'SHA_TEST1' = $true
			'SHA_TEST2' = $true
			'SHA_TEST3' = $true   # Multi files
			'UEX_Task' = $True   # Outside of this module
		}
	}
	"ServerNT" {
		$SHA_MyScenarioTest_ETWTracingSwitchesStatus = [Ordered]@{
			'SHA_TEST1' = $true
			'SHA_TEST2' = $true
		}
	}
	"LanmanNT" {
		$SHA_MyScenarioTest_ETWTracingSwitchesStatus = [Ordered]@{
			'SHA_TEST1' = $true
			'SHA_TEST2' = $true
		}
	}
	Default {
		$SHA_MyScenarioTest_ETWTracingSwitchesStatus = [Ordered]@{
			'SHA_TEST1' = $true
			'SHA_TEST2' = $true
		}
	}
}
#>


#region ### Pre-Start / Post-Stop / Collect functions for trace components and scenarios 
function SHA_start_common_tasks {
	#collect info for all tss runs at _Start_
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "___switch Mini: $global:Mini" "cyan"
	if ($global:Mini -ne $true) {
		FwGetSysInfo _Start_
		FwGetSVC _Start_
		FwGetSVCactive _Start_ 
		FwGetTaskList _Start_
		FwGetSrvWkstaInfo _Start_
		FwGetNltestDomInfo _Start_
		FwGetDFScache _Start_
		FwGetKlist _Start_ 
		FwGetBuildInfo
		if ($global:noClearCache -ne $true) { FwClearCaches _Start_ } else { LogInfo "[$($MyInvocation.MyCommand.Name) skip FwClearCaches" }
		FwGetRegList _Start_
		FwGetPoolmon _Start_
		FwGetSrvRole
	}
	FwGetLogmanInfo _Start_
	LogInfoFile "___ SHA_start_common_tasks DONE"
	EndFunc $MyInvocation.MyCommand.Name
}
function SHA_stop_common_tasks {
	#collect info for all tss runs at _Stop_
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:Mini -ne $true) {
		FwGetDFScache _Stop_
		FwGetSVC _Stop_
		FwGetSVCactive _Stop_ 
		FwGetTaskList _Stop_
		FwGetKlist _Stop_
		FwGetDSregCmd
		FwGetPowerCfg
		FwGetHotfix
		FwGetPoolmon _Stop_
		FwGetLogmanInfo _Stop_
		FwGetNltestDomInfo _Stop_
		FwGetRegList _Stop_
		("System", "Application") | ForEach-Object { FwAddEvtLog $_ _Stop_}
		FwGetEvtLogList _Stop_
	}
	FwGetSrvWkstaInfo _Stop_
	FwGetRegHives _Stop_
	LogInfoFile "___ SHA_stop_common_tasks DONE"
	EndFunc $MyInvocation.MyCommand.Name
}

function SHA_HypHostPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwGetNetAdapter _Start_
	FwFwGetVMNetAdapter _Start_
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectSHA_HypHostLog {
	EnterFunc $MyInvocation.MyCommand.Name
	($EvtLogsShaHypHost, $global:EvtLogsSMBcli ) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	if ($global:OSVersion.Build -gt 9600) { $global:EvtLogsSMBcliOpt | ForEach-Object { FwAddEvtLog $_ _Stop_} }
	FwAddRegItem @("HyperV") _Stop_
	FwGetNetAdapter _Stop_
	FwGetVMNetAdapter _Stop_
	LogInfo "[$($MyInvocation.MyCommand.Name)] exporting the Hyper-V configuration"
	Invoke-Command -ScriptBlock { Get-VMHost | Export-Clixml -LiteralPath $global:LogFolder\$($LogPrefix)HyperV_Config.xml }
	EndFunc $MyInvocation.MyCommand.Name
}

function SHA_HypVMPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwSetEventLog "Microsoft-Windows-Hyper-V-NETVSC/Diagnostic"
	LogInfo "[$($MyInvocation.MyCommand.Name)] *** [Hint] Consider running FRUTI.exe for Hyper-V replication issues."
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectSHA_HypVMLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwResetEventLog @("Microsoft-Windows-Hyper-V-NETVSC/Diagnostic")
	("Microsoft-Windows-Hyper-V-NETVSC/Diagnostic") | ForEach-Object { FwAddEvtLog $_ _Stop_}
	EndFunc $MyInvocation.MyCommand.Name
}

Function Register_SDDC{
	EnterFunc $MyInvocation.MyCommand.Name
	$ispresent = get-command Get-PCStorageDiagnosticInfo -ErrorAction SilentlyContinue
	if ($null -eq $ispresent) {
			$module = 'PrivateCloud.DiagnosticInfo'; $branch = 'master'
			#Remove old version
			if (Test-Path $env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\$module) {
				Remove-Item -Recurse $env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\$module -ErrorAction Stop
				Remove-Module $module -ErrorAction SilentlyContinue
			}

			$md = "$env:ProgramFiles\WindowsPowerShell\Modules"
		   	Copy-Item -Recurse $global:ScriptFolder\psSDP\Diag\global\PrivateCloud.DiagnosticInfo $md -Force -ErrorAction Stop

			$ispresent = get-command Get-PCStorageDiagnosticInfo -ErrorAction SilentlyContinue
	} 
	EndFunc $MyInvocation.MyCommand.Name
}

### Data Collection
Function CollectSHA_SDDCLog{
	# invokes external script for PrivateCloud.DiagnosticInfo
	EnterFunc $MyInvocation.MyCommand.Name
	Register_SDDC
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling GetSddcDiagnosticInfo.ps1"
	if (Test-Path -path "$global:ScriptFolder\psSDP\Diag\global\GetSddcDiagnosticInfo.ps1") {
		LogInfoFile "--- $(Get-Date -Format 'HH:mm:ss') ..starting .\psSDP\Diag\global\GetSddcDiagnosticInfo.ps1 -WriteToPath $global:LogFolder\HealthTest -ZipPrefix $global:LogFolder\_Sddc-Diag"
		& Get-PCStorageDiagnosticInfo -WriteToPath $global:LogFolder\HealthTest -ZipPrefix $global:LogFolder\_Sddc-Diag
		#& "$global:ScriptFolder\psSDP\Diag\global\GetSddcDiagnosticInfo.ps1" -WriteToPath $global:LogFolder\HealthTest -ZipPrefix $global:LogFolder\_Sddc-Diag
		LogInfoFile "--- $(Get-Date -Format 'HH:mm:ss') ...Finished SDDC Diagnostics Data (PrivateCloud.DiagnosticInfo)"
		LogInfo "[$($MyInvocation.MyCommand.Name)] . Done GetSddcDiagnosticInfo.ps1"
	} else { LogWarn "Script GetSddcDiagnosticInfo.ps1 not found!" cyan} 

	# SpaceDB ChkSpace
	if ((!$global:IsLiteMode) -and (Test-Path  $global:SpaceDBPath)){ 
		LogInfo "[$($MyInvocation.MyCommand.Name)] . calling spacedb Chkspace"
		$outFile = $PrefixTime + "SPACEDB_Chkspace" +".txt"
		$Commands = @(
						"$global:SpaceDBPath Chkspace| Out-File -Append $outfile")
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		LogInfo "[$($MyInvocation.MyCommand.Name)] running SpaceDB Chkspace"
	}
	else {
		LogInfo "[$($MyInvocation.MyCommand.Name)] skipped SpaceDB Chkspace"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function SHA_MsClusterScenarioPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	#_# if "%_LiveDmp_analytic%" equ "1" call :Start_LiveDump_Analytic_logs
	EndFunc $MyInvocation.MyCommand.Name
}
Function CollectSHA_MsClusterScenarioLog{
	EnterFunc $MyInvocation.MyCommand.Name
	#_# if "%_LiveDmp_analytic%" equ "1" call :Stop_LiveDump_Analytic_logs
	GetClusterRegHives _Stop_

	LogInfo "[$($MyInvocation.MyCommand.Name)] Running Cluster GetLogs from all nodes "
	$GetLogsPath = $global:LogFolder + "\ClusterLogs"
	
	.\scripts\tss_Cluster_GetLogs.ps1 -LogPath $GetLogsPath

	EndFunc $MyInvocation.MyCommand.Name
}

function CollectSHA_ShieldedVMLog {
	EnterFunc $MyInvocation.MyCommand.Name
	$Commands = @(
		"Get-HgsTrace -RunDiagnostics -Detailed -Path $global:LogFolder\ShieldedVM"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	($EvtLogsShieldedVm) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectSHA_SmsLog{
	# invokes external script GetSmsLogs.psm1 until fully integrated into TSSv2
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		$Global:fServerSKU = (Get-CimInstance -Class CIM_OperatingSystem -ErrorAction Stop).Caption -like "*Server*"
	}Catch{
		LogException "An exception happened in Get-CimInstance for CIM_OperatingSystem" $_ $fLogFileOnly
		$Global:fServerSKU = $False
	}
	if ($Global:fServerSKU) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] . calling GetSmsLogs.psm1"
		Import-Module .\scripts\GetSmsLogs.psm1 -DisableNameChecking
		Get-SmsLogs -Path $global:LogFolder #-AcceptEula
		LogInfo "[$($MyInvocation.MyCommand.Name)] . Done GetSmsLogs.psm1"
	} else { LogWarn " Computer $env:Computername is not running Server SKU"}
	EndFunc $MyInvocation.MyCommand.Name
}

Function SHA_VMLPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:Mode -iMatch "Verbose") {
		LogInfo ".. will restart the Hyper-V service now with script tss_VMLVerbosity.ps1 -set 'Verbose'"
		.\scripts\tss_VMLverbosity.ps1 -set "Verbose"
	}
	if (!$global:IsLiteMode){
		LogInfo ".. starting $VmlTrace_exe $global:VmltraceCmd in circular mode"	# _VmltraceCmd is defined in tss_config.cfg
		$Commands = @(
			"$VmlTrace_exe $global:VmltraceCmd /l $PrefixTime`Vmltrace.etl /n ms_VmlTraceSession 2>&1 | Out-File -Append $global:ErrorLogFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		if ($global:OSVersion.Build -ge 14393) {
			$outFile = $PrefixTime + "FRuti.txt"
			#LogInfo ".. starting $frutiExe /t /LN 1001 /f /v /lp $outFile"
			# START !_FrutiExe! /t /LN 1001 /f /v /lp !_PrefixT!FRuti.txt
			$ArgumentList = " /t /LN 1001 /f /v /lp `"$outFile`""
			LogInfo ".. starting $frutiExe $ArgumentList"
			$global:FrutiExeProc = Start-Process -FilePath $FrutiExe -ArgumentList $ArgumentList -PassThru
				
			#$Commands = @(	"$frutiExe /t /LN 1001 /f /v /lp $outFile | Out-File -Append $global:ErrorLogFile")
			#RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		}
	}else{ LogInfo "Skipping Start of $VmlTrace_exe and $FrutiExe in Lite mode"}
	LogInfo " .. will start dummy SHA_VMLtrace.etl"
	EndFunc $MyInvocation.MyCommand.Name
}
Function CollectSHA_VMLLog{
	EnterFunc $MyInvocation.MyCommand.Name

	if (!$global:IsLiteMode){
		LogInfo ".. stoppping and converting VmlTrace.etl"
		$Commands = @(
			"$VmlTrace_exe /s /n ms_VmlTraceSession 2>&1 | Out-File -Append $global:ErrorLogFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		if ($global:OSVersion.Build -ge 14393) {
			#Ending Fruti trace session
			LogInfo ".. running LogMan stop FrutiLog -ets"
			$global:FrutiExeProc = Start-Process -FilePath "logman.exe" -ArgumentList "stop FrutiLog -ets"

			if(Test-path "$PrefixTime`Vmltrace.etl") {
				$Commands = @("netsh trace convert $PrefixTime`Vmltrace.etl 2>&1 | Out-File -Append $global:ErrorLogFile")
				RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
			}
		}
	}else{ LogInfo "Skipping Stop of $VmlTrace_exe and $FrutiExe in Lite mode"}
	if ($global:Mode -iMatch "Verbose") {
		LogInfo ".. will restart the Hyper-V service now with script tss_VMLVerbosity.ps1 -set 'Standard'"
		.\scripts\tss_VMLverbosity.ps1 -set "Standard"
	}
	EndFunc $MyInvocation.MyCommand.Name
}
	
#endregion ### Pre-Start / Post-Stop / Collect functions for trace components and scenarios 

#region --- HelperFunctions ---
function GetClusterRegHives {
	param(
		[Parameter(Mandatory=$False)]
		[String]$global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $global:TssPhase")
	if (-not (Test-Path "$PrefixCn`RegHive_Cluster.hiv")) {
		LogInfoFile "... collecting Cluster Registry Hives"
		$Commands = @(
			"REG SAVE HKLM\cluster $PrefixCn`RegHive_Cluster.hiv /Y"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}
	EndFunc $MyInvocation.MyCommand.Name
}
#endregion --- HelperFunctions ---


#region Registry Key modules for FwAddRegItem
	$global:KeysHyperV = @("HKLM:Software\Microsoft\Windows NT\CurrentVersion\Virtualization", "HKLM:System\CurrentControlSet\Services\vmsmp\Parameters")
#endregion Registry Key modules

#region groups of Eventlogs for FwAddEvtLog
	$EvtLogsShaHypHost	= @("Microsoft-Windows-Hyper-V-VMMS-Admin", "Microsoft-Windows-Hyper-V-VMMS-operational", "Microsoft-Windows-Hyper-V-Worker-Admin", "Microsoft-Windows-Hyper-V-VMMS-Networking", "Microsoft-Windows-Hyper-V-EmulatedNic-Admin", "Microsoft-Windows-Hyper-V-Hypervisor-Admin", "Microsoft-Windows-Hyper-V-Hypervisor-Operational", "Microsoft-Windows-Hyper-V-SynthNic-Admin", "Microsoft-Windows-Hyper-V-VmSwitch-Operational", "Microsoft-Windows-MsLbfoProvider/Operational")
	$EvtLogsShieldedVm	= @("Microsoft-Windows-HostGuardianService-Client/Operational", "Microsoft-Windows-HostGuardianService-Client/Admin", "Microsoft-Windows-HostGuardianService-CA/Operational", "Microsoft-Windows-HostGuardianService-CA/Admin", "Microsoft-Windows-HostGuardianService-KeyProtection/Admin", "Microsoft-Windows-HostGuardianService-KeyProtection/Operational", "Microsoft-Windows-HostGuardianService-Attestation/Admin", "Microsoft-Windows-HostGuardianService-Attestation/Operational", "Microsoft-Windows-HostGuardianClient-Service/Operational", "Microsoft-Windows-HostGuardianClient-Service/Admin")
#endregion groups of Eventlogs

Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *



# SIG # Begin signature block
# MIInvgYJKoZIhvcNAQcCoIInrzCCJ6sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCGDdBKssVAmcMi
# HEiRPb3NJ90/uFVMFdfT1d1JlKSDsaCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGZ4wghmaAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPyX3V8bzKamYD3uHXqzIf8u
# dQxmYlh5Rc43y2jvzZyrMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAF0xKIyueWfzKoXSiThF1LnKioBv/nPwotPSPO4i0XyHgrifqaVsNodrX
# 0fQunsuRGOha7/K87EaOVnbZkjOT6FiVDS63bwe2u8i8uv1PkrvuaRhdpTtRQCCw
# VKsmoFKS9EMSuXAh1MGPmgihqL23WFEMJxTrCWKv14+JVBpuCv41frnD7ND4trnO
# LXaOtl9xy7uPUz2K+eT/WPHej3Y2SCIQa/HYeIqTZlzIYfggSva0QwLqjzDDk75I
# IrLV+5uZws2q6bOjerFpOvWjXApsoq+V1KW8MBS82xr5VDS1hSJ6R3Py5IJ4fr2K
# 5Teq+7WeBkaisxtJZH31JpR1mI781aGCFygwghckBgorBgEEAYI3AwMBMYIXFDCC
# FxAGCSqGSIb3DQEHAqCCFwEwghb9AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFYBgsq
# hkiG9w0BCRABBKCCAUcEggFDMIIBPwIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCBhxAXaS2xxGTwjr5Nzut3W5E7SVvhlwmvRCoFS5A1TcQIGZGzyr5du
# GBIyMDIzMDYwNjExNDQxNi45NVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVs
# YW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046
# RkM0MS00QkQ0LUQyMjAxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNl
# cnZpY2WgghF4MIIHJzCCBQ+gAwIBAgITMwAAAbn2AA1lVE+8AwABAAABuTANBgkq
# hkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMjA5
# MjAyMDIyMTdaFw0yMzEyMTQyMDIyMTdaMIHSMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVy
# YXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkZDNDEtNEJE
# NC1EMjIwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA40k+yWH1FsfJAQJtQgg3EwXm
# 5CTI3TtUhKEhNe5sulacA2AEIu8JwmXuj/Ycc5GexFyZIg0n+pyUCYsis6Odietu
# hwCeLGIwRcL5rWxnzirFha0RVjtVjDQsJzNj7zpT/yyGDGqxp7MqlauI85ylXVKH
# xKw7F/fTI7uO+V38gEDdPqUczalP8dGNaT+v27LHRDhq3HSaQtVhL3Lnn+hOUosT
# TSHv3ZL6Zpp0B3LdWBPB6LCgQ5cPvznC/eH5/Af/BNC0L2WEDGEw7in44/3zzxbG
# RuXoGpFZe53nhFPOqnZWv7J6fVDUDq6bIwHterSychgbkHUBxzhSAmU9D9mIySqD
# FA0UJZC/PQb2guBI8PwrLQCRfbY9wM5ug+41PhFx5Y9fRRVlSxf0hSCztAXjUeJB
# LAR444cbKt9B2ZKyUBOtuYf/XwzlCuxMzkkg2Ny30bjbGo3xUX1nxY6IYyM1u+Wl
# wSabKxiXlDKGsQOgWdBNTtsWsPclfR8h+7WxstZ4GpfBunhnzIAJO2mErZVvM6+L
# i9zREKZE3O9hBDY+Nns1pNcTga7e+CAAn6u3NRMB8mi285KpwyA3AtlrVj4RP+Vv
# RXKOtjAW4e2DRBbJCM/nfnQtOm/TzqnJVSHgDfD86zmFMYVmAV7lsLIyeljT0zTI
# 90dpD/nqhhSxIhzIrJUCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBS3sDhx21hDmgmM
# TVmqtKienjVEUjAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
# KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMI
# MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAzdxns0VQdEywsrOO
# Xusk8iS/ugn6z2SS63SFmJ/1ZK3rRLNgZQunXOZ0+pz7Dx4dOSGpfQYoKnZNOpLM
# FcGHAc6bz6nqFTE2UN7AYxlSiz3nZpNduUBPc4oGd9UEtDJRq+tKO4kZkBbfRw1j
# euNUNSUYP5XKBAfJJoNq+IlBsrr/p9C9RQWioiTeV0Z+OcC2d5uxWWqHpZZqZVzk
# Bl2lZHWNLM3+jEpipzUEbhLHGU+1x+sB0HP9xThvFVeoAB/TY1mxy8k2lGc4At/m
# RWjYe6klcKyT1PM/k81baxNLdObCEhCY/GvQTRSo6iNSsElQ6FshMDFydJr8gyW4
# vUddG0tBkj7GzZ5G2485SwpRbvX/Vh6qxgIscu+7zZx4NVBC8/sYcQSSnaQSOKh9
# uNgSsGjaIIRrHF5fhn0e8CADgyxCRufp7gQVB/Xew/4qfdeAwi8luosl4VxCNr5J
# R45e7lx+TF7QbNM2iN3IjDNoeWE5+VVFk2vF57cH7JnB3ckcMi+/vW5Ij9IjPO31
# xTYbIdBWrEFKtG0pbpbxXDvOlW+hWwi/eWPGD7s2IZKVdfWzvNsE0MxSP06fM6Uc
# r/eas5TxgS5F/pHBqRblQJ4ZqbLkyIq7Zi7IqIYEK/g4aE+y017sAuQQ6HwFfXa3
# ie25i76DD0vrII9jSNZhpC3MA/0wggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZ
# AAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVa
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1
# V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9
# alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmv
# Haus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928
# jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3t
# pK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEe
# HT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26o
# ElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4C
# vEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ug
# poMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXps
# xREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0C
# AwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYE
# FCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtT
# NRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5o
# dG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBD
# AEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZW
# y4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5t
# aWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAt
# MDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0y
# My5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pc
# FLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpT
# Td2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0j
# VOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3
# +SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmR
# sqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSw
# ethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5b
# RAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmx
# aQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsX
# HRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0
# W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0
# HVUzWLOhcGbyoYIC1DCCAj0CAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFu
# ZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkZD
# NDEtNEJENC1EMjIwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloiMKAQEwBwYFKw4DAhoDFQDHYh4YeGTnwxCTPNJaScZwuN+BOqCBgzCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA
# 6Ck8YjAiGA8yMDIzMDYwNjEzMDIyNloYDzIwMjMwNjA3MTMwMjI2WjB0MDoGCisG
# AQQBhFkKBAExLDAqMAoCBQDoKTxiAgEAMAcCAQACAgIkMAcCAQACAhJUMAoCBQDo
# Ko3iAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMH
# oSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAwqt57+KMcQdkHaowd2TJ
# p6THHQ8HpF5v+7fo0gaEJiF+EmETKR+Z+ShG9PZWWet8KpFYQDbiCwJ4yvhYv8+W
# wFTFIx6TNp0Ois2wCI+UOTcAFbsSkjgD3hmA/wreNGe0/DRa8meEt9falE5b7++q
# B1u46Gllmo2ZbZs3gwbYgdwxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMAITMwAAAbn2AA1lVE+8AwABAAABuTANBglghkgBZQMEAgEF
# AKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEi
# BCBkVOrVKqn7RYczquibD0XYr7T6gl+iKp8LxfUjK6AIczCB+gYLKoZIhvcNAQkQ
# Ai8xgeowgecwgeQwgb0EIGTrRs7xbzm5MB8lUQ7e9fZotpAVyBwal3Cw6iL5+g/0
# MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAG59gAN
# ZVRPvAMAAQAAAbkwIgQgiJRAU4P8N88rOHYdQI1zoviHLnpMqWBLR3++ZRH8g54w
# DQYJKoZIhvcNAQELBQAEggIAD4zLMIov0wOhIumxlcfTPZgXxn98yW/2JJfUl7jK
# KlW7GOK/8HvYBZVoahWfRqUDkh3TS3bAn70JvxDVRIC6UCh4eUGGutw6gkydupIB
# bZMuHnTjsNy2B1m9mZ6qa3Dru+cVCRbJd2TYD8XmrVvW6sNtAIW9tVubMxc7JWJZ
# /oqrC6rO1WlHLLzfhbKxoYWC/pxyoFvO+4rhhmvDZBie6/q51xibj0vZLt00tVuw
# A/PbHVFkhL9BE4Zs2gIVh4AcA17s8qyI55Mu+GUIqR4ybWQrBHECpqLAbIqJSYZq
# WchuXumAgneTzApXUD3zdHKBZ0bSjeI68d61Aq+59aVlMhkVpedSAF6fmd0aKFdM
# B81OdNfulcGb2s8ZsNvi+crWMEgAKUC2d3BfmN1TK1rP0tn9yNQnX1+yvLiTEsIN
# 0jTmKyZMTFOFyWQmmgdUMs6oLdDmlUL46uBsyXprQXwgGj0E2F0uW9cg8+m9CpP/
# uk6HT3VqtetFBiUNHJLcsLh80/k0SIDyv19UEV1EQ9S2gF2l7zc8zyXByBeKoZa5
# cfW1LlfghxBAkyIKtNs5Y0shUg/HbHWuyvunccMOICRcMC2cum6NhQO+FT8aBfYl
# +v+L/tgUP+LzJ2jHRsN9ifJrauWNyIClxrWuYyWIprezMHuJulr52osbj/yZHXYi
# WZk=
# SIG # End signature block
