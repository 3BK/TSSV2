<#
.SYNOPSIS
	ADS Scenarios module for collecting ETW traces and various custom tracing functionality

.DESCRIPTION
	Define ETW traces for Windows ADS components 
	Add any custom tracing functinaliy for tracing ADS components.
	Use Enter-ADSModule as entry function from the calling Powershell script/module.
	Run 'Get-Help TSSv2_ADS.psm1 -full' for more detail.


.NOTES  
	Dev. Lead: milanmil
	Authors  : milanmil, waltere, atobata, wiaftrin, teterenc
	Requires : PowerShell V4(Supported from Windows 8.1/Windows Server 2012 R2)
	Version	 : see $global:TssVerDateADS

.LINK
	TSSv2 https://internal.support.services.microsoft.com/en-us/help/4619187
	ADS https://internal.support.services.microsoft.com/en-us/help/4619196
#>

<# latest changes

::   2023.05.07.0 [we] _ADS: follow _NET component/scenario logging
::   2023.04.06.0 [we] _ADS: enhance ADS_EFSProviders
::   2023.03.27.0 [ao] _ADS: fix some commands in ADS_ADDS
::   2023.03.23.0 [we] _ADS: enable full LDAPsrv logging (or -Mode Basic)
::   2023.03.22.0 [ao] _ADS: ADS_ADDS improvements
::   2023.03.16.0 [mm] _ADS: added ADS_EESummitDemo trace and scenario for demoing purposes in EE summit 2023
::   2023.03.15.0 [ao] _ADS: added ADS_ADDS trace and collectlog
::   2023.03.13.0 [tt] _ADS: added export of Secureprotocols DWORD reg key
::   2023.03.10.0 [mm] _ADS: removed "Microsoft-Windows-LAPS-Operational" 
::   2023.03.03.0 [mm] _ADS: handling exception caused by missing dsregcmd in ADSAuth trace
::   2023.02.15.0 [mm] _ADS: cleaning and improving ADS_Auth for separate container module
::   2023.02.13.1 [we] _ADS: add again Reg DotNETFramework, but now as non-recursive
::   2023.02.13.0 [mm] _ADS:removing DotNETFramework from ADS_SSL for perf reasons
::   2023.02.08.0 [we] _ADS replaced reg "NETFramework" with "DotNETFramework", added ADS_SSL scenario #894
::   2023.02.07.1 [we] _ADS: fixed ADS_AuthEx; remove duplicate definition of -noBasicLog in NET_Auth scenario
::   2023.02.04.0 [we] _FW: renamed auth_v, containerId, watchProcess, slowlogon, without prefix auth_
::   2023.02.03.1 [we] _ADS: fix 3 scenarios ADS_*Ex to invoke scenario functions; don't try 'netsh trace start' if user specifies -NetSh in ADS_Auth scenario
::   2023.02.02.0 [mm] _FW: add switch -noISEcheck; adjustments for new ADS_Auth, _ADS: integrated Auth-start/-stop scripts (v4.7) into component/scenario ADS_Auth
::   2023.01.24.0 [mm] _ADS: updating ADS_WinLAPS to use 'Netsh' = $true (instead of 'NetshScenario NetConnection' = $true)
::   2023.01.24.0 [we] _ADS: added scenarios ADS_AccountLockoutEx, ADS_AuthEx and ADS_BasicEx, which include PSR and NETSH trace; removed $ADS_KDCProviders for non-DC
::   2023.01.23.0 [we] _ADS: renamed "Microsoft-Windows-LAPS/Operational" to "Microsoft-Windows-LAPS-Operational" 
::   2023.01.19.0 [we] _ADS: add ADS_WinLAPS component/scenario
::   2023.01.18.0 [we] _ADS: put ADS_SSL System.Net.WebClient in try{} block; $ADS_DummyProviders = @()
::   2022.12.28.0 [we] _ADS: replaced/consolidated ADS_GroupPolicy with ADS_GPO
::   2022.12.27.1 [we] _ADS: remove component ADS_SBSL; adjust ADS_SSL Reg.Keys (see Git #894)
::   2022.12.07.0 [we] _ADS: add -Scenario ADS_General
::   2022.11.22.0 [mm] _ADS: updated ssl etl traces in $ADS_SSLProviders in the same way as it is done in NET module and moved from NET module to ADS 
::   2022.11.10.0 [we] _ADS: add ADS_UserInfo
::   2022.10.31.0 [we] _ADS: add User Profile Service $EvtLogsProfSvc*
::   2022.10.26.0 [we] _ADS: add 'Directory Service' EvtLog to ADS_LDAPsrv
::   2022.09.27.0 [we] _ADS: fix ADS_GroupPolicy
::   2022.08.28.0 [we] _ADS: add ADS_OCSP,ADS_SBSL
::   2022.08.24.0 [we] _ADS: ESR Remove "Microsoft-Windows-SettingSync*" & Add new CDS ETW provider 
::   2022.07.27.0 [we] _ADS: add to ADS_W32Time: w32tm.exe /query /peers /verbose
::   2022.07.27.0 [we] _ADS: updated tss_ADPerfDataCollection.ps1
::   2022.07.26.0 [we] _ADS: fixed ProcMon path in tss_ADPerfDataCollection, Warning on 'procdump lsass'
::   2022.07.18.0 [we] _ADS: add ADS_w32Time
::   2022.07.12.1 [we] _ADS: add ADS_Netlogon (included also in ADS_Auth) (issue #670)
::   2022.07.07.0 [we] _ADS: ADS_DFSr: copy only DFSR*.log and last 5 DFSR*.log.gz files (#654)
::   2022.07.05.0 [we] _ADS: add Security.evtx to ADS_AUTH (issue #659)
::   2022.05.21.0 [we] _ADS: add 'ADS_Perf' es external script tss_ADPerfDataCollection.ps1
::   2022.05.18.0 [we] _ADS: replaced *-key.txt with *reg_*.txt; replaced $($global:LogFolder)\$($global:LogPrefix) with $($PrefixTime); added FwListProcsAndSvcs
::   2022.05.16.0 [we] _ADS: replaced DSregCmd with FwGetDSregCmd
::   2022.04.14.0 [we] _ADS: avoid dsregcmd for OS < 10
::   2022.02.21.0 [we] _ADS: re-added component functions ADS_AuthPostStop and ADS_ESRPreStart, so that they could be combined with other POD scenarios
::   2022.02.06.0 [we] _ADS: defined ADS scenarios also as components (to allow combination with NET scenarios); removed '_' from provider names, moved some LogInfo into LogInfoFile, added LogInfo "[ADS Stage:] ..."
::   2022.02.01.0 [we] _ADS: changed value LspDbgInfoLevel=0x50410800, Reason: QFE 2022.1B added a new flag and without it we don’t see this final status STATUS_TRUSTED_DOMAIN_FAILURE on RODC.
::   2022.02.01.0 [we] _ADS: removed '_' in Crypto_DPAPI and NTLM_Cred for correct handling of METL traces
::   2021.12.31.1 [we] _ADS: moving NET_ components to ADS: GPedit GPmgmt GPsvc GroupPolicy Profile
::   2021.11.29.0 [we] _ADS: moving NET_ADcore, NET_ADsam, NET_BadPwd, NET_DFSR, NET_LDAPsrv, NET_LockOut to ADS
::   2021.11.10.0 [we] _ADS: replaced all 'Get-WmiObject' with 'Get-CimInstance' to be compatible with PowerShell v7
#>

$global:TssVerDateADS= "2023.05.07.0"
$global:TssVerDateAuth = "5.0"
 
$global:TLStestSite = "www.ssllabs.com" # for SSL test

#region --- ETW component trace Providers ---
#
$ADS_DummyProviders = @()
$ADS_BadPwdProviders 	= $ADS_DummyProviders
$ADS_GPeditProviders 	= $ADS_DummyProviders
$ADS_GPmgmtProviders 	= $ADS_DummyProviders
$ADS_GPsvcProviders 	= $ADS_DummyProviders
$ADS_PerfProviders		= $ADS_DummyProviders
$ADS_UserInfoProviders	= $ADS_DummyProviders

$ADS_ADDSProviders = @(
	'{1C83B2FC-C04F-11D1-8AFC-00C04FC21914}' # Active Directory Domain Services: Core; see 2826734 ADPERF: Using Active Directory (AD) Event Tracing 
)

$ADS_ADsamProviders = @(
	'{9A7D7195-B713-4092-BDC5-58F4352E9563}' # SamLib								** see 4135049 ADPERF: Tools: SAM client-side activity tracing *Windows 10 RS1 and above*
	'{1FF6B227-2CA7-40F9-9A66-980EADAA602E}' # WMI_Tracing_Guid WBEMCOMM
)

if ($global:Mode -iMatch "Basic") {
	$ADS_LDAPsrvProviders = @( 
		'{90717974-98DB-4E28-8100-E84200E22B3F}!LDAPsrvBasic!0x8!0xff' # NTDSA
	)
}else{
	$ADS_LDAPsrvProviders = @( 
		'{90717974-98DB-4E28-8100-E84200E22B3F}!LDAPsrv!0xffffffffffffffff!0xff' 
	)
}

$ADS_DFSrProviders = @(
	'{40D22086-BDFE-4893-B4C7-C10651ADB0CA}' # DFSrRoFltWmiGuid	
	'{926D226A-1D6E-4F02-B8D0-64E431C1324B}' # FrsFltWmiGuid
	'{CB25CD9F-703B-4F1B-A8F2-209E5484ACB0}' # DFSFrs
)

$ADS_NetlogonProviders = @(
	'{CA030134-54CD-4130-9177-DAE76A3C5791}' # NETLOGON/ NETLIB
	'{E5BA83F6-07D0-46B1-8BC7-7E669A1D31DC}' # Microsoft-Windows-Security-Netlogon
)

$ADS_ADCSProviders = @(  #remove varous file extension and the following characters (), .  ... as they are not allowed in logman command
	'{98BF1CD3-583E-4926-95EE-A61BF3F46470}!CertCli'				# Microsoft-Windows-CertificationAuthorityClient-CertCli
	'{6A71D062-9AFE-4F35-AD08-52134F85DFB9}!CertificationAuthority'	# Microsoft-Windows-CertificationAuthority
)
if ($global:OSVersion.Build  -gt 14393) {
	$ADS_ADCSProviders += @(
	'{A7FB5B34-C0A5-4247-A1F6-300E40ECE26B}!CertificationAuthority-EnterprisePolicy'	# Microsoft-Windows-CertificationAuthority-EnterprisePolicy # not supported on WS2016 and below
	)
}

$ADS_PKIClientProviders = @(
	'{82B5AD62-B453-481A-B838-CA1EEAE6E472}'
	'{7A688F0E-F39B-4A7A-BBBB-066E2C1FCB04}'
	'Microsoft-Windows-Security-EnterpriseData-FileRevocationManager'
	'Microsoft-Windows-EFS'
	'{9D2A53B2-1411-5C1C-D88C-F2BF057645BB}'
	'{EA3F84FC-03BB-540E-B6AA-9664F81A31FB}'
	'Microsoft-Windows-Crypto-DPAPI'
	'Microsoft-Windows-CAPI2!CAPI2!0x0000ffffffffffff'
	'Microsoft-Windows-Crypto-NCrypt'
	'Microsoft-Windows-Crypto-BCrypt'
	'Microsoft-Windows-Crypto-CNG'
	'Microsoft-Windows-Crypto-DSSEnh'
	'Microsoft-Windows-Crypto-RSAEnh'
	'{A74EFE00-14BE-4EF9-9DA9-1484D5473303}'
	'{F3A71A4B-6118-4257-8CCB-39A33BA059D4}'
	'{413E55F6-5309-4E2D-A7E7-EA98BA06EE89}'
	'{EAC19293-76ED-48C3-97D3-70D75DA61438}'
	'{84C5F702-EB27-41CB-AED2-64AA9850C3D0}'
	'{1D6540CE-A81B-4E74-AD35-EEF8463F97F5}'
	'{133A980D-035D-4E2D-B250-94577AD8FCED}'
	'{A5BFFA95-ACCA-4C18-B51C-DCA0A33A039D}'
	'{FCA9C1D0-5872-4AC2-BB61-1B64511108BA}'
	'{9B52E09F-0C58-4EAF-877F-70F9B54A7946}'
	'{80DF111F-178D-44FB-AFB4-5D179DE9D4EC}'
	'{DE5DCAEE-6F88-585A-05EE-D8B05B912772}'
)

# begining of auth providers

$ADS_NGCProviders = @(  
	'{B66B577F-AE49-5CCF-D2D7-8EB96BFD440C}!ngc!0x0'                # Microsoft.Windows.Security.NGC.KspSvc
	'{CAC8D861-7B16-5B6B-5FC0-85014776BDAC}!ngc!0x0'                # Microsoft.Windows.Security.NGC.CredProv
	'{6D7051A0-9C83-5E52-CF8F-0ECAF5D5F6FD}!ngc!0x0'                # Microsoft.Windows.Security.NGC.CryptNgc
	'{0ABA6892-455B-551D-7DA8-3A8F85225E1A}!ngc!0x0'                # Microsoft.Windows.Security.NGC.NgcCtnr
	'{9DF6A82D-5174-5EBF-842A-39947C48BF2A}!ngc!0x0'                # Microsoft.Windows.Security.NGC.NgcCtnrSvc
	'{9B223F67-67A1-5B53-9126-4593FE81DF25}!ngc!0x0'                # Microsoft.Windows.Security.NGC.KeyStaging
	'{89F392FF-EE7C-56A3-3F61-2D5B31A36935}!ngc!0x0'                # Microsoft.Windows.Security.NGC.CSP
	'{CDD94AC7-CD2F-5189-E126-2DEB1B2FACBF}!ngc!0x0'                # Microsoft.Windows.Security.NGC.LocalAccountMigPlugin
	'{1D6540CE-A81B-4E74-AD35-EEF8463F97F5}!ngc!0xffff'             # Microsoft-Windows-Security-NGC-PopKeySrv
	'{CDC6BEB9-6D78-5138-D232-D951916AB98F}!ngc!0x0'                # Microsoft.Windows.Security.NGC.NgcIsoCtnr
	'{C0B2937D-E634-56A2-1451-7D678AA3BC53}!ngc!0x0'                # Microsoft.Windows.Security.Ngc.Truslet
	'{9D4CA978-8A14-545E-C047-A45991F0E92F}!ngc!0x0'                # Microsoft.Windows.Security.NGC.Recovery
	'{3b9dbf69-e9f0-5389-d054-a94bc30e33f7}!ngc!0x0'                # Microsoft.Windows.Security.NGC.Local
	'{34646397-1635-5d14-4d2c-2febdcccf5e9}!ngc!0x0'                # Microsoft.Windows.Security.NGC.KeyCredMgr
	'{c12f629d-37d4-58f7-22a8-94ac45ad8648}!ngc!0x0'                # Microsoft.Windows.Security.NGC.Utils
	'{3A8D6942-B034-48e2-B314-F69C2B4655A3}!ngc!0xffffffff'         # TPM
	'{5AA9A3A3-97D1-472B-966B-EFE700467603}!ngc!0xffffffff'         # TPM Virtual Smartcard card simulator
	'{EAC19293-76ED-48C3-97D3-70D75DA61438}!ngc!0xffffffff'         # Cryptographic TPM Endorsement Key Services

	'{23B8D46B-67DD-40A3-B636-D43E50552C6D}!ngc!0x0'                # Microsoft-Windows-User Device Registration (event)

	'{2056054C-97A6-5AE4-B181-38BC6B58007E}!ngc!0x0'                # Microsoft.Windows.Security.DeviceLock

	'{7955d36a-450b-5e2a-a079-95876bca450a}!ngc!0x0'                # Microsoft.Windows.Security.DevCredProv
	'{c3feb5bf-1a8d-53f3-aaa8-44496392bf69}!ngc!0x0'                # Microsoft.Windows.Security.DevCredSvc
	'{78983c7d-917f-58da-e8d4-f393decf4ec0}!ngc!0x0'                # Microsoft.Windows.Security.DevCredClient
	'{36FF4C84-82A2-4B23-8BA5-A25CBDFF3410}!ngc!0x0'                # Microsoft.Windows.Security.DevCredWinRt
	'{86D5FE65-0564-4618-B90B-E146049DEBF4}!ngc!0x0'                # Microsoft.Windows.Security.DevCredTask

	'{D5A5B540-C580-4DEE-8BB4-185E34AA00C5}!ngc!0x0'                # MDM SCEP Trace
	'{9FBF7B95-0697-4935-ADA2-887BE9DF12BC}!ngc!0x0'                # Microsoft-Windows-DM-Enrollment-Provider (event)
	'{3DA494E4-0FE2-415C-B895-FB5265C5C83B}!ngc!0x0'                # Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider (event)

	'{73370BD6-85E5-430B-B60A-FEA1285808A7}!ngc!0x0'                # Microsoft-Windows-CertificateServicesClient (event)
	'{F0DB7EF8-B6F3-4005-9937-FEB77B9E1B43}!ngc!0x0'                # Microsoft-Windows-CertificateServicesClient-AutoEnrollment (event)
	'{54164045-7C50-4905-963F-E5BC1EEF0CCA}!ngc!0x0'                # Microsoft-Windows-CertificateServicesClient-CertEnroll (event)
	'{89A2278B-C662-4AFF-A06C-46AD3F220BCA}!ngc!0x0'                # Microsoft-Windows-CertificateServicesClient-CredentialRoaming (event)
	'{BC0669E1-A10D-4A78-834E-1CA3C806C93B}!ngc!0x0'                # Microsoft-Windows-CertificateServicesClient-Lifecycle-System (event)
	'{BEA18B89-126F-4155-9EE4-D36038B02680}!ngc!0x0'                # Microsoft-Windows-CertificateServicesClient-Lifecycle-User (event)
	'{B2D1F576-2E85-4489-B504-1861C40544B3}!ngc!0x0'                # Microsoft-Windows-CertificateServices-Deployment (event)
	'{98BF1CD3-583E-4926-95EE-A61BF3F46470}!ngc!0x0'                # Microsoft-Windows-CertificationAuthorityClient-CertCli (event)
	'{AF9CC194-E9A8-42BD-B0D1-834E9CFAB799}!ngc!0x0'                # Microsoft-Windows-CertPolEng (event)

	'{d0034f5e-3686-5a74-dc48-5a22dd4f3d5b}!ngc!0xFFFFFFFF'         # Microsoft.Windows.Shell.CloudExperienceHost
	'{99eb7b56-f3c6-558c-b9f6-09a33abb4c83}!ngc!0xFFFFFFFF'         # Microsoft.Windows.Shell.CloudExperienceHost.Common
	'{aa02d1a4-72d8-5f50-d425-7402ea09253a}!ngc!0x0'                # Microsoft.Windows.Shell.CloudDomainJoin.Client
	'{507C53AE-AF42-5938-AEDE-4A9D908640ED}!ngc!0x0'                # Microsoft.Windows.Security.Credentials.UserConsentVerifier

	'{02ad713f-20d4-414f-89d0-da5a6f3470a9}!ngc!0xffffffffffffffff' # Microsoft.Windows.Security.CFL.API
	'{acc49822-f0b2-49ff-bff2-1092384822b6}!ngc!0xffffffffffffffff' # Microsoft.CAndE.ADFabric.CDJ
	'{f245121c-b6d1-5f8a-ea55-498504b7379e}!ngc!0xffffffffffffffff' # Microsoft.Windows.DeviceLockSettings
)

# **NGC** **Add additional NGC providers in case it's a client and the '-v' switch is added**
if ($v) {
	if ($ProductType -eq "WinNT") {
		$ADS_NGCProviders = $ADS_NGCProviders + @(
			'{6ad52b32-d609-4be9-ae07-ce8dae937e39}!ngc!0xffffffffffffffff'	 # Microsoft-Windows-RPC
			'{f4aed7c7-a898-4627-b053-44a7caa12fcd}!ngc!0xffffffffffffffff'	 # Microsoft-Windows-RPC-Events
			'{ac01ece8-0b79-5cdb-9615-1b6a4c5fc871}!ngc!0xffffffffffffffff'	 # Microsoft.Windows.Application.Service
		)
	}
}

$ADS_BioProviders = @(
	'{34BEC984-F11F-4F1F-BB9B-3BA33C8D0132}!Bio!0xffff'
	'{225b3fed-0356-59d1-1f82-eed163299fa8}!Bio!0x0'
	'{9dadd79b-d556-53f2-67c4-129fa62b7512}!Bio!0x0'
	'{1B5106B1-7622-4740-AD81-D9C6EE74F124}!Bio!0x0'
	'{1d480c11-3870-4b19-9144-47a53cd973bd}!Bio!0x0'
	'{e60019f0-b378-42b6-a185-515914d3228c}!Bio!0x0'
	'{48CAFA6C-73AA-499C-BDD8-C0D36F84813E}!Bio!0x0'
	'{add0de40-32b0-4b58-9d5e-938b2f5c1d1f}!Bio!0x0'
	'{e92355c0-41e4-4aed-8d67-df6b2058f090}!Bio!0x0'
	'{85be49ea-38f1-4547-a604-80060202fb27}!Bio!0x0'
	'{F4183A75-20D4-479B-967D-367DBF62A058}!Bio!0x0'
	'{0279b50e-52bd-4ed6-a7fd-b683d9cdf45d}!Bio!0x0'
	'{39A5AA08-031D-4777-A32D-ED386BF03470}!Bio!0x0'
	'{22eb0808-0b6c-5cd4-5511-6a77e6e73a93}!Bio!0x0'
	'{63221D5A-4D00-4BE3-9D38-DE9AAF5D0258}!Bio!0x0'
	'{9df19cfa-e122-5343-284b-f3945ccd65b2}!Bio!0x0'
	'{beb1a719-40d1-54e5-c207-232d48ac6dea}!Bio!0x0'
	'{8A89BB02-E559-57DC-A64B-C12234B7572F}!Bio!0x0'
	'{a0e3d8ea-c34f-4419-a1db-90435b8b21d0}!Bio!0xffffffffffffffff'
)

$ADS_LSAProviders = @(
	'{D0B639E0-E650-4D1D-8F39-1580ADE72784}!lsa!0xC43EFF'               # (WPP)LsaTraceControlGuid
	'{169EC169-5B77-4A3E-9DB6-441799D5CACB}!lsa!0xffffff'               # LsaDs
	'{DAA76F6A-2D11-4399-A646-1D62B7380F15}!lsa!0xffffff'               # (WPP)LsaAuditTraceControlGuid
	'{366B218A-A5AA-4096-8131-0BDAFCC90E93}!lsa!0xfffffff'              # (WPP)LsaIsoTraceControlGuid
	'{4D9DFB91-4337-465A-A8B5-05A27D930D48}!lsa!0xff'                   # (TL)Microsoft.Windows.Security.LsaSrv
	'{7FDD167C-79E5-4403-8C84-B7C0BB9923A1}!lsa!0xFFF'                  # (WPP)VaultGlobalDebugTraceControlGuid
	'{CA030134-54CD-4130-9177-DAE76A3C5791}!lsa!0xfffffff'              # (WPP)NETLOGON
	'{5a5e5c0d-0be0-4f99-b57e-9b368dd2c76e}!lsa!0xffffffffffffffff'     # (WPP)VaultCDSTraceGuid
	'{2D45EC97-EF01-4D4F-B9ED-EE3F4D3C11F3}!lsa!0xffffffffffffffff'     # (WPP)GmsaClientTraceControlGuid
	'{C00D6865-9D89-47F1-8ACB-7777D43AC2B9}!lsa!0xffffffffffffffff'     # (WPP)CCGLaunchPadTraceControlGuid
	'{7C9FCA9A-EBF7-43FA-A10A-9E2BD242EDE6}!lsa!0xffffffffffffffff'     # (WPP)CCGTraceControlGuid
	'{794FE30E-A052-4B53-8E29-C49EF3FC8CBE}!lsa!0xffffffffffffffff'
	'{ba634d53-0db8-55c4-d406-5c57a9dd0264}!lsa!0xffffffffffffffff'     # (TL)Microsoft.Windows.Security.PasswordlessPolicy
	'{45E7DBC5-E130-5CEF-9353-CC5EBF05E6C8}!lsa!0xFFFF'                 # (EVT)Microsoft-Windows-Containers-CCG/Admin
	'{A4E69072-8572-4669-96B7-8DB1520FC93A}!lsa!0xffffffffffffffff'
	'{C5D12E1B-84A0-4fe6-9E5F-FEBA123EAE66}!lsa!0xffffffffffffffff'     # (WPP)RoamingSecurityDebugTraceControlGuid
	'{E2E66F29-4D71-4646-8E58-20E204C3C25B}!lsa!0xffffffffffffffff'     # (WPP)RoamingSecurityDebugTraceControlGuid
	'{6f2c1ee5-1dfd-519b-2d55-702756f5964d}!lsa!0xffffffffffffffff'
	'{FB093D76-8964-11DF-9EA1-CB38E0D72085}!lsa!0xFFFF'                 # (WPP)KDSSVCCtlGuid
	'{3353A14D-EE30-436E-8FF5-575A4351EA80}!lsa!0xFFFF'                 # (WPP)KDSPROVCtlGuid
	'{afda4fd8-2fe5-5c75-ba0e-7d5c0b225e12}!lsa!0xffffffffffffffff'
	'{cbb61b6d-a2cf-471a-9a58-a4cd5c08ffba}!lsa!0xff'                   # (WPP)UACLog
)

$ADS_NtLmCredSSPProviders = @(
	'{5BBB6C18-AA45-49b1-A15F-085F7ED0AA90}!NtLmCredssp!0x5ffDf'			# Security: NTLM Authentication
	'{AC69AE5B-5B21-405F-8266-4424944A43E9}!NtLmCredssp!0xffffffff'			# NtlmSharedDebugTraceControlGuid
	'{6165F3E2-AE38-45D4-9B23-6B4818758BD9}!NtLmCredssp!0xffffffff'			# Security: TSPkg
	'{AC43300D-5FCC-4800-8E99-1BD3F85F0320}!NtLmCredssp!0xffffffffffffffff'	# Microsoft-Windows-NTLM
	'{DAA6CAF5-6678-43f8-A6FE-B40EE096E06E}!NtLmCredssp!0xffffffffffffffff'	# TSClientActiveXControlTrace
	'{6165F3E2-AE38-45D4-9B23-6B4818758BD9}!NtLmCredssp!0xffffffff'			#not in auth ds\security\protocols\credssp\lsa\debug.hxx
)

$ADS_KerbProviders = @(
	'{6B510852-3583-4e2d-AFFE-A67F9F223438}!Kerb!0x7ffffff'
	'{60A7AB7A-BC57-43E9-B78A-A1D516577AE3}!Kerb!0xffffff'
	'{FACB33C4-4513-4C38-AD1E-57C1F6828FC0}!Kerb!0xffffffff'
	'{97A38277-13C0-4394-A0B2-2A70B465D64F}!Kerb!0xff'
	'{8a4fc74e-b158-4fc1-a266-f7670c6aa75d}!Kerb!0xffffffffffffffff'
	'{98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1}!Kerb!0xffffffffffffffff'
)

$ADS_KDCProviders = @(
	'{1BBA8B19-7F31-43c0-9643-6E911F79A06B}!kdc!0xfffff'
	'{f2c3d846-1d17-5388-62fa-3839e9c67c80}!kdc!0xffffffffffffffff'
	'{6C51FAD2-BA7C-49b8-BF53-E60085C13D92}!kdc!0xffffffffffffffff'
)

$ADS_SAMProviders = @(
	'{8E598056-8993-11D2-819E-0000F875A064}!Sam!0xffffffffffffffff'
	'{0D4FDC09-8C27-494A-BDA0-505E4FD8ADAE}!Sam!0xffffffffffffffff'
	'{BD8FEA17-5549-4B49-AA03-1981D16396A9}!Sam!0xffffffffffffffff'
	'{F2969C49-B484-4485-B3B0-B908DA73CEBB}!Sam!0xffffffffffffffff'
	'{548854B9-DA55-403E-B2C7-C3FE8EA02C3C}!Sam!0xffffffffffffffff'
)

$ADS_SSLProviders = @(  # this is more than in auth scripts
	'{37D2C3CD-C5D4-4587-8531-4696C44244C8}!Ssl!0xffffffffffffffff!0xff' # Ssl / Microsoft-Windows-CAPI2 - see Git #894, changed Level from 0x4000ffff to 0x7fffffff to 0xffffffffffffffff
	'{A74EFE00-14BE-4ef9-9DA9-1484D5473304}!NcryptSslp!0x7fffffff!0xff' # NcryptSslp
	'{1F678132-5938-4686-9FDC-C8FF68F15C85}!Schannel'					# Schannel
	'{91CC1150-71AA-47E2-AE18-C96E61736B6F}!Schannel'					# Microsoft-Windows-Schannel-Events	
	'{44492B72-A8E2-4F20-B0AE-F1D437657C92}!Schannel'					# Microsoft.Windows.Security.Schannel	
)

$ADS_CryptNcryptDpapiProviders = @(
	'{EA3F84FC-03BB-540e-B6AA-9664F81A31FB}!CryptNcryptDpapi!0xFFFFFFFF'
	'{A74EFE00-14BE-4ef9-9DA9-1484D5473302}!CryptNcryptDpapi!0xFFFFFFFF'
	'{A74EFE00-14BE-4ef9-9DA9-1484D5473301}!CryptNcryptDpapi!0xFFFFFFFF'
	'{A74EFE00-14BE-4ef9-9DA9-1484D5473303}!CryptNcryptDpapi!0xFFFFFFFF'
	'{A74EFE00-14BE-4ef9-9DA9-1484D5473305}!CryptNcryptDpapi!0xFFFFFFFF'
	'{786396CD-2FF3-53D3-D1CA-43E41D9FB73B}!CryptNcryptDpapi!0x0'
	'{a74efe00-14be-4ef9-9da9-1484d5473304}!CryptNcryptDpapi!0xffffffffffffffff'
	'{9d2a53b2-1411-5c1c-d88c-f2bf057645bb}!CryptNcryptDpapi!0xffffffffffffffff'

    # not in auth scripts:
	'{89FE8F40-CDCE-464E-8217-15EF97D4C7C3}!CryptNcryptDpapi!0xffffffffffffffff' # Microsoft-Windows-Crypto-DPAPI
	'{DE5DCAEE-6F88-585A-05EE-D8B05B912772}!CryptNcryptDpapi!0xffffffffffffffff' # WinVerifyTrust
	# '{5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB}!CryptNcryptDpapi!0xffffffffffffffff' # Microsoft-Windows-CAPI2 commented out as this also goes in CAPI2 evtx
)

$ADS_WebAuthProviders = @(
	'{B1108F75-3252-4b66-9239-80FD47E06494}!WebAuth!0x2FF'                  #IDCommon
	'{82c7d3df-434d-44fc-a7cc-453a8075144e}!WebAuth!0x2FF'                  #IdStoreLib
	'{D93FE84A-795E-4608-80EC-CE29A96C8658}!WebAuth!0x7FFFFFFF'             #idlisten

	'{EC3CA551-21E9-47D0-9742-1195429831BB}!WebAuth!0xFFFFFFFF'             #cloudap
	'{bb8dd8e5-3650-5ca7-4fea-46f75f152414}!WebAuth!0xffffffffffffffff'     #Microsoft.Windows.Security.CloudAp
	'{7fad10b2-2f44-5bb2-1fd5-65d92f9c7290}!WebAuth!0xffffffffffffffff'     #Microsoft.Windows.Security.CloudAp.Critical

	'{077b8c4a-e425-578d-f1ac-6fdf1220ff68}!WebAuth!0xFFFFFFFF'             #Microsoft.Windows.Security.TokenBroker
	'{7acf487e-104b-533e-f68a-a7e9b0431edb}!WebAuth!0xFFFFFFFF'             #Microsoft.Windows.Security.TokenBroker.BrowserSSO
	'{5836994d-a677-53e7-1389-588ad1420cc5}!WebAuth!0xFFFFFFFF'             #Microsoft.Windows.MicrosoftAccount.TBProvider

	'{3F8B9EF5-BBD2-4C81-B6C9-DA3CDB72D3C5}!WebAuth!0x7'                    #wlidsvc
	'{C10B942D-AE1B-4786-BC66-052E5B4BE40E}!WebAuth!0x3FF'                  #livessp
	'{05f02597-fe85-4e67-8542-69567ab8fd4f}!WebAuth!0xFFFFFFFF'             #Microsoft-Windows-LiveId, MSAClientTraceLoggingProvider

	'{74D91EC4-4680-40D2-A213-45E2D2B95F50}!WebAuth!0xFFFFFFFF'             #Microsoft.AAD.CloudAp.Provider
	'{4DE9BC9C-B27A-43C9-8994-0915F1A5E24F}!WebAuth!0xFFFFFFFF'             #Microsoft-Windows-AAD
	'{bfed9100-35d7-45d4-bfea-6c1d341d4c6b}!WebAuth!0xFFFFFFFF'             #AADPlugin
	'{556045FD-58C5-4A97-9881-B121F68B79C5}!WebAuth!0xFFFFFFFF'             #AadCloudAPPlugin
	'{F7C77B8D-3E3D-4AA5-A7C5-1DB8B20BD7F0}!WebAuth!0xFFFFFFFF'             #AadWamExtension
	'{9EBB3B15-B094-41B1-A3B8-0F141B06BADD}!WebAuth!0xFFF'                  #AadAuthHelper
	'{6ae51639-98eb-4c04-9b88-9b313abe700f}!WebAuth!0xFFFFFFFF'             #AadWamPlugin
	'{7B79E9B1-DB01-465C-AC8E-97BA9714BDA2}!WebAuth!0xFFFFFFFF'             #AadTB
	'{86510A0A-FDF4-44FC-B42F-50DD7D77D10D}!WebAuth!0xFFFFFFFF'             #AadBrokerPluginApp
	'{5A9ED43F-5126-4596-9034-1DCFEF15CD11}!WebAuth!0xFFFFFFFF'             #AadCloudAPPluginBVTs

	'{08B15CE7-C9FF-5E64-0D16-66589573C50F}!WebAuth!0xFFFFFF7F'             #Microsoft.Windows.Security.Fido

	'{5AF52B0D-E633-4ead-828A-4B85B8DAAC2B}!WebAuth!0xFFFF'                 #negoexts
	'{2A6FAF47-5449-4805-89A3-A504F3E221A6}!WebAuth!0xFFFF'                 #pku2u

	'{EF98103D-8D3A-4BEF-9DF2-2156563E64FA}!WebAuth!0xFFFF'                 #webauth
	'{2A3C6602-411E-4DC6-B138-EA19D64F5BBA}!WebAuth!0xFFFF'                 #webplatform

	'{FB6A424F-B5D6-4329-B9B5-A975B3A93EAD}!WebAuth!0x000003FF'             #wdigest

	'{2745a526-23f5-4ef1-b1eb-db8932d43330}!WebAuth!0xffffffffffffffff'     #Microsoft.Windows.Security.TrustedSignal
	'{c632d944-dddb-599f-a131-baf37bf22ef0}!WebAuth!0xffffffffffffffff'     #Microsoft.Windows.Security.NaturalAuth.Service

	'{63b6c2d2-0440-44de-a674-aa51a251b123}!WebAuth!0xFFFFFFFF'             #Microsoft.Windows.BrokerInfrastructure
	'{4180c4f7-e238-5519-338f-ec214f0b49aa}!WebAuth!0xFFFFFFFF'             #Microsoft.Windows.ResourceManager
	'{EB65A492-86C0-406A-BACE-9912D595BD69}!WebAuth!0xFFFFFFFF'             #Microsoft-Windows-AppModel-Exec
	'{d49918cf-9489-4bf1-9d7b-014d864cf71f}!WebAuth!0xFFFFFFFF'             #Microsoft-Windows-ProcessStateManager
	'{072665fb-8953-5a85-931d-d06aeab3d109}!WebAuth!0xffffffffffffffff'     #Microsoft.Windows.ProcessLifetimeManager
	'{EF00584A-2655-462C-BC24-E7DE630E7FBF}!WebAuth!0xffffffffffffffff'     #Microsoft.Windows.AppLifeCycle
	'{d48533a7-98e4-566d-4956-12474e32a680}!WebAuth!0xffffffffffffffff'     #RuntimeBrokerActivations
	'{0b618b2b-0310-431e-be64-09f4b3e3e6da}!WebAuth!0xffffffffffffffff'     #Microsoft.Windows.Security.NaturalAuth.wpp
)

# **WebAuth** **Add additional WebAuth providers in case it's a client and the -v switch is added**
if ($v) {
	if ($ProductType -eq "WinNT") {
		$ADS_WebAuthProviders = $ADS_WebAuthProviders + @(
			'{20f61733-57f1-4127-9f48-4ab7a9308ae2}!WebAuth!0xffffffffffffffff'
			'{b3a7698a-0c45-44da-b73d-e181c9b5c8e6}!WebAuth!0xffffffffffffffff'
			'{4e749B6A-667D-4C72-80EF-373EE3246B08}!WebAuth!0xffffffffffffffff'
		)
	}
}

$ADS_SmartCardProviders = @(
	'{30EAE751-411F-414C-988B-A8BFA8913F49}!SmartCard!0xffffffffffffffff'
	'{13038E47-FFEC-425D-BC69-5707708075FE}!SmartCard!0xffffffffffffffff'
	'{3FCE7C5F-FB3B-4BCE-A9D8-55CC0CE1CF01}!SmartCard!0xffffffffffffffff'
	'{FB36CAF4-582B-4604-8841-9263574C4F2C}!SmartCard!0xffffffffffffffff'
	'{133A980D-035D-4E2D-B250-94577AD8FCED}!SmartCard!0xffffffffffffffff'
	'{EED7F3C9-62BA-400E-A001-658869DF9A91}!SmartCard!0xffffffffffffffff'
	'{27BDA07D-2CC7-4F82-BC7A-A2F448AB430F}!SmartCard!0xffffffffffffffff'
	'{15DE6EAF-EE08-4DE7-9A1C-BC7534AB8465}!SmartCard!0xffffffffffffffff'
	'{31332297-E093-4B25-A489-BC9194116265}!SmartCard!0xffffffffffffffff'
	'{4fcbf664-a33a-4652-b436-9d558983d955}!SmartCard!0xffffffffffffffff'
	'{DBA0E0E0-505A-4AB6-AA3F-22F6F743B480}!SmartCard!0xffffffffffffffff'
	'{125f2cf1-2768-4d33-976e-527137d080f8}!SmartCard!0xffffffffffffffff'
	'{beffb691-61cc-4879-9cd9-ede744f6d618}!SmartCard!0xffffffffffffffff'
	'{545c1f45-614a-4c72-93a0-9535ac05c554}!SmartCard!0xffffffffffffffff'
	'{AEDD909F-41C6-401A-9E41-DFC33006AF5D}!SmartCard!0xffffffffffffffff'
	'{09AC07B9-6AC9-43BC-A50F-58419A797C69}!SmartCard!0xffffffffffffffff'
	'{AAEAC398-3028-487C-9586-44EACAD03637}!SmartCard!0xffffffffffffffff'
	'{9F650C63-9409-453C-A652-83D7185A2E83}!SmartCard!0xffffffffffffffff'
	'{F5DBD783-410E-441C-BD12-7AFB63C22DA2}!SmartCard!0xffffffffffffffff'
	'{a3c09ba3-2f62-4be5-a50f-8278a646ac9d}!SmartCard!0xffffffffffffffff'
	'{15f92702-230e-4d49-9267-8e25ae03047c}!SmartCard!0xffffffffffffffff'
	'{179f04fd-cf7a-41a6-9587-a3d22d5e39b0}!SmartCard!0xffffffffffffffff'
)

$ADS_CredprovAuthuiProviders = @(
	'{5e85651d-3ff2-4733-b0a2-e83dfa96d757}!CredprovAuthui!0xffffffffffffffff'
	'{D9F478BB-0F85-4E9B-AE0C-9343F302F9AD}!CredprovAuthui!0xffffffffffffffff'
	'{462a094c-fc89-4378-b250-de552c6872fd}!CredprovAuthui!0xffffffffffffffff'
	'{8db3086d-116f-5bed-cfd5-9afda80d28ea}!CredprovAuthui!0xffffffffffffffff'
	'{a55d5a23-1a5b-580a-2be5-d7188f43fae1}!CredprovAuthui!0xFFFF'
	'{4b8b1947-ae4d-54e2-826a-1aee78ef05b2}!CredprovAuthui!0xFFFF'
	'{176CD9C5-C90C-5471-38BA-0EEB4F7E0BD0}!CredprovAuthui!0xffffffffffffffff'
	'{3EC987DD-90E6-5877-CCB7-F27CDF6A976B}!CredprovAuthui!0xffffffffffffffff'
	'{41AD72C3-469E-5FCF-CACF-E3D278856C08}!CredprovAuthui!0xffffffffffffffff'
	'{4F7C073A-65BF-5045-7651-CC53BB272DB5}!CredprovAuthui!0xffffffffffffffff'
	'{A6C5C84D-C025-5997-0D82-E608D1ABBBEE}!CredprovAuthui!0xffffffffffffffff'
	'{C0AC3923-5CB1-5E37-EF8F-CE84D60F1C74}!CredprovAuthui!0xffffffffffffffff'
	'{DF350158-0F8F-555D-7E4F-F1151ED14299}!CredprovAuthui!0xffffffffffffffff'
	'{FB3CD94D-95EF-5A73-B35C-6C78451095EF}!CredprovAuthui!0xffffffffffffffff'
	'{d451642c-63a6-11d7-9720-00b0d03e0347}!CredprovAuthui!0xffffffffffffffff'
	'{b39b8cea-eaaa-5a74-5794-4948e222c663}!CredprovAuthui!0xffffffffffffffff'
	if(!$slowlogon){'{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}!CredprovAuthui!0xffffffffffffffff'}
	'{c2ba06e2-f7ce-44aa-9e7e-62652cdefe97}!CredprovAuthui!0xffffffffffffffff'
	'{5B4F9E61-4334-409F-B8F8-73C94A2DBA41}!CredprovAuthui!0xffffffffffffffff'
	'{a789efeb-fc8a-4c55-8301-c2d443b933c0}!CredprovAuthui!0xffffffffffffffff'
	'{301779e2-227d-4faf-ad44-664501302d03}!CredprovAuthui!0xffffffffffffffff'
	'{557D257B-180E-4AAE-8F06-86C4E46E9D00}!CredprovAuthui!0xffffffffffffffff'
	'{D33E545F-59C3-423F-9051-6DC4983393A8}!CredprovAuthui!0xffffffffffffffff'
	'{19D78D7D-476C-47B6-A484-285D1290A1F3}!CredprovAuthui!0xffffffffffffffff'
	'{EB7428F5-AB1F-4322-A4CC-1F1A9B2C5E98}!CredprovAuthui!0xffffffffffffffff'
	'{D9391D66-EE23-4568-B3FE-876580B31530}!CredprovAuthui!0xffffffffffffffff'
	'{D138F9A7-0013-46A6-ADCC-A3CE6C46525F}!CredprovAuthui!0xffffffffffffffff'
	'{2955E23C-4E0B-45CA-A181-6EE442CA1FC0}!CredprovAuthui!0xffffffffffffffff'
	'{012616AB-FF6D-4503-A6F0-EFFD0523ACE6}!CredprovAuthui!0xffffffffffffffff'
	'{5A24FCDB-1CF3-477B-B422-EF4909D51223}!CredprovAuthui!0xffffffffffffffff'
	'{63D2BB1D-E39A-41B8-9A3D-52DD06677588}!CredprovAuthui!0xffffffffffffffff'
	'{4B812E8E-9DFC-56FC-2DD2-68B683917260}!CredprovAuthui!0xffffffffffffffff'
	'{169CC90F-317A-4CFB-AF1C-25DB0B0BBE35}!CredprovAuthui!0xffffffffffffffff'
	'{041afd1b-de76-48e9-8b5c-fade631b0dd5}!CredprovAuthui!0xffffffffffffffff'
	'{39568446-adc1-48ec-8008-86c11637fc74}!CredprovAuthui!0xffffffffffffffff'
	'{d1731de9-f885-4e1f-948b-76d52702ede9}!CredprovAuthui!0xffffffffffffffff'
	'{d5272302-4e7c-45be-961c-62e1280a13db}!CredprovAuthui!0xffffffffffffffff'
	'{55f422c8-0aa0-529d-95f5-8e69b6a29c98}!CredprovAuthui!0xffffffffffffffff'
)

$ADS_AppxProviders = @(
	'{f0be35f8-237b-4814-86b5-ade51192e503}!Appx!0xffffffffffffffff'
	'{8127F6D4-59F9-4abf-8952-3E3A02073D5F}!Appx!0xffffffffffffffff'
	'{3ad13c53-cf84-4522-b349-56b81ffcd939}!Appx!0xffffffffffffffff'
	'{b89fa39d-0d71-41c6-ba55-effb40eb2098}!Appx!0xffffffffffffffff'
	'{fe762fb1-341a-4dd4-b399-be1868b3d918}!Appx!0xffffffffffffffff'
)

# **Kernel**
$ADS_kernelProviders = @(
	'{9E814AAD-3204-11D2-9A82-006008A86939}!kernel!0x0000000000000005'	# SystemTraceControlGuid 'NT Kernel Logger'
)

$ADS_NTKernelLoggerProviders = @(
	'{9E814AAD-3204-11D2-9A82-006008A86939}!kernel!0x0000000000000005'	# SystemTraceControlGuid 'NT Kernel Logger'
)

$ADS_CryptoPrimitivesProviders = @(
	'{E8ED09DC-100C-45E2-9FC8-B53399EC1F70}!CryptoPrimitives!0xffffffffffffffff' #  Microsoft-Windows-Crypto-NCrypt
	'{C7E089AC-BA2A-11E0-9AF7-68384824019B}!CryptoPrimitives!0xffffffffffffffff' #  Microsoft-Windows-Crypto-BCrypt
	'{F3A71A4B-6118-4257-8CCB-39A33BA059D4}!CryptoPrimitives!0xffffffffffffffff' #  Microsoft.Windows.Security.BCrypt
	'{E3E0E2F0-C9C5-11E0-8AB9-9EBC4824019B}!CryptoPrimitives!0xffffffffffffffff' #  Microsoft-Windows-Crypto-CNG
	'{43DAD447-735F-4829-A6FF-9829A87419FF}!CryptoPrimitives!0xffffffffffffffff' #  Microsoft-Windows-Crypto-DSSEnh
	'{152FDB2B-6E9D-4B60-B317-815D5F174C4A}!CryptoPrimitives!0xffffffffffffffff' #  Microsoft-Windows-Crypto-RSAEnh
	'{A74EFE00-14BE-4EF9-9DA9-1484D5473303}!CryptoPrimitives!0xffffffffffffffff' #  CNGTraceControlGuid
	'{413E55F6-5309-4E2D-A7E7-EA98BA06EE89}!CryptoPrimitives!0xffffffffffffffff' #  CryptXmlGlobalDebugTraceControlGuid
	'{EAC19293-76ED-48C3-97D3-70D75DA61438}!CryptoPrimitives!0xffffffffffffffff' #  WPP_CRYPTTPMEKSVC_CONTROL_GUID
	'{FCA9C1D0-5872-4AC2-BB61-1B64511108BA}!CryptoPrimitives!0xffffffffffffffff' #  AeCryptoGuid
	'{80DF111F-178D-44FB-AFB4-5D179DE9D4EC}!CryptoPrimitives!0xffffffffffffffff' #  WPP_CRYPT32_CONTROL_GUID
)

# end of auth providers


$ADS_ProfileProviders = @(
	'{89B1E9F0-5AFF-44A6-9B44-0A07A7CE5845}' # Microsoft-Windows-User Profiles Service
	'{DB00DFB6-29F9-4A9C-9B3B-1F4F9E7D9770}' # Microsoft-Windows-User Profiles General
	'{eb7428f5-ab1f-4322-a4cc-1f1a9b2c5e98}' # Profile
	'{63A3ADBE-9717-410D-A0F5-E07E68823B4D}' # ShellPerfTraceProvider
	'{6B6C257F-5643-43E8-8E5A-C66343DBC650}' # UstCommonProvider
)
 if ($global:OSVersion.Build -ge 18362) {
	$ADS_ProfileProviders += @( 
		'{9891e0a7-f966-547f-eb21-d98616bf72ee}' # Microsoft.Windows.Shell.UserProfiles
		'{9959adbd-b5ac-5758-3ffa-ee0da5b8fe4b}' # 
		'{7f1bd045-965d-4f47-b3a7-acdbcfb11ca6}' # 
		'{40654520-7460-5c90-3c10-e8b6c8b430c1}' # 
		'{d5ee9312-a511-4c0e-8b35-b6d980f6ba25}' # 
		'{04a241e7-cea7-466d-95a1-87dcf755f1b0}' # 
		'{9aed307f-a41d-40e7-9539-b8d2742578f6}' #
	)
 }

$ADS_Profile8Providers = @(			# ToDo:
	'{20c46239-d059-4214-a11e-7d6769cbe020}!Profile8!255!FF' # Microsoft-Windows-Remote-FileSystem-Log, MupLog, included in fskm
)

<#$ADS_EFSProviders = @(
	'{82B5AD62-B453-481A-B838-CA1EEAE6E472}!EFS!0xffffffffffffffff'
	'{7A688F0E-F39B-4A7A-BBBB-066E2C1FCB04}!EFS!0xffffffffffffffff'
	'{2CD58181-0BB6-463E-828A-056FF837F966}!EFS!0xffffffffffffffff'
	'{3663A992-84BE-40EA-BBA9-90C7ED544222}!EFS!0xffffffffffffffff'
)
#>
$ADS_EFSProviders = @(
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

$ADS_ShellRoamingProviders = @(
#	'{83D6E83B-900B-48A3-9835-57656B6F6474}!ShellRoaming!0xffffffffffffffff' 	# Microsoft-Windows-SettingSync 			=> replace with ADS_CDS
#	'{C1779399-4943-4610-83EC-CACE7DA7C2DF}!ShellRoaming!0xffffffffffffffff' 	# Microsoft-Windows-SettingSyncMonitorSVC 	=> replace with ADS_CDS
	'{9F973C1D-D056-4E38-84A5-7BE81CDD6AB6}!ShellRoaming!0xffffffffffffffff' 	# Microsoft-Windows-SettingSync-Azure
	'{885735DA-EFA7-4042-B9BC-195BDFA8B7E7}!ShellRoaming!0xffffffffffffffff'	# Microsoft.Windows.BackupAndRoaming.AzureSyncEngine	
	'{d1731de9-f885-4e1f-948b-76d52702ede9}!ShellRoaming!0xffffffffffffffff'	# 
	'{d5272302-4e7c-45be-961c-62e1280a13db}!ShellRoaming!0xffffffffffffffff'	# 
	'{55f422c8-0aa0-529d-95f5-8e69b6a29c98}!ShellRoaming!0xffffffffffffffff'	# 
)
$ADS_CDSProviders = @(
	'{741BB90C-A7A3-49D6-BD82-1E6B858403F7}!CDS!0xffffffffffffffff' 	# Microsoft-Windows-CloudStore
)

$ADS_CDPProviders = @(
	'{A1EA5EFC-402E-5285-3898-22A5ACCE1B76}!cdp!0xffffffffffffffff'
	'{ABB10A7F-67B4-480C-8834-8B049C428715}!cdp!0xffffffffffffffff'
	'{5fe36556-c4cd-509a-8c3e-2a547ea568ae}!cdp!0xffffffffffffffff'
	'{bc1826c8-369c-5b0b-4cd1-3c6ae5bfe2e7}!cdp!0xffffffffffffffff'
	'{9f4cc6dc-1bab-5772-0c71-a89954718d66}!cdp!0xffffffffffffffff'
	'{30ad9f59-ec19-54b2-4bdf-76dbfc7404a6}!cdp!0xffffffffffffffff'
	'{A48E7274-BB8F-520D-7E6F-1737E9D68491}!cdp!0xffffffffffffffff'
	'{833E7812-D1E2-5172-66FD-4DD4B255A3BB}!cdp!0xffffffffffffffff'
	'{D229987F-EDC3-5274-26BF-82BE01D6D97E}!cdp!0xffffffffffffffff'
	'{88cd9180-4491-4640-b571-e3bee2527943}!cdp!0xffffffffffffffff'
	'{4a16abff-346d-56dc-fa87-eb1e29fe670a}!cdp!0xffffffffffffffff'
	'{ed1640e7-9dc0-45b5-a1ef-88b70cf1742c}!cdp!0xffffffffffffffff'
	'{633383CB-D7A9-4964-876A-66B7DC98C0FE}!cdp!0xffffffffffffffff'
	'{A29339AD-B137-486C-A8F3-88C9738E5379}!cdp!0xffffffffffffffff'
	'{f06690ca-9325-5dcf-65bc-fc3164fa8acc}!cdp!0xffffffffffffffff'
)

$ADS_WinHTTPProviders = @(
	'{7D44233D-3055-4B9C-BA64-0D47CA40A232}!WinHTTP!0xffffffffffffffff'
	'{72B18662-744E-4A68-B816-8D562289A850}!WinHTTP!0xffffffffffffffff'
	'{5402E5EA-1BDD-4390-82BE-E108F1E634F5}!WinHTTP!0xffffffffffffffff'
	'{1070F044-721C-504B-C01C-671DADCBC77D}!WinHTTP!0xffffffffffffffff'
	'{7C109AC5-8971-4B39-AA88-ECF239827664}!WinHTTP!0xffffffffffffffff'
	'{ABC3A4DD-BEEF-BEEF-BEEF-E9E36E904E02}!WinHTTP!0xffffffffffffffff'
)

$ADS_CEPCESProviders = @(
	'{F64ED6BA-BD9B-4CE1-90FB-7B8765928134}!cepces!0xffffffffffffffff'	# Microsoft-Windows-EnrollmentPolicyWebService
	'{C3CBA89D-B3D1-48F1-BE6C-9B317A3CF3D5}!cepces!0xffffffffffffffff'	# Microsoft-Windows-EnrollmentWebService
)

$ADS_IISProviders = @(
	'{670080D9-742A-4187-8D16-41143D1290BD}!InetsrvIIS!0xffffffffffffffff'	# Microsoft-Windows-IIS-W3SVC-WP
	'{05448E22-93DE-4A7A-BBA5-92E27486A8BE}!InetsrvIIS!0xffffffffffffffff'	# Microsoft-Windows-IIS-W3SVC
	'Microsoft-Windows-IIS!InetsrvIIS!0xffffffffffffffff'	# Microsoft-Windows-IIS
	'{3A2A4E84-4C21-4981-AE10-3FDA0D9B0F83}!InetsrvIIS!0xffffffffffffffff'
	'{06B94D9A-B15E-456E-A4EF-37C984A2CB4B}!InetsrvIIS!0xffffffffffffffff'
	'{AFF081FE-0247-4275-9C4E-021F3DC1DA35}!InetsrvIIS!0xffffffffffffffff'
	'{7ACDCAC8-8947-F88A-E51A-24018F5129EF}!InetsrvIIS!0xffffffffffffffff'
	'{04C8A86F-3369-12F8-4769-24E484A9E725}!InetsrvIIS!0xffffffffffffffff'
	'{7EA56435-3F2F-3F63-A829-F0B35B5CAD41}!InetsrvIIS!0xffffffffffffffff'
	'{DD5EF90A-6398-47A4-AD34-4DCECDEF795F}!InetsrvIIS!0xffffffffffffffff'	# Microsoft-Windows-HttpService
	'{7B6BC78C-898B-4170-BBF8-1A469EA43FC5}!InetsrvIIS!0xffffffffffffffff'	# Microsoft-Windows-HttpEvent
)

$ADS_GPOProviders = @(
 if (!$global:StartAutologger.IsPresent) {
	'{6FC72ED3-75DA-4BC4-8365-C4228CEAEDFE}!gpo!0xffffffffffffffff'	# Microsoft.Windows.GroupPolicy.RegistryCSE
	'{C1DF9318-DA0B-4CD1-92BF-59415E6454F7}!gpo!0xffffffffffffffff'	# Microsoft.Windows.GroupPolicy.CSEs
	'{AEA1B4FA-97D1-45F2-A64C-4D69FFFD92C9}!gpo!0xffffffffffffffff'	# Microsoft-Windows-GroupPolicy
	'{BD2F4252-5E1E-49FC-9A30-F3978AD89EE2}!gpo!0xffffffffffffffff'	# Microsoft-Windows-GroupPolicyTriggerProvider
 }
)

$ADS_OCSPProviders = @(
	'{C7D49BBE-356F-4711-ADB9-32FF162CAB9E}' # Microsoft-Windows-OnlineResponderWebProxy
	'{563E23F4-74B1-40A3-BD37-202BC5711CD7}' # Microsoft-Windows-OnlineResponderRevocationProvider
	'{21B2E773-EBED-4CE1-834A-1444F9E20D6E}' # Microsoft-Windows-OnlineResponder
)

$ADS_W32TimeProviders = @(
	'{361E40D2-7B9E-51C4-DE42-A7F1E997A1D7}' # Microsoft.Windows.Shell.SystemSettings.SyncTime
	'{CFFB980E-327C-5B87-19C6-62C4C3BE2290}' # Microsoft-Windows-Time-Service-PTP-Provider
	'{D5ED0171-F751-4198-9BEE-310358EFC3DC}' # Microsoft.Windows.W32Time.PTP
	'{06EDCFEB-0FD0-4E53-ACCA-A6F8BBF81BCB}' # Microsoft-Windows-Time-Service
	'{8EE3A3BF-9379-4DAC-B376-038F498B19A4}' # Microsoft.Windows.W32Time
	'{95559226-8B1D-4B62-AC40-7176901D66F0}' # W32TimeFlightingProvider
	'{63665931-A4EE-47B3-874D-5155A5CFB415}' # AuthzTraceProvider
	'{13F3DA1B-C22C-4CB1-8C77-ED37787953E9}' # Microsoft.Windows.W32Time.Sync
)

$ADS_WinLAPSProviders = @(
	'{177720b0-e8fe-47ed-bf71-d6dbc8bd2ee7}!LAPS!0x7FFFFFFF!0xFF' # LAPSv2
)

$ADS_TESTProviders = @(
'{6B510852-3583-4e2d-AFFE-A67F9F223438}!AdsTest!0x7ffffff'  #this is in fact Kerberos, just for testing
)

$ADS_EESummitDemoProviders = @(
	'{CA030134-54CD-4130-9177-DAE76A3C5791}!netlogon' # NETLOGON/ NETLIB
	'{E5BA83F6-07D0-46B1-8BC7-7E669A1D31DC}!netlogon' # Microsoft-Windows-Security-Netlogon
	'{8EE3A3BF-9379-4DAC-B376-038F498B19A4}!w32time' # Microsoft.Windows.W32Time
)


# combinations of providers, as seen in ADS-Scenarios, in order to allow component tracing as well (in combination with other scenarios)
$ADS_BasicProviders = @(
	$ADS_BioProviders
	$ADS_CredprovAuthuiProviders
	$ADS_CryptNcryptDpapiProviders
	$ADS_CryptoPrimitivesProviders
	$ADS_EFSProviders
	$ADS_KerbProviders
	$ADS_LSAProviders
	$ADS_NGCProviders
	$ADS_NtLmCredSSPProviders
	$ADS_SmartCardProviders
	$ADS_SSLProviders
	$ADS_WebAuthProviders
 )
 if ($global:ProductType -eq "LanmanNT") {
		$ADS_BasicProviders += $ADS_KDCProviders	#only for KDC/LanmanNT
 }
$ADS_AccountLockoutProviders = @(
	$ADS_KerbProviders
	$ADS_LSAProviders
	$ADS_NtLmCredSSPProviders
	$ADS_SSLProviders
 )
  if ($global:ProductType -eq "LanmanNT") {
		$ADS_AccountLockoutProviders += $ADS_KDCProviders	#only for KDC/LanmanNT
 }
$ADS_ESRProviders = @(
	$ADS_CDPProviders
	$ADS_CDSProviders
	$ADS_ShellRoamingProviders
	$ADS_SSLProviders
	$ADS_WebAuthProviders
	$ADS_WinHTTPProviders
 )

$ADS_AuthProviders = @(
	$ADS_AppxProviders
	$ADS_BioProviders
	$ADS_CredprovAuthuiProviders
	$ADS_CryptNcryptDpapiProviders
	$ADS_KerbProviders
	$ADS_LSAProviders
	$ADS_NetlogonProviders
	$ADS_NGCProviders
	$ADS_NtLmCredSSPProviders
	$ADS_SAMProviders
	$ADS_SmartCardProviders
	$ADS_SSLProviders
	$ADS_WebAuthProviders
 )
#endregion --- ETW component trace Providers ---

#region --- Scenario definitions ---
$ADS_ScenarioTraceList = [Ordered]@{
	"ADS_AccountLockout" = "Kerb,NtLmCredSSP,KDC,SSL,LSA ETL log(s)"
	"ADS_AccountLockoutEx" = "Kerb,NtLmCredSSP,KDC,SSL,LSA ETL log(s), PSR, Netsh scenario=InternetClient_dbg"
	"ADS_Auth"       = "Netlogon,CryptoDPAPI,Kerb,NtLmCredSSP,SAM,SSL,WebAuth,SmartCard,CredprovAuthui,NGC,Bio,LSA,NTKernelLogger(only client),KDC(only DC) ETL log(s), Netsh"
	"ADS_AuthEx"     = "Netlogon,CryptoDPAPI,Kerb,NtLmCredSSP,SAM,SSL,WebAuth,SmartCard,CredprovAuthui,NGC,Bio,LSA,NTKernelLogger(only client),KDC(only DC) ETL log(s), PSR, Netsh"
	"ADS_Basic"      = "CryptoDPAPI,EFS,CryptoPrimitives,Kerb,NtLmCredSSP,KDC,SSL,WebAuth,SmartCard,CredprovAuthui,NGC,Bio,LSA ETL log(s)"
	"ADS_BasicEx"    = "CryptoDPAPI,EFS,CryptoPrimitives,Kerb,NtLmCredSSP,KDC,SSL,WebAuth,SmartCard,CredprovAuthui,NGC,Bio,LSA ETL log(s), PSR, Netsh scenario=InternetClient_dbg"
	"ADS_ESR"        = "WebAuth,ShellRoaming,CDP,WinHTTP,SSL ETL log(s)"
	"ADS_General"    = "CommonTask NET, Procmon, PerfMon ALL, PSR, Video, SDP NET, xray, Netsh scenario=InternetClient_dbg"
	"ADS_OCSP"       = "PSR,SDP Dom, OCSP,HTTP,ADS_SSL,IIS ETL log(s), Netsh scenario=NetConnection"
	"ADS_SBSL"       = "Slow Boot/Slow Logon: Profile,Netlogon,WinLogon,GPO GroupPolicy,DCLocator,GPresult,GPsvc,Auth ETL log(s), WhoAmI, -Xperf SBSLboot, Netsh scenario=NetConnection; for Boot use with -StartAutologger; def. XperfMaxFileMB=16384"
	"ADS_SSL"        =  "SSL/TLS ETL log(s), PSR, Video, Netsh"
	"ADS_WinLAPS"    = "LAPSv2 ETL log(s), ADS_Auth, Event-logs, REG, PSR, Netsh"
	"ADS_EESummitDemo"    = "ADS_EESummitDemo Trace, ADS_Kerb, PSR, Netsh"
}

$ADS_General_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_Dummy' = $true
	'CommonTask NET' = $True  ## <------ the commontask can take one of "Dev", "NET", "ADS", "UEX", "DnD" and "SHA", or "Full" or "Mini"
	'NetshScenario InternetClient_dbg' = $true
	'Procmon' = $true
	'PerfMon ALL' = $true
	'PSR' = $true
	'Video' = $true
	'SDP Dom' = $True
	'xray' = $True
	'CollectComponentLog' = $True
}

#ADS_ACCOUNTLOCKUT Scenario
$ADS_AccountLockout_ETWTracingSwitchesStatus = [Ordered]@{
	'ADS_AccountLockout' = $true
	'CollectComponentLog' = $True
}
 if ($global:ProductType -eq "LanmanNT") {
		$ADS_AccountLockout_ETWTracingSwitchesStatus.add('ADS_KDC',"$True")	#only for KDC/LanmanNT
 }
$ADS_AccountLockoutEx_ETWTracingSwitchesStatus = [Ordered]@{
	'ADS_AccountLockout' = $true
	'NetshScenario InternetClient_dbg' = $true
	'PSR' = $true
	'xray' = $True
	'CollectComponentLog' = $True
}
 if ($global:ProductType -eq "LanmanNT") {
		$ADS_AccountLockoutEx_ETWTracingSwitchesStatus.add('ADS_KDC',"$True")	#only for KDC/LanmanNT
 }

$ADS_Auth_ETWTracingSwitchesStatus = [Ordered]@{
	'ADS_Auth' = $true
	'noBasicLog' = $true
	'Netsh' = $true
	'CollectComponentLog' = $True
}
 switch (global:FwGetProductTypeFromReg)
 {
	 "WinNT" {
			$ADS_Auth_ETWTracingSwitchesStatus.add('ADS_kernel',"$True")
		}
	 "ServerNT" {
			$ADS_Auth_ETWTracingSwitchesStatus.add('ADS_kernel',"$True")
		}
	 "LanmanNT" {
			$ADS_Auth_ETWTracingSwitchesStatus.add('ADS_kernel',"$True")
			$ADS_Auth_ETWTracingSwitchesStatus.add('ADS_KDC',"$True")	#only for KDC/LanmanNT
		}
	 Default {
		"EmptyProductType"
			$ADS_Auth_ETWTracingSwitchesStatus.add('ADS_kernel',"$True")
		}
 }

$ADS_AuthEx_ETWTracingSwitchesStatus = [Ordered]@{ # removed = $ADS_Auth_ETWTracingSwitchesStatus
	'ADS_Auth' = $true
	'Netsh' = $true
	'PSR' = $true
	'xray' = $true
	'CollectComponentLog' = $True
} 
	switch (global:FwGetProductTypeFromReg)
	{
		"WinNT" {
			#$ADS_Auth_ETWTracingSwitchesStatus.add('ADS_kernel',"$True")	#_# will produce ERROR
			$ADS_AuthEx_ETWTracingSwitchesStatus.add('PerfMon SMB',"$True")
		}
		"ServerNT" {
			$ADS_AuthEx_ETWTracingSwitchesStatus.add('PerfMon SMB',"$True")
		}
		"LanmanNT" {
			$ADS_AuthEx_ETWTracingSwitchesStatus.add('ADS_KDC',"$True")	#only for KDC/LanmanNT
			$ADS_AuthEx_ETWTracingSwitchesStatus.add('PerfMon DC',"$True")
		}
		Default {
			$ADS_AuthEx_ETWTracingSwitchesStatus.add('PerfMon SMB',"$True")
		}
	}

#ADS_Basic Scenario
$ADS_Basic_ETWTracingSwitchesStatus = [Ordered]@{
	'ADS_Basic' = $true
	'CollectComponentLog' = $True
}
if ($global:ProductType -eq "LanmanNT") {
		$ADS_Basic_ETWTracingSwitchesStatus.add('ADS_KDC',"$True")	#only for KDC/LanmanNT
}
$ADS_BasicEx_ETWTracingSwitchesStatus = [Ordered]@{
	'ADS_Basic' = $true
	'NetshScenario InternetClient_dbg' = $true
	'PSR' = $true
	'xray' = $True
	'CollectComponentLog' = $True
}
if ($global:ProductType -eq "LanmanNT") {
		$ADS_BasicEx_ETWTracingSwitchesStatus.add('ADS_KDC',"$True")	#only for KDC/LanmanNT
}

#ADS ESR Scenario
$ADS_ESR_ETWTracingSwitchesStatus = [Ordered]@{
	"ADS_ESR" = $true
	'CollectComponentLog' = $True
}

#ADS OCPS Scenario - Online Certificate Status Protocol
$ADS_OCSP_ETWTracingSwitchesStatus = [Ordered]@{
	'ADS_OCSP' = $true
	'NET_HttpSys' = $true
	'ADS_SSL' = $true
	'NET_IIS' = $true
	'NetshScenario NetConnection' = $true
	#'Procmon' = $true
	'PSR' = $true
	#'Video' = $true
	'SDP DOM' = $True
	#'xray' = $True
	'CollectComponentLog' = $True
}

$ADS_SBSL_ETWTracingSwitchesStatus = [Ordered]@{
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
	'NetshScenario NetConnection' = $true
	'PerfMon SMB' = $true
	'SDP NET' = $True
	'xray' = $True
	'CollectComponentLog' = $True
 }

$ADS_SSL_ETWTracingSwitchesStatus = [Ordered]@{
	'ADS_SSL' = $true
	'Netsh' = $true
	'PSR' = $true
	'Video' = $true
	'noBasicLog' = $true
	'xray' = $True
	'CollectComponentLog' = $True
}

$ADS_WinLAPS_ETWTracingSwitchesStatus = [Ordered]@{
	'ADS_WinLAPS' = $true
	'ADS_Auth' = $true
	'Netsh' = $true
	'PSR' = $true
	#'Video' = $true
	#'SDP DOM' = $True
	'xray' = $True
	'CollectComponentLog' = $True
}

$ADS_EESummitDemo_ETWTracingSwitchesStatus = [Ordered]@{
	'ADS_EESummitDemo' = $true
	'ADS_Kerb' = $true
	'Netsh' = $true
	'PSR' = $true
	'xray' = $true
	'noBasicLog' = $true
	'CollectComponentLog' = $True
}
#endregion --- Scenario definitions ---

#region ### Pre-Start / Post-Stop / Collect functions for trace components and scenarios 
#region -------------- AdsTest -----------
# IMPORTANT: this trace should be used only for development and testing purposes
function AdsTestPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"

	global:FwCollect_BasicLog

	#### Various EVENT LOG  actions ***
	# A simple way for exporting EventLogs in .evtx and .txt format is done by function FwAddEvtLog ($EvtLogsLAPS array is defined at bottom of this file)
	# Ex: ($EvtLogsLAPS) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	
	#Event Log - Set Log - Enable
	$EventLogSetLogListOn = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogSetLogListOn = @(  #LogName, enabled, retention, quiet, MaxSize
		@("Microsoft-Windows-CAPI2/Operational", "true", "false", "true", "102400000"),
		@("Microsoft-Windows-Kerberos/Operational", "true", "", "", "")
	)
	ForEach ($EventLog in $EventLogSetLogListOn)
	{
	 global:FwEventLogsSet $EventLog[0] $EventLog[1] $EventLog[2] $EventLog[3] $EventLog[4]
	}

	#Event Log - Export Log
	$EventLogExportLogList = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogExportLogList = @(  #LogName, filename, overwrite
		@("Microsoft-Windows-CAPI2/Operational", "c:\dev\Capi2_Oper.evtx", "true"),
		@("Microsoft-Windows-Kerberos/Operational", "c:\dev\Kerberos_Oper.evtx", "true")
	)
	ForEach ($EventLog in $EventLogExportLogList)
	{
	 global:FwExportSingleEventLog $EventLog[0] $EventLog[1] $EventLog[2] 
	}

	#Event Log - Set Log - Disable
	$EventLogSetLogListOff = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogSetLogListOff = @(  #LogName, enabled, retention, quiet, MaxSize
		@("Microsoft-Windows-CAPI2/Operational", "false", "", "", ""),
		@("Microsoft-Windows-Kerberos/Operational", "false", "", "", "")
	)
	ForEach ($EventLog in $EventLogSetLogListOff)
	{
	 global:FwEventLogsSet $EventLog[0] $EventLog[1] $EventLog[2] $EventLog[3] $EventLog[4]
	}

	 #Event Log - Clear Log
	$EventLogClearLogList = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogClearLogList = @(  #LogName, enabled, retention, quiet, MaxSize
		@("Microsoft-Windows-CAPI2/Operational"),
		@("Microsoft-Windows-Kerberos/Operational")
	)
	ForEach ($EventLog in $EventLogClearLogList){
		global:FwEventLogClear $EventLog[0] 
	}

	#### Various REGISTRY manipulaiton functions ***
	# A simple way for exporting Regisgtry keys is done by function FwAddRegItem with a registry array defined at bottom of this file ($global:KeysWinLAPS)
	# Ex.: FwAddRegItem @("WinLAPS") _Stop_
	
	# RegAddValues
	$RegAddValues = New-Object 'System.Collections.Generic.List[Object]'

	$RegAddValues = @(  #RegKey, RegValue, Type, Data
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key", "my test1", "REG_DWORD", "0x1"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key", "my test2", "REG_DWORD", "0x2")
	)

	ForEach ($regadd in $RegAddValues){
		global:FwAddRegValue $regadd[0] $regadd[1] $regadd[2] $regadd[3]
	}

	# RegExport in TXT
	LogInfo "[$global:TssPhase ADS Stage:] Exporting Reg.keys .. " "gray"
	$RegExportKeyInTxt = New-Object 'System.Collections.Generic.List[Object]'
	$RegExportKeyInTxt = @(  #Key, ExportFile, Format (TXT or REG)
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key", "C:\Dev\regtestexportTXT1.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL", "C:\Dev\regtestexportTXT2.txt", "TXT")
	)
 
	ForEach ($regtxtexport in $RegExportKeyInTxt){
		global:FwExportRegKey $regtxtexport[0] $regtxtexport[1] $regtxtexport[2]
	}

	# RegExport in REG
	$RegExportKeyInReg = New-Object 'System.Collections.Generic.List[Object]'
	$RegExportKeyInReg = @(  #Key, ExportFile, Format (TXT or REG)
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key", "C:\Dev\regtestexportREG1.reg", "REG"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL", "C:\Dev\regtestexportREG2.reg", "REG")
	)

	ForEach ($regregexport in $RegExportKeyInReg)	{
		global:FwExportRegKey $regregexport[0] $regregexport[1] $regregexport[2]
	}

	# RegDeleteValues
	$RegDeleteValues = New-Object 'System.Collections.Generic.List[Object]'

	$RegDeleteValues = @(  #RegKey, RegValue
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key", "my test1"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key", "my test2")
	)

	ForEach ($regdel in $RegDeleteValues){
		global:FwDeleteRegValue $regdel[0] $regdel[1] 
	}
 
	#### FILE COPY Operations ***
	# Create Dest. Folder
	FwCreateFolder $global:LogFolder\test2
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(  #source (* wildcard is supported) and destination
		@("C:\Dev\my folder\test*", "$global:LogFolder\test2"), 		#this will copy all files that match * criteria into dest folder
		@("C:\Dev\my folder\test1.txt", "$global:LogFolder\test2") 		#this will copy test1.txt to destination file name and add logprefix
	)

	global:FwCopyFiles $SourceDestinationPaths
	EndFunc $MyInvocation.MyCommand.Name
}
function AdsTestPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"
	EndFunc $MyInvocation.MyCommand.Name
}
#endregion -------------- AdsTest -----------

# -------------- ADS_AccountLockout ---------------
function ADS_AccountLockoutPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"

	global:FwEventLogsSet "Security" "true" "false" "true" "102400000"
	
	# better use FwAuditPolSet function: FwAuditPolSet "AccountLockout" @('"Logon","Logoff","Account Lockout","Special Logon","Other Logon/Logoff Events","User Account Management","Kerberos Service Ticket Operations","Other Account Logon events","Kerberos Authentication Service","Credential Validation"')
	auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>&1 | Out-Null
	auditpol /set /subcategory:"Logoff" /success:enable /failure:enable 2>&1 | Out-Null
	auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable 2>&1 | Out-Null
	auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable 2>&1 | Out-Null
	auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable 2>&1 | Out-Null
	auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable 2>&1 | Out-Null
	auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable 2>&1 | Out-Null
	auditpol /set /subcategory:"Other Account Logon events" /success:enable /failure:enable 2>&1 | Out-Null
	auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable 2>&1 | Out-Null
	auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable 2>&1 | Out-Null
		
	# **Netlogon logging**
	nltest /dbflag:0x2EFFFFFF 2>&1 | Out-Null
	EndFunc $MyInvocation.MyCommand.Name
}
function ADS_AccountLockoutPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"
	# *** Disable logging
	
	# better use FwAuditPolUnSet function: FwAuditPolSet "AccountLockout" @('"Logon","Logoff","Account Lockout","Special Logon","Other Logon/Logoff Events","User Account Management","Kerberos Service Ticket Operations","Other Account Logon events","Kerberos Authentication Service","Credential Validation"')
	auditpol /set /subcategory:"Logon" /success:disable /failure:disable 2>&1 | Out-Null
	auditpol /set /subcategory:"Logoff" /success:disable /failure:disable 2>&1 | Out-Null
	auditpol /set /subcategory:"Account Lockout" /success:disable /failure:disable 2>&1 | Out-Null
	auditpol /set /subcategory:"Special Logon" /success:disable /failure:disable 2>&1 | Out-Null
	auditpol /set /subcategory:"Other Logon/Logoff Events" /success:disable /failure:disable 2>&1 | Out-Null
	auditpol /set /subcategory:"User Account Management" /success:disable /failure:disable 2>&1 | Out-Null
	auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:disable /failure:disable 2>&1 | Out-Null
	auditpol /set /subcategory:"Other Account Logon events" /success:disable /failure:disable 2>&1 | Out-Null
	auditpol /set /subcategory:"Kerberos Authentication Service" /success:disable /failure:disable 2>&1 | Out-Null
	auditpol /set /subcategory:"Credential Validation" /success:disable /failure:disable 2>&1 | Out-Null

	nltest /dbflag:0x0  2>&1 | Out-Null
	global:FwEventLogsSet "Security" "false" "" "" ""
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_AccountLockoutLog{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"	

	wevtutil.exe export-log "Security" "$($PrefixTime)Security.evtx" /overwrite:true  2>&1 | Out-Null
	wevtutil epl System "$($PrefixTime)System.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil epl Application "$($PrefixTime)Application.evtx" /overwrite:true 2>&1 | Out-Null

	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(  #source (* wildcard is supported) and destination
		@("$($env:windir)\debug\Netlogon.*", "$global:LogFolder"),	#this will copy test1.txt to destination file name and add logprefix
		@("$($env:windir)\system32\Lsass.log", "$($PrefixTime)Lsass.log"),
		@("$($env:windir)\debug\Lsp.*", "$global:LogFolder")
	)

	global:FwCopyFiles $SourceDestinationPaths 
	
	Get-ChildItem env:* |  Out-File -FilePath "$($PrefixTime)env.txt" 2>&1 | Out-Null
	FwListProcsAndSvcs
	#Get-Process | Out-File -FilePath "$($PrefixTime)stop-tasklist.txt" 2>&1 | Out-Null

	LogInfoFile "CollectADS_AccountLockoutScenarioLog completed"
	EndFunc $MyInvocation.MyCommand.Name
}

# -------------- ADS_ADCS ---------------
function ADS_ADCSPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"

	$CertSrvProcess = "CertSrv" 
	$process = Get-Process $CertSrvProcess -ErrorAction SilentlyContinue
	If (!($process)) {
		LogWarn "ADCS Certification Authority is not running on this box.`n"
		$UserConsent = Read-Host -Prompt 'Are you sure you want to continue with the data collection[Y/N]'
		if ($UserConsent -ne 'Y'){
			LogWarn("Script execution cancelled, exiting.")
			global:FwCleanUpandExit
		} 
	}

	wevtutil.exe clear-log "Microsoft-Windows-CAPI2/Operational" 2>&1 | Out-Null
	wevtutil.exe sl "Microsoft-Windows-CAPI2/Operational" /ms:102400000 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Kerberos/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe clear-log "Microsoft-Windows-Kerberos/Operational" 2>&1 | Out-Null

	certutil.exe -f -setreg ca\debug 0xffffffe3 2>&1 | Out-Null
	certutil.exe getreg ca\loglevel 4 2>&1 | Out-Null
	
	Net.exe Stop Certsvc 2>&1 | Out-Null
	Net.exe Start Certsvc 2>&1 | Out-Null

	FwListProcsAndSvcs
	#Get-Process | Out-File -FilePath "$($PrefixTime)start-tasklist.txt" 2>&1 | Out-Null

	LogInfo "ADS ADCS (cert authority) tracing started"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_ADCSLog{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"

	wevtutil epl System "$($PrefixTime)System.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil epl Application "$($PrefixTime)Application.evtx" /overwrite:true 2>&1 | Out-Null

	certutil.exe -v -silent -store my > "$($PrefixTime)machine-store.txt" 2>&1 | Out-Null
	certutil.exe -v -user -silent -store my > "$($PrefixTime)user-store.txt" 2>&1 | Out-Null

	certutil.exe -v -template > "$($PrefixTime)templateCache.txt" 2>&1 | Out-Null
	#certutil.exe -v -dstemplate > "$($PrefixTime)templateAD.txt" 2>&1 | Out-Null

	ipconfig /all > "$($PrefixTime)ipconfig-info.txt" 2>&1 | Out-Null

	Copy-Item "$($Env:windir)\certsrv.log" -Destination "$($PrefixTime)certsrv.log" 2>&1 | Out-Null
	Copy-Item "$($Env:windir)\certocm.log" -Destination "$($PrefixTime)certocm.log" 2>&1 | Out-Null
	Copy-Item "$($Env:windir)\certutil.log" -Destination "$($PrefixTime)certutil.log" 2>&1 | Out-Null
	Copy-Item "$($Env:windir)\certmmc.log" -Destination "$($PrefixTime)certmmc.log" 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-CAPI2/Operational" "$($PrefixTime)Capi2_Oper.evtx" /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Kerberos/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Kerberos/Operational" "$($PrefixTime)Kerb_Oper.evtx" /overwrite:true  2>&1 | Out-Null

	Get-ChildItem env:* |  Out-File -FilePath "$($PrefixTime)env.txt" 2>&1 | Out-Null

	reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v BuildLabEx > "$($PrefixTime)build.txt" 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography" /s > "$($PrefixTime)reg_HKLMControl-Cryptography.txt" 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography" /s > "$($PrefixTime)reg_HKLMSoftware-Cryptography.txt"
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography" /s > "$($PrefixTime)reg_HKLMSoftware-policies-Cryptography.txt" 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc" /s > "$($PrefixTime)reg_CertSvc.txt" 2>&1 | Out-Null

	FwListProcsAndSvcs
	#Get-Process | Out-File -FilePath "$($PrefixTime)stop-tasklist.txt" 2>&1 | Out-Null

	klist > "$($PrefixTime)tickets-stop.txt" 2>&1 | Out-Null
	klist -li 0x3e7 > "$($PrefixTime)ticketscomputer-stop.txt" 2>&1 | Out-Null

	FwCaptureUserDump "CertSvc" $global:LogFolder -IsService:$True

	certutil -f -setreg ca\debug 0x0 2>&1 | Out-Null
	certutil -getreg ca\loglevel 3 2>&1 | Out-Null

	Net Stop Certsvc 2>&1 | Out-Null
	Net Start Certsvc 2>&1 | Out-Null

	LogInfoFile "ADS ADCS (cert authority) tracing completed"
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectADS_ADDSLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] Collecting ADS_ADDS logs started."
	$ComputerSystem = Get-WmiObject -Namespace "root\CIMv2" -Class Win32_ComputerSystem
	
	if (!([string]::IsNullOrEmpty($ComputerSystem))) {
		$ComputerDomain = $ComputerSystem.Domain
		$DomainRole = $ComputerSystem.DomainRole
	} else {
		$ComputerDomain = "WORKGROUP"
		$DomainRole = 0
	}
	
	$RootDSE = [ADSI]"LDAP://RootDSE"
	$DefaultNamingContext = $RootDSE.defaultNamingContext
	
	if ($Null -ne $DefaultNamingContext) {
		$ConfigurationNamingContext = $RootDSE.configurationNamingContext
		$DCAccessible = $True
	} else {
		$DCAccessible = $False
	}
	
	$Commands += @(
		"klist tgt | Out-File -Append $PrefixTime`ADDS_klist_tgt.txt"
		"klist tickets | Out-File -Append $PrefixTime`ADDS_klist_tickets.txt"
		"klist tgt -li 0x3e4 | Out-File -Append $PrefixTime`ADDS_klist_tgt_0x3e4.txt"
		"klist tickets -li 0x3e4 | Out-File -Append $PrefixTime`ADDS_klist_tickets_0x3e4.txt"
		"klist tgt -li 0x3e7 | Out-File -Append $PrefixTime`ADDS_klist_tgt_0x3e7.txt"
		"klist tickets -li 0x3e7 | Out-File -Append $PrefixTime`ADDS_klist_tickets_0x3e7.txt"
		"klist sessions | Out-File -Append $PrefixTime`ADDS_klist_sessions.txt"
		"klist kcd_cache | Out-File -Append $PrefixTime`ADDS_klist_kcd_cache.txt"
		"klist query_bind | Out-File -Append $PrefixTime`ADDS_klist_query_bind.txt"
		"klist cloud_debug | Out-File -Append $PrefixTime`ADDS_klist_cloud_debug.txt"
		"cmdkey /list | Out-File -Append $PrefixTime`ADDS_cmdkey_list.txt"
		"tasklist /svc | Out-File -Append $PrefixTime`ADDS_tasklist_svc.txt"
		"reg query `"HKLM\SYSTEM\CurrentControlSet\Control\Lsa`" /s | Out-File -Append $PrefixTime`ADDS_Reg_Lsa.txt"
		"reg query `"HKLM\SYSTEM\CurrentControlSet\Control\EAS`" /s | Out-File -Append $PrefixTime`ADDS_Reg_EAS.txt"
		"reg query `"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon`" /s | Out-File -Append $PrefixTime`ADDS_Reg_Netlogon.txt"
		"reg query `"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders`" /s | Out-File -Append $PrefixTime`ADDS_Reg_SecurityProviders.txt"
		"reg query `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`" /s | Out-File -Append $PrefixTime`ADDS_Reg_Winlogon.txt"
		"reg query `"HKLM\SYSTEM\CurrentControlset\Services\ProfSvc`" /s | Out-File -Append $PrefixTime`ADDS_Reg_ProfSvc.txt"
		"reg query `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`" /s | Out-File -Append $PrefixTime`ADDS_Reg_ProfileList.txt"
		"reg query `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileGuid`" /s | Out-File -Append $PrefixTime`ADDS_Reg_ProfileGuid.txt"
		"reg query `"HKLM\SOFTWARE\Policies`" /s | Out-File -Append $PrefixTime`ADDS_Reg_Policies_Machine.txt"
		"reg query `"HKCU\SOFTWARE\Policies`" /s | Out-File -Append $PrefixTime`ADDS_Reg_Policies_User.txt"
	)
	
	if (Test-Path "$Env:SYSTEMROOT\PolicyDefinitions") {
		Copy-Item "$Env:SYSTEMROOT\PolicyDefinitions" "$global:LogFolder\PolicyDefinitions" -Recurse
	}
	
	if (Test-Path "$Env:SYSTEMROOT\debug\adprep") {
		Copy-Item "$Env:SYSTEMROOT\debug\adprep" "$global:LogFolder\adprep" -Recurse
	}
	
	$SourceDestinationPaths = @(
		@("$Env:SYSTEMROOT\Security\audit\audit.csv", "$($PrefixTime)ADDS_audit.csv"),
		@("$Env:SYSTEMROOT\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv", "$($PrefixTime)ADDS_audit_lgpo.csv"),
		@("$Env:SYSTEMROOT\debug\dcpromo.log", "$($PrefixTime)ADDS_dcpromo.log"),
		@("$Env:SYSTEMROOT\debug\dcpromoui.log", "$($PrefixTime)ADDS_dcpromoui.log"),
		@("$Env:SYSTEMROOT\debug\netlogon.log", "$($PrefixTime)ADDS_netlogon.log"),
		@("$Env:SYSTEMROOT\System32\config\netlogon.dns", "$($PrefixTime)ADDS_netlogon.dns"),
		@("$Env:SYSTEMROOT\debug\netsetup.log", "$($PrefixTime)ADDS_netsetup.log"),
		@("$Env:SYSTEMROOT\security\logs\winlogon.log", "$($PrefixTime)ADDS_winlogon.log")
	)
	
	if (($DomainRole -eq 1) -Or ($DomainRole -eq 3) -Or ($DomainRole -eq 4) -Or ($DomainRole -eq 5)) { # Member Workstation, Member Server, BDC, or PDC
		$Commands += @(
			"nltest /sc_query:$ComputerDomain | Out-File -Append $PrefixTime`ADDS_nltest_sc_query.txt"
		)
		
		if ($DCAccessible -eq $True) {
			$Commands += @(
				"netdom query fsmo | Out-File -Append $PrefixTime`ADDS_netdom_query_fsmo.txt"
				"nltest /dclist: | Out-File -Append $PrefixTime`ADDS_nltest_dclist.txt"
				"nltest /dsgetsite | Out-File -Append $PrefixTime`ADDS_nltest_dsgetsite.txt"
				"nltest /domain_trusts /all_trusts /v | Out-File -Append $PrefixTime`ADDS_nltest_domain_trusts_all_trusts_v.txt"
				"nltest /trusted_domains | Out-File -Append $PrefixTime`ADDS_nltest_trusted_domains.txt"
				"setspn -Q */* -F | Out-File -Append $PrefixTime`ADDS_setspn_q_f.txt"
				"setspn -X -F | Out-File -Append $PrefixTime`ADDS_setspn_x_f.txt"
				"Get-ChildItem -Path `"\\$ComputerDomain\SYSVOL`" -Force -Recurse | Out-File -Append $PrefixTime`ADDS_dir_sysvol_unc.txt"
				"icacls `"\\$ComputerDomain\SYSVOL`" /T /C | Out-File -Append $PrefixTime`ADDS_icacls_sysvol_unc.txt"
			)
		}
	}
	
	if (($DomainRole -eq 4) -Or ($DomainRole -eq 5)) { # BDC or PDC
		$Commands += @(
			"dcdiag /v | Out-File -Append $PrefixTime`ADDS_dcdiag_v.txt"
			"repadmin /showrepl /verbose | Out-File -Append $PrefixTime`ADDS_repadmin_showrepl_verbose.txt"
			"repadmin /bridgeheads | Out-File -Append $PrefixTime`ADDS_repadmin_bridgeheads.txt"
			"repadmin /queue | Out-File -Append $PrefixTime`ADDS_repadmin_queue.txt"
			"repadmin /failcache | Out-File -Append $PrefixTime`ADDS_repadmin_failcache.txt"
			"repadmin /istg | Out-File -Append $PrefixTime`ADDS_repadmin_istg.txt"
			"repadmin /showbackup | Out-File -Append $PrefixTime`ADDS_repadmin_showbackup.txt"
			"repadmin /showcert | Out-File -Append $PrefixTime`ADDS_repadmin_showcert.txt"
			"repadmin /showconn | Out-File -Append $PrefixTime`ADDS_repadmin_showconn.txt"
			"repadmin /showtrust | Out-File -Append $PrefixTime`ADDS_repadmin_showtrust.txt"
			"ntfrsutl ds | Out-File -Append $PrefixTime`ADDS_ntfrsutl_ds.txt"
			"ntfrsutl sets | Out-File -Append $PrefixTime`ADDS_ntfrsutl_sets.txt"
			"reg query `"HKLM\SYSTEM\CurrentControlSet\Services\NTDS`" /s | Out-File -Append $PrefixTime`ADDS_Reg_NTDS.txt"
		)
		
		$SysVolPath = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" -Name SysVol).SysVol
		
		if (!([string]::IsNullOrEmpty($SysVolPath))) {
			$Commands += @(
				"Get-ChildItem -Path `"$SysVolPath`" -Force -Recurse | Out-File -Append $PrefixTime`ADDS_dir_sysvol_local.txt"
				"icacls `"$SysVolPath`" /T /C | Out-File -Append $PrefixTime`ADDS_icacls_sysvol_local.txt"
			)
		}
		
		$Partitions = (Get-ADDomainController -Identity "$Env:COMPUTERNAME").Partitions
		
		if (!([string]::IsNullOrEmpty($Partitions))) {
			foreach ($Partition in $Partitions) {
				$ReplacedPartition = $Partition.Replace(",", "_")
				$Commands += @(
					"repadmin /showvector `"$Partition`" /latency | Out-File -Append $PrefixTime`ADDS_repadmin_showvector_$ReplacedPartition.txt"
					"repadmin /notifyopt `"$Env:COMPUTERNAME`" `"$Partition`" | Out-File -Append $PrefixTime`ADDS_repadmin_notifyopt_$ReplacedPartition.txt"
				)
			}
		}
		
		ldifde -f "$PrefixTime`ADDS_ldifde_config.txt" -d "$ConfigurationNamingContext" | Out-Null
		ldifde -f "$PrefixTime`ADDS_ldifde_domain_base.txt" -d "$DefaultNamingContext" -p Base | Out-Null
		ldifde -f "$PrefixTime`ADDS_ldifde_dc.txt" -d "OU=Domain Controllers,$DefaultNamingContext" | Out-Null
		ldifde -f "$PrefixTime`ADDS_ldifde_system.txt" -d "CN=System,$DefaultNamingContext" | Out-Null
		Get-ADRootDSE | Export-Clixml -Path "$PrefixTime`ADDS_Get_ADRootDSE.xml" | Out-Null
		Get-ADForest | Export-Clixml -Path "$PrefixTime`ADDS_Get_ADForest.xml" | Out-Null
		Get-ADDomain | Export-Clixml -Path "$PrefixTime`ADDS_Get_ADDomain.xml" | Out-Null
		Get-ADDomainController | Export-Clixml -Path "$PrefixTime`ADDS_Get_ADDomainController.xml" | Out-Null
		Get-ADDefaultDomainPasswordPolicy | Export-Clixml -Path "$PrefixTime`ADDS_Get_ADDefaultDomainPasswordPolicy.xml" | Out-Null
		Get-ADFineGrainedPasswordPolicy -Filter * | Export-Clixml -Path "$PrefixTime`ADDS_Get_ADFineGrainedPasswordPolicy.xml" | Out-Null
		Get-ADOptionalFeature -Filter * | Export-Clixml -Path "$PrefixTime`ADDS_Get_ADOptionalFeature.xml" | Out-Null
		Get-ADReplicationConnection -Filter * | Export-Clixml -Path "$PrefixTime`ADDS_Get_ADReplicationConnection.xml" | Out-Null
		Get-ADReplicationFailure -Target "$Env:COMPUTERNAME" | Export-Clixml -Path "$PrefixTime`ADDS_Get_ADReplicationFailure.xml" | Out-Null
		Get-ADReplicationQueueOperation -Server "$Env:COMPUTERNAME" | Export-Clixml -Path "$PrefixTime`ADDS_Get_ADReplicationQueueOperation.xml" | Out-Null
		Get-ADReplicationSite -Filter * -Properties * | Export-Clixml -Path "$PrefixTime`ADDS_Get_ADReplicationSite.xml" | Out-Null
		Get-ADReplicationSiteLink -Filter * -Properties * | Export-Clixml -Path "$PrefixTime`ADDS_Get_ADReplicationSiteLink.xml" | Out-Null
		Get-ADReplicationSiteLinkBridge -Filter * -Properties * | Export-Clixml -Path "$PrefixTime`ADDS_Get_ADReplicationSiteLinkBridge.xml" | Out-Null
		Get-ADReplicationSubnet -Filter * -Properties * | Export-Clixml -Path "$PrefixTime`ADDS_Get_ADReplicationSubnet.xml" | Out-Null
		Get-ADTrust -Filter * -Properties * | Export-Clixml -Path "$PrefixTime`ADDS_Get_ADTrust.xml" | Out-Null
		Get-GPO -Domain $ComputerDomain -All | Export-Clixml -Path "$PrefixTime`ADDS_Get_GPO.xml" | Out-Null
	}
	
	FwCopyFiles $SourceDestinationPaths
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	FwGetDSregCmd
	FwGetGPresultAS
	
	LogInfo "[$($MyInvocation.MyCommand.Name)] Collecting ADS_ADDS logs ended."
	EndFunc $MyInvocation.MyCommand.Name
}

# -------------- ADS_BadPwd ---------------
function CollectADS_BadPwdLog {
	EnterFunc $MyInvocation.MyCommand.Name
	.\scripts\tss_FindUserBadPwdAttempts.ps1 -DataPath $global:LogFolder
	EndFunc $MyInvocation.MyCommand.Name
}

# -------------- ADSAUTH ---------------
function ADS_AuthPreStart{
	[float]$_Authscriptver = "5.0" # add/update this also in TSS FW
	$_WatchProcess = $null
	$_BASE_LOG_DIR = $global:LogFolder #".\authlogs"
	$_LOG_DIR = $_BASE_LOG_DIR
	$_CH_LOG_DIR = "$_BASE_LOG_DIR\container-host"
	$_BASE_C_DIR = "$_BASE_LOG_DIR`-container"
	$_C_LOG_DIR = "$_BASE_LOG_DIR\container"

	# *** Set some system specifc variables ***
	$wmiOSObject = Get-WmiObject -class Win32_OperatingSystem
	$osVersionString = $wmiOSObject.Version
	$osBuildNumString = $wmiOSObject.BuildNumber

	# **WPR Check** ** Checks if WPR is installed in case OS < Win10 and 'slowlogon' switch is added**
	if ($slowlogon) {

	[version]$OSVersion = (Get-CimInstance Win32_OperatingSystem).version
	if(!($OSVersion -gt [version]'10.0')){
		try{
			Start-Process -FilePath wpr -WindowStyle Hidden -ErrorVariable WPRnotInstalled;}
		catch{
		if($WPRnotInstalled){
			LogInfo "`nWarning!" Yellow
			LogInfo "Windows Performance Recorder (WPR) needs to be installed before the '-slowlogon' switch can be used.`n" Yellow
			LogInfo "You can download Windows Performance Recorder here: https://go.microsoft.com/fwlink/p/?LinkId=526740" Yellow
			LogInfo "Exiting script.`n" Yellow
			exit;
			}
		}
		}
	}

	$_PRETRACE_LOG_DIR = $_LOG_DIR + "\PreTraceLogs"

	If ((Test-Path $_PRETRACE_LOG_DIR) -eq "True") { Remove-Item -Path $_PRETRACE_LOG_DIR -Force -Recurse }
	# removed form TSSv2: If ((Test-Path $_LOG_DIR) -eq "True") { Remove-Item -Path $_LOG_DIR -Force -Recurse }

	# removed form TSSv2: New-Item -name $_LOG_DIR -ItemType Directory | Out-Null
	#New-Item -name $_PRETRACE_LOG_DIR -ItemType Directory | Out-Null
	FwCreateFolder $_PRETRACE_LOG_DIR

	$ProductType = (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions).ProductType	#we# note TSS FW has already defined $global:ProductType 
	Add-Content -Path $_LOG_DIR\script-info.txt -Value "Microsoft CSS Authentication Script version $_Authscriptver"

	Add-Content -Path $_LOG_DIR\started.txt -Value "Started"

	# **slowlogon** ** Generate customer WPRP**

	if ($slowlogon) {
	function Generate-slowlogonWPRP{	
	
	$sbsl_wprp_file = @"
<?xml version="1.0" encoding="utf-8"?>
<WindowsPerformanceRecorder Version="1.0"  Author="Auth Scripts Team">
  <Profiles>
	<SystemCollector Id="SBSL_System_Collector" Name="SBSL System Collector">
	  <BufferSize Value="1024" />
	  <Buffers Value="3276" />
	</SystemCollector>
	<EventCollector Id="SBSL_Event_Collector" Name="SBSL Event Collector">
	  <BufferSize Value="1024" />
	  <Buffers Value="655" />
	</EventCollector>
	<SystemProvider Id="SBSL_Collector_Provider">
	  <Keywords>	
		<Keyword Value="CpuConfig" />
		<Keyword Value="CSwitch" />
		<Keyword Value="DiskIO" />
		<Keyword Value="DPC" />
		<Keyword Value="Handle" />
		<Keyword Value="HardFaults" />
		<Keyword Value="Interrupt" />
		<Keyword Value="Loader" />
		<Keyword Value="MemoryInfo" />
		<Keyword Value="MemoryInfoWS" />
		<Keyword Value="ProcessCounter" />
		<Keyword Value="Power" />
		<Keyword Value="ProcessThread" />
		<Keyword Value="ReadyThread" />
		<Keyword Value="SampledProfile" />
		<Keyword Value="ThreadPriority" />
		<Keyword Value="VirtualAllocation" />
		<Keyword Value="WDFDPC" />
		<Keyword Value="WDFInterrupt" />
	  </Keywords>
	  <Stacks>
		<Stack Value="CSwitch" />
		<Stack Value="HandleCreate" />
		<Stack Value="HandleClose" />
		<Stack Value="HandleDuplicate" />
		<Stack Value="SampledProfile" />
		<Stack Value="ThreadCreate" />
		<Stack Value="ReadyThread" />
	  </Stacks>
	</SystemProvider>
	<EventProvider Id="Microsoft-Windows-Winlogon" Name="dbe9b383-7cf3-4331-91cc-a3cb16a3b538"/>
	<EventProvider Id="Microsoft-Windows-GroupPolicy" Name="aea1b4fa-97d1-45f2-a64c-4d69fffd92c9"/>
	<EventProvider Id="Microsoft-Windows-Wininit" Name="206f6dea-d3c5-4d10-bc72-989f03c8b84b111111"/>
	<EventProvider Id="Microsoft-Windows-User_Profiles_Service" Name="89b1e9f0-5aff-44a6-9b44-0a07a7ce5845"/>
	<EventProvider Id="Microsoft-Windows-User_Profiles_General" Name="db00dfb6-29f9-4a9c-9b3b-1f4f9e7d9770"/>
	<EventProvider Id="Microsoft-Windows-Folder_Redirection" Name="7d7b0c39-93f6-4100-bd96-4dda859652c5"/>
	<EventProvider Id="Microsoft-Windows-Security-Netlogon" Name="e5ba83f6-07d0-46b1-8bc7-7e669a1d31dca"/>
	<EventProvider Id="Microsoft-Windows-Shell-Core" Name="30336ed4-e327-447c-9de0-51b652c86108"/>
	<Profile Id="SBSL.Verbose.Memory" Name="SBSL" Description="RunningProfile:SBSL.Verbose.Memory" LoggingMode="Memory" DetailLevel="Verbose"> <!-- Default profile. Used when the '-slowlogon' switch is used  -->
	  <ProblemCategories>
		<ProblemCategory Value="First level triage" />
	  </ProblemCategories>
	  <Collectors>
		<SystemCollectorId Value="SBSL_System_Collector">
		  <SystemProviderId Value="SBSL_Collector_Provider" />
		</SystemCollectorId>
		<EventCollectorId Value="SBSL_Event_Collector">
		  <EventProviders>
			<EventProviderId Value="Microsoft-Windows-Winlogon"/>
			<EventProviderId Value="Microsoft-Windows-GroupPolicy"/>
			<EventProviderId Value="Microsoft-Windows-Wininit"/>
			<EventProviderId Value="Microsoft-Windows-User_Profiles_Service"/>
			<EventProviderId Value="Microsoft-Windows-User_Profiles_General"/>
			<EventProviderId Value="Microsoft-Windows-Folder_Redirection"/>
			<EventProviderId Value="Microsoft-Windows-Shell-Core"/>
			<EventProviderId Value="Microsoft-Windows-Security-Netlogon"/>
		  </EventProviders>
		</EventCollectorId>
	  </Collectors>
	  <TraceMergeProperties>
		<TraceMergeProperty Id="BaseVerboseTraceMergeProperties" Name="BaseTraceMergeProperties">
		  <DeletePreMergedTraceFiles Value="true" />
		  <FileCompression Value="false" />
		  <InjectOnly Value="false" />
		  <CustomEvents>
			<CustomEvent Value="ImageId" />
			<CustomEvent Value="BuildInfo" />
			<CustomEvent Value="VolumeMapping" />
			<CustomEvent Value="EventMetadata" />
			<CustomEvent Value="PerfTrackMetadata" />
			<CustomEvent Value="WinSAT" />
			<CustomEvent Value="NetworkInterface" />
		  </CustomEvents>
		</TraceMergeProperty>
	  </TraceMergeProperties>
	</Profile>
		<Profile Id="SBSL.Light.Memory" Name="SBSL" Description="RunningProfile:SBSL.Light.Memory" Base="SBSL.Verbose.Memory" LoggingMode="Memory" DetailLevel="Light" /> <!-- Light memory profile. Not currently in use. Reserved for later usage -->
		<Profile Id="SBSL.Verbose.File" Name="SBSL" Description="RunningProfile:SBSL.Verbose.File" Base="SBSL.Verbose.Memory" LoggingMode="File" DetailLevel="Verbose" /> <!-- Default -File mode profile. Used when the '-slowlogon' switch is added -->
		<Profile Id="SBSL.Light.File" Name="SBSL" Description="RunningProfile:SBSL.Light.File" Base="SBSL.Verbose.Memory" LoggingMode="File" DetailLevel="Light" /> <!-- Light file profile. Not currently in use. Reserved for later usage -->
  </Profiles>
</WindowsPerformanceRecorder>

"@
		Out-file -FilePath "$_LOG_DIR\sbsl.wprp" -InputObject $sbsl_wprp_file -Encoding ascii
	}
}

	# **slowlogon** ** Generate Slow Logon WPRP file in case the 'slowlogon' switch is added**
	if ($slowlogon) {Generate-slowlogonWPRP}

	# *** QUERY RUNNING PROVIDERS ***
	# TSS implements this as part of TSS FW ETW tracing

	# Enable Eventvwr logging
	wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-CAPI2/Operational" $_PRETRACE_LOG_DIR\Capi2_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe clear-log "Microsoft-Windows-CAPI2/Operational" 2>&1 | Out-Null
	wevtutil.exe sl "Microsoft-Windows-CAPI2/Operational" /ms:102400000 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Kerberos/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe clear-log "Microsoft-Windows-Kerberos/Operational" 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Kerberos-KdcProxy/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-WebAuth/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-WebAuthN/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-WebAuthN/Operational" $_PRETRACE_LOG_DIR\WebAuthn_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-WebAuthN/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-CertPoleEng/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	wevtutil.exe clear-log "Microsoft-Windows-CertPoleEng/Operational" 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-IdCtrls/Operational" /enabled:false | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-IdCtrls/Operational" $_PRETRACE_LOG_DIR\Idctrls_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-IdCtrls/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-User Control Panel/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-User Control Panel/Operational" $_PRETRACE_LOG_DIR\UserControlPanel_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Control Panel/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUser-Client" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Biometrics/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Biometrics/Operational" $_PRETRACE_LOG_DIR\WinBio_oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Biometrics/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-LiveId/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-LiveId/Operational" $_PRETRACE_LOG_DIR\LiveId_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-LiveId/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-AAD/Analytic" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-AAD/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-AAD/Operational" $_PRETRACE_LOG_DIR\Aad_oper.evtx /ow:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-AAD/Operational"  /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-User Device Registration/Admin" $_PRETRACE_LOG_DIR\UsrDeviceReg_Adm.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Debug" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-HelloForBusiness/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-HelloForBusiness/Operational" $_PRETRACE_LOG_DIR\Hfb_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-HelloForBusiness/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Shell-Core/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-WMI-Activity/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Crypto-DPAPI/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Crypto-DPAPI/Operational" $_PRETRACE_LOG_DIR\DPAPI_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Crypto-DPAPI/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null


	# *** ENABLE LOGGING VIA REGISTRY ***

	# NEGOEXT
	reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NegoExtender\Parameters /v InfoLevel /t REG_DWORD /d 0xFFFF /f 2>&1 | Out-Null

	# PKU2U
	reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Pku2u\Parameters /v InfoLevel /t REG_DWORD /d 0xFFFF /f 2>&1 | Out-Null

	# LSA
	reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v SPMInfoLevel /t REG_DWORD /d 0xC43EFF /f 2>&1 | Out-Null
	reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LogToFile /t REG_DWORD /d 1 /f 2>&1 | Out-Null
	reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v NegEventMask /t REG_DWORD /d 0xF /f 2>&1 | Out-Null

	# LSP Logging
	reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgInfoLevel /t REG_DWORD /d 0x41C20800 /f 2>&1 | Out-Null
	reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgTraceOptions /t REG_DWORD /d 0x1 /f 2>&1 | Out-Null

	# Kerberos Logging to SYSTEM event log in case this is a client
	if ($ProductType -eq "WinNT") {
		reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters /v LogLevel /t REG_DWORD /d 1 /f 2>&1 | Out-Null
	}

	# *** START ETL PROVIDER GROUPS *** removed as it is handled by TSS FW



	# *** Nonet check  ***  removed,  psl. use TSS FW for network trace 
	wevtutil.exe set-log "Microsoft-Windows-Containers-CCG/Admin" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Containers-CCG/Admin" $_PRETRACE_LOG_DIR\Containers-CCG_Admin.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Containers-CCG/Admin" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	# **AppX** **Start Appx logman on clients, or in servers (except Domain Controllers) in case the '-v' switch is added**

	# Start Kernel logger

	# **Netlogon logging**
	nltest /dbflag:0x2EFFFFFF 2>&1 | Out-Null

	# **Enabling Group Policy Logging**
	New-Item -Path "$($env:windir)\debug\usermode" -ItemType Directory 2>&1 | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" /f 2>&1 | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" /v GPSvcDebugLevel /t REG_DWORD /d 0x30002 /f 2>&1 | Out-Null

	# ** Turn on debug and verbose Cert Enroll  logging **

	LogInfo "Enabling Certificate Enrolment debug logging..."
	LogInfo "Verbose Certificate Enrolment debug output may be written to this window"
	LogInfo "It is also written to a log file which will be collected during tracing stop phase.`n"

	Start-Sleep -s 5

	certutil -setreg -f Enroll\Debug 0xffffffe3 2>&1 | Out-Null

	certutil -setreg ngc\Debug 1 2>&1 | Out-Null
	certutil -setreg Enroll\LogLevel 5 2>&1 | Out-Null

	<#
	Switch -Regex ($osVersionString) {
					'^6\.1\.7600' { 'Windows Server 2008 R2, Skipping dsregcmd...'}
					'^6\.1\.7601' { 'Windows Server 2008 R2 SP1, Skipping dsregcmd...'}
					'^6\.2\.9200' { 'Windows Server 2012, Skipping dsregcmd...'}
					'^6\.3\.9600' { 'Windows Server 2012 R2, Skipping dsregcmd...'}
					default {
						Add-Content -Path $_PRETRACE_LOG_DIR\Dsregcmddebug.txt -Value (dsregcmd /status /debug /all 2>&1) | Out-Null
						Add-Content -Path $_PRETRACE_LOG_DIR\DsRegCmdStatus.txt -Value (dsregcmd /status 2>&1) | Out-Null
					}
			} 
			#>
	FwGetDSregCmd -Subfolder "PreTraceLogs"

	Add-Content -Path $_PRETRACE_LOG_DIR\Tasklist.txt -Value (tasklist /svc 2>&1) | Out-Null
	Add-Content -Path $_PRETRACE_LOG_DIR\Services-config.txt -Value (sc.exe query 2>&1) | Out-Null
	Add-Content -Path $_PRETRACE_LOG_DIR\Services-started.txt -Value (net start 2>&1) | Out-Null

	Add-Content -Path $_PRETRACE_LOG_DIR\netstat.txt -Value (netstat -ano 2>&1) | Out-Null
	Add-Content -Path $_PRETRACE_LOG_DIR\Tickets.txt -Value(klist) | Out-Null
	Add-Content -Path $_PRETRACE_LOG_DIR\Tickets-localsystem.txt -Value (klist -li 0x3e7) | Out-Null
	Add-Content -Path $_PRETRACE_LOG_DIR\Klist-Cloud-Debug.txt -Value (klist Cloud_debug) | Out-Null
	Add-Content -Path $_PRETRACE_LOG_DIR\Displaydns.txt -Value (ipconfig /displaydns 2>&1) | Out-Null


	# ** Run WPR in case the 'slowlogon' switch is added. (Default File mode = sbsl.wprp!sbsl.verbose -filemode)
	if ($slowlogon){
		wpr -start $_LOG_DIR\sbsl.wprp!sbsl.verbose -filemode
	}

	# *** QUERY RUNNING PROVIDERS ***
	Add-Content -Path $_LOG_DIR\running-etl-sessions.txt -value (logman query * -ets)

	ipconfig /flushdns 2>&1 | Out-Null


	if ($v.IsPresent -eq "True") {
		Add-Content -Path $_LOG_DIR\script-info.txt -Value "Arguments passed: v"
	}

	if ($nonet.IsPresent -eq "True") {
		Add-Content -Path $_LOG_DIR\script-info.txt -Value "Arguments passed: nonet"
	}

	if ($slowlogon.IsPresent -eq "True") {
		Add-Content -Path $_LOG_DIR\script-info.txt -Value "Arguments passed: slowlogon"
	}

	Add-Content -Path $_LOG_DIR\script-info.txt -Value ("Data collection started on: " + (Get-Date -Format "yyyy/MM/dd HH:mm:ss"))
}
function CollectADS_AuthLog{
	[float]$_Authscriptver = "5.0"
	$_BASE_LOG_DIR = $global:LogFolder #".\authlogs"
	$_LOG_DIR = $_BASE_LOG_DIR
	$_CH_LOG_DIR = "$_BASE_LOG_DIR\container-host"
	$_BASE_C_DIR = "$_BASE_LOG_DIR`-container"
	$_C_LOG_DIR = "$_BASE_LOG_DIR\container"

	# *** Set some system specifc variables ***
	$wmiOSObject = Get-WmiObject -class Win32_OperatingSystem
	$osVersionString = $wmiOSObject.Version
	$osBuildNumString = $wmiOSObject.BuildNumber

	$ProductType = (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions).ProductType	#we# note TSS FW has already defined $global:ProductType 

	# ***STOP LOGMAN TRACING*** implemented in TSS FW

	$_WAM_LOG_DIR = "$_LOG_DIR\WAM"
	$_SCCM_LOG_DIR = "$_LOG_DIR\SCCM-enrollment"
	$_MDM_LOG_DIR = "$_LOG_DIR\DeviceManagement_and_MDM"
	$_CERT_LOG_DIR = "$_LOG_DIR\Certinfo_and_Certenroll"

	New-Item -Path $_WAM_LOG_DIR -ItemType Directory | Out-Null
	New-Item -Path $_SCCM_LOG_DIR -ItemType Directory | Out-Null
	New-Item -Path $_MDM_LOG_DIR -ItemType Directory | Out-Null
	New-Item -Path $_CERT_LOG_DIR -ItemType Directory | Out-Null

	Add-Content -Path $_LOG_DIR\Tasklist.txt -Value (tasklist /svc 2>&1) | Out-Null
	Add-Content -Path $_LOG_DIR\Tickets.txt -Value(klist) | Out-Null
	Add-Content -Path $_LOG_DIR\Tickets-localsystem.txt -Value (klist -li 0x3e7) | Out-Null
	Add-Content -Path $_LOG_DIR\Klist-Cloud-Debug.txt -Value (klist Cloud_debug) | Out-Null

	# STOP ETW Traces is implemented in TSS FW

	# Stop WPR 
	#checking if the slowlogon switched was passed 
	$CheckIfslowlogonWasPassed = get-content $_LOG_DIR\script-info.txt | Select-String -pattern "slowlogon"
	if ($CheckIfslowlogonWasPassed.Pattern -eq "slowlogon") {
		LogInfo "Stopping WPR. This may take some time depending on the size of the WPR Capture, please wait...."

		# Stop WPRF
		wpr -stop $_LOG_DIR\SBSL.etl
	}

	# ***CLEAN UP ADDITIONAL LOGGING***
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v SPMInfoLevel /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LogToFile /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v NegEventMask /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA\NegoExtender\Parameters /v InfoLevel /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA\Pku2u\Parameters /v InfoLevel /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgInfoLevel /f  2>&1 | Out-Null
	reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LspDbgTraceOptions /f  2>&1 | Out-Null

	if ($ProductType -eq "WinNT") {
		reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters /v LogLevel /f  2>&1 | Out-Null
	}

	reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" /v GPSvcDebugLevel /f  2>&1 | Out-Null
	nltest /dbflag:0x0  2>&1 | Out-Null

	# *** Event/Operational logs

	wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-CAPI2/Operational" $_LOG_DIR\Capi2_Oper.evtx /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Kerberos/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Kerberos/Operational" $_LOG_DIR\Kerb_Oper.evtx /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Kerberos-key-Distribution-Center/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Kerberos-key-Distribution-Center/Operational" $_LOG_DIR\Kdc_Oper.evtx /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Kerberos-KdcProxy/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Kerberos-KdcProxy/Operational" $_LOG_DIR\KdcProxy_Oper.evtx /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-WebAuth/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-WebAuth/Operational" $_LOG_DIR\WebAuth_Oper.evtx /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-WebAuthN/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-WebAuthN/Operational" $_LOG_DIR\\WebAuthn_Oper.evtx /overwrite:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-WebAuthN/Operational" /enabled:true /rt:false /q:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-CertPoleEng/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-CertPoleEng/Operational" $_LOG_DIR\Certpoleng_Oper.evtx /overwrite:true  2>&1 | Out-Null

	wevtutil query-events Application "/q:*[System[Provider[@Name='Microsoft-Windows-CertificateServicesClient-CertEnroll']]]" > $_CERT_LOG_DIR\CertificateServicesClientLog.xml 2>&1 | Out-Null
	certutil -policycache $_LOG_DIR\CertificateServicesClientLog.xml > $_LOG_DIR\ReadableClientLog.txt 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-IdCtrls/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-IdCtrls/Operational" $_LOG_DIR\Idctrls_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-IdCtrls/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-User Control Panel/Operational"  /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-User Control Panel/Operational" $_LOG_DIR\UserControlPanel_Oper.evtx /overwrite:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" $_LOG_DIR\Auth_Policy_Fail_DC.evtx /overwrite:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUser-Client" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Authentication/ProtectedUser-Client" $_LOG_DIR\Auth_ProtectedUser_Client.evtx /overwrite:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController" $_LOG_DIR\Auth_ProtectedUser_Fail_DC.evtx /overwrite:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController" $_LOG_DIR\Auth_ProtectedUser_Success_DC.evtx /overwrite:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Biometrics/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Biometrics/Operational" $_LOG_DIR\WinBio_oper.evtx /overwrite:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Biometrics/Operational" /enabled:true /rt:false /q:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-LiveId/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-LiveId/Operational" $_LOG_DIR\LiveId_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-LiveId/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-AAD/Analytic" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-AAD/Analytic" $_LOG_DIR\Aad_Analytic.evtx /overwrite:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-AAD/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-AAD/Operational" $_LOG_DIR\Aad_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-AAD/Operational"  /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Debug" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-User Device Registration/Debug" $_LOG_DIR\UsrDeviceReg_Dbg.evtx /overwrite:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-User Device Registration/Admin" $_LOG_DIR\UsrDeviceReg_Adm.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-HelloForBusiness/Operational" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-HelloForBusiness/Operational" $_LOG_DIR\Hfb_Oper.evtx /overwrite:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-HelloForBusiness/Operational" /enabled:true /rt:false /q:true  2>&1 | Out-Null

	wevtutil.exe export-log SYSTEM $_LOG_DIR\System.evtx /overwrite:true  2>&1 | Out-Null
	wevtutil.exe export-log APPLICATION $_LOG_DIR\Application.evtx /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Shell-Core/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Shell-Core/Operational" $_LOG_DIR\ShellCore_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Shell-Core/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-WMI-Activity/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-WMI-Activity/Operational" $_LOG_DIR\WMI-Activity_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-WMI-Activity/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe export-log "Microsoft-Windows-GroupPolicy/Operational" $_LOG_DIR\GroupPolicy.evtx /overwrite:true  2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Crypto-DPAPI/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Crypto-DPAPI/Operational" $_LOG_DIR\DPAPI_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Crypto-DPAPI/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-Containers-CCG/Admin" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Containers-CCG/Admin" $_LOG_DIR\Containers-CCG_Admin.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Containers-CCG/Admin" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" $_LOG_DIR\CertificateServicesClient-Lifecycle-System_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	wevtutil.exe set-log "Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational" $_LOG_DIR\CertificateServicesClient-Lifecycle-User_Oper.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational" /enabled:true /rt:false /q:true 2>&1 | Out-Null

	# ***COLLECT NGC DETAILS***
	<#
	Switch -Regex ($osVersionString) {
					'^6\.1\.7600' { 'Windows Server 2008 R2, Skipping dsregcmd...'}
					'^6\.1\.7601' { 'Windows Server 2008 R2 SP1, Skipping dsregcmd...'}
					'^6\.2\.9200' { 'Windows Server 2012, Skipping dsregcmd...'}
					'^6\.3\.9600' { 'Windows Server 2012 R2, Skipping dsregcmd...'}
					default {
									  Add-Content -Path $_LOG_DIR\Dsregcmd.txt -Value (dsregcmd /status 2>&1) | Out-Null
									  Add-Content -Path $_LOG_DIR\Dsregcmddebug.txt -Value (dsregcmd /status /debug /all 2>&1) | Out-Null
					}
	}
	#> 
	FwGetDSregCmd

	certutil -delreg Enroll\Debug  2>&1 | Out-Null
	certutil -delreg ngc\Debug  2>&1 | Out-Null
	certutil -delreg Enroll\LogLevel  2>&1 | Out-Null

	Copy-Item -Path "$($env:windir)\Ngc*.log" -Destination $_LOG_DIR -Force 2>&1 | Out-Null
	Get-ChildItem -Path $_LOG_DIR -Filter "Ngc*.log" | Rename-Item -NewName { "Pregenlog_" + $_.Name } 2>&1 | Out-Null

	Copy-Item -Path "$($env:LOCALAPPDATA)\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\settings\settings.dat" -Destination $_WAM_LOG_DIR\settings.dat -Force 2>&1 | Out-Null

	if ((Test-Path "$($env:LOCALAPPDATA)\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts\") -eq "True") {
		$WAMAccountsFullPath = GCI "$($env:LOCALAPPDATA)\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts\*.tbacct"
		foreach ($WAMAccountsFile in $WAMAccountsFullPath) {
			"File Name: " + $WAMAccountsFile.name + "`n" >> $_WAM_LOG_DIR\tbacct.txt
			Get-content -Path $WAMAccountsFile.FullName >> $_WAM_LOG_DIR\tbacct.txt -Encoding Unicode | Out-Null
			"`n`n" >> $_WAM_LOG_DIR\tbacct.txt
		}
	}

	#checking if Network trace is running - handled in TSS FW

	Add-Content -Path $_LOG_DIR\Ipconfig-info.txt -Value (ipconfig /all 2>&1) | Out-Null
	Add-Content -Path $_LOG_DIR\Displaydns.txt -Value (ipconfig /displaydns 2>&1) | Out-Null
	Add-Content -Path $_LOG_DIR\netstat.txt -Value (netstat -ano 2>&1) | Out-Null

	# ***Netlogon, LSASS, LSP, Netsetup and Gpsvc log***
	Copy-Item -Path "$($env:windir)\debug\Netlogon.*" -Destination $_LOG_DIR -Force 2>&1 | Out-Null
	Copy-Item -Path "$($env:windir)\system32\Lsass.log" -Destination $_LOG_DIR -Force 2>&1 | Out-Null
	Copy-Item -Path "$($env:windir)\debug\Lsp.*" -Destination $_LOG_DIR -Force 2>&1 | Out-Null
	Copy-Item -Path "$($env:windir)\debug\Netsetup.log" -Destination $_LOG_DIR -Force 2>&1 | Out-Null
	Copy-Item -Path "$($env:windir)\debug\usermode\gpsvc.*" -Destination $_LOG_DIR -Force 2>&1 | Out-Null

	# ***Credman***
	Add-Content -Path $_LOG_DIR\Credman.txt -Value (cmdkey.exe /list 2>&1) | Out-Null

	# ***Build info***
	$ProductName = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").ProductName
	$DisplayVersion = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").DisplayVersion
	$InstallationType = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").InstallationType
	$CurrentVersion = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentVersion
	$ReleaseId = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").ReleaseId
	$BuildLabEx = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").BuildLabEx
	$CurrentBuildHex = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentBuild
	$UBRHEX = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").UBR

	Add-Content -Path $_LOG_DIR\Build.txt -Value ($env:COMPUTERNAME + " " + $ProductName + " " + $InstallationType + " Version:" + $CurrentVersion + " " + $DisplayVersion + " Build:" + $CurrentBuildHex + "." + $UBRHEX) | Out-Null
	Add-Content -Path $_LOG_DIR\Build.txt -Value ("-------------------------------------------------------------------") | Out-Null
	Add-Content -Path $_LOG_DIR\Build.txt -Value ("BuildLabEx: " + $BuildLabEx) | Out-Null
	Add-Content -Path $_LOG_DIR\Build.txt -Value ("---------------------------------------------------") | Out-Null

	# ***Reg Exports***
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /s > $_LOG_DIR\Lsa-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /s > $_LOG_DIR\Policies-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /s > $_LOG_DIR\SystemGP-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer" /s > $_LOG_DIR\Lanmanserver-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /s > $_LOG_DIR\Lanmanworkstation-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon" /s > $_LOG_DIR\Netlogon-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /s > $_LOG_DIR\Schannel-key.txt 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography" /s > $_LOG_DIR\Cryptography-HKLMControl-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography" /s > $_LOG_DIR\Cryptography-HKLMSoftware-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography" /s > $_LOG_DIR\Cryptography-HKLMSoftware-Policies-key.txt 2>&1 | Out-Null

	reg query "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Cryptography" /s > $_LOG_DIR\Cryptography-HKCUSoftware-Policies-key.txt 2>&1 | Out-Null
	reg query "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Cryptography" /s > $_LOG_DIR\Cryptography-HKCUSoftware-key.txt 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider" /s > $_LOG_DIR\SCardCredentialProviderGP-key.txt 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication" /s > $_LOG_DIR\Authentication-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Authentication" /s > $_LOG_DIR\Authentication-key-Wow64.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /s > $_LOG_DIR\Winlogon-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Winlogon" /s > $_LOG_DIR\Winlogon-CCS-key.txt 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityStore" /s > $_LOG_DIR\Idstore-Config-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityCRL" /s >> $_LOG_DIR\Idstore-Config-key.txt 2>&1 | Out-Null
	reg query "HKEY_USERS\.Default\Software\Microsoft\IdentityCRL" /s >> $_LOG_DIR\Idstore-Config-key.txt 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc" /s > $_LOG_DIR\KDC-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KPSSVC" /s > $_LOG_DIR\KDCProxy-key.txt 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CloudDomainJoin" /s > $_LOG_DIR\RegCDJ-key.txt 2>&1 | Out-Null
	reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin" /s > $_LOG_DIR\Reg-WPJ-key.txt 2>&1 | Out-Null
	reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\AADNGC" /s > $_LOG_DIR\RegAADNGC-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\Software\Policies\Windows\WorkplaceJoin" /s > $_LOG_DIR\Reg-WPJ-Policy-key.txt 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Winbio" /s > $_LOG_DIR\Winbio-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc" /s > $_LOG_DIR\Wbiosrvc-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics" /s > $_LOG_DIR\Winbio-Policy-key.txt 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\EAS\Policies" /s > $_LOG_DIR\Eas-key.txt 2>&1 | Out-Null

	reg query "HKEY_CURRENT_USER\SOFTWARE\Microsoft\SCEP" /s > $_LOG_DIR\Scep-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient" /s > $_LOG_DIR\MachineId.txt 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork" /s > $_LOG_DIR\NgcPolicyIntune-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork" /s > $_LOG_DIR\NgcPolicyGp-key.txt 2>&1  | Out-Null
	reg query "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\PassportForWork" /s > $_LOG_DIR\NgcPolicyGpUser-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc" /s > $_LOG_DIR\NgcCryptoConfig-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock" /s > $_LOG_DIR\DeviceLockPolicy-key.txt 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork\SecurityKey " /s > $_LOG_DIR\FIDOPolicyIntune-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FIDO" /s > $_LOG_DIR\FIDOGp-key.txt 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /s > $_LOG_DIR\RpcGP-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /s > $_LOG_DIR\NTDS-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP" /s > $_LOG_DIR\LdapClient-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard" /s > $_LOG_DIR\DeviceGuard-key.txt 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CCMSetup" /s > $_SCCM_LOG_DIR\CCMSetup-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CCM" /s > $_SCCM_LOG_DIR\CCM-key.txt 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" > $_LOG_DIR\DotNET-TLS-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" >> $_LOG_DIR\DotNET-TLS-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" >> $_LOG_DIR\DotNET-TLS-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" >> $_LOG_DIR\DotNET-TLS-key.txt 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedPC" > $_LOG_DIR\SharedPC.txt 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess" > $_LOG_DIR\Passwordless.txt 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Authz" /s > $_LOG_DIR\Authz-key.txt 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" > $_LOG_DIR\WinHttp-TLS-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" >> $_LOG_DIR\WinHttp-TLS-key.txt 2>&1 | Out-Null

	reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" > $_LOG_DIR\SecureProtocols.txt 2>&1 | Out-Null
	reg query "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" >> $_LOG_DIR\SecureProtocols.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" >> $_LOG_DIR\SecureProtocols.txt 2>&1 | Out-Null
	reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" >> $_LOG_DIR\SecureProtocols.txt 2>&1 | Out-Null

	Add-Content -Path $_LOG_DIR\http-show-sslcert.txt -Value (netsh http show sslcert 2>&1) | Out-Null
	Add-Content -Path $_LOG_DIR\http-show-urlacl.txt -Value (netsh http show urlacl 2>&1) | Out-Null

	Add-Content -Path $_LOG_DIR\trustinfo.txt -Value (nltest /DOMAIN_TRUSTS /ALL_TRUSTS /V 2>&1) | Out-Null

	$domain = (Get-WmiObject Win32_ComputerSystem).Domain
	switch ($ProductType) {
		"WinNT" {
			Add-Content -Path $_LOG_DIR\SecureChannel.txt -Value (nltest /sc_query:$domain 2>&1) | Out-Null
		}
		"ServerNT" {
			Add-Content -Path $_LOG_DIR\SecureChannel.txt -Value (nltest /sc_query:$domain 2>&1) | Out-Null
		}
	}

	# ***Cert info***
	Add-Content -Path $_CERT_LOG_DIR\Machine-Store.txt -Value (certutil -v -silent -store my 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\User-Store.txt -Value (certutil -v -silent -user -store my 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Scinfo.txt -Value (Certutil -v -silent -scinfo 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Tpm-Cert-Info.txt -Value (certutil -tpminfo 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\CertMY_SmartCard.txt -Value (certutil -v -silent -user -store my "Microsoft Smart Card Key Storage Provider" 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Cert_MPassportKey.txt -Value (Certutil -v -silent -user -key -csp "Microsoft Passport Key Storage Provider" 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Homegroup-Machine-Store.txt -Value (certutil -v -silent -store "Homegroup Machine Certificates" 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\NTAuth-store.txt -Value (certutil -v -enterprise -store NTAuth 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Machine-Root-AD-store.txt -Value (certutil -v -store -enterprise root 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Machine-Root-Registry-store.txt -Value (certutil -v -store root 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Machine-Root-GP-Store.txt -Value (certutil -v -silent -store -grouppolicy root 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Machine-Root-ThirdParty-Store.txt -Value (certutil -v -store authroot 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Machine-CA-AD-store.txt -Value (certutil -v -store -enterprise ca 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Machine-CA-Registry-store.txt -Value (certutil -v -store ca 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Machine-CA-GP-Store.txt -Value (certutil -v -silent -store -grouppolicy ca 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Cert-template-cache-machine.txt -Value (certutil -v -template 2>&1) | Out-Null
	Add-Content -Path $_CERT_LOG_DIR\Cert-template-cache-user.txt -Value (certutil -v -template -user 2>&1) | Out-Null

	# *** Cert enrolment info
	Copy-Item "$($env:windir)\CertEnroll.log" -Destination $_CERT_LOG_DIR\CertEnroll-fromWindir.log -Force 2>&1 | Out-Null

	Copy-Item "$($env:windir)\certmmc.log" -Destination $_CERT_LOG_DIR\CAConsole.log -Force 2>&1 | Out-Null
	Copy-Item "$($env:windir)\certocm.log" -Destination $_CERT_LOG_DIR\ADCS-InstallConfig.log -Force 2>&1 | Out-Null
	Copy-Item "$($env:windir)\certsrv.log" -Destination $_CERT_LOG_DIR\ADCS-Debug.log -Force 2>&1 | Out-Null
	Copy-Item "$($env:windir)\CertUtil.log" -Destination $_CERT_LOG_DIR\CertEnroll-Certutil.log -Force 2>&1 | Out-Null
	Copy-Item "$($env:windir)\certreq.log" -Destination $_CERT_LOG_DIR\CertEnroll-Certreq.log -Force 2>&1 | Out-Null

	Copy-Item "$($env:userprofile)\CertEnroll.log" -Destination $_CERT_LOG_DIR\CertEnroll-fromUserProfile.log -Force 2>&1 | Out-Null
	Copy-Item "$($env:LocalAppData)\CertEnroll.log" -Destination $_CERT_LOG_DIRCertEnroll\CertEnroll-fromLocalAppData.log -Force 2>&1 | Out-Null

	Add-Content -Path $_LOG_DIR\Schtasks.query.v.txt -Value (schtasks.exe /query /v 2>&1) | Out-Null
	Add-Content -Path $_LOG_DIR\Schtasks.query.xml.txt -Value (schtasks.exe /query /xml 2>&1) | Out-Null

	LogInfo "Collecting Device enrollment information, please wait...."

	# **SCCM**
	$_SCCM_DIR = "$($env:windir)\CCM\Logs"
	If (Test-Path $_SCCM_DIR) {
		Copy-Item $_SCCM_DIR\CertEnrollAgent*.log -Destination $_SCCM_LOG_DIR -Force 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\StateMessage*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\DCMAgent*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\ClientLocation*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\CcmEval*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\CcmRepair*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\PolicyAgent.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\CIDownloader.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\PolicyEvaluator.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\DcmWmiProvider*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\CIAgent*.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\CcmMessaging.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\ClientIDManagerStartup.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
		Copy-Item $_SCCM_DIR\LocationServices.log -Destination $_SCCM_LOG_DIR 2>&1 | Out-Null
	}

	$_SCCM_DIR_Setup = "$($env:windir)\CCMSetup\Logs"
	If (Test-Path $_SCCM_DIR_Setup) {
		Copy-Item $_SCCM_DIR_Setup\ccmsetup.log -Destination $_SCCM_LOG_DIR -Force 2>&1 | Out-Null
	}

	# ***MDM***
	reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Enrollments" /s > $_MDM_LOG_DIR\MDMEnrollments-key.txt 2>&1 | Out-Null
	reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\EnterpriseResourceManager" /s > $_MDM_LOG_DIR\MDMEnterpriseResourceManager-key.txt 2>&1 | Out-Null
	reg query "HKEY_CURRENT_USER\Software\Microsoft\SCEP" /s > $_MDM_LOG_DIR\MDMSCEP-User-key.txt 2>&1 | Out-Null
	reg query "HKEY_CURRENT_USER\S-1-5-18\Software\Microsoft\SCEP" /s > $_MDM_LOG_DIR\MDMSCEP-SystemUser-key.txt 2>&1 | Out-Null

	wevtutil query-events Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin /format:text > $_MDM_LOG_DIR\DmEventLog.txt 2>&1 | Out-Null

	#DmEventLog.txt and Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider-Admin.txt might contain the same content
	$DiagProvierEntries = wevtutil el
	foreach ($DiagProvierEntry in $DiagProvierEntries) {
		$tempProvider = $DiagProvierEntry.Split('/')
		if ($tempProvider[0] -eq "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider") {
			wevtutil qe $($DiagProvierEntry) /f:text /l:en-us > "$_MDM_LOG_DIR\$($tempProvider[0])-$($tempProvider[1]).txt"   2>&1 | Out-Null
		}
	}

	LogInfo "Collecting Device configuration information, please wait...."

	Add-Content -Path $_LOG_DIR\Services-config.txt -Value (sc.exe query 2>&1) | Out-Null
	Add-Content -Path $_LOG_DIR\Services-started.txt -Value (net start 2>&1) | Out-Null
	Add-Content -Path $_LOG_DIR\FilterManager.txt -Value (fltmc 2>&1) | Out-Null
	Gpresult /h $_LOG_DIR\GPOresult.html 2>&1 | Out-Null

	(Get-ChildItem env:*).GetEnumerator() | Sort-Object Name | Out-File -FilePath $_LOG_DIR\Env.txt | Out-Null

	$env:COMPUTERNAME + " " + $ProductName + " " + $InstallationType + " Version:" + $CurrentVersion + " " + $DisplayVersion + " Build:" + $CurrentBuildHex + "." + $UBRHEX | Out-File -Append $_LOG_DIR\Build.txt
	"BuildLabEx: " + $BuildLabEx | Out-File -Append $_LOG_DIR\Build.txt

	$SystemFiles = @(
		"$($env:windir)\System32\kerberos.dll"
		"$($env:windir)\System32\lsasrv.dll"
		"$($env:windir)\System32\netlogon.dll"
		"$($env:windir)\System32\kdcsvc.dll"
		"$($env:windir)\System32\msv1_0.dll"
		"$($env:windir)\System32\schannel.dll"
		"$($env:windir)\System32\dpapisrv.dll"
		"$($env:windir)\System32\basecsp.dll"
		"$($env:windir)\System32\scksp.dll"
		"$($env:windir)\System32\bcrypt.dll"
		"$($env:windir)\System32\bcryptprimitives.dll"
		"$($env:windir)\System32\ncrypt.dll"
		"$($env:windir)\System32\ncryptprov.dll"
		"$($env:windir)\System32\cryptsp.dll"
		"$($env:windir)\System32\rsaenh.dll"
		"$($env:windir)\System32\Cryptdll.dll"
		"$($env:windir)\System32\cloudAP.dll"
	)

	ForEach ($File in $SystemFiles) {
		if (Test-Path $File -PathType leaf) {
			$FileVersionInfo = (get-Item $File).VersionInfo
			$FileVersionInfo.FileName + ",  " + $FileVersionInfo.FileVersion | Out-File -Append $_LOG_DIR\Build.txt
		}
	}

	# ***Hotfixes***
	Get-WmiObject -Class "win32_quickfixengineering" | Select -Property Description, HotfixID, @{Name = "InstalledOn"; Expression = { ([DateTime]($_.InstalledOn)).ToLocalTime() } }, Caption | Out-File -Append $_LOG_DIR\Qfes_installed.txt

	Add-Content -Path $_LOG_DIR\whoami.txt -Value (Whoami /all 2>&1) | Out-Null

	Add-Content -Path $_LOG_DIR\script-info.txt -Value ("Data collection stopped on: " + (Get-Date -Format "yyyy/MM/dd HH:mm:ss"))

	Remove-Item -Path $_LOG_DIR\started.txt -Force | Out-Null
}

# -------------- ADS_Basic ---------------
function ADS_BasicPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"

	$PreTraceLogs = $global:LogFolder + "\PreTraceLogs"
	FwCreateFolder $PreTraceLogs
	FwCreateFolder $env:SystemRoot\debug\usermode

	logman query * -ets > "$($PreTraceLogs)\$($global:LogPrefix)running-etl-providers.txt" 2>&1 | Out-Null

	# Event Logs

	#Event Log - Export Log
	$EventLogExportLogList = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogExportLogList = @(  #LogName, filename, overwrite
		@("Microsoft-Windows-CAPI2/Operational", "$($PreTraceLogs)\$($global:LogPrefix)Capi2_Oper.evtx", "true"),
		@("Microsoft-Windows-Kerberos/Operational", "$($PreTraceLogs)\$($global:LogPrefix)Kerberos_Oper.evtx", "true"),
		@("Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational", "$($PreTraceLogs)\$($global:LogPrefix)Kdc_Oper.evtx", "true"),
		@("Microsoft-Windows-Kerberos-KdcProxy/Operational", "$($PreTraceLogs)\$($global:LogPrefix)Kdc_Proxy_Oper.evtx", "true"),
		@("Microsoft-Windows-WebAuthN/Operational", "$($PreTraceLogs)\$($global:LogPrefix)WebAuthN_Oper.evtx", "true"),
		@("Microsoft-Windows-WebAuth/Operational", "$($PreTraceLogs)\$($global:LogPrefix)WebAuth_Oper.evtx", "true"),
		@("Microsoft-Windows-Biometrics/Operational", "$($PreTraceLogs)\$($global:LogPrefix)WinBio_oper.evtx", "true"),
		@("Microsoft-Windows-HelloForBusiness/Operational", "$($PreTraceLogs)\$($global:LogPrefix)Hfb_Oper.evtx", "true"),
		@("Microsoft-Windows-CertPoleEng/Operational", "$($PreTraceLogs)\$($global:LogPrefix)CertPoleEng_Oper.evtx", "true")
	)
	ForEach ($EventLog in $EventLogExportLogList){
		global:FwExportSingleEventLog $EventLog[0] $EventLog[1] $EventLog[2] 
	}

	#Event Log - Set Log - Enable
	$EventLogSetLogListOn = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogSetLogListOn = @(  #LogName, enabled, retention, quiet, MaxSize
		@("Microsoft-Windows-CAPI2/Operational", "true", "false", "true", "102400000"),
		@("Microsoft-Windows-Kerberos/Operational", "true", "false", "true", ""),
		@("Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational", "true", "false", "true", ""),
		@("Microsoft-Windows-Kerberos-KdcProxy/Operational", "true", "false", "true", ""),
		@("Microsoft-Windows-WebAuthN/Operational", "true", "false", "true", ""),
		@("Microsoft-Windows-WebAuth/Operational", "true", "false", "true", ""),
		@("Microsoft-Windows-Biometrics/Operational", "true", "false", "true", ""),
		@("Microsoft-Windows-HelloForBusiness/Operational", "true", "false", "true", ""),
		@("Microsoft-Windows-CertPoleEng/Operational", "true", "false", "true", "")
	)
	ForEach ($EventLog in $EventLogSetLogListOn)
	{
	global:FwEventLogsSet $EventLog[0] $EventLog[1] $EventLog[2] $EventLog[3] $EventLog[4]
	}

	#Event Log - Clear Log
	$EventLogClearLogList = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogClearLogList = @(  #LogName, enabled, retention, quiet, MaxSize
		@("Microsoft-Windows-CAPI2/Operational"),
		@("Microsoft-Windows-Kerberos/Operational")
	)
	ForEach ($EventLog in $EventLogClearLogList){
		global:FwEventLogClear $EventLog[0] 
	}
	
	# Registry
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" /f 2>&1 | Out-Null

	# *** ENABLE LOGGING VIA REGISTRY ***

	$RegAddValues = New-Object 'System.Collections.Generic.List[Object]'

	$RegAddValues = @(  #RegKey, RegValue, Type, Data
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\NegoExtender\Parameters", "InfoLevel", "REG_DWORD", "0xFFFF"),	# **NEGOEXT**
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Pku2u\Parameters", "InfoLevel", "REG_DWORD", "0xFFFF"),	# **PKU2U **
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "SPMInfoLevel", "REG_DWORD", "0xC43EFF"),	# **LSA**
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "LogToFile", "REG_DWORD", "0x1"),	# **LSA**
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "NegEventMask", "REG_DWORD", "0xF"),	# **LSA**
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "LspDbgInfoLevel", "REG_DWORD", "0x50410800"), # **LSP Logging** Reason: QFE 2022.1B added a new flag and without it we don’t see this final status STATUS_TRUSTED_DOMAIN_FAILURE on RODC
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "LspDbgTraceOptions", "REG_DWORD", "0x1"), # **LSP Logging**
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters", "LogLevel", "REG_DWORD", "0x1"), # **KERBEROS Logging to SYSTEM event log**
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL", "EventLogging", "REG_DWORD", "0x7"), # **SCHANNEL Logging to SYSTEM event log**
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics", "GPSvcDebugLevel", "REG_DWORD", "0x30002"), # **Enabling Group Policy Logging**
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics", "FdeployDebugLevel", "REG_DWORD", "0xF"), # **Enabling Folder Redirection Logging**
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}", "ExtensionDebugLevel", "REG_DWORD", "0x2") # **disable Winlogon Logging (Security Client Side Extension) **
	)

	ForEach ($regadd in $RegAddValues){
		global:FwAddRegValue $regadd[0] $regadd[1] $regadd[2] $regadd[3]
	}

	# **Netlogon logging**
	nltest /dbflag:0x2EFFFFFF 2>&1 | Out-Null

	# ** Turn on debug and verbose Cert Enroll event logging **
	Start-Sleep -s 7

	switch ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions).ProductType) 	#we# note TSS FW has already defined $global:ProductType 
	{
	"WinNT" {
			#write-host "WinNT"
			certutil -setreg -f Enroll\Debug 0xffffffe3 2>&1 | Out-Null
		}
	"ServerNT" {
			#write-host "ServerNT, Cert Enroll logging disabled by default"
			certutil -setreg -f Enroll\Debug 0xffffffe3 2>&1 | Out-Null
		}
	"LanmanNT" {
			#write-host "LanmanNT, Cert Enroll logging not disabled by default"
			certutil -setreg -f Enroll\Debug 0xffffffe3 2>&1 | Out-Null
		}
	}

	certutil -setreg ngc\Debug 1 2>&1 | Out-Null
	certutil -setreg Enroll\LogLevel 5 2>&1 | Out-Null

	FwGetDSregCmd
	FwGetTasklist
	FwGetSVC
	FwGetSVCactive
	#tasklist /svc > "$($PreTraceLogs)\$($global:LogPrefix)Tasklist.txt" 2>&1 | Out-Null
	#sc.exe query > "$($PreTraceLogs)\$($global:LogPrefix)Services-config.txt" 2>&1 | Out-Null
	#net start > "$($PreTraceLogs)\$($global:LogPrefix)Services-started.txt" 2>&1 | Out-Null

	FwGetKlist
	#klist > "$($PreTraceLogs)\$($global:LogPrefix)Tickets.txt" 2>&1 | Out-Null
	#klist -li 0x3e7 > "$($PreTraceLogs)\$($global:LogPrefix)Tickets-localsystem.txt" 2>&1 | Out-Null

	$Commands = @(
		"ipconfig /all | Out-File -Append $($PrefixTime)Ipconfig-info.txt"
		"ipconfig /displaydns | Out-File -Append $($PrefixTime)DisplayDns.txt"
		"netstat -ano  | Out-File -Append $($PrefixTime)netstat.txt"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False  
	EndFunc $MyInvocation.MyCommand.Name
}
function ADS_BasicPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	$CertinfoCertenroll = $global:LogFolder + "\Certinfo_and_Certenroll"

	#create CertinfoCertenroll in LogFolder
	FwCreateFolder $CertinfoCertenroll

	#tasklist /svc > "$($PrefixTime)Tasklist.txt" 2>&1 | Out-Null
	FwGetKlist
	#klist > "$($PrefixTime)Tickets.txt" 2>&1 | Out-Null
	#klist -li 0x3e7 > "$($PrefixTime)Tickets-localsystem.txt" 2>&1 | Out-Null

	# *** Clean up additional logging

	nltest /dbflag:0x0  2>&1 | Out-Null

	# RegDeleteValues
	$RegDeleteValues = New-Object 'System.Collections.Generic.List[Object]'
	$RegDeleteValues = @(  #RegKey, RegValue
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "SPMInfoLevel"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "LogToFile"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "NegEventMask"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\NegoExtender\Parameters", "InfoLevel"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\Pku2u\Parameters", "InfoLevel"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "LspDbgInfoLevel"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA", "LspDbgTraceOptions"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters", "LogLevel"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics", "GPSvcDebugLevel"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics", "FdeployDebugLevel") # **Enabling Folder Redirection Logging**
	)
	ForEach ($regdel in $RegDeleteValues){
		global:FwDeleteRegValue $regdel[0] $regdel[1] 
	}

	reg add HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL /v EventLogging /t REG_DWORD /d 1 /f  2>&1 | Out-Null
	reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" /v ExtensionDebugLevel /t REG_DWORD /d 0 /f  # **disable Winlogon Logging (Security Client Side Extension) **

	# *** Event/Operational logs
	#Event Log - Set Log - Disable
	$EventLogSetLogListOn = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogSetLogListOn = @(  #LogName, enabled, retention, quiet, MaxSize
		@("Microsoft-Windows-CAPI2/Operational", "false", "", "", ""),
		@("Microsoft-Windows-Kerberos/Operational", "false", "", "", ""),
		@("Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational", "false", "", "", ""),
		@("Microsoft-Windows-Kerberos-KdcProxy/Operational", "false", "", "", ""),
		@("Microsoft-Windows-WebAuthN/Operational", "false", "", "", ""),
		@("Microsoft-Windows-WebAuth/Operational", "false", "", "", ""),
		@("Microsoft-Windows-Biometrics/Operational", "false", "", "", ""),
		@("Microsoft-Windows-HelloForBusiness/Operational", "false", "", "", ""),
		@("Microsoft-Windows-CertPoleEng/Operational", "false", "", "", "")
	)
	ForEach ($EventLog in $EventLogSetLogListOn){
	global:FwEventLogsSet $EventLog[0] $EventLog[1] $EventLog[2] $EventLog[3] $EventLog[4]
	}

	#Event Log - Export Log
	$EventLogExportLogList = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogExportLogList = @(  #LogName, filename, overwrite
		@("Microsoft-Windows-CAPI2/Operational", "$($PrefixTime)Capi2_Oper.evtx", "true"),
		@("Microsoft-Windows-Kerberos/Operational", "$($PrefixTime)Kerberos_Oper.evtx", "true"),
		@("Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational", "$($PrefixTime)Kdc_Oper.evtx", "true"),
		@("Microsoft-Windows-Kerberos-KdcProxy/Operational", "$($PrefixTime)Kdc_Proxy_Oper.evtx", "true"),
		@("Microsoft-Windows-WebAuthN/Operational", "$($PrefixTime)WebAuthN_Oper.evtx", "true"),
		@("Microsoft-Windows-WebAuth/Operational", "$($PrefixTime)WebAuth_Oper.evtx", "true"),
		@("Microsoft-Windows-Biometrics/Operational", "$($PrefixTime)WinBio_oper.evtx", "true"),
		@("Microsoft-Windows-HelloForBusiness/Operational", "$($PrefixTime)Hfb_Oper.evtx", "true"),
		@("Microsoft-Windows-CertPoleEng/Operational", "$($PrefixTime)CertPoleEng_Oper.evtx", "true"),
		@("SYSTEM", "$($PrefixTime)System.evtx", "true"),
		@("APPLICATION", "$($PrefixTime)Application.evtx", "true"),
		@("Microsoft-Windows-GroupPolicy/Operational", "$($PrefixTime)GroupPolicy.evtx", "true")
	)
	ForEach ($EventLog in $EventLogExportLogList){
		global:FwExportSingleEventLog $EventLog[0] $EventLog[1] $EventLog[2] 
	}

	#Event Log - Set Log - Enable
	$EventLogSetLogListOn = New-Object 'System.Collections.Generic.List[Object]'
	$EventLogSetLogListOn = @(  #LogName, enabled, retention, quiet, MaxSize
		@("Microsoft-Windows-WebAuthN/Operational", "true", "false", "true", ""),
		@("Microsoft-Windows-Biometrics/Operational", "true", "false", "true", ""),
		@("Microsoft-Windows-HelloForBusiness/Operational", "true", "false", "true", "")
	)
	ForEach ($EventLog in $EventLogSetLogListOn){
	global:FwEventLogsSet $EventLog[0] $EventLog[1] $EventLog[2] $EventLog[3] $EventLog[4]
	}

	wevtutil query-events Application "/q:*[System[Provider[@Name='Microsoft-Windows-CertificateServicesClient-CertEnroll']]]" > "$CertinfoCertenroll\$($global:LogPrefix)CertificateServicesClientLog.xml" 2>&1 | Out-Null
	certutil -policycache "$CertinfoCertenroll\$($global:LogPrefix)CertificateServicesClientLog.xml" > "$CertinfoCertenroll\$($global:LogPrefix)ReadableClientLog.txt" 2>&1 | Out-Null

	# *** NGC
	$Commands = @(
		"certutil -delreg Enroll\Debug"
		"certutil -delreg ngc\Debug"
		"certutil -delreg Enroll\LogLevel"
		"ipconfig /all | Out-File -Append $($PrefixTime)Ipconfig-info.txt"
		"ipconfig /displaydns | Out-File -Append $($PrefixTime)DisplayDns.txt"
		"netstat -ano  | Out-File -Append $($PrefixTime)netstat.txt"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False	

	# *** Netlogon, LSASS, LSP, Netsetup and Gpsvc log
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(  #source (* wildcard is supported) and destination
		@("$($env:windir)\Ngc*.log", "$global:LogFolder"),	#this will copy all files that match * criteria into dest folder
		@("$($env:windir)\debug\Netlogon.*", "$global:LogFolder"),	#this will copy test1.txt to destination file name and add logprefix
		@("$($env:windir)\system32\Lsass.log", "$($PrefixTime)Lsass.log"),
		@("$($env:windir)\debug\Lsp.*", "$global:LogFolder"),
		@("$($env:windir)\debug\Netsetup.log", "$($PrefixTime)Netsetup.log"),
		@("$($env:windir)\debug\usermode\gpsvc.*", "$global:LogFolder"),
		@("$($env:windir)\CertEnroll.log", "$CertinfoCertenroll\$($global:LogPrefix)CertEnroll-fromWindir.log"), # *** Cert enrolment info
		@("$($env:userprofile)\CertEnroll.log", "$CertinfoCertenroll\$($global:LogPrefix)CertEnroll-fromUserProfile.log"), # *** Cert enrolment info
		@("$($env:LocalAppData)\CertEnroll.log", "$CertinfoCertenroll\$($global:LogPrefix)CertEnroll-fromLocalAppData.log"), # *** Cert enrolment info
		@("$($env:windir)\security\logs\winlogon.log", "$($PrefixTime)Winlogon.log") # *** Winlogon log
	)

	global:FwCopyFiles $SourceDestinationPaths 

	# *** Credman
	cmdkey.exe /list > "$($PrefixTime)Credman.txt"  2>&1 | Out-Null

	# *** Build info 
	$ProductName = $global:OperatingSystemInfo.ProductName
	$CurrentVersion = $global:OperatingSystemInfo.CurrentVersion
	$ReleaseId = $global:OperatingSystemInfo.ReleaseId
	$BuildLabEx = $global:OperatingSystemInfo.BuildLabEx
	$CurrentBuildHex = $global:OperatingSystemInfo.CurrentBuild

	LogInfoFile ($env:COMPUTERNAME + " " + $ProductName + " " + $ReleaseId + " Version:" + $CurrentVersion + " " + $CurrentBuildHex)
	LogInfoFile ("BuildLabEx: " + $BuildLabEx)

	# *** Reg exports
	LogInfo "[$global:TssPhase ADS Stage:] Exporting Reg.keys .. " "gray"
	$RegExportKeyInTxt = New-Object 'System.Collections.Generic.List[Object]'

	$RegExportKeyInTxt = @(  #Key, ExportFile, Format (TXT or REG)
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa", "$($PrefixTime)reg_Lsa.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies", "$($PrefixTime)reg_Policies.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System", "$($PrefixTime)reg_SystemGP.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer", "$($PrefixTime)reg_Lanmanserver.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation", "$($PrefixTime)reg_Lanmanworkstation.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon", "$($PrefixTime)reg_Netlogon.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL", "$($PrefixTime)reg_Schannel.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography", "$($PrefixTime)reg_Cryptography-HKLMControl.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography", "$($PrefixTime)reg_Cryptography-HKLMSoftware.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography", "$($PrefixTime)reg_Cryptography-HKLMSoftware-Policies.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider", "$($PrefixTime)reg_SCardCredentialProviderGP.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication", "$($PrefixTime)reg_Authentication.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Authentication", "$($PrefixTime)reg_Authentication-key-Wow64.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "$($PrefixTime)reg_Winlogon.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Winlogon", "$($PrefixTime)reg_Winlogon-CCS.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc", "$($PrefixTime)reg_KDC.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KPSSVC", "$($PrefixTime)reg_KDCProxy.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Winbio", "$($PrefixTime)reg_Winbio.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc", "$($PrefixTime)reg_Wbiosrvc.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics", "$($PrefixTime)reg_Winbio-Policy.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\EAS\Policies", "$($PrefixTime)reg_Eas.txt", "TXT"),
		@("HKEY_CURRENT_USER\SOFTWARE\Microsoft\SCEP", "$($PrefixTime)reg_Scep.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient", "$($PrefixTime)reg_MachineId.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork", "$($PrefixTime)reg_NgcPolicyIntune.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork", "$($PrefixTime)reg_NgcPolicyGp.txt", "TXT"),
		@("HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\PassportForWork", "$($PrefixTime)reg_NgcPolicyGpUser.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc", "$($PrefixTime)reg_NgcCryptoConfig.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock", "$($PrefixTime)reg_DeviceLockPolicy.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork\SecurityKey ", "$($PrefixTime)reg_FIDOPolicyIntune.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FIDO", "$($PrefixTime)reg_FIDOGp.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc", "$($PrefixTime)reg_RpcGP.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters", "$($PrefixTime)reg_NTDS.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP", "$($PrefixTime)reg_LdapClient.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard", "$($PrefixTime)reg_DeviceGuard.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions", "$($PrefixTime)reg_GPExtensions.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedPC", "$($PrefixTime)reg_SharedPC.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess", "$($PrefixTime)reg_Passwordless.txt", "TXT"),
		@("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Authz", "$($PrefixTime)reg_Authz.txt", "TXT")
	)
	ForEach ($regtxtexport in $RegExportKeyInTxt){
		global:FwExportRegKey $regtxtexport[0] $regtxtexport[1] $regtxtexport[2]
	}

	LogInfo "[$global:TssPhase ADS Stage:] 'http show sslcert' .. " "gray"
	netsh http show sslcert > "$($PrefixTime)http-show-sslcert.txt" 2>&1 | Out-Null 
	netsh http show urlacl > "$($PrefixTime)http-show-urlacl.txt" 2>&1 | Out-Null 

	nltest /DOMAIN_TRUSTS /ALL_TRUSTS /V > "$($PrefixTime)trustinfo.txt" 2>&1 | Out-Null 

	$domain = (Get-CimInstance Win32_ComputerSystem).Domain

	switch ((Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions).ProductType) 	#we# note TSS FW has already defined $global:ProductType 
		{
		"WinNT" {
				nltest /sc_query:$domain > "$($PrefixTime)SecureChannel.txt" 2>&1 | Out-Null 
			}
		"ServerNT" {
				nltest /sc_query:$domain > "$($PrefixTime)SecureChannel.txt" 2>&1 | Out-Null 
			}
		"LanmanNT" {
				LogInfo "LanmanNT, skip nltest"
				#certutil -setreg -f Enroll\Debug 0xffffffe3 2>&1 | Out-Null
			}
		}

	# *** Cert info
	LogInfo "[$global:TssPhase ADS Stage:] 'certutil -v' .. " "gray"
	certutil -v -silent -store my > "$CertinfoCertenroll\$($global:LogPrefix)Machine-Store.txt"  2>&1 | Out-Null
	certutil -v -silent -user -store my > "$CertinfoCertenroll\$($global:LogPrefix)User-Store.txt" 2>&1 | Out-Null
	Certutil -v -silent -scinfo > "$CertinfoCertenroll\$($global:LogPrefix)Scinfo.txt" 2>&1 | Out-Null
	certutil -tpminfo > "$CertinfoCertenroll\$($global:LogPrefix)Tpm-Cert-Info.txt" 2>&1 | Out-Null
	certutil -v -silent -user -store my "Microsoft Smart Card Key Storage Provider" > "$CertinfoCertenroll\$($global:LogPrefix)CertMY_SmartCard.txt" 2>&1 | Out-Null
	Certutil -v -silent -user -key -csp "Microsoft Passport Key Storage Provider" > "$CertinfoCertenroll\$($global:LogPrefix)Cert_MPassportKey.txt" 2>&1 | Out-Null
	certutil -v -silent -store "Homegroup Machine Certificates" > "$CertinfoCertenroll\$($global:LogPrefix)Homegroup-Machine-Store.txt" 2>&1 | Out-Null
	certutil -v -enterprise -store NTAuth > "$CertinfoCertenroll\$($global:LogPrefix)NTAuth-store.txt" 2>&1 | Out-Null
	certutil -v -store -enterprise root > "$CertinfoCertenroll\$($global:LogPrefix)Machine-Root-AD-store.txt" 2>&1 | Out-Null
	certutil -v -store root > "$CertinfoCertenroll\$($global:LogPrefix)Machine-Root-Registry-store.txt" 2>&1 | Out-Null
	certutil -v -silent -store -grouppolicy root > "$CertinfoCertenroll\$($global:LogPrefix)Machine-Root-GP-Store.txt" 2>&1 | Out-Null
	certutil -v -store authroot > "$CertinfoCertenroll\$($global:LogPrefix)Machine-Root-ThirdParty-Store.txt" 2>&1 | Out-Null
	certutil -v -store -enterprise ca > "$CertinfoCertenroll\$($global:LogPrefix)Machine-CA-AD-store.txt" 2>&1 | Out-Null
	certutil -v -store ca > "$CertinfoCertenroll\$($global:LogPrefix)Machine-CA-Registry-store.txt" 2>&1 | Out-Null
	certutil -v -silent -store -grouppolicy ca > "$CertinfoCertenroll\$($global:LogPrefix)Machine-CA-GP-Store.txt" 2>&1 | Out-Null
	
	LogInfo "[$global:TssPhase ADS Stage:] 'schtasks' .. " "gray"
	schtasks.exe /query /v > "$($PrefixTime)Schtasks.query.v.txt"  2>&1 | Out-Null
	schtasks.exe /query /xml > "$($PrefixTime)Schtasks.query.xml.txt"  2>&1 | Out-Null

	LogInfo "[$global:TssPhase ADS Stage:] 'Services' .. " "gray"
	FwGetTasklist
	FwGetSVC
	FwGetSVCactive
	#sc.exe query > "$($PrefixTime)Services-config.txt" 2>&1 | Out-Null
	#net start > "$($PrefixTime)Services-started.txt" 2>&1 | Out-Null

	fltmc > "$($PrefixTime)FilterManager.txt" 2>&1 | Out-Null

	LogInfo "[$global:TssPhase ADS Stage:] 'gpresult /h' .. " "gray"
	gpresult /h "$($PrefixTime)GPOresult.html"  2>&1 | Out-Null

	(Get-ChildItem env:*).GetEnumerator() | Sort-Object Name | Out-File -FilePath "$($PrefixTime)Env.txt"

	LogInfo "[$global:TssPhase ADS Stage:] 'FileVersionInfo' .. " "gray"
	$env:COMPUTERNAME + " " + $ProductName + " " + $ReleaseId + " Version:" + $CurrentVersion + " " + $CurrentBuildHex | Out-File -Append "$($PrefixTime)Build.txt"
	"BuildLabEx: " + $BuildLabEx | Out-File -Append "$($PrefixTime)Build.txt"

	$SystemFiles = @(
	"$($env:windir)\System32\kerberos.dll"
	"$($env:windir)\System32\lsasrv.dll"
	"$($env:windir)\System32\netlogon.dll"
	"$($env:windir)\System32\kdcsvc.dll"
	"$($env:windir)\System32\msv1_0.dll"
	"$($env:windir)\System32\schannel.dll"
	"$($env:windir)\System32\dpapisrv.dll"
	"$($env:windir)\System32\basecsp.dll"
	"$($env:windir)\System32\scksp.dll"
	"$($env:windir)\System32\bcrypt.dll"
	"$($env:windir)\System32\bcryptprimitives.dll"
	"$($env:windir)\System32\ncrypt.dll"
	"$($env:windir)\System32\ncryptprov.dll"
	"$($env:windir)\System32\cryptsp.dll"
	"$($env:windir)\System32\rsaenh.dll"
	"$($env:windir)\System32\Cryptdll.dll"
	)

	ForEach($File in $SystemFiles){
		if (Test-Path $File -PathType leaf) {
			$FileVersionInfo = (get-Item $File).VersionInfo
			$FileVersionInfo.FileName + ",  " + $FileVersionInfo.FileVersion | Out-File -Append "$($PrefixTime)Build.txt"
		}
	}		
  
	LogInfo "[$global:TssPhase ADS Stage:] 'Hotfix Info' .. " "gray"  
	Get-CimInstance -Class "win32_quickfixengineering" | Select-Object -Property "Description", "HotfixID", @{Name="InstalledOn"; Expression={([DateTime]($_.InstalledOn)).ToLocalTime()}} | Out-File -Append "$($PrefixTime)Qfes_installed.txt"

	EndFunc $MyInvocation.MyCommand.Name
}

# -------------- ADS_CEPCES ---------------
function ADS_CEPCESPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"	

	wevtutil.exe set-log "Microsoft-Windows-EnrollmentPolicyWebService/Admin" /enabled:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-EnrollmentWebService/Admin" /enabled:true 2>&1 | Out-Null

	FwListProcsAndSvcs
	#Get-Process | Out-File -FilePath "$($PrefixTime)start-tasklist.txt" 2>&1 | Out-Null

	LogInfoFile "ADS_CEPCESPreStart completed"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_CEPCESLog{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"	
	wevtutil.exe set-log "Microsoft-Windows-EnrollmentPolicyWebService/Admin" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-EnrollmentPolicyWebService/Admin" "$($PrefixTime)EnrollmentPolicy.evtx" /overwrite:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-EnrollmentWebService/Admin" /enabled:false  2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-EnrollmentWebService/Admin" "$($PrefixTime)EnrollmentWeb.evtx" /overwrite:true  2>&1 | Out-Null
	wevtutil epl System "$($PrefixTime)System.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil epl Application "$($PrefixTime)Application.evtx" /overwrite:true 2>&1 | Out-Null
	Get-ChildItem env:* |  Out-File -FilePath "$($PrefixTime)env.txt" 2>&1 | Out-Null
	FwListProcsAndSvcs
	#Get-Process | Out-File -FilePath "$($PrefixTime)stop-tasklist.txt" 2>&1 | Out-Null
	LogInfoFile "CollectADS_CEPCESLog completed"
	EndFunc $MyInvocation.MyCommand.Name
}

# -------------- ADS_DFSr ---------------
function CollectADS_DFSrLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwExportEventLog @("DFS Replication") $global:LogFolder
	LogInfoFile "[$($MyInvocation.MyCommand.Name)]  copy DFSR*.log and last 5 *DFSR*.log.gz files"
	FwCreateFolder $global:LogFolder\DFSR
	Get-ChildItem $Env:SystemRoot\debug\*DFSR*.log.gz | Sort-Object -Property LastWriteTime | Select-Object -Last 5 | Copy-Item -Destination $global:LogFolder\DFSR\
	$Commands = @(
		"xcopy /i/q/y/H $Env:SystemRoot\debug\Dfsr*.log $global:LogFolder\DFSR"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

# -------------- ADSESR  ---------------
function ADS_ESRPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v BuildLabEx > "$($PrefixTime)build.txt" 2>&1 | Out-Null 

	# -- ** Starting WAM tracing and saving it in .\ESRLogs **

	#set.exe SslDbFlags=0x4000ffff
	$env:SslDbFlags = '0x4000ffff'

	<#
	this is already implemetedin WebAuth and NGC ETL...verify
	set.exe _TRACEGUID.WAM=077b8c4a-e425-578d-f1ac-6fdf1220ff68
	[System.Environment]::SetEnvironmentVariable('_TRACEGUID.WAM','077b8c4a-e425-578d-f1ac-6fdf1220ff68',[System.EnvironmentVariableTarget]::Machine)
	set.exe _TRACEGUID.MSAWamProvider=5836994d-a677-53e7-1389-588ad1420cc5
	set.exe _TRACEGUID.CXH=d0034f5e-3686-5a74-dc48-5a22dd4f3d5b
	set.exe _TRACEGUID.AADWamProvider=4DE9BC9C-B27A-43C9-8994-0915F1A5E24F
	set.exe _TRACEGUID.BackgroundInfra=63b6c2d2-0440-44de-a674-aa51a251b123
	set.exe _TRACEGUID.ResourceManager=4180c4f7-e238-5519-338f-ec214f0b49aa
	set.exe _TRACEGUID.AppModel=EB65A492-86C0-406A-BACE-9912D595BD69
	#>

	wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /e:true /rt:false /q:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-CloudStore/Debug" /e:true /rt:false /q:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-AAD/Analytic" /e:true /rt:false /q:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-AAD/Operational" /e:true /rt:false /q:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Debug" /e:true /rt:false /q:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /e:true /rt:false /q:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-PushNotification-Platform/Debug" /e:true /rt:false /q:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-PushNotification-Platform/Admin" /e:true /rt:false /q:true  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /e:true /rt:false /q:true  2>&1 | Out-Null

	# ** Flushing DNS Cache **
	ipconfig /flushdns

	# ** IP Configuration **
	ipconfig /all > "$($PrefixTime)Ipconfig-info.txt" 2>&1 | Out-Null
	#ipconfig /all> .\ipconfig.txt

	# ** Collecting Tasklist output at the time of starting the script **
	FwGetTasklist
	#tasklist /svc > "$($PrefixTime)Tasklist.txt" 2>&1 | Out-Null

	EndFunc $MyInvocation.MyCommand.Name
}
function ADS_ESRPostStop{	
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"
	<#
	this is already implemetedin WebAuth and NGC ETL...verify
	set.exe _TRACEGUID.WAM=077b8c4a-e425-578d-f1ac-6fdf1220ff68
	[System.Environment]::SetEnvironmentVariable('_TRACEGUID.WAM','077b8c4a-e425-578d-f1ac-6fdf1220ff68',[System.EnvironmentVariableTarget]::Machine)
	set.exe _TRACEGUID.MSAWamProvider=5836994d-a677-53e7-1389-588ad1420cc5
	set.exe _TRACEGUID.CXH=d0034f5e-3686-5a74-dc48-5a22dd4f3d5b
	set.exe _TRACEGUID.AADWamProvider=4DE9BC9C-B27A-43C9-8994-0915F1A5E24F
	set.exe _TRACEGUID.BackgroundInfra=63b6c2d2-0440-44de-a674-aa51a251b123
	set.exe _TRACEGUID.ResourceManager=4180c4f7-e238-5519-338f-ec214f0b49aa
	set.exe _TRACEGUID.AppModel=EB65A492-86C0-406A-BACE-9912D595BD69
	#>

	#create CDPLogs in LogFolder
	$CDPLogs = $global:LogFolder + "\CDPlogs"
	if (!(Test-Path $CDPLogs)){
		New-Item -ItemType directory -Path $CDPLogs | Out-Null
		#Write-debug ("New log folder" + $CDPLogs + " created")
		LogInfo ($CDPLogs + " created") "gray"
	}else{
		#write-debug ($CDPLogs + ' already exists.')
		LopInfo ($CDPLogs + " already exists")
	}

	#settingsynchost.exe -loadandrundiagscript .\
	#settingsynchost.exe -loadandrundiagscript $($global:LogFolder)  #settingsynchost.exe is not present on Win11 machine... need to check with ESR script owner
	FwGetDSregCmd

	wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /e:false  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-CloudStore/Debug" /e:false  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-AAD/Analytic" /e:false  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-AAD/Operational" /e:false  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Debug" /e:false  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /e:false  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-PushNotification-Platform/Debug" /e:false  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-PushNotification-Platform/Admin" /e:false  2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /e:false  2>&1 | Out-Null


	wevtutil.exe export-log "Microsoft-Windows-AAD/Operational" "$($PrefixTime)aad_oper.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-AAD/Analytic" "$($PrefixTime)aad_analytic.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-User Device Registration/Admin" "$($PrefixTime)usrdevicereg_adm.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-User Device Registration/Debug" "$($PrefixTime)usrdevicereg_dbg.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-PushNotification-Platform/Admin" "$($PrefixTime)push-notification-platform_adm.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-PushNotification-Platform/Debug" "$($PrefixTime)push-notification-platform_dbg.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-CloudStore/Debug" "$($PrefixTime)CDS-Debug.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-CloudStore/Operational" "$($PrefixTime)CDS-Operational.evtx" /overwrite:true 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-CAPI2/Operational" "$($PrefixTime)CAPI2.evtx" /overwrite:true 2>&1 | Out-Null

	# - ** Collecting Tasklist output at the time of starting the script **
	FwGetTasklist
	#tasklist /svc > "$($PrefixTime)tasklist-at-stop.txt" 2>&1 | Out-Null

	# -- ** Capture DNS Cache **
	ipconfig /displaydns > "$($PrefixTime)DisplayDns.txt" 2>&1 | Out-Null

	#reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /s > "$($PrefixTime)reg_CDPlogs_Policies-key1.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /s > "$CDPLogs\$($global:LogPrefix)reg_CDPlogs_Policies-key1.txt" 2>&1 | Out-Null 
	
	#reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /s > "$($PrefixTime)reg_CDPlogs_Policies-key2.txt" 2>&1 | Out-Null 
	reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /s > "$CDPLogs\$($global:LogPrefix)reg_CDPlogs_Policies-key2.txt" 2>&1 | Out-Null 

	#set.exe > env.txt
	(Get-ChildItem env:*).GetEnumerator() | Sort-Object Name | Out-File -FilePath "$($PrefixTime)Env.txt"
	
	EndFunc $MyInvocation.MyCommand.Name
}

function ADS_GPeditPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] adding Group Policy Management Editor Reg Debug keys"
	FwCreateFolder $env:SystemRoot\debug\usermode
	FwAddRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "GPEditDebugLevel" "REG_DWORD" $global:GPEditDebugLevel	#_# $global:GPEditDebugLevel = "0x10002"
	FwAddRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "GPTextDebugLevel" "REG_DWORD" "0x10002"
	LogWarn "[Info] [$($MyInvocation.MyCommand.Name)] consider to add -LDAPcli tracing" Cyan
	LogInfoFile " starting dummy ADS_GPeditTrace.etl"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_GPeditLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] resetting GPedit Debug Reg Key to default"
	FwDeleteRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "GPEditDebugLevel"
	FwDeleteRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "GPTextDebugLevel"
	LogInfo "[$($MyInvocation.MyCommand.Name)]  collecting debug GPedit.log into debug\usermode\"
	FwCreateFolder $global:LogFolder\debug\usermode
	$Commands = @(
		"xcopy /e/y $env:WinDir\debug\usermode\*.* $global:LogFolder\debug\usermode\ "
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function ADS_GPmgmtPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] adding Group Policy Management Console Reg Debug keys"
	FwAddRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" "GPMgmtTraceLevel" "REG_DWORD" "0x2"
	FwAddRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" "GPMgmtLogFileOnly" "REG_DWORD" "0x1"
	LogInfoFile " starting dummy ADS_GPmgmtTrace.etl"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_GPmgmtLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] resetting GPmgmt Reg Keys to default"
	FwDeleteRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" "GPMgmtTraceLevel"
	FwDeleteRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" "GPMgmtLogFileOnly"
	LogInfo "[$($MyInvocation.MyCommand.Name)] collecting debug $env:temp\GPmgmt.log"
	$Commands = @(
		"xcopy /y $env:temp\GPmgmt*.* $global:LogFolder\GPmgmt\ "
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function ADS_GPOPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"

# import registry
# Key "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Group Policy" does not exist by default
$regcontent = 'Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy]
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{0E28E245-9368-4853-AD84-6DA3BA35BB75}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{17D89FEC-5C44-4972-B12D-241CAEF74509}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{1A6364EB-776B-4120-ADE1-B63A406A76B5}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{3A0DBA37-F8B2-4356-83DE-3E90BD5C261F}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{5794DAFD-BE60-433f-88A2-1A31939AC01F}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{6232C319-91AC-4931-9385-E70C2B099F0E}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{6A4C88C6-C502-4f74-8F60-2CB23EDC24E2}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{7150F9BF-48AD-4da4-A49C-29EF4A8369BA}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{728EE579-943C-4519-9EF7-AB56765798ED}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{74EE6C03-5363-4554-B161-627540339CAB}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{91FBB303-0CD5-4055-BF42-E512A681B325}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{A3F3E39B-5D83-4940-B954-28315B82F0A8}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{AADCED64-746C-4633-A97C-D61349046527}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{B087BE9D-ED37-454f-AF9C-04291E351182}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{C418DD9D-0D14-4efb-8FBF-CFE535C8FAC7}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{E47248BA-94CC-49c4-BBB5-9EB7F05183D0}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{E4F48E54-F38D-4884-BFB9-D4D2E5729C18}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{E5094040-C46C-4115-B030-04FB2E545B00}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{E62688F0-25FD-4c90-BFF5-F508B9D2E31F}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{F9C77450-3A41-477E-9310-9ACD617BD9E3}]
"LogLevel"=dword:00000003
"TraceLevel"=dword:00000002
"TraceFilePathUser"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,52,\
  00,49,00,56,00,45,00,25,00,5c,00,55,00,73,00,65,00,72,00,2e,00,6c,00,6f,00,\
  67,00,00,00
"TraceFilePathMachine"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,43,00,6f,00,6d,00,70,00,75,00,74,00,65,\
  00,72,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFilePathPlanning"=hex(2):25,00,53,00,59,00,53,00,54,00,45,00,4d,00,44,00,\
  52,00,49,00,56,00,45,00,25,00,5c,00,50,00,6c,00,61,00,6e,00,6e,00,69,00,6e,\
  00,67,00,2e,00,6c,00,6f,00,67,00,00,00
"TraceFileMaxSize"=dword:00000400'

	$regcontent | Out-File myreg.reg
	$RegImportResult = (Start-Process -FilePath "reg.exe" -ArgumentList "import myreg.reg" -NoNewWindow -PassThru -Wait ).ExitCode
	LogInfo "RegImportResult = $RegImportResult"
	EndFunc $MyInvocation.MyCommand.Name
}
function ADS_GPOPostStop{
	#delete registry
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"
	Get-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy" | Remove-Item -Recurse -Force -Verbose -Confirm:$false
	EndFunc $MyInvocation.MyCommand.Name

}
function CollectADS_GPOLog{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] .. started"

	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(  #source (* wildcard is supported) and destination
		#@("C:\User.log", "$($PrefixTime)User.log"),
		#@("C:\Computer.log", "$($PrefixTime)Computer.log")
		#@("C:\Planning.log", "$($PrefixTime)Planing.log")
		@("$env:SystemDrive\User.log", "$($PrefixTime)GPPREF_User.log"),
		@("$env:SystemDrive\Computer.log", "$($PrefixTime)GPPREF_Computer.log"),
		@("$env:SystemDrive\Planning.log", "$($PrefixTime)GPPREF_Planing.log")
	)
	global:FwCopyFiles $SourceDestinationPaths

	#delete log files in $env:SystemDrive\User.log, $env:SystemDrive\Computer.log and $env:SystemDrive\Planing.log
		$FileClearLogList = New-Object 'System.Collections.Generic.List[Object]'
		$FileClearLogList = @(  
		@("$env:SystemDrive\User.log"),
		@("$env:SystemDrive\Computer.log"),
		@("$env:SystemDrive\Planing.log"),
		@("myreg.reg")
		)

		ForEach ($file in $FileClearLogList){
			if (Test-Path $file){
				Remove-Item $file -Force
			}
		}
	EndFunc $MyInvocation.MyCommand.Name
}

function ADS_GPsvcPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] adding Group Policy Processing Reg Debug key: GPSvcDebugLevel=0x30002"
	FwCreateFolder $env:SystemRoot\debug\usermode
	FwAddRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" "GPSvcDebugLevel" "REG_DWORD" "0x30002"
	FwAddRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" "RunDiagnosticLoggingGlobal" "REG_DWORD" "0x1"
	$Commands = @( "NLTEST /DbFlag:0x2EFFFFFF | Out-File -Append $global:ErrorLogFile")
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	FwAddRegItem @("GPsvc") _Start_ 
	LogInfoFile " starting dummy ADS_GPsvcTrace.etl"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_GPsvcLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] resetting GPsvc Reg Keys to default"
	FwDeleteRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" "GPSvcDebugLevel"
	FwDeleteRegValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" "RunDiagnosticLoggingGlobal"
	$Commands = @( "NLTEST /DbFlag:0x0 | Out-File -Append $global:ErrorLogFile")
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	LogInfo "[$($MyInvocation.MyCommand.Name)] collecting debug GPsvc.log"
	FwCreateFolder $global:LogFolder\GPsvc
	$Commands = @(
		"xCopy /y $env:SystemRoot\debug\usermode\GPsvc.* $global:LogFolder\GPsvc\ "
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	FwAddRegItem @("GPsvc","Print") _Stop_ 
	$EvtLogsGPO | ForEach-Object { FwAddEvtLog $_ _Stop_} 
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectADS_LDAPsrvLog {
	EnterFunc $MyInvocation.MyCommand.Name
	$EvtLogsLDAPsrv | ForEach-Object { FwAddEvtLog $_ _Stop_} 
	EndFunc $MyInvocation.MyCommand.Name
}

# -------------- ADS_LockOut --------------- #_# ToDo: compare to ADS_AccountLockoutS
function CollectADS_LockOutLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] you need to have domain admin privilege to run this script GetLockoutEvents"
	.\scripts\tss_GetLockoutEvents.ps1 -DataPath $global:LogFolder
	EndFunc $MyInvocation.MyCommand.Name
}

function ADS_NetlogonPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] .. Enabling Netlogon service debug log DbFlag:$global:NetLogonFlag"
	FwAddRegValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" "DbFlag" "REG_DWORD" "$global:NetLogonFlag"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_NetlogonLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] .. Disabling Netlogon service debug log, copying $env:SystemRoot\debug"
	FwAddRegValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" "DbFlag" "REG_DWORD" "0x0"
	$Commands = @(
			"xcopy /i/q/y $env:SystemRoot\debug\netlogon*.* $global:LogFolder\WinDir-debug"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function ADS_OCSPPreStart {
	#  https://supportability.visualstudio.com/WindowsDirectoryServices/_wiki/wikis/WindowsDirectoryServices/414016/Workflow-PKI-Server-Online-Responder-(OCSP)
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "Set Debug Flags, running IISreset, restarting OCSP service to activate OCSP service debug logging"
	$Commands = @("$Sys32\certutil.exe -setreg -f Debug 0xffffffe3")
	If(FwIsOsCommandAvailable IISreset.exe){ $Commands += @("$Sys32\IISreset.exe")}
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	if (Get-Service -Name "OCSPsvc" -ErrorAction Ignore) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] restarting Service 'OCSPsvc'"
		Restart-Service -Name "OCSPsvc" -Force
	} else { LogWarn "[$($MyInvocation.MyCommand.Name)] Service 'OCSPsvc' not found"}
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] * OCSP reference: https://technet.microsoft.com/en-us/library/cc770413(v=WS.10).aspx"
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] * IIS Failed Request Tracing: https://www.iis.net/learn/troubleshoot/using-failed-request-tracing/troubleshooting-failed-requests-using-tracing-in-iis-85"
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] * Online Responder http://technet.microsoft.com/en-us/library/cc732526.aspx"
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_OCSPLog{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "Set Debug Flags, running IISreset, restarting OCSP service to activate OCSP service debug logging"
	$Commands = @("$Sys32\certutil.exe -setreg -f Debug 0xffffffe3")
	If(FwIsOsCommandAvailable IISreset.exe){ $Commands += @("$Sys32\IISreset.exe")}
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False	
	if (Get-Service -Name "OCSPsvc" -ErrorAction Ignore) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] restarting Service 'OCSPsvc'"
		Restart-Service -Name "OCSPsvc" -Force
	} else { LogWarn "[$($MyInvocation.MyCommand.Name)] Service 'OCSPsvc' not found"}
	FwAddRegItem @("OCSP") _Stop_
	if (Test-Path $env:SystemRoot\ServiceProfiles\networkservice\OCSPsvc.log) {
		FwCreateFolder $global:LogFolder\OCSP_serviceprofiles
		$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
		$SourceDestinationPaths = @(
			@("$env:SystemRoot\ServiceProfiles\networkservice\OCSPsvc.log", "$global:LogFolder\OCSP_serviceprofiles\")
		)
		FwCopyFiles $SourceDestinationPaths -ShowMessage:$False
	}
	if (Test-Path $PrefixTime`OCSP.etl) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] .. Converting OCSP.etl using command: netsh trace convert input=OCSP.etl"
		$Commands = @(
			"netsh trace convert input=$PrefixTime`OCSP.etl | Out-File -append -FilePath $global:ErrorLogFile"
			)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectADS_PerfLog{
	# invokes external script until fully integrated into TSSv2
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] . calling tss_ADPerfDataCollection.ps1"
	.\scripts\tss_ADPerfDataCollection.ps1 -DataPath $global:LogFolder -AcceptEula
	LogInfo "[$($MyInvocation.MyCommand.Name)] . Done tss_ADPerfDataCollection.ps1"
	EndFunc $MyInvocation.MyCommand.Name
}

function ADS_ProfilePreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	FwSetEventLog $EvtLogsProfSvcAnalytic
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_ProfileLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwAddRegItem @("Print") _Stop_ 
	($EvtLogsGPO, $EvtLogsProfSvc, $EvtLogsProfSvcAnalytic) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	FwResetEventLog $EvtLogsProfSvcAnalytic
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectADS_SBSLScenarioLog {
	CollectNET_SBSLScenarioLog
}

function ADS_SSLPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfoFile " *** [Hint] https://osgwiki.com/wiki/Collect_Schannel_Logs" "Cyan"
	#if (-Not(Test-Path $global:LogFolder\SavedEventLog\Microsoft-Windows-CAPI2-Operational.evtx)) {
		FwSetEventLog "Microsoft-Windows-CAPI2/Operational" -EvtxLogSize $global:EvtxLogSize -ClearLog
	#}
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_SSLLog {
	EnterFunc $MyInvocation.MyCommand.Name
	FwResetEventLog @("Microsoft-Windows-CAPI2/Operational")
	("Microsoft-Windows-CAPI2/Operational") | ForEach-Object { FwAddEvtLog $_ _Stop_}
	$Commands = @(
		"wevtutil epl /q:""*[System[Provider[@Name='Schannel' or @Name='Microsoft-Windows-Schannel-Events']]]"" System $PrefixTime`evt_schannel.evtx"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	FwAddRegItem @("TLS","WinHTTP") _Stop_
	FwAddRegItem @("DotNETFramework") _Stop_ -noRecursive
	LogInfoFile " *** [Hint] SSLyze - see internal KB: PKI: TOOLS: 3rd party Schannel SSL/TLS troubleshooting tools"
	LogInfoFile " *** [Hint] SSL Test: check TLS 1.2 Version here: https://www.ssllabs.com/ssltest/viewMyClient.html" "Cyan"
	$TestConnTLS = FwTestConnWebSite $global:TLStestSite
	if (!$TestConnTLS) {LogInfo "Unable to connect to the remote server - 'https://www.ssllabs.com'" "Magenta"}
	if ($TestConnTLS -and (!(Get-Service -Name "IAS" -ErrorAction Ignore))) { #ToDo: verify - failed on NPS server
		try {
			LogInfo "[$($MyInvocation.MyCommand.Name)] ... running 'https' PS command for System.Net.WebClient 'https://www.ssllabs.com/ssltest/viewMyClient.html' "
			(New-Object System.Net.WebClient -ErrorAction SilentlyContinue).DownloadString('https://www.ssllabs.com/ssltest/viewMyClient.html') | Out-File $PrefixCn`TestConn_TLS.html
		} catch { LogInfo "Unable to connect to the remote server - 'https://www.ssllabs.com'" "Magenta"}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectADS_UserInfoLog {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] running 'GPresult,whoami,klist' for user $env:username at $TssPhase"
	$Commands = @(
		"GPresult.exe /h $PrefixTime`GPresult-H_$env:username`$TssPhase.htm /f"
		"GPresult.exe /z $PrefixTime`GPresult-Z_$env:username`$TssPhase.txt /f"
		"GPresult.exe /v | Out-File $PrefixTime`GPresult-V_$env:username`$TssPhase.txt"
		"whoami.exe /UPN | Out-File $PrefixTime`WhoAmI_UPN_$env:username`$TssPhase.txt"
		"klist.exe cloud_debug | Out-File $PrefixTime`klist_cloud_$env:username`$TssPhase.txt"
		"$Sys32\certutil.exe -v -user -store my | Out-File $PrefixTime`mystore_$env:username`$TssPhase.txt"
		"REG.exe export HKCU $PrefixTime`RegHive_HKCU_$env:username`.hiv /Y"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	FwGetWhoAmI
	FwGetDSregCmd
	FwGetKlist
	EndFunc $MyInvocation.MyCommand.Name
}

function ADS_W32TimePreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	$w32tm_FileLogName = (get-itemproperty HKLM:\SYSTEM\CurrentControlSet\services\W32Time\Config\).FileLogName
	# If $w32tm_FileLogName is null (because FileLogName is not set) then throw an error.
	If ($null -eq $w32tm_FileLogName)	{
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] W32Tm FileLogName registry value is not set. Any previous W32Time debug logging is not enabled."
		} 
	# If $w32tm_FileLogName is populated, check if the path exists and if so, copy the file to TSS directory, prepending the computer name.
	Else {
		LogInfoFile "[$($MyInvocation.MyCommand.Name)] previous W32Tm FileLogName = $w32tm_FileLogName" 
		$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
		$SourceDestinationPaths.add(@("$w32tm_FileLogName", "$PrefixTime`W32Time_debug_till-Start.log"))
		FwCopyFiles $SourceDestinationPaths
	}
	LogInfo "[$($MyInvocation.MyCommand.Name)] .. Enabling W32Time service debug logging"
	$Commands = @(
		"w32tm.exe /debug /enable /file:$($PrefixTime)w32tm_debug.txt /size:100000000 /entries:0-300"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False 
	EndFunc $MyInvocation.MyCommand.Name
}
function CollectADS_W32TimeLog {
	EnterFunc $MyInvocation.MyCommand.Name
	# w32tm /query /status for local machine, PDC, and authenticating DC.
	$OutputFile = "$($PrefixTime)W32Time_Query_Status.TXT"

	$Domain = [adsi]("LDAP://RootDSE")
	$AUTHDC_DNSHOSTNAME = $Domain.dnshostname
	$DomainDN = $Domain.defaultNamingContext
	if ($DomainDN) {
		$PDC_NTDS_DN = ([adsi]("LDAP://"+ $DomainDN)).fsmoroleowner
		$PDC_NTDS = [adsi]("LDAP://"+ $PDC_NTDS_DN)
		$PDC = $PDC_NTDS.psbase.get_parent() #_# -ErrorAction SilentlyContinue
	} else { LogInfoFile "[$($MyInvocation.MyCommand.Name)] could not resolve DomainDN ($DomainDN) via LDAP://RootDSE" }
	if ($null -ne $PDC) { $PDC_DNSHOSTNAME = $PDC.dnshostname }

	"[INFO] The following errors are expected to occur under the following conditions: " | Out-File -append -FilePath $OutputFile 
	"   -  'Access is Denied' is expected if TSS was run with an account that does not have local administrative rights on the target machine. " | Out-File -append -FilePath $OutputFile 
	"   -  'The RPC server is unavailable' is expected if Windows Firewall is enabled on the target machine, or the target machine is otherwise unreachable. `n `n " | Out-File -append -FilePath $OutputFile 
	"Output of 'w32tm /query /status /verbose'" | Out-File -append -FilePath $OutputFile 
	"========================================= " | Out-File -append -FilePath $OutputFile 
	cmd /d /c w32tm.exe /query /status /verbose | Out-File -append -FilePath $OutputFile 

	if ($global:ParameterArray -notcontains 'noHang') {  #_# below command might appear hung on some systems
		If ($null -ne $PDC_DNSHOSTNAME) { 
			"`n[INFO] The PDC Emulator for this computer's domain is $PDC_DNSHOSTNAME `n" | Out-File -append -FilePath $OutputFile 
			"Output of 'w32tm /query /computer:$PDC_DNSHOSTNAME /status /verbose'" | Out-File -append -FilePath $OutputFile 
			"=========================================================================== " | Out-File -append -FilePath $OutputFile 
			cmd /d /c w32tm.exe /query /computer:$PDC_DNSHOSTNAME /status /verbose | Out-File -append -FilePath $OutputFile 
		}Else{
			"[Error] Unable to determine the PDC Emulator for the domain." | Out-File -append -FilePath $OutputFile 
		}
		If ($null -ne $AUTHDC_DNSHOSTNAME) {
			"`n[INFO] This computer's authenticating domain controller is $AUTHDC_DNSHOSTNAME `n" | Out-File -append -FilePath $OutputFile 
			"Output of 'w32tm /query /computer:$AUTHDC_DNSHOSTNAME /status /verbose'" | Out-File -append -FilePath $OutputFile 
			"=========================================================================== " | Out-File -append -FilePath $OutputFile 
			cmd /d /c w32tm.exe /query /computer:$AUTHDC_DNSHOSTNAME /status /verbose | Out-File -append -FilePath $OutputFile 
		}Else{
			"[Error] Unable to determine this computer's authenticating domain controller." | Out-File -append -FilePath $OutputFile 
		}
		$outStripchart = "$($PrefixTime)W32Time_Stripchart.TXT"
		If ($null -ne $PDC_DNSHOSTNAME) {
			"[INFO] The PDC Emulator for this computer's domain is $PDC_DNSHOSTNAME `n" | Out-File -append $outStripchart
			"Output of 'w32tm /stripchart /computer:$PDC_DNSHOSTNAME /samples:5 /dataonly'" | Out-File -append $outStripchart
			"===================================================================================== " | Out-File -append -FilePath $outStripchart 
			cmd /d /c w32tm.exe /stripchart /computer:$PDC_DNSHOSTNAME /samples:5 /dataonly | Out-File -append $outStripchart
		}Else{
			"[Error] Unable to determine the PDC Emulator for the domain." | Out-File -append $outStripchart
		}
		If ($null -ne $AUTHDC_DNSHOSTNAME) {
			"`n`n[INFO] This computer's authenticating domain controller is $AUTHDC_DNSHOSTNAME `n" | Out-File -append $outStripchart
			"Output of 'w32tm /stripchart /computer:$AUTHDC_DNSHOSTNAME /samples:5 /dataonly'" | Out-File -append $outStripchart
			"===================================================================================== " | Out-File -append -FilePath $outStripchart 
			cmd /d /c w32tm.exe /stripchart /computer:$AUTHDC_DNSHOSTNAME /samples:5 /dataonly | Out-File -append $outStripchart
		}Else{
			"[Error] Unable to determine this computer's authenticating domain controller." | Out-File -append $outStripchart
		}
	}
	
	LogInfo "[$($MyInvocation.MyCommand.Name)] .. Disabling W32Time service debug logging"
	$Commands = @(
		"w32tm.exe /query /status /verbose	| Out-File -Append $PrefixTime`W32Time_query_status_verbose.txt"
		"w32tm.exe /query /configuration	| Out-File -Append $PrefixTime`W32Time_query_configuration.txt"
		"w32tm.exe /query /peers			| Out-File -Append $PrefixTime`W32Time_query_peers.txt"
		"w32tm.exe /query /peers /verbose	| Out-File -Append $PrefixTime`W32Time_query_peers.txt"
		"sc.exe query w32time				| Out-File -Append $PrefixTime`W32Time_Service_Status.txt"
		"sc.exe sdshow w32time				| Out-File -Append $PrefixTime`W32Time_Service_Perms.txt"
		"w32tm.exe /monitor					| Out-File -Append $PrefixTime`W32Time_Monitor.txt"
		"w32tm.exe /testif /qps				| Out-File -Append $PrefixTime`W32Time_TestIf_QPS.txt"
		"w32tm.exe /tz						| Out-File -Append $PrefixTime`W32Time_TimeZone.txt"
		"REG QUERY `"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time`" /s | Out-File -Append $PrefixTime`W32Time_Reg_Key.txt"
		"Get-Acl HKLM:\SYSTEM\CurrentControlSet\services\W32Time | Format-List | Out-File  -Append $PrefixTime`W32Time_Reg_Key_Perms.txt"
		"w32tm.exe /debug /disable"
		)
	RunCommands $LogPrefix $Commands -ThrowException:$False ## -ShowMessage:$False 
	#Get-Acl HKLM:\SYSTEM\CurrentControlSet\services\W32Time | Format-List | Out-File  -Append $PrefixTime`W32Time_Reg_Key_Perms.txt
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectADS_WinLAPSLog {
	EnterFunc $MyInvocation.MyCommand.Name
	($EvtLogsLAPS) | ForEach-Object { FwAddEvtLog $_ _Stop_}
	FwAddRegItem @("WinLAPS") _Stop_
	$binaries = @("Lapspsh.dll", "LapsUtil.dll")
	foreach($file in $binaries){
		FwFileVersion -Filepath ("$Env:windir\System32\WindowsPowerShell\v1.0\Modules\LAPS\$file") | Out-File -FilePath "$($_prefix)FilesVersion_PowerShell_Laps.txt" -Append
	}
	$binaries = @("Laps.dll", "Lapscsp.dll", "Samsrv.dll")
	foreach($file in $binaries){
		FwFileVersion -Filepath ("$Env:windir\System32\$file") | Out-File -FilePath "$($_prefix)FilesVersion_WinSys32_Laps.txt" -Append
	}
	FwCreateFolder $global:LogFolder\Files_LAPS
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(
		@("$Env:windir\System32\WindowsPowerShell\v1.0\Modules\LAPS\Laps*.dll", "$global:LogFolder\Files_LAPS"),
		@("$Env:windir\System32\Laps*.dll", "$global:LogFolder\Files_LAPS"),
		@("$Env:windir\System32\Samsrv.dll", "$global:LogFolder\Files_LAPS")
	)
	FwCopyFiles $SourceDestinationPaths
	FwGetGPresultAS _Stop_
	EndFunc $MyInvocation.MyCommand.Name
}

#region ADS_EESummitDemo
function ADS_EESummitDemoPreStart {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] .. Enabling Netlogon service debug log"
	FwAddRegValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" "DbFlag" "REG_DWORD" "$global:NetLogonFlag"
	EndFunc $MyInvocation.MyCommand.Name
}

function ADS_EESummitDemoPostStop {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] .. Disabling Netlogon service debug log"
	FwAddRegValue "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" "DbFlag" "REG_DWORD" "0x0"
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectADS_EESummitDemoLog {
EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] Collecting ADS_EESummitDemo logs started."
	# init variables
	$ComputerSystem = Get-WmiObject -Namespace "root\CIMv2" -Class Win32_ComputerSystem
	if (!([string]::IsNullOrEmpty($ComputerSystem))) {
		#$ComputerDomain = $ComputerSystem.Domain
		$DomainRole = $ComputerSystem.DomainRole
	} else {
		#$ComputerDomain = "WORKGROUP"
		$DomainRole = 0
	}
	$RootDSE = [ADSI]"LDAP://RootDSE"
	$DefaultNamingContext = $RootDSE.defaultNamingContext
	if ($Null -ne $DefaultNamingContext) {
		$ConfigurationNamingContext = $RootDSE.configurationNamingContext
		$DCAccessible = $True
	} else {
		$DCAccessible = $False
	}

	#setting commands to execute
	if (($DomainRole -eq 1) -Or ($DomainRole -eq 3) -Or ($DomainRole -eq 4) -Or ($DomainRole -eq 5)) { # Member Workstation, Member Server, BDC, or PDC
		if ($DCAccessible -eq $True) {
			$Commands = @(
				"nltest /dclist: | Out-File -Append $($PrefixTime)nltest_dclist.txt"
				"nltest /dsgetsite | Out-File -Append $($PrefixTime)nltest_dsgetsite.txt"
				"nltest /domain_trusts /all_trusts /v | Out-File -Append $($PrefixTime)nltest_domain_trusts_all_trusts_v.txt"
				"nltest /trusted_domains | Out-File -Append $($PrefixTime)nltest_trusted_domains.txt"
				"w32tm /query /status /verbose | Out-File -Append $($PrefixTime)w32tm_query_status.txt"
				"w32tm /query /configuration | Out-File -Append $($PrefixTime)w32tm_query_config.txt"
				"w32tm /query /peers /verbose | Out-File -Append $($PrefixTime)w32tm_query_peers.txt"
			)
		} else {
			#do nothing
		}
	}
	# executing commands:
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False

	# FW conveniance function for GPO relevant data
	FwGetGPresultAS 

	# files to copy: source , destination
	$SourceDestinationPaths = @(
		@("$Env:SYSTEMROOT\debug\dcpromo.log", "$($PrefixTime)dcpromo.log"),
		@("$Env:SYSTEMROOT\debug\dcpromoui.log", "$($PrefixTime)dcpromoui.log"),
		@("$Env:SYSTEMROOT\debug\netlogon.log", "$($PrefixTime)netlogon.log"),
		@("$Env:SYSTEMROOT\debug\netsetup.log", "$($PrefixTime)netsetup.log")
	)
	# copying files
	FwCopyFiles $SourceDestinationPaths

	# export registry
	$global:KeysEESummitDemo = @(
		"HKLM:System\CurrentControlSet\Services\W32Time"
		"HKLM:Software\Policies\Microsoft\W32Time"
		"HKLM:System\CurrentControlSet\Services\Netlogon\Parameters"
		"HKLM:Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}"
	)
	FwAddRegItem @("EESummitDemo") _Stop_

	#export event logs
	$EvtEESummitDemo = @("Application", "System", "Directory Service")
	($EvtEESummitDemo) | ForEach-Object { FwAddEvtLog $_ _Stop_}

	LogInfo "[$($MyInvocation.MyCommand.Name)] Collecting ADS_EESummit logs ended."
	EndFunc $MyInvocation.MyCommand.Name
}

function CollectADS_EESummitDemoScenarioLog{
	LogInfo "[$($MyInvocation.MyCommand.Name)] Collecting ADS_EESummitDemoScenario logs started."
	CollectADS_EESummitDemoLog
}
#endregion ADS_EESummitDemo

#endregion ### Pre-Start / Post-Stop / Collect functions for trace components and scenarios 

#region Registry Key modules for FwAddRegItem
 # A) section of recursive lists
	$global:KeysGPsvc = @("HKLM:Software\Policies\Microsoft")
	$global:KeysPrint = @("HKLM:Software\Microsoft\Windows NT\CurrentVersion\Ports", "HKLM:Software\Policies\Microsoft\Windows NT\Printers", "HKLM:System\CurrentControlSet\Control\Print\Printers")
	$global:KeysKIRMyKnobs = @("HKLM:Software\Microsoft\Windows\CurrentVersion\QualityCompat", "HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management", "HKLM:System\CurrentControlSet\Policies")
	$global:KeysOCSP = @("HKLM:System\CurrentControlSet\Services\OcspSvc")
	$global:KeysTLS = @(
		"HKLM:System\CurrentControlSet\Control\SecurityProviders\Schannel"
		"HKLM:System\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
		"HKLM:System\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010003"
		"HKLM:System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
		"HKLM:Software\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
	)
	$global:KeysWinHTTP = @(
		"HKLM:Software\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
		"HKLM:Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
	)
	$global:KeysWinLAPS = @(
		"HKLM:Software\Microsoft\Policies\LAPS"
		"HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\LAPS"
		"HKLM:Software\Policies\Microsoft Services\AdmPwd"
		"HKLM:Software\Microsoft\Windows\CurrentVersion\LAPS\Config"
		"HKLM:Software\Microsoft\Windows\CurrentVersion\LAPS\State"
		"HKLM:Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}"
	)
 # B) section of NON-recursive lists
 	$global:KeysDotNETFramework = @(
		"HKLM:Software\Microsoft\.NETFramework\v2.0.50727"
		"HKLM:Software\Wow6432Node\Microsoft\.NETFramework\v2.0.50727"
		"HKLM:Software\Microsoft\.NETFramework\v4.0.30319"
		"HKLM:Software\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
	)

#endregion Registry Key modules

#region groups of Eventlogs for FwAddEvtLog
	$EvtLogsGPO		= @("Microsoft-Windows-GroupPolicy/Operational")
	$EvtLogsLDAPsrv	= @("Directory Service")
	$EvtLogsProfSvc	= @("Microsoft-Windows-User Profile Service/Operational")
	$EvtLogsProfSvcAnalytic = @("Microsoft-Windows-User Profile Service/Diagnostic")
	$EvtLogsLAPS	= @("Microsoft-Windows-LAPS/Operational")

#endregion groups of Eventlogs

Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *


# SIG # Begin signature block
# MIInvwYJKoZIhvcNAQcCoIInsDCCJ6wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD866PCw0DuTACb
# tUH6KBFbBCTIPcpBhYsk8dPe+IwAbaCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBhX2axJARA0cLvHnw+u7AIc
# Y/tfZ1KYTJudfW4do8TeMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEABatPXOWiA2I1NPDYGVFu3Z4zA9WX4jFpv1nbUDhpvGZlUHje9lbIEg/3
# jAsAGHEWcuRRKvE126TvwFywKwOW2WZzvHzlbtHI+bhdWPtH9B8W4lT6kCQ9/8tb
# 2yxSsXp6iYG/CZ528sn5vu4p/IE2012IECNWCgnvVQIq0Z4WNecJNqZPPQy9QFHg
# Zdngds4aXoR0DzrEMiPL0CirA6U5Y3RyamLasOSv/pSzKTLWDWrjSPrNWanAdl8k
# PN43Ci0t3yrz7dzIbUQX7E+jYWKwuFs1tyQFAGGzDRhNGOsCEmI79+AK4OGZygVD
# htNOkuNVbvOpB2J3yPP9KHYZe/bnRaGCFykwghclBgorBgEEAYI3AwMBMYIXFTCC
# FxEGCSqGSIb3DQEHAqCCFwIwghb+AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsq
# hkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCBB5Ks0jR5IBjDAZrNdL3Y7G5Zancgz+KI8mISQJXE8TwIGZGzyr5fP
# GBMyMDIzMDYwNjExNDQxOC4zMjRaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJV
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
# IgQgR6CpaAjuENOXCVp4OgB7cd4Da5Pf6vuh4b3kF1FZvI0wgfoGCyqGSIb3DQEJ
# EAIvMYHqMIHnMIHkMIG9BCBk60bO8W85uTAfJVEO3vX2aLaQFcgcGpdwsOoi+foP
# 9DCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABufYA
# DWVUT7wDAAEAAAG5MCIEIIiUQFOD/DfPKzh2HUCNc6L4hy56TKlgS0d/vmUR/IOe
# MA0GCSqGSIb3DQEBCwUABIICAG/Ce6UOkHmE9A9a3yJpyytfoQG7jkOy7XK4ps1L
# MQSG6qDD1TYfVu5D9Ol5I7EfkSQI0MiAyA8JRJNTq51V5x8ZXI30bllKyA8tzlnm
# teSx547OswzLH3DKuxr4d0kM+gP89ffMvjVLx5jmgK1TcYTMh7r+39FymFZ4cQs7
# 6/4IKBaYGfQrG1C0j+qc7RS42GXkW6SungUlf51fk1G+lNolZPsqYZLBP6Pdhl+s
# zp1qVIrwBDt74wGJdwAle8yZMWfVNz75XVnEyXRZw79l4dB3e5D6mnCmsqe2P0C/
# HCaGdWKxEfLZ0bQ9LNdvyCVaux+21udGZU4eFEtwXJQmfLBHM/Sad7YLRBFUdXqG
# ps0BDszze5aa1BJSWBVhlM4IiRlSC7Oar+H302EzTczyF9qIdVFRaMJ5iGYyh0q7
# zqjkuh0oEh2IOF9AGVy+pSjmXFn2ZZPxjvjcQkEm96rVqtZMimdrQJ0HiC0M5i5g
# c+2FggEiVjGa8RFNiG17WAferfatl5Jmx1uHTYkgp5HIfRFEt/mjBJ4DDjBLthcX
# vX9XlfW9U1o3QNwUmfFqC097e0c7ScI+kO1UA/iRYZQt5vlJ5oaeoGOYEgprGAWv
# uirbkdHFDh+XAAZUHMlIv51vLJKjXw+7z5idK3lM/F0bm7Ly4LeirInXhsdAeJ1C
# iaba
# SIG # End signature block
