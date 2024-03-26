<#
.SYNOPSIS
   PRF module for collecting ETW traces and various custom tracing functionality

.DESCRIPTION
   Define ETW traces for Windows PRF components 
   Add any custom tracing functinaliy for tracing PRF components
   For Developers:
   1. Switch test: .\TSSv2.ps1 -Start -PRF_TEST1
   2. Scenario test: .\TSSv2.ps1 -start -Scenario PRF_MyScenarioTest

.NOTES
   Dev. Lead  : ?
   Authors    : Takahiro Aizawa 
   Requires   : PowerShell V4 (Supported from Windows 8.1/Windows Server 2012 R2)
   Version    : see $global:TssVerDatePRF

.LINK
	TSSv2 https://internal.support.services.microsoft.com/en-us/help/4619187
	PRF https://internal.support.services.microsoft.com/en-us/help/5009898
#>

<# latest changes
  2023.05.19.3 [tfairman] Move SCM component from UEX and NET to PRF
  2023.04.18.0 [we] _PRF: add $global:EvtLogsIME, EvtLogsAppX; alphabetical sort; move NET_PerfLib to PRF_PerfLib
  2023.04.07.0 [rh] _PRF: merge previous UEX components to PERF
  2022.12.07.0 [we] _PRF: add -Scenario PRF_General
  2021.12.18.0 [rh] _FW: change variable name to $global:StartAutologger from $global:SetAutoLogger to refect the change happened in FW
  2021.11.10.0 [we] #_# replaced all 'Get-WmiObject' with 'Get-CimInstance' to be compatible with PowerShell v7
#>

$global:TssVerDatePRF= "2023.05.19.3"

#------------------------------------------------------------
#region --- ETW component trace Providers ---
#------------------------------------------------------------

$PRF_AlarmProviders = @(
	'{B333D303-D0C7-4D0B-A417-D331DA97E7D3}' # Microsoft.Windows.AlarmsAndClock
)

$PRF_AppxProviders = @(
	'{BA44067A-3C4B-459C-A8F6-18F0D3CF0870}' # AppXDeployment WPP tracing
	'{8127F6D4-59F9-4abf-8952-3E3A02073D5F}' # Microsoft-Windows-AppXDeployment
	'{3F471139-ACB7-4A01-B7A7-FF5DA4BA2D43}' # Microsoft-Windows-AppXDeployment-Server
	'{fe762fb1-341a-4dd4-b399-be1868b3d918}' # Microsoft.Windows.AppXDeploymentServer
	'{BA723D81-0D0C-4F1E-80C8-54740F508DDF}' # Microsoft-Windows-AppxPackagingOM
	'{f0be35f8-237b-4814-86b5-ade51192e503}' # Microsoft-Windows-AppReadiness
	'{C567E5D7-A908-49C0-8C2C-A8DC3E8F0CF6}' # Microsoft.Windows.ARS.Tiles
	'{594bf743-ce2e-48ee-83ee-3d50a0add692}' # Microsoft.Windows.AppModel.TileDataModel
	'{3d6120a6-0986-51c4-213a-e2975903051d}' # Microsoft-Windows-Shell-Launcher
	'{39ddcb8d-ef82-5c84-89ca-09580bf0a947}' # Microsoft-Windows-Shell-AppResolver
	'{F84AA759-31D3-59BF-2C89-3748CF17FD7E}' # Microsoft-Windows-Desktop-Shell-Windowing
	'{3C42000F-CC27-48C3-A005-48F6E38B131F}' # Microsoft-WindowsPhone-AppPlatProvider
	'{15322370-3694-59f5-f979-0c7a918b81da}' # Microsoft.Windows.Desktop.Shell.ViewManagerInterop
	'{D75DF9F1-5F3D-49D0-9D15-2A55BD1C012E}' # ViewManagerInterop
	'{EF00584A-2655-462C-BC24-E7DE630E7FBF}' # Microsoft.Windows.AppLifeCycle
	'{58E68FB9-538C-47FA-8CEC-BC112DC6264A}' # EventProvider_IAM
	'{5C6E364D-3A8F-41D4-B7BB-2B03432CB665}' # VIEWMGRLIB(WPP)
	'{9C6FC32A-E17A-11DF-B1C4-4EBADFD72085}' # PLM
	'{29CFB5C5-E518-4960-A985-E18E570F935B}' # ACTIVATIONLIB(WPP)
	'{cf7f94b3-08dc-5257-422f-497d7dc86ab3}' # ActivationManager
	'{F1EF270A-0D32-4352-BA52-DBAB41E1D859}' # Microsoft-Windows-AppModel-Runtime
	'{BFF15E13-81BF-45EE-8B16-7CFEAD00DA86}' # Microsoft-Windows-AppModel-State
	'{41B5F6E6-F53C-4645-A991-135C2011C074}' # Microsoft.Windows.AppModel.StateManagerTelemetry
	'{5B5AB841-7D2E-4A95-BB4F-095CDF66D8F0}' # Microsoft-Windows-Roaming
	'{EB65A492-86C0-406A-BACE-9912D595BD69}' # Microsoft-Windows-AppModel-Exec
	'{315a8872-923e-4ea2-9889-33cd4754bf64}' # Microsoft-Windows-Immersive-Shell
	'{5F0E257F-C224-43E5-9555-2ADCB8540A58}' # Microsoft-Windows-Immersive-Shell-API
	'{8360D517-2805-4654-AA04-E9985B4433B4}' # Microsoft-Windows-AppModel-CoreApplication
	'{35D4A1FA-4036-40DC-A907-E330F3104E24}' # Microsoft-Windows-Desktop-ApplicationManager
	'{076A5FE9-E0F4-43DC-B246-9EA382B5C69F}' # Microsoft.Windows.Desktop.Shell.ViewManagement
	'{8BFE6B98-510E-478D-B868-142CD4DEDC1A}' # Windows.Internal.Shell.ModalExperience
	'{fa386406-8e25-47f7-a03f-413635a55dc0}' # TwinUITraceLoggingProvider
	'{c17f56cb-764e-5d2d-3b4e-0711ad368aaf}' # Microsoft.Windows.Shell.ApplicationHost
	'{4fc2cbef-b755-5b53-94db-8d816ca8c9cd}' # Microsoft.Windows.Shell.WindowMessageService
	'{072665fb-8953-5a85-931d-d06aeab3d109}' # Microsoft.Windows.ProcessLifetimeManager
	'{678e492b-5de1-50c5-7219-ae4aa7d6a141}' # Microsoft-Windows-Desktop-ApplicationFrame
	'{f6a774e5-2fc7-5151-6220-e514f1f387b6}' # Microsoft.Windows.HostActivityManager
	'{D2440861-BF3E-4F20-9FDC-E94E88DBE1F6}' # BiCommonTracingGuid(WPP)
	'{e6835967-e0d2-41fb-bcec-58387404e25a}' # Microsoft-Windows-BrokerInfrastructure
	'{63b6c2d2-0440-44de-a674-aa51a251b123}' # Microsoft.Windows.BrokerInfrastructure
	'{1941f2b9-0939-5d15-d529-cd333c8fed83}' # Microsoft.Windows.BackgroundManager
	'{d82215e3-bddf-54fa-895b-685099453b1c}' # Microsoft.Windows.BackgroundActivityModerator
	'{4a743cbb-3286-435c-a674-b428328940e4}' # PsmTrace(WPP)
	'{d49918cf-9489-4bf1-9d7b-014d864cf71f}' # Microsoft-Windows-PSM-Legacy(ProcessStateManager)
	'{0001376b-930d-50cd-2b29-491ca938cd54}' # Microsoft-Windows-PSM
	'{4180c4f7-e238-5519-338f-ec214f0b49aa}' # Microsoft-Windows-ResourceManager
	'{e8109b99-3a2c-4961-aa83-d1a7a148ada8}' # BrokerCommon(WPP)
	'{369f0950-bf83-53a7-b3f0-771a8926329d}' # Microsoft-Windows-Shell-ServiceHostBuilder
	'{3B3877A1-AE3B-54F1-0101-1E2424F6FCBB}' # SIHost
	'{770CA594-B467-4811-B355-28F5E5706987}' # Microsoft-Windows-ApplicationResourceManagementSystem
	'{a0b7550f-4e9a-4f03-ad41-b8042d06a2f7}' # Microsoft-Windows-CoreUIComponents
	'{89592015-D996-4636-8F61-066B5D4DD739}' # Microsoft.Windows.StateRepository
	'{1ded4f74-5def-425d-ae55-4fd4e9bbe0a7}' # Microsoft.Windows.StateRepository.Common
	'{a89336e8-e6cf-485c-9c6a-ddb6614f278a}' # Microsoft.Windows.StateRepository.Client
	'{312326fa-036d-4888-bc77-c3de2ff9ae06}' # Microsoft.Windows.StateRepository.Broker
	'{551ff9b3-0b7e-4408-b008-0068c8da2ff1}' # Microsoft.Windows.StateRepository.Service
	'{7237c668-b9a2-4fbd-9987-87d4502b9e00}' # Microsoft.Windows.StateRepository.Tools
	'{80a49605-87cb-4480-be97-d6ccb3dde5f2}' # Microsoft.Windows.StateRepository.Upgrade
	'{bf4c9654-66d1-5720-7b51-d2ae226735ea}' # Microsoft.Windows.ErrorHandling.Fallback
	'{CC79CF77-70D9-4082-9B52-23F3A3E92FE4}' # Microsoft.Windows.WindowsErrorReporting
	'{1AFF6089-E863-4D36-BDFD-3581F07440BE}' # CombaseTraceLoggingProvider
	'{f0558438-f56a-5987-47da-040ca757ef05}' # Microsoft.Windows.WinRtClassActivation
	'{5526aed1-f6e5-5896-cbf0-27d9f59b6be7}' # Microsoft.Windows.ApplicationModel.DesktopAppx
	'{fe0ab4b4-19b6-485b-89bb-60fd931fdd56}' # Microsoft.Windows.AppxPackaging
	'{19c13211-dec8-42d5-885a-c4cfa82ea1ed}' # Microsoft.Windows.Mrt.Runtime
	'{932a397d-97ed-50f9-29ab-051457f7af3e}' # Microsoft.Windows.Desktop.LanguageBCP47
	'{aa1b41d3-d193-4660-9b47-dd701ba55841}' # Microsoft-Windows-AppXDeploymentFallback
	'{BB86E31D-F955-40F3-9E68-AD0B49E73C27}' # Microsoft-Windows-User-UserManager-Events
	'{8CCCA27D-F1D8-4DDA-B5DD-339AEE937731}' # Microsoft.Windows.Compatibility.Apphelp
	'{b89fa39d-0d71-41c6-ba55-effb40eb2098}' # Microsoft.Windows.AppXDeploymentClient
	'{d9e5f8fb-06b1-4796-8fa8-abb07f4fc662}' # Microsoft.Windows.AppXDeploymentExtensions
	'{2f29dca8-fbb3-4944-8953-2d390f0fe746}' # DEPLOYMENT_WPP_GUID
	'{4dab1c21-6842-4376-b7aa-6629aa5e0d2c}' # Microsoft.Windows.AppXAllUserStore
	'{AF9FB9DF-E373-4653-84CE-01D8857E79FD}' # Microsoft.Windows.AppxMigrationPlugin
	'{8FD4B82B-602F-4470-8577-CBB56F702EBF}' # Microsoft.Windows.AppXDeploymentClient.WPP
	'{c94526b9-c642-489c-adfc-224530dda439}' # APPREADINESS_WPP_TRACE_GUID
)

$PRF_CalcProviders = @(
	'{0905CA09-610E-401E-B650-2F212980B9E0}' # MicrosoftCalculator
)

$PRF_CameraProviders = @(
	'{e647b5bf-99a4-41fe-8789-56c6bb3fa9c8}' # Microsoft.Windows.Apps.Camera
	'{f4296e10-4a0a-506c-7899-eb93382208e6}' # Microsoft.Windows.Apps.Camera
	'{EF00584A-2655-462C-BC24-E7DE630E7FBF}' # Microsoft.Windows.AppLifeCycle
	'{4f50731a-89cf-4782-b3e0-dce8c90476ba}' # TraceLoggingOptionMicrosoftTelemetry
	'{c7de053a-0c2e-4a44-91a2-5222ec2ecdf1}' # TraceLoggingOptionWindowsCoreTelemetry
	'{B8197C10-845F-40ca-82AB-9341E98CFC2B}' # Microsoft-Windows-MediaFoundation-MFCaptureEngine
	'{B20E65AC-C905-4014-8F78-1B6A508142EB}' # Microsoft-Windows-MediaFoundation-Performance-Core
	'{548C4417-CE45-41FF-99DD-528F01CE0FE1}' # Microsoft-Windows-Ks(Kernel Streaming)
	'{8F0DB3A8-299B-4D64-A4ED-907B409D4584}' # Microsoft-Windows-Runtime-Media
	'{A4112D1A-6DFA-476E-BB75-E350D24934E1}' # Microsoft-Windows-MediaFoundation-MSVProc
	'{AE5C851E-B4B0-4F47-9D6A-2B2F02E39A5A}' # Microsoft.Windows.Sensors.SensorService
	'{A676B545-4CFB-4306-A067-502D9A0F2220}' # PlugPlayControlGuid
)

$PRF_ClipboardProviders = @(
	'{f917a1ee-0a04-5157-9a8b-9ba716e318cb}' # Microsoft.Windows.ClipboardHistory.UI
	'{e0be2aaa-b6c3-5f17-4e86-1cde27b51ac1}' # Microsoft.Windows.ClipboardHistory.Service
	'{28d62fb0-2131-41d6-84e8-e2325867964c}' # Microsoft.Windows.AppModel.Clipboard
	'{3e0e3a92-b00b-4456-9dee-f40aba77f00e}' # Microsoft.Windows.OLE.Clipboard
	'{A29339AD-B137-486C-A8F3-88C9738E5379}' # Microsoft.Windows.ApplicationModel.DataTransfer.CloudClipboard
	'{ABB10A7F-67B4-480C-8834-8B049C428715}' # Microsoft.Windows.CDP.Core
	'{796F204A-44FC-47DF-8AE4-77C210BD5AF4}' # RdpClip
)

$PRF_CortanaProviders = @(
	'{E34441D9-5BCF-4958-B787-3BF824F362D7}' # Microsoft.Windows.Shell.CortanaSearch
	'{0FE37773-6C29-5233-0DD0-50E974F24203}' # Microsoft-Windows-Shell-CortanaDss
	'{2AF7F6B8-E17E-52A1-F715-FA43D637798A}' # Microsoft-Windows-Shell-CortanaHistoryUploader
	'{66f03b1f-1aec-5184-d349-a81761122be4}' # Microsoft.Windows.Shell.CortanaHome
	'{c0d0fe1d-53e4-5b98-71d7-c51fe5c10003}' # Microsoft-Windows-Shell-CortanaNL
	'{b9ca7b47-8bad-5693-9481-028527614d30}' # Microsoft.Windows.Shell.CortanaNotebook
	'{8E6931A7-4C49-5FB7-A500-65B951D7652F}' # Microsoft.Windows.Shell.CortanaPersonality
	'{5B7144A2-F0F6-4F99-A66D-FB2477E4CEE6}' # Microsoft.Windows.Shell.CortanaPlaces
	'{0E6F34B3-0637-55AB-F0BB-8B8FA83EDA04}' # Microsoft-Windows-Shell-CortanaProactive
	'{94041064-dbc2-4668-a729-b7b82747a0c2}' # Microsoft.Windows.Shell.CortanaReminders
	'{9B3FE00F-DAC4-4437-A77B-DE27B87046D4}' # Microsoft.Windows.Shell.CortanaSearch
	'{d8caafb9-7211-5dc8-7c1f-8027d50640ec}' # Microsoft.Windows.Shell.CortanaSignals
	'{a1f18f1f-bf5c-54d1-214d-8e1d3fe8427f}' # Microsoft-Windows-Shell-CortanaValidation
	'{2AEDC292-3FA5-472A-8EB4-33978D449853}' # Microsoft.Windows.Shell.CortanaSync
	'{92F43F71-2741-40B2-A566-70EEBCF2D181}' # Microsoft-Windows-Shell-CortanaValidation
	'{1aea69ee-2cfc-5eb1-f1f6-18f99a528b11}' # Microsoft-Windows-Shell-Cortana-IntentExtraction
	'{88BCD62D-F7AE-45B7-B578-4BF2B8AB867B}' # Microsoft-Windows-Shell-CortanaTrace
	'{ff32ada1-5a4b-583c-889e-a3c027b201f5}' # Microsoft.Web.Platform
	'{FC7BA620-EB50-483D-97A0-72D8268A14B5}' # Microsoft.Web.Platform.Chakra
	'{F65B3890-19BA-486E-A5F6-0378B356E0CE}' # Microsoft.Windows.UserSpeechPreferences
	'{adbb52ad-4e74-56c1-ecbe-cc4539ac4b2d}' # Microsoft.Windows.SpeechPlatform.Settings
	# '{57277741-3638-4A4B-BDBA-0AC6E45DA56C}' # Microsoft-JScript(chakra.dll)  // Too many logs will be recorded.
)

$PRF_DMProviders = @(
	'{9bfa0c89-0339-4bd1-b631-e8cd1d909c41}' # Microsoft.Windows.StoreAgent.Telemetry
	'{E0C6F6DE-258A-50E0-AC1A-103482D118BC}' # Microsoft-Windows-Install-Agent
	'{F36F2574-AC04-4A3D-8263-B97DA864B0BC}' # Microsoft-WindowsPhone-EnrollmentClient-Provider
	'{0e71a49b-ca69-5999-a395-626493eb0cbd}' # Microsoft.Windows.EnterpriseModernAppManagement
	'{16EAA7BB-5B6E-4615-BF44-B8195B5BF873}' # Microsoft.Windows.EnterpriseDesktopAppManagement
	'{FADD8651-7B42-423F-B37D-3B98B9E81560}' # Microsoft.Windows.DeviceManagement.SyncMLDpu
	'{18F2AB69-92B9-47E4-B9DB-B4AC2E4C7115}' # Microsoft.Windows.DeviceManagement.WAPDpu
	'{F9E3B648-9AF1-4DC3-9A8E-BF42C0FBCE9A}' # Microsoft.Windows.EnterpriseManagement.Enrollment
	'{E74EFD1A-B62D-4B83-AB00-66F4A166A2D3}' # Microsoft.Windows.EMPS.Enrollment
	'{0BA3FB88-9AF5-4D80-B3B3-A94AC136B6C5}' # Microsoft.Windows.DeviceManagement.ConfigManager2
	'{76FA08A3-6807-48DB-855D-2C12702630EF}' # Microsoft.Windows.EnterpriseManagement.ConfigManagerHook
	'{FFDB0CFD-833C-4F16-AD3F-EC4BE3CC1AF5}' # Microsoft.Windows.EnterpriseManagement.PolicyManager
	'{5AFBA129-D6B7-4A6F-8FC0-B92EC134C86C}' # Microsoft.Windows.EnterpriseManagement.DeclaredConfiguration
	'{F058515F-DBB8-4C0D-9E21-A6BC2C422EAB}' # Microsoft.Windows.DeviceManagement.SecurityPolicyCsp
	'{33466AA0-09A2-4C47-9B7B-1B8A4DC3A9C9}' # Microsoft-Windows-DeviceManagement-W7NodeProcessor
	'{F5123688-4272-436C-AFE1-F8DFA7AB39A8}' # Microsoft.Windows.DeviceManagement.DevDetailCsp
	'{FE5A93CC-0B38-424A-83B0-3C3FE2ACB8C9}' # Microsoft.Windows.DeviceManagement.DevInfo
	'{E1A8D70D-11F0-420E-A170-29C6B686342D}' # Microsoft.Windows.DeviceManagement.DmAccCsp
	'{6222F3F1-237E-4B0F-8D12-C20072D42197}' # Microsoft.Windows.EnterpriseManagement.ResourceManagerUnenrollHook
	'{6B865228-DEFA-455A-9E25-27D71E8FE5FA}' # Microsoft.Windows.EnterpriseManagement.ResourceManager
	'{797C5746-634F-4C59-8AE9-93F900670DCC}' # Microsoft.Windows.DeviceManagement.OMADMPRC
	'{0EC685CD-64E4-4375-92AD-4086B6AF5F1D}' # Microsoft.Windows.DeviceManagement.OmaDmClient
	'{F3B5BC3C-A182-4F7D-806D-070012D8D16D}' # Microsoft.Windows.DeviceManagement.SessionManagement
	'{86625C04-72E1-4D36-9C86-CA142FD0A946}' # Microsoft.Windows.DeviceManagement.OmaDmApiProvider
	'{22111816-32de-5f2f-7260-2e7c4a7899ce}' # Microsoft.Windows.Shell.Personalization.CSP
)

$PRF_DWMProviders = @(
	'{d29d56ea-4867-4221-b02e-cfd998834075}' # Microsoft-Windows-Dwm-Dwm(dwm.exe)
	'{9e9bba3c-2e38-40cb-99f4-9e8281425164}' # Microsoft-Windows-Dwm-Core
	'{292a52c4-fa27-4461-b526-54a46430bd54}' # Microsoft-Windows-Dwm-Api
	'{31f60101-3703-48ea-8143-451f8de779d2}' # Microsoft-Windows-DesktopWindowManager-Diag
	'{802ec45a-1e99-4b83-9920-87c98277ba9d}' # Microsoft-Windows-DxgKrnl
	'{93112de2-0aa3-4ed7-91e3-4264555220c1}' # Microsoft.Windows.Dwm.DComp
	'{504665a2-31f7-4b2f-bf1b-9635312e8088}' # Microsoft.Windows.Dwm.DwmApi
	'{1bf43430-9464-4b83-b7fb-e2638876aeef}' # Microsoft.Windows.Dwm.DwmCore
	'{45ac0c12-fa92-4407-bc96-577642890490}' # Microsoft.Windows.Dwm.DwmInit
	'{707d4382-a144-4d0a-827c-3f4422b5cf1f}' # Microsoft.Windows.Dwm.GhostWindow
	'{289E2456-EE16-4C81-AAF1-7414D66CA0BE}' # WindowsDwmCore
	'{c7a6e2fd-24f6-48fd-aad8-03ee14faf5ce}' # Microsoft.Windows.Dwm.WindowFrame
	'{11a377e3-be1e-4ee7-abda-81c6eda62e71}' # DwmAltTab
	'{25bd019c-3858-4ea4-a7b3-55b9ec8977e5}' # DwmRedir
	'{57e0b31d-de8c-4181-bcd1-f70e880b49fc}' # Microsoft-Windows-Dwm-Redir
	'{8c416c79-d49b-4f01-a467-e56d3aa8234c}' # DwmWin32kWin8
	'{8c9dd1ad-e6e5-4b07-b455-684a9d879900}' # Microsoft-Windows-Dwm-Core-Win7
	'{8cc44e31-7f28-4f45-9938-4810ff517464}' # DwmScheduler
	'{92ae46d7-6d9c-4727-9ed5-e49af9c24cbf}' # Microsoft-Windows-Dwm-Api-Win7
	'{98583af0-fc93-4e71-96d5-9f8da716c6b8}' # Microsoft-Windows-Dwm-Udwm
	'{bc2eeeec-b77a-4a52-b6a4-dffb1b1370cb}' # Microsoft-Windows-Dwm-Dwm
	'{e7ef96be-969f-414f-97d7-3ddb7b558ccc}' # DwmWin32k
	'{ed56cd5c-617b-49a5-9b80-eca3e02414bd}' # Dw
	'{72AB269D-8B68-4A17-B599-FCB1226A0319}' # Microsoft_Windows_Dwm_Udwm_Provider
	'{0C24D94B-8305-4D60-9765-5AFFD5462872}' # Microsoft.Windows.Udwm
	'{1a289bed-9134-4b49-9c10-4f98675cad08}' # Microsoft.Windows.Dwm.DwmRedir
)

$PRF_FontProviders = @(
	'{8479f1a8-524e-5226-d27e-05636c12b837}' # Microsoft.Windows.Desktop.Fonts.FontManagementSystem
	'{0ae92c9d-6960-566e-221f-5784660d04c3}' # Microsoft.Windows.Fonts.FontEmbedding
	'{E856C26A-E105-4683-A948-6920DCC42E45}' # Microsoft-Windows-DirectWrite-FontCache
	'{487d6e37-1b9d-46d3-a8fd-54ce8bdf8a53}' # Win32kTraceLogging
)

$PRF_IMEProviders = @(
	'{E2242B38-9453-42FD-B446-00746E76EB82}' # Microsoft-Windows-IME-CustomerFeedbackManager
	'{31BCAC7F-4AB8-47A1-B73A-A161EE68D585}' # Microsoft-Windows-IME-JPAPI
	'{3AD571F3-BDAE-4942-8733-4D1B85870A1E}' # Microsoft-Windows-IME-JPPRED
	'{8C8A69AD-CC89-481F-BBAD-FD95B5006256}' # Microsoft-Windows-IME-JPTIP
	'{BDD4B92E-19EF-4497-9C4A-E10E7FD2E227}' # Microsoft-Windows-IME-TIP
	'{FD44A6E7-580F-4A9C-83D9-D820B7D3A033}' # Microsoft-Windows-IME-OEDCompiler
	'{4FBA1227-F606-4E5F-B9E8-FAB9AB5740F3}' # Microsoft-Windows-TSF-msctf
	'{ebadf775-48aa-4bf3-8f8e-ec68d113c98e}' # Microsoft-Windows-TextInput
	'{7B434BC1-8EFF-41A3-87E9-5D8AF3099784}' # Microsoft-Windows-Shell-KeyboardHosting-ShellKeyboardManager
	'{34c25d46-d194-5918-c399-d3641f0c609d}' # Microsoft-Windows-ComposableShell-Components-InputHost
	'{5C3E3AA8-3BA4-43CD-A7DE-3BF5F70F9CA4}' # Microsoft-Windows-Shell-TextInput-InputPanel
	'{7e6b69b9-2aec-4fb3-9426-69a0f2b61a86}' # Microsoft-Windows-Win32kBase-Input
	'{74B655A2-8958-410E-80E2-3457051B8DFF}' # Microsoft-Windows-TSF-msutb
	'{4DD778B8-379C-4D8C-B659-517A43D6DF7D}' # Microsoft-Windows-TSF-UIManager
	'{39A63500-7D76-49CD-994F-FFD796EF5A53}' # Microsoft-Windows-TextPredictionEngine
	'{E2C15FD7-8924-4C8C-8CFE-DA0BE539CE27}' # Microsoft-Windows-IME-Broker
	'{7C4117B1-ED82-4F47-B2CA-29E4E25719C7}' # Microsoft-Windows-IME-CandidateUI
	'{1B734B40-A458-4B81-954F-AD7C9461BED8}' # Microsoft-Windows-IME-CustomerFeedbackManagerUI
	'{DBC388BC-89C2-4FE0-B71F-6E4881FB575C}' # Microsoft-Windows-IME-JPLMP
	'{14371053-1813-471A-9510-1CF1D0A055A8}' # Microsoft-Windows-IME-JPSetting
	'{7562948E-2671-4DDA-8F8F-BF945EF984A1}' # Microsoft-Windows-IME-KRAPI
	'{E013E74B-97F4-4E1C-A120-596E5629ECFE}' # Microsoft-Windows-IME-KRTIP
	'{F67B2345-47FA-4721-A6FB-FE08110EECF7}' # Microsoft-Windows-IME-TCCORE
	'{D5268C02-6F51-436F-983B-74F2EFBFAF3A}' # Microsoft-Windows-IME-TCTIP
	'{28e9d7c3-908a-5980-90cc-1581dd9d451d}' # Microsoft.Windows.Desktop.Shell.EUDCEditor
	'{397fe846-4109-5a9b-f2eb-c1d3b72630fd}' # Microsoft.Windows.Desktop.TextInput.InputSwitch
	'{c442c41d-98c0-4a33-845d-902ed64f695b}' # Microsoft.Windows.TextInput.ImeSettings
	'{6f72e560-ef48-5597-9970-e83a697071ac}' # Microsoft.Windows.Desktop.Shell.InputDll
	'{03e60cf9-4fa0-5ddd-7452-1d05ce7d61bd}' # Microsoft.Windows.Desktop.TextInput.UIManager
	'{86df9ee3-15c5-589d-4355-17cc2371dae1}' # Microsoft.Windows.Desktop.TextInput.TabNavigation
	'{887B7E68-7106-4E20-B8A1-2506C336EC2E}' # Microsoft-Windows-InputManager
	'{ED07CE1C-CEE3-41E0-93E2-EEB312301848}' # Microsoft-WindowsPhone-Input
	'{BB8E7234-BBF4-48A7-8741-339206ED1DFB}' # Microsoft-Windows-InputSwitch
	'{E978F84E-582D-4167-977E-32AF52706888}' # Microsoft-Windows-TabletPC-InputPanel
	'{3F30522E-D47A-407C-9067-2E928D00D54E}' # TouchKeyboard
	'{B2A2AFC4-FD0B-5A85-9EEF-0CE26805CB02}' # Microsoft.Windows.Input.HidClass
	'{6465DA78-E7A0-4F39-B084-8F53C7C30DC6}' # Microsoft-Windows-Input-HIDCLASS
	'{83BDA64C-A52C-4B37-8E61-086C22A4CD15}' # Microsoft.Windows.InputStateManager
	'{36D7CADA-005D-4F57-A37A-DA52FB3C1296}' # Tablet Input Perf
	'{2C3E6D9F-8298-450F-8E5D-49B724F1216F}' # Microsoft-Windows-TabletPC-Platform-Input-Ninput
	'{E5AA2A53-30BE-40F5-8D84-AD3F40A404CD}' # Microsoft-Windows-TabletPC-Platform-Input-Wisp
	'{B5FD844A-01D4-4B10-A57F-58B13B561582}' # Microsoft-Windows-TabletPC-Platform-Input-Core
	'{A8106E5C-293A-4CD0-9397-2E6FAC7F9749}' # Microsoft-Windows-TabletPC-InputPersonalization
	'{4f6a3c95-b86c-59f7-d8ed-d5b0b6a683d6}' # Microsoft.Windows.Desktop.TextInput.TextServiceFramework
	'{78eba95a-9f43-44b0-8391-6992cb068def}' # Microsoft.Windows.Desktop.TextInput.MsCtfIme
	'{f7febf94-a5f7-464b-abbd-84a042681d00}' # Microsoft.Windows.Desktop.TextInput.ThreadInputManager"
	'{06404639-ec4f-56d8-f82e-49bf6ad1b96a}' # Microsoft.Windows.Desktop.TextInput.BopomofoIme
	'{2593bdf1-313b-5c29-355c-6065ba331797}' # Microsoft.Windows.Desktop.TextInput.ImeCommon
	'{68259fff-ce2b-4a91-8df0-9656cdb7a4d6}' # Microsoft.Windows.Desktop.TextInput.MSCand20
	'{a703f75d-9c1d-59c0-6b0a-a1251f1c6c55}' # Microsoft.Windows.DeskTop.TextInput.ModeIndicator
	'{a097d80a-cae1-5a27-bdea-58bd574c9901}' # Microsoft.Windows.Desktop.TextInput.CloudSuggestionFlyout
	'{47a8ea0f-be9f-5a94-1586-5ded19d57c3d}' # Microsoft.Windows.Desktop.TextInput.JapaneseIme
	'{ca8d5125-1b72-5208-5147-0d345b85bd11}' # Microsoft.Windows.Desktop.TextInput.KoreanIme
	'{e3905915-dd2b-5802-062b-85f03eb993d5}' # Microsoft.Windows.Desktop.TextInput.OldKoreanIme
	'{54cedcd4-5f61-54b3-d8e2-dd26feae36b2}' # Microsoft.Windows.Shell.MTF.DesktopInputHistoryDS
	'{99d75be6-d696-565a-1c56-25d65942b571}' # Microsoft.Windows.Shell.MTF.LMDS
	'{89DB9EAC-5750-580C-39D6-6978396822DD}' # Microsoft.Windows.TextInput.Gip
	'{2D66BB8D-2A6B-5A2D-A09C-4F57A1776BD1}' # Microsoft.Windows.TextInput.ChsIme
	'{4B7BD959-BFEA-5953-583C-FB7BF825BC92}' # Microsoft.Windows.Desktop.TextInput.ChtIme
	'{FF5023D9-8341-5DFB-3C33-17A1AB76A426}' # Microsoft.Windows.Shell.CandidateWindow
	'{73AE0EC4-37FC-4B10-92C0-7F6D9D0539B9}' # Microsoft-Windows-TextInput-ExpressiveInput
	'{D49F5FDD-C4AB-47BD-BD68-A9A8688A92AB}' # Microsoft.Windows.TextInput.Gip.Perf
	'{6BE754E7-F231-4DB7-A9B6-3720F91A7AD2}' # Microsoft.Windows.TextInput.Gip.LegacyBopomofo.Perf
	'{04708A84-8C97-4B32-A8A9-2762C83573C0}' # Microsoft-IPX-Core
	'{C3AF4B8A-C24F-56D4-CE67-DEF9F522A0DD}' # Microsoft.Windows.Shell.TouchKeyboardExperience
	'{68396F5F-E685-5C1B-3181-A17CF8D96FA6}' # Microsoft-Windows-Desktop-TextInput-TouchKeyboard
	'{04acff1a-30a0-4e6c-81bd-ad3ff3c67771}' # Microsoft.WindowsInternal.ComposableShell.Experiences.SuggestionUI.Web
	'{9cecf4ae-61a9-41bc-ac51-06bd5f4a30d1}' # Microsoft.WindowsInternal.ComposableShell.Experiences.SuggestionUI
	'{2a72b023-e9bf-4b39-9924-7f1872bd0959}' # Microsoft.WindowsInternal.Client.Components.PackageFeed
	'{393ff4cc-f02d-5d0a-4180-b79bf8da529d}' # Microsoft.Windows.Shell.MTF.Platform
	'{C73DBAB0-5395-4D87-8134-290D28AC0E01}' # Microsoft.Windows.Fundamentals.UserInitiatedFeedback
	'{5FB75EAC-9F0B-550C-339F-FC21FDE966CD}' # Microsoft.Windows.InputCore.TraceLogging.UIF
	'{A90E365C-CC39-4B68-B943-DCD45C83BB52}' # Microsoft.Windows.InputCore.Manifested.UIF
	'{47C779CD-4EFD-49D7-9B10-9F16E5C25D06}' # Microsoft.Windows.HID.HidClass
	'{E742C27D-29B1-4E4B-94EE-074D3AD72836}' # Microsoft.Windows.HID.I2C
	'{0A6B3BB2-3504-49C1-81D0-6A4B88B96427}' # Microsoft.Windows.HID.SPI
	'{896F2806-9D0E-4D5F-AA25-7ACDBF4EAF2C}' # Microsoft.Windows.HID.USB
	'{07699FF6-D2C0-4323-B927-2C53442ED29B}' # Microsoft.Windows.HID.BTH
	'{0107CF95-313A-473E-9078-E73CD932F2FE}' # Microsoft.Windows.HID.GATT
	'{B41B0A56-4483-48EF-A772-0B007CBEA8C6}' # Microsoft.Windows.HID.kbd
	'{09281F1F-F66E-485A-99A2-91638F782C49}' # Microsoft.Windows.HID.kbdclass
	'{BBBC2565-8272-486E-B5E5-2BC4630374BA}' # Microsoft.Windows.HID.mou
	'{FC8DF8FD-D105-40A9-AF75-2EEC294ADF8D}' # Microsoft.Windows.HID.mouclass
	'{46BCE2CC-ED23-41DF-BE49-6BB8EC04CF70}' # Microsoft.Windows.Drivers.MtConfig
	'{4B2862FE-F8BE-41FF-984A-0AF845F78E86}' # Microsoft.Windows.HID.Buttonconverter
	'{78396E52-9753-4D63-8CF5-A936B4989FF2}' # Microsoft.Windows.HID.HidInterrupt
	'{5A81715A-84C0-4DEF-AE38-EDDE40DF5B3A}' # Microsoft.Windows.HID.GPIO
	'{51B2172F-205D-40C1-9A30-ED090FF72E6C}' # Microsoft.Windows.HID.VHF
	'{E6086B4D-AEFF-472B-BDA7-EEC662AFBF11}' # Microsoft.Windows.HID.SpbCx
	'{6E6CC2C5-8110-490E-9905-9F2ED700E455}' # Microsoft.Windows.USB.UsbHub3
	'{6FB6E467-9ED4-4B73-8C22-70B97E22C7D9}' # Microsoft.Windows.USB.ucx01000
	'{9F7711DD-29AD-C1EE-1B1B-B52A0118A54C}' # Microsoft.Windows.USB.XHCI
	'{BC6C9364-FC67-42C5-ACF7-ABED3B12ECC6}' # Microsoft.Windows.USB.CCGP
	'{B10D03B8-E1F6-47F5-AFC2-0FA0779B8188}' # Microsoft.Windows.USB.Hub
	'{D75AEDBE-CFCD-42B9-94AB-F47B224245DD}' # Microsoft.Windows.USB.Port
	'{7FFB8EB8-2C86-45D6-A7C5-C023D9C070C1}' # Microsoft.Windows.Drivers.I8042prt
	'{8D83BA5C-E85E-4859-B18E-314BA4475A12}' # Microsoft.Windows.Drivers.msgpioclx
	'{D88ACE07-CAC0-11D8-A4C6-000D560BCBA5}' # Microsoft.Windows.Drivers.bthport
	'{CDEF60FA-5777-4B02-9980-1E2C0DF22635}' # Microsoft.Windows.Power.DeviceProblems
	'{3374F1C0-597F-4AA1-B2C2-12789D9C8C3F}' # Microsoft.Windows.RIM_RS1.WPP
	'{0F81EC00-9E52-48E6-B899-EB3BBEEDE741}' # Microsoft.Windows.Win32kBase.WPP
	'{03914E49-F3DD-40B9-BB7F-9445BF46D43E}' # Microsoft.Windows.Win32kMin.WPP
	'{335D5E04-5638-4E58-AA36-7ED1CFE76FD6}' # Microsoft.Windows.Win32kFull.WPP
	'{9C648335-6987-470C-B588-3DE7A6A1FDAC}' # Microsoft.Windows.Win32kNs.WPP
	'{487D6E37-1B9D-46D3-A8FD-54CE8BDF8A53}' # Microsoft.Windows.Win32k.TraceLogging
	'{8C416C79-D49B-4F01-A467-E56D3AA8234C}' # Microsoft.Windows.Win32k.UIF
	'{7D30FE49-D67F-42D7-A360-9A0639EC5719}' # Microsoft.Windows.OneCore.MinUser
	'{331C3B3A-2005-44C2-AC5E-77220C37D6B4}' # Microsoft.Windows.Kernel.Power
	'{029769EE-ED48-4166-894E-357918A77E68}' # Microsoft.Windows.WCOS.Adapter
	'{9956C4CC-7B21-4D55-B22D-3A0EA2BDDEB9}' # Microsoft.Windows.OneCore.MinUserExt
	'{A7F923A4-8693-4876-92F4-4FF49791D3CF}' # Microsoft.Windows.Ninput.Interaction
	'{2BED2D8B-72D4-4D19-B0AC-DC27BF3B24EA}' # Microsoft.Windows.Dwm.Tests
	'{461B985D-2EBE-49C1-B506-BBF6C753A82B}' # Microsoft.Windows.Dwm.LiftedTests
	'{2729BE56-B41A-54BE-8C2A-8DA6127A8E38}' # Microsoft.Windows.Dwm.Interaction
	'{07E4CEB9-D0CC-48A6-AF64-00F7A7D1198F}' # Microsoft.Windows.Dwm.LiftedInteraction
	'{9E9BBA3C-2E38-40CB-99F4-9E8281425164}' # Microsoft.Windows.Dwm.Core.Input
	'{973C694B-79A6-480E-89A5-C8C20745D461}' # Microsoft.Windows.OneCore.MinInput
	'{23E0D3D9-6334-4EDD-9C80-54D3D7CFA8DA}' # Microsoft.Windows.WinUI.WPP
	'{CB18E7B3-F5B0-412F-9F18-5D87FEFCD662}' # Microsoft.Windows.DirectManipulation.WPP
	'{5786E035-EF2D-4178-84F2-5A6BBEDBB947}' # Microsoft.Windows.DirectManipulation
	'{EE8FDBA0-14D6-50EC-A17A-33F388F21065}' # Microsoft.Windows.DirectInk
	'{C44219D0-F344-11DF-A5E2-B307DFD72085}' # Microsoft.Windows.DirectComposition
	'{7D99F6A4-1BEC-4C09-9703-3AAA8148347F}' # Microsoft.Windows.Dwm.Redir
	'{531A35AB-63CE-4BCF-AA98-F88C7A89E455}' # Microsoft.Windows.XAML
	'{A3D95055-34CC-4E4A-B99F-EC88F5370495}' # Microsoft.Windows.CoreWindow
	'{55A5DC53-E24E-5B53-5B52-EA83A0CC4E0C}' # Microsoft.Windows.Heat.HeatCore
	'{54225112-EAA1-5E29-C8F8-1CB9924D6049}' # Microsoft.Windows.Heat.HeatCore.Test
	'{4AE53EDA-2033-5DD2-8850-99823083A9E5}' # Microsoft.Windows.Heat.Processor
	'{A0B7550F-4E9A-4F03-AD41-B8042D06A2F7}' # Microsoft.Windows.CoreUIComponents
)

$PRF_ImmersiveUIProviders = @(
	'{74827cbb-1e0f-45a2-8523-c605866d2f22}' # Microsoft-Windows-WindowsUIImmersive
	'{ee818f02-698c-48be-8ff2-326c6dd34db5}' # SystemInitiatedFeedbackLoggingProvider
	'{EE9969D1-3438-42EA-B879-1AA52A135844}' # HostingFramework
	'{7D45E281-B342-4B07-9061-43056E1C4BA4}' # PopupWindow
	'{239d82f3-77e1-541b-2cbc-50274c47b5f7}' # Microsoft.Windows.Shell.BridgeWindow
	'{f8e28969-b1df-57fa-23f6-42260c77135c}' # Microsoft.Windows.ImageSanitization
	'{46668d11-2db1-5756-2a4b-98fce8b0375f}' # Microsoft.Windows.Shell.Windowing.LightDismiss
	'{9dc9156d-fbd5-5780-bd80-b1fd208442d6}' # Windows.UI.Popups
	'{1941DE80-2226-413B-AFA4-164FD76914C1}' # Microsoft.Windows.Desktop.Shell.WindowsUIImmersive.LockScreen
	'{D3F64994-CCA2-4F97-8622-07D451397C09}' # MicrosoftWindowsShellUserInfo
)

$PRF_MediaProviders = @(
	'{F3F14FF3-7B80-4868-91D0-D77E497B025E}' # Microsoft-Windows-WMP
	'{AE4BD3BE-F36F-45B6-8D21-BDD6FB832853}' # Microsoft-Windows-Audio
	'{7C314E58-8246-47D1-8F7A-4049DC543E0B}' # Microsoft-Windows-WMPNSSUI
	'{614696C9-85AF-4E64-B389-D2C0DB4FF87B}' # Microsoft-Windows-WMPNSS-PublicAPI
	'{BE3A31EA-AA6C-4196-9DCC-9CA13A49E09F}' # Microsoft-Windows-Photo-Image-Codec
	'{02012A8A-ADF5-4FAB-92CB-CCB7BB3E689A}' # Microsoft-Windows-ShareMedia-ControlPanel
	'{B20E65AC-C905-4014-8F78-1B6A508142EB}' # Microsoft-Windows-MediaFoundation-Performance-Core
	'{3F7B2F99-B863-4045-AD05-F6AFB62E7AF1}' # Microsoft-Windows-TerminalServices-MediaRedirection
	'{42D580DA-4673-5AA7-6246-88FDCAF5FFBB}' # Microsoft.Windows.CastQuality
	'{1F930302-F484-4E01-A8A7-264354C4B8E3}' # Microsoft.Windows.Cast.MiracastLogging
	'{596426A4-3A6D-526C-5C63-7CA60DB99F8F}' # Microsoft.Windows.WindowsMediaPlayer	
	'{E27950EB-1768-451F-96AC-CC4E14F6D3D0}' # AudioTrace
	'{A9C1A3B7-54F3-4724-ADCE-58BC03E3BC78}' # Windows Media Player Trace
	'{E2821408-C59D-418F-AD3F-AA4E792AEB79}' # SqmClientTracingGuid
	'{6E7B1892-5288-5FE5-8F34-E3B0DC671FD2}' # Microsoft.Windows.Audio.Client
	'{AAC97853-E7FC-4B93-860A-914ED2DEEE5A}' # MediaServer
	'{E1CCD9F8-6E9F-43ad-9A32-8DBEBE72A489}' # WMPDMCCoreGuid
	'{d3045008-e530-485e-81b7-c6d54dbd9044}' # CTRLGUID_EVR_WPP
	'{00000000-0dc9-401d-b9b8-05e4eca4977e}' # CTRLGUID_MF_PLATFORM
	'{00000001-0dc9-401d-b9b8-05e4eca4977e}' # CTRLGUID_MF_PIPELINE
	'{00000002-0dc9-401d-b9b8-05e4eca4977e}' # CTRLGUID_MF_CORE_SINKS
	'{00000003-0dc9-401d-b9b8-05e4eca4977e}' # CTRLGUID_MF_CORE_SOURCES
	'{00000004-0dc9-401d-b9b8-05e4eca4977e}' # CTRLGUID_MF_NETWORK
	'{00000005-0dc9-401d-b9b8-05e4eca4977e}' # CTRLGUID_MF_CORE_MFTS
	'{00000006-0dc9-401d-b9b8-05e4eca4977e}' # CTRLGUID_MF_PLAY
	'{00000007-0dc9-401d-b9b8-05e4eca4977e}' # CTRLGUID_MF_CAPTURE_ENGINE
	'{00000008-0dc9-401d-b9b8-05e4eca4977e}' # CTRLGUID_MF_VIDEO_PROCESSOR
	'{C9C074D2-FF9B-410F-8AC6-81C7B8E60D0F}' # MediaEngineCtrlGuid
	'{982824E5-E446-46AE-BC74-836401FFB7B6}' # Microsoft-Windows-Media-Streaming
	'{8F2048E0-F260-4F57-A8D1-932376291682}' # Microsoft-Windows-MediaEngine
	'{8F0DB3A8-299B-4D64-A4ED-907B409D4584}' # Microsoft-Windows-Runtime-Media
	'{DD2FE441-6C12-41FD-8232-3709C6045F63}' # Microsoft-Windows-DirectAccess-MediaManager
	'{D2402FDE-7526-5A7B-501A-25DC7C9C282E}' # Microsoft-Windows-Media-Protection-PlayReady-Performance
	'{B8197C10-845F-40CA-82AB-9341E98CFC2B}' # Microsoft-Windows-MediaFoundation-MFCaptureEngine
	'{4B7EAC67-FC53-448C-A49D-7CC6DB524DA7}' # Microsoft-Windows-MediaFoundation-MFReadWrite
	'{A4112D1A-6DFA-476E-BB75-E350D24934E1}' # Microsoft-Windows-MediaFoundation-MSVProc
	'{F404B94E-27E0-4384-BFE8-1D8D390B0AA3}' # Microsoft-Windows-MediaFoundation-Performance
	'{BC97B970-D001-482F-8745-B8D7D5759F99}' # Microsoft-Windows-MediaFoundation-Platform
	'{B65471E1-019D-436F-BC38-E15FA8E87F53}' # Microsoft-Windows-MediaFoundation-PlayAPI
	'{323DAD74-D3EC-44A8-8B9D-CAFEB4999274}' # Microsoft-Windows-WLAN-MediaManager
	'{F4C9BE26-414F-42D7-B540-8BFF965E6D32}' # Microsoft-Windows-WWAN-MediaManager
	'{4199EE71-D55D-47D7-9F57-34A1D5B2C904}' # TSMFTrace
	'{A9C1A3B7-54F3-4724-ADCE-58BC03E3BC78}' # CtlGuidWMP
	'{3CC2D4AF-DA5E-4ED4-BCBE-3CF995940483}' # Microsoft-Windows-DirectShow-KernelSupport
	'{968F313B-097F-4E09-9CDD-BC62692D138B}' # Microsoft-Windows-DirectShow-Core
	'{9A010476-792D-57BE-6AF9-8DE32164F021}' # Microsoft.Windows.DirectShow.FilterGraph
	'{E5E16361-C9F0-4BF4-83DD-C3F30E37D773}' # VmgTraceControlGuid
	'{A0386E75-F70C-464C-A9CE-33C44E091623}' # DXVA2 (DirectX Video Acceleration 2)
	'{86EFFF39-2BDD-4EFD-BD0B-853D71B2A9DC}' # Microsoft-Windows-MPEG2_DLNA-Encoder
	'{AE5CF422-786A-476A-AC96-753B05877C99}' # Microsoft-Windows-MSMPEG2VDEC 
	'{51311DE3-D55E-454A-9C58-43DC7B4C01D2}' # Microsoft-Windows-MSMPEG2ADEC
	'{0A95E01D-9317-4506-8796-FB946ACD7016}' # CodecLogger
	'{EA6D6E3B-7014-4AB1-85DB-4A50CDA32A82}' # Codec
	'{7F2BD991-AE93-454A-B219-0BC23F02262A}' # Microsoft-Windows-MP4SDECD
	'{2A49DE31-8A5B-4D3A-A904-7FC7409AE90D}' # Microsoft-Windows-MFH264Enc
	'{55BACC9F-9AC0-46F5-968A-A5A5DD024F8A}' # Microsoft-Windows-wmvdecod
	'{313B0545-BF9C-492E-9173-8DE4863B8573}' # Microsoft-Windows-WMVENCOD
	'{3293F985-41D3-4B6A-B187-2FF4AA91F2FC}' # Multimedia-HEVCDECODER / Microsoft-OneCore-Multimedia-HEVCDECODER
	'{D17B213A-C505-49C9-98CC-734253EF65D4}' # Microsoft-Windows-msmpeg2venc
	'{B6C06841-5C8C-47A6-BEDE-6159F4D4A701}' # MyDriver1TraceGuid
	'{E80ADCF1-C790-4108-8BB9-8A5CA3466C04}' # Microsoft-Windows-TerminalServices-RDP-AvcSoftwareDecoder
	'{3f7b2f99-b863-4045-ad05-f6afb62e7af1}' # Microsoft-Windows-TerminalServices-MediaRedirection(tsmf.dll)
)

$PRF_PerflibProviders = @(
	'{04D66358-C4A1-419B-8023-23B73902DE2C}!Perflib' # Microsoft-Windows-PDH
	'{E1A5FA6F-2E74-4C70-B292-D34C4338D54C}!Perflib' # LoadperfDll
	'{13B197BD-7CEE-4B4E-8DD0-59314CE374CE}!Perflib' # Microsoft-Windows-Perflib
	'{970407AD-6485-45DA-AA30-58E0037770E4}!Perflib' # PerfLib
	'{BC44FFCD-964B-5B85-8662-0BA87EDAF07A}!Perflib' # Microsoft.Windows.PerfLib
	'{C9BF4A07-D547-4D11-8242-E03A18B5BE01}!Perflib' # PERFLIB
	'{BFFB9DBD-5983-4197-BB1A-243798DDBEC7}!WmiPerf' # WMIPerfClass
	'{970406AD-6475-45DA-AA30-57E0037770E4}!WmiPerf' # WMIPerfInst 
)

$PRF_PhotoProviders = @(
	'{054B421C-7DEF-54EF-EF59-41B32C8F94BC}'
	'{6A1E3074-FFEE-5D94-F0B9-F1E92857AC55}'
	'{3C20A2BD-0497-5E1D-AD49-7B789B9D7318}'
	'{1EE9AB78-81DE-5903-9F1B-4C73E2F3501D}'
	'{8F4FD2AF-C8DB-5CC1-27EC-54A4BCF3AAB5}'
	'{EBDDC69C-80FB-5062-B3BA-C203645A72EE}'
	'{DCA2B5B9-047F-5768-688F-9B4C705B541F}'
)

$PRF_RADARProviders = @(
	'{17FBAB0B-1E4F-45F8-91ED-C1C85BCF6E61}' # RdrResTraceGuid
	'{9D3A5FA0-29F7-423F-B026-E4456ABEEF2C}' # RdrDetTraceGuid
	'{C2B32509-6F1B-4A71-A2D7-EE0B8F5DEBD1}' # RdrLeakDiagTraceGuid
	'{5C9BE3E0-3593-4DCD-8F6D-63840923FFEE}' # Microsoft-Windows-Resource-Leak-Diagnostic
	'{9988748E-C2E8-4054-85F6-0C3E1CAD2470}' # Microsoft-Windows-Resource-Exhaustion-Detector
	'{91F5FB12-FDEA-4095-85D5-614B495CD9DE}' # Microsoft-Windows-Resource-Exhaustion-Resolver
)

$PRF_ShellProviders = @(
	# Shell
	'{30336ed4-e327-447c-9de0-51b652c86108}' # Microsoft-Windows-Shell-Core(shsvcs.dll) => Too many logs will be logged.
	'{46FCB024-5EA4-446C-B6C4-C7A4EE784198}' # ShellTraceProvider
	'{687AE510-1C00-4108-A958-ACFA78ECCCD5}' # Microsoft.Windows.Shell.AccountsControl
	'{c6fe0c47-96ef-5d29-c249-c3cecc6f9930}' # Microsoft.Windows.Shell.SyncPartnership.Api
	'{DC3B5BCF-BF7B-42CE-803C-71AF48F0F546}' # Microsoft.Windows.CredProviders.PasswordProvider
	'{d0034f5e-3686-5a74-dc48-5a22dd4f3d5b}' # Microsoft.Windows.Shell.CloudExperienceHost
	'{ff91e668-f7be-577e-14a3-44d801cccfa0}' # Microsoft.Windows.Shell.CloudExperienceHostCore
	'{f385e1a5-0346-5411-11a2-e8c8afe3b6ca}' # Microsoft.Windows.Desktop.Shell.CloudExperienceHostSpeech
	'{e305fb0f-da8e-52b5-a918-7a4f17a2531a}' # Microsoft.Windows.Shell.DefaultAssoc
	'{ee97cdc4-b095-5c70-6e37-a541eb74c2b5}' # Microsoft.Windows.AppLifeCycle.UI
	'{df8dab3f-b1c9-58d3-2ea1-4c08592bb71b}' # Microsoft.Windows.Shell.Taskbar
	'{653fe5bd-e1d2-5d40-d93c-a551a97cd49a}' # Microsoft.Windows.Desktop.Shell.NotificationArea
	'{5AFB7971-45E5-4d49-AAEB-1B04D39872CF}' # Microsoft.Windows.MobilityExperience
	'{7ca6a4dd-dae5-5fb7-ec8e-4a6c648fadf9}' # Microsoft.Windows.ShellPlacements
	'{55e357f8-ef0d-5ffd-a4dd-50e3d8f707cb}' # Microsoft.Windows.Desktop.Shell.CoreApplication.CoreApplicationView
	'{5487F421-E4DE-41D4-BFF3-72A4D6584898}' # Microsoft.Windows.Shell.SystemSettings.SettingHandlersSystem
	'{79c43bcd-08ea-5914-1e38-9e3008863a0c}' # Microsoft.Windows.Settings.Accessibility
	'{571ac9d5-12fd-4438-b630-61fb26bbb0ac}' # Microsoft.Windows.Shell.SystemSettings.BatterySaver
	'{e04d85e2-56a2-5bb7-5dab-6f761366a4c2}' # Microsoft.Windows.Shell.SystemSettings.BatterySaver.Desktop
	'{d43920c8-d57d-4e58-9283-f0fddd4afdcb}' # WindowsFlightingSettings
	'{080e197d-7cc1-54a3-e889-27636425992a}' # Microsoft.Windows.Shell.ShareUXSettings
	'{DB7BD825-B56F-48c4-8196-22BC145DDB08}' # Microsoft.Windows.Shell.SystemSettings.SIUF
	'{830a1f34-7797-4e31-9b75-c82056330051}' # Microsoft.Windows.Shell.SystemSettings.StorageSense
	'{0e6f34b3-0637-55ab-f0bb-8b8fa83eda04}' # Microsoft-Windows-Shell-CortanaProactive
	'{C11543B0-3A34-4F10-B50B-4DDB76FF2C6E}' # Microsoft.Windows.Shell.ThumbnailCache
	'{382B5E24-181E-417F-A8D6-2155F749E724}' # Microsoft.Windows.ShellExecute
	# Windows.Storage.dll
	'{79172b48-631e-5d2c-9f04-1ad99f6e1046}' # Microsoft.Windows.Desktop.Shell.Shell32
	'{9399df73-403c-5d8f-70c7-25aa3184c6f3}' # Microsoft.Windows.Shell.Libraries
	'{f168d2fa-5642-58bb-361e-127980c64a1b}' # Microsoft.Windows.Shell.OpenWith
	'{59a3be04-f025-4585-acfc-34456b550813}' # Microsoft.Windows.Shell.Edp
	'{8e12dcd2-fe15-5af4-2a6a-e707d9dc7de5}' # MicrosoftWindowsFileExplorer
	'{A40B455C-253C-4311-AC6D-6E667EDCCEFC}' # CloudFileAggregateProvider
	'{32980F26-C8F5-5767-6B26-635B3FA83C61}' # FileExplorerAggregateProvider
	'{8939299F-2315-4C5C-9B91-ABB86AA0627D}' # Microsoft-Windows-KnownFolders
	'{E0142D4F-9E39-5B3B-9DEB-8B576025FF5E}' # Microsoft.Windows.CentennialActivation
	'{3889f5d8-66b1-44d9-b52c-48ca283ac5d8}' # Microsoft.Windows.DataPackage
	'{e1fa35be-5192-5b1e-f23e-e2a38f6414b9}' # Microsoft.Windows.FileExplorerPerf
	'{B87CF16B-0BF8-4492-A510-D5F59626B033}' # Microsoft.Windows.FileExplorerErrorFallback
	'{08f5d47e-67d3-4ee0-8e0c-cbd309ab5d1b}' # Microsoft.Windows.Shell.CloudFiles
	'{f85b4793-1347-5620-7572-b79d5a28da82}' # Microsoft.Windows.Shell.DataLayer
	'{4E21A072-576A-4254-838B-059D479563BA}' # Microsoft.Windows.ComposableShell.Components.ContextMenu
	'{783f30af-5514-51bc-5b99-5d33b678539b}' # Microsoft.Windows.Shell.StorageSearch
	'{E5067383-0952-468C-9399-2E963F38B097}' # Microsoft\\ThemeUI
	'{869FB599-80AA-485D-BCA7-DB18D72B7219}' # Microsoft-Windows-ThemeUI
	'{61F044AF-9104-4CA5-81EE-CB6C51BB01AB}' # Microsoft-Windows-ThemeCPL
	'{D3F64994-CCA2-4F97-8622-07D451397C09}' # MicrosoftWindowsShellUserInfo
	'{1941DE80-2226-413B-AFA4-164FD76914C1}' # Microsoft.Windows.Desktop.Shell.WindowsUIImmersive.LockScreen
	'{9dc9156d-fbd5-5780-bd80-b1fd208442d6}' # Windows.UI.Popups
	'{46668d11-2db1-5756-2a4b-98fce8b0375f}' # Microsoft.Windows.Shell.Windowing.LightDismiss
	'{f8e28969-b1df-57fa-23f6-42260c77135c}' # Microsoft.Windows.ImageSanitization
	'{239d82f3-77e1-541b-2cbc-50274c47b5f7}' # Microsoft.Windows.Shell.BridgeWindow
	'{4fc2cbef-b755-5b53-94db-8d816ca8c9cd}' # Microsoft.Windows.Shell.WindowMessageService
	'{d2ff0031-cf02-500b-5898-8af98680cedb}' # Microsoft.Windows.Shell.ProjectionManager
	'{3635a139-1289-567e-b0ef-71e7adf3adf2}' # Microsoft.Windows.Shell.PlayToReceiverManager
	'{f71512b7-5d8e-41ee-aad8-4a6aebd29d4e}' # Microsoft.Windows.Shell.InkWorkspaceHostedAppsManager
	'{50c2b532-05e6-4616-ae28-2a023fe55216}' # Microsoft.Windows.Shell.PenSignalManager
	'{69ecab7c-aa2d-5d2e-e85c-debcf6fc9016}' # Microsoft.Windows.Desktop.OverrideScaling
	'{C127316F-7E36-5489-189A-99E57A8E788D}' # Microsoft-Windows-Explorer-ThumbnailMTC
	'{8911c0ab-6f93-4513-86d5-3de7175dd720}' # Microsoft.Windows.Shell.NotesManager
	'{08194E35-5511-4C06-9008-8C2CE1FE6B52}' # Microsoft.Windows.Shell.MSAWindowManager
	'{158715e0-18df-56cb-1a2e-d29da8fb9973}' # Microsoft.Windows.Desktop.Shell.MonitorManager
	'{D81F69FC-478D-4631-AD03-44046980BBFA}' # MicrosoftWindowsTwinUISwitcher
	'{ED576CEC-4ED0-4E09-9291-67EAD252DDE2}' # Microsoft.Windows.Desktop.Shell.KeyboardOcclusionMitigation
	'{34581546-9f8e-45f4-b73c-1c0ac79f7b20}' # Microsoft.Windows.Shell.PenWorkspace.ExperienceManager
	'{2ca51213-29c5-564f-fd60-355148e8b47f}' # Microsoft.Windows.Shell.SingleViewExperience
	'{F84AA759-31D3-59BF-2C89-3748CF17FD7E}' # Microsoft-Windows-Desktop-Shell-Windowing
	'{4cd50c2c-1018-53d5-74a1-4214e0941c20}' # Microsoft.Windows.Shell.ClickNote
	'{1608b891-0406-5011-1238-3e93b292a6ef}' # Microsoft.Windows.Shell.Autoplay
	'{7B0C2561-285F-46BB-9229-09D11947AE28}' # Microsoft.Windows.Desktop.Shell.AccessibilityDock
	'{6924642c-34a3-5050-2915-053f31e18534}' # Microsoft.Windows.Shell.CoreApplicationBridge
	'{64aa695c-9c53-58ad-2fe7-9358ab788507}' # Microsoft.Windows.Shell.Desktop.Themes
	'{dc140d17-88f7-55d0-fcb1-068435d69c4b}' # Microsoft.Windows.Shell.RunDialog
	'{75d2b56f-3f9d-5b1c-0792-d243507f67ce}' # Microsoft.Windows.Shell.PostBootReminder
	'{8D07CB9D-CA74-44E4-B389-C7068A51393E}' # Microsoft.Windows.Shell.IconCache
	'{4a9fe8c1-cde0-5f0a-f472-69b949097daf}' # Microsoft.Windows.Shell.Desktop.IconLayout
	'{59a36fc6-225a-41bf-b1b4-b558a37798cd}' # Microsoft.Windows.Shell.CoCreateInstanceAsSystemTaskServer
	'{44db9cfe-6db3-4a53-be9a-3057fa778b50}' # Microsoft.Windows.Shell.FileExplorer.Banners
	'{3d4b08aa-1df6-4549-b479-cf49b47cfcd3}' # Microsoft-Windows-BackupAndRoaming-SyncHandlers
	'{6e43b858-f3d9-5db1-0070-f99259784399}' # Microsoft.Windows.Desktop.Shell.LanguageOptions
	'{2446bc6d-2a96-5948-96ba-db27816dee43}' # Microsoft.Windows.Shell.SharingWizard
	'{45896826-7c5e-5a91-763d-67db83540f1b}' # Microsoft.Windows.Desktop.Shell.FontFolder
	'{9a9d6c4e-0c84-5401-7148-5d809fa78018}' # Microsoft.Windows.Desktop.Shell.RegionOptions
	'{ed7432ee-0f83-5083-030b-39f66ba307c5}' # Microsoft.Windows.Desktop.ScreenSaver
	'{8fe8ebd4-0f51-5f91-9481-cd2cfefdf96e}' # Microsoft.Windows.Desktop.Shell.Charmap
	'{28e9d7c3-908a-5980-90cc-1581dd9d451d}' # Microsoft.Windows.Desktop.Shell.EUDCEditor
	'{6d960cb7-fb14-5ed4-95fd-4d157414ecdb}' # Microsoft.Windows.Desktop.Shell.OOBEMonitor
	'{5391f591-9ca5-5833-7c1d-ad0ddec652cd}' # Microsoft.Windows.Desktop.Shell.MachineOOBE
	'{2cfa8474-fc39-51c6-c0ac-f08e5da70d91}' # Microsoft.Windows.Shell.Desktop.FirstLogonAnim
	'{451ceb17-c9c0-596d-78a3-df866a3867fb}' # Microsoft.Windows.Desktop.DesktopShellHostExtensions
	'{b93d4107-dc22-5d11-c2e1-afba7a88d694}' # Microsoft.Windows.Shell.Tracing.LockAppBroker
	'{e58f5f9c-3abb-5fc1-5ae5-dbe956bdbd33}' # Microsoft.Windows.Shell.AboveLockShellComponent
	'{1915117c-a61c-54d4-6548-56cac6dbfede}' # Microsoft.Windows.Shell.AboveLockActivationManager
	'{b82b78d7-831a-4747-bce9-ccc6d109ecf3}' # Microsoft.Windows.Shell.Prerelease
	'{2de4263a-8b3d-5824-1c83-6182d50c5356}' # Microsoft.Windows.Shell.Desktop.LogonAnaheimPromotion
	'{F1C13488-91AC-4350-94DE-5F060589C584}' # Microsoft.Windows.Shell.LockScreenBoost
	'{a51097ad-c000-5ea3-bbd4-863addaedd23}' # Microsoft.Windows.Desktop.Shell.ImmersiveIcons
	'{ffe467f7-4f51-4061-82be-c2ed8946a961}' # Microsoft.Windows.Shell.CoCreateInstanceAsSystem
	'{8A5010B1-0DCD-5AA6-5390-B288A15AC820}' # Microsoft-Windows-LockScreen-MediaTransportControlsUI
	'{C0B1CBF9-F523-51C9-15B0-02351517DAF8}' # Microsoft-Windows-Explorer-MediaTransportControlsUI
	'{1EE8CA37-11AE-4815-800E-58D6BAE1FEF9}' # Microsoft.Windows.Shell.SystemSettings.SettingsPane
	'{1ABBDEEA-0CF0-46B1-8EC2-DAAD6F165F8F}' # Microsoft.Windows.Shell.SystemSettings.HotKeyActivation
	'{7e8b48e9-dfa1-5073-f3f2-6251909a4d9d}' # Microsoft.Windows.BackupAndRoaming.Restore
	'{58b09b7d-fd44-5a27-101d-5d2472a7bb42}' # Microsoft.Windows.Shell.PrivacyConsentLogging
	'{04d28e21-00aa-5228-cfd0-d70863aa5ce9}' # Microsoft.Windows.Shell.Desktop.LogonFramework
	'{24fd15bb-a367-42b2-9210-e39c6467bf3a}' # Microsoft.Windows.Shell.Homegroup
	'{1d6a5020-c697-53bf-0f85-ae99be728db3}' # Microsoft.Windows.Shell.Display
	'{6b2cb30d-2176-5de5-c0f5-65aedfbb1b1f}' # Microsoft-Windows-Desktop-Shell-Personalization
	'{15584c9b-7d86-5fe0-a123-4a0f438a82c0}' # Microsoft.Windows.Shell.ServiceProvider
	'{354F4275-62B7-51B3-44C3-A1CB50CA4BC5}' # Microsoft-Windows-WebServicesWizard-OPW
	'{9cd954e1-c547-52c4-50c7-1a3f5df69321}' # Microsoft.Windows.Shell.SystemTray
	'{9d9f8d9d-81f1-4173-a667-4c54a4831dba}' # Microsoft.Windows.Shell.NetPlWiz
	'{397fe846-4109-5a9b-f2eb-c1d3b72630fd}' # Microsoft.Windows.Desktop.TextInput.InputSwitch
	'{feabe86d-d7a7-5e6d-9665-92819bc73768}' # Microsoft.Windows.Desktop.Shell.TimeDateOptions
	'{9493aaa3-34b7-5b53-daf1-cb9b80c7e772}' # Microsoft.Windows.Shell.DesktopUvc
	'{69219098-3c47-5f65-4b95-2e2ae89c07fc}' # WindowsInternal.Shell.Start.TraceLoggingProvider
	'{f0c781fb-3451-566e-121c-9020159a5306}' # Microsoft.Windows.SharedPC.AccountManager
	'{e49b2c1a-1ad0-505c-a11a-73dba0c60f50}' # Microsoft.Windows.Shell.Theme
	'{2c00a440-76de-4fe3-856f-00557535be83}' # Microsoft.Windows.Shell.ControlCenter
	'{462B9C75-E5D7-4E0D-8AA1-294D175566BB}' # Microsoft-Windows-Shell-ActionCenter
	'{f401924c-6fb0-5abb-be79-b010fb9ba7d4}' # Microsoft.Windows.Shell.FilePicker
	'{d173c6af-d86c-5327-17b8-5dcc03543da5}' # Microsoft.Windows.Mobile.Shell.FileExplorer
	'{813552F2-2082-4873-8E75-2DE43AA7B725}' # Microsoft.Windows.Mobile.Shell.Share
	'{08f5d47e-67d3-4ee0-8e0c-cbd309ab5d1b}' # Microsoft.Windows.Shell.CloudFiles
	'{c45c91e9-3750-5f9d-63c2-ec9d4991fcda}' # Microsoft.Windows.Shell.CloudStore.Internal
	# CLDAPI.DLL
	'{62e03996-3f13-473b-ba8c-9a507277abf8}' # Microsoft-OneCore-SyncEngine-Service
	'{6FDFA2FD-23C7-5152-1A51-618729D0E93D}' # Microsoft.Windows.FileSystem.CloudFiles
	# OneDriveSettingSyncProvider.dll
	'{F43C3C35-22E2-53EB-F169-07594054779E}' # Microsoft-Windows-SettingSync-OneDrive
	'{22111816-32de-5f2f-7260-2e7c4a7899ce}' # Microsoft.Windows.Shell.Personalization.CSP
)

$PRF_ShutdownProviders = @(
	'{206f6dea-d3c5-4d10-bc72-989f03c8b84b}' # WinInit
	'{e8316a2d-0d94-4f52-85dd-1e15b66c5891}' # CsrEventProvider
	'{9D55B53D-449B-4824-A637-24F9D69AA02F}' # WinsrvControlGuid
	'{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}' # Microsoft-Windows-Winlogon 
	'{e8316a2d-0d94-4f52-85dd-1e15b66c5891}' # Microsoft-Windows-Subsys-Csr
	'{331c3b3a-2005-44c2-ac5e-77220c37d6b4}' # Microsoft-Windows-Kernel-Power
	'{23b76a75-ce4f-56ef-f903-c3a2d6ae3f6b}' # Microsoft.Windows.Kernel.BootEnvironment
	'{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}' # Microsoft-Windows-Kernel-General
	'{15ca44ff-4d7a-4baa-bba5-0998955e531e}' # Microsoft-Windows-Kernel-Boot
)

$PRF_SpeechProviders = @(
	'{7f02214a-4eb1-50e4-adff-62654d1e42f6}'  # NLClientPlatformAPI
	'{a9da5902-9012-4f82-bdc8-905c88db93ee}'  # Bing-Platform-ConversationalUnderstanding-Client
	'{8eb79eb6-8701-4d39-9196-9efc81a31489}'  # Microsoft-Speech-SAPI
	'{46f27ed9-a8d6-5c0c-8c30-6e846b4c4e46}'  # Windows.ApplicationModel.VoiceCommands.VoiceCommandServiceConnection
	'{70400dee-6c5b-5209-4052-b9f8cf41b7d7}'  # Microsoft.Windows.ReactiveAgentFramework
	'{5656A338-AC25-4E57-93DC-4703091CB85A}'  # Microsoft-Windows-NUI-Audio
	'{E5514D5F-A8E4-4658-B381-63227E390476}'  # Microsoft-WindowsPhone-Speech-Ux
	'{614f2573-da68-5a1b-c2c6-cba6de5de7f8}'  # Microsoft.Windows.Media.Speech.Internal.SoundController.WinRT
	'{E6C38788-C835-4D10-B26E-5920C34E5F20}'  # Microsoft-Speech-WinRT
	'{07f283ce-2538-5e77-44d2-04212575a63d}'  # Microsoft.Windows.Analog.Speech.RecognizerClient
	'{2a8bc2a0-4cf9-5429-c90c-f5cd30dc6dd1}'  # Microsoft.Windows.Analog.Speech.RecognizerServer
)

$PRF_StartMenuProviders = @(
	'{a5934a92-d47c-55c9-7a3d-4f9acb7f44fe}' # Microsoft.Windows.Shell.StartMenu.Frame(Until RS2)
	'{d3e36643-28fd-5ccd-99b7-3b13c721ee51}' # Microsoft.Windows.Shell.StartMenu.Experience
	'{2ca51213-29c5-564f-fd60-355148e8b47f}' # Microsoft.Windows.Shell.SingleViewExperience
	'{53E167D9-E368-4150-9563-4ED25700CCC7}' # Microsoft.Windows.Shell.ExperienceHost
	'{66FEB609-F4B6-4224-BF13-121F8A4829B4}' # Microsoft.Windows.Start.SharedStartModel.Cache
	'{45D87330-FFEC-4A95-9F07-206A4452555D}' # Microsoft.Windows.Start.ImageQueueManager
	'{e7137ec0-0e64-4c48-a590-5b62661d3abc}' # Microsoft.Windows.ShellCore.SharedVerbProvider
	'{65cacb72-8567-457a-bc48-e16b67fb3e27}' # Microsoft.Windows.ShellCore.StartLayoutInitialization
	'{8d43f18f-af82-450a-bfb7-d6f1b53570ba}' # Microsoft.Windows.ShellCore.SharedModel
	'{36F1D421-D446-43AE-8AA7-A4F85CB176D3}' # Microsoft.Windows.UI.Shell.StartUI.WinRTHelpers
	'{9BB1A5A5-ABD6-4F8E-9507-12CC2B314896}' # Microsoft.Windows.Shell.TileDataLayerItemWrappers
	'{a331d81d-2f6f-50de-2461-a5530d0465d7}' # Microsoft.Windows.Shell.DataStoreCache
	'{6cfc5fc0-7e30-51e0-898b-57ac43152695}' # Microsoft.Windows.Shell.DataStoreTransformers
	'{2d069757-4018-5cf0-e4a2-bf70a1a0183c}' # Microsoft.Windows.Shell.MRTTransformer
	'{F2CDC8A0-AF2C-450F-9859-3251CCE0D234}' # WindowsInternal.Shell.UnifiedTile
	'{97CA8142-10B1-4BAA-9FBB-70A7D11231C3}' # Microsoft-Windows-ShellCommon-StartLayoutPopulation
	'{98CCAAD9-6464-48D7-9A66-C13718226668}' # Microsoft.Windows.AppModel.Tiles
	'{1a554939-2d19-5b10-ceda-ee4dd6910d59}' # Microsoft.Windows.ShellCommon.StartLayout
	'{8cba0f81-8ad7-5395-2125-5703822c822a}' # Microsoft.Windows.ContentDeliveryManager
	'{4690f625-1ceb-402e-acef-db8f00f3a446}' # Microsoft.Windows.Shell.TileControl
	'{c8416d9b-12d3-41f8-9a4c-c8d7033f4d30}' # Microsoft-Windows-Shell-Launcher-Curation
	'{c6ba71ae-658c-5a9b-94f5-b2026290198a}' # Microsoft.Windows.Desktop.Shell.QuickActions
	'{7B434BC1-8EFF-41A3-87E9-5D8AF3099784}' # Microsoft.Windows.Shell.KeyboardHosting.ShellKeyboardManager
	'{cbc427d6-f93e-5bcf-3137-d22fe2305d1f}' # Microsoft.Windows.Shell.ClockCalendar
	'{F84AA759-31D3-59BF-2C89-3748CF17FD7E}' # Microsoft-Windows-Desktop-Shell-Windowing
	'{BAA05370-7451-48D2-8F38-778380946CE9}' # Microsoft.Windows.SharedStartModel.NotificationQueueManager
	'{462B9C75-E5D7-4E0D-8AA1-294D175566BB}' # Microsoft-Windows-Shell-ActionCenter
	'{2c00a440-76de-4fe3-856f-00557535be83}' # Microsoft.Windows.Shell.ControlCenter
)

$PRF_StoreProviders = @(
	'{53e3d721-2aa0-4743-b2db-299d872b8e3d}' # Microsoft_Windows_Store_Client_UI
	'{945a8954-c147-4acd-923f-40c45405a658}' # Microsoft-Windows-WindowsUpdateClient
	'{9c2a37f3-e5fd-5cae-bcd1-43dafeee1ff0}' # Microsoft-Windows-Store
	'{5F0B026E-BCC1-5001-95D3-65E170A11EFA}' # Microsoft.Store
	'{6938F4E9-4F5F-54FE-EDFF-7D728ACECA12}' # Microsoft.Windows.Store.Partner
	'{9bfa0c89-0339-4bd1-b631-e8cd1d909c41}' # Microsoft.Windows.StoreAgent.Telemetry
	'{FF79A477-C45F-4A52-8AE0-2B324346D4E4}' # Windows-ApplicationModel-Store-SDK
	'{f4b9ce38-744d-4916-b645-f1574e19bbaa}' # Microsoft.Windows.PushToInstall
	'{DD2E708D-F725-5C93-D0D1-91C985457612}' # Microsoft.Windows.ApplicationModel.Store.Telemetry
	'{13020F14-3A73-4DB1-8BE0-679E16CE17C2}' # Microsoft.Windows.Store.LicenseManager.UsageAudit
	'{AF9F58EC-0C04-4BE9-9EB5-55FF6DBE72D7}' # Microsoft.Windows.LicenseManager.Telemetry
	'{4DE9BC9C-B27A-43C9-8994-0915F1A5E24F}' # Microsoft.Windows.AAD
	'{84C5F702-EB27-41CB-AED2-64AA9850C3D0}' # CryptNgcCtlGuid(Until RS4)
	'{B66B577F-AE49-5CCF-D2D7-8EB96BFD440C}' # Microsoft.Windows.Security.NGC.KspSvc
	'{CAC8D861-7B16-5B6B-5FC0-85014776BDAC}' # Microsoft.Windows.Security.NGC.CredProv
	'{6D7051A0-9C83-5E52-CF8F-0ECAF5D5F6FD}' # Microsoft.Windows.Security.NGC.CryptNgc
	'{0ABA6892-455B-551D-7DA8-3A8F85225E1A}' # Microsoft.Windows.Security.NGC.NgcCtnr
	'{9DF6A82D-5174-5EBF-842A-39947C48BF2A}' # Microsoft.Windows.Security.NGC.NgcCtnrSvc
	'{9B223F67-67A1-5B53-9126-4593FE81DF25}' # Microsoft.Windows.Security.NGC.KeyStaging
	'{89F392FF-EE7C-56A3-3F61-2D5B31A36935}' # Microsoft.Windows.Security.NGC.CSP
	'{CDD94AC7-CD2F-5189-E126-2DEB1B2FACBF}' # Microsoft.Windows.Security.NGC.LocalAccountMigPlugin
	'{2056054C-97A6-5AE4-B181-38BC6B58007E}' # Microsoft.Windows.Security.NGC.NgcIsoCtnr
	'{786396CD-2FF3-53D3-D1CA-43E41D9FB73B}' # Microsoft.Windows.Security.CryptoWinRT
	'{9D4CA978-8A14-545E-C047-A45991F0E92F}' # Microsoft.Windows.Security.NGC.Recovery
	'{507C53AE-AF42-5938-AEDE-4A9D908640ED}' # Microsoft.Windows.Security.Credentials.UserConsentVerifier
	'{CDC6BEB9-6D78-5138-D232-D951916AB98F}' # Microsoft.Windows.Security.NGC.NgcIsoCtnr
	'{C0B2937D-E634-56A2-1451-7D678AA3BC53}' # Microsoft.Windows.Security.Ngc.Truslet
	'{34646397-1635-5d14-4d2c-2febdcccf5e9}' # Microsoft.Windows.Security.NGC.KeyCredMgr
	'{3b9dbf69-e9f0-5389-d054-a94bc30e33f7}' # Microsoft.Windows.Security.NGC.Local
	'{1D6540CE-A81B-4E74-AD35-EEF8463F97F5}' # CryptNgcCtlGuid(WPP -> Until RS4)
	'{3A8D6942-B034-48e2-B314-F69C2B4655A3}' # TpmCtlGuid(WPP)
	'{D5A5B540-C580-4DEE-8BB4-185E34AA00C5}' # Microsoft.Windows.DeviceManagement.SCEP
	'{7955d36a-450b-5e2a-a079-95876bca450a}' # Microsoft.Windows.Security.DevCredProv
	'{c3feb5bf-1a8d-53f3-aaa8-44496392bf69}' # Microsoft.Windows.Security.DevCredSvc
	'{78983c7d-917f-58da-e8d4-f393decf4ec0}' # Microsoft.Windows.Security.DevCredClient
	'{36FF4C84-82A2-4B23-8BA5-A25CBDFF3410}' # Microsoft.Windows.Security.DevCredWinRt
	'{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}' # Microsoft-Windows-CAPI2
	'{73370BD6-85E5-430B-B60A-FEA1285808A7}' # Microsoft-Windows-CertificateServicesClient
	'{F0DB7EF8-B6F3-4005-9937-FEB77B9E1B43}' # Microsoft-Windows-CertificateServicesClient-AutoEnrollment
	'{54164045-7C50-4905-963F-E5BC1EEF0CCA}' # Microsoft-Windows-CertificateServicesClient-CertEnroll
	'{89A2278B-C662-4AFF-A06C-46AD3F220BCA}' # Microsoft-Windows-CertificateServicesClient-CredentialRoaming
	'{BC0669E1-A10D-4A78-834E-1CA3C806C93B}' # Microsoft-Windows-CertificateServicesClient-Lifecycle-System
	'{BEA18B89-126F-4155-9EE4-D36038B02680}' # Microsoft-Windows-CertificateServicesClient-Lifecycle-User
	'{B2D1F576-2E85-4489-B504-1861C40544B3}' # Microsoft-Windows-CertificateServices-Deployment
	'{98BF1CD3-583E-4926-95EE-A61BF3F46470}' # Microsoft-Windows-CertificationAuthorityClient-CertCli
	'{AF9CC194-E9A8-42BD-B0D1-834E9CFAB799}' # Microsoft-Windows-CertPolEng
	'{d0034f5e-3686-5a74-dc48-5a22dd4f3d5b}' # Microsoft-Windows-Shell-CloudExperienceHost
	'{aa02d1a4-72d8-5f50-d425-7402ea09253a}' # Microsoft.Windows.Shell.CloudDomainJoin.Client
	'{9FBF7B95-0697-4935-ADA2-887BE9DF12BC}' # Microsoft-Windows-DM-Enrollment-Provider
	'{3DA494E4-0FE2-415C-B895-FB5265C5C83B}' # Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider
	'{8db3086d-116f-5bed-cfd5-9afda80d28ea}' # Microsoft-OSG-OSS-CredProvFramework
	'{7D44233D-3055-4B9C-BA64-0D47CA40A232}' # Microsoft-Windows-WinHttp
)

#--- Superfetch (sysmain) Providers ---#
$PRF_SysmainProviders = @(
	'{A319D300-015C-48BE-ACDB-47746E154751}' # Microsoft-Windows-FileInfoMinifilter
	'{99806515-9F51-4C2F-B918-1EAE407AA8CB}' # Microsoft-Windows-Superfetch
	'{4D5A5784-B063-4C87-8DEF-DBF683902CE3}' # SuperFetch
	'{164B9D03-A84D-4C1F-9941-715E07E2C6C9}' # SUMAPIGuid
	'{DE441FFA-FAFA-4495-977F-2E9D2509746D}' # PfTlgSysmainProvRegHandle
	'{2A3C1DCD-DDCB-41DE-BE16-E72DF40EE8DD}' # Microsoft.Windows.PrelaunchOptIn
	'{E6307A09-292C-497E-AAD6-498F68E2B619}' # Microsoft-Windows-ReadyBoost
	'{2A274310-42D5-4019-B816-E4B8C7ABE95C}' # Microsoft-Windows-ReadyBoostDriver
	'{648A0644-7D62-4FD3-8841-440064762F95}' # Microsoft-Windows-BackgroundTransfer-ContentPrefetcher
)

$PRF_SystemSettingsProviders = @(
	'{c1be8ae8-b6b1-566a-8453-ec627f8eb2de}' # Microsoft.Windows.Shell.MockDataSystemSettings
	'{B7AFA6AF-AAAB-4F50-B7DC-B61D4DDBE34F}' # Microsoft.Windows.Shell.SystemSettings.SettingsAppActivity
	'{8BCDF442-3070-4118-8C94-E8843BE363B3}' # Microsoft-Windows-SystemSettingsThreshold
	'{1EE8CA37-11AE-4815-800E-58D6BAE1FEF9}' # Microsoft.Windows.Shell.SystemSettings.SettingsPane
	'{1ABBDEEA-0CF0-46B1-8EC2-DAAD6F165F8F}' # Microsoft.Windows.Shell.SystemSettings.HotKeyActivation
	'{80B3FF7A-BAB0-4ED1-958C-E89A6D5557B3}' # Microsoft.Windows.Shell.SystemSettings.WorkAccessHandlers
	'{68D9DE11-9358-4C97-8B72-A7CE49EF593C}' # Wi-Fi Calling Logging
	'{0ae9ad8e-d4d3-5486-f015-498e0b6860ef}' # Microsoft.Windows.Shell.SystemSettings.UserPage
	'{44f1a90c-4250-5bab-f09b-df45384c6951}' # Microsoft.Windows.Shell.SystemSettings.RegionSettings
	'{6bee332c-7ddb-5ec2-dec4-91b8be7612f8}' # Microsoft.Windows.Shell.PersonalizeSettingsTelemetry
	'{f323b60d-51ff-5c64-f7d1-f8149e2b3d81}' # Microsoft.Windows.Shell.SystemSettings.Pen
	'{6b2dfe1c-ae63-55d0-edea-60c166860d63}' # Microsoft.Windows.Shell.SystemSettings.OtherPeoplePage
	'{e613a5d7-363e-5200-b311-02b426d8a73b}' # Microsoft.Windows.Desktop.Shell.LanguageFeaturesOnDemandSettings
	'{c442c41d-98c0-4a33-845d-902ed64f695b}' # Microsoft.Windows.TextInput.ImeSettings
	'{9a35425e-61bc-4d68-8542-568a28963abe}' # Microsoft.Windows.Shell.SystemSettings.AdvancedGraphics
	'{ec696ee4-fac7-4df4-9aaa-3862cb16eb4b}' # Microsoft.Windows.Shell.SystemSettings.FontPreview
	'{23cd8d50-ed49-5a0b-4562-65dff962d5f1}' # Microsoft.Windows.Mobile.Shell.DisplaySettings
	'{55f422c8-0aa0-529d-95f5-8e69b6a29c98}' # Microsoft.Windows.Shell.SystemSettings.SignInOptionsPage
	'{e3bfeaae-cb1d-5f12-e2e5-b9d2d7ca7bf0}' # Microsoft.Windows.Shell.SystemSettings.Devices
	'{17d6a222-af97-560b-6f18-389900d6ad1e}' # Microsoft.Windows.Desktop.Shell.LanguagePackInstallSettings
	'{8b5a39e9-7fc8-5ccb-18c9-d410973436a9}' # Microsoft.Windows.Shell.TabShell
	'{56143DD6-AD65-4FB1-972C-6DFA2BEF0916}' # Microsoft.Windows.Shell.SystemSettings.BluetoothHandler
	'{6cd9d548-4f28-5e7c-503d-86e3cd9db63d}' # Microsoft.Windows.DeveloperPlatform.DeveloperOptions
	'{4b82b48e-8625-5aba-2a86-b5266e869e10}' # Microsoft.Windows.Shell.SystemSettings.KeyboardSettings
	'{fc27cce8-72b0-5a6f-8fe3-22bfcfefd495}' # Microsoft.Windows.Shell.SystemSettings.MediaRadioManagerSink
	'{35a6b23c-c542-5414-bc49-b0f81b96a266}' # Microsoft.Windows.Shell.SystemSettings.OneDriveBackup
	'{e2a3ad70-42b5-452c-a113-20476e27e37c}' # Microsoft.Windows.Desktop.Shell.SystemSettingsThreshold.Handlers
	'{3A245D5A-F00F-48F6-A94B-C51CDD290F18}' # Microsoft-Windows-Desktop-Shell-SystemSettingsV2-Handlers
	'{068b0237-1f0a-593a-bc39-5155685f1bef}' # Microsoft.PPI.Settings.AdminFlow
	'{57d940ae-e2fc-55c3-f31b-253c5b172135}' # Microsoft.Windows.Shell.SystemSettings.ManageUser
	'{e6fcf13b-1ab7-4236-823b-0c0cf5c589d5}' # Microsoft.Windows.Upgrade.Uninstall
	'{e881df47-b77c-48c5-b321-1454b88fdd6b}' # Microsoft.Windows.Shell.SystemSettings.ManageOrganization
	'{2e07964e-7d10-5d8e-761d-99b038f42bb6}' # Microsoft.Windows.Shell.SystemSettings.AdminFlow
	'{e881df47-b77c-48c5-b321-1454b88fdd6b}' # Microsoft.Windows.Shell.SystemSettings.ManageOrganization
	'{3e8fb07b-3e10-5981-01a9-fbd924fd5436}' # Microsoft.Windows.Shell.AssignedAccessSettings
	'{a306fcf9-ad27-5c4d-f69a-22506ef908ad}' # Microsoft.Windows.Shell.SystemSettings.RemoteDesktopAdminFlow
)

$PRF_XAMLProviders = @(
	'{59E7A714-73A4-4147-B47E-0957048C75C4}' # Microsoft-Windows-XAML-Diagnostics
	'{922CDCF3-6123-42DA-A877-1A24F23E39C5}' # Microsoft-WindowsPhone-CoreMessaging
	'{A0B7550F-4E9A-4F03-AD41-B8042D06A2F7}' # Microsoft-WindowsPhone-CoreUIComponents
	'{DB6F6DDB-AC77-4E88-8253-819DF9BBF140}' # Microsoft-Windows-Direct3D11
	'{C44219D0-F344-11DF-A5E2-B307DFD72085}' # Microsoft-Windows-DirectComposition
	'{5786E035-EF2D-4178-84F2-5A6BBEDBB947}' # Microsoft-Windows-DirectManipulation
	'{8360BD0F-A7DC-4391-91A7-A457C5C381E4}' # Microsoft-Windows-DUI
	'{8429E243-345B-47C1-8A91-2C94CAF0DAAB}' # Microsoft-Windows-DUSER
	'{292A52C4-FA27-4461-B526-54A46430BD54}' # Microsoft-Windows-Dwm-Api
	'{CA11C036-0102-4A2D-A6AD-F03CFED5D3C9}' # Microsoft-Windows-DXGI
	'{950D4EDA-1729-47CC-8F1E-D9ED5AA17642}' # Windows.Ui.Xaml
	'{531A35AB-63CE-4BCF-AA98-F88C7A89E455}' # Microsoft-Windows-XAML
)

$PRF_SCMProviders = @(
	'{0063715b-eeda-4007-9429-ad526f62696e}' # Microsoft-Windows-Services
	'{06184c97-5201-480e-92af-3a3626c5b140}' # Microsoft-Windows-Services-Svchost
	'{555908D1-A6D7-4695-8E1E-26931D2012F4}' # Service Control Manager
	'{b8ddcea7-b520-4909-bceb-e0170c9f0e99}' # ScmTraceLoggingGuid
	'{EBCCA1C2-AB46-4A1D-8C2A-906C2FF25F39}' # ScmWppLoggingGuid
	'{06184c97-5201-480e-92af-3a3626c5b140}' # Microsoft.Windows.SvchostTelemetryProvider
)

#endregion --- ETW component trace Providers ---

#------------------------------------------------------------
#region --- Scenario definitions ---
#------------------------------------------------------------

#--- Boot Scenario ---#
## Usage: TSSv2.ps1 -StartAutoLogger -Scenario PRF_BOOT
$PRF_Boot_ETWTracingSwitchesStatus = [Ordered]@{
	'ADS_LSA' = $true
	'ADS_CredprovAuthui' = $true
	'UEX_Logon' = $true
	'UEX_Shell' = $true
	'PRF_SCM' = $true
	'WPR General' = $true
}

$PRF_Clipboard_ETWTracingSwitchesStatus = [Ordered]@{
	'PRF_Clipboard' = $True
	'UEX_Win32k' = $True
	'PRF_Shell' = $True
	'WPR General' = $true
	'Procmon' = $true
	'PSR' = $true
}

$PRF_Cortana_ETWTracingSwitchesStatus = [Ordered]@{
	'PRF_AppX' = $True
	'PRF_Cortana' = $True
	'PRF_Shell' = $True
	'UEX_COM' = $True
	'UEX_Search' = $True
	'WPR General' = $true
	'Procmon' = $true
	'PSR' = $true
}

$PRF_General_ETWTracingSwitchesStatus = [Ordered]@{
	#'NET_Dummy' = $true
	'CommonTask NET' = $True  ## <------ the commontask can take one of "Dev", "NET", "ADS", "UEX", "DnD" and "SHA", or "Full" or "Mini"
	'NetshScenario InternetClient_dbg' = $true
	'Procmon' = $true
	'WPR General' = $true
	'PerfMon ALL' = $true
	'PSR' = $true
	'Video' = $true
	'SDP Perf' = $True
	'xray' = $True
	'CollectComponentLog' = $True
}

$PRF_Perflib_ETWTracingSwitchesStatus = [Ordered]@{
	'UEX_WMI' = $true
	'UEX_COM' = $true
	'PRF_Perflib' = $true
	'Procmon' = $true
	'WPR General' = $true
}

$PRF_Photo_ETWTracingSwitchesStatus = [Ordered]@{
	'PRF_AppX' = $True
	'PRF_Photo' = $True
	'PRF_Shell' = $True
	'UEX_COM' = $True
	'WPR General' = $true
	'Procmon' = $true
	'PSR' = $true
}

$PRF_StartMenu_ETWTracingSwitchesStatus = [Ordered]@{
	'PRF_AppX' = $True
	'PRF_StartMenu' = $True
	'UEX_COM' = $True
	'PRF_Shell' = $True
	'WPR General' = $true
	'Procmon' = $true
	'PSR' = $true
}

$PRF_Store_ETWTracingSwitchesStatus = [Ordered]@{
	'PRF_AppX' = $True
	'PRF_Store' = $True
	'UEX_COM' = $True
	'PRF_Shell' = $True
	'WPR General' = $true
	'Procmon' = $true
	'PSR' = $true
}

$PRF_UWP_ETWTracingSwitchesStatus = [Ordered]@{
	'PRF_AppX' = $True
	'UEX_COM' = $True
	'PRF_Shell' = $True
	'WPR General' = $true
	'Procmon' = $true
	'PSR' = $true
}
#endregion --- Scenario definitions ---

#------------------------------------------------------------
#region ### Pre-Start / Post-Stop / Collect functions for trace components and scenarios 
#------------------------------------------------------------

Function CollectPRF_AppXLog{
	EnterFunc $MyInvocation.MyCommand.Name
	$AppXLogFolder = "$global:LogFolder\AppXLog$LogSuffix"
	FwCreateLogFolder $AppXLogFolder

	LogInfo ("[AppX] Running Get-AppxPackage")
	ForEach ($p in $(Get-AppxPackage)){ 
		ForEach ($n in ($p).Dependencies.PackageFullName){ 
			$p.packagefullname + '--' + $n | Out-File -Append "$AppXLogFolder\appxpackage_output.txt"
		}
	}

	If(FwIsElevated){
		LogInfo ("[AppX] Running Get-AppxPackage -allusers")
		Try{
			ForEach ($p in $(Get-AppxPackage -AllUsers)){
				ForEach ($n in ($p).PackageUserInformation){
					$p.packagefullname + ' -- ' + $n.UserSecurityId.Sid + ' [' + $n.UserSecurityId.UserName + '] : ' + $n.InstallState | Out-File -Append "$AppXLogFolder/Get-Appxpackage-installeduser.txt"
				}
			}
		}Catch{
			LogException  ("An error happened in Get-AppxPackage.") $_ $fLogFileOnly
		}
		Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-File (Join-Path $AppXLogFolder 'Get-AppxProvisionedPackage-online.txt')
	}

	LogInfo ("[AppX] Exporting event logs.")
	FwExportEventLog $global:EvtLogsAppX $AppXLogFolder

	LogInfo ("[AppX] Exporting registries.")
	$AppxRegistries = @(
		("HKCU:Software\Classes\Extensions\ContractId\Windows.Launch", "$AppXLogFolder\reg_HKCU-WindowsLaunch.txt"),
		("HKLM:Software\Microsoft\Windows\CurrentVersion\Policies", "$AppXLogFolder\reg_HKLM-Policies.txt"),
		("HKLM:Software\Microsoft\Windows\CurrentVersion\Policies", "$AppXLogFolder\reg_HKLM-Policies.txt"),
		("HKLM:Software\Policies\Microsoft\Windows\AppX", "$AppXLogFolder\reg_HKLM-AppXPolicy.txt"),
		("HKLM:Software\Microsoft\Windows\CurrentVersion\SystemProtectedUserData" , "$AppXLogFolder\reg_HKLM-SystemProtectedUserData.txt"),
		("HKEY_CLASSES_ROOT:Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel", "$AppXLogFolder\reg_HKCR-AppModel.txt")
	)
	FwExportRegistry "AppX" $AppxRegistries

	# Size of these keys are large so use reg export to shorten export time.
	$Commands = @(
		"Get-ChildItem `"c:\program files\windowsapps`" -Recurse -ErrorAction Stop | Out-File $AppXLogFolder\dir-windowsapps.txt",
		"Get-ChildItem `"c:\Windows\SystemApps`" -Recurse -ErrorAction Stop | Out-File -Append $AppXLogFolder\dir-systemapps.txt",
		"Get-Appxpackage -ErrorAction Stop | Out-File $AppXLogFolder\Get-Appxpackage.txt"
		"Get-AppxPackage -alluser -ErrorAction Stop | Out-File $AppXLogFolder\Get-AppxPackage-alluser.txt",
		"New-Item $AppXLogFolder\Panther -ItemType Directory -ErrorAction Stop | Out-Null",
		"Copy-Item C:\Windows\Panther\*.log $AppXLogFolder\Panther -ErrorAction SilentlyContinue | Out-Null",
		"Copy-Item $env:ProgramData\Microsoft\Windows\AppXProvisioning.xml $AppXLogFolder -ErrorAction SilentlyContinue | Out-Null",
		"whoami /user /fo list | Out-File $AppXLogFolder\userinfo.txt",
		"New-Item $AppXLogFolder\ARCache -ItemType Directory -ErrorAction Stop | Out-Null",
		"Copy-Item $env:userprofile\AppData\Local\Microsoft\Windows\Caches\* $AppXLogFolder\ARCache",
		"REG EXPORT HKLM\Software\Microsoft\windows\currentversion\appx $AppXLogFolder\reg_HKLM-appx.txt | Out-Null",
		"REG EXPORT HKLM\System\SetUp\Upgrade\AppX $AppXLogFolder\reg_HKLM-AppXUpgrade.txt | Out-Null",
		"REG EXPORT HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository $AppXLogFolder\reg_HKLM-StateRepository.txt | Out-Null",
		"REG EXPORT `"HKLM\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel`" $AppXLogFolder\reg_LM-Classes-AppModel.txt | Out-Null",
		"REG EXPORT `"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel`" $AppXLogFolder\reg_HKCU-Classes-AppModel.txt | Out-Null",
		"REG SAVE `"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer`" $AppXLogFolder\reg_HKCU-AppContainer.hiv | Out-Null",
		"REG EXPORT HKLM\Software\Microsoft\Windows\CurrentVersion\AppModel $AppXLogFolder\reg_HKLM-AppModel.txt",
		"REG EXPORT HKCU\Software\Microsoft\Windows\CurrentVersion\AppModel $AppXLogFolder\reg_HKCU-AppModel.txt",
		"tree $env:USERPROFILE\AppData\Local\Microsoft\Windows\Shell /f | Out-File $AppXLogFolder\tree_UserProfile_Shell.txt",
		"tree $env:USERPROFILE\AppData\Local\Packages /f | Out-File $AppXLogFolder\tree_UserProfile_Packages.txt",
		"tree `"C:\Program Files\WindowsApps`" /f | Out-File $AppXLogFolder\tree_ProgramFiles_WindowsApps.txt",
		"ls `"C:\Program Files\WindowsApps`" -Recurse -ErrorAction SilentlyContinue | Out-File $AppXLogFolder\dir_ProgramFiles_WindowsApps.txt",
		"tree `"C:\Users\Default\AppData\Local\Microsoft\Windows\Shell`" /f | Out-File $AppXLogFolder\tree_Default_Shell.txt"
	)
	RunCommands "AppX" $Commands -ThrowException:$False -ShowMessage:$True
	EndFunc $MyInvocation.MyCommand.Name
}

#--- Boot Scenario---#
function PRF_BootScenarioPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	<#
	# Parameter check
	If(!($ParameterArray -contains 'StartAutoLogger')){
		LogDebug "ParameterArray: $ParameterArray"
		LogInfo "Boot Scenario must be called with ""StartAutoLogger"" switch"
		CleanUpandExit
	}   
	#>
	# Netlogon logging
	nltest /dbflag:0x2EFFFFFF 2>&1 | Out-Null

	# Enabling Group Policy Loggging
	mkdir "$($env:windir)\debug\usermode" 2>&1 | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" /f 2>&1 | Out-Null
	reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics" /v GPSvcDebugLevel /t REG_DWORD /d 0x30002 /f 2>&1 | Out-Null

	# Create additional ETW trace (OnOff Collector) for WPR
	logman create trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -ow -o "$global:LogFolder\WPR_initiated_WprApp_boottr_WPR OnOff Collector.etl" -p "{0063715b-eeda-4007-9429-ad526f62696e}" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets # Microsoft-Windows-Services
	logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{06184c97-5201-480e-92af-3a3626c5b140}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-Services-Svchost
	logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{15ca44ff-4d7a-4baa-bba5-0998955e531e}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-Kernel-Boot
	logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{2a274310-42d5-4019-b816-e4b8c7abe95c}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-ReadyBoostDriver
	logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{43e63da5-41d1-4fbf-aded-1bbed98fdd1d}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-Subsys-SMSS
	logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-CodeIntegrity
	logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{5322d61a-9efa-4bc3-a3f9-14be95c144f8}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-Kernel-Prefetch
	logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{63d2bb1d-e39a-41b8-9a3d-52dd06677588}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-Shell-AuthUI
	logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-Kernel-General
	logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{aea1b4fa-97d1-45f2-a64c-4d69fffd92c9}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-GroupPolicy
	logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{b675ec37-bdb6-4648-bc92-f3fdc74d3ca2}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-Kernel-EventTracing
	logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-Winlogon
	logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{de7b24ea-73c8-4a09-985d-5bdadcfa9017}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-TaskScheduler
	logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{e6307a09-292c-497e-aad6-498f68e2b619}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-ReadyBoost
	logman update trace "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -p "{9C205A39-1250-487D-ABD7-E831C6290539}" 0xffffffffffffffff 0xff -ets # Microsoft-Windows-Kernel-PnP

	# Override output folder path
	reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WPR_initiated_WprApp_boottr_WPR OnOff Collector" /v FileName /t REG_SZ /d "$global:LogFolder\WPR_initiated_WprApp_boottr_WPR OnOff Collector.etl" /f

	EndFunc $MyInvocation.MyCommand.Name
}
function PRF_BootScenarioPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."

	# Disable Group Policy Logging
	reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Diagnostics" /v GPSvcDebugLevel /f 2>&1 | Out-Null
	Copy-Item -Recurse "$env:windir\debug\UserMode" $global:LogFolder

	# Disable Netlogon trace
	nltest /dbflag:0x0 2>&1 | Out-Null
	Copy-Item "$env:windir\debug\netlogon*" $global:LogFolder

	# Stop Additional ETW trace for WPR
	logman stop "WPR_initiated_WprApp_boottr_WPR OnOff Collector" -ets 2>&1 | Out-Null
	logman delete "autosession\WPR_initiated_WprApp_boottr_WPR OnOff Collector" -ets 2>&1 | Out-Null

	
	# Wait for starting wpr.exe -stop command. 
	Start-Sleep 5
	
	# Merge etl files and delete original files
	$OriginalWPRLogFile = "$global:LogFolder\WPR-boottrace$LogSuffix.etl"
	$AdditionalETWLogFile = "$global:LogFolder\WPR_initiated_WprApp_boottr_WPR OnOff Collector.etl"
	$MergedLogFile = "$global:LogFolder\WPR-boottrace$LogSuffix-merged.etl"

	LogInfo ('[Boot] Waiting for wpr to complete')
	Wait-Process -Name "wpr" | Out-Null

	LogInfo ('[Boot] Merging wpr files')
	xperf -merge "$OriginalWPRLogFile" "$AdditionalETWLogFile" "$MergedLogFile"
	if(Test-Path "$MergedLogFile"){
		Remove-Item "$OriginalWPRLogFile" -Force
		Remove-item "$AdditionalETWLogFile" -Force
	}

	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectPRF_CortanaLog{
	EnterFunc $MyInvocation.MyCommand.Name
	$LogPrefix = 'Cortana'
	$ComponentLogFolder = "$global:LogFolder\$LogPrefix"+ "Log" + $LogSuffix
	FwCreateLogFolder $ComponentLogFolder

	$CortanaRegistries = @(
		("HKLM:SOFTWARE\Policies\Microsoft\Windows\Windows Search" ,"$ComponentLogFolder\CortanaPolicy_Reg.txt"),
		("HKLM:SOFTWARE\Microsoft\Windows Search", "$ComponentLogFolder\HKLM-Cortana_Reg.txt"),
		("HKCU:Software\Microsoft\Windows\CurrentVersion\Search", "$ComponentLogFolder\HKCU-Cortana_Reg.txt")
	)
	FwExportRegistry $LogPrefix $CortanaRegistries
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectPRF_FontLog{
	EnterFunc $MyInvocation.MyCommand.Name
	$FontLogFolder = "$global:LogFolder\FontLog$LogSuffix"
	FwCreateLogFolder $FontLogFolder
	LogInfo ("[Font] Exporting registries.")
	reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Font Management" /s | Out-File "$FontLogFolder\reg_HKCU_FontManagement.txt"
	reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Fonts" /s | Out-File "$FontLogFolder\reg_HKCU_Fonts.txt"

	reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers" /s | Out-File "$FontLogFolder\reg_HKLM_FontDrivers.txt"
	reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Management" /s | Out-File "$FontLogFolder\reg_HKLM_FontManagement.txt"
	reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontDPI" /s | Out-File "$FontLogFolder\reg_HKLM_FontDPI.txt"
	reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontIntensityCorrection" /s | Out-File "$FontLogFolder\reg_HKLM_FontIntensityCorrection.txt"
	reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontLink" /s | Out-File "$FontLogFolder\reg_HKLM_FontLink.txt"
	reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontMapper" /s | Out-File "$FontLogFolder\reg_HKLM_FontMapper.txt"
	reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontMapperFamilyFallback" /s | Out-File "$FontLogFolder\reg_HKLM_FontMapperFamilyFallback.txt"
	reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /s | Out-File "$FontLogFolder\reg_HKLM_Fonts.txt"
	reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes" /s | Out-File "$FontLogFolder\reg_HKLM_FontSubstitetes.txt"
}

Function PRF_IMEPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		FwSetEventLog $global:EvtLogsIME
	}Catch{
		$ErrorMessage = 'An exception happened in FwSetEventLog'
		LogException $ErrorMessage $_ $fLogFileOnly
		Throw ($ErrorMessage)
	}
	EndFunc $MyInvocation.MyCommand.Name
}
Function CollectPRF_IMELog{
	EnterFunc $MyInvocation.MyCommand.Name
	FwResetEventLog $global:EvtLogsIME
	$IMELogFolder = "$global:LogFolder\IMELog$LogSuffix"
	$IMELogEventFolder = "$IMELogFolder\event"
	$IMELogDumpFolder = "$IMELogFolder\dump"
	FwCreateLogFolder $IMELogFolder
	FwCreateLogFolder $IMELogEventFolder
	FwCreateLogFolder $IMELogDumpFolder

	# Event log
	LogInfo ("[IME] Exporting event logs.")
	FwExportEventLog $global:EvtLogsIME -ExportFolder $IMELogEventFolder

	LogInfo ("[IME] Exporting HKCU registries.")
	reg query "HKCU\Control Panel"									  /s | Out-File -Append "$IMELogFolder\reg_HKCU.txt"
	reg query "HKCU\Keyboard Layout"									/s | Out-File -Append "$IMELogFolder\reg_HKCU.txt"
	reg query "HKCU\Software\AppDataLow\Software\Microsoft\IME"		 /s | Out-File -Append "$IMELogFolder\reg_HKCU.txt"
	reg query "HKCU\Software\Microsoft\CTF"							 /s | Out-File -Append "$IMELogFolder\reg_HKCU.txt"
	reg query "HKCU\Software\Microsoft\IME"							 /s | Out-File -Append "$IMELogFolder\reg_HKCU.txt"
	reg query "HKCU\Software\Microsoft\IMEJP"						   /s | Out-File -Append "$IMELogFolder\reg_HKCU.txt"
	reg query "HKCU\Software\Microsoft\IMEMIP"						  /s | Out-File -Append "$IMELogFolder\reg_HKCU.txt"
	reg query "HKCU\Software\Microsoft\Input"						   /s | Out-File -Append "$IMELogFolder\reg_HKCU.txt"
	reg query "HKCU\Software\Microsoft\InputMethod"					 /s | Out-File -Append "$IMELogFolder\reg_HKCU.txt"
	reg query "HKCU\Software\Microsoft\Keyboard"						/s | Out-File -Append "$IMELogFolder\reg_HKCU.txt"
	reg query "HKCU\Software\Microsoft\Speech"						  /s | Out-File -Append "$IMELogFolder\reg_HKCU.txt"
	reg query "HKCU\Software\Microsoft\Speech Virtual"				  /s | Out-File -Append "$IMELogFolder\reg_HKCU.txt"
	reg query "HKCU\Software\Microsoft\Speech_OneCore"				  /s | Out-File -Append "$IMELogFolder\reg_HKCU.txt"
	reg query "HKCU\Software\Microsoft\Spelling"						/s | Out-File -Append "$IMELogFolder\reg_HKCU.txt"
	reg query "HKCU\Software\Policies"								  /s | Out-File -Append "$IMELogFolder\reg_HKCU.txt"

	LogInfo ("[IME] Exporting HKLM registries.")
	reg query "HKLM\SOFTWARE\Microsoft\CTF"							 /s | Out-File -Append "$IMELogFolder\reg_HKLM.txt"
	reg query "HKLM\SOFTWARE\Microsoft\IME"							 /s | Out-File -Append "$IMELogFolder\reg_HKLM.txt"
	reg query "HKLM\SOFTWARE\Microsoft\IMEJP"						   /s | Out-File -Append "$IMELogFolder\reg_HKLM.txt"
	reg query "HKLM\SOFTWARE\Microsoft\IMEKR"						   /s | Out-File -Append "$IMELogFolder\reg_HKLM.txt"
	reg query "HKLM\SOFTWARE\Microsoft\IMETC"						   /s | Out-File -Append "$IMELogFolder\reg_HKLM.txt"
	reg query "HKLM\SOFTWARE\Microsoft\Input"						   /s | Out-File -Append "$IMELogFolder\reg_HKLM.txt"
	reg query "HKLM\SOFTWARE\Microsoft\InputMethod"					 /s | Out-File -Append "$IMELogFolder\reg_HKLM.txt"
	reg query "HKLM\SOFTWARE\Microsoft\MTF"							 /s | Out-File -Append "$IMELogFolder\reg_HKLM.txt"
	reg query "HKLM\SOFTWARE\Microsoft\MTFFuzzyFactors"				 /s | Out-File -Append "$IMELogFolder\reg_HKLM.txt"
	reg query "HKLM\SOFTWARE\Microsoft\MTFInputType"					/s | Out-File -Append "$IMELogFolder\reg_HKLM.txt"
	reg query "HKLM\SOFTWARE\Microsoft\MTFKeyboardMappings"			 /s | Out-File -Append "$IMELogFolder\reg_HKLM.txt"
	reg query "HKLM\SOFTWARE\Microsoft\PolicyManager"				   /s | Out-File -Append "$IMELogFolder\reg_HKLM.txt"
	reg query "HKLM\SOFTWARE\Microsoft\Speech"						  /s | Out-File -Append "$IMELogFolder\reg_HKLM.txt"
	reg query "HKLM\SOFTWARE\Microsoft\Speech_OneCore"				  /s | Out-File -Append "$IMELogFolder\reg_HKLM.txt"
	reg query "HKLM\SOFTWARE\Microsoft\Spelling"						/s | Out-File -Append "$IMELogFolder\reg_HKLM.txt"
	reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /s | Out-File -Append "$IMELogFolder\reg_HKLM.txt"
	reg query "HKLM\SOFTWARE\Policies"								  /s | Out-File -Append "$IMELogFolder\reg_HKLM.txt"

	LogInfo ("[IME] Collecting command outputs.")
	Try{
		tasklist /M MsCtfMonitor.dll | Out-File -Append "$IMELogFolder\tasklist_MsCtfMonitor.txt"
		tree "%APPDATA%\Microsoft\IME" /f | Out-File -Append "$IMELogFolder\tree_APPDATA_IME.txt"
		tree "%APPDATA%\Microsoft\InputMethod" /f | Out-File -Append "$IMELogFolder\tree_APPDATA_InputMethod.txt"
		tree "%LOCALAPPDATA%\Microsoft\IME" /f | Out-File -Append "$IMELogFolder\tree_LOCALAPPDATA_IME.txt"
		tree "C:\windows\system32\ime" /f | Out-File -Append "$IMELogFolder\tree_windows_system32_ime.txt"
		tree "C:\windows\ime" /f | Out-File -Append "$IMELogFolder\tree_windows_ime.txt"
		Get-WinLanguageBarOption | Out-File -Append "$IMELogFolder\get-winlanguagebaroption.txt"
	}Catch{
		LogException ("ERROR: Execute command") $_ $fLogFileOnly
	}

	# Process dump
	LogInfo ("[IME] Collecting process dumps.")
	FwCaptureUserDump "ctfmon" $IMELogDumpFolder -IsService:$False
	FwCaptureUserDump "TextInputHost" $IMELogDumpFolder -IsService:$False
	if ( Get-Process | Where-Object Name -eq imebroker ) {
		foreach ($proc in (Get-Process imebroker)) {
			FwCaptureUserDump -ProcPID $proc.Id -DumpFolder $IMELogDumpFolder
		}
	}
	foreach ($proc in (Get-Process taskhostw)) {
		if ($proc.Modules | Where-Object {$_.ModuleName -eq "msctfmonitor.dll"}) {
			FwCaptureUserDump -ProcPID $proc.Id -DumpFolder $IMELogDumpFolder
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectPRF_NlsLog{
	EnterFunc $MyInvocation.MyCommand.Name
	$NlsLogFolder = "$global:LogFolder\NlsLog$LogSuffix"
	FwCreateLogFolder $NlsLogFolder

	LogInfo ("[Nls] Exporting registry hives.")
	$NlsRegLogFolder = "$NlsLogFolder\Reg"
	Try{
		New-Item $NlsRegLogFolder -ItemType Directory -ErrorAction Stop | Out-Null
		reg save "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" $NlsRegLogFolder\Software.hiv 2>&1 | Out-Null
		reg save "HKLM\SOFTWARE\Microsoft\Windows NT" $NlsRegLogFolder\WindowsNT.hiv 2>&1 | Out-Null
		reg save "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" $NlsRegLogFolder\WindowsUpdate.hiv 2>&1 | Out-Null
		reg save "HKLM\SYSTEM\CurrentControlSet" $NlsRegLogFolder\SYSTEM.hiv 2>&1 | Out-Null
		reg save "HKLM\SYSTEM\DriverDatabase" $NlsRegLogFolder\DriverDatabase.hiv 2>&1 | Out-Null
		reg save "HKLM\SYSTEM\CurrentControlSet\Services" $NlsRegLogFolder\Services.hiv 2>&1 | Out-Null
		reg save "HKCU\Control Panel" $NlsRegLogFolder\hkcu_ControlPanel.hiv 2>&1 | Out-Null
		reg save "HKCU\Software\Classes\Local Settings" $NlsRegLogFolder\hkcu_LocalSettings.hiv 2>&1 | Out-Null
	}Catch{
		LogException ("ERROR: Exporting from Registry") $_ $fLogFileOnly
	}
	LogInfo ("[Nls] Collecting command outputs.")
	Try{
	  dism /online /get-intl 2>&1| Out-File -Append "$NlsLogFolder\dism-get-intl.txt"
	  dism /online /get-features 2>&1| Out-File -Append "$NlsLogFolder\dism-get-features.txt"
	  dism /online /get-packages 2>&1| Out-File "$NlsLogFolder\dism-get-package.txt" 
  
	  Get-WinUserLanguageList | Out-File "$NlsLogFolder\get-winuserlist.txt"
	  Get-Culture | Out-File "$NlsLogFolder\get-culture.txt"
	  Get-WinHomeLocation | Out-File "$NlsLogFolder\get-winhomelocation.txt"
	  Get-WinSystemLocale | Out-File "$NlsLogFolder\get-winsystemlocale.txt"
	  Get-WinLanguageBarOption | Out-File "$NlsLogFolder\get-winlanguagebaroption.txt"
	  #we# Get-TimeZone | Out-File "$NlsLogFolder\get-timezone.txt"
	  If(($PSVersionTable.PSVersion.Major -le 4) -or ($OSVersion.Build -le 9600)){ # PowerShell 4.0 / #we# Get-TimeZone fails on Srv2012R2 with PS v5.0 
			$TimeZone = [System.TimeZoneInfo]::Local.DisplayName
	  }Else{
			$TimeZone = (Get-TimeZone).DisplayName
	  }
	  $TimeZone | Out-File "$NlsLogFolder\get-timezone.txt"
	}Catch{
		LogException ("ERROR: Execute command") $_ $fLogFileOnly
	}

	LogInfo ("[Nls] Collecting Panther files.")
	$NlsPantherLogFolder = "$NlsLogFolder\Panther"
	Try{
		New-Item $NlsPantherLogFolder -ItemType Directory -ErrorAction Stop | Out-Null
		Copy-Item C:\Windows\Panther\* $NlsPantherLogFolder
	}Catch{
		LogException ("ERROR: Copying files from C:\Windows\Panther") $_ $fLogFileOnly
	}

	LogInfo ("[Nls] Collecting Setupapi files.")
	$NlsSetupApiLogFolder = "$NlsLogFolder\Setupapi"
	Try{
		New-Item $NlsSetupApiLogFolder -ItemType Directory -ErrorAction Stop | Out-Null
		Copy-Item "C:\Windows\inf\Setupapi*" $NlsSetupApiLogFolder
	}Catch{
		LogException ("ERROR: Copying files from C:\Windows\Inf\Setup*") $_ $fLogFileOnly
	}

	EndFunc $MyInvocation.MyCommand.Name
}

<# function CollectPRF_PerflibLog {	# was previously defined in NET module
	EnterFunc $MyInvocation.MyCommand.Name
	.\scripts\tss_Perf-Collect.ps1 -Folderpath $global:LogFolder
	EndFunc $MyInvocation.MyCommand.Name
}
#>
function CollectPRF_PerflibLog{
	EnterFunc $MyInvocation.MyCommand.Name
	LogMessage $Loglevel.Info "$($MyInvocation.MyCommand.Name) is called."
	
	# Log folder
	$PerflibLogFolder = "$global:LogFolder\PerflibLog$LogSuffix"
	$EventLogFolder = "$PerflibLogFolder\EventLog"
	FwCreateLogFolder $PerflibLogFolder
	FwCreateLogFolder $EventLogFolder
	# Registry
	LogMessage $LogLevel.Info ("[Perflib] Exporting registry keys related to performance counter.")
	reg query   "HKLM\System\CurrentControlSet\Services" /s																		 | Out-File -FilePath "$PerflibLogFolder\services.txt"
	reg save	"HKLM\System\CurrentControlSet\Services" "$PerflibLogFolder\services.hiv" /y 2>&1								   | Out-Null 
	reg export  "HKLM\System\CurrentControlSet\Services" "$PerflibLogFolder\services.reg" /y 2>&1								   | Out-Null 
	reg query   "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Perflib" /s													  | Out-File -FilePath "$PerflibLogFolder\Perflib.txt"
	reg save	"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Perflib" "$PerflibLogFolder\Perflib.hiv" /y 2>&1				 | Out-Null 
	reg export  "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Perflib" "$PerflibLogFolder\Perflib.reg" /y 2>&1				 | Out-Null 
	reg query   "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Perflib" /s										  | Out-File -FilePath "$PerflibLogFolder\Perflib32.txt"
	reg save	"HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Perflib" "$PerflibLogFolder\Perflib32.hiv" /y 2>&1   | Out-Null 
	reg export  "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Perflib" "$PerflibLogFolder\Perflib32.reg" /y 2>&1   | Out-Null 
	Get-ChildItem -Recurse "$env:windir\Inf"																						| Out-File -FilePath "$PerflibLogFolder\inf-dir.txt"
	(Get-ItemProperty -ErrorAction SilentlyContinue -literalpath ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage")).Counter	| Out-File -FilePath "$PerflibLogFolder\Counter.txt"
	(Get-ItemProperty -ErrorAction SilentlyContinue -literalpath ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage")).Help	   | Out-File -FilePath "$PerflibLogFolder\Help.txt"

	# .Dat file
	LogMessage $LogLevel.Info ("[Perflib] Exporting .dat files related to performance counter.")
	Copy-Item "$env:Windir\System32\perf*.dat" $PerflibLogFolder 

	# Command result
	LogMessage $LogLevel.Info ("[Perflib] Enumerating performance counters.")
	$cmd = "typeperf -q"
	Invoke-Expression ($cmd) | Out-File -FilePath "$PerflibLogFolder\typeperf.txt"
	$cmd = "typeperf -qx"
	Invoke-Expression ($cmd) | Out-File -FilePath "$PerflibLogFolder\typeperf-inst.txt"
	$cmd = "lodctr /Q"
	Invoke-Expression ($cmd) | Out-File -FilePath "$PerflibLogFolder\lodctrQuery.txt"
	$cmd = $env:windir + "\SysWOW64\typeperf.exe -q" 
	Invoke-Expression ($cmd) | Out-File -FilePath "$PerflibLogFolder\typeperf32.txt"
	$cmd = $env:windir + "\SysWOW64\typeperf.exe -qx" 
	Invoke-Expression ($cmd) | Out-File -FilePath "$PerflibLogFolder\typeperf32-inst.txt"
	$cmd = $env:windir + "\SysWOW64\lodctr.exe /Q"
	Invoke-Expression ($cmd) | Out-File -FilePath "$PerflibLogFolder\lodctrQuery32.txt"

	Get-CimInstance -Query "select * from meta_class where __CLASS like '%Win32_Perf%'" | Select-Object -Property __CLASS | Sort-Object -Property __CLASS | Out-File -FilePath "$PerflibLogFolder\WMIPerfClasses.txt"
	
	# Eventlog
	LogMessage $LogLevel.Info ("[Perflib] Exporting Event logs related to performance counter.")
	$EventLogs = Get-WinEvent -ListLog * -ErrorAction Ignore
	$PLALogs =  @(
				'System', 'Application', 'Microsoft-Windows-Diagnosis-PLA/Operational'
				   ) 
	ForEach($EventLog in $EventLogs){
		if ($PLALogs -contains $EventLog.LogName){
			$tmpStr = $EventLog.LogName.Replace('/','-')
			$EventLogName = ($tmpStr.Replace(' ','-') + '.evtx')
			wevtutil epl $EventLog.LogName "$EventLogFolder\$EventLogName" 2>&1 | Out-Null
		}
	}
	
	EndFunc $MyInvocation.MyCommand.Name
}

Function CollectPRF_ShellLog{
	EnterFunc $MyInvocation.MyCommand.Name
	$ShellLogFolder = "$global:LogFolder\ShellLog$LogSuffix"
	$LogPrefix = 'Shell'
	FwCreateLogFolder $ShellLogFolder

	$ShellRegistries = @(
		('HKLM:Software\Policies\Microsoft\Windows\Explorer', "$ShellLogFolder\ExplorerPolicy_HKLM-Reg.txt"),
		('HKCU:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', "$ShellLogFolder\ExplorerPolicy_HKCU-Reg.txt"),
		("HKCU:Software\Microsoft\Windows\Shell\Associations", "$ShellLogFolder\HKCU-Associations_Reg.txt"),
		("HKCU:Software\Microsoft\Windows\CurrentVersion\FileAssociations", "$ShellLogFolder\HKCU-FileAssociations_Reg.txt"),
		("HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\ThumbnailCache", "$ShellLogFolder\HKCU-ThumbnailCache_Reg.txt")
	)
	FwExportRegistry $LogPrefix $ShellRegistries

	# Explorer reg
	REG SAVE 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer' "$ShellLogFolder\HKCU-Explorer_Reg.HIV" 2>&1 | Out-Null
	REG SAVE 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' "$ShellLogFolder\HKLM-Explorer_Reg.HIV" 2>&1 | Out-Null

	# ARCache. Use ARCacheDump.exe to dump ARCache({GUID}.X.ver0x000000000000000X.db)
	LogInfo ("[Shell] Copying ARCache.")
	Try{
		New-Item "$ShellLogFolder\ARCache" -ItemType Directory -ErrorAction Stop | Out-Null
		Copy-Item "$env:userprofile\AppData\Local\Microsoft\Windows\Caches\*" "$ShellLogFolder\ARCache" 
	}Catch{
		LogException  ("Unable to copy ARCache.") $_ $fLogFileOnly
	}

	LogInfo ("[Shell] Copying program shortcut files.")
	Copy-Item "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs" "$ShellLogFolder\Programs-user" -Recurse
	Copy-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs" "$ShellLogFolder\Programs-system" -Recurse
	EndFunc $MyInvocation.MyCommand.Name
}


Function CollectPRF_StartMenuLog{
	EnterFunc $MyInvocation.MyCommand.Name
	$StartLogFolder = "$global:LogFolder\StartMenuLog$LogSuffix"
	FwCreateLogFolder $StartLogFolder
	$cacheDumpToolPath = "$env:windir\system32\datastorecachedumptool.exe"

	### Data Layer State ###
	LogInfo ("[StartMenu] Collecting data for DataLayerState.")
	mkdir "$StartLogFolder\DataLayerState" | Out-Null
	Copy-Item "$Env:LocalAppData\Microsoft\Windows\appsfolder*" "$StartLogFolder\DataLayerState\" -ErrorAction SilentlyContinue | Out-Null
	Copy-Item "$Env:LocalAppData\Microsoft\Windows\Caches\`{3D*" "$StartLogFolder\DataLayerState\" -ErrorAction SilentlyContinue | Out-Null
	Copy-Item "$env:LocalAppData\Microsoft\Windows\Application Shortcuts\" "$StartLogFolder\DataLayerState\Shortcuts\ApplicationShortcuts\" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
	Copy-Item "$env:ProgramData\Microsoft\Windows\Start Menu\" "$StartLogFolder\DataLayerState\Shortcuts\CommonStartMenu\" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
	Copy-Item "$env:APPDATA\Microsoft\Windows\Start Menu\" "$StartLogFolder\DataLayerState\Shortcuts\StartMenu\" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null

	if (Test-Path ("$env:windir\panther\miglog.xml")) {
		Copy-Item "$env:windir\panther\miglog.xml" "$StartLogFolder\DataLayerState" -ErrorAction SilentlyContinue  | Out-Null
	} else {
		"No miglog.xml present on system. Probably not an upgrade" > "$StartLogFolder\DataLayerState\miglog_EMPTY.txt"
	}

	### Trace ###
	LogInfo ("[StartMenu] Collecting trace files.")
	mkdir "$StartLogFolder\Trace" | Out-Null
	Copy-Item "$env:LocalAppData\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState\StartUiTraceloggingSession*" "$StartLogFolder\Trace" -ErrorAction SilentlyContinue | Out-Null
	Copy-Item "$env:LocalAppData\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\TempState\StartUiTraceloggingSession*" "$StartLogFolder\Trace" -ErrorAction SilentlyContinue | Out-Null

	### Tile Cache ###
	LogInfo ("[StartMenu] Collecting data for Tile Cache.")
	mkdir "$StartLogFolder\TileCache" | Out-Null
	mkdir "$StartLogFolder\TileCache\ShellExperienceHost" | Out-Null
	mkdir "$StartLogFolder\TileCache\StartMenuExperienceHost" | Out-Null

	Copy-Item "$env:LocalAppData\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState\Tile*" "$StartLogFolder\TileCache\ShellExperienceHost" -Force -ErrorAction SilentlyContinue | Out-Null
	Copy-Item "$env:LocalAppData\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\TempState\Tile*" "$StartLogFolder\TileCache\StartMenuExperienceHost" -Force -ErrorAction SilentlyContinue | Out-Null

	# After copying off the cache files we should attempt to dump them.  This functionality was added to DataStoreCacheDumpTool.exe in late RS4 and will silently NOOP for
	# builds older than that.
	if (Test-Path -PathType Leaf $cacheDumpToolPath) {
		$allTileCaches = Get-ChildItem -Recurse "$StartLogFolder\TileCache\TileCache*Header.bin";
		foreach ($cache in $allTileCaches) {
			FwInvokeUnicodeTool("$cacheDumpToolPath -v $cache > $cache.html");
		}
	}

	### Upgrade dumps ###
	$dump_files = Get-ChildItem "$env:LocalAppData\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState\" -Filter *.archive
	if ($dump_files.count -gt 0)
	{
		LogInfo ("[StartMenu] Collecting data for UpgradeDumps.")
		mkdir "$StartLogFolder\UpgradeDumps" | Out-Null
		Copy-Item "$env:LocalAppData\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState\*.archive" "$StartLogFolder\UpgradeDumps\" -Force -ErrorAction SilentlyContinue | Out-Null
	}

	### UTM ###
	LogInfo ("[StartMenu] Collecting data for UTM.")
	$UTMLogFolder = "$StartLogFolder\UnifiedTileModel"
	mkdir "$UTMLogFolder\ShellExperienceHost" | Out-Null
	mkdir "$UTMLogFolder\StartMenuExperienceHost" | Out-Null

	Copy-Item "$env:LocalAppData\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState\StartUnifiedTileModelCache*" "$UTMLogFolder\ShellExperienceHost" -Force -ErrorAction SilentlyContinue | Out-Null
	Copy-Item "$env:LocalAppData\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState\UnifiedTileCache*" "$UTMLogFolder\ShellExperienceHost" -Force -ErrorAction SilentlyContinue | Out-Null
	Copy-Item "$env:LocalAppData\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\TempState\StartUnifiedTileModelCache*" "$UTMLogFolder\StartMenuExperienceHost" -Force -ErrorAction SilentlyContinue | Out-Null

	if (Test-Path -PathType Leaf $cacheDumpToolPath) {
		LogInfo ("[StartMenu] Dumping the tile cache with datastorecachedumptool.exe.")
		# The cache dump tool is present in the OS image.  Use it.  If the cache file exists then dump it.  Regardless of whether it exists also take
		# a live dump.
		if (Test-Path -PathType Leaf "$UTMLogFolder\ShellExperienceHost\StartUnifiedTileModelCache.dat") {
			FwInvokeUnicodeTool("$cacheDumpToolPath -f $UTMLogFolder\ShellExperienceHost\StartUnifiedTileModelCache.dat") | Out-File "$UTMLogFolder\ShellExperienceHost\StartUnifiedTileModelCacheDump.log"
		}
		elseif (Test-Path -PathType Leaf "$UTMLogFolder\ShellExperienceHost\UnifiedTileCache.dat") {
			FwInvokeUnicodeTool("$cacheDumpToolPath -f $UTMLogFolder\ShellExperienceHost\UnifiedTileCache.dat") | Out-File "$UTMLogFolder\ShellExperienceHost\UnifiedTileCacheDump.log"
		}

		if (Test-Path -PathType Leaf "$UTMLogFolder\StartMenuExperienceHost\StartUnifiedTileModelCache.dat") {
			FwInvokeUnicodeTool("$cacheDumpToolPath -f $UTMLogFolder\StartMenuExperienceHost\StartUnifiedTileModelCache.dat") | Out-File "$UTMLogFolder\StartMenuExperienceHost\StartUnifiedTileModelCacheDump.log"
		}
	}

	### CDSData ###
	LogInfo ("[StartMenu] Collecting data for CloudDataStore.")
	mkdir "$StartLogFolder\CloudDataStore" | Out-Null
	Invoke-Expression "reg.exe export HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store $StartLogFolder\CloudDataStore\Store.txt 2>&1" | Out-Null
	Invoke-Expression "reg.exe export HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore $StartLogFolder\CloudDataStore\CloudStore.txt 2>&1" | Out-Null
	Invoke-Expression "reg.exe export HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CuratedTileCollections $StartLogFolder\CloudDataStore\CuratedTileCollections.txt 2>&1" | Out-Null

	### DefaultLayout ###
	LogInfo ("[StartMenu] Collecting data for DefaultLayout.")
	mkdir "$StartLogFolder\DefaultLayout" | Out-Null
	Copy-Item "$env:LocalAppData\Microsoft\windows\shell\*" "$StartLogFolder\DefaultLayout" -Force -ErrorAction SilentlyContinue

	### ContentDeliveryManagagerData ###
	LogInfo ("[StartMenu] Collecting data for ContentDeliveryManager.")
	$cdmLogDirectory = "$StartLogFolder\ContentDeliveryManager"
	mkdir $cdmLogDirectory | Out-Null

	$cdmLocalStateDirectory = "$env:LocalAppData\Packages\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\LocalState\";

	# Copy the entire cdm local state directory
	Copy-Item $cdmLocalStateDirectory $cdmLogDirectory -Recurse -Force -ErrorAction SilentlyContinue

	# Extract and highlight key start files
	$cdmExtractedLogDirectory = (Join-Path $cdmLogDirectory "Extracted");
	mkdir $cdmExtractedLogDirectory | Out-Null

	# Collection of folders to extract and give readable names. The last number in most of these is the subscription ID.
	Try{
		@(
			@{'SourceName'	= "TargetedContentCache\v3\314558"
		  	'ExtractedName' = "TargetedContentCache PgStart Internal"},
			@{'SourceName'	= "TargetedContentCache\v3\314559"
		  	'ExtractedName' = "TargetedContentCache PgStart External"},
			@{'SourceName'	= "TargetedContentCache\v3\338381"
		  	'ExtractedName' = "TargetedContentCache Start Suggestions Internal"},
			@{'SourceName'	= "TargetedContentCache\v3\338388"
		  	'ExtractedName' = "TargetedContentCache Start Suggestions External"},
			@{'SourceName'	= "ContentManagementSDK\Creatives\314558"
		  	'ExtractedName' = "ContentManagementSDK PgStart Internal"},
			@{'SourceName'	= "ContentManagementSDK\Creatives\314559"
		  	'ExtractedName' = "ContentManagementSDK PgStart External"},
			@{'SourceName'	= "ContentManagementSDK\Creatives\338381"
		  	'ExtractedName' = "ContentManagementSDK Start Suggestions Internal"},
			@{'SourceName'	= "ContentManagementSDK\Creatives\338388"
		  	'ExtractedName' = "ContentManagementSDK Start Suggestions External"}
			  
		) | ForEach-Object {
			$sourceLogDirectory = (Join-Path $cdmLocalStateDirectory $_.SourceName);
			if (Test-Path -Path $sourceLogDirectory -PathType Container)			{
				$extractedLogDirectory = Join-Path $cdmExtractedLogDirectory $_.ExtractedName;
				mkdir $extractedLogDirectory | Out-Null
				Get-ChildItem $sourceLogDirectory | Foreach-Object {
					$destinationLogFilePath = Join-Path $extractedLogDirectory "$($_.BaseName).json"
					Get-Content $_.FullName | ConvertFrom-Json | ConvertTo-Json -Depth 10 > $destinationLogFilePath;
				}
			}else{
				$extractedLogFilePath = Join-Path $cdmExtractedLogDirectory "NoFilesFor_$($_.ExtractedName)";
				$null > $extractedLogFilePath;
			}
		}
	}Catch{
		LogException ("An error happened during converting JSON data. This might be ignorable.") $_ $fLogFileOnly
	}

	Invoke-Expression "reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /s >> $cdmLogDirectory\Registry.txt"

	### App Resolver Cache ###
	LogInfo ("[StartMenu] Copying ARCache.")
	Try{
		New-Item "$StartLogFolder\ARCache" -ItemType Directory -ErrorAction Stop | Out-Null
		Copy-Item "$env:userprofile\AppData\Local\Microsoft\Windows\Caches\*" "$StartLogFolder\ARCache" 
	}Catch{
		LogException  ("Unable to copy ARCache.") $_ $fLogFileOnly
	}

	### Program shortcut ###
	LogInfo ("[StartMenu] Copying program shortcut files.")
	Copy-Item "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs" "$StartLogFolder\Programs-user" -Recurse
	Copy-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs" "$StartLogFolder\Programs-system" -Recurse
	whoami /user /fo list | Out-File (Join-Path $StartLogFolder 'userinfo.txt')
	EndFunc $MyInvocation.MyCommand.Name
}

#endregion ### Pre-Start / Post-Stop / Collect functions for trace components and scenarios 

#region --- performance counters ---
$PRF_SupportedPerfCounter = @{
	'PRF_IME' = 'General counters + Input delay counters'
}
$PRF_IMECounters = @(
	$global:GeneralCounters
	'\User Input Delay per Process(*)\*'
	'\User Input Delay per Session(*)\*'
)
#endregion --- performance counters ---

#region Registry Key modules for FwAddRegItem
	<# Example:
	$global:KeysHyperV = @("HKLM:Software\Microsoft\Windows NT\CurrentVersion\Virtualization", "HKLM:System\CurrentControlSet\Services\vmsmp\Parameters")
	#>
	# A) section of recursive lists
	
	# B) section of FwAddRegItem -norecursive lists
	
#endregion Registry Key modules

#region groups of Eventlogs for FwAddEvtLog
	<# Example:
	$global:EvtLogsEFS		= @("Microsoft-Windows-NTFS/Operational", "Microsoft-Windows-NTFS/WHC")
	#>
	$global:EvtLogsAppX = @("Microsoft-Windows-Shell-Core/Operational", "Microsoft-Windows-ShellCommon-StartLayoutPopulation/Operational", "Microsoft-Windows-TWinUI/Operational", "Microsoft-Windows-AppModel-RunTime/Admin", "Microsoft-Windows-AppReadiness/Operational", "Microsoft-Windows-AppReadiness/Admin", "Microsoft-Windows-AppXDeployment/Operational", "Microsoft-Windows-AppXDeploymentServer/Operational", "Microsoft-Windows-AppxPackaging/Operational", "Microsoft-Windows-BackgroundTaskInfrastructure/Operational", "Microsoft-Windows-StateRepository/Operational", "Microsoft-Windows-Store/Operational", "Microsoft-Windows-CloudStore/Operational", "Microsoft-Windows-CoreApplication/Operational", "Microsoft-Windows-CodeIntegrity/Operational", "Microsoft-Windows-PushNotification-Platform/Operational", "Microsoft-Windows-ApplicationResourceManagementSystem/Operational")
	$global:EvtLogsIME = @("Microsoft-Windows-IME-Broker/Analytic", "Microsoft-Windows-IME-CandidateUI/Analytic", "Microsoft-Windows-IME-CustomerFeedbackManager/Debug", "Microsoft-Windows-IME-CustomerFeedbackManagerUI/Analytic", "Microsoft-Windows-IME-JPAPI/Analytic", "Microsoft-Windows-IME-JPLMP/Analytic", "Microsoft-Windows-IME-JPPRED/Analytic", "Microsoft-Windows-IME-JPSetting/Analytic", "Microsoft-Windows-IME-JPTIP/Analytic", "Microsoft-Windows-IME-KRAPI/Analytic", "Microsoft-Windows-IME-KRTIP/Analytic", "Microsoft-Windows-IME-OEDCompiler/Analytic", "Microsoft-Windows-IME-TCCORE/Analytic", "Microsoft-Windows-IME-TCTIP/Analytic", "Microsoft-Windows-IME-TIP/Analytic", "Microsoft-Windows-TaskScheduler/Operational")
#endregion groups of Eventlogs


Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *
# SIG # Begin signature block
# MIInvwYJKoZIhvcNAQcCoIInsDCCJ6wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCClEsnMR1LixipI
# 7voG1UW7P4Mlbkg++9ytKLXyJueZJ6CCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHQdyC9ituoWJsyanB5JxnCI
# +uOYuPn91xwi/hCqV7joMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEA0eI6e9SL6KmHxQ6EUZU55Jhx5GLZEhFYZnW+3kjXwO3dCUcefki+sJii
# wV/dIIeNSkWHHe7uFjFUHytr25+ACR5S74ptWqfb9QVERzjqORGadC+n1y3qxQ/D
# ZBzN7mKTsFtTx0Hyq7GRHdA32zHV92RmpiiYBZp94zZNDaPT0moDjT8gUguQCCeb
# 6pZF+GjowvXAXYJEYOM42ygurWVWgadDJAbgiI+qA0lyp8A81ar/66CzhZvzCyPw
# tOVcJim+mOfki1g7z2NdMTPQYANUmfepprjDNe+bjbzDFt5mx0x7YTUHFbsX6/Mi
# utrY8EfWWu6i5ItFjVSGjqoaWFZ6taGCFykwghclBgorBgEEAYI3AwMBMYIXFTCC
# FxEGCSqGSIb3DQEHAqCCFwIwghb+AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsq
# hkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCheBMk1N676+RWhVrPNmQude5oo0Ip9bxL4EYFKXFPGgIGZGzybO6P
# GBMyMDIzMDYwNjExNDQxNi45NDZaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJV
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
# IgQg/6+3Dq0kEWGZlJh6cd9o7RcVkC7GD6f7kfEWaTe7rR4wgfoGCyqGSIb3DQEJ
# EAIvMYHqMIHnMIHkMIG9BCBsJ3jTsh7aL8hNeiYGL5/8IBn8zUfr7/Q7rkM8ic1w
# QTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABtyEn
# GgeiKoZGAAEAAAG3MCIEIPOsUWfmWdIHLgaDbkUHkxu5CNz9CZaukkAFfy6Ko1YB
# MA0GCSqGSIb3DQEBCwUABIICALsVutZw+hwebav1gxnUIYFxgqJ1u9ozMqsZBZle
# eZ0tz6v8orU/JYUPO9JuvsjAtdXWE3v36RlhZNOdTzYFGvoVVHcW8D6EyKMSqAgM
# eXS3MDuxuQwoFFQjSsTWTAvnZ35Pymce186nZyRxzttpL0pAQPiyH6DrhYtRfeqX
# 5VOBpQGl2zMZT2pzxAZwNQyyN6RMafLQ+WzUrbySLi1qMqGzoO79QYQlgt8maFmk
# P5k3q2xyRY2cOpZuGWh03rxatU3NeHOyR7kpYOfv40iZoU80lm54oBVlK0kVFu8K
# I4LS15Lq68eS0nGWmLJ0XCkRmHtd/H3fgllbUK8EV+zpn8TrkTSQgP1lmrBFuFAx
# pWSyv81MdNnZZ5BpltHLIZd4QMY9wgoffa7gWIouzgkAw/ODdN3hsCmAqDdrYBtW
# jWwz6Yt3H/7q+fjvfFwn5jWwczJtkpsLUefyN/G4irbPDrtQh8CD9C8vemSX/W71
# fajTFx0p4+s10y5ySEaVgUCuaZcXbwUVlh3WBek311HBWdyiOaO/mQwgSyzbfbhl
# hgqTqg/FxnPzOO/4DjvvymzGyz0j/lCHmftM7PLi8YRdIL9zL/XEN5q7arV9DFjJ
# JoWBGq5NPv9b3QN4N8PivYe3LCK4ajdq8k7QKwlHXB/CC00v/TwfihM0XOg3aJoE
# 66EU
# SIG # End signature block
