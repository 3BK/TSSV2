================
IMPORTANT NOTICE
================
 
This script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Azure Virtual Desktop or Remote Desktop Services.
The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses, PC names and user names.
The script will save the collected data in a subfolder and also compress the results into a ZIP file. The folder or ZIP file are not automatically sent to Microsoft. 
You can send the ZIP file to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have. 
Find our privacy statement here: https://privacy.microsoft.com/en-US/privacystatement



==============================
About MSRD-Collect (v230523.3)
==============================

 • Are you running into issues with your AVD and/or RDS machines or RDP connections?
 • Are you struggling to find the relevant logs/data on your machines for troubleshooting remote desktop related issues or you'd just like to know which data could be helpful?
 • Would you like an easy, scripted way to collect the relevant remote desktop related troubleshooting data from your machines?
 • Would you like to check if your AVD or RDS machines are configured correctly or if they are running into some known remote desktop related issues?

If the answer to any of these questions is 'yes', then this tool will be of great help to you!

MSRD-Collect is a PowerShell script to simplify data collection for troubleshooting Azure Virtual Desktop, Windows 365 Cloud PC and Remote Desktop Services related issues and a convenient method for submitting and following quick & easy action plans. ​​​​​​​

The collected data can help troubleshoot remote desktop related issues ranging from deployment and configuration, to session connectivity, profile (incl. FSLogix), media optimization for Teams, MSIX App Attach, Remote Assistance and more.
Some scenarios are only viable for AVD deployments.

​​​​​​​The MSRD-Diag.html diagnostics report included in MSRD-Collect provides an extensive overview of the system to quickly pinpoint several known issues and can significantly speed up troubleshooting.


==========
How to use
==========

Run the script on Windows source or Windows target machines, as needed.

Running MSRD-Collect in PowerShell ISE is not supported. Please run the script in a regular elevated/admin PowerShell window.

The script requires at least PowerShell version 5.1 and must be run with elevated permissions in order to collect all required data.

Preferably run the script while logged in to the machine with a Domain Admin account and running PowerShell in the same Domain Admin account's context.
A local Administrator account can also be used, but the script will not have permissions to collect domains related information.
If logged in with a different account than the one running the script, collecting gpresult may fail.

Support for Windows 7 ended on January 10, 2023. While the current version of the script can still be used on Windows 7 source clients, it will no longer collect Windows 7 AVD host specific data and future versions may no longer be compatible with Windows 7 at all.

--//--
Important: 

The script has multiple module (.psm1) files located in a "Modules" folder. This folder (with its underlying .psm1 files) must stay in the same folder as the main MSRD-Collect.ps1 file for the script to work properly.
Download the MSRD-Collect.zip package from the official public download location (https://aka.ms/MSRD-Collect) and extract all files from it, not just the MSRD-Collect.ps1.
The script will import the required module(s) on the fly when specific data is being invoked. You do not need to manually import the modules.

Depending on the OS and security settings of the computer where you downloaded the script, the .zip file may be "blocked" by default.
If you unzip and run this blocked version, you may be prompted by PowerShell to confirm if you want to run the script or each of its modules.
To avoid this, before unzipping the MSRD-Collect.zip file, go to the zip file's Properties, select 'Unblock' and 'Apply'.
After that you can unzip the script and use it.

Alternatively, you can unblock the main script file using the PowerShell command line:
	Unblock-File -Path C:\<path to the extracted script>\MSRD-Collect.ps1

MSRD-Collect.ps1 will also attempt to unblock its module files automatically, by running the following command at the start of the main script:
	Get-ChildItem -Recurse -Path C:\<path to the extracted script>\Modules\MSRDC*.psm1 | Unblock-File -Confirm:$false

--//--


The script can be used in 2 ways:

1) with a GUI: Start the script by running ".\MSRD-Collect.ps1" in an elevated PowerShell window and follow the on-screen guide. 
In the GUI, you can choose between different display languages (English, French, German, Hungarian, Italian, Portuguese, Romanian).
These languages relate only to the UI text. Machine types and Scenario names, collected data/diagnostics results and potential error messages encountered during script usage are in English.

2) without a GUI, using any combination of one or more scenario-based command line parameters, which will start the corresponding data collection automatically. Example: ".\MSRD-Collect.ps1 -Machine 'isAVD' -Profiles -MSIXAA -Scard"


When launched, the script will:
a) present the Microsoft Diagnostic Tools End User License Agreement (EULA). You need to accept the EULA before you can continue using the script.
Acceptance of the EULA will be stored in the registry under HKCU\Software\Microsoft\CESDiagnosticTools and you will not be prompted again to accept it as long as the registry key is in place.
You can also use the "-AcceptEula" command line parameter to silently accept the EULA.
This is a per user setting, so each user running the script will have to accept the EULA once.

b) present an internal notice that the admin needs to confirm if they agree and want to continue with the data collection.


Available command line parameters
---------------------------------

Scenario-based parameters:

	"-Core" - Collects Core data + Runs Diagnostics

	"-Profiles" - Collects all Core data + Profiles data + Runs Diagnostics

	"-Activation" - Collects all Core data + OS Licensing/Activation data + Runs Diagnostics

	"-MSRA" - Collects all Core data + Remote Assistance data + Runs Diagnostics

	"-SCard" - Collects all Core data + Smart Card/RDGW data + Runs Diagnostics

	"-IME" - Collects all Core data + input method data + Runs Diagnostics

	"-DumpPID <pid>" - Generate a process dump based on the provided PID (This dump collection is part of the 'Core' dataset and works with any other scenario parameter except '-DiagOnly')

	"-Teams" - Collects all Core data + Teams data + Runs Diagnostics (AVD Only)

	"-MSIXAA" - Collects all Core data + MSIX App Attach data + Runs Diagnostics  (AVD Only)

	"-HCI" - Collects all Core data + Azure Stack HCI data + Runs Diagnostics  (AVD Only)

	"-NetTrace" - Collects a netsh network trace (netsh trace start scenario=netconnection maxsize=2048 filemode=circular overwrite=yes report=yes)
				If selected, it will always run first, before any other data collection/diagnostics

	"-DiagOnly" - The script will skip all data collection and will only run the diagnostics part (even if other parameters have been specified)
	

Other parameters:

	"-Machine" - Indicates the type of machine from where data is collected. This is a mandatory parameter when not using the GUI
				 Based on the provided value, only data specific to that machine type will be collected
				 Supported values: "isSource", "isAVD", "isRDS"
					- "isSource" : Source machine from where you initiate a remote desktop connection to any target machine
					- "isAVD"    : Azure Virtual Desktop or Windows 365 host machine
					- "isRDS"    : RDS server running any RDS roles or target machine for non-AVD remote connections

	"-AcceptEula" - Silently accepts the Microsoft Diagnostic Tools End User License Agreement
	
	"-AcceptNotice" - Silently accepts the internal Important Notice message on data collection

	"-OutputDir <path>" - ​​​​​​Specify a custom directory where to store the collected files. By default, if this parameter is not specified, the script will store the collected data under "C:\MSDATA". If the path specified does not exit, the script will attempt to create it

	"-NoGUI" - Start the script without a graphical user interface (legacy mode)

	"-UserContext <username>" - Defines the context in which some of the data will be collected
				MSRD-Collect needs to be run with elevated priviledges to be able to collect all the relevant data, which can sometimes be an inconvenient when troubleshooting issues occuring only with non-admin users or even different admin users than the one running the script, where you need data from the affected user's profile, not the admin's profile running the script
				With this option, you can specify that some data should be collected from another user's context (e.g. RDClientAutoTrace, Teams settings)
				This does not apply to collecting HKCU registry keys from the other user. For now, HKCU output will still reflect the settings of the admin user running the script
	

You can combine multiple command line parameters to build your desired dataset.

Usage examples with parameters:

To collect only Core data (excluding Profiles, Teams, MSIX App Attach, MSRA, Smart Card, IME) from a machine that is used as the 'source/client' to connect to other machines:
	.\MSRD-Collect.ps1 -Machine 'isSource' -Core

To collect Core + Profiles + MSIX App Attach + IME data ('Core' is collected implicitly when other scenarios are specified) from an AVD host
	.\MSRD-Collect.ps1 -Machine 'isAVD' -Profiles -MSIXAA -IME

To only run Diagnostics without collecting Core or scenario based data from an RDS server (or a target machine of a non-AVD remote connection)
	.\MSRD-Collect.ps1 -Machine 'isRDS' -DiagOnly

To store the resulting files in a different folder than C:\MSDATA
	.\MSRD-Collect.ps1 -OutputDir "E:\AVDdata\"

To collect Core data and also generate a process dump for a running process, based on the process PID (e.g. in this case a process with PID = 13380), from an AVD host
	.\MSRD-Collect.ps1 -Machine 'isAVD' -Core -DumpPID 13380

To start the script with the GUI (all additional parameters can be set also via the UI)
	.\MSRD-Collect.ps1


​​​​​​​If you are missing any of the data that the script should normally collect (see "Data being collected"), check the content of "*_MSRD-Collect-Log.txt" and "*_MSRD-Collect-Errors.txt" files for more information. Some data may not be present during data collection and thus not picked up by the script. This should be visible in one of the two text files.


PowerShell ExecutionPolicy
--------------------------

If the script does not start, complaining about execution restrictions, then in an elevated PowerShell console run:

	Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force -Scope Process

and verify with "Get-ExecutionPolicy -List" that no ExecutionPolicy with higher precedence is blocking execution of this script.
The script is digitally signed with a Microsoft Code Sign certificate.

After that run the MSRD-Collect script again.


Once the script has started, p​​​lease read the "IMPORTANT NOTICE" message and confirm if you agree to continue with the data collection.

Depending on the amount of data that needs to be collected, the script may need to run for up to a few minutes. 
During this time, the operating system's built-in commands run by MSRD-Collect might not respond or take a long time to complete. 
Please wait, as the tool should still be running in the background. If it is still stuck in the same place for over 5 minutes, try to close/kill it and collect data again.
If the issue keeps repeating with the same machine and at the same step, please send feedback to MSRDCollectTalk@microsoft.com.



====================
Data being collected
====================

The collected data is stored in a subfolder under C:\MSDATA\ and at the end of the data collection, the results are archived into a .zip file also under C:\MSDATA\. 
No data is automatically uploaded to Microsoft.
You can change the default C:\MSDATA\ location either through the GUI (Tools/Set Output Location...) or by command line using the "-OutputDir <location>" parameter.

Data collected in the "Core" scenario:

	• Log files
		o C:\Packages\Plugins\Microsoft.Azure.ActiveDirectory.AADLoginForWindows\
		o C:\Packages\Plugins\Microsoft.Compute.JsonADDomainExtension\<version>\Status\
		o C:\Packages\Plugins\Microsoft.EnterpriseCloud.Monitoring.MicrosoftMonitoringAgent\<version>\Status\
		o C:\Packages\Plugins\Microsoft.Powershell.DSC\<version>\Status\​​​​​​​
		o C:\Program Files\Microsoft RDInfra\AgentInstall.txt
		o C:\Program Files\Microsoft RDInfra\​GenevaInstall.txt
		o C:\Program Files\Microsoft RDInfra\​SXSStackInstall.txt
		o C:\Program Files\Microsoft RDInfra\WVDAgentManagerInstall.txt
		o C:\Users\AgentInstall.txt
		o C:\Users\AgentBootLoaderInstall.txt
		o C:\Windows\debug\NetSetup.log
		o C:\Windows\Temp\ScriptLog.log
		o C:\WindowsAzure\Logs\WaAppAgent.log
		o C:\WindowsAzure\Logs\MonitoringAgent.log
		o C:\WindowsAzure\Logs\Plugins\
	• Local group membership information
		o Remote Desktop Users
		o RDS Management Servers (if available and 'RDS' machine type selected)
		o RDS Remote Access Servers (if available and 'RDS' machine type selected)
		o RDS Endpoint Servers (if available and 'RDS' machine type selected)
	• The content of the "C:\Users\%username%\AppData\Local\Temp\DiagOutputDir\RdClientAutoTrace" folder (available on devices used as source clients to connect to AVD hosts) from the past 5 days, containing:
		o AVD remote desktop client connection ETL traces
		o AVD remote desktop client application ETL traces
		o AVD remote desktop client upgrade log (MSI.log)
	• "%localappdata%\rdclientwpf\ISubscription.json" file
	• "Qwinsta /counter" output
	• DxDiag output in .txt format with no WHQL check
	• Geneva, Remote Desktop and Remote Assistance Scheduled Task information
	• "Azure Instance Metadata service endpoint" request info
	• Convert existing .tsf files on AVD hosts from under "C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Monitoring\Tables" into .csv files and collect the resulting .csv files
	• AVD Monitoring Agent environment variables
	• Output of "C:\Program Files\Microsoft Monitoring Agent\Agent\TestCloudConnection.exe"
	• "dsregcmd /status" output
	• AVD Services API health check (BrokerURI, BrokerURIGlobal, DiagnosticsUri, BrokerResourceIdURIGlobal)
	• Event Logs
		o Application
		o Microsoft-Windows-AAD/Operational
		o Microsoft-Windows-CAPI2/Operational
		o Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin
		o Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational
		o Microsoft-Windows-Diagnostics-Performance/Operational
		o Microsoft-Windows-DSC/Operational
		o Microsoft-Windows-HelloForBusiness/Operational
		o Microsoft-Windows-NTLM/Operational
		o Microsoft-Windows-PowerShell/Operational
		o Microsoft-Windows-RemoteDesktopServices
		o Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Admin
		o Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Operational
		o Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin
		o Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational
		o Microsoft-Windows-RemoteDesktopServices-SessionServices/Operational
		o Microsoft-Windows-TaskScheduler/Operational
		o Microsoft-Windows-TerminalServices-LocalSessionManager/Admin
		o Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
		o Microsoft-Windows-TerminalServices-PnPDevices/Admin
		o Microsoft-Windows-TerminalServices-PnPDevices/Operational
		o Microsoft-Windows-TerminalServices-RDPClient/Operational
		o Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin
		o Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
		o Microsoft-Windows-WER-Diagnostics/Operational
		o Microsoft-Windows-WinINet-Config/ProxyConfigChanged
		o Microsoft-Windows-Winlogon/Operational
		o Microsoft-Windows-WinRM/Operational
		o Microsoft-WindowsAzure-Diagnostics/Bootstrapper
		o Microsoft-WindowsAzure-Diagnostics/GuestAgent
		o Microsoft-WindowsAzure-Diagnostics/Heartbeat
		o Microsoft-WindowsAzure-Diagnostics/Runtime
		o Microsoft-WindowsAzure-Status/GuestAgent
		o Microsoft-WindowsAzure-Status/Plugins
		o Security
		o Setup
		o System
	• Registry keys
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\MSRDC
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\RdClientRadc
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\Remote Desktop​
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\Terminal Server Client
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure\DSC
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSRDC
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDAgentBootLoader
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDMonitoringAgent
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSLicensing
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Terminal Server Client
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies
		o ​​​​​​​HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		o ​​​​​​​HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server
		o HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography
		o HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation
		o HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions
		o HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Safer
		o HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions
		o HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CloudDomainJoin
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CoDeviceInstallers
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server​​
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\TERMINPUT_BUS
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\TERMINPUT_BUS_SXS
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSSQL$MICROSOFT##WID
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RdAgent
		o ​​​​​​​HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDAgentBootLoader
        o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDMS
        o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermServLicensing
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip
        o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TScPubRPC
        o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TSFairShare
        o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tssdis
        o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TSGateway
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmRdpService
        o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM​​
		o HKEY_LOCAL_MACHINE\SYSTEM\DriverDatabase\DeviceIds\TS_INPT
		o HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings
	• Filtered NPS event logs if available, when the RD Gateway role is detected
	• Networking information (firewall rules, ipconfig /all, network profiles, netstat -anob, proxy configuration, route table, winsock show catalog, Get-NetIPInterface, netsh interface Teredo show state)
	• Details of the running processes and services
	• List of installed software (on both machine and user level)
	• Information on installed AntiVirus products
	• List of top 10 processes using CPU at the moment when the script is running
	• "gpresult /h" and "gpresult /r /v" output
	• "fltmc filters" and "fltmc volumes" output
	• File versions of the currently running binaries
	• File versions of key binaries (Windows\System32\*.dll, Windows\System32\*.exe, Windows\System32\*.sys, Windows\System32\drivers\*.sys)
	• Basic system information
	• .NET Framework information
	• "Get-DscConfiguration" and "Get-DscConfigurationStatus" output
	• Msinfo32 output (.nfo)
	• PowerShell version
	• WinRM configuration information
	• Windows Update History
	• Output of "Test-DscConfiguration -Detailed"
	• Output of "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe" (if the NVIDIA GPU drivers are already installed on the machine)
	• Certificate store information ('My' and 'AAD Token Issuer')
	• Certificate thumbprint information ('My', 'AAD Token Issuer', 'Remote Desktop')
	• SPN information (WSMAN, TERMSRV)
	• "nltest /sc_query:<domain>" and "nltest /dnsgetdc:<domain>" output
	• Remote Desktop Gateway information, incl. RAP and CAP policies (if RDGW role is installed - for Server OS deployments)
	• Remote Desktop Connection Broker information, incl. GetFarmData output (if RDCB role is installed - for Server OS deployments)
	• Remote Desktop Web Access information, incl. IIS Server configuration (if RDWA role is installed - for Server OS deployments)
	• Remote Desktop License Server information, incl. installed and issued licenses (if RDLS role is installed - for Server OS deployments)
	• Tree output of the "C:\Windows\RemotePackages" and "C:\Program Files\Microsoft RDInfra" folder's content
	• MMR log from "C:\Program Files\MsRDCMMRHost\MsRDCMMRHostInstall.log"
	• "tasklist /v" output
	• DACLs for "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys" and "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\f686aace6942fb7f7ceb231212eef4a4_"
	• List of AppLocker rules collections
	• Information on installed Firewall products
	• Information on Power Settings ('powercfg /list', 'powercfg /query', 'powercfg /systempowerreport')
	• Verbose list of domain trusts
	• NTFS permissions from the C:\ drive
	• "pnputil /e" output
	• Members of the 'Terminal Server License Servers' group in the domain, if the machine is domain-joined and has either the RD Session Host or RD Licensing role installed
	• Environment variables
	• Debug log for RDP Shortpath availability using 'avdnettest.exe'


Data collected additionally to the "Core" dataset, depending on the selected scenario or command line parameter(s) used:

When using "-Profiles" scenario/parameter:

	• Log files
		o C:\ProgramData\FSLogix\Logs
		o C:\Windows\inf\setupapi.dev.log
	• FSLogix tool output (frx list-redirects, frx list-rules, frx version)
	• Registry keys
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office​
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive
		o HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Office
		o HKEY_CURRENT_USER\Volatile Environment
		o HKEY_LOCAL_MACHINE\SOFTWARE\FSLogix
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search
		o HKEY_LOCAL_MACHINE\SOFTWARE\Policies\FSLogix	
		o HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\OneDrive
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_Msft&Prod_Virtual_Disk
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\frxccd
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\frxccds
	• Output of 'whoami /all'
	• Event Logs
		o Microsoft-FSLogix-Apps/Admin
		o Microsoft-FSLogix-Apps/Operational
		o Microsoft-FSLogix-CloudCache/Admin
		o Microsoft-FSLogix-CloudCache/Operational
		o Microsoft-Windows-GroupPolicy/Operational
		o Microsoft-Windows-SMBClient/Connectivity
		o Microsoft-Windows-SMBClient/Operational
		o Microsoft-Windows-SMBClient/Security
		o Microsoft-Windows-SMBServer/Connectivity
		o Microsoft-Windows-SMBServer/Operational
		o Microsoft-Windows-SMBServer/Security
		o Microsoft-Windows-User Profile Service/Operational
		o Microsoft-Windows-VHDMP/Operational
	• Local group membership information
		o FSLogix ODFC Exclude List
		o FSLogix ODFC Include List
		o FSLogix Profile Exclude List
		o FSLogix Profile Include List
	• DACLs for the FSLogix Profiles and ODFC storage logations
	• 'klist get krbtgt' output
	• 'klist get cifs/<FSLogix Profiles VHDLocations storage>' output
	• A filtered output of the VHD Disk Compaction metric events for FSLogix for the past 5 days


When using "-Activation" scenario/parameter:
	• 'licensingdiag.exe' output
	• 'slmgr.vbs /dlv' output
	• List of available KMS servers in the VM's domain (if domain joined)

		
When using "-MSIXAA" scenario/parameter:

	• Event Logs
		o Microsoft-Windows-AppXDeploymentServer/Operational
		o Microsoft-Windows-RemoteDesktopServices (filtered for MSIX App Attach events only)


When using "-Teams" scenario/parameter:

	• Log files (MSTeams Diagnostics Logs require to be manually generated first by using CTRL+ALT+SHIFT+1 within Teams)
		o %appdata%\Microsoft\Teams\logs.txt
		o %userprofile%\Downloads\MSTeams Diagnostics Log DATE_TIME.txt
		o %userprofile%\Downloads\MSTeams Diagnostics Log DATE_TIME_calling.txt
		o %userprofile%\Downloads\MSTeams Diagnostics Log DATE_TIME_cdl.txt
		o %userprofile%\Downloads\MSTeams Diagnostics Log DATE_TIME_cdlWorker.txt
		o %userprofile%\Downloads\MSTeams Diagnostics Log DATE_TIME_chatListData.txt
		o %userprofile%\Downloads\MSTeams Diagnostics Log DATE_TIME_sync.txt
		o %userprofile%\Downloads\MSTeams Diagnostics Log DATE_TIME_vdi_partner.txt
	• Registry keys
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Teams
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDWebRTCSvc


When using "-MSRA" scenario/parameter:

	• Local group membership information
		o Distributed COM Users
		o Offer Remote Assistance Helpers
	• Registry keys
		o HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance
	• Event Logs
		o Microsoft-Windows-RemoteAssistance/Admin
		o Microsoft-Windows-RemoteAssistance/Operational
	• Information on the COM Security permissions


When using "-SCard" scenario/parameter:

	• Event Logs
		o Microsoft-Windows-Kerberos-KDCProxy/Operational
		o Microsoft-Windows-SmartCard-Audit/Authentication
		o Microsoft-Windows-SmartCard-DeviceEnum/Operational
		o Microsoft-Windows-SmartCard-TPM-VCard-Module/Admin
		o Microsoft-Windows-SmartCard-TPM-VCard-Module/Operational
	• "certutil -scinfo -silent" output
	• RD Gateway information when ran on the KDC Proxy server and the RD Gateway role is present
		o Server Settings, Resource Authorization Policy, Connection Authorization Policy


When using "-IME" scenario/parameter:

	• Registry keys
		o HKEY_CURRENT_USER\Control Panel\International
		o HKEY_CURRENT_USER\Keyboard Layout
		o HKEY_CURRENT_USER\Software\AppDataLow\Software\Microsoft\IME
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\CTF
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\IME
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\IMEMIP
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\IMEJP
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\Input
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputMethod
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\Keyboard
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\Speech
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\Speech Virtual
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\Speech_OneCore
		o HKEY_CURRENT_USER\SOFTWARE\Microsoft\Spelling
		o HKEY_LOCAL_MACHINE\SYSTEM\Keyboard Layout
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CTF
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IME
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IMEJP
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IMEKR
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IMETC
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Input
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\InputMethod
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MTF
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MTFFuzzyFactors
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MTFInputType
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MTFKeyboardMappings
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Speech
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Speech_OneCore
		o HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Spelling
	• 'tree' output for the following folders:
		o %APPDATA%\Microsoft\IME
		o %APPDATA%\Microsoft\InputMethod
		o %LOCALAPPDATA%\Microsoft\IME
		o C:\Windows\System32\IME
		o C:\Windows\IME
	• 'Get-Culture' and 'Get-WinUserLanguageList' output


When using "-HCI" scenario/parameter:
	• Log files
		o %ProgramData%\AzureConnectedMachineAgent\Log\himds.log
		o %ProgramData%\AzureConnectedMachineAgent\Log\azcmagent.log
		o %ProgramData%\GuestConfig\arc_policy_logs\gc_agent.log
		o %ProgramData%\GuestConfig\ext_mgr_logs\gc_ext.log
	• Information on Azure Instance Metadata Service (IMDS) endpoint accessibility specific for Azure Stack HCI


When using "-NetTrace" scenario/parameter (If selected, it will always run first, before any other data collection/diagnostics):
	• 'netsh' trace (netsh trace start scenario=netconnection maxsize=2048 filemode=circular overwrite=yes report=yes)



=========
MSRD-Diag
=========

MSRD-Collect also generates a diagnostics report containing an extensive overview of the system to quickly pinpoint several known issues and significantly speed up troubleshooting.
The report may include checks for options/features that are not available on the system. This is expected as Diagnostics aims to cover as many topics as possible in one. Always place the results into the right troubleshooting context.
New diagnostics checks may be added in each new release, so make sure to always use the latest version of the script for the best troubleshooting experience.​​

Important: MSRD-Diag is not a replacement of a full data analysis. Depending on the scenario, further data collection and analysis may be needed.

The script performs the following diagnostics, from Remote Desktop (AVD/RDS/RDP) perspective:

	• Overview of the system the script is running on (General information)
	• OS activation / licensing
	• Top 10 processes using the most CPU time on all processors
	• Total and available disk space
	• Graphics configuration
	• Windows Installer information
	• Windows Search information
	• SSL/TLS configuration
	• User Account Control (UAC) configuration
	• Windows Update configuration
	• WinRM and PowerShell configuration / requirements
	• Authentication and Logon information
	• FSLogix configuration and presence of the recommended Windows Defender Antivirus exclusion values for FSLogix (if present)
	• Multimedia configuration (Multimedia Redirection and Audio/Video privacy settings)
	• Remote Desktop client information
	• Remote Desktop licensing configuration
	• RDP and remote desktop listener configuration
	• Information on installed RDS roles and their services (if present)
	• Remote Desktop device and resource redirection configuration
	• Antivirus information (if present)
	• Remote Desktop related security settings and requirements
	• Remote Desktop 'Session Time Limits' and other network time limit policy settings
	• Quick Assist information
	• AVD host pool information
	• AVD Agent and SxS Stack information
	• Information related to AVD usage on Azure Stack HCI
	• AVD required URLs accesibility
	• AVD services API health status (BrokerURI, BrokerURIGlobal, DiagnosticsUri, BrokerResourceIdURIGlobal)
    • RDP ShortPath configuration (Windows 10+ and Server OS) for both managed and public networks
	• Azure AD-join configuration
	• Check for Domain Controller configuration (trusted and available)
	• DNS configuration (Windows 10+ and Server OS)
	• Firewall configuration (Firewall software available inside the VM - does not apply to external firewalls)
	• Proxy and route configuration
	• Public IP address information
	• VPN connection profile information
	• Settings that are sometimes related to various logon issues (black screens, delays, disappearing remote desktop windows etc.)
	• Installed Citrix software and some other 3rd party components potentially running on the system, which may be relevant in various troubleshooting scenarios
	• Microsoft Office configuration
	• OneDrive configuration and requirements for FSLogix compatibility
	• Printing information (spooler service status, available printers)
	• Teams information and AVD media optimization configuration for Teams (if present)	
	• Known AVD agent related issues over the past 5 days
	​​​​• Known FSLogix related issues over the past 5 days
	• Known MSIX App Attach related issues over the past 5 days
	• Known RDP ShortPath issues over the past 5 days
	• Known Black Screen issues over the past 5 days
	• Known TCP issues over the past 5 days
	• Known Process and system crashes over the past 5 days
	• Known Process hangs over the past 5 days
	• Known RD Licensing related issues over the past 5 days (when the RD Licensing role is installed)
	• Known RD Gateway related issues over the past 5 days (when the RD Gateway role is installed)


The script generates a *_MSRD-Diag.html output file with the results of the above checks. 
Additional output files might be generated too, based on what (AVD Agent, FSLogix, MSIX App Attach, RDP Shortpath, Black Screen, TCP, process hang or process/system crash) issues have been identified over the past 5 days.



===========
Tool Owners
===========

Robert Klemencz @ Microsoft
Alexandru Olariu @ Microsoft

If you have any feedback about MSRD-Collect, send an e-mail to MSRDCollectTalk@microsoft.com or fill out our survey at: https://aka.ms/MSRD-Collect-Survey
