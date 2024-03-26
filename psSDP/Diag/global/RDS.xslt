<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:msxsl="urn:schemas-microsoft-com:xslt" exclude-result-prefixes="msxsl"
>
  <xsl:output method="html" indent="yes" standalone="yes" encoding="UTF-16"/>
  
  <xsl:variable name="SectionDescription">
    <string id="Win32_TSGeneralSetting">Setting found in the General settings tab of the RDP properties</string>
    <string id="Win32_TSLogonSetting">Setting found in the Logon settings tab of the RDP properties</string>
    <string id="Win32_TSSessionSetting">Setting found in the Session settings tab of the RDP properties</string>
    <string id="Win32_TSEnvironmentSetting">Setting found in the Environment settings tab of the RDP properties</string>
    <string id="Win32_TSRemoteControlSetting">Setting found in the RemoteControl settings tab of the RDP properties</string>
    <string id="Win32_TSClientSetting">Setting responding to the Client settings tab of the RDP properties</string>
    <string id="Win32_TerminalServiceSetting">Setting of the Remote Desktop service</string>
    <string id="Win32_TSPublishedApplication">Describes a Remote Application</string>
    <string id="Win32_SessionDirectoryServer">Setting responding to the session directory</string>
    <string id="Win32_TSLicenseKeyPack">Information on installed licenses</string>
    <string id="Win32_TSIssuedLicense">Information on issued licenses</string>
    <string id="Win32_TSGatewayLoadBalancer">The named servers participating in gateway loadbalacing</string>
    <string id="Win32_TSGatewayResourceAuthorizationPolicy">Describes a Remote Desktop resource authorization policy (RD RAPs)</string>
    <string id="Win32_TSGatewayConnectionAuthorizationPolicy">Describes a Remote Desktop connection authorization policy (RD CAP)</string>
    <string id="Win32_TSGatewayServerSettings">Setting found in the gateway server properties (all tabs)</string>
    <string id="Win32_TSLicenseServer">Setting found in the license server properties (all tabs)</string>
    <string id="Win32_Workspace">TS Workspace Configuration</string>
    <string id="Win32_RDCentralPublishedRemoteDesktop">Desktop published on another computer, for remote use through Terminal Services</string>
    <string id="Win32_RDCentralPublishedDeploymentSettings">Deployment Settings used to generate RDP files for resources published from a farm</string>
    <string id="Win32_RDCentralPublishedFarm">The List of Farms from which Desktops or Applications have been Published</string>
    <string id="Win32_RDCentralPublishedFileAssociation">Info for a file extension associated with an application</string>
    <string id="Win32_RDPersonalDesktopAssignment">The list of Personal Desktop assignments</string>
    <string id="Win32_RDCentralPublishedRemoteApplication">Application published on another computer, for remote use through Terminal Services</string>
  </xsl:variable>

  <xsl:variable name="SettingDescription">
    <!--Win32_TSLogonSetting-->
    <string id="ClientLogonInfoPolicy">The policy the server uses to determine connection settings. 0=Server Overide 1=Per User</string>
    <string id="Domain">The user's domain logon authentication credential. This is the domain in which the user's computer resides. This property cannot be longer than 17 characters.</string>
    <string id="Password">The user's password logon authentication credential. This property cannot be longer than 14 characters.</string>
    <string id="PolicySourceDomain">Indicates whether the Domain property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default</string>
    <string id="PolicySourcePromptForPassword">Indicates whether the Domain property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default</string>
    <string id="PolicySourceUserName">Indicates whether the UserName property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default</string>
    <string id="PromptForPassword">Specifies whether the user is always prompted for a password while logging into the server.</string>
    <string id="TerminalName">The name of the terminal.</string>
    <string id="UserName">The user's user name logon authentication credential. This property cannot be longer than 20 characters.</string>
    <!--Win32_TSEnvironmentSetting-->
    <string id="ClientWallPaper">Specifies whether the wallpaper image is displayed on the client. Not displaying the wallpaper image can save system resources by decreasing the time required to repaint the screen.0=Not Displayed 1=Displayed</string>
    <string id="InitialProgramPath">The name and the path of the program the user will run immediately after logging on to the RD Session Host server.</string>
    <string id="InitialProgramPolicy">The policy the server uses to determine the startup program path and file name, and the name of the folder it is located in. 0=Per User 1=Server Override 2=Single-App Mode</string>
    <string id="PolicySourceClientWallPaper">Indicates whether the ClientWallPaper property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default</string>
    <string id="PolicySourceInitialProgramPath">Indicates whether the InitialProgramPath property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default</string>
    <string id="PolicySourceStartIn">Indicates whether the StartIn property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default</string>
    <string id="Startin">The path of the working directory of the program the user will run immediately after logging on to the RD Session Host server.</string>
    <string id="TerminalName">The name of the terminal.</string>
    <!-- Win32_TSClientSetting -->
    <string id="ConnectionPolicy">The policy the server uses to retrieve the user connection settings. 0=Server Override 1=Per Users</string>
    <string id="ConnectClientDrivesAtLogon">Specifies whether the client's drives will be automatically connected during the logon process. 0=Drives not autoconnected 1=Drives autoconnect</string>
    <string id="ConnectPrinterAtLogon">Specifies whether all mapped local printers of the client will be automatically connected during the logon process. 0=Local Printers not Automatically connected 1=Local Printers Automatically COnnected </string>
    <string id="DefaultToClientPrinter">Specifies whether print jobs will be automatically sent to the client's local printer. 0=Not Enabled 1=Enabled</string>
    <string id="PolicySourceDefaultToClientPrinter">Indicates whether the DefaultToClientPrinter property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default</string>
    <string id="WindowsPrinterMapping">Specifies whether printer mapping is disabled or enabled for the client's window. 0=enabled 1=disabled</string>
    <string id="PolicySourceWindowsPrinterMapping">Indicates whether the WindowsPrinterMapping property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default</string>
    <string id="LPTPortMapping">Specifies whether LPT port mapping is disabled or enabled. 0=enabled 1=disabled</string>
    <string id="PolicySourceLPTPortMapping">Indicates whether the LPTPortMapping property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default</string>
    <string id="COMPortMapping">Specifies whether COM port mapping is disabled or enabled. 0=enabled 1=disabled</string>
    <string id="PolicySourceCOMPortMapping">Indicates whether the COMPortMapping property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default</string>
    <string id="DriveMapping">Specifies whether drive mapping is disabled or enabled. 0=enabled 1=disabled</string>
    <string id="PolicySourceDriveMapping">Indicates whether the DriveMapping property is configured by the server, group policy, or by default.  0=Server 1=Group Policy 2=Default</string>
    <string id="AudioMapping">Specifies whether audio mapping is disabled or enabled. 0=enabled 1=disabled</string>
    <string id="PolicySourceAudioMapping">Indicates whether the AudioMapping property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default</string>
    <string id="ClipboardMapping">Specifies whether clipboard mapping is disabled or enabled. 0=enabled 1=disabled</string>
    <string id="PolicySourceClipboardMapping">Indicates whether the ClipboardMapping property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default</string>
    <string id="ColorDepthPolicy">Specifies whether to override the user's maximum color setting. 0=Don't override 1=Override</string>
    <string id="PolicySourceColorDepthPolicy">Indicates whether the ColorDepthPolicy property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default</string>
    <string id="ColorDepth">Specifies the color depth. 5=32bit 4=24bit 3=16bit 2=15bit 1=8bit</string>
    <string id="PolicySourceColorDepth">Indicates whether the ColorDepth property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default</string>
    <string id="MaxMonitors">2008 R2 Only. The maximum number of monitors supported by the server.</string>
    <string id="MaxXResolution">2008 R2 Only. The maximum X resolution supported by the server.</string>
    <string id="MaxYResolution">2008 R2 Only. The maximum Y resolution supported by the server.</string>
    <string id="PolicySourceMaxMonitors">Indicates whether the MaxMonitors property is configured by the server, group policy, or default. 0=Server 1=Group Policy 2=Default</string>
    <string id="PolicySourceMaxResolution">Indicates whether the MaxXResolution and MaxYResolution properties are configured by the server, group policy, or default. 0=Server 1=Group Policy 2=Default</string>
    <string id="PNPRedirection">Specifies whether to allow Plug and Play redirection. 0=Allowed 1=Not Allowed</string>
    <string id="PolicySourcePNPRedirection">Indicates whether the PNPRedirection property is configured by the server or by group policy. 0=Server 1=Group Policy</string>
    <string id="AudioCaptureRedir">2008 R2 Only. Specifies whether to allow audio capture redirection.</string>
    <string id="PolicySourceAudioCaptureRedir">Indicates whether the AudioCaptureRedir property is configured by the server or group policy.0=Server 1=Group Policy</string>
    <string id="VideoPlaybackRedir">2008 R2 Only. Specifies whether to allow video playback redirection.</string>
    <string id="PolicySourceVideoPlaybackRedir">Indicates whether the VideoPlaybackRedir property is configured by the server or group policy.  0=Server 1=Group Policy 2=Default</string>
    <string id="AllowDwm">2008 R2 Only. Specifies whether to enable or disable remote desktop composition. Zero will disable remote desktop composition and a nonzero value will enable it.</string>
    <string id="PolicySourceAllowDwm">2008 R2 Only. Specifies whether to allow Plug and Play redirection. 0=Server 1=Group Policy</string>
    <!-- Win32_TSPublishedApplication -->
    <string id="Name">The name of the object.</string>
    <string id="Alias">The alias of the object. The alias is a unique identifier for the object that defaults to the objects file name (without the extension).</string>
    <string id="SecurityDescriptor">A security descriptor that controls access to the application, in SDDL format. An empty string implies allow all access. This security descriptor does not support DENY ACEs, or ACEs that refer to nondomain users or groups.</string>
    <string id="Path">The path of the application.</string>
    <string id="PathExists">Indicates whether the application path is valid.</string>
    <string id="VPath">The virtual path of the application, meaning the path with environment variables included.</string>
    <string id="IconPath">The path of the application icon.</string>
    <string id="IconIndex">The index or ID of the icon.</string>
    <string id="IconContents">The byte contents of the icon that corresponds to the application.</string>
    <string id="CommandLineSetting">The command-line arguments setting for the application. 0=CL Arguments Not Allowed 1=Any CL Arguments Allowed 2=Always user RequiredCommandLine Arguments</string>
    <string id="RequiredCommandLine">The command-line arguments that are required for the application.</string>
    <string id="ShowInPortal">Indicates whether the application should be shown in RD Web Access.</string>
    <string id="RDPFileContents">The contents of the RDP file that correspond to the application.</string>
    <!-- Win32_TSLicenseKeyPack -->
    <string id="KeyPackId">Identifier for the Remote Desktop Services license key pack.</string>
    <string id="Description">Description of the Remote Desktop Services license key pack.</string>
    <string id="KeyPackType">Type of key pack for the Remote Desktop license server.0=Unkown 1=Retail 2=Volume 3=Concurrent 4=Temp 5=Open 6=Built-in Win2K TS</string>
    <string id="ProductType">Product type of the Remote Desktop Services license key pack. 0=Per Device 1=Per User 2=Invalid</string>
    <string id="ProductVersion">Product version for the Remote Desktop Services license key pack.</string>
    <string id="ProductVersionID">Product version identifier for the Remote Desktop Services license key pack. 0=2000 1=2003 2=2008(r2) 3=2008R2 4=2012</string>
    <string id="TotalLicenses">Total number of licenses in the Remote Desktop Services license key pack.</string>
    <string id="IssuedLicenses">Total number of issued licenses in the Remote Desktop Services license key pack.</string>
    <string id="AvailableLicenses">Total number of available licenses in the Remote Desktop Services license key pack.</string>
    <string id="ExpirationDate">The expiration date of the Remote Desktop Services license key pack.</string>
    <!-- Win32_TSIssuedLicense-->
    <string id="LicenseId">Unique identifier for this license.</string>
    <string id="KeyPackId">Identifies the Remote Desktop Services license key pack.</string>
    <string id="sIssuedToUser">User name for which the license was issued.</string>
    <string id="sIssuedToComputer">Computer name for which the license was issued.</string>
    <string id="LicenseStatus">Status of the license. 0=Unknown 1=Temp 2=Active 3=Upgrade 4=Revoked 5=Pending 6=Concurrent</string>
    <string id="IssueDate">Identifies the date that the license was issued.</string>
    <string id="ExpirationDate">Identifies the date that the license will expire.</string>
    <string id="sHardwareId">Hardware identifier for which the license was issued.</string>
    <!-- Win32_TSGatewayLoadBalancer -->
    <string id="Servers">Semicolon-separated list of RD Gateway load-balancing servers.</string>
    <!-- Win32_TSLicenseServer -->
    <string id="FirstName">First name of the contact for RD Licensing</string>
    <string id="LastName">Last name of the contact for RD Licensing</string>
    <string id="Company">Company of the contact for RD Licensing.</string>
    <string id="CountryRegion">Country/region of the contact for RD Licensing.</string>
    <string id="eMail">Email address of the contact for RD Licensing.</string>
    <string id="OrgUnit">Organizational unit of the contact for RD Licensing.</string>
    <string id="Address">Street address of the contact for RD Licensing.</string>
    <string id="City">City of the contact for RD Licensing. </string>
    <string id="State">State of the contact for RD Licensing.</string>
    <string id="PostalCode">Postal code of the contact for RD Licensing.</string>
    <string id="ServerRole">Describes the licensing scope for the Remote Desktop license server within the organization. 0=Workgroup 1=Domain 2=Forest</string>
    <string id="DatabasePath">Path of the RDS Licensing database.</string>
    <string id="ProductId">Product ID of the Remote Desktop license server.</string>
    <string id="Version">Version of the Remote Desktop license server.</string>
    <string id="VersionNumber">Version number of the Remote Desktop license server.</string>
    <!-- Win32_TerminalServiceSetting -->
    <string id="ServerName">Name of the RD Session Host server whose properties are of interest.</string>
    <string id="TerminalServerMode">The RD Session Host server operating mode. 0=Remote Administration 1=Application Server</string>
    <string id="GetCapabilitiesID">Capabilities ID for the provider.</string>
    <string id="LicensingType">The licensing type. 0=Personal RD Session Host server 1=Remote Desktop for Administration 2=Per Device 4=Per User 5=Not configured.</string>
    <string id="PolicySourceLicensingType">Indicates whether the LicensingType property is configured by the server or by group policy. 0=Server 1=Group Policy</string>
    <string id="PossibleLicensingTypes">A bitmask that specifies the licensing types that are available. This can be a combination of one or more of the following values. 1=Personal RD Session Host server licenses are supported. 2=Remote Desktop licenses are supported. 4=Per device licenses are supported. 8=Per user licenses are supported.</string>
    <string id="LicensingName">The name of the licensing mode.</string>
    <string id="LicensingDescription">A brief description of the licensing mode.</string>
    <string id="ActiveDesktop">Specifies whether Active Desktop is allowed in each user session. 0=Disallowed 1=Allowed.</string>
    <string id="UserPermission">Specifies if each user session has tight or relaxed security. 0=Tight 1=Relaxed.</string>
    <string id="DeleteTempFolders">Specifies whether temporary directories are deleted on exit. 0=Disabled 1=Enabled.</string>
    <string id="PolicySourceDeleteTempFolders">Indicates whether the DeleteTempFolders property is configured by the server or by group policy. 0=Server 1=Group Policy.</string>
    <string id="UseTempFolders">Specifies whether temporary directories are created and deleted on a per-session basis. 0=They are not created and deleted for each session. One is created for the first session and never deleted. 1=They are created and deleted for each session.</string>
    <string id="PolicySourceUseTempFolders">Indicates whether the UseTempFolders property is configured by the server or by group policy. 0=Server 1=Group Policy.</string>
    <string id="AllowTSConnections">Specifies whether new Remote Desktop Services connections are allowed. 0=Not allowed 1=Allowed.</string>
    <string id="PolicySourceAllowTSConnections">Indicates whether the AllowTSConnections property is configured by the server or by group policy. 0=Server 1=Group Policy.</string>
    <string id="SingleSession">Specifies whether one or more Remote Desktop Services sessions are allowed per user. 0=More than one session is allowed per user 1=Only one session is allowed per user.</string>
    <string id="PolicySourceSingleSession">Indicates whether the property SingleSession is configured by the server or by group policy. 0=Server 1=Group Policy.</string>
    <string id="ProfilePath">Profile path for the computer.</string>
    <string id="PolicySourceProfilePath">Indicates whether the ProfilePath property is configured by the server or by group policy. 0=Server 1=Group Policy.</string>
    <string id="HomeDirectory">The root directory for the computer.</string>
    <string id="PolicySourceHomeDirectory">Indicates whether the HomeDirectory property is configured by the server or by group policy. 0=Server 1=Group Policy.</string>
    <string id="TimeZoneRedirection">Specifies whether the client computer can redirect its time zone settings to the Remote Desktop Services session. 0=Disabled 1=Enabled.</string>
    <string id="PolicySourceTimeZoneRedirection">Indicates whether the property TimeZoneRedirection is configured by the server or by group policy. 0=Server 1=Group Policy.</string>
    <string id="Logons">Specifies whether new sessions are allowed. This setting does not affect existing settings. 0=Allowed 1=Not allowed.</string>
    <string id="DirectConnectLicenseServers">Deprecated in 2008 R2. Enumerates the list of license servers in Windows Server 2003 and 2008.</string>
    <string id="PolicySourceDirectConnectLicenseServers ">Deprecated in 2008 R2. 2008-Indicates whether the DirectConnectLicenseServers property is configured by the server or by group policy. 0=Server 1=Group Policy. N/A for 2003.</string>
    <string id="PolicySourceConfiguredLicenseServers">Indicates whether the license servers returned by the GetSpecifiedLicenseServerList method are configured by the server or by group policy. 0=Server 1=Group Policy</string>
    <string id="DisableForcibleLogoff">Determines whether an administrator logged on to the console can be forcibly logged off. 0=Can be forcibly logged off 1=Cannot be forcibly logged off.</string>
    <string id="FallbackPrintDriverType">Specifies which printer driver to fallback to. 0=No fallback drivers 1=Best guess 2=Best guess. If no match is found, fallback to Hewlett-Packard Printer Control Language (PCL). 3=Best guess. If no match is found, fallback to Postscript (PS). 4=Best guess. If no match is found, show both PS and PCL drivers.</string>
    <string id="PolicySourceFallbackPrintDriverType">Indicates whether the FallbackPrintDriverType property is configured by the server or by group policy. 0=Server 1=Group Policy.</string>
    <string id="LimitedUserSessions">Limit the number of sessions (both active and inactive) on RD Session Host server. 0=Feature disabled 1 or greater=The maximum number of sessions allowed.</string>
    <string id="EnableDFSS">Indicates whether dynamic fair-share scheduling (DFSS) is enabled or disabled. 0=Disabled 1=Enabled.</string>
    <string id="PolicySourceEnableDFSS">Indicates whether the EnableDFSS property is configured by the server or by group policy. 0=Server 1=Group Policy.</string>
    <string id="EnableRemoteDesktopMSI">Indicates whether the Remote Desktop MSI is enabled or disabled. 0=disabled 1=Enabled.</string>
    <string id="PolicySourceEnableRemoteDesktopMSI">Indicates whether the EnableRemoteDesktopMSI property is configured by the server or group policy. 0=Server 1=Group Policy.</string>
    <string id="EnableAutomaticReconnection">Allow clients to automatically reconnect if the network link is temporarily lost. 0=Disabled 1=Enabled.</string>
    <string id="PolicySourceEnableAutomaticReconnection">Indicates whether the EnableAutomaticReconnection property is configured by the server or group policy. 0=Server 1=Group Policy.</string>
    <string id="UseRDEasyPrintDriver">Specifies whether the Remote Desktop Easy Print printer driver is used first to install all client printers. 0=The RD Session Host server tries to find a suitable printer driver. If the RD Session Host server does not have a printer driver that matches the client printer, the server tries to use the Remote Desktop Easy Print driver to install the client printer. 1=The RD Session Host server tries to find a suitable printer driver to install the client printer. If the RD Session Host server does not have a printer driver that matches the client printer, the server tries to use the Remote Desktop Easy Print driver to install the client printer.</string>
    <string id="PolicySourceUseRDEasyPrintDriver">Indicates whether the UseRDEasyPrintDriver property is configured by the server or group policy. 0=Server 1=Group Policy.</string>
    <string id="RedirectSmartCards">Specifies if redirection of smart card devices is allowed in a remote session. 0=Not allowed 1=Allowed.</string>
    <string id="PolicySourceRedirectSmartCards">Indicates whether the RedirectSmartCards property is configured by the server or group policy. 0=Server 1=Group Policy.</string>
    <string id="EnableDiskFSS">Specifies if disk fair share scheduling is enabled. 0=Disabled 1=Enabled.</string>
    <string id="EnableNetworkFSS">Specifies if network fair share scheduling is enabled. 0=Disabled 1=Enabled.</string>
    <string id="NetworkFSSUserSessionWeight">Specifies the default network fair share weight for a user session. Valid values are 1 to 9.</string>
    <string id="NetworkFSSLocalSystemWeight">Specifies the default network fair share weight for a local system processes. Valid values are 1 to 9.</string>
    <string id="NetworkFSSCatchAllWeight">Specifies the default network fair share weight for catch-all network traffic. Valid values are 1 to 9.</string>
    <!-- Win32_TSGatewayResourceAuthorizationPolicy -->
    <string id="RAPName">Name of the RD RAP.</string>
    <string id="Description">Description of the RD RAP.</string>
    <string id="Enabled">Indicates whether this RD RAP is enabled.</string>
    <string id="ResourceGroupType">Identifies the type of the resource group. RG=Resource Group CG=Computer Group in AD ALL=All Resources</string>
    <string id="ResourceGroupName">Resource group name.</string>
    <string id="UserGroupNames">Semicolon-separated list of user group names. If the user belongs to any of these user groups, access will be permitted.</string>
    <string id="ProtocolNames">List of semicolon-separated protocol names that are enabled for this policy.</string>
    <string id="PortNumbers">List of semicolon-separated port numbers that are allowed for this policy. *=allow any port number.</string>
    <!-- Win32_TSGatewayConnectionAuthorizationPolicy -->
    <string id="CAPName">Name of the RD CAP</string>
    <string id="Order">Evaluation order of the RD CAP. 1=First RD CAP evaluated</string>
    <string id="SmartcardAllowed">Indicates if a smart card can be used to connect to the RD Gateway server.</string>
    <string id="PasswordAllowed">Indicates if a password can be used to connect to the RD Gateway server.</string>
    <string id="SecureIdAllowed">Indicates if a secure identifier can be used to connect to the RD Gateway server.</string>
    <string id="CookieAuthenticationAllowed">Indicates if cookie authentication can be used to connect to the RD Gateway server.</string>
    <string id="Enabled">Indicates whether this RD CAP will be used to evaluate a user for authorization.</string>
    <string id="IdleTimeout">The idle timeout value, in minutes. 0=no timeout</string>
    <string id="SessionTimeout">The session timeout value, in minutes. 0=No Timeout </string>
    <string id="SessionTimeoutAction">Specifies the action to be taken in the case of a session timeout. 0=Disconnect 1=Re-Authorize the Session</string>
    <string id="DeviceRedirectionType">Specifies which devices will be redirected. 0=ALL 1=NONE 2=Some -depends on DEVICEdisabled properties</string>
    <string id="DiskDrivesDisabled">Indicates if disk drive redirection will be disabled. This property has an effect only if the DeviceRedirectionType property has a value of "2".</string>
    <string id="PrintersDisabled">Indicates if printer redirection will be disabled. This property has an effect only if the DeviceRedirectionType property has a value of "2".</string>
    <string id="SerialPortsDisabled">Indicates if serial port redirection will be disabled. This property has an effect only if the DeviceRedirectionType property has a value of "2".</string>
    <string id="ClipboardDisabled">Indicates if clipboard redirection will be disabled. This property has an effect only if the DeviceRedirectionType property has a value of "2".</string>
    <string id="PlugAndPlayDevicesDisabled">Indicates if redirection of Plug and Play devices will be disabled. This property has an effect only if the DeviceRedirectionType property has a value of "2".</string>
    <string id="UserGroupNames">List of semicolon-separated user group names. Format=Domain\UserGroupName. If the user belongs to any of these user groups, the user will be permitted access to the RD GW.</string>
    <string id="ComputerGroupNames">List of semicolon-separated computer group names. Format = Domain\ComputerGroupName. If a value is specified, then the client computer must belong to one of these computer groups for the user to access the RD GW.</string>
    <string id="HasNapAttributes">Indicates if the RD CAP uses Network Access Protection (NAP) attributes.</string>
    <!-- Win32_TSSessionSetting -->
    <string id="ActiveSessionLimit">The maximum amount of time, in milliseconds, allocated to an active session. A value of 0 specifies an infinite amount of time.</string>
    <string id="BrokenConnectionAction">The action the server takes on the session when a connection has been broken due to network loss or exceeded time-limits. 0=Disconnected 1=Permanently deleted.</string>
    <string id="BrokenConnectionPolicy">The policy the server uses to determine when to break a connection because of network loss or exceeded time-limits. 0=The user's disconnection policy settings are overridden by the server 1=The user's disconnection policy settings are in effect.</string>
    <string id="DisconnectedSessionLimit">The time interval, in milliseconds, after which a disconnected session is terminated. A value of 0 specifies an infinite amount of time.</string>
    <string id="IdleSessionLimit">The time interval, in milliseconds, after which an idle session is terminated. A value of 0 specifies an infinite amount of time.</string>
    <string id="PolicySourceActiveSessionLimit">Indicates whether the ActiveSessionLimit property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default.</string>
    <string id="PolicySourceBrokenConnectionAction">Indicates whether the BrokenConnectionAction property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default.</string>
    <string id="PolicySourceDisconnectedSessionLimit">Indicates whether the DisconnectedSessionLimit property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default.</string>
    <string id="PolicySourceIdleSessionLimit">Indicates whether the IdleSessionLimit property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default.</string>
    <string id="PolicySourceReconnectionPolicy">Indicates whether the ReconnectPolicy property is configured by the server, group policy, or by default.</string>
    <string id="ReconnectionPolicy">Specifies whether a user must use the previous client to reconnect to a disconnected session. 0=Any client will be used to reconnect 1=The previous client used in a connection will be used to reconnect.</string>
    <string id="SettingID">Identifier by which the CIM_Setting object is known. This property is inherited from CIM_Setting.</string>
    <string id="TerminalName">The name of the terminal.</string>
    <string id="TimeLimitPolicy">The policy the server uses to determine time-limits for user sessions. 0=Server Override 1=Per User.</string>
    <!-- Win32_TSGeneralSetting -->
    <string id="CertificateName">Display name for the local computer personal certificate subject name.</string>
    <string id="Certificates[]">Contains a serialized certificate store that contains all of the certificates from the My user account store on the computer that are valid server certificates for use with secure sockets layer (SSL).</string>
    <string id="Comment">Descriptive name of the combination of session layer and transport protocol.</string>
    <string id="MinEncryptionLevel">The minimum encryption level. 1=Low 2=Client compatible 3=High 4=FIPS compliant.</string>
    <string id="PolicySourceMinEncryptionLevel">Indicates whether the MinEncryptionLevel property is configured by the server, by group policy, or by default. 0=Server 1=Group Policy 2=Default.</string>
    <string id="PolicySourceSecurityLayer">Indicates whether the SecurityLayer property is configured by the server, by group policy, or by default. 0=Server 1=Group Policy 2=Default.</string>
    <string id="PolicySourceUserAuthenticationRequired">Indicates whether the UserAuthenticationRequired property is configured by the server, by group policy, or by default. 0=Server 1=Group Policy 2=Default.</string>
    <string id="SecurityLayer">Specifies the security layer used between the client and server. 1=RDP security layer 2=Negotiate 3=SSL 4=NLA.</string>
    <string id="SettingID">Identifier by which the CIM_Setting object is known. This property is inherited from CIM_Setting.</string>
    <string id="SSLCertificateSHA1Hash">Specifies the SHA1 hash in hexadecimal format of the SSL certificate for the target server to use. The thumbprint of a certificate may be found using the Certificates MMC snap-in on the Details tab of the certificate properties page.</string>
    <string id="SSLCertificateSHA1HashType">Indicates the state of the SSLCertificateSHA1Hash property. 0=Not Valid 1=Default self-signed 2=Default group policy enforced 3=Custom.</string>
    <string id="TerminalProtocol">The name of the session layer protocol; for example, Microsoft RDP 5.0.</string>
    <string id="Transport">The type of transport used in the connection; for example, TCP, NetBIOS, or IPX/SPX.</string>
    <string id="UserAuthenticationRequired">Specifies the type of user authentication used for remote connections. If set to 1, which means enabled, UserAuthenticationRequired requires user authentication at connection time to increase server protection against network attacks. 0=Disabled 1=Enabled.</string>
    <string id="WindowsAuthentication">Specifies whether the connection defaults to the standard Windows authentication process or to another authentication package that has been installed on the system. 0=Other authentication process 1=Default Windows authentication process.</string>
    <!-- Win32_ TSRemoteControlSetting -->
    <string id="LevelOfControl">Level of control for the session by the remote user 0=Remote control disabled 1=Full control, with the user's permission 2=Full control, user's permission not required 3=View session only, with user's permission 4=View session only, user's permission not required.</string>
    <string id="PolicySourceLevelOfControl">Indicates whether the LevelOfControl property is configured by the server, group policy, or by default. 0=Server 1=Group Policy 2=Default.</string>
    <string id="RemoteControlPolicy">The policy the server uses to retrieve the remote control settings. 0= Server overrides user's settings 1=User's remote control settings are in effect.</string>
    <string id="SettingID">Identifier by which the CIM_Setting object is known. This property is inherited from CIM_Setting.</string>
    <string id="TerminalName">The name of the terminal.</string>
    <!-- Win32_ SessionDirectoryServer -->
    <string id="ServerName">Name of the RD Connection Broker server.</string>
    <string id="ServerIPAddress">IP address of the RD Connection Broker server. If the server is configured for both IPv4 and IPv6 addresses, this will contain the IPv4 address.</string>
    <string id="ClusterName">Name of the farm that includes the server.</string>
    <string id="NumberOfSessions">Number of sessions in the RD Connection Broker server.</string>
    <string id="SingleSessionMode">Single session mode setting of the RD Connection Broker server. 0=Farm is not in single session mode 1=Farm is in single session mode.</string>
    <string id="ServerWeight">Server weight value, used in load balancing.</string>
    <string id="NumPendRedir">Number of pending redirection requests.</string>
    <string id="LoadIndicator">A relative number that represents the RD Session Host server load when the default load-balancing algorithm is used. The LoadIndicator property value is based on the number of sessions, the number of pending redirection requests, and the server weight value.</string>
    <!-- Win32_ TSGatewayServerSettings -->
    <string id="MaxConnections">Returns the maximum number of connections that are allowed through RD Gateway. This property can be set by using the SetMaxConnections method.</string>
    <string id="UnlimitedConnections">Indicates whether an unlimited number of connections are allowed through RD Gateway. This property can be set by using the SetMaxConnections method.</string>
    <string id="MaximumAllowedConnectionsBySku">Maximum number of connections that the stock-keeping unit (SKU) allows.</string>
    <string id="SkuName">Name of the SKU.</string>
    <string id="MaxProtocols">Number of protocols supported by RD Gateway.</string>
    <string id="MaxLogEvents">Returns the maximum number of log events.</string>
    <string id="adminMessageText">The administrative message text.</string>
    <string id="adminMessageStartTime">The administrative message start time.</string>
    <string id="adminMessageEndTime">The administrative message end time.</string>
    <string id="consentMessageText">The consent message text.</string>
    <string id="OnlyConsentCapableClients">Specifies if only clients capable of consent messages are allowed to connect to the RD Gateway. nonzero=only consent capable clients can connect zero=clients that are not consent message capable can also connect.</string>
    <string id="CentralCAPEnabled">Specifies whether central RD CAP servers are used for controlling this server. This property can be changed by calling the EnableCentralCAP method.</string>
    <string id="RequestSOH">Specifies whether the server must request a Statement of Health (SoH) from the client. This property can be changed by using the EnableRequestSOH method.</string>
    <string id="AuthenticationPluginName">The name of the current authentication plug-in.</string>
    <string id="AuthenticationPluginCLSID">The CLSID of the current authentication plug-in.</string>
    <string id="AuthenticationPluginDescription">The description of the current authentication plug-in.</string>
    <string id="AuthorizationPluginName">The name of the current authorization plug-in.</string>
    <string id="AuthorizationPluginCLSID">The CLSID of the current authorization plug-in.</string>
    <string id="AuthorizationPluginDescription">The description of the current authorization plug-in.</string>
    <string id="SslBridging">Specifies which type of SSL bridging to be used by the RD Gateway server. 0=No SSL bridging 1=HTTPS to HTTP bridging 2=HTTPS to HTTPS bridging.</string>
    <string id="IsConfigured">Specifies if IIS and RPC settings required by the RD Gateway service are configured.</string>
    <string id="CertHash">Specifies the certificate hash for HTTPS binding on port 443 in IIS.</string>
    <string id="EnforceChannelBinding">Indicates if channel binding is enforced for the HTTP transport. This property value can be changed by using the SetEnforceChannelBinding method.</string>
    <!-- Win32_Workspace -->
    <string id="IsDefaultName">True if workspace name is default.</string>
    <string id="ID">ID of the Workspace.</string>
    <string id="Redirector">Machine name of the Redirector.</string>
    <string id="RedirectorAlternateAddress">Alternate Address for the Redirector.</string>
    <!-- Win32_RDCentralPublishedRemoteDesktop -->
    <string id="PublishingFarm">Alias of the farm that published the object.</string>
    <string id="IconContents">Contents of the icon corresponding to the application.</string>
    <string id="ShowInPortal">Whether this application should be shown in the TS Web Access.</string>
    <string id="Folders">List of the folders where this resource should be displayed.</string>
    <!-- Win32_RDCentralPublishedDeploymentSettings -->
    <string id="Port">RDP Port.</string>
    <string id="FarmName">Farm Name.</string>
    <string id="GatewayUsage">How Gateway is Used.</string>
    <string id="GatewayName">Gateway Name.</string>
    <string id="GatewayAuthMode">Gateway Authentication Mode, Password(0), Smartcard(1), Allow User to Choose(4).</string>
    <string id="GatewayUseCachedCreds">Use the same user credentials for TS Gateway and TS Server when possible.</string>
    <string id="ColorBitDepth">Color Bit Depth.</string>
    <string id="AllowFontSmoothing">Allow Font Smoothing.</string>
    <string id="UseMultimon">Enable Multi-Monitor for desktop (not RAIL).</string>
    <string id="RedirectionOptions">Redirection Options is configured by adding the following flags  None(0), Drives(1), Printers(2), Clipboard(4), Plug and Play(8), Smart Card(16)
      .</string>
    <string id="HasCertificate">Use a Certificate to Sign the RDP Files.</string>
    <string id="CertificateHash">Certificate used to sign RDP files.</string>
    <string id="CustomRDPSettings">Contents of the RDP file corresponding to the Custom RDP Settings.</string>
    <string id="DeploymentRDPSettings">Contents of the RDP file corresponding to the Deployment Settings, if this is set the corresponding Redirection settings and other Deployment settings are ignored and this RDP file is used.</string>
    <!-- Win32_RDCentralPublishedFarm -->
    <string id="FarmType">The kind of farm: RDSH=0, TempVm=1, ManualPersonalVm=2, AutoPersonalVM=3.</string>
    <string id="IsUserAdmin">Whether a user needs to be added to local administrator group upon connection. Applicable only to ManualPersonalVm and AutoPersonalVM farm types.</string>
    <string id="RollbackEnabled">Whether to auto rollback VM to a snapshot after user logoff. Applicable only to TempVm farm types.</string>
    <string id="SecurityDescriptor">Security Descriptor controlling access to the application, in SDDL Format. Empty string implies allow all access.</string>
    <string id="VmFarmSettings">Virtual machine farm settings.</string>
    <!-- Win32_RDCentralPublishedFileAssociation -->
    <string id="ExtName">Name of the extension (e.g. .txt)</string>
    <string id="AppAlias">Alias of the file association's RemoteApp.</string>
    <string id="FarmAlias">Alias of the Farm where the object is published.</string>
    <string id="ProgIdHint">Hint to help open documents with this file association.</string>
    <string id="PrimaryHandler">Reserved for future use. Will always be TRUE.</string>
    <!-- Win32_RDPersonalDesktopAssignment -->
    <string id="UserName">User name to whom personal desktop has been assigned.</string>
    <string id="DomainName">Domain name of the user.</string>
    <string id="VMName">Assigned VM name.</string>

  </xsl:variable>

  <xsl:template name ="Table">
    <xsl:param name="Section">
    </xsl:param>
    <xsl:param name="Name">
      <xsl:value-of select="@Name"/>
    </xsl:param>
    
     <tr font-size="75%" vertical-align="top">
       <td>
         <a target="_blank">
           <xsl:attribute name="href">http://www.bing.com/search?q=<xsl:value-of select="$Section"/>+<xsl:apply-templates select="@Name"/>
           </xsl:attribute>
           <xsl:apply-templates select="@Name"/>
         </a>
       </td>
        <td>&quot;<xsl:apply-templates select="node()"/>&quot;
        </td>
       <td>
         <xsl:choose>
           <xsl:when test="$Section != 'Win32_TSGatewayResourceAuthorizationPolicy' or $Section !='Win32_TSGatewayConnectionAuthorizationPolicy'">
             <xsl:value-of select="msxsl:node-set($SettingDescription)/string[@id=$Name][1]/child::node()"/>
           </xsl:when>
           <xsl:otherwise>
             <xsl:choose>
              <xsl:when  test ="@Name != 'Name'">
                <xsl:value-of select="msxsl:node-set($SettingDescription)/string[@id=$Name][1]/child::node()"/>
              </xsl:when>
               <xsl:otherwise>
                 <xsl:choose>
                   <xsl:when test="$Section ='Win32_TSGatewayConnectionAuthorizationPolicy'">
                     <xsl:value-of select="msxsl:node-set($SettingDescription)/string[@id='CAP'+ $Name][1]/child::node()"/>
                   </xsl:when>
                   <xsl:otherwise>
                     <xsl:value-of select="msxsl:node-set($SettingDescription)/string[@id='RAP'+ $Name][1]/child::node()"/>
                   </xsl:otherwise>
                 </xsl:choose>
                 
               </xsl:otherwise>
             </xsl:choose>
           </xsl:otherwise>
         </xsl:choose>
       </td>
      </tr>
  </xsl:template>

  <xsl:template name="Section">
    <xsl:param name="Section"/>
    <th>
      <xsl:apply-templates select="@Type"/>:<br></br>
      <xsl:value-of select="msxsl:node-set($SectionDescription)/string[@id=$Section][1]/child::node()"/>
    </th>
    <th>
      Value:
    </th>
    <th>
      Description:
    </th>
  </xsl:template>

  <xsl:template name="SectionBottom">
    <tr>
      <td>
        <br/>
      </td>
      <td></td>
      <td></td>
    </tr>
    <tr>
      <td>
        <br/>
      </td>
      <td></td>
      <td></td>
    </tr>
  </xsl:template>


  <xsl:template match="/">
    <style>
      body{ font-family: 'Segoe UI'; color: black; margin-left: 5px; margin-right: 5px; margin-top: 5px; }
      td{ font-size: 75%; vertical-align: top; }
      th{ font-size: 70%; vertical-align: top; text-align: left; padding-left: 0px; }
      tr{ padding-top: 2px; }
      hr{ border:1px solid lightgrey; height:1px;}
      a:visited{ color: #0066CC; }
      a{ color: #0066CC; }
      .page { width: 480px; }
      .arrows{ font-family: webdings; font-size: 15px; line-height: 9px; font-weight: 100; width: 16px; }
      .bullets{ font-family: webdings; font-size: 10px; font-weight: 100; padding-top: 8px; padding-left: 4px; }
      .info{ width: 100%; }
      .title{ color: windowtext; font-size: 9pt; font-weight: bold; text-align: left; }
      .heading{ font-family: 'Segoe UI'; color: windowtext; font-size: 12pt; font-weight: normal; }
      .detail{ cursor: hand; color: #0066CC; }
      .content { padding-left: 20px; }
      .italic{ font-style: italic; }
      .clip{ width: 340px; overflow: hidden; text-overflow: ellipsis; }
      .scroll{ width: 458px; overflow-x: scroll; border: solid lightgrey 1px; margin-top: 3px; padding: 4px;}
      .local{ text-decoration: none; }
      .block{ margin-bottom: 12px; page-break-inside: avoid; }
      .b1{ background: white; }
      .b2{ background: whitesmoke; }
      .popup{ position: absolute; z-index: 1; background-color: infobackground; border: solid; border-width: 1px; border-right-width: 2px; border-bottom-width: 2px; font-size: x-small; font-weight: normal; text-align: left;padding: 8px; width: 240px; }
      v\:* {behavior:url(#default#VML);}
    </style>
	  <html>
      <body>
        <table border="0" cellpadding="2" cellspacing="0" width="90%">
          <xsl:apply-templates/>
        </table>
      </body>
    </html>
  </xsl:template>
  
 
  <xsl:template match="Objects/Object">
    <xsl:choose>
      <xsl:when test ="@Type = 'System.Object[]'">
        <xsl:for-each select="Property">
          <xsl:variable name="Section" select="@Type"/>
          <xsl:call-template name="Section">
            <xsl:with-param name="Section" select="$Section"/>
          </xsl:call-template>
          <xsl:for-each select="Property">
            <xsl:if test="@Name !=''">
            <xsl:call-template name="Table">
              <xsl:with-param name="Section" select="$Section"/>
            </xsl:call-template>
            </xsl:if>
          </xsl:for-each>
          <xsl:call-template name="SectionBottom"/>
        </xsl:for-each>
      </xsl:when>
      <xsl:otherwise>
        <xsl:variable name="Section" select="@Type"/>
        <xsl:call-template name="Section">
          <xsl:with-param name="Section" select="$Section"/>
        </xsl:call-template>
          <xsl:for-each select="Property">
            <xsl:if test="@Name !=''">
              <xsl:call-template name="Table">
                <xsl:with-param name="Section" select="$Section"/>
              </xsl:call-template>
            </xsl:if>
          </xsl:for-each>
      </xsl:otherwise>
    </xsl:choose>
    <td></td>
    <td></td>
    <td></td>
  </xsl:template>
</xsl:stylesheet>
