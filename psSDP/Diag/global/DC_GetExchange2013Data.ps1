#################################################################################
# Copyright © 2012, Microsoft Corporation. All rights reserved.
#
# You may use this code and information and create derivative works of it,
# provided that the following conditions are met:
# 1. This code and information and any derivative works may only be used for
# troubleshooting a) Windows and b) products for Windows, in either case using
# the Windows Troubleshooting Platform
# 2. Any copies of this code and information
# and any derivative works must retain the above copyright notice, this list of
# conditions and the following disclaimer.
# 3. THIS CODE AND INFORMATION IS PROVIDED ``AS IS'' WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. IF THIS CODE AND
# INFORMATION IS USED OR MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN CONNECTION
# WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.
#################################################################################
# DC_GetExchange2013Data.ps1
################################################################################# 
#
#
#
#
#
#
#
#################################################################################
# Version 1.0.0
# Date: 9/5/2012
# Author: Brad Hughes - bradhugh@microsoft.com
# Description: Collects Exchange Server 2013 information
#################################################################################

PARAM ([switch]$GetSetupLogs)


$script:RootOutFile = $null
$script:ExchangeServerName = $null
$script:ExchangeVersion = $null


# <summary>
# Write Exchange 2013 Server and role information to the diagnostic report
# </summary>
Function Display-ExchangeServerInfo {
    trap [Exception] {
        Log-Error $_
        Continue
    }
    
    # Get our Exchange Server object
    $server = Invoke-ExchangeCommand "Get-ExchangeServer $script:ExchangeServerName" | Select-Object -First 1
    
    $sb = New-Object Text.StringBuilder
    
    # Version
    $sb.AppendFormat("ProductVersion: {0}<br/>", $script:ExchangeVersion) | Out-Null
    
    # TODO: Handle printing IU information
    $sb.AppendFormat("Interim Update: {0}<br/>", "None") | Out-Null
    
	# Site
    $sb.AppendFormat("Site: {0}<br/>", $server.Site) | Out-Null
    
    # Roles
    $sb.AppendFormat("Role(s): {0}", [string]::Join(",",$server.ServerRole)) | Out-Null
    

    
    # Create a new object for the summary
    $summaryObject = New-Object PSCustomObject
    Add-Member -InputObject $summaryObject -MemberType NoteProperty `
        -Name $ExchangeServerName -Value $sb.ToString()
    
    # Update the diagnostic report with the summary object
    # TODO: Get Name from Strings File
    $summaryObject | ConvertTo-Xml2 | Update-DiagReport -Id 00_ExchangeServer_Summary `
        -Name "Exchange Server Version and Role" -Verbosity informational
}

Function Collect-TransportRules {
	 trap [Exception] {
        Log-Error $_
        Continue
    }
	
	ExportResults -cmdlet "Get-TransportRule" -outformat "FL"
	$ExportedTransportRules = Export-TransportRuleCollection
    Set-Content -Path ($script:RootOutFile + "_ExportedTransportRules.xml") -Value $ExportedTransportRules.FileData -Encoding Byte

    $ExportedLegacyTransportRules = Export-TransportRuleCollection -ExportLegacyRules
    Set-Content -Path ($script:RootOutFile + "_ExportedLegacyTransportRules.xml") -Value $ExportedLegacyTransportRules.FileData -Encoding Byte
    CollectFiles -filestocollect ($script:RootOutFile + "_ExportedTransportRules.xml") -filedescription ("Export-TransportRuleCollection") -sectiondescription (Get-ReportSection) -noFileExtensionsOnDescription
    CollectFiles -filestocollect ($script:RootOutFile + "_ExportedLegacyTransportRules.xml") -filedescription ("Export-TransportRuleCollection -ExportLegacyRules") -sectiondescription (Get-ReportSection) -noFileExtensionsOnDescription    
}

# <summary>
# Collects todays IIS Logs for all web sites
# </summary>
Function Get-IISLogs {
	trap [Exception] {
		Log-Error $_
		continue
	}
	
	$server = $env:computername
    $iis = [ADSI]"IIS://$server/W3SVC" 
    $sites = $iis.psbase.children | Where-Object { $_.keyType -eq "IIsWebServer"}
    foreach($site in $sites){
        $sp = $site.psbase.path
        $lfd = $site.logfiledirectory
        $slf = $sp.substring($sp.indexof("W3SVC")) | ForEach-Object{$_.replace("/","")}
        $w3logpath = Join-Path -Path $lfd -ChildPath $slf
        $tfldr = ($slf + "LogFiles")
        if  (Test-Path $w3logpath){
			# Call CollectCompressedFiles to get the logs
			CompressCollectFiles -FilesToCollect $w3logpath -DestinationFileName "$tfldr.zip" -SectionDescription "Exchange Server IIS Information" -FileDescription "Logs_$slf (todays logs)" -NumberOfDays 1 -Recurse
        }
        Else{
            Write-DebugLog ("Get-IISLogs: IIS Log Path was expected but not found on filesystem: " + $w3logpath)
        }
    }
}

# <summary>
# Gets Logs from the Exchange 2013 logging folder of a certain type
# </summary>
# <param name="$LogKind">The type of log to gather, for example "RPC Client Access"</param>
# <param name="$Days">The number of days of logs to gather (1 by default)</param>
Function Get-ExchangeLogs([string]$LogKind, $Days = 1) {
	$logPath = (Join-Path (Join-Path $global:ExchangeInstallPath "Logging") $LogKind)
	Get-ExchangeLogsFromPath -Path $logPath -LogKind $LogKind -Days $Days
}

# <summary>
# Gets Logs from the Exchange 2013 logging folder of a certain type
# </summary>
# <param name="$Path">The path to the log files</param>
# <param name="$LogKind">The type of log to gather, for example "RPC Client Access"</param>
# <param name="$Days">The number of days of logs to gather (1 by default)</param>
Function Get-ExchangeLogsFromPath([string]$Path, [string]$LogKind, $Days = 1) {
	if (Test-Path $Path) {
		Update-ActivityProgress "$($Strings.ID_GetExch2013DataGatheringLogs): $LogKind"
		CompressCollectFiles -FilesToCollect $Path -DestinationFileName "Logs_$($LogKind).zip" -SectionDescription "Exchange Logging" -FileDescription "Logs_$LogKind ($Days days)" -NumberOfDays $Days -Recurse
	}
	else {
		Write-DebugLog ("ExchangeLogs: could not find log folder: $Path")
	}
}

# <summary>
# Gets role-specific information for the Mailbox Role
# </summary>
Function Get-MailboxRoleData {
    Write-DebugLog "Starting Get-MailboxRoleData"
    trap [Exception] {
        Log-Error $_
        Continue
    }
    
    Set-ReportSection "Exchange Mailbox Server Role"
    Set-CurrentActivity ($Strings.ID_GetExchDataCollectingAct + " " + $Strings.ID_GetExchServerMailbox)
    
    Update-ActivityProgress $Strings.ID_GetExchDataWait

    # BEGIN Traditional Mailbox Role style collection
    $mailboxDatabases = Invoke-ExchangeCommand "Get-MailboxDatabase -server $ExchangeServerName"
    
    # Export the Get-MailboxServer Information
    ExportResults -Cmdlet "Get-MailboxServer -identity $Script:ExchangeServerName -Status" -outformat "FL"
    
    # Dump the database information
    $DagNames = @()
    foreach ($mailboxDatabase in $mailboxDatabases) {
        $mbEdbFilePath = Split-Path -Path ($mailboxDatabase.EdbFilePath) -Parent
        $mailboxDatabaseName = ("DBMb_" + $mailboxDatabase.Name + "_")
        $edbFilePathName = ("DBMb_" + $mailboxDatabase.name + "_EDBFilePath_Contents")
        
        ExportResults -Cmdlet "Get-MailboxDatabase '$mailboxDatabase' -Status" -outformat "FL" -filename "$mailboxDatabaseName"
        ExportResults -Cmdlet "Get-ChildItem -Path '$mbEdbFilePath'" -outformat "FT" -filename "$edbFilePathName"
        
		# Use the ToString() for this to make it work in both local/remote PS
        $mbLogFolderPath = $mailboxDatabase.LogFolderPath.ToString()

        # If the logs are in a different place from the EDB, dump that information to a different file
        if ($mbEdbFilePath -ne $mbLogFolderPath){
            $fn = ("DBMb_" + $mailboxDatabase.name + "_LogFolderPath")
            ExportResults -Cmdlet "Get-ChildItem -path '$mbLogFolderPath'" -outformat "FT" -filename "$fn"
        }
        
        # Collect all the DAG names
        if ($mailboxDatabase.MasterType -eq "DatabaseAvailabilityGroup"){
            $DAGnames += $mailboxDatabase.MasterServerOrAvailabilityGroup
        }
    }
    
    # If there are DAG's defined, dump DAG Info
    if ($null -ne $DAGnames){
        $uDagNames = ($DAGNames | Get-Unique)
        foreach($uDAG in $uDagNames){
            ExportResults -cmdlet "Get-DatabaseAvailabilityGroup -id '$uDAG' -Status" -filename "DAG_$uDAG" 
        }
        ExportResults -cmdlet "Get-DatabaseAvailabilityGroupNetwork -server '$ExchangeServerName'" -filename "DAGNetworks" -outformat "FL"
    }
    
    #
    # TODO: Collect new store FCL Logging equivalent
    #
    
    ExportResults -Cmdlet "Get-MailboxDatabaseCopyStatus -Server '$ExchangeServerName'" -outformat "FL"
    ExportResults -Cmdlet "Get-StoreUsageStatistics -Server '$ExchangeServerName'" -outformat "FL"
    
    #
    # REVIEW: Do we need to gather any files in Store's working directory?
    #
    
    # BEGIN Traditional CAS Role style collection
        
    # Get Server-level CAS Data
    
    # POP/IMAP
    ExportResults -cmdlet "Get-PopSettings -Server '$ExchangeServerName'"
    ExportResults -cmdlet "Get-ImapSettings -Server '$ExchangeServerName'"
    
    # Virtual Directories
    ExportResults -cmdlet "Get-OutlookAnywhere -Server '$ExchangeServerName'"
    ExportResults -cmdlet "Get-ActiveSyncVirtualDirectory -Server '$ExchangeServerName' -ShowBackEndVirtualDirectories"
    ExportResults -cmdlet "Get-AutodiscoverVirtualDirectory -Server '$ExchangeServerName' -ShowBackEndVirtualDirectories"
    ExportResults -cmdlet "Get-OabVirtualDirectory -Server '$ExchangeServerName' -ShowBackEndVirtualDirectories"
    ExportResults -cmdlet "Get-OwaVirtualDirectory -Server '$ExchangeServerName' -ShowBackEndVirtualDirectories"
    ExportResults -cmdlet "Get-EcpVirtualDirectory -Server '$ExchangeServerName' -ShowBackEndVirtualDirectories"
    ExportResults -cmdlet "Get-PowerShellVirtualDirectory -Server '$ExchangeServerName' -ShowBackEndVirtualDirectories"
    ExportResults -cmdlet "Get-WebServicesVirtualDirectory -Server '$ExchangeServerName' -ShowBackEndVirtualDirectories"
    
    # Dump RpcProxy registry keys
    $regkeys = "HKLM:SOFTWARE\Microsoft\Rpc\RpcProxy"
    $outfile = ($script:RootOutFile + "_REG_RPCPROXY.TXT")
    RegQuery -RegistryKeys $regKeys -OutputFile $outfile -fileDescription ("HKLM:SOFTWARE\Microsoft\Rpc\RpcProxy*") -sectiondescription (Get-ReportSection) -Recursive $true
	
	# Get RpcHttp logs from MBX
	Get-ExchangeLogs -LogKind "RpcHttp" -Days 1
	
	# Get RPCClientAccess logs
	Get-ExchangeLogs -LogKind "RPC Client Access" -Days 1
	
	# Get AddressBook service logs
	Get-ExchangeLogs -LogKind "AddressBook Service" -Days 1
	
	# Get today's Hybrid Config Logs
	Get-ExchangeLogs -LogKind "Update-HybridConfiguration" -Days 1
    
    # BEGIN Traditional Hub Role style collection
    
	# Server-Level
    ExportResults -cmdlet "Get-TransportService -Identity '$ExchangeServerName'"
    ExportResults -cmdlet "Get-ReceiveConnector -Server '$ExchangeServerName'"
    ExportResults -cmdlet "Get-Queue -Server '$ExchangeServerName'"
	ExportResults -cmdlet "Get-MailboxTransportService -Identity '$ExchangeServerName'"
	
	# These cmdlets run implicitly on the server you're connected to and aren't remotable
	ExportResults -cmdlet "Get-TransportAgent"
    ExportResults -cmdlet "Get-TransportPipeline"
	ExportResults -cmdlet "Get-EdgeSyncServiceConfig"
	
	$transportService = Invoke-ExchangeCommand "Get-TransportService -Identity $ExchangeServerName"
	
	# Get today's QueueViewer log
	$queueViewerLogPath = $transportService.QueueLogPath.ToString()
	Get-ExchangeLogsFromPath -Path $queueViewerLogPath -LogKind "QueueViewer" -Days 1
	
	# Today's message tracking logs
	$messageTrackingLogPath = $transportService.MessageTrackingLogPath.ToString()
    Get-ExchangeLogsFromPath -Path $messageTrackingLogPath -LogKind "MessageTracking" -Days 1
	
	# Today's routing logs
    $routingLogPath = $transportService.RoutingTableLogPath.ToString()
	Get-ExchangeLogsFromPath -Path $routingLogPath -LogKind "BE_Routing" -Days 1

    # Today's agent logs
	$agentLogPath = $transportService.AgentLogPath.ToString()
    Get-ExchangeLogsFromPath -Path $agentLogPath -LogKind "BE_Agent" -Days 1
	
	# BEGIN Traditional UM Role style collection
    
	# UM Server collection
    ExportResults -cmdlet "Get-UMService -identity '$ExchangeServerName'"
}

# <summary>
# Gets role-specific information for the CAS Role
# </summary>
Function Get-ClientAccessRoleData {
    Write-DebugLog "Starting Get-ClientAccessRoleData"
	trap [Exception] {
        Log-Error $_
        Continue
    }
	
	Set-ReportSection "Exchange Client Access Server Role"
    Set-CurrentActivity ($Strings.ID_GetExchDataCollectingAct + " " + $Strings.ID_GetExchServerCAS)
	
	# Get CAS Information
    ExportResults -cmdlet "Get-ClientAccessServer -Identity '$ExchangeServerName'"
	
	# Server Collection
	ExportResults -cmdlet "Get-PopSettings -Server '$ExchangeServerName'"
    ExportResults -cmdlet "Get-ImapSettings -Server '$ExchangeServerName'"
    
	# Virtual Directories
    ExportResults -cmdlet "Get-OutlookAnywhere -Server '$ExchangeServerName'"
    ExportResults -cmdlet "Get-ActiveSyncVirtualDirectory -Server '$ExchangeServerName'"
    ExportResults -cmdlet "Get-AutodiscoverVirtualDirectory -Server '$ExchangeServerName'"
    ExportResults -cmdlet "Get-OabVirtualDirectory -Server '$ExchangeServerName'"
    ExportResults -cmdlet "Get-OwaVirtualDirectory -Server '$ExchangeServerName'"
    ExportResults -cmdlet "Get-EcpVirtualDirectory -Server '$ExchangeServerName'"
    ExportResults -cmdlet "Get-PowerShellVirtualDirectory -Server '$ExchangeServerName'"
    ExportResults -cmdlet "Get-WebServicesVirtualDirectory -Server '$ExchangeServerName'"
	
	# Get HttpProxy and RPCHttpLogs
	Get-ExchangeLogs -LogKind "RpcHttp" -Days 1
	Get-ExchangeLogs -LogKind "HttpProxy" -Days 1
	
	# FrontEndTransport collection
	ExportResults -cmdlet "Get-FrontendTransportService -Identity '$ExchangeServerName'"
	ExportResults -cmdlet "Get-ReceiveConnector -Server '$ExchangeServerName'"

    $frontEndTransport = Invoke-ExchangeCommand "Get-FrontendTransportService -Identity $ExchangeServerName"
	
	# Today's routing logs
	# This path isn't accessible on a front-end through the FrontendTransportService config
	# So build the default location here
	$routingLogPath = Join-Path $global:ExchangeInstallPath "TransportRoles\Logs\Routing"
	Get-ExchangeLogsFromPath -Path $routingLogPath -LogKind "FE_Routing" -Days 1
	
	# Today's connectivity Logs for FrontEndTransport
	$feConnectivityLogPath = Join-Path $global:ExchangeInstallPath "TransportRoles\Logs\FrontEnd\Connectivity"
	Get-ExchangeLogsFromPath -Path $feConnectivityLogPath -LogKind "FE_Connectivity" -Days 1

    # Today's agent logs
	$agentLogPath = $frontEndTransport.AgentLogPath.ToString()
    Get-ExchangeLogsFromPath -Path $agentLogPath -LogKind "FE_Agent" -Days 1

	# Once we figure out the local vs remote PS story
	# These cmdlets run implicitly on the server you're connected to and aren't remotable
	ExportResults -cmdlet "Get-TransportAgent" -Local
	ExportResults -cmdlet "Get-TransportPipeline" -Local
	ExportResults -cmdlet "Get-EdgeSyncServiceConfig" -Local
	
	# UM Cmdlets that are also not remotable
	ExportResults -cmdlet "Get-UMCallRouterSettings" -Local
}

# <summary>
# Gets common Exchange 2013 data
# </summary>
Function Get-CommonData { 
    trap [Exception] {
        Log-Error $_
        Continue
    }
    
    Write-DebugLog "Starting Get-CommonData"
    
    Set-ReportSection "Exchange Server and Organization Baseline"
    Set-CurrentActivity ($Strings.ID_GetExchDataCollectingAct + " " + $Strings.ID_GetExchServerCommon)
    Update-ActivityProgress $Strings.ID_GetExchDataWait
        
    # Get the Exchange Build Version
    $exSetup = Join-Path $global:ExchangeInstallPath "\bin\exsetup.exe"
    $script:ExchangeVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($exSetup).ProductVersion
    
    # TODO: Detect Interim Updates
    
    # Display Exchange Server Info
    Display-ExchangeServerInfo
    
    # Local Server
    ExportResults -cmdlet "Write-Output '$Script:ExchangeServerName exsetup.exe ProductVersion:  $script:ExchangeVersion' ; Get-ExchangeServer | Select-Object Name,AdminDisplayVersion,ServerRole,Site" -outformat "FL" -filename "AllExchangeServers" -filedescription "All Exchange Servers - Versions-Roles-Site"
    ExportResults -cmdlet "Get-ExchangeCertificate -Server $Script:ExchangeServerName" -outformat "FL" -filename "ExchangeCertificate"
    ExportResults -cmdlet "Get-ExchangeServer -identity $Script:ExchangeServerName -status"
    ExportResults -cmdlet "Get-PowerShellVirtualDirectory -Server $Script:ExchangeServerName" -outformat "FL"
	ExportResults -cmdlet "Get-MalwareFilteringServer -Identity $Script:ExchangeServerName"
	ExportResults -cmdlet "Get-ServerHealth -Identity $Script:ExchangeServerName" -outformat "FL"
	ExportResults -cmdlet "Get-ServerComponentState -Identity $Script:ExchangeServerName" -outformat "FL"
    
    # Organization Stuff
	ExportResults -cmdlet "Get-OrganizationConfig"
	ExportResults -cmdlet "Get-UserPrincipalNamesSuffix"
	ExportResults -cmdlet "Get-WorkloadManagementPolicy"
	ExportResults -cmdlet "Get-WorkloadPolicy"
	ExportResults -cmdlet "Get-ResourcePolicy"
	ExportResults -cmdlet "Get-SiteMailboxProvisioningPolicy"
	ExportResults -cmdlet "Get-AddressBookPolicy"
	
	# Transport Organization
    #ExportResults -cmdlet "Get-AcceptedDomain" #removing to test reported hang on activity after this cmdlet
    ExportResults -cmdlet "Get-RemoteDomain" 
    ExportResults -cmdlet "Get-EmailAddressPolicy"
	ExportResults -cmdlet "Get-SendConnector"
	ExportResults -cmdlet "Get-EdgeSubscription"
	ExportResults -cmdlet "Get-TransportConfig"
	ExportResults -cmdlet "Get-EdgeSyncServiceConfig"
	ExportResults -cmdlet "Get-DataClassification | where { `$_.Publisher -notlike 'Microsoft*' }" -outformat "FL" -filename "ThirdPartyDataClassifications"
	ExportResults -cmdlet "Get-DlpPolicyTemplate | where { `$_.PublisherName -notlike 'Microsoft*' }" -outformat "FL" -filename "ThirdPartyDplPolicyTemplates"
	ExportResults -cmdlet "Get-DlpPolicy"
	ExportResults -cmdlet "Get-MalwareFilterPolicy"
	ExportResults -cmdlet "Get-PolicyTipConfig"
	
	# Client Access Organization
    ExportResults -cmdlet "Get-AvailabilityAddressSpace"
    ExportResults -cmdlet "Get-AvailabilityConfig"
    ExportResults -cmdlet "Get-ThrottlingPolicy"
	ExportResults -cmdlet "Get-ActiveSyncMailboxPolicy"
	ExportResults -cmdlet "Get-ActiveSyncDeviceAutoblockThreshold"
	ExportResults -cmdlet "Get-MobileDeviceMailboxPolicy"
    ExportResults -cmdlet "Get-OutlookProvider"
	#ExportResults -cmdlet "Get-App" #Eliminated 9/26/13 - Long running, low ROI
	
	# UM Organization
	ExportResults -cmdlet "Get-UMDialPlan"
    ExportResults -cmdlet "Get-UMIPGateway"
    ExportResults -cmdlet "Get-UMHuntGroup"
    ExportResults -cmdlet "Get-UMMailboxPolicy"
    ExportResults -cmdlet "Get-UMAutoAttendant"
	
	foreach ($dialplan in (Invoke-ExchangeCommand "Get-UMDialPlan")) {
        $cFileDialPlanName = ("UMDialPlan_" + $dialplan.Name + "_CountryOrRegionGroups")
        $iFileDialPlanName = ("UMDialPlan_" + $dialplan.Name + "_InternationalGroups")
        ExportResults -cmdlet "(Get-UMDialPlan $dialplan.Name).ConfiguredInCountryOrRegionGroups" -filename "'$cFileDialPlanName'" -cmdletDescription "Get-UMDialPlan (InCountryOrRegionGroups)"
        ExportResults -cmdlet "(Get-UMDialPlan $dialplan.Name).ConfiguredInternationalGroups" -filename "'$iFileDialPlanName'" -cmdletDescription "Get-UMDialPlan (ConfiguredInternationalGroups)"
    }
	
	foreach ($UMAutoAttendant in (Invoke-ExchangeCommand "Get-UMAutoAttendant")) {
        $bFileUMAAName = ("UMAutoAttendant_" + $UMAutoAttendant.Name + "_BusinessHoursKeyMapping")
        $aFileUMAAName = ("UMAutoAttendant_" + $UMAutoAttendant.Name + "_AfterHoursKeyMapping")
        ExportResults -cmdlet "(Get-UMAutoAttendant $UMAutoAttendant.Name).BusinessHoursKeyMapping" -filename "'$bFileUMAAName'" -cmdletDescription "Get-UMAutoAttendant (BusinessHoursKeyMapping)"
        ExportResults -cmdlet "(Get-UMAutoAttendant $UMAutoAttendant.Name).AfterHoursKeyMapping" -filename "'$aFileUMAAName'" -cmdletDescription "Get-UMAutoAttendant (AfterHoursKeyMapping)"
    }
    
    # If they have a Federation trust configured, dump related information
    If (Invoke-ExchangeCommand "Get-FederationTrust"){
        ExportResults -cmdlet "Get-FederationTrust"
        ExportResults -cmdlet "Test-FederationTrustCertificate"
        ExportResults -cmdlet "Get-FederatedOrganizationIdentifier -IncludeExtendedDomainInfo -Verbose"
        ExportResults -cmdlet "Get-OrganizationRelationship"
    }
    
	# Get IIS Logs
	Get-IISLogs
}


# <summary>
# Main Exchange Data Collection Function
# </summary>
Function Get-Exchange2013Data {
    "Starting Get-Exchange2013Data" | WriteTo-StdOut
    trap [Exception] {
        Log-Error $_
        Continue
    }
    
    # Global Variable initialization
    $script:RootOutFile = Join-Path $PWD.Path.ToString() $env:COMPUTERNAME
    
    if ($global:ExchangeVersion -eq 15) {
        if (-not ($global:CasRoleInstalled -or $global:MbxRoleInstalled)) {
            Write-DebugLog "This is an Admin Tools only installation, please run on the server"
            return
        }
        
        # Set the Exchange Server name variable
        $script:ExchangeServerName = $env:COMPUTERNAME
		
		# Initialize the Exchange Runspace and load the Management Shell
		Set-CurrentActivity $Strings.ID_GetExch2013DataInit
		Update-ActivityProgress $Strings.ID_GetExch2013DataConnectEMS
		
		# Just trigger the load at startup, we don't need it yet
		Get-ExchangeRemoteRunspace | Out-Null
    }
    else {
        Write-DebugLog "Exchange 2013 is not installed"
        return
    }
	
    # Get Common Data for all Server Roles
    Get-CommonData
    
    # Get CAS Role Data if installed
    if ($global:CasRoleInstalled) { Get-ClientAccessRoleData }
    
    # Get Mailbox Role Data if installed
    if ($global:MbxRoleInstalled) { Get-MailboxRoleData }
	
}

# Main Script Body

#======================================
# Load localized strings
#======================================
Import-LocalizedData -BindingVariable Strings -ErrorAction SilentlyContinue

#======================================
# Set global variables regardless of Exchange version inestalled
#======================================
$global:SystemDrv = (Get-ChildItem env:systemdrive).value
#$formatenumerationlimit = 128

#======================================
# Tracks Script Execution count and disables confirmation
#======================================
$script:count = 0
$ConfirmPreference = "NONE"

If ($getSetupLogs) { $script:paramGetSetupLogs = $true }

#======================================
# Call the  Get-Exchange2013Data function
#======================================
"Calling Get-Exchange2013Data" | WriteTo-StdOut
Get-Exchange2013Data

# Collect Debug logs
Collect-DebugLog


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBZpn2nDofZqL0N
# Q7OQQIbtAV40ATsSXa01Sw/BD22XtaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXgwghl0AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKGXtUQ+3fuYXbjRDs2l5WKH
# SmPAdsw2DNAYQAlKTLSKMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAQYgp8GL4MKtlBQ6ZZl5IZqeLwjGEm8DudV1eHWSsW/vrDRPEPdOJc
# bbzxL20xMgt/S/vbAJtOnXyFRJdHuf5aDslGw9ofEJqJOUCMoyumAxp6kEk1lbRG
# VIyO4Dr3gi+jx8PFPKJnZ4M8g7zF0UZvy9Ia9VJ3Dwad7aJgumNnoblbIluhNlzV
# 07gdQsNSR+xgsU1rC1wIQAFBawhy8tQRYuQle3tcHG+uPfy5wZPaSQzX5EISDouL
# BPxR4aTpgEJpytv2JYSNo0+OpN2i4MsoqstGJuXKVxRrqEqTqrj/qKe7YHHhT1FY
# 3cYwmkMwKAeQq9DTK93Ni9dhQqMrsOwAoYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIMCeZqBrzJU6O5KDDzENFe7t3+tclEFT03XQDiCVfhl+AgZi2BAW
# 95cYEzIwMjIwODAxMDc0MDIzLjUxNFowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkVBQ0Ut
# RTMxNi1DOTFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGawHWixCFtPoUAAQAAAZowDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTE3WhcNMjMwMjI4MTkwNTE3WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RUFDRS1FMzE2LUM5MUQxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDacgasKiu3ZGEU/mr6A5t9oXAgbsCJq0NnOu+54zZP
# t9Y/trEHSTlpE2n4jua4VnadE4sf2Ng8xfUxDQPO4Vb/3UHhhdHiCnLoUIsW3wtE
# 2OPzHFhAcUNzxuSpk667om4o/GcaPlwiIN4ZdDxSOz6ojSNT9azsKXwQFAcu4c9t
# svXiul99sifC3s2dEEJ0/BhyHiJAwscU4N2nm1UDf4uMAfC1B7SBQZL30ssPyiUj
# U7gIijr1IRlBAdBYmiyR0F7RJvzy+diwjm0Isj3f8bsVIq9gZkUWxxFkKZLfByle
# Eo4BMmRMZE9+AfTprQne6mcjtVAdBLRKXvXjLSXPR6h54pttsShKaV3IP6Dp6bXR
# f2Gb2CfdVSxty3HHAUyZXuFwguIV2OW3gF3kFQK3uL6QZvN8a6KB0hto06V98Ote
# y1OTOvn1mRnAvVu4Wj8f1dc+9cOPdPgtFz4cd37mRRPEkAdX2YaeTgpcNExa+jCb
# OSN++VtNScxwu4AjPoTfQjuQ+L1p8SMZfggT8khaXaWWZ9vLvO7PIwIZ4b2SK3/X
# mWpk0AmaTha5QG0fu5uvd4YZ/xLuI/kiwHWcTykviAZOlwkrnsoYZJJ03RsIAWv6
# UHnYjAI8G3UgCFFlAm0nguQ3rIX54pmujS83lgrm1YqbL2Lrlhmi98Mk2ktCHCXK
# RwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFF+2nlnwnNtR6aVZvQqVyK02K9FwMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAAATu4fMRtRH20+nNzGAXFxdXEpRPTfbM0LJDeNe4QCxj0FM+wrJdu6UKrM2
# wQuO31UDcQ4nrUJBe81N6W2RvEa8xNXjbO0qzNitwUfOVLeZp6HVGcNTtYEMAvK9
# k//0daBFxbp04BzMaIyaHRy7y/K/zZ9ckEw7jF9VsJqlrwqkx9HqI/IBsCpJdlTt
# KBl/+LRbD8tWvw6FDrSkv/IDiKcarPE0BU6//bFXvZ5/h7diE13dqv5DPU5Kn499
# HvUOAcHG31gr/TJPEftqqK40dfpB+1bBPSzAef58rJxRJXNJ661GbOZ5e64EuyIQ
# v0Vo5ZptaWZiftQ5pgmztaZCuNIIvxPHCyvIAjmSfRuX7Uyke0k29rSTruRsBVIs
# ifG39gldsbyjOvkDN7S3pJtTwJV0ToC4VWg00kpunk72PORup31ahW99fU3jxBh2
# fHjiefjZUa08d/nQQdLWCzadttpkZvCgH/dc8Mts2CwrcxCPZ5p9VuGcqyFhK2I6
# PS0POnMuf70R3lrl5Y87dO8f4Kv83bkhq5g+IrY5KvLcIEER5kt5uuorpWzJmBNG
# B+62OVNMz92YJFl/Lt+NvkGFTuGZy96TLMPdLcrNSpPGV5qHqnHlr/wUz9UAViTK
# JArvSbvk/siU7mi29oqRxb0ahB4oYVPNuv7ccHTBGqNNGol4MIIHcTCCBVmgAwIB
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
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs4wggI3AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjpFQUNFLUUzMTYtQzkxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAAbquMnUCam/m7Ox1Uv/GNs1jmu+g
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRt4wwIhgPMjAyMjA4MDExMDIzMDhaGA8yMDIyMDgwMjEwMjMwOFow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pG3jAIBADAKAgEAAgIXMgIB/zAHAgEA
# AgIRmjAKAgUA5pMJDAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAJDWOTBH
# wWT7ODdvvwN83fTgmYJaXHNYartsyVF9rpHSxt/MeCzRG3eJuIv7NN6AGwYQ8iSI
# VKoLlWgJQBfdXcpJH9npPTaOFGGOp0CneOrMEDrZALoYvSJOgOCNPuZXjWrPDM0I
# 9TUzezb8sCF5uOFDpiZ7xObT3zfRoTb0Xg+1MYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGawHWixCFtPoUAAQAAAZowDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgESsNwqMQsV4oEGZucR6Ike6+GtM21GvCkilGrAnexQwwgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCABTkDjOBEUfZnligJiL539Lx+nsr/N
# FVTnKFX030iNYDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABmsB1osQhbT6FAAEAAAGaMCIEILUtm4TpisXoG7kTsxOI51IMkFhuOyD6
# Xm+yAr8gIh09MA0GCSqGSIb3DQEBCwUABIICADii0+XM/RqdHXS2db011cMICMq3
# N26eFFVL6OaTbdGZz3vLRTIZiJ390q++qMnBi/rwIEzYnOQ4VS37FbaA/R3C6jex
# RhXK4lCg5isg1ldmZOjXnujZNETdlBKRq9EcaSX//qUS4GXML8o2PasvkZGLP3Rt
# VW5dQp3IQh0pWMRaeXIdkgFmgTzB58oz2kHptdgvnAefqj1kQKm89buDOyh60J34
# 3qoCjtx/nUSn7TSa3NxCGU9iCjiSWWM88mw9Jgg4rYsvTYeG3tI4CHaC6+EUekwW
# iVFDVH3CLa+iQR/+Bxj9zB/EeXw4hgG7lfFyncarWh4+fKvR7AtxtXXXLylPG6CV
# fyjRaLcKOgZ2BH5aOUiI4CJ0LBgSjoW+TN0W9zivFo4M9Fplu0YrKEmEtDsj98VK
# i05iXdD3IyGJO8h+z+ox3YiFDrKo317u8ZpZzs7eRcBmu69jElgsWZToyGm4CE3D
# QPC4O7MDVuMGis+pN8JQuoKbtrR3uNQGqdnJrOI1r668MVwGPuHxuu8l9ZryzHIK
# EBBWrrxxhHy13D9RDA57HNJaf8JIT6zFmQnBqt0v4Rbs46zLDKW9DaQaTjEA8tiq
# eAlzWXs0oCRf4I4LjJezmToqjIGdKl1UdNL5GOnD6/nnB1Wq/qNJvDp2q9Fh+Jas
# Vhg5SUCzXXtbUmGo
# SIG # End signature block
