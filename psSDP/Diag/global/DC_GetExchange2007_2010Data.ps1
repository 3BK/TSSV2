#################################################################################
# Copyright © 2008, Microsoft Corporation. All rights reserved.
#
# You may use this code and information and create derivative works of it, provided that the following conditions are met:
# 1. This code and information and any derivative works may only be used for # troubleshooting a) Windows and b) products for Windows, in either case using the Windows Troubleshooting Platform
# 2. Any copies of this code and information and any derivative works must retain the above copyright notice, this list of # conditions and the following disclaimer.
# 3. THIS CODE AND INFORMATION IS PROVIDED ``AS IS'' WITHOUT WARRANTY OF ANY KIND,
#    WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES
#    OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. IF THIS CODE AND
#    INFORMATION IS USED OR MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN CONNECTION
#    WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.
#################################################################################
# DC_GetExchange2007_2010Data.ps1
# Version 3.7.0
# Date: 2013-04-25
# Author: Brian Prince - brianpr@microsoft.com
# Description: Collects Exchange Server 2007 and Exchange Server 2010 information
#################################################################################

PARAM ([switch]$getSetupLogs, [switch]$getExBPA)

######################
## Output Functions ##
######################

function out-zip ($FilePath,$zipFileName){
        $oZipFileName = $zipFileName
        $ZipFileName = ($PWD.Path) + "\" + ($env:COMPUTERNAME + "_") + $zipFileName
        if (-not $zipFileName.EndsWith('.zip')) {$zipFileName += '.zip'} 
        
        Write-DiagProgress -Activity ($GetExchDataStrings.ID_GetExchDataCompressingAct) -Status ($GetExchDataStrings.ID_GetExchDataCompressingStatus + " " + $oZipFileName + ".zip")
        
        if (-not (Test-Path($ZipFileName))) {Set-Content $ZipFileName ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))}
        
        $ZipFileObj = (new-object -com Shell.Application).NameSpace($ZipFileName)
        
        $sleepCounter = 0
        $zipItemCounter = 0
        #$itemsToZipCount = $FilePath.count
        #$InitialZipItemCount = 0
        #$InitialZipItemCount = $ZipFileObj.Items().Count            
        
        foreach ($file in $FilePath){
        
            $ZipFileObj.CopyHere($file.FullName)
            $zipItemCounter += 1
            
            do{
                Start-Sleep -Milliseconds 500
                $sleepCounter += 1
            } while (($ZipFileObj.Items().Count -lt $zipItemCounter) -and ($sleepCounter -lt 600))
        }

        return $zipFileName
}

Function New-DDF($path,$filePath)
{
 $ddfFile = Join-Path -path $path -childpath temp.ddf
 $cabName = Split-Path -path $filepath -leaf
 #"DDF file path is $ddfFile"
 $ddfHeader =@"
;*** MakeCAB Directive file
;
.OPTION EXPLICIT      
.Set CabinetNameTemplate=$cabName.cab
.set DiskDirectory1=$path
.set CompressionType=MSZIP
.Set MaxDiskSize=0
.Set Cabinet=on
.Set Compress=on
"@
 #"Writing ddf file header to $ddfFile" 
 $ddfHeader | Out-File -filepath $ddfFile -force -encoding ASCII
 #"Generating collection of files from $filePath"
 Get-ChildItem -path $filePath | Where-Object { !$_.psiscontainer } | ForEach-Object `
 { 
 '"' + $_.fullname.tostring() + '"' | 
 Out-File -filepath $ddfFile -encoding ASCII -append
 }
 #"ddf file is created. Calling New-Cab function"
 New-Cab($ddfFile)
} #end New-DDF

Function New-Cab($ddfFile)
{
 #"Entering the New-Cab function. The DDF File is $ddfFile"
 makecab /f $ddfFile | Out-Null
} #end New-Cab

#############################################
#############################################
##                                         ##
##  Begin Exchange Data Collection Section ##
##                                         ##
#############################################
#############################################

################
# Main Exchange Data Collection Function
################
function Get-ExchangeData {
    "Starting Get-ExchangeData" | WriteTo-StdOut
    trap [Exception] {
        Log-Error $_
        Continue
    }
    
    #Get the machine name
    $machineName = ${env:computername}
    
    #Initialize the Output Filename Prefix and Exchange Server Name variables
    $script:rootOutFile = Join-Path $pwd.Path.ToString() $machinename
    $Script:ExchangeServerName = $null
    Write-DebugLog ("Calling utils_exchange Function: GetExchangeVersionInstalled")
    
    If (($global:ExchInstalled -eq $true) -and ($global:IsExchPSSnapin -eq $true)) #values should be populated by utils_exchange
	{
        if (Get-ExchangeServerLocalCached){#($isExchServerFound = $true){
            Write-DebugLog ("Exchange Server Name: $Script:ExchangeServerName")
            $ExVersion = (Get-ExchangeServerLocalCached).AdminDisplayVersion.Major 
            if ($ExVersion -eq 8){[bool]$script:Exchange2007 = $true}
            elseif ($ExVersion -eq 14){[bool]$script:Exchange2010 = $true}
            Write-DebugLog ("Exchange Version: $ExVersion")

            $ExchangeServer = Get-ExchangeServerLocalCached
			$Script:ExchangeServerName = $ExchangeServer.Name
          
            Write-DebugLog ("Function: GetCommonServerData")
            GetCommonServerData

            Write-DebugLog ("Function: GetIISInfo")
            GetIISInfo

            if($ExchangeServer.IsMailboxServer){
                Write-DebugLog ("Function: GetMailboxServerData")
                GetMailboxServerData
            }
            if($ExchangeServer.IsClientAccessServer){
                Write-DebugLog ("Function: GetClientAccessServerData")
                GetClientAccessServerData
            }
            if($ExchangeServer.IsHubTransportServer){
                Write-DebugLog ("Function: GetHubTransportServerData")
                GetHubTransportServerData
            }
            if($ExchangeServer.IsUnifiedMessagingServer){
                Write-DebugLog ("Function: GetUnifiedMessagingServerData")
                GetUnifiedMessagingServerData
            }
            if(((Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\ExchangeDominoConnector") -eq $true)-or ((Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\MSExchangeCalcon")-eq $true)){
                Write-DebugLog ("Function: GetTransporterSuite")
                GetTransporterSuite
            }
            
            Write-DebugLog ("Done!")
                    
            CollectFiles -filestocollect ($script:rootOutFile + "__GetExchangeData_LOG.TXT") -filedescription ("Get-ExchangeData Script Log" ) -sectiondescription ("zExchange Troubleshooter Logs") -noFileExtensionsOnDescription
            CollectFiles -filestocollect ($script:rootOutFile + "__GetExchangeData_No_Result.TXT") -filedescription "Get-ExchangeData Script cmd without result" -sectiondescription ("zExchange Troubleshooter Logs") -noFileExtensionsOnDescription
        }

    }    
    Else{
        "Exchange Server Not Installed or Exchange Powershell Snapin Failed to Load or Get-ExchangeServer Failed." | WriteTo-StdOut
    }
#
#"Clearing Error." | WriteTo-StdOut
#$Error.Clear()
}

#############################
# Basic data collected for all Exchange server roles
#############################
function GetCommonServerData {
    trap [Exception] {
        Log-Error $_
        Continue
    }
    Set-ReportSection "Exchange Server and Organization Baseline"
    Set-CurrentActivity ($GetExchDataStrings.ID_GetExchDataCollectingAct + " " + $GetExchDataStrings.ID_GetExchServerCommon)
    #[void]$shell.popup($script:RActivity)
    #[void]$shell.popup($GetExchDataStrings.ID_GetExchDataCollectingAct)
    
    $installPath = $global:exinstall
    $exSetup = (Join-Path $installPath \bin\exsetup.exe)
    $script:productversion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exSetup).ProductVersion
	
	#Detect Service Pack
	$script:SPInstalled = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exSetup).ProductMinorPart
	
	#Detect Update Rollup
	If (Test-Path HKLM\SOFTWARE\MICROSOFT\UPDATES)
	{
		$UpdatedProducts = Resolve-Path -Path 'HKLM:SOFTWARE\MICROSOFT\UPDATES\*'
		ForEach ($Product in $UpdatedProducts)
		{
			If ($Product = "Exchange 2007")
			{
				$E2K7Updates_SP = Resolve-Path -Path 'HKLM:SOFTWARE\MICROSOFT\UPDATES\EXCHANGE 2007\*'
				Foreach ($E2K7UpdateSP in $E2K7Updates_SP)
				{
					$E2K7Updates_KB = Resolve-Path -Path 'HKLM:SOFTWARE\MICROSOFT\UPDATES\EXCHANGE 2007\*'
				}
			}
			If ($Product = "Exchange 2010")
			{
			
			}
			
		}
	}
	
    
	#Detect Interim Updates
    $IUDetected = $global:exregSetupKey.GetValue("InterimUpdate")
    If ($IUDetected){
        $script:IUInstalled = $IUDetected.ToString()
    } 
    Else{
        $script:IUInstalled = "None"
    }
    
    # Update MSDT report with Exchange Server version and roles if run under WTP / PowerShell 2.0
    if($Host.Version.Major -ge 2){
        displayExchangeServers
    }

    ExportResults -cmdlet "Write-Output '$Script:ExchangeServerName exsetup.exe ProductVersion: $script:productversion' ; Get-ExchangeServer | Select-Object Name,AdminDisplayVersion,Site,ServerRole" -outformat "FL" -filename "AllExchangeServers" -filedescription "All Exchange Servers - Version Site and Roles"
    ExportResults -cmdlet "Get-ExchangeCertificate" -outformat "FL" -filename "ExchangeCertificate"
    ExportResults -cmdlet "Get-ExchangeServer -identity $Script:ExchangeServerName -status"
    ExportResults -cmdlet "Get-AcceptedDomain"
    ExportResults -cmdlet "Get-RemoteDomain"
    ExportResults -cmdlet "Get-OrganizationConfig"
    ExportResults -cmdlet "Get-EmailAddressPolicy"
    ExportResults -cmdlet "Get-AvailabilityAddressSpace"
    ExportResults -cmdlet "Get-AvailabilityConfig"
    
##### Exchange 2010-specific output #########
    if ($ExchangeVersion -eq 14){
        ExportResults -cmdlet "Get-UserPrincipalNamesSuffix"
        ExportResults -cmdlet "Get-ThrottlingPolicy" #56c20cd2-91c7-48d3-889d-be2a9510569a
        ExportResults -cmdlet "Get-PowerShellVirtualDirectory -Server '$Script:ExchangeServerName'" -outformat "FL"
        If (Get-FederationTrust){
            ExportResults -cmdlet "Get-FederationTrust"
            ExportResults -cmdlet "Test-FederationTrustCertificate"
            ExportResults -cmdlet "Get-FederatedOrganizationIdentifier -IncludeExtendedDomainInfo ?Verbose"
            ExportResults -cmdlet "Get-OrganizationRelationship"
            # Get-FederationInformation -Domain <the hosted Exchange domain namespace> - run against all domains in accepteddomain
			# on O365, run against verified domains from MSOL
			# Get-MSOLDomain returns all domains. One of the properties is status "verified" or "not verified"
			# http://support.microsoft.com/kb/2626696/EN-US
            
        }
        GetHybridConfigLogs
        
    }
#####/End Exchange 2010-specific output #####
#############################################

    Write-DebugLog ("Function: GetFiles -sourcePath $exinstall -targetFolder 'ExchangeConfigFiles' -reportsection 'Exchange Setup Information' -include '*.config' -recurse -cab")
    GetFiles -sourcePath $exinstall -targetFolder "ExchangeConfigFiles" -reportsection "Exchange Setup Information" -include "*.config" -recurse -cab
    
    
    if ($script:paramGetSetupLogs -eq $true){
        $ExchangeSetupLogPath = (Join-Path $global:SystemDrv "ExchangeSetupLogs")
		If (Test-Path $ExchangeSetupLogPath)
		{
			$ExchangeSetupLogPath = Join-Path -Path $ExchangeSetupLogPath -ChildPath "\*.*"
        	CompressCollectFiles -filesToCollect $ExchangeSetupLogPath -fileDescription ("Setup logs modified in past 14 days") -DestinationFileName "ExchangeSetupLogs.zip" -sectionDescription "Exchange Setup Information" -NumberOfDays 14 -Recursive 
        }
    }
    
    
    Write-DebugLog ("Function: GetExchangeRegistryKeys")
    GetExchangeRegistryKeys

#### Exchange Toolbox Output Collection #####
    #Get files from most recent Exchange Performance Troubleshooting Analyzer if less than 14 days old.
    If (Test-Path HKCU:Software\Microsoft\ExchangeServer\v14\ExPTA){
        $PTADataFolderPath = (Get-ItemProperty HKCU:Software\Microsoft\ExchangeServer\v14\ExPTA).DefaultDataFolder
    }
    If (Test-Path HKCU:Software\Microsoft\Exchange\ExPTA){
        $PTADataFolderPath = (Get-ItemProperty -Path HKCU:Software\Microsoft\Exchange\ExPTA -Name DefaultDataFolder)
    }
    If ($null -ne $PTADataFolderPath){
       #$PTADataFolder  = "ExPTA_" + (Split-Path $PTADataFolderPath -Leaf)
        If ((Test-Path $PTADataFolderPath)-and ((Get-Item $PTADataFolderPath).CreationTime -ge (get-date).AddDays(-14))){
            Write-DebugLog ("Function: GetFiles -sourcePath '$PTADataFolderPath' -targetFolder 'ExPTAData' -filedescription 'Exchange Performance Troubleshooting Assistant Files' -include '*.*' -recurse -cab")
            GetFiles -sourcePath "$PTADataFolderPath" -targetFolder "ExPTAData" -filedescription "Exchange Performance Troubleshooting Assistant Files" -reportsection "Exchange Toolbox" -include "*.*" -recurse -cab
        }
    }
    
    #Get files from Exchange Troubleshooting Analyzer Tracing
    $LogLocationXMLFileName = Join-Path -Path $global:exbin -childpath TraceFileConfig.xml
    If (Test-Path $LogLocationXMLFileName){
        [xml]$LogLocationXML = Get-Content -Path $LogLocationXMLFileName
        $ETLLogpath = ($LogLocationXML.selectsinglenode("TraceFile")).getattribute("FilePath")
        If ($null -ne (Get-ChildItem $ETLlogpath -include *.etl -Recurse)){
            Write-DebugLog ("Function: GetFiles -sourcePath '$ETLLogpath' -targetFolder 'ExTRATrace' -filedescription 'Exchange Troubleshooting Analyzer Trace Files' -include '*.etl' -recurse -cab")
            GetFiles -sourcePath "$ETLlogpath" -targetFolder "ExTRATrace" -filedescription "Exchange Troubleshooting Assistant Trace Files" -reportsection "Exchange Toolbox" -include "*.etl" -recurse -agemaxdays "14" -cab
        }
    }
}

#======================================
# Write Exchange Server version and role(s) information to MSDT diagnostic report when running under Win7 Troubleshooting Framework
#======================================
function displayExchangeServers{
    trap [System.Exception]{
    Write-DebugLog ("ERROR: " + $_); Continue}
    
    $allExchangeServers = (Get-ExchangeServer $Script:ExchangeServerName)
    $allExchangeServers_Summary = New-Object PSCustomObject
    #$script:IUInstalled
    foreach ($Server in $allExchangeServers)
	{
        $exServername = $Server.Name
        If ($script:IUInstalled -eq "None"){
            $exServerVersionRole = "ProductVersion:" + $script:productversion + "<br/>" + "InterimUpdate: " + $script:IUInstalled + "<br/>" + "Site: " + $Server.Site + "<br/>" + "Role(s): " + ([system.string]::join(",",($Server.ServerRole)))
        }
        Else{
            $exServerVersionRole = "ProductVersion:" + $script:productversion + "<br/>" + "InterimUpdate: " + $script:IUInstalled + "<br/>" + "Site: " + $Server.Site + "<br/>" + "Role(s): " + ([system.string]::join(",",($Server.ServerRole)))
        }
        Add-Member -InputObject $allExchangeServers_Summary -MemberType NoteProperty -Name $exServername -Value $exServerVersionRole
			# Site
    $sb.AppendFormat("Site: {0}<br/>", $server.Site) | Out-Null
    }
    $allExchangeServers_Summary | ConvertTo-Xml2 | Update-DiagReport -Id 00_ExchangeServer_Summary -Name "Exchange Server Version Site and Role" -Verbosity informational #Get Name from Strings File
    #[void]$shell.popup(($allExchangeServers_Summary | ConvertTo-Xml2).innerxml)
}


##################
# Data Collected for Exchange Mailbox Server Role
##################

function GetMailboxServerData{
    trap [Exception] {
        Log-Error $_
        Continue
    }
    Set-ReportSection "Exchange Mailbox Server Role"
    Set-CurrentActivity ($GetExchDataStrings.ID_GetExchDataCollectingAct + " " + $GetExchDataStrings.ID_GetExchServerMailbox)

    $mailboxDatabases = Get-MailboxDatabase -server $ExchangeServer
    $publicFolderDatabases = Get-PublicFolderDatabase -server $ExchangeServer
    $WorkingDirPath = (get-itemproperty -path HKLM:\SYSTEM\CurrentControlSet\Services\MSExchangeIS\ParametersSystem)."Working Directory"
    
    ExportResults -cmdlet "Get-MailboxServer -identity $Script:ExchangeServerName -Status" -outformat "FL"

    #Dump properties and EDB File Path inventory for each Mailbox Database
    foreach($mailboxDatabase in $mailboxDatabases){
        $mbEdbFilePath = Split-Path -Path ($mailboxDatabase.EdbFilePath) -Parent
        if ($ExchangeVersion -eq 8){
            $mbdbn = ("SG_" + $mailboxDatabase.StorageGroupName + "_DBMb_" + $mailboxDatabase.Name + "_")
            $edbfp = ("SG_" + $mailboxDatabase.StorageGroupName + "_DBMb_" + $mailboxDatabase.name + "_EDBFilePath")
        }
        if ($ExchangeVersion -eq 14){
            $mbdbn = ("DBMb_" + $mailboxDatabase.Name + "_")
            $edbfp = ("DBMb_" + $mailboxDatabase.name + "_EDBFilePath_Contents")
        }
        ExportResults -cmdlet "Get-MailboxDatabase '$mailboxDatabase' -Status" -outformat "FL" -filename "$mbdbn"
        ExportResults -cmdlet "Get-Childitem -path '$mbEdbFilePath'" -outformat "FT" -filename "$edbfp"
    }
    
    #Dump properties, \NON_IPM_SUBTREE and EDB File Path inventory for each Public Folder Database
    if ($null -ne $publicFolderDatabases){
        foreach($publicFolderDatabase in $publicFolderDatabases){
            $pfEDBFilePath = Split-Path -Path ($publicFolderDatabase.EdbFilePath) -Parent
            if ($ExchangeVersion -eq 8){
                $pfdbn = ("SG_" + $publicFolderDatabase.StorageGroupName + "_DBPf_" + $publicFolderDatabase.Name + "_")
                $edbfp = ("SG_" + $publicFolderDatabase.StorageGroupName + "_DBPf_" + $publicFolderDatabase.name + "_EDBFilePath")
                $nipmflds = ("SG_" + $publicFolderDatabase.StorageGroupName + "_DBPf_" + $publicFolderDatabase.name + "_NON_IPM_SUBTREE")
            }
            if ($ExchangeVersion -eq 14){
                $pfdbn = ("DBPf_" + $publicFolderDatabase.Name + "_")
                $edbfp = ("DBPf_" + $publicFolderDatabase.name + "_EDBFilePath")
                $nipmflds = ("DBPf_" + $publicFolderDatabase.name + "_NON_IPM_SUBTREE")
            }
            ExportResults -cmdlet "Get-PublicFolderDatabase '$publicFolderDatabase'" -outformat "FL" -filename "$pfdbn"
            ExportResults -cmdlet "Get-Childitem -path '$pfEDBFilePath'" -outformat "FT" -filename "$edbfp"    
            ExportResults -cmdlet "Get-PublicFolder -server '$ExchangeServer' -identity '\NON_IPM_SUBTREE' -Recurse" -outformat "FT FL CSV" -filename "$nipmflds"
        }
    }
    
    ## Collect any Store.FCL files that are present under Exchange/Logging folder if last write time less than 14 days.
    $FCLLoggingPath = Join-Path $global:exinstall Logging
    $FCLFiles = Get-ChildItem $FCLLoggingPath -Filter *.fcl
    
    If ($null -ne $FCLFiles){
        ForEach ($file in $FCLFiles){
            If ($file.LastWriteTime -ge (Get-Date).AddDays(-14)){
                $collectFCL = $true
            }
        }
        $StoreFCLFolder = "ExchangeStoreFCL" #+ (Split-Path $FCLLoggingPath -Leaf)
        If ($collectFCL -eq $true){
            Write-DebugLog ("Function: GetFiles -sourcePath '$FCLLoggingPath' -targetFolder '$StoreFCLFolder' -filedescription 'Exchange Store.FCL File(s)' -include '*.fcl' -recurse -cab")
            GetFiles -sourcePath "$FCLLoggingPath" -targetFolder "$StoreFCLFolder" -filedescription "Exchange Store.FCL File(s)" -include "*.fcl" -recurse -cab
        }
    }
    


    ###################
    #Exchange 2007-only
    ###################
    if ($ExchangeVersion -eq 8){
        $storageGroups = Get-StorageGroup -Server $ExchangeServer

        #Dump properties for each Storage Group, and log & system folder directory inventory 
        foreach($storageGroup in $storageGroups)
        {
        $sgName = ("SG_" + $storageGroup.name + "_")
        $SgLf = ("SG_" + $storageGroup.name + "_LogFolderPath")
        $SgSf = ("SG_" + $storageGroup.name + "_SystemFolderPath")
        $LogFldPath = $storageGroup.LogFolderPath.PathName
        $SysFldPath = $storageGroup.SystemFolderPath.PathName
            ExportResults -cmdlet "Get-StorageGroup '$storageGroup'" -outformat "FL" -filename "$sgName"
            ExportResults -cmdlet "Get-ChildItem -path '$LogFldPath'" -outformat "FT" -filename "$SgLf"
            ExportResults -cmdlet "Get-ChildItem -path '$SysFldPath'" -outformat "FT" -filename "$SgSf"
        }
        if ($ExchangeServer.IsMemberOfCluster -eq "Yes"){
            ExportResults -cmdlet "Get-ClusteredMailboxServerStatus -Identity '$Script:ExchangeServerName'" -outformat "FL"
            ExportResults -cmdlet "Get-StorageGroupCopyStatus" -outformat "FL"
            
            #Export status of SCR-enabled storage groups if present - Added 04/30/2010
            $SCRSGs = Get-StorageGroup -Server $ExchangeServer | Where-Object {$_.StandbyMachines.Count -gt 0} 
            If ($null -ne $SCRSGs){
                ForEach ($SG in $SCRSGs){
                    $SCRStandbyMachines = $SCRSGs | ForEach-Object {$_.standbymachines}
                    ForEach ($node in $SCRStandbyMachines){
                        $nn = ($node.NodeName).tostring()
                        $fn = ("SG_" + $SG.name + "_StandbyMachine_" + $nn)
                        ExportResults -cmdlet "Get-StorageGroupCopyStatus -Identity '$SG' -StandbyMachine '$nn'" -outformat "FL" -filename "$fn"
                    }    
                }
            }
        }
    }
    
    ###################
    #Begin Exchange 2010-only section
    ###################
    if ($ExchangeVersion -eq 14){
        ExportResults -cmdlet "Get-MailboxDatabaseCopyStatus -Server '$ExchangeServer'" -outformat "FL"
        ExportResults -cmdlet "Get-StoreUsageStatistics -Server '$ExchangeServer'" -outformat "FL"
    
        #Dump Log Folder Path, Database Availability Group properties for each Mailbox Database
        $DAGnames = $null
        foreach($mailboxDatabase in $mailboxDatabases){
            $mbLogFolderPath = $mailboxDatabase.LogFolderPath.PathName
            
            if ($mbEdbFilePath -ne $mbLogFolderPath){
                $fn = ("DBMb_" + $mailboxDatabase.name + "_LogFolderPath")
                ExportResults -cmdlet "Get-ChildItem -path '$mbLogFolderPath'" -outformat "FT" -filename "$fn"
            }
            if ($mailboxDatabase.MasterType -eq "DatabaseAvailabilityGroup"){
                $DAGnames += $mailboxDatabase.MasterServerOrAvailabilityGroup
            }
        }

        if ($null -ne $DAGnames){
            $uDagNames = ($DAGNames | Get-Unique)
            foreach($uDAG in $uDagNames){
                ExportResults -cmdlet "Get-DatabaseAvailabilityGroup -id '$uDAG' -Status" -filename "DAG_$uDAG" 
            }
            ExportResults -cmdlet "Get-DatabaseAvailabilityGroupNetwork -server '$ExchangeServer'" -filename "DAGNetworks" -outformat "FL"
        }
        
        
        #Dump Log Folder Path inventory for each Public Folder Database
        if ($null -ne $publicFolderDatabases){
            foreach($publicFolderDatabase in $publicFolderDatabases){
                $pfLogFolderPath = $publicFolderDatabase.LogFolderPath.PathName
                $fn = ("DBPf_" + $publicFolderDatabase.name + "_LogFolderPath")
                ExportResults -cmdlet "Get-ChildItem -path '$pfLogFolderPath'" -outformat "FT" -filename "$fn"
            }
        }
    }
    
    ##
    #End version-specific information
    ##
    
    #Properties of the server InformationStore object from Active Directory via ADSI
   # $ExchangeServerDn = $ExchangeServer.DistinguishedName
      #$isDn = "CN=InformationStore," + $ExchangeServerDn
      #$LDAPAddress = "LDAP://" + $isDN
      #$InformationStore = [ADSI]$LDAPAddress
    #$ADSI_MSExchISPropertiesFromAD = $InformationStore.psBase.Properties
    ExportResults -cmdlet ('$ADSI_MSExchISPropertiesFromAD') -outformat "FT FL" -filename "InformationStore_ADSIProperties"
    
    #Inventory of files, if any, in MSExchangeIS Working Directory
    If ($null -ne (Get-Childitem -path $WorkingDirPath)){
        ExportResults -cmdlet "Get-ChildItem -Path '$WorkingDirPath' -recurse -Include *.* | Where-Object { !`$_.psiscontainer } | Select-Object DirectoryName, FullName, Length, IsReadOnly, CreationTimeUtc, LastWriteTimeUtc" -outformat "FL" -filename "MSExchangeIS_WorkingDirectory"
    }
}

##################
# Data Collected for Exchange Client Access Server Role
##################

function GetClientAccessServerData {
    trap [Exception] {
        Log-Error $_
        Continue
    }
    Set-ReportSection "Exchange Client Access Server Role"
    Set-CurrentActivity ($GetExchDataStrings.ID_GetExchDataCollectingAct + " " + $GetExchDataStrings.ID_GetExchServerCAS)
    
    Write-DebugLog (Get-ReportSection)
    ExportResults -cmdlet "Get-ClientAccessServer -Identity '$Script:ExchangeServerName'"
    ExportResults -cmdlet "Get-PopSettings -Server '$ExchangeServer'"
    ExportResults -cmdlet "Get-ImapSettings -Server '$ExchangeServer'"
    ExportResults -cmdlet "Get-ActiveSyncVirtualDirectory -Server '$ExchangeServer'"
    ExportResults -cmdlet "Get-ActiveSyncMailboxPolicy"
    ExportResults -cmdlet "Get-OutlookAnywhere -Server '$ExchangeServer'"
    ExportResults -cmdlet "Get-OutlookProvider" #Added 10/29/2010 brianpr
    ExportResults -cmdlet "Get-AutodiscoverVirtualDirectory -Server '$ExchangeServer'"
    ExportResults -cmdlet "Get-OabVirtualDirectory -Server '$ExchangeServer'"
    ExportResults -cmdlet "Get-OwaVirtualDirectory -Server '$ExchangeServer'"
    ExportResults -cmdlet "Get-WebServicesVirtualDirectory -Server '$ExchangeServer'"
    
    $regkeys = "HKLM:SOFTWARE\Microsoft\Rpc\RpcProxy"
      $outfile = ($script:rootOutFile + "_REG_RPCPROXY.TXT")
    RegQuery -RegistryKeys $regKeys -OutputFile $outfile -fileDescription ("HKLM:SOFTWARE\Microsoft\Rpc\RpcProxy*") -sectiondescription (Get-ReportSection) -Recursive $true
    
    Write-DebugLog ("Function: GetIISLogs")
    GetIISLogs
    
    ###################
    #Exchange 2010-only cmdlets
    ###################
    if ($ExchangeVersion -eq 14){
        ExportResults -cmdlet "Get-RPCClientAccess"
        Write-DebugLog ("Function: GetRPCClientAccessLogs")
        GetRPCClientAccessLogs
        Write-DebugLog ("Function: GetAddressBookServiceLogs")
        GetAddressBookServiceLogs
        
        # RID:2944 SSID:f446a1fe-2d73-4adb-91e3-a913afeafae2 DA:20120229
            ExportResults -cmdlet "Get-EcpVirtualDirectory -Server '$ExchangeServer'"
        
        
    }
    
    #####
    #ToDo
    #####
    #Need to get the list of mobile devices to support the following command
    #InvokeExpression(("Get-ActiveSyncDeviceStatistics -Server " + $ExchangeServer.identity))
}

##################
# Data Collected for All Transport Server Roles
##################
function GetCommonTransportServerData(){
    trap [Exception] {
        Log-Error $_
        Continue
    }
    #global:section = "Exchange Transport Server Roles"

    ExportResults -cmdlet "Get-TransportConfig"
    ExportResults -cmdlet "Get-TransportServer -identity '$Script:ExchangeServerName'"
    ExportResults -cmdlet "Get-ReceiveConnector -server '$ExchangeServer'"
    ExportResults -cmdlet "Get-SendConnector"
    ExportResults -cmdlet "Get-TransportAgent"
    ExportResults -cmdlet "Get-TransportPipeline"
    ExportResults -cmdlet "Get-EdgeSubscription"
    ExportResults -cmdlet "Get-Queue"
    
    #Get the newest 4 routing logs
    $TransportServer = Get-TransportServer -identity $Script:ExchangeServerName
    $routingLogPath = ($TransportServer.RoutingTableLogPath.PathName + "\")
    GetFiles -sourcePath "$routingLogPath" -targetFolder "Logs_Routing" -include "Routing*.xml" -Recurse -newest "4" -cab

    #Get the newest 5 agent logs
    If (Test-Path (Join-Path $global:exinstall TransportRoles\Logs\AgentLog\*.log)){
        $AgentLogPath = (Join-Path $global:exinstall TransportRoles\Logs\AgentLog)
        GetFiles -sourcePath "$AgentLogPath" -targetFolder "Logs_Agent" -include "*.log" -Recurse -newest "5" -cab
    }
    
    Write-DebugLog ("Function: GetMessageTrackingLogs")
    GetMessageTrackingLogs
	
	Write-DebugLog ("Function: GetConnectivitylogs")
	GetConnectivitylogs

    ###################
    #Exchange 2010-only
    ###################
    if ($ExchangeVersion -eq 14){
        ExportResults -cmdlet "Get-EdgeSyncServiceConfig"
    }
    
    
    Write-DebugLog ("GetTransportRules")
    GetTransportRules
    
    Write-DebugLog ("GetAntispamConfig")
    GetAntispamConfig
}

function GetTransportRules
{
    trap [Exception] {
        Log-Error $_
        Continue
    }

    ExportResults -cmdlet "Get-TransportRule" -outformat "FL"
    
    if ($ExchangeVersion -eq 8){
        
        #Delete the TransportRuleCollection if it already exists, otherwise script may hang here
        $ExportedTransportRules = $script:rootOutFile + "_ExportedTransportRules.xml"
        If( [System.IO.File]::Exists($ExportedTransportRules) ){
            Remove-Item $ExportedTransportRules
        }
        
        Write-DebugLog ("Export-TransportRuleCollection $ExportedTransportRules")
        Export-TransportRuleCollection $ExportedTransportRules
        CollectFiles -filestocollect ($ExportedTransportRules) -filedescription ("Export-TransportRuleCollection") -sectiondescription (Get-ReportSection) -noFileExtensionsOnDescription
    }
    
    if ($ExchangeVersion -eq 14){
        $ExportedTransportRules = Export-TransportRuleCollection
        Set-Content -Path ($script:rootOutFile + "_ExportedTransportRules.xml") -Value $ExportedTransportRules.FileData -Encoding Byte

        $ExportedLegacyTransportRules = Export-TransportRuleCollection -ExportLegacyRules
        Set-Content -Path ($script:rootOutFile + "_ExportedLegacyTransportRules.xml") -Value $ExportedLegacyTransportRules.FileData -Encoding Byte
        CollectFiles -filestocollect ($script:rootOutFile + "_ExportedTransportRules.xml") -filedescription ("Export-TransportRuleCollection") -sectiondescription (Get-ReportSection) -noFileExtensionsOnDescription
        CollectFiles -filestocollect ($script:rootOutFile + "_ExportedLegacyTransportRules.xml") -filedescription ("Export-TransportRuleCollection -ExportLegacyRules") -sectiondescription (Get-ReportSection) -noFileExtensionsOnDescription    
    }
}

function GetAntiSpamConfig(){
  trap [Exception] {
        Log-Error $_
        Continue
    }

    ExportResults -cmdlet "Get-ContentFilterConfig"
    ExportResults -cmdlet "Get-ContentFilterPhrase"
    ExportResults -cmdlet "Get-IPBlockListConfig"
    ExportResults -cmdlet "Get-IPBlockListEntry"
    ExportResults -cmdlet "Get-IPBlockListProvidersConfig"
    ExportResults -cmdlet "Get-IPBlockListProvider"
    ExportResults -cmdlet "Get-IPAllowListConfig"
    ExportResults -cmdlet "Get-IPAllowListEntry"
    ExportResults -cmdlet "Get-IPAllowListProvidersConfig"
    ExportResults -cmdlet "Get-IPAllowListProvider"
    ExportResults -cmdlet "Get-SenderIdConfig"
    ExportResults -cmdlet "Get-SenderReputationConfig"
    ExportResults -cmdlet "Get-SenderFilterConfig"
    ExportResults -cmdlet "Get-RecipientFilterConfig"
    ExportResults -cmdlet "Get-AntispamUpdates -identity '$Script:ExchangeServerName'"
    
}


##################
# Data Collected for Exchange Hub Server Role
##################
function GetHubTransportServerData(){
	trap [Exception] {
        Log-Error $_
        Continue
    }
    Set-ReportSection "Exchange Hub Transport Server Role"
    Set-CurrentActivity ($GetExchDataStrings.ID_GetExchDataCollectingAct + " " + $GetExchDataStrings.ID_GetExchServerHub)

      Write-DebugLog ("GetCommonTransportServerData")
        GetCommonTransportServerData
    
    ExportResults -cmdlet "Get-ForeignConnector"
    ExportResults -cmdlet "Get-RoutingGroupConnector"
    ExportResults -cmdlet "Get-JournalRule" -outformat "FL" -filename "JournalRules"
    
    ###################
    #Exchange 2010-only
    ###################
    if ($ExchangeVersion -eq 14){
        ExportResults -cmdlet "Get-IRMConfiguration"
    }
}

##################
# Data Collected for Exchange Edge Server Role
##################
function GetEdgeServerData(){
    trap [Exception] {
        Log-Error $_
        Continue
    }
    Set-ReportSection "Exchange Edge Server Role"
    Set-CurrentActivity ($GetExchDataStrings.ID_GetExchDataCollectingAct + " " + $GetExchDataStrings.ID_GetExchServerEdge)

      Write-DebugLog ("GetCommonTransportServerData")
        GetCommonTransportServerData
    ExportResults -cmdlet "Get-AddressRewriteEntry"
    ExportResults -cmdlet "Get-AttachmentFilterListConfig"
    ExportResults -cmdlet "Get-AttachmentFilterEntry"
}

##################
# Data Collected for Exchange Unified Messaging Server Role
##################
function GetUnifiedMessagingServerData(){
    trap [Exception] {
        Log-Error $_
        Continue
    }
    Set-ReportSection "Exchange Unified Messaging Server Role"
    Set-CurrentActivity ($GetExchDataStrings.ID_GetExchDataCollectingAct + " " + $GetExchDataStrings.ID_GetExchServerUM)
    
    ExportResults -cmdlet "Get-UMServer -identity $Script:ExchangeServerName"
    ExportResults -cmdlet "Get-UMDialPlan"
    ExportResults -cmdlet "Get-UMIPGateway"
    ExportResults -cmdlet "Get-UMHuntGroup"
    ExportResults -cmdlet "Get-UMMailboxPolicy"
    ExportResults -cmdlet "Get-UMVirtualDirectory"
    ExportResults -cmdlet "Get-UMAutoAttendant"
    
    foreach ($dialplan in Get-UMDialPlan){
        $DialPlanInCountryOrRegionGroups = $dialplan.ConfiguredInCountryOrRegionGroups
        $DialPlanInternationalGroups = $dialplan.ConfiguredInternationalGroups
        $cFileDialPlanName = ("UMDialPlan_" + $dialplan.Name + "_CountryOrRegionGroups")
        $iFileDialPlanName = ("UMDialPlan_" + $dialplan.Name + "_InternationalGroups")
        ExportResults -cmdlet "'$DialPlanInCountryOrRegionGroups'" -filename "'$cFileDialPlanName'"
        ExportResults -cmdlet "'$DialPlanInternationalGroups'" -filename "'$iFileDialPlanName'"
    }
    
    foreach ($UMAutoAttendant in Get-UMAutoAttendant){
        $UMAA_BusinessHoursKeyMapping = $UMAutoAttendant.BusinessHoursKeyMapping
        $UMAA_AfterHoursKeyMapping = $UMAutoAttendant.AfterHoursKeyMapping
        $bFileUMAAName = ("UMAutoAttendant_" + $UMAutoAttendant.Name + "_BusinessHoursKeyMapping")
        $aFileUMAAName = ("UMAutoAttendant_" + $UMAutoAttendant.Name + "_AfterHoursKeyMapping")
        ExportResults -cmdlet "'$UMAA_BusinessHoursKeyMapping'" -filename "'$bFileUMAAName'"
        ExportResults -cmdlet "'$UMAA_AfterHoursKeyMapping'" -filename "'$aFileUMAAName'"
    }
}

Function GetExchangeRegistryKeys {
    trap [Exception] {
        Log-Error $_
        Continue
    }

    #Collect Exchange HKLM:SYSTEM\CCS\SVCS registry keys and values
    $regkey = "HKLM:SYSTEM\CurrentControlSet\Services"
    $regKeys = Get-ChildItem $regKey | Where-Object{$_.Name -like "*Exchange*"} | FOREACH-OBJECT {$_.name -replace ("HKEY_LOCAL_MACHINE\\","HKLM:")}
    $outfile = ($script:rootOutFile + "_REG_SERVICES_EXCHANGE.TXT")
    RegQuery -RegistryKeys $regKeys -OutputFile $outfile -fileDescription ("HKLM:SYSTEM\CCS\SVCS\*Exchange*") -sectiondescription (Get-ReportSection) -Recursive $true

    #Collect Exchange HKLM:Software\Microsoft\Exchange* keys and values
    $regkey = "HKLM:SOFTWARE\Microsoft" 
    $regKeys = Get-ChildItem $regKey | Where-Object{$_.Name -like "*Exchange*"} | FOREACH-OBJECT {$_.name -replace ("HKEY_LOCAL_MACHINE\\","HKLM:")}
    $outfile = ($script:rootOutFile + "_REG_SOFTWARE_EXCHANGE.TXT")
    RegQuery -RegistryKeys $regKeys -OutputFile $outfile -fileDescription ("HKLM:Software\Microsoft\Exchange*") -sectiondescription (Get-ReportSection) -Recursive $true
    
    #Colect HKLM:Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options keys and values
    $regkey = "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" 
    $regKeys = Get-ChildItem $regKey | FOREACH-OBJECT {$_.name -replace ("HKEY_LOCAL_MACHINE\\","HKLM:")}
    $outfile = ($script:rootOutFile + "_REG_ImageFileExecutionOptions.TXT")
    RegQuery -RegistryKeys $regKeys -OutputFile $outfile -fileDescription ("HKLM:Software\...ImageFileExecutionOptions") -sectiondescription (Get-ReportSection) -Recursive $true

    #Collect Exchange trace key if it is present (unlikely)
    $regkeys = "HKLM:Software\Microsoft\MosTrace"
    $outfile = ($script:rootOutFile + "_REG_MOSTRACE.TXT")

    RegQuery -RegistryKeys $regKeys -OutputFile $outfile -fileDescription ("HKLM:Software\Microsoft\MosTrace") -sectiondescription (Get-ReportSection) -Recursive $true

    #Collect Windows Installer keys and values for the installed version of Exchange
    If ($global:ExchangeVersion -eq "14"){
        [array]$regkeys = "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\AE1D439464EB1B8488741FFA028E291C"
    }
    Else{
        [array]$regkeys = "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\461C2B4266EDEF444B864AD6D9E5B613"
    }
    
    #If found, add Windows Installer Patch keys for the installed version of Exchange
    $exchPatchesKey = Join-Path $regkeys[0] Patches
    If ((Get-ChildItem $exchPatchesKey).count -gt 0){
        $regkeys += Get-ChildItem $exchPatchesKey | ForEach-Object {Join-Path HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Patches (Split-Path $_.Name -Leaf)}
    }
    
    $outfile = ($script:rootOutFile + "_REG_INSTALLER_EXCHANGE.TXT")
    RegQuery -RegistryKeys $regKeys -OutputFile $outfile -fileDescription ("HKLM:SOFTWARE\..\Installer\[Exchange]") -sectiondescription "Exchange Setup Information" -Recursive $true
}

function GetTransporterSuite(){
    Set-ReportSection "Exchange Transporter Suite"
    Set-CurrentActivity ($GetExchDataStrings.ID_GetExchDataCollectingAct + " " + $GetExchDataStrings.ID_GetExchServerTransSuite)
    trap [Exception] {
        Log-Error $_
        Continue
    }
    $ExchangeDominoConnector = $null
    $CalCon = $null
    
    $ExchangeDominoConnector = (get-item HKLM:\SYSTEM\CurrentControlSet\Services\ExchangeDominoConnector)
    $CalCon = (Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\MSExchangeCalcon)
    
    #Load snap-ins if either of these is available
    if(($null -ne $ExchangeDominoConnector) -or ($null -ne $CalCon)){
        Add-PSSnapin -Name "Microsoft.Exchange.Transporter.DominoConnector"
        Add-PSSnapin -Name "Microsoft.Exchange.Transporter"
    }
    #$TransporterBin = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Transporter).ApplicationBase
    
    #Calendar Connector is installed
    if($null -ne $CalCon){
        ExportResults -cmdlet "Get-DominoFreeBusyConnector"
    }
    
    #Exchange Domino Connector is installed
    if($null -ne $ExchangeDominoConnector){
        ExportResults -cmdlet "Get-DominoDirectoryConnector"
        
        $DominoDirectoryConnectors = Get-DominoDirectoryConnector
        foreach($dominoDirectoryConnector in $DominoDirectoryConnectors){
            #Try to get the Notes.ini file
            $notesini = $dominoDirectoryConnector.NotesINIFile
            
            if($null -ne $notesini){
                if([System.IO.File]::Exists($notesini)){
                    $iniFile = ($pwd.Path.ToString() + "\" + $dominoDirectoryConnector.Name.ToString() + "_Notes.ini")
                    copy-item -path $notesini -destination $iniFile -recurse
                    GetFiles -sourcePath "$iniFile" -recurse
                }
                else{
                    $iniFileMissing = ($pwd.Path.ToString() + "\" + $dominoDirectoryConnector.Name.ToString() + "_Missing_Notes.ini")
                    out-file -filepath $iniFileMissing -InputObject ("Notes.INI file for " + $dominoDirectoryConnector.Name.ToString() + " is missing!!!")
                    GetFiles -sourcePath "$iniFileMissing"
                }
            }
        }
    }
}

##################
# Collect IIS-related information
##################
function GetIISInfo {
    trap [Exception] {
        Log-Error $_
        Continue
    }
    Set-ReportSection "Exchange Server IIS Information"
    Set-CurrentActivity ($GetExchDataStrings.ID_GetExchDataCollectingAct + " " + $GetExchDataStrings.ID_GetExchServerIIS)

    #$CopyToPath = ($pwd.Path.ToString())
    #$inetSrvPath = (join-path $env:systemroot system32\inetsrv)
    $metabase_xml = ($env:systemroot + "\system32\inetsrv\metabase.xml")
    $filePrefix = ($env:COMPUTERNAME + "_")
    $regkeys = "HKLM:SYSTEM\CurrentControlSet\Services\IISADMIN", "HKLM:SYSTEM\CurrentControlSet\Services\InetInfo","HKLM:SYSTEM\CurrentControlSet\Services\W3SVC", "HKLM:SYSTEM\CurrentControlSet\Services\msdtc", "HKLM:SOFTWARE\Microsoft\Transaction Server", "HKLM:SOFTWARE\Microsoft\InetStp", "HKLM:SOFTWARE\Microsoft\InetMGR", "HKLM:SOFTWARE\Microsoft\Keyring"
    $outfile = ($script:rootOutFile + "_REG_IIS.TXT")
    RegQuery -RegistryKeys $regKeys -OutputFile $outfile -fileDescription ("IIS and Related Registry Keys/Values") -sectiondescription (Get-ReportSection) -Recursive $true

    GetFiles -sourcePath "$metabase_xml" -filedescription "IIS Metabase" -prefix $filePrefix -sectiondescription (Get-ReportSection)
}
########################
# Collect and .cab two most recent IIS logs for every website (called only if CAS role is detected)
########################
function GetIISLogs{
    trap [Exception] {
        Log-Error $_
        Continue
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
            GetFiles -sourcePath $w3logpath -targetFolder "$tfldr" -reportsection "Exchange Server IIS Information" -filedescription "Logs_$slf (newest two)" -include "*.log" -recurse -cab -newest "2"
        }
        Else{
            Write-DebugLog ("GetIISLogs: IIS Log Path was expected but not found on filesystem: " + $w3logpath)
        }
    }
}

########################
# Collect and .zip two most recent RPC Client Access Logs (called only if CAS role is detected)
########################
function GetRPCClientAccessLogs{
    trap [Exception] {
        Log-Error $_
        Continue
    }
    
    $LogLocationXMLFileName = Join-Path -Path $global:exbin -childpath Microsoft.Exchange.RpcClientAccess.Service.exe.config
    If (Test-Path $LogLocationXMLFileName)
	{
        [xml]$LogLocationXML = Get-Content -Path $LogLocationXMLFileName
        $RPCLogPathFromConfig = $loglocationxml.configuration.appsettings.selectsinglenode("add[@key='LogPath']").value
        If ($rpclogpathfromconfig.tolower().startswith("%exchangeinstalldir%") -eq $true)
		{
            $RPCLogPath = $RPCLogPathFromConfig.replace("%ExchangeInstallDir%\",$global:exinstall)
        }
        Else
		{
            $RPCLogPath = $RPCLogPathFromConfig
        }
    }
    
    if (Test-Path $RPCLogPath){
		If ($rpclogpathfromconfig.tolower().endswith("\") -eq $false)
		{
			$RPCLogPath += "\"
		}
		Write-DebugLog ("RPC Client Access Log Path: '$RPCLogPath'")
        CompressCollectFiles -filesToCollect ($RPCLogPath + '*.log')-fileDescription ("RPCClientAccess logs modified in past 5 days") -DestinationFileName "Logs_RPCClientAccess.zip" -sectionDescription (Get-ReportSection) -NumberOfDays 5 #-Recursive 
    }
	Else
	{
        Write-DebugLog ("Logs_RPCCLientAccess: No Files Found to Zip At '$RPCLogPath'")
	}
}

########################
# Collect and .zip two most recent AddressBook Service Logs (called only if CAS role is detected)
########################
function GetAddressBookServiceLogs{
    trap [Exception] {
        Log-Error $_
        Continue
    }
    
    $LogLocationXMLFileName = Join-Path -Path $global:exbin -childpath Microsoft.Exchange.addressbook.Service.exe.config
    If (Test-Path $LogLocationXMLFileName){
        [xml]$LogLocationXML = Get-Content -Path $LogLocationXMLFileName
        $ABServiceLogPath = $loglocationxml.configuration.appsettings.selectsinglenode("add[@key='LogFilePath']").value
    }
    
    If (Test-Path $ABServiceLogPath){
        $ABServiceLogs = Get-ChildItem $ABServiceLogPath | Where-Object {!$_.psiscontainer } | Sort-Object LastWriteTime -Descending | select-object -First 2
        "ABService Logs: " + $ABServiceLogs | WriteTo-StdOut
        if ($ABServiceLogs.length -gt 0){
            $ABServiceLogsZipFile = out-zip -FilePath $ABServiceLogs -zipFileName "Logs_AddressBookService"
            CollectFiles -filestocollect ($ABServiceLogsZipFile) -filedescription ("Logs_AddressBookService") -sectiondescription (Get-ReportSection) #-noFileExtensionsOnDescription
        }
            Else{
            Write-DebugLog ("Logs_AddressBookService: No Files Found to Zip At '$ABServiceLogPath'")
        }
    }
}

########################
# Collect and .zip 5 most recent Connectivity Logs (called only if Transport role is detected)
########################
function GetConnectivitylogs{
    trap [Exception] {
        Log-Error $_
        Continue
    }
 
    $Connectivitylogpath = (Get-TransportServerCached).connectivitylogpath.PathName

    
    If (Test-Path $Connectivitylogpath){
        $ConnectivityLogs = Get-ChildItem $Connectivitylogpath | Where-Object {!$_.psiscontainer } | Sort-Object LastWriteTime -Descending | select-object -First 5
        "Connectivity Logs: " + $ConnectivityLogs | WriteTo-StdOut
        if ($ConnectivityLogs.length -gt 0){
            $ConnectivityLogsZipFile = out-zip -FilePath $ConnectivityLogs -zipFileName "Logs_Connectivity"
            CollectFiles -filestocollect ($ConnectivityLogsZipFile) -filedescription ("Logs_Connectivity") -sectiondescription (Get-ReportSection) #-noFileExtensionsOnDescription
        }
            Else{
            Write-DebugLog ("Logs_Connectivity: No Files Found to Zip At '$Connectivitylogpath'")
        }
    }
}


########################
# Collect and .zip 5 most recent Message Tracking Logs (called only if Transport role is detected)
########################
function GetMessageTrackingLogs{
    trap [Exception] {
        Log-Error $_
        Continue
    }

    $MessageTrackingLogPath = (Get-TransportServerCached).MessageTrackingLogPath.PathName
    
    If (Test-Path $MessageTrackingLogPath){
        $MessageTrackingLogs = Get-ChildItem $MessageTrackingLogPath | Where-Object {!$_.psiscontainer } | Sort-Object LastWriteTime -Descending | select-object -First 5
        "Message Tracking Logs: " + $MessageTrackingLogs | WriteTo-StdOut
        if ($MessageTrackingLogs.length -gt 0){
            $MessageTrackingLogsZipFile = out-zip -FilePath $MessageTrackingLogs -zipFileName "Logs_MessageTracking"
            CollectFiles -filestocollect ($MessageTrackingLogsZipFile) -filedescription ("Logs_MessageTracking") -sectiondescription (Get-ReportSection) #-noFileExtensionsOnDescription
        }
            Else{
            Write-DebugLog ("Logs_MessageTracking: No Files Found to Zip At '$MessageTrackingLogPath'")
        }
    }
}

########################
# Collect and .zip two most recent Update-HybridConfiguration Logs if present
########################
function GetHybridConfigLogs{
    trap [Exception] {
        Log-Error $_
        Continue
    }
    
    $HybridConfigLogPath = Join-Path -Path $global:exinstall -ChildPath "Logging\Update-HybridConfiguration"
    
    If (Test-Path $HybridConfigLogPath){
        $HybridConfigLogs = Get-ChildItem $HybridConfigLogPath | Where-Object {!$_.psiscontainer } | Sort-Object LastWriteTime -Descending | select-object -First 2
        "HybridConfiguration Logs: " + $HybridConfigLogs | WriteTo-StdOut
        if ($HybridConfigLogs.length -gt 0){
            $HybridConfigLogsZipFile = out-zip -FilePath $HybridConfigLogs -zipFileName "Logs_Update-HybridConfiguration"
            CollectFiles -filestocollect ($HybridConfigLogsZipFile) -filedescription ("Logs_Update-HybridConfiguration") -sectiondescription (Get-ReportSection) #-noFileExtensionsOnDescription
        }
            Else{
            Write-DebugLog ("Logs_Update-HybridConfiguration: No Files Found to Zip At '$HybridConfigLogPath'")
        }
    }
}

############################################################# 
#                                                           # 
# Script Starts Here                                        #
#                                                           #
#############################################################
    
#======================================
# Load localized strings
#======================================
Import-LocalizedData -BindingVariable GetExchDataStrings

#======================================
# Set global variables regardless of Exchange version inestalled
#======================================
$global:SystemDrv = (Get-ChildItem env:systemdrive).value


#======================================
# Tracks Script Execution count and disables confirmation
#======================================
$script:count = 0
$ConfirmPreference = "NONE"
$script:executedNoResults

If ($getExBPA){$script:paramGetExBPA = $true}
If ($getSetupLogs){$script:paramGetSetupLogs = $true}
#======================================
# Call the  Get-ExchangeData function
#======================================

"Calling Get-ExchangeData" | WriteTo-StdOut
    Get-ExchangeData

# Collect Debug logs
Collect-DebugLog


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA6oHLN04ZHiwX2
# 0WDSrUJUeA7i88htoxV/LjVJ4qS3DKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGHXHYFRsZWXN3+69KkHEJdd
# Lle6wzgtep5x1eyBhTMCMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCPVwDUdl5lE91gJAQeF0RyzKiszEBEe0ZAuDtnBDJmP4tn0wjP0MlY
# jhQbnskMkLAkS8cvFenJ6Z7pVQB+uz46KCKAiKH6c19MWBnZp9oOA2keHIQzLEjD
# ZgBWSws0AZCDvwcADxYleDbwkBGSOW1F0Zh+/3PI2YAqY6Ck7Yjo1Rw6yK1hSZl2
# b7XWNyzInmqcF1hZopvlWY9RlrySdBuwIbJBdKVfikTWSi3eQUVPkusKVZFcdIfs
# uTRlmFmWoIK6A5DDnY4GRnzeyy3Mk759LlXvyXrEQMfs62l5AGHmpgQBnIVpzyfb
# xilsTqE+FXO77mEF2Ni4y51nmrsf2LdioYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIHFNFznlpEfevN3R8sNJteXzTmebUIo/PyQTZGcfmyZrAgZi1VDl
# wfkYEzIwMjIwODAxMDc0MDIwLjAzOFowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjdCRjEt
# RTNFQS1CODA4MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGfK0U1FQguS10AAQAAAZ8wDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTIyWhcNMjMwMjI4MTkwNTIyWjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046N0JGMS1FM0VBLUI4MDgxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCk9Xl8TVGyiZAvzm8tB4fLP0znL883YDIG03js1/Wz
# CaICXDs0kXlJ39OUZweBFa/V8l27mlBjyLZDtTg3W8dQORDunfn7SzZEoFmlXaSY
# cQhyDMV5ghxi6lh8y3NV1TNHGYLzaoQmtBeuFSlEH9wp6rC/sRK7GPrOn17XAGzo
# +/yFy7DfWgIQ43X35ut20TShUeYDrs5GOVpHp7ouqQYRTpu+lAaCHfq8tr+LFqIy
# jpkvxxb3Hcx6Vjte0NPH6GnICT84PxWYK7eoa5AxbsTUqWQyiWtrGoyQyXP4yIKf
# TUYPtsTFCi14iuJNr3yRGjo4U1OHZU2yGmWeCrdccJgkby6k2N5AhRYvKHrePPh5
# oWHY01g8TckxV4h4iloqvaaYGh3HDPWPw4KoKyEy7QHGuZK1qAkheWiKX2qE0eNR
# WummCKPhdcF3dcViVI9aKXhty4zM76tsUjcdCtnG5VII6eU6dzcL6YFp0vMl7JPI
# 3y9Irx9sBEiVmSigM2TDZU4RUIbFItD60DJYzNH0rGu2Dv39P/0Owox37P3ZfvB5
# jAeg6B+SBSD0awi+f61JFrVc/UZ83W+5tgI/0xcLGWHBNdEibSF1NFfrV0KPCKfi
# 9iD2BkQgMYi02CY8E3us+UyYA4NFYcWJpjacBKABeDBdkY1BPfGgzskaKhIGhdox
# 9QIDAQABo4IBNjCCATIwHQYDVR0OBBYEFGI08tUeExYrSA4u6N/ZasfWHchhMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAB2KKCk8O+kZ8+m9bPXQIAmo+6xbKDaKkMR3/82A8XVAMa9RpItYJkdkta+C
# 6ZIVBsZEARJkKnWpYJiiyGBV3PmPoIMP5zFbr0BYLMolDJZMtH3MifVBD9NknYNK
# g+GbWyaAPs8VZ6UD3CRzjoVZ2PbHRH+UOl2Yc/cm1IR3BlvjlcNwykpzBGUndARe
# fuzjfRSfB+dBzmlFY+dME8+J3OvveMraIcznSrlr46GXMoWGJt0hBJNf4G5JZqyX
# e8n8z2yR5poL2uiMRzqIXX1rwCIXhcLPFgSKN/vJxrxHiF9ByViouf4jCcD8O2mO
# 94toCSqLERuodSe9dQ7qrKVBonDoYWAx+W0XGAX2qaoZmqEun7Qb8hnyNyVrJ2C2
# fZwAY2yiX3ZMgLGUrpDRoJWdP+tc5SS6KZ1fwyhL/KAgjiNPvUBiu7PF4LHx5TRF
# U7HZXvgpZDn5xktkXZidA4S26NZsMSygx0R1nXV3ybY3JdlNfRETt6SIfQdCxRX5
# YUbI5NdvuVMiy5oB3blfhPgNJyo0qdmkHKE2pN4c8iw9SrajnWcM0bUExrDkNqcw
# aq11Dzwc0lDGX14gnjGRbghl6HLsD7jxx0+buzJHKZPzGdTLMFKoSdJeV4pU/t3d
# PbdU21HS60Ex2Ip2TdGfgtS9POzVaTA4UucuklbjZkQihfg2MIIHcTCCBVmgAwIB
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
# IEVTTjo3QkYxLUUzRUEtQjgwODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAdF2umB/yywxFLFTC8rJ9Fv9c9reg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRmxgwIhgPMjAyMjA4MDEwODIxNDRaGA8yMDIyMDgwMjA4MjE0NFow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pGbGAIBADAKAgEAAgIbQwIB/zAHAgEA
# AgIRqjAKAgUA5pLsmAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAEg80CEF
# JzLl8HeAJ/hZbnWQNsuIwu49g6NyKJi5qDBmnp/p+lUYWLzptwQ8IZws+2i1BWTq
# rded+t2dg1o3aCvWO7+8zpJUL+MYbToFai4eHsm4gREbd8MJ20XBPG8dyFA9AHGL
# CNzy86mPSsSureH5EZOyVbA1/999a8cmYWEOMYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGfK0U1FQguS10AAQAAAZ8wDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgrKr23KXxhPbXf8mD84a9RUUN+nS8/5Fng7gXbfrDRgkwgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCG8V4poieJnqXnVzwNUejeKgLJfEH7
# P+jspyw3S3xc2jCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABnytFNRUILktdAAEAAAGfMCIEIOlIiYcAkE7hdl0Wdg0v2Y1xxRsJuCeW
# RwNv6bySR2rrMA0GCSqGSIb3DQEBCwUABIICAF/670F050R8C17HIBKXAYFf5jwg
# tYvE5iHIe1u0UrPVyIGtM3dsHvS8DhTQhOiCpb1lm/UFop38zAoeqFNgQmpyY5vj
# wJyDoSbfr4wChHunKeY5goR0D487shkRBmLB6c00VF+Oe50xbvl3VHbgHox6Fglx
# doE+vAh11krar8te7xhIhNMGzpUF3UxwjjaXU0vXmPK4zNjhDoV8Z/UObfqTWNK7
# IFpweeCXD/t1XGXzwr3pEfObjm6tf04WSk5g4t2HgK8aHeG4rhcmcWqimA3O8YfX
# 2oe6VwyqOw5ohtSMDhAcWlJ2dmoUIdCKkGEAb5lNDRFqBMHdlotf9GWzxPPwyK9U
# KeOIq2rwjcLP6EwmsW0zs+Cryxbuxp5JDQadtivWSCQH9jW7XZzhu9fm7+XkXfO1
# zInyttY7YZDgCmBO2QS+96YJwipfq8xLKwTPRefCBNoNFAgy5e6VPvQyK1CLLtot
# KCugQgdsSDNOR4w23ekWKuztUra0ja3tNhf5Gih/ahEDJEN/0+DsQG8dfoH37AxZ
# IQSJJKkNe4oYxPa/h2HA6S45R2QH9seHPez2BrkpHGC6A6QeUEPtaeei8F04ZOwj
# C0R6LUgnJoLcMZsRKudbg5ksSq+t/Q94vCPnfnt4vrwJeT8EO0sRkML1abVLyVYh
# msC+VUCew9xjA1tl
# SIG # End signature block
