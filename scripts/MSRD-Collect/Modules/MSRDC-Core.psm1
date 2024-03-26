<#
.SYNOPSIS
   Scenario module for collecting Microsoft Remote Desktop Core related data

.DESCRIPTION
   Collect 'Core' troubleshooting data, suitable for generic Microsoft Remote Desktop troubleshooting

.NOTES
   Authors    : Robert Klemencz (Microsoft) & Alexandru Olariu (Microsoft)
   Requires   : At least PowerShell 5.1 (This module is not for stand-alone use. It is used automatically from within the main MSRD-Collect.ps1 script)
   Version    : See MSRD-Collect.ps1 version
   Feedback   : Send an e-mail to MSRDCollectTalk@microsoft.com
#>

$msrdLogPrefix = "Core"
$msrdCertLogFolder = $global:msrdBasicLogFolder + "Certificates\"
$msrdDumpFolder = $global:msrdBasicLogFolder + "Dumps\"
$msrdMonTablesFolder = $global:msrdGenevaLogFolder + "MonTables\"
$msrdMonConfigFolder = $global:msrdGenevaLogFolder + "Configuration\"
$msrdRDClientFolder = $global:msrdBasicLogFolder + "RDClient\"

$bodyRDLS = '<style>
BODY { background-color:#E0E0E0; font-family: sans-serif; font-size: small; }
table { background-color: white; border-collapse:collapse; border: 1px solid black; padding: 10px; }
td { padding-left: 10px; padding-right: 10px; }
</style>'

$global:msrdFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName

Add-Type -MemberDefinition @"
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint NetApiBufferFree(IntPtr Buffer);
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int NetGetJoinInformation(
    string server,
    out IntPtr NameBuffer,
    out int BufferType);
"@ -Namespace Win32Api -Name NetApi32


Function msrdGetMonTables {

    #get AVD monitoring tables data
    msrdLogMessage Normal ("[Core] msrdGetMonTables")
    $MTfolder = 'C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Monitoring\Tables'

    if (Test-path -path $MTfolder) {
        msrdCreateLogFolder $msrdMonTablesFolder

        Try {
            Switch(Get-ChildItem -Path "C:\Program Files\Microsoft RDInfra\") {
                {$_.Name -match "RDMonitoringAgent"} {
                    $convertpath = "C:\Program Files\Microsoft RDInfra\" + $_.Name + "\Agent\table2csv.exe"
                }
            }
        } Catch {
            msrdLogException ("ERROR: An error occurred during preparing Monitoring Tables conversion") -ErrObj $_ $fLogFileOnly
            Continue
        }

        Try {
            Switch(Get-ChildItem -Path $MTfolder) {
                {($_.Name -notmatch "00000") -and ($_.Name -match ".tsf")} {
                    $monfile = $MTfolder + "\" + $_.name
                    cmd /c $convertpath -path $msrdMonTablesFolder $monfile 2>&1 | Out-Null
                }
            }
        } Catch {
            msrdLogException ("ERROR: An error occurred during getting Monitoring Tables data") -ErrObj $_ $fLogFileOnly
            Continue
        }

    } else {
        msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] Monitoring\Tables folder not found."
    }
}

Function msrdGetMonConfig {

    #get AVD monitoring configuration
    msrdLogMessage Normal ("[Core] msrdGetMonConfig")
    $MCfolder = 'C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Monitoring\Configuration'

    if (Test-path -path $MCfolder) {
        Try {
            Copy-Item $MCfolder $msrdMonConfigFolder -Recurse -ErrorAction Continue 2>&1 | Out-Null
        } Catch {
            msrdLogException ("Error: An error occurred during getting Monitoring Configuration data") -ErrObj $_ $fLogFileOnly
        }

    } else {
        msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] Monitoring\Configuration folder not found."
    }
}

Function msrdGetWinRMConfig {

    #get WinRM information
    msrdLogMessage Normal ("[$msrdLogPrefix] Exporting WinRM configuration")
    if ((get-service -name WinRM).status -eq "Running") {
        Try {
            $config = Get-ChildItem WSMan:\localhost\ -Recurse -ErrorAction Continue 2>>$global:msrdErrorLogFile
            if (!($config)) {
                msrdLogMessage WarnLogFileOnly ("[$msrdLogPrefix] Cannot connect to localhost, trying with FQDN " + $global:msrdFQDN)

                try {
                    Connect-WSMan -ComputerName $global:msrdFQDN -ErrorAction Continue 2>>$global:msrdErrorLogFile
                    $config = Get-ChildItem WSMan:\$global:msrdFQDN -Recurse -ErrorAction Continue 2>>$global:msrdErrorLogFile
                    Disconnect-WSMan -ComputerName $global:msrdFQDN -ErrorAction Continue 2>>$global:msrdErrorLogFile
                } catch {
                    msrdLogException ("ERROR: An error occurred during msrdGetWinRMConfig / Connect-WSMan") -ErrObj $_ $fLogFileOnly
                }
            }
            $config | Format-Table Name, Value -AutoSize -Wrap | out-file -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "WinRM-Config.txt")
        } Catch {
            msrdLogException ("ERROR: An error occurred during msrdGetWinRMConfig") -ErrObj $_ $fLogFileOnly
        }

        Try {
            winrm get winrm/config | Format-Table Name, Value -AutoSize -Wrap 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "WinRM-Config.txt")
        } Catch {
            msrdLogException ("ERROR: An error occurred during winrm get winrm/config") -ErrObj $_ $fLogFileOnly
        }

        Try {
            winrm e winrm/config/listener | Format-Table Name, Value -AutoSize -Wrap 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "WinRM-Config.txt")
        } Catch {
            msrdLogException ("ERROR: An error occurred during winrm e winrm/config/listener") -ErrObj $_ $fLogFileOnly
        }

    } else {
        msrdLogMessage Error ("[$msrdLogPrefix] WinRM service is not running. Skipping collection of WinRM configuration data.")
    }
}

Function msrdGetNBDomainName {

    $pNameBuffer = [IntPtr]::Zero
    $joinStatus = 0
    $apiResult = [Win32Api.NetApi32]::NetGetJoinInformation(
        $null,               # lpServer
        [Ref] $pNameBuffer,  # lpNameBuffer
        [Ref] $joinStatus    # BufferType
    )
    if ($apiResult -eq 0) {
        [Runtime.InteropServices.Marshal]::PtrToStringAuto($pNameBuffer)
        [Void] [Win32Api.NetApi32]::NetApiBufferFree($pNameBuffer)
    }
}

Function msrdGetRdClientAutoTrace {

    #get AVD RDClientAutoTrace files
    if ($global:msrdUserprof) {
        $MSRDCfolder = 'C:\Users\' + $global:msrdUserprof + '\AppData\Local\Temp\DiagOutputDir\RdClientAutoTrace\*'
    } else {
        $MSRDCfolder = $env:USERPROFILE + '\AppData\Local\Temp\DiagOutputDir\RdClientAutoTrace\*'
    }

    if (Test-path -path $MSRDCfolder) {
        msrdCreateLogFolder $msrdRDClientFolder

        msrdLogMessage Normal ("[$msrdLogPrefix] Copy-Item $MSRDCfolder")
        #Getting only traces from over the past 5 days
        (Get-ChildItem $MSRDCfolder).LastWriteTime | ForEach-Object {
            if (([datetime]::Now - $_).Days -le "5") {
                Try {
                    Copy-Item $MSRDCfolder $msrdRDClientFolder -Recurse -ErrorAction Continue 2>&1 | Out-Null
                } Catch {
                    msrdLogException ("Error: An exception occurred in msrdGetRdClientAutoTrace.") -ErrObj $_ $fLogFileOnly
                    Continue
                }
            }
        }
    } else {
        msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] '$MSRDCfolder' folder not found."
    }
}

Function msrdGetRdClientSub {

    #get AVD RD Client subscription information
    if ($global:msrdUserprof) {
        $MSRDCsub = 'C:\Users\' + $global:msrdUserprof + '\AppData\Local\rdclientwpf\ISubscription.json'
    } else {
        $MSRDCsub = $env:USERPROFILE + '\AppData\Local\rdclientwpf\ISubscription.json'
    }

    if (Test-path -path $MSRDCsub) {
        msrdCreateLogFolder $msrdRDClientFolder

        msrdLogMessage Normal ("[$msrdLogPrefix] Copy-Item $MSRDCsub")
        Try {
            Copy-Item $MSRDCsub $msrdRDClientFolder -ErrorAction Continue 2>&1 | Out-Null
        } Catch {
            msrdLogException ("Error: An exception occurred in msrdGetRdClientSub.") -ErrObj $_ $fLogFileOnly
        }
    } else {
        msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] '$MSRDCsub' not found."
    }
}

Function msrdFileVersion {
    param([string] $FilePath, [bool] $Log = $false)

    if (Test-Path -Path $FilePath) {
        $fileobj = Get-item $FilePath
        $filever = $fileobj.VersionInfo.FileMajorPart.ToString() + "." + $fileobj.VersionInfo.FileMinorPart.ToString() + "." + $fileobj.VersionInfo.FileBuildPart.ToString() + "." + $fileobj.VersionInfo.FilePrivatepart.ToString()

        if ($log) {
            ($FilePath + "," + $filever + "," + $fileobj.CreationTime.ToString("yyyyMMdd HH:mm:ss")) 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "KeyFileVersions.csv")
        }
        return $filever | Out-Null
    } else {
        return ""
    }
}

function msrdGetRDLSDB {

    #get RD licensing database information
    $RDSLSKP = msrdGetRDRoleInfo Win32_TSLicenseKeyPack "root\cimv2"
    if ($RDSLSKP) {
        $KPtitle = "Installed RDS license packs"
        $RDSLSKP | ConvertTo-Html -Title $KPtitle -body $bodyRDLS -Property PSComputerName, ProductVersion, Description, TypeAndModel, TotalLicenses, AvailableLicenses, IssuedLicenses, KeyPackId, KeyPackType, ProductVersionId, AccessRights, ExpirationDate | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdls_LicenseKeyPacks.html")
    } else {
        msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] [WARNING] Failed to get Win32_TSLicenseKeyPack."
    }

    $RDSLSIL = msrdGetRDRoleInfo Win32_TSIssuedLicense "root\cimv2"
    if ($RDSLSIL) {
        $KPtitle = "Issued RDS licenses"
        $RDSLSIL | ConvertTo-Html -Title $KPtitle -body $bodyRDLS -Property PSComputerName, LicenseId, sIssuedToUser, sIssuedToComputer, IssueDate, ExpirationDate, LicenseStatus, KeyPackId, sHardwareId | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdls_IssuedLicenses.html")
    } else {
        msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] [WARNING] Failed to get Win32_TSIssuedLicense."
    }
}

function msrdGetRDGW {

    #get RD Gateway information
    $RDSGWLB = msrdGetRDRoleInfo Win32_TSGatewayLoadBalancer root\cimv2\TerminalServices
    if ($RDSGWLB)
    { $RDSGWLB | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdgw_LoadBalancer.txt") }
    else { msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] [WARNING] Failed to get Win32_TSGatewayLoadBalancer." }

    $RDSGWRAD = msrdGetRDRoleInfo Win32_TSGatewayRADIUSServer root\cimv2\TerminalServices
    if ($RDSGWRAD)
    { $RDSGWRAD | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdgw_RADIUSServer.txt") }
    else { msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] [WARNING] Failed to get Win32_TSGatewayRADIUSServer." }

    $RDSGWRAP = msrdGetRDRoleInfo Win32_TSGatewayResourceAuthorizationPolicy root\cimv2\TerminalServices
    if ($RDSGWRAP)
    { $RDSGWRAP | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdgw_ResourceAuthorizationPolicy.txt") }
    else { msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] [WARNING] Failed to get Win32_TSGatewayResourceAuthorizationPolicy." }

    $RDSGWCAP = msrdGetRDRoleInfo Win32_TSGatewayConnectionAuthorizationPolicy root\cimv2\TerminalServices
    if ($RDSGWCAP)
    { $RDSGWCAP | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdgw_ConnectionAuthorizationPolicy.txt") }
    else { msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] [WARNING] Failed to get Win32_TSGatewayConnectionAuthorizationPolicy." }

    $RDSGWRG = msrdGetRDRoleInfo Win32_TSGatewayResourceGroup root\cimv2\TerminalServices
    if ($RDSGWRG)
    { $RDSGWRG | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdgw_ResourceGroup.txt") }
    else { msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] [WARNING] Failed to get Win32_TSGatewayResourceGroup." }

    $RDSGWS = msrdGetRDRoleInfo Win32_TSGatewayServerSettings root\cimv2\TerminalServices
    if ($RDSGWS)
    { $RDSGWS | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdgw_ServerSettings.txt") }
    else { msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] [WARNING] Failed to get Win32_TSGatewayServerSettings." }

    msrdLogMessage Normal "[$msrdLogPrefix] NPS filtered event logs"
    $eventlog = "Security"
    $msixaalog = $global:msrdEventLogFolder + $env:computername + "_NPS_filtered.evtx"

    if (Get-WinEvent -ListLog $eventlog -ErrorAction SilentlyContinue) {
        Try {
            wevtutil epl $eventlog $msixaalog "/q:*[System [Provider[@Name='NPS']]]"
        } Catch {
            msrdLogException "Error: An error occurred while exporting the MSIXAA logs" -ErrObj $_ $fLogFileOnly
        }
    } else {
        msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] Event log '$eventlog' not found."
    }
}

function msrdGetRDCB {

    #get RD Connection Broker information
    $RDCBW = msrdGetRDRoleInfo Win32_Workspace root\cimv2\TerminalServices
    if ($RDCBW)
    { $RDCBW | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdcb_Workspace.txt") }
    else { msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] [WARNING] Failed to get Win32_Workspace." }

    $RDCBCPF = msrdGetRDRoleInfo Win32_RDCentralPublishedFarm root\cimv2\TerminalServices
    if ($RDCBCPF)
    { $RDCBCPF | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdcb_CentralPublishedFarm.txt") }
    else { msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] [WARNING] Failed to get Win32_RDCentralPublishedFarm." }

    $RDCBCPDS = msrdGetRDRoleInfo Win32_RDCentralPublishedDeploymentSettings root\cimv2\TerminalServices
    if ($RDCBCPDS)
    { $RDCBCPDS | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdcb_CentralPublishedDeploymentSettings.txt") }
    else { msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] [WARNING] Failed to get Win32_RDCentralPublishedDeploymentSettings." }

    $RDCBCPFA = msrdGetRDRoleInfo Win32_RDCentralPublishedFileAssociation root\cimv2\TerminalServices
    if ($RDCBCPFA)
    { $RDCBCPFA | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdcb_CentralPublishedFileAssociation.txt") }
    else { msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] [WARNING] Failed to get Win32_RDCentralPublishedFileAssociation." }

    $RDCBPDA = msrdGetRDRoleInfo Win32_RDPersonalDesktopAssignment root\cimv2\TerminalServices
    if ($RDCBPDA)
    { $RDCBPDA | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdcb_PersonalDesktopAssignment.txt") }
    else { msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] [WARNING] Failed to get Win32_RDPersonalDesktopAssignment." }

    $RDCBSDC = msrdGetRDRoleInfo Win32_SessionDirectoryCluster root\cimv2
    if ($RDCBSDC)
    { $RDCBSDC | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdcb_SessionDirectoryCluster.txt") }
    else { msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] [WARNING] Failed to get Win32_SessionDirectoryCluster." }

    $RDCBDS = msrdGetRDRoleInfo Win32_RDMSDeploymentSettings root\cimv2\rdms
    if ($RDCBDS)
    { $RDCBDS | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdcb_RDMSDeploymentSettings.txt") }
    else { msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] [WARNING] Failed to get Win32_RDMSDeploymentSettings." }
}

function msrdGetRDWA {

    #get RD Web Access information
    $IISConfig = (C:\WINDOWS\SYSTEM32\INETSRV\APPCMD list config)
    if ($IISConfig) {
        $IISConfig | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdwa_IISConfig.txt")
    }
}

Function msrdGetPowerInfo {

    #get Windows Power Management information
    $Commands = @(
        "powercfg /systempowerreport"
        "powercfg /list 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "PowerSettings.txt'"
    )
    msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True

    "`n`n" | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "PowerSettings.txt")
    $Commands = @(
        "powercfg /query 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "PowerSettings.txt'"
    )
    msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True

    if ($global:TSSinUse) {
        $isSleepy = "$global:ScriptFolder\sleepstudy-report.html"
    } else {
        $isSleepy = "$global:msrdScriptpath\sleepstudy-report.html"
    }

    if (Test-path -path $isSleepy) {
        Try {
            Move-Item -Path $isSleepy -Destination ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "PowerReport.html")
        } Catch {
            msrdLogException ("Error: An exception occurred in msrdGetPowerInfo") -ErrObj $_ $fLogFileOnly
        }
    } else {
        msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] PowerReport 'sleepstudy-report.html' not found. ($isSleepy)"
    }
}

Function GetFarmData {

    #get RDS deployment information
    Import-Module remotedesktop 2>&1 | Out-File -Append ($global:msrdErrorLogFile)

    #Get Servers of the farm:
    $servers = Get-RDServer -ErrorAction Continue 2>>$global:msrdErrorLogFile
    $BrokerServers = @()
    $WebAccessServers = @()
    $RDSHostServers = @()
    $GatewayServers = @()

    foreach ($server in $servers) {
	    switch ($server.Roles) {
	        "RDS-CONNECTION-BROKER" {$BrokerServers += $server.Server}
	        "RDS-WEB-ACCESS" {$WebAccessServers += $server.Server}
	        "RDS-RD-SERVER" {$RDSHostServers += $server.Server}
	        "RDS-GATEWAY" {$GatewayServers += $server.Server}
	    }
    }

    "Machines involved in the deployment : " + $servers.Count 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    "	-Broker(s) : " + $BrokerServers.Count 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")

    foreach ($BrokerServer in $BrokerServers) {
		    "		" +	$BrokerServer 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
            Try {
                $BrokerServicesStatus = Get-WmiObject -ComputerName $BrokerServer -Query "Select * from Win32_Service where Name='rdms' or Name='tssdis' or Name='tscpubrpc'" -ErrorAction Stop
                foreach ($stat in $BrokerServicesStatus) {
                    "		      - " + $stat.Name + " service is " + $stat.State 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
                }
            } catch {
                msrdLogException ("$(msrdGetLocalizedText "errormsg") BrokerServicesStatus check") -ErrObj $_ $fLogFileOnly
                Continue
            }
    }

    " "	 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    "	-RDS Host(s) : " + $RDSHostServers.Count 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")

    foreach ($RDSHostServer in $RDSHostServers) {
		    "		" +	$RDSHostServer 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
            Try {
                $RDSHostServicesStatus = Get-WmiObject -ComputerName $RDSHostServer -Query "Select * from Win32_Service where Name='TermService'" -ErrorAction Stop
                foreach ($stat in $RDSHostServicesStatus) {
                    "		      - " + $stat.Name +  " service is " + $stat.State 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
                }
            } catch {
                msrdLogException ("$(msrdGetLocalizedText "errormsg") RDSHostServicesStatus check") -ErrObj $_ $fLogFileOnly
                Continue
            }
    }

    " "  2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    "	-Web Access Server(s) : " + $WebAccessServers.Count 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")

    foreach ($WebAccessServer in $WebAccessServers) {
		    "		" +	$WebAccessServer 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    }

    " " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    "	-Gateway server(s) : " + $GatewayServers.Count 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")

    foreach ($GatewayServer in $GatewayServers) {
		    "		" +	$GatewayServer 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
            Try {
                $GatewayServicesStatus = Get-WmiObject -ComputerName $GatewayServer -Query "Select * from Win32_Service where Name='TSGateway'" -ErrorAction Stop
                foreach ($stat in $GatewayServicesStatus) {
                    "		      - " + $stat.Name + " service is " + $stat.State 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
                }
            } catch {
                msrdLogException ("$(msrdGetLocalizedText "errormsg") GatewayServicesStatus check") -ErrObj $_ $fLogFileOnly
                Continue
            }
    }
    " " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")

    #Get active broker server.
    $ActiveBroker = Invoke-WmiMethod -Path ROOT\cimv2\rdms:Win32_RDMSEnvironment -Name GetActiveServer -ErrorAction Continue 2>>$global:msrdErrorLogFile 
    $ConnectionBroker = $ActiveBroker.ServerName
    "ActiveManagementServer (broker) : " +	$ActiveBroker.ServerName 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    " " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")

    # Deployment Properties
    "Deployment details : " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    # Is Broker configured in High Availability?
    $HighAvailabilityBroker = Get-RDConnectionBrokerHighAvailability -ErrorAction Continue 2>>$global:msrdErrorLogFile
    $BoolHighAvail = $false
    If ($HighAvailabilityBroker -eq $null)
    {
	    $BoolHighAvail = $false
	    "	Is Connection Broker configured for High Availability : " + $BoolHighAvail 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    }
    else
    {
	    $BoolHighAvail = $true
	    "	Is Connection Broker configured for High Availability : " + $BoolHighAvail 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
	    "		- Client Access Name (Round Robin DNS) : " + $HighAvailabilityBroker.ClientAccessName 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
	    "		- DatabaseConnectionString : " + $HighAvailabilityBroker.DatabaseConnectionString 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
        "		- DatabaseSecondaryConnectionString : " + $HighAvailabilityBroker.DatabaseSecondaryConnectionString 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
	    "		- DatabaseFilePath : " + $HighAvailabilityBroker.DatabaseFilePath 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    }

    #Gateway Configuration
    $GatewayConfig = Get-RDDeploymentGatewayConfiguration -ConnectionBroker $ConnectionBroker -ErrorAction Continue 2>>$global:msrdErrorLogFile
    "	Gateway Mode : " + $GatewayConfig.GatewayMode 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    if ($GatewayConfig.GatewayMode -eq "custom")
    {
    "		- LogonMethod : " + $GatewayConfig.LogonMethod 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    "		- GatewayExternalFQDN : " + $GatewayConfig.GatewayExternalFQDN 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    "		- GatewayBypassLocal : " + $GatewayConfig.BypassLocal 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    "		- GatewayUseCachedCredentials : " + $GatewayConfig.UseCachedCredentials 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")

    }

    # RD Licencing
    $LicencingConfig = Get-RDLicenseConfiguration -ConnectionBroker $ConnectionBroker -ErrorAction Continue 2>>$global:msrdErrorLogFile
    "	Licencing Mode : " + $LicencingConfig.Mode 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    if ($LicencingConfig.Mode -ne "NotConfigured")
    {
    "		- Licencing Server(s) : " + $LicencingConfig.LicenseServer.Count 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    foreach ($licserver in $LicencingConfig.LicenseServer)
    {
    "		       - Licencing Server : " + $licserver 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    }

    }
    # RD Web Access
    "	Web Access Server(s) : " + $WebAccessServers.Count 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    foreach ($WebAccessServer in $WebAccessServers)
    {
    "	     - Name : " + $WebAccessServer 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    "	     - Url : " + "https://" + $WebAccessServer + "/rdweb" 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    }

    # Certificates
    "	Certificates " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    $certificates = Get-RDCertificate -ConnectionBroker $ConnectionBroker -ErrorAction Continue 2>>$global:msrdErrorLogFile
    foreach ($certificate in $certificates)
    {
    "		- Role : " + $certificate.Role 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    "			- Level : " + $certificate.Level 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    "			- Expires on : " + $certificate.ExpiresOn 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    "			- Issued To : " + $certificate.IssuedTo 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    "			- Issued By : " + $certificate.IssuedBy 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    "			- Thumbprint : " + $certificate.Thumbprint 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    "			- Subject : " + $certificate.Subject 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    "			- Subject Alternate Name : " + $certificate.SubjectAlternateName 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")

    }
    " " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")

    #RDS Collections
    $collectionnames = Get-RDSessionCollection -ErrorAction Continue 2>>$global:msrdErrorLogFile
    $client = $null
    $connection = $null
    $loadbalancing = $null
    $Security = $null
    $UserGroup = $null
    $UserProfileDisks = $null

    "RDS Collections : " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
    foreach ($Collection in $collectionnames)
    {
	    $CollectionName = $Collection.CollectionName
	    "	Collection : " +  $CollectionName 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
	    "		Resource Type : " + $Collection.ResourceType 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
	    if ($Collection.ResourceType -eq "RemoteApp programs")
	    {
		    "			Remote Apps : " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    $remoteapps = Get-RDRemoteApp -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -ErrorAction Continue 2>>$global:msrdErrorLogFile
		    foreach ($remoteapp in $remoteapps)
		    {
			    "			- DisplayName : " + $remoteapp.DisplayName 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
			    "				- Alias : " + $remoteapp.Alias 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
			    "				- FilePath : " + $remoteapp.FilePath 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
			    "				- Show In WebAccess : " + $remoteapp.ShowInWebAccess 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
			    "				- CommandLineSetting : " + $remoteapp.CommandLineSetting 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
			    "				- RequiredCommandLine : " + $remoteapp.RequiredCommandLine 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
			    "				- UserGroups : " + $remoteapp.UserGroups 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    }
	    }

    #       $rdshServers
		    $rdshservers = Get-RDSessionHost -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -ErrorAction Continue 2>>$global:msrdErrorLogFile
		    "		Servers in that collection : " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    foreach ($rdshServer in $rdshservers)
		    {
			    "			- SessionHost : " + $rdshServer.SessionHost 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
			    "				- NewConnectionAllowed : " + $rdshServer.NewConnectionAllowed 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    }

		    $client = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -Client -ErrorAction Continue 2>>$global:msrdErrorLogFile
		    "		Client Settings : " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- MaxRedirectedMonitors : " + $client.MaxRedirectedMonitors 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- RDEasyPrintDriverEnabled : " + $client.RDEasyPrintDriverEnabled 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- ClientPrinterRedirected : " + $client.ClientPrinterRedirected 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- ClientPrinterAsDefault : " + $client.ClientPrinterAsDefault 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- ClientDeviceRedirectionOptions : " + $client.ClientDeviceRedirectionOptions 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    " " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")

		    $connection = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -Connection -ErrorAction Continue 2>>$global:msrdErrorLogFile
		    "		Connection Settings : " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- DisconnectedSessionLimitMin : " + $connection.DisconnectedSessionLimitMin 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- BrokenConnectionAction : " + $connection.BrokenConnectionAction 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- TemporaryFoldersDeletedOnExit : " + $connection.TemporaryFoldersDeletedOnExit 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- AutomaticReconnectionEnabled : " + $connection.AutomaticReconnectionEnabled 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- ActiveSessionLimitMin : " + $connection.ActiveSessionLimitMin 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- IdleSessionLimitMin : " + $connection.IdleSessionLimitMin 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    " " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")

		    $loadbalancing = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -LoadBalancing -ErrorAction Continue 2>>$global:msrdErrorLogFile
		    "		Load Balancing Settings : " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    foreach ($SessHost in $loadbalancing)
		    {
		    "			- SessionHost : " + $SessHost.SessionHost 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "				- RelativeWeight : " + $SessHost.RelativeWeight 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "				- SessionLimit : " + $SessHost.SessionLimit 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    }
		    " " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")

		    $Security = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -Security -ErrorAction Continue 2>>$global:msrdErrorLogFile
		    "		Security Settings : " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- AuthenticateUsingNLA : " + $Security.AuthenticateUsingNLA 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- EncryptionLevel : " + $Security.EncryptionLevel 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- SecurityLayer : " + $Security.SecurityLayer 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    " " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")

		    $UserGroup = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -UserGroup -ErrorAction Continue 2>>$global:msrdErrorLogFile
		    "		User Group Settings : " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- UserGroup  : " + $UserGroup.UserGroup 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    " " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")

		    $UserProfileDisks = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -UserProfileDisk -ErrorAction Continue 2>>$global:msrdErrorLogFile
		    "		User Profile Disk Settings : " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- EnableUserProfileDisk : " + $UserProfileDisks.EnableUserProfileDisk 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- MaxUserProfileDiskSizeGB : " + $UserProfileDisks.MaxUserProfileDiskSizeGB 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- DiskPath : " + $UserProfileDisks.DiskPath 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- ExcludeFilePath : " + $UserProfileDisks.ExcludeFilePath 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- ExcludeFolderPath : " + $UserProfileDisks.ExcludeFolderPath 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- IncludeFilePath : " + $UserProfileDisks.IncludeFilePath 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "			- IncludeFolderPath : " + $UserProfileDisks.IncludeFolderPath 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    " " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")

		    $usersConnected = Get-RDUserSession -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -ErrorAction Continue 2>>$global:msrdErrorLogFile
		    "		Users connected to this collection : " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    foreach ($userconnected in $usersConnected)
		    {
		    "			User : " + $userConnected.DomainName + "\" + $userConnected.UserName 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "				- HostServer : " + $userConnected.HostServer 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    "				- UnifiedSessionID : " + $userConnected.UnifiedSessionID 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
		    }
		    " " 2>&1 | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "GetFarmData.txt")
        }
} #to rename

Function msrdGetStore($store) {

    $certlist = Get-ChildItem ("Cert:\LocalMachine\" + $store)

    foreach ($cert in $certlist) {
        $EKU = ""
        foreach ($item in $cert.EnhancedKeyUsageList) {
            if ($item.FriendlyName) {
                $EKU += $item.FriendlyName + " / "
            } else {
                $EKU += $item.ObjectId + " / "
            }
        }

        $row = $tbcert.NewRow()

        foreach ($ext in $cert.Extensions) {
            if ($ext.oid.value -eq "2.5.29.14") {
                $row.SubjectKeyIdentifier = $ext.SubjectKeyIdentifier.ToLower()
            }
            if (($ext.oid.value -eq "2.5.29.35") -or ($ext.oid.value -eq "2.5.29.1")) {
                $asn = New-Object Security.Cryptography.AsnEncodedData ($ext.oid,$ext.RawData)
                $aki = $asn.Format($true).ToString().Replace(" ","")
                $aki = (($aki -split '\n')[0]).Replace("KeyID=","").Trim()
                $row.AuthorityKeyIdentifier = $aki
            }
        }

        if ($EKU) {$EKU = $eku.Substring(0, $eku.Length-3)}
        $row.Store = $store
        $row.Thumbprint = $cert.Thumbprint.ToLower()
        $row.Subject = $cert.Subject
        $row.Issuer = $cert.Issuer
        $row.NotAfter = $cert.NotAfter
        $row.EnhancedKeyUsage = $EKU
        $row.SerialNumber = $cert.SerialNumber.ToLower()
        $tbcert.Rows.Add($row)
    }
}

function msrdGetDump {
    param ([int]$pidProc)

    #get process dump
    if ($pidProc) {
        if ($global:msrdProcDumpExe -ne "") {
            $procname = Get-Process -id $pidProc -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
            if ($procname) {
                msrdCreateLogFolder $msrdDumpFolder
                msrdLogMessage Info ('Collecting Process Dump for PID ' + $pidProc + ' (' + $procname + ')')
                try {
                    $Commands = @(
                        "$global:msrdProcDumpExe -AcceptEula -ma $pidProc $msrdDumpFolder 2>&1 | Out-File -Append " + $msrdDumpFolder + $global:msrdLogFilePrefix + "ProcDumpOutput.txt"
                    )
                    msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$True -ShowMessage:$True -ShowError:$True
                } catch {
                    $failedCommand = $_.InvocationInfo.Line.TrimStart()
                    $errorMessage = $_.Exception.Message.TrimStart()
                    msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
                    if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                        msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
                    } else {
                        msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
                    }
                }
            } else {
                msrdLogMessage Info ('A process with PID ' + $pidProc + ' could not be found')
                msrdLogMessage Error ('A process with PID ' + $pidProc + ' could not be found')
            }
        }
    } else {
        if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            msrdAdd-OutputBoxLine ("Error in msrdGetDump - $pidProc not found") "Magenta"
        } else {
            msrdLogMessage Warning ("Error in msrdGetDump - $pidProc not found")
        }
    }
}

function msrdGetCoreEventLogs {
    param( [bool[]]$varsCore )

    #get event logs
    " " | Out-File -Append $global:msrdOutputLogFile
    msrdCreateLogFolder $global:msrdEventLogFolder

    if ($varsCore[0]) { msrdGetEventLogs -LogPrefix $msrdLogPrefix 'Security' 'Security' }

    $logs = @{
        'System' = 'System'
        'Application' = 'Application'
        'Setup' = 'Setup'
        'Microsoft-Windows-AAD/Operational' = 'AAD-Operational'
        'Microsoft-Windows-CAPI2/Operational' = 'CAPI2-Operational'
        'Microsoft-Windows-Diagnostics-Performance/Operational' = 'DiagnosticsPerformance-Operational'
        'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin' = 'DeviceManagement-EnterpriseDiagProvider-Admin'
        'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational' = 'DeviceManagement-EnterpriseDiagProvider-Operational'
        'Microsoft-Windows-DSC/Operational' = 'DSC-Operational'
        'Microsoft-Windows-HelloForBusiness/Operational' = 'HelloForBusiness-Operational'
        'Microsoft-Windows-NTLM/Operational' = 'NTLM-Operational'
        'Microsoft-Windows-PowerShell/Operational' = 'PowerShell-Operational'
        'Microsoft-Windows-RemoteApp and Desktop Connection Management/Admin' = 'RemoteAppAndDesktopConnections-Management-Admin'
        'Microsoft-Windows-RemoteApp and Desktop Connection Management/Operational' = 'RemoteAppAndDesktopConnections-Management-Operational'
        'Microsoft-Windows-RemoteApp and Desktop Connections/Admin' = 'RemoteAppAndDesktopConnections-Admin'
        'Microsoft-Windows-RemoteApp and Desktop Connections/Operational' = 'RemoteAppAndDesktopConnections-Operational'
        'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin' = 'RemoteDesktopServicesRdpCoreTS-Admin'
        'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational' = 'RemoteDesktopServicesRdpCoreTS-Operational'
        'Microsoft-Windows-TaskScheduler/Operational' = 'TaskScheduler-Operational'
        'Microsoft-Windows-TerminalServices-ClientUSBDevices/Admin' = 'TerminalServicesClientUSBDevices-Admin'
        'Microsoft-Windows-TerminalServices-ClientUSBDevices/Operational' = 'TerminalServicesClientUSBDevices-Operational'
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Admin' = 'TerminalServicesLocalSessionManager-Admin'
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' = 'TerminalServicesLocalSessionManager-Operational'
        'Microsoft-Windows-TerminalServices-PnPDevices/Admin' = 'TerminalServicesPnPDevices-Admin'
        'Microsoft-Windows-TerminalServices-PnPDevices/Operational' = 'TerminalServicesPnPDevices-Operational'
        'Microsoft-Windows-TerminalServices-Printers/Admin' = 'TerminalServicesPrinters-Admin'
        'Microsoft-Windows-TerminalServices-Printers/Operational' = 'TerminalServicesPrinters-Operational'
        'Microsoft-Windows-TerminalServices-RDPClient/Operational' = 'RDPClient-Operational'
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin' = 'TerminalServicesRemoteConnectionManager-Admin'
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' = 'TerminalServicesRemoteConnectionManager-Operational'
        'Microsoft-Windows-WER-Diagnostics/Operational' = 'WER-Diagnostics-Operational'
        'Microsoft-Windows-WinINet-Config/ProxyConfigChanged' = 'WinHttp-ProxyConfigChanged'
        'Microsoft-Windows-Winlogon/Operational' = 'Winlogon-Operational'
        'Microsoft-Windows-WinRM/Operational' = 'WinRM-Operational'
    }
    foreach ($log in $logs.GetEnumerator()) { msrdGetEventLogs -LogPrefix $msrdLogPrefix $log.Key $log.Value }

    #not source specific
    if (!($global:msrdSource)) {
        $logs = @{
            'Microsoft-WindowsAzure-Diagnostics/Bootstrapper' = 'WindowsAzure-Diag-Bootstrapper'
            'Microsoft-WindowsAzure-Diagnostics/GuestAgent' = 'WindowsAzure-Diag-GuestAgent'
            'Microsoft-WindowsAzure-Diagnostics/Heartbeat' = 'WindowsAzure-Diag-Heartbeat'
            'Microsoft-WindowsAzure-Diagnostics/Runtime' = 'WindowsAzure-Diag-Runtime'
            'Microsoft-WindowsAzure-Status/GuestAgent' = 'WindowsAzure-Status-GuestAgent'
            'Microsoft-WindowsAzure-Status/Plugins' = 'WindowsAzure-Status-Plugins'
            'Microsoft-Windows-Rdms-UI/Admin' = 'Microsoft-Windows-Rdms-UI-Admin'
            'Microsoft-Windows-Rdms-UI/Operational' = 'Rdms-UI-Operational'
            'Microsoft-Windows-Remote-Desktop-Management-Service/Admin' = 'RemoteDesktopManagementService-Admin'
            'Microsoft-Windows-Remote-Desktop-Management-Service/Operational' = 'RemoteDesktopManagementService-Operational'
            'Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Admin' = 'RemoteDesktopServicesRdpCoreCDV-Admin'
            'Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Operational' = 'RemoteDesktopServicesRdpCoreCDV-Operational'
            'Microsoft-Windows-RemoteDesktopServices-SessionServices/Operational' = 'RemoteDesktopServicesSessionServices-Operational'
            'Microsoft-Windows-TerminalServices-Gateway/Admin' = 'TerminalServicesGateway-Admin'
            'Microsoft-Windows-TerminalServices-Gateway/Operational' = 'TerminalServicesGateway-Operational'
            'Microsoft-Windows-TerminalServices-Licensing/Admin' = 'TerminalServicesLicensing-Admin'
            'Microsoft-Windows-TerminalServices-Licensing/Operational' = 'TerminalServicesLicensing-Operational'
            'Microsoft-Windows-TerminalServices-ServerUSBDevices/Admin' = 'TerminalServicesServerUSBDevices-Admin'
            'Microsoft-Windows-TerminalServices-ServerUSBDevices/Operational' = 'TerminalServicesServerUSBDevices-Operational'
            'Microsoft-Windows-TerminalServices-SessionBroker/Admin' = 'TerminalServicesSessionBroker-Admin'
            'Microsoft-Windows-TerminalServices-SessionBroker/Operational' = 'TerminalServicesSessionBroker-Operational'
            'Microsoft-Windows-TerminalServices-SessionBroker-Client/Admin' = 'TerminalServicesSessionBroker-Client-Admin'
            'Microsoft-Windows-TerminalServices-SessionBroker-Client/Operational' = 'TerminalServicesSessionBroker-Client-Operational'
            'Microsoft-Windows-TerminalServices-TSAppSrv-TSMSI/Admin' = 'TerminalServicesTSAppSrv-TSMSI-Admin'
            'Microsoft-Windows-TerminalServices-TSAppSrv-TSMSI/Operational' = 'TerminalServicesTSAppSrv-TSMSI-Operational'
            'Microsoft-Windows-TerminalServices-TSAppSrv-TSVIP/Admin' = 'TerminalServicesTSAppSrv-TSVIP-Admin'
            'Microsoft-Windows-TerminalServices-TSAppSrv-TSVIP/Operational' = 'TerminalServicesTSAppSrv-TSVIP-Operational'
        }
        foreach ($log in $logs.GetEnumerator()) { msrdGetEventLogs -LogPrefix $msrdLogPrefix $log.Key $log.Value }
    }

    #RDS specific
    if ($global:msrdRDS) {
        $logs = @{
            'Microsoft-Windows-Rdms-UI/Admin' = 'Microsoft-Windows-Rdms-UI-Admin'
            'Microsoft-Windows-Rdms-UI/Operational' = 'Rdms-UI-Operational'
            'Microsoft-Windows-Remote-Desktop-Management-Service/Admin' = 'RemoteDesktopManagementService-Admin'
            'Microsoft-Windows-Remote-Desktop-Management-Service/Operational' = 'RemoteDesktopManagementService-Operational'
            'Microsoft-Windows-TerminalServices-Gateway/Admin' = 'TerminalServicesGateway-Admin'
            'Microsoft-Windows-TerminalServices-Gateway/Operational' = 'TerminalServicesGateway-Operational'
            'Microsoft-Windows-TerminalServices-Licensing/Admin' = 'TerminalServicesLicensing-Admin'
            'Microsoft-Windows-TerminalServices-Licensing/Operational' = 'TerminalServicesLicensing-Operational'
            'Microsoft-Windows-TerminalServices-SessionBroker/Admin' = 'TerminalServicesSessionBroker-Admin'
            'Microsoft-Windows-TerminalServices-SessionBroker/Operational' = 'TerminalServicesSessionBroker-Operational'
            'Microsoft-Windows-TerminalServices-SessionBroker-Client/Admin' = 'TerminalServicesSessionBroker-Client-Admin'
            'Microsoft-Windows-TerminalServices-SessionBroker-Client/Operational' = 'TerminalServicesSessionBroker-Client-Operational'
            'Microsoft-Windows-TerminalServices-TSAppSrv-TSMSI/Admin' = 'TerminalServicesTSAppSrv-TSMSI-Admin'
            'Microsoft-Windows-TerminalServices-TSAppSrv-TSMSI/Operational' = 'TerminalServicesTSAppSrv-TSMSI-Operational'
            'Microsoft-Windows-TerminalServices-TSAppSrv-TSVIP/Admin' = 'TerminalServicesTSAppSrv-TSVIP-Admin'
            'Microsoft-Windows-TerminalServices-TSAppSrv-TSVIP/Operational' = 'TerminalServicesTSAppSrv-TSVIP-Operational'
        }
        foreach ($log in $logs.GetEnumerator()) { msrdGetEventLogs -LogPrefix $msrdLogPrefix $log.Key $log.Value }
    }

    #avd specific
    if ($global:msrdAVD) {
        msrdGetEventLogs -LogPrefix $msrdLogPrefix 'RemoteDesktopServices' 'RemoteDesktopServices'
    }
}

function msrdGetCoreRegKeys {

    #get registry keys
    " " | Out-File -Append $global:msrdOutputLogFile
    msrdCreateLogFolder $msrdRegLogFolder

    $regs = @{
        'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' = 'SW-MS-NetFS-NDP'
        'HKLM:\SOFTWARE\Microsoft\Terminal Server Client' = 'SW-MS-TerminalServerClient'
        'HKCU:\SOFTWARE\Microsoft\Terminal Server Client' = 'SW-MS-TerminalServerClient'
        'HKLM:\SOFTWARE\Microsoft\MSLicensing' = 'SW-MS-MSLicensing'
        'HKLM:\SOFTWARE\Microsoft\Ole' = 'SW-MS-Ole'
        'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters' = 'SW-MS-VM-GuestParams'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' = 'SW-MS-Win-CV-InternetSettings'
        'HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' = 'Def-SW-MS-Win-CV-InternetSettings'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies' = 'SW-MS-Win-CV-Policies'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' = 'SW-MS-Win-CV-Run'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' = 'SW-MS-Win-CV-Run'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' = 'SW-MS-Win-CV-RunOnce'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' = 'SW-MS-Win-CV-RunOnce'
        'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' = 'SW-MS-Win-WindowsErrorReporting'
        'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions' = 'SW-MS-WinDef-Exclusions'
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers' = 'SW-MS-WinNT-CV-AppCompatFlags-Layers'
        'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography' = 'SW-Policies-MS-Cryptography'
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' = 'SW-Policies-MS-Win-CredentialsDelegation'
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions' = 'SW-Policies-MS-Win-DeviceInstall-Restrictions'
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer' = 'SW-Policies-MS-Win-SoftwareRestrictionPolicies'
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' = 'SW-GPO-MS-WinDef-Exclusions'
        'HKLM:\SYSTEM\CurrentControlSet\Control\CoDeviceInstallers' = 'SW-CCS-Control-CoDeviceInstallers'
        'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' = 'System-CCS-Control-CrashControl'
        'HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography' = 'System-CCS-Control-Cryptography'
        'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin' = 'System-CCS-Control-CloudDomainJoin'
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' = 'System-CCS-Control-LSA'
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders' = 'System-CCS-Control-SecurityProviders'
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' = 'System-CCS-Control-SessMan-MemoryManagement'
        'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip' = 'System-CCS-Svc-Tcpip'
        'HKLM:\SYSTEM\CurrentControlSet\Services\WinRM' = 'System-CCS-Svc-WinRM'
    }
    foreach ($reg in $regs.GetEnumerator()) { msrdGetRegKeys -LogPrefix $msrdLogPrefix $reg.Key $reg.Value }

    #not source specific
    if (!($global:msrdSource)) {
        $regs = @{
            'HKLM:\SOFTWARE\Microsoft\Azure\DSC' = 'SW-MS-Azure-DSC'
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server' = 'SW-MS-WinNT-CV-TerminalServer'
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' = 'SW-Policies-MS-WinNT-TerminalServices'
            'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' = 'System-CCS-Control-TerminalServer'
            'HKLM:\SYSTEM\CurrentControlSet\Enum\TERMINPUT_BUS' = 'System-CCS-Enum-TERMINPUT_BUS'
            'HKLM:\SYSTEM\CurrentControlSet\Enum\TERMINPUT_BUS_SXS' = 'System-CCS-Enum-TERMINPUT_BUS_SXS'
            'HKLM:\SYSTEM\CurrentControlSet\Services\TermService' = 'System-CCS-Svc-TermService'
            'HKLM:\SYSTEM\CurrentControlSet\Services\TermServLicensing' = 'System-CCS-Svc-TermServLicensing'
            'HKLM:\SYSTEM\CurrentControlSet\Services\TSFairShare' = 'System-CCS-Svc-TSFairShare'
            'HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService' = 'System-CCS-Svc-UmRdpService'
            'HKLM:\SYSTEM\DriverDatabase\DeviceIds\TS_INPT' = 'System-DriverDB-DeviceIds-TS_INPT'
        }
        foreach ($reg in $regs.GetEnumerator()) { msrdGetRegKeys -LogPrefix $msrdLogPrefix $reg.Key $reg.Value }
    }
    
    #rds specific
    if ($global:msrdRDS) {
        $regs = @{
            'HKLM:\SYSTEM\CurrentControlSet\Services\MSSQL$MICROSOFT##WID' = 'System-CCS-Svc-MSSQL$MICROSOFT##WID'
            'HKLM:\SYSTEM\CurrentControlSet\Services\RDMS' = 'System-CCS-Svc-RDMS'
            'HKLM:\SYSTEM\CurrentControlSet\Services\TScPubRPC' = 'System-CCS-Svc-TScPubRPC'
            'HKLM:\SYSTEM\CurrentControlSet\Services\Tssdis' = 'System-CCS-Svc-Tssdis'
            'HKLM:\SYSTEM\CurrentControlSet\Services\TSGateway' = 'System-CCS-Svc-TSGateway'
            'HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC' = 'System-CCS-Svc-W3SVC'
        }
        foreach ($reg in $regs.GetEnumerator()) { msrdGetRegKeys -LogPrefix $msrdLogPrefix $reg.Key $reg.Value }
    }

    #avd specific
    if ($global:msrdAVD) {
        $regs = @{
            'HKLM:\SOFTWARE\Microsoft\MSRDC' = 'SW-MS-MSRDC'
            'HKCU:\SOFTWARE\Microsoft\MSRDC' = 'SW-MS-MSRDC'
            'HKCU:\SOFTWARE\Microsoft\RdClientRadc' = 'SW-MS-RdClientRadc'
            'HKLM:\SOFTWARE\Microsoft\RDMonitoringAgent' = 'SW-MS-RDMonitoringAgent'
            'HKLM:\SOFTWARE\Microsoft\RDInfraAgent' = 'SW-MS-RDInfraAgent'
            'HKCU:\SOFTWARE\Microsoft\Remote Desktop' = 'SW-MS-RemoteDesktop'
            'HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader' = 'SW-MS-RDAgentBootLoader'
            'HKLM:\SYSTEM\CurrentControlSet\Services\RDAgentBootLoader' = 'System-CCS-Svc-RDAgentBootLoader'
        }
        foreach ($reg in $regs.GetEnumerator()) { msrdGetRegKeys -LogPrefix $msrdLogPrefix $reg.Key $reg.Value }
    }
}

function msrdGetCoreRDPNetADInfo {
    param( [bool[]]$varsCore )

    #get RDP, networking and AD information
    " " | Out-File -Append $global:msrdOutputLogFile
    msrdCreateLogFolder $global:msrdNetLogFolder
    msrdCreateLogFolder $global:msrdSysInfoLogFolder

    if (!($global:msrdSource)) {
        if ($global:msrdAVD) {
            $global:rdtreefolder = $global:msrdAVDLogFolder
        } else {
            $global:rdtreefolder = $global:msrdRDSLogFolder
        }
        msrdCreateLogFolder $rdtreefolder
        $Commands = @(
            "tree 'C:\Windows\RemotePackages' /f 2>&1 | Out-File -Append '" + $rdtreefolder + $global:msrdLogFilePrefix + "tree_Win-RemotePackages.txt'"
        )
        msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
    }

    Get-NetConnectionProfile -ErrorAction SilentlyContinue | Out-File -Append ($global:msrdNetLogFolder + $global:msrdLogFilePrefix + "NetConnectionProfile.txt")
    Get-NetIPInterface -ErrorAction SilentlyContinue | Out-File -Append ($global:msrdNetLogFolder + $global:msrdLogFilePrefix + "NetIPInterface.txt")
    Get-NetIPInterface -ErrorAction SilentlyContinue | fl | Out-File -Append ($global:msrdNetLogFolder + $global:msrdLogFilePrefix + "NetIPInterface.txt")

    $Commands = @(
        "netsh advfirewall firewall show rule name=all 2>&1 | Out-File -Append '" + $global:msrdNetLogFolder + $global:msrdLogFilePrefix + "FirewallRules.txt'"
        "netstat -anob 2>&1 | Out-File -Append '" + $global:msrdNetLogFolder + $global:msrdLogFilePrefix + "Netstat.txt'"
        "ipconfig /all 2>&1 | Out-File -Append '" + $global:msrdNetLogFolder + $global:msrdLogFilePrefix + "Ipconfig.txt'"
        "netsh winhttp show proxy 2>&1 | Out-File -Append '" + $global:msrdNetLogFolder + $global:msrdLogFilePrefix + "Proxy.txt'"
        "netsh winsock show catalog 2>&1 | Out-File -Append '" + $global:msrdNetLogFolder + $global:msrdLogFilePrefix + "WinsockCatalog.txt'"
        "netsh interface Teredo show state 2>&1 | Out-File -Append '" + $global:msrdNetLogFolder + $global:msrdLogFilePrefix + "Teredo.txt'"
        "nslookup wpad 2>&1 | Out-File -Append '" + $global:msrdNetLogFolder + $global:msrdLogFilePrefix + "Nslookup.txt'"
        "bitsadmin /util /getieproxy LOCALSYSTEM 2>&1 | Out-File -Append '" + $global:msrdNetLogFolder + $global:msrdLogFilePrefix + "Proxy.txt'"
        "bitsadmin /util /getieproxy NETWORKSERVICE 2>&1 | Out-File -Append '" + $global:msrdNetLogFolder + $global:msrdLogFilePrefix + "Proxy.txt'"
        "bitsadmin /util /getieproxy LOCALSERVICE 2>&1 | Out-File -Append '" + $global:msrdNetLogFolder + $global:msrdLogFilePrefix + "Proxy.txt'"
        "route print 2>&1 | Out-File -Append '" + $global:msrdNetLogFolder + $global:msrdLogFilePrefix + "Route.txt'"
    )
    msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True

    if ($global:msrdAVD) {
        $Commands = @(
            "nslookup rdweb.wvd.microsoft.com 2>&1 | Out-File -Append '" + $global:msrdNetLogFolder + $global:msrdLogFilePrefix + "Nslookup.txt'"
            "tree 'C:\Program Files\Microsoft RDInfra' /f 2>&1 | Out-File -Append '" + $global:msrdAVDLogFolder + $global:msrdLogFilePrefix + "tree_ProgFiles-MicrosoftRDInfra.txt'"
        )
        msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
    }

    Try {
        $vmdomain = [System.Directoryservices.Activedirectory.Domain]::GetComputerDomain()
        $Commands = @(
            "nltest /sc_query:$vmdomain 2>&1 | Out-File -Append '" + $global:msrdNetLogFolder + $global:msrdLogFilePrefix + "Nltest-scquery.txt'"
            "nltest /dnsgetdc:$vmdomain 2>&1 | Out-File -Append '" + $global:msrdNetLogFolder + $global:msrdLogFilePrefix + "Nltest-dnsgetdc.txt'"
            "nltest /domain_trusts /all_trusts /v 2>&1 | Out-File -Append '" + $global:msrdNetLogFolder + $global:msrdLogFilePrefix + "Nltest-domtrusts.txt'"
        )
        msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
    } Catch {
        $failedCommand = $_.InvocationInfo.Line.TrimStart()
        $errorMessage = $_.Exception.Message.TrimStart()
        msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
        if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
        } else {
            msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
        }
    }

    if ($varsCore[0]) {
        $Commands = @("dsregcmd /status 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "Dsregcmd.txt'")
        msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
    }
}

function msrdGetCoreSchedTasks {

    #get task scheduler information
    if ($global:msrdAVD) {
        msrdCreateLogFolder $global:msrdSchtaskFolder

        if (Get-ScheduledTask -TaskPath '\RemoteDesktop\*' -ErrorAction Ignore) {

            if ($global:msrdUserprof) {
                $rdschedUser = "\RemoteDesktop\" + $global:msrdUserprof + "\"
            } else {
                $rdschedUser = "\RemoteDesktop\" + [System.Environment]::UserName + "\"
            }

            Get-ScheduledTask -TaskPath "$rdschedUser" | Export-ScheduledTask 2>&1 | Out-File -Append ($global:msrdSchtaskFolder + $global:msrdLogFilePrefix + "schtasks_RemoteDesktop.xml")
            Get-ScheduledTaskInfo -TaskName "Remote Desktop Feed Refresh Task" -TaskPath "$rdschedUser" 2>&1 | Out-File -Append ($global:msrdSchtaskFolder + $global:msrdLogFilePrefix + "schtasks_RemoteDesktop_Info.txt")
        } else {
            msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] Remote Desktop Scheduled Tasks not found."
        }
    }
}

function msrdGetCoreSystemInfo {

    #get system information
    " " | Out-File -Append $global:msrdOutputLogFile
    msrdCreateLogFolder $global:msrdSysInfoLogFolder

    msrdLogMessage Normal "[$msrdLogPrefix] Exporting details about currently running processes and key system binaries"

    if ($PSVersionTable.psversion.ToString() -ge "3.0") {
        $StartTime= @{e={$_.CreationDate.ToString("yyyyMMdd HH:mm:ss")};n="Start time"}
    } else {
        $StartTime= @{n='StartTime';e={$_.ConvertToDateTime($_.CreationDate)}}
    }

    Try {
        $proc = Get-CimInstance -Namespace "root\cimv2" -Query "select Name, CreationDate, ProcessId, ParentProcessId, WorkingSetSize, UserModeTime, KernelModeTime, ThreadCount, HandleCount, CommandLine, ExecutablePath from Win32_Process" -ErrorAction Continue 2>>$global:msrdErrorLogFile
        if ($proc) {
            $proc | Sort-Object Name | Format-Table -AutoSize -property @{e={$_.ProcessId};Label="PID"}, @{e={$_.ParentProcessId};n="Parent"}, Name,
            @{N="WorkingSet";E={"{0:N0}" -f ($_.WorkingSetSize/1kb)};a="right"},
            @{e={[DateTime]::FromFileTimeUtc($_.UserModeTime).ToString("HH:mm:ss")};n="UserTime"}, @{e={[DateTime]::FromFileTimeUtc($_.KernelModeTime).ToString("HH:mm:ss")};n="KernelTime"},
            @{N="Threads";E={$_.ThreadCount}}, @{N="Handles";E={($_.HandleCount)}}, $StartTime, CommandLine | Out-String -Width 500 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "RunningProcesses.txt")

            $binlist = $proc | Group-Object -Property ExecutablePath
            foreach ($file in $binlist) {
                if ($file.Name) {
                    msrdFileVersion -Filepath ($file.name) -Log $true 2>&1 | Out-Null
                }
            }

            $pad = 27
            $OS = Get-CimInstance -Namespace "root\cimv2" -Query "select Caption, CSName, OSArchitecture, BuildNumber, InstallDate, LastBootUpTime, LocalDateTime, TotalVisibleMemorySize, FreePhysicalMemory, SizeStoredInPagingFiles, FreeSpaceInPagingFiles from Win32_OperatingSystem" -ErrorAction SilentlyContinue 2>>$global:msrdErrorLogFile
            $CS = Get-CimInstance -Namespace "root\cimv2" -Query "select Model, Manufacturer, SystemType, NumberOfProcessors, NumberOfLogicalProcessors, TotalPhysicalMemory, DNSHostName, Domain, DomainRole from Win32_ComputerSystem" -ErrorAction SilentlyContinue 2>>$global:msrdErrorLogFile
            $BIOS = Get-CimInstance -Namespace "root\cimv2" -query "select BIOSVersion, Manufacturer, ReleaseDate, SMBIOSBIOSVersion from Win32_BIOS" -ErrorAction SilentlyContinue 2>>$global:msrdErrorLogFile
            $TZ = Get-CimInstance -Namespace "root\cimv2" -Query "select Description from Win32_TimeZone" -ErrorAction SilentlyContinue 2>>$global:msrdErrorLogFile
            $PR = Get-CimInstance -Namespace "root\cimv2" -Query "select Name, Caption from Win32_Processor" -ErrorAction SilentlyContinue 2>>$global:msrdErrorLogFile

            $ctr = Get-Counter -Counter "\Memory\Pool Paged Bytes" -ErrorAction SilentlyContinue 2>>$global:msrdErrorLogFile
            if ($ctr) { $PoolPaged = $ctr.CounterSamples[0].CookedValue }

            $ctr = Get-Counter -Counter "\Memory\Pool Nonpaged Bytes" -ErrorAction SilentlyContinue 2>>$global:msrdErrorLogFile
            if ($ctr) { $PoolNonPaged = $ctr.CounterSamples[0].CookedValue }

            "Computer name".PadRight($pad) + " : " + $OS.CSName 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "Model".PadRight($pad) + " : " + $CS.Model 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "Manufacturer".PadRight($pad) + " : " + $CS.Manufacturer 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "BIOS Version".PadRight($pad) + " : " + $BIOS.BIOSVersion 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "BIOS Manufacturer".PadRight($pad) + " : " + $BIOS.Manufacturer 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "BIOS Release date".PadRight($pad) + " : " + $BIOS.ReleaseDate 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "SMBIOS Version".PadRight($pad) + " : " + $BIOS.SMBIOSBIOSVersion 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "SystemType".PadRight($pad) + " : " + $CS.SystemType 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "Processor".PadRight($pad) + " : " + $PR.Name + " / " + $PR.Caption 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "Processors physical/logical".PadRight($pad) + " : " + $CS.NumberOfProcessors + " / " + $CS.NumberOfLogicalProcessors 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "Memory physical/visible".PadRight($pad) + " : " + ("{0:N0}" -f ($CS.TotalPhysicalMemory/1mb)) + " MB / " + ("{0:N0}" -f ($OS.TotalVisibleMemorySize/1kb)) + " MB" 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "Pool Paged / NonPaged".PadRight($pad) + " : " + ("{0:N0}" -f ($PoolPaged/1mb)) + " MB / " + ("{0:N0}" -f ($PoolNonPaged/1mb)) + " MB" 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "Free physical memory".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.FreePhysicalMemory/1kb)) + " MB" 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "Paging files size / free".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.SizeStoredInPagingFiles/1kb)) + " MB / " + ("{0:N0}" -f ($OS.FreeSpaceInPagingFiles/1kb)) + " MB" 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "Operating System".PadRight($pad) + " : " + $OS.Caption + " " + $OS.OSArchitecture 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")

            [string]$WinVerRevision = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' UBR).UBR

            [string]$WinVerMajor = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentMajorVersionNumber).CurrentMajorVersionNumber
            [string]$WinVerMinor = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentMinorVersionNumber).CurrentMinorVersionNumber
            "Build Number".PadRight($pad) + " : " + $WinVerMajor + "." + $WiNVerMinor + "." + $global:WinVerBuild + "." + $WinVerRevision 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")

            "Installation type".PadRight($pad) + " : " + (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").InstallationType 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "Time zone".PadRight($pad) + " : " + $TZ.Description 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "Install date".PadRight($pad) + " : " + $OS.InstallDate 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "Last boot time".PadRight($pad) + " : " + $OS.LastBootUpTime 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "Local time".PadRight($pad) + " : " + $OS.LocalDateTime 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "DNS Hostname".PadRight($pad) + " : " + $CS.DNSHostName 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "DNS Domain name".PadRight($pad) + " : " + $CS.Domain 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            "NetBIOS Domain name".PadRight($pad) + " : " + (msrdGetNBDomainName) 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
            $roles = "Standalone Workstation", "Member Workstation", "Standalone Server", "Member Server", "Backup Domain Controller", "Primary Domain Controller"
            "Domain role".PadRight($pad) + " : " + $roles[$CS.DomainRole] 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")

            " " | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")

            $drives = @()
            $drvtype = "Unknown", "No Root Directory", "Removable Disk", "Local Disk", "Network Drive", "Compact Disc", "RAM Disk"
            $Vol = Get-CimInstance -NameSpace "root\cimv2" -Query "select * from Win32_LogicalDisk" -ErrorAction Continue 2>>$global:msrdErrorLogFile
            foreach ($disk in $vol) {
                    $drv = New-Object PSCustomObject
                    $drv | Add-Member -type NoteProperty -name Letter -value $disk.DeviceID
                    $drv | Add-Member -type NoteProperty -name DriveType -value $drvtype[$disk.DriveType]
                    $drv | Add-Member -type NoteProperty -name VolumeName -value $disk.VolumeName
                    $drv | Add-Member -type NoteProperty -Name TotalMB -Value ($disk.size)
                    $drv | Add-Member -type NoteProperty -Name FreeMB -value ($disk.FreeSpace)
                    $drives += $drv
                }
            $drives | Format-Table -AutoSize -property Letter, DriveType, VolumeName, @{N="TotalMB";E={"{0:N0}" -f ($_.TotalMB/1MB)};a="right"}, @{N="FreeMB";E={"{0:N0}" -f ($_.FreeMB/1MB)};a="right"} 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
        } else {
            $proc = Get-Process | Where-Object {$_.Name -ne "Idle"}
            $proc | Format-Table -AutoSize -property id, name, @{N="WorkingSet";E={"{0:N0}" -f ($_.workingset/1kb)};a="right"},
            @{N="VM Size";E={"{0:N0}" -f ($_.VirtualMemorySize/1kb)};a="right"},
            @{N="Proc time";E={($_.TotalProcessorTime.ToString().substring(0,8))}}, @{N="Threads";E={$_.threads.count}},
            @{N="Handles";E={($_.HandleCount)}}, StartTime, Path | Out-String -Width 300 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "RunningProcesses.txt")
        }

    } Catch {
        msrdLogMessage Error ("Error collecting details about currently running processes" + $_.Exception.Message)
    }

    msrdLogMessage Normal "[$msrdLogPrefix] Get-DscConfiguration"
    Get-DscConfiguration -ErrorAction SilentlyContinue | Format-Table -AutoSize -Wrap 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "DscConfiguration.txt")
    msrdLogMessage Normal "[$msrdLogPrefix] Get-DscConfigurationStatus -all"
    Get-DscConfigurationStatus -all -ErrorAction SilentlyContinue | Format-Table -AutoSize -Wrap 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "DscConfiguration.txt")
    msrdLogMessage Normal "[$msrdLogPrefix] Test-DscConfiguration -Detailed"
    Test-DscConfiguration -Detailed -ErrorAction SilentlyContinue | Format-Table -AutoSize -Wrap 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "DscConfiguration.txt")

    msrdLogMessage Normal "[$msrdLogPrefix] (Get-Item -Path 'C:\Windows\System32\*.exe').VersionInfo"
    (Get-Item -Path 'C:\Windows\System32\*.exe').VersionInfo | Format-List -Force 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "System32_EXE.txt")
    msrdLogMessage Normal "[$msrdLogPrefix] (Get-Item -Path 'C:\Windows\System32\*.sys').VersionInfo"
    (Get-Item -Path 'C:\Windows\System32\*.sys').VersionInfo | Format-List -Force 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "System32_SYS.txt")
    msrdLogMessage Normal "[$msrdLogPrefix] (Get-Item -Path 'C:\Windows\System32\drivers\*.sys').VersionInfo"
    (Get-Item -Path 'C:\Windows\System32\drivers\*.sys').VersionInfo | Format-List -Force 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "Drivers.txt")
    $dllpath = $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "System32_DLL.txt"
    msrdLogMessage Normal "[$msrdLogPrefix] (Get-Item -Path 'C:\Windows\System32\*.dll').VersionInfo"
    Start-Job { (Get-Item -Path 'C:\Windows\System32\*.dll').VersionInfo | Format-List -Force 2>&1 | Out-File "$args" } -ArgumentList $dllpath | Out-Null

    msrdLogMessage Normal "[$msrdLogPrefix] Get-Process | Sort-Object CPU -desc | Select-Object -first 10"
    Get-Process | Sort-Object CPU -desc | Select-Object -first 10 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "RunningProcesses-Top10CPU.txt")

    msrdLogMessage Normal "[$msrdLogPrefix] Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct"
    Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "AntiVirusProducts.txt")
    msrdLogMessage Normal "[$msrdLogPrefix] 'Get-CimInstance -NameSpace 'root\SecurityCenter2' -Query 'select * from FirewallProduct'"
    Get-CimInstance -NameSpace 'root\SecurityCenter2' -Query 'select * from FirewallProduct' 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "FirewallProducts.txt")

    $Commands = @(
        "fltmc filters 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "Fltmc.txt'"
        "fltmc volumes 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "Fltmc.txt'"
        "tasklist /v 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "Tasklist.txt'"
        "icacls C:\ 2>&1 | Out-File -Append " + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "Permissions-DriveC.txt"
        "pnputil /e 2>&1 | Out-File -Append " + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "PnpUtil.txt"
        "gpresult /h '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "Gpresult.html'" + " 2>&1 | Out-Null"
        "gpresult /r /z 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "Gpresult-rz.txt'"
    )
    msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True

    msrdLogMessage Normal "[$msrdLogPrefix] Get-ChildItem Env: | Format-Table -AutoSize -Wrap"
    $envVars = Get-ChildItem Env: | Format-Table -AutoSize -Wrap | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "EnvironmentVariables.txt")

    msrdLogMessage Normal ("[$msrdLogPrefix] msinfo32 /nfo")
    $mspathnfo = $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "Msinfo32.nfo"
    Start-Job { msinfo32 /nfo $args } -ArgumentList $mspathnfo | Out-Null

    Get-MpComputerStatus 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "AntiVirusProducts.txt")

    #get installed updates
    Import-Module -Name "$PSScriptRoot\MSRDC-WU" -DisableNameChecking -Force
    msrdRunUEX_MSRDWU

    msrdGetWinRMConfig

    #get system power configuration information
    msrdGetPowerInfo

    msrdLogMessage Normal "[$msrdLogPrefix] Exporting list of installed applications"
    $paths=@(
      'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\',
      'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\',
      'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\',
      'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'
    )
    foreach($path in $paths) {
        if (Test-Path -Path $path) {
            "Based on $path" 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "InstalledApplications.txt")
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Get-ItemProperty | Select-Object DisplayName, Publisher, InstallDate, DisplayVersion | Format-Table -AutoSize -Wrap | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "InstalledApplications.txt")
        } else {
            msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] '$path' not found.`n`n"
        }
    }

    $nvidiasmiPath = "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
    if (Test-Path -Path $nvidiasmiPath) {
        msrdLogMessage Normal "[$msrdLogPrefix] NVIDIA SMI"
        $Commands = @(
            "cmd /c '$nvidiasmiPath' 2>&1 | Out-File '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "nvidia-smi.txt'"
        )
        msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
    }

    msrdLogMessage Normal "[$msrdLogPrefix] Exporting PowerShell and .Net version information"
    "PowerShell Information:" 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
    $PSVersionTable | Format-Table Name, Value 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
    ".Net Framework Information:" 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name version -EA 0 | Where-Object { $_.PSChildName -Match '^(?!S)\p{L}'} | Select-Object PSChildName, version 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SystemInfo.txt")

    msrdLogMessage Normal "[$msrdLogPrefix] Exporting Windows services information"
    $svc = Get-CimInstance -NameSpace "root\cimv2" -Query "select  ProcessId, DisplayName, StartMode,State, Name, PathName, StartName from Win32_Service" -ErrorAction Continue
    if ($svc) {
        $svc | Sort-Object DisplayName | Format-Table -AutoSize -Property ProcessId, DisplayName, StartMode,State, Name, PathName, StartName | Out-String -Width 400 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "Services.txt")
    }

    ##### Collecting certificates information
    if (!($global:msrdSource)) {
        msrdCreateLogFolder $msrdCertLogFolder

        $Commands = @(
            "certutil -verifystore -v MY 2>&1 | Out-File -Append '" + $msrdCertLogFolder + $global:msrdLogFilePrefix + "Certificates-My.txt'"
            "certutil -verifystore -v 'AAD Token Issuer' 2>&1 | Out-File -Append '" + $msrdCertLogFolder + $global:msrdLogFilePrefix + "Certificates-AAD.txt'"
            "certutil -verifystore -v 'Remote Desktop' 2>&1 | Out-File -Append '" + $msrdCertLogFolder + $global:msrdLogFilePrefix + "Certificates-RemoteDesktop.txt'"
        )
        msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True

        "Get-Acl -Path 'C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys'" | Out-File -Append ($msrdCertLogFolder + $global:msrdLogFilePrefix + "MachineKeys.txt")
        Get-Acl -Path "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys" | Select-Object -ExpandProperty Access | Out-File -Append ($msrdCertLogFolder + $global:msrdLogFilePrefix + "MachineKeys.txt")
        "Get-Acl -Path 'C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\f686aace6942fb7f7ceb231212eef4a4_*'`n" | Out-File -Append ($msrdCertLogFolder + $global:msrdLogFilePrefix + "MachineKeys.txt")
        Get-Acl -Path "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\f686aace6942fb7f7ceb231212eef4a4_*" | Select-Object -ExpandProperty Access | Out-File -Append ($msrdCertLogFolder + $global:msrdLogFilePrefix + "MachineKeys.txt")

        $tbCert = New-Object system.Data.DataTable
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
        msrdGetStore "My"
        $aCert = $tbCert.Select("Store = 'My' ")
        foreach ($cert in $aCert) {
            $aIssuer = $tbCert.Select("SubjectKeyIdentifier = '" + ($cert.AuthorityKeyIdentifier).tostring() + "'")
            if ($aIssuer.Count -gt 0) {
            $cert.IssuerThumbprint = ($aIssuer[0].Thumbprint).ToString()
            }
        }
        $tbcert | Export-Csv ($msrdCertLogFolder + $global:msrdLogFilePrefix + "Certificates-My.csv") -noType -Delimiter "`t" -Append

        ##### Collecting SPN information
        $Commands = @(
            "setspn -L " + $env:computername + " 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SPN.txt'"
            "setspn -Q WSMAN/" + $env:computername + " 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SPN.txt'"
            "setspn -Q WSMAN/" + $global:msrdFQDN + " 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SPN.txt'"
            "setspn -F -Q WSMAN/" + $env:computername + " 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SPN.txt'"
            "setspn -F -Q WSMAN/" + $global:msrdFQDN + " 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SPN.txt'"
            "setspn -Q TERMSRV/" + $env:computername + " 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SPN.txt'"
            "setspn -Q TERMSRV/" + $global:msrdFQDN + " 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SPN.txt'"
            "setspn -F -Q TERMSRV/" + $env:computername + " 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SPN.txt'"
            "setspn -F -Q TERMSRV/" + $global:msrdFQDN + " 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SPN.txt'"
        )
        msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
    }
}

function msrdGetCoreRoles {

    #get RDS roles information
    if ($global:msrdOSVer -like "*Windows Server*") {
        msrdLogMessage Normal "[$msrdLogPrefix] Installed Remote Desktop Roles"

        msrdCreateLogFolder $global:msrdSysInfoLogFolder

        $isRoleInst = Get-WindowsFeature | Where-Object { $_.InstallState -eq "Installed" }
        $isRoleInst | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "InstalledRoles.txt")

        $script:isRDSinst = (Get-WindowsFeature -Name RDS-*) | Where-Object { $_.InstallState -eq "Installed" }
        if ($script:isRDSinst) {
            msrdCreateLogFolder $global:msrdRDSLogFolder
        }

        #Collecting RDLS information
        if ($script:isRDSinst.Name -eq "RDS-Licensing") {
            " " | Out-File -Append $global:msrdOutputLogFile
            msrdLogMessage Normal "[$msrdLogPrefix] Remote Desktop Licensing"
            msrdGetRDLSDB
        }

        #Collecting RDSH information
        if ($script:isRDSinst.Name -eq "RDS-RD-Server") {
            " " | Out-File -Append $global:msrdOutputLogFile
            msrdLogMessage Normal "[$msrdLogPrefix] Remote Desktop Session Host"

            $Commands = @(
                "cmd /c 'wmic /namespace:\\root\CIMV2\TerminalServices PATH Win32_TerminalServiceSetting WHERE (__CLASS !=`"`") CALL GetGracePeriodDays' 2>&1 | Out-File -Append '" + $global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdsh_GracePeriod.txt'"
            )
            msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
        }

        if (($script:isRDSinst.Name -eq "RDS-Licensing") -or ($script:isRDSinst.Name -eq "RDS-RD-Server")) {
            if ((get-ciminstance -Class Win32_ComputerSystem).PartOfDomain) {
                $Commands = @("net localgroup 'Terminal Server License Servers' /domain 2>&1 | Out-File -Append '" + $global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "TSLSMembership.txt'")
                msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
            } else {
                msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] Machine is not part of a domain. 'Terminal Server License Servers' group not found."
            }
        }

        if ($global:msrdRDS) {
            #Collecting RDCB/GetFarmData information
            if ($script:isRDSinst.Name -eq "RDS-CONNECTION-BROKER") {
                " " | Out-File -Append $global:msrdOutputLogFile
                msrdLogMessage Normal "[$msrdLogPrefix] RDS GetFarmData"
                GetFarmData

                " " | Out-File -Append $global:msrdOutputLogFile
                msrdLogMessage Normal "[$msrdLogPrefix] Remote Desktop Connection Broker"
                msrdGetRDCB
            }

            #Collecting RDGW information
            if ($script:isRDSinst.Name -eq "RDS-GATEWAY") {
                " " | Out-File -Append $global:msrdOutputLogFile
                msrdLogMessage Normal "[$msrdLogPrefix] Remote Desktop Gateway"
                msrdGetRDGW
            }

            #Collecting RDWA information
            if ($script:isRDSinst.Name -eq "RDS-WEB-ACCESS") {
                " " | Out-File -Append $global:msrdOutputLogFile
                msrdLogMessage Normal "[$msrdLogPrefix] Remote Desktop Web Access"
                msrdGetRDWA
            }
        }
    }
}

function msrdGetCoreRDSAVDInfo {

    #get RDS and AVD related data
    msrdCreateLogFolder $global:msrdSysInfoLogFolder

    if (!($global:msrdSource)) {
        msrdLogMessage Normal ("[$msrdLogPrefix] Copy-Item 'C:\WindowsAzure\Logs\Plugins\*'")
        if (Test-path -path 'C:\WindowsAzure\Logs\Plugins') {
            Copy-Item 'C:\WindowsAzure\Logs\Plugins\*' $global:msrdSysInfoLogFolder -Recurse -ErrorAction Continue 2>>$global:msrdErrorLogFile
        } else {
            msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] WindowsAzure Plugins logs not found."
        }

        msrdLogMessage Normal ("[$msrdLogPrefix] Copy-Item 'C:\Packages\Plugins\*\*\Status'")
        $sourceFolder = "C:\Packages\Plugins"
        if (Test-Path -Path $sourceFolder) { 
            $subfolders = Get-ChildItem -Path $sourceFolder -Directory -Recurse -Filter "Status" 2>&1 | Out-Null

            foreach ($subfolder in $subfolders) {
                $statusFolder = Join-Path -Path $subfolder.Parent.FullName -ChildPath "Status"
                if (Test-Path -Path $statusFolder) {
                    # Build the destination folder path dynamically based on the subfolder path
                    $destinationSubfolder = $subfolder.FullName.Replace($sourceFolder, $global:msrdSysInfoLogFolder)

                    # Create the destination folder if it does not exist
                    if (!(Test-Path -Path $destinationSubfolder)) {
                        New-Item -ItemType Directory -Path $destinationSubfolder -Force
                    }

                    # Copy only the "Status" subfolder and its contents
                    $statusFiles = Get-ChildItem -Path $statusFolder -Recurse 2>&1 | Out-Null
                    foreach ($statusFile in $statusFiles) {
                        $relativePath = $statusFile.FullName.Replace($statusFolder, "")
                        $destinationPath = Join-Path -Path $destinationSubfolder -ChildPath $relativePath
                        Try {
                            Copy-Item -Path $statusFile.FullName -Destination $destinationPath -Force -ErrorAction Continue 2>&1 | Out-Null
                        } Catch {
                            $failedCommand = $_.InvocationInfo.Line.TrimStart()
                            $errorMessage = $_.Exception.Message.TrimStart()
                            msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
                            if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                                msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
                            } else {
                                msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
                            }
                        }
                    }
                }
            }
        } else {
            msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] C:\Packages\Plugins not found."
        }

        msrdGetLogFiles -LogPrefix $msrdLogPrefix -Type Files -OutputFolder $global:msrdSysInfoLogFolder -LogFilePath 'C:\WindowsAzure\Logs\WaAppAgent.log' -LogFileID 'WaAppAgent'
        msrdGetLogFiles -LogPrefix $msrdLogPrefix -Type Files -OutputFolder $global:msrdSysInfoLogFolder -LogFilePath 'C:\WindowsAzure\Logs\MonitoringAgent.log' -LogFileID 'MonitoringAgent'
        msrdGetLogFiles -LogPrefix $msrdLogPrefix -Type Files -OutputFolder $global:msrdSysInfoLogFolder -LogFilePath 'c:\windows\inf\setupapi.dev.log' -LogFileID 'setupapi-dev-log'

        msrdCreateLogFolder $global:msrdNetLogFolder
        msrdGetLogFiles -LogPrefix $msrdLogPrefix -Type Files -OutputFolder $global:msrdNetLogFolder -LogFilePath 'C:\Windows\debug\NetSetup.LOG' -LogFileID 'NetSetup'

        if ($global:msrdAVD) { $global:msrdTechFolder = $global:msrdAVDLogFolder } else { $global:msrdTechFolder = $global:msrdRDSLogFolder }
        msrdCreateLogFolder $global:msrdTechFolder
        $Commands = @(
            "qwinsta /counter 2>&1 | Out-File -Append '" + $global:msrdTechFolder + $global:msrdLogFilePrefix + "Qwinsta.txt'"
        )
        msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
    }

    (Get-AppLockerPolicy -Effective).RuleCollections 2>&1 | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "AppLockerRules.txt")

    $Commands = @(
        "dxdiag /whql:off /t '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "DxDiag.txt'"
    )
    msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True

    if (!($global:msrdRDS)) {
        msrdGetRdClientAutoTrace
        msrdGetRdClientSub

        msrdCreateLogFolder $global:msrdAVDLogFolder
        if ($global:avdnettestpath -ne "") {
            $global:avdnettestpathlog = $global:msrdLogDir + "${env:computername}_AVD\${env:computername}_avdnettest.log"
            $Commands = @(
                "$global:avdnettestpath --log-level debug --log-file '$global:avdnettestpathlog'"
            )
            msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
        }
    }

    if ([ADSI]::Exists("WinNT://localhost/Administrators")) {
        $Commands = @("net localgroup 'Administrators' 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "LocalGroupsMembership.txt'")
        msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
    } else {
        msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] 'Administrators' group not found."
    }

    if ([ADSI]::Exists("WinNT://localhost/Remote Desktop Users")) {
        $Commands = @("net localgroup 'Remote Desktop Users' 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "LocalGroupsMembership.txt'")
        msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
    } else {
        msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] 'Remote Desktop Users' group not found."
    }

    if ($global:msrdRDS) {
        if ([ADSI]::Exists("WinNT://localhost/RDS Remote Access Servers")) {
            $Commands = @("net localgroup 'RDS Remote Access Servers' 2>&1 | Out-File -Append " + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "LocalGroupsMembership.txt")
            msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
        } else {
            msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] 'RDS Remote Access Servers' group not found."
        }

        if ([ADSI]::Exists("WinNT://localhost/RDS Management Servers")) {
            $Commands = @("net localgroup 'RDS Management Servers' 2>&1 | Out-File -Append " + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "LocalGroupsMembership.txt")
            msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
        } else {
            msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] 'RDS Management Servers' group not found."
        }

        if ([ADSI]::Exists("WinNT://localhost/RDS Endpoint Servers")) {
            $Commands = @("net localgroup 'RDS Endpoint Servers' 2>&1 | Out-File -Append " + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "LocalGroupsMembership.txt")
            msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
        } else {
            msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] 'RDS Endpoint Servers' group not found."
        }
    }

    if ($global:msrdAVD) {
        msrdGetLogFiles -LogPrefix $msrdLogPrefix -Type Files -OutputFolder $global:msrdTechFolder -LogFilePath 'C:\Users\AgentInstall.txt' -LogFileID 'AgentInstall_initial'
        msrdGetLogFiles -LogPrefix $msrdLogPrefix -Type Files -OutputFolder $global:msrdTechFolder -LogFilePath 'C:\Users\AgentBootLoaderInstall.txt' -LogFileID 'AgentBootLoaderInstall_initial'
        msrdGetLogFiles -LogPrefix $msrdLogPrefix -Type Files -OutputFolder $global:msrdTechFolder -LogFilePath 'C:\Program Files\Microsoft RDInfra\AgentInstall.txt' -LogFileID 'AgentInstall_updates'
        msrdGetLogFiles -LogPrefix $msrdLogPrefix -Type Files -OutputFolder $global:msrdTechFolder -LogFilePath 'C:\Program Files\Microsoft RDInfra\GenevaInstall.txt' -LogFileID 'GenevaInstall'
        msrdGetLogFiles -LogPrefix $msrdLogPrefix -Type Files -OutputFolder $global:msrdTechFolder -LogFilePath 'C:\Program Files\Microsoft RDInfra\SXSStackInstall.txt' -LogFileID 'SXSStackInstall'
        msrdGetLogFiles -LogPrefix $msrdLogPrefix -Type Files -OutputFolder $global:msrdTechFolder -LogFilePath 'C:\Program Files\MsRDCMMRHost\MsRDCMMRHostInstall.log' -LogFileID 'MsRDCMMRHostInstall'
        msrdGetLogFiles -LogPrefix $msrdLogPrefix -Type Files -OutputFolder $global:msrdTechFolder -LogFilePath 'C:\Windows\Temp\ScriptLog.log' -LogFileID 'ScriptLog'

        msrdLogMessage Normal ("[$msrdLogPrefix] <BrokerURI>api/health and <BrokerURIGlobal>api/health status")
        $brokerURIregpath = "HKLM:\SOFTWARE\Microsoft\RDInfraAgent\"

        $brokerout = $global:msrdAVDLogFolder + $global:msrdLogFilePrefix + "AVDServicesURIHealth.txt"
        $brokerURIregkey = "BrokerURI"
            if (msrdTestRegistryValue -path $brokerURIregpath -value $brokerURIregkey) {
                try {
                    $brokerURI = (Get-ItemPropertyValue -Path $brokerURIregpath -name $brokerURIregkey) + "api/health"
                    "$brokerURI" | Out-File -Append $brokerout
                    Invoke-WebRequest $brokerURI -UseBasicParsing | Out-File -Append $brokerout
                    "`n" | Out-File -Append $brokerout
                } catch {
                    msrdLogException ("$(msrdGetLocalizedText "errormsg") Invoke-WebRequest $brokerURI") -ErrObj $_ $fLogFileOnly
                }
            } else {
                msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] Reg key '$brokerURIregpath$brokerURIregkey' not found."
            }

        $brokerURIGlobalregkey = "BrokerURIGlobal"
            if (msrdTestRegistryValue -path $brokerURIregpath -value $brokerURIGlobalregkey) {
                try {
                    $brokerURIGlobal = (Get-ItemPropertyValue -Path $brokerURIregpath -name $brokerURIGlobalregkey) + "api/health"
                    "$brokerURIGlobal" | Out-File -Append $brokerout
                    Invoke-WebRequest $brokerURIGlobal -UseBasicParsing | Out-File -Append $brokerout
                    "`n" | Out-File -Append $brokerout
                } catch {
                    msrdLogException ("$(msrdGetLocalizedText "errormsg") Invoke-WebRequest $brokerURIGlobal") -ErrObj $_ $fLogFileOnly
                }
            } else {
                msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] Reg key '$brokerURIregpath$brokerURIGlobalregkey' not found."
            }

        $diagURIregkey = "DiagnosticsUri"
            if (msrdTestRegistryValue -path $brokerURIregpath -value $diagURIregkey) {
                try {
                    $diagURI = (Get-ItemPropertyValue -Path $brokerURIregpath -name $diagURIregkey) + "api/health"
                    "$diagURI" | Out-File -Append $brokerout
                    Invoke-WebRequest $diagURI -UseBasicParsing | Out-File -Append $brokerout
                    "`n" | Out-File -Append $brokerout
                } catch {
                    msrdLogException ("$(msrdGetLocalizedText "errormsg") Invoke-WebRequest $diagURI") -ErrObj $_ $fLogFileOnly
                }
            } else {
                msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] Reg key '$brokerURIregpath$diagURIregkey' not found."
            }

        $brokerResURIGlobalregkey = "BrokerResourceIdURIGlobal"
            if (msrdTestRegistryValue -path $brokerURIregpath -value $brokerResURIGlobalregkey) {
                try {
                    $brokerResURIGlobal = (Get-ItemPropertyValue -Path $brokerURIregpath -name $brokerResURIGlobalregkey) + "api/health"
                    "$brokerResURIGlobal" | Out-File -Append $brokerout
                    Invoke-WebRequest $brokerResURIGlobal -UseBasicParsing | Out-File -Append $brokerout
                } catch {
                    msrdLogException ("$(msrdGetLocalizedText "errormsg") Invoke-WebRequest $brokerResURIGlobal") -ErrObj $_ $fLogFileOnly
                }
            } else {
                msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] Reg key '$brokerURIregpath$brokerResURIGlobalregkey' not found."
            }
        #endregion URI

        #region Collecting Geneva Monitoring information
        " " | Out-File -Append $global:msrdOutputLogFile

        msrdCreateLogFolder $global:msrdGenevaLogFolder
        msrdCreateLogFolder $global:msrdSchtaskFolder

        Try {
            msrdLogMessage Normal "[$msrdLogPrefix] Azure Instance Metadata Service (IMDS) endpoint accessibility"
            $request = [System.Net.WebRequest]::Create("http://169.254.169.254/metadata/instance/network?api-version=2021-12-13")
            $request.Proxy = [System.Net.WebProxy]::new()
            $request.Headers.Add("Metadata","True")
            $request.Timeout = 10000
            $request.GetResponse() | Out-File -Append ($global:msrdGenevaLogFolder + $global:msrdLogFilePrefix + "IMDSRequestInfo.txt")

        } Catch {
            msrdLogException ("$(msrdGetLocalizedText "errormsg") $request") -ErrObj $_ $fLogFileOnly
            if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                msrdAdd-OutputBoxLine ("Error in IMDSquery: $_") "Magenta"
            } else {
                msrdLogMessage Warning ("Error in IMDSquery: $_")
            }
        }

        if (Get-ScheduledTask GenevaTask* -ErrorAction Ignore) {
            (Get-ScheduledTask GenevaTask*).TaskName | ForEach-Object -Process {
                Export-ScheduledTask -TaskName $_ 2>&1 | Out-File -Append ($global:msrdSchtaskFolder + $global:msrdLogFilePrefix + "schtasks_" + $_ + ".xml")
                Get-ScheduledTaskInfo -TaskName $_ 2>&1 | Out-File -Append ($global:msrdSchtaskFolder + $global:msrdLogFilePrefix + "schtasks_" + $_ + "_Info.txt")
            }
        } else {
            msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] Geneva Scheduled Task not found."
        }

        msrdGetMonTables
        msrdGetMonConfig

        $tccpath = "C:\Program Files\Microsoft Monitoring Agent"
        if (Test-Path -Path $tccpath) {
            $Commands = @(
                "cmd /c `"C:\Program Files\Microsoft Monitoring Agent\Agent\TestCloudConnection.exe`" 2>&1 | Out-File -Append '" + $global:msrdGenevaLogFolder + $global:msrdLogFilePrefix + "AMA-TestCloudConnection.txt'"
            )
            msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
        
            $monVars = Get-ChildItem Env: | Where-Object {$_.Name -like "*monitoring*" -or $_.Value -like "*monitoring*"} | Format-Table -AutoSize -Wrap | Out-File -Append ($global:msrdGenevaLogFolder + $global:msrdLogFilePrefix + "MonitoringVariables.txt")
        } else {
            msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] Microsoft Monitoring Agent components not found."
        }
        #endregion geneva
    }
}

Function msrdCollectUEX_AVDCoreLog {
    param( [bool[]]$varsCore, [bool]$dumpProc, [int]$pidProc )

    #main Core
    " " | Out-File -Append $global:msrdOutputLogFile
    msrdLogMessage Info "$(msrdGetLocalizedText "rdcmsg")`n" -Color "Cyan"
    " " | Out-File -Append $global:msrdOutputLogFile

    msrdLogMessage Info ("$(msrdGetLocalizedText "coremsg")") #Collecting Core troubleshooting data
    msrdProgressStatusInit 202
    
    if($dumpProc -and $pidProc) { msrdGetDump -pidProc $pidProc } #Collecting process dumps
    if ($varsCore[0]) { msrdGetCoreRDSAVDInfo } #Collect RDS/AVD information
    if ($varsCore[1]) { msrdGetCoreEventLogs -varsCore $varsCore[2] } #Collect event logs
    if ($varsCore[3]) { msrdGetCoreRegKeys } #Collect reg keys
    if ($varsCore[4]) { msrdGetCoreRDPNetADInfo -varsCore $varsCore[5] } #Collect RDP and Net info
    if ($varsCore[6]) { msrdGetCoreSchedTasks } #Remote Desktop scheduled tasks
    if ($varsCore[7]) { msrdGetCoreSystemInfo } #Collect system information
    if ($varsCore[8] -and !($global:msrdSource)) { msrdGetCoreRoles } #RDS roles and data

    msrdProgressStatusEnd
}

Export-ModuleMember -Function msrdCollectUEX_AVDCoreLog
# SIG # Begin signature block
# MIInlgYJKoZIhvcNAQcCoIInhzCCJ4MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAofbMR8usb1bp2
# YHoohM5zDyzSYYmaEpc5R7Wh/l1eOqCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXYwghlyAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBtJz0BhQ1EJ6/rA97KehWOn
# 6epdso6mCvKiQJP+3tfTMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAeBkJByoHH17skfCGBxbb94eZl08bi/zlwL8O/oIhBCnDIhtoxM5oMMEO
# dyntingi8AI7t/ADgN4qEr7aOXMpBoplhgpax5D8QYJULZ6ynDcVuMKarWSnT0eK
# KoNt4o93bI3poSeht9EVbtgTUSj+LFewR5wVi//0fKeV8v1qgMG/U4IGgIxwMR0W
# O8P8l8GkhDpFed0eiAkLRVATwMkbSq1hQZqGLCnNzqBvCikHFcb8lvpCKr74nMYy
# x3BcTVeHOBOp11J6V2aZmooQkxwjrJGDmwQ2Ntm+Kgxr4LZkHvWZHo/eB0e4FkHR
# 2fUqFll9veuyZAEo71fgtB6tStxywaGCFwAwghb8BgorBgEEAYI3AwMBMYIW7DCC
# FugGCSqGSIb3DQEHAqCCFtkwghbVAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCCpQTtAE8EB/Nv4jGEQx/Tor1juZ4k3LF8sSOi8q/u3gIGZF1oi5d7
# GBMyMDIzMDUyMzE0NDQ1NS4wODlaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4QTgyLUUz
# NEYtOUREQTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVcwggcMMIIE9KADAgECAhMzAAABwvp9hw5UU0ckAAEAAAHCMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEy
# OFoXDTI0MDIwMjE5MDEyOFowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhBODItRTM0Ri05RERBMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAtfEJvPKOSFn3petp9wco29/UoJmDDyHpmmpRruRVWBF3
# 7By0nvrszScOV/K+LvHWWWC4S9cme4P63EmNhxTN/k2CgPnIt/sDepyACSkya4uk
# qc1sT2I+0Uod0xjy9K2+jLH8UNb9vM3yH/vCYnaJSUqgtqZUly82pgYSB6tDeZIY
# cQoOhTI+M1HhRxmxt8RaAKZnDnXgLdkhnIYDJrRkQBpIgahtExtTuOkmVp2y8YCo
# FPaUhUD2JT6hPiDD7qD7A77PLpFzD2QFmNezT8aHHhKsVBuJMLPXZO1k14j0/k68
# DZGts1YBtGegXNkyvkXSgCCxt3Q8WF8laBXbDnhHaDLBhCOBaZQ8jqcFUx8ZJSXQ
# 8sbvEnmWFZmgM93B9P/JTFTF6qBVFMDd/V0PBbRQC2TctZH4bfv+jyWvZOeFz5yl
# tPLRxUqBjv4KHIaJgBhU2ntMw4H0hpm4B7s6LLxkTsjLsajjCJI8PiKi/mPKYERd
# mRyvFL8/YA/PdqkIwWWg2Tj5tyutGFtfVR+6GbcCVhijjy7l7otxa/wYVSX66Lo0
# alaThjc+uojVwH4psL+A1qvbWDB9swoKla20eZubw7fzCpFe6qs++G01sst1SaA0
# GGmzuQCd04Ue1eH3DFRDZPsN+aWvA455Qmd9ZJLGXuqnBo4BXwVxdWZNj6+b4P8C
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBRGsYh76V41aUCRXE9WvD++sIfGajAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQARdu3dCkcLLPfaJ3rR1M7D9jWHvneffkmXvFIJtqxHGWM1oqAh+bqxpI7HZz2M
# eNhh1Co+E9AabOgj94Sp1seXxdWISJ9lRGaAAWzA873aTB3/SjwuGqbqQuAvUzBF
# CO40UJ9anpavkpq/0nDqLb7XI5H+nsmjFyu8yqX1PMmnb4s1fbc/F30ijaASzqJ+
# p5rrgYWwDoMihM5bF0Y0riXihwE7eTShak/EwcxRmG3h+OT+Ox8KOLuLqwFFl1si
# TeQCp+YSt4J1tWXapqGJDlCbYr3Rz8+ryTS8CoZAU0vSHCOQcq12Th81p7QlHZv9
# cTRDhZg2TVyg8Gx3X6mkpNOXb56QUohI3Sn39WQJwjDn74J0aVYMai8mY6/WOurK
# MKEuSNhCiei0TK68vOY7sH0XEBWnRSbVefeStDo94UIUVTwd2HmBEfY8kfryp3Rl
# A9A4FvfUvDHMaF9BtvU/pK6d1CdKG29V0WN3uVzfYETJoRpjLYFGq0MvK6QVMmuN
# xk3bCRfj1acSWee14UGjglxWwvyOfNJe3pxcNFOd8Hhyp9d4AlQGVLNotaFvopgP
# LeJwUT3dl5VaAAhMwvIFmqwsffQy93morrprcnv74r5g3ejC39NYpFEoy+qmzLW1
# jFa1aXE2Xb/KZw2yawqldSp0Hu4VEkjGxFNc+AztIUWwmTCCB3EwggVZoAMCAQIC
# EzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoX
# DTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC
# 0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VG
# Iwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP
# 2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/P
# XfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361
# VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwB
# Sru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9
# X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269e
# wvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDw
# wvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr
# 9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+e
# FnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAj
# BgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+n
# FV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBH
# hkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
# BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4Swf
# ZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTC
# j/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu
# 2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/
# GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3D
# YXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbO
# xnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqO
# Cb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I
# 6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0
# zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaM
# mdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNT
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLOMIICNwIBATCB+KGB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046OEE4Mi1FMzRGLTlEREExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAMp1N1VLhPMvWXEoZfmF4apZlnRUoIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoFxALMCIYDzIwMjMwNTIzMTgxMjI3WhgPMjAyMzA1MjQxODEyMjdaMHcw
# PQYKKwYBBAGEWQoEATEvMC0wCgIFAOgXEAsCAQAwCgIBAAICBAECAf8wBwIBAAIC
# EUkwCgIFAOgYYYsCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAK
# MAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQCMwhTZ1hYY
# v/672PMsliHQSNMSpkhHH6eAEydI58fqkYIYFL4j8h+mkAwq388Gw/xiwOQKW2FW
# uPhMV+tAGAuOv18ZAGJYZZXF5Df1Sq2dRj0etO3ShBsAEXNYDB+GLzjaQ079BvHP
# NcB/+EHwSteqK19sZqpczpnyn7xjoRrGMDGCBA0wggQJAgEBMIGTMHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABwvp9hw5UU0ckAAEAAAHCMA0GCWCG
# SAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZI
# hvcNAQkEMSIEIDpTQxq3n8l3VoUbAm1QUQB9MClU5AbnLqFp34o2YLcuMIH6Bgsq
# hkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgypNgW8fpsMV57r0F5beUuiEVOVe4Bdma
# O+e28mGDUBYwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAIT
# MwAAAcL6fYcOVFNHJAABAAABwjAiBCDJ/B2zg0AuHEaNKiONZu2VhTGFkQRDI7w+
# OF9ftoYeTjANBgkqhkiG9w0BAQsFAASCAgBhJzCVU5yWd+A+SBaCggRq+QjuUq4e
# eCQRmz/j5JFIKn2fVgzYo1n4QNcaQtJV40kjvmjmlLXn985OvUs7++TnXY2t4+J9
# hYJp1vZoWdbHRmnaq1B1nYsRtx9gVSJy6elZIQe6Ug78GsP8s/xl67c4k3h4DO7w
# YotTVhBCxpZo3jVnBqI6axA/duXgruXd8UUkc6teJrEOIdWMisdSpYuuSBYMJHD6
# iUQZdNCi+AXLwcq7KDwn9rMVPfXztuE4Jq/r5vmNmuSxOQnYKdq/MnAcLptaOL4H
# aVpe+ntHiC7gBEhoUxjIml4koySgGyAIphedT+qBbYDlHNMg4d3w0F0eyFTR4IBx
# NxlMiXsrXjE2eVyQbjodpfqv2Yw9fXrybCOcpF/TNxpMg5Pus+jOL2dJ92d0vt81
# yK52PrhuNhnptB681k/SFF356GciY4Ldd+5KlJuVyFkLHWb2wbPEtEzQib6JEh1x
# BeIxr/nQx864qzCgu+0Henb4A/HI04DGlyHxRUFmJWOU5myuz/kWsaYt4RtwzruI
# lL8zgDqLD3Pb3LcwQyNUiKCQ+mMuMXRgQAKOGDx7JuITYRYIHTnRWaSNuOk26t64
# 6tC26U/80cvxEx3rwDChrP8joGeFWFiqIVqbpkaIoji6+I+7a1W5uT9BCVLzcy8h
# 1JUDWhqQ7UWm9A==
# SIG # End signature block
