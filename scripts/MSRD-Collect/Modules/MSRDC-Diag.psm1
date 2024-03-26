<#
.SYNOPSIS
   Scenario module for collecting Microsoft Remote Desktop Diagnostics data

.DESCRIPTION
   Runs Diagnostics checks and generates a report in .html format

.NOTES
   Authors    : Robert Klemencz (Microsoft) & Alexandru Olariu (Microsoft)
   Requires   : At least PowerShell 5.1 (This module is not for stand-alone use. It is used automatically from within the main MSRD-Collect.ps1 script)
   Version    : See MSRD-Collect.ps1 version
   Feedback   : Send an e-mail to MSRDCollectTalk@microsoft.com
#>

#region versions
$latestRDCver = 1242400 #desktop client
$minRDCver = 1216720
$minRDCverPubSpath = 1234880

$latestStoreCver = 10230000 #old store client
$minStoreCver = 10215340
$latestw365ver = 111620

$latestAvdStoreApp = 1241570 #new store client
$latestAvdHostApp = 1241570

$latestFSLogixVer = 29844042104

$latestWebRTCVer = 133230207001
$latestMMRver = 10230124004
$minRDCverMMR = 123916
$minVCRverMMR = 1432313320 #Visual C++ Redistributable
#endregion versions

$msrdLogPrefix = "Diag"
$msrdDiagFile = $global:msrdBasicLogFolder + "MSRD-Diag.html"
$msrdAgentpath = "C:\Program Files\Microsoft RDInfra\"

$script:RDClient = (Get-ItemProperty hklm:\software\microsoft\windows\currentversion\uninstall\* | Where-Object {(($_.DisplayName -eq "Remote Desktop") -or ($_.DisplayName -eq "Remotedesktop")) -and ($_.Publisher -like "*Microsoft*")})

if ($global:msrdAVD) { $script:msrdMenuCat = "AVD/RDS" } else { $script:msrdMenuCat = "RDS" }


#region URL references
$msrdcRef = "<a href='https://learn.microsoft.com/en-us/azure/virtual-desktop/whats-new-client-windows' target='_blank'>What's new in the Remote Desktop client for Windows</a>"
$vmsizeRef = "<a href='https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/virtual-machine-recs#recommended-vm-sizes-for-standard-or-larger-environments' target='_blank'>Session host virtual machine sizing guidelines</a>"
$uwpcRef = "<a href='https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/windows-whatsnew' target='_blank'>What's new in the Remote Desktop Microsoft Store client</a>"
$avexRef = "<a href='https://docs.microsoft.com/en-us/azure/architecture/example-scenario/wvd/windows-virtual-desktop-fslogix#antivirus-exclusions' target='_blank'>Antivirus exclusions</a>"
$w10proRef = "<a href='https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro' target='_blank'>Windows 10 Home and Pro</a>"
$w10entRef = "<a href='https://docs.microsoft.com/en-us/lifecycle/products/windows-10-enterprise-and-education' target='_blank'>Windows 10 Enterprise and Education</a>"
$w81Ref = "<a href='https://learn.microsoft.com/en-us/lifecycle/products/windows-81' target='_blank'>Windows 8.1</a>"
$avdOSRef = "<a href='https://docs.microsoft.com/en-us/azure/virtual-desktop/prerequisites#operating-systems-and-licenses' target='_blank'>Operating systems and licenses</a>"
$avdLicRef = "<a href='https://docs.microsoft.com/en-us/azure/virtual-desktop/apply-windows-license' target='_blank'>Apply Windows license to session host virtual machines</a>"
$fslogixRef = "<a href='https://docs.microsoft.com/en-us/fslogix/whats-new' target='_blank'>FSLogix Release Notes</a>"
$cloudcacheRef = "<a href='https://docs.microsoft.com/en-us/fslogix/configure-cloud-cache-tutorial#configure-cloud-cache-for-smb' target='_blank'>Configure profile containers with Cloud Cache</a>"
$gpuRef = "<a href='https://learn.microsoft.com/en-us/azure/virtual-desktop/enable-gpu-acceleration' target='_blank'>Configure graphics processing unit (GPU) acceleration for Azure Virtual Desktop</a>"
$mmrRef = "<a href='https://learn.microsoft.com/en-us/azure/virtual-desktop/whats-new-multimedia-redirection' target='_blank'>What's new in multimedia redirection?</a>"
$defenderRef = "<a href='https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/security-malware-windows-defender-disableantispyware' target='_blank'>DisableAntiSpyware</a>"
$shortpathRef = "<a href='https://go.microsoft.com/fwlink/?linkid=2204021' target='_blank'>https://go.microsoft.com/fwlink/?linkid=2204021</a>"
$webrtcRef = "<a href='https://learn.microsoft.com/en-us/azure/virtual-desktop/whats-new-webrtc' target='_blank'>What's new in the Remote Desktop WebRTC Redirector Service</a>"
$avdTsgRef = "https://docs.microsoft.com/en-us/azure/virtual-desktop/troubleshoot-agent"
$spathTsgRef = "https://learn.microsoft.com/en-us/azure/virtual-desktop/troubleshoot-rdp-shortpath"
$fslogixTsgRef = "https://learn.microsoft.com/en-us/fslogix/troubleshooting-events-logs-diagnostics"
#endregion URL references

#region hyperlinks
$computerName = $env:computername

$msrdErrorfileurl = "${computerName}_MSRD-Collect-Error.txt"
$permDriveCfile = "${computerName}_SystemInfo\${computerName}_Permissions-DriveC.txt"
$fwrfile = "${computerName}_Networking\${computerName}_FirewallRules.txt"
$getfarmdatafile = "${computerName}_RDS\${computerName}_GetFarmData.txt"
$getcapfile = "${computerName}_RDS\${computerName}_rdgw_ConnectionAuthorizationPolicy.txt"
$getrapfile = "${computerName}_RDS\${computerName}_rdgw_ResourceAuthorizationPolicy.txt"
$dxdiagfile = "${computerName}_SystemInfo\${computerName}_DxDiag.txt"
$domtrustfile = "${computerName}_Networking\${computerName}_Nltest-domtrust.txt"
$kmsfile = "${computerName}_SystemInfo\${computerName}_KMS-Servers.txt"
$slmgrfile = "${computerName}_SystemInfo\${computerName}_slmgr-dlv.txt"
$sysinfofile = "${computerName}_SystemInfo\${computerName}_SystemInfo.txt"
$gracefile = "${computerName}_RDS\${computerName}_rdsh_GracePeriod.txt"
$avinfofile = "${computerName}_SystemInfo\${computerName}_AntiVirusProducts.txt"
$dsregfile = "${computerName}_SystemInfo\${computerName}_Dsregcmd.txt"
$instappsfile = "${computerName}_SystemInfo\${computerName}_InstalledApplications.txt"
$tslsgroupfile = "${computerName}_RDS\${computerName}_TSLSMembership.txt"
$agentInitinstfile = "${computerName}_AVD\${computerName}_AgentInstall_initial.txt"
$agentUpdateinstfile = "${computerName}_AVD\${computerName}_AgentInstall_updates.txt"
$agentBLinstfile = "${computerName}_AVD\${computerName}_AgentBootLoaderInstall_initial.txt"
$sxsinstfile = "${computerName}_AVD\${computerName}_SXSStackInstall.txt"

$avdnettestfile = "${computerName}_AVD\${computerName}_avdnettest.log"

$montablesfolder = "${computerName}_AVD\Monitoring\MonTables"
$fslogixfolder = "${computerName}_FSLogix"

$updhistfile = "${computerName}_SystemInfo\${computerName}_UpdateHistory.html"
$powerfile = "${computerName}_SystemInfo\${computerName}_PowerReport.html"
$licpakfile = "${computerName}_RDS\${computerName}_rdls_LicenseKeyPacks.html"
$licoutfile = "${computerName}_RDS\${computerName}_rdls_IssuedLicenses.html"
$gpresfile = "${computerName}_SystemInfo\${computerName}_Gpresult.html"

$script:aplevtxfile = "${computerName}_EventLogs\${computerName}_Application.evtx"
$script:sysevtxfile = "${computerName}_EventLogs\${computerName}_System.evtx"
$script:rdsevtxfile = "${computerName}_EventLogs\${computerName}_RemoteDesktopServices.evtx"
#endregion hyperlinks

$rdiagmsg = msrdGetLocalizedText "rdiagmsg"
$checkmsg = msrdGetLocalizedText "checkmsg"

if (msrdTestRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' -Value 'ReverseConnectionListener') {
    $script:msrdListenervalue = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' -name "ReverseConnectionListener"
} else {
    $script:msrdListenervalue = ""
}

if (Test-Path $msrdAgentpath) {
    $avdcheck = $true
} else {
    $avdcheck = $false
    $avdcheckmsg = "AVD Agent <span style='color: brown'>not found</span>. This machine does not seem to be part of an AVD host pool. Skipping additional AVD host specific checks."
}

#region Main Diag functions

$LogLevel = @{
    'Normal' = 0
    'Info' = 1
    'Warning' = 2
    'Error' = 3
    'ErrorLogFileOnly' = 4
    'WarnLogFileOnly' = 5
    'DiagFileOnly' = 7
}

Function msrdLogDiag {
    param([LogLevel] $Level = [LogLevel]::Normal, [string] $Type, [string] $DiagTag, [string] $Message, [string] $Message2, [string] $Message3, [string] $Title, [int] $col, [string] $circle )

    $global:msrdPerc = "{0:P}" -f ($global:msrdProgress/100)

    switch($circle) {
        'green' { $tdcircle = "circle_green" }
        'red' { $tdcircle = "circle_red" }
        'blue' { $tdcircle = "circle_blue" }
        'no' { $tdcircle = "circle_no" }
        default { $tdcircle = "circle_white" }
    }

    Switch($Level) {
        ([LogLevel]::Normal) {
            $LogConsole = $True; $MessageColor = 'Yellow'
            [decimal]$global:msrdProgress = $global:msrdProgress + $global:msrdProgstep

            if (!(($global:msrdGUIform -and $global:msrdGUIform.Visible)) -and $global:msrdDiagnosing) {
                Write-Progress -Activity "Running diagnostics. Please wait..." -Status "$global:msrdPerc complete:" -PercentComplete $global:msrdProgress
            } elseif (($global:msrdGUIform -and $global:msrdGUIform.Visible) -and $global:msrdDiagnosing) {
                $global:msrdProgbar.PerformStep()
                $global:msrdStatusBar.Text = "$rdiagmsg"
            }

            $DiagMessage2Screen = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " $checkmsg " + $Message
            if ($DiagTag -eq "DeploymentCheck") {
                $DiagMessage = "<details open><summary style='user-select: none;'><span style='position:relative;'><a name='$DiagTag' style='position:absolute; top:-120px;'></a><b>$Message</b><span class='b2top'><a href='#'>^top</a></span></summary></span><div class='detailsP'><table class='tduo'><tbody>"
            } else {
                $DiagMessage = "</tbody></table></div></details><details open><summary style='user-select: none;'><span style='position:relative;'><a name='$DiagTag' style='position:absolute; top:-120px;'></a><b>$Message</b><span class='b2top'><a href='#'>^top</a></span></summary></span><div class='detailsP'><table class='tduo'><tbody>"
            }
        } # Normal

        ([LogLevel]::Info) {
            $LogConsole = $True; $MessageColor = 'White'
            [decimal]$global:msrdProgress = $global:msrdProgress + $global:msrdProgstep

            if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                $global:msrdProgbar.PerformStep()
                $global:msrdStatusBar.Text = "$rdiagmsg"
            }

            $DiagMessage2Screen = (Get-Date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $Message
        } # Info

        ([LogLevel]::Warning) { $LogConsole = $True; $MessageColor = 'Magenta' } # Warning
        ([LogLevel]::Error) { $LogConsole = $True; $MessageColor = 'Red' } # Error

        ([LogLevel]::DiagFileOnly) {
            $LogConsole = $False
            $DiagMessage2Screen = (Get-Date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $Message
            if ($circle -eq "red") {
                if ($Message) { $Message = "<span style='background-color: #FFFFDD'>$Message</span>" }
                if ($Message2) { $Message2 = "<span style='background-color: #FFFFDD'>$Message2</span>" }
                if ($Message3) { $Message3 = "<span style='background-color: #FFFFDD'>$Message3</span>" }
            }

            if ($Type -eq "Text") {
                    $DiagMessage = "<tr><td width='10px'><div class='$tdcircle'></div></td><td class='cText' colspan='$col'>$Message</td></tr>"
            } elseif ($Type -eq "Table1-2") {
                    $DiagMessage = "<tr><td width='10px'><div class='$tdcircle'></div></td><td class='cTable1-2'>$Message</td><td colspan='2'>$Message2</td></tr>"
            } elseif ($Type -eq "Table2-1") {
                if ($Title) {
                        $DiagMessage = "<tr><td width='10px'><div class='$tdcircle'></div></td><td class='cTable2-1' colspan='2'>$Message <span title='$Title' style='cursor: pointer'>&#9432;</span></td><td class='cReg2'>$Message2</td></tr>"
                } else {
                        $DiagMessage = "<tr><td width='10px'><div class='$tdcircle'></div></td><td class='cTable2-1' colspan='2'>$Message</td><td>$Message2</td></tr>"
                }
            } elseif ($Type -eq "Table1-3") {
                if ($Title) {
                        $DiagMessage = "<tr><td width='10px'><div class='$tdcircle'></div></td><td class='cTable1-3'>$Message</td><td class='cTable1-3b'>$Message2 <span title='$Title' style='cursor: pointer'>&#9432;</span></td><td>$Message3</td></tr>"
                } else {
                        $DiagMessage = "<tr><td width='10px'><div class='$tdcircle'></div></td><td class='cTable1-3'>$Message</td><td class='cTable1-3b'>$Message2</td><td>$Message3</td></tr>"
                }
            } elseif ($Type -eq "HR") {
                if ($col -eq 5) {
                    $DiagMessage = "<tr style='height:5px; padding-left: 0px; padding-right: 0px; padding-bottom: 0px;'><td></td><td><hr></td><td><hr></td><td><hr></td><td><hr></td><td><hr></td></tr>"
                } else {
                    $DiagMessage = "<tr style='height:5px; padding-left: 0px; padding-right: 0px; padding-bottom: 0px;'><td></td><td><hr></td><td><hr></td><td><hr></td></tr>"
                }
            } elseif ($Type -eq "Spacer") {
                $DiagMessage = "<tr style='height:5px;'></tr>"
            } elseif ($Type -eq "DL") {
                $DiagMessage = "<tr style='height:5px; padding-left: 0px; padding-right: 0px; padding-bottom: 0px;'><td></td><td><hr style='border-style: dashed; border-color: gray;'></td><td><hr style='border-style: dashed; border-color: gray;'></td><td><hr style='border-style: dashed; border-color: gray;'></td></tr>"
            }
        } # Info only
    }

    If (($Color) -and $Color.Length -ne 0) { $MessageColor = $Color }

    if ($LogConsole) {
        if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            $msrdPsBox.SelectionStart = $msrdPsBox.TextLength
            $msrdPsBox.SelectionLength = 0
            $msrdPsBox.SelectionColor = $MessageColor
            $msrdPsBox.AppendText("$DiagMessage2Screen`r`n")
            $msrdPsBox.ScrollToCaret()
            $msrdPsBox.Refresh()
        } else {
            Write-Host $DiagMessage2Screen -ForegroundColor $MessageColor
        }
    }

    if (($Level -eq 'Normal') -or ($Level -eq 'Info') -or ($Level -eq 'Warning')) { $DiagMessage2Screen | Out-File -Append $global:msrdOutputLogFile }

    if ($Level -ne 'Info') { Add-Content $msrdDiagFile $DiagMessage }
}

Function msrdmsrdConvertToHex([int64]$number) {
	return ("0x{0:x8}" -f $number)
}

Function msrdCheckRegKeyValue {
    Param([string]$RegPath, [string]$RegKey, [string]$RegValue, [string]$OptNote, [string]$skipValue, [string]$addWarning, [switch]$warnMissing)

    $global:msrdRegok = $null

    if (msrdTestRegistryValue -path $RegPath -value $RegKey) {
        (Get-ItemProperty -path $RegPath).PSChildName | foreach-object -process {
            $key = Get-ItemPropertyValue -Path $RegPath -name $RegKey
            $keytype = $key.GetType().Name

            if ($keytype -like "*int*") {
                $hexkey = msrdmsrdConvertToHex $key
                $key2 = "$key ($hexkey)"
            } else {
                $key2 = $key
            }

            if ($RegValue) {
                if ($key -eq $RegValue) {
                    $global:msrdRegok = 1
                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$RegPath<span style='color: blue'>$RegKey</span>" -Message2 "$key2" -Title "$OptNote" -circle "green"
                }
                else {
                    $global:msrdRegok = 2
                    $global:msrdSetWarning = $true
                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$RegPath<span style='color: blue'>$RegKey</span>" -Message2 "$key2 (Expected: $RegValue)" -Title "$OptNote" -circle "red" #warning
                }
            } else {
                if ($skipValue) {
                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$RegPath<span style='color: blue'>$RegKey</span>" -Message2 "found" -Title "$OptNote" -circle "blue"
                } else {
                    if ($addWarning) {
                        $global:msrdSetWarning = $true
                        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$RegPath<span style='color: blue'>$RegKey</span>" -Message2 "$key2" -Title "$OptNote" -circle "red" #warning
                    } else {
                        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$RegPath<span style='color: blue'>$RegKey</span>" -Message2 "$key2" -Title "$OptNote" -circle "blue"
                    }
                }
            }
        }
    } else {
        $global:msrdRegok = 0
        if ($warnMissing) {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$RegPath<span style='color: blue'>$RegKey</span>" -Message2 "not found" -Title "$OptNote" -circle "red"
        } else {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$RegPath<span style='color: blue'>$RegKey</span>" -Message2 "not found" -Title "$OptNote" -circle "white"
        }
    }
}

function msrdTestTCP {
    param([string]$Address,[int]$Port,[int]$Timeout = 20000)

    try {
        $Socket = New-Object System.Net.Sockets.TcpClient
        $Result = $Socket.BeginConnect($Address, $Port, $null, $null)
        $WaitHandle = $Result.AsyncWaitHandle
        if (!$WaitHandle.WaitOne($Timeout)) {
            throw [System.TimeoutException]::new('Connection Timeout')
        }
        $Socket.EndConnect($Result) | Out-Null
        $Connected = $Socket.Connected
    } catch {
        $FailedCommand = $MyInvocation.Line.TrimStart()
        $ErrorMessage = $_.Exception.Message.TrimStart()
        msrdLogException ("$(msrdGetLocalizedText 'errormsg') $FailedCommand") -ErrObj $_ $fLogFileOnly
        if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            msrdAdd-OutputBoxLine ("Error in $FailedCommand $ErrorMessage") "Magenta"
        } else {
            msrdLogMessage Warning ("Error in $FailedCommand $ErrorMessage")
        }

        $global:msrdSetWarning = $true
    } finally {
        if ($Socket) { $Socket.Dispose() }
        if ($WaitHandle) { $WaitHandle.Dispose() }
    }

    $Connected
}

Function msrdCheckServicePort {
    param ([String]$service, [String[]]$tcpports, [String[]]$udpports, [int]$skipWarning, [int]$stopWarning)

    #check service status and port access
    $serv = Get-CimInstance Win32_Service -Filter "name = '$service'" | Select-Object Name, ProcessId, State, StartMode, StartName, DisplayName, Description

    if ($serv) {
        if (($serv.StartMode -eq "Disabled") -or (($serv.StartMode -eq "Stopped") -and ($stopWarning -eq 1))) {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "Service:" -Message2 "<b>$service</b> - $($serv.DisplayName)" -Message3 "$($serv.State) ($($serv.StartMode)) ($($serv.StartName))" -Title "$($serv.Description)" -circle "red"
        } elseif ($serv.State -eq "Running") {
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "Service:" -Message2 "<b>$service</b> - $($serv.DisplayName)" -Message3 "$($serv.State) ($($serv.StartMode)) ($($serv.StartName))" -Title "$($serv.Description)" -circle "green"
        } else {
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "Service:" -Message2 "<b>$service</b> - $($serv.DisplayName)" -Message3 "$($serv.State) ($($serv.StartMode)) ($($serv.StartName))" -Title "$($serv.Description)" -circle "blue"
        }

        #dependencies
        $dependsOn = (Get-Service -Name "$service").RequiredServices
        if ($dependsOn) {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$service depends on the following system components:"
            foreach ($dep in $dependsOn) {
                $depConfig = Get-CimInstance Win32_Service -Filter "name = '$($dep.Name)'" | Select-Object State, StartMode, StartName, DisplayName, Description
                if ($depConfig) {
                    if ($depConfig.State -eq "Running") {
                        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($dep.Name) - $($depConfig.DisplayName)" -Message3 "$($depConfig.State) ($($depConfig.StartMode)) ($($depConfig.StartName))" -circle "green" -Title "$($depConfig.Description)"
                    } else {
                        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($dep.Name) - $($depConfig.DisplayName)" -Message3 "$($depConfig.State) ($($depConfig.StartMode)) ($($depConfig.StartName))" -circle "blue" -Title "$($depConfig.Description)"
                    }
                } else {
                    $depConfig = Get-Service "$($dep.Name)" | Select-Object Status, StartType, DisplayName
                    if ($depConfig.Status -eq "Running") {
                        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($dep.Name) - $($depConfig.DisplayName)" -Message3 "$($depConfig.Status) ($($depConfig.StartType))" -circle "green"
                    } else {
                        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($dep.Name) - $($depConfig.DisplayName)" -Message3 "$($depConfig.Status) ($($depConfig.StartType))" -circle "blue"
                    }
                }
            }
        }

        $othersDepend = (Get-Service -Name "$service").DependentServices
        if ($othersDepend) {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "System components depending on $service" + ":"
            foreach ($other in $othersDepend) {
                $otherConfig = Get-CimInstance Win32_Service -Filter "name = '$($other.Name)'" | Select-Object State, StartMode, StartName, DisplayName, Description
                if ($otherConfig) {
                    if ($otherConfig.State -eq "Running") {
                        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($other.Name) - $($otherConfig.DisplayName)" -Message3 "$($otherConfig.State) ($($otherConfig.StartMode)) ($($otherConfig.StartName))" -circle "green" -Title "$($otherConfig.Description)"
                    } else {
                        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($other.Name) - $($otherConfig.DisplayName)" -Message3 "$($otherConfig.State) ($($otherConfig.StartMode)) ($($otherConfig.StartName))" -circle "blue" -Title "$($otherConfig.Description)"
                    }
                } else {
                    $otherConfig = Get-Service "$($other.Name)" | Select-Object Status, StartType, DisplayName
                    if ($otherConfig.Status -eq "Running") {
                        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($other.Name) - $($otherConfig.DisplayName)" -Message3 "$($otherConfig.Status) ($($otherConfig.StartType))" -circle "green"
                    } else {
                        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($other.Name) - $($otherConfig.DisplayName)" -Message3 "$($otherConfig.Status) ($($otherConfig.StartType))" -circle "blue"
                    }
                }
            }
        }

        #recovery settings
        $commandline = "sc.exe qfailure '$service'"
        $out = Invoke-Expression -Command $commandline
        if ($out) {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$service recovery settings:"
            foreach ($fsout in $out) {
                if (($fsout -like "*RESET*") -or ($fsout -like "*REBOOT*") -or ($fsout -like "*COMMAND*") -or ($fsout -like "*FAILURE*") -or ($fsout -like "*RUN*") -or ($fsout -like "*RESTART*")) {
                    $fsrec1 = $fsout.Split(":")[0]
                    $fsrec2 = $fsout.Split(":")[1]
                    if ($fsrec2) {
                        if ($fsrec2 -ne " ") { $reccircle = "blue" } else { $reccircle = "white" }
                        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$fsrec1" -Message3 "$fsrec2" -circle "$reccircle"
                    } else {
                        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message3 "$fsrec1" -circle "blue"
                    }
                }
            }
        } else {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Could not retrieve $service service failure settings" -circle "red"
        }

        #ports
        If (!($global:msrdOSVer -like "*Server*2008*")) {
            if ($tcpports) {
                foreach ($port in $tcpports) {
                    $exptcplistener = Get-NetTCPConnection -OwningProcess $serv.ProcessId -LocalPort $port -ErrorAction Continue 2>>$global:msrdErrorLogFile

                    if ($exptcplistener) {
                        foreach ($tcpexp in $exptcplistener) {
                            $tcpexpaddr = $tcpexp.LocalAddress
                            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$service is listening on port" -Message2 "$port (TCP) (LocalAddress: $tcpexpaddr)" -circle "green"
                        }
                    } else {
                        $tcphijackpid = (Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue).OwningProcess
                        if ($tcphijackpid) {
                            foreach ($tcppid in $tcphijackpid) {
                                $global:msrdSetWarning = $true
                                $tcpaddress = $tcppid.LocalAddress
                                $tcphijackproc = (Get-WmiObject Win32_service | Where-Object ProcessId -eq "$tcppid").Name
                                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$service is not listening on TCP port $port (LocalAddress: $tcpaddress). The TCP port $port is being used by:" -Message2 "$tcphijackproc ($tcppid)" -circle "red"
                            }
                        } else {
                            $global:msrdSetWarning = $true
                            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "No process is listening on TCP port $port." -circle "red"
                        }
                    }
                }
            }

            if ($udpports) {
                foreach ($port in $udpports) {
                    $expudplistener = Get-NetUDPEndpoint -OwningProcess $serv.ProcessId -LocalPort $port -ErrorAction Continue 2>>$global:msrdErrorLogFile

                    if ($expudplistener) {
                        foreach ($udpexp in $expudplistener) {
                            $udpexpaddr = $udpexp.LocalAddress
                            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$service is listening on port" -Message2 "$port (UDP) (LocalAddress: $udpexpaddr)" -circle "green"
                        }
                    } else {
                        $udphijackpid = (Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue).OwningProcess
                        if ($udphijackpid) {
                            foreach ($udppid in $udphijackpid) {
                                $global:msrdSetWarning = $true
                                $udpaddress = $udppid.LocalAddress
                                $udphijackproc = (Get-WmiObject Win32_service | Where-Object ProcessId -eq "$udphijackpid").Name
                                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$service is not listening on UDP port $port (LocalAddress: $tcpaddress). The UDP port $port is being used by:" -Message2 "$udphijackproc ($udppid)" -circle "red"
                            }
                        } else {
                            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "No process is listening on UDP port $port." -circle "blue"
                        }
                    }
                }
            }
        }

    } else {
        if ($skipWarning -eq 1) {
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "Service:" -Message2 "$service" -Message3 "not found"
        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "Service:" -Message2 "$service" -Message3 "not found" -circle "red"
        }
    }
}

#endregion Main Diag functions


#region System diag functions

Function msrdDiagDeployment {

    #deployment diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Core"
    $menucatmsg = "System"
    msrdLogDiag Normal -DiagTag "DeploymentCheck" -Message $menuitemmsg

    $sysinfofileExists = Test-Path -Path ($global:msrdLogDir + $sysinfofile)
    $instappsfileExists = Test-Path -Path ($global:msrdLogDir + $instappsfile)
    $gpresfileExists = Test-Path -Path ($global:msrdLogDir + $gpresfile)
    $existingFiles = @()
    if ($sysinfofileExists) { $existingFiles += "<a href='$sysinfofile' target='_blank'>SystemInfo</a>" }
    if ($instappsfileExists) { $existingFiles += "<a href='$instappsfile' target='_blank'>InstalledApps</a>" }
    if ($gpresfileExists) { $existingFiles += "<a href='$gpresfile' target='_blank'>Gpresult</a>" }

    if ($existingFiles.Count -eq 0) {
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "FQDN:" -Message2 "$global:msrdFQDN"
    } else {
        $filesString = $existingFiles -join " / "
        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "FQDN:" -Message2 "$global:msrdFQDN" -Message3 "(See: $filesString)"
    }

    if (!(get-ciminstance -Class Win32_ComputerSystem).PartOfDomain) {
        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message2 "This machine is not joined to a domain." -circle "red" #warning
    }

    [string]$script:WinVerBuild = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentBuild).CurrentBuild
    [string]$script:WinVerRevision = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' UBR).UBR
    [string]$script:WinVer7 = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentVersion).CurrentVersion

    #Azure VM query
    Try {
        $WSProxy = New-object System.Net.WebProxy
        $WSWebSession = new-object Microsoft.PowerShell.Commands.WebRequestSession
        $WSWebSession.Proxy = $WSProxy
        $WSWebSession.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        $AzureVMquery = Invoke-RestMethod -Headers @{"Metadata"="true"} -URI 'http://169.254.169.254/metadata/instance?api-version=2021-12-13' -Method Get -WebSession $WSWebSession -TimeoutSec 30

        $vmloc = $AzureVMquery.Compute.location
        $script:vmsize = $AzureVMquery.Compute.vmSize
        if ($AzureVMquery.Compute.sku -eq "") { $vmsku = "N/A" } else { $vmsku = $AzureVMquery.Compute.sku }
        if ($AzureVMquery.Compute.licenseType -eq "") { $global:msrdVmlictype = "N/A" } else { $global:msrdVmlictype = $AzureVMquery.Compute.licenseType }
    
    } Catch {
        $failedCommand = $_.InvocationInfo.Line.TrimStart()
        $errorMessage = $_.Exception.Message.TrimStart()
        msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
        if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
        } else {
            msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
        }
        $vmsku = "N/A"
        $vmloc = "N/A"
        $script:vmsize = "N/A"
        $global:msrdVmlictype = "N/A"
    }

    if (!($global:msrdOSVer -like "*Windows 7*")) {
        [string]$script:WinVerMajor = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentMajorVersionNumber).CurrentMajorVersionNumber
        [string]$script:WinVerMinor = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentMinorVersionNumber).CurrentMinorVersionNumber

        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "OS:" -Message2 "$global:msrdOSVer (Build: $WinVerMajor.$WinVerMinor.$global:WinVerBuild.$WinVerRevision)" -Message3 "SKU: $vmsku"

        $unsupportedMsg = "This OS version is no longer supported. See: {0}. Please upgrade the machine to a more current, in-service, and supported Windows release."
        $ref = switch -Wildcard ($global:msrdOSVer) {
            "*Pro*" { $w10proRef }
            "*Home*" { $w10proRef }
            "*Enterprise*" { $w10entRef }
            "*Education*" { $w10entRef }
            "*Windows 8.1*" { $w81Ref }
        }
        if ((($WinVerMajor -like "*10*") -and (@("18363", "18362", "17134", "19041", "19042", "19043", "16299", "15063") -contains $global:WinVerBuild)) -or ($global:msrdOSVer -like "*Windows 8.1*")) {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message2 ($unsupportedMsg -f $ref) -circle "red"
        }
    } else {
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "OS:" -Message2 "$global:msrdOSVer (Build: $WinVer7.$global:WinVerBuild.$WinVerRevision)" -Message3 "SKU: $vmsku"
        $global:msrdSetWarning = $true
        $w7message = "The Windows 7 Extended Security Update (ESU) Program ended on January 10, 2023. This OS version is no longer supported. Please upgrade the machine to a more current, in-service, and supported Windows release."
        if ($avdcheck) {
            $w7message += " See the list of supported OS: $avdOSRef"
        }
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message2 $w7message -circle "red"
    }

    if (($global:msrdOSVer -like "*Pro*") -or ($global:msrdOSVer -like "*Enterprise N*") -or ($global:msrdOSVer -like "*LTSB*") -or ($global:msrdOSVer -like "*LTSC*") -or ($global:msrdOSVer -like "*Enterprise KN*") -or ($global:msrdOSVer -like "*Windows 8*")) {
        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message2 "If this machine is intended to be an AVD host, then this OS is not supported. See the list of supported operating systems for AVD hosts: $avdOSRef" -circle "red"
    }

    #image type
    if ($avdcheck) {
        if (msrdTestRegistryValue -path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -value "AzureVmImageType") {
            $azvmtype = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -name "AzureVmImageType"
            if ($azvmtype -eq "Marketplace") {
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Image Type:" -Message2 "$azvmtype" -circle "green"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Image Type:" -Message2 "$azvmtype" -circle "blue"
            }
        } else {
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Image Type:" -Message2 "N/A"
        }
    }

    #SystemProductName
    if (msrdTestRegistryValue -path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -value "SystemProductName") {
        $sysprodname = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -name "SystemProductName"
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Model:" -Message2 "$sysprodname"
    } else {
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Model:" -Message2 "N/A"
    }

    #check number of vCPUs
    $vCPUs = (Get-CimInstance -Namespace "root\cimv2" -Query "select NumberOfLogicalProcessors from Win32_ComputerSystem" -ErrorAction SilentlyContinue).NumberOfLogicalProcessors
    $vMemInit = (Get-CimInstance -Namespace "root\cimv2" -Query "select TotalPhysicalMemory from Win32_ComputerSystem" -ErrorAction SilentlyContinue).TotalPhysicalMemory
    $vMem = ("{0:N0}" -f ($vMemInit/1gb)) + " GB "

    if (($global:msrdOSVer -like "*Virtual Desktops*") -or ($global:msrdOSVer -like "*Server*")) {
        if (($vCPUs -lt 4) -or ($vCPUs -gt 24)) {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Size:" -Message2 "$script:vmsize ($vCPUs vCPUs / $vMem RAM). Recommended is to have between 4 and 24 vCPUs for multi-session VMs. See $vmsizeRef" -circle "red"
        } else {
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Size:" -Message2 "$script:vmsize ($vCPUs vCPUs / $vMem RAM)"
        }
    } else {
        if ($vCPUs -lt 4) {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Size:" -Message2 "$script:vmsize ($vCPUs vCPUs / $vMem RAM). Recommended is to have at least 4 vCPUs for single-session VMs. See $vmsizeRef" -circle "red"
        } else {
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Size:" -Message2 "$script:vmsize ($vCPUs vCPUs / $vMem RAM)"
        }
    }

    msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Location:" -Message2 "$vmloc"

    #get timezone
    $tz = (Get-TimeZone).DisplayName
    msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Timezone:" -Message2 "$tz"

    #culture
    $cul = Get-Culture | Select-Object Name, DisplayName, KeyboardLayoutId
    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "Culture:" -Message2 "$($cul.DisplayName)" -Message3 "$($cul.Name) ($($cul.KeyboardLayoutId))"

    #Azure resource id
    if (msrdTestRegistryValue -path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -value "AzureResourceId") {
        $arid = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -name "AzureResourceId"
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Azure Resource Id:" -Message2 "$arid"
    }

    #Azure VM id
    if (msrdTestRegistryValue -path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -value "AzureVmId") {
        $avmid = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -name "AzureVmId"
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Azure VM Id:" -Message2 "$avmid"
    }

    #AVD host GUID
    if (msrdTestRegistryValue -path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -value "GUID") {
        $hguid = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -name "GUID"
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "AVD Host GUID:" -Message2 "$hguid"
    }

    #check TPM
    msrdLogDiag DiagFileOnly -Type "Spacer"
    $tpmstatus = Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, TpmOwned
    if ($tpmstatus.TpmPresent) { $TpmPresent = $tpmstatus.TpmPresent } else { $TpmPresent = "N/A" }
    if ($tpmstatus.TpmReady) { $TpmReady = $tpmstatus.TpmReady } else { $TpmReady = "N/A" }
    if ($tpmstatus.TpmEnabled) { $TpmEnabled = $tpmstatus.TpmEnabled } else { $TpmEnabled = "N/A" }
    if ($tpmstatus.TpmActivated) { $TpmActivated = $tpmstatus.TpmActivated } else { $TpmActivated = "N/A" }
    if ($tpmstatus.TpmOwned) { $TpmOwned = $tpmstatus.TpmOwned } else { $TpmOwned = "N/A" }
    msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "TPM Status:" -Message2 "Present: $TpmPresent | Ready: $TpmReady | Enabled: $TpmEnabled | Activated: $TpmActivated | Owned: $TpmOwned"

    #check secure boot
    try {
        $secboot = Confirm-SecureBootUEFI
        if ($secboot) {
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Secure Boot:" -Message2 "Enabled" -circle "green"
        } else {
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Secure Boot:" -Message2 "Not enabled"
        }
    } catch {
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Secure Boot:" -Message2 "Not supported" -circle "blue"
    }

    #check last boot up time
    $lboott = (Get-CimInstance -ClassName win32_operatingsystem).lastbootuptime
    $lboottdif = [datetime]::Now - $lboott
    $sincereboot = "$($lboottdif.Days)d $($lboottdif.Hours)h $($lboottdif.Minutes)m ago"

    if ($lboottdif.TotalHours -gt 24) {
        $global:msrdSetWarning = $true
        if (Test-Path ($global:msrdLogDir + $powerfile)) {
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "Last boot up time:" -Message2 "$lboott ($sincereboot). Rebooting once every day could help clean out stuck sessions and avoid potential profile load issues." -circle "red" -Message3 "(See: <a href='$powerfile' target='_blank'>PowerReport</a>)"
        } else {
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Last boot up time:" -Message2 "$lboott ($sincereboot). Rebooting once every day could help clean out stuck sessions and avoid potential profile load issues." -circle "red"
        }
    } else {
        if (Test-Path ($global:msrdLogDir + $powerfile)) {
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "Last boot up time:" -Message2 "$lboott ($sincereboot)" -Message3 "(See: <a href='$powerfile' target='_blank'>PowerReport</a>)"
        } else {
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Last boot up time:" -Message2 "$lboott ($sincereboot)"
        }
    }

    #check .Net Framework
    $dotnet = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release
    if ($dotnet -ge 533320) { $dotnetver = "4.8.1 or later" }
    elseif (($dotnet -ge 528040) -and ($dotnet -lt 533320)) { $dotnetver = "4.8" }
    elseif (($dotnet -ge 461808) -and ($dotnet -lt 528040)) { $dotnetver = "4.7.2" }
    elseif (($dotnet -ge 461308) -and ($dotnet -lt 461808)) { $dotnetver = "4.7.1" }
    elseif (($dotnet -ge 460798) -and ($dotnet -lt 461308)) { $dotnetver = "4.7" }
    elseif (($dotnet -ge 394802) -and ($dotnet -lt 460798)) { $dotnetver = "4.6.2" }
    elseif (($dotnet -ge 394254) -and ($dotnet -lt 394802)) { $dotnetver = "4.6.1" }
    elseif (($dotnet -ge 393295) -and ($dotnet -lt 394254)) { $dotnetver = "4.6" }
    elseif (($dotnet -ge 379893) -and ($dotnet -lt 393295)) { $dotnetver = "4.5.2" }
    elseif (($dotnet -ge 378675) -and ($dotnet -lt 379893)) { $dotnetver = "4.5.1" }
    elseif (($dotnet -ge 378389) -and ($dotnet -lt 378675)) { $dotnetver = "4.5" }
    else { $dotnetver = "No .NET Framework 4.5 or later" }

    msrdLogDiag DiagFileOnly -Type "Spacer"
    if ($global:msrdAVD) {
        if ($dotnet -lt 461808) {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message ".Net Framework:" -Message2 "$dotnetver - AVD requires .NET Framework 4.7.2 or later" -circle "red"
        } else {
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message ".Net Framework:" -Message2 "$dotnetver" -circle "green"
        }
    } else {
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message ".Net Framework:" -Message2 "$dotnetver"
    }

    #check Windows features
    If (!($global:msrdSource) -and !($global:msrdOSVer -like "*Server*2008*")) {
        msrdLogDiag DiagFileOnly -Type "HR"
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Windows Features:"
        $winfeat = "Microsoft-Hyper-V", "IsolatedUserMode", "Containers-DisposableClientVM"
        foreach ($wf in $winfeat) {
            $winOptFeat = Get-WindowsOptionalFeature -Online -FeatureName "$wf" -ErrorAction SilentlyContinue
            if ($winOptFeat) {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($winOptFeat.DisplayName)" -Message3 "$($winOptFeat.State)" -circle "blue"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$wf" -Message3 "not found"
            }
        }
    }

    #checking for useful reg keys
    msrdLogDiag DiagFileOnly -Type "HR"
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\Setup\' 'OOBEInProgress' '0'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\Setup\' 'SystemSetupInProgress' '0'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\Setup\' 'SetupPhase' '0'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\' 'RebootInProgress'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\' 'RebootPending'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\' 'DisallowRun' '' 'User Policy: Do not run specified Windows applications'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\' 'RestrictRun' '' 'User Policy: Run only specified Windows applications'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' 'DisableRegistryTools' '' 'User Policy: Prevent access to registry editing tools'
    msrdCheckRegKeyValue 'HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' 'DisableRegistryTools'
    msrdCheckRegKeyValue 'HKU:\S-1-5-18\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' 'DisableRegistryTools'

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagCPU {

    #CPU diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "CPU Utilization"
    $menucatmsg = "System"
    msrdLogDiag Normal -DiagTag "CPUCheck" -Message $menuitemmsg

    $Top10CPU = Get-Process | Sort-Object CPU -desc | Select-Object -first 10
    msrdLogDiag DiagFileOnly -Type "Text" -Message "Top 10 processes using the most CPU time on all processors:" -col 7

    msrdLogDiag DiagFileOnly -Type "Spacer"
    Add-Content $msrdDiagFile "<tr align='center'><th width='10px'><div class='circle_no'></div></th><th>Process</th><th>Id</th><th>CPU(s)</th><th>Handles</th><th>NPM(K)</th><th>PM(K)</th><th>WS(K)</th></tr>"
    foreach ($entry in $Top10CPU) {
        if ($entry.Description) {
            $desc = $entry.Description
        } else {
            $desc = "N/A"
        }
        Add-Content $msrdDiagFile "<tr align='center'><td width='10px'><div class='circle_white'></div></td><td align='left' width='25%'>$($entry.ProcessName) ($desc)</td><td align='right'>$($entry.Id)</td><td align='right'>$($entry.CPU)</td><td align='right'>$($entry.Handles)</td><td align='right'>$($entry.NPM)</td><td align='right'>$($entry.PM)</td><td align='right'>$($entry.WS)</td></tr>"
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagDrives {

    #disk diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Drives"
    $menucatmsg = "System"
    msrdLogDiag Normal -DiagTag "DiskCheck" -Message $menuitemmsg

    msrdLogDiag DiagFileOnly -Type "Text" -col 5 -Message "Local/Network drives:"
    msrdLogDiag DiagFileOnly -Type "Spacer"

    $drives = @()
    $drvtype = "Unknown", "No Root Directory", "Removable Disk", "Local Disk", "Network Drive", "Compact Disc", "RAM Disk"
    $Vol = Get-CimInstance -NameSpace "root\cimv2" -Query "select * from Win32_LogicalDisk" -ErrorAction Continue 2>>$global:msrdErrorLogFile

    Add-Content $msrdDiagFile "<tr align='center'><th width='10px'><div class='circle_no'></div></th><th>Drive</th><th>Type</th><th>Total space (MB)</th><th>Free space (MB)</th><th>Percent free space</th></tr>"
    foreach ($disk in $vol) {
        if ($disk.Size -ne $null) { $PercentFreeSpace = $disk.FreeSpace*100/$disk.Size }
        else { $PercentFreeSpace = 0 }

        $driveid = $disk.DeviceID
        $drivetype = $drvtype[$disk.DriveType]
        $ts = [math]::Round($disk.Size/1MB,2)
        $fs = [math]::Round($disk.FreeSpace/1MB,2)
        $pfs = [math]::Round($PercentFreeSpace,2)

        #warn if free space is below 5% of disk size
        if (($PercentFreeSpace -lt 5) -and (($drivetype -eq "Local Disk") -or ($drivetype -eq "Network Drive"))) {
            $global:msrdSetWarning = $true
            if ($driveid -eq "C:") {
                if (Test-Path ($global:msrdLogDir + $permDriveCfile)) {
                    Add-Content $msrdDiagFile "<tr align='center'><td width='10px'><div class='circle_red'></div></td><td>$driveid (See: <a href='$permDriveCfile' target='_blank'>Permissions</a>)</td><td>$drivetype</td><td>$ts</td><td>$fs</td><td><span style='color: red'>$pfs%</span></td></tr>"
                } else {
                    Add-Content $msrdDiagFile "<tr align='center'><td width='10px'><div class='circle_red'></div></td><td>$driveid</td><td>$drivetype</td><td>$ts</td><td>$fs</td><td><span style='color: red'>$pfs%</span></td></tr>"
                }
            } else {
                Add-Content $msrdDiagFile "<tr align='center'><td width='10px'><div class='circle_red'></div></td><td>$driveid</td><td>$drivetype</td><td>$ts</td><td>$fs</td><td><span style='color: red'>$pfs%</span></td></tr>"
            }
            msrdLogDiag DiagFileOnly -Type "Text" -Message "You are running low on free space (less than 5%) on drive: $driveid" -col 5 -circle "red"
        } else {
            if ($driveid -eq "C:") {
                if (Test-Path ($global:msrdLogDir + $permDriveCfile)) {
                    Add-Content $msrdDiagFile "<tr align='center'><td width='10px'><div class='circle_white'></div></td><td>$driveid (See: <a href='$permDriveCfile' target='_blank'>Permissions</a>)</td><td>$drivetype</td><td>$ts</td><td>$fs</td><td>$pfs%</td></tr>"
                } else {
                    Add-Content $msrdDiagFile "<tr align='center'><td width='10px'><div class='circle_white'></div></td><td>$driveid</td><td>$drivetype</td><td>$ts</td><td>$fs</td><td>$pfs%</td></tr>"
                }
            } else {
                Add-Content $msrdDiagFile "<tr align='center'><td width='10px'><div class='circle_white'></div></td><td>$driveid</td><td>$drivetype</td><td>$ts</td><td>$fs</td><td>$pfs%</td></tr>"
            }
        }
    }

    #rdp redirected drives
    msrdLogDiag DiagFileOnly -Type "HR" -col 5
    $rdpdrives = Invoke-Expression "net use" -ErrorAction SilentlyContinue
    if ($rdpdrives -and ($rdpdrives -like "*tsclient*")) {
        msrdLogDiag DiagFileOnly -Type "Text" -col 5 -Message "Remote Desktop redirected drives:"
        foreach ($rdpd in $rdpdrives) {
            if ($rdpd -like "*tsclient*") {
                $rdpdregex1 = [regex]::new("\\\\[^ ]+")
                $drive = $rdpdregex1.Match($rdpd).Value

                $rdpdregex2 = [regex]::new("\\\\[^ ]+ *(.+)$")
                $network = $rdpdregex2.Match($rdpd).Groups[1].Value
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$drive" -Message3 "$network" -circle "blue"
            }
        }
    } else {
        msrdLogDiag DiagFileOnly -Type "Text" -col 5 -Message "Remote Desktop redirected drives not found"
    }

    #client side redirection
    msrdLogDiag DiagFileOnly -Type "HR" -col 5
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Terminal Server Client\' 'DisableDriveRedirection' '0'

    #host side redirection
    if (!($global:msrdSource)) {
        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDisableCdm' '0' 'Computer Policy: Do not allow drive redirection'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'fDisableCdm' '0'
        if ($global:msrdAVD) {
            if ($script:msrdListenervalue) {
                msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue + '\') 'fDisableCdm' '0'
            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Active AVD listener configuration not found" -circle "red"
            }
        }
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }

}

Function msrdGetDispScale {

    #get display scale %
$code2 = @'
  using System;
  using System.Runtime.InteropServices;
  using System.Drawing;

  public class DPI {
    [DllImport("gdi32.dll")]
    static extern int GetDeviceCaps(IntPtr hdc, int nIndex);

    public enum DeviceCap { VERTRES = 10, DESKTOPVERTRES = 117 }

    public static float scaling() {
      Graphics g = Graphics.FromHwnd(IntPtr.Zero);
      IntPtr desktop = g.GetHdc();
      int LogicalScreenHeight = GetDeviceCaps(desktop, (int)DeviceCap.VERTRES);
      int PhysicalScreenHeight = GetDeviceCaps(desktop, (int)DeviceCap.DESKTOPVERTRES);
      return (float)PhysicalScreenHeight / (float)LogicalScreenHeight;
    }
  }
'@
    
if ($PSVersionTable.PSVersion.Major -eq 5) {
    Add-Type -TypeDefinition $code2 -ReferencedAssemblies 'System.Drawing.dll'
} else {
    Add-Type -TypeDefinition $code2 -ReferencedAssemblies 'System.Drawing.dll','System.Drawing.Common'
}

    $DScale = [Math]::round([DPI]::scaling(), 2) * 100
    if ($DScale) {
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Display scaling rate:" -Message2 "$DScale%"
    } else {
        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Text" -Message "Display scaling rate could not be determined." -col 3 -circle "red"
    }
}

Function msrdDiagGraphics {

    #graphics diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Graphics"
    $menucatmsg = "System"
    msrdLogDiag Normal -DiagTag "GPUCheck" -Message $menuitemmsg

    if (!($global:msrdOSVer -like "*Windows Server 2012 R2*")) {

        if (($script:vmsize -like "*NV*") -or ($script:vmsize -like "*NC*")) {
            if (Test-Path ($global:msrdLogDir + $dxdiagfile)) {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "A GPU optimized VM size has been detected." -Message2 "(See: <a href='$dxdiagfile' target='_blank'>DxDiag</a>)" -circle "green"
            } else {
                msrdLogDiag DiagFileOnly -Type "Text" -Message "A GPU optimized VM size has been detected." -col 3 -circle "green"
            }
            msrdLogDiag DiagFileOnly -Type "Text" -Message "Make sure all the prerequisites are met to take full advantage of the GPU capabilities. See $gpuRef" -col 3 -circle "blue"
        } else {
            if (Test-Path ($global:msrdLogDir + $dxdiagfile)) {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "This machine does not seem to be a GPU enabled Azure VM." -Message2 "(See: <a href='$dxdiagfile' target='_blank'>DxDiag</a>)" -circle "blue"
            } else {
                msrdLogDiag DiagFileOnly -Type "Text" -Message "This machine does not seem to be a GPU enabled Azure VM." -col 3 -circle "blue"
            }
        }
    } else {
        msrdLogDiag DiagFileOnly -Type "Text" -Message "GPU-accelerated rendering and encoding are not supported for this OS version." -col 3 -circle "red"
    }

    msrdLogDiag DiagFileOnly -Type "Spacer"

    $gfx = Get-CimInstance -Class Win32_VideoController | Select-Object Name, DriverVersion
    if ($gfx) {
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Video Controllers:"
        foreach ($item in $gfx) {
            $gfxname = $item.Name
            $gfxdriver = $item.DriverVersion
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$gfxname" -Message3 "$gfxdriver"
        }
    }

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Monitors:"

    $Monitors = Get-WmiObject WmiMonitorID -Namespace root\wmi -ErrorAction Continue 2>>$global:msrdErrorLogFile
    if ($Monitors) {
        ForEach ($Monitor in $Monitors) {
            $Manufacturer = ($Monitor.ManufacturerName | where {$_ -ne 0} | ForEach {[char]$_}) -join ""
            $Name = ($Monitor.UserFriendlyName | where {$_ -ne 0} | ForEach {[char]$_}) -join ""
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$Manufacturer" -Message3 "$Name"
        }
    } else {
        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Could not retrieve monitor information. See <a href='$msrdErrorfileurl' target='_blank'>MSRD-Collect-Error</a> for more information." -circle "red"
    }

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdGetDispScale  #Get display scale

    msrdLogDiag DiagFileOnly -Type "HR"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Terminal Server Client\' 'EnableAdvancedRemoteFXRemoteAppSupport'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Terminal Server Client\' 'EnableAdvancedRemoteFXRemoteAppSupport'

    if (!($global:msrdSource)) {
        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'bEnumerateHWBeforeSW' '1' 'Computer Policy: Use hardware graphics adapters for all Remote Desktop Services sessions'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'AVCHardwareEncodePreferred' '1' 'Computer Policy: Configure H.264/AVC hardware encoding for Remote Desktop Connections'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'AVC444ModePreferred' '1' 'Computer Policy: Prioritize H.264/AVC 444 graphics mode for Remote Desktop Connections'

        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fEnableWddmDriver' '' 'Computer Policy: Use WDDM graphics display driver for Remote Desktop Connections'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fEnableRemoteFXAdvancedRemoteApp' '' 'Computer Policy: Use advanced RemoteFX graphics for RemoteApp'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'MaxMonitors' '' 'Computer Policy: Limit number of monitors'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'MaxXResolution' '' 'Computer Policy: Limit maximum display resolution'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'MaxYResolution' '' 'Computer Policy: Limit maximum display resolution'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' 'DWMFRAMEINTERVAL'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' 'fEnableRemoteFXAdvancedRemoteApp'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' 'IgnoreClientDesktopScaleFactor'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'MaxMonitors'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'MaxXResolution'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'MaxYResolution'
    }

    if ($global:msrdAVD) {
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs\' 'MaxMonitors'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs\' 'MaxXResolution'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs\' 'MaxYResolution'
    }

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\' 'PreferExternalManifest'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Display\' 'DisableGdiDPIScaling' '' 'Computer Policy: Turn off GdiDPIScaling for applications'
    msrdCheckRegKeyValue 'HKCU:\Control Panel\Desktop\' 'DesktopDPIOverride'
    msrdCheckRegKeyValue 'HKCU:\Control Panel\Desktop\' 'LogPixels'
    msrdCheckRegKeyValue 'HKCU:\Control Panel\Desktop\' 'UserPreferencesMask'
    msrdCheckRegKeyValue 'HKCU:\Control Panel\Desktop\' 'Win8DpiScaling'

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagActivation {

    #activation diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "OS Activation / Licensing"
    $menucatmsg = "System"
    msrdLogDiag Normal -DiagTag "KMSCheck" -Message $menuitemmsg

    try {
        $activ = Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID = '55c92734-d682-4d71-983e-d6ec3f16059f'" -Property Name, Description, licensestatus -OperationTimeoutSec 30 -ErrorAction Stop | Where-Object licensestatus -eq 1
        if ($activ) {
            if (Test-Path ($global:msrdLogDir + $slmgrfile)) {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "Product Name:" -Message2 "$($activ.Name)" -Message3 "(See: <a href='$slmgrfile' target='_blank'>slmgr-dlv</a>)"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Product Name:" -Message2 "$($activ.Name)"
            }
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Product Description:" -Message2 "$($activ.Description)"
        } else {
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Product Name:" -Message2 "N/A"
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Product Description:" -Message2 "N/A"
        }
    } catch {
        $failedCommand = $_.InvocationInfo.Line.TrimStart()
        $errorMessage = $_.Exception.Message.TrimStart()
        msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
        if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
        } else {
            msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
        }

        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "An error occurred while trying to retrieve SoftwareLicensingProduct information. See <a href='$msrdErrorfileurl' target='_blank'>MSRD-Collect-Error</a> for more information." -circle "red"
    }

    $kms = Get-CimInstance SoftwareLicensingService | Select-Object KeyManagementServiceMachine, KeyManagementServicePort, DiscoveredKeyManagementServiceMachineIpAddress -ErrorAction Continue 2>>$global:msrdErrorLogFile
    if ($kms) {
        if ($kms.KeyManagementServiceMachine) { $kmsurl = $kms.KeyManagementServiceMachine; $kmsurlcircle = "blue" } else { $kmsurl = "N/A"; $kmsurlcircle = "white" }
        if ($kms.DiscoveredKeyManagementServiceMachineIpAddress) { $kmsip = $kms.DiscoveredKeyManagementServiceMachineIpAddress; $kmsipcircle = "blue" } else { $kmsip = "N/A"; $kmsipcircle = "white" }
        if ($kms.KeyManagementServicePort) { $kmsport = $kms.KeyManagementServicePort; $kmsportcircle = "blue" } else { $kmsport = "N/A"; $kmsportcircle = "white" }
    } else {
        $kmsurl = "N/A"; $kmsurlcircle = "white"
        $kmsip = "N/A"; $kmsipcircle = "white"
        $kmsport = "N/A"; $kmsportcircle = "white"
    }
    msrdLogDiag DiagFileOnly -Type "HR"
    if (Test-Path ($global:msrdLogDir + $kmsfile)) {
        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "KMS machine:" -Message2 "$kmsurl" -Message3 "(See: <a href='$kmsfile' target='_blank'>KMS-Servers</a>)" -circle $kmsurlcircle
    } else {
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "KMS machine:" -Message2 "$kmsurl" -circle $kmsurlcircle
    }
    msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "KMS IP address:" -Message2 "$kmsip" -circle $kmsipcircle
    msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "KMS port:" -Message2 "$kmsport" -circle $kmsportcircle

    Try {
        if ($kmsurl -and ($kmsurl -ne "N/A")) {
            $kmsconTest = msrdTestTCP "$kmsurl" "$kmsport"
            if ($kmsconTest -eq "True") {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "TCP connection result for KMS server '$kmsurl' ($kmsip) on port '$kmsport'" -Message2 "Reachable" -circle "green"
            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "TCP connection result for KMS server '$kmsurl' ($kmsip) on port '$kmsport'" -Message2 "Not reachable" -circle "red"
            }
        }
    } Catch {
        $failedCommand = $_.InvocationInfo.Line.TrimStart()
        $errorMessage = $_.Exception.Message.TrimStart()
        msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
        if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
        } else {
            msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
        }

        $global:msrdSetWarning = $true
    }

    if ($global:msrdAVD) {
        msrdLogDiag DiagFileOnly -Type "HR"
        if ($global:msrdVmlictype -eq "Windows_Client") {
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "License Type:" -Message2 "$global:msrdVmlictype (Expected for AVD VMs)" -circle "green"
        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "License Type:" -Message2 "$global:msrdVmlictype. This is not the expected license type for an AVD host. See: $avdLicRef" -circle "red"
        }
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }


}

Function msrdDiagSSLTLS {

    #SSL/TLS diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "SSL / TLS"
    $menucatmsg = "System"
    msrdLogDiag Normal -DiagTag "SSLCheck" -Message $menuitemmsg

    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\' 'Functions' '' '' '' 'Warning'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\' 'EccCurves' '' '' '' 'Warning'

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\' 'SchUseStrongCrypto' '1'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\' 'SystemDefaultTlsVersions' '1'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\' 'SchUseStrongCrypto' '1'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\' 'SystemDefaultTlsVersions' '1'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727\' 'SchUseStrongCrypto' '1'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727\' 'SystemDefaultTlsVersions' '1'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319\' 'SchUseStrongCrypto' '1'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319\' 'SystemDefaultTlsVersions' '1'

    msrdLogDiag DiagFileOnly -Type "HR"
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client\' 'Enabled' '0'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client\' 'DisabledByDefault' '1'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server\' 'Enabled' '0'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server\' 'DisabledByDefault' '1'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client\' 'Enabled' '0'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client\' 'DisabledByDefault' '1'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\' 'Enabled' '0'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server\' 'DisabledByDefault' '1'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client\' 'Enabled' '0'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client\' 'DisabledByDefault' '1'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\' 'Enabled' '0'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server\' 'DisabledByDefault' '1'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client\' 'Enabled' '1'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client\' 'DisabledByDefault' '0'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server\' 'Enabled' '1'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server\' 'DisabledByDefault' '0'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client\' 'Enabled'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client\' 'DisabledByDefault'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server\' 'Enabled'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server\' 'DisabledByDefault'

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagUAC {

    #User Access Control diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "User Account Control"
    $menucatmsg = "System"
    msrdLogDiag Normal -DiagTag "UACCheck" -Message $menuitemmsg

    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' 'EnableLUA' '1' 'Computer Policy: User Account Control: Run all administrators in Admin Approval Mode'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' 'PromptOnSecureDesktop' '1' 'Computer Policy: User Account Control: Switch to the secure desktop when prompting for elevation'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' 'ConsentPromptBehaviorAdmin' '5' 'Computer Policy: User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' 'ConsentPromptBehaviorUser' '3' 'Computer Policy: User Account Control: Behavior of the elevation prompt for standard users'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' 'EnableUIADesktopToggle' '0' 'Computer Policy: User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' 'EnableInstallerDetection' '' 'Computer Policy: User Account Control: Detect application installations and prompt for elevation'

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagInstaller {

    #Windows Installer diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Windows Installer"
    $menucatmsg = "System"
    msrdLogDiag Normal -DiagTag "InstallerCheck" -Message $menuitemmsg

    msrdCheckServicePort -service msiserver

    msrdLogDiag DiagFileOnly -Type "HR"
    msrdCheckRegKeyValue 'HKLM:\Software\Policies\Microsoft\Windows\Installer\' 'disablemsi' '' 'Computer Policy: Turn off Windows Installer'

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagSearch {

    #Windows Search diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Windows Search"
    $menucatmsg = "System"
    msrdLogDiag Normal -DiagTag "SearchCheck" -Message $menuitemmsg

    msrdCheckServicePort -service wsearch

    msrdLogDiag DiagFileOnly -Type "HR"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows Search\' 'EnablePerUserCatalog'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Apps\' 'RoamSearch'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Profiles\' 'RoamSearch'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\FSLogix\ODFC\' 'RoamSearch'

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagWU {

    #Windows Update diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Windows Update"
    $menucatmsg = "System"
    msrdLogDiag Normal -DiagTag "WUCheck" -Message $menuitemmsg

    if (Test-Path ($global:msrdLogDir + $updhistfile)) {
        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "OS Build:" -Message2 ($WinVerMajor + "." + $WinVerMinor + "." + $global:WinVerBuild + "." + $WinVerRevision) -Message3 "(See: <a href='$updhistfile' target='_blank'>UpdateHistory</a>)"
    } else {
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "OS Build:" -Message2 ($WinVerMajor + "." + $WinVerMinor + "." + $global:WinVerBuild + "." + $WinVerRevision)
    }

    if ($WinVerMajor -like "*10*") {
        If ($global:WinVerBuild -like "*14393*") { $PatchURL = "<a href='https://support.microsoft.com/en-us/help/4000825' target='_blank'>Windows 10 and Windows Server 2016 update history</a>"
        } elseif ($global:WinVerBuild -like "*17763*") { $PatchURL = "<a href='https://support.microsoft.com/en-us/help/4464619' target='_blank'>Windows 10 and Windows Server 2019 update history</a>"
        } elseif ($global:WinVerBuild -like "*19044*") { $PatchURL = "<a href='https://support.microsoft.com/en-us/help/5008339' target='_blank'>Windows 10, version 21H2 update history</a>"
        } elseif ($global:WinVerBuild -like "*20348*") { $PatchURL = "<a href='https://support.microsoft.com/en-us/help/5005454' target='_blank'>Windows Server 2022 update history</a>"
        } elseif ($global:WinVerBuild -like "*22000*") { $PatchURL = "<a href='https://support.microsoft.com/en-us/help/5006099' target='_blank'>Windows 11, version 21H2 update history</a>"
        } elseif ($global:WinVerBuild -like "*22621*") { $PatchURL = "<a href='https://support.microsoft.com/en-us/help/5018680' target='_blank'>Windows 11, version 22H2 update history</a>" }

        $buildlist = "14393", "17763", "18363", "19044", "20348", "22000", "22621"
        $buildlist | ForEach-Object -Process {
            if ($global:WinVerBuild -like $_) {
                $PatchHistory = "Check the public " + $PatchURL + " if the latest OS update is installed. Use the last digits of the OS build number for an easy comparison."
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$PatchHistory" -circle "blue"
            }
        }
    }

    if (($WinVerMajor -like "*10*") -and (@("10240", "10586", "15063", "16299", "17134", "18362", "18363", "19041", "19042", "19043") -contains $global:WinVerBuild)) {
        $global:msrdSetWarning = $true
        $unsupportedMsg = "This OS version is no longer supported. Upgrade the OS to a supported version. See: {0}"
        $ref = switch -Wildcard ($global:msrdOSVer) {
            "*Pro*" { $w10proRef }
            "*Home*" { $w10proRef }
            "*Enterprise*" { $w10entRef }
            "*Education*" { $w10entRef }
        }
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message2 ($unsupportedMsg -f $ref) -circle "red"
    }

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\' 'WUServer' '' 'Computer Policy: Specify intranet Microsoft update service location'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\' 'WUStatusServer' '' 'Computer Policy: Specify intranet Microsoft update service location'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\' 'NoAutoUpdate' '' 'Computer Policy: Configure Automatic Updates'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\' 'AUOptions' '' 'Computer Policy: Configure Automatic Updates'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\' 'UseWUServer'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\' 'RebootRequired'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\' 'PostRebootReporting'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\' 'IsOOBEInProgress'

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagWinRMPS {

    #WinRM/PowerShell diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "WinRM / PowerShell"
    $menucatmsg = "System"
    msrdLogDiag Normal -DiagTag "WinRMPSCheck" -Message $menuitemmsg

    msrdCheckServicePort -service WinRM

    msrdLogDiag DiagFileOnly -Type "Spacer"
    if ($servstatus -eq "Running") {
        $ipfilter = Get-Item WSMan:\localhost\Service\IPv4Filter
        if ($ipfilter.Value) {
            if ($ipfilter.Value -eq "*") {
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "IPv4Filter:" -Message2 "*" -circle "green"
            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "IPv4Filter:" -Message2 "$($ipfilter.Value)" -circle "red"
            }
        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "IPv4Filter:" -Message2 "Empty value, WinRM will not listen on IPv4." -circle "red"
        }

        $ipfilter = Get-Item WSMan:\localhost\Service\IPv6Filter
        if ($ipfilter.Value) {
            if ($ipfilter.Value -eq "*") {
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "IPv6Filter:" -Message2 "*" -circle "green"
            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "IPv6Filter:" -Message2 "$($ipfilter.Value)" -circle "red"
            }
        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "IPv6Filter:" -Message2 "Empty value, WinRM will not listen on IPv6." -circle "red"
        }
    }

    $fwrules5 = (Get-NetFirewallPortFilter -Protocol TCP | Where-Object { $_.localport -eq '5985' } | Get-NetFirewallRule)
    if ($fwrules5.count -eq 0) {
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Windows Firewall rule(s) for TCP port 5985" -Message2 "not found"
    } else {
        if (Test-Path ($global:msrdLogDir + $fwrfile)) {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Windows Firewall rule(s) for TCP port 5985" -Message2 "found (See: <a href='$fwrfile' target='_blank'>FirewallRules</a>)" -circle "blue"
        } else {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Windows Firewall rule(s) for TCP port 5985" -Message2 "found" -circle "blue"
        }
    }


    $fwrules6 = (Get-NetFirewallPortFilter -Protocol TCP | Where-Object { $_.localport -eq '5986' } | Get-NetFirewallRule)
    if ($fwrules6.count -eq 0) {
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Windows Firewall rule(s) for TCP port 5986" -Message2 "not found"
    } else {
        if (Test-Path $fwrfile) {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Windows Firewall rule(s) for TCP port 5986" -Message2 "found (See: <a href='$fwrfile' target='_blank'>FirewallRules</a>)" -circle "blue"
        } else {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Windows Firewall rule(s) for TCP port 5986" -Message2 "found" -circle "blue"
        }
    }

    msrdLogDiag DiagFileOnly -Type "Spacer"
    if ((get-ciminstance -Class Win32_ComputerSystem).PartOfDomain) {
        $DSsearch = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
        $DSsearch.filter = "(samaccountname=WinRMRemoteWMIUsers__)"
        try {
            $results = $DSsearch.Findall()
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

        if ($results.count -gt 0) {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Found $($results.Properties.distinguishedname)" -circle "green"
            if ($results.Properties.grouptype -eq  -2147483644) {
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "WinRMRemoteWMIUsers__ is a Domain local group." -circle "green"
            } elseif ($results.Properties.grouptype -eq -2147483646) {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "WinRMRemoteWMIUsers__ is a Global group." -circle "red"
            } elseif ($results.Properties.grouptype -eq -2147483640) {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "WinRMRemoteWMIUsers__ is a Universal group." -circle "red"
            }
            if (get-ciminstance -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "The group WinRMRemoteWMIUsers__ is also present as machine local group." -circle "green"
            }
        } else {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "The WinRMRemoteWMIUsers__ was not found in the domain."
            if (get-ciminstance -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "The group WinRMRemoteWMIUsers__ is present as machine local group." -circle "green"
            } else {
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "WinRMRemoteWMIUsers__ group was not found as machine local group."
            }
        }
    } else {
        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "This machine is not joined to a domain." -circle "red"
        if (get-ciminstance -query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "The group WinRMRemoteWMIUsers__ is present as machine local group." -circle "green"
        } else {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "WinRMRemoteWMIUsers__ group was not found as machine local group."
        }
    }

    #security protocol
    msrdLogDiag DiagFileOnly -Type "HR"
    $secprot = [System.Net.ServicePointManager]::SecurityProtocol
    if ($secprot) {
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "[Net.ServicePointManager]::SecurityProtocol" -Message2 "$secprot" -circle "blue"
    } else {
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "[Net.ServicePointManager]::SecurityProtocol" -Message2 "not found" -circle "blue"
    }

    #powershell
    msrdLogDiag DiagFileOnly -Type "Spacer"
    $PSlock = $ExecutionContext.SessionState.LanguageMode
    if ($PSlock -eq "FullLanguage") {
        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "PowerShell:" -Message2 "Running Mode" -Message3 "$PSlock" -circle "green"
    } else {
        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "PowerShell:" -Message2 "Running Mode" -Message3 "$PSlock" -circle "red"
    }

    $pssexec = Get-ExecutionPolicy -List
    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Execution policies:"
    foreach ($entrypss in $pssexec) {
        $mode = $entrypss.ExecutionPolicy
        if ($mode -like "*Undefined*") {
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($entrypss.Scope)" -Message3 "$mode"
        } else {
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($entrypss.Scope)" -Message3 "$mode" -circle "blue"
        }
    }

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Modules:"
    $instmodulelist = "Az.Accounts", "Az.Resources", "Az.DesktopVirtualization", "Microsoft.RDInfra.RDPowerShell"
    $instmodulelist | ForEach-Object -Process {
        $instmod = Get-InstalledModule -Name $_ -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($instmod) {
            $instmodver = [string]$instmod.Version
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$_" -Message3 "$instmodver" -circle "blue"
        } else {
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$_" -Message3 "not found"
        }
    }

    $modulelist = "PowerShellGet", "PSReadLine"
    $modulelist | ForEach-Object -Process {
        $mod = Get-Module -Name $_ -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($mod) {
            $modver = [string]$mod.Version
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$_" -Message3 "$modver" -circle "blue"
        } else {
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$_" -Message3 "not found"
        }
    }

    msrdLogDiag DiagFileOnly -Type "HR"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS\' 'AllowRemoteShellAccess' '' 'Computer Policy: Allow Remote Shell Access'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\' 'MaxRequestBytes'

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

#endregion System diag functions


#region AVD/RDS diag functions

Function msrdDiagRedirection {

    #RD Redirection diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Device and Resource Redirection"
    $menucatmsg = $script:msrdMenuCat
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "RedirCheck"
    
    if (!($global:msrdSource)) {
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDisableAudioCapture' '0' 'Computer Policy: Allow audio recording redirection'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDisableCam' '0' 'Computer Policy: Allow audio and video playback redirection'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDisableCameraRedir' '0' 'Computer Policy: Do not allow video capture redirection'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDisableCcm' '0' 'Computer Policy: Do not allow COM port redirection'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDisableCdm' '0' 'Computer Policy: Do not allow drive redirection'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDisableClip' '0' 'Computer Policy: Do not allow clipboard redirection'
        msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDisableClip' '0' 'User Policy: Do not allow clipboard redirection'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDisableCpm' '0' 'Computer Policy: Do not allow client printer redirection'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDisableLPT' '0' 'Computer Policy: Do not allow LPT port redirection'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDisablePNPRedir' '0' 'Computer Policy: Do not allow supported Plug and Play device redirection'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDisableWebAuthn' '0' 'Computer Policy: Do not allow WebAuthn redirection'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fEnableSmartCard' '1' 'Computer Policy: Do not allow smart card device redirection'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fEnableTimeZoneRedirection' '' 'Computer Policy: Allow time zone redirection'
        msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fEnableTimeZoneRedirection' '' 'User Policy: Allow time zone redirection'
    }

    #client side redirections
    msrdLogDiag DiagFileOnly -Type "Spacer"

    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Terminal Server Client\' 'DisableClipboardRedirection' '0'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Terminal Server Client\' 'DisableClipboardRedirection' '0'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Terminal Server Client\' 'DisableDriveRedirection' '0'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Terminal Server Client\' 'DisablePrinterRedirection' '0'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Terminal Server Client\' 'DisablePrinterRedirection' '0'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Terminal Server Client\' 'DisableWebAuthnRedirection'

    if (!($global:msrdSource)) {
        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\' 'fEnableSmartCard'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'fDisableAudioCapture' '0'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'fDisableCam' '0'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'fDisableCcm' '0'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'fDisableCdm' '0'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'fDisableClip' '0'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'fDisableCpm' '0'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'fDisableLPT' '0'
    }

    if ($global:msrdAVD) {
        msrdLogDiag DiagFileOnly -Type "Spacer"
        if ($avdcheck) {
            msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue + '\') 'fDisableAudioCapture' '0'
            msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue + '\') 'fDisableCam' '0'
            msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue + '\') 'fDisableCcm' '0'
            msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue + '\') 'fDisableCdm' '0'
            msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue + '\') 'fDisableClip' '0'
            msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue + '\') 'fDisableCpm' '0'
            msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue + '\') 'fDisableLPT' '0'
        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$avdcheckmsg" -circle "red"
        }
    }

    if (!($global:msrdSource)) {
        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Keyboard Layout\' 'IgnoreRemoteKeyboardLayout'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System\' 'IoEnableSessionZeroAccessCheck' '1'
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdTestAVExclusion {
    Param([string]$ExclPath, [array]$ExclValue)

    #Antivirus Exclusion diagnostics
    if (Test-Path $ExclPath) {
        if ((Get-Item $ExclPath).Property) {
            $msgpath = Compare-Object -ReferenceObject(@((Get-Item $ExclPath).Property)) -DifferenceObject(@($ExclValue))

            if ($msgpath) {
                $valueNotConf = ($msgpath | Where-Object {$_.SideIndicator -eq '=>'}).InputObject
                $valueNotRec = ($msgpath | Where-Object {$_.SideIndicator -eq '<='}).InputObject

                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "The following recommended values are not configured:" -circle "red"
                foreach ($entryNC in $valueNotConf) {
                    msrdLogDiag DiagFileOnly -Type "Table1-2" -Message2 "$entryNC" -circle "red"
                }

                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "The following values are configured but are not part of the public list of recommended settings:" -circle "blue"
                foreach ($entryNR in $valueNotRec) {
                    msrdLogDiag DiagFileOnly -Type "Table1-2" -Message2 "$entryNR" -circle "blue"
                }

            } else {
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message2 "No differences found" -circle "green"
            }

        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message2 "No '$ExclPath' exclusions have been found" -circle "red"
        }

    } else {
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message2 "'$ExclPath' <span style='color: brown'>not found</span>." -circle "blue"
    }
}

Function msrdDiagFSLogix {

    #FSLogix diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "FSLogix"
    $menucatmsg = $script:msrdMenuCat
    msrdLogDiag Normal -DiagTag "ProfileCheck" -Message $menuitemmsg

    $cmd = "c:\program files\fslogix\apps\frx.exe"

    if (Test-path -path 'C:\Program Files\FSLogix\apps') {

        msrdCheckServicePort -service frxsvc -stopWarning 1
        msrdLogDiag DiagFileOnly -Type "HR"
        msrdCheckServicePort -service frxccds

        msrdLogDiag DiagFileOnly -Type "HR"

        if (Test-Path -path $cmd) {
            Invoke-Expression "& '$cmd' + 'version'" | ForEach-Object -Process {
                $fsv1 = $_.Split(":")[0]
                $fsv2 = $_.Split(":")[-1]
                if ($fsv2 -like "*unknown*") {
                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message ($fsv1 + ":") -Message2 "unknown" -circle "red"
                } else {
                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message ($fsv1 + ":") -Message2 "$fsv2" -circle "blue"
                }

                if ($fsv1 -like "Service*") {
                    if ($fsv2 -like "*unknown*") {
                        $script:frxverstrip = "unknown"
                    } else {
                        [int64]$script:frxverstrip = $fsv2.Replace(".","")
                    }
                }
            }
            if (($script:frxverstrip -lt $latestFSLogixVer) -and (!($script:frxverstrip -eq "unknown"))) {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "You are not using the latest available FSLogix release. Please consider updating. See: $fslogixRef" -circle "red"
            } elseif ($script:frxverstrip -eq "unknown") {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Could not retrieve all FSLogix version information" -circle "red"
            }

        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -Message "FSLogix seems to be installed, but $cmd could not be found" -col 3 -circle "red"
        }

        #profile container
        msrdLogDiag DiagFileOnly -Type "HR"
        if (Test-Path -Path ($global:msrdLogDir + $fslogixfolder) -PathType Container) {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "<b>Profile container</b>" -Message2 "(See: <a href='$fslogixfolder' target='_blank'>FSLogix logs</a>)"
        } else {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "<b>Profile container</b>"
        }

        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Profiles\' 'Enabled' '1'

        if (!(msrdTestRegistryValue -path "HKLM:\SOFTWARE\FSLogix\Profiles\" -value "Enabled")) {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "FSLogix <span style='color: blue'>Profile</span> Container 'Enabled' reg key <span style='color: brown'>not found</span>. Profile Container is not enabled." -circle "blue"
        }

        if (msrdTestRegistryValue -path "HKLM:\SOFTWARE\FSLogix\Profiles\" -value "VHDLocations") {
            $pvhd = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\FSLogix\Profiles\" -name "VHDLocations"

            $var1P = $pvhd -split ";"
            $var2P = foreach ($varItemP in $var1P) {
                        if ($varItemP -like "AccountName=*") { $varItemP = "AccountName=xxxxxxxxxxxxxxxx"; $varItemP }
                        elseif ($varItemP -like "AccountKey=*") { $varItemP = "AccountKey=xxxxxxxxxxxxxxxx"; $varItemP }
                        else { $varItemP }
                    }
            $var3P = $var2P -join ";"
            $pvhd = $var3P

            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "HKLM:\SOFTWARE\FSLogix\Profiles\<span style='color: blue'>VHDLocations</span>" -Message2 "$pvhd" -circle "blue"

            $pconPath = $pvhd.split("\")[2]
            if ($pconPath) {
                $pconTest = "msrdTestTCP '$pconPath' '445'"
                $pconout = Invoke-Expression -Command $pconTest
                if ($pconout -eq "True") {
                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "TCP connection result for Profile storage location on port '445'" -Message2 "Reachable" -circle "green"
                }
                if ($pconout.PingSucceeded) {
                    $global:msrdSetWarning = $true
                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "TCP connection result for Profile storage location on port '445'" -Message2 "Not reachable" -circle "red"
                }
            }
        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "HKLM:\SOFTWARE\FSLogix\Profiles\<span style='color: blue'>VHDLocations</span>" -Message2 "not found"
        }

        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Profiles\' 'CCDLocations' '' '' 'skip'

        if ((msrdTestRegistryValue -path "HKLM:\SOFTWARE\FSLogix\Profiles\" -value "VHDLocations") -and (msrdTestRegistryValue -path "HKLM:\SOFTWARE\FSLogix\Profiles\" -value "CCDLocations")) {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Both Profile VHDLocations and Profile Cloud Cache CCDLocations reg keys are present. If you want to use Profile Cloud Cache, remove any setting for Profile 'VHDLocations'. See: $cloudcacheRef" -circle "red"
            msrdLogDiag DiagFileOnly -Type "Spacer"
        }

        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Profiles\' 'ConcurrentUserSessions' '0' 'Computer Policy: Allow concurrent user sessions'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Profiles\' 'DeleteLocalProfileWhenVHDShouldApply' '1' 'Computer Policy: Delete local profile when FSLogix Profile should apply'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Profiles\' 'SizeInMBs' '30000' 'Computer Policy: Size in MBs'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Profiles\' 'VolumeType' 'VHDx' 'Computer Policy: Virtual disk type'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Profiles\' 'FlipFlopProfileDirectoryName' '1' 'Computer Policy: Swap directory name components'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Profiles\' 'InstallAppxPackages'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Profiles\' 'NoProfileContainingFolder' '0' 'Computer Policy: No containing folder'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Profiles\' 'OutlookCachedMode' '' 'Computer Policy: Set Outlook cached mode on successful container attach'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Profiles\' 'RebootOnUserLogoff' '0' 'Computer Policy: Reboot computer when user logs off'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Profiles\' 'RedirectType' '2'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Profiles\' 'RedirXMLSourceFolder' '' 'Computer Policy: Provide RedirXML file to customize redirections'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Profiles\' 'RoamSearch'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Profiles\' 'ShutdownOnUserLogoff' '0' 'Computer Policy: Shutdown computer when user logs off'

        #office container
        msrdLogDiag DiagFileOnly -Type "HR"
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "<b>Office container</b>"

        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\FSLogix\ODFC\' 'Enabled'

        if (!(msrdTestRegistryValue -path "HKLM:\SOFTWARE\Policies\FSLogix\ODFC\" -value "Enabled")) {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "FSLogix <span style='color: blue'>Office</span> Container 'Enabled' reg key <span style='color: brown'>not found</span>. Office Container is not enabled." -circle "blue"
        }

        if (msrdTestRegistryValue -path "HKLM:\SOFTWARE\Policies\FSLogix\ODFC\" -value "VHDLocations") {
            $ovhd = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\FSLogix\ODFC\" -name "VHDLocations"

            $var1O = $ovhd -split ";"
            $var2O = foreach ($varItemO in $var1O) {
                        if ($varItemO -like "AccountName=*") { $varItemO = "AccountName=xxxxxxxxxxxxxxxx"; $varItemO }
                        elseif ($varItemO -like "AccountKey=*") { $varItemO = "AccountKey=xxxxxxxxxxxxxxxx"; $varItemO }
                        else { $varItemO }
                    }
            $var3O = $var2O -join ";"
            $ovhd = $var3O

            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "HKLM:\SOFTWARE\Policies\FSLogix\ODFC\<span style='color: blue'>VHDLocations</span>" -Message2 "$ovhd" -circle "blue"

            $oconPath = $ovhd.split("\")[2]
            if ($oconPath) {
                $oconTest = "msrdTestTCP '$oconPath' '445'"
                $oconout = Invoke-Expression -Command $oconTest
                if ($oconout -eq "True") {
                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "TCP connection result for ODFC storage location on port '445'" -Message2 "Reachable" -circle "green"
                }
                if ($oconout.PingSucceeded) {
                    $global:msrdSetWarning = $true
                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "TCP connection result for ODFC storage location on port '445'" -Message2 "Not reachable" -circle "red"
                }
            }
        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "HKLM:\SOFTWARE\Policies\FSLogix\ODFC\<span style='color: blue'>VHDLocations</span>" -Message2 "not found"
        }

        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\FSLogix\ODFC\' 'CCDLocations' '' '' 'skip'

        if ((msrdTestRegistryValue -path "HKLM:\SOFTWARE\Policies\FSLogix\ODFC\" -value "VHDLocations") -and (msrdTestRegistryValue -path "HKLM:\SOFTWARE\Policies\FSLogix\ODFC\" -value "CCDLocations")) {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Both Office VHDLocations and Office Cloud Cache CCDLocations reg keys are present. If you want to use Office Cloud Cache, remove any setting for Office 'VHDLocations'. See: $cloudcacheRef" -circle "red"
            msrdLogDiag DiagFileOnly -Type "Spacer"
        }

        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\FSLogix\ODFC\' 'IncludeOfficeActivation' '' 'Computer Policy: Include Office activation data in container'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\FSLogix\ODFC\' 'DeleteLocalProfileWhenVHDShouldApply' '1' 'Computer Policy: Delete local profile when FSLogix Profile should apply'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\FSLogix\ODFC\' 'SizeInMBs' '30000' 'Computer Policy: Size in MBs'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\FSLogix\ODFC\' 'VolumeType' 'VHDx' 'Computer Policy: Virtual dksik type'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\FSLogix\ODFC\' 'FlipFlopProfileDirectoryName' '1' 'Computer Policy: Swap directory name components'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\FSLogix\ODFC\' 'NoProfileContainingFolder' '0' 'Computer Policy: No containing folder'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\FSLogix\ODFC\' 'OutlookCachedMode' '' 'Computer Policy: Set Outlook cached mode on successful container attach'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\FSLogix\ODFC\' 'VHDAccessMode' '' 'Computer Policy: VHD access type'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\FSLogix\ODFC\' 'RoamSearch'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\outlook\ost\' 'NoOST' '' 'Computer Policy: Do not allow an OST file to be created'

        #apps & other
        msrdLogDiag DiagFileOnly -Type "HR"
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "<b>Other relevant settings</b>"
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Apps\' 'CleanupInvalidSessions' '1'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Apps\' 'RoamRecycleBin'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Apps\' 'RoamSearch'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Apps\' 'VHDCompactDisk'
        
        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\' 'SpecialRoamingOverrideAllowed'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\' 'CloudKerberosTicketRetrievalEnabled' '' 'Computer Policy: Allow retrieving the Azure AD Kerberos Ticket Granting Ticket during logon'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\' 'SupportedEncryptionTypes' '' 'Computer Policy: Network security: Configure encryption types allowed for Kerberos' '' 'AddWarning'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\AzureADAccount\' 'LoadCredKeyFromProfile'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters\' 'CloudKerberosTicketRetrievalEnabled' '' 'Computer Policy: Allow retrieving the Azure AD Kerberos Ticket Granting Ticket during logon'

        #AV exclusions
        msrdLogDiag DiagFileOnly -Type "HR"
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "<b>Antivirus exclusions</b>"

        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Recommended FSLogix Windows Defender Exclusions. See: $avexRef"
        #checking for actual Profiles VHDLocations value
        $pVHDpath = "HKLM:\SOFTWARE\FSLogix\Profiles\"
        $pVHDkey = "VHDLocations"
        if (msrdTestRegistryValue -path $pVHDpath -value $pVHDkey) {
            $pkey = (Get-ItemPropertyValue -Path $pVHDpath -name $pVHDkey).replace("`n","")
            $pkey1 = $pkey + "\*.VHD"
            $pkey2 = $pkey + "\*.VHDX"
        } else {
            #no path found, defaulting to generic value
            $pkey1 = "\\<storageaccount>.file.core.windows.net\<share>\*.VHD"
            $pkey2 = "\\<storageaccount>.file.core.windows.net\<share>\*.VHDX"
        }

        $ccdVHDkey = "CCDLocations"
        if (msrdTestRegistryValue -path $pVHDpath -value $ccdVHDkey) {
            $ccdkey = $True
        } else {
            $ccdkey = $false
        }

        $ccdRec = "%ProgramData%\FSLogix\Cache\*.VHD","%ProgramData%\FSLogix\Cache\*.VHDX","%ProgramData%\FSLogix\Proxy\*.VHD","%ProgramData%\FSLogix\Proxy\*.VHDX"
        $avRec = "%ProgramFiles%\FSLogix\Apps\frxdrv.sys","%ProgramFiles%\FSLogix\Apps\frxdrvvt.sys","%ProgramFiles%\FSLogix\Apps\frxccd.sys","%TEMP%\*.VHD","%TEMP%\*.VHDX","%Windir%\TEMP\*.VHD","%Windir%\TEMP\*.VHDX"

        if ($ccdkey) {
            $recAVexclusionsPaths = $avRec + $pkey1 + $pkey2 + $ccdRec
        } else {
            $recAVexclusionsPaths = $avRec + $pkey1 + $pkey2
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Cloud Cache is not enabled. The recommended Cloud Cache Exclusions will not be taken into consideration for this check. This may lead to false positives if you have the Cloud Cache Exclusions configured."
        }
        msrdLogDiag DiagFileOnly -Type "Spacer"

        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Windows Defender Paths exclusions (local config):"
        msrdTestAVExclusion "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" $recAVexclusionsPaths
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Windows Defender Paths exclusions (GPO config):"
        msrdTestAVExclusion "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths" $recAVexclusionsPaths

        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Windows Defender Processes exclusions (local config):"
        msrdTestAVExclusion "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes" ("%ProgramFiles%\FSLogix\Apps\frxccd.exe","%ProgramFiles%\FSLogix\Apps\frxccds.exe","%ProgramFiles%\FSLogix\Apps\frxsvc.exe")
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Windows Defender Processes exclusions (GPO config):"
        msrdTestAVExclusion "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes" ("%ProgramFiles%\FSLogix\Apps\frxccd.exe","%ProgramFiles%\FSLogix\Apps\frxccds.exe","%ProgramFiles%\FSLogix\Apps\frxsvc.exe")

        #Java
        msrdLogDiag DiagFileOnly -Type "HR"
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "<b>Java related installations</b>"

        $fsjava = Get-WmiObject -Class Win32_Product -Filter "Name like '%Java%'" -ErrorAction SilentlyContinue | Select-Object Name, Vendor, Version
        if ($fsjava) {
            foreach ($fsj in $fsjava) {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($fsj.Name) ($($fsj.Vendor))" -Message3 "$($fsj.Version)" -circle "blue"
            }
        } else {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Java related installation(s) not found"
        }

    } else {
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "FSLogix <span style='color: brown'>not found</span>. Skipping check (not applicable)."
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagMultimedia {

    #Multimedia diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Multimedia"
    $menucatmsg = $script:msrdMenuCat
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "MultiMedCheck"

    $featuremp = Get-WindowsOptionalFeature -Online -FeatureName "MediaPlayback" -ErrorAction Continue 2>>$global:msrdErrorLogFile
    if ($featuremp) {
        if ($featuremp.State -eq "Enabled") {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Media Playback feature:" -Message2 "$($featuremp.State)" -circle "green"
        } else {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Media Playback feature:" -Message2 "$($featuremp.State)" -circle "blue"
        }
    } else {
        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Media Playback feature information could not be retrieved" -circle "red"
    }

    $featurewmp = Get-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -ErrorAction Continue 2>>$global:msrdErrorLogFile
    if ($featurewmp) {
        if ($featurewmp.State -eq "Enabled") {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Windows Media Player feature:" -Message2 "$($featurewmp.State)" -circle "green"
        } else {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Windows Media Player feature:" -Message2 "$($featurewmp.State)" -circle "blue"
        }
    } else {
        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Windows Media Player feature information could not be retrieved" -circle "red"
    }

    msrdLogDiag DiagFileOnly -Type "HR"
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\' 'Value' 'Allow' 'Microphone access - general'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged\' 'Value' 'Allow' 'Microphone access - desktop apps'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\' 'Value' 'Allow' 'Camera access - general'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged\' 'Value' 'Allow' 'Camera access - desktop apps'

    if (!($global:msrdSource)) {
        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDisableAudioCapture' '0' 'Computer Policy: Allow audio recording redirection'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDisableCam' '0' 'Computer Policy: Allow audio and video playback redirection'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDisableCameraRedir' '0' 'Computer Policy: Do not allow video capture redirection'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'fDisableCam' '0'
        if ($global:msrdAVD) {
            if ($script:msrdListenervalue) {
                msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue + '\') 'fDisableCam' '0'
            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Active AVD listener configuration not found" -circle "red"
            }
        }
    }


    msrdLogDiag DiagFileOnly -Type "HR"
    if ($script:RDClient) {
        foreach ($RDCitem in $script:RDClient) {
            $RDCver = $RDCitem.DisplayVersion
            [int64]$RDCverStrip = $RDCver.Replace(".","")
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Multimedia Redirection compatible Windows Desktop RD client found installed on this machine" -Message2 "$RDCver" -circle "green"
            if (($RDCverStrip -ge $minRDCver) -and ($RDCverStrip -lt $minRDCverMMR)) {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Older Windows Desktop RD client found installed on this machine. Multimedia Redirection requires version 1.2.3916 or later. Please consider updating. See: $msrdcRef" -circle "red"
            }
            if ($RDCverStrip -lt $minRDCver) {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Unsupported Windows Desktop RD Client found installed on this machine. Please update. See: $msrdcRef" -circle "red"
            }
        }
    }

    if ($global:msrdAVD) {
        msrdLogDiag DiagFileOnly -Type "Spacer"

        $instreg = @("hklm:\software\microsoft\windows\currentversion\uninstall\*", "hklm:\software\wow6432node\microsoft\windows\currentversion\uninstall\*")
        $instfound = $false

        foreach ($instkey in $instreg) {
            $vcrinst = Get-ItemProperty $instkey | Where-Object { $_.DisplayName -like "*Microsoft Visual C++*Redistributable*" } -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion
            if ($vcrinst) {
                $instfound = $true
                foreach ($vcr in $vcrinst) {
                    $regex = "(?<!@{DisplayName=}).*?(?=\s*-\s*[^\-]*$)"
                    $vcrdn = [regex]::Match($vcr.DisplayName.ToString(), $regex).Value.Trim()
                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$vcrdn" -Message2 "$($vcr.DisplayVersion)" -circle "blue"
                }
            }
        }
        if (-not $instfound) {
            $novcrmsg = "Microsoft Visual C++ Redistributable installation not found. AVD Multimedia Redirection requirements are not met."
            msrdLogDiag DiagFileOnly -Type "Text" -Col 3 -Message $novcrmsg -Circle "blue"
        }

        msrdLogDiag DiagFileOnly -Type "Spacer"
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader') {

            $path= "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
            if (Test-Path $path) {
                $MMRver = (Get-ChildItem -Path $path -ErrorAction Continue 2>>$global:msrdErrorLogFile | Get-ItemProperty | Select-Object DisplayName, DisplayVersion | Where-Object DisplayName -like "Remote Desktop Multimedia*").DisplayVersion
                if ($MMRver) {
                    [int64]$MMRverStrip = $MMRver.Replace(".","")
                    
                    if ($MMRverStrip -lt $latestMMRver) { $global:msrdSetWarning = $true; $circle = "red" }
                    else { $circle = "green" }
                    
                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop Multimedia Redirection Service installation found" -Message2 "$MMRver" -circle $circle

                    if ($MMRverStrip -lt $latestMMRver) {
                        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Older Remote Desktop Multimedia Redirection Service version found installed on this machine. Please consider updating. See: $mmrRef" -circle "red"
                    }
                } else {
                    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Remote Desktop Multimedia Redirection Service installation <span style='color: brown'>not found</span>."
                }
            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Error retrieving Remote Desktop Multimedia Redirection Service information" -circle "red"
            }

            msrdLogDiag DiagFileOnly -Type "Spacer"
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Google\Chrome\' 'ExtensionSettings'
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\' 'ExtensionSettings'
        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$avdcheckmsg" -circle "red"
        }
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagQA {

    #Quick Assist diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Quick Assist"
    $menucatmsg = $script:msrdMenuCat
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "QACheck"

    $qa = Get-AppxPackage -Name "*QuickAssist*" -ErrorAction SilentlyContinue | Select-Object Name, Version, InstallLocation

    if ($qa) {
        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "Quick Assist installation:" -Message2 "$($qa.Name)" -Message3 "$($qa.version)" -circle "blue"
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Path: $($qa.InstallLocation)"

        msrdLogDiag DiagFileOnly -Type "HR"
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "DNS name query resolution:"
        $qadnsurls = @("remoteassistance.support.services.microsoft.com", "aadcdn.msauth.net", "aria.microsoft.com", "cc.skype.com",
            "edge.skype.com", "events.data.microsoft.com", "flightproxy.skype.com", "live.com", "login.microsoftonline.com", "monitor.azure.com",
            "registrar.skype.com", "remoteassistanceprodacs.communication.azure.com", "support.services.microsoft.com", "trouter.skype.com", "turn.azure.com")

        foreach ($dnsurl in $qadnsurls) {
            try {
                $dnstcp = Resolve-DnsName -Name $dnsurl -QuickTimeout -ErrorAction SilentlyContinue
                if ($dnstcp) {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$dnsurl" -Message3 "Successful" -circle "green"
                } else {
                    $global:msrdSetWarning = $true
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$dnsurl" -Message3 "Failed" -circle "red"
                }
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
        }

        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Endpoint access over port 443:"
        $qatesturls = @("remoteassistance.support.services.microsoft.com", "aadcdn.msauth.net", "live.com", "login.microsoftonline.com", "microsoft.com", "remoteassistanceprodacs.communication.azure.com", "skype.com", "turn.azure.com")

        foreach ($tcpurl in $qatesturls) {
            try {
                $outtcp = msrdTestTCP -address $tcpurl -port 443
                if ($outtcp -eq $true) {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$tcpurl" -Message3 "Reachable" -circle "green"
                } else {
                    $global:msrdSetWarning = $true
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$tcpurl" -Message3 "Not reachable (See <a href='$msrdErrorfileurl' target='_blank'>MSRD-Collect-Error</a>)" -circle "red"
                }
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
        }
    } else {
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Quick Assist installation not found. Skipping Quick Assist URL checks (not applicable)."
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagRDPListener {

    #RDP/RD Listener diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "RDP / Listener"
    $menucatmsg = $script:msrdMenuCat
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "ListenerCheck"

    msrdCheckServicePort -service TermService -tcpports 3389 -udpports 3389 -stopWarning 1
    msrdLogDiag DiagFileOnly -Type "HR"
    msrdCheckServicePort -service SessionEnv -stopWarning 1
    msrdLogDiag DiagFileOnly -Type "HR"
    msrdCheckServicePort -service UmRdpService -stopWarning 1
    msrdLogDiag DiagFileOnly -Type "HR"

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDenyTSConnections' '' 'Computer Policy: Allow users to connect remotely by using Remote Desktop Services'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fPromptForPassword' '' 'Computer Policy: Always prompt for password upon connection'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fSingleSessionPerUser' '' 'Computer Policy: Restrict RDS users to a single RDS session'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'MaxInstanceCount' '' 'Computer Policy: Limit number of connections'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\' 'fDenyTSConnections' '0'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\' 'fSingleSessionPerUser' '1'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\' 'IgnoreRegUserConfigErrors'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\' 'KeepAliveInterval'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\' 'KeepAliveEnable'

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'CitrixBackupRdpTcpLoadableProtocolObject' '' '' '' 'AddWarning'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'fEnableWinStation' '1'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'MaxInstanceCount' '4294967295'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'LoadableProtocol_Object'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'PortNumber' '3389'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'SecurityLayer' '2'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'UserAuthentication' '1'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'WebSocketListenerPort'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'WebSocketTlsListenerPort'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'WebSocketURI'

    if ($global:msrdAVD) {
        msrdLogDiag DiagFileOnly -Type "Spacer"
        #checking if multiple AVD listener reg keys are present
        if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs*') {

            msrdLogDiag DiagFileOnly -Type "Spacer"
            $SxSlisteners = (Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs*').PSChildName
            $SxSlisteners | foreach-object -process {
                if ($_ -ne "rdp-sxs") {
                    msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $_ + '\') 'fEnableWinStation'
                }
            }
        }
        else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "AVD listener (HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs*) reg keys <span style='color: brown'>not found</span>. This machine is either not a AVD VM or the AVD listener is not configured properly." -circle "red"
        }

        #checking for the current AVD listener version and "fReverseConnectMode"
        if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations') {
            if ($script:msrdListenervalue) {
                $listenerregpath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue

                msrdLogDiag DiagFileOnly -Type "Spacer"
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "<b>The AVD listener currently in use is: $script:msrdListenervalue</b>"
                msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings\' 'SessionDirectoryListener' $script:msrdListenervalue
                msrdLogDiag DiagFileOnly -Type "Spacer"

                msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue + '\') 'fReverseConnectMode' '1'
                msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue + '\') 'MaxInstanceCount' '4294967295'
                msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue + '\') 'SecurityLayer' '2'
                msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue + '\') 'UserAuthentication' '1'
            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\ReverseConnectionListener' <span style='color: brown'>not found</span>. This machine is either not a AVD VM or the AVD listener is not configured properly." -circle "red"
            }
        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations' <span style='color: brown'>not found</span>. This machine is not properly configured for either AVD or RDS connections." -circle "red"
        }
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagRDSRoles {

    #RDS Roles diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "RDS Roles"
    $menucatmsg = $script:msrdMenuCat
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "RolesCheck"
    if ($global:msrdOSVer -like "*Windows Server*") {

        $script:foundRDS = (Get-WindowsFeature -Name RDS-* -ErrorAction Continue 2>>$global:msrdErrorLogFile) | Where-Object { $_.InstallState -eq "Installed" }

        Function msrdDotNetTrustCheck {
            param([string] $pspath)

            $tcheck = (Get-WebConfiguration -Filter '/system.web/trust' -PSPath "$pspath" -ErrorAction Continue 2>>$global:msrdErrorLogFile).level
            if ($tcheck) {
                if ($tcheck -eq "Full") {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$pspath" -Message3 $tcheck -circle "green"
                } else {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$pspath" -Message3 $tcheck -circle "red"
                }
            } else {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$pspath" -Message3 "Error retrieving or value not found" -circle "red"
            }
        }

        #gateway
        if ($script:foundRDS.Name -eq "RDS-GATEWAY") {
            if ((Test-Path ($global:msrdLogDir + $getcapfile)) -and (Test-Path ($global:msrdLogDir + $getrapfile))) {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "<b>Remote Desktop Gateway role</b>" -Message2 "Installed (See: <a href='$getcapfile' target='_blank'>CAP</a> / <a href='$getrapfile' target='_blank'>RAP</a>)" -circle "green"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "<b>Remote Desktop Gateway role</b>" -Message2 "Installed" -circle "green"
            }
            if ($global:msrdAVD) {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Having the Remote Desktop Gateway role installed on an AVD host is not supported" -circle "red"
            }

            msrdLogDiag DiagFileOnly -Type "Spacer"
            msrdCheckServicePort -service TSGateway -udpports 3391 -stopWarning 1

            msrdLogDiag DiagFileOnly -Type "DL"
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "IIS .Net Trust Levels:"
            
            Import-Module WebAdministration

            msrdDotNetTrustCheck "MACHINE/WEBROOT"
            msrdDotNetTrustCheck "MACHINE/WEBROOT/APPHOST"
            msrdDotNetTrustCheck "MACHINE/WEBROOT/APPHOST/Default Web Site"
            msrdDotNetTrustCheck "MACHINE/WEBROOT/APPHOST/Default Web Site/Rpc"
            msrdDotNetTrustCheck "MACHINE/WEBROOT/APPHOST/Default Web Site/RpcWithCert"

            Remove-Module WebAdministration

        } else {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop Gateway role" -Message2 "not found"
        }

        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Terminal Server Gateway\' 'SkipMachineNameAttribute'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\TerminalServerGateway\Config\Core\' 'EnforceChannelBinding'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\TerminalServerGateway\Config\Core\' 'IasTimeout'

        #web access
        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdLogDiag DiagFileOnly -Type "HR"
        msrdLogDiag DiagFileOnly -Type "Spacer"
        if ($script:foundRDS.Name -eq "RDS-WEB-ACCESS") {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "<b>Remote Desktop Web Access role</b>" -Message2 "Installed" -circle "green"
            if ($global:msrdAVD) {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Having the Remote Desktop Web Access role installed on an AVD host is not supported" -circle "red"
            }

            msrdLogDiag DiagFileOnly -Type "Spacer"
            msrdCheckServicePort -service W3SVC  -stopWarning 1

            msrdLogDiag DiagFileOnly -Type "DL"
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "IIS .Net Trust Levels:"
            
            Import-Module WebAdministration

            msrdDotNetTrustCheck "MACHINE/WEBROOT"
            msrdDotNetTrustCheck "MACHINE/WEBROOT/APPHOST"
            msrdDotNetTrustCheck "MACHINE/WEBROOT/APPHOST/Default Web Site"
            msrdDotNetTrustCheck "MACHINE/WEBROOT/APPHOST/Default Web Site/RDWeb"
            msrdDotNetTrustCheck "MACHINE/WEBROOT/APPHOST/Default Web Site/RDWeb/Pages"

            Remove-Module WebAdministration

            #RDWeb client components
            msrdLogDiag DiagFileOnly -Type "Spacer"

            try {
                $rdwcver = (Get-RDWebClientPackage -ErrorAction SilentlyContinue).Version
                if ($rdwcver) {
                    foreach ($wcver in $rdwcver) {
                        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop Web Client" -Message2 "$wcver" -circle "blue"
                    }
                } else {
                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop Web Client" -Message2 "not found"
                }
            } catch {
                $failedCommand = $_.InvocationInfo.Line.TrimStart()
                msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop Web Client" -Message2 "not found"
            }

            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Remote Desktop Web Client PowerShell prerequisites:"

            $rdwcProvs = "NuGet"
            $rdwcProvs | ForEach-Object -Process {
                $rdwcProvVer = [String](Get-PackageProvider -Name $_ -ErrorAction SilentlyContinue).Version
                if ($rdwcProvVer) {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$_" -Message3 "$rdwcProvVer" -circle "blue"
                } else {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$_" -Message3 "not found"
                }
            }

            $rdwcMods = "PackageManagement", "PowerShellGet"
            $rdwcMods | ForEach-Object -Process {
                $rdwcmodver = [String](Get-Module -Name $_ -ErrorAction SilentlyContinue).Version
                if ($rdwcmodver) {
                    if (($_ -eq "PowerShellGet") -and ($rdwcmodver -eq "1.0.0.1")) {
                        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$_" -Message3 "$rdwcmodver" -circle "red"
                        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "This $_ version does not support installing the web client management module" -circle "red"
                    } else {
                        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$_" -Message3 "$rdwcmodver" -circle "blue"
                    }
                } else {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$_" -Message3 "not found"
                }
            }

            $rdwcMods = "RDWebClientManagement"
            $rdwcMods | ForEach-Object -Process {
                $rdwcmodver = [String](Get-InstalledModule -Name $_ -ErrorAction SilentlyContinue).Version
                if ($rdwcmodver) {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$_" -Message3 "$rdwcmodver" -circle "blue"
                } else {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$_" -Message3 "not found"
                }
            }

            try {
                $rdwcconfig = Get-RDWebClientDeploymentSetting -ErrorAction SilentlyContinue | Select-Object Name, Value
                if ($rdwcconfig) {
                    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Remote Desktop Web Client Deployment Settings:"
                    foreach ($wcconfig in $rdwcconfig) {
                        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($wcconfig.Name)" -Message3 "$($wcconfig.Value)" -circle "blue"
                    }
                } else {
                        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop Web Client Deployment Settings" -Message2 "not found"
                }
            } catch {
                $failedCommand = $_.InvocationInfo.Line.TrimStart()
                msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop Web Client Deployment Settings" -Message2 "not found"
            }

            try {
                $rdwccert = Get-RDWebClientBrokerCert -ErrorAction SilentlyContinue | Select-Object Subject, Thumbprint, NotAfter
                if ($rdwccert) {
                    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Remote Desktop Web Client Broker Certificate:" 
                    $wcthresholdDate = (Get-Date).AddDays(30)
                    if ($rdwccert.NotAfter) {
                        $wcexpdate = Get-Date ($rdwccert.NotAfter)
                        $wcexpdiff = $wcexpdate - $wcthresholdDate
                        if ($wcexpdiff -lt "30") {
                            $global:msrdSetWarning = $true
                            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "Expires on: $wcexpdate" -Message3 "Subject: $($rdwccert.Subject)" -circle "red"
                            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "Thumbprint: $($rdwccert.Thumbprint)" -circle "red"
                        } else {
                            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "Expires on: $wcexpdate" -Message3 "Subject: $($rdwccert.Subject)" -circle "blue"
                            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "Thumbprint: $($rdwccert.Thumbprint)" -circle "blue"
                        }
                    } else {
                        $global:msrdSetWarning = $true
                        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Remote Desktop Web Client Broker Certificate information could not be retrieved" -circle "red"
                    }
                } else {
                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop Web Client Broker Certificate information" -Message2 "not found"
                }
            } catch {
                $failedCommand = $_.InvocationInfo.Line.TrimStart()
                msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop Web Client Broker Certificate information" -Message2 "not found"
            }

        } else {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop Web Access role" -Message2 "not found"
        }

        #broker
        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdLogDiag DiagFileOnly -Type "HR"
        msrdLogDiag DiagFileOnly -Type "Spacer"
        if ($script:foundRDS.Name -eq "RDS-CONNECTION-BROKER") {
            if (Test-Path ($global:msrdLogDir + $getfarmdatafile)) {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "<b>Remote Desktop Connection Broker role</b>" -Message2 "Installed (See: <a href='$getfarmdatafile' target='_blank'>GetFarmData</a>)" -circle "green"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "<b>Remote Desktop Connection Broker role</b>" -Message2 "Installed" -circle "green"
            }
            if ($global:msrdAVD) {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Having the Remote Desktop Connection Broker role installed on an AVD host is not supported" -circle "red"
            }

            msrdLogDiag DiagFileOnly -Type "Spacer"
            msrdCheckServicePort -service Tssdis -stopWarning 1
            msrdLogDiag DiagFileOnly -Type "DL"
            msrdCheckServicePort -service RDMS -stopWarning 1
            msrdLogDiag DiagFileOnly -Type "DL"
            msrdCheckServicePort -service TScPubRPC -tcpports 5504 -stopWarning 1
            msrdLogDiag DiagFileOnly -Type "DL"
            msrdCheckServicePort -service 'MSSQL$MICROSOFT##WID'

            # Certificates
            msrdLogDiag DiagFileOnly -Type "DL"
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "RDS deployment certificates:"
            $rdscert = Get-RDCertificate -ErrorAction Continue 2>>$global:msrdErrorLogFile | Select-Object Role, Level, ExpiresOn, Subject, SubjectAlternateName, Thumbprint
            if ($rdscert) {
                $thresholdDate = (Get-Date).AddDays(30)
                foreach ($cert in $rdscert) {
                    $certlvl = $cert.Level
                    if ($cert.ExpiresOn) {
                        $expdate = Get-Date ($cert.ExpiresOn)
                        $expdiff = $expdate - $thresholdDate
                        if (($expdiff -lt "30") -or ($certlvl -ne "Trusted")) {
                            $global:msrdSetWarning = $true
                            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "$($cert.Role)" -Message2 "$certlvl - Expires on: $expdate" -Message3 "Subject: $($cert.Subject)" -circle "red"
                            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "Thumbprint: $($cert.Thumbprint)" -Message3 "SAN: $($cert.SubjectAlternateName)" -circle "red"
                        } else {
                            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "$($cert.Role)" -Message2 "$certlvl - Expires on: $expdate" -Message3 "Subject: $($cert.Subject)" -circle "blue"
                            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "Thumbprint: $($cert.Thumbprint)" -Message3 "SAN: $($cert.SubjectAlternateName)" -circle "blue"
                        }
                    } else {
                        $global:msrdSetWarning = $true
                        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "$($cert.Role)" -Message2 "$certlvl" -circle "red"
                    }
                }
            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Remote Desktop certificates information not found or could not be retrieved" -circle "red"
            }

        } else {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop Connection Broker role" -Message2 "not found"
        }

        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\CentralizedPublishing\' 'Redirector'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\CentralizedPublishing\' 'RedirectorAlternateAddress'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\CentralizedPublishing\' 'Port'

        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings\' 'DeploymentServerName'

        #session host
        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdLogDiag DiagFileOnly -Type "HR"
        msrdLogDiag DiagFileOnly -Type "Spacer"
        if ($script:foundRDS.Name -eq "RDS-RD-Server") {
            if (Test-Path ($global:msrdLogDir + $gracefile)) {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "<b>Remote Desktop Session Host role</b>" -Message2 "Installed (See: <a href='$gracefile' target='_blank'>GracePeriod</a>)" -circle "green"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "<b>Remote Desktop Session Host role</b>" -Message2 "Installed" -circle "green"
            }
        } else {
            if ($global:msrdAVD) {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop Session Host role" -Message2 "not found" -circle "red"
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "This machine is running a Windows Server OS but the Remote Desktop Session Host role is not installed. This role is required for AVD VMs running Windows Server OS." -circle "red"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop Session Host role" -Message2 "not found"
            }
        }

        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'CertTemplateName' '' 'Computer Policy: Server authentication certificate template'

        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'SessionDirectoryLocation' '' 'Computer Policy: Configure RD Connection Broker server name'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'SessionDirectoryClusterName' '' 'Computer Policy: Configure RD Connection Broker farm name'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'ParticipateInLoadBalancing' '' 'Computer Policy: Use RD Connection Broker load balancing'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'SessionDirectoryActive' '' 'Computer Policy: Join RD Connection Broker'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'SessionDirectoryExposeServerIP' '' 'Computer Policy: Use IP Address Redirection'
        
        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\' 'SessionDirectoryActive'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\' 'TSServerDrainMode' '0'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings\' 'SessionDirectoryClusterName'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings\' 'SessionDirectoryLocation'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings\' 'SessionDirectoryRedirectionIP'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings\' 'ParticipateInLoadBalancing'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings\' 'ServerWeight'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings\' 'UvhdEnabled'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings\' 'UvhdShareUrl'

        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\TSAppSrv\VirtualIP\' 'EnableVirtualIP' '' 'Computer Policy: Turn on Remote Desktop IP Virtualization'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\TSAppSrv\VirtualIP\' 'VirtualMode' '' 'Computer Policy: Turn on Remote Desktop IP Virtualization'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\TSAppSrv\VirtualIP\' 'PerApp' '' 'Computer Policy: Turn on Remote Desktop IP Virtualization'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\TSAppSrv\VirtualIP\' 'VIPAdapter' '' 'Computer Policy: Select the network adapter to be used for Remote Desktop IP Virtualization'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\TSAppSrv\VirtualIP\' 'PromptOnIPLeaseFail' '' 'Computer Policy: Do not use Remote Desktop Session Host server IP address when virtual IP address is not available'

        #license server
        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdLogDiag DiagFileOnly -Type "HR"
        msrdLogDiag DiagFileOnly -Type "Spacer"
        if ($script:foundRDS.Name -eq "RDS-Licensing") {
            if ((Test-Path ($global:msrdLogDir + $licpakfile)) -and (Test-Path ($global:msrdLogDir + $licoutfile))) {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "<b>Remote Desktop Licensing role</b>" -Message2 "Installed (See: <a href='$licpakfile' target='_blank'>LicenseKeyPacks.html</a> / <a href='$licoutfile' target='_blank'>IssuedLicenses.html</a>)" -circle "green"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "<b>Remote Desktop Licensing role</b>" -Message2 "Installed" -circle "green"
            }
            msrdLogDiag DiagFileOnly -Type "Spacer"
            msrdCheckServicePort -service TermServLicensing -stopWarning 1

            msrdLogDiag DiagFileOnly -Type "Spacer"
            $licactivation = (Invoke-WmiMethod Win32_TSLicenseServer -Name GetActivationStatus -ErrorAction Continue 2>>$global:msrdErrorLogFile).ActivationStatus
            if ($null -ne $licactivation) {
                if ($licactivation -eq 0) {
                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop license server activation status:" -Message2 "Activated" -circle "green"
                } elseif ($licactivation -eq 1) {
                    $global:msrdSetWarning = $true
                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop license server activation status:" -Message2 "Not activated" -circle "red"
                } else {
                    $global:msrdSetWarning = $true
                    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Remote Desktop license server activation status: An unknown error occurred. It is not known whether the Remote Desktop license server is activated" -circle "red"
                }
            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop license server activation status:" -Message2 "Could not be retrieved" -circle "red"
            }

            $licTSLSG = (Invoke-WmiMethod Win32_TSLicenseServer -Name IsLSinTSLSGroup -ErrorAction Continue 2>>$global:msrdErrorLogFile).IsMember
            if ($licTSLSG) {
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Remote Desktop license server is a member of the Terminal Server License Servers group in the domain." -circle "green"
            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Remote Desktop license server is either not a member of the Terminal Server License Servers group in the domain, not joined to a domain or the domain cannot be contacted." -circle "red"
            }

            msrdLogDiag DiagFileOnly -Type "Spacer"
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fSecureLicensing' '' 'Computer Policy: License server security group'
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fPreventLicenseUpgrade' '' 'Computer Policy: Prevent license upgrade'

        } else {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop Licensing role" -Message2 "not found"
        }

    } else {
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Windows Server OS not found. Skipping check (not applicable)"
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagRDClient {

    #RD Client diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Remote Desktop Clients"
    $menucatmsg = $script:msrdMenuCat
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "RDCCheck"

    $mstscVer = (Get-Item C:\Windows\System32\mstsc.exe).VersionInfo.FileVersion
    if ($mstscVer) {
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Microsoft RD client (MSTSC)" -Message2 "$mstscVer" -circle "blue"
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Path: C:\Windows\System32\mstsc.exe" -circle "blue"
    } else {
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Microsoft RD client (MSTSC)" -Message2 "not found" -circle "red"
    }

    msrdLogDiag DiagFileOnly -Type "HR"
    if ($script:RDClient) {
        foreach ($RDCitem in $script:RDClient) {
            $RDCver = $RDCitem.DisplayVersion
            if ($RDCitem.InstallDate) { $RDCdate = $RDCitem.InstallDate } else { $RDCdate = "N/A" }
            if ($RDCitem.InstallLocation) { $RDCloc = $RDCitem.InstallLocation } else { $RDCloc = "N/A" }

            [int64]$RDCverStrip = $RDCver.Replace(".","")
            if ($RDCverStrip -lt $latestRDCver) { $global:msrdSetWarning = $true; $circle1 = "red"; $circle2 = "red" }
            else { $circle1 = "green"; $circle2 = "blue" }

            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Windows Desktop RD client" -Message2 "$RDCver (Installed on: $RDCdate)" -circle $circle1
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Path: $RDCloc" -circle $circle2

            if ($RDCverStrip -lt $latestRDCver) {
                if ($RDCverStrip -ge $minRDCver) {
                    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "You are not using the latest available Windows Desktop RD client version. Please consider updating. See: $msrdcRef" -circle "red"
                } else {
                    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Unsupported Windows Desktop RD client version found installed on this machine. Please update. See: $msrdcRef" -circle "red"
                }
            }
            msrdLogDiag DiagFileOnly -Type "Spacer"
        }

        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\MSRDC\Policies\' 'AutomaticUpdates'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\MSRDC\Policies\' 'ReleaseRing'

    } else {
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Windows Desktop RD client" -Message2 "not found"
    }

    msrdLogDiag DiagFileOnly -Type "HR"
    $avdStoreApp = Get-AppxPackage -name MicrosoftCorporationII.AzureVirtualDesktopClient
    $avdStoreAppVer = $avdStoreApp.Version
    if ($avdStoreApp.InstallLocation) { $avdStoreAppLoc = $avdStoreApp.InstallLocation } else { $avdStoreAppLoc = "N/A" }
    if ($avdStoreAppVer) { $avdStoreAppVerStrip = $avdStoreAppVer.Replace(".","") } else { $avdStoreAppVerStrip = 0 }
    
    if ($avdStoreApp) {
            if ($avdStoreAppVerStrip -lt $latestAvdStoreApp) {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Azure Virtual Desktop Store App" -Message2 "$avdStoreAppVer" -circle "red"
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Path: $avdStoreAppLoc" -circle "red"
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Older Azure Virtual Desktop Store App version found installed on this machine. Please consider updating." -circle "red"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Azure Virtual Desktop Store App" -Message2 "$avdStoreAppVer" -circle "green"
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Path: $avdStoreAppLoc" -circle "blue"
            }
    } else {
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Azure Virtual Desktop Store App" -Message2 "not found"
    }

    msrdLogDiag DiagFileOnly -Type "HR"
    $avdHostApp = Get-AppxPackage -name MicrosoftCorporationII.AzureVirtualDesktopHostApp
    $avdHostAppVer = $avdHostApp.Version
    if ($avdHostApp.InstallLocation) { $avdHostAppLoc = $avdHostApp.InstallLocation } else { $avdHostAppLoc = "N/A" }
    if ($avdHostAppVer) { $avdHostAppVerStrip = $avdHostAppVer.Replace(".","") } else { $avdHostAppVerStrip = 0 }

    if ($avdHostApp) {
            if ($avdHostAppVerStrip -lt $latestAvdHostApp) {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Azure Virtual Desktop Host App" -Message2 "$avdHostAppVer" -circle "red"
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Path: $avdHostAppLoc" -circle "red"
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Older Azure Virtual Desktop Host App version found installed on this machine. Please consider updating." -circle "red"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Azure Virtual Desktop Host App" -Message2 "$avdHostAppVer" -circle "green"
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Path: $avdHostAppLoc" -circle "blue"
            }
    } else {
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Azure Virtual Desktop Host App" -Message2 "not found"
    }

    msrdLogDiag DiagFileOnly -Type "HR"
    $w365client = Get-AppxPackage -name MicrosoftCorporationII.Windows365
    $w365ver = $w365client.Version
    if ($w365client.InstallLocation) { $w365loc = $w365client.InstallLocation } else { $w365loc = "N/A" }
    if ($w365ver) { $w365verStrip = $w365ver.Replace(".","") } else { $w365verStrip = 0 }

    if ($w365client) {
        if ($w365verStrip -lt $latestw365ver) { $global:msrdSetWarning = $true; $circle1 = "red"; $circle2 = "red" }
        else { $circle1 = "green"; $circle2 = "blue" }
        
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Windows 365 client" -Message2 "$w365ver" -circle $circle1
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Path: $w365loc" -circle $circle2
        
        if ($w365verStrip -lt $latestw365ver) {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Older Windows 365 client version found installed on this machine. Please consider updating." -circle "red"
        }
    } else {
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Windows 365 client" -Message2 "not found"
    }

    msrdLogDiag DiagFileOnly -Type "HR"
    $StoreClient = Get-AppxPackage -name microsoft.remotedesktop
    $StoreCver = $StoreClient.Version
    $StoreCloc = $StoreClient.InstallLocation
    if ($StoreCver) { $StoreCverStrip = $StoreCver.Replace(".","") } else { $StoreCverStrip = 0 }

    if ($StoreClient) {
        if ($StoreCverStrip -lt $latestStoreCver) { $global:msrdSetWarning = $true; $circle1 = "red"; $circle2 = "red" }
        else { $circle1 = "green"; $circle2 = "blue" }
        
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Windows Remote Desktop App" -Message2 "$StoreCver" -circle $circle1
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Path: $StoreCloc" -circle $circle2

        if ($StoreCverStrip -lt $latestStoreCver) {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Older Windows Remote Desktop App version found installed on this machine. Please consider updating. See: $uwpcRef" -circle "red"
        }

        if ($StoreCverStrip -lt $minStoreCver) {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "This version of the Windows Remote Desktop App does not support AVD ARM connections." -circle "red"
        }
    } else {
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Windows Remote Desktop App" -Message2 "not found"
    }

    msrdLogDiag DiagFileOnly -Type "HR"
    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Remote Desktop Web Client (AVD)"
    $webclienturls = @("client.wvd.microsoft.com", "rdweb.wvd.azure.us", "rdweb.wvd.azure.cn")

    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "DNS name query resolution:"
    foreach ($wcurl in $webclienturls) {
        try {
            $dnswc = Resolve-DnsName -Name $wcurl -QuickTimeout -ErrorAction SilentlyContinue
            if ($dnswc) {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$wcurl" -Message3 "Successful" -circle "green"
            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$wcurl" -Message3 "Failed" -circle "red"
            }
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
    }

    msrdLogDiag DiagFileOnly -Type "HR"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Terminal Server Client\' 'DisableUDPTransport'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Terminal Server Client\' 'EnableCredSSPSupport'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Terminal Server Client\' 'RDGClientTransport'

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagLicensing {

    #RD Licensing diagnostics
    $global:msrdSetWarning = $false
    msrdLogDiag Normal -Message "Remote Desktop Licensing" -DiagTag "LicCheck"

    
    if (($script:foundRDS.Name -eq "RDS-Licensing") -or ($script:foundRDS.Name -eq "RDS-RD-Server")) {
        if (Test-Path ($global:msrdLogDir + $tslsgroupfile)) {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "RD Session Host and/or RD Licensing role(s) detected" -Message2 "(See: <a href='$tslsgroupfile' target='_blank'>TSLSMembership</a>)" -circle "blue"
            msrdLogDiag DiagFileOnly -Type "Spacer"
        }
    }

    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'LicenseServers' '' 'Computer Policy: Use the specified Remote Desktop license servers'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'LicensingMode' '' 'Computer Policy: Set the Remote Desktop licensing mode'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDisableTerminalServerTooltip' '' 'Computer Policy: Hide notifications about RD Licensing problems that affect the RD Session Host server'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Services\TermService\Parameters\LicenseServers\' 'SpecifiedLicenseServers'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core\' 'LicensingMode'

    if ($global:msrdOSVer -like "*Windows Server*") {
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\' 'X509 Certificate' '' '' 'skip'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\' 'X509 Certificate ID' '' '' 'skip'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\' 'X509 Certificate2' '' '' 'skip'
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagTimeLimits {

    #Session Time Limit diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Session Time Limits"
    $menucatmsg = $script:msrdMenuCat
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "STLCheck"

    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'MaxIdleTime' '' 'Computer Policy: Set time limit for active but idle RDS sessions'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'MaxIdleTime' '' 'User Policy: Set time limit for active but idle RDS sessions'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'MaxConnectionTime' '' 'Computer Policy: Set time limit for active RDS sessions'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'MaxConnectionTime' '' 'User Policy: Set time limit for active RDS sessions'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'MaxDisconnectionTime' '' 'Computer Policy: Set time limit for disconnected sessions'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'MaxDisconnectionTime' '' 'User Policy: Set time limit for disconnected sessions'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'RemoteAppLogoffTimeLimit' '' 'Computer Policy: Set time limit for logoff of RemoteApp sessions'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'RemoteAppLogoffTimeLimit' '' 'User Policy: Set time limit for logoff of RemoteApp sessions'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fResetBroken' '' 'Computer Policy: End session when time limits are reached'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fResetBroken' '' 'User Policy: End session when time limits are reached'

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'MaxIdleTime'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'MaxConnectionTime'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'MaxDisconnectionTime'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'fResetBroken'

    if ($global:msrdAVD) {
        msrdLogDiag DiagFileOnly -Type "Spacer"
        if ($avdcheck) {
            msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue + '\') 'MaxIdleTime'
            msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue + '\') 'MaxConnectionTime'
            msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue + '\') 'MaxDisconnectionTime'
            msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue + '\') 'fResetBroken'
        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$avdcheckmsg" -circle "red"
        }
    }

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' 'InactivityTimeoutSecs' '' 'Computer Policy: Interactive logon: Machine inactivity limit'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\' '\AutoDisconnect' '' 'Computer Policy: Microsoft network server: Amount of idle time required before suspending session'

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagTeams {

    #Microsoft Teams diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Teams Media Optimization"
    $menucatmsg = $script:msrdMenuCat
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "TeamsCheck"

    if ($global:msrdOSVer -like "*Windows 1*") {

        msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Terminal Server Client\' 'IsSwapChainRenderingEnabled'
        msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Terminal Server Client\Default\AddIns\WebRTC Redirector\' 'UseHardwareEncoding'

        if ($global:msrdAVD) {
            msrdLogDiag DiagFileOnly -Type "Spacer"
            if ($avdcheck) {
                #Checking Teams installation info
                if ($global:msrdUserprof) {
                    $TeamsLogPath = "C:\Users\" + $global:msrdUserprof + "\AppData\Local\Microsoft\Teams\current\Teams.exe"
                } else {
                    $TeamsLogPath = $env:userprofile + "\AppData\Local\Microsoft\Teams\current\Teams.exe"
                }

                if(Test-Path $TeamsLogPath) {
                    $global:msrdSetWarning = $true
                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Teams installation <span style='color: blue'>found</span>" -Message2 "per-user" -circle "red"
                    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Teams won't work properly with per-user installation on a non-persistent setup." -circle "red"
                    $isinst = $true
                } elseif (Test-Path "C:\Program Files (x86)\Microsoft\Teams\current\Teams.exe") {
                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Teams installation <span style='color: blue'>found</span>" -Message2 "per-machine" -circle "green"
                    $isinst = $true
                } else {
                    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Teams <span style='color: brown'>not found</span>. Skipping check (not applicable)"
                    $isinst = $false
                }

                if ($isinst) {
                    #Checking Teams deployment
                    if ($global:msrdUserprof) {
                        $verpath = 'C:\Users\' + $global:msrdUserprof + "\AppData\Roaming\Microsoft\Teams\settings.json"
                    } else {
                        $verpath = $env:userprofile + "\AppData\Roaming\Microsoft\Teams\settings.json"
                    }

                    if (Test-Path $verpath) {
                        if ($PSVersionTable.PSVersion -like "*5.1*") {
                            $response = Get-Content $verpath -ErrorAction Continue
                            $response = $response -creplace 'enableIpsForCallingContext','enableIPSForCallingContext'
                            $response = $response | ConvertFrom-Json

                            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Teams version:" -Message2 "$($response.version)"

                            if ($response.ring) { $teamsring = $response.ring } else { $teamsring = "N/A" }
                            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Teams ring:" -Message2 "$teamsring"
                            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Teams environment:" -Message2 "$($response.environment)"
                        } else {
                            $tver = (Get-Content $verpath -ErrorAction Continue | ConvertFrom-Json -AsHashTable).version
                            $tring = (Get-Content $verpath -ErrorAction Continue | ConvertFrom-Json -AsHashTable).ring
                            $tenv = (Get-Content $verpath -ErrorAction Continue | ConvertFrom-Json -AsHashTable).environment
                            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Teams version:" -Message2 "$tver"
                            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Teams ring:" -Message2 "$tring"
                            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Teams environment:" -Message2 "$tenv"
                        }
                    } else {
                        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$verpath <span style='color: brown'>not found</span>."
                    }

                    msrdLogDiag DiagFileOnly -Type "Spacer"
                    $path= "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
                    if (Test-Path $path) {
                        $WebRTC = Get-ChildItem -Path $path -ErrorAction Continue 2>>$global:msrdErrorLogFile | Get-ItemProperty | Select-Object DisplayName, DisplayVersion, InstallDate | Where-Object DisplayName -eq "Remote Desktop WebRTC Redirector Service"
                        if ($WebRTC) {
                            $WebRTCver = $WebRTC.DisplayVersion
                            [int64]$WebRTCstrip = $WebRTCver -replace '[.]',''
                            if ($WebRTC.InstallDate) { $WebRTCdate = $WebRTC.InstallDate } else { $WebRTCdate = "N/A" }
                            if ($WebRTCstrip -lt $latestWebRTCVer) {
                                $global:msrdSetWarning = $true
                                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop WebRTC Redirector Service:" -Message2 "$WebRTCver (Installed on: $WebRTCdate)" -circle "red"
                                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "You are not using the latest available Remote Desktop WebRTC Redirector Service version. Please consider updating. See: $webrtcRef" -circle "red"
                            } else {
                                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Remote Desktop WebRTC Redirector Service:" -Message2 "$WebRTCver (Installed on: $WebRTCdate)" -circle "blue"
                            }
                        } else {
                            $global:msrdSetWarning = $true
                            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Error retrieving Remote Desktop WebRTC Redirector Service information" -circle "red"
                        }
                    } else {
                        $global:msrdSetWarning = $true
                        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Error retrieving Remote Desktop WebRTC Redirector Service information" -circle "red"
                    }

                    msrdLogDiag DiagFileOnly -Type "Spacer"

                    msrdCheckServicePort -service RDWebRTCSvc -tcpports 9500
                    msrdLogDiag DiagFileOnly -Type "HR"

                    #Checking reg keys
                    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Teams\' 'IsWVDEnvironment' '1'
                    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\WebRTC Redirector\' 'Enabled' '1'
                    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\WebRTC Redirector\Policy\' 'ShareClientDesktop'
                    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\WebRTC Redirector\Policy\' 'DisableRAILScreenSharing'
                    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\WebRTC Redirector\Policy\' 'DisableRAILAppSharing'
                    msrdCheckRegPath 'HKLM:\SOFTWARE\Citrix\PortICA' 'This path should not exist on an AVD-only deployment'
                    msrdCheckRegPath 'HKLM:\SOFTWARE\VMware, Inc.\VMware VDM\Agent' 'This path should not exist on an AVD-only deployment'
                }

            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$avdcheckmsg" -circle "red"
            }
        }
    } else {
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Windows 10+ OS <span style='color: brown'>not found</span>. Skipping check (not applicable)."
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

#endregion AVD/RDS diag functions


#region AVD Infra functions

Function msrdDiagAgentStack {

    #AVD Agent/Stack diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "AVD Agent / SxS Stack"
    $menucatmsg = "AVD Infra"
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "AgentStackCheck"

    if ($avdcheck) {
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader') {

            msrdCheckServicePort -service RDAgentBootLoader -stopWarning 1

            msrdLogDiag DiagFileOnly -Type "Spacer"
            if (msrdTestRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader\' -Value 'CurrentBootLoaderVersion') {
                $AVDBLA = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader\' -name "CurrentBootLoaderVersion"

                if (Test-Path ($global:msrdLogDir + $agentBLinstfile)) {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "Agent BootLoader:" -Message2 "Current version" -Message3 "$AVDBLA (See: <a href='$agentBLinstfile' target='_blank'>AgentBootLoaderInstall</a>)" -circle "blue"
                } else {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "Agent BootLoader:" -Message2 "Current version" -Message3 "$AVDBLA" -circle "blue"
                }

            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "Agent BootLoader:" -Message2 "'HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader\CurrentBootLoaderVersion' <span style='color: brown'>not found</span>." -circle "red"
            }

            msrdLogDiag DiagFileOnly -Type "Spacer"
            if (msrdTestRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader\' -Value 'DefaultAgent') {

                $AVDagent = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader\' -name "DefaultAgent"
                $AVDagentver = $AVDagent.split("_")[1]
                $AVDagentdate = (Get-ItemProperty  hklm:\software\microsoft\windows\currentversion\uninstall\* | Where-Object {($_.DisplayName -eq "Remote Desktop Services Infrastructure Agent" -and $_.DisplayVersion -eq $AVDagentver)}).InstallDate

                if (Test-Path ($global:msrdLogDir + $agentInitinstfile)) {
                    if (Test-Path -Path ($global:msrdLogDir + $agentUpdateinstfile)) {
                        if (Test-Path -Path ($global:msrdLogDir + $montablesfolder) -PathType Container) {
                            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "AVD Agent:" -Message2 "Current version (Installed on: $AVDagentdate)" -Message3 "$AVDagentver (See: <a href='$agentInitinstfile' target='_blank'>AgentInstall</a> / <a href='$agentUpdateinstfile' target='_blank'>AgentUpdates</a> / <a href='$montablesfolder' target='_blank'>MonTables</a>)" -circle "blue"
                        } else {
                            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "AVD Agent:" -Message2 "Current version (Installed on: $AVDagentdate)" -Message3 "$AVDagentver (See: <a href='$agentInitinstfile' target='_blank'>AgentInstall</a> / <a href='$agentUpdateinstfile' target='_blank'>AgentUpdates</a>)" -circle "blue"
                        }
                    } else {
                        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "AVD Agent:" -Message2 "Current version (Installed on: $AVDagentdate)" -Message3 "$AVDagentver (See: <a href='$agentInitinstfile' target='_blank'>AgentInstall</a>)" -circle "blue"
                    }
                } else {
                    if (Test-Path ($global:msrdLogDir + $agentUpdateinstfile)) {
                        if (Test-Path ($global:msrdLogDir + $montablesfolder)) {
                            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "AVD Agent:" -Message2 "Current version (Installed on: $AVDagentdate)" -Message3 "$AVDagentver (See: <a href='$agentUpdateinstfile' target='_blank'>AgentInstall</a> / <a href='$montablesfolder' target='_blank'>MonTables</a>)" -circle "blue"
                        } else {
                            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "AVD Agent:" -Message2 "Current version (Installed on: $AVDagentdate)" -Message3 "$AVDagentver (See: <a href='$agentUpdateinstfile' target='_blank'>AgentInstall</a>)" -circle "blue"
                        }
                    } else {
                        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "AVD Agent:" -Message2 "Current version (Installed on: $AVDagentdate)" -Message3 "$AVDagentver" -circle "blue"
                    }
                }

                if (msrdTestRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader\' -Value 'PreviousAgent') {
                    $AVDagentpre = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader\' -name "PreviousAgent"
                    $AVDagentverpre = $AVDagentpre.split("_")[1]
                    $AVDagentdatepre = (Get-ItemProperty  hklm:\software\microsoft\windows\currentversion\uninstall\* | Where-Object {($_.DisplayName -eq "Remote Desktop Services Infrastructure Agent" -and $_.DisplayVersion -eq $AVDagentverpre)}).InstallDate
                } else {
                    $AVDagentverpre = "N/A"
                    $AVDagentdatepre = "N/A"
                }
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "Previous version (Installed on: $AVDagentdatepre)" -Message3 "$AVDagentverpre" -circle "blue"
            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "'HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader\DefaultAgent' <span style='color: brown'>not found</span>. This machine is either not part of an AVD host pool or it is not configured properly." -circle "red"
            }

        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "RDAgentBootLoader configuration <span style='color: brown'>not found</span>. This machine is either not part of an AVD host pool or it is not configured properly." -circle "red"
            if ($hp) {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "VM is part of host pool '$hp' but the HKLM:\SOFTWARE\Microsoft\RDAgentBootLoader registry key could not be found. You may have issues accessing this VM through AVD." -circle "red"
            }
        }

        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\RDInfraAgent') {

            msrdLogDiag DiagFileOnly -Type "Spacer"
            msrdLogDiag DiagFileOnly ("... SxS Stack:")

            if (msrdTestRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\RDInfraAgent\SxsStack\' -Value 'CurrentVersion') {
                $sxsstack = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\RDInfraAgent\SxsStack' -name "CurrentVersion"
                $sxsstackpath = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\RDInfraAgent\SxsStack' -name $sxsstack
                $sxsstackver = $sxsstackpath.split("-")[1].trimend(".msi")
                $sxsstackdate = (Get-ItemProperty  hklm:\software\microsoft\windows\currentversion\uninstall\* | Where-Object {($_.DisplayName -eq "Remote Desktop Services SxS Network Stack" -and $_.DisplayVersion -eq $sxsstackver)}).InstallDate

                if (Test-Path ($global:msrdLogDir + $sxsinstfile)) {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "SxS Stack:" -Message2 "Current version (Installed on: $sxsstackdate)" -Message3 "$sxsstackver (See: <a href='$sxsinstfile' target='_blank'>SxSStackInstall</a>)" -circle "blue"
                } else {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "SxS Stack:" -Message2 "Current version (Installed on: $sxsstackdate)" -Message3 "$sxsstackver" -circle "blue"
                }

            } else {
                $sxsstackver = "N/A"
                $sxsstackdate = "N/A"
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "SxS Stack:" -Message2 "Current version: <span style='color: brown'>not found</span>. Check if the SxS Stack was installed properly." -circle "red"
            }

            if (msrdTestRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\RDInfraAgent\SxsStack\' -Value 'PreviousVersion') {
                $sxsstackpre = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\RDInfraAgent\SxsStack' -name "PreviousVersion"
                if (($sxsstackpre) -and ($sxsstackpre -ne "")) {
                    $sxsstackpathpre = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\RDInfraAgent\SxsStack' -name $sxsstackpre
                    $sxsstackverpre = $sxsstackpathpre.split("-")[1].trimend(".msi")
                    $sxsstackdatepre = (Get-ItemProperty  hklm:\software\microsoft\windows\currentversion\uninstall\* | Where-Object {($_.DisplayName -eq "Remote Desktop Services SxS Network Stack" -and $_.DisplayVersion -eq $sxsstackverpre)}).InstallDate
                } else {
                    $sxsstackverpre = "N/A"
                    $sxsstackdatepre = "N/A"
                }
            } else {
                $sxsstackverpre = "N/A"
                $sxsstackdatepre = "N/A"
            }
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "Previous version (Installed on: $sxsstackdatepre)" -Message3 "$sxsstackverpre" -circle "blue"


            msrdLogDiag DiagFileOnly -Type "Spacer"
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\RDInfraAgent\' 'IsRegistered' '1' -warnMissing
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\RDInfraAgent\' 'RegistrationToken'

        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "RDInfraAgent configuration <span style='color: brown'>not found</span>. This machine is either not part of an AVD host pool or it is not configured properly." -circle "red"
        }
    } else {
        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$avdcheckmsg" -circle "red"
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagHP {

    #AVD host pool diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "AVD Host Pool"
    $menucatmsg = "AVD Infra"
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "HPCheck"

    If (Test-Path 'HKLM:\SOFTWARE\Microsoft\RDMonitoringAgent') {
        if (msrdTestRegistryValue -path "HKLM:\SOFTWARE\Microsoft\RDMonitoringAgent" -value "SessionHostPool") {
            $script:hp = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\RDMonitoringAgent" -name "SessionHostPool"
        } else { $hp = $false }

        if (msrdTestRegistryValue -path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -value "Geography") {
            $geo = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -name "Geography"
        } else { $geo = "N/A" }

        if (msrdTestRegistryValue -path "HKLM:\SOFTWARE\Microsoft\RDMonitoringAgent" -value "Tenant") {
            $rg = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\RDMonitoringAgent" -name "Tenant"
        } else { $rg = "N/A" }

        if (msrdTestRegistryValue -path "HKLM:\SOFTWARE\Microsoft\RDMonitoringAgent" -value "Cluster") {
            $cluster = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\RDMonitoringAgent" -name "Cluster"
        } else { $cluster = "N/A" }

        if ($hp) {
            if (msrdTestRegistryValue -path "HKLM:\SOFTWARE\Microsoft\RDMonitoringAgent" -value "Ring") {
                $ring = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\RDMonitoringAgent" -name "Ring"
            } else { $ring = "N/A" }

            Add-Content $msrdDiagFile "<tr align='center'><th width='10px'><div class='circle_no'></div></th><th>Host Pool</th><th>Ring</th><th>Resource Group</th><th>Geography</th><th>Cluster</th></tr>"

            if ($ring -eq "R0") {
                $global:msrdSetWarning = $true
                Add-Content $msrdDiagFile "<tr align='center'><td width='10px'><div class='circle_red'></div></td><td>$hp</td><td>$ring</td><td>$rg</td><td>$geo</td><td>$cluster</td></tr>"
                msrdLogDiag DiagFileOnly -Type "Text" -col 4 -Message "This host pool is in the validation ring (R0). Validation ring deployments are intended for testing, not for production use!" -circle "red"
            } else {
                Add-Content $msrdDiagFile "<tr align='center'><td width='10px'><div class='circle_white'></div></td><td>$hp</td><td>$ring</td><td>$rg</td><td>$geo</td><td>$cluster</td></tr>"
            }

            if (msrdTestRegistryValue -path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -value "HostPoolArmPath") {
                msrdLogDiag DiagFileOnly -Type "Spacer"
                $armpath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -name "HostPoolArmPath"
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Host pool ARM path:" -Message2 "$armpath"
            }

        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -col 4 -Message "'RDMonitoringAgent' reg key found, but this machine is not part of an AVD host pool. It might have host pool registration issues." -circle "red"
        }

    } else {
        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Text" -col 4 -Message "'RDMonitoringAgent' reg key not found. This machine does not seem to be part of an AVD host pool." -circle "red"
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagURL {

    #AVD required URLs diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "AVD Required URLs"
    $menucatmsg = "AVD"
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "URLCheck"

    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "<b>AVD Client URLs:</b>"
    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "DNS name query resolution:"

    $rdcdnsurls = @("login.microsoftonline.com", "wvd.microsoft.com", "servicebus.windows.net", "go.microsoft.com", "aka.ms", "learn.microsoft.com", "privacy.microsoft.com", "query.prod.cms.rt.microsoft.com")

    foreach ($rddnsurl in $rdcdnsurls) {
        try {
            $rdoutdns = Resolve-DnsName -Name $rddnsurl -QuickTimeout -ErrorAction SilentlyContinue
            if ($rdoutdns) {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$rddnsurl" -Message3 "Successful" -circle "green"
            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$rddnsurl" -Message3 "Failed" -circle "red"
            }
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
    }

    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Endpoint access over port 443:"

    $rdctcpurls = @("login.microsoftonline.com", "microsoft.com", "windows.net", "go.microsoft.com", "aka.ms", "learn.microsoft.com", "privacy.microsoft.com", "query.prod.cms.rt.microsoft.com")

    foreach ($rdtcpurl in $rdctcpurls) {
        try {
            $rdouttcp = msrdTestTCP -address $rdtcpurl -port 443
            if ($rdouttcp -eq $true) {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$rdtcpurl" -Message3 "Reachable" -circle "green"
            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$rdtcpurl" -Message3 "Not reachable (See <a href='$msrdErrorfileurl' target='_blank'>MSRD-Collect-Error</a>)" -circle "red"
            }
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
    }

    if ($global:msrdAVD) {
        msrdLogDiag DiagFileOnly -Type "HR"
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "<b>AVD Host URLs:</b>"

        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "DNS name query resolution:"

        $avddnsurls = @("login.microsoftonline.com", "catalogartifact.azureedge.net", "kms.core.windows.net", "azkms.core.windows.net", "wvdportalstorageblob.blob.core.windows.net", "oneocsp.microsoft.com", "www.microsoft.com")

        foreach ($avddnsurl in $avddnsurls) {
            try {
                $avdoutdns = Resolve-DnsName -Name $avddnsurl -QuickTimeout -ErrorAction SilentlyContinue
                if ($rdoutdns) {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$avddnsurl" -Message3 "Successful" -circle "green"
                } else {
                    $global:msrdSetWarning = $true
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$avddnsurl" -Message3 "Failed" -circle "red"
                }
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
        }

        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Endpoint access over port 443:"

        $rdctcpurls = @("login.microsoftonline.com", "catalogartifact.azureedge.net", "wvdportalstorageblob.blob.core.windows.net")

        foreach ($rdtcpurl in $rdctcpurls) {
            try {
                $rdouttcp = msrdTestTCP -address $rdtcpurl -port 443
                if ($rdouttcp -eq $true) {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$rdtcpurl" -Message3 "Reachable" -circle "green"
                } else {
                    $global:msrdSetWarning = $true
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$rdtcpurl" -Message3 "Not reachable (See <a href='$msrdErrorfileurl' target='_blank'>MSRD-Collect-Error</a>)" -circle "red"
                }
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
        }

        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Endpoint access over port 1688:"

        $rdctcpurls = @("kms.core.windows.net", "azkms.core.windows.net")

        foreach ($rdtcpurl in $rdctcpurls) {
            try {
                $rdouttcp = msrdTestTCP -address $rdtcpurl -port 1688
                if ($rdouttcp -eq $true) {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$rdtcpurl" -Message3 "Reachable" -circle "green"
                } else {
                    $global:msrdSetWarning = $true
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$rdtcpurl" -Message3 "Not reachable (See <a href='$msrdErrorfileurl' target='_blank'>MSRD-Collect-Error</a>)" -circle "red"
                }
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
        }

        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Endpoint access over port 80:"

        $rdctcpurls = @("169.254.169.254", "168.63.129.16", "oneocsp.microsoft.com", "www.microsoft.com")

        foreach ($rdtcpurl in $rdctcpurls) {
            try {
                $rdouttcp = msrdTestTCP -address $rdtcpurl -port 80
                if ($rdouttcp -eq $true) {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$rdtcpurl" -Message3 "Reachable" -circle "green"
                } else {
                    $global:msrdSetWarning = $true
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$rdtcpurl" -Message3 "Not reachable (See <a href='$msrdErrorfileurl' target='_blank'>MSRD-Collect-Error</a>)" -circle "red"
                }
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
        }

        msrdLogDiag DiagFileOnly -Type "Spacer"
        If ($avdcheck) {
            $toolfolder = Get-ChildItem $msrdAgentpath -Directory | Foreach-Object {If (($_.psiscontainer) -and ($_.fullname -like "*RDAgent_*")) { $_.Name }} | Select-Object -Last 1
            $URLCheckToolPath = $msrdAgentpath + $toolfolder + "\WVDAgentUrlTool.exe"

            if (Test-Path $URLCheckToolPath) {
                Try {
                    $urlout = Invoke-Expression "& '$URLCheckToolPath'"
                    $urlna = $false
                    foreach ($urlline in $urlout) {
                        if (!($urlline -eq "") -and !($urlline -like "*===========*") -and !($urlline -like $null) -and ($urlline -ne "WVD") -and !($urlline -like "*Acquired on*") -and !($urlline -like "*Agent URL Tool*") -and !($urlline -like "*Copyright*")) {

                            if ($urlline -like "*Not Accessible*") { $urlna = $true }

                            if ($urlline -like "*Version*") {
                                $uver = $urlline.Split(" ")[1]
                                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Azure Virtual Desktop Agent URL Tool:" -Message2 "$uver"

                            } elseif (($urlline -like "*.com") -or ($urlline -like "*.net")) {
                                if ($urlna) {
                                    $global:msrdSetWarning = $true
                                    msrdLogDiag DiagFileOnly -Type "Table1-2" -Message2 "$urlline" -circle "red"
                                } else {
                                    msrdLogDiag DiagFileOnly -Type "Table1-2" -Message2 "$urlline" -circle "green"
                                }

                            } elseif ($urlline -like "UrlsAccessibleCheck*") {
                                $urlc2 = $urlline.Split(": ")[-1]
                                $urlc1 = $urlline.Trimend($urlc2)
                                if ($urlc2 -like "*HealthCheckSucceeded*") {
                                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$urlc1" -Message2 "$urlc2" -circle "green"
                                } else {
                                    $global:msrdSetWarning = $true
                                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$urlc1" -Message2 "$urlc2" -circle "red"
                                }

                            } elseif (($urlline -like "*Unable to extract*") -or ($urlline -like "*Failed to connect to the Agent*") -or ($urlline -like "*Tool failed with*")) {
                                $global:msrdSetWarning = $true
                                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$urlline" -circle "red"

                            } else {
                                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$urlline"
                            }
                        }
                    }
                } Catch {
                    $failedCommand = $_.InvocationInfo.Line.TrimStart()
                    $errorMessage = $_.Exception.Message.TrimStart()
                    msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
                    if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                        msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
                    } else {
                        msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
                    }
                    Continue
                }
            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$msrdAgentpath found, but 'WVDAgentUrlTool.exe' is missing, skipping check. You should be running agent version 1.0.2944.1200 or higher." -circle "red"
            }       

        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$avdcheckmsg" -circle "red"
        }

        msrdLogDiag DiagFileOnly -Type "HR"
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "<b>Optional URLs (not required for AVD but needed for other services):</b>"
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "DNS name query resolution:"

        $optionalurls = @("login.windows.net", "events.data.microsoft.com", "www.msftconnecttest.com", "prod.do.dsp.mp.microsoft.com", "sfx.ms", "digicert.com", "azure-dns.com", "azure-dns.net")

        foreach ($opturl in $optionalurls) {
            try {
                $optdns = Resolve-DnsName -Name $opturl -QuickTimeout -ErrorAction SilentlyContinue
                if ($optdns) {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$opturl" -Message3 "Successful" -circle "green"
                } else {
                    $global:msrdSetWarning = $true
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$opturl" -Message3 "Failed" -circle "red"
                }
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
        }

        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Endpoint access over port 443:"

        $optionaltcpurls = @("login.windows.net", "events.data.microsoft.com", "www.msftconnecttest.com", "digicert.com")

        foreach ($opttcpurl in $optionaltcpurls) {
            try {
                $opttcp = msrdTestTCP -address $opttcpurl -port 443
                if ($opttcp -eq $true) {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$opttcpurl" -Message3 "Reachable" -circle "green"
                } else {
                    $global:msrdSetWarning = $true
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$opttcpurl" -Message3 "Not reachable (See <a href='$msrdErrorfileurl' target='_blank'>MSRD-Collect-Error</a>)" -circle "red"
                }
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
        }
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

function msrdCheckSiteURLStatus {
    Param([Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string]$URIkey, [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string]$URL)

    try {
        $WSProxyURL = New-object System.Net.WebProxy
        $WSWebSessionURL = new-object Microsoft.PowerShell.Commands.WebRequestSession
        $WSWebSessionURL.Proxy = $WSProxyURL
        $WSWebSessionURL.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        $request = Invoke-WebRequest -Uri $URL -WebSession $WSWebSessionURL -UseBasicParsing -TimeoutSec 30

        if ($request) {
            if ($request.StatusCode -eq "200") {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message ($URIkey + ":") -Message2 "$URL" -Message3 "Accessible ($($request.StatusDescription) - $($request.StatusCode))" -circle "green"
            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message ($URIkey + ":") -Message2 "$URL" -Message3 "Not accessible ($($request.StatusDescription) - $($request.StatusCode))" -circle "red"
            }
        }
    } catch {
        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message ($URIkey + ":") -Message2 "$URL" -Message3 "Not accessible" -circle "red"
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

Function msrdDiagURIHealth {

    #AVD service URI diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "AVD Services URI Health"
    $menucatmsg = "AVD Infra"
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "BrokerURICheck"

    $brokerURIregpath = "HKLM:\SOFTWARE\Microsoft\RDInfraAgent\"

    if (Test-Path $brokerURIregpath) {
        $brokerURIregkey = "BrokerURI"
            if (msrdTestRegistryValue -path $brokerURIregpath -value $brokerURIregkey) {
                $brokerURI = Get-ItemPropertyValue -Path $brokerURIregpath -name $brokerURIregkey
                $brokerURI = $brokerURI + "api/health"
                msrdCheckSiteURLStatus $brokerURIregkey $brokerURI
            } else {
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "'$brokerURIregpath$brokerURIregkey' <span style='color: brown'>not found</span>. This machine doesn't seem to be a AVD VM or it is not configured properly." -circle "red"
            }

        $brokerURIGlobalregkey = "BrokerURIGlobal"
            if (msrdTestRegistryValue -path $brokerURIregpath -value $brokerURIGlobalregkey) {
                $brokerURIGlobal = Get-ItemPropertyValue -Path $brokerURIregpath -name $brokerURIGlobalregkey
                $brokerURIGlobal = $brokerURIGlobal + "api/health"
                msrdCheckSiteURLStatus $brokerURIGlobalregkey $brokerURIGlobal
            } else {
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "'$brokerURIregpath$brokerURIGlobalregkey' <span style='color: brown'>not found</span>. This machine doesn't seem to be a AVD VM or it is not configured properly." -circle "red"
            }

        $diagURIregkey = "DiagnosticsUri"
            if (msrdTestRegistryValue -path $brokerURIregpath -value $diagURIregkey) {
                $diagURI = Get-ItemPropertyValue -Path $brokerURIregpath -name $diagURIregkey
                $diagURI = $diagURI + "api/health"
                msrdCheckSiteURLStatus $diagURIregkey $diagURI
            } else {
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "'$brokerURIregpath$diagURIregkey' <span style='color: brown'>not found</span>. This machine doesn't seem to be a AVD VM or it is not configured properly." -circle "red"
            }

        $BrokerResourceIdURIGlobalregkey = "BrokerResourceIdURIGlobal"
            if (msrdTestRegistryValue -path $brokerURIregpath -value $diagURIregkey) {
                $BrokerResourceIdURIGlobal = Get-ItemPropertyValue -Path $brokerURIregpath -name $BrokerResourceIdURIGlobalregkey
                $BrokerResourceIdURIGlobal = $BrokerResourceIdURIGlobal + "api/health"
                msrdCheckSiteURLStatus $BrokerResourceIdURIGlobalregkey $BrokerResourceIdURIGlobal
            } else {
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "'$brokerURIregpath$BrokerResourceIdURIGlobalregkey' <span style='color: brown'>not found</span>. This machine doesn't seem to be a AVD VM or it is not configured properly." -circle "red"
            }

    } else {
        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$avdcheckmsg" -circle "red"
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagHCI {

    #AVD Azure Stack HCI diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Azure Stack HCI"
    $menucatmsg = "AVD Infra"
    msrdLogDiag Normal -Message "Azure Stack HCI" -DiagTag "HCICheck"

    if ($avdcheck) {
        msrdCheckServicePort -service GCArcService -skipWarning 1
        msrdCheckServicePort -service ExtensionService -skipWarning 1
        msrdCheckServicePort -service himds -skipWarning 1
    } else {
        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$avdcheckmsg" -circle "red"
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

function msrdAVDShortpathCheck {

    if ($global:avdnettestpath -ne "") {
        $avdok = $false
        try {
            $avdout = Invoke-Expression "& '$global:avdnettestpath'"
            $avdout = $avdout -split "`n" | Where-Object { $_ -ne "" }
            $avdpattern = '(?i)\b(?:https?://|www\.)\S+\b'

            if ($avdout) {
                foreach ($avdline in $avdout) {
                    if ($avdline -like "*AVD Network Test Version*") {
                        $aver = $avdline.Split(" ")[-1]
                        if (Test-Path -Path ($global:msrdLogDir + $avdnettestfile)) {
                            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "AVD Network Test Version:" -Message2 "$aver (See: <a href='$avdnettestfile' target='_blank'>avdnettest</a>)" -circle "blue"
                        } else {
                            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "AVD Network Test Version:" -Message2 "$aver"
                        }
                    } elseif ($avdline -like "*...*") {
                        $avdc2 = $avdline.Split("... ")[-1]
                        $avdc1 = $avdline.Trimend($avdc2)
                        if ($avdc2 -like "*OK*") {
                            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$avdc1" -Message2 "$avdc2" -circle "green"
                        } else {
                            $global:msrdSetWarning = $true
                            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$avdc1" -Message2 "$avdc2" -circle "red"
                        }
                    } elseif (($avdline -like "*cone shaped*") -or ($avdline -like "*you have access to TURN servers*")) {
                        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$avdline" -circle "green"
                        $avdok = $true
                    } else {
                        if ($avdline -match $avdpattern) {
                            $avdreplace = "<a href='https://go.microsoft.com/fwlink/?linkid=2204021' target='_blank'>https://go.microsoft.com/fwlink/?linkid=2204021</a>"
                            $avdline = $avdline -replace $avdpattern, $avdreplace
                        }
                        
                        if ($avdok) {
                            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$avdline" -circle "green"
                        } else {
                            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$avdline" -circle "red"
                        }
                    }
                }
            }

        } catch {
            $failedCommand = $_.InvocationInfo.Line.TrimStart()
            $errorMessage = $_.Exception.Message.TrimStart()
            msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
            if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
            } else {
                msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
            }
            Continue
        }
    } else {
        $global:msrdSetWarning = $true
        $notfoundmsg = "avdnettest.exe could not be found. Skipping check. Information on RDP Shortpath for AVD availability will be incomplete. Make sure you download and unpack the full package of MSRD-Collect or TSSv2."
        if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            msrdAdd-OutputBoxLine ("$notfoundmsg") "Magenta"
        } else {
            msrdLogMessage Warning $notfoundmsg
        }
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$notfoundmsg" -circle "red"
    }
}

Function msrdDiagShortpath {

    #AVD Shortpath diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "RDP Shortpath"
    $menucatmsg = "AVD Infra"
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "UDPCheck"

    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client\' 'fClientDisableUDP'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Terminal Server Client\' 'DisableUDPTransport'

    msrdLogDiag DiagFileOnly -Type "Spacer"
    if ($script:RDClient) {
        foreach ($RDCitem in $script:RDClient) {
            $RDCver = $RDCitem.DisplayVersion
            [int64]$RDCverStrip = $RDCver.Replace(".","")
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Shortpath compatible Windows Desktop RD client found installed on this machine" -Message2 "$RDCver" -circle "green"
            if (($RDCverStrip -ge $minRDCver) -and ($RDCverStrip -lt $minRDCverPubSpath)) {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Older Windows Desktop RD client found installed on this machine. RDP Shortpath requires version 1.2.3488 or later. Please consider updating. See: $msrdcRef" -circle "red"
            }
            if ($RDCverStrip -lt $minRDCver) {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Unsupported Windows Desktop RD Client found installed on this machine. Please update. See: $msrdcRef" -circle "red"
            }
        }
    }

    If (!($global:msrdOSVer -like "*Server*2008*")) {
        msrdLogDiag DiagFileOnly -Type "Spacer"
        #Checking if there are Firewall rules for UDP 3390
        $fwrulesUDP = (Get-NetFirewallPortFilter -Protocol UDP | Where-Object { $_.localport -eq '3390' } | Get-NetFirewallRule)
        if ($fwrulesUDP.count -eq 0) {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Windows Firewall rule(s) for UDP port 3390" -Message2 "not found"
        } else {
            if (Test-Path $fwrfile) {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Windows Firewall rule(s) for UDP port 3390" -Message "found (See: <a href='$fwrfile' target='_blank'>FirewallRules</a>)" -circle "blue"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Windows Firewall rule(s) for UDP port 3390" -Message2 "found" -circle "blue"
            }
        }

        msrdLogDiag DiagFileOnly -Type "Spacer"
        # Checking Teredo configuration
        $teredo = Get-NetTeredoConfiguration
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Teredo configuration:"
        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "Type" -Message3 "$($teredo.Type)"
        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "ServerName" -Message3 "$($teredo.ServerName)"
        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "RefreshIntervalSeconds" -Message3 "$($teredo.RefreshIntervalSeconds)"
        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "ClientPort" -Message3 "$($teredo.ClientPort)"
        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "ServerVirtualIP" -Message3 "$($teredo.ServerVirtualIP)"
        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "DefaultQualified" -Message3 "$($teredo.DefaultQualified)"
        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "ServerShunt" -Message3 "$($teredo.ServerShunt)"
    }

    if ($global:msrdAVD) {
        msrdLogDiag DiagFileOnly -Type "HR"

        if ($avdcheck) {
            #Checking for events 131 in the past 5 days
            $StartTimeSP = (Get-Date).AddDays(-5)
            If (Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Operational"; id="131"; StartTime=$StartTimeSP} -MaxEvents 1 -ErrorAction SilentlyContinue | where-object { $_.Message -like '*UDP*' }) {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "UDP events 131 have been found in the 'Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Operational' event logs" -Message2 "RDP Shortpath <span style='color: green'>has been used</span> within the last 5 days" -circle "green"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "UDP events 131 have not been found in the 'Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Operational' event logs" -Message2 "RDP Shortpath <span style='color: brown'>has not been used</span> within the last 5 days" -circle "blue"
            }

            msrdLogDiag DiagFileOnly -Type "Spacer"
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "RDP Shortpath for <span style='color: blue'>managed</span> networks:"
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fUseUdpPortRedirector' '1' 'Computer Policy: Enable RDP Shortpath for managed networks'
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'UdpRedirectorPort' '3390' 'Computer Policy: Enable RDP Shortpath for managed networks'

            msrdLogDiag DiagFileOnly -Type "Spacer"
            # Checking if TermService is listening for UDP
            $udplistener = Get-NetUDPEndpoint -OwningProcess ((get-ciminstance win32_service -Filter "name = 'TermService'").ProcessId) -LocalPort 3390 -ErrorAction SilentlyContinue

            if ($udplistener) {
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "TermService is listening on UDP port 3390."
            } else {
                # Checking the process occupying UDP port 3390
                $procpid = (Get-NetUDPEndpoint -LocalPort 3390 -LocalAddress 0.0.0.0 -ErrorAction SilentlyContinue).OwningProcess

                if ($procpid) {
                    $global:msrdSetWarning = $true
                    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "TermService is NOT listening on UDP port 3390. RDP Shortpath is not configured properly. The UDP port 3390 is being used by:" -circle "red"
                    tasklist /svc /fi "PID eq $procpid" | Out-File -Append $msrdDiagFile
                } else {
                    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "No process is listening on UDP port 3390. RDP Shortpath for managed networks is not enabled." -circle "blue"
                }
            }

            msrdLogDiag DiagFileOnly -Type "Spacer"
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "RDP Shortpath for <span style='color: blue'>public</span> networks:"
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'SelectTransport' '0' 'Computer Policy: Select RDP transport protocols'
            msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' 'ICEControl' '2'
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'ICEEnableClientPortRange'
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'ICEClientPortBase'
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'ICEClientPortRange'

        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$avdcheckmsg" -circle "red"
        }
    }

    #Checking STUN server connectivity and NAT type            
    if (!($global:msrdRDS)) {
        if ($global:msrdAVD) {
            msrdLogDiag DiagFileOnly -Type "Spacer"
        } else {
            msrdLogDiag DiagFileOnly -Type "HR"
        }
        msrdAVDShortpathCheck
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

#endregion AVD Infra functions


#region AD functions

Function msrdGetDsregcmdInfo {
    Param([Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string]$dsregentry, [switch]$file = $false)

    foreach ($entry in $DsregCmdStatus) {
        $ds1 = $entry.Split(":")[0]
        $ds1 = $ds1.Trim()
        if ($ds1 -like "*$dsregentry*") {
            $ds2 = $entry -split ":" | Select-Object -Skip 1
            if ($file) {
                if (Test-Path ($global:msrdLogDir + $dsregfile)) {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message ($ds1 + ":") -Message2 "$ds2" -Message3 "(See: <a href='$dsregfile' target='_blank'>Dsregcmd</a>)"
                } else {
                    msrdLogDiag DiagFileOnly -Type "Table1-2" -Message ($ds1 + ":") -Message2 "$ds2"
                }
            } else {
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message ($ds1 + ":") -Message2 "$ds2"
            }
        }
    }
}

Function msrdDiagAADJ {

    #Azure AD join diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Azure AD Join"
    $menucatmsg = "Active Directory"
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "AADJCheck"

    $DsregCmdStatus = dsregcmd /status

    msrdGetDsregcmdInfo 'AzureAdJoined' -file
    msrdGetDsregcmdInfo 'WorkplaceJoined'
    msrdGetDsregcmdInfo 'DeviceAuthStatus'
    msrdGetDsregcmdInfo 'TenantName'
    msrdGetDsregcmdInfo 'TenantId'
    msrdGetDsregcmdInfo 'DeviceID'
    msrdGetDsregcmdInfo 'DeviceCertificateValidity'

    msrdLogDiag DiagFileOnly -Type "HR"
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u\' 'AllowOnlineID' '1'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\' 'AzureVmComputeMetadataEndpoint' 'http://169.254.169.254/metadata/instance/compute'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\' 'AzureVmMsiTokenEndpoint' 'http://169.254.169.254/metadata/identity/oauth2/token'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\' 'AzureVmTenantIdEndpoint' 'http://169.254.169.254/metadata/identity/info'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin\' 'BlockAADWorkplaceJoin'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin\' 'autoWorkplaceJoin'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\IdentityStore\LoadParameters\{B16898C6-A148-4967-9171-64D755DA8520}\' 'Enabled'

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdGetDCInfo {

        Try {
            $vmdomain = [System.Directoryservices.Activedirectory.Domain]::GetComputerDomain()
            $trusteddc = nltest /sc_query:$vmdomain

            foreach ($entry in $trusteddc) {
                if (!($entry -like "The command completed*") -and !($entry -like "*correctamente*") -and !($entry -like "*Befehl wurde *")) {
                    if (($entry -like "*Trusted DC Name*") -or ($entry -like "*Nombre DC de confianza*") -or ($entry -like "*Vertrauenswürdiger Domänencontrollername*")) {
                        $tdcn = $entry.Split(" ")[3]
                        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Trusted DC Name:" -Message2 "$tdcn" -circle "blue"
                    } elseif (($entry -like "*Connection Status*") -or ($entry -like "*Estado de conexión*")) {
                        $tdccs = $entry.Split(" ")[-1]
                        if ($tdccs -like "*Success*") {
                            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Trusted DC Connection Status:" -Message2 "$tdccs" -circle "green"
                        } else {
                            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Trusted DC Connection Status:" -Message2 "$tdccs" -circle "blue"
                        }
                    } else {
                        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$entry"
                    }
                }
            }

            msrdLogDiag DiagFileOnly -Type "Spacer"
            $alldc = nltest /dnsgetdc:$vmdomain
            foreach ($dcentry in $alldc) {
                if (!($dcentry -like "The command completed*")) {
                    if (($dcentry -like "*DCs in pseudo-random order*") -or ($dcentry -like "*Site specific*") -or ($dcentry -like "*en orden pseudoaleatorio*") -or ($dcentry -like "*específico del*") -or ($dcentry -like "*Liste der Domänencontroller in*") -or ($dcentry -like "*standortspezifisch*")) {
                        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$dcentry"
                    } else {
                        $dc0 = $dcentry.split(" ")[0]
                        $dc1 = $dcentry.split(" ")[1]
                        $dc2 = $dcentry.split(" ")[2]
                        if (($dc0 -eq "") -and ($dc1 -eq "") -and ($dc2 -eq "")) {
                            $dcfqdn = $dcentry.split(" ")[3]
                            $dcip = $dcentry.trim("$dc0 + $dc1 + $dc2")
                            $dcip2 = $dcip.trim("$dcfqdn")
                            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$dcfqdn" -Message3 "$dcip2" -circle "blue"
                        } else {
                            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message2 "$dcentry" -circle "blue"
                        }
                    }
                }
            }

            msrdLogDiag DiagFileOnly -Type "Spacer"
            $alltrust = nltest /domain_trusts /all_trusts
            foreach ($trustentry in $alltrust) {
                if (!($trustentry -like "The command completed*")) {
                    if ($trustentry -like "*List of domain trusts*") {
                        if (Test-Path ($global:msrdLogDir + $domtrustfile)) {
                            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$trustentry" -Message2 "(See: <a href='$domtrustfile' target='_blank'>Nltest-domtrust</a>)" -circle "blue"
                        } else {
                            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$trustentry"
                        }
                    } else {
                        $trust1 = $trustentry.split("(")[0]
                        $trust2 = $trustentry.trimstart($trust1)
                        msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$trust1" -Message3 "$trust2" -circle "blue"
                    }
                }
            }
        } Catch {
            $failedCommand = $_.InvocationInfo.Line.TrimStart()
            $errorMessage = $_.Exception.Message.TrimStart()
            msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
            if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
            } else {
                msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
            }

            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "An error occurred while trying to retrieve DC information. See <a href='$msrdErrorfileurl' target='_blank'>MSRD-Collect-Error</a> for more information." -circle "red"
        }
}

Function msrdDiagDC {

    #Domain diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Domain"
    $menucatmsg = "Active Directory"
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "DCCheck"

    $isDomain = (get-ciminstance -Class Win32_ComputerSystem).PartOfDomain
    if ($isDomain) {

        Try {
            $commandline = "Test-ComputerSecureChannel -Verbose 4>&1"
            $out = Invoke-Expression -Command $commandline
            foreach ($outopt in $out) {
                if ($outopt -like "False") {
                    $global:msrdSetWarning = $true
                    msrdLogDiag DiagFileOnly -Type "Table2-1"-Message "Domain secure channel connection:" -Message2 "$outopt" -circle "red"
                } elseif ($outopt -like "True") {
                    msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Domain secure channel connection:" -Message2 "$outopt" -circle "green"
                } elseif ($outopt -like "*broken*") {
                    $global:msrdSetWarning = $true
                    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$outopt" -circle "red"
                } elseif (($outopt -like "*good condition*") -or ($outopt -like "*guten Zustand*")) {
                    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$outopt" -circle "green"
                } elseif (!($outopt -like "*Performing the operation*") -and !($outopt -like "*Ausführen des Vorgangs*")) {
                    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$outopt" -circle "blue"
                }
            }
            msrdLogDiag DiagFileOnly -Type "Spacer"
        } Catch {
            $failedCommand = $_.InvocationInfo.Line.TrimStart()
            $errorMessage = $_.Exception.Message.TrimStart()
            msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
            if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
            } else {
                msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
            }

            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Could not test secure channel connection. See <a href='$msrdErrorfileurl' target='_blank'>MSRD-Collect-Error</a> for more information." -circle "red"
            msrdLogDiag DiagFileOnly -Type "Spacer"
        }

        msrdGetDCInfo

    } else {
        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "This machine is not joined to a domain." -circle "red"
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

#endregion AD functions


#region Networking functions

Function msrdGetDNSInfo {

    Try {
        $dnsip = Get-DnsClientServerAddress -AddressFamily IPv4
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Local network interface DNS configuration:"
        foreach ($entry in $dnsip) {
            if (!($entry.InterfaceAlias -like "Loopback*")) {
                $ip = $entry.ServerAddresses
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($entry.InterfaceAlias)" -Message3 "$ip" -circle "blue"
            }
        }
    } Catch {
        $failedCommand = $_.InvocationInfo.Line.TrimStart()
        $errorMessage = $_.Exception.Message.TrimStart()
        msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
        if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
        } else {
            msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
        }
        Continue
    }

    Try {
        msrdLogDiag DiagFileOnly -Type "Spacer"
        $vmdomain = [System.Directoryservices.Activedirectory.Domain]::GetComputerDomain()
        $dcdns = $vmdomain | ForEach-Object {$_.DomainControllers} |
            ForEach-Object {
                $hostEntry= [System.Net.Dns]::GetHostByName($_.Name)
                New-Object -TypeName PSObject -Property @{
                        Name = $_.Name
                        IPAddress = $hostEntry.AddressList[0].IPAddressToString
                    }
                } | Select-Object Name, IPAddress

        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "DNS servers available in the domain '$($vmdomain.Name)':"
        foreach ($dcentry in $dcdns) {
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($dcentry.Name)" -Message3 "$($dcentry.IPAddress)"
        }

        msrdLogDiag DiagFileOnly -Type "Spacer"
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

Function msrdDiagDNS {

    #DNS diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "DNS"
    $menucatmsg = "Networking"
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "DNSCheck"

    msrdGetDNSInfo

    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\' 'EnableNetbios' '' 'Computer Policy: Configure NetBIOS settings'

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdGetFirewallInfo {

    msrdCheckServicePort -service mpssvc

    msrdLogDiag DiagFileOnly -Type "Spacer"
    $FWProfiles = Get-NetFirewallProfile -PolicyStore ActiveStore

    if (Test-Path ($global:msrdLogDir + $fwrfile)) {
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Windows Firewall profiles:" -Message2 "(See: <a href='$fwrfile' target='_blank'>FirewallRules</a>)" -circle "blue"
    } else {
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Windows Firewall profiles:"
    }

    $FWProfiles | ForEach-Object -Process {
        If ($_.Enabled -eq "True") {
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($_.Name) profile" -Message3 "Enabled" -circle "green"
        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($_.Name) profile" -Message3 "Disabled" -circle "red"
        }
    }

    Try {
        msrdLogDiag DiagFileOnly -Type "HR"
        $3fw = Get-CimInstance -NameSpace "root\SecurityCenter2" -Query "select * from FirewallProduct" -ErrorAction SilentlyContinue
        if ($3fw) {
            foreach ($3fwentry in $3fw) {
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Third party firewall found: $($3fwentry.displayName)" -circle "blue"
            }
        } else {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Third party firewall(s) <span style='color: brown'>not found</span>" -circle "white"
        }

    } Catch {
        $failedCommand = $_.InvocationInfo.Line.TrimStart()
        $errorMessage = $_.Exception.Message.TrimStart()
        msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
        if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
        } else {
            msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
        }

        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "An error occurred while trying to retrieve third party firewall information. See <a href='$msrdErrorfileurl' target='_blank'>MSRD-Collect-Error</a> for more information." -circle "red"
        Continue
    }
}

Function msrdDiagFirewall {

    #Firewall diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Firewall"
    $menucatmsg = "Networking"
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "FWCheck"

    msrdGetFirewallInfo

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagProxyRoute {

    #Proxy diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Proxy / Route"
    $menucatmsg = "Networking"
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "ProxyCheck"

    $binval = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name WinHttpSettings).WinHttPSettings
    $proxylength = $binval[12]
    if ($proxylength -gt 0) {
        $proxy = -join ($binval[(12+3+1)..(12+3+1+$proxylength-1)] | ForEach-Object {([char]$_)})
        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "NETSH WINHTTP proxy is configured" -Message2 "$proxy" -circle "red"
        $bypasslength = $binval[(12+3+1+$proxylength)]

        if ($bypasslength -gt 0) {
            $bypasslist = -join ($binval[(12+3+1+$proxylength+3+1)..(12+3+1+$proxylength+3+1+$bypasslength)] | ForEach-Object {([char]$_)})
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Bypass list:" -Message2 "$bypasslist" -circle "red"
        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Bypass list:" -Message2 "<span style='color:red'>Not configured</span>" -circle "red"
        }
    } else {
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "NETSH WINHTTP proxy configuration" -Message2 "not found"
    }

    msrdLogDiag DiagFileOnly -Type "HR"

    function GetBitsadmin {
        Param([string]$batype)

        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Device-wide IE proxy configuration ($batype)"
        $commandline = "bitsadmin /util /getieproxy $batype"
        $out = Invoke-Expression -Command $commandline
        foreach ($outopt in $out) {
            if (($outopt -like "*Proxy usage:*") -or ($outopt -like "*Auto discovery script URL:*") -or ($outopt -like "*Proxy list:*") -or ($outopt -like "*Proxy bypass:*")) {
                $p1 = $outopt.Split(":")[0]
                $p2 = $outopt.Trim($p1 + ": ")
                if ($p2 -like "*AUTODETECT*") {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 ($p1 + ":") -Message3 "$p2" -circle "blue"
                } else {
                    msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 ($p1 + ":") -Message3 "$p2" -circle "red"
                }
            }
        }
    }

    GetBitsadmin "LOCALSYSTEM"
    GetBitsadmin "NETWORKSERVICE"
    GetBitsadmin "LOCALSERVICE"

    msrdLogDiag DiagFileOnly -Type "HR"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\' 'ProxyEnable'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\' 'ProxyServer' '' '' '' 'AddWarning'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\' 'ProxyOverride'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\' 'AutoConfigURL' '' '' '' 'AddWarning'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\' 'WinHttpSettings'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\' 'ProxyEnable'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\' 'ProxyServer' '' '' '' 'AddWarning'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\' 'ProxyOverride'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\' 'AutoConfigURL' '' '' '' 'AddWarning'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\' 'DefaultConnectionSettings'
    msrdCheckRegKeyValue 'HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\' 'ProxyEnable'
    msrdCheckRegKeyValue 'HKU:\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\' 'DefaultConnectionSettings'

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\' 'ProxySettings' '' 'Computer Policy: Configure address or URL of proxy server'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Edge\' 'ProxySettings' '' 'User Policy: Configure address or URL of proxy server'

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation\' 'DProxiesAuthoritive' '' 'Computer Policy: Proxy definitions are authoritative'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation\' 'DomainProxies' '' 'Computer Policy: Internet proxy servers for apps'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation\' 'DomainLocalProxies' '' 'Computer Policy: Intranet proxy servers for apps'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkIsolation\' 'CloudResources' '' 'Computer Policy: Intranet proxy servers for apps'
    msrdCheckRegKeyValue 'HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\' 'force_Tunneling' '' 'Computer Policy: Enterprise resource domains hosted in the cloud'

    msrdLogDiag DiagFileOnly -Type "HR"
    try {
        $WSProxy = New-object System.Net.WebProxy
        $WSWebSession = new-object Microsoft.PowerShell.Commands.WebRequestSession
        $WSWebSession.Proxy = $WSProxy
        $WSWebSession.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        $ZScalerTest = Invoke-WebRequest -Uri "https://ip.zscaler.com" -WebSession $WSWebSession -UseBasicParsing -TimeoutSec 30

        if ($ZScalerTest) {
            $html = New-Object -ComObject "HTMLFile"
            Try {
                $html.IHTMLDocument2_write($ZScalerTest.Content)
            } catch {
                $src = [System.Text.Encoding]::Unicode.GetBytes($ZScalerTest.Content)
                $html.write($src)
            }
            $ZScalerResponse = ($html.getElementsByTagName('div') | Where-Object {$_.className -eq 'headline'}).innerText
            $ZScalerDetails = ($html.getElementsByTagName('div') | Where-Object {$_.className -eq 'details'}).innerText
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "ZScaler information (based on <a href='https://ip.zscaler.com' target='_blank'>https://ip.zscaler.com</a>):"
            if ($ZscalerResponse -like "*you are not going through the Zscaler proxy service*") {
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$ZScalerResponse" -circle "green"
            } else {
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$ZScalerResponse" -circle "red"
            }
            $zs = $false
            foreach ($Zitem in $ZScalerDetails) {
                if ($Zitem -like "*You are accessing the Internet via Zscaler*") {
                    $global:msrdSetWarning = $true
                    $zs = $true
                    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$Zitem" -circle "red"
                } else {
                    if ($zs) {
                        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$Zitem" -circle "red"
                    } else {
                        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$Zitem" -circle "green"
                    }
                }
            }

        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "ZScaler information (based on <a href='https://ip.zscaler.com' target='_blank'>https://ip.zscaler.com</a>) could not be retrieved." -circle "red"
        }
    } Catch {
        $failedCommand = $_.InvocationInfo.Line.TrimStart()
        $errorMessage = $_.Exception.Message.TrimStart()
        msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
        if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
        } else {
            msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
        }

        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "An error occurred during the ZScaler usage check. See <a href='$msrdErrorfileurl' target='_blank'>MSRD-Collect-Error</a> for more information." -circle "red"
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }


}

Function msrdDiagPublicIP {

    #Public IP address diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Public IP"
    $menucatmsg = "Networking"
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "PublicIPCheck"

    try {
        $WSProxy = New-object System.Net.WebProxy
        $WSWebSession = new-object Microsoft.PowerShell.Commands.WebRequestSession
        $WSWebSession.Proxy = $WSProxy
        $WSWebSession.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        $pubip = Invoke-RestMethod -Uri "https://ipinfo.io/json" -Method Get -WebSession $WSWebSession -TimeoutSec 30

        if ($pubip) {
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Public IP:" -Message2 "$($pubip.ip)"
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "City/Region:" -Message2 "$($pubip.city)/$($pubip.region)"
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Country:" -Message2 "$($pubip.country)"
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Organization:" -Message2 "$($pubip.org)"
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Timezone:" -Message2 "$($pubip.timezone)"
        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Public IP information could not be retrieved." -circle "red"
        }

    } Catch {
        $failedCommand = $_.InvocationInfo.Line.TrimStart()
        $errorMessage = $_.Exception.Message.TrimStart()
        msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
        if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
        } else {
            msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
        }

        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Public IP information could not be retrieved. See <a href='$msrdErrorfileurl' target='_blank'>MSRD-Collect-Error</a> for more information." -circle "red"
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagVPN {

    #VPN diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "VPN"
    $menucatmsg = "Networking"
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "VPNCheck"

    try {
        $vpn = Get-VpnConnection -ErrorAction Continue 2>>$global:msrdErrorLogFile
        if ($vpn) {
            foreach ($v in $vpn) {
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Name:" -Message2 "$($v.Name)"
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "ServerAddress:" -Message2 "$($v.ServerAddress)"
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "DnsSuffix:" -Message2 "$($v.DnsSuffix)"
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Guid:" -Message2 "$($v.Guid)"
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "ConnectionStatus:" -Message2 "$($v.ConnectionStatus)" -circle "blue"
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "RememberCredentials:" -Message2 "$($v.RememberCredential)"
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "SplitTunneling:" -Message2 "$($v.SplitTunneling)"
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "IdleDisconnectSeconds:" -Message2 "$($v.IdleDisconnectSeconds)" -circle "blue"
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "PlugInApplicationID:" -Message2 "$($v.PlugInApplicationID)"
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "ProfileType:" -Message2 "$($v.ProfileType)"
                if ($v.Proxy -and ($v.Proxy -ne "")) {
                    msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Proxy:" -Message2 "$($v.Proxy)" -circle "blue"
                } else {
                    msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "Proxy:" -Message2 "$($v.Proxy)"
                }
            }
        } else {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "VPN connection profile information <span style='color: brown'>not found</span>"
        }

    } Catch {
        $failedCommand = $_.InvocationInfo.Line.TrimStart()
        $errorMessage = $_.Exception.Message.TrimStart()
        msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
        if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
        } else {
            msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
        }

        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "VPN information could not be retrieved. See <a href='$msrdErrorfileurl' target='_blank'>MSRD-Collect-Error</a> for more information." -circle "red"
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

#endregion Networking functions


#region Logon/Security functions

Function msrdDiagAuth {

    #Authentication/Logon diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Authentication / Logon"
    $menucatmsg = "Logon / Security"
    msrdLogDiag Normal -DiagTag "AuthCheck" -Message $menuitemmsg

    msrdLogDiag DiagFileOnly -Type "Table1-2" -Message "User context:" -Message2 "$global:msrdUserprof"

    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI') {
        if (msrdTestRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\' -Value 'LastLoggedOnProvider') {
            $logonprov = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -name "LastLoggedOnProvider"
            $credprovpath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$logonprov"
            if (Test-Path $credprovpath) {
                $credprov = Get-ItemPropertyValue -Path $credprovpath -name "(Default)"
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Last Logged On Credential Provider used:" -Message2 "$credprov"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Last Logged On Credential Provider used:" -Message2 "<span style='color: brown'>not found</span>"
            }
        }
    }

    msrdLogDiag DiagFileOnly -Type "HR"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Terminal Server Client\' 'DisableWebAuthnRedirection'

    if (!($global:msrdSource)) {
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDisableWebAuthn' '0' 'Computer Policy: Do not allow WebAuthn redirection'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fEnableRdsAadAuth'
    }

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\' 'MaxTokenSize'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' 'AppSetup'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' 'AutoAdminLogon'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' 'ForceAutoLogon'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' 'ScreenSaverGracePeriod'
    

    if (!($global:msrdSource)) {
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\' 'ProcessTSUserLogonAsync' '' 'Computer Policy: Allow asynchronous user Group Policy processing when logging on through Remote Desktop Services'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fQueryUserConfigFromDC'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fQueryUserConfigFromLocalMachine'
    }

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\' 'AllowDefaultCredentials' '' 'Computer Policy: Allow delegating default credentials'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\' 'AllowDefCredentialsWhenNTLMOnly' '' 'Computer Policy: Allow delegating default credentials with NTLM-only server authentication'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\' 'DenyDefaultCredentials' '' 'Computer Policy: Deny delegating default credentials'
    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\' 'AllowSavedCredentials' '' 'Computer Policy: Allow delegating saved credentials'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\' 'AllowSavedCredentialsWhenNTLMOnly' '' 'Computer Policy: Allow delegating saved credentials with NTLM-only server authentication'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\' 'DenySavedCredentials' '' 'Computer Policy: Deny delegating saved credentials'

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }


}

Function msrdGetAntivirusInfo {

    #get Antivirus information
    Try {
        $AVprod = (Get-CimInstance -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ErrorAction SilentlyContinue).displayName

        if ($AVprod) {
            if (Test-Path ($global:msrdLogDir + $avinfofile)) {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message "Antivirus software:" -Message3 "(See: <a href='$avinfofile' target='_blank'>AntiVirusProducts</a>)" -circle "blue"
            } else {
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Antivirus software:"
            }
            foreach ($AVPentry in $AVprod) {
                msrdLogDiag DiagFileOnly -Type "Table1-2" -Message2 "$AVPentry" -circle "blue"
            }
        } else {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Antivirus software <span style='color: brown'>not found</span>."
        }

    } Catch {
        $failedCommand = $_.InvocationInfo.Line.TrimStart()
        $errorMessage = $_.Exception.Message.TrimStart()
        msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
        if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
        } else {
            msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
        }

        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "An error occurred while trying to retrieve Antivirus information. See <a href='$msrdErrorfileurl' target='_blank'>MSRD-Collect-Error</a> for more information." -circle "red"
        Continue
    }

    If (!($global:msrdOSVer -like "*Server*2008*")) {
        $DefPreference = Get-MpPreference | Select-Object DisableAutoExclusions, RandomizeScheduleTaskTimes, SchedulerRandomizationTime, ProxyServer, ProxyPacUrl, ProxyBypass, ForceUseProxyOnly, ScanScheduleTime, ScanScheduleQuickScanTime, ScanOnlyIfIdleEnabled
        if ($DefPreference) {
            msrdLogDiag DiagFileOnly -Type "Spacer"

            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Defender settings:"
            msrdLogDiag DiagFileOnly -Type "Table1-3"  -Message2 "DisableAutoExclusions" -Message3 "$($DefPreference.DisableAutoExclusions)" -circle "blue"
            msrdLogDiag DiagFileOnly -Type "Table1-3"  -Message2 "RandomizeScheduleTaskTimes" -Message3 "$($DefPreference.RandomizeScheduleTaskTimes)" -circle "blue"
            msrdLogDiag DiagFileOnly -Type "Table1-3"  -Message2 "SchedulerRandomizationTime" -Message3 "$($DefPreference.SchedulerRandomizationTime)" -circle "blue"

            if ($DefPreference.ProxyServer) {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "ProxyServer" -Message3 "$($DefPreference.ProxyServer)" -circle "blue"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "ProxyServer" -Message3 "$($DefPreference.ProxyServer)"
            }

            if ($DefPreference.ProxyPacUrl) {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "ProxyPacUrl" -Message3 "$($DefPreference.ProxyPacUrl)" -circle "blue"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "ProxyPacUrl" -Message3 "$($DefPreference.ProxyPacUrl)"
            }

            if ($DefPreference.ProxyBypass) {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "ProxyBypass" -Message3 "$($DefPreference.ProxyBypass)" -circle "blue"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "ProxyBypass" -Message3 "$($DefPreference.ProxyBypass)"
            }

            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "ForceUseProxyOnly" -Message3 "$($DefPreference.ForceUseProxyOnly)" -circle "blue"
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "ScanScheduleTime" -Message3 "$($DefPreference.ScanScheduleTime)" -circle "blue"
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "ScanScheduleQuickScanTime" -Message3 "$($DefPreference.ScanScheduleQuickScanTime)" -circle "blue"
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "ScanOnlyIfIdleEnabled" -Message3 "$($DefPreference.ScanOnlyIfIdleEnabled)" -circle "blue"
        }
    }
}

function msrdGetUserRights {

    #get User Rights policy information
    [array]$localrights = $null

    function msrdGet-SecurityPolicy {

        # Fail script if we can't find SecEdit.exe
        $SecEdit = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) "SecEdit.exe"
        if (-not (Test-Path $SecEdit)) {
            msrdLogException ("File not found - '$SecEdit'") -ErrObj $_ $fLogFileOnly
            return
        }
        # LookupPrivilegeDisplayName Win32 API doesn't resolve logon right display names, so use this hashtable
        $UserLogonRights = @{
"SeBatchLogonRight"				    = "Log on as a batch job"
"SeDenyBatchLogonRight"			    = "Deny log on as a batch job"
"SeDenyInteractiveLogonRight"	    = "Deny log on locally"
"SeDenyNetworkLogonRight"		    = "Deny access to this computer from the network"
"SeDenyRemoteInteractiveLogonRight" = "Deny log on through Remote Desktop Services"
"SeDenyServiceLogonRight"		    = "Deny log on as a service"
"SeInteractiveLogonRight"		    = "Allow log on locally"
"SeNetworkLogonRight"			    = "Access this computer from the network"
"SeRemoteInteractiveLogonRight"	    = "Allow log on through Remote Desktop Services"
"SeServiceLogonRight"			    = "Log on as a service"
}

        # Create type to invoke LookupPrivilegeDisplayName Win32 API
        $Win32APISignature = @'
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool LookupPrivilegeDisplayName(
string systemName,
string privilegeName,
System.Text.StringBuilder displayName,
ref uint cbDisplayName,
out uint languageId
);
'@

        $AdvApi32 = Add-Type advapi32 $Win32APISignature -Namespace LookupPrivilegeDisplayName -PassThru

        # Use LookupPrivilegeDisplayName Win32 API to get display name of privilege (except for user logon rights)

        function msrdGet-PrivilegeDisplayName {
        param ([String]$name)

            $displayNameSB = New-Object System.Text.StringBuilder 1024
            $languageId = 0
            $ok = $AdvApi32::LookupPrivilegeDisplayName($null, $name, $displayNameSB, [Ref]$displayNameSB.Capacity, [Ref]$languageId)

            if ($ok) { $displayNameSB.ToString() }
            else {
                # Doesn't lookup logon rights, so use hashtable for that
                if ($UserLogonRights[$name]) { $UserLogonRights[$name] }
                else { $name }
            }
        }

        # Outputs list of hashtables as a PSObject
        function msrdOut-Object {
        param ([System.Collections.Hashtable[]]$hashData)

            $order = @()
            $result = @{ }
            $hashData | ForEach-Object {
                $order += ($_.Keys -as [Array])[0]
                $result += $_
            }

            $out = New-Object PSObject -Property $result | Select-Object $order
            return $out
        }

        # Translates a SID in the form *S-1-5-... to its account name;
        function msrdGet-AccountName {
        param ([String]$principal)

            try {
                $sid = New-Object System.Security.Principal.SecurityIdentifier($principal.Substring(1))
                $sid.Translate([Security.Principal.NTAccount])
            } catch { $principal }
        }

        $TemplateFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
        $LogFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
        $StdOut = & $SecEdit /export /cfg $TemplateFilename /areas USER_RIGHTS /log $LogFilename

        if ($LASTEXITCODE -eq 0) {
            $dtable = $null
            $dtable = New-Object System.Data.DataTable
            $dtable.Columns.Add("Privilege", "System.String") | Out-Null
            $dtable.Columns.Add("PrivilegeName", "System.String") | Out-Null
            $dtable.Columns.Add("Principal", "System.String") | Out-Null

            Select-String '^(Se\S+) = (\S+)' $TemplateFilename | Foreach-Object {
                $Privilege = $_.Matches[0].Groups[1].Value
                $Principals = $_.Matches[0].Groups[2].Value -split ','
                foreach ($Principal in $Principals) {
                    $nRow = $dtable.NewRow()
                    $nRow.Privilege = $Privilege
                    $nRow.PrivilegeName = msrdGet-PrivilegeDisplayName $Privilege
                    $nRow.Principal = msrdGet-AccountName $Principal
                    $dtable.Rows.Add($nRow)
                }
                return $dtable
            }
        } else {
            msrdLogException ("$(msrdGetLocalizedText "errormsg") $StdOut") -ErrObj $_ $fLogFileOnly
        }
        Remove-Item $TemplateFilename, $LogFilename -ErrorAction SilentlyContinue
    }

    $localrights += msrdGet-SecurityPolicy
    $localrights = $localrights | Select-Object Privilege, PrivilegeName, Principal -Unique | Where-Object { ($_.Privilege -like "*NetworkLogonRight") -or ($_.Privilege -like "*RemoteInteractiveLogonRight")}

    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "User Rights policies:"
    Foreach ($LR in $localrights) {
        if (!($LR -like "Privilege*")) {
            $lrprincipal = $LR.Principal
            $lrprivilege = $LR.Privilege
            if (($lrprivilege -like "*SeRemoteInteractiveLogonRight*") -and (($lrprincipal -like "*BUILTIN\Remote Desktop Users*") -or ($lrprincipal -like "*BUILTIN\Administrators*") -or ($lrprincipal -like "*VORDEFINIERT\Administratoren*") -or ($lrprincipal -like "*VORDEFINIERT\Remotedesktopbenutzer*"))) {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($LR.PrivilegeName) ($lrprivilege)" -Message3 "$lrprincipal" -circle "green"
            } elseif (($lrprivilege -like "*SeDenyRemoteInteractiveLogonRight*") -and (($lrprincipal -like "*BUILTIN\Remote Desktop Users*") -or ($lrprincipal -like "*BUILTIN\Administrators*"))) {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($LR.PrivilegeName) ($lrprivilege)" -Message3 "$lrprincipal" -circle "red"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($LR.PrivilegeName) ($lrprivilege)" -Message3 "$lrprincipal" -circle "blue"
            }
        }
    }
}

Function msrdDiagSecurity {

    #Security diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Security"
    $menucatmsg = "Logon / Security"
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "SecCheck"

    msrdGetAntivirusInfo  #get antivirus software information

    if (!($global:msrdSource)) {
        msrdLogDiag DiagFileOnly -Type "HR"
        msrdGetUserRights  #get user rights policies information
    }

    msrdLogDiag DiagFileOnly -Type "HR"

    if ($global:msrdOSVer -like "*Windows Server*") {
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\' 'DisableAntiSpyware' 'false'

        if (msrdTestRegistryValue -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\" -value "DisableAntiSpyware") {
            $key = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\" -name "DisableAntiSpyware"
            if ($key -eq "true") {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "It is not recommended to disable Windows Defender, unless you are using another Antivirus software. See: $defenderRef" -circle "red"
            }
        }
    }

    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' 'ImpersonateCheckProtection' '' '' '' 'AddWarning'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' 'DisableRestrictedAdmin'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' 'LmCompatibilityLevel'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' 'RestrictRemoteSam'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' 'RestrictRemoteSamAuditOnlyMode'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' 'DisableLockWorkstation' '' 'Computer Policy: Remove Lock Computer'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters\' 'AllowEncryptionOracle' '' 'Computer Policy: Encryption Oracle Remediation'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\' 'SupportedEncryptionTypes' '' 'Network security: Configure encryption types allowed for Kerberos' '' 'AddWarning'

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\' 'EnableVirtualizationBasedSecurity' '' 'Computer Policy: Turn On Virtualization Based Security (Device Guard)'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\' 'LsaCfgFlags' '' 'Computer Policy: Turn On Virtualization Based Security (Device Guard)'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\' 'RequirePlatformSecurityFeatures' '' 'Computer Policy: Turn On Virtualization Based Security (Device Guard)'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\' 'EnableVirtualizationBasedSecurity'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\' 'RequirePlatformSecurityFeatures'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' 'LsaCfgFlags'

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\' 'RestrictedRemoteAdministration' '' 'Computer Policy: Restrict delegation of credentials to remote servers'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\' 'RestrictedRemoteAdministrationType' '' 'Computer Policy: Restrict delegation of credentials to remote servers'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\' 'DisableRestrictedAdmin'

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\' 'AuditReceivingNTLMTraffic' '' 'Computer Policy: Network security: Restrict NTLM: Audit Incoming NTLM Traffic'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\' 'ClientAllowedNTLMServers' '' 'Computer Policy: Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication' '' 'AddWarning'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\' 'RestrictReceivingNTLMTraffic' '' 'Computer Policy: Network security: Restrict NTLM: Incoming NTLM traffic' '' 'AddWarning'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\' 'RestrictSendingNTLMTraffic' '' 'Computer Policy: Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' '' 'AddWarning'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\' 'AuditNTLMInDomain' '' 'Computer Policy: Network security: Restrict NTLM: Audit NTLM authentication in this domain'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\' 'DCAllowedNTLMServers' '' 'Computer Policy: Network security: Restrict NTLM: Add server exceptions in this domain' '' 'AddWarning'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\' 'RestrictNTLMInDomain' '' 'Computer Policy: Network security: Restrict NTLM: NTLM authentication in this domain' '' 'AddWarning'

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Browser\' 'AllowSmartScreen'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\device\Browser\AllowSmartScreen\' 'value'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\SmartScreen\EnableSmartScreenInShell\' 'value'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\' 'SmartScreenEnabled'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\' 'SmartScreenEnabled' '' 'Computer Policy: Configure Microsoft Defender SmartScreen'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Edge\' 'SmartScreenEnabled' '' 'User Policy: Configure Microsoft Defender SmartScreen'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\' 'EnableSmartScreen' '' 'Computer Policy: Configure Windows Defender SmartScreen'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Edge\' 'SmartScreenEnabled'

    if ($global:msrdAVD) {
        msrdLogDiag DiagFileOnly -Type "Spacer"
        if ($avdcheck) {
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fEnableScreenCaptureProtect' '' 'Computer Policy: Enable screen capture protection'
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fEnableWatermarking' '' 'Computer Policy: Enable watermarking'
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'WatermarkingHeightFactor' '' 'Computer Policy: Enable watermarking'
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'WatermarkingOpacity' '' 'Computer Policy: Enable watermarking'
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'WatermarkingQrScale' '' 'Computer Policy: Enable watermarking'
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'WatermarkingWidthFactor' '' 'Computer Policy: Enable watermarking'
        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$avdcheckmsg" -circle "red"
        }
    }

    msrdLogDiag DiagFileOnly -Type "HR"
    msrdCheckServicePort -service AppIDSvc

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

#endregion Logon/Security functions


#region Known Issues

Function msrdDiagIssues {
    Param([Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string]$IssueType, [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string]$LogName,
        [array]$LogID, [array]$Message, [array]$Provider, [string]$lvl, [string]$helpurl, [string]$helpurlmsg, [string]$evtxfile)

    #diagnostics of potential issues showing up in Event logs (based on messages)
    if ($lvl -eq "Full") { $evlvl = @(1,2,3,4) } else { $evlvl = @(1,2,3) }

    msrdLogDiag Info -Message "[Diag] '$IssueType' issues in '$LogName' event logs"

    $StartTimeA = (Get-Date).AddDays(-5)
    if ($LogID) { $geteventDiag = Get-WinEvent -FilterHashtable @{logname="$LogName"; id=$LogID; StartTime=$StartTimeA; Level=$evlvl} -ErrorAction SilentlyContinue }
    else { $geteventDiag = Get-WinEvent -FilterHashtable @{logname="$LogName"; StartTime=$StartTimeA; Level=$evlvl} -ErrorAction SilentlyContinue }

    if ($IssueType -eq "Agent") { $issuefile = "MSRD-Diag-AgentIssues.txt" }
    elseif ($IssueType -eq "MSIXAA") { $issuefile = "MSRD-Diag-MSIXAAIssues.txt" }
    elseif ($IssueType -eq "FSLogix") { $issuefile = "MSRD-Diag-FSLogixIssues.txt" }
    elseif ($IssueType -eq "Shortpath") { $issuefile = "MSRD-Diag-ShortpathIssues.txt" }
    elseif ($IssueType -eq "Crash") { $issuefile = "MSRD-Diag-Crashes.txt" }
    elseif ($IssueType -eq "ProcessHang") { $issuefile = "MSRD-Diag-ProcessHangs.txt" }
    elseif ($IssueType -eq "BlackScreen") { $issuefile = "MSRD-Diag-PotentialBlackScreens.txt" }
    elseif ($IssueType -eq "TCP") { $issuefile = "MSRD-Diag-TCPIssues.txt" }
    elseif ($IssueType -eq "RDLicensing") { $issuefile = "MSRD-Diag-RDLicensingIssues.txt" }
    elseif ($IssueType -eq "RDGateway") { $issuefile = "MSRD-Diag-RDGatewayIssues.txt" }

    $exportfile = $global:msrdBasicLogFolder + $issuefile
    $issuefileurl = $global:msrdLogFilePrefix + $issuefile
    $issuefiledisp = $issuefile.Split("-")[2].Split(".")[0]
    $issuefilelink = "<a href='$issuefileurl' target='_blank'>$issuefiledisp</a>"
    
    $evtxfileurl = $global:msrdLogDir + $evtxfile
    $evtxfilelink = "<a href='$evtxfileurl' target='_blank'>$LogName Event Logs</a>"

    $pad = 13
    $counter = 0

    If ($geteventDiag) {
        if ($Message) {
            foreach ($eventItem in $geteventDiag) {
                foreach ($msg in $Message) {
                    if ($eventItem.Message -like "*$msg*") {
                        $counter = $counter + 1
                        "TimeCreated".PadRight($pad) + " : " + $eventItem.TimeCreated 2>&1 | Out-File -Append ($exportfile)
                        "EventLog".PadRight($pad) + " : " + $LogName 2>&1 | Out-File -Append ($exportfile)
                        "ProviderName".PadRight($pad) + " : " + $eventItem.ProviderName 2>&1 | Out-File -Append ($exportfile)
                        "Id".PadRight($pad) + " : " + $eventItem.Id 2>&1 | Out-File -Append ($exportfile)
                        "Level".PadRight($pad) + " : " + $eventItem.LevelDisplayName 2>&1 | Out-File -Append ($exportfile)
                        "Message".PadRight($pad) + " : " + $eventItem.Message 2>&1 | Out-File -Append ($exportfile)
                        "" 2>&1 | Out-File -Append ($exportfile)
                    }
                }
            }
        }

        if ($Provider) {
            foreach ($eventItem in $geteventDiag) {
                foreach ($prv in $Provider) {
                    if ($eventItem.ProviderName -eq $prv) {
                        $counter = $counter + 1
                        "TimeCreated".PadRight($pad) + " : " + $eventItem.TimeCreated 2>&1 | Out-File -Append ($exportfile)
                        "EventLog".PadRight($pad) + " : " + $LogName 2>&1 | Out-File -Append ($exportfile)
                        "ProviderName".PadRight($pad) + " : " + $eventItem.ProviderName 2>&1 | Out-File -Append ($exportfile)
                        "Id".PadRight($pad) + " : " + $eventItem.Id 2>&1 | Out-File -Append ($exportfile)
                        "Level".PadRight($pad) + " : " + $eventItem.LevelDisplayName 2>&1 | Out-File -Append ($exportfile)
                        "Message".PadRight($pad) + " : " + $eventItem.Message 2>&1 | Out-File -Append ($exportfile)
                        "" 2>&1 | Out-File -Append ($exportfile)
                    }
                }
            }
        }
    }

    if ($counter -gt 0) {
        $global:msrdSetWarning = $true
        if ($evtxfile) {
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message ($IssueType + ":") -Message2 "Issues found in the '$LogName' event logs" -Message3 "(See: $issuefilelink / $evtxfilelink)" -circle "red"
        } else {
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message ($IssueType + ":") -Message2 "Issues found in the '$LogName' event logs" -Message3 "(See: $issuefilelink)" -circle "red"
        }
        if ($helpurl) {
            msrdLogDiag DiagFileOnly -Type "Table1-2" -Message2 "See <a href='$helpurl' target='_blank'>$helpurlmsg</a> for potential solutions" -circle "red"
        }
    } else {
        msrdLogDiag DiagFileOnly -Type "Table1-2" -Message ($IssueType + ":") -Message2 "No known issues found in the '$LogName' event logs" -circle "green"
    }

    [System.GC]::Collect()
}

function msrdDiagAVDIssueEvents {

    #AVD events issues
    $global:msrdSetWarning = $false
    $menuitemmsg = "Issues found in Event Logs over the past 5 days"
    $menucatmsg = "Known Issues"
    if ($avdcheck) {
        msrdDiagIssues -IssueType 'Agent' -LogName 'Application' -LogID @(3019,3277,3389,3703) -Message @('Transport received an exception','ENDPOINT_NOT_FOUND','INVALID_FORM','INVALID_REGISTRATION_TOKEN','NAME_ALREADY_REGISTERED','DownloadMsiException','InstallationHealthCheckFailedException','InstallMsiException','AgentLoadException','BootLoader exception','Unable to retrieve DefaultAgent from registry','MissingMethodException','RD Gateway Url') -lvl 'Full' -helpurl $avdTsgRef -helpurlmsg 'Troubleshoot common Azure Virtual Desktop Agent issues' -evtxfile $script:aplevtxfile
        msrdDiagIssues -IssueType 'Agent' -LogName 'RemoteDesktopServices' -LogID @(0) -Message @('IMDS not accessible','Monitoring Agent Launcher file path was NOT located','NOT ALL required URLs are accessible!','SessionHost unhealthy','Unable to connect to the remote server','Unhandled status [ConnectFailure] returned for url','System.ComponentModel.Win32Exception (0x80004005)','Unable to extract and validate Geneva URLs','PingHost: Could not PING url','Unable to locate running process') -lvl 'Full' -helpurl $avdTsgRef -helpurlmsg 'Troubleshoot common Azure Virtual Desktop Agent issues' -evtxfile $script:rdsevtxfile
        msrdDiagIssues -IssueType 'Shortpath' -LogName 'Microsoft-Windows-RemoteDesktopServices-RdpCoreCDV/Operational' -LogID @(135,226) -Message @('UDP Handshake Timeout','UdpEventErrorOnMtReqComplete') -lvl 'Full' -helpurl $spathTsgRef -helpurlmsg 'Troubleshoot RDP Shortpath for public networks'
        msrdDiagIssues -IssueType 'Shortpath' -LogName 'RemoteDesktopServices' -LogID @(0) -Message @('TURN check threw exception','TURN relay health check failed') -lvl 'Full' -evtxfile $script:rdsevtxfile -helpurl $spathTsgRef -helpurlmsg 'Troubleshoot RDP Shortpath for public networks'

        if ($global:WinVerBuild -lt 19041) {
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "MSIX App Attach requires Windows 10 Enterprise or Windows 10 Enterprise multi-session, version 20H2 or later. Skipping check for MSIX App Attach issues (not applicable)." -circle "white"
        } else {
            msrdDiagIssues -IssueType 'MSIXAA' -LogName 'RemoteDesktopServices' -LogID @(0) -Provider @('Microsoft.RDInfra.AppAttach.AgentAppAttachPackageListServiceImpl','Microsoft.RDInfra.AppAttach.AppAttachServiceImpl','Microsoft.RDInfra.AppAttach.SysNtfyServiceImpl','Microsoft.RDInfra.AppAttach.UserImpersonationServiceImpl','Microsoft.RDInfra.RDAgent.AppAttach.CimVolume','Microsoft.RDInfra.RDAgent.AppAttach.ImagedMsixExtractor','Microsoft.RDInfra.RDAgent.AppAttach.MsixProcessor','Microsoft.RDInfra.RDAgent.AppAttach.VhdVolume','Microsoft.RDInfra.RDAgent.AppAttach.VirtualDiskManager','Microsoft.RDInfra.RDAgent.Service.AppAttachHealthCheck', 'Microsoft.RDInfra.RDAgent.EtwReader.AppAttachProcessParser') -evtxfile $script:rdsevtxfile
        }

    } else {
        $global:msrdSetWarning = $true
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$avdcheckmsg" -circle "red"
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

function msrdDiagRDIssueEvents {

    #RD events issues
    $global:msrdSetWarning = $false
    $menuitemmsg = "Issues found in Event Logs over the past 5 days"
    $menucatmsg = "Known Issues"
    if (Test-path -path 'C:\Program Files\FSLogix\apps') {
        msrdDiagIssues -IssueType 'FSLogix' -LogName 'Microsoft-FSLogix-Apps/Admin' -Provider @('Microsoft-FSLogix-Apps') -helpurl $fslogixTsgRef -helpurlmsg 'Troubleshooting with Logging and Diagnostics'
        msrdDiagIssues -IssueType 'FSLogix' -LogName 'Microsoft-FSLogix-Apps/Operational' -Provider @('Microsoft-FSLogix-Apps') -helpurl $fslogixTsgRef -helpurlmsg 'Troubleshooting with Logging and Diagnostics'
        msrdDiagIssues -IssueType 'FSLogix' -LogName 'RemoteDesktopServices' -LogID @(0) -Message @('The disk detach may have invalidated handles','ErrorCode: 743') -lvl 'Full' -evtxfile $script:rdsevtxfile -helpurl $fslogixTsgRef -helpurlmsg 'Troubleshooting with Logging and Diagnostics'
        msrdDiagIssues -IssueType 'FSLogix' -LogName 'System' -LogID @(4) -Message @('The Kerberos client received a KRB_AP_ERR_MODIFIED error from the server') -lvl 'Full' -evtxfile $script:sysevtxfile -helpurl $fslogixTsgRef -helpurlmsg 'Troubleshooting with Logging and Diagnostics'
    } else {
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "FSLogix <span style='color: brown'>not found</span>. Skipping check for FSLogix issues (not applicable)." -circle "white"
    }

    msrdDiagIssues -IssueType 'BlackScreen' -LogName 'Application' -LogID @(4005) -Message @('The Windows logon process has unexpectedly terminated') -evtxfile $script:aplevtxfile
    msrdDiagIssues -IssueType 'BlackScreen' -LogName 'System' -LogID @(7011,10020) -Message @('was reached while waiting for a transaction response from the AppReadiness service','The machine wide Default Launch and Activation security descriptor is invalid') -evtxfile $script:sysevtxfile

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

function msrdDiagCommonIssueEvents {

    #common issues
    $global:msrdSetWarning = $false
    $menuitemmsg = "Issues found in Event Logs over the past 5 days"
    $menucatmsg = "Known Issues"
    msrdDiagIssues -IssueType 'Crash' -LogName 'Application' -LogID @(1000) -Message @('Faulting application name') -evtxfile $script:aplevtxfile
    msrdDiagIssues -IssueType 'Crash' -LogName 'System' -LogID @(41,6008) -Message @('The system rebooted without cleanly shutting down first','was unexpected') -evtxfile $script:sysevtxfile
    msrdDiagIssues -IssueType 'ProcessHang' -LogName 'Application' -LogID @(1002) -Message @('stopped interacting with Windows') -evtxfile $script:aplevtxfile
    msrdDiagIssues -IssueType 'TCP' -LogName 'System' -LogID @(4227) -Message @('TCP/IP failed to establish') -evtxfile $script:sysevtxfile

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

function msrdDiagRDLicensingIssueEvents {

    #RD Licensing issues
    $global:msrdSetWarning = $false
    $menuitemmsg = "Issues found in Event Logs over the past 5 days"
    $menucatmsg = "Known Issues"
    msrdDiagIssues -IssueType 'RDLicensing' -LogName 'System' -Provider @('Microsoft-Windows-TerminalServices-Licensing') -evtxfile $script:sysevtxfile
    msrdDiagIssues -IssueType 'RDLicensing' -LogName 'Microsoft-Windows-TerminalServices-Licensing/Admin'
    msrdDiagIssues -IssueType 'RDLicensing' -LogName 'Microsoft-Windows-TerminalServices-Licensing/Operational'

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

function msrdDiagRDGatewayIssueEvents {

    #RD Gateway issues
    $global:msrdSetWarning = $false
    $menuitemmsg = "Issues found in Event Logs over the past 5 days"
    $menucatmsg = "Known Issues"
    msrdDiagIssues -IssueType 'RDGateway' -LogName 'Microsoft-Windows-TerminalServices-Gateway/Admin'
    msrdDiagIssues -IssueType 'RDGateway' -LogName 'Microsoft-Windows-TerminalServices-Gateway/Operational'

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagLogonIssues {

    #potential Black Screen diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Potential Logon Issue Generators"
    $menucatmsg = "Known Issues"
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "BlackCheck"
    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Incorrect configuration of one or more of the below values can sometimes lead to logon issues like: black screen, delay, remote desktop window disappearing etc."
    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "When investigating such issues, also take into consideration the results of the 'Third party software' check below."
    msrdLogDiag DiagFileOnly -Type "HR"

    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\NetCache\' 'DisableFRAdminPin'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\NetCache\{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}\' 'DisableFRAdminPinByFolder' '' 'AppData(Roaming) folder redirection'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\NetCache\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\' 'DisableFRAdminPinByFolder' '' 'Desktop folder redirection'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\NetCache\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\' 'DisableFRAdminPinByFolder' '' 'Start Menu folder redirection'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\NetCache\{FDD39AD0-238F-46AF-ADB4-6C85480369C7}\' 'DisableFRAdminPinByFolder' '' 'Documents folder redirection'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\NetCache\{33E28130-4E1E-4676-835A-98395C3BC3BB}\' 'DisableFRAdminPinByFolder' '' 'Pictures folder redirection'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\NetCache\{4BD8D571-6D19-48D3-BE97-422220080E43}\' 'DisableFRAdminPinByFolder' '' 'Music folder redirection'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\NetCache\{18989B1D-99B5-455B-841C-AB7C74E4DDFC}\' 'DisableFRAdminPinByFolder' '' 'Videos folder redirection'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\NetCache\{1777F761-68AD-4D8A-87BD-30B759FA33DD}\' 'DisableFRAdminPinByFolder' '' 'Favorites folder redirection'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\NetCache\{56784854-C6CB-462b-8169-88E350ACB882}\' 'DisableFRAdminPinByFolder' '' 'Contacts folder redirection'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\NetCache\{374DE290-123F-4565-9164-39C4925E467B}\' 'DisableFRAdminPinByFolder' '' 'Downloads folder redirection'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\NetCache\{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}\' 'DisableFRAdminPinByFolder' '' 'Links folder redirection'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\NetCache\{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}\' 'DisableFRAdminPinByFolder' '' 'Searches folder redirection'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\NetCache\{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}\' 'DisableFRAdminPinByFolder' '' 'Saved Games folder redirection'

    msrdLogDiag DiagFileOnly -Type "HR"
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4340}\' 'IsInstalled'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'AVCHardwareEncodePreferred' '' 'Computer Policy: Configure H.264/AVC hardware encoding for Remote Desktop Connections'
    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata\' 'PreventDeviceMetadataFromNetwork' '' 'Computer Policy: Prevent device metadata retrieval from the Internet' '' 'AddWarning'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\' 'DenyDeviceClasses' '' 'Computer Policy: Prevent Installation of devices using drivers that match these device setup classes' '' 'AddWarning'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\' 'DenyDeviceIDs' '' 'Computer Policy: Prevent Installation of devices that match any of these device IDs' '' 'AddWarning'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\' 'DenyInstanceIDs' '' 'Computer Policy: Prevent Installation of devices that match any of these device instance IDs' '' 'AddWarning'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\' 'DenyRemovableDevices' '' 'Computer Policy: Prevent Installation of Removable Devices' '' 'AddWarning'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\' 'DenyUnspecified' '' 'Computer Policy: Prevent installation of devices not described by other policy settings' '' 'AddWarning'

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\' 'AppReadinessPreShellTimeoutMs'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' 'FirstLogonTimeout'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' 'DelayedDesktopSwitchTimeout'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' 'Shell' 'explorer.exe'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' 'ShellAppRuntime' 'ShellAppRuntime.exe'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' 'Userinit' 'C:\Windows\system32\userinit.exe,'

    if (Test-path -path 'C:\Program Files\FSLogix\apps') {
        if (($script:frxverstrip -lt $latestFSLogixVer) -and (!($script:frxverstrip -eq "unknown"))) {
            msrdLogDiag DiagFileOnly -Type "Spacer"
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "You are not using the latest available FSLogix release. Please consider updating. See: $fslogixRef" -circle "red"
        }
    }

    msrdLogDiag DiagFileOnly -Type "HR"
    msrdCheckServicePort -service AppXSvc

    msrdLogDiag DiagFileOnly -Type "HR"
    msrdCheckServicePort -service AppReadiness

    msrdLogDiag DiagFileOnly -Type "HR"
    $countreg = @('HKLM:\SOFTWARE\Microsoft\Windows Search\CrawlScopeManager\Windows\SystemIndex\DefaultRules', 'HKLM:\SOFTWARE\Microsoft\Windows Search\CrawlScopeManager\Windows\SystemIndex\WorkingSetRules')
    foreach ($creg in $countreg) {
        if (Test-Path -Path $creg) {
            $c = Get-ChildItem -Path $creg | Measure-Object | Select-Object -ExpandProperty Count
            if ($c -gt 5000) {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$creg" -Message2 "$c keys found" -circle "red"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$creg" -Message2 "$c keys found" -circle "blue"
            }
        } else {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message $creg -Message2 "not found"
        }
    }

    msrdLogDiag DiagFileOnly -Type "Spacer"
    $regFW = @('HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules', 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedInterfaces\IfIso\FirewallRules', 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules')
    foreach ($fwreg in $regFW) {
        if (Test-Path -Path $fwreg) {
            $valuesFW = Get-ItemProperty -Path $fwreg
            $valueCountFW = ($valuesFW | Get-Member -MemberType NoteProperty).Count
            if ($valueCountFW -gt 5000) {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$fwreg" -Message2 "$valueCountFW values found" -circle "red"
            } else {
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$fwreg" -Message2 "$valueCountFW values found" -circle "blue"
            }
        } else {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message $fwreg -Message2 "not found"
        }
    }
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\' 'DeleteUserAppContainersOnLogoff' '1'

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\DriverDatabase\DeviceIds\TS_INPT\TS_KBD\' 'termkbd.inf' -warnMissing
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\DriverDatabase\DeviceIds\TS_INPT\TS_MOU\' 'termmou.inf' -warnMissing

    if (!($global:msrdSource)) {
        if ($global:msrdAVD) {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\TERMINPUT_BUS\UMB\", "HKLM:\SYSTEM\CurrentControlSet\Enum\TERMINPUT_BUS_SXS\UMB\"
        } else {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\TERMINPUT_BUS\UMB\"
        }
        foreach ($regP in $regPath) {

            if (Test-Path -Path $regP) {
                if ($regP -eq "HKLM:\SYSTEM\CurrentControlSet\Enum\TERMINPUT_BUS\UMB\") {
                    $umbfile = "${computerName}_RegistryKeys\${computerName}_HKLM-System-CCS-Enum-TERMINPUT_BUS.txt"
                    $umbname = "TERMINPUT_BUS\UMB\"
                } elseif ($regP -eq "HKLM:\SYSTEM\CurrentControlSet\Enum\TERMINPUT_BUS_SXS\UMB\") {
                    $umbfile = "${computerName}_RegistryKeys\${computerName}_HKLM-System-CCS-Enum-TERMINPUT_BUS_SXS.txt"
                    $umbname = "TERMINPUT_BUS_SXS\UMB\"
                }

                $keyNames = Get-ChildItem -Path $regP -Name -ErrorAction Continue 2>>$global:msrdErrorLogFile

                if ($keyNames) {
                    $sessions = @{}
                    foreach ($keyName in $keyNames) {
                        $match = $keyName -match "^(\d+)&(\w+)&(\d+)&Session(\d+)(Keyboard|Mouse)(\d+)$"
                        if ($match) {
                            $sessionId = [int]$matches[4]
                            $deviceType = $matches[5]
                            $deviceId = [int]$matches[6]
                            if (!$sessions.ContainsKey($sessionId)) {
                                $sessions[$sessionId] = @{
                                    "keyboardIds" = @()
                                    "mouseIds" = @()
                                }
                            }
                            if ($deviceType -eq "Keyboard") {
                                $sessions[$sessionId]["keyboardIds"] += $deviceId
                            } elseif ($deviceType -eq "Mouse") {
                                $sessions[$sessionId]["mouseIds"] += $deviceId
                            }
                        } else {
                            $global:msrdSetWarning = $true
                            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Error retrieving information from '$keyName'" -circle "red"
                        }
                    }

                    msrdLogDiag DiagFileOnly -Type "Spacer"
                    if (Test-Path -Path $umbfile) {
                        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Count of keyboard and mouse entries per remote session under $regP" + ":" -Message2 "(See: <a href='$umbfile' target='_blank'>$umbname registry</a>)"
                    } else {
                        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Count of keyboard and mouse entries per remote session under $regP" + ":"
                    }
                
                    foreach ($session in $sessions.Keys) {
                        $keyboardCount = $sessions[$session]["keyboardIds"].Count
                        $mouseCount = $sessions[$session]["mouseIds"].Count
                        $msgwarn = $false
                        if ($keyboardCount -ne 1) {
                            $msgwarn = $true
                            $msgkeyboard = "Keyboard entries found: $keyboardCount (Expected: 1)"
                        } else {
                            $msgkeyboard = "Keyboard entries found: $keyboardCount"
                        }

                        if ($mouseCount -ne 1) {
                            $msgwarn = $true
                            $msgmouse = "Mouse entries found: $mouseCount (Expected: 1)"
                        } else {
                            $msgmouse = "Mouse entries found: $mouseCount"
                        }

                        if ($msgwarn) {
                            $global:msrdSetWarning = $true
                            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "Session ID: $session" -Message3 "$msgkeyboard<br>$msgmouse" -circle "red"
                        } else {
                            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "Session ID: $session" -Message3 "$msgkeyboard<br>$msgmouse" -circle "green"
                        }
                    }
                } else {
                    $global:msrdSetWarning = $true
                    msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "$regP found but Session Keyboard/Mouse information could not be retrieved. See <a href='$msrdErrorfileurl' target='_blank'>MSRD-Collect-Error</a> for more information." -circle "red"
                }
            } else {
                msrdLogDiag DiagFileOnly -Type "Spacer"
                msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$regP" -Message2 "not found"
            }
        }
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

#endregion Known Issues


#region Other

Function msrdDiagOffice {

    #Microsoft Office diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Office"
    $menucatmsg = "Other"
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "MSOCheck"

    $oversion = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\O365ProPlusRetail* -ErrorAction Continue 2>>$global:msrdErrorLogFile

    if ($oversion) {
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Office installation(s):"
        foreach ($oitem in $oversion) {
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($oitem.Displayname)" -Message3 "$($oitem.DisplayVersion)" -circle "blue"
        }

        msrdLogDiag DiagFileOnly -Type "HR"
        msrdCheckServicePort -service "ClickToRunSvc"

        msrdLogDiag DiagFileOnly -Type "HR"
        msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\common\' 'InsiderSlabBehavior' '2' 'Computer Policy: Show the option for Office Insider'
        msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\outlook\cached mode\' 'enable' '1'
        msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\outlook\cached mode\' 'syncwindowsetting' '1' 'Computer Policy: Cached Exchange Mode Sync Settings'
        msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\outlook\cached mode\' 'CalendarSyncWindowSetting' '1'
        msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\outlook\cached mode\' 'CalendarSyncWindowSettingMonths' '1'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate\' 'hideupdatenotifications' '1' 'Computer Policy: Hide Update Notifications'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate\' 'hideenabledisableupdates' '1' 'Computer Policy: Hide option to enable or disable updates'

    } else {
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Microsoft Office <span style='color: brown'>not found</span>. Skipping check (not applicable)."
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagOD {

    #Microsoft OneDrive diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "OneDrive"
    $menucatmsg = "Other"
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "MSODCheck"

    $ODM86 = "C:\Program Files (x86)\Microsoft OneDrive" + '\OneDrive.exe'
    $ODM = "C:\Program Files\Microsoft OneDrive" + '\OneDrive.exe'
    $ODU = "$ENV:localappdata" + '\Microsoft\OneDrive\OneDrive.exe'

    $ODM86test = Test-Path $ODM86
    $ODMtest = Test-Path $ODM
    $ODUtest = Test-Path $ODU

    if (($ODM86test) -or ($ODMtest) -or ($ODUtest)) {

        if ($ODMtest) {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "OneDrive installation ($ODM)" -Message2 "per-machine" -circle "blue"
        } elseif ($ODM86test) {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "OneDrive installation ($ODM86)" -Message2 "per-machine" -circle "blue"
        } else {
            $global:msrdSetWarning = $true
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "OneDrive installation ($ODU)" -Message2 "per-user" -circle "red"
        }

        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckServicePort -service "OneDrive Updater Service"

        msrdLogDiag DiagFileOnly -Type "HR"
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\OneDrive\' 'AllUsersInstall' '1'

        if (!($global:msrdSource)) {
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Profiles\' 'ConcurrentUserSessions' '0' 'Computer Policy: Allow concurrent user sessions'
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\FSLogix\Profiles\' 'ProfileType' '0' 'Computer Policy: Profile type'
            msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\FSLogix\ODFC\' 'VHDAccessMode' '0' 'Computer Policy: VHD access type'
        }

        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\' 'OneDrive'
        msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\' 'OneDrive'
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\' 'OneDrive'
        msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\' 'OneDrive'

        if (!($global:msrdSource)) {
            msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RailRunonce\' 'OneDrive'
        }

    } else {
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "OneDrive installation <span style='color: brown'>not found</span>."
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdDiagPrinting {

    #Printing diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Printing"
    $menucatmsg = "Other"
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "PrintCheck"

    msrdCheckServicePort -service spooler

    msrdLogDiag DiagFileOnly -Type "HR"
    $printlist = Get-Printer | Select-Object Name, DriverName -ErrorAction Continue 2>>$global:msrdErrorLogFile
    if ($printlist) {
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Printer(s):"
        foreach ($printitem in $printlist) {
            msrdLogDiag DiagFileOnly -Type "Table1-3" -Message2 "$($printitem.Name)" -Message3 "$($printitem.DriverName)"
        }
    } else {
        msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Printers <span style='color: brown'>not found</span>"
    }

    msrdLogDiag DiagFileOnly -Type "HR"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Providers\Client Side Rendering Print Provider\' 'RemovePrintersAtLogoff'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\' 'MaintainDefaultPrinter'
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC\' 'RpcNamedPipeAuthentication'
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\' 'RpcAuthnLevelPrivacyEnabled'

    msrdLogDiag DiagFileOnly -Type "Spacer"
    msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Microsoft\Terminal Server Client\' 'DisablePrinterRedirection' '0'
    msrdCheckRegKeyValue 'HKCU:\SOFTWARE\Microsoft\Terminal Server Client\' 'DisablePrinterRedirection' '0'

    if (!($global:msrdSource)) {
        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\' 'fDisableCpm' '0' 'Computer Policy: Do not allow client printer redirection'
        msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' 'fDisableCpm' '0'

        if ($global:msrdAVD) {
            if ($script:msrdListenervalue) {
                msrdCheckRegKeyValue ('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\' + $script:msrdListenervalue + '\') 'fDisableCpm' '0'
            } else {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Active AVD listener configuration not found" -circle "red"
            }
        }
    }

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

Function msrdProcessCheck {
    Param([Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string]$proc, [string]$intName, $sp1, $sp2)

    try {
        $check = Get-Process $proc -ErrorAction SilentlyContinue
        if ($check -eq $null) {
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$intName ($proc)" -Message2 "not found"
        } else {
            $vendor = (Get-Process $proc | Group-Object -Property Company).Name
            if (($vendor -eq $null) -or ($vendor -eq "")) { $vendor = "N/A" }
            $counter = (Get-Process $proc | Group-Object -Property ProcessName).Count
            $desc = (Get-Process $proc | Group-Object -Property Description).Name
            $path = (Get-Process $proc | Group-Object -Property Path).Name
            $prodver = (Get-Process $proc | Group-Object -Property ProductVersion).Name
            if (($desc -eq $null) -or ($desc -eq "")) { $desc = "N/A" }
            if (($prodver -eq $null) -or ($prodver -eq "")) { $prodver = "N/A" }
            $global:msrdSetWarning = $true
            if ($sp1) { msrdLogDiag DiagFileOnly -Type "Spacer" }
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$proc found running on this system in $counter instance(s)" -Message2 "$prodver" -circle "red"
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Company: $vendor - Description: $desc" -circle "red"
            msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "Path: $path" -circle "red"
            if ($sp2) { msrdLogDiag DiagFileOnly -Type "Spacer" }
        }
    } catch {
        $FailedCommand = $MyInvocation.Line.TrimStart()
        $ErrorMessage = $_.Exception.Message.TrimStart()
        msrdLogException ("$(msrdGetLocalizedText 'errormsg') $FailedCommand") -ErrObj $_ $fLogFileOnly
    }
}

Function msrdCheckRegPath {
    Param([Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string]$RegPath, [string]$OptNote)

    $isPath = Test-Path -path $RegPath
    if ($isPath) {
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$RegPath" -Message2 "found" -Title "$OptNote" -circle "red"
    }
    else {
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$RegPath" -Message2 "not found" -Title "$OptNote"
    }
}

Function msrdDiagCitrix3P {

    #Citrix and other 3rd party software diagnostics
    $global:msrdSetWarning = $false
    $menuitemmsg = "Third Party Software"
    $menucatmsg = "Other"
    msrdLogDiag Normal -Message $menuitemmsg -DiagTag "3pCheck"

    $CitrixProd = (Get-ItemProperty  hklm:\software\microsoft\windows\currentversion\uninstall\* | Where-Object {($_.DisplayName -like "*Citrix*")})
    $CitrixProd2 = (Get-ItemProperty  hklm:\software\wow6432node\microsoft\windows\currentversion\uninstall\* | Where-Object {($_.DisplayName -like "*Citrix*")})

    if ($CitrixProd) {
        foreach ($cprod in $CitrixProd) {
            if ($cprod.DisplayVersion) { $cprodDisplayVersion = $cprod.DisplayVersion } else { $cprodDisplayVersion = "N/A" }
            if ($cprod.InstallDate) { $cprodInstallDate = $cprod.InstallDate } else { $cprodInstallDate = "N/A" }
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$($cprod.DisplayName)" -Message2 "$cprodDisplayVersion (Installed on: $cprodInstallDate)" -circle "blue"

            if (($CitrixProd -like "*Citrix Virtual Apps and Desktops*") -and (($cprodDisplayVersion -eq "1912.0.4000.4227") -or ($cprodDisplayVersion -like "2109.*") -or ($cprodDisplayVersion -like "2112.*"))) {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "An older Citrix Virtual Apps and Desktops version has been found. Please consider updating. You could be running into issues described in: https://support.citrix.com/article/CTX338807" -circle "red"
            }
        }
    } elseif ($CitrixProd2) {
        foreach ($cprod2 in $CitrixProd2) {
            if ($cprod2.DisplayVersion) { $cprod2DisplayVersion = $cprod2.DisplayVersion } else { $cprod2DisplayVersion = "N/A" }
            if ($cprod2.InstallDate) { $cprod2InstallDate = $cprod2.InstallDate } else { $cprod2InstallDate = "N/A" }
            msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "$($cprod2.DisplayName)" -Message2 "$cprod2DisplayVersion (Installed on: $cprod2InstallDate)" -circle "blue"

            if (($CitrixProd2 -like "*Citrix Virtual Apps and Desktops*") -and (($cprod2DisplayVersion -eq "1912.0.4000.4227") -or ($cprod2DisplayVersion -like "2109.*") -or ($cprod2DisplayVersion -like "2112.*"))) {
                $global:msrdSetWarning = $true
                msrdLogDiag DiagFileOnly -Type "Text" -col 3 -Message "An older Citrix Virtual Apps and Desktops version has been found. Please consider updating. You could be running into issues described in: https://support.citrix.com/article/CTX338807" -circle "red"
            }
        }

    } else {
        msrdLogDiag DiagFileOnly -Type "Table2-1" -Message "Citrix products" -Message2 "not found"
    }

    if (($CitrixProd) -or ($CitrixProd2)) {
        msrdLogDiag DiagFileOnly -Type "Spacer"
        msrdCheckRegKeyValue 'HKLM:\SOFTWARE\SOFTWARE\Citrix\Graphics\' 'SetDisplayRequiredMode'
    }

    msrdLogDiag DiagFileOnly -Type "HR"
    msrdProcessCheck -proc "aakore" -intName "Acronis Cyber Protect" -sp2 1
    msrdProcessCheck -proc "cyber-protect-service" -intName "Acronis Cyber Protect" -sp1 1 -sp2 1
    msrdProcessCheck -proc "WebCompanion" -intName "Adaware" -sp1 1 -sp2 1
    msrdProcessCheck -proc "DefendpointService" -intName "BeyondTrust" -sp1 1 -sp2 1
    msrdProcessCheck -proc "vpnagent" -intName "Cisco AnyConnect" -sp1 1 -sp2 1
    msrdProcessCheck -proc "csagent" -intName "CrowdStrike" -sp1 1 -sp2 1
    msrdProcessCheck -proc "secureconnector" -intName "ForeScout SecureConnector" -sp1 1 -sp2 1
    msrdProcessCheck -proc "hwtag" -intName "Forcepoint Endpoint Security Agent" -sp1 1 -sp2 1
    msrdProcessCheck -proc "sgpm" -intName "Forcepoint Stonesoft VPN" -sp1 1 -sp2 1
    msrdProcessCheck -proc "mcshield" -intName "McAfee" -sp1 1 -sp2 1
    msrdProcessCheck -proc "stAgentSvc" -intName "Netskope Client" -sp1 1 -sp2 1
    msrdProcessCheck -proc "NVDisplay.Container" -intName "NVIDIA" -sp1 1 -sp2 1
    msrdProcessCheck -proc "GpVpnApp" -intName "Palo Alto GlobalProtect" -sp1 1 -sp2 1
    msrdProcessCheck -proc "sentinelagent" -intName "SentinelOne Agent" -sp1 1 -sp2 1
    msrdProcessCheck -proc "SAVService" -intName "Sophos Anti-Virus" -sp1 1 -sp2 1
    msrdProcessCheck -proc "SEDService" -intName "Sophos Endpoint Defense Service" -sp1 1 -sp2 1
    msrdCheckRegKeyValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense\EndpointFlags\' 'modernweb.offloading.enabled'
    msrdProcessCheck -proc "SophosNtpService" -intName "Sophos Network Threat Protection" -sp1 1 -sp2 1
    msrdProcessCheck -proc "SSPService" -intName "Sophos System Protection Service" -sp1 1 -sp2 1
    msrdProcessCheck -proc "swi_fc" -intName "Sophos Web Intelligence Service" -sp1 1 -sp2 1
    msrdProcessCheck -proc "wssad" -intName "Symantec WSS Agent" -sp1 1 -sp2 1
    msrdProcessCheck -proc "nessusd" -intName "Tenable Nessus" -sp1 1 -sp2 1
    msrdProcessCheck -proc "TSPrintManagementService" -intName "TerminalWorks TSPrint Server" -sp1 1 -sp2 1
    msrdProcessCheck -proc "tmiacagentsvc" -intName "Trend Micro Application Control" -sp1 1 -sp2 1
    msrdProcessCheck -proc "endpointbasecamp" -intName "Trend Micro Endpoint Basecamp" -sp1 1 -sp2 1
    msrdProcessCheck -proc "tmbmsrv" -intName "Trend Micro Unauthorized Change Prevention" -sp1 1 -sp2 1
    msrdProcessCheck -proc "ivpagent" -intName "Trend Micro Vulnerability Protection" -sp1 1 -sp2 1
    msrdProcessCheck -proc "ZSAService" -intName "ZScaler" -sp1 1

    if ($global:msrdSetWarning) { msrdSetMenuWarning -htmloutfile "$msrdDiagFile" -MenuItem $menuitemmsg -MenuCat $menucatmsg }
}

#endregion Other


#start
Function msrdRunUEX_RDDiag {
    param ([bool[]]$varsSystem, [bool[]]$varsAVDRDS, [bool[]]$varsInfra, [bool[]]$varsAD, [bool[]]$varsNET, [bool[]]$varsLogSec, [bool[]]$varsIssues, [bool[]]$varsOther)

    #main Diag
    msrdLogMessage Info "$rdiagmsg`n" -Color "Cyan"

    msrdProgressStatusInit 59
    msrdCreateLogFolder $global:msrdLogDir

    if ($global:msrdSource) {
        $TitleScenario = "RDP source"
    } elseif ($global:msrdAVD) {
        $TitleScenario = "AVD host"
    } elseif ($global:msrdRDS) {
        $TitleScenario = "RDS server/RDP target"
    }

    msrdHtmlInit $msrdDiagFile
    msrdHtmlHeader -htmloutfile $msrdDiagFile -title "MSRD-Diag ($TitleScenario): $($env:computername)" -fontsize "small"
    msrdHtmlBodyDiag -htmloutfile $msrdDiagFile -title "Microsoft CSS Remote Desktop Diagnostics" -feedback "(<a href='https://aka.ms/MSRD-Collect-Survey' target='_blank'>MSRD-Collect feedback survey</a>)" -varsSystem $varsSystem -varsAVDRDS $varsAVDRDS -varsInfra $varsInfra -varsAD $varsAD -varsNET $varsNET -varsLogSec $varsLogSec -varsIssues $varsIssues -varsOther $varsOther

    #system
    if ($varsSystem[0]) { msrdDiagDeployment }
    if ($varsSystem[1]) { msrdDiagCPU }
    if ($varsSystem[2]) { msrdDiagDrives }
    if ($varsSystem[3]) { msrdDiagGraphics }
    if (!($global:msrdSource)) { if ($varsSystem[4]) { msrdDiagActivation } }
    if ($varsSystem[5]) { msrdDiagSSLTLS }
    if ($varsSystem[6]) { msrdDiagUAC }
    if ($varsSystem[7]) { msrdDiagInstaller }
    if (!($global:msrdSource)) { if ($varsSystem[8]) { msrdDiagSearch } }
    if ($varsSystem[9]) { msrdDiagWU }
    if ($varsSystem[10]) { msrdDiagWinRMPS }

    #avd/rds
    if ($varsAVDRDS[0]) { msrdDiagRedirection }
    if (!($global:msrdSource)) { if ($varsAVDRDS[1]) { msrdDiagFSLogix } }
    if ($varsAVDRDS[2]) { msrdDiagMultimedia }
    if ($varsAVDRDS[3]) { msrdDiagQA }
    if (!($global:msrdSource)) {
        if ($varsAVDRDS[4]) { msrdDiagRDPListener }
        if ($varsAVDRDS[5]) { msrdDiagRDSRoles }
    }
    if ($varsAVDRDS[6]) { msrdDiagRDClient }
    if (!($global:msrdSource)) {
        if ($varsAVDRDS[7]) { msrdDiagLicensing }
        if ($varsAVDRDS[8]) { msrdDiagTimeLimits }
    }
    if (!($global:msrdRDS)) { if ($varsAVDRDS[9]) { msrdDiagTeams } }

    #avd infra
    if ($global:msrdAVD) {
        if ($varsInfra[0]) { msrdDiagAgentStack }
        if ($varsInfra[1]) { msrdDiagHP }
    }
    if (!($global:msrdRDS)) { if ($varsInfra[2]) { msrdDiagURL } }
    if ($global:msrdAVD) {
        if ($varsInfra[3]) { msrdDiagURIHealth }
        if ($varsInfra[4]) { msrdDiagHCI }
    }
    if (!($global:msrdRDS)) { if ($varsInfra[5]) { msrdDiagShortpath } }

    #ad
    if ($varsAD[0]) { msrdDiagAADJ }
    if ($varsAD[1]) { msrdDiagDC }

    #networking
    if ($varsNET[0]) { msrdDiagDNS }
    if ($varsNET[1]) { msrdDiagFirewall }
    if ($varsNET[2]) { msrdDiagProxyRoute }
    if ($varsNET[3]) { msrdDiagPublicIP }
    if ($varsNET[4]) { msrdDiagVPN }

    #logon/security
    if ($varsLogSec[0]) { msrdDiagAuth }
    if ($varsLogSec[1]) { msrdDiagSecurity }

    #known issues
    if ($varsIssues[0]) {
        msrdLogDiag Normal -Message "Issues identified in Event Logs over the past 5 days" -DiagTag "IssuesCheck"
        if ($global:msrdAVD) {
            msrdDiagAVDIssueEvents
            msrdLogDiag DiagFileOnly -Type "HR"
        }
        if (!($global:msrdSource)) {
            $needHR = $false
            if ($script:foundRDS.Name -eq "RDS-Licensing") { msrdDiagRDLicensingIssueEvents; $needHR = $true }
            if ($script:foundRDS.Name -eq "RDS-GATEWAY") { msrdDiagRDGatewayIssueEvents; $needHR = $true }
            if ($needHR) { msrdLogDiag DiagFileOnly -Type "HR" }
            msrdDiagRDIssueEvents
            msrdLogDiag DiagFileOnly -Type "HR"
        }

        msrdDiagCommonIssueEvents
        if (!($global:msrdSource)) { if ($varsIssues[1]) { msrdDiagLogonIssues } }
    }

    #other
    if (!($global:msrdSource)) {
        if ($varsOther[0]) { msrdDiagOffice }
        if ($varsOther[1]) { msrdDiagOD }
    }
    if ($varsOther[2]) { msrdDiagPrinting }
    if ($varsOther[3]) { msrdDiagCitrix3P }

    msrdHtmlEnd $msrdDiagFile
}

Export-ModuleMember -Function msrdRunUEX_RDDiag
# SIG # Begin signature block
# MIInlgYJKoZIhvcNAQcCoIInhzCCJ4MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB73bMuuF+5aq1Q
# 2YRx3lv3we98jWCy0MVmGxgUdFXiYqCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOTwpf++yK1KdcVgyegaWJH7
# xUGKyDJHEK8mZjfg7fyMMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAvMDNNusL7c/yoL5NX/O8F/A44wXLaUEsYc/9WgrC8Tegifjif3tmIBfW
# nVOxgSX0sUAc5910qE6RmjnpgeAuwUn6zFUsAR1LCUQaBOdq27rNhaZSv54V2uUp
# HmITlGCy1hyJmmwjoOWf4NRoegZXgmrJeufVzV8sigIurxV5JYIwwLIJl1kPZAnE
# ka7L33ORJYF0dwQDcuRkO1Ikarq7Ex/NbTcCjCtNNzjJMIvKeNIirpsDc5NDy1ww
# G6B3DMyOHW7lMIglK1ZqWkDTGt+bz9q2VBaLi+NJOVRQTf9Csxc10DPcbrMUPVGb
# +uxOZvhD31LVXOK8WTpqoK7RPBjPWqGCFwAwghb8BgorBgEEAYI3AwMBMYIW7DCC
# FugGCSqGSIb3DQEHAqCCFtkwghbVAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCBPukw8GKvBEFzAHc/k4U1IfuKhb5qvLY2a8IfRa7NgaQIGZF1oi5eb
# GBMyMDIzMDUyMzE0NDQ1NS41MjdaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
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
# hvcNAQkEMSIEIA+QThcdy52Snqn7qc0S30rOw4R2YXegNdMMF4BbBAYjMIH6Bgsq
# hkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgypNgW8fpsMV57r0F5beUuiEVOVe4Bdma
# O+e28mGDUBYwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAIT
# MwAAAcL6fYcOVFNHJAABAAABwjAiBCDJ/B2zg0AuHEaNKiONZu2VhTGFkQRDI7w+
# OF9ftoYeTjANBgkqhkiG9w0BAQsFAASCAgBZs/aic1AIO8Agga4ALb68HEZUbLHS
# xNXtO+b7DgcDhu/GkMjPj0fCmlYNpOul+BfpggtbK19H166kl6UrlFdJke0vXnZ1
# RJ5G//9VyeMtFbee6csoDbZumG08J6MKwWD9ScP22iEZNC2h3OYfJL9xvIRE/gwo
# MBaRsDg4zDxSX8e5NeDJ6byWHI7sNn3VIrEoYEP61vADhTnzynZPV8JtfdSpNqXh
# GYXCPTaIEe8XXxjuZFBZJY4xu7F20vDPGOAJDHF4DXswmXQ73h3KjmuB+SerjBdf
# 63eaHbIvo75GqXNDCQ+dvlkgSKyPvbdsA7E6b23VGDsSs1SYq3FGM9rYBsinwE7K
# NjboIjOetJcg9HsZIBL83Pzg9IGIC8dfU7w8RrTzAuGCK1oyRxI7ZqfZk8jfl2LF
# lVYlL+Sh0u8pMXmq5kw/RbTApk55w2XY7ggFCgAPldHmwx9WOBHLybmlpSKq7VT+
# 0NPU+JYQ083bxa6VWGdK1sjleP9T9BxlKhBhZWwG7efYXs1aisIekyV3zGko0g0m
# eaN+0i/+fCYKwHetshFMOz1TvSfP9NrMDZKVxi/W42RVjDrOql0Obq70t1FLTOod
# eq+x32PPTTZZtq4ebeYNroOvAqs5uctCs86cPiReKSah7ZICba2+Nx9HL46Iv0JW
# 2MDinFyznUoubA==
# SIG # End signature block
