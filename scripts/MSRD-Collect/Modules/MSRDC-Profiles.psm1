<#
.SYNOPSIS
   Scenario module for collecting Microsoft Remote Desktop Profiles related data

.DESCRIPTION
   Collect Profiles related troubleshooting data (incl. FSLogix, OneDrive)

.NOTES
   Authors    : Robert Klemencz (Microsoft) & Alexandru Olariu (Microsoft)
   Requires   : At least PowerShell 5.1 (This module is not for stand-alone use. It is used automatically from within the main MSRD-Collect.ps1 script)
   Version    : See MSRD-Collect.ps1 version
   Feedback   : Send an e-mail to MSRDCollectTalk@microsoft.com
#>

$msrdLogPrefix = "Profiles"
$FSLogixLogFolder = $global:msrdBasicLogFolder + "FSLogix\"

Function msrdGetFSLogixLogFiles {
    Param([Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string]$LogFilePath)

    #get FSLogix log files
    msrdLogMessage Normal ("[$msrdLogPrefix] Copy-Item $LogFilePath")
    if (Test-path -path "$LogFilePath") {
        Try {
            Copy-Item $LogFilePath $FSLogixLogFolder -Recurse -ErrorAction Continue 2>&1 | Out-Null
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
    } else {
        msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] '$LogFilePath' folder not found."
    }
}

Function msrdGetFSLogixCompact {

    #get FSLogix compact action logs
    msrdLogMessage Normal ("[$msrdLogPrefix] FSLogix VHD compaction events")
    $startTime = (Get-Date).AddDays(-5)

    $diskCompactionEvents = Get-WinEvent -FilterHashtable @{StartTime = $startTime; logname = 'Microsoft-FSLogix-Apps/Operational'; id = 57} -ErrorAction SilentlyContinue

    if ($diskCompactionEvents) {
        $compactionMetrics = $diskCompactionEvents | Select-Object `
            @{l="Timestamp";e={$_.TimeCreated}},`
            @{l="Path";e={$_.Properties[0].Value}},`
            @{l="WasCompacted";e={$_.Properties[1].Value}},`
            @{l="TimeSpent(ms)";e={[math]::round($_.Properties[7].Value,2)}},`
            @{l="MaxSupportedSize(MB)";e={[math]::round($_.Properties[2].Value,2)}},`
            @{l="MinSupportedSize(MB)";e={[math]::round($_.Properties[3].Value,2)}},`
            @{l="InitialSize(MB)";e={[math]::round($_.Properties[4].Value,2)}},`
            @{l="FinalSize(MB)";e={[math]::round($_.Properties[5].Value,2)}},`
            @{l="SavedSpace(MB)";e={[math]::round($_.Properties[6].Value,2)}}

        $compactionMetrics | Out-File -FilePath ($FSLogixLogFolder + $global:msrdLogFilePrefix + "vhdCompactionEvents.txt") -Append
    } else {
        msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] FSLogix VHD compaction events not found."
    }
}

Function msrdGetFSLogixRedirXML {

    #get FSLogix redirection xml information
    msrdLogMessage Normal ("[$msrdLogPrefix] FSLogix Redirections XML")

    if (msrdTestRegistryValue -path "HKLM:\SOFTWARE\FSLogix\Profiles\" -value "RedirXMLSourceFolder") {
        $pxml = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\FSLogix\Profiles\" -name "RedirXMLSourceFolder"
        $pxmlfile = $pxml + "\redirections.xml"
        $pxmlout = $FSLogixLogFolder + $env:computername + "_redirectionsXML.txt"

        if (Test-Path -Path $pxmlfile) {
            Try {
                Copy-Item $pxmlfile $pxmlout -ErrorAction Continue 2>&1 | Out-Null
            } Catch {
                msrdLogException ("Error: An exception occurred in msrdGetFSLogixRedirXML $pxmlfile.") -ErrObj $_ $fLogFileOnly
            }
        } else {
            msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] '$pxmlfile' log not found."
        }
    } else {
        msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] RedirXMLSourceFolder registry key not found."
    }
}

Function msrdGetProfilesRegKeys {

    msrdCreateLogFolder $msrdRegLogFolder
    $regs = @{
        'HKCU:\SOFTWARE\Microsoft\Office' = 'SW-MS-Office'
        'HKCU:\SOFTWARE\Policies\Microsoft\office' = 'SW-Policies-MS-Office'
        'HKCU:\SOFTWARE\Microsoft\OneDrive' = 'SW-MS-OneDrive'
        'HKLM:\SOFTWARE\Microsoft\OneDrive' = 'SW-MS-OneDrive'
        'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' = 'SW-Pol-MS-OneDrive'
        'HKLM:\SOFTWARE\Microsoft\Windows Search' = 'SW-MS-WindowsSearch'
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' = 'SW-MS-WinNT-CV-ProfileList'
        'HKCU:\Volatile Environment' = 'VolatileEnvironment'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers' = 'SW-MS-Win-CV-Auth-CredProviders'
        'HKLM:\SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_Msft&Prod_Virtual_Disk' = 'System-CCS-Enum-SCSI-ProdVirtualDisk'
        'HKLM:\SOFTWARE\FSLogix' = 'SW-FSLogix'
        'HKLM:\SOFTWARE\Policies\FSLogix' = 'SW-Policies-FSLogix'
        'HKLM:\SYSTEM\CurrentControlSet\Services\frxccd' = 'System-CCS-Svc-frxccd'
        'HKLM:\SYSTEM\CurrentControlSet\Services\frxccds' = 'System-CCS-Svc-frxccds'
    }
    foreach ($reg in $regs.GetEnumerator()) { msrdGetRegKeys -LogPrefix $msrdLogPrefix $reg.Key $reg.Value }
}

Function msrdGetProfilesEventLogs {

    msrdCreateLogFolder $global:msrdEventLogFolder
    $logs = @{
        'Microsoft-Windows-GroupPolicy/Operational' = 'GroupPolicy-Operational'
        'Microsoft-Windows-User Profile Service/Operational' = 'UserProfileService-Operational'
        'Microsoft-Windows-VHDMP-Operational' = 'VHDMP-Operational'
        'Microsoft-Windows-SMBClient/Operational' = 'SMBClient-Operational'
        'Microsoft-Windows-SMBClient/Connectivity' = 'SMBClient-Connectivity'
        'Microsoft-Windows-SMBClient/Security' = 'SMBClient-Security'
        'Microsoft-Windows-SMBServer/Operational' = 'SMBServer-Operational'
        'Microsoft-Windows-SMBServer/Connectivity' = 'SMBServer-Connectivity'
        'Microsoft-Windows-SMBServer/Security' = 'SMBServer-Security'
        'Microsoft-FSLogix-Apps/Admin' = 'FSLogix-Apps-Admin'
        'Microsoft-FSLogix-Apps/Operational' = 'FSLogix-Apps-Operational'
        'Microsoft-FSLogix-CloudCache/Admin' = 'FSLogix-CloudCache-Admin'
        'Microsoft-FSLogix-CloudCache/Operational' = 'FSLogix-CloudCache-Operational'
    }
    foreach ($log in $logs.GetEnumerator()) { msrdGetEventLogs -LogPrefix $msrdLogPrefix $log.Key $log.Value }

}

Function msrdCollectUEX_AVDProfilesLog {
    param( [bool[]]$varsProfiles )

    #get FSLogix data
    msrdProgressStatusInit 43

    " " | Out-File -Append $global:msrdOutputLogFile
    $profilesmsg = msrdGetLocalizedText "profilesmsg" #Collecting User Profiles troubleshooting data
    msrdLogMessage Info ("$profilesmsg")

    if ($varsProfiles[0]) { msrdGetProfilesEventLogs } #profiles event logs
    if ($varsProfiles[1]) { msrdGetProfilesRegKeys } #profiles reg keys

    if ($varsProfiles[2]) {
        #whoami information
        msrdCreateLogFolder $global:msrdSysInfoLogFolder
        $Commands = @(
            "Whoami /all 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "WhoAmI-all.txt'"
        )
        msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
    }

    if ($varsProfiles[3]) {
        #fslogix logs
        if (Test-path -path 'C:\Program Files\FSLogix') {

            msrdCreateLogFolder $FSLogixLogFolder
            msrdGetFSLogixCompact
            msrdGetFSLogixRedirXML

            if (Test-Path -path 'C:\ProgramData\FSLogix\Logs') {
                msrdGetFSLogixLogFiles 'C:\ProgramData\FSLogix\Logs\*'
            } else {
                msrdLogMessage WarnLogFileOnly ("[$msrdLogPrefix] 'C:\Program Files\FSLogix\Logs' folder not found.")
            }

            $cmd = "c:\program files\fslogix\apps\frx.exe"

            if (Test-path -path 'C:\Program Files\FSLogix\apps') {
                msrdLogMessage Normal ("[$msrdLogPrefix] Running frx.exe version")
                Invoke-Expression "& '$cmd' + 'version'" | Out-File -FilePath ($FSLogixLogFolder + $global:msrdLogFilePrefix + "frx-list.txt") -Append

                "`n====================================================================================`n" | Out-File -FilePath ($FSLogixLogFolder + $global:msrdLogFilePrefix + "Frx-list.txt") -Append

                msrdLogMessage Normal ("[$msrdLogPrefix] Running frx.exe list-redirects")
                Invoke-Expression "& '$cmd' + 'list-redirects'" | Out-File -FilePath ($FSLogixLogFolder + $global:msrdLogFilePrefix + "frx-list.txt") -Append

                "`n====================================================================================`n" | Out-File -FilePath ($FSLogixLogFolder + $global:msrdLogFilePrefix + "Frx-list.txt") -Append

                msrdLogMessage Normal ("[$msrdLogPrefix] Running frx.exe list-rules")
                Invoke-Expression "& '$cmd' + 'list-rules'" | Out-File -FilePath ($FSLogixLogFolder + $global:msrdLogFilePrefix + "frx-list.txt") -Append

            } else {
                msrdLogMessage WarnLogFileOnly ("[$msrdLogPrefix] 'C:\Program Files\FSLogix\apps' folder not found.")
            }

            #if applicable, removing accountname and account key from the exported CCDLocations reg key for security reasons
            $ccdRegOutP = $msrdRegLogFolder + $global:msrdLogFilePrefix + "HKLM-SW-FSLogix.txt"
            if (Test-Path -path $ccdRegOutP) {
                $ccdContentP = Get-Content -Path $ccdRegOutP
                $ccdReplaceP = foreach ($ccdItemP in $ccdContentP) {
                    if ($ccdItemP -like "*CCDLocations*") {
                        $var1P = $ccdItemP -split ";"
                        $var2P = foreach ($varItemP in $var1P) {
                                    if ($varItemP -like "AccountName=*") { $varItemP = "AccountName=xxxxxxxxxxxxxxxx"; $varItemP }
                                    elseif ($varItemP -like "AccountKey=*") { $varItemP = "AccountKey=xxxxxxxxxxxxxxxx"; $varItemP }
                                    else { $varItemP }
                                }
                        $var3P = $var2P -join ";"
                        $var3P
                    } else {
                        $ccdItemP
                    }
                }
                $ccdReplaceP | Set-Content -Path $ccdRegOutP
            }

            $ccdRegOutO = $msrdRegLogFolder + $global:msrdLogFilePrefix + "HKLM-SW-Policies-FSLogix.txt"
            if (Test-Path -path $ccdRegOutO) {
                $ccdContentO = Get-Content -Path $ccdRegOutO
                $ccdReplaceO = foreach ($ccdItemO in $ccdContentO) {
                    if ($ccdItemO -like "*CCDLocations*") {
                        $var1O = $ccdItemO -split ";"
                        $var2O = foreach ($varItemO in $var1O) {
                                    if ($varItemO -like "AccountName=*") { $varItemO = "AccountName=xxxxxxxxxxxxxxxx"; $varItemO }
                                    elseif ($varItemO -like "AccountKey=*") { $varItemO = "AccountKey=xxxxxxxxxxxxxxxx"; $varItemO }
                                    else { $varItemO }
                                }
                        $var3O = $var2O -join ";"
                        $var3O
                    } else {
                        $ccdItemO
                    }
                }
                $ccdReplaceO | Set-Content -Path $ccdRegOutO
            }

            if ([ADSI]::Exists("WinNT://localhost/FSLogix ODFC Exclude List")) {
                $Commands = @(
                    "net localgroup 'FSLogix ODFC Exclude List' 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "LocalGroupsMembership.txt'"
                )
                msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
            } else {
                msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] 'FSLogix ODFC Exclude List' group not found."
            }

            if ([ADSI]::Exists("WinNT://localhost/FSLogix ODFC Include List")) {
                $Commands = @(
                    "net localgroup 'FSLogix ODFC Include List' 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "LocalGroupsMembership.txt'"
                )
                msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
            } else {
                msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] 'FSLogix ODFC Include List' group not found."
            }

            if ([ADSI]::Exists("WinNT://localhost/FSLogix Profile Exclude List")) {
                $Commands = @(
                    "net localgroup 'FSLogix Profile Exclude List' 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "LocalGroupsMembership.txt'"
                )
                msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
            } else {
                msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] 'FSLogix Profile Exclude List' group not found."
            }

            if ([ADSI]::Exists("WinNT://localhost/FSLogix Profile Include List")) {
                $Commands = @(
                    "net localgroup 'FSLogix Profile Include List' 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "LocalGroupsMembership.txt'"
                )
                msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
            } else {
                msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] 'FSLogix Profile Include List' group not found."
            }


            if (msrdTestRegistryValue -path "HKLM:\SOFTWARE\FSLogix\Profiles\" -value "VHDLocations") {
                $pvhd = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\FSLogix\Profiles\" -name "VHDLocations"

                $Commands = @(
                    "icacls $pvhd 2>&1 | Out-File -Append " + $FSLogixLogFolder + $global:msrdLogFilePrefix + "folderPermissions.txt"
                )
                msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
            }

            if (msrdTestRegistryValue -path "HKLM:\SOFTWARE\Policies\FSLogix\ODFC\" -value "VHDLocations") {
                $ovhd = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\FSLogix\ODFC\" -name "VHDLocations"

                $Commands = @(
                    "icacls $ovhd 2>&1 | Out-File -Append " + $FSLogixLogFolder + $global:msrdLogFilePrefix + "folderPermissions.txt"
                )
                msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
            }


            #Collecting AAD Kerberos Auth for FSLogix
            $Commands = @(
                    "klist get krbtgt 2>&1 | Out-File -Append " + $FSLogixLogFolder + $global:msrdLogFilePrefix + "klist-get-krbtgt.txt"
                )
            msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True

            if (msrdTestRegistryValue -path "HKLM:\SOFTWARE\FSLogix\Profiles\" -value "VHDLocations") {
                    $pvhd = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\FSLogix\Profiles\" -name "VHDLocations" -ErrorAction SilentlyContinue
                    $pconPath = $pvhd.split("\")[2]
                    if ($pconPath) {
                        $Commands = @(
                            "klist get cifs/$pconPath 2>&1 | Out-File -Append " + $FSLogixLogFolder + $global:msrdLogFilePrefix + "klist-get-cifs-ProfileVHDLocations.txt"
                        )
                        msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
                    }
            } else {
                msrdLogMessage WarnLogFileOnly ("[$msrdLogPrefix] 'HKLM:\SOFTWARE\FSLogix\Profiles\VHDLocations' not found. Skipping 'klist get cifs/...'")
            }

        } else {
            msrdLogMessage WarnLogFileOnly ("[$msrdLogPrefix] 'C:\Program Files\FSLogix' folder not found.")
        }
    }

    msrdProgressStatusEnd
}

Export-ModuleMember -Function msrdCollectUEX_AVDProfilesLog
# SIG # Begin signature block
# MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBszTGbWxHopn6Y
# 5Up1sno/HHgab7T1crAwQdk57mpph6CCDYUwggYDMIID66ADAgECAhMzAAADTU6R
# phoosHiPAAAAAANNMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI4WhcNMjQwMzE0MTg0MzI4WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDUKPcKGVa6cboGQU03ONbUKyl4WpH6Q2Xo9cP3RhXTOa6C6THltd2RfnjlUQG+
# Mwoy93iGmGKEMF/jyO2XdiwMP427j90C/PMY/d5vY31sx+udtbif7GCJ7jJ1vLzd
# j28zV4r0FGG6yEv+tUNelTIsFmmSb0FUiJtU4r5sfCThvg8dI/F9Hh6xMZoVti+k
# bVla+hlG8bf4s00VTw4uAZhjGTFCYFRytKJ3/mteg2qnwvHDOgV7QSdV5dWdd0+x
# zcuG0qgd3oCCAjH8ZmjmowkHUe4dUmbcZfXsgWlOfc6DG7JS+DeJak1DvabamYqH
# g1AUeZ0+skpkwrKwXTFwBRltAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUId2Img2Sp05U6XI04jli2KohL+8w
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzUwMDUxNzAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# ACMET8WuzLrDwexuTUZe9v2xrW8WGUPRQVmyJ1b/BzKYBZ5aU4Qvh5LzZe9jOExD
# YUlKb/Y73lqIIfUcEO/6W3b+7t1P9m9M1xPrZv5cfnSCguooPDq4rQe/iCdNDwHT
# 6XYW6yetxTJMOo4tUDbSS0YiZr7Mab2wkjgNFa0jRFheS9daTS1oJ/z5bNlGinxq
# 2v8azSP/GcH/t8eTrHQfcax3WbPELoGHIbryrSUaOCphsnCNUqUN5FbEMlat5MuY
# 94rGMJnq1IEd6S8ngK6C8E9SWpGEO3NDa0NlAViorpGfI0NYIbdynyOB846aWAjN
# fgThIcdzdWFvAl/6ktWXLETn8u/lYQyWGmul3yz+w06puIPD9p4KPiWBkCesKDHv
# XLrT3BbLZ8dKqSOV8DtzLFAfc9qAsNiG8EoathluJBsbyFbpebadKlErFidAX8KE
# usk8htHqiSkNxydamL/tKfx3V/vDAoQE59ysv4r3pE+zdyfMairvkFNNw7cPn1kH
# Gcww9dFSY2QwAxhMzmoM0G+M+YvBnBu5wjfxNrMRilRbxM6Cj9hKFh0YTwba6M7z
# ntHHpX3d+nabjFm/TnMRROOgIXJzYbzKKaO2g1kWeyG2QtvIR147zlrbQD4X10Ab
# rRg9CpwW7xYxywezj+iNAc+QmFzR94dzJkEPUSCJPsTFMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGXMwghlvAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAANNTpGmGiiweI8AAAAA
# A00wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIAqS
# b5ftX99HGf1HpzQH2LeSGR5ORd8jVuaAHm9FpyglMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAp/I57YsBquN2N4hgHa4aV4NX3T98bl2iqB8/
# erQ/Ov/jC5En+NWO2XO8mkZz3UC75mHUe5uOhvV25ehV/bd1UJw9RH3dS8lKtOFa
# QJNFNDnShQg02gmKkppuahn0DH1mU/v2jH7ofOQN0Qnq1chr3qxh2Qv0ixqQrzKE
# rka6XhLjflQBi0KDGFDOuVvvkzQ4o5MRxzB7NN8VPNXIJ3WSM/qi1m47Jf8hfiAt
# lUDGSo7ISWYyuPUWVd8Mm4SSKsHyRYokHWlh6ostKwJMKkBVwWyjM8nEkKPxj11U
# h0zYNtRNrZ+HG9L+iWFo4A5JfJiK7PnDiT+ORjOBonbwn1spK6GCFv0wghb5Bgor
# BgEEAYI3AwMBMYIW6TCCFuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCDCm1/I5ClqyUlIQclTiY0mPwbBqVGNKSLA
# xm/93EiGnQIGZF1fGWSGGBMyMDIzMDUyMzE0NDQ1MS43ODRaMASAAgH0oIHQpIHN
# MIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjoyMjY0LUUzM0UtNzgwQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEVQwggcMMIIE9KADAgECAhMzAAABwT6gg5zgCa/FAAEA
# AAHBMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMTEwNDE5MDEyN1oXDTI0MDIwMjE5MDEyN1owgcoxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjIyNjQtRTMz
# RS03ODBDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5LHXMydw2hUC4pJU0I5uPJnM
# eRm8LKC4xaIDu3Fxx3IpZ/We2qXLj4NOmow/WPFeY4vaT4/S4T9xoDsFGg5wEJM6
# OLZVfa7BUNu0tDt4rkl7QBYNHzz6pcr9bwaq2qm7x6P9yi5W0Y8sjoj+QTgtmmXo
# xCoNXhJ1oG6GbqADQXDZkTcDjIAiteE6TxrhBpIb7e6upifTGZNfcChPfuzHq61F
# SIwJ0XCxcaR1BwAlSKhb/NUOuQGPr9Zzd6OnIcA+RctxwKgfOKB9aWEEHlt0jhKK
# gpEBvcJnMMP+WaTwmMhob1e+hoCEFx/nI0YHupi6082kFdNFraE72msOYQrwrUyW
# CeSmN202LZDpTzxZVty6QrBOk+f+BErsR+M5evkKuUTWVJHI3vtNgb6K5+gk6EuQ
# w0ocsDdspiPp+qlxBaW50yUbr6wnfzYjJh7QkPcfBIZbJAhWQHaV0uS3T7OkObdC
# ssCRMWH7VWUAeSbemuUqOXCR7rdpFTfY/SXKO9lCIQBAQSh+wzwh5Zv1b+jT2zWw
# Vl82By3YHmST8b8CKnRXSCjLtgoyy7ERLwkbzPIkCfBXcyVneC1w2/wUnqPiAjK0
# wQfztfXFfoMQr8YUcLHnAtek8OVNPuRIV6bcERbF6rtFXmnjjD4ZwVxIZ/HM4cje
# VGsEwkFA9XTzqX9W1P8CAwEAAaOCATYwggEyMB0GA1UdDgQWBBRfr2MJ6x7yE+gP
# 5uX9xWGTwpRC+jAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
# KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4ICAQBfuiaBgsecHvM90RZiTDlfHblL09r9X+5q9ckuMR0B
# s1Sr5B2MALhT5Y0R3ggLufRX6RQQbSc7WxRXIMr5tFEgB5zy/7Yg81Cn2dhTf1Gz
# jCb7/n3wtJSGtr2QwHsa1ehYWdMfi+ETLoEX1G79VPFrs0t6Giwpr74tv+CLE3s6
# m10VOwe80wP4yuT3eiFfqRV8poUFSdL2wclgQKoSwbCpbJlNC/ESaDQbbQFli9uO
# 5j2f/G7S4TMG/gyyxvMQ5QJui9Fw2s7qklmozQoX2Ah4aKubKe9/VZveiETNYl1A
# ZPj0kj1g51VNyWjvHw+Hz1xZekWIpfMXQEi0wrGdWeiW4i8l92rY3ZbdHsErFYqz
# h6FRFOeXgazNsfkLmwy+TK17mA7CTEUzaAWMq5+f9K4Y/3mhB4r6UristkWpdkPW
# Eo8b9tbkdKSY00E+FS5DUtjgAdCaRBNaBu8cFYCbErh9roWDxc+Isv8yMQAUDuEw
# XSy0ExnIAlcVIrhzL40OsG2ca5R5BgAevGP1Hj9ej4l/y+Sh0HVcN9N6LmPDmI/M
# aU2rEZ7Y+jRfCZ1d+l5DESdLXIxDTysYXkT+3VM/1zh6y2s0Zsb/3vPaGnp2zejw
# f2YlGWl1XpChNZTelF5eOCCfSzUUn3qHe7IyyDKhahgbnKpmwcEkMVBs+RHbVkNW
# qDCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQEL
# BQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNV
# BAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4X
# DTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM
# 57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm
# 95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzB
# RMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBb
# fowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCO
# Mcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYw
# XE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW
# /aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/w
# EPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPK
# Z6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2
# BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfH
# CBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYB
# BAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8v
# BO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYM
# KwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEF
# BQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBW
# BgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUH
# AQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# L2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsF
# AAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518Jx
# Nj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+
# iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2
# pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefw
# C2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7
# T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFO
# Ry3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhL
# mm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3L
# wUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5
# m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE
# 0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLLMIICNAIB
# ATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UE
# CxMdVGhhbGVzIFRTUyBFU046MjI2NC1FMzNFLTc4MEMxJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAESKOtSK7RVV
# K+Si+aqFd0YSY+VPoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwDQYJKoZIhvcNAQEFBQACBQDoFwX6MCIYDzIwMjMwNTIzMTcyOTMwWhgPMjAy
# MzA1MjQxNzI5MzBaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOgXBfoCAQAwBwIB
# AAICECIwBwIBAAICEaUwCgIFAOgYV3oCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYK
# KwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUF
# AAOBgQANk8jHj5PZMeD+NFv8wgFkbStZ5XAjT0MeITi6cyZ9fjXMERBdnUwF0MfF
# WgiLakgdZ8PgDOrtxWcjgkKlf5PpNL/lvXB2C/c0CWJDrxpR3hGFjoqa+ocjiHQb
# qLU0z6hYhlDKiUN/6xwqE4c4QXeOCfipNj1KEGp+xjXhXQmwnTGCBA0wggQJAgEB
# MIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABwT6gg5zgCa/F
# AAEAAAHBMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwLwYJKoZIhvcNAQkEMSIEIHFDdd10C7iUHB9p4JIcoShLwSfn0W1p7N20
# Z5Pvw2hPMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgCrkg6tgYHeSgIsN3
# opR2z7EExWA0YkirkvVYSTBgdtQwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAcE+oIOc4AmvxQABAAABwTAiBCDGuAq1Iedowa94Ghcc
# zatrtyRYGO3Uvh4GZF6gEb4MdTANBgkqhkiG9w0BAQsFAASCAgBC749s6kKGcmxp
# MpgO2dPEZrP1EKmlW9ztw5iGTPG/M1wI5jd7zS5LPWKAzsokMVmB5RnqWUxOihsl
# zHxNvv4hyfvG3taRA07TDleyTeCtlYLSsgATCxpoyrye+y/n0xu31KnS3Qqytx2V
# oedKlJ3O/GzMfwrpwnOFYE09E3OZY7eULrho9BOLdmD8683hlI8qTewFfAzszv/M
# 0t2jD/vDhwxEpA5qChGA7I4yEh7BXelllqL6cjw4NDJdWUQcIbQbvJ2/3Wzr57Wz
# oyzHTMihu8PfsyCnicCBa+6UUhALa5i3cScuPit7sniZaboVq4+BKnas36rb4akg
# aXTNL5y5YZe+89/UdXJRgssX++y+jhfOp3SgTFNf0QLWYWGUYPTzewDMBG5R6xZK
# 0G6wxzv4B4pD5G9B8cZ3+BNDmIfYOYJHk6rYuPvERwSXqw67n0BtBcEEmEQi0HK0
# wCe8EpUqF2MQ9IClC1y+nWytm61e+e0tXQNubpjTsuVuoeQkXRA+jXFDYWLxLVyo
# SxQnH2Gu5eOkch0ux0RHy6ITq/HpNJamhJ9fK3vYtijuTbnwj/30YOuRHSg1PxPI
# 21nu3vg2OfCkJwg6rmf1rgEbC70xwTvbKFItStshuM4zhUdLbIaK6chjlcnvLESi
# B2RKoA+b1lb2H5vWkrACyN/Dhdt/nA==
# SIG # End signature block
