<#
.SYNOPSIS
   Scenario module for collecting Microsoft Remote Desktop Remote Assistance related data

.DESCRIPTION
   Collect Remote Assistance related troubleshooting data

.NOTES
   Authors    : Robert Klemencz (Microsoft) & Alexandru Olariu (Microsoft)
   Requires   : At least PowerShell 5.1 (This module is not for stand-alone use. It is used automatically from within the main MSRD-Collect.ps1 script)
   Version    : See MSRD-Collect.ps1 version
   Feedback   : Send an e-mail to MSRDCollectTalk@microsoft.com
#>

$msrdLogPrefix = "MSRA"

Function msrdGetMSRAGroupsMembership {

    msrdCreateLogFolder $global:msrdSysInfoLogFolder

    if ([ADSI]::Exists("WinNT://localhost/Offer Remote Assistance Helpers")) {
        $Commands = @(
            "net localgroup 'Offer Remote Assistance Helpers' 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "LocalGroupsMembership.txt'"
        )
        msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
    } else {
        msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] 'Offer Remote Assistance Helpers' group not found."
    }

    if ([ADSI]::Exists("WinNT://localhost/Distributed COM Users")) {
        $Commands = @(
            "net localgroup 'Distributed COM Users' 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "LocalGroupsMembership.txt'"
        )
        msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
    } else {
        msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] 'Distributed COM Users' group not found."
    }

}

Function msrdGetMSRAEventLogs {

    msrdCreateLogFolder $global:msrdEventLogFolder
    msrdGetEventLogs -LogPrefix $msrdLogPrefix 'Microsoft-Windows-RemoteAssistance/Operational' 'RemoteAssistance-Operational'
    msrdGetEventLogs -LogPrefix $msrdLogPrefix 'Microsoft-Windows-RemoteAssistance/Admin' 'RemoteAssistance-Admin'
}

Function GetMSRARegKeys {

    msrdCreateLogFolder $global:msrdRegLogFolder
    msrdGetRegKeys -LogPrefix $msrdLogPrefix 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'System-CCS-Control-MSRA'
}

Function msrdGetMSRAPermissions {

    msrdCreateLogFolder $global:msrdSysInfoLogFolder

    $Reg = [WMIClass]"\\.\root\default:StdRegProv"
    $DCOMMachineLaunchRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction").uValue
    $DCOMMachineAccessRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineAccessRestriction").uValue
    $DCOMDefaultLaunchPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultLaunchPermission").uValue
    $DCOMDefaultAccessPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultAccessPermission").uValue

    # Convert the current permissions to SDDL
    $converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
    "Default Access Permission = " + ($converter.BinarySDToSDDL($DCOMDefaultAccessPermission)).SDDL | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "COMSecurity.txt")
    "Default Launch Permission = " + ($converter.BinarySDToSDDL($DCOMDefaultLaunchPermission)).SDDL | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "COMSecurity.txt")
    "Machine Access Restriction = " + ($converter.BinarySDToSDDL($DCOMMachineAccessRestriction)).SDDL | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "COMSecurity.txt")
    "Machine Launch Restriction = " + ($converter.BinarySDToSDDL($DCOMMachineLaunchRestriction)).SDDL | Out-File -Append ($global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "COMSecurity.txt")
}

Function msrdGetMSRASchedTasks {

    msrdCreateLogFolder $global:msrdSchtaskFolder

    if (Get-ScheduledTask RemoteAssistance* -ErrorAction Ignore) {
        (Get-ScheduledTask RemoteAssistance*).TaskName | ForEach-Object -Process {
            $Commands = @(
                "Export-ScheduledTask -TaskName $_ -TaskPath '\Microsoft\Windows\RemoteAssistance' 2>&1 | Out-File -Append '" + $global:msrdSchtaskFolder + $global:msrdLogFilePrefix + "schtasks_" + $_ + ".xml'"
                "Get-ScheduledTaskInfo -TaskName $_ -TaskPath '\Microsoft\Windows\RemoteAssistance' 2>&1 | Out-File -Append '" + $global:msrdSchtaskFolder + $global:msrdLogFilePrefix + "schtasks_" + $_ + "_Info.txt'"
            )
            msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
        }
    } else {
        msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] Remote Assistance Scheduled Tasks not found."
    }
}

Function msrdCollectUEX_AVDMSRALog {
    param( [bool[]]$varsMSRA )

    #get Remote Assistance information
    " " | Out-File -Append $global:msrdOutputLogFile
    $msramsg = msrdGetLocalizedText "msramsg" #Collecting Remote Assistance troubleshooting data
    msrdLogMessage Info ("$msramsg")

    msrdProgressStatusInit 7

    if ($varsMSRA[0]) { msrdGetMSRAEventLogs } #get event logs
    if ($varsMSRA[1]) { GetMSRARegKeys } #get reg keys
    if ($varsMSRA[2]) { msrdGetMSRAGroupsMembership } #get groups membership
    if ($varsMSRA[3]) { msrdGetMSRAPermissions } #get permissions
    if ($varsMSRA[4]) { msrdGetMSRASchedTasks } #get scheduled task

    msrdProgressStatusEnd
}

Export-ModuleMember -Function msrdCollectUEX_AVDMSRALog
# SIG # Begin signature block
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBemxE3iEFa1ljV
# e41bnyM629R3QLzyvfzYpgs7r1JirqCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXMwghlvAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPQplf2Bqp//vy5UALDOCgr1
# xpJpohgZxbdvDMGhKbHQMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAA/kuHfXxZ3DC/aQwRzmdp8zc5aMHkwHHHAYn86p/5W1hIL5Mcodn5fG3
# 5X8AhMmnSOzlCABvx7QjN3f9/Z3QUQ9/gZkLwVmlooFtCdpng8UzKoCi50HsCO3H
# RTEMCqi0kLUK9m0nNstuRVXFQ0kc9EfutoBaZEOjr/jSRQc7Aphs4ZAf+VGu6H3o
# Y5GRPrVj9dVy2i1bZazLDvnzV+hStNP6SSsrlP+2olJuLPAGMxLaMBduzQ+OhvSd
# BU2+Ws+0DoO2yk3SsfnsYv3PMudbfxahPnnP8JyAllh2oJguHup7NnAgRPFuEPvU
# HfkmgQ8rhTZkxiyzFHBU/0+dQn26YaGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCC
# FuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCbdcX8pnNxmUQe+m8HbocFla96KseWNFb6GjGEN78kCAIGZF0epKW8
# GBMyMDIzMDUyMzE0NDQ1NS4xMTRaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpBRTJDLUUz
# MkItMUFGQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVQwggcMMIIE9KADAgECAhMzAAABv99uuQQVUihYAAEAAAG/MA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEy
# NFoXDTI0MDIwMjE5MDEyNFowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkFFMkMtRTMyQi0xQUZDMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAuExh0n1UxKMzBvkPHer47nryD4UK2GVy1X6bOVC+hLVh
# DlsIWQ1uX/9a8IRI3zXo/y1oTDuj+rJHyX4OZQn42E0iu7x6swPvM34zIOSPn8lg
# nWzGEAsRtz9zBrLW9+4w/YhWlXI8hvc7ovqupuL3TXte8BbmNOUDSL+Ou2bBfObG
# zsH3yY/BELvqwO13KZ9Z1OxKacnqq1u9E9Rhai90STog22lR2MVRSx55FHi/emnZ
# A/IKvsAtEH2K6JmgOyQ7/mDQrWNEA5roUjhQqLQw1/3wz/CIvc9+FPxX2dxR0nvv
# Ye5VLqv8Q99cOkO6z6V4stGDyFDuO8CwtiSvCC3QrOOugAl33aPD9YZswywWRk+Y
# GyLI+Fw+kCCUY6h1qOjTj5glz0esmds3ue45WaI2hI9usForM8gy//5tDZXj0KKU
# 1BxA04xpfEy91RZUbc6pdAvEkpYrN2jlpXhMvTD7pgdYyxkVSaWZv7kWp5y9NjWP
# /CTDGXTC6DWiGcXwPQO66QdVNWxuiGdpfPaEUnWXcKnDVua1khBAxO4m9wg/1qM6
# f7HwXf/pHifMej+qB7SUZOiJScX+1HmffmZRAFiJXS0qUDk0ZAZW3oX2xLyl0044
# eHI7Y95GPaw8OlSTeNiNAKl+MyH5OaifsUuyVHOf4rsrE+ZyAuS9e9ERqu5H/10C
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBRVAolUT3eV3wK/+Luf/wawCPMYpzAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQAjCREvjT6yXwJYdvkFUqTGGh6RizAY+ciuB6UOBUm0yqq5QC+5pCEa9WSMvbUG
# zxDCEFBgD93gWGnkiyYcHCazlgZK+E7WxtI3bP++Fb4RJZiWLo/IC9hX12hCZZwY
# XIGVzC9BVAcNx/zsFqI/9u8u/bhGjDHPad47C4OQNCHrkNqzGYxb4GQq6Psw6o7c
# Ety3MU3Jd4uzBazaFhPRvmBfSn+Ufd6pTNZLgIX9BjrLmZblc/d2LIAurEr5W29W
# fW5RMRIEZzO9TaMr/zzdmW/cV6VdaDTygy5g4O3UXadt1DraUpn5jcD10TVWNnyz
# /paeleHojrGCCksqexpelMkUsiYP0HX9pFUgNglWU10r1wEzFwZM9aX2Rqq3fFRr
# N3gu8tCX+H1nKK2AobW1vmsKLTH6PyX1LkyvRwTj45a1paeHIR8TGzm3+iY7wpC1
# MHuzqAqAdDeaIVdVlch807VJJ4hDive6AiOQCV9MwiUyhf5v4P8jTGof8CqjDb3P
# nLlNSnFm2BFhMZ35oNTEosc37GZHScM83hTN1E481sLYJrrhhcdtcyNB60juMjqG
# UD6uQ/7DbMvtv93tFj5WjxVhMCkkY66EEYgpfFLOCb2ngJJWFuJCIGsCiDfDxGwE
# 4RVYAnoFzoa2OfSqijYg2drdZfpptRRvKxMsAzu3oxkS/TCCB3EwggVZoAMCAQIC
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
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLLMIICNAIBATCB+KGB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046QUUyQy1FMzJCLTFBRkMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVADgEd+JNrp4dpvFKMZi91txbfic3oIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoFsYgMCIYDzIwMjMwNTIzMTI1NzA0WhgPMjAyMzA1MjQxMjU3MDRaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOgWxiACAQAwBwIBAAICDa8wBwIBAAICEf4w
# CgIFAOgYF6ACAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQAJyN7LbmDwPjRP
# +UPXcCT8IWY2IokkSkR8DdxBcvWexT6pXswd4deMA4hreqbiZC+QBSYkSjShisjm
# FtJwSm+OHxPGDeQUFVSO8+PvRPfjbULfsYW/TSOj+egb035/NCOCydbYvD7in+/Q
# WXNEG9YDCF1rr7OnPHv1RvjIpCiB9DGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABv99uuQQVUihYAAEAAAG/MA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIEdE3ANVA7z8O1xd/Wop8bwUcHk+0kKaMvo4eHfuOsqKMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQg/Q4tRz63EiRj4K+19yNUwogBIOsp44CIuBfn
# ZHCvBa4wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# Ab/fbrkEFVIoWAABAAABvzAiBCCc+uj7nbFRyrzNdU7Wf6La5A1SXUa5yvVchlNI
# MmIvNzANBgkqhkiG9w0BAQsFAASCAgCSggCdc9ba4R4RqSG79qXKekcw+aj8QvkC
# Iun8049P4jydQDicZyyBPLa5S5tarMTy7yI0vIeIRcAxygENuEUQca1gnzhGnA/h
# DP+1yWgPOn6KYr9mCxUZ8+VdByQeetJJ1qki2Hq7e9tZ4gsHgNAz/fBn3bmvdhEE
# MH1VzuLUXOf8GKYjX97SL7oZiblON142InQUbyGbiz3YrL76kNK9fC2JH7i0kpwb
# UcLmrwypjGHQ3KP7CcAJWWsoXYGBEklw3dc+cKim4bLAsn9TtFgf2LPRZuIoq24R
# ayDiON1euU/lOrHQCwHEcdwaUutxLW/PQYoUSv1o1BrLE/U7L7XbYn7y9C9TlTy3
# s1Ew7qHg4vzoXsyRKepgJLMFVz/jEoCcflkfzR5R/EwAfNWO23f3RPglE3mvYhKk
# 2059Wp1THYG4UueDxCByyMg7rZkx3VNnmhUiLBJxNem5AMkiVUEGHBT89ku4YVze
# QJoxlfOjl4pHa6V98DdTyvGrxcLJu01ibH8S8dYcYOlZxg405KrvheEy1XSyMCDp
# LK0HkWAUYsOMBzGjnPY9LMJBEXrk7C5mcHZ0vO+/SnQZ5sKAJnwv6bz/+j4u3wfe
# 55Jay/1F47O9bQIhJtgrW3Sxhuohz8Z5c8RKUBb9IOC83IgigB6Cu5i1nVT/cEUJ
# l/df37vA1Q==
# SIG # End signature block
