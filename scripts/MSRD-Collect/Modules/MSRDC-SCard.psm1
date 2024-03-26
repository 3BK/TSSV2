<#
.SYNOPSIS
   Scenario module for collecting Microsoft Remote Desktop Smart Card related data

.DESCRIPTION
   Collect Smart Card related troubleshooting data

.NOTES
   Authors    : Robert Klemencz (Microsoft) & Alexandru Olariu (Microsoft)
   Requires   : At least PowerShell 5.1 (This module is not for stand-alone use. It is used automatically from within the main MSRD-Collect.ps1 script)
   Version    : See MSRD-Collect.ps1 version
   Feedback   : Send an e-mail to MSRDCollectTalk@microsoft.com
#>

$msrdLogPrefix = "SCard"

Function msrdGetSCardEventLogs {

    msrdCreateLogFolder $global:msrdEventLogFolder
    $logs = @{
        'Microsoft-Windows-SmartCard-Audit/Authentication' = 'SmartCard-Audit-Auth'
        'Microsoft-Windows-SmartCard-DeviceEnum/Operational' = 'SmartCard-DeviceEnum-Operational'
        'Microsoft-Windows-SmartCard-TPM-VCard-Module/Admin' = 'SmartCard-TPM-Admin'
        'Microsoft-Windows-SmartCard-TPM-VCard-Module/Operational' = 'SmartCard-TPM-Operational'
    }
    foreach ($log in $logs.GetEnumerator()) { msrdGetEventLogs -LogPrefix $msrdLogPrefix $log.Key $log.Value }
}

function msrdGetRDGW {

    #get RD Gateway information
    msrdLogMessage Normal ("[SCard] msrdGetRDGW")
    $RDSGWRAP = msrdGetRDRoleInfo Win32_TSGatewayResourceAuthorizationPolicy root\cimv2\TerminalServices
    if ($RDSGWRAP)
    { $RDSGWRAP | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdgw_ResourceAuthorizationPolicy.txt") }
    else { msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] [WARNING] Failed to get Win32_TSGatewayResourceAuthorizationPolicy." }

    $RDSGWCAP = msrdGetRDRoleInfo Win32_TSGatewayConnectionAuthorizationPolicy root\cimv2\TerminalServices
    if ($RDSGWCAP)
    { $RDSGWCAP | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdgw_ConnectionAuthorizationPolicy.txt") }
    else { msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] [WARNING] Failed to get Win32_TSGatewayConnectionAuthorizationPolicy." }

    $RDSGWS = msrdGetRDRoleInfo Win32_TSGatewayServerSettings root\cimv2\TerminalServices
    if ($RDSGWS)
    { $RDSGWS | Out-File -Append ($global:msrdRDSLogFolder + $global:msrdLogFilePrefix + "rdgw_ServerSettings.txt") }
    else { msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] [WARNING] Failed to get Win32_TSGatewayServerSettings." }
}

Function msrdGetKDCRDGWInfo {

    if ($global:msrdOSVer -like "*Windows Server*") {
        msrdGetEventLogs -LogPrefix $msrdLogPrefix 'Microsoft-Windows-Kerberos-KDCProxy/Operational' 'Kerberos-KDCProxy-Operational'

        #Collecting RDGW information
        $isRDGW = (Get-WindowsFeature -Name RDS-GATEWAY).InstallState
        if ($isRDGW -eq "Installed") {
            " " | Out-File -Append $global:msrdOutputLogFile
            msrdLogMessage Info ('Collecting Remote Desktop Gateway information')

            msrdCreateLogFolder $global:msrdRDSLogFolder
            msrdGetRDGW

        } else {
            msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] RD Gateway role not found. Skipping collection of RD Gateway information"
        }
    } else {
            msrdLogMessage WarnLogFileOnly "[$msrdLogPrefix] Windows Server OS not found. Skipping collection of KDCProxy and RD Gateway information"
    }
}

Function msrdCollectUEX_AVDSCardLog {
    param( [bool[]]$varsSCard )

    #get Smart Card information
    msrdProgressStatusInit 7

    " " | Out-File -Append $global:msrdOutputLogFile
    msrdLogMessage Info ("$(msrdGetLocalizedText "scardmsg")") #Collecting Smart Card troubleshooting data

    if ($varsSCard[0]) { msrdGetSCardEventLogs } #get event logs

    msrdCreateLogFolder $global:msrdSysInfoLogFolder

    if ($varsSCard[1]) {
        $Commands = @(
            "certutil -scinfo -silent 2>&1 | Out-File -Append '" + $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "SmartCardInfo.txt'"
        )
        msrdRunCommands $msrdLogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
    }

    if ($varsSCard[2]) { msrdGetKDCRDGWInfo } #get KDCProxy and RD Gateway information

    msrdProgressStatusEnd
}

Export-ModuleMember -Function msrdCollectUEX_AVDSCardLog
# SIG # Begin signature block
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAG9NEy5w6JcNkt
# AtChIQaHIWhwBiDlUVaR8etAtqQraKCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDIDASgBafLsg1rPE/Ifu6nE
# 6c93nd4CrqbvWOqWTn/LMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAMJAogY6PGGAJisZ3OsggyBSwZKLTpMRHkkgtjXGHBfEXISGUU3Jg8Oij
# OdFZQP1xQW/m6IB/G/0jfO4HACm08qvEw5JJS3JoMWpfujjX+C0fV3FkAYsL8/pH
# uZ3kDzbRIFx9KL9916OaRaK9Y0p5h/av4tNIMyg4ou9rhrvTtPm8BI2u/SONFrKy
# OI5fseEef+5Xh7yHQLXniKbMbOC2e2ebVifAgjhrltPEHKVzY57RsiVxZpoiMSAw
# E89a62eOorfaNwkw9vnesvlDTl0+KXqVk1aLsFXq/r6Evfq/QM9dfjeuewq0qeVX
# SkLZUn1E8Wfpl3ijhPOppxSxcvuG0aGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCC
# FuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCAT+S9UQ+Ni/EnQAhonyPEAJJ0PCi5Dlb6i83LtGJy3vAIGZF1fGWSw
# GBMyMDIzMDUyMzE0NDQ1Mi42ODZaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoyMjY0LUUz
# M0UtNzgwQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVQwggcMMIIE9KADAgECAhMzAAABwT6gg5zgCa/FAAEAAAHBMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEy
# N1oXDTI0MDIwMjE5MDEyN1owgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjIyNjQtRTMzRS03ODBDMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEA5LHXMydw2hUC4pJU0I5uPJnMeRm8LKC4xaIDu3Fxx3Ip
# Z/We2qXLj4NOmow/WPFeY4vaT4/S4T9xoDsFGg5wEJM6OLZVfa7BUNu0tDt4rkl7
# QBYNHzz6pcr9bwaq2qm7x6P9yi5W0Y8sjoj+QTgtmmXoxCoNXhJ1oG6GbqADQXDZ
# kTcDjIAiteE6TxrhBpIb7e6upifTGZNfcChPfuzHq61FSIwJ0XCxcaR1BwAlSKhb
# /NUOuQGPr9Zzd6OnIcA+RctxwKgfOKB9aWEEHlt0jhKKgpEBvcJnMMP+WaTwmMho
# b1e+hoCEFx/nI0YHupi6082kFdNFraE72msOYQrwrUyWCeSmN202LZDpTzxZVty6
# QrBOk+f+BErsR+M5evkKuUTWVJHI3vtNgb6K5+gk6EuQw0ocsDdspiPp+qlxBaW5
# 0yUbr6wnfzYjJh7QkPcfBIZbJAhWQHaV0uS3T7OkObdCssCRMWH7VWUAeSbemuUq
# OXCR7rdpFTfY/SXKO9lCIQBAQSh+wzwh5Zv1b+jT2zWwVl82By3YHmST8b8CKnRX
# SCjLtgoyy7ERLwkbzPIkCfBXcyVneC1w2/wUnqPiAjK0wQfztfXFfoMQr8YUcLHn
# Atek8OVNPuRIV6bcERbF6rtFXmnjjD4ZwVxIZ/HM4cjeVGsEwkFA9XTzqX9W1P8C
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBRfr2MJ6x7yE+gP5uX9xWGTwpRC+jAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQBfuiaBgsecHvM90RZiTDlfHblL09r9X+5q9ckuMR0Bs1Sr5B2MALhT5Y0R3ggL
# ufRX6RQQbSc7WxRXIMr5tFEgB5zy/7Yg81Cn2dhTf1GzjCb7/n3wtJSGtr2QwHsa
# 1ehYWdMfi+ETLoEX1G79VPFrs0t6Giwpr74tv+CLE3s6m10VOwe80wP4yuT3eiFf
# qRV8poUFSdL2wclgQKoSwbCpbJlNC/ESaDQbbQFli9uO5j2f/G7S4TMG/gyyxvMQ
# 5QJui9Fw2s7qklmozQoX2Ah4aKubKe9/VZveiETNYl1AZPj0kj1g51VNyWjvHw+H
# z1xZekWIpfMXQEi0wrGdWeiW4i8l92rY3ZbdHsErFYqzh6FRFOeXgazNsfkLmwy+
# TK17mA7CTEUzaAWMq5+f9K4Y/3mhB4r6UristkWpdkPWEo8b9tbkdKSY00E+FS5D
# UtjgAdCaRBNaBu8cFYCbErh9roWDxc+Isv8yMQAUDuEwXSy0ExnIAlcVIrhzL40O
# sG2ca5R5BgAevGP1Hj9ej4l/y+Sh0HVcN9N6LmPDmI/MaU2rEZ7Y+jRfCZ1d+l5D
# ESdLXIxDTysYXkT+3VM/1zh6y2s0Zsb/3vPaGnp2zejwf2YlGWl1XpChNZTelF5e
# OCCfSzUUn3qHe7IyyDKhahgbnKpmwcEkMVBs+RHbVkNWqDCCB3EwggVZoAMCAQIC
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
# U046MjI2NC1FMzNFLTc4MEMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAESKOtSK7RVVK+Si+aqFd0YSY+VPoIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoFwX6MCIYDzIwMjMwNTIzMTcyOTMwWhgPMjAyMzA1MjQxNzI5MzBaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOgXBfoCAQAwBwIBAAICECIwBwIBAAICEaUw
# CgIFAOgYV3oCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQANk8jHj5PZMeD+
# NFv8wgFkbStZ5XAjT0MeITi6cyZ9fjXMERBdnUwF0MfFWgiLakgdZ8PgDOrtxWcj
# gkKlf5PpNL/lvXB2C/c0CWJDrxpR3hGFjoqa+ocjiHQbqLU0z6hYhlDKiUN/6xwq
# E4c4QXeOCfipNj1KEGp+xjXhXQmwnTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABwT6gg5zgCa/FAAEAAAHBMA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIGqVt5O+3udOjw1hSwfsRVpx6v4GtHbNkuKfLZSMC6dyMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQgCrkg6tgYHeSgIsN3opR2z7EExWA0YkirkvVY
# STBgdtQwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AcE+oIOc4AmvxQABAAABwTAiBCDGuAq1Iedowa94GhcczatrtyRYGO3Uvh4GZF6g
# Eb4MdTANBgkqhkiG9w0BAQsFAASCAgB3bIaNO+bNV2PDI3BBt5+aeT1TEVf19uJO
# xZFaC9OoGLHjXr+oOLHoNOTzF6h38E3WpSTSTYsbsRYeTelNxrmrSv2iFLGhGoTU
# lm2SG9hLqXVkBoq4BJkqekiI7eUcp+qQp9RUlwUt3RhHwR/lTSR6gcZ1pp0M4aLA
# rnNz2OcZqtlhz9qAmfss3O06f+yRNTOdMcsWUPPU9PcuwmeZrgwqCGSsIFQmfxL4
# G+F1m3JaK7X+DfZi8x7mKuhTK8ZgEXLQg2vW8AWZhacp4IbTLRwSe4Ud8la4YKDp
# 8jUld2dCEGQX5HTKI2INxN+NAL4tVEIs3fZjV/zeysV5bJM6MUEJcfGdA8tQ5XPB
# RxNXrFJxDWPHMbcXf15EESdSizsM96fUfS5ClwA0EHbgHAZgDGi2X9wC54YQSYQ7
# aD1ynSUx/j3+drRwUlJ26QyrGCTmKwg9cypmbwNGlkdBHkQHNyQUVcpv4TVWpCFh
# UR7nMSZqXWJp0ubwU1dJrpFYpffoiDukSMrbD/SloiYMTznoWyHyl4SyxI3OWGKw
# hcVHSt2m0LCVWNwCk7Ob2YyHhgoT9dZAyc4LLKC1OWsv8C1LtZw110RQNmkf0smb
# 896nidxuFFdIkoDKgs6xnVTTOro7782SBb6Q/rQ/HjugvAP8y3tgMM1AUyR6nsXj
# SpJQAJWxXQ==
# SIG # End signature block
