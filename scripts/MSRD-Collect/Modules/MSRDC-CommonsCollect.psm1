<#
.SYNOPSIS
   MSRD-Collect 'data collection' specific functions

.DESCRIPTION
   Module for the MSRD-Collect local 'data collection' functions

.NOTES
   Authors    : Robert Klemencz (Microsoft) & Alexandru Olariu (Microsoft)
   Requires   : At least PowerShell 5.1 (This module is not for stand-alone use. It is used automatically from within the main MSRD-Collect.ps1 script)
   Version    : See MSRD-Collect.ps1 version
   Feedback   : Send an e-mail to MSRDCollectTalk@microsoft.com
#>

Function msrdGetRegKeys {
    [CmdletBinding()]
    Param([string]$LogPrefix,[string]$RegPath,[string]$RegFile)

    $RegExport = $RegPath.Replace(":", "")
    $RegRoot = (Split-Path -Path $RegPath -Qualifier).Replace(":", "")
    $RegOut = "$msrdRegLogFolder$global:msrdLogFilePrefix$RegRoot-$RegFile.txt"

    msrdLogMessage Normal "[$LogPrefix] reg export '$RegExport'"

    if (Test-Path $RegPath) {
        Try {
            reg export "$RegExport" "$RegOut" > $null
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
        msrdLogMessage WarnLogFileOnly "[$LogPrefix] Reg key '$RegExport' not found."
    }
}

Function msrdGetEventLogs {
    Param($LogPrefix, [string]$EventSource, [string]$EventFile)

    $EventOut = Join-Path $global:msrdEventLogFolder "$global:msrdLogFilePrefix$EventFile.evtx"

    msrdLogMessage Normal ("[$LogPrefix] wevtutil epl/al '$EventSource'")
    
    if (Get-WinEvent -ListLog $EventSource -ErrorAction SilentlyContinue) {
        Try {
            wevtutil epl "$EventSource" "$EventOut" | Out-Null
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

        Try {
            wevtutil al "$EventOut" /l:en-us | Out-Null
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
        msrdLogMessage WarnLogFileOnly "[$LogPrefix] Event log '$EventSource' not found."
    }
}

Function msrdGetLogFiles {
    Param([string]$LogPrefix,[string]$LogFilePath,[string]$LogFileID,[ValidateSet("Files","Packages")][string]$Type, [string]$OutputFolder)

    msrdLogMessage Normal ("[$LogPrefix] Copy-Item '$LogFilePath'")

    if (-not (Test-Path -Path $LogFilePath)) {
        msrdLogMessage WarnLogFileOnly "[$LogPrefix] '$LogFilePath' not found."
        return
    } else {
        switch ($Type) {
            "Files" {
                $LogFile = Join-Path $OutputFolder "$env:computername`_$LogFileID.txt"
                Try {
                    Copy-Item -Path $LogFilePath -Destination $LogFile -ErrorAction Continue -Force 2>&1 | Out-Null
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
}

function msrdGetRDRoleInfo {
    param ($Class, $Namespace, $ComputerName = "localhost")

    Get-CimInstance -Class $Class -Namespace $Namespace -ComputerName $ComputerName -ErrorAction Continue 2>>$global:msrdErrorLogFile

}

function msrdCloseMSRDC {

    # Get the MSRDC process if it is running
    $msrdc = Get-Process msrdc -ErrorAction SilentlyContinue

    if ($msrdc) {
        $rdcnotice = @"
The AVD Windows Desktop client (MSRDC) is currently running on this machine.
To collect the most recent Windows Desktop client specific ETL traces, MSRDC.exe must be closed first.

Do you want to close MSRDC.exe now?
This will disconnect all currently active AVD connections on this machine, which were initiated through this client!
"@

        $msrdcResult = [System.Windows.Forms.MessageBox]::Show($rdcnotice, "Are you sure you want to continue?", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    
        if ($msrdcResult -eq [System.Windows.Forms.DialogResult]::Yes) {
            msrdLogMessage Info "Closing MSRDC.exe ..."
            # Try to close the MSRDC window gracefully
            $msrdc.CloseMainWindow() | Out-Null
            Start-Sleep -Seconds 5

            # If the process is still running, kill it forcefully
            if (!$msrdc.HasExited) { $msrdc | Stop-Process -Force }

            msrdLogMessage Info "MSRDC.exe has been closed. Waiting 20 seconds for the latest trace file(s) to get saved before continuing."
            Start-Sleep -Seconds 20
        } else {
            msrdLogMessage Info "MSRDC.exe has not been closed. The most recent ETL traces will NOT be available for troubleshooting! Continuing data collection."
        }
    }
}

Export-ModuleMember -Function *
# SIG # Begin signature block
# MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCgYFrKji2eKdVb
# 6vl+/Pp/VMYx8oEzrLVQw+V1PfajwaCCDYUwggYDMIID66ADAgECAhMzAAADTU6R
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPy0
# QuuVUNcwdLzFcVFqpXggDxdlZM6/pqCeyxE+8EebMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAgSKCjknejHyJocoql85mHdAjTeQmE7SbRvlH
# S6Ig4Ms/LB9QVbqFPi6lNHQeSOMYyDzNc/QvRuVLT7tBcyk8blxYfk8RZu0Rk3VZ
# cMnLD7FDkO11z3DIs1eTx7uDfBLBl073HR87LQ4JQNs42Du9bdTzeegw+oeI+Rl+
# NmyfUgLUt5RmlOFC2aOtM875TxjEsF8MA5beJkloXPBARIhJMkKzayYjmf5o3GWe
# BYcxeyrTMIjfS0UuluTaeVa6/tMcX0DIFySMJG9iFZDahbyYL9q83rjd6SeymHRl
# umOD0jxl1zQOBKCfojyG58IrMsy7/ZgRvUwfyUkzbLoX+QuW5aGCFv0wghb5Bgor
# BgEEAYI3AwMBMYIW6TCCFuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCCeKsMYYIU8lI+CTYK7XkP9VKyD/VlE5fQb
# Rj3pcCc8TQIGZF1yocNkGBMyMDIzMDUyMzE0NDQ1Mi44NTZaMASAAgH0oIHQpIHN
# MIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjpFQUNFLUUzMTYtQzkxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEVQwggcMMIIE9KADAgECAhMzAAABw4tv00i/DpFdAAEA
# AAHDMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMTEwNDE5MDEyOVoXDTI0MDIwMjE5MDEyOVowgcoxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkVBQ0UtRTMx
# Ni1DOTFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAu+u86s3R/q+ikos80aD42Ym2
# 1NDOZtldNRxMFUxm4o9kVWkSh2c8jOCxJXwV2KFodCTxpGQs9jy5nUI+Lq/bt0HW
# tSYPMPPtet420gzwM1EsR26kbpwlBHxFY4hk3y3AH+1YKf9bhvPs7kPbXbH7gdac
# iteB+F7FoORt9e0D/dsBeG80GZAF2y6LWAj6C2mMqlafXkwbfTyQanuX65Yu+xMp
# yJ1fAREpuR766rePrqlE0KaaeD0nqOgGrTkSZeCMDPH6OtJ00jXMwbIDyH7l4fYR
# eIsTfzN5Gf3Uairsjea+KFy22lU8elnIXjoeyx3pcesH+q5arY1c6HPfeSnkeMok
# /gxnB7P1Mjt7I9EI9thQtMvy/1SUmLG12rBR/DfheE/VJpcm/TYeoV11NfQQnl/j
# BbPbSRBp0HGqTIcWDpY6MgSdBoQET1DvpE4PX4sndNGc1wGyg45pH62ZMfUF/CzG
# Z7iV637RtnQFXDzTxoSEEkdXMdWDJG+jjxoC16lRk1xFnfkA4uoma4mKso7qvE6d
# 27+K6yzISWQ7TjutYLKJnSzNvfiNiuyv/0xxCASSARvOQ3v9cegvM/pnuU9c6s+4
# gmK3+5jhcvnWGQqJE0tpYHmk3bmmBL1gHm9TjBJz5m/8rvHM3Rw3OUhV4/wmAL32
# KmPR5Ubb4ww5HNGiuY0CAwEAAaOCATYwggEyMB0GA1UdDgQWBBQcGL7N2NdvAaK8
# TcLrxMTsa8aB1jAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
# KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4ICAQDd8qZbHBqdBFRDxGGwDollnRyd0WmUnjqoP+5QCH4v
# MPBt4umHVhJuyeRkDELkTWZuWqK3U1z2HnGatbnETcHUlywlH+3I7R7fU0zKYw2P
# LA+VawCcrnsICgE3242EsEC/Z0YU740NJ/xbuzrGtTEtUIiQvr2ACPJyhsPote8I
# tTf4uNW4Mbo1QP0tjcBKCgEezIC4DYUM0BYCWCmeZmNwAlxfpTliOFEKB9UaSqHS
# s51cH8JY0gqL3LwI9LYfjEO77++HY/nMqXCMi9ihUKoIp2Tfjfzdm5Ng5V+yw8+w
# Xl29RcW4Q4CvHntNfKxT9oQ3J7YBQQEHWJPg8TNR9w4B82FzmrDd8sL6ETvGux5h
# FcwmF+Q2rT5Ma8dYUSdCSg/ihoEYUGJZnZL9nyDp1snflSVX7FpLyALzDDlHBW1C
# JhYVffJRoqz1D4kRooqRBNRaMFMPingywwbEghMheJKNoda7AGgq+1HH1afRlE+9
# qYW9FKMezxeQmf8gcuAuhr9IAXyaF9DF0PJ5f4uhzOSvIC1BkJtzF6op45UYaI7V
# +9X8dcwXbZJnIIAH1cjVO8KEChxKIkpk4Qgy0PocgUwaGWqmLWRu1hQ1WJWnQXvv
# BYeYDGWbj/PtSlywv6m8mujLepfMvJcU25KWklSP2FuNx6aOVfeje+pgbwIQIVQ1
# nTCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQEL
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
# CxMdVGhhbGVzIFRTUyBFU046RUFDRS1FMzE2LUM5MUQxJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAPEdL+Ps+h03
# e+SLXdGzuY7tLu7OoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwDQYJKoZIhvcNAQEFBQACBQDoFxohMCIYDzIwMjMwNTIzMTg1NTI5WhgPMjAy
# MzA1MjQxODU1MjlaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOgXGiECAQAwBwIB
# AAICD2AwBwIBAAICEdgwCgIFAOgYa6ECAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYK
# KwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUF
# AAOBgQBKOMt27Y3974CEO2XDQFuBkGtinu4HzUP/CAlbQi5qyGZELKz9dYGD8XXN
# 3kHVHmE/5EJ/8K12KBXcIuD8PdwXvkI1mLWoHiMM/AHy6/TrOD1vtdDyJrYXpaZ7
# XOGhIT2zZPWK01aCtGqG4NgwbfcaXNkd62pYmkIgDvq3+Uf7gDGCBA0wggQJAgEB
# MIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABw4tv00i/DpFd
# AAEAAAHDMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwLwYJKoZIhvcNAQkEMSIEIK47x2vl39++ALuKzypQLtboB+7FHsI8k1A4
# hNSY55rmMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg0vtTm2+SSerh1KiA
# kwrJTALxTfJotlPcDZ2ZSn78KkkwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAcOLb9NIvw6RXQABAAABwzAiBCDyqIfp5kPZPtjaZONG
# C9E+utsWnslP5tXR8f9Topy7bjANBgkqhkiG9w0BAQsFAASCAgAfI/y6NfZI1/U9
# Tp7AcjxT2cabCT5i5+wxMT5URmMKdRYCrqMGsBnYKmb1R9gcqddI45zdngim1CsW
# RZzf7fx68Qw7dSLVLivoAe4YiEAbQIVRYAbht+hMHgIEFSLJqUIPrpEGyyE5ds6W
# /jkC2TOI6H/E2x5qlwTTIj43mFkSwgJYWhMSzlUgevb1KSyJuw4zK2NAynx2cLuU
# +QS9TXt1iCvj2SnBbYlI1fVvffTcr93brqwmYATfErDIJEYwUBHzUl/yZzIKDVU4
# 2z9hIDaa3MUpGJFWjF0IjEM/fWhDhFO8wP+bGzp2LREocpSUME8xy01mvMq7GKof
# oMF0e+BIdatfrsTV5t9qBWQAYU2OWnZBqmgUYDUqoiu9Imw/ObKIycQUe9W6hjFv
# EmYgW/KqNP2JFtltckHILuLemZJFf6IGzRywGg9UNX9DwUVx3U4fgSUDhZ/KIvxD
# YI/AUa+uWNgzwwvknbNUarPMwd08T4kUs9V9zcdW2CwiczcPa01PenvhXEERVU1o
# JfV3xBg/B8iGBNAWomiJwDh/8m3fmn0MkV7p7f6BJBMEkuu1DJU5NYTvG04Yt73t
# 0/3p0/1aj1ibnWqaBgUkGny3gOvWOpPZcnBNkk9C0uzEwvk5mjVZEyAXBMM3hwIt
# bMLJX6B1w4DEs+6DFw5bVLhbvqTiSw==
# SIG # End signature block
