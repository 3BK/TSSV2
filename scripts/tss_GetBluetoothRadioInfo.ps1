# Copyright and License https://github.com/Microsoft/busiotools/blob/master/LICENSE
# Script: GetBluetoothRadioInfo.ps1
#region ::::: Script Input PARAMETERS :::::
[CmdletBinding()]param(
 [Parameter(Mandatory=$true, Position=0)] [String] $DataPath
)
$ScriptVer="1.01"	#Date: 2021-05-13


function Get-BluetoothRadioInfo
# SYNOPSIS: collect BluetoothRadio Info
{
	$devices = Get-PnpDevice -Class Bluetooth -EA SilentlyContinue |Where-Object InstanceId -notlike "BTH*"
	if ($null -ne $devices) {
		$radios = New-Object System.Collections.ArrayList
		foreach ($device in $devices)
		{   
			$radio = New-Object PSObject
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "InstanceId" -Value $device.InstanceId
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Bluetooth_RadioAddress'
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "MAC" -Value $(-join ($property.Data |  ForEach-Object { "{0:X2}" -f $_ } ))
			$radios.Add($radio) | Out-Null

			# Driver Info
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Device_DriverDesc'
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "DriverDescription" -Value $property.Data
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Device_DriverVersion'
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "DriverVersion" -Value $property.Data

			# Radio Roles
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Bluetooth_RadioIsCentralRoleSupported'
			$isCentralRole = [boolean]($property.Data)
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Bluetooth_RadioIsPeripheralRoleSupported'
			$isPeripheralRole = [boolean]($property.Data)
			if ($isCentralRole -And $isPeripheralRole) { 
				$role = "Both" 
			} elseif ($isCentralRole) {
				$role = "Central"
			} elseif ($isPeripheral) {
				$role = "Peripheral"
			} else {
				$role = "None"
			}
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "LERole" -Value $role

			# Radio Secure Connections
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Bluetooth_RadioAreBRSecureConnectionsSupported'
			$isBR = [boolean]($property.Data)
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Bluetooth_RadioAreLESecureConnectionsSupported'
			$isLE = [boolean]($property.Data)
			if ($isBR -And $isLE) { 
				$role = "Both" 
			} elseif ($isBR) {
				$role = "BR"
			} elseif ($isLE) {
				$role = "LE"
			} else {
				$role = "None"
			}
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "SecureConnections" -Value $role
			
			# Error Recovery
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName '{A92F26CA-EDA7-4B1D-9DB2-27B68AA5A2EB} 14'
			$supportedTypes = $property.Data
			if ($supportedTypes -eq 0)
			{
				Add-Member -InputObject $radio -MemberType NoteProperty -Name "ErrorRecovery" -Value "None"
			} elseif ($supportedTypes -band 1 -shl 0)
			{
				Add-Member -InputObject $radio -MemberType NoteProperty -Name "ErrorRecovery" -Value "FLDR"
			} elseif ($supportedTypes -band 1 -shl 1)
			{
				Add-Member -InputObject $radio -MemberType NoteProperty -Name "ErrorRecovery" -Value "PLDR"
			}
			
			# Proximal Connections
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName '{A92F26CA-EDA7-4B1D-9DB2-27B68AA5A2EB} 13'
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "ProximalConnections" -Value ([boolean]($property.Data))
			
			# Key Size Enforcement
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName '{A92F26CA-EDA7-4B1D-9DB2-27B68AA5A2EB} 15'
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "KeySizeEnforcement" -Value ([boolean]($property.Data))

			# Extended Advertising
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName '{A92F26CA-EDA7-4B1D-9DB2-27B68AA5A2EB} 16'
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "ExtendedAdvertising" -Value ([boolean]($property.Data))
			
			# LE2MPhy
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName '{A92F26CA-EDA7-4B1D-9DB2-27B68AA5A2EB} 18'
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "LE2MPhy" -Value ([boolean]($property.Data))

			# LECodedPhy
			$property = Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName '{A92F26CA-EDA7-4B1D-9DB2-27B68AA5A2EB} 19'
			Add-Member -InputObject $radio -MemberType NoteProperty -Name "LECodedPhy" -Value ([boolean]($property.Data))
			
		}
		$radios | Format-Table -autosize -Wrap -Property *
	}
} # end of function Get-BluetoothRadioInfo

#region ::::: MAIN ::::
$InfoFileName = $dataPath + '\' + $env:COMPUTERNAME + '_BluetoothRadioInfo.txt'
Get-BluetoothRadioInfo |Out-File $InfoFileName -Width 500
#endregion ::::: MAIN :::::
# SIG # Begin signature block
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB9z1ABWzZKXlfL
# YgqSdXzkW8gnqIW7gnkKzwHuU1v/EaCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINlxewVoCgWxci3NoxahOcso
# UJNVcHI0oz1KssaMxSvJMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAdzhUBmvNy2fx9+jaDTgg11MhPH2NJPsDj6WmTR9iSG4H3snPtXSLUNyP
# r2hQhTXS0J7mEYcn6dcHotXV+2fqkFFPBQa79c3+KcrhG94bLgF3IOPaJPs3Qqq0
# uTWrtgjUlkkyo5wC5yt9rk3Cepe51hpDQZ0VcaFo5H2gyw+e6/BxYP2PdYwxKLFb
# GoM+cDDZr9495U6/4yV3G17RjggjV5hyWA6yTJ3CJRKy2L9snrNcCTPtgERqKaUD
# ON/ePmqfbOP4nArKHmUwiRispMA4bBHWY4+k1A0JoKxcOhWobJSEdO85DxG8Xw0U
# PI3RpXdkj5GzQRiMOEGPD7JlhIISF6GCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCC
# FuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCDA+PmS4NyStKf7gMSwJpjoyfwAT2RTEYxQ7vvDWWtnwQIGZGzYv1Uw
# GBMyMDIzMDYwNjExNDU1MC41NDdaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
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
# BQACBQDoKSMMMCIYDzIwMjMwNjA2MTExNDIwWhgPMjAyMzA2MDcxMTE0MjBaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOgpIwwCAQAwBwIBAAICEDQwBwIBAAICErYw
# CgIFAOgqdIwCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQCS37L16YyPjkdn
# 2yVbTedmKJEBbDfkOae+MI6T4bBUGZ+U+jGlYuZqYBE489vW9n9Ph0lrVEjVcdC6
# syfasRl3BWWQWq3yijZ5MgDsi/ZPJWJtIWIIqFDfnQXBx2ZV4cskei6jJVggnXH4
# bYjZohS8MuwWPUui8MU6wzu0oo7K0DGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABwT6gg5zgCa/FAAEAAAHBMA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIDVVsembSWLxwmG5DIzWgY1OnNM6LGvKr93YWmmaUqt5MIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQgCrkg6tgYHeSgIsN3opR2z7EExWA0YkirkvVY
# STBgdtQwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AcE+oIOc4AmvxQABAAABwTAiBCABv9AtP4ZdbMpajGnqgLBaXg68lbEpYN4pu77q
# 4wOleDANBgkqhkiG9w0BAQsFAASCAgA6a6hjum7YaIV/sUhWMsUVAGPOztbkXODG
# FIigI4aMRp7n2CyPXYshRYZ6nrBllhAwT2hNZcLMLQTW3AktHXpKRr9Q0ywOFBk+
# g21RAtgFRb6EuWHBpgfmCcL9Ka53DGIvaHliKTKW0LdVla0wpsTfCkP+QCsG86pG
# ILBfZa6ZDOR3VArMutWCUg0f60lYzl6Bs8KCe9UyCgffvX0uwuv05Ucovp18McON
# yEUz6g6yvHHELNxvVgHmHJDncgzimkD0ZSSkSotkH038Ka/2IXHUGHpOZoqb9Gn2
# rRv4FAgBE2tp5EInA1Tvda3rSYnKe7ypPkX6icLddjcj8nHlmpaMb1G6JktkDqLJ
# J4i6/1q5sQRvZk1w5eHqJHFA17eLYiHSWdU81JGWYqz6gAfoakjQRf84wrwpC5XE
# IUcTrhb0MBBTVpHrfAQW605e7s6TmW7jbm8mMzdTU1/+PDR5VJkoJe7I5/32POUJ
# lnp90dy6n5KI0cGtdtmUnhQok1dqge9UH0OluJdbQaRrRAseli2cHqM8dN6HNbr8
# a/raC1myug48bplD33FbUxKAIUc1F4cj71cdRvHRWrvZmqfRDqHqL/ifUI7hWRXH
# lc/R79Kf15r5koordt7BcDqPcgpEupbPW5K6U+QEmN1jvx5ow74MFgftLXUhs5NU
# wLGOHApGbQ==
# SIG # End signature block