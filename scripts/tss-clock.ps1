Param (
    [Parameter(Mandatory=$False)]
    [switch]$noTopMost # Usually this is used with RDS/AVD scenario.
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName PresentationFramework  # We load WPF for DPI awareness
[xml]$Xaml= @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    x:Name="Window"></Window>
"@
$Reader= (New-Object System.Xml.XmlNodeReader $Xaml)
$Window= [Windows.Markup.XamlReader]::Load($Reader)
$IsHighDPI = $False

$LogPixels = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontDPI" -ErrorAction Ignore).LogPixels
If($Null -ne $LogPixels -and $LogPixels -ge 144){
    $IsHighDPI = $True
}

###           ###
### Functions ###
###           ###
Function UpdateTimeLabel{
    $Date = Get-Date -Format "yyyy/MM/dd"
    $Time = Get-Date -Format "HH:mm:ss"
    $DateLabel.Text = "$Date`n$Time"
}

###             ###
### Window Form ###
###             ###
$Form = New-Object System.Windows.Forms.Form
If($IsHighDPI){
    $FormHight=380
    $FormWidth=400
}Else{
    $FormHight=255
    $FormWidth=300
}
$Form.Size = New-Object System.Drawing.Size($FormWidth,$FormHight)

# Titile bar
$Form.Text = "TSS Clock"
$Form.FormBorderStyle = 3 # FixedDialog
If(!$noTopMost.IsPresent){
    $Form.Topmost = $True		# keep TSS clock Topmost
}
# Color. Set Windows 11 color style.
$Form.BackColor = "#E8F1F8"

# Window position
$Form.StartPosition = 0 # FormStartPosition.Manual
$Screens = [System.Windows.Forms.Screen]::PrimaryScreen	#we# was ::AllScreens- fix ADO#433
$Left = $Screens.WorkingArea.Width * 0.05
$Top = $Screens.WorkingArea.Height * 0.1
$Form.Location = New-Object System.Drawing.Point($Left,$Top)

###       ###
### Label ###
###       ###
If($IsHighDPI){
    $DateLabelPosition = 140
}Else{
    $DateLabelPosition = 70
}
# Date
$DateLabel = New-Object System.Windows.Forms.Label
$DateLabel.AutoSize = $False
$DateLabel.Size = New-Object System.Drawing.size($FormWidth,$DateLabelPosition)
$DateLabel.Font = New-Object System.Drawing.Font("Segoe UI",20)
$DateLabel.ForeColor = "#0078D4"
$DateLabel.TextAlign = 32 # MiddleCenter

# Computer/User/Session
If($IsHighDPI){
    $InfoLabelPosition = 140
    $InfoLabelSize = 130
}Else{
    $InfoLabelPosition = 80
    $InfoLabelSize = 100
}
$InfoLabel = New-Object System.Windows.Forms.Label
$InfoLabel.AutoSize = $False
$InfoLabel.Location = New-Object System.Drawing.Point(25,$InfoLabelPosition)
$InfoLabel.Size = New-Object System.Drawing.size($FormWidth,$InfoLabelSize)
$InfoLabel.Font = New-Object System.Drawing.Font("Segoe UI",10)
$InfoLabel.ForeColor = "#281E5D"
$SessionID = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
# Issue#334 - add Timezone info to clock display
#we# If($PSVersionTable.PSVersion.Major -le 4){ # PowerShell 4.0
If(($PSVersionTable.PSVersion.Major -le 4) -or ($global:OSBuild -le 9600)){ # PowerShell 4.0 / #we# Get-TimeZone fails on Srv2012R2 with PS v5.0 
    $TimeZone = [System.TimeZoneInfo]::Local.DisplayName
}Else{
    $TimeZone = (Get-TimeZone).DisplayName
}
$InfoLabel.Text = "Computer: $ENV:COMPUTERNAME`nUser: $ENV:USERNAME`nSession: $SessionID`nTZ: $TimeZone"

# Footer
If($IsHighDPI){
    $FooterLabelPosition = 260
    $FooterLabelSize = 70
}Else{
    $FooterLabelPosition = 170
    $FooterLabelSize = 50
}
$FooterLabel = New-Object System.Windows.Forms.Label
$FooterLabel.AutoSize = $False
$FooterLabel.Location = New-Object System.Drawing.Point(0,$FooterLabelPosition)
$FooterLabel.Size = New-Object System.Drawing.size($FormWidth,$FooterLabelSize)
$FooterLabel.Font = New-Object System.Drawing.Font("Segoe UI",9)
$FooterLabel.Text = "PLEASE do NOT close this window `nor any TSS related windows OPENED!"
$FooterLabel.BackColor = "#1F456E"
$FooterLabel.ForeColor = "#FFFFFF"
$FooterLabel.TextAlign = 32 # MiddleCenter

UpdateTimeLabel # Set $DateLabel.Text

###       ###
### Timer ###
###       ###

# Update clock using Timer with 1 sec interval.
$Timer = New-Object System.Windows.Forms.Timer
$Timer.Interval = 1000
$DisplayedTime = "(Get-Date -Format `"yyyy/MM/dd`")`n(Get-Date -Format `"HH:mm:ss`")"
$UpdateTime = {UpdateTimeLabel} # Call UpdateTimeLabel()
$Timer.Add_Tick($UpdateTime)
$Timer.Enabled = $True

# We are all set. Add components and show the window.
$Form.Controls.Add($FooterLabel)
$Form.Controls.Add($InfoLabel)
$Form.Controls.Add($DateLabel)
$Form.Add_Shown({$Form.Activate()})
$Ret = $Form.ShowDialog()  # Script stops here.

# Release instances.
$DateLabel.Dispose()
$InfoLabel.Dispose()
$FooterLabel.Dispose()
$Form.Close()
$Form.Dispose()

# SIG # Begin signature block
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCARpVUfdSdGpn4J
# jxzuSzCLlZVVzNmM1x1rNfUPsd4876CCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILv+GtaEMQPAGPGaGH3gPAAV
# cnP/F89Dz4w5XA546cAsMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAhGbSt7pHkdw+lEQR5jGR/RvxkEuoih3280vAONvBZMMzzptwzCfeNxUf
# ML9vvgTUjCyydNwHGpQ28/Yu3RhFOg6PvweE7D7GB6bAyP511mc/PGh4mtLWPusq
# gbeuIL4/7FNK3bJ51WFPkv5KSEl/ZJiQQhzlYgbvVwj/ftWbGcX7nmgriNbmQV+e
# V8pCM+zUVj5+oI2ChInD7osjLdu+RQuqXQerZ3ogtyiQ42A0kDpIBxVAjyIaLN+N
# iQOHXeLkcRg6ZFuijYoLHoQOJ72kqaZhkpfH1+yS2+7akyWIO7SR8DiUsTU7p0T2
# kNcEGnNzSZRIMhQ3kO1oz5d2r+VuOqGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCC
# FuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCBSSlmOi+iD7Tq8PIkpFzf7HIAoL42sHAe8SuQM3LDgagIGZGzVO1+0
# GBMyMDIzMDYwNjExNDU1Mi44OTFaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo3QkYxLUUz
# RUEtQjgwODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVQwggcMMIIE9KADAgECAhMzAAAByPmw7mft6mtGAAEAAAHIMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEz
# N1oXDTI0MDIwMjE5MDEzN1owgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjdCRjEtRTNFQS1CODA4MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAucudfihPgyRWwnnIuJCqc3TCtFk0XOimFcKjU9bS6WFn
# g2l+FrIid0mPZ7KWs6Ewj21X+ZkGkM6x+ozHlmNtnHSQ48pjIFdlKXIoh7fSo41A
# 4n0tQIlwhs8uIYIocp72xwDBHKSZxGaEa/0707iyOw+aXZXNcTxgNiREASb9thlL
# ZM75mfJIgBVvUmdLZc+XOUYwz/8ul7IEztPNH4cn8Cn0tJhIFfp2netr8GYNoiyI
# qxueG7+sSt2xXl7/igc5cHPZnWhfl9PaB4+SutrA8zAhzVHTnj4RffxA4R3k4BRb
# PdGowQfOf95ZeYxLTHf5awB0nqZxOY+yuGWhf6hp5RGRouc9beVZv98M1erYa55S
# 1ahZgGDQJycVtEy82RlmKfTYY2uNmlPLWtnD7sDlpVkhYQGKuTWnuwQKq9ZTSE+0
# V2cH8JaWBYJQMIuWWM83vLPo3IT/S/5jT2oZOS9nsJgwwCwRUtYtwtq8/PJtvt1V
# 6VoG4Wd2/MAifgEJOkHF7ARPqI9Xv28+riqJZ5mjLGz84dP2ryoe0lxYSz3PT5Er
# KoS0+zJpYNAcxbv2UXiTk3Wj/mZ3tulz6z4XnSl5gy0PLer+EVjz4G96GcZgK2d9
# G+uYylHWwBneIv9YFQj6yMdW/4sEpkEbrpiJNemcxUCmBipZ7Sc35rv4utkJ4/UC
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBS1XC9JgbrSwLDTiJJT4iK7NUvk9TAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQDD1nJSyEPDqSgnfkFifIbteJb7NkZCbRj5yBGiT1f9fTGvUb5CW7k3eSp3uxUq
# om9LWykcNfQa/Yfw0libEim9YRjUNcL42oIFqtp/7rl9gg61oiB8PB+6vLEmjXkY
# xUUR8WjKKC5Q5dx96B21faSco2MOmvjYxGUR7An+4529lQPPLqbEKRjcNQb+p+mk
# QH2XeMbsh5EQCkTuYAimFTgnui2ZPFLEuBpxBK5z2HnKneHUJ9i4pcKWdCqF1AOV
# N8gXIH0R0FflMcCg5TW8v90Vwx/mP3aE2Ige1uE8M9YNBn5776PxmA16Z+c2s+hY
# I+9sJZhhRA8aSYacrlLz7aU/56OvEYRERQZttuAFkrV+M/J+tCeGNv0Gd75Y4lKL
# Mp5/0xoOviPBdB2rD5C/U+B8qt1bBqQLVZ1wHRy0/6HhJxbOi2IgGJaOCYLGX2zz
# 0VAT6mZ2BTWrJmcK6SDv7rX7psgC+Cf1t0R1aWCkCHJtpYuyKjf7UodRazevOf6V
# 01XkrARHKrI7bQoHFL+sun2liJCBjN51mDWoEgUCEvwB3l+RFYAL0aIisc5cTaGX
# /T8F+iAbz+j2GGVum85gEQS9uLzSedoYPyEXxTblwewGdAxqIZaKozRBow49OnL+
# 5CgooVMf3ZSqpxc2QC0E03l6c/vChkYyqMXq7Lwd4PnHqjCCB3EwggVZoAMCAQIC
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
# U046N0JGMS1FM0VBLUI4MDgxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAN/OE1C7xjU0ClIDXQBiucAY7suyoIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoKR78MCIYDzIwMjMwNjA2MTA1NzAwWhgPMjAyMzA2MDcxMDU3MDBaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOgpHvwCAQAwBwIBAAICJrEwBwIBAAICEW4w
# CgIFAOgqcHwCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQBagqAwDqo3JECP
# 1EZQbP5BZJWdFg4XRT3jXH9woEPG5iRdyEeqovan/XMAb5CoRVUPwyWTfqfqf2iC
# D4QzPJPNMmjNOLANInONImuJvXA7CioFXeDO0k1QsuZazbMLXvGXq5qYFFaPJMfw
# 8Uw0BrlqiCYorIaMRvK5vbI3JCsvVDGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAByPmw7mft6mtGAAEAAAHIMA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIMxmZ188RIn3C6eZ1MIRfm2M6dRtYUIU8G0a2IHaz08SMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQgYgCYz80/baMvxw6jcqSvL0FW4TdvA09nxHfs
# PhuEA2YwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# Acj5sO5n7eprRgABAAAByDAiBCB4oOXWdN298RrWHfuEENvkCjSxUg/ZtmMChlYp
# Y6wB6TANBgkqhkiG9w0BAQsFAASCAgBevvjh0aJKV2lyqkqA98MI/1Q4dFFDk9Cn
# z3V95OlAn0vGM+GZbyeKO/NPedijjnomRp2dkt7gBpZNrPsg27Q8M8qvlieyY+wI
# pzddQArcv4IR+InTGSO5WGpjfEoTUjRJb71ZJX64Avzd87OOumslechSpHS+D9Ox
# GCdeIyVAOcfrK7itMG1eHfJErkCRiDDS8mRz3oJ8tcSdkJ5HS4SExWJmeqIevw8t
# hoGZtWbI8s5FzgUW0DJ/jw2YsSV/g2Hrsc4IOzk0+rsQymU6f5n3QE1xFf4f2j1i
# Gj4jXrb7i/TT+T2C8gk2crqVgXSJiXMe89K0WNka4mzOvfMiQup/nhb0DJvVPdOa
# 06nJqnatoaovDwAOtWEvvNI4hWJ/LlkoaQPVHwv/1dau8IcTTVqCl+YNLLKR6pxa
# aEAXGpqBXdKHljcKFhyPg+T8CRmlYvsgOVef5AJm8t0c7PQf4SsgQ+FYQcQ0Djst
# T2DG5gxX+/tO6nDlSZP2HYdbU1/u8F1JyQ0MtQmAJ75qjj6C9bvjZO5AM1i0Di17
# QlaLFOcVUS+bs34KBOdBwC9tI1ZwVMZUPZG4N4eRbwzUU8tCVgFwSMcmUaU0bQny
# y2AjdUeGTKU2agXrFfI4krS3hoP83aGdBQt7APoyPqDqhSIUIVlmLGJlTrDK7JiQ
# HNc+JrgTQQ==
# SIG # End signature block
