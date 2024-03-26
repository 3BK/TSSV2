<# Script name: tss_DAclient-collector.ps1
Purpose: - a script you can use to generate the same information that the DCA generates for DirectAccess
 see also DARA: DirectAccess troubleshooting guide https://internal.support.services.microsoft.com/en-US/help/2921221
#>

param(
	[Parameter(Mandatory=$False,Position=0,HelpMessage='Choose a writable output folder location, i.e. C:\Temp\ ')]
	[string]$DataPath = (Split-Path $MyInvocation.MyCommand.Path -Parent)
)

$ScriptVer="1.01"	#Date: 2018-12-19
$logfile = $DataPath+"\_DirectAccessCli_"+$env:COMPUTERNAME+"_"+(Get-Date -Format yyddMMhhmm)+".txt"

Write-Host "v$ScriptVer Starting collection of debug information for DirectAccess Client on this machine ..." -ForegroundColor White -BackgroundColor DarkGreen
Write-Host "... resulting Logfile: $logfile"
$user = whoami
write-output "v$ScriptVer - Direct Access connectivity status for user: $user is" | out-file -Encoding ascii $logfile
$date = Get-date
Write-output "DATE: $date" | Out-File -Encoding ascii -Append $logfile


# Get a List of all available DTEs
$RegDTEs = get-item hklm:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityAssistant\DTEs -EA SilentlyContinue
$DTEs=($RegDTEs).property -split ("PING:")
$DTEs= $DTEs | Where-Object {$_}
# $DTEs

# Get a List of all available Probes
# Separate them into icmp and http probes
$RegProbes = get-item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityAssistant\Probes" -EA SilentlyContinue
$probelist = ($RegProbes).property
$httpprobe = New-Object System.Collections.ArrayList
$ICMPProbe = New-Object System.Collections.ArrayList
foreach($probe in $probelist)
	{
		if($probe -match "http") {	$httpprobe = $httpprobe + $probe}
		else					 {	$ICMPProbe = $ICMPProbe + $probe}
	}
$httpprobe = $httpprobe -csplit "HTTP:"
$httpprobe = $httpprobe | Where-Object {$_}
$icmpprobe = $icmpprobe -csplit "PING:"
$icmpprobe = $icmpprobe | Where-Object {$_}

# $httpprobe
# $icmpprobe

# check if each of the probe URLs are accessible
if($httpprobe -gt 0)
{
Write-output "`n =============HTTP PROBES=============" | Out-File -Encoding ascii -Append $logfile
foreach ($URL in $httpprobe)
	{
		$result = (Invoke-WebRequest -Uri $URL).statusdescription
		Invoke-WebRequest -Uri $url -ErrorAction SilentlyContinue -ErrorVariable test
		if($result = 'OK' -and !$test)
			{    write-output "$url Pass" | Out-File -Encoding ascii -Append $logfile}
		elseif ($test -match "Unable to connect to the remote server" )
			{	write-output "$url (NAME Resolved)" | Out-File -Encoding ascii -Append $logfile}
		else 
			{	write-output "$url Failed" | Out-File -Encoding ascii -Append $logfile}
	}
}
else
{
Write-output "There are no HTTP probes configured" | Out-File -Encoding ascii -Append $logfile
}	

# check if each ICMP probe is accessible
if($icmpprobe -gt 0)
{
Write-output "`n =============ICMP PROBES=============" | Out-File -Encoding ascii -Append $logfile
foreach($ip in $icmpprobe)
	{
		$result = ping $ip -n 1
		if($result -match "Packets: Sent = 1, Received = 1, Lost = 0")
			{	write-output "$ip PASS" | Out-File -Encoding ascii -Append $logfile}
		elseif($result -match "Pinging")
			{	write-output "$ip Name resolved But ping failed" | Out-File -Encoding ascii -Append $logfile}
		else
			{	write-output "$ip Failed to resolve name" | Out-File -Encoding ascii -Append $logfile}
	}
}
else 
{
Write-output "There are no ICMP probes configured" | Out-File -Encoding ascii -Append $logfile
}

# check if DTEs are pingable
Write-output "`n =============DTEs=============" | Out-File -Encoding ascii -Append $logfile
if ($DTEs) {
  foreach($ip in $DTEs)
	{
		$result = ping $ip -n 1
		if($result -match "Packets: Sent = 1, Received = 1, Lost = 0")
			{	write-output "DTE: $ip PASS" | Out-File -Encoding ascii -Append $logfile}
		else
			{	write-output "DTE: $ip Fail" | Out-File -Encoding ascii -Append $logfile}
	}		
  }
  else
			{	write-output "There are no DTE's to test configured in `n HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityAssistant\DTEs " | Out-File -Encoding ascii -Append $logfile}

Write-output "`n _____ IP Configuration (Get-NetIPConfiguration -All -Detailed)" | Out-File -Encoding ascii -Append $logfile
Get-NetIPConfiguration -All -Detailed | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ System Info (systeminfo)" | Out-File -Encoding ascii -Append $logfile
systeminfo | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ 6to4 State (Netsh int 6to4 show state)" | Out-File -Encoding ascii -Append $logfile
Netsh int 6to4 show state | Out-File -Encoding ascii -Append $logfile
Write-output "`n _____ teredo State (Netsh int teredo show state)" | Out-File -Encoding ascii -Append $logfile
Netsh int teredo show state | Out-File -Encoding ascii -Append $logfile
Write-output "`n _____ httpstunnel Int (Netsh int httpstunnel show int)" | Out-File -Encoding ascii -Append $logfile
Netsh int httpstunnel show int | Out-File -Encoding ascii -Append $logfile
Write-output "`n _____ dnsclient State (Netsh dnsclient show state)" | Out-File -Encoding ascii -Append $logfile
Netsh dnsclient show state | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ 6to4 Configuration (Get-Net6to4Configuration)" | Out-File -Encoding ascii -Append $logfile
Get-Net6to4Configuration | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ Proxy Configuration (netsh winhttp show proxy)" | Out-File -Encoding ascii -Append $logfile
netsh winhttp show proxy | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ Teredo Configuration (Get-NetTeredoConfiguration)" | Out-File -Encoding ascii -Append $logfile
Get-NetTeredoConfiguration | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ Teredo State (Get-NetTeredoState)" | Out-File -Encoding ascii -Append $logfile
Get-NetTeredoState | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ HTTPs Configuration (Get-NetIPHttpsConfiguration)" | Out-File -Encoding ascii -Append $logfile
Get-NetIPHttpsConfiguration | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ IP-HTTPs State (Get-NetIPHttpsState)" | Out-File -Encoding ascii -Append $logfile
Get-NetIPHttpsState | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ Certificate Store (root) (certutil -store root)" | Out-File -Encoding ascii -Append $logfile
certutil -store root | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ NRPT Policy (Get-DnsClientNrptPolicy)" | Out-File -Encoding ascii -Append $logfile
Get-DnsClientNrptPolicy | Out-File -Encoding ascii -Append $logfile
Write-output "`n _____ NCSI Policy (Get-NCSIPolicyConfiguration)" | Out-File -Encoding ascii -Append $logfile
Get-NCSIPolicyConfiguration | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ Winsock Catalog (netsh winsock show catalog)" | Out-File -Encoding ascii -Append $logfile
netsh winsock show catalog | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ WFP Netevents (netsh wfp show netevents file=-)" | Out-File -Encoding ascii -Append $logfile
netsh wfp show netevents file=- | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ IPsec Rules (Show-NetIPsecRule -PolicyStore ActiveStore)" | Out-File -Encoding ascii -Append $logfile
Show-NetIPsecRule -PolicyStore ActiveStore | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ IPsec Main Mode SA's (Get-NetIPsecMainModeSA)" | Out-File -Encoding ascii -Append $logfile
Get-NetIPsecMainModeSA | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ IPsec Quick Mode SA's (Get-NetIPsecQuickModeSA)" | Out-File -Encoding ascii -Append $logfile
Get-NetIPsecQuickModeSA | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ IP Address (Get-NetIPAddress)" | Out-File -Encoding ascii -Append $logfile
Get-NetIPAddress | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ Route (Get-NetRoute)" | Out-File -Encoding ascii -Append $logfile
Get-NetRoute | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ DA Multisite (Get-DAEntryPointTableItem)" | Out-File -Encoding ascii -Append $logfile
Get-DAEntryPointTableItem | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ DA ConnectionStatus (Get-DAConnectionStatus)" | Out-File -Encoding ascii -Append $logfile
$DaStat_Temp = Get-DAConnectionStatus -EA SilentlyContinue
if ($DaStat_Temp) {
		Get-DAConnectionStatus | Out-File -Encoding ascii -Append $logfile}
Write-output "`n _____ DA Settings (Get-DAClientExperienceConfiguration)" | Out-File -Encoding ascii -Append $logfile
Get-DAClientExperienceConfiguration | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ Prefix Policy Table (Get-NetPrefixPolicy)" | Out-File -Encoding ascii -Append $logfile
Get-NetPrefixPolicy | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ Certificate Store (my) (certutil -silent -store -user my)" | Out-File -Encoding ascii -Append $logfile
certutil -silent -store -user my | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ Groups (whoami /all)" | Out-File -Encoding ascii -Append $logfile
whoami /all | Out-File -Encoding ascii -Append $logfile

Write-output "`n _____ === END of DAclient collector ===" | Out-File -Encoding ascii -Append $logfile	

Write-Host "$(Get-Date -Format 'HH:mm:ss') Done - tss_DAclient-collector`n" -ForegroundColor White -BackgroundColor DarkGreen
# SIG # Begin signature block
# MIInkgYJKoZIhvcNAQcCoIIngzCCJ38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCACji+T5RwWtKZm
# 2GTHPvB1gORPisnPxsUzvRCMsUapZ6CCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXIwghluAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIEXeX2XCDFTOHAWU0vZ/dGw6
# A+wddXvMkZwjmm9hwrcdMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAZTy1rriIpfLjHMuBEMT+I7Obo2rOgg89KjHrrku2siRUk9QuqrhQ4pj/
# UXAIsDwHiflWrNOAlLd1auzfRJMmHAPRUBq4z5IlfpCteQV8QFK+dgXmqNnM1bLY
# ER44bCqXvrMV4lZRz8V7/2uN863yiURpyNX70Ue0DeIyt3VHqjAWRCeeUyBp1jyV
# 7mqQoybM6EAo4luG5bs6ObXaeAmGhdI4WIB3uwT9ZmGgyjHHwT9uUFroHJVs6HOg
# VapfMdmDSg6EjjuglpVttGoWIbuKBpEmdYUD/CCmv0I5akKahpmJZlJKVgGnaRd1
# BnwTraHZIl42GC/sR2pCOlriIzYyh6GCFvwwghb4BgorBgEEAYI3AwMBMYIW6DCC
# FuQGCSqGSIb3DQEHAqCCFtUwghbRAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCAuu43zin3Z64WVJWhrjC0G9rJNLMNoWKLcTPc/Jj3orgIGZGzY6LuU
# GBMyMDIzMDYwNjExNDU1MC41MjFaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4QTgyLUUz
# NEYtOUREQTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVMwggcMMIIE9KADAgECAhMzAAABwvp9hw5UU0ckAAEAAAHCMA0GCSqGSIb3DQEB
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
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLKMIICMwIBATCB+KGB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046OEE4Mi1FMzRGLTlEREExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAMp1N1VLhPMvWXEoZfmF4apZlnRUoIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoKSM0MCIYDzIwMjMwNjA2MTExNTAwWhgPMjAyMzA2MDcxMTE1MDBaMHMw
# OQYKKwYBBAGEWQoEATErMCkwCgIFAOgpIzQCAQAwBgIBAAIBOjAHAgEAAgIS6jAK
# AgUA6Cp0tAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIB
# AAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAFZgOS2cxWNlQU+4
# EZz0CkCAdj8jOK0VCt616ZxB/RSkwQu1gYys+dyc/C+DeUyErTeHYowikr04gslf
# WRLPEkOfd4kBYS0BG1bbzPyjWQKTjE1Y98psjLFzKPK4MPJrAb6CPaY5/V26SQwW
# d/zAwsp4HwXLCdbQUdX51nHRNjacMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTACEzMAAAHC+n2HDlRTRyQAAQAAAcIwDQYJYIZIAWUD
# BAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0B
# CQQxIgQgb6HnSLvj6skcpjMzK8rRZW1YjvRD6/3TXLDuKubHmp0wgfoGCyqGSIb3
# DQEJEAIvMYHqMIHnMIHkMIG9BCDKk2Bbx+mwxXnuvQXlt5S6IRU5V7gF2Zo757by
# YYNQFjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB
# wvp9hw5UU0ckAAEAAAHCMCIEIDDBI//YST+Fp/fjuVy77UL0wSXXqmJxBSLupCWj
# Jxz9MA0GCSqGSIb3DQEBCwUABIICACEPOXPQ6EZ2SxJnezFX20VjcDbjgHq3yCWc
# 1pONEYHjMpFZMf6evcjsQAqjAJU9mOUpAJ3agw9fKdf2S13+doDa22KVVcEO8xrP
# +7XJp/KbkUICPn2BopJjwGqiIgQWQRAd4apsYQYyka9I7mp6nfWUZ48AF7dUcXa3
# EuMXmnU6HzQKlwjbwtEdSL6FnY7/1HAfLhUxSYdgF2EzKKHBVIr6RdlgHzI+NGfx
# fkTzsexTVJov8PHvxukiVAHx/QdpXlpge5NNf69gByWsZzlKLQB+7CXn40AUdXoT
# S1PCfnWC3GmCHghO8iB9NLE0+DYeYVasQrjrYYQP6C1fE26/NW2CRtNas8VzO5/g
# Gs7BNK/rt08dGktZY9col2XFVk/4WKh6lM8N2FwdTta/WDTFY39d5523wEGQ2N2z
# DC9uN8ctPOObVs3xiIW2eD9eS2HRpcKHLHJYVOVxXxIdXbJ9xJMDpih6RUhtLmMg
# DQJ8ARPDRlqbHaZecxtGqereLwbC0/dZHonfJgcrWiZP9cnjPoGNfB1SeGYHpgsz
# RFBKv+jWuleCJRaiWcZLxMUO1BsFHb7XprDowSP0o88OR4D0jMIkOZlgy/gJnzAB
# n8jcM/U2/jmBJmoyOtg/PsyOThxV8hPnpKTUoTv7io+0cTfmcdWXaOGOGLzDxxlX
# 5dyF9rZt
# SIG # End signature block
