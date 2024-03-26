#************************************************
# DC_NetworkingDiagnostic.ps1
# Version 1.0.2006: The Networking Diagnostic was created in 2006 with SDPv1 and SDPv2.
# Version 1.1.2009: The Networking Diagnostic was moved to SDP3.
# Version 1.2.2009-2014: Many updates to all the static data collection scripts.
# Version 2.0.08.27.14: Republish 05.03.19.
# Date: 2006-2019
# Author: Boyd Benson (bbenson@microsoft.com) +WalterE
# Description: Creates an output file showing the version of the Networking Diagnostic
# Called from: Networking Diagnostic, psSDP: all TS_AutoAddCommands_*
#*******************************************************
# 2019-06-11 WalterE added to psSDP #_#

Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}

Import-LocalizedData -BindingVariable ScriptVariable

$sectionDescription = "Diagnostic Version"

# detect OS version and SKU
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber
$sku = $((Get-CimInstance win32_operatingsystem).OperatingSystemSKU)
$domainRole = (Get-CimInstance -Class Win32_ComputerSystem).DomainRole	# 0 or 1: client; >1: server


function GetOsVerName($bn)
{
	switch ($bn)
	{ # 	:: 10.0 - Windows 10		10240 RTM, 10586 TH2 v1511, 14393 RS1 v1607, 15063 RS2 v1703, 16299 RS3 1709, 17134 RS4 1803, 17763 RS5 1809, 18362 19H1 1903, 18363 19H2 1909
		20348 {return "WS2022"}
		22000 {return "Win11"}
		19044 {return "W10v21H2"}
		19043 {return "W10v21H1"}
		19042 {return "W10v20H2"}
		17763 {return "W10v1809/WS2019"}
		14393 {return "W10v1607/WS2016"}
		10240 {return "W10rtm"}		
		9600  {return "W8.1/WS2012R2"}
		9200  {return "W8/WS2012"}
		7601  {return "W7/WS2008R2 SP1"}
		7600  {return "W7/WS2008R2 RTM"}
		6003  {return "Vista/WS2008"}
		6002  {return "Vista/WS2008"}
		default {return "unknown-OS"}
	}
}

function GetOsSkuName($sku)
{
	switch ($sku)
	{
		# GetProductInfo function
		# http://msdn.microsoft.com/en-us/library/ms724358.aspx
		#
		0  {return ""}
		1  {return "Ultimate Edition"}
		2  {return "Home Basic Edition"}
		3  {return "Home Basic Premium Edition"}
		4  {return "Enterprise Edition"}
		5  {return "Home Basic N Edition"}
		6  {return "Business Edition"}
		7  {return "Standard Server Edition"}
		8  {return "Datacenter Server Edition"}
		9  {return "Small Business Server Edition"}
		10 {return "Enterprise Server Edition"}
		11 {return "Starter Edition"}
		12 {return "Datacenter Server Core Edition"}
		13 {return "Standard Server Core Edition"}
		14 {return "Enterprise Server Core Edition"}
		15 {return "Enterprise Server Edition for Itanium-Based Systems"}
		16 {return "Business N Edition"}
		17 {return "Web Server Edition"}
		18 {return "Cluster Server Edition"}
		19 {return "Home Server Edition"}
		20 {return "Storage Express Server Edition"}
		21 {return "Storage Standard Server Edition"}
		22 {return "Storage Workgroup Server Edition"}
		23 {return "Storage Enterprise Server Edition"}
		24 {return "Server For Small Business Edition"}
		25 {return "Small Business Server Premium Edition"} # 0x00000019
		26 {return "Home Premium N Edition"} # 0x0000001a
		27 {return "Enterprise N Edition"} # 0x0000001b
		28 {return "Ultimate N Edition"} # 0x0000001c
		29 {return "Web Server Edition (core installation)"} # 0x0000001d
		30 {return "Windows Essential Business Server Management Server"} # 0x0000001e
		31 {return "Windows Essential Business Server Security Server"} # 0x0000001f
		32 {return "Windows Essential Business Server Messaging Server"} # 0x00000020
		33 {return "Server Foundation"} # 0x00000021
		34 {return "Windows Home Server 2011"} # 0x00000022 not found
		35 {return "Windows Server 2008 without Hyper-V for Windows Essential Server Solutions"} # 0x00000023
		36 {return "Server Standard Edition without Hyper-V (full installation)"} # 0x00000024
		37 {return "Server Datacenter Edition without Hyper-V (full installation)"} # 0x00000025
		38 {return "Server Enterprise Edition without Hyper-V (full installation)"} # 0x00000026
		39 {return "Server Datacenter Edition without Hyper-V (core installation)"} # 0x00000027
		40 {return "Server Standard Edition without Hyper-V (core installation)"} # 0x00000028
		41 {return "Server Enterprise Edition without Hyper-V (core installation)"} # 0x00000029
		42 {return "Microsoft Hyper-V Server"} # 0x0000002a
		43 {return "Storage Server Express (core installation)"} # 0x0000002b
		44 {return "Storage Server Standard (core installation)"} # 0x0000002c
		45 {return "Storage Server Workgroup (core installation)"} # 0x0000002d
		46 {return "Storage Server Enterprise (core installation)"} # 0x0000002e
		47 {return "Starter N"} # 0x0000002f
		48 {return "Professional Edition"} #0x00000030
		49 {return "ProfessionalN Edition"} #0x00000031
		50 {return "Windows Small Business Server 2011 Essentials"} #0x00000032
		51 {return "Server For SB Solutions"} #0x00000033
		52 {return "Server Solutions Premium"} #0x00000034
		53 {return "Server Solutions Premium (core installation)"} #0x00000035
		54 {return "Server For SB Solutions EM"} #0x00000036
		55 {return "Server For SB Solutions EM"} #0x00000037
		55 {return "Windows MultiPoint Server"} #0x00000038
		#not found: 3a
		59 {return "Windows Essential Server Solution Management"} #0x0000003b
		60 {return "Windows Essential Server Solution Additional"} #0x0000003c
		61 {return "Windows Essential Server Solution Management SVC"} #0x0000003d
		62 {return "Windows Essential Server Solution Additional SVC"} #0x0000003e
		63 {return "Small Business Server Premium (core installation)"} #0x0000003f
		64 {return "Server Hyper Core V"} #0x00000040
		 #0x00000041 not found
		 #0x00000042-48 not supported
		76 {return "Windows MultiPoint Server Standard (full installation)"} #0x0000004C
		77 {return "Windows MultiPoint Server Premium (full installation)"} #0x0000004D
		79 {return "Server Standard (evaluation installation)"} #0x0000004F
		80 {return "Server Datacenter (evaluation installation)"} #0x00000050
		84 {return "Enterprise N (evaluation installation)"} #0x00000054
		95 {return "Storage Server Workgroup (evaluation installation)"} #0x0000005F
		96 {return "Storage Server Standard (evaluation installation)"} #0x00000060
		98 {return "Windows 8 N"} #0x00000062
		99 {return "Windows 8 China"} #0x00000063
		100 {return "Windows 8 Single Language"} #0x00000064
		101 {return "Windows 8"} #0x00000065
		102 {return "Professional with Media Center"} #0x00000067
	}	
}


function FwGetSrvSKU {
	Try{
		$IsServerSKU = (Get-CimInstance -Class CIM_OperatingSystem -ErrorAction Stop).Caption -like "*Server*"
	}Catch{
		LogException "An exception happened in Get-CimInstance for CIM_OperatingSystem" $_ $fLogFileOnly
		$IsServerSKU = $False
	}
	Return $IsServerSKU
}

function FwGetSrvRole {
	$OutputFile = "$Env:ComputerName$Prefix" +  "_Roles_Features.txt"
	If ($IsServerSKU) { # get Windows Feature and Role (on Windows Server 2008R2+)
		Get-WindowsFeature | Where-Object {$_.installed -eq $true} 	| Out-File -FilePath $OutputFile 
		Get-WindowsFeature -ErrorAction Stop 						| Out-File -FilePath $OutputFile -append
	} else {
		if ($bn -gt 9200) { # Client >= 2012
			Get-WindowsOptionalFeature -Online | Format-Table -AutoSize | Out-File -FilePath $OutputFile
		}
	}
}

$osVerName = GetOsVerName $bn
$osSkuName = GetOsSkuName $sku

$OutputFile= "_psSDP_DiagnosticVersion.TXT"
"`n"												| Out-File -FilePath $OutputFile -append
"Diagnostic  : psSDP Diagnostic v$global:VerDate"	| Out-File -FilePath $OutputFile -append
"Publish Date: $global:Publish_Date"				| Out-File -FilePath $OutputFile -append
"`n"												| Out-File -FilePath $OutputFile -append
if ($domainRole -gt 1) {$Server_Client = "Server"
} else { $Server_Client = "Client"}
"Type                         : $Server_Client"			| Out-File -FilePath $OutputFile -append
"Operating System Name        : $osVerName" 			| Out-File -FilePath $OutputFile -Append
"Operating System SKU         : $osSkuName" 			| Out-File -FilePath $OutputFile -Append
"Operating System Build Number: $bn" 					| Out-File -FilePath $OutputFile -Append
"`n"													| Out-File -FilePath $OutputFile -append
"`n"													| Out-File -FilePath $OutputFile -append
"`n Powershell version:"								| Out-File -FilePath $OutputFile -append
$PSVersionTable	| Format-Table -AutoSize							| Out-File -FilePath $OutputFile -append
"`n ExecutionPolicy:"									| Out-File -FilePath $OutputFile -append
Get-ExecutionPolicy -List 								| Out-File -FilePath $OutputFile -append
CollectFiles -filesToCollect $OutputFile -fileDescription "Diagnostic Version" -SectionDescription $sectionDescription	

if ($bn -gt 7600) {
	FwGetSrvSKU | Out-Null #_#
	FwGetSrvRole
	$OutputFile = "$Env:ComputerName$Prefix" +  "_Roles_Features.txt"
	CollectFiles -filesToCollect $OutputFile -fileDescription "Roles_Features" -SectionDescription "System Information"	
}


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAGT+xV0qfHUrQe
# uB+DJ05Ny40zdRVvR0UYOkPmL95HvKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGY4wghmKAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINQ6QlvjxYN1wAiwJBEb6zIG
# MSJ4r3+e7/Psa5ItnO5QMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAFZnjdqk1Wr9eG405g+3yj7y+rfBjWS61ybB9qJF7kL7FdNLzfH7tw
# hAnqEX5za7ViTreFZrGJv1GvAndan2dEZ/MHCiNziQMBzOb+5O58hdWg76UjtKWg
# n6za26ObF+BOQLLe8VZfqWRUtCS4o2LAtmSqyUWz1x6dBYQIBgCRZsxsn85oy2i/
# oggba1X3HZYJQHUaQh6obKnaghT3bJ9eazYPgyxLNTWxRxxDR+7uiCNjqhXKdxB/
# WpMfi55TztjPjKzz/Iv8gYG2ChVCmScHJP9k9Aca/vwDJ6R0U8OgUqRypvAaUlUs
# mldxNUALXqim6QDVYmETHyL11IAWE/YpoYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIDQmIWJJPZpBvtZjluXn3qChf2WN0yE4g9ojEdEzVLacAgZi3mQf
# IRgYEzIwMjIwODAxMDc1NTA3LjQyM1owBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046ODZERi00QkJDLTkzMzUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAYwBl2JHNnZmOwABAAABjDAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDRaFw0yMzAxMjYxOTI3NDRaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjg2REYt
# NEJCQy05MzM1MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA00hoTKET+SGsayw+9BFd
# m+uZ+kvEPGLd5sF8XlT3Uy4YGqT86+Dr8G3k6q/lRagixRKvn+g2AFRL9VuZqC1u
# Tva7dZN9ChiotHHFmyyQZPalXdJTC8nKIrbgTMXAwh/mbhnmoaxsI9jGlivYgi5G
# NOE7u6TV4UOtnVP8iohTUfNMKhZaJdzmWDjhWC7LjPXIham9QhRkVzrkxfJKc59A
# saGD3PviRkgHoGxfpdWHPPaW8iiEHjc4PDmCKluW3J+IdU38H+MkKPmekC7GtRTL
# XKBCuWKXS8TjZY/wkNczWNEo+l5J3OZdHeVigxpzCneskZfcHXxrCX2hue7qJvWr
# ksFStkZbOG7IYmafYMQrZGull72PnS1oIdQdYnR5/ngcvSQb11GQ0kNMDziKsSd+
# 5ifUaYbJLZ0XExNV4qLXCS65Dj+8FygCjtNvkDiB5Hs9I7K9zxZsUb7fKKSGEZ9y
# A0JgTWbcAPCYPtuAHVJ8UKaT967pJm7+r3hgce38VU39speeHHgaCS4vXrelTLiU
# MAl0Otk5ncKQKc2kGnvuwP2RCS3kEEFAxonwLn8pyedyreZTbBMQBqf1o3kj0ilO
# J7/f/P3c1rnaYO01GDJomv7otpb5z+1hrSoIs8u+6eruJKCTihd0i/8bc67AKF76
# wpWuvW9BhbUMTsWkww4r42cCAwEAAaOCATYwggEyMB0GA1UdDgQWBBSWzlOGqYIh
# YIh5Vp0+iMrdQItSIzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQDXaMVFWMIJqdblQZK6oks7cdCUwePAmmEIedsy
# usgUMIQlQqajfCP9iG58yOFSRx2k59j2hABSZBxFmbkVjwhYEC1yJPQm9464gUz5
# G+uOW51i8ueeeB3h2i+DmoWNKNSulINyfSGgW6PCDCiRqO3qn8KYVzLzoemfPir/
# UVx5CAgVcEDAMtxbRrTHXBABXyCa6aQ3+jukWB5aQzLw6qhHhz7HIOU9q/Q9Y2Nn
# VBKPfzIlwPjb2NrQGfQnXTssfFD98OpRHq07ZUx21g4ps8V33hSSkJ2uDwhtp5Vt
# FGnF+AxzFBlCvc33LPTmXsczly6+yQgARwmNHeNA262WqLLJM84Iz8OS1VfE1N6y
# YCkLjg81+zGXsjvMGmjBliyxZwXWGWJmsovB6T6h1GrfmvMKudOE92D67SR3zT3D
# dA5JwL9TAzX8Uhi0aGYtn5uNUDFbxIozIRMpLVpP/YOLng+r2v8s8lyWv0afjwZY
# HBJ64MWVNxHcaNtjzkYtQjdZ5bhyka6dX+DtQD9bh3zji0SlrfVDILxEb6Ojyqtf
# Gj7iWZvJrb4AqIVgHQaDzguixES9ietFikHff6p97C5qobTTbKwN0AEP3q5teyI9
# NIOVlJl0gi5Ibd58Hif3JLO6vp+5yHXjoSL/MlhFmvGtaYmQwD7KzTm9uADF4BzP
# /mx2vzCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
# AQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAw
# BgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEw
# MB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk
# 4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9c
# T8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWG
# UNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6Gnsz
# rYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2
# LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLV
# wIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTd
# EonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0
# gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFph
# AXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJ
# YfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXb
# GjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJ
# KwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnP
# EP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMw
# UQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggr
# BgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYw
# DwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoY
# xDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
# L2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYB
# BQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0B
# AQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U5
# 18JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgAD
# sAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo
# 32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZ
# iefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZK
# PmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RI
# LLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgk
# ujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9
# af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzba
# ukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/
# OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLUMIIC
# PQIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046ODZERi00QkJDLTkzMzUxJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVADSi8hTrq/Q8oppweGyuZLNEJq/VoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmkXQnMCIYDzIwMjIwODAx
# MDUzNTM1WhgPMjAyMjA4MDIwNTM1MzVaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaRdCcCAQAwBwIBAAICGM0wBwIBAAICEU8wCgIFAOaSxacCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQCIsY9Ly+6K9S9Shp4oRSoLWJ00XRTLqUH0YK7lKobW
# 8eWfIrppdWOIf4H7BnWoO0/tMJJHgeSrJisS6vnLflRO/4yJ/OiGy6tcxoTZPfeS
# K5q/F4NEIboNLCDhW8RxBTAI4Hor5tEA4Y4BdGmZl++3Tly7aywliLfU/qiVJvKi
# VjGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABjAGXYkc2dmY7AAEAAAGMMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIDyaNtAN7CvkY3bLXyVs
# U7THH6m4J/khfCGV2vwgGSjSMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# 1a2L+BUqkM8Gf8TmIQWdgeKTTrYXIwOofOuJiBiYaZ4wgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYwBl2JHNnZmOwABAAABjDAiBCBY
# eC4LEStKyRogWYCSryzBcOErikzXGGVi2RsI7tYWwzANBgkqhkiG9w0BAQsFAASC
# AgAAlMf/LDlRCplrflJ9CB6sx3kT2fENRa99TaHQkftvDMIf9xwVWanX8yQOJkHo
# di4UswPQT2PhDq5Jois+0DZ0u+qoxzczCrlhiTwlxW3vg+3XnMdDre3NhCHim3Ws
# scmfQqGEVP49M8POBNV1PxjrfP+fhWozjEvq73T/IloqIoO2yn8YX6N4Ezq5+Iwp
# 0MhiGVB6J2lfAsdki5cmE35puL8mu4HbPJxxFdgh3pEQtb3uFLDPbi/4AmFhXR60
# CydkJf71Tci+Pfj4gHcRYshm/fHw09fgaFF+urmRgLmyysYchFHJrDMsevRWV9Ri
# CIJjsED+EMNkKZ/6JXHMTE8oXpE9VY/jHTCUCWqaRqrqx+JBvlIpxz7wuptJgu1l
# CVsMrGcxp38H9y3zeMh5iGwtf7kYH5JCdBzpNJmLmsjDxSqrtAA7A9zq+Q9hEKyr
# L47MAuHpE1xjqlKKxr2SEEihj4i8nQJvHH5AqMXQX8rBfzKo9WKYfEmzjg3qGpkm
# 66SLimZL0Y2GncXxO8jM3F3lsskAzLp4SuPPvVumkFoNEaxSACXiMSrtD0qCYoPR
# VQsJpPTRMmmszWyNucOu1BuCqctIGfSEA9kn+Pz3t3KG1YsDt7wTlCBzDfsQrpmm
# Okxh5g24YctL5RERdGxdbGcMTyhU2/TIyDNlrfptHJCmPg==
# SIG # End signature block
