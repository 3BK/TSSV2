#************************************************
# TS_SurfaceDetectFirmwareVersions.ps1
# Description: SurfaceDetectFirmwareVersions
#
# Rule GUID: 34F6567E-7B92-4C37-B1CA-5DE6E66D4881
#
# Files:
# TS_SurfaceDetectFirmwareVersions.ps1
# RC_SurfaceDetectFirmwareVersions.xml
# Include.xml
#
# Output files:
# none
#
# Called from: Networking and Setup Diagnostics
#************************************************

Import-LocalizedData -BindingVariable RegKeyCheck
Write-DiagProgress -Activity $RegKeyCheck.ID_SurfaceDetectFirmwareVersions -Status $RegKeyCheck.ID_SurfaceDetectFirmwareVersionsDesc

$RootCauseDetected = $false
$HasIssue = $false
$RootCauseName = "RC_SurfaceDetectFirmwareVersions"
#$PublicContent Title: "Surface firmware and driver packs"
$PublicContent = "http://www.microsoft.com/en-us/download/details.aspx?id=38826"
#InternalContent Title: "2961421 - Surface: How to check firmware versions"
$InternalContent = "https://vkbexternal.partners.extranet.microsoft.com/VKBWebService/ViewContent.aspx?scid=B;EN-US;2961421"
$Verbosity = "Error"
$Visibility = "4"
$SupportTopicsID = "8041"
$InformationCollected = new-object PSObject

#********************
#Functions
#********************
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber
#we#$sku = $((Get-CimInstance win32_operatingsystem).OperatingSystemSKU)

function isOSVersionAffected
{
	if ([int]$bn -gt [int](9600))
	{
		return $true
	}
	else
	{
		return $false
	}
}

function isSurface
{
	$regkeyBIOS = "HKLM:\HARDWARE\DESCRIPTION\System\BIOS"
	if (test-path $regkeyBIOS)
	{
		$regvalueSystemSKUReg = Get-ItemProperty -path $regkeyBIOS -name "SystemSKU" -ErrorAction SilentlyContinue
		$regvalueSystemSKU = $regvalueSystemSKUReg.SystemSKU
		if ($regvalueSystemSKU -like "*Surface*")
		{
			return $true
		}
		else
		{
			return $false
		}
	}
}

#****************************************************
#  Firmware         : Filename                        : Version       : Version Hex/Dec       : Date
#  --------         : -----------------------           -------         ---------------         ----
#
# Oct2014
#  ECFirmware       : "ECFirmware.38.6.50.0.cap"      : "38.6.50.0"   : 0x00380650 = 3671632  : "08/27/2014"
#  SAMfirmware      : "SamFirmware.3.9.350.0.cap      : "3.9.350.0"   : 0x03090350 = 50922320 : "08/08/2014"
#  TouchFirmware    : "TouchFirmware.426.27.66.0.cap" : "426.27.66.0" : 0x01aa1b42 = 27925314 : "05/15/2014"
#  UEFI             : "UEFI.3.10.250.0.cap"           : "3.10.250.0"  : 0x030a00fa = 50987258 : "08/28/2014"
#
# Nov2014
#  ECFirmware       : "ECFirmware.38.7.50.0.cap"      : "38.7.50.0"   :  0x00380750 = 3671888  : "09/18/2014"	#NEW VERSION
#  SAMfirmware      : "SamFirmware.3.11.350.0.cap"    : "3.9.350.0"   :  0x03090350 = 50922320 : "08/08/2014"
#  TouchFirmware    : "TouchFirmware.426.27.66.0.cap" : "426.27.66.0" :  0x01aa1b42 = 27925314 : "05/15/2014"
#  UEFI             : "UEFI.3.11.350.0.cap"           : "3.11.350.0"  :  0x030b00fa = 50987258 : "10/16/2014"	#NEW VERSION
#
#****************************************************

$regvalueECFirmwareFileNameLatest    = "ECFirmware.38.7.50.0.cap"
$regvalueECFirmwareVersionLatest     = 3671888
$regvalueSamFirmwareFileNameLatest   = "SamFirmware.3.9.350.0.cap"
$regvalueSamFirmwareVersionLatest    = 50922320
$regvalueTouchFirmwareFileNameLatest = "TouchFirmware.426.27.66.0.cap"
$regvalueTouchFirmwareVersionLatest  = 27925314 
$regvalueUEFIFileNameLatest          = "UEFI.3.10.250.0.cap"
$regvalueUEFIVersionLatest           = 50987258

#********************
#Detection Logic and Alert Evaluation
#********************
if ((isOSVersionAffected) -and (isSurface))
{
	# Detection Details
	# -----------------
	# The current firmware detection method uses this location:
	# Check for "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FirmwareResources\{512B1F42-CCD2-403B-8118-2F54353A1226}"  Filename = "SamFirmware.3.9.350.0.cap"
	# Check for "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FirmwareResources\{52D9DA80-3D55-47E4-A9ED-D538A9B88146}"  Filename = "ECFirmware.38.6.50.0.cap"
	# Check for "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FirmwareResources\{5A2D987B-CB39-42FE-A4CF-D5D0ABAE3A08}"  Filename = "UEFI.3.10.250.0.cap"
	# Check for "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FirmwareResources\{E5FFF56F-D160-4365-9E21-22B06F6746DD}"  Filename = "TouchFirmware.426.27.66.0.cap"
	#
	$regkeyECFirmware    = "HKLM:\SYSTEM\CurrentControlSet\Control\FirmwareResources\{52D9DA80-3D55-47E4-A9ED-D538A9B88146}"
	$regkeySamFirmware   = "HKLM:\SYSTEM\CurrentControlSet\Control\FirmwareResources\{512B1F42-CCD2-403B-8118-2F54353A1226}"
	$regkeyTouchFirmware = "HKLM:\SYSTEM\CurrentControlSet\Control\FirmwareResources\{E5FFF56F-D160-4365-9E21-22B06F6746DD}"
	$regkeyUEFI          = "HKLM:\SYSTEM\CurrentControlSet\Control\FirmwareResources\{5A2D987B-CB39-42FE-A4CF-D5D0ABAE3A08}"

	# The original firmware detection method used this location, but guidance recommended using the FirmwareResources registry value:
	#  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\UEFI\RES_{GUID}\0\Device Parameters
	#

	If (test-path $regkeyECFirmware)
	{
		$regvalueECFirmwareFileName = Get-ItemProperty -path $regkeyECFirmware -name "Filename" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueECFirmwareFileName)
		{
			$regvalueECFirmwareFileName = $regvalueECFirmwareFileName.Filename
		}
		$regvalueECFirmwareVersion = Get-ItemProperty -path $regkeyECFirmware -name "Version" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueECFirmwareVersion)
		{
			add-member -inputobject $InformationCollected -membertype noteproperty -name "Surface Embedded Controller Firmware" -value " "
			$regvalueECFirmwareVersion = $regvalueECFirmwareVersion.Version
			if ($regvalueECFirmwareVersion -lt $regvalueECFirmwareVersionLatest)
			{
				$RootCauseDetected  = $true
				add-member -inputobject $InformationCollected -membertype noteproperty -name "ECFirmware Installed Version" -value $regvalueECFirmwareFileName
				add-member -inputobject $InformationCollected -membertype noteproperty -name "ECFirmware Recommended Version" -value $regvalueECFirmwareFileNameLatest
			}
			else
			{
				add-member -inputobject $InformationCollected -membertype noteproperty -name "ECFirmware Version: No Action Needed" -value $regvalueECFirmwareFileName
			}
		}
	}

	If (test-path $regkeySamFirmware)
	{
		$regvalueSamFirmwareFilename = Get-ItemProperty -path $regkeySamFirmware -name "Filename" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueSamFirmwareFilename)
		{
			$regvalueSamFirmwareFilename = $regvalueSamFirmwareFilename.Filename
		}
		$regvalueSamFirmwareVersion = Get-ItemProperty -path $regkeySamFirmware -name "Version" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueSamFirmwareVersion)
		{
			add-member -inputobject $InformationCollected -membertype noteproperty -name "Surface System Aggregator Firmware" -value " "
			$regvalueSamFirmwareVersion = $regvalueSamFirmwareVersion.Version
			if ($regvalueSamFirmwareVersion -lt $regvalueSamFirmwareVersionLatest)	
			{
				$RootCauseDetected = $true
				add-member -inputobject $InformationCollected -membertype noteproperty -name "SamFirmware Installed Version" -value $regvalueSamFirmwareFileName
				add-member -inputobject $InformationCollected -membertype noteproperty -name "SamFirmware Recommended Version" -value $regvalueSamFirmwareFileNameLatest
			}
			else
			{
				add-member -inputobject $InformationCollected -membertype noteproperty -name "SamFirmware Version: No Action Needed" -value $regvalueSamFirmwareFileName
			}
		}
	}

	If (test-path $regkeyTouchFirmware)
	{
		$regvalueTouchFirmwareFileName = Get-ItemProperty -path $regkeyTouchFirmware -name "Filename" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueTouchFirmwareFileName)
		{
			$regvalueTouchFirmwareFileName = $regvalueTouchFirmwareFileName.Filename
		}
		$regvalueTouchFirmwareVersion = Get-ItemProperty -path $regkeyTouchFirmware -name "Version" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueTouchFirmwareVersion)
		{
			add-member -inputobject $InformationCollected -membertype noteproperty -name "Surface Touch Controller Firmware" -value " "
			$regvalueTouchFirmwareVersion  = $regvalueTouchFirmwareVersion.Version
			if ($regvalueTouchFirmwareVersion -lt $regvalueTouchFirmwareVersionLatest)
			{
				$RootCauseDetected  = $true
				add-member -inputobject $InformationCollected -membertype noteproperty -name "TouchFirmware Installed Version:" -value $regvalueTouchFirmwareFileName
				add-member -inputobject $InformationCollected -membertype noteproperty -name "TouchFirmware Recommended Version" -value $regvalueTouchFirmwareFileNameLatest
			}
			else
			{
				add-member -inputobject $InformationCollected -membertype noteproperty -name "TouchFirmware Version: No Action Needed" -value $regvalueTouchFirmwareFileName
			}
		}
	}

	If (test-path $regkeyUEFI)
	{
		$regvalueUEFIFileName = Get-ItemProperty -path $regkeyUEFI -name "Filename" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueUEFIFileName)
		{
			$regvalueUEFIFileName = $regvalueUEFIFileName.Filename
		}
		
		$regvalueUEFIVersion = Get-ItemProperty -path $regkeyUEFI -name "Version" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueUEFIVersion)
		{
			add-member -inputobject $InformationCollected -membertype noteproperty -name "Surface UEFI" -value " "
			$regvalueUEFIVersion  = $regvalueUEFIVersion.Version
			if ($regvalueUEFIVersion -lt $regvalueUEFIVersionLatest)
			{
				$RootCauseDetected  = $true
				add-member -inputobject $InformationCollected -membertype noteproperty -name "UEFI Installed Version" -value $regvalueUEFIFileName
				add-member -inputobject $InformationCollected -membertype noteproperty -name "UEFI Recommended Version" -value $regvalueUEFIFileNameLatest
			}
			else
			{
				add-member -inputobject $InformationCollected -membertype noteproperty -name "UEFI Version: No Action Needed" -value $regvalueUEFIFileName
			}
		}
	}

	if ($RootCauseDetected -eq $true)
	{
		"[info] RootCauseDetected: Completing RootCause" | WriteTo-StdOut
		# Completing the Root Cause
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL $PublicContent -InternalContentURL $InternalContent -Verbosity $Verbosity -InformationCollected $InformationCollected -Visibility $Visibility -SupportTopicsID $SupportTopicsID -MessageVersion 1
	}
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}


# SIG # Begin signature block
# MIInoAYJKoZIhvcNAQcCoIInkTCCJ40CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAjZTtSS56yNQv0
# TwQ6DHX4ygHKSLb70OElmN94IdJHjKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGYAwghl8AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINujVzSdl43rzRPuUlX749QC
# uya0IkmM1gFfLR4PLPLtMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCEoCG91OMlR6B7VG/9upxM/cK0p8t5r6A+GATRgijRHPH7pm2M5qO8
# Syy2WTcDtq23wfT+0t4VT8DB3Lr0XE1cT4WkvSssK8QvRIddkHw9tznhvd0SL34k
# A3TGmc9mayoRrF6Lcv74VAWAHmpGxh+MJPFPRBXr8bS5tvZJWdNZOYMAEENH4BOt
# C4++B+UXoj72DHK+9GgH6nyPhbHF3yILgPKJfWsvpow2nCOIE8rbKy3ZjhaeCWdq
# FJ4+HH+6NcbCbY3amGKAn6Lity0Et2mkiOy9REjD0I9QLmPMNnMUsGs5aDfsZO8B
# QCzxg59wQ2qP6N0k2FOOxWXuV0pu+yEMoYIXCDCCFwQGCisGAQQBgjcDAwExghb0
# MIIW8AYJKoZIhvcNAQcCoIIW4TCCFt0CAQMxDzANBglghkgBZQMEAgEFADCCAVQG
# CyqGSIb3DQEJEAEEoIIBQwSCAT8wggE7AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIGbGlpC8QXyNFTZ+kTKesf4Wz8kGOT6b4SjOjEE66rIiAgZi2xAP
# jgEYEjIwMjIwODAxMDgxMDE1LjgxWjAEgAIB9KCB1KSB0TCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjg5
# N0EtRTM1Ni0xNzAxMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloIIRXDCCBxAwggT4oAMCAQICEzMAAAGrCQnvq2PU6KkAAQAAAaswDQYJKoZI
# hvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIwMzAy
# MTg1MTI4WhcNMjMwNTExMTg1MTI4WjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVl
# cnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjg5N0EtRTM1Ni0xNzAx
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyZ1LWjl16EBJSyxwurLHbCb9aKs1R+qQ
# YHKYMi1jMSegq2SGt3vA2wmziD4G4ze4FfzVac7bvSWSsLR7WaYOpC3jbROZvyXC
# yNAozqYRo1Ah9cOuietU3drDWXH1sB/tVkQDeQcWqXpgA7eSNDo9+0DiJUdfclW/
# 3ye2ORu2rMp4kxo1Z3x0FoAPdEKWIyhqNMMZvJg0pO/EGFYgvInxZh0n80EOmo/N
# CX6nGbpllVJ4FAAg65tmNTS9+kQLEcLm8jUSuupqkb7SgGGE436CWVWSU8BZm/aK
# /SaCMJOPtg0pfvIvbHZO+u8dWrkY81rl81unLf23ly+KJiox/VFlVlxx2v7a8CmT
# mJvlrg7xKICA9JTBgag7BtkbWiceKPQBM8uSApR+Bo/MV93kllJtGXZeDfjv8uNZ
# AtH4qMDIAIVvTpupbO8e1AlM0PxjSPljZIGdIKpXbM0dJW2zj5pR+RSGwpL4YBdL
# ePldSBgDtIw2iDvo2eyzmXTWcRfuwcN1jKRiHO5AoWtPvRdVNl5fbm1IF/LdVpzN
# h3UlIj/3A4apsVTnY3KuWwDWqKbE6Gy52zs/Gj6M7dGNX+QL4AQ6hVpcN2aKexzc
# +2UEJWH+yBiej0BTKZuVJGZ57WDCWeVknS6Icoj2rYcWBlYzXTI8bmBW3SmteckW
# LVbGaaD4Ef8CAwEAAaOCATYwggEyMB0GA1UdDgQWBBQUW87yjV41xIIhBky+oZ90
# 0v6mqjAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBW
# MFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNy
# b3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUH
# AQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEp
# LmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3
# DQEBCwUAA4ICAQDKS5SBNzUoyzMyCwduGCOAQa/90IcV/RvL30LjlJHvvT+50I01
# 6qVPrXQSHPXfEYVTodyL5MtQ9SeG9SdK7PvGSJZGu7lGNlmZKicRW/yelrfPVC95
# R+eC3KLQl3qqVLKSgRUnq0O5HUrD3FT3K+2FlaFCz/KbI7CH6bG3QL3Bt4sn3Z6v
# a9z2XLXakXFsI0Mn6ZDu/nbSEC+t5apnTYY4mHDRHhzWI/f2I0HMc6jP4Ow7SxiP
# CFrP0eu9gwTM4PUwl0s9Z9QWxn/+JN3ePMTKSTTZaOdk3Mh7YQ1+ZD8puUZcd5J7
# wliqKZMXGXmR4x8tQQuMCHSaFDW8sIlnbQHALg7nsSDvI79i4Gej7hGtXQIPaCng
# E7XQoVbZJD8yG9FYrsduBLoHO3vSuQh5JS2julGQcyqueG5shNxd12TLoa1mybAz
# eG+pe5K0x5TVbk03ccDzKmM8t39uiZ8bH3oe7Dw6t+1xC+Tu2F027gmEDIpRdQ/t
# 0owIl+s52mWDSPW0TRqIT6kNNJBWY/MZ7MIvjayXI8lVem7jHETSGkAKva5rQse/
# 8sHpFXkLgI7gyz+l9qX/8Xc76Ell7mLF6/Mo2RddvE85rVH5Iitb+sdkzpEgMtMn
# FMYUMzWFAPJp8a71L9ru6aS+KWAEc3Fl+TQhgTtFFYlwbuiJj4UZ3HVyzTCCB3Ew
# ggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1p
# Y3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkz
# MDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5
# osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVri
# fkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFEx
# N6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S
# /rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3j
# tIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKy
# zbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX78
# 2Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjt
# p+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2
# AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb
# 3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3ir
# Rbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUB
# BAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYD
# VR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGC
# N0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZ
# BgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/
# BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8E
# TzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9k
# dWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBM
# MEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRz
# L01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEA
# nVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx8
# 0HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ
# 7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2
# KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZ
# QhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa
# 2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARx
# v2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRr
# akURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6T
# vsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4
# JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6
# ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLPMIICOAIBATCB/KGB
# 1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcG
# A1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOjg5N0EtRTM1Ni0xNzAxMSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBbqHr/bhYKjtZn
# PoIRUB4vO1yYPqCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MA0GCSqGSIb3DQEBBQUAAgUA5pFr2DAiGA8yMDIyMDgwMTAxMDAwOFoYDzIwMjIw
# ODAyMDEwMDA4WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDmkWvYAgEAMAcCAQAC
# AgbUMAcCAQACAhE3MAoCBQDmkr1YAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisG
# AQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQAD
# gYEAART6kv59Vdy6qDJ3JFLbG7QpdtoCJMPcyW0KeOSfd6Q28WBw/7g6tMl7gMCm
# 6dNEJvhu8mtiJ8r96A8JQ8jrv45tqP0znRy5W0f03MRQWzxCF5A5sRTq0bThf8G/
# RyrMQbfJkp2nQ7SHWTowy0ishxwo3ck8xt0WYQcB5vvDVMAxggQNMIIECQIBATCB
# kzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAasJCe+rY9ToqQAB
# AAABqzANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJ
# EAEEMC8GCSqGSIb3DQEJBDEiBCCN1XHVDOEkastWyK+b/j/19ZeB6kti7C1h1FyD
# KV01/TCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIA4cr/qwhWARVJUPcCu+
# To7JAq9HEUcrKtpTNs3X8ApXMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTACEzMAAAGrCQnvq2PU6KkAAQAAAaswIgQgcj5FAodNnYh3v+5+8qr8
# NCT52pDLViSa+w83M6SkvSIwDQYJKoZIhvcNAQELBQAEggIAtNlJfOGBliADroWS
# IBVlxT+pcyPDXv7vun7cmOAhocI8tlUMLoQPPbPSE3JQWJG0pb2bukIDXuRPnTk5
# 9EL4X306Irs0WWMtRKahsgdPs/7zbc9bJmuYRyVErcBBHYwEg0SMIZSSMtM/ycXb
# OJbUGmCUu+AgXn61K6Z3BUpV5MOc4m6YKzVX8vGRh7/yqD+Wy+SJTpfzGLp7TWcl
# 4E7q5cdlcqSeiBxBslUcmvt8gUt/Cv+9tUKNiwTKCS51QNOpL+LuOXc1gxja1TOB
# 5Y9JMOhi06mI6O1lQp6x5JZ187HORBvLvFK61Wdiou/oDhddn9JEEDaF1096zxaf
# O23HvCrxufHNsHlfHCrTvbGnURrZ4rUDy/y5SPEOxEBqSv9fr0cJh7ElKgadKQka
# 7tsIMRAEfFktv3cP02h5XNH5oPc0B0Xujh2ebuVpP9dXnO4T62aoYTc0mQXq0Vmq
# qCGNbGKjToqQ+yU55KZKvvdPdxG+BnX1tmVX8ITkCBEc9nHV6vnCMHK7jGpYSiGG
# 3tQoDkHWS3jC+CTWB19Tdn7jxV8OR5IxTy1qc1LZLkwPMm8u+6D2Zj9zegISEOD4
# lp6GjXym8cSZTRIvEQW67CdbLm6+TajhjX622IoVjOHPWTjFMHt+4EawefTDMSBl
# xAdMPLYybANkV4Wti7NwW2SCjIA=
# SIG # End signature block
