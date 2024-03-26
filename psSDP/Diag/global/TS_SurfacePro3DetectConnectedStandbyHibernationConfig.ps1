#************************************************
# TS_SurfacePro3DetectConnectedStandbyHibernationConfig.ps1
# Version 1.0.09.19.14: Created and tested SurfacePro3 scripts from Sep12-19
# Date: 2014
# Author: bbenson
# Description: SurfacePro3DetectConnectedStandbyHibernationConfig
#
# Rule GUID: 03F8CAD0-6D61-4501-AA1F-ACAECC18411C
#
# Files:
# TS_SurfacePro3DetectConnectedStandbyConfig.ps1
# RC_SurfacePro3DetectConnectedStandbyConfig.xml
# Include.xml
#
# Output Files:
# none
#
#
# Called from: Networking and Setup Diagnostics
#************************************************

Import-LocalizedData -BindingVariable RegKeyCheck
Write-DiagProgress -Activity $RegKeyCheck.ID_SurfacePro3DetectConnectedStandbyHibernationConfig -Status $RegKeyCheck.ID_SurfacePro3DetectConnectedStandbyHibernationConfigDesc


$RootCauseDetected = $false
$HasIssue = $false
$RootCauseName = "RC_SurfacePro3DetectConnectedStandbyHibernationConfig"
#$PublicContent Title: ""
#$PublicContent = ""
#InternalContent Title: "Surface Pro 3 does not hibernate after 4 hours in connected standby"
$InternalContent = "https://vkbexternal.partners.extranet.microsoft.com/VKBWebService/ViewContent.aspx?scid=KB;EN-US;2998588"
$Verbosity = "Error"
$Visibility = "3"
$SupportTopicsID = "8041"
$InformationCollected = new-object PSObject


#********************
#Functions
#********************
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber
$sku = $((Get-CimInstance win32_operatingsystem).OperatingSystemSKU)

Function isOSVersionAffected
{
	if ($bn -ge 9600)
	 {
		return $true
	 }
	 else
	 {
		return $false
	 }
}

Function isSurfacePro3
{
	# Check for: "HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS"; SystemSKU = Surface_Pro_3
	$regkeyBIOS = "HKLM:\HARDWARE\DESCRIPTION\System\BIOS"
	If (test-path $regkeyBIOS)
	{
		$regvalueSystemSKUReg = Get-ItemProperty -path $regkeyBIOS -name "SystemSKU" -ErrorAction SilentlyContinue
		$regvalueSystemSKU = $regvalueSystemSKUReg.SystemSKU
		if ($regvalueSystemSKU -eq "Surface_Pro_3")
		{
			return $true
		}
		else
		{
			return $false
		}
	}
}



#********************
#Detection Logic and Alert Evaluation
#********************
if ((isOSVersionAffected) -and (isSurfacePro3))
{
	"[info] W8.1 or later AND SurfacePro3" | WriteTo-Stdout
	#
	# Connected Standby Battery Saver Timeout
	#
	#HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\381b4222-f694-41f0-9685-ff5bb260df2e\e73a048d-bf27-4f12-9731-8b2076e8891f\7398e821-3937-4469-b07b-33eb785aaca1
	$regkeyCsBsTimeout = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\381b4222-f694-41f0-9685-ff5bb260df2e\e73a048d-bf27-4f12-9731-8b2076e8891f\7398e821-3937-4469-b07b-33eb785aaca1"
	If (test-path $regkeyCsBsTimeout)
	{
		$regvalueCsBsTimeoutACSettingIndexRecommended = 14400
		$regvalueCsBsTimeoutACSettingIndex = Get-ItemProperty -path $regkeyCsBsTimeout -name "ACSettingIndex" -ErrorAction SilentlyContinue	
		if ($null -ne $regvalueCsBsTimeoutACSettingIndex)
		{
			$regvalueCsBsTimeoutACSettingIndex = $regvalueCsBsTimeoutACSettingIndex.ACSettingIndex
			if ($regvalueCsBsTimeoutACSettingIndex -ne 14400)
			{
				$RootCauseDetected = $true
				add-member -inputobject $InformationCollected -membertype noteproperty -name "Connected Standby Battery Saver Timeout: ACSettingIndex (Current Setting Not Optimal)" -value $regvalueCsBsTimeoutACSettingIndex
				#add-member -inputobject $InformationCollected -membertype noteproperty -name "Connected Standby Battery Saver Timeout: ACSettingIndex (Recommended Setting)" -value $regvalueCsBsTimeoutACSettingIndexRecommended
			}
			else
			{
				add-member -inputobject $InformationCollected -membertype noteproperty -name "Connected Standby Battery Saver Timeout: ACSettingIndex (No Action Needed)" -value $regvalueCsBsTimeoutACSettingIndexRecommended	
			}
		}
		
		$regvalueCsBsTimeoutDCSettingIndexRecommended = 14400
		$regvalueCsBsTimeoutDCSettingIndex = Get-ItemProperty -path $regkeyCsBsTimeout -name "DCSettingIndex" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueCsBsTimeoutDCSettingIndex)
		{
			$regvalueCsBsTimeoutDCSettingIndex = $regvalueCsBsTimeoutDCSettingIndex.DCSettingIndex
			if ($regvalueCsBsTimeoutDCSettingIndex -ne 14400)
			{
				$RootCauseDetected = $true
				add-member -inputobject $InformationCollected -membertype noteproperty -name "Connected Standby Battery Saver Timeout: DCSettingIndex (Current Setting Not Optimal)" -value $regvalueCsBsTimeoutDCSettingIndex
				#add-member -inputobject $InformationCollected -membertype noteproperty -name "Connected Standby Battery Saver Timeout: DCSettingIndex (Recommended Setting)" -value $regvalueCsBsTimeoutDCSettingIndexRecommended
			}
			else
			{
				add-member -inputobject $InformationCollected -membertype noteproperty -name "Connected Standby Battery Saver Timeout: DCSettingIndex (No Action Needed)" -value $regvalueCsBsTimeoutDCSettingIndex	
			}
		}
	}

	#
	# Connected Standby Battery Saver Trip Point
	#
	#HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\381b4222-f694-41f0-9685-ff5bb260df2e\e73a048d-bf27-4f12-9731-8b2076e8891f\1e133d45-a325-48da-8769-14ae6dc1170b
	$regkeyCsBsTripPoint = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\381b4222-f694-41f0-9685-ff5bb260df2e\e73a048d-bf27-4f12-9731-8b2076e8891f\1e133d45-a325-48da-8769-14ae6dc1170b"
	If (test-path $regkeyCsBsTripPoint)
	{
		$regvalueCsBstpACSettingIndexRecommended = 100
		$regvalueCsBstpACSettingIndex = Get-ItemProperty -path $regkeyCsBsTripPoint -name "ACSettingIndex" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueCsBstpACSettingIndex)	
		{
			$regvalueCsBstpACSettingIndex = $regvalueCsBstpACSettingIndex.ACSettingIndex
			if ($regvalueCsBstpACSettingIndex -ne 100)
			{
				$RootCauseDetected = $true
				add-member -inputobject $InformationCollected -membertype noteproperty -name "Connected Standby Battery Saver Trip Point: ACSettingIndex (Current Setting Not Optimal)" -value $regvalueCsBstpACSettingIndex
				#add-member -inputobject $InformationCollected -membertype noteproperty -name "Connected Standby Battery Saver Trip Point: ACSettingIndex (Recommended Setting)" -value $regvalueCsBstpACSettingIndexRecommended
			}
			else
			{
				add-member -inputobject $InformationCollected -membertype noteproperty -name "Connected Standby Battery Saver Trip Point: ACSettingIndex (No Action Needed)" -value $regvalueCsBstpACSettingIndex				
			}
		}

		$regvalueCsBstpDCSettingIndex = Get-ItemProperty -path $regkeyCsBsTripPoint -name "DCSettingIndex" -ErrorAction SilentlyContinue	
		if ($null -ne $regvalueCsBstpDCSettingIndex)	
		{
			$regvalueCsBstpDCSettingIndex = $regvalueCsBstpDCSettingIndex.DCSettingIndex
			$regvalueCsBstpDCSettingIndexRecommended = 100
			if ($regvalueCsBstpDCSettingIndex -ne 100)
			{
				$RootCauseDetected = $true
				add-member -inputobject $InformationCollected -membertype noteproperty -name "Connected Standby Battery Saver Trip Point: DCSettingIndex (Current Setting Not Optimal)" -value $regvalueCsBstpDCSettingIndex
				#add-member -inputobject $InformationCollected -membertype noteproperty -name "Connected Standby Battery Saver Trip Point: DCSettingIndex (Recommended Setting)" -value $regvalueCsBstpDCSettingIndexRecommended
			}
			else
			{
				add-member -inputobject $InformationCollected -membertype noteproperty -name "Connected Standby Battery Saver Trip Point: DCSettingIndex (No Action Needed)" -value $regvalueCsBstpDCSettingIndex				
			}
		}
	}
	
	#
	# Connected Standby Battery Saver Action
	#
	# HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\381b4222-f694-41f0-9685-ff5bb260df2e\e73a048d-bf27-4f12-9731-8b2076e8891f\c10ce532-2eb1-4b3c-b3fe-374623cdcf07
	$regkeyCsBsAction = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\381b4222-f694-41f0-9685-ff5bb260df2e\e73a048d-bf27-4f12-9731-8b2076e8891f\c10ce532-2eb1-4b3c-b3fe-374623cdcf07"
	If (test-path $regkeyCsBsAction)
	{
		$regvalueCsBsActionACSettingIndex = Get-ItemProperty -path $regkeyCsBsAction -name "ACSettingIndex" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueCsBsActionACSettingIndex)
		{
			$regvalueCsBsActionACSettingIndex = $regvalueCsBsActionACSettingIndex.ACSettingIndex
			$regvalueCsBsActionACSettingIndexRecommended = 1
			if ($regvalueCsBsActionACSettingIndex -ne 1)
			{
				$RootCauseDetected = $true
				add-member -inputobject $InformationCollected -membertype noteproperty -name "Connected Standby Battery Saver Action: ACSettingIndex (Current Setting Not Optimal)" -value $regvalueCsBsActionACSettingIndex
				#add-member -inputobject $InformationCollected -membertype noteproperty -name "Connected Standby Battery Saver Action: ACSettingIndex (Recommended Setting)" -value $regvalueCsBsActionACSettingIndexRecommended
			}
			else
			{
				add-member -inputobject $InformationCollected -membertype noteproperty -name "Connected Standby Battery Saver Action: ACSettingIndex (No Action Needed)" -value $regvalueCsBsActionACSettingIndex
			}
		}
		
		$regvalueCsBsActionDCSettingIndex = Get-ItemProperty -path $regkeyCsBsAction -name "DCSettingIndex" -ErrorAction SilentlyContinue
		if ($null -ne $regvalueCsBsActionDCSettingIndex)
		{
			$regvalueCsBsActionDCSettingIndex = $regvalueCsBsActionDCSettingIndex.DCSettingIndex
			$regvalueCsBsActionDCSettingIndexRecommended = 1
			if ($regvalueCsBsActionDCSettingIndex -ne 1)
			{
				$RootCauseDetected = $true
				add-member -inputobject $InformationCollected -membertype noteproperty -name "Connected Standby Battery Saver Action: DCSettingIndex (Current Setting Not Optimal)" -value $regvalueCsBsActionDCSettingIndex
				#add-member -inputobject $InformationCollected -membertype noteproperty -name "Connected Standby Battery Saver Action: DCSettingIndex (Recommended Setting)" -value $regvalueCsBsActionDCSettingIndexRecommended
			}
			else
			{
				add-member -inputobject $InformationCollected -membertype noteproperty -name "Connected Standby Battery Saver Action: DCSettingIndex (No Action Needed)" -value $regvalueCsBsActionDCSettingIndex
			}
		}
	}



	if ($RootCauseDetected -eq $true)
	{
		# Completing the Root Cause
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName  -InternalContentURL $InternalContent -Verbosity $Verbosity -InformationCollected $InformationCollected -Visibility $Visibility -SupportTopicsID $SupportTopicsID -MessageVersion 1
		# -PublicContentURL $PublicContent
	}
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}


# SIG # Begin signature block
# MIInpAYJKoZIhvcNAQcCoIInlTCCJ5ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC9lC6Qp4OyiV5k
# qSmMBgLE99t/0u6TQkasrI9+8ZncOaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGYQwghmAAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKs6l/gpnnL8qxwwEzrMRGXz
# K59wRVHazmpfApFu454vMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBMLeMo0hOKabPLNAQLRko0and536E0H2b/RX49fIyE0Y1cDOZ8Psze
# 7WcKxCS4NyKtKopk1KZeq2MQraA3MWwUoysRgVr3Axj+C8kWlFUTqx5qAJOOV/DN
# x8YLGsGE6va4WplaL67zqPKOS9KAkP7YNrKlYHOcvu7Tub0fEHiQIIXzC10dHafL
# 4lJc0HW3PvcI8dWszPGzek9zLH/DYHzpUu/NZUEU69fN31kKiEH/C4HfiDnbT3Wb
# KvZkknMkW5IiOFAjPatwU+tNBMdDr5NXrc2wboj2bV6HwYyb+DnP0vLkF7d2LWW/
# RkYIONbYayH5K+25J2hDW0jPsvkq0wGsoYIXDDCCFwgGCisGAQQBgjcDAwExghb4
# MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEINkGFWnh+/034/ZZ188YfXQ4CQKw26GONTF0J19MofQQAgZi2wZs
# lC8YEzIwMjIwODAxMDgxMDE2LjAzOFowBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0
# RDJGLUUzREQtQkVFRjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaCCEV8wggcQMIIE+KADAgECAhMzAAABsKHjgzLojTvAAAEAAAGwMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMDMw
# MjE4NTE0MloXDTIzMDUxMTE4NTE0Mlowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0RDJGLUUzREQtQkVF
# RjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAJzGbTsM19KCnQc5RC7VoglySXMKLut/
# yWWPQWD6VAlJgBexVKx2n1zgX3o/xA2ZgZ/NFGcgNDRCJ7mJiOeW7xeHnoNXPlg7
# EjYWulfk3oOAj6a7O15GvckpYsvLcx+o8Se8CrfIb40EJ8W0Qx4TIXf0yDwAJ4/q
# O94dJ/hGabeJYg4Gp0G0uQmhwFovAWTHlD1ci+sp36AxT9wIhHqw/70tzMvrnDF7
# jmQjaVUPnjOgPOyFWZiVr7e6rkSl4anT1tLv23SWhXqMs14wolv4ZeQcWP84rV2F
# rr1KbwkIa0vlHjlv4xG9a6nlTRfo0CYUQDfrZOMXCI5KcAN2BZ6fVb09qtCdsWdN
# NxB0y4lwMjnuNmx85FNfzPcMZjmwAF9aRUUMLHv626I67t1+dZoVPpKqfSNmGtVt
# 9DETWkmDipnGg4+BdTplvgGVq9F3KZPDFHabxbLpSWfXW90MZXOuFH8yCMzDJNUz
# eyAqytFFyLZir3j4T1Gx7lReCOUPw1puVzbWKspV7ModZjtN/IUWdVIdk3HPp4QN
# 1wwdVvdXOsYdhG8kgjGyAZID5or7C/75hyKQb5F0Z+Ee04uY9K+sDZ3l3z8TQZWA
# fYurbZCMWWnmJVsu5V4PR5PO+U6D7tAtMvMULNYibT9+sxVZK/WQer2JJ9q3Z7lj
# Fs4lgpmfc6AVAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUOt8BJDcBJm4dy6ASZHrX
# IEfWNj8wHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgw
# VjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWlj
# cm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUF
# BwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
# KS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQsFAAOCAgEA3XPih5sNtUfAyLnlXq6MZSpCh0TF+uG+nhIJ44//cMcQGEVi
# Z2N263NwvrQjCFOni/+oxf76jcmUhcKWLXk9hhd7vfFBhZZzcF5aNs07Uligs24p
# veasFuhmJ4y82OYm1G1ORYsFndZdvF//NrYGxaXqUNlRHQlskV/pmccqO3Oi6wLH
# cPB1/WRTLJtYbIiiwE/uTFEFEL45wWD/1mTCPEkFX3hliXEypxXzdZ1k6XqGTysG
# AtLXUB7IC6CH26YygKQuXG8QjcJBAUG/9F3yNZOdbFvn7FinZyNcIVLxld7h0bEL
# fQzhIjelj+5sBKhLcaFU0vbjbmf0WENgFmnyJNiMrL7/2FYOLsgiQDbJx6Dpy1Ef
# vuRGsdL5f+jVVds5oMaKrhxgV7oEobrA6Z56nnWYN47swwouucHf0ym1DQWHy2DH
# OFRRN7yv++zes0GSCOjRRYPK7rr1Qc+O3nsd604Ogm5nR9QqhOOc2OQTrvtSgXBS
# tu5vF6W8DPcsns53cQ4gdcR1Y9Ng5IYEwxCZzzYsq9oalxlH+ZH/A6J7ZMeSNKNk
# rXPx6ppFXUxHuC3k4mzVyZNGWP/ZgcUOi2qV03m6Imytvi1kfGe6YdCh32POgWeN
# H9lfKt+d1M+q4IhJLmX0E2ZZICYEb9Q0romeMX8GZ+cbhuNsFimJga/fjjswggdx
# MIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGI
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylN
# aWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5
# MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciEL
# eaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa
# 4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxR
# MTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEByd
# Uv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi9
# 47SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJi
# ss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+
# /NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY
# 7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtco
# dgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH
# 29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94
# q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcV
# AQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0G
# A1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQB
# gjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# GQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB
# /wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0f
# BE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJv
# ZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4w
# TDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIB
# AJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRs
# fNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6
# Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveV
# tihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKB
# GUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoy
# GtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQE
# cb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFU
# a2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+
# k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0
# +CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cir
# Ooo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC0jCCAjsCAQEwgfyh
# gdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAn
# BgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjo0RDJGLUUzREQtQkVFRjElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAAp4vkN3fD5FN
# BVYZklZeS/JFPBiggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQUFAAIFAOaRYjswIhgPMjAyMjA4MDEwMDE5MDdaGA8yMDIy
# MDgwMjAwMTkwN1owdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pFiOwIBADAKAgEA
# AgIIYAIB/zAHAgEAAgIQpDAKAgUA5pKzuwIBADA2BgorBgEEAYRZCgQCMSgwJjAM
# BgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEB
# BQUAA4GBACIGRhs2npZ86ze5XX7bBRD/cJXce61yTudp0mcrK6L61CQtFKU97yxX
# 70q6VQobkjEyQHfH1Hv4CF/K4uK2KTMj1KexQaqMmfS1oHs0euVDl7Hao5qOdQzl
# rY+r47GbBQeZA0409+8Enz5PtxoLEgvTkrjuZhJN/8JtrfsuE8WfMYIEDTCCBAkC
# AQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGwoeODMuiN
# O8AAAQAAAbAwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG
# 9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgVtFWaTJlgyACHnszxj49PDpaJHaKWsCv
# AynQPyW8ozAwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCDNBgtDd8uf9KTj
# Gf1G67IfKmcNFJmeWTd6ilAy5xWEoDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAABsKHjgzLojTvAAAEAAAGwMCIEIFn307NRqWDFmauv
# lOK94kvWvU2F8vPBc3hLhZ9yD3zCMA0GCSqGSIb3DQEBCwUABIICAFOcwPeCxfqF
# nxrE+iiP2URhMp1BDc2hZngGc47veepLTKn+b/Tp84FX8NCqMobO/Bjd6ljmiuKI
# oYyY99weqB4CFObzXfLjIeh3DAF/F6I4brIR9io8KoavlWMKGYVPpj0lRH+3A+za
# 17H9NSh3qjvtLToQItM0nHqq+7VzpvAmoUbLSyMjocBDGhm8B5Q+pudS/ov5mfPD
# geHUj7CMN7nj3SshRad2ckB7pAcZcM+VbvajI8P7lizNxDp2y3GpXOE0L8HLa67s
# 7BzoI814Su0vtKjEHHt7K2E0Lt4VAMgMWfh3yy7oUc7qeNRvUP+pC/lvew+m5Ml8
# 8+54YBIoIqFittKikHzBVkXKHpQP6Ofhbp6Otwl5KkRr/pSUEqHNjG9GFd5pqheh
# gLhxlEMvXsp1/HeprNybrHchovNgWR9pQViJ0rti7p8Bbd9pkHQR6jHKvLPqmjGL
# 5IlAz9EOID3ZoUjanJoI2I58fCj9lOPeji85eguW88G6TGCwA6YkgaG7wBiD2DKy
# 67IGcIdN1Sjmu6fKxZe7smhfngvYwgRkld/Dc86ab7x8suN6LxTOsl4dT+1Ux4wx
# CcBwNKlEYbu12lN0+wux8K0emPZaVpgqcd9mJmY3RSP7c+GIg9YmiZwIh6N7Ri5y
# XfmBzS6qnGkGqc6+JkCiQdnnGsyo6nav
# SIG # End signature block
