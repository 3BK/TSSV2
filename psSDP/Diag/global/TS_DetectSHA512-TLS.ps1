#***********************************************
# TS_DetectSHA512-TLS.ps1
# Version 1.0
# Date: 03/19/2014
# Author: Tim Springston [MSFT]
# Description:  On Windows 7/Server 2008 R2 and later computers which are default and do not have
#  RSA/SHA512 (OID 1.2.840.113549.1.1.5) enabled for TLS 1.2, the script searches through the user and computer My certificate
#  stores for Server Auth and Client Auth certificates which are signed with SHA512RSA signatures.
#  The script then warns the engineer that there are certificates which will cause SSL/TLS to fail. 
#  http://bemis/2950636
#************************************************
$RootCauseDetected = $False 

"Within SHA 512 Script." | WriteTo-StdOut -shortformat

#Add root cause and status string stuff here.
Import-LocalizedData -BindingVariable ScriptStrings
Write-DiagProgress -Activity $ScriptStrings.ID_PKITests_Wait -Status $ScriptStrings.ID_PKITests_Status

function RC_DetectSHA512-TLS
{	PARAM( $InformationCollected)
	"InfoCollected is $InformationCollected" | WriteTo-StdOut -shortformat
	Add-GenericMessage -id "RC_DetectSHA512-TLS" -InformationCollected $InformationCollected
}

#Detect if the OS may have the issue, and if the workaround to the issue is in the registry or not.
$OSApplies = $false
$512Value = $false

$OS = Get-CimInstance -Class win32_operatingsystem
if ($OS.Buildnumber -ge 7600)
	{
	$OSApplies = $True
	"Applies to this OS" | WriteTo-StdOut -shortformat
	}

$SSLKey = get-item -Path Registry::HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010003
$FunctionsValue = $SSLKey.GetValue('Functions')

if ($FunctionsValue -contains 'RSA/SHA512')
	{
	$512Value = $true
	"Within RSA/SHA512 registry value detected" | WriteTo-StdOut -shortformat
	}


if (($OSApplies -eq $true) -and ($512Value -eq $true))
	{
	#Look through the My stores of computer and user for Server Auth or Client Auth certificates which have been signed using RSA512 sigs.
	get-childitem -path cert:\ -recurse | Where-Object {(($_.PSParentPath -ne $null) -or ($CheckStores -contains (Split-Path ($_.PSParentPath) -Leaf))) -and `
	($_.PSIsContainer -ne $true) -and  (($_.EnhancedKeyUsageList -match '(1.3.6.1.5.5.7.3.1)') -or ($_.EnhancedKeyUsageList -match '(1.3.6.1.5.5.7.3.2)')) `
	-and ($_.SignatureAlgorithm.value -eq '1.2.840.113549.1.1.13')  } | ForEach-Object {

		"Within detection of a certificate which matches." | WriteTo-StdOut -shortformat
		"Certificate details $_" | WriteTo-StdOut -shortformat

		$Store = (Split-Path ($_.PSParentPath) -Leaf)
	    $StorePath = (($_.PSParentPath).Split("\"))     
	    $CertObject = new-object PSObject
	    $StoreWorkingContext = $Store
	    $StoreContext = Split-Path $_.PSParentPath.Split("::")[-1] -Leaf
	   if ($_.FriendlyName.length -gt 0)
	  	{add-member -inputobject $CertObject -membertype noteproperty -name "Friendly Name" -value $_.FriendlyName}
	  	else
	  	{add-member -inputobject $CertObject -membertype noteproperty -name "Friendly Name" -value "[None]"}
	  
		#Determine the context (User or Computer) of the certificate store.
	   $StoreWorkingContext = (($_.PSParentPath).Split("\"))
	   $StoreContext = ($StoreWorkingContext[1].Split(":"))
	   add-member -inputobject $CertObject -membertype noteproperty -name "Path" -value $StoreContext[2]
	   add-member -inputobject $CertObject -membertype noteproperty -name "Store" -value $StorePath[$StorePath.count-1]
	   add-member -inputobject $CertObject -membertype noteproperty -name "Has Private Key" -value $_.HasPrivateKey
	   add-member -inputobject $CertObject -membertype noteproperty -name "Serial Number" -value $_.SerialNumber
	   add-member -inputobject $CertObject -membertype noteproperty -name "Thumbprint" -value $_.Thumbprint
	   add-member -inputobject $CertObject -membertype noteproperty -name "Issuer" -value $_.IssuerName.Name
		if ($_.SignatureAlgorithm.value -eq  '1.2.840.113549.1.1.12')
	    {add-member -inputobject $CertObject -membertype noteproperty -name "Signature Strength" -value 'sha384RSA'}
			if ($_.SignatureAlgorithm.value -eq  '1.2.840.113549.1.1.13')
	    {add-member -inputobject $CertObject -membertype noteproperty -name "Signature Strength" -value 'sha512RSA'}
	   add-member -inputobject $CertObject -membertype noteproperty -name "Not Before" -value $_.NotBefore
	   add-member -inputobject $CertObject -membertype noteproperty -name "Not After" -value $_.NotAfter
	   add-member -inputobject $CertObject -membertype noteproperty -name "Subject Name" -value $_.SubjectName.Name
	   if (($_.Extensions | Where-Object {$_.Oid.FriendlyName -match "subject alternative name"}) -ne $null)
	        {add-member -inputobject $CertObject -membertype noteproperty -name "Subject Alternative Name" -value ($_.Extensions | Where-Object {$_.Oid.FriendlyName -match "subject alternative name"}).Format(1)
	        }
	        else
	        {add-member -inputobject $CertObject -membertype noteproperty -name "Subject Alternative Name" -value "[None]"}
	   if (($_.Extensions | Where-Object {$_.Oid.FriendlyName -like "Key Usage"}) -ne $null) 
	        {add-member -inputobject $CertObject -membertype noteproperty -name "Key Usage" -value ($_.Extensions | Where-Object {$_.Oid.FriendlyName -like "Key Usage"}).Format(1)
	        }
	        else
	        {add-member -inputobject $CertObject -membertype noteproperty -name "Key Usage" -value "[None]"}
	   if ($_.EnhancedKeyUsageList -ne $null)
	        {add-member -inputobject $CertObject -membertype noteproperty -name "Enhanced Key Usage" -value $_.EnhancedKeyUsageList}
	        else
	        {add-member -inputobject $CertObject -membertype noteproperty -name "Enhanced Key Usage" -value "[None]"}
	   if (($_.Extensions | Where-Object {$_.Oid.FriendlyName -match "Certificate Template Information"}) -ne $null)
	        {add-member -inputobject $CertObject -membertype noteproperty -name "Certificate Template Information" -value ($_.Extensions | Where-Object {$_.Oid.FriendlyName -match "Certificate Template Information"}).Format(1)
	        }
	        else
	        {add-member -inputobject $CertObject -membertype noteproperty -name "Certificate Template Information" -value "[None]"}
	   if (($_.Extensions | Where-Object {$_.Oid.FriendlyName -match "authority key identifier"}) -ne $null)
	        {add-member -inputobject $CertObject -membertype noteproperty -name "Authority Key Identifier" -value ($_.Extensions | Where-Object {$_.Oid.FriendlyName -match "Authority Key Identifier" }).Format(1)
	        }
	        else
	        {add-member -inputobject $CertObject -membertype noteproperty -name "Authority Key Identifier"  -value "[None]"}
	
	   ForEach ($Extension in $_.Extensions)
	        {
	        if ($Extension.OID.FriendlyName -eq 'Authority Information Access')
	              {
	              #Convert the RawData in the extension to readable form.
	              $FormattedExtension = $Extension.Format(1)
				  $AIAFound = $True
	              add-member -inputobject $CertObject -membertype noteproperty -name "AIA URLs" -value $FormattedExtension
	              }
	        if ($Extension.OID.FriendlyName -eq 'CRL Distribution Points')
	              {
	              #Convert the RawData in the extension to readable form.
	              $FormattedExtension = $Extension.Format(1)
				  $CDPFound = $True
	              add-member -inputobject $CertObject -membertype noteproperty -name "CDP URLs" -value $FormattedExtension
	              }
	        if ($Extension.OID.Value -eq '1.3.6.1.5.5.7.48.1')
	              {
	              #Convert the RawData in the extension to readable form.
	              $FormattedExtension = $Extension.Format(1)
				  $OCSPFound = $True
	              add-member -inputobject $CertObject -membertype noteproperty -name "OCSP URLs" -value $FormattedExtension
	              }
	        }
		
		if ($AIAFound -ne $true)
			{add-member -inputobject $CertObject -membertype noteproperty -name "AIA URLs" -value "[None]"}
		if ($CDPFound -ne $true)
			{add-member -inputobject $CertObject -membertype noteproperty -name "CDP URLs" -value "[None]"}
		if ($OCSPFound -ne $true)
			{add-member -inputobject $CertObject -membertype noteproperty -name "OCSP URLs" -value "[None]"}

		"CertObject is $CertObject" | WriteTo-StdOut -shortformat
     	RC_DetectSHA512-TLS $CertObject
		$RootCauseDetected = $true
	 	$CertObject = $null

	  }
}





if ($RootCauseDetected -eq $true)
	{
	#Red/ Yellow Light
	Update-DiagRootCause -id "RC_DetectSHA512-TLS" -Detected $true
	}
	else
	{
	#Green Light
	Update-DiagRootCause -id "RC_DetectSHA512-TLS" -Detected $false
	}


# SIG # Begin signature block
# MIInlwYJKoZIhvcNAQcCoIIniDCCJ4QCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD03eKAjll46/CP
# 7HOFb6b2r6FRmN8i0oTQqw2RcGV3OqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXcwghlzAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILJeucFCBE2d0eN4ARkbMvo5
# vTFMKOOIcsko7x5UVj0MMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBATQ4jfCTAEcgRxg14v/WRGo0Lgt2bDQht0wPPLqjegCe4YHpxINS8
# gDV+ZZ2tgRlTMiL6t3OPYKOXNKbp3AwyFni8VeLlxEnvy0UzLIKHnt+1LGtWoa2r
# Kl7pKOKIxx0JKLOobi03T18XVznej2n66ZxiVqPmyf6sPeB2Ifp608wgzj3ftMnm
# CCPT2H557dg4hj7moZqiT9LA1S1nW4ytqBVnL2WbwmwLy++t3cQvmZBEyQIO4RFD
# iSTvP3brrJztQGd1osp3VTgPARW3bujyq5P/TLqDTamdgnKooErLhrFpC+t/BsfZ
# ZZZo8F6PsJBJIbjK88J3kqRJYCQZitGhoYIW/zCCFvsGCisGAQQBgjcDAwExghbr
# MIIW5wYJKoZIhvcNAQcCoIIW2DCCFtQCAQMxDzANBglghkgBZQMEAgEFADCCAVAG
# CyqGSIb3DQEJEAEEoIIBPwSCATswggE3AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEICUW0yEeADPHxU2uJxh9uESLOe0qxFyzbf0NNk8ScVnLAgZiz/Ws
# D/cYEjIwMjIwODAxMDgwMTAyLjMyWjAEgAIB9KCB0KSBzTCByjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFt
# ZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046REQ4Qy1F
# MzM3LTJGQUUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghFXMIIHDDCCBPSgAwIBAgITMwAAAZwPpk1h0p5LKAABAAABnDANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMTEyMDIxOTA1
# MTlaFw0yMzAyMjgxOTA1MTlaMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpERDhDLUUzMzctMkZBRTElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBANtSKgwZXUkWP6zrXazTaYq7bco9Q2zvU6MN4ka3GRMX
# 2tJZOK4DxeBiQACL/n7YV/sKTslwpD0f9cPU4rCDX9sfcTWo7XPxdHLQ+WkaGbKK
# WATsqw69bw8hkJ/bjcp2V2A6vGsvwcqJCh07BK3JPmUtZikyy5PZ8fyTyiKGN7hO
# WlaIU9oIoucUNoAHQJzLq8h20eNgHUh7eI5k+Kyq4v6810LHuA6EHyKJOZN2xTw5
# JSkLy0FN5Mhg/OaFrFBl3iag2Tqp4InKLt+Jbh/Jd0etnei2aDHFrmlfPmlRSv5w
# SNX5zAhgEyRpjmQcz1zp0QaSAefRkMm923/ngU51IbrVbAeHj569SHC9doHgsIxk
# h0K3lpw582+0ONXcIfIU6nkBT+qADAZ+0dT1uu/gRTBy614QAofjo258TbSX9aOU
# 1SHuAC+3bMoyM7jNdHEJROH+msFDBcmJRl4VKsReI5+S69KUGeLIBhhmnmQ6drF8
# Ip0ZiO+vhAsD3e9AnqnY7Hcge850I9oKvwuwpVwWnKnwwSGElMz7UvCocmoUMXk7
# Vn2aNti+bdH28+GQb5EMsqhOmvuZOCRpOWN33G+b3g5unwEP0eTiY+LnWa2AuK43
# z/pplURJVle29K42QPkOcglB6sjLmNpEpb9basJ72eA0Mlp1LtH3oYZGXsggTfuX
# AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUu2kJZ1Ndjl2112SynL6jGMID+rIwHwYD
# VR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZO
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBc
# BggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYD
# VR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOC
# AgEApwAqpiMYRzNNYyz3PSbtijbeyCpUXcvIrqA4zPtMIcAk34W9u9mRDndWS+tl
# R3WwTpr1OgaV1wmc6YFzqK6EGWm903UEsFE7xBJMPXjfdVOPhcJB3vfvA0PX56oo
# bcF2OvNsOSwTB8bi/ns+Cs39Puzs+QSNQZd8iAVBCSvxNCL78dln2RGU1xyB4AKq
# V9vi4Y/Gfmx2FA+jF0y+YLeob0M40nlSxL0q075t7L6iFRMNr0u8ROhzhDPLl+4e
# PYfUmyYJoobvydel9anAEsHFlhKl+aXb2ic3yNwbsoPycZJL/vo8OVvYYxCy+/5F
# rQmAvoW0ZEaBiYcKkzrNWt/hX9r5KgdwL61x0ZiTZopTko6W/58UTefTbhX7Pni0
# MApH3Pvyt6N0IFap+/LlwFRD1zn7e6ccPTwESnuo/auCmgPznq80OATA7vufsRZP
# vqeX8jKtsraSNscvNQymEWlcqdXV9hYkjb4T/Qse9cUYaoXg68wFHFuslWfTdPYP
# Ll1vqzlPMnNJpC8KtdioDgcq+y1BaSqSm8EdNfwzT37+/JFtVc3Gs915fDqgPZDg
# OSzKQIV+fw3aPYt2LET3AbmKKW/r13Oy8cg3+D0D362GQBAJVv0NRI5NowgaCw6o
# NgWOFPrN72WSEcca/8QQiTGP2XpLiGpRDJZ6sWRpRYNdydkwggdxMIIFWaADAgEC
# AhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQg
# Um9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVa
# Fw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7V
# gtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeF
# RiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3X
# D9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoP
# z130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+
# tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5Jas
# AUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/b
# fV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuv
# XsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg
# 8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzF
# a/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqP
# nhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEw
# IwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSf
# pxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBB
# MD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0Rv
# Y3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGC
# NxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8w
# HwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmg
# R4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWlj
# Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEF
# BQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29D
# ZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEs
# H2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHk
# wo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinL
# btg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCg
# vxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsId
# w2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2
# zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23K
# jgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beu
# yOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/
# tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjm
# jJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBj
# U02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICzjCCAjcCAQEwgfihgdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOkREOEMtRTMzNy0yRkFFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQDN2Wnq3fCz9ucStub1zQz7129TQKCB
# gzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEB
# BQUAAgUA5pGFwDAiGA8yMDIyMDgwMTA2NTA0MFoYDzIwMjIwODAyMDY1MDQwWjB3
# MD0GCisGAQQBhFkKBAExLzAtMAoCBQDmkYXAAgEAMAoCAQACAh+tAgH/MAcCAQAC
# AhG4MAoCBQDmktdAAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKg
# CjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAiwzVlsn7
# X736sQ9EdfKdxDxpdG1PMxol7pOQyKWNdyXyvoR8dNDy6PmVQDqaeGPGB3i6lfKm
# G2PEPWZwYsXEuIGdV5N/hlxIzSrp4hgimt+l3Yb5MCdeH3TGHmH/84kYAKcajET8
# aqhQ1kbR53pB/gs+JxjWaBUROJvx+u6bovMxggQNMIIECQIBATCBkzB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAZwPpk1h0p5LKAABAAABnDANBglg
# hkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqG
# SIb3DQEJBDEiBCBEDpNziar5TjcTQ4CKp2a/on1zJU4wYW3SOS4RFduYazCB+gYL
# KoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIDcPRYUgjSzKOhF39d4QgbRZQgrPO7Lo
# /qE5GtvSeqa8MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAC
# EzMAAAGcD6ZNYdKeSygAAQAAAZwwIgQg2BjLC7vGc956wwX/nL39Jz98XP4t6yr7
# LlEYR9NmjBcwDQYJKoZIhvcNAQELBQAEggIAUz2RKKmUnw3YdQMOa+9ZtWTf/QNG
# 7KAkhH4NWRgUgNI0CyUKnM0/vLtN70UWD6yvTmYiUTDKKbbBs/sMOBQKkCZ+ZOg4
# o3KBcn60L31oeRt7jtYXl/DKOlj3BHtOocIEmEbJc310sdnDCJgOSKU6jTB81qZN
# RrtmAlU3tvHFlBn8m0jqxGf2/4T2OwQLdxIT1cR9S8eC8yZo/fjnmBdBM3Q+ciRR
# sbIE5+GFaDjD77/zrSzUB8AUkeL7UA+i3euHQW4EqMicIrhX1MX+INBNEcGnU88O
# GJOipK3OxtHbKeRRYzvMBsjvQWvGDUFH3Sf4y7qvXhhIwiEE6oSH/KfKg6i0e1Dw
# i04zn3g6GCdqUk/Ra2MViRF93p3RRTVwt0hM4QBOCc1/3o/RuxZAqHxGO9lNCOgU
# 7ct7GlTzFEewKDPVcIWlVZrfAnfGDvFfTHsotD5KDIFof8KWzJw4yYWRlxDx4WHo
# vx7+QJddpy5mcx3nkswXgc/wCVYfNCdGTJr5962Lj29ORQ11ZhdLucz3Pp+DNzdP
# 6k3Xu44psUwyNLVo3+ugTpbmZpqVqoZEgxs5YSH8fvLnErUe+6AL9t2T8lQdweff
# VbMHMpHt/H/vxmytslQEu4CGdkSEcwFJ3aojwXfsGPn/MhKiqSd+za1rmOxSxjM5
# MO6ySJBrT+QDDQU=
# SIG # End signature block
