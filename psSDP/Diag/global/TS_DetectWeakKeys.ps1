#************************************************
# TS_DetectWeakKeys.ps1
# Version 1.0.1
# Date: 8/6/2012
# Author: tspring
# Description:  [Idea ID 5009] [Windows] Weak Key Block Detection
# Rule number:  5009
# Rule URL:  http://sharepoint/sites/rules/Rule Submissions/Forms/DispForm.aspx?ID=5009
# This rule looks at all certificates in the "My" stores and if they have RSA keys less than 1024 length the problem is detected.
#************************************************

Import-LocalizedData -BindingVariable ScriptStrings

Write-DiagProgress -Activity $ScriptStrings.ID_DetectWeakKeysCertTitle `
-Status $ScriptStrings.ID_DetectWeakKeysCertDesc

$RuleApplicable = $false
$RootCauseDetected = $false
$RootCauseName = "RC_DetectWeakKeys"
$PublicContent = "http://blogs.technet.com/b/pki/archive/2012/06/12/rsa-keys-under-1024-bits-are-blocked.aspx"
$InternalContent = ""
$Verbosity = "Error"
$Visibility = "4"
$SupportTopicsID = "18568"
$Title = $ScriptStrings.ID_DetectWeakKeys_ST
$IssueDetected = $false
$InformationCollected = new-object PSObject
$CheckStores = @("My", "CA", "Root")

$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber
[int]$sp = [int]$wmiOSVersion.ServicePackMajorVersion
	#$OSVer = Get-CimInstance -Class Win32_OperatingSystem
	#$bn = $OSVer.BuildNumber
	#$sp = $OSVer.ServicePackMajorVersion
	"Build number is $bn" | WriteTo-StdOut -ShortFormat
	"SP level is $sp" | WriteTo-StdOut -ShortFormat

"Script is running." | WriteTo-StdOut -ShortFormat

# ***************************
# Data Gathering
# ***************************

Function AppliesToSystem
	{
	$HotfixInstalled = $false
	"Within AppliesToSystem function" | WriteTo-StdOut -ShortFormat

	switch -exact ($bn){
	"2600"  {"In Windows XP switch." | WriteTo-StdOut -ShortFormat		
		if	(CheckMinimalFileVersion "$System32Folder\Crypt32.dll" 5 131 2600 6239) 
				{$HotfixInstalled = $true}
		}
	"3790" { "In Windows Server 2003 switch." | WriteTo-StdOut -ShortFormat		
			$Proc = Get-CimInstance -class "Win32_Processor" -property "AddressWidth"
		if ($Proc.AddressWidth -eq 32)
			{if (CheckMinimalFileVersion "$System32Folder\Crypt32.dll" 5 131 3790 5014) 
				{$HotfixInstalled = $true}
			}
		if ($Proc.AddressWidth -eq 64)
			{ if ((CheckMinimalFileVersion "$System32Folder\Crypt32.dll" 5 131 3790 5014) -and (CheckMinimalFileVersion "$System32Folder\WCrypt32.dll" 5 131 3790 5014))
				{$HotfixInstalled = $true}
			}
		}
	"6002" {	"In Windows Server 2008 RTM switch." | WriteTo-StdOut -ShortFormat		
		if ($sp -eq 1)
			{if ((CheckMinimalFileVersion "$System32Folder\Crypt32.dll.mui" 6 0 6002 18643) -and (CheckMinimalFileVersion "$System32Folder\Crypt32.dll" 6 0 6002 18643) -and (CheckMinimalFileVersion "$System32Folder\Cryptnet.dll" 6 0 6002 18643) -and (CheckMinimalFileVersion "$System32Folder\Cryptsvc.dll" 6 0 6002 18643))
			{$HotfixInstalled = $true}
			}
		if($sp -eq 2)
			{if ((CheckMinimalFileVersion "$System32Folder\Crypt32.dll.mui" 6 0 6002 22869) -and (CheckMinimalFileVersion "$System32Folder\Crypt32.dll" 6 0 6002 22869) -and (CheckMinimalFileVersion "$System32Folder\Cryptnet.dll" 6 0 6002 22869) -and (CheckMinimalFileVersion "$System32Folder\Cryptsvc.dll" 6 0 6002 22869))
		 	{$HotfixInstalled = $true}
			}
		}
	"7600" { "In Windows Server 2008 R2 switch." | WriteTo-StdOut -ShortFormat		
		if ($sp -eq 1)
			{if ((CheckMinimalFileVersion "$System32Folder\Crypt32.dll.mui" 6 1 7600 17035) -and (CheckMinimalFileVersion "$System32Folder\Crypt32.dll" 6 1 7600 17035) -and (CheckMinimalFileVersion "$System32Folder\Cryptnet.dll" 6 1 7600 17035) -and (CheckMinimalFileVersion "$System32Folder\Cryptsvc.dll" 6 1 7600 17035))
			{$HotfixInstalled = $true}
			}
		
		if($sp -eq 2)
			{if ((CheckMinimalFileVersion "$System32Folder\Crypt32.dll.mui" 6 1 7600 21225) -and (CheckMinimalFileVersion "$System32Folder\Crypt32.dll" 6 1 7600 21225) -and (CheckMinimalFileVersion "$System32Folder\Cryptnet.dll" 6 1 7600 21225) -and (CheckMinimalFileVersion "$System32Folder\Cryptsvc.dll" 6 1 7600 21225))
			{$HotfixInstalled = $true}
			}
		}
	"7601" { 	"In Windows Server 2008 R2 switch." | WriteTo-StdOut -ShortFormat		
		if ($sp -eq 1)
			{if ((CheckMinimalFileVersion "$System32Folder\Crypt32.dll.mui" 6 1 7601 17856) -and (CheckMinimalFileVersion "$System32Folder\Crypt32.dll" 6 1 7601 17856) -and (CheckMinimalFileVersion "$System32Folder\Cryptnet.dll" 6 1 7601 17856) -and (CheckMinimalFileVersion "$System32Folder\Cryptsvc.dll" 6 1 7601 17856))
			{$HotfixInstalled = $true}
			}
		if($sp -eq 2)
			{if ((CheckMinimalFileVersion "$System32Folder\Crypt32.dll.mui" 6 1 7601 22010) -and (CheckMinimalFileVersion "$System32Folder\Crypt32.dll" 6 1 7601 22010) -and (CheckMinimalFileVersion "$System32Folder\Cryptnet.dll" 6 1 7601 22010) -and (CheckMinimalFileVersion "$System32Folder\Cryptsvc.dll" 6 1 7601 22010))
			{$HotfixInstalled = $true}
			}
		}
	"9200" { 
			#Windows 8 and Server 2012 comes with this out of box.
			$HotfixInstalled = $true
			"In Windows 8 switch." | WriteTo-StdOut -ShortFormat
			}
	"9600" { 
			#Windows 8 and Server 2012 comes with this out of box.
			$HotfixInstalled = $true
			"In Windows 8.1 switch." | WriteTo-StdOut -ShortFormat
			}
	[default] {WriteTo-StdOut "[info]: Hotfix check default for switch." -shortformat }
	}
	if ($HotfixInstalled -eq $true)
		{return $True}
		else
		{return $false}
	}

if (AppliesToSystem)
{#Set date to exclude expired certificates from being detected as the problem.
$Now = Get-Date
$Certindex = 0
$DetectedCertList = @()

$GetReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\OID\EncodingType 0\CertDLLCreateCertificateChainEngine\Config"
$WeakSigFlagRegVal = $GetReg.EnableWeakSignatureFlags

$CheckStores = @("My", "CA", "Root")

get-childitem -path cert:\ -recurse | Where-Object {($_.PSParentPath -ne $null) -and ($_.PublicKey.Key.Keysize -le 1023) -and `
($_.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1') -and ($CheckStores -contains (Split-Path ($_.PSParentPath) -Leaf)) -and `
($_.IssuerName.Name -ne "CN=Root Agency") -and (-not($_.NotAfter -lt $Now)) -and (-not($_.NotBefore -gt $Now)) } | ForEach-Object {

	$Store = (Split-Path ($_.PSParentPath) -Leaf)
	$StorePath = (($_.PSParentPath).Split("\"))	
	$InformationCollected = new-object PSObject
	$StoreWorkingContext = $Store
	$StoreContext = Split-Path $_.PSParentPath.Split("::")[-1] -Leaf
	     add-member -inputobject $InformationCollected -membertype noteproperty -name "Security Fix Installed" -value "True"
		 if ($WeakSigFlagRegVal -eq 2)
 			{add-member -inputobject $InformationCollected -membertype noteproperty -name "Registry Setting" -value "Use of weak RSA Root certificates Allowed" }
			elseif ($WeakSigFlagRegVal -eq 8)
			{add-member -inputobject $InformationCollected -membertype noteproperty -name "Registry Setting" -value "Use of all weak key certificates Allowed"}
				elseif  ($WeakSigFlagRegVal -eq $null)
				{add-member -inputobject $InformationCollected -membertype noteproperty -name "Registry Setting" -value "Use of weak key certificates Prohibited"}
		 if ($_.FriendlyName.length -gt 0)
		 {add-member -inputobject $InformationCollected -membertype noteproperty -name "Friendly Name" -value $_.FriendlyName}
			else
			{add-member -inputobject $InformationCollected -membertype noteproperty -name "Friendly Name" -value "[None]"}
		 #Determine the context (User or Computer) of the certificate store.
		 $StoreWorkingContext = (($_.PSParentPath).Split("\"))
		 $StoreContext = ($StoreWorkingContext[1].Split(":"))
		 add-member -inputobject $InformationCollected -membertype noteproperty -name "Path" -value $StoreContext[2]
		 add-member -inputobject $InformationCollected -membertype noteproperty -name "Store" -value $StorePath[$StorePath.count-1]
		 add-member -inputobject $InformationCollected -membertype noteproperty -name "Has Private Key" -value $_.HasPrivateKey
		 add-member -inputobject $InformationCollected -membertype noteproperty -name "Serial Number" -value $_.SerialNumber
		 add-member -inputobject $InformationCollected -membertype noteproperty -name "Thumbprint" -value $_.Thumbprint
		 add-member -inputobject $InformationCollected -membertype noteproperty -name "Issuer" -value $_.IssuerName.Name
		 add-member -inputobject $InformationCollected -membertype noteproperty -name "Not Before" -value $_.NotBefore
		 add-member -inputobject $InformationCollected -membertype noteproperty -name "Not After" -value $_.NotAfter
		 add-member -inputobject $InformationCollected -membertype noteproperty -name "Subject Name" -value $_.SubjectName.Name
		 add-member -inputobject $InformationCollected -membertype noteproperty -name "Public Key Name" -value $_.PublicKey.Oid.FriendlyName
		 add-member -inputobject $InformationCollected -membertype noteproperty -name "Public Key OID" -value $_.PublicKey.Oid.Value
		 add-member -inputobject $InformationCollected -membertype noteproperty -name "Public Key Size" -value $_.PublicKey.Key.Keysize
		  if (($_.Extensions | Where-Object {$_.Oid.FriendlyName -match "subject alternative name"}) -ne $null)
				{add-member -inputobject $InformationCollected -membertype noteproperty -name "Subject Alternative Name" -value ($_.Extensions | Where-Object {$_.Oid.FriendlyName -match "subject alternative name"}).Format(1)
				}
				else
				{add-member -inputobject $InformationCollected -membertype noteproperty -name "Subject Alternative Name" -value "[None]"}
		 if (($_.Extensions | Where-Object {$_.Oid.FriendlyName -like "Key Usage"}) -ne $null) 
				{add-member -inputobject $InformationCollected -membertype noteproperty -name "Key Usage" -value ($_.Extensions | Where-Object {$_.Oid.FriendlyName -like "Key Usage"}).Format(1)
				}
				else
				{add-member -inputobject $InformationCollected -membertype noteproperty -name "Key Usage" -value "[None]"}
		 if (($_.Extensions | Where-Object {$_.Oid.FriendlyName -like "Enhanced Key Usage"}) -ne $null)
				{add-member -inputobject $InformationCollected -membertype noteproperty -name "Enhanced Key Usage" -value ($_.Extensions | Where-Object {$_.Oid.FriendlyName -like "Enhanced Key Usage"}).Format(1)
				}
				else
				{add-member -inputobject $InformationCollected -membertype noteproperty -name "Enhanced Key Usage" -value "[None]"}
		 if (($_.Extensions | Where-Object {$_.Oid.FriendlyName -match "Certificate Template Information"}) -ne $null)
				{add-member -inputobject $InformationCollected -membertype noteproperty -name "Certificate Template Information" -value ($_.Extensions | Where-Object {$_.Oid.FriendlyName -match "Certificate Template Information"}).Format(1)
				}
				else
				{add-member -inputobject $InformationCollected -membertype noteproperty -name "Certificate Template Information" -value "[None]"}

		 if (($InformationCollected."Public Key Size" -le "1023") -and ($InformationCollected."Public Key Size" -ne $null) -and ($InformationCollected."Public Key OID" -eq "1.2.840.113549.1.1.1"))
			{add-member -inputobject $InformationCollected -membertype noteproperty -name "Problem Detected" -value $True
		 	 if ($InformationCollected."Problem Detected" -eq $True)
				{$IssueDetected = $true
	 			 Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL $PublicContent -InformationCollected $InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID -InternalContentURL $InternalContent -SolutionTitle $Title -MessageVersion 2
				}
				 $InformationCollected
			}
		
		$InformationCollected = $null
	}
}


# *********************
# Root Cause processing
# *********************
if ($IssueDetected)
	{
		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
	}
	else
	{
		# Green Light
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}


# SIG # Begin signature block
# MIInoQYJKoZIhvcNAQcCoIInkjCCJ44CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDdtGrgAQgM1xSJ
# FofLLG0423zIFfS8xVW2+6LjJQEioKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGYEwghl9AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFMw06Ze5NgxThfHnOUYX3uj
# UeyycO1mjiOoXOG9XsLdMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCIM8o+5aZw1906Ln7v/eGj+SqSfR6T62rOkA4U7OIX0HbUZF2KQmoh
# D5NaLSmhIbCgE9GpZL7fHV2PLAxCfWHCm+Ac+lBBuCUN3pC4En57cG1ADYZD7Krx
# qDA80Tn/2Le2JNE4W2DNl0sR+ePyRAhH6Ci6OR2benOzxHuFwu8fCmhBaCbMYSBR
# 6770DMs5p5M2IMHwFPanLw3rVwHs585ATWi4V3nQzcUZBVUaVN+l9M77twSuLmix
# oF7/sE8KH1MNOFye7DGn1N7IzXIX5GlMBDG/mz7olSz4rT5xSFciGB/UXy6wMtgE
# KiGrOOwE1qwUNeG5C6EM3Y6x8UOX37P/oYIXCTCCFwUGCisGAQQBgjcDAwExghb1
# MIIW8QYJKoZIhvcNAQcCoIIW4jCCFt4CAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEII6SMitlarx0DxnE6BgxdWsbGWvnacrpkgh3mcHrqGnqAgZi2xAP
# ZpcYEzIwMjIwODAxMDgwMTA2Ljc4MVowBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4
# OTdBLUUzNTYtMTcwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaCCEVwwggcQMIIE+KADAgECAhMzAAABqwkJ76tj1OipAAEAAAGrMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMDMw
# MjE4NTEyOFoXDTIzMDUxMTE4NTEyOFowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4OTdBLUUzNTYtMTcw
# MTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmdS1o5dehASUsscLqyx2wm/WirNUfq
# kGBymDItYzEnoKtkhrd7wNsJs4g+BuM3uBX81WnO270lkrC0e1mmDqQt420Tmb8l
# wsjQKM6mEaNQIfXDronrVN3aw1lx9bAf7VZEA3kHFql6YAO3kjQ6PftA4iVHX3JV
# v98ntjkbtqzKeJMaNWd8dBaAD3RCliMoajTDGbyYNKTvxBhWILyJ8WYdJ/NBDpqP
# zQl+pxm6ZZVSeBQAIOubZjU0vfpECxHC5vI1ErrqapG+0oBhhON+gllVklPAWZv2
# iv0mgjCTj7YNKX7yL2x2TvrvHVq5GPNa5fNbpy39t5cviiYqMf1RZVZccdr+2vAp
# k5ib5a4O8SiAgPSUwYGoOwbZG1onHij0ATPLkgKUfgaPzFfd5JZSbRl2Xg347/Lj
# WQLR+KjAyACFb06bqWzvHtQJTND8Y0j5Y2SBnSCqV2zNHSVts4+aUfkUhsKS+GAX
# S3j5XUgYA7SMNog76Nnss5l01nEX7sHDdYykYhzuQKFrT70XVTZeX25tSBfy3Vac
# zYd1JSI/9wOGqbFU52NyrlsA1qimxOhsuds7Pxo+jO3RjV/kC+AEOoVaXDdminsc
# 3PtlBCVh/sgYno9AUymblSRmee1gwlnlZJ0uiHKI9q2HFgZWM10yPG5gVt0prXnJ
# Fi1Wxmmg+BH/AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUFFvO8o1eNcSCIQZMvqGf
# dNL+pqowHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgw
# VjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWlj
# cm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUF
# BwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
# KS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQsFAAOCAgEAykuUgTc1KMszMgsHbhgjgEGv/dCHFf0by99C45SR770/udCN
# NeqlT610Ehz13xGFU6Hci+TLUPUnhvUnSuz7xkiWRru5RjZZmSonEVv8npa3z1Qv
# eUfngtyi0Jd6qlSykoEVJ6tDuR1Kw9xU9yvthZWhQs/ymyOwh+mxt0C9wbeLJ92e
# r2vc9ly12pFxbCNDJ+mQ7v520hAvreWqZ02GOJhw0R4c1iP39iNBzHOoz+DsO0sY
# jwhaz9HrvYMEzOD1MJdLPWfUFsZ//iTd3jzEykk02WjnZNzIe2ENfmQ/KblGXHeS
# e8JYqimTFxl5keMfLUELjAh0mhQ1vLCJZ20BwC4O57Eg7yO/YuBno+4RrV0CD2gp
# 4BO10KFW2SQ/MhvRWK7HbgS6Bzt70rkIeSUto7pRkHMqrnhubITcXddky6GtZsmw
# M3hvqXuStMeU1W5NN3HA8ypjPLd/bomfGx96Huw8OrftcQvk7thdNu4JhAyKUXUP
# 7dKMCJfrOdplg0j1tE0aiE+pDTSQVmPzGezCL42slyPJVXpu4xxE0hpACr2ua0LH
# v/LB6RV5C4CO4Ms/pfal//F3O+hJZe5ixevzKNkXXbxPOa1R+SIrW/rHZM6RIDLT
# JxTGFDM1hQDyafGu9S/a7umkvilgBHNxZfk0IYE7RRWJcG7oiY+FGdx1cs0wggdx
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
# Ooo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICzzCCAjgCAQEwgfyh
# gdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAn
# BgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjo4OTdBLUUzNTYtMTcwMTElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAW6h6/24WCo7W
# Zz6CEVAeLztcmD6ggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQUFAAIFAOaRa9gwIhgPMjAyMjA4MDEwMTAwMDhaGA8yMDIy
# MDgwMjAxMDAwOFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5pFr2AIBADAHAgEA
# AgIG1DAHAgEAAgIRNzAKAgUA5pK9WAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUA
# A4GBAAEU+pL+fVXcuqgydyRS2xu0KXbaAiTD3MltCnjkn3ekNvFgcP+4OrTJe4DA
# punTRCb4bvJrYifK/egPCUPI67+Obaj9M50cuVtH9NzEUFs8QheQObEU6tG04X/B
# v0cqzEG3yZKdp0O0h1k6MMtIrIccKN3JPMbdFmEHAeb7w1TAMYIEDTCCBAkCAQEw
# gZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGrCQnvq2PU6KkA
# AQAAAaswDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0B
# CRABBDAvBgkqhkiG9w0BCQQxIgQgPoTny9NAzylymghzArC1dOgPWrCW6yBPmaQ1
# 7YVD2mUwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAOHK/6sIVgEVSVD3Ar
# vk6OyQKvRxFHKyraUzbN1/AKVzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABqwkJ76tj1OipAAEAAAGrMCIEIHI+RQKHTZ2Id7/ufvKq
# /DQk+dqQy1YkmvsPNzOkpL0iMA0GCSqGSIb3DQEBCwUABIICAIj4UOKOnIJF6Fhs
# tgdNZLWqJCU4BPbpXHQ8jnt2jreDfzyyLsgIB8TffOCDcqSM9NzZ2orL+pQ4KB+e
# H9kEsDi2fdVmBwjmEcotCULgn3xxtGmS8cZLgVa4p9KWuaHxOuLJkmT6htWDbTq/
# fBP+Wc/rrFfFivojQJrZqBOACTwO+WhYvIYTU6W10Hyj3Kk2xKgb6KFMAxMmcjnj
# MAYtfMUqqjOHGgrh8Yjdl//iYFcuSdW/61G8CuYCn25WsYIc0S0R0XBL00N5asMD
# 4tVymVG0NtMYAzMgMZpDKbEOPQjez02rzM9Fcji/Ymbt7tqxgbgbyulwVoQrmQdp
# CrWUIPvwwr8UpOLZXqtY6fQjycfwQfy1gGTRj3bnnGItQ8xTrXcbzzBH3+WijWtC
# lPTDSgQOvVIuExbC3A9TCl5vm4tFadicoAUAaCG2EGRcR6d3NgPHtOmlHxOsLd+q
# yNXOZzW/6rG4Uta5Rdt5AxgUUfLVa4bki9KqjBJF4l/RWxXMDzJ2lzhCupRbJsU5
# Novofi5O+FEL8usvvZfStfgFrcFNEkOOSE5+BAnvL673hYnTO3YJdVxIA31/L+eY
# mr/R7zOBsZiRab8YT5FDw2YBAnTk12B9U3GWIeEnx9McvM4Juh+fk5dM5v8KA3rv
# GCePuPBXWTqExoZeUiuyWy1OxbPP
# SIG # End signature block
