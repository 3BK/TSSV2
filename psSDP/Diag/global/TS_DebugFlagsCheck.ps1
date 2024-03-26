#************************************************
# TS_DebugFlagsCheck.ps1
# Version 1.0.1
# Date: 02-27-2011
# Author: Andre Teixeira - andret@microsoft.com
# Description: - This script checks if any of the 'GFlags' are enabled on the system and fire an alert.
#                Version 1.0 only checks for PageHeap enabled against a process
#************************************************


Import-LocalizedData -BindingVariable ScriptVariables

Write-DiagProgress -Activity $ScriptVariables.ID_GFlags -Status $ScriptVariables.ID_GFlagsObtaining

$ImageFileExecutionRegKey = Get-Item ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")

$PageHeapEnabled = $false
$PageHeapProcesses = $ImageFileExecutionRegKey | Get-ChildItem -ErrorAction SilentlyContinue | Where-Object {$_.Property -eq "PageHeapFlags"}

if ($null -ne $PageHeapProcesses)
{
	foreach ($ProcesswithPageHeapEnabled in $PageHeapProcesses)
	{
		if ($ProcesswithPageHeapEnabled.GetValue("PageHeapFlags") -gt 0)
		{
			$ProcessName = Split-Path ($ProcesswithPageHeapEnabled.Name) -Leaf
			$InformationCollected = @{"Process Name" = $ProcessName; "PageHeap Flags" = $ProcesswithPageHeapEnabled.GetValue("PageHeapFlags")}
			$PageHeapEnabled = $true
			Write-GenericMessage -RootCauseId "RC_PageHeapEnabled" -ProcessName $ProcessName -PublicContentURL "http://blogs.technet.com/b/askperf/archive/2007/06/29/what-a-heap-of-part-two.aspx" -InformationCollected $InformationCollected -Verbosity "Error" -Visibility 4 -SupportTopicsID 8117 -MessageVersion 2 -Component "Windows Core" 
		}
	}
}
else
{
	Update-DiagRootCause -id "RC_PageHeapEnabled" -Detected $false
}

if ($PageHeapEnabled)
{
	Update-DiagRootCause -id "RC_PageHeapEnabled" -Detected $true
}


#Rule ID 603
#-----------
#http://sharepoint/sites/rules/_layouts/listform.aspx?PageType=4&ListId={9318793E-073A-415E-8FF5-C433133C2A9E}&ID=1759&ContentTypeID=0x01008FE8F6282AC12B4DB4505EA8C2BDB8F8
#
#Description
#-----------
# Typically, an engineer will review the verifier.txt in an MSDT report to determine if driver verification is enabled for certain test types.  I suggest creating an alert in 
# UDE whenever any driver is being verified.   Anything other then none, should be alerted to an engineer.   For example: Disabled Special pool: DisabledForce IRQL checking: 
# DisabledLow resources simulation: DisabledPool tracking: DisabledI/O verification: DisabledDeadlock detection: DisabledEnhanced I/O verification: DisabledDMA checking: DisabledDisk 
# integrity checking: Disabled Verified drivers: None   Enabled Special pool: EnabledPool tracking: DisabledForce IRQL checking: DisabledI/O verification: DisabledDeadlock detection: 
# DisabledDMA checking: DisabledSecurity checks: DisabledForce pending I/O requests: DisabledLow resources simulation: DisabledIRP Logging: DisabledMiscellaneous checks: Disabled Verified 
# drivers: ataport.sys  In the alert, we should alert of the driver and the test type current being used.   Other then querying the verifiy.txt, you can also query the registry:   
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management   To enable Driver Verifier by editing the registry, follow these steps: Start Registry Editor 
# (Regedt32). Locate the following registry key: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\VerifyDriversEdit the REG_SZ key.Set the REG_SZ key 
# to the case-insensitive names of the drivers that you want to test. You can specify multiple drivers, but only use one driver. By doing so, you can make sure that available system resources 
# are not prematurely exhausted. Premature exhaustion of resources does not cause any system reliability problems, but it can cause some driver checking to be bypassed.   The following list 
# shows examples of values for the REG_SZ key: Ntfs.sysWin32k.sys ftdisk.sys*.sys 
#
#Related KB 
#----------
# 244617 
#
#Script Author
#-------------
# anecho

Write-DiagProgress -Activity $ScriptVariables.ID_Verifier -Status $ScriptVariables.ID_VerifierObtaining

$RootCauseDetected = $false
$RootCauseName = "RC_DriverVerifierEnabled"
	
#********************
#Data gathering
#********************
	$InformationCollected = new-object PSObject
	
	$keyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
	
	
	###Table of verifier values
	$verifierTable = ("Miscellaneous checks" , $false),
					   ("IRP logging", $false),
					   ("Force pending I/O requets" , $false),
					   ("Security checks" , $false),
					   ("DMA verification" , $false),
					   ("Unused" , $false),
					   ("Deadlock detection" , $false),
					   ("I/O verification" , $false),
					   ("Pool tracking" , $false),
					   ("Low resources simulation", $false),
					   ("Force irql checking" , $false),
					   ("Special pool checking" , $false)
	
		
	Function Get-RegistryValue($Name)
	{
		#
		#	.SYNOPSIS
		#		Gets a specific value from the selected key
		#	.DESCRIPTION
		#		Uses Get-ItemProperty to pull the value out of the key path defined above
		#	.NOTES
		#	.LINK
		#	.EXAMPLE
		#	.OUTPUTS
		#		PSObject
		#	.PARAMETER file
		#
		if(Test-Path $keyPath)
		{
			return Get-ItemProperty -Path $keyPath -Name $Name -ErrorAction SilentlyContinue 
		}
		else
		{
			return $null
		}
	}
	
	Function Set-VerifierFlags($verifyDriverLevel)
	{
		#
		#	.SYNOPSIS
		#		Sets the Flags for the Veifier types
		#	.DESCRIPTION
		#		Converts the decimal version of the verifyDriverLevel one bit at a time
		#	.NOTES
		#	.LINK
		#	.EXAMPLE
		#	.OUTPUTS
		#	.PARAMETER file
		#
		
		
		[int]$i = 2048
		
		foreach($verifier in $verifierTable)
		{
			if(($verifyDriverLevel-$i) -ge 0)
			{
				$verifier[1] = $true
				$verifyDriverLevel =  $verifyDriverLevel - $i
			}
			if($i -gt 1)
			{
				$i /= 2
			}
		}
		
	}
	
	Function Get-VerifyDrivers
	{
		#
		#	.SYNOPSIS
		#		Gets the values for verify drivers
		#	.DESCRIPTION
		#		Uses the Get-RegistryValue function to pull the drivers by name and saves them to global variables
		#	.NOTES
		#	.LINK
		#	.EXAMPLE
		#	.OUTPUTS
		#		PSObject
		#	.PARAMETER file
		#
		
		$Driver = Get-RegistryValue -Name "VerifyDrivers"
		if($null -ne $Driver)
		{
			$verifyDriver = $Driver.VerifyDrivers
			$verifyDriver = $verifyDriver.Replace(" ", ", ")
		}
		else
		{
			$verifyDriver = $null
		}
		
		return $verifyDriver
	}
	
	Function Get-VerifyDriverLevel
	{
		#
		#	.SYNOPSIS
		#		Gets the values for verify Driver Level
		#	.DESCRIPTION
		#		Uses the Get-RegistryValue function to pull the drivers by name 
		#	.NOTES
		#	.LINK
		#	.EXAMPLE
		#	.OUTPUTS
		#		PSObject
		#	.PARAMETER file
		#
		
		$Driver  = Get-RegistryValue -Name "VerifyDriverLevel"
		if($null -ne $Driver)
		{
			$verifyDriverLevel = $Driver.VerifyDriverLevel	
			if($verifyDriverLevel -eq 0)
			{
				$verifyDriverLevel = $null
			}
		}
		else
		{
			$verifyDriverLevel = $null
		}
		
		return $verifyDriverLevel
	}
		
#********************
#Detection Logic
#********************
		
		$HasIssue = $false 
		$verifyDriver = Get-VerifyDrivers
		$verifyDriverLevel = Get-VerifyDriverLevel	
		
		if(($null -ne $verifyDriver) -and ($null -ne $verifyDriverLevel))
		{					
			Set-VerifierFlags -verifyDriverLevel $verifyDriverLevel			
			$HasIssue = $true
		}
	
	
#********************
#Alert Evaluation
#********************

	if($HasIssue)
	{
		add-member -inputobject $InformationCollected -membertype noteproperty -name "Drivers" -value $verifyDriver
		
		add-member -inputobject $InformationCollected -membertype noteproperty -name $verifierTable[0][0] -value $verifierTable[0][1]
		add-member -inputobject $InformationCollected -membertype noteproperty -name $verifierTable[1][0] -value $verifierTable[1][1]
		add-member -inputobject $InformationCollected -membertype noteproperty -name $verifierTable[2][0] -value $verifierTable[2][1]
		add-member -inputobject $InformationCollected -membertype noteproperty -name $verifierTable[3][0] -value $verifierTable[3][1]
		add-member -inputobject $InformationCollected -membertype noteproperty -name $verifierTable[4][0] -value $verifierTable[4][1]
		add-member -inputobject $InformationCollected -membertype noteproperty -name $verifierTable[5][0] -value $verifierTable[5][1]
		add-member -inputobject $InformationCollected -membertype noteproperty -name $verifierTable[6][0] -value $verifierTable[6][1]
		add-member -inputobject $InformationCollected -membertype noteproperty -name $verifierTable[7][0] -value $verifierTable[7][1]
		add-member -inputobject $InformationCollected -membertype noteproperty -name $verifierTable[8][0] -value $verifierTable[8][1]
		add-member -inputobject $InformationCollected -membertype noteproperty -name $verifierTable[9][0] -value $verifierTable[9][1]
		add-member -inputobject $InformationCollected -membertype noteproperty -name $verifierTable[10][0] -value $verifierTable[10][1]
		add-member -inputobject $InformationCollected -membertype noteproperty -name $verifierTable[11][0] -value $verifierTable[11][1]
		
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL "http://support.microsoft.com/kb/244617" -Verbosity "Warning" -InformationCollected $InformationCollected  -Visibility 4 -SupportTopicsID 8117 -MessageVersion 2 -Component "Windows Core" 
		
	}
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	} 


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBUAqSeMpJtMPGq
# VQfMtmQU6sT0d04cfZS4LGd6op/MS6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXgwghl0AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFHXFKZkgP6Id//Ffu81UXHv
# jBQsHLPHqWlk27DUSk+qMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAJW5tKOxUHTA0hU+LLJ++5CtCDDLfHwKl/8oeT6ybpDnC/xnhAyFAL
# ppRPgM6EfnC53/kgD8+T0FfbpMRJTbgyTU5OvCz+HVQtniC4k//iddoDbiSB2rEl
# kNc4BLfRzTpcACAA6XWmKiP1e9NxZ6bYgwxVPAvbY8PzxSWiZcRgACtLnge1bg3n
# W2YUDZ095KtmaRd54b1rQvxp8RsDrdsfWIeRlp0xGb3g1VV6qHZH5Sc0xVCnhZIq
# AoyLPUKsXoiATvCiN4V8hL0EYzC3Xk00HfFSQe+LKBb9bXlLLbtkLbkmG/1ZGtDI
# Inz9MSy1mg/V/8VYn/EYirT20vWFg87soYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIBk70Yfje+pmQzk0oeV6BvGs0/lsjnMQASI8W6JOZJQ9AgZi2BAX
# AVwYEzIwMjIwODAxMDgwMDUyLjY4NVowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkVBQ0Ut
# RTMxNi1DOTFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGawHWixCFtPoUAAQAAAZowDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTE3WhcNMjMwMjI4MTkwNTE3WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RUFDRS1FMzE2LUM5MUQxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDacgasKiu3ZGEU/mr6A5t9oXAgbsCJq0NnOu+54zZP
# t9Y/trEHSTlpE2n4jua4VnadE4sf2Ng8xfUxDQPO4Vb/3UHhhdHiCnLoUIsW3wtE
# 2OPzHFhAcUNzxuSpk667om4o/GcaPlwiIN4ZdDxSOz6ojSNT9azsKXwQFAcu4c9t
# svXiul99sifC3s2dEEJ0/BhyHiJAwscU4N2nm1UDf4uMAfC1B7SBQZL30ssPyiUj
# U7gIijr1IRlBAdBYmiyR0F7RJvzy+diwjm0Isj3f8bsVIq9gZkUWxxFkKZLfByle
# Eo4BMmRMZE9+AfTprQne6mcjtVAdBLRKXvXjLSXPR6h54pttsShKaV3IP6Dp6bXR
# f2Gb2CfdVSxty3HHAUyZXuFwguIV2OW3gF3kFQK3uL6QZvN8a6KB0hto06V98Ote
# y1OTOvn1mRnAvVu4Wj8f1dc+9cOPdPgtFz4cd37mRRPEkAdX2YaeTgpcNExa+jCb
# OSN++VtNScxwu4AjPoTfQjuQ+L1p8SMZfggT8khaXaWWZ9vLvO7PIwIZ4b2SK3/X
# mWpk0AmaTha5QG0fu5uvd4YZ/xLuI/kiwHWcTykviAZOlwkrnsoYZJJ03RsIAWv6
# UHnYjAI8G3UgCFFlAm0nguQ3rIX54pmujS83lgrm1YqbL2Lrlhmi98Mk2ktCHCXK
# RwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFF+2nlnwnNtR6aVZvQqVyK02K9FwMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAAATu4fMRtRH20+nNzGAXFxdXEpRPTfbM0LJDeNe4QCxj0FM+wrJdu6UKrM2
# wQuO31UDcQ4nrUJBe81N6W2RvEa8xNXjbO0qzNitwUfOVLeZp6HVGcNTtYEMAvK9
# k//0daBFxbp04BzMaIyaHRy7y/K/zZ9ckEw7jF9VsJqlrwqkx9HqI/IBsCpJdlTt
# KBl/+LRbD8tWvw6FDrSkv/IDiKcarPE0BU6//bFXvZ5/h7diE13dqv5DPU5Kn499
# HvUOAcHG31gr/TJPEftqqK40dfpB+1bBPSzAef58rJxRJXNJ661GbOZ5e64EuyIQ
# v0Vo5ZptaWZiftQ5pgmztaZCuNIIvxPHCyvIAjmSfRuX7Uyke0k29rSTruRsBVIs
# ifG39gldsbyjOvkDN7S3pJtTwJV0ToC4VWg00kpunk72PORup31ahW99fU3jxBh2
# fHjiefjZUa08d/nQQdLWCzadttpkZvCgH/dc8Mts2CwrcxCPZ5p9VuGcqyFhK2I6
# PS0POnMuf70R3lrl5Y87dO8f4Kv83bkhq5g+IrY5KvLcIEER5kt5uuorpWzJmBNG
# B+62OVNMz92YJFl/Lt+NvkGFTuGZy96TLMPdLcrNSpPGV5qHqnHlr/wUz9UAViTK
# JArvSbvk/siU7mi29oqRxb0ahB4oYVPNuv7ccHTBGqNNGol4MIIHcTCCBVmgAwIB
# AgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1
# WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
# 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZn
# hUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t
# 1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxq
# D89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmP
# frVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSW
# rAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
# 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zb
# r17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
# IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQc
# xWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17a
# j54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3h
# LB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
# 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74p
# y27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1A
# oL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbC
# HcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB
# 9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNt
# yo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
# rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcV
# v7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
# 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lw
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs4wggI3AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjpFQUNFLUUzMTYtQzkxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAAbquMnUCam/m7Ox1Uv/GNs1jmu+g
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRt4wwIhgPMjAyMjA4MDExMDIzMDhaGA8yMDIyMDgwMjEwMjMwOFow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pG3jAIBADAKAgEAAgIXMgIB/zAHAgEA
# AgIRmjAKAgUA5pMJDAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAJDWOTBH
# wWT7ODdvvwN83fTgmYJaXHNYartsyVF9rpHSxt/MeCzRG3eJuIv7NN6AGwYQ8iSI
# VKoLlWgJQBfdXcpJH9npPTaOFGGOp0CneOrMEDrZALoYvSJOgOCNPuZXjWrPDM0I
# 9TUzezb8sCF5uOFDpiZ7xObT3zfRoTb0Xg+1MYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGawHWixCFtPoUAAQAAAZowDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgLhAWxMzsm4tqzAwHo+ErjDMeYqSMtcTObF0gCfYcjuswgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCABTkDjOBEUfZnligJiL539Lx+nsr/N
# FVTnKFX030iNYDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABmsB1osQhbT6FAAEAAAGaMCIEILUtm4TpisXoG7kTsxOI51IMkFhuOyD6
# Xm+yAr8gIh09MA0GCSqGSIb3DQEBCwUABIICANKUxSxCtnauC4CC9mmErB7BEBUe
# 5AjHTRIEe2358PzHIJ1DnO3cJZ40ufIANDhRM0caxpp4RjinKwelBunlya/5hY9n
# tKqUg3DT+JDIs1Rv0TvSohI6V9F+F5F7cBzteR6YhbpCfsbO/Hs8FJZ3odl4v19q
# R8oDUqDomgl1C+HNUwHoW/bLlRzPCuT4RrxJ2u4PnWQHCWo12V+YMvQ5SwmTINHO
# kpNqL5nlEs4VvKHcSqgz9jmpOh48CxNcDeGufNlPmO6YBMxwItFceT8JdydzLDao
# rSnZEvLCOyNm3Dg0/LyHd7m22cjNHgxsWpPrUnh7SPap1FURIRmywUvmpY7McJyW
# 4TjC1VyoA9XRN3aVKeLdxXwdBULq6zR3pPPglZ0c+0BFI5fHGcG27XDO05eJDt6n
# uD8zlgCy/4yhNTcDVcwiYnv3ZPGpX3Yf9OGZ2IgpbIgRLolJn7ZBNnoi1Whkk0Da
# SEaTKuJDCL04P5W7PQPPTdHK1ugREMPW6IT557Si4qKA/eJwPRF+U+I2zCXOINAI
# tSBqKLA39hzdrIefvwGmVVzp2e/m/rP2JlW7y/RRMBTNzKtsKydIOM08Z6IBE9Lq
# Y9gGBKvHevNWt62nz6TKjiv0Np3PrFGUmF9Z2FFedcuMpa2usk7SEclSubk0vzYl
# zVqfPF2X2T2ywwnN
# SIG # End signature block
