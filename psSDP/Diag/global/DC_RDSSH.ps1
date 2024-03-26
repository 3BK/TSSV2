#************************************************
# DC_RDSSH.ps1
# Version 1.0.1
# Date: 21-01-2012
# Author: Daniel Grund - dgrund@microsoft.com
# Description: 
#	This script gets the RDSSH config and
#   checks vital signs to inform user.
# 1.0.0 Beta release
#************************************************
PARAM(
	$TargetHost,
   	$RDSobject,
	$OutputFileName ,
	$OS,
	$bIsRDSSH
)
# globals and function definitions for RDS
$OutputFolder = $PWD.Path 
Import-LocalizedData -BindingVariable RDSSDPStrings

# get all the RDP-Tcp settings
$Query = "Select * from Win32_TSGeneralSetting where TerminalName='RDP-Tcp'" 
[array]$RDPSettings = Get-CimInstance -Query $Query -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate
$Query = "Select * from Win32_TSLogonSetting where TerminalName='RDP-Tcp'" 
$RDPSettings += Get-CimInstance -Query $Query -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate
$Query = "Select * from Win32_TSSessionSetting where TerminalName='RDP-Tcp'" 
$RDPSettings += Get-CimInstance -Query $Query -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate
$Query = "Select * from Win32_TSEnvironmentSetting where TerminalName='RDP-Tcp'" 
$RDPSettings += Get-CimInstance -Query $Query -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate
$Query = "Select * from Win32_TSRemoteControlSetting where TerminalName='RDP-Tcp'" 
$RDPSettings += Get-CimInstance -Query $Query -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate
$Query = "Select * from Win32_TSClientSetting where TerminalName='RDP-Tcp'" 
$RDPSettings += Get-CimInstance -Query $Query -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate
$RDPSettings = FilterWMIObject $RDPSettings 

$OutputFileName = SaveAsXml $RDPSettings  ($TargetHost + "_RDPSettings.xml") $OutputFileName

# See if RDS is enabled otherwise exit
$RDSEnabled = Get-RemoteRegistryKeyProperty -ComputerName $TargetHost -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Property fDenyTSConnections
$RDSEnabledPol = Get-RemoteRegistryKeyProperty -ComputerName $TargetHost -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Property fDenyTSConnections
UpdateAndMessage -Id "RC_RDSENABLED" -Detected (($RDSEnabled.fDenyTSConnections-eq 1) -or ($RDSEnabledPol.fDenyTSConnections -eq 1) )
$OOBEInProgress = Get-RemoteRegistryKeyProperty -ComputerName $TargetHost -Path "HKLM:\SYSTEM\Setup" -Property OOBEInProgress
UpdateAndMessage -Id "RC_RDSOOBE" -Detected ($OOBEInProgress.OOBEInProgress -eq 1)

if ( ($RDSEnabled.fDenyTSConnections-eq 1) -or ($RDSEnabledPol.fDenyTSConnections -eq 1) -or ($OOBEInProgress.OOBEInProgress -eq 1) )
{
	# RDS disabled, no sense to continue
	return
}




# RULE  524 : see what port is configured
Write-DiagProgress -Activity $RDSSDPStrings.ID_RDSServerProgress -Status $RDSSDPStrings.ID_RDSGetPort
$RDPPort = Get-RemoteRegistryKeyProperty -ComputerName $TargetHost -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Property PortNumber
UpdateAndMessage -Id "RC_RDSPort" -Detected ($null -eq $RDPPort)


#  test if there is something listening on that port
Write-DiagProgress -Activity $RDSSDPStrings.ID_RDSServerProgress -Status $RDSSDPStrings.ID_RDSListenPort
UpdateAndMessage -Id "RC_RDSListenPortDefault" -Detected  (($null -ne $RDPPort) -and ($RDPPort.PortNumber -ne "3389"))

if (($null -ne $RDPPort) -and ([RDSHelper]::RDPTestPort($TargetHost,$RDPPort.PortNumber) -eq $false))
{ 
	Update-DiagRootCause -Id "RC_RDSListenPort" -Detected $true -Parameter @{"Error" = $RDSSDPStrings.ID_RDSListenPortError + " " + $RDPPort.PortNumber; "Solution" = ""}
	Add-GenericMessage -Id "RC_RDSListenPort"
}else{
	Update-DiagRootCause -Id "RC_RDSListenPort" -Detected $false -Parameter @{"Error" = $RDSSDPStrings.ID_RDSListenPortError + " " + $RDPPort.PortNumber; "Solution" = ""}
}
# END RULE 524

# See if server default listener is up
Write-DiagProgress -Activity $RDSSDPStrings.ID_RDSServerProgress -Status $RDSSDPStrings.ID_RDSQWinSta
$DefaultListener = (qwinsta "/Server:$($TargetHost)")
if ($null -ne $DefaultListener)
{
    $savepath = $OutputFolder + "\"+ $TargetHost+"_QWinSta.txt"
	[array]$OutputFileName += $savepath
    $DefaultListener | Out-File $savepath
	$IsListening =(!$DefaultListener[$DefaultListener.Length-1].ToString().Contains("65536")) -and (!$DefaultListener[$DefaultListener.Length-1].ToString().Contains("rdp-tcp"))
	UpdateAndMessage -Id "RC_RDSIsListening" -Detected $IsListening

}
$CertNotValid  = $false

#open TCP connection on target port and get cert
Write-DiagProgress -Activity $RDSSDPStrings.ID_RDSServerProgress -Status $RDSSDPStrings.ID_RDSRDPCert
$certfile = $OutputFolder + "\"+ $TargetHost + "_RDPCert.cer"
$RemoteCertificate = [RDSHelper]::RDPGetCert($TargetHost, $RDPPort.PortNumber, $certfile)
if ($null -eq $RemoteCertificate)
{
	UpdateAndMessage -Id "RC_RDSCert" -Detected $true
}else{
	UpdateAndMessage -Id "RC_RDSCert" -Detected $false
	[array]$OutputFileName += $certfile
	UpdateAndMessage -Id "RC_RDSCertMatch" -Detected ($RDPSettings[0].SSLCertificateSHA1Hash -ne $RemoteCertificate.GetCertHashString())

}

#$ipadress = [RDSHelper]::DNSLookup($node)

# check to see if hardware acceleration is set for rdpdd
UpdateAndMessage -Id "RC_RDSH_RDPDD" -Detected (IsRDPDDAccelerated)

# check for reg permisions on the LICENSE keys
UpdateAndMessage -Id "RC_RDSH_DEVLIC" -Detected (IsRegPermIssue)

if ($bIsRDSSH -eq $true)
{
	# try to verify the license type with the available licenses on the LServer
	$RDSobject = Get-CimInstance -Class Win32_TerminalServiceSetting -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate
	Write-DiagProgress -Activity $RDSSDPStrings.ID_RDSServerProgress -Status $RDSSDPStrings.ID_RDSLicenseServer
	[array]$LicenseServerReport = "Specified RDS License Servers:"
	[array]$SpecifiedLicenseServer = $RDSObject.GetSpecifiedLicenseServerList().SpecifiedLSList
	$LicenseServerReport+= $SpecifiedLicenseServer
	
	#$LicenseServerReport+= ""
	#$LicenseServerReport+= "Discovered RDS License servers:"
	#$LicenseServerReport+=$LicenseServer.Length,$RDSObject.GetRegisteredLicenseServerList().RegisteredLSList.Split(" ")

	if ($null -ne $SpecifiedLicenseServer )
	{
		# RULE 525 get RDS RCM 509 certificate only if we got a specified license server
		UpdateAndMessage -Id "RC_RDSLicenseServer" -Detected $false
		Write-DiagProgress -Activity $RDSSDPStrings.ID_RDSServerProgress -Status $RDSSDPStrings.ID_RDSx509Cert
		#[System.Security.Cryptography.X509Certificates.X509CertificateCollection]
		$ByteArray = Get-RemoteRegistryKeyProperty -ComputerName $TargetHost -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM" -Property "X509 Certificate"
		$RDSCertificates = $ByteArray.'X509 Certificate'
		#$ByteArray = Get-RemoteRegistryKeyProperty -ComputerName $TargetHost -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM" -Property "X509 Certificate2"
		#$RDSCertificates2 = [RDSHelper]::GetCertCollFromReg($ByteArray."X509 Certificate2")
		
		UpdateAndMessage -Id "RC_RDSx509Cert" -Detected ($null -eq $RDSCertificates) # -or ($RDSCertificates2 -eq $null))

		#END RULE 525

	   $LicenseServerReport+= ""
	   $LicenseServerReport +="Connectivity to Specified License Servers:"
	   $CanConnectToLicenseServer = $false
	   $SpecifiedLicenseServer|foreach-object{
		   Write-DiagProgress -Activity $RDSSDPStrings.ID_RDSServerProgress -Status ($RDSSDPStrings.ID_RDSLicenseServerConnect + " " + $_)
		   $TStoLSConnectivityStatus = $RDSObject.GetTStoLSConnectivityStatus($_).TStoLSConnectivityStatus
		   $string = GetLSConnectDesc $TStoLSConnectivityStatus
		   $LicenseServerReport+= "License Server " + $_ + " status: "+ $string
		   #note dgrund, not enough need more failure status check http://msdn.microsoft.com/en-us/library/windows/desktop/ff955669(v=vs.85).aspx unsure why we need -and here
		   if (($TStoLSConnectivityStatus -ne  1) -and ($TStoLSConnectivityStatus -ne 2) -and ($TStoLSConnectivityStatus -ne 11))
		   {
				UpdateAndMessage -Id "RC_RDSLicenseServerConnect" -RootCause $RDSSDPStrings.ID_RDSLicenseServerConnectError  -Solution ($RDSSDPStrings.ID_RDSLicenseServerConnectSolution + " " + $_) -Detected $true 
		   }else{
		   		$CanConnectToLicenseServer = $true
				Update-DiagRootCause -Id "RC_RDSLicenseServerConnect" -Detected $false 
			}
	   } #end foreach-object


	}else{ #$SpecifiedLicenseServer
		UpdateAndMessage -Id "RC_RDSLicenseServer" -Detected $true
	}

	# get the licenses from the server where the licensetype is the RDS requested licensetype
	$LicenseServerReport+= "The server is configured for: " + (TSLicensingType -Type $RDSobject.LicensingType)
	if ($RDSobject.LicensingType -eq 2) #per device
	{

		$LicenseType= 0
	}else # assume per user
	{

		$LicenseType = 1
	}
	
	# Ask to connect to the remote license server
	if ($null -ne $SpecifiedLicenseServer)
	{
		$Connect = Get-DiagInput -id "QuestionYesNo" -Parameter @{"Question" = $RDSSDPStrings.ID_RDSLSConnectInteract; "QuestionDescription" = $RDSSDPStrings.ID_RDSLSConnectInteractDescription}
		if ($Connect -eq "Yes") 
		{
			foreach ($LicenseServer in $SpecifiedLicenseServer)
			{
				$RDSLServerLicenses = FilterWMIObject (Get-CimInstance -Class Win32_TSLicenseKeyPack  -Namespace root\cimv2 -ComputerName $LicenseServer -Authentication PacketPrivacy -Impersonation Impersonate)
	        
				if ($null -ne $RDSLServerLicenses)
				{
					$OutputFileName = SaveAsXml $RDSLServerLicenses  ($LicenseServer + "_RDS_Licenses.xml") $OutputFileName
					$relevantLicenses += $RDSLServerLicenses| where-object {
									($_.TotalLicenses -gt 0) -and ($_.TotalLicenses -lt 4294967295) -and ($_.ProductType -eq $LicenseType) -and
									($_.ProductVersionID -ge [System.Convert]::ToInt32($OS.Version[2].ToString())) } 
					$relevantLicenses| foreach-object {
							$availablelicenses += $_.AvailableLicenses
					}
				}
			} # end foreach ($LicenseServer in $SpecifiedLicenseServer)
			if ($null -ne $relevantLicenses)
			{
				UpdateAndMessage -Id "RC_RDSLSValidLicense" -Detected $false
				$LicenseServerReport+= ""
				$LicenseServerReport+= "Checking for valid licenses in specified license servers:"
				$LicensingName = $RDSObject.LicensingName
				$ProductVersion = $relevantLicenses[0].ProductVersion
				$LicenseServerReport += "Found valid $LicensingName licenses with $availablelicenses available licenses."
			}else{
				UpdateAndMessage -Id "RC_RDSLSValidLicense" -Detected $true
			}

		}
	}
	$savepath = $TargetHost + "_LicenseServerReport.txt"
	$LicenseServerReport | Out-File $savepath
	[array]$OutputFileName += $savepath

# RemotePublishing section
	$remoteAppList = $null
	if( ( (([int]$OS.Version[0] -48) -eq 6 ) -and (([int]$OS.Version[2]- 48) -lt 2) ) -or (([int]$OS.Version[0] -48) -lt 6 )  )
	{
	$remoteAppList =  FilterWMIObject (Get-CimInstance -Class Win32_TSPublishedApplication -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate)
	$OutputFileName = SaveRDPFileContents -Object $remoteAppList -ObjectName "PublishedApplication" -OutputFileName $OutputFileName
	}
	else
	{
	$remoteAppList =  FilterWMIObject (Get-CimInstance -Class Win32_RDCentralPublishedRemoteApplication -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate)
	$OutputFileName = SaveRDPFileContents -Object $remoteAppList -ObjectName "PublishedRemoteApplication" -OutputFileName $OutputFileName
	$PublishedRemoteDesktop = FilterWMIObject (Get-CimInstance -Class Win32_RDCentralPublishedRemoteDesktop -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate)
	$OutputFileName = SaveRDPFileContents -Object $remoteAppList -ObjectName "PublishedRemoteDesktop" -OutputFileName $OutputFileName
	$workspace = FilterWMIObject (Get-CimInstance -Class Win32_Workspace -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate)
	$OutputFileName = SaveAsXml $workspace  ($TargetHost +"_Workspace.xml") $OutputFileName
	$PublishedFarm = FilterWMIObject (Get-CimInstance -Class Win32_RDCentralPublishedFarm -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate)
	$OutputFileName = SaveAsXml $PublishedFarm  ($TargetHost +"_PublishedFarm.xml") $OutputFileName
	$PublishedDeploymentSettings = FilterWMIObject (Get-CimInstance -Class Win32_RDCentralPublishedDeploymentSettings -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate)
	$OutputFileName = SaveAsXml $PublishedDeploymentSettings  ($TargetHost +"_PublishedDeploymentSettings.xml") $OutputFileName
	$PublishedFileAssociation  = FilterWMIObject (Get-CimInstance -Class Win32_RDCentralPublishedFileAssociation -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate)
	$OutputFileName = SaveAsXml $PublishedFileAssociation  ($TargetHost +"_PublishedFileAssociation.xml") $OutputFileName
	$PersonalDesktopAssignment = FilterWMIObject (Get-CimInstance -Class Win32_RDPersonalDesktopAssignment -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate)
	$OutputFileName = SaveAsXml $PersonalDesktopAssignment  ($TargetHost +"_PersonalDesktopAssignment.xml") $OutputFileName
	}

# end RemotePublishing
}


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCClCimcPvOYFodS
# /bw7OSKXxjqefUy47JzSKHY2uN5TR6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDz0H9k0EfC0/dYTVLu1zUCd
# ZQlESyBr3QKbeYYBK2OKMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCt3h8yozpybizul1EUDmf0tSSBXBbNEwUZZjBoTXMG38Nsg777vO4u
# iLjPoPeCQpry0FPKrSil051EO//OU9QI2YlI6RGB2omAmeJwxFUvtX3FuNV/Rm99
# 2yb2Vj+dIOVdlES+7RdYGUsSvaV2VSCm6tU5dxnC6vWz7gjS6EXDk1JxKxd2WIC4
# R9vKMOAIhxg12+ZtFGCuf5Y20E2ye8vuG2YU28fk5mVt5GjmQmQHotbC6iK52/a9
# aG7SIW9ByDmfxi2d6qSButfGrifgIJBqAwM+oQcF2mcR+QPmjeZ/46P+WKQ81YzE
# ogNRNGHsE2od/1DaTY3zFKzsiLD9ezBBoYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIOel2ODU531G0fINVSG5SBkcyZjafZA6SHE9BYbEnIJOAgZi3ohP
# 7PsYEzIwMjIwODAxMDc1MDMyLjQwN1owBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RDA4Mi00QkZELUVFQkExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAY/zUajrWnLdzAABAAABjzAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDZaFw0yMzAxMjYxOTI3NDZaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQwODIt
# NEJGRC1FRUJBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmVc+/rXPFx6Fk4+CpLru
# bDrLTa3QuAHRVXuy+zsxXwkogkT0a+XWuBabwHyqj8RRiZQQvdvbOq5NRExOeHia
# CtkUsQ02ESAe9Cz+loBNtsfCq846u3otWHCJlqkvDrSr7mMBqwcRY7cfhAGfLvlp
# MSojoAnk7Rej+jcJnYxIeN34F3h9JwANY360oGYCIS7pLOosWV+bxug9uiTZYE/X
# clyYNF6XdzZ/zD/4U5pxT4MZQmzBGvDs+8cDdA/stZfj/ry+i0XUYNFPhuqc+UKk
# wm/XNHB+CDsGQl+ZS0GcbUUun4VPThHJm6mRAwL5y8zptWEIocbTeRSTmZnUa2iY
# H2EOBV7eCjx0Sdb6kLc1xdFRckDeQGR4J1yFyybuZsUP8x0dOsEEoLQuOhuKlDLQ
# Eg7D6ZxmZJnS8B03ewk/SpVLqsb66U2qyF4BwDt1uZkjEZ7finIoUgSz4B7fWLYI
# eO2OCYxIE0XvwsVop9PvTXTZtGPzzmHU753GarKyuM6oa/qaTzYvrAfUb7KYhvVQ
# KxGUPkL9+eKiM7G0qenJCFrXzZPwRWoccAR33PhNEuuzzKZFJ4DeaTCLg/8uK0Q4
# QjFRef5n4H+2KQIEibZ7zIeBX3jgsrICbzzSm0QX3SRVmZH//Aqp8YxkwcoI1WCB
# izv84z9eqwRBdQ4HYcNbQMMCAwEAAaOCATYwggEyMB0GA1UdDgQWBBTzBuZ0a65J
# zuKhzoWb25f7NyNxvDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQDNf9Oo9zyhC5n1jC8iU7NJY39FizjhxZwJbJY/
# Ytwn63plMlTSaBperan566fuRojGJSv3EwZs+RruOU2T/ZRDx4VHesLHtclE8GmM
# M1qTMaZPL8I2FrRmf5Oop4GqcxNdNECBClVZmn0KzFdPMqRa5/0R6CmgqJh0muvI
# mikgHubvohsavPEyyHQa94HD4/LNKd/YIaCKKPz9SA5fAa4phQ4Evz2auY9SUluI
# d5MK9H5cjWVwBxCvYAD+1CW9z7GshJlNjqBvWtKO6J0Aemfg6z28g7qc7G/tCtrl
# H4/y27y+stuwWXNvwdsSd1lvB4M63AuMl9Yp6au/XFknGzJPF6n/uWR6JhQvzh40
# ILgeThLmYhf8z+aDb4r2OBLG1P2B6aCTW2YQkt7TpUnzI0cKGr213CbKtGk/OOIH
# SsDOxasmeGJ+FiUJCiV15wh3aZT/VT/PkL9E4hDBAwGt49G88gSCO0x9jfdDZWdW
# GbELXlSmA3EP4eTYq7RrolY04G8fGtF0pzuZu43A29zaI9lIr5ulKRz8EoQHU6cu
# 0PxUw0B9H8cAkvQxaMumRZ/4fCbqNb4TcPkPcWOI24QYlvpbtT9p31flYElmc5wj
# GplAky/nkJcT0HZENXenxWtPvt4gcoqppeJPA3S/1D57KL3667epIr0yV290E2ot
# ZbAW8DCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
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
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDA4Mi00QkZELUVFQkExJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAD5NL4IEdudIBwdGoCaV0WBbQZpqoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmkZg6MCIYDzIwMjIwODAx
# MDgwOTMwWhgPMjAyMjA4MDIwODA5MzBaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaRmDoCAQAwBwIBAAICEbAwBwIBAAICEXEwCgIFAOaS6boCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQAhp8Aod4IrqWSzJRIvhdfsjjJ0NJWgA/ZOXoGxuTHB
# Nc+n4eD9raE8WV172xcQru+BQW4ecbLSElX8gQ88qDD0qPr3S/FY/5drB43kpsZb
# 3smIRpvR0AhUrfQV/szgrx7+5TBOZSinvdOPsft4KHAzsWahf7BfumsXJdtpt6+W
# nzGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABj/NRqOtact3MAAEAAAGPMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIPfgsj28ep7rDxP6AM1+
# qyYTmJe5HyAdp7WZvdySi9+sMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# l3IFT+LGxguVjiKm22ItmO6dFDWW8nShu6O6g8yFxx8wgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY/zUajrWnLdzAABAAABjzAiBCDK
# yRgnJWWXshnmgygiJTZnJFpENKNV36rl3eKKIz0TKjANBgkqhkiG9w0BAQsFAASC
# AgCE78hhBovmh1NRwOvArXEQfV14Oew6hB9hTP86FHrbXuypLcBPdXm59F0Z9JWP
# THLVa5KrR6UZM7MXWOIcssyRFx8uDCO4wj4Wfv6b4oxELERyT/CJF3W+IJZeJseG
# +UkayWWmHaxjVVazTTvhS4yOTehe++1av88Lxylioel5ARjCSkJnHfqcwGftwDH1
# 5+gHCjsNWgtuEfRVfqwDkyPlr1Bm6H0EkfhM8GGcmnkt2uTq1oR9iW/Bj65xx06y
# V1+YNfjuAhWiVgGO1MfK/UTzLoL6F1UorP0NzIMW9FocGO3H0FWX+TuLnjNhb3bl
# mVgnbaN0nYWmr5/SzDLvfGBJzFIMDW43CJ+SRA8N09RT4RAgUESMTVThi5VXxvyY
# bta0DaTP6EfEDd6N+Ybk7YnwxeLX21GOBeaDuye8NmRynohKedoZl78lt5shKsQA
# Sg8lQ8wgkUxO6nhSh+HQplw3nZwHjlEHLYY0dtBwsNmIvr3j0a2sxhYbrsBFD0GA
# a4zkQeffhwzkeNa1ivOwL7WAf0GhZP/QsiwPGBgZFjDqgR7yd9miwH7A5gAVsESR
# NuuvV67cOvO1QTWnXC5MPqLFC3pEutb5lzpOtLH9thERe20Kmhz9l9S3+xeVR6vH
# /sYPYM+wMBq2ydQ/fZHMsxFC7HGwtcuUUs7TxqoWvALhJQ==
# SIG # End signature block
