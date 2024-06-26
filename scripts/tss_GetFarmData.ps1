# Script: tss_GetFarmData.ps1
# from https://microsoft.sharepoint.com/teams/css-rds/SitePages/getfarmdata.aspx?xsdata=MDN8MDF8fDRhNGUxOTM4NmE3ZTQ0ODliNWJlMWQ2MDdmYjgwMjU2fDcyZjk4OGJmODZmMTQxYWY5MWFiMmQ3Y2QwMTFkYjQ3fDF8MHw2Mzc3NzU4NTEyODY0MjIxMDZ8R29vZHxWR1ZoYlhOVFpXTjFjbWwwZVZObGNuWnBZMlY4ZXlKV0lqb2lNQzR3TGpBd01EQWlMQ0pRSWpvaVYybHVNeklpTENKQlRpSTZJazkwYUdWeUlpd2lWMVFpT2pFeGZRPT0%3D&sdata=ZzVWUFZRZXQvWUMwa3VWbzZpeStmNHhRN2VDMTlVd1NjdkthNUNIWkYyUT0%3D&ovuser=72f988bf-86f1-41af-91ab-2d7cd011db47%2Cwaltere%40microsoft.com&OR=Teams-HL&CT=1642008472926
# addon to tss RDSsrv

#region ::::: Script Input PARAMETERS :::::
[CmdletBinding()]param(
 [Parameter(Mandatory=$False, Position=0)] [String] $DataPath
)
$ScriptVer="1.00"	#Date: 2022-01-12


Import-Module remotedesktop


#Get Servers of the farm:
$servers = Get-RDServer

$BrokerServers = @()
$WebAccessServers = @()
$RDSHostServers = @()
$GatewayServers = @()

foreach ($server in $servers)
{
	switch ($server.Roles)
	{
	"RDS-CONNECTION-BROKER" {$BrokerServers += $server.Server}
	"RDS-WEB-ACCESS" {$WebAccessServers += $server.Server}
	"RDS-RD-SERVER" {$RDSHostServers += $server.Server}
	"RDS-GATEWAY" {$GatewayServers += $server.Server}
	}
}
"Machines involved in the deployment : " + $servers.Count
"	-Broker(s) : " + $BrokerServers.Count
foreach ($BrokerServer in $BrokerServers)
		{
		"		" +	$BrokerServer
$ServicesStatus = Get-WmiObject -ComputerName $BrokerServer -Query "Select * from Win32_Service where Name='rdms' or Name='tssdis' or Name='tscpubrpc'"
        foreach ($stat in $ServicesStatus)
        {
        "		      - " + $stat.Name + " service is " + $stat.State
        }

		}
" "	
"	-RDS Host(s) : " + $RDSHostServers.Count
foreach ($RDSHostServer in $RDSHostServers)
		{
		"		" +	$RDSHostServer
$ServicesStatus = Get-WmiObject -ComputerName $RDSHostServer -Query "Select * from Win32_Service where Name='TermService'"
        foreach ($stat in $ServicesStatus)
        {
        "		      - " + $stat.Name +  "service is " + $stat.State
        }
		}
" " 
"	-Web Access Server(s) : " + $WebAccessServers.Count
foreach ($WebAccessServer in $WebAccessServers)
		{
		"		" +	$WebAccessServer
		}
" " 	
"	-Gateway server(s) : " + $GatewayServers.Count
foreach ($GatewayServer in $GatewayServers)
		{
		"		" +	$GatewayServer

$ServicesStatus = Get-WmiObject -ComputerName $GatewayServer -Query "Select * from Win32_Service where Name='TSGateway'"
        foreach ($stat in $ServicesStatus)
        {
        "		      - " + $stat.Name + " service is " + $stat.State
        }
		}
" "

#Get active broker server.
$ActiveBroker = Invoke-WmiMethod -Path ROOT\cimv2\rdms:Win32_RDMSEnvironment -Name GetActiveServer
$ConnectionBroker = $ActiveBroker.ServerName
"ActiveManagementServer (broker) : " +	$ActiveBroker.ServerName
" "

# Deployment Properties  TODO ##############
##########
"Deployment details : "
# Is Broker configured in High Availability?
$HighAvailabilityBroker = Get-RDConnectionBrokerHighAvailability
$BoolHighAvail = $false
If ($null -eq $HighAvailabilityBroker)
{
	$BoolHighAvail = $false
	"	Is Connection Broker configured for High Availability : " + $BoolHighAvail
}
else
{
	$BoolHighAvail = $true
	"	Is Connection Broker configured for High Availability : " + $BoolHighAvail
	"		- Client Access Name (Round Robin DNS) : " + $HighAvailabilityBroker.ClientAccessName
	"		- DatabaseConnectionString : " + $HighAvailabilityBroker.DatabaseConnectionString
    "		- DatabaseSecondaryConnectionString : " + $HighAvailabilityBroker.DatabaseSecondaryConnectionString
	"		- DatabaseFilePath : " + $HighAvailabilityBroker.DatabaseFilePath
}

#Gateway Configuration
$GatewayConfig = Get-RDDeploymentGatewayConfiguration -ConnectionBroker $ConnectionBroker
"	Gateway Mode : " + $GatewayConfig.GatewayMode
if ($GatewayConfig.GatewayMode -eq "custom")
{
"		- LogonMethod : " + $GatewayConfig.LogonMethod   
"		- GatewayExternalFQDN : " + $GatewayConfig.GatewayExternalFQDN
"		- GatewayBypassLocal : " + $GatewayConfig.BypassLocal
"		- GatewayUseCachedCredentials : " + $GatewayConfig.UseCachedCredentials

}

# RD Licencing
$LicencingConfig = Get-RDLicenseConfiguration -ConnectionBroker $ConnectionBroker
"	Licencing Mode : " + $LicencingConfig.Mode
if ($LicencingConfig.Mode -ne "NotConfigured")
{
"		- Licencing Server(s) : " + $LicencingConfig.LicenseServer.Count
foreach ($licserver in $LicencingConfig.LicenseServer)
{
"		       - Licencing Server : " + $licserver
}

}
# RD Web Access
"	Web Access Server(s) : " + $WebAccessServers.Count
foreach ($WebAccessServer in $WebAccessServers)
{
"	     - Name : " + $WebAccessServer
"	     - Url : " + "https://" + $WebAccessServer + "/rdweb"
}

# Certificates
#Get-ChildItem -Path cert:\LocalMachine\my -Recurse | Format-Table -Property DnsNameList, EnhancedKeyUsageList, NotAfter, SendAsTrustedIssuer
"	Certificates "
$certificates = Get-RDCertificate -ConnectionBroker $ConnectionBroker
foreach ($certificate in $certificates)
{
"		- Role : " + $certificate.Role
"			- Level : " + $certificate.Level
"			- Expires on : " + $certificate.ExpiresOn
"			- Issued To : " + $certificate.IssuedTo
"			- Issued By : " + $certificate.IssuedBy
"			- Thumbprint : " + $certificate.Thumbprint
"			- Subject : " + $certificate.Subject
"			- Subject Alternate Name : " + $certificate.SubjectAlternateName

}
" "

#RDS Collections
$collectionnames = Get-RDSessionCollection 
$client = $null
$connection = $null
$loadbalancing = $null 
$Security = $null
$UserGroup = $null
$UserProfileDisks = $null

"RDS Collections : "
foreach ($Collection in $collectionnames)
{
	$CollectionName = $Collection.CollectionName
	"	Collection : " +  $CollectionName	
	"		Resource Type : " + $Collection.ResourceType
	if ($Collection.ResourceType -eq "RemoteApp programs")
	{
		"			Remote Apps : "
		$remoteapps = Get-RDRemoteApp -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName
		foreach ($remoteapp in $remoteapps)
		{
			"			- DisplayName : " + $remoteapp.DisplayName
			"				- Alias : " + $remoteapp.Alias
			"				- FilePath : " + $remoteapp.FilePath
			"				- Show In WebAccess : " + $remoteapp.ShowInWebAccess
			"				- CommandLineSetting : " + $remoteapp.CommandLineSetting
			"				- RequiredCommandLine : " + $remoteapp.RequiredCommandLine
			"				- UserGroups : " + $remoteapp.UserGroups
		}		
	}

#       $rdshServers		
		$rdshservers = Get-RDSessionHost -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName
		"		Servers in that collection : "
		foreach ($rdshServer in $rdshservers)
		{		
			"			- SessionHost : " + $rdshServer.SessionHost			
			"				- NewConnectionAllowed : " + $rdshServer.NewConnectionAllowed			
		}		
		
		$client = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -Client 
		"		Client Settings : " 
		"			- MaxRedirectedMonitors : " + $client.MaxRedirectedMonitors
		"			- RDEasyPrintDriverEnabled : " + $client.RDEasyPrintDriverEnabled
		"			- ClientPrinterRedirected : " + $client.ClientPrinterRedirected
		"			- ClientPrinterAsDefault : " + $client.ClientPrinterAsDefault
		"			- ClientDeviceRedirectionOptions : " + $client.ClientDeviceRedirectionOptions
		" "
		
		$connection = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -Connection
		"		Connection Settings : " 
		"			- DisconnectedSessionLimitMin : " + $connection.DisconnectedSessionLimitMin
		"			- BrokenConnectionAction : " + $connection.BrokenConnectionAction
		"			- TemporaryFoldersDeletedOnExit : " + $connection.TemporaryFoldersDeletedOnExit
		"			- AutomaticReconnectionEnabled : " + $connection.AutomaticReconnectionEnabled
		"			- ActiveSessionLimitMin : " + $connection.ActiveSessionLimitMin
		"			- IdleSessionLimitMin : " + $connection.IdleSessionLimitMin
		" "
		
		$loadbalancing = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -LoadBalancing
		"		Load Balancing Settings : " 
		foreach ($SessHost in $loadbalancing)
		{
		"			- SessionHost : " + $SessHost.SessionHost
		"				- RelativeWeight : " + $SessHost.RelativeWeight
		"				- SessionLimit : " + $SessHost.SessionLimit
		}
		" "
		
		$Security = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -Security
		"		Security Settings : " 
		"			- AuthenticateUsingNLA : " + $Security.AuthenticateUsingNLA
		"			- EncryptionLevel : " + $Security.EncryptionLevel
		"			- SecurityLayer : " + $Security.SecurityLayer
		" "
		
		$UserGroup = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -UserGroup 
		"		User Group Settings : "
		"			- UserGroup  : " + $UserGroup.UserGroup 
		" "
		
		$UserProfileDisks = Get-RDSessionCollectionConfiguration -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName -UserProfileDisk
		"		User Profile Disk Settings : "
		"			- EnableUserProfileDisk : " + $UserProfileDisks.EnableUserProfileDisk
		"			- MaxUserProfileDiskSizeGB : " + $UserProfileDisks.MaxUserProfileDiskSizeGB
		"			- DiskPath : " + $UserProfileDisks.DiskPath                 
		"			- ExcludeFilePath : " + $UserProfileDisks.ExcludeFilePath
		"			- ExcludeFolderPath : " + $UserProfileDisks.ExcludeFolderPath
		"			- IncludeFilePath : " + $UserProfileDisks.IncludeFilePath
		"			- IncludeFolderPath : " + $UserProfileDisks.IncludeFolderPath
		" "
				
		$usersConnected = Get-RDUserSession -ConnectionBroker $ConnectionBroker -CollectionName $CollectionName
		"		Users connected to this collection : " 
		foreach ($userconnected in $usersConnected)
		{
		"			User : " + $userConnected.DomainName + "\" + $userConnected.UserName
		"				- HostServer : " + $userConnected.HostServer
		"				- UnifiedSessionID : " + $userConnected.UnifiedSessionID
		}
		" "	 	
    }


# SIG # Begin signature block
# MIInpQYJKoZIhvcNAQcCoIInljCCJ5ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCWEhKoBksWIeEl
# jSvC9xPcH4cRlhpSa8aO9dzLXKkBAaCCDYUwggYDMIID66ADAgECAhMzAAADTU6R
# phoosHiPAAAAAANNMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI4WhcNMjQwMzE0MTg0MzI4WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDUKPcKGVa6cboGQU03ONbUKyl4WpH6Q2Xo9cP3RhXTOa6C6THltd2RfnjlUQG+
# Mwoy93iGmGKEMF/jyO2XdiwMP427j90C/PMY/d5vY31sx+udtbif7GCJ7jJ1vLzd
# j28zV4r0FGG6yEv+tUNelTIsFmmSb0FUiJtU4r5sfCThvg8dI/F9Hh6xMZoVti+k
# bVla+hlG8bf4s00VTw4uAZhjGTFCYFRytKJ3/mteg2qnwvHDOgV7QSdV5dWdd0+x
# zcuG0qgd3oCCAjH8ZmjmowkHUe4dUmbcZfXsgWlOfc6DG7JS+DeJak1DvabamYqH
# g1AUeZ0+skpkwrKwXTFwBRltAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUId2Img2Sp05U6XI04jli2KohL+8w
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzUwMDUxNzAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# ACMET8WuzLrDwexuTUZe9v2xrW8WGUPRQVmyJ1b/BzKYBZ5aU4Qvh5LzZe9jOExD
# YUlKb/Y73lqIIfUcEO/6W3b+7t1P9m9M1xPrZv5cfnSCguooPDq4rQe/iCdNDwHT
# 6XYW6yetxTJMOo4tUDbSS0YiZr7Mab2wkjgNFa0jRFheS9daTS1oJ/z5bNlGinxq
# 2v8azSP/GcH/t8eTrHQfcax3WbPELoGHIbryrSUaOCphsnCNUqUN5FbEMlat5MuY
# 94rGMJnq1IEd6S8ngK6C8E9SWpGEO3NDa0NlAViorpGfI0NYIbdynyOB846aWAjN
# fgThIcdzdWFvAl/6ktWXLETn8u/lYQyWGmul3yz+w06puIPD9p4KPiWBkCesKDHv
# XLrT3BbLZ8dKqSOV8DtzLFAfc9qAsNiG8EoathluJBsbyFbpebadKlErFidAX8KE
# usk8htHqiSkNxydamL/tKfx3V/vDAoQE59ysv4r3pE+zdyfMairvkFNNw7cPn1kH
# Gcww9dFSY2QwAxhMzmoM0G+M+YvBnBu5wjfxNrMRilRbxM6Cj9hKFh0YTwba6M7z
# ntHHpX3d+nabjFm/TnMRROOgIXJzYbzKKaO2g1kWeyG2QtvIR147zlrbQD4X10Ab
# rRg9CpwW7xYxywezj+iNAc+QmFzR94dzJkEPUSCJPsTFMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGXYwghlyAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAANNTpGmGiiweI8AAAAA
# A00wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFuQ
# Jn46t80mO6mimNmZ4aPuWz9U9sLk7meHk1IeknX5MEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAmCzKfdozT3Wa5R/qa9BI/21/18TDY3YFVS4v
# I688cRxc4tCVbpFlOr4GnyxsbtbdwV10wbn0UdgvR+LvpljUZ2nnpNEcm2ZgrGBt
# TSZzSYJfVud7ofyEagjBK7aneJMeg3rRHtI/x+R3LUO8xPjeKMPlNcTuKx5dJqyE
# pJpbTfvjVMkNB9SKLM2J9eqntG1nbAhpdyGTEB5f+Rq+sQFcax7bvlFR4gtOA+Rn
# cnME/OirCenZp48f3O0VmmgiW+pH/l5KWvsJlaoh4W+suaMzOXqSFsPxmvQOtpni
# Ykrd0vxTf17hIlV71mkmjbm6KrOHHLsa5vEzm9Clujh+AVCDDKGCFwAwghb8Bgor
# BgEEAYI3AwMBMYIW7DCCFugGCSqGSIb3DQEHAqCCFtkwghbVAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCBByZF6jk1l94Au8rysFRJ0rmtuT1w4ld3S
# wtkzE5P/nAIGZGzCbDxRGBMyMDIzMDYwNjExNDU1Mi41OTJaMASAAgH0oIHQpIHN
# MIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjpERDhDLUUzMzctMkZBRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEVcwggcMMIIE9KADAgECAhMzAAABxQPNzSGh9O85AAEA
# AAHFMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMTEwNDE5MDEzMloXDTI0MDIwMjE5MDEzMlowgcoxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkREOEMtRTMz
# Ny0yRkFFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAq0hds70eX23J7pappaKXRhz+
# TT7JJ3OvVf3+N8fNpxRs5jY4hEv3BV/w5EWXbZdO4m3xj01lTI/xDkq+ytjuiPe8
# xGXsZxDntv7L1EzMd5jISqJ+eYu8kgV056mqs8dBo55xZPPPcxf5u19zn04aMQF5
# PXV/C4ZLSjFa9IFNcribdOm3lGW1rQRFa2jUsup6gv634q5UwH09WGGu0z89Rbtb
# yM55vmBgWV8ed6bZCZrcoYIjML8FRTvGlznqm6HtwZdXMwKHT3a/kLUSPiGAsrIg
# Ezz7NpBpeOsgs9TrwyWTZBNbBwyIACmQ34j+uR4et2hZk+NH49KhEJyYD2+dOIaD
# GB2EUNFSYcy1MkgtZt1eRqBB0m+YPYz7HjocPykKYNQZ7Tv+zglOffCiax1jOb0u
# 6IYC5X1Jr8AwTcsaDyu3qAhx8cFQN9DDgiVZw+URFZ8oyoDk6sIV1nx5zZLy+hNt
# akePX9S7Y8n1qWfAjoXPE6K0/dbTw87EOJL/BlJGcKoFTytr0zPg/MNJSb6f2a/w
# DkXoGCGWJiQrGTxjOP+R96/nIIG05eE1Lpky2FOdYMPB4DhW7tBdZautepTTuShm
# gn+GKER8AoA1gSSk1EC5ZX4cppVngJpblMBu8r/tChfHVdXviY6hDShHwQCmZqZe
# bgSYHnHl4urE+4K6ZC8CAwEAAaOCATYwggEyMB0GA1UdDgQWBBRU6rs4v1mxNYG/
# rtpLwrVwek0FazAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
# KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4ICAQCMqN58frMHOScciK+Cdnr6dK8fTsgQDeZ9bvQjCuxN
# IJZJ92+xpeKRCf3Xq47qdRykkKUnZC6dHhLwt1fhwyiy/LfdVQ9yf1hYZ/RpTS+z
# 0hnaoK+P/IDAiUNm32NXLhDBu0P4Sb/uCV4jOuNUcmJhppBQgQVhFx/57JYk1LCd
# jIee//GrcfbkQtiYob9Oa93DSjbsD1jqaicEnkclUN/mEm9ZsnCnA1+/OQDp/8Q4
# cPfH94LM4J6X0NtNBeVywvWH0wuMaOJzHgDLCeJUkFE9HE8sBDVedmj6zPJAI+7o
# zLjYqw7i4RFbiStfWZSGjwt+lLJQZRWUCcT3aHYvTo1YWDZskohWg77w9fF2QbiO
# 9DfnqoZ7QozHi7RiPpbjgkJMAhrhpeTf/at2e9+HYkKObUmgPArH1Wjivwm1d7PY
# WsarL7u5qZuk36Gb1mETS1oA2XX3+C3rgtzRohP89qZVf79lVvjmg34NtICK/pMk
# 99SButghtipFSMQdbXUnS2oeLt9cKuv1MJu+gJ83qXTNkQ2QqhxtNRvbE9QqmqJQ
# w5VW/4SZze1pPXxyOTO5yDq+iRIUubqeQzmUcCkiyNuCLHWh8OLCI5mIOC1iLtVD
# f2lw9eWropwu5SDJtT/ZwqIU1qb2U+NjkNcj1hbODBRELaTTWd91RJiUI9ncJkGg
# /jCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQEL
# BQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNV
# BAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4X
# DTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM
# 57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm
# 95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzB
# RMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBb
# fowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCO
# Mcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYw
# XE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW
# /aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/w
# EPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPK
# Z6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2
# BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfH
# CBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYB
# BAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8v
# BO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYM
# KwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEF
# BQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBW
# BgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUH
# AQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# L2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsF
# AAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518Jx
# Nj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+
# iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2
# pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefw
# C2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7
# T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFO
# Ry3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhL
# mm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3L
# wUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5
# m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE
# 0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLOMIICNwIB
# ATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UE
# CxMdVGhhbGVzIFRTUyBFU046REQ4Qy1FMzM3LTJGQUUxJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVACEAGvYXZJK7
# cUo62+LvEYQEx7/noIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwDQYJKoZIhvcNAQEFBQACBQDoKQwjMCIYDzIwMjMwNjA2MDkzNjM1WhgPMjAy
# MzA2MDcwOTM2MzVaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOgpDCMCAQAwCgIB
# AAICC3ECAf8wBwIBAAICE+gwCgIFAOgqXaMCAQAwNgYKKwYBBAGEWQoEAjEoMCYw
# DAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0B
# AQUFAAOBgQDn/AVkinnxoW7oiA6JaC2aH8bU3EddsOkS5TGsob5xe6RIod8OpI8a
# 54rjAfuQhf1qET2KD8WWMLsMShcG8nbA0FcbGWIxShkZXeyzLAnna1i19M5dQVkj
# cXOqMKlDzAVCgDtwKKiyEjHbDPf7aPLNz0n1FfmEDmGOjZ5BhCG3ZzGCBA0wggQJ
# AgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABxQPNzSGh
# 9O85AAEAAAHFMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZI
# hvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIPTC4WcPRhHHtTWbI4mVEuiEvJjgRUnb
# 6MCjy5MuLk1QMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgGQGxkfYkd0wK
# +V09wO0sO+sm8gAMyj5EuKPqvNQ/fLEwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMAITMwAAAcUDzc0hofTvOQABAAABxTAiBCAUBiLXb89pWwpW
# fiLt7KCdsFZonG2R84rYVWZMvQb62DANBgkqhkiG9w0BAQsFAASCAgCkIaFM72oW
# mkiY0ScIHjhH1q57sEVD5rMT1myCtuxjaE8KVZ5k2tPv+gUX8eBz9ztFF9iAFBfP
# N8Vhn/YtokZnsX27ogAFEls3gmYego9gG/XhBKOXVERySuU5zpXiLK3iTTUQj/Ax
# mi7w9BgD+gnxPFM3x742XjjMvUZf9dVOKHnGxbkC+bhAU76AVFH3w9XwnhKsGFSU
# ulLmBJWlA26KtXfm3GfzisuO478EdqQiVlemTei44FPCnQdhq4KA3Rksv9jElG/u
# AO/2AHMaYb4Ri6w5yAux1qnoOEvQUDxQf+gAZ/fx065wHbAtgIgr/oFoOWqFWBw3
# g+GUi9IAe10uok0IRr+pV7LFQ3PAkBcEiMU+sp9ofjOD+Oz+CVqlMv/r21t/TqYp
# 5bmF7eRfwj3rPkXLbNRIqdGy8IupDPkuMkhMQU8nKiVHdRsHCJU+rMbm/mSx9bnM
# fmKH1o3cAoqSI3C2TGD2JD649UwGj34yyuczEqEOWVbSbFthkvkzSl+1ouQWFAS/
# m43PKai1X87DaQgglebsCXrjOT61Ee+EsaGmjcITuyXWLzYndGwCOocRqEuqfskc
# XuqA9gS0A5dF0R+dAMEs653BfoixC0f6xRi6zFC2mC3HPhPM3hk9e1wJBuP3kvue
# RM0bh1mKP6PmNlGB7MQ/3DMvP3yEsCb/UQ==
# SIG # End signature block
