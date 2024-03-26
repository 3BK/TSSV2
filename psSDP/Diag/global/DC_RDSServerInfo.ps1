#************************************************
# DC_RDSServerInfo.ps1
# Version 1.0.0
# Date: 21-01-2012
# Author: Daniel Grund - dgrund@microsoft.com
# Description: 
#	This script gets the RDS config and
#   checks vital signs to inform user.
# 1.0.0 Beta release / 2021-03-30 Waltere #_#
#************************************************
PARAM(
	[string] $TargetHost = "localhost",
   	[string] $RootCause = "",
   	[object] $RDSobject = $null,
	[array]  $OutputFileName
)
# globals and function definitions for RDS
$OutputFolder = $PWD.Path 
Import-LocalizedData -BindingVariable RDSSDPStrings -FileName DC_RDSServerInfo -UICulture en-us
$bIsRDSSH = $false
$bIsRDSGW = $false
$bIsRDSCB = $false
$bIsRDSLS = $false
$RCNum = 0

Trap [Exception]  #_#
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}
	
. ./DC_RDSHelper.ps1 $RDSHelper $RDSSDPStrings
Write-DiagProgress -Activity $RDSSDPStrings.ID_RDSServerProgress -Status $RDSSDPStrings.ID_RDSWMIGet
Copy-Item .\RDS.xslt (join-path $pwd.path "result\RDS.xslt")
#[array]$OutputFileName+= $OutputFolder + "\" + "RDS.xslt"

#test for validity of the target end point
#$OS = Get-CimInstance -Class win32_operatingsystem -Namespace root\cimv2 -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate 
#$Computer = Get-CimInstance -Class win32_ComputerSystem -Namespace root\cimv2 -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate  
$OS = Get-CimInstance -Class win32_operatingsystem -Namespace root\cimv2 
$Computer = Get-CimInstance -Class win32_ComputerSystem -Namespace root\cimv2
if (($null -ne $Computer) -and (($TargetHost -ne $Computer.DNSHostName) -or ( $TargetHost -eq $Computer.DNSHostName + "." + $Computer.Domain)))
{
    $TargetHost = $Computer.DNSHostName.ToUpper()
}



#$RDSobject = FilterWMIObject (Get-CimInstance -Class Win32_TerminalServiceSetting -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate)
#$RDSGateWay = FilterWMIObject (Get-CimInstance -Class Win32_TSGatewayServer -Namespace root\cimv2\TerminalServices -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate -EA SilentlyContinue) #_# -EA
#$RDSCB = FilterWMIObject (Get-CimInstance -Class Win32_SessionDirectoryServer -Namespace root\cimv2 -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate -EA SilentlyContinue) #_# -EA
#$RDSLS = FilterWMIObject (Get-CimInstance -Class Win32_TSLicenseServer -Namespace root\cimv2 -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate -EA SilentlyContinue) #_# -EA
$RDSobject = FilterWMIObject (Get-CimInstance -Class Win32_TerminalServiceSetting -Namespace root\cimv2\TerminalServices)
$RDSGateWay = FilterWMIObject (Get-CimInstance -Class Win32_TSGatewayServer -Namespace root\cimv2\TerminalServices) #_# -EA
$RDSCB = FilterWMIObject (Get-CimInstance -Class Win32_SessionDirectoryServer -Namespace root\cimv2) #_# -EA
$RDSLS = FilterWMIObject (Get-CimInstance -Class Win32_TSLicenseServer -Namespace root\cimv2) #_# -EA
$Error.Clear()
if ($null -eq $OS) 
{
	ReportError -RCNum $RCNum -RootCause $RDSSDPStrings.ID_RDSWMIGetError -Solution $RDSSDPStrings.ID_RDSWMIGetSolution
	exit
}

if ($null -ne $RDSCB)
{
	"RDSCB " | WriteTo-StdOut
	$bIsRDSCB = $true
	$OutputFileName = SaveAsXml $RDSCB  ($TargetHost + "_Win32_SessionDirectoryServer.xml") $OutputFileName

	#start multi system
	# skip this for now, enable after further testing
	if($false) # remove for enable
	{		   # remove for enable
	$TargetHost_Temp = $TargetHost  # calling ourself will break targethost, saving it.
    #$RDSCBCluster = Get-CimInstance -Class Win32_SessionDirectoryCluster -Namespace root\cimv2 -ComputerName $TargetHost -Authentication PacketPrivacy -Impersonation Impersonate
    $RDSCBCluster = Get-CimInstance -Class Win32_SessionDirectoryCluster -Namespace root\cimv2
    $ConnectionBroker = New-Object RDSHelper+ConnectionBroker
	$ConnectionBroker.ConnectionBrokerName = $TargetHost_Temp
	
	foreach( $Cluster in $RDSCBCluster)
    {
		$Collection = New-Object RDSHelper+Collection
		$Collection.CollectionName = $Cluster.ClusterName
	
        $Query = "Select * from Win32_SessionDirectoryServer where ClusterName='" + $Cluster.ClusterName + "'" 
	    $RDSCBClusterEnum = Get-CimInstance -Query $Query -Namespace root\cimv2
		$Collection.CollectionServers = $RDSCBClusterEnum.ServerName
        $ConnectionBroker.Collections += $Collection
    }
	# Treeview for the server list , don't show if there are no collections
	if($ConnectionBroker.Collections.Count -gt 0)
	{
		$objTreeView = CreateTreeViewUI -ConnectionBroker $ConnectionBroker
		# Get all the servers that were checked in the UI
		$ServersToCollect = GetNodesChecked -objTreeView $objTreeView -ServersToCollect $ServersToCollect
		# Get report logs from each server
		foreach($Server in $ServersToCollect)
		{
			. ./DC_RDSServerInfo.ps1 -TargetHost $Server
		}
	}
	$TargetHost = $TargetHost_Temp # restore targethost when we come back
	} # remove for enable
	#end multi system
	. ./DC_RDSCB.ps1 -TargetHost $TargetHost -RDSobject $RDSobject -OutputFileName $OutputFileName -OS $OS -bIsRDSCB $bIsRDSCB
}
 
if ($null -ne $RDSobject)
{
	
	if($RDSobject.TerminalServerMode -eq "1") {$bIsRDSSH = $true}
	"RDSSH" + $bIsRDSSH| WriteTo-StdOut
    $OutputFileName = SaveAsXml $RDSobject  ($TargetHost + "_Win32_TerminalServiceSetting.xml") $OutputFileName
	. ./DC_RDSSH.ps1 -TargetHost $TargetHost -RDSobject $RDSobject -OutputFileName $OutputFileName -OS $OS -bIsRDSSH $bIsRDSSH
}

if ($null -ne $RDSGateWay)
{
	"RDSGateWay" | WriteTo-StdOut
	$bIsRDSGW = $true
	. ./DC_RDSGW.ps1 $TargetHost $RDSobject $OutputFileName $OS $RDSSDPStrings $bIsRDSGW
}



if ($null -ne $RDSLS)
{
	"RDSLS" | WriteTo-StdOut
	$bIsRDSLS = $true
	$OutputFileName = SaveAsXml $RDSLS  ($TargetHost + "_Win32_TSLicenseServer.xml") $OutputFileName
	. ./DC_RDSLS.ps1 $TargetHost $RDSobject $OutputFileName $OS $RDSSDPStrings $bIsRDSLS
}

#get All RDS eventlogs
. ./DC_RDSEventLog.ps1 $TargetHost $RDSSDPStrings $OutputFolder  #_# . .\

#get IIS information
Write-DiagProgress -Activity $RDSSDPStrings.ID_RDSServerProgress -Status $RDSSDPStrings.ID_RDSIIS
. ./DC_RDSRDWeb.ps1 $TargetHost $OutputFileName  #_# . .\

#get all the info we can get from RDS powershell plugin !! Only if we have RDS components and if we have powershell V2
#if (($host.version.Major -ge 2) -and (($bIsRDSSH -eq $true) -or ($bIsRDSGW -eq $true) -or ($bIsRDSCB -eq $true) -or ($bIsRDSLS -eq $true)))
#{
#	Write-DiagProgress -Activity $RDSSDPStrings.ID_RDSServerProgress -Status $RDSSDPStrings.ID_RDSPowerShell
#	. ./DC_RDSPowerInfo.ps1 $TargetHost $OutputFileName $RDSSDPStrings
#}

# get the RDMSDeploymentUI
$File = $Env:windir + "\Logs\RDMSDeploymentUI.txt"
if(Test-Path $File )
{
	$OutputFileName += $File
}
#get the RDMSUI-trace.log
$File = $Env:temp + "\RDMSUI-trace.log"
if(Test-Path $File )
{
	$OutputFileName += $File
}

#collect our files !!!
$sectionDescription = "RDS specific files"
[array]$RDPFiles = $null
if ($OutputFileName -is [array])
	{
		ForEach ($OutputFile in $OutputFileName)
		{
			$fileDescription = $OutputFile.Substring($OutputFile.LastIndexOf('_')+1, ($OutputFile.LastIndexOf('.')-$OutputFile.LastIndexOf('_')-1))
			if ($OutputFile.Substring($OutputFile.Length -4, 4) -eq ".xml")
			{
				CollectFiles -filesToCollect ([System.IO.Path]::Combine($OutputFolder, $OutputFile)) -fileDescription $fileDescription -sectionDescription $sectionDescription -Verbosity Debug
			}elseif($OutputFile.Substring($OutputFile.Length -4, 4) -eq ".rdp")
			{
				[array]$RDPFiles += $OutputFile
			}
			else
			{
				CollectFiles -filesToCollect ([System.IO.Path]::Combine($OutputFolder, $OutputFile)) -fileDescription $fileDescription -sectionDescription $sectionDescription 
			}
			
			Write-DiagProgress -Activity $RDSSDPStrings.ID_RDSServerProgress -Status ($RDSSDPStrings.ID_RDSSaved + " " + $OutputFile)
		}
		if($RDPFiles -ne "")
		{
			$RDPFiles = ($RDPFiles | ForEach-Object {([System.IO.Path]::Combine( $OutputFolder,$_))})
			CompressCollectFiles -filesToCollect $RDPFiles -DestinationFileName "RDSRdpFiles.zip" -renameOutput $false  -fileDescription "Compressed collected RDP files" -sectionDescription $sectionDescription 
		}
	}
	else
	{
		CollectFiles -filesToCollect ([System.IO.Path]::Combine($OutputFolder, $OutputFileName)) -fileDescription $FileDescription -sectionDescription $sectionDescription
	}



# SIG # Begin signature block
# MIInoAYJKoZIhvcNAQcCoIInkTCCJ40CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCARsxcrUg+OEUdu
# TPN/KrnDYenBEDKHA/4N2LgK5FsbI6CCDYEwggX/MIID56ADAgECAhMzAAACzI61
# lqa90clOAAAAAALMMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NjAxWhcNMjMwNTExMjA0NjAxWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCiTbHs68bADvNud97NzcdP0zh0mRr4VpDv68KobjQFybVAuVgiINf9aG2zQtWK
# No6+2X2Ix65KGcBXuZyEi0oBUAAGnIe5O5q/Y0Ij0WwDyMWaVad2Te4r1Eic3HWH
# UfiiNjF0ETHKg3qa7DCyUqwsR9q5SaXuHlYCwM+m59Nl3jKnYnKLLfzhl13wImV9
# DF8N76ANkRyK6BYoc9I6hHF2MCTQYWbQ4fXgzKhgzj4zeabWgfu+ZJCiFLkogvc0
# RVb0x3DtyxMbl/3e45Eu+sn/x6EVwbJZVvtQYcmdGF1yAYht+JnNmWwAxL8MgHMz
# xEcoY1Q1JtstiY3+u3ulGMvhAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUiLhHjTKWzIqVIp+sM2rOHH11rfQw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDcwNTI5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAeA8D
# sOAHS53MTIHYu8bbXrO6yQtRD6JfyMWeXaLu3Nc8PDnFc1efYq/F3MGx/aiwNbcs
# J2MU7BKNWTP5JQVBA2GNIeR3mScXqnOsv1XqXPvZeISDVWLaBQzceItdIwgo6B13
# vxlkkSYMvB0Dr3Yw7/W9U4Wk5K/RDOnIGvmKqKi3AwyxlV1mpefy729FKaWT7edB
# d3I4+hldMY8sdfDPjWRtJzjMjXZs41OUOwtHccPazjjC7KndzvZHx/0VWL8n0NT/
# 404vftnXKifMZkS4p2sB3oK+6kCcsyWsgS/3eYGw1Fe4MOnin1RhgrW1rHPODJTG
# AUOmW4wc3Q6KKr2zve7sMDZe9tfylonPwhk971rX8qGw6LkrGFv31IJeJSe/aUbG
# dUDPkbrABbVvPElgoj5eP3REqx5jdfkQw7tOdWkhn0jDUh2uQen9Atj3RkJyHuR0
# GUsJVMWFJdkIO/gFwzoOGlHNsmxvpANV86/1qgb1oZXdrURpzJp53MsDaBY/pxOc
# J0Cvg6uWs3kQWgKk5aBzvsX95BzdItHTpVMtVPW4q41XEvbFmUP1n6oL5rdNdrTM
# j/HXMRk1KCksax1Vxo3qv+13cCsZAaQNaIAvt5LvkshZkDZIP//0Hnq7NnWeYR3z
# 4oFiw9N2n3bb9baQWuWPswG0Dq9YT9kb+Cs4qIIwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZdTCCGXECAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBsDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgNBl5Y66x
# wXlihv1wAirBvXTshJ2gZseoPRzveqYrwzYwRAYKKwYBBAGCNwIBDDE2MDSgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20g
# MA0GCSqGSIb3DQEBAQUABIIBACHuWiuBVw7G37BFjkcowJcfIP2JjI8hUSoVfuyO
# orEjGSrnmyNHFg5/PqppSK44OKgwcTYShnjlVUVgn7C7anandb0IX7UvkyhiXZek
# OK4dQsCHsfLSeFnXbAvVWHR9N2bxX07bMLr2+B6WCGz/I8HNbtMnWcR0+lZXyvJm
# U220BZ9ddpZU2EbF6VxZouPuhNUefjVEgfYU4JeroMpmASC2/ftv0dWwzw8q6/om
# AaMCzl2XszltFMdS+c3rrnpfonaACr1L/Jsxv+7fSfgmADMfPxHU0ACe3er6dr8e
# 0G62WSvQOpbLVJ+X1Iz5cZtNJr01v1Oosfu50Dvm2gg/Q7Khghb9MIIW+QYKKwYB
# BAGCNwMDATGCFukwghblBgkqhkiG9w0BBwKgghbWMIIW0gIBAzEPMA0GCWCGSAFl
# AwQCAQUAMIIBUQYLKoZIhvcNAQkQAQSgggFABIIBPDCCATgCAQEGCisGAQQBhFkK
# AwEwMTANBglghkgBZQMEAgEFAAQgvk6SbsqXgLTutGFF13MZTxLykzSfDkngtEbb
# YkshfsACBmNIXQAXXhgTMjAyMjEwMjQwODE1MjUuMTU1WjAEgAIB9KCB0KSBzTCB
# yjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMc
# TWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRT
# UyBFU046OEE4Mi1FMzRGLTlEREExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFNlcnZpY2WgghFUMIIHDDCCBPSgAwIBAgITMwAAAZnIj6+ttn2+iwABAAAB
# mTANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAe
# Fw0yMTEyMDIxOTA1MTZaFw0yMzAyMjgxOTA1MTZaMIHKMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmlj
# YSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4QTgyLUUzNEYt
# OUREQTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALgT+VdcoyzL2tVrZrxtFvQCv8+P
# j5sqICAyAprK8IwWfd10ah/x5YWAlankl0qNaOueZbWv20elw/aQWmNenZR2uPnm
# O3k1iLUwRFygij4Tb1e4LAUAwl+0Z2+xZ5r85NA8gWxkRaoS15d1GdzJXBy3nEXM
# EgLUlYJ2Z9ztHn1EwjK+BaMjPzfnqbB6jCQ6y03V97ncognx+WtggshBaw1Ew5Pf
# OcAbAhv2TIvngLqNmMXE5K6wZiZVD4av+plAQvDWKnH2zmM0/UtKk6l9MQEW77L0
# os0GYwEBGRI+lMWQYTIZLAYaBJ06LoFToU8r7q6tnzfSOtF6YrgmQgn21CGUZwiE
# COFyplK2f7fyVGNW+t9sEjkSkjY3CVUgraJsZbuxZ5MDP/I080hJRtCEYAmx786A
# aP/WrP8dr2ap9hnwEdyE3GfTydaSrKuOsqJxDLG4PyYJq1OtVJs4lh9DJl0dH1ri
# +DIZ5kRcFhA0CUi4HftAI4CCz9V4NTwzh1z8iWtPILS5XVJLgaTzNX7lfl5G75c5
# E3wVarMjqT/3LpxbA5YwrppQ3VeotxoX+yb2tfzh4pbaWENzcLfVYuOnxQ584dl8
# +7LLnjF+KWeGEI/LhAon2OCCiqp54SEIR+ANiPL48HJX97kcMHbEd22Uv3fCW0CQ
# jdoLGjziRU8EJrQ7AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUjbpWuD6cZa+u8iHR
# 1A8SicQ1HRAwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0f
# BFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwv
# TWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsG
# AQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAx
# MCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkq
# hkiG9w0BAQsFAAOCAgEAcbNaHb2JsE2ujeezwTcQ4cawsHUbOT3RIVhQoGKUi7iM
# NtHupu9c13yeeX/PkP0sqDDdPzWOrLm0yJan6niNgEGTc9HHXJKotR+EXlkxaiVH
# Nb5xBkZdXfyJKZ0BQbQKlHnHWsx08itNzNVQWw5gaqaShRD91GJUviIBcksI1OPj
# HdjAhBwI+3SKMlWKc8gwBjMDx/30Ft6KyTIjQEcYB3SQZRfYjb+m5ieXJLy2gGcA
# 2OHbXGC8S5pnZ29Gq9aT+LVciU7rtq79cJ4xO9eE84hSarzRTfZOJ/DdJKIEpPKK
# vuahYfWLsfarlACesHG7LL/9mwN8BENX8C2aPmOvoBN9EcN1RqdCl6gFL6LKU1Tp
# EBG7yD5MwK79md1mauz3D7yBqVQgaD4aaU2TTt9cnnw5z6oWqA0Cw2QyL51LMqRY
# YDj+SUkWfReJyFcvz63so5rJcobNCNroJ20KOKyfJLyFu/g8qFp4y1/rzAlYoo6z
# S23YAl9gLm9Jsf1yTwEaPZ7/JBcRkS7zwvn98crldST8gpfHfNouTFdNJnjcRr9Y
# pdUHMxqwdnc+afLSagR6QBfHVSEs01i/hW6bfdWKvFIHqv8YpDEVIe7vIV+tZClj
# LIMfXX1OaEB51LxPVVpup207lk/YTXhMrzZXLHLfEQ96U6jh1EiWGbtdjqT0Hrww
# ggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUA
# MIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQD
# EylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0y
# MTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0
# ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveV
# U3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTI
# cVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36M
# EBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHI
# NSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxP
# LOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2l
# IH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDy
# t0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymei
# XtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1
# GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgV
# GD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQB
# gjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTu
# MB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsG
# AQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUH
# AwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
# EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQAD
# ggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/
# 2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvono
# aeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRW
# qveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8Atq
# gcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7
# hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkct
# wRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu
# +yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FB
# SX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/
# Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ
# 8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICyzCCAjQCAQEw
# gfihgdCkgc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOjhBODItRTM0Ri05RERBMSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQCS7/Ni6Oepqk3o
# En0wnmO2AOuU66CBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MA0GCSqGSIb3DQEBBQUAAgUA5wCzEDAiGA8yMDIyMTAyNDE0NDUzNloYDzIwMjIx
# MDI1MTQ0NTM2WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDnALMQAgEAMAcCAQAC
# Ah8lMAcCAQACAhGeMAoCBQDnAgSQAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisG
# AQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQAD
# gYEAgkqGoLn4ozeW+7PXrgnCAhdlu39HA1kf11B2o+xiDig6ziwiV1mYxYE/AFj5
# 87TSHCJxDhuNre5zEOtWO4Oe9mccQOd1hWYmrz0xmi5bbR/oNBR6wktwtGmrCPd9
# hzQQER4eWJJJ4wf5xTnHOpUqldZvakJB5uchQa7XHSVBleExggQNMIIECQIBATCB
# kzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAZnIj6+ttn2+iwAB
# AAABmTANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJ
# EAEEMC8GCSqGSIb3DQEJBDEiBCAbT8PB6r7qHvczsSIFT7hMSTeF8lFbELSVnJfj
# lB2IMzCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIGZ9afnyoo3tZakFNg6t
# Q7UFIJKco8sL8bvAI4hzYmx+MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTACEzMAAAGZyI+vrbZ9vosAAQAAAZkwIgQgJrSflPSXjSWwBe2rHYVO
# rXh+lrrWldSvB3njUSRUwQcwDQYJKoZIhvcNAQELBQAEggIAZyaImmHzYOU++pGV
# Qky8kd/iL9JQPmdtvLaOl7Re6UpYv2+OVZyyrrXKn+q53rCvbaQYAbJtQtq3hfPO
# Km0222X5VloGjazYqXa0UmO/kLwv++2tYB8N03VF7vWlOs+rIj8NLe1WX2wfukpG
# OF/owZUWcqhz2BQhMVdZxnqZ8EENi1+mUoaZfr2UvYtWHM/lw0Ob9Qm3BltkPSwK
# IXZLxjctMoCSoN+h4NmBRbiYWxmK5Tk+jJnJJrpvf7smLBXfWXTvcwnXdWELw9vI
# qYSYQX8AeXsR3zcSs+RomMoRtwdYfstri2xG+P6sshZDnaqp846tPg13fHarm+iB
# hgtEeWoJc0fbWdvqLRd4TnX7o+BQelzk9gEjDDaOKv9NRSmRIFYQODrsME2yvGZP
# SaS7+XRzUBwgN4NcUV6pKnsHKs8n5DcjinkViigkzsflqDfcjW7XhUHDNOg4Q/ja
# BjncTOp08nCpDLZ9K6AfiGOBS/srAjMbYuS7M3/23NXkuHMLrxn9UcABsxEJZUxU
# e6M1kFgNl648oWfbmD4BDeP9wVulYfypKZWzd1sL5foHj9ylResvfCOLsRnavZn3
# wFAvtuIbhye7bMlwFPbviAly18yoAi1nJocp/MmDeF3cxiS3GQiXompzWiHueZ8k
# 3sEqjnDqUHrAKMzfur/jMVacoec=
# SIG # End signature block
