#************************************************
# TS_SelectClusterNodes.ps1
# Version 1.0.1
# Date: 02-09-2011
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script asks customer to select the cluster nodes on which the diagnostic will obtain data from
#************************************************

Import-LocalizedData -BindingVariable ScriptStrings

Function GetWin32OSFromRemoteSystem([string] $RemoteMachine)
{
	$Error.Clear()
	
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $Error[0] -ScriptErrorText ("[GetWin32OSFromRemoteSystem] Remote Machine: $RemoteMachine")
		continue
	}

	Write-DiagProgress -Activity ($ScriptStrings.ID_EPSConnectingTo.Replace("%Machine%", $RemoteMachine)) -Status $ScriptStrings.ID_EPSConnectingToDesc
	
	$Win32OS = Get-CimInstance -Class Win32_OperatingSystem -ComputerName $RemoteMachine -ErrorAction SilentlyContinue
	
	if ($Error.Count -gt 0)
	{
		if ($Error[0].Exception.ErrorCode -eq -2147023174) #The RPC server is unavailable. (Exception from HRESULT: 0x800706BA)
		{
			get-diaginput -id "ErrorContactingNode" -Parameter @{"Machine"=$RemoteMachine; "Error"=$ScriptStrings.ID_EPSConnectingRCPError}
			$Error.Clear()
		} 
		else 
		{
			get-diaginput -id "ErrorContactingNode" -Parameter @{"Machine"=$RemoteMachine; "Error"= $Error[0].Exception.Message}
			$Error.Clear()
		}
		return $null
	} 
	else 
	{
		Return $Win32OS
	}
}

Function isClusterNode([string] $RemoteMachine)
{
	$Error.Clear()
	
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("[isClusterNode] Check if machine $RemoteMachine has ClusSvc service")
		continue
	}
	
	Write-DiagProgress -Activity ($ScriptStrings.ID_EPSConnectingTo.Replace("%Machine%", $RemoteMachine)) -Status $ScriptStrings.ID_EPSSelectNodesObtainingCluster
	
	"[isClusterNode] Detecting if $RemoteMachine is a cluster node..." | WriteTo-StdOut -ShortFormat
	
	$CluSvc = Get-Service -ComputerName $RemoteMachine | Where-Object {$_.Name -eq "ClusSvc"}
	
	if ($null -ne $CluSvc.Status)
	{
		"[isClusterNode] $RemoteMachine is a cluster node. Cluster Service is currently " + $CluSvc.Status.ToString() | WriteTo-StdOut -ShortFormat
		return $true
	}
	else
	{
		"[isClusterNode]  Error obtaining status of cluster service of machine $RemoteMachine"  | WriteTo-StdOut -ShortFormat
		get-diaginput -id "ErrorContactingNode" -Parameter @{"Machine"=$RemoteMachine; "Error"= $ScriptStrings.ID_EPSSelectNodesUnableService}
		return $false
	}
}


#Step 1: Check if machine is a cluster machine - fastest way: Check if HKLM\Cluster exists

trap [Exception] 
{
	WriteTo-ErrorDebugReport -ErrorRecord $Error[0] -ScriptErrorText ("[isClusterNode] Remote Machine: $RemoteMachine")
	$Error.Clear()
	continue
}

$ClusterKey = "HKLM:\SYSTEM\CurrentControlSet\services\ClusSvc"
$RemoteScriptExecuted = $false

do
{
	$IsClusterNode = $false
	$NodeName = $null
	
	if (Test-Path -Path $ClusterKey) 
	{
		"Machine is cluster node: True" | WriteTo-StdOut -ShortFormat
		$IsClusterNode = $true
		$NodeName = $COMPUTERNAME
	}
	else
	{
		"Machine is cluster node: False" | WriteTo-StdOut -ShortFormat
		#$NodeName = $COMPUTERNAME #_#
		$NodeName = Get-DiagInput -Id ClusterNode -Parameter @{"Machine"=$COMPUTERNAME}
		
		if (-not (($NodeName[0] -eq 0) -or ($null -eq $NodeName[0])))
		{
			$NodeName = $NodeName[0].ToUpper()
		}
		else
		{
			$NodeName = $null
		}
	
		if ($null -ne $NodeName)
		{
			
			"Customer selected cluster node: $NodeName" | WriteTo-StdOut -ShortFormat
			
			$RemoteMachineOS = GetWin32OSFromRemoteSystem $NodeName

			"Remote Machine OS Build: " + $RemoteMachineOS.BuildNumber  | WriteTo-StdOut -ShortFormat

			if ($null -ne $RemoteMachineOS) 
			{
				if (($RemoteMachineOS.BuildNumber -lt 3790) -or ($RemoteMachineOS.ProductType -eq 1))
				{
					"Error: $NodeName is not a supported OS version. OS version of $NodeName is " + $RemoteMachineOS.Caption | WriteTo-StdOut
					get-diaginput -id "ErrorContactingNode" -Parameter @{"Machine"=$NodeName; "Error"=($ScriptStrings.ID_EPSSelectNodesNotSupported.Replace("%Machine%",$NodeName).Replace("%OSName%",$RemoteMachineOS.Caption))}
				} 
				else 
				{	
					if (isClusterNode $NodeName)
					{
						$IsClusterNode = $true
					}
					else
					{
						"Error: $NodeName is not a cluster node." | WriteTo-StdOut
						get-diaginput -id "ErrorContactingNode" -Parameter @{"Machine"=$NodeName; "Error"=$ScriptStrings.ID_MachineIsNotaCluster.Replace("%Machine%", $NodeName)}
						$IsClusterNode = $false
					}
				}
			}
		}
	}
} while (-not $IsClusterNode)

#Now obtain the names of nodes by querying the cluster key
if ($IsClusterNode)
{
	$Error.Clear()

	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("Querying remote registry on [" + $NodeName + "]")
		continue
	}
	
	#Connect to remote Registry
	$RemoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $NodeName)
	
	if ($Error.Count -eq 0)
	{
	
		trap [Exception] 
		{
			WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("Querying cluster information [" + $NodeName + "]")
			continue
		}
	
		$RemoteNodesKey = $RemoteReg.OpenSubKey("Cluster\Nodes")
		
		if ($RemoteNodesKey.SubKeyCount -gt 0)
		{
			$ClusterName = $RemoteReg.OpenSubKey("Cluster", $false).GetValue("ClusterName").ToUpper()
			
			$Choices = @()
			
			foreach ($SubKey in $RemoteNodesKey.GetSubKeyNames())
			{

				$NodeMachineName = $RemoteReg.OpenSubKey("Cluster\Nodes\$SubKey", $false).GetValue("NodeName").ToUpper()
				
				if ($NodeName -ne $NodeMachineName) 
				{
					$ExtensionPoint = ""
				} else {
					#Set the node local machine (or machine indicated by customer) the default
					$ExtensionPoint = "<Default/>"
				}

				$Choices += @{"Name"=$NodeMachineName;"Value"=$NodeMachineName;"Description"=$NodeMachineName;"ExtensionPoint"=$ExtensionPoint}
				
			}

			$TroubleshootingNodeNames = @()
			
			"ClusterName: $ClusterName - Choices: " | WriteTo-StdOut
			$Choices | WriteTo-StdOut
			
			if ($Choices.Count -gt 0)
			{
				do
				{
					$TroubleshootingNodeNames += Get-DiagInput -Id "SelectNodes" -Parameter (@{"Cluster"=$ClusterName}) -Choice $Choices
					
				} while ($TroubleshootingNodeNames.Count -eq 0)

				if (($TroubleshootingNodeNames[0] -ne 0) -and ($TroubleshootingNodeNames.Count -ne 0))
				{
					if ($TroubleshootingNodeNames -contains "All")
					{
						foreach ($MachinName in $ClusterValues)
						{
							$MachineNames = $MachinName.Value
						}
					}
					else 
					{
						$MachineNames = $TroubleshootingNodeNames
					}

					Return $MachineNames

				}
			}
			else 
			{
				get-diaginput -id "ErrorContactingNode" -Parameter @{"Machine"=$NodeName; "Error"=$ScriptStrings.ID_EPSSelectNodesUnableObtainNames}
			}
		} 
		else 
		{
			#Machine is a cluster node, but HKLM\Cluster does not exist. In this case proceed collecting information only from local machine.
			return @($Env:COMPUTERNAME)
		}
	} else {
		get-diaginput -id "ErrorContactingNode" -Parameter @{"Machine"=$NodeName; "Error"=$ScriptStrings.ID_UnableQueryRegistry.Replace("%ErrorMessage%", $Error[0].Exception.Message).Replace("%NodeName%", $NodeName)}
	}
}


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAGsOR8IAyxIk+/
# gazI8LyUT19m2SUiCPADBXfOw2MoFqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKR8t459TPYtRIGkkQOD44aq
# /W+pF9mkPIm3cW9B3d6KMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBiS5r87RX6TGZyLTK+TKmUgoQIIw17FdG00JwBP1Nk45HXuacQrs75
# A7peXF28zyNlm9E4KOtjHhpXGh5DQZ6KMyyEP3J4OSfsz4gtsl7LjW5ViysYjPcL
# gEJlfi4Qu33okjvXADqj3q37fN1DcRyFLalbsNW/9Pnv9AUN0VKr5M2UJo8NYcxW
# k/JwG9jv9y7WMTVSHQDzygQQmu0BIe2SrYPEgDsgtbWj296V0cucach2aW3O5Nbz
# Z6BOh3BhLc9eTnHkw7kLxCRxzcqEjS/Ck5QcgbMRBkGsUwW2dGsENSK3bfcP8thS
# BdmUG04TzEv/1j5TjwNP+K2SC9cij4VIoYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIJFZrXAY+E/KfdzPldPDiZFLoR3qc2hClropI7r/qnWyAgZi3n81
# KuAYEzIwMjIwODAxMDgwNTU1LjMyMVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046M0JENC00QjgwLTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAYm0v4YwhBxLjwABAAABiTAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDFaFw0yMzAxMjYxOTI3NDFaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNCRDQt
# NEI4MC02OUMzMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvQZXxZFma6plmuOyvNpV
# 8xONOwcYolZG/BjyZWGSk5JOGaLyrKId5VxVHWHlsmJE4SvnzsdpsKmVx8otONve
# IUFvSceEZp8VXmu5m1fu8L7c+3lwXcibjccqtEvtQslokQVx0r+L54abrNDarwFG
# 73IaRidIS1i9c+unJ8oYyhDRLrCysFAVxyQhPNZkWK7Z8/VGukaKLAWHXCh/+R53
# h42gFL+9/mAALxzCXXuofi8f/XKCm7xNwVc1hONCCz6oq94AufzVNkkIW4brUQgY
# pCcJm9U0XNmQvtropYDn9UtY8YQ0NKenXPtdgLHdQ8Nnv3igErKLrWI0a5n5jjdK
# fwk+8mvakqdZmlOseeOS1XspQNJAK1uZllAITcnQZOcO5ofjOQ33ujWckAXdz+/x
# 3o7l4AU/TSOMzGZMwhUdtVwC3dSbItpSVFgnjM2COEJ9zgCadvOirGDLN471jZI2
# jClkjsJTdgPk343TQA4JFvds/unZq0uLr+niZ3X44OBx2x+gVlln2c4UbZXNueA4
# yS1TJGbbJFIILAmTUA9Auj5eISGTbNiyWx79HnCOTar39QEKozm4LnTmDXy0/KI/
# H/nYZGKuTHfckP28wQS06rD+fDS5xLwcRMCW92DkHXmtbhGyRilBOL5LxZelQfxt
# 54wl4WUC0AdAEolPekODwO8CAwEAAaOCATYwggEyMB0GA1UdDgQWBBSXbx+zR1p4
# IIAeguA6rHKkrfl7UDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQCOtLdpWUI4KwfLLrfaKrLB92DqbAspGWM41TaO
# 4Jl+sHxPo522uu3GKQCjmkRWreHtlfyy9kOk7LWax3k3ke8Gtfetfbh7qH0LeV2X
# OWg39BOnHf6mTcZq7FYSZZch1JDQjc98+Odlow+oWih0Dbt4CV/e19ZcE+1n1zzW
# kskUEd0f5jPIUis33p+vkY8szduAtCcIcPFUhI8Hb5alPUAPMjGzwKb7NIKbnf8j
# 8cP18As5IveckF0oh1cw63RY/vPK62LDYdpi7WnG2ObvngfWVKtwiwTI4jHj2cO9
# q37HDe/PPl216gSpUZh0ap24mKmMDfcKp1N4mEdsxz4oseOrPYeFsHHWJFJ6Aivv
# qn70KTeJpp5r+DxSqbeSy0mxIUOq/lAaUxgNSQVUX26t8r+fcikofKv23WHrtRV3
# t7rVTsB9YzrRaiikmz68K5HWdt9MqULxPQPo+ppZ0LRqkOae466+UKRY0JxWtdrM
# c5vHlHZfnqjawj/RsM2S6Q6fa9T9CnY1Nz7DYBG3yZJyCPFsrgU05s9ljqfsSptp
# FdUh9R4ce+L71SWDLM2x/1MFLLHAMbXsEp8KloEGtaDULnxtfS2tYhfuKGqRXoEf
# DPAMnIdTvQPh3GHQ4SjkkBARHL0MY75alhGTKHWjC2aLVOo8obKIBk8hfnFDUf/E
# yVw4uTCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
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
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JENC00QjgwLTY5QzMxJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVACGlCa3ketyeuey7bJNpWkMuiCcQoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmkY8xMCIYDzIwMjIwODAx
# MDczMDU3WhgPMjAyMjA4MDIwNzMwNTdaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaRjzECAQAwBwIBAAICJRswBwIBAAICEXMwCgIFAOaS4LECAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQArnk4S9bEdxCdv6lvAqDJLnushxbjSdiB7sVOCFegm
# 1hIyiOlgngN4YIZy5wYXFTnbUcThdirf/aWO9Kgq7ym54onCUb8XY9R6vBbJz4h4
# 5T/wMIKNVGo2pIyBEGyYLgmsXSYP5pIvgzFhbGvfTynStAvFB//Ows/cSog4V5qO
# JTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABibS/hjCEHEuPAAEAAAGJMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIKUVSu8DYHqbqSkUGMa1
# KaUWYQqu4WtounqSAkmYvrQ+MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# ZndHMdxQV1VsbpWHOTHqWEycvcRJm7cY69l/UmT8j0UwgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYm0v4YwhBxLjwABAAABiTAiBCAk
# t45JlrVvo3nFtAGQW8QKtuen+cccumsnztg/aYVKETANBgkqhkiG9w0BAQsFAASC
# AgAlofhuyJigpjCDrW41ElzY+YdQPStyDJJpYVXSmOsWQTV59gxjTnr6jSl51FGn
# yQ1aJ/UjecnvFVjT/ROR8brNDyfGGp0lvM6U3XoFcVE2IuyXcbWG00YE33+oxPWx
# GJGTPnPRv4mvBRRRu/JO6Jf3TfiBGvvuOp2V0tTljRXNwW3OTQscOOsY6Fn2eGO7
# m6HF+uWhNLHW0D2+uNuvfLqn24fRb3c08zt/tLW/QYc5gceV4e7joaPbEHZevxDs
# +BFsuTzyZIUQb1YKSRcaKaug+NcgynFNxI62wHJQzXDUThAahY9VeFqZ0PO0b2hl
# 9B4VKMofWmqD/YK9M1OsWCuAcKmeWx7rn9daPeSOU4lh3fNj+M+b5oqp2SaeACPK
# bNVcVlzSLFDwhoqZG4eTxvGAKhDOO48LSht8jBqwfKc+l62uY5EVXRy28wdFZoSX
# wGCBWfdsOTyrojz7x1wZRSQT9x/dc/ssOckbf4EtDKc+xootQzN5ylcyQjj751kH
# y0Efs7uUOln+6qA3jEpJz8sdRX/gpoeUxZ4+hffJReW1ZZjyammE12b4iGTyf+ZY
# lGstS3B3rvhchcuxmHpRzjBEKJ2oAlpFoYw+ugGpfJbiv+PA7DNtadUsLzIO7ee5
# KFMpaG4a43EP7R6jX70U2Q+Iqw6/zANm2mVg4wRY4nKW0w==
# SIG # End signature block
