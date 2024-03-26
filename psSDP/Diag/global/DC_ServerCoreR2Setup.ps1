Import-LocalizedData -BindingVariable Strings

Function GetWin32OSFromRemoteSystem([string] $MachineName){
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("[GetWin32OSFromRemoteSystem] Error contacting " + $MachineName)
		continue
	}
	
	#Obtain OS From Remote Machine and return the WMI class.
	#If error communicating, return the exeption error code instead of WMI class
	$Error.Clear()	
	$OS = Get-CimInstance -Class Win32_OperatingSystem -ComputerName $MachineName
	
	if ($Error.Count -gt 0)	{
		Return $Error[0].Exception.ErrorCode
	} 
	else {
		return $OS
	}
}

trap [Exception] 
{
	WriteTo-ErrorDebugReport -ErrorRecord $_
	continue
}

do{
	do{
		#_#$RemoteServerCore = get-diaginput -id "BrowseServerCore"
		$RemoteServerCore = Read-Host 'please supply Remote-Server-Name: ' #_#
	} while (($RemoteServerCore[0] -eq 0) -or ($null -eq $RemoteServerCore[0]))

	$Error.Clear()

	#_#$RemoteServerCore = $RemoteServerCore[0].ToUpper()
	$RemoteServerCore = $RemoteServerCore.ToUpper() #_#

	Write-DiagProgress -Activity ($Strings.ID_EPSConnectingTo -replace("%MACHINE%", $RemoteServerCore)) -Status $Strings.ID_EPSConnectingToDesc

	$RemoteMachineOS = GetWin32OSFromRemoteSystem $RemoteServerCore
	
	if ($RemoteMachineOS -isnot [wmi]){
		if ($Error[0].Exception.ErrorCode -eq -2147023174){ #The RPC server is unavailable. (Exception from HRESULT: 0x800706BA)
			get-diaginput -id "ErrorContactingServerCore" -Parameter @{"Machine"=$RemoteServerCore; "Error"=$Strings.ID_EPSConnectingRCPError}
		} 
		else{
			get-diaginput -id "ErrorContactingServerCore" -Parameter @{"Machine"=$RemoteServerCore; "Error"= $Error[0].Exception.Message}
		}
		$Error.Clear()
	}
	else{
		$Error.Clear()
		if ($RemoteMachineOS.BuildNumber -gt 7000){
			$Error.Clear()
			
			#Now connect to machine to see if it is a Cluster
			$RemoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $RemoteServerCore)
	
			if ($Error.Count -eq 0){
				$RemoteNodesKey = $RemoteReg.OpenSubKey("Cluster\Nodes")
				
				if ($RemoteNodesKey.SubKeyCount -gt 0){
					$ClusterName = $RemoteReg.OpenSubKey("Cluster", $false).GetValue("ClusterName").ToUpper()
					
					$Choices = @()
					
					foreach ($SubKey in $RemoteNodesKey.GetSubKeyNames()){
						$NodeMachineName = $RemoteReg.OpenSubKey("Cluster\Nodes\$SubKey", $false).GetValue("NodeName").ToUpper()
						
						if ($NodeMachineName -ne $RemoteServerCore){
							$ExtensionPoint = ""
						} else {
							#Set the machine indicated by customer the default
							$ExtensionPoint = "<Default/>"
						}

						$Choices += @{"Name"=$NodeMachineName;"Value"=$NodeMachineName;"Description"=$NodeMachineName;"ExtensionPoint"=$ExtensionPoint}
					}

					$TroubleshootingNodeNames = @()
					if ($Choices.Count -gt 0){
						do{
							$TroubleshootingNodeNames = Get-DiagInput -Id SelectServerCoreClusterNodes -Parameter @{"Cluster"=$ClusterName; "Machine"=$RemoteServerCore} -Choice $Choices
							
						} while ($TroubleshootingNodeNames.Count -eq 0)

						if (($TroubleshootingNodeNames[0] -ne 0) -and ($TroubleshootingNodeNames.Count -ne 0)){
							if ($TroubleshootingNodeNames -contains "All"){
								foreach ($MachinName in $ClusterValues){
									$MachineNames = $MachinName.Value
								}
							}
							else {
								$MachineNames = $TroubleshootingNodeNames
							}
							Return $MachineNames
						}
					}
					else {
						get-diaginput -id "ErrorContactingServerCore" -Parameter @{"Machine"=$NodeName; "Error"=$Strings.ID_EPSSelectNodesUnableObtainNames}
					}
				}
				else{
					#Machine is not a cluster node
					return $RemoteServerCore
				}
			}
			else{
				get-diaginput -id "ErrorContactingServerCore" -Parameter @{"Machine"=$RemoteServerCore; "Error"= $Error[0].Exception.Message}
			}
		}
		else{
			get-diaginput -id "ErrorContactingServerCore" -Parameter @{"Machine"=$RemoteServerCore; "Error"=$Strings.ID_EPSSelectNodesNotSupported.Replace("%Machine%",$NodeName).Replace("%OSName%",$RemoteMachineOS.Caption)}
		}
	}
} while ($true)


# SIG # Begin signature block
# MIInoQYJKoZIhvcNAQcCoIInkjCCJ44CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAkIFfR+Sh8KSE7
# WgFs1kTMAFPBmHxF8BgSyyF+3KjxNqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJACwRYlrKjRkNLhsK0izH71
# prDbJqjQDOgNwPafphaiMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCQxt1GqxWTwIT0AbMo4xn+mO477EicQ61XL1GTM5bu34EJ9jHDubIW
# ok7YNNISG8LOqivdt85NRIHe7KFlZclqiR2n4/bcSK9qJNANX4lLQICFP+NazVSd
# 6c8yAg8rP1WV3+4pMGVBWKCoUp9tLpnMy9EE6VPobgPdPm8Tkbmf/S8J+75MKfid
# X0c43QtjzOb00ado/tdSY3h95w4ROOyX6OZZTcXhBcIUnxUDK1jg6eOl9fdgakJa
# mAsQIf4nPeTstMjk3Fr1FLm3iGqrZyM6DXEqCTx5ML/lzSoE3OqD0Pzg9I2QiSyH
# LJRUAmCBHLG0BJhKsPpivFMCj/rfkgp5oYIXCTCCFwUGCisGAQQBgjcDAwExghb1
# MIIW8QYJKoZIhvcNAQcCoIIW4jCCFt4CAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIJoN048GZTRpsOH8PIWsPM8eVJOSfXXy9VS0J/vGsYxBAgZjKakU
# QogYEzIwMjIwOTI3MDY1MDE2LjE4M1owBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpD
# NEJELUUzN0YtNUZGQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaCCEVwwggcQMIIE+KADAgECAhMzAAABo/uas457hkNPAAEAAAGjMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMDMw
# MjE4NTExNloXDTIzMDUxMTE4NTExNlowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpDNEJELUUzN0YtNUZG
# QzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAO+9TcrLeyoKcCqLbNtz7Nt2JbP1TEzz
# Mhi84gS6YLI7CF6dVSA5I1bFCHcw6ZF2eF8Qiaf0o2XSXf/jp5sgmUYtMbGi4neA
# tWSNK5yht4iyQhBxn0TIQqF+NisiBxW+ehMYWEbFI+7cSdX/dWw+/Y8/Mu9uq3XC
# K5P2G+ZibVwOVH95+IiTGnmocxWgds0qlBpa1rYg3bl8XVe5L2qTUmJBvnQpx2bU
# ru70lt2/HoU5bBbLKAhCPpxy4nmsrdOR3Gv4UbfAmtpQntP758NRPhg1bACH06Fl
# vbIyP8/uRs3x2323daaGpJQYQoZpABg62rFDTJ4+e06tt+xbfvp8M9lo8a1agfxZ
# Q1pIT1VnJdaO98gWMiMW65deFUiUR+WngQVfv2gLsv6o7+Ocpzy6RHZIm6WEGZ9L
# Bt571NfCsx5z0Ilvr6SzN0QbaWJTLIWbXwbUVKYebrXEVFMyhuVGQHesZB+VwV38
# 6hYonMxs0jvM8GpOcx0xLyym42XA99VSpsuivTJg4o8a1ACJbTBVFoEA3VrFSYzO
# dQ6vzXxrxw6i/T138m+XF+yKtAEnhp+UeAMhlw7jP99EAlgGUl0KkcBjTYTz+jEy
# PgKadrU1of5oFi/q9YDlrVv9H4JsVe8GHMOkPTNoB4028j88OEe426BsfcXLki0p
# hPp7irW0AbRdAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUUFH7szwmCLHPTS9Bo2ir
# LnJji6owHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgw
# VjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWlj
# cm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUF
# BwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
# KS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQsFAAOCAgEAWvLep2mXw6iuBxGu0PsstmXI5gLmgPkTKQnjgZlsoeipsta9
# oku0MTVxlHVdcdBbFcVHMLRRkUFIkfKnaclyl5eyj03weD6b/pUfFyDZB8AZpGUX
# hTYLNR8PepM6yD6g+0E1nH0MhOGoE6XFufkbn6eIdNTGuWwBeEr2DNiGhDGlwaUH
# 5ELz3htuyMyWKAgYF28C4iyyhYdvlG9VN6JnC4mc/EIt50BCHp8ZQAk7HC3ROltg
# 1gu5NjGaSVdisai5OJWf6e5sYQdDBNYKXJdiHei1N7K+L5s1vV+C6d3TsF9+ANpi
# oBDAOGnFSYt4P+utW11i37iLLLb926pCL4Ly++GU0wlzYfn7n22RyQmvD11oyiZH
# hmRssDBqsA+nvCVtfnH183Df5oBBVskzZcJTUjCxaagDK7AqB6QA3H7l/2SFeeqf
# X/Dtdle4B+vPV4lq1CCs0A1LB9lmzS0vxoRDusY80DQi10K3SfZK1hyyaj9a8pbZ
# G0BsBp2Nwc4xtODEeBTWoAzF9ko4V6d09uFFpJrLoV+e8cJU/hT3+SlW7dnr5dtY
# vziHTpZuuRv4KU6F3OQzNpHf7cBLpWKRXRjGYdVnAGb8NzW6wWTjZjMCNdCFG7pk
# KLMOGdqPDFdfk+EYE5RSG9yxS76cPfXqRKVtJZScIF64ejnXbFIs5bh8KwEwggdx
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
# Ex1UaGFsZXMgVFNTIEVTTjpDNEJELUUzN0YtNUZGQzElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAHl/pXkLMAbPa
# pCwa+GXc3SlDDROggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQUFAAIFAObcuQ4wIhgPMjAyMjA5MjcwMzQ5MzRaGA8yMDIy
# MDkyODAzNDkzNFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5ty5DgIBADAHAgEA
# AgIjFjAHAgEAAgIRNjAKAgUA5t4KjgIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUA
# A4GBAGybz11IbXYQA2tM6NkEb3oh3qs02JRxebKARhoKTunYTz+iEIGNaDI6Pf37
# XoGu1Pb2P2ku8DE3Fv7MvXu17z+BYzixqQsC12yGKxKqsD1Lth++iYKzUPxBCkQo
# x6y5mKOF2rBOfe92206+u+er5QCiiLRdcqaALiivljYiqUAWMYIEDTCCBAkCAQEw
# gZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGj+5qzjnuGQ08A
# AQAAAaMwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0B
# CRABBDAvBgkqhkiG9w0BCQQxIgQgeJxkCKKKX87bOLyZ/2k4B0n7IdbgaTeSxqr/
# 502cQQgwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCM+LiwBnHMMoOd/sgb
# aYxpwvEJlREZl/pTPklz6euN/jCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABo/uas457hkNPAAEAAAGjMCIEII9oe4OvT5nT8incWzoX
# BrUtl6YmCRH6SyGIYEcDkHOyMA0GCSqGSIb3DQEBCwUABIICAOayzPa1JxFZLk4G
# aav8XOUEmH/Iegw1NYpo5677i20dp4GeOaE06y0oghE/PNzE1uyE1Q5xwPkEfKyC
# zNTCNOYhdy7WEhmLlm9O67zZ2yjirdWXxaQijRQNWiq5amOoRJ8BxbSE50aah35i
# qvT/2xPMagyd8OQmASOiqyuiPi/5hBETY5dHW2Nw7nKT5h2nOetAnovFs9pchEGr
# rh41JkZGb7c9SC6eVmsW2TtL4Wt+8wkQOC+I2GC7GGgZpLzGABj+2JTNM+fqma7q
# Z7Z16zybs1XzZ7byLAoRpZZ/MOv8NNxCX3TEQcO44wDPHlkgLND4NsdrFdt6aqgg
# 28Na96zSMMqMJqMqCEsKgp2TGsCWjUqNnnqJbFYOIQYnUG84IXo+yWhaaP5ZxIdE
# RiPYEjFicI4MLAqCtnaw+00vRXFpJbNH+Fz0oyV3sZ0Cj2Q1e9yB4PwwogcnBzNi
# GGyIFqFRcB3phfvu5SH3WK+gbZns1pvN/Ms+4BoFjtVk0ffZWfbOV6GgXzuzGRSt
# HBfcom2uqBgyxWOh3QTQei7vTnJzPH18AVXukey+P4LMFjHNMihn9HuBP1pAMPm4
# qYwfZFtjBBzLLPomTwxaZGZTYFdY8UhCMdCS1sbVJp2trngAhPsu/yHXUD/QK1hm
# Rue1w2pKmA8PHOM4DJrZQ/yqEBq8
# SIG # End signature block
