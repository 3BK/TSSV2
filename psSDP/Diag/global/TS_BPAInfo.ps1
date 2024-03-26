#************************************************
# TS_BPAInfo.ps1
# Version 1.5.6
# Date: 12-10-2010 / 2019 WalterE
# Author: Andre Teixeira - andret@microsoft.com
# Description: - This script is used to obtain a report from any inbox BPA Module information or other BPAs with MBCA support.
#************************************************

Param ($BPAModelID = $null, $OutputFileName, $ReportTitle, $ModuleName="BestPractices", $InvokeCommand="Invoke-BpaModel", $GetBPAModelCommand="Get-BPAModel", $GetBPAResultCommand="Get-BpaResult")

# 2023-02-20 WalterE mod Trap #we#
Trap [Exception]
{
	WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "TS_BPAInfo.ps1 Error, ReportTitle: $ReportTitle, BPAModelID: $BPAModelID"
	WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; continue
	Write-Host "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_"
}

Function Write-ScriptProgress ($Activity = "", $Status = "") {
	if ($Activity -ne $LastActivity) {
		if (-not $TroubleShootingModuleLoaded -and ($Activity -ne "")) {
			$Activity | Out-Host
		}
		if ($Activity -ne "") {
			Set-variable -Name "LastActivity" -Value $Activity -Scope "global"
		}else{
			$Activity = $LastActivity
		}	
	}
	if ($TroubleShootingModuleLoaded) {
			Write-DiagProgress -activity $Activity -status $Status
		
	}else{
		"    [" + (Get-Date) + "] " + $Status | Out-Host
	}
}

Function SaveToHTMLFile($SourceXMLDoc, $HTMLFileName){
	$XMLFilename = $Env:TEMP + "\" + [System.IO.Path]::GetFileNameWithoutExtension($HTMLFileName) + ".XML"
	$SourceXMLDoc.Save($XMLFilename)
	[xml] $XSLContent = Get-Content 'BPAInfo.xsl'
	$XSLObject = New-Object System.Xml.Xsl.XslTransform
	$XSLObject.Load($XSLContent)
	$XSLObject.Transform($XMLFilename, $HTMLFilename)
	Remove-Item $XMLFilename
	"Output saved to $HTMLFilename" | WriteTo-StdOut -ShortFormat
}

Function AddXMLElement{
	Param ([xml] $xmlDoc,
		[string] $ElementName="Item", 
		[string] $Value,
		[string] $AttributeName="name", 
		[string] $attributeValue,
		[string] $xpath="/Root")

	[System.Xml.XmlElement] $rootElement=$xmlDoc.SelectNodes($xpath).Item(0)
	if ($null -ne $rootElement) { 
		[System.Xml.XmlElement] $element = $xmlDoc.CreateElement($ElementName)
		if ($attributeValue.Length -ne 0) {$element.SetAttribute($AttributeName, $attributeValue)}
		if ($Value.lenght -ne 0) { 
			if ($PowerShellV2) {
				$element.innerXML = $Value
			}else{
				$element.set_InnerXml($Value)
			}
		}
		$Null = $rootElement.AppendChild($element)
	}else{
		"Error. Path $xpath returned a null value. Current XML document: `n" + $xmlDoc.OuterXml
	}
}

#***********************************************
#*  Starts here
#***********************************************

if (($ModuleName -eq "BestPractices") -and ($InvokeCommand -eq "Invoke-BpaModel") -and ($OSVersion.Build -lt 7601)){
	"Inbox BPAs Not Supported on OS Build " + $OSVersion.Build | WriteTo-StdOut
}else{
	if (Test-Path (Join-Path $PWD.Path 'BPAInfo.xsl')){
		if ($null -ne $BPAModelID){
			Import-LocalizedData -BindingVariable BPAInfo

			if ((Get-CimInstance -Class Win32_ComputerSystem).DomainRole -gt 1){ #Server
				if ((Get-Host).Name -ne "Default Host"){
					#_# "Windows Troubleshooting Platform not loaded."
					#_# $TroubleshootingModuleLoaded = $false
					$TroubleshootingModuleLoaded = $true
				}else{
					$TroubleshootingModuleLoaded = $true
				}
				Write-ScriptProgress -activity $ReportTitle -status $BPAInfo.ID_BPAStarting
				$PowerShellV2 = (((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine").PowerShellVersion).Substring(0,1) -ge 2)
				$Error.Clear()
				Import-Module $ModuleName
				if ($Error.Count -eq 0){
					$InstalledBPAs = Invoke-Expression "$GetBPAModelCommand"
					if ($null -ne (($InstalledBPAs | where-object {$_.Id -eq $BPAModelID}).Id)){
						Write-ScriptProgress -activity $ReportTitle -status $BPAInfo.ID_BPARunning	
						$BPAResults = Invoke-Expression "$InvokeCommand $BPAModelID"
						if ($null -ne ($BPAResults | where-object {($_.ModelID -eq $BPAModelID) -and ($_.Success -eq $true)})){
							Write-ScriptProgress -activity $ReportTitle -status $BPAInfo.ID_BPAGenerating	
							$BPAXMLDoc = Invoke-Expression "$GetBPAResultCommand $BPAModelID | ConvertTo-XML"
							if ($null -ne $BPAXMLDoc){
								AddXMLElement -xmlDoc $BPAXMLDoc -ElementName "Machine" -Value $Env:COMPUTERNAME -xpath "/Objects"
								AddXMLElement -xmlDoc $BPAXMLDoc -ElementName "TimeField" -Value ($BPAResults[0].Detail).ScanTime -xpath "/Objects"
								AddXMLElement -xmlDoc $BPAXMLDoc -ElementName "ModelId" -Value ($BPAResults[0].Detail).ModelId -xpath "/Objects"
								AddXMLElement -xmlDoc $BPAXMLDoc -ElementName "ReportTitle" -Value $ReportTitle -xpath "/Objects"
								AddXMLElement -xmlDoc $BPAXMLDoc -ElementName "OutputFileName" -Value $OutputFileName -xpath "/Objects"
								SaveToHTMLFile -HTMLFileName $OutputFileName -SourceXMLDoc $BPAXMLDoc
								if ($TroubleshootingModuleLoaded){
									CollectFiles -filesToCollect $OutputFileName -fileDescription $ReportTitle -sectionDescription "Best Practices Analyzer reports"
									$XMLName = [System.IO.Path]::GetFileNameWithoutExtension($OutputFileName) + ".xml"
									$BPAXMLDoc.Save($XMLName)
									CollectFiles -filesToCollect $XMLName -fileDescription $ReportTitle -sectionDescription "Best Practices Analyzer RAW XML Files" -Verbosity "Debug"
									if ($BPAXMLDoc.SelectNodes("(//Object[(Property[@Name=`'Severity`'] = `'Warning`') or (Property[@Name=`'Severity`'] = `'Error`')])").Count -ne 0){
										$BPAXMLFile = [System.IO.Path]::GetFullPath($PWD.Path + ("\..\BPAResults.XML"))
										if (Test-Path $BPAXMLFile){
											[xml] $ExistingBPAXMLDoc = Get-Content $BPAXMLFile
											AddXMLElement -xmlDoc $ExistingBPAXMLDoc -xpath "/Root" -ElementName "BPAModel" -Value $BPAXMLDoc.SelectNodes("/Objects").Item(0).InnerXML
											$ExistingBPAXMLDoc.Save($BPAXMLFile)
										}else{
											[xml] $BPAFileXMLDoc = "<Root/>"
											AddXMLElement  -xmlDoc $BPAFileXMLDoc -xpath "/Root" -ElementName "BPAModel" -Value $BPAXMLDoc.SelectNodes("/Objects").Item(0).InnerXML
											$BPAFileXMLDoc.Save($BPAXMLFile)
										}
										Update-DiagRootCause -id RC_BPAInfo -Detected $true
									}
								}
								Write-ScriptProgress -activity $ReportTitle -status "Completed."
							}else{
								"$GetBPAResultCommand did not return any result" | WriteTo-StdOut -ShortFormat
							}
						}
					}else{
						$Msg = "ERROR: BPA Module $BPAModelID is not installed. Follow the list of installed BPAs: `r`n"
						foreach ($BPA in $InstalledBPAs){
							$Msg += "   " + $BPA.Id + "`r`n"
						}
						$Msg | WriteTo-StdOut -ShortFormat
					}
				}else{
					"ERROR: Unable to load BestPractices module - $ModuleName"  | WriteTo-StdOut -ShortFormat
				}
			}
		}else{
			"ERROR: BPAModelID was not specified. BPAInfo not executed"  | WriteTo-StdOut -ShortFormat
		}
	}else{
		"ERROR: BPAInfo.xsl not found. Make sure to use <Folder source> instead of <File source>" | WriteTo-StdOut -IsError
		"ERROR: BPAInfo.xsl not found. Make sure to use <Folder source> instead of <File source>" | WriteTo-ErrorDebugReport
	}
}


# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCAcT9tTMCYsJXV
# 6EvmHmOZct55XFIrPJfIV21MGn07eKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXUwghlxAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKYs2UOoYleuuaybrbSrCcH7
# IoxEW7ocRtNzhEBs9bqgMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQApfvgXXigM5rfFPPljKZr5929R2TtVd4qwfooZHhCBEXuMdKWSgfkU
# EzwDfLTEz9LY6jaXjgSlJX8zVywYMqoFJABHhVlS/c1EGvS0/iIdqPEIDF26bfFQ
# N3slu2ewbJuPdusvTHL4eGE6a5HZ8G/uPjbriPXrsw4zaDU+nxsCgaITxP2H12GX
# aWEG2YIpnvvaoet4Ak1G/NmO0D9lWWfKhJEaGJp5o6f28qtH6jdakNWum/V76aRF
# EQt8P5sby7WQL4oBXzTBW4/8SSPi9EDAD3Pxv1w7VHJ1KvfTT5PCnq8SmcPCpmmC
# cnECVsd9Ne8AWsIgBt9vbxFtdHezM/97oYIW/TCCFvkGCisGAQQBgjcDAwExghbp
# MIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIDpKkGiJ8LPkqmSTjJ1Ugl/2XrUjd/HgR+eGqvPx2mhRAgZj7hU3
# XRkYEzIwMjMwMjIwMTUwNTE1Ljc3OFowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkREOEMt
# RTMzNy0yRkFFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVDCCBwwwggT0oAMCAQICEzMAAAHFA83NIaH07zkAAQAAAcUwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkw
# MTMyWhcNMjQwMjAyMTkwMTMyWjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046REQ4Qy1FMzM3LTJGQUUxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCrSF2zvR5fbcnulqmlopdGHP5NPsknc69V/f43x82n
# FGzmNjiES/cFX/DkRZdtl07ibfGPTWVMj/EOSr7K2O6I97zEZexnEOe2/svUTMx3
# mMhKon55i7ySBXTnqaqzx0GjnnFk889zF/m7X3OfThoxAXk9dX8LhktKMVr0gU1y
# uJt06beUZbWtBEVraNSy6nqC/rfirlTAfT1YYa7TPz1Fu1vIznm+YGBZXx53ptkJ
# mtyhgiMwvwVFO8aXOeqboe3Bl1czAodPdr+QtRI+IYCysiATPPs2kGl46yCz1OvD
# JZNkE1sHDIgAKZDfiP65Hh63aFmT40fj0qEQnJgPb504hoMYHYRQ0VJhzLUySC1m
# 3V5GoEHSb5g9jPseOhw/KQpg1BntO/7OCU598KJrHWM5vS7ohgLlfUmvwDBNyxoP
# K7eoCHHxwVA30MOCJVnD5REVnyjKgOTqwhXWfHnNkvL6E21qR49f1LtjyfWpZ8CO
# hc8TorT91tPDzsQ4kv8GUkZwqgVPK2vTM+D8w0lJvp/Zr/AORegYIZYmJCsZPGM4
# /5H3r+cggbTl4TUumTLYU51gw8HgOFbu0F1lq616lNO5KGaCf4YoRHwCgDWBJKTU
# QLllfhymlWeAmluUwG7yv+0KF8dV1e+JjqENKEfBAKZmpl5uBJgeceXi6sT7grpk
# LwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFFTquzi/WbE1gb+u2kvCtXB6TQVrMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAIyo3nx+swc5JxyIr4J2evp0rx9OyBAN5n1u9CMK7E0glkn3b7Gl4pEJ/der
# jup1HKSQpSdkLp0eEvC3V+HDKLL8t91VD3J/WFhn9GlNL7PSGdqgr4/8gMCJQ2bf
# Y1cuEMG7Q/hJv+4JXiM641RyYmGmkFCBBWEXH/nsliTUsJ2Mh57/8atx9uRC2Jih
# v05r3cNKNuwPWOpqJwSeRyVQ3+YSb1mycKcDX785AOn/xDhw98f3gszgnpfQ200F
# 5XLC9YfTC4xo4nMeAMsJ4lSQUT0cTywENV52aPrM8kAj7ujMuNirDuLhEVuJK19Z
# lIaPC36UslBlFZQJxPdodi9OjVhYNmySiFaDvvD18XZBuI70N+eqhntCjMeLtGI+
# luOCQkwCGuGl5N/9q3Z734diQo5tSaA8CsfVaOK/CbV3s9haxqsvu7mpm6TfoZvW
# YRNLWgDZdff4LeuC3NGiE/z2plV/v2VW+OaDfg20gIr+kyT31IG62CG2KkVIxB1t
# dSdLah4u31wq6/Uwm76AnzepdM2RDZCqHG01G9sT1CqaolDDlVb/hJnN7Wk9fHI5
# M7nIOr6JEhS5up5DOZRwKSLI24IsdaHw4sIjmYg4LWIu1UN/aXD15auinC7lIMm1
# P9nCohTWpvZT42OQ1yPWFs4MFEQtpNNZ33VEmJQj2dwmQaD+MIIHcTCCBVmgAwIB
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
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAsswggI0AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjpERDhDLUUzMzctMkZBRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAIQAa9hdkkrtxSjrb4u8RhATHv+eg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOed2W8wIhgPMjAyMzAyMjAxOTM1MTFaGA8yMDIzMDIyMTE5MzUxMVow
# dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA553ZbwIBADAHAgEAAgIVpjAHAgEAAgIR
# TzAKAgUA558q7wIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBANGwA53yv/tF
# DKALBRzPPuDbjKGUAIeTbg1nkAhc7r0Ou1At3JVyAiHrBnc61gP/sw69ryMTu88x
# TfhbIZtZhMqD4aZCDnTdWchBWrDVEBPLeYLgtlslJ0Tfk2/TJM/e2vnosga5XQT8
# VqlqNQb2IK3jLxcGN+AGhvpB1b3i3YcUMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHFA83NIaH07zkAAQAAAcUwDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQg95fZjp/I+NSNPy1keDCpC+m1M3wTkQ9q/w8OKd2BcVUwgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAZAbGR9iR3TAr5XT3A7Sw76ybyAAzKPkS4
# o+q81D98sTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABxQPNzSGh9O85AAEAAAHFMCIEIIUbJX7a5vorpF0lHoTR02vVVCEdAW33PVLF
# VaJhuFtWMA0GCSqGSIb3DQEBCwUABIICAIaYEbdEVs22nZ9ouDdG5nRFWq1JbHWG
# 7USPnlaY9iuNfj+khuR/Dl86bJqzk83GPe+jfoUyZoXOHu9QbuA5vASQbmUdM5A6
# oXsJc7DRU9IS1qskV+Gx/QLwFIa0DaFwVrz48g/XJ+5nefzj4vME7D2I/rBzPyHN
# 4WVc5s2PVqdlm9Gjd4rbkHFfuC96tfle+9KQNkRvAik2oNGgjRMoBL/rVMrtDnNp
# Ux3fNQeMSCwyP2U4Rxl5PhFyDaEnTrPaB0Q85aAMxvw5GUoUvY+2X7XqoFd1vgmb
# F1oExOl3jeDZzFHXhl+RTgT297X9D1BP9bzzMhdLVZraAJ+oFBFlnzlSS3888n8c
# TOuzjUeVcnmP06vC+pNqIRvy1dEVpgYncC8qqFZR15DzhZ+w7PmPmxEyVsyyVCtL
# OTDmR5mwPFLGfLEdwo1w4LjoSLDBY2/CptUduYcJTDdQ3FFH8A/oQAex3ODfhwYj
# YYTPzVQHzPqGPFIxGEm8mNAxefjHtyepMbzebgpTfVewWtWDpfGcvoZ9bhqJ8NdA
# cgTusS4EeYF/TButPo97HvgUOZFmiDY3HLHaO6SrMaVPPd/22HykUywLkAeNC9/j
# 9/itK9S5BEpxzmFEHDticyJkNynfq6l5cyekm2QBPpixVedwop/pnrDuHZeGf4yy
# paxL4TQiF0wk
# SIG # End signature block
