# Rule ID 4628
# ---------
#    http://sharepoint/sites/rules/Rule%20Submissions/Dynamics-CRM_ehagen_2012-06-11-03-02-42.xml
#	
# Description: This checks to see if the data types on each CRM registry key is correct.
#
# Related KB
#-----------
# Script Author:  jrandall
#


PARAM($RegistryPath=$null)

#region function
function Get-MSCRMRegistryKeys{
	param ([string] $RegKeyPath)
		trap [Exception]{
			WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; 
		}
	$RegInfoObjs = @()
	if (Test-Path $RegKeyPath){
		$MSCRMKey = Get-Item $RegKeyPath
		if ($MSCRMKey -ne $null){
			$regInfo = GetRegistryProperties $MSCRMKey
		}
		$RegInfoObjs += $regInfo
		

		#Handle the subkeys
		$childItems = Get-ChildItem -Path $MSCRMKey.PSPath -Recurse 
		foreach ($item in $childItems){
			if ($item.ValueCount -gt 0){
				$childRegInfo = GetRegistryProperties $item	
				
			}
			$RegInfoObjs += $childRegInfo
		}
		
		#finally return the collection
		return $RegInfoObjs
		
	}
}
function GetRegistryDataType([string] $type){
		switch ($type){
			"Binary" {return "REG_BINARY"}
			"Dword" {return "REG_DWORD"}
			"String" {return "REG_SZ"}
			"Qword" {return "REG_QWORD"}
			"ExpandString" {return "REG_EXPAND_SZ"}
			"MultiString" {return "REG_MULTI_SZ"}
			default {return $type}
		}
}
function GetRegistryProperties{
	param ([Object]$key	)
	
	$PropertiesCollected=@()	
	$valueNames = $key.GetValueNames()
	foreach ($valueName in $valueNames){
	    $RegistryValueObj = new-object PSObject
		$RegistryValueObj | add-member -membertype noteproperty -name "Name" -value $valueName
		$RegistryValueObj | Add-Member -MemberType NoteProperty -Name "DataType" -Value (GetRegistryDataType $key.GetValueKind($valueName).ToString())
		$RegistryValueObj | Add-Member -MemberType NoteProperty -Name "Value" -Value $key.GetValue($valueName)
		$PropertiesCollected += $RegistryValueObj
	}
	return $PropertiesCollected
}
function ValidateDataTypes{
	param([Object] $registryObjectCollection,
	[Object] $InformationCollected)
	
	trap [Exception]{
		WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; 
	}
	$detectedObjs = @()
	$detectedObjs = $registryObjectCollection | Where-Object {($_.DataType -ne "REG_DWORD") -and ($_.DataType -ne "REG_SZ") -and ($_ -ne $null)}
	if ($detectedObjs -ne $null -or $detectedObjs.Count -gt 0){
	  #found issues, loop through and add them to the Information Collected object
	  foreach ($detectedObj in $detectedObjs){
	  	$InformationCollected | add-member -membertype noteproperty -name "The Microsoft CRM Registry Key $($detectedObj.Name) has an incorrect Data Type :" -value "Current Data Type is $($detectedObj.DataType)"
	  }
	  return $true
	}else{
	  return $false
	}
}	
#endregion function

Import-LocalizedData -BindingVariable LocalizedMessages 
Write-DiagProgress -Activity $LocalizedMessages.PROGRESSBAR_ID_REGISTRYDATATYPECHECK -Status $LocalizedMessages.PROGRESSBAR_ID_REGISTRYDATATYPECHECKDesc
"--> Entered TS_REGISTRYDATATYPECHECK.ps1" | WriteTo-StdOut
$Error.Clear()
$RootCauseDetected = $false
$RuleApplicable = $true
$RootCauseName = "RC_REGISTRYDATATYPEINCORRECT"
$InternalContent = "https://vkbexternal.partners.extranet.microsoft.com/VKBWebService/ViewContent.aspx?scid=MSS;EN-US;113012110154455"
$PublicContentURL=""
$SolutionTitle="The data type on one or more the Microsoft Dynamics CRM Registry Keys is incorrect"
$Verbosity = "Error"
$Visibility = "3"
$SupportTopicsID = "11953"
$InformationCollected = new-object PSObject
$arrRegInfoObjs = Get-MSCRMRegistryKeys -RegKeyPath $RegistryPath
$RootCauseDetected = ValidateDataTypes $arrRegInfoObjs $InformationCollected
if ($RootCauseDetected){
		# Red/ Yellow Light
		Update-DiagRootCause -Id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -Verbosity $Verbosity -SolutionTitle $SolutionTitle -PublicContentURL $PublicContentURL -SupportTopicsID $SupportTopicsID -InformationCollected $InformationCollected
}else{
		# Green Light
		Update-DiagRootCause -Id $RootCauseName -Detected $false
}
"<-- Exited TS_REGISTRYDATATYPECHECK.ps1" | WriteTo-StdOut



# SIG # Begin signature block
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBVaIQBtDQv8wK9
# pxWD95UygAKfna/qfCfUZ5+WhZgEnaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXMwghlvAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPz5gJAgc8WjgNIBgV81TXwq
# caYCh/poAaQZBq8iix1uMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQB4eANAF4eE6N846hFzMEwnMawJ8fe6pV6ToY73s5Fu1iczbReXIVc9
# 8+ocjIxFSBTXopVToV8MRmNZNb1GzArzpRrxDeZdsR1nVKgpw9TskYJEWqwZCrsv
# wyJIhZbnFufa9kEjJK0Nj00dX2j+ViuX0OwzhshQJcAbPZImoPt9lO03RRZA9kT4
# V8zccOghH5IYAhuRTx6wO3YKhcHXsCk7rmsmTz18AHFrpDNJON+rhQu0hjc0FPmM
# YVKzb6FFrF8JyJYHLv0Aa/iOZSBbDJaTaOJ5xE3yUQeriFmrb1kvI7vw5egdJh/P
# AGNAgMUxjV0GQFNSuLzIA8Re7x0FWwChoYIW+zCCFvcGCisGAQQBgjcDAwExghbn
# MIIW4wYJKoZIhvcNAQcCoIIW1DCCFtACAQMxDzANBglghkgBZQMEAgEFADCCAU8G
# CyqGSIb3DQEJEAEEoIIBPgSCATowggE2AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIOVh5dQ7YJrTFiER3ZUrDoLZx5eEiiSmrI+Wz6tu2iUjAgZj7imN
# rWwYETIwMjMwMjI3MDkyMTMyLjhaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpENkJELUUz
# RTctMTY4NTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVQwggcMMIIE9KADAgECAhMzAAABx/sAoEpb8ifcAAEAAAHHMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEz
# NVoXDTI0MDIwMjE5MDEzNVowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQ2QkQtRTNFNy0xNjg1MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAr0LcVtnatNFMBrQTtG9P8ISAPyyGmxNfhEzaOVlt088p
# BUFAIasmN/eOijE6Ucaf3c2bVnN/02ih0smSqYkm5P3ZwU7ZW202b6cPDJjXcrjJ
# j0qfnuccBtE3WU0vZ8CiQD7qrKxeF8YBNcS+PVtvsqhd5YW6AwhWqhjw1mYuLetF
# 5b6aPif/3RzlyqG3SV7QPiSJends7gG435Rsy1HJ4XnqztOJR41I0j3EQ05JMF5Q
# NRi7kT6vXTT+MHVj27FVQ7bef/U+2EAbFj2X2AOWbvglYaYnM3m/I/OWDHUgGw8K
# IdsDh3W1eusnF2D7oenGgtahs+S1G5Uolf5ESg/9Z+38rhQwLgokY5k6p8k5arYW
# tszdJK6JiIRl843H74k7+QqlT2LbAQPq8ivQv0gdclW2aJun1KrW+v52R3vAHCOt
# bUmxvD1eNGHqGqLagtlq9UFXKXuXnqXJqruCYmfwdFMD0UP6ii1lFdeKL87PdjdA
# wyCiVcCEoLnvDzyvjNjxtkTdz6R4yF1N/X4PSQH4FlgslyBIXggaSlPtvPuxAtua
# c/ITj4k0IRShGiYLBM2Dw6oesLOoxe07OUPO+qXXOcJMVHhE0MlhhnxfN2B1JWFP
# WwQ6ooWiqAOQDqzcDx+79shxA1Cx0K70eOBplMog27gYoLpBv7nRz4tHqoTyvA0C
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBQFUNLdHD7BAF/VU/X/eEHLiUSSIDAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQDQy5c8ogP0y8xAsLVca07wWy1mT+nqYgAFnz2972kNO+KJ7AE4f+SVbvOnkeeu
# OPq3xc+6TS8g3FuKKYEwYqvnRHxX58tjlscZsZeKnu7fGNUlpNT9bOQFHWALURuo
# Xp8TLHhxj3PEq9jzFYBP2YNMLol70ojY1qpze3nMMJfpdurdBBpaOLlJmRNTLhxd
# +RJGJQbY1XAcx6p/FigwqBasSDUxp+0yFPEBB9uBE3KILAtq6fczGp4EMeon6Ymk
# yCGAtXMKDFQQgdP/ITe7VghAVbPTVlP3hY1dFgc+t8YK2obFSFVKslkASATDHulC
# Mht+WrIsukclEUP9DaMmpq7S0RLODMicI6PtqqGOhdnaRltA0d+Wf+0tPt9SUVtr
# PJyO7WMPKbykCRXzmHK06zr0kn1YiUYNXCsOgaHF5ImO2ZwQ54UE1I55jjUdldyj
# y/UPJgxRm9NyXeO7adYr8K8f6Q2nPF0vWqFG7ewwaAl5ClKerzshfhB8zujVR0d1
# Ra7Z01lnXYhWuPqVZayFl7JHr6i6huhpU6BQ6/VgY0cBiksX4mNM+ISY81T1RYt7
# fWATNu/zkjINczipzbfg5S+3fCAo8gVB6+6A5L0vBg39dsFITv6MWJuQ8ZZy7fwl
# FBZE4d5IFbRudakNwKGdyLGM2otaNq7wm3ku7x41UGAmkDCCB3EwggVZoAMCAQIC
# EzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoX
# DTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC
# 0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VG
# Iwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP
# 2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/P
# XfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361
# VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwB
# Sru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9
# X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269e
# wvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDw
# wvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr
# 9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+e
# FnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAj
# BgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+n
# FV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBH
# hkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
# BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4Swf
# ZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTC
# j/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu
# 2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/
# GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3D
# YXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbO
# xnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqO
# Cb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I
# 6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0
# zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaM
# mdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNT
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLLMIICNAIBATCB+KGB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RDZCRC1FM0U3LTE2ODUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAOIASP0JSbv5R23wxciQivHyckYooIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDnpn8OMCIYDzIwMjMwMjI3MDg1OTU4WhgPMjAyMzAyMjgwODU5NThaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOemfw4CAQAwBwIBAAICBHQwBwIBAAICEUow
# CgIFAOen0I4CAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQBFU+INno6OsaaG
# 9rlMiHiJuOHG088J8OAlQpuo9iR1nWBrn+RixNqqhXMokS8AtR6SsuEzBeNMvxad
# KoZP1tAjH4RFRzf3eJ6Dcv+wTiw2mNy11ePHrqnVnb4b4xejKHXENnmGzhN+FgFe
# XrRg9e88mXlX8SRI3191aY0RWpX8MDGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABx/sAoEpb8ifcAAEAAAHHMA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIDVL32ruiX0SMCNMCILIiN1HmX8QeFVCt5RtHGb1tgJeMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQgR+fl2+JSskULOeVYLbeMgk7HdIbREmAsjwtc
# y6MJkskwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# Acf7AKBKW/In3AABAAABxzAiBCDz00qNYleF7Ux/r/PTwlNn5eO9vUWYZnO7EDwP
# +DGjyzANBgkqhkiG9w0BAQsFAASCAgB04Rks1W6iFdLAzWeK8qco34JcudpbWyYv
# rLzkkI50uCdJzTDWYUGQ2Fa6GfseW7Q2LsE0CHCZfMToOnptj+ZxoItf69FBlI9W
# RiboKHuocnUnsyOkDKuqhGbqrF8VE86SIRXN0GtuzzZt3yE3NIiTX3Pmrxh/xiko
# dG5v/3qbXJposQLlaki4ASYZMZGc9lV/GqVsIMwfdWDIl3bTvtTfQQzdb/vrhpm6
# DYdgyOrESQogxbmmNQIDQoH0HdfwYlO4GBUG150IJHaxcqC8w6MbBNp9Gs1HIjo6
# 15ugi2LnU3VApnKV+gpwDD978ILElUvYFx7sGtIslb5MToNZYc9J979x+pPbbzNC
# rQaaPgXiWNWpGYjx4LYVZj+73UYXPVhqkmav3a9+7BHIcPa2RVQLNhDeVMJbtuFD
# 1dBOaUp0HPxSD88ltq3d0bX3Qs1yES5mRp7sO1yJaOQOwUkWGcdRxt0ZKuGoiP3p
# zoQou0e2jt6VAHlK1tg8LU0T0kM16Dg45ngCHP49No+9LDuDeSNz+zglMZz0Kf7u
# VGEuzguSs5oTUsN8DZdO/G9aNptyV31H/6dUfhVhLVfrq3HBWDiyi6zj4hd0BnIr
# dBk4DSSClz2zZPdui+BVyzA8PrpxuHscxtYJ//+mLBEc5jQD+jE+jT4hhbu8U9P7
# l2W2LHC8Bg==
# SIG # End signature block
