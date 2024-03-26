#************************************************
# DC_ServerManagerInfo.ps1
# Version 1.0.1
# Date: 09-11-2010
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script can be used to 
#************************************************

# 2023-02-20 WalterE mod Trap #we#
trap [Exception]{
	WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; continue
	Write-Host "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_"
}

<# trap [Exception] 
{
	WriteTo-ErrorDebugReport -ErrorRecord $_
	continue
} #>

Function Out-MultiLevelObject{
	Param ($items, $startObjects, $path=("Path"), $parent=("Parent"), $label=("Label"), $indent=0, $Attributes="")			
	Foreach ($startAt in $StartObjects){
		$children = $items | where-object {$_.$parent -eq $startAt.$path} 
		$AttributesText = ""
		if ($null -ne $children){
			if ($null -ne $startAt.$label){
				("<div style=`"margin-left:" + ($indent * 15) + "`">") + "$($startAt.$label)"  + "</div>" 
			}
			$children | ForEach-Object {Out-MultiLevelObject $items $_ $path $parent $label ($indent + 1)} 
		}else{
			("<div style=`"margin-left:" + ($indent * 15) + "`">" + "$($startAt.$label)" + "</div>")
		}
	}
}

if ($OSVersion.Build -gt 6000){
	Import-LocalizedData -BindingVariable ServerManagerStrings
	Write-DiagProgress -Activity $ServerManagerStrings.ID_ServerManagerInfo -Status $ServerManagerStrings.ID_ServerManagerObtaining
	if ((Get-CimInstance -Class Win32_ComputerSystem).DomainRole -gt 1){ #Server
		if (test-path "$Env:windir\system32\oclist.exe"){
			$OutputFile = $ComputerName + "_OptionalComponents.txt"
			$CommandToExecute = "$Env:windir\system32\cmd.exe /c $Env:windir\system32\oclist.exe > $OutputFile"
			$fileDescription = $ServerManagerStrings.ID_ServerManagerOclist
			RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect "$OutputFile.*" -fileDescription $fileDescription
		}else{ # dont execute code below in ServerCore or pre-Windows Server 2008
			if ($OSVersion.Build -gt 7000){
				Import-Module "ServerManager"			
				$Features_Summary = new-object PSObject
				$AllFeatures = Get-WindowsFeature | Where-Object {($_.installed -eq $true)}
				$Roles = $AllFeatures | Where-Object {($_.FeatureType -eq "Role")}
				$RoleServices = $AllFeatures | Where-Object {($_.FeatureType -ne "Role")}
				$Features = $AllFeatures | Where-Object {($_.FeatureType -eq "Feature") -and ($_.Depth -eq 1)}
				Foreach ($Feature in $Roles){
					$RoleServicesForFeature = ($AllFeatures | Where-Object {($_.Parent -eq $Feature.Name) -and ($_.Installed -eq $true)})
					if ($RoleServicesForFeature){
						$RoleServiceDisplay = Out-MultiLevelObject -items $RoleServices -StartObjects $RoleServicesForFeature -path "Name" -Parent "Parent" -label "DisplayName"
					}else{
						$RoleServiceDisplay = "<div style=`"margin-left:0`">(There are no role services for " + $Feature.Name + ")</div>"
					}
					add-member -inputobject $Features_Summary -membertype noteproperty -name $Feature.DisplayName -value $RoleServiceDisplay
				}
				$Features_Summary | ConvertTo-Xml2 | update-diagreport -ID "06_Roles" -name "Server Roles/ Role Services" -verbosity "Informational"
				$Features_Summary = new-object PSObject
				Foreach ($Feature in $Features){
					$RoleServicesForFeature = ($AllFeatures | Where-Object {($_.Parent -eq $Feature.Name)})
					if ($RoleServicesForFeature){
						$RoleServiceDisplay = Out-MultiLevelObject -items $RoleServices -StartObjects $RoleServicesForFeature -path "Name" -Parent "Parent" -label "DisplayName"
					}else{
						$RoleServiceDisplay =  "<div style=`"margin-left:0`">&#160;</div>"
					}
					add-member -inputobject $Features_Summary -membertype noteproperty -name $Feature.DisplayName -value $RoleServiceDisplay
				}
				$Features_Summary | ConvertTo-Xml2 | update-diagreport -ID "06_RolesFeatures" -name "Feature/ Services" -verbosity "Informational"				
			}
			if(($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 2)){
				$AllRemovedFeatures = Get-WindowsFeature | Where-Object {$_.InstallState -eq "Removed"}    #This need to be confirmed.
				$RemovedRoles = $AllRemovedFeatures | Where-Object {($_.FeatureType -eq "Role")}
				$RemovedRoleServices = $AllRemovedFeatures | Where-Object {($_.FeatureType -ne "Role")}
				$RemovedFeatures = $AllRemovedFeatures | Where-Object {($_.FeatureType -eq "Feature") -and ($_.Depth -eq 1)}
				$Roles_Summary = new-object PSObject
				Foreach ($Feature in $RemovedRoles){
					$RoleServicesForFeature = ($AllRemovedFeatures | Where-Object { $_.Parent -eq $Feature.Name })
					if ($null -ne $RoleServicesForFeature){
						$RoleServiceDisplay = Out-MultiLevelObject -items $RemovedRoleServices -StartObjects $RoleServicesForFeature -path "Name" -Parent "Parent" -label "DisplayName"
					  }else{
						 $RoleServiceDisplay = "<div style=`"margin-left:0`">(There are no role services for " + $Feature.Name + ")</div>"
					  }
					  add-member -inputobject $Roles_Summary -membertype noteproperty -name $Feature.DisplayName -value $RoleServiceDisplay
				}
				$Roles_Summary | ConvertTo-Xml2 | update-diagreport -ID "07_RemovedRoles" -name "Removed Server Roles/ Role Services" -verbosity "Informational"
				$Features_Summary = new-object PSObject
				Foreach ($Feature in $RemovedFeatures){
					  $RoleServicesForFeature = ($AllRemovedFeatures | Where-Object { $_.Parent -eq $Feature.Name })
					  if ($RoleServicesForFeature){
			 			 $RoleServiceDisplay = Out-MultiLevelObject -items $RemovedRoleServices -StartObjects $RoleServicesForFeature -path "Name" -Parent "Parent" -label "DisplayName"
		 			 }else{
						  $RoleServiceDisplay =  "<div style=`"margin-left:0`">&#160;</div>"
	 				 }
					 add-member -inputobject $Features_Summary -membertype noteproperty -name $Feature.DisplayName -value $RoleServiceDisplay
				}
				$Features_Summary | ConvertTo-Xml2 | update-diagreport -ID "07_RemovedRolesFeatures" -name "Removed Feature/ Services" -verbosity "Informational"
			}
		}
	}
}


# SIG # Begin signature block
# MIInwQYJKoZIhvcNAQcCoIInsjCCJ64CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCzVBWq3/qvf76I
# fA2Mi537C1LnglT5VoJ0cqF9PmDuL6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGaEwghmdAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIK79bR1VSabL+jilJEaFAPc1
# Hr3vH4qfdv4DPxPAaQvRMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAwci4e/ztKdMGykPVEL3+QZwkQy3GOhLqjMWVzJMPmZbwH6gL0/Qlc
# bwuUbZLuatdre2BWads/+OGf19CD4DhIeK8OLM5aiaM64oKf1XsNFaELsOyMNoOp
# Uov318nyurB2DAwZFPMbQOGL+wOiWWevJRJTdz47UjdOSdOX7VJ5aLGtgfv/AChW
# eIkhwznulbGUQx1g7twlPsSENTRIgD8BJhAEcPyA4+iXuWOtX0F6uX7uW8B5YAWh
# kKvfy/Z0CyWGaoo5vVGZMR7o/1n/6jWk2q7q7tPcZgLfxENkNH9cUFdVkFvZzvPM
# 4S2AoKMN9SXmv4XSlb4+ZGAKmJSAhoKhoYIXKTCCFyUGCisGAQQBgjcDAwExghcV
# MIIXEQYJKoZIhvcNAQcCoIIXAjCCFv4CAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIMsKY88KDeMLyGldre99g7PdOPBWvaUwHghHx6lavD84AgZj5ZF2
# kuwYEzIwMjMwMjIwMTUwMDQyLjE0OFowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046QTI0MC00QjgyLTEzMEUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF4MIIHJzCCBQ+gAwIBAgITMwAAAbgI1MG4eeBRSQABAAABuDAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MjA5MjAyMDIyMTZaFw0yMzEyMTQyMDIyMTZaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkEyNDAt
# NEI4Mi0xMzBFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAnBux/BEcRGfkL3lA8aff
# u0nm86Jj1paN4gPGmBpdpgaKqzDQbRy8Irdi6Wup6YR/YKQZJ1w4kAX74SqE5Kqs
# 7XecZyOrDqEU2ewbAoA3LN13Cc47SPPWV8Egi7vtNt82+dpZvBJG7QNMYcDufs9H
# Qxgn1sL8eilK2lsV/rTospxNafBpS4R0CHHoUCqDWuSC6CK65prErLFGR2MVksoV
# cRcv2nTU+3BLR8bq9mJFWcQqB5qXZN4u90AipqkHCW09iJ+CqentnhUkxw+jRNaZ
# E1UU5wdE3BYd6E33GDq6AgZc+juEylas+CDiagc7Z6lzRPfquCb2GUOuXbxsblNq
# SZXs0n3yRsXmWC2WujBPp5zARW24t3hrSDNiqFqdbvNoVmcN+3nIx7HLn2J8RN3O
# nACuPackDIiyKrU9jdc+baZQwuUAKSyp6Ucp9aKEr8V6HD+bOKi8FXCSSv8bQXX0
# 5aBH4wFQqJ/Ck7JCIsDGuq9Wd8JjhCMkJmIci5LXkcJD9Mi39CPjHVa9FrVSqOea
# ku7j/IFhZmx29mirxJcjuI6zua55wAl4SRiUzqI6QyKCHMSGNAr1OE+mgC2W5dsv
# uogcat8WUeZf/iyhzuOPWPy4HfVTfiAmUHZemGMxpP4T471IiaT/oZFX1KbwLzwW
# eabZV3AyW4I0BTM8WN+8fHcCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBTE/UclN4XD
# M1ijWeN+5xe5R9BpbjAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAn26TyaLCkygr
# DcP33qmITNt6AAbGQAEdifa8/aFuqeRL1T3uz/pCXJk6EYWxW51qIt5FllOxobmF
# HSgK4Eg1n+V6WjnHMdz6YE6kFenFJpbWGqjFoIuxUfUQG3PuKfbkePL56O4FyKUf
# oRnRm03GZYYhDPxHQC5LROPhWAlcciVc/11U6LIaj1V6WuT4UbH8EL6IS4Jop38i
# zKkc+IJQKHnYMZz3WzZLuV1DHUfgKWM4C1qcN9u9J6MBJYuj+zfDRcwBsO6tY2ez
# ReJ0AXZGcvU9rGg7LP1VhqQ0YrgXf+4lFmdWBuwJi7A1fUGZLAzVls9KeCA1IZNn
# H8VDbQmP+6WsrSvIBu81s1viSRpLhrvruJ8Kq9Q4UuVRPw83jeGGV3EjrIc8w5Yi
# 0mkQchkGJM0puUGxhsiuCFvVib219KwtrlkkPNVk2d1F+FSok7JcX4JWb061WYUM
# b2QjAzpABfxDSJ/vbXPhU7Nk28PyS2DWUj5eNeBcMlWzeHjuwy70ZdJjOTL7t22C
# ZzeJE+R1rdhVF2Y8m00U3Q0vJtyywTu+EUKKPvl4MZAEWrQDgpUbq4F2vpRNbATR
# UofEHPYGka+fsEKz7nLGcX4dXoJSJyQOqo+L8gjtmyx30Rs/27OPiW6V1cMA+tYa
# 10ar7ArSh2UY1W4IzGwveGfz4qI71SIwggdxMIIFWaADAgECAhMzAAAAFcXna54C
# m0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMy
# MjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51
# yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY
# 6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9
# cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN
# 7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDua
# Rr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74
# kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2
# K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5
# TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZk
# i1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9Q
# BXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3Pmri
# Lq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUC
# BBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9y
# eS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUA
# YgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
# 1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIw
# MTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/yp
# b+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulm
# ZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM
# 9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECW
# OKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4
# FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3Uw
# xTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPX
# fx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVX
# VAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGC
# onsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU
# 5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEG
# ahC0HVUzWLOhcGbyoYIC1DCCAj0CAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OkEyNDAtNEI4Mi0xMzBFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBwa15WoXH8htMpcct65cI9E8wPu6CBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA553nADAiGA8yMDIzMDIyMDIwMzMwNFoYDzIwMjMwMjIxMjAzMzA0WjB0MDoG
# CisGAQQBhFkKBAExLDAqMAoCBQDnnecAAgEAMAcCAQACAixjMAcCAQACAhKbMAoC
# BQDnnziAAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEA
# AgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAGLFSO0Hj8c1bnhs4
# e3Jv4IVB8jxHasVEUgDsjBSPBMRlHJgVEBy/KLkfsNdIDWrkAWfoo1WvdH9M61gc
# Q9gZezwmffGb63tWwWJneQ5bGSfx4RnbIbnOe3X2Iy/viDkEdK17uOuh5bTeHY5c
# +xo9Vj8ztN8pJ2Q79kyoUThMqCkxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAbgI1MG4eeBRSQABAAABuDANBglghkgBZQME
# AgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJ
# BDEiBCAOy9lufW+ydVK1pVQ0QM5roPlMb3GXlur9xZtyF6e8BzCB+gYLKoZIhvcN
# AQkQAi8xgeowgecwgeQwgb0EICjr1jigcDtDilL5jU2wF+ukhhN5aw94ZNqaLRfQ
# 8PsfMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAG4
# CNTBuHngUUkAAQAAAbgwIgQg8BbMIGC4HZi0YL6GKSIbaOUXff4I+WxkA+d2lsfd
# NKcwDQYJKoZIhvcNAQELBQAEggIAIxUFE/H064VsxnQ74pUXaErO9zPGQ5rnDFDu
# 6AqXR5OxA95OTPqdDekV76AnBcQ28wXQFaxHNopB7zOVpnasD+UZYtmtfLTgXUHs
# ONl4NBpEDGhfVwKJ4ivgO/pTUtUVUs/vKatrrNDuLNbSlkmJsgi2ju9aHhPpL6B/
# hdMXib+g3g6HyDowCihKg++hAHO5oQycKbZF6MOouyuMOUdaEs21io9pvii8U1OT
# 8f9ZiPORYziu4Jv/OKwFBgj4uaeETo8PNq/jW5QXK5d4l9tiGLDggeRhTpzm5BMT
# pDfYWuB9HDKyxUbM22jFJRiczVudm99Hh0C2RmAn+xBtQy6pXxPv+zl/mNaG6azt
# +xoVFBDaDt/27VgyDv4fGLxGGKoMowaxxqCK6rMsUk2C96udjZZBYUbpkVVIOBja
# Zvzo1VDwRypCPICaIAMUWdTFa563u1fnav05cQM//Coe4h+HsQ3xOUwyaX/C9eSM
# WYsAlBQuBtqGi1cNeVxcGfXnITbQtLszaQU2awwCTY9Qqelsy3x+xgOS96MB7JYi
# pJ1eAc9k0pd8bk84mn3ZuL/JRvC5v3Vxdi6XUsuJ3GuXgfIgK2FHzZOzxkptToli
# +wxpnPQW0b71i4sblgRj3LpogQKmRziMBTf0Ofl4v+3DlDxKdjphXe/1KTP6cQrA
# lfNn52k=
# SIG # End signature block
