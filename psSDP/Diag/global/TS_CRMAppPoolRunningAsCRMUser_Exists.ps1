# 
# http://support.microsoft.com/kb/2593042
#   Rule to check to see if CRM App Pool running under CRM User Account
#
# Created: 01/03/2012
# Author: Jonathan Randall
# Last Modified: 2023-02-18 by #we#
#******************************************************************************************************************
. ./utils_MBS.ps1

function GetOrganizations([string] $conn_string){
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$DataSet = New-Object System.Data.DataSet
	$SqlConnection.ConnectionString = $conn_string
	$SqlCmd.CommandText = "SELECT FriendlyName,ConnectionString FROM Organization"
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter.SelectCommand = $SqlCmd
	$SqlAdapter.Fill($DataSet)
	$SqlConnection.Close()
	$DataSet.Tables[0]
}

function GetIISVersion(){   
    if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters){
	  $parameters = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters
      $majorVersion = $parameters.MajorVersion
	  return $majorVersion;
	}else{
	   return $null
	}
}

Import-LocalizedData -BindingVariable LocalizedMessages 
Write-DiagProgress -Activity $LocalizedMessages.PROGRESSBAR_ID_CRM_APPPOOLRUNNINGASCRMUSER_EXISTS -Status $LocalizedMessages.PROGRESSBAR_ID_CRM_APPPOOLRUNNINGASCRMUSER_EXISTSDesc

trap [Exception]{
	WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;continue
}
"--> Entered TS_CRMAppPoolRunningAsCRMUser_Exists.ps1" | WriteTo-StdOut
$Error.Clear()
$RootCauseDetected = $false
$iis_version = GetIISVersion
 
if (Test-Path HKLM:\Software\Microsoft\MSCRM){
	$MSCRMKey = Get-Item HKLM:\Software\Microsoft\MSCRM
	if ($MSCRMKey -ne $null){
		if ($iis_version -eq '6'){
			$colAppPools = Get-CimInstance -class "IIsApplicationPoolSetting" -namespace "root\MicrosoftIISv2" -Filter "Name='W3SVC/APPPOOLS/CRMAppPool'"
		}
		else{
			[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Web.Administration") | Out-Null
			$iis = new-object Microsoft.Web.Administration.ServerManager
		}
		
		#Need to get CRM website identifier
		$crm_website = ([System.Convert]::ToInt64($MSCRMKey.GetValue("website").Substring(10)))
		
		#Get the IIS site using that identifier
		foreach ($site in $iis.Sites){
			if ($site.Id -eq $crm_website){
				#Match found, get the sites application pool name
				$crm_running_appPool = $site.Applications[0].ApplicationPoolName
				
				#Now loop through AppPools in IIS and check process Identity
				foreach ($appPool in $iis.ApplicationPools){
					if ($appPool.Name -eq $crm_running_appPool -and $appPool.ProcessModel.IdentityType -ne [Microsoft.Web.Administration.ProcessModelIdentityType]::NetworkService){
						if ($appPool.ProcessModel.Username -ne "" -or  $appPool.WAMUserName -ne ""){
							if ($appPool.ProcessModel.Username -ne ""){
								$username = $appPool.ProcessModel.Username
								"The userrname for the CRMAppPool is set to $($username)" | WriteTo-StdOut
							}
							else{
								$username = $appPool.WAMUserName
								"The username for the CRMAppPool is set to $($username)" | WriteTo-StdOut
							}
						}
						#Identified that this app pool is running under a user account.
						$mscrm_config_conn = $MSCRMKey.GetValue("configdb")
						$server_version = $MSCRMKey.GetValue("CRM_Server_Version").Substring(0,1)
						if ($mscrm_config_conn -ne $null){
							#get organizations
							$crm_organizations = GetOrganizations $mscrm_config_conn
							foreach($org in $crm_organizations){
							    if ($server_version -eq '5'){
									if ($org.GetType() -ne [System.Int32] -and [System.Data.DataRow]$org){
										"V5: Examining Organization $($org.FriendlyName) to see if $($username) is a CRM user" | WriteTo-StdOut	#we#
										$org_conn = New-Object System.Data.SqlClient.SqlConnection($org.ConnectionString)
										$org_db_cmd = New-Object System.Data.SqlClient.SqlCommand
										$org_db_cmd.CommandText = "SELECT Count(*) From SystemUser WHERE DomainName='$($username)' OR DomainName = '$($Env:USERDOMAIN)\$($username)'"
										$org_db_cmd.Connection = $org_conn
										$org_conn.Open()
										$user_count = $org_db_cmd.ExecuteScalar()
										"Query returned $($user_count) records from SystemUser table" | WriteTo-StdOut
										if ($user_count -gt 0){
											$RootCauseDetected=$true
											Write-GenericMessage -RootCauseID "RC_CRMAppPoolRunningAsCRMUser_Exists" -Verbosity "Error" -SolutionTitle "CRM App Pool Running As A CRM User" -PublicContentURL "http://support.microsoft.com/kb/2593042"  -ProcessName "W3WP.exe" 
											break
										}
										$org_conn.Close()
										$org_conn.Dispose()	
										
									}
								}else{
									if ($org.GetType() -ne [System.Int32] -and [System.Data.DataRow]$org){
										"_Examining Organization $($org.FriendlyName) to see if $($username) is a CRM user, [org.ConnectionString: $($org.ConnectionString)]" | WriteTo-StdOut	#we#
										$org_conn = New-Object System.Data.OleDb.OleDbConnection($org.ConnectionString)	#we#
										$org_db_cmd = New-Object System.Data.OleDb.OleDbCommand
										$org_db_cmd.CommandText ="SELECT Count(*) From SystemUser WHERE DomainName='$($username)' OR DomainName = '$($Env:USERDOMAIN)\$($username)'"
										$org_db_cmd.Connection = $org_conn
										$org_conn.Open()
										$user_count = $org_db_cmd.ExecuteScalar()
										"Query returned $($user_count) records from SystemUser table" | WriteTo-StdOut
										if ($user_count -gt 0){
											$RootCauseDetected=$true
											Write-GenericMessage -RootCauseID "RC_CRMAppPoolRunningAsCRMUser_Exists" -Verbosity "Error" -SolutionTitle "CRM App Pool Running As A CRM User" -PublicContentURL "http://support.microsoft.com/kb/2593042"  -ProcessName "W3WP.exe" 
											break
										}
										$org_conn.Close()
										$org_conn.Dispose()	
									}
								}
							}
						}
					}
				}
			}
		}		
	}
}

if ($RootCauseDetected -eq $true){
	Update-DiagRootCause -Id "RC_CRMAppPoolRunningAsCRMUser_Exists" -Detected $true 
	if ($Error.Count -gt 0)	{
		("ERROR=" + $Error) | WriteTo-StdOut
	}
}	
else{
	Update-DiagRootCause -Id "RC_CRMAppPoolRunningAsCRMUser_Exists" -Detected $false 
}
"<-- Exited TS_CRMAppPoolRunningAsCRMUser_Exists.ps1" | WriteTo-StdOut

# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAC7ykutu30LiG5
# G8TnOiU1t2vKAdykQkf07c6HTwmhdaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMdacPd1gAV9gWjOPc2juWuK
# qHxLhCOUWic5LMr6QVkpMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQA+qaUAaRrQEN/GTpPueCYEZA2j3nBsDnGG3yuOSSZDT6OOKCDHS3kS
# nB7kfLb5IzjgnR+79uopiHSh/UnSwJ0VmA8odkW9dO3IK5CSM0jmbwIYJtnqsBGt
# 34n1BfJEL2++ZGYwYvChbfdaW3DlG97I5DyHcKzNXjuj+xfBvT7G6NRM8Hflnmfn
# 6uJe5u1E/4X7dsrG0p8W9X4VUxhp/0Ie76YH+k3bl5CFo3oZICrybidjPgZ8+6x/
# D+/DmJyoBOM6P9d7dydK/XEfhMZqyUVick0bLa9i8KBBS90u9Sf/mSdtBpSBKMOs
# kpbVxn9N8Qunbv0MPdCtiGOY664wREYDoYIW/TCCFvkGCisGAQQBgjcDAwExghbp
# MIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEICAG5CLIvV1LSb0E5384dIhYDQGztIbvbMnzrtbOZYOEAgZj7imN
# rL8YEzIwMjMwMjI3MDkyMDQ4LjQzNlowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQ2QkQt
# RTNFNy0xNjg1MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVDCCBwwwggT0oAMCAQICEzMAAAHH+wCgSlvyJ9wAAQAAAccwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkw
# MTM1WhcNMjQwMjAyMTkwMTM1WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDZCRC1FM0U3LTE2ODUxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCvQtxW2dq00UwGtBO0b0/whIA/LIabE1+ETNo5WW3T
# zykFQUAhqyY3946KMTpRxp/dzZtWc3/TaKHSyZKpiSbk/dnBTtlbbTZvpw8MmNdy
# uMmPSp+e5xwG0TdZTS9nwKJAPuqsrF4XxgE1xL49W2+yqF3lhboDCFaqGPDWZi4t
# 60Xlvpo+J//dHOXKobdJXtA+JIl6d2zuAbjflGzLUcnheerO04lHjUjSPcRDTkkw
# XlA1GLuRPq9dNP4wdWPbsVVDtt5/9T7YQBsWPZfYA5Zu+CVhpiczeb8j85YMdSAb
# Dwoh2wOHdbV66ycXYPuh6caC1qGz5LUblSiV/kRKD/1n7fyuFDAuCiRjmTqnyTlq
# tha2zN0kromIhGXzjcfviTv5CqVPYtsBA+ryK9C/SB1yVbZom6fUqtb6/nZHe8Ac
# I61tSbG8PV40YeoaotqC2Wr1QVcpe5eepcmqu4JiZ/B0UwPRQ/qKLWUV14ovzs92
# N0DDIKJVwISgue8PPK+M2PG2RN3PpHjIXU39fg9JAfgWWCyXIEheCBpKU+28+7EC
# 25pz8hOPiTQhFKEaJgsEzYPDqh6ws6jF7Ts5Q876pdc5wkxUeETQyWGGfF83YHUl
# YU9bBDqihaKoA5AOrNwPH7v2yHEDULHQrvR44GmUyiDbuBigukG/udHPi0eqhPK8
# DQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFAVQ0t0cPsEAX9VT9f94QcuJRJIgMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBANDLlzyiA/TLzECwtVxrTvBbLWZP6epiAAWfPb3vaQ074onsATh/5JVu86eR
# 5644+rfFz7pNLyDcW4opgTBiq+dEfFfny2OWxxmxl4qe7t8Y1SWk1P1s5AUdYAtR
# G6henxMseHGPc8Sr2PMVgE/Zg0wuiXvSiNjWqnN7ecwwl+l26t0EGlo4uUmZE1Mu
# HF35EkYlBtjVcBzHqn8WKDCoFqxINTGn7TIU8QEH24ETcogsC2rp9zMangQx6ifp
# iaTIIYC1cwoMVBCB0/8hN7tWCEBVs9NWU/eFjV0WBz63xgrahsVIVUqyWQBIBMMe
# 6UIyG35asiy6RyURQ/0NoyamrtLREs4MyJwjo+2qoY6F2dpGW0DR35Z/7S0+31JR
# W2s8nI7tYw8pvKQJFfOYcrTrOvSSfViJRg1cKw6BocXkiY7ZnBDnhQTUjnmONR2V
# 3KPL9Q8mDFGb03Jd47tp1ivwrx/pDac8XS9aoUbt7DBoCXkKUp6vOyF+EHzO6NVH
# R3VFrtnTWWddiFa4+pVlrIWXskevqLqG6GlToFDr9WBjRwGKSxfiY0z4hJjzVPVF
# i3t9YBM27/OSMg1zOKnNt+DlL7d8ICjyBUHr7oDkvS8GDf12wUhO/oxYm5DxlnLt
# /CUUFkTh3kgVtG51qQ3AoZ3IsYzai1o2rvCbeS7vHjVQYCaQMIIHcTCCBVmgAwIB
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
# IEVTTjpENkJELUUzRTctMTY4NTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA4gBI/QlJu/lHbfDFyJCK8fJyRiig
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOemfw4wIhgPMjAyMzAyMjcwODU5NThaGA8yMDIzMDIyODA4NTk1OFow
# dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA56Z/DgIBADAHAgEAAgIEdDAHAgEAAgIR
# SjAKAgUA56fQjgIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAEVT4g2ejo6x
# pob2uUyIeIm44cbTzwnw4CVCm6j2JHWdYGuf5GLE2qqFcyiRLwC1HpKy4TMF40y/
# Fp0qhk/W0CMfhEVHN/d4noNy/7BOLDaY3LXV48euqdWdvhvjF6ModcQ2eYbOE34W
# AV5etGD17zyZeVfxJEjfX3VpjRFalfwwMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHH+wCgSlvyJ9wAAQAAAccwDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgF2FY5DXjP27ZNUw1jMEGhiEYXUqCDGVrFr1xKXvQSkgwgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBH5+Xb4lKyRQs55Vgtt4yCTsd0htESYCyP
# C1zLowmSyTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABx/sAoEpb8ifcAAEAAAHHMCIEIPPTSo1iV4XtTH+v89PCU2fl4729RZhmc7sQ
# PA/4MaPLMA0GCSqGSIb3DQEBCwUABIICAC0EabMbBdGPE0E6lt1EaRQeIUetNGvQ
# PbCQB840ZtV7aBTexdd932/wCuj37r/HWZ8g0yvKeOYpi+7jXNLhBS3rnB77yFNT
# CChwO/cB2Uby9Vhbmu7L1tXCjtfWW1bMd/qbbRHDqPlQ2Kkl3XBUkuoEJUSD4g/8
# 8Kf0QFaddkov2RY8lsiY7vtx2q9hON6F8sIVhezunLJ/38qXaNXKZFe04kJLdM/g
# 2Zwbb/kh+6Dc80CBUaLSf7nPTcoNgN6aOST9XqznbLGTkyB+QYMPSjWDwDFS+Agd
# Kx1QtXUVKHhPEaVwqyR0vcZu87SLRKX+UUlRut71fS841TjPPp4omf285jtxeJRk
# 6KQtdU/4hxYCLyboGa8ANCP7CfbceMzAeSnMMW/hmGYIMj5B0Ouc7KEx+0DNcDEy
# 3axW1aF9uvF4Fm+CpY8I9xmmnPfribB1PvhfYU1AdvaseTT/1aMW2066yIgkioat
# dLEnDsXDPZa3NTR7uPVzDk9fHgs3pJ1bXyCDlHS8ra9TBczdDhlcO7ShsGWNrlee
# aE7XIKQ8KnQU9EVKBiY/jx5/RttNW27e+s3PS0cBXHyrKwhflXDYBuw89KMwpx+E
# qDdFx5bsCEG/vCDgAoi1jSt2qyNrq8r7fof45juyHsKgvyLFjJtIP9VqSc5jmN32
# tROyfr0LZxCd
# SIG # End signature block
