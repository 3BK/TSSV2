# 
# http://support.microsoft.com/kb/2593042
# Rule to check to see if CRMAppPool account is a member of the PrivUserGroup
#
# Created: 05/23/2012
# Author: Jonathan Randall
#******************************************************************************************************************
# Rule Id 5738 10/16/2012
# Rule reported issue locating user in PrivUserGroup so refactored the code to search the AD group in a different way
#******************************************************************************************************************
# Last Modified: 2023-02-18 by #we#

. ./utils_MBS.ps1

#region Functions
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
    if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters)
	{
	  $parameters = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters
      $majorVersion = $parameters.MajorVersion
	  return $majorVersion;
	}
	else
	{
	   return $null
	}
}
function GetADGroupMemberShip([string] $conn_string){
$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
$DataSet = New-Object System.Data.DataSet
$SqlConnection.ConnectionString = $conn_string
$SqlCmd.CommandText = "SELECT * From ConfigSettings"
$SqlCmd.Connection = $SqlConnection
$SqlAdapter.SelectCommand = $SqlCmd
$SqlAdapter.Fill($DataSet)
$SqlConnection.Close()
$DataSet.Tables[0]
}
function GetDirectoryEntry([string] $strGUID){
	if ($strGUID -ne $null){
		return New-Object DirectoryServices.DirectoryEntry("LDAP://<GUID=" + $strGUID +">")
	}
	else{
		return $null
	}
}
#endregion

Import-LocalizedData -BindingVariable LocalizedMessages 
Write-DiagProgress -Activity $LocalizedMessages.PROGRESSBAR_ID_CRMAPPPOOLACCOUNTPRIVUSERGROUP_EXISTS -Status $LocalizedMessages.PROGRESSBAR_ID_CRMAPPPOOLACCOUNTPRIVUSERGROUP_EXISTSDesc

$Error.Clear()
$RootCauseDetected = $false
$iis_version = GetIISVersion
$domain = $ENV:USERDOMAIN
 
if (Test-Path HKLM:\Software\Microsoft\MSCRM){
	$MSCRMKey = Get-Item HKLM:\Software\Microsoft\MSCRM
	if ($MSCRMKey -ne $null){
		$username = ""
		#Need to get CRM website identifier
		$crm_website = ([System.Convert]::ToInt64($MSCRMKey.GetValue("website").Substring(10)))		
		#if ($iis_version -ne '7'){ #RBJC_To_DO
		#	$colAppPools = Get-CimInstance -class "IIsApplicationPoolSetting" -namespace "root\MicrosoftIISv2" -Filter "Name='W3SVC/APPPOOLS/CRMAppPool'"
		#}else{
			[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Web.Administration") | Out-Null
			$iis = new-object Microsoft.Web.Administration.ServerManager
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
								}
								else{
									$username = $appPool.WAMUserName
								}
							}
						}
					}		
				}
			}
		#}
		
		if ($username -ne [System.String]::Empty){
			Add-Type -AssemblyName  System.DirectoryServices.AccountManagement
			$ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
			$pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ct, $domain)
			$user = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($pc,[System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName,$username)
			"The user running the CRMAppPool is $($user.SamAccountName)" | WriteTo-StdOut
			
			#Get the connection information to MSCRM_Config.
			$mscrm_config_conn = $MSCRMKey.GetValue("configdb")
			$crm_ad_group_member_details = GetADGroupMemberShip $mscrm_config_conn
			foreach ($ad_row in $crm_ad_group_member_details){
				if ($ad_row.GetType() -ne [System.Int32] -and [System.Data.DataRow]$ad_row)	{
					 $privUserGroupId = $ad_row.PrivilegeUserGroupId.ToString()
					  "The PrivUserGroupId is set to $($privUserGroupId)" | WriteTo-StdOut
					 #Check to see if user is a member of the PrivUserGroup
					  if (-not $user.IsMemberOf($pc, [System.DirectoryServices.AccountManagement.IdentityType]::Guid,$privUserGroupId)){
 							$RootCauseDetected = $true
					  }
				}
			}
		}
	}
}

if ($RootCauseDetected -eq $true){
	Update-DiagRootCause -Id "RC_CRMAppPoolAccountPrivUserGroup_Exists" -Detected $true 
	Write-GenericMessage -RootCauseID "RC_CRMAppPoolAccountPrivUserGroup_Exists" -Verbosity "Error" -SolutionTitle "CRMAppPool Account is not a member of PrivUserGroup" -PublicContentURL "http://support.microsoft.com/kb/2593042"  -ProcessName "W3WP.exe" 
	if ($Error.Count -gt 0)	{
		("ERROR=" + $Error) | WriteTo-StdOut
	}
}	
else{
	Update-DiagRootCause -Id "RC_CRMAppPoolAccountPrivUserGroup_Exists" -Detected $false 
}



# SIG # Begin signature block
# MIInwgYJKoZIhvcNAQcCoIInszCCJ68CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDNcpeem2cPVyWb
# of7yI/RbF8bVNn/42gArTSX51c1FJKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGaIwghmeAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFR1bSFVnaMFgH3X1a0davnR
# 1mBGLbXHJs6iziTP3drqMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBsg4BFhRnXIvuHdFaLYpkrgmAOn1F4sKsWGp3Z7oTqY7skrKZyBpty
# syDcAtoQJVoQkwmUPinZa5DC2WZCgrKe1mQHpI03G0ZzonVeujAYFMu5su2QyVdt
# g//t2kjrPd4kgXiHu6YlUVw1xU0G4h2GzZd59mEPUx8/vnWDBNNFVJqEvTt3X/ip
# tl/eF3HRT/hZkJWOPEr358lq8sqdvy2WgpV1Dk6fono/ljYJIJOW1EC2h/QAVlnM
# mb33OCsqax7WAgjLhn6A3hIe5Gbw5O/CJ2O5HpMdvO9prt4BZ/jXQx0BFm7zb02d
# 9uxs6xUveGfkA9BBCrrpRyXi+8APGaOGoYIXKjCCFyYGCisGAQQBgjcDAwExghcW
# MIIXEgYJKoZIhvcNAQcCoIIXAzCCFv8CAQMxDzANBglghkgBZQMEAgEFADCCAVgG
# CyqGSIb3DQEJEAEEoIIBRwSCAUMwggE/AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIPcnku5zNTJpWSjA0/vuapPdXx66v0dlgPneWkKebRkvAgZj91lq
# PScYEjIwMjMwMjI3MDkyMDM3LjQyWjAEgAIB9KCB2KSB1TCB0jELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IEly
# ZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# Tjo4RDQxLTRCRjctQjNCNzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaCCEXowggcnMIIFD6ADAgECAhMzAAABs/4lzikbG4ocAAEAAAGzMA0G
# CSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIy
# MDkyMDIwMjIwM1oXDTIzMTIxNDIwMjIwM1owgdIxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9w
# ZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046OEQ0MS00
# QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0fA+65hiAriywYIKyvY3t
# 4SUqXPQk8G62v+Cm9nruQ2UeqAoBbQm4oDLjHGN9UJR6/95LloRydOZ+Prd++zx6
# J3Qw28/3VPqvzX10iq9acFNji8pWNLMOd9VWdbFgHcg9hEAhM03Sw+CiWwusJgAq
# J4iQQKr4Q8l8SdDbr5ZO+K3VRL64m7A2ccwpVhGuL+thDY/x8oglF9zGRp2PwIQ8
# ms36XIQ1qD+nCYDQkl5h1fV7CYFyeJfgGAIGqgLzfDfhKTftExKwoBTn8GVdtXIO
# 74HpzlePIJhvxDH9C70QHoq8T1LvozQdyUhW1tVlPGecbCxKDZXt+YnHRE/ht8Az
# ZnEl5UGLOLfeCFkeeNfj7FE5KtJJnT+P9TuBg+eGbCeXlJy2msFzscU9X4G1m/VU
# YNWeGrKVqbi+YBcB2vFDTEcbCn36K+qq11VUNTnSTktSZXr4aWZbLEglQ6HTHN9C
# N31ns58urTTqH6X2j67cCdLpF3Cw9ck/vPbuLkAf66lCuiex6ZDbtH0eTOcRrTnI
# fZ8p3DvWpaK8Q34hHW+s3qrQn3G6OOrvv637LJXBkriRc5cBDZ1Pr0PiSeoyUVKw
# fpq+dc1lDIlkyw1ZoS3euv/w2v2AYwNAYtIXGLjv1nLX1pP98fOwC27ahwG5OotX
# CfGtnKInro/vQQEko7l5AQIDAQABo4IBSTCCAUUwHQYDVR0OBBYEFNAaXcJRZ1IM
# GIs4SCH/XgXcn8ONMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8G
# A1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBs
# BggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUH
# AwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUAA4ICAQBahrs3zrAJuMAC
# XxEZiYFltLTSyz5OlWI+d/oQZlCArKhoI/aFzTWrYAqvox7dNxIk81YcbXilji6E
# zMd/XAnFCYAzkCB/ho7so2FVXTgmvRcepSOvdPzgWRZc9gw7i6VAbqP/793uCp7O
# NdpjtwOpg0JJ3cXiUrHQUm5CqnHAe0wv5rhToc4N/Zn4oxiAnNZGc4iRP+h3Sghf
# Kffr7NchlEebs5CKPuvKv5+ZDbd94XWkNt+FRIdMD0hPnQoKSkan8YGLAU/+bV2t
# 3vE18iZVaBvY8Fwayp0kG+PpNfYx1Qd8FVH5Z7gDSUSPWs1sKmBSg22VpH0PLaTa
# BXyihUR21qJnKHT9W1Z+5CllAkwPGBtkZUwbb67NwqmN5gA0yVIoOHJDfzBugCK/
# EPgApigRJuDhaTnGTF9HMWrKKXYMTPWknQbrGiX2dyLZd7wuQt0RPe7lEbFQdqbw
# vgp4xbbfz5GO9ZfVEx81AjvvjOIUhks5H7vsgYVzBngWai15fXH34GD3J0RY0E/e
# xm/24OLLCyBbjSTTQCbm/iL8YaJka7VrgeEjfd+aDH7xuXBHme3smKQWeA25LzeO
# GbxEdBB0WpC9sW9a67I+3PCPmrhKmM7VKQ57qugcaQSFAJRd1AydEjBucalv/YSz
# Fp2iQryHqxFkxZuuI7YQItAQzMJwsDCCB3EwggVZoAMCAQICEzMAAAAVxedrngKb
# SZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmlj
# YXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIy
# NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXI
# yjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjo
# YH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1y
# aa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v
# 3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pG
# ve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viS
# kR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYr
# bqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlM
# jgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSL
# W6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AF
# emzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIu
# rQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIE
# FgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWn
# G1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEW
# M2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5
# Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBi
# AEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV
# 9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3Js
# Lm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAx
# MC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2
# LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv
# 6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZn
# OlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1
# bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4
# rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU
# 6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDF
# NLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/
# HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdU
# CbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKi
# excdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTm
# dHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZq
# ELQdVTNYs6FwZvKhggLWMIICPwIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVs
# YW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046
# OEQ0MS00QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNl
# cnZpY2WiIwoBATAHBgUrDgMCGgMVAHGLROiW3R4SpcJCXiqAldSSJA5hoIGDMIGA
# pH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQAC
# BQDnpnRXMCIYDzIwMjMwMjI3MDgxNDE1WhgPMjAyMzAyMjgwODE0MTVaMHYwPAYK
# KwYBBAGEWQoEATEuMCwwCgIFAOemdFcCAQAwCQIBAAIBIAIB/zAHAgEAAgISzjAK
# AgUA56fF1wIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIB
# AAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAMJDHkU17cEfr2gB
# 0BshlIQjWVrAfQQgeowef2KkOY4nDM4bMw+NDuXhSNeOU4gnz32mbt6ujOHR3qUv
# xNEzf0JKozf4/5KmlAW9cxDsD1mcSacc9Lz+HL/wvYzYoCCX+fftlvCeLpak/ORk
# kAJQpXdIj7ZIyzIfm/Qf8EDR7RoiMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTACEzMAAAGz/iXOKRsbihwAAQAAAbMwDQYJYIZIAWUD
# BAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0B
# CQQxIgQgLC61doVdyrx9rJsBLClsIQbdJ2zr93OapdISF+gq5ZQwgfoGCyqGSIb3
# DQEJEAIvMYHqMIHnMIHkMIG9BCCGoTPVKhDSB7ZG0zJQZUM2jk/ll1zJGh6KOhn7
# 6k+/QjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB
# s/4lzikbG4ocAAEAAAGzMCIEIGuwuV6pO6CctH+QC6iOwzilDQIonaalpPo8jIEg
# wMzQMA0GCSqGSIb3DQEBCwUABIICADPQtSWuGS6Up+HCI0Zxrq3hnWK7rXQoh79r
# 4YboEH20rM/mt7u0EIGaP7LjRKrNczVk9xCEPZqXw71PBf7Wf2wgsXMY1/HuHJU3
# 6+x1Gq2FXWGLmPtnxszTtvCyHC8DU5k5LTivFKmaafrEobrOK5iGc3jJ9Wcz9Dt8
# MWIHZUlgvss86kavFqO3cBRqOGv9IMWQEercAgRf3Iaq7dIz5E5q1uoRO2/OqxcP
# QGmFKr9TTPuRdiJcTHP/BTCd053SSrc9PejYifucV2My5JQNHxMdW7nR2byxoNTG
# w119nCaxG5dIPqLFTC/GLyz25itR5ovZfjEpwD4yYtGghRXZqyuxtSgF8N24xsbm
# w9Z58r1/7GOzSzk6gh/HmDdQTRL5tQGAYj8M3Euu35hLD/2RoopJerLw2sPjGJud
# EXAwecsblaeNmVjR+rJUDsYX73JGphwI6IxJB4mrfTdsI8FVGUZfdQPFCk9CLsYQ
# IIUY+K0nhTfJiKRhNBcIEB0uagB4CbnNaqxkSyax2tr+15rjvtjeILbIf7tij327
# eBWj54MIeNYyWpNwVxjYDjCx1hSeR/bkM/Ij1wzHJRTwcK2ANacAqsJkBMqb8mg9
# pujQNhtasfx8ponjGVlqvwcmw4rIOK786ED9GFw7sffs46olSgF7iJ49V8tZpkNs
# Ru3Uof6n
# SIG # End signature block
