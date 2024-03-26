#************************************************ 
# DC_UserLogonInfo.ps1 
# Version 1.0 
# Date: 2/18/2014 
# Author: Tim Springston [MS] 
# Description:  This script queries for the user and computer domain
#  and returns details.
#************************************************ 
Import-LocalizedData -BindingVariable ADInfoStrings
Write-DiagProgress -Activity $AdInfoStrings.ID_ADInfo_Status -Status   $AdInfoStrings.ID_ADInfo_Wait
#| WriteTo-StdOut -shortformat

Trap [Exception]
		{
		 #Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 WriteTo-StdOut "[info]:An exception occurred." -shortformat
		 WriteTo-StdOut "[info]: Exception.Message $ExceptionMessage."
		 WriteTo-ErrorDebugReport -ErrorRecord $_
		 $Error.Clear()
		 continue
		}

#Define output file.
$FileDescription = "Text File containing details about the currently logged on user."
$SectionDescription = "Active Directory User Logon Info (TXT)"
$ExportFile = Join-Path $Pwd.Path ($ComputerName + "_UserLogonInfo.txt")
$global:FormatEnumerationLimit = -1


#Determine OS and computer role
$OS = Get-CimInstance -Class Win32_OperatingSystem
$cs =  Get-CimInstance -Namespace "root\cimv2" -class win32_computersystem
$DomainRole = $cs.domainrole
$LogonServer = $env:Logonserver
$LogonServer = $LogonServer.replace("`\","")
$ComputerName = $cs.name
if ($LogonServer -match $ComputerName)
	{$LoggedOnLocally = $true}
	else
	{$LoggedOnLocally = $false}

switch -regex ($DomainRole) {
	[0-1]{
		 #Workstation.
		$RoleString = "Client"
		if ($OS.BuildNumber -eq 3790)									
		{$OSString = "Windows XP"}
			elseif (($OS.BuildNumber -eq 6001) -or ($OS.BuildNumber -eq 6002))
				{$OSString = "Windows Vista"}
					elseif (($OS.BuildNumber -eq 7600) -or ($OS.BuildNumber -eq 7601))
							{$OSString = "Windows 7" }
						elseif  ($OS.BuildNumber -eq 9200)
							{$OSString =  "Windows 8"}
							elseif ($OS.BuildNumber -eq 9600)
								{$OSString =  "Windows 8.1"}
		}
	[2-3]{
		 #Member server.
		 $RoleString = "Member Server"
		 if ($OS.BuildNumber -eq 3790)
	 		{$OSString =  "Windows Server 2003"}
			elseif (($OS.BuildNumber -eq 6001) -or ($OS.BuildNumber -eq 6002))
				{$OSString =  "Windows Server 2008 RTM"}
				elseif (($OS.BuildNumber -eq 7600) -or ($OS.BuildNumber -eq 7601))
					{$OSString =  "Windows Server 2008 R2"}
					elseif ($OS.BuildNumber -eq 9200)
						{$OSString = "Windows Server 2012"}
								elseif ($OS.BuildNumber -eq 9600)
									{$OSString = "Windows Server 2012 R2"}
		 }
	[4-5]{
		 #Domain Controller
		 $RoleString = "Domain Controller"
		 if ($OS.BuildNumber -eq 3790)
	 		{$OSString =  "Windows Server 2003"}
			elseif (($OS.BuildNumber -eq 6001) -or ($OS.BuildNumber -eq 6002))
				{$OSString =  "Windows Server 2008 RTM"}
				elseif (($OS.BuildNumber -eq 7600) -or ($OS.BuildNumber -eq 7601))
					{$OSString =  "Windows Server 2008 R2"}
					elseif ($OS.BuildNumber -eq 9200)
						{$OSString = "Windows Server 2012"}
							elseif ($OS.BuildNumber -eq 9600)
									{$OSString = "Windows Server 2012 R2"}
		 }
	}

#Next, get useraccountcontrol value of the user object.
$user = $env:username
function GetUACAttr
{
	param ([string]$username)

	$ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
	$RootString = "GC://" + $ForestInfo.Name
	$Root = New-Object  System.DirectoryServices.DirectoryEntry($RootString)
	$searcher = New-Object DirectoryServices.DirectorySearcher($Root)
	$searcher.Filter="(&(samaccountname=$username))"
	$results=$searcher.findone()
	if ($null -ne $results)
		{
		$UAC = $results.properties.useraccountcontrol[0]
		return $UAC
		}
}



#Function from Fabian Muller to translate value to flags.
Function Set-UserAccountControlValueTable 
{ 
    # see http://support.microsoft.com/kb/305144/en-us 
     
    $userAccountControlHashTable = New-Object HashTable 
    $userAccountControlHashTable.Add("SCRIPT",1) 
    $userAccountControlHashTable.Add("ACCOUNTDISABLE",2) 
    $userAccountControlHashTable.Add("HOMEDIR_REQUIRED",8)  
    $userAccountControlHashTable.Add("LOCKOUT",16) 
    $userAccountControlHashTable.Add("PASSWD_NOTREQD",32) 
    $userAccountControlHashTable.Add("ENCRYPTED_TEXT_PWD_ALLOWED",128) 
    $userAccountControlHashTable.Add("TEMP_DUPLICATE_ACCOUNT",256) 
    $userAccountControlHashTable.Add("NORMAL_ACCOUNT",512) 
    $userAccountControlHashTable.Add("INTERDOMAIN_TRUST_ACCOUNT",2048) 
    $userAccountControlHashTable.Add("WORKSTATION_TRUST_ACCOUNT",4096) 
    $userAccountControlHashTable.Add("SERVER_TRUST_ACCOUNT",8192) 
    $userAccountControlHashTable.Add("DONT_EXPIRE_PASSWORD",65536)  
    $userAccountControlHashTable.Add("MNS_LOGON_ACCOUNT",131072) 
    $userAccountControlHashTable.Add("SMARTCARD_REQUIRED",262144) 
    $userAccountControlHashTable.Add("TRUSTED_FOR_DELEGATION",524288)  
    $userAccountControlHashTable.Add("NOT_DELEGATED",1048576) 
    $userAccountControlHashTable.Add("USE_DES_KEY_ONLY",2097152)  
    $userAccountControlHashTable.Add("DONT_REQ_PREAUTH",4194304)  
    $userAccountControlHashTable.Add("PASSWORD_EXPIRED",8388608)  
    $userAccountControlHashTable.Add("TRUSTED_TO_AUTH_FOR_DELEGATION",16777216)  
    $userAccountControlHashTable.Add("PARTIAL_SECRETS_ACCOUNT",67108864) 
 
    $userAccountControlHashTable = $userAccountControlHashTable.GetEnumerator() | Sort-Object -Property Value  
    return $userAccountControlHashTable 
} 
 
Function Get-UserAccountControlFlags($userInput) 
{     
        Set-UserAccountControlValueTable | ForEach-Object { 
        $binaryAnd = $_.value -band $userInput 
        if ($binaryAnd -ne "0") { Write-Output $_ } 
    } 
} 

$UACValue = GetUACAttr $user

#Translate the UAC flags into human readable form for placement into return info.
$Flags = Get-UserAccountControlFlags($UACValue)
$UACFlags = @()
ForEach ($Flag in $Flags)
	{
	$UACFlags += $Flag.Name
	}

function GetPwdLastSet 
    {
	param ([string]$username)
	Trap [Exception]
		{
		 #Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 WriteTo-StdOut "[info]:An exception occurred." -shortformat
		 WriteTo-StdOut "[info]: Exception.Message $ExceptionMessage."
		 WriteTo-ErrorDebugReport -ErrorRecord $_
		 $Error.Clear()
		 continue
		}
    $ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $RootString = "GC://" + $ForestInfo.Name
    $Root = New-Object  System.DirectoryServices.DirectoryEntry($RootString)
    $searcher = New-Object DirectoryServices.DirectorySearcher($Root)
    $searcher.Filter="(&(samaccountname=$username))"
    $results=$searcher.findone()
	if ($null -ne $results)
		{
		$LastTime = $results.properties.pwdlastset[0]
   		[datetime]$Time = [datetime]::fromfiletime($LastTime)
		return $Time
		}
    }

	
function GetUserDN 
    {
	param ([string]$username)
	$ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
	$RootString = "GC://" + $ForestInfo.Name
	$Root = New-Object  System.DirectoryServices.DirectoryEntry($RootString)
	$searcher = New-Object DirectoryServices.DirectorySearcher($Root)
	$searcher.Filter="(&(samaccountname=$username))"
	$results=$searcher.findone()
		if ($null -ne $results)
			{
			$DN = $results.properties.distinguishedname[0]
			return $DN
			}
	}


if ($LoggedOnLocally -eq $false)
	{
	$ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
	$ComputerSite = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()
	$ComputerDomain= [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
	$UserDomain= [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
	$UserIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
	$UserName = $UserIdentity.Name
	$UserSID = $UserIdentity.User
	$AuthenticationType = $UserIdentity.AuthenticationType

	"User Logon Info" | Out-File $ExportFile -Append
	"***************************************" | Out-File $ExportFile -Append

	$UserDN = GetUserDN $user
	$UserPwdLastSet = GetPwdLastSet $user

	"Username is $username" | WriteTo-StdOut -shortformat
	"UserDN is $UserDN" | WriteTo-StdOut -shortformat
	"Userpwdlasstset is $UserPwdLastSet" | WriteTo-StdOut -shortformat

	#Gather the DC and GC which are responsive as well.
	$DomainDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
	$DCName = $DomainDSE.dnsHostName
	if (($DCName -contains '{') -or ($DCName -contains '}'))
		{
		$DCName = $DCName.ToString()
		$DCName = $DCName.Replace('{','')
		$DCName = $DCName.Replace('}','')
		}

	$GCDSE = New-Object System.DirectoryServices.DirectoryEntry("GC://RootDSE")
	$GCName = $GCDSE.dnsHostName
	if (($GCName -contains '{') -or ($GCName -contains '}'))
		{
		$GCName = $GCName.ToString()
		$GCName = $GCName.Replace('{','')
		$GCName = $GCName.Replace('}','')
		}
	$UserInfoObject = New-Object PSObject
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'User Name' -Value $UserName
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'User SID' -Value $UserSID
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'User Object DN' -Value $UserDN
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'User Password Last Set' -Value $UserPwdLastSet
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'UserAccountControl Value' -Value $UACFlags
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'Logon Authentication Method' -Value $AuthenticationType
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'User Domain' -Value $UserDomain
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'Computer Site' -Value $ComputerSite
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'Computer Role' -Value $RoleString
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'Computer Operating System' -Value $OSString
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'Computer Domain' -Value $ComputerDomain
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'Domain Controller' -Value $DCName
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'Global Catalog' -Value $GCName
	}

if ($LoggedOnLocally -eq $true)
	{
	$UserInfoObject = New-Object PSObject
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'User Name' -Value ($env:username)
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'User SID' -Value "[NONE]"
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'User Object DN' -Value "[Logged On To Local Computer]"
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'User Password Last Set' -Value "[Logged On To Local Computer]"
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'UserAccountControl Value' -Value "[Logged On To Local Computer]"
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'Logon Authentication Method' -Value "[Logged On To Local Computer]"
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'User Domain' -Value $Computername
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'Computer Site' -Value "[Logged On To Local Computer]"
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'Computer Role' -Value $RoleString
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'Computer Operating System' -Value $OSString
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'Computer Domain' -Value "[Logged On To Local Computer]"
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'Domain Controller' -Value "[Logged On To Local Computer]"
	Add-Member -InputObject $UserInfoObject -MemberType NoteProperty -Name 'Global Catalog' -Value "[Logged On To Local Computer]"



	}
$UserInfoObject | Out-File $ExportFile -Append

$UserInfoObject | WriteTo-StdOut -shortformat

#Add user details to the report.
$UserInfoReportObject = new-object PSObject
$TableString += "`t<tr><td></td><td></td></tr>`r`n"
$TableString = ("<table>`r`n`n" + $TableString + "</table>") 
add-member -inputobject $UserInfoReportObject -membertype noteproperty -name "User Logon Information" -value $TableString
$TableString = $null
$UserInfoReport = "__UserInfoReport"
# Write the Report
[string]$UserInputDesc = "User Logon Information"
$UserInfoObject | ConvertTo-Xml2 | update-diagreport -id $UserInfoReport -name $UserInputDesc -verbosity informational

CollectFiles -filesToCollect $ExportFile -fileDescription $FileDescription -sectionDescription $SectionDescription -renameOutput $false


# SIG # Begin signature block
# MIInpAYJKoZIhvcNAQcCoIInlTCCJ5ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBTkJ3T9hy0qBaw
# QlV5gJrs+u9lgY1tLBpuS7UB4mcVvaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGYQwghmAAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPaIb+mLhLpFp41wDM+NBcM+
# Pm7tks4IoA8My84PY1ZBMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCff1rXfKwGybO2icQnK8NK1S8Ez6RhCdAJTo7zmEosTXNwHStAAcW6
# 3xLlVTIvklqo23KHk+4IZVHYeft3iSGroCZYdkx3qX5Jh8hAT4r9ZsekgamgtkqK
# mfKql1h+7wEaUqnTUI7ku5h9hkZ315GWTl2mOe890xZXdlAyZx1KddvmHBheYlCp
# drQwqm3GEE8TLb6hcsFE4nelQwNZhWXyQX0ELzUzI1imVSIMV0oU59MQvSUPzSsj
# 3NWvYKiBabxTNPN1Wli+UmHBYXUyQQC1ZhNkV0zZuRqtNAbLWtkvdZOwYL9vsF6S
# IJ5WApIlcfUYVJMsbMVqp5Zb4XM9fHbaoYIXDDCCFwgGCisGAQQBgjcDAwExghb4
# MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIAhrvmlCsEFO5sJUra/1tbSRxF8ncBTuRYQLCywnzpp+AgZi2wZs
# WjYYEzIwMjIwODAxMDc1MTMzLjUzN1owBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0
# RDJGLUUzREQtQkVFRjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaCCEV8wggcQMIIE+KADAgECAhMzAAABsKHjgzLojTvAAAEAAAGwMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMDMw
# MjE4NTE0MloXDTIzMDUxMTE4NTE0Mlowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0RDJGLUUzREQtQkVF
# RjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAJzGbTsM19KCnQc5RC7VoglySXMKLut/
# yWWPQWD6VAlJgBexVKx2n1zgX3o/xA2ZgZ/NFGcgNDRCJ7mJiOeW7xeHnoNXPlg7
# EjYWulfk3oOAj6a7O15GvckpYsvLcx+o8Se8CrfIb40EJ8W0Qx4TIXf0yDwAJ4/q
# O94dJ/hGabeJYg4Gp0G0uQmhwFovAWTHlD1ci+sp36AxT9wIhHqw/70tzMvrnDF7
# jmQjaVUPnjOgPOyFWZiVr7e6rkSl4anT1tLv23SWhXqMs14wolv4ZeQcWP84rV2F
# rr1KbwkIa0vlHjlv4xG9a6nlTRfo0CYUQDfrZOMXCI5KcAN2BZ6fVb09qtCdsWdN
# NxB0y4lwMjnuNmx85FNfzPcMZjmwAF9aRUUMLHv626I67t1+dZoVPpKqfSNmGtVt
# 9DETWkmDipnGg4+BdTplvgGVq9F3KZPDFHabxbLpSWfXW90MZXOuFH8yCMzDJNUz
# eyAqytFFyLZir3j4T1Gx7lReCOUPw1puVzbWKspV7ModZjtN/IUWdVIdk3HPp4QN
# 1wwdVvdXOsYdhG8kgjGyAZID5or7C/75hyKQb5F0Z+Ee04uY9K+sDZ3l3z8TQZWA
# fYurbZCMWWnmJVsu5V4PR5PO+U6D7tAtMvMULNYibT9+sxVZK/WQer2JJ9q3Z7lj
# Fs4lgpmfc6AVAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUOt8BJDcBJm4dy6ASZHrX
# IEfWNj8wHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgw
# VjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWlj
# cm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUF
# BwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
# KS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQsFAAOCAgEA3XPih5sNtUfAyLnlXq6MZSpCh0TF+uG+nhIJ44//cMcQGEVi
# Z2N263NwvrQjCFOni/+oxf76jcmUhcKWLXk9hhd7vfFBhZZzcF5aNs07Uligs24p
# veasFuhmJ4y82OYm1G1ORYsFndZdvF//NrYGxaXqUNlRHQlskV/pmccqO3Oi6wLH
# cPB1/WRTLJtYbIiiwE/uTFEFEL45wWD/1mTCPEkFX3hliXEypxXzdZ1k6XqGTysG
# AtLXUB7IC6CH26YygKQuXG8QjcJBAUG/9F3yNZOdbFvn7FinZyNcIVLxld7h0bEL
# fQzhIjelj+5sBKhLcaFU0vbjbmf0WENgFmnyJNiMrL7/2FYOLsgiQDbJx6Dpy1Ef
# vuRGsdL5f+jVVds5oMaKrhxgV7oEobrA6Z56nnWYN47swwouucHf0ym1DQWHy2DH
# OFRRN7yv++zes0GSCOjRRYPK7rr1Qc+O3nsd604Ogm5nR9QqhOOc2OQTrvtSgXBS
# tu5vF6W8DPcsns53cQ4gdcR1Y9Ng5IYEwxCZzzYsq9oalxlH+ZH/A6J7ZMeSNKNk
# rXPx6ppFXUxHuC3k4mzVyZNGWP/ZgcUOi2qV03m6Imytvi1kfGe6YdCh32POgWeN
# H9lfKt+d1M+q4IhJLmX0E2ZZICYEb9Q0romeMX8GZ+cbhuNsFimJga/fjjswggdx
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
# Ooo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC0jCCAjsCAQEwgfyh
# gdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAn
# BgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjo0RDJGLUUzREQtQkVFRjElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAAp4vkN3fD5FN
# BVYZklZeS/JFPBiggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQUFAAIFAOaRYjswIhgPMjAyMjA4MDEwMDE5MDdaGA8yMDIy
# MDgwMjAwMTkwN1owdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pFiOwIBADAKAgEA
# AgIIYAIB/zAHAgEAAgIQpDAKAgUA5pKzuwIBADA2BgorBgEEAYRZCgQCMSgwJjAM
# BgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEB
# BQUAA4GBACIGRhs2npZ86ze5XX7bBRD/cJXce61yTudp0mcrK6L61CQtFKU97yxX
# 70q6VQobkjEyQHfH1Hv4CF/K4uK2KTMj1KexQaqMmfS1oHs0euVDl7Hao5qOdQzl
# rY+r47GbBQeZA0409+8Enz5PtxoLEgvTkrjuZhJN/8JtrfsuE8WfMYIEDTCCBAkC
# AQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGwoeODMuiN
# O8AAAQAAAbAwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG
# 9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgygB3CrmwnThW/Dc4wE+jdAbR6c/l8QGG
# RE3ezI6ykm4wgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCDNBgtDd8uf9KTj
# Gf1G67IfKmcNFJmeWTd6ilAy5xWEoDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAABsKHjgzLojTvAAAEAAAGwMCIEIFn307NRqWDFmauv
# lOK94kvWvU2F8vPBc3hLhZ9yD3zCMA0GCSqGSIb3DQEBCwUABIICAHThLfcpmrfY
# mjFJgO1elsfVH3BipwMyWXuAvO55wX5Je7hsxUradrLD5Glq7IgtqYmncVuDYrji
# EA7llPZqeRmuvyGSgjcNXlj944VmnXtSam0mlWO2lNSXPLBBxoSMs95wePPw6FJX
# TkfUKoEoj1a22BALRTxxvbGmtPlRLoS2chqn54BSJg41XW2XaSE/MEl7+OxVrkPw
# Mh9PFMB4CRNwXR71odLwGkbEacHZ0I3RFZ1pVCTIHiMF+6GIJx6Bsmc1R3IMcrLP
# ZxFXkTdpszGKgG3sdlfzUSqFl0AugKv6D7F1evEcZsKC3rOoR1NaqFNi9g8BmeB2
# hhFzHYdPgBN2vu8Ckdmn6DucZXgqTgXRPzLJKzVJ7uA7TtkfMyXpWUnb/G7Pm7wB
# nwEeL7GkMy14DJ9C94xEHSgi6mD0WWfKE4P75oFs3BsEQzWjD3f4WDzhNEl3F8X2
# HPGTBqPXtw9UNsyTkPcBhW5S9gzizVMUYlLfNPUt/LEdStcNCCsWs6m2aSBiFXmg
# drV8IK3tv8QLM+NH5StIXgMOy23VV/PLsQoK6QrvMPm859JDplv2pED8KshCkiOs
# MT/G/IzDAxc6uq77x85zLOcBkq+w8uH68fe01Fr8GRpfcHeSJDXnk+NRmrc8jhUa
# WzqCVn8kXni727ztz24du5SYIYke+a61
# SIG # End signature block
