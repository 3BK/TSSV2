#************************************************
# DC_BranchCache-Component.ps1
# Version x
# Date: 2009-2014
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: Collects information about the BranchCache Client Component.
#*******************************************************

Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
		 # later use return to return the exception message to an object:   return $Script:ExceptionMessage
	}

Import-LocalizedData -BindingVariable ScriptVariable
Write-DiagProgress -Activity $ScriptVariable.ID_CTSBranchCache -Status $ScriptVariable.ID_CTSBranchCacheDescription


function RunPS ([string]$RunPScmd="", [switch]$ft)
{
	$RunPScmdLength = $RunPScmd.Length
	"-" * ($RunPScmdLength)		| Out-File -FilePath $OutputFile -append
	"$RunPScmd"  				| Out-File -FilePath $OutputFile -append
	"-" * ($RunPScmdLength)  	| Out-File -FilePath $OutputFile -append
	
	if ($ft)
	{
		# This format-table expression is useful to make sure that wide ft output works correctly
		Invoke-Expression $RunPScmd	|format-table -autosize -outvariable $FormatTableTempVar | Out-File -FilePath $outputFile -Width 500 -append
	}
	else
	{
		Invoke-Expression $RunPScmd	| Out-File -FilePath $OutputFile -append
	}	
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
}




function RunNetSH ([string]$NetSHCommandToExecute="")
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSBranchCache -Status "netsh $NetSHCommandToExecute"
	
	$NetSHCommandToExecuteLength = $NetSHCommandToExecute.Length + 6
	"`n`n`n" + "-" * ($NetSHCommandToExecuteLength) + "`r`n" + "netsh $NetSHCommandToExecute" + "`r`n" + "-" * ($NetSHCommandToExecuteLength) | Out-File -FilePath $OutputFile -append

	$CommandToExecute = "cmd.exe /c netsh.exe " + $NetSHCommandToExecute + " >> $OutputFile "
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
}


$sectionDescription = "BranchCache"

#----------W8/WS2012 powershell cmdlets
# detect OS version and SKU
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber


$outputFile= $Computername + "_BranchCacheClient_info_pscmdlets.TXT"
"===================================================="									| Out-File -FilePath $OutputFile -append
"BranchCache Client Powershell Cmdlets"													| Out-File -FilePath $OutputFile -append
"===================================================="									| Out-File -FilePath $OutputFile -append
"Overview"																				| Out-File -FilePath $OutputFile -append
"----------------------------------------------------"									| Out-File -FilePath $OutputFile -append
"   1. Get-BCstatus"																	| Out-File -FilePath $OutputFile -append
"      This powershell cmdlet includes the following output:"							| Out-File -FilePath $OutputFile -append
"        Status Information              (Get-BCStatus).BranchCacheIsEnabled"			| Out-File -FilePath $OutputFile -append
"                                        (Get-BCStatus).BranchCacheServiceStartType"	| Out-File -FilePath $OutputFile -append
"                                        (Get-BCStatus).BranchCacheServiceStatus"		| Out-File -FilePath $OutputFile -append
"        ClientConfiguration             (Get-BCClientConfiguration)"					| Out-File -FilePath $OutputFile -append
"        HostedCacheServerConfiguration  (Get-BCHostedCacheServerConfiguration)"		| Out-File -FilePath $OutputFile -append
"        NetworkConfiguration            (Get-BCNetworkConfiguration)"					| Out-File -FilePath $OutputFile -append
"        HashCache                       (Get-BCHashCache)"								| Out-File -FilePath $OutputFile -append
"        DataCache                       (Get-BCDataCache and Get-BCDataCacheExtension)"| Out-File -FilePath $OutputFile -append
"===================================================="									| Out-File -FilePath $OutputFile -append
"`n"																					| Out-File -FilePath $OutputFile -append
"`n"																					| Out-File -FilePath $OutputFile -append
"`n"																					| Out-File -FilePath $OutputFile -append
"`n"																					| Out-File -FilePath $OutputFile -append
"`n"																					| Out-File -FilePath $OutputFile -append
#$SvcKey = "HKLM:\SYSTEM\CurrentControlSet\services\PeerDistSvc"
$bcServiceStatus = get-service * | Where-Object {$_.name -eq "PeerDistSvc"}	
if ($null -ne $bcServiceStatus)
{
	if ((Get-Service "PeerDistSvc").Status -eq 'Running')
	{
		#WS2012+
		if ($bn -gt 9000)
		{
			RunPS "Get-BCstatus" 		-ft 	# W8/WS2012, W8.1/WS2012R2	#fl
		}
		else
		{
			"This server is not running WS2012 or WS2012 R2. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"The `"PeerDistSvc`" service is not Running. Not running ps cmdlets." 	| Out-File -FilePath $OutputFile -append
	}
}
else
{
	"The `"PeerDistSvc`" service does not exist. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append
}

CollectFiles -filesToCollect $OutputFile -fileDescription "BranchCache pscmdlets output" -SectionDescription $sectionDescription







#----------Netsh
$OutputFile = $ComputerName + "_BranchCache_netsh_output.TXT"

"===================================================="		| Out-File -FilePath $OutputFile -append
"BranchCache Client Netsh Output"							| Out-File -FilePath $OutputFile -append
"===================================================="		| Out-File -FilePath $OutputFile -append
"Overview"													| Out-File -FilePath $OutputFile -append
"----------------------------------------"					| Out-File -FilePath $OutputFile -append
"   1. netsh branchcache show hostedcache"					| Out-File -FilePath $OutputFile -append
"   2. netsh branchcache show localcache"					| Out-File -FilePath $OutputFile -append
"   3. netsh branchcache show publicationcache"				| Out-File -FilePath $OutputFile -append
"   3. netsh branchcache show status all"					| Out-File -FilePath $OutputFile -append
"   3. netsh branchcache smb show latency"					| Out-File -FilePath $OutputFile -append
"===================================================="		| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
$bcServiceStatus = get-service * | Where-Object {$_.name -eq "PeerDistSvc"}	
if ($null -ne $bcServiceStatus)
{
	if ((Get-Service "PeerDistSvc").Status -eq 'Running')
	{
		#W7/WS2008R2+
		if ($bn -gt 7000)
		{
			RunNetSH -NetSHCommandToExecute "branchcache show hostedcache"
			RunNetSH -NetSHCommandToExecute "branchcache show localcache"
			RunNetSH -NetSHCommandToExecute "branchcache show publicationcache"
			RunNetSH -NetSHCommandToExecute "branchcache show status all"
			RunNetSH -NetSHCommandToExecute "branchcache smb show latency"
		}
		else
		{
			"This server is not running WS2012 or WS2012 R2. Not running netsh commands."	| Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"The `"PeerDistSvc`" service is not Running. Not running netsh commands." 	| Out-File -FilePath $OutputFile -append
	}
}
else
{
	"The `"PeerDistSvc`" service does not exist. Not running netsh commands."	| Out-File -FilePath $OutputFile -append
}
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append

CollectFiles -filesToCollect $OutputFile -fileDescription "BranchCache netsh output" -SectionDescription $sectionDescription





#----------Registry
$OutputFile= $Computername + "_BranchCache_reg_output.TXT"
$CurrentVersionKeys =	"HKLM\SOFTWARE\Policies\Microsoft\PeerDist",
						"HKLM\SYSTEM\CurrentControlSet\services\PeerDistKM",
						"HKLM\SYSTEM\CurrentControlSet\services\PeerDistSvc"

RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -OutputFile $OutputFile -fileDescription "BranchCache Registry Keys" -SectionDescription $sectionDescription





#----------BranchCache-Client EventLog
$sectionDescription = "BranchCache Eventlogs"
$EventLogNames = "Microsoft-Windows-BranchCache/Operational"
$Prefix = ""
$Suffix = "_evt_"
.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix

$EventLogNames = "Microsoft-Windows-BranchCacheSMB/Operational"
$Prefix = ""
$Suffix = "_evt_"
.\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBpJosgc1uukXQx
# Ss3Lpk1oc7ngV/IPI2VMhTTeHaD1sqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIG6uttxvA60/A5HpDQe6PasN
# S/5Twg0uhYhnlCPg++3bMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCxqzFy7V08K9+lp99Vg91B0HWIa1SprXTaOK4UyRAatUNWXf5BO0FD
# GRUH0qGaawDH+9bGRt7ozcGnjCgWg/zYGOv3bZ72AqQtxHU1i7a8dCHe1WZAJJYA
# zSuU/fnLs2dR6jiMldo1AVZNaNJ1ZF9AqnB/G7hG7E2YpEgNznBPBVbRIFjNqTvy
# KR45fEC8YbsP0WWwdf7ENdAxCUf8lngV1zcvKb0HfI1a5tvKHbL665KM7kvy+T3B
# f3K/xUThAlbQXMHl1DKNmpxZkbOwswmhe417QpHc6s3NHV0EmRRBUQVEMwvsEE9F
# tHnVf61zsAnsA1cWxa+bvH50aHWaiODqoYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIEB+EHRq3/ENuqoIPXzk7xDj7pufOc8ZFQr0/b1QDHNnAgZi3n80
# 0ToYEzIwMjIwODAxMDczNTI3LjU4MVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
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
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIAvWnnN0z/nMnQYeLY8m
# vCxbIVqqqEnce7JwYzqKGrQjMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# ZndHMdxQV1VsbpWHOTHqWEycvcRJm7cY69l/UmT8j0UwgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYm0v4YwhBxLjwABAAABiTAiBCAk
# t45JlrVvo3nFtAGQW8QKtuen+cccumsnztg/aYVKETANBgkqhkiG9w0BAQsFAASC
# AgAhAGYdh8UYTF9V628NtmdbG/Gxxecp7j/muhCqfwIyYhoYZactjnaPHLpbg9os
# 9EbeTBVBN8+YgxTTul1wPNo4XlwjA678Xt0XcXZLvFyAjlSEP/g9cQoJOWYFsEvv
# zdf75zHaAupG4ql9qFQzv8YZakHEBMI9tWiToztkhJOFuy4x9dVxUtT8OeEuRcoL
# yoUf8pEK9o4ip9Ir87BayT6ZDcUmJYBWK2HGMJkG7/gQAq8021EescX6w6xQdIzY
# VIdLSglZnmRBz3g+drDZzpbPYvT0MF42HjWfdbMwt+PpG4Dl6Ym5soPwgkjzIky/
# ev/lS3SL02ucrzP4A+Ez8FxqCHXQmNURNrGF88Z6cK/rLaNa+QIUhQV8QJSGYu32
# HuFKAHYLcvIjtNk8mrlK7X/xXxJIafXiSOR5WpUMfefbH+dPQGd61Voi8PVBKk1h
# Lx5+Kv2mld3sG9VmMZY1o23YLc3DEmiksfPBGUKEZpLpBWs5xKgSMPyU+UDW1UCg
# 2/+7hycNg9oI/Rd4xtsn33XvLyyHXtXHQkOlUmeR+uvHR/RScqRAR5OPyPUl/Fzq
# AVL58HNE72nn8pCgRefmBgCpxE5PSfSrHZIWlaQP5nckrVsBrsVDIxgF9m+JrTdl
# 9YiAwyDlQTbxXXGJ/jVYYXxQ0+p99KjkUJEnWmOBg/dNDw==
# SIG # End signature block
