#************************************************
# DC_SMBServer-Component.ps1
# Version 1.0
# Date: 2009-2014
# Author: Boyd Benson (bbenson@microsoft.com)
# Description: Collects information about SMB Server.
# Called from: Networking Diags
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
Write-DiagProgress -Activity $ScriptVariable.ID_CTSSMBServer -Status $ScriptVariable.ID_CTSSMBServerDescription

function RunNet ([string]$NetCommandToExecute="")
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSSMBServer -Status "net $NetCommandToExecute"
	
	$NetCommandToExecuteLength = $NetCommandToExecute.Length + 6
	"`n`n`n" + "=" * ($NetCommandToExecuteLength) + "`r`n" + "net $NetCommandToExecute" + "`r`n" + "=" * ($NetCommandToExecuteLength) | Out-File -FilePath $OutputFile -append
	$CommandToExecute = "cmd.exe /c net.exe " + $NetCommandToExecute + " >> $OutputFile "
	
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
	"`n`n`n" | Out-File -FilePath $OutputFile -append
}


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
	"`n`n`n"	| Out-File -FilePath $OutputFile -append
}


$sectionDescription = "SMB Server"


#----------W8/WS2012 powershell cmdlets
# detect OS version and SKU
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber


$OutputFile= $Computername + "_SmbServer_info_pscmdlets.TXT"
"===================================================="	| Out-File -FilePath $OutputFile -append
"SMB Server Powershell Cmdlets"							| Out-File -FilePath $OutputFile -append
"===================================================="	| Out-File -FilePath $OutputFile -append
"   1. Get-SmbServerConfiguration"						| Out-File -FilePath $OutputFile -append
"   2. Get-SmbServerNetworkInterface"					| Out-File -FilePath $OutputFile -append
"   3. Get-SmbShare"									| Out-File -FilePath $OutputFile -append
"   4. Get-SmbMultichannelConnection"					| Out-File -FilePath $OutputFile -append
"   5. Get-SmbMultichannelConstraint"					| Out-File -FilePath $OutputFile -append
"   6. Get-SmbOpenFile"									| Out-File -FilePath $OutputFile -append
"   7. Get-SmbSession"									| Out-File -FilePath $OutputFile -append
"   8. Get-SmbWitnessClient"							| Out-File -FilePath $OutputFile -append
"   9. Get-SmbBandWidthLimit"							| Out-File -FilePath $OutputFile -append
"===================================================="	| Out-File -FilePath $OutputFile -append
"`n`n`n`n"	| Out-File -FilePath $OutputFile -append


$smbServerServiceStatus = get-service * | Where-Object {$_.name -eq "lanmanserver"}	
if ($null -ne $smbServerServiceStatus)
{
	if ((Get-Service "lanmanserver").Status -eq 'Running')
	{
		if ($bn -ge 9200)
		{
			# Reference:
			#	The basics of SMB PowerShell, a feature of Windows Server 2012 and SMB 3.0
			#   http://blogs.technet.com/b/josebda/archive/2012/06/27/the-basics-of-smb-powershell-a-feature-of-windows-server-2012-and-smb-3-0.aspx

			RunPS "Get-SmbServerConfiguration"			# W8/WS2012, W8.1/WS2012R2	#default fl
			RunPS "Get-SmbServerNetworkInterface"	-ft	# W8/WS2012, W8.1/WS2012R2	#default ft		
			RunPS "Get-SmbShare"					-ft	# W8/WS2012, W8.1/WS2012R2	#default ft
			#RunPS "Get-SmbShare | select Name, ScopeName, FolderEnumerationMode, Path, Description" -ft
			RunPS "Get-SmbShare | select Name, FolderEnumerationMode, Path, ShareState, ScopeName, CachingMode, LeasingMode, ContinuouslyAvailable, CATimeout, AvailabilityType" -ft
			RunPS "Get-SmbShare | select Name, EncryptData, SecurityDescriptor, Description" -ft
			RunPS "Get-SmbMultichannelConnection"	-ft	# W8/WS2012, W8.1/WS2012R2	#default ft			# run on both client and server
			RunPS "Get-SmbMultichannelConstraint"		# W8/WS2012, W8.1/WS2012R2	#default <unknown>	# run on both client and server
			RunPS "Get-SmbOpenFile"					-ft # W8/WS2012, W8.1/WS2012R2	#default ft	
			RunPS "Get-SmbSession"					-ft	# W8/WS2012, W8.1/WS2012R2	#default ft	
			RunPS "Get-SmbWitnessClient"				# W8/WS2012, W8.1/WS2012R2	#default <unknown>

			# Check if OS is W8.1/WS2012R2 and if the Windows Feature has been installed (FS-SMBBW)
			if ($bn -ge 9600)
			{
				if (Test-path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SmbBandwidthLimitFilter")
				{
					RunPS "Get-SmbBandWidthLimit"			# W8.1/WS2012R2				#default <unknown>
				}
				else
				{
					"The `"SMB Bandwidth Limit`" feature is not installed."			| Out-File -FilePath $OutputFile -append
				}
			}
			else
			{
				"The `"SMB Bandwidth Limit`" feature and the Get-SmbBandWidthLimit ps cmdlet are only available on WS2012R2."			| Out-File -FilePath $OutputFile -append
			}
		}
		else
		{
			"The powershell cmdlets are only available on W8/WS2012 and later."	| Out-File -FilePath $OutputFile -append
		}
	}
	else
	{
		"The `"Server`" service is not running. Not running pscmdlets."	| Out-File -FilePath $OutputFile -append
	}
}
else
{
	"The `"Server`" service does not exist. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append
}
CollectFiles -filesToCollect $OutputFile -fileDescription "SMB Server Information from Powershell cmdlets" -SectionDescription $sectionDescription

		<#
		The following cmdlets have not be included:

		Get-SmbDelegation
			This 
			PS C:\windows\system32> Get-SmbDelegation -SmbServer "."
			CheckDelegationPrerequisites : SMB Delegation cmdlets require the installation of the Active Directory module for Windows PowerShell.
			At C:\windows\system32\windowspowershell\v1.0\Modules\SmbShare\SmbScriptModule.psm1:72 char:14
			+     $check = CheckDelegationPrerequisites
			+              ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
				+ CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
				+ FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,CheckDelegationPrerequisites


		Get-SmbShareAccess
			PS C:\> Get-SmbShareAccess

			cmdlet Get-SmbShareAccess at command pipeline position 1
			Supply values for the following parameters:
			Name[0]: Get-SmbWitnessClient
			Name[1]:
			Get-SmbShareAccess : No MSFT_SMBShare objects found with property 'Name' equal to 'Get-SmbWitnessClient'.  Verify the value of the property and
			retry.
			At line:1 char:1
			+ Get-SmbShareAccess
			+ ~~~~~~~~~~~~~~~~~~
				+ CategoryInfo          : ObjectNotFound: (Get-SmbWitnessClient:String) [Get-SmbShareAccess], CimJobException
				+ FullyQualifiedErrorId : CmdletizationQuery_NotFound_Name,Get-SmbShareAccess
		#>

#----------Net Commands
$OutputFile= $Computername + "_SmbServer_info_net.txt"
"========================================"	| Out-File -FilePath $OutputFile -append
"SMB Server Net Commands"					| Out-File -FilePath $OutputFile -append
"========================================"	| Out-File -FilePath $OutputFile -append
"Overview"									| Out-File -FilePath $OutputFile -append
"----------------------------------------"	| Out-File -FilePath $OutputFile -append
"   1. net accounts"						| Out-File -FilePath $OutputFile -append
"   2. net config server"					| Out-File -FilePath $OutputFile -append
"   3. net session"							| Out-File -FilePath $OutputFile -append
"   4. net files"							| Out-File -FilePath $OutputFile -append
"   5. net share"							| Out-File -FilePath $OutputFile -append
"========================================"	| Out-File -FilePath $OutputFile -append
"`n`n`n`n`n" | Out-File -FilePath $OutputFile -append

RunNet "accounts"

$smbServerServiceStatus = get-service * | Where-Object {$_.name -eq "lanmanserver"}	
if ($null -ne $smbServerServiceStatus)
{
	if ((Get-Service "lanmanserver").Status -eq 'Running')
	{
		RunNet "config server"
		RunNet "session"
		RunNet "files"
		RunNet "share"
	}
	else
	{
		"The `"Server`" service is not running. Not running pscmdlets."	| Out-File -FilePath $OutputFile -append
	}
}
else
{
	"The `"Server`" service does not exist. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append
}
	
CollectFiles -filesToCollect $OutputFile -fileDescription "SMB Server Information (using net.exe)" -SectionDescription $sectionDescription

#----------Check if SMB Server (File and Printer Sharing) is installed, and then run the script
$SvcKey = "HKLM:\SYSTEM\CurrentControlSet\services\LanManServer"
if (Test-Path $SvcKey) 
{
	#----------Registry
	$OutputFile= $Computername + "_SmbServer_reg_output.TXT"
	$sectionDescription = "SMB Server"
	$CurrentVersionKeys =	"HKLM\SYSTEM\CurrentControlSet\services\LanManServer",
							"HKLM\SYSTEM\CurrentControlSet\services\SRV",
							"HKLM\SYSTEM\CurrentControlSet\services\SRV2",
							"HKLM\SYSTEM\CurrentControlSet\services\SRVNET",
							"HKLM\Software\Microsoft\Windows\Windows Error Reporting\FullLiveKernelReports"
	RegQuery -RegistryKeys $CurrentVersionKeys -Recursive $true -OutputFile $OutputFile -fileDescription "SMB Server registry output" -SectionDescription $sectionDescription
}

#W8/WS2012 and later
if ($bn -gt 9000)
{
	#----------SMBClient / Operational
	$sectionDescription = "SMBServer-Operational EventLogs"
	$EventLogNames = "Microsoft-Windows-SMBServer/Connectivity", "Microsoft-Windows-SMBServer/Operational", "Microsoft-Windows-SMBServer/Security", "Microsoft-Windows-SMBDirect/Operational"
	$Prefix = ""
	$Suffix = "_evt_"
	& "$global:ToolsPath`\TS_GetEvents.ps1" -EventLogNames $EventLogNames -SectionDescription $sectionDescription -Prefix $Prefix -Suffix $Suffix
}


# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCwIfY6VOBgfFf+
# Z1L036v4Zt1TxEmOPhgqd0gUG5YboqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINpdE+xMnfLa9IJZ5WVs0sVz
# JrSDj9cKoZdjr9ii11UlMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAIKsnFiTQTDever5OQoMMMmpnTIg1z9IjZU99W0yypPsjS1LIYw8BO
# yKvzUMOj3jfHZQnGfhSDYc7PzWnmWfYztMUbz/KKHtFwFSxprAzmTjlPQeZmmVEi
# E7KFo7DcAuio0J6U/37FFgNzcN42e13W/2/Y+l7KseyzK0/isKcIDjIyiEQs4GV7
# ltwlsg4eUsWrIPwwbKkyt0Qx4FsEc2j690tn+Hjw8mUNQhPioinziVr0wVhtXTXT
# xEeTEgxq5jQsBod7ZBfg+xg3UOgcanqtwXd7TEBR4/+bsTBR5gVcrWc+iRJ2T0u/
# QjL87ccu8CrgkGrzFoSJKWy8LTFuAF/6oYIW/TCCFvkGCisGAQQBgjcDAwExghbp
# MIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEILSUGZqxwVTNDk75V1kjrqyeyBcjYKA32tI3MyNW/OIpAgZi1/U5
# Xp8YEzIwMjIwODAxMDc1MTExLjA1OFowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjIyNjQt
# RTMzRS03ODBDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVDCCBwwwggT0oAMCAQICEzMAAAGYdrOMxdAFoQEAAQAAAZgwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTE1WhcNMjMwMjI4MTkwNTE1WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MjI2NC1FMzNFLTc4MEMxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDG1JWsVksp8xG4sLMnfxfit3ShI+7G1MfTT+5XvQzu
# AOe8r5MRAFITTmjFxzoLFfmaxLvPVlmDgkDi0rqsOs9Al9jVwYSFVF/wWC2+B76O
# ysiyRjw+NPj5A4cmMhPqIdNkRLCE+wtuI/wCaq3/Lf4koDGudIcEYRgMqqToOOUI
# V4e7EdYb3k9rYPN7SslwsLFSp+Fvm/Qcy5KqfkmMX4S3oJx7HdiQhKbK1C6Zfib+
# 761bmrdPLT6eddlnywls7hCrIIuFtgUbUj6KJIZn1MbYY8hrAM59tvLpeGmFW3Gj
# eBAmvBxAn7o9Lp2nykT1w9I0s9ddwpFnjLT2PK74GDSsxFUZG1UtLypi/kZcg9We
# nPAZpUtPFfO5Mtif8Ja8jXXLIP6K+b5LiQV8oIxFSBfgFN7/TL2tSSfQVcvqX1mc
# SOrx/tsgq3L6YAxI6Pl4h1zQrcAmToypEoPYNc/RlSBk6ljmNyNDsX3gtK8p6c7H
# CWUhF+YjMgfanQmMjUYsbjdEsCyL6QAojZ0f6kteN4cV6obFwcUEviYygWbedaT8
# 6OGe9LEOxPuhzgFv2ZobVr0J8hl1FVdcZFbfFN/gdjHZ/ncDDqLNWgcoMoEhwwzo
# 7FAObqKaxfB5zCBqYSj45miNO5g3hP8AgC0eSCHl3rK7JPMr1B+8JTHtwRkSKz/+
# cwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFG6RhHKNpsg3mgons7LR5YHTzeE3MB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBACT6B6F33i/89zXTgqQ8L6CYMHx9BiaHOV+wk53JOriCzeaLjYgRyssJhmnn
# J/CdHa5qjcSwvRptWpZJPVK5sxhOIjRBPgs/3+ER0vS87IA+aGbf7NF7LZZlxWPO
# l/yFBg9qZ3tpOGOohQInQn5zpV23hWopaN4c49jGJHLPAfy9u7+ZSGQuw14CsW/X
# RLELHT18I60W0uKOBa5Pm2ViohMovcbpNUCEERqIO9WPwzIwMRRw34/LgjuslHJo
# p+/1Ve/CfyNqweUmwepQHJrd+wTLUlgm4ENbXF6i52jFfYpESwLdAn56o/pj+grs
# d2LrAEPQRyh49rWvI/qZfOhtT2FWmzFw6IJvZ7CzT1O+Fc0gIDBNqass5QbmkOkK
# Yy9U7nFA6qn3ZZ+MrZMsJTj7gxAf0yMkVqwYWZRk4brY9q8JDPmcfNSjRrVfpYyz
# EVEqemGanmxvDDTzS2wkSBa3zcNwOgYhWBTmJdLgyiWJGeqyj1m5bwNgnOw6NzXC
# iVMzfbztdkqOdTR88LtAJGNRjevWjQd5XitGuegSp2mMJglFzRwkncQau1BJsCj/
# 1aDY4oMiO8conkmaWBrYe11QCS896/sZwSdnEUJak0qpnBRFB+THRIxIivCKNbxG
# 2QRZ8dh95cOXgo0YvBN5a1p+iJ3vNwzneU2AIC7z3rrIbN2fMIIHcTCCBVmgAwIB
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
# IEVTTjoyMjY0LUUzM0UtNzgwQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA8ywe/iF5M8fIU2aT6yQ3vnPpV5Og
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRnKMwIhgPMjAyMjA4MDEwODI4MTlaGA8yMDIyMDgwMjA4MjgxOVow
# dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5pGcowIBADAHAgEAAgISNDAHAgEAAgIR
# qTAKAgUA5pLuIwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAGW0b6G1nxJf
# Sz+162eIfZKEeCT5UlfEbylGeWHEIa2FOqerhClam6wPRPAJD+i5gmNDLWEXoJhE
# 9mfD/DNtILqESrGPO8DLhy1fGnzIFrHCh+Hmog+1BobdtTTDsZ63lI6Mp6+O44xP
# gtveVE5cjYmTGOZttcbmk0FXsnRiWdbDMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGYdrOMxdAFoQEAAQAAAZgwDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgzKEB4qIOKH/OUS9vO80YFPcM8wDkIBcANpxdJp8cK/YwgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCC/ps4GOTn/9wO1NhHM9Qfe0loB3slkw1FF
# 3r+bh21WxDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABmHazjMXQBaEBAAEAAAGYMCIEIITB9XHZkmFVJEo8WDGAMhrrxCbnPT0sQRQc
# 2rAtWwOFMA0GCSqGSIb3DQEBCwUABIICACS6fP1N6VBIEFh/6XP3RcBtzzgVHLku
# DSzgO+FzsFuyvKQi2bsYSAyxpVMSYmvEno97EJDz2c4XNXLJ9SAkudhXz8gj6Yjq
# dKRRbwWa1K08cN5vGlvFEJZoG8TqkDhGoBOr46tqvqibAG+mXwppQhZgmLW33g4f
# e1+wg5fd7Bt4038Yk4MNU0szBNEQC6f18qqha0aoPFoo06Tt2+AqCguEFI3gaFtE
# si3K4rfwp61etivPl3PVPE055H+T1eISc5etdD8PbE50bjWwsc67YECTS+ns9D2k
# vZoMS1YrnNhRWev+Fw8mXl2b5ataYRamAygKRxtovEf8B2oXCm16bMY0SDV7CGfH
# LylESFmjRlm232MkcvcIeamOLT1aGd8pooAIiV/304Fr+/dHBZclIvRYBKnzcfoS
# +0hHljieUT5w2UHoDG+BUrndzpcRfwFySAuC3W38T+ZoNBXnavuXl+DLDL4l9hkb
# OJpZClbRvIct8sEUbZXZ/1mGEYDj8usBBc8g2Y0lFR0Wq6jXRV9BFz27EDNBtpCf
# e2IrWrzXgh4Zw4KL5b7uU5kxnIxWmCrWMCwVD3v/+GD7PzCZekBdWQoOTVPkJUz/
# 7zWQWwFptq6kalQYWfCMfHgJknmas637YprAkRy69K3QXk7VPwhkmy+5gWJBR4wX
# mooKJU2nkAWc
# SIG # End signature block
