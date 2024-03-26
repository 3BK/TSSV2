#************************************************
# DC_AppxCollect.ps1
# Version 1.1
# Date: 2009-2019
# Author: Walter Eder (waltere@microsoft.com)
# Description: Collects AppX additional information.
# Called from: TS_AutoAddCommands_Apps.ps1
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

Write-verbose "$(Get-Date -UFormat "%R:%S") : Start of script DC_AppxCollect.ps1"

"\n\n==================== Starting AppXCollect.ps1 script ====================\n\n" | WriteTo-StdOut
Import-LocalizedData -BindingVariable ScriptStrings

# Registry keys
"Getting Appx Registry Keys" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_AppxRegistryKeys_Title -Status $ScriptStrings.ID_AppxRegistryKeys_Status
$sectionDescription = "Software Registry keys"
$Regkeys = "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer"
$OutputFile = $ComputerName + "_reg_AppContainer_HKCU.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "HKCU AppContainer Registry Key" -SectionDescription $sectionDescription

$Regkeys =  "HKLM\Software\Microsoft\Windows\CurrentVersion\AppModel","HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel"
$OutputFile = $ComputerName + "_reg_AppModel.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "AppModel Registry Key" -SectionDescription $sectionDescription

$Regkeys = "HKLM\Software\Microsoft\Windows\CurrentVersion\Appx"
$OutputFile = $ComputerName + "_reg_Appx_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "HKLM Appx Registry Key" -SectionDescription $sectionDescription

$Regkeys = "HKLM\Software\Policies\Microsoft\Windows\AppX"
$OutputFile = $ComputerName + "_reg_AppxPolicies_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "HKLM Appx Policies Registry Key" -SectionDescription $sectionDescription

$Regkeys = "HKLM\Software\Microsoft\Windows\Windows Error Reporting\BrokerUp"
$OutputFile = $ComputerName + "_reg_BrokerUp.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "WER BrokerUp Registry Key" -SectionDescription $sectionDescription

$Regkeys = "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel","HKLM\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel"
$OutputFile = $ComputerName + "_reg_LocalSettings_AppModel.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "LocalSettings AppModel Registry Key" -SectionDescription $sectionDescription

$Regkeys = "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\PluggableProtocols"
$OutputFile = $ComputerName + "_reg_PluggableProtocols_HKLM.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "HKLM PluggableProtocols Registry Key" -SectionDescription $sectionDescription

$Regkeys = "HKLM\Software\Microsoft\Windows\CurrentVersion\WebApplicationHost","HKCU\Software\Microsoft\Windows\CurrentVersion\WebApplicationHost"
$OutputFile = $ComputerName + "_reg_webApplicationHost.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "WebApplicationHost Registry Key" -SectionDescription $sectionDescription

$Regkeys = "HKLM\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages","HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages"
$OutputFile = $ComputerName + "_reg_AppModel_Repository.txt"
RegQuery -RegistryKeys $Regkeys -Recursive $true -OutputFile $OutputFile -fileDescription "WebApplicationHost Registry Key" -SectionDescription $sectionDescription


# Saved Directories
"Getting Appx Files" | WriteTo-StdOut
Write-DiagProgress  -Activity $ScriptStrings.ID_AppxFiles_Title -Status $ScriptStrings.ID_AppxFiles_Status
$sectionDescription = "Appx Files"
if(test-path "$env:SystemDrive\ProgramData\Microsoft\Windows\AppRepository")
{
	Write-DiagProgress  -Activity $ScriptStrings.ID_AppxFiles_Title -Status "AppRepository"
	$DesinationTempFolder = Join-Path ($PWD.Path) ([System.Guid]::NewGuid().ToString())
	Copy-Item "$env:SystemDrive\ProgramData\Microsoft\Windows\AppRepository" -Destination $DesinationTempFolder -Force -Recurse -ErrorAction SilentlyContinue
	CompressCollectFiles -filesToCollect $DesinationTempFolder -DestinationFileName "AppRepository.zip" -fileDescription "AppRepository files" -sectionDescription $sectionDescription -Recursive
	Remove-Item $DesinationTempFolder -Force -Recurse
}

if(test-path "$env:localappdata\Packages\Package.Metadata")
{
	Write-DiagProgress  -Activity $ScriptStrings.ID_AppxFiles_Title -Status "Package.Metadata"
	$DesinationTempFolder = Join-Path ($PWD.Path) ([System.Guid]::NewGuid().ToString())
	Copy-Item "$env:localappdata\Packages\Package.Metadata" -Destination $DesinationTempFolder -Force -Recurse -ErrorAction SilentlyContinue
	CompressCollectFiles -filesToCollect $DesinationTempFolder -DestinationFileName "PackageMetadata.zip" -fileDescription "PackageMetadata files" -sectionDescription $sectionDescription -Recursive
	Remove-Item $DesinationTempFolder -Force -Recurse
}

<# removed since all colecting all executables takes huge space and long time
if(test-path "$env:windir\SystemApps")
{
	$DesinationTempFolder = Join-Path ($PWD.Path) ([System.Guid]::NewGuid().ToString())
	Copy-Item "$env:windir\SystemApps" -Destination $DesinationTempFolder -Force -Recurse -ErrorAction SilentlyContinue
	CompressCollectFiles -filesToCollect $DesinationTempFolder -DestinationFileName "SystemApps.zip" -fileDescription "SystemApps files" -sectionDescription $sectionDescription -Recursive
	Remove-Item $DesinationTempFolder -Force -Recurse
}

if(test-path "$env:programFiles\WindowsApps")
{
	$DesinationTempFolder = Join-Path ($PWD.Path) ([System.Guid]::NewGuid().ToString())
	Copy-Item "$env:programFiles\WindowsApps" -Destination $DesinationTempFolder -Force -Recurse -ErrorAction SilentlyContinue
	CompressCollectFiles -filesToCollect $DesinationTempFolder -DestinationFileName "WindowsApps.zip" -fileDescription "WindowsApps files" -sectionDescription $sectionDescription -Recursive
	Remove-Item $DesinationTempFolder -Force -Recurse
}
#>

# Permission Data

# Directory Listings
"Getting Appx Directory Listings" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_DirListings_Title -Status $ScriptStrings.ID_DirListings_Status
$sectionDescription = "Appx Directory Listings"
<# removed
if(test-path "$env:SystemDrive\ProgramFiles\WindowsApps")
{	$OutputFile = $ComputerName + "_DirList_WindowsApps_1.txt"
	dir "$env:SystemDrive\ProgramFiles\WindowsApps"        >> $OutputFile
	CollectFiles -filesToCollect $OutputFile -fileDescription "WindowsApps Directory Listings" -sectionDescription $sectionDescription
}
#>
if(test-path "$env:windir\SystemApps")
{	$OutputFile = $ComputerName + "_DirList_SystemApps.txt"
	Get-ChildItem "$env:windir\SystemApps"        >> $OutputFile
	CollectFiles -filesToCollect $OutputFile -fileDescription "ProgramFiles SystemApps Directory Listings" -sectionDescription $sectionDescription
}
if(test-path "$env:ProgramFiles\WindowsApps")
{	$OutputFile = $ComputerName + "_DirList_WindowsApps.txt"
	Get-ChildItem "$env:ProgramFiles\WindowsApps"        >> $OutputFile
	CollectFiles -filesToCollect $OutputFile -fileDescription "ProgramFiles WindowsApps Directory Listings" -sectionDescription $sectionDescription
}
if(test-path "$env:windir\ImmersiveControlPanel")
{	$OutputFile = $ComputerName + "_DirList_ImmersiveControlPanel.txt"
	Get-ChildItem "$env:windir\ImmersiveControlPanel"                >> $OutputFile
	CollectFiles -filesToCollect $OutputFile -fileDescription "ImmersiveControlPanel Directory Listings" -sectionDescription $sectionDescription
}
if(test-path "$env:SystemDrive\Program Files\Internet Explorer")
{	$OutputFile = $ComputerName + "_DirList_InternetExplorer.txt"
	Get-ChildItem "$env:SystemDrive\Program Files\Internet Explorer" >> $OutputFile
	CollectFiles -filesToCollect $OutputFile -fileDescription "Internet Explorer Directory Listings" -sectionDescription $sectionDescription
}
if(test-path "$env:SystemDrive\Program Files (x86)\Internet Explorer")
{	$OutputFile = $ComputerName + "_DirList_InternetExplorerx86.txt"
	Get-ChildItem "$env:SystemDrive\Program Files (x86)\Internet Explorer" >> $OutputFile
	CollectFiles -filesToCollect $OutputFile -fileDescription "Internet Explorer(x86) Directory Listings" -sectionDescription $sectionDescription
}
if(test-path "$env:localappdata\Packages")
{	$OutputFile = $ComputerName + "_DirList_LocalAppData.txt"
	Get-ChildItem "$env:localappdata\Packages"                       >> $OutputFile
	CollectFiles -filesToCollect $OutputFile -fileDescription "Local Appdata Packages Directory Listings" -sectionDescription $sectionDescription
}
if(test-path "$env:SystemDrive\WindowApps")
{	$OutputFile = $ComputerName + "_DirList_WindowsAppx.txt"
	Get-ChildItem "$env:SystemDrive\WindowApps"                      >> $OutputFile
	CollectFiles -filesToCollect $OutputFile -fileDescription "SystemDrive WindowApps Directory Listings" -sectionDescription $sectionDescription
}


# Event Logs
"Getting Appx Event Logs" | WriteTo-StdOut
$sectionDescription = "Event Logs"
$EventLogNames = "Microsoft-Windows-AppXDeployment/Operational", "Microsoft-Windows-AppXDeploymentServer/Operational", 
				 "Microsoft-Windows-AppXDeploymentServer/Restricted"
Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription

$EventLogNames = "Microsoft-Windows-AppxPackaging/Operational"
Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription

$EventLogNames = "Microsoft-Windows-AppModel-Runtime/Admin"
Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription

$EventLogNames = "Microsoft-Windows-All-User-Install-Agent/Admin"
Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription

$EventLogNames = "Microsoft-Windows-AppHost/Admin"
Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription 

$EventLogNames = "Microsoft-Windows-CodeIntegrity/Operational"
Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription

$EventLogNames = "Microsoft-Windows-ApplicationResourceManagementSystem/Operational"
Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription

$EventLogNames = "Microsoft-Windows-SettingSync/Operational", "Microsoft-Windows-SettingSync/Debug"
Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription

$EventLogNames = "Microsoft-Windows-PackageStateRoaming"
Run-DiagExpression .\TS_GetEvents.ps1 -EventLogNames $EventLogNames -SectionDescription $sectionDescription


# Appx PowerShell Commandlet output
"Getting Appx Data" | WriteTo-StdOut
Write-DiagProgress -Activity $ScriptStrings.ID_AppxDataLogs_Title -Status $ScriptStrings.ID_AppxDataLogs_Status

$sectionDescription = "Appx Data"
$OutputFile = $ComputerName + "_Inventory_FL.txt"
Get-AppxPackage | Format-List | Out-File -FilePath $OutputFile -append
CollectFiles -filesToCollect $OutputFile -fileDescription "Appx Package Inventory FL" -sectionDescription $sectionDescription
$OutputFile = $ComputerName + "_AppxPackage.txt"
Get-AppxPackage | Select-Object * | Out-File -FilePath $OutputFile -append
CollectFiles -filesToCollect $OutputFile -fileDescription "Appx Package Inventory" -sectionDescription $sectionDescription
$OutputFile = $ComputerName + "_AppxLog.txt"
Get-AppxLog | Format-List | Out-File -FilePath $OutputFile -append 
CollectFiles -filesToCollect $OutputFile -fileDescription "Appx Log" -sectionDescription $sectionDescription


Write-verbose "$(Get-Date -UFormat "%R:%S") :   end of script DC_AppxCollect.ps1"


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDekr0zbDbF6+Tu
# y+hDPzwa67qQJNLR38/thc+ylb73DqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXgwghl0AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFiOjuIL/pMLvp5zTe1OA9b5
# BqI84y9tQAtG6knj7cL6MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQC03AqqHH17SFwonUf4tcrax8Rp2xSGPvfDMTA73fc4+giYjI1ja6vv
# GEz1lPQpGjC0OPwyOCcfnN5JZZivGdg8u4PMyOsHkHPRxQZByNFDm0Jrx9jV612b
# GiM8eliSjErYCPtbUBJShULi3S678+JsUPH8xOMwioLzIk29SEjU8pSZOPSHHTzw
# p3dTAwUTCbr9hXzzRxfH54LDptQ7z/+hGsrG0gXORWsackoTyCYnfPSoSwHAz3c2
# YwYKrVelxe8032GA61OVpOEqfxgdvtpC56lyur5pIBVFDNGNEHsyam7o3uWMhFOW
# Pm5PTLA3ZvZkAWx046uFZFnSWL19nuO2oYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIGuTunt3RHQdwGVR3BXiNGAuAxrkGZY9QiFIi8AuRPQwAgZi1tDS
# 3noYEzIwMjIwODAxMDczNTA2Ljg1OFowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkU1QTYt
# RTI3Qy01OTJFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAGVt/wN1uM3MSUAAQAAAZUwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTEyWhcNMjMwMjI4MTkwNTEyWjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RTVBNi1FMjdDLTU5MkUxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCfbUEMZ7ZLOz9aoRCeJL4hhT9Q8JZB2xaVlMNCt3bw
# hcTI5GLPrt2e93DAsmlqOzw1cFiPPg6S5sLCXz7LbbUQpLha8S4v2qccMtTokEaD
# QS+QJErnAsl6VSmRvAy0nlj+C/PaZuLb3OzY0ARw7UeCZLpyWPPH+k5MdYj6NUDT
# NoXqbzQHCuPs+fgIoro5y3DHoO077g6Ir2THIx1yfVFEt5zDcFPOYMg4yBi4A6Xc
# 3hm9tZ6w849nBvVKwm5YALfH3y/f3n4LnN61b1wzAx3ZCZjf13UKbpE7p6DYJrHR
# B/+pwFjG99TwHH6uXzDeZT6/r6qH7AABwn8fpYc1TmleFY8YRuVzzjp9VkPHV8Vz
# vzLL7QK2kteeXLL/Y4lvjL6hzyOmE+1LVD3lEbYho1zCt+F7bU+FpjyBfTC4i/wH
# sptb218YlbkQt1i1B6llmJwVFwCLX7gxQ48QIGUacMy8kp1+zczY+SxlpaEgNmQk
# fc1raPh9y5sMa6X48+x0K7B8OqDoXcTiECIjJetxwtuBlQseJ05HRfisfgFm09kG
# 7vdHEo3NbUuMMBFikc4boN9Ufm0iUhq/JtqV0Kwrv9Cv3ayDgdNwEWiL2a65InEW
# SpRTYfsCQ03eqEh5A3rwV/KfUFcit+DrP+9VcDpjWRsCokZv4tgn5qAXNMtHa8Ni
# qQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFKuX02ICFFdXgrcCBmDJfH5v/KkXMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAOCzNt4fJ+jOvQuq0Itn37IZrYNBGswAi+IAFM3YGK/wGQlEncgjmNBuac95
# W2fAL6xtFVfMfkeqSLMLqoidVsU9Bm4DEBjaWNOT9uX/tcYiJSfFQM0rDbrl8V4n
# M88RZF56G/qJW9g5dIqOSoimzKUt/Q7WH6VByW0sar5wGvgovK3qFadwKShzRYcE
# qTkHH2zip5e73jezPHx2+taYqJG5xJzdDErZ1nMixRjaHs3KpcsmZYuxsIRfBYOJ
# vAFGymTGRv5PuwsNps9Ech1Aasq84H/Y/8xN3GQj4P3MiDn8izUBDCuXIfHYk39b
# qnaAmFbUiCby+WWpuzdk4oDKz/sWwrnsoQ72uEGVEN7+kyw9+HSo5i8l8Zg1Ymj9
# tUgDpVUGjAduoLyHQ7XqknKmS9kJSBKk4okEDg0Id6LeKLQwH1e4aVeTyUYwcBX3
# wg7pLJQWvR7na2SGrtl/23YGQTudmWOryhx9lnU7KBGV/aNvz0tTpcsucsK+cZFK
# DEkWB/oUFVrtyun6ND5pYZNj0CgRup5grVACq/Agb+EOGLCD+zEtGNop4tfKvsYb
# 64257NJ9XrMHgpCib76WT34RPmCBByxLUkHxHq5zCyYNu0IFXAt1AVicw14M+czL
# YIVM7NOyVpFdcB1B9MiJik7peSii0XTRdl5/V/KscTaCBFz3MIIHcTCCBVmgAwIB
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
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs4wggI3AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjpFNUE2LUUyN0MtNTkyRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA0Y+CyLezGgVHWFNmKI1LuE/hY6ug
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRyb0wIhgPMjAyMjA4MDExMTQwNDVaGA8yMDIyMDgwMjExNDA0NVow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pHJvQIBADAKAgEAAgIkxQIB/zAHAgEA
# AgIRpDAKAgUA5pMbPQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAKnc4eja
# NHGQtFMYlnQrCSihDgi1yJVZFt/wcGCQwz+DF+61Te6N2mXCImPjnqxgiTFepbcl
# 3+vz8Ih+LX7oWetgl7QfhEgrr/oy7p1qZrMHe9n4TfsLDaALwstfsmSS0S4oshuH
# XWBEpiFeuVUOCNhOf8JxJQx3ns823StpSZGUMYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGVt/wN1uM3MSUAAQAAAZUwDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgMhKaZo7Tnm4ND0FkgG21fy3NC2UzRQywZ98yXaAzTCgwgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBc5kvhjZALe2mhIz/Qd7keVOmA/cC1
# dzKZT4ybLEkCxzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABlbf8DdbjNzElAAEAAAGVMCIEIIxp4HDnVtLykNRLgteiviwshiJRAVGl
# B2+QHsqdeu7HMA0GCSqGSIb3DQEBCwUABIICAEhn0MSXQMCsCMrheX+i0GF+XCH3
# UwOI521CvQ1w+MXgo1t7+65znOz9FNUHM883gcyiSO0sVpwEgvmS+w9vl0Irk/a/
# Sb2RUDSZqbhjT98sFkW5Ir4kLyD89UN4w0Nd+ADV0qmjwcaIwp65Q0/4ogTDSgjf
# 2MXc3JbebyBIGV6kpymNA51nqzkRnMsy2rseXxowUxxyyEA/VWhoyMqdfPE70G0F
# R/7ZigFSc/AuFFa0HXMjYdBlgMAHAjFGOfzmAGPmmiz7/7RR5louUa5Fgm3kvBmc
# UUnHFrMG+M/7w21iA8eEGiodCODD/0UnEdOLcT3BLkvECNzudnQNOzdNLskSfHp2
# fyx7iorBS0ulmSnPM0ImP5jxEE0PzFyfAikskNsumNK8MMUEeGRrBXa4pNfYLm6T
# ndnVr0JIlcTjV5lL54gxywd7T1dcnbJxYv1i/oLrgz0xY8z3jLzbUf5hVfurD+n5
# /PSeADno8KFT1dhOxSk/wqTJlckiHzcC2fe7ObyCuFTT50qbdalqTRbJHuYJuLIU
# /WQlWaAsx+oyV4KR6NOAIdzBh46BOCxGMXqUEOT+Ufuo7GehuwvsCzT5XtcgPLuJ
# kRbza6FJrn+o/Sh0aIQIdpfcJmHLge+Y63SqNtZzIuTudSd4l4NbQsS9uu8P67Qu
# toNvi2iLVV0QjDHo
# SIG # End signature block
