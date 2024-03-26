<#
.SYNOPSIS
   Module for extended installed Windows Updates report

.DESCRIPTION
   Collects information on installed Windows Updates and generates a report in .html format

.NOTES
   Authors    : Robert Klemencz (Microsoft) & Alexandru Olariu (Microsoft)
   Requires   : At least PowerShell 5.1 (This module is not for stand-alone use. It is used automatically from within the main MSRD-Collect.ps1 script)
   Version    : See MSRD-Collect.ps1 version
   Feedback   : Send an e-mail to MSRDCollectTalk@microsoft.com
#>

$msrdLogPrefix = "Core"
$WUFile = $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "UpdateHistory.html"
$Script:WUErrors

Function msrdPrintUpdate ([string]$Category,[string]$ID,[string]$Operation,[string]$Date,[string]$ClientID,[string]$InstalledBy,[string]$OperationResult,[string]$Title,[string]$Description,[string]$HResult,[string]$UnmappedResultCode) {

	if ($Category -eq "QFE hotfix") { $Category = "Other updates not listed in history" }

	if (-not [String]::IsNullOrEmpty($ID)) {
		$NumberHotFixID = msrdToNumber $ID
		if($NumberHotFixID.Length -gt 5) {
			$SupportLink = "http://support.microsoft.com/kb/$NumberHotFixID"
		}
	} else {
		$ID = ""
		$SupportLink = ""
	}

	if ([String]::IsNullOrEmpty($Date)) {
		$DateTime = ""
	} else {
		$DateTime = msrdFormatDateTime $Date -SortFormat
	}

	if ([String]::IsNullOrEmpty($Title)) {
		$Title = ""
	} else {
		if (($Title -like "*Security Update for Windows*") -or ($Title -like "*Cumulative Update for Windows*") -or ($Title -like "*Security Update for .NET*") -or ($Title -like "*Cumulative Update for .NET*") -or ($Title -like "*Cumulative Update Preview*")) {
			$Title = "<b>" + $Title.Trim() + "</b>"
		} else {
			$Title = $Title.Trim()
		}
	}

	if ([String]::IsNullOrEmpty($Description)) {
		$Description = ""
	} else {
		$Description = $Description.Trim()
	}

	switch($OperationResult) {
        'Completed successfully' { $tdcircle = "circle_green" }
        'Operation was aborted' { $tdcircle = "circle_red" }
		'Completed with errors' { $tdcircle = "circle_red" }
		'Failed to complete' { $tdcircle = "circle_red" }
        'In progress' { $tdcircle = "circle_blue" }
        default { $tdcircle = "circle_white" }
	}

	if ((-not [String]::IsNullOrEmpty($HResult)) -and ($HResult -ne 0)) {
		$HResultHex = msrdConvertToHex $HResult
		$HResultArray= msrdGetWUErrorCodes $HResultHex

		$errmsg = "Error code: $HResultHex"

		if ($HResultArray -ne $null) {
			$errmsg = $errmsg + " (" + $HResultArray[0] + " - " + $HResultArray[1] + ")"
		}

		$HResultHex2 = msrdConvertToHex $UnmappedResultCode
		$errmsg = "<tr><td width='10px'><div class='circle_red'></div></td><td colspan='3'></td><td colspan='3' style='background-color: #FFFFDD'>$errmsg [$HResultHex2]</td></tr>"
	}

	$DiagMessage = "<tr>
		<td width='10px'><div class='$tdcircle'></div></td>
		<td width='17%' style='padding-left: 5px;'>$Category</td>
		<td width='11%'>$Date</td>
		<td width='6%'>$Operation</td>
		<td width='11%'>$OperationResult</td>
		<td width='7%'><a href='$SupportLink' target='_blank'>$ID</a></td>
		<td><span title='$Description' style='cursor: pointer'>$Title</span></td>
	</tr>"

	Add-Content $WUFile $DiagMessage
	if ($errmsg) {
		Add-Content $WUFile $errmsg
	}
}

Function msrdGetHotFixFromRegistry {
	$RegistryHotFixList = @{}
	$UpdateRegistryKeys = @("HKLM:\SOFTWARE\Microsoft\Updates")

	#if $OSArchitecture -ne X86 , should be 64-bit machine. we also need to check HKLM:\SOFTWARE\Wow6432Node\Microsoft\Updates
	if($OSArchitecture -ne "X86")
	{
		$UpdateRegistryKeys += "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Updates"
	}

	foreach($RegistryKey in $UpdateRegistryKeys) {
		If(Test-Path $RegistryKey) {
			$AllProducts = Get-ChildItem $RegistryKey -Recurse | Where-Object {$_.Name.Contains("KB") -or $_.Name.Contains("Q")}

			foreach($subKey in $AllProducts) {
				if($subKey.Name.Contains("KB") -or $subKey.Name.Contains("Q")) {
					$HotFixID = msrdGetHotFixID $subKey.Name

					if($RegistryHotFixList.Keys -notcontains $HotFixID) {
						$Category = [regex]::Match($subKey.Name,"Updates\\(?<Category>.*?)[\\]").Groups["Category"].Value
						$HotFix = @{HotFixID=$HotFixID;Category=$Category}
						foreach($property in $subKey.Property)
						{
							$HotFix.Add($property,$subKey.GetValue($property))
						}
						$RegistryHotFixList.Add($HotFixID,$HotFix)
					}
				}
			}
		}
	}
	return $RegistryHotFixList
}

Function msrdGetHotFixID ($strContainID) {
	return [System.Text.RegularExpressions.Regex]::Match($strContainID,"(KB|Q)\d+(v\d)?").Value
}

Function msrdToNumber ($strHotFixID) {
	return [System.Text.RegularExpressions.Regex]::Match($strHotFixID,"([0-9])+").Value
}

Function msrdFormatStr ([string]$strValue,[int]$NumberofChars) {

	if([String]::IsNullOrEmpty($strValue)) {
		$strValue = " "
		return $strValue.PadRight($NumberofChars," ")
	} else {
		if($strValue.Length -lt $NumberofChars) {
			return $strValue.PadRight($NumberofChars," ")
		} else {
			return $strValue.Substring(0,$NumberofChars)
		}
	}
}

# dates with dd/mm/yy hh:mm:ss
Function msrdFormatDateTime ($dtLocalDateTime,[Switch]$SortFormat) {

	if([string]::IsNullOrEmpty($dtLocalDateTime)) { return "" }

	if($SortFormat.IsPresent) {
		# Obtain dates on yyyymmdddhhmmss
		return Get-Date -Date $dtLocalDateTime -Format "yyyyMMddHHmmss"
	} else {
		return Get-Date -Date $dtLocalDateTime -Format G
	}
}

Function msrdValidatingDateTime ($dateTimeToValidate) {

	if([String]::IsNullOrEmpty($dateTimeToValidate)) { return $false }

	$ConvertedDateTime = Get-Date -Date $dateTimeToValidate

	if($ConvertedDateTime -ne $null) {
		if(((Get-Date) - $ConvertedDateTime).Days -le $NumberOfDays) { return $true }
	}

	return $false
}

Function msrdGetOSSKU ($SKU) {

	switch ($SKU) {
		0  {return ""}
		1  {return "Ultimate Edition"}
		2  {return "Home Basic Edition"}
		3  {return "Home Basic Premium Edition"}
		4  {return "Enterprise Edition"}
		5  {return "Home Basic N Edition"}
		6  {return "Business Edition"}
		7  {return "Standard Server Edition"}
		8  {return "Datacenter Server Edition"}
		9  {return "Small Business Server Edition"}
		10 {return "Enterprise Server Edition"}
		11 {return "Starter Edition"}
		12 {return "Datacenter Server Core Edition"}
		13 {return "Standard Server Core Edition"}
		14 {return "Enterprise Server Core Edition"}
		15 {return "Enterprise Server Edition for Itanium-Based Systems"}
		16 {return "Business N Edition"}
		17 {return "Web Server Edition"}
		18 {return "Cluster Server Edition"}
		19 {return "Home Server Edition"}
		20 {return "Storage Express Server Edition"}
		21 {return "Storage Standard Server Edition"}
		22 {return "Storage Workgroup Server Edition"}
		23 {return "Storage Enterprise Server Edition"}
		24 {return "Server For Small Business Edition"}
		25 {return "Small Business Server Premium Edition"}
		175 {return "Enterprise for Virtual Desktops Edition"}
	}
}

Function msrdGetOS() {

	$WMIOS = Get-WmiObject -Class Win32_OperatingSystem
	$StringOS = $WMIOS.Caption

	if($WMIOS.CSDVersion -ne $null) {
		$StringOS += " - " + $WMIOS.CSDVersion
	}

	if(($WMIOS.OperatingSystemSKU -ne $null) -and ($WMIOS.OperatingSystemSKU.ToString().Length -gt 0)) {
		$StringOS += " ("+(msrdGetOSSKU $WMIOS.OperatingSystemSKU)+")"
	}

	return $StringOS
}

# Query SID of an object using WMI and return the account name
Function msrdConvertSIDToUser([string]$strSID)  {

	if([string]::IsNullOrEmpty($strSID)) { return }

	if($strSID.StartsWith("S-1-5")) {
		$UserSIDIdentifier = New-Object System.Security.Principal.SecurityIdentifier `
    	($strSID)
		$UserNTAccount = $UserSIDIdentifier.Translate( [System.Security.Principal.NTAccount])
		if($UserNTAccount.Value.Length -gt 0) {
			return $UserNTAccount.Value
		} else {
			return $strSID
		}
	}
	return $strSID
}

Function msrdConvertToHex([int]$number) {
	return ("0x{0:x8}" -f $number)
}

Function msrdGetUpdateOperation($Operation) {

	switch ($Operation) {
		1 { return "Install" }
		2 { return "Uninstall" }
		Default { return "Unknown("+$Operation+")" }
	}
}

Function msrdGetUpdateResult($ResultCode) {

	switch ($ResultCode) {
		0 { return "Not started" }
		1 { return "In progress" }
		2 { return "Completed successfully" }
		3 { return "Completed with errors" }
		4 { return "Failed to complete" }
		5 { return "Operation was aborted" }
		Default { return "Unknown("+$ResultCode+")" }
	}
}

Function msrdGetWUErrorCodes($HResult) {

	if($Script:WUErrors -eq $null) {

		$WUErrorsFilePath = Join-Path $PSScriptRoot "MSRDC-WUErrors.xml"

		if(Test-Path $WUErrorsFilePath) {
			[xml] $Script:WUErrors = Get-Content $WUErrorsFilePath
		} else {
			"[Error]: Did not find the WUErrors.xml file, can not load all WU errors" | Out-File -Append ($global:msrdErrorLogFile)
		}
	}

	$WUErrorNode = $Script:WUErrors.ErrV1.err | Where-Object {$_.n -eq $HResult}

	if($WUErrorNode -ne $null) {
		$WUErrorCode = @()
		$WUErrorCode += $WUErrorNode.name
		$WUErrorCode += $WUErrorNode."#text"
		return $WUErrorCode
	}
	return $null
}


# Start here
Function msrdRunUEX_MSRDWU {

	msrdLogMessage Normal "[$msrdLogPrefix] Exporting Windows Update history"

	msrdCreateLogFolder $global:msrdSysInfoLogFolder

	$global:msrdGetos = msrdGetOS

	msrdHtmlInit $WUFile
	msrdHtmlHeader -htmloutfile $WUFile -title "Update History : $($env:computername)" -fontsize "11px"
    msrdHtmlBodyWU -htmloutfile $WUFile -title "Update History for $global:msrdFQDN"

	# Get updates from the com object
	$Session = New-Object -ComObject Microsoft.Update.Session
	$Searcher = $Session.CreateUpdateSearcher()
	$HistoryCount = $Searcher.GetTotalHistoryCount()

	if ($HistoryCount -gt 0) {
		$ComUpdateHistory = $Searcher.QueryHistory(1,$HistoryCount)
	} else {
		$ComUpdateHistory = @()
		"`nNo updates found on Microsoft.Update.Session`n" | Out-File -Append $global:msrdOutputLogFile
	}

	# Get updates from the Wmi object Win32_QuickFixEngineering
	$QFEHotFixList = New-Object "System.Collections.ArrayList"
	$QFEHotFixList.AddRange(@(Get-WmiObject -Class Win32_QuickFixEngineering))

	# Get updates from the regsitry keys
	$RegistryHotFixList = msrdGetHotFixFromRegistry

	# Format each update history to the stringbuilder
	foreach($updateEntry in $ComUpdateHistory) {

		# Do not list the updates on which the $updateEntry.ServiceID = '117CAB2D-82B1-4B5A-A08C-4D62DBEE7782' or '855e8a7c-ecb4-4ca3-b045-1dfa50104289'. These are Windows Store updates and are bringing inconsistent results
		if (($updateEntry.ServiceID -ne '117CAB2D-82B1-4B5A-A08C-4D62DBEE7782') -and ($updateEntry.ServiceID -ne '855e8a7c-ecb4-4ca3-b045-1dfa50104289')) {

			$HotFixID = msrdGetHotFixID $updateEntry.Title
			$HotFixIDNumber = msrdToNumber $HotFixID
			$strInstalledBy = ""
			$strSPLevel = ""

			if(($HotFixID -ne "") -or ($HotFixIDNumber -ne "")) {
				foreach($QFEHotFix in $QFEHotFixList) {
					if(($QFEHotFix.HotFixID -eq $HotFixID) -or ((msrdToNumber $QFEHotFix.HotFixID) -eq $HotFixIDNumber)) {
						$strInstalledBy = msrdConvertSIDToUser $QFEHotFix.InstalledBy
						$strSPLevel = $QFEHotFix.ServicePackInEffect

						#Remove the duplicate HotFix in the QFEHotFixList
						$QFEHotFixList.Remove($QFEHotFix)
						break
					}
				}
			}

			# Remove the duplicate HotFix in the RegistryHotFixList
			if ($RegistryHotFixList.Keys -contains $HotFixID) { $RegistryHotFixList.Remove($HotFixID) }

			$strCategory = ""
			if($updateEntry.Categories.Count -gt 0) { $strCategory = $updateEntry.Categories.Item(0).Name }

			if ([String]::IsNullOrEmpty($strCategory)) { $strCategory = "(None)" }

			$strOperation = msrdGetUpdateOperation $updateEntry.Operation
			$strDateTime = msrdFormatDateTime $updateEntry.Date
			$strResult = msrdGetUpdateResult $updateEntry.ResultCode

			msrdPrintUpdate $strCategory $HotFixID $strOperation $strDateTime $updateEntry.ClientApplicationID $strInstalledBy $strResult $updateEntry.Title $updateEntry.Description $updateEntry.HResult $updateEntry.UnmappedResultCode
		}
	}

	Add-Content $WUFile "</table></div></details>
	<details open>
		<summary>
			<a name='QFE'></a><b>Other - QFE</b><span class='b2top'><a href='#'>^top</a></span>
		</summary>
		<div class='detailsP'>
			<table class='tduo'>
				<tr style='text-align: left;'>
					<th width='10px'><div class='circle_no'></div></th><th style='padding-left: 5px;'>Category</th><th>Date/Time</th><th>Operation</th><th>Result</th><th>KB</th><th>Description</th>
				</tr>"
	# Output the Non History QFEFixes
	foreach($QFEHotFix in $QFEHotFixList) {
		$strInstalledBy = msrdConvertSIDToUser $QFEHotFix.InstalledBy
		$strDateTime = msrdFormatDateTime $QFEHotFix.InstalledOn
		$strCategory = ""

		# Remove the duplicate HotFix in the RegistryHotFixList
		if($RegistryHotFixList.Keys -contains $QFEHotFix.HotFixID) {
			$strCategory = $RegistryHotFixList[$QFEHotFix.HotFixID].Category
			$strRegistryDateTime = msrdFormatDateTime $RegistryHotFixList[$QFEHotFix.HotFixID].InstalledDate

			if ([String]::IsNullOrEmpty($strInstalledBy)) {
				$strInstalledBy = $RegistryHotFixList[$QFEHotFix.HotFixID].InstalledBy
			}

			$RegistryHotFixList.Remove($QFEHotFix.HotFixID)
		}

		if ([string]::IsNullOrEmpty($strCategory)) {
			$strCategory = "QFE hotfix"
		}

		if ($strDateTime.Length -eq 0) {
			$strDateTime = $strRegistryDateTime
		}

		if ([string]::IsNullOrEmpty($QFEHotFix.Status)) {
			$strResult = "Completed successfully"
		} else {
			$strResult = $QFEHotFix.Status
		}

		msrdPrintUpdate $strCategory $QFEHotFix.HotFixID "Install" $strDateTime "" $strInstalledBy $strResult $QFEHotFix.Description $QFEHotFix.Caption
	}

	Add-Content $WUFile "</table></div></details>
	<details open>
		<summary>
			<a name='REG'></a><b>Other - Registry</b><span class='b2top'><a href='#'>^top</a></span>
		</summary>
		<div class='detailsP'>
			<table class='tduo'>
				<tr style='text-align: left;'>
					<th width='10px'><div class='circle_no'></div></th><th style='padding-left: 5px;'>Category</th><th>Date/Time</th><th>Operation</th><th>Result</th><th>KB</th><th>Description</th>
				</tr>"
	# Generating information for updates found on registry
	foreach ($key in $RegistryHotFixList.Keys) {
		$strCategory = $RegistryHotFixList[$key].Category
		$HotFixID = $RegistryHotFixList[$key].HotFixID
		$strDateTime = $RegistryHotFixList[$key].InstalledDate
		$strInstalledBy = $RegistryHotFixList[$key].InstalledBy
		$ClientID = $RegistryHotFixList[$key].InstallerName

		if ($HotFixID.StartsWith("Q")) {
			$Description = $RegistryHotFixList[$key].Description
		} else {
			$Description = $RegistryHotFixList[$key].PackageName
		}

		if ([string]::IsNullOrEmpty($Description)) {
			$Description = $strCategory
		}

		msrdPrintUpdate $strCategory $HotFixID "Install" $strDateTime $ClientID $strInstalledBy "Completed successfully" $strCategory $Description
	}

	# Creating output files
	msrdHtmlEnd $WUFile
}

Export-ModuleMember -Function msrdRunUEX_MSRDWU
# SIG # Begin signature block
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAbrZdUqlp2ntpQ
# VXiK0L/Y8qk9TjXqDZgE8b08Xlk7sqCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
# esGEb+srAAAAAANOMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI5WhcNMjQwMzE0MTg0MzI5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDdCKiNI6IBFWuvJUmf6WdOJqZmIwYs5G7AJD5UbcL6tsC+EBPDbr36pFGo1bsU
# p53nRyFYnncoMg8FK0d8jLlw0lgexDDr7gicf2zOBFWqfv/nSLwzJFNP5W03DF/1
# 1oZ12rSFqGlm+O46cRjTDFBpMRCZZGddZlRBjivby0eI1VgTD1TvAdfBYQe82fhm
# WQkYR/lWmAK+vW/1+bO7jHaxXTNCxLIBW07F8PBjUcwFxxyfbe2mHB4h1L4U0Ofa
# +HX/aREQ7SqYZz59sXM2ySOfvYyIjnqSO80NGBaz5DvzIG88J0+BNhOu2jl6Dfcq
# jYQs1H/PMSQIK6E7lXDXSpXzAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnMc7Zn/ukKBsBiWkwdNfsN5pdwAw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMDUxNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAD21v9pHoLdBSNlFAjmk
# mx4XxOZAPsVxxXbDyQv1+kGDe9XpgBnT1lXnx7JDpFMKBwAyIwdInmvhK9pGBa31
# TyeL3p7R2s0L8SABPPRJHAEk4NHpBXxHjm4TKjezAbSqqbgsy10Y7KApy+9UrKa2
# kGmsuASsk95PVm5vem7OmTs42vm0BJUU+JPQLg8Y/sdj3TtSfLYYZAaJwTAIgi7d
# hzn5hatLo7Dhz+4T+MrFd+6LUa2U3zr97QwzDthx+RP9/RZnur4inzSQsG5DCVIM
# pA1l2NWEA3KAca0tI2l6hQNYsaKL1kefdfHCrPxEry8onJjyGGv9YKoLv6AOO7Oh
# JEmbQlz/xksYG2N/JSOJ+QqYpGTEuYFYVWain7He6jgb41JbpOGKDdE/b+V2q/gX
# UgFe2gdwTpCDsvh8SMRoq1/BNXcr7iTAU38Vgr83iVtPYmFhZOVM0ULp/kKTVoir
# IpP2KCxT4OekOctt8grYnhJ16QMjmMv5o53hjNFXOxigkQWYzUO+6w50g0FAeFa8
# 5ugCCB6lXEk21FFB1FdIHpjSQf+LP/W2OV/HfhC3uTPgKbRtXo83TZYEudooyZ/A
# Vu08sibZ3MkGOJORLERNwKm2G7oqdOv4Qj8Z0JrGgMzj46NFKAxkLSpE5oHQYP1H
# tPx1lPfD7iNSbJsP6LiUHXH1MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
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
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJR0wT6+jtB05g8doelOenPI
# MzQ8PZ4UjQz/3z7KVhFlMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEA0cuFjBRuOqshHnJYPvCvZ850+DhH7bJDpF3d+c6BY7PE50AqHDsDz9g6
# L7aokbuyhSEj7d+waNv5IgF+STxI+dcTRDtHB53iG1DuEcox0ngczPx7EMFxqOkc
# ISyjPzXBmIjQmR5UyBmj6ugrdkYjzCo3zFU6McFSiGYjXIqv3ZNHQklQDmw7QVKP
# ZR3RWUYU0lLDLv3AAmGfs0dxh1v5w+zH00di8deau3rw2a9lERWSVlVownnCnRwE
# z7rLMnVFKnHLnSCsrp2IBJ7btzE3XtGUGBARr2l1biF1ZG7M16HI82iuCg+6l5Sl
# hKTvsXA+1R+P3/C1tj1K6m7+nW8sqaGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCC
# FuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCGvhQLbkFyIuA/1Nbtx3W0MX4sCTK5nBFNPYkpgr9UqAIGZF0U7BO/
# GBMyMDIzMDUyMzE0NDQ1NS43NTRaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpFNUE2LUUy
# N0MtNTkyRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVQwggcMMIIE9KADAgECAhMzAAABvvQgou6W1iDWAAEAAAG+MA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEy
# MloXDTI0MDIwMjE5MDEyMlowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkU1QTYtRTI3Qy01OTJFMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEApV/y2z7Da7nMu0tykLY8olh7Z03EqFNz3iFlMp9gOfVm
# ZABmheCc87RuPdQ2P+OHUJiqCQAWNuNSoI/Q1ixEw9AA657ldD8Z3/EktpmxKHHa
# vOhwQSFPcpTGFVXIxKCwoO824giyHPG84dfhdi6WU7f7D+85LaPB0dOsPHKKMGlC
# 9p66Lv9yQzvAhZGFmFhlusCy/egrz6JX/OHOT9qCwughrL0IPf47ULe1pQSEEihy
# 438JwS+rZU4AVyvQczlMC26XsTuDPgEQKlzx9ru7EvNV99l/KCU9bbFf5SnkN1mo
# UgKUq09NWlKxzLGEvhke2QNMopn86Jh1fl/PVevN/xrZSpV23rM4lB7lh7XSsCPe
# FslTYojKN2ioOC6p3By7kEmvZCh6rAsPKsARJISdzKQCMq+mqDuiP6mr/LvuWKin
# P+2ZGmK/C1/skvlTjtIehu50yoXNDlh1CN9B3QLglQY+UCBEqJog/BxAn3pWdR01
# o/66XIacgXI/d0wG2/x0OtbjEGAkacfQlmw0bDc02dhQFki/1Q9Vbwh4kC7VgAiJ
# A8bC5zEIYWHNU7C+He69B4/2dZpRjgd5pEpHbF9OYiAf7s5MnYEnHN/5o/bGO0aj
# Ab7VI4f9av62sC6xvhKTB5R4lhxEMWF0z4v7BQ5CHyMNkL+oTnzJLqnLVdXnuM0C
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBTrKiAWoYRBoPGtbwvbhhX6a2+iqjAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQDHlfu9c0ImhdBis1yj56bBvOSyGpC/rSSty+1F49Tf6fmFEeqxhwTTHVHOeIRN
# d8gcDLSz0d79mXCqq8ynq6gJgy2u4LyyAr2LmwzFVuuxoGVR8YuUnRtvsDH5J+un
# ye/nMkwHiC+G82h3uQ8fcGj+2H0nKPmUpUtfQruMUXvzLjV5NyRjDiCL5c/f5ecm
# z01dnpnCvE6kIz/FTpkvOeVJk22I2akFZhPz24D6OT6KkTtwBRpSEHDYqCQ4cZ+7
# SXx7jzzd7b+0p9vDboqCy7SwWgKpGQG+wVbKrTm4hKkZDzcdAEgYqehXz78G00mY
# ILiDTyUikwQpoZ7am9pA6BdTPY+o1v6CRzcneIOnJYanHWz0R+KER/ZRFtLCyBMv
# LzSHEn0sR0+0kLklncKjGdA1YA42zOb611UeIGytZ9VhNwn4ws5GJ6n6PJmMPO+y
# PEkOy2f8OBiuhaqlipiWhzGtt5UsC0geG0sW9qwa4QAW1sQWIrhSl24MOOVwNl/A
# m9/ZqvLRWr1x4nupeR8G7+DNyn4MTg28yFZRU1ktSvyBMUSvN2K99BO6p1gSx/wv
# SsR45dG33PDG5fKqHOgDxctjBU5bX49eJqjNL7S/UndLF7S0OWL9mdk/jPVHP2I6
# XtN0K4VjdRwvIgr3jNib3GZyGJnORp/ZMbY2Dv1mKcx7dTCCB3EwggVZoAMCAQIC
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
# U046RTVBNi1FMjdDLTU5MkUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAGitWlL3vPu8ENOAe+i2+4wfTMB7oIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoFrxpMCIYDzIwMjMwNTIzMTIxNTM3WhgPMjAyMzA1MjQxMjE1MzdaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOgWvGkCAQAwBwIBAAICFfEwBwIBAAICEbYw
# CgIFAOgYDekCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQB3fN0+c48sj81M
# P5M2a+VaMcHV1G+A2bZYpPxjoLmVpFYPWCKzwlmr9urjZU78+KZsUFC5wKqddnGV
# XVG8mAORC5JQ9+Ft2+h2dGRKSr7PYMXvW2BsZ2j0QTBMw0pZm9WdgTrjifmHeOcA
# B9/sMNA8zrdyhAdCl0a/waq6O6CF7DGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABvvQgou6W1iDWAAEAAAG+MA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIMERyY/UsbCxZ5gz8m7gcojaCNlJ9Y5gDxJbIoaYGohgMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQglO6Kr632/Oy9ZbXPrhEPidNAg/Fef7K3SZg+
# DxjhDC8wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# Ab70IKLultYg1gABAAABvjAiBCCd8JRvzTX0THpWOIGxsHMjBm7wnwd8sa+oSmZ7
# kHGR/DANBgkqhkiG9w0BAQsFAASCAgB7gaEu0t8MNPHskSbDdgbJ5cqrH1fF9Mj/
# XDH2GB5CqtAZz5yeMZEZbyfN049Fv0hVIbPVcyvjSBWo71zDsxcb1opB7g3NGK/z
# X/E8dTQQFRcyr3I7tPzC9vIa0t7UKbNott2CC7TT5GnqHROlZngpdDr44aaU2dK4
# i2+2nefuy5ctXJgi19SJ2DwugILLV6JaYTcwuerHZqVJQvJVGjVXKiizV+rzBjwf
# s/UnuAWFO0cvV+KmMlsrFMY96R6vTiGxnllCb4JyJEVgC6rm9bQNvkAV3WayYoKw
# VN6hP09ZaeMelZSPJKYweI/8DhsbrqZtEYs+KHLhX0rk/HeiDHBTXOGrLD1GNwws
# z6Q8C/YFOSHh+8V2QB4/SBgZnUk1jYdrhZBi4M9ZTMBYpkdAv0w7aTHwy0wiqGqJ
# zP08Lt+IRydRIPelsikfNbBBaINxeaUsSF1BFTtVtA7sCn6xOK7JdO9oVrLcisEK
# 7fR6q/ptOqLgzGafUfvc+7EQOMoshGywUua64aXj6ZwYCXR28f5kw3n/A4Q+FOFB
# p/GYiPELk89E7thRuTa4eBHX7795LXQkTOJZFO1lFNjDIS2/ouHDJ6+oB7hUVshy
# d8fYYo2BMfcmQZiCAkcLQLgkoSi0J5seeT8A6fwgdsgZ1AmhqE4QSNIRb/YBaGQU
# YuEHoQMf6A==
# SIG # End signature block
