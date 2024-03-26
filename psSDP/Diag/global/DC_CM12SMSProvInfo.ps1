# ***********************************************************************************************************
# Version 1.0
# Date: 01-24-2014
# Author: Vinay Pamnani - vinpa@microsoft.com
# Description: Collects data from SMS Provider
# ***********************************************************************************************************

trap [Exception]
{
	WriteTo-ErrorDebugReport -ErrorRecord $_
	continue
}

If (!$Is_SiteServer) {
	TraceOut "ConfigMgr Site Server not detected. This script gathers data only from a Site Server. Exiting."
	exit 0
}

If ($SiteType -eq 2) {
	TraceOut "Secondary Site Server detected. This script gathers data only from a Primary Site Server. Exiting."
	AddTo-CMServerSummary -Name "Boundaries" -Value "Not available on a Secondary Site" -NoToSummaryReport
	AddTo-CMServerSummary -Name "Cloud Services Info" -Value "Not available on a Secondary Site" -NoToSummaryReport
	AddTo-CMServerSummary -Name "Features Info" -Value "Not available on a Secondary Site" -NoToSummaryReport
	exit 0
}

function Get-BoundariesNotInAnyGroups ()
{
	param (
		$SMSProvServer,
		$SMSProvNamespace
	)

	process {
		$BoundaryNotInGroups = @()
		Get-CimInstance -Query "SELECT * FROM SMS_Boundary WHERE GroupCount = 0" -ComputerName $SMSProvServer -Namespace $SMSProvNamespace | `
			ForEach-Object {
				$BoundaryType = switch($_.BoundaryType) {
					0 {"IP Subnet"}
					1 {"AD Site"}
					2 {"IPv6 Prefix"}
					3 {"IP Range"}
					default {"Unknown"}
				}

				$Boundary = @{'BoundaryID'=$_.BoundaryID;
						'BoundaryType'=$BoundaryType;
						'DisplayName'=$_.DisplayName;
						'Value'=$_.Value;
						'SiteSystems'=$_.SiteSystems}

				$BoundaryObject = New-Object PSObject -Property $Boundary
				$BoundaryNotInGroups += $BoundaryObject
			}

		# $BoundaryNotInGroups | Select BoundaryID, BoundaryType, DisplayName, Value, SiteSystems | Sort BoundaryType | Format-Table -AutoSize
		return $BoundaryNotInGroups
	}
}

function Get-Boundaries ()
{
	param (
		$SMSProvServer,
		$SMSProvNamespace
	)

	process {
		# Boundary Groups
		$BoundaryResults  = "#######################`r`n"
		$BoundaryResults += "# All Boundary Groups #`r`n"
		$BoundaryResults += "#######################`r`n"
		$BoundaryGroups = Get-CimInstance -Query "SELECT * FROM SMS_BoundaryGroup LEFT JOIN SMS_BoundaryGroupSiteSystems ON SMS_BoundaryGroupSiteSystems.GroupId = SMS_BoundaryGroup.GroupId" -ComputerName $SMSProvServer -Namespace $SMSProvNamespace -ErrorAction SilentlyContinue -ErrorVariable WMIError
		If ($WMIError.Count -eq 0) {
			if ($null -ne $BoundaryGroups) {
				$BoundaryGroups = Get-BoundaryGroupsFromWmiResults -BoundaryGroupsFromWmi $BoundaryGroups
				$BoundaryResults += $BoundaryGroups | Sort-Object GroupID | Format-Table -AutoSize | Out-String -Width 2048
			}
			else {
				$BoundaryResults += "    None.`r`n`r`n"
			}
		}
		else {
			$BoundaryResults += "    ERROR: $($WMIError[0].Exception.Message)`r`n`r`n"
			$WMIError.Clear()
		}

		# Boundaries with multiple Sites for Assignment
		$BoundaryResults += "###################################################`r`n"
		$BoundaryResults += "# Boundaries set for Assignment to multiple Sites #`r`n"
		$BoundaryResults += "###################################################`r`n"
		$BoundariesWithAssignments = Get-CimInstance -Query "SELECT * FROM SMS_Boundary WHERE GroupCount > 0" -ComputerName $SMSProvServer -Namespace $SMSProvNamespace -ErrorAction SilentlyContinue -ErrorVariable WMIError
		If ($WMIError.Count -eq 0) {
			if ($null -ne $BoundariesWithAssignments) {
				$BoundaryMultipleAssignments = $BoundariesWithAssignments | ForEach-Object {$asc = $_.DefaultSiteCode | Where-Object {$_}; if ($asc.Count -gt 1) {$_}}
				if ($null -ne $BoundaryMultipleAssignments) {
					$BoundaryMultipleAssignments = Get-BoundariesFromWmiResults -BoundariesFromWmi $BoundaryMultipleAssignments
					$BoundaryResults += $BoundaryMultipleAssignments
				}
				else {
					$BoundaryResults += "`r`n    None.`r`n`r`n"
				}
			}
			else {
				$BoundaryResults += "`r`n    None.`r`n`r`n"
			}
		}
		else {
			$BoundaryResults += "    ERROR: $($WMIError[0].Exception.Message)`r`n`r`n"
			$WMIError.Clear()
		}

		# Boundaries not in any groups
		$BoundaryResults += "#########################################`r`n"
		$BoundaryResults += "# Boundaries not in any Boundary Groups #`r`n"
		$BoundaryResults += "#########################################`r`n"
		$BoundaryNotInGroups = 	Get-CimInstance -Query "SELECT * FROM SMS_Boundary WHERE GroupCount = 0" -ComputerName $SMSProvServer -Namespace $SMSProvNamespace -ErrorAction SilentlyContinue -ErrorVariable WMIError
		If ($WMIError.Count -eq 0) {
			if ($null -ne $BoundaryNotInGroups) {
				$BoundaryNotInGroups = Get-BoundariesFromWmiResults -BoundariesFromWmi $BoundaryNotInGroups
				$BoundaryResults += $BoundaryNotInGroups
			}
			else {
				$BoundaryResults += "`r`n    None.`r`n`r`n"
			}
		}
		else {
			$BoundaryResults += "`r`n    ERROR: $($WMIError[0].Exception.Message)`r`n`r`n"
			$WMIError.Clear()
		}

		# Members for each Boundary Group
		$BoundaryResults += "#############################`r`n"
		$BoundaryResults += "# Boundary Group Membership #`r`n"
		$BoundaryResults += "#############################`r`n`r`n"
		$Members = Get-CimInstance -Query "SELECT * FROM SMS_Boundary JOIN SMS_BoundaryGroupMembers ON SMS_BoundaryGroupMembers.BoundaryID = SMS_Boundary.BoundaryID" -ComputerName $SMSProvServer -Namespace $SMSProvNamespace -ErrorAction SilentlyContinue -ErrorVariable WMIError
		If ($WMIError.Count -eq 0) {
			if ($null -ne $Members) {
				#foreach ($Member in $($Members.SMS_BoundaryGroupMembers | Select GroupID -Unique)) { # Works with PowerShell 3.0
				foreach ($Member in $($Members | Select-Object -ExpandProperty SMS_BoundaryGroupMembers | Select-Object GroupID -Unique)) {  # Works with PowerShell 2.0
					$BoundaryResults += "Boundary Members for Boundary Group ID: $($Member.GroupId)`r`n"
					$BoundaryResults += "===================================================`r`n"
					$MembersWmi = $Members | Where-Object {$_.SMS_BoundaryGroupMembers.GroupID -eq $Member.GroupId} | Select-Object -ExpandProperty SMS_Boundary
					$MemberBoundary = Get-BoundariesFromWmiResults -BoundariesFromWmi $MembersWmi
					$BoundaryResults += $MemberBoundary
				}
			}
			else {
				$BoundaryResults += "    Boundary Groups have no members.`r`n`r`n"
			}
		}
		else {
			$BoundaryResults += "    ERROR: $($WMIError[0].Exception.Message)`r`n`r`n"
			$WMIError.Clear()
		}

		return $BoundaryResults
	}
}

function Get-BoundaryGroupsFromWmiResults ()
{
	param (
		$BoundaryGroupsFromWmi
	)

	$BoundaryGroups = @()

	foreach($Group in ($BoundaryGroupsFromWmi | Select-Object -ExpandProperty SMS_BoundaryGroup | Select-Object GroupId -Unique)) {
		$BoundaryGroupWmi = $BoundaryGroupsFromWmi | Select-Object -ExpandProperty SMS_BoundaryGroup | Where-Object {$_.GroupId -eq $Group.GroupId} | Select-Object -Unique
		$SiteSystems = ""
		$SiteSystems = $BoundaryGroupsFromWmi | Select-Object -ExpandProperty SMS_BoundaryGroupSiteSystems | Where-Object {$_.GroupId -eq $Group.GroupId} | Select-Object -ExpandProperty ServerNalPath `
			| ForEach-Object {$SiteSystem = $_; $SiteSystem.Split("\\")[2]}
		$BoundaryGroup = @{
			'GroupID'=$BoundaryGroupWmi.GroupID;
			'Name'=$BoundaryGroupWmi.Name;
			'AssignmentSiteCode'=$BoundaryGroupWmi.DefaultSiteCode
			'Shared'=$BoundaryGroupWmi.Shared;
			'MemberCount'=$BoundaryGroupWmi.MemberCount;
			'SiteSystemCount'=$BoundaryGroupWmi.SiteSystemCount;
			'SiteSystems'=$SiteSystems -join "; ";
			'Description'=$BoundaryGroupWmi.Description
		}

		$BoundaryGroupObject = New-Object PSObject -Property $BoundaryGroup
		$BoundaryGroups += $BoundaryGroupObject
	}

	return ($BoundaryGroups | Select-Object GroupID, Name, AssignmentSiteCode, Shared, MemberCount, SiteSystemCount, SiteSystems, Description)
}

function Get-BoundariesFromWmiResults ()
{
	param (
		$BoundariesFromWmi
	)

	$Boundaries = @()

	foreach ($BoundaryWmi in $BoundariesFromWmi)
	{
		$BoundaryType = switch($BoundaryWmi.BoundaryType) {
			0 {"IP Subnet"}
			1 {"AD Site"}
			2 {"IPv6 Prefix"}
			3 {"IP Range"}
			default {"Unknown"}
		}

		if (($BoundaryWmi.DefaultSiteCode | Where-Object {$_}).Count -gt 1) {
			$AssignmentSiteCode = $BoundaryWmi.DefaultSiteCode -join "; "
		}
		else {
			$AssignmentSiteCode = $BoundaryWmi.DefaultSiteCode -join ""
		}

		$Boundary = @{
			'BoundaryID'=$BoundaryWmi.BoundaryID;
			'DisplayName'=$BoundaryWmi.DisplayName;
			'BoundaryType'=$BoundaryType;
			'Value'=$BoundaryWmi.Value;
			'AssignmentSiteCode'=$AssignmentSiteCode;
			'SiteSystems'=$BoundaryWmi.SiteSystems -join "; "
		}

		$BoundaryObject = New-Object PSObject -Property $Boundary
		$Boundaries += $BoundaryObject
	}

	return ($Boundaries | Select-Object BoundaryID, DisplayName, BoundaryType, Value, AssignmentSiteCode, SiteSystems | Sort-Object BoundaryID | Format-Table -AutoSize | Out-String -Width 2048)
}

function Get-WmiOutput {
	Param(
		[Parameter(Mandatory=$false)]
	    [string]$ClassName,
		[Parameter(Mandatory=$false)]
	    [string]$Query,
		[Parameter(Mandatory=$false)]
	    [string]$DisplayName,
		[Parameter(Mandatory=$false)]
		[switch]$FormatList,
		[Parameter(Mandatory=$false)]
		[switch]$FormatTable
	)

	if ($DisplayName) {
		$DisplayText = $DisplayName
	}
	else {
		$DisplayText = $ClassName
	}

	$results =  "`r`n=================================`r`n"
	$results += " $DisplayText `r`n"
	$results += "=================================`r`n`r`n"

	if ($ClassName) {
		$Temp = Get-WmiData -ClassName $ClassName
	}

	if ($Query) {
		$Temp = Get-WmiData -Query $Query
	}

	if ($Temp) {
		if ($FormatList) {
			$results += ($Temp | Format-List | Out-String).Trim()
		}

		if ($FormatTable) {
			$results += ($Temp | Format-Table | Out-String -Width 500).Trim()
		}

		$results += "`r`n"
	}
	else {
		$results += "    No Instances.`r`n"
	}

	return $results
}

function Get-WmiData{
	Param(
	   [Parameter(Mandatory=$false)]
	   [string]$ClassName,
		[Parameter(Mandatory=$false)]
	   [string]$Query
	)

	if ($ClassName) {
		$Temp = Get-CimInstance -Computername $SMSProviderServer -Namespace $SMSProviderNamespace -Class $ClassName -ErrorVariable WMIError -ErrorAction SilentlyContinue
	}

	if ($Query) {
		$Temp = Get-CimInstance -Computername $SMSProviderServer -Namespace $SMSProviderNamespace -Query $Query -ErrorVariable WMIError -ErrorAction SilentlyContinue
	}

	if ($WMIError.Count -ne 0) {
		if ($WMIError[0].Exception.Message -eq "") {
			$results = $WMIError[0].Exception.ToString()
		}
		else {
			$results = $WMIError[0].Exception.Message
		}
		$WMIError.Clear()
		return $results
	}

	if (($Temp | Measure-Object).Count -gt 0) {
		$results = $Temp | Select-Object * -ExcludeProperty __GENUS, __CLASS, __SUPERCLASS, __DYNASTY, __RELPATH, __PROPERTY_COUNT, __DERIVATION, __SERVER, __NAMESPACE, __PATH, PSComputerName, Scope, Path, Options, ClassPath, Properties, SystemProperties, Qualifiers, Site, Container
	}
	else {
		$results = $null
	}

	return $results
}

TraceOut "Started"

Import-LocalizedData -BindingVariable ScriptStrings
$sectiondescription = "Configuration Manager Server Information"

TraceOut "    SMS Provider: $SMSProviderServer"
TraceOut "    SMS Provider Namespace: $SMSProviderNamespace"

# ===========
# Boundaries
# ===========
TraceOut "    Getting Boundaries from SMS Provider"
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CM07ServerInfo -Status $ScriptStrings.ID_SCCM_CMServerInfo_Boundary
$TempFileName = ($ComputerName + "_CMServer_Boundaries.TXT")
$OutputFile = join-path $pwd.path $TempFileName
$Temp = Get-Boundaries -SMSProvServer $SMSProviderServer -SMSProvNamespace $SMSProviderNamespace
$Temp | Out-File $OutputFile -Append
AddTo-CMServerSummary -Name "Boundaries" -Value "Review $TempFileName" -NoToSummaryReport
CollectFiles -filesToCollect $OutputFile -fileDescription "Boundaries" -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# ============
# Cloud Roles
# ============
TraceOut "    Getting Cloud Services Data from SMS Provider"
Write-DiagProgress -Activity $ScriptStrings.ID_SCCM_ACTIVITY_CM07ServerInfo -Status $ScriptStrings.ID_SCCM_CMServerInfo_Cloud

$TempFileName = ($ComputerName + "_CMServer_CloudServices.TXT")
$OutputFile = join-path $pwd.path $TempFileName

Get-WmiOutput -ClassName SMS_Azure_CloudService -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -ClassName SMS_CloudSubscription -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -ClassName SMS_IntuneAccountInfo -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -ClassName SMS_CloudProxyConnector -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -ClassName SMS_CloudProxyRoleEndpoint -FormatTable | Out-File $OutputFile -Append -Width 500
Get-WmiOutput -ClassName SMS_CloudProxyEndpointDefinition -FormatTable | Out-File $OutputFile -Append -Width 500
Get-WmiOutput -ClassName SMS_CloudProxyExternalEndpoint -FormatTable | Out-File $OutputFile -Append -Width 500
Get-WmiOutput -ClassName SMS_AzureService -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -ClassName SMS_WSfBConfigurationData -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -ClassName SMS_OMSConfigurationData -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -ClassName SMS_OMSCollection -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -ClassName SMS_ReadinessDashboardConfigurationData -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -ClassName SMS_AfwAccountStatus -FormatList | Out-File $OutputFile -Append
Get-WmiOutput -ClassName SMS_MDMAppleVppToken -FormatList | Out-File $OutputFile -Append

AddTo-CMServerSummary -Name "Cloud Services Info" -Value "Review $TempFileName" -NoToSummaryReport
CollectFiles -filesToCollect $OutputFile -fileDescription "Cloud Services" -sectionDescription $sectiondescription -noFileExtensionsOnDescription

# ============
# Features
# ============
TraceOut "    Getting Features List from SMS Provider"
$TempFileName = ($ComputerName + "_CMServer_Features.TXT")
$OutputFile = join-path $pwd.path $TempFileName

Get-WmiOutput -Query "SELECT FeatureGUID, FeatureType, Exposed, Status, Name FROM SMS_CM_UpdateFeatures" `
	-DisplayName "SMS_CM_UpdateFeatures" -FormatTable | Out-File $OutputFile -Append
AddTo-CMServerSummary -Name "Features Info" -Value "Review $TempFileName" -NoToSummaryReport
CollectFiles -filesToCollect $OutputFile -fileDescription "Features Information" -sectionDescription $sectiondescription -noFileExtensionsOnDescription

TraceOut "Completed"


# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAnU0J3xd7W7xLJ
# zgj1NIwVUZwyDZCsUqiljGafTCknPKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIN/pmMu1T1IE8ahm0g5k6We
# RpMULChRaYXnSTdBo2WRMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAPPJBjO0I7YHWdb36DGVY78SRDAEclCz788M2JmfoTVEXywX7TjtnJ
# 1CSYVNMwzXjX36vZDXIJJ3SHsw6onoqXzMJodjtQRJflor/PBihgRddLC+vXPuMG
# 5ILXPA9eBOeujBUlnpOpYUNaT8F3eF97p0DJcjZJLcvY5AsAINCi4fRJ4tN+uTdX
# n1ozEsaobgZWxcO7YGkpdWmU67zPMcNlIJSqIW89snl6NicknID+udORfzX9/E63
# r7JzlMt22zkpwbAW1QkwK3zl8kG7UuU/H6Kva7MpyGVyclOi539HEHLqA7540sRe
# +lW9R4VV3BBYm/Ms3NTaRXpS3nQkru54oYIW/TCCFvkGCisGAQQBgjcDAwExghbp
# MIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIDHIQ5YigKU0KiC1ZXFGYznnEnDdozbN/ostEGtRSv3nAgZi1+uY
# GzEYEzIwMjIwODAxMDczNTQ2LjYxNlowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjQ5QkMt
# RTM3QS0yMzNDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVDCCBwwwggT0oAMCAQICEzMAAAGXA89ZnGuJeD8AAQAAAZcwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTE0WhcNMjMwMjI4MTkwNTE0WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046NDlCQy1FMzdBLTIzM0MxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDtAErqSkFN8/Ce/csrHVWcv1iSjNTArPKEMqKPUTpY
# JX8TBZl88LNrpw4bEpPimO+Etcli5RBoZEieo+SzYUnb0+nKEWaEYgubgp+HTFZi
# D85Lld7mk2Xg91KMDE2yMeOIH2DHpTsn5p0Lf0CDlfPE5HOwpP5/vsUxNeDWMW6z
# sSuKU69aL7Ocyk36VMyCKjHNML67VmZMJBO7bX1vYVShOvQqZUkxCpCR3szmxHT0
# 9s6nhwLeNCz7nMnU7PEiNGVxSYu+V0ETppFpK7THcGYAMa3SYZjQxGyDOc7J20kE
# ud6tz5ArSRzG47qscDfPYqv1+akex81w395E+1kc4uukfn0CeKtADum7PqRrbRMD
# 7wyFnX2FvyaytGj0uaKuMXFJsZ+wfdk0RsuPeWHtVz4MRCEwfYr1c+JTkmS3n/pv
# Hr/b853do28LoPHezk3dSxbniQojW3BTYJLmrUei/n4BHK5mTT8NuxG6zoP3t8HV
# mhCW//i2sFwxVHPsyQ6sdrxs/hapsPR5sti2ITG/Hge4SeH7Sne942OHeA/T7sOS
# JXAhhx9VyUiEUUax+dKIV7Gu67rjq5SVr5VNS4bduOpLsWEjeGHpMei//3xd8dxZ
# 42G/EDkr5+L7UFxIuBAq+r8diP/D8yR/du7vc4RGKw1ppxpo4JH9MnYfd+zUDuUg
# cQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFG3PAc8o6zBullUL0bG+3X69FQBgMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAARI2GHSJO0zHnshct+Hgu4dsPU0b0yUsDXBhAdAGdH1T+uDeq3c3Hp7v5C4
# QowSEqp0t/eDlFHhH+hkvm8QlVZR8hIf+hJZ3OqtKGpyZPg7HNzYIGzRS2fKilUO
# bhbYK6ajeq7KRg+kGgZ16Ku8N13XncDCwmQgyCb/yzEkpsgF5Pza2etSeA2Y2jy7
# uXW4TSGwwCrVuK9Drd9Aiev5Wpgm9hPRb/Q9bukDeqHihw2OJfpnx32SPHwvu4E8
# j8ezGJ8KP/yYVG+lUFg7Ko/tjl2LlkCeNMNIcxk1QU8e36eEVdRweNc9FEcIyqom
# DgPrdfpvRXRHztD3eKnAYhcEzM4xA0i0k5F6Qe0eUuLduDouemOzRoKjn9GUcKM2
# RIOD7FXuph5rfsv84pM2OqYfek0BrcG8/+sNCIYRi+ABtUcQhDPtYxZJixZ5Q8Vk
# jfqYKOBRjpXnfwKRC0PAzwEOIBzL6q47x6nKSI/QffbKrAOHznYF5abV60X4+TD+
# 3xc7dD52IW7saCKqN16aPhV+lGyba1M30ecB7CutvRfBjxATa2nSFF03ZvRSJLEy
# YHiE3IopdVoMs4UJ2Iuex+kPSuM4fyNsQJk5tpZYuf14S8Ov5A1A+9Livjsv0Brw
# uvUevjtXAnkTaAISe9jAhEPOkmExGLQqKNg3jfJPpdIZHg32MIIHcTCCBVmgAwIB
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
# IEVTTjo0OUJDLUUzN0EtMjMzQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAYUDSsI2YSTTNTXYNg0YxTcHWY9Gg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRkxgwIhgPMjAyMjA4MDEwNzQ3MzZaGA8yMDIyMDgwMjA3NDczNlow
# dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5pGTGAIBADAHAgEAAgIeizAHAgEAAgIR
# wzAKAgUA5pLkmAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAF1eQuLWB69l
# cRkwlDC//Q8t6MKhMl4o4Q+GcAYe9w/P1hDjWpsFI3X3Q+q6z8QtX/Q1c4IK5S6G
# JXMlxEbcKpiXknCiQ8r4UssZYTe3qUIeBsh0XohckQUJEbEzUMUAqe474r3Ibf4d
# gwN5gry9881JMrkws7I0ZHaZmL36EBVuMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGXA89ZnGuJeD8AAQAAAZcwDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgNeXQPNO9QopQe+nG16CgJqmFSIdlmzY/zfOxXtFxZ6owgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBbe9obEJV6OP4EDMVJ8zF8dD5vHGSoLDwu
# Qxj9BnimvzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABlwPPWZxriXg/AAEAAAGXMCIEIJ3XeUNIGOGvXHlvVJ8soX+gMgA0CH0mLbWJ
# R46ykrvfMA0GCSqGSIb3DQEBCwUABIICAAtj/kX8UE6aZ2ChhkbieTuAgMmY4l+/
# juy/5TozXGToIpDHckMs+OqdZ2Ub2NvPMC0ebwpZkcr5RgbeC2fg7kKh+LH/Z6jA
# +EgZg4w68GRrCkZKrROugjsWPZRN+SWXNXGi3ELYN65ZDGRjLwVU1AY4E4DfPVwu
# +O/K2TnZSTb3x1VJGiGcUg9HMnMil2LqR/+T35z3QSd8aLEbeG8w93+Kv8YfU90a
# 851QKVTefaFfm4GXh5p5k0txgfqVD73EsPAwEK52Jd4tVKxPrOiHiS71RQqGk0t+
# sJ3uEGLLF+Pff5G1WqYvKcrna/5YUaiKaA6s6Kn5pP1RaabvmVMLLki7CioRyxfC
# XMlG7b8rc3MUl22trSskuWMzAPcRlwAGOdboZg+x36LcyYXOXqFtxQUAoHWK+fof
# piRCJp+XbXgHqFgzY7g3xYms+FsL0wXiqkVkJcabXO3RKerIGwdSmG3w4VVAu9KM
# Z94dLFflogfyAQ+ruadPAw/g9N1WX8l12ljVJhk+4Ukzfafi6OAwjqwX6qVL7xcN
# GeETjL/WwyBgggc3fHWkZfEDyZYtni5dJkkltVwYjhQpzUvVm2AD2pRHRzmajGgZ
# ItWqYRaUEcZxq4QmPb9P8+JUbOTd98YGAdWTMMIqhtk87QMTmk/CgpxFNADZbrb2
# gRfwmzCMv/tF
# SIG # End signature block
