# DC_BasicSystemInformationTXT.ps1

PARAM($MachineName=$null)

if ($Null -ne $MachineName) {
	#$AddToHeader = "$MachineName - "
	if ($ComputerName -eq $MachineName)
	{
		$MachineName = "."
	}
} else {
	#$AddToHeader = ""
	$MachineName = "."
}

Import-LocalizedData -BindingVariable DC_Strings

# Write-DiagProgress -activity $DC_Strings.ID_CollectActivity -status ($AddToHeader + $DC_Strings.ID_CollectingData)

$OS_Summary = new-object PSObject                  # Operating System Summary
$CS_Summary = new-object PSObject                  # Computer System Summary

$WMIOS = $null

$error.Clear()

$WMIOS = Get-CimInstance -class "win32_operatingsystem" -ComputerName $MachineName -ErrorAction SilentlyContinue

if ($Error.Count -ne 0) {
	$errorMessage = $Error[0].Exception.Message
	$errorCode = "0x{0:X}" -f $Error[0].Exception.ErrorCode
	"Error" +  $errorCode + ": $errorMessage connecting to $MachineName" | WriteTo-StdOut
	$Error.Clear()
}

# Get all data from WMI

if ($null -ne $WMIOS) { #if WMIOS is null - means connection failed. Abort script execution.

	$WMICS = Get-CimInstance -Class "win32_computersystem" -ComputerName $MachineName
	$WMIProcessor = Get-CimInstance -Class "Win32_processor" -ComputerName $MachineName

	# Write-DiagProgress -activity $DC_Strings.ID_CollectActivity -status ($AddToHeader + $DC_Strings.ID_FormattingData)

	$OSProcessorArch = $WMIOS.OSArchitecture
	$OSProcessorArchDisplay = " " + $OSProcessorArch
	#There is no easy way to detect the OS Architecture on pre-Windows Vista Platform
	if ($null -eq $OSProcessorArch)
	{
		if ($MachineName -eq ".") { #Local Computer
			$OSProcessorArch = $Env:PROCESSOR_ARCHITECTURE
		} else {
			$RemoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$MachineName)
			$OSProcessorArch = ($RemoteReg.OpenSubKey("SYSTEM\CurrentControlSet\Control\Session Manager\Environment")).GetValue("PROCESSOR_ARCHITECTURE")
		}

<#		if ($null -ne $OSProcessorArch) {
			switch ($OSProcessorArch) {
				"AMD64" {$ProcessorArchDisplay = " (64-bit)"}
				"i386" {$ProcessorArchDisplay = " (32-bit)"}
				"IA64" {$ProcessorArchDisplay = " (64-bit - Itanium)"}
				default {$ProcessorArchDisplay = " ($ProcessorArch)"}
			}
		} else {
			$OSProcessorArchDisplay = ""
		}
#>
	}


	# Build OS Summary
	# Name
	add-member -inputobject $OS_Summary -membertype noteproperty -name "Machine Name" -value $WMIOS.CSName
	add-member -inputobject $OS_Summary -membertype noteproperty -name "OS Name" -value ($WMIOS.Caption + " Service Pack " + $WMIOS.ServicePackMajorVersion + $OSProcessorArchDisplay)
	add-member -inputobject $OS_Summary -membertype noteproperty -name "Build" -value ($WMIOS.Version)
	add-member -inputobject $OS_Summary -membertype noteproperty -name "Time Zone/Offset" -value (Replace-XMLChars -RAWString ((Get-CimInstance -Class Win32_TimeZone).Caption + "/" + $WMIOS.CurrentTimeZone))

	# Install Date
	#$date = [DateTime]::ParseExact($wmios.InstallDate.Substring(0, 8), "yyyyMdd", $null)
	#add-member -inputobject $OS_Summary -membertype noteproperty -name "Install Date" -value $date.ToShortDateString()
	add-member -inputobject $OS_Summary -membertype noteproperty -name "Last Reboot/Uptime" -value (($WMIOS.LastBootUpTime).ToString() + " (" + (GetAgeDescription(New-TimeSpan $WMIOS.LastBootUpTime)) + ")") #_#
	
	# Build Computer System Summary
	# Name
	add-member -inputobject $CS_Summary -membertype noteproperty -name "Computer Model" -value ($WMICS.Manufacturer + ' ' + $WMICS.model)
	
	$numProcs=0
	#$ProcessorType = ""
	$ProcessorName = ""
	$ProcessorDisplayName= ""

	foreach ($WMIProc in $WMIProcessor) 
	{
		#$ProcessorType = $WMIProc.manufacturer
		switch ($WMIProc.NumberOfCores) 
		{
			1 {$numberOfCores = "single core"}
			2 {$numberOfCores = "dual core"}
			4 {$numberOfCores = "quad core"}
			$null {$numberOfCores = "single core"}
			default { $numberOfCores = $WMIProc.NumberOfCores.ToString() + " core" } 
		}
		
		switch ($WMIProc.Architecture)
		{
			0 {$CpuArchitecture = "x86"}
			1 {$CpuArchitecture = "MIPS"}
			2 {$CpuArchitecture = "Alpha"}
			3 {$CpuArchitecture = "PowerPC"}
			6 {$CpuArchitecture = "Itanium"}
			9 {$CpuArchitecture = "x64"}
		}
		
		if ($ProcessorDisplayName.Length -eq 0)
		{
			$ProcessorDisplayName = " " + $numberOfCores + " $CpuArchitecture processor " + $WMIProc.name
		} else {
			if ($ProcessorName -ne $WMIProc.name) 
			{
				$ProcessorDisplayName += "/ " + " " + $numberOfCores + " $CpuArchitecture processor " + $WMIProc.name
			}
		}
		$numProcs += 1
		$ProcessorName = $WMIProc.name
	}
	$ProcessorDisplayName = "$numProcs" + $ProcessorDisplayName
	
	add-member -inputobject $CS_Summary -membertype noteproperty -name "Processor(s)" -value $ProcessorDisplayName
	
	if ($null -ne $WMICS.Domain) {
		add-member -inputobject $CS_Summary -membertype noteproperty -name "Machine Domain" -value $WMICS.Domain
	}
	
	if ($null -ne $WMICS.DomainRole) {
		switch ($WMICS.DomainRole) {
			0 {$RoleDisplay = "Workstation"}
			1 {$RoleDisplay = "Member Workstation"}
			2 {$RoleDisplay = "Standalone Server"}
			3 {$RoleDisplay = "Member Server"}
			4 {$RoleDisplay = "Backup Domain Controller"}
			5 {$RoleDisplay = "Primary Domain controller"}
		}
		add-member -inputobject $CS_Summary -membertype noteproperty -name "Role" -value $RoleDisplay
	}
	
	if ($WMIOS.ProductType -eq 1) { #Client
		$AntivirusProductWMI = Get-CimInstance -query "select companyName, displayName, versionNumber, productUptoDate, onAccessScanningEnabled FROM AntivirusProduct" -Namespace "root\SecurityCenter" -ComputerName $MachineName
		if ($null -ne $AntivirusProductWMI.displayName) {
			$AntivirusDisplay= $AntivirusProductWMI.companyName + " " + $AntivirusProductWMI.displayName + " version " + $AntivirusProductWMI.versionNumber
			if ($AntivirusProductWMI.onAccessScanningEnabled) {
				$AVScanEnabled = "Enabled"
			} else {
				$AVScanEnabled = "Disabled"
			}
			if ($AntivirusProductWMI.productUptoDate) {
				$AVUpToDate = "Yes"
			} else {
				$AVUpToDate = "No"
			}
			#$AntivirusStatus = "OnAccess Scan: $AVScanEnabled" + ". Up to date: $AVUpToDate" 
	
			add-member -inputobject $OS_Summary -membertype noteproperty -name "Anti Malware" -value $AntivirusDisplay
		} else {
			$AntivirusProductWMI = Get-CimInstance -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ComputerName $MachineName
			if ($null -ne $AntivirusProductWMI) 
			{	
				#$X = 0
				$Antivirus = @()
				$AntivirusProductWMI | ForEach-Object -Process {
					$ProductVersion = $null
					if ($_.pathToSignedProductExe -ne $null)
					{
						$AVPath = [System.Environment]::ExpandEnvironmentVariables($_.pathToSignedProductExe)
						if (($AVPath -ne $null) -and (Test-Path $AVPath))
						{
							$VersionInfo = (Get-ItemProperty $AVPath).VersionInfo
							if ($VersionInfo -ne $null)
							{
								$ProductVersion = " version " + $VersionInfo.ProductVersion.ToString()
							}
						}
					}
					
					$Antivirus += "$($_.displayName) $ProductVersion"
				}
				if ($Antivirus.Count -gt 0)
				{
					add-member -inputobject $OS_Summary -membertype noteproperty -name "Anti Malware" -value ([string]::Join('<br/>', $Antivirus))
				}
			}
		}
	}
	
	if ($MachineName -eq ".") { #Local Computer
		$SystemPolicies = get-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
		$EnableLUA = $SystemPolicies.EnableLUA
		$ConsentPromptBehaviorAdmin = $SystemPolicies.ConsentPromptBehaviorAdmin
	} else {
		$RemoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$MachineName)
		$EnableLUA  = ($RemoteReg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")).GetValue("EnableLUA")
		$ConsentPromptBehaviorAdmin = ($RemoteReg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")).GetValue("ConsentPromptBehaviorAdmin")
	}
	
	if ($EnableLUA) {
		$UACDisplay = "Enabled"
	
		switch ($ConsentPromptBehaviorAdmin) {
			0 {$UACDisplay += " / " + $DC_Strings.ID_UACAdminMode + ": " + $DC_Strings.ID_UACNoPrompt}
			1 {$UACDisplay += " / " + $DC_Strings.ID_UACAdminMode + ": " + $DC_Strings.ID_UACPromptCredentials}
			2 {$UACDisplay += " / " + $DC_Strings.ID_UACAdminMode + ": " + $DC_Strings.ID_UACPromptConsent}
			5 {$UACDisplay += " / " + $DC_Strings.ID_UACAdminMode + ": " + $DC_Strings.ID_UACPromptConsentApp}
		}
	} else {
		$UACDisplay = "Disabled"
	}
	
	add-member -inputobject $OS_Summary -membertype noteproperty -name $DC_Strings.ID_UAC -value $UACDisplay
	
	if ($MachineName -eq ".") { #Local Computer only. Will not retrieve username from remote computers
		add-member -inputobject $OS_Summary -membertype noteproperty -name "Username" -value ($Env:USERDOMAIN + "\" + $Env:USERNAME)
	}
	
	#System Center Advisor Information
	$SCAKey = "HKLM:\SOFTWARE\Microsoft\SystemCenterAdvisor"
	if (Test-Path($SCAKey))
	{
		$CustomerID = (Get-ItemProperty -Path $SCAKey).CustomerID
		if ($null -ne $CustomerID)
		{
			"System Center Advisor detected. Customer ID: $CustomerID" | writeto-stdout
			$SCA_Summary = New-Object PSObject
			$SCA_Summary | add-member -membertype noteproperty -name "Customer ID" -value $CustomerID
			# $SCA_Summary | ConvertTo-Xml2 | update-diagreport -id ("01_SCACustomerSummary") -name "System Center Advisor" -verbosity Informational
		}		
	}

	Add-Member -InputObject $CS_Summary -MemberType NoteProperty -name "RAM (physical)" -value (FormatBytes -bytes $WMICS.TotalPhysicalMemory -precision 1)
	

	$OutputFile = $Computername + "_BasicSystemInfo.TXT"
	$sectionDescription = "Basic System Info TXT output"
	$OS_Summary | Out-File -FilePath $OutputFile -append
	$CS_Summary | Out-File -FilePath $OutputFile -append

    CollectFiles -filesToCollect $OutputFile -fileDescription "Basic System Information" -SectionDescription $sectionDescription

}


# SIG # Begin signature block
# MIInowYJKoZIhvcNAQcCoIInlDCCJ5ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAchzLj6lrDh9wD
# 3CUZzcU2CfTDiKZcXu0JIrrz1aX90aCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGYMwghl/AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMHxqNNSB3ewMjwDSpqZ7+hw
# asvYspGQblgHHrn79vTBMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBfpvl1ODpgG7Ac5YEuFdF3H/asMBYiaBmVx2tAVS7mlXgVCjVLvydW
# XYrmYJ/zb8RSizqjXfAlo7taTpQGQrelTxQoNOg6mjxIm/p6etVhhx2AT9de7AWS
# 9K6uI+Zr6uNxHMvOEm8lFVGxa817dRxHN97Trm7Vig4F+55GGf4MtEfpr9xEAxtb
# 3sXlJ/gJ5BQtcKAxHWYlKRjKhLQnsuolRXvcedTEwOEufqffcNwZkqXgsPc1vwaB
# /KPM63oSAI9v+VUfSb9QE9fA/qMnxZ9n85WK9PaMwxVg0x+QBMI4GIBtx68tCSxo
# lLcw9wgd288c6sV/PD0tWhcgvKLlJV+koYIXCzCCFwcGCisGAQQBgjcDAwExghb3
# MIIW8wYJKoZIhvcNAQcCoIIW5DCCFuACAQMxDzANBglghkgBZQMEAgEFADCCAVQG
# CyqGSIb3DQEJEAEEoIIBQwSCAT8wggE7AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIBGXnMWLvmhq+62Z74bvtLcHMOVunHqn8ABMUteYgrz/AgZi2yMn
# O20YEjIwMjIwODA4MDkxNTExLjE1WjAEgAIB9KCB1KSB0TCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjMy
# QkQtRTNENS0zQjFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloIIRXzCCBxAwggT4oAMCAQICEzMAAAGt/N9NWONdMukAAQAAAa0wDQYJKoZI
# hvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIwMzAy
# MTg1MTM2WhcNMjMwNTExMTg1MTM2WjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVl
# cnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjMyQkQtRTNENS0zQjFE
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA6J5TKqVNKtUuG9jtM7y+AL5Pk3/L8xd5
# Heg3ATSssjUSD+AzmD02E/4qqolz/u48vhOygAtv5FV/quhg2WXJCtiaq5SPCyrb
# rYwPkv2X2tTWmXPa0w96E/xp11WU0iNggGHQ0LgLIwTq3FWmlCvt4V39tbRf22dn
# LVoNb7OhokHYVjyFqiSrlxE40Rbi6hWxNNewgKRtg4Bh98ggZqQwVdW8HfQ1yy6I
# Ofq4OTzdddOzS2dKvwXHM+gPxKA88hxZpY8SMJAuvkjQHF91SWLA08cg8SCWqiys
# KVGNcbutxlZtZ44OABOLSLoNSy/VafQs5biy8rj9a5z+/12Wa4itqa/3CFuALKRS
# 5hnLwzFPOxCpTZHFybyHz0JcDmN/WTuTdmJotQnTTcyO1O01fOWBv6TUDl4vXsbc
# LgSPDkChWIz5QEZC/G5PGkV5oahAWp44Ya0QrSqTTB1Rf2n/gC71eyV7kPl+/KkF
# 2xxcGyVQFxPr4JirSRD2yaxPKFXgMr3Bv1mfs5sQ59PQBDKmkjqPDMGMeEAYXKsp
# iMhuCUxoSLGNG/td02JzZW5grJLvUDSGzp1tsPH9XuENt2/ayu1nZVM7TLYT7hCo
# xEq0AG/gCCCNgrPlNga5DhVts9jx8E71eq9rcafHVkM5DecZUUofBqsYNw10Hep6
# y+0lsgYmAmMCAwEAAaOCATYwggEyMB0GA1UdDgQWBBR9UHQdBLyqIVpuaoSo5X0u
# ssbBWTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBW
# MFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNy
# b3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUH
# AQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEp
# LmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3
# DQEBCwUAA4ICAQCL0B1FuzH+A5J0Fed3BF6NC661Cpx7eTduCzWyU+NlLHoUNenU
# hnOM7JPUmj/d5RYMEUl2L4d67U2jIN0af28vqvGXLUvrwrgyd8sGb7JvKM37FrV4
# 1rj7hw6g67ETYq3yO2ZlsiHHaO9jsX2pj+VqdHk9JtQrIKWE1CHGyc1Sn8lJD6ju
# cC5An7CwLA8KtdgTsL5O8oONrp7pZTQrhGIFcUZTXPoy3cr3CUwP9AZTj78gZkOY
# T79n+TQl8mNnLEICVyaF7euB2EPMCwbElirg9uUZlMF2vzCRDCk/aOCDIwxrAwzk
# OCDC9doNuuoJDyCSw2EJnNOp9LZ1uAsXSbsd/CVQytyfOL9t1NJFbMheDlCwfW3l
# dpogf5NnW5kG3BcnwQ5evpL7YDqrxFBVjXQqcEfpikYT06Fc9+4i7zzaa4UR2HgR
# ds90BFRHUgxIjGDzySFIEL9gHBCEKmNOSyrkndn6PIdZngyddflHjaYBHnziJFhz
# tqBi+6i0MSpwPRT2UiOBbfU+p+plDW25hlOIZwoT1Bxga9kUqdV2SorxXQz176QX
# kKoM6swxhFXb4j8WHJCwkfEr8bncPQ7lu90iHaAOcQdEAWKF1mPb1ntbSloY+i0Z
# fSgHmv3Co2Mzetu+4R7oUnfbcw9jXH383WDXbpP9KiSoAMkFMqrIFg3jMzCCB3Ew
# ggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1p
# Y3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkz
# MDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5
# osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVri
# fkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFEx
# N6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S
# /rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3j
# tIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKy
# zbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX78
# 2Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjt
# p+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2
# AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb
# 3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3ir
# Rbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUB
# BAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYD
# VR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGC
# N0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZ
# BgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/
# BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8E
# TzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9k
# dWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBM
# MEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRz
# L01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEA
# nVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx8
# 0HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ
# 7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2
# KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZ
# QhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa
# 2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARx
# v2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRr
# akURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6T
# vsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4
# JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6
# ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLSMIICOwIBATCB/KGB
# 1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcG
# A1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOjMyQkQtRTNENS0zQjFEMSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBAktGtRVHhlsEO
# BY+O42pVy1TOkKCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MA0GCSqGSIb3DQEBBQUAAgUA5pq4wzAiGA8yMDIyMDgwODAyMTg0M1oYDzIwMjIw
# ODA5MDIxODQzWjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDmmrjDAgEAMAoCAQAC
# AhvbAgH/MAcCAQACAhFPMAoCBQDmnApDAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwG
# CisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEF
# BQADgYEAGhxaSFmjwXUrez6vJf4EES9qX6w/dwpLiNg6xlRKFsbnl8bF+MAfJMKb
# UQzOGdhJ2OpKvlaNFUVhsyk/D9smnRcyWPmH8V6DuVJr1Ni7xjtNKFCyiGYm8/XZ
# IphV1VAjziEOw+BHChsKbJWtYwfssnTW6C0lU0xMxUGoQ2VhM2QxggQNMIIECQIB
# ATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAa38301Y410y
# 6QABAAABrTANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3
# DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCD79dSqjQmhQhmOqwco4hDmyNbbjHjaTupZ
# a6TpkGe6kzCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIJ/qfD0JHl7X4621
# yfXD33YqafxgxNj8NY8gd4xsy1CCMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTACEzMAAAGt/N9NWONdMukAAQAAAa0wIgQgWDX3YCoFZZ3owfHF
# gJMMTz6tlyPrdKO939Vm0d+9TGowDQYJKoZIhvcNAQELBQAEggIAzFG+TOj3iRlh
# SN1qDOO+Pu3XR70NVSEzABEMA2+63ukG8+q5F/VDsY+EK9QyVVtDPcYZpYj5EUP9
# Zto8YsblyrSc58yN7BN4XifJHyZ5yx1gfMtJNYqvZq39wDWgdp9pabt63Ijq4Drc
# LpciVh9czZ0Rxi2E2NptNuIUADBFGKBM+18V8TSrTGZma8P6UemYfDx6UxEARLrA
# saJreysXKqTOhgjisGlpmmMva2vuxrrC9LnHLBvIFnBaN0eYP8a5b8C7HvJiEPce
# hI8Wte5HsBgsAhuwJ6KiYW7bPgFKfCtcJmBTXZZRJBfKQffKX0zTCDpreXxtxkoh
# fs7SSC4Gne617RJTnQctYshoQwVCTjRm225qsB27HcbL5IOsm4Le8mrBNfIUwQg6
# BkAaNAslSYMyPMgr/0G2yV7MPNoWemoto5vRd1LyycuM4FJEM7s+w9Nx92VmWyoH
# d2C9fVE6Rw3HibrOPKaziUtSeSb/tigK3w1ek4bYy7XpbEi/MFeBw100VkzzGuY7
# Y/wZ5Yjnqmx8etrbqYqSsG/noTBmhHGrPdifnO67ASOY3RC5yR8We7FMRwJWR7jZ
# fYIb08K+iGI8zKJu3k+di+EDVyiVgyOmYhnjGTHX/Wr5W+AnACA2pqnbaj92YcOR
# DOCkO6SofZXK5+LgFr2kWoIvM6aQoak=
# SIG # End signature block
