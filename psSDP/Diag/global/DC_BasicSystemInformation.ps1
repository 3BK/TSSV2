# DC_BasicSystemInformation.ps1

PARAM($MachineName=$null)
# 2023-02-20 WalterE mod Trap #we#
trap [Exception]{
	WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; continue
	Write-Host "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_"
}
	
if ($Null -ne $MachineName) {
	$AddToHeader = "$MachineName - "
	if ($ComputerName -eq $MachineName)
	{
		$MachineName = "."
	}
}else{
	$AddToHeader = ""
	$MachineName = "."
}

Import-LocalizedData -BindingVariable DC_Strings

Write-DiagProgress -activity $DC_Strings.ID_CollectActivity -status ($AddToHeader + $DC_Strings.ID_CollectingData)

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

	Write-DiagProgress -activity $DC_Strings.ID_CollectActivity -status ($AddToHeader + $DC_Strings.ID_FormattingData)

	$OSProcessorArch = $WMIOS.OSArchitecture
	$OSProcessorArchDisplay = " " + $OSProcessorArch
	#There is no easy way to detect the OS Architecture on pre-Windows Vista Platform
	if ($null -eq $OSProcessorArch)
	{
		if ($MachineName -eq ".") { #Local Computer
			$OSProcessorArch = $Env:PROCESSOR_ARCHITECTURE
		}else{
			$RemoteReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$MachineName)
			$OSProcessorArch = ($RemoteReg.OpenSubKey("SYSTEM\CurrentControlSet\Control\Session Manager\Environment")).GetValue("PROCESSOR_ARCHITECTURE")
		}

<#		if ($null -ne $OSProcessorArch) {
			switch ($OSProcessorArch) {
				#"AMD64" {$ProcessorArchDisplay = " (64-bit)"}
				#"i386" {$ProcessorArchDisplay = " (32-bit)"}
				#"IA64" {$ProcessorArchDisplay = " (64-bit - Itanium)"}
				#default {$ProcessorArchDisplay = " ($ProcessorArch)"}
			}
		}else{
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
		}else{
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
			}else{
				$AVScanEnabled = "Disabled"
			}
			if ($AntivirusProductWMI.productUptoDate) {
				$AVUpToDate = "Yes"
			}else{
				$AVUpToDate = "No"
			}
			#$AntivirusStatus = "OnAccess Scan: $AVScanEnabled" + ". Up to date: $AVUpToDate" 
	
			add-member -inputobject $OS_Summary -membertype noteproperty -name "Anti Malware" -value $AntivirusDisplay
		}else{
			$AntivirusProductWMI = Get-CimInstance -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ComputerName $MachineName
			if ($null -ne $AntivirusProductWMI) 
			{	
				# = 0
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
	}else{
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
	}else{
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
			$SCA_Summary | ConvertTo-Xml2 | update-diagreport -id ("01_SCACustomerSummary") -name "System Center Advisor" -verbosity Informational
		}		
	}

	Add-Member -InputObject $CS_Summary -MemberType NoteProperty -name "RAM (physical)" -value (FormatBytes -bytes $WMICS.TotalPhysicalMemory -precision 1)
	
	$OS_Summary | convertto-xml2 | update-diagreport -id ("00_OSSummary") -name ($AddToHeader + "Operating System")  -verbosity informational
	$CS_Summary | convertto-xml | update-diagreport -id ("01_CSSummary") -name ($AddToHeader + "Computer System") -verbosity informational
	
}


# SIG # Begin signature block
# MIInmAYJKoZIhvcNAQcCoIIniTCCJ4UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBA+7G46csncYlm
# UTUmwfaH94B6tYD88DNo7VeeK/WkH6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINkSNPJzWdHc1vY8XFmSzJcZ
# WFDCLOCyNcX5DIOooqwoMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBXZxuaYRovL6865ijPIZbZ4oPp2dy5pkJFfHbXTZFdMIlN8AIuKNmF
# vpJyUu784R9XHwe95pIq8G17u3fiEwrreGk822HpWd9bzK6F1dkNtcmwMpDnFs5J
# sNxsRx9ijK/mfPOSJWdo3qr+wPuKqtyuHE28PFqMUv02R7zEKYSbs+Qnh9LPRcRi
# jJDpv/ltoqIAeRPnzKEJijuXe/9ftT3fzrUzJOjpE8e1ZXvz/PB8o7bS0QSr8UaK
# 6yl+V7KDubKfasaaCAyw09JXnAveY+5n6bAYeYp8GHVKZqz/NDUCX0mT9ACZ0cnU
# Z9cKEHP6waDVAalGTXfkqQBldRyW7px6oYIXADCCFvwGCisGAQQBgjcDAwExghbs
# MIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEINRVjPshqHqnajwc9LiBTsyVZb618fRUmh/ttQrh614iAgZj7ndi
# za0YEzIwMjMwMjIwMTUwMDEwLjI5NlowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjQ5QkMt
# RTM3QS0yMzNDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVzCCBwwwggT0oAMCAQICEzMAAAHAVaSNw2QVxUsAAQAAAcAwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkw
# MTI1WhcNMjQwMjAyMTkwMTI1WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046NDlCQy1FMzdBLTIzM0MxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC87WD7Y2GGYFC+UaUJM4xoXDeNsiFR0NOqRpCFGl0d
# Vv6G5T/Qc2EuahFi+unvPm8igvUw8CRUEVYkiStwbuxKt52fJnCt5jbTsL2fxeK8
# v1kE5B6JR4v9MyUnpWKetxp9uF2eQ07kkOU+jML10bJKK5uvJ2zkYq27r0PXA1q3
# 0MhCXpqUU7qmdxkrhEjN+/4rOQztGRje8emFXQLwQVSkX6XKxoYlcV/1CxRQfCP1
# cpYd9z0F+EugJF5dTO+Cuyl0WZWcD0BNheaJ1KOuyF/wD4TT8WlN2Fc8j1deqxkM
# cGqvsOVihIJTeW+tUNG7Wnmkcd/uzeQzXoekrpqsO1jdqLWygBKYSm/cLY3/LkwM
# ECkN3hKlKQsxrv7p6z91p5LvN0fWp0JrZGgk8zoSH/piYF+h+F8tCh8o8mXfgAuV
# lYrkDNW0VE05dpyiPowAbZ1PxFzl+koIfUTeftmN7R0rbhBV9K/9g7HDnYQJowuV
# bk+EdPdkg01oKZGBwcJMKU4rMLYU6vTdgFzbM85bpshV1eWg+YExVoT62Feo+YA0
# HDRiydxo6RWCCMNvk7lWo6n3wySUekmgkjqmTnMCXHz860LsW62t21g1QLrKRfMw
# A8W5iRYaDH9bsDSK0pbxbNjPA7dsCGmvDOei4ZmZGLDaTyl6fzQHOrN3I+9vNPFC
# wwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFABExnjzSPCkrc/qq5VZQQnRzfSFMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAK1OHQRCfXqQpDIJ5WT1VzXSbovQTAtGjcBNGi4/th3aFZ4QHZjhkXgIkp72
# p9dYYkrNXu0xSboMCwEpgf+dP7zJsjy4mIcad+dWLpKHuAWOdOl+HWPVP3Qf+4t6
# gWOk6f/56gKgmaitbkZvZ7OVOWjkjSQ0C5vG0LGpsuLO480+hvyREApCC/7j8ILU
# maJQUbS4og2UqP1KwdytZ4EFAdfrac2DOIjBPjgmoesDTYjpyZACL0Flyx/ns44u
# lFiXOg8ffH/6V1LJJcCbIura5Jta1C4Pzgj/RmBL8Hkvd7CpN2ITUpspfz0xbkmo
# Ir/Ij+YAhBqaYCUc+pT15llMw84dCzReukKKOWT6rKjYloeLJLDDqe4+pfNTewSP
# dVbTRiJVJrIoS7UitHPNfctryp7o6otO8r/qC7ld0qrtNPznacHog/RAz4G522vg
# VvHj+y+kocakr3/MG5occNdfkChKSyH+RINgp959AiEh9AknOgTdf4yKYwmuCvBl
# eW1vqPUgvQdjeoKlrTcaGCLQhPOp+TDcxqfcbyQHVCX5J41yI9SPvcqfa94l6cYu
# 1PwmRQz1FSLTCg7SK5ji0mdi5L5J6pq9dQ5apRhVjX0UivU8uqmZaRus7nEqOTI4
# egCYvGM1sqM6eQDB+37UbTSS6UqrOo9ub5Kf7jsmwZAWE0ZtMIIHcTCCBVmgAwIB
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
# IEVTTjo0OUJDLUUzN0EtMjMzQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAEBDsTEXX0qTBUvUTcB3yTQ95vp2g
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOedkt8wIhgPMjAyMzAyMjAxNDM0MDdaGA8yMDIzMDIyMTE0MzQwN1ow
# dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA552S3wIBADAKAgEAAgIbbQIB/zAHAgEA
# AgISVjAKAgUA557kXwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMC
# oAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBADoF19+J
# V4XEFdan0kUeaKN3ZBUreDTlHy5rM05CFf7dqQV05+mUqpH/j1abHRfHiBgRKfT7
# e2Ub+iicYpKXOKlZuJ+JLP24PDMH8w7R0+VnAMk4IYHoElCPkin3uxUzN7scGLDo
# 58F0ZbtiRGgUvHX6rSFQC90/pueoWs8HKrpEMYIEDTCCBAkCAQEwgZMwfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHAVaSNw2QVxUsAAQAAAcAwDQYJ
# YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkq
# hkiG9w0BCQQxIgQgQIHhwB6ua9k+qsBZxLLQ/ytGpDpZ3qqjn94uIs2phx0wgfoG
# CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBa8ViiUghcwTTMr9bpewKSRhfuVg1v
# 3IDwnHBjTg+TTzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# AhMzAAABwFWkjcNkFcVLAAEAAAHAMCIEIGUc928ie0HsT8McRXHRkF3ReD/bRoRM
# 0xNHgn25ZUkpMA0GCSqGSIb3DQEBCwUABIICAGo2pXOU68mIEg9peL4DD0rExFAn
# 1ZioK2hzLF226Axsv7Uat9+2AcqN+QKXivurnKrENNGzoO2rGTV1SLO23LaX0Wb3
# P78E4Ok5732Q2JhDwYW8p/1izMZFmx8KNyGygxqJJXy8bT8wT8YsxL28FeWCAIye
# iBDJjxIySiZFaTd3Scpz54kC+euoByRwobHZmWdyJukGhUJrxIQE4Ua8XJoiEw9x
# luKPWOhgKtGp5zzxnp3X42LJDfiEW0lj2qS74sOmFVhkg2QlM+p/4xx//vyRYB2h
# HKpiKSafIfE8DJiQcDrPx5oJWc8tu1TeZMF1gXdUFpvy+Y3UKLDCb2+ivyYYy3VH
# TM1UCb96zRfeiZt2AvoHfNH2ii49CwFy0rjaG3R+yn4DkoQDm2IzyCjec4H/PjTv
# 2fZpbrmr9+3Bg/iBw0Fuhe2dJpJdsVzPnHyP1A4G2k5RGZFXkQHuf1L+0+8SBAWh
# KfFKrcnsnoLVWvdAL38SsXBCRERZrqIsFkkEZkik+VBP/qabwQLjJ1b+RZjIxyW1
# jlnVjLxtWFTBzst4GPaMjjFIBD7Hc6NMUkgpsKuSan4nIMmwQAtAErYHacFzUq9g
# nhqAv0MOH7JbyHsjj4//lJXtqwLoNzpfnIDbWAga97dsGuHYwwHamM4OBjz8kH6P
# w+jk0tT31N3C8omG
# SIG # End signature block
