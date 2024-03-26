#************************************************
# DC_HotfixRollups.ps1
# Version 1.0.04.02.14: Created script to easily view what rollups are installed for W7/WS2008R2, W8/WS2012, and W8.1/WS2012R2
# Version 1.1.05.16.14: Added W8.1 Update1 (April2014 rollup);  Added OS Version below each heading.
# Version 1.6.10.16.14: Added Oct2014 updates for W8/W8.1
# Date: 2019,2020
# Author: Boyd Benson (bbenson@microsoft.com) +WalterE
# Description: Creates output to easily identify what rollups are installed on W7/WS2008R2 and later.
# Called from: Networking Diagnostics, and all psSDP
# Last Modified: 2023-04-26 by #we#
#  - read latest KB#s from rfl_Hotfix.csv file
#*******************************************************

trap [Exception]{	#we#
	WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; continue
	Write-Host "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_"
}

Import-LocalizedData -BindingVariable ScriptVariable

$OutputFile = $Env:ComputerName + "_HotfixRollups.TXT"
$sectionDescription = "Hotfix Rollups"

# get list of installed fixes only once for performance reason
$hotfixesWMIQuery = "SELECT * FROM Win32_QuickFixEngineering" #_# WHERE HotFixID='KB$hotfixID'"
$script:hotfixesWMI = Get-CimInstance -query $hotfixesWMIQuery #_# or PS > Get-HotFix

function CheckForHotfix ($hotfixID, $title, $Warn=""){
	$link = "http://support.microsoft.com/kb/" + $hotfixID
	if (-not (($script:hotfixesWMI.HotfixID) -contains $hotfixID)){
		"No          $hotfixID - $title   ($link)" | Out-File -FilePath $OutputFile -append
		If ($Warn -match "Yes") {
			Write-Host -ForegroundColor Cyan "This system is not up-to-date. Many known issues are resolved by applying latest cumulative update!"
			Write-Host -ForegroundColor Magenta "*** [WARNING] latest OS cumulative KB $hotfixID is missing.`n Please update this machine with recommended Microsoft KB $hotfixID and verify if your issue is resolved."
			$Global:MissingCU = $hotfixID
		}
	}else{
		"Yes         $hotfixID - $title   ($link)" | Out-File -FilePath $OutputFile -append
	}
}

#----------detect OS version and SKU
	$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
	[int]$bn = [int]$wmiOSVersion.BuildNumber
	$ReferenceCSVpath = Join-Path -Path ($PWD.Path) -ChildPath "\rfl_Hotfix.csv"
	$ReferenceCSV = Import-Csv $ReferenceCSVpath

if ($bn -match 22621){ # Win 11 22H2 = 22621
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 11 22H2" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"OS Build:  " + $bn + "`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append
	foreach ($line in $ReferenceCSV){
		if($line.OSversion -eq "Win1122H2"){
			CheckForHotfix -hotfixID $($line.Article) -title $($line.Title) -Warn $($line.Warn)
		}
	}
}
elseif ($bn -match 2200){ # Win 11 = 22000
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 11 " | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"OS Build:  " + $bn + "`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append
	foreach ($line in $ReferenceCSV){
		if($line.OSversion -eq "Win11"){
			CheckForHotfix -hotfixID $($line.Article) -title $($line.Title) -Warn $($line.Warn)
		}
	}
}
elseif ($bn -match 20348){ # Server 2022 = 20348
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows Server 2022 " | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"OS Build:  " + $bn + "`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append
	foreach ($line in $ReferenceCSV){
		if($line.OSversion -eq "2022"){
			CheckForHotfix -hotfixID $($line.Article) -title $($line.Title) -Warn $($line.Warn)
		}
	}
}
elseif (($bn -match 19042) -or ($bn -match 19044)){ # 20H2 = 19042, 21H2 = 19044
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 10 20H2/21H2 and Windows Server 2019 20H2/21H2 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"OS Build:  " + $bn + "`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append
	foreach ($line in $ReferenceCSV){
		if($line.OSversion -eq "201621H2"){
			CheckForHotfix -hotfixID $($line.Article) -title $($line.Title) -Warn $($line.Warn)
		}
	}
}
elseif ($bn -match 19045){ # 22H2 = 19045, 22H2 has C/D updates
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 10 22H2 and Windows Server 2019 22H2 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"OS Build:  " + $bn + "`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append
	foreach ($line in $ReferenceCSV){
		if($line.OSversion -eq "201622H2"){
			CheckForHotfix -hotfixID $($line.Article) -title $($line.Title) -Warn $($line.Warn)
		}
	}
}
elseif ($bn -eq 17763){
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 10 RS5 v1809 and Windows Server 2019 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"OS Build:  " + $bn + "`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append
	foreach ($line in $ReferenceCSV){
		if($line.OSversion -eq "2016RS5"){
			CheckForHotfix -hotfixID $($line.Article) -title $($line.Title) -Warn $($line.Warn)
		}
	}
	CheckForHotfix -hotfixID 5005112 -title "KB5005112: Servicing stack update for Windows 10, version 1809: August 10, 2021"
}
elseif ($bn -eq 14393){
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 10 RS1 v1607 and Windows Server 2016 RS1 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"OS Build:  " + $bn + "`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append
	foreach ($line in $ReferenceCSV){
		if($line.OSversion -eq "2016RS1") {
			CheckForHotfix -hotfixID $($line.Article) -title $($line.Title) -Warn $($line.Warn)
		}
	}
	CheckForHotfix -hotfixID 5005698 -title "KB5005698: Servicing stack update for Windows 10, version 1607: September 14, 2021"
}	
elseif ($bn -eq 10240){
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 10 and Windows Server 2016 RTM Rollups"	 | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"OS Build:  " + $bn + "`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append
	foreach ($line in $ReferenceCSV){
		if($line.OSversion -eq "2016") {
			CheckForHotfix -hotfixID $($line.Article) -title $($line.Title) -Warn $($line.Warn)
		}
	}
	CheckForHotfix -hotfixID 5001399 -title "KB5001399: Servicing stack update for Windows 10: April 13, 2021"
}
elseif ($bn -eq 9600){
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 8.1 and Windows Server 2012 R2 Rollups"	 | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"OS Build:  " + $bn + "`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append
	foreach ($line in $ReferenceCSV){
		if($line.OSversion -eq "2012R2") {
			CheckForHotfix -hotfixID $($line.Article) -title $($line.Title) -Warn $($line.Warn)
		}
	}
	CheckForHotfix -hotfixID 5001403 -title "KB5001403: Servicing stack update for Windows 8.1, Windows RT 8.1, and Windows Server 2012 R2: April 13, 2021"
	CheckForHotfix -hotfixID 3123245 -title "Update improves port exhaustion identification in Windows Server 2012 R2"
	CheckForHotfix -hotfixID 3179574 -title "August 2016 update rollup for Windows RT 8.1, Windows 8.1, and Windows Server 2012 R2"
	CheckForHotfix -hotfixID 3172614 -title "July 2016 update rollup for Windows RT 8.1, Windows 8.1, and Windows Server 2012 R2"
	CheckForHotfix -hotfixID 3013769 -title "December 2014 update rollup for Windows RT 8.1, Windows 8.1, and Windows Server 2012 R2"
	CheckForHotfix -hotfixID 3000850 -title "November 2014 update rollup for Windows RT 8.1, Windows 8.1, and Windows Server 2012 R2"
	CheckForHotfix -hotfixID 2919355 -title "Windows RT 8.1, Windows 8.1, and Windows Server 2012 R2 Update: April 2014"
}
elseif ($bn -eq 9200){
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows Server 2012 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"OS Build:  " + $bn + "`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append
	foreach ($line in $ReferenceCSV){
		if($line.OSversion -eq "2012") {
			CheckForHotfix -hotfixID $($line.Article) -title $($line.Title) -Warn $($line.Warn)
		}
	}
	CheckForHotfix -hotfixID 5001401 -title "KB5001401: Servicing stack update for Windows Server 2012: April 13, 2021"
	CheckForHotfix -hotfixID 3179575 -title "August 2016 update rollup for Windows Server 2012"
	CheckForHotfix -hotfixID 2984005 -title "September 2014 update rollup for Windows RT, Windows 8, and Windows Server 2012"
	CheckForHotfix -hotfixID 2962407 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: June 2014" 
	CheckForHotfix -hotfixID 2934016 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: April 2014" 	
	CheckForHotfix -hotfixID 2862768 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: August 2013"	
	CheckForHotfix -hotfixID 2756872 -title "Windows 8 Client and Windows Server 2012 General Availability Update Rollup"
}
elseif ($bn -eq 7601){
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 7 and Windows Server 2008 R2 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"OS Build:  " + $bn + "   (RTM=7600, SP1=7601)`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append
	foreach ($line in $ReferenceCSV){
		if($line.OSversion -eq "2008R2") {
			CheckForHotfix -hotfixID $($line.Article) -title $($line.Title) -Warn $($line.Warn)
		}
	}
	CheckForHotfix -hotfixID 3125574 -title "Convenience roll-up update for Windows 7 SP1 and Windows Server 2008 R2 SP1" -Warn "Yes"
	CheckForHotfix -hotfixID 4490628 -title "Servicing stack update for Windows 7 SP1 and Windows Server 2008 R2 SP1: March 12, 2019"
	CheckForHotfix -hotfixID 4592510 -title "Servicing stack update for Windows 7 SP1 and Server 2008 R2 SP1: December 8, 2020"
	CheckForHotfix -hotfixID 5010451 -title "KB5010451: Servicing stack update for Windows 7 SP1 and Server 2008 R2 SP1: February 8, 2022"
	CheckForHotfix -hotfixID 4538483 -title "Extended Security Updates (ESU) Licensing Preparation Package for Windows 7 SP1 and Windows Server 2008 R2 SP1"
	CheckForHotfix -hotfixID 2775511 -title "An enterprise hotfix rollup is available for Windows 7 SP1 and Windows Server 2008 R2 SP1"
}
elseif (($bn -eq 6002) -or ($bn -eq 6003)){
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows Vista and Windows Server 2008 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"OS Build:  " + $bn + "   (RTM=6000, SP2=6002 or 6003)`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append
	foreach ($line in $ReferenceCSV){
		if($line.OSversion -eq "2008") {
			CheckForHotfix -hotfixID $($line.Article) -title $($line.Title) -Warn $($line.Warn)
		}
	}
	CheckForHotfix -hotfixID 4517134 -title "Servicing stack update for Windows Server 2008 SP2: September 10, 2019"
	CheckForHotfix -hotfixID 4580971 -title "Servicing stack update for Windows Server 2008 SP2: October 13, 2020"
	CheckForHotfix -hotfixID 5010452 -title "KB5010452: Servicing stack update for Windows Server 2008 SP2: February 8, 2022"
}

CollectFiles -filesToCollect $OutputFile -fileDescription "Hotfix Rollups" -SectionDescription $sectionDescription


# SIG # Begin signature block
# MIInxAYJKoZIhvcNAQcCoIIntTCCJ7ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA/mZtztrar2Jv0
# ApSTuNppt8dOiS6f5AxFgn/vtlAYfKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGaQwghmgAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILhQvIfitUHaTi2brU7N9X0v
# Hc9R8O1l6nzxS5QMsmkAMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAhm/IfZDEp8rtVZ2GX0WoD5n524YMcM009yxpJY1WPjr8fcaR2Th8S
# WBNlRsN8Il63A4FdQVoIMMRs05wbVgdKgBK/6Nn9+E12+8+U3Lcwa1u9QPjW2W4i
# HDQ+6d5stgJmjdx5duJUwjRyOk/gOFBilfdztd0j1uqmoDC5+rN67G9uvZqN+CYg
# uQfJ6rTbOjWi056bb3bNUL7DGFmj+U5ZBb587o8ZcC1smfdjmH8Uxck7/ib6I18E
# Vju7g2sp8Nt7JU+gbr7vLY7ccGsObD7quzxxDphdOJ9dpxxRGMwhZHaWRuLrghu8
# ingU3YQtGEhRf2S0/MXxumxD/bR/Fnj1oYIXLDCCFygGCisGAQQBgjcDAwExghcY
# MIIXFAYJKoZIhvcNAQcCoIIXBTCCFwECAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIEeSOLS3nQnusbCsdv4WZKyzIyO0bdUoxsyPspr/XGTeAgZkP9G6
# OwMYEzIwMjMwNDI2MTUwMDA4LjkwMVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046QTI0MC00QjgyLTEzMEUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF7MIIHJzCCBQ+gAwIBAgITMwAAAbgI1MG4eeBRSQABAAABuDAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MjA5MjAyMDIyMTZaFw0yMzEyMTQyMDIyMTZaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkEyNDAt
# NEI4Mi0xMzBFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAnBux/BEcRGfkL3lA8aff
# u0nm86Jj1paN4gPGmBpdpgaKqzDQbRy8Irdi6Wup6YR/YKQZJ1w4kAX74SqE5Kqs
# 7XecZyOrDqEU2ewbAoA3LN13Cc47SPPWV8Egi7vtNt82+dpZvBJG7QNMYcDufs9H
# Qxgn1sL8eilK2lsV/rTospxNafBpS4R0CHHoUCqDWuSC6CK65prErLFGR2MVksoV
# cRcv2nTU+3BLR8bq9mJFWcQqB5qXZN4u90AipqkHCW09iJ+CqentnhUkxw+jRNaZ
# E1UU5wdE3BYd6E33GDq6AgZc+juEylas+CDiagc7Z6lzRPfquCb2GUOuXbxsblNq
# SZXs0n3yRsXmWC2WujBPp5zARW24t3hrSDNiqFqdbvNoVmcN+3nIx7HLn2J8RN3O
# nACuPackDIiyKrU9jdc+baZQwuUAKSyp6Ucp9aKEr8V6HD+bOKi8FXCSSv8bQXX0
# 5aBH4wFQqJ/Ck7JCIsDGuq9Wd8JjhCMkJmIci5LXkcJD9Mi39CPjHVa9FrVSqOea
# ku7j/IFhZmx29mirxJcjuI6zua55wAl4SRiUzqI6QyKCHMSGNAr1OE+mgC2W5dsv
# uogcat8WUeZf/iyhzuOPWPy4HfVTfiAmUHZemGMxpP4T471IiaT/oZFX1KbwLzwW
# eabZV3AyW4I0BTM8WN+8fHcCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBTE/UclN4XD
# M1ijWeN+5xe5R9BpbjAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAn26TyaLCkygr
# DcP33qmITNt6AAbGQAEdifa8/aFuqeRL1T3uz/pCXJk6EYWxW51qIt5FllOxobmF
# HSgK4Eg1n+V6WjnHMdz6YE6kFenFJpbWGqjFoIuxUfUQG3PuKfbkePL56O4FyKUf
# oRnRm03GZYYhDPxHQC5LROPhWAlcciVc/11U6LIaj1V6WuT4UbH8EL6IS4Jop38i
# zKkc+IJQKHnYMZz3WzZLuV1DHUfgKWM4C1qcN9u9J6MBJYuj+zfDRcwBsO6tY2ez
# ReJ0AXZGcvU9rGg7LP1VhqQ0YrgXf+4lFmdWBuwJi7A1fUGZLAzVls9KeCA1IZNn
# H8VDbQmP+6WsrSvIBu81s1viSRpLhrvruJ8Kq9Q4UuVRPw83jeGGV3EjrIc8w5Yi
# 0mkQchkGJM0puUGxhsiuCFvVib219KwtrlkkPNVk2d1F+FSok7JcX4JWb061WYUM
# b2QjAzpABfxDSJ/vbXPhU7Nk28PyS2DWUj5eNeBcMlWzeHjuwy70ZdJjOTL7t22C
# ZzeJE+R1rdhVF2Y8m00U3Q0vJtyywTu+EUKKPvl4MZAEWrQDgpUbq4F2vpRNbATR
# UofEHPYGka+fsEKz7nLGcX4dXoJSJyQOqo+L8gjtmyx30Rs/27OPiW6V1cMA+tYa
# 10ar7ArSh2UY1W4IzGwveGfz4qI71SIwggdxMIIFWaADAgECAhMzAAAAFcXna54C
# m0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMy
# MjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51
# yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY
# 6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9
# cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN
# 7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDua
# Rr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74
# kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2
# K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5
# TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZk
# i1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9Q
# BXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3Pmri
# Lq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUC
# BBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9y
# eS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUA
# YgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
# 1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIw
# MTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/yp
# b+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulm
# ZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM
# 9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECW
# OKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4
# FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3Uw
# xTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPX
# fx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVX
# VAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGC
# onsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU
# 5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEG
# ahC0HVUzWLOhcGbyoYIC1zCCAkACAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OkEyNDAtNEI4Mi0xMzBFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBwa15WoXH8htMpcct65cI9E8wPu6CBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA5/OJtjAiGA8yMDIzMDQyNjE5Mjk1OFoYDzIwMjMwNDI3MTkyOTU4WjB3MD0G
# CisGAQQBhFkKBAExLzAtMAoCBQDn84m2AgEAMAoCAQACAhS5AgH/MAcCAQACAjJi
# MAoCBQDn9Ns2AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAI
# AgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAK+S1zWL5Csx7
# RhiQgdDiRj3d3N+G7LtvVq0yRPfCHWlZ73fc32CFfzvLYcpQW/8WdLYmeTLUWbXE
# o/uw8ycfMhts8TiXq0fAUK3sXY1ntDYETzEi10KVOZbEho9wp6s3Ut0f94cw6u31
# 6NKTyCu2u1ZvvT9R4IxlVmQTzK8alt4xggQNMIIECQIBATCBkzB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAbgI1MG4eeBRSQABAAABuDANBglghkgB
# ZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3
# DQEJBDEiBCD4llbERS+kQNfjfxkPtKidpC/9H6Wkg69fPMxj3dfIWjCB+gYLKoZI
# hvcNAQkQAi8xgeowgecwgeQwgb0EICjr1jigcDtDilL5jU2wF+ukhhN5aw94ZNqa
# LRfQ8PsfMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAG4CNTBuHngUUkAAQAAAbgwIgQg0o0pESqzMOsSnLe4v5FzAxMAZYn6+0pPHK9n
# uvCGL0cwDQYJKoZIhvcNAQELBQAEggIAhEKYJuEG3wQAijgJLb2R8tT8wSEbPAUi
# WA5JJDKo4BZE2sInAtnE/hQMGjTEwnI2G0kfw699iSyr6M7cKg7LpI9H4feKQJun
# uA029aFIOtNoKytoslGsvMbIBWFuWDA1VIAsoOEGC9FJuPKVPMU11wUKIjpskvHV
# dQ+7queEF2RA1vxGA4z2XC0lpzCZKg0pQ1CRgyJUFliXDWCOIf4xAL4v05gAOB/3
# mRcLoSuVBrrATYDut6CYGRlwlWwCQw7+TOfFkne6MsYHzWAYlHuzkSD29QZnOYcE
# qbGqhMbTAj+Z0GhziWABT3nYs48W8lUJw0yx53zmVFvMf2mtG77QOkNN4xTRkjLC
# 7xTBLc1fyYb6KgGWSQURf79c2uXLKWgA1uhluF+jKOQBlhoRUHDxPQ/xLGl4lB28
# AQFcdcJjKNu2emOCSowJnat8KYs7C2IJ5qEUgJJzmm6cgyeslmrc0ifn36R06SY1
# E2yqE1nV0ocX3lz2FMzHPcjNQSban9UMKBUeILWebq7l2nG/8bbJ8Le03bvnjuX5
# LIjgB6QAe/ClR2dlXCPL4Bio0kx//QWX0BQT7S+9DGtstx6JN3Ei0GMFoRq+W3RS
# jfrJv4/qL4ADi91r6oc4tzKwnvvD0IzDzyQMuIP8YP2IeDR52l/CRL+d/euDC9hW
# cBvK/NYNIww=
# SIG # End signature block
