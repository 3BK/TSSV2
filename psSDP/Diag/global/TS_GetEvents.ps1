#************************************************
# TS_GetEvents.ps1
# Version 2.3.5
# Date: 05-13-2013 - Last_Edit: 2022-08-14
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script is used to export machine event logs in different formats, such as EVT(X), CSV and TXT
#***********************************************

PARAM($EventLogNames="AllWMI", 
	  $OutputFormats="",
	  $ExclusionList="", 
	  $Days="", 
	  $EventLogAdvisorAlertXMLs ="",
	  $SectionDescription="Event Logs",
	  $Prefix=$null,
	  $Suffix=$null,
	  $Query=$Null,
	  $After,
	  $Before,
	  [switch] $DisableRootCauseDetection)

# 2023-02-20 WalterE mod Trap #we#
trap [Exception]{
	WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; continue
	Write-Host "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_"
}

Import-LocalizedData -BindingVariable GetEventsStrings

If ([string]::IsNullOrEmpty($Days) -and ($null -ne $Global:EvtDaysBck)) {$Days=$Global:EvtDaysBck}
#Write-DiagProgress -Activity $GetEventsStrings.ID_EVENTLOG -Status ($GetEventsStrings.ID_ExportingLogsDays + ": " + $Days)

$DisplayToAdd = ''
$OutputPath = $PWD.Path + "\EventLogs"
if (-not (Test-Path($OutputPath))) {New-Item -ItemType "Directory" $OutputPath | Out-Null }

if (($OSVersion.Major -lt 6) -and ($EventLogNames -eq "AllEvents")){ #Pre-WinVista
	$EventLogNames = "AllWMI"
}

if ($Days -ne ""){
	$Days = "/days:$Days"
	$DisplayToAdd = " ($Days days)"
	
	if ($null -ne $Query) {"WARNING: Query argument cannot be used in conjunction with -Days and will be ignored" | WriteTo-StdOut -IsError -ShortFormat -InvokeInfo $MyInvocation}
	if (($null -ne $After) -or ($null -ne $Before) ) {"WARNING: -After or -Before arguments cannot be used in conjunction with -Days and will be ignored" | WriteTo-StdOut -ShortFormat -InvokeInfo $MyInvocation}
}
elseif ($null -ne $Query){
	$Query = "`"/query:$Query`""
	if (($null -ne $After) -or ($null -ne $Before)) {"WARNING: -After or -Before arguments cannot be used in conjunction with -Query and will be ignored" | WriteTo-StdOut -ShortFormat -InvokeInfo $MyInvocation}
}
elseif (($null -ne $After) -and ($null -ne $Before) -and ($Before -le $After)){
	"WARNING: -Before argument contains [$Before] and cannot be earlier than -After argument: [$After] and therefore it will ignored." | WriteTo-StdOut -ShortFormat -InvokeInfo $MyInvocation
	$After = $null
}

if ((($null -ne $After) -or ($null -ne $Before)) -and ($OSVersion.Major -ge 6)){
	if (($null -ne $After) -and ($null -eq ($After -as [DateTime]))){
		"-After argument type is [" + $After.GetType() + "] and contains value [$After]. This value cannot be converted to [datetime] and will be ignored" | WriteTo-StdOut -IsError
		$After = $null
	}
	
	if (($null -ne $Before) -and ($null -eq ($Before -as [DateTime]))){
		"-Before argument type is [" + $Before.GetType() + "] and contains value [$Before]. This value cannot be converted to [datetime] and will be ignored" | WriteTo-StdOut -IsError
		$Before = $null
	}
	
	if (($null -ne $After) -or ($null -ne $Before)){
		$DisplayToAdd = " (Filtered)"
		$TimeRange = @()
		if ($null -ne $Before){
			$BeforeLogString = "[Before: $Before $($Before.Kind.ToString())]"
			if ($Before.Kind -ne [System.DateTimeKind]::Utc){
				$Before += [System.TimeZoneInfo]::ConvertTimeToUtc($Before)
			}
			$TimeRange += "@SystemTime <= '" + $Before.ToString("o") + "'"
		}
		if ($null -ne $After){
			$AfterLogString = "[After: $After $($After.Kind.ToString())]"
			if ($After.Kind -ne [System.DateTimeKind]::Utc){
				$After += [System.TimeZoneInfo]::ConvertTimeToUtc($After)
			}
			$TimeRange += "@SystemTime >= '" + $After.ToString("o") + "'"
		}

		"-Before and/ or -After arguments to TS_GetEvents were used: $BeforeLogString $AfterLogString" | WriteTo-StdOut
		$Query = "*[System[TimeCreated[" + [string]::Join(" and ", $TimeRange) + "]]]"
		$Query = "`"/query:$Query`""
	}
}
elseif ((($null -ne $After) -or ($null -ne $Before)) -and ($OSVersion.Major -lt 6)){
	"WARNING: Arguments -After or -Before arguments are supported only on Windows Vista or newer Operating Systems and therefore it will ignored" | WriteTo-StdOut -ShortFormat -InvokeInfo $MyInvocation
	$After = $null
	$Before = $null
}

switch ($EventLogNames){
	"AllEvents" {
		#Commented line below since Get-WinEvent requires .NET Framework 3.5 - which is not always installed on server media
		#$EventLogNames = Get-WinEvent -ListLog * | Where-Object {$_.RecordCount -gt 0} | Select-Object LogName
		$EventLogNames = wevtutil.exe el
	}
	"AllWMI" {
		$EventLogList = Get-EventLog -List | Where-Object {$_.Entries.Count -gt 0} | Select-Object @{Name="LogName"; Expression={$_.Log}}
		$EventLogNames = @()
		$EventLogList | ForEach-Object {$EventLogNames += $_.LogName}
	}
}

if ($OutputFormats -eq ""){
	$OutputFormatCMD = "/TXT /CSV /evtx /evt"
} 
else{
	ForEach ($OutputFormat in $OutputFormats){
		$OutputFormatCMD += "/" + $OutputFormat + " "
	}
}

$EventLogAdvisorXMLCMD = ""

if (($EventLogAdvisorAlertXMLs -ne "") -or ($null -ne $Global:EventLogAdvisorAlertXML)){
	$EventLogAdvisorXMLFilename = Join-Path -Path $PWD.Path -ChildPath "EventLogAdvisorAlerts.XML"
	"<?xml version='1.0'?>" | Out-File $EventLogAdvisorXMLFilename
	
	if ($EventLogAdvisorAlertXMLs -ne ""){
		ForEach ($EventLogAdvisorXML in $EventLogAdvisorAlertXMLs){
			#Save Alerts to disk, then, use file as command line for GetEvents script
			$EventLogAdvisorXML | Out-File $EventLogAdvisorXMLFilename -append
		}
	}
	
	if ($null -ne $Global:EventLogAdvisorAlertXML){
		if (Test-Path $EventLogAdvisorXMLFilename){
			"[GenerateEventLogAdvisorXML] $EventLogAdvisorXMLFilename already exists. Merging content."
			[xml] $EventLogAdvisorXML = Get-Content $EventLogAdvisorXMLFilename
			
			ForEach ($GlobalSectionNode in $Global:EventLogAdvisorAlertXML.SelectNodes("/Alerts/Section")){
				$SectionName = $GlobalSectionNode.SectionName
				$SectionElement = $EventLogAdvisorXML.SelectSingleNode("/Alerts/Section[SectionName = `'$SectionName`']")
				if ($null -eq $SectionElement){
					$SectionElement = $EventLogAdvisorXML.CreateElement("Section")						
					$Null = $EventLogAdvisorXML.SelectSingleNode('Alerts').AppendChild($SectionElement)
					
					$SectionNameElement = $EventLogAdvisorXML.CreateElement("SectionName")
					$Null = $SectionNameElement.set_InnerText($SectionName)						
					$Null = $SectionElement.AppendChild($SectionNameElement)
					
					$SectionPriorityElement = $EventLogAdvisorXML.CreateElement("SectionPriority")
					$Null = $SectionPriorityElement.set_InnerText(30)
					$Null = $SectionElement.AppendChild($SectionPriorityElement)
				}
				
				ForEach ($GlobalSectionAlertNode in $GlobalSectionNode.SelectNodes("Alert")){
					$EventLogName = $GlobalSectionAlertNode.EventLog
					$EventLogSource = $GlobalSectionAlertNode.Source
					$EventLogId = $GlobalSectionAlertNode.ID
					
					$ExistingAlertElement = $EventLogAdvisorXML.SelectSingleNode("/Alerts/Section[Alert[(EventLog = `'$EventLogName`') and (Source = `'$EventLogSource`') and (ID = `'$EventLogId`')]]")

					if ($null -eq $ExistingAlertElement){
						$AlertElement = $EventLogAdvisorXML.CreateElement("Alert")
						$Null = $AlertElement.Set_InnerXML($GlobalSectionAlertNode.Get_InnerXML())
						$Null = $SectionElement.AppendChild($AlertElement)
					}else{
						"WARNING: An alert for event log [$EventLogName], Event ID [$EventLogId], Source [$EventLogSource] was already been queued by another script." | WriteTo-StdOut -ShortFormat
					}
				}
			}
			$EventLogAdvisorXML.Save($EventLogAdvisorXMLFilename)
		}else{
			$Global:EventLogAdvisorAlertXML.Save($EventLogAdvisorXMLFilename)
		}
	}
	$EventLogAdvisorXMLCMD = "/AlertXML:$EventLogAdvisorXMLFilename /GenerateScriptedDiagXMLAlerts "
}
	
if ($SectionDescription -eq ""){
	$SectionDescription = $GetEventsStrings.ID_EventLogFiles
}

if ($null -ne $Prefix){
	$Prefix = "/prefix:`"" + $ComputerName + "_evt_" + $Prefix + "`""
}

if ($null -ne $Suffix){
	$Suffix = "/suffix:`"" + $Suffix + "`""
}

ForEach ($EventLogName in $EventLogNames){
    if ($ExclusionList -notcontains $EventLogName){
		$ExportingString = $GetEventsStrings.ID_ExportingLogs
    	Write-DiagProgress -Activity $GetEventsStrings.ID_EVENTLOG -Status ($ExportingString + $DisplayToAdd + ": " + $EventLogName)
    	$CommandToExecute = "cscript.exe //E:vbscript GetEvents.VBS `"$EventLogName`" /channel $Days $OutputFormatCMD $EventLogAdvisorXMLCMD `"$OutputPath`" /noextended $Query $Prefix $Suffix"
		$OutputFiles = $OutputPath + "\" + $Computername + "_evt_*.*"
		$FileDescription = $EventLogName.ToString() + $DisplayToAdd
		RunCmD -commandToRun $CommandToExecute -sectionDescription $SectionDescription -filesToCollect $OutputFiles -fileDescription $FileDescription

		$EventLogFiles = Get-ChildItem $OutputFiles
		if ($null -ne $EventLogFiles){
    		$EventLogFiles | Remove-Item
    	}
    }
}

$EventLogAlertXMLFileName = $Computername + "_EventLogAlerts.XML"

if (($DisableRootCauseDetection.IsPresent -ne $true) -and (test-path $EventLogAlertXMLFileName)){	
	[xml] $XMLDoc = Get-Content -Path $EventLogAlertXMLFileName
	if($null -ne $XMLDoc){
		$Processed = $XMLDoc.SelectSingleNode("//Processed").InnerXML
	}
	if($null -eq $Processed){
		#Check if there is any node that does not contain SkipRootCauseDetection. In this case, set root cause detected to 'true'
		if ($null -eq $XMLDoc.SelectSingleNode("//Object[not(Property[@Name=`"SkipRootCauseDetection`"])]")){
			Update-DiagRootCause -id RC_GetEvents -Detected $true
			if($null -ne $XMLDoc){
				[System.Xml.XmlElement] $rootElement=$XMLDoc.SelectSingleNode("//Root")
				[System.Xml.XmlElement] $element = $XMLDoc.CreateElement("Processed")
				$element.innerXML = "True"
				$rootElement.AppendChild($element)
				$XMLDoc.Save($EventLogAlertXMLFileName)	
			}
		}
	}
}

# SIG # Begin signature block
# MIInwQYJKoZIhvcNAQcCoIInsjCCJ64CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDy0OLlIVxHHt3k
# s9s/sh29QGgzTHw9k53mbm4Wpng78KCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGaEwghmdAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIKD0T53vOzmeAHkJgCAfJcK
# GXXSyLOmg5rHbkrwi1uHMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBIOSKN+CnMKGfP8OVcU0py7sVidWP4i3wEITOR+ZIMO+vWXMBCEiBN
# tTOx7+6Rb/fDuCf2780CVm3sCW1V38I/b3JnQDXDQtSay28wlCk4iw7pu3X+/lsr
# KrKkSE528MKRZoafXjuy9T+nNNElsdbPrWodCNJtSxEURFdeNEmYNCuZBl6Zbmxv
# 3uRQ0INsCvkw0dGxj3nT3o8CTGZyJDsOtHBn16auykZ0hJ8dB6ZVgC14YlmtR4Oj
# xBULhx/g3RjrkqpR6o5OuUSP8vAgiP8CvyS+I+agHWDV9+3DQ9tCFZ4fhFPbKWGI
# 9yLUa07OycHLSWpis1NoGMhjKO+yXcLtoYIXKTCCFyUGCisGAQQBgjcDAwExghcV
# MIIXEQYJKoZIhvcNAQcCoIIXAjCCFv4CAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIGAD/BVx7q9V5uQOif3UEiphedKW6MQMGTU5U+vNNRqcAgZj5YzF
# dPYYEzIwMjMwMjIwMTUwNTM4LjIyM1owBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046MTc5RS00QkIwLTgyNDYxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF4MIIHJzCCBQ+gAwIBAgITMwAAAbWtGt/XhXBtEwABAAABtTAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MjA5MjAyMDIyMTFaFw0yMzEyMTQyMDIyMTFaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjE3OUUt
# NEJCMC04MjQ2MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlwsKuGVegsKNiYXFwU+C
# SHnt2a7PfWw2yPwiW+YRlEJsH3ibFIiPfk/yblMp8JGantu+7Di/+3e5wWN/nbJU
# IMUjEWJnc8JMjoPmHCWsMtJOuR/1Ru4aa1RrxQtIelq098TBl4k7NsEE87l7qKFm
# y8iwGNQjkwr0bMu4BJwy7BUXiXHegOSU992rfQ4xNZoxznv42TLQsc9NmcBq5Wsl
# kqVATcc8PSfgBLEpdG1Dp2wqNw4JrJFwJNA1bfzTScYABc5smRZBgsP4JiK/8CVr
# locheEyQonjm3rFttrojAreSUnixALu9pDrsBI4DUPGG34oIbieI1oqFl/xk7A+7
# uM8k4o8ifMVWNTaczbPldDYtn6hBre7r25RED4uecCxP8Dxy34YPUElWllPP3LAX
# p5cMwRjx+EWzjEtILEKXuAcfxrXCTwyYhm5XNzCCZYh4/gF2U2y/bYfekKpaoFYw
# koZeT6ZxoQbX5Kftgj+tZkFV21UvZIkJ6b34a/44dtrsK6diTmVnNTM9J6P6Ehlk
# 2sfcUwbHIGL8mYqdKOiyd4RxOCmSvcFNkZEgrk548mHCbDbTyO9xSzN1EkWxbp8n
# /LHVnZ9fp5hILGntkMzaD5aXRCQyHSIhsPtR7Q/rKoHyjFqgtGO9ftnxYvxzNrbK
# eMCzwmcqwMrX6Hcxe0SeKZ8CAwEAAaOCAUkwggFFMB0GA1UdDgQWBBRsUIbZgoZV
# XVXVWQX0Ok1VO2bHUzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAkFGOpyjKV2s2
# sA+wTqDwDdhp0mFrPtiU4rN3OonTWqb85M6WH19c/P517xujLCih/HllP5xKWmXn
# AIRV1/NQDkJBLSdLTb/NQtcT1FWGQ7CMTnrn9tLZxqIFtKVylvQNyh31C/qkC8Qm
# NpyzakO0G38uOGgOkJ9Eq4nA+7QwVfobDlggWuEpzdFnRdyXL32gOqSvrLjFKpv4
# KEVqaBTiaxCWZDlIhG3YgUza7cnG5Z2SA/feMq/IiV06AzUadZw6XgcTrqXmEmE0
# tMmdl44MMFC3wGU9AVeFCWKdD9WOnYA2zHg+XF2LQVto0VYtFLd6c6DQFcmB38Gv
# PCKVYSn8r10EoXuRN+gQ7hLcim12esOnW4F4bHCmHWTVWeAGgPiSItHHRfGKLEUZ
# motVOdFPR8wiuADT/fHSXBkkdpL12tvgEGELeTznzFulZ16b/Nv6dtbgSRZreesJ
# BNKpTjdYju/GqnlAkpflL6J0wxk957/UVYnmjjRY61jX90QGQmBzm9vs/+2bj02X
# x/bXXy8vq57jmNXQ2ufOaJm3nAcD2qOaSyXEOj9mqhMt4tdvMjHhiNPldfj0Q7Kq
# 1HgdRBrKWkzCQNi4ts8HRJBipNaVpWfU7BcRn8BeYzdLoIzwRLDtatz6aBho3oD/
# bXHrZagxprM5MsMB/rVfb5Xn1YS7/uEwggdxMIIFWaADAgECAhMzAAAAFcXna54C
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
# ahC0HVUzWLOhcGbyoYIC1DCCAj0CAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjE3OUUtNEJCMC04MjQ2MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQCNMJ9r11RZj0PWu3uk+aQHF3IsVaCBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA553iNjAiGA8yMDIzMDIyMDIwMTIzOFoYDzIwMjMwMjIxMjAxMjM4WjB0MDoG
# CisGAQQBhFkKBAExLDAqMAoCBQDnneI2AgEAMAcCAQACAg1KMAcCAQACAhNVMAoC
# BQDnnzO2AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEA
# AgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAjSJ7osP/iG+9gpaP
# aCYs9DUdgh1lH1DPgLGGNBiR8NtMTP3FamhfUcGnZ0ujZPAs0gYpjEwUYSbE/l4w
# VIN5QPDqHyTRckFNGWmdLt+b9l0thj+LDhlynEWLF1EtnmIlIuk+L5T0IGx9rQTO
# LEltCQ4Pf3jhDsZ0a6rmStgcw3sxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAbWtGt/XhXBtEwABAAABtTANBglghkgBZQME
# AgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJ
# BDEiBCCZ5UKoJ1HwuxDA/6ffI7Gb+6rk9KEx/DcJHhDkkWOaazCB+gYLKoZIhvcN
# AQkQAi8xgeowgecwgeQwgb0EICfKDTUtaGcWifYc3OVnIpp7Ykn0S8JclVzrlAgF
# 8ciDMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAG1
# rRrf14VwbRMAAQAAAbUwIgQgCpQ7yHCYq6SSx6pbyBKpti3OzKk1m19JNvFoeNj6
# tNYwDQYJKoZIhvcNAQELBQAEggIAYg3RahbkYE2wM5Lpvtq+akQKIA39hcTp75qQ
# 4LbGU0CWydZqRAYTzmzat12nvmQuYHzZp86fECoN3Yk+Iu9LrGhmchbzsMHrdXWR
# /p1eJAJJwkvOxQdK5uW+dHcI4tKCpHuzrmkJRR2PcwzZyPRdf+DPKIP9+Yv/vmIk
# Kqd6L7YSUq9JKNRJgbspAvtm02kCoDgBuvxxLIy6kA98zihbEQD+PPZVjmri3nSc
# 5QAZeh+AA1HBm9vwtRzSFjXT/syQvd25c/JeMyd/q2DFpTXgAugOYyrdLMwTo5XT
# XPwZiBlIdU5hGyWcvkZu8RgBaY5AkcGniJV0n/j3ljtyaHbfj6itgnc+kGjhS0qZ
# 3eyJm3Iu/HhG96eYMFm4jyTUw1C+Pe6nrGDbe94rBiOmXf0+iz/VBFllvqGIZPdk
# 4wXc2tUCUEhjifpKeVdK9feINmwrXMp9rDbYoQ76nzLmOr06pH8nbf1Flyx8r7wz
# /OFqTB45ky9Qb7o9D5XFtx8qohuU29XijvOvz/WM4t2FO4Tx+WyWIFju3xgJKepV
# b8DS5akACF46toLgckFAV5YhrJ+J+GgAmXY/yc1qKPu/1qNyGAMEIg09fybnljrI
# xOSVQ2gbrnmqq/SRkTAbEDWvdDFBNcJW2KH+sCWx2JusUXHCFqvbrirEiQcpof6G
# Yh8i5X8=
# SIG # End signature block
