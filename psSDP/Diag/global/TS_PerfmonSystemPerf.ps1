#************************************************
# TS_PerfmonSystemPerf.ps1
# Version 2.0.1
# Date: 2-05-2011
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script obtains a 1 minute performance monitor based on the inbox 
#              'System Performance' data collector set. It also list the summary on results report.
#              For Windows XP/2003, script generates a simple data collection using basic counters
#************************************************

PARAM([int]$NumberOfSeconds = 60, [switch]$DoNotCollectPerfmonFiles, [string] $DataCollectorSetXMLName = "SystemPerformance.xml", [switch] $DoNotShowTOPProcesses, $ShowProcessesInReport = $null, [string] $ProcessesSectionTitle=$null, $CollectPerfmonDataFrom=$null)

#Arguments only work on WinVista+ OSs. On pre-Win7, this will only collect a 60 sec perfmon with basic counters

Import-LocalizedData -BindingVariable PerfMonCollectorStrings
Write-DiagProgress -Activity $PerfMonCollectorStrings.ID_PerfMonSystemPerf -Status $PerfMonCollectorStrings.ID_PerfMonSystemPerfRunning

$ProcGraph   = "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group id=`"GraphValue`" class=`"vmlimage`" style=`"width:320px;height:15px;vertical-align:middle`" coordsize=`"{MaxValue},100`" title=`"{ValueDisplay}`"><v:rect class=`"vmlimage`" style=`"top:1;left:1;width:{MaxValue};height:100`" strokecolor=`"#336699`"><v:fill type=`"gradient`" angle=`"0`" color=`"#C4CCC7`" color2=`"white`" /></v:rect><v:rect class=`"vmlimage`" style=`"top:2;left:1;width:{Value};height:99`" strokecolor=`"{GraphColorEnd}`"><v:fill type=`"gradient`" angle=`"270`" color=`"{GraphColorStart}`" color2=`"{GraphColorEnd}`" /></v:rect><v:rect style=`"top:-70;left:{TextStartPos};width:{MaxValue};height:50`" filled=`"false`" stroked=`"false`" textboxrect=`"top:19;left:1;width:{MaxValue};height:30`"><v:textbox style=`"color:{TextColor};`" inset=`"20px, 10px, 28px, 177px`">{ValueDisplay}</v:textbox></v:rect></v:group></span>"
$Image = @{
		"Red" = "<font face=`"Webdings`" color=`"Red`">n </font>";
		"Yellow" = "<font face=`"Webdings`" color=`"Orange`">n </font>";
		"Green" = "<font face=`"Webdings`" color=`"Green`">n </font>";
		}

Function Run-DataCollectorSetFromXML(
	[string] $Name,
	[string] $PathToXML,
	[string] $DestinationFolder,
	[int] $NumberOfSecondsToRun = 60,
	$PerfMonCollectorStrings)
{
	if (Test-Path $PathToXML) 
	{
		[xml] $DataCollectorXML = Get-Content $PathToXML

		$DataCollectorXML.DataCollectorSet.RootPath = $DestinationFolder
		$DataCollectorXML.DataCollectorSet.Duration = $NumberOfSecondsToRun.ToString()

		$DataCollectorSet = New-Object -ComObject PLA.DatacollectorSet

		if ($DataCollectorSet -is [System.__ComObject])
		{
			$Error.Clear()
			
			$DataCollectorSet.SetXml($DataCollectorXML.Get_InnerXML()) | Out-Null
			$DataCollectorSet.Commit($Name, $null , 0x0003) | Out-Null
			$DataCollectorSet.Query($Name,$null) | Out-Null
			$DataCollectorSet.start($false) | Out-Null
			
			If (($null -ne $DataCollectorSet) -and ($Error.Count -eq 0))
			{
			
				Start-Sleep -Seconds $NumberOfSecondsToRun
				
				Write-DiagProgress -Activity $PerfMonCollectorStrings.ID_PerfMonSystemPerf -Status $PerfMonCollectorStrings.ID_PerfMonSystemPerfObtaining
				
				if ($DataCollectorSet.Status -eq 1) {$DataCollectorSet.Stop($false)}
				
				$retries = 0
				do 
				{
					$retries++
					Start-Sleep -Milliseconds 500
				} while (($DataCollectorSet.Status -ne 0) -and ($retries -lt 1800) -and ($null -ne $DataCollectorSet.Status)) #Wait for up to 15 minutes for the report to finish
			
				"Retries: $retries. Maximum retries: 1800. DataCollectorSet.Status: " + ($DataCollectorSet.Status) | WriteTo-StdOut -ShortFormat
			
				$OutputLocation = $DataCollectorSet.OutputLocation
			
				$DataCollectorSet.Delete()
		
				Write-DiagProgress -Activity $PerfMonCollectorStrings.ID_PerfMonSystemPerf -Status $PerfMonCollectorStrings.ID_PerfMonSystemPerfAnalyzing
				
				Return $OutputLocation
			} 
			else 
			{
				"An error has ocurred to create the following Data Collector Set:"  | WriteTo-StdOut -ShortFormat
				"Name: $Name"  | WriteTo-StdOut -ShortFormat
				"XML: $PathToXML"  | WriteTo-StdOut -ShortFormat
			}
		}
		else
		{
			"[DataCollectorSet is Null] An error has ocurred to create the following Data Collector Set:" | WriteTo-StdOut -ShortFormat
			"Name: $Name"  | WriteTo-StdOut -ShortFormat
			"XML: $PathToXML"  | WriteTo-StdOut -ShortFormat
		}

	} else {
		$PathToXML + " does not exist. Exiting..."  | WriteTo-StdOut -ShortFormat
	}
}

Function Get-StringTranslation([xml] $ReportXML, [string] $Value) 
{
	if ($Value.Length -gt 0)
	{
		$TranslatedString = $ReportXML.SelectSingleNode("//String[@ID='$Value']").Get_InnerText()
		if ($null -ne $TranslatedString) 
		{
			$TranslatedString
		} else {
			$Value
		}
	}
	else
	{
		return ""
	}
}

Function Add-SummaryToReport([string] $PathToXML, [boolean] $AddHighCPUProcesses = $true, [switch] $DoNotAddURLForPerfmonFiles, $ShowProcessesInReport, $ProcessesSectionTitle)
{
	#Open the PLA report.xml, obtain the header and add this information to the WTP Report
	if (Test-Path $PathToXML)
	{
		[xml] $ReportXML = Get-Content $PathToXML

		#Summary (Resource Overview) and Warnings
		foreach ($Table in $ReportXML.SelectNodes("/Report/Section[@name='advice']/Table"))
		{
			$Item_Summary = new-object PSObject
			$HTMTable  = $null
			#Resource Overview
			if ($Table.name -eq "sysHealthSummary") { 
				[Array] $Header = $null
				
				foreach ($Item in $Table.SelectNodes("Header"))
				{
					#$Header += "<tr>"
					foreach ($Data in $Item.SelectNodes("Data")) 
					{
						if ($null -ne $Data.name)
						{
						#if ($Data.name -ne "SysHealthComponentHdr") {
							$DataDisplayValue = Get-StringTranslation -ReportXML $ReportXML -Value $Data.name
							$Header += $DataDisplayValue
						#}
						}
					}
					#$Header += "</tr>"
				}
				
				foreach ($Item in $Table.SelectNodes("Item"))
				{
					$HTMTable += "<table>"
					$x = -1
					foreach ($Data in $Item.SelectNodes("Data")) 
					{	
						$x++
						if ($Data.name -eq "component") {
							$Component = Get-StringTranslation -ReportXML $ReportXML -Value $Data.Get_InnerText()
						} else {
							$DataDisplayValue = ""
							if ($Data.HasAttribute("img"))
							{
								$img = $Data.img
								$DataDisplayValue += $Image.$img
							}
		
							if ($Data.HasAttribute("translate")) 
							{
								#Need to translate String
								$DataDisplayValue += Get-StringTranslation -ReportXML $ReportXML -Value $Data.Get_InnerText()
							} else {
								$DataDisplayValue += $Data.Get_InnerText()
							}						
							
							if ($Data.HasAttribute("units")) 
							{
								$DataDisplayValue += $Data.units
							}	
							
							$HTMTable += "<tr><td>" + $Header[$x] + "</td><td>" + $DataDisplayValue + "</td></tr>"
						}
					}
					$HTMTable += "</table>"
					if ($null -ne $HTMTable) {
						add-member -inputobject $Item_Summary  -membertype noteproperty -name $Component -value $HTMTable
					}
					$HTMTable = $null
				}
			}
			
			
			if ($Table.name -eq "warning")
			{
				if ($Table.ChildNodes.Count -gt 0) 
				{
					#There is a warning on the report. Flag the Root Cause.
					
					$XMLFileName = [System.IO.Path]::GetFullPath("..\PerfmonReport.XML")
					
					"There are one or more alerts on perfmon xml file. RC_PerformanceMonitorWarning will be set. Report saved to $XMLFileName" | WriteTo-StdOut					
					$RootCauseDetected = $true
					#Make a copy of Perfmon XML file so the Resolver can display Warning information.
					$ReportXML.Save($XMLFileName)
				}
			}
		}
		
		if ($RootCauseDetected)
		{
			Update-DiagRootCause -Id "RC_PerformanceMonitorWarning" -Detected $true -Parameter @{"XMLFileName"=$XMLFileName}
		}
		
		#CPU
		$ID =  (Get-StringTranslation -ReportXML $ReportXML -Value $Table.ParentNode.name)
		$Item_Summary | ConvertTo-Xml2 | update-diagreport -id ("10_$ID") -name "Performance Monitor Overview" -verbosity informational

		if ($AddHighCPUProcesses -or ($null -ne $ShowProcessesInReport)) {
			$Processes = @()
			$MaxValue = 0
			foreach ($Item in $ReportXML.SelectNodes("/Report/Section[@name='tracerptCpusection']/Table[@name='imageStats']/Item[Data[@name='image']]"))
			{
				$ProcessName = $Item.SelectSingleNode("Data[@name='image']").Get_InnerText()
				[int]  $ProcessID = $Item.SelectSingleNode("Data[@name='pid']").Get_InnerText()
				[double] $ProcessCPU = $Item.SelectSingleNode("Data[@name='cpu']").Get_InnerText()
				$MaxValue += $Item.SelectSingleNode("Data[@name='cpu']").Get_InnerText()
				if ($ProcessID -ne 0) { #Skip Idle
					$process = @{ProcessName = $ProcessName; ProcessID = $ProcessID; ProcessCPU = $ProcessCPU}
					$Processes = $Processes + $process
				}
			}
		}
		
		if ($AddHighCPUProcesses) {
			
			$TopCPU_Summary = new-object PSObject
			
			foreach ($Process in $Processes | Sort-Object -Property {$_.ProcessCPU} -Descending | Select-Object -First 3)
			{
			
				$ValueDisplay = ("{0:N1}" -f $Process.ProcessCPU + "%")
				$GraphValue = $Process.ProcessCPU
				if (($GraphValue/$MaxValue) -lt .15)
				{
					$TextStartPos = $GraphValue
					$TextColor = "Gray"
				} else {
					$TextStartPos = 1
					$TextColor = "white"
				}
				
				$Graph = $ProcGraph -replace "{MaxValue}", "$MaxValue" -replace "{ValueDisplay}", "$ValueDisplay" -replace "{Value}", $GraphValue -replace "{GraphColorStart}", "#00336699" -replace "{GraphColorEnd}", "#00538CC6" -replace "{TextStartPos}", $TextStartPos -replace "{TextColor}", $TextColor
				add-member -inputobject $TopCPU_Summary -membertype noteproperty -name ($Process.get_Item("ProcessName") + " (PID " + $Process.get_Item("ProcessID") + ")") -value $Graph
			}
			
			#if (-not $DoNotAddURLForPerfmonFiles.IsPresent)
			#{
				#add-member -inputobject $TopCPU_Summary -membertype noteproperty -name "More Information" -value "For the information, please open the <a href= `"`#" + $OutputFile + "`">" + "Performance Monitor Report</a>."
			#}
			
			$TopCPU_Summary | ConvertTo-Xml2 | update-diagreport -id ("11_TopCPUProcesses") -name "Process Monitor Top Processes (CPU)" -verbosity informational
		}

		if ($null -ne $ShowProcessesInReport)
		{
			$ShowProcesses_Summary = new-object PSObject
			$ProcessAdded = $false
			foreach ($Process in $Processes | Sort-Object -Property {$_.ProcessCPU} -Descending)
			{
				$ShowProcess = $false
				foreach ($processToShow in $ShowProcessesInReport)
				{
					if (($processToShow -like ($Process.ProcessName + "*")) -or ($processToShow -eq $Process.ProcessID))
					{
						$ShowProcess = $true
					}
				}
				
				if ($ShowProcess)
				{	
					$ProcessAdded = $true
					$ValueDisplay = ("{0:N1}" -f $Process.ProcessCPU + "%")
					$GraphValue = $Process.ProcessCPU
					if (($GraphValue/$MaxValue) -lt .15)
					{
						$TextStartPos = $GraphValue
						$TextColor = "Gray"
					} else {
						$TextStartPos = 1
						$TextColor = "white"
					}
					
					$Graph = $ProcGraph -replace "{MaxValue}", "$MaxValue" -replace "{ValueDisplay}", "$ValueDisplay" -replace "{Value}", $GraphValue -replace "{GraphColorStart}", "#00336699" -replace "{GraphColorEnd}", "#00538CC6" -replace "{TextStartPos}", $TextStartPos -replace "{TextColor}", $TextColor
					add-member -inputobject $ShowProcesses_Summary -membertype noteproperty -name ($Process.get_Item("ProcessName") + " (PID " + $Process.get_Item("ProcessID") + ")") -value $Graph
				}
			}
			if ($ProcessAdded -eq $true)
			{
			$ShowProcesses_Summary | ConvertTo-Xml2 | update-diagreport -id ("11_CPUProcesses") -name $ProcessesSectionTitle -verbosity informational	
			}	
		}
	}
	else
	{
		"Error: $PathToXML does not exist" | WriteTo-StdOut
	}
}

Function AddPropertiestoXMLNode($WMIObject, $XMLNode)
{
	Foreach ($WMIProperty in $WMIObject | Get-Member -type *Property | Where-Object {$_.Name.StartsWith("__") -eq $false})
	{
		$PropertyValue = $WMIObject.($WMIProperty.Name)
		if ($null -ne $PropertyValue)
		{
			$XMLNode.SetAttribute($WMIProperty.Name.ToString(),$PropertyValue.ToString())
		}
		else
		{
			$XMLNode.SetAttribute($WMIProperty.Name.ToString(),'')
		}
	}
	return $XMLNode
}

Function CleanACLOnPerfmonFolder($DestinationFolderName)
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $Error[0]
		$Error.Clear()
		continue
	}
	
	$Error.Clear()	
	$SysmonAccount = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonLog").ObjectName
	if ($null -ne $SysmonAccount)
	{
		"Performance Monitor Account: [$SysmonAccount]. Setting permissions to output folder" | WriteTo-StdOut
		
		$FullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
		$InheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit, "ContainerInherit"
		$PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None

		$objType =[System.Security.AccessControl.AccessControlType]::Allow 
		
		$rule=new-object System.Security.AccessControl.FileSystemAccessRule($SysmonAccount,$FullControl,$InheritanceFlag, $PropagationFlag, $objType)

		$ACL = Get-Acl $DestinationFolderName
		$ACL.SetAccessRule($rule)

		Set-Acl -Path $DestinationFolderName -AclObject $ACL
	}
	else
	{
		"Error: Unable to find account name for SysmonLog. Folder permissions will not be set" | WriteTo-StdOut
	}
}

Function DumpBasicSysInfoToXML($OutputFileName)
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $Error[0]
		$Error.Clear()
		continue
	}
	$Error.Clear()
	
	#Collect Win32_OperatingSystem and Win32_ComputerSystem classes for use with Cave/Perfmon plug-in
	
	[xml] $OutputXML = "<WmiDataCollection><WmiData ClassName=`"Win32_ComputerSystem`"><Record MachineName=`"$Computername`"/></WmiData><WmiData ClassName=`"Win32_OperatingSystem`"><Record MachineName=`"$Computername`"/></WmiData></WmiDataCollection>"
	
	$CSWMI = Get-CimInstance Win32_ComputerSystem
	$CSNode = $OutputXML.WmiDataCollection.SelectSingleNode("WmiData[@ClassName='Win32_ComputerSystem']/Record[@MachineName='$Computername']")
	
	$CSNode = AddPropertiestoXMLNode -WMIObject $CSWMI -XMLNode $CSNode
	
	$OSWMI = Get-CimInstance Win32_OperatingSystem
	$OSNode = $OutputXML.WmiDataCollection.SelectSingleNode("WmiData[@ClassName='Win32_OperatingSystem']/Record[@MachineName='$Computername']")
	
	$OSNode = AddPropertiestoXMLNode -WMIObject $OSWMI -XMLNode $OSNode
	
	$OutputXML.Save($OutputFileName)
}

#********************************
#     Script Starts Here
#********************************

$DestinationFolderName = Join-Path $PWD.Path "Perfmon"
if ((Test-Path ($DestinationFolderName)) -ne $true) {[void]( mkdir $DestinationFolderName )} 

if ($OSVersion.Major -ge 6) #Vista+
{
	if ($null -eq $CollectPerfmonDataFrom) #We need to run a Data Collector Set
	{
		$DataCollectorName = "CTS Performance Troubleshooter"
		
		if (Test-Path (Join-Path $PWD.Path $DataCollectorSetXMLName))
		{
			$DataCollectorSetXMLName = (Join-Path $PWD.Path $DataCollectorSetXMLName)
		}
		
		if ([System.IO.File]::Exists($DataCollectorSetXMLName))
		{
			$DataCollectorSetXMLName = [System.IO.Path]::GetFullPath($DataCollectorSetXMLName)
			
			$DataCollectorSetPath = Run-DataCollectorSetFromXML -Name $DataCollectorName -DestinationFolder $DestinationFolderName -PathToXML ($DataCollectorSetXMLName) -NumberOfSecondsToRun $NumberOfSeconds -PerfMonCollectorStrings $PerfMonCollectorStrings
			if ($DataCollectorSetPath.Count -gt 0)
			{
				$DataCollectorSetPath = $DataCollectorSetPath[$DataCollectorSetPath.Count -1]
			}
			if($debug -eq $true){[void]$shell.popup("DCS Path: $DataCollectorSetPath")}
			
		} else {
			"ERROR: $DataCollectorSetXMLName was not found !!" | WriteTo-StdOut
		}
		
	} else {
		$DataCollectorSetPath = $CollectPerfmonDataFrom
		$DestinationFolderName = $CollectPerfmonDataFrom
	}

	if (-not $DoNotCollectPerfmonFiles.IsPresent) 
	{
		Add-SummaryToReport -PathToXML ([System.IO.Path]::Combine($DataCollectorSetPath, "Report.XML")) -AddHighCPUProcesses (-not $DoNotShowTOPProcesses.IsPresent) -ShowProcessesInReport $ShowProcessesInReport -ProcessesSectionTitle $ProcessesSectionTitle
		
		CollectFiles -filesToCollect "$DestinationFolderName\report.html" -renameOutput $true -fileDescription "Performance Monitor Report" -sectionDescription "System Performance Monitor"
		CollectFiles -filesToCollect "$DestinationFolderName\*.blg" -renameOutput $true -fileDescription "Performance Monitor Log" -sectionDescription "System Performance Monitor"

	} else {
		Add-SummaryToReport -PathToXML ([System.IO.Path]::Combine($DataCollectorSetPath, "Report.XML")) -AddHighCPUProcesses (-not $DoNotShowTOPProcesses.IsPresent) -DoNotAddURLForPerfmonFiles -ShowProcessesInReport $ShowProcessesInReport -ProcessesSectionTitle $ProcessesSectionTitle
	}

}
else
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $Error[0]
		$Error.Clear()
		continue
	}
	$Error.Clear()
	
	# Windows Server 2003/ Windows XP - run via Logman
	
	$PerfmonCounters = @"
\Cache\*
\Memory\*
\Network Interface(*)\*
\Objects\*
\Paging File(*)\*
\PhysicalDisk(*)\*
\Process(*)\*
\Processor(*)\*
\Redirector\*
\Server Work Queues(*)\*
\Server\*
\System\*
\LogicalDisk(*)\*
"@
	$PerfmonConfigPath = Join-Path $DestinationFolderName "PerfMonCounters.Config"
	$PerfmonCounters | Out-File $PerfmonConfigPath -Encoding "ASCII"
	
	$OutputFileName = Join-Path $DestinationFolderName ($ComputerName + "_Perfmon.blg")
	
	CleanACLOnPerfmonFolder $DestinationFolderName
	
	$CounterLogName = "SDPPerfmon_" + (Get-Random)
	
	"Starting logman and waiting for one minute..." | WriteTo-StdOut -ShortFormat

	$CommandToRun = "logman.exe create counter -n $CounterLogName -cf `"$PerfmonConfigPath`" -f bincirc -max 512 -si 3 -rf 00:01:00 -v mmddhhmm -o `"$OutputFileName`""
	RunCMD -commandToRun $CommandToRun -collectFiles $false
	
	Start-Sleep -Seconds 61
	
    "Stopping Perfmon Counter Log." | WriteTo-StdOut -ShortFormat
    Write-DiagProgress -Activity $PerfMonCollectorStrings.ID_PerfMonSystemPerf -Status $PerfMonCollectorStrings.ID_PerfMonSystemPerfObtaining
	
	$CommandToRun = "logman.exe stop $CounterLogName"
	RunCMD -commandToRun $CommandToRun -collectFiles $false

	Start-Sleep -Seconds 3
	
	$CommandToRun = "logman.exe delete -n $CounterLogName"
	RunCMD -commandToRun $CommandToRun -collectFiles $false
	
	CollectFiles -filesToCollect "$DestinationFolderName\*.blg" -fileDescription "Performance Monitor Log" -sectionDescription "Performance Monitor Logs"
}

$BasicMachineInfoXMLPath = Join-Path $PWD.Path "MachineInfo.xml"
DumpBasicSysInfoToXML $BasicMachineInfoXMLPath 
CollectFiles -filesToCollect $BasicMachineInfoXMLPath -renameOutput $true -fileDescription "Machine basic configuration XML" -sectionDescription "Additional Files" -Verbosity Debug


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBNl0J6k81hAWB2
# 3fWu1XKxfAGVurN4GtgdzNW1AbR7I6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHzVdzYO/ksqubGKIKbIXXF7
# hcKuLiHMGsizKXIK0UuqMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQA6C7WIWoFtjPldBlgARpsaRkAEI02cKNT5eBWvj6B/OYeolNvPAKso
# wVV0t9fgBJsH/ndqEDI9zQYyLGqDttpUcJXEhj2+lNA5sH0ATVaXg78o9x/0YFmc
# dBreWT0uLKJS29bZNXyLwUiKzDlly8cH5Cbmo4lPw3/dIaWcwQa56AjDYyhoy32/
# JJku5rkLDnR2t9gWKebtOZfUWCjLjGbkN5rLOnoAfd/GE7oVgCSrlaFiwEdwiqVp
# j1KbavGDyki+ruDEoXLyAHs5f6DoQAHrRuEIvgrAP41AQjKT89eQcQAMWGX0OfGk
# vaBo0pPjNk7DtqF7dkQYRHyjkBLnrKoPoYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIP5+HhPsLusxH731vH1QmIjRvTN8RbamBiQ7RDa5dmSdAgZi3mrX
# 5IQYEzIwMjIwODAxMDc0MjQ1LjQ1N1owBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046MDg0Mi00QkU2LUMyOUExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAYdCFmYEXPP0jQABAAABhzAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3MzlaFw0yMzAxMjYxOTI3MzlaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjA4NDIt
# NEJFNi1DMjlBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvml4GWM9A6PREQiHgZAA
# PK6n+Th6m+LYwKYLaQFlZXbTqrodhsni7HVIRkqBFuG8og1KZry02xEmmbdp89O4
# 0xCIQfW8FKW7oO/lYYtUAQW2kp0uMuYEJ1XkZ6eHjcMuqEJwC47UakZx3AekakP+
# GfGuDDO9kZGQRe8IpiiJ4Qkn6mbDhbRpgcUOdsDzmNz6kXG7gfIfgcs5kzuKIP6n
# N4tsjPhyF58VU0ZfI0PSC+n5OX0hsU8heWe3pUiDr5gqP16a6kIjFJHkgNPYgMiv
# GTQKcjNxNcXnnymT/JVuNs7Zvk1P5KWf8G1XG/MtZZ5/juqsg0QoUmQZjVh0XRku
# 7YpMpktW7XfFA3y+YJOG1pVzizB3PzJXUC8Ma8AUywtUuULWjYT5y7/EwwHWmn1R
# T0PhYp9kmpfS6HIYfEBboYUvULW2HnGNfx65f4Ukc7kgNSQbeAH6yjO5dg6MUwPf
# zo/rBdNaZfJxZ7RscTByTtlxblfUT46yPHCXACiX/BhaHEY4edFgp/cIb7XHFJbu
# 4mNDAPzRlAkIj1SGuO9G4sbkjM9XpNMWglj2dC9QLN/0geBFXoNI8F+HfHw4Jo+p
# 6iSP8hn43mkkWKSGOiT4hLJzocErFntK5i9PebXSq2BvMgzVc+BBvCN35DfD0mok
# RKxam2tQM060SORy3S7ucesCAwEAAaOCATYwggEyMB0GA1UdDgQWBBQiUcAWukEt
# YYF+3WFzmZA/DaWNIDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQC5q35T2RKjAFRN/3cYjnPFztPa7KeqJKJnKgvi
# Uj9IMfC8/FQ2ox6Uwyd40TS7zKvtuMl11FFlfWkEncN3lqihiSAqIDPOdVvr1oJY
# 4NFQBOHzLpetepHnMg0UL2UXHzvjKg24VOIzb0dtdP69+QIy7SDpcVh9KI0EXKG2
# bolpBypqRttGTDd0JQkOtMdiSpaDpOHwgCMNXE8xIu48hiuT075oIqnHJha378/D
# pugI0DZjYcZH1cG84J06ucq5ygrod9szr19ObCZJdJLpyvJWCy8PRDAkRjPJglSm
# fn2UR0KvnoyCOzjszAwNCp/JJnkRp20weItzm97iNg+FZF1J9E16eWIB1sCr7Vj9
# QD6Kt+z81rOcLRfxhlO2/sK09Uw+DiQkPbu6OZ3TsDvLsr8yG9W2A8yXcggNqd4X
# pLtdEkf52OIN0GgRLSY1LNDB4IKY+Zj34IwMbDbs2sCig5Li2ILWEMV/6gyL37J7
# 1NbW7Vzo7fcGrNne9OqxgFC2WX5degxyJ3Sx2bKw6lbf04KaXnTBOSz0QC+RfJuz
# 8nOpIf28+WmMPicX2l7gs/MrC5anmyK/nbeKkaOx+AXhwYLzETNg+1Icygjdwnbq
# WKafLdCNKfhsb/gM5SFbgD5ATEX1bAxwUFVxKvQv0dIRAm5aDjF3DZpgvy3mSojS
# rBN/8zCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
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
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MDg0Mi00QkU2LUMyOUExJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAHh3k1QEKAZEhsLGYGHtf/6DG4PzoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmkXrqMCIYDzIwMjIwODAx
# MDYwNDI2WhgPMjAyMjA4MDIwNjA0MjZaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaReuoCAQAwBwIBAAICHj8wBwIBAAICES4wCgIFAOaSzGoCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQCF/hfbIZQ0IEk6Kh2lseeEtTISZpszbfBnEeumjmWO
# 0hdqTDaefoW0+b7u5tEPoWvT2Y26R/5PThTeB8JmkwcqCENPZii9O+oZLx+a5Iou
# 6CKUmF9a1B/JSMc0nzpCTZddlgNPs96jeJuJfSrQ0BGHRHmxERqh1JwzqpL2X6pr
# 5TGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABh0IWZgRc8/SNAAEAAAGHMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIDgbkE+8i6JF/ntoi6Os
# a4RwhgmMK/VaSqtgXi8pAVIKMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# xCzwoBNuoB92wsC2SxZhz4HVGyvCZnwYNuczpGyam1gwgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYdCFmYEXPP0jQABAAABhzAiBCDA
# p3m7l8Nc7DlqiRsVc7ZPNSsKmHhdZilO6Ifx7KEsVTANBgkqhkiG9w0BAQsFAASC
# AgCM+Gg5JFmXGHY7NNpqzz7aq08i80V+58c9VzYP8nzmgfqwECafmq1qcofxEHSO
# HumUv/pXRM7Cgco15pufEepDljU8IO0VVT0qe+WOdj1qcIMH/WnrQjYLByUbNL6S
# uFyYk12nTomglDkXKUUwi/VelVTxEUTOm1Scx2FGO/ULTj4zAa1slE2oDHbzZrCf
# C7AO7alM7OQQGAXJLvFMaoqO62/QJbOtbp7mVCTh+aZEwJvU8s+R7f1jUyOVZxp1
# GComZwV9jOVgTfK+wJVmhAZv0QF/tvJqEW5YDbsOeTWZb3dO5Fqwg51mvcjS7tOs
# tb/hsCosSvrdKe0qkzSY32CDXQd4/hlGKfGhwxfL7vvcuxYk5E6tq+ol/ojGp/aI
# qi/iZ07gLO0vElSyOtyzsEfXmU8Dk+wJ8cyV+mexNyAIvQ44SeNhJz+aeH1sKPzv
# 8L6YkbqfcCUa4q55nfBHXgWlkzhOw/OLQF0syHPa2cRh9ThM4mUXW0t/FL95LCbh
# GmH9P1dAhJan17BbMJB/iM41+Ftfz+6Nf6gKZcCatO/gksqxvG6lRuUAPwQN69+L
# YHlUgHnTWdPE6noEHU2kfkxTCqJ+JAErxsIYuozPZhg7uKCHjeskOn/NKfePSZf2
# EYdUez4UVloOFpX9f1bm61QU883KGhakH18CCvcgxr0crA==
# SIG # End signature block
