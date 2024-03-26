#************************************************
# DC_UpdateHistory.ps1
# Version 1.0.1
# Date: 7/2/2013
# Author: v-maam, waltere 2019.07.15
# Description:  This file will list all updates installed on the local machine
#************************************************
#_#Param($Prefix = '', $Suffix = '', $OutputFormats= @("TXT", "CSV", "HTM"), [int]$NumberOfDays=10, [Switch]$ExportOnly)
Param($Prefix = '', $Suffix = '', $OutputFormats= @("TXT", "CSV"), [int]$NumberOfDays=10, [Switch]$ExportOnly) #_#

trap
{		
	WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[UpdateHistory.ps1] error"
	continue
}

Import-LocalizedData -BindingVariable ScriptStrings

# ***************************
# Store the updates history output information in CSV, TXT, XML format
# ***************************

$Script:SbCSVFormat = New-Object -TypeName System.Text.StringBuilder
$Script:SbTXTFormat = New-Object -TypeName System.Text.StringBuilder
$Script:SbXMLFormat = New-Object -TypeName System.Text.StringBuilder

# Store the WU errors
$Script:WUErrors

# Store the Updated installed in the past $NumberOfDays days when $ExportOnly is not used
if($ExportOnly.IsPresent -eq $false)
{
	$LatestUpdates_Summary= New-Object PSObject
	$LatestUpdates_Summary | Add-Member -MemberType NoteProperty -Name "  Date" -Value ("<table><tr><td width=`"40px`" style=`"border-bottom:1px solid #CCCCCC`">Results</td><td width=`"60px`" style=`"border-bottom:1px solid #CCCCCC`">ID</td><td width=`"300px`" style=`"border-bottom:1px solid #CCCCCC`">Category</td></tr></table>")
	[int]$Script:LatestUpdateCount = 0
}

# ***************************
# Functions
# ***************************

Function GetHotFixFromRegistry
{
	$RegistryHotFixList = @{}
	$UpdateRegistryKeys = @("HKLM:\SOFTWARE\Microsoft\Updates")

	#if $OSArchitecture -ne X86 , should be 64-bit machine. we also need to check HKLM:\SOFTWARE\Wow6432Node\Microsoft\Updates
	if($OSArchitecture -ne "X86")
	{
		$UpdateRegistryKeys += "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Updates"
	}
						  						 	
	foreach($RegistryKey in $UpdateRegistryKeys)
	{
		If(Test-Path $RegistryKey)
		{
			$AllProducts = Get-ChildItem $RegistryKey -Recurse | Where-Object {$_.Name.Contains("KB") -or $_.Name.Contains("Q")}

			foreach($subKey in $AllProducts)
			{
				if($subKey.Name.Contains("KB") -or $subKey.Name.Contains("Q"))
				{
					$HotFixID = GetHotFixID $subKey.Name
					if($RegistryHotFixList.Keys -notcontains $HotFixID)
					{
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

Function GetHotFixID($strContainID)
{
	return [System.Text.RegularExpressions.Regex]::Match($strContainID,"(KB|Q)\d+(v\d)?").Value
}

Function ToNumber($strHotFixID)
{
	return [System.Text.RegularExpressions.Regex]::Match($strHotFixID,"([0-9])+").Value
}

Function FormatStr([string]$strValue,[int]$NumberofChars)
{
	if([String]::IsNullOrEmpty($strValue))
	{
		$strValue = " "
		return $strValue.PadRight($NumberofChars," ")
	}
	else
	{
		if($strValue.Length -lt $NumberofChars)
		{
			return $strValue.PadRight($NumberofChars," ")
		}
		else
		{
			return $strValue.Substring(0,$NumberofChars)
		}
	}
}

# Make sure all dates are with dd/mm/yy hh:mm:ss
Function FormatDateTime($dtLocalDateTime,[Switch]$SortFormat)
{	
	trap
	{		
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[FormatDateTime] Error Convert date time"
		continue
	}

	if([string]::IsNullOrEmpty($dtLocalDateTime))
	{
		return ""
	}
	
	if($SortFormat.IsPresent)
	{
		# Obtain dates on yyyymmdddhhmmss
		return Get-Date -Date $dtLocalDateTime -Format "yyyyMMddHHmmss"
	}
	else
	{
		return Get-Date -Date $dtLocalDateTime -Format G
	}
}

Function ValidatingDateTime($dateTimeToValidate)
{
	trap
	{		
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[ValidateDateTime] Error"
		continue
	}

	if([String]::IsNullOrEmpty($dateTimeToValidate))
	{
		return $false
	}

	$ConvertedDateTime = Get-Date -Date $dateTimeToValidate

	if($null -ne $ConvertedDateTime)
	{
		if(((Get-Date) - $ConvertedDateTime).Days -le $NumberOfDays)
		{
			return $true
		}
	}

	return $false
}

Function GetUpdateResultString($OperationResult)
{
	switch ($OperationResult)
	{
		"Completed successfully"  {return "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group id=`"Inf1`" class=`"vmlimage`" style=`"width:15px;height:15px;vertical-align:middle`" coordsize=`"100,100`" title=`"Completed successfully`"><v:oval class=`"vmlimage`" style=`"width:100;height:100;z-index:0`" fillcolor=`"#009933`" strokecolor=`"#C0C0C0`" /></v:group></span>"}
		"In progress"  {return "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group class=`"vmlimage`" style=`"width:14px;height:14px;vertical-align:middle`" coordsize=`"100,100`" title=`"In progress`"><v:roundrect class=`"vmlimage`" arcsize=`"10`" style=`"width:100;height:100;z-index:0`" fillcolor=`"#00FF00`" strokecolor=`"#C0C0C0`" /><v:shape class=`"vmlimage`" style=`"width:100; height:100; z-index:0`" fillcolor=`"white`" strokecolor=`"white`"><v:path v=`"m 40,25 l 75,50 40,75 x e`" /></v:shape></v:group></span>"}
		"Operation was aborted"  {return "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group class=`"vmlimage`" style=`"width:15px;height:15px;vertical-align:middle`" coordsize=`"100,100`" title=`"Operation was aborted`"><v:roundrect class=`"vmlimage`" arcsize=`"20`" style=`"width:100;height:100;z-index:0`" fillcolor=`"#290000`" strokecolor=`"#C0C0C0`" /><v:line class=`"vmlimage`" style=`"z-index:2`" from=`"52,30`" to=`"52,75`" strokecolor=`"white`" strokeweight=`"8px`" /></v:group></span>"}
		"Completed with errors"  {return "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group class=`"vmlimage`" style=`"width:15px;height:15px;vertical-align:middle`" coordsize=`"100,100`" title=`"Completed with errors`"><v:shape class=`"vmlimage`" style=`"width:100; height:100; z-index:0`" fillcolor=`"yellow`" strokecolor=`"#C0C0C0`"><v:path v=`"m 50,0 l 0,99 99,99 x e`" /></v:shape><v:rect class=`"vmlimage`" style=`"top:35; left:45; width:10; height:35; z-index:1`" fillcolor=`"black`" strokecolor=`"black`"></v:rect><v:rect class=`"vmlimage`" style=`"top:85; left:45; width:10; height:5; z-index:1`" fillcolor=`"black`" strokecolor=`"black`"></v:rect></v:group></span>"}
		"Failed to complete"  {return "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group class=`"vmlimage`" style=`"width:15px;height:15px;vertical-align:middle`" coordsize=`"100,100`" title=`"Failed to complete`"><v:oval class=`"vmlimage`" style=`"width:100;height:100;z-index:0`" fillcolor=`"red`" strokecolor=`"#C0C0C0`"></v:oval><v:line class=`"vmlimage`" style=`"z-index:1`" from=`"25,25`" to=`"75,75`" strokecolor=`"white`" strokeweight=`"3px`"></v:line><v:line class=`"vmlimage`" style=`"z-index:2`" from=`"75,25`" to=`"25,75`" strokecolor=`"white`" strokeweight=`"3px`"></v:line></v:group></span>"}
		Default { return "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group id=`"Inf1`" class=`"vmlimage`" style=`"width:15px;height:15px;vertical-align:middle`" coordsize=`"100,100`" title=`"{$OperationResult}`"><v:oval class=`"vmlimage`" style=`"width:100;height:100;z-index:0`" fillcolor=`"#FF9933`" strokecolor=`"#C0C0C0`" /></v:group></span>" }
	}
}

Function GetOSSKU($SKU)
{
	switch ($SKU)
	{
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
	}	
}

Function GetOS()
{
	$WMIOS = Get-CimInstance -Class Win32_OperatingSystem

	$StringOS = $WMIOS.Caption

	if($null -ne $WMIOS.CSDVersion)
	{
		$StringOS += " - " + $WMIOS.CSDVersion
	}
	else
	{
		$StringOS += " - Service Pack not installed"
	}

	if(($null -ne $WMIOS.OperatingSystemSKU) -and ($WMIOS.OperatingSystemSKU.ToString().Length -gt 0))
	{
		$StringOS += " ("+(GetOSSKU $WMIOS.OperatingSystemSKU)+")"
	}

	return $StringOS
}

# Query SID of an object using WMI and return the account name
Function ConvertSIDToUser([string]$strSID) 
{
	trap
	{		
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[ConvertSIDToUser] Error convert User SID to User Account"
		continue
	}
	
	if([string]::IsNullOrEmpty($strSID))
	{
		return
	}

	if($strSID.StartsWith("S-1-5"))
	{
		$UserSIDIdentifier = New-Object System.Security.Principal.SecurityIdentifier `
    	($strSID)
		$UserNTAccount = $UserSIDIdentifier.Translate( [System.Security.Principal.NTAccount])
		if($UserNTAccount.Value.Length -gt 0)
		{
			return $UserNTAccount.Value
		}
		else
		{
			return $strSID
		}
	}
	
	return $strSID	
}

Function ConvertToHex([int]$number)
{
	return ("0x{0:x8}" -f $number)
}

Function GetUpdateOperation($Operation)
{
	switch ($Operation)
	{
		1 { return "Install" }
		2 { return "Uninstall" }
		Default { return "Unknown("+$Operation+")" }
	}
}

Function GetUpdateResult($ResultCode)
{
	switch ($ResultCode)
	{
		0 { return "Not started" }
		1 { return "In progress" }
		2 { return "Completed successfully" }
		3 { return "Completed with errors" }
		4 { return "Failed to complete" }
		5 { return "Operation was aborted" }
		Default { return "Unknown("+$ResultCode+")" }
	}					
}

Function GetWUErrorCodes($HResult)
{
	if($null -eq $Script:WUErrors)
	{
		$WUErrorsFilePath = Join-Path $PWD.Path "WUErrors.xml"
		if(Test-Path $WUErrorsFilePath)
		{
			[xml] $Script:WUErrors = Get-Content $WUErrorsFilePath
		}
		else
		{
			"[Error]: Did not find the WUErrors.xml file, can not load all WU errors" | WriteTo-StdOut -ShortFormat
		}
	}

	$WUErrorNode = $Script:WUErrors.ErrV1.err | Where-Object {$_.n -eq $HResult}

	if($null -ne $WUErrorNode)
	{
		$WUErrorCode = @()
		$WUErrorCode += $WUErrorNode.name
		$WUErrorCode += $WUErrorNode."#text"
		return $WUErrorCode
	}

	return $null
}

Function PrintHeaderOrXMLFooter([switch]$IsHeader,[switch]$IsXMLFooter)
{
	if($IsHeader.IsPresent)
	{
		if($OutputFormats -contains "TXT")
		{
			# TXT formate Header
			LineOut -IsTXTFormat -Value ([String]::Format("{0} {1} {2} {3} {4} {5} {6} {7} {8}",
												(FormatStr "Category" 20),
												(FormatStr "Level" 6),
												(FormatStr "ID" 10),
												(FormatStr "Operation" 11),
												(FormatStr "Date" 23),
												(FormatStr "Client" 18),
												(FormatStr "By" 28),
												(FormatStr "Result" 23),
												"Title"))																								
			LineOut -IsTXTFormat -Value ("-").PadRight(200,"-")
		}

		if($OutputFormats -contains "CSV")
		{
			# CSV formate Header										
			LineOut -IsCSVFormat -Value ("Category,Level,ID,Operation,Date,Client,By,Result,Title")
		}

		if($OutputFormats -contains "HTM")
		{
			# XML format Header
			LineOut -IsXMLFormat -IsXMLLine -Value "<?xml version=`"1.0`" encoding=`"UTF-8`"?>"
			LineOut -IsXMLFormat -IsOpenTag -TagName "Root"
			LineOut -IsXMLFormat -IsOpenTag -TagName "Updates"
			LineOut -IsXMLFormat -IsXMLLine -Value ("<Title name=`"QFE Information from`">"+$Env:COMPUTERNAME+"</Title>")
			LineOut -IsXMLFormat -IsXMLLine -Value ("<OSVersion name=`"Operating System`">"+(GetOS)+"</OSVersion>")
			LineOut -IsXMLFormat -IsXMLLine -Value ("<TimeField name=`"Local time`">"+[DateTime]::Now.ToString()+"</TimeField>")
		}
	}
	
	if($IsXMLFooter)
	{
		if($OutputFormats -contains "HTM")
		{
			LineOut -IsXMLFormat -IsCloseTag -TagName "Updates"
			LineOut -IsXMLFormat -IsCloseTag -TagName "Root"
		}		
	}
}

Function LineOut([string]$TagName,[string]$Value,[switch]$IsTXTFormat,[switch]$IsCSVFormat,[switch]$IsXMLFormat,[switch]$IsXMLLine,[switch]$IsOpenTag,[switch]$IsCloseTag)
{
	if($IsTXTFormat.IsPresent)
	{		
		[void]$Script:SbTXTFormat.AppendLine($Value)
	}
	
	if($IsCSVFormat.IsPresent)
	{
		[void]$Script:SbCSVFormat.AppendLine($Value)
	}
	
	if($IsXMLFormat.IsPresent)
	{
		if($IsXMLLine.IsPresent)
		{
			[void]$Script:SbXMLFormat.AppendLine($Value)
			return
		}
		
		if(($TagName -eq $null) -or ($TagName -eq ""))
		{
			"[Warning]: Did not provide valid TagName: $TagName, will not add this Tag." | WriteTo-StdOut -ShortFormat
			return
		}
		
		if($IsOpenTag.IsPresent -or $IsCloseTag.IsPresent)
		{
			if($IsOpenTag.IsPresent)
			{
				[void]$Script:SbXMLFormat.AppendLine("<"+$TagName+">")
			}
	
			if($IsCloseTag.IsPresent)
			{
				[void]$Script:SbXMLFormat.AppendLine("</"+$TagName+">")
			}
		}
		else
		{
			[void]$Script:SbXMLFormat.AppendLine("<"+$TagName+">"+$Value+"</"+$TagName+">")
		}
	}
}

Function PrintUpdate([string]$Category,[string]$SPLevel,[string]$ID,[string]$Operation,[string]$Date,[string]$ClientID,[string]$InstalledBy,[string]$OperationResult,[string]$Title,[string]$Description,[string]$HResult,[string]$UnmappedResultCode)
{
	if($OutputFormats -contains "TXT")
	{
		LineOut -IsTXTFormat -Value ([String]::Format("{0} {1} {2} {3} {4} {5} {6} {7} {8}",
												(FormatStr $Category 20),
												(FormatStr $SPLevel 6),
												(FormatStr $ID 10),
												(FormatStr $Operation 11),
												(FormatStr $Date 23),
												(FormatStr $ClientID 18),
												(FormatStr $InstalledBy 28),
												(FormatStr $OperationResult 23),
												$Title))
	}

	if($OutputFormats -contains "CSV")
	{
		LineOut -IsCSVFormat -Value ([String]::Format("{0},{1},{2},{3},{4},{5},{6},{7},{8}",
												  $Category,
												  $SPLevel,
												  $ID,
												  $Operation,
												  $Date,
												  $ClientID,
												  $InstalledBy,
												  $OperationResult,
												  $Title))
	}

	if($OutputFormats -contains "HTM")
	{	
		if($Category -eq "QFE hotfix")
		{
			$Category = "Other updates not listed in history"
		}
		
		if(-not [String]::IsNullOrEmpty($ID))
		{
			$NumberHotFixID = ToNumber $ID
			if($NumberHotFixID.Length -gt 5)
			{
				$SupportLink = "http://support.microsoft.com/kb/$NumberHotFixID"				
			}
		}
		else
		{
			$ID = ""
			$SupportLink = ""
		}	

		if([String]::IsNullOrEmpty($Date))
		{
			$DateTime = ""
		}
		else
		{
			$DateTime = FormatDateTime $Date -SortFormat			
		}

		if([String]::IsNullOrEmpty($Title))
		{
			$Title = ""
		}
		else
		{
			$Title = $Title.Trim()
		}

		if([String]::IsNullOrEmpty($Description))
		{
			$Description = ""
		}
		else
		{
			$Description = $Description.Trim()			
		}

		# Write the Update to XML Formate
		LineOut -IsXMLFormat -TagName "Update" -IsOpenTag
		LineOut -IsXMLFormat -TagName "Category" -Value $Category
		if(-not [String]::IsNullOrEmpty($SPLevel))
		{
			LineOut -IsXMLFormat -TagName "SPLevel" -Value $SPLevel
		}
		LineOut -IsXMLFormat -TagName "ID" -Value $ID
		LineOut -IsXMLFormat -TagName "SupportLink" -Value $SupportLink
		LineOut -IsXMLFormat -TagName "Operation" -Value $Operation
		LineOut -IsXMLFormat -TagName "Date" -Value $Date
		LineOut -IsXMLFormat -TagName "SortableDate" -Value $DateTime
		LineOut -IsXMLFormat -TagName "ClientID" -Value $ClientID
		LineOut -IsXMLFormat -TagName "InstalledBy" -Value $InstalledBy
		LineOut -IsXMLFormat -TagName "OperationResult" -Value $OperationResult
		LineOut -IsXMLFormat -TagName "Title" -Value $Title
		LineOut -IsXMLFormat -TagName "Description" -Value $Description

		if((-not [String]::IsNullOrEmpty($HResult)) -and ($HResult -ne 0))
		{
			$HResultHex = ConvertToHex $HResult
			$HResultArray= GetWUErrorCodes $HResultHex
					
			LineOut -IsXMLFormat -IsOpenTag -TagName "HResult"
			LineOut -IsXMLFormat -TagName "HEX" -Value $HResultHex
			if($null -ne $HResultArray)
			{
				LineOut -IsXMLFormat -TagName "Constant" -Value $HResultArray[0]
				LineOut -IsXMLFormat -TagName "Description" -Value $HResultArray[1]
			}
			LineOut -IsXMLFormat -IsCloseTag -TagName "HResult"
			LineOut -IsXMLFormat -TagName "UnmappedResultCode" -Value (ConvertToHex $UnmappedResultCode)
		}

		LineOut -IsXMLFormat -TagName "Update" -IsCloseTag


		if (($ExportOnly.IsPresent -eq $false) -and (ValidatingDateTime $Date))
		{	
			if($null -ne $LatestUpdates_Summary.$Date)	
			{	
				$LatestUpdates_Summary.$Date = $LatestUpdates_Summary.$Date.Insert($LatestUpdates_Summary.$Date.LastIndexOf("</table>"),"<tr><td width=`"40px`" align=`"center`">" +(GetUpdateResultString $OperationResult) + "</td><td width=`"60px`"><a href=`"$SupportLink`" Target=`"_blank`">$ID</a></td><td>$Category</td></tr>")
			}
			else
			{
				$LatestUpdates_Summary | Add-Member -MemberType NoteProperty -Name $Date -Value ("<table><tr><td width=`"40px`" align=`"center`">" +(GetUpdateResultString $OperationResult) + "</td><td width=`"60px`"><a href=`"$SupportLink`" Target=`"_blank`">$ID</a></td><td>$($Category): $($Title)</td></tr></table>")	
			}
					
			$Script:LatestUpdateCount++
		}	
	}
}

Function GenerateHTMFile([string] $XMLFileNameWithoutExtension)
{
	trap
	{		
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[GenerateHTMFile] Error creating HTM file"
		continue
	}

	$UpdateXslFilePath = Join-Path $pwd.path "UpdateHistory.xsl"
	if(Test-Path $UpdateXslFilePath)
	{
		$XSLObject = New-Object System.Xml.Xsl.XslTransform
		$XSLObject.Load($UpdateXslFilePath)
		if(Test-Path ($XMLFileNameWithoutExtension + ".XML"))
		{
			$XSLObject.Transform(($XMLFileNameWithoutExtension + ".XML"), ($XMLFileNameWithoutExtension + ".HTM"))
		}
		else
		{
			"Error: HTML file was not generated" | WriteTo-StdOut -ShortFormat
		}
	}
	else
	{
		"Error: Did not find the UpdateHistory.xsl, won't generate HTM file" | WriteTo-StdOut -ShortFormat
	}
}

# ***************************
# Start here
# ***************************

Write-DiagProgress -Activity $ScriptStrings.ID_InstalledUpdates -Status $ScriptStrings.ID_InstalledUpdatesObtaining

# Get updates from the com object
"Querying IUpdateSession Interface to get the Update History" | WriteTo-StdOut -ShortFormat

$Session = New-Object -ComObject Microsoft.Update.Session
$Searcher = $Session.CreateUpdateSearcher()
$HistoryCount = $Searcher.GetTotalHistoryCount()
if ($HistoryCount -gt 0) 
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "Querying Update History"
		continue
	}

	$ComUpdateHistory = $Searcher.QueryHistory(1,$HistoryCount)
}
else
{
	$ComUpdateHistory = @()
	"No updates found on Microsoft.Update.Session" | WriteTo-StdOut -ShortFormat
}

# Get updates from the Wmi object Win32_QuickFixEngineering
"Querying Win32_QuickFixEngineering to obtain updates that are not on update history" | WriteTo-StdOut -ShortFormat

$QFEHotFixList = New-Object "System.Collections.ArrayList"
$QFEHotFixList.AddRange(@(Get-CimInstance -Class Win32_QuickFixEngineering))

# Get updates from the regsitry keys
"Querying Updates listed in the registry" | WriteTo-StdOut -ShortFormat
$RegistryHotFixList = GetHotFixFromRegistry

Write-DiagProgress -Activity $ScriptStrings.ID_InstalledUpdates -Status $ScriptStrings.ID_InstalledUpdatesFormateOutPut
PrintHeaderOrXMLFooter -IsHeader

# Format each update history to the stringbuilder
"Generating information for $HistoryCount updates found on update history" | WriteTo-StdOut -ShortFormat
foreach($updateEntry in $ComUpdateHistory)
{	
	#Do not list the updates on which the $updateEntry.ServiceID = '117CAB2D-82B1-4B5A-A08C-4D62DBEE7782'. These are Windows Store updates and are bringing inconsistent results
	if($updateEntry.ServiceID -ne '117CAB2D-82B1-4B5A-A08C-4D62DBEE7782')
	{		
		$HotFixID = GetHotFixID $updateEntry.Title
		$HotFixIDNumber = ToNumber $HotFixID
		$strInstalledBy = ""
		$strSPLevel = ""
	
		if(($HotFixID -ne "") -or ($HotFixIDNumber -ne ""))
		{
			foreach($QFEHotFix in $QFEHotFixList)
			{
				if(($QFEHotFix.HotFixID -eq $HotFixID) -or
		   			((ToNumber $QFEHotFix.HotFixID) -eq $HotFixIDNumber))
				{
					$strInstalledBy = ConvertSIDToUser $QFEHotFix.InstalledBy
					$strSPLevel = $QFEHotFix.ServicePackInEffect

					#Remove the duplicate HotFix in the QFEHotFixList
					$QFEHotFixList.Remove($QFEHotFix)
					break
				}
			}
		}
	
		#Remove the duplicate HotFix in the RegistryHotFixList
		if($RegistryHotFixList.Keys -contains $HotFixID)
		{
			$RegistryHotFixList.Remove($HotFixID)
		}

		$strCategory = ""		
		if($updateEntry.Categories.Count -gt 0)
		{
			$strCategory = $updateEntry.Categories.Item(0).Name
		}
	
		if([String]::IsNullOrEmpty($strCategory))
		{
			$strCategory = "(None)"
		}
	
		$strOperation = GetUpdateOperation $updateEntry.Operation
		$strDateTime = FormatDateTime $updateEntry.Date
		$strResult = GetUpdateResult $updateEntry.ResultCode

		PrintUpdate $strCategory $strSPLevel $HotFixID $strOperation $strDateTime $updateEntry.ClientApplicationID $strInstalledBy $strResult $updateEntry.Title $updateEntry.Description $updateEntry.HResult $updateEntry.UnmappedResultCode
	}
}

# Out Put the Non History QFEFixes
"Generating information for " + $QFEHotFixList.Count + " updates found on Win32_QuickFixEngineering WMI class" | WriteTo-StdOut -ShortFormat
foreach($QFEHotFix in $QFEHotFixList)
{
	$strInstalledBy = ConvertSIDToUser $QFEHotFix.InstalledBy
	$strDateTime = FormatDateTime $QFEHotFix.InstalledOn
	$strCategory = ""

	#Remove the duplicate HotFix in the RegistryHotFixList
	if($RegistryHotFixList.Keys -contains $QFEHotFix.HotFixID)
	{
		$strCategory = $RegistryHotFixList[$QFEHotFix.HotFixID].Category
		$strRegistryDateTime = FormatDateTime $RegistryHotFixList[$QFEHotFix.HotFixID].InstalledDate		
		if([String]::IsNullOrEmpty($strInstalledBy))
		{
			$strInstalledBy = $RegistryHotFixList[$QFEHotFix.HotFixID].InstalledBy
		}

		$RegistryHotFixList.Remove($QFEHotFix.HotFixID)
	}
	
	if([string]::IsNullOrEmpty($strCategory))
	{
		$strCategory = "QFE hotfix"
	}	
	if($strDateTime.Length -eq 0)
	{
		$strDateTime = $strRegistryDateTime
	}
	if([string]::IsNullOrEmpty($QFEHotFix.Status))
	{
		$strResult = "Completed successfully"
	}
	else
	{
		$strResult = $QFEHotFix.Status
	}	

	PrintUpdate $strCategory $QFEHotFix.ServicePackInEffect $QFEHotFix.HotFixID "Install" $strDateTime "" $strInstalledBy $strResult $QFEHotFix.Description $QFEHotFix.Caption
}

"Generating information for " + $RegistryHotFixList.Count + " updates found on registry" | WriteTo-StdOut -ShortFormat
foreach($key in $RegistryHotFixList.Keys)
{
	$strCategory = $RegistryHotFixList[$key].Category
	$HotFixID = $RegistryHotFixList[$key].HotFixID
	$strDateTime = $RegistryHotFixList[$key].InstalledDate
	$strInstalledBy = $RegistryHotFixList[$key].InstalledBy
	$ClientID = $RegistryHotFixList[$key].InstallerName

	if($HotFixID.StartsWith("Q"))
	{
		$Description = $RegistryHotFixList[$key].Description
	}
	else
	{
		$Description = $RegistryHotFixList[$key].PackageName		
	}

	if([string]::IsNullOrEmpty($Description))
	{
		$Description = $strCategory
	}

	PrintUpdate $strCategory "" $HotFixID "Install" $strDateTime $ClientID $strInstalledBy "Completed successfully" $strCategory $Description
}

PrintHeaderOrXMLFooter -IsXMLFooter

Write-DiagProgress -Activity $ScriptStrings.ID_InstalledUpdates -Status $ScriptStrings.ID_InstalledUpdatesOutPutAndCollectFile
$FileNameWithoutExtension = $ComputerName +"_"+ $Prefix + "Hotfixes" + $Suffix

"Creating output files" | WriteTo-StdOut -ShortFormat
if($OutputFormats -contains "CSV")
{
	$Script:SbCSVFormat.ToString() | Out-File ($FileNameWithoutExtension + ".CSV") -Encoding "UTF8"
}

if($OutputFormats -contains "TXT")
{
	$Script:SbTXTFormat.ToString() | Out-File ($FileNameWithoutExtension + ".TXT") -Encoding "UTF8"
}

if($OutputFormats -contains "HTM")
{
	$Script:SbXMLFormat.ToString().replace("&","") | Out-File ($FileNameWithoutExtension + ".XML") -Encoding "UTF8"

	"Generate the HTML Updates file according the UpdateHistory.xsl and XML file" | WriteTo-StdOut -ShortFormat
	GenerateHTMFile $FileNameWithoutExtension
}

$FileToCollects = @("$FileNameWithoutExtension.CSV","$FileNameWithoutExtension.TXT","$FileNameWithoutExtension.HTM")

if($ExportOnly.IsPresent)
{
	Copy-Item $FileToCollects -Destination (Join-Path $PWD.Path "result")
}
else
{
	if($Script:LatestUpdateCount -gt 0)
	{		
		$LatestUpdates_Summary | Add-Member -MemberType NoteProperty -Name "More Information" -Value ("<table><tr><td>For a complete list of installed updates, please open <a href= `"`#" + $FileNameWithoutExtension + ".HTM`">" + $FileNameWithoutExtension + ".HTM</a></td></tr></table>")
		$LatestUpdates_Summary | ConvertTo-Xml2 -sortObject | update-diagreport -id 11_Updates -name "Updates installed in past $NumberOfDays days ($($Script:LatestUpdateCount))" -verbosity informational
	}
	
	CollectFiles -filesToCollect $FileToCollects -fileDescription "Installed Updates and Hotfixes" -sectionDescription "General Information"
}

# --------------------------------------------------------------- added: 2019-07-15 #_#
if ($Global:runFull -eq $True) { # $False = disabling for now for this long-lasting step
#----------WMIC list
	$sectionDescription = "UpdateHistory WMIC QFE"
	$OutputFile = Join-Path $pwd.path ($ComputerName + "_Hotfixes-WMIC.txt")
	Write-DiagProgress -Activity $ScriptStrings.ID_InstalledUpdates -Status "WMIC QFEs"
	$CommandToExecute = 'wmic qfe list full /format:texttable '
	RunCmD -commandToRun ("cmd.exe /c $CommandToExecute  >> `"$OutputFile`"") -collectFiles $false
	collectfiles -filesToCollect $OutputFile -fileDescription "wmic qfe list full" -sectionDescription $sectionDescription

#----------Get Windows Update Configuration info
	$sectionDescription = "Windows Update Configuration info"
	$OutputFile = Join-Path $pwd.path ($ComputerName + "_WindowsUpdateConfiguration.txt")
	Write-DiagProgress -Activity $ScriptStrings.ID_InstalledUpdates -Status "Windows Update Configuration info"
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Windows Update Configuration info" 					| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	$MUSM = New-Object -ComObject "Microsoft.Update.ServiceManager"
	$MUSM.Services | Select-Object Name, IsDefaultAUService, OffersWindowsUpdates | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	"Now get all data" 										| Out-File -FilePath $OutputFile -append
	"===================================================="	| Out-File -FilePath $OutputFile -append
	$MUSM = New-Object -ComObject "Microsoft.Update.ServiceManager" 
	$MUSM.Services | Out-File -FilePath $OutputFile -append
	collectfiles -filesToCollect $OutputFile -fileDescription "Windows Update Configuration" -sectionDescription $sectionDescription
}


# SIG # Begin signature block
# MIInoQYJKoZIhvcNAQcCoIInkjCCJ44CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDw98zBX7MGpHzl
# IpYatB5bxN44PdYmqCIzgc7Bs6+G0aCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGYEwghl9AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIExl5o84sUuBAiS4M/1bbVZs
# 6sB9Y6ffxJBKSEBedMbQMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAmGtl3pguAjP7kWGaxeTy7UJt6pgY57oEmOJDM0R+cp+e3c2filNV/
# 5bf4txJUNHeOuqGg7Rl9lvLyU9qT1WB4aegJLuqw+xph2WtnWS3/YLGTxj9T1y65
# s2jS3FOewbdjyYiZ9D/IVBt3EF2bkVU66FDBmWLo0qHZUZZAdV7pk1b8X7Gl+YNj
# LTtubmDmMK1fV7LxlZ7pRmyjw4LDdWZj0DgB6/ZP5zBC/fTgyt+oH5snfWu8jK+e
# 1o4zEsXUIJp+UAmJjpyAJD4rBZ0J02fnXmq8PeLCeK0/oF8UrGojgO7Q3UCSUvNp
# 9FOvOyuGwg5AxFzzrXTHUW9vuOZu2MMLoYIXCTCCFwUGCisGAQQBgjcDAwExghb1
# MIIW8QYJKoZIhvcNAQcCoIIW4jCCFt4CAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIH34vNAJ8ddsd4bMdaCdThO8eLMX9cLVqESMHZh+UjfLAgZi2xAP
# VUQYEzIwMjIwODAxMDc1MTI5LjAyM1owBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4
# OTdBLUUzNTYtMTcwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaCCEVwwggcQMIIE+KADAgECAhMzAAABqwkJ76tj1OipAAEAAAGrMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMDMw
# MjE4NTEyOFoXDTIzMDUxMTE4NTEyOFowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4OTdBLUUzNTYtMTcw
# MTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmdS1o5dehASUsscLqyx2wm/WirNUfq
# kGBymDItYzEnoKtkhrd7wNsJs4g+BuM3uBX81WnO270lkrC0e1mmDqQt420Tmb8l
# wsjQKM6mEaNQIfXDronrVN3aw1lx9bAf7VZEA3kHFql6YAO3kjQ6PftA4iVHX3JV
# v98ntjkbtqzKeJMaNWd8dBaAD3RCliMoajTDGbyYNKTvxBhWILyJ8WYdJ/NBDpqP
# zQl+pxm6ZZVSeBQAIOubZjU0vfpECxHC5vI1ErrqapG+0oBhhON+gllVklPAWZv2
# iv0mgjCTj7YNKX7yL2x2TvrvHVq5GPNa5fNbpy39t5cviiYqMf1RZVZccdr+2vAp
# k5ib5a4O8SiAgPSUwYGoOwbZG1onHij0ATPLkgKUfgaPzFfd5JZSbRl2Xg347/Lj
# WQLR+KjAyACFb06bqWzvHtQJTND8Y0j5Y2SBnSCqV2zNHSVts4+aUfkUhsKS+GAX
# S3j5XUgYA7SMNog76Nnss5l01nEX7sHDdYykYhzuQKFrT70XVTZeX25tSBfy3Vac
# zYd1JSI/9wOGqbFU52NyrlsA1qimxOhsuds7Pxo+jO3RjV/kC+AEOoVaXDdminsc
# 3PtlBCVh/sgYno9AUymblSRmee1gwlnlZJ0uiHKI9q2HFgZWM10yPG5gVt0prXnJ
# Fi1Wxmmg+BH/AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUFFvO8o1eNcSCIQZMvqGf
# dNL+pqowHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgw
# VjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWlj
# cm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUF
# BwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
# KS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQsFAAOCAgEAykuUgTc1KMszMgsHbhgjgEGv/dCHFf0by99C45SR770/udCN
# NeqlT610Ehz13xGFU6Hci+TLUPUnhvUnSuz7xkiWRru5RjZZmSonEVv8npa3z1Qv
# eUfngtyi0Jd6qlSykoEVJ6tDuR1Kw9xU9yvthZWhQs/ymyOwh+mxt0C9wbeLJ92e
# r2vc9ly12pFxbCNDJ+mQ7v520hAvreWqZ02GOJhw0R4c1iP39iNBzHOoz+DsO0sY
# jwhaz9HrvYMEzOD1MJdLPWfUFsZ//iTd3jzEykk02WjnZNzIe2ENfmQ/KblGXHeS
# e8JYqimTFxl5keMfLUELjAh0mhQ1vLCJZ20BwC4O57Eg7yO/YuBno+4RrV0CD2gp
# 4BO10KFW2SQ/MhvRWK7HbgS6Bzt70rkIeSUto7pRkHMqrnhubITcXddky6GtZsmw
# M3hvqXuStMeU1W5NN3HA8ypjPLd/bomfGx96Huw8OrftcQvk7thdNu4JhAyKUXUP
# 7dKMCJfrOdplg0j1tE0aiE+pDTSQVmPzGezCL42slyPJVXpu4xxE0hpACr2ua0LH
# v/LB6RV5C4CO4Ms/pfal//F3O+hJZe5ixevzKNkXXbxPOa1R+SIrW/rHZM6RIDLT
# JxTGFDM1hQDyafGu9S/a7umkvilgBHNxZfk0IYE7RRWJcG7oiY+FGdx1cs0wggdx
# MIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGI
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylN
# aWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5
# MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciEL
# eaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa
# 4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxR
# MTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEByd
# Uv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi9
# 47SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJi
# ss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+
# /NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY
# 7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtco
# dgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH
# 29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94
# q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcV
# AQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0G
# A1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQB
# gjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# GQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB
# /wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0f
# BE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJv
# ZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4w
# TDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIB
# AJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRs
# fNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6
# Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveV
# tihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKB
# GUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoy
# GtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQE
# cb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFU
# a2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+
# k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0
# +CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cir
# Ooo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICzzCCAjgCAQEwgfyh
# gdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAn
# BgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjo4OTdBLUUzNTYtMTcwMTElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAW6h6/24WCo7W
# Zz6CEVAeLztcmD6ggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQUFAAIFAOaRa9gwIhgPMjAyMjA4MDEwMTAwMDhaGA8yMDIy
# MDgwMjAxMDAwOFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5pFr2AIBADAHAgEA
# AgIG1DAHAgEAAgIRNzAKAgUA5pK9WAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUA
# A4GBAAEU+pL+fVXcuqgydyRS2xu0KXbaAiTD3MltCnjkn3ekNvFgcP+4OrTJe4DA
# punTRCb4bvJrYifK/egPCUPI67+Obaj9M50cuVtH9NzEUFs8QheQObEU6tG04X/B
# v0cqzEG3yZKdp0O0h1k6MMtIrIccKN3JPMbdFmEHAeb7w1TAMYIEDTCCBAkCAQEw
# gZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGrCQnvq2PU6KkA
# AQAAAaswDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0B
# CRABBDAvBgkqhkiG9w0BCQQxIgQgCYblweygrJvLc4a2LtTZBsT3jPg67Alv+1Hh
# 3mr3Z/IwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAOHK/6sIVgEVSVD3Ar
# vk6OyQKvRxFHKyraUzbN1/AKVzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABqwkJ76tj1OipAAEAAAGrMCIEIHI+RQKHTZ2Id7/ufvKq
# /DQk+dqQy1YkmvsPNzOkpL0iMA0GCSqGSIb3DQEBCwUABIICADviHB3ttlUQQGW+
# LFEbfSGjRzBMwZVX417i4e5eKgL78oyxBt9lpzH5DnxVBZvIxXPgMEGGsWUkC405
# zVctWhNP+QQ5EfZ5w9DYfHGOOSeUUpgwM+Ho8UFpTz4V+YPwvcQRiKhWl//i5GE8
# hjpPfVO++VVP0IxZZ7Msw/qKTb3vDFykelo7031RlTCXBUJBSWvW2MrvyHmjFnl9
# Daxx2MclNlh54Xru5dOwpQYRvNtTl4z4hQQDANYFURM1RknAx5WMRyEOyl/fodop
# 0jxdGjPwmq+qxi/d6QTzjsuDoSbmXDzK71So9bzbhqgWgFiHWwrtIXg7+orPSzwu
# XTFVpNkp7ofJ7LVqsTGrzLzx3yyXriXbbPYXccdzritVTKJRcj5PiT7Sfwn/82xG
# 7DjJgnR1qP51oa/J2hMMWtzMihektLIrvd2VqRy5WrhR/EtHRBSPSjb5m8/2rI1O
# l7e7n5gougjFmvaFmER51/lNo5zN7VB8j7DK4rncKw6yydxkzbhSol5iRIw8HTSt
# gXseDeAvDXzJo9WlqEVGi5koFJ7yZHX4YSRZ3wAoo61WPJ1zafsfG0bqnSPPAcdB
# FwfE0mXwiTjc9Oh1T05eiOQKS36MSaxGLSaxV9aVFpRw7UJ+KJszhTpKieSTKaAD
# HiR3qYO7ZQf06WFbN3Ko61/EK6mf
# SIG # End signature block
