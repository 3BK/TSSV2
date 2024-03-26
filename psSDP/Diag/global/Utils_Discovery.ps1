PARAM ($WorkingPath = $PWD.Path, $SchemaXMLPath = 'ConfigXPLSchema.xml')

## Initializing Variables

$ComputerName = $Env:COMPUTERNAME
[xml] $SchemaXML = $null

$DiscoveryReportXMLPath = Join-Path $WorkingPath ($ComputerName + '_DiscoveryReport.xml')

$StatusXMLPath =  Join-Path $WorkingPath ($ComputerName + '_DiscoveryStatus.xml')

$DebugLogXMLPath =  Join-Path $WorkingPath ($ComputerName + '_DiscoveryDebugLog.xml')
[XML] $DebugLogXML = "<root/>"

$CXPExecutionLog = Join-Path $WorkingPath ($ComputerName + '_DiscoveryExecutionLog.log')

$DiscoveryExecution_Summary = New-Object PSObject

$DiscoveryScriptContents = ''

$script:GlobalDataTypes = $null
$script:GlobalGenericDataTypes = $null


#####################
# General Functions #
#####################

#Log Exceptions to Debug Report XML
Filter Log-CXPWriteLine{
	param (
		$InputObject,
		[switch]$IsError,
		[switch]$IsWarning,
		[switch]$Debug,
		[System.Management.Automation.InvocationInfo] $InvokeInfo = $MyInvocation
		)
	BEGIN
	{
		$WhatToWrite = @()
		if ($null -ne $InputObject){
			$WhatToWrite  += $InputObject
		} 
		
		if((($Debug) -and ($Host.Name -ne "Default Host") -and ($Host.Name -ne "Default MSH Host")) -or ($Host.Name -eq 'PowerGUIScriptEditorHost') -or ($Host.Name -like '*PowerShell*')){
			if($null -eq $Color){
				$Color = [ConsoleColor]::Gray
			}
			elseif($Color -isnot [ConsoleColor]){
				$Color = [Enum]::Parse([ConsoleColor],$Color)
			}
			if ($IsWarning.IsPresent){
				$BackGroundColor = [ConsoleColor]::DarkYellow
			}
			$scriptName = [System.IO.Path]::GetFileName($InvokeInfo.ScriptName)
		}
	}
	
	PROCESS
	{
		if ($_ -ne $null){
			if ($_.GetType().Name -ne "FormatEndData"){
				$WhatToWrite += $_ | Out-String 
			}
			else{
				$WhatToWrite = "(Object not correctly formatted. The object of type Microsoft.PowerShell.Commands.Internal.Format.FormatEntryData is not valid or not in the correct sequence)"
			}
		}
	}
	END
	{
		$separator = "`r`n"
		$WhatToWrite = [string]::Join($separator,$WhatToWrite)
		
		while($WhatToWrite.EndsWith("`r`n")){
			$WhatToWrite = $WhatToWrite.Substring(0,$WhatToWrite.Length-2)
		}
		
		if ($Warning.IsPresent){
			$WhatToWrite = "[Warning] $WhatToWrite"
		}
		
		if((($Host.Name -ne "Default Host") -and ($Host.Name -ne "Default MSH Host")) -or ($Host.Name -eq 'PowerGUIScriptEditorHost')){
			$output = "[$([DateTime]::Now.ToString(`"s`"))] [$($scriptName):$($MyInvocation.ScriptLineNumber)]: $WhatToWrite"
			if($IsError.Ispresent){
				$Host.UI.WriteErrorLine($output)
			}
			else{
			
				If (($null -ne $BackgroundColor) -and ($null -ne $Color)){
					$output | Write-Host -ForegroundColor $Color -BackgroundColor $BackgroundColor
				}
				elseif ($null -ne $Color){
					$output | Write-Host -ForegroundColor $Color
				}
				else{
					$output | Write-Host 
				}
			}
		}
		else{
             "[ConfigXPL] [" + (Get-Date -Format "T") + " " + $ComputerName + " - " + [System.IO.Path]::GetFileName($InvokeInfo.ScriptName) + " - " + $InvokeInfo.ScriptLineNumber.ToString().PadLeft(4) + "] $WhatToWrite" | Out-File -FilePath $CXPExecutionLog -append -ErrorAction SilentlyContinue 
		}
	}
}


Filter Log-CXPWriteXML
(
	[XML] $XML,
	[string] $Id,
	[string] $Name,
	[string] $Verbosity = "Debug"
)
{
	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText "[Log-CXPWriteXML]" -InvokeInfo $MyInvocation
		$Error.Clear()
		return
	}


	if ($null -eq $XML){$XML = $_}
	if ($null -eq $XML){
		throw ('XML argument is empty or null')
	}
	
	if (([string]::IsNullOrEmpty($Id)) -or ([string]::IsNullOrEmpty($Name))){
		throw ('Either $Id or $Name are empty. XML entry will not be logged to report: ' + $XML.get_OuterXml())
	}
	
	[System.Xml.XmlElement] $XMLElement = $DebugLogXML.CreateElement("Detail")
	
	$XMLElement.SetAttribute("id", $Id)
	$XMLElement.SetAttribute("name", $Name)
	$XMLElement.SetAttribute("verbosity", $Verbosity)
	
	$XMLElement.set_InnerXml($XML.get_DocumentElement().get_OuterXml())
	
	$x = $DebugLogXML.DocumentElement.AppendChild($XMLElement)
	$DebugLogXML.Save($DebugLogXMLPath)
}

#Log Exceptions to Debug Report XML
Filter Log-CXPException
(
	[string] $ScriptErrorText, 
	[System.Management.Automation.ErrorRecord] $ErrorRecord = $null,
	[System.Management.Automation.InvocationInfo] $InvokeInfo = $null
)
{
	trap [Exception] 
	{
		$ExInvokeInfo = $_.Exception.ErrorRecord.InvocationInfo
		if ($null -ne $ExInvokeInfo){
			$line = ($_.Exception.ErrorRecord.InvocationInfo.Line).Trim()
		}
		else{
			$Line = ($_.InvocationInfo.Line).Trim()
		}
		
		"[Log-CXPException] Error: " + $_.Exception.Message + " [" + $Line + "].`r`n" + $_.StackTrace | Log-CXPWriteLine
		continue
	}

	if (($ScriptErrorText.Length -eq 0) -and ($ErrorRecord -eq $null)) {$ScriptErrorText=$_}

	if (($ErrorRecord -ne $null) -and ($InvokeInfo -eq $null)){
		if ($null -ne $ErrorRecord.InvocationInfo){
			$InvokeInfo = $ErrorRecord.InvocationInfo
		}
		elseif ($null -ne $ErrorRecord.Exception.ErrorRecord.InvocationInfo){
			$InvokeInfo = $ErrorRecord.Exception.ErrorRecord.InvocationInfo
		}
		if ($null -eq $InvokeInfo){			
			$InvokeInfo = $MyInvocation
		}
	}
	elseif ($InvokeInfo -eq $null){
		$InvokeInfo = $MyInvocation
	}

	$Error_Summary = New-Object PSObject
	
	if (($null -ne $InvokeInfo.ScriptName) -and ($InvokeInfo.ScriptName.Length -gt 0)){
		$ScriptName = [System.IO.Path]::GetFileName($InvokeInfo.ScriptName)
	}
	elseif (($null -ne $InvokeInfo.InvocationName) -and ($InvokeInfo.InvocationName.Length -gt 1)){
		$ScriptName = $InvokeInfo.InvocationName
	}
	elseif ($null -ne $MyInvocation.ScriptName){
		$ScriptName = [System.IO.Path]::GetFileName($MyInvocation.ScriptName)
	}
	
	$Error_Summary_TXT = @()
	if (-not ([string]::IsNullOrEmpty($ScriptName))){
		$Error_Summary | Add-Member -MemberType NoteProperty -Name "Script" -Value $ScriptName 
	}
	
	if ($null -ne $InvokeInfo.Line){
		$Error_Summary | Add-Member -MemberType NoteProperty -Name "Command" -Value ($InvokeInfo.Line).Trim()
		$Error_Summary_TXT += "Command: [" + ($InvokeInfo.Line).Trim() + "]"
	}
	elseif ($null -ne $InvokeInfo.MyCommand){
		$Error_Summary | Add-Member -MemberType NoteProperty -Name "Command" -Value $InvokeInfo.MyCommand.Name
		$Error_Summary_TXT += "Command: [" + $InvokeInfo.MyCommand.Name + "]"
	}
	
	if ($null -ne $InvokeInfo.ScriptLineNumber){
		$Error_Summary | Add-Member -MemberType NoteProperty -Name "Line Number" -Value $InvokeInfo.ScriptLineNumber
	}
	
	if ($null -ne $InvokeInfo.OffsetInLine){
		$Error_Summary | Add-Member -MemberType NoteProperty -Name "Column  Number" -Value $InvokeInfo.OffsetInLine
	}

	if (-not ([string]::IsNullOrEmpty($ScriptErrorText))){
		$Error_Summary | Add-Member -MemberType NoteProperty -Name "Additional Info" -Value $ScriptErrorText
	}
	
	if ($null -ne $ErrorRecord.Exception.Message){
		$Error_Summary | Add-Member -MemberType NoteProperty -Name "Error Text" -Value $ErrorRecord.Exception.Message
		$Error_Summary_TXT += "Error Text: " + $ErrorRecord.Exception.Message
	}
	if($null -ne $ErrorRecord.ScriptStackTrace){
		$Error_Summary | Add-Member -MemberType NoteProperty -Name "Stack Trace" -Value $ErrorRecord.ScriptStackTrace
	}
	
	$Error_Summary | Add-Member -MemberType NoteProperty -Name "Custom Error" -Value "Yes"

	if ($ScriptName.Length -gt 0){
		$ScriptDisplay = "[$ScriptName]"
	}
	
	$Error_Summary | ConvertTo-Xml | Log-CXPWriteXML -id ("ScriptError_" + (Get-Random)) -name "Script Error $ScriptDisplay" -verbosity "Debug"
	"[Log-CXPException] An error was logged to Debug Report: " + [string]::Join(" / ", $Error_Summary_TXT) | Log-CXPWriteLine -InvokeInfo $InvokeInfo -IsError
	$Error_Summary | Format-List * | Out-String | Log-CXPWriteLine -Debug -IsError -InvokeInfo $InvokeInfo
}

#Write Execution Status to Status XML
Filter Set-CXPExecutionStatus
{
	param ($InputObject,
	[switch] $IsWarning,
	[switch] $IsError)
	
	if ($null -eq $InputObject) { $InputObject=$_ }
	if ($IsWarning.IsPresent){
		$StatusType = "Warning"
	}
	elseif ($IsError.IsPresent){
		$StatusType = "Error"
	}
	else{
		$StatusType = "Informational"
	}
	
	[XML] $StatusXML = 	"<root>" + 
						"<StatusMessage>$InputObject</StatusMessage>" + 
						"<StatusType>$StatusType</StatusType>" + 
						"<Time>" + (Get-Date).ToFileTime() +  "</Time>"+
						"</root>"
	
	"Status: [$StatusType] $InputObject" | Log-CXPWriteLine -InvokeInfo $MyInvocation
	
	$StatusXML.Save($StatusXMLPath)
}

Function OpenSchemaXML($SchemaXMLPath){
	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText "[OpenSchemaXML] Path = $SchemaXMLPath"
		return $false
	}
	
	if (Test-Path $SchemaXMLPath){
		[xml] $script:SchemaXML = Get-Content $SchemaXMLPath
		$script:GlobalDataTypes = $script:SchemaXML.SelectSingleNode('/Schema/SystemObjects/DataTypes')
		$script:GlobalGenericDataTypes = $script:SchemaXML.SelectSingleNode('/Schema/SystemObjects/GenericDataTypes')
		return $true
	}
	else{
		"File Not Found: $SchemaXMLPath" | Log-CXPWriteLine -IsError
		return $false
	}
}

Function Get-RootDiscoverySet{
	return $SchemaXML.Schema.Root.Trim()
}

Function Get-DiscoverySetLinks([string] $DiscoverSetGuid){
	return ($SchemaXML.SelectNodes("/Schema/DiscoverySet[@Guid='$DiscoverSetGuid']/Entities/Entity[@Type='Section']/DiscoverySetLink") | ForEach-Object {$_.Guid})
}

Function Check-FunctionExist ($FunctionName, [ref] $ScriptContents){
	if ($ScriptContents.Value -match "Function $FunctionName"){
		return $true
	}
	else{
		"[Check-FunctionExist] Discovery function $FunctionName could not be found" | Log-CXPWriteLine -IsError
		$ScriptFunction = $null
	}
}

Function Get-ChildEntityNodes ([string] $GUID, [ref] $DiscoverySetNode){
	$ChildEntities = @()
	Foreach ($EntityNode in ($DiscoverySetNode.Value).SelectNodes("Entities/Entity[(@Parent = `'$GUID`')]")){
		#If Entity is a Section, look at the child of the section instead
		if ($EntityNode.Type -eq 'Section'){
			$ChildEntities += Get-ChildEntityNodes -GUID $EntityNode.Guid -DiscoverySetNode ($DiscoverySetNode)
		}
		else{
			$ChildEntities += $EntityNode
		}
	}
	return $ChildEntities
}

Function Get-EntityNode ([ref] $DiscoverySetNode, [string] $EntityGuid){
	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText "[Get-EntityNode]"
		return $null
	}
	
	$DiscoverySetNodeValue = $DiscoverySetNode.Value
	if ($DiscoverySetNodeValue -is [System.Xml.XmlLinkedNode]){
		return $DiscoverySetNodeValue.SelectSingleNode("Entities/Entity[@Guid = '$EntityGuid']")
	}
	else{
		"Unknown type of DiscoverySetNode: " + $DiscoverySetNode.GetType().Name | Log-CXPWriteLine -IsError
		return $null
	}
}

Function Get-GenericTypeNode([string] $GenericTypeName){
	 $SchemaXML.SelectSingleNode("Schema/SystemObjects/GenericDataTypes/GenericDataType[@Name = '$GenericTypeName']")
}

Function Validate-GenericTypeArguments ([string] $GenericType, $EntityGenericTypeInputArguments, $EntityNode){
	$GenericTypeNode = Get-GenericTypeNode -GenericTypeName $GenericType
	if ($null -ne $GenericTypeNode){
		#If GenericClass has a functionName, then always return $true as the arguments will be built at run time
		if ($null -eq $EntityNode.FunctionName){
			ForEach ($RequiredArgument in $GenericTypeNode.GenericDataTypeInputArguments.Argument |  Where-Object {$_.Required -eq "true"})
			{
				if (($EntityGenericTypeInputArguments.GenericTypeInputArgumentValue | ForEach-Object {$_.Name}) -notcontains $RequiredArgument.Name){
					"There is a Required Argument for $GenericType that is missing: " + $RequiredArgument.Name | Log-CXPWriteLine -IsError
					return $false
				}
			}
		}
		return $true
	}
	else{
		"Unable to find GenericType $GenericType" | Log-CXPWriteLine -IsError
		return $false
	}
}

Function Get-GenericTypeFunctionName ([string] $GenericType){
	$GenericTypeNode = Get-GenericTypeNode -GenericTypeName $GenericType
	if ($null -ne $GenericTypeNode){
		return $GenericTypeNode.FunctionName
	}
	else{
		"Unable to find GenericType $GenericType" | Log-CXPWriteLine -IsError
		return $null
	}
}

Function Convert-PSObjectToHashTable([PSObject] $PSObject){
	$HT = @{}
	foreach($p in $ExecutionResults.PSObject.Members | Where-Object {$_.MemberType -eq "NoteProperty"}) 
	{
		$HT += {$p.Name = $p.Value}
	}
	return $HT 
}

Function Run-GenericClassGetArguments($EntityName, $FunctionName, [Hashtable] $ArgumentList = @{}){
	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText "[Run-GenericClassGetArguments] Expression: $($MyInvocation.Line)"
		continue
	}
	$Error.Clear()
	if (-not [string]::IsNullOrEmpty($FunctionName)){
		"[Run-GenericClassGetArguments]: Obtaining GenericClass arguments for [$EntityName] via GetArguments function $FunctionName" | Log-CXPWriteLine
		$ScriptTimeStarted = Get-Date
		$ExecutionResults = Invoke-Expression $FunctionName
		$TimeToRun = (New-TimeSpan $ScriptTimeStarted)
		"[Run-GenericClassGetArguments]: Finished GetArguments for [$EntityName]" | Log-CXPWriteLine
		if ($TimeToRun.Seconds -gt 3){
			"$FunctionName took " + $TimeToRun.Seconds + " seconds to complete" | Log-CXPWriteLine -IsWarning
		}
		
		if ($ExecutionResults -is [HashTable]){
			$ReturnObject = $ExecutionResults
		}
		elseif ($ExecutionResults -is [PSObject]){
			$ReturnObject = (Convert-PSObjectToHashTable $ExecutionResults)
		}
		elseif (($null -ne $ExecutionResults) -and ([string]::IsNullOrEmpty($ExecutionResults) -eq $false)){
			"$FunctionName returned a " + $ExecutionResults.GetType().FullName + " and the expected is a HashTable or PSObject. Return value will be ignored " | Log-CXPWriteLine -IsError
			return $ArgumentList
		}
		else{
			return $ArgumentList
		}
		
		$ArgumentList.GetEnumerator() | ForEach-Object -Process {
			$Key = $_.Key
			if ($ReturnObject.ContainsKey($Key)){
				"[Run-GenericClassGetArguments] Argument $($Key) containing [$($_.Value)] is being overwritten to " + $ReturnObject.get_Item($Key) + " by GetArguments Function" | Log-CXPWriteLine
			}
			else{
				$ReturnObject += $_
			}
		}
		return $ReturnObject
	}
	else{
		"[Run-GenericClassGetArguments] [" + [System.IO.Path]::GetFileName($MyInvocation.ScriptName) + " - " + $MyInvocation.ScriptLineNumber.ToString() + '] - Error: a null expression was sent to Run-GenericClassGetArguments' | Log-CXPWriteLine -IsError
	}
}

Function Get-DiscoveryCommandLine($EntityType, $EntityName, $EntityFunctionName, $EntityGuid, [ref] $DiscoverySetNode, [ref] $DiscoveryScriptContents){
	$CommandLine = @()
	$InputArgumentsLine = @()
	$ResultsVariableName = $EntityName.replace(".", "").replace(" ","") + "Results"
	$EntityNode = Get-EntityNode -DiscoverySetNode $DiscoverySetNode -EntityGuid $EntityGuid
	$ArgumentCommandLine = ''

	if ($EntityType -eq 'GenericClass'){
		if ($null -ne $EntityNode){
			$GenericType = $EntityNode.GenericType
			$GenericTypeInputArgumentsValues = $EntityNode.GenericTypeInputArgumentValues
			$GenericClassFunctionName = $EntityNode.FunctionName
		
			If (Validate-GenericTypeArguments -GenericType $GenericType -EntityGenericTypeInputArguments $GenericTypeInputArgumentsValues -EntityNode $EntityNode){
				$GenericTypeFunctionName = Get-GenericTypeFunctionName -GenericType $GenericType
				$GetArgumentsFunctionName = ('$' + $GenericTypeFunctionName + 'ArgumentList').Replace('-','')
				$CommandLine += $GetArgumentsFunctionName + ' = @{}'
				
				foreach ($Argument in $GenericTypeInputArgumentsValues.GenericTypeInputArgumentValue)
				{
					$CommandLine += $GetArgumentsFunctionName + ' += @{"' + $Argument.Name + "`" = `'" + $Argument.Value + "`'}"
				}
				if ($null -ne $GenericClassFunctionName){
					$CommandLine += $GetArgumentsFunctionName + ' = Run-GenericClassGetArguments -EntityName "' + $EntityNode.Name + '" -FunctionName "' + $GenericClassFunctionName + '" -ArgumentList ' + $GetArgumentsFunctionName
				}
				$ArgumentCommandLine += " -Entity `'" + $EntityGuid + "`' -DiscoverySet `'" + $DiscoverySetNode.Value.Guid + "`' -ArgumentList " + $GetArgumentsFunctionName
			}
			else{
				return
			}
		}
		else{
			"Unable to find GenericyClass: $EntityName [$EntityGuid]" | Log-CXPWriteLine -IsError
			return
		}
	}

	$CommandLine += ('$' + "$ResultsVariableName = Run-DiscoveryFunction $EntityFunctionName" + $ArgumentCommandLine)
	
	if ($null -ne $ParentResultsID){
		$ParentCmdLine = ' -ParentID ' + $ParentResultsID
	}
	else{
		$ParentCmdLine = ''
	}
	
	$CommandLine += "Write-DiscoveryInfo -InputObject $" + $ResultsVariableName + " -DiscoverySet '" + $DiscoverySetNode.Value.Guid + "' -Entity '" + $EntityGuid + "'" + $ParentCmdLine
	
	[array] $ChildEntitites = Get-ChildEntityNodes -GUID $EntityGuid -DiscoverySetNode $DiscoverySetNode
	if ($ChildEntitites.Count -gt 0){
		foreach ($ChildEntity in $ChildEntitites)
		{
			if ($null -ne $ChildEntity){
				$EntityType = $ChildEntity.Type
				if ($EntityType -eq 'Class'){
					$EntityFunctionName = $ChildEntity.FunctionName
				}
				else{
					$EntityFunctionName = Get-GenericTypeFunctionName -GenericType $ChildEntity.GenericType
				}
				$CommandLine += Get-DiscoveryCommandLine -EntityType $EntityType -EntityName $ChildEntity.Name -EntityFunctionName $EntityFunctionName -EntityGuid $ChildEntity.Guid -DiscoverySetNode $DiscoverySetNode -DiscoveryScriptContents $DiscoveryScriptContents 
			}
		}
	}
	return $CommandLine
}

Function Get-DiscoverySetNode ([string] $DiscoverySetGuid){
	return $SchemaXML.SelectSingleNode("/Schema/DiscoverySet[@Guid='" + $DiscoverySetGuid + "']")
}

Function Get-CommandLineForEntity($EntityNode, $DiscoverySetNode){
	$EntityType = $EntityNode.Type
	if ($EntityType -eq 'Class'){
		$EntityFunctionName = $EntityNode.FunctionName
	}
	elseif ($EntityType -eq 'GenericClass'){
		$EntityFunctionName = Get-GenericTypeFunctionName -GenericType $EntityNode.GenericType
	}
	$EntityName = $EntityNode.Name
	$EntityGuid = $EntityNode.Guid
	if (($EntityType -ne 'Class') -or (Check-FunctionExist -FunctionName $EntityFunctionName -ScriptContents ([ref] $DiscoveryScriptContents))){
		$CommandLine += Get-DiscoveryCommandLine -EntityType $EntityType -EntityName $EntityName -EntityFunctionName $EntityFunctionName -EntityGuid $EntityGuid -DiscoverySetNode ([ref] $DiscoverySetNode) -DiscoveryScriptContents ([ref] $DiscoveryScriptContents)
	}
	else{
		"[Build-DiscoveryScript] DiscoverySet [$DiscoverySetName] Function for Class [$EntityName] Not Found: " + $EntityFunctionName + ". Discovery will not be executed against this DiscoverySet" | Log-CXPWriteLine -IsError
	}
	return $CommandLine
}

Function Get-AllSectionChildNodes ($DiscoverySetNode, $SectionGuid){
	$ChildNodes = @()
	Foreach ($EntityChildNode in (Get-ChildEntityNodes -DiscoverySetNode ([ref] $DiscoverySetNode) -GUID $SectionGuid))
	{
		if ($EntityChildNode.Type -eq 'Section'){
			$ChildNodes += Get-AllSectionChildNodes $DiscoverySetNode $SectionGuid
		}
		else{
			$ChildNodes += $EntityChildNode
		}
	}
	return $ChildNodes
}

Function Build-DiscoveryScript ($DiscoverySetGuid){
	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText "[Build-DiscoveryScript]"
		return $false
	}
	
	"Preparing to run DiscoverySet [$DiscoverySetGuid]" | Set-CXPExecutionStatus
	
	$DiscoverySetNode = Get-DiscoverySetNode -DiscoverySetGuid $DiscoverySetGuid
	
	if ($null -ne $DiscoverySetNode){
		$DiscoverySetScriptName = $DiscoverySetNode.Script
		$DiscoverySetName = $DiscoverySetNode.Name
		
		"Obtaining Information about DiscoverySet $DiscoverySetName" | Set-CXPExecutionStatus
		$DiscoveryScriptPath = (Join-Path $WorkingPath $DiscoverySetScriptName)
		if (Test-Path $DiscoveryScriptPath){
			$DiscoveryScriptContents = Get-Content $DiscoveryScriptPath
		
			$Results = @()
			foreach ($line in $DiscoveryScriptContents.GetEnumerator())
			{
				# Remove the signature block from the script contents
				if ($line -eq '# SIG # Begin signature block'){
					break
				}
				else{
					$Results += $line
				}
			}
			
			#$Results += ". `"" + $DiscoveryScriptPath + "`""
			
			Foreach ($EntityNode in $DiscoverySetNode.SelectNodes("Entities/Entity[not (@Parent)]")){
				if ($EntityNode.Type -ne 'Section'){
					$Results += Get-CommandLineForEntity $EntityNode $DiscoverySetNode
				}
				else{
					$ChildNodes = Get-AllSectionChildNodes -DiscoverySetNode $DiscoverySetNode -SectionGuid $EntityNode.Guid
					Foreach ($ChildEntityNode in $ChildNodes){
						$Results += Get-CommandLineForEntity -EntityNode $ChildEntityNode -DiscoverySetNode $DiscoverySetNode
					}
				}
			}
			
			Foreach ($SectionNode in $DiscoverySetNode.SelectNodes("Entities/Entity[@DiscoverySetLink]")){
				"[Build-DiscoveryScript] DiscoverySet [$DiscoverySetName] Section [$EntityName] contains an EntityLink with Entity " + $SectionNode.DiscoverySetLink | Log-CXPWriteLine
				$Results += Build-DiscoveryScript -DiscoverySetGuid $SectionNode.DiscoverySetLink
			}
			return $Results
		}
		else{
			"[Build-DiscoveryScript] DiscoverySet [$DiscoverySetName] Script File Not Found: " + $DiscoveryScriptPath + ". Discovery will not be executed against this DiscoverySet" | Log-CXPWriteLine -IsError
			Return $null
		}
	}
	else{
		"[Build-DiscoveryScript] Unable to locate DiscoverySet [$DiscoverySetGuid]. Discovery will not be executed against this DiscoverySet" | Log-CXPWriteLine -IsError
		Return $null
	}
}

Function Get-ParentEntity ([ref] $DiscoverySetNode, [ref] $EntityNode){
	$EntityParentGUID = $EntityNode.Value.Parent
	If (-not( [string]::IsNullOrEmpty($EntityParentGUID))){
		if ($DiscoverySetNode.Value -is [System.String]){
			$DiscoverySetNode.Value = Get-DiscoverySetNode -DiscoverySetGuid $DiscoverySetNode
		}
		
		$ParentNode = $DiscoverySetNode.Value.SelectSingleNode("Entities/Entity[@Guid='" + $EntityParentGUID + "']")
		if ($null -ne $ParentNode){
			if ($ParentNode.Type -ne 'Section'){
				return $EntityParentGUID
			}
			else{
				return Get-ParentEntity -DiscoverySetNode $DiscoverySetNode -EntityNode ([ref] $ParentNode)
			}
		}
		else{
			"Unable to find parent for Entity " + $EntityNode.Name + "[" +$EntityNode.Guid + "]: Parent [$EntityParentGUID]"
		}
	}
	else{
		return $null
	}
}

Function Write-DiscoveryInfo{
	param (
		$InputObject,
		[String] $DiscoverySet,
		[string] $Entity,
		$ParentID = $null,
		[System.Management.Automation.InvocationInfo] $InvokeInfo = $MyInvocation)
	BEGIN
	{
		$DiscoverySetNode = Get-DiscoverySetNode -DiscoverySetGuid $DiscoverySet
		
		$EntityNode = Get-EntityNode -DiscoverySetNode ([ref] $DiscoverySetNode) -EntityGuid $Entity
		if ($null -eq $EntityNode){
			"[Write-DiscoveryInfo] Unable to find Entity [$EntityNode]" | Log-CXPWriteLine -IsError
			return $null
		}
		else{
			$ParentEntity = Get-ParentEntity -DiscoverySet ([ref] $DiscoverySetNode) -EntityNode ([ref] $EntityNode)
		}
	}
	PROCESS
	{
		if ($_ -ne $null){
			if ($null -eq $InputObject) { $InputObject=@() }
			$InputObject += $_
		}
	}
	END
	{
		if ($null -ne $InputObject){
			if (($InputObject -is [array]) -and ($InputObject.Count -gt 0) -and (($InputObject[0] -is [PSObject]) -or ($InputObject[0] -is [Hashtable])) -or ($InputObject -is [PSObject]) -or ($InputObject -is [Hashtable]))
			{
				$MemberId = Write-DataEntityMember -InputObject $InputObject -EntityNode $EntityNode -ParentEntity $ParentEntity -ParentMember $ParentID -DiscoverySet $DiscoverySet
			}
			elseif ($InputObject -is [array]){
				if ($InputObject.Count -gt 0){
					"[Write-DiscoveryInfo] InputObject is not one of the acceptable types. Entity: [$Entity]. Inputobject Type: [Array] of " + ($InputObject[0].GetType().FullName) | Log-CXPWriteLine -IsError
				}
			}
			else{
				("[Write-DiscoveryInfo] InputObject is not one of the acceptable types. Entity: [$Entity]. Inputobject Type: " + ($InputObject.GetType().FullName)) | Log-CXPWriteLine -IsError
			}
			return $MemberId
		}
		else{
			"[Write-DiscoveryInfo] Skipping entity $Entity as inputobject is null" | Log-CXPWriteLine
		}
	}
}

Function Get-ParentMemberNode ([string] $ParentEntity, [string] $Xpath){
	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText "[Get-ParentMemberNode] ParentEntity: $ParentEntity - XPath: $Xpath"
		return $null
	}
	
	$ParentMemberNodes = $DiscoveryReportXML.SelectNodes("/Root/DiscoverySetData[@ComputerName='" + $Env:ComputerName +"']/EntityData[@Entity=`'" + $ParentEntity + "`']/Data/Member[$xpath]")
	return $ParentMemberNodes
}

#Return The Parent Member of a InputObjectMember
Function Get-ParentMember($InputObject, $EntityNode, $DiscoverySet, $InputObjectMember){
	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText "[Get-ParentMember] XPath: $Xpath"
		return $null
	}
	
	$ParentMemberID = $null
		#Check if There are InputArguments and if so, the item has a parent
	if ($null -ne $EntityNode.InputArguments){
		$ParentEntity = Get-ParentEntity -DiscoverySetNode ([ref] $DiscoverySet) -EntityNode ([ref] $EntityNode)
		$XpathArray = @()
		$QueryKeyValuePairs = @{}
		$EntityNode.InputArguments.InputArgument | ForEach-Object -Process {
			$ArgumentName = $_.Name
			$ParentProperty = $_.OutputProperty
			$ArgumentValue = $InputObjectMember.$ArgumentName

			if ($null -ne $ArgumentValue){
				if (($ArgumentValue -is [string]) -and (-not $ArgumentValue.Contains("'")) -or ($ArgumentValue -isnot [string])){
					$XpathArray += "($ParentProperty = `'" + $ArgumentValue + "`')"
					$QueryKeyValuePairs += @{$ParentProperty = $ArgumentValue}
				}
				else{
					"Argument [$ArgumentName] contains single quotes, which is not supported. Current Value: [$ArgumentValue]" | Log-CXPWriteLine -IsError
				}
			}
		}
		
		if ($XpathArray.Count -gt 0){
			$Xpath = [string]::Join(" and ", $XpathArray)
		}
		else{
			#Try to see if there is one single parent member. If so, use this member as the default parent
			#"Unable to locate parent data member for data member of entity " + $EntityNode.Name + " [" + $EntityNode.Guid + "] as no arguments were returned. Below a list of arguments required for the class: `n`r" + ($EntityNode.InputArguments.InputArgument | Select-Object Name | fl | Out-String) + "`n`r`n`rAnd below is the list of properties returned by the first object: " + ($InputObjectMember | Select-Object -First 1 | fl | Out-String) | Log-CXPWriteLine -Debug
			$Xpath = '*'
		}
	}
	else{
		$ParentEntity = Get-ParentEntity -DiscoverySetNode ([ref] $DiscoverySet) -EntityNode ([ref] $EntityNode)
		$Xpath = '*'
	}
	
	if ($null -ne $ParentEntity){
		$ParentMemberNode = Get-ParentMemberNode -ParentEntity $ParentEntity -XPath $Xpath
			
		if ($ParentMemberNode -is [System.Xml.XmlElement]){
			$ParentMemberID = $ParentMemberNode.ID
		}
		elseif ($null -eq $ParentMemberNode){
			if ($QueryKeyValuePairs.Count -gt 0){
				$QueryUsedDisplay = "Below is the filter used: `n`r" + ($QueryKeyValuePairs | Format-List | Out-String) 
			}
			"[Get-ParentMember] Unable to locate parent data member for data member of entity " + $EntityNode.Name + " [" + $EntityNode.Guid + "] Member will be ignored. " + $QueryUsedDisplay | Log-CXPWriteLine -Debug -IsWarning
		}
		elseif ($ParentMemberNode -is [System.Xml.XmlNodeList]){
			if ($QueryKeyValuePairs.Count -gt 0){
				$QueryUsedDisplay = "Below is the filter used: `n`r" + ($QueryKeyValuePairs | Format-List | Out-String) 
			}
			"[Get-ParentMember] When locating parent data member for data member of entity " + $EntityNode.Name + " [" + $EntityNode.Guid + "] " + $ParentMemberNode.Count + " members were found and entry will be ignored. " + $QueryUsedDisplay  | Log-CXPWriteLine -IsError
		}
	}
	return $ParentMemberID
}

#Generic function to create a node with its properties added from an object
Function Get-EntityDataNode($InputObject, $EntityNode, $DiscoverySet, $ElementTypeName){
	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText "[Get-EntityDataNode] Entity: $($EntityNode.Name)"
		continue
	}
	
	[System.Xml.XmlElement] $DataNode = $DiscoveryReportXML.CreateElement($ElementTypeName)
	
	$ParentMemberID = $null
	Foreach ($InputObjectMember in $InputObject)
	{
		#Check if there are InputArguments. Each member need a different parent
		if ($null -ne $EntityNode.InputArguments)
		{
			$ParentMemberID = Get-ParentMember -InputObject $InputObject -EntityNode $EntityNode -InputObjectMember $InputObjectMember -DiscoverySet $DiscoverySet
		}
		#If InputArguments are not used it means all members share a single parent
		elseif ($null -eq $ParentMemberID)
		{
			$ParentMemberID = Get-ParentMember -InputObject $InputObject -EntityNode $EntityNode -InputObjectMember $InputObjectMember -DiscoverySet $DiscoverySet
		}
		
		$ParentEntity = ''
		if (($null -eq $ParentMemberID) -and ($null -ne $EntityNode.Parent))
		{
			$ParentEntity = Get-ParentEntity -DiscoverySetNode ([ref] $DiscoverySet) -EntityNode ([ref] $EntityNode)
		}
		
		if (($null -ne $ParentMemberID) -or ($null -eq $EntityNode.Parent) -or ($null -eq $ParentEntity))
		{
			$MemberDataNode = $DiscoveryReportXML.CreateElement("Member")
			$X = $MemberDataNode.SetAttribute("ID", [Guid]::NewGuid())
			if ($null -ne $ParentMemberID)
			{
				$MemberDataNode.SetAttribute("ParentMemberID", $ParentMemberID)
			}
			
			$EntityNode.Properties.Property | ForEach-Object -Process {
				$PropertyName = $_.Name
				$PropertyDataType = $_.DataType
				$PropertyOrder = $_.Order
			
				if ($null -ne $InputObjectMember.$PropertyName)
				{
					#Check for Data Type Formats
					$DataTypeInfo = $Script:GlobalDataTypes.DataType | Where-Object {$_.Name -eq $PropertyDataType}
					if ($null -ne $DataTypeInfo)
					{
						#Check if the type from the return object is of the allowed Type in PowerShell. For example, check if a specific property is a numeric value
						if ($null -ne ($InputObjectMember.$PropertyName -as $DataTypeInfo.PSTypeName))
						{
							$MemberDataElement = $DiscoveryReportXML.CreateElement($PropertyName)
							$X = $MemberDataElement.set_InnerText($InputObjectMember.$PropertyName)
							$MemberDataElement.SetAttribute('Order', $PropertyOrder)
							
							#Special Types Handling: Registry Values, Files etc
							$PropertyDataTypeFormat = $_.DataTypeFormat
							
							if ($null -ne $PropertyDataTypeFormat)
							{
								$DataTypeInfo = $Script:GlobalDataTypes.DataType | Where-Object {$_.Name -eq $PropertyDataType}
								
								#Check if a function needs to be called to format the item. If so, call the function.
								$DataTypeFormatFunctioName = ($DataTypeInfo.DataTypeFormats.DataTypeFormat | Where-Object {$_.Name -eq $PropertyDataTypeFormat}).FunctionName
								if (-not ([string]::IsNullOrEmpty($DataTypeFormatFunctioName)))
								{
									#Obtain Formatted Value
									trap [Exception] 
									{
										Log-CXPException -ErrorRecord $_ -ScriptErrorText "[Get-EntityDataNode] Running function $DataTypeFormatFunctioName for Entity $($EntityNode.Name)"
										Continue
									}
									
									$CommandToRun = $DataTypeFormatFunctioName + " `'" + ($InputObjectMember.$PropertyName) + "`'"
									$Error.Clear()
									$returnValue = Invoke-Expression $CommandToRun
									
									if ($null -ne $returnValue)
									{
										#[System.Xml.XmlElement] $FormatedValue = $DiscoveryReportXML.CreateElement('FormattedValue')
										#$FormatedValue.SetAttribute('Value', $returnValue)
										$MemberDataElement.SetAttribute('FormattedValue', $returnValue)
										#$X = $MemberDataElement.AppendChild($FormatedValue)
									}
									elseif ($Error.Count -gt 0)
									{
										"[Get-EntityDataNode] Unable to properly format to $($PropertyDataTypeFormat) the value $($InputObjectMember.$PropertyName). Property Name: $PropertyName Entity $($EntityNode.Name). Error: " + $Error[0].Exception.get_Message()  | Log-CXPWriteLine -IsError
									}
								}
							}
							else
							{
								"[Get-EntityDataNode] Unable to find Data Type Information for Property $($PropertyName): $PropertyDataTypeFormat - Value: $($InputObjectMember.$PropertyName). Entity " + $EntityNode.Name | Log-CXPWriteLine -IsError
							}
							
							$X = $MemberDataNode.AppendChild($MemberDataElement)
						}
						elseif ($null -eq $TypeConflictExceptionLogged)
						{
							"[Get-EntityDataNode] Property $($PropertyName) cannot be converted to [" + $DataTypeInfo.PSTypeName + "] as it contains a [" + $InputObjectMember.$PropertyName.GetType().FullName + "] - Current Value: $($InputObjectMember.$PropertyName) - Entity " + $EntityNode.Name | Log-CXPWriteLine -IsError
							$TypeConflictExceptionLogged = $true
						}
					}
					elseif ($null -eq $MissingDataTypeExceptionLogged)
					{
						"[Get-EntityDataNode] Unable to find Data Type Information for ($PropertyDataType). This is defined on " + $EntityNode.Name | Log-CXPWriteLine -IsError
						$MissingDataTypeExceptionLogged = $true
					}
				}
			}
			$X = $DataNode.AppendChild($MemberDataNode)
		}
		
	}
	
	return $DataNode
}

Function Write-DataEntityMember($InputObject, $EntityNode, $ParentEntity = $null, $ParentMember = $null, $DiscoverySet){

	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText "[Write-DataEntityMember]"
		return
	}

	$DiscoverySetDataNode = $DiscoveryReportXML.SelectSingleNode("/Root/DiscoverySetData[(@DiscoverySet = `'$DiscoverySetGuid`') and (@ComputerName = `'$($Env:COMPUTERNAME)`')]")
	if ($null -eq $DiscoverySetDataNode)
	{
		[System.Xml.XmlElement] $DiscoverySetDataNode = $DiscoveryReportXML.CreateElement("DiscoverySetData")
		$X = $DiscoverySetDataNode.SetAttribute('DiscoverySet', $DiscoverySet)
		$X = $DiscoverySetDataNode.SetAttribute('ComputerName', $Env:COMPUTERNAME)
		$X = $DiscoveryReportXML.SelectSingleNode("/Root").AppendChild($DiscoverySetDataNode)
	}
	
	#if (($ParentMember -ne $null) -and ($ParentEntity -ne $null))
	#{
	#	$ParentNode = $DiscoverySetDataNode.SelectSingleNode(".//EntityData[(@Entity=`'" + $ParentEntity + "`')]/Member[@ID=`"" + $ParentMember + "`"]")
	#}
	
	if ($null -eq $ParentNode)
	{
		$ParentNode = $DiscoverySetDataNode
	}
	
	#Check if Entity already exists on Discovery Report XML
	#$EntityDataNode = $ParentNode.SelectSingleNode(".//EntityData[(@Entity=`'" + $EntityNode.Guid + "`')]")
	
	#if ($EntityDataNode -eq $null)
	#{
		#If not, create the Entity data node		
		[System.Xml.XmlElement] $EntityDataNode = $DiscoveryReportXML.CreateElement("EntityData")
		$X = $EntityDataNode.SetAttribute('Entity', $EntityNode.Guid)
		$X = $EntityDataNode.SetAttribute('Version', $EntityNode.Version)
		$X = $ParentNode.AppendChild($EntityDataNode)
	#}

	#$MemberID = [Guid]::NewGuid()
	#[System.Xml.XmlElement] $EntityDataMemberNode = $DiscoveryReportXML.CreateElement("Member")
	#$EntityDataMemberNode.SetAttribute("ID", $MemberID)
	#$X = $EntityDataNode.AppendChild($EntityDataMemberNode)

	$DataElement = Get-EntityDataNode -EntityNode $EntityNode -InputObject $InputObject -ElementTypeName 'Data' -DiscoverySet $DiscoverySet
	
	$X = $EntityDataNode.AppendChild($DataElement)
	return $MemberID
}

#Get a list of arguments for a GenericType based on their current argument list and default values
Function Get-GenericTypeArgumentHashTable ($GenericTypeNode, $ArgumentList){
	$Error1 = $false
	$GenericTypeName = $GenericTypeNode.Name
	$GenericTypeArgumentsTable = @{}
	$GenericTypeNode.GenericDataTypeInputArguments.Argument | ForEach-Object -Process {
		$ArgumentName = $_.Name
		if ($ArgumentList.ContainsKey($ArgumentName))
		{
			$GenericTypeArgumentsTable += @{$ArgumentName = $ArgumentList.get_Item($ArgumentName)}
		}
		elseif(-not ([string]::IsNullOrEmpty($_.DefaultValue)))
		{
			$GenericTypeArgumentsTable += @{$ArgumentName = $_.DefaultValue}
		}
		elseif($_.Required -eq 'true')
		{
			"Argument $ArgumentName is a required argument to [$GenericTypeName] GenericType and it was not set. Please set this value in Authoring Tool" | Log-CXPWriteLine -IsError
			$Error1 = $true
		}
	}
	
	$ArgumentList.GetEnumerator() | ForEach-Object -Process {
		$ArgumentName = $_.Key
		$ArgumentValue = $_.Value
		if ($null -eq $GenericTypeNode.GenericDataTypeInputArguments.SelectSingleNode("Argument[@Name=`'$ArgumentName`']"))
		{
			"Argument $ArgumentName containing [$ArgumentValue] is not defined in GenericType [$GenericTypeName] and will be ignored " | Log-CXPWriteLine -IsWarning
		}
	}
	
	if (-not $Error1)
	{
		return $GenericTypeArgumentsTable
	}
	else
	{
		return $null
	}
}

Function Get-GenericWMIClass ($Entity, $DiscoverySet, [hashtable] $ArgumentList){
	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText "[Get-GenericWMIClass] Entity: $($Entity) - WMIClassName: $($WMIClassName)"
		continue
	}
	
	$GenericTypeNode = Get-GenericTypeNode "WMIClass"
	
	$GenericTypeArgumentsTable = Get-GenericTypeArgumentHashTable -GenericTypeNode $GenericTypeNode -ArgumentList $ArgumentList
	
	if ($null -ne $GenericTypeArgumentsTable)
	{
		$GenericTypeArgumentsTable.GetEnumerator() | ForEach-Object -Process {
			$ArgumentName = $_.Name
			New-Variable -Name $ArgumentName -Value $GenericTypeArgumentsTable.get_Item($ArgumentName)
		}
	}
	else
	{
		return $null
	}
	
	$DiscoverySetNode = Get-DiscoverySetNode -DiscoverySetGuid $DiscoverySet
	$EntityNode = Get-EntityNode -EntityGuid $Entity -DiscoverySetNode ([ref] $DiscoverySetNode)
	
	$EntityProperties = $EntityNode.Properties.Property
	
	$ReturnObject = @()
	$WmiObject = Get-CimInstance -Class $WMIClassName -Namespace $NameSpace -Filter $Filter
	
	if ($null -ne $WmiObject)
	{
		foreach ($WmiObjectMember in $WmiObject)
		{
			$DataValues = @{}
			$WMIProperties = ($WmiObjectMember.Properties | ForEach-Object { $_.Name })
			Foreach ($EntityProperty in $EntityProperties)
			{		
				$PropertyName = $EntityProperty.Name
				if ($WMIProperties -contains $PropertyName)
				{
					$DataValues += @{$PropertyName = $WmiObjectMember.$PropertyName}
				}
				elseif ($ExceptionLogged = $null)
				{
					"[Get-GenericWMIClass] Definition of $($EntityNode.Name) contains property $PropertyName, however WMI Class $WMIClassName does not have this property" | Log-CXPWriteLine
					$ExceptionLogged = $true
				}
			}
			$ReturnObject += $DataValues 
		}
	}
	else
	{
		"[Get-GenericWMIClass] Nothing was returned by $WMIClassName on NameSpace $NameSpace ($Filter). This WMI Class is defined on class $($EntityNode.Name)" | Log-CXPWriteLine
	}
	return $ReturnObject
}

#Get a list of required properties for system objects like folder, file and registry
Function Get-SystemObjectPropertyList($TypeName){
	switch ($TypeName)
	{
		'Folder'
		{
			@('FullName', 'Name', 'CreationTime', 'LastWriteTime', 'RelativePath')
		}
		'File'
		{
			@('Name', 'Extension', 'FullName', 'Length', 'CreationTime', 'LastWriteTime', 'RelativePath')
		}
		'FileVersionInfo'
		{
			@('CompanyName', 'FileBuildPart', 'FileDescription', 'FileMajorPart', 'FileMinorPart', 'FilePrivatePart', 'FileVersion', 'InternalName', 'Language', 'ProductName', 'OriginalFilename', 'ProductVersion')
		}
		'RegistryKey'
		{
			@{'FullName' = 'Name'; 'Name' = 'PSChildName'; 'SubKeyCount' = 'SubKeyCount'; 'ValueCount'= 'ValueCount', 'RelativePath'}
		}
		'RegistryValue'
		{
			@('Name', 'Type', 'Data')
		}
	}
}

#Obtain a XML node for a 'System Object' (Folder/ File/ Registry)
Function Get-SystemObjectNode($Object, $TypeName, $RootQualifier)
{
	$PropertyList = Get-SystemObjectPropertyList -TypeName $TypeName
						
	[System.Xml.XmlElement] $ObjectNode = $DiscoveryReportXML.CreateElement($TypeName)
	
	if ($PropertyList -is [array])
	{
		$PropertyList | ForEach-Object -Process {
			trap [Exception] 
			{
				Log-CXPException -ErrorRecord $_ -ScriptErrorText ("[Get-SystemObjectNode] FullPath: $CurrentFullPath - Property: $PropertyName")
				Continue
			}
			$PropertyName = $_
			if (($PropertyName -ne 'Name') -or ($Object.$PropertyName -ne ($RootQualifier + '\')))
			{
				
				$ObjectNode.SetAttribute($PropertyName, $Object.$PropertyName)
			}
			else
			{
				$ObjectNode.SetAttribute($PropertyName, $RootQualifier)
			}
		}
	}
	elseif ($PropertyList -is [HashTable])
	{
		$PropertyList.GetEnumerator() | ForEach-Object -Process {
			trap [Exception] 
			{
				Log-CXPException -ErrorRecord $_ -ScriptErrorText ("[Get-SystemObjectNode] FullPath: $CurrentFullPath - Property: $PropertyName")
				Continue
			}
			$PropertyName = $_.Key
			$ObjectPropertyName = $_.Value
			$ObjectNode.SetAttribute($PropertyName, (Convert-RootRegistryString $Object.$ObjectPropertyName))
		}
	}
	return $ObjectNode 
}

Function Convert-RegistryString ($RegistryString){
	$RegistryString -replace "HKLM\\", "HKLM:\" -replace "HKCU\\", "HKCU:\" -replace "HKU\\", "Registry::HKEY_USERS\" -replace "HKEY_LOCAL_MACHINE\\", "HKLM:\" -replace "HKEY_CURRENT_USER\\", "HKCU:\" -replace "HKEY_USERS\\", "Registry::HKEY_USERS\"
}

Function Convert-RootRegistryString($RootRegkey){
	switch ($RootRegkey)
	{
		"HKEY_CURRENT_USER"{"HKCU:"; break;}
      	"HKEY_LOCAL_MACHINE" {"HKLM:"; break;}
      	"HKEY_USERS" {"HKU:"; break;}
      	default {$RootRegkey}
    }
}

Function Get-RegistryKeyInfo ($Entity, $DiscoverySet, [HashTable] $ArgumentList){
	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText ("[Get-RegistryKeyInfo] Entity: $Entity - DiscoverySet: $DiscoverySet - Path: $Path")
		Continue
	}
	
	$GenericTypeNode = Get-GenericTypeNode "RegistryKey"
	$GenericTypeArgumentsTable = Get-GenericTypeArgumentHashTable -GenericTypeNode $GenericTypeNode -ArgumentList $ArgumentList
	
	if ($null -ne $GenericTypeArgumentsTable)
	{
		$GenericTypeArgumentsTable.GetEnumerator() | ForEach-Object -Process {
			$ArgumentName = $_.Name
			New-Variable -Name $ArgumentName -Value $GenericTypeArgumentsTable.get_Item($ArgumentName)
		}
	}
	else
	{
		return
	}
	
	if ($null -ne $FullName)
	{
		$PSRegKeyName = Convert-RegistryString $FullName
	}
	
	if (-not (Test-path $PSRegKeyName))
	{
		"[Get-RegistryKeyInfo] $PSRegKeyName does not exists Entity: [$Entity] DiscoverySet [$DiscoverySet]." | Log-CXPWriteLine
		return
	}
	
	[array] $AllRegKeys = $PSRegKeyName
	
	if ($Recursive -ne "False")
	{
		trap [Exception]
		{
			Log-CXPException -ErrorRecord $_ -ScriptErrorText ("[Get-RegistryKeyInfo] Enumerating subkeys of $PSRegKeyName - Entity: [$Entity] DiscoverySet [$DiscoverySet]")
			Continue
		}
		
		$AllRegKeys += Get-ChildItem $PSRegKeyName -Recurse | Where-Object {$_.PSIsContainer -eq $true} | ForEach-Object {$_.PSPath}
	}
	
	
	Foreach ($RegKeyName in $AllRegKeys)
	{
		trap [Exception] 
		{
			Log-CXPException -ErrorRecord $_ -ScriptErrorText ("[Get-FolderInfo] Enumerating $($Folder)\$($Filter) - Entity: [$Entity] DiscoverySet [$DiscoverySet]")
			Continue
		}
		
		$ParentRegistryKeyNode = Get-DirectoryNode -DirectoryPath $RegKeyName -TypeName 'Registry'		
		$RegValues = Get-ItemProperty -Path $RegKeyName		
		Write-RegValue -ParentKeyNode $ParentRegistryKeyNode -RegKeyPSObject $RegValues -Filter $Filter
	}
}

#Obtain RelativePaths using Replacement Strings
Function Get-RelativePath ($Path){
	trap [Exception] 
	{
		continue
	}
	
	if ($RelativePaths.Count -gt 0)
	{
		$RelativePaths | ForEach-Object -Process {
			$RelativePathVariable = Get-Variable $_ -ErrorAction SilentlyContinue
			if ((($RelativePathVariable.Value -is [string]) -and (-not [string]::IsNullOrEmpty($RelativePathVariable.Value))) -or
				(($RelativePathVariable.Value -is [array]) -and ($RelativePathVariable.Value.Count -gt 0)))
			{
				foreach ($RelativePathValue in $RelativePathVariable.Value)
				{
					$Path = $Path -replace $RelativePathValue.Replace('\', '\\'), ("%" + $RelativePathVariable.Name + "%")
				}
			}
		}
	}
	return $Path
}

Function GetRegistryValueTypeName($RegValueData)
{
	$TypeString = ""
	
	if($RegValueData -is [System.Management.Automation.PSNoteProperty])
	{
		$TypeString = $RegValueData.TypeNameOfValue
	}
	else
	{
		$TypeString = $RegValueData.GetType().FullName
	}
	
	switch ($TypeString)
	{
		"System.String" {"REG_SZ"; break;}
	    "System.Int32" {"REG_DWORD"; break;}
	    "System.Int64" {"REG_QWORD"; break;}
	    "System.String[]" {"REG_MULTI_SZ"; break;}
	    "System.Byte[]" {"REG_BINARY"; break;}
	    default {"Unknown type"}
	}
}

Function Write-RegValue ($FullPath, $ParentKeyNode, $RegKeyPSObject, $Filter){
	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText ("[Write-RegValue] Writing $FullPath / $ValueName / $KeyName")
		Continue
	}
	
	if ($null -ne $FullPath)
	{
		$ValueName = Split-Path -Path $FullPath -Leaf
		$RegistryKeyName = Convert-RegistryString (Split-Path -Path $FullPath)
		
		if (Test-Path $RegistryKeyName)
		{
			$ParentKeyNode = Get-DirectoryNode -DirectoryPath $RegistryKeyName -TypeName 'Registry'
		}
		else
		{
			"[Write-RegValue] $FullPath does not exist." | Log-CXPWriteLine -Debug
		}		
		
		if ($null -ne $ParentKeyNode)
		{
			$RegValueData = (Get-ItemProperty $KeyName -Name $ValueName).$ValueName
			$RegValueDataType = GetRegistryValueTypeName $RegValueData
			
			$RegCustomObject = New-Object 'PSObject'
			$RegCustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value $ValueName
			$RegCustomObject | Add-Member -MemberType NoteProperty -Name "Data" -Value $RegValueData
			$RegCustomObject | Add-Member -MemberType NoteProperty -Name "DataType" -Value $RegValueDataType
			
			[System.Xml.XmlElement] $ValueNode = Get-SystemObjectNode -TypeName 'RegistryValue' -Object $RegCustomObject
			
			$ExistingValueNode = $ParentKeyNode.SelectSingleNode("RegistryValue[@Name='$($ValueName)']")
			if ($ExistingValueNode)
			{
				$X = $ParentKeyNode.ReplaceChild($ValueNode, $ExistingValueNode)
			}
			else
			{
				$X = $ParentKeyNode.AppendChild($ValueNode)
			}
		}
		else
		{
			"[Write-RegValue] Unable to create Registry Structure for Key: [$RegistryKeyName]. Value Name: [$RegistryValueName]" | Log-CXPWriteLine -Debug
		}
	}
	elseif (($RegKeyPSObject -is [PSObject]) -and ($ParentKeyNode -is [System.Xml.XmlElement]))
	{
		$RegPropertiesToExclude = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
		foreach($RegValue in $RegValues.PSObject.Members | Where-Object {$_.MemberType -eq "NoteProperty"}) 
		{
			If ((([string]::IsNullOrEmpty($Filter)) -or ($RegValue.Name -like $Filter)) -and ($RegPropertiesToExclude -notcontains $RegValue.Name))
			{		
				$RegCustomObject = New-Object 'PSObject'
				
				$RegCustomObject | Add-Member -MemberType NoteProperty -Name "Name" -Value $RegValue.Name
				$RegCustomObject | Add-Member -MemberType NoteProperty -Name "Type" -Value (GetRegistryValueTypeName -RegValueData $RegValue)
				
				if($RegValue.Value -is [System.String[]])
				{
					$RegValue.Value = [string]::Join("\0", $RegValue.Value)
				}
				$RegCustomObject | Add-Member -MemberType NoteProperty -Name "Data" -Value $RegValue.Value
				
				[System.Xml.XmlElement] $ValueNode = Get-SystemObjectNode -TypeName 'RegistryValue' -Object $RegCustomObject
				$ExistingValueNode = $ParentKeyNode.SelectSingleNode("RegistryValue[@Name='$($RegValue.Name)']")
				if ($ExistingValueNode)
				{
					$X = $ParentKeyNode.ReplaceChild($ValueNode, $ExistingValueNode)
				}
				else
				{
					$X = $ParentKeyNode.AppendChild($ValueNode)
				}
			}
			elseif ([string]::IsNullOrEmpty($Filter))
			{
				$RegValue.Name + "\" + $RegValue.Value + " skipped due filter [$Filter] used Entity: $Entity - DiscoverySet: $DiscoverySet" | Log-CXPWriteLine -Debug
			}
		}
	}
}

Function Get-FolderInfo ($Entity, $DiscoverySet, [HashTable] $ArgumentList){
	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText ("[Get-FolderInfo] Entity: $Entity - DiscoverySet: $DiscoverySet - Path: $Path")
		Continue
	}
	
	$GenericTypeNode = Get-GenericTypeNode "Folder"
	$GenericTypeArgumentsTable = Get-GenericTypeArgumentHashTable -GenericTypeNode $GenericTypeNode -ArgumentList $ArgumentList
	
	if ($null -ne $GenericTypeArgumentsTable)
	{
		$GenericTypeArgumentsTable.GetEnumerator() | ForEach-Object -Process {
			$ArgumentName = $_.Name
			New-Variable -Name $ArgumentName -Value $GenericTypeArgumentsTable.get_Item($ArgumentName)
		}
	}
	else
	{
		return $null
	}
	
	if (-not ([System.IO.Directory]::Exists($Path)))
	{
		#Check if the path is a file. In this case, strip the file from the path
		if ([System.IO.File]::Exists($Path))
		{
			"[Get-DirectoryNode] $DirectoryPath is a file. Removing file from path..." | Log-CXPWriteLine
			$Path = [System.IO.Path]::GetDirectoryName($Path)
		}
		else
		{
			"[Get-DirectoryNode] $DirectoryPath does not exists Entity: [$Entity] DiscoverySet [$DiscoverySet]." | Log-CXPWriteLine
			return $null
		}
	}
	
	
	[array] $AllFolders = $Path
	
	if ($Recursive -eq $true)
	{
		trap [Exception] 
		{
			Log-CXPException -ErrorRecord $_ -ScriptErrorText ("[Get-FolderInfo] Enumerating subfolders of $Path - Entity: [$Entity] DiscoverySet [$DiscoverySet]")
			Continue
		}
		
		$AllFolders += [System.IO.Directory]::EnumerateDirectories($Path, '*.*', [System.IO.SearchOption]::AllDirectories)
	}
	
	Foreach ($Folder in $AllFolders)
	{
		trap [Exception] 
		{
			Log-CXPException -ErrorRecord $_ -ScriptErrorText ("[Get-FolderInfo] Enumerating $($Folder)\$($Filter) - Entity: [$Entity] DiscoverySet [$DiscoverySet]")
			Continue
		}
		
		$FolderNode = Get-DirectoryNode -DirectoryPath $Folder -TypeName 'FileSystem'
		if ($null -ne $FolderNode)
		{
			$Files = [System.IO.Directory]::EnumerateFiles($Folder, $Filter, [System.IO.SearchOption]::TopDirectoryOnly)
			
			ForEach ($FileName in $Files)
			{
				Write-FileInfo -Path $FileName -FolderName $Folder -ParentFolderNode $FolderNode
			}
			
		}
	}
	
}

#Return a XML Node for a File or a Registy Key
Function Get-DirectoryNode ($DirectoryPath, $TypeName){

	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText "[Get-DirectoryNode] Path: $DirectoryPath"
		Continue
	}

	switch ($TypeName)
	{
		'Registry' {$DirectoryTypeName = 'RegistryKey'}
		default {$DirectoryTypeName = 'Folder'}
	}
	
	if ($TypeName -eq 'FileSystem')
	{
		if (-not ([System.IO.Directory]::Exists($DirectoryPath)))
		{
			#Check if the path is a file. In this case, strip the file from the path
			if ([System.IO.File]::Exists($DirectoryPath))
			{
				"[Get-DirectoryNode] $DirectoryPath is a file. Removing file from path..." | Log-CXPWriteLine
				$FolderParts = [System.IO.Path]::GetDirectoryName($DirectoryPath)
			}
			else
			{
				"[Get-DirectoryNode] $DirectoryPath does not exists. Entry not created" | Log-CXPWriteLine
				return $null
			}
		}
	}
	
	$FolderParts = $DirectoryPath.Split([System.IO.Path]::DirectorySeparatorChar)
	
	$RootQualifier = Split-Path $DirectoryPath -Qualifier
	$DirectoryNode = $null
	
	$TopLevelDirectoryNode = $DiscoveryReportXML.SelectSingleNode("/Root/$($TypeName)Data[@ComputerName=`'" + $Env:COMPUTERNAME + "`']")
	if ($null -eq $TopLevelDirectoryNode)
	{
		[System.Xml.XmlElement] $TopLevelDirectoryNode = $DiscoveryReportXML.CreateElement(($TypeName + "Data"))
		$TopLevelDirectoryNode.SetAttribute('ComputerName', $Env:COMPUTERNAME)
		$RootNode = $DiscoveryReportXML.SelectSingleNode('/Root')
		$X = $RootNode.AppendChild($TopLevelDirectoryNode)
	}
	
	$RootQualifierNode = $TopLevelDirectoryNode.SelectSingleNode("Root[translate(@Name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')=`'" + $RootQualifier.ToLower() + "`']")
	
	if ($null -eq $RootQualifierNode)
	{
		[System.Xml.XmlElement] $RootQualifierNode = $DiscoveryReportXML.CreateElement("Root")
		$X = $RootQualifierNode.SetAttribute('Name', $RootQualifier)
		$X = $TopLevelDirectoryNode.AppendChild($RootQualifierNode)
	}
	else
	{
		$XPath = ''
		$FolderParts | ForEach-Object -Process {
			if ($_ -eq $RootQualifier)
			{
				$XPath += $DirectoryTypeName  + "[@Name=`'" + $RootQualifier + "`']"
			}
			else
			{
				$XPath += "/" + $DirectoryTypeName  + "[translate(@Name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')=`'" + $_.ToLower() + "`']"
			}
		}
		
		$DirectoryNode = $RootQualifierNode.SelectSingleNode($XPath)
	}
	$XPath = ''
	if ($null -eq $DirectoryNode)
	{
		$ParentNode = $RootQualifierNode
		$CurrentFullPath = $RootQualifier
		$FolderParts | ForEach-Object -Process {
			if ($_ -eq $RootQualifier)
			{
				$CurrentFolder = "\"
			}
			else
			{
				$CurrentFolder = $_
			}

			$CurrentFullPath = Join-Path $CurrentFullPath $CurrentFolder 

			$XPath = $DirectoryTypeName + "[translate(@Name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')=`'" + $CurrentFolder.ToLowerInvariant() + "`']"			
			$DirectoryNode = $ParentNode.SelectSingleNode($XPath)
			
			if ($null -eq $DirectoryNode)
			{
				trap [Exception] 
				{
					Log-CXPException -ErrorRecord $_ -ScriptErrorText "[Get-DirectoryNode] FullPath: $CurrentFullPath"
					Continue
				}
				
				$Object = (Get-Item $CurrentFullPath -Force)
				
				if ($null -ne $Object)
				{
					$DirectoryNode = Get-SystemObjectNode -Object $Object -TypeName $DirectoryTypeName -RootQualifier $RootQualifier
					if ($null -ne $DirectoryNode)
					{
						$DirectoryNode.SetAttribute('RelativePath', (Get-RelativePath -Path $DirectoryNode.FullName))
						$X = $ParentNode.AppendChild($DirectoryNode)
					}
				}
			}
			
			$ParentNode = $DirectoryNode
		}
	}
	
	return $DirectoryNode
}

Function Get-FileVersionInfo($FileObject, [Ref] $FileNode){
	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText "[Write-FileVersionInfo] Path: " + $FileObject.FullPath
		return
	}
	
	$FilePropertiesNode = $FileNode.Value
	if (($FileObject -is [System.IO.FileInfo]) -and ($FilePropertiesNode -is [System.Xml.XmlElement]))
	{
		$FileVersionInfo = $FileObject.VersionInfo
		#Fill out with known properties
		$FileVersionInfoNode = Get-SystemObjectNode -TypeName 'FileVersionInfo' -Object $FileVersionInfo
		
		if ($null -ne $FileVersionInfoNode)
		{		
			#LDRGDR
			#For LDR/GDR, we first see if the file version matches the OS version
			if (($FileVersionInfo.FileBuildPart -ge 6000) -and ($FileVersionInfo.FileMajorPart -eq $OSVersion.Major) -and ($FileVersionInfo.CompanyName -eq 'Microsoft Corporation'))
			{
				$Branch = $null
				#Check if the current version of the file is GDR or LDR:
				if (($FileVersionInfo.FilePrivatePart.ToString().StartsWith(16)) -or 
					($FileVersionInfo.FilePrivatePart.ToString().StartsWith(17)) -or
					($FileVersionInfo.FilePrivatePart.ToString().StartsWith(18)))
				{
					$Branch = 'GDR'
				}
				elseif (($FileVersionInfo.FilePrivatePart.ToString().StartsWith(20)) -or 
					($FileVersionInfo.FilePrivatePart.ToString().StartsWith(21)) -or
					($FileVersionInfo.FilePrivatePart.ToString().StartsWith(22)))
				{
					$Branch = 'LDR'
				}
				### Missing: Need to calculate Branch for XP and 2K3
				if ($Branch)
				{
					$FileVersionInfoNode.SetAttribute('Branch', $Branch)
				}
			}
			$X = $FilePropertiesNode.AppendChild($FileVersionInfoNode)
		}
	}
	else
	{
		'[Write-FileVersionInfo] Either $FileObject is not a fileinfo or $FileNode is not a XMLElement' | Log-CXPWriteLine -IsWarning
		'                        $FileObject type : ' + $FileObject.GetType().BaseType | Log-CXPWriteLine
		'                        $FileNode type   : ' + $FileNode.GetType().BaseType | Log-CXPWriteLine
	}
}

Function Write-FileInfo ($Path, $FolderName, $ParentFolderNode){
	if ([System.IO.File]::Exists($Path))
	{
		if (($null -eq $FolderName) -or ($null -eq $ParentFolderNode))
		{
			#Check if file information already exist		
			$FolderName = [System.IO.Path]::GetFullPath([System.IO.Path]::GetDirectoryName($Path))
			
			$ParentFolderNode = Get-DirectoryNode $FolderName 'FileSystem'
		}
		
		if ($null -ne $ParentFolderNode)
		{
		
			trap [Exception] 
			{
				Log-CXPException -ErrorRecord $_ -ScriptErrorText "[Write-FileInfo] Path: $Path"
				Continue
			}
			
			#$FileObject = (Get-Item $Path -Force)
			$FileObject = [System.IO.FileInfo] $Path
				
			if ($null -eq $ParentFolderNode.SelectSingleNode("File[translate(@Name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')='$($FileObject.Name.ToLowerInvariant())']"))
			{					
				$FileNode = Get-SystemObjectNode -Object $FileObject -TypeName 'File'
				if ($null -ne $FileNode)
				{
					#$FileNode.RelativePath = Get-RelativePath -Path $FileNode.FullName
					$FileNode = $ParentFolderNode.AppendChild($FileNode)
					
					if ($null -ne $FileObject.VersionInfo.ProductVersion)
					{
						Get-FileVersionInfo -FileObject $FileObject -FileNode ([ref] $FileNode)
					}
					
					$X = $ParentFolderNode.AppendChild($FileNode)
				}
			}
		}
		else
		{
			"[Write-FileInfo] Unable to create Folder Structure for file: [$Path]. Parent Folder Name: [$FolderName]" | Log-CXPWriteLine -IsWarning
		}
	}
	else
	{
		if ([System.IO.Directory]::Exists($Path))
		{
			"[Write-FileInfo] Error: [$Path] is a folder not a file. Entry not created" | Log-CXPWriteLine -IsWarning
		}
		else
		{
			"[Write-FileInfo] Error: File $Path does not exist. Entry not created" | Log-CXPWriteLine -IsWarning
		}
	}
}

function ConvertTo-ScriptBlock{
   param ([string]$string)
   [scriptblock] $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock($string)
   Return $ScriptBlock 
}

Function SaveSchemaOnReport($DiscoveryReportXML){
	$SchemaNodeOnReport = $DiscoveryReportXML.SelectSingleNode('/Root/Schema')
	
	if ($null -ne $SchemaNodeOnReport)
	{
		$DiscoveryReportXML.Root.RemoveChild($SchemaNodeOnReport)
	}
	
	[System.Xml.XmlElement] $SchemaNodeOnReport = $DiscoveryReportXML.CreateElement("Schema")
	
	if ($null -ne $script:SchemaXML)
	{
		$SchemaNodeOnReport.Set_InnerXML($script:SchemaXML.Schema.get_OuterXML()) | Out-Null
		$X = $DiscoveryReportXML.Root.AppendChild($SchemaNodeOnReport)
		return $DiscoveryReportXML
	}
	else
	{
		"Unable to open Schema XML" | Log-CXPWriteLine -IsError
		return $null
	}
}

Function Get-DiscoveryReportXML([string] $Path){
	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText "[Get-DiscoveryReportXML] Path: $Path"
		return $false
	}
	
	#Make sure Schema XML is opened
	if ($null -eq $script:SchemaXML) 
	{
		$SchemaOpened = OpenSchemaXML -SchemaXMLPath $SchemaXMLPath
	}
	
	$Now = ((Get-Date).ToString([System.Globalization.CultureInfo]::InvariantCulture))
	if (-not (Test-Path $Path)) 
	{
		#DiscoveryReport does not Exist. Create a new one and stamp the schema in the results.
		"DiscoveryReport $Path does not exist. Creating a new report" | Log-CXPWriteLine
		[xml] $XML = "<Root TimeCreated=`"$($Now)`"/>"
	}
	else
	{
		"DiscoveryReport $Path already exists at $($Path). Using existing DiscoveryReport" | Log-CXPWriteLine
		[xml] $XML = (Get-Content -Path $Path)
		$XML.Root.SetAttribute('TimeUpdated', $Now)
	}
	
	if ($null -ne (SaveSchemaOnReport $XML))
	{
		return $XML
	}
	else
	{
		return $null
	}
}

Function WriteDiscoveryExecutionSummary{
	if ($null -ne $DiscoveryExecution_Summary)
	{
		$DiscoveryExecution_Summary | ConvertTo-Xml | Write-Output
	}
}


Filter FormatBytes 
{
	param ($bytes,$precision='0')
	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText "[FormatBytes] - Bytes: $bytes / Precision: $precision" -InvokeInfo $MyInvocation
		continue
	}
	
	if ($null -eq $bytes)
	{
		$bytes = $_
	}
	
	if ($null -ne $bytes)
	{
		$bytes = [double] $bytes
		foreach ($i in ("Bytes","KB","MB","GB","TB")) {
			if (($bytes -lt 1000) -or ($i -eq "TB")){
				$bytes = ($bytes).tostring("F0" + "$precision")
				return $bytes + " $i"
			} else {
				$bytes /= 1KB
			}
		}
	}
}

Function GetAgeDescription($TimeSpan){
	$Age = $TimeSpan

	if ($Age.Days -gt 0) 
	{
		$AgeDisplay = $Age.Days.ToString()
		if ($Age.Days -gt 1) 
		{
			$AgeDisplay += " Days"
		}
		else
		{
			$AgeDisplay += " Day"
		}
	} 
	else 
	{
		if ($Age.Hours -gt 0) 
		{
			if ($AgeDisplay.Length -gt 0) {$AgeDisplay += " "}
			$AgeDisplay = $Age.Hours.ToString()
			if ($Age.Hours -gt 1)
			{
				$AgeDisplay += " Hours"
			}
			else
			{
				$AgeDisplay += " Hour"
			}
		}
		if ($Age.Minutes -gt 0) 
		{
			if ($AgeDisplay.Length -gt 0) {$AgeDisplay += " "}
			$AgeDisplay += $Age.Minutes.ToString()
			if ($Age.Minutes -gt 1)
			{
				$AgeDisplay += " Minutes"
			}
			else
			{
				$AgeDisplay += " Minute"
			}
		}		
		if ($Age.Seconds -gt 0) 
		{
			if ($AgeDisplay.Length -gt 0) {$AgeDisplay += " "}
			$AgeDisplay += $Age.Seconds.ToString()
			if ($Age.Seconds -gt 1) 
			{
				$AgeDisplay += " Seconds"
			}
			else
			{
				$AgeDisplay += " Second"
			}
		}
		if (($Age.TotalSeconds -lt 1)) 
		{
			if ($AgeDisplay.Length -gt 0) {$AgeDisplay += " "}
			$AgeDisplay += $Age.TotalSeconds.ToString()
			$AgeDisplay += " Seconds"
		}	
	}
    Return $AgeDisplay
}

Function Run-DiscoveryFunction{
	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText "[Run-DiscoveryFunction] Expression: $($MyInvocation.Line)" -InvokeInfo $MyInvocation
		continue
	}
	
	$Error.Clear()

	$line = [regex]::Split($MyInvocation.Line.Trim(),'Run-DiscoveryFunction ')[1]

	if (-not [string]::IsNullOrEmpty($line))
	{
		"[Run-DiscoveryFunction]: Starting $line" | Log-CXPWriteLine
		$ScriptTimeStarted = Get-Date
		
		invoke-expression $line
		
		$TimeToRun = (New-TimeSpan $ScriptTimeStarted)
		
		if ($null -ne $ScriptExecutionInfo_Summary.$line) 
		{
			$X = 1
			$memberExist = $true
			do {
				if ($null -eq $ScriptExecutionInfo_Summary.($line + " [$X]")) {
					$memberExist = $false
					$line += " [$X]"
				}
				$X += 1
			} while ($memberExist)
		}
		
		$lineExecutionTimeDisplay = $line
		$x=0
		while ($null -ne $DiscoveryExecution_Summary.$lineExecutionTimeDisplay)
		{
			$x++
			$lineExecutionTimeDisplay = $line + " [$x]"
		}
		
	    $DiscoveryExecution_Summary | add-member -membertype noteproperty -name $lineExecutionTimeDisplay -value (GetAgeDescription $TimeToRun)
		
		"[Run-DiscoveryFunction]: Finished $line" | Log-CXPWriteLine

		if ($TimeToRun.Seconds -gt 20)
		{
			"$line took " + $TimeToRun.Seconds + " seconds to complete" | Log-CXPWriteLine -IsWarning
		}
	}
	else
	{
		"[Run-DiscoveryFunction] [" + [System.IO.Path]::GetFileName($MyInvocation.ScriptName) + " - " + $MyInvocation.ScriptLineNumber.ToString() + '] - Error: a null expression was sent to Run-DiscoveryFunction' | Log-CXPWriteLine -IsError
	}
}

Function Save-DiscoveryReport(){
	trap [Exception] 
	{
		Log-CXPException -ErrorRecord $_ -ScriptErrorText "[Save-DiscoveryReport] Path: $DiscoveryReportXMLPath"
		return
	}
	#### Add Encoding
	$DiscoveryReportXML.Save($DiscoveryReportXMLPath)
	"[Save-DiscoveryReport] Discovery report saved to $DiscoveryReportXMLPath" | Log-CXPWriteLine
}

#Remove any DiscoverySetData from the DiscoveryReport to avoid duplicating data from a previous execution
Function Remove-DiscoverySetResultsFromReport($DiscoverySetGuid){
	$DiscoverySetData = $DiscoveryReportXML.SelectSingleNode("/Root/DiscoverySetData[(@DiscoverySet = `'$DiscoverySetGuid`') and (@ComputerName = `'$($Env:COMPUTERNAME)`')]")
	if ($null -ne $DiscoverySetData)
	{
		
		"Data from DiscoverySet $DiscoverySetGuid already existed in the report. Removing it."  | Log-CXPWriteLine
		#$DiscoverySetData.RemoveAll()
		$X = $DiscoveryReportXML.Root.RemoveChild($DiscoverySetData)
	}
}

Function Get-DiscoverySetRelativePaths($DiscoverSetGuid){
	$DiscoverySetNode = Get-DiscoverySetNode -DiscoverySetGuid $DiscoverSetGuid
	$RelativePathsNode = $DiscoverySetNode.RelativePaths
	$RelativePathVars = @()
	if ($null -ne $RelativePathsNode)
	{
		$RelativePathVars = $RelativePathsNode.RelativePath | ForEach-Object {$_.Name}
	}
	Return $RelativePathVars
}

# Execute a DiscoverySet and return all child DiscoverySets
Function Run-DiscoverySet ([String] $DiscoverySetGuid){
	$ScriptContents = Build-DiscoveryScript $DiscoverySetGuid
	$ScriptBlock = ConvertTo-ScriptBlock ($ScriptContents -join "`r`n")
	$DiscoverySetNode = Get-DiscoverySetNode -DiscoverySetGuid $DiscoverySetGuid
	"[Run-DiscoverySet] Starting DiscoverySet Execution for $($DiscoverySetNode.Name) [$DiscoverySetGuid]" | Log-CXPWriteLine
	Remove-DiscoverySetResultsFromReport $DiscoverySetGuid
	New-Variable -Name Discovery -Scope Global -Force -Value $true
	$RelativePathVarNames = Get-DiscoverySetRelativePaths $DiscoverySetGuid
	if ($RelativePathVarNames.Count -gt 0)
	{
		New-Variable -Name RelativePaths -Scope Script -Force -Value $RelativePathVarNames
	}
	
	$ScriptBlock.InvokeReturnAsIs()
	Remove-Variable -Name Discovery -Scope Global
	if ($RelativePaths.Count -gt 0)
	{
		Remove-Variable -Name RelativePaths -Scope Script
	}
	
	"[Run-DiscoverySet] Finished DiscoverySet Execution for $($DiscoverySetNode.Name) [$DiscoverySetGuid]" | Log-CXPWriteLine
	Save-DiscoveryReport
}

"[Starting Discovery]" | Log-CXPWriteLine
$DiscoveryReportXML = Get-DiscoveryReportXML -Path $DiscoveryReportXMLPath
if ($null -ne $Discovery)
{
	Remove-Variable -Name Discovery -Scope Global
}
"[Starting Discovery] End Discovery" | Log-CXPWriteLine


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAKEhbQGhR6CvtY
# Zcz2sQezkaMBcZEhKkk60z/4YChM4qCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPCPVw7p1r8/DUAdL2UB5W5j
# N9YOWWORlHMRO0BvX319MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAydSPZ+tYR2yiT1gwyLCFvDMGVNGjBHMXYv0n0B1h5AfUA+f4l1jb3
# YI1nT0uU+pXEK5JObHnk9FFp1KvEK1P+bmxGSIzvnJwGOkDx1/VaLp7NPpxtUJ5I
# I6zzWJRINmqHlerZ3f/+IpQ0zJQy6ukb/6kMYRURAvbB7jZs7v00xfGtS3yXZFkt
# t6FsGnFy0Eum+f6pFg1q+o1EnN9TK78xQHo7pPQ1ipuqVjcv548YjboDhO0vfitc
# WCiiRgh+U5gPUAbPyJcd4D+Jt4v2UWa/vbEQXSpudl1dEDJ+cYgwW5wW+q8F0KRX
# 1fXwoINwagCU0avx0apRe9bWgNJlNT8qoYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIK5VO2iO9aRog1vV5uavQb01OlpOXnixxIXl66gf3QNvAgZi3nWy
# 2okYEzIwMjIwODE4MDcxNTI1LjQ4NlowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046OEQ0MS00QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAYguzcaBQeG8KgABAAABiDAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDBaFw0yMzAxMjYxOTI3NDBaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhENDEt
# NEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmucQCAQmkcXHyDrV4S88
# VeJg2XGqNKcWpsrapRKFWchhjLsf/M9XN9bgznLN48BXPAtOlwoedB2kN4bZdPP3
# KdRNbYq1tNFUh8UnmjCCr+CjLlrigHcmS0R+rsN2gBMXlLEZh2W/COuD9VOLsb2P
# 2jDp433V4rUAAUW82M7rg81d3OcctO+1XW1h3EtbQtS6QEkw6DYIuvfX7Aw8jXHZ
# nsMugP8ZA1otprpTNUh/zRWC7CJyBzymQIDSCdWhVfD4shxe+Rs61axf27bTg5H/
# V/SkNd9hzM6Nq/y2OjDKrLtuN9hS53569uhTNQeAhAVDfeHpEzlMvtXOyX6MTme3
# jnHdHPj6GLT9AMRIrAf96hPYOiPEBvHtrg6MpiI3+l6NlbSOs16/FTeljT1+sdsW
# GtFTZvea9pAqV1aB795aDkmZ6sRm5jtdnVazfoWrHd3vDeh35WV08vW4TlOfEcV2
# +KbairPxaFkJ4+tlsJ+MfsVOiTr/ZnDgaMaHnzzogelI3AofDU9ITbMkTtTxrLPy
# gTbRdtbptrnLzBn2jzR4TJfkQo+hzWuaMu5OtMZiKV2I5MO0m1mKuUAgoq+442Lw
# 8CQuj9EC2F8nTbJb2NcUDg+74dgJis/P8Ba/OrlxW+Trgc6TPGxCOtT739Uqeslv
# WD6rNQ6UEO9f7vWDkhd2vtsCAwEAAaOCATYwggEyMB0GA1UdDgQWBBRkebVQxKO7
# zru9+o27GjPljMlKSjAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQBAEFrb+1gIJsv/GKLS2zavm2ek177mk4yu6BuS
# 6ViIuL0e20YN2ddXeiUhEdhk3FRto/GD93k5SIyNJ6X+p8uQMOxI23YOSdyEzLJw
# h7+ftu0If8y3x6AJ0S1d12OZ7fsYqljHUeccneS9DWqipHk8uM8m2ZbBhRnUN8M4
# iqg4roJGmZKZ9Fc8Z7ZHJgM97i7fIyA9hJH017z25WrDJlxapD5dmMyNyzzfAVqa
# ByemCoBn4VkRCGNISx0xRlcb93W6ENhJF1NBjMl3cKVEHW4d8Y0NZhpdXDteLk9H
# gbJyeCI2fN9GBrCS1B1ak+194PGiZKL8+gtK7NorAoAMQvFkYgrHrWCYfjV6PouC
# 3N+A6wOBrckVOHT9PUIDK5ADCH4ZraQideS9LD/imKHM3I4iazPkocHcFHB9yo5d
# 9lMJZ+pnAAWglQQjMWhUqnE/llA+EqjbO0lAxlmUtVioVUswhT3pK6DjFRXM/LUx
# wTttufz1zBjELkRIZ8uCy1YkMxfBFwEos/QFIlDaFSvUn4IiWZA3VLfAEjy51iJw
# K2jSIHw+1bjCI+FBHcCTRH2pP3+h5DlQ5AZ/dvcfNrATP1wwz25Ir8KgKObHRCIY
# H4VI2VrmOboSHFG79JbHdkPVSjfLxTuTsoh5FzoU1t5urG0rwuloZZFZxTkrxfyT
# khvmjDCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
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
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046OEQ0MS00QkY3LUIzQjcxJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAOE8isx8IBeVPSweD805l5Qdeg5CoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmp+6DMCIYDzIwMjIwODE4
# MDY0NzMxWhgPMjAyMjA4MTkwNjQ3MzFaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOan7oMCAQAwBwIBAAICDb4wBwIBAAICEVMwCgIFAOapQAMCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQBQ1dJFiK3dTQ+6LRyu9+B6FUIgWKjFKSsAKj8FuhNY
# Hubrl/gaugKLXECH7yZIY6LAbIaLvAJR2/3BSdMLJ0vZLkyDVyPjaV22kwdkDux4
# Ygbg21x+U0+pXnL84AnmnHFXfKui2Vff2wI74mAK6J3g1Ytxk4VHXt17uQ5USGXG
# hzGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABiC7NxoFB4bwqAAEAAAGIMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIJDj9DOgeGyIy3dv67hc
# y3A1/xyzRZ7OD2nJycD3NCNOMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# Zune7awGN0aEgvjP7JyO3NKl7hstX8ChhrKmXtJJQKUwgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYguzcaBQeG8KgABAAABiDAiBCC4
# c3rEPQCon440gOWoVDyr8qQKRRuUpFS17S3VU/VX4DANBgkqhkiG9w0BAQsFAASC
# AgB///90kg6VvUGW/OXqcLihplB7Vw7cQ/K61GIHWmovIvAydUH8cM3ic6QCVKp2
# 28tVJDYL3dpoYfUZTsAocMKdi7lA0fcJkNVcukWERvJC53C5Qtd3YZPoKXqjnKi8
# bl9ARU0aG829KEoD8HmaPepzLrB623thUMaU8C/9XYhR8dwrncst3VVkazEYMkIt
# vlBobZB0WFmaOKJIQCbO90eUGRhZZfFB2jRoYXFs+KWv0ZAWBoLDwMqXIQgA0nxb
# vpLPiGOw9WO96nma4GThqenomH0+XCuy/fQ5Bf0RtGx+yrGBN5KunTaGvsLAxXGs
# HI0lBLHnzbUDNtc2qzL6U548t/0dphz3c63qW90g715fP23Y9e8tJv9/VjiDa0mb
# No2jVMaAZDOhvPqaYYU0yHCFsKriuzAZ/+DIEv6ll65U+L2bMS6AoXy8Yf+NDpg5
# wWYn+knmhTIr8l/0HOGUEzqUuw+nvbwzP+2vw4W6qVJvKd3+nf/SocMXKbDEiHdo
# WAUnKDjdJtz/af8uEDHH4ZzfR5mKrcDDuyzYnOh6HbWg+8aiRQfjL8iFX7hYJQVl
# swJqROArV8HkUHCKvZ7OYdgC8Q749eP5Jw1jKG48N3AhlyQlYQdX3cgvRRCmVFtL
# mLemsrJ23s/nkXpQyjYDmmeBOtkcCr0gGY8fLVVDywZHGA==
# SIG # End signature block
