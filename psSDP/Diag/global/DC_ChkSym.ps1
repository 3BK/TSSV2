#************************************************
# DC_ChkSym.ps1
# Version 1.0.1
# Date: 7/15/2019
# Author: +waltere 2019.07.15
# Description:  This file will use Checksym.exe to list all file versions on the local machine
#************************************************

PARAM($range="All", $prefix="_sym", $FolderName=$null, $FileMask=$null, $Suffix=$null, $FileDescription = $null, [switch] $Recursive, [switch] $SkipCheckSymExe)

#$ProcArc = $Env:PROCESSOR_ARCHITECTURE
$ChkSymExe = "Checksym.exe"
$IsSkipChecksymExe = ($SkipCheckSymExe.IsPresent)

if (($OSArchitecture -eq 'ARM') -and (-not($IsSkipChecksymExe))){
	'Skipping running chksym executable since it is not supported in ' + $OSArchitecture + ' architecture.' | WriteTo-StdOut
	$IsSkipChecksymExe=$true
}
if($IsSkipChecksymExe){
	"External chksym executable not be used since $ChkSymExe does not exist" | WriteTo-StdOut -ShortFormat
}

$Error.Clear() | Out-Null 

Import-LocalizedData -BindingVariable LocalsCheckSym -FileName DC_ChkSym

trap [Exception] 
{
	$errorMessage = $Error[0].Exception.Message
	$errorCode = $Error[0].Exception.ErrorRecord.FullyQualifiedErrorId
	$line = $Error[0].InvocationInfo.PositionMessage
	"[DC_ChkSym] Error " + $errorCode + " on line " + $line + ": $errorMessage running dc_chksym.ps1" | WriteTo-StdOut -ShortFormat
	$Error.Clear() | Out-Null 
}

function GetExchangeInstallFolder{
	If ((Test-Path "HKLM:SOFTWARE\Microsoft\ExchangeServer\v14") -eq $true){
		[System.IO.Path]::GetDirectoryName((get-itemproperty HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup).MsiInstallPath)
	} ElseIf ((Test-Path "HKLM:SOFTWARE\Microsoft\Exchange\v8.0") -eq $true) {
		[System.IO.Path]::GetDirectoryName((get-itemproperty HKLM:\SOFTWARE\Microsoft\Exchange\Setup).MsiInstallPath)
	} Else { 
		$null
	}
}

function GetDPMInstallFolder{
	if ((Test-Path "HKLM:SOFTWARE\Microsoft\Microsoft Data Protection Manager\Setup") -eq $true)
	{
		return [System.IO.Path]::GetDirectoryName((get-itemproperty HKLM:\SOFTWARE\Microsoft\Microsoft Data Protection Manager\Setup).InstallPath)
	}
	else
	{
		return $null
	}
}

Function FileExistOnFolder($PathToScan, $FileMask, [switch] $Recursive){
	trap [Exception] {
	
		$ErrorStd = "[FileExistOnFolder] The following error ocurred when checking if a file exists on a folder:`n" 
		$errorMessage = $Error[0].Exception.Message
		$errorCode = $Error[0].Exception.ErrorRecord.FullyQualifiedErrorId
		$line = $Error[0].InvocationInfo.PositionMessage
		"$ErrorStd Error " + $errorCode + " on line " + $line + ": $errorMessage`n   Path: $PathToScan`n   FileMask: $FileMask" | WriteTo-StdOut -ShortFormat
		 $error.Clear
		 continue
	}
	
	$AFileExist = $false
	
	if (Test-Path $PathToScan)
	{
		foreach ($mask in $FileMask) {
			if ($AFileExist -eq $false) {
				if ([System.IO.Directory]::Exists($PathToScan)) {
					if ($Recursive.IsPresent)
					{
						$Files = [System.IO.Directory]::GetFiles($PathToScan, $mask,[System.IO.SearchOption]::AllDirectories)
					} else {
						$Files = [System.IO.Directory]::GetFiles($PathToScan, $mask,[System.IO.SearchOption]::TopDirectoryOnly)
					}
					$AFileExist = ($Files.Count -ne 0)
				}
			}
		}
	}
	return $AFileExist
}

Function GetAllRunningDriverFilePath([string] $DriverName){
	$driversPath = "HKLM:System\currentcontrolset\services\"+$DriverName
	if(Test-Path $driversPath){
		$ImagePath = (Get-ItemProperty ("HKLM:System\currentcontrolset\services\"+$DriverName)).ImagePath
	}
	if($null -eq $ImagePath){
		$driversPath = "system32\drivers\"+$DriverName+".sys"
		$ImagePath = join-path $env:windir $driversPath
		if(-not(Test-Path $ImagePath))
		{
			$Driver.Name + "not exist in the system32\drivers\"| WriteTo-StdOut -ShortFormat
		}
	}
	else{
		if($ImagePath.StartsWith("\SystemRoot\")){
			$ImagePath = $ImagePath.Remove(0,12)
		}
		elseif($ImagePath.StartsWith("\??\")){
			$ImagePath = $ImagePath.Remove(0,14)
		}
		$ImagePath = join-path $env:windir $ImagePath	
	}
	return $ImagePath
}

Function PrintTXTCheckSymInfo([PSObject]$OutPut, $StringBuilder, [switch]$S, [switch]$R){	
	if($null -ne $OutPut.Processes)
	{
		[void]$StringBuilder.Append("*******************************************************************************`r`n")
		[void]$StringBuilder.Append("[PROCESSES] - Printing Process Information for "+$OutPut.Processes.Count +" Processes.`r`n")
		[void]$StringBuilder.Append("[PROCESSES] - Context: System Process(es)`r`n")
		[void]$StringBuilder.Append("*******************************************************************************`r`n")
		
		Foreach($Process in $OutPut.Processes)
		{
			$Index = 1
			[void]$StringBuilder.Append("-----------------------------------------------------------`r`n")
			[void]$StringBuilder.Append("Process Name ["+$Process.ProcessName.ToUpper()+".EXE] - PID="+$Process.Id +" - "+ $Process.Modules.Count +" modules recorded`r`n")
			[void]$StringBuilder.Append("-----------------------------------------------------------`r`n")
			foreach($mod in $Process.Modules)
			{
				if($null -ne $mod.FileName)
				{
					[void]$StringBuilder.Append("Module[  "+$Index+"] [" + $mod.FileName+"]`r`n")
					if($R.IsPresent)
					{
						$FileItem = Get-ItemProperty $mod.FileName
						[void]$StringBuilder.Append("  Company Name:      " + $FileItem.VersionInfo.CompanyName	+"`r`n")
						[void]$StringBuilder.Append("  File Description:  " + $FileItem.VersionInfo.FileDescription +"`r`n")
						[void]$StringBuilder.Append("  Product Version:   " + $FileItem.VersionInfo.ProductVersion+"`r`n")
						[void]$StringBuilder.Append("  File Version:      " + $FileItem.VersionInfo.FileVersion+"`r`n")
						[void]$StringBuilder.Append("  File Size (bytes): " + $FileItem.Length+"`r`n")
						[void]$StringBuilder.Append("  File Date:         " + $FileItem.LastWriteTime+"`r`n")
					
					}	
				
					if($S.IsPresent)
					{
						
					}
					[void]$StringBuilder.Append("`r`n")
					$Index+=1
				}
			}	
		}
	}
	
	if($null -ne $OutPut.Drivers)
	{		
		[void]$StringBuilder.Append("*******************************************************************************`r`n")
		[void]$StringBuilder.Append( "[KERNEL-MODE DRIVERS] - Printing Module Information for "+$OutPut.Drivers.Count +" Modules.`r`n")
		[void]$StringBuilder.Append( "[KERNEL-MODE DRIVERS] - Context: Kernel-Mode Driver(s)`r`n")
		[void]$StringBuilder.Append( "*******************************************************************************`r`n")
		$Index = 1
		Foreach($Driver in $OutPut.Drivers)
		{		
			$DriverFilePath = GetAllRunningDriverFilePath $Driver.Name	
			[void]$StringBuilder.Append("Module[  "+$Index+"] [" + $DriverFilePath+"]`r`n")
						
			if($R.IsPresent)
			{
				$FileItem = Get-ItemProperty $DriverFilePath
				if(($null -ne $FileItem.VersionInfo.CompanyName) -and ($FileItem.VersionInfo.CompanyName -ne ""))
				{
					[void]$StringBuilder.Append("  Company Name:      " + $FileItem.VersionInfo.CompanyName	+"`r`n")
				}
				
				if(($null -ne $FileItem.VersionInfo.FileDescription) -and ($FileItem.VersionInfo.FileDescription.trim() -ne ""))
				{
					[void]$StringBuilder.Append("  File Description:  " + $FileItem.VersionInfo.FileDescription +"`r`n")
				}
				
				if(($null -ne $FileItem.VersionInfo.ProductVersion) -and ($FileItem.VersionInfo.ProductVersion -ne ""))
				{
					[void]$StringBuilder.Append("  Product Version:   " + $FileItem.VersionInfo.ProductVersion+"`r`n")
				}
				
				if(($null -ne $FileItem.VersionInfo.FileVersion) -and ($FileItem.VersionInfo.FileVersion -ne ""))
				{
					[void]$StringBuilder.Append("  File Version:      " + $FileItem.VersionInfo.FileVersion+"`r`n"	)
				}
				[void]$StringBuilder.Append("  File Size (bytes): " + $FileItem.Length+"`r`n")
				[void]$StringBuilder.Append("  File Date:         " + $FileItem.LastWriteTime+"`r`n")
			}
			
			if($S.IsPresent)
			{

			}
			
			[void]$StringBuilder.Append("`r`n")
			$Index+=1
		}
	}
	
	if($null -ne $OutPut.Files)
	{
		[void]$StringBuilder.Append("*******************************************************************************`r`n")
		[void]$StringBuilder.Append("[FILESYSTEM MODULES] - Printing Module Information for "+$OutPut.Files.Count +" Modules.`r`n")
		[void]$StringBuilder.Append("[FILESYSTEM MODULES] - Context: Filesystem Modules`r`n")
		[void]$StringBuilder.Append("*******************************************************************************`r`n")
		$Index = 1
		Foreach($File in $OutPut.Files)
		{
			[void]$StringBuilder.Append("Module[  "+$Index+"] [" + $File+"]`r`n")
			if($R.IsPresent)
			{	
				$FileItem = Get-ItemProperty $File
				if(($null -ne $FileItem.VersionInfo.CompanyName) -and ($FileItem.VersionInfo.CompanyName -ne ""))
				{
					[void]$StringBuilder.Append("  Company Name:      " + $FileItem.VersionInfo.CompanyName	+"`r`n")
				}
				
				if(($null -ne $FileItem.VersionInfo.FileDescription) -and ($FileItem.VersionInfo.FileDescription.trim() -ne ""))
				{
					[void]$StringBuilder.Append("  File Description:  " + $FileItem.VersionInfo.FileDescription +"`r`n")
				}
				
				if(($null -ne $FileItem.VersionInfo.ProductVersion) -and ($FileItem.VersionInfo.ProductVersion -ne ""))
				{
					[void]$StringBuilder.Append("  Product Version:   " + $FileItem.VersionInfo.ProductVersion+"`r`n")
				}
				
				if(($null -ne $FileItem.VersionInfo.FileVersion) -and ($FileItem.VersionInfo.FileVersion -ne ""))
				{
					[void]$StringBuilder.Append("  File Version:      " + $FileItem.VersionInfo.FileVersion+"`r`n"	)
				}
				[void]$StringBuilder.Append("  File Size (bytes): " + $FileItem.Length+"`r`n")
				[void]$StringBuilder.Append("  File Date:         " + $FileItem.LastWriteTime+"`r`n")	
			}	
				
			if($S.IsPresent)
			{
						
			}
			[void]$StringBuilder.Append("`r`n")
			$Index+=1
		}			
	}
}

Function PrintCSVCheckSymInfo([PSObject]$OutPut, $StringBuilder, [switch]$S, [switch]$R){
	[void]$StringBuilder.Append("Create:,"+[DateTime]::Now+"`r`n")
	[void]$StringBuilder.Append("Computer:,"+ $ComputerName+"`r`n`r`n")

	if($null -ne $OutPut.Processes)
	{	
		[void]$StringBuilder.Append("[PROCESSES]`r`n")
		[void]$StringBuilder.Append(",Process Name,Process ID,Module Path,Symbol Status,Checksum,Time/Date Stamp,Time/Date String,Size Of Image,DBG Pointer,PDB Pointer,PDB Signature,PDB Age,Product Version,File Version,Company Name,File Description,File Size,File Time/Date Stamp (High),File Time/Date Stamp (Low),File Time/Date String,Local DBG Status,Local DBG,Local PDB Status,Local PDB`r`n")
		Foreach($Process in $OutPut.Processes)
		{
			if($null -ne $Process.Modules)
			{
				foreach($mod in $Process.Modules)
				{						
					if($null -ne $mod.FileName)
					{
						[void]$StringBuilder.Append("," +$Process.Name+".EXE,"+$Process.Id+",")
						[void]$StringBuilder.Append( $mod.FileName+",")
						if($S.IsPresent)
						{
							[void]$StringBuilder.Append("SYMBOLS_PDB,,,,,,,,,")
						}
						else
						{
							[void]$StringBuilder.Append("SYMBOLS_No,,,,,,,,,")
						}
						
						if($R.IsPresent)
						{
							$FileItem = Get-ItemProperty $mod.FileName
							[void]$StringBuilder.Append( "("+$FileItem.VersionInfo.ProductVersion.Replace(",",".")+"	),("+$FileItem.VersionInfo.FileVersion.Replace(",",".")+"	),"+$FileItem.VersionInfo.CompanyName.Replace(",",".")+","+$FileItem.VersionInfo.FileDescription.Replace(",",".")+","+$FileItem.Length+",,,"+$FileItem.LastWriteTime+",,,,,`r`n")
						}
						else
						{
							[void]$StringBuilder.Append( ",,,,,,,,,,,,`r`n")
						}
					}
				}
			}	
		}
	}
	
	if($null -ne $OutPut.Drivers)
	{
		[void]$StringBuilder.Append("[KERNEL-MODE DRIVERS]`r`n")
		[void]$StringBuilder.Append(",,,Module Path,Symbol Status,Checksum,Time/Date Stamp,Time/Date String,Size Of Image,DBG Pointer,PDB Pointer,PDB Signature,PDB Age,Product Version,File Version,Company Name,File Description,File Size,File Time/Date Stamp (High),File Time/Date Stamp (Low),File Time/Date String,Local DBG Status,Local DBG,Local PDB Status,Local PDB`r`n")
		Foreach($Driver in $OutPut.Drivers)
		{		
			$DriverFilePath = GetAllRunningDriverFilePath $Driver.Name	
			[void]$StringBuilder.Append(",,," +$DriverFilePath+",")
			if($S.IsPresent)
			{
				[void]$StringBuilder.Append("SYMBOLS_PDB,,,,,,,,,")
			}
			else
			{
				[void]$StringBuilder.Append("SYMBOLS_NO,,,,,,,,,")
			}
						
			if($R.IsPresent)
			{
				$DriverItem = Get-ItemProperty $DriverFilePath
				if($null -ne $DriverItem.VersionInfo.ProductVersion)
				{
					[void]$StringBuilder.Append("("+$DriverItem.VersionInfo.ProductVersion.Replace(",",".")+"),("+$DriverItem.VersionInfo.FileVersion.Replace(",",".")+"),"+$DriverItem.VersionInfo.CompanyName.Replace(",",".")+","+$DriverItem.VersionInfo.FileDescription.Replace(",",".")+","+$DriverItem.Length+",,,"+$DriverItem.LastWriteTime+",,,,,`r`n")
				}
				else
				{
					[void]$StringBuilder.Append(",,,,"+$DriverItem.Length+",,,"+$DriverItem.LastWriteTime+",,,,,`r`n")
				}
			}
			else
			{
				[void]$StringBuilder.Append(",,,,,,,,,,,,`r`n")
			}	
		}
	}
	
	if($null -ne $OutPut.Files)
	{	
		[void]$StringBuilder.Append("[FILESYSTEM MODULES]`r`n")
		[void]$StringBuilder.Append(",,,Module Path,Symbol Status,Checksum,Time/Date Stamp,Time/Date String,Size Of Image,DBG Pointer,PDB Pointer,PDB Signature,PDB Age,Product Version,File Version,Company Name,File Description,File Size,File Time/Date Stamp (High),File Time/Date Stamp (Low),File Time/Date String,Local DBG Status,Local DBG,Local PDB Status,Local PDB`r`n")
		Foreach($File in $OutPut.Files)
		{						
			[void]$StringBuilder.Append(",,," +$File+",")
			if($S.IsPresent)
			{
				[void]$StringBuilder.Append("SYMBOLS_PDB,,,,,,,,,")
			}
			else
			{
				[void]$StringBuilder.Append("SYMBOLS_NO,,,,,,,,,")
			}
						
			if($R.IsPresent)
			{
				$FileItem = Get-ItemProperty $File
				if($null -ne $FileItem.VersionInfo.ProductVersion)
				{
					[void]$StringBuilder.Append("("+$FileItem.VersionInfo.ProductVersion.Replace(",",".")+"	),("+$FileItem.VersionInfo.FileVersion.Replace(",",".")+"	),"+$FileItem.VersionInfo.CompanyName.Replace(",",".")+","+$FileItem.VersionInfo.FileDescription.Replace(",",".")+","+$FileItem.Length+",,,"+$FileItem.LastWriteTime+",,,,,`r`n")
				}
				else
				{
					[void]$StringBuilder.Append(",,,,"+$FileItem.Length+",,,"+$FileItem.LastWriteTime+",,,,,`r`n")
				}
			}
			else
			{
				[void]$StringBuilder.Append(",,,,,,,,,,,,`r`n")
			}	
		}
	}
}

Function PSChkSym ([string]$PathToScan="", [array]$FileMask = "*.*", [string]$O2="", [String]$P ="", [switch]$D, [switch]$F, [switch]$F2, [switch]$S, [switch]$R){
	#check the system information
	# P ---- get the process information, can give a * get all process info or give a process name get the specific process
	# D ---- get the all local running drivers infor
	# F ---- search the top level folder to get the files
	# F2 ---- search the all level from folder, Recursive
	# S ---- get Symbol Information
	# R ---- get the Version and File-System Information
	# O2 ---- Out the result to the file
	trap [Exception] {
	
		$ErrorStd = "[PSChkSym] The following error ocurred when getting the file from a folder:`n" 
		$errorMessage = $Error[0].Exception.Message
		$errorCode = $Error[0].Exception.ErrorRecord.FullyQualifiedErrorId
		$line = $Error[0].InvocationInfo.PositionMessage
		"$ErrorStd Error " + $errorCode + " on line " + $line + ": $errorMessage`n   Path: $PathToScan`n   FileMask: $FileMask" | WriteTo-StdOut -ShortFormat
		 $error.Clear
		 continue
	}	

	$OutPutObject = New-Object PSObject
	$SbCSVFormat = New-Object -TypeName System.Text.StringBuilder
	$SbTXTFormat = New-Object -TypeName System.Text.StringBuilder
	[void]$SbTXTFormat.Append("***** COLLECTION OPTIONS *****`r`n")
	
	if($P -ne "")
	{
		[void]$SbTXTFormat.Append("Collect Information From Running Processes`r`n")
		if($P -eq "*")
		{
			[void]$SbTXTFormat.Append("    -P *     (Query all local processes) `r`n")
			
			$Processes = [System.Diagnostics.Process]::GetProcesses()
		}
		else
		{
			[void]$SbTXTFormat.Append("    -P $P     (Query for specific process by name) `r`n" )
			
			$Processes = [System.Diagnostics.Process]::GetProcessesByName($P)
		}
	}
	
	if($D.IsPresent)
	{
		[void]$SbTXTFormat.Append("    -D     (Query all local device drivers) `r`n")
		Add-Type -assemblyname System.ServiceProcess
		$DeviceDrivers = [System.ServiceProcess.ServiceController]::GetDevices() | where-object {$_.Status -eq "Running"}
		#$DeviceDrivers = GetAllRunningDriverFileName
	}
	
	if($F.IsPresent -or $F2.IsPresent)
	{
		[void]$SbTXTFormat.Append("Collect Information From File(s) Specified by the User`r`n")
		[void]$SbTXTFormat.Append("   -F $PathToScan\$FileMask`r`n")
		if($F.IsPresent) 
		{
			Foreach($Mask in $FileMask)
			{
				$Files += [System.IO.Directory]::GetFiles($PathToScan, $Mask,[System.IO.SearchOption]::TopDirectoryOnly)
			}
		}
		else
		{
			Foreach($Mask in $FileMask)
			{
				$Files += [System.IO.Directory]::GetFiles($PathToScan, $Mask,[System.IO.SearchOption]::AllDirectories)
			}
		}
	}
	
	[void]$SbTXTFormat.Append("***** INFORMATION CHECKING OPTIONS *****`r`n")
	if($S.IsPresent -or $R.IsPresent)
	{
		if($S.IsPresent)
		{
			
			[void]$SbTXTFormat.Append("Output Symbol Information From Modules`r`n")
			[void]$SbTXTFormat.Append("   -S `r`n")
		}
		
		if($R.IsPresent)
		{
			[void]$SbTXTFormat.Append("Collect Version and File-System Information From Modules`r`n")
			[void]$SbTXTFormat.Append("   -R `r`n")
		}
	}
	else
	{
		[void]$SbTXTFormat.Append("Output Symbol Information From Modules`r`n")
		[void]$SbTXTFormat.Append("   -S `r`n")
		[void]$SbTXTFormat.Append("Collect Version and File-System Information From Modules`r`n")
		[void]$SbTXTFormat.Append("   -R `r`n")
	}
	
	[void]$SbTXTFormat.Append("***** OUTPUT OPTIONS *****`r`n")
	[void]$SbTXTFormat.Append("Output Results to STDOUT`r`n")
	[void]$SbTXTFormat.Append("Output Collected Module Information To a CSV File`r`n")
	
	if($O2 -ne "")
	{
		$OutFiles = $O2.Split('>')
		[void]$SbTXTFormat.Append("   -O "+$OutFiles[0]+" `r`n")
	}
	
	add-member -inputobject $OutPutObject -membertype noteproperty -name "Processes" -value $Processes
	add-member -inputobject $OutPutObject -membertype noteproperty -name "Drivers" -value $DeviceDrivers
	add-member -inputobject $OutPutObject -membertype noteproperty -name "Files" -value $Files
	
	if(($S.IsPresent -and $R.IsPresent) -or (-not$S.IsPresent -and -not$R.IsPresent))
	{
		PrintTXTCheckSymInfo -OutPut $OutPutObject $SbTXTFormat -S -R
		PrintCSVCheckSymInfo -OutPut $OutPutObject $SbCSVFormat -S -R
	}
	elseif($S.IsPresent -and -not$R.IsPresent)
	{
		PrintTXTCheckSymInfo -OutPut $OutPutObject $SbTXTFormat -S
		PrintCSVCheckSymInfo -OutPut $OutPutObject $SbCSVFormat -S
	}
	else
	{
		PrintTXTCheckSymInfo -OutPut $OutPutObject $SbTXTFormat -R
		PrintCSVCheckSymInfo -OutPut $OutPutObject $SbCSVFormat -R
	}	
	
	foreach($out in $OutFiles)
	{
		if($out.EndsWith("CSV",[StringComparison]::InvariantCultureIgnoreCase))
		{
			$SbCSVFormat.ToString() | Out-File $out -Encoding "utf8"
		}
		else
		{
			if(Test-Path $out)
			{
				$SbTXTFormat.ToString() | Out-File $out -Encoding "UTF8" -Append
			}
			else
			{
				$SbTXTFormat.ToString() | Out-File $out -Encoding "UTF8"
			}
		}
	}
}

Function RunChkSym ([string]$PathToScan="", [array]$FileMask = "*.*", [string]$Output="", [boolean]$Recursive=$false, [string]$Arguments="", [string]$Description="", [boolean]$SkipChksymExe=$false){
	if (($Arguments -ne "") -or (Test-Path ($PathToScan))) 
	{
		if ($PathToScan -ne "")
		{
			$eOutput = $Output
			ForEach ($scFileMask in $FileMask){ #
				$eFileMask = ($scFileMask.replace("*.*","")).toupper()
				$eFileMask = ($eFileMask.replace("*.",""))
				$eFileMask = ($eFileMask.replace(".*",""))
				if (($eFileMask -ne "") -and (Test-Path ("$eOutput.*") )) {$eOutput += ("_" + $eFileMask)}
				$symScanPath += ((Join-Path -Path $PathToScan -ChildPath $scFileMask) + ";")
			}
		}
		
		if ($Description -ne "") 
		{
			$FileDescription = $Description
		} else {
			$fdFileMask = [string]::join(";",$FileMask)
			if ($fdFileMask -contains ";") { 
				$FileDescription = $PathToScan + " [" + $fdFileMask + "]"
			} else {
				$FileDescription = (Join-Path $PathToScan $fdFileMask)
			}
		}
	

		if ($Arguments -ne "") 
		{
			$eOutput = $Output
			Write-DiagProgress -Activity $LocalsCheckSym.ID_FileVersionInfo -Status $Description
			if(-not($SkipChksymExe))
			{
				$CommandToExecute = "cmd.exe /c $ChkSymExe $Arguments"
			}
			else
			{
				#calling the method to implement the functionalities
				$Arguments = $Arguments.Substring(0,$Arguments.IndexOf("-O2")+4) +"$Output.CSV>$Output.TXT"
				invoke-expression "PSChkSym  $Arguments"
			}
		}
		else {
			Write-DiagProgress -Activity $LocalsCheckSym.ID_FileVersionInfo -Status ($FileDescription)# + " Recursive: " + $Recursive)
			if ($Recursive -eq $true) {
				$F = "-F2"
				$AFileExistOnFolder = (FileExistOnFolder -PathToScan $PathToScan -FileMask $scFileMask -Recursive) 
			} else {
				$F = "-F"
				$AFileExistOnFolder = (FileExistOnFolder -PathToScan $PathToScan -FileMask $scFileMask)
				
			}
			if ($AFileExistOnFolder) 
			{
				if(-not($SkipChksymExe))
				{
					$CommandToExecute = "cmd.exe /c $ChkSymExe $F `"$symScanPath`" -R -S -O2 `"$eOutput.CSV`" > `"$eOutput.TXT`""
				}
				else
				{
					#calling the method to implement the functionalities
					if($F -eq "-F2")
					{
						PSChkSym -PathToScan $PathToScan -FileMask $FileMask -F2 -S -R -O2 "$eOutput.CSV>$eOutput.TXT"
					}
					else
					{
						PSChkSym -PathToScan $PathToScan -FileMask $FileMask -F -S -R -O2 "$eOutput.CSV>$eOutput.TXT"
					}
				}
			} 
			else 
			{
				"Chksym did not run against path '$PathToScan' since there are no files with mask ($scFileMask) on system" | WriteTo-StdOut -ShortFormat
				$CommandToExecute = ""
			}
		}
		if ($CommandToExecute -ne "") {
			RunCmD -commandToRun $CommandToExecute -sectionDescription "File Version Information (ChkSym)" -filesToCollect ("$eOutput.*") -fileDescription $FileDescription -BackgroundExecution
		}
	}
	else {
		"Chksym did not run against path '$PathToScan' since path does not exist" | WriteTo-StdOut -ShortFormat
	}
}

### Main ###
#Check if using $FolderName or $RangeString
if (($null -ne $FolderName) -and ($null -ne $FileMask) -and ($null -ne $Suffix)) {
	$OutputBase = $ComputerName + $Prefix + $Suffix
	$IsRecursive = ($Recursive.IsPresent)
	RunChkSym -PathToScan $FolderName -FileMask $FileMask -Output $OutputBase  -Description $FileDescription -Recursive $IsRecursive -CallChksymExe $IsSkipChecksymExe
} else {
	[array] $RunChkSym = $null
	Foreach ($RangeString in $range) 
	{
		if ($RangeString -eq "All")	
		{
			$RunChkSym += "ProgramFilesSys", "Drivers", "System32DLL", "System32Exe", "System32SYS", "Spool", "iSCSI", "Process", "RunningDrivers", "Cluster"
		} else {
			$RunChkSym += $RangeString
		}
	}

	switch ($RunChkSym)	{
		"ProgramFilesSys" {
			$OutputBase="$ComputerName$Prefix" + "_ProgramFiles_SYS"
			RunChkSym -PathToScan "$Env:ProgramFiles" -FileMask "*.sys" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			if (($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") -or $Env:PROCESSOR_ARCHITECTURE -eq "IA64")  {
				$OutputBase="$ComputerName$Prefix" + "_ProgramFilesx86_SYS"
				RunChkSym -PathToScan (${Env:ProgramFiles(x86)}) -FileMask "*.sys" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
			}
		"Drivers" {
			$OutputBase="$ComputerName$Prefix" + "_Drivers"
			RunChkSym -PathToScan "$Env:SystemRoot\System32\drivers" -FileMask "*.*" -Output $OutputBase -Recursive $false -SkipChksymExe $IsSkipChecksymExe
			}
		"System32DLL" {
			$OutputBase="$ComputerName$Prefix" + "_System32_DLL"
			RunChkSym -PathToScan "$Env:SystemRoot\System32" -FileMask "*.DLL" -Output $OutputBase -Recursive $false -SkipChksymExe $IsSkipChecksymExe
			if (($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") -or $Env:PROCESSOR_ARCHITECTURE -eq "IA64")  {
				$OutputBase="$ComputerName$Prefix" + "_SysWOW64_DLL"
				RunChkSym -PathToScan "$Env:SystemRoot\SysWOW64" -FileMask "*.dll" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
			}
		"System32Exe" {
			$OutputBase="$ComputerName$Prefix" + "_System32_EXE"
			RunChkSym -PathToScan "$Env:SystemRoot\System32" -FileMask "*.EXE" -Output $OutputBase -Recursive $false -SkipChksymExe $IsSkipChecksymExe
			if (($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") -or $Env:PROCESSOR_ARCHITECTURE -eq "IA64")  {
				$OutputBase="$ComputerName$Prefix" + "_SysWOW64_EXE"
				RunChkSym -PathToScan "$Env:SystemRoot\SysWOW64" -FileMask "*.exe" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
			}
		"System32SYS" {
			$OutputBase="$ComputerName$Prefix" + "_System32_SYS"
			RunChkSym -PathToScan "$Env:SystemRoot\System32" -FileMask "*.SYS" -Output $OutputBase -Recursive $false -SkipChksymExe $IsSkipChecksymExe
			if (($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") -or $Env:PROCESSOR_ARCHITECTURE -eq "IA64")  {
				$OutputBase="$ComputerName$Prefix" + "_SysWOW64_SYS"
				RunChkSym -PathToScan "$Env:SystemRoot\SysWOW64" -FileMask "*.sys" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
			}
		"Spool" {
			$OutputBase="$ComputerName$Prefix" + "_PrintSpool"
			RunChkSym -PathToScan "$Env:SystemRoot\System32\Spool" -FileMask "*.*" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
		"Cluster" {
			$OutputBase="$ComputerName$Prefix" + "_Cluster"
			RunChkSym -PathToScan "$Env:SystemRoot\Cluster" -FileMask "*.*" -Output $OutputBase -Recursive $false -SkipChksymExe $IsSkipChecksymExe
			}
		"iSCSI" {
			if(Test-Path "$Env:ProgramFiles\Microsoft iSNS Server" ) {
				$OutputBase="$ComputerName$Prefix" + "_MS_iSNS"
				RunChkSym -PathToScan "$Env:ProgramFiles\Microsoft iSNS Server" -FileMask "*.*" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
			$OutputBase="$ComputerName$Prefix" + "_MS_iSCSI"
			RunChkSym -PathToScan "$Env:SystemRoot\System32" -FileMask "iscsi*.*" -Output $OutputBase -Recursive $false -SkipChksymExe $IsSkipChecksymExe
			}
		"Process" {
			$OutputBase="$ComputerName$Prefix" + "_Process"
#we#		Get-Process |                                             Format-Table -Property "Handles","NPM","PM","WS","VM","CPU","Id","ProcessName","StartTime",@{ Label = "Running Time";Expression={(GetAgeDescription -TimeSpan (new-TimeSpan $_.StartTime))}} -AutoSize | Out-File "$OutputBase.txt" -Encoding "UTF8" -Width 200
			Get-Process | where-object  {$_.ProcessName -ne "idle"} | Format-Table -Property "Handles","NPM","PM","WS","VM","CPU","Id","ProcessName","StartTime",@{ Label = "Running Time";Expression={(GetAgeDescription -TimeSpan (new-TimeSpan $($_).StartTime))}} -AutoSize | Out-File "$OutputBase.txt" -Encoding "UTF8" -Width 200

			"--------------------------------" | Out-File "$OutputBase.txt" -Encoding "UTF8" -append
			tasklist -svc | Out-File "$OutputBase.txt" -Encoding "UTF8" -append -EA SilentlyContinue
			"--------------------------------" | Out-File "$OutputBase.txt" -Encoding "UTF8" -append
			RunChkSym -Output $OutputBase -Arguments "-P * -R -O2 `"$OutputBase.CSV`" >> `"$OutputBase.TXT`"" -Description "Running Processes" -SkipChksymExe $IsSkipChecksymExe
			}
		"RunningDrivers" {
			$OutputBase="$ComputerName$Prefix" + "_RunningDrivers"
			RunChkSym -Output $OutputBase -Arguments "-D -R -S -O2 `"$OutputBase.CSV`" > `"$OutputBase.TXT`"" -Description "Running Drivers" -SkipChksymExe $IsSkipChecksymExe
			}
		"InetSrv" {
			$inetSrvPath = (join-path $env:systemroot "system32\inetsrv")
			$OutputBase = "$ComputerName$Prefix" + "_InetSrv"
			RunChkSym -PathToScan $inetSrvPath -FileMask ("*.exe","*.dll") -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
		"Exchange" {
			$ExchangeFolder = GetExchangeInstallFolder
			if ($null -ne $ExchangeFolder){
				$OutputBase = "$ComputerName$Prefix" + "_Exchange"
				RunChkSym -PathToScan $ExchangeFolder -FileMask ("*.exe","*.dll") -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			} else {
				"Chksym did not run against Exchange since it could not find Exchange server installation folder" | WriteTo-StdOut -ShortFormat
			}
		}
		"DPM" {
			$DPMFolder = GetDPMInstallFolder
			If ($null -ne $DPMFolder)
			{
				$DPMFolder = Join-Path $DPMFolder "bin"
				$OutputBase= "$ComputerName$Prefix" + "_DPM"
				RunChkSym -PathToScan $DPMFolder -FileMask("*.exe","*.dll") -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			} else {
				"Chksym did not run against DPM since it could not find the DPM installation folder" | WriteTo-StdOut -ShortFormat
			}
		}
		"WinSxsDLL" {
			$OutputBase="$ComputerName$Prefix" + "_WinSxS_DLL"
			RunChkSym -PathToScan "$Env:SystemRoot\WinSxS" -FileMask "*.DLL" -Output $OutputBase -Recursive $True -SkipChksymExe $IsSkipChecksymExe
			}
		"WinSxsEXE" {
			$OutputBase="$ComputerName$Prefix" + "_WinSxS_EXE"
			RunChkSym -PathToScan "$Env:SystemRoot\WinSxS" -FileMask "*.EXE" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
		"WinSxsSYS" {
			$OutputBase="$ComputerName$Prefix" + "_WinSxS_SYS"
			RunChkSym -PathToScan "$Env:SystemRoot\WinSxS" -FileMask "*.SYS" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
		"RefAssmDLL" {
			$OutputBase="$ComputerName$Prefix" + "_RefAssm_DLL"
			RunChkSym -PathToScan "$Env:programfiles\Reference Assemblies" -FileMask "*.DLL" -Output $OutputBase -Recursive $true -SkipChksymExe $IsSkipChecksymExe
			}
		"DotNETDLL" {
			$OutputBase="$ComputerName$Prefix" + "_DotNET_DLL"
			RunChkSym -PathToScan "$Env:SystemRoot\Microsoft.NET" -FileMask "*.DLL" -Output $OutputBase -Recursive $True -SkipChksymExe $IsSkipChecksymExe
			}
	}
}



# SIG # Begin signature block
# MIInrAYJKoZIhvcNAQcCoIInnTCCJ5kCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBnqRuaN1udH4YX
# UUPy1coK5+8OzorouuW8Fq2V7uMtaaCCDYEwggX/MIID56ADAgECAhMzAAACzI61
# lqa90clOAAAAAALMMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NjAxWhcNMjMwNTExMjA0NjAxWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCiTbHs68bADvNud97NzcdP0zh0mRr4VpDv68KobjQFybVAuVgiINf9aG2zQtWK
# No6+2X2Ix65KGcBXuZyEi0oBUAAGnIe5O5q/Y0Ij0WwDyMWaVad2Te4r1Eic3HWH
# UfiiNjF0ETHKg3qa7DCyUqwsR9q5SaXuHlYCwM+m59Nl3jKnYnKLLfzhl13wImV9
# DF8N76ANkRyK6BYoc9I6hHF2MCTQYWbQ4fXgzKhgzj4zeabWgfu+ZJCiFLkogvc0
# RVb0x3DtyxMbl/3e45Eu+sn/x6EVwbJZVvtQYcmdGF1yAYht+JnNmWwAxL8MgHMz
# xEcoY1Q1JtstiY3+u3ulGMvhAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUiLhHjTKWzIqVIp+sM2rOHH11rfQw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDcwNTI5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAeA8D
# sOAHS53MTIHYu8bbXrO6yQtRD6JfyMWeXaLu3Nc8PDnFc1efYq/F3MGx/aiwNbcs
# J2MU7BKNWTP5JQVBA2GNIeR3mScXqnOsv1XqXPvZeISDVWLaBQzceItdIwgo6B13
# vxlkkSYMvB0Dr3Yw7/W9U4Wk5K/RDOnIGvmKqKi3AwyxlV1mpefy729FKaWT7edB
# d3I4+hldMY8sdfDPjWRtJzjMjXZs41OUOwtHccPazjjC7KndzvZHx/0VWL8n0NT/
# 404vftnXKifMZkS4p2sB3oK+6kCcsyWsgS/3eYGw1Fe4MOnin1RhgrW1rHPODJTG
# AUOmW4wc3Q6KKr2zve7sMDZe9tfylonPwhk971rX8qGw6LkrGFv31IJeJSe/aUbG
# dUDPkbrABbVvPElgoj5eP3REqx5jdfkQw7tOdWkhn0jDUh2uQen9Atj3RkJyHuR0
# GUsJVMWFJdkIO/gFwzoOGlHNsmxvpANV86/1qgb1oZXdrURpzJp53MsDaBY/pxOc
# J0Cvg6uWs3kQWgKk5aBzvsX95BzdItHTpVMtVPW4q41XEvbFmUP1n6oL5rdNdrTM
# j/HXMRk1KCksax1Vxo3qv+13cCsZAaQNaIAvt5LvkshZkDZIP//0Hnq7NnWeYR3z
# 4oFiw9N2n3bb9baQWuWPswG0Dq9YT9kb+Cs4qIIwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZgTCCGX0CAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBsDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgd5VF35M5
# ZcgEKmUnYobbYg7dIhlEG9bszZ39eqN62A4wRAYKKwYBBAGCNwIBDDE2MDSgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20g
# MA0GCSqGSIb3DQEBAQUABIIBAA0MHXi9ikM9brfTYVWNrtkS2tCVxAiirAWBh4Xd
# XQG3oaAndqINYN4zSKn73cB0B8nhzcgtq9vmJnsA9O+lbt42JGI6k/TeYbkMHYo9
# 3XCyF1m3T0B5OYHXLbtQw17ePS+Ruo9DohrtdbyoL5Vk9O/IfH9XXCseO+/soXzr
# 9QPlvz2hPRKhSTWBIQBK3AjgGYFegYCCP6FMi3izTPFBDbEGKpF6nlpWwpgRJ5kK
# xFEW2gaAKzToZkkDnAP5ce4vTAP3T7BWO6CcSqi7jIjP7gH/qanclQEwx9A80Uel
# LSMXGPB/Pii+yuzQrM1DWlWWwpRLSeFALrxN5k68UOgNNeehghcJMIIXBQYKKwYB
# BAGCNwMDATGCFvUwghbxBgkqhkiG9w0BBwKgghbiMIIW3gIBAzEPMA0GCWCGSAFl
# AwQCAQUAMIIBVQYLKoZIhvcNAQkQAQSgggFEBIIBQDCCATwCAQEGCisGAQQBhFkK
# AwEwMTANBglghkgBZQMEAgEFAAQg3MvT/Nx1L1Jy3pkGAttevp6+65NVdV1iWSSu
# 7WecltQCBmNO64bD/xgTMjAyMjEwMjQwODE1MDUuMTA2WjAEgAIB9KCB1KSB0TCB
# zjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMg
# TWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxl
# cyBUU1MgRVNOOkQ5REUtRTM5QS00M0ZFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloIIRXDCCBxAwggT4oAMCAQICEzMAAAGsZryHIl3ePXsA
# AQAAAawwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwHhcNMjIwMzAyMTg1MTI5WhcNMjMwNTExMTg1MTI5WjCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQ5
# REUtRTM5QS00M0ZFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAx3gLUMUXYu7Hccwr
# wASUx1MXiIb1E7IpBYV6FNd74RfVA6tMEWeEwAo0chBajGQrVbrb+hBBCa0gejyy
# mEy3VamQs28Kbctryx1Uve38EDHtRaSZ++6MncoNpKC3dyVzm409SPt7fZTif8Sn
# 2g5z4+/8QdztcYfV8ZG8tFjPCjE/XGQqV66xsjNP9oqfpYLYGCA/OMdeKf0oTuSu
# IK6oD4k2GySR51MclAii1uVH6tlyx7FNKaM75ntHSZ94eJTwOe29m9n/1p31dSEP
# BQkUpnxlm/GeqdlfAViQMo1qBjyDToEXW8O6VuUCzoDiG4/V7um0oWmkHVVmQtQC
# YhbXHEkazeR6J0BNYhXHbawZXJ6ZpPb01+0On+NGwPD9qHC/U2S/pa/KSi8rSQM8
# hj1MJb1xFu9R4SWT74JUztwiquXxBjeaARDyiLjlXMQFe5jThjUqKNsYthEU1TKl
# cxEMClX6RyMby5JPXeZIJ/aIyFZFEvP3+PIjB7uWZfPjNTJhySv7Y2bwatKrl9UA
# +yEg7wBv9o6jr+h7cbdj5yKXyLJEksk3FsxjGJAkpm9vGUIin6kYidoPXfvczso8
# 8X/Jd5PiEbQupcq96WSC2WnN58+uZRW6mNhOB4Z+6lTAXPKZKTglE07W2FEHRsMo
# MjI0xWoS69XVTF1yuJxXSiOB4kcCAwEAAaOCATYwggEyMB0GA1UdDgQWBBRYEZ93
# BMsfQGdKPHxJWphawECOTTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnp
# cjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5j
# cmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQ
# Q0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMA0GCSqGSIb3DQEBCwUAA4ICAQB50LUCWFVccKV2Ty2gjMBb1DIhNxF7KFSm
# zW4PrvMILfTx9HNgURL/a8xfujQ5smDMLFPWeLS+RyzxYbYxQiyT3VEI8h4PNNAi
# 0imP1lPP2HS259woabdqGSdGzWGhXXaNEWRxqpcmjV+zK6gqAP4VNPaU6+sSw2Mm
# HnASyL48H+ZWaH8lrRW7yOFQlzWGsFRDliKxDg3TSydnCE6gJ49dt0PocazVyaxd
# luuRPy809hXwucjiXG4n9hphLbSpCvpj0MgcUM1jFltOWxB5ez8qOeFE10WIIagB
# wsdbB5Z5GzOHaJSEx9jX/v13uyiZ+PHpnIk9k6vh8TRRPaX+sFoFOug+kM6+lo6x
# joT+14ssx/KevpQ5B4TiVGLDn2yJUbIAaqlMFNt3MAUsEUfjS5uvtUSV2aOIdrXg
# SRnFi9yDMrEqq5vjKspp+j+P1pRvAusvZUwdZylrXwmG/rMiN3TUgaRR2PdQn4kp
# A0DPl7I/JBJk+33CzxvKeh0aUzmdiQcHLus++PjnL5nPuOsuCOC9kiLEazPCorIo
# njsA8fGsfwaMJC6xu9b00XgsBgqhlkaPs/CZAD5ebAPm19RDQq7MxEWYyk5TO2JM
# CAmNB/1My5zeliakVYSvySxh3CuOt1ZgAsJcD8hBcR0CKxDCPljNOyHhDFNSr69F
# LGz3fIHecjCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZI
# hvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# MjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAy
# MDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25Phdg
# M/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPF
# dvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6
# GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBp
# Dco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50Zu
# yjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3E
# XzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0
# lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1q
# GFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ
# +QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PA
# PBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkw
# EgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxG
# NSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARV
# MFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAK
# BggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMC
# AYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvX
# zpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20v
# cGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYI
# KwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG
# 9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0x
# M7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmC
# VgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449
# xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wM
# nosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDS
# PeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2d
# Y3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxn
# GSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+Crvs
# QWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokL
# jzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL
# 6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLP
# MIICOAIBATCB/KGB1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJp
# Y28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQ5REUtRTM5QS00M0ZFMSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoD
# FQCxGtITsLiwSf3oAyGM2RdnRjWKoKCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5wCqJDAiGA8yMDIyMTAyNDEw
# MDczMloYDzIwMjIxMDI1MTAwNzMyWjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDn
# AKokAgEAMAcCAQACAgTfMAcCAQACAhGaMAoCBQDnAfukAgEAMDYGCisGAQQBhFkK
# BAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJ
# KoZIhvcNAQEFBQADgYEAlytETBaaFfsKDO4inYcOpg+400ER766dCU1FwLPdfTJR
# Fua/lRbtqb4VwPuRhJfCKBoEZEmCLhgxmRyUGJ5cKzCTTe0WtgJHdpCq0hks3EbX
# e8PslyI66pgYn8rVjRoK1cUqY9l90Rt+19HHpp1DVTe99jbpa/JT69HUV+d4suQx
# ggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AaxmvIciXd49ewABAAABrDANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkD
# MQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCApkUahCCuFRgxn4tsy05F5
# IeOxw34U5c6uD9ljXJqWVTCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIPm3
# AZKDOC8JcQBytXPnqbv0+n5tAl/7T4uDZ9oELML1MIGYMIGApH4wfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGsZryHIl3ePXsAAQAAAawwIgQgHsuU
# +nN3x8HEar890GC56vyXHE0aznZ8HgNGwgburRswDQYJKoZIhvcNAQELBQAEggIA
# MWhK8O5ABzcJmKlJYVVt13Zo6k1XEe5BpDJGWeRipBJFg0VlWQJpg6maMBJZsXEy
# kg1ddPVWMz8Gn7eZJhAtHeFpb4zJWd8t3HhZRefrjUeeXvXwR2F893Ll0hYXf4Lo
# Qag10HQPhwl33+Awe/v1Fs0FeHmddMhU+TIlufeB+9zuzlMSXchodJguimb0YoPK
# w+twdY7Aok2jOcLJpUbW0EA3GwEEOIBcwIQm9yqQQXbq+3Kmh/iI23ZE2vPbIqbY
# rmsTiRWQBcBADIdj4YW1FkAaHh9k+N/F4hWzleesi7+XdVGuHgJpTROhg6e6y0TK
# bZST3hE+hyxkT2jpje8BV6A4+BFkD//oRPC/DlkP4oPRSZzxTz1QDGit0dUNRUhM
# EuEH3HWsv9VyPzFnGAe1rs8PXmziy++LoX4E0xN4Nz/7bv0bOob+mfwVyYwkzJeb
# 0pF8JgzUKSf+wZficjKLCzs5R6HLEuF33COEPg1/eWnhsowutUEaKAPjAISN09ET
# ZKQZHY7qUF4eMOZg/1/u6ljvko7tCx8mCIrl2xJuwui1wK42AxKmhAqRPYIStt4I
# b1dV8ur+Zt/FPHxlKm0R0b4SklReMEPSRUMODiFpEstJ665Xf8xh+qPNv9t0Ipwx
# ycVCf7nwjq+nkd6z9DwE2MZtMInfhNrxUaEVigF7NJM=
# SIG # End signature block
