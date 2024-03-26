# ***********************************************************************************************
# Version 1.0
# Date: 02-17-2012 -- Last edit: 2022-06-01
# Author: Vinay Pamnani - vinpa@microsoft.com
# Description:  Utility Script to load common functions.
# 		1. Defines commonly used functions in the Troubleshooter
# ***********************************************************************************************

trap [Exception]
{
	WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[utils_Shared]"
	continue
}
##########################################
# Set Variables
##########################################

$ComputerName = $ENV:COMPUTERNAME
$windir = $Env:windir 
$ProgFiles64 = $ENV:ProgramFiles 
$ProgFiles86 = ${Env:ProgramFiles(x86)} 
$system32 = $windir + "\system32"
$SystemRoot = $Env:SystemRoot
$OS = Get-CimInstance Win32_OperatingSystem

##########################
## Function Definitions ##
##########################

Function Check-RegKeyExists($RegKey){
	# To check if a Registry Key exists
	# Taken from Kurt Saren's FEP Scripts
	$RegKey = $RegKey -replace "HKLM\\", "HKLM:\"
	$RegKey = $RegKey -replace "HKCU\\", "HKCU:\"
	return (Test-Path $RegKey)
}

Function Get-RegValue($RegKey, $RegValue){
	# To get a specified Registry Value
	# Taken from Kurt Saren's FEP Scripts
	$RegKey = $RegKey -replace "HKLM\\", "HKLM:\"
	$RegKey = $RegKey -replace "HKCU\\", "HKCU:\"
	If (Check-RegValueExists $RegKey $RegValue){
		return (Get-ItemProperty -Path $RegKey).$RegValue
	}Else{
		return $null
	}
}

Function Check-RegValueExists ($RegKey, $RegValue){
	# To check if a Registry Value exists
	$RegKey = $RegKey -replace "HKLM\\", "HKLM:\"
	$RegKey = $RegKey -replace "HKCU\\", "HKCU:\"

	If (Test-Path $RegKey){
		If (Get-ItemProperty -Path $RegKey -Name $RegValue -ErrorAction SilentlyContinue){
			$true
		}Else{
			$false
			$Error.Clear()
		}
	}Else{
		$false
	}
}

Function Get-RegValueWithError($RegKey, $RegValue){
	# Modified version of Get-RegValue to get the error as well, instead of checking if the value is null everytime I call Get-RegValue
	$RegKey = $RegKey -replace "HKLM\\", "HKLM:\"
	$RegKey = $RegKey -replace "HKCU\\", "HKCU:\"
	If (Check-RegValueExists $RegKey $RegValue){
		$Value = (Get-ItemProperty -Path $RegKey -ErrorAction SilentlyContinue -ErrorVariable RegError).$RegValue
		if ($RegError.Count -gt 0) {
			Return "ERROR: $($RegValue.Exception[0].Message)"
		}
		if ($null -ne $Value) {
			Return $Value
		}else{
			Return "ERROR: Registry value is NULL."
		}
	}Else{
		Return "ERROR: Registry value does not exist."
	}
}

Function Copy-FilesWithStructure(){
	# Copy files with structure
	# Always uses Recurse and filtering is done by -Include switch which can take multiple parameters.
	param (
		$Source,
		$Destination,
		$Include
	)
	process {
		# This function uses -Include with Get-ChildItem so that multiple patterns can be specified
		if ($Source.EndsWith("\")) {
			$Source = $Source.Substring(0, $Source.Length - 1)
		}
		TraceOut "Copying $Include files from $Source to $Destination"
		if (Test-Path $Source) {
			try {
				if ($Source -eq (Join-Path $Env:windir "Temp")) {
					$Files = Get-ChildItem $Source -Recurse -Include $Include | Where-Object {-not ($_.FullName -like '*SDIAG_*') -and -not($_.FullName -like '*MATS-Temp*')}
				}else{
					$Files = Get-ChildItem $Source -Recurse -Include $Include
				}

				$FileCount = ($Files | Measure-Object).Count
				if ($FileCount -eq 0) {
					TraceOut "    No files match the Include criteria."
					return
				}

				TraceOut "    Found $FileCount files matching specified criteria"
				$Files | ForEach-Object {
					$targetFile = $_.FullName.Replace($Source, $Destination)    # Replace the source location with destination in file path
        			New-Item -ItemType File -Path $targetFile -Force | Out-Null # This creates the folder structure to the file including the 0 byte file #_#
        			Copy-Item $_.FullName -Destination $targetFile -Force -ErrorAction SilentlyContinue -ErrorVariable CopyErr		# Copy and overwrite the file
					if ($CopyErr.Count -ne 0) {
						TraceOut "    ERROR occurred while copying $Source file: $($CopyErr.Exception)"
					}
					$CopyErr.Clear()
    			}
			}
			catch [Exception] {
				TraceOut "    ERROR: $_"
			}
		}else{
			TraceOut "    $Source does not exist."
		}
	}
}

Function Copy-Files{
	# Copy files with specified filter
	# Uses Recurse if specified. Filtering is done by -Filter switch which takes only a single parameter.
	param(
		$Source,
		$Destination,
		$Filter,
		[switch]$Recurse,
		[switch]$RenameFileToPath
	)
	process {
		TraceOut "Copying $Filter files from $Source to $Destination"

		if (Test-Path $Source) {
			if ($Recurse) {
				$Files = Get-ChildItem $Source -Recurse -Filter $Filter | Where-Object {-not ($_.FullName -like '*SDIAG_*') -and -not($_.FullName -like '*MATS-Temp*')}
			}else{
				$Files = Get-ChildItem $Source -Filter $Filter | Where-Object {-not ($_.FullName -like '*SDIAG_*') -and -not($_.FullName -like '*MATS-Temp*')}
			}
			$FileCount = ($Files | Measure-Object).Count
			if ($FileCount -eq 0) {
				TraceOut "    No files match the Include criteria."
				return
			}
			TraceOut "    Found $FileCount files matching specified criteria"
			$Files | `
			ForEach-Object {
				$FilePath = $_.FullName

				if ($RenameFileToPath) {
					$DestFileName = ($FilePath -replace "\\","_" ) -replace ":","" 
				}else{
					$DestFileName = $_.Name
				}
				Copy-Item $FilePath (Join-Path $Destination $DestFileName) -ErrorAction SilentlyContinue -ErrorVariable CopyErr -Force
				if ($CopyErr.Count -ne 0) {
					TraceOut "    ERROR occurred while copying $Source files: $($CopyErr.Exception)"
				}
				$CopyErr.Clear()
			}
		}else{
			TraceOut "    $Source does not exist."
		}
	}
}

Function Export-RegKey ([string]$RegKey, [string]$OutFile, [string]$FileDescription="", [boolean]$collectFiles=$true, [boolean]$Recurse=$true, [boolean]$UpdateDiagProgress=$true, [boolean]$ForceRegExe=$false){
	# To export a Registry Key with subkeys and all values (decimal)
	# This function should call ExportRegKey if ForceRegExe=$false, to export the values in decimal instead of Hex, which is not user friendly.
	TraceOut "Registry Key to Export: $RegKey"

	if ($UpdateDiagProgress) {
		Import-LocalizedData -BindingVariable UtilsCTSStrings
		$RegKeyString = $UtilsCTSStrings.ID_RegistryKeys
		Write-DiagProgress -Activity $UtilsCTSStrings.ID_ExportingRegistryKeys -Status "$RegKeyString $RegKey" -ErrorAction SilentlyContinue
	}
	$sectionDescription = "Registry Keys"

	If (-not (Check-RegKeyExists $RegKey)) {
		TraceOut "    Registry Key does not exist!"
		return
	}

	$ScriptToRun = Join-Path $Pwd.Path "ExportReg.ps1" #-# this is curently not used, as all invocations use -ForceRegExe
	If ($Recurse -eq $true) {
		If ($OSVersion.Major -ge 6 -and -not($ForceRegExe)) {
			$CmdToRun = "Powershell.exe -ExecutionPolicy Bypass $ScriptToRun '$RegKey' `"$OutFile`" -Recurse `$true"  } # if needed, call ExportRegKey()

		Else {
			$CmdToRun = "cmd.exe /c Reg.exe Query `"$RegKey`" /s >> $OutFile" }
	}Else{
		If ($OSVersion.Major -ge 6 -and -not($ForceRegExe)) {
			$CmdToRun = "Powershell.exe -ExecutionPolicy Bypass $ScriptToRun '$RegKey' `"$OutFile`" -Recurse `$false" } # if needed, call ExportRegKey()
		Else {
			$CmdToRun = "cmd.exe /c Reg.exe Query `"$RegKey`" >> $OutFile"
		}
	}

	TraceOut "    Running command: $CmdToRun"
	If ($collectFiles -eq $true) {
		# Background Execution used because recursive parsing of Registry Key and Subkeys takes time
		Runcmd -commandToRun $CmdToRun -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $OutFile -BackgroundExecution | Out-Null #_#
	}Else{
		# Background Execution not used because it's ignored when collectFiles is set to False
		Runcmd -commandToRun $CmdToRun -filesToCollect $OutFile -collectFiles $false -useSystemDiagnosticsObject | Out-Null #_#
	}
	TraceOut "    Registry Key Export Completed for $RegKey."
}

function Get-CertInfo (){
	param($Path)
	$Temp = Get-ChildItem $Path -ErrorAction SilentlyContinue
	if (($Temp | Measure-Object).Count -gt 0) {
		$Return = $Temp | Select-Object Subject, Issuer, Thumbprint, HasPrivateKey, NotAfter, NotBefore, FriendlyName | Format-Table -AutoSize | Out-String -Width 1000
	}else{
		$Return = "`r`n  None.`r`n`r`n"
	}
	return $Return
}

Function Get-PendingReboot{
	# Taken from https://gallery.technet.microsoft.com/scriptcenter/Get-PendingReboot-Query-bdb79542
	<#
	.SYNOPSIS
		Gets the pending reboot status on a local or remote computer.

	.DESCRIPTION
		This function will query the registry on a local or remote computer and determine if the
		system is pending a reboot, from either Microsoft Patching or a Software Installation.
		For Windows 2008+ the function will query the CBS registry key as another factor in determining
		pending reboot state.  "PendingFileRenameOperations" and "Auto Update\RebootRequired" are observed
		as being consistant across Windows Server 2003 & 2008.

		CBServicing = Component Based Servicing (Windows 2008)
		WindowsUpdate = Windows Update / Auto Update (Windows 2003 / 2008)
		CCMClientSDK = SCCM 2012 Clients only (DetermineIfRebootPending method) otherwise $null value
		PendFileRename = PendingFileRenameOperations (Windows 2003 / 2008)

	.PARAMETER ComputerName
		A single Computer or an array of computer names.  The default is localhost ($env:COMPUTERNAME).

	.PARAMETER ErrorLog
		A single path to send error data to a log file.

	.EXAMPLE
		PS C:\> Get-PendingReboot -ComputerName (Get-Content C:\ServerList.txt) | Format-Table -AutoSize

		Computer CBServicing WindowsUpdate CCMClientSDK PendFileRename PendFileRenVal RebootPending
		-------- ----------- ------------- ------------ -------------- -------------- -------------
		DC01     False   False           False      False
		DC02     False   False           False      False
		FS01     False   False           False      False

		This example will capture the contents of C:\ServerList.txt and query the pending reboot
		information from the systems contained in the file and display the output in a table. The
		null values are by design, since these systems do not have the SCCM 2012 client installed,
		nor was the PendingFileRenameOperations value populated.

	.EXAMPLE
		PS C:\> Get-PendingReboot

		Computer     : WKS01
		CBServicing  : False
		WindowsUpdate      : True
		CCMClient    : False
		PendComputerRename : False
		PendFileRename     : False
		PendFileRenVal     :
		RebootPending      : True

		This example will query the local machine for pending reboot information.

	.EXAMPLE
		PS C:\> $Servers = Get-Content C:\Servers.txt
		PS C:\> Get-PendingReboot -Computer $Servers | Export-Csv C:\PendingRebootReport.csv -NoTypeInformation

		This example will create a report that contains pending reboot information.

	.LINK
		Component-Based Servicing:
		http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx

		PendingFileRename/Auto Update:
		http://support.microsoft.com/kb/2723674
		http://technet.microsoft.com/en-us/library/cc960241.aspx
		http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx

		SCCM 2012/CCM_ClientSDK:
		http://msdn.microsoft.com/en-us/library/jj902723.aspx

	.NOTES
		Author:  Brian Wilhite
		Email:   bcwilhite (at) live.com
		Date:    29AUG2012
		PSVer:   2.0/3.0/4.0/5.0
		Updated: 01DEC2014
		UpdNote: Added CCMClient property - Used with SCCM 2012 Clients only
		   Added ValueFromPipelineByPropertyName=$true to the ComputerName Parameter
		   Removed $Data variable from the PSObject - it is not needed
		   Bug with the way CCMClientSDK returned null value if it was false
		   Removed unneeded variables
		   Added PendFileRenVal - Contents of the PendingFileRenameOperations Reg Entry
		   Removed .Net Registry connection, replaced with WMI StdRegProv
		   Added ComputerPendingRename
	#>

[CmdletBinding()]
param(
  [Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
  [Alias("CN","Computer")]
  [String[]]$ComputerName="$env:COMPUTERNAME"
  )

Begin {  }## End Begin Script Block
Process {
	TraceOut "Get-PendingReboot: Entered"
	$Computer = $ComputerName
	Try {
		## Setting pending values to false to cut down on the number of else statements
		$CompPendRen,$PendFileRename,$Pending,$SCCM = $false,$false,$false,$false

		## Setting CBSRebootPend to null since not all versions of Windows has this value
		$CBSRebootPend = $null

		## Querying WMI for build version
		$WMI_OS = Get-CimInstance -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName $Computer -ErrorAction Stop

		## Making registry connection to the local/remote computer
		$HKLM = [UInt32] "0x80000002"
		$WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"

		## If Vista/2008 & Above query the CBS Reg Key
		If ([Int32]$WMI_OS.BuildNumber -ge 6001) {
			$RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
			$CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"
		}

		## Query WUAU from the registry
		$RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
		$WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"

		## Query PendingFileRenameOperations from the registry
		$RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\","PendingFileRenameOperations")
		$RegValuePFRO = $RegSubKeySM.sValue

		## Query ComputerName and ActiveComputerName from the registry
		$ActCompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\","ComputerName")
		$CompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\","ComputerName")
		If ($ActCompNm -ne $CompNm) {
			$CompPendRen = $true
		}

		## If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true
		If ($RegValuePFRO) {
			$PendFileRename = $true
		}

		## Determine SCCM 2012 Client Reboot Pending Status
		## To avoid nested 'if' statements and unneeded WMI calls to determine if the CCM_ClientUtilities class exist, setting EA = 0
		$CCMClientSDK = $null
		$CCMSplat = @{
		NameSpace='ROOT\ccm\ClientSDK'
		Class='CCM_ClientUtilities'
		Name='DetermineIfRebootPending'
		ComputerName=$Computer
		ErrorAction='Stop'
		}
		## Try CCMClientSDK
		Try {
			$CCMClientSDK = Invoke-WmiMethod @CCMSplat
		} Catch [System.UnauthorizedAccessException] {
			$CcmStatus = Get-Service -Name CcmExec -ComputerName $Computer -ErrorAction SilentlyContinue
			If ($CcmStatus.Status -ne 'Running') {
			TraceOut "Get-PendingReboot Error - CcmExec service is not running."
			$CCMClientSDK = $null
		}
		} Catch {
			$CCMClientSDK = $null
		}

		If ($CCMClientSDK) {
			If ($CCMClientSDK.ReturnValue -ne 0) {
				TraceOut  "Get-PendingReboot Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"
			}
			If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending) {
				$SCCM = $true
			}
		}Else{
			$SCCM = $null
		}

		## Creating Custom PSObject and Select-Object Splat
		$SelectSplat = @{
			Property=(
				'Computer',
				'RebootPending',
				'CBS',
				'WindowsUpdate',
				'CCMClientSDK',
				'PendingComputerRename',
				'PendingFileRenameOperations',
				'PendingFileRenameValue'
			)
		}
		New-Object -TypeName PSObject -Property @{
			Computer=$WMI_OS.CSName
			RebootPending=($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename)
			CBS=$CBSRebootPend
			WindowsUpdate=$WUAURebootReq
			CCMClientSDK=$SCCM
			PendingComputerRename=$CompPendRen
			PendingFileRenameOperations=$PendFileRename
			PendingFileRenameValue=$RegValuePFRO
		} | Select-Object @SelectSplat
	}
	Catch {
		TraceOut "Get-PendingReboot Error: $_"
	}
	TraceOut "Get-PendingReboot: Exiting."
}## End Process
End {  }## End End
}## End Function Get-PendingReboot

function TraceOut {
	#_# ___ from utils_shared.ps1 in SUVP
	##########################################
	# TraceOut (Taken from Vinay Pamnani)
	#-----------------
	# To standardize Logging to StdOut.log
	##########################################
    param ($WhatToWrite)
	process{
		$SName = ([System.IO.Path]::GetFileName($MyInvocation.ScriptName))
		$SName = $SName.Substring(0, $SName.LastIndexOf("."))
		$SLine = $MyInvocation.ScriptLineNumber.ToString()
		$STime =Get-Date -Format G
		WriteTo-StdOut "$STime [$ComputerName][$SName][$SLine] $WhatToWrite"
	}
}

function global:GetRegValue ($RegKey, $RegValue){
	##########################################
	# GetRegValue -- currently not used
	#-----------------
	# Used to quickly get a registry value
	##########################################
	$bkey=$RegKey -replace "HKLM\\", "HKLM:\"
	$bkey=$bkey -replace "HKCU\\", "HKCU:\"
	$bkey=$bkey -replace "HKU\\", "Registry::HKEY_USERS\"
	return (Get-ItemProperty -path $bkey).$RegValue
}

function global:RegKeyExist ($RegKey){
	##########################################
	# RegKeyExist -- currently not used
	#-----------------
	# Used to quickly check if a regsitry key exist
	##########################################
	$bkey=$RegKey -replace "HKLM\\", "HKLM:\"
	$bkey=$bkey -replace "HKCU\\", "HKCU:\"
	$bkey=$bkey -replace "HKU\\", "Registry::HKEY_USERS\"
	return (Test-Path $bkey)
}

##########################################
# pow
#-----------------
# to calculate powers
##########################################

function global:calcdate ($values){
	##########################################
	# calcdate -- currently not used
	#-----------------
	# to convert the binary date
	##########################################
	$calcvalues=$values -split " "
	
     [int64]$ourSeconds = [int]$calcvalues[7]*[math]::pow(2,56) + [int]$calcvalues[6]*[math]::pow(2,48) + [int]$calcvalues[5]*[math]::pow(2,40) + [int]$calcvalues[4]*[math]::pow(2,32) + [int]$calcvalues[3]*[math]::pow(2,24) + [int]$calcvalues[2]*[math]::pow(2,16) + [int]$calcvalues[1]*[math]::pow(2,8) + [int]$calcvalues[0] 
     [DateTime] $DDate = [DateTime]::FromFileTime($ourSeconds);	
     return $DDate;
}

function DirectoryOutput ($dir, $fDesc, $sDesc){
	##########################################
	# DirectoryOutput
	#-----------------
	# Gets directory output and copies to SDP
	##########################################
	$CommandLineToExecute = "cmd.exe /c dir /s $dir > $OutputFile"
	RunCMD -commandToRun $CommandLineToExecute -filesToCollect $OutputFile -fileDescription $fDesc -sectionDescription $sDesc
}

Function CopyDeploymentFile ($sourceFileName, $destinationFileName, $fileDescription){
	##########################################
	# CopyDeploymentFile
	#-----------------
	# Copies specified file to SDP
	##########################################
	if (test-path $sourceFileName) {
		$sourceFile = Get-Item $sourceFileName
		#copy the file only if it is not a 0KB file.
		if ($sourceFile.Length -gt 0) 
		{
			$CommandLineToExecute = "cmd.exe /c copy `"$sourceFileName`" `"$destinationFileName`""
			"Collecting " + $sourceFileName | WriteTo-StdOut 
			RunCmD -commandToRun $CommandLineToExecute -sectionDescription $sectionDescription -filesToCollect $destinationFileName -fileDescription $fileDescription
		}
	}
}

function query_registry ($key){
	##########################################
	# query_registry
	#-----------------
	# Runs reg.exe to query the registry
	##########################################
	$CommandLineToExecute = "cmd.exe /c reg.exe query $key >> $OutputFile"
	$Header = "Querying Registry: " + $key + ":"
	$Header | Out-File $OutputFile 
	$Header | WriteTo-StdOut 
	RunCMD -commandToRun $CommandLineToExecute
}

function logCmdToExecute(){
	##########################################
	# logCmdToExecute
	#-----------------
	# Logs $CommandLineToExecute
	##########################################
	$CommandLineToExecute | WriteTo-StdOut 
}

function logStart(){
	# Adds start in StdOut
	"Start collecting " + $OutputFile | WriteTo-StdOut 
}

function logStop(){
	# Adds stop in StdOut
	"Stop collecting " + $OutputFile | WriteTo-StdOut 
}

function ExportRegKey{	# -- obsolete
	# this function was previously a separate script ExportReg.ps1 , but it is no more used, as Reg.EXE as it is a LOT quicker than ExportReg.ps1
	PARAM([string]$RegKey, [string]$OutFile, [Boolean]$Recurse=$true)
	Write-Host "Export Reg Started for $RegKey"
	Write-Host "Destination: $OutFile"
	"`r`n" + "-" * ($RegKey.Length + 2) + "`r`n[" + $RegKey + "]`r`n" + "-" * ($RegKey.Length + 2) + "`r`n" | Out-File $OutFile -Append
	$PSRegKey= $RegKey -replace "HKLM\\", "HKLM:\" -replace "HKCU\\", "HKCU:\" -replace "HKU\\", "Registry::HKEY_USERS\"
	If (Test-Path $PSRegKey) {
		Write-Host "Registry Key Exists."
		# Print values from the Key
		$key = Get-Item $PSRegKey
		"[$key]" | Out-File $OutFile -Append
		$values = Get-ItemProperty $key.PSPath
		ForEach ($value in ($key.Property | Sort-Object)) {
			"    " + $value + " = " + $values.$value | Out-File $OutFile -Append				
		}
		If ($Recurse) {
			Write-Host "Recurse = $Recurse"
			# Print values from subkeys
			$SubKeys = Get-ChildItem $PSRegKey -Recurse -ErrorAction SilentlyContinue
			If ($null -ne $SubKeys) {
				Write-Host "SubKeys exist."
				ForEach ($subkey in $SubKeys) {
					$key = Get-Item $subkey.PSPath
					"" | Out-File $OutFile -Append
					"[$key]" | Out-File $OutFile -Append
					$values = Get-ItemProperty $key.PSPath
					ForEach ($value in ($key.Property | Sort-Object)) {
						"    " + $value + " = " + $values.$value | Out-File $OutFile -Append
					}			
				}
			}Else{
				Write-Host "No Subkeys Found"
			}
		}
	}Else{
		Write-Host "Registry Key does not Exist!"
		"    Registry Key does not exist" | Out-File $OutFile -Append
	}
	Write-Host "Registry Export Complete."
}


# SIG # Begin signature block
# MIInwwYJKoZIhvcNAQcCoIIntDCCJ7ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCbXQ3sORO08CXs
# wJKou5MbvTqdZHPk70gaCgxHhxEudaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGaMwghmfAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGR5yYfc27eqPVPT4g6Xp3nf
# WFRGPSyS3DqSJPprajQaMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCcGCO3sNBgjPm4tBoN5r03j4KcrkRcxHwPKJaXABRl2JkLdVcpEQpP
# hq0yMx2oQUjw5hf8qL7FyxgJttO5ysPQ5co9wrhUhFAYvmHbCwIlf3bZ8Rh1kdrg
# cIRAzHZ6HY6UMI4f+PlE6LdIlevBVf7sDvX7j59YKSTKX6Mi5xlu5B4UBAb3HOT7
# OTcTeE5e0Pp1SuvzK+aywMNV1PSULSCcmg10f4kg7YAnIFeZq6NDRWHumo4tiwSk
# 3MFEGlpZgKpMBZxW4hOP94P9E41+itWrA7SvX75/BZ4hnBjjDlN6jWC1VohYiU3n
# 9maZCN3Hu5HJauLpcLuzepp+V85doRlOoYIXKzCCFycGCisGAQQBgjcDAwExghcX
# MIIXEwYJKoZIhvcNAQcCoIIXBDCCFwACAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIBP+3CI5rQ2zWLYEj9bj+/CSGaBlY+iaCreEKh8iV3pHAgZj91lq
# ZKgYEzIwMjMwMjI3MDkyNTEwLjU3NFowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046OEQ0MS00QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF6MIIHJzCCBQ+gAwIBAgITMwAAAbP+Jc4pGxuKHAABAAABszAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MjA5MjAyMDIyMDNaFw0yMzEyMTQyMDIyMDNaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhENDEt
# NEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHwPuuYYgK4ssGCCsr2N
# 7eElKlz0JPButr/gpvZ67kNlHqgKAW0JuKAy4xxjfVCUev/eS5aEcnTmfj63fvs8
# eid0MNvP91T6r819dIqvWnBTY4vKVjSzDnfVVnWxYB3IPYRAITNN0sPgolsLrCYA
# KieIkECq+EPJfEnQ26+WTvit1US+uJuwNnHMKVYRri/rYQ2P8fKIJRfcxkadj8CE
# PJrN+lyENag/pwmA0JJeYdX1ewmBcniX4BgCBqoC83w34Sk37RMSsKAU5/BlXbVy
# Du+B6c5XjyCYb8Qx/Qu9EB6KvE9S76M0HclIVtbVZTxnnGwsSg2V7fmJx0RP4bfA
# M2ZxJeVBizi33ghZHnjX4+xROSrSSZ0/j/U7gYPnhmwnl5SctprBc7HFPV+BtZv1
# VGDVnhqylam4vmAXAdrxQ0xHGwp9+ivqqtdVVDU50k5LUmV6+GlmWyxIJUOh0xzf
# Qjd9Z7OfLq006h+l9o+u3AnS6RdwsPXJP7z27i5AH+upQronsemQ27R9HkznEa05
# yH2fKdw71qWivEN+IR1vrN6q0J9xujjq77+t+yyVwZK4kXOXAQ2dT69D4knqMlFS
# sH6avnXNZQyJZMsNWaEt3rr/8Nr9gGMDQGLSFxi479Zy19aT/fHzsAtu2ocBuTqL
# VwnxrZyiJ66P70EBJKO5eQECAwEAAaOCAUkwggFFMB0GA1UdDgQWBBTQGl3CUWdS
# DBiLOEgh/14F3J/DjTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAWoa7N86wCbjA
# Al8RGYmBZbS00ss+TpViPnf6EGZQgKyoaCP2hc01q2AKr6Me3TcSJPNWHG14pY4u
# hMzHf1wJxQmAM5Agf4aO7KNhVV04Jr0XHqUjr3T84FkWXPYMO4ulQG6j/+/d7gqe
# zjXaY7cDqYNCSd3F4lKx0FJuQqpxwHtML+a4U6HODf2Z+KMYgJzWRnOIkT/od0oI
# Xyn36+zXIZRHm7OQij7ryr+fmQ23feF1pDbfhUSHTA9IT50KCkpGp/GBiwFP/m1d
# rd7xNfImVWgb2PBcGsqdJBvj6TX2MdUHfBVR+We4A0lEj1rNbCpgUoNtlaR9Dy2k
# 2gV8ooVEdtaiZyh0/VtWfuQpZQJMDxgbZGVMG2+uzcKpjeYANMlSKDhyQ38wboAi
# vxD4AKYoESbg4Wk5xkxfRzFqyil2DEz1pJ0G6xol9nci2Xe8LkLdET3u5RGxUHam
# 8L4KeMW238+RjvWX1RMfNQI774ziFIZLOR+77IGFcwZ4FmoteX1x9+Bg9ydEWNBP
# 3sZv9uDiywsgW40k00Am5v4i/GGiZGu1a4HhI33fmgx+8blwR5nt7JikFngNuS83
# jhm8RHQQdFqQvbFvWuuyPtzwj5q4SpjO1SkOe6roHGkEhQCUXdQMnRIwbnGpb/2E
# sxadokK8h6sRZMWbriO2ECLQEMzCcLAwggdxMIIFWaADAgECAhMzAAAAFcXna54C
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
# ahC0HVUzWLOhcGbyoYIC1jCCAj8CAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjhENDEtNEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBxi0Tolt0eEqXCQl4qgJXUkiQOYaCBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA56Z0VzAiGA8yMDIzMDIyNzA4MTQxNVoYDzIwMjMwMjI4MDgxNDE1WjB2MDwG
# CisGAQQBhFkKBAExLjAsMAoCBQDnpnRXAgEAMAkCAQACASACAf8wBwIBAAICEs4w
# CgIFAOenxdcCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQDCQx5FNe3BH69o
# AdAbIZSEI1lawH0EIHqMHn9ipDmOJwzOGzMPjQ7l4UjXjlOIJ899pm7erozh0d6l
# L8TRM39CSqM3+P+SppQFvXMQ7A9ZnEmnHPS8/hy/8L2M2KAgl/n37Zbwni6WpPzk
# ZJACUKV3SI+2SMsyH5v0H/BA0e0aIjGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABs/4lzikbG4ocAAEAAAGzMA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEILUOVlaluqDczl8T7+TA2lNpeRBM0oMB5Z5BuVQvgrjPMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQghqEz1SoQ0ge2RtMyUGVDNo5P5ZdcyRoeijoZ
# ++pPv0IwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AbP+Jc4pGxuKHAABAAABszAiBCBrsLleqTugnLR/kAuojsM4pQ0CKJ2mpaT6PIyB
# IMDM0DANBgkqhkiG9w0BAQsFAASCAgBazONQoU9VtMMattqaFtn2Gth61BVPQGHp
# uib6KfmCbW2OyTdv7MLNjjY1ckLg1zfJ3/lJvdDMjcAPT9+w1m4jGmJK2olwlZlQ
# kdH7197XP+ytHnIU3S5J2ypzy44X5EaRsGDJOefn0Jfrsbj8ZzIH1lEYBhJCasMh
# 36gTG5RSOhLpaw3v/VxxqmcbuRMfD/VZwBhMydNhRh99Gsp3NgJKizn6dpOiooEp
# OMRvDCQubdrXWERdaaZCJQZe9Czufyeu21S6XdPPjLhrbLDlI7C+k3vsZkMysDbm
# iXMZHGyYwxdMaYho8YdE8vYamv+5yhZvMxN+FOiZFa5efpLD6bzMOLkzWfa2MXrh
# DYihLKutvldi2fXBjYMafI6UetebIX8Dfd7OhntUl3f9eN2VLCKzMtPfqK88cOjQ
# aGt8AXexYYFbZhZVG5ylgPdqLuojcZ35TfYtCoe9NQopyu+SzkI7K66Kc9CZ+7RZ
# jZT2Dq+7ExqQom9mk1GHTkorq44t9DwebPQV/czOlxGCPsJvdVw1ri1iMocY9pqp
# IN7r2Mxi/BTO0GL+Kmrjj2fp/9LMDds0XZnXLm1CZXZjaKAqEnPp1Wm4PCUwHMf/
# iBLCPXrc62edyQ+/XLKRv13+KlYoEIlGC0scvTY9saGrWZ/oQML2sOVmtTMftElL
# QuuTV+nE0w==
# SIG # End signature block
