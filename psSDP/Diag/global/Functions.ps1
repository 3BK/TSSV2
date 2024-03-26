#************************************************
# Function.ps1
# Version 1.0.0
# Date: 03-01-2012
# Author: Wilson Souza - wsouza@microsoft.com
# Description: This script contains functions used by others ps1 files
#************************************************
Import-LocalizedData -BindingVariable ScriptStrings

function GetDPMInstallFolder
{
	if ((Test-Path "HKLM:SOFTWARE\Microsoft\Microsoft Data Protection Manager\Setup") -eq $true)
	{
		return (get-itemproperty HKLM:\SOFTWARE\Microsoft\"Microsoft Data Protection Manager"\Setup).InstallPath
	} Else {
		$null
	}
}

Function DPMVersion ([String]$Folder)
{
	$DPMFile = $Folder + "bin\msdpm.exe"
	if(Test-Path $DPMFile)
	{
		$MSDPM_Version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($dpmfile).filemajorpart
		Return $MSDPM_Version
	}
	else
	{
		$Folder + "bin\msdpm.exe is not found" | WriteTo-StdOut 
	}
}

Function DPMRAVersion ([String]$Folder)
{
	$DPMRAFile = $Folder + "bin\dpmra.exe"
	if(Test-Path $DPMRAFile)
	{
		$DPMRA_Version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($DPMRAFile).filemajorpart
		Return $DPMRA_Version
	}
	else
	{
		$Folder + "bin\dpmra.exe is not found" | WriteTo-StdOut 
	}
}


####################################################################################
# Check to be see if DPM is installed
####################################################################################
Function IsDPMInstalled
{
	$IsDPMInstalled = $false
	if (Test-Path "HKLM:SOFTWARE\Microsoft\Microsoft Data Protection Manager\Setup")	
	{
		$IsDPMInstalled =(get-itemproperty "HKLM:\SOFTWARE\Microsoft\Microsoft Data Protection Manager\Setup").InstallPath 
		if(!([string]::IsNullOrEmpty($IsDPMInstalled)))
		{
			$IsDPMInstalled = $true
		}
	}
	return $IsDPMInstalled
}

####################################################################################
# Check to be see if Microsoft Azure Backup is installed
####################################################################################
Function IsMABInstalled
{
	$IsMABInstalled = $false
	if (Test-Path "HKLM:SOFTWARE\Microsoft\Windows Azure Backup\Setup")	
	{
		$IsMABInstalled =(get-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows Azure Backup\Setup").InstallPath 
		if(!([string]::IsNullOrEmpty($IsMABInstalled)))
		{
			$IsMABInstalled = $true
		}
	}
	return $IsMABInstalled
}

####################################################################################
# Check to be see if it is a DPM Server or a protected server
####################################################################################
Function IsDPMServer
{
	if (Test-Path "HKLM:SOFTWARE\Microsoft\Microsoft Data Protection Manager\DB")
	{
		return $true
	}
	else
	{
		return $false
	}	
}

####################################################################################
# Check to be sure the DPM namespace is loaded, if not then load it
####################################################################################
function LoadDPMNamespace ()
{	
	Write-DiagProgress -Activity $ScriptStrings.ID_DPM_Obtain_DPM_Information_Title -Status $ScriptStrings.ID_DPM_Obtain_DPM_Information_Status
	$DPMFolder = GetDPMInstallFolder	
	$DPMVersion = DPMVersion ($DPMFolder)
	Switch ($DPMVersion)
	{	
		2	{
				if (!(get-PSSnapin | ? { $_.name -eq 'Microsoft.DataProtectionManager.PowerShell'}))
				{
					Add-PSSnapin -name Microsoft.DataProtectionManager.PowerShell
				}
			}
		3	{
				if (!(get-PSSnapin | ? { $_.name -eq 'Microsoft.DataProtectionManager.PowerShell'}))
				{
					Add-PSSnapin -name Microsoft.DataProtectionManager.PowerShell
				}
			}
		4	{
				Import-Module -name dataprotectionmanager
			}
	}
} 

####################################################################################
# Format an XML string in indentation format for easier read
####################################################################################
function Format-XML ([xml]$xml, $indent=2) 
{ 
    $StringWriter = New-Object System.IO.StringWriter 
    $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter 
    $xmlWriter.Formatting = "indented" 
    $xmlWriter.Indentation = $Indent 
    $xml.WriteContentTo($XmlWriter) 
    $XmlWriter.Flush() 
    $StringWriter.Flush() 
    Write-Output $StringWriter.ToString() 
}

# NEED TO change the entires below to look at the date and only collect logs where last write time is withing the 30 days or passed in time period

# CompressCollectFilesForTimePeriod function
# ---------------------
# Description:
#       This function compresses files in a ZIP or CAB file, collecting these files after the ZIP file is created
#       ZIP format is way faster than CAB but - once Shell is used for ZIP files, there is no support for ZIP files on ServerCore
#       Where support for ZIP files is inexistent (like on ServerCore), function will automatically switch to CAB
#
# Arguments:
#		filesToCollect: Folder or Files that to be collected (Ex: C:\windows\*.txt). This value can also be an array.
#       DestinationFileName: Destination name for the zip file (Ex: MyZipFile.ZIP or MyCabFile.CAB)
#		fileDescription: Individual description of the zip file 
#		sectionDescription: Section description.
#       Recursive: Copy files in subfolders
#       renameOutput: Add the %ComputerName% prefix to the ZIP file name - if not existent
#       noFileExtensionsOnDescription: Do not add file extension to the file description (Default format is $fileDescription ($FileExtension))
#       Verbosity: When $collectFiles is true, $Verbosity is the verbosity level for CollectFiles function
#       DoNotCollectFile: If present, function will generate the ZIP file but it will not collect it
#       ForegroundProcess: *Only for CAB files - By default CAB files are compressed in a Background process. Use -ForegroundProcess to force waiting for compression routine to complete before continuing.

function CompressCollectFilesForTimePeriod
{
	PARAM($filesToCollect,
		[string]$DestinationFileName="File.zip",
		[switch]$Recursive,
		[string]$fileDescription="File", 
		[string]$sectionDescription="Section",
		[boolean]$renameOutput=$true,
		[switch]$noFileExtensionsOnDescription,
		[string]$Verbosity="Informational",
		[switch]$DoNotCollectFile,
		[switch]$ForegroundProcess=$false,
		[int]$NumberOfDays="30" # Collect last 15 days of files if not present
		)

	$FileFormat = [System.IO.Path]::GetExtension($DestinationFileName)

	if ($FileFormat.Length -ne 4) {$FileFormat = ".zip"}

	if ((-not (Test-Path -Path (join-path ([Environment]::SystemDirectory) "shell32.dll"))) -and ($FileFormat -eq ".zip")) 
	{
		"[CompressCollectFilesForTimePeriod] - File format was switched to .CAB once shell is not present" | WriteTo-StdOut -ShortFormat
		$FileFormat = ".cab"
	}
	
	if (($renameOutput -eq $true) -and (-not $DestinationFileName.StartsWith($ComputerName))) 
	{
		$CompressedFileNameWithoutExtension = $ComputerName + "_" + [System.IO.Path]::GetFileNameWithoutExtension($DestinationFileName)
	} else {
		# if ($DestinationFileName.Contains("zip_dpmerrlog"))
		if ($DestinationFileName.Contains(".zip"))
		{
			$CompressedFileNameWithoutExtension = $DestinationFileName
		} else {
			$CompressedFileNameWithoutExtension = [System.IO.Path]::GetFileNameWithoutExtension($DestinationFileName)
		}
	}

	$CompressedFileName = ($PWD.Path) + "\" + $CompressedFileNameWithoutExtension + $FileFormat

	if ($FileFormat -eq ".cab")
	{
		#Create DDF File
		$ddfFilename = $ddfFilename = $env:temp + [System.IO.Path]::DirectorySeparatorChar + [System.IO.Path]::GetRandomFileName();
		
	    ".Set DiskDirectoryTemplate=" + "`"" + $PWD.Path + "`"" | Out-File -FilePath $ddfFilename -Encoding "UTF8";
	    ".Set CabinetNameTemplate=`"" + [IO.Path]::GetFileName($CompressedFileName) + "`""| Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
	 
	    ".Set Cabinet=ON" | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
	    ".Set Compress=ON" | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
	    ".Set InfAttr=" | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
		".Set FolderSizeThreshold=2000000" | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
		".Set MaxCabinetSize=0" | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
		".Set MaxDiskSize=0" | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
	}

	$ShellGetAllItems = {
	PARAM ($ShellFolderObj, $ZipFileName)
		if ($ShellFolderObj -is "System.__ComObject")
		{
			$ArrayResults = @()
			foreach ($ZipFileItem in $ShellFolderObj.Items())
			{
				$ArrayResults += $ZipFileItem.Path.Substring($ZipFileName.Length + 1)
				
				if ($ZipFileItem.IsFolder)
				{
					$ArrayResults += $ShellGetAllItems.Invoke((new-object -com Shell.Application).NameSpace($ZipFileItem.Path), $ZipFileName)
				}
			}
			return $ArrayResults
		}
	}

	ForEach ($pathFilesToCollect in $filesToCollect) 
	{
		 #I think we're right here when we go through all of the loop of files
		"[CompressCollectFilesForTimePeriod] Compressing " + $pathFilesToCollect + " to " + [System.IO.Path]::GetFileName($CompressedFileName) | WriteTo-StdOut -ShortFormat
		
		if (test-path ([System.IO.Path]::GetDirectoryName($pathFilesToCollect)) -ErrorAction SilentlyContinue) 
		{
		
			if ($Recursive.IsPresent) 
			{
				$FileExtension = Split-Path $pathFilesToCollect -leaf
				$RootFolder = [System.IO.Path]::GetDirectoryName($pathFilesToCollect)
				if ($FileExtension -eq "*.*" -and $FileFormat -eq ".zip")
				{
					#Optimization to collect subfolders on ZIP files
					$FilestobeCollected = Get-ChildItem -Path ([System.IO.Path]::GetDirectoryName($pathFilesToCollect))
				} else {
					$FilestobeCollected = Get-ChildItem -Path ([System.IO.Path]::GetDirectoryName($pathFilesToCollect)) -Include $FileExtension -Recurse
				}
				$SubfolderToBeCollected = $FilestobeCollected | Select-Object -Unique -ExpandProperty "Directory"
			} else {
				$FilestobeCollected = Get-ChildItem -Path $pathFilesToCollect
			}
			if ((($FilestobeCollected -is [array]) -and ($FilestobeCollected.Count -gt 0)) -or ($FilestobeCollected -ne $null))
			{
		 		switch ($FileFormat)
				{
					".zip" 
					{
						#Create file if it does not exist, otherwise just add to the ZIP file name
						$FilesToSkip = @()
						if (-not (Test-Path($CompressedFileName))) 
						{
							Set-Content $CompressedFileName ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
						} else {
							#Need to check file name conflicts, otherwise Shell will raise a message asking for overwrite
							$ZipFileObj = (new-object -com Shell.Application).NameSpace($CompressedFileName)
							$FilesToBeCollectedFullPath = ($FilestobeCollected | Select-Object -ExpandProperty "FullName")
							$AllZipItems = $ShellGetAllItems.Invoke($ZipFileObj, $CompressedFileName)
							
							foreach ($ZipFileItem in $AllZipItems)
							{
								$FileNameToCheck = $RootFolder + "\" + $ZipFileItem
								if ($FilesToBeCollectedFullPath -contains $FileNameToCheck)
								{
									if (($FileExtension -eq "*.*") -or ([System.IO.Directory]::Exists($FileNameToCheck) -eq $false)) #Check if it is a folder, so it will not fire a message on stdout.log
									{
										#Error - File Name Conflics exist
										$ErrorDisplay = "[CompressCollectFiles] Error: One or more file name conflicts when compressing files were detected:`r`n"
										$ErrorDisplay += "        File Name   : "+ $FileNameToCheck + "`r`n"
										$ErrorDisplay += "        Zip File    : " + $CompressedFileName + "`r`n"
										$ErrorDisplay += "   File/ Folder will not be compressed."
										$ErrorDisplay | WriteTo-StdOut
									}
									$FilesToSkip += $FileNameToCheck
								}
							}
						} #end else
						
						if($debug -eq $true){[void]$shell.popup("Processing list of files:t")}						
																	
						$currentDate = [System.DateTime]::Now

						#TODO: Add if NumOfDays > 0 then default to 0 for all files
						
						#Create emtpy array
						$NewFileList = @()
						
						foreach ($NameOfFile in $FilestobeCollected)
						{
							$LastTime = $NameOfFile.LastWriteTime
							$TimeDiff = ($currentDate - $LastTime).Days

							if ($TimeDiff -le $NumberOfDays)
							{
								#Now add to list
								$NewFileList += $NameOfFile
							}
							
						}
						$FilestobeCollected = $NewFileList
						
						$ExecutionTimeout = 20 #Time-out for compression - in minutes

						$ZipFileObj = (new-object -com Shell.Application).NameSpace($CompressedFileName)
						$InitialZipItemCount = 0
						
						if (($Recursive.IsPresent) -and ($FileExtension -ne "*.*"))
						{
							#Create Subfolder structure on ZIP files
							$TempFolder = mkdir -Path ($Env:TEMP + "\ZIP" + (Get-Random).toString())
							$TempFolderObj = (new-object -com Shell.Application).NameSpace($TempFolder.FullName)
							
							foreach ($SubfolderToCreateOnZip in $SubfolderToBeCollected | Select-Object -ExpandProperty "FullName")
							{
								$RelativeFolder = $SubfolderToCreateOnZip.Substring($RootFolder.Length)
								if ($RelativeFolder.Length -gt 0)
							{
									$TempFolderToCreate = (Join-Path $TempFolder $RelativeFolder)
									MKDir -Path $TempFolderToCreate | Out-Null
									"Temporary file" |Out-File -FilePath ($TempFolderToCreate + "\_DeleteMe.Txt") -Append #Temporary file just to make sure file isn't empty so it won't error out when using 'CopyHere
								}
							}
							#Create subfolder structure on ZIP file:
							
							foreach ($ParentTempSubfolder in $TempFolder.GetDirectories("*.*", [System.IO.SearchOption]::AllDirectories))
							{
								if (($AllZipItems -eq $null) -or ($AllZipItems -notcontains ($ParentTempSubfolder.FullName.Substring($TempFolder.FullName.Length+1))))
								{
									
									$TimeCompressionStarted = Get-Date
									$ZipFileObj = (new-object -com Shell.Application).NameSpace($CompressedFileName + $ParentTempSubfolder.Parent.FullName.Substring($TempFolder.FullName.Length))
								$InitialZipItemCount = $ZipFileObj.Items().Count
								$ZipFileObj.CopyHere($ParentTempSubfolder.FullName, $DontShowDialog)
									do
									{
										sleep -Milliseconds 100
										
										if ((New-TimeSpan -Start $TimeCompressionStarted).Minutes -ge 2)
										{
											$ErrorDisplay = "[CompressCollectFilesForTimePeriod] Compression routine will be terminated due it reached a timeout of 2 minutes to create a subfolder on zip file:`r`n"
											$ErrorDisplay += "        SubFolder   : " + $RootFolder + $ParentTempSubfolder.FullName.Substring($TempFolder.FullName.Length) + "`r`n"
											$ErrorDisplay += "        Start Time  : " + $TimeCompressionStarted + "`r`n"
											$ErrorDisplay | WriteTo-StdOut
											$TimeoutOcurred = $true
										}
																
									} while ((-not $TimeoutOcurred) -and ($ZipFileObj.Items().Count -le $InitialZipItemCount))
									
									$AllZipItems += [System.IO.Directory]::GetDirectories($ParentTempSubfolder.FullName, "*.*", [System.IO.SearchOption]::AllDirectories) | ForEach-Object -Process {$_.Substring($TempFolder.FullName.Length + 1)}
									$AllZipItems  = $ShellGetAllItems.Invoke($ZipFileObj, $CompressedFileName)
								}
							}
						}
						
						if (($ZipFileObj -eq $null) -or ($ZipFileObj.Self.Path -ne $CompressedFileName))
						{
							$ZipFileObj = (new-object -com Shell.Application).NameSpace($CompressedFileName)
						}
					} # switch .zip
				} #switch
		
			$FilestobeCollected | ForEach-object -process {
				
					$FileName = Split-Path $_.Name -leaf
					$FileNameFullPath = $_.FullName
					if (($Recursive.IsPresent) -and ([System.IO.Path]::GetDirectoryName($FileNameFullPath).Length -gt [System.IO.Path]::GetDirectoryName($pathFilesToCollect).Length))
					{
						$RelativeFolder = [System.IO.Path]::GetDirectoryName($FileNameFullPath).Substring([System.IO.Path]::GetDirectoryName($pathFilesToCollect).Length)
					} else {
						$RelativeFolder = ""
						$CurrentZipFolder = ""
					} 
					
			 		switch ($FileFormat)
					{
						".zip" 
						{
							$TimeCompressionStarted = Get-Date
							$TimeoutOcurred = $false

							if (($FileExtension -eq "*.*") -and ([System.IO.Directory]::Exists($FileNameFullPath)))
							{
								#Check if folder does not have any file
								if (([System.IO.Directory]::GetFiles($FileNameFullPath, "*.*", [System.IO.SearchOption]::AllDirectories)).Count -eq 0)
								{
									$FilesToSkip += $FileNameFullPath 
									"[CompressCollectFilesForTimePeriod] Folder $FileNameFullPath will not be compressed since it does not contain any file`r`n"
								}
							}

						if ($RelativeFolder -ne $CurrentZipFolder)
							{
								$ZipFileObj = (new-object -com Shell.Application).NameSpace((join-path $CompressedFileName $RelativeFolder))
								ForEach ($TempFile in $ZipFileObj.Items()) 
								{
									#Remove temporary file from ZIP
									if ($TempFile.Name -eq "_DeleteMe") 
									{
										$DeleteMeFileOnTemp = (Join-Path $TempFolder.FullName "_DeleteMe.TXT")
										if (Test-Path $DeleteMeFileOnTemp) {Remove-Item -Path $DeleteMeFileOnTemp}
										$TempFolderObj.MoveHere($TempFile)
										if (Test-Path $DeleteMeFileOnTemp) {Remove-Item -Path (Join-Path $TempFolder.FullName "_DeleteMe.TXT")}
									}
								}
								$CurrentZipFolder = $RelativeFolder
							} elseif (($RelativeFolder.Length -eq 0) -and ($ZipFileObj.Self.Path -ne $CompressedFileName))
							{
								$ZipFileObj = (new-object -com Shell.Application).NameSpace($CompressedFileName)
							}
			
							if (($FilesToSkip -eq $null) -or ($FilesToSkip -notcontains $FileNameFullPath))
							{
								"             Adding " + $FileNameFullPath + " to " + [System.IO.Path]::GetFileName($CompressedFileName) + $ZipFileObj.Self.Path.Substring($CompressedFileName.Length) | WriteTo-StdOut -ShortFormat
								$InitialZipItemCount = $ZipFileObj.Items().Count
								$ZipFileObj.CopyHere($FileNameFullPath, $DontShowDialog)
						
								while ((-not $TimeoutOcurred) -and ($ZipFileObj.Items().Count -le $InitialZipItemCount))
								{
									sleep -Milliseconds 200
									
									if ((New-TimeSpan -Start $TimeCompressionStarted).Minutes -ge $ExecutionTimeout)
									{
										$ErrorDisplay = "[CompressCollectFilesForTimePeriod] Compression routine will be terminated due it reached a timeout of $ExecutionTimeout minutes:`r`n"
										$ErrorDisplay += "        File Name   : $FileNameFullPath `r`n"
										$ErrorDisplay += "        Start Time  : " + $TimeCompressionStarted + "`r`n"
										$ErrorDisplay | WriteTo-StdOut
										$TimeoutOcurred = $true
									}
															
								} 
							}
						}
						".cab"
						{
							if ($RelativeFolder -ne $CurrentCabFolder)
							{
								$ListOfFilesonDDF += ".Set DestinationDir=`"" + $RelativeFolder + "`"`r`n"
								$CurrentCabFolder = $RelativeFolder
							}
							$ListOfFilesonDDF += "`"" + $FileNameFullPath + "`"`r`n" 
						}
					}
				}   
			} else {
				"[CompressCollectFilesForTimePeriod] No files found: $pathFilesToCollect" | WriteTo-StdOut -ShortFormat
			}
		} else {
			"[CompressCollectFilesForTimePeriod] Path not found: $pathFilesToCollect" | WriteTo-StdOut -ShortFormat
		}
		if (($TempFolder -ne $null) -and ($TempFolder.Exists)) {$TempFolder.Delete($true)}
} #ForEach 	
	if (($FileFormat -eq ".zip") -and (Test-Path $CompressedFileName) -and (-not $DoNotCollectFile.IsPresent))
	{
		# Now check to see if this is a DPM Errorlog zipped file. if so remove the .zip extension
		# NOTE: The statement below is case sesitive with files

		# if ([System.IO.Path]::GetFileNameWithoutExtension($CompressedFileName).Contains("DPM_Error_Logs"))
		if ([System.IO.Path]::GetFileNameWithoutExtension($CompressedFileName).Contains("DPM_Error_Logs"))
		{
			if ($debug -eq $true) {[void]$shell.popup("Inside of rename")}
			[System.IO.File]::Move($CompressedFileName, $DestinationFileName)
			$CompressedFilename = [System.IO.Path]::GetFileNameWithoutExtension($CompressedFileName)
		}		
        "[CompressCollectFilesForTimePeriod] Calling CollectFiles with following parameters: -fileToCollect " +  $CompressedFileName | WriteTo-StdOut -ShortFormat
        CollectFiles -filesToCollect $CompressedFileName -fileDescription $fileDescription -sectionDescription $sectionDescription 
	}
	
	if ($FileFormat -eq ".cab")
	{
		if ($FilestobeCollected -ne $null) 
		{
			$ListOfFilesonDDF | Out-File -FilePath $ddfFilename -Encoding "UTF8" -Append;
			if ($ForegroundProcess.IsPresent)
			{
				Runcmd -commandToRun ($env:windir + "\system32\cmd.exe /c " +$env:windir + "\system32\makecab.exe /f `"" + $ddfFilename + "`" >nul") -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -noFileExtensionsOnDescription ($noFileExtensionsOnDescription.IsPresent -eq $true) -Verbosity $Verbosity
				Remove-Item $ddfFilename
			} else {
				if ($noFileExtensionsOnDescription.IsPresent -eq $true)
				{
					BackgroundProcessCreate -ProcessName ($env:windir + "\system32\cmd.exe") -Arguments ("/c "+ $env:windir + "\system32\makecab.exe /f `"" + $ddfFilename + "`" >nul & del `"$ddfFilename`"") -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -Verbosity $Verbosity -noFileExtensionsOnDescription
				} else {
					BackgroundProcessCreate -ProcessName ($env:windir + "\system32\cmd.exe") -Arguments ("/c "+ $env:windir + "\system32\makecab.exe /f `"" + $ddfFilename + "`" >nul & del `"$ddfFilename`"") -fileDescription $fileDescription -sectionDescription $sectionDescription -filesToCollect $CompressedFileName -Verbosity $Verbosity -noFileExtensionsOnDescription
				}
			}
		} else {
			Remove-Item $ddfFilename
		}
	} 
}


# SIG # Begin signature block
# MIIjlQYJKoZIhvcNAQcCoIIjhjCCI4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDeFwd2F9VmmHqH
# TejgItKyMXFav9ep76excemhMz5bjaCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVajCCFWYCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBpDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgyAH1QaQv
# 7pVMaihn4HZrZOcQq6iyV+zVJGRmHZDfgM4wOAYKKwYBBAGCNwIBDDEqMCigCIAG
# AFQAUwBToRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20gMA0GCSqGSIb3DQEB
# AQUABIIBAGUu4B8TtAtlC915+QZYU3UgjoLaVrkbvUMbuTpJMOrBXTB+EONHxmtc
# 6T7m3VUxt1v74hdL8ij9iPsbbnY3Kca5BJd6JIQCY7CLgQGPqSda8A4rS4sDCAfc
# q1dit42/gJ/uuxdaMxUovJ14jPOTSTmn6t2CJNXvfQcjRiVUAqDRP0s4+GgfZtBE
# WOBQ9tDWh9DBPpoO1cnb1v5QsH35dHsn+HwJLYgUCs7M7A4AN9dvuV112PPm9AiL
# tj0w9vFQomTiDRBK8tdrkwynN4DtW2ZiX2Atd0WNYf0DNg1dnueGxIF2RMFqDWkm
# VkC6xrDkqkq/LLwBWbwxaBy4C3dh89ihghL+MIIS+gYKKwYBBAGCNwMDATGCEuow
# ghLmBgkqhkiG9w0BBwKgghLXMIIS0wIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBWQYL
# KoZIhvcNAQkQAQSgggFIBIIBRDCCAUACAQEGCisGAQQBhFkKAwEwMTANBglghkgB
# ZQMEAgEFAAQgojvEBrz6EcSgw9BU5NSGLt0xDMvpCD9JU6uCzQX+F/kCBmGDCPNZ
# 5RgTMjAyMTExMTExNjUzMzguMDI3WjAEgAIB9KCB2KSB1TCB0jELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IEly
# ZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# TjpGQzQxLTRCRDQtRDIyMDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaCCDk0wggT5MIID4aADAgECAhMzAAABQCMZ1l7elSQxAAAAAAFAMA0G
# CSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIw
# MTAxNTE3MjgyNloXDTIyMDExMjE3MjgyNlowgdIxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9w
# ZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RkM0MS00
# QkQ0LUQyMjAxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCufWszcerVL03TPxH5gqpm
# 7bnKSTk6VPxOy7C10FbIMJEWgBKT18HqyIKiUWFcGHJ6PhzfIjA3RTIlYE5MCMe1
# 44hiN8KnHnf2tuAEjn8FMe0L6pwFPt+0+SdO1Cfz2U05yk/vR+5hVkuhCwOcuMbH
# G1b95V7BHlDQjWZZB8nLnE596WTk5aPPdhXgcq2rIhHMll39HNxjzDqqbOhI2xgh
# 2+WJPZ55BlvJhN0lCxGjMgpMwsIlQF9WOjDZ8kwO3MMH1cQ51+E9bO9Q5p1iCqqH
# SWyUBHs1X3QUWZmBlYBGsbyPtmdWcLkw5c5L80jnxLjzJyy6DSk3Y0YsuTZhaPEL
# AgMBAAGjggEbMIIBFzAdBgNVHQ4EFgQUNUMcLiZ3RiCOjNKqdWz454QtDmcwHwYD
# VR0jBBgwFoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZF
# aHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGlt
# U3RhUENBXzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcw
# AoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQ
# Q0FfMjAxMC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEF
# BQcDCDANBgkqhkiG9w0BAQsFAAOCAQEAYwxSraBC4IL3CvhiEhJ8/Khto1hXc6/h
# jBaxJ8jP+PXFo31O8sAHYHE+LYK1FuBsFR/jyfTvJF5kifC7avy/Aug0bZO1jN7L
# TUNHKOOw2iIcX1S5EsXIpkKGQoLej2vQ7LbHRhiNSkPFUKFnmrlwB/DzzjA/SJRx
# icooafx4nSfCmvvOv9OW74c6NcNP0LvnhpLgpQU2bwPuLC69ZbNI5WXtcxZ27zYG
# edOYHuzY5x/cjhp0bN2LFDlnHFrfM4C8rOtX7QdxVAhjdJAn0/OMNGXMK+IxOHED
# wVQhEvcWdiq9yFaQShnjDxLsWwZY2VctZDt8cxveXiCO54fI7inq1TCCBnEwggRZ
# oAMCAQICCmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1
# MDcwMTIxNDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ
# 1aUKAIKF++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP
# 8WCIhFRDDNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRh
# Z5FfgVSxz5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39
# dx898Fd1rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2
# iAg16HgcsOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGj
# ggHmMIIB4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xG
# G8UzaFqFbVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGG
# MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186a
# GMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3Br
# aS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsG
# AQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB
# /wSBlTCBkjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUF
# BwICMDQeMiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0A
# ZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFv
# s+umzPUxvs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5
# U4zM9GASinbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFS
# AK84Dxf1L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1V
# ry/+tuWOM7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6
# f32WapB4pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35j
# WSUPei45V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHa
# sFAeb73x4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLN
# HfS4hQEegPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4
# sanblrKnQqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHX
# odLFVeNp3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUe
# CLraNtvTX4/edIhJEqGCAtcwggJAAgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IEly
# ZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# TjpGQzQxLTRCRDQtRDIyMDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaIjCgEBMAcGBSsOAwIaAxUAQqXmHvITpjsyl+YykRtDOQlyUVOggYMw
# gYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUF
# AAIFAOU3aiAwIhgPMjAyMTExMTExODA4MzJaGA8yMDIxMTExMjE4MDgzMlowdzA9
# BgorBgEEAYRZCgQBMS8wLTAKAgUA5TdqIAIBADAKAgEAAgIO7wIB/zAHAgEAAgIR
# dzAKAgUA5Ti7oAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBANEyD5Ljo9OQ
# SWXH6IHTDCTITSyNr8EZKXoanwHFhGnSBciAXIHmbeZcwwlqaoeK8yp5GTyXexIE
# xobyFbrdHl1wWVAfcRR9rnOnWx7R0oXpHgReDLdwHLySbSrsQ63ofwwGM/S5XEuK
# vlErjLYXNIKHIZt8CY6YPtFDCASWrRrAMYIDDTCCAwkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFAIxnWXt6VJDEAAAAAAUAwDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgU2WRC8II+7+LaksmpsYOCnjlOXDXkkmnCFEiB2v4GZcwgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAvNrC16szSpFwk7/Ny8lPt2j/JynxFmxFJ
# Oqq2AgiXgzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABQCMZ1l7elSQxAAAAAAFAMCIEIBBMG02OYr9XqrlepsjPw+b55xQrKrger77b
# WRAMxNnzMA0GCSqGSIb3DQEBCwUABIIBAGsqO9C8nVyijNKL4eSI/ed2cd7p1WIK
# Rh3QbpnrRxYfTKbDlvep4iGOD8MQc72qLJeU6XLzGQHSvh1oXda6gRdrnodNkDA4
# sZf2CCPJ6FJt+y4nwmXA+RNXADPLVzLsbsgNcuJF/J3htccNZWvTlmWsi5UR8bou
# PuM52c2aIjKEhWZ1/nAJX0EBQtx8OrIa48Hh0iKZx2mPushCd4X7ZT4n85lN5n49
# JsPvt2tcxWXfZcgwv+c4RpBHt2Xu/a+MiF0ka2L44uFosECBYS2yaQoTg3l9M2XO
# 7Fa9h6q03myqNjM8OiIwXX6lw9jWMk6O8lPKs6nrKRwg9ztb6cUOiCw=
# SIG # End signature block
