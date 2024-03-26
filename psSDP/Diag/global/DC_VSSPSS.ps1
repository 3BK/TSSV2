#************************************************
# DC_VSSPSS
# Date: 05/18/2012
# Author: jasonf, randym
# Description:  based on VSSPSS.vbs writen By Will Effinger and Dennis Middelton
#************************************************
Import-LocalizedData -BindingVariable VSSBackupVSSPSSStrings

$VSSPSSVersion = "1.1"
$strComputer = $computername
$file = New-Item -type file "$($strComputer)_VSSPSS.txt" -force | Out-Null #_#
$systeminfo = Get-CimInstance -computer $strComputer -Class Win32_ComputerSystem | Select-Object Name, Manufacturer, Model, SystemType, Description, NumberOfProcessors, NumberOfLogicalProcessors, TotalPhysicalMemory
$OSInfo = Get-CimInstance -computer $strComputer -Class Win32_operatingSystem | Select-Object Caption,CSDVersion,OSArchitecture
$RC_DirtyBitErrorDetected = $false
$RC_DefragErrorDetected = $false
$RC_ServicesErrorDetected = $false
$RC_VSSProviderErrorDetected = $false
$RC_ClustersizeErrorDetected = $false
$RC_4kDriveCheckDetected = $false
$arrErrors = @()

add-content $file " "
add-content $file "------------------------------------"
add-content $file "System Information"
add-content $file "------------------------------------"
$SystemInformationCollected = New-Object PSobject

$name = $systeminfo.name
Add-Member -InputObject $SystemInformationCollected -MemberType NoteProperty -Name "Name" -Value $name
add-content $file -value "Name                    : $Name"
Add-Member -InputObject $SystemInformationCollected -MemberType NoteProperty -Name "Operating System" -Value $OSInfo.Caption
Add-Content $file "Operating System        : $($OSInfo.Caption)"
Add-Member -InputObject $SystemInformationCollected -MemberType NoteProperty -Name "Service Pack" -Value $OSInfo.CSDVersion
Add-Content $file "Service Pack            : $($OSInfo.CSDVersion)"
$Manufactor = $systeminfo.Manufacturer
Add-Member -InputObject $SystemInformationCollected -MemberType NoteProperty -Name "Manufacturer" -Value $Manufactor
add-content $file "Manufacturer            : $Manufactor"
$Model = $systeminfo.Model
Add-Member -InputObject $SystemInformationCollected -MemberType NoteProperty -Name "Model" -Value $Model
add-content $file "Model                   : $model"
$Systemtype = $systeminfo.Systemtype
Add-Member -InputObject $SystemInformationCollected -MemberType NoteProperty -Name "OS Architecture" -Value $Systemtype
add-content $file "OS Architecture         : $Systemtype"
$Desciption = $systeminfo.Desciption
Add-Member -InputObject $SystemInformationCollected -MemberType NoteProperty -Name "Description" -Value $Desciption
add-content $file "Description             : $Desciption"
$NumberofProcessors = $systeminfo.NumberofProcessors
Add-Member -InputObject $SystemInformationCollected -MemberType NoteProperty -Name "Processors" -Value $NumberofProcessors
add-content $file "Processors              : $NumberofProcessors"
$NumberOfLogicalProcessors = $systeminfo.NumberOfLogicalProcessors
Add-Member -InputObject $SystemInformationCollected -MemberType NoteProperty -Name "Logical Processors" -Value $NumberOfLogicalProcessors
add-content $file "Logical Processors      : $NumberOfLogicalProcessors"
$TotalPhysicalMemory = formatbytes -bytes $systeminfo.TotalPhysicalMemory
Add-Member -InputObject $SystemInformationCollected -MemberType NoteProperty -Name "Total Physical Memory" -Value $TotalPhysicalMemory
#add-content $file ("Total Physical Memory   : " + "{0:0.00}GB" -f ($systeminfo.TotalPhysicalMemory/1gb))
add-content $file "Total Physical Memory   : $TotalPhysicalMemory"

$sectionDisplayOrder = 1
$sectionDescription = "System Information"
$SystemInformationCollected | ConvertTo-Xml2 | update-diagreport -id $sectionDisplayOrder -name $sectionDescription

function convert-FileInfoToTable ($Filename)
{
	$FileInfo = (Get-Command $Filename).FileVersionInfo
	$fileInfoVer = (Get-Item $Filename).VersionInfo | ForEach-Object {("FileVersion     : {0}.{1}.{2}.{3}" -f $_.ProductMajorPart,$_.ProductMinorPart,$_.ProductBuildPart,$_.ProductPrivatePart)}
	$Table = "<table>"
	$Table += "<tr><td>File Path</td><td>" + $FileInfo.FileName + "</td></tr>"
	#$Table += "<tr><td>OriginalFileName</td><td>" + $FileInfo.OriginalFileName + "</td></tr>"
	$Table += "<tr><td>Description</td><td>" + (Replace-XMLChars $FileInfo.FileDescription) + "</td></tr>" 
	$Table += "<tr><td>Product Version</td><td>" + $fileInfoVer + "</td></tr>"
	#$Table += "<tr><td>Product Language</td><td>" + $FileInfo.Language + "</td></tr>"
	$Table += "</table>"
	return $Table
}

$VSSVC = "$env:SystemRoot\System32\VSSVC.EXE"
$VSSAPI = "$env:SystemRoot\System32\vssapi.dll"
$SWPRV = "$env:SystemRoot\System32\swprv.dll"
$VSS_PS = "$env:SystemRoot\System32\vss_ps.dll"
$NTOSKRNL = "$env:SystemRoot\System32\ntoskrnl.exe"
$ES = "$env:SystemRoot\System32\es.dll"
$EVENTCLS = "$env:SystemRoot\System32\eventcls.dll"
$PARTMGR = "$env:SystemRoot\System32\drivers\partmgr.sys"
$STORPORT = "$env:SystemRoot\System32\drivers\storport.sys"


$arrFiles = @($VSSVC, $VSSAPI, $SWPRV, $VSS_PS, $NTOSKRNL, $ES, $EVENTCLS, $PARTMGR, $STORPORT)

$FileInformationCollected = New-Object PSObject

Foreach ($_ in $arrFiles)
{
      Add-Member -InputObject $FileInformationCollected -MemberType NoteProperty -Name (Split-Path $_ -Leaf) -Value (convert-FileInfoToTable $_)
}

$sectionDisplayOrder = 2
$sectionDescription = "File Information"
$FileInformationCollected | ConvertTo-Xml2 | update-diagreport -id $sectionDisplayOrder -name $sectionDescription

add-content $file " "
add-content $file " "
add-content $file "------------------------------------"
add-content $file "File Information"
add-content $file "------------------------------------"

foreach($arrfile in $arrFiles)
{
	$fileInfo1 = ((Get-Command $arrfile).FileVersionInfo | Select-Object FileName,OriginalFilename,FileDescription,ProductName | Format-List | Out-String ).Trim()
	add-content $file $fileInfo1
	$fileInfo2 = (Get-Item $arrfile).VersionInfo | ForEach-Object {("FileVersion     : {0}.{1}.{2}.{3}" -f $_.ProductMajorPart,$_.ProductMinorPart,$_.ProductBuildPart,$_.ProductPrivatePart)}
	add-content $file $fileInfo2
	add-content $file "------------------------------------"

}
#add-content $file (Get-Command $env:SystemRoot\System32\VSSVC.EXE).FileVersionInfo
#add-content $file "------------------------------------"
#add-content $file (Get-Command $env:SystemRoot\System32\vssapi.dll).FileVersionInfo
#add-content $file "------------------------------------"
#add-content $file (Get-Command $env:SystemRoot\System32\swprv.dll).FileVersionInfo
#add-content $file "------------------------------------"
#add-content $file (Get-Command $env:SystemRoot\System32\vss_ps.dll).FileVersionInfo
#add-content $file "------------------------------------"
#add-content $file (Get-Command $env:SystemRoot\System32\ntoskrnl.exe).FileVersionInfo
#add-content $file "------------------------------------"
#add-content $file (Get-Command $env:SystemRoot\System32\es.dll).FileVersionInfo
#add-content $file "------------------------------------"
#add-content $file (Get-Command $env:SystemRoot\System32\eventcls.dll).FileVersionInfo
#add-content $file "------------------------------------"
#add-content $file (Get-Command $env:SystemRoot\System32\drivers\partmgr.sys).FileVersionInfo
#add-content $file "------------------------------------"
#add-content $file (Get-Command $env:SystemRoot\System32\drivers\Storport.sys).FileVersionInfo

function convert-DiskInfoToTable ($Disk)
{
	$Table = "<table>"
	$Table += "<tr><td>Name</td><td>" + $Disk.name + "</td></tr>"
	$Table += "<tr><td>Model</td><td>" + $Disk.Model + "</td></tr>"
	$Table += "<tr><td>Bytes per Sector</td><td>" + $Disk.BytesPerSector + "</td></tr>" 
	$Table += "<tr><td>Signature</td><td>" + "{0:X}" -f $Disk.Signature + "</td></tr>"
	$Table += "</table>"
	return $Table
}

$DiskInformationCollected = New-Object PSObject
Write-DiagProgress -Activity $VSSBackupVSSPSSStrings.ID_VSSBackupPkg_VSSPSS_Obtaining_DiskVolume -Status $VSSBackupVSSPSSStrings.ID_VSSBackupPkg_VSSPSS_Obtaining_DiskVolumeDesc
add-content $file "------------------------------------"
add-content $file "Physical Disk Information"
add-content $file "------------------------------------"
$colItems = Get-CimInstance -computer $strComputer -Class Win32_DiskDrive | Select-Object Name, Model, BytesPerSector, SCSILogicalUnit, Signature
foreach ($objItem in $colItems)
{
	$diskname = $objItem.name
	add-content $file "Name            : $diskname"
	$diskmodel = $objItem.Model
	add-content $file "Model           : $diskmodel"
	$BytesPerSector = $objItem.BytesPerSector
	add-content $file "Bytes/Sector    : $BytesPerSector"
	
	#4096 bytes per sector check
	If ($BytesPerSector -eq "4096")
	{
		$RC_4kDriveCheckDetected = $true
		$arrErrors += "ERROR: 4k Advanced Format Disks are not supported as backup destination. (See KB2510009)."
		$arrErrors += "------------------------------------"
		$arrErrors += ""
		#add-content $file "ERROR: 4k Advanced Format Disks are not supported as backup destination. (See KB2510009)."
		#add-content $file "------------------------------------"
		#add-content $file ""
	}
	$hexsig = "{0:X}" -f $objItem.Signature
	add-content $file "Signature       : $($hexsig)"
	add-content $file ""
	Add-Member -InputObject $DiskInformationCollected -MemberType NoteProperty -Name (Split-Path $objItem.name -leaf) -Value (convert-DiskInfoToTable $objItem)

}
$sectionDisplayOrder = 3
$sectionDescription = "Physical Disk Information"
$DiskInformationCollected | ConvertTo-Xml2 | update-diagreport -id $sectionDisplayOrder -name $sectionDescription


function convert-MountvolInfoToTable ($MountvolItem)
{
	$mountvoldirectory = Replace-XMLChars -RAWString (($MountvolItem.Directory).Substring(21))
	$mountvolvolume = Replace-XMLChars -RAWString (($MountVolItem.Volume).Substring(22))
	$Table = "<table>"
	$Table += "<tr><td>Drive Letter</td><td>" + $mountvoldirectory + "</td></tr>"
	$Table += "<tr><td>Mountvol Entry</td><td>" + $mountvolvolume + "</td></tr>"
	$Table += "</table>"
	return $Table
}
$MountvolInformationCollected = New-Object PSObject

add-content $file "------------------------------------"
add-content $file "Mountvol Information"
add-content $file "------------------------------------"
add-content $file ""

$mountvol = Get-CimInstance -computer $strComputer -Class Win32_Mountpoint | Select-Object Directory, Volume

foreach ($objItem in $mountvol)
{
	$DirectoryRaw = $objItem.Directory
	$DirectoryTrim = $DirectoryRaw.Substring(21)
	add-content $file $DirectoryTrim

	$volumeRaw = $objItem.Volume
	$volumeTrim = $volumeRaw.Substring(22)
	add-content $file $volumeTrim
	add-content $file ""
	$mountvolitemdetected += 1
	Add-Member -InputObject $MountvolInformationCollected -MemberType NoteProperty -Name ($mountvolitemdetected) -Value (convert-MountvolInfoToTable $objItem)
}

$sectionDisplayOrder = 4
$sectionDescription = "Mountvol Information"
$MountvolInformationCollected | ConvertTo-Xml2 | update-diagreport -id $sectionDisplayOrder -name $sectionDescription


function convert-VolumeInfoToTable ($objvolume, $objdefraganalysis)
{
	$Table = "<table>"
	$Table += "<tr><td>Drive</td><td>" + $objvolume.DriveLetter + "</td></tr>"
	$Table += "<tr><td>File System</td><td>" + $objvolume.FileSystem + "</td></tr>"
	$Table += "<tr><td>Volume Size</td><td>" + "{0:0.00}GB" -f ($objdefraganalysis.VolumeSize/1GB) + "</td></tr>"
	$Table += "<tr><td>Free Space Percent</td><td>" + $objdefraganalysis.FreeSpacePercent + "</td></tr>"
	$Table += "<tr><td>Free Space Frag. Percent</td><td>" + $objdefraganalysis.FreeSpacePercentFragmentation + "</td></tr>"
	$Table += "<tr><td>Files</td><td>" + $objdefraganalysis.TotalFiles + "</td></tr>"
	$Table += "<tr><td>Fragmented Files</td><td>" + $objdefraganalysis.TotalFragmentedFiles + "</td></tr>"
	$Table += "<tr><td>File Fragmentation Percent</td><td>" + $objdefraganalysis.FilePercentFragmentation + "</td></tr>"
	$Table += "<tr><td>Folders</td><td>" + $objdefraganalysis.TotalFolders + "</td></tr>"
	$Table += "<tr><td>Fragmented Folders</td><td>" + $objdefraganalysis.FragmentedFolders + "</td></tr>"
	$Table += "<tr><td>MFT Usage Percent</td><td>" + $objdefraganalysis.MFTPercentInUse + "</td></tr>"
	$Table += "<tr><td>MFT Fragments</td><td>" + $objdefraganalysis.TotalMFTFragments + "</td></tr>"
	$Table += "<tr><td>MFT Records</td><td>" + $objdefraganalysis.MFTRecordCount + "</td></tr>"
	$Table += "<tr><td>PageFile Size</td><td>" + "{0:0.00}GB" -f ($objdefraganalysis.PageFileSize/1GB) + "</td></tr>"
	$Table += "<tr><td>PageFile Fragments</td><td>" + $objdefraganalysis.TotalPageFileFragments + "</td></tr>"
	$Table += "</table>"
	return $Table
}

$volumeInformationCollected = New-Object PSObject

add-content $file "------------------------------------"
add-content $file "Volume Information"
add-content $file "------------------------------------"
add-content $file ""

Write-DiagProgress -Activity $VSSBackupVSSPSSStrings.ID_VSSBackupPkg_VSSPSS_Obtaining_Defrag -Status $VSSBackupVSSPSSStrings.ID_VSSBackupPkg_VSSPSS_Obtaining_DefragDesc
# Defrag Info
$volumes = @(Get-CimInstance Win32_Volume -ComputerName $strComputer -Filter 'DriveType = 3')
  
foreach ($volume in $volumes) 
{
	$analysis = $volume.DefragAnalysis().DefragAnalysis
	add-content $file   "Drive               : $($volume.DriveLetter)"
	add-content $file  "File System         : $($volume.FileSystem)"
	add-content $file  ("Volume Size         : " + "{0:0.00}GB" -f ($analysis.VolumeSize/1GB))
	add-content $file  ""
	add-content $file  "Free Space          : $($analysis.FreeSpacePercent)%"
	add-content $file  ("Free Space Frag.    : " + "$($analysis.FreeSpacePercentFragmentation)%")
	add-content $file  ""
	add-content $file  "Files               : $($analysis.TotalFiles)"
	add-content $file  "Fragmented Files    : $($analysis.TotalFragmentedFiles)"
	add-content $file  "File Fragmentation  : $($analysis.FilePercentFragmentation)%"
	add-content $file  ""
	add-content $file  "Folders             : $($analysis.TotalFolders)"
	add-content $file  "Fragmented Folders  : $($analysis.FragmentedFolders)"
	add-content $file  ""
	add-content $file  "MFT Usage           : $($analysis.MFTPercentInUse)%"
	add-content $file  "MFT Fragments       : $($analysis.TotalMFTFragments)"
	add-content $file  "MFT Records         : $($analysis.MFTRecordCount)"
	add-content $file  ""
	add-content $file  ("PageFile Size       : " + "{0:0.00}GB" -f ($analysis.PageFileSize/1GB))
	add-content $file  "PageFile Fragments  : $($analysis.TotalPageFileFragments)"
	add-content $file  ""
	add-content $file  "----------------------------"
	$Driveletter = $volume.driveletter
	# checking for fragmentation
	If ($analysis.FilePercentFragmentation -gt "10")
	{
		$RC_DefragErrorDetected = $true
		$arrErrors += "ERROR: Volume $($volume.DriveLetter) needs to be defragmented for proper operation."
		$arrErrors += "------------------------------------"
		$arrErrors += ""
		#add-content $file "ERROR: Volume $($volume.DriveLetter) needs to be defragmented for proper operation."
		#add-content $file "------------------------------------"
		#add-content $file ""
	}
	$volumedetectednumber += 1
		Add-Member -InputObject $volumeInformationCollected -MemberType NoteProperty -Name $volumedetectednumber -Value (convert-VolumeInfoToTable -objvolume $volume -objDefragAnalysis $analysis)
}

$sectionDisplayOrder = 5
$sectionDescription = "Volume Information"
$volumeInformationCollected | ConvertTo-Xml2 | update-diagreport -id $sectionDisplayOrder -name $sectionDescription

# Checking cluster size vs size of volume 
 
Foreach ($volume in $volumes)
{
	if (($volume.filesystem -eq "NTFS" -and $volume.blocksize -gt 4096 -and $volume.Capacity -lt 2147483648) -or
	($volume.filesystem -eq "NTFS" -and $volume.blocksize -gt 8192 -and $volume.Capacity -lt 17592186044416) -or 
	($volume.filesystem -eq "NTFS" -and $volume.blocksize -gt 16536 -and $volume.Capacity -lt 35184372088832) -or
	($volume.filesystem -eq "NTFS" -and $volume.blocksize -gt 32768 -and $volume.Capacity -lt 70368744177664) -or
	($volume.filesystem -eq "NTFS" -and $volume.blocksize -gt 65536 -and $volume.Capacity -lt 140737488355328))
	{
		$RC_ClustersizeErrorDetected = $true
		add-content $file "VOLUME ERROR: $($volume.Driveletter) $($Volume.DriveLetter) -- The cluster size is too small for efficient VSS snapshot operation (see KB140365)."
		add-content $file  ""
		add-content $file  "----------------------------"
		$arrErrors += "VOLUME ERROR: $($volume.Driveletter) $($Volume.DriveLetter) -- The cluster size is too small for efficient VSS snapshot operation (see KB140365)."
		$arrErrors += "------------------------------------"
		$arrErrors += ""
	}
	# checking for the dirty bit being set and providing an error
	if ($volume.DirtyBitSet -eq "True")
	{
		$RC_DirtyBitErrorDetected = $true
		#add-content $file "ERROR: Run CHKDSK on volume $($volume.DriveLetter)"
		#add-content $file "------------------------------------"
		$arrErrors += "ERROR: Run CHKDSK on volume $($volume.DriveLetter)"
		$arrErrors += "------------------------------------"
		$arrErrors += ""
	}
}

Write-DiagProgress -Activity $VSSBackupVSSPSSStrings.ID_VSSBackupPkg_VSSPSS_Obtaining_Provider -Status $VSSBackupVSSPSSStrings.ID_VSSBackupPkg_VSSPSS_Obtaining_ProviderDesc

add-content $file "------------------------------------"
add-content $file "VSS Providers"
add-content $file "------------------------------------"
add-content $file ""

if((Get-CimInstance -Class Win32_OperatingSystem).ProductType -ge 2)
{
	$vssproviders = Get-CimInstance -computer $strComputer -Class Win32_ShadowProvider | Select-Object Name, Version, CLSID

	foreach ($objItem in $vssproviders)
	{
		$ProviderName = $objItem.Name
		add-content $file "Name     : $ProviderName"

		$ProviderVersion = $objItem.Version
		add-content $file "Version  : $ProviderVersion"

		$providerCLSID = $objItem.CLSID
		add-content $file "CLSID    : $providerCLSID"
		add-content $file ""
	}
}

Write-DiagProgress -Activity $VSSBackupVSSPSSStrings.ID_VSSBackupPkg_VSSPSS_Obtaining_VSSStorage  -Status $VSSBackupVSSPSSStrings.ID_VSSBackupPkg_VSSPSS_Obtaining_VSSStorageDesc

add-content $file "------------------------------------"
add-content $file "Listing Shadow Copy Storage"
add-content $file "------------------------------------"
add-content $file ""

if((Get-CimInstance -Class Win32_OperatingSystem).ProductType -ge 2)
{
	$shadowCount = Get-CimInstance -computer $strComputer -class win32_shadowcopy
	$ShadowStorage = Get-CimInstance -computer $strComputer -Class Win32_ShadowStorage | Select-Object Volume, AllocatedSpace, DiffVolume, MaxSpace, UsedSpace
	#Collect writer information 
	$tmpdiskshadowscriptfile = join-path $pwd.path "tmpdiskshadowscriptfile.txt"

	"list writers detailed" | out-file $tmpdiskshadowscriptfile -encoding ASCII

	Write-DiagProgress -Activity $VSSBackupVSSPSSStrings.ID_VSSBackupPkg_VSSPSS_Writers -Status $VSSBackupVSSPSSStrings.ID_VSSBackupPkg_VSSPSS_WritersDesc

	$fileDescription = "DiskShadow list writers detailed output"
	$sectionDescription = "VSS Writers"
	$DiskShadowOutputFile = join-path $pwd.path ($ComputerName + "_WriterMetaData.txt")
	$CommandToExecute = "cmd.exe /c diskshadow /s `"$tmpdiskshadowscriptfile`" /l `"$DiskShadowOutputFile`""
	RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $DiskShadowOutputFile -fileDescription $fileDescription 
	Remove-Item $tmpdiskshadowscriptfile
	
	$fileDescription = "VSSAdmin list writers output"
	$VSSAdminOutputFile = join-path $pwd.path ($ComputerName + "_List_Writers.txt")
	$CommandToExecute = "cmd.exe /c vssadmin list writers > `"$VSSAdminOutputFile`""
	RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $VSSAdminOutputFile -fileDescription $fileDescription 

	foreach ($objItem in $ShadowStorage)
	{
		$ShadowVolumeRaw = $objItem.Volume
		$ShadowVolume = $ShadowVolumeRaw.Substring(22)
		add-content $file "Volume              : $shadowVolume"

		$ShadowDiff = $objItem.DiffVolume
		add-content $file "Diff Voluem          : $shadowDiff"

		$ShadowAllocated = $objItem.AllocatedSpace /1mb
		add-content $file "Space Allocated      : $ShadowAllocated /Mb"

		$ShadowMaxSpaceRaw = $objItem.MaxSpace / 1mb
		add-content $file "Max Space            : $ShadowMaxSpace /Mb"

		$ShadowUsed = $objItem.UsedSpace / 1mb
		add-content $file "Used Space           : $ShadowUsed /Mb"

		add-content $file "Snapshots on System    : $($shadowCount.count)"

		add-content $file "------------------------------------"
	}

	add-content $file ""
	add-content $file "------------------------------------"
	add-content $file "Test SnapShot Creation"
	add-content $file "------------------------------------"
	add-content $file ""

	$ShadowCompleted = @()
	$ShadowErrors = @()
	$arrCSVPartitions = @()
	if (test-path "hklm:/cluster")
	{
		import-module failoverclusters
		$arrCSVPartitions = Get-ClusterSharedVolume | ForEach-Object {($_.sharedvolumeinfo | Select-Object -expandproperty partition).name}
	}
		
	## Create list of volumes that are NTFS
	$Snapvolumes = Get-CimInstance -computer $strComputer -class Win32_Volume | Where-object { $_.FileSystem -match "NTFS"}

	$snapvolumesInformationCollected = New-Object PSObject
	## Create snapshot for each volume that is listed in $snapvolumes
	Foreach ($volume in $snapvolumes)
	{
		if (-not ($arrCSVPartitions -contains (($volume.Name).tostring()).trimend("\")))
		{
			$createSnapshotString = $VSSBackupVSSPSSStrings.ID_VSSBackupPkg_VSSPSS_Create_SnapshotDesc + ": " + $volume.Name
			#Write-DiagProgress -activity $VSSBackupVSSPSSStrings.ID_VSSBackupPkg_VSSPSS_Create_Snapshot -status ($VSSBackupVSSPSSStrings.ID_VSSBackupPkg_VSSPSS_Create_SnapshotDesc -replace ("%VolumeName%", $volume.name))
			Write-DiagProgress -Activity $VSSBackupVSSPSSStrings.ID_VSSBackupPkg_VSSPSS_Create_Snapshot -Status $createSnapshotString
			$newsnap = (Get-CimInstance -computer $strComputer -list win32_shadowcopy).Create($volume.name,"ClientAccessible")

			if ($($newsnap.ReturnValue) -eq "0")
			{
				#Write to log if success
				Add-content $file "VSS Provider Test      : SUCCESS -- Volume:  $($volume.name) SnapShot ID:  $($newsnap.ShadowID)"
			}

			if ($($newsnap.ReturnValue) -ne "0")
			{
				Add-Content $file "VSS Provider Test      : Failed -- Volume:  $($volume.name)"
				$arrErrors += "VSS Provider Test      : Failed -- Volume:  $($volume.name)"
				$RC_VSSProviderErrorDetected = $true
				Add-Member -InputObject $snapvolumeInformationCollected -MemberType NoteProperty -Name $volume.name -Value "Error - Snapshot Creation Returned $newsnap.ReturnValue"
			}

			$colItems = Get-CimInstance -computer $strComputer -class Win32_ShadowCopy

			Foreach ($objItem in $colItems)
			{
				#Match the Shadow created above to an existing snapshot on the volume and delete
				If ($objItem.ID -match $newsnap.ShadowID)
				{
					$objItem.Delete()
				}
			}
		}
		else
		{
			Add-content $file "VSS Provider Test      : CSV Detected - skipping -- Volume:  $($volume.name)"
		}
	}

	add-content $file "------------------------------------"
	add-content $file "Listing VSS Service"
	add-content $file "------------------------------------"
	add-content $file ""

	$vssService = Get-Service -computer $strComputer VSS,eventsystem,CryptSvc,SWPRV,COMSysApp,VDS |	Select-Object Name, Status

	foreach ($service in $vssService)
	{
		Add-Content $file "Service Name: $($service.Name) Status: $($Service.Status)"
	}

	add-content $file ""
	add-content $file "------------------------------------"
	add-content $file "Errors"
	add-content $file "------------------------------------"
	add-content $file ""

	Add-Content $file $arrErrors 

	$ServicesInformationCollected = New-Object PSObject
	function ServiceStartType($servicename,$Starttype)
	{
		$StartTemp = (Get-CimInstance -computer $strComputer -class Win32_Service -filter "Name='$servicename'").StartMode
		If ($StartTemp -ne $Starttype)
		{
			Add-content $file "SERVICE ERROR: $($servicename) service start type should be $($Starttype)"
			Add-Member -
			Add-Member -InputObject $ServicesInformationCollected -MemberType NoteProperty -Name $servicename -Value $StartTemp
			return $true
		}
		else
		{
			return $false
		}
	}

	$VSSIncorrectServiceStartType = ServiceStartType VSS Manual
	$SWPRVIncorrectServiceStartType = ServiceStartType SWPRV Manual
	$EventSystemIncorrectServiceStartType = ServiceStartType EventSystem Auto
	$COMSysAppIncorrectServiceStartType = ServiceStartType COMSysApp Manual
	$CryptSvcIncorrectServiceStartType = ServiceStartType CryptSvc Auto
	$VDSIncorrectServiceStartType = ServiceStartType VDS Manual    
	
	if ($VSSIncorrectServiceStartType -or $SWPRVIncorrectServiceStartType -or $EventSystemIncorrectServiceStartType -or $COMSysAppIncorrectServiceStartType -or $CryptSvcIncorrectServiceStartType -or $VDSIncorrectServiceStartType)
	{
		$RC_ServicesErrorDetected = $true
	}

	add-content $file "VSSPSS Version: $VSSPSSVersion"
}
else
{
	Write-DiagProgress -Activity $VSSBackupVSSPSSStrings.ID_VSSBackupPkg_VSSPSS_Writers -Status $VSSBackupVSSPSSStrings.ID_VSSBackupPkg_VSSPSS_WritersDesc
	$sectionDescription = "VSS Writers"
	$fileDescription = "VSSAdmin list writers output"
	$VSSAdminOutputFile = join-path $pwd.path ($ComputerName + "_List_Writers.txt")
	$CommandToExecute = "cmd.exe /c vssadmin list writers > `"$VSSAdminOutputFile`""
	RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $VSSAdminOutputFile -fileDescription $fileDescription 
}

CollectFiles -filesToCollect $file -fileDescription $VSSBackupVSSPSSStrings.ID_VSSBackupPkg_VSSPSS_resultsreportfiledesc -sectionDescription $VSSBackupVSSPSSStrings.ID_VSSBackupPkg_VSSPSS_resultsreportsectiondesc

#Rule to detect VSS provider error
$RootCauseName = "RC_VSSPSS_ProviderError"
$InternalContent = "http://bemis.partners.extranet.microsoft.com/2718662"
$Verbosity = "Error"
$Visibility = "3"
$SupportTopicsID = "7993"
$SolutionTitle = $VSSBackupVSSPSSStrings.ID_VSSPSS_VSSProviderErrorSD

Write-DiagProgress -Activity $VSSBackupVSSPSSStrings.ID_VSSPSS_VSSProviderErrorTitle -Status $VSSBackupVSSPSSStrings.ID_VSSPSS_VSSProviderErrorDesc

if ($RC_VSSProviderErrorDetected -eq $true)
{
	# Red/ Yellow Light
	Update-DiagRootCause -id $RootCauseName -Detected $true
	Write-GenericMessage -RootCauseId $RootCauseName -InternalContentURL $InternalContent -InformationCollected $snapvolumeInformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID -SolutionTitle $SolutionTitle
}
else
{
	# Green Light
	Update-DiagRootCause -id $RootCauseName -Detected $false
}


# SIG # Begin signature block
# MIInpAYJKoZIhvcNAQcCoIInlTCCJ5ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDS2x/DPwH9hzgQ
# L5YlnC8y/kUOVFLvhIf5A3aSEGxfaKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGYQwghmAAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIakaz9/YWYzv/CMkNIVGeRX
# oSlctH9QHSod3RaR6TWBMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAUaVCdGMkI0v1br3E6OdUli0nHOCeW61nghsTv1VnzIvJqRkCeH7G7
# B74icegVRSBNkcEwsJokKgBBlbP4TDMqr+90eXnfxkmYEdcJCrs+ejyVSxDcRbbr
# jNo4TUFOtFEllDcPeIxoOhWkOThLD88ULAZLZ5/w4ruMY5DTZ8oXFnLz8hWtFY7V
# o0tW8SDO+QJ5LPyB5Y65XYvSRH7kcuzZJY2Gz4Dis5i+I/r146HYWZ8DpBuN/4Gk
# W6NAx8ZUXTxqX6IL7XV9bAV9lna8ijRSerrqD9QUWpky39gzFcULMk7nt5QJwXkU
# hIIPKM2+EXKFv2lR7n3qaWfwX0n6SJIDoYIXDDCCFwgGCisGAQQBgjcDAwExghb4
# MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIBlsYjInPYy0ZR7u/OkuULbvnPYXdQPPscZKbsJbAiBsAgZi2wZs
# Wk4YEzIwMjIwODAxMDc1MTM4LjM0OVowBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0
# RDJGLUUzREQtQkVFRjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaCCEV8wggcQMIIE+KADAgECAhMzAAABsKHjgzLojTvAAAEAAAGwMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMDMw
# MjE4NTE0MloXDTIzMDUxMTE4NTE0Mlowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0RDJGLUUzREQtQkVF
# RjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAJzGbTsM19KCnQc5RC7VoglySXMKLut/
# yWWPQWD6VAlJgBexVKx2n1zgX3o/xA2ZgZ/NFGcgNDRCJ7mJiOeW7xeHnoNXPlg7
# EjYWulfk3oOAj6a7O15GvckpYsvLcx+o8Se8CrfIb40EJ8W0Qx4TIXf0yDwAJ4/q
# O94dJ/hGabeJYg4Gp0G0uQmhwFovAWTHlD1ci+sp36AxT9wIhHqw/70tzMvrnDF7
# jmQjaVUPnjOgPOyFWZiVr7e6rkSl4anT1tLv23SWhXqMs14wolv4ZeQcWP84rV2F
# rr1KbwkIa0vlHjlv4xG9a6nlTRfo0CYUQDfrZOMXCI5KcAN2BZ6fVb09qtCdsWdN
# NxB0y4lwMjnuNmx85FNfzPcMZjmwAF9aRUUMLHv626I67t1+dZoVPpKqfSNmGtVt
# 9DETWkmDipnGg4+BdTplvgGVq9F3KZPDFHabxbLpSWfXW90MZXOuFH8yCMzDJNUz
# eyAqytFFyLZir3j4T1Gx7lReCOUPw1puVzbWKspV7ModZjtN/IUWdVIdk3HPp4QN
# 1wwdVvdXOsYdhG8kgjGyAZID5or7C/75hyKQb5F0Z+Ee04uY9K+sDZ3l3z8TQZWA
# fYurbZCMWWnmJVsu5V4PR5PO+U6D7tAtMvMULNYibT9+sxVZK/WQer2JJ9q3Z7lj
# Fs4lgpmfc6AVAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUOt8BJDcBJm4dy6ASZHrX
# IEfWNj8wHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgw
# VjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWlj
# cm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUF
# BwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
# KS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQsFAAOCAgEA3XPih5sNtUfAyLnlXq6MZSpCh0TF+uG+nhIJ44//cMcQGEVi
# Z2N263NwvrQjCFOni/+oxf76jcmUhcKWLXk9hhd7vfFBhZZzcF5aNs07Uligs24p
# veasFuhmJ4y82OYm1G1ORYsFndZdvF//NrYGxaXqUNlRHQlskV/pmccqO3Oi6wLH
# cPB1/WRTLJtYbIiiwE/uTFEFEL45wWD/1mTCPEkFX3hliXEypxXzdZ1k6XqGTysG
# AtLXUB7IC6CH26YygKQuXG8QjcJBAUG/9F3yNZOdbFvn7FinZyNcIVLxld7h0bEL
# fQzhIjelj+5sBKhLcaFU0vbjbmf0WENgFmnyJNiMrL7/2FYOLsgiQDbJx6Dpy1Ef
# vuRGsdL5f+jVVds5oMaKrhxgV7oEobrA6Z56nnWYN47swwouucHf0ym1DQWHy2DH
# OFRRN7yv++zes0GSCOjRRYPK7rr1Qc+O3nsd604Ogm5nR9QqhOOc2OQTrvtSgXBS
# tu5vF6W8DPcsns53cQ4gdcR1Y9Ng5IYEwxCZzzYsq9oalxlH+ZH/A6J7ZMeSNKNk
# rXPx6ppFXUxHuC3k4mzVyZNGWP/ZgcUOi2qV03m6Imytvi1kfGe6YdCh32POgWeN
# H9lfKt+d1M+q4IhJLmX0E2ZZICYEb9Q0romeMX8GZ+cbhuNsFimJga/fjjswggdx
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
# Ooo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC0jCCAjsCAQEwgfyh
# gdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAn
# BgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjo0RDJGLUUzREQtQkVFRjElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAAp4vkN3fD5FN
# BVYZklZeS/JFPBiggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQUFAAIFAOaRYjswIhgPMjAyMjA4MDEwMDE5MDdaGA8yMDIy
# MDgwMjAwMTkwN1owdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pFiOwIBADAKAgEA
# AgIIYAIB/zAHAgEAAgIQpDAKAgUA5pKzuwIBADA2BgorBgEEAYRZCgQCMSgwJjAM
# BgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEB
# BQUAA4GBACIGRhs2npZ86ze5XX7bBRD/cJXce61yTudp0mcrK6L61CQtFKU97yxX
# 70q6VQobkjEyQHfH1Hv4CF/K4uK2KTMj1KexQaqMmfS1oHs0euVDl7Hao5qOdQzl
# rY+r47GbBQeZA0409+8Enz5PtxoLEgvTkrjuZhJN/8JtrfsuE8WfMYIEDTCCBAkC
# AQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGwoeODMuiN
# O8AAAQAAAbAwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG
# 9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgTkKMgcwXFCw9hV2SEr1hO9PRFB954Zm4
# BId67NdWANIwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCDNBgtDd8uf9KTj
# Gf1G67IfKmcNFJmeWTd6ilAy5xWEoDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAABsKHjgzLojTvAAAEAAAGwMCIEIFn307NRqWDFmauv
# lOK94kvWvU2F8vPBc3hLhZ9yD3zCMA0GCSqGSIb3DQEBCwUABIICACKFgVemw7hD
# wtMKy899ZlLU3kp7eT4jhgJzrxXEqD95EPaNLLRmCDA+rOmticRytCS6OU1ubkHv
# TBEwWRHTdXca3uLq8Wvg78FFm1vwb11+myVTg61WhxfEnmGstKhcu0ELyMD21QOS
# XqEBuQjZQV25oNVRR/DvRLOibBWGoEr9hHQsiL2OpqOGBmEVaWj8ZG0O4x7UeN6N
# ywttrreZG6mxliHIf2ToFUtJ+iVcjzJCBie3opiD0Lu60COYXvlcnNniqbGJ2r81
# Ek2oi+Bmg1Pjy1YCenoYcKihto9ln4IewPbNIrgzYA9YXJSY8hJ0T2NHgzXppnpi
# KIk2oRCul/mAb57z8Dtvyybnk16w8p6tbbkC/vmI98dwmVLiHEGK93N7SNNxhuqh
# nCddr4t3vY+rYN5EHJs6m6SUHFe+RF9tQJRBk4CD8RuCc3hRkpMUNSrVRPIQ3ELG
# EWli0etOsIEdjY+cOZhSDoqx1sRo4rHwm44gMpkuBb2etw/YZn90KYO+Bv7Sninj
# lJp0P6Atp2EBcoVHpt8jI2NeDH607i7YJVmO2oDmdkKSMND49gbF/wPGS1aH7jwG
# qh5kiiR7wXCizzbw4W68oUW1NlvnJ5ik4lo595sIZQNdCahYD4VmQSp7NS0gDtXD
# 1J6PMb7C2MpdFTUARzqIQ/o1A0k2o1Hr
# SIG # End signature block
