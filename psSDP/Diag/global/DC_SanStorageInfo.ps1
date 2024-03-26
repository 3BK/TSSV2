#region 'Old Code'
<#
if ($OSVersion.Major -eq 5)
{
	# Disabling running on Win2K3 x64 due some reports of crashes for specific controllers
	"[San.exe] - Skipping running san.exe on Windows prior to Server 2008" | WriteTo-StdOut
}
else
{
	Import-LocalizedData -BindingVariable SanStorageInfoStrings
	Write-DiagProgress -Activity $SanStorageInfoStrings.ID_SanDev -Status $DOSDevStrings.ID_SanDevRunning

	$fileDescription = $SanStorageInfoStrings.ID_SanStorageInfoOutput
	$sectionDescription = $SanStorageInfoStrings.ID_SanStorageInfoOutputDesc
	$OutputFile = $ComputerName + "_Storage_Information.txt"
	$CommandToExecute = "cmd.exe /c SAN.exe $CommandToAdd"

	RunCmD -commandToRun $CommandToExecute -sectionDescription $sectionDescription -filesToCollect $OutputFile -fileDescription $fileDescription
}
#>
#endregion

<#
	COLLECTING FOLLOWING INFORMATION:
	----------------------------------------------
	Important registry entries related to storage.
	Trim support
	Thin provisioning
	ODX support
	Device drivers and settings (if appropriate)
	DSM settings
	SCSI registry information
	SCSI inquiry information
	SCSI reservation information
	Tape Devices
	Tape Changers
	VDS information
	MPIO information
	Disk failure prediction information
	iSCSI connection information
	NTFS information
#>

Import-LocalizedData -BindingVariable SanStorageInfoStrings

Write-DiagProgress -Activity $SanStorageInfoStrings.ID_SanDev -Status $DOSDevStrings.ID_SanDevRunning

$fileDescription = $SanStorageInfoStrings.ID_SanStorageInfoOutput
$sectionDescription = $SanStorageInfoStrings.ID_SanStorageInfoOutputDesc
$OutputFile = ("{0}_StorageInfo.LOG" -f $env:COMPUTERNAME)

$temp = (Get-CimInstance -Class Win32_OperatingSystem).Version.Split('.')
[Float]$OSVersion = [Float]("$($temp[0]).$($temp[1])")
if([Float]$OSVersion -lt [Float](6.0))
{
    # Skipping collecting storage info on Windows prior to Server 2008.
    return
}

# ============================================= #
# Generic Info
# ============================================= #
"`n" | Out-File -FilePath $OutputFile -Append

$os = Get-CimInstance Win32_OperatingSystem
"{0, -17}: {1} (Build {2}) [{3}]" -f 'Operating System', ($os.Caption), ($os.BuildNumber), ($os.OSArchitecture) | Out-File -FilePath $OutputFile -Append
"{0, -17}: {1}" -f 'Processor', ((Get-CimInstance Win32_Processor).Name) | Out-File -FilePath $OutputFile -Append
"{0, -17}: {1}" -f 'Log Time', (Get-Date -Format 'HH:mm:ss yyyy/MM/dd') | Out-File -FilePath $OutputFile -Append
"`n" | Out-File -FilePath $OutputFile -Append

# ============================================= #
# VDS Alignment
# ============================================= #

$regKeyVDSAlignment = 'HKLM:\SYSTEM\ControlSet001\Services\vds\Alignment'
if(Test-Path ($regKeyVDSAlignment))
{
	'============================================='	| Out-File -FilePath $OutputFile -Append
    'VDS Alignment' 								| Out-File -FilePath $OutputFile -Append
    '============================================='	| Out-File -FilePath $OutputFile -Append
    "`n" | Out-File -FilePath $OutputFile -Append
    'INFO: Alignment Settings in Bytes'	| Out-File -FilePath $OutputFile -Append
    "`n" | Out-File -FilePath $OutputFile -Append

    'Between4_8GB', 'Between8_32GB', 'GreaterThan32GB', 'LessThan4GB' | ForEach-Object { 
     "{0,-16}: {1}" -f $_, ((Get-ItemProperty -Path $regKeyVDSAlignment -Name $_ -ErrorAction SilentlyContinue)."$_") | Out-File -FilePath $OutputFile -Append
    }
    "`n" | Out-File -FilePath $OutputFile -Append
}

# ============================================= #
# SAN Policy
# ============================================= #

Add-Type -TypeDefinition @"
    public enum SANPolicy
    {
        VDS_SP_UNKNOWN         = 0x0,
        VDS_SP_ONLINE          = 0x1,
        VDS_SP_OFFLINE_SHARED  = 0x2,
        VDS_SP_OFFLINE         = 0x3
    }
"@

$sanPolicyDescriptions = @{
'VDS_SP_UNKNOWN' = 'The SAN policy is unknown.'; 
'VDS_SP_ONLINE' = 'All newly discovered disks are brought online and made read-write.'; 
'VDS_SP_OFFLINE_SHARED' = 'All newly discovered disks that do not reside on a shared bus are brought online and made read-write.'; 
'VDS_SP_OFFLINE' = 'All newly discovered disks remain offline and read-only.'}

[SANPolicy] $sanPolicy = 0
$regKeySanPolicy = 'HKLM:\SYSTEM\CurrentControlSet\Services\partmgr\Parameters'
if(Test-Path ($regKeySanPolicy))
{
    $sanPolicyRegValue = (Get-ItemProperty -Path $regKeySanPolicy -Name 'SanPolicy' -ErrorAction SilentlyContinue).SanPolicy
    if($sanPolicyRegValue)
    {
	    '============================================='	| Out-File -FilePath $OutputFile -Append
        'SAN Policy' 									| Out-File -FilePath $OutputFile -Append
        '============================================='	| Out-File -FilePath $OutputFile -Append
        "`n" | Out-File -FilePath $OutputFile -Append

        $sanPolicy = [Enum]::ToObject([SANPolicy], $sanPolicyRegValue) 
 
        "{0} ({1}): {2}" -f $sanPolicy.value__, $sanPolicy, ($sanPolicyDescriptions.Get_Item("$sanPolicy")) | Out-File -FilePath $OutputFile -Append
        "`n" | Out-File -FilePath $OutputFile -Append
        'Refer: https://msdn.microsoft.com/en-us/library/bb525577.aspx' | Out-File -FilePath $OutputFile -Append
        "`n" | Out-File -FilePath $OutputFile -Append
    }
}

# ============================================= #
# File System Settings
# ============================================= #

$regKeyFileSystem = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'
if(Test-Path ($regKeyFileSystem))
{
    '============================================='	| Out-File -FilePath $OutputFile -Append
    'File System Settings' 							| Out-File -FilePath $OutputFile -Append
    '============================================='	| Out-File -FilePath $OutputFile -Append
    "`n" | Out-File -FilePath $OutputFile -Append

    # Trim/UnMap Support
    $regValueDisableDeleteNotification = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name 'DisableDeleteNotification' -ErrorAction SilentlyContinue
    if($regValueDisableDeleteNotification)
    {
        "{0, -38}: {1} (Trim/UnMap {2})" -f 'DisableDeleteNotification', ($regValueDisableDeleteNotification.DisableDeleteNotification), `
        (('Disabled','Enabled')[$regValueDisableDeleteNotification.DisableDeleteNotification -eq 0]) | Out-File -FilePath $OutputFile -Append
    }

    # ODX Support
    $regValueFilterSupportedFeaturesMode = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name 'FilterSupportedFeaturesMode' -ErrorAction SilentlyContinue
    if($regValueDisableDeleteNotification)
    {
        "{0, -38}: {1} (ODX {2})" -f 'FilterSupportedFeaturesMode', ($regValueFilterSupportedFeaturesMode.FilterSupportedFeaturesMode), `
        (('Disabled','Enabled')[$regValueFilterSupportedFeaturesMode.FilterSupportedFeaturesMode -eq 0]) | Out-File -FilePath $OutputFile -Append
    }

    "`n" | Out-File -FilePath $OutputFile -Append
    "`n" | Out-File -FilePath $OutputFile -Append
    'Other values from "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"' | Out-File -FilePath $OutputFile -Append

	Get-ItemProperty $regKeyFileSystem  -ErrorAction SilentlyContinue | Format-List -Property NtfsAllowExtendedCharacter8dot3Rename, NtfsBugcheckOnCorrupt, NtfsDisable8dot3NameCreation, `
    NtfsDisableCompression, NtfsDisableEncryption, NtfsDisableLastAccessUpdate, NtfsDisableLfsDowngrade, NtfsDisableVolsnapHints, NtfsEncryptPagingFile, NtfsMemoryUsage, `
    NtfsMftZoneReservation, NtfsQuotaNotifyRate, ScrubMode, SymlinkLocalToLocalEvaluation, SymlinkLocalToRemoteEvaluation, SymlinkRemoteToLocalEvaluation, SymlinkRemoteToRemoteEvaluation, `
    UdfsCloseSessionOnEject, UdfsSoftwareDefectManagement, Win31FileSystem, Win95TruncatedExtensions | Out-File -FilePath $OutputFile -Append
}

# ============================================= #
# Disk Failure Prediction
# ============================================= #

'============================================='	| Out-File -FilePath $OutputFile -Append
'Disk Failure Prediction' 						| Out-File -FilePath $OutputFile -Append
'============================================='	| Out-File -FilePath $OutputFile -Append

Get-CimInstance -Namespace Root\WMI -Class MSStorageDriver_FailurePredictStatus -ErrorAction Silentlycontinue | Select-Object InstanceName, PredictFailure, Reason, Active | Format-Table -Wrap -AutoSize -GroupBy PredictFailure | Out-File -FilePath $OutputFile -Append


if([Float]$OSVersion -lt [Float](6.2))
{
    # ============================================= #
    # Disk Information
    # ============================================= #

    '==============================================' | Out-File -FilePath $OutputFile -Append
    'Disk Information'								 | Out-File -FilePath $OutputFile -Append    
    '==============================================' | Out-File -FilePath $OutputFile -Append
    $items = @('Name', 'Index', 'Status', 'StatusInfo', 'Access', 'Availability', 'BlockSize', 'Bootable', 'BootPartition', 'ConfigManagerErrorCode', 'ConfigManagerUserConfig', 'Description', 'DeviceID', 'DiskIndex', 'ErrorCleared', 'ErrorDescription', 'ErrorMethodology', 'HiddenSectors', 'InstallDate', 'LastErrorCode', 'NumberOfBlocks', 'PowerManagementCapabilities', 'PowerManagementSupported', 'PrimaryPartition', 'Purpose', 'RewritePartition', 'Size', 'StartingOffset', 'Type', 'Properties')
    Get-CimInstance Win32_DiskPartition | Format-List $items | Out-File -FilePath $OutputFile -Append 

    # ============================================= #
    # Volume Information
    # ============================================= #

    '==============================================' | Out-File -FilePath $OutputFile -Append
    'Volume Information'							 | Out-File -FilePath $OutputFile -Append    
    '==============================================' | Out-File -FilePath $OutputFile -Append
    $items = @('AddMountPoint', 'Chkdsk', 'Defrag', 'DefragAnalysis', 'Dismount', 'Format', 'Mount', 'Reset', 'SetPowerState', 'Access', 'Automount', 'Availability', 'BlockSize', 'BootVolume', 'Capacity', 'Caption', 'Compressed', 'ConfigManagerErrorCode', 'ConfigManagerUserConfig', 'CreationClassName', 'Description', 'DeviceID', 'DirtyBitSet', 'DriveLetter', 'DriveType', 'ErrorCleared', 'ErrorDescription', 'ErrorMethodology', 'FileSystem', 'FreeSpace', 'IndexingEnabled', 'InstallDate', 'Label', 'LastErrorCode', 'MaximumFileNameLength', 'Name', 'NumberOfBlocks', 'PageFilePresent', 'PNPDeviceID', 'PowerManagementCapabilities', 'PowerManagementSupported', 'Purpose', 'QuotasEnabled', 'QuotasIncomplete', 'QuotasRebuilding', 'SerialNumber', 'Status', 'StatusInfo', 'SupportsDiskQuotas', 'SupportsFileBasedCompression', 'SystemCreationClassName', 'SystemVolume')
    Get-CimInstance Win32_Volume | Format-List $items -GroupBy DeviceID | Out-File -FilePath $OutputFile -Append 

    # ============================================= #
    # iSCSI Information 
    # ============================================= #

    '==============================================' | Out-File -FilePath $OutputFile -Append
    'iSCSI Information'								 | Out-File -FilePath $OutputFile -Append    
    '==============================================' | Out-File -FilePath $OutputFile -Append
    $MSiSCSI = Get-Service -Name MSiSCSI -ErrorAction SilentlyContinue
    if($MSiSCSI)
    {
        "`n" | Out-File -FilePath $OutputFile -Append
        "{0} is {1}" -f $MSiSCSI.DisplayName, $MSiSCSI.Status | Out-File -FilePath $OutputFile -Append
        "`n" | Out-File -FilePath $OutputFile -Append
    }
}
else
{
    # ============================================= #
    # Disk Information
    # ============================================= #

    '==============================================' | Out-File -FilePath $OutputFile -Append
    'Disk Information'								 | Out-File -FilePath $OutputFile -Append    
    '==============================================' | Out-File -FilePath $OutputFile -Append
    Get-Disk -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty CimSystemProperties, CimInstanceProperties, CimClass, PSComputerName, Path, PassThroughServer, PassThroughNamespace, PassThroughIds, PassThroughClass, ObjectId, UniqueIdFormat | 
    Format-List -GroupBy BusType | Out-File -FilePath $OutputFile -Append

    # ============================================= #
    # Volume Information
    # ============================================= #

    '==============================================' | Out-File -FilePath $OutputFile -Append
    'Volume Information'							 | Out-File -FilePath $OutputFile -Append    
    '==============================================' | Out-File -FilePath $OutputFile -Append
    "`n" | Out-File -FilePath $OutputFile -Append
    $volumes = Get-Volume -ErrorAction SilentlyContinue
    "Total Volume(s) : $($volumes.Count)" | Out-File -FilePath $OutputFile -Append

    $volumes | Select-Object * -ExcludeProperty CimSystemProperties, CimInstanceProperties, CimClass, PSComputerName, Path, PassThroughServer, PassThroughNamespace, PassThroughIds, PassThroughClass, ObjectId, UniqueId | 
    Format-List -GroupBy DriveType | Out-File -FilePath $OutputFile -Append

    # ============================================= #
    # Partition Information
    # ============================================= #

    '==============================================' | Out-File -FilePath $OutputFile -Append
    'Partition Information'							 | Out-File -FilePath $OutputFile -Append    
    '==============================================' | Out-File -FilePath $OutputFile -Append
    "`n" | Out-File -FilePath $OutputFile -Append
    $partitions = Get-Partition -ErrorAction SilentlyContinue
    "Total Partition(s) : $($partitions.Count)" | Out-File -FilePath $OutputFile -Append

    $partitions | Select-Object * -ExcludeProperty CimSystemProperties, CimInstanceProperties, CimClass, PSComputerName, Path, PassThroughServer, PassThroughNamespace, PassThroughIds, PassThroughClass, ObjectId, UniqueId | 
    Format-List -GroupBy DiskNumber | Out-File -FilePath $OutputFile -Append

    # ============================================= #
    # iSCSI Information 
    # ============================================= #

    '==============================================' | Out-File -FilePath $OutputFile -Append
    'iSCSI Information'								 | Out-File -FilePath $OutputFile -Append    
    '==============================================' | Out-File -FilePath $OutputFile -Append
    $MSiSCSI = Get-Service -Name MSiSCSI -ErrorAction SilentlyContinue
    if($MSiSCSI)
    {
        "`n" | Out-File -FilePath $OutputFile -Append
        "{0} is {1}" -f $MSiSCSI.DisplayName, $MSiSCSI.Status | Out-File -FilePath $OutputFile -Append
    }

    if($MSiSCSI.Status -eq 'Running')
    {
        Get-IscsiTarget | Format-List | Out-File -FilePath $OutputFile -Append
        Get-IscsiTargetPortal | Format-List | Out-File -FilePath $OutputFile -Append

        "`n" | Out-File -FilePath $OutputFile -Append
        'Initiator Ports' | Out-File -FilePath $OutputFile -Append    
        '---------------' | Out-File -FilePath $OutputFile -Append    

        Get-InitiatorPort | Format-Table -AutoSize | Out-File -FilePath $OutputFile -Append
    }
    else
    {
        "`n" | Out-File -FilePath $OutputFile -Append
    }

    # ============================================= #
    # Storage Subsystem 
    # ============================================= #

    '==============================================' | Out-File -FilePath $OutputFile -Append
    'Storage Subsystem'								 | Out-File -FilePath $OutputFile -Append    
    '==============================================' | Out-File -FilePath $OutputFile -Append
    Get-StorageSubsystem -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty CimSystemProperties, CimInstanceProperties, CimClass, PSComputerName, Path, PassThroughServer, PassThroughNamespace, PassThroughIds, PassThroughClass, ObjectId, UniqueId | 
    Format-List | Out-File -FilePath $OutputFile -Append 

    '==============================================' | Out-File -FilePath $OutputFile -Append
    'Storage Pool'								 	 | Out-File -FilePath $OutputFile -Append    
    '==============================================' | Out-File -FilePath $OutputFile -Append
    Get-StoragePool | Select-Object * -ExcludeProperty CimSystemProperties, CimInstanceProperties, CimClass, PSComputerName, Path, PassThroughServer, PassThroughNamespace, PassThroughIds, PassThroughClass, ObjectId, UniqueId | 
    Format-List | Out-File -FilePath $OutputFile -Append 
}

# ============================================= #
# Properties of Important Drivers
# ============================================= #

'StorPort.sys', 'ScsiPort.sys', 'Classpnp.sys', 'Mountmgr.sys', 'VolSnap.sys', 'Ntfs.sys', 'PartMgr.sys', 'SpacePort.sys' | ForEach-Object { 
'==============================================' | Out-File -FilePath $OutputFile -Append
"$_ Service Properties"                          | Out-File -FilePath $OutputFile -Append    
'==============================================' | Out-File -FilePath $OutputFile -Append
Get-ItemProperty -Path "$env:windir\System32\drivers\$_" -ErrorAction SilentlyContinue | Format-List -Property Name, Length, Mode, VersionInfo, LinkType, Target, CreationTime, LastWriteTime, LastAccessTime | 
Out-File -FilePath $OutputFile -Append}

# ============================================= #
# NTFS Information
# ============================================= #
'==============================================' | Out-File -FilePath $OutputFile -Append
'NTFS Information'								 | Out-File -FilePath $OutputFile -Append    
'==============================================' | Out-File -FilePath $OutputFile -Append
"`n" | Out-File -FilePath $OutputFile -Append
[System.IO.DriveInfo]::GetDrives() | Where-Object {$_.DriveFormat -eq 'NTFS'} | Select-Object Name | 
ForEach-Object { 
"Volume {0} `n`n" -f $_.Name | Out-File -FilePath $OutputFile -Append 
FSUTIL fsinfo ntfsInfo ($_.Name) | Out-File -FilePath $OutputFile -Append 
"`n" | Out-File -FilePath $OutputFile -Append }

"`n" | Out-File -FilePath $OutputFile -Append

CollectFiles -filesToCollect $OutputFile -fileDescription $fileDescription -SectionDescription $sectionDescription


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCoZYf+QYWxL3dG
# 7aRbdboIEI0dtSSHrEMio6I/snj6cKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIQA2rAj28cmDpcZvuTQhxuV
# PxRDgBUojURy9PPqVlFsMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAGxdFwgqLIE+olpR2eIAVEUF1yk/nYl9GYbYZNnssOfvA7mBeLHVAV
# euYF+STS3xGAoWX5b5WXhQTVxlkTtl7YXj+gT+dnLZFIwtNakb4nUrQ9tHLmm+6u
# MBbv7srwi7NDjM0oSAQuXLsAGrN6VWu0y8B45Ml4A2mjLZVV1TXPbyV8EVqYuybz
# sBaSwIDQeT7tQZ+Gu6fE8sQdzTDgZgvNZIva5kxygzBHXpuixaaCHAX9BE+EXQsd
# FodPN4LmTC2qr2i325LzRHxUpBciTUW/zql5u7CbiSaXTwBJzabunJxNKh1ilQPL
# tu2pNfML6HDMWhBhlCLnoTYgjYQWYiIGoYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIAzB3hqa16Yr8oUc4nZP8J+O+d2GTzpR2+BwEVbSSq+eAgZi3ohP
# 7R0YEzIwMjIwODAxMDc1MDUyLjQwOFowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RDA4Mi00QkZELUVFQkExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAY/zUajrWnLdzAABAAABjzAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDZaFw0yMzAxMjYxOTI3NDZaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQwODIt
# NEJGRC1FRUJBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmVc+/rXPFx6Fk4+CpLru
# bDrLTa3QuAHRVXuy+zsxXwkogkT0a+XWuBabwHyqj8RRiZQQvdvbOq5NRExOeHia
# CtkUsQ02ESAe9Cz+loBNtsfCq846u3otWHCJlqkvDrSr7mMBqwcRY7cfhAGfLvlp
# MSojoAnk7Rej+jcJnYxIeN34F3h9JwANY360oGYCIS7pLOosWV+bxug9uiTZYE/X
# clyYNF6XdzZ/zD/4U5pxT4MZQmzBGvDs+8cDdA/stZfj/ry+i0XUYNFPhuqc+UKk
# wm/XNHB+CDsGQl+ZS0GcbUUun4VPThHJm6mRAwL5y8zptWEIocbTeRSTmZnUa2iY
# H2EOBV7eCjx0Sdb6kLc1xdFRckDeQGR4J1yFyybuZsUP8x0dOsEEoLQuOhuKlDLQ
# Eg7D6ZxmZJnS8B03ewk/SpVLqsb66U2qyF4BwDt1uZkjEZ7finIoUgSz4B7fWLYI
# eO2OCYxIE0XvwsVop9PvTXTZtGPzzmHU753GarKyuM6oa/qaTzYvrAfUb7KYhvVQ
# KxGUPkL9+eKiM7G0qenJCFrXzZPwRWoccAR33PhNEuuzzKZFJ4DeaTCLg/8uK0Q4
# QjFRef5n4H+2KQIEibZ7zIeBX3jgsrICbzzSm0QX3SRVmZH//Aqp8YxkwcoI1WCB
# izv84z9eqwRBdQ4HYcNbQMMCAwEAAaOCATYwggEyMB0GA1UdDgQWBBTzBuZ0a65J
# zuKhzoWb25f7NyNxvDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQDNf9Oo9zyhC5n1jC8iU7NJY39FizjhxZwJbJY/
# Ytwn63plMlTSaBperan566fuRojGJSv3EwZs+RruOU2T/ZRDx4VHesLHtclE8GmM
# M1qTMaZPL8I2FrRmf5Oop4GqcxNdNECBClVZmn0KzFdPMqRa5/0R6CmgqJh0muvI
# mikgHubvohsavPEyyHQa94HD4/LNKd/YIaCKKPz9SA5fAa4phQ4Evz2auY9SUluI
# d5MK9H5cjWVwBxCvYAD+1CW9z7GshJlNjqBvWtKO6J0Aemfg6z28g7qc7G/tCtrl
# H4/y27y+stuwWXNvwdsSd1lvB4M63AuMl9Yp6au/XFknGzJPF6n/uWR6JhQvzh40
# ILgeThLmYhf8z+aDb4r2OBLG1P2B6aCTW2YQkt7TpUnzI0cKGr213CbKtGk/OOIH
# SsDOxasmeGJ+FiUJCiV15wh3aZT/VT/PkL9E4hDBAwGt49G88gSCO0x9jfdDZWdW
# GbELXlSmA3EP4eTYq7RrolY04G8fGtF0pzuZu43A29zaI9lIr5ulKRz8EoQHU6cu
# 0PxUw0B9H8cAkvQxaMumRZ/4fCbqNb4TcPkPcWOI24QYlvpbtT9p31flYElmc5wj
# GplAky/nkJcT0HZENXenxWtPvt4gcoqppeJPA3S/1D57KL3667epIr0yV290E2ot
# ZbAW8DCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
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
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDA4Mi00QkZELUVFQkExJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAD5NL4IEdudIBwdGoCaV0WBbQZpqoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmkZg6MCIYDzIwMjIwODAx
# MDgwOTMwWhgPMjAyMjA4MDIwODA5MzBaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaRmDoCAQAwBwIBAAICEbAwBwIBAAICEXEwCgIFAOaS6boCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQAhp8Aod4IrqWSzJRIvhdfsjjJ0NJWgA/ZOXoGxuTHB
# Nc+n4eD9raE8WV172xcQru+BQW4ecbLSElX8gQ88qDD0qPr3S/FY/5drB43kpsZb
# 3smIRpvR0AhUrfQV/szgrx7+5TBOZSinvdOPsft4KHAzsWahf7BfumsXJdtpt6+W
# nzGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABj/NRqOtact3MAAEAAAGPMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIOM1DmtPkC1t4ECEHctC
# 4NCVV0PMoliTfwHMhHBt3qbaMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# l3IFT+LGxguVjiKm22ItmO6dFDWW8nShu6O6g8yFxx8wgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY/zUajrWnLdzAABAAABjzAiBCDK
# yRgnJWWXshnmgygiJTZnJFpENKNV36rl3eKKIz0TKjANBgkqhkiG9w0BAQsFAASC
# AgB2D5c8uD3u4YTNy70kqK03gyfnYxnC7ElUGk+i5OixEcYzNia+PihiFri12C3H
# tJKpcA026q2vpqxtAha+NkgwaGJ1xiXqxep7m84MjVaq6CHhwBZ9+tExkzfylpPR
# /F9doSCOvo/GF9gfUD1X4GBqgBe4cjR+3Z8tfws2aIb5juIHDqd/F2ghgrgyVEGg
# lBI9ZicSTZQOp/eKm5zRLHSoOK9G5UsUmvRTPW0nQkPkmuvcmaNrsgCbjtmPxiSS
# Dm8NGCEkN+cLCuv1M43DYrsrr1So3l0xH3r2PP0zUY6APpquLZcCA6GfpaXiOZ7N
# //Wv9IK+zOAG+FXq64/xonufENT622U5tCixZU4zUKg6beiifetvn41bwBPd4FMu
# TM8GU1xF/qgNiMgxuhQsReyok+Uoq93MUxO0KrY6K0aVDZLS6c/Li1yo1zOsTqv4
# ypljLf8hjQMzUihRCWCQtaD9eh6ltLmYjt08dQY2XFVcp8Fkrj1yP+huR077nzeI
# Gakm57c9nATT9f7oOP0N7fT9rO/Ih/twStH+MUIDpbFSh9qQGzEfa4nBUOx1U7qp
# YREb2IkKEXoRMH2aBOwnrEvDuxrbY9+Fxom0WmrWgK5OG8nWeUgNSk66PCzhHcAY
# yIzN/MhLAtXpIuchSlk5yjyTYf1KKjYit9llfCwN/fRxnw==
# SIG # End signature block
