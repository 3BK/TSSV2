#************************************************
# TS_4KDriveInfo.ps1
# Version 1.0.2
# Date: 03-21-2011
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script detects 4KB/ 512e drive informaiton
#************************************************
# 2023-02-20 WalterE mod Trap #we#
trap [Exception]{
	WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; continue
	Write-Host "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_"
}

[string]$typeDefinition = @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.ComponentModel;

namespace Microsoft.DeviceIoControl
{
    internal static class NativeMethods
    {

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, CharSet = CharSet.Unicode,
             ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern IntPtr CreateFile(string fileName,
                                                  int desiredAccess,
                                                  int sharedMode,
                                                  IntPtr securityAttributes,
                                                  int creationDisposition,
                                                  int flagsandAttributes,
                                                  IntPtr templatFile);

        [DllImport("kernel32.dll", ExactSpelling = true, EntryPoint = "DeviceIoControl", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        internal static extern bool DeviceIoControl(IntPtr device,
                                                    int ioControlCode,
                                                    IntPtr inBuffer,
                                                    int inBufferSize,
                                                    IntPtr outBuffer,
                                                    int outputBufferSize,
                                                    out int bytesReturned,
                                                    IntPtr ignore);


        internal static readonly IntPtr INVALID_HANDLE_VALUE = (IntPtr)(-1);

        [DllImport("kernel32.dll")]
        internal static extern void ZeroMemory(IntPtr destination, int size);

    }

    public class SectorSize
    {

        [StructLayout(LayoutKind.Sequential)]   
        public struct STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR  
        {
            public int Version;
            public int Size;
            public int BytesPerCacheLine;
            public int BytesOffsetForCacheAlignment;
            public int BytesPerLogicalSector;
            public int BytesPerPhysicalSector;
            public int BytesOffsetForSectorAlignment;
        }

        public enum STORAGE_PROPERTY_ID 
        {
            StorageDeviceProperty = 0,
            StorageAdapterProperty,
            StorageDeviceIdProperty,
            StorageDeviceUniqueIdProperty,              // See storduid.h for details
            StorageDeviceWriteCacheProperty,
            StorageMiniportProperty,
            StorageAccessAlignmentProperty = 6,
            StorageDeviceSeekPenaltyProperty,
            StorageDeviceTrimProperty,
            StorageDeviceWriteAggregationProperty
        }

        public enum STORAGE_QUERY_TYPE {
              PropertyStandardQuery     = 0,
              PropertyExistsQuery,
              PropertyMaskQuery,
              PropertyQueryMaxDefined 
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STORAGE_PROPERTY_QUERY
        {
            public STORAGE_PROPERTY_ID PropertyId;
            public STORAGE_QUERY_TYPE QueryType;
            public IntPtr AdditionalParameters;
        }

        private const int GENERIC_READ = -2147483648;
        private const int FILE_SHARE_READ = 0x00000001;
        private const int FILE_SHARE_WRITE = 0x00000002;
        private const int OPEN_EXISTING = 3;
        private const int FILE_ATTRIBUTE_NORMAL = 0x00000080;
        private const int FSCTL_IS_VOLUME_DIRTY = 589944;
        private const int VOLUME_IS_DIRTY = 1;

        private const int PropertyStandardQuery = 0;
        private const int StorageAccessAlignmentProperty = 6;

        public static STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR DetectSectorSize(string devName)
        {
            string FileName = @"\\.\" + devName;
            int bytesReturned;
            IntPtr outputBuffer = IntPtr.Zero;

            STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR pAlignmentDescriptor = new STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR();

            SectorSize.STORAGE_PROPERTY_QUERY StoragePropertQuery = new SectorSize.STORAGE_PROPERTY_QUERY();

            StoragePropertQuery.QueryType = SectorSize.STORAGE_QUERY_TYPE.PropertyStandardQuery;
            StoragePropertQuery.PropertyId = SectorSize.STORAGE_PROPERTY_ID.StorageAccessAlignmentProperty;

            IntPtr hVolume = NativeMethods.CreateFile(FileName, 0, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);

            if (hVolume != NativeMethods.INVALID_HANDLE_VALUE)
            {
                outputBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(pAlignmentDescriptor));
                NativeMethods.ZeroMemory(outputBuffer, Marshal.SizeOf(pAlignmentDescriptor));

                IntPtr outputBufferStoragePropertQuery = Marshal.AllocHGlobal(Marshal.SizeOf(StoragePropertQuery));
                Marshal.StructureToPtr(StoragePropertQuery, outputBufferStoragePropertQuery,false);

                int IOCTL_STORAGE_QUERY_PROPERTY = 2954240;
                
                bool status = NativeMethods.DeviceIoControl(hVolume,
                         IOCTL_STORAGE_QUERY_PROPERTY,
                         outputBufferStoragePropertQuery,
                         Marshal.SizeOf(StoragePropertQuery),
                         outputBuffer,
                         Marshal.SizeOf(pAlignmentDescriptor),
                         out bytesReturned,
                         IntPtr.Zero);

                if (!status)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                pAlignmentDescriptor = (STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR) Marshal.PtrToStructure(outputBuffer, typeof(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR));
            }
            return pAlignmentDescriptor;
        }
	}
}
"@

function FormatBytes{
	param ($bytes,$precision='0')
	foreach ($i in ("Bytes","KB","MB","GB","TB")) {
		if (($bytes -lt 1000) -or ($i -eq "TB")){
			$bytes = ($bytes).tostring("F0" + "$precision")
			return $bytes + " $i"
		}else{
			$bytes /= 1KB
		}
	}
}


Function CheckMinimalFileVersionWithCTS([string] $Binary, $RequiredMajor, $RequiredMinor, $RequiredBuild, $RequiredFileBuild){
	$newProductVersion = Get-FileVersionString($Binary)
	if((CheckMinimalFileVersion -Binar $Binary -RequiredMajor $RequiredMajor -RequiredMinor $RequiredMinor -RequiredBuild $RequiredBuild -RequiredFileBuild $RequiredFileBuild -LDRGDR) -eq $true){
		"[CheckMinimalFileVersion] $Binary version is " + $newProductVersion + " - OK" | WriteTo-StdOut -ShortFormat
		return $true
	}else{
		"[CheckMinimalFileVersion] $Binary version is " + $newProductVersion | WriteTo-StdOut -ShortFormat
		add-member -inputobject $KB982018Binaries_Summary  -membertype noteproperty -name $Binary -value $newProductVersion
		return $false
	}
}

Function KB982018IsInstalled(){
	if ($OSVersion.Build -le 7601){ #Win7 Service Pack 1 or RTM
		#Pre-Win7 SP1 - Need to check if KB 982018 is actually installed
		$System32Folder = $Env:windir + "\system32"		
		if (((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Amdsata.sys" 1 1 2 5) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Amdxata.sys" 1 1 2 5) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Nvraid.sys" 10 6 0 18) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Nvstor.sys" 10 6 0 18) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Ntfs.sys" 6 1 7600 16778) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Ntfs.sys" 6 1 7600 20921) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Ntfs.sys" 6 1 7601 17577) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Ntfs.sys" 6 1 7601 21680) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Usbstor.sys" 6 1 7600 16778) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Usbstor.sys" 6 1 7600 20921) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Usbstor.sys" 6 1 7601 17577) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Usbstor.sys" 6 1 7601 21680) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Storport.sys" 6 1 7601 17577) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Storport.sys" 6 1 7601 21680) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Storport.sys" 6 1 7600 16778) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Storport.sys" 6 1 7600 20921) -eq $true)
			)
		{ 
			#Everything is fine
			return $true
		}else{
			return $false
		}		
	}else{
		#SP1 is already installed
		return $true
	}
}

$512eDrivesXML = Join-Path -Path $PWD.Path -ChildPath "512eDrives.xml"

# Windows 8 fully support 4KB drives: http://blogs.msdn.com/b/b8/archive/2011/11/29/enabling-large-disks-and-large-sectors-in-windows-8.aspx
if (($OSVersion.Build -gt 7000) -and ($OSVersion.Build -lt 9000)){
	Import-LocalizedData -BindingVariable AdvDrivesString
	$4KBDriveE = @()
	$4KBDriveN = @()
	if (Test-Path $512eDrivesXML){
		$512eDrivesXML | Remove-Item -Force -ErrorAction Continue
	}
	Write-DiagProgress -Activity $AdvDrivesString.ID_CheckingDriveSize
	$StorageType = Add-Type -TypeDefinition $typeDefinition -PassThru
	$AlignmentDescriptor = $StorageType::STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR
	#$AlignmentDescriptor = $StorageType[1]::DetectSectorSize("C:")
	#$devices = (Get-CimInstance -query "Select DeviceID from Win32_LogicalDisk WHERE ((MediaType=12) or (MediaType=11)) and ((DriveType=3) or (DriveType=2))")
	$devices = (Get-CimInstance -query "Select DeviceID, Model, InterfaceType, Size, BytesPerSector, MediaType from Win32_DiskDrive where ConfigManagerErrorCode=0 and MediaLoaded = true and SectorsPerTrack > 0")
	if($null -ne $devices){
		$4KDriveDetected = $false
		$SectorSize_Summary = new-object PSObject
		$4KDrive_Summary = new-object PSObject
		$KB982018Binaries_Summary = new-object PSObject
		$4KNativeDetected = $false
	    foreach($device in $devices){
			trap [Exception]{
			    $errorMessage = $_.Exception.Message
				"           Error: " + $errorMessage | WriteTo-StdOut
				$_.InvocationInfo | Format-List | out-string | WriteTo-StdOut
				WriteTo-ErrorDebugReport -ErrorRecord $_ -InvokeInfo $MyInvocation
				$Error.Clear()
				continue
			}
			Write-DiagProgress -Activity $AdvDrivesString.ID_CheckingDriveSize -Status ($AdvDrivesString.ID_4KDriveDetectedDesc -replace ("%Drive%", $device.DeviceID))
			$Interface = Get-CimInstance -Query ("ASSOCIATORS OF {Win32_DiskDrive.DeviceID='" + $device.DeviceID + "'} Where ResultClass=Win32_PnPEntity") | ForEach-Object {Get-CimInstance -Query ("ASSOCIATORS OF {Win32_PnPEntity.DeviceID='" + $_.DeviceID + "'} Where ResultClass=CIM_Controller")}
			$Partitions = Get-CimInstance -Query ("ASSOCIATORS OF {Win32_DiskDrive.DeviceID='" + $device.DeviceID + "'} Where ResultClass=Win32_DiskPartition")
			$DriveLetters = @()
			foreach ($Partition in $Partitions){
				$Win32Logical = Get-CimInstance -Query ("ASSOCIATORS OF {Win32_DiskPartition.DeviceID='" + $Partition.DeviceID + "'} Where ResultClass=Win32_LogicalDisk")
				if ($null -ne $Win32Logical){
					$DriveLetters += $Win32Logical.DeviceID
				}
			}
			
			if ($DriveLetters.Length -gt 0){
				$DriveLetterString = "[" + [string]::Join(", ", $DriveLetters) + "]"
				$DriveLetters | Export-Clixml -Path $512eDrivesXML
			}else{
				$DriveLetterString = ""
			}
			
			$BytesDisplay = ""
			$4KDriveType = ""
			"Checking drive: " + $device.DeviceID | WriteTo-StdOut -ShortFormat
			"Storage Type: " + $StorageType[1].ToString() | WriteTo-StdOut -ShortFormat
			$AlignmentDescriptor = $StorageType[1]::DetectSectorSize($device.DeviceID)
			if ($null -ne $AlignmentDescriptor){
				$BytesDisplay = ($AlignmentDescriptor.BytesPerPhysicalSector.ToString()) + " Bytes"
			}else{
				$BytesDisplay = "(Unknown)"
			}
			
			$DebugString = "    Results for drive " + $device.DeviceID
			$DebugString += "`r`n      Drive Letter(s)       : " + $DriveLetterString
			$DebugString += "`r`n      Model                 : " + $device.Model
			$DebugString += "`r`n      Interface Name        : " + $Interface.Name
			$DebugString += "`r`n      Interface Type        : " + $device.InterfaceType
			$DebugString += "`r`n      Bytes per sector (WMI): " + $device.BytesPerSector
			$DebugString += "`r`n      BytesPerPhysicalSector: " + $AlignmentDescriptor.BytesPerPhysicalSector
			$DebugString += "`r`n      BytesPerLogicalSector : " + $AlignmentDescriptor.BytesPerLogicalSector
			$DebugString += "`r`n      Version               : " + $AlignmentDescriptor.Version
			$DebugString | WriteTo-StdOut
			if (($AlignmentDescriptor.BytesPerPhysicalSector -gt 512) -or ($device.BytesPerSector -ne 512)){
				trap [Exception]{
				    $errorMessage = $_.Exception.Message
					"           Error: " + $errorMessage | WriteTo-StdOut
					$_.InvocationInfo | Format-List | out-string | WriteTo-StdOut
					WriteTo-ErrorDebugReport -ErrorRecord $_ -InvokeInfo $MyInvocation
					$Error.Clear()
					continue
				}

				#4K Drive
				$4KDriveDetected = $true
				$InformationCollected = @{"Drive Model"=$device.Model}
				$InformationCollected += @{"Device ID"=$device.DeviceID}
				$InformationCollected += @{"Drive Letter(s)"=$DriveLetterString}
				$InformationCollected += @{"Drive Size"=($device.Size | FormatBytes -precision 2)}
				$InformationCollected += @{"Media Type"=$device.MediaType}
				$InformationCollected += @{"Drive Type"=$device.InterfaceType}
				$InformationCollected += @{"Interface Name"=$Interface.Name}
				$InformationCollected += @{"Bytes per sector (Physical)"=$AlignmentDescriptor.BytesPerPhysicalSector}
				$InformationCollected += @{"Bytes per sector (Logical)"=$AlignmentDescriptor.BytesPerLogicalSector}
				$InformationCollected += @{"Bytes per sector (WMI)"=$device.BytesPerSector}
				if (($AlignmentDescriptor.BytesPerPhysicalSector -eq 3072) -or ($device.BytesPerSector -eq 4096)){
					# known issue
					$BytesDisplay = "Physical: 4KB"
				}else{
					$BytesDisplay = "Physical: " + ($AlignmentDescriptor.BytesPerPhysicalSector.ToString())
				}
				
				if (($AlignmentDescriptor.BytesPerLogicalSector -eq 512) -and ($device.BytesPerSector -eq 512)){
					$512EDriveDetected = $true
					$4KDriveType = " - Logical: " + $AlignmentDescriptor.BytesPerLogicalSector + " bytes<br/><b>[512e Drive]</b>"
					$4KBDriveE += $device.DeviceID
				}
				elseif ($device.BytesPerSector -eq 4096){
					$4KNativeDetected = $true
					if ($AlignmentDescriptor.BytesPerPhysicalSector -eq 4096){
						$4KDriveType = "Physical: " + ($AlignmentDescriptor.BytesPerPhysicalSector.ToString()) + "<b><font color=`"red`">[4KB Native]</font></b>"
					}else{
						$4KDriveType = "<b><font color=`"red`">[4KB Native]</font></b>"
					}					
				}else{
					$4KNativeDetected = $true
					$4KDriveType = " - Logical: " + $AlignmentDescriptor.BytesPerLogicalSector + " bytes<br/><b><font color=`"red`">[4KB Native]</font></b>"
					$4KBDriveN += $device.DeviceID
				}
			}
			
			add-member -inputobject $SectorSize_Summary  -membertype noteproperty -name ($device.DeviceID + " " + $DriveLetterString) -value ($BytesDisplay + $4KDriveType)
			if ($512EDriveDetected){
				Write-GenericMessage -RootCauseID "RC_4KDriveDetected" -PublicContentURL "http://support.microsoft.com/kb/2510009" -Verbosity "Informational" -InformationCollected $InformationCollected -Visibility 4 -MessageVersion 4 -SupportTopicsID 8122
				$512EDriveDetected = $false
				$RC_4KDriveDetected = $true
			}
						
			if ($4KNativeDetected){
				Write-GenericMessage -RootCauseID "RC_4KNativeDriveDetected" -PublicContentURL "http://support.microsoft.com/kb/2510009" -Verbosity "Error" -InformationCollected $InformationCollected -MessageVersion 3 -Visibility 4 -MessageVersion 4 -SupportTopicsID 8122
				$RC_4KNativeDriveDetected = $true
				$4KNativeDetected = $false
			}
	    }
		$SectorSize_Summary | ConvertTo-Xml2 | update-diagreport -id 99_SectorSizeSummary -name "Drive Sector Size Information" -verbosity informational
		if ($RC_4KDriveDetected){	
			Update-DiagRootCause -id "RC_4KDriveDetected" -Detected $true
			if (-not (KB982018IsInstalled)){
				$XMLFileName = "..\KB982018.XML"
				($KB982018Binaries_Summary | ConvertTo-Xml2).Save($XMLFileName)
				Update-DiagRootCause -id "RC_KB982018IsNotInstalled" -Detected $true 
				Write-GenericMessage -RootCauseID "RC_KB982018IsNotInstalled" -PublicContentURL "http://support.microsoft.com/kb/982018" -Verbosity "Error" -MessageVersion 3 -Visibility 4 -MessageVersion 3 -SupportTopicsID 8122
			}else{
				Update-DiagRootCause -Id "RC_KB982018IsNotInstalled" -Detected $false
			}
		}else{
			Update-DiagRootCause -Id "RC_4KDriveDetected" -Detected $false
		}
		
		if ($RC_4KNativeDriveDetected){
			Update-DiagRootCause -id "RC_4KNativeDriveDetected" -Detected $true
			Write-GenericMessage -RootCauseID "RC_4KNativeDriveDetected" -Verbosity "Error" -PublicContentURL "http://support.microsoft.com/kb/2510009" -Visibility 4 -MessageVersion 3 -SupportTopicsID 8122
		}else{
			Update-DiagRootCause -Id "RC_4KNativeDriveDetected" -Detected $false
		}
	}
}

# SIG # Begin signature block
# MIInwQYJKoZIhvcNAQcCoIInsjCCJ64CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAni0HuFySzTagv
# U6b1S+1L94JuKIWEDBmObErBpZGpMaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEII7p8YyZx9TIdaLntt68JTmP
# P88VROQNjQiSF5g8NOBZMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBMwWOrXGl8xxaSaOqEgrBq4Z+RhCqoI/s2LTLaW6FxVc013RxyDe02
# /mfLvUe9jtHYCt7YGfCCHwKIehryIdjhVu4uoD1acyLGwb63URAE9EcyKh8R4pxY
# PYnp/U+og+NsWR1GwBNumTqOuiqJhKn5SddUJZWNsTMdLUY0tODRXq8Aj6/bam7o
# sJKXi9kIFWxnSmX/xhNA/tuZNS2p4NI4s51JpsdF2Cf79VtC7qb8lzHSlaIkjkRP
# gC/lqhsVCk8l/6vCVZVyPZ8JHoGHKNwAOcbBq9bOX0YhaIpNNCUCPNndTXnC34kc
# BzJcoLl4jKefbluVN1b05QY33ff+aEH5oYIXKTCCFyUGCisGAQQBgjcDAwExghcV
# MIIXEQYJKoZIhvcNAQcCoIIXAjCCFv4CAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIMG7h1WALgGlJBmE8fdUwZHwzgQf2kjuyi9hepcuT71NAgZj5YzF
# dB8YEzIwMjMwMjIwMTUwNTMxLjU2MVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
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
# BDEiBCDd+hCkCaif35i5PiPmlHrrPJCtjnJQSx/uurqFlSkX+TCB+gYLKoZIhvcN
# AQkQAi8xgeowgecwgeQwgb0EICfKDTUtaGcWifYc3OVnIpp7Ykn0S8JclVzrlAgF
# 8ciDMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAG1
# rRrf14VwbRMAAQAAAbUwIgQgCpQ7yHCYq6SSx6pbyBKpti3OzKk1m19JNvFoeNj6
# tNYwDQYJKoZIhvcNAQELBQAEggIAhPErIP337gbGINmMHoVh4DGdw3PdFFCXPYN8
# JTebE4ZAr3kVi4NA4Vp/4FwRQeq1EiR3aycXQUWgiuljHgrI/muGXi8Hx2c50rmY
# 8QAg4J5KZSO1gLatrxrjG8NodmoIaDRMJA8FTpXSldrHTX7kDdhffZaoAI5t+T1w
# 9XwRMZLvmX4f1RFeZvSYqCJZTMvJnPR5twD0ecBo61H1mU8IckNA4jC8imhhAuGz
# Pb+pjH0PK9+QS8VMO/gQ3I+cxZp2AeSP1Z+mY1LI9RdLNm3M374W4M9eeo9v6lT0
# Mg3Ji5GyucRq24GCJ09IeHqcIkUzjnHvoddojLV+F/47iIJbgVavY8OuCJi0nWp3
# 6rwlpez8xQloXeb+b/muDvH9Q52v1ynFKC+/aGfNN542AlGRJadZYL3MyrWGaCcl
# ccnz7R8c5fbNye7zpvu+rOxZU9gk0wEFAMVkTV8fj8jAkmKVpUcKBjuo7h18DyGA
# uzyE23MgCwJYLvzTKHtrjdsEF2GzH2B4dvV6Vo9cI8rm132jOdkKZlIK0jiZxs1z
# H0EhAmjQ18ASrMxfGh+Zij4qxC1qlbWx/rbSevLd16O8McTeXOh9yaqntIfhSxjT
# GC1FbmWot8ZfthyA3LAEE/gprrKxNbNwiZvyG/7UxqitWLSsVXKyLrtcSGucU5y0
# f4digCU=
# SIG # End signature block
