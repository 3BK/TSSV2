#************************************************
# TS_KnownKernelTags.ps1
# Version 1.0.1
# Date: 5/18/2012
# Author: v-maam
# Description:  This script detects and report memory problems
#************************************************

trap [Exception] 
{
	WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("TS_KnownKernelTags.ps1 Error")
	continue
}

Import-LocalizedData -BindingVariable ScriptStrings
$SupportTopicsID = "8113"

$script:PagePool = @{}
$script:NonPagePool = @{}
$script:MemSnapFilePath = join-path $PWD.Path "memsnap.txt"

#region Check the script running condition
	
if(-not(Test-Path $script:MemSnapFilePath))
{
	Run-DiagExpression .\TS_ProcessInfo.ps1
}

if(-not(Test-Path $script:MemSnapFilePath))
{
	$script:MemSnapFilePath + " does not exist. Exiting..."  | WriteTo-StdOut -ShortFormat
	return
}

#endregion

#region shared functions

Function LoadPoolMemUsageTags($PagePool,$NonPagepool)
{
	if(Test-Path $script:MemSnapFilePath)
	{
		$fileArray = Get-Content $script:MemSnapFilePath
		for($i = 0; $i -lt $fileArray.Length; $i++)
		{
			if($i -ne 0)
			{
				$LineArray = $fileArray[$i].Split(" ", [StringSplitOptions]::RemoveEmptyEntries)
				if($LineArray.Length -eq 7)
				{
					$TageType = $LineArray[1]
					$TagName = $LineArray[0]
					[int]$MemUsage = $LineArray[5]
	
					if($TageType -contains "Paged")
					{
						if($PagePool.ContainsKey($TagName))
						{
							$PagePool[$TagName] += $MemUsage
						}
						else
						{
							$PagePool.Add($TagName,$MemUsage)
						}
					}
	
					if($TageType -contains "Nonp")
					{
						if($NonPagePool.ContainsKey($TagName))
						{
							$NonPagePool[$TagName] += $MemUsage
						}
						else
						{
							$NonPagePool.Add($TagName,$MemUsage)
						}
					}	
				}
			}
		}
	}
	else
	{
		"Unable to find "+ $script:MemSnapFilePath +" file and will exit" | WriteTo-StdOut -ShortFormat
		return
	}
}

Function getFileVersionInfo($filePath)
{
	if(Test-Path $filePath)
	{
		$fileVersion = ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($filePath))
		return $fileVersion
	}
	else
	{
		return $null
	}
}

Function checkTagProcessInfo($TagName,$InformationCollected,$Top=5,[switch] $NonPagedPoolCheck)
{
	if($NonPagedPoolCheck.IsPresent)
	{
		$PoolMemoryUsage = $script:NonPagePool.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $Top | Where-Object {$_.Name -eq $TagName}
	}
	else
	{
		$PoolMemoryUsage = $script:PagePool.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $Top | Where-Object {$_.Name -eq $TagName}
	}

	if($null -ne $PoolMemoryUsage)
	{
		add-member -inputobject $InformationCollected -membertype noteproperty -name "$TagName Kernel Tag Current Usage" -value (FormatBytes -bytes $PoolMemoryUsage.Value -precision 2)
		return $true
	}
	else
	{
		return $false
	}
}

#check the machine is server media or not
Function isServerMedia
{
	$Win32OS = Get-CimInstance -Class Win32_OperatingSystem
	
	if (($Win32OS.ProductType -eq 3) -or ($Win32OS.ProductType -eq 2)) #Server Media
	{
		return $true
	}
	else
	{
		return $false
	}
}

#endregion

# Load all PagePool and NonPagePool tags to hashtable
LoadPoolMemUsageTags -PagePool $script:PagePool -NonPagepool $script:NonPagePool
if(($script:PagePool.Count -eq 0) -and ($script:NonPagePool.Count -eq 0))
{
	"Load the memory page pool tags failed and will exit" | WriteTo-StdOut -ShortFormat
	return
}


#region rule 2334 related function and detect logic

Display-DefaultActivity -Rule -RuleNumber 2334

Function isAffectedOSVersionFor2334
{
	if(($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2)) #WinXP64/Server 2003 
	{
		return $true
	}
	else
	{
		return $false
	}
}

#rule 2334 detect logic
if(isAffectedOSVersionFor2334)
{
	$SysEventfilePath = "$Env:windir\system32\drivers\SymEvent.sys"
	$2334InformationCollected = new-object PSObject
	$RootCauseName = "RC_PagedPoolD2dSymEvent"
	$InternalContent = "https://vkbexternal.partners.extranet.microsoft.com/VKBWebService/ViewContent.aspx?scid=B;EN-US;2658721"
	$Verbosity = "Error"
	$Visibility = "3"
	
	$currentVersion = Get-FileVersionString($SysEventfilePath)		
	
	#Detect root cause 
	if (($currentVersion -eq "12.8.3.22") -and (checkTagProcessInfo -TagName "D2d" -InformationCollected $2334InformationCollected))
	{		
		add-member -inputobject $2334InformationCollected -membertype noteproperty -name "Current symevent.sys version" -value $currentVersion
			
		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -InternalContentURL $InternalContent -InformationCollected $2334InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID -SolutionTitle $ScriptStrings.ID_PagedPoolD2dSymEvent_SD
	}
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}

#endregion

#region rule 1870 related function and detect logic

Display-DefaultActivity -Rule -RuleNumber 1870

Function isAffectedOSVersionFor1870
{
	if(((($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2)) -or #Server 2003
	   (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 0)) -or # Server 2008
	   (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 1))) -and #Win 7/Server 2008 R2 
	    (isRDSEnabled)) #Terminal Services
	{
		return $true
	}
	else
	{
		return $false
	}
}

#Check if Disable WindowsUpdateAccess is enabled
Function isWindowsUpdateAccessEnabled
{
	$WindowsUpdateAccessPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate"
	if(Test-Path $WindowsUpdateAccessPath)
	{
		if((Get-ItemProperty ($WindowsUpdateAccessPath)).WindowsUpdate -eq 1)
		{
			return $true
		}
		else
		{
			return $false
		}
	}
	else 
	{
		return $false
	}
}

#Check if RDS Role/ Terminal Services app mode is installed
Function isRDSEnabled
{
	trap [Exception] 
	{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("[isRDSEnabled] Checking if RDS is Enabled")
		continue
	}
	
	$RDSEnabled = $false
	
	if ((Get-CimInstance -Class Win32_OperatingSystem -Property ProductType).ProductType -ne 1) #Server
	{
		if (($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2))
		{
			$NameSpace = 'root\CIMV2'
		}
		else
		{
			$NameSpace = 'root\CIMV2\TerminalServices'
		}
		
		$TSSetting = (Get-CimInstance -Class Win32_TerminalServiceSetting  -Namespace $NameSpace).TerminalServerMode
		
		if (($null -ne $TSSetting) -and ($TSSetting -eq 1))
		{
			$RDSEnabled = $true
		}
	}
	return $RDSEnabled
}

#rule 1870 detect logic
if (isAffectedOSVersionFor1870)
{
	$1870InformationCollected = new-object PSObject
	$RootCauseName = "RC_KernelTagTokeKB982010"
	$InternalContent = "http://support.microsoft.com/kb/982010"
	$Verbosity = "Error"
	$Visibility = "4"
	
	#Detect root cause 
	if(isWindowsUpdateAccessEnabled -and (checkTagProcessInfo -TagName "Toke" -InformationCollected $1870InformationCollected))
	{	
		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -InternalContentURL $InternalContent -InformationCollected $1870InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID -SolutionTitle $ScriptStrings.ID_KernelTagTokeKB982010_SD
	}
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}

#endregion

#region rule 3297 related function and detect logic

Display-DefaultActivity -Rule -RuleNumber 3297

Function isAffectedOSVersionFor3297
{
	if(($OSVersion.Build -eq 7600) -or ($OSVersion.Build -eq 7601)) #Win7/Server 2008 R2 SP0,SP1
	{
		return $true
	}
	else
	{
		return $false
	}
}

#rule 3297 detect logic
if (isAffectedOSVersionFor3297)
{
	$RdbssfilePath = "$Env:windir\system32\drivers\Rdbss.sys"	
	$3297InformationCollected = new-object PSObject
	$RootCauseName = "RC_KernelTagRxM4SeTIKB2647452"
	$PublicContent = "http://support.microsoft.com/kb/2647452"
	$Verbosity = "Error"
	$Visibility = "4"
	
	$currentVersion = Get-FileVersionString($RdbssfilePath)
	if(($OSVersion.Build) -eq 7600)
	{
		$requiredVersion = "6.1.7600.21095"
		$CheckHotFix2647452 = CheckMinimalFileVersion $RdbssfilePath 6 1 7600 21095
	}
	else
	{
		$requiredVersion = "6.1.7601.21864"
		$CheckHotFix2647452 = CheckMinimalFileVersion $RdbssfilePath 6 1 7601 21864
	}
	
	#Detect root cause 
	if (-not($CheckHotFix2647452))
	{	
		$CheckRxM4 = checkTagProcessInfo -TagName "RxM4" -InformationCollected $3297InformationCollected
		$CheckSeTI = checkTagProcessInfo -TagName "SeTI" -InformationCollected $3297InformationCollected
		
		if($CheckRxM4 -or $CheckSeTI)
		{
			add-member -inputobject $3297InformationCollected -membertype noteproperty -name "Current Rdbss.sys version" -value $currentVersion
			add-member -inputobject $3297InformationCollected -membertype noteproperty -name "Required Rdbss.sys version" -value $requiredVersion
	
			# Red/ Yellow Light
			Update-DiagRootCause -id $RootCauseName -Detected $true
			Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL $PublicContent -InformationCollected $3297InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID -SolutionTitle $ScriptStrings.ID_KernelTagRxM4SeTIKB2647452_SD
		}
		else
		{
			Update-DiagRootCause -id $RootCauseName -Detected $false
		}
	}	
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}	

#endregion

#region rule 2527 related function and detect logic

Display-DefaultActivity -Rule -RuleNumber 2527

Function isAffectedOSVersionFor2527
{
	if($OSVersion.Build -eq 6002) #Server 2008 SP2
	{
		return $true
	}
	else
	{
		return $false
	}
}

#rule 2527 detect logic
if (isAffectedOSVersionFor2527)
{
	$KsecddfilePath = "$Env:windir\system32\drivers\Ksecdd.sys"
	$2527InformationCollected = new-object PSObject
	$RootCauseName = "RC_KernelTagSslCKB2585542"
	$InternalContent = "http://support.microsoft.com/kb/2585542"
	$Verbosity = "Error"
	$Visibility = "4"
	
	$currentVersionInfo = getFileVersionInfo($KsecddfilePath)
	if($null -ne $currentVersionInfo)
	{
		$currentVersion = Get-FileVersionString($KsecddfilePath)
	}	
	
	switch($currentVersionInfo.FilePrivatePart.ToString().Remove(2))
	{
		"18" {
				$requiredVersion = "6.0.6002.18541"
				$CheckHotFix2585542 = CheckMinimalFileVersion $KsecddfilePath 6 0 6002 18541 -LDRGDR
			 }
		"22" {
		        $requiredVersion = "6.0.6002.22742"
				$CheckHotFix2585542 = CheckMinimalFileVersion $KsecddfilePath 6 0 6002 22742 -LDRGDR
			 }
	}
		
	#Detect root cause 
	if (-not($CheckHotFix2585542) -and (checkTagProcessInfo -TagName "SslC" -InformationCollected $2527InformationCollected))
	{		
		add-member -inputobject $2527InformationCollected -membertype noteproperty -name "Current Ksecdd.sys version" -value $currentVersion
		add-member -inputobject $2527InformationCollected -membertype noteproperty -name "Required Ksecdd.sys version" -value $requiredVersion
	
		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -InternalContentURL $InternalContent -InformationCollected $2527InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID -SolutionTitle $ScriptStrings.ID_KernelTagSslCKB2585542_SD
	}
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}

#endregion

#region rule 4631 related function and detect logic

Display-DefaultActivity -Rule -RuleNumber 4631

# Check if it is a Failovercluster
# - To detect a Failovercluster, just check if HKLM:\Cluster exists
Function IsCluster
{
	$ClusterKeyName = "HKLM:\Cluster"
	if (Test-Path -Path $ClusterKeyName) 
	{
		return $true
	}
	else
	{
		return $false
	}
}

#check the Mpio service is running
Function IsMpioRunning
{
	$MpioRegistryPath = "HKLM:\System\CurrentControlSet\Services\Mpio"
	if(Test-Path $MpioRegistryPath)
	{
		if((Get-ItemProperty ($MpioRegistryPath)).Start -eq 0)
		{
			return $true
		}
		else
		{
			return $false
		}
	}
	else
	{
		return $false
	}
}

Function isAffectedOSVersionFor4631
{
	if(($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2) -and (IsCluster) -and (IsMpioRunning)) #Server 2003 with Failovercluster and Mpio service is running
	{		
		return $true
	}
	else
	{
		return $false
	}
}

#rule 4631 detect logic
if (isAffectedOSVersionFor4631)
{
	$4631InformationCollected = new-object PSObject
	$RootCauseName = "RC_MPIO2K3Check"
	$PublicContent = "http://support.microsoft.com/kb/961640"
	$Verbosity = "Warning"
	$Visibility = "4"
	
	$MpioRegistryImagePath = (Get-ItemProperty ("HKLM:\System\CurrentControlSet\Services\Mpio")).ImagePath
	if($null -ne $MpioRegistryImagePath)
	{
		$MpiofilePath = join-path $env:windir "$MpioRegistryImagePath"
	}
	else
	{
		$MpiofilePath = join-path $env:windir "system32\drivers\mpio.sys"
	}
	
	#Detect root cause 
	if (-not(CheckMinimalFileVersion $MpiofilePath 1 23 -ForceMinorCheck))
	{		
		$currentVersion = Get-FileVersionString($MpiofilePath)	
		$requiredVersion = "1.23"
		if(-not(checkTagProcessInfo -TagName "Mpio" -InformationCollected $4631InformationCollected -NonPagedPoolCheck))
		{
			add-member -inputobject $4631InformationCollected -membertype noteproperty -name "MPIO Pool Memory usage" -Value $null
		}
		add-member -inputobject $4631InformationCollected -membertype noteproperty -name "Current Mpio.sys version" -value $currentVersion
		add-member -inputobject $4631InformationCollected -membertype noteproperty -name "Required Mpio.sys version" -value $requiredVersion
	
		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL $PublicContent -InformationCollected $4631InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID -SolutionTitle $ScriptStrings.ID_MPIO2K3Check_ST
	}
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}

#endregion

#region rule 4062 and 5769 related function and detect logic

Display-DefaultActivity -Rule -RuleNumber 4062

$script:BaspfilePath = join-path $env:windir "system32\drivers\Basp.sys"

Function isAffectedOSVersionFor4062
{
	if((($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 1)) -and  #Windows Server 2008 R2
	   (isServerMedia)) #Server Media
	{	
		if(Test-Path $script:BaspfilePath) #check BASP.SYS present on the system
		{
			return $true
		}
		else
		{
			return $false
		}
	}
	else
	{
		return $false
	}
}

#rule 4062,5769 detect logic
if (isAffectedOSVersionFor4062)
{
	$4062InformationCollected = new-object PSObject
	$RootCauseName = "RC_BASPNPPLeakCheck"
	$InternalContent = "https://vkbexternal.partners.extranet.microsoft.com/VKBWebService/ViewContent.aspx?scid=B;EN-US;2211813"
	$Verbosity = "Error"
	$Visibility = "3"
	
	#Detect root cause 
	if (-not(CheckMinimalFileVersion $script:BaspfilePath 1 3 23 0 ) -and (checkTagProcessInfo -TagName "Blfp" -InformationCollected $4062InformationCollected -NonPagedPoolCheck))
	{	
		$currentVersion = Get-FileVersionString($script:BaspfilePath)
		
		add-member -inputobject $4062InformationCollected -membertype noteproperty -name "Current Basp.sys version" -value $currentVersion
	
		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -InternalContentURL $InternalContent -InformationCollected $4062InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID -SolutionTitle $ScriptStrings.ID_BASPNPPLeakCheck_ST
	}
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}

#endregion

#region rule 4061 related function and detect logic

Display-DefaultActivity -Rule -RuleNumber 4061

Function isAffectedOSVersionFor4061
{
	if((($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2)) -or #Server 2003
	   (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 0)) -or #Server 2008
	   (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 1))) #Windows Server 2008 R2 
	{	
		if(($OSArchitecture -like "*64*") -and (isServerMedia)) #check the OS is X64 version and is Server Media
		{
			return $true
		}
		else
		{
			return $false
		}
	}
	else
	{
		return $false
	}
}

#rule 4061 detect logic
if (isAffectedOSVersionFor4061)
{
	$4061InformationCollected = new-object PSObject
	$RootCauseName = "RC_AladdinDeviceDriversCheck"
	$InternalContent = "https://vkbexternal.partners.extranet.microsoft.com/VKBWebService/ViewContent.aspx?scid=B;EN-US;2461230"
	$Verbosity = "Error"
	$Visibility = "3"
	$HardlockfilePath = join-path $env:windir "system32\drivers\Hardlock.sys"
	$AksdffilePath = join-path $env:windir "system32\drivers\Aksdf.sys"
	
	$HardlockFileVersionInfo = getFileVersionInfo($HardlockfilePath)
	if($null -ne $HardlockFileVersionInfo)
	{
		$HardlockcurrentVersion = Get-FileVersionString($HardlockfilePath)
	}
		
	$AksdfFileVersionInfo = getFileVersionInfo($AksdffilePath)
	if($null -ne $AksdfFileVersionInfo)
	{
		$AksdfcurrentVersion = Get-FileVersionString($AksdffilePath)
	}
	
	#Detect root cause 
	if ((($HardlockFileVersionInfo.FileMajorPart -eq 3 ) -and ($HardlockFileVersionInfo.FileMinorPart -eq 42 )) -and (($AksdfFileVersionInfo.FileMajorPart -eq 1 ) -and ($AksdfFileVersionInfo.FileMinorPart -eq 11 )))
	{				
		if($script:NonPagePool.ContainsKey("Proc"))
		{
			add-member -inputobject $4061InformationCollected -membertype noteproperty -name "Proc Kernel Tag Current Usage" -value (FormatBytes -bytes $script:NonPagePool["Proc"] -precision 2)
		}
		
		if($script:NonPagePool.ContainsKey("Toke"))
		{
			add-member -inputobject $4061InformationCollected -membertype noteproperty -name "Toke Kernel Tag Current Usage" -value (FormatBytes -bytes $script:NonPagePool["Toke"] -precision 2)
		}
		
		add-member -inputobject $4061InformationCollected -membertype noteproperty -name "Current Hardlock.sys version" -value $HardlockcurrentVersion
		add-member -inputobject $4061InformationCollected -membertype noteproperty -name "Current Aksdf.sys version" -value $AksdfcurrentVersion
	
		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Write-GenericMessage -RootCauseId $RootCauseName -InternalContentURL $InternalContent -InformationCollected $4061InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID -SolutionTitle $ScriptStrings.ID_AladdinDeviceDriversCheck_ST
	}
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}

#endregion

#region rule 6296 related function and detect logic

Display-DefaultActivity -Rule -RuleNumber 6296

Function isAffectedOSVersionFor6296
{
	return (($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2)) #Win Server 2003 
}

#rule 6296 detect logic
if (isAffectedOSVersionFor6296)
{
	$6296InformationCollected = new-object PSObject
	$RootCauseName = "RC_MemoryLeakInMountmgrCheck"
	$MountmgrfilePath = "$Env:windir\system32\drivers\Mountmgr.sys"

	$MountmgrCurrentVersionInfo = getFileVersionInfo($MountmgrfilePath)
	if($null -ne $MountmgrCurrentVersionInfo)
	{
		$MountmgrCurrentVersion = Get-FileVersionString($MountmgrfilePath)
		switch($MountmgrCurrentVersionInfo.FilePrivatePart.ToString().Remove(1))
		{
			"2" {
					$MountmgrRequiredVersion = "5.2.3790.2979"
					$CheckHotFix940307 = CheckMinimalFileVersion $MountmgrfilePath 5 2 3790 2979
				}
			"4" {
			       $MountmgrRequiredVersion = "5.2.3790.4121"
					$CheckHotFix940307 = CheckMinimalFileVersion $MountmgrfilePath 5 2 3790 4121
				}
		}
	}	

	#Detect root cause 
	if (-not($CheckHotFix940307) -and (checkTagProcessInfo -TagName "MntA" -InformationCollected $6296InformationCollected -Top 10))
	{		
		add-member -inputobject $6296InformationCollected -membertype noteproperty -name "Current Mountmgr.sys version" -value $MountmgrCurrentVersion
		add-member -inputobject $6296InformationCollected -membertype noteproperty -name "Required Mountmgr.sys version" -value $MountmgrRequiredVersion

		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Add-GenericMessage -Id $RootCauseName -InformationCollected $6296InformationCollected
	}
	else
	{
		# Green Light
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}

#endregion

#region rule 6911 related function and detect logic

Display-DefaultActivity -Rule -RuleNumber 6911

Function isAffectedOSVersionFor6911
{
	return (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 1)) #Windows 7 or Windows Server 2008 R2
}

#rule 6911 detect logic
if (isAffectedOSVersionFor6911)
{
	$6911InformationCollected = new-object PSObject
	$RootCauseName = "RC_ALPCandPowerManagementPoolCheck"
	
	#Detect root cause 
	if ((checkTagProcessInfo -TagName "AlMs" -InformationCollected $6911InformationCollected -Top 10) -and (checkTagProcessInfo -TagName "Powe" -InformationCollected $6911InformationCollected -Top 10 -NonPagedPoolCheck))
	{		
		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Add-GenericMessage -Id $RootCauseName -InformationCollected $6911InformationCollected
	}
	else
	{
		# Green Light
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
}

#endregion

#region rule 8267 related function and detect logic

Function isAffectedOSVersionFor8267 ($AdditionalFileToCheck)
{	
	$FileExists = Test-Path $AdditionalFileToCheck
	return (($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2) -and $FileExists) #Windows Server 2003 and WDICA file exists.
}

#rule 8267 detect logic
$WdicaFilePath = "$Env:windir\system32\drivers\WDICA.sys"
if (isAffectedOSVersionFor8267 -AdditionalFileToCheck $WdicaFilePath)
{
	Display-DefaultActivity -Rule -RuleNumber 8267
	
	$8267InformationCollected = new-object PSObject
	$RootCauseName = "RC_CitrixDriverCausedPagePoolMemoryLeak"	
	
	#Detect root cause 	
	$currentVersion = (Get-Item $WdicaFilePath).VersionInfo.ProductVersion
	if(($currentVersion -eq "4.5.4400.1") -and (checkTagProcessInfo -TagName "Ica" -InformationCollected $8267InformationCollected -NonPagedPoolCheck))
	{
		add-member -inputobject $8267InformationCollected -membertype noteproperty -name "Current WDICA.sys version" -value $currentVersion			
		# Red/ Yellow Light
		Update-DiagRootCause -id $RootCauseName -Detected $true
		Add-GenericMessage -Id $RootCauseName -InformationCollected $8267InformationCollected		
	}
	
	else
	{
		Update-DiagRootCause -id $RootCauseName -Detected $false
	}
	"$WdicaFilePath detected with version number $currentVersion" | WriteTo-StdOut
}

#endregion


# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAAsWCrhqPOvOhD
# HHmEqKH8kqtUZ1t1YqdkIId4w8hNRKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXUwghlxAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINpyNXJn628CIt1i/Hho03rn
# /BeWGJzhtJBfq2jMbU4DMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQC2L5/hilRqzu82cxsygM6oHE8ViPgkbzsNVKl+7rKyuirNvdQAwZuB
# ztz4dA7DJmqZatBIh+KbKdzDI+5zTeu6JxzjcfpvNS3e2GCYV3VijXHTdIztQqPo
# eZSuEsAmSk8jcPwegBvCz9+AZjYp3j4192qkjisfsPv2oigSU0sEyI6vkE7fWHxH
# Nl1vR4Fp6YEdKGIA1sCM2c6xKc9f8j4J5t3D/PPP5krQNSRfbTBrNjpxBRUdQ2A/
# NDKUwL8fmGwkh4C9hE5p7ZtbdAiQn5S5uL9bcMytuX9pieNx1B19ttqQbN76myU7
# oIWLGz2lrKBnkchDolXE34yfTM8r4Lw1oYIW/TCCFvkGCisGAQQBgjcDAwExghbp
# MIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIBcxWqFYOJSXvlKYobexbGTyN9kRgBc/HQtslanmXSEOAgZi1/U5
# ccwYEzIwMjIwODAxMDgwNTA0LjI0MlowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjIyNjQt
# RTMzRS03ODBDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVDCCBwwwggT0oAMCAQICEzMAAAGYdrOMxdAFoQEAAQAAAZgwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTE1WhcNMjMwMjI4MTkwNTE1WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MjI2NC1FMzNFLTc4MEMxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDG1JWsVksp8xG4sLMnfxfit3ShI+7G1MfTT+5XvQzu
# AOe8r5MRAFITTmjFxzoLFfmaxLvPVlmDgkDi0rqsOs9Al9jVwYSFVF/wWC2+B76O
# ysiyRjw+NPj5A4cmMhPqIdNkRLCE+wtuI/wCaq3/Lf4koDGudIcEYRgMqqToOOUI
# V4e7EdYb3k9rYPN7SslwsLFSp+Fvm/Qcy5KqfkmMX4S3oJx7HdiQhKbK1C6Zfib+
# 761bmrdPLT6eddlnywls7hCrIIuFtgUbUj6KJIZn1MbYY8hrAM59tvLpeGmFW3Gj
# eBAmvBxAn7o9Lp2nykT1w9I0s9ddwpFnjLT2PK74GDSsxFUZG1UtLypi/kZcg9We
# nPAZpUtPFfO5Mtif8Ja8jXXLIP6K+b5LiQV8oIxFSBfgFN7/TL2tSSfQVcvqX1mc
# SOrx/tsgq3L6YAxI6Pl4h1zQrcAmToypEoPYNc/RlSBk6ljmNyNDsX3gtK8p6c7H
# CWUhF+YjMgfanQmMjUYsbjdEsCyL6QAojZ0f6kteN4cV6obFwcUEviYygWbedaT8
# 6OGe9LEOxPuhzgFv2ZobVr0J8hl1FVdcZFbfFN/gdjHZ/ncDDqLNWgcoMoEhwwzo
# 7FAObqKaxfB5zCBqYSj45miNO5g3hP8AgC0eSCHl3rK7JPMr1B+8JTHtwRkSKz/+
# cwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFG6RhHKNpsg3mgons7LR5YHTzeE3MB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBACT6B6F33i/89zXTgqQ8L6CYMHx9BiaHOV+wk53JOriCzeaLjYgRyssJhmnn
# J/CdHa5qjcSwvRptWpZJPVK5sxhOIjRBPgs/3+ER0vS87IA+aGbf7NF7LZZlxWPO
# l/yFBg9qZ3tpOGOohQInQn5zpV23hWopaN4c49jGJHLPAfy9u7+ZSGQuw14CsW/X
# RLELHT18I60W0uKOBa5Pm2ViohMovcbpNUCEERqIO9WPwzIwMRRw34/LgjuslHJo
# p+/1Ve/CfyNqweUmwepQHJrd+wTLUlgm4ENbXF6i52jFfYpESwLdAn56o/pj+grs
# d2LrAEPQRyh49rWvI/qZfOhtT2FWmzFw6IJvZ7CzT1O+Fc0gIDBNqass5QbmkOkK
# Yy9U7nFA6qn3ZZ+MrZMsJTj7gxAf0yMkVqwYWZRk4brY9q8JDPmcfNSjRrVfpYyz
# EVEqemGanmxvDDTzS2wkSBa3zcNwOgYhWBTmJdLgyiWJGeqyj1m5bwNgnOw6NzXC
# iVMzfbztdkqOdTR88LtAJGNRjevWjQd5XitGuegSp2mMJglFzRwkncQau1BJsCj/
# 1aDY4oMiO8conkmaWBrYe11QCS896/sZwSdnEUJak0qpnBRFB+THRIxIivCKNbxG
# 2QRZ8dh95cOXgo0YvBN5a1p+iJ3vNwzneU2AIC7z3rrIbN2fMIIHcTCCBVmgAwIB
# AgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1
# WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
# 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZn
# hUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t
# 1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxq
# D89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmP
# frVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSW
# rAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
# 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zb
# r17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
# IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQc
# xWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17a
# j54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3h
# LB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
# 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74p
# y27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1A
# oL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbC
# HcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB
# 9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNt
# yo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
# rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcV
# v7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
# 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lw
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAsswggI0AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjoyMjY0LUUzM0UtNzgwQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA8ywe/iF5M8fIU2aT6yQ3vnPpV5Og
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRnKMwIhgPMjAyMjA4MDEwODI4MTlaGA8yMDIyMDgwMjA4MjgxOVow
# dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5pGcowIBADAHAgEAAgISNDAHAgEAAgIR
# qTAKAgUA5pLuIwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAGW0b6G1nxJf
# Sz+162eIfZKEeCT5UlfEbylGeWHEIa2FOqerhClam6wPRPAJD+i5gmNDLWEXoJhE
# 9mfD/DNtILqESrGPO8DLhy1fGnzIFrHCh+Hmog+1BobdtTTDsZ63lI6Mp6+O44xP
# gtveVE5cjYmTGOZttcbmk0FXsnRiWdbDMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGYdrOMxdAFoQEAAQAAAZgwDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgcWITHDeCZ2CmSYxscUA2oeXyA9lgZdEVvsrzQm8H72AwgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCC/ps4GOTn/9wO1NhHM9Qfe0loB3slkw1FF
# 3r+bh21WxDCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABmHazjMXQBaEBAAEAAAGYMCIEIITB9XHZkmFVJEo8WDGAMhrrxCbnPT0sQRQc
# 2rAtWwOFMA0GCSqGSIb3DQEBCwUABIICAGKacULKHbrkL7DftIU3i0KuXu+k0Yde
# kOJHNK2CHXAiu8FTHqIsCQL/IafREpzBB4tMBa8oU6y+uK4aWMrzFcf8SIEFgfz2
# QFvz3YDhujkOnGUK+0Bf/y/O8o2CrYewd6CGZC+jPH5HNZ1Kdet7+4yYFuLdozwy
# jANgHYYqOkey3KP7Zqg1nba7hkf3X3TyUsX+BSFtMhsw7IwiiJgRLA809yGqQBP7
# gLf5cqiFaemh+nBMU5AXSp+svi44w8Vz1WAveK2Hq0knOBbegK7HOz1FOlLyN4rH
# Mx7ssYJSq2MW+rSmKuOpE34+TVcljZcGXGZ9rJ70SVG6YjNjMjkz2WOm/ZfNtd2a
# wIAfETAaztKUxn0M35gbtFGkYumUs0yK2YC3+Su/fBod5iJNIZCYTJoKa7X/793X
# 6GQyF+JnD4qAcXSg4DUtPHGDG5X2QWkx0a4AN6IfbjcZvImLSnlczXP8E8QzX+bU
# VMm9qoJdXYNppADcuckZB+aakEhic6/cJrk9crDNt+PQ/RaC5A3uTRamn0D1UNOO
# l17bd4jWXQZtzN69xtaVlJ6w2CCiEQXPB1J0Y5iT6E6ATpH4Xrj0DB8g5dmP5IPz
# 7lczql4FFCtTwgKAHwsYEKVhBTP/iUaBTUAHnBwKEebIdMl8em3AttMtc5NYyDmT
# fuG0RYs6wHfj
# SIG # End signature block
