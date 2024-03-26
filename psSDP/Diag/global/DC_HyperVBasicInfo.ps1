#************************************************
# DC_HyperVBasicInfo.ps1
# Version 1.0
# Date: 4-7-2015
# Author: Ryutaro Hayashi <Ryutaro.Hayashi@microsoft.com>
# Ported to SDP and included in HyperV SDP by Tim Springston <tspring@microsoft.com>
# Description: Data collection for hyperv.
#************************************************
#Output file info
$FileDescription = "Text File containing Hyper-V basic settings and configuration information."
$SectionDescription = "Hyper-V Basic Information"
$Outputfile = Join-Path $Pwd.Path (($env:COMPUTERNAME) + "_Hyper-VBasicInfo.txt")

Get-Date | Out-File $Outputfile -encoding UTF8

Filter Import-CimXml
{
    # Create new XML object from input
    $CimXml = [Xml]$_
    $CimObj = New-Object -TypeName System.Object
    
    # Iterate over the data and pull out just the value name and data for each entry
    ForEach ($CimProperty in $CimXml.SelectNodes("/INSTANCE/PROPERTY[@NAME='Name']"))
    {
        $CimObj | Add-Member -MemberType NoteProperty -Name $CimProperty.NAME -Value $CimProperty.VALUE
    }

    ForEach ($CimProperty in $CimXml.SelectNodes("/INSTANCE/PROPERTY[@NAME='Data']"))
    {
        $CimObj | Add-Member -MemberType NoteProperty -Name $CimProperty.NAME -Value $CimProperty.VALUE
    }

    # Display output
    $CimObj
}

Function showHVGlobalSettings
{
    $VSMgtServiceSettingData = $args[0]

    ("Hyper-V Global Settings") | Out-File $Outputfile  -Append -encoding UTF8
    ("----------------------------------------") | Out-File $Outputfile  -Append -encoding UTF8
    ("") | Out-File $Outputfile  -Append -encoding UTF8

    ("Hyper-V Settings:") | Out-File $Outputfile  -Append -encoding UTF8
    ("    Virtual Hard Disks: " + $VSMgtServiceSettingData.DefaultVirtualHardDiskPath) | Out-File $Outputfile  -Append -encoding UTF8
    ("    Virtual Machines: " + $VSMgtServiceSettingData.DefaultExternalDataRoot) | Out-File $Outputfile  -Append -encoding UTF8
    ("    Physical GPUs: ") | Out-File $Outputfile  -Append -encoding UTF8
    ("    NUMA Spanning: " + $VSMgtServiceSettingData.NumaSpanningEnabled) | Out-File $Outputfile  -Append -encoding UTF8

    ### Live migrations
    $VSMigrationService = Get-CimInstance -Namespace 'root\virtualization\v2' -Class 'Msvm_VirtualSystemMigrationService' 
    $VSMigServiceSettingData = $VSMigrationService.GetRelated('Msvm_VirtualSystemMigrationServiceSettingData') 
    ("    Live Migrations:") | Out-File $Outputfile  -Append -encoding UTF8
    ("        Enable incoming and outgoing live migrations: " + $VSMigServiceSettingData.EnableVirtualSystemMigration) | Out-File $Outputfile  -Append -encoding UTF8

    switch ($VSMigServiceSettingData.AuthenticationType)
    {
        0   {$AuthTypeStr = "CredSSP(0)"}
        1   {$AuthTypeStr = "Kerberos(1)"}
    }
    ("        Authentication protocol: " + $AuthTypeStr) | Out-File $Outputfile  -Append -encoding UTF8
    ("        Simultaneous live migrations: " + $VSMigServiceSettingData.MaximumActiveVirtualSystemMigration) | Out-File $Outputfile  -Append -encoding UTF8
    ("        Incoming live migrations: ") | Out-File $Outputfile  -Append -encoding UTF8

    $MigNetworksSettings = Get-CimInstance -Namespace 'root\virtualization\v2' -Class 'Msvm_VirtualSystemMigrationNetworkSettingData' 
    $NetworksSet = 0

    ForEach($MigNetworksSetting in $MigNetworksSettings)
    {
        For($i=0; $i -lt $MigNetworksSetting.Tags.Count; $i++)
        {
            If($MigNetworksSetting.Tags[$i] -eq "Microsoft:UserManagedAllNetworks")
            {
                $NetworksSet++
            }
        }
    }
    
    If($NetworksSet -gt 0)
    {
        $NetworkOptionStr = "Use any available network for live migration"
    }
    Else
    {
        $NetworkOptionStr = "Use these IP addresses for live migration"
        $IPList = $VSMigrationService.MigrationServiceListenerIPAddressList

        For($y=0; $y -lt $IPLIst.count; $y++)
        {
            $IPListStr = $IPListStr + " " + $IPList[$y]
        }
    }

    ("            Option: " + $NetworkOptionStr) | Out-File $Outputfile  -Append -encoding UTF8

    If($NetworksSet -eq 0)
    {
        ("                Network List: " + $IPListStr) | Out-File $Outputfile  -Append -encoding UTF8
    }

    #### Storage Migrations
    ("    Storage Migrations:") | Out-File $Outputfile  -Append -encoding UTF8
    ("        Simultaneous storage migrations: " + $VSMigServiceSettingData.MaximumActiveStorageMigration) | Out-File $Outputfile  -Append -encoding UTF8

    ### Replication Configuration
    ("    Replication Configuration:") | Out-File $Outputfile  -Append -encoding UTF8
    $HVRServiceSettingData = Get-CimInstance -Namespace 'root\virtualization\v2' -Class 'Msvm_ReplicationServiceSettingData'

    If ($HVRServiceSettingData.RecoveryServerEnabled) 
    {
       switch ($HVRServiceSettingData.AllowedAuthenticationType)
        {
            0   {$AllowedAuthenticationType = "Not defined"}
            1   {$AllowedAuthenticationType = "Use kerberos (HTTP)"}
            2   {$AllowedAuthenticationType = "Use certificate-based Authentication"}
            3   {$AllowedAuthenticationType = "Both certificate based authentication and integrated authentication"}
        }

        ("        Authentication and ports:") | Out-File $Outputfile  -Append -encoding UTF8
        ("            Authentication Type: " + $AllowedAuthenticationType) | Out-File $Outputfile  -Append -encoding UTF8 
        ("            HttpPort(Kerberos) : " + $HVRServiceSettingData.HttpPort) | Out-File $Outputfile  -Append -encoding UTF8
        ("            HttpsPort(Certificate): " + $HVRServiceSettingData.HttpsPort) | Out-File $Outputfile  -Append -encoding UTF8

        $HVRAuthSettingData = Get-CimInstance -Namespace 'root\virtualization\v2' -Class 'Msvm_ReplicationAuthorizationSettingData'
        $AuthEntryCount = ($HVRAuthSettingData | Measure-Object).count

        ("        Authentication and Storage:") | Out-File $Outputfile  -Append -encoding UTF8
 
        If($AuthEntryCount -eq 1 -and $HVRAuthSettingData.AllowedPrimaryHostSystem -eq "*")
        {
            $AuthServerStr = "Type: Allow replication from any authenticated server"
            ("            " + $AuthServerStr) | Out-File $Outputfile  -Append -encoding UTF8
            ("            Storage location: " + $HVRAuthSettingData.ReplicaStorageLocation) | Out-File $Outputfile  -Append -encoding UTF8
        }
        Else
        {
            $AuthServerStr = "Type: Allow replication from specifed servers"
            ("            " + $AuthServerStr) | Out-File $Outputfile  -Append -encoding UTF8
            ForEach($HVRAuthSetting in $HVRAuthSettingData)
            {
                ("                Primary server: " + $HVRAuthSetting.AllowedPrimaryHostSystem + " | Storage location: "  + $HVRAuthSetting.ReplicaStorageLocation + " | TrustGroup: " + $HVRAuthSetting.TrustGroup) | Out-File $Outputfile  -Append -encoding UTF8
            }
        }
    }
    Else
    {
         ("        Hyper-V Replica is not configured as replica server.") | Out-File $Outputfile  -Append -encoding UTF8
    }

    ### Enhanced Session Mode Policy (WS2012R2 or later)
    If($VSMgtServiceSettingData.EnhancedSessionModeEnabled -eq $null)
    {
        $EnhancedSessionMode = "N/A (Enhanced session mode is supported from Windows Server 2012 R2)"
    } 
    Else
    {
        $EnhancedSessionMode = $VSMgtServiceSettingData.EnhancedSessionModeEnabled     
    }

    ("    Enhanced session mode policy: " + $EnhancedSessionMode) | Out-File $Outputfile  -Append -encoding UTF8

    ### Memory reserve
    $memReserveRegKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\"
    $memReserveReg = Get-ItemProperty $memReserveRegKey
    $memoryReserve = $memReserveReg."MemoryReserve"

    If($memoryReserve -ne $null)
    {
        ("    Memory Reserve: " + $memoryReserve + " MB(WARNING: Memory reserve is set)") | Out-File $Outputfile  -Append -encoding UTF8
    }

    ("") | Out-File $Outputfile  -Append -encoding UTF8
}

Function showNUMAinfo()
{

    ("NUMA Information") | Out-File $Outputfile  -Append -encoding UTF8
    ("----------------------------------------") | Out-File $Outputfile  -Append -encoding UTF8

    $hostName = hostname
    $hostComputer = Get-CimInstance -Namespace 'root\virtualization\v2' -Class 'Msvm_ComputerSystem' | Where-Object { $_.ElementName -eq $hostname}
    $numaNodes = $hostComputer.GetRelated("Msvm_NumaNode")
    
    Foreach($numaNode in $numaNodes) {
        ("") | Out-File $Outputfile  -Append -encoding UTF8 
        ($numaNode.ElementName + ":") | Out-File $Outputfile  -Append -encoding UTF8
        ("    EnabledState                   : " + $numaNode.EnabledState) | Out-File $Outputfile  -Append -encoding UTF8
        ("    HealthState                    : " + $numaNode.HealthState) | Out-File $Outputfile  -Append -encoding UTF8
        ("    NumberOfLogicalProcessors      : " + $numaNode.NumberOfLogicalProcessors) | Out-File $Outputfile  -Append -encoding UTF8
        ("    NumberOfProcessorCores         : " + $numaNode.NumberOfProcessorCores) | Out-File $Outputfile  -Append -encoding UTF8
        ("    CurrentlyConsumableMemoryBlocks: " + $numaNode.CurrentlyConsumableMemoryBlocks) | Out-File $Outputfile  -Append -encoding UTF8
        ("") | Out-File $Outputfile  -Append -encoding UTF8
        
        $Memory = $numaNode.GetRelated("Msvm_Memory") | Where-Object { $_.SystemName -eq $hostName}
        $MemSizeGB = ($Memory.ConsumableBlocks * $Memory.BlockSize / 1024 / 1024 / 1024)
        $MemSizeGB2 = [math]::round($MemSizeGB, 2)
        $MemSizeMB = ($Memory.ConsumableBlocks * $Memory.BlockSize / 1024 / 1024)

        ("    ==== " + $Memory.ElementName + " ====") | Out-File $Outputfile  -Append -encoding UTF8
        ("    BlockSize                      : " + $Memory.BlockSize) | Out-File $Outputfile  -Append -encoding UTF8
        ("    ConsumableBlocks               : " + $Memory.ConsumableBlocks) | Out-File $Outputfile  -Append -encoding UTF8
        ("    Size                           : " + $MemSizeMB + "MB / " + $MemSizeGB2 + "GB") | Out-File $Outputfile  -Append -encoding UTF8
        ("    EnabledState                   : " + $Memory.EnabledState) | Out-File $Outputfile  -Append -encoding UTF8
        ("    HealthState                    : " + $Memory.HealthState) | Out-File $Outputfile  -Append -encoding UTF8
        ("") | Out-File $Outputfile  -Append -encoding UTF8
    }
}

Function showVMBasicinfo()
{
    $VM = $args[0]
    $VSSettingData = $args[1]
    ("Basic information:") | Out-File $Outputfile  -Append -encoding UTF8
    ("    GUID: " + $VM.Name) | Out-File $Outputfile  -Append -encoding UTF8

    If($VM.ProcessID -eq $null)
    {
        $procId = "N/A => Virtual Machine is not running."
    }
    Else
    {
        $procId = $VM.ProcessID
    }

    ("    PID: " + $procId) | Out-File $Outputfile  -Append -encoding UTF8

    ### VM Version
    ("    Version: " + $VSSettingData.Version) | Out-File $Outputfile  -Append -encoding UTF8

    ### VM Generation
    $vmGgeneration = getVmGeneration $VSSettingData  
    ("    Generation: " + $vmGgeneration) | Out-File $Outputfile  -Append -encoding UTF8

    ### Enabled state
    $vmStatus = getVMEnabledState $VM.EnabledState
    ("    State: " + $vmStatus) | Out-File $Outputfile  -Append -encoding UTF8

    ### Heartbeat
    $heartbeatComponent = Get-CimInstance  -namespace 'root\virtualization\v2' -query "associators of {$VM} where ResultClass = Msvm_HeartbeatComponent"

    If($heartbeatComponent -eq $null)
    {
        $heartbeartStr = "N/A(Virtual Machine is not running)"
    }
    ElseIf($heartbeatComponent.EnabledState -eq 3) 
    {
        $heartbeartStr = "N/A(Heartbeat service is not enabled)"
    }
    Else
    {
        $hbStatusStr1 = getHBOperationalStatus $heartbeatComponent.OperationalStatus[0]
        $hbStatusStr2 = getHBSecondaryStatus $heartbeatComponent.OperationalStatus[1]
        $heartbeartStr = $hbStatusStr1 + "(Application state - " + $hbStatusStr2 + ")"
    }

    ("    Heartbeat: " + $heartbeartStr) | Out-File $Outputfile  -Append -encoding UTF8

    ### Health state
    switch ($VM.HealthState)
    {
        # https://msdn.microsoft.com/en-us/library/hh850116(v=vs.85).aspx
        5   {$healthState = "OK" + "(" + $VM.HealthState + ")"}
       20   {$healthState = "Major Failure" + "(" + $VM.HealthState + ")"}
       25   {$healthState = "Critical failure)" + "(" + $VM.HealthState + ")"}                               
    }

    ("    Health state: " + $healthState) | Out-File $Outputfile  -Append -encoding UTF8

    ### Uptime
    $uptimeSeconds = $VM.OnTimeInMilliseconds / 1000
    $uptimeMinutes = $uptimeSeconds / 60
    $seconds = [math]::Truncate($uptimeSeconds % 60)
    $minutes = [math]::Truncate($uptimeMinutes % 60)
    $hours = [math]::Truncate($uptimeSeconds / 3600)

    ("    Uptime: " + $hours + ":" + $minutes +  ":" + $seconds) | Out-File $Outputfile  -Append -encoding UTF8
 
    ### IC version
    If($VM.EnabledState -eq 2)
    {
        $KvpExchangeComponent = $VM.GetRelated("Msvm_KvpExchangeComponent")

        If($KvpExchangeComponent.count -eq 0)
        {
            $versionString = "Unable to retrieve IC version. VM would not be started."
        }
        ElseIf($KvpExchangeComponent.GuestIntrinsicExchangeItems -ne $null)
        {
            $IntrinsicItems = $KvpExchangeComponent.GuestIntrinsicExchangeItems | Import-CimXml 
            $icVersionItem = $IntrinsicItems | Where {$_.Name -eq "IntegrationServicesVersion"}

            If($icVersionItem.Data -ne $null)
            {
                $versionString = $icVersionItem.Data
                $icVersionExist = $True
            }
            Else
            {
                $versionString = "Unable to retrieve IC version. Key exchange service would not be running in guest."
            }
        }
        Else
        {
            $versionString = "Unable to retrieve IC version. Key exchange service would not be running in guest."
        }
    }
    Else
    {
        $versionString = "N/A(VM is not running)"
    }

    $icRegistryKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestInstaller\Version\"
	$icReg = Get-ItemProperty $icRegistryKey -EA SilentlyContinue
	if ($icReg) {	$hostICVersion =  $icReg."Microsoft-Hyper-V-Guest-Installer-Win6x-Package" }
    If($hostICVersion -eq $icVersionItem.Data)
    {
        ("    Integration Service Version: " + $versionString + " => IC version is same with host version.") | Out-File $Outputfile  -Append -encoding UTF8
    }
    ElseIf($icVersionExist)
    {
        ("    Integration Service Version: " + $versionString + " => WARNING: IC version is not same with host version(" + $hostICVersion + ").") | Out-File $Outputfile  -Append -encoding UTF8
    }
    Else
    {
        ("    Integration Service Version: " + $versionString) | Out-File $Outputfile  -Append -encoding UTF8
    }

    If($VM.EnhancedSessionModeState -ne $null)
    {
        switch ($VM.EnhancedSessionModeState)
        {
            2   {$EnhancedSessionModeState = "Enhanced mode is allowed and available on the virtual machine(2)"}
            3   {$EnhancedSessionModeState = "Enhanced mode is not allowed on the virtual machine(3)"}
            6   {$EnhancedSessionModeState = "Enhanced mode is allowed and but not currently available on the virtual machine(6)"}
            default {$EnhancedSessionModeState = "Unknown"}
        }
        ("    EnhancedSession Mode:  " + $EnhancedSessionModeState) | Out-File $Outputfile  -Append -encoding UTF8
    }

    ("    Number of NUMA nodes: " + $VM.NumberOfNumaNodes) | Out-File $Outputfile  -Append -encoding UTF8

    ### Configuration file
    $configPath = $VSSettingData.ConfigurationDataRoot + "\" + $VSSettingData.ConfigurationFile
    ("    Configuration File: " + $configPath) | Out-File $Outputfile  -Append -encoding UTF8



    ("") | Out-File $Outputfile  -Append -encoding UTF8
}

Function showKVPItems()
{
    $VM = $args[0]
    $VSSettingData = $args[1]

    $KvpExchangeComponent = $VM.GetRelated("Msvm_KvpExchangeComponent")
    $KvpExchangeComponentSettingData = $VSSettingData.GetRelated("Msvm_KvpExchangeComponentSettingData")

    ("KVP Items:") | Out-File $Outputfile  -Append -encoding UTF8
    ("    Guest intrinsic items:") | Out-File $Outputfile  -Append -encoding UTF8

    If($KvpExchangeComponent.count -eq 0)
    {
        ("        Unable to retrieve guest items. VM would not be started.") | Out-File $Outputfile  -Append -encoding UTF8
    }
    ElseIf($KvpExchangeComponent.GuestIntrinsicExchangeItems -ne $null)
    {
        $IntrinsicItems = $KvpExchangeComponent.GuestIntrinsicExchangeItems | Import-CimXml 

        ForEach($IntrinsicItem in $IntrinsicItems)
        {
            ("        " + $IntrinsicItem.Name + ": " + $IntrinsicItem.Data) | Out-File $Outputfile  -Append -encoding UTF8
        }
        ("") | Out-File $Outputfile  -Append -encoding UTF8
    }
    Else
    {
        ("        Unable to retrieve guest items. Key exchange service would not be running in guest.") | Out-File $Outputfile  -Append -encoding UTF8
    }

    ("") | Out-File $Outputfile  -Append -encoding UTF8
    ("    Host only items:") | Out-File $Outputfile  -Append -encoding UTF8

    If($KvpExchangeComponentSettingData.HostOnlyItem -eq $null)
    {
        ("        No host only items.") | Out-File $Outputfile  -Append -encoding UTF8
    }
    Else
    {
        $HostItems = $KvpExchangeComponentSettingData.HostOnlyItems | Import-CimXml 
    
        If($HostItems.count -eq 0)
        {
            ("        No host only items are registerd.") | Out-File $Outputfile  -Append -encoding UTF8
        }
        Else
        {
            ForEach($HostItem in $HostItems)
            {
                ("        " + $HostItem.Name + ": " + $HostItem.Data) | Out-File $Outputfile  -Append -encoding UTF8
            }
        }
    }
    ("") | Out-File $Outputfile  -Append -encoding UTF8
}

Function showBIOSinfo
{
    $VSSettingData = $args[0]

    ("BIOS:") | Out-File $Outputfile  -Append -encoding UTF8
    ("    Num Lock: " + $VSSettingData.BIOSNumLock) | Out-File $Outputfile  -Append -encoding UTF8

    For($i=0; $i -lt $VSSettingData.BootOrder.length; $i++)
    {
        switch ($VSSettingData.BootOrder[$i])
        {
            0   {$deviceStr = "Floppy"}
            1   {$deviceStr = "CD-ROM"}
            2   {$deviceStr = "Hard Drive"}
            3   {$deviceStr = "PXE Boot"}
        }

        $BootOrderStr = $BootOrderStr + $deviceStr

        If($i -lt ($VSSettingData.BootOrder.length-1)) {
            $BootOrderStr = $BootOrderStr + " -> "
        }
    }

    ("    Startup order: " + $BootOrderStr) | Out-File $Outputfile  -Append -encoding UTF8
    ("") | Out-File $Outputfile  -Append -encoding UTF8
}

Function showMeminfo 
{
    $VSSettingData = $args[0]
    $MemSettingData = $VSSettingData.GetRelated('Msvm_MemorySettingData')
    ("Memory:") | Out-File $Outputfile  -Append -encoding UTF8
    ("    Startup RAM: " + $MemSettingData.VirtualQuantity + "MB") | Out-File $Outputfile  -Append -encoding UTF8
    ("    Enable Dynamic Memory: " + $MemSettingData.DynamicMemoryEnabled) | Out-File $Outputfile  -Append -encoding UTF8

    If($MemSettingData.DynamicMemoryEnabled)
    {
        ("        Minimum RAM: " + $MemSettingData.Reservation + "MB") | Out-File $Outputfile  -Append -encoding UTF8
        ("        Maximum RAM: " + $MemSettingData.Limit + "MB") | Out-File $Outputfile  -Append -encoding UTF8
        ("        Memory Buffer: " + $MemSettingData.TargetMemoryBuffer) | Out-File $Outputfile  -Append -encoding UTF8
    }

    ("    Memory Weight: " + $MemSettingData.Weight) | Out-File $Outputfile  -Append -encoding UTF8
    ("") | Out-File $Outputfile  -Append -encoding UTF8
}

Function showCPUinfo 
{
    $VSSettingData = $args[0]
    $ProcSettingData = $VSSettingData.GetRelated('Msvm_ProcessorSettingData')
    ("Processor:") | Out-File $Outputfile  -Append -encoding UTF8
    ("    Number of Virtual Processors: " + $ProcSettingData.VirtualQuantity) | Out-File $Outputfile  -Append -encoding UTF8
    ("    Resource control: ") | Out-File $Outputfile  -Append -encoding UTF8
    ("        Virtual machine reserve: " + $ProcSettingData.Reservation / 1000) | Out-File $Outputfile  -Append -encoding UTF8
    ("        Virtual machine limit  : " + $ProcSettingData.Limit / 1000) | Out-File $Outputfile  -Append -encoding UTF8
    ("        Relative weight        : " + $ProcSettingData.Weight) | Out-File $Outputfile  -Append -encoding UTF8
    ("    Compatibility: ") | Out-File $Outputfile  -Append -encoding UTF8
    ("        Migrate to physical computer with a differnet processor version: " + $ProcSettingData.LimitProcessorFeatures) | Out-File $Outputfile  -Append -encoding UTF8
    ("    NUMA: ") | Out-File $Outputfile  -Append -encoding UTF8
    ("        Maximum number of virtual processors  : " + $ProcSettingData.MaxProcessorsPerNumaNode) | Out-File $Outputfile  -Append -encoding UTF8

    $MemSettingData = $VSSettingData.GetRelated('Msvm_MemorySettingData')
    ("        MaxMemoryBlocksPerNumaNode            : " + $MemSettingData.MaxMemoryBlocksPerNumaNode + " MB") | Out-File $Outputfile  -Append -encoding UTF8
    ("        Maximum NUMA nodes allowed on a socket: " + $ProcSettingData.MaxNumaNodesPerSocket) | Out-File $Outputfile  -Append -encoding UTF8
    ("") | Out-File $Outputfile  -Append -encoding UTF8
}

Function showIDEHardDriveinfo 
{
    $VM = $args[0]

    ("IDE Controller :") | Out-File $Outputfile  -Append -encoding UTF8

    $hardDrives = Get-VMHardDiskDrive -VMName $VM.ElementName | Where-Object {$_.ControllerType -eq "IDE" }

	If($hardDrives.count -eq 0)
       {
           ("    No IDE drive attached.") | Out-File $Outputfile  -Append -encoding UTF8
           ("") | Out-File $Outputfile  -Append -encoding UTF8
           return
       }

	ForEach($hardDrive in $hardDrives)
    {
        If($hardDrive.ControllerType -eq "IDE")
        {
            ("    Virtual Hard Disks: ") | Out-File $Outputfile  -Append -encoding UTF8

            If( $hardDrive.Path -eq $null)
            {
                ("        WARNING: Disk path is null. Probably the disk is removed or deleted.")  | Out-File $Outputfile  -Append -encoding UTF8
                continue
            }
            Else
            {
                ("        - " + $hardDrive.Path) | Out-File $Outputfile  -Append -encoding UTF8
                ("            Location: " + $hardDrive.Name) | Out-File $Outputfile  -Append -encoding UTF8
            }

            If(!(Test-Path $hardDrive.Path))
            {
                ("        WARNING: the file does not exist.") | Out-File $Outputfile  -Append -encoding UTF8
                continue
            }

            $vhdInfo = Get-VHD -Path $hardDrive.Path
            $property = Get-ChildItem $hardDrive.Path
            $fileSize = [math]::round($property.Length / 1GB , 3)
            $maxFileSize = [math]::round($vhdInfo.Size / 1GB , 3)
            $ACL = Get-ACL $hardDrive.Path

            ("            VhdType: " + $vhdInfo.VhdType) | Out-File $Outputfile  -Append -encoding UTF8
            ("            Creation time: " + $property.CreationTime + "    " + "Last write time: " + $property.LastWriteTime) | Out-File $Outputfile  -Append -encoding UTF8
            ("            Current size: " + $fileSize + " GB" + "  /  Max file size: " + $maxFileSize + " GB") | Out-File $Outputfile  -Append -encoding UTF8
            ("            LogicalSectorSize: " + $vhdInfo.LogicalSectorSize + " bytes  /  PhysicalSectorSize: " + $vhdInfo.PhysicalSectorSize + " bytes") | Out-File $Outputfile  -Append -encoding UTF8
            ("            Owner: " + $ACL.Owner) | Out-File $Outputfile  -Append -encoding UTF8
            ("            ACL: ") | Out-File $Outputfile  -Append -encoding UTF8

            $AccessRules = $ACL.GetAccessRules($true,$true, [System.Security.Principal.NTAccount])

            ForEach($AccessRule in $AccessRules)
            {
                ("                " + $AccessRule.IdentityReference + " => " + $AccessRule.FileSystemRights) | Out-File $Outputfile  -Append -encoding UTF8
            }
            ("            ID: " + $hardDrive.ID) | Out-File $Outputfile  -Append -encoding UTF8
            ("") | Out-File $Outputfile  -Append -encoding UTF8

            ### Advanced Features(Windows Server 2012 R2 or later)
            ("    Advanced Features:") | Out-File $Outputfile  -Append -encoding UTF8

            $StorageAllocationSettingData = Get-CimInstance -Namespace 'root\virtualization\v2' -Class 'Msvm_StorageAllocationSettingData' | Where-Object { $_.HostResource  -eq $hardDrive.Path}
            
            If($StorageAllocationSettingData.IOPSLimit -eq $null)
            {
                $isStorageQoSEnabled = $false
                $StorageQoSStr = "This feature is supported from Windows Server 2012 R2."
            }
            ElseIf($StorageAllocationSettingData.IOPSLimit -eq 0)
            {
                $isStorageQoSEnabled = $false
                $StorageQoSStr = "Disabled"
            }
            Else
            {
                $isStorageQoSEnabled = $true
                $StorageQoSStr = "Enabled"
            }

            ("        Enable Quality of Service management: " + $StorageQoSStr)  | Out-File $Outputfile  -Append -encoding UTF8
  
            If($isStorageQoSEnabled)
            {
                ("            Minimum: " + $StorageAllocationSettingData.IOPSReservation) | Out-File $Outputfile  -Append -encoding UTF8
                ("            Maximum: " + $StorageAllocationSettingData.IOPSLimit) | Out-File $Outputfile  -Append -encoding UTF8
            }
        }
        ("") | Out-File $Outputfile  -Append -encoding UTF8
    }
}

Function showSCSIHardDriveinfo 
{
    $VM = $args[0]
    ("SCSI Controller :") | Out-File $Outputfile  -Append -encoding UTF8

    $hardDrives = Get-VMHardDiskDrive -VMName $VM.ElementName | Where-Object {$_.ControllerType -eq "SCSI" }
    If($hardDrives.count -eq 0)
    {
        ("    No SCSI drive attached.") | Out-File $Outputfile  -Append -encoding UTF8
        ("") | Out-File $Outputfile  -Append -encoding UTF8
        return
    }

    ForEach($hardDrive in $hardDrives)
    {
        If($hardDrive.ControllerType -eq "SCSI")
        {
            ("    Virtual Hard Disks: ") | Out-File $Outputfile  -Append -encoding UTF8

            If( $hardDrive.Path -eq $null)
            {
                ("        WARNING: Disk path is null. Probably the disk is detached or deleted.")  | Out-File $Outputfile  -Append -encoding UTF8
                continue  
            }
            Else
            {  
                ("        - " + $hardDrive.Path) | Out-File $Outputfile  -Append -encoding UTF8
                ("            Location: " + $hardDrive.Name) | Out-File $Outputfile  -Append -encoding UTF8
            }

            If(!(Test-Path $hardDrive.Path))
            {
               ("            WARNING: above file does not exist.") | Out-File $Outputfile  -Append -encoding UTF8
                continue
            }

            $vhdInfo = Get-VHD -Path $hardDrive.Path 
            $property = Get-ChildItem $hardDrive.Path
            $fileSize = [math]::round($property.Length / 1GB , 3)
            $maxFileSize = [math]::round($vhdInfo.Size / 1GB , 3)
            $ACL = Get-ACL $hardDrive.Path            

            ("            VhdType: " + $vhdInfo.VhdType) | Out-File $Outputfile  -Append -encoding UTF8
            ("            Creation time: " + $property.CreationTime + "    " + "Last write time: " + $property.LastWriteTime) | Out-File $Outputfile  -Append -encoding UTF8
            ("            Current size: " + $fileSize + " GB" + "  /  Max file size: " + $maxFileSize + " GB") | Out-File $Outputfile  -Append -encoding UTF8
            ("            LogicalSectorSize: " + $vhdInfo.LogicalSectorSize + " bytes  /  PhysicalSectorSize: " + $vhdInfo.PhysicalSectorSize + " bytes") | Out-File $Outputfile  -Append -encoding UTF8
            ("            Owner: " + $ACL.Owner) | Out-File $Outputfile  -Append -encoding UTF8
            ("            ACL: ") | Out-File $Outputfile  -Append -encoding UTF8

            $AccessRules = $ACL.GetAccessRules($true,$true, [System.Security.Principal.NTAccount])

            ForEach($AccessRule in $AccessRules)
            {
                ("                " + $AccessRule.IdentityReference + " => " + $AccessRule.FileSystemRights) | Out-File $Outputfile  -Append -encoding UTF8
            }
            ("            ID: " + $hardDrive.ID) | Out-File $Outputfile  -Append -encoding UTF8
            ("") | Out-File $Outputfile  -Append -encoding UTF8

            ### Advanced Features(Windows Server 2012 R2 or later)
            ("    Advanced Features:") | Out-File $Outputfile  -Append -encoding UTF8

            $StorageAllocationSettingData = Get-CimInstance -Namespace 'root\virtualization\v2' -Class 'Msvm_StorageAllocationSettingData' | Where-Object { $_.HostResource  -eq $hardDrive.Path}
            
            # Storage Qos
            If($StorageAllocationSettingData.IOPSLimit -eq $null)
            {
                $isStorageQoSEnabled = $false
                $StorageQoSStr = "This feature is supported from Windows Server 2012 R2."
            }
            ElseIf($StorageAllocationSettingData.IOPSLimit -eq 0)
            {
                $isStorageQoSEnabled = $false
                $StorageQoSStr = "Disabled"
            }
            Else
            {
                $isStorageQoSEnabled = $true
                $StorageQoSStr = "Enabled"
            }

            ("        Enable Quality of Service management: " + $StorageQoSStr) | Out-File $Outputfile  -Append -encoding UTF8
  
            If($isStorageQoSEnabled)
            {
                ("            Minimum: " + $StorageAllocationSettingData.IOPSReservation) | Out-File $Outputfile  -Append -encoding UTF8
                ("            Maximum: " + $StorageAllocationSettingData.IOPSLimit) | Out-File $Outputfile  -Append -encoding UTF8
                ("") | Out-File $Outputfile  -Append -encoding UTF8
            }

            # Shared disk support
            If($StorageAllocationSettingData.PersistentReservationsSupported -eq $null)
            {
                $sharedDiskStr = "This feature is supported from Windows Server 2012 R2."
            }
            ElseIf($StorageAllocationSettingData.PersistentReservationsSupported)
            {
                $sharedDiskStr = "Enabled"
            }
            Else
            {
                $sharedDiskStr = "Disabled"
            }
            ("        Enable virtual hard disk sharing: " + $sharedDiskStr) | Out-File $Outputfile  -Append -encoding UTF8
        }
        ("") | Out-File $Outputfile  -Append -encoding UTF8
    }
    ("") | Out-File $Outputfile  -Append -encoding UTF8
}

Function showNetworkAdapterinfo 
{
    $VSSettingData = $args[0]
    $EthernetPortAllocationSettings = $VSSettingData.GetRelated('Msvm_EthernetPortAllocationSettingData')

    ForEach($EthernetPortAllocationSetting in $EthernetPortAllocationSettings)
    {
        ### Get GUID for vSwitch
        $VirtualEthernetSwitch = Get-CimInstance -Namespace 'root\virtualization\v2' -Class 'Msvm_VirtualEthernetSwitch' | Where-Object { $_.__PATH -eq $EthernetPortAllocationSetting.HostResource}

        ("Network Adapter :") | Out-File $Outputfile  -Append -encoding UTF8

        If ($VirtualEthernetSwitch -ne $null)
        {
            $switchName = $VirtualEthernetSwitch.ElementName
        }
        Else
        {
            $switchName = "Not Connected"
        }
        ("    Virtual Switch: " + $switchName) | Out-File $Outputfile  -Append -encoding UTF8

        ### VLAN Info
        $EthernetSwitchPortVlanSettingData = $EthernetPortAllocationSetting.GetRelated('Msvm_EthernetSwitchPortVlanSettingData')

        If($EthernetSwitchPortVlanSettingData -ne $NULL)
        {
            switch ($EthernetSwitchPortVlanSettingData.OperationMode)
            {
                0   {$VlanMode = "None(0)"}
                1   {$VlanMode = "Access(1)"}
                2   {$VlanMode = "Trunk(2)"}
                3   {$VlanMode = "Private(3)"}
                default {$VlanMode = "Disabled"}
            }
            ("    Enable virtual LAN identification: " + $VlanMode) | Out-File $Outputfile  -Append -encoding UTF8
            ("    VLAN ID: " + $EthernetSwitchPortVlanSettingData.AccessVlanId) | Out-File $Outputfile  -Append -encoding UTF8
        }
        Else
        {
            ("    Enable virtual LAN identification: Disabled") | Out-File $Outputfile  -Append -encoding UTF8
        }
        ("") | Out-File $Outputfile  -Append -encoding UTF8

        ### Bandwidth Management Info
        $EthernetSwitchPortBandwidthSettingData = $EthernetPortAllocationSetting.GetRelated('Msvm_EthernetSwitchPortBandwidthSettingData')

        ("    Bandwitdth Management:") | Out-File $Outputfile  -Append -encoding UTF8

        If($EthernetSwitchPortBandwidthSettingData -ne $NULL)
        {
            ("        Enable bandwidth management: True") | Out-File $Outputfile  -Append -encoding UTF8
            ("        Minimum bandwidth          : " + $EthernetSwitchPortBandwidthSettingData.Reservation / 1000000.0 + " Mbps") | Out-File $Outputfile  -Append -encoding UTF8
            ("        Maximum bandwidth          : " + $EthernetSwitchPortBandwidthSettingData.Limit / 1000000.0 + " Mbps") | Out-File $Outputfile  -Append -encoding UTF8
        }
        Else
        {
            ("        Enable bandwidth management: False") | Out-File $Outputfile  -Append -encoding UTF8
        }
        ("") | Out-File $Outputfile  -Append -encoding UTF8

        ### Hardware Acceleration
        $EthernetSwitchPortOffloadSettingData = $EthernetPortAllocationSetting.GetRelated('Msvm_EthernetSwitchPortOffloadSettingData')

        ("    Hardware Acceleration:") | Out-File $Outputfile  -Append -encoding UTF8

        If($EthernetSwitchPortOffloadSettingData.VMQOffloadWeight -ne 0)
        {
            $VMQEnabled = "True(VMQOffloadWeight=" + $EthernetSwitchPortOffloadSettingData.VMQOffloadWeight +")"
        }
        Else
        {
            $VMQEnabled = "False"
        }

        ("        Enable virtual machine queue: " +$VMQEnabled) | Out-File $Outputfile  -Append -encoding UTF8

        If($EthernetSwitchPortOffloadSettingData.IPSecOffloadLimit -ne 0)
        {
            $IPSecEnabled = "True(Maximum Number = " + $EthernetSwitchPortOffloadSettingData.IPSecOffloadLimit +" Offloaded SA)"
        }
        Else
        {
            $IPSecEnabled = "False"
        }

        ("        IPSec task offloading: " +$IPSecEnabled) | Out-File $Outputfile  -Append -encoding UTF8

        If($EthernetSwitchPortOffloadSettingData.IOVOffloadWeight -ne 0)
        {
            $SRIOVEnabled = "True(IOVOffloadWeight = " + $EthernetSwitchPortOffloadSettingData.IOVOffloadWeight + ")"
        }
        Else
        {
            $SRIOVEnabled = "False"
        }

        ("        Enable SR-IOV: " +$SRIOVEnabled) | Out-File $Outputfile  -Append -encoding UTF8
        ("") | Out-File $Outputfile  -Append -encoding UTF8

        ### Failover TCP/IP
        $SyntheticEthernetPortSettings = $VSSettingData.GetRelated('Msvm_SyntheticEthernetPortSettingData')

        # Get Msvm_SyntheticEthernetPortSettingData corresponding to the current Msvm_EthernetPortAllocationSetting
        ForEach($SyntheticEthernetPortSetting in $SyntheticEthernetPortSettings)
        {
            If($EthernetPortAllocationSetting.InstanceID.Contains($SyntheticEthernetPortSetting.InstanceID))
            {
                $SyntheticPort = $SyntheticEthernetPortSetting
                break
            }
        }

        If($SyntheticPort -eq $null)
        {
            ("    WARNING: Failed to retrieve Msvm_SyntheticEthernetPortSettingData.") | Out-File $Outputfile  -Append -encoding UTF8
            ("") | Out-File $Outputfile  -Append -encoding UTF8 

            ### As Msvm_SyntheticEthernetPortSettingData is not found, we cannot show any info on vNIC.
            return 
        }

        ("    Failover TCP/IP: ") | Out-File $Outputfile  -Append -encoding UTF8

        $FailoverNetworkAdapterSettingData = $SyntheticPort.GetRelated('Msvm_FailoverNetworkAdapterSettingData')

        If($FailoverNetworkAdapterSettingData -ne $null)
        {
            If($FailoverNetworkAdapterSettingData.DHCPEnabled)
            {
                ("        IPv4/IPv6 TCP/IP Settings: DHCP(No static IP address is specified)") | Out-File $Outputfile  -Append -encoding UTF8
            }
            Else
            {
                ("        IPv4 TCP/IP Settings:") | Out-File $Outputfile  -Append -encoding UTF8
                ("            IPv4 Address   : " + $FailoverNetworkAdapterSettingData.IPAddresses[0]) | Out-File $Outputfile  -Append -encoding UTF8
                ("            Subnet mask    : " + $FailoverNetworkAdapterSettingData.Subnets[0]) | Out-File $Outputfile  -Append -encoding UTF8
                ("            Default gateway: " + $FailoverNetworkAdapterSettingData.DefaultGateways[0]) | Out-File $Outputfile  -Append -encoding UTF8
                ("            Prefferred DNS server: " + $FailoverNetworkAdapterSettingData.DNSServers[0]) | Out-File $Outputfile  -Append -encoding UTF8
                ("            Alternate DNS server : " + $FailoverNetworkAdapterSettingData.DNSServers[1]) | Out-File $Outputfile  -Append -encoding UTF8
                ("") | Out-File $Outputfile  -Append -encoding UTF8

                If($FailoverNetworkAdapterSettingData.IPAddresses.length -eq 2)
                {
                    ("        IPv6 TCP/IP Settings:") | Out-File $Outputfile  -Append -encoding UTF8
                    ("            IPv4 Address   : " + $FailoverNetworkAdapterSettingData.IPAddresses[1]) | Out-File $Outputfile  -Append -encoding UTF8
                    ("            Subnet mask    : " + $FailoverNetworkAdapterSettingData.Subnets[1]) | Out-File $Outputfile  -Append -encoding UTF8
                    ("            Default gateway: " + $FailoverNetworkAdapterSettingData.DefaultGateways[1]) | Out-File $Outputfile  -Append -encoding UTF8
                    ("            Prefferred DNS server: " + $FailoverNetworkAdapterSettingData.DNSServers[2]) | Out-File $Outputfile  -Append -encoding UTF8
                    ("            Alternate DNS server : " + $FailoverNetworkAdapterSettingData.DNSServers[3]) | Out-File $Outputfile  -Append -encoding UTF8
                }
            }
        }
        Else 
        {
            ("        Hyper-V replica is not configured.") | Out-File $Outputfile  -Append -encoding UTF8
        }

        ("") | Out-File $Outputfile  -Append -encoding UTF8

        ### Advanced Feature
        ("    Advanced Features:") | Out-File $Outputfile  -Append -encoding UTF8

        If($SyntheticPort.StaticMacAddress)
        {
			$MACAddr = "Static (" + $SyntheticPort.address + ")" 
        }
        Else
        {
            $MACAddr = "Dynamic (" + $SyntheticPort.address + ")" 

        }

        ("        MAC Address: " + $MACAddr) | Out-File $Outputfile  -Append -encoding UTF8

        $EthernetSwitchPortSecuritySettingData = $EthernetPortAllocationSetting.GetRelated('Msvm_EthernetSwitchPortSecuritySettingData')
        
        If($EthernetSwitchPortSecuritySettingData.AllowMacSpoofing -ne $null)
        {
            $MACAddressSpoofing = $EthernetSwitchPortSecuritySettingData.AllowMacSpoofing
        }
        Else
        {
            $MACAddressSpoofing = "False"
        }

        ("        Enable MAC address spoofing: " + $MACAddressSpoofing) | Out-File $Outputfile  -Append -encoding UTF8

        ### DHCP guard
        If($EthernetSwitchPortSecuritySettingData.EnableDhcpGuard -ne $null)
        {
            $DHCPGuard = $EthernetSwitchPortSecuritySettingData.EnableDhcpGuard
        }
        Else
        {
            $DHCPGuard = "False"
        }

        ("        Enable DHCP guard: " + $DHCPGuard) | Out-File $Outputfile  -Append -encoding UTF8

        ### Router guard
        If($EthernetSwitchPortSecuritySettingData.EnableRouterGuard -ne $null)
        {
            $RouterGuard = $EthernetSwitchPortSecuritySettingData.EnableRouterGuard
        }
        Else
        {
            $RouterGuard = "False"
        }

        ("        Enable router advertisement guard: " + $RouterGuard) | Out-File $Outputfile  -Append -encoding UTF8

        ### Port mirroring
        If($EthernetSwitchPortSecuritySettingData.MonitorMode -ne $null)
        {
            switch ($EthernetSwitchPortSecuritySettingData.MonitorMode)
            {
                0   {$MonitorMode = "None (0)"}
                1   {$MonitorMode = "Destination (1)"}
                2   {$MonitorMode = "Source (2)"}
                default {$MonitorMode = "False"}
            }
        }
        Else
        {
            $MonitorMode = "False"
        }
        ("        Mirrorring mode: " + $MonitorMode) | Out-File $Outputfile  -Append -encoding UTF8

        ### Proctected Netowrk(WS2012R2 or later)
        If($SyntheticPort.ClusterMonitored -ne $null)
        {
            ("        Protected network: " + $SyntheticPort.ClusterMonitored) | Out-File $Outputfile  -Append -encoding UTF8
        }

        ### NIC Teaming
        If($EthernetSwitchPortSecuritySettingData.AllowTeaming -ne $null)
        {
            $AllowTeaming = $EthernetSwitchPortSecuritySettingData.AllowTeaming
        }
        Else
        {
            $AllowTeaming = "False"
        }

        ("        Enable this network adapter to be partof a team in the guest operating system: " + $AllowTeaming) | Out-File $Outputfile  -Append -encoding UTF8
        ("") | Out-File $Outputfile  -Append -encoding UTF8
    }
}

Function showComPortinfo 
{
    $VM = $args[0]

    $ComPorts = Get-VMComPort -VMName $VM.ElementName

    ("COM Port:") | Out-File $Outputfile  -Append -encoding UTF8

    Foreach ($ComPort in $ComPorts)
    {
        ("    " + $ComPort.Name + ": " + $ComPort.Path) | Out-File $Outputfile  -Append -encoding UTF8
    }
    ("") | Out-File $Outputfile  -Append -encoding UTF8
}

Function showFloppyDriveinfo 
{
    $VM = $args[0]

    $loppyDrive = Get-VMFloppyDiskDrive -VMName $VM.ElementName

    ("Diskette Drive:") | Out-File $Outputfile  -Append -encoding UTF8
    ("    Path: " + $floppyDrive.Path) | Out-File $Outputfile  -Append -encoding UTF8
    ("") | Out-File $Outputfile  -Append -encoding UTF8
}

Function showICinfo 
{
    $VSSettingData = $args[0]

    ("Integration Services:") | Out-File $Outputfile  -Append -encoding UTF8

    $ShutdownComponentSettingData = $VSSettingData.GetRelated('Msvm_ShutdownComponentSettingData')
    $enabledState = getStateString($ShutdownComponentSettingData.EnabledState)
    ("    Operating system shutdown: " + $enabledState) | Out-File $Outputfile  -Append -encoding UTF8

    $TimeSyncComponentSettingData = $VSSettingData.GetRelated('Msvm_TimeSyncComponentSettingData')
    $enabledState = getStateString($TimeSyncComponentSettingData.EnabledState)
    ("    Time synchronization     : " + $enabledState) | Out-File $Outputfile  -Append -encoding UTF8

    $KvpExchangeComponentSettingData = $VSSettingData.GetRelated('Msvm_KvpExchangeComponentSettingData')
    $enabledState = getStateString($KvpExchangeComponentSettingData.EnabledState)
    ("    Data Exchange            : " + $enabledState) | Out-File $Outputfile  -Append -encoding UTF8

    $HeartbeatComponentSettingData = $VSSettingData.GetRelated('Msvm_HeartbeatComponentSettingData')
    $enabledState = getStateString($HeartbeatComponentSettingData.EnabledState)
    ("    Heartbeat                : " + $enabledState) | Out-File $Outputfile  -Append -encoding UTF8

    ### Show heartbeat interval if it is enabled.
    If($HeartbeatComponentSettingData.EnabledState -eq 2)
    {
        ("        Interval      : " + $HeartbeatComponentSettingData.Interval + " ms") | Out-File $Outputfile  -Append -encoding UTF8
        ("        Latency       : " + $HeartbeatComponentSettingData.Latency + " ms") | Out-File $Outputfile  -Append -encoding UTF8
        ("        ErrorThreshold: " + $HeartbeatComponentSettingData.ErrorThreshold + " times") | Out-File $Outputfile  -Append -encoding UTF8
    }

    $VssComponentSettingData = $VSSettingData.GetRelated('Msvm_VssComponentSettingData')
    $enabledState = getStateString($VssComponentSettingData.EnabledState)
    ("    Backup (volume snapshot) : " + $enabledState) | Out-File $Outputfile  -Append -encoding UTF8

    ### Guest service(Windows server 2012 R2 or later)
    $GuestServiceInterfaceComponentSettingData = $VSSettingData.GetRelated('Msvm_GuestServiceInterfaceComponentSettingData')
    $enabledState = getStateString($GuestServiceInterfaceComponentSettingData.EnabledState)
    ("    Guest service            : " + $enabledState) | Out-File $Outputfile  -Append -encoding UTF8
    ("") | Out-File $Outputfile  -Append -encoding UTF8
}

Function getStateString 
{
    $enabledState = $args[0]

    switch ($enabledState)
    {
        2   {$enabledStateStr = "Enabled(2)"}
        3   {$enabledStateStr = "Disabled(3)"}
        default {$enabledStateStr = "Unknown"}
    }
    return $enabledStateStr
}

Function showSnapshotFileinfo
{
    $VSSettingData = $args[0]

    ("Snapshot File Location(File Location for xml):") | Out-File $Outputfile  -Append -encoding UTF8
    ("    Path: " + $VSSettingData.SnapshotDataRoot) | Out-File $Outputfile  -Append -encoding UTF8
    ("") | Out-File $Outputfile  -Append -encoding UTF8
}

Function showSmartPagingFileinfo
{
    $VSSettingData = $args[0]

    ("Smart Paging File Location:") | Out-File $Outputfile  -Append -encoding UTF8
    ("    Path: " + $VSSettingData.SwapFileDataRoot) | Out-File $Outputfile  -Append -encoding UTF8
    ("") | Out-File $Outputfile  -Append -encoding UTF8
}

Function showAutomaticActioninfo
{
    $VSSettingData = $args[0]
    ("Automatic Start Action:") | Out-File $Outputfile  -Append -encoding UTF8
    switch ($VSSettingData.AutomaticStartupAction)
    {
        2   {$startActionStr = "Nothing(2)"}
        3   {$startActionStr = "Automatically start if it was running when the service stopped(3)"}
        4   {$startActionStr = "Always start this virtual machine automatically(4)"}
        default {$startActionStr = "Unknown"}
    }
    ("    Action: " + $startActionStr) | Out-File $Outputfile  -Append -encoding UTF8
    ("") | Out-File $Outputfile  -Append -encoding UTF8

    ("Automatic Stop Action:") | Out-File $Outputfile  -Append -encoding UTF8
    switch ($VSSettingData.AutomaticShutdownAction)
    {
        2   {$shutdownActionStr = "Turn off the virtual machine(2)"}
        3   {$shutdownActionStr = "Save the virtual machine state(3)"}
        4   {$shutdownActionStr = "Shut down the guest operating system(4)"}
        default {$shutdownActionStr = "Unknown"}
    }
    ("    Action: " + $shutdownActionStr) | Out-File $Outputfile  -Append -encoding UTF8
    ("") | Out-File $Outputfile  -Append -encoding UTF8
}

Function showSnapshotInfo
{
    $VM = $args[0]
    ("Snapshot: ") | Out-File $Outputfile  -Append -encoding UTF8

    $Snapshots =  Get-VMSnapshot -VMName $VM.ElementName

    If($Snapshots.length -eq 0)
    {
        ("    No snapshots in this VM.") | Out-File $Outputfile  -Append -encoding UTF8
        ("") | Out-File $Outputfile  -Append -encoding UTF8
        return
    }

    ("    -----------------------------------------------------") | Out-File $Outputfile  -Append -encoding UTF8

    ForEach($Snapshot in $Snapshots)
    { 
        $VirtualSystemSettingData = $VM.GetRelated('Msvm_VirtualSystemSettingData') | Where-Object { $_.ElementName -eq $Snapshot.Name }

        If($VirtualSystemSettingData.count -gt 1) 
        {
            ### Sometimes there are two same Msvm_StorageAllocationSettingData. So we get first one. Probably this is a bug...
            $HardDrives = $VirtualSystemSettingData[0].GetRelated('Msvm_StorageAllocationSettingData') 
        } 
        Else
        {
            $HardDrives = $VirtualSystemSettingData.GetRelated('Msvm_StorageAllocationSettingData') 
        }

        ("    Name         : " + $Snapshot.Name) | Out-File $Outputfile  -Append -encoding UTF8
        ("    Type         : " + $Snapshot.SnapshotType) | Out-File $Outputfile  -Append -encoding UTF8
        ("    Creation Time: " + $Snapshot.CreationTime) | Out-File $Outputfile  -Append -encoding UTF8
        ("    Parent       : " + $Snapshot.ParentSnapshotName) | Out-File $Outputfile  -Append -encoding UTF8
        ("    File List    : ") | Out-File $Outputfile  -Append -encoding UTF8

        If($HardDrives -eq $null)
        {
            continue  # No drives attached to this snapshot.
        }

        # Get ACL and file property.
        ForEach($HardDrive in $HardDrives)
        {
            If(($HardDrive.HostResource[0]).Contains("vhd"))
            {
                ("        - " + $HardDrive.HostResource) | Out-File $Outputfile  -Append -encoding UTF8
            }
            Else
            {
                continue  ### Probably physical drive or ISO file
            }

            If(!(Test-Path $HardDrive.HostResource))
            {
                ("            !!! WARNING: above file does not exist !!!") | Out-File $Outputfile  -Append -encoding UTF8
                continue
            }


            $vhdInfo = Get-VHD -Path $HardDrive.HostResource[0] 
            $property = Get-ChildItem $HardDrive.HostResource[0]
            $fileSize = [math]::round($property.Length / 1GB , 3)
            $maxFileSize = [math]::round($vhdInfo.Size / 1GB , 3)
            $ACL = Get-ACL $HardDrive.HostResource[0]            

            ("            VhdType: " + $vhdInfo.VhdType) | Out-File $Outputfile  -Append -encoding UTF8
            ("            Creation time: " + $property.CreationTime + "    " + "Last write time: " + $property.LastWriteTime) | Out-File $Outputfile  -Append -encoding UTF8
            ("            Current size: " + $fileSize + " GB" + "  /  Max file size: " + $maxFileSize + " GB") | Out-File $Outputfile  -Append -encoding UTF8
            ("            LogicalSectorSize: " + $vhdInfo.LogicalSectorSize + " bytes  /  PhysicalSectorSize: " + $vhdInfo.PhysicalSectorSize + " bytes") | Out-File $Outputfile  -Append -encoding UTF8
            ("            Owner: " + $ACL.Owner) | Out-File $Outputfile  -Append -encoding UTF8
            ("            ACL: ") | Out-File $Outputfile  -Append -encoding UTF8

            $AccessRules = $ACL.GetAccessRules($true,$true, [System.Security.Principal.NTAccount])

            ForEach($AccessRule in $AccessRules)
            {
                ("                " + $AccessRule.IdentityReference + " => " + $AccessRule.FileSystemRights) | Out-File $Outputfile  -Append -encoding UTF8
            }
        }
        ("    -----------------------------------------------------") | Out-File $Outputfile  -Append -encoding UTF8
    }
    ("") | Out-File $Outputfile  -Append -encoding UTF8
}

Function showReplicationinfo
{
    $VM = $args[0]
    $VirtualSystemSettingData = $VM.GetRelated('Msvm_VirtualSystemSettingData') | Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' }

    switch ($VM.ReplicationState)
    {
        0   {$ReplicationState = "Disabled"}
        1   {$ReplicationState = "Ready for replication"}
        2   {$ReplicationState = "Waiting to complete initial replication"}
        3   {$ReplicationState = "Replicating"}
        4   {$ReplicationState = "Synced replication complete"}
        5   {$ReplicationState = "Recovered"}
        6   {$ReplicationState = "Committed"}
        7   {$ReplicationState = "Suspended"}
        8   {$ReplicationState = "Critical"}
        9   {$ReplicationState = "Waiting to start resynchronization"}
       10   {$ReplicationState = "Resynchronizing"}
       11   {$ReplicationState = "Resynchronization suspended"}
       12   {$ReplicationState = "Failover in progress"}
       13   {$ReplicationState = "Failback in progress"}
       14   {$ReplicationState = "Failback complete"}
    }

    switch ($VM.FailedOverReplicationType)
    {
        0   {$FailedOverReplicationType = "None"}
        1   {$FailedOverReplicationType = "Regular"}
        2   {$FailedOverReplicationType = "Application consistent"}
        3   {$FailedOverReplicationType = "Planned"}
    }

    switch ($VM.ReplicationHealth)
    {
        0   {$ReplicationHealth = "Not applicable"}
        1   {$ReplicationHealth = "Ok"}
        2   {$ReplicationHealth = "Warning"}
        3   {$ReplicationHealth = "Critical"}
    }

    switch ($VM.ReplicationMode)
    {
        0   {$ReplicationMode = "None"}
        1   {$ReplicationMode = "Primary"}
        2   {$ReplicationMode = "Recovery"}
        3   {$ReplicationMode = "Replica"}
        4   {$ReplicationMode = "Extended Replica"}
    }

    ### Sometimes there are two same Msvm_ReplicationSettingData. So we get first one. 
    $ReplicationSettingData = $VM.GetRelated('Msvm_ReplicationSettingData') | Select-Object -first 1

    switch ($ReplicationSettingData.AuthenticationType)
    {
        1   {$AuthenticationType = "Kerberos authentication"}
        2   {$AuthenticationType = "Certificate based authentication"}
    }

    $HVRConfiRoot = $VirtualSystemSettingData.ConfigurationDataRoot.ToString()
    $HVRConfigFile = $VirtualSystemSettingData.ConfigurationFile.ToString()
    $VHD = get-vhd -vmid $VM.Name

    If($ReplicationSettingData.ReplicationInterval -eq $null)
    {
        $ReplicationInterval = 300
    }
    Else
    {
        $ReplicationInterval = $ReplicationSettingData.ReplicationInterval
    }

    ("Replication:") | Out-File $Outputfile  -Append -encoding UTF8
    ("") | Out-File $Outputfile  -Append -encoding UTF8
    ("    Replication:") | Out-File $Outputfile  -Append -encoding UTF8
    ("        This virtual machinge is configured as " + $ReplicationMode + " virtual machine.") | Out-File $Outputfile  -Append -encoding UTF8
    ("") | Out-File $Outputfile  -Append -encoding UTF8
    ("        Port on the Replica server  : " + $ReplicationSettingData.RecoveryServerPortNumber) | Out-File $Outputfile  -Append -encoding UTF8
    ("        Authentication Type         : " + $AuthenticationType) | Out-File $Outputfile  -Append -encoding UTF8
    ("        Compression the data that is transmitted over the network: " + $ReplicationSettingData.CompressionEnabled) | Out-File $Outputfile  -Append -encoding UTF8
    ("") | Out-File $Outputfile  -Append -encoding UTF8
    ("    Recovery Points:") | Out-File $Outputfile  -Append -encoding UTF8

    If($ReplicationSettingData.RecoveryHistory -eq 0)
    {
        ("        Only the latest point for recovery") | Out-File $Outputfile  -Append -encoding UTF8
    }
    Else
    {
        ("        Additional recovery points") | Out-File $Outputfile  -Append -encoding UTF8
        ("            Number of recovery point: " + $ReplicationSettingData.RecoveryHistory) | Out-File $Outputfile  -Append -encoding UTF8

        $isVssReplicaEnabled = $True
        If($ReplicationSettingData.ApplicationConsistentSnapshotInterval -eq 0)
        {
            $isVssReplicaEnabled = $False
        }

        ("        Application consistent replication: " + $isVssReplicaEnabled) | Out-File $Outputfile  -Append -encoding UTF8

        If($isVssReplicaEnabled)
        {
            ("        Replicate incremental VSS copy every: "  + $ReplicationSettingData.ApplicationConsistentSnapshotInterval + " hour(s)") | Out-File $Outputfile  -Append -encoding UTF8
        }
    }

    ### Windows Server 2012 R2 or later
    ### We don't show resync setting if it is RecoveryVM as it is not available.
    If($VM.ReplicationMode -eq 1)
    {
        ("") | Out-File $Outputfile  -Append -encoding UTF8
        ("    Resynchronization:") | Out-File $Outputfile  -Append -encoding UTF8

        $resyncIntervalEnd = [System.Management.ManagementDateTimeConverter]::Totimespan($ReplicationSettingData.AutoResynchronizeIntervalEnd)
        $resyncIntervalStart = [System.Management.ManagementDateTimeConverter]::Totimespan($ReplicationSettingData.AutoResynchronizeIntervalStart)
        $oneSecond = New-TimeSpan -Seconds 1
        $endPlusOneSec = $resyncIntervalEnd + $oneSecond

        If($ReplicationSettingData.AutoResynchronizeEnabled)
        {
            If(($resyncIntervalStart.Hours -eq $endPlusOneSec.Hours) -and ($resyncIntervalStart.Minutes -eq $endPlusOneSec.Minutes) -and ($resyncIntervalStart.Seconds -eq $endPlusOneSec.Seconds))
            {
                ("        Automatically start resynchronization") | Out-File $Outputfile  -Append -encoding UTF8
            }
            Else
            {
                ("        Automatically start resynchronization only during the follwing hours:") | Out-File $Outputfile  -Append -encoding UTF8
                ("            From: " + $resyncIntervalStart.Hours.ToString("00") + $resyncIntervalStart.Minutes.ToString("\:00")) | Out-File $Outputfile  -Append -encoding UTF8
                ("              To: " + $resyncIntervalEnd.Hours.ToString("00") + $resyncIntervalEnd.Minutes.ToString("\:00")) | Out-File $Outputfile  -Append -encoding UTF8
            }
        }
        Else
        {
            ("        Manually") | Out-File $Outputfile  -Append -encoding UTF8
        }
    }

    ("") | Out-File $Outputfile  -Append -encoding UTF8
    ("    Other replication info: ") | Out-File $Outputfile  -Append -encoding UTF8
    ("        VM GUID                     : " + $VM.Name) | Out-File $Outputfile  -Append -encoding UTF8
    ("        Configuration file          : " + $HVRConfiRoot + "\" + $HVRConfigFile) | Out-File $Outputfile  -Append -encoding UTF8
    ("        Included VHD files          : ") | Out-File $Outputfile  -Append -encoding UTF8

    ForEach($includedDisk in $ReplicationSettingData.IncludedDisks)
    {
        ("            - " + $includedDisk) | Out-File $Outputfile  -Append -encoding UTF8
    }

    ("        Primary server              : " + $ReplicationSettingData.PrimaryHostSystem) | Out-File $Outputfile  -Append -encoding UTF8
    ("        Primary connection point    : " + $ReplicationSettingData.PrimaryConnectionPoint) | Out-File $Outputfile  -Append -encoding UTF8
    ("        Replica server              : " + $ReplicationSettingData.RecoveryHostSystem) | Out-File $Outputfile  -Append -encoding UTF8
    ("        Replication interval        : " + $ReplicationInterval + " seconds") | Out-File $Outputfile  -Append -encoding UTF8
    ("        ReplicationHealth           : " + $ReplicationHealth) | Out-File $Outputfile  -Append -encoding UTF8
    ("        ReplicationMode             : " + $ReplicationMode) | Out-File $Outputfile  -Append -encoding UTF8
    ("        ReplicationState            : " + $ReplicationState) | Out-File $Outputfile  -Append -encoding UTF8
    ("        Last update time            : " + $VM.LastReplicationTime) | Out-File $Outputfile  -Append -encoding UTF8
    ("        Last update time(VSS)       : " + $VM.LastApplicationConsistentReplicationTime) | Out-File $Outputfile  -Append -encoding UTF8
}

Function showHVFileVersion
{
    $system32Files = dir "C:\Windows\System32\vm*"
    $hypervisorFiles = dir "C:\Windows\System32\hv*"
    $driversFiles = dir "C:\Windows\System32\drivers\vm*"
    $fileArray = ($system32Files, $driversFiles, $hypervisorFiles)
    
    ("File version:") | Out-File $Outputfile  -Append -encoding UTF8

    ForEach($files in $fileArray)
    {
        ForEach($file in $files)
        {
            $ext = (Get-ChildItem $File).get_Extension()

            If($ext -ne ".dll" -and $ext -ne ".sys" -and $ext -ne ".exe")
            {
               continue
            }

            ("    " + $file.Name + "    " + $file.VersionInfo.FileVersion) | Out-File $Outputfile  -Append -encoding UTF8
        }
    }
    ("") | Out-File $Outputfile  -Append -encoding UTF8
}

Function getVmGeneration
{
    $VSSettingData = $args[0]

    If($VSSettingData.VirtualSystemSubType -eq $null) ### WS2012
    {
        $vmGgeneration = "1"
    }
    Else ### WS2012R2 or later
    {
        $subType = $VSSettingData.VirtualSystemSubType.split(":")
        $vmGgeneration = $subType[3]
    }

    return $vmGgeneration
}

Function getHeartBeatInfo
{
    $heartbeatComponent = $args[0]

    If ( $heartbeatComponent.StatusDescriptions -ne $null )
    {
        $heartbeat = $HeartbeatComponent.OperationalStatus[0]
        $strhbPrimaryStatus = getHBOperationalStatus($heartbeat)
    }
}

Function getVMEnabledState
{
    $vmStatus = $args[0]

    # http://msdn.microsoft.com/en-us/library/hh850116(v=vs.85).aspx
    switch ($vmStatus)
    {
        0   {$EnabledState = "Unknown"}
        1   {$EnabledState = "Other"}
        2   {$EnabledState = "Running(Enabled - 2)"}
        3   {$EnabledState = "Off(Disabled - 3)"}
        4   {$EnabledState = "Shutting down(4)"}
        5   {$EnabledState = "Not Applicable(5)"}
        6   {$EnabledState = "Saved(Enabled but Offline - 6)"}
        7   {$EnabledState = "In Test(7)"}
        8   {$EnabledState = "Deferred(8)"}
        9   {$EnabledState = "Quiesce(9)"}
       10   {$EnabledState = "Starting(10)"}
    }

    return $EnabledState
}

Function getHBOperationalStatus
{
    $hbStatus = $args[0]

    # http://msdn.microsoft.com/en-us/library/hh850157(v=vs.85).aspx
    switch ($hbStatus)
    {
        2   {$hbPrimaryStatus = "OK"}
        3   {$hbPrimaryStatus = "Degraded"}
        7   {$hbPrimaryStatus = "Non-Recoverable Error"}
       12   {$hbPrimaryStatus = "No Contact"}
       13   {$hbPrimaryStatus = "Lost Communication"}
       15   {$hbPrimaryStatus = "Paused"}
       default {$hbPrimaryStatus = "N/A"}
    }
    return $hbPrimaryStatus
}

Function getHBSecondaryStatus
{
    $hbStatus2 = $args[0]

    # http://msdn.microsoft.com/en-us/library/hh850157(v=vs.85).aspx
    switch ($hbStatus2)
    {
            2   {$hbSecondaryStatus = "OK"}
        32775   {$hbSecondaryStatus = "Protocol Mismatch"}
        32782   {$hbSecondaryStatus = "Application Critical State"}
        32783   {$hbSecondaryStatus = "Communication Timed Out"}
        32784   {$hbSecondaryStatus = "Communication Failed"}
        default {$hbSecondaryStatus = "N/A"}
    }
    return $hbSecondaryStatus
}

###
### MAIN
###
$osVersion = [environment]::OSVersion.Version
$TestPath = Test-Path "C:\Windows\System32\vmms.exe"
If (($TestPath -eq $False) -or ($osVersion.Build -lt 9200))
{
    "Hyper-V basic information cannot be collected on this system."  | WriteTo-StdOut
    "Hyper-V is installed: $TestPath"  | WriteTo-StdOut
    "OS version is build $OSVersion"  | WriteTo-StdOut
}
Else
{
    $hostName = hostname
    $VMs = Get-CimInstance -Namespace 'root\virtualization\v2' -Class 'Msvm_ComputerSystem' | Where-Object { $_.ElementName -ne $hostName}
    $VSMgtServiceSettingData = Get-CimInstance -Namespace 'root\virtualization\v2' -Class 'Msvm_VirtualSystemManagementServiceSettingData'

    showHVGlobalSettings $VSMgtServiceSettingData
    showNUMAinfo
    
    ("Virtual Machine Settings") | Out-File $Outputfile  -Append -encoding UTF8
    ("----------------------------------------") | Out-File $Outputfile  -Append -encoding UTF8
    ("") | Out-File $Outputfile  -Append -encoding UTF8 
    
    ForEach ($VM in $VMs)
    {
        
        $VirtualSystemSettingData = $VM.GetRelated('Msvm_VirtualSystemSettingData') | Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' }
        
        ("<<<<<<<<<< " + $VM.elementName + " >>>>>>>>>>") | Out-File $Outputfile  -Append -encoding UTF8
        ("") | Out-File $Outputfile  -Append -encoding UTF8
        
        showVMBasicinfo $VM $VirtualSystemSettingData
        
        ### Hyper-V UI settings
        showBIOSinfo $VirtualSystemSettingData
        showMeminfo $VirtualSystemSettingData
        showCPUinfo $VirtualSystemSettingData
        
        # We don't get IDE info in case of Gen2VM as IDE does not exist.
        $vmGeneration = getVmGeneration $VirtualSystemSettingData
        If($vmGeneration -eq "1")
        {
            showIDEHardDriveinfo $VM
        }

        showSCSIHardDriveinfo $VM
        showNetworkAdapterinfo $VirtualSystemSettingData
        showComPortinfo $VM 

        If($vmGeneration -eq "1")
        {
            showFloppyDriveinfo $VM
        }

        showICinfo $VirtualSystemSettingData
        showSnapshotFileinfo $VirtualSystemSettingData
        showSmartPagingFileinfo $VirtualSystemSettingData
        showAutomaticActioninfo $VirtualSystemSettingData

        ### Additional info
        showSnapshotInfo $VM
        showKVPItems $VM $VirtualSystemSettingData

        # Get replication info if it is enabled
        if ($VM.ReplicationState -ne 0)
        {
            ("Detected Hyper-V replica enabled...") | Out-File $Outputfile  -Append -encoding UTF8
            ("") | Out-File $Outputfile  -Append -encoding UTF8
            showReplicationinfo $VM
        }

        ("") | Out-File $Outputfile  -Append -encoding UTF8
        ("================================================================================") | Out-File $Outputfile  -Append -encoding UTF8
        ("") | Out-File $Outputfile  -Append -encoding UTF8

    }
    
    showHVFileVersion
    CollectFiles -filesToCollect $OutputFile  -fileDescription $FileDescription  -sectionDescription $SectionDescription  -renameOutput $false
}

# SIG # Begin signature block
# MIIjhwYJKoZIhvcNAQcCoIIjeDCCI3QCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBEtmMqo9c5RMNT
# 0i6yeLSjp5NTQg3w+ms9Fd4xXeF5haCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVXDCCFVgCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBpDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQge+qKkMKu
# R5wJvJeE3+m6+k6EbTEndVxmdgk7i/aeqxswOAYKKwYBBAGCNwIBDDEqMCigCIAG
# AFQAUwBToRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20gMA0GCSqGSIb3DQEB
# AQUABIIBAKGWH9UitdZHl/AfZ7Ko7pKG2a5PblmQ4sGiGq3pJMbGbhKoh/pXwTIC
# HY0+4J3GY8dt2RZqrNGdi+NkkoBaa0s4tRFtYu3E83bErklmKPfyftlHFFiUrP7s
# sIMtyjfvM0SsEEJuLzz01w0qdx5xiskNttnP2qeQymBfpkw++i3JiktPtLWvioI6
# x3yLFGtiEqYKZ9Zon+I/aGbrHizgi5VHMHa/lzZU0B+CCa4vpSkjN3K1IhvIwUFu
# AGrvxWsqp0kp3S7ZpxOhff8NPCGUqyE3vGs2UPwY83ZzV/tRUEFqo/QWibgfXHps
# y/kwir+mE2cPhAAaU2WU+5HptZT6LLahghLwMIIS7AYKKwYBBAGCNwMDATGCEtww
# ghLYBgkqhkiG9w0BBwKgghLJMIISxQIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBVAYL
# KoZIhvcNAQkQAQSgggFDBIIBPzCCATsCAQEGCisGAQQBhFkKAwEwMTANBglghkgB
# ZQMEAgEFAAQgQ9fdivYC55F2HbfERNLZogyA0BLX8FjF+j+oVUvX7JoCBmGCAKQz
# IRgSMjAyMTExMTExNjUzMzYuMThaMASAAgH0oIHUpIHRMIHOMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3Bl
# cmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDlE
# RS1FMzlBLTQzRkUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZp
# Y2Wggg5EMIIE9TCCA92gAwIBAgITMwAAAWH1ojNeoCokaQAAAAABYTANBgkqhkiG
# 9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMTAxMTQx
# OTAyMjFaFw0yMjA0MTExOTAyMjFaMIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVy
# dG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDlERS1FMzlBLTQzRkUx
# JTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCXiJ2oQa1P/xs06ocVMgAvFF3LelCQpG9s
# RGSld4I4IJiwIXga8SZO7R/j8NrU3Mmqy0X5ldsaOaAZOaVvznA3P5/03E3kFOiS
# DeT5U3J9AvUZSkOrfTrlP1gMgMRk4yhOBDZ1I17cYjZQ/ytmRjC746UTgSoe07ZF
# CSumRlsP7k0WmzQcUYNd0745Bh1xFBAyfIpmnMPQQnkfS+rp3a99rY+HbjhSBw/J
# tXrN0jTffGauCAwT9wnG/h0IMaW3hyFJStMus5syJL3ze92ccHxrxb9PzGse/ViW
# NHA/KaAp2RYo3Ilq39Hg9U9v/ux4HsM63cT3UhaHJFEPEKLyAyGJAgMBAAGjggEb
# MIIBFzAdBgNVHQ4EFgQUVh6andYb+9UlY+SwHT3zROz4Sy8wHwYDVR0jBBgwFoAU
# 1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENBXzIw
# MTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAxMC0w
# Ny0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkq
# hkiG9w0BAQsFAAOCAQEAEEwPW6lQZseU0zIc4/kPM1pD0F4AnEkIqstmGFhdIVq+
# RhIjdi7QPhFnbtcvKMrGWruAj+0szPFU0qt9QiyYjst/WeEbxKtpq9BH7Rb5l9gs
# UO2cs65IVjGWmUC5GGx+aGmyBcJ3Vt+J4ffNATmN/ebX5zUv2OjdH/o13aBZ+3yN
# nON0xWLFKiD1ozhyZaDHpLZQ+v7kumZ+MbHv5SLRZvn1jnAdgMclxAd2URHkoPY+
# /hqBJdcU/4iblf0qO05VncMmnELuJb9zAbL8c0SGyoWcKw2KIJqMifq8IEAfJiku
# PzNUg0bSKbWpqExSeek5Og7lF8dSbnU6HpYIxGT2uTCCBnEwggRZoAMCAQICCmEJ
# gSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmlj
# YXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIxNDY1
# NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF++18
# aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRDDNdN
# uDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSxz5NM
# ksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1rL2K
# Qk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16HgcsOmZ
# zTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB4jAQ
# BgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqFbVUw
# GQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB
# /wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0f
# BE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJv
# ZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4w
# TDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCBkjCB
# jwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQeMiAd
# AEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQALiAd
# MA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUxvs8F
# 4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GASinbM
# QEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1L3mB
# ZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWOM7ti
# X5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4pm3S
# 4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45V3ai
# caoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x4QDf
# 5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEegPsb
# iSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKnQqLJ
# zxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp3lfB
# 0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvTX4/e
# dIhJEqGCAtIwggI7AgEBMIH8oYHUpIHRMIHOMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQ
# dWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDlERS1FMzlBLTQz
# RkUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAH
# BgUrDgMCGgMVABVuUoQMOXpExF7y/+FdbNK2w895oIGDMIGApH4wfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDlN7OwMCIYDzIw
# MjExMTExMTkyMjI0WhgPMjAyMTExMTIxOTIyMjRaMHcwPQYKKwYBBAGEWQoEATEv
# MC0wCgIFAOU3s7ACAQAwCgIBAAICCEsCAf8wBwIBAAICEdgwCgIFAOU5BTACAQAw
# NgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgC
# AQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQCHWaYWwF5AVr7RNdzEygGScg5WwVkT
# Xcufaw5uOQKMzgOQZKfHA4IPFRx2shmm6OWCoHlLRjHlvdsr5+zHlqFFe7UE8JPd
# RJVoug3z90JRZwMnDVeKjse4lxdloprxEAdS/uf9RqB1+xSq3yGDQ9TG35SV1qaa
# xIU2u3vj51xr1zGCAw0wggMJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABYfWiM16gKiRpAAAAAAFhMA0GCWCGSAFlAwQCAQUAoIIBSjAa
# BgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIMQC4RJ7
# ZTDC9Jd+LZ3jNdb3kwrF+V4bUfdcFYMd+r1oMIH6BgsqhkiG9w0BCRACLzGB6jCB
# 5zCB5DCBvQQgYc+Lp+ppEi3f8wPtDeWCwxqeL1v1QbTVv5aZobQJOG8wgZgwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAWH1ojNeoCokaQAA
# AAABYTAiBCCqWWe6VJvYi9dYwKEDfuWHEGNGDjXOsZBVNlYfhKuDeTANBgkqhkiG
# 9w0BAQsFAASCAQBPV2NJHvZHYGSBBi8sHRs1fh2mAGudOoisKGsSkfoGiG6qeHAU
# q35Cbz3nLWT+mEwPFy5CtpDWnODsiv5h5jgwG45yHBAlWituQ+ZwvQGCOLqyoLaK
# TGqMGB/Ha89b6KurbSgmWUPuBpipwekXeF3Rpac3W3v8B9vjK6WivX1DQRZN8Lkl
# 2q7PaW4TseSkhTz/MOiEns4zngtiqUD4AUJ7OP8vBbjExr2d38ptSwavFTGBUR3t
# 1uvYNLFv+EaoO2QhX61SL2o7hfwblN3/LaCwnX+T0SFDQuVAVKCNgTjIvLNVaw63
# rA61ldWRh6e/SION9m8fmpyCxjneqJ3IBPOP
# SIG # End signature block
