/*
Copyright (c) Microsoft Corporation
 
Module Name:
 
    nvspinfo.js

    updates to provide support for 2012/2012 R2 wmi namespace 
*/


//
// VirtualSwitchManagementService object.  Logical wrapper class for Switch Management Service
//
function 
VirtualSwitchManagementService(
    Server,
    User,
    Password
    ) {
    //
    // Define instance fields.
    //    
    this.m_VirtualizationNamespace = null;

    this.m_VirtualSwitchManagementService = null;



    VirtualSwitchManagementService.prototype.GetSingleObject =
    function (
        SWbemObjectSet
        )

        /*++
    
        Description:
    
            Takes a SWbemObjectSet which is expected to have one object and returns the object
    
        Arguments:
    
            SWbemObjectSet - The set.
    
        Return Value:
    
            The lone member of the set.  Exception thrown if Count does not equal 1.
    
        --*/ {
        if (SWbemObjectSet.Count != 1) {
            throw (new Error(5, "SWbemObjectSet was expected to have one item but actually had " + SWbemObjectSet.Count));
        }

        return SWbemObjectSet.ItemIndex(0);
    }


    //
    // Constructor code
    //

    if (Server == null) {
        Server = WScript.CreateObject("WScript.Network").ComputerName;
    }

    //
    // Set Namespace fields
    //
    try {
        var locator = new ActiveXObject("WbemScripting.SWbemLocator");

        this.m_VirtualizationNamespace = locator.ConnectServer(Server, "root\\virtualization\\v2", User, Password);
    }
    catch (e) {
        this.m_VirtualizationNamespace = null;

        throw (new Error("Unable to get an instance of Virtualization namespace: " + e.description));
    }

    //
    // Set Msvm_VirtualSwitchManagementService field
    //
    try {
        var physicalComputerSystem =
                this.m_VirtualizationNamespace.Get(
                        "Msvm_ComputerSystem.CreationClassName='Msvm_ComputerSystem',Name='" + Server + "'");

        this.m_VirtualSwitchManagementService = this.GetSingleObject(
                                                        physicalComputerSystem.Associators_(
                                                            "Msvm_HostedService",
                                                            "Msvm_VirtualEthernetSwitchManagementService",
                                                            "Dependent"));
    }
    catch (e) {
        this.m_VirtualSwitchManagementService = null;

        throw (new Error("Unable to get an instance of Msvm_VirtualSwitchManagementService: " + e.description));
    }
}


//
// main
// 

var wshShell = WScript.CreateObject("WScript.Shell");

var g_NvspWmi = null;
var g_CimV2 = null;


Main();

//
// Helper function for displaying Win32_NetworkAdapterConfiguration settings
//
function DisplayWin32NetworkAdapterConfiguration(win32NetworkAdapterConfiguration) {
    WScript.echo("    Win32_NetworkAdapterConfiguration. " + win32NetworkAdapterConfiguration.Index);
    WScript.echo("        SettingID = " + win32NetworkAdapterConfiguration.SettingID);
    WScript.echo("        InterfaceIndex = " + win32NetworkAdapterConfiguration.InterfaceIndex);
    WScript.echo("        IPEnabled = " + win32NetworkAdapterConfiguration.IPEnabled);

    if (win32NetworkAdapterConfiguration.IPEnabled) {
        if (win32NetworkAdapterConfiguration.IPAddress != null) {
            var ipAddresses = win32NetworkAdapterConfiguration.IPAddress.toArray();
            WScript.echo("        IP addresses:");
            for (k = 0; k < ipAddresses.length; k++) {
                WScript.echo("            " + ipAddresses[k]);
            }
        }

        if (win32NetworkAdapterConfiguration.IPSubnet != null) {
            var ipSubnet = win32NetworkAdapterConfiguration.IPSubnet.toArray();
            WScript.echo("        IP subnets:");
            for (k = 0; k < ipSubnet.length; k++) {
                WScript.echo("            " + ipSubnet[k]);
            }
        }

        if (win32NetworkAdapterConfiguration.DefaultIPGateway != null) {
            var ipGateway = win32NetworkAdapterConfiguration.DefaultIPGateway.toArray();
            WScript.echo("        IP gateways:");
            for (k = 0; k < ipGateway.length; k++) {
                WScript.echo("            " + ipGateway[k]);
            }
        }
    }
}

//
// Helper function for displaying Win32_NetworkAdapter settings
//
function DisplayWin32NetworkAdapter(win32NetworkAdapter) {
    var protocols = win32NetworkAdapter.Associators_(
                                    "Win32_ProtocolBinding",
                                    "Win32_NetworkProtocol",
                                    "Antecedent");

    WScript.echo("    Win32_NetworkAdapter");
    WScript.echo("        Name = " + win32NetworkAdapter.Name);
    WScript.echo("        GUID = " + win32NetworkAdapter.GUID);
    WScript.echo("        DeviceID = " + win32NetworkAdapter.DeviceID);
    WScript.echo("        Index = " + win32NetworkAdapter.Index);
    WScript.echo("        ConfigManagerErrorCode = " + win32NetworkAdapter.ConfigManagerErrorCode);
    WScript.echo("        NetConnectionID = " + win32NetworkAdapter.NetConnectionID);
    WScript.echo("        NetConnectionStatus = " + win32NetworkAdapter.NetConnectionStatus);
    WScript.echo("        NetEnabled = " + win32NetworkAdapter.NetEnabled);
    WScript.echo("        MAC address = " + win32NetworkAdapter.MACAddress);
    WScript.echo("        Bindings:");

    for (k = 0; k < protocols.Count; k++) {
        var protocol = protocols.ItemIndex(k);
        WScript.echo("            " + protocol.Name);
    }
}

//
// Helper function for displaying network settings
//
function DisplayNetworkSettings(DeviceID) {
    // get corresponding Win32_NetworkAdapterConfiguration
    var win32NetworkAdapterConfigurations =
            g_CimV2.ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE SettingID = '" + DeviceID + "'");

    if (win32NetworkAdapterConfigurations.Count) {
        var win32NetworkAdapterConfiguration = win32NetworkAdapterConfigurations.ItemIndex(0);
        DisplayWin32NetworkAdapterConfiguration(win32NetworkAdapterConfiguration);
    }

    // get corresponding Win32_NetworkAdapter
    var win32NetworkAdapters =
            g_CimV2.ExecQuery("SELECT * FROM Win32_NetworkAdapter WHERE GUID = '" + DeviceID + "'");

    if (win32NetworkAdapters.Count) {
        var win32NetworkAdapter = win32NetworkAdapters.ItemIndex(0);
        DisplayWin32NetworkAdapter(win32NetworkAdapter);
    }
}

//
// Helper function which takes a connection string and displays the switch and port
//
function DumpConnectionInformation(connection) {
    var connected = false;

    if (connection != null && connection != "") {
        var switchPort = null;

        try {
            switchPort = GetObject("winmgmts:" + connection);
        }
        catch (e) {
            switchPort = null;
        }

        if (switchPort != null) {
            var switches =
                g_NvspWmi.m_VirtualizationNamespace.ExecQuery("SELECT * FROM Msvm_VirtualSwitch WHERE Name = '" + switchPort.SystemName + "'");

            if (switches.Count) {
                WScript.echo("    connection:");
                WScript.echo("        switch = " + switches.ItemIndex(0).ElementName);
                WScript.echo("        port = " + switchPort.Name);
                connected = true;
            }
        }

        if (!connected) {
            WScript.echo("    invalid connection: " + connection);
        }
    }
    else {
        WScript.echo("    not connected");
    }
}

function Main() {
    var enumAdapters = false;
    var everything = false;
    var analyze = false;
    var includePorts = false;
    var includeMac = false;

    if (WScript.arguments.Named.Exists("?")) {
        WScript.Echo("");
        WScript.Echo("    /e    display all network adapters");
        WScript.Echo("    /p    include port details");
        WScript.Echo("    /m    include mac details (implies -p)");
        WScript.Echo("    /e    everything");
        WScript.Echo("    /z    analyze (implies /e)");
        WScript.Echo("");
        WScript.Quit();
    }

    if (WScript.arguments.Named.Exists("p")) {
        includePorts = true;
    }

    if (WScript.arguments.Named.Exists("a")) {
        enumAdapters = true;
    }

    if (WScript.arguments.Named.Exists("m")) {
        includePorts = true;
        includeMac = true;
    }

    if (WScript.arguments.Named.Exists("e")) {
        everything = true;
    }

    if (WScript.arguments.Named.Exists("z")) {
        analyze = true;
        everything = true;
    }

    if (everything) {
        enumAdapters = true;
        includePorts = true;
        includeMac = true;
    }

    //
    // Connect to troot\cimv2 namespace and verify Hyper-V network drivers and services are running
    //
    WScript.Echo("Looking for root\\cimv2...");
    var locator = new ActiveXObject("WbemScripting.SWbemLocator");
    g_CimV2 = locator.ConnectServer("", "root\\cimv2", "", "");

    WScript.Echo("");
    WScript.Echo("Looking for VSP driverss...");
    var list = g_CimV2.ExecQuery("SELECT * FROM Win32_SystemDriver WHERE Name='VMSMP' OR Name='vmbus' OR Name='storvsp'");
    for (i = 0; i < list.Count; i++) {
        var next = list.ItemIndex(i);
        WScript.echo("Driver " + next.Name + ": State = " + next.State + ", Status = " + next.Status);
    }

    WScript.Echo("");
    WScript.Echo("Looking for VSP services...");
    var list = g_CimV2.ExecQuery("SELECT * FROM Win32_Service WHERE Name='nvspwmi' OR Name='vmms' OR Name='vhdsvc'");
    for (i = 0; i < list.Count; i++) {
        var next = list.ItemIndex(i);
        WScript.echo("Service " + next.Name + ": State = " + next.State + ", Status = " + next.Status);
    }

    //
    // Enumerate all the adapters in the system
    //
    if (enumAdapters) {
        WScript.Echo("");
        WScript.Echo("Looking for Win32_NetworkAdapterConfiguration...");
        var list = g_CimV2.ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration");
        for (i = 0; i < list.Count; i++) {
            var next = list.ItemIndex(i);
            DisplayWin32NetworkAdapterConfiguration(next);
            WScript.Echo("");
        }

        WScript.Echo("");
        WScript.Echo("Looking for Win32_NetworkAdapterConfiguration...");
        var list = g_CimV2.ExecQuery("SELECT * FROM Win32_NetworkAdapter");
        for (i = 0; i < list.Count; i++) {
            var next = list.ItemIndex(i);
            DisplayWin32NetworkAdapter(next);
            WScript.Echo("");
        }
    }

    //
    // The nvspwmi service exposes the Hyper-V WMI objects
    //
    WScript.Echo("Looking for nvspwmi...");
    g_NvspWmi = new VirtualSwitchManagementService();

    //
    // "Internal" NICs are virtual NICs exposed to the root partition and provide the root
    // connectivity to the virtual network.
    //
    WScript.Echo("");
    WScript.Echo("Looking for internal (host) virtual nics...");
    var list = g_NvspWmi.m_VirtualizationNamespace.ExecQuery("SELECT * FROM Msvm_InternalEthernetPort");
    for (i = 0; i < list.Count; i++) {
        var next = list.ItemIndex(i);
        WScript.echo(next.DeviceID);
        WScript.echo("    " + next.ElementName);
        WScript.echo("    MTU = " + next.MaxDataSize);

        DisplayNetworkSettings(next.DeviceID);

        WScript.Echo("");
    }

    //
    // "External" NICs are NICs (typically physical) used by a virtual network.
    //
    // "IsBound=TRUE" indicates the NIC is currently bound to the switch protocol and is already used by a
    // virtual network.
    //
    WScript.Echo("");
    WScript.Echo("Looking for bound external nics...");
    list = g_NvspWmi.m_VirtualizationNamespace.ExecQuery("SELECT * FROM Msvm_ExternalEthernetPort WHERE IsBound=TRUE");
    for (i = 0; i < list.Count; i++) {
        var next = list.ItemIndex(i);
        WScript.echo(next.DeviceID);
        WScript.echo("    " + next.ElementName);

        DisplayNetworkSettings(next.DeviceID);

        WScript.Echo("");
    }

    //
    // "IsBound=FALSE" indicates the NIC is not currently bound to the switch protocol.
    //
    WScript.Echo("");
    WScript.Echo("Looking for unbound external nics...");
    list = g_NvspWmi.m_VirtualizationNamespace.ExecQuery("SELECT * FROM Msvm_ExternalEthernetPort WHERE IsBound=FALSE");
    for (i = 0; i < list.Count; i++) {
        var next = list.ItemIndex(i);
        WScript.echo(next.DeviceID);
        WScript.echo("    " + next.ElementName);
        WScript.echo("    MTU = " + next.MaxDataSize);

        DisplayNetworkSettings(next.DeviceID);

        WScript.Echo("");
    }

    //
    // "Synthetic" NICs are enlightended virtual NICs within VMs
    //
    WScript.Echo("");
    WScript.Echo("Looking for synthetic nics...");
    list = g_NvspWmi.m_VirtualizationNamespace.ExecQuery("SELECT * FROM Msvm_SyntheticEthernetPortSettingData");
    for (i = 0; i < list.Count; i++) {
        var next = list.ItemIndex(i);

        if (next.Address == null) {
            continue;
        }

        var syntheticEthernetPorts = next.Associators_(
                                        "Msvm_ElementSettingData",
                                        "Msvm_SyntheticEthernetPort",
                                        "ManagedElement");

        WScript.echo(next.ElementName + ":");

        if (next.Connection != null) {
            var connection = next.Connection.toArray();
            for (k = 0; k < connection.length; k++) {
                DumpConnectionInformation(connection[k]);
            }
        }

        WScript.Echo("    MAC address = " + next.Address);

        if (syntheticEthernetPorts.Count) {
            syntheticEthernetPort = syntheticEthernetPorts.ItemIndex(0);
            WScript.echo("    DeviceID = " + syntheticEthernetPort.DeviceID);
            WScript.echo("    MTU = " + syntheticEthernetPort.MaxDataSize);
        }
        else {
            WScript.echo("    not powered on");
        }

        WScript.Echo("");
    }

    //
    // "Emulated" NICs are emulated legacy virtual NICs within VMs
    //
    WScript.Echo("");
    WScript.Echo("Looking for emulated nics...");
    list = g_NvspWmi.m_VirtualizationNamespace.ExecQuery("SELECT * FROM Msvm_EmulatedEthernetPortSettingData");
    for (i = 0; i < list.Count; i++) {
        var next = list.ItemIndex(i);

        if (next.Address == null) {
            continue;
        }

        var emulatedEthernetPorts = next.Associators_(
                                        "Msvm_ElementSettingData",
                                        "Msvm_EmulatedEthernetPort",
                                        "ManagedElement");

        WScript.echo(next.ElementName + ":");

        if (next.Connection != null) {
            var connection = next.Connection.toArray();
            for (k = 0; k < connection.length; k++) {
                DumpConnectionInformation(connection[k]);
            }
        }

        WScript.Echo("    MAC address = " + next.Address);

        if (emulatedEthernetPorts.Count) {
            emulatedEthernetPort = emulatedEthernetPorts.ItemIndex(0);
            WScript.echo("    DeviceID = " + emulatedEthernetPort.DeviceID);
            WScript.echo("    MTU = " + emulatedEthernetPort.MaxDataSize);
        }
        else {
            WScript.echo("    not powered on");
        }

        WScript.Echo("");
    }

    //
    // Enumerate all the switches (virtual networks) in the system
    //
    WScript.Echo("");
    WScript.Echo("Looking for switches...");
    var switches = g_NvspWmi.m_VirtualizationNamespace.ExecQuery("SELECT * FROM Msvm_VirtualEthernetSwitch");
    for (i = 0; i < switches.Count; i++) {
        var isExternalConnected = false;    // indicates if an external NIC is connected
        var isInternalConnected = false;    // indicates if an internal NIC is connected

        var nextSwitch = switches.ItemIndex(i);
        WScript.echo(nextSwitch.Name);
        WScript.echo("    " + nextSwitch.ElementName);
        WScript.echo("    Ports:");

        var ports = g_NvspWmi.m_VirtualizationNamespace.ExecQuery("SELECT * FROM Msvm_EthernetSwitchPort WHERE SystemName= '" + nextSwitch.Name + "'");
        for (j = 0; j < ports.Count; j++) {
            var port = ports.ItemIndex(j);
            var isConnected = false;

            if (includePorts) {
                if (j > 0) {
                    WScript.Echo("");
                }

                WScript.echo("        " + port.Name);
            }

            // switch Msvm_LANEndpoints are for internal and external NICs
            var switchLanEndpoints = port.Associators_(
                            "Msvm_ActiveConnection",
                            "Msvm_SwitchLANEndpoint",
                            "Dependent");

            // VM Msvm_LANEndpoints are for virtual machine (synthetic and emulated) NICs
            var vmLanEndpoints = port.Associators_(
                            "Msvm_ActiveConnection",
                            "Msvm_VmLANEndpoint",
                            "Dependent");

            // Msvm_VLANEndpoint hold VLAN data for a switch port
            var vlanEndpoints = port.Associators_(
                            "Msvm_BindsTo",
                            "Msvm_VLANEndpoint",
                            "Dependent");

            // if interesed in port details, find VLAN settings
            if (includePorts && vlanEndpoints.Count) {
                var vlanEndpoint = vlanEndpoints.ItemIndex(0);
                var mode = vlanEndpoint.OperationalEndpointMode;

                // the VLAN ID and trunk array are stored in Msvm_VLANEndpointSettingData
                var vLANEndpointSettingData = vlanEndpoint.Associators_(
                                                "Msvm_NetworkElementSettingData",
                                                "Msvm_VLANEndpointSettingData",
                                                "SettingData");

                var accessVlanId = 0;   // only applicable in access mode
                var nativeVlanId = 0;   // only applicable in trunk mode

                if (vLANEndpointSettingData.Count) {
                    accessVlanId = vLANEndpointSettingData.ItemIndex(0).AccessVLAN;
                    nativeVlanId = vLANEndpointSettingData.ItemIndex(0).NativeVLAN;
                }

                // 2 = access mode, 5 = trunk mode
                if (mode == 2) {
                    WScript.echo("        VLAN Mode            = ACCESS " + accessVlanId);
                }
                else if (mode == 5) {
                    // build up a string for the trunk list
                    var trunkList = vLANEndpointSettingData.ItemIndex(0).TrunkedVLANList.toArray();
                    var txtTrunkList = "";

                    for (k = 0; k < trunkList.length; k++) {
                        if (k != 0) {
                            txtTrunkList = txtTrunkList + ",";
                        }
                        txtTrunkList = txtTrunkList + trunkList[k];
                    }

                    WScript.echo("        VLAN Mode            = TRUNK, NativeVLAN=" + nativeVlanId + ", TrunkArray=" + txtTrunkList);
                }
                else {
                    WScript.echo("        VLAN Mode            = ", mode);
                }
            }

            if (switchLanEndpoints.Count) {
                var switchLanEndpoint = switchLanEndpoints.ItemIndex(0);

                var internals = switchLanEndpoint.Associators_(
                                    "Msvm_GlobalEthernetPortSAPImplementation",
                                    "Msvm_InternalEthernetPort",
                                    "Antecedent");

                if (internals.Count) {
                    // the connected port of of type "Internal"
                    WScript.echo("        Internal NIC: " + internals.ItemIndex(0).Name);
                    WScript.echo("            " + internals.ItemIndex(0).ElementName);
                    isInternalConnected = true;
                    isConnected = true;
                }

                var externals = switchLanEndpoint.Associators_(
                                    "Msvm_GlobalEthernetPortSAPImplementation",
                                    "Msvm_ExternalEthernetPort",
                                    "Antecedent");

                if (externals.Count) {
                    // the connected port of of type "External"
                    WScript.echo("        External NIC: " + externals.ItemIndex(0).Name);
                    WScript.echo("            " + externals.ItemIndex(0).ElementName);
                    isExternalConnected = true;
                    isConnected = true;
                }
            }

            if (vmLanEndpoints.Count) {
                var vmLanEndpoint = vmLanEndpoints.ItemIndex(0);

                var synthetic = vmLanEndpoint.Associators_(
                                    "Msvm_DeviceSAPImplementation",
                                    "Msvm_SyntheticEthernetPort",
                                    "Antecedent");

                if (synthetic.Count) {
                    // get name of VM
                    var vmName = synthetic.ItemIndex(0).SystemName;

                    var vm = g_NvspWmi.m_VirtualizationNamespace.ExecQuery(
                        "SELECT * FROM Msvm_ComputerSystem WHERE Name= '" + synthetic.ItemIndex(0).SystemName + "'");

                    if (vm.Count) {
                        vmName = vm.ItemIndex(0).ElementName;
                    }

                    // the connected port is of type "Synthetic"
                    WScript.echo("        VM NIC:       " + synthetic.ItemIndex(0).ElementName);
                    WScript.echo("            VM = " + vmName);
                    WScript.echo("            DeviceID = " + synthetic.ItemIndex(0).DeviceID);
                    isConnected = true;

                    // get the corresponding Msvm_SyntheticEthernetPortSettingData
                    var syntheticEthernetPortSettingData = synthetic.ItemIndex(0).Associators_(
                                                    "Msvm_ElementSettingData",
                                                    "Msvm_SyntheticEthernetPortSettingData",
                                                    "SettingData");
                    if (syntheticEthernetPortSettingData.Count) {
                        WScript.Echo("            MAC address = " +
                                            syntheticEthernetPortSettingData.ItemIndex(0).Address);

                        WScript.Echo("            VirtualSystemIdentifiers = ");
                        var vsids = syntheticEthernetPortSettingData.ItemIndex(0).VirtualSystemIdentifiers.toArray();

                        for (k = 0; k < vsids.length; k++) {
                            WScript.Echo("                " + vsids[k]);
                        }
                    }
                }

                var emulated = vmLanEndpoint.Associators_(
                                    "Msvm_DeviceSAPImplementation",
                                    "Msvm_EmulatedEthernetPort",
                                    "Antecedent");

                if (emulated.Count) {
                    // get name of VM
                    var vmName = emulated.ItemIndex(0).SystemName;

                    var vm = g_NvspWmi.m_VirtualizationNamespace.ExecQuery(
                        "SELECT * FROM Msvm_ComputerSystem WHERE Name= '" + emulated.ItemIndex(0).SystemName + "'");

                    if (vm.Count) {
                        vmName = vm.ItemIndex(0).ElementName;
                    }

                    // the connected port is of type "Emulated" (legacy)
                    WScript.echo("        Legacy NIC:   " + emulated.ItemIndex(0).ElementName);
                    WScript.echo("            VM = " + vmName);
                    WScript.echo("            DeviceID = " + emulated.ItemIndex(0).DeviceID);
                    isConnected = true;

                    // get the corresponding Msvm_EmulatedEthernetPortSettingData
                    var emulatedEthernetPortSettingData = emulated.ItemIndex(0).Associators_(
                                                    "Msvm_ElementSettingData",
                                                    "Msvm_EmulatedEthernetPortSettingData",
                                                    "SettingData");
                    if (emulatedEthernetPortSettingData.Count) {
                        WScript.Echo("            MAC address = " +
                                            emulatedEthernetPortSettingData.ItemIndex(0).Address);
                    }
                }
            }

            if (includeMac) {
                var macs = port.Associators_(
                                "Msvm_SwitchPortDynamicForwarding",
                                "Msvm_DynamicForwardingEntry",
                                "Dependent");

                for (k = 0; k < macs.Count; k++) {
                    var mac = macs.ItemIndex(k);
                    var str = mac.MACAddress;
                    if (str.length != 12) {
                        WScript.echo("                " + str);
                    }
                    else {
                        WScript.echo("                " +
                            str.charAt(0) + str.charAt(1) + "-" +
                            str.charAt(2) + str.charAt(3) + "-" +
                            str.charAt(4) + str.charAt(5) + "-" +
                            str.charAt(6) + str.charAt(7) + "-" +
                            str.charAt(8) + str.charAt(9) + "-" +
                            str.charAt(10) + str.charAt(11));
                    }
                }
            }

            if (!includePorts && isConnected && j < (ports.Count - 1)) {
                WScript.Echo("");
            }

        }

        if (isExternalConnected) {
            if (isInternalConnected) {
                WScript.echo("    Switch is of type 'External' with a root virtual NIC");
            }
            else {
                WScript.echo("    Switch is of type 'External' without a root virtual NIC");
            }
        }
        else {
            if (isInternalConnected) {
                WScript.echo("    Switch is of type 'Internal'");
            }
            else {
                WScript.echo("    Switch is of type 'Private'");
            }
        }
        WScript.Echo("");
    }

    WScript.Echo("");
    WScript.Echo("Finished!");
}

// SIG // Begin signature block
// SIG // MIIa2QYJKoZIhvcNAQcCoIIayjCCGsYCAQExCzAJBgUr
// SIG // DgMCGgUAMGcGCisGAQQBgjcCAQSgWTBXMDIGCisGAQQB
// SIG // gjcCAR4wJAIBAQQQEODJBs441BGiowAQS9NQkAIBAAIB
// SIG // AAIBAAIBAAIBADAhMAkGBSsOAwIaBQAEFKiMCitMn3n+
// SIG // R75zM5mqcTXm9h7FoIIVgjCCBMMwggOroAMCAQICEzMA
// SIG // AABMoehNzLR0ezsAAAAAAEwwDQYJKoZIhvcNAQEFBQAw
// SIG // dzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
// SIG // b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
// SIG // Y3Jvc29mdCBDb3Jwb3JhdGlvbjEhMB8GA1UEAxMYTWlj
// SIG // cm9zb2Z0IFRpbWUtU3RhbXAgUENBMB4XDTEzMTExMTIy
// SIG // MTEzMVoXDTE1MDIxMTIyMTEzMVowgbMxCzAJBgNVBAYT
// SIG // AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
// SIG // EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
// SIG // cG9yYXRpb24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsT
// SIG // Hm5DaXBoZXIgRFNFIEVTTjpDMEY0LTMwODYtREVGODEl
// SIG // MCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
// SIG // dmljZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
// SIG // ggEBALHY+hsGK3eo5JRdfA/meqaS7opUHaT5hHWFl8zL
// SIG // XJbQ13Ut2Qj7W9LuLSXGNz71q34aU+VXvmvov8qWCtxG
// SIG // 8VoePgLSsuAmjgBke748k/hYMnmH0hpdI7ycUcQPEPoE
// SIG // WLUWdm7svMblvvytrMFB26rOefUcsplBp3olK/+reA1Y
// SIG // OrFeUN5kTODKFSrfpun+pGYvWxAJCSYh1D8NL23S+HeQ
// SIG // A2zeFBKljOc2H/SHpbBBF2/jTXRmwv2icUY1UcxrF1Fj
// SIG // +hWUkppfSyi65hZFSekstf6Lh6/8pW1D3KYw+iko75sN
// SIG // LFyD3hKNarTbce9cFFoqIyj/gXBX8YwHmhPYKlMCAwEA
// SIG // AaOCAQkwggEFMB0GA1UdDgQWBBS5Da2zTfTanxqyJyZV
// SIG // DSBE2Jji9DAfBgNVHSMEGDAWgBQjNPjZUkZwCu1A+3b7
// SIG // syuwwzWzDzBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
// SIG // Y3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0
// SIG // cy9NaWNyb3NvZnRUaW1lU3RhbXBQQ0EuY3JsMFgGCCsG
// SIG // AQUFBwEBBEwwSjBIBggrBgEFBQcwAoY8aHR0cDovL3d3
// SIG // dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNyb3Nv
// SIG // ZnRUaW1lU3RhbXBQQ0EuY3J0MBMGA1UdJQQMMAoGCCsG
// SIG // AQUFBwMIMA0GCSqGSIb3DQEBBQUAA4IBAQAJik4Gr+jt
// SIG // gs8dB37XKqckCy2vmlskf5RxDFWIJBpSFWPikE0FSphK
// SIG // nPvhp21oVYK5KeppqbLV4wza0dZ6JTd4ZxwM+9spWhqX
// SIG // OCo5Vkb7NYG55D1GWo7k/HU3WFlJi07bPBWdc1JL63sM
// SIG // OsItwbObUi3gNcW5wVez6D2hPETyIxYeCqpZNyfQlVJe
// SIG // qH8/VPCB4dyavWXVePb3TDm73eDWNw6RmoeMc+dxZFL3
// SIG // PgPYxs1yuDQ0mFuM0/UIput4xlGgDQ5v9Gs8QBpgFiyp
// SIG // BlKdHBOQzm8CHup7nLP2+Jdg8mXR0R+HOsF18EKNeu2M
// SIG // crJ7+yyKtJFHVOIuacwWVBpZMIIE7DCCA9SgAwIBAgIT
// SIG // MwAAAMps1TISNcThVQABAAAAyjANBgkqhkiG9w0BAQUF
// SIG // ADB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
// SIG // Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
// SIG // TWljcm9zb2Z0IENvcnBvcmF0aW9uMSMwIQYDVQQDExpN
// SIG // aWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQTAeFw0xNDA0
// SIG // MjIxNzM5MDBaFw0xNTA3MjIxNzM5MDBaMIGDMQswCQYD
// SIG // VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
// SIG // A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
// SIG // IENvcnBvcmF0aW9uMQ0wCwYDVQQLEwRNT1BSMR4wHAYD
// SIG // VQQDExVNaWNyb3NvZnQgQ29ycG9yYXRpb24wggEiMA0G
// SIG // CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCWcV3tBkb6
// SIG // hMudW7dGx7DhtBE5A62xFXNgnOuntm4aPD//ZeM08aal
// SIG // IV5WmWxY5JKhClzC09xSLwxlmiBhQFMxnGyPIX26+f4T
// SIG // UFJglTpbuVildGFBqZTgrSZOTKGXcEknXnxnyk8ecYRG
// SIG // vB1LtuIPxcYnyQfmegqlFwAZTHBFOC2BtFCqxWfR+nm8
// SIG // xcyhcpv0JTSY+FTfEjk4Ei+ka6Wafsdi0dzP7T00+Lnf
// SIG // NTC67HkyqeGprFVNTH9MVsMTC3bxB/nMR6z7iNVSpR4o
// SIG // +j0tz8+EmIZxZRHPhckJRIbhb+ex/KxARKWpiyM/gkmd
// SIG // 1ZZZUBNZGHP/QwytK9R/MEBnAgMBAAGjggFgMIIBXDAT
// SIG // BgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUH17i
// SIG // XVCNVoa+SjzPBOinh7XLv4MwUQYDVR0RBEowSKRGMEQx
// SIG // DTALBgNVBAsTBE1PUFIxMzAxBgNVBAUTKjMxNTk1K2I0
// SIG // MjE4ZjEzLTZmY2EtNDkwZi05YzQ3LTNmYzU1N2RmYzQ0
// SIG // MDAfBgNVHSMEGDAWgBTLEejK0rQWWAHJNy4zFha5TJoK
// SIG // HzBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1p
// SIG // Y3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWND
// SIG // b2RTaWdQQ0FfMDgtMzEtMjAxMC5jcmwwWgYIKwYBBQUH
// SIG // AQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1p
// SIG // Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY0NvZFNpZ1BD
// SIG // QV8wOC0zMS0yMDEwLmNydDANBgkqhkiG9w0BAQUFAAOC
// SIG // AQEAd1zr15E9zb17g9mFqbBDnXN8F8kP7Tbbx7UsG177
// SIG // VAU6g3FAgQmit3EmXtZ9tmw7yapfXQMYKh0nfgfpxWUf
// SIG // tc8Nt1THKDhaiOd7wRm2VjK64szLk9uvbg9dRPXUsO8b
// SIG // 1U7Brw7vIJvy4f4nXejF/2H2GdIoCiKd381wgp4Yctgj
// SIG // zHosQ+7/6sDg5h2qnpczAFJvB7jTiGzepAY1p8JThmUR
// SIG // dwmPNVm52IaoAP74MX0s9IwFncDB1XdybOlNWSaD8cKy
// SIG // iFeTNQB8UCu8Wfz+HCk4gtPeUpdFKRhOlludul8bo/En
// SIG // UOoHlehtNA04V9w3KDWVOjic1O1qhV0OIhFeezCCBbww
// SIG // ggOkoAMCAQICCmEzJhoAAAAAADEwDQYJKoZIhvcNAQEF
// SIG // BQAwXzETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcGCgmS
// SIG // JomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMkTWlj
// SIG // cm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
// SIG // MB4XDTEwMDgzMTIyMTkzMloXDTIwMDgzMTIyMjkzMlow
// SIG // eTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
// SIG // b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
// SIG // Y3Jvc29mdCBDb3Jwb3JhdGlvbjEjMCEGA1UEAxMaTWlj
// SIG // cm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EwggEiMA0GCSqG
// SIG // SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCycllcGTBkvx2a
// SIG // YCAgQpl2U2w+G9ZvzMvx6mv+lxYQ4N86dIMaty+gMuz/
// SIG // 3sJCTiPVcgDbNVcKicquIEn08GisTUuNpb15S3GbRwfa
// SIG // /SXfnXWIz6pzRH/XgdvzvfI2pMlcRdyvrT3gKGiXGqel
// SIG // cnNW8ReU5P01lHKg1nZfHndFg4U4FtBzWwW6Z1KNpbJp
// SIG // L9oZC/6SdCnidi9U3RQwWfjSjWL9y8lfRjFQuScT5EAw
// SIG // z3IpECgixzdOPaAyPZDNoTgGhVxOVoIoKgUyt0vXT2Pn
// SIG // 0i1i8UU956wIAPZGoZ7RW4wmU+h6qkryRs83PDietHdc
// SIG // pReejcsRj1Y8wawJXwPTAgMBAAGjggFeMIIBWjAPBgNV
// SIG // HRMBAf8EBTADAQH/MB0GA1UdDgQWBBTLEejK0rQWWAHJ
// SIG // Ny4zFha5TJoKHzALBgNVHQ8EBAMCAYYwEgYJKwYBBAGC
// SIG // NxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQU/dExTtMm
// SIG // ipXhmGA7qDFvpjy82C0wGQYJKwYBBAGCNxQCBAweCgBT
// SIG // AHUAYgBDAEEwHwYDVR0jBBgwFoAUDqyCYEBWJ5flJRP8
// SIG // KuEKU5VZ5KQwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDov
// SIG // L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVj
// SIG // dHMvbWljcm9zb2Z0cm9vdGNlcnQuY3JsMFQGCCsGAQUF
// SIG // BwEBBEgwRjBEBggrBgEFBQcwAoY4aHR0cDovL3d3dy5t
// SIG // aWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNyb3NvZnRS
// SIG // b290Q2VydC5jcnQwDQYJKoZIhvcNAQEFBQADggIBAFk5
// SIG // Pn8mRq/rb0CxMrVq6w4vbqhJ9+tfde1MOy3XQ60L/svp
// SIG // LTGjI8x8UJiAIV2sPS9MuqKoVpzjcLu4tPh5tUly9z7q
// SIG // QX/K4QwXaculnCAt+gtQxFbNLeNK0rxw56gNogOlVuC4
// SIG // iktX8pVCnPHz7+7jhh80PLhWmvBTI4UqpIIck+KUBx3y
// SIG // 4k74jKHK6BOlkU7IG9KPcpUqcW2bGvgc8FPWZ8wi/1wd
// SIG // zaKMvSeyeWNWRKJRzfnpo1hW3ZsCRUQvX/TartSCMm78
// SIG // pJUT5Otp56miLL7IKxAOZY6Z2/Wi+hImCWU4lPF6H0q7
// SIG // 0eFW6NB4lhhcyTUWX92THUmOLb6tNEQc7hAVGgBd3TVb
// SIG // Ic6YxwnuhQ6MT20OE049fClInHLR82zKwexwo1eSV32U
// SIG // jaAbSANa98+jZwp0pTbtLS8XyOZyNxL0b7E8Z4L5UrKN
// SIG // MxZlHg6K3RDeZPRvzkbU0xfpecQEtNP7LN8fip6sCvsT
// SIG // J0Ct5PnhqX9GuwdgR2VgQE6wQuxO7bN2edgKNAltHIAx
// SIG // H+IOVN3lofvlRxCtZJj/UBYufL8FIXrilUEnacOTj5XJ
// SIG // jdibIa4NXJzwoq6GaIMMai27dmsAHZat8hZ79haDJLmI
// SIG // z2qoRzEvmtzjcT3XAH5iR9HOiMm4GPoOco3Boz2vAkBq
// SIG // /2mbluIQqBC0N1AI1sM9MIIGBzCCA++gAwIBAgIKYRZo
// SIG // NAAAAAAAHDANBgkqhkiG9w0BAQUFADBfMRMwEQYKCZIm
// SIG // iZPyLGQBGRYDY29tMRkwFwYKCZImiZPyLGQBGRYJbWlj
// SIG // cm9zb2Z0MS0wKwYDVQQDEyRNaWNyb3NvZnQgUm9vdCBD
// SIG // ZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMDcwNDAzMTI1
// SIG // MzA5WhcNMjEwNDAzMTMwMzA5WjB3MQswCQYDVQQGEwJV
// SIG // UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
// SIG // UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
// SIG // cmF0aW9uMSEwHwYDVQQDExhNaWNyb3NvZnQgVGltZS1T
// SIG // dGFtcCBQQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
// SIG // ggEKAoIBAQCfoWyx39tIkip8ay4Z4b3i48WZUSNQrc7d
// SIG // GE4kD+7Rp9FMrXQwIBHrB9VUlRVJlBtCkq6YXDAm2gBr
// SIG // 6Hu97IkHD/cOBJjwicwfyzMkh53y9GccLPx754gd6udO
// SIG // o6HBI1PKjfpFzwnQXq/QsEIEovmmbJNn1yjcRlOwhtDl
// SIG // KEYuJ6yGT1VSDOQDLPtqkJAwbofzWTCd+n7Wl7PoIZd+
// SIG // +NIT8wi3U21StEWQn0gASkdmEScpZqiX5NMGgUqi+YSn
// SIG // EUcUCYKfhO1VeP4Bmh1QCIUAEDBG7bfeI0a7xC1Un68e
// SIG // eEExd8yb3zuDk6FhArUdDbH895uyAc4iS1T/+QXDwiAL
// SIG // AgMBAAGjggGrMIIBpzAPBgNVHRMBAf8EBTADAQH/MB0G
// SIG // A1UdDgQWBBQjNPjZUkZwCu1A+3b7syuwwzWzDzALBgNV
// SIG // HQ8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwgZgGA1Ud
// SIG // IwSBkDCBjYAUDqyCYEBWJ5flJRP8KuEKU5VZ5KShY6Rh
// SIG // MF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAXBgoJkiaJ
// SIG // k/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jv
// SIG // c29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eYIQ
// SIG // ea0WoUqgpa1Mc1j0BxMuZTBQBgNVHR8ESTBHMEWgQ6BB
// SIG // hj9odHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
// SIG // bC9wcm9kdWN0cy9taWNyb3NvZnRyb290Y2VydC5jcmww
// SIG // VAYIKwYBBQUHAQEESDBGMEQGCCsGAQUFBzAChjhodHRw
// SIG // Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01p
// SIG // Y3Jvc29mdFJvb3RDZXJ0LmNydDATBgNVHSUEDDAKBggr
// SIG // BgEFBQcDCDANBgkqhkiG9w0BAQUFAAOCAgEAEJeKw1wD
// SIG // RDbd6bStd9vOeVFNAbEudHFbbQwTq86+e4+4LtQSooxt
// SIG // YrhXAstOIBNQmd16QOJXu69YmhzhHQGGrLt48ovQ7DsB
// SIG // 7uK+jwoFyI1I4vBTFd1Pq5Lk541q1YDB5pTyBi+FA+mR
// SIG // KiQicPv2/OR4mS4N9wficLwYTp2OawpylbihOZxnLcVR
// SIG // DupiXD8WmIsgP+IHGjL5zDFKdjE9K3ILyOpwPf+FChPf
// SIG // wgphjvDXuBfrTot/xTUrXqO/67x9C0J71FNyIe4wyrt4
// SIG // ZVxbARcKFA7S2hSY9Ty5ZlizLS/n+YWGzFFW6J1wlGys
// SIG // OUzU9nm/qhh6YinvopspNAZ3GmLJPR5tH4LwC8csu89D
// SIG // s+X57H2146SodDW4TsVxIxImdgs8UoxxWkZDFLyzs7BN
// SIG // Z8ifQv+AeSGAnhUwZuhCEl4ayJ4iIdBD6Svpu/RIzCzU
// SIG // 2DKATCYqSCRfWupW76bemZ3KOm+9gSd0BhHudiG/m4LB
// SIG // J1S2sWo9iaF2YbRuoROmv6pH8BJv/YoybLL+31HIjCPJ
// SIG // Zr2dHYcSZAI9La9Zj7jkIeW1sMpjtHhUBdRBLlCslLCl
// SIG // eKuzoJZ1GtmShxN1Ii8yqAhuoFuMJb+g74TKIdbrHk/J
// SIG // mu5J4PcBZW+JC33Iacjmbuqnl84xKf8OxVtc2E0bodj6
// SIG // L54/LlUWa8kTo/0xggTDMIIEvwIBATCBkDB5MQswCQYD
// SIG // VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
// SIG // A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
// SIG // IENvcnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQg
// SIG // Q29kZSBTaWduaW5nIFBDQQITMwAAAMps1TISNcThVQAB
// SIG // AAAAyjAJBgUrDgMCGgUAoIHcMBkGCSqGSIb3DQEJAzEM
// SIG // BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgor
// SIG // BgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQF1Uz0S+FT
// SIG // iSL0APO1jgrH4iuAADB8BgorBgEEAYI3AgEMMW4wbKBS
// SIG // gFAAQwBUAFMAXwBOAGUAdAB3AG8AcgBrAGkAbgBnAF8A
// SIG // TQBhAGkAbgBfAGcAbABvAGIAYQBsAF8AbgB2AHMAcABp
// SIG // AG4AZgBvAHYAMgAuAGoAc6EWgBRodHRwOi8vbWljcm9z
// SIG // b2Z0LmNvbTANBgkqhkiG9w0BAQEFAASCAQAxScq0johw
// SIG // HHcMmOKrnWA0vFT5ZYvNgtDvjtQR/5mPsS2U78+CaGBA
// SIG // 7wCjd+3R/2/tDXTnOf6NcdTAwGHN5MfDMV6HxHCGU83u
// SIG // 0FERPizQtTAO2PBGg3kcR38BiVPH8tRwiUpETRunGwh+
// SIG // H52mEx+vtKBVnYTA8QX0BjUrUxgbvwXx7BWDhnXnB4ud
// SIG // C9uYEJH1qFMJIbY1fw4FFFybIFCcubScfWWnt+A+ZZUf
// SIG // tQwrPlDNySusG5TAyF7nLFBFFS6aupRLLJY8P8XzvG68
// SIG // ZxKec/k030Q9STbHSAg9LnHjo+CaqvFi/kkHgdDXDaZU
// SIG // 7JKPMkwObeL0r2vJIItP6klsoYICKDCCAiQGCSqGSIb3
// SIG // DQEJBjGCAhUwggIRAgEBMIGOMHcxCzAJBgNVBAYTAlVT
// SIG // MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
// SIG // ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
// SIG // YXRpb24xITAfBgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0
// SIG // YW1wIFBDQQITMwAAAEyh6E3MtHR7OwAAAAAATDAJBgUr
// SIG // DgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEH
// SIG // ATAcBgkqhkiG9w0BCQUxDxcNMTQxMDIwMTgwODM3WjAj
// SIG // BgkqhkiG9w0BCQQxFgQUYmBWV0vw4nCEJSrFKV/z7E1y
// SIG // BmowDQYJKoZIhvcNAQEFBQAEggEAUzPMTjVDfBA/vsAr
// SIG // wCSkWGNQDv89mNhvquyd0/LbMKEw/pX+OCCuJQgPRjg4
// SIG // 3uj9Wqyw+YFPqAjWWQ2Qh8HNEeZOmyIITzS5bRMj2EVa
// SIG // NfcnLYP2I1S1s21Xcb3Wa+1WNsD87/xOp1yFNbDqwUxN
// SIG // vqNtkHJK6SzLGOKJ2/i7O5Nn+lP/TZqPjuLPZQPuioid
// SIG // FPyDlBIX5YOpm4wgINHuFbMUOPCjvC7/1cssL9LA05b6
// SIG // YekZf41U7c0fkJmvoghwYxoY0Zri4nxpWutAPhcREDRL
// SIG // Ia5ACbwTMwpnRms8bOWi9ZFWU2KgVYy+a/cPUUOtIodv
// SIG // pVffjbkzp3t0S16uxw==
// SIG // End signature block
