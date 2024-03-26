using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
    public struct WnfStateName
        {
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
    public UInt32[] data;

    public WnfStateName(UInt32[] content)
    {
        data = new UInt32[] { 0, 0 };
        if (content != null && content.Length == 2)
        {
            data[0] = content[0];
            data[1] = content[1];
        }
    }

    public WnfStateName(UInt32 lower, UInt32 higher)
    {
	    data = new UInt32[] { 0, 0 };
        data[0] = lower;
        data[1] = higher;
    }
}

public class WnfUtil
{
    [DllImport("ntdll.dll", EntryPoint = "NtQueryWnfStateData")]
    public static extern UInt32 QueryWnfStateData(
            [MarshalAs(UnmanagedType.Struct)]
            ref WnfStateName stateName,
            IntPtr typeId, 
            IntPtr explicitScope,
            ref uint changeStamp,
            [Out] byte[] buffer,
            ref uint bufferSize);

    [DllImport("dmcmnutils.dll", EntryPoint = "DmWnfPublish")]
    public static extern uint DmWnfPublish(
            WnfStateName stateName,
            byte[] StateData,
            int StateDataLength); 

    [DllImport("dmcmnutils.dll", EntryPoint = "DmWnfQuery")]
    public static extern uint DmWnfQuery(
            WnfStateName stateName,
            uint maxLength,
            byte[] StateData,
            ref uint StateDataLength); 

    [DllImport("ntdll.dll", EntryPoint = "RtlPublishWnfStateData", CallingConvention = CallingConvention.StdCall)]
    public static extern uint PublishWnfStateData(
            WnfStateName stateName,
            IntPtr TypeId,
            byte[] StateData,
            int StateDataLength,
            IntPtr ExplicitScope);

    [DllImport("policymanager.dll", EntryPoint = "PolicyManager_GetPolicyString")]
    public static extern uint MdmGetPolicyString(
        [MarshalAs(UnmanagedType.LPWStr)]
        String area,
        [MarshalAs(UnmanagedType.LPWStr)]
        String policy,
        [MarshalAs(UnmanagedType.LPWStr)]
        out String policyValue);
}
