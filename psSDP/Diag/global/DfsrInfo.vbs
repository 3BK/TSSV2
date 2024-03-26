'=========================================================================================================
' NAME:         DfsrInfo.vbs
' VERSION       2.1
' LAST UPDATE:  4/23/2010
' AUTHOR:       clandis@microsoft.com
' COMMENT:      Gathers data to assist in troubleshooting DFS Replication.
'               Can also be used to configure debug logging and DFS Management 
'               tracing, and event log verbosity. Run dfsrinfo /? for more info.
'
' ==========[DISCLAIMER]==================================================================================
' Microsoft provides programming examples for illustration only, without warranty either expressed or
' implied, including, but not limited to, the implied warranties of merchantability and/or fitness for a 
' particular purpose.  This article assumes that you are familiar with the programming language being
' demonstrated and the tools used to create and debug procedures. Microsoft support professionals 
' can help explain the functionality of a particular procedure, but they will not modify these examples 
' to provide added functionality or construct procedures to meet your specific needs. If you have limited 
' programming experience, you may want to contact a Microsoft Certified Solution Provider or the 
' Microsoft fee-based consulting line at (800) 936-5200.
' ========================================================================================================

'Option Explicit
On Error Resume Next

Const wbemFlagReturnImmediately = &h10
Const wbemFlagForwardOnly = &h20
Const FOR_READING = 1, FOR_WRITING = 2, FOR_APPENDING = 8
Const OverwriteExisting = TRUE
Const TO_SCREEN = 1, TO_FILE = 2
Const ADS_SCOPE_SUBTREE = 2
Const RECOMMENDED_MAXDEBUGLOGFILES = 1000
Const CONVERSION_FACTOR = 1073741824
Const SCRIPT_VERSION = "2.1"

Dim objExec, objWMIService, objWMIDfsService, objWMIDfsService2, objNetwork, objRegExp, objShell, objItem, objEvent, objFSO, objOutput, objLogfile, objFolder, objFile, objCabDirectiveFile, objCabFolder, objDisk
Dim objFileVersionInfo, objInfoFile, objParsedInfoFile, objService, objPerfData, objEvents, objTextFile, objInstance, objVolume, objDomain, objRecordSet, objHotfix, objHotfixInfo, objDebugFile
Dim objSubscriber, objSubscriberParent, objSubscriberGrandParent, objRootDSE, objConnection, objCommand, objOperatingsystem, objConflictInfo, objTempDrive, objDebugFolder
Dim colDisks, colOperatingSystems, colListOfServices, colItems, colEvents, colLogFiles, colFiles, colHotfixes, colDebugFiles, colTempFiles, objTempFile
Dim colDFSReplicatedFolders, colDFSReplicationConnections, colDFSReplicationServiceVolumes, colNamedArguments, colVolumes
Dim strCurrentLine, strTempFolder, strRGName, strParsedRGName, strCommand, strComputer, strComputerName, strSubscriptionCommand, strMachineConfigCommand, strADConfigCommand, strDebugLogFilePath, strCabFolder
Dim strScheduleExplainText, strDFSRInfoFile, strWinDir, strDomain, strRGDN, strServicePack, strTempDriveName, strOSVersion
Dim strADsPath, strDomainDN, strRFGUID, strDN, strDfsrServiceStatus, strBuildNumber, strCaption, strFilePath, strFilePathWMI, strDfsrServiceAccount
Dim dtmNow, dtmStartDate, strVersionWarning, blnNoEvents, blnTimedout, blnNoDebugLogs, blnFoundConfigFile
Dim arrRGCommands(31), arrMachineCommands(19), arrDN, arrHotfixes(), arrTemp, arrDFSRFiles
Dim errReturn, strSKU, strFileVersion, strFileName, dtmCommandCompletionTime, dtmCommandStartTime
Dim blnDfsrInstalled, blnNoReports, blnCheckHotfixesOnly, blnNoMSINFO32, blnOutputToTextFile, blnNoDBGUIDs, blnNoLogFileCheck, blnConfigChange, blnMSDT, blnFirstRun
Dim i, j, k, strMsgBoxTxt1, objTempFolder, strDFSRFiles, objClusterTextFile, objClusWMIService
Dim strErrText, objProgressText, objDebugLogFilesDrive, currentDebugLogFilePath, freeGigabytes, currentMaxDebugLogFiles, strMsgBoxTxt2, strMsgBoxTxt3
Dim blnCoreInstall, objFeature, colOptionalFeatures, blnDfsradmin, dtmStartTime, dtmEndTime, strElapsedTime, strSystemDrive
Dim str2003PreSP2Fixes, str2003PreSP3Fixes, str2008R2PreSP1Fixes, str2008PreSP2Fixes, str2008PreSP3Fixes, seconds

dtmStartTime = Timer

strComputer = "."
blnConfigChange = False
blnMSDT = False
blnFirstRun = True
blnDfsradmin = True

strScheduleExplainText = "Each row represents a day of the week. Each column represents an hour in the day." & vbCrLf &_
                         "A hex value (0-F) represents the bandwidth usage for each 15 min. interval in an hour."  & vbCrLf &_
                         "F = Full,E=256M,D=128M,C=64M,B=32M,A=16M,9=8M,8=4M,7=2M,6=1M,5=512K,4=256K,3=128K,2=64K,1=16K,0=No replication" & vbCrLf &_
                         "The values are either in megabits per second (M) or kilobits per second (K)." & vbCrLf

str2008R2PreSP1Fixes = "975763 DFS Replication does not use Remote Differential...(superseded by 979524)," &_
                       "976655 You cannot perform a system state restore in the Directory Service Restore...," &_
                       "979524 The DFS Replication service crashes randomly in x64-based versions...," &_
                       "979564 The DFS Replication Management Pack shows alerts for cluster network..."

str2008PreSP2Fixes = "953325 A Windows Server 2003- or 2008-based computer becomes...," &_
                     "962969 Error message when you run Dfsradmin.exe to set membership...," &_
                     "970770 NTDS Writer PostSnapshot behavior in Windows Server 2008...," &_
                     "973275 Only the first character appears for some strings in the...," &_
                     "979646 Some folders or some files are unexpectedly deleted on the..."

str2008PreSP3Fixes = "979646 Some folders or some files are unexpectedly deleted on the upstream...," &_
                     "973275 Only the first character appears for some strings in the...," &_
                     "973123 The Distributed File System Replication service may...," &_
                     "970770 NTDS Writer PostSnapshot behavior in Windows Server 2008..."

str2003PreSP2Fixes = "908521 Office Outlook 2003 may stop responding on a computer that is running...," &_
				     "905700 You may receive an RPC server is too busy to complete this operation...," &_  
				     "912154 You cannot create a diagnostic report for DFS replication on a...," &_
				     "912850 Unable to access performance counters in DFS Replication report for...," &_
				     "917953 MS06-032: Vulnerability in TCP/IP could allow remote code execution...," &_
				     "917622 Hotfix rollup package for Distributed File System Replication (superseded by 967357)," &_
				     "920335 You cannot create a replication group for data collection when the...," &_ 
				     "925377 Error message when you continuously use the Dfsrdiag.exe utility to...(superseded by 967357)," &_
				     "925332 Error message when you try to change the permissions on a folder...(superseded by 967357)," &_
				     "928569 FIX: The first CLR thread pool worker thread is never initialized...," &_
				     "931685 Files are copied over the network even though the versions of the...(superseded by 967357)," &_
                     "933061 An update is available that improves the stability of the Windows...," &_
                     "943661 Replication may fail after a dirty system shutdown on a Windows...(superseded by 967357)," &_
                     "944804 Distributed File System Replication in Windows Server 2003 R2...," &_
                     "953527 An event ID 6002 that references Distributed File System...," &_
                     "954968 Subfolder file content on an upstream member does not match...," &_
                     "953325 A Windows Server 2003- or 2008-based computer becomes...," &_
                     "967357 Some files are missing on a Windows Server 2003 R2-based..."
				
str2003PreSP3Fixes = "928569 FIX: The first CLR thread pool worker thread is never initialized...," &_
                     "931685 Files are copied over the network even though the versions of the...(superseded by 979646)," &_
                     "933061 An update is available that improves the stability of the Windows...," &_
                     "943661 Replication may fail after a dirty system shutdown on a Windows...(superseded by 979646)," &_
                     "944804 Distributed File System Replication in Windows Server 2003 R2...," &_
                     "953527 An event ID 6002 that references Distributed File System...," &_
                     "954968 Subfolder file content on an upstream member does not match...," &_
                     "953325 A Windows Server 2003- or 2008-based computer becomes...," &_
                     "979646 Some folders or some files are unexpectedly deleted on the..."

strDFSRFiles =  "dfsmgmt.dll," &_
                "dfsobjectmodel.dll," &_
                "dfsr.exe," &_
                "dfsradmin.exe," &_
                "dfsrapi.dll," &_
                "dfsrclus.dll," &_
                "dfsrdiag.exe," &_
                "dfsres.dll," &_
                "dfsrhelper.dll," &_
                "dfsrmig.exe," &_
                "dfsrress.dll," &_
                "drivers\dfsrro.sys," &_
                "dfsrs.exe," &_
                "netlogon.dll," &_
                "drivers\ntfs.sys," &_
                "wbem\repdrvfs.dll," &_
                "rpcrt4.dll," &_
                "drivers\tcpip.sys"
                
strVersionWarning = "NOTE:  The version string for Dfsmgmt.dll, Dfsobjectmodel.dll, and Dfsradmin.exe does not contain the RTM/GDR information. " &_
                    "This does not indicate a problem with those files. " & vbCrLf & vbCrLf &_
                    "Dfsmgmt.dll and Dfsobjectodel.dll will only be present on Windows Server 2003 R2. " &_
                    "Those files will not be present on Windows Server 2008 or Windows Server 2008 R2."

Set objRegExp = New RegExp
Set colNamedArguments = WScript.Arguments.Named
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objShell = WScript.CreateObject("WScript.Shell")
Set objNetwork = WScript.CreateObject("WScript.Network")
Set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate,(Security,Backup)}!\\" & strComputer & "\root\cimv2")

If InStr(1, UCase(Wscript.FullName), "CSCRIPT.EXE", vbTextCompare) = 0 Then
    dbgPrint "This script can only be executed by Cscript.exe." & vbCRLF & vbCRLF &_
                 "You can either:" & vbCRLF & vbCRLF & _
                 "1. Set Cscript.exe as the default (Run CScript //h:cscript), or" & vbCRLF & _
                 "2. Run Cscript.exe directly i.e. " & Chr(34) & "cscript " & Wscript.ScriptName & Chr(34), TO_SCREEN
    Wscript.Quit(-1)
End If

If colNamedArguments.Exists("?") Then
    ShowUsage
End If
If colNamedArguments.Exists("MSDT") Then
    blnMSDT = True
    dbgPrint "blnMSDT = " & blnMSDT, TO_FILE
    dbgPrint "Checking for files named DfsrInfo_Some or DfsrInfo_Minimal to determine what data to collect.", TO_FILE
    If objFSO.FileExists("..\DfsrInfo_Some") Then
        dbgPrint "Found ..\DfsrInfo_Some file. Skipping health reports.", TO_FILE
        blnNoReports = True
        dbgPrint "blnNoReports = " & blnNoReports, TO_FILE
    ElseIf objFSO.FileExists("..\DfsrInfo_Minimal") Then
        dbgPrint "Found ..\DfsrInfo_Minimal file. Skipping debug logs, health reports, and database GUID collection.", TO_FILE
        blnNoDebugLogs = True
        dbgPrint "blnNoDebugLogs = " & blnNoDebugLogs, TO_FILE
        blnNoDBGUIDs = True
        dbgPrint "blnNoDBGUIDs = " & blnNoDBGUIDs, TO_FILE
        blnNoReports = True
        dbgPrint "blnNoReports = " & blnNoReports, TO_FILE
    Else 
        dbgPrint "Did not find a file named DfsrInfo_Some or DfsrInfo_Minimal so proceeding with full data collection.", TO_FILE
    End If
End If

dbgPrint "Checking OS version", TO_FILE
dbgPrint "Select BuildNumber,Caption,Version,ServicePackMajorVersion from Win32_OperatingSystem", TO_FILE
Set colOperatingSystems = objWMIService.ExecQuery("Select BuildNumber,Caption,Version,ServicePackMajorVersion from Win32_OperatingSystem")
CheckForError
For Each objOperatingSystem in colOperatingSystems
    strBuildNumber = objOperatingSystem.BuildNumber    
    strServicePack = objOperatingSystem.ServicePackMajorVersion
    strOSVersion = objOperatingSystem.Version
    strCaption = objOperatingSystem.Caption
Next
dbgPrint "Caption (strCaption) =                     " & strCaption, TO_FILE 
dbgPrint "ServicePackMajorVersion (strServicePack) = " & strServicePack, TO_FILE 
dbgPrint "Version (strOSVersion) =                   " & strOSVersion, TO_FILE 
dbgPrint "BuildNumber (strBuildNumber) =             " & strBuildNumber, TO_FILE

If strBuildNumber = "6001" Or "6002" Or "7600" Then
    dbgPrint "Checking if this is a Core Install", TO_FILE
    dbgPrint "Select OperatingSystemSKU from Win32_OperatingSystem", TO_FILE
    Set colOperatingSystems = objWMIService.ExecQuery("Select OperatingSystemSKU from Win32_OperatingSystem")
    CheckForError
    For Each objOperatingSystem in colOperatingSystems
        strSKU = objOperatingSystem.OperatingSystemSKU
    Next
    If strSKU = 12 Or strSKU = 13 Or strSKU = 14 Or strSKU = 29 Or strSKU = 39 Or strSKU = 40 Or strSKU = 41 Then
        blnCoreInstall = True
    Else
        blnCoreInstall = False
    End If
    dbgPrint "blnCoreInstall = " & blnCoreInstall, TO_FILE
End If

If colNamedArguments.Exists("hotfixes") Then
    blnCheckHotfixesOnly = True
    dbgPrint "blnCheckHotfixesOnly = " & blnCheckHotfixesOnly, TO_FILE
    CheckHotfixes
    Wscript.Quit
End If

dbgPrint "Checking location of Windows directory", TO_FILE
strWinDir = objShell.ExpandEnvironmentStrings("%WinDir%")
strSystemDrive = objShell.ExpandEnvironmentStrings("%SystemDrive%")
dbgPrint "strWinDir = " & strWinDir, TO_FILE

dbgPrint "Checking if DFSR service is installed", TO_FILE
dbgPrint "Select Name,State,StartName from Win32_Service", TO_FILE
Set colListOfServices = objWMIService.ExecQuery("Select Name,State,StartName from Win32_Service")
CheckForError
For Each objService in colListOfServices
    If UCase(objService.Name) = "DFSR" Then
        blnDfsrInstalled = True
        dbgPrint "DFSR service is installed", TO_FILE
        strDfsrServiceStatus = objService.State
        strDfsrServiceAccount = UCase(objService.StartName)
        dbgPrint "DFSR service account = " & strDfsrServiceAccount, TO_FILE
        If strDfsrServiceAccount <> "LOCALSYSTEM" Then
            dbgPrint "[ERROR] DFSR service account is not LOCALSYSTEM. This is an unsupported configuration.", TO_FILE
        End If
        dbgPrint "Checking if Dfrsdiag.exe exists in " & strWinDir & "\System32\Dfsrdiag.exe", TO_FILE
		If Not objFSO.FileExists(strWinDir & "\System32\Dfsrdiag.exe") Then
			dbgPrint "[ERROR] DFSR is installed but Dfsrdiag.exe was not found.", TO_SCREEN + TO_FILE
			Wscript.Quit(2)
        End If
        dbgPrint "Found Dfrsdiag.exe", TO_FILE
        dbgPrint "Checking if Dfsradmin.exe exists in " & strWinDir & "\System32\Dfsradmin.exe or in " & strWinDir & "\Dfsradmin.exe", TO_FILE
		If Not objFSO.FileExists(strWinDir & "\System32\Dfsradmin.exe") Then
            If Not objFSO.FileExists(strWinDir & "\Dfsradmin.exe") Then
                blnDfsradmin = False
                dbgPrint "blnDfsradmin = " & blnDfsradmin, TO_FILE
                dbgPrint "[ERROR] DFSR is installed but Dfsradmin.exe was not found. Dfsradmin commands will not be run.", TO_FILE
    		Else
    		    blnDfsradmin = True
                dbgPrint "Dfsradmin.exe found at " & strWinDir & "\Dfsradmin.exe", TO_FILE
    		    dbgPrint "blnDfsradmin = " & blnDfsradmin, TO_FILE
    		End If
        Else
            blnDfsradmin = True
            dbgPrint "Dfsradmin.exe found at " & strWinDir & "\System32\Dfsradmin.exe", TO_FILE
            dbgPrint "blnDfsradmin = " & blnDfsradmin, TO_FILE
        End If
        dbgPrint "Checking if this is a Core install of Windows Server 2008", TO_FILE
        dbgPrint "blnCoreInstall = " & blnCoreInstall & " strBuildNumber = " & strBuildNumber, TO_FILE
        If blnCoreInstall And (strBuildNumber = "6001" Or "6002") Then
            dbgPrint "This is a Core install of Windows Server 2008.", TO_FILE
            blnDfsradmin = False
            dbgPrint "[ERROR] Dfsradmin will not run on Core installs of Windows Server 2008. Dfsradmin commands will not be run.", TO_FILE     
        Else
            dbgPrint "This is not a Core install of Windows Server 2008.", TO_FILE
        End If
        dbgPrint "Checking if this is a Core install of Windows Server 2008 R2.", TO_FILE
        dbgPrint "blnCoreInstall = " & blnCoreInstall & " strBuildNumber = " & strBuildNumber, TO_FILE
        If blnCoreInstall And strBuildNumber = "7600" Then
            dbgPrint "SELECT Name,InstallState FROM Win32_OptionalFeature", TO_FILE
        	Set colOptionalFeatures = objWMIService.ExecQuery("SELECT Name,InstallState FROM Win32_OptionalFeature", "WQL", wbemFlagReturnImmediately + wbemFlagForwardOnly)
        	CheckForError
            dbgPrint "Checking for NetFx2-ServerCore optional feature. Dfsradmin will not run without it.", TO_FILE
            
            ' If NetFx2-ServerCore was never installed or is currently installed, this check will be accurate.
            ' If it was installed and later removed, it may reflect that it is still installed if a reboot was not done.
            
            blnNetFx2ServerCore = False                    
            For Each objFeature In colOptionalFeatures
                If objFeature.Name = "NetFx2-ServerCore" And objFeature.InstallState = "1" Then
                    blnNetFx2ServerCore = True
                End If
            Next
            dbgPrint "blnNetFx2ServerCore = " & blnNetFx2ServerCore, TO_FILE
            If Not blnNetFx2ServerCore Then
                dbgPrint "[ERROR] NetFx2-ServerCore is not installed so Dfsradmin commands will not be run.", TO_FILE
                blnDfsradmin = False
                dbgPrint "blnDfsradmin = " & blnDfsradmin, TO_FILE
            End If
        Else 
            dbgPrint "This is not a Core install of Windows Server 2008 R2.", TO_FILE
        End If
    End If
Next
If blnDfsrInstalled = False Then
    dbgPrint "[ERROR] DFS Replication is not installed. This script must be run on a server where DFS Replication is installed.", TO_SCREEN + TO_FILE
    Wscript.Quit(-1)    
End If
If UCase(strDfsrServiceStatus) <> "RUNNING" Then
    dbgPrint "[ERROR] The DFS Replication service is not running. Please start the service and run the script again.", TO_SCREEN + TO_FILE
    Wscript.Quit(-1)
Else 
    dbgPrint "DFSR service is running", TO_FILE
End If

dtmNow = Month(Now) & Day(Now) & Year(Now) & Hour(Now) & Minute(Now) & Second(Now)
dtmStartDate = Now - 3

dbgPrint "Checking computer name", TO_FILE
strComputerName = objNetwork.ComputerName
CheckForError
dbgPrint "strComputerName = " & strComputerName, TO_FILE

dbgPrint "Determining output folder location", TO_FILE
dbgPrint "blnMSDT = " & blnMSDT, TO_FILE
If blnMSDT Then
    dbgPrint "Using current directory for output directory", TO_FILE
    dbgPrint "Current directory = " & objShell.CurrentDirectory, TO_FILE
    strTempFolder = objShell.CurrentDirectory & "\"
Else
    dbgPrint "Using TEMP directory for output directory", TO_FILE
    dbgPrint "TEMP = " & objShell.ExpandEnvironmentStrings("%TEMP%"), TO_FILE
    strTempFolder = objShell.ExpandEnvironmentStrings("%TEMP%") & "\DfsrInfo_" & dtmNow & "\"
End If
dbgPrint "strTempFolder = " & strTempFolder, TO_FILE


dbgPrint "Checking for at least 200 MB free on drive where temp folder resides", TO_FILE
strTempDriveName = Left(strTempFolder, 2)
Set objTempDrive = objWMIService.Get("Win32_LogicalDisk='" & strTempDriveName & "'")
CheckForError
If objTempDrive.FreeSpace < 209715200 Then
    dbgPrint vbCrLf & "[ERROR] Drive " & strTempDriveName & " has less than 200 mb free space. Please free up additional disk space.", TO_FILE + TO_SCREEN
    Wscript.Quit(-1)    
End If
dbgPrint "Drive " & strTempDriveName & " has " & Int(objTempDrive.FreeSpace / CONVERSION_FACTOR) & " GB free", TO_FILE

If blnMSDT = False Then
    dbgPrint "Creating output folder: " & strTempFolder, TO_FILE
    objFSO.CreateFolder strTempFolder
    CheckForError
    strCabFolder = strTempFolder & "Cab\"
    dbgPrint "strCabFolder = " & strTempFolder & "Cab\", TO_FILE
End If

dbgPrint "Connecting to \root\microsoftDfs WMI namespace", TO_FILE
Set objWMIDfsService = GetObject("winmgmts:\\" & strComputer & "\root\microsoftDfs")
CheckForError

dbgPrint "Found " & Wscript.Arguments.Count & " command-line arguments", TO_FILE
If WScript.Arguments.Count > 0 Then
    CheckArgs
Else
    CollectData
End If

Sub CheckArgs
    If colNamedArguments.Exists("getdbguids") Then
        If colNamedArguments.Exists("rgname") Then
            GetDBGUIDs colNamedArguments.Item("rgname"),vbFalse
            Wscript.Quit
        Else
            ShowUsage
        End If
    End If   
    If colNamedArguments.Exists("Q") Or colNamedArguments.Exists("QUICK") Then
        blnNoLogFileCheck = True
        blnNoReports = True
        blnNoMSINFO32 = True
        blnNoDBGUIDs = True
        blnNoEvents = True
        blnNoDebugLogs = True
        CollectData
    End If
    If colNamedArguments.Exists("nodebuglogs") Then
        blnNoDebugLogs = True
    End If
    If colNamedArguments.Exists("nologfilecheck") Or blnMSDT Then
        blnNoLogFileCheck = True
    End If
    If colNamedArguments.Exists("noevents") Or blnMSDT Then
        blnNoEvents = True
    End If
    If colNamedArguments.Exists("noreports") Then
        blnNoReports = True
    End If
    If colNamedArguments.Exists("nomsinfo32") Or blnMSDT Then
        blnNoMSINFO32 = True
    End If
    If colNamedArguments.Exists("nodbguids") Then
        blnNoDBGUIDs = True
    End If 
    If blnNoLogFileCheck + blnNoReports + blnNoMSINFO32 + blnNoDBGUIDs + blnMSDT <> 0 Then
        CollectData
    End If
    If colNamedArguments.Exists("enableaudit") Then
        ConfigureAuditing(True)
        Wscript.Quit
    End If 
    If colNamedArguments.Exists("disableaudit") Then
        ConfigureAuditing(False)
        Wscript.Quit
    End If 
    If colNamedArguments.Exists("EnableDfsmgmtTracing") Then
        blnEnableDfsmgmtTracing = UCase(colNamedArguments.Item("EnableDfsmgmtTracing"))
        If blnEnableDfsmgmtTracing <> "TRUE" And blnEnableDfsmgmtTracing <> "FALSE" Then
            Wscript.Echo "Please specify either True or False for EnableVerboseEventLogging."
            Wscript.Quit
        End If
        If (objFSO.FileExists(strWinDir & "\System32\dfsmgmt.dll.config")) = False Then
            Wscript.Echo "Could not find " & strWinDir & "\System32\dfsmgmt.dll.config."
            Wscript.Quit
        End If
        Set objTextFile = objFSO.OpenTextFile(strWinDir & "\System32\dfsmgmt.dll.config",FOR_READING) 
        strTextFile = objTextFile.ReadAll
        objTextFile.Close
        If blnEnableDfsmgmtTracing = "TRUE" Then
            strTextFile = replace(strTextFile,"DfsTraceListenerEnabled" & Chr(34) & " value=" & Chr(34) & "0","DfsTraceListenerEnabled" & Chr(34) & " value=" & Chr(34) & "1") 
            strTextFile = replace(strTextFile,"DfsFrsTracing" & Chr(34) & " value=" & Chr(34) & "0","DfsFrsTracing" & Chr(34) & " value=" & Chr(34) & "65535") 
            strTextFile = replace(strTextFile,"DfsFrsSnapIn" & Chr(34) & " value=" & Chr(34) & "0","DfsFrsSnapIn" & Chr(34) & " value=" & Chr(34) & "65535") 
            Set objTextFile = objFSO.openTextFile(strWinDir & "\System32\dfsmgmt.dll.config",FOR_WRITING)
            objTextFile.Write strTextFile
            objTextFile.Close
            Wscript.Echo "DFS Manangement trace logging is now enabled." & vbCrLf & vbCrLf &_
                         "Please close and reopen the DFS Management MMC for the change to take effect." & vbCrLf & vbCrLf &_
                         "Information will be logged to " & strWinDir & "\Debug\DfsMgmt\DfsMgmt.current.log."
        Else
            strTextFile = replace(strTextFile,"DfsTraceListenerEnabled" & Chr(34) & " value=" & Chr(34) & "1","DfsTraceListenerEnabled" & Chr(34) & " value=" & Chr(34) & "0") 
            strTextFile = replace(strTextFile,"DfsFrsTracing" & Chr(34) & " value=" & Chr(34) & "65535","DfsFrsTracing" & Chr(34) & " value=" & Chr(34) & "0") 
            strTextFile = replace(strTextFile,"DfsFrsSnapIn" & Chr(34) & " value=" & Chr(34) & "65535","DfsFrsSnapIn" & Chr(34) & " value=" & Chr(34) & "0")
            Set objTextFile = objFSO.openTextFile(strWinDir & "\System32\dfsmgmt.dll.config",FOR_WRITING)
            objTextFile.Write strTextFile
            objTextFile.Close
            Wscript.Echo "DFS Management trace logging is now disabled."
        End If
        Wscript.Quit
    End If
    
    If colNamedArguments.Exists("EnableVerboseEventLogging") Then
        blnEnableVerboseEventLogging = UCase(colNamedArguments.Item("EnableVerboseEventLogging"))
        If blnEnableVerboseEventLogging <> "TRUE" And blnEnableVerboseEventLogging <> "FALSE" Then
            Wscript.Echo "Please specify either True or False for EnableVerboseEventLogging."
            Wscript.Quit
        End If
        strKeyPath = "SYSTEM\CurrentControlSet\Services\Dfsr\Parameters"
        strValueName = "Enable Verbose Event Logging" 
        dwValue = 1
        If blnEnableVerboseEventLogging = "TRUE" Then
            errReturn = objShell.RegWrite("HKLM\SYSTEM\CurrentControlSet\Services\Dfsr\Parameters\Enable Verbose Event Logging", 1, "REG_DWORD")
            Wscript.Echo errReturn
            Wscript.Echo "Verbose event logging now enabled."
        Else
            objShell.RegDelete "HKLM\SYSTEM\CurrentControlSet\Services\Dfsr\Parameters\Enable Verbose Event Logging"
            Wscript.Echo "Verbose event logging now disabled."
        End If
        Wscript.Quit
    End If
    
    dbgPrint "SELECT * FROM DfsrMachineConfig", TO_FILE
    Set colItems = objWMIDfsService.ExecQuery("SELECT * FROM DfsrMachineConfig")
    If colNamedArguments.Exists("ConflictHighWatermarkPercent") Then
        intNewConflictHighWatermarkPercent = CLng(colNamedArguments.Item("ConflictHighWatermarkPercent"))
        If intNewConflictHighWatermarkPercent < 80 Or intNewConflictHighWatermarkPercent > 100 Then
            Wscript.Echo "Please specify a value between 80 and 100 for ConflictHighWatermarkPercent."
            Wscript.Quit
        End If
        For Each objItem in colItems
            intOldConflictHighWatermarkPercent = objItem.ConflictHighWatermarkPercent
            blnConfigChange = True
        Next
    End If
    If colNamedArguments.Exists("ConflictLowWatermarkPercent") Then
        intNewConflictLowWatermarkPercent = CLng(colNamedArguments.Item("ConflictLowWatermarkPercent"))
        If intNewConflictLowWatermarkPercent < 10 Or intNewConflictLowWatermarkPercent > 80 Then
            Wscript.Echo "Please specify a value between 10 and 80 for ConflictLowWatermarkPercent."
            Wscript.Quit
        End If
        For Each objItem in colItems
            intOldConflictLowWatermarkPercent = objItem.ConflictLowWatermarkPercent
            blnConfigChange = True
        Next
    End If
    If colNamedArguments.Exists("DebugLogFilePath") Then
        strNewDebugLogFilePath = UCase(colNamedArguments.Item("DebugLogFilePath"))
        If Not objFSO.FolderExists(strNewDebugLogFilePath) Then
            Wscript.Echo strNewDebugLogFilePath & " does not exist. Would you like to create it? (Y/N)"
            Do While Not WScript.StdIn.AtEndOfLine
                Input = Input & WScript.StdIn.Read(1)
            Loop
            If UCase(Input) = "Y" Then
                objFSO.CreateFolder(strNewDebugLogFilePath)
                If Not objFSO.FolderExists(strNewDebugLogFilePath) Then
                    Wscript.Echo "Unable to create folder " & strNewDebugLogFilePath
                    Wscript.Quit
                End If
            End If
        End If
        For Each objItem in colItems
            strOldDebugLogFilePath = objItem.DebugLogFilePath
            blnConfigChange = True
        Next
    End If
    If colNamedArguments.Exists("DebugLogSeverity") Then
        intNewDebugLogSeverity = CLng(colNamedArguments.Item("DebugLogSeverity"))
        If intNewDebugLogSeverity < 1 Or intNewDebugLogSeverity > 5 Then
            Wscript.Echo "Please specify a value between 1 and 5 for DebugLogSeverity."
            Wscript.Quit
        End If
        For Each objItem in colItems
            intOldDebugLogSeverity = objItem.DebugLogSeverity
            blnConfigChange = True
        Next
    End If
    If colNamedArguments.Exists("Description") Then
        strNewDescription = colNamedArguments.Item("Description")
        For Each objItem in colItems
            strNewDescription = objItem.Description
            blnConfigChange = True
        Next
    End If
    If colNamedArguments.Exists("DsPollingIntervalInMin") Then
        intNewDsPollingIntervalInMin = CLng(colNamedArguments.Item("DsPollingIntervalInMin"))
        If intNewDsPollingIntervalInMin < 1 Then
            Wscript.Echo "Please specify a value greater than 0 for DsPollingIntervalInMin."
            Wscript.Quit
        End If
        For Each objItem in colItems
            intOldDsPollingIntervalInMin = objItem.DsPollingIntervalInMin
            blnConfigChange = True
        Next
    End If
    If colNamedArguments.Exists("EnableDebugLog") Then
        blnNewEnableDebugLog = UCase(colNamedArguments.Item("EnableDebugLog"))
        If blnNewEnableDebugLog = "TRUE" Or blnNewEnableDebugLog = "FALSE" Then
            For Each objItem in colItems
                blnOldEnableDebugLog = UCase(objItem.EnableDebugLog)
                blnConfigChange = True
            Next
        Else
            Wscript.Echo "Please specify either True or False for EnableDebugLog."
            Wscript.Quit
        End If
    End If
    If colNamedArguments.Exists("EnableLightDsPolling") Then
        blnNewEnableLightDsPolling = UCase(colNamedArguments.Item("EnableLightDsPolling"))
        If blnNewEnableLightDsPolling = "TRUE" Or blnNewEnableLightDsPolling = "FALSE" Then
            For Each objItem in colItems
                blnOldEnableLightDsPolling = UCase(objItem.EnableLightDsPolling)
                blnConfigChange = True
            Next
        Else
            Wscript.Echo "Please specify either True or False for EnableLightDsPolling."
            Wscript.Quit
        End If
    End If
    If colNamedArguments.Exists("MaxDebugLogFiles") Then
        intNewMaxDebugLogFiles = CLng(colNamedArguments.Item("MaxDebugLogFiles"))
        If intNewMaxDebugLogFiles < 1 Then
            Wscript.Echo "Please specify a value greater than 0 for MaxDebugLogFiles."
            Wscript.Quit
        End If
        For Each objItem in colItems
            intOldMaxDebugLogFiles = objItem.MaxDebugLogFiles
            blnConfigChange = True
        Next
    End If
    If colNamedArguments.Exists("MaxDebugLogMessages") Then
        intNewMaxDebugLogMessages = CLng(colNamedArguments.Item("MaxDebugLogMessages"))
        If intNewMaxDebugLogMessages < 1000 Then
            Wscript.Echo "Please specify a value of 1000 or greater for MaxDebugLogMessages."
            Wscript.Quit
        End If
        For Each objItem in colItems
            intOldMaxDebugLogMessages = objItem.MaxDebugLogMessages
            blnConfigChange = True
        Next
    End If
    If colNamedArguments.Exists("RpcPortAssignment") Then
        intNewRpcPortAssignment = CLng(colNamedArguments.Item("RpcPortAssignment"))
        If intNewRpcPortAssignment < 0 Or intNewRpcPortAssignment > 65535 Then
            Wscript.Echo "Please specify a value between 0 and 65535 for RpcPortAssignment. Recommended values are 49152-65535."
            Wscript.Quit
        End If
        For Each objItem in colItems
            intOldRpcPortAssignment = objItem.RpcPortAssignment
            blnConfigChange = True
        Next
    End If
    If colNamedArguments.Exists("StagingHighWatermarkPercent") Then
        intNewStagingHighWatermarkPercent = CLng(colNamedArguments.Item("StagingHighWatermarkPercent"))
        If intNewStagingHighWatermarkPercent < 80 Or intNewStagingHighWatermarkPercent > 100 Then
            Wscript.Echo "Please specify a value between 80 and 100 for StagingHighWatermarkPercent."
            Wscript.Quit
        End If
        For Each objItem in colItems
            intOldStagingHighWatermarkPercent = objItem.StagingHighWatermarkPercent
            blnConfigChange = True
        Next
    End If
    If colNamedArguments.Exists("StagingLowWatermarkPercent") Then
        intNewStagingLowWatermarkPercent = CLng(colNamedArguments.Item("StagingLowWatermarkPercent"))
        If intNewStagingLowWatermarkPercent < 10 Or intNewStagingLowWatermarkPercent > 80 Then
            Wscript.Echo "Please specify a value between 10 and 80 for StagingLowWatermarkPercent."
            Wscript.Quit
        End If
        For Each objItem in colItems
            intOldStagingLowWatermarkPercent = objItem.StagingLowWatermarkPercent
            blnConfigChange = True
        Next
    End If
    
    If blnConfigChange Then
    	For Each objItem In colItems
            If intNewConflictHighWatermarkPercent = intOldConflictHighWatermarkPercent Then
                WScript.Echo "   ConflictHighWatermarkPercent   : " & objItem.ConflictHighWatermarkPercent
            Else
                objItem.ConflictHighWatermarkPercent = intNewConflictHighWatermarkPercent
                WScript.Echo "   ConflictHighWatermarkPercent   : " & intNewConflictHighWatermarkPercent & " (was " & intOldConflictHighWatermarkPercent & ")"
            End If
            If intNewConflictLowWatermarkPercent = intOldConflictLowWatermarkPercent Then
                WScript.Echo "   ConflictLowWatermarkPercent    : " & objItem.ConflictLowWatermarkPercent
            Else
                objItem.ConflictLowWatermarkPercent = intNewConflictLowWatermarkPercent
                WScript.Echo "   ConflictLowWatermarkPercent    : " & intNewConflictLowWatermarkPercent & " (was " & intOldConflictLowWatermarkPercent & ")"
            End If
            If strNewDebugLogFilePath = strOldDebugLogFilePath Then
                WScript.Echo "   DebugLogFilePath               : " & objItem.DebugLogFilePath
            Else
                objItem.DebugLogFilePath = strNewDebugLogFilePath
                WScript.Echo "   DebugLogFilePath               : " & strNewDebugLogFilePath & " (was " & strOldDebugLogFilePath & ")"
            End If
            If intNewDebugLogSeverity = intOldDebugLogSeverity Then
                WScript.Echo "   DebugLogSeverity               : " & objItem.DebugLogSeverity
            Else
                objItem.DebugLogSeverity = intNewDebugLogSeverity
                WScript.Echo "   DebugLogSeverity               : " & intNewDebugLogSeverity & " (was " & intOldDebugLogSeverity & ")"
            End If
            If strNewDescription = strOldDescription Then
                WScript.Echo "   Description                    : " & objItem.Description
            Else
                objItem.Description = strNewDescription
                WScript.Echo "   Description                    : " & strNewDescription & " (was " & strOldDescription & ")"
            End If
            If intNewDsPollingIntervalInMin = intOldDsPollingIntervalInMin Then
                WScript.Echo "   DsPollingIntervalInMin         : " & objItem.DsPollingIntervalInMin
            Else
                objItem.DsPollingIntervalInMin = intNewDsPollingIntervalInMin
                WScript.Echo "   DsPollingIntervalInMin         : " & intNewDsPollingIntervalInMin & " (was " & intOldDsPollingIntervalInMin & ")"
            End If
            If blnNewEnableDebugLog = blnOldEnableDebugLog Then
                WScript.Echo "   EnableDebugLog                 : " & objItem.EnableDebugLog
            Else
                objItem.EnableDebugLog = blnNewEnableDebugLog
                WScript.Echo "   EnableDebugLog                 : " & blnNewEnableDebugLog & " (was " & blnOldEnableDebugLog & ")"
            End If        
            If blnNewEnableLightDsPolling = blnOldEnableLightDsPolling Then
                WScript.Echo "   EnableLightDsPolling           : " & objItem.EnableLightDsPolling
            Else
                objItem.EnableLightDsPolling = blnNewEnableLightDsPolling
                WScript.Echo "   EnableLightDsPolling           : " & blnNewEnableLightDsPolling & " (was " & blnOldEnableLightDsPolling & ")"
            End If        
            If intNewMaxDebugLogFiles = intOldMaxDebugLogFiles Then
                WScript.Echo "   MaxDebugLogFiles               : " & objItem.MaxDebugLogFiles
            Else
                objItem.MaxDebugLogFiles = intNewMaxDebugLogFiles
                WScript.Echo "   MaxDebugLogFiles               : " & intNewMaxDebugLogFiles & " (was " & intOldMaxDebugLogFiles & ")"
            End If
            If intNewMaxDebugLogMessages = intOldMaxDebugLogMessages Then
                WScript.Echo "   MaxDebugLogMessages            : " & objItem.MaxDebugLogMessages
            Else
                objItem.MaxDebugLogMessages = intNewMaxDebugLogMessages
                WScript.Echo "   MaxDebugLogMessages            : " & intNewMaxDebugLogMessages & " (was " & intOldMaxDebugLogMessages & ")"
            End If        
            If intNewRpcPortAssignment = intOldRpcPortAssignment Then
                WScript.Echo "   RpcPortAssignment              : " & objItem.RpcPortAssignment
            Else
                objItem.RpcPortAssignment = intNewRpcPortAssignment
                WScript.Echo "   RpcPortAssignment              : " & intNewRpcPortAssignment & " (was " & intOldRpcPortAssignment & ")"
            End If
            If intNewStagingHighWatermarkPercent = intOldStagingHighWatermarkPercent Then
                WScript.Echo "   StagingHighWatermarkPercent    : " & objItem.StagingHighWatermarkPercent
            Else
                objItem.StagingHighWatermarkPercent = intNewStagingHighWatermarkPercent
                WScript.Echo "   StagingHighWatermarkPercent    : " & intNewStagingHighWatermarkPercent & " (was " & intOldStagingHighWatermarkPercent & ")"
            End If
            If intNewStagingLowWatermarkPercent = intOldStagingLowWatermarkPercent Then
                WScript.Echo "   StagingLowWatermarkPercent     : " & objItem.StagingLowWatermarkPercent
            Else
                objItem.StagingLowWatermarkPercent = intNewStagingLowWatermarkPercent
                WScript.Echo "   StagingLowWatermarkPercent     : " & intNewStagingLowWatermarkPercent & " (was " & intOldStagingLowWatermarkPercent & ")"
            End If
            objItem.Put_
        Next
	Else
	  	dbgPrint "[ERROR] Unrecognized command. Run cscript dfsrinfo.vbs /? to show usage syntax.", TO_SCREEN
  	End If
End Sub

Sub CollectData
    On Error Resume Next
    GetClusterInfo
    dbgPrint "Collecting data about each replication group local machine is a member of", TO_FILE
    If blnNoLogFileCheck <> True Then
        dbgPrint "SELECT * FROM DfsrMachineConfig", TO_FILE
        Set colItems = objWMIDfsService.ExecQuery("SELECT * FROM DfsrMachineConfig")
        CheckForError
        For Each objItem in colItems
            currentMaxDebugLogFiles = objItem.MaxDebugLogFiles
            dbgPrint "currentMaxDebugLogFiles = " & currentMaxDebugLogFiles, TO_FILE
            currentDebugLogFilePath = objItem.DebugLogFilePath
            dbgPrint "currentDebugLogFilePath = " & currentDebugLogFilePath, TO_FILE
            If currentMaxDebugLogFiles < 1000 Then
                dbgPrint "Checking free space on drive where DFSR debug logs reside", TO_FILE
                Set objDebugLogFilesDrive = objWMIService.Get("Win32_LogicalDisk='" & Left(currentDebugLogFilePath,2) & "'")
                CheckForError
                freeGigabytes = Int(objDebugLogFilesDrive.FreeSpace / CONVERSION_FACTOR)
                dbgPrint freeGigabytes & " GB free on " & Left(currentDebugLogFilePath,2), TO_FILE
                strMsgBoxTxt1 = "Current settings: " & vbCrLf &_
                       vbCrLf & "MaxDebugLogFiles" & vbTab & currentMaxDebugLogFiles &_
                       vbCrLf & "DebugLogFilePath" & vbTab & currentDebugLogFilePath &_
                       vbCrLf & "Free space on " & Left(currentDebugLogFilePath,2) & vbTab & freeGigabytes & " GB" & vbCrLf &_ 
                       vbCrLf & "Because the DFSR debug logs can wrap quickly on a busy server, " & vbCrLf &_
                       "it is recommended to increase the number of logs to 1000." & vbCrLf &_
                       "This would consume approximately 1 GB of disk space (1 MB per log file). " & vbCrLf &_
                       "The logs currently reside on drive " & Left(currentDebugLogFilePath,2) & " which has " & freeGigabytes & " GB free." & vbCrLf &_
                       vbCrLf & "Increase the number of debug logs to 1000?"
                errReturn = MsgBox(strMsgBoxTxt1, vbYesNo, "DfsrInfo")
                If errReturn = vbYes Then
                    dbgPrint "Setting MaxDebugLogFiles to " & RECOMMENDED_MAXDEBUGLOGFILES, TO_FILE
                    objItem.MaxDebugLogFiles = RECOMMENDED_MAXDEBUGLOGFILES
                    objItem.Put_
                    CheckForError
                    strMsgBoxTxt2 = "MaxDebugLogFiles successfully changed from " & currentMaxDebugLogFiles & " to 1000." & vbCrLf &_
                                    vbCrLf &"If you also want to change the debug log file path, rerun this script -" & vbCrLf &_
                                    vbCrLf & "Cscript.exe DfsrInfo.vbs /DebugLogFilePath:<new location>" & vbCrLf &_
                                    vbCrLf & "Begin data collection?"
                    errReturn = MsgBox(strMsgBoxTxt2, vbYesNo, "DfsrInfo")
                    If errReturn = vbNo Then
                        Wscript.Quit
                    End If
                Else
                    strMsgBoxTxt3 = "No change was made. Number of debug logs remains " & currentMaxDebugLogFiles & vbCrLf &_
                                    vbCrLf & "Begin data collection?"
                    errReturn = MsgBox(strMsgBoxTxt3, vbYesNo, "DfsrInfo")
                    If errReturn = vbNo Then
                        Wscript.Quit
                    End If
                End If
            End If
        Next
    End If
    dbgPrint "Creating " & strTempFolder & strComputerName & "_DFSR_Info.txt", TO_FILE     
    strDFSRInfoFile = strTempFolder & strComputerName & "_DFSR_Info.txt"
    CheckForError
    dbgPrint "SELECT ReplicationGroupName,ReplicationGroupDN FROM DfsrReplicationGroupConfig", TO_FILE
    Set colItems = objWMIDfsService.ExecQuery("SELECT ReplicationGroupName,ReplicationGroupDN FROM DfsrReplicationGroupConfig", "WQL",wbemFlagReturnImmediately + wbemFlagForwardOnly)
    CheckForError
    For Each objItem In colItems
        strDomain = ""
        strRGDN = UCase(objItem.ReplicationGroupDN)
        dbgPrint "strRGDN = " & strRGDN, TO_FILE
        arrDN = Split(strRGDN, "DC=", -1, 1)
        For i = 1 to UBound(arrDN)
            strDomain = strDomain & Replace(arrDN(i), ",", ".")
        Next       
        strRGName = objItem.ReplicationGroupName
        objRegExp.Pattern = "\\"
        objRegExp.Global = True
        strParsedRGName = objRegExp.Replace(strRGName, "_")
        objRegExp.Pattern = "\."
        objRegExp.Global = True
        strParsedRGName = objRegExp.Replace(strParsedRGName, "_")
        objRegExp.Pattern = " "
        objRegExp.Global = True
        strParsedRGName = objRegExp.Replace(strParsedRGName, "_")
        objRegExp.Pattern = "\*"
        objRegExp.Global = True
        strParsedRGName = objRegExp.Replace(strParsedRGName, "_")
        objRegExp.Pattern = "\+"
        objRegExp.Global = True
        strParsedRGName = objRegExp.Replace(strParsedRGName, "_")
        objRegExp.Pattern = "\^"
        objRegExp.Global = True
        strParsedRGName = objRegExp.Replace(strParsedRGName, "_")
        objRegExp.Pattern = "\&"
        objRegExp.Global = True
        strParsedRGName = objRegExp.Replace(strParsedRGName, "_")

        If blnNoReports Or blnDfsradmin = False Then
            dbgPrint "[SKIPPED] Health reports skipped because /noreports switch was used or Dfsradmin was not available.", TO_FILE
            arrRGCommands(0) = "cmd /d /c Echo Health report(s) not created because /noreports switch was used or Dfsradmin was not present. >> " & strDFSRInfoFile
        Else
            arrRGCommands(0) = "Dfsradmin Health New /RGName:" & Chr(34) & strRGName &  Chr(34) & " /RefMemName:" & strComputerName & " /RepName:" & strTempFolder & strComputerName & "_DFSR_" & strParsedRGName & "_HealthReport.html /domain:" & strDomain
        End If   
        arrRGCommands(1) = "cmd /d /c Echo. >> " & strDFSRInfoFile
        arrRGCommands(2) = "cmd /d /c Echo ================================================================= >> " & strDFSRInfoFile

        ' These commands only work if the RG is not the SYSVOL RG.

        If strRGName <> "Domain System Volume" And blnDfsradmin Then
            arrRGCommands(3) = "cmd /d /c Echo " & strRGName & " replication group schedule: >> " & strDFSRInfoFile
            arrRGCommands(4) = "cmd /d /c Echo ================================================================= >> " & strDFSRInfoFile
            arrRGCommands(5) = "cmd /d /c Echo. >> " & strDFSRInfoFile
            arrRGCommands(6) = "cmd /d /c Dfsradmin RG Export Schedule /RGName:"  & Chr(34) & strRGName & Chr(34) & " /File:" & strTempFolder & strComputerName & "_" & strParsedRGName & "_rgsched.txt /domain:" & strDomain
            arrRGCommands(7) = "cmd /d /c Type " & strTempFolder & strComputerName & "_" & strParsedRGName & "_rgsched.txt" & " >> " & strDFSRInfoFile
    	    arrRGCommands(8) = "cmd /d /c Echo. >> " & strDFSRInfoFile
            arrRGCommands(9) = "cmd /d /c Echo ================================================================= >> " & strDFSRInfoFile
            arrRGCommands(10) = "cmd /d /c Echo "  & Chr(34) & strRGName & Chr(34) & " connection information: >> " & strDFSRInfoFile
            arrRGCommands(11) = "cmd /d /c Echo ================================================================= >> " & strDFSRInfoFile
            arrRGCommands(12) = "cmd /d /c Echo. >> " & strDFSRInfoFile
            arrRGCommands(13) = "cmd /d /c Dfsradmin Conn List /RGName:"  & Chr(34) & strRGName & Chr(34) & " /Attr:All  /domain:" & strDomain & " >> " & strDFSRInfoFile
            arrRGCommands(14) = "cmd /d /c Echo. >> " & strDFSRInfoFile
            arrRGCommands(15) = "cmd /d /c Echo ================================================================= >> " & strDFSRInfoFile
	    Else
	        dbgPrint "[SKIPPED] Dfsradmin schedule and connection commands skipped because Dfsradmin is unavailable or this was the SYSVOL RG.", TO_FILE
	    End If
        
        If blnDfsradmin Then
            arrRGCommands(16) = "cmd /d /c Echo " & strRGName & " member information: >> " & strDFSRInfoFile
            arrRGCommands(17) = "cmd /d /c Echo ================================================================= >> " & strDFSRInfoFile
            arrRGCommands(18) = "cmd /d /c Echo. >> " & strDFSRInfoFile
            arrRGCommands(19) = "cmd /d /c Dfsradmin Mem List /Attr:All /RGName:"  & Chr(34) & strRGName & Chr(34) & " /domain:" & strDomain & " >> " & strDFSRInfoFile
            arrRGCommands(20) = "cmd /d /c Echo. >> " & strDFSRInfoFile
            arrRGCommands(21) = "cmd /d /c Echo ================================================================= >> " & strDFSRInfoFile
            arrRGCommands(22) = "cmd /d /c Echo " & strRGName & " membership information: >> " & strDFSRInfoFile
            arrRGCommands(23) = "cmd /d /c Echo ================================================================= >> " & strDFSRInfoFile
            arrRGCommands(24) = "cmd /d /c Echo. >> " & strDFSRInfoFile
            arrRGCommands(25) = "cmd /d /c Dfsradmin Membership List /Attr:All /RGName:"  & Chr(34) & strRGName & Chr(34) & " /domain:" & strDomain & " >> " & strDFSRInfoFile
            arrRGCommands(26) = "cmd /d /c Echo. >> " & strDFSRInfoFile
        Else
            dbgPrint "[SKIPPED] Dfsradmin member and membership commands skipped because Dfsradmin is unavailable.", TO_FILE
        End If

        ' This command only works if the replication group is not the SYSVOL replication group.

        If strRGName <> "Domain System Volume" And blnDfsradmin Then
            arrRGCommands(27) = "cmd /d /c Echo ================================================================= >> " & strDFSRInfoFile
            arrRGCommands(28) = "cmd /d /c Echo " & strRGName & " replicated folder information: >> " & strDFSRInfoFile
            arrRGCommands(29) = "cmd /d /c Echo ================================================================= >> " & strDFSRInfoFile
            arrRGCommands(30) = "cmd /d /c Echo. >> " & strDFSRInfoFile
	        arrRGCommands(31) = "cmd /d /c Dfsradmin RF List /Attr:All /RGName:"  & Chr(34) & strRGName & Chr(34) & " /domain:" & strDomain & " >> " & strDFSRInfoFile
	    Else
	        dbgPrint "[SKIPPED] Dfsradmin replicated folder commands skipped because Dfsradmin is unavailable or this was the SYSVOL RG", TO_FILE
	    End If
    
        Wscript.StdOut.Write "Collecting information about replication group:  " & strRGName
        For i = 0 to UBound(arrRGCommands)
            WScript.StdOut.Write "."
            RunCommand(arrRGCommands(i))
        Next
        WScript.Echo
        If objFSO.FileExists(strTempFolder & strComputerName & "_" & strParsedRGName & "_rgsched.txt") Then
            objFSO.DeleteFile(strTempFolder & strComputerName & "_" & strParsedRGName & "_rgsched.txt")
        End If
        
        ' Get DFSR database GUIDs from all machines in the replication group.
        
        If blnNoDBGUIDs Then
            dbgPrint "[SKIPPED] Collection of database GUIDs skipped because /nodbguids switch was used.", TO_FILE
        Else
            GetDBGuids strRGName, 1
        End If
    Next
    
    dbgPrint "Collecting machine-specific data", TO_FILE
    
    arrMachineCommands(0) = "cmd /d /c Echo. >> " & strDFSRInfoFile
    arrMachineCommands(1) = "cmd /d /c Echo ================================================================= >> " & strDFSRInfoFile
    arrMachineCommands(2) = "cmd /d /c Echo " & strComputerName & " machine configuration information: >> " & strDFSRInfoFile
    arrMachineCommands(3) = "cmd /d /c Echo ================================================================= >> " & strDFSRInfoFile
    arrMachineCommands(4) = "cmd /d /c Echo. >> " & strDFSRInfoFile
    arrMachineCommands(5) = "cmd /d /c Dfsrdiag DumpMachineCfg >> " & strDFSRInfoFile
    arrMachineCommands(6) = "cmd /d /c Echo. >> " & strDFSRInfoFile
    If blnDfsradmin Then
        arrMachineCommands(7) = "cmd /d /c Echo ================================================================= >> " & strDFSRInfoFile
        arrMachineCommands(8) = "cmd /d /c Echo " & strComputerName & " subscriber information: >> " & strDFSRInfoFile
        arrMachineCommands(9) = "cmd /d /c Echo ================================================================= >> " & strDFSRInfoFile
        arrMachineCommands(10) = "cmd /d /c Echo. >> " & strDFSRInfoFile
        arrMachineCommands(11) = "cmd /d /c Dfsradmin Sub List /Attr:All /Computer:" & strComputerName & " >> " & strDFSRInfoFile
        arrMachineCommands(12) = "cmd /d /c Echo. >> " & strDFSRInfoFile
    Else
        dbgPrint "[SKIPPED] Dfsradmin subscriber commands skipped because Dfsradmin is unavailable.", TO_FILE
    End If
    arrMachineCommands(13) = "cmd /d /c Echo ================================================================= >> " & strDFSRInfoFile
    arrMachineCommands(14) = "cmd /d /c Echo " & strComputerName & " Active Directory configuration information: >> " & strDFSRInfoFile
    arrMachineCommands(15) = "cmd /d /c Echo ================================================================= >> " & strDFSRInfoFile
    arrMachineCommands(16) = "cmd /d /c Echo. >> " & strDFSRInfoFile
    arrMachineCommands(17) = "cmd /d /c Dfsrdiag DumpAdCfg /RGSecDesc >> " & strDFSRInfoFile
    If blnDfsradmin = False Then
        arrMachineCommands(18) = "cmd /d /c Echo. >> " & strDFSRInfoFile
        arrMachineCommands(19) = "cmd /d /c Echo Dfsradmin commands were not run because this is a Server 2008 Core install, or a 2008 R2 Core install and NetFx2-ServerCore optional feature is not enabled, or Dfsradmin.exe just was not there. >> " & strDFSRInfoFile
    End If
        
    Wscript.StdOut.Write "Collecting information about server:             " & strComputerName
    For i = 0 to UBound(arrMachineCommands)
        WScript.StdOut.Write "."
        RunCommand(arrMachineCommands(i))
    Next
    WScript.Echo
    
    dbgPrint "Cleaning up info file", TO_FILE
    Set objInfoFile = objFSO.OpenTextFile(strDFSRInfoFile, FOR_READING)
    Set objParsedInfoFile = objFSO.CreateTextFile(strTempFolder & strComputerName & "_" & strParsedRGName & "_DFSR_Info2.txt")
    Do While objInfoFile.AtEndOfStream <> True
        strCurrentLine = objInfoFile.ReadLine
        If InStr(1, strCurrentLine, "Command completed successfully.", vbtextcompare) Then
            objInfoFile.SkipLine
        ElseIf Trim(strCurrentLine) = "1" Then
            objParsedInfoFile.WriteLine strScheduleExplainText
        ElseIf InStr(1, strCurrentLine, "Operation Succeeded", vbtextcompare) Then
            objInfoFile.SkipLine
        Else
            objParsedInfoFile.WriteLine strCurrentLine
        End If
    Loop
    objInfoFile.Close
    objParsedInfoFile.Close
    objFSO.DeleteFile(strDFSRInfoFile)
    objFSO.CopyFile strTempFolder & strComputerName & "_" & strParsedRGName & "_DFSR_Info2.txt", strDFSRInfoFile
    objFSO.DeleteFile strTempFolder & strComputerName & "_" & strParsedRGName & "_DFSR_Info2.txt"
    dbgPrint "Done cleaning up info file", TO_FILE
    
    If blnNoEvents Then
        dbgPrint "[SKIPPED] Event log information skipped because /noevents or /quick or /msdt switch was used.", TO_FILE
    Else
        dbgPrint "Collecting event logs", TO_FILE
        dbgPrint "Creating file: " & strTempFolder & strComputerName & "_" & "DFSR_Events_Last_72_Hours.xls", TO_FILE
        Set objEvents = objFSO.CreateTextFile(strTempFolder & strComputerName & "_" & "DFSR_Events_Last_72_Hours.xls")
        CheckForError
        dbgPrint "Select TimeWritten,EventCode,Type,Message from Win32_NTLogEvent where TimeWritten >= '" & dtmStartDate & "' and LogFile = 'DFS Replication'", TO_FILE
        Set colEvents = objWMIService.ExecQuery("Select TimeWritten,EventCode,Type,Message from Win32_NTLogEvent where TimeWritten >= '" & dtmStartDate & "' and LogFile = 'DFS Replication'")
        CheckForError
        Wscript.StdOut.Write "Collecting event log information"
        objEvents.WriteLine "Time" & vbTab & "Event ID" & vbTab & "Event Type" & vbTab & "Description"
        For Each objEvent in colEvents
            objEvents.WriteLine WMIDateStringToDate(objEvent.TimeWritten) & vbTab & objEvent.EventCode & vbTab & objEvent.Type & vbTab & Replace(objEvent.Message, vbCrLf, " ")
        Next
        objEvents.Close
        WScript.StdOut.Write "."
        
        dbgPrint "SELECT * FROM Win32_NTEventLogFile WHERE LogFileName = 'Application' OR LogFileName = 'System' OR LogFileName = 'DFS Replication' OR LogFileName = 'Directory Service'", TO_FILE    
        Set colLogFiles = objWMIService.ExecQuery("SELECT * FROM Win32_NTEventLogFile WHERE LogFileName = 'Application' OR LogFileName = 'System' OR LogFileName = 'DFS Replication' OR LogFileName = 'Directory Service'")
        CheckForError
        For Each objLogfile in colLogFiles
            WScript.StdOut.Write "."
            dbgPrint "Executing BackupEventLog method to collect " & objLogfile.FileName & " event log", TO_FILE
            errReturn = objLogFile.BackupEventLog(strTempFolder & strComputername & "_evt_" & objLogfile.FileName & ".evt")
            CheckForError
            If Err <> 0 Then
                Wscript.Echo objLogfile.FileName & ".evt could not be backed up. Error code " & errBackupLog
                dbgPrint "[ERROR] BackupEventLog method failed to collect " & objLogfile.FileName, TO_FILE
                Err.Clear
            End If
        Next
        dbgPrint "Done collecting event logs", TO_FILE
        Wscript.Echo
    End If 
    
    dbgPrint "Collecting information about conflicts and deletes", TO_FILE
    dbgPrint "Creating file: " & strTempFolder & strComputerName & "_" & "DFSR_ConflictAndDeleted.xls", TO_FILE
    Set objConflictInfo = objFSO.CreateTextFile(strTempFolder & strComputerName & "_" & "DFSR_ConflictAndDeleted.xls")
    CheckForError
    dbgPrint "SELECT * FROM DfsrConflictInfo", TO_FILE
    Set colItems = objWMIDfsService.ExecQuery("SELECT * FROM DfsrConflictInfo","WQL",wbemFlagReturnImmediately + wbemFlagForwardOnly)
    CheckForError
    objConflictInfo.WriteLine "Current name" & vbTab & "Original path" & vbTab & "Type" & vbTab & "Time" & vbTab & "Attributes" & vbTab & "UID" & vbTab & "GVSN" & vbTab & "Member GUID" & vbTab & "Replicated folder GUID" & vbTab & "Replication group GUID" & vbTab & "File count" & vbTab & "Size in bytes"
    For Each objItem In colItems
        objConflictInfo.Write objItem.FileName & vbTab
        objConflictInfo.Write Replace(objItem.ConflictPath, "\\.\", "")  & vbTab
        objConflictInfo.Write GetConflictType(objItem.ConflictType) & vbTab
        objConflictInfo.Write WMIDateStringToDate(objItem.ConflictTime) & vbTab
        objConflictInfo.Write GetFileAttributes(objItem.FileAttributes) & vbTab
        objConflictInfo.Write objItem.UID & vbTab
        objConflictInfo.Write objItem.GVSN & vbTab
        objConflictInfo.Write objItem.MemberGuid & vbTab
        objConflictInfo.Write objItem.ReplicatedFolderGuid & vbTab
        objConflictInfo.Write objItem.ReplicationGroupGuid & vbTab
        objConflictInfo.Write objItem.ConflictFileCount & vbTab
        objConflictInfo.WriteLine objItem.ConflictSizeInBytes
    Next
	objConflictInfo.Close
    
    ' Check for recommended hotfixes

    CheckHotfixes
    
    ' Check file versions for relevant files.
    
    CheckFileVersions
    
    ' Collect DFSR performance counter data
    
    dbgPrint "Creating file: " & strTempFolder & strComputerName & "_" & "DFSR_Performance_Data.txt", TO_FILE
    Set objPerfData = objFSO.CreateTextFile(strTempFolder & strComputerName & "_" & "DFSR_Performance_Data.txt")
    CheckForError
    dbgPrint "SELECT * FROM Win32_PerfFormattedData_Dfsr_DFSReplicatedFolders", TO_FILE
    Set colDFSReplicatedFolders = objWMIService.ExecQuery("SELECT * FROM Win32_PerfFormattedData_Dfsr_DFSReplicatedFolders", "WQL", _
                                      wbemFlagReturnImmediately)
    CheckForError
    If colDFSReplicatedFolders.Count = 0 Then
        dbgPrint "No instances of Win32_PerfFormattedData_Dfsr_DFSReplicatedFolders found.", TO_FILE
        objPerfData.WriteLine vbCrLf & "No instances of Win32_PerfFormattedData_Dfsr_DFSReplicatedFolders found." & vbCrLf
    Else
        dbgPrint "Writing information to file: " & strTempFolder & strComputerName & "_" & "DFSR_Performance_Data.txt", TO_FILE
        For Each objItem In colDFSReplicatedFolders
            objPerfData.WriteLine vbCrLF & "Replicated Folder Name: " & objItem.Name & vbCrLf
            objPerfData.WriteLine "BandwidthSavingsUsingDFSReplication: " & objItem.BandwidthSavingsUsingDFSReplication
            objPerfData.WriteLine "Caption: " & objItem.Caption
            objPerfData.WriteLine "CompressedSizeofFilesReceived: " & objItem.CompressedSizeofFilesReceived
            objPerfData.WriteLine "ConflictBytesCleanedup: " & objItem.ConflictBytesCleanedup
            objPerfData.WriteLine "ConflictBytesGenerated: " & objItem.ConflictBytesGenerated
            objPerfData.WriteLine "ConflictFilesCleanedup: " & objItem.ConflictFilesCleanedup
            objPerfData.WriteLine "ConflictFilesGenerated: " & objItem.ConflictFilesGenerated
            objPerfData.WriteLine "ConflictFolderCleanupsCompleted: " & objItem.ConflictFolderCleanupsCompleted
            objPerfData.WriteLine "ConflictSpaceInUse: " & objItem.ConflictSpaceInUse
            objPerfData.WriteLine "DeletedBytesCleanedup: " & objItem.DeletedBytesCleanedup
            objPerfData.WriteLine "DeletedBytesGenerated: " & objItem.DeletedBytesGenerated
            objPerfData.WriteLine "DeletedFilesCleanedup: " & objItem.DeletedFilesCleanedup
            objPerfData.WriteLine "DeletedFilesGenerated: " & objItem.DeletedFilesGenerated
            objPerfData.WriteLine "DeletedSpaceInUse: " & objItem.DeletedSpaceInUse
            objPerfData.WriteLine "Description: " & objItem.Description
            objPerfData.WriteLine "FileInstallsRetried: " & objItem.FileInstallsRetried
            objPerfData.WriteLine "FileInstallsSucceeded: " & objItem.FileInstallsSucceeded
            objPerfData.WriteLine "RDCBytesReceived: " & objItem.RDCBytesReceived
            objPerfData.WriteLine "RDCCompressedSizeofFilesReceived: " & objItem.RDCCompressedSizeofFilesReceived
            objPerfData.WriteLine "RDCNumberofFilesReceived: " & objItem.RDCNumberofFilesReceived
            objPerfData.WriteLine "RDCSizeofFilesReceived: " & objItem.RDCSizeofFilesReceived
            objPerfData.WriteLine "SizeofFilesReceived: " & objItem.SizeofFilesReceived
            objPerfData.WriteLine "StagingBytesCleanedup: " & objItem.StagingBytesCleanedup
            objPerfData.WriteLine "StagingBytesGenerated: " & objItem.StagingBytesGenerated
            objPerfData.WriteLine "StagingFilesCleanedup: " & objItem.StagingFilesCleanedup
            objPerfData.WriteLine "StagingFilesGenerated: " & objItem.StagingFilesGenerated
            objPerfData.WriteLine "StagingSpaceInUse: " & objItem.StagingSpaceInUse
            objPerfData.WriteLine "TotalFilesReceived: " & objItem.TotalFilesReceived
            objPerfData.WriteLine "UpdatesDropped: " & objItem.UpdatesDropped
        Next
    End If
    
    dbgPrint "SELECT * FROM Win32_PerfFormattedData_Dfsr_DFSReplicationConnections", TO_FILE
    Set colDFSReplicationConnections = objWMIService.ExecQuery("SELECT * FROM Win32_PerfFormattedData_Dfsr_DFSReplicationConnections", "WQL", _
                                          wbemFlagReturnImmediately + wbemFlagForwardOnly)
    CheckForError
    
'    Wscript.Echo "VarType(colDFSReplicationConnections)  = " & VarType(colDFSReplicationConnections)
'    Wscript.Echo "IsEmpty(colDFSReplicationConnections)  = " & IsEmpty(colDFSReplicationConnections)
'    Wscript.Echo "IsNull(colDFSReplicationConnections)   = " & IsNull(colDFSReplicationConnections)
'    Wscript.Echo "IsObject(colDFSReplicationConnections) = " & IsObject(colDFSReplicationConnections)
'    Wscript.Echo "colDFSReplicationConnections.Count     = " & colDFSReplicationConnections.Count

    If colDFSReplicationConnections.Count = 0 Then
        dbgPrint "No instances of Win32_PerfFormattedData_Dfsr_DFSReplicationConnections found.", TO_FILE
        objPerfData.WriteLine vbCrLf & "No instances of Win32_PerfFormattedData_Dfsr_DFSReplicationConnections found." & vbCrLf
    Else
        dbgPrint "Writing information to file: " & strTempFolder & strComputerName & "_" & "DFSR_Performance_Data.txt", TO_FILE
        For Each objItem In colDFSReplicationConnections
            objPerfData.WriteLine vbCrLF & "Connection Name: " & objItem.Name & vbCrLf
            objPerfData.WriteLine "BandwidthSavingsUsingDFSReplication: " & objItem.BandwidthSavingsUsingDFSReplication
            objPerfData.WriteLine "BytesReceivedPerSecond: " & objItem.BytesReceivedPerSecond
            objPerfData.WriteLine "Caption: " & objItem.Caption
            objPerfData.WriteLine "CompressedSizeofFilesReceived: " & objItem.CompressedSizeofFilesReceived
            objPerfData.WriteLine "Description: " & objItem.Description
            objPerfData.WriteLine "RDCBytesReceived: " & objItem.RDCBytesReceived
            objPerfData.WriteLine "RDCCompressedSizeofFilesReceived: " & objItem.RDCCompressedSizeofFilesReceived
            objPerfData.WriteLine "RDCNumberofFilesReceived: " & objItem.RDCNumberofFilesReceived
            objPerfData.WriteLine "RDCSizeofFilesReceived: " & objItem.RDCSizeofFilesReceived
            objPerfData.WriteLine "SizeofFilesReceived: " & objItem.SizeofFilesReceived
            objPerfData.WriteLine "TotalBytesReceived: " & objItem.TotalBytesReceived
            objPerfData.WriteLine "TotalFilesReceived: " & objItem.TotalFilesReceived
        Next
    End If
    
    dbgPrint "SELECT * FROM Win32_PerfFormattedData_Dfsr_DFSReplicationServiceVolumes", TO_FILE
    Set colDFSReplicationServiceVolumes = objWMIService.ExecQuery("SELECT * FROM Win32_PerfFormattedData_Dfsr_DFSReplicationServiceVolumes", "WQL", _
                                          wbemFlagReturnImmediately + wbemFlagForwardOnly)
    CheckForError
    If colDFSReplicationServiceVolumes.Count = 0 Then
        dbgPrint "No instances of Win32_PerfFormattedData_Dfsr_DFSReplicationServiceVolumes found.", TO_FILE
        objPerfData.WriteLine vbCrLf & "No instances of Win32_PerfFormattedData_Dfsr_DFSReplicationServiceVolumes found." & vbCrLf
    Else
        dbgPrint "Writing information to file: " & strTempFolder & strComputerName & "_" & "DFSR_Performance_Data.txt", TO_FILE
        For Each objItem In colDFSReplicationServiceVolumes
            objPerfData.WriteLine vbCrLF & "Volume Name: " & objItem.Name & vbCrLf
            objPerfData.WriteLine "Caption: " & objItem.Caption
            objPerfData.WriteLine "DatabaseCommits: " & objItem.DatabaseCommits
            objPerfData.WriteLine "DatabaseLookups: " & objItem.DatabaseLookups
            objPerfData.WriteLine "Description: " & objItem.Description
            objPerfData.WriteLine "USNJournalRecordsAccepted: " & objItem.USNJournalRecordsAccepted
            objPerfData.WriteLine "USNJournalRecordsRead: " & objItem.USNJournalRecordsRead
            objPerfData.WriteLine "USNJournalUnreadPercentage: " & objItem.USNJournalUnreadPercentage
        Next
    End If
    
    If colDFSReplicatedFolders.Count = 0 Or colDFSReplicationConnections = 0 Or colDFSReplicationServiceVolumes = 0 Then
        objPerfData.WriteLine vbCrLF & "NOTE: Messages about having no instances of a particular performance counter object are expected in most cases." & vbCrLf
    End If
    objPerfData.Close

    If blnNoDebugLogs Then
        dbgPrint "[SKIPPED] Debug logs skipped because /msdt or /quick or /nodebuglogs switch was used.", TO_FILE
    Else
        dbgPrint "Collecting DFSR debug logs and DFS Management trace logs", TO_FILE
        Wscript.StdOut.Write "Collecting debug logs"
        WScript.StdOut.Write "."
        dbgPrint "SELECT DebugLogFilePath FROM DfsrMachineConfig", TO_FILE
        Set colItems = objWMIDfsService.ExecQuery("SELECT DebugLogFilePath FROM DfsrMachineConfig", "WQL", wbemFlagReturnImmediately + wbemFlagForwardOnly)
        CheckForError
        WScript.StdOut.Write "."
        For Each objItem In colItems
            WScript.StdOut.Write "."
            strDebugLogFilePath = objItem.DebugLogFilePath & "\"
        Next
        WScript.StdOut.Write "."
        dbgPrint "Copying " & strDebugLogFilePath & "\dfsr*.log* to " & strTempFolder, TO_FILE
        objFSO.CopyFile strDebugLogFilePath & "\dfsr*.log*", strTempFolder
        WScript.StdOut.Write "."
        If objFSO.FolderExists(strDebugLogFilePath & "\Dfsmgmt") Then
            dbgPrint "Found folder " & strDebugLogFilePath & "\Dfsmgmt, Dfsmgmt tracing is enabled.", TO_FILE
            Set objFolder = objFSO.GetFolder(strDebugLogFilePath & "\Dfsmgmt")
            CheckForError
            Set colFiles = objFolder.Files
            CheckForError
            For Each objFile in colFiles
                If UCase(objFile.Name) = "DFSMGMT.CURRENT.LOG" Or UCase(objFile.Name) = "DFSMGMT.PREVIOUS.LOG" Then
                    dbgPrint "Copying file: " & objFile.Path & " to " & strTempFolder & strComputerName & "_DFSR_" & objFile.Name, TO_FILE
                    objFSO.CopyFile objFile.Path, strTempFolder & strComputerName & "_DFSR_" & objFile.Name
                    CheckForError
                End If
            Next
'            dbgPrint "Copying " & strDebugLogFilePath & "\Dfsmgmt\Dfsmgmt* to " & strTempFolder, TO_FILE
'            objFSO.CopyFile strDebugLogFilePath & "\Dfsmgmt\Dfsmgmt*", strTempFolder
        Else
            dbgPrint "Did not find folder " & strDebugLogFilePath & "\Dfsmgmt, Dfsmgmt tracing is not enabled.", TO_FILE
        End If
        WScript.StdOut.Write "."
        Wscript.Echo
    End If
    
    dbgPrint "Collecting DFSR XML configuration files from \System Volume Information\DFSR\Config directory", TO_FILE
    Wscript.StdOut.Write "Collecting configuration files"
    dbgPrint "Collecting files from %SystemDrive%\System Volume Information\DFSR\Config", TO_FILE
    Set objFolder = objFSO.GetFolder(strSystemDrive & "\System Volume Information\DFSR\Config")
    CheckForError
    Set colFiles = objFolder.Files
    CheckForError
    For Each objFile in colFiles
        dbgPrint "Copying file: " & objFile.Path & " to " & strTempFolder & strComputerName & "_DFSR_" & objFile.Name, TO_FILE
        objFSO.CopyFile objFile.Path, strTempFolder & strComputerName & "_DFSR_" & objFile.Name
        CheckForError
        WScript.StdOut.Write "."
    Next
    dbgPrint "SELECT volumepath FROM DfsrVolumeInfo", TO_FILE
    Set colVolumes = objWMIDfsService.ExecQuery("SELECT volumepath FROM DfsrVolumeInfo")
    CheckForError
    WScript.StdOut.Write "."
    For Each objVolume in colVolumes
        Set objFolder = objFSO.GetFolder(Mid(objVolume.VolumePath, 5) & "\System Volume Information\DFSR\Config")
        CheckForError
        Set colFiles = objFolder.Files
        CheckForError
        For Each objFile in colFiles
            dbgPrint "Copying file: " & objFile.Path & " to " & strTempFolder & strComputerName & "_DFSR_" & objFile.Name, TO_FILE
            objFSO.CopyFile objFile.Path, strTempFolder & strComputerName & "_DFSR_" & objFile.Name
            CheckForError
            WScript.StdOut.Write "."
        Next
    Next
    Wscript.Echo
    dbgPrint "Exporting DFSR and TCP/IP Parameters registry keys", TO_FILE
    Wscript.Echo "Collecting registry information..."
    RunCommand("cmd /d /c reg query HKLM\System\CurrentControlSet\Services\DFSR /s >" & strTempFolder & strComputerName & "_DFSR_RegKey_DFSR.txt")
    CheckForError
    RunCommand("cmd /d /c reg query HKLM\System\CurrentControlSet\Services\Tcpip\Parameters >" & strTempFolder & strComputerName & "_DFSR_RegKey_TCPIP.txt")
    CheckForError
        
    dbgPrint "Collecting MSINFO32 .NFO file", TO_FILE
    If blnNoMSINFO32 Then
        dbgPrint "[SKIPPED] MSINFO32 skipped because /msdt or /quick or /nomsinfo32 switch was used.", TO_FILE
    Else
        Wscript.Echo "Collecting MSINFO32 output..."
        If strBuildNumber = "3790" Then
            dbgPrint "RUNNING:  " & "msinfo32 /nfo " & strTempFolder & strComputerName & ".nfo", TO_FILE
            objShell.Run "msinfo32.exe /nfo " & strTempFolder & strComputerName & ".nfo", 0, TRUE
            CheckForError
        Else 
            RunCommand("msinfo32.exe /nfo " & strTempFolder & strComputerName & ".nfo")
            CheckForError
        End If
    End If
    
    dbgPrint "Checking for file screens", TO_FILE
    If objFSO.FileExists(strWinDir & "\System32\filescrn.exe") Then
        Wscript.Echo "Collecting FSRM file screen information..."
        RunCommand("cmd /d /c Filescrn Screen List >" & strTempFolder & strComputerName & "_DFSR_FSRM_File_Screens.txt")
        CheckForError
    End If
    dbgPrint "Done checking for file screens", TO_FILE

    dbgPrint "Checking for quotas", TO_FILE
    If objFSO.FileExists(strWinDir & "\System32\dirquota.exe") Then
        Wscript.Echo "Collecting FSRM quota information..."
        RunCommand("cmd /d /c Dirquota Quota List >" & strTempFolder & strComputerName & "_DFSR_FSRM_Quotas.txt")
        CheckForError
    End If
    dbgPrint "Done checking for quotas", TO_FILE
    
    If blnMSDT Then
        dbgPrint "Script completed in " & GetElapsedTime, TO_FILE
        Wscript.Sleep 200
        objFSO.MoveFile "Progress.txt", "DFSR__Progress.txt"
        Wscript.Quit
    Else
        dbgPrint "Copying Progress.txt into output folder so it will be included in the .CAB file", TO_FILE
        dbgPrint "Script execution time so far (before CAB file creation) " & GetElapsedTime, TO_FILE
        objFSO.CopyFile "Progress.txt", strTempFolder & "\_Progress.txt", OverwriteExisting
        dbgPrint "Creating cab file " & strCabFolder & strComputername & "_" & dtmNow & "_DfsrInfo.cab", TO_FILE + TO_SCREEN
        dbgPrint "Creating folder: " & strCabFolder, TO_FILE
        Set objCabFolder = objFSO.CreateFolder(strCabFolder)
        CheckForError
        dbgPrint "Creating file: " & strCabFolder & "CABDIRECT.DDF", TO_FILE
        Set objCabDirectiveFile = objFSO.CreateTextFile(strCabFolder & "CABDIRECT.DDF", True)
        CheckForError
        objCabDirectiveFile.WriteLine ".OPTION EXPLICIT" & vbCrLf &_
        objShell.ExpandEnvironmentStrings(".Set CabinetNameTemplate=" & strComputername & "_" & dtmNow & "_DfsrInfo.cab") & vbCrLf &_
                                          ".Set DiskDirectoryTemplate=" & strCabFolder & vbCrLf &_
                                          ".Set MaxDiskSize=0" & vbCrLf &_
                                          ".Set CompressionType=MSZIP" & vbCrLf &_
                                          ".Set Cabinet=on" & vbCrLf &_
                                          ".Set Compress=on"
        dbgPrint "Checking " & strTempFolder, TO_FILE
        Set objTempFolder = objFSO.GetFolder(strTempFolder)
        CheckForError
        Set colTempFiles = objTempFolder.Files
        dbgPrint "Writing the rest of the files to " & strCabFolder & "CABDIRECT.DDF", TO_FILE
        For Each objTempFile in colTempFiles
            objCabDirectiveFile.WriteLine Chr(34) & strTempFolder & objTempFile.Name & Chr(34)
        Next
        objCabDirectiveFile.Close
        strCommand = "cmd /c cd /d " & strCabFolder & " & makecab /F " & strCabFolder & "CABDIRECT.DDF /L " & strCabFolder
        dbgPrint "RUNNING:  " & strCommand, TO_FILE
        objShell.Run strCommand, 1, TRUE
        CheckForError
        If Err <> 0 Then
            dbgPrint "Failed to create cab file. [ERROR] " & errReturn, TO_FILE + TO_SCREEN
            Err.Clear
        Else
            dbgPrint "Successfully created cab file", TO_FILE
        End If
        dbgPrint "Deleting file: " & strTempFolder & "\Cab\CABDIRECT.DDF", TO_FILE
        objFSO.DeleteFile(strTempFolder & "\Cab\CABDIRECT.DDF")
        CheckForError
        dbgPrint "Deleting file: " & strTempFolder & "\Cab\setup.inf", TO_FILE
        objFSO.DeleteFile(strTempFolder & "\Cab\setup.inf")
        CheckForError
        dbgPrint "Deleting file: " & strTempFolder & "\Cab\setup.rpt", TO_FILE
        objFSO.DeleteFile(strTempFolder & "\Cab\setup.rpt")
        CheckForError
    
        If blnCoreInstall Then
            dbgPrint "This is a Core install so just switch the command prompt into the cab folder and do a dir on it.", TO_FILE
            strCommand = "cmd /d /k cd /d " & strCabFolder & " & dir"
        Else
            dbgPrint "This is not a Core install so just open the cab folder in Windows Explorer.", TO_FILE
            strCommand = "cmd /d /c start " & strCabFolder
        End If
        dbgPrint "RUNNING:  " & strCommand, TO_FILE
        objShell.Run strCommand
        CheckForError
    End If
    dbgPrint vbCrLf & "Script completed in " & GetElapsedTime, TO_SCREEN
    dbgPrint "Script completed in " & GetElapsedTime, TO_FILE
    Wscript.Quit
End Sub

Function GetConflictType(strConflictType)
    Select Case strConflictType
        Case 1 GetConflictType = "Name Conflict"
        Case 2 GetConflictType = "Remote Update Local Update Conflict"
        Case 3 GetConflictType = "Remote Update Local Delete Conflict"
        Case 4 GetConflictType = "Local Delete Remote Update Conflict"
        Case 5 GetConflictType = "Remote File Delete"
        Case 6 GetConflictType = "Remote File Does Not Exist At Initial Sync"
    End Select
End Function

Function GetFileAttributes(intFileAttributes)
    If intFileAttributes And &H1 Then 
        GetFileAttributes = "Read-only,"
    End If
    If intFileAttributes And &H2 Then 
        GetFileAttributes = GetFileAttributes + "Hidden,"
    End If
    If intFileAttributes And &H4 Then 
        GetFileAttributes = GetFileAttributes + "System,"
    End If
    If intFileAttributes And &H10 Then 
        GetFileAttributes = GetFileAttributes + "Directory,"
    End If
    If intFileAttributes And &H20 Then 
        GetFileAttributes = GetFileAttributes + "Archive,"
    End If
    If intFileAttributes And &H40 Then 
        GetFileAttributes = GetFileAttributes + "Device,"
    End If
    If intFileAttributes And &H80 Then 
        GetFileAttributes = GetFileAttributes + "Normal,"
    End If
    If intFileAttributes And &H100 Then 
        GetFileAttributes = GetFileAttributes + "Temporary,"
    End If
    If intFileAttributes And &H200 Then 
        GetFileAttributes = GetFileAttributes + "Sparse File,"
    End If
    If intFileAttributes And &H400 Then 
        GetFileAttributes = GetFileAttributes + "Reparse Point,"
    End If
    If intFileAttributes And &H800 Then 
        GetFileAttributes = GetFileAttributes + "Compressed,"
    End If
    If intFileAttributes And &H1000 Then 
        GetFileAttributes = GetFileAttributes + "Offline,"
    End If
    If intFileAttributes And &H2000 Then 
        GetFileAttributes = GetFileAttributes + "Not Content Indexed,"
    End If
    If intFileAttributes And &H4000 Then 
        GetFileAttributes = GetFileAttributes + "Encrypted,"
    End If
    If InStr(1,GetFileAttributes, ",",vbTextCompare) Then 
        GetFileAttributes = Left(GetFileAttributes, Len(GetFileAttributes) - 1)
    End If
End Function

Function WMIDateStringToDate(dtmInstallDate)
    WMIDateStringToDate = CDate(Mid(dtmInstallDate, 5, 2) & "/" & Mid(dtmInstallDate, 7, 2) & "/" & Left(dtmInstallDate, 4) _
    & " " & Mid (dtmInstallDate, 9, 2) & ":" & Mid(dtmInstallDate, 11, 2) & ":" & Mid(dtmInstallDate,13, 2))
End Function

Function CheckHotfixes
    On Error Resume Next
    dbgPrint "Checking hotfixes", TO_FILE
    Select Case strBuildNumber
    Case "7600"
        dbgPrint "Using str2008R2PreSP1Fixes hotfix list", TO_FILE
        arrTemp = Split(str2008R2PreSP1Fixes,",")
    Case "6001", "6002"
        If strServicePack = "1" Then
            dbgPrint "Using str2008PreSP2Fixes hotfix list", TO_FILE
            arrTemp = Split(str2008PreSP2Fixes,",")
        ElseIf strServicePack = "2" Then
            dbgPrint "Using str2008PreSP3Fixes hotfix list", TO_FILE
            arrTemp = Split(str2008PreSP3Fixes,",")
        Else 
            dbgPrint "Unrecognized service pack found while checking hotfixes", TO_FILE
	        Exit Function
        End If
    Case "3790"
        If strServicePack = "1" Then
            dbgPrint "Using str2003PreSP2Fixes hotfix list", TO_FILE
            arrTemp = Split(str2003PreSP2Fixes,",")
        ElseIf strServicePack = "2" Then
            dbgPrint "Using str2003PreSP3Fixes hotfix list", TO_FILE
            arrTemp = Split(str2003PreSP3Fixes,",")
        Else 
            dbgPrint "Unrecognized service pack found while checking hotfixes - " & strBuildNumber, TO_FILE
	        Exit Function
        End If
	Case Else 
	    dbgPrint "Unrecognized OS build number found while checking hotfixes", TO_FILE
	    Exit Function
    End Select
    dbgPrint "Select HotFixID from Win32_QuickFixEngineering", TO_FILE
    Set colHotfixes = objWMIService.ExecQuery("Select HotFixID from Win32_QuickFixEngineering")
    CheckForError
    ReDim arrHotfixes(UBound(arrTemp),2)

    For i = 0 to UBound(arrTemp)
        arrHotfixes(i,0) = Left(arrTemp(i), 6)
        arrHotfixes(i,1) = Mid(arrTemp(i), 8)
        arrHotfixes(i,2) = False
    Next
    
    For Each objHotfix in colHotfixes
        For i = 0 to UBound(arrHotfixes)
            If InStr(objHotfix.HotFixID, arrHotfixes(i,0)) Then
                arrHotfixes(i,2) = True
            End If
        Next
    Next
	If blnCheckHotfixesOnly Then
        dbgPrint "Writing hotfix check output to screen", TO_FILE
        Wscript.Echo vbCrLf & strCaption & " Service Pack " & strServicePack & vbCrLf
        For i = 0 to UBound(arrHotfixes)
            If arrHotfixes(i,2) Then
		        Wscript.Echo "INSTALLED     " & arrHotfixes(i,0) & " " & arrHotfixes(i,1)
            Else
		        Wscript.Echo "NOT INSTALLED " & arrHotfixes(i,0) & " " & arrHotfixes(i,1)
            End If
        Next
    	dbgPrint "Done checking hotfixes", TO_FILE
    	dbgPrint vbCrLf & "Script completed in " & GetElapsedTime, TO_SCREEN
    	dbgPrint "Script completed in " & GetElapsedTime, TO_FILE
        Wscript.Quit
    Else
    	dbgPrint "Creating file: " & strTempFolder & strComputerName & "_" & "DFSR_Hotfixes.txt", TO_FILE
    	Set objHotfixInfo = objFSO.CreateTextFile(strTempFolder & strComputerName & "_" & "DFSR_Hotfixes.txt")
    	CheckForError
        objHotfixInfo.WriteLine strCaption & "Service Pack " & strServicePack & " Version " & strOSVersion & vbCrLf
        For i = 0 to UBound(arrHotfixes)
            If arrHotfixes(i,2) Then
			    objHotfixInfo.WriteLine "INSTALLED     " & arrHotfixes(i,0) & " " & arrHotfixes(i,1)
            Else
			    objHotfixInfo.WriteLine "NOT INSTALLED " & arrHotfixes(i,0) & " " & arrHotfixes(i,1)
            End If
        Next
	    objHotfixInfo.Close
	End If
	dbgPrint "Done checking hotfixes", TO_FILE
End Function

Function ConfigureAuditing(blnEnableAudit)
    dbgPrint "Creating file: " & strTempFolder & "AuditObjectAccess.inf", TO_FILE
    Set objSecurityTemplate = objFSO.CreateTextFile(strTempFolder & "AuditObjectAccess.inf")
    CheckForError
    objSecurityTemplate.WriteLine "[Unicode]" & vbCrLf & "Unicode=yes" & vbCrLf & "[Version]" & vbCrLf & "signature=" & Chr(34) & "$CHICAGO$" & Chr(34)  & vbCrLf & "Revision=1" & vbCrLf & "[Event Audit]"
    If blnEnableAudit Then
        objSecurityTemplate.WriteLine "AuditObjectAccess = 1"
        dbgPrint "Writing registry key: HKLM\SYSTEM\CurrentControlSet\Services\Dfsr\Parameters\Enable Audit", TO_FILE
        errReturn = objShell.RegWrite("HKLM\SYSTEM\CurrentControlSet\Services\Dfsr\Parameters\Enable Audit\","")
        CheckForError
        If errReturn Then
            Wscript.Echo "[ERROR] " & errReturn & "attempting to create the registry key:" & vbCrLF
            Wscript.Echo "HKLM\SYSTEM\CurrentControlSet\Services\Dfsr\Parameters\Enable Audit" & vbCrLF
            Wscript.Echo "No changes made. Exiting."
            Exit Function
        Else
            Wscript.Echo vbCrLf & "Registry key successfully created:" & vbCrLf  & vbCrLF & "  HKLM\SYSTEM\CurrentControlSet\Services\Dfsr\Parameters\Enable Audit" & vbCrLF
            dbgPrint "Registry key successfully created: HKLM\SYSTEM\CurrentControlSet\Services\Dfsr\Parameters\Enable Audit", TO_FILE
        End If
    Else
        objSecurityTemplate.WriteLine "AuditObjectAccess = 0"
        dbgPrint "Deleting registry key: HKLM\SYSTEM\CurrentControlSet\Services\Dfsr\Parameters\Enable Audit", TO_FILE
        errReturn = objShell.RegDelete("HKLM\SYSTEM\CurrentControlSet\Services\Dfsr\Parameters\Enable Audit\")
        CheckForError
        If errReturn Then
            Wscript.Echo "[ERROR] " & errReturn & "attempting to delete the registry key:" & vbCrLF
            Wscript.Echo "HKLM\SYSTEM\CurrentControlSet\Services\Dfsr\Parameters\Enable Audit" & vbCrLF
            Wscript.Echo "No changes made. Exiting." & vbCrLF
        Else
            Wscript.Echo "Registry key successfully deleted:" & vbCrLf & vbCrLf & "HKLM\SYSTEM\CurrentControlSet\Services\Dfsr\Parameters\Enable Audit" & vbCrLf
            dbgPrint "Registry key successfully deleted: HKLM\SYSTEM\CurrentControlSet\Services\Dfsr\Parameters\Enable Audit"
        End If
    End If        
    objSecurityTemplate.WriteLine "[Registry Values]"
    objSecurityTemplate.Close
    If blnEnableAudit Then
        Wscript.Echo "Running secedit to generate rollback template (used if DfsrInfo /disableaudit is run)." & vbCrLF
        strCommand = "secedit /generaterollback /db %windir%\security\database\AuditObjectAccess.sdb /cfg " & strTempFolder & "AuditObjectAccess.inf /rbk %windir%\security\templates\AuditObjectAccessRollback.inf /log " & strTempFolder & "secedit.log /quiet"
        dbgPrint "RUNNING:  " & strCommand, TO_FILE
        errReturn = objShell.Run(strCommand, 0, TRUE)
        CheckForError
        If errReturn Then
            Wscript.Echo "[ERROR] attempting to generate the rollback template. No changes were made. " & vbCrLf & "See " & strTempFolder & "secedit.log"
            dbgPrint "[ERROR] attempting to generate the rollback template. No changes were made. See " & strTempFolder & "secedit.log", TO_FILE
            Exit Function
        Else
            If objFSO.FileExists(strWinDir & "\security\templates\AuditObjectAccessRollback.inf") Then
                Wscript.Echo "Rollback template successfully created at " & strWinDir & "\security\templates\AuditObjectAccessRollback.inf" & vbCrLF
                Set objRollbackTemplate = objFSO.OpenTextFile(strWinDir & "\security\templates\AuditObjectAccessRollback.inf", FOR_READING,False,-1)
                Do Until objRollbackTemplate.AtEndOfStream
                    strText = objRollbackTemplate.ReadLine
                    strAuditObjectAccess = "AuditObjectAccess"
                    If InStr(1,strText,strAuditObjectAccess,vbTextCompare) Then
                        strCurrentSetting = Right(strText,1)
                    End If
                Loop
                objRollbackTemplate.Close
                Select Case strCurrentSetting
                    Case "0" strCurrentSetting = "No Auditing"
                    Case "1" strCurrentSetting = "Success"
                    Case "2" strCurrentSetting = "Failure"
                    Case "3" strCurrentSetting = "Success,Failure"
                End Select
                Wscript.Echo "Server is currently configured for Audit Object Access:" & strCurrentSetting & vbCrLf
                If strCurrentSetting = "Success" Or strCurrentSetting = "Success,Failure" Then
                    Wscript.Echo "No changes required. Audit Object Access is correctly configured for DFS Replication auditing."
                    Exit Function
                Else 
                    Wscript.Echo "Running secedit to configure the local policy setting Audit Object Access:Success"
                    objShell.Run "secedit /configure /db %windir%\security\database\AuditObjectAccess.sdb /cfg " & strTempFolder & "AuditObjectAccess.inf /overwrite  /log " & strTempFolder & "secedit.log /quiet", 0, TRUE
                    If Err <> 0 Then
                        Wscript.Echo "[ERROR] attempting to configure the Audit Object Access local security policy setting. No changes were made. " & vbCrLf & "See " & strTempFolder & "secedit.log"
                        Err.Clear
                        Exit Function
                    Else
                        Wscript.Echo "Successfully enabled local policy setting Audit Object Access:Success." & vbCrLf
                        Wscript.Echo "DFS Replication auditing is now enabled. You will now see Event ID 3 from Source DFSR in the Security log"
                        Wscript.Echo "when an update is attempted and when the file has successfully replicated."
                    End If
                End If
            End If
        End If
    Else
        If objFSO.FileExists(strWinDir & "\security\templates\AuditObjectAccessRollback.inf") Then
            objShell.Run "secedit /configure /db %windir%\security\database\AuditObjectAccess.sdb /cfg %windir%\security\templates\AuditObjectAccessRollback.inf /overwrite  /log " & strTempFolder & "secedit.log /quiet", 0, TRUE
            If Err <> 0 Then
                Wscript.Echo "[ERROR] attempting to configure the Audit Object Access local security policy setting. No changes were made. " & vbCrLf & "See " & strTempFolder & "secedit.log"
                Err.Clear
                Exit Function
            Else
                Wscript.Echo "Successfully reverted local policy setting Audit Object Access to its original setting." & vbCrLf
                Wscript.Echo "DFS Replication auditing is now disabled. Event ID 3 from Source DFSR will no longer be logged in the Security log"
                Wscript.Echo "when an update is attempted or when a file has successfully replicated."
            End If
        Else
            Wscript.Echo "The security template to revert the Audit Object Access local security policy setting was not found:" & vbCrLf
            Wscript.Echo strWinDir & "\security\templates\AuditObjectAccessRollback.inf" & vbCrLf
            Wscript.Echo "Would you like to disable the Audit Object Access local security policy setting? (Y/N)"
            Do While Not WScript.StdIn.AtEndOfLine
                strInput = WScript.StdIn.Read(1)
            Loop
            If UCase(strInput) = "Y" Then
                objShell.Run "secedit /configure /db %windir%\security\database\AuditObjectAccess.sdb /cfg %windir%\security\templates\AuditObjectAccessRollback.inf /overwrite  /log " & strTempFolder & "secedit.log /quiet", 0, TRUE
                If Err <> 0 Then
                    Wscript.Echo "[ERROR] attempting to configure the Audit Object Access local security policy setting. No changes were made. " & vbCrLf & "See " & strTempFolder & "secedit.log"
                    Err.Clear
                    Exit Function
                Else
                    Wscript.Echo "Successfully reverted local policy setting Audit Object Access to its original setting."
                    Wscript.Echo "DFS Replication auditing is now disabled. Event ID 3 from Source DFSR will no longer be logged in the Security log"
                    Wscript.Echo "when an update is attempted or when a file has successfully replicated."
                End If
            End If
        End If
    End If
End Function

Function GetDBGUIDs(strRGName,blnOutputToTextFile)
    On Error Resume Next
    dbgPrint "Getting database GUIDs", TO_FILE
    dbgPrint "Instantiating rootDSE", TO_FILE
    Set objRootDSE = GetObject("LDAP://rootDSE")
    CheckForError
    strADsPath = "LDAP://" & objRootDSE.Get("defaultNamingContext")
    dbgPrint "Instantiating defaultNamingContext", TO_FILE
    Set objDomain = GetObject(strADsPath)
    CheckForError
    strDomainDN = objDomain.DistinguishedName
    dbgPrint "strDomainDN = " & strDomainDN, TO_FILE
    If IsEmpty(strDomainDN) Then
        dbgPrint "[ERROR] Could not determine distinguished name of domain. DFSR database GUIDs will not be collected.", TO_FILE
        Exit Function
    End If
    
    Set objConnection = CreateObject("ADODB.Connection")
    Set objCommand =   CreateObject("ADODB.Command")
    objConnection.Provider = "ADsDSOObject"
    objConnection.Open "Active Directory Provider"
    
    Set objCommand.ActiveConnection = objConnection
    objCommand.CommandText = "Select distinguishedname,objectguid from 'LDAP://" & strDomainDN & "' where objectClass='msdfsr-replicationgroup' and name= '" & strRGName & "'"
    objCommand.Properties("Page Size") = 1000
    objCommand.Properties("Searchscope") = ADS_SCOPE_SUBTREE 
    dbgPrint objCommand.CommandText, TO_FILE
    Set objRecordSet = objCommand.Execute
    CheckForError
    objRecordSet.MoveFirst
    
    Do Until objRecordSet.EOF
        'strRFGUID = myADsEncodeBinaryData(objRecordSet.Fields("objectguid").Value) ' this was from the old way of doing it
        strDN = objRecordSet.Fields("distinguishedName").Value ' NEW!!!
        objRecordSet.MoveNext
    Loop    
    
    objCommand.CommandText = "Select msDFSR-ComputerReference from 'LDAP://CN=Topology," & strDN & "' where objectClass='msdfsr-member'"
    objCommand.Properties("Page Size") = 1000
    objCommand.Properties("Searchscope") = ADS_SCOPE_SUBTREE 
    dbgPrint objCommand.CommandText, TO_FILE
    Set objRecordSet = objCommand.Execute
    CheckForError
    objRecordSet.MoveFirst
    
    Do Until objRecordSet.EOF
        Set objMember = GetObject("LDAP://" & objRecordSet.Fields("msDFSR-ComputerReference").Value)
        strComputer = objMember.dnshostname
        dbgPrint "strComputer = " & strComputer, TO_FILE
        CheckForError
        If Err = 0 Then
            dbgPrint "Connecting to \root\microsoftDfs namespace on " & strComputer, TO_FILE
            Set objWMIDfsService2 = GetObject("winmgmts:\\" & strComputer & "\root\microsoftDfs")
            CheckForError
            dbgPrint "SELECT databaseguid,volumepath FROM DfsrVolumeInfo", TO_FILE
            Set colVolumes = objWMIDfsService2.ExecQuery("SELECT databaseguid,volumepath FROM DfsrVolumeInfo",,48)
            If blnOutputToTextFile Then
                Set objFile = objFSO.OpenTextFile(strTempFolder & strComputerName & "_DFSR_" & "DBGUIDs.txt", FOR_APPENDING, TRUE)
                objFile.WriteLine(vbCrLf & "Computer:          " & strComputer & vbCrLf & "Replication Group: " & strRGName)
                For Each objVolume in colVolumes
                    objFile.WriteLine "Volume path:       " & objVolume.VolumePath & " Database GUID: " & objVolume.DatabaseGUID
                Next
                objFile.Close
            Else
                Wscript.Echo vbCrLf & "Computer:    " & strComputer
                For Each objVolume in colVolumes
                    Wscript.Echo "Volume path: " & objVolume.VolumePath & " Database GUID: " & objVolume.DatabaseGUID
                Next
            End If
        End If
        objRecordSet.MoveNext
    Loop
    
' ********** This is the old way of doing it that did not work if RGs contained members from more than one domain. ***********
'    
'    objCommand.CommandText = "Select distinguishedname from 'LDAP://" & strDomainDN & "' where objectClass='msdfsr-subscriber' and msdfsr-replicationgroupguid = '" & strRFGUID & "'"
'    objCommand.Properties("Page Size") = 1000
'    objCommand.Properties("Searchscope") = ADS_SCOPE_SUBTREE 
'    dbgPrint objCommand.CommandText, TO_FILE
'    Set objRecordSet = objCommand.Execute
'    CheckForError
'    objRecordSet.MoveFirst
'    
'    Do Until objRecordSet.EOF	
'        strDN = objRecordSet.Fields("distinguishedname").Value
'        Set objSubscriber = GetObject("LDAP://" & strDN)
'        Set objSubscriberParent = GetObject(objSubscriber.Parent)
'        Set objSubscriberGrandParent = GetObject(objSubscriberParent.Parent)
'        strComputer = objSubscriberGrandParent.dnshostname
'        dbgPrint "strComputer = " & strComputer, TO_FILE
'        CheckForError
'        If Err = 0 Then
'            dbgPrint "Connecting to \root\microsoftDfs namespace on " & strComputer, TO_FILE
'            Set objWMIDfsService2 = GetObject("winmgmts:\\" & strComputer & "\root\microsoftDfs")
'            CheckForError
'            dbgPrint "SELECT databaseguid,volumepath FROM DfsrVolumeInfo", TO_FILE
'            Set colVolumes = objWMIDfsService2.ExecQuery("SELECT databaseguid,volumepath FROM DfsrVolumeInfo")
'            If blnOutputToTextFile Then
'                Set objFile = objFSO.OpenTextFile(strTempFolder & strComputerName & "_DFSR_" & "DBGUIDs.txt", FOR_APPENDING, TRUE)
'                objFile.WriteLine(vbCrLf & "Computer:          " & strComputer & vbCrLf & "Replication Group: " & strRGName)
'                For Each objVolume in colVolumes
'                    objFile.WriteLine "Volume path:       " & objVolume.VolumePath & " Database GUID: " & objVolume.DatabaseGUID
'                Next
'                objFile.Close
'            Else
'                Wscript.Echo vbCrLf & "Computer:    " & strComputer
'                For Each objVolume in colVolumes
'                    Wscript.Echo "Volume path: " & objVolume.VolumePath & " Database GUID: " & objVolume.DatabaseGUID
'                Next
'            End If
'        End If
'        objRecordSet.MoveNext
'    Loop

End Function

Function myADsEncodeBinaryData (arrByte)
    Dim str, s, i
    str = OctetToHexStr (arrByte)
    s = ""
    For i = 1 to Len (str) Step 2
        s = s & "\" & Mid (str, i, 2)
    Next
    myADsEncodeBinaryData = s
End Function

Function OctetToHexStr (arrbytOctet)
    Dim k
    OctetToHexStr = ""
    For k = 1 To Lenb (arrbytOctet)
        OctetToHexStr = OctetToHexStr & Right("0" & Hex(Ascb(Midb(arrbytOctet, k, 1))), 2)
    Next
End Function

Sub ShowUsage
    dbgPrint     vbCrLf & "Usage: dfsrinfo.vbs [<switches>]" & vbCrLf & _
                 vbCrLf & "The following information is collected from the local machine if no switches are specified:" & vbCrLf &_
                 vbCrLf & "   DFSR debug logs/DFS Management snap-in trace log" &_
                 vbCrLf & "   DFSR health reports" &_
                 vbCrLf & "   List of DFSR hotfixes and if they are installed or not" &_
                 vbCrLf & "   List of DFSR binaries and their versions" &_
                 vbCrLf & "   List of DFSR database GUIDs" &_
                 vbCrLf & "   List of DFSR conflicts and deletes" &_
                 vbCrLf & "   DFSR performance data" &_
                 vbCrLf & "   DFSR and TCPIP registry keys" &_                 
                 vbCrLf & "   DFSR, Directory Service, System, and Application event logs" &_
                 vbCrLf & "   MSINFO32 .NFO file" &_
                 vbCrLf & "   DFSR Replica/Volume XML files" &_
                 vbCrLf & "   Additional information about DFS Replication (replication groups, connection status, schedules, and so on.)" & vbCrLf &_
                 vbCrLf & "   /NoReports      Skips health report creation." & vbCrLf &_
                 vbCrLf & "   /NoDebugLogs    Skips health report creation." & vbCrLf &_
                 vbCrLf & "   /NoEvents       Skips event log collection." & vbCrLf &_
                 vbCrLf & "   /NoMSINFO32     Skips MSINFO32 .NFO file creation." & vbCrLf &_
                 vbCrLf & "   /NoDBGUIDs      Skips enumeration of DFSR database GUIDs." & vbCrLf &_
                 vbCrLf & "   /NoLogFileCheck Skips check for recommended MaxDebugLogfiles setting." & vbCrLf &_
                 vbCrLf & "   /Q or /QUICK    Same as /NoReports + /NoMSINFO32 + /NoDBGUIDs + /NoLogFileCheck + /NoDebugLogs + /NoEvents." & vbCrLf &_
                 vbCrLf & "   /Hotfixes       Only shows hotfix check results to screen." & vbCrLf &_
                 vbCrLf & "   /GetDBGUIDs     Only shows DFSR database GUIDs for all servers in the specified replication group." & vbCrLf &_
                 vbCrLf & "   dfsrinfo.vbs /getdbguids /rgname:<rgname>" & vbCrLf &_
                 vbCrLf & "The following switches are supported for configuring DFS Replication parameters:" & vbCrLf &_
                 vbCrLf & "   /EnableDfsmgmtTracing:<TRUE/FALSE>" &_
                 vbCrLf & "   /EnableVerboseEventLogging:<TRUE/FALSE>" &_
                 vbCrLf & "   /ConflictHighWatermarkPercent:<80-100>" &_
                 vbCrLf & "   /ConflictLowWatermarkPercent:<10-80>" &_
                 vbCrLf & "   /DebugLogFilePath:<path>" &_
                 vbCrLf & "   /DebugLogSeverity:<1-5>" &_
                 vbCrLf & "   /Description:<description>" &_
                 vbCrLf & "   /DsPollingIntervalInMin:<1-MAXDWORD>" &_
                 vbCrLf & "   /EnableDebugLog:<TRUE/FALSE>" &_
                 vbCrLf & "   /EnableLightDsPolling:<TRUE/FALSE>" &_
                 vbCrLf & "   /MaxDebugLogFiles:<1-MAXDWORD>" &_
                 vbCrLf & "   /MaxDebugLogMessages:<1000-MAXDWORD>" &_
                 vbCrLf & "   /RpcPortAssignment:<0-65535>" &_
                 vbCrLf & "   /StagingHighWatermarkPercent:<80-100>" &_
                 vbCrLf & "   /StagingLowWatermarkPercent:<10-80>" & vbCrLf &_
                 vbCrLf & "   MAXDWORD = 4,294,967,295" & vbCrLf, TO_SCREEN
    Wscript.Quit
End Sub

Sub CheckForError
    If Err <> 0 Then
        dbgPrint "[ERROR] " & Err.Source & " " & Err.Number & " " & Err.Description, TO_FILE
        Err.Clear
    End If
End Sub

Function dbgPrint(strErrText, intDbgLevel)
    On Error Resume Next
    If intDbgLevel And TO_SCREEN Then
        Wscript.Echo strErrText
    End If
    If intDbgLevel And TO_FILE Then
        If blnFirstRun Then
            objFSO.DeleteFile "Progress.txt", True
            Set objProgressText = objFSO.CreateTextFile("Progress.txt")
            Set objProgressText = objFSO.OpenTextFile("Progress.txt", 8)
            Wscript.Echo vbCrLf & "DfsrInfo.vbs version " & SCRIPT_VERSION & " clandis@microsoft.com" & vbCrLf
						Wscript.Echo "Writing script debug information to " & objShell.CurrentDirectory & "\Progress.txt" & vbCrLf
            objProgressText.WriteLine Month(Now) & "\" & Day(Now) & "\" & Year(Now) & " " & Hour(Now) & ":" & Minute(Now) & ":" & Second(Now) & " " & "DfsrInfo.vbs Version " & SCRIPT_VERSION & " clandis@microsoft.com"
            objProgressText.WriteLine Month(Now) & "\" & Day(Now) & "\" & Year(Now) & " " & Hour(Now) & ":" & Minute(Now) & ":" & Second(Now) & " " & strErrText
            blnFirstRun = False
            objProgressText.Close
        Else
            Set objProgressText = objFSO.OpenTextFile("Progress.txt", 8)
            objProgressText.WriteLine Month(Now) & "\" & Day(Now) & "\" & Year(Now) & " " & Hour(Now) & ":" & Minute(Now) & ":" & Second(Now) & " " & strErrText
            objProgressText.Close
        End If
    End If
End Function

Function GetClusterInfo
    On Error Resume Next
    For Each objItem in colListOfServices
        If UCase(objItem.Name) = "CLUSSVC" Then
            blnCLUSSVC = True
            Set objClusterTextFile = objFSO.CreateTextFile(strTempFolder & strComputerName & "_" & "Cluster.txt")
            CheckForError
            objClusterTextFile.WriteLine "Cluster Service (CLUSSVC) is installed."
            dbgPrint "Cluster Service (CLUSSVC) is installed", TO_FILE
            If UCase(objItem.State) <> "RUNNING" Then
                objClusterTextFile.WriteLine "Cluster Service (CLUSSVC) is not running."
                dbgPrint "Cluster Service (CLUSSVC) is not running", TO_FILE
            Else
                objClusterTextFile.WriteLine "Cluster Service (ClusSvc) is running." & vbCrLf
                dbgPrint "Cluster Service (CLUSSVC) is running", TO_FILE
                Set objClusWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\MSCluster")
                CheckForError
                Set colClusterResources = objClusWMIService.ExecQuery("Select * from MSCluster_Resource")
                CheckForError
                For Each objClusterResource in colClusterResources
                    If objClusterResource.Type = "DFS Replicated Folder" Then
                        dbgPrint "Detected DFS Replicated Folder cluster resource", TO_FILE
                        objClusterTextFile.WriteLine "Detected DFS Replicated Folder cluster resource:" & vbCrLf
                        objClusterTextFile.WriteLine "Name: " & objClusterResource.Name
                        dbgPrint "Name: " & objClusterResource.Name, TO_FILE
                        objClusterTextFile.Close
                    End If
                Next
            End If
        End If
    Next  
    If blnCLUSSVC <> True Then
        dbgPrint "Cluster Service (CLUSSVC) is not installed", TO_FILE
    End If
End Function

Function CheckFileVersions
    dbgPrint "Checking file versions", TO_FILE
    dbgPrint "Creating file: " & strTempFolder & strComputerName & "_" & "DFSR_File_Versions.txt", TO_FILE
    Set objFileVersionInfo = objFSO.CreateTextFile(strTempFolder & strComputerName & "_" & "DFSR_File_Versions.txt")
    CheckForError
    objFileVersionInfo.WriteLine strCaption & " Service Pack " & strServicePack & " Version " & strOSVersion & vbCrLf
    arrDFSRFiles = Split(strDFSRFiles,",")
    For i = 0 to UBound(arrDFSRFiles)
        If ((arrDFSRFiles(i) = "dfsradmin.exe") And strBuildNumber = "7600") Then
            strFilePath = strWinDir & "\" & arrDFSRFiles(i)
        Else 
            strFilePath = strWinDir & "\system32\" & arrDFSRFiles(i)
        End If
        GetFileInfo strFilePath, strFileVersion
        strFilePathWMI = Replace(strFilePath, "\", "\\")
        Set colItems = objWMIService.ExecQuery("Select Caption,CreationDate,Extension,FileName from CIM_DataFile where Name = '" & strFilePathWMI & "'", , 48)
        For Each objItem In colItems
            strFileName = objItem.Filename & "." & objItem.Extension
            objFileVersionInfo.Write strFileName
            For j = 0 to (20-Len(strFileName))
                objFileVersionInfo.Write " "
            Next
            objFileVersionInfo.Write strFileVersion
            For k = 0 to (45-(Len(strFileVersion)))
                objFileVersionInfo.Write " "
            Next
            arrTemp = Split(WMIDateStringToDate(objItem.CreationDate), " ")
            objFileVersionInfo.WriteLine arrTemp(0)
        Next
    Next
    objFileVersionInfo.WriteLine vbCrLf & strVersionWarning
    objFileVersionInfo.Close
    dbgPrint "Done checking file versions", TO_FILE
End Function

Sub GetFileInfo(ByVal strFilePath, ByRef strFileVersion)
    Dim ClsVI, VI
    Set ClsVI = New CVersionInfo
    Set VI = ClsVI.GetFileVersionInfo(strFilePath)
    Select Case VI.State
        Case 0
            strFileVersion = VI.Value("FileVersion")
        Case 1
            strFileVersion = "Invalid file path."
        Case 2
            strFileVersion = "No .rsrc table listed in section table."
        Case 3
            strFileVersion = "Failed to find version info."
        Case 4
            strFileVersion = "File is not a PE file."
        Case 5
            strFileVersion = "File is a 16-bit executable. There is no file version info. for 16-bit."
    End Select   
End Sub

Class CVersionInfo
	  Private FSOcvi, TScvi, ANumscvi, VIcvi
	   
	  Private Sub Class_Initialize()
	    On Error Resume Next
	         Set FSOcvi = CreateObject("Scripting.FileSystemObject")
	  End Sub
	          
	  Private Sub Class_Terminate()
	    On Error Resume Next
	      Set TScvi = Nothing   '-- just in case.
	      Set FSOcvi = Nothing
	      Set VIcvi = Nothing
	  End Sub
	  
	  '-- The public function in this class: GetFileVersionInfo -----------------------------------------  
	Public Function GetFileVersionInfo(sFilePath)  
	Dim ARetcvi, s1cvi, Pt1cvi, sRes, sBcvi, A1cvi, A4cvi(3), A2cvi(1), LocRes, VLocRes, SizeRes, iOffSet, Boocvi, sVerString, sMarker
	Dim iNum1cvi, iNum2cvi, iReadPt, iNum3cvi, LocAspack, VLocAspack, VIOffset, ReadOffset, BooAspack
	   On Error Resume Next
	     Set VIcvi = Nothing
	     Set VIcvi = New VSInfo
	               If (FSOcvi.FileExists(sFilePath) = False) Then
	                    VIcvi.Init "", 1
	                    Set GetFileVersionInfo = VIcvi  'bad path.
	                    Exit Function
	               End If
	       sRes = ".rsrc"
	       sVerString = "VS_VER"
	       BooAspack = False
	           
	   Set TScvi = FSOcvi.OpenTextFile(sFilePath, 1)
	       s1cvi = TScvi.Read(2048) '-- Read first 2 KB.
	       TScvi.Close
	   Set TScvi = Nothing    
	      A1cvi = GetArray(Mid(s1cvi, 61, 2))  '-- get number value at offset 60 that points to PE signature address.
	      iNum1cvi = (GetNumFromBytes(A1cvi) + 1)     '-- get offset of "PE00"
	      sBcvi = GetByteString(s1cvi, False)  '-- get a workable string with Chr(0) replaced by "*".       
	       sMarker = Mid(sBcvi, iNum1cvi, 4) 
	         If (sMarker <> "PE**") Then
	                 If Left(sMarker, 2) = "NE" Then
	                      VIcvi.Init "", 5
	                    Set GetFileVersionInfo = VIcvi  '-- 16 bit.
	                 Else 
	                      VIcvi.Init "", 4
	                     Set GetFileVersionInfo = VIcvi  '-- no PE signature found.
	                 End If   
	             Exit Function 
	         End If
	          
	     Pt1cvi = InStr(1, sBcvi, sRes)   '-- find .rsrc table.
	         If (Pt1cvi = 0) Then   
	              VIcvi.Init "", 2
	              Set GetFileVersionInfo = VIcvi  'no resource table header found.
	              Exit Function
	         End If
	     Pt1cvi = Pt1cvi + 12  '--  size of raw data is 4 bytes at offset of 16 into the .rsrc table. 
	        A1cvi = GetArray(Mid(s1cvi, Pt1cvi, 12))  '-- get the same string as a numeric array to Read offset numbers.  
	           For iOffSet = 0 to 3
	                A4cvi(iOffSet) = A1cvi(iOffSet)
	           Next
	             VLocRes = GetNumFromBytes(A4cvi) 
	           For iOffSet = 0 to 3
	                A4cvi(iOffSet) = A1cvi(iOffSet + 4)
	           Next
	             SizeRes = GetNumFromBytes(A4cvi) '--size of resource section in bytes.
	           For iOffSet = 0 to 3
	                A4cvi(iOffSet) = A1cvi(iOffSet + 8)
	           Next
	              LocRes = GetNumFromBytes(A4cvi)    '-- offset location of resource section.  
	          Pt1cvi = InStr(1, sBcvi, ".aspack")   '-- find .rsrc table.
	             If (Pt1cvi > 0) Then
	                  BooAspack = True
	                      Pt1cvi = Pt1cvi + 12    '--  virtual offset is first 4 bytes; raw offset is bytes 9-12.
	                      A1cvi = GetArray(Mid(s1cvi, Pt1cvi, 12))                      
	                   For iOffSet = 0 to 3
	                      A4cvi(iOffSet) = A1cvi(iOffSet)
	                   Next
	                     VLocAspack = GetNumFromBytes(A4cvi)             
	                   For iOffSet = 0 to 3
	                      A4cvi(iOffSet) = A1cvi(iOffSet + 8)
	                   Next
	                     LocAspack = GetNumFromBytes(A4cvi) 
	              End If    
	  
	   Boocvi = False
	   Set TScvi = FSOcvi.OpenTextFile(sFilePath, 1)
	      TScvi.Skip LocRes + 12  '-- get number of names from bytes 13,14 in top level "Type" directory.
	        s1cvi = TScvi.Read(2)       '-- Read bytes 13,14 to get number of named resource types.
	          iNum1cvi = Asc(s1cvi)       '-- number of names.
	        s1cvi = TScvi.Read(2)       '-- Read bytes 15,16 to get number of numbered resource types.
	          iNum2cvi = Asc(s1cvi)       '-- number of nums.
	        
	       If (iNum2cvi = 0) Then '-- no numbered entries. have to quit here.
	            TScvi.Close
	            Set TScvi = Nothing
	             VIcvi.Init "", 3
	            Set GetFileVersionInfo = VIcvi  'failed to find version info in resource table.
	            Exit Function
	       End If
	     
	     If (iNum1cvi > 0) Then TScvi.Skip (iNum1cvi * 8) '-- Skip past named entries.
	     iReadPt = LocRes + 16 + (iNum1cvi * 8)  '-- update file offset variable because this will be needed.
	     Boocvi = False
	        For iOffSet = 1 to iNum2cvi
	           s1cvi = TScvi.Read(8)
	           iReadPt = iReadPt + 8
	              If (Asc(s1cvi) = 16) Then  '-- this is version info. entry.
	                 Boocvi = True
	                 Exit For
	              End If
	        Next
	     If (Boocvi = False) Then  '-- have to quit. no version info. entry found.
	         TScvi.Close
	         Set TScvi = Nothing
	          VIcvi.Init "", 3
	        Set GetFileVersionInfo = VIcvi  'failed to find version info in resource table.
	         Exit Function
	     End If
	       
	     A1cvi = GetArray(s1cvi)  '-- get a byte array for version info entry at top level.
	     iOffSet = 0
	     iNum3cvi = 1
	   Do
	       For iNum1cvi = 0 to 2  '-- get offset number to next level from 2nd 4 bytes of entry structure.  
	          A4cvi(iNum1cvi) = A1cvi(iNum1cvi + 4)
	       Next
	            A4cvi(3) = 0
	            iNum2cvi = GetNumFromBytes(A4cvi)        
	       If (A1cvi(7) > 127) Then  '-- high bit was set in entry offset value, so it's just a pointer to another pointer.    
	             iNum2cvi = LocRes + iNum2cvi + 16
	             TScvi.Skip (iNum2cvi - iReadPt)   '- 1)
	             s1cvi = TScvi.Read(8)
	             iReadPt = iReadPt + ((iNum2cvi - iReadPt) + 8)
	             A1cvi = GetArray(s1cvi)
	       Else  '-- this is the offset of version info offset info.! 
	              iOffSet = (iNum2cvi + LocRes)
	              Exit Do
	       End If
	          iNum3cvi = iNum3cvi + 1
	          If (iNum3cvi > 10) Then Exit Do
	   Loop    
	       If (iOffSet = 0) Then  '-- have to quit. no final offset found.       
	            TScvi.Close
	            Set TScvi = Nothing
	             VIcvi.Init "", 3
	            Set GetFileVersionInfo = VIcvi  'failed to find version info in resource table.
	            Exit Function
	       End If
	   TScvi.Skip (iOffSet - iReadPt) 
	   s1cvi = TScvi.Read(8)
	   iReadPt = iReadPt + ((iOffSet - iReadPt) + 8)
	    A1cvi = GetArray(s1cvi)
	       For iNum1cvi = 0 to 3
	         A4cvi(iNum1cvi) = A1cvi(iNum1cvi)
	       Next   
	           VIOffset = GetNumFromBytes(A4cvi)  '--offset of version info. given in .rsrc section.
	           ReadOffset = ((VIOffset - VLocRes) + LocRes)
	       For iNum1cvi = 0 to 3
	         A4cvi(iNum1cvi) = A1cvi(iNum1cvi + 4)
	       Next      
	           SizeRes = GetNumFromBytes(A4cvi)
	    TScvi.Skip (ReadOffset - iReadPt)
	    s1cvi = TScvi.Read(SizeRes)  '-- read out the entire FileVersionInfo data area.
	    TScvi.Close
	  Set TScvi = Nothing
	      sBcvi = GetByteString(s1cvi, True) '-- snip unicode.
	      Pt1cvi = InStr(1, sBcvi, sVerString)                                                           
	           If (Pt1cvi > 0) Then        '-- "VS_VER" was found, so process the string and quit.
	                VIcvi.Init sBcvi, 0
	               Set GetFileVersionInfo = VIcvi  ' ok              
	           ElseIf (BooAspack = True) Then   '-- if "VS_VER" was not found but there is an "aspack" section then try that.
	              ReadOffset = ((VIOffset - VLocAspack) + LocAspack)  '-- calculate a new file version info data offset.           
	                Set TScvi = FSOcvi.OpenTextFile(sFilePath, 1)  '-- The file was closed and is now re-opened here. Keeping the file
	                   TScvi.Skip ReadOffset                            '-- open "just in case" wouldn't have helped because the file pointer
	                     s1cvi = TScvi.Read(SizeRes)                     '-- for this read may be further back thean the pointer was when the file
	                   TScvi.Close                                  '-- was closed. So rather than try to sort out the read point, the file is just
	                Set TScvi = Nothing                        '-- opened fresh and Skip is used.
	                   sBcvi = GetByteString(s1cvi, True) 
	                   Pt1cvi = InStr(1, sBcvi, sVerString) 
	                     If (Pt1cvi > 0) Then     
	                         VIcvi.Init sBcvi, 0
	                         Set GetFileVersionInfo = VIcvi  ' ok
	                     Else  
	                        VIcvi.Init "", 3
	                        Set GetFileVersionInfo = VIcvi  'failed to find version info in resource table.
	                     End If  
	           Else   
	                 VIcvi.Init "", 3
	                 Set GetFileVersionInfo = VIcvi  'failed to find version info in resource table.         
	           End If
	End Function  
	
	'-------------- simplified version of GetByteString For this Class. ---------------------
	Private Function GetByteString(sStr, SnipUnicode)
	  Dim sRet, iLen, iA, iLen2, A2cvi()
	    On Error Resume Next
	      iLen2 = 0
	   If (SnipUnicode = False) Then
	       ReDim A2cvi(len(sStr) - 1)
	        For iLen = 1 to Len(sStr)
	            iA = Asc(Mid(sStr, iLen, 1))
	              If iA = 0 Then iA = 42  '-- converts 0-byte to *
	            A2cvi(iLen - 1) = Chr(iA)
	        Next
	   Else     
	      ReDim A2cvi((len(sStr) \ 2) - 1)
	       For iLen = 1 to Len(sStr) step 2
	             iA = Asc(Mid(sStr, iLen, 1))
	                If iA = 0 Then iA = 42  '-- converts 0-byte to *
	              A2cvi(iLen2) = Chr(iA)
	              iLen2 = iLen2 + 1
	       Next  
	   End If     
	       GetByteString = Join(A2cvi, "")
	End Function
	'-------------------------------- Simplified version of GetArray. -----------------------
	Private Function GetArray(sStr)
	Dim iA, Len1, Len2, AStr()
	  On Error Resume Next
	    Len1 = Len(sStr)
	    ReDim AStr(Len1 - 1)
	     For iA = 1 to Len1
	        AStr(iA - 1) = Asc(Mid(sStr, iA, 1))
	     Next      
	         GetArray = AStr    
	End Function
	'-------------------- return a number from 2 or 4 bytes. ---------------
	Private Function GetNumFromBytes(ABytes)
	   Dim Num1
	    Err.Clear
	        On Error Resume Next
	        GetNumFromBytes = -1
	    Num1 = ABytes(0) + (ABytes(1) * 256)
	      If (UBound(ABytes) = 3) Then
	          Num1 = Num1 + (ABytes(2) * 65536) + (ABytes(3) * 16777216)
	      End If
	    If (Err.number = 0) Then GetNumFromBytes = Num1
	End Function
	  
	End Class
	
	'---------===================== Class SVInfo ========================--------------------------
	
	'-- This class is returned by GetFileVersionInfo in other class. ------------------------
	Class VSInfo
	 Private sFVI, iErr, Char1
	
	Private Sub Class_Initialize()
	  Char1 = Chr(1)
	End Sub
	'-- class receives error code and, hopefully, version info data when this is called by GetFileVersionInfo.
	Public Sub Init(sVInfo, iErrCode)
	  sFVI = sVInfo
	  iErr = iErrCode
	End Sub
	
	'-- State is error code. If State <> 0 then there's no version info.
	'  Possible State values: 0 = success. 1 - invalid file path. 2 - no .rsrc table listed in section table. 
	'  3 - failed to find version info. 4 - not a PE file. 5 - file is a 16-bit executable. ("NE" file rather than "PE")
	Public Property Get State()
	  State = iErr
	End Property
	
	  '----------------- parse version info string to get specific value.
	  '-- call like: s = Cls.Value("Company")
	  '-- possible values: CompanyName FileDescription FileVersion InternalName LegalCopyright OriginalFilename ProductName ProductVersion
	Public Property Get Value(sValName)
	  On Error Resume Next
	    Value = ""
	      If iErr <> 0 Then Exit Property
	    Value = GetInfo(sValName) 
	End Property
	
	Private Function GetInfo(sVal)
	  Dim Pta, Ptb, LenVal, s4
	       On Error Resume Next
	         GetInfo = ""
	    LenVal = Len(sVal) + 1  '-- length of info string: "CompanyName" = 11
	     Pta = InStr(1, sFVI, sVal, 1)  '-- find string name.
	       If (Pta > 0) Then
	          Pta = Pta + LenVal
	          Ptb = InStr((Pta + 1), sFVI, "*")   '-- look for next *. some properties are Name**value** and some are
	            If Ptb > (Pta + 2) Then              '-- Name*value**. So start looking at 3rd character after. If that                      
	               s4 = Mid(sFVI, Pta, (Ptb - Pta))    '-- character is * then it's Name*** which means there's
	               s4 = Replace(s4, "*", "")                                           '--no value for that specific property.
	              If InStr(1, s4, Char1, 0) = 0 Then GetInfo = s4   '-- check for Chr(1) which seems to be found
	           End If                             ' between values. If it's in the string that means there is no value for
	                                               ' this property and function has actually read next property name.
	      End If 
	End Function
End Class

Function GetElapsedTime
    Const SECONDS_IN_DAY = 86400
    Const SECONDS_IN_HOUR = 3600
    Const SECONDS_IN_MINUTE = 60
    Const SECONDS_IN_WEEK = 604800

    dtmEndTime = Timer
    seconds = Round(dtmEndTime - dtmStartTime, 2)
    If seconds < SECONDS_IN_MINUTE Then
        GetElapsedTime = seconds & " seconds "
        Exit Function
    End If
    If seconds < SECONDS_IN_HOUR Then 
        minutes = seconds / SECONDS_IN_MINUTE
        seconds = seconds MOD SECONDS_IN_MINUTE
        GetElapsedTime = Int(minutes) & " minutes " & seconds & " seconds "
        Exit Function
    End If
    If seconds < SECONDS_IN_DAY Then
        hours = seconds / SECONDS_IN_HOUR
        minutes = (seconds MOD SECONDS_IN_HOUR) / SECONDS_IN_MINUTE
        seconds = (seconds MOD SECONDS_IN_HOUR) MOD SECONDS_IN_MINUTE
        GetElapsedTime = Int(hours) & " hours " & Int(minutes) & " minutes " & seconds & " seconds "
        Exit Function
    End If
    If seconds < SECONDS_IN_WEEK Then
        days = seconds / SECONDS_IN_DAY
        hours = (seconds MOD SECONDS_IN_DAY) / SECONDS_IN_HOUR
        minutes = ((seconds MOD SECONDS_IN_DAY) MOD SECONDS_IN_HOUR) / SECONDS_IN_MINUTE
        seconds = ((seconds MOD SECONDS_IN_DAY) MOD SECONDS_IN_HOUR) MOD SECONDS_IN_MINUTE
        GetElapsedTime = Int(days) & " days " & Int(hours) & " hours " & Int(minutes) & " minutes " & seconds & " seconds "
        Exit Function
    End If
End Function

Function RunCommand(strCommand)
    Const TIMEOUT = 3600 ' 3600 seconds = 1 hour timeout interval
    blnTimedout = False
    If IsEmpty(strCommand) = False Then
        dbgPrint "RUNNING:   " & strCommand, TO_FILE
        dtmCommandStartTime = Timer
        Set objExec = objShell.Exec(strCommand)
        CheckForError
        Do While objExec.Status = 0
            Wscript.Sleep 100
            If Timer - dtmCommandStartTime > TIMEOUT Then
                dbgPrint "TERMINATED:  Exceeded " & TIMEOUT & " second timeout interval.", TO_FILE
                objExec.Terminate
                CheckForError
                blnTimedout = True
                Exit Do
            End If
        Loop
        If blnTimedout = False Then
            dbgPrint "COMPLETED: " & Round(Timer - dtmCommandStartTime, 2) & " seconds.", TO_FILE
        End If
    End If
End Function


Sub GetVarInfo(varname)
    Wscript.Echo ""
    Wscript.Echo "VarType   = " & VarType(varname)
    Wscript.Echo "TypeName  = " & TypeName(varname)
    Wscript.Echo "IsArray   = " & IsArray(varname)
    Wscript.Echo "IsDate    = " & IsDate(varname)
    Wscript.Echo "IsEmpty   = " & IsEmpty(varname)
    Wscript.Echo "IsNull    = " & IsNull(varname)
    Wscript.Echo "IsNumeric = " & IsNumeric(varname)
    Wscript.Echo "IsObject  = " & IsObject(varname)
    Wscript.Echo "Count     = " & varname.count
    Wscript.Echo ""
End Sub
'' SIG '' Begin signature block
'' SIG '' MIInuwYJKoZIhvcNAQcCoIInrDCCJ6gCAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' F1CxFZgTecXNFa116BfHu8YEgZ2CNiXX7QhQmZH53fqg
'' SIG '' gg2FMIIGAzCCA+ugAwIBAgITMwAAAlPjg96W3sVuzAAA
'' SIG '' AAACUzANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJV
'' SIG '' UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
'' SIG '' UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
'' SIG '' cmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBT
'' SIG '' aWduaW5nIFBDQSAyMDExMB4XDTIxMDkwMjE4MzMwMFoX
'' SIG '' DTIyMDkwMTE4MzMwMFowdDELMAkGA1UEBhMCVVMxEzAR
'' SIG '' BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
'' SIG '' bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
'' SIG '' bjEeMBwGA1UEAxMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
'' SIG '' MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
'' SIG '' y4cR8KtzoR/uCfkl+Kkv1UBvB8m3HB+7ZxvgVKq17m3x
'' SIG '' rgxWD2dvbgrh30JTtZcoC4DKSeBnoev+qaEOVZAyn1bL
'' SIG '' J+mgNTwsyIfIjjzEPTI7t7CxfUp/j87monuATa6dDLmS
'' SIG '' wxF4FWMdljY5s6nMQu3WPUgt85zoealMtr55lsoAu2/Z
'' SIG '' I9HdyaxrY3OaudFn1d1i1wEB5HkUTrCRQWX1xRqEr0ZY
'' SIG '' xRVAI1P83YT/dj/tSYkUUYpFcv7KiITA2Pu7VXc5RNn8
'' SIG '' Jyjr/S0oYCnshHr4DJdAdRauxNmHgWSheipYZmIvQhNd
'' SIG '' +dHJ01KFOGKUEp2aNGAJ2np0RAy3xRik3QIDAQABo4IB
'' SIG '' gjCCAX4wHwYDVR0lBBgwFgYKKwYBBAGCN0wIAQYIKwYB
'' SIG '' BQUHAwMwHQYDVR0OBBYEFJWaS1iHHF6MXrLAPw0W3tuo
'' SIG '' JYRDMFQGA1UdEQRNMEukSTBHMS0wKwYDVQQLEyRNaWNy
'' SIG '' b3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQx
'' SIG '' FjAUBgNVBAUTDTIzMDAxMis0Njc1OTgwHwYDVR0jBBgw
'' SIG '' FoAUSG5k5VAF04KqFzc3IrVtqMp1ApUwVAYDVR0fBE0w
'' SIG '' SzBJoEegRYZDaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
'' SIG '' L3BraW9wcy9jcmwvTWljQ29kU2lnUENBMjAxMV8yMDEx
'' SIG '' LTA3LTA4LmNybDBhBggrBgEFBQcBAQRVMFMwUQYIKwYB
'' SIG '' BQUHMAKGRWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
'' SIG '' a2lvcHMvY2VydHMvTWljQ29kU2lnUENBMjAxMV8yMDEx
'' SIG '' LTA3LTA4LmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3
'' SIG '' DQEBCwUAA4ICAQClWPsinCVVcX/VtrzZC+bn4zqanL1T
'' SIG '' jjnVco8tXZrDuDvJIVoaq3nHVWadPWnTmfJHDLUNFPqC
'' SIG '' sePOCYNdXHOApNBcjgZ6fmCBWzsWAqs2qjHGkQIMuPJ9
'' SIG '' bW8/xBWIhcyZjIhp5YFhQkrTjT70DgQ9svxI96gUZxsv
'' SIG '' RGUtRA5UTf/JeUbNx19pWYXfVrrpEW1JPN1PfUzycqNd
'' SIG '' nFNDG959Ryb/yWacEsqm9ztKOBxMVSUpMDdZuNn0lSFb
'' SIG '' V1VUmmGYlab99hqA/3cgEv4MqZX0ehSN0ZwjqJs5cnEq
'' SIG '' qM9MwQjxYgjIVYUOqp/idBoYEQSbxios8PuZU35wRaKi
'' SIG '' mSQ0Ts/rhg5fbcOib51agGShq1r/wrGGnoGj3jxawFUs
'' SIG '' QMlMDhU5AKrTQvLgHnvq79lecS8PBX6SieciojCpwiqy
'' SIG '' GhUA6+QGe39noxhg3/vE8zoitQIAbzlt4kxBGv2rfGeP
'' SIG '' rNQppxAJAItHC4we9giXnVNSwLMHTgljNjAyGVaPY9E+
'' SIG '' +DpCS04z3d1jRMsNKwV08oZW2ELGLexJU9pdk05ReRJq
'' SIG '' VYsRrY+AoTY1qCq/ckwKrWnXdmJuRTQe/dhs8DcGut9Q
'' SIG '' TwoASZnEaRSl7dFREKu1F1TWAYgUXfseMr46quWhe1wu
'' SIG '' Z1woI2wpOyF8JjqYTbjQzYkavNxI453O5sayRjCCB3ow
'' SIG '' ggVioAMCAQICCmEOkNIAAAAAAAMwDQYJKoZIhvcNAQEL
'' SIG '' BQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
'' SIG '' aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
'' SIG '' ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMT
'' SIG '' KU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhv
'' SIG '' cml0eSAyMDExMB4XDTExMDcwODIwNTkwOVoXDTI2MDcw
'' SIG '' ODIxMDkwOVowfjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
'' SIG '' Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
'' SIG '' BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYG
'' SIG '' A1UEAxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0Eg
'' SIG '' MjAxMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
'' SIG '' ggIBAKvw+nIQHC6t2G6qghBNNLrytlghn0IbKmvpWlCq
'' SIG '' uAY4GgRJun/DDB7dN2vGEtgL8DjCmQawyDnVARQxQtOJ
'' SIG '' DXlkh36UYCRsr55JnOloXtLfm1OyCizDr9mpK656Ca/X
'' SIG '' llnKYBoF6WZ26DJSJhIv56sIUM+zRLdd2MQuA3WraPPL
'' SIG '' bfM6XKEW9Ea64DhkrG5kNXimoGMPLdNAk/jj3gcN1Vx5
'' SIG '' pUkp5w2+oBN3vpQ97/vjK1oQH01WKKJ6cuASOrdJXtjt
'' SIG '' 7UORg9l7snuGG9k+sYxd6IlPhBryoS9Z5JA7La4zWMW3
'' SIG '' Pv4y07MDPbGyr5I4ftKdgCz1TlaRITUlwzluZH9TupwP
'' SIG '' rRkjhMv0ugOGjfdf8NBSv4yUh7zAIXQlXxgotswnKDgl
'' SIG '' mDlKNs98sZKuHCOnqWbsYR9q4ShJnV+I4iVd0yFLPlLE
'' SIG '' tVc/JAPw0XpbL9Uj43BdD1FGd7P4AOG8rAKCX9vAFbO9
'' SIG '' G9RVS+c5oQ/pI0m8GLhEfEXkwcNyeuBy5yTfv0aZxe/C
'' SIG '' HFfbg43sTUkwp6uO3+xbn6/83bBm4sGXgXvt1u1L50kp
'' SIG '' pxMopqd9Z4DmimJ4X7IvhNdXnFy/dygo8e1twyiPLI9A
'' SIG '' N0/B4YVEicQJTMXUpUMvdJX3bvh4IFgsE11glZo+TzOE
'' SIG '' 2rCIF96eTvSWsLxGoGyY0uDWiIwLAgMBAAGjggHtMIIB
'' SIG '' 6TAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQUSG5k
'' SIG '' 5VAF04KqFzc3IrVtqMp1ApUwGQYJKwYBBAGCNxQCBAwe
'' SIG '' CgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB
'' SIG '' /wQFMAMBAf8wHwYDVR0jBBgwFoAUci06AjGQQ7kUBU7h
'' SIG '' 6qfHMdEjiTQwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDov
'' SIG '' L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVj
'' SIG '' dHMvTWljUm9vQ2VyQXV0MjAxMV8yMDExXzAzXzIyLmNy
'' SIG '' bDBeBggrBgEFBQcBAQRSMFAwTgYIKwYBBQUHMAKGQmh0
'' SIG '' dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMv
'' SIG '' TWljUm9vQ2VyQXV0MjAxMV8yMDExXzAzXzIyLmNydDCB
'' SIG '' nwYDVR0gBIGXMIGUMIGRBgkrBgEEAYI3LgMwgYMwPwYI
'' SIG '' KwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNv
'' SIG '' bS9wa2lvcHMvZG9jcy9wcmltYXJ5Y3BzLmh0bTBABggr
'' SIG '' BgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwAXwBwAG8AbABp
'' SIG '' AGMAeQBfAHMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkq
'' SIG '' hkiG9w0BAQsFAAOCAgEAZ/KGpZjgVHkaLtPYdGcimwuW
'' SIG '' EeFjkplCln3SeQyQwWVfLiw++MNy0W2D/r4/6ArKO79H
'' SIG '' qaPzadtjvyI1pZddZYSQfYtGUFXYDJJ80hpLHPM8QotS
'' SIG '' 0LD9a+M+By4pm+Y9G6XUtR13lDni6WTJRD14eiPzE32m
'' SIG '' kHSDjfTLJgJGKsKKELukqQUMm+1o+mgulaAqPyprWElj
'' SIG '' HwlpblqYluSD9MCP80Yr3vw70L01724lruWvJ+3Q3fMO
'' SIG '' r5kol5hNDj0L8giJ1h/DMhji8MUtzluetEk5CsYKwsat
'' SIG '' ruWy2dsViFFFWDgycScaf7H0J/jeLDogaZiyWYlobm+n
'' SIG '' t3TDQAUGpgEqKD6CPxNNZgvAs0314Y9/HG8VfUWnduVA
'' SIG '' KmWjw11SYobDHWM2l4bf2vP48hahmifhzaWX0O5dY0Hj
'' SIG '' Wwechz4GdwbRBrF1HxS+YWG18NzGGwS+30HHDiju3mUv
'' SIG '' 7Jf2oVyW2ADWoUa9WfOXpQlLSBCZgB/QACnFsZulP0V3
'' SIG '' HjXG0qKin3p6IvpIlR+r+0cjgPWe+L9rt0uX4ut1eBrs
'' SIG '' 6jeZeRhL/9azI2h15q/6/IvrC4DqaTuv/DDtBEyO3991
'' SIG '' bWORPdGdVk5Pv4BXIqF4ETIheu9BCrE/+6jMpF3BoYib
'' SIG '' V3FWTkhFwELJm3ZbCoBIa/15n8G9bW1qyVJzEw16UM0x
'' SIG '' ghmOMIIZigIBATCBlTB+MQswCQYDVQQGEwJVUzETMBEG
'' SIG '' A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
'' SIG '' ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
'' SIG '' MSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5n
'' SIG '' IFBDQSAyMDExAhMzAAACU+OD3pbexW7MAAAAAAJTMA0G
'' SIG '' CWCGSAFlAwQCAQUAoIGwMBkGCSqGSIb3DQEJAzEMBgor
'' SIG '' BgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
'' SIG '' AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAZVrGlFRoFpnbx
'' SIG '' KfSdUXJaxtDwa9c2SBP1keK6IlVZ3jBEBgorBgEEAYI3
'' SIG '' AgEMMTYwNKAUgBIATQBpAGMAcgBvAHMAbwBmAHShHIAa
'' SIG '' aHR0cHM6Ly93d3cubWljcm9zb2Z0LmNvbSAwDQYJKoZI
'' SIG '' hvcNAQEBBQAEggEAnrrObCBmBbxB+R3QWQxJokQLa1qi
'' SIG '' COLL6+59c6aKbIqLQTJ9/Fb9UvYbQd1s73YH7H1CWOOW
'' SIG '' lZDNCU8KTfmpc4N65tHGQhc+9j5GZMovnV4zdRnWXPN6
'' SIG '' m5S7MvFEzBHN7hXZyepXgE5DJIv5EAAJkS1NCTZoK7Xm
'' SIG '' KVOsIRrrcjoIGhG4nDIO+/dX5AJRFixAlKbZPoy/Asjf
'' SIG '' IPFaGWJ2drVgFFnU9Xm3qVJBxDtRRqCcDYHNprJPKwx7
'' SIG '' 5Cr7by9KUcb73Y0lRn6EHXi8XQ+wpelLJiiJOE9jYr3S
'' SIG '' r7EIJWjn2hManr0H7cWd4DR/XQf6N1v8cULnh1yhhY8w
'' SIG '' RLSRQ6GCFxYwghcSBgorBgEEAYI3AwMBMYIXAjCCFv4G
'' SIG '' CSqGSIb3DQEHAqCCFu8wghbrAgEDMQ8wDQYJYIZIAWUD
'' SIG '' BAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIB
'' SIG '' QAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUA
'' SIG '' BCC+K2JPDLVmuUcHO1V6v2JX4nT+GKeiQ1wmkH59h6oT
'' SIG '' zwIGYheYDNQ+GBMyMDIyMDMyODE2NTUxNy41NzdaMASA
'' SIG '' AgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UE
'' SIG '' CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
'' SIG '' MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0w
'' SIG '' KwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRp
'' SIG '' b25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
'' SIG '' RVNOOkQwODItNEJGRC1FRUJBMSUwIwYDVQQDExxNaWNy
'' SIG '' b3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIRZTCCBxQw
'' SIG '' ggT8oAMCAQICEzMAAAGP81Go61py3cwAAQAAAY8wDQYJ
'' SIG '' KoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNV
'' SIG '' BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
'' SIG '' HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
'' SIG '' MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
'' SIG '' IDIwMTAwHhcNMjExMDI4MTkyNzQ2WhcNMjMwMTI2MTky
'' SIG '' NzQ2WjCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
'' SIG '' c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
'' SIG '' BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UE
'' SIG '' CxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBM
'' SIG '' aW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpE
'' SIG '' MDgyLTRCRkQtRUVCQTElMCMGA1UEAxMcTWljcm9zb2Z0
'' SIG '' IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcN
'' SIG '' AQEBBQADggIPADCCAgoCggIBAJlXPv61zxcehZOPgqS6
'' SIG '' 7mw6y02t0LgB0VV7svs7MV8JKIJE9Gvl1rgWm8B8qo/E
'' SIG '' UYmUEL3b2zquTURMTnh4mgrZFLENNhEgHvQs/paATbbH
'' SIG '' wqvOOrt6LVhwiZapLw60q+5jAasHEWO3H4QBny75aTEq
'' SIG '' I6AJ5O0Xo/o3CZ2MSHjd+Bd4fScADWN+tKBmAiEu6Szq
'' SIG '' LFlfm8boPbok2WBP13JcmDRel3c2f8w/+FOacU+DGUJs
'' SIG '' wRrw7PvHA3QP7LWX4/68votF1GDRT4bqnPlCpMJv1zRw
'' SIG '' fgg7BkJfmUtBnG1FLp+FT04RyZupkQMC+cvM6bVhCKHG
'' SIG '' 03kUk5mZ1GtomB9hDgVe3go8dEnW+pC3NcXRUXJA3kBk
'' SIG '' eCdchcsm7mbFD/MdHTrBBKC0LjobipQy0BIOw+mcZmSZ
'' SIG '' 0vAdN3sJP0qVS6rG+ulNqsheAcA7dbmZIxGe34pyKFIE
'' SIG '' s+Ae31i2CHjtjgmMSBNF78LFaKfT70102bRj885h1O+d
'' SIG '' xmqysrjOqGv6mk82L6wH1G+ymIb1UCsRlD5C/fniojOx
'' SIG '' tKnpyQha182T8EVqHHAEd9z4TRLrs8ymRSeA3mkwi4P/
'' SIG '' LitEOEIxUXn+Z+B/tikCBIm2e8yHgV944LKyAm880ptE
'' SIG '' F90kVZmR//wKqfGMZMHKCNVggYs7/OM/XqsEQXUOB2HD
'' SIG '' W0DDAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQU8wbmdGuu
'' SIG '' Sc7ioc6Fm9uX+zcjcbwwHwYDVR0jBBgwFoAUn6cVXQBe
'' SIG '' Yl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZO
'' SIG '' aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
'' SIG '' cmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
'' SIG '' MDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggr
'' SIG '' BgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
'' SIG '' L3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0
'' SIG '' YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/
'' SIG '' BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
'' SIG '' 9w0BAQsFAAOCAgEAzX/TqPc8oQuZ9YwvIlOzSWN/RYs4
'' SIG '' 4cWcCWyWP2LcJ+t6ZTJU0mgaXq2p+eun7kaIxiUr9xMG
'' SIG '' bPka7jlNk/2UQ8eFR3rCx7XJRPBpjDNakzGmTy/CNha0
'' SIG '' Zn+TqKeBqnMTXTRAgQpVWZp9CsxXTzKkWuf9EegpoKiY
'' SIG '' dJrryJopIB7m76IbGrzxMsh0GveBw+PyzSnf2CGgiij8
'' SIG '' /UgOXwGuKYUOBL89mrmPUlJbiHeTCvR+XI1lcAcQr2AA
'' SIG '' /tQlvc+xrISZTY6gb1rSjuidAHpn4Os9vIO6nOxv7Qra
'' SIG '' 5R+P8tu8vrLbsFlzb8HbEndZbweDOtwLjJfWKemrv1xZ
'' SIG '' JxsyTxep/7lkeiYUL84eNCC4Hk4S5mIX/M/mg2+K9jgS
'' SIG '' xtT9gemgk1tmEJLe06VJ8yNHChq9tdwmyrRpPzjiB0rA
'' SIG '' zsWrJnhifhYlCQoldecId2mU/1U/z5C/ROIQwQMBrePR
'' SIG '' vPIEgjtMfY33Q2VnVhmxC15UpgNxD+Hk2Ku0a6JWNOBv
'' SIG '' HxrRdKc7mbuNwNvc2iPZSK+bpSkc/BKEB1OnLtD8VMNA
'' SIG '' fR/HAJL0MWjLpkWf+Hwm6jW+E3D5D3FjiNuEGJb6W7U/
'' SIG '' ad9X5WBJZnOcIxqZQJMv55CXE9B2RDV3p8VrT77eIHKK
'' SIG '' qaXiTwN0v9Q+eyi9+uu3qSK9MldvdBNqLWWwFvAwggdx
'' SIG '' MIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0G
'' SIG '' CSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEG
'' SIG '' A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
'' SIG '' ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
'' SIG '' MTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
'' SIG '' Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIy
'' SIG '' MjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVT
'' SIG '' MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
'' SIG '' ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
'' SIG '' YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
'' SIG '' YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOC
'' SIG '' Ag8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP9
'' SIG '' 7pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveV
'' SIG '' U3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLem
'' SIG '' jkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5
'' SIG '' YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEByd
'' SIG '' Uv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxR
'' SIG '' nOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZht
'' SIG '' aDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss25
'' SIG '' 4o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXN
'' SIG '' xF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2
'' SIG '' K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/
'' SIG '' TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahha
'' SIG '' YQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ug
'' SIG '' poMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzF
'' SIG '' a/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3
'' SIG '' xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEA
'' SIG '' AaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJ
'' SIG '' KwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTu
'' SIG '' MB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBc
'' SIG '' BgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsG
'' SIG '' AQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
'' SIG '' cGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0l
'' SIG '' BAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBT
'' SIG '' AHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQF
'' SIG '' MAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb
'' SIG '' 186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
'' SIG '' bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMv
'' SIG '' TWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsG
'' SIG '' AQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3
'' SIG '' dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29D
'' SIG '' ZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQEL
'' SIG '' BQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+
'' SIG '' TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7
'' SIG '' bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvono
'' SIG '' aeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3Uk
'' SIG '' V7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIR
'' SIG '' XT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKB
'' SIG '' GUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy8
'' SIG '' 7JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Q
'' SIG '' q3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k
'' SIG '' +SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjc
'' SIG '' ZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVX
'' SIG '' VAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+Dvk
'' SIG '' txW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC482
'' SIG '' 2rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0
'' SIG '' W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBj
'' SIG '' U02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC1DCCAj0C
'' SIG '' AQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEG
'' SIG '' A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
'' SIG '' ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
'' SIG '' MS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVy
'' SIG '' YXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBU
'' SIG '' U1MgRVNOOkQwODItNEJGRC1FRUJBMSUwIwYDVQQDExxN
'' SIG '' aWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEw
'' SIG '' BwYFKw4DAhoDFQA+TS+CBHbnSAcHRqAmldFgW0GaaqCB
'' SIG '' gzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
'' SIG '' YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
'' SIG '' VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
'' SIG '' BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
'' SIG '' MA0GCSqGSIb3DQEBBQUAAgUA5exD0jAiGA8yMDIyMDMy
'' SIG '' ODIyMjUyMloYDzIwMjIwMzI5MjIyNTIyWjB0MDoGCisG
'' SIG '' AQQBhFkKBAExLDAqMAoCBQDl7EPSAgEAMAcCAQACAgbu
'' SIG '' MAcCAQACAhJ1MAoCBQDl7ZVSAgEAMDYGCisGAQQBhFkK
'' SIG '' BAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSCh
'' SIG '' CjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAA6sz
'' SIG '' 7zYfVIiwg4efbxIdema52BWPpKinnEJylY8vxohJH4DQ
'' SIG '' CLqdI0HfBYX8G7OLi5AT8zQZRmEFaD7BTjyF4CmYXvCn
'' SIG '' 73oTm6mxjteyxdVwUx4nllxAXSxhsA3l0AftlGctOw9S
'' SIG '' wLN9dUicLb+b79kYCzq85Sy7NJZShyprDeMxggQNMIIE
'' SIG '' CQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
'' SIG '' V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
'' SIG '' A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
'' SIG '' VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
'' SIG '' MAITMwAAAY/zUajrWnLdzAABAAABjzANBglghkgBZQME
'' SIG '' AgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJ
'' SIG '' EAEEMC8GCSqGSIb3DQEJBDEiBCAwPFY6NXBJQRo3uJZX
'' SIG '' 08Y1OmMJsUIiyxH/JnFdPKCuwzCB+gYLKoZIhvcNAQkQ
'' SIG '' Ai8xgeowgecwgeQwgb0EIJdyBU/ixsYLlY4ipttiLZju
'' SIG '' nRQ1lvJ0obujuoPMhccfMIGYMIGApH4wfDELMAkGA1UE
'' SIG '' BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
'' SIG '' BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
'' SIG '' b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
'' SIG '' bWUtU3RhbXAgUENBIDIwMTACEzMAAAGP81Go61py3cwA
'' SIG '' AQAAAY8wIgQg8oo4+dCNGXy+16u42TvFPxx6bjUvLwxJ
'' SIG '' 7AYUGfIg+cQwDQYJKoZIhvcNAQELBQAEggIAcf4veA6J
'' SIG '' mttggBflxBQ3xxTBMg5/4tzQJVY1fwOKDfKZ/KJW/aeo
'' SIG '' ymUZzqL0qj7euaQbULAegiwABOgTgKEffIDFXchw0WLg
'' SIG '' 2AJRdXlvv56zFXe/ZDv3OB3T81oQt23uL0uYDaepNUkB
'' SIG '' 8CxeA1UIwkQx0TLpGJOIUr88If/2Bxu267B8e1LcwT2Y
'' SIG '' xn9e1gySnsWAtewr030N2CPYErDEC42H7k0HykFzFB0S
'' SIG '' GzPQHFJbnT8E5MEpz5xo1Oxdr0gqAbTMfiJbVewlViuw
'' SIG '' 0Fy4heVluiJ6BwtYqD+kZR7tTo3AvXlokysxtYKaAygy
'' SIG '' 8jKRRyctklaNuiVQPfC/AdgRrRtciKfvYrZPvjXAv+A1
'' SIG '' 4fqx7JMOYHZ5JNqo6nFBsi5JtGvXdkG3GsgNdkZSTbCd
'' SIG '' v7je8Gi7/DdlM8YLfsqD221Tqxw1kB4akiSa2tJtHZOo
'' SIG '' V+yqaoltr1DCeDUYnX1/g0cwztpTCida6SnQ1QZIsmgw
'' SIG '' y4pp5RpeObkCbyyigQFk06V7ddROEmB/N3iC5rPqSa8p
'' SIG '' wVz0H99yCbWotF6ouL+FrBiuMTn0PCZNRqylkiPVo6jD
'' SIG '' 8Tj7DaeC6E1Bpg0KCG0AVY/CdU8+rDhnOj/tosZoUyxE
'' SIG '' n5m/+4VSzPQjDKr+d+dvbCwgZ3nj7LLCH3Y/D3I7fkeG
'' SIG '' HFY3KtUNj5C7stI=
'' SIG '' End signature block
