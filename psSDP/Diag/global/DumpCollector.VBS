'************************************************
'DumpCollector.VBS
'Version 4.7.16b
'Date: 08-09-2010
'Author: Andre Teixeira - andret@microsoft.com
'************************************************

Option Explicit
Dim objShell
Dim objFSO

Dim bRestrictNumberOfFiles
Dim bRestrictAge
Dim bCollectWERDumps
Dim bCollectMinidumps
Dim bCollectMemoryDump
Dim bCollectWERFullDumps
Dim bCollectWERMiniDumps
Dim bCollectWERDumpAuxFile
Dim bCollectUserDumps
Dim bCollectTDRDumps
Dim bRestrictDumpSize
Dim bUserDumpExclusionList
Dim arrUserDumpProcessExclusionList
Dim bUserDumpProcessInclusionList
Dim arrUserDumpProcessInclusionList
Dim bReportOnly
Dim bGetDebuggerInfo
Dim intMaxFiles
Dim intMaxAge
Dim lngMaxSize
Dim bUserSelection
Dim objIncFile
Dim bIncludeEventStats
Dim g_LocalFolder
Dim arrMachineAnalyzeQueue, arrMachineCompressedTo
Dim arrUserAnalyzeQueue, arrUserCompressedTo
Dim arrAlertsXML, arrScriptedDiagXML, strHTMLOutputfilename
Dim arrAlertsTXTType, arrAlertsTXTCategory, arrAlertsTXTMessage, arrAlertsTXTRecommendation
Dim objTXTFile, objXMLFile, objWMIService
Dim intCurrentTzBias
Dim objWMIReg
Dim bArgumentFileEnabled
Dim strArgumentFileFilePath
Dim bIsDebuggerPathSet
Dim strDebuggerPath
Dim intWindowsVersion
Dim bDeleteCDBFolder
Dim bGenerateSDP2Alerts
Dim bGenerateScriptedDiagXMLAlerts
Dim bMachineDumpConfigProblemDetected
Dim bDumpCopiedDetected
Dim strComputerName
Dim intCurrentBiasfromWMIDateTime
Dim strSymbol_Path

Const adDBTimeStamp = 135
Const adVarChar = 200
Const ForReading = 1, ForWriting = 2
Const OpenFileMode = -2

Const MAX_AGE_DEFAULT = 30
Const MAX_FILES_DEFAULT = 3
Const MAX_DUMP_SIZE_DEFAULT = 17179869184

Const HKLM = &H80000002
Const HKCU = &H80000001

Const ALERT_INFORMATION = 1
Const ALERT_WARNING = 2
Const ALERT_ERROR = 3
Const ALERT_DUMP_FOUND = 4

Const MACHINE_DUMP = 0
Const USER_DUMP = 1
Const TDR_DUMP = 2

Const DEFAULTDEBUGGERPATH = "c:\debuggers\cdb.exe"

Const ALERT_CATEGORY_MACHINE_DMP_CONF = "Machine memory dump configuration"
Const ALERT_CATEGORY_USER_DMP_CONF = "User dump configuration"
Const ALERT_CATEGORY_USER_DMP_FOUND = "User dump"
Const ALERT_CATEGORY_MACHINE_DMP_FOUND = "Machine memory dump"
Const ALERT_CATEGORY_OTHER = "Other"

Const ALERT_CATEGORY_USER_DMP_COPIED = "User dump copied"
Const ALERT_CATEGORY_MACHINE_DMP_COPIED = "Machine memory dump copied"

Dim bWriteALERT_CATEGORY_MACHINE_DMP_CONF
Dim bWriteALERT_CATEGORY_USER_DMP_CONF
Dim bWriteALERT_CATEGORY_USER_DMP_FOUND
Dim bWriteALERT_CATEGORY_OTHER
Dim bWriteALERT_CATEGORY_USER_DMP_COPIED
Dim bWriteALERT_CATEGORY_MACHINE_DMP_COPIED
Dim bWriteALERT_CATEGORY_MACHINE_DMP_FOUND

Main

Sub Main()
    
    wscript.Echo ""
    wscript.Echo "Dump Collector Script"
    wscript.Echo "Revision 4.7.16b"
    wscript.Echo "2008-2010 Microsoft Corporation"
    wscript.Echo ""
    
    Set objShell = CreateObject("WScript.Shell")
    Set objFSO = CreateObject("Scripting.FileSystemObject")
    
    If Len(ReplaceEnvVars("%PROCESSOR_ARCHITEW6432%")) > 0 Then 'Running in WOW, we need to make sure we start the 64 bit version
        wscript.Echo "Script engine is under WOW. Trying to start it in 64 bit mode..."
        If RunScriptin64BitMode Then
            Exit Sub
        Else
            'Script failed to run in 64-bit mode, let's fallback to 32 bit mode.
            DoWork
        End If
    Else
        DoWork
    End If
    wscript.Echo ""
    wscript.Echo "****** Script Finished ******"
End Sub

Sub DoWork()
    Dim strValidateArguments
   
    g_LocalFolder = objFSO.GetParentFolderName(wscript.ScriptFullName)
    
    strValidateArguments = InitializeAndValidateCommandLineArguments
    
    If (strValidateArguments = "0" Or bArgumentFileEnabled) Then
        If strValidateArguments = "0" Then
            wscript.Echo "Command line arguments:"
            wscript.Echo "-----------------------"
            DisplayArguments
        Else
            Exit Sub
        End If
        If bArgumentFileEnabled Then
            Dim arrArgumentFile, bError, strError
            If ProcessArgumentFile(arrArgumentFile) Then
                wscript.Echo ""
                ProcessArgumentList arrArgumentFile, bError, strError
                If bError Then
                    wscript.Echo "-- Error processing argument file:"
                    wscript.Echo "   " & strError
                    wscript.Echo ""
                End If
                wscript.Echo "User/Command line merged arguments:"
                wscript.Echo "-----------------------------------"
                wscript.Echo ""
                DisplayArguments
            End If
        End If
        Dim strMemDumpLocation, dtTimeStarted, strTXTFile, strXMLFile, strBaseName
                           
        dtTimeStarted = Now
        
        strComputerName = objShell.Environment("PROCESS").Item("COMPUTERNAME")
        strBaseName = strComputerName & "_DumpReport"
        strTXTFile = strBaseName & ".txt"
        strHTMLOutputfilename = strBaseName & ".htm"
    
        wscript.Echo "Creating " & strTXTFile & "..."
        Set objTXTFile = objFSO.OpenTextFile(strTXTFile, ForWriting, True, OpenFileMode)
    
        strXMLFile = objFSO.GetAbsolutePathName(".") & "\" & strBaseName & ".XML"
    
        Set objXMLFile = objFSO.OpenTextFile(strXMLFile, ForWriting, True, OpenFileMode)
        
        objXMLFile.WriteLine "<?xml version='1.0' encoding='iso-8859-1'?>"
        objXMLFile.WriteLine "<Root>"
    
        intCurrentTzBias = ObtainTimeZoneBias
        
        LineOut "Memory dump report from : ", strComputerName, False, True, "Title"
        LineOut "Local time : ", FormatDateTime(Now), False, True, "TimeField"
        
        wscript.Echo ""
        wscript.Echo "Memory dump report from : " & strComputerName
        wscript.Echo "Local time : " & FormatDateTime(Now)
        wscript.Echo ""
        
        bMachineDumpConfigProblemDetected = False
        intCurrentBiasfromWMIDateTime = -1
        
        WriteGeneralInformation
        WritePageFileInfo
        
        CollectMachineDumps
        
        If intWindowsVersion < 6 Then 'PreVista
           CollectWatsonDumps
        Else 'Vista and newer
            CollectSP1WERUserDumps
            CollectWERDumps
        End If
        
        If bGetDebuggerInfo Then
            RunDebuggerOperations
        End If
        
        CheckForKnownIssuesToAlert
        
        WriteAlertsToXML
        objXMLFile.WriteLine "</Root>"
        objXMLFile.Close
        
        CreateHTMLFile
        wscript.Echo "Closing file : '" & strTXTFile & "'"
        
        If bGenerateScriptedDiagXMLAlerts Then WriteAlertsToScriptedDiagXML strBaseName
        
        Set objTXTFile = Nothing
        Set objXMLFile = Nothing
        
        WriteAlertsToTXT (strTXTFile)
        WriteQueuedAlertstoMSDTPLA
        
        If bDeleteCDBFolder Then CleanupCDBFolder
        
        wscript.Echo "Script completed in " & FormatNumber(DateDiff("s", dtTimeStarted, Now), 0) & " seconds."
    Else
        ShowArgumentsSyntax (strValidateArguments)
    End If
End Sub

Sub CleanupCDBFolder()
    On Error Resume Next
    If objFSO.FileExists(strDebuggerPath) Then
        objFSO.DeleteFolder objFSO.GetParentFolderName(strDebuggerPath), True
    End If
End Sub

Sub WriteQueuedAlertstoMSDTPLA()
    If bGenerateSDP2Alerts Then
        If bMachineDumpConfigProblemDetected Then
            AddMSDTPLAAlert ALERT_WARNING, "Memory Dump configuration warnings or errors.", "One or more warnings or errors related to the memory dump configuration of " & strComputerName & " machine were detected.", "Please open the file " & GetMSDTDumpReportURL & " for more information.", 50
        End If
        If bDumpCopiedDetected Then
            AddMSDTPLAAlert ALERT_INFORMATION, "Memory dump.", "One or more memory dumps from " & strComputerName & " machine were copied.", "Please open the file " & GetMSDTDumpReportURL & " for more information about memory dumps.", 200
        End If
    End If
End Sub

Sub WriteAlertsToScriptedDiagXML(strBaseFileName)
    Dim strScriptedDiagXMLFileName, objScriptedDiagXMLFile, strLine
    If Not IsEmpty(arrScriptedDiagXML) Then
        strScriptedDiagXMLFileName = strBaseFileName + "Alerts.XML"
        wscript.Echo "Writing file : '" & strScriptedDiagXMLFileName & "'"
        Set objScriptedDiagXMLFile = objFSO.OpenTextFile(strScriptedDiagXMLFileName, ForWriting, True, OpenFileMode)
        objScriptedDiagXMLFile.WriteLine "<?xml version=""1.0""?><Root>"
        For Each strLine In arrScriptedDiagXML
            objScriptedDiagXMLFile.WriteLine strLine
        Next
        objScriptedDiagXMLFile.WriteLine "</Root>"
        objScriptedDiagXMLFile.Close
    End If
End Sub

Sub AddScriptedDiagAlert(intAlertType, strAlertCategory, strAlertMessage, strAlertRecommendation, intPriority)
    
    Dim strAlertType, strAlertXML
    Dim bWriteScriptedDiagAlert
    If bGenerateScriptedDiagXMLAlerts Then
        bWriteScriptedDiagAlert = False
        
        If (strAlertCategory = ALERT_CATEGORY_MACHINE_DMP_CONF) And (bWriteALERT_CATEGORY_MACHINE_DMP_CONF) Then bWriteScriptedDiagAlert = True
        If (strAlertCategory = ALERT_CATEGORY_USER_DMP_CONF) And bWriteALERT_CATEGORY_USER_DMP_CONF Then bWriteScriptedDiagAlert = True
        If (strAlertCategory = ALERT_CATEGORY_USER_DMP_FOUND) And bWriteALERT_CATEGORY_USER_DMP_FOUND Then bWriteScriptedDiagAlert = True
        If (strAlertCategory = ALERT_CATEGORY_OTHER) And bWriteALERT_CATEGORY_OTHER Then bWriteScriptedDiagAlert = True
        If (strAlertCategory = ALERT_CATEGORY_USER_DMP_COPIED) And bWriteALERT_CATEGORY_USER_DMP_COPIED Then bWriteScriptedDiagAlert = True
        If (strAlertCategory = ALERT_CATEGORY_MACHINE_DMP_COPIED) And bWriteALERT_CATEGORY_MACHINE_DMP_COPIED Then bWriteScriptedDiagAlert = True
        If (strAlertCategory = ALERT_CATEGORY_MACHINE_DMP_FOUND) And bWriteALERT_CATEGORY_MACHINE_DMP_FOUND Then bWriteScriptedDiagAlert = True
        
        If bWriteScriptedDiagAlert Then
            Select Case intAlertType
                Case ALERT_INFORMATION
                    strAlertType = "Informational"
                Case ALERT_WARNING
                    strAlertType = "Warning"
                Case ALERT_ERROR
                    strAlertType = "Error"
                Case Else
                    strAlertType = "Informational"
            End Select
            
            strAlertXML = "<Alert Priority=" & Chr(34) & CStr(intPriority) & Chr(34) & " Type=" & Chr(34) & strAlertType & Chr(34) & " Category=" & Chr(34) & strAlertCategory & Chr(34) & ">" & _
                          "<Objects><Object Type=" & Chr(34) & "System.Management.Automation.PSCustomObject" & Chr(34) & " >" & _
                          "<Property Name=" & Chr(34) & "Message" & Chr(34) & ">" & strAlertMessage & "</Property>" & _
                          iif(Len(strAlertRecommendation) > 0, "<Property Name=" & Chr(34) & "Recommendation" & Chr(34) & ">" & strAlertRecommendation & "</Property>", "") & _
                          "</Object></Objects>" & _
                          "</Alert>"
                          
            AddtoArray arrScriptedDiagXML, strAlertXML
        End If
    End If
End Sub

Sub CheckForKnownIssuesToAlert()
    'I am checking two items here: First is the existence of HP Sysdown Servive and IBM Auto Restart Service
    'as well as checking the version for HPCISSS2.SYS driver and version against Windows Server 2003
    
    Err.Clear
    
    Dim objItem, colItems
    
    On Error Resume Next
    
    OpenWMIService
    
    Set colItems = objWMIService.ExecQuery("Select DisplayName, State, StartMode from Win32_Service where name='sysdown' or name='ibmasrex' or name='ibms6asr'", , 48)
    
    If Err.Number <> 0 Then
        DisplayError "Checking for extended alerts", Err.Number, Err.Description, "Querying Win32_Service WMI class."
    Else
        For Each objItem In colItems
            If LCase(objItem.StartMode) = "auto" Then
                AddXMLAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "Service '<b>" & objItem.DisplayName & "</b>' is configured to automatically start on this machine. This service may cause a memory dump to be either corrupted or not be created.", "" & _
                            "If you are interested to obtain machine memory dumps, please stop and disable this service on this machine or configure this service to do not restart in case of failure to assure the process to generate a memory dump can finish without problems.", 1000
                AddTXTAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "Service '" & objItem.DisplayName & "' is configured to automatically start on this machine. This service may cause a memory dump to be either corrupted or not be created.", "" & _
                            "If you are interested to obtain machine memory dumps, please stop and disable this service on this machine or configure this service to do not restart in case of failure to assure the process to generate a memory dump can finish without problems."
                AddScriptedDiagAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "Service '<b>" & objItem.DisplayName & "</b>' is configured to automatically start on this machine. This service may cause a memory dump to be either corrupted or not be created.", "" & _
                            "If you are interested to obtain machine memory dumps, please stop and disable this service on this machine or configure this service to do not restart in case of failure to assure the process to generate a memory dump can finish without problems.", 1000
                bMachineDumpConfigProblemDetected = True
            ElseIf LCase(objItem.State) = "running" Then 'Service may be disabled but running
                AddXMLAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "Service '<b>" & objItem.DisplayName & "</b>' is running on this machine. This service may cause a memory dump to be either corrupted or not be created.", "" & _
                            "If you are interested in obtaining machine memory dumps, please stop and disable this service on this machine to assure the process to generate a memory dump will be finished without problems.", 1000
                    
                AddTXTAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "Service '" & objItem.DisplayName & "' is running on this machine. This service may cause a memory dump to be either corrupted or not be created.", "" & _
                            "If you are interested in obtaining machine memory dumps, please stop and disable this service on this machine to assure the process to generate a memory dump will be finished without problems."
                
                AddScriptedDiagAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "Service '<b>" & objItem.DisplayName & "</b>' is running on this machine. This service may cause a memory dump to be either corrupted or not be created.", "" & _
                            "If you are interested in obtaining machine memory dumps, please stop and disable this service on this machine to assure the process to generate a memory dump will be finished without problems.", 1000
                
                bMachineDumpConfigProblemDetected = True
                
            End If
        Next
    End If
    
    If intWindowsVersion = 5.2 Then
        Dim strDriverPath, strCompanyName, strFileVersion, strFileDescription
        Dim intMajor, intMinor, intRevision, intSubRevision
        strDriverPath = objFSO.BuildPath(objFSO.GetSpecialFolder(1), "drivers\HPCISSS2.SYS")
        If objFSO.FileExists(strDriverPath) Then
            GetFileInfo strDriverPath, strCompanyName, strFileVersion, strFileDescription
            If Len(strFileDescription) > 0 Then
                GetVersionMajorMinor strFileVersion, intMajor, intMinor, intRevision, intSubRevision
                If (((intMajor = 6) And (intMinor < 8)) Or (intMajor < 6)) Then
                    Set colItems = objWMIService.ExecQuery("Select CSDVersion from Win32_OperatingSystem", , 48)
                    For Each objItem In colItems
                        If LCase(objItem.CSDVersion) = "service pack 2" Then
                            AddXMLAlert ALERT_ERROR, ALERT_CATEGORY_OTHER, "The current version of HPCISSS2.SYS installed in machine is '" & strFileVersion & "'. This version may cause different STOP errors in a Windows Server 2003 where Service Pack 2 is installed.", "" & _
                                        "Please update HPCISSS2.SYS to a newest version. Check article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;940015'>KB 940015</a> for more information about the problem.", 10000
                            
                            AddScriptedDiagAlert ALERT_ERROR, ALERT_CATEGORY_OTHER, "The current version of HPCISSS2.SYS installed in machine is '" & strFileVersion & "'. This version may cause different STOP errors in a Windows Server 2003 where Service Pack 2 is installed.", "" & _
                                        "Please update HPCISSS2.SYS to a newest version. Check article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;940015'>KB 940015</a> for more information about the problem.", 10000
                                
                            AddTXTAlert ALERT_ERROR, ALERT_CATEGORY_OTHER, "The current version of HPCISSS2.SYS installed in machine is '" & strFileVersion & "'. This version may cause different STOP errors in a Windows Server 2003 where Service Pack 2 is installed.", "" & _
                                        "Please update HPCISSS2.SYS to a newest version. Check article KB 940015 for more information about the problem."
                                        
                            AddMSDTPLAAlert ALERT_ERROR, ALERT_CATEGORY_OTHER, "The current version of HPCISSS2.SYS installed in this machine is " & strFileVersion & ". This version is known for causing different STOP errors in a Windows Server 2003 where Service Pack 2 is installed.", "" & _
                                                                                "Please update HPCISSS2.SYS to a newest version. Please open file " & GetMSDTDumpReportURL & " for more information, or consult article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;940015'>KB 940015</a>.", 1
                            
                        End If
                    Next
                End If
            Else
                DisplayError "Checking for extended alerts", 5000, "", "Obtaining version information HPCISSS2.SYS."
            End If
        End If
    End If

    If intWindowsVersion = 5.2 Then
        strDriverPath = objFSO.BuildPath(objFSO.GetSpecialFolder(1), "drivers\mpio.sys")
        
        If objFSO.FileExists(strDriverPath) Then
            'Check if cluster service is enabled:
            Dim intRegValue
            intRegValue = 99
            intRegValue = objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ClusSvc\Start")
            If intRegValue < 4 Then
                GetFileInfo strDriverPath, strCompanyName, strFileVersion, strFileDescription
                If Len(strFileVersion) > 0 Then
                    GetVersionMajorMinor strFileVersion, intMajor, intMinor, intRevision, intSubRevision
                    wscript.Echo strDriverPath & " detected with version " & strFileVersion
                    If ((intMajor = 1) And (intMinor <= 21)) Then
                    
                        AddXMLAlert ALERT_WARNING, ALERT_CATEGORY_OTHER, "MPIO.SYS version " & strFileVersion & " was detected on this system. This version may cause non-paged pool memory leaks (tag MPIO) on Windows Server 2003 Clusters machine.", "" & _
                                    "We recommend you to upgrade MPIO.SYS to a newest version. Please review the following article for more information about the problem: <a target='_blank' href='http://support.microsoft.com/kb/961640'>KB 961640</a>.", 8000
                                        
                        AddScriptedDiagAlert ALERT_WARNING, ALERT_CATEGORY_OTHER, "MPIO.SYS version " & strFileVersion & " was detected on this system. This version may cause non-paged pool memory leaks (tag MPIO) on Windows Server 2003 Clusters machine.", "" & _
                                    "We recommend you to upgrade MPIO.SYS to a newest version. Please review the following article for more information about the problem: <a target='_blank' href='http://support.microsoft.com/kb/961640'>KB 961640</a>.", 8000
                        
                        AddTXTAlert ALERT_WARNING, ALERT_CATEGORY_OTHER, "MPIO.SYS version " & strFileVersion & " was detected on this system. This version may cause non-paged pool memory leaks (tag MPIO) on Windows Server 2003 Clusters machine.", "" & _
                                    "We recommend you to upgrade MPIO.SYS to a newest version. Please review the following article for more information about the problem: KB 961640."
        
                        AddMSDTPLAAlert ALERT_WARNING, ALERT_CATEGORY_OTHER, "MPIO.SYS version " & strFileVersion & " was detected on this system. This version may cause non-paged pool memory leaks (tag MPIO) on Windows Server 2003 Clusters machine.", "" & _
                                    "We recommend you to upgrade MPIO.SYS to a newest version. Please open the file " & GetMSDTDumpReportURL & " or review article <a target='_blank' href='http://support.microsoft.com/kb/961640'>KB 961640</a>.", 10
        
                    End If
                End If
            End If
        End If
    End If
End Sub

Sub GetVersionMajorMinor(strVersionString, ByRef intMajor, ByRef intMinor, ByRef intRevision, ByRef intSubRevision)
    Dim intSepStart, intSepEnd, x, strNumber, intAsc
    strNumber = ""
    intMajor = -1
    intMinor = -1
    intRevision = -1
    intSubRevision = -1
    
    For x = 1 To Len(strVersionString)
        intAsc = Asc(Mid(strVersionString, x, 1))
        If ((intAsc >= 48) And (intAsc <= 57)) Then
            strNumber = strNumber & Mid(strVersionString, x, 1)
        ElseIf (intAsc = 44) Or (intAsc = 46) Or (intAsc = 58) Then 'Separator
            If intMajor = -1 Then
                intMajor = CLng(strNumber)
            ElseIf intMinor = -1 Then
                intMinor = CLng(strNumber)
            ElseIf intRevision = -1 Then
                intRevision = CLng(strNumber)
            ElseIf intSubRevision = -1 Then
                intSubRevision = CLng(strNumber)
            End If
            strNumber = ""
        ElseIf (intAsc = 40) Or ((intAsc >= 65) And (intAsc <= 126)) Then 'End of line
            If strNumber <> "" Then
                If intMajor = -1 Then
                    intMajor = CLng(strNumber)
                ElseIf intMinor = -1 Then
                    intMinor = CLng(strNumber)
                ElseIf intRevision = -1 Then
                    intRevision = CLng(strNumber)
                ElseIf intSubRevision = -1 Then
                    intSubRevision = CLng(strNumber)
                End If
                strNumber = ""
            End If
            Exit Sub
        End If
    Next
    
    If strNumber <> "" Then
        If intMajor = -1 Then
            intMajor = CLng(strNumber)
        ElseIf intMinor = -1 Then
            intMinor = CLng(strNumber)
        ElseIf intRevision = -1 Then
            intRevision = CLng(strNumber)
        ElseIf intSubRevision = -1 Then
            intSubRevision = CLng(strNumber)
        End If
        strNumber = ""
    End If

    If intMajor = -1 Then intMajor = 0
    If intMinor = -1 Then intMinor = 0
    If intRevision = -1 Then intRevision = 0
    If intSubRevision = -1 Then intSubRevision = 0
    
End Sub

Sub DisplayAlertforSTOP0xAB(strBugcheckCode, strFirstArgument, strSecondArgument, strThirdArgument, strFourthArgument, strFileAge, strDumpFile, x, strCompressedTo)
    On Error Resume Next
    Dim strRecommendationToAddXML, strRecommendationToAddTXT, bDisplayGenericAlert, colItems, objItem, strMSGToAddXML, strMSGToAddTXT, strMSGToAddScriptedDiagXML
    If Len(strCompressedTo) > 0 Then
        strMSGToAddXML = ". Dump compressed to " & ObtainURLForExternalFiles(objFSO.GetFileName(strCompressedTo), 1) & ""
        strMSGToAddScriptedDiagXML = ". Dump compressed to " & ObtainURLForExternalFiles(objFSO.GetFileName(strCompressedTo), 2) & ""
        strMSGToAddTXT = ". Dump compressed to " & objFSO.GetFileName(strCompressedTo) & ""
    Else
        strMSGToAddXML = ""
        strMSGToAddTXT = ""
    End If
    If intWindowsVersion = 5.2 Then
        Dim strDriverPath, strCompanyName, strFileVersion, strFileDescription
        Dim intMajor, intMinor, intRevision, intSubRevision
        strDriverPath = objFSO.BuildPath(objFSO.GetSpecialFolder(1), "win32k.sys")
        If objFSO.FileExists(strDriverPath) Then
            GetFileInfo strDriverPath, strCompanyName, strFileVersion, strFileDescription
            GetVersionMajorMinor strFileVersion, intMajor, intMinor, intRevision, intSubRevision
            If Len(strFileDescription) > 0 Then
                Set colItems = objWMIService.ExecQuery("Select CSDVersion from Win32_OperatingSystem", , 48)
                For Each objItem In colItems
                    Select Case LCase(objItem.CSDVersion)
                        Case "service pack 2"
                            If intSubRevision < 4403 Then
                                strRecommendationToAddXML = " The current version for Win32k.sys is " & strFileDescription & ". The recommended version for Windows Server 2003 SP2 is from <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;959466'>KB 959466</a> or newer." & _
                                                 "Check <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;951749'>KB 951749</a> for more information."
                                strRecommendationToAddTXT = " The recommended version for Windows Server 2003 SP2 is from KB 959466 or newer. Check KB 951749 for more information."
                            End If
                        Case "service pack 1"
                            If intSubRevision < 3239 Then
                                strRecommendationToAddXML = " The current version for Win32k.sys is " & strFileDescription & ". The recommended version for Windows Server 2003 SP1 is from <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;959466'>KB 959466</a> or newer." & _
                                                 "Check <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;951749'>KB 951749</a> for more information."
                                strRecommendationToAddTXT = " The recommended version for Windows Server 2003 SP1 is from KB 959466 or newer. Check KB 951749 for more information."
                            End If
                    End Select
                Next
            End If
        End If
    End If
    AddXMLAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_MACHINE_DMP_FOUND, "Machine memory dump from <b>" & strFileAge & " ago</b> was found in " & strDumpFile & ". This dump is a <b>Stop error " & _
        "<font color='red'>0x" & strBugcheckCode & "</font> (" & strFirstArgument & ", " & strSecondArgument & ", " & strThirdArgument & ", " & strFourthArgument & "))</b>. Most of STOP error 0xAB are caused by a problem with <i>win32k.sys</i> driver" & strMSGToAddXML & ".", "" & _
        "Check more information about this memory dump <a href=" & Chr(34) & "#" & strDumpFile & Chr(34) & ">here</a>. The current version of win32k.sys driver is " & strFileVersion & " - please certify this is the latest version." & strRecommendationToAddXML, 100 - x
    
    AddScriptedDiagAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_MACHINE_DMP_FOUND, "Machine memory dump from <b>" & strFileAge & " ago</b> was found in " & strDumpFile & ". This dump is a <b>Stop error " & _
        "<font color='red'>0x" & strBugcheckCode & "</font> (" & strFirstArgument & ", " & strSecondArgument & ", " & strThirdArgument & ", " & strFourthArgument & "))</b>. Most of STOP error 0xAB are caused by a problem with <i>win32k.sys</i> driver" & strMSGToAddScriptedDiagXML & ".", "" & _
        "Check more information about this memory dump <a href=" & Chr(34) & "#" & strDumpFile & Chr(34) & ">here</a>. The current version of win32k.sys driver is " & strFileVersion & " - please certify this is the latest version." & strRecommendationToAddXML, 100 - x
        
    AddTXTAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_MACHINE_DMP_FOUND, "Machine memory dump from " & strFileAge & " ago was found in " & strDumpFile & ". This dump is from a Stop error 0x" & _
        strBugcheckCode & " (" & strFirstArgument & ", " & strSecondArgument & ", " & strThirdArgument & ", " & strFourthArgument & "). Most of STOP error 0xAB are caused by a problem with win32k.sys driver" & strMSGToAddTXT & ".", "" & _
        "Check more information about this memory dump below. The current version of win32k.sys driver is " & strFileVersion & " - please certify this is the latest version." & strRecommendationToAddTXT
End Sub

Sub DisplayArguments()
    
    Dim x
    If bCollectMemoryDump Then
        wscript.Echo "   Copy Memory Dumps"
    End If
    If bCollectMinidumps Then
        wscript.Echo "   Copy Mini Machine Dumps"
    End If
    If bCollectTDRDumps Then
        wscript.Echo "   Copy Timeout Detection and Recovery (TDR) Dumps"
    End If
    If bCollectWERMiniDumps Then
        wscript.Echo "   Copy Windows Error Reporting minidumps"
    End If
    If bCollectWERFullDumps Then
        wscript.Echo "   Copy Windows Error Reporting full dumps"
    End If
    If bCollectWERDumpAuxFile Then
        wscript.Echo "   Copy other Windows Error Reporting files"
    End If
    
    If bUserDumpExclusionList Then
        If UBound(arrUserDumpProcessExclusionList) = 0 Then
            wscript.Echo "   Do not copy user dumps from: " & arrUserDumpProcessExclusionList(0) & ""
        Else
            wscript.Echo "   Do not copy user dumps from: " & arrUserDumpProcessExclusionList(0)
            For x = 1 To UBound(arrUserDumpProcessExclusionList)
                wscript.Echo "                                " & arrUserDumpProcessExclusionList(x)
            Next
        End If
    End If
    
    If bUserDumpProcessInclusionList Then
        If UBound(arrUserDumpProcessInclusionList) = 0 Then
            wscript.Echo "   Copy user dumps only from: " & arrUserDumpProcessInclusionList(0) & ""
        Else
            wscript.Echo "   Copy user dumps files only from: " & arrUserDumpProcessInclusionList(0)
            For x = 1 To UBound(arrUserDumpProcessInclusionList)
                wscript.Echo "                                    " & arrUserDumpProcessInclusionList(x)
            Next
        End If
    End If
    
    If bCollectUserDumps Then
        wscript.Echo "   Copy DrWatson / Windows Error Reporting User Dumps"
    End If
    If bReportOnly Then
        wscript.Echo "   Report only - do not copy any memory dump file"
    End If
    
    If bGetDebuggerInfo Then
        wscript.Echo "   Obtain Debugger information from dumps"
        If bIsDebuggerPathSet Then
                wscript.Echo "   Debugger Path:"
                wscript.Echo "         " & strDebuggerPath
        End If
    End If
    
    If bRestrictAge Then
        wscript.Echo "   Maximum file age                      : " & CStr(intMaxAge) & " days"
    End If
    
    If bRestrictNumberOfFiles Then
        wscript.Echo "   Maximum number of files per collection: " & CStr(intMaxFiles)
    End If
    
    If bRestrictDumpSize Then
        wscript.Echo "   Maximum dump file size                : " & CStr(lngMaxSize / 1024 / 1024) & " MB"
    End If

    If bGenerateSDP2Alerts Then
        wscript.Echo "   Generate MSDT 2.x Alerts"
    End If
    
    If bGenerateScriptedDiagXMLAlerts Then
        wscript.Echo "   Generate Scripted Diagnostic XML Alerts"
    End If
    
    If Not (bWriteALERT_CATEGORY_MACHINE_DMP_CONF And bWriteALERT_CATEGORY_USER_DMP_CONF And bWriteALERT_CATEGORY_USER_DMP_FOUND And bWriteALERT_CATEGORY_OTHER And bWriteALERT_CATEGORY_USER_DMP_COPIED And bWriteALERT_CATEGORY_MACHINE_DMP_COPIED) Then
        wscript.Echo "   Do not generate external (MSDT/ Scripted Diagnostic) alerts for the following categories:"
        If bWriteALERT_CATEGORY_MACHINE_DMP_CONF Then wscript.Echo "       - Machine memory dump configuration"
        If bWriteALERT_CATEGORY_USER_DMP_CONF Then wscript.Echo "       - User memory dump configuration"
        If bWriteALERT_CATEGORY_USER_DMP_FOUND Then wscript.Echo "       - User memory dump found"
        If bWriteALERT_CATEGORY_OTHER Then wscript.Echo "       - Other"
        If bWriteALERT_CATEGORY_USER_DMP_COPIED Then wscript.Echo "       - User memory dump was copied"
        If bWriteALERT_CATEGORY_MACHINE_DMP_COPIED Then wscript.Echo "       - Machine memory dump was copied"
        If bWriteALERT_CATEGORY_MACHINE_DMP_FOUND Then wscript.Echo "       - Machine memory dump was found"
    End If
    
    wscript.Echo ""
End Sub

Sub CollectMachineDumps()
    OpenTag "Session"
    LineOut " -- Machine memory dumps file information", "", False, False, "SessionTitle"
    LineOut "", "", True, False, ""
    CollectMachineMemoryDMP
    CollectMachineMiniDumps
    CollectTDRDumps
    CloseTag "Session"
End Sub

Function ProcessArgumentFile(ByRef arrUserArgumentList)
    'Arguments in user file should be separated by a ';'
    On Error Resume Next
    Err.Clear
    
    Dim objArgumentFileFile
    
    wscript.Echo "Using argument file: '" & UCase(objFSO.GetFileName(strArgumentFileFilePath)) & "'"
    
    Set objArgumentFileFile = objFSO.OpenTextFile(strArgumentFileFilePath)
    
    If Err.Number = 0 Then
            While Not objArgumentFileFile.AtEndOfStream
                If IsEmpty(arrUserArgumentList) Then
                    arrUserArgumentList = Split(objArgumentFileFile.ReadLine, ";")
                Else
                    arrUserArgumentList = AddtoArray(arrUserArgumentList, Split(objArgumentFileFile.ReadLine, ";"))
                End If
                ProcessArgumentFile = True
            Wend
        Else
            ProcessArgumentFile = False
        End If
        
    objArgumentFileFile.Close
End Function

Function RunScriptin64BitMode()
    On Error Resume Next
    Dim strCmdArguments
    Dim strStdOutFilename
    Dim objStdoutFile
    Dim strArguments, x
    If LCase(objFSO.GetExtensionName(wscript.ScriptFullName)) = "vbs" Then
        strStdOutFilename = objFSO.GetSpecialFolder(2) & objFSO.GetFileName(wscript.ScriptFullName) & ".log"
        strArguments = ""
        If wscript.Arguments.Count > 0 Then
            For x = 0 To wscript.Arguments.Count - 1
                strArguments = strArguments & " " & Chr(34) & wscript.Arguments(x) & Chr(34) & " "
            Next
        End If
        strCmdArguments = "/c " & objFSO.GetDriveName(wscript.ScriptFullName) & " & cd " & Chr(34) & objFSO.GetParentFolderName(wscript.ScriptFullName) & Chr(34) & " & cscript.exe " & Chr(34) & wscript.ScriptFullName & Chr(34) & strArguments & " > " & Chr(34) & strStdOutFilename & Chr(34)
        ProcessCreate ReplaceEnvVars("%windir%\System32\CMD.EXE"), strCmdArguments
        If objFSO.FileExists(strStdOutFilename) Then
            Set objStdoutFile = objFSO.OpenTextFile(strStdOutFilename, ForReading, False, -2)
            While Not objStdoutFile.AtEndOfStream
                wscript.Echo objStdoutFile.ReadLine
            Wend
            objStdoutFile.Close
            Set objStdoutFile = Nothing
            objFSO.DeleteFile strStdOutFilename, True
            If Err.Number = 0 Then
                RunScriptin64BitMode = True
            End If
        Else
            wscript.Echo "An error ocurred running the command and resulting file was not created:"
            wscript.Echo ReplaceEnvVars("%windir%\System32\CMD.EXE") & strCmdArguments
            wscript.Echo ""
            wscript.Echo ""
            RunScriptin64BitMode = False
        End If
    Else
        RunScriptin64BitMode = False
    End If
End Function

Function ObtainTimeZoneBias()
    ' Obtain local Time Zone bias from machine registry.
    Dim lngBiasKey, lngBias, k
    
    lngBiasKey = objShell.RegRead("HKLM\System\CurrentControlSet\Control\TimeZoneInformation\ActiveTimeBias")
      
    If UCase(TypeName(lngBiasKey)) = "LONG" Then
      lngBias = lngBiasKey
    ElseIf UCase(TypeName(lngBiasKey)) = "VARIANT()" Then
      lngBias = 0
      For k = 0 To UBound(lngBiasKey)
        lngBias = lngBias + (lngBiasKey(k) * 256 ^ k)
      Next
    End If
    ObtainTimeZoneBias = lngBias
End Function
Function CollectSP1WERUserDumps()
    'New in Vista SP1 and Server 2008, users can configure machine to generate user dumps from process crashes.
    
    'Check http://msdn.microsoft.com/en-us/library/bb787181(VS.85).aspx for more details
    'This routine also copy dumps from System, Network Service and Local Service accounts when path is the Default.
    
    wscript.Echo ""
    wscript.Echo "Windows Error Reporting Process User Dumps"
    wscript.Echo "------------------------------------------"
        
    Dim strDumpFolder, intDumpAge, arrDumpFiles, arrDateDumpFiles
    
    Const WERMachineKey = "HKLM\Software\Microsoft\Windows\Windows Error Reporting"
    Const DEFAULTDUMPFOLDER = "%LOCALAPPDATA%\CrashDumps"
    
    Dim arrAppWerDumpFolders
    
    If RegKeyExists(WERMachineKey & "\LocalDumps") Then
        On Error Resume Next
        strDumpFolder = DEFAULTDUMPFOLDER
        strDumpFolder = objShell.RegRead(WERMachineKey & "\LocalDumps\DumpFolder")
        
        If objFSO.FolderExists(ReplaceEnvVars(strDumpFolder)) Then AddtoArray arrAppWerDumpFolders, ReplaceEnvVars(strDumpFolder)
        
        If LCase(strDumpFolder) = LCase(DEFAULTDUMPFOLDER) Then 'From: http://msdn.microsoft.com/en-us/library/bb787181(VS.85).aspx
            'If value is default, we need to search to System and Network Profiles Local Application Data folders
            Dim strAppDataLocation, strProfile
            
            strAppDataLocation = ReplaceEnvVars(objShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\FolderDescriptions\{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}\RelativePath")) 'Local AppData
            strAppDataLocation = objFSO.BuildPath(strAppDataLocation, "CrashDumps")
            strProfile = ReplaceEnvVars(objShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-18\ProfileImagePath")) 'System Account
            
            strDumpFolder = objFSO.BuildPath(strProfile, strAppDataLocation)
            If objFSO.FolderExists(strDumpFolder) Then AddtoArray arrAppWerDumpFolders, strDumpFolder
            
            strProfile = ReplaceEnvVars(objShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-20\ProfileImagePath")) 'Network Service
            strDumpFolder = objFSO.BuildPath(strProfile, strAppDataLocation)
            If objFSO.FolderExists(strDumpFolder) Then AddtoArray arrAppWerDumpFolders, strDumpFolder
            
            strProfile = ReplaceEnvVars(objShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-19\ProfileImagePath")) 'Local Service
            strDumpFolder = objFSO.BuildPath(strProfile, strAppDataLocation)
            If objFSO.FolderExists(strDumpFolder) Then AddtoArray arrAppWerDumpFolders, strDumpFolder
            
        End If
    
        'Check if any app specific dump configuration exists.
        Dim arrSubKeys, x, bExists
        arrSubKeys = RegEnumSubKeys(WERMachineKey & "\LocalDumps")
        
        If Not IsNull(arrSubKeys) Then
            Dim strSubKey
            If Not IsNull(arrSubKeys) Then
                For Each strSubKey In arrSubKeys
                    strDumpFolder = DEFAULTDUMPFOLDER
                    strDumpFolder = objShell.RegRead(WERMachineKey & "\LocalDumps\" & strSubKey & "\DumpFolder")
                    If objFSO.FolderExists(strDumpFolder) Then
                        If Not IsArrayMember(arrAppWerDumpFolders, strDumpFolder) Then AddtoArray arrAppWerDumpFolders, strDumpFolder
                    End If
                    
                    If LCase(strDumpFolder) = LCase(DEFAULTDUMPFOLDER) Then 'From: http://msdn.microsoft.com/en-us/library/bb787181(VS.85).aspx
                        'If value is default, we need to search to System and Network Profiles Local Application Data folders
                        strAppDataLocation = ReplaceEnvVars(objShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\FolderDescriptions\{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}\RelativePath")) 'Local AppData
                        strAppDataLocation = objFSO.BuildPath(strAppDataLocation, "CrashDumps")
                        strProfile = ReplaceEnvVars(objShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-18\ProfileImagePath")) 'System Account
                        
                        strDumpFolder = objFSO.BuildPath(strProfile, strAppDataLocation)
                        If objFSO.FolderExists(strDumpFolder) Then If IsArrayMember(arrAppWerDumpFolders, strDumpFolder) Then AddtoArray arrAppWerDumpFolders, strDumpFolder
                        
                        strProfile = ReplaceEnvVars(objShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-20\ProfileImagePath")) 'Network Service
                        strDumpFolder = objFSO.BuildPath(strProfile, strAppDataLocation)
                        If objFSO.FolderExists(strDumpFolder) Then If IsArrayMember(arrAppWerDumpFolders, strDumpFolder) Then AddtoArray arrAppWerDumpFolders, strDumpFolder
                        
                        strProfile = ReplaceEnvVars(objShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-19\ProfileImagePath")) 'Local Service
                        strDumpFolder = objFSO.BuildPath(strProfile, strAppDataLocation)
                        If objFSO.FolderExists(strDumpFolder) Then If IsArrayMember(arrAppWerDumpFolders, strDumpFolder) Then AddtoArray arrAppWerDumpFolders, strDumpFolder
                        
                    End If
                Next
            End If
        End If
    Else
        wscript.Echo " -- " & WERMachineKey & "\LocalDumps registry key does not exist"
    End If
    
    Dim objFile
    If Not IsEmpty(arrAppWerDumpFolders) Then
        For Each strDumpFolder In arrAppWerDumpFolders
            For Each objFile In objFSO.GetFolder(strDumpFolder).Files
                If LCase(objFSO.GetExtensionName(objFile.Path)) = "dmp" Then
                    intDumpAge = DateDiff("d", objFile.DateLastModified, Now)
                    If intDumpAge < intMaxAge Then 'In order to decrease the number of events, we will report only events from a certaing age
                        x = x + 1
                        AddtoArray arrDumpFiles, objFile.Path
                        AddtoArray arrDateDumpFiles, objFile.DateLastModified
                    End If
                End If
            Next
        Next
    End If
    
    Dim intDumpSetNumber
    intDumpSetNumber = 1
    If Not IsEmpty(arrDumpFiles) Then
        OpenTag ("Session")
        LineOut " -- Windows Error Reporting User Dumps", "", False, False, "SessionTitle"
        LineOut "", "", True, False, ""
        Dim objDataList, strProcessName, intDotPos, bCanFireAlert
        bCanFireAlert = True
        If x > 0 Then
            x = 0
            Set objDataList = MultipleSortFilesByFileDate(arrDumpFiles, arrDateDumpFiles)
            Do Until objDataList.EOF
                x = x + 1
                OpenTag "SubSession"
                LineOut " -- File : ", objDataList.Fields.Item("FileName"), False, False, "SessionTitle"
                strProcessName = objFSO.GetFileName(objDataList.Fields.Item("FileName"))
                intDotPos = InStr(1, strProcessName, ".")
                strProcessName = Left(strProcessName, InStr(intDotPos + 1, strProcessName, ".") - 1)
                If CallCompressFiles(objDataList.Fields.Item("FileName"), "UserDump", strProcessName, "Memory dump from process " & strProcessName, intDumpSetNumber, bCanFireAlert, 50) Or (Not bCollectUserDumps) Then
                    intDumpSetNumber = intDumpSetNumber + 1
                Else
                    bCanFireAlert = (x < 4)
                End If
                CloseTag "SubSession"
                objDataList.MoveNext
            Loop
        Else
            'LineOut " -- No Windows Error Reporting data found"
        End If
    
        CloseTag ("Session")
    End If

End Function

Function IsArrayMember(strMemberToCheck, arrArray) 'Check if a member is already part of an array
    Dim bExists, strMember
    IsArrayMember = False
    For Each strMember In arrArray
        If LCase(ReplaceEnvVars(strMember)) = LCase(ReplaceEnvVars(strMemberToCheck)) Then
            IsArrayMember = True
            Exit For
        End If
    Next
End Function

Function CollectWatsonDumps()

    'I am here - Collect watson dumps
    On Error Resume Next
    Dim strRegValue

    Dim strCommonAppData, strUserDrWatsonDumpFile, strDefaultUserDrWatsonDumpFile, strAllUsersDrWatsonDumpFile, arrWatsonDumps
    
    strAllUsersDrWatsonDumpFile = ReplaceEnvVars(objShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Common AppData")) & _
                                "\Microsoft\Dr Watson\user.dmp"
    
    strUserDrWatsonDumpFile = ReplaceEnvVars(objShell.RegRead("HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Local AppData")) & _
                          "\Microsoft\Dr Watson\user.dmp"
    
    strDefaultUserDrWatsonDumpFile = ReplaceEnvVars(objShell.RegRead("HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Local AppData")) & _
                                    "\Microsoft\Dr Watson\user.dmp"
    
    strRegValue = ""
    strRegValue = objShell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DrWatson\CrashDumpFile")
    
    If Len(strRegValue) > 0 Then
        'It is easy now, the user dump is only in one location:
        If objFSO.FileExists(strRegValue) Then
            AddtoArray arrWatsonDumps, strRegValue
        End If
    Else
        'We need to look for user dumps in different folders:
        If objFSO.FileExists(strAllUsersDrWatsonDumpFile) Then
            AddtoArray arrWatsonDumps, strAllUsersDrWatsonDumpFile
        End If
        If objFSO.FileExists(strUserDrWatsonDumpFile) Then
            AddtoArray arrWatsonDumps, strUserDrWatsonDumpFile
        End If
        If objFSO.FileExists(strDefaultUserDrWatsonDumpFile) Then
            AddtoArray arrWatsonDumps, strDefaultUserDrWatsonDumpFile
        End If
    End If
    
    
    Dim objFile, strDumpFile, intDumpAge, arrDumpFiles, arrDateDumpFiles
    If Not IsEmpty(arrWatsonDumps) Then
        For Each strDumpFile In arrWatsonDumps
            Set objFile = objFSO.GetFile(strDumpFile)
            intDumpAge = DateDiff("d", objFile.DateLastModified, Now)
            AddtoArray arrDumpFiles, objFile.Path
            AddtoArray arrDateDumpFiles, objFile.DateLastModified
        Next
    End If
    
    Dim intDumpSetNumber, x, strDumpDescription, bCanBeAlerted
    intDumpSetNumber = 0
    OpenTag ("Session")
    LineOut " -- Dr Watson User Dumps", "", False, False, "SessionTitle"
    LineOut "", "", True, False, ""
    Dim objDataList, strProcessName, intDotPos
    If Not IsEmpty(arrDumpFiles) Then
        bCanBeAlerted = True
        Set objDataList = MultipleSortFilesByFileDate(arrDumpFiles, arrDateDumpFiles)
        Do Until objDataList.EOF
            OpenTag "SubSession"
            LineOut " -- File : ", objDataList.Fields.Item("FileName"), False, False, "SessionTitle"
            
            If bGetDebuggerInfo Then
                Dim bCopyFile
                strProcessName = objFSO.GetFileName(GetProcessPathFromDump(objDataList.Fields.Item("FileName")))
                If Len(strProcessName) > 0 Then
                    strDumpDescription = "Memory dump from process " & strProcessName & " "
                Else
                    strDumpDescription = "Memory dump from process (Unknown) "
                End If
            Else
                strDumpDescription = "Dr. Watson user dump "
            End If
            
            If CallCompressFiles(objDataList.Fields.Item("FileName"), "UserDump", strProcessName, strDumpDescription, intDumpSetNumber, bCanBeAlerted, 50) Or Not (bCollectUserDumps) Then
                intDumpSetNumber = intDumpSetNumber + 1
            Else
                bCanBeAlerted = (x > 4)
            End If
            CloseTag "SubSession"
            objDataList.MoveNext
        Loop
    Else
        LineOut " -- A user dump from Dr. Watson was not found.", "", False, False, "Item"
    End If

    CloseTag ("Session")
    
End Function

Function CollectWERDumps()
    Dim strMiniDumpFolder
    Dim objFolder, objSubFolder
    Dim objFile, strWERUserfolder, intEventAge
    Dim arrWerFiles, strWERmachinefolder
    Dim arrWerFileEventTime, varWEREventTime
    Dim x, intDumpSetNumer
    
    Dim objDataList
    
    On Error Resume Next

    wscript.Echo ""
    wscript.Echo "Windows Error Reporting Dumps"
    wscript.Echo "-----------------------------"
    
    strWERmachinefolder = objShell.Environment("PROCESS").Item("ALLUSERSPROFILE") & _
                          "\Microsoft\Windows\WER"
                          
    strWERUserfolder = objShell.Environment("PROCESS").Item("LOCALAPPDATA") & _
                          "\Microsoft\Windows\WER"
                          
    If Not objFSO.FolderExists(strWERUserfolder) Then
        strWERUserfolder = objShell.Environment("PROCESS").Item("APPDATA") & _
                          "\Microsoft\Windows\WER"
    End If
                              
    x = -1
    If objFSO.FolderExists(strWERmachinefolder) Then
        For Each objSubFolder In objFSO.GetFolder(strWERmachinefolder).SubFolders
            For Each objFolder In objSubFolder.SubFolders
                For Each objFile In objFolder.Files
                    If LCase(objFSO.GetExtensionName(objFile.Path)) = "wer" Then
                        varWEREventTime = GetEventTimefromWERfile(objFile.Path)
                        intEventAge = DateDiff("d", varWEREventTime, Now)
                        If intEventAge < intMaxAge Then 'In order to decrease the number of events, we will report only events from a certaing age
                            x = x + 1
                            AddtoArray arrWerFiles, objFile.Path
                            AddtoArray arrWerFileEventTime, varWEREventTime
                        End If
                    End If
                Next
            Next
        Next
    End If
    If objFSO.FolderExists(strWERUserfolder) Then
        For Each objSubFolder In objFSO.GetFolder(strWERUserfolder).SubFolders
            For Each objFolder In objSubFolder.SubFolders
                For Each objFile In objFolder.Files
                    If LCase(objFSO.GetExtensionName(objFile.Path)) = "wer" Then
                        varWEREventTime = GetEventTimefromWERfile(objFile.Path)
                        intEventAge = DateDiff("d", varWEREventTime, Now)
                        If intEventAge < intMaxAge Then
                            x = x + 1
                            AddtoArray arrWerFiles, objFile.Path
                            AddtoArray arrWerFileEventTime, varWEREventTime
                        End If
                    End If
                Next
            Next
        Next
    End If
    
    OpenTag ("Session")
    LineOut " -- Windows Error Reporting Events from past " & CStr(intMaxAge) & " days", "", False, False, "SessionTitle"
    LineOut "", "", True, False, ""
    
    
    If x > -1 Then
        intDumpSetNumer = 1
        Set objDataList = MultipleSortFilesByFileDate(arrWerFiles, arrWerFileEventTime)
        OpenTag ("WerSession")
        Do Until objDataList.EOF
            fHandleWERData objDataList.Fields.Item("FileName"), objDataList.Fields.Item("FileDate"), intDumpSetNumer
            objDataList.MoveNext
        Loop
        CloseTag ("WerSession")
    Else
        LineOut "Status:", "No Windows Error Reporting data found in machine", False, False, "Item"
    End If

    CloseTag ("Session")
    
End Function

Function GetEventTimefromWERfile(strWERFilePath)
    Dim bolEventTimeFound, strLine, objWERFile
    Dim strValueName, strAttributeName, intIndex, strValueData
    bolEventTimeFound = False
    
    Set objWERFile = objFSO.OpenTextFile(strWERFilePath, ForReading, False, OpenFileMode)
    GetEventTimefromWERfile = ""
    While (Not objWERFile.AtEndOfStream) And Not (bolEventTimeFound)
    
        strLine = objWERFile.ReadLine
        ObtainDataFromWERLine strLine, strValueName, strAttributeName, intIndex, strValueData

        Select Case LCase(strValueName)
            Case "eventtime"
                GetEventTimefromWERfile = ConvertFILETIMEtoDateTime(BinaryToHex(Dec2Bin(strValueData)))
                bolEventTimeFound = True
        End Select
    Wend
End Function

Function RemoveVCChars(strString)
    RemoveVCChars = Replace(strString, "/n", " ", , , vbTextCompare)
End Function

Function fHandleWERData(strWERFile, datEventTime, intDumpSetNumer)
    'Read information from *.WER files to obtain information from Windows Error Reporting files
    Dim objWERFile
    Dim strLine, strValueName, strValueData, strAttributeName, intIndex
    Dim strEventType, strAppName, strAppPath, strFriendlyEventName, strReportDescription, bReadNextLine, x
    
    Set objWERFile = objFSO.OpenTextFile(strWERFile, ForReading, False, OpenFileMode)
        
    bReadNextLine = True
    strReportDescription = ""
    While Not objWERFile.AtEndOfStream
        If bReadNextLine Then
            strLine = objWERFile.ReadLine
            ObtainDataFromWERLine strLine, strValueName, strAttributeName, intIndex, strValueData
        Else
            bReadNextLine = True
        End If
        
        Select Case LCase(strValueName)
            Case "eventtype"
                strEventType = strValueData
            Case "appname"
                strAppName = strValueData
            Case "apppath"
                strAppPath = strValueData
            Case "friendlyeventname"
                strFriendlyEventName = strValueData
            Case "reportdescription"
                strReportDescription = RemoveVCChars(strValueData)
            Case "eventtime"
                'datEventTime = ConvertFILETIMEtoDateTime(BinaryToHex(Dec2Bin(strValueData)))
                'Receing the datEventTime as argument now to avoid converting the dates twice
            Case "file"
                Dim bolMinidumpIncluded, bolFullDumpIncluded, bolReadAllFileCabs
                Dim strMinidumpName, strFulldumpName
                Dim strFilePath, intFileType, strFileName, bolReadAllFileAttributes, intWorkingIndex
                bolReadAllFileCabs = False
                While Not bolReadAllFileCabs And Not (objWERFile.AtEndOfStream)
                    bolReadAllFileAttributes = False
                    strFileName = ""
                    intFileType = ""
                    strFilePath = ""
                    intWorkingIndex = intIndex
                    While (intWorkingIndex = intIndex) And Not (objWERFile.AtEndOfStream)
                        Select Case LCase(strAttributeName)
                            Case "cabname"
                                strFileName = strValueData
                            Case "type"
                                intFileType = strValueData
                            Case "path"
                                strFilePath = strValueData
                        End Select
    
                        If Not objWERFile.AtEndOfStream Then
                            strLine = objWERFile.ReadLine
                            ObtainDataFromWERLine strLine, strValueName, strAttributeName, intIndex, strValueData
                        End If
                    Wend
                    If LCase(strValueName) <> "file" Then
                        bolReadAllFileCabs = True
                    End If
                    Dim bMiniDumpIncluded, bFullDumpIncluded
                    Dim arrFileNames, arrFilePaths, arrFileTypes
                    AddtoArray arrFileNames, strFileName
                    AddtoArray arrFilePaths, strFilePath
                    AddtoArray arrFileTypes, intFileType
                    If LCase(Right(strFileName, 3)) = "dmp" Then
                        Select Case intFileType
                            Case 2 'Minidump
                                bMiniDumpIncluded = True
                            Case 3 'FullDump
                                bFullDumpIncluded = True
                        End Select
                    End If
                    bReadNextLine = False
                Wend
            Case "sig"
                Dim bolReadAllSigs, strSigValue, strSigName
                Dim arrSigNames, arrSigValues
                bolReadAllSigs = False

                While Not bolReadAllSigs And Not (objWERFile.AtEndOfStream)
                    intWorkingIndex = intIndex
                    While (intWorkingIndex = intIndex) And (LCase(strValueName) = "sig") And (Not (objWERFile.AtEndOfStream))
                        Select Case LCase(strAttributeName)
                            Case "name"
                                strSigName = strValueData
                            Case "value"
                                strSigValue = strValueData
                        End Select
                        
                        If Not objWERFile.AtEndOfStream Then
                            strLine = objWERFile.ReadLine
                            ObtainDataFromWERLine strLine, strValueName, strAttributeName, intIndex, strValueData
                        End If
                    Wend
                    
                    If LCase(strValueName) <> "sig" Then
                        bolReadAllSigs = True
                    End If
                    
                    AddtoArray arrSigNames, strSigName
                    AddtoArray arrSigValues, strSigValue

                    bReadNextLine = False
                Wend
        End Select
    Wend


    OpenTag "SubSession"
    wscript.Echo "    Analyzing file: " & strWERFile
    wscript.Echo "             Event: " & strFriendlyEventName & " (" & strEventType & ") Application: " & strAppName
    LineOut "  - Event Type : ", strFriendlyEventName & " (" & strEventType & ")", False, False, "SessionTitle"
    LineOut "", "", True, False, ""
    LineOut "      Application Name: ", strAppName, False, False, "AppName"
    LineOut "      Path:             ", strAppPath, False, False, "Item"
    LineOut "Lookup", strEventType & "-" & objFSO.GetBaseName(strAppPath), False, True, "LookupSessionName"
    OpenTag "Table"
    LineOut "      Event Time      : ", FormatDateTime(datEventTime), False, False, "Time"
    
    x = 0
    If Not IsEmpty(arrSigNames) Then
        For Each strSigName In arrSigNames
            LineOut "          " & strSigName & ": ", arrSigValues(x), False, False, "Sig"
            x = x + 1
        Next
    End If
    CloseTag "Table"
    
    Dim strCABName
    If (bCollectWERFullDumps And bFullDumpIncluded) Or (bCollectWERMiniDumps And bMiniDumpIncluded) Then
        Dim bCopyWerFiles
        If (bUserDumpExclusionList Or bUserDumpProcessInclusionList) Then
            If Not CanDumpsFromThisProcessBeCopied(objFSO.GetBaseName(strAppPath)) Then
                If bUserDumpExclusionList Then
                        LineOut "      Memory dump     : ", "Excluded to copy", False, False, "Dump"
                End If
                If bUserDumpProcessInclusionList Then
                        LineOut "      Memory dump     : ", "Not selected to copy", False, False, "Dump"
                End If
                bCopyWerFiles = False
            Else
                bCopyWerFiles = True
            End If
        Else
            bCopyWerFiles = True
        End If
        If bCopyWerFiles Then
            If fGetWERFile(objFSO.GetParentFolderName(strWERFile), arrFileNames, arrFilePaths, arrFileTypes, intDumpSetNumer, objFSO.GetFileName(strAppPath), GetAgeDescription(datEventTime), strEventType, strFriendlyEventName, strReportDescription) Then
                intDumpSetNumer = intDumpSetNumer + 1
            End If
        End If
    Else
        If (bMiniDumpIncluded) Then
            LineOut "      Memory dump     : ", "Only a minidump was generated. File not copied", False, False, "Dump"
        ElseIf bFullDumpIncluded Then
            LineOut "      Memory dump     : ", "Only a full dump was generated. File not copied", False, False, "Dump"
        Else
           LineOut "      Memory dump     : ", "Not created", False, False, "Dump"
        End If
    End If
    
    LineOut "", "", True, False, ""
        
    CloseTag "SubSession"
    
    objWERFile.Close
    
End Function

Sub ProcessCreate(strProcess, strParameters)

    Const SW_HIDE = 0
    Dim strComputer, i, objStartup, objProcess, objWMIService, errResult, objConfig, intProcessID, colProcess, bExit
    strComputer = "."
    i = 0
    
    On Error Resume Next
    
    Set objWMIService = GetObject("winmgmts:" _
                        & "{impersonationLevel=impersonate}!\\" _
                        & strComputer & "\root\cimv2")
                    
    Set objStartup = objWMIService.Get("Win32_ProcessStartup")
    Set objConfig = objStartup.SpawnInstance_
                    objConfig.ShowWindow = SW_HIDE
    
    Set objProcess = objWMIService.Get("Win32_Process")

    If Err.Number <> 0 Then
        DisplayError "Accessing Win32_Process/ Win32_ProcessStartup WMI classes", Err.Number, Err.Source, Err.Description
        Exit Sub
    End If

    errResult = objProcess.Create(strProcess & " " & strParameters, Null, objConfig, intProcessID)
    
    If errResult = 0 Then
        Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
        
        i = 0
        While (Not bExit) And (i < 1000) 'Wait for exit for up 1000 times
            Set colProcess = objWMIService.ExecQuery _
                            ("Select ProcessID From Win32_Process where ProcessID = " & CStr(intProcessID))
            If colProcess.Count = 0 Then
                bExit = True
            Else
                wscript.Sleep 200
                i = i + 1
            End If
        Wend
    Else
        DisplayError "Creating a process using the command line: " & strProcess & " " & strParameters, 5000, "WMI", "Error 0x" & HexFormat(errResult)
    End If

End Sub

Function ConvertFILETIMEtoDateTime(strFILETIME)
    Dim lngHigh, lngLow, dtmDate
    If IsDate(strFILETIME) Then
        ConvertFILETIMEtoDateTime = strFILETIME
    Else
        On Error Resume Next
        'Datatype is a 64-bit FILETIME structure string. We need to convert it
        lngHigh = CLng("&H" & Left(strFILETIME, Len(strFILETIME) / 2))
        lngLow = CLng("&H" & Right(strFILETIME, Len(strFILETIME) / 2))
            
        If Err.Number <> 0 Then
            ConvertFILETIMEtoDateTime = ""
        Else
            If lngLow < 0 Then
              lngHigh = lngHigh + 1
            End If
            If (lngHigh = 0) And (lngLow = 0) Then
              dtmDate = ""
            Else
              dtmDate = #1/1/1601# + (((lngHigh * (2 ^ 32)) _
                + lngLow) / 600000000 - intCurrentTzBias) / 1440
              If Not IsDate(dtmDate) Then
                 dtmDate = ""
              End If
            End If
            ConvertFILETIMEtoDateTime = dtmDate
        End If
    End If
End Function

Function Dec2Bin(ByVal DecimalIn)
    Dec2Bin = ""
    DecimalIn = Int(CDbl(DecimalIn))
    Do While DecimalIn <> 0
        Dec2Bin = Trim(CStr(DecimalIn - _
            2 * Int(DecimalIn / 2))) & Dec2Bin
            DecimalIn = Int(DecimalIn / 2)
    Loop
    
    Dec2Bin = Right(String(64, "0") & Dec2Bin, 64)
End Function

Private Function BinaryToHex(ByVal binary_value)

    Dim hex_result
    Dim nibble_num
    Dim nibble_value
    Dim factor
    Dim bit

    ' Remove any leading &B if present.
    ' (Note: &B is not a standard prefix, it just
    ' makes some sense.)
    binary_value = UCase(Trim(binary_value))
    If Left(binary_value, 2) = "&B" Then binary_value = _
        Mid(binary_value, 3)

    ' Strip out spaces in case the bytes are separated
    ' by spaces.
    binary_value = Replace(binary_value, " ", "")

    ' Left pad with zeros so we have a full 32 bits.
    binary_value = Right(String(64, "0") & binary_value, _
        64)

    ' Read the bits in nibbles from right to left.
    ' (A nibble is half a byte. No kidding!)
    For nibble_num = 15 To 0 Step -1
        ' Convert this nibble into a hexadecimal string.
        factor = 1
        nibble_value = 0

        ' Read the nibble's bits from right to left.
        For bit = 3 To 0 Step -1
            If Mid(binary_value, 1 + nibble_num * 4 + bit, _
                1) = "1" Then
                nibble_value = nibble_value + factor
            End If
            factor = factor * 2
        Next

        ' Add the nibble's value to the left of the
        ' result hex string.
        hex_result = Hex(nibble_value) & hex_result
    Next

    ' Convert the result string into a long.
    BinaryToHex = hex_result
End Function

Private Function FileTimeToDateEx(strFILETIME, ByVal LeaveAsUTC)
  Const ToLT = "FileTimeToLocalFileTime"

    Dim dwHighDateTime, dwLowDateTime
    'dwHighDateTime = CLng(Left(strFILETIME, 9))
    'dwLowDateTime = CLng(Right(strFILETIME, 9))


  If dwHighDateTime = 0 And dwLowDateTime = 0 Then
    FileTimeToDateEx = Empty
    Exit Function
  End If

  Const Epoch = #1/1/1601#
  Dim ToDate
  Dim Bit32
  Dim D
  
  Bit32 = 2 ^ 32
  ToDate = 0.0000001 * (#1/1/2000# - #12/31/1999#) / 24 / 3600
  If dwHighDateTime < 0 Then
    D = (Bit32 + dwHighDateTime) * Bit32 * ToDate + Epoch
  Else
    D = dwHighDateTime * Bit32 * ToDate + Epoch
  End If
  If dwLowDateTime < 0 Then
    FileTimeToDateEx = (Bit32 + dwLowDateTime) * ToDate + D
  Else
    FileTimeToDateEx = dwLowDateTime * ToDate + D
  End If
End Function



Function ObtainDataFromWERLine(ByVal strLine, ByRef strValueName, ByRef strAttributeName, ByRef intIndex, ByRef strValueData)
        Dim intPosStart, intPosEnd
        strValueName = ""
        
        intPosStart = InStr(1, strLine, "[")
        
        If intPosStart = 0 Then 'There is no index
            intIndex = -1
        Else
            intPosEnd = InStr(1, strLine, "]")
            If intPosEnd <> 0 Then
                intIndex = Mid(strLine, intPosStart + 1, intPosEnd - intPosStart - 1)
                strValueName = Left(strLine, intPosStart - 1)
            Else
                intIndex = -1
            End If
        End If
                        
        intPosStart = InStr(1, strLine, ".")
        intPosEnd = InStr(1, strLine, "=")
        
        If (intPosStart >= intPosEnd) Or (intPosStart = 0) Then 'It is not an attribute
            strAttributeName = ""
        Else
            strAttributeName = Mid(strLine, intPosStart + 1, intPosEnd - intPosStart - 1)
            If strValueName = "" Then
                strValueName = Left(strLine, intPosStart - 1)
            End If
        End If
        
        If strValueName = "" Then
            strValueName = Left(strLine, intPosEnd - 1)
        End If
        
        strValueData = Right(strLine, Len(strLine) - intPosEnd)
End Function

Function CollectMachineMiniDumps()
    Dim strMiniDumpFolder
    Dim objFolder
    Dim objFile
    Dim x, bCanBeAlerted
    
    Dim objDataList
    Set objDataList = CreateObject("ADODB.Recordset")
    
    strMiniDumpFolder = ReplaceEnvVars(objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\MinidumpDir"))
    
    wscript.Echo ""
    wscript.Echo "Mini Dumps"
    wscript.Echo "----------"
           
    x = 0
    If objFSO.FolderExists(strMiniDumpFolder) Then
        Set objDataList = SortFilesByFileDate(strMiniDumpFolder)
        bCanBeAlerted = True
        Do Until objDataList.EOF
            x = x + 1
            If InStr(1, objFSO.GetExtensionName(objDataList.Fields.Item("FileName")), "dmp", 1) Then
                OpenTag "SubSession"
                LineOut " -- File : ", objDataList.Fields.Item("FileName"), False, False, "SessionTitle"
                If CallCompressFiles(objDataList.Fields.Item("FileName"), "Minidump", "", "Machine mini dump", x, bCanBeAlerted, 80) Or Not (bCollectMinidumps) Then
                    x = x + 1
                Else
                    bCanBeAlerted = (x < 4)
                End If
                CloseTag "SubSession"
            Else
                wscript.Echo "    It seems this is not a dump file."
            End If
            objDataList.MoveNext
        Loop

    Else
        OpenTag "SubSession"
        LineOut " -- Machine minidumps", "", False, True, "SessionTitle"
        LineOut " -- Status : ", "Folder " & strMiniDumpFolder & " does not exist", False, False, "Item"
        CloseTag "SubSession"
    End If
    
End Function

Function CollectTDRDumps()
    Dim strTDRDumpsFolder
    Dim objFolder
    Dim objFile
    Dim x, bCanBeAlerted
    
    Dim objDataList
    Set objDataList = CreateObject("ADODB.Recordset")
    
    strTDRDumpsFolder = ReplaceEnvVars("%WINDIR%\LiveKernelReports\WATCHDOG")
    
    wscript.Echo ""
    wscript.Echo "TDR Dumps"
    wscript.Echo "----------"
           
    x = 0
    If objFSO.FolderExists(strTDRDumpsFolder) Then
        Set objDataList = SortFilesByFileDate(strTDRDumpsFolder)
        bCanBeAlerted = True
        Do Until objDataList.EOF
            x = x + 1
            If InStr(1, objFSO.GetExtensionName(objDataList.Fields.Item("FileName")), "dmp", 1) Then
                OpenTag "SubSession"
                LineOut " -- File : ", objDataList.Fields.Item("FileName"), False, False, "SessionTitle"
                If CallCompressFiles(objDataList.Fields.Item("FileName"), "TDRDump", "", "Timeout Detection and Recovery (TDR) memory dump", x, bCanBeAlerted, 50) Or Not (bCollectTDRDumps) Then
                    x = x + 1
                Else
                    bCanBeAlerted = (x < 4)
                End If
                CloseTag "SubSession"
            Else
                wscript.Echo "    It seems this is not a dump file."
            End If
            objDataList.MoveNext
        Loop

    Else
        LineOut " -- TDR Dumps", "", False, False, "SessionTitle"
        LineOut " -- Status : ", "Folder " & strTDRDumpsFolder & " does not exist", False, False, "Item"
    End If
    
End Function

Function MultipleSortFilesByFileDate(arrFiles, arrFileDates)
    Dim objDataList, x, objFile
    
    Set objDataList = CreateObject("ADODB.RecordSet")
    objDataList.Fields.Append "FileDate", adDBTimeStamp
    objDataList.Fields.Append "FileName", adVarChar, 500
    objDataList.Open
    
    For x = 0 To UBound(arrFiles)
        If objFSO.FileExists(arrFiles(x)) Then
            Set objFile = objFSO.GetFile(arrFiles(x))
            objDataList.AddNew
                If IsEmpty(arrFileDates) Then
                    objDataList("FileDate") = objFile.DateLastModified
                Else
                    objDataList("FileDate") = arrFileDates(x)
                End If
                objDataList("FileName") = objFile.Path
            objDataList.Update
        End If
        
        objDataList.Sort = "FileDate DESC"
        objDataList.MoveFirst
    Next
    Set MultipleSortFilesByFileDate = objDataList
End Function

Function SortFilesByFileDate(strFolder)
    Dim objDataList, objFolder, objFile
    
    Set objDataList = CreateObject("ADODB.RecordSet")
    objDataList.Fields.Append "FileDate", adDBTimeStamp
    objDataList.Fields.Append "FileName", adVarChar, 500
    objDataList.Open
    
        
    If objFSO.FolderExists(strFolder) Then
    
        Set objFolder = objFSO.GetFolder(strFolder)
        
        For Each objFile In objFolder.Files
            objDataList.AddNew
                objDataList("FileDate") = objFile.DateLastModified
                objDataList("FileName") = objFile.Path
            objDataList.Update
        Next
        
        If Not (objDataList.BOF And objDataList.EOF) Then
            objDataList.Sort = "FileDate DESC"
            objDataList.MoveFirst
        End If
    End If
    Set SortFilesByFileDate = objDataList
End Function

Function CollectMachineMemoryDMP()
    Dim strMemDumpLocation
    
    strMemDumpLocation = ReplaceEnvVars(objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\DumpFile"))
    
    wscript.Echo ""
    wscript.Echo "Memory Dump"
    wscript.Echo "------------"
    
    OpenTag "SubSession"
    LineOut " --   File : ", strMemDumpLocation, False, False, "SessionTitle"
     
     If objFSO.FileExists(strMemDumpLocation) Then
         CallCompressFiles strMemDumpLocation, "MemoryDump", "", "Machine memory dump", 0, True, 70
     Else
         LineOut "", "", True, False, ""
         LineOut " --     Status : ", "File " & strMemDumpLocation & " does not exist.", False, False, "Item"
         LineOut "", "", True, False, ""
     End If
    CloseTag "SubSession"
     
End Function

Function ObtainURLForExternalFiles(strExternalFilePath, intDestinationEnvironment)
    'intEnvironment = 1 = StandAlone/ Other/ SDP 2.x or ScriptedDiag inside DumpReport.HTM
    'intEnvironment = 2 = ScriptedDiag report alert
    
    If bGenerateSDP2Alerts Or bGenerateScriptedDiagXMLAlerts Then
        If intDestinationEnvironment = 2 Then
            ObtainURLForExternalFiles = "<a href='#" & strExternalFilePath & "'>" & strExternalFilePath & "</a>."
        Else
            ObtainURLForExternalFiles = "<i>" & strExternalFilePath & "</a>."
        End If
    Else
        'Standalone
        ObtainURLForExternalFiles = "<a href='" & strExternalFilePath & "'>" & strExternalFilePath & "</a>."
    End If
End Function


Function fGetWERFile(strReportFolder, arrFileNames, arrFilePaths, arrFileTypes, intFileSetNumber, strAppName, strFileAge, strConsentKey, strFriendlyEventName, strReportDescription)
    On Error Resume Next
    Dim strCabFile, x, objCABFile, strFileTypeCopied, arrFileTypesCopied
    Dim bMiniDumpIncluded, bFullDumpIncluded
    fGetWERFile = False
    If intFileSetNumber <= intMaxFiles Then
        strCabFile = CopyWERFiles(strReportFolder, arrFileNames, arrFilePaths, arrFileTypes, objFSO.GetBaseName(strAppName), arrFileTypesCopied)
        wscript.Echo ""
        If strCabFile <> "" Then
            bDumpCopiedDetected = True
            fGetWERFile = True
            Dim strFileType
            strFileTypeCopied = ""
            For x = 0 To UBound(arrFileTypes)
                Select Case arrFileTypes(x)
                    Case 2 'Minidump
                        If Len(strFileType) > 0 Then strFileType = strFileType & " and a "
                        strFileType = strFileTypeCopied & "mini dump"
                    Case 3 'FullDump
                        If Len(strFileType) > 0 Then strFileType = strFileType & " and a "
                        strFileType = strFileType & "full dump"
                End Select
            Next
            For x = 0 To UBound(arrFileTypesCopied)
                Select Case arrFileTypesCopied(x)
                    Case 2 'Minidump
                        bMiniDumpIncluded = True
                        If Len(strFileTypeCopied) > 0 Then strFileTypeCopied = strFileTypeCopied & " and "
                        strFileTypeCopied = strFileTypeCopied & "mini dump"
                    Case 3 'FullDump
                        bFullDumpIncluded = True
                        If Len(strFileTypeCopied) > 0 Then strFileTypeCopied = strFileTypeCopied & " and "
                        strFileTypeCopied = strFileTypeCopied & "full dump"
                End Select
            Next
            
            strFileType = strFileType & iif(InStr(7, strFileTypeCopied, "dump", vbTextCompare) > 0, " were", " was")
            If Len(strFileTypeCopied) = 0 Then strFileTypeCopied = "More information "
            
            LineOut "      Memory dump     : ", strFileTypeCopied & " compressed to " & objFSO.GetFileName(strCabFile), True, False, ""
            LineOut "      Memory dump     : ", objFSO.GetFileName(strCabFile), False, True, "Dump"
            
            Dim strAlertMSGhtm
            Dim strAlertMSGtxt, strAlertMSGhtmScriptedXML
            strAlertMSGhtmScriptedXML = ""
            Select Case (LCase(strConsentKey))
                Case "bluescreen"
                    strAlertMSGhtm = "An unexpectedly shutdown ocurred <b>" & strFileAge & "</b> ago and Windows Error Reporting created a " & strFileType & ". " & strFileTypeCopied & " compressed to " & ObtainURLForExternalFiles(objFSO.GetFileName(strCabFile), 1) & "."
                    strAlertMSGhtmScriptedXML = "An unexpectedly shutdown ocurred <b>" & strFileAge & "</b> ago and Windows Error Reporting created a " & strFileType & ". " & strFileTypeCopied & " compressed to " & ObtainURLForExternalFiles(objFSO.GetFileName(strCabFile), 2) & "."
                    strAlertMSGtxt = "An unexpectedly shutdown ocurred " & strFileAge & " ago and Windows Error Reporting created a " & strFileType & ". " & strFileTypeCopied & " compressed to " & objFSO.GetFileName(strCabFile) & "."
                Case Else
                    If Len(strReportDescription) > 0 Then
                        strAlertMSGhtm = "<b>" & strFileAge & "</b> ago: " & strReportDescription & " A " & strFileType & " created. " & strFileTypeCopied & " compressed to " & ObtainURLForExternalFiles(objFSO.GetFileName(strCabFile), 1) & "."
                        strAlertMSGhtmScriptedXML = "<b>" & strFileAge & "</b> ago: " & strReportDescription & " A " & strFileType & " created. " & strFileTypeCopied & " compressed to " & ObtainURLForExternalFiles(objFSO.GetFileName(strCabFile), 2) & "."
                        strAlertMSGtxt = strFileAge & " ago: " & strReportDescription & " A " & strFileType & " was created. " & strFileTypeCopied & " compressed to " & objFSO.GetFileName(strCabFile)
                    Else
                        strAlertMSGhtm = "<b>" & strFileAge & "</b> ago, process <b>" & strAppName & "</b> failed and a " & strFileType & " created - " & strFileTypeCopied & " compressed to " & ObtainURLForExternalFiles(objFSO.GetFileName(strCabFile), 1) & "."
                        strAlertMSGhtmScriptedXML = "<b>" & strFileAge & "</b> ago, process <b>" & strAppName & "</b> failed and a " & strFileType & " created - " & strFileTypeCopied & " compressed to " & ObtainURLForExternalFiles(objFSO.GetFileName(strCabFile), 2) & "."
                        strAlertMSGtxt = strFileAge & " ago, process " & strAppName & " failed and a " & strFileType & " created. " & strFileTypeCopied & " compressed to " & objFSO.GetFileName(strCabFile)
                    End If
            End Select
            If Len(strAlertMSGhtmScriptedXML) = 0 Then strAlertMSGhtmScriptedXML = strAlertMSGhtm
            AddXMLAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_USER_DMP_FOUND, strAlertMSGhtm, "" & _
                    "Check more information about this failure <a href=" & Chr(34) & "#" & strConsentKey & "-" & objFSO.GetBaseName(strAppName) & Chr(34) & ">here</a>.", 30 - intFileSetNumber
            
            AddScriptedDiagAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_USER_DMP_FOUND, strAlertMSGhtmScriptedXML, "" & _
                    "Please open the file <a href=" & Chr(34) & "#" & strHTMLOutputfilename & Chr(34) & ">" & strHTMLOutputfilename & "</a> for more information about this dump.", 30 - intFileSetNumber
            
            AddTXTAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_USER_DMP_FOUND, strAlertMSGtxt, "Please open the dump file in a debugger for more information"

        Else
            LineOut "      Memory dump     : ", "Dump file does not exist or error copying dump file.", False, False, "Dump"
            fGetWERFile = False
        End If
    Else
        LineOut "      Memory dump     : ", "" & CStr(intMaxFiles) & " other files copied already", False, False, "Dump"
        fGetWERFile = False
    End If
End Function

Function GetStrFileAge(objFile)
    Dim intFileAge, strFileAge
    GetStrFileAge = GetAgeDescription(objFile.DateLastModified)
End Function

Function GetAgeDescription(datDateTime)
    On Error Resume Next
    Dim intAge, strAge
    intAge = DateDiff("d", datDateTime, Now)
    strAge = CStr(intAge) & " day"
    If intAge = 0 Then
        intAge = DateDiff("h", datDateTime, Now)
        If intAge > 0 Then
            strAge = CStr(intAge) & " hour"
        Else
            intAge = DateDiff("n", datDateTime, Now)
            If intAge > 0 Then
                strAge = CStr(intAge) & " minute"
            Else
                intAge = DateDiff("s", datDateTime, Now)
                strAge = CStr(intAge) & " second"
            End If
        End If
    End If

    If CDbl(Left(strAge, 2)) > 1 Then
        strAge = strAge & "s"
    End If
    
    GetAgeDescription = strAge
End Function

Function CanDumpsFromThisProcessBeCopied(strProcessName)
    Dim x, bCopyFile
    If Len(strProcessName) > 0 Then
        If bUserDumpExclusionList Then
            bCopyFile = True
            For x = 0 To UBound(arrUserDumpProcessExclusionList)
                If LCase(objFSO.GetBaseName(arrUserDumpProcessExclusionList(x))) = LCase(objFSO.GetBaseName(strProcessName)) Then
                    bCopyFile = False
                    Exit For
                End If
            Next
        ElseIf bUserDumpProcessInclusionList Then
            bCopyFile = False
            For x = 0 To UBound(arrUserDumpProcessInclusionList)
                If LCase(objFSO.GetBaseName(arrUserDumpProcessInclusionList(x))) = LCase(objFSO.GetBaseName(strProcessName)) Then
                    bCopyFile = True
                    Exit For
                End If
            Next
        Else
            bCopyFile = True
        End If
    Else
        'Unable to obtain process name. In this case, it will return true if bUserDumpExclusionList is true
        If bUserDumpExclusionList Then
            bCopyFile = True
        Else
            bCopyFile = False
        End If
    End If
    CanDumpsFromThisProcessBeCopied = bCopyFile
End Function

Function CallCompressFiles(strLocation, strType, strProcessName, strDescription, ByRef Filenumber, ByRef bCanBeAlerted, ByRef intSetPriority)

    Dim objFile
    Dim intFileAge, strDestCABName
    Dim strFileAge
    Dim strAlertToAddXML, strAlertToAddTXT, strAlertToAddScriptedXML
    
    CallCompressFiles = False
    strDestCABName = ""
    Set objFile = objFSO.GetFile(strLocation)
        
    strFileAge = GetStrFileAge(objFile)
    intFileAge = DateDiff("d", objFile.DateLastModified, Now)
    
    LineOut "    Size            : ", FormatNumber(objFile.Size / 1024 / 1024, 2) & " MB", False, False, "Item"
    LineOut "    Date Modified   : ", FormatDateTime(objFile.DateLastModified), False, False, "Item"
    LineOut "    Age             : ", strFileAge, False, False, "Item"
    strAlertToAddXML = ""
    strAlertToAddTXT = ""
    
    If intFileAge < intMaxAge Then
        If Filenumber <= intMaxFiles Then
            If (strType = "Minidump" And bCollectMinidumps) Or (strType = "MemoryDump" And bCollectMemoryDump) Or (strType = "UserDump" And bCollectUserDumps) Or (strType = "TDRDump" And bCollectTDRDumps) Then
                If (strType = "UserDump") Then
                    strDestCABName = BuildCompressedFile(strLocation, USER_DUMP, strProcessName)
                Else
                    strDestCABName = BuildCompressedFile(strLocation, MACHINE_DUMP, "")
                End If
                strAlertToAddScriptedXML = ""
                If Len(strDestCABName) > 0 Then
                    CallCompressFiles = True
                    bCanBeAlerted = True
                    strAlertToAddXML = " Dump compressed to " & ObtainURLForExternalFiles(objFSO.GetFileName(strDestCABName), 1) & ""
                    strAlertToAddScriptedXML = " Dump compressed to " & ObtainURLForExternalFiles(objFSO.GetFileName(strDestCABName), 2) & ""
                    strAlertToAddTXT = " Dump compressed to " & objFSO.GetFileName(strDestCABName) & "."
                    bDumpCopiedDetected = True
                End If
            End If
            If bGetDebuggerInfo Then
                LineOut "", strLocation, False, True, "LookupSessionName"
                LineOut "    Dump Information: ", "Check the report for dump below.", True, False, ""
                If ((strType = "Minidump") Or (strType = "MemoryDump")) Then
                    AddToAnalysis objFile.Path, MACHINE_DUMP, strDestCABName
                ElseIf (strType = "TDRDump") Then
                    AddToAnalysis objFile.Path, TDR_DUMP, strDestCABName
                Else
                    AddToAnalysis objFile.Path, USER_DUMP, strDestCABName
                End If
            Else
                If bCanBeAlerted Then
                    If Len(strAlertToAddScriptedXML) = 0 Then strAlertToAddScriptedXML = strAlertToAddXML
                    Dim strAlertCategory
                    Select Case strType
                        Case "Minidump", "MemoryDump", "TDRDump"
                            strAlertCategory = ALERT_CATEGORY_MACHINE_DMP_FOUND
                        Case "UserDump"
                            strAlertCategory = ALERT_CATEGORY_USER_DMP_FOUND
                    End Select
                    AddXMLAlert ALERT_DUMP_FOUND, strAlertCategory, strDescription & " from <b>" & strFileAge & " ago</b> was found in " & strLocation & "." & strAlertToAddXML, "" & _
                        "Check more information about this memory dump <a href=" & Chr(34) & "#" & strLocation & Chr(34) & ">here</a>.", 90 - Filenumber + iif(Len(strAlertToAddXML) > 0, 100, 0) + intSetPriority
                    
                    AddScriptedDiagAlert ALERT_DUMP_FOUND, strAlertCategory, strDescription & " from <b>" & strFileAge & " ago</b> was found in " & strLocation & "." & strAlertToAddScriptedXML, "" & _
                        "Please open the file <a href=" & Chr(34) & "#" & strHTMLOutputfilename & Chr(34) & ">" & strHTMLOutputfilename & "</a> for more information.", 90 - Filenumber + iif(Len(strAlertToAddXML) > 0, 100, 0) + intSetPriority
                    
                    AddTXTAlert ALERT_DUMP_FOUND, strAlertCategory, strDescription & " from " & strFileAge & " ago was found in " & strLocation & "." & strAlertToAddTXT, "" & _
                        "Check more information about this memory dump in the dump analysis section."
                End If
                CallCompressFiles = (Len(strDestCABName) > 0)
            End If
        Else
            If (bCollectMinidumps) Or (bCollectMemoryDump) Or (bCollectUserDumps) Or (bCollectTDRDumps) Then
                LineOut "    Status          : ", "Skipped since " & CStr(intMaxFiles) & " files were already copied. ", False, False, "Item"
            End If
        End If
    Else
        LineOut "    Status          : ", "File is older than " & CStr(intMaxAge) & " day(s).", False, False, "Item"
    End If
        
    LineOut "", "", True, False, ""
    
End Function

Sub AddToAnalysis(strFileName, intType, CompressedTo)
    If ((intType = MACHINE_DUMP) Or (intType = TDR_DUMP)) Then
        AddtoArray arrMachineAnalyzeQueue, strFileName
        AddtoArray arrMachineCompressedTo, CompressedTo
    ElseIf intType = USER_DUMP Then
        AddtoArray arrUserAnalyzeQueue, strFileName
        AddtoArray arrUserCompressedTo, CompressedTo
    End If
    wscript.Echo "    - File added to the Analyzer queue."
End Sub

Function GetProcessPathFromDump(strDumpPath)
    Dim objDebugger
    If bGetDebuggerInfo Then
        Set objDebugger = New Debugger
        If objDebugger.OpenDumpFile(strDebuggerPath, strDumpPath) Then
            Dim strProcessPath, strProcessID
            If objDebugger.GetUsermodeProcessInfo(strProcessPath, strProcessID) Then
                GetProcessPathFromDump = strProcessPath
            Else
                wscript.Echo " - Error: Unable to obtain process name from dump " & strDumpPath
                GetProcessPathFromDump = "(Unknown)"
            End If
            objDebugger.CloseDumpFile
        End If
        Set objDebugger = Nothing
    Else
        GetProcessPathFromDump = "(Unknown)"
    End If
End Function

Sub RunDebuggerOperations()
    'KernelDumps
    Dim objDebugger
    Dim strDumpFile, strShortBugcheckCode, objFile, strFileAge, x
    Dim strAlertToAddXML, strAlertToAddTXT, intarrIndex, strAlertToAddScriptedDiagXML
    x = 0
    intarrIndex = 0
    On Error Resume Next
    
    wscript.Echo ""
    wscript.Echo "Analyzing memory dumps information"
    wscript.Echo "----------------------------------"
    
    strAlertToAddScriptedDiagXML = ""
    
    If Not IsEmpty(arrMachineAnalyzeQueue) Then
        For Each strDumpFile In arrMachineAnalyzeQueue
            x = x + 1
            Dim strSessionTime, strUptime
            Dim strOStarget, strBuild
            
            wscript.Echo " -- Opening " & strDumpFile & " in debugger..."
            If objFSO.FileExists(strDumpFile) Then
                If Len(arrMachineCompressedTo(intarrIndex)) > 0 Then
                    strAlertToAddXML = ". Dump compressed to " & ObtainURLForExternalFiles(objFSO.GetFileName(arrMachineCompressedTo(intarrIndex)), 1) & ""
                    strAlertToAddScriptedDiagXML = ". Dump compressed to " & ObtainURLForExternalFiles(objFSO.GetFileName(arrMachineCompressedTo(intarrIndex)), 2) & ""
                    strAlertToAddTXT = ". Dump compressed to " & objFSO.GetFileName(arrMachineCompressedTo(intarrIndex)) & ""
                Else
                    strAlertToAddXML = ""
                    strAlertToAddTXT = ""
                End If
                Set objFile = objFSO.GetFile(strDumpFile)
                strFileAge = GetStrFileAge(objFile)
                Set objDebugger = New Debugger
                If objDebugger.OpenDumpFile(strDebuggerPath, strDumpFile) Then
                    strShortBugcheckCode = objFSO.GetBaseName(strDumpFile) & "." & objFSO.GetExtensionName(strDumpFile)
                    Dim strBugcheckCode, strFirstArgument, strSecondArgument, strThirdArgument, strFourthArgument
                    If objDebugger.GetKernelBugcheckInfo(strBugcheckCode, strFirstArgument, strSecondArgument, strThirdArgument, strFourthArgument) Then
                        
                        wscript.Echo "    STOP Error: " & strBugcheckCode & " (" & strFirstArgument & ", " & strSecondArgument & ", " & strThirdArgument & ", " & strFourthArgument & ")"
                        
                        Select Case UCase(strBugcheckCode)
                            Case "000000E2"
                                AddXMLAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_MACHINE_DMP_FOUND, "Machine memory dump from <b>" & strFileAge & " ago</b> was found in " & strDumpFile & ". This dump is a <b> user manually initiated machine memory dump (Stop error " & _
                                        "<font color='red'>0x" & strBugcheckCode & "</font> (" & strFirstArgument & ", " & strSecondArgument & ", " & strThirdArgument & ", " & strFourthArgument & "))</b>" & strAlertToAddXML & ".", "" & _
                                        "Check more information about this memory dump <a href=" & Chr(34) & "#" & strDumpFile & Chr(34) & ">here</a>. Check more information about this STOP Error in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;244139'>KB 244139</a>. or ", 100 - x
                                
                                AddScriptedDiagAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_MACHINE_DMP_FOUND, "Machine memory dump from <b>" & strFileAge & " ago</b> was found in " & strDumpFile & ". This dump is a <b> user manually initiated machine memory dump (Stop error " & _
                                        "<font color='red'>0x" & strBugcheckCode & "</font> (" & strFirstArgument & ", " & strSecondArgument & ", " & strThirdArgument & ", " & strFourthArgument & "))</b>" & strAlertToAddScriptedDiagXML & ".", "" & _
                                        "Please open the file <a href=" & Chr(34) & "#" & strHTMLOutputfilename & Chr(34) & ">" & strHTMLOutputfilename & "</a> for more details. Check more information about this STOP Error in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;244139'>KB 244139</a>. or ", 100 - x
                                
                                AddTXTAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_MACHINE_DMP_FOUND, "Machine memory dump from " & strFileAge & " ago was found in " & strDumpFile & ". This dump was a manually initiated machine memory dump (Stop error 0x" & _
                                        strBugcheckCode & " (" & strFirstArgument & ", " & strSecondArgument & ", " & strThirdArgument & ", " & strFourthArgument & ")" & strAlertToAddTXT & ".", "" & _
                                        "Check more information about this memory dump below. Check more information about this STOP Error in KB 244139."
                            Case "0000009C"
                                AddXMLAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_MACHINE_DMP_FOUND, "Machine memory dump from <b>" & strFileAge & " ago</b> was found in " & strDumpFile & ". This dump is a <b>Stop error " & _
                                        "<font color='red'>0x" & strBugcheckCode & "</font> (" & strFirstArgument & ", " & strSecondArgument & ", " & strThirdArgument & ", " & strFourthArgument & "))</b>. Most of STOP error 0x9C are <b>hardware initiated</b>" & strAlertToAddXML & ".", "" & _
                                        "Check more information about this memory dump <a href=" & Chr(34) & "#" & strDumpFile & Chr(34) & ">here</a>. Check more information about this STOP Error in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;162363'>KB 162363</a> or <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;329284'>KB 329284</a>.", 100 - x
                                
                                AddScriptedDiagAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_MACHINE_DMP_FOUND, "Machine memory dump from <b>" & strFileAge & " ago</b> was found in " & strDumpFile & ". This dump is a <b>Stop error " & _
                                        "<font color='red'>0x" & strBugcheckCode & "</font> (" & strFirstArgument & ", " & strSecondArgument & ", " & strThirdArgument & ", " & strFourthArgument & "))</b>. Most of STOP error 0x9C are <b>hardware initiated</b>" & strAlertToAddScriptedDiagXML & ".", "" & _
                                        "Please open the file <a href=" & Chr(34) & "#" & strDumpFile & Chr(34) & ">" & strDumpFile & "</a> for more information about this dump. Check more information about this STOP Error in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;162363'>KB 162363</a> or <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;329284'>KB 329284</a>.", 100 - x
                                
                                AddTXTAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_MACHINE_DMP_FOUND, "Machine memory dump from " & strFileAge & " ago was found in " & strDumpFile & ". This dump is from a Stop error 0x" & _
                                        strBugcheckCode & " (" & strFirstArgument & ", " & strSecondArgument & ", " & strThirdArgument & ", " & strFourthArgument & "). Most of STOP error 0x9C are hardware initiated" & strAlertToAddTXT & ".", "" & _
                                        "Check more information about this memory dump below. Check more information about this STOP Error in KB 162363."
                            Case "00000116", "00000117"
                                AddXMLAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_MACHINE_DMP_FOUND, "Timeout Detection and Recovery (TDR) dump from <b>" & strFileAge & " ago</b> was found in " & strDumpFile & ". This dump is a <b>Stop error " & _
                                        "<font color='red'>0x" & strBugcheckCode & "</font> (" & strFirstArgument & ", " & strSecondArgument & ", " & strThirdArgument & ", " & strFourthArgument & "))</b>. Most of STOP error 0x116 and 0x117 are related to video and video driver components" & strAlertToAddXML & ".", "" & _
                                        "Check more information about this memory dump <a href=" & Chr(34) & "#" & strDumpFile & Chr(34) & ">here</a>. Check more information about this TDR mechanism <a target='_blank' href='http://www.microsoft.com/whdc/device/display/wddm_timeout.mspx'>on this following article</a>.", 100 - x
                                
                                AddScriptedDiagAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_MACHINE_DMP_FOUND, "Timeout Detection and Recovery (TDR) dump from <b>" & strFileAge & " ago</b> was found in " & strDumpFile & ". This dump is a <b>Stop error " & _
                                        "<font color='red'>0x" & strBugcheckCode & "</font> (" & strFirstArgument & ", " & strSecondArgument & ", " & strThirdArgument & ", " & strFourthArgument & "))</b>. Most of STOP error 0x116 and 0x117 are related to video and video driver components" & strAlertToAddScriptedDiagXML & ".", "" & _
                                        "Please open the file <a href=" & Chr(34) & "#" & strDumpFile & Chr(34) & ">" & strDumpFile & "</a> for more information about this dump. Check more information about this TDR mechanism <a target='_blank' href='http://www.microsoft.com/whdc/device/display/wddm_timeout.mspx'>on this following article</a>.", 100 - x
                                
                                AddTXTAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_MACHINE_DMP_FOUND, "Machine memory dump from " & strFileAge & " ago was found in " & strDumpFile & ". This dump is from a Stop error 0x" & _
                                        strBugcheckCode & " (" & strFirstArgument & ", " & strSecondArgument & ", " & strThirdArgument & ", " & strFourthArgument & "). Most of STOP error 0x116 and 0x117 are related to video and video driver components." & strAlertToAddTXT & ".", "" & _
                                        "Check more information about this memory dump below. Check more information about this STOP Error in article http://www.microsoft.com/whdc/device/display/wddm_timeout.mspx."
                            Case "000000AB"
                                DisplayAlertforSTOP0xAB strBugcheckCode, strFirstArgument, strSecondArgument, strThirdArgument, strFourthArgument, strFileAge, strDumpFile, x, arrMachineCompressedTo(intarrIndex)
                            Case Else
                                AddXMLAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_MACHINE_DMP_FOUND, "Machine memory dump from <b>" & strFileAge & " ago</b> was found in " & strDumpFile & ". This dump is from a <b>stop error code " & _
                                        "<font color='red'>0x" & strBugcheckCode & "</font> (" & strFirstArgument & ", " & strSecondArgument & ", " & strThirdArgument & ", " & strFourthArgument & ")</b>" & strAlertToAddXML & ".", "" & _
                                        "Check more information about this memory dump <a href=" & Chr(34) & "#" & strDumpFile & Chr(34) & ">here</a>.", 100 - x
                                
                                AddScriptedDiagAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_MACHINE_DMP_FOUND, "Machine memory dump from <b>" & strFileAge & " ago</b> was found in " & strDumpFile & ". This dump is from a <b>stop error code " & _
                                        "<font color='red'>0x" & strBugcheckCode & "</font> (" & strFirstArgument & ", " & strSecondArgument & ", " & strThirdArgument & ", " & strFourthArgument & ")</b>" & strAlertToAddScriptedDiagXML & ".", "" & _
                                        "Please open the file <a href=" & Chr(34) & "#" & strHTMLOutputfilename & Chr(34) & ">" & strHTMLOutputfilename & "</a> for more information about this dump.", 100 - x
                                
                                AddTXTAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_MACHINE_DMP_FOUND, "Machine memory dump from " & strFileAge & " ago was found in " & strDumpFile & ". This dump is from a stop error code " & _
                                        strBugcheckCode & " (" & strFirstArgument & ", " & strSecondArgument & ", " & strThirdArgument & ", " & strFourthArgument & ")" & strAlertToAddTXT & ".", "" & _
                                        "Check more information about this memory dump below."
                        End Select
                                
                        OpenTag "MemoryDumpDebugInfo"
                        LineOut "", "", True, False, ""
                        LineOut "Report for : ", strDumpFile, False, False, "Title"
                        LineOut "----------------------------------", "", True, False, ""
                        LineOut "", "", True, False, ""
                        LineOut "Memory dump path: ", strDumpFile, False, False, "Item"
                        LineOut "Stop error code : ", "0x" & strBugcheckCode & " (" & strFirstArgument & ", " & strSecondArgument & ", " & strThirdArgument & ", " & strFourthArgument & ")", False, False, "Item"
                        
                        If objDebugger.GetTimeInfo(strSessionTime, strUptime) Then
                            LineOut "Debug time      : ", strSessionTime, False, False, "Item"
                            LineOut "System uptime   : ", strUptime, False, False, "Item"
                        End If
                        If objDebugger.GetOSInfo(strOStarget, strBuild) Then
                            LineOut "Operating system: ", strOStarget, False, False, "Item"
                            If Len(strBuild) > 0 Then LineOut "Build           : ", strBuild, False, False, "Item"
                        End If
                        
                        ListModuleList objDebugger, strDumpFile
                        
                        CloseTag "MemoryDumpDebugInfo"
                        
                    Else
                        wscript.Echo " -- Error Obtaining Bugcheck information from " & strDumpFile & " in debugger..."
                        
                        ShowDebuggerDiagInfo (objDebugger.ExitandGetStdOutOutput)
                        
                        OpenTag "MemoryDumpDebugInfo"
                        LineOut "", "", True, False, ""
                        LineOut "Report for : ", strDumpFile, False, False, "Title"
                        LineOut "----------------------------------", "", True, False, ""
                        LineOut "", "", True, False, ""
                        LineOut "Memory dump path: ", strDumpFile, False, False, "Item"
                        LineOut "Additional Info : ", "Unable to obtain bugcheck information from file. This memory dump may be corrupted.", False, False, "Item"
                        CloseTag "MemoryDumpDebugInfo"
                        
                    End If
                    objDebugger.CloseDumpFile
                Else
                    wscript.Echo " -- Error opening " & strDumpFile & " in debugger..."
                    ShowDebuggerDiagInfo (objDebugger.ExitandGetStdOutOutput)
                    OpenTag "MemoryDumpDebugInfo"
                    LineOut "", "", True, False, ""
                    LineOut "Report for : ", strDumpFile, False, False, "Title"
                    LineOut "Additional Info : ", "Unable to open dump file. This memory dump may be corrupted.", False, False, "Item"
                    CloseTag "MemoryDumpDebugInfo"
                    
                    AddXMLAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_MACHINE_DMP_FOUND, "Machine memory dump from <b>" & strFileAge & " ago</b> found at " & strDumpFile & ".", "" & _
                        "Check more information about this memory dump <a href=" & Chr(34) & "#" & strDumpFile & Chr(34) & ">here</a>.", 100
                    
                    AddScriptedDiagAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_MACHINE_DMP_FOUND, "Machine memory dump from <b>" & strFileAge & " ago</b> found at " & strDumpFile & ".", "" & _
                        "Please open the file <a href=" & Chr(34) & "#" & strHTMLOutputfilename & Chr(34) & ">" & strHTMLOutputfilename & "</a> for more information about this dump.", 100
                    
                    AddTXTAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_MACHINE_DMP_FOUND, "Machine memory dump from " & strFileAge & " ago found at " & strDumpFile & ".", "" & _
                        "Check more information about this memory dump in the dump analysis section."
                    objDebugger.CloseDumpFile
                End If
            Else
                wscript.Echo " -- Error. " & strDumpFile & " does not exist..."
                'File does not exist. Most likely it was deleted by another process during execution
            End If
            intarrIndex = intarrIndex + 1
        Next
    Else
        wscript.Echo " -- There are no machine memory dumps to analyze."
    End If

    If Not IsEmpty(arrUserAnalyzeQueue) Then
        intarrIndex = 0
        For Each strDumpFile In arrUserAnalyzeQueue
            x = x + 1
            If Len(arrUserCompressedTo(intarrIndex)) > 0 Then
                strAlertToAddXML = ". Dump compressed to " & ObtainURLForExternalFiles(objFSO.GetFileName(arrUserCompressedTo(intarrIndex)), 1)
                strAlertToAddScriptedDiagXML = ". Dump compressed to " & ObtainURLForExternalFiles(objFSO.GetFileName(arrUserCompressedTo(intarrIndex)), 2)
                strAlertToAddTXT = ". Dump compressed to " & objFSO.GetFileName(arrUserCompressedTo(intarrIndex)) & ""
            Else
                strAlertToAddXML = ""
                strAlertToAddTXT = ""
            End If
            wscript.Echo " -- Opening " & strDumpFile & " in debugger..."
            If objFSO.FileExists(strDumpFile) Then
                Set objFile = objFSO.GetFile(strDumpFile)
                strFileAge = GetStrFileAge(objFile)
                Set objDebugger = New Debugger
                If objDebugger.OpenDumpFile(strDebuggerPath, strDumpFile) Then
                    Dim strProcessPath, strProcessID, strExceptionModule, strLastEvent, strEffMach, bModuleNameFound
                    objDebugger.GetLastEvent strLastEvent
                    objDebugger.GetEffectiveMachine strEffMach
                    If objDebugger.GetUsermodeProcessInfo(strProcessPath, strProcessID) Then
                        wscript.Echo "    User Mode Process: " & strProcessPath
                        If objDebugger.GetUsermodeExceptionModule(strExceptionModule) Then
                            bModuleNameFound = (strExceptionModule <> "0x0")
                            AddXMLAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_USER_DMP_FOUND, "User mode process dump from <b>" & strFileAge & " ago</b> from <b>" & objFSO.GetFileName(strProcessPath) & "</b> was found in " & strDumpFile & _
                                    iif(bModuleNameFound, " in <b><font color='red'>" & strExceptionModule & "</font></b>", "") & strAlertToAddXML & ".", "" & _
                                    "Check more information about this dump <a href=" & Chr(34) & "#" & strDumpFile & Chr(34) & ">here</a>.", 100 - x
                            
                            AddScriptedDiagAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_USER_DMP_FOUND, "User mode process dump from <b>" & strFileAge & " ago</b> from <b>" & objFSO.GetFileName(strProcessPath) & "</b> was found in " & strDumpFile & _
                                    iif(bModuleNameFound, " in <b><font color='red'>" & strExceptionModule & "</font></b>", "") & strAlertToAddScriptedDiagXML & ".", "" & _
                                    "Please open the file <a href=" & Chr(34) & "#" & strHTMLOutputfilename & Chr(34) & ">" & strHTMLOutputfilename & "</a> for more information about this dump.", 100 - x
                            
                            AddTXTAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_USER_DMP_FOUND, "User mode process dump from " & strFileAge & " ago from " & objFSO.GetFileName(strProcessPath) & " was found in " & strDumpFile & "." & _
                                    iif(bModuleNameFound, " in " & strExceptionModule, "") & strAlertToAddTXT & ".", "" & _
                                    "Check more information about this memory dump in the dump analysis section."
                        Else
                            bModuleNameFound = False
                            AddXMLAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_USER_DMP_FOUND, "User mode process dump <b>" & strFileAge & "</b> ago from <b>" & objFSO.GetFileName(strProcessPath) & "</b> was found in " & strDumpFile & strAlertToAddXML & ".", "" & _
                                    "Check more information about this dump <a href=" & Chr(34) & "#" & strDumpFile & Chr(34) & ">here</a>.", 100 - x
                            
                            AddScriptedDiagAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_USER_DMP_FOUND, "User mode process dump <b>" & strFileAge & "</b> ago from <b>" & objFSO.GetFileName(strProcessPath) & "</b> was found in " & strDumpFile & strAlertToAddScriptedDiagXML & ".", "" & _
                                    "Please open the file <a href=" & Chr(34) & "#" & strHTMLOutputfilename & Chr(34) & ">" & strHTMLOutputfilename & "</a> for more information about this dump.", 100 - x
                                    
                            AddTXTAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_USER_DMP_FOUND, "User mode process dump " & strFileAge & " ago from " & objFSO.GetFileName(strProcessPath) & " was found in " & strDumpFile & strAlertToAddTXT & ".", "" & _
                                    "Check more information about this memory dump in the dump analysis section."
                        End If
                                
                        OpenTag "MemoryDumpDebugInfo"
                        LineOut "", "", True, False, ""
                        LineOut "Report for : ", strDumpFile, False, False, "Title"
                        LineOut "----------------------------------", "", True, False, ""
                        LineOut "", "", True, False, ""
                        'LineOut "Type of Analysis: ", "User mode image summary", False, False, "Item"
                        'LineOut "User dump path  : ", strDumpFile, False, False, "Item"
                        LineOut "Process path    : ", strProcessPath, False, False, "Item"
                        If Len(strEffMach) Then LineOut "Process type    : ", strEffMach, False, False, "Item"
                        If bModuleNameFound And (Len(strExceptionModule) > 0) Then LineOut "Module     : ", strExceptionModule, False, False, "Item"
                        If Len(strLastEvent) > 0 Then LineOut "Exception       : ", strLastEvent, False, False, "Item"
                        
                        If objDebugger.GetTimeInfo(strSessionTime, strUptime) Then
                            LineOut "Debug time      : ", strSessionTime, False, False, "Item"
                        End If
                        
                        If objDebugger.GetOSInfo(strOStarget, strBuild) Then
                            LineOut "Operating system: ", strOStarget, False, False, "Item"
                            If Len(strBuild) > 0 Then LineOut "Build           : ", strBuild, False, False, "Item"
                        End If
                        
                        ListModuleList objDebugger, strDumpFile
                        
                        CloseTag "MemoryDumpDebugInfo"
                    Else
                        wscript.Echo " -- Error obtaining process information."
                        ShowDebuggerDiagInfo (objDebugger.ExitandGetStdOutOutput)
                    End If
                    objDebugger.CloseDumpFile
                Else
                    wscript.Echo " -- Error opening " & strDumpFile & " in debugger..."
                    ShowDebuggerDiagInfo (objDebugger.ExitandGetStdOutOutput)
                    OpenTag "MemoryDumpDebugInfo"
                    LineOut "", "", True, False, ""
                    LineOut "Error: ", "Unable to open dump file. Dump may be corrupted or there is a problem with the debugger.", False, False, "Item"
                    CloseTag "MemoryDumpDebugInfo"
                    
                    AddXMLAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_USER_DMP_FOUND, "User mode process dump from <b>" & strFileAge & " ago</b> found at " & strDumpFile & ".", "" & _
                        "Check more information about this memory dump <a href=" & Chr(34) & "#" & strDumpFile & Chr(34) & ">here</a>" & strAlertToAddTXT & ".", 100 - x
                    
                    AddScriptedDiagAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_USER_DMP_FOUND, "User mode process dump from <b>" & strFileAge & " ago</b> found at " & strDumpFile & ".", "" & _
                        "Please open the file <a href=" & Chr(34) & "#" & strHTMLOutputfilename & Chr(34) & ">" & strHTMLOutputfilename & "</a> for more information about this dump." & strAlertToAddTXT & ".", 100 - x
                    
                    AddTXTAlert ALERT_DUMP_FOUND, ALERT_CATEGORY_USER_DMP_FOUND, "User mode process  dump from " & strFileAge & " ago found at " & strDumpFile & strAlertToAddTXT & ".", "" & _
                        "Check more information about this memory dump in the dump analysis section."
                End If
            Else
                wscript.Echo " -- Error. " & strDumpFile & " does not exist..."
                'File does not exist. Most likely it was deleted by another process during execution
            End If
            intarrIndex = intarrIndex + 1
            Set objDebugger = Nothing
        Next
    Else
        wscript.Echo " -- There are no user memory dumps to analyze."
    End If
End Sub

Sub ShowDebuggerDiagInfo(strMSGToShow)
    wscript.Echo "Diagnostic information:"
    wscript.Echo "-------------------------"
    wscript.Echo strMSGToShow
    wscript.Echo "-------------------------"
    wscript.Echo ""
End Sub

Sub ListModuleList(objDebugger, strDumpFile)
    On Error Resume Next
    Err.Clear
    Dim arrImageName, arrImagePath, arrTimeStamp, arrFileVersion, arrProductVersion, arrFileDescription, arrCompanyName, arrLegalCopyright, arrMemoryRange
    Dim strCompanyNameFromFS, strFileVersionFromFS, strFileDescriptionFromFS, x, strTimeStampDataTimeOnly
    If objDebugger.GetLoadedModuleList(arrImageName, arrImagePath, arrTimeStamp, arrFileVersion, arrProductVersion, arrFileDescription, arrCompanyName, arrLegalCopyright, arrMemoryRange) Then
        OpenTag "ModuleList"
        LineOut "", "", True, True, ""
        LineOut "-- Module list", "", True, True, ""
        LineOut "", "", True, True, ""
            For x = 0 To UBound(arrImageName)
                If Err.Number = 0 Then
                    OpenTag ("Binary")
                    LineOut "  Image Name        : ", arrImageName(x), False, False, "Name"
                    LineOut "    Memory Range    : ", arrMemoryRange(x), False, False, "Range"
                    LineOut "    Image Path      : ", arrImagePath(x), False, False, "Property"
                    LineOut "    Time Stamp      : ", arrTimeStamp(x), True, False, "Property"
                    strTimeStampDataTimeOnly = Left(arrTimeStamp(x), InStr(1, arrTimeStamp(x), " (") - 1)
                    LineOut "    Time Stamp      : ", strTimeStampDataTimeOnly, False, True, "Property"
                    If arrFileVersion(x) <> "" Then LineOut "    File description: ", arrFileDescription(x), False, False, "Property"
                    If arrFileVersion(x) <> "" Then LineOut "    File version    : ", arrFileVersion(x), False, False, "Property"
                    If arrProductVersion(x) <> "" Then LineOut "    Product version : ", arrProductVersion(x), False, False, "Property"
                    If arrCompanyName(x) <> "" Then LineOut "    Company Name    : ", arrCompanyName(x), False, False, "Property"
                    If arrLegalCopyright(x) <> "" Then LineOut "    Copyrights      : ", arrLegalCopyright(x), True, False, "Property"
                    If arrCompanyName(x) = "" Then  'Company is missing from dump. Let's try to find this information in the file system
                        If ObtainNonDumpInfofromFS(arrImagePath(x), strCompanyNameFromFS, strFileVersionFromFS, strFileDescriptionFromFS) Then 'if binary is still in the file system, obtain these information
                            If (Len(strCompanyNameFromFS) > 0) Then
                                LineOut "    Company Name    : ", strCompanyNameFromFS, False, True, "FSProperty"
                                LineOut "   *Company Name    : ", strCompanyNameFromFS, True, False, ""
                            End If
                            If (Len(strFileVersionFromFS) > 0) Then
                                LineOut "    Current version : ", strFileVersionFromFS, False, True, "FSProperty"
                                LineOut "   *Current version : ", strFileVersionFromFS, True, False, ""
                            End If
                            If (Len(strFileDescriptionFromFS) > 0) And (Len(arrFileDescription(x)) = 0) Then
                                LineOut "    File description: ", strFileDescriptionFromFS, False, True, "FSProperty"
                                LineOut "   *File description: ", strFileDescriptionFromFS, True, False, ""
                            End If
                        End If
                    End If
                    LineOut "", "", True, True, ""
                    CloseTag ("Binary")
                End If
            Next
        CloseTag "ModuleList"
    End If
End Sub

Function GetMachineDumpType(intType)
    Select Case intType
        Case 0
            GetMachineDumpType = "None"
        Case 1
            GetMachineDumpType = "Complete memory dump"
        Case 2
            GetMachineDumpType = "Kernel memory dump"
        Case 3
            GetMachineDumpType = "Small memory dump 64 KB"
        Case 7
            GetMachineDumpType = "Automatic memory dump"
        Case Else
            GetMachineDumpType = CStr(intType) & " - Unknown type"
    End Select
End Function

Sub WriteDumpConfigInfo()
    'Obtain general dump configuration information
    OpenTag "SubSession"
    On Error Resume Next
    LineOut " -- Machine memory dump configuration information", "", False, False, "SessionTitle"
    LineOut "", "", True, False, ""
    
    Dim strMemoryDumpLocation, intMemoryDumpType, bFullMemoryDumpEnabled, intMachineMemory, colItems, objItem, bIgnorePagefileSize, bAlertStandardInfo, intOverwriteExistingDump, bDedicatedDumpFile
    Dim strDedicatedDumpFile, strDumpFileSizeinMB, lngCurrentDedicatedDumpFileSizeinMB
    Dim strDedicatedDumpFileSize, strDedicatedDumpFileSizeinMB, objPageFile
    
    OpenWMIService
    
    bAlertStandardInfo = True
    strMemoryDumpLocation = ReplaceEnvVars(objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\DumpFile"))
    intMemoryDumpType = objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\CrashDumpEnabled")
    bFullMemoryDumpEnabled = iif(intMemoryDumpType = 1, True, False)
    
    bIgnorePagefileSize = False
    bIgnorePagefileSize = (objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\IgnorePagefileSize") = 1)

    intOverwriteExistingDump = 1
    intOverwriteExistingDump = (objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\Overwrite") = 1)
    
    LineOut "    Memory Dump Location   : ", strMemoryDumpLocation, False, False, "Item"
    LineOut "    Memory Dump Type       : ", CStr(intMemoryDumpType) & " - " & GetMachineDumpType(intMemoryDumpType), False, False, "Item"
    LineOut "    Autoreboot             : ", iif(objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\AutoReboot") = 1, "True", "False"), False, False, "Item"
    LineOut "    Overwrite existing file: ", iif(intOverwriteExistingDump = 1, "True", "False"), False, False, "Item"
    LineOut "    Write event log        : ", iif(objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\LogEvent") = 1, "True", "False"), False, False, "Item"
    
    If bIgnorePagefileSize Then
        LineOut "    Ignore pagefile size   : ", "Enabled", False, False, "Item"
        AddXMLAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "Machine is configured to ignore the size of page file when generating memory dumps.", "By default Windows Vista and Windows Server 2008 need to have a page file on system drive that is larger than the size of the memory. This machine is configured to ignore this restriction by having the IgnorePagefileSize setting. Article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;949052'>KB 949052</a> contains more information about this setting.", 100
        AddScriptedDiagAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "Machine is configured to ignore the size of page file when generating memory dumps.", "By default Windows Vista and Windows Server 2008 need to have a page file on system drive that is larger than the size of the memory. This machine is configured to ignore this restriction by having the IgnorePagefileSize setting. Article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;949052'>KB 949052</a> contains more information about this setting.", 100
        AddTXTAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "Machine is configured to ignore the size of page file when generating memory dumps.", "By default Windows Vista and Windows Server 2008 need to have a page file on system drive that is larger than the size of the memory. This machine is configured to ignore this restriction by having the IgnorePagefileSize setting. Article KB 949052 contains more information about this setting."
        bMachineDumpConfigProblemDetected = True
        bAlertStandardInfo = False
    End If
    
    bDedicatedDumpFile = False
    bDedicatedDumpFile = (Len(objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\DedicatedDumpFile")) > 0)
    
    
    If bDedicatedDumpFile Then
        strDedicatedDumpFileSize = objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\DedicatedDumpFile")
        strDedicatedDumpFileSizeinMB = objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\DumpFileSize")
        
        LineOut "    Dedicated Memory Dump Page File      : ", "Enabled", False, False, "Item"
        LineOut "    Dedicated Memory Dump Page File Name : ", ReplaceEnvVars(strDedicatedDumpFile), False, False, "Item"
        LineOut "    Dedicated Memory Dump Page File Size : ", CStr(strDedicatedDumpFileSizeinMB) + " MB", False, False, "Item"
        If objFSO.FileExists(ReplaceEnvVars(strDedicatedDumpFile)) Then
            Set objPageFile = objFSO.GetFile(ReplaceEnvVars(strDedicatedDumpFile))
            lngCurrentDedicatedDumpFileSizeinMB = CLng(objPageFile.Size / 1024)
        End If
    End If
    
    LineOut "    Minidumps folder       : ", ReplaceEnvVars(objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\MinidumpDir")), False, False, "Item"
    
    Select Case intMemoryDumpType
        Case 0
            AddXMLAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is not configured to generate memory dumps.", "If you are interested in obtaining machine memory dumps in this machine, please use steps described in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;254649'>KB 254649</a> to configure machine to generate a memory dump", 100
            AddScriptedDiagAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is not configured to generate memory dumps.", "If you are interested in obtaining machine memory dumps in this machine, please use steps described in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;254649'>KB 254649</a> to configure machine to generate a memory dump", 100
            AddTXTAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is not configured to generate memory dumps.", "If you are interested in obtaining machine memory dumps in this machine, please use steps described in KB 254649 to configure machine to generate a memory dump"
            bAlertStandardInfo = False
            bMachineDumpConfigProblemDetected = True
        Case 3
            AddXMLAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate small dumps only.", "If you are interested in obtaining machine memory dumps in this machine, it is recommended that you use steps described in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;254649'>KB 254649</a> to configure machine to generate either a Kernel or Complete memory dump.", 100
            AddScriptedDiagAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate small dumps only.", "If you are interested in obtaining machine memory dumps in this machine, it is recommended that you use steps described in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;254649'>KB 254649</a> to configure machine to generate either a Kernel or Complete memory dump.", 100
            AddTXTAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate small dumps only.", "If you are interested in obtaining machine memory dumps in this machine, it is recommended that you use steps described in KB 254649 to configure machine to generate either a Kernel or Complete memory dump."
            bMachineDumpConfigProblemDetected = True
            bAlertStandardInfo = False
    End Select
       
    If intOverwriteExistingDump = 0 Then
        If objFSO.FileExists(strMemoryDumpLocation) Then
            AddXMLAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to not overwrite existing memory dump files and a memory dump file already exists under <b>" + strMemoryDumpLocation + "</b>. Based on this configuration, if this machine crashes again, the memory dump information will not be generated.", "If you are interested in obtaining machine memory dumps in this machine, please make sure the option 'Overwrite any existing file' under Startup and Recovery is checked. For more information, please check the following article: <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;307973'>KB 307973</a>.", 2000
            AddScriptedDiagAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to not overwrite existing memory dump files and a memory dump file already exists under <b>" + strMemoryDumpLocation + "</b>. Based on this configuration, if this machine crashes again, the memory dump information will not be generated.", "If you are interested in obtaining machine memory dumps in this machine, please make sure the option 'Overwrite any existing file' under Startup and Recovery is checked. For more information, please check the following article: <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;307973'>KB 307973</a>.", 2000
            AddTXTAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to not overwrite existing memory dump files and a memory dump file already exists under " + strMemoryDumpLocation + ". Based on this configuration, if this machine crashes again, the memory dump information will not be generated.", "If you are interested in obtaining machine memory dumps in this machine, please make sure the option 'Overwrite any existing file' under Startup and Recovery is checked. For more information, please check the article KB 307973."
            bAlertStandardInfo = False
            bMachineDumpConfigProblemDetected = True
        Else
            AddXMLAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to do not overwrite the existing memory dump files.", "If you are interested to obtain machine memory dumps, it is recommended that you uncheck the option 'Overwrite any existing file' under Startup and Recovery to make sure the memory dump present on the disk is from the most recent crash. For more information, please check the following article: <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;307973'>KB 307973</a>.", 50
            AddScriptedDiagAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to do not overwrite the existing memory dump files.", "If you are interested to obtain machine memory dumps, it is recommended that you uncheck the option 'Overwrite any existing file' under Startup and Recovery to make sure the memory dump present on the disk is from the most recent crash. For more information, please check the following article: <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;307973'>KB 307973</a>.", 50
            AddTXTAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to do not overwrite the existing memory dump files.", "If you are interested to obtain machine memory dumps, it is recommended that you uncheck the option 'Overwrite any existing file' under Startup and Recovery to make sure the memory dump present on the disk is from the most recent crash. For more information, please check the article KB 307973."
            bAlertStandardInfo = False
        End If
    End If
    
    Set colItems = objWMIService.ExecQuery("Select * from Win32_OperatingSystem", , 48)
    For Each objItem In colItems
        intMachineMemory = objItem.TotalVisibleMemorySize
    Next

    Dim objDrive, lngSystemPageFileSizeinMB
    
    'Check for free space on dump drive

    Set objDrive = objFSO.GetDrive(objFSO.GetDriveName(strMemoryDumpLocation))
    If bFullMemoryDumpEnabled Then
        If ((objDrive.FreeSpace / 1048576) < CLng(intMachineMemory / 1048576)) Then
            AddXMLAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate a full memory dump on '" & strMemoryDumpLocation & "', however the space available on drive " & objDrive.DriveLetter & ": is only " & FormatNumber(objDrive.FreeSpace / 1024 / 1024 / 1024, 2) & " GB", "Please free space on drive " & objDrive.DriveLetter & ":. There is no space available to save the memory dump. Please change the memory dump type to 'Kernel' or change the memory dump location. For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;130536'>KB 130536</a>.", 500
            AddScriptedDiagAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate a full memory dump on '" & strMemoryDumpLocation & "', however the space available on drive " & objDrive.DriveLetter & ": is only " & FormatNumber(objDrive.FreeSpace / 1024 / 1024 / 1024, 2) & " GB", "Please free space on drive " & objDrive.DriveLetter & ":. There is no space available to save the memory dump. Please change the memory dump type to 'Kernel' or change the memory dump location. For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;130536'>KB 130536</a>.", 500
            AddTXTAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate a full memory dump on '" & strMemoryDumpLocation & "', however the space available on drive " & objDrive.DriveLetter & ": is only " & FormatNumber(objDrive.FreeSpace / 1024 / 1024 / 1024, 2) & " GB", "Please free space on drive " & objDrive.DriveLetter & ":. There is no space available to save the memory dump. Please change the memory dump type to 'Kernel' or change the memory dump location. For more information, please check the article KB 130536."
            bMachineDumpConfigProblemDetected = True
            bAlertStandardInfo = False
        ElseIf ((objDrive.FreeSpace / 1048576) < ((intMachineMemory / 1048576) + 0.2)) Then
            AddXMLAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "Machine is configured to generate full memory dump on '" & strMemoryDumpLocation & "', however the space available on drive " & objDrive.DriveLetter & ": is only " & FormatNumber(objDrive.FreeSpace / 1024 / 1024 / 1024, 2) & " GB", "Please free space on drive " & objDrive.DriveLetter & ":, in order to make sure the full machine memory dump will be generated, change the location to save the memory dump to another drive or change the memory dump type to 'Kernel'. For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;130536'>KB 130536</a>.", 500
            AddScriptedDiagAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "Machine is configured to generate full memory dump on '" & strMemoryDumpLocation & "', however the space available on drive " & objDrive.DriveLetter & ": is only " & FormatNumber(objDrive.FreeSpace / 1024 / 1024 / 1024, 2) & " GB", "Please free space on drive " & objDrive.DriveLetter & ":, in order to make sure the full machine memory dump will be generated, change the location to save the memory dump to another drive or change the memory dump type to 'Kernel'. For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;130536'>KB 130536</a>.", 500
            AddTXTAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "Machine is configured to generate full memory dump on '" & strMemoryDumpLocation & "', however the space available on drive " & objDrive.DriveLetter & ": is only " & FormatNumber(objDrive.FreeSpace / 1024 / 1024 / 1024, 2) & " GB", "Please free space on drive " & objDrive.DriveLetter & ":, in order to make sure the full machine memory dump will be generated, change the location to save the memory dump to another drive or change the memory dump type to 'Kernel'. For more information, please check the article KB 130536."
            bMachineDumpConfigProblemDetected = True
            bAlertStandardInfo = False
        End If
    ElseIf intMemoryDumpType = 2 Then 'Kernel
        If ((objDrive.FreeSpace / 1048576) < 1.2) Then 'Test if we have at least 1.2 GB of space in system drive
            AddXMLAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate Kernel memory dump on '" & strMemoryDumpLocation & "', however the space available on drive " & objDrive.DriveLetter & ": is only " & FormatNumber(objDrive.FreeSpace / 1024 / 1024 / 1024, 1) & " GB", "Please free space on drive " & objDrive.DriveLetter & ": to make sure there will be enough space for the kernel dump to be generated. For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;130536'>KB 130536</a>.", 2000
            AddScriptedDiagAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate Kernel memory dump on '" & strMemoryDumpLocation & "', however the space available on drive " & objDrive.DriveLetter & ": is only " & FormatNumber(objDrive.FreeSpace / 1024 / 1024 / 1024, 1) & " GB", "Please free space on drive " & objDrive.DriveLetter & ": to make sure there will be enough space for the kernel dump to be generated. For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;130536'>KB 130536</a>.", 2000
            AddTXTAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate Kernel memory dump on '" & strMemoryDumpLocation & "', however the space available on drive " & objDrive.DriveLetter & ": is only " & FormatNumber(objDrive.FreeSpace / 1024 / 1024 / 1024, 1) & " GB", "Please free space on drive " & objDrive.DriveLetter & ": to make sure there will be enough space for the kernel dump to be generated. For more information, please check the article KB 130536."
            bMachineDumpConfigProblemDetected = True
            bAlertStandardInfo = False
        End If
    End If
    
    'Rules for Pre-Windows Vista
    '---------------------------
    
    'Check if there is a page file in System Drive and its size
    If (intWindowsVersion < 6) Then
        If objFSO.FileExists(ReplaceEnvVars("%SystemDrive%") & "\pagefile.sys") Then
            Set objPageFile = objFSO.GetFile(ReplaceEnvVars("%SystemDrive%") & "\pagefile.sys")
            Set objDrive = objFSO.GetDrive(objFSO.GetDriveName(ReplaceEnvVars("%SystemDrive%")))
            If bFullMemoryDumpEnabled And (CLng(objPageFile.Size / 1024) < CLng(intMachineMemory)) Then
                AddXMLAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory and is configured to generate full memory dump, however the page file configured on drive " & objDrive.DriveLetter & ": has only " & FormatNumber(objPageFile.Size / 1024 / 1024 / 1024, 2) & " GB.", "Please increase the pagefile size on drive " & objDrive.DriveLetter & ": since there is no space available on pagefile to save the memory dump information, or change the memory dump type to 'Kernel'. For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;130536'>KB 130536</a>.", 5000
                AddScriptedDiagAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory and is configured to generate full memory dump, however the page file configured on drive " & objDrive.DriveLetter & ": has only " & FormatNumber(objPageFile.Size / 1024 / 1024 / 1024, 2) & " GB.", "Please increase the pagefile size on drive " & objDrive.DriveLetter & ": since there is no space available on pagefile to save the memory dump information, or change the memory dump type to 'Kernel'. For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;130536'>KB 130536</a>.", 5000
                AddTXTAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory and is configured to generate full memory dump, however the page file configured on drive " & objDrive.DriveLetter & ": has only " & FormatNumber(objPageFile.Size / 1024 / 1024 / 1024, 2) & " GB.", "Please increase the pagefile size on on drive " & objDrive.DriveLetter & ": since there is no space available on pagefile to save the memory dump information, or change the memory dump type to 'Kernel'. For more information, please check the article KB 130536."
                bMachineDumpConfigProblemDetected = True
                bAlertStandardInfo = False
            ElseIf intMemoryDumpType = 2 Then 'Kernel
                If ((objPageFile.Size / 1024) < (intMachineMemory / 4)) Then 'Test if we have at least 1/4 of memory space space in page file
                    AddXMLAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate Kernel memory dump and the pagefile configured on drive " & objDrive.DriveLetter & ": has only " & FormatNumber(objPageFile.Size / 1024 / 1024 / 1024, 2) & " GB.", "The size of pagefile in System drive (" & ReplaceEnvVars("%SystemDrive%") & ":) may be too small. We recommend you to increase the pagefile size on drive " & objDrive.DriveLetter & ": to make sure there will be enough space for the kernel dump to be generated. For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;130536'>KB 130536</a>.", 2000
                    AddScriptedDiagAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate Kernel memory dump and the pagefile configured on drive " & objDrive.DriveLetter & ": has only " & FormatNumber(objPageFile.Size / 1024 / 1024 / 1024, 2) & " GB.", "The size of pagefile in System drive (" & ReplaceEnvVars("%SystemDrive%") & ":) may be too small. We recommend you to increase the pagefile size on drive " & objDrive.DriveLetter & ": to make sure there will be enough space for the kernel dump to be generated. For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;130536'>KB 130536</a>.", 2000
                    AddTXTAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate Kernel memory dump and the pagefile configured on drive " & objDrive.DriveLetter & ": has only " & FormatNumber(objPageFile.Size / 1024 / 1024 / 1024, 2) & " GB.", "The size of pagefile in System (" & ReplaceEnvVars("%SystemDrive%") & ":) drive may be too small. We recommend you to increase the pagefile size on drive " & objDrive.DriveLetter & ": to make sure there will be enough space for the kernel dump to be generated. For more information, please check the article KB 130536."
                    bMachineDumpConfigProblemDetected = True
                    bAlertStandardInfo = False
                End If
            End If
        Else
            If intMemoryDumpType > 0 Then
                AddXMLAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate memory dumps, however there is no pagefile created on system drive (" & ReplaceEnvVars("%SystemDrive%") & ").", "Please create a pagefile on drive " & ReplaceEnvVars("%SystemDrive%") & ". For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;130536'>KB 130536</a>.", 5000
                AddScriptedDiagAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate memory dumps, however there is no pagefile created on system drive (" & ReplaceEnvVars("%SystemDrive%") & ").", "Please create a pagefile on drive " & ReplaceEnvVars("%SystemDrive%") & ". For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;130536'>KB 130536</a>.", 5000
                AddTXTAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate memory dumps, however there is no pagefile created on system drive (" & ReplaceEnvVars("%SystemDrive%") & ").", "Please create a pagefile on drive " & ReplaceEnvVars("%SystemDrive%") & ". For more information, please check the article KB 130536."
                bMachineDumpConfigProblemDetected = True
                bAlertStandardInfo = False
            End If
        End If
    End If
    
    'Rules for Windows Vista
    '-----------------------
    If (intWindowsVersion = 6) Then
    
        lngSystemPageFileSizeinMB = 0
        Set colItems = objWMIService.ExecQuery("Select * from Win32_PageFileUsage where Name like '" + ReplaceEnvVars("%SystemDrive%") + "%'", , 48)
        For Each objItem In colItems
            lngSystemPageFileSizeinMB = lngSystemPageFileSizeinMB + objItem.AllocatedBaseSize
        Next
        
        If bFullMemoryDumpEnabled Then
            If (Not (bDedicatedDumpFile)) And (CLng(lngSystemPageFileSizeinMB) < CLng(intMachineMemory / 1024)) Then
                AddXMLAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory and is configured to generate full machine memory dumps, however the page file configured on system drive (" & ReplaceEnvVars("%SystemDrive%") & ":) has only " & FormatNumber(lngSystemPageFileSizeinMB / 1024, 2) & " GB.", "Please increase the size of the pagefile on System drive since there is currently no space available to save the memory dump information. Alternatively, change the memory dump type to 'Kernel' or use the DedicatedDumpFile setting. For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;969028'>KB 969028</a>.", 5000
                AddScriptedDiagAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory and is configured to generate full machine memory dumps, however the page file configured on system drive (" & ReplaceEnvVars("%SystemDrive%") & ":) has only " & FormatNumber(lngSystemPageFileSizeinMB / 1024, 2) & " GB.", "Please increase the size of the pagefile on System drive since there is currently no space available to save the memory dump information. Alternatively, change the memory dump type to 'Kernel' or use the DedicatedDumpFile setting. For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;969028'>KB 969028</a>.", 5000
                AddTXTAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory and is configured to generate full machine memory dumps, however the page file configured on system drive (" & ReplaceEnvVars("%SystemDrive%") & ":) has only " & FormatNumber(lngSystemPageFileSizeinMB / 1024, 2) & " GB.", "Please increase the size of the pagefile on System drive since there is currently no space available to save the memory dump information. Alternatively, change the memory dump type to 'Kernel' or use the DedicatedDumpFile setting. For more information, please check the article KB 969028."
                bMachineDumpConfigProblemDetected = True
                bAlertStandardInfo = False
            ElseIf ((bDedicatedDumpFile) And (CLng(lngCurrentDedicatedDumpFileSizeinMB) < CLng(intMachineMemory / 1024))) Then
                AddXMLAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory, it is configured to a Dedicated Page File for machine memory dumps and is configured to generate full memory dump. However the dedicated page file configured on " & ReplaceEnvVars(strDedicatedDumpFile) & " has only " & FormatNumber(lngCurrentDedicatedDumpFileSizeinMB / 1024, 2) & " GB and it is too small for the current configuration.", "Please increase the size of the dedicated memory dump file since it does not have space available to save the full memory dump information. Alternatively, change the memory dump type to 'Kernel' and use the IgnorePagefileSize setting. For more information, please check the articles <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;969028'>KB 969028</a> and <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;949052'>KB 949052</a>.", 5000
                AddScriptedDiagAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory, it is configured to a Dedicated Page File for machine memory dumps and is configured to generate full memory dump. However the dedicated page file configured on " & ReplaceEnvVars(strDedicatedDumpFile) & " has only " & FormatNumber(lngCurrentDedicatedDumpFileSizeinMB / 1024, 2) & " GB and it is too small for the current configuration.", "Please increase the size of the dedicated memory dump file since it does not have space available to save the full memory dump information. Alternatively, change the memory dump type to 'Kernel' and use the IgnorePagefileSize setting. For more information, please check the articles <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;969028'>KB 969028</a> and <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;949052'>KB 949052</a>.", 5000
                AddTXTAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory, it is configured to a Dedicated Page File for machine memory dumps and is configured to generate full memory dump. However the dedicated page file configured on " & ReplaceEnvVars(strDedicatedDumpFile) & " has only " & FormatNumber(lngCurrentDedicatedDumpFileSizeinMB / 1024, 2) & " GB and it is too small for the current configuration.", "Please increase the size of the dedicated memory dump file since it does not have space available to save the full memory dump information. Alternatively, change the memory dump type to 'Kernel' and use the IgnorePagefileSize setting. For more information, please check the articles KB 969028 and KB 949052."
                bMachineDumpConfigProblemDetected = True
                bAlertStandardInfo = False
            End If
        ElseIf (intMemoryDumpType = 2) Then 'Kernel
            If bDedicatedDumpFile Then
                If (CLng(lngCurrentDedicatedDumpFileSizeinMB) < CLng(intMachineMemory / 1024) And (bIgnorePagefileSize = False)) Then
                    AddXMLAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory, it is configured to a Dedicated Page File and configured to generate kernel machine memory dumps, however the dedicated page file configured on " & ReplaceEnvVars(strDedicatedDumpFile) & " has only " & FormatNumber(lngCurrentDedicatedDumpFileSizeinMB / 1024, 2) & " GB and it is too small for the current configuration.", "Please increase the size of the dedicated memory dump file since it does not have space available to save the full memory dump information. Alternatively, change the memory dump type to 'Kernel' and use the IgnorePagefileSize setting. For more information, please check the articles <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;969028'>KB 969028</a> and <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;949052'>KB 949052</a>.", 5000
                    AddScriptedDiagAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory, it is configured to a Dedicated Page File and configured to generate kernel machine memory dumps, however the dedicated page file configured on " & ReplaceEnvVars(strDedicatedDumpFile) & " has only " & FormatNumber(lngCurrentDedicatedDumpFileSizeinMB / 1024, 2) & " GB and it is too small for the current configuration.", "Please increase the size of the dedicated memory dump file since it does not have space available to save the full memory dump information. Alternatively, change the memory dump type to 'Kernel' and use the IgnorePagefileSize setting. For more information, please check the articles <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;969028'>KB 969028</a> and <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;949052'>KB 949052</a>.", 5000
                    AddTXTAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory, it is configured to a Dedicated Page File and configured to generate kernel machine memory dumps, however the dedicated page file configured on " & ReplaceEnvVars(strDedicatedDumpFile) & " has only " & FormatNumber(lngCurrentDedicatedDumpFileSizeinMB / 1024, 2) & " GB and it is too small for the current configuration.", "Please increase the size of the dedicated memory dump file since it does not have space available to save the full memory dump information. Alternatively, change the memory dump type to 'Kernel' and use the IgnorePagefileSize setting. For more information, please check the articles KB 969028 and KB 949052."
                    bMachineDumpConfigProblemDetected = True
                    bAlertStandardInfo = False
                End If
            Else
                If (CLng(lngSystemPageFileSizeinMB) < CLng(intMachineMemory / 1024) And (bIgnorePagefileSize = False)) Then
                    AddXMLAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory and is configured to generate kernel memory dump, however the page file configured on System drive (" & ReplaceEnvVars("%SystemDrive%") & ":) has only " & FormatNumber(lngSystemPageFileSizeinMB / 1024, 2) & " GB.", "Please increase the size of the pagefile on System drive since there is currently no space available to save the memory dump information. Alternatively, please add the IgnorePagefileSize setting. For more information, please check articles For more information, please check the articles <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;969028'>KB 969028</a> and <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;949052'>KB 949052</a>.", 5000
                    AddScriptedDiagAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory and is configured to generate kernel memory dump, however the page file configured on System drive (" & ReplaceEnvVars("%SystemDrive%") & ":) has only " & FormatNumber(lngSystemPageFileSizeinMB / 1024, 2) & " GB.", "Please increase the size of the pagefile on System drive since there is currently no space available to save the memory dump information. Alternatively, please add the IgnorePagefileSize setting. For more information, please check articles For more information, please check the articles <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;969028'>KB 969028</a> and <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;949052'>KB 949052</a>.", 5000
                    AddTXTAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory and is configured to generate kernel memory dump, however the page file configured on System drive (" & ReplaceEnvVars("%SystemDrive%") & ":) has only " & FormatNumber(lngSystemPageFileSizeinMB / 1024, 2) & " GB.", "Please increase the size of the pagefile on System drive since there is currently no space available to save the memory dump information. Alternatively, please add the IgnorePagefileSize setting. For more information, please check articles For more information, please check the articles KB 969028 and KB 949052."
                    bMachineDumpConfigProblemDetected = True
                    bAlertStandardInfo = False
                End If
            End If
        End If
        
    End If
    
    'Rules for Windows 7
    '-------------------------------------
    
    If (intWindowsVersion > 6) Then
        'Calculate the total pagefile size
        Dim lngTotalPageFileSizeinMB, lngSizeofBiggestPagefileinMB

        lngTotalPageFileSizeinMB = 0
        lngSizeofBiggestPagefileinMB = 0

        Set colItems = objWMIService.ExecQuery("Select * from Win32_PageFileUsage", , 48)
        For Each objItem In colItems
            lngTotalPageFileSizeinMB = lngTotalPageFileSizeinMB + objItem.AllocatedBaseSize
            If (lngSizeofBiggestPagefileinMB < objItem.AllocatedBaseSize) Then
                lngSizeofBiggestPagefileinMB = objItem.AllocatedBaseSize
            End If
        Next

        
        If (bFullMemoryDumpEnabled) Then
            If (Not (bDedicatedDumpFile)) And (CLng(lngSizeofBiggestPagefileinMB) < CLng(intMachineMemory / 1024)) Then
                AddXMLAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory and is configured to generate full memory dump, however the size of the largest page file is only " & FormatNumber(lngSizeofBiggestPagefileinMB / 1024 / 1024, 2) & " GB.", "Please increase the size of the individual pagefiles since there is currently no space available to save the memory dump information. Alternatively, change the memory dump type to 'Kernel'. For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;969028'>KB 969028</a>.", 5000
                AddScriptedDiagAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory and is configured to generate full memory dump, however the size of the largest page file is only " & FormatNumber(lngSizeofBiggestPagefileinMB / 1024 / 1024, 2) & " GB.", "Please increase the size of the individual pagefiles since there is currently no space available to save the memory dump information. Alternatively, change the memory dump type to 'Kernel'. For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;969028'>KB 969028</a>.", 5000
                AddTXTAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory and is configured to generate full memory dump, however the size of the largest page file is only " & FormatNumber(lngSizeofBiggestPagefileinMB / 1024 / 1024, 2) & " GB.", "Please increase the size of the individual pagefiles since there is currently no space available to save the memory dump information. Alternatively, change the memory dump type to 'Kernel'. For more information, please check the article KB 969028."
                bMachineDumpConfigProblemDetected = True
                bAlertStandardInfo = False
            ElseIf ((bDedicatedDumpFile) And (CLng(lngCurrentDedicatedDumpFileSizeinMB) < CLng(intMachineMemory / 1024))) Then
                AddXMLAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory, it is configured to a Dedicated Page File for machine memory dumps and is configured to generate full memory dump. However the dedicated page file configured on " & ReplaceEnvVars(strDedicatedDumpFile) & " has only " & FormatNumber(lngCurrentDedicatedDumpFileSizeinMB / 1024, 2) & " GB and it is too small for the current configuration.", "Please increase the size of the dedicated memory dump file since it does not have space available to save the full memory dump information. Alternatively, change the memory dump type to 'Kernel' and use the IgnorePagefileSize setting. For more information, please check the articles <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;969028'>KB 969028</a> and <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;949052'>KB 949052</a>.", 5000
                AddScriptedDiagAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory, it is configured to a Dedicated Page File for machine memory dumps and is configured to generate full memory dump. However the dedicated page file configured on " & ReplaceEnvVars(strDedicatedDumpFile) & " has only " & FormatNumber(lngCurrentDedicatedDumpFileSizeinMB / 1024, 2) & " GB and it is too small for the current configuration.", "Please increase the size of the dedicated memory dump file since it does not have space available to save the full memory dump information. Alternatively, change the memory dump type to 'Kernel' and use the IgnorePagefileSize setting. For more information, please check the articles <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;969028'>KB 969028</a> and <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;949052'>KB 949052</a>.", 5000
                AddTXTAlert ALERT_ERROR, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory, it is configured to a Dedicated Page File for machine memory dumps and is configured to generate full memory dump. However the dedicated page file configured on " & ReplaceEnvVars(strDedicatedDumpFile) & " has only " & FormatNumber(lngCurrentDedicatedDumpFileSizeinMB / 1024, 2) & " GB and it is too small for the current configuration.", "Please increase the size of the dedicated memory dump file since it does not have space available to save the full memory dump information. Alternatively, change the memory dump type to 'Kernel' and use the IgnorePagefileSize setting. For more information, please check the articles KB 969028 and KB 949052."
                bMachineDumpConfigProblemDetected = True
                bAlertStandardInfo = False
            End If
        ElseIf intMemoryDumpType = 2 Then 'Kernel
            If (Not (bDedicatedDumpFile)) And (CLng(lngSizeofBiggestPagefileinMB) < (CLng(intMachineMemory / 1024) / 4)) Then
                AddXMLAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory and is configured to generate Kernel machine memory dump, however the size of the largest page file is only " & FormatNumber(lngSizeofBiggestPagefileinMB / 1024 / 1024, 2) & " GB.", "If you are interested to obtain machine memory dumps on this machine, please increase the size of any individual pagefiles to make sure there will be enough space for the kernel dump to be generated. Alternatively, you can create a dedicated page file for memory dumps on this machine. For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;969028'>KB 969028</a>.", 5000
                AddScriptedDiagAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory and is configured to generate Kernel machine memory dump, however the size of the largest page file is only " & FormatNumber(lngSizeofBiggestPagefileinMB / 1024 / 1024, 2) & " GB.", "If you are interested to obtain machine memory dumps on this machine, please increase the size of any individual pagefiles to make sure there will be enough space for the kernel dump to be generated. Alternatively, you can create a dedicated page file for memory dumps on this machine. For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;969028'>KB 969028</a>.", 5000
                AddTXTAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory and is configured to generate Kernel machine memory dump, however the size of the largest page file is only " & FormatNumber(lngSizeofBiggestPagefileinMB / 1024 / 1024, 2) & " GB.", "If you are interested to obtain machine memory dumps on this machine, please increase the size of any individual pagefiles to make sure there will be enough space for the kernel dump to be generated. Alternatively, you can create a dedicated page file for memory dumps on this machine. For more information, please check the article KB 969028."
                bMachineDumpConfigProblemDetected = True
                bAlertStandardInfo = False
            ElseIf ((bDedicatedDumpFile) And (CLng(lngCurrentDedicatedDumpFileSizeinMB) < CLng(intMachineMemory / 1024 / 4))) Then
                AddXMLAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory and is configured to generate Kernel machine memory dump, however the size of the dedicated file is only " & FormatNumber(lngSizeofBiggestPagefileinMB / 1024 / 1024, 2) & " GB.", "If you are interested to obtain machine memory dumps on this machine, please increase the size of the dedicated pagefile to make sure there will be enough space for the kernel dump to be generated. For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;969028'>KB 969028</a>.", 5000
                AddScriptedDiagAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory and is configured to generate Kernel machine memory dump, however the size of the dedicated file is only " & FormatNumber(lngSizeofBiggestPagefileinMB / 1024 / 1024, 2) & " GB.", "If you are interested to obtain machine memory dumps on this machine, please increase the size of the dedicated pagefile to make sure there will be enough space for the kernel dump to be generated. For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;969028'>KB 969028</a>.", 5000
                AddTXTAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine has " & FormatNumber(intMachineMemory / 1024 / 1024, 2) & " GB of memory and is configured to generate Kernel machine memory dump, however the size of the dedicated file is only " & FormatNumber(lngSizeofBiggestPagefileinMB / 1024 / 1024, 2) & " GB.", "If you are interested to obtain machine memory dumps on this machine, please increase the size of the dedicated pagefile to make sure there will be enough space for the kernel dump to be generated. For more information, please check the article KB 969028."
                bMachineDumpConfigProblemDetected = True
                bAlertStandardInfo = False
            End If
        End If
    End If

    
    Set objDrive = objFSO.GetDrive(objFSO.GetDriveName(strMemoryDumpLocation))
    
    Dim bCrashOnCtrlScroll, bCrashOnCtrlScroll2, bCrashOnCtrlScrollNMI
    On Error Resume Next
    bCrashOnCtrlScroll = -1
    bCrashOnCtrlScroll2 = -1
    bCrashOnCtrlScrollNMI = -1
    bCrashOnCtrlScroll = objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters\CrashOnCtrlScroll")
    bCrashOnCtrlScroll2 = objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters\CrashOnCtrlScroll")
    bCrashOnCtrlScrollNMI = objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\NMICrashDump")
    
    If bCrashOnCtrlScroll = 1 Then
        LineOut "    Manual dump w/ keyboard: ", "Configured as KB 244139 for PS/2 keyboards.", False, False, "Item"
        AddXMLAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate manual machine memory dumps by using PS/2 keyboards as described in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;244139'>KB 244139</a>.", "", 10
        Rem AddScriptedDiagAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate manual machine memory dumps by using PS/2 keyboards as described in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;244139'>KB 244139</a>.", "", 10
        AddTXTAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate manual machine memory dumps by using PS/2 keyboard as described in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;244139'>KB 244139</a>.", ""
        bAlertStandardInfo = False
    End If

    If (bCrashOnCtrlScroll2 = 1) And (intWindowsVersion < 6) Then
        LineOut "    Manual dump w/ keyboard: ", "Configured as KB 244139 for USB keyboards.", False, False, "Item"
        AddXMLAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate manual machine memory dumps by using USB keyboard as described in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;244139'>KB 244139</a>.", "", 10
        Rem AddScriptedDiagAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate manual machine memory dumps by using USB keyboard as described in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;244139'>KB 244139</a>.", "", 10
        AddTXTAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate manual machine memory dumps by using USB keyboard as described in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;244139'>KB 244139</a>.", ""
        bAlertStandardInfo = False
    ElseIf (bCrashOnCtrlScroll2 = 1) And (intWindowsVersion = 6) Then
        
        Set colItems = objWMIService.ExecQuery("Select CSDVersion from Win32_OperatingSystem", , 48)
        For Each objItem In colItems
            If (InStr(1, objItem.CSDVersion, "service pack 2", vbTextCompare) = 0) Then
                AddXMLAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is has the registry value <i>HKLM\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters\CrashOnCtrlScroll</i> configured to generate a manual machine memory dumps by using USB keyboard, however Windows Vista and Windows Server 2008 pre-Service Pack 2 do not have support for manual dump using a USB keyboard.", "For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;944564'>KB 944564</a>", 10
                AddScriptedDiagAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is has the registry value <i>HKLM\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters\CrashOnCtrlScroll</i> configured to generate a manual machine memory dumps by using USB keyboard, however Windows Vista and Windows Server 2008 pre-Service Pack 2 do not have support for manual dump using a USB keyboard.", "For more information, please check the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;944564'>KB 944564</a>", 10
                AddTXTAlert ALERT_WARNING, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is has the registry value HKLM\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters\CrashOnCtrlScroll configured to generate a manual machine memory dumps by using USB keyboard, however Windows Vista and Windows Server 2008 pre-Service Pack 2 do not have support for manual dump using a USB keyboard.", "For more information, please check the article KB 944564"
                bMachineDumpConfigProblemDetected = True
                bAlertStandardInfo = False
            Else
                LineOut "    Manual dump w/ keyboard: ", "Configured as KB 244139 for USB keyboards.", False, False, "Item"
                AddXMLAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate manual machine memory dumps by using USB keyboard as described in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;244139'>KB 244139</a>.", "", 10
                Rem AddScriptedDiagAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate manual machine memory dumps by using USB keyboard as described in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;244139'>KB 244139</a>.", "", 10
                AddTXTAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate manual machine memory dumps by using USB keyboard as described in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;244139'>KB 244139</a>.", ""
                bAlertStandardInfo = False
            End If
        Next
    End If

    If bCrashOnCtrlScrollNMI = 1 Then
        LineOut "    NMI manual dump switch : ", "Configured as KB 927069.", False, False, "Item"
        AddXMLAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate machine memory dumps by using NMI switch as described in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;927069'>KB 927069</a>.", "", 10
        Rem AddScriptedDiagAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate machine memory dumps by using NMI switch as described in <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;927069'>KB 927069</a>.", "", 10
        AddTXTAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate machine memory dumps by using NMI switch as described in KB 927069.", ""
        bAlertStandardInfo = False
    End If
    
    If bAlertStandardInfo Then
        AddXMLAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate " & GetMachineDumpType(intMemoryDumpType) & "s. Dump will be saved at " & strMemoryDumpLocation & ".", "", 10
        AddTXTAlert ALERT_INFORMATION, ALERT_CATEGORY_MACHINE_DMP_CONF, "This machine is configured to generate " & GetMachineDumpType(intMemoryDumpType) & "s. Dump will be saved at " & strMemoryDumpLocation & ".", ""
    End If
    
    CloseTag "SubSession"
    LineOut "", "", True, False, ""
End Sub

Function GetWindowsVersion(strWindowsVersion)
    'wmi Windows version is always separated with ., such as 5.2.x, however this may represent a problem if the decimal separator is not a '.'
    'First test the decimal separator
    Dim strSeparator
    strSeparator = Mid(CStr(1.2), 2, 1)
    GetWindowsVersion = CDbl(Replace(Left(strWindowsVersion, 3), ".", strSeparator))
End Function

Sub WriteGeneralInformation()
    Dim colItems, objItem, x, objDrive, objFile, strDepPolicy, strRegValue, intOSSKU, strWindowsVersion
    
    On Error Resume Next
    OpenWMIService
    
    OpenTag "Session"
    LineOut " -- General Information", "", False, False, "SessionTitle"
    LineOut "", "", True, False, ""

    Set colItems = objWMIService.ExecQuery("Select * from Win32_OperatingSystem", , 48)
    
    strRegValue = ""
    intOSSKU = ""
    strWindowsVersion = ""
    
    For Each objItem In colItems

        intOSSKU = objItem.OperatingSystemSKU
        strWindowsVersion = objItem.Version
        intWindowsVersion = GetWindowsVersion(strWindowsVersion)

        LineOut "    Operating System     : ", objItem.Caption, False, False, "Item"
        If Not IsNull(objItem.CSDVersion) Then
            LineOut "    Service Pack         : ", objItem.CSDVersion, False, False, "Item"
        Else
            LineOut "    Service Pack         : ", "Not Installed", False, False, "Item"
        End If
        
        If Len(intOSSKU) > 0 Then
            LineOut "    Operating System SKU : ", GetOSSKU(intOSSKU), False, False, "Item"
        End If
        
        strRegValue = objShell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\BuildLab")
        If strRegValue <> "" Then
            LineOut "    Build                : ", strRegValue, False, False, "Item"
            strRegValue = ""
        Else
            LineOut "    Build                : ", objShell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Build"), False, False, "Item"
            strRegValue = ""
        End If
        
        strRegValue = objShell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug\Debugger")
        If Len(strRegValue) Then
            LineOut "    Default Debugger     : ", GetDefaultDebuggerName(strRegValue), False, False, "Item"
        Else
            LineOut "    Default Debugger     : ", "Not Set", False, False, "Item"
        End If
        
    Next
    
    LineOut "", "", True, False, ""
    
    WriteMemoryInfo
        
    If intWindowsVersion < 6 Then
        WritePCHealthInfo
        WriteDrWatsonInfo
    Else
        WriteWindowsErrorReportingInfo
    End If
    
    WriteDumpConfigInfo
    
    CloseTag "Session"
    LineOut "", "", True, False, ""

End Sub

Function GetDefaultDebuggerName(strRegValue)
    Dim strQuoteStart
    On Error Resume Next
    strQuoteStart = InStr(1, strRegValue, Chr(34))
    If strQuoteStart <> 0 Then
        GetDefaultDebuggerName = Mid(strRegValue, strQuoteStart + 1, InStr(strQuoteStart + 1, strRegValue, Chr(34)) - 2)
    Else
        GetDefaultDebuggerName = Trim(Left(strRegValue, InStr(strQuoteStart + 1, strRegValue, " ")))
    End If
    GetDefaultDebuggerName = ReplaceEnvVars(GetDefaultDebuggerName)
End Function

Function WriteWindowsErrorReportingInfo()
    'Write Windows Error Reporting Information and obtain array with folders that contains Dump Files

    Dim strRegValueUser, strRegValueMachine, strRegValueUserPolicy, strRegValueMachinePolicy, bolEnabled, strState, strRegValue, strValue
    Dim WERMachineKey, WERMachinePolicyKey, WERUserKey, WERUserPolicyKey, ArrExclusionList, ArrInclusionList, strInclusionList
    Dim strReason
    
    On Error Resume Next
    
    WERMachineKey = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Error Reporting"
    WERMachinePolicyKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Windows\Windows Error Reporting"
    WERUserKey = "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\Windows Error Reporting"
    WERUserPolicyKey = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
    
    OpenTag "SubSession"
    
    LineOut "", "", True, False, ""
    LineOut " -- Windows Error Reporting Information", "", False, False, "SessionTitle"
    LineOut "", "", True, False, ""
    
    strRegValueUser = -1
    strRegValueMachine = -1
    strRegValueUserPolicy = -1
    strRegValueMachinePolicy = -1
    
    strRegValueMachine = objShell.RegRead(WERMachineKey & "\Disabled")
    strRegValueUser = objShell.RegRead(WERUserKey & "\Disabled")
    strRegValueUserPolicy = objShell.RegRead(WERUserPolicyKey & "\Disabled")
    strRegValueMachinePolicy = objShell.RegRead(WERMachinePolicyKey & "\Disabled")
    
    If strRegValueUserPolicy = 1 Then
        strState = "Disabled (By a User Policy)"
        bolEnabled = False
    ElseIf strRegValueMachinePolicy = 1 Then
        strState = "Disabled (By a Machine Policy)"
        bolEnabled = False
    ElseIf strRegValueUser = 1 Then
        strState = "Disabled (User Profile)"
        bolEnabled = False
    ElseIf strRegValueMachine = 1 Then
        strState = "Disabled (Machine wide)"
        bolEnabled = False
    Else
        strState = "Enabled"
        bolEnabled = True
    End If
    
    LineOut "    State                  : ", strState, False, False, "Item"
    If bolEnabled Then 'Error reporting is enabled
        
        strRegValue = ObtainEffectiveValue(WERMachineKey & "\DisableArchive", WERUserKey & "\DisableArchive", WERMachinePolicyKey & "\DisableArchive", WERUserPolicyKey & "\DisableArchive", 0, strReason)
        If strRegValue <> -1 Then LineOut "    Archive Data           : ", iif((strRegValue = 1), "Disabled - ", "Enabled - ") & strReason, False, False, "Item"
        
        strReason = ""
        strRegValue = ObtainEffectiveValue(WERMachineKey & "\DisableQueue", WERUserKey & "\DisableQueue", WERMachinePolicyKey & "\DisableQueue", WERUserPolicyKey & "\DisableQueue", 0, strReason)
        
        If strRegValue <> -1 Then LineOut "    Report Queueing        : ", iif((strRegValue = 1), "Disabled - ", "Enabled - ") & strReason, False, False, "Item"
          
        'New features for Vista/SP1 - Collecting User-Mode Dumps
        
        If RegKeyExists(WERMachineKey & "\LocalDumps") Then
            'Documentation about this feature: http://msdn.microsoft.com/en-us/library/bb787181(VS.85).aspx
            
            LineOut "    User Mode Dumps        : ", "Enabled", False, False, "Item"
        
            strRegValue = 1
            strRegValue = objShell.RegRead(WERMachineKey & "\LocalDumps\DumpType")
            Dim strDumpType
            Select Case strRegValue
                Case 0
                    strDumpType = "Custom"
                Case 2
                    strDumpType = "Full user dumps"
                Case Else
                    strDumpType = "Mini user dumps"
            End Select
            LineOut "    User dump type         : ", strDumpType, False, False, "Item"
            
            strRegValue = "10"
            strRegValue = objShell.RegRead(WERMachineKey & "\LocalDumps\DumpCount")
            LineOut "    Maximum number of dumps: ", strRegValue, False, False, "Item"
            
            On Error Resume Next
            
            strRegValue = "%LOCALAPPDATA%\CrashDumps"
            strRegValue = objShell.RegRead(WERMachineKey & "\LocalDumps\DumpFolder")
            LineOut "    Folder for user dumps  : ", strRegValue, False, False, "Item"
            
            'Check if any app specific dump configuration exists.
            Dim arrSubKeys
            arrSubKeys = RegEnumSubKeys(WERMachineKey & "\LocalDumps")
            
            If Not IsNull(arrSubKeys) Then
                Dim strSubKey, strDumpFolder
                If Not IsNull(arrSubKeys) Then
                    LineOut "    Per process settings   : ", "Enabled", False, False, "Item"
                    strDumpType = "dumps"
                    For Each strSubKey In arrSubKeys
                        strDumpFolder = "%LOCALAPPDATA%\CrashDumps"
                        strDumpFolder = objShell.RegRead(WERMachineKey & "\LocalDumps\" & strSubKey & "\DumpFolder")
                        LineOut "                             ", "Dumps for " & strSubKey & " - folder: " & strDumpFolder, False, False, "Item"
                    Next
                End If
            End If
            AddXMLAlert ALERT_INFORMATION, ALERT_CATEGORY_USER_DMP_CONF, "Windows Error Reporting is configured on this machine to generate " & LCase(strDumpType) & " for user mode processes.", "For more information about Windows Error Reporting settings please visit the page <a target='_blank' href='http://msdn.microsoft.com/en-us/library/bb513638(VS.85).aspx'>WER Settings</a> on MSDN Web site or visit Technet web site <a target='_blank' href='http://technet2.microsoft.com/WindowsVista/en/library/03a97dba-6b24-42c7-81f0-fb751f6e839d1033.mspx'>here</a> for details about Windows Error Reporting.", 5
            Rem AddScriptedDiagAlert ALERT_INFORMATION, ALERT_CATEGORY_USER_DMP_CONF, "Windows Error Reporting is configured on this machine to generate " & LCase(strDumpType) & " for user mode processes.", "For more information about Windows Error Reporting settings please visit the page <a target='_blank' href='http://msdn.microsoft.com/en-us/library/bb513638(VS.85).aspx'>WER Settings</a> on MSDN Web site or visit Technet web site <a target='_blank' href='http://technet2.microsoft.com/WindowsVista/en/library/03a97dba-6b24-42c7-81f0-fb751f6e839d1033.mspx'>here</a> for details about Windows Error Reporting.", 5
            AddTXTAlert ALERT_INFORMATION, ALERT_CATEGORY_USER_DMP_CONF, "Windows Error Reporting is configured on this machine to generate " & LCase(strDumpType) & " for user mode processes.", "For more information, please review the following MSDN Web site: http://msdn.microsoft.com/en-us/library/bb513638(VS.85).aspx. or the following link for details about Windows Error Reporting: http://technet2.microsoft.com/WindowsVista/en/library/03a97dba-6b24-42c7-81f0-fb751f6e839d1033.mspx"
        Else
            AddXMLAlert ALERT_INFORMATION, ALERT_CATEGORY_USER_DMP_CONF, "Windows Error Reporting is configured on this machine.", "If you want to configure Windows Error Reporting to generate mini or full dumps when user mode processes crashes, please create the <i> HKLM\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps</i> registry key. For more information, please review <a target='_blank' href='http://msdn.microsoft.com/en-us/library/bb513638(VS.85).aspx'>WER Settings</a> in MSDN Web site or visit Technet web site <a target='_blank' href='http://technet2.microsoft.com/WindowsVista/en/library/03a97dba-6b24-42c7-81f0-fb751f6e839d1033.mspx'>here</a> for details about Windows Error Reporting.", 5
            AddTXTAlert ALERT_INFORMATION, ALERT_CATEGORY_USER_DMP_CONF, "Windows Error Reporting is configured on this machine.", "If you want to configure Windows Error Reporting to generate mini or full dumps when user mode processes crashes, please create the HKLM\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps registry key. For more information, please review the following MSDN Web site: http://msdn.microsoft.com/en-us/library/bb513638(VS.85).aspx."
        End If
    Else
        AddXMLAlert ALERT_WARNING, ALERT_CATEGORY_USER_DMP_CONF, "Windows Error Reporting is Disabled. No information will be gathered about hardware and software problems.", "In order to enable Windows Error Reporting, please check the article <a target='_blank' href='http://msdn.microsoft.com/en-us/library/bb513638(VS.85).aspx'>WER Settings</a> in MSDN Web site or visit Technet web site <a target='_blank' href='http://technet2.microsoft.com/WindowsVista/en/library/03a97dba-6b24-42c7-81f0-fb751f6e839d1033.mspx'>here</a> for details about Windows Error Reporting.", 100
        AddScriptedDiagAlert ALERT_WARNING, ALERT_CATEGORY_USER_DMP_CONF, "Windows Error Reporting is Disabled. No information will be gathered about hardware and software problems.", "In order to enable Windows Error Reporting, please check the article <a target='_blank' href='http://msdn.microsoft.com/en-us/library/bb513638(VS.85).aspx'>WER Settings</a> in MSDN Web site or visit Technet web site <a target='_blank' href='http://technet2.microsoft.com/WindowsVista/en/library/03a97dba-6b24-42c7-81f0-fb751f6e839d1033.mspx'>here</a> for details about Windows Error Reporting.", 100
        AddTXTAlert ALERT_WARNING, ALERT_CATEGORY_USER_DMP_CONF, "Windows Error Reporting is Disabled. No information will be gathered about hardware and software problems.", "In order to enable Windows Error Reporting, please check the article http://msdn.microsoft.com/en-us/library/bb513638(VS.85).aspx in MSDN Web site or visit Technet web site at http://technet2.microsoft.com/WindowsVista/en/library/03a97dba-6b24-42c7-81f0-fb751f6e839d1033.mspx for details about Windows Error Reporting."
    End If
    
    CloseTag "SubSession"
    
    LineOut "", "", True, False, ""

End Function

Function ObtainEffectiveValue(strRegValueNameMachine, strRegValueNameUser, strRegValueNameMachinePolicy, strRegValueNameUserPolicy, varEffectiveValue, strReason)

    On Error Resume Next

    Dim strRegValueUser, strRegValueMachine, strRegValueUserPolicy, strRegValueMachinePolicy
    

    strRegValueUser = -1
    strRegValueMachine = -1
    strRegValueUserPolicy = -1
    strRegValueMachinePolicy = -1
    
    strRegValueMachine = objShell.RegRead(strRegValueNameMachine)
    strRegValueUser = objShell.RegRead(strRegValueNameUser)
    strRegValueUserPolicy = objShell.RegRead(strRegValueNameMachinePolicy)
    strRegValueMachinePolicy = objShell.RegRead(strRegValueNameMachinePolicy)

    If (strRegValueMachine <> -1) Or (strRegValueUser <> -1) Or (strRegValueUserPolicy <> -1) Or (strRegValueMachinePolicy <> -1) Then
        
            If strRegValueUserPolicy = varEffectiveValue Then
                ObtainEffectiveValue = strRegValueUser
                strReason = "User Policy"
            ElseIf strRegValueMachinePolicy = varEffectiveValue Then
                ObtainEffectiveValue = strRegValueMachinePolicy
                strReason = "Machine Policy"
            ElseIf strRegValueUser = varEffectiveValue Then
                ObtainEffectiveValue = strRegValueUser
                strReason = "User Selection/Profile"
            ElseIf strRegValueMachine = varEffectiveValue Then
                ObtainEffectiveValue = strRegValueMachine
                strReason = "Machine Setting"
            Else
                ObtainEffectiveValue = strRegValueMachine
                strReason = "Unknown"
            End If
    Else
        ObtainEffectiveValue = -1
        strReason = "Setting does not exist"
    End If
End Function


Function WritePCHealthInfo()
    Dim strRegValueUser, strRegValueMachine, strRegValueUserPolicy, strRegValueMachinePolicy, bolEnabled, strState, strRegValue, strValue
    Dim PCHealthMachineKey, PCHealthMachinePolicyKey, PCHealthUserKey, PCHealthUserPolicyKey, ArrExclusionList, ArrInclusionList, strInclusionList
    On Error Resume Next
    
    PCHealthMachineKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PCHealth\ErrorReporting"
    PCHealthMachinePolicyKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW"
    PCHealthUserKey = "HKEY_CURRENT_USER\SOFTWARE\Microsoft\PCHealth\ErrorReporting\DW"
    PCHealthUserPolicyKey = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW"
    
    OpenTag "SubSession"
    
    LineOut "", "", True, False, ""
    LineOut " -- Windows Error Reporting Information", "", False, False, "SessionTitle"
    LineOut "", "", True, False, ""
    
    strRegValueUser = -1
    strRegValueMachine = -1
    strRegValueUserPolicy = -1
    strRegValueMachinePolicy = -1
    
    strRegValueMachine = objShell.RegRead(PCHealthMachineKey & "\DoReport")
    strRegValueUser = objShell.RegRead(PCHealthUserKey & "\DWNeverUpload")
    strRegValueUserPolicy = objShell.RegRead(PCHealthUserPolicyKey & "\DWNeverUpload")
    strRegValueMachinePolicy = objShell.RegRead(PCHealthMachinePolicyKey & "\DWNeverUpload")
    
    If (strRegValueUser <> -1) Or (strRegValueMachine <> -1) Then
    
        If strRegValueUserPolicy = 1 Then
            strState = "Disabled (By User Policy)"
            bolEnabled = False
        ElseIf strRegValueMachinePolicy = 1 Then
            strState = "Disabled (By Machine Policy)"
            bolEnabled = False
        ElseIf strRegValueUser = 1 Then
            strState = "Disabled (User Profile)"
            bolEnabled = False
        Else
            strState = "Enabled"
            bolEnabled = True
        End If
        
        LineOut "    State                  : ", strState, False, False, "Item"
        If bolEnabled Then 'Error reporting is enabled
            
            strRegValue = -1
            strRegValue = objShell.RegRead(PCHealthMachineKey & "\ForceQueueMode")
            If strRegValue <> -1 Then LineOut "    Force queue mode       : ", iif((strRegValue = 1), "True", "False"), False, False, "Item"
            
            strRegValue = -1
            strRegValue = objShell.RegRead(PCHealthUserKey & "\IncludeKernelFaults")
            
            If strRegValue = -1 Then
                strRegValue = objShell.RegRead(PCHealthMachineKey & "\IncludeKernelFaults")
            End If
            
            If strRegValue <> -1 Then LineOut "    Kernel Faults          : ", iif((strRegValue = 1), "Included", "Not Included"), False, False, "Item"
            
            strRegValue = -1
            strRegValue = objShell.RegRead(PCHealthMachineKey & "\IncludeWindowsApps")
            If strRegValue <> -1 Then LineOut "    Windows Components     : ", iif((strRegValue = 1), "Included", "Excluded"), False, False, "Item"
            
            strRegValue = -1
            strRegValue = objShell.RegRead(PCHealthMachineKey & "\IncludeMicrosoftApps")
            If strRegValue <> -1 Then LineOut "    Microsoft Programs     : ", iif((strRegValue = 1), "Include", "Exclude"), False, False, "Item"
                        
            strRegValue = -1
            strRegValue = objShell.RegRead(PCHealthMachineKey & "\IncludeShutdownErrs")
            If strRegValue <> -1 Then LineOut "    Shutdown Errors        : ", iif((strRegValue = 1), "Include", "Exclude"), False, False, "Item"
            
            strRegValue = -1
            strRegValue = objShell.RegRead(PCHealthMachineKey & "\AllOrNone")
            If strRegValue <> -1 Then
                
                ArrExclusionList = GetAllRegistryValues(HKLM, "SOFTWARE\Microsoft\PCHealth\ErrorReporting\ExclusionList")
                ArrInclusionList = GetAllRegistryValues(HKLM, "SOFTWARE\Microsoft\PCHealth\ErrorReporting\InclusionList")

                Select Case strRegValue
                    Case 0
                        strValue = "Selected Applications"
                    Case 1
                        If IsArray(ArrExclusionList) Then
                            strValue = "All (Except those on the exclusion list)"
                        Else
                            strValue = "All programs"
                        End If
                    Case 2, 3
                        strValue = "Disabled for all applications"
                End Select
                LineOut "    Programs Included      : ", strValue, False, False, "Item"
                
                If (IsArray(ArrExclusionList)) Or (IsArray(ArrExclusionList)) Then
                    If strRegValue = 1 Then
                        Dim strExclusionList
                        strExclusionList = ""
                        For Each strRegValue In ArrExclusionList
                            If objShell.RegRead(PCHealthMachineKey & "\ExclusionList\" & strRegValue) = 1 Then
                                strExclusionList = strExclusionList & strRegValue & ", "
                            End If
                        Next
                        If Len(strExclusionList) <> 0 Then
                            strExclusionList = Left(strExclusionList, Len(strExclusionList) - 2)
                        Else
                            strExclusionList = "(Empty)"
                        End If
                        LineOut "    Excluded Applications  : ", strExclusionList, False, False, "Item"
                    ElseIf strRegValue = 0 Then
                        strInclusionList = ""
                        For Each strRegValue In ArrInclusionList
                            If objShell.RegRead(PCHealthMachineKey & "\InclusionList\" & strRegValue) = 1 Then
                                strInclusionList = strInclusionList & strRegValue & ", "
                            End If
                        Next
                        If Len(strExclusionList) <> 0 Then
                            strInclusionList = Left(strExclusionList, Len(strInclusionList) - 2)
                        Else
                            strInclusionList = "(Empty)"
                        End If
                        LineOut "    Included Applications  : ", strInclusionList, False, False, "Item"
                    End If
                End If
            End If
        End If
    End If
    
    CloseTag "SubSession"

End Function

Function WriteDrWatsonInfo()
    
    On Error Resume Next
    Dim DrWatsonKey, strRegValue, strUserDrWatsonDumpFile, strDumpType, strDefaultDebugger
    Dim bIsWatsonDefaultDebugger, bAlertStandardInfo
    
    DrWatsonKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DrWatson"
    bAlertStandardInfo = True
    OpenTag "SubSession"
    
    LineOut "", "", True, False, ""
    LineOut " -- Dr Watson Configuration Information", "", False, False, "SessionTitle"
    LineOut "", "", True, False, ""
    
    strRegValue = objShell.RegRead(DrWatsonKey & "\CreateCrashDump")
    LineOut "    Create Crash Dump      : ", iif(strRegValue = 1, "Enabled", "Disabled"), False, False, "Item"
    
    strRegValue = objShell.RegRead(DrWatsonKey & "\CrashDumpType")
    Select Case strRegValue
        Case 0
            strDumpType = "NT4 compatible full user dumps"
        Case 1
            strDumpType = "Mini user dumps"
        Case 2
            strDumpType = "Full user dumps"
        Case Else
            strDumpType = "(Unknown)"
            bAlertStandardInfo = False
    End Select
    
    LineOut "    Dump type              : ", strDumpType, False, False, "Item"
    
    strUserDrWatsonDumpFile = objShell.Environment("PROCESS").Item("APPDATA") & _
                             "\Microsoft\Dr Watson\user.dmp"
    
    strRegValue = ""
    strRegValue = objShell.RegRead(DrWatsonKey & "\CrashDumpFile")
    
    If Len(strRegValue) > 0 Then
        strUserDrWatsonDumpFile = strRegValue
    End If
    LineOut "    User dump location     : ", strUserDrWatsonDumpFile, False, False, "Item"
    
    strRegValue = objShell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug\Debugger")
    strDefaultDebugger = GetDefaultDebuggerName(strRegValue)
    bIsWatsonDefaultDebugger = (InStr(1, strDefaultDebugger, "drwtsn32", vbTextCompare) > 0)
    
    If bIsWatsonDefaultDebugger Then
        LineOut "    Is default debugger    : ", "Yes", False, False, "Item"
    Else
        LineOut "    Is default debugger    : ", "No", True, False, "Item"
        LineOut "    Is default debugger    : ", "<b><font color='red'>No</font></b>", False, True, "Item"
        LineOut "    Default debugger       : ", strDefaultDebugger, False, False, "Item"
        AddXMLAlert ALERT_WARNING, ALERT_CATEGORY_USER_DMP_CONF, "Dr Watson is not the Default Debugger. User dumps will not be generated by Dr. Watson.", "The current Default Debugger is '" & strDefaultDebugger & ". If you want DrWatson to generate user dumps, please run the command: 'drwtsn32.exe -i'. For more information, please read article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;121434'>KB 121434</a> .", 500
        AddScriptedDiagAlert ALERT_WARNING, ALERT_CATEGORY_USER_DMP_CONF, "Dr Watson is not the Default Debugger. User dumps will not be generated by Dr. Watson.", "The current Default Debugger is '" & strDefaultDebugger & ". If you want DrWatson to generate user dumps, please run the command: 'drwtsn32.exe -i'. For more information, please read article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;121434'>KB 121434</a> .", 500
        AddTXTAlert ALERT_WARNING, ALERT_CATEGORY_USER_DMP_CONF, "Dr Watson is not the Default Debugger. User dumps will not be created by Dr. Watson.", "The current Default Debugger is '" & strDefaultDebugger & ". If you want DrWatson to generate user dumps, please run the command: 'drwtsn32.exe -i'. For more information, please read article KB 121434."
        bAlertStandardInfo = False
        
    End If
    
    If bIsWatsonDefaultDebugger Then
        strRegValue = ""
        strRegValue = objShell.RegRead(DrWatsonKey & "\CreateCrashDump")
        
        If Len(strRegValue) > 0 Then
            If CDbl(strRegValue) = 0 Then
                AddXMLAlert ALERT_ERROR, ALERT_CATEGORY_USER_DMP_CONF, "Dr Watson the default debugger however 'Create dump file' is disabled. User dumps will not be created by Dr. Watson when an application fails.", "If you want DrWatson to generate user dumps, please run the command: 'drwtsn32.exe' and select the option 'Create Crash Dump File'. For more information, please read the following <a target='_blank' href='http://www.microsoft.com/technet/prodtechnol/windows2000serv/reskit/regentry/1707.mspx'>MSDN article</a> .", 500
                AddScriptedDiagAlert ALERT_ERROR, ALERT_CATEGORY_USER_DMP_CONF, "Dr Watson the default debugger however 'Create dump file' is disabled. User dumps will not be created by Dr. Watson when an application fails.", "If you want DrWatson to generate user dumps, please run the command: 'drwtsn32.exe' and select the option 'Create Crash Dump File'. For more information, please read the following <a target='_blank' href='http://www.microsoft.com/technet/prodtechnol/windows2000serv/reskit/regentry/1707.mspx'>MSDN article</a> .", 500
                AddTXTAlert ALERT_ERROR, ALERT_CATEGORY_USER_DMP_CONF, "Dr Watson the default debugger however 'Create dump file' is disabled. User dumps will not be created by Dr. Watson when an application fails.", "If you want DrWatson to generate user dumps, please run the command: 'drwtsn32.exe' and select the option 'Create Crash Dump File'."
                bAlertStandardInfo = False
            End If
        End If
    End If
    
    If bAlertStandardInfo Then
        AddXMLAlert ALERT_INFORMATION, ALERT_CATEGORY_USER_DMP_CONF, "Dr. Watson is configured to generate " & strDumpType & " and is the default debugger.", "For more information, please read article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;308538'>KB 308538</a>", 5
        AddTXTAlert ALERT_INFORMATION, ALERT_CATEGORY_USER_DMP_CONF, "Dr. Watson is configured to generate " & strDumpType & " and is the default debugger.", "For more information, please read article KB 308538"
    End If
    
    CloseTag "SubSession"

End Function

Function GetAllRegistryValues(HIVE, strRegKey)
    
    Dim arrAllValues

    objWMIReg.EnumValues HIVE, strRegKey, arrAllValues
    
    If (IsEmpty(arrAllValues)) Or (IsNull(arrAllValues)) Then
        GetAllRegistryValues = 0
    Else
        GetAllRegistryValues = arrAllValues
    End If
    
End Function

Sub SplitHivefromRegName(strCompleteRegKey, ByRef HIVE, ByRef strRemainingRegKey)
    Dim intHivePos, strHiveString
    HIVE = 0
    
    strHiveString = "HKLM"
    intHivePos = InStr(1, strCompleteRegKey, strHiveString, vbTextCompare)
    If intHivePos = 0 Then
        strHiveString = "HKEY_LOCAL_MACHINE"
        intHivePos = InStr(1, strCompleteRegKey, strHiveString, vbTextCompare)
    End If
        
    If intHivePos = 0 Then
        strHiveString = "HKCU"
        intHivePos = InStr(1, strCompleteRegKey, strHiveString, vbTextCompare)
        If intHivePos = 0 Then
            strHiveString = "HKEY_CURRENT_USER"
            intHivePos = InStr(1, strCompleteRegKey, strHiveString, vbTextCompare)
        End If
        If intHivePos <> 0 Then HIVE = HKCU
    Else
        HIVE = HKLM
    End If
    If intHivePos <> 0 Then
        strRemainingRegKey = Right(strCompleteRegKey, Len(strCompleteRegKey) - Len(strHiveString) - 1)
    End If
End Sub

Function RegKeyExists(strRegKeyPath)
    
    Dim arrAllValues
    Dim intPos, strParentKey, strRemainingName, strKeyName
    intPos = InStrRev(strRegKeyPath, "\", Len(strRegKeyPath) - 1)
    RegKeyExists = False
    If intPos > 0 Then
        strParentKey = Left(strRegKeyPath, intPos - 1)
        strRemainingName = Right(strRegKeyPath, Len(strRegKeyPath) - intPos)
        
        arrAllValues = RegEnumSubKeys(strParentKey)
        
        If Not IsNull(arrAllValues) Then
            For Each strKeyName In arrAllValues
                If LCase(strKeyName) = LCase(strRemainingName) Then
                    RegKeyExists = True
                    Exit For
                End If
            Next
        End If
    End If
End Function

Function RegEnumSubKeys(strRegKeyPath)
    
    On Error Resume Next
    
    Dim strRemainingRegKey, HIVE, arrSubKeys
    SplitHivefromRegName strRegKeyPath, HIVE, strRemainingRegKey
    
    objWMIReg.EnumKey HIVE, strRemainingRegKey, arrSubKeys
    
    RegEnumSubKeys = arrSubKeys
    
End Function

Function GetOSSKU(intSKU)
    Select Case intSKU
        Case 0
            GetOSSKU = "Undefined"
        Case 1
            GetOSSKU = "Ultimate Edition"
        Case 2
            GetOSSKU = "Home Basic Edition"
        Case 3
            GetOSSKU = "Home Basic Premium Edition"
        Case 4
            GetOSSKU = "Enterprise Edition"
        Case 5
            GetOSSKU = "Home Basic N Edition"
        Case 6
            GetOSSKU = "Business Edition"
        Case 7
            GetOSSKU = "Standard Server Edition"
        Case 8
            GetOSSKU = "Datacenter Server Edition"
        Case 9
            GetOSSKU = "Small Business Server Edition"
        Case 10
            GetOSSKU = "Enterprise Server Edition"
        Case 11
            GetOSSKU = "Starter Edition"
        Case 12
            GetOSSKU = "Datacenter Server Core Edition"
        Case 13
            GetOSSKU = "Standard Server Core Edition"
        Case 14
            GetOSSKU = "Enterprise Server Core Edition"
        Case 15
            GetOSSKU = "Enterprise Server Edition for Itanium-Based Systems"
        Case 16
            GetOSSKU = "Business N Edition"
        Case 17
            GetOSSKU = "Web Server Edition"
        Case 18
            GetOSSKU = "Cluster Server Edition"
        Case 19
            GetOSSKU = "Home Server Edition"
        Case 20
            GetOSSKU = "Storage Express Server Edition"
        Case 21
            GetOSSKU = "Storage Standard Server Edition"
        Case 22
            GetOSSKU = "Storage Workgroup Server Edition"
        Case 23
            GetOSSKU = "Storage Enterprise Server Edition"
        Case 24
            GetOSSKU = "Server For Small Business Edition"
        Case 25
            GetOSSKU = "Small Business Server Premium Edition"
    End Select
End Function

Sub WriteMemoryInfo()
    
    Dim colItems, objItem, x, objDrive, objFile, strDepPolicy, strBootOptions
    
    On Error Resume Next
    
    OpenWMIService
    OpenTag "SubSession"

    LineOut " -- Memory Information", "", False, False, "SessionTitle"
    LineOut "", "", True, False, ""

    Set colItems = objWMIService.ExecQuery("Select * from Win32_OperatingSystem", , 48)
    
    For Each objItem In colItems
        Select Case objItem.DataExecutionPrevention_SupportPolicy
            Case 0
                strDepPolicy = "Always Off"
            Case 1
                strDepPolicy = "Always On"
            Case 2
                strDepPolicy = "Opt In"
            Case 3
                strDepPolicy = "Opt Out"
            Case Else
                strDepPolicy = "(Unknown - " & CStr(objItem.DataExecutionPrevention_SupportPolicy) & ")"
        End Select
        
        strBootOptions = objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SystemStartOptions")
        
        LineOut "    Total Visible Memory : ", FormatNumber(objItem.TotalVisibleMemorySize / 1024 / 1024, 2) & " GB", False, False, "Item"
        LineOut "    Free Physical Memory : ", FormatNumber(objItem.FreePhysicalMemory / 1024 / 1024, 2) & " GB", False, False, "Item"
        LineOut "    Total Virtual Memory : ", FormatNumber(objItem.TotalVirtualMemorySize / 1024 / 1024, 2) & " GB", False, False, "Item"
        LineOut "    Free Virtual Memory  : ", FormatNumber(objItem.FreeVirtualMemory / 1024 / 1024, 2) & " GB", False, False, "Item"
        LineOut "    Page File Commit Size: ", FormatNumber(objItem.SizeStoredInPagingFiles / 1024 / 1024, 2) & " GB", False, False, "Item"
        LineOut "    Free Pagefile Space  : ", FormatNumber(objItem.FreeSpaceInPagingFiles / 1024 / 1024, 2) & " GB", False, False, "Item"
        LineOut "    PAE Enabled          : ", iif(objItem.PAEEnabled, "True", "False"), False, False, "Item"
        LineOut "    DEP Available        : ", iif(objItem.DataExecutionPrevention_Available, "True", "False"), False, False, "Item"
        LineOut "    DEP Support Policy   : ", strDepPolicy, False, False, "Item"
        LineOut "    Boot Options         : ", iif(Len(strBootOptions), strBootOptions, "(None)"), False, False, "Item"
        LineOut "    Current Local Time   : ", ConvertWMIDateTime(objItem.LocalDateTime), False, False, "Item"
        LineOut "    Last Boot Up Time    : ", ConvertWMIDateTime(objItem.LastBootUpTime), False, False, "Item"
    Next
    
    LineOut "", "", True, False, ""
    CloseTag "SubSession"

End Sub

Function GetFileDescriptionUsingShell(strFileName)

    Dim arrHeaders(34), objShellApp, objFolder, objFolderItem, x
    
    Set objShellApp = CreateObject("Shell.Application")
    Set objFolder = objShellApp.NameSpace(objFSO.GetParentFolderName(strFileName))
    
    
    Set objFolderItem = objFolder.ParseName(objFSO.GetFileName(strFileName))

    If (Not objFolderItem Is Nothing) Then
        'GetFileDescriptionUsingShell = objFolder.GetDetailsOf(objFolderItem, -1)
        'x = InStr(1, GetFileDescriptionUsingShell, ": ") + 2
        'GetFileDescriptionUsingShell = Mid(GetFileDescriptionUsingShell, x, InStr(1, GetFileDescriptionUsingShell, vbLf) - x)
        GetFileDescriptionUsingShell = objFolder.GetDetailsOf(objFolderItem, 34)
        If GetFileDescriptionUsingShell = "" Then
            GetFileDescriptionUsingShell = objFolder.GetDetailsOf(objFolderItem, -1)
            x = InStr(1, GetFileDescriptionUsingShell, ": ") + 2
            GetFileDescriptionUsingShell = Mid(GetFileDescriptionUsingShell, x, InStr(1, GetFileDescriptionUsingShell, vbLf) - x)
        End If
    End If

End Function

Function FormatDateTime(dtLocalDateTime) 'make sure all dates are with dd/mm/yy hh:mm:ss

    Dim hr, ampm
    FormatDateTime = Right(0 & CStr(Month(dtLocalDateTime)), 2) & "/" & _
                     Right(0 & CStr(Day(dtLocalDateTime)), 2) & "/" & _
                     CStr(Year(dtLocalDateTime))

    hr = Hour(dtLocalDateTime)
    If hr >= 12 Then
      If hr <> 12 Then
          hr = CStr(hr - 12)
          hr = Right("0" & hr, 2)
      End If
      ampm = "PM"
    Else
      ampm = "AM"
      If hr = "0" Then
        hr = "12"
      Else
        hr = Right("0" & hr, 2)
      End If
    End If
    
    FormatDateTime = FormatDateTime & " " & hr & ":" & Right(0 & CStr(Minute(dtLocalDateTime)), 2) & ":" & Right(0 & CStr(Second(dtLocalDateTime)), 2) & " " & ampm

End Function

Function ConvertWMIDateTime(ByVal WmiDatetime)
    
    If Len(WmiDatetime) > 0 Then
        On Error Resume Next
        Dim dtUTCDateTime, dtLocalDateTime, hr, ampm, mn, sec
        dtUTCDateTime = DateSerial(Left(WmiDatetime, 4), Mid(WmiDatetime, 5, 2), Mid(WmiDatetime, 7, 2)) + _
                        TimeSerial(Mid(WmiDatetime, 9, 2), Mid(WmiDatetime, 11, 2), Mid(WmiDatetime, 13, 2))
            
        If intCurrentBiasfromWMIDateTime = -1 Then
            intCurrentBiasfromWMIDateTime = -(CInt(Right(WmiDatetime, 4)) + intCurrentTzBias)
        End If
        dtLocalDateTime = DateAdd("n", intCurrentBiasfromWMIDateTime, dtUTCDateTime)
        
        hr = Hour(dtLocalDateTime)
        If hr >= 12 Then
          If hr <> 12 Then
              hr = CStr(hr - 12)
              hr = Right("0" & hr, 2)
          End If
          ampm = "PM"
        Else
          ampm = "AM"
          If hr = "0" Then
            hr = "12"
          Else
            hr = Right("0" & hr, 2)
          End If
        End If
        
        mn = Right("0" & Minute(dtLocalDateTime), 2)
        sec = Mid(WmiDatetime, 13, 2)
        
        'strDate = Right("0" & Month(dtLocalDateTime), 2) & "/" & Right("0" & Day(dtLocalDateTime), 2) & "/" & CStr(Year(dtLocalDateTime))
        'strTime = hr & ":" & mn & ":" & sec & " " & ampm
        ConvertWMIDateTime = dtLocalDateTime
    Else
        ConvertWMIDateTime = 0
    End If
End Function


Sub WritePageFileInfo()

    Dim colItems, objPageFileUsageItem, objPageFileSettingItem, colItemsPageFileSetting, x, objDrive, objFile
    
    OpenWMIService
    
    OpenTag ("Session")
    LineOut " -- Pagefile Settings", "", False, False, "SessionTitle"
    LineOut "", "", True, False, ""
    
    Set colItems = objWMIService.ExecQuery("Select * from Win32_PageFileUsage", , 48)
    
    For Each objPageFileUsageItem In colItems
    
        OpenTag "SubSession"
        LineOut "File : ", objPageFileUsageItem.Name, False, False, "SessionTitle"
        LineOut "", "", True, False, ""
        
        LineOut "Allocated Size         : ", FormatNumber(objPageFileUsageItem.AllocatedBaseSize, 0) & " MB", False, False, "Item"
        
        Set objFile = objFSO.GetFile(objPageFileUsageItem.Name)
        LineOut "Current File Size      : ", FormatNumber(objFile.Size / 1024 / 1024, 0) & " MB", False, False, "Item"
        
        LineOut "Current Usage          : ", FormatNumber(objPageFileUsageItem.CurrentUsage, 0) & " MB", False, False, "Item"
    
        Set colItemsPageFileSetting = objWMIService.ExecQuery("Select * from Win32_PageFileSetting where Name = '" + Replace(objPageFileUsageItem.Name, "\", "\\") + "'", , 48)
        For Each objPageFileSettingItem In colItemsPageFileSetting
            If (objPageFileSettingItem.InitialSize = 0) And (objPageFileSettingItem.MaximumSize = 0) Then
                LineOut "Configured size        : ", "(System Managed)", False, False, "Item"
            Else
                LineOut "Initial configured size: ", FormatNumber(objPageFileSettingItem.InitialSize, 0) & " MB", False, False, "Item"
                LineOut "Maximum configured size: ", FormatNumber(objPageFileSettingItem.MaximumSize, 0) & " MB", False, False, "Item"
            End If
            LineOut "", "", True, False, ""
        Next
        x = x + 1
        CloseTag "SubSession"
    Next
'
'    x = 0
'    Set colItems = objWMIService.ExecQuery("Select * from Win32_PageFileSetting", , 48)
'    For Each objItem In colItems
'        LineOut "    File         : ", objItem.Name, True, False, "Item"
'        LineOut "File: " & objItem.Name, " ", False, True, "Item"
'        LineOut "                   ", "Initial size: " & FormatNumber(objItem.InitialSize, 0) & " MB", False, False, "Item"
'        LineOut "                   ", "Maximum size: " & FormatNumber(objItem.MaximumSize, 0) & " MB", False, False, "Item"
'        LineOut "", "", True, False, ""
'        x = x + 1
'    Next
'
    If x = 0 Then
        LineOut "    Page files   : ", "Autoconfigured", False, False, "Item"
        LineOut "", "", True, False, ""
    
    
        OpenTag "SubSession"
        
        LineOut " -- Pagefiles information from file system", "", False, False, "SessionTitle"
        LineOut "", "", True, False, ""
            
        For Each objDrive In objFSO.Drives
            If objDrive.DriveType = 2 Then
                If objFSO.FileExists(objDrive.Path & "\pagefile.sys") Then
                    Set objFile = objFSO.GetFile(objDrive.Path & "\pagefile.sys")
                    LineOut "    " & objDrive.Path & "\pagefile.sys current size : ", FormatNumber(objFile.Size / 1024 / 1024 / 1024, 2) & " GB", False, False, "Item"
                End If
            End If
        Next
        
        CloseTag "SubSession"
    
    End If
    
    CloseTag "Session"
    
    LineOut "", "", True, False, ""
    
End Sub

Function ObtainNonDumpInfofromFS(ByVal strImagePath, ByRef strCompanyName, ByRef strFileVersion, ByRef strFileDescription)

    If InStr(1, strImagePath, "\") = 0 Then
        strImagePath = objFSO.GetSpecialFolder(1) & "\drivers\" & strImagePath
    End If
    If Not objFSO.FileExists(strImagePath) Then
        strImagePath = Replace(strImagePath, "\SystemRoot", objShell.Environment("PROCESS").Item("SystemRoot"), 1, 1, vbTextCompare)
        If Not objFSO.FileExists(strImagePath) Then
            strImagePath = Replace(strImagePath, "\??\", "", 1, 1, vbTextCompare)
        End If
    End If
    
    If objFSO.FileExists(strImagePath) Then
        GetFileInfo strImagePath, strCompanyName, strFileVersion, strFileDescription
        If Len(strImagePath) Or Len(strCompanyName) Or Len(strFileVersion) Then
            ObtainNonDumpInfofromFS = True
        End If
    Else
        ObtainNonDumpInfofromFS = False
    End If
    
End Function

Sub OpenWMIService()
    On Error Resume Next
    Err.Clear
    If IsEmpty(objWMIService) Then
        'wscript.Echo ("   Opening WMI Service")
        Set objWMIService = GetObject("winmgmts:" & _
        "{impersonationLevel=impersonate, (Backup, Security)}!\\" & _
        ".\root\cimv2")

        If Err.Number <> 0 Then
           wscript.Echo "Error " & HexFormat(Err.Number) & ": binding to WMI Service"
           wscript.Echo Err.Source & " - " & Err.Description
           wscript.Quit
        End If
        
        Set objWMIReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\." & _
                 "\root\default:StdRegProv")

        If Err.Number <> 0 Then
           wscript.Echo "Error " & HexFormat(Err.Number) & ": binding to WMI Service (Registry)"
           wscript.Echo Err.Source & " - " & Err.Description
           wscript.Quit
        End If
        
    End If
End Sub

Sub GetFileInfo(ByVal strFilePath, ByRef strCompanyName, ByRef strFileVersion, strFileDescription)
    OpenWMIService
    
    On Error Resume Next
    
    Dim colItems, objItem
    
    Dim strVersion, strModifiedDate, strManufacturer, strDescription
    Dim strCreatedDate, objLocalDrive, strFilePathWMI
    
    strFileVersion = ""
    strCompanyName = ""
    strFileDescription = ""
    
    If Left(strFilePath, 2) <> "\\" Then
    
        Set objLocalDrive = objFSO.GetDrive(objFSO.GetDriveName(strFilePath))
        If objLocalDrive.DriveType = Fixed Or objLocalDrive.DriveType = Removable Then
        
            strFilePathWMI = Replace(strFilePath, "\", "\\")
        
            Set colItems = objWMIService.ExecQuery("Select * from CIM_DataFile where Name = '" & strFilePathWMI & "'", , 48)
        
            For Each objItem In colItems
                strFileVersion = objItem.Version
                strCompanyName = objItem.Manufacturer
                strFileDescription = GetFileDescriptionUsingShell(strFilePath)
            Next
        End If
    End If
End Sub

Sub ListFileInfoUsingFSO(ByVal strFilePath, intNumberofSpaces)
    
    Dim strModifiedDate
    Dim strCreatedDate, objFile

    Set objFile = objFSO.GetFile(strFilePath)

    strModifiedDate = objFile.DateLastModified
    strCreatedDate = objFile.DateCreated
    
    LineOut Space(intNumberofSpaces) & "Modified date: ", strModifiedDate, False, False, "Item"
    LineOut Space(intNumberofSpaces) & "Created date : ", strCreatedDate, False, False, "Item"

End Sub

Sub AddXMLAlert(intAlertType, strAlertCategory, strAlertMessage, strAlertRecommendation, intPriority)
    
    Dim strAlertType, strAlertXML
    
    Select Case intAlertType
        Case ALERT_INFORMATION
            strAlertType = "Information"
        Case ALERT_WARNING
            strAlertType = "Warning"
        Case ALERT_ERROR
            strAlertType = "Error"
        Case ALERT_DUMP_FOUND
            strAlertType = "Memory Dump"
    End Select
    
    strAlertXML = "<AlertType>" & strAlertType & "</AlertType>" & _
                  "<AlertCategory>" & strAlertCategory & "</AlertCategory>" & _
                  "<AlertMessage><!" & Chr(91) & "CDATA" & Chr(91) & strAlertMessage & Chr(93) & Chr(93) & "></AlertMessage>" & _
                  "<AlertRecommendation><!" & Chr(91) & "CDATA" & Chr(91) & strAlertRecommendation & Chr(93) & Chr(93) & "></AlertRecommendation>" & _
                  "<AlertPriority>" & CStr(intPriority) & "</AlertPriority>"
                  
    AddtoArray arrAlertsXML, strAlertXML

End Sub

Sub AddMSDTPLAAlert(intAlertType, strAlertCategory, strAlertMessage, strAlertRecommendation, intPriority)
    
    Dim strAlertXML
    
    If bGenerateSDP2Alerts Then
        
        Select Case intAlertType
            Case ALERT_INFORMATION
                intAlertType = 1
            Case ALERT_WARNING
                intAlertType = 2
            Case ALERT_ERROR
                intAlertType = 3
            Case ALERT_DUMP_FOUND
                intAlertType = 1
        End Select
        
        Dim objPLA
        Set objPLA = New ezPLA
        
        wscript.Echo "Creating PLA Alert: " & strAlertMessage
        objPLA.Section = "Memory Dump Related Alerts"
        objPLA.SectionPriority = 30
        
        objPLA.AlertType = intAlertType
        objPLA.Symptom = strAlertCategory
        objPLA.Details = strAlertMessage
        objPLA.MoreInformation = strAlertRecommendation
    
        objPLA.AddAlerttoPLA
    
    End If
    
End Sub

Sub WriteAlertsToXML()
    Dim strLine
    If Not IsEmpty(arrAlertsXML) Then
        OpenTag "Alerts"
        For Each strLine In arrAlertsXML
            OpenTag "Alert"
            objXMLFile.WriteLine strLine
            CloseTag "Alert"
        Next
        CloseTag "Alerts"
    End If
End Sub

Sub WriteAlertsToTXT(strOutputTXTFilePath)
     On Error Resume Next
    'Alerts in txt file needs to be in top of file
    Dim strTempTXTFilePath, objTempTXTFile, x, strAlertType
    Dim objOutputTXTFile
    
    If Not IsEmpty(arrAlertsTXTType) Then
    
        strTempTXTFilePath = objFSO.BuildPath(objFSO.GetSpecialFolder(2), "_DumpCollector.TXT")
        Set objTempTXTFile = objFSO.OpenTextFile(strTempTXTFilePath, ForWriting, True, OpenFileMode)
        
        objTempTXTFile.WriteLine "Alerts"
        objTempTXTFile.WriteLine "------"
        For x = 0 To UBound(arrAlertsTXTType)
            Select Case arrAlertsTXTType(x)
                Case ALERT_INFORMATION
                    strAlertType = "Information"
                Case ALERT_WARNING
                    strAlertType = "Warning"
                Case ALERT_ERROR
                    strAlertType = "Error"
                Case ALERT_DUMP_FOUND
                    strAlertType = "Memory Dump"
            End Select
            
            objTempTXTFile.WriteLine " Alert Type: " & strAlertType
            objTempTXTFile.WriteLine " ------------" & String(Len(strAlertType), "-")
            objTempTXTFile.WriteLine ""
            objTempTXTFile.WriteLine "     Category:"
            objTempTXTFile.WriteLine "     --------"
            objTempTXTFile.WriteLine "     " & arrAlertsTXTCategory(x)
            objTempTXTFile.WriteLine ""
            objTempTXTFile.WriteLine "     Message:"
            objTempTXTFile.WriteLine "     --------"
            objTempTXTFile.WriteLine "     " & arrAlertsTXTMessage(x)
            objTempTXTFile.WriteLine ""
            objTempTXTFile.WriteLine "     Recommendation:"
            objTempTXTFile.WriteLine "     ---------------"
            objTempTXTFile.WriteLine "     " & arrAlertsTXTRecommendation(x)
            objTempTXTFile.WriteLine ""
        Next
        
        Set objOutputTXTFile = objFSO.OpenTextFile(strOutputTXTFilePath, ForReading, False, OpenFileMode)
        objTempTXTFile.Write objOutputTXTFile.ReadAll
        
        objTempTXTFile.Close
        objOutputTXTFile.Close
        Set objTempTXTFile = Nothing
        Set objOutputTXTFile = Nothing
        
        'Replace the contents and delete the temp file
        objFSO.CopyFile strTempTXTFilePath, strOutputTXTFilePath, True
        objFSO.DeleteFile strTempTXTFilePath, True
    End If
End Sub

Sub AddTXTAlert(intAlertType, strAlertCategory, strAlertMessage, strAlertRecommendation)
    AddtoArray arrAlertsTXTType, intAlertType
    AddtoArray arrAlertsTXTCategory, strAlertCategory
    AddtoArray arrAlertsTXTMessage, strAlertMessage
    AddtoArray arrAlertsTXTRecommendation, strAlertRecommendation
End Sub

Sub OpenTag(strTag)
    objXMLFile.WriteLine "<" & strTag & ">"
End Sub

Sub CloseTag(strTag)
    objXMLFile.WriteLine "</" & strTag & ">"
End Sub

Function BuildCompressedFile(strFilePath, DumpType, strProcessName)
    'Check the size of file. Maximum size: MAX_DUMP_SIZE_DEFAULT
    On Error Resume Next
    Err.Clear
    Dim bCopyFile
    bCopyFile = True
    BuildCompressedFile = False
    If bReportOnly Then
        LineOut "    Status       : ", "Report Only mode - Memory dump not collected", False, False, "Item"
        bCopyFile = False
    Else
        Dim objFile, strDestName, strCommandLine, objExec
        Set objFile = objFSO.GetFile(strFilePath)
        If objFile.Size > lngMaxSize Then
            LineOut "    Status          : ", "File not copied since it is larger than " & CStr(lngMaxSize / 1024 / 1024) & " MB.", False, False, "Item"
            bCopyFile = False
        Else
            'Check the space available
            If objFSO.GetDrive(objFSO.GetDriveName(wscript.ScriptFullName)).AvailableSpace < objFile.Size Then
                LineOut "    Status          : ", "File not copied since there is no space available on drive " & objFSO.GetDriveName(wscript.ScriptFullName) & ". There is only " & FormatNumber(objFSO.GetDrive(objFSO.GetDriveName(wscript.ScriptFullName)).AvailableSpace / 1024 / 1024 / 1024, 2) & " GB available.", False, False, "Item"
                bCopyFile = False
            Else
                If (DumpType = USER_DUMP) Then
                    If Not CanDumpsFromThisProcessBeCopied(strProcessName) Then
                        If bUserDumpExclusionList Then
                                LineOut "    Status          : ", "Not copied. Process " & strProcessName & " selected to be excluded.", False, False, "Item"
                                bCopyFile = False
                        ElseIf bUserDumpProcessInclusionList Then
                                LineOut "    Status          : ", "Not copied. Process " & strProcessName & " was not selected to be copied.", False, False, "Item"
                                bCopyFile = False
                        End If
                    End If
                End If
                If bCopyFile Then
                    strDestName = PickNextFile(strComputerName & "_DMP_" & _
                                objFSO.GetBaseName(strFilePath) & GetExtensionCompressedFile)
                    
                    wscript.Echo ""
                    Dim arrFileNames(0)
                    arrFileNames(0) = strFilePath
                    If CompressFiles(arrFileNames, objFSO.BuildPath(objFSO.GetAbsolutePathName("."), strDestName)) Then
                        LineOut "    Status          : ", "File compressed to " & strDestName & "." & _
                                                        iif(bGetDebuggerInfo, " Check dump report for this dump below.", ""), True, False, ""
                        LineOut "    Status          : ", "File compressed to " & ObtainURLForExternalFiles(strDestName, 1) & ".", False, True, "Item"
                        bCopyFile = True
                    Else
                        LineOut "    Status          : ", "An error has ocurred when compressing file. Error " & HexFormat(Err.Number) & ".", False, False, "Item"
                        bCopyFile = False
                        strDestName = ""
                    End If
                End If
            End If
        End If
    End If
    If bCopyFile Then
        BuildCompressedFile = strDestName
    Else
        BuildCompressedFile = ""
    End If
End Function

Function GetExtensionCompressedFile()
    GetExtensionCompressedFile = iif((intWindowsVersion > 5) And (objFSO.FileExists(objFSO.BuildPath(objFSO.GetSpecialFolder(0), "explorer.exe"))), ".zip", ".cab")
End Function

Function CopyWERFiles(strReportFolder, arrFileNames, arrFilePaths, arrFileTypes, strAppName, ByRef arrFileTypesToCopy)

    'Check the size of file. Maximum size: MAX_DUMP_SIZE_DEFAULT
    
    Dim bCopyEntireReportFile, arrFileNamesToCopy, x
    Dim strReportFilesFolderToCompress, bNeedToCompressFiles, arrFilePathsToCopy
    Dim strCABFileName
    
    strCABFileName = objFSO.BuildPath(g_LocalFolder, strComputerName & _
                        "_DMP_" & strAppName & "-" & Replace(objFSO.GetBaseName(strReportFolder), "Report", "", 1, 1, vbTextCompare) & GetExtensionCompressedFile)
    If bReportOnly Then
        LineOut "    Status       : ", "Report Only mode - Memory dump not collected", False, False, "Item"
    Else
        'We first need to check if files are inside report.cab file or uncompressed
        
        strReportFilesFolderToCompress = strReportFolder
        For x = 0 To UBound(arrFileNames)
            Select Case arrFileTypes(x)
                Case 2 'Minidump
                    If bCollectWERMiniDumps Then
                        AddtoArray arrFileNamesToCopy, arrFileNames(x)
                        AddtoArray arrFilePathsToCopy, arrFilePaths(x)
                        AddtoArray arrFileTypesToCopy, 2
                    End If
                Case 3 'FullDump
                    If bCollectWERFullDumps Then
                        AddtoArray arrFileNamesToCopy, arrFileNames(x)
                        AddtoArray arrFilePathsToCopy, arrFilePaths(x)
                        AddtoArray arrFileTypesToCopy, 3
                    End If
                Case Else
                    If bCollectWERDumpAuxFile Then
                        AddtoArray arrFileNamesToCopy, arrFileNames(x)
                        AddtoArray arrFilePathsToCopy, arrFilePaths(x)
                        AddtoArray arrFileTypesToCopy, arrFileTypes(x)
                    End If
            End Select
        Next
        
        If objFSO.FileExists(objFSO.BuildPath(strReportFolder, arrFilePathsToCopy(0))) Then
                bNeedToCompressFiles = True
                strReportFilesFolderToCompress = objFSO.BuildPath(objFSO.GetSpecialFolder(2), objFSO.GetBaseName(strReportFolder))
                If objFSO.FolderExists(strReportFilesFolderToCompress) Then
                    objFSO.DeleteFile objFSO.BuildPath(strReportFilesFolderToCompress, "*.*"), True
                Else
                    objFSO.CreateFolder strReportFilesFolderToCompress
                End If
                bNeedToCompressFiles = True
                On Error Resume Next
                For x = 0 To UBound(arrFileNamesToCopy)
                    objFSO.CopyFile objFSO.BuildPath(strReportFolder, arrFilePathsToCopy(x)), objFSO.BuildPath(strReportFilesFolderToCompress, arrFileNamesToCopy(x)), True
                    arrFileNamesToCopy(x) = objFSO.BuildPath(strReportFilesFolderToCompress, arrFileNamesToCopy(x))
                    If Err.Number <> 0 Then
                        bNeedToCompressFiles = False
                        wscript.Echo "       [" & Now & "] - Error " & HexFormat(Err.Number) & " when copying " & objFSO.BuildPath(strReportFolder, arrFilePathsToCopy(x)) & " to " & objFSO.BuildPath(strReportFilesFolderToCompress, arrFilePathsToCopy(x)) & "."
                    End If
                Next
                
            'it seems file does not exist, let's check for report.cab file:
        ElseIf objFSO.FileExists(objFSO.BuildPath(strReportFolder, "report.cab")) Then
            Dim objFile
            Set objFile = objFSO.GetFile(objFSO.BuildPath(strReportFolder, "report.cab"))
            If bCollectWERDumpAuxFile And ((bCollectWERMiniDumps Or bCollectWERFullDumps) Or bCollectWERFullDumps) And (objFile.Size <= lngMaxSize) Then
                bCopyEntireReportFile = True
            Else
                'Need to extract only the dumps or the files we need so we can compress files dumps later
                strReportFilesFolderToCompress = objFSO.BuildPath(objFSO.GetSpecialFolder(2), objFSO.GetBaseName(strReportFolder))
                If objFSO.FolderExists(strReportFilesFolderToCompress) Then
                    objFSO.DeleteFile objFSO.BuildPath(strReportFilesFolderToCompress, "*.*"), True
                Else
                    objFSO.CreateFolder strReportFilesFolderToCompress
                End If
                bNeedToCompressFiles = True
                For x = 0 To UBound(arrFileNamesToCopy)
                    If Not ExpandFileFromCab(objFSO.BuildPath(strReportFolder, "report.cab"), arrFileNamesToCopy(x), strReportFilesFolderToCompress) Then
                        bNeedToCompressFiles = False
                        Exit For
                    Else
                        arrFileNamesToCopy(x) = objFSO.BuildPath(strReportFilesFolderToCompress, arrFileNamesToCopy(x))
                    End If
                Next
            End If
        Else
            DisplayError "Uncompressing/checking WER file", 5000, "CopyWerFiles", "File '" & objFSO.BuildPath(strReportFolder, arrFilePathsToCopy(0)) & " does not exist."
        End If
        
        Dim strFileToCompress, strDestName, strCommandLine, objExec
        'Compress Files
        If bCopyEntireReportFile Then
            objFSO.CopyFile objFSO.BuildPath(strReportFolder, "report.cab"), strCABFileName, True
        ElseIf bNeedToCompressFiles Then
            StripLargeFilesFromArray arrFileNamesToCopy, arrFileTypesToCopy
            AddtoArray arrFilePathsToCopy, "report.wer"
            AddtoArray arrFileNamesToCopy, objFSO.BuildPath(strReportFolder, "report.wer")
            AddtoArray arrFileTypesToCopy, 0
            
            Dim bFileCompressed
            bFileCompressed = CompressFiles(arrFileNamesToCopy, strCABFileName)
            If objFSO.FolderExists(strReportFilesFolderToCompress) Then
                For Each strFileToCompress In objFSO.GetFolder(strReportFilesFolderToCompress).Files
                    'Cleanup
                    objFSO.DeleteFile strFileToCompress, True
                Next
                objFSO.DeleteFolder strReportFilesFolderToCompress, True
            End If
            If bFileCompressed Then
                CopyWERFiles = strCABFileName
            Else
                CopyWERFiles = ""
            End If
        End If
        
    End If

End Function

Function StripLargeFilesFromArray(ByRef arrFileNames, ByRef arrAuxArray)
    'Remove the large files (bigger than lngMaxSize) from array
    Dim strFileName, objFile, arrNewFilesArray, arrNewAuxArray, x
    On Error Resume Next
    For x = 0 To UBound(arrFileNames)
        strFileName = arrFileNames(x)
        If objFSO.FileExists(strFileName) Then
            Set objFile = objFSO.GetFile(strFileName)
            If objFile.Size > lngMaxSize Then
                LineOut "      Status          : ", "File " & objFSO.GetFileName(strFileName) & " not copied since it is bigger than " & CStr(lngMaxSize / 1024 / 1024) & " MB.", True, False, "Item"
            Else
                AddtoArray arrNewFilesArray, strFileName
                AddtoArray arrNewAuxArray, arrAuxArray(x)
            End If
        Else
            DisplayError "CheckingFileSize", 5000, "StripLargeFilesFromArray", "File " & strFileName & " does not exist."
        End If
    Next
    arrFileNames = arrNewFilesArray
    arrAuxArray = arrNewAuxArray
End Function

Function CompressFiles(ArrayFileNamestoCompress, strCABFileName)
    Dim strCommandLine, objExec, strFileName, strDDFFile, objDDFFile, intInitialFileCount, datStart, intMinutes
    Const COMPRESS_OPTION = 4
    Const SHELL_COMPRESS_TIMEOUT_IN_MINUTES = 25
    'Let's Check the version. Windows 2000 shell does not support ZIP files.
    'Also, ServerCore does not implement this support.
    
    On Error Resume Next
    Err.Clear
    Dim objShellApp, x
    wscript.Echo ""
    wscript.Echo "       [" & Now & "] - Compressing files to '" & strCABFileName & "': "
    
    If (intWindowsVersion > 5) And (objFSO.FileExists(objFSO.BuildPath(objFSO.GetSpecialFolder(0), "explorer.exe"))) Then
        If CreateEmptyZipFile(strCABFileName) Then
            x = 0
            Set objShellApp = CreateObject("Shell.Application")
            For Each strFileName In ArrayFileNamestoCompress
                x = x + 1
                wscript.Echo "        " & Space(Len(Now)) & "      -> " & objFSO.GetFileName(strFileName)
                Dim objCABFile
                Set objCABFile = objShellApp.NameSpace(strCABFileName)
                                intInitialFileCount = objCABFile.Items.Count
                objCABFile.CopyHere strFileName, COMPRESS_OPTION

                datStart = Now()
                
                Do Until (objCABFile.Items.Count <> intInitialFileCount) Or (Err.Number <> 0) Or (intMinutes >= SHELL_COMPRESS_TIMEOUT_IN_MINUTES) 'Abort after 20 minutes to avoid infinte loops
                    wscript.Sleep 400
                    intMinutes = DateDiff("n", datStart, Now)
                Loop
                
                If intMinutes >= SHELL_COMPRESS_TIMEOUT_IN_MINUTES Then
                    DisplayError "Compressing file " & ArrayFileNamestoCompress(x - 1) & " to " & strCABFileName, 5001, "Shell", "Time out compressing file - compression did not complete after " & CStr(SHELL_COMPRESS_TIMEOUT_IN_MINUTES) & " minutes..."
                    CompressFiles = False
                    objFSO.DeleteFile strCABFileName
                    Exit Function
                End If
                
                Set objCABFile = Nothing
            Next
            Set objShellApp = Nothing
            If Err.Number = 0 Then
                If objFSO.FileExists(strCABFileName) Then
                    CompressFiles = True
                    wscript.Echo "       [" & Now & "] - Done."
                    wscript.Echo ""
                Else
                    DisplayError "Compressing file " & ArrayFileNamestoCompress(x - 1) & " to " & strCABFileName, 5000, "Unknown", "File does not exist. File copy operation may have been aborted."
                End If
            Else
                DisplayError "Compressing file " & ArrayFileNamestoCompress(x - 1) & " to " & strCABFileName, Err.Number, Err.Source, Err.Description
                CompressFiles = False
            End If
        Else
            CompressFiles = False
        End If
    Else 'Windows 2000
        'Creating DDF
        strDDFFile = objFSO.BuildPath(objFSO.GetSpecialFolder(2), "_DumpCollector.DDF")
        Set objDDFFile = objFSO.OpenTextFile(strDDFFile, ForWriting, True, OpenFileMode)
        
        objDDFFile.WriteLine ".Set Cabinet=on"
        objDDFFile.WriteLine ".Set Compress=on"
        objDDFFile.WriteLine ".Set CompressionType=MSZIP"
        objDDFFile.WriteLine ".Set CabinetNameTemplate=" & objFSO.GetFileName(strCABFileName)
        objDDFFile.WriteLine ".Set DiskDirectoryTemplate=" & objFSO.GetParentFolderName(strCABFileName)
        objDDFFile.WriteLine ".Set FolderSizeThreshold=2000000"
        objDDFFile.WriteLine ".Set MaxCabinetSize=0"
        objDDFFile.WriteLine ".Set MaxDiskSize=0"
        
        For Each strFileName In ArrayFileNamestoCompress
            objDDFFile.WriteLine strFileName
            wscript.Echo "        " & Space(Len(Now)) & "      -> " & objFSO.GetFileName(strFileName)
        Next
        
        objDDFFile.Close
        
        strCommandLine = "cmd.exe /c makecab /F " & Chr(34) & strDDFFile & Chr(34) & " /L " & Chr(34) & objFSO.GetAbsolutePathName(".") & Chr(34) & "> nul"
        Set objExec = objShell.Exec(strCommandLine)
        
        While objExec.Status = 0
            wscript.Sleep 200
        Wend
        
        If objExec.ExitCode = 0 Then
            wscript.Echo "       [" & Now & "] - Done."
            CompressFiles = True
        Else
            wscript.Echo "       [" & Now & "] - Exit Code " & HexFormat(objExec.ExitCode) & " compressing file."
            wscript.Echo "                  - Command line: " & strCommandLine
            CompressFiles = False
        End If
        
        objFSO.DeleteFile strDDFFile
        'Delete makecab setup files
        If objFSO.FileExists(objFSO.BuildPath(objFSO.GetAbsolutePathName("."), "setup.inf")) Then objFSO.DeleteFile objFSO.BuildPath(objFSO.GetAbsolutePathName("."), "setup.inf")
        If objFSO.FileExists(objFSO.BuildPath(objFSO.GetAbsolutePathName("."), "setup.rpt")) Then objFSO.DeleteFile objFSO.BuildPath(objFSO.GetAbsolutePathName("."), "setup.rpt")
    End If
End Function

Function CreateEmptyZipFile(strDestination)
    Dim objZipFile
    On Error Resume Next
    Set objZipFile = objFSO.OpenTextFile(strDestination, ForWriting, True, OpenFileMode)
    If Err <> 0 Then
        CreateEmptyZipFile = False
    Else
        objZipFile.Write Chr(80) & Chr(75) & Chr(5) & Chr(6) & String(18, 0)
        If Err <> 0 Then
            CreateEmptyZipFile = False
        Else
            CreateEmptyZipFile = True
        End If
        objZipFile.Close
        Set objZipFile = Nothing
    End If
End Function


Function ExpandFileFromCab(strSourceCab, strFileToExtract, strDestinationFolder)
    Dim objCABFile, strCommandLine, objExec
    
    On Error Resume Next
    
    Set objCABFile = objFSO.GetFile(strSourceCab)
    
    wscript.Echo "       [" & Now & "] - Extracting file '" & objFSO.BuildPath(strDestinationFolder, strFileToExtract) & "' from " & objFSO.GetBaseName(strDestinationFolder)

    strCommandLine = "cmd.exe /cexpand.exe " & Chr(34) & strSourceCab & Chr(34) & " -F:" & Chr(34) & strFileToExtract & Chr(34) & " " & Chr(34) & strDestinationFolder & Chr(34)
    
    Set objExec = objShell.Exec(strCommandLine)

    While objExec.Status = 0
        wscript.Sleep 50
    Wend
    
    If objExec.ExitCode = 0 Then
        wscript.Echo "       [" & Now & "] - Done."
        ExpandFileFromCab = True
    Else
        wscript.Echo "       [" & Now & "] - Exit Code " & HexFormat(objExec.ExitCode) & " extracting file."
        ExpandFileFromCab = False
    End If
End Function

Sub LineOut(strName, strValue, bDoNotWriteToXML, bDoNotWritetoTXT, strXMLTag)

    On Error Resume Next

    If Not bDoNotWritetoTXT Then
        objTXTFile.WriteLine strName & strValue
    End If

    If Not bDoNotWriteToXML Then
                
        If Right(strName, 2) = ": " Then
            strName = Left(strName, Len(strName) - 2)
        End If
        If Left(strName, 4) = " -- " Then
            If Not bDoNotWritetoTXT Then wscript.Echo strName & strValue
            strName = Right(strName, Len(strName) - 4)
        End If
        strName = Trim(strName)
        
        WriteToXML strName, strValue, strXMLTag
    End If
    
End Sub

Function ReplaceEnvVars(ByVal strString)
    Dim intFirstPercentPos, intSecondPercentPos
    Dim strEnvVar
    intFirstPercentPos = InStr(1, strString, "%")
    
    While intFirstPercentPos > 0
        intSecondPercentPos = InStr(intFirstPercentPos + 1, strString, "%")
        strEnvVar = Mid(strString, intFirstPercentPos + 1, intSecondPercentPos - intFirstPercentPos - 1)
        strString = Replace(strString, "%" & strEnvVar & "%", objShell.Environment("PROCESS").Item(strEnvVar))
        intFirstPercentPos = InStr(1, strString, "%")
    Wend
    ReplaceEnvVars = strString
End Function

Function WriteToXML(strName, strValue, strXMLTag)
    If Len(strXMLTag) = 0 And Len(strValue) = 0 Then
        objXMLFile.WriteLine strName
    ElseIf Len(strValue) = 0 Then
        objXMLFile.WriteLine "<" & strXMLTag & " name=" & Chr(34) & Chr(34) & ">" & strName & "</" & strXMLTag & ">"
    ElseIf Len(strValue) > 0 Then
        
        objXMLFile.WriteLine "<" & strXMLTag & " name=" & Chr(34) & strName & Chr(34) & ">" & TranslateXMLChars(strValue) & "</" & strXMLTag & ">"
    End If
End Function

Function TranslateXMLChars(strRAWString)
    strRAWString = Replace(strRAWString, "&", "&amp;")
    strRAWString = Replace(strRAWString, "<", "&lt;")
    strRAWString = Replace(strRAWString, ">", "&gt;")
    strRAWString = Replace(strRAWString, "'", "&apos;")
    strRAWString = Replace(strRAWString, Chr(34), "&quot;")
    TranslateXMLChars = strRAWString
End Function

Function iif(Expression, Truepart, Falsepart)
    If Expression Then
        iif = Truepart
    Else
        iif = Falsepart
    End If
End Function

Function GetMSDTDumpReportURL()
    GetMSDTDumpReportURL = "<i>" & strComputerName & "_DumpReport.HTM" & "</i>"
End Function

Function InitializeAndValidateCommandLineArguments()

    'Validate Command Line Arguments
    'This function returns 0 if everything is ok or
    
    Dim x, bErrorValidation, bError, strAdditionalError, strArgument, strDebugCommands

    InitializeAndValidateCommandLineArguments = False
    bRestrictNumberOfFiles = False
    bRestrictAge = False
    bCollectMinidumps = False
    bCollectTDRDumps = False
    bCollectMemoryDump = False
    intMaxAge = MAX_AGE_DEFAULT
    intMaxFiles = MAX_FILES_DEFAULT
    lngMaxSize = MAX_DUMP_SIZE_DEFAULT
    bReportOnly = False
    bCollectUserDumps = False
    bCollectWERMiniDumps = False
    bCollectWERFullDumps = False
    bCollectWERDumpAuxFile = False
    bArgumentFileEnabled = False
    bIsDebuggerPathSet = False
    bDeleteCDBFolder = False
    bGenerateSDP2Alerts = False
    bGenerateScriptedDiagXMLAlerts = False
    
    bWriteALERT_CATEGORY_MACHINE_DMP_CONF = True
    bWriteALERT_CATEGORY_USER_DMP_CONF = True
    bWriteALERT_CATEGORY_USER_DMP_FOUND = True
    bWriteALERT_CATEGORY_OTHER = True
    bWriteALERT_CATEGORY_USER_DMP_COPIED = True
    bWriteALERT_CATEGORY_MACHINE_DMP_COPIED = True
    bWriteALERT_CATEGORY_MACHINE_DMP_FOUND = True
    
    Dim arrArgumentList
    
    If (wscript.Arguments.Count >= 1) Then
        InitializeAndValidateCommandLineArguments = 0
        ReDim arrArgumentList(wscript.Arguments.Count - 1)
        For x = 0 To wscript.Arguments.Count - 1
            arrArgumentList(x) = wscript.Arguments(x)
        Next
        ProcessArgumentList arrArgumentList, bError, strAdditionalError
    
        If bError Then
            InitializeAndValidateCommandLineArguments = strAdditionalError
        End If
    Else
        InitializeAndValidateCommandLineArguments = 0
    End If
         
End Function

Sub CreateHTMLFile()

    On Error Resume Next
    Err.Clear

    Dim strHTMLFileName, objHTMLFile, xmlStylesheet, xmlStylesheetPath, xmlFile, strXmlFilePath
    Dim strErrText
        
    strXmlFilePath = objFSO.GetAbsolutePathName(".") & "\" & strComputerName & _
                     "_DumpReport.XML"
    
    strHTMLFileName = objFSO.GetAbsolutePathName(".") & "\" & strHTMLOutputfilename
    
    If ExtractEmbeddedXSL(xmlStylesheetPath) Then
    
        Set xmlStylesheet = CreateObject("Microsoft.XMLDOM")
        Set xmlFile = CreateObject("Microsoft.XMLDOM")
        
        xmlFile.Load strXmlFilePath
        
        If (Err.Number <> 0) Or (xmlFile.parseError.errorCode <> 0) Then
            If Err.Number <> 0 Then
                DisplayError "Loading XML file or XSLT " & strXmlFilePath & ".", Err.Number, Err.Source, Err.Description
            Else
                With xmlFile.parseError
                strErrText = "Failed to load XML file " & strXmlFilePath & "" & _
                        "due the following error:" & vbCrLf & _
                        "Error #: " & .errorCode & ": " & .reason & _
                        "Line #: " & .Line & vbCrLf & _
                        "Line Position: " & .linepos & vbCrLf & _
                        "Position In File: " & .filepos & vbCrLf & _
                        "Source Text: " & .srcText & vbCrLf & _
                        "Document URL: " & .url
                End With
                DisplayError "Loading " & strXmlFilePath & ".", 5000, "CreateHTMFile", strErrText
            End If
            objFSO.DeleteFile xmlStylesheetPath, True
            Exit Sub
        End If
    
        xmlStylesheet.Load xmlStylesheetPath
        
        If (Err.Number <> 0) Or (xmlFile.parseError.errorCode <> 0) Then
            If Err.Number <> 0 Then
                DisplayError "Loading XSLT " & xmlStylesheetPath & ".", Err.Number, Err.Source, Err.Description
            Else
                With xmlFile.parseError
                strErrText = "Failed to load XSL file " & xmlStylesheetPath & "" & _
                        "due the following error:" & vbCrLf & _
                        "Error #: " & .errorCode & ": " & .reason & _
                        "Line #: " & .Line & vbCrLf & _
                        "Line Position: " & .linepos & vbCrLf & _
                        "Position In File: " & .filepos & vbCrLf & _
                        "Source Text: " & .srcText & vbCrLf & _
                        "Document URL: " & .url
                End With
                DisplayError "Loading " & xmlStylesheetPath & ".", 5000, "CreateHTMFile", strErrText
            End If
            objFSO.DeleteFile xmlStylesheetPath, True
            Exit Sub
        End If
        
        wscript.Echo "Building file: '" & objFSO.GetFileName(strHTMLFileName) & "'"
        Set objHTMLFile = objFSO.OpenTextFile(strHTMLFileName, ForWriting, True, -1)
    
        If Err.Number <> 0 Then
            DisplayError "Creating HTML file " & strHTMLFileName, Err.Number, Err.Source, Err.Description
            Exit Sub
        End If
        
        objHTMLFile.Write xmlFile.transformNode(xmlStylesheet)
        
        If Err.Number <> 0 Then
            DisplayError "Error transforming " & strXmlFilePath & " using stylesheet " & xmlStylesheetPath & ".", Err.Number, Err.Source, Err.Description
            objFSO.DeleteFile xmlStylesheetPath, True
            objHTMLFile.Close
            objFSO.DeleteFile strHTMLFileName, True
            Exit Sub
        End If
    
        objHTMLFile.Close
        
        Set xmlFile = Nothing
        Set xmlStylesheet = Nothing
        Set objXMLFile = Nothing
        
        objFSO.DeleteFile xmlStylesheetPath, True
        
        If Not bGenerateScriptedDiagXMLAlerts Then
            objFSO.DeleteFile strXmlFilePath, True
        End If
        
        If Err.Number <> 0 Then
            DisplayError "Error deleting files " & strXmlFilePath & "/ " & xmlStylesheetPath & ".", Err.Number, Err.Source, Err.Description
            Exit Sub
        End If
    End If
End Sub

Sub DisplayError(strErrorLocation, errNumber, errSource, errDescription)
    On Error Resume Next
    If errNumber <> 0 Then
        wscript.Echo "Error " & HexFormat(errNumber) & iif(Len(strErrorLocation) > 0, ": " & strErrorLocation, "")
        wscript.Echo errSource & " - " & errDescription
    Else
        wscript.Echo "An error has ocurred!. " & iif(Len(strErrorLocation) > 0, ": " & strErrorLocation, "")
    End If
End Sub

Sub RemoveExternalAlert(arrAlertExclusionList)
    Dim strAlertToRemove
    For Each strAlertToRemove In arrAlertExclusionList
        Select Case LCase(strAlertToRemove)
            Case "machinedumpconfig"
                bWriteALERT_CATEGORY_MACHINE_DMP_CONF = False
            Case "userdumpconfig"
                bWriteALERT_CATEGORY_USER_DMP_CONF = False
            Case "userdumpfound"
                bWriteALERT_CATEGORY_USER_DMP_FOUND = False
            Case "other"
                bWriteALERT_CATEGORY_OTHER = False
            Case "userdumpcopied"
                bWriteALERT_CATEGORY_USER_DMP_COPIED = False
            Case "machinedumpcopied"
                bWriteALERT_CATEGORY_MACHINE_DMP_COPIED = False
            Case "machinedumpfound"
                bWriteALERT_CATEGORY_MACHINE_DMP_FOUND = False
        End Select
    Next
End Sub

Sub ProcessArgumentList(arrArgumentList, ByRef bError, ByRef strErrorDetails)
    bError = False
    Dim bIgnoreGenerateSDP2Alerts
    Dim strArgument
    Dim arrAlertExclusionList
    bIgnoreGenerateSDP2Alerts = False
    For Each strArgument In arrArgumentList
        strArgument = Trim(strArgument)
        Select Case LCase(strArgument)
            Case "/?", "-?", "/help"
                bError = True
                strErrorDetails = "Command Syntax:"
                Exit Sub
            Case "/reportonly"
                bReportOnly = True
            Case "/copymachinememorydump"
                bCollectMemoryDump = True
            Case "/copymachineminidumps"
                bCollectMinidumps = True
            Case "/copytdrdumps"
                bCollectTDRDumps = True
            Case "/copyuserdumps"
                bCollectUserDumps = True
            Case "/copywerminidumps"
                bCollectWERMiniDumps = True
            Case "/copywerfulldumps"
                bCollectWERFullDumps = True
            Case "/copywerdumpaux"
                bCollectWERDumpAuxFile = True
            Case "/debuginfo"
                bGetDebuggerInfo = True
            Case "/deletecdbfolder"
                bDeleteCDBFolder = True
            Case "/generatesdp2alerts"
                If Not bIgnoreGenerateSDP2Alerts Then
                    bGenerateSDP2Alerts = True
                End If
            Case "/nomsdtplaalerts"
                bGenerateSDP2Alerts = False
                bIgnoreGenerateSDP2Alerts = True
            Case "/generatescripteddiagxmlalerts"
                bGenerateScriptedDiagXMLAlerts = True
            Case Else
                If (LCase(Left(strArgument, 7)) = "/maxage") Then
                    bRestrictAge = True
                    intMaxAge = CInt(Right(strArgument, Len(strArgument) - 8))
                ElseIf (LCase(Left(strArgument, 9)) = "/maxfiles") Then
                    bRestrictNumberOfFiles = True
                    intMaxFiles = CInt(Right(strArgument, Len(strArgument) - 10))
                ElseIf (LCase(Left(strArgument, 8)) = "/maxsize") Then
                    bRestrictDumpSize = True
                    lngMaxSize = CLng(Right(strArgument, Len(strArgument) - 9))
                ElseIf LCase(Left(strArgument, 10)) = "/arguments" Then
                    'Non documented: Sets a file location with user arguments
                    bArgumentFileEnabled = True
                    strArgumentFileFilePath = Right(strArgument, Len(strArgument) - 11)
                ElseIf LCase(Left(strArgument, 22)) = "/dontcopyuserdumpsfrom" Then
                    bUserDumpExclusionList = True
                    AddtoArray arrUserDumpProcessExclusionList, Split(Right(strArgument, Len(strArgument) - 23), ",")
                ElseIf LCase(Left(strArgument, 22)) = "/onlycopyuserdumpsfrom" Then
                    bUserDumpProcessInclusionList = True
                    AddtoArray arrUserDumpProcessInclusionList, Split(Right(strArgument, Len(strArgument) - 23), ",")
                ElseIf LCase(Left(strArgument, 20)) = "/dontalertcategories" Then
                    AddtoArray arrAlertExclusionList, Split(Right(strArgument, Len(strArgument) - 21), ",")
                ElseIf LCase(Left(strArgument, 8)) = "/cdbpath" Then
                    bIsDebuggerPathSet = True
                    strDebuggerPath = Right(strArgument, Len(strArgument) - 9)
                End If
        End Select
    Next
    
    If bReportOnly Then
        bCollectMemoryDump = False
        bCollectMinidumps = False
        bCollectTDRDumps = False
        bCollectWERFullDumps = False
        bCollectUserDumps = False
        bCollectWERMiniDumps = False
        bCollectWERDumpAuxFile = False
        bCollectWERDumpAuxFile = False
    End If

    If Not IsEmpty(arrAlertExclusionList) Then
        RemoveExternalAlert (arrAlertExclusionList)
    End If
    
    If bCollectWERDumpAuxFile And Not (bCollectWERFullDumps Or bCollectWERMiniDumps Or bCollectUserDumps) Then
        bError = True
        strErrorDetails = "/copywerdumpaux needs to be used with /copywerfulldumps or /copywerminidumps."
    ElseIf bUserDumpProcessInclusionList And bUserDumpExclusionList Then
        bUserDumpExclusionList = False
        bError = True
        strErrorDetails = "/onlycopyuserdumpsfrom and /dontcopyuserdumpsfrom should not be used together."
    End If
    
    If bGetDebuggerInfo And Not bIsDebuggerPathSet Then
        wscript.Echo ""
        wscript.Echo "Warning: /debuginfo was used, however /cdbpath was not used."
        wscript.Echo "         In this case the default debugger path will be used:"
        wscript.Echo "                      " & DEFAULTDEBUGGERPATH
        wscript.Echo ""
        strDebuggerPath = DEFAULTDEBUGGERPATH
        bIsDebuggerPathSet = True
        bDeleteCDBFolder = False 'In this case, script should not delete the existing debugger folder
    End If

    If bRestrictDumpSize And (((lngMaxSize * 1024 * 1024) > (MAX_DUMP_SIZE_DEFAULT)) Or lngMaxSize = 0) Then
        strErrorDetails = "This script limits the maximum dump size to be copied to 16GB. Please use a smaller value for /maxsize. This value is in MB."
        bError = True
        lngMaxSize = MAX_DUMP_SIZE_DEFAULT
    Else
        lngMaxSize = lngMaxSize * 1024 * 1024
    End If

    If bGetDebuggerInfo Then
        If Not objFSO.FileExists(strDebuggerPath) Then
            bError = True
            strErrorDetails = "Debugger was not found in the following location: " & strDebuggerPath & ". Debugger information will not be loaded."
            bGetDebuggerInfo = False
        Else
            strDebuggerPath = objFSO.GetAbsolutePathName(strDebuggerPath)
        End If
    Else
        If bDeleteCDBFolder Then bDeleteCDBFolder = False
    End If
    
End Sub

Function AddtoArray(arrSourceArray, arrArrayToAdd)
    Dim y, varFirstMember, bWasSourceArrayNothing
    
    
    If IsEmpty(arrSourceArray) Then
        If Not IsArray(arrArrayToAdd) Then
            ReDim arrSourceArray(0)
            arrSourceArray(0) = arrArrayToAdd
        Else
            arrSourceArray = arrArrayToAdd
        End If
    Else
        If Not IsArray(arrSourceArray) Then
            If TypeName(arrSourceArray) = "Nothing" Then
                ReDim arrSourceArray(0)
                bWasSourceArrayNothing = True
            Else
                varFirstMember = arrSourceArray
                ReDim arrSourceArray(0)
                arrSourceArray(0) = varFirstMember
                bWasSourceArrayNothing = False
            End If
        Else
            bWasSourceArrayNothing = False
        End If
        If Not IsEmpty(arrArrayToAdd) Then
            If IsArray(arrArrayToAdd) Then
                For y = 0 To UBound(arrArrayToAdd)
                    If bWasSourceArrayNothing Then
                        ReDim Preserve arrSourceArray(UBound(arrSourceArray))
                        arrSourceArray(UBound(arrSourceArray) - 1) = arrArrayToAdd(y)
                    Else
                        ReDim Preserve arrSourceArray(UBound(arrSourceArray) + 1)
                        arrSourceArray(UBound(arrSourceArray)) = arrArrayToAdd(y)
                    End If
                Next
            Else
                If bWasSourceArrayNothing Then
                    ReDim Preserve arrSourceArray(UBound(arrSourceArray))
                    arrSourceArray(UBound(arrSourceArray)) = arrArrayToAdd
                Else
                    ReDim Preserve arrSourceArray(UBound(arrSourceArray) + 1)
                    arrSourceArray(UBound(arrSourceArray)) = arrArrayToAdd
                End If
            End If
        End If
    End If
    AddtoArray = arrSourceArray
End Function


Function HexFormat(intNumber)
    HexFormat = "0x" & Right("00000000" & CStr(Hex(intNumber)), 8)
End Function

Function PickNextFile(strFileName)
    Dim x, strTempFilename
    x = 0
    strTempFilename = strFileName
    While (objFSO.FileExists(strTempFilename)) And (x < 51)
        x = x + 1
        strTempFilename = objFSO.GetBaseName(strFileName) & "[" & x & "]" & _
                        "." & objFSO.GetExtensionName(strFileName)
    Wend
    PickNextFile = strTempFilename
End Function

Function DetectScriptEngine()
    Dim ScriptHost
    ScriptHost = wscript.FullName
    ScriptHost = Right(ScriptHost, Len(ScriptHost) - InStrRev(ScriptHost, "\"))
    If (UCase(ScriptHost) <> "CSCRIPT.EXE") Then
        MsgBox "This script runs under CSCRIPT.EXE only." + Chr(13) + "Script aborting.", vbExclamation, "Script running by WScript or other processor"
        DetectScriptEngine = False
    Else
        DetectScriptEngine = True
    End If
End Function

Sub ShowArgumentsSyntax(strErrorMsg)
    If Len(strErrorMsg) > 0 Then
        wscript.Echo "Error: " & strErrorMsg
    End If
    MissingParameters
End Sub

Function ExtractEmbeddedXSL(ByRef strXSLDestination)
    Dim objScriptFile
    Dim objXSL, strXSLPath
    Dim bolXSLExtracted, strLine, bCDataBegin
    
    On Error Resume Next
    wscript.Echo ""
    wscript.Echo "Building XSLT File..."
    
    Set objScriptFile = objFSO.OpenTextFile(wscript.ScriptFullName, ForReading, False, OpenFileMode)
    
    If Err.Number <> 0 Then
        DisplayError "Error opening script file to extract XSL file" & wscript.ScriptFullName & ".", Err.Number, Err.Source, Err.Description
        ExtractEmbeddedXSL = False
        Exit Function
    End If
    
    strXSLPath = objFSO.GetSpecialFolder(2) & "\DumpCollector.XSL"
    Set objXSL = objFSO.OpenTextFile(strXSLPath, ForWriting, True, OpenFileMode)
    
    If Err.Number <> 0 Then
        DisplayError "Error creating XSL file " & strXSLPath & ".", Err.Number, Err.Source, Err.Description
        ExtractEmbeddedXSL = False
        Exit Function
    End If
    
    bolXSLExtracted = False
    While (Not objScriptFile.AtEndOfStream) And (Not bolXSLExtracted)
        strLine = objScriptFile.ReadLine
        If strLine = "Sub EmbeddedXSL()" Then
            bCDataBegin = False
            Do
                strLine = objScriptFile.ReadLine
                If Not bCDataBegin Then 'In SDP we cannot have the CDATA notation, therefore we are translating as indicated below
                    If InStr(1, strLine, "<!{CDATA{", vbTextCompare) > 0 Then
                        strLine = Replace(strLine, "<!{CDATA{", "<!" & Chr(91) & "CDATA" & Chr(91), 1, -1, vbTextCompare)
                        bCDataBegin = True
                    End If
                Else
                    If InStr(1, strLine, "}}>", vbTextCompare) > 0 Then
                        strLine = Replace(strLine, "}}>", Chr(93) & Chr(93) & ">", 1, -1, vbTextCompare)
                        bCDataBegin = False
                    End If
                End If
                If Left(strLine, 1) = "'" Then objXSL.WriteLine Right(strLine, Len(strLine) - 1)
            Loop While Left(strLine, 1) = "'"
            bolXSLExtracted = True
        End If
    Wend
    
    If Err.Number <> 0 Then
        DisplayError "Error extracting XSL file from script.", Err.Number, Err.Source, Err.Description
        ExtractEmbeddedXSL = False
        strXSLDestination = ""
    Else
        objXSL.Close
        objScriptFile.Close
        strXSLDestination = strXSLPath
        ExtractEmbeddedXSL = True
    End If
    
    Set objXSL = Nothing
    Set objScriptFile = Nothing
    
End Function


Sub MissingParameters()

    wscript.Echo "  Use: "
    wscript.Echo "     cscript DumCollector.VBS [/maxage:{Days}] [/maxfiles:{NumberOfFilesPerCollection}] [/debuginfo] [/cdbpath:{c:\folder\cdb.exe}] "
    wscript.Echo "                              {[/reportonly] | [/copymachinememorydump] [/copymachineminidumps] [/copyuserdumps] [/copywerminidumps] "
    wscript.Echo "                              [/copywerfulldumps] [/copywerdumpaux] [/dontcopyuserdumpsfrom:{processname;process2}] "
    wscript.Echo "                              [/onlycopyuserdumpsfrom:{processname;process2}] [/maxsize:{MaximumDumpSizeinMB}"
    
End Sub

Sub EmbeddedXSL()
'<?xml version="1.0"?>
'<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
'<xsl:output method="html" />
'<xsl:key name="EventType" match="SubSession" use="SessionTitle/text()" />
'<xsl:key name="AppNames" match="SubSession" use="concat(SessionTitle/text(), '|', AppName/text())" />
'<xsl:template match="/Root">
'<html dir="ltr" xmlns:v="urn:schemas-microsoft-com:vml" gpmc_reportInitialized="false">
'<head>
'<!-- Styles -->
'<style type="text/css">
'                body    { background-color:#FFFFFF; border:1px solid #666666; color:#000000; font-size:68%; font-family:MS Shell Dlg; margin:0,0,10px,0; word-break:normal; word-wrap:break-word; }
'
'                table   { font-size:100%; table-layout:fixed; width:100%; }
'
'                td,th   { overflow:visible; text-align:left; vertical-align:top; white-space:normal; }
'
'                .title  { background:#FFFFFF; border:none; color:#333333; display:block; height:24px; margin:0px,0px,-1px,0px; padding-top:4px; position:relative; table-layout:fixed; width:100%; z-index:5; }
'
'                .he0_expanded    { background-color:#FEF7D6; border:1px solid #BBBBBB; color:#3333CC; cursor:hand; display:block; font-family:Verdana; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%;
'                                 filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=1,StartColorStr='#FEF7D6',EndColorStr='white');}
'
'                .he1_expanded    { background-color:#A0BACB; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'                .he4_expanded { background-color:#DDE6EC; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; font-weight:bold; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'                .he3_expanded { background-color:#C0D2DE; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; font-weight:bold; margin-left:0px; margin-right:0px; padding-left:4px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'                .he1old { background-color:#A0BACB; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'                .he1    { background-color:#FEF7D6; border:1px solid #BBBBBB; color:#3333CC; cursor:hand; display:block; font-family:Verdana; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'                .he2    { background-color:#C0D2DE; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'               .he2g   { background-color:#F9F9F9; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'                .he2c   { background-color:F2F7F9; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'                .he3    { background-color:#D9E3EA; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:30px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'                .he4    { background-color:#E8E8E8; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:40px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'               .he2b    { background-color:#C0D2DE; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'                .he4h   { background-color:#E8E8E8; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:45px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'                .he4i   { background-color:#F9F9F9; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; margin-bottom:-1px; margin-left:15px; margin-right:0px; padding-bottom:5px; padding-left:12px; padding-top:4px; position:relative; width:100%; }
'
'                .he5    { background-color:#E8E8E8; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:50px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'                .he5h   { background-color:#E8E8E8; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; padding-right:5em; padding-top:4px; margin-bottom:-1px; margin-left:55px; margin-right:0px; position:relative; width:100%; }
'
'                .he5i   { background-color:#F9F9F9; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; margin-bottom:-1px; margin-left:55px; margin-right:0px; padding-left:21px; padding-bottom:5px; padding-top: 4px; position:relative; width:100%; }
'
'                DIV .expando { color:#000000; text-decoration:none; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:normal; position:absolute; right:10px; text-decoration:underline; z-index: 0; }
'
'                .he0 .expando { font-size:100%; }
'
'                .info, .info0th, .info3, .info4, .disalign, .infoqfe, .infower { line-height:1.6em; padding:0px,0px,0px,0px; margin:0px,px,0px,0px;}
'
'                .disalign TD                      { padding-bottom:5px; padding-right:10px; }
'
'               .info5filename                    { padding-right:10px; width:30%; border-bottom:1px solid #CCCCCC; padding-right:10px;}
'
'               .info0th                          { padding-right:10px; width:12%; border-bottom:1px solid #CCCCCC; padding-right:10px;}
'
'                .info TD                          { padding-right:10px; width:50%; }
'
'                .infoqfe                          { table-layout:auto; }
'
'                .infoqfe TD, .infoqfe TH          { padding-right:10px;}
'
'                .info3 TD                         { padding-right:10px; width:33%; }
'
'                .info4 TD, .info4 TH              { padding-right:10px; width:25%;}
'
'                .infoFirstCol                     { padding-right:10px; width:20%; }
'                .infoSecondCol                     { padding-right:10px; width:80%; }
'
'                .info TH, .info0th, .info3 TH, .info4 TH, .disalign TH, .infoqfe TH, infower TH { border-bottom:1px solid #CCCCCC; padding-right:10px; }
'
'                .subtable, .subtable3             { border:1px solid #CCCCCC; margin-left:0px; background:#FFFFFF; margin-bottom:10px; }
'
'                .subtable TD, .subtable3 TD       { padding-left:10px; padding-right:5px; padding-top:3px; padding-bottom:3px; line-height:1.1em; width:10%; }
'
'                .subtable TH, .subtable3 TH       { border-bottom:1px solid #CCCCCC; font-weight:normal; padding-left:10px; line-height:1.6em;  }
'
'                .subtable .footnote               { border-top:1px solid #CCCCCC; }
'
'                .OkWingFont                       {font-family: Wingdings; color: #008080; font-size:130%; cursor:default; }
'                .BlackWingFont                    {font-family: Wingdings; color: #000000; font-size:175%; cursor:default; }
'                .BlueWingFont                     {font-family: Wingdings; color: #0000FF; font-size:175%; cursor:default; }
'                .RedWingFont                      {font-family: Wingdings; color: #993300; font-size:175%; cursor:default; }
'                .OrangeFont                          {color: #FF9900; font-size:160%; font-weight:900; cursor:default; }
'                .lines0                           {background-color: #F5F5F5;}
'                .lines1                           {background-color: #F9F9F9;}
'               .lines3                           {background-color: #FFFFF0;}
'
'                .subtable3 .footnote, .subtable .footnote { border-top:1px solid #CCCCCC; }
'
'                .subtable_frame     { background:#D9E3EA; border:1px solid #CCCCCC; margin-bottom:10px; margin-left:15px; }
'
'                .subtable_frame TD  { line-height:1.1em; padding-bottom:3px; padding-left:10px; padding-right:15px; padding-top:3px; }
'
'                .subtable_frame TH  { border-bottom:1px solid #CCCCCC; font-weight:normal; padding-left:10px; line-height:1.6em; }
'
'                .subtableInnerHead { border-bottom:1px solid #CCCCCC; border-top:1px solid #CCCCCC; }
'
'                .explainlink            { color:#000000; text-decoration:none; cursor:hand; }
'
'                .explainlink:hover      { color:#0000FF; text-decoration:underline; }
'
'                .spacer { background:transparent; border:1px solid #BBBBBB; color:#FFFFFF; display:block; font-family:MS Shell Dlg; font-size:100%; height:10px; margin-bottom:-1px; margin-left:43px; margin-right:0px; padding-top: 4px; position:relative; }
'
'                .filler { background:transparent; border:none; color:#FFFFFF; display:block; font:100% MS Shell Dlg; line-height:8px; margin-bottom:-1px; margin-left:43px; margin-right:0px; padding-top:4px; position:relative; }
'
'                .container { display:block; position:relative; }
'
'                .rsopheader { background-color:#A0BACB; border-bottom:1px solid black; color:#333333; font-family:MS Shell Dlg; font-size:130%; font-weight:bold; padding-bottom:5px; text-align:center;
'                              filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=0,StartColorStr='#FFFFFF',EndColorStr='#A0BACB')}
'
'                .rsopname { color:#333333; font-family:MS Shell Dlg; font-size:130%; font-weight:bold; padding-left:11px; }
'
'                .gponame{ color:#333333; font-family:MS Shell Dlg; font-size:130%; font-weight:bold; padding-left:11px; }
'
'                .gpotype{ color:#333333; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; padding-left:11px; }
'
'                #uri    { color:#333333; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; }
'
'                #dtstamp{ color:#333333; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; text-align:left; width:30%; }
'
'                #objshowhide { color:#000000; cursor:hand; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; margin-right:0px; padding-right:10px; text-align:right; text-decoration:underline; z-index:2; word-wrap:normal; }
'
'                #gposummary { display:block; }
'
'                #gpoinformation { display:block; }
'
'                @media print {
'
'                    #objshowhide{ display:none; }
'
'                    body    { color:#000000; border:1px solid #000000; }
'
'                    .title  { color:#000000; border:1px solid #000000; }
'
'                    .he0_expanded    { color:#000000; border:1px solid #000000; }
'
'                    .he1_expanded    { color:#000000; border:1px solid #000000; }
'
'                    .he1    { color:#000000; border:1px solid #000000; }
'
'                    .he2    { color:#000000; background:#EEEEEE; border:1px solid #000000; }
'
'                    .he3    { color:#000000; border:1px solid #000000; }
'
'                    .he4    { color:#000000; border:1px solid #000000; }
'
'                    .he4h   { color:#000000; border:1px solid #000000; }
'
'                    .he4i   { color:#000000; border:1px solid #000000; }
'
'                    .he5    { color:#000000; border:1px solid #000000; }
'
'                    .he5h   { color:#000000; border:1px solid #000000; }
'
'                    .he5i   { color:#000000; border:1px solid #000000; }
'
'                    }
'
'                    v\:* {behavior:url(#default#VML);}
'
'</style>
'<!-- Script 1 -->
'
'<script language="vbscript" type="text/vbscript">
'<!{CDATA{
'<!--
''================================================================================
'' String "strShowHide(0/1)"
'' 0 = Hide all mode.
'' 1 = Show all mode.
'strShowHide = 1
'
''Localized strings
'strShow = "show"
'strHide = "hide"
'strShowAll = "show all"
'strHideAll = "hide all"
'strShown = "shown"
'strHidden = "hidden"
'strExpandoNumPixelsFromEdge = "10px"
'
'
'Function IsSectionHeader(obj)
'    IsSectionHeader = (obj.className = "he0_expanded") Or (obj.className = "he1_expanded") Or (obj.className = "he1") Or (obj.className = "he2") Or (obj.className = "he2g") Or (obj.className = "he2c") or (obj.className = "he3") Or (obj.className = "he4") Or (obj.className = "he4h") Or (obj.className = "he5") Or (obj.className = "he5h")  or (obj.className = "he4_expanded")
'End Function
'
'
'Function IsSectionExpandedByDefault(objHeader)
'    IsSectionExpandedByDefault = (Right(objHeader.className, Len("_expanded")) = "_expanded")
'End Function
'
'
'Sub SetSectionState(objHeader, strState)
'    ' Get the container object for the section.  It's the first one after the header obj.
'
'    i = objHeader.sourceIndex
'    Set all = objHeader.parentElement.document.all
'    While (all(i).className <> "container")
'        i = i + 1
'    Wend
'
'    Set objContainer = all(i)
'
'    If strState = "toggle" Then
'        If objContainer.style.display = "none" Then
'            SetSectionState objHeader, "show"
'        Else
'            SetSectionState objHeader, "hide"
'        End If
'
'    Else
'        Set objExpando = objHeader.children(1)
'
'        If strState = "show" Then
'            objContainer.style.display = "block"
'            objExpando.innerHTML = "<v:group class=" & chr(34) & "expando" & chr(34) & " style=" & chr(34) & "width:15px;height:15px;vertical-align:middle" & chr(34) & _
'                                                        " coordsize=" & chr(34) & "100,100" & chr(34) & " title=" & chr(34) & "Collapse" & chr(34) & "><v:oval class=" & chr(34) & "vmlimage" & chr(34) & _
'                                                        " style='width:100;height:100;z-index:0' fillcolor=" & chr(34) & "#B7B7B7" & chr(34) & " strokecolor=" & chr(34) & "#8F8F8F" & chr(34) & "><v:fill type=" & chr(34) & _
'                                                        "gradient" & chr(34) & " angle=" & chr(34) & "0" & chr(34) & " color=" & chr(34) & "#D1D1D1" & chr(34) & " color2=" & chr(34) & "#F5F5F5" & chr(34) & " /></v:oval><v:line class=" & chr(34) & _
'                                                        "vmlimage" & chr(34) & " style=" & chr(34) & "z-index:1" & chr(34) & " from=" & chr(34) & "25,65" & chr(34) & " to=" & chr(34) & "50,37" & chr(34) & " strokecolor=" & chr(34) & "#5D5D5D" & chr(34) & _
'                                                        " strokeweight=" & chr(34) & "2px" & chr(34) & "></v:line><v:line class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "z-index:2" & chr(34) & " from=" & chr(34) & "50,37" & chr(34) & _
'                                                        " to=" & chr(34) & "75,65" & chr(34) & " strokecolor=" & chr(34) & "#5D5D5D" & chr(34) & " strokeweight=" & chr(34) & "2px" & chr(34) & "></v:line></v:group>"
'
'        ElseIf strState = "hide" Then
'            objContainer.style.display = "none"
'            objExpando.innerHTML = "<v:group class=" & chr(34) & "expando" & chr(34) & " style=" & chr(34) & "width:15px;height:15px;vertical-align:middle" & chr(34) & _
'                                                           " coordsize=" & chr(34) & "100,100" & chr(34) & " title=" & chr(34) & "Expand" & chr(34) & "><v:oval class=" & chr(34) & "vmlimage" & chr(34) & _
'                                                           " style='width:100;height:100;z-index:0' fillcolor=" & chr(34) & "#B7B7B7" & chr(34) & " strokecolor=" & chr(34) & "#8F8F8F" & chr(34) & "><v:fill type=" & chr(34) & _
'                                                           "gradient" & chr(34) & " angle=" & chr(34) & "0" & chr(34) & " color=" & chr(34) & "#D1D1D1" & chr(34) & " color2=" & chr(34) & "#F5F5F5" & chr(34) & " /></v:oval><v:line class=" & _
'                                                           chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "z-index:1" & chr(34) & " from=" & chr(34) & "25,40" & chr(34) & " to=" & chr(34) & "50,68" & chr(34) & " strokecolor=" & chr(34) & _
'                                                           "#5D5D5D" & chr(34) & " strokeweight=" & chr(34) & "2px" & chr(34) & "></v:line><v:line class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "z-index:2" & chr(34) & " from=" & chr(34) & _
'                                                           "50,68" & chr(34) & " to=" & chr(34) & "75,40" & chr(34) & " strokecolor=" & chr(34) & "#5D5D5D" & chr(34) & " strokeweight=" & chr(34) & "2px" & chr(34) & "></v:line></v:group>"
'        end if
'    End If
'End Sub
'
'
'Sub ShowSection(objHeader)
'    SetSectionState objHeader, "show"
'End Sub
'
'
'Sub HideSection(objHeader)
'    SetSectionState objHeader, "hide"
'End Sub
'
'
'Sub ToggleSection(objHeader)
'    SetSectionState objHeader, "toggle"
'End Sub
'
'
''================================================================================
'' When user clicks anywhere in the document body, determine if user is clicking
'' on a header element.
''================================================================================
'Function document_onclick()
'    Set strsrc    = window.event.srcElement
'
'    While (strsrc.className = "sectionTitle" Or strsrc.className = "expando" Or strsrc.className = "vmlimage")
'        Set strsrc = strsrc.parentElement
'    Wend
'
'    ' Only handle clicks on headers.
'    If Not IsSectionHeader(strsrc) Then Exit Function
'
'    ToggleSection strsrc
'
'    window.event.returnValue = False
'End Function
'
''================================================================================
'' link at the top of the page to collapse/expand all collapsable elements
''================================================================================
'Function objshowhide_onClick()
'    Set objBody = document.body.all
'    Select Case strShowHide
'        Case 0
'            strShowHide = 1
'            objshowhide.innerText = strShowAll
'            For Each obji In objBody
'                If IsSectionHeader(obji) Then
'                    HideSection obji
'                End If
'            Next
'        Case 1
'            strShowHide = 0
'            objshowhide.innerText = strHideAll
'            For Each obji In objBody
'                If IsSectionHeader(obji) Then
'                    ShowSection obji
'                End If
'            Next
'    End Select
'End Function
'
''================================================================================
'' onload collapse all except the first two levels of headers (he0, he1)
''================================================================================
'Function window_onload()
'    ' Only initialize once.  The UI may reinsert a report into the webbrowser control,
'    ' firing onLoad multiple times.
'    If UCase(document.documentElement.getAttribute("gpmc_reportInitialized")) <> "TRUE" Then
'
'        ' Set text direction
'        Call fDetDir(UCase(document.dir))
'
'        ' Initialize sections to default expanded/collapsed state.
'        Set objBody = document.body.all
'
'        For Each obji in objBody
'            If IsSectionHeader(obji) Then
'                If IsSectionExpandedByDefault(obji) Then
'                    ShowSection obji
'                Else
'                    HideSection obji
'                End If
'            End If
'        Next
'
'        objshowhide.innerText = strShowAll
'
'        document.documentElement.setAttribute "gpmc_reportInitialized", "true"
'    End If
'End Function
'
'
'
'
''================================================================================
'' When direction (LTR/RTL) changes, change adjust for readability
''================================================================================
'Function document_onPropertyChange()
'    If window.event.propertyName = "dir" Then
'        Call fDetDir(UCase(document.dir))
'    End If
'End Function
'Function fDetDir(strDir)
'    strDir = UCase(strDir)
'    Select Case strDir
'        Case "LTR"
'            Set colRules = document.styleSheets(0).rules
'            For i = 0 To colRules.length -1
'                Set nug = colRules.item(i)
'                strClass = nug.selectorText
'                If nug.style.textAlign = "right" Then
'                    nug.style.textAlign = "left"
'                End If
'                Select Case strClass
'                    Case "DIV .expando"
'                        nug.style.Left = ""
'                        nug.style.right = strExpandoNumPixelsFromEdge
'                    Case "#objshowhide"
'                        nug.style.textAlign = "right"
'                End Select
'            Next
'        Case "RTL"
'            Set colRules = document.styleSheets(0).rules
'            For i = 0 To colRules.length -1
'                Set nug = colRules.item(i)
'                strClass = nug.selectorText
'                If nug.style.textAlign = "left" Then
'                    nug.style.textAlign = "right"
'                End If
'                Select Case strClass
'                    Case "DIV .expando"
'                        nug.style.Left = strExpandoNumPixelsFromEdge
'                        nug.style.right = ""
'                    Case "#objshowhide"
'                        nug.style.textAlign = "left"
'                End Select
'            Next
'    End Select
'End Function
'
''================================================================================
''When printing reports, if a given section is expanded, let's says "shown" (instead of "hide" in the UI).
''================================================================================
'Function window_onbeforeprint()
'    For Each obji In document.all
'        If obji.className = "expando" Then
'            If obji.innerText = strHide Then obji.innerText = strShown
'            If obji.innerText = strShow Then obji.innerText = strHidden
'        End If
'    Next
'End Function
'
''================================================================================
''If a section is collapsed, change to "hidden" in the printout (instead of "show").
''================================================================================
'Function window_onafterprint()
'    For Each obji In document.all
'        If obji.className = "expando" Then
'            If obji.innerText = strShown Then obji.innerText = strHide
'            If obji.innerText = strHidden Then obji.innerText = strShow
'        End If
'    Next
'End Function
'
''================================================================================
'' Adding keypress support for accessibility
''================================================================================
'Function document_onKeyPress()
'    If window.event.keyCode = "32" Or window.event.keyCode = "13" Or window.event.keyCode = "10" Then 'space bar (32) or carriage return (13) or line feed (10)
'        If window.event.srcElement.className = "expando" Then Call document_onclick() : window.event.returnValue = false
'        If window.event.srcElement.className = "sectionTitle" Then Call document_onclick() : window.event.returnValue = false
'        If window.event.srcElement.id = "objshowhide" Then Call objshowhide_onClick() : window.event.returnValue = false
'    End If
'End Function
'
'-->
'}}>
'</script>
'
'<!-- Script 2 -->
'
'<script language="javascript"><!{CDATA{
'<!--
'function getExplainWindowTitle()
'{
'        return document.getElementById("explainText_windowTitle").innerHTML;
'}
'
'function getExplainWindowStyles()
'{
'        return document.getElementById("explainText_windowStyles").innerHTML;
'}
'
'function getExplainWindowSettingPathLabel()
'{
'        return document.getElementById("explainText_settingPathLabel").innerHTML;
'}
'
'function getExplainWindowExplainTextLabel()
'{
'        return document.getElementById("explainText_explainTextLabel").innerHTML;
'}
'
'function getExplainWindowPrintButton()
'{
'        return document.getElementById("explainText_printButton").innerHTML;
'}
'
'function getExplainWindowCloseButton()
'{
'        return document.getElementById("explainText_closeButton").innerHTML;
'}
'
'function getNoExplainTextAvailable()
'{
'        return document.getElementById("explainText_noExplainTextAvailable").innerHTML;
'}
'
'function getExplainWindowSupportedLabel()
'{
'        return document.getElementById("explainText_supportedLabel").innerHTML;
'}
'
'function getNoSupportedTextAvailable()
'{
'        return document.getElementById("explainText_noSupportedTextAvailable").innerHTML;
'}
'
'function showExplainText(srcElement)
'{
'    var strSettingName = srcElement.getAttribute("gpmc_settingName");
'    var strSettingPath = srcElement.getAttribute("gpmc_settingPath");
'    var strSettingDescription = srcElement.getAttribute("gpmc_settingDescription");
'
'    if (strSettingDescription == "")
'    {
'                strSettingDescription = getNoExplainTextAvailable();
'    }
'
'    var strSupported = srcElement.getAttribute("gpmc_supported");
'
'    if (strSupported == "")
'    {
'        strSupported = getNoSupportedTextAvailable();
'    }
'
'    var strHtml = "<html>\n";
'    strHtml += "<head>\n";
'    strHtml += "<title>" + getExplainWindowTitle() + "</title>\n";
'    strHtml += "<style type='text/css'>\n" + getExplainWindowStyles() + "</style>\n";
'    strHtml += "</head>\n";
'    strHtml += "<body>\n";
'    strHtml += "<div class='head'>" + strSettingName +"</div>\n";
'    strHtml += "<div class='path'><b>" + getExplainWindowSettingPathLabel() + "</b><br/>" + strSettingPath +"</div>\n";
'    strHtml += "<div class='path'><b>" + getExplainWindowSupportedLabel() + "</b><br/>" + strSupported +"</div>\n";
'    strHtml += "<div class='info'>\n";
'    strHtml += "<div class='hdr'>" + getExplainWindowExplainTextLabel() + "</div>\n";
'    strHtml += "<div class='bdy'>" + strSettingDescription + "</div>\n";
'    strHtml += "<div class='btn'>";
'    strHtml += getExplainWindowPrintButton();
'    strHtml += getExplainWindowCloseButton();
'    strHtml += "</div></body></html>";
'
'    var strDiagArgs = "height=360px, width=630px, status=no, toolbar=no, scrollbars=yes, resizable=yes ";
'    var expWin = window.open("", "expWin", strDiagArgs);
'    expWin.document.write("");
'    expWin.document.close();
'    expWin.document.write(strHtml);
'    expWin.document.close();
'    expWin.focus();
'
'    //cancels navigation for IE.
'    if(navigator.userAgent.indexOf("MSIE") > 0)
'    {
'        window.event.returnValue = false;
'    }
'
'    return false;
'}
'-->
'}}>
'</script>
'
'</head>
'
'<body>
'
'   <table class="title" cellpadding="0" cellspacing="0">
'   <tr><td colspan="2" class="rsopheader">Memory Dump Information</td></tr>
'   <tr><td colspan="2" class="rsopname">Machine name: <xsl:value-of select="Title"/></td></tr>
'   <tr><td id="dtstamp">Data collected on: <xsl:value-of select="TimeField"/></td><td><div id="objshowhide" tabindex="0"></div></td></tr>
'   </table>
'   <div class="filler"></div>
'
'   <div class="container">
'   <div class="he0_expanded"><span class="sectionTitle" tabindex="0">Alerts</span><a class="expando" href="#"></a></div>
'   <div class="container">
'   <xsl:for-each select="./Alerts/Alert">
'       <xsl:sort select="AlertPriority" order="descending" data-type="number"/>
'       <div class="he2b">
'           <span class="sectionTitle" tabindex="0">
'               <xsl:choose>
'                   <xsl:when test="AlertType = 'Information'">
'                           <v:group id="Inf1" class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Information">
'                             <v:oval class="vmlimage" style="width:100;height:100;z-index:0" fillcolor="white" strokecolor="#336699" />
'                             <v:line class="vmlimage" style="z-index:1" from="50,15" to="50,25" strokecolor="#336699" strokeweight="3px" />
'                             <v:line class="vmlimage" style="z-index:2" from="50,35" to="50,80" strokecolor="#336699" strokeweight="3px" />
'                             </v:group>
'                   </xsl:when>
'                   <xsl:when test="AlertType = 'Warning'">
'                       <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Warning">
'                               <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="yellow" strokecolor="#C0C0C0">
'                               <v:path v="m 50,0 l 0,99 99,99 x e" />
'                               </v:shape>
'                               <v:rect class="vmlimage" style="top:35; left:45; width:10; height:35; z-index:1" fillcolor="black" strokecolor="black">
'                               </v:rect>
'                               <v:rect class="vmlimage" style="top:85; left:45; width:10; height:5; z-index:1" fillcolor="black" strokecolor="black">
'                               </v:rect>
'                       </v:group>
'                   </xsl:when>
'                   <xsl:when test="AlertType = 'Error'">
'                   <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Error">
'                       <v:oval class="vmlimage" style='width:100;height:100;z-index:0' fillcolor="red" strokecolor="red">
'                       </v:oval>
'                       <v:line class="vmlimage" style="z-index:1" from="25,25" to="75,75" strokecolor="white" strokeweight="3px">
'                       </v:line>
'                       <v:line class="vmlimage" style="z-index:2" from="75,25" to="25,75" strokecolor="white" strokeweight="3px">
'                       </v:line>
'                   </v:group>
'                   </xsl:when>
'                   <xsl:when test="AlertType = 'Memory Dump'">
'                       <v:group class="vmlimage" style="width:14px;height:14px;vertical-align:middle" coordsize="100,100" title="Memory Dump">
'                        <v:roundrect class="vmlimage" arcsize="0.3" style="width:100;height:100;z-index:0" fillcolor="#008000" strokecolor="#66665B" />
'                        <v:line class="vmlimage" style="z-index:2" from="50,15" to="50,60" strokecolor="white" strokeweight="3px" />
'                           <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="white" strokecolor="white">
'                                   <v:path v="m 50,85 l 75,60 25,60 x e" />
'                               </v:shape>
'                      </v:group>
'                      <xsl:text>&#160;</xsl:text>
'                   </xsl:when>
'               </xsl:choose>
'               <xsl:value-of select="AlertType"/>
'           </span><a class="expando" href="#"></a>
'       </div>
'       <div class="container"><div class="he4i"><table cellpadding="0" class="info0">
'           <tr><td class="infoFirstCol">Category: </td><td class="infoSecondCol"><xsl:value-of disable-output-escaping="yes" select="AlertCategory"/></td><td></td></tr>
'           <tr><td class="infoFirstCol">Message: </td><td class="infoSecondCol"><xsl:value-of disable-output-escaping="yes" select="AlertMessage"/></td><td></td></tr>
'           <tr><td class="infoFirstCol">Recommendation: </td><td class="infoSecondCol"><xsl:value-of disable-output-escaping="yes" select="AlertRecommendation"/></td><td></td></tr>
'           </table>
'       </div>
'       </div>
'   </xsl:for-each>
'   </div>
'   </div>
'   <div class="filler"></div>
'
'   <xsl:for-each select="./Session">
'
'   <div class="he0_expanded"><span class="sectionTitle" tabindex="0"><xsl:value-of select="SessionTitle"/></span><a class="expando" href="#"></a></div>
'
'       <div class="container"><div class="he4i"><table cellpadding="0" class="info4" >
'       <tr><td></td><td></td><td></td><td></td><td></td></tr>
'       <xsl:for-each select="./Item">
'       <xsl:variable name="pos" select="position()" />
'       <xsl:variable name="mod" select="($pos mod 2)" />
'       <tr><td><xsl:value-of select="@name"/></td><td colspan="4"><xsl:value-of select="."/></td></tr>
'       </xsl:for-each>
'       </table>
'       <xsl:for-each select="./SubSession">
'                   <xsl:variable name="LookupSessionName" select="LookupSessionName"/>
'                   <div class="container">
'                   <div class="he3_expanded"><span class="sectionTitle" tabindex="0"><xsl:value-of select="SessionTitle/@name"/><xsl:text> </xsl:text><a name="{SessionTitle}"><xsl:value-of select="SessionTitle"/></a></span><a class="expando" href="#"></a></div>
'                   <div class="container"><div class="he4i"><table cellpadding="0" class="info4">
'                       <tr><td></td><td></td><td></td><td></td><td></td></tr>
'                       <xsl:for-each select="./Item">
'                       <xsl:variable name="pos" select="position()" />
'                       <xsl:variable name="mod" select="($pos mod 2)" />
'                       <tr><td><xsl:value-of select="@name"/></td><td colspan="4"><xsl:value-of disable-output-escaping="yes" select="."/></td><td></td></tr>
'                       </xsl:for-each>
'                       </table>
'                   </div></div>
'                   <xsl:if test="LookupSessionName">
'                       <div class="he4_expanded"><span class="sectionTitle" tabindex="0">Dump Information</span><a class="expando" href="#"></a></div>
'                           <xsl:variable name="DumpReportInfo" select="LookupSessionName" />
'                           <xsl:for-each select="/Root/MemoryDumpDebugInfo[Title=$DumpReportInfo]">
'                               <div class="container"><div class="he4i"><table cellpadding="0" class="info4">
'                               <tr><td></td><td></td><td></td><td></td></tr>
'                               <xsl:for-each select="./Item">
'                                   <tr><td><xsl:value-of select="@name"/></td><td colspan="3"><xsl:value-of disable-output-escaping="yes" select="."/></td><td></td></tr>
'                               </xsl:for-each>
'                               </table>
'                               </div></div>
'
'                               <div class="he2c"><span class="sectionTitle" tabindex="0">Module List</span><a class="expando" href="#"></a></div>
'                               <div class="container"><div class="he4i"><table cellpadding="0" class="info4">
'                               <table cellpadding="0" class="infoqfe" >
'                                   <tr><th>Image Name</th><th>Memory Range</th><th>Image Path</th><th>Time Stamp</th><th>File Description</th><th>Product Version</th><th>Company name</th></tr>
'                                       <xsl:for-each select="./ModuleList/Binary">
'                                               <xsl:variable name="pos" select="position()" />
'                                               <xsl:variable name="mod" select="($pos mod 2)"/>
'                                               <tr><td class="lines{$mod}"><xsl:value-of select="Name"/></td>
'                                                   <td class="lines{$mod}"><xsl:value-of select="Range"/></td>
'                                                   <td class="lines{$mod}"><xsl:value-of select="Property[@name = 'Image Path']"/></td>
'                                                   <td class="lines{$mod}"><xsl:value-of select="Property[@name = 'Time Stamp']"/></td>
'                                                   <td class="lines{$mod}"><xsl:value-of select="Property[@name = 'File description']"/></td>
'                                                   <td class="lines{$mod}">
'                                                       <xsl:choose>
'                                                           <xsl:when test="Property[@name = 'File version'] and Property[@name = 'Product version']"><span title="{Property[@name = 'Product version']}" style="cursor:pointer"><xsl:value-of select="Property[@name = 'File version']"/></span></xsl:when>
'                                                           <xsl:when test="Property[@name = 'File version']"><xsl:value-of select="Property[@name = 'File version']"/></xsl:when>
'                                                           <xsl:when test="Property[@name = 'Product version']"><xsl:value-of select="Property[@name = 'Product version']"/></xsl:when>
'                                                           <xsl:when test="FSProperty[@name = 'Current version']"><span title="Information not obtained in dump. This is the current version of file." style="cursor:pointer;" class="lines3"><xsl:value-of select="FSProperty[@name = 'Current version']"/></span></xsl:when>
'                                                       </xsl:choose>
'                                                   </td>
'                                                   <td class="lines{$mod}">
'                                                       <xsl:choose>
'                                                           <xsl:when test="Property[@name = 'Company Name']"><xsl:value-of select="Property[@name = 'Company Name']"/></xsl:when>
'                                                           <xsl:when test="FSProperty[@name = 'Company Name']"><span title="Information obtained from current version of file." style="cursor:pointer;" class="lines3"><xsl:value-of select="FSProperty[@name = 'Company Name']"/></span></xsl:when>
'                                                       </xsl:choose>
'                                                   </td>
'                                               </tr>
'                                       </xsl:for-each>
'                                   </table>
'                               </table>
'                           </div></div>
'                           <div class="filler"></div>
'                           </xsl:for-each>
'
'                   </xsl:if>
'
'                   </div>
'       </xsl:for-each>
'
'       <xsl:if test="WerSession">
'           <div class="container">
'           <xsl:for-each select="//WerSession/SubSession[count(. | key('EventType', SessionTitle/text())[1]) = 1]">
'               <xsl:variable name="CurrentEventType" select="SessionTitle/text()" />
'               <div class="he3_expanded"><span class="sectionTitle" tabindex="0"><xsl:value-of select="SessionTitle"/></span><a class="expando" href="#"></a></div>
'               <xsl:for-each select="key('EventType', $CurrentEventType)[count(. | key('AppNames', concat($CurrentEventType, '|', AppName/text()))[1]) = 1]">
'                   <xsl:variable name="AppName" select="AppName" />
'                   <xsl:variable name="DumpExists" select="boolean(//Table[../Dump != 'Not created' and ../AppName=$AppName and ../SessionTitle=$CurrentEventType])" />
'                   <div class="he2c"><span class="sectionTitle" tabindex="0"><a name="{LookupSessionName}"></a><xsl:value-of select="$AppName"/></span><a class="expando" href="#"></a></div>
'                   <div class="container"> <div class="he4i">
'                   <xsl:for-each select="key('AppNames', concat($CurrentEventType, '|', $AppName))">
'                       <table cellpadding="0" class="infower" >
'                           <xsl:if test="position() = 1">
'                           <tr>
'                           <th>Date</th>
'                               <xsl:for-each select="./Table/Sig">
'                                       <th><xsl:value-of select="@name"/></th>
'                               </xsl:for-each>
'                           <xsl:if test="$DumpExists">
'                           <th>Dump</th>
'                           </xsl:if>
'                           </tr>
'                           </xsl:if>
'                           <xsl:for-each select="./Table[../AppName=$AppName and ../SessionTitle=$CurrentEventType]">
'                               <tr>
'                               <td><xsl:value-of select="Time"/></td>
'                               <xsl:for-each select="./Sig">
'                                   <td><xsl:value-of select="."/></td>
'                               </xsl:for-each>
'                               <xsl:if test="$DumpExists">
'                                   <td>
'                                   <xsl:choose>
'                                       <xsl:when test="../Dump = 'Not created'">
'                                           <span title="Dump not created" class="BlackWingFont">&#251;</span>
'                                       </xsl:when>
'                                       <xsl:when test="../Dump = 'Created but not copied'">
'                                           <span title="Created, but not copied." class="RedWingFont">&#253;</span>
'                                       </xsl:when>
'                                       <xsl:when test="contains(../Dump,'.CAB') or contains(../Dump,'.cab') or contains(../Dump,'.cab') or contains(../Dump,'.zip')">
'                                           <span title="Copied to {../Dump}" class="OkWingFont"><a style="text-decoration:none" href="{../Dump}" name="{../Dump}">&#49;</a></span>
'                                       </xsl:when>
'                                       <xsl:otherwise>
'                                           <span title="{../Dump}" class="OkWingFont">&#253;</span>
'                                       </xsl:otherwise>
'                                   </xsl:choose>
'                                   </td>
'                               </xsl:if>
'                               </tr>
'                           </xsl:for-each>
'                       </table>
'
'                   </xsl:for-each>
'                   </div></div>
'               </xsl:for-each>
'           </xsl:for-each>
'           </div>
'       </xsl:if>
'
'
'       </div></div>
'   <div class="filler"></div>
'
'   </xsl:for-each>
'
'</body>
'</html>
'</xsl:template>
'</xsl:stylesheet>
End Sub

Class ezPLA
    '************************************************
    'ezPLA VB Class
    'Version 1.0.1
    'Date: 4-24-2009
    'Author: Andre Teixeira - andret@microsoft.com
    '************************************************
    
    Private objFSO
    Private objShell
    
    Public Section
    Public SectionPriority
    Public AlertType
    Public AlertPriority
    Public Symptom
    Public Details
    Public MoreInformation
    
    Private ALERT_INFORMATION
    Private ALERT_WARNING
    Private ALERT_ERROR
    Private ALERT_NOTE
    
    Public Function AddAlerttoPLA()
        
        Set objShell = CreateObject("WScript.Shell")
        Set objFSO = CreateObject("Scripting.FileSystemObject")
            
        ALERT_INFORMATION = 1
        ALERT_WARNING = 2
        ALERT_ERROR = 3
        ALERT_NOTE = 4
                
        On Error Resume Next
        
        'Validation
        If Len(Section) = 0 Then
            Section = "Messages"
        End If
        
        If Len(SectionPriority) = 0 Then
            If IsNumeric(SectionPriority) Then
                SectionPriority = CInt(SectionPriority)
            Else
                SectionPriority = 50 'Default Value
            End If
            SectionPriority = 50 'Default Value
        End If
    
        If Not IsNumeric(AlertType) Then
            AlertType = ALERT_NOTE
        ElseIf AlertType > 4 Then
            AlertType = ALERT_NOTE
        End If
        
        If Not IsNumeric(AlertPriority) Then
            AlertPriority = 20 - AlertType
        End If
        
        If Len(Symptom) = 0 Then
            DisplayError "Checking Values for Symptom", 5000, "AddAlertoPLA", "You have to assign a correct value for Symptom."
            Exit Function
        End If
    
        WriteAlertToPLA
        
    End Function
    
    Private Function WriteAlertToPLA()
        
        Dim strAlertType
        Dim XMLDoc
        Dim XMLDoc2
        
        Dim objSectionElement
        Dim objTableElement
        Dim objXMLAtt
        Dim objReportElement
        Dim objHeaderElement
        Dim objItemElement
        Dim objDataElement
        Dim strDiagnosticXMLPath
                
        strDiagnosticXMLPath = "..\ReportFiles\Diagnostic_Results.XML"
        
        Select Case AlertType
            Case ALERT_INFORMATION
                strAlertType = "info"
            Case ALERT_WARNING
                strAlertType = "warning"
            Case ALERT_ERROR
                strAlertType = "error"
            Case ALERT_NOTE
                strAlertType = "note"
        End Select
        
        Set XMLDoc = CreateObject("Microsoft.XMLDOM")
        XMLDoc.async = "false"
    
        If objFSO.FileExists(strDiagnosticXMLPath) Then 'A PLA reporting already exists
            XMLDoc.Load strDiagnosticXMLPath
            Set objSectionElement = XMLDoc.selectNodes("/Report/Section[@name='" & Section & "']").Item(0) 'Try to find the 'Section' section
            If CheckForError(XMLDoc, "Searching Section Object") <> 0 Then Exit Function
        Else
            wscript.Echo "      " & strDiagnosticXMLPath & " does not exist. Creating it..."
            If Not objFSO.FolderExists("..\ReportFiles") Then objFSO.CreateFolder ("..\ReportFiles")
            XMLDoc.loadXML ("<?xml version=""1.0""?><?xml-stylesheet type=""text/xsl"" href=""report.xsl""?><Report name=""msdtAdvisor"" level=""1"" version=""1"" top=""9999"" portable=""1""/>")
            If CheckForError(XMLDoc, "Loading Standard XML file") <> 0 Then Exit Function
        End If
              
        If XMLObjectIsEmptyorNothing(objSectionElement) Then  'Create the 'Messages' section if it does not exist
                Set objReportElement = XMLDoc.selectNodes("/Report").Item(0)
                
                Set objSectionElement = XMLDoc.createElement("Section")
                
                Set objXMLAtt = XMLDoc.createAttribute("name")
                objSectionElement.Attributes.setNamedItem(objXMLAtt).Text = Section
                Set objXMLAtt = XMLDoc.createAttribute("expand")
                objSectionElement.Attributes.setNamedItem(objXMLAtt).Text = "true"
                Set objXMLAtt = XMLDoc.createAttribute("key")
                objSectionElement.Attributes.setNamedItem(objXMLAtt).Text = CStr(SectionPriority)
                
                objReportElement.appendChild objSectionElement
                
                If CheckForError(XMLDoc, "Creating Section Object") <> 0 Then Exit Function
        End If
        
        'Setting Alert Type and Priority
        Set objTableElement = XMLDoc.createElement("Table")
        Set objXMLAtt = XMLDoc.createAttribute("name")
        objTableElement.Attributes.setNamedItem(objXMLAtt).Text = strAlertType
        Set objXMLAtt = XMLDoc.createAttribute("style")
        objTableElement.Attributes.setNamedItem(objXMLAtt).Text = "info"
        Set objXMLAtt = XMLDoc.createAttribute("key")
        objTableElement.Attributes.setNamedItem(objXMLAtt).Text = CStr(AlertPriority)
        
        Set objHeaderElement = XMLDoc.createElement("Header")
        objTableElement.appendChild objHeaderElement
        If CheckForError(XMLDoc, "Setting Alert Type and Priority to XML Header") <> 0 Then Exit Function
        
        Set objItemElement = XMLDoc.createElement("Item")
        Set objDataElement = XMLDoc.createElement("Data")
        
        Set objXMLAtt = XMLDoc.createAttribute("name")
        objDataElement.Attributes.setNamedItem(objXMLAtt).Text = "Symptom"
        Set objXMLAtt = XMLDoc.createAttribute("img")
        objDataElement.Attributes.setNamedItem(objXMLAtt).Text = strAlertType
        Set objXMLAtt = XMLDoc.createAttribute("message")
        objDataElement.Attributes.setNamedItem(objXMLAtt).Text = "standard_Message"
        
        objDataElement.appendChild XMLDoc.createTextNode(Symptom)
        objItemElement.appendChild objDataElement
    
        If CheckForError(XMLDoc, "Appending Symptom to XML") <> 0 Then Exit Function
    
        If Len(Details) > 0 Then
            Set XMLDoc2 = CreateObject("Microsoft.XMLDOM")
            XMLDoc2.async = "false"
            XMLDoc2.loadXML "<?xml version=""1.0""?><Data name=""Details"" message=""standard_Message"">" & Details & "</Data>"
            Set objDataElement = XMLDoc2.documentElement
            objItemElement.appendChild objDataElement
            If CheckForError(XMLDoc, "Appending Details to XML") <> 0 Then Exit Function
        End If
                    
        If Len(MoreInformation) > 0 Then
            Set XMLDoc2 = CreateObject("Microsoft.XMLDOM")
            XMLDoc2.async = "false"
            XMLDoc2.loadXML "<?xml version=""1.0""?><Data name=""Additional Information"" message=""standard_Message"">" & MoreInformation & "</Data>"
            Set objDataElement = XMLDoc2.documentElement
            objItemElement.appendChild objDataElement
            If CheckForError(XMLDoc, "Appending MoreInformation to XML") <> 0 Then Exit Function
        End If
        
        objTableElement.appendChild objItemElement
        If CheckForError(XMLDoc, "Appending Table to XML") <> 0 Then Exit Function
        
        objSectionElement.appendChild objTableElement
        If CheckForError(XMLDoc, "Appending Alert XML Element to XML") <> 0 Then Exit Function
        
        XMLDoc.Save strDiagnosticXMLPath
    
        If CheckForError(XMLDoc, "Saving Report.XML file") <> 0 Then Exit Function
    
    End Function
    
    Private Function XMLObjectIsEmptyorNothing(objXML)
        On Error Resume Next
        XMLObjectIsEmptyorNothing = (objXML Is Nothing)
        If Err.Number > 0 Then
            XMLObjectIsEmptyorNothing = IsEmpty(objXML)
        End If
        Err.Clear
    End Function
    
    Private Function TranslateXMLChars(strRAWString)
        strRAWString = Replace(strRAWString, "&", "&amp;")
        strRAWString = Replace(strRAWString, "<", "&lt;")
        strRAWString = Replace(strRAWString, ">", "&gt;")
        strRAWString = Replace(strRAWString, "'", "&apos;")
        strRAWString = Replace(strRAWString, Chr(34), "&quot;")
        TranslateXMLChars = strRAWString
    End Function
    
    Private Function CheckForError(xmlFile, strOperation)
        Dim strErrText
            If (Err.Number <> 0) Or (xmlFile.parseError.errorCode <> 0) Then
                If Err.Number <> 0 Then
                    DisplayError strOperation, Err.Number, Err.Source, Err.Description
                    CheckForError = Err.Number
                Else
                    With xmlFile.parseError
                        strErrText = "Failed to process/ load XML file " & _
                                "due the following error:" & vbCrLf & _
                                "Error #: " & .errorCode & ": " & .reason & _
                                "Line #: " & .Line & vbCrLf & _
                                "Line Position: " & .linepos & vbCrLf & _
                                "Position In File: " & .filepos & vbCrLf & _
                                "Source Text: " & .srcText & vbCrLf & _
                                "Document URL: " & .url
                        CheckForError = .errorCode
                    End With
                    DisplayError strOperation, 5001, "CheckForXMLError", strErrText
                End If
            Else
                CheckForError = 0
            End If
    End Function
    
    Private Sub DisplayError(strErrorLocation, errNumber, errSource, errDescription)
        On Error Resume Next
        If errNumber <> 0 Then
            wscript.Echo "Error " & HexFormat(errNumber) & iif(Len(strErrorLocation) > 0, ": " & strErrorLocation, "")
            wscript.Echo errSource & " - " & errDescription
        Else
            wscript.Echo "An error has ocurred!. " & iif(Len(strErrorLocation) > 0, ": " & strErrorLocation, "")
        End If
    End Sub
    
End Class

Class Debugger

    Public objDebuggerExec
    Private arrDiagInfo
    Dim objFSO
    Dim objShell
    
    Private Sub Class_Initialize()
        Set objShell = CreateObject("WScript.Shell")
        Set objFSO = CreateObject("Scripting.FileSystemObject")
    End Sub
    
    Public Function CloseDumpFile()
        On Error Resume Next
        If IsDebuggerOpen Then
            objDebuggerExec.StdIn.WriteLine "q"
            objDebuggerExec.StdIn.Close
        End If
    End Function
    
    Private Sub Class_Terminate()
        If Not (objDebuggerExec Is Nothing) Then
            If objDebuggerExec.Status = 0 Then
                CloseDumpFile
            End If
            Set objDebuggerExec = Nothing
        End If
        Set objShell = Nothing
        Set objFSO = Nothing
    End Sub
    
    Function IsDebuggerOpen()
        IsDebuggerOpen = (objDebuggerExec.Status = 0)
    End Function
    
    Public Function OpenDumpFile(strDebuggerPath, strDumpLocation)
        Dim strCommandLine
        OpenDumpFile = False
        If objFSO.FileExists(strDebuggerPath) Then
            Rem strCommandLine = "CMD.exe /c SET _NT_SYMBOL_PATH=SRV*..\SymCache*http://msdl.microsoft.com/download/symbols & ntsd.exe -x -G -x -c " & Chr(34) & ".logopen DebuggerOutput.TXT;!analyze -v;q" & Chr(34) & " -z " & Chr(34) & strDumpLocation & Chr(34)
            strCommandLine = strDebuggerPath & " -z " & Chr(34) & strDumpLocation & Chr(34)
            Set objDebuggerExec = objShell.Exec(strCommandLine)
            wscript.Sleep 100
            If IsDebuggerOpen Then
                OpenDumpFile = True
            End If
        End If
    End Function
    
    Public Function ExitandGetStdOutOutput()
        CloseDumpFile
        If Not IsEmpty(arrDiagInfo) Then
            Dim strLine
            For Each strLine In arrDiagInfo
                ExitandGetStdOutOutput = ExitandGetStdOutOutput & strLine
            Next
        End If
    
        ExitandGetStdOutOutput = ExitandGetStdOutOutput & vbCrLf & objDebuggerExec.StdOut.ReadAll
    End Function
    
    Public Function GetRAWDebuggerOutput(ByVal strDebuggerCommand, ByRef arrDebuggerOutput)
        Dim objDebugLogFile, strDebuggerOutputFilePath, strLine, bCommandEnded, bEndOfLogReached
        
        GetRAWDebuggerOutput = False
        
        If IsDebuggerOpen Then
            Set arrDebuggerOutput = Nothing
        
            strDebuggerOutputFilePath = objFSO.BuildPath(objFSO.GetSpecialFolder(2), "DebuggerOutput.TXT")
            
            objDebuggerExec.StdIn.WriteLine ".logopen " & Chr(34) & strDebuggerOutputFilePath & Chr(34)
            objDebuggerExec.StdIn.WriteLine ".echo ##Command##:" & strDebuggerCommand & "; " & strDebuggerCommand
            objDebuggerExec.StdIn.WriteLine ".echo ##CommandFinished##;.logclose"
            
            bCommandEnded = False
            
            Do While (Not objDebuggerExec.StdOut.AtEndOfStream) And (Not bCommandEnded) 'Wait for the command to complete
                strLine = objDebuggerExec.StdOut.ReadLine()
                'Debug.Print strLine
                If InStr(1, strLine, "##CommandFinished##") Then
                    bCommandEnded = True
                End If
            Loop
            
            Set objDebugLogFile = objFSO.OpenTextFile(strDebuggerOutputFilePath, 1, False, -2)
            
            bEndOfLogReached = False
            While (Not objDebugLogFile.AtEndOfStream) And (Not bEndOfLogReached)
                strLine = objDebugLogFile.ReadLine
                If Left(strLine, 12) = "##Command##:" Then
                    strLine = objDebugLogFile.ReadLine
                    While (Not objDebugLogFile.AtEndOfStream) And (Not bEndOfLogReached)
                        AddtoArray arrDebuggerOutput, strLine
                        strLine = objDebugLogFile.ReadLine
                        If InStr(1, strLine, "##CommandFinished##") Then
                            bEndOfLogReached = True
                        End If
                    Wend
                End If
            Wend
            objDebugLogFile.Close
            objFSO.DeleteFile strDebuggerOutputFilePath
        
            If bEndOfLogReached Then
                GetRAWDebuggerOutput = True
            Else
                GetRAWDebuggerOutput = False
            End If
        Else
            GetRAWDebuggerOutput = False
        End If
    End Function
    
    Private Function HexFormat(intNumber)
        HexFormat = Right("00000000" & CStr(Hex(intNumber)), 8)
    End Function
    
    Public Function GetKernelBugcheckInfo(ByRef strBugcheckCode, ByRef strFirstArgument, ByRef strSecondArgument, ByRef strThirdArgument, ByRef strFourthArgument)
        Dim arrOutput, x, intSpaceStart, intSpaceEnd
        GetKernelBugcheckInfo = False
        On Error Resume Next
        If GetRAWDebuggerOutput(".bugcheck", arrOutput) Then
            'First line is the bugcheck code
            If IsArray(arrOutput) Then
                If LCase(Left(arrOutput(0), 8)) = "bugcheck" Then
                    strBugcheckCode = Right(arrOutput(0), Len(arrOutput(0)) - InStrRev(arrOutput(0), " "))
                    intSpaceStart = InStr(1, arrOutput(1), " ")
                    intSpaceEnd = InStr(intSpaceStart + 1, arrOutput(1), " ")
                    strFirstArgument = Mid(arrOutput(1), intSpaceStart + 1, intSpaceEnd - intSpaceStart - 1)
                    intSpaceStart = intSpaceEnd
                    intSpaceEnd = InStr(intSpaceStart + 1, arrOutput(1), " ")
                    strSecondArgument = Mid(arrOutput(1), intSpaceStart + 1, intSpaceEnd - intSpaceStart - 1)
                    intSpaceStart = intSpaceEnd
                    intSpaceEnd = InStr(intSpaceStart + 1, arrOutput(1), " ")
                    strThirdArgument = Mid(arrOutput(1), intSpaceStart + 1, intSpaceEnd - intSpaceStart - 1)
                    intSpaceStart = intSpaceEnd
                    intSpaceEnd = Len(arrOutput(1)) + 1
                    strFourthArgument = Mid(arrOutput(1), intSpaceStart + 1, intSpaceEnd - intSpaceStart - 1)
                    If Err.Number = 0 Then GetKernelBugcheckInfo = True
                End If
            End If
        End If
    End Function
    
    Public Function GetTimeInfo(ByRef strSessionTime, ByRef strUptime)
        Dim arrOutput
        GetTimeInfo = False
        On Error Resume Next
        If GetRAWDebuggerOutput(".time", arrOutput) Then
            If LCase(Left(arrOutput(0), 5)) = "debug" Then
                strSessionTime = Right(arrOutput(0), Len(arrOutput(0)) - 20)
                strUptime = Right(arrOutput(1), Len(arrOutput(1)) - 15)
                GetTimeInfo = True
            End If
        End If
    End Function
    
    Public Function GetOSInfo(ByRef strOSDescription, ByRef strBuild)
        Dim arrOutput, strLine
        On Error Resume Next
        GetOSInfo = False
        strBuild = ""
        If GetRAWDebuggerOutput("vertarget", arrOutput) Then
            strOSDescription = arrOutput(0)
            For Each strLine In arrOutput
                If LCase(Left(LCase(strLine), 10)) = "built by: " Then
                    strBuild = Right(strLine, Len(strLine) - 10)
                End If
                GetOSInfo = True
            Next
        End If
    End Function
    
    Function GetLoadedModuleList(arrImageName, arrImagePath, arrTimeStamp, arrFileVersion, arrProductVersion, arrFileDescription, arrCompanyName, arrLegalCopyright, arrMemoryRange)
        
        Dim strImageName, strImagePath, strTimeStamp, strFileVersion, strProductVersion, strFileDescription, strCompanyName, strLegalCopyright, strMemoryRange
        
        Dim arrModuleList, arrOutput, strLine, x, intSepPosition, boolNextBinary, strModule
        
        On Error Resume Next
        GetLoadedModuleList = False
        If GetRAWDebuggerOutput("lm o1m", arrModuleList) Then
            For Each strModule In arrModuleList
                If GetRAWDebuggerOutput("lm vm " & strModule, arrOutput) Then
                    strImageName = ""
                    strImagePath = ""
                    strTimeStamp = ""
                    strFileVersion = ""
                    strProductVersion = ""
                    strFileDescription = ""
                    strCompanyName = ""
                    strLegalCopyright = ""
                    strMemoryRange = ""
                    For x = 0 To UBound(arrOutput)
                        strLine = arrOutput(x)
                        If x = 1 And Left(strLine, 1) <> " " Then
                            intSepPosition = InStr(1, strLine, " ")
                            intSepPosition = InStr(intSepPosition + 1, strLine, " ")
                            strMemoryRange = Left(strLine, intSepPosition - 1)
                        End If
                        
                        intSepPosition = InStr(1, strLine, "Image path: ", 1)
                        If intSepPosition > 0 Then strImagePath = Trim(Right(strLine, Len(strLine) - intSepPosition - 11))
                        intSepPosition = InStr(1, strLine, "Image name: ", 1)
                        If intSepPosition > 0 Then strImageName = Trim(Right(strLine, Len(strLine) - intSepPosition - 11))
                        intSepPosition = InStr(1, strLine, "Timestamp: ", 1)
                        If intSepPosition > 0 Then strTimeStamp = Trim(Right(strLine, Len(strLine) - intSepPosition - 11))
                        intSepPosition = InStr(1, strLine, "FileVersion:", 1)
                        If intSepPosition > 0 Then strFileVersion = Trim(Right(strLine, Len(strLine) - intSepPosition - 11))
                        intSepPosition = InStr(1, strLine, "ProductVersion:", 1)
                        If intSepPosition > 0 Then strProductVersion = Trim(Right(strLine, Len(strLine) - intSepPosition - 15))
                        intSepPosition = InStr(1, strLine, "FileDescription:", 1)
                        If intSepPosition > 0 Then
                            strFileDescription = Trim(Right(strLine, Len(strLine) - intSepPosition - 16))
                        End If
                        intSepPosition = InStr(1, strLine, "CompanyName:", 1)
                        If intSepPosition > 0 Then strCompanyName = Trim(Right(strLine, Len(strLine) - intSepPosition - 12))
                        intSepPosition = InStr(1, strLine, "LegalCopyright:", 1)
                        If intSepPosition > 0 Then strLegalCopyright = Trim(Right(strLine, Len(strLine) - intSepPosition - 15))
                    Next
                    
                    AddtoArray arrMemoryRange, strMemoryRange
                    AddtoArray arrImageName, strImageName
                    AddtoArray arrImagePath, strImagePath
                    AddtoArray arrTimeStamp, strTimeStamp
                    AddtoArray arrFileVersion, strFileVersion
                    AddtoArray arrProductVersion, strProductVersion
                    AddtoArray arrFileDescription, strFileDescription
                    AddtoArray arrCompanyName, strCompanyName
                    AddtoArray arrLegalCopyright, strLegalCopyright
                    
                End If
            Next
        End If
        GetLoadedModuleList = (UBound(arrImageName) > 0)
    End Function
    
    Function GetLastEvent(ByRef strLastEvent)
        Dim arrOutput, strLine
        On Error Resume Next
        GetLastEvent = False
        If GetRAWDebuggerOutput(".lastevent", arrOutput) Then
            For Each strLine In arrOutput
                If LCase(Left(LCase(strLine), 12)) = "last event: " Then
                    strLastEvent = Right(strLine, Len(strLine) - InStr(12, strLine, ":"))
                    GetLastEvent = True
                End If
            Next
        End If
    End Function
    
    Function GetUsermodeProcessInfo(strProcessPath, strProcessID)
        Dim arrOutput, strLine, intPos
        On Error Resume Next
        GetUsermodeProcessInfo = False
        If GetRAWDebuggerOutput("|", arrOutput) Then
            For Each strLine In arrOutput
                intPos = InStr(1, strLine, "id:", 1)
                If intPos > 0 Then
                    strProcessID = "0x" & Mid(strLine, intPos + 4, InStr(intPos, strLine, vbTab) - intPos - 4)
                    intPos = InStr(1, strLine, "name: ", 1)
                    If intPos > 0 Then
                        strProcessPath = Right(strLine, Len(strLine) - intPos - 5)
                        GetUsermodeProcessInfo = True
                    End If
                End If
            Next
        End If
        If Not GetUsermodeProcessInfo Then
            arrDiagInfo = arrOutput
        End If
    End Function
    
    Function GetEffectiveMachine(strEffMach)
        Dim arrOutput, strLine, intPos
        On Error Resume Next
        GetEffectiveMachine = False
        If GetRAWDebuggerOutput(".effmach", arrOutput) Then
            For Each strLine In arrOutput
                If LCase(Left(strLine, 18)) = "effective machine:" Then
                    strEffMach = Right(strLine, Len(strLine) - intPos - 19)
                    GetEffectiveMachine = True
                Else
                    arrDiagInfo = arrOutput
                End If
            Next
        End If
    End Function
    
    Function GetUsermodeExceptionModule(ByRef ExceptionModule)
        Dim arrOutput, strLine, x, intPos
        On Error Resume Next
        GetUsermodeExceptionModule = False
        If GetRAWDebuggerOutput("kn1", arrOutput) Then
            x = 0
            For Each strLine In arrOutput
                x = x + 1
                If x > 1 Then
                    If Left(strLine, 1) <> "*" And Left(strLine, 2) <> " #" Then
                        intPos = InStr(4, strLine, " ")
                        If intPos > 0 Then
                            intPos = InStr(intPos + 1, strLine, " ")
                            If intPos > 0 Then
                                ExceptionModule = Right(strLine, Len(strLine) - intPos)
                                GetUsermodeExceptionModule = True
                            End If
                        End If
                    End If
                End If
            Next
        End If
    End Function
    
    Function GetStackModules(arrStackModuleList)
        Dim arrOutput, intPos, strFrame, strLine
        On Error Resume Next
        GetStackModules = False
        If GetRAWDebuggerOutput("kn50", arrOutput) Then
            For Each strFrame In arrOutput
                If Left(strLine, 1) <> "*" And Left(strLine, 2) <> " #" Then
                    If Mid(strFrame, 2, 1) = " " Then
                        intPos = InStr(4, strLine, " ")
                        If intPos > 0 Then
                            intPos = InStr(intPos + 1, strLine, " ")
                            If intPos > 0 Then
                                AddtoArray Right(strLine, Len(strLine) - intPos), arrStackModuleList
                                GetStackModules = True
                            End If
                        End If
                    End If
                End If
            Next
        End If
    End Function

    
End Class

'' SIG '' Begin signature block
'' SIG '' MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' GeS6wwe9uyHbeHN5C+XyUYCt/jFMWYBpYtbmBJhtvJGg
'' SIG '' gg12MIIF9DCCA9ygAwIBAgITMwAAAsu3dTn7AnFCNgAA
'' SIG '' AAACyzANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJV
'' SIG '' UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
'' SIG '' UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
'' SIG '' cmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBT
'' SIG '' aWduaW5nIFBDQSAyMDExMB4XDTIyMDUxMjIwNDU1OVoX
'' SIG '' DTIzMDUxMTIwNDU1OVowdDELMAkGA1UEBhMCVVMxEzAR
'' SIG '' BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
'' SIG '' bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
'' SIG '' bjEeMBwGA1UEAxMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
'' SIG '' MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
'' SIG '' t7DdFnHRqRlz2SG+YjXxQdMWfK5yb2J8Q+lH9gR14JaW
'' SIG '' 0xH6Hvpjv/6C1pEcQMKaXYrbElTg9KIJSm7Z4fVqdgwE
'' SIG '' S3MWxmluGGpzlkgdS8i0aR550OTzpYdlOba4ON4EI75T
'' SIG '' WZUAd5S/s6z7WzbzAOxNFpJqPmemBZ7H+2npPihs2hm6
'' SIG '' AHhTuLimY0F2OUZjMxO9AcGs+4bwNOYw1EXUSh9Iv9ci
'' SIG '' vekw7j+yckRSzrwN1FzVs9NEfcO6aTA3DZV7a5mz4oL9
'' SIG '' 8RPRX6X5iUbYjmUCne9yu9lro5o+v0rt/gwU6TquzYHZ
'' SIG '' 7VtpSX1912uqHuBfT5PcUYZMB7JOybvRPwIDAQABo4IB
'' SIG '' czCCAW8wHwYDVR0lBBgwFgYKKwYBBAGCN0wIAQYIKwYB
'' SIG '' BQUHAwMwHQYDVR0OBBYEFK4P57f4I/gQS3dY2VmIaJO7
'' SIG '' +f8OMEUGA1UdEQQ+MDykOjA4MR4wHAYDVQQLExVNaWNy
'' SIG '' b3NvZnQgQ29ycG9yYXRpb24xFjAUBgNVBAUTDTIzMDAx
'' SIG '' Mis0NzA1MjgwHwYDVR0jBBgwFoAUSG5k5VAF04KqFzc3
'' SIG '' IrVtqMp1ApUwVAYDVR0fBE0wSzBJoEegRYZDaHR0cDov
'' SIG '' L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWlj
'' SIG '' Q29kU2lnUENBMjAxMV8yMDExLTA3LTA4LmNybDBhBggr
'' SIG '' BgEFBQcBAQRVMFMwUQYIKwYBBQUHMAKGRWh0dHA6Ly93
'' SIG '' d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWlj
'' SIG '' Q29kU2lnUENBMjAxMV8yMDExLTA3LTA4LmNydDAMBgNV
'' SIG '' HRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQCS+beq
'' SIG '' VYyEZUPI+HQBSWZzJHt60R3kAzjxcbMDOOx0b4EGthNY
'' SIG '' 3mtmmIjJNVpnalp2MNW2peCM0ZUlX+HM388dr4ziDomh
'' SIG '' pZVtgch5HygKZ4DsyZgEPBdecUhz0bzTJr6QtzxS7yjH
'' SIG '' 98uUsjycYfdtk06tKuXqSb9UoGQ1pVJRy/xMdZ1/JMwU
'' SIG '' YR73Og+heZWvqADuAN6P2QtOTjoJuBCcWT/TKlIuYond
'' SIG '' ncOCYPx77Q6QnC49RiyIQg2nmynoGowiZTIYcZw16xhS
'' SIG '' yX1/I+5Oy1L62Q7EJ4iWdw+uivt0mUy4b8Cu3TBlRblF
'' SIG '' CVHw4n65Qk4yhvZsbDw5ZX8nJOMxp0Wb/CcPUYBNcwII
'' SIG '' Z1NeC9L1VDTs4v+GxO8CLIkciHAnFaF0Z3gQN5/36y17
'' SIG '' 3Yw7G29paRru/PrNc2zuTdG4R1quI+VjLra7KQcRIaht
'' SIG '' j0gYwuWKYvo4bX7t/se+jZgb7Mirscffh5vwC55cysa+
'' SIG '' CsjEd/8+CETMwNUMqaTZOuVIvowdeIPsOL6JXt9zNaVa
'' SIG '' lXJK5knm1JJo5wrIQoh9diBYB2Re4EcBOGGaye0I8WXq
'' SIG '' Gah2irEC0TKeud23gXx33r2vcyT4QUnVXAlu8fatHNh1
'' SIG '' TyyR1/WAlFO9eCPqrS6Qxq3W2cQ/ZopD6i/06P9ZQ2dH
'' SIG '' IfBbXj4TBO4aLrqD3DCCB3owggVioAMCAQICCmEOkNIA
'' SIG '' AAAAAAMwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYT
'' SIG '' AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
'' SIG '' EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
'' SIG '' cG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290
'' SIG '' IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDExMB4XDTEx
'' SIG '' MDcwODIwNTkwOVoXDTI2MDcwODIxMDkwOVowfjELMAkG
'' SIG '' A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
'' SIG '' BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
'' SIG '' dCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9zb2Z0
'' SIG '' IENvZGUgU2lnbmluZyBQQ0EgMjAxMTCCAiIwDQYJKoZI
'' SIG '' hvcNAQEBBQADggIPADCCAgoCggIBAKvw+nIQHC6t2G6q
'' SIG '' ghBNNLrytlghn0IbKmvpWlCquAY4GgRJun/DDB7dN2vG
'' SIG '' EtgL8DjCmQawyDnVARQxQtOJDXlkh36UYCRsr55JnOlo
'' SIG '' XtLfm1OyCizDr9mpK656Ca/XllnKYBoF6WZ26DJSJhIv
'' SIG '' 56sIUM+zRLdd2MQuA3WraPPLbfM6XKEW9Ea64DhkrG5k
'' SIG '' NXimoGMPLdNAk/jj3gcN1Vx5pUkp5w2+oBN3vpQ97/vj
'' SIG '' K1oQH01WKKJ6cuASOrdJXtjt7UORg9l7snuGG9k+sYxd
'' SIG '' 6IlPhBryoS9Z5JA7La4zWMW3Pv4y07MDPbGyr5I4ftKd
'' SIG '' gCz1TlaRITUlwzluZH9TupwPrRkjhMv0ugOGjfdf8NBS
'' SIG '' v4yUh7zAIXQlXxgotswnKDglmDlKNs98sZKuHCOnqWbs
'' SIG '' YR9q4ShJnV+I4iVd0yFLPlLEtVc/JAPw0XpbL9Uj43Bd
'' SIG '' D1FGd7P4AOG8rAKCX9vAFbO9G9RVS+c5oQ/pI0m8GLhE
'' SIG '' fEXkwcNyeuBy5yTfv0aZxe/CHFfbg43sTUkwp6uO3+xb
'' SIG '' n6/83bBm4sGXgXvt1u1L50kppxMopqd9Z4DmimJ4X7Iv
'' SIG '' hNdXnFy/dygo8e1twyiPLI9AN0/B4YVEicQJTMXUpUMv
'' SIG '' dJX3bvh4IFgsE11glZo+TzOE2rCIF96eTvSWsLxGoGyY
'' SIG '' 0uDWiIwLAgMBAAGjggHtMIIB6TAQBgkrBgEEAYI3FQEE
'' SIG '' AwIBADAdBgNVHQ4EFgQUSG5k5VAF04KqFzc3IrVtqMp1
'' SIG '' ApUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYD
'' SIG '' VR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0j
'' SIG '' BBgwFoAUci06AjGQQ7kUBU7h6qfHMdEjiTQwWgYDVR0f
'' SIG '' BFMwUTBPoE2gS4ZJaHR0cDovL2NybC5taWNyb3NvZnQu
'' SIG '' Y29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0
'' SIG '' MjAxMV8yMDExXzAzXzIyLmNybDBeBggrBgEFBQcBAQRS
'' SIG '' MFAwTgYIKwYBBQUHMAKGQmh0dHA6Ly93d3cubWljcm9z
'' SIG '' b2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0MjAx
'' SIG '' MV8yMDExXzAzXzIyLmNydDCBnwYDVR0gBIGXMIGUMIGR
'' SIG '' BgkrBgEEAYI3LgMwgYMwPwYIKwYBBQUHAgEWM2h0dHA6
'' SIG '' Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvZG9jcy9w
'' SIG '' cmltYXJ5Y3BzLmh0bTBABggrBgEFBQcCAjA0HjIgHQBM
'' SIG '' AGUAZwBhAGwAXwBwAG8AbABpAGMAeQBfAHMAdABhAHQA
'' SIG '' ZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEA
'' SIG '' Z/KGpZjgVHkaLtPYdGcimwuWEeFjkplCln3SeQyQwWVf
'' SIG '' Liw++MNy0W2D/r4/6ArKO79HqaPzadtjvyI1pZddZYSQ
'' SIG '' fYtGUFXYDJJ80hpLHPM8QotS0LD9a+M+By4pm+Y9G6XU
'' SIG '' tR13lDni6WTJRD14eiPzE32mkHSDjfTLJgJGKsKKELuk
'' SIG '' qQUMm+1o+mgulaAqPyprWEljHwlpblqYluSD9MCP80Yr
'' SIG '' 3vw70L01724lruWvJ+3Q3fMOr5kol5hNDj0L8giJ1h/D
'' SIG '' Mhji8MUtzluetEk5CsYKwsatruWy2dsViFFFWDgycSca
'' SIG '' f7H0J/jeLDogaZiyWYlobm+nt3TDQAUGpgEqKD6CPxNN
'' SIG '' ZgvAs0314Y9/HG8VfUWnduVAKmWjw11SYobDHWM2l4bf
'' SIG '' 2vP48hahmifhzaWX0O5dY0HjWwechz4GdwbRBrF1HxS+
'' SIG '' YWG18NzGGwS+30HHDiju3mUv7Jf2oVyW2ADWoUa9WfOX
'' SIG '' pQlLSBCZgB/QACnFsZulP0V3HjXG0qKin3p6IvpIlR+r
'' SIG '' +0cjgPWe+L9rt0uX4ut1eBrs6jeZeRhL/9azI2h15q/6
'' SIG '' /IvrC4DqaTuv/DDtBEyO3991bWORPdGdVk5Pv4BXIqF4
'' SIG '' ETIheu9BCrE/+6jMpF3BoYibV3FWTkhFwELJm3ZbCoBI
'' SIG '' a/15n8G9bW1qyVJzEw16UM0xghl1MIIZcQIBATCBlTB+
'' SIG '' MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
'' SIG '' bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
'' SIG '' cm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNy
'' SIG '' b3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExAhMzAAAC
'' SIG '' y7d1OfsCcUI2AAAAAALLMA0GCWCGSAFlAwQCAQUAoIGw
'' SIG '' MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
'' SIG '' AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3
'' SIG '' DQEJBDEiBCAA0I0LaMC0PmyTCIST4+jU1BOJGdUfTr+4
'' SIG '' i+rS4gSCTjBEBgorBgEEAYI3AgEMMTYwNKAUgBIATQBp
'' SIG '' AGMAcgBvAHMAbwBmAHShHIAaaHR0cHM6Ly93d3cubWlj
'' SIG '' cm9zb2Z0LmNvbSAwDQYJKoZIhvcNAQEBBQAEggEAlNIG
'' SIG '' DrlQoIrkQszf2BDKswPNlMMEcUv8ZxsZhtiK+9pNuSd9
'' SIG '' OHzDcpkjIG2i8kwnoXnZmHwA0KwCnEUVIOCYORVRCfvv
'' SIG '' +90+cgBrCgBKON/cIWa17lPREkcvWjQVGl7zRdRYON+7
'' SIG '' dxQRme3zmFspA65kP2L7ZM8BWLUUmbwVaeiquYF8sRA9
'' SIG '' vLlQIwb6K5CO7HwGr7kgZPoZwvhYtJT+vsIK7a3uy+Mx
'' SIG '' l/HVJrvGodUxq8Gv+4v+YJ91NKOAHGM6zychmWkWQWbv
'' SIG '' Q/HuYdRHEFVLjlMifJSO23cDASHLwlxfAX2cMvBcJSfW
'' SIG '' MDoI/uvPkkMS7Dllad/WUTKOjnpYPKGCFv0wghb5Bgor
'' SIG '' BgEEAYI3AwMBMYIW6TCCFuUGCSqGSIb3DQEHAqCCFtYw
'' SIG '' ghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsqhkiG
'' SIG '' 9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoD
'' SIG '' ATAxMA0GCWCGSAFlAwQCAQUABCA7Lecm7P/Da52cVQNt
'' SIG '' WP2qqXbbVnr2IEJGwfEcZOF4jQIGYv2AdCOaGBMyMDIy
'' SIG '' MDgyNDA4MDAxMi42MDdaMASAAgH0oIHQpIHNMIHKMQsw
'' SIG '' CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
'' SIG '' MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
'' SIG '' b2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3Nv
'' SIG '' ZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1U
'' SIG '' aGFsZXMgVFNTIEVTTjoyMjY0LUUzM0UtNzgwQzElMCMG
'' SIG '' A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
'' SIG '' ZaCCEVQwggcMMIIE9KADAgECAhMzAAABmHazjMXQBaEB
'' SIG '' AAEAAAGYMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYT
'' SIG '' AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
'' SIG '' EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
'' SIG '' cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1l
'' SIG '' LVN0YW1wIFBDQSAyMDEwMB4XDTIxMTIwMjE5MDUxNVoX
'' SIG '' DTIzMDIyODE5MDUxNVowgcoxCzAJBgNVBAYTAlVTMRMw
'' SIG '' EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
'' SIG '' b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
'' SIG '' b24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9w
'' SIG '' ZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
'' SIG '' OjIyNjQtRTMzRS03ODBDMSUwIwYDVQQDExxNaWNyb3Nv
'' SIG '' ZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG
'' SIG '' 9w0BAQEFAAOCAg8AMIICCgKCAgEAxtSVrFZLKfMRuLCz
'' SIG '' J38X4rd0oSPuxtTH00/uV70M7gDnvK+TEQBSE05oxcc6
'' SIG '' CxX5msS7z1ZZg4JA4tK6rDrPQJfY1cGEhVRf8Fgtvge+
'' SIG '' jsrIskY8PjT4+QOHJjIT6iHTZESwhPsLbiP8Amqt/y3+
'' SIG '' JKAxrnSHBGEYDKqk6DjlCFeHuxHWG95Pa2Dze0rJcLCx
'' SIG '' Uqfhb5v0HMuSqn5JjF+Et6Ccex3YkISmytQumX4m/u+t
'' SIG '' W5q3Ty0+nnXZZ8sJbO4QqyCLhbYFG1I+iiSGZ9TG2GPI
'' SIG '' awDOfbby6XhphVtxo3gQJrwcQJ+6PS6dp8pE9cPSNLPX
'' SIG '' XcKRZ4y09jyu+Bg0rMRVGRtVLS8qYv5GXIPVnpzwGaVL
'' SIG '' TxXzuTLYn/CWvI11yyD+ivm+S4kFfKCMRUgX4BTe/0y9
'' SIG '' rUkn0FXL6l9ZnEjq8f7bIKty+mAMSOj5eIdc0K3AJk6M
'' SIG '' qRKD2DXP0ZUgZOpY5jcjQ7F94LSvKenOxwllIRfmIzIH
'' SIG '' 2p0JjI1GLG43RLAsi+kAKI2dH+pLXjeHFeqGxcHFBL4m
'' SIG '' MoFm3nWk/OjhnvSxDsT7oc4Bb9maG1a9CfIZdRVXXGRW
'' SIG '' 3xTf4HYx2f53Aw6izVoHKDKBIcMM6OxQDm6imsXwecwg
'' SIG '' amEo+OZojTuYN4T/AIAtHkgh5d6yuyTzK9QfvCUx7cEZ
'' SIG '' Eis//nMCAwEAAaOCATYwggEyMB0GA1UdDgQWBBRukYRy
'' SIG '' jabIN5oKJ7Oy0eWB083hNzAfBgNVHSMEGDAWgBSfpxVd
'' SIG '' AF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQ
'' SIG '' hk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
'' SIG '' L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
'' SIG '' JTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
'' SIG '' CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
'' SIG '' b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUt
'' SIG '' U3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMB
'' SIG '' Af8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqG
'' SIG '' SIb3DQEBCwUAA4ICAQAk+gehd94v/Pc104KkPC+gmDB8
'' SIG '' fQYmhzlfsJOdyTq4gs3mi42IEcrLCYZp5yfwnR2uao3E
'' SIG '' sL0abVqWST1SubMYTiI0QT4LP9/hEdL0vOyAPmhm3+zR
'' SIG '' ey2WZcVjzpf8hQYPamd7aThjqIUCJ0J+c6Vdt4VqKWje
'' SIG '' HOPYxiRyzwH8vbu/mUhkLsNeArFv10SxCx09fCOtFtLi
'' SIG '' jgWuT5tlYqITKL3G6TVAhBEaiDvVj8MyMDEUcN+Py4I7
'' SIG '' rJRyaKfv9VXvwn8jasHlJsHqUBya3fsEy1JYJuBDW1xe
'' SIG '' oudoxX2KREsC3QJ+eqP6Y/oK7Hdi6wBD0EcoePa1ryP6
'' SIG '' mXzobU9hVpsxcOiCb2ews09TvhXNICAwTamrLOUG5pDp
'' SIG '' CmMvVO5xQOqp92WfjK2TLCU4+4MQH9MjJFasGFmUZOG6
'' SIG '' 2PavCQz5nHzUo0a1X6WMsxFRKnphmp5sbww080tsJEgW
'' SIG '' t83DcDoGIVgU5iXS4MoliRnqso9ZuW8DYJzsOjc1wolT
'' SIG '' M3287XZKjnU0fPC7QCRjUY3r1o0HeV4rRrnoEqdpjCYJ
'' SIG '' Rc0cJJ3EGrtQSbAo/9Wg2OKDIjvHKJ5Jmlga2HtdUAkv
'' SIG '' Pev7GcEnZxFCWpNKqZwURQfkx0SMSIrwijW8RtkEWfHY
'' SIG '' feXDl4KNGLwTeWtafoid7zcM53lNgCAu8966yGzdnzCC
'' SIG '' B3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUw
'' SIG '' DQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMw
'' SIG '' EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
'' SIG '' b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
'' SIG '' b24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRp
'' SIG '' ZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4
'' SIG '' MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMC
'' SIG '' VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
'' SIG '' B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
'' SIG '' b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
'' SIG '' U3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUA
'' SIG '' A4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC
'' SIG '' 0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm
'' SIG '' 95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNE
'' SIG '' t6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZT
'' SIG '' fDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQ
'' SIG '' HJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5
'' SIG '' LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVV
'' SIG '' mG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKy
'' SIG '' zbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpG
'' SIG '' dc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2
'' SIG '' TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZ
'' SIG '' fD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1q
'' SIG '' GFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSL
'' SIG '' W6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLU
'' SIG '' HMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXb
'' SIG '' GjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQID
'' SIG '' AQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAj
'' SIG '' BgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8v
'' SIG '' BO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1Gely
'' SIG '' MFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYI
'' SIG '' KwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNv
'' SIG '' bS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNV
'' SIG '' HSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4K
'' SIG '' AFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/
'' SIG '' BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2U
'' SIG '' kFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8v
'' SIG '' Y3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0
'' SIG '' cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYI
'' SIG '' KwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8v
'' SIG '' d3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jv
'' SIG '' b0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0B
'' SIG '' AQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwU
'' SIG '' tj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTC
'' SIG '' j/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+
'' SIG '' iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhT
'' SIG '' dSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYS
'' SIG '' EhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qB
'' SIG '' woEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0
'' SIG '' DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxy
'' SIG '' bxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARx
'' SIG '' v2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+k
'' SIG '' KNxnGSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2
'' SIG '' tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4
'' SIG '' O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokL
'' SIG '' jzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTm
'' SIG '' dHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/Z
'' SIG '' cGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLLMIIC
'' SIG '' NAIBATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxEzAR
'' SIG '' BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
'' SIG '' bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
'' SIG '' bjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3Bl
'' SIG '' cmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046
'' SIG '' MjI2NC1FMzNFLTc4MEMxJTAjBgNVBAMTHE1pY3Jvc29m
'' SIG '' dCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
'' SIG '' GgMVAPMsHv4heTPHyFNmk+skN75z6VeToIGDMIGApH4w
'' SIG '' fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
'' SIG '' b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
'' SIG '' Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWlj
'' SIG '' cm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZI
'' SIG '' hvcNAQEFBQACBQDmr+fdMCIYDzIwMjIwODI0MDc1NzE3
'' SIG '' WhgPMjAyMjA4MjUwNzU3MTdaMHQwOgYKKwYBBAGEWQoE
'' SIG '' ATEsMCowCgIFAOav590CAQAwBwIBAAICDMAwBwIBAAIC
'' SIG '' EdEwCgIFAOaxOV0CAQAwNgYKKwYBBAGEWQoEAjEoMCYw
'' SIG '' DAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQAC
'' SIG '' AwGGoDANBgkqhkiG9w0BAQUFAAOBgQAyFEjgS7qkY7Ba
'' SIG '' L0MBnogmCZ3K/yxS2eknYAhF2WoyiQMCnYQgM7Fp1I9c
'' SIG '' 2bzTN995pkkZafLfWIB7KVmYzeOS73+c0++mxCf9wV9I
'' SIG '' A/7z6zofgw/yA9tBoOr2mNwp0A/pf1YEgd9/4vk5pDzj
'' SIG '' ilG1SryhrNd2L7J9wxEc/J+9XDGCBA0wggQJAgEBMIGT
'' SIG '' MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
'' SIG '' dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
'' SIG '' aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
'' SIG '' Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB
'' SIG '' mHazjMXQBaEBAAEAAAGYMA0GCWCGSAFlAwQCAQUAoIIB
'' SIG '' SjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJ
'' SIG '' KoZIhvcNAQkEMSIEIMXJUoY9r12elRo2CIgr9jeMZVD4
'' SIG '' u6OzsGc5O717ddIzMIH6BgsqhkiG9w0BCRACLzGB6jCB
'' SIG '' 5zCB5DCBvQQgv6bOBjk5//cDtTYRzPUH3tJaAd7JZMNR
'' SIG '' Rd6/m4dtVsQwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzET
'' SIG '' MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
'' SIG '' bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
'' SIG '' aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
'' SIG '' cCBQQ0EgMjAxMAITMwAAAZh2s4zF0AWhAQABAAABmDAi
'' SIG '' BCCLeTLpfwyQot/IlufNPlV+d5lOUYRvd+SxBPmMn38R
'' SIG '' sjANBgkqhkiG9w0BAQsFAASCAgBJKYMZN2k/aNLgyl+3
'' SIG '' UHZHCJSD10/ydjer2p0ZTUQkhw3DkLalagEUzLs4udqO
'' SIG '' 2+UrrB/RwuqJrKlGwpw9dApapucW1Fhe5oyw4BT/tnXh
'' SIG '' WeksjotViAzHDw5izvQhgWpor5uB+ZHi+Jur+tbxvZY+
'' SIG '' j58D0n7pE0y+z/R8113T+gDfiNvu1O8eDMrAycxOd5iv
'' SIG '' 276BkLINVh4hlGw1R3EzSv84odcUqJQmCAA/dTCQXTK4
'' SIG '' yGUKS78pQDjNnn0c/y3e3+tzGctmP4+NjbxZtRrlyELK
'' SIG '' 23l3P/6USWayvZiDNFlHf+Jt3OwhDpNUjAPzTO+F29vY
'' SIG '' lsAxjObQCUWpt1UfwzZV5nScyOKckt/kDlKpEBuzFXUj
'' SIG '' n7cRSpJIp+q7DptuxMe4Nx1MynmO2zBGLz7mKpFxafjP
'' SIG '' bMN4c6jfBnUCsCzzLtGiIu76zwieujY57U1zkZLcnZcQ
'' SIG '' DPhmlwkOAD9DNCc+Vi8ex0o91vzOG+CkhDBn6gZ9ZhWX
'' SIG '' p/Hsn2HEYxCteqwDuNvJTp+a3bE8203GM7tW2llMlz9u
'' SIG '' cDzWhbk3n4Pmk96t73PnuFB6Yd7OAXlmJzzdpUAa+KZD
'' SIG '' N7xvRxmEZHD7XB3PsO3brNzTX9iKk2OBC7SGhYC0R29l
'' SIG '' ZfVoj4oFSu16LtbiR8pCmtWIEfUlUvTwwhCBtByFng+c
'' SIG '' 6N6X6w==
'' SIG '' End signature block
