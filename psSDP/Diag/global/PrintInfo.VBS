'************************************************
'PrintInfo.VBS
'Version 3.2.11
'Date: 12-09-2009
'Author: Andre Teixeira - andret@microsoft.com
'************************************************

Option Explicit
Dim objShell
Dim objFSO
Dim objWMIService, objWMIReg
Dim objXMLFile
Dim UID
Dim objTXTFile, intCurrentTzBias
Dim arrAlertsXML, arrAlertsTXTType, arrAlertsTXTCategory, arrAlertsTXTMessage, arrAlertsTXTRecommendation
Dim intCountVer2Drivers, intCountOEMDrivers, intCountOEMPrintProcessors, intCountOEMPrintMonitors
Dim arrPrintMonitorNames, strComputerName
Dim bGenerateScriptedDiagXMLAlerts, arrScriptedDiagXML

Const adDBTimeStamp = 135
Const adVarChar = 200
Const LOCAL_PRINT_KEY = "SYSTEM\CurrentControlSet\Control\Print"
Const HKEY_LOCAL_MACHINE = &H80000002
Const DEFAULTDRIVERPATH = "%windir%\system32\spool\drivers"
Const DEFAULTSPOOLFOLDER = "%windir%\system32\spool\PRINTERS"
Const ERR_NOTFOUND = &H80070002

Const Fixed = 2, Removable = 1, ForReading = 1, ForWriting = 2
Const OpenFileMode = -2

Const ALERT_INFORMATION = 1
Const ALERT_WARNING = 2
Const ALERT_ERROR = 3

Main

Sub Main()
    
    On Error Resume Next
    
    wscript.Echo ""
    wscript.Echo "PrintInfo Script"
    wscript.Echo "Revision 3.2.11"
    wscript.Echo "2008/2009 Microsoft Corporation"
    wscript.Echo ""
   
    Set objShell = CreateObject("WScript.Shell")
    Set objFSO = CreateObject("Scripting.FileSystemObject")
    
    bGenerateScriptedDiagXMLAlerts = False
    If wscript.Arguments.Count > 0 Then
    	  If LCase(wscript.Arguments(0)) = "/generatescripteddiagxmlalerts" Then
            bGenerateScriptedDiagXMLAlerts = True
        End If
    End If
    
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

Function DoWork()
       
    Dim strTXTFile, strXMLFile
    
    On Error Resume Next
    intCurrentTzBias = ObtainTimeZoneBias
    Dim strBaseName
    UID = 0
    
    wscript.Echo ""
    Err.Clear
    
    OpenWMIService
    
    strComputerName = objShell.Environment("PROCESS").Item("COMPUTERNAME")
    
    strBaseName = strComputerName & "_PrintInfo"
    
    strTXTFile = strBaseName + ".TXT"
    
    wscript.Echo "Creating " & strTXTFile & "..."
    
    Set objTXTFile = objFSO.OpenTextFile(strTXTFile, ForWriting, True, OpenFileMode)
    
    strXMLFile = objFSO.GetAbsolutePathName(".") & "\" + strBaseName & _
                     ".XML"
    
    Set objXMLFile = objFSO.OpenTextFile(strXMLFile, ForWriting, True, OpenFileMode)
    
    If Err.Number <> 0 Then
        DisplayError "Creating " & strXMLFile, Err.Number, Err.Source, Err.Description
    Else
        objXMLFile.WriteLine "<?xml version='1.0' encoding='iso-8859-1'?>"
        objXMLFile.WriteLine "<Root>"
        
        DumpPrintInformation
        BuildAlerts
        
        WriteAlertsToXML
        
        objXMLFile.WriteLine "</Root>"
        objXMLFile.Close
        Set objXMLFile = Nothing
        
        CreateHTMFile
        
        If bGenerateScriptedDiagXMLAlerts Then WriteAlertsToScriptedDiagXML strBaseName
        
        wscript.Echo "Closing file : '" & strTXTFile & "'"
        objTXTFile.Close
        Set objTXTFile = Nothing
        
        WriteAlertsToTXT (strTXTFile)
        
    End If
    
End Function

Sub WriteAlertsToScriptedDiagXML(strBaseFileName)
    Dim strScriptedDiagXMLFileName, objScriptedDiagXMLFile, strLine

      
    If Not IsEmpty(arrScriptedDiagXML) Then
		    wscript.Echo "Writing ScriptedDiag Alerts..."
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
    If bGenerateScriptedDiagXMLAlerts Then
        
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
End Sub

Function RunScriptin64BitMode()
    On Error Resume Next
    Dim strCmdArguments
    Dim strStdOutFilename
    Dim objStdoutFile
    Dim strArguments, x
    If LCase(objFSO.GetExtensionName(wscript.ScriptFullName)) = "vbs" Then
        strStdOutFilename = objFSO.BuildPath(objFSO.GetSpecialFolder(2), objFSO.GetFileName(wscript.ScriptFullName) & ".log")
        strArguments = ""
        If wscript.Arguments.Count > 0 Then
            For x = 0 To wscript.Arguments.Count - 1
                strArguments = strArguments & " " & Chr(34) & wscript.Arguments(x) & Chr(34) & " "
            Next
        End If
        strCmdArguments = "/c " & objFSO.GetDriveName(wscript.ScriptFullName) & " & cd " & Chr(34) & objFSO.GetParentFolderName(wscript.ScriptFullName) & Chr(34) & " & cscript.exe " & Chr(34) & wscript.ScriptFullName & Chr(34) & strArguments & " > " & Chr(34) & strStdOutFilename & Chr(34)
        ProcessCreate ReplaceEnvVars("%windir%\System32\CMD.EXE"), strCmdArguments
        If objFSO.FileExists(strStdOutFilename) Then
            Set objStdoutFile = objFSO.OpenTextFile(strStdOutFilename, ForReading, False, OpenFileMode)
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


Sub BuildAlerts()
    Dim strStringToAdd, strPrintInfoReportURL
    strPrintInfoReportURL = "<a href=" & Chr(34) & "#" + strComputerName + "_PrintInfo.HTM" & Chr(34) & ">" + strComputerName + "_PrintInfo.HTM</a>"
    If intCountVer2Drivers > 0 Then
        strStringToAdd = iif(intCountVer2Drivers > 1, "s", "")
        AddXMLAlert ALERT_WARNING, "Version 2 drivers", "This machine has <b>" & CStr(intCountVer2Drivers) & "</b> version 2 print driver" & strStringToAdd & ". Please click <a href=" & Chr(34) & "#Version-2" & Chr(34) & ">here</a> for a list of version 2 drivers.", "" & _
                "Version 2 drivers are very old drivers designed for Windows NT 4.0 and not recommended to install on newest operating systems. Please work with driver manufacturer to update these drivers or remove these drivers from machine. Alternatively, replace these drivers with inbox similar drivers. For more information about version 2 drivers please consult the following <a target='_blank' href='http://technet.microsoft.com/en-us/library/cc784266.aspx'>technet article</a>.", 1000
        AddTXTAlert ALERT_WARNING, "Version 2 drivers", "This machine has " & CStr(intCountVer2Drivers) & " version 2 print driver" & strStringToAdd & ".", "" & _
                "Version 2 drivers are very old drivers designed for Windows NT 4.0 and not recommended to install on newest operating systems. Please work with driver manufacturer to update these drivers or remove these drivers from machine. Alternatively, replace these drivers with inbox similar drivers. For more information about version 2 drivers please consult the following technet article: http://technet.microsoft.com/en-us/library/cc784266.aspx."
        AddScriptedDiagAlert ALERT_WARNING, "Version 2 Drivers", "This machine has <b>" & CStr(intCountVer2Drivers) & "</b> version 2 print driver" & strStringToAdd & ". Please open the file " + strPrintInfoReportURL + " for a list of version 2 drivers.", "" & _
                "Version 2 drivers are very old drivers designed for Windows NT 4.0 and not recommended to install on newest operating systems. Please work with driver manufacturer to update these drivers or remove these drivers from machine. Alternatively, replace these drivers with inbox similar drivers. For more information about version 2 drivers please consult the following <a target='_blank' href='http://technet.microsoft.com/en-us/library/cc784266.aspx'>technet article</a>.", 1000
    End If
    CheckAndAlertPostSPUpgrade
    If (intCountOEMDrivers > 0) Or (intCountOEMPrintMonitors > 0) Or (intCountOEMPrintProcessors > 0) Then
        If (intCountOEMDrivers > 0) Then
            strStringToAdd = iif(intCountOEMDrivers > 1, "s", "")
            AddXMLAlert ALERT_INFORMATION, "OEM Print Drivers", "This machine has <b>" & CStr(intCountOEMDrivers) & "</b> third party print driver" & strStringToAdd & ".", "" & _
                    "Please click <a href=" & Chr(34) & "#PrintersByProvider" & Chr(34) & ">here</a> for a list of 3rd party drivers.", 100
            AddTXTAlert ALERT_INFORMATION, "OEM Print Drivers", "This machine has " & CStr(intCountOEMDrivers) & " third party print driver" & strStringToAdd & ".", "" & _
                    "Please check this report for a list of 3rd party drivers. Check the HTML report for a summary of 3rd party print drivers."
            AddScriptedDiagAlert ALERT_INFORMATION, "OEM Print Drivers", "This machine has " & CStr(intCountOEMDrivers) & " third party print driver" & strStringToAdd & ".", "" & _
                    "Please check " + strPrintInfoReportURL + " report for a list of 3rd party drivers.", 100
        End If
        If (intCountOEMPrintMonitors > 0) Then
            strStringToAdd = iif(intCountOEMPrintMonitors > 1, "s", "")
            AddXMLAlert ALERT_INFORMATION, "OEM Print Monitors", "This machine has <b>" & CStr(intCountOEMPrintMonitors) & "</b> third party print monitor" & strStringToAdd & ".", "" & _
                    "Please click <a href=" & Chr(34) & "#PrintMonitorsByProvider" & Chr(34) & ">here</a> for a list of third party print monitors.", 200
            AddTXTAlert ALERT_INFORMATION, "OEM Print Monitors", "This machine has " & CStr(intCountOEMPrintMonitors) & " third party print monitor" & strStringToAdd & ".", "" & _
                    "Please check this report for a list of third party print monitors. Check the HTML report for a summary of printers using these third party print monitors."
            AddScriptedDiagAlert ALERT_INFORMATION, "OEM Print Monitors", "This machine has <b>" & CStr(intCountOEMPrintMonitors) & "</b> third party print monitor" & strStringToAdd & ".", "" & _
                    "Please please open " + strPrintInfoReportURL + " for a list of third party print monitors.", 200
        End If
        If (intCountOEMPrintProcessors > 0) Then
            strStringToAdd = iif(intCountOEMPrintProcessors > 1, "s", "")
            AddXMLAlert ALERT_INFORMATION, "OEM Print Processors", "This machine has <b>" & CStr(intCountOEMPrintProcessors) & "</b> third party print processor" & strStringToAdd & ".", "" & _
                    "Please click <a href=" & Chr(34) & "#PrintProcessorsByProvider" & Chr(34) & ">here</a> for a list of third party processors.", 150
            AddTXTAlert ALERT_INFORMATION, "OEM Print Processors", "This machine has " & CStr(intCountOEMPrintProcessors) & " third party print processor" & strStringToAdd & ".", "" & _
                    "Please check this report for a list of third party print processors. Check the HTML report for a summary of printers using these third party print processors."
            AddScriptedDiagAlert ALERT_INFORMATION, "OEM Print Processors", "This machine has <b>" & CStr(intCountOEMPrintProcessors) & "</b> third party print processor" & strStringToAdd & ".", "" & _
                    "Please open the file " + strPrintInfoReportURL + " for a list of third party processors.", 150
        End If
    Else
        AddXMLAlert ALERT_INFORMATION, "General", "This machine does not have any third party print driver, print monitor or print processor.", "" & _
                "", 1000
        AddTXTAlert ALERT_INFORMATION, "General", "This machine does not have any third party print driver, print monitor or print processor.", "" & _
                ""
    End If
End Sub

Function IsVistaOrNewer()
    IsVistaOrNewer = (CInt(Left(objShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentVersion"), 1)) >= 6)
End Function

Sub DisplayError(strErrorLocation, errNumber, errSource, errDescription)
    On Error Resume Next
    wscript.Echo ""
    If errNumber <> 0 Then
        wscript.Echo "Error 0x" & HexFormat(errNumber) & iif(Len(strErrorLocation) > 0, ": " & strErrorLocation, "")
        wscript.Echo errSource & " - " & errDescription
    Else
        wscript.Echo "An error ocurred!. " & iif(Len(strErrorLocation) > 0, ": " & strErrorLocation, "")
    End If
    wscript.Echo ""
End Sub

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

Sub OpenTag(strTag)
    objXMLFile.WriteLine "<" & strTag & ">"
End Sub

Sub CloseTag(strTag)
    objXMLFile.WriteLine "</" & strTag & ">"
End Sub

Function ObtainTimeZoneBias()
    ' Obtain local Time Zone bias from machine registry.
    On Error Resume Next
    Err.Clear
    
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
    
    If Err.Number = 0 Then
        ObtainTimeZoneBias = lngBias
    Else
        DisplayError "Calculating timezone bias. ActiveBias:" & CStr(lngBiasKey), Err.Number, Err.Source, Err.Description
        ObtainTimeZoneBias = 0
    End If

    
End Function

Sub DumpPrintInformation()
    On Error Resume Next
    
    LineOut "Print Information from : ", objShell.Environment("PROCESS").Item("COMPUTERNAME"), False, False, True, "Title"
    LineOut "Local time : ", CStr(Now), False, False, True, "TimeField"
    
    Dim colItems, objitem, strPrintName, objSubItem, arrEnv, strClusterName, strResourceName
    Dim strVersion, strModifiedDate, strManufacturer, strDescription, arrDriverKeys, strDriverKey
    
    OpenTag "PrinterLocation"
    Rem First session: Local printers
    
    LineOut "", "", True, False, False, ""
    LineOut "Location : ", "Local Print Spooler", False, False, False, "LocationName"
    LineOut "--------------------------------------------------", "", True, False, False, ""
    LineOut "", "", True, False, False, ""
    
    arrDriverKeys = GetDriversSubkeyNames(HKEY_LOCAL_MACHINE, LOCAL_PRINT_KEY)
        
    OpenTag "Resource"
        
    If Not IsEmpty(arrDriverKeys) Then
        ListLocationDetails HKEY_LOCAL_MACHINE, LOCAL_PRINT_KEY, arrDriverKeys
        LineOut "", "", True, False, False, ""
        ListDriversInfoForPrintResource HKEY_LOCAL_MACHINE, LOCAL_PRINT_KEY, ReplaceEnvVars(DEFAULTDRIVERPATH), ""
    Else
        LineOut "Information: ", "No local print drivers installed.", False, False, False, "LocationDetailsMsg"
        LineOut "", "", True, False, True, ""
    End If

    ListPrintProcessors HKEY_LOCAL_MACHINE, LOCAL_PRINT_KEY, ReplaceEnvVars(DEFAULTDRIVERPATH)
    ListPrintMonitors HKEY_LOCAL_MACHINE, LOCAL_PRINT_KEY, ReplaceEnvVars(DEFAULTDRIVERPATH)

    CloseTag "Resource"
    
    CloseTag "PrinterLocation"

    Rem Second session: Clustered printers
    strClusterName = GetRegValue(HKEY_LOCAL_MACHINE, "Cluster", "ClusterName")

    If Len(strClusterName) > 0 Then
    
        OpenTag "PrinterLocation"
    
        Dim arrSpoolerResources, strSpoolerResourceKey, strClusterNetworkName, strClusterDriverFolder
        LineOut "", "", True, False, True, ""
        LineOut "Location : ", strClusterName & " cluster", False, False, False, "LocationName"
        LineOut "--------------------------------------------------", "", True, False, False, ""
        LineOut "", "", True, False, False, ""
        
        arrSpoolerResources = GetSpoolerResourcesKeyNames(HKEY_LOCAL_MACHINE, "Cluster\Resources")

        If Not IsEmpty(arrSpoolerResources) Then
            For Each strSpoolerResourceKey In arrSpoolerResources
                strClusterNetworkName = FindNetworkNameforSpoolerResource(HKEY_LOCAL_MACHINE, strSpoolerResourceKey)
                strResourceName = GetRegValue(HKEY_LOCAL_MACHINE, strSpoolerResourceKey, "Name")
                OpenTag "Resource"
                LineOut "", "", True, False, False, ""
                LineOut "Resource name       : ", strResourceName, True, False, False, "Name"
                LineOut "Resource name       : ", strClusterNetworkName & " (" & strResourceName & ")", False, True, True, "Name"
                LineOut "Cluster network name: ", strClusterNetworkName, False, False, False, "Details"
                LineOut "----------------------------------------", "", True, False, False, ""
                
                strClusterDriverFolder = FindDriversFolderforSpoolerResource(HKEY_LOCAL_MACHINE, strSpoolerResourceKey, strClusterNetworkName)
                arrDriverKeys = GetDriversSubkeyNames(HKEY_LOCAL_MACHINE, strSpoolerResourceKey & "\Parameters")
                If Not IsEmpty(arrDriverKeys) Then
                    ListLocationDetails HKEY_LOCAL_MACHINE, strSpoolerResourceKey & "\Parameters", arrDriverKeys
                    LineOut "", "", True, False, True, ""
                    ListDriversInfoForPrintResource HKEY_LOCAL_MACHINE, strSpoolerResourceKey & "\Parameters", strClusterDriverFolder, strClusterNetworkName & " (" & strResourceName & ")"
                    'ListDriverProperties HKEY_LOCAL_MACHINE, strSpoolerResourceKey & "\Parameters", strClusterDriverFolder, arrDriverKeys, strClusterNetworkName & " (" & strResourceName & ")"
                Else
                    LineOut "Information: ", "No print drivers installed on Print Spooler resource " & strClusterNetworkName & " (" & strResourceName & ")", False, False, False, "LocationDetailsMsg"
                    LineOut "", "", True, False, False, ""
                End If
                
                ListPrintProcessors HKEY_LOCAL_MACHINE, strSpoolerResourceKey & "\Parameters", strClusterDriverFolder
                LineOut "", "", True, False, False, ""
                ListPrintMonitors HKEY_LOCAL_MACHINE, strSpoolerResourceKey & "\Parameters", strClusterDriverFolder
                LineOut "", "", True, False, False, ""
                
                CloseTag "Resource"
            Next
        Else
            LineOut "Information: ", "No Print Spooler resources detected on cluster " & strClusterName & ".", False, False, False, "LocationDetailsMsg"
        End If
        
        CloseTag "PrinterLocation"
    End If
    
End Sub

Sub CheckAndAlertPostSPUpgrade()
    'Check the existance of PostSPUpgrade and PendingUpgrades key.
    'Once detected, test the existance of old .bud files on drivers folders.
    'Alert if any issue is found. Reference: KB 832219
    
    On Error Resume Next
    
    Dim intOldestBUDFileAge, bolClusterUpgradeExists, arrClusterUpgrade, arrPostSPUpgrade, strAgeDesciption
    Const ClusterUpgradePrintKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Cluster\ClusterUpgrade"
    
    wscript.Echo ""
    wscript.Echo "Checking PostUpgrade and ClusterUpgrade registry keys..."
    
    objWMIReg.EnumValues HKEY_LOCAL_MACHINE, ClusterUpgradePrintKey, arrClusterUpgrade 'We don't need to know the resources.
    objWMIReg.EnumValues HKEY_LOCAL_MACHINE, LOCAL_PRINT_KEY & "\PostSPUpgrade", arrPostSPUpgrade 'We don't need to know the resources.
   
    If (Not IsNull(arrClusterUpgrade)) Or (Not IsNull(arrPostSPUpgrade)) Then
        intOldestBUDFileAge = 0
        wscript.Echo "PostUpgrade or ClusterUpgrade found. Checking for .BUD files..."
        If CheckForOldestBudFiles(ReplaceEnvVars(DEFAULTDRIVERPATH), intOldestBUDFileAge) Then
            If intOldestBUDFileAge > 0 Then
                ' > 1 hour BUD file exists. Issue alert.
                strAgeDesciption = GetAgeDescription(DateAdd("h", intOldestBUDFileAge * -1, Now))
                AddXMLAlert ALERT_WARNING, "PostUpgrade/ ClusterUpgrade registry keys", "The registry key HKLM\" & iif(IsEmpty(arrClusterUpgrade), LOCAL_PRINT_KEY & "\PostSPUpgrade", ClusterUpgradePrintKey) & " exists on this machine and and there are binary printer description files (.bud files) on spooler folder from <b>" & strAgeDesciption & "</b> ago. This may be affecting the print spooler performance on this machine.", "" & _
                    "This key is usually created after a service pack, hotfix installation or a driver upgrade. For more information about the issue, please consult the article <a target='_blank' href='http://support.microsoft.com/default.aspx?scid=kb;EN-US;832219'>KB 832219</a>.", 2000
                AddTXTAlert ALERT_WARNING, "PostUpgrade/ ClusterUpgrade registry keys", "The registry key HKLM\" & iif(IsEmpty(arrClusterUpgrade), LOCAL_PRINT_KEY & "\PostSPUpgrade", ClusterUpgradePrintKey) & " exists on this machine and and there are binary printer description files (.bud files) on spooler folder from " & strAgeDesciption & " ago. This may be affecting the server performance.", "" & _
                    "This key is usually created after a service pack, hotfix installation or a driver upgrade. For more information about the issue, please consult the article KB 832219"
            End If
        End If
        Else
            wscript.Echo "PostUpgrade and ClusterUpgrade registry keys not found."
    End If
    wscript.Echo ""
End Sub

Function GetAgeDescription(datDateTime)
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

Function CheckForOldestBudFiles(ByVal strSpoolDriverPath, ByRef intOldestFile)
    'This function checks the existance of *.bud files on subfolder of spooler folder
    'Once it found, it calculate the date of the OLDEST file and return the age (in days) to intOldestBUDFileAge
    Dim arrSubFolders, strSubFolder, intBUDFilesCount, intFileAgeinHours, strFile
    
    For Each strFile In objFSO.GetFolder(strSpoolDriverPath).Files
        If LCase(objFSO.GetExtensionName(strFile)) = "bud" Then
            intBUDFilesCount = intBUDFilesCount + 1
            intFileAgeinHours = DateDiff("h", objFSO.GetFile(strFile).DateLastModified, Now)
            If intFileAgeinHours > intOldestFile Then
                intOldestFile = intFileAgeinHours
            End If
        End If
    Next
    
    Set arrSubFolders = objFSO.GetFolder(strSpoolDriverPath).SubFolders
    For Each strSubFolder In arrSubFolders
        CheckForOldestBudFiles = CheckForOldestBudFiles(strSubFolder, intOldestFile)
    Next
    
    CheckForOldestBudFiles = (intOldestFile > 0)
        
End Function

Sub ListLocationDetails(HIVE, strPrintKey, arrDriverResource)
    On Error Resume Next
    Dim strSpoolFolder
    If (Not IsEmpty(arrDriverResource)) And (Not IsNull(arrDriverResource)) Then
        LineOut "   Number of drivers       : ", CStr(UBound(arrDriverResource) + 1), False, False, False, "LocationDetails"
    Else
        LineOut "   Number of drivers       : ", "0", False, False, False, "LocationDetails"
    End If
    LineOut "   Number of printers      : ", CStr(GetNumberOfPrinters(HIVE, strPrintKey)), False, False, False, "LocationDetails"
    strSpoolFolder = GetSpoolFolder(HIVE, strPrintKey)
    LineOut "   Spool folder            : ", strSpoolFolder, False, False, False, "LocationDetails"
    If objFSO.FolderExists(strSpoolFolder) Then
        LineOut "   Files on spooler folder : ", CStr(objFSO.GetFolder(strSpoolFolder).Files.Count), False, False, False, "LocationDetails"
    End If
End Sub

Function GetNumberOfPrinters(HIVE, strPrintKey)
    On Error Resume Next
    Dim arrPrinters
    objWMIReg.EnumKey HIVE, strPrintKey & "\Printers", arrPrinters
    If (IsEmpty(arrPrinters)) Or (IsNull(arrPrinters)) Then
        GetNumberOfPrinters = 0
    Else
        GetNumberOfPrinters = UBound(arrPrinters) + 1
    End If
End Function

Function GetSpoolFolder(HIVE, strPrintKey)
    On Error Resume Next
    GetSpoolFolder = GetRegValue(HIVE, strPrintKey & "\Printers", "DefaultSpoolDirectory")
    If IsNull(GetSpoolFolder) Then
        GetSpoolFolder = DEFAULTSPOOLFOLDER
    End If
    GetSpoolFolder = ReplaceEnvVars(GetSpoolFolder)
End Function


Function GetRegValue(ByVal HIVE, ByVal strRegKey, strValue)
    On Error Resume Next
    Dim varRegValue
    If HIVE = HKEY_LOCAL_MACHINE Then
        strRegKey = "HKLM\" & strRegKey
    End If
    varRegValue = objShell.RegRead(strRegKey & "\" & strValue)
    
    If Err.Number = ERR_NOTFOUND Then
        varRegValue = Null
    Else
        If IsNull(varRegValue) Then
            varRegValue = "(Unknown)"
        End If
    End If
    GetRegValue = varRegValue
End Function

Function GenerateUniqueBookmark()
    UID = UID + 1
    GenerateUniqueBookmark = CStr(UID)
End Function

Function FindNetworkNameforSpoolerResource(HIVE, strSpoolerResourceKey)
    'Check the dependences to know the network name for the resource
    On Error Resume Next
    Err.Clear
    Dim arrDependsOn, strResourceKeyName, strResourceType
    
    arrDependsOn = GetRegValue(HIVE, strSpoolerResourceKey, "DependsOn")
    
    If Not IsNull(arrDependsOn) Then 'DependsOn key does not exist. It may be Windows 2008 Cluster
        For Each strResourceKeyName In arrDependsOn
            strResourceType = GetRegValue(HIVE, "Cluster\Resources\" & strResourceKeyName, "Type")
            If LCase(strResourceType) = "network name" Then
                FindNetworkNameforSpoolerResource = GetRegValue(HIVE, "Cluster\Resources\" & strResourceKeyName, "Parameters\Name")
                Exit Function
            End If
        Next
    Else
        Dim arrAllClusterGroups, arrGroupContains, strClusterGroupKey, strResourceGUID
        
        objWMIReg.EnumKey HIVE, "Cluster\Groups", arrAllClusterGroups
        
        If Not IsNull(arrAllClusterGroups) Then
            For Each strClusterGroupKey In arrAllClusterGroups
                arrGroupContains = GetRegValue(HIVE, "Cluster\Groups\" & strClusterGroupKey, "Contains")
                
                If IsArray(arrGroupContains) Then
                    For Each strResourceGUID In arrGroupContains
                        If LCase("Cluster\Resources\" & strResourceGUID) = LCase(strSpoolerResourceKey) Then
                            FindNetworkNameforSpoolerResource = GetRegValue(HIVE, "Cluster\Groups\" & strClusterGroupKey, "Name")
                            Exit Function
                        End If
                    Next
                End If
            Next
            arrDependsOn = GetRegValue(HIVE, "Cluster\Groups", "DependsOn")
        Else
            FindNetworkNameforSpoolerResource = ""
        End If
    
    End If
    
    If Err.Number <> 0 Then
        DisplayError "Obtaining Dependencies of Spooler Cluster resouce. Key:" & strSpoolerResourceKey, Err.Number, Err.Source, Err.Description
    End If
    
    FindNetworkNameforSpoolerResource = ""
    
End Function

Function GetSpoolerResourcesKeyNames(HIVE, strResourcesKey)

    On Error Resume Next
    Err.Clear

    Dim arrAllResources, strResourceKey, strResourceType, strResourceKeyName, arrSpoolResourcesKey
    objWMIReg.EnumKey HIVE, strResourcesKey, arrAllResources
    
    For Each strResourceKeyName In arrAllResources
        strResourceKey = strResourcesKey & "\" & strResourceKeyName
        strResourceType = GetRegValue(HIVE, strResourceKey, "Type")
        If LCase(strResourceType) = "print spooler" Then
            AddtoArray arrSpoolResourcesKey, strResourceKey
        End If
    Next
    
    GetSpoolerResourcesKeyNames = arrSpoolResourcesKey
    
    If Err.Number <> 0 Then
        DisplayError "Obtaining Print Spooler Resource registry key names. Resources Key:" & strResourcesKey & " Resource: " & strResourceKey, Err.Number, Err.Source, Err.Description
    End If
    
End Function

Function FindDriversFolderforSpoolerResource(HIVE, strSpoolerResourceKey, ResourcerNetworkName)
    'We need to know the driver location. We first try to access locally.
    'If it fails we try to find the network location for these drivers
    On Error Resume Next
    Dim strLocalDiskPrintDrivers
    strLocalDiskPrintDrivers = GetRegValue(HIVE, strSpoolerResourceKey & "\Parameters", "ClusterDriverDirectory")
    If objFSO.FolderExists(strLocalDiskPrintDrivers) Then
        FindDriversFolderforSpoolerResource = strLocalDiskPrintDrivers
    Else
        LineOut "Warning: ", "Unable to access " & strLocalDiskPrintDrivers & " folder. Resource may not be active on this node.", False, False, False, "LocationDetailsMsg"
        If objFSO.FolderExists("\\" & ResourcerNetworkName & "\print$") Then
            FindDriversFolderforSpoolerResource = "\\" & ResourcerNetworkName & "\print$\" & _
                                                Right(strSpoolerResourceKey, Len(strSpoolerResourceKey) - InStrRev(strSpoolerResourceKey, "\")) & _
                                                "\Drivers"
        Else
            LineOut "Error: ", "Unable to list information for print drivers files: Share \\" & ResourcerNetworkName & "\print$ not found - the resource may be offline.", False, False, False, "LocationDetailsMsg"
            FindDriversFolderforSpoolerResource = ""
        End If
        LineOut "", "", True, False, False, ""
    End If
End Function

Sub BuildDriverProviderType(ByVal strProvider, ByVal strDriverName, ByRef strProviderType, ByRef strProviderCompany)
    On Error Resume Next
    
    'I classify three type of drivers:
    '   Inbox       - Builtin Microsoft Drivers
    '   Out of Box  - Microsoft Drivers not inbox, such as Microsoft Office or XPS
    '   OEM         - Non Microsoft Drivers
    '     To identify Out of Box driver, I see if the driver name contains 'Microsoft'
    If (LCase(strProvider) = "microsoft") Then
        strProviderType = "Inbox"
        strProviderCompany = "Microsoft"
    ElseIf Len(strProvider) = 0 Then
        If InStr(1, strDriverName, "microsoft", vbTextCompare) > 0 Then
            strProviderType = "Out-Of-Box"
            strProviderCompany = "Microsoft"
        ElseIf InStr(1, strDriverName, "Services Easy Print", vbTextCompare) > 0 Then
            strProviderType = "Inbox"
            strProviderCompany = "Microsoft"
        Else
            strProviderType = "OEM"
            strProviderCompany = "(Not Defined)"
            intCountOEMDrivers = intCountOEMDrivers + 1
        End If
    ElseIf InStr(1, strProvider, "microsoft", vbTextCompare) > 0 Then
        'a few drivers has 'Microsoft Windows 2000' string in the provider registry value
        'in this case, I am considering as OEM - Unknown Provider
        If (InStr(1, strDriverName, "Services Easy Print", vbTextCompare) > 0) Or (InStr(1, strDriverName, "Desktop Easy Print", vbTextCompare) > 0) Or (InStr(1, strProvider, "Terminal Services", vbTextCompare) > 0) Then
            strProviderType = "Inbox"
            strProviderCompany = "Microsoft"
        Else
            strProviderType = "OEM"
            strProviderCompany = "(Unknown)"
            intCountOEMDrivers = intCountOEMDrivers + 1
        End If
    Else
        strProviderType = "OEM"
        strProviderCompany = strProvider
        intCountOEMDrivers = intCountOEMDrivers + 1
    End If
End Sub

Sub BuildPrintMonitorProviderType(ByVal strDLLCompanyName, ByVal strMonitorName, ByRef strDLLCompanyNameType, ByRef strDLLCompanyNameCompany)
    'I classify three type of Monitor:
    '   Inbox       - Builtin Microsoft Print Monitors
    '   Out of Box  - Microsoft Monitors not inbox, such as Microsoft Office Live Meeting 2007 Document Writer Monitor
    '   OEM         - Non Microsoft Drivers
    '     To identify Out of Box driver, I see if the driver name contains 'Microsoft'
    
    On Error Resume Next
    
    Select Case LCase(strMonitorName)
        Case "bj language monitor", "local port", "lpr port", "pjl language monitor", "standard tcp/ip port", "usb monitor", "appletalk printing devices", "windows nt fax", "wsd port", "microsoft shared fax monitor"
            strDLLCompanyNameType = "Inbox"
            strDLLCompanyNameCompany = "Microsoft"
        Case Else
            If InStr(1, strDLLCompanyName, "microsoft", vbTextCompare) > 0 Then
                strDLLCompanyNameType = "Out-Of-Box"
                strDLLCompanyNameCompany = "Microsoft"
            Else
                strDLLCompanyNameType = "OEM"
                If Len(strDLLCompanyName) > 0 Then
                    strDLLCompanyNameCompany = strDLLCompanyName
                Else
                    strDLLCompanyNameCompany = "(Unknown)"
                End If
                If Not PrintMonitorAlreadyCatalogued(strMonitorName) Then
                    intCountOEMPrintMonitors = intCountOEMPrintMonitors + 1
                End If
            End If
    End Select
End Sub

Function PrintMonitorAlreadyCatalogued(strMonitorNametoCheck)
    Dim strPrintMonitorName
    If Not IsEmpty(arrPrintMonitorNames) Then
        For Each strPrintMonitorName In arrPrintMonitorNames
            If UCase(strMonitorNametoCheck) = UCase(strPrintMonitorName) Then
                PrintMonitorAlreadyCatalogued = True
                Exit Function
            End If
        Next
    End If
    AddtoArray arrPrintMonitorNames, strMonitorNametoCheck
    PrintMonitorAlreadyCatalogued = False
End Function

Sub BuildPrintProcessorProviderType(ByVal strDLLCompanyName, ByVal strProcessorName, ByRef strDLLCompanyNameType, ByRef strDLLCompanyNameCompany)
    'I classify three type of Processors:
    '   Inbox       - Builtin Microsoft Print Processors
    '   Out of Box  - Microsoft Processors not inbox, such as MS_XPS
    '   OEM         - Non Microsoft
    '     To identify Out of Box Processor, see if the driver name contains 'Microsoft'
    On Error Resume Next
    
    Select Case LCase(strProcessorName)
        Case "winprint"
            strDLLCompanyNameType = "Inbox"
            strDLLCompanyNameCompany = "Microsoft"
        Case Else
            If InStr(1, strDLLCompanyName, "microsoft", vbTextCompare) > 0 Then
                strDLLCompanyNameType = "Out-Of-Box"
                strDLLCompanyNameCompany = "Microsoft"
            Else
                strDLLCompanyNameType = "OEM"
                If Len(strDLLCompanyName) > 0 Then
                    strDLLCompanyNameCompany = strDLLCompanyName
                Else
                    strDLLCompanyNameCompany = "(Unknown)"
                End If
                intCountOEMPrintProcessors = intCountOEMPrintProcessors + 1
            End If
    End Select
End Sub


Function ListDriverProperties(HIVE, strPrintKey, strDriversPath, arrDriverKeys, strClusterResouceName)

    Dim objitem, varVersion, strProvider, strProviderType, strProviderCompany, strVersion, strPrintName, strModifiedDate, strManufacturer, strDescription
    Dim strDriverKey, strPlatform, strPrintMonitor, strDriverDll, strConfigDll, strDataFile
    Dim strDriverName, strOEMUrl, strRegKey
    Dim strDependentFile, arrDependentFiles, strDependentFilePath, bolFirstDependentFile

    On Error Resume Next
    Err.Clear

    OpenTag "Drivers"

    For Each strDriverKey In arrDriverKeys
        OpenTag "Driver"
            LineOut Space(9) & "***************************************************", "", True, False, True, ""
            LineOut "Bookmark", "Driver" & GenerateUniqueBookmark, False, True, True, "Bookmark"
            strDriverName = Right(strDriverKey, Len(strDriverKey) - InStrRev(strDriverKey, "\"))
            LineOut Space(9) & "Driver name  : ", strDriverName, False, False, False, "DriverName"
            strPlatform = GetPlatform(strPrintKey, strDriverKey)
            LineOut Space(9) & "Platform     : ", strPlatform, False, False, True, "Item"
            varVersion = GetRegValue(HIVE, strDriverKey, "Version")
            Select Case varVersion
                Case 2
                  strVersion = "2 - Windows NT 4.0"
                Case 3
                  strVersion = "3 - Windows 2000 or newer"
                Case Else
                  strVersion = varVersion + " - (Unknown)"
            End Select
            LineOut Space(9) & "Version      : ", strVersion, False, False, True, "Item"
            strProvider = GetRegValue(HIVE, strDriverKey, "Provider")
            BuildDriverProviderType strProvider, strDriverName, strProviderType, strProviderCompany
            
            LineOut Space(9) & "Type         : ", strProviderType, False, False, True, "Item"
            LineOut Space(9) & "Provider     : ", strProviderCompany, False, False, True, "Item"
            
            strRegKey = strDriverKey
            If HIVE = HKEY_LOCAL_MACHINE Then
                strRegKey = "HKLM\" & strDriverKey
            End If
            
            LineOut Space(9) & "Registry Key : ", strRegKey, False, False, True, "Item"

            strPrintMonitor = GetRegValue(HIVE, strDriverKey, "Monitor")

            If (strPrintMonitor <> "(Unknown)") And (Len(strPrintMonitor) > 0) Then
                LineOut Space(9) & "Print Monitor: ", strPrintMonitor, False, False, True, "Item"
            Else
                LineOut Space(9) & "Print Monitor: ", "(Not found)", False, False, True, "Item"
            End If
            
            If Len(strClusterResouceName) > 0 Then
                LineOut Space(9) & "Cluster Resource: ", strClusterResouceName, False, False, True, "Item"
            End If

           strDriverDll = BuildSpoolDLLPath(strDriverKey, strDriversPath, varVersion, strPlatform, GetRegValue(HIVE, strDriverKey, "Driver"))
           OpenTag "File"
           LineOut Space(9) & "Driver DLL   : ", strDriverDll, False, False, True, "FilePath"
           If Len(strDriversPath) > 0 Then ListFileInfo strDriverDll, 29, False
           CloseTag "File"
           
           strConfigDll = BuildSpoolDLLPath(strDriverKey, strDriversPath, varVersion, strPlatform, GetRegValue(HIVE, strDriverKey, "Configuration File"))
           OpenTag "File"
           LineOut Space(9) & "ConfigFile   : ", strConfigDll, False, False, True, "FilePath"
           If Len(strDriversPath) > 0 Then ListFileInfo strConfigDll, 29, False
           CloseTag "File"
           
           strDataFile = BuildSpoolDLLPath(strDriverKey, strDriversPath, varVersion, strPlatform, GetRegValue(HIVE, strDriverKey, "Data File"))
           OpenTag "File"
           LineOut Space(9) & "DataFile     : ", strDataFile, False, False, True, "FilePath"
           If Len(strDriversPath) > 0 Then ListFileInfo strDataFile, 29, False
           CloseTag "File"
           
           arrDependentFiles = GetRegValue(HIVE, strDriverKey, "Dependent Files")
           bolFirstDependentFile = True
           For Each strDependentFile In arrDependentFiles
                strDependentFilePath = BuildSpoolDLLPath(strDriverKey, strDriversPath, varVersion, strPlatform, strDependentFile)
                OpenTag "File"
                If bolFirstDependentFile Then
                    LineOut Space(9) & "Dependencies : ", strDependentFilePath, True, False, True, "FilePath"
                    bolFirstDependentFile = False
                Else
                    LineOut Space(9) & "               ", strDependentFilePath, True, False, True, "FilePath"
                End If
                LineOut Space(9) & "Dependent: ", strDependentFilePath, False, True, True, "FilePath"
                If Len(strDriversPath) > 0 Then ListFileInfo strDependentFilePath, 30, False
                CloseTag "File"
           Next
           
            strOEMUrl = GetRegValue(HIVE, strDriverKey, "Monitor")

            If strPrintMonitor = "(Unknown)" Then
                LineOut Space(9) & "OEM URL     : ", strOEMUrl, False, False, True, "Item"
            End If
            
            OpenTag "Printers"
            LineOut "", "", True, False, True, """"
            LineOut Space(12) & "Printers", "", False, False, True, "Title"
            LineOut Space(12) & "--------", "", True, False, True, """"
           
            ListPrinters HIVE, strPrintKey, strDriverName, True
            CloseTag "Printers"
            
            If varVersion = 2 Then
                intCountVer2Drivers = intCountVer2Drivers + 1
            End If
            
        CloseTag "Driver"
    Next 'For Each strDriverKey In arrDriverKeys
    
    CloseTag "Drivers"
    
End Function

Sub ListPrinters(HIVE, strPrintKey, strDriverName, bolDisplayMSGWhenMissing)
    Dim arrPrinters, strPrinterKey, strShareName
    
    On Error Resume Next
    Err.Clear
    arrPrinters = GetPrintersRegKeys(HIVE, strPrintKey, strDriverName)
    
    If IsArray(arrPrinters) Then
        For Each strPrinterKey In arrPrinters
            OpenTag "Printer"
              LineOut "", "", True, False, True, ""
              LineOut Space(12) & " -- Printer name    : ", GetRegValue(HIVE, strPrinterKey, "Name"), False, False, False, "SessionTitle"
              LineOut Space(12) & "    Driver Name     : ", GetRegValue(HIVE, strPrinterKey, "Printer Driver"), False, False, True, "Item"
              LineOut Space(12) & "    Server          : ", GetRegValue(HIVE, strPrinterKey, "DsSpooler\serverName"), False, False, True, "Item"
              strShareName = GetRegValue(HIVE, strPrinterKey, "Share Name")
              If (strShareName <> "(Unknown)") And (Len(strShareName) > 0) Then
                LineOut Space(12) & "    Share           : ", strShareName, False, False, True, "Item"
              Else
                LineOut Space(12) & "    Share           : ", "(Not shared)", False, False, True, "Item"
              End If
              LineOut Space(12) & "    Port            : ", GetRegValue(HIVE, strPrinterKey, "Port"), False, False, True, "Item"
              LineOut Space(12) & "    Data Type       : ", GetRegValue(HIVE, strPrinterKey, "Datatype"), False, False, True, "Item"
              LineOut Space(12) & "    Print Processor : ", GetRegValue(HIVE, strPrinterKey, "Print Processor"), False, False, True, "Item"
              LineOut "Bookmark", "Printer" & GenerateUniqueBookmark, False, True, True, "Bookmark"
              LineOut "", "", False, False, True, ""
            CloseTag "Printer"
        Next
    ElseIf bolDisplayMSGWhenMissing Then
        OpenTag "Printer"
        LineOut Space(12) & " -- Information    : ", "   - No printers created for " & strDriverName, False, False, True, "SessionTitle"
        LineOut "", "", True, False, True, ""
        CloseTag "Printer"
    End If
    
    If Err.Number <> 0 Then
        DisplayError "Listing Printers for driver:" & strDriverName & " Print Key: " & strPrintKey, Err.Number, Err.Source, Err.Description
    End If

End Sub

Function BuildSpoolDLLPath(strPrinterRegKey, strPrintDriversPath, intVersion, strPlat, strDLLName)

    On Error Resume Next
    
    If Len(strPrintDriversPath) > 0 Then

        Dim strPlatFolder, strDLLPath
        
        Select Case LCase(strPlat)
            Case "windows nt x86"
                strPlatFolder = "W32X86"
            Case "windows ia64"
                strPlatFolder = "IA64"
            Case "windows x64"
                strPlatFolder = "x64"
        End Select
        strDLLPath = objFSO.BuildPath(strPrintDriversPath, strPlatFolder & "\" & CStr(intVersion) & "\" & strDLLName)
        If objFSO.FileExists(strDLLPath) Then
            BuildSpoolDLLPath = strDLLPath
        Else
            BuildSpoolDLLPath = "(" & strDLLName & ")"
        End If
    Else
        BuildSpoolDLLPath = "(" & strDLLName & ")"
    End If
    
End Function

Function BuildPrintProcessorDLLPath(strPrintSpoolPath, strPlat, strDLLName)
    On Error Resume Next
    Err.Clear
    
    If Len(strPrintSpoolPath) > 0 Then

        Dim strPlatFolder, strDLLPath
        
        strDLLPath = objFSO.BuildPath(objFSO.GetSpecialFolder(1), strDLLName) 'Dll is in System32 folder
        If objFSO.FileExists(strDLLPath) Then
            BuildPrintProcessorDLLPath = strDLLPath
        Else
            Select Case LCase(strPlat)
                Case "windows nt x86"
                    strPlatFolder = "W32X86"
                Case "windows ia64"
                    strPlatFolder = "IA64"
                Case "windows x64"
                    strPlatFolder = "x64"
            End Select
            
            strDLLPath = objFSO.BuildPath(strPrintSpoolPath, "..\prtprocs\" & strPlatFolder & "\" & strDLLName)
            If objFSO.FileExists(strDLLPath) Then
                BuildPrintProcessorDLLPath = objFSO.GetFile(strDLLPath).Path
            Else
                    strDLLPath = objFSO.BuildPath(strPrintSpoolPath, strPlatFolder & "\prtprocs\" & strDLLName)
                    If objFSO.FileExists(strDLLPath) Then
                        BuildPrintProcessorDLLPath = objFSO.GetFile(strDLLPath).Path
                    Else
                    BuildPrintProcessorDLLPath = ""
                End If
            End If
        End If
    Else
        BuildPrintProcessorDLLPath = ""
    End If
        
    If Err.Number <> 0 Then
        DisplayError "Obtaining the path for DLL for print processor:" & strDLLName & " Print Spooler path: " & strPrintSpoolPath, Err.Number, Err.Source, Err.Description
    End If

    
End Function

Function FindPrintMonitorFullPath(strDLLName, strDriversPath)

    Dim strDLLPath
    On Error Resume Next
    
    If InStr(1, strDLLName, "\") <> 0 Then
        'We have the full path of DLL
        FindPrintMonitorFullPath = strDLLName
    Else
        'DLL may be in System32 folder
        strDLLPath = objFSO.BuildPath(objFSO.GetSpecialFolder(1), strDLLName)
        If objFSO.FileExists(strDLLPath) Then
            FindPrintMonitorFullPath = strDLLPath
        Else
            strDLLPath = objFSO.BuildPath(strDriversPath, strDLLName)
            If objFSO.FileExists(strDLLPath) Then
                FindPrintMonitorFullPath = strDLLPath
            Else
                FindPrintMonitorFullPath = ""
            End If
        End If
    End If
    
End Function


Function GetPrintersRegKeys(HIVE, strPrintKey, strDriverName)
    On Error Resume Next
    Err.Clear
    Dim arrAllPrinters, strPrinterKey, arrPrintersKey, strPrinterDriver, strPrinterKeyName
    objWMIReg.EnumKey HIVE, strPrintKey & "\Printers", arrAllPrinters
    If Not IsNull(arrAllPrinters) Then
        For Each strPrinterKeyName In arrAllPrinters
            strPrinterKey = strPrintKey & "\Printers\" & strPrinterKeyName
            strPrinterDriver = GetRegValue(HIVE, strPrinterKey, "Printer Driver")
            If LCase(strPrinterDriver) = LCase(strDriverName) Then
                AddtoArray arrPrintersKey, strPrinterKey
            End If
        Next
        GetPrintersRegKeys = arrPrintersKey
    Else
        GetPrintersRegKeys = Null
    End If
    
    If Err.Number <> 0 Then
        DisplayError "Obtaining the registry path for printers for the following driver:" & strDriverName & " Printer key: " & strPrintKey, Err.Number, Err.Source, Err.Description
    End If
End Function

Function GetPlatform(strPrintKey, strDriverKey)
    On Error Resume Next
    Dim intEnvStart
    intEnvStart = Len(strPrintKey + "\Environments\")
    GetPlatform = Mid(strDriverKey, intEnvStart + 1, InStr(intEnvStart + 1, strDriverKey, "\") - intEnvStart - 1)
End Function

Function GetDriversSubkeyNames(HIVE, strPrintKey)
    On Error Resume Next
    Err.Clear
    Dim arrEnvironment, strEnvironment
    Dim arrDriverVersions, strDriverVersion
    Dim arrDriverNames, arrDriverKeyNames, y
    objWMIReg.EnumKey HIVE, strPrintKey & "\Environments", arrEnvironment
    For Each strEnvironment In arrEnvironment
        objWMIReg.EnumKey HIVE, strPrintKey & "\Environments\" & strEnvironment & "\Drivers", arrDriverVersions
        If IsArray(arrDriverVersions) Then
            For Each strDriverVersion In arrDriverVersions
                objWMIReg.EnumKey HIVE, strPrintKey & "\Environments\" & strEnvironment & "\Drivers\" & strDriverVersion, arrDriverNames
                
                If IsArray(arrDriverNames) Then
                    For y = 0 To UBound(arrDriverNames)
                        arrDriverNames(y) = strPrintKey & "\Environments\" & strEnvironment & "\Drivers\" & strDriverVersion & "\" & arrDriverNames(y)
                    Next
                    AddtoArray arrDriverKeyNames, arrDriverNames
                End If
            Next 'arrDriversVersion
        End If
    Next 'arrEnvironment
    GetDriversSubkeyNames = arrDriverKeyNames
    
    If Err.Number <> 0 Then
        DisplayError "Obtaining the subkey names for driver. Printer key: " & strPrintKey, Err.Number, Err.Source, Err.Description
    End If

End Function

Function DriverstoThisEnvironmentExist(HIVE, strEnvironmentKey)
    'Returns true if any driver for an specific environment exists
    Dim arrDriverVersions, strDriverVersion, arrDriverNames
    DriverstoThisEnvironmentExist = False
    objWMIReg.EnumKey HIVE, strEnvironmentKey & "\Drivers", arrDriverVersions
    If IsArray(arrDriverVersions) Then
        For Each strDriverVersion In arrDriverVersions
            objWMIReg.EnumKey HIVE, strEnvironmentKey & "\Drivers\" & strDriverVersion, arrDriverNames
            If IsArray(arrDriverNames) Then
                DriverstoThisEnvironmentExist = True
                Exit Function
            Else
                DriverstoThisEnvironmentExist = False
            End If
        Next
    Else
        DriverstoThisEnvironmentExist = False
    End If
End Function

Function DriverstoThisVersionExist(HIVE, strVersionKey)
    'Returns true if any driver for an specific environment exists
    Dim arrDriverNames
    DriverstoThisVersionExist = False
    objWMIReg.EnumKey HIVE, strVersionKey, arrDriverNames
    If IsArray(arrDriverNames) Then
        DriverstoThisVersionExist = True
    Else
        DriverstoThisVersionExist = False
    End If
End Function


Function ListDriversInfoForPrintResource(HIVE, strPrintKey, strFSDriversPath, strClusterResourceDisplayName)
    
    On Error Resume Next
        Err.Clear
        Dim arrEnvironment, strEnvironment
        Dim arrDriverVersions, strDriverVersion
        Dim arrDriverNames, arrDriverKeyNames, y
        objWMIReg.EnumKey HIVE, strPrintKey & "\Environments", arrEnvironment
        For Each strEnvironment In arrEnvironment
            If DriverstoThisEnvironmentExist(HIVE, strPrintKey & "\Environments\" & strEnvironment) Then
                OpenTag "Environment"
                LineOut "   Platform  : ", strEnvironment, False, False, False, "EnvironmentName"
                LineOut "   ------------", String(Len(strEnvironment), "-"), True, False, True, ""
                objWMIReg.EnumKey HIVE, strPrintKey & "\Environments\" & strEnvironment & "\Drivers", arrDriverVersions
                If IsArray(arrDriverVersions) Then
                    For Each strDriverVersion In arrDriverVersions
                        If DriverstoThisVersionExist(HIVE, strPrintKey & "\Environments\" & strEnvironment & "\Drivers\" & strDriverVersion) Then
                            OpenTag "Version"
                            LineOut "      Version  : ", strDriverVersion, False, False, False, "VersionName"
                            LineOut "      -----------", String(Len(strDriverVersion), "-"), True, False, True, ""

                            objWMIReg.EnumKey HIVE, strPrintKey & "\Environments\" & strEnvironment & "\Drivers\" & strDriverVersion, arrDriverNames
                            
                            If IsArray(arrDriverNames) Then
                                For y = 0 To UBound(arrDriverNames)
                                    arrDriverNames(y) = strPrintKey & "\Environments\" & strEnvironment & "\Drivers\" & strDriverVersion & "\" & arrDriverNames(y)
                                Next
                            End If
                            
                            If Not IsEmpty(arrDriverNames) Then
                                LineOut "", "", True, False, True, ""
                                ListDriverProperties HIVE, strPrintKey, strFSDriversPath, arrDriverNames, strClusterResourceDisplayName
                            End If
                            CloseTag "Version"
                        End If
                    Next 'arrDriversVersion
                End If
                CloseTag "Environment"
                End If
        Next 'arrEnvironment
    
    If Err.Number <> 0 Then
        DisplayError "Obtaining the subkey names for driver. Printer key: " & strPrintKey, Err.Number, Err.Source, Err.Description
    End If

End Function

Function GetPrintProcessorSubkeyNames(HIVE, strPrintKey, arrPrintProcessorsKeyNames, arrArch)
    Dim arrEnvironment, strEnvironment
    Dim arrDriverVersions, arrPrintProcessorsKey, strPrintProcessor
    Dim arrDriverNames, y
    
    On Error Resume Next
    Err.Clear
    
    objWMIReg.EnumKey HIVE, strPrintKey & "\Environments", arrEnvironment
    For Each strEnvironment In arrEnvironment
        objWMIReg.EnumKey HIVE, strPrintKey & "\Environments\" & strEnvironment & "\Print Processors", arrPrintProcessorsKey
        If IsArray(arrPrintProcessorsKey) Then
            For Each strPrintProcessor In arrPrintProcessorsKey
                AddtoArray arrArch, strEnvironment
                AddtoArray arrPrintProcessorsKeyNames, strPrintKey & "\Environments\" & strEnvironment & "\Print Processors\" & strPrintProcessor
            Next 'arrDriversVersion
        End If
    Next 'arrEnvironment
    GetPrintProcessorSubkeyNames = arrPrintProcessorsKeyNames
    
    If Err.Number <> 0 Then
        DisplayError "Obtaining Print processor registry key names. Print Key: " & strPrintKey & ". Processor: " & strPrintProcessor, Err.Number, Err.Source, Err.Description
    End If

    
End Function

Function ReplaceEnvVars(strString)
    Dim intFirstPercentPos, intSecondPercentPos
    Dim strEnvVar
    
    On Error Resume Next
    intFirstPercentPos = InStr(1, strString, "%")
    
    While intFirstPercentPos > 0
        intSecondPercentPos = InStr(intFirstPercentPos + 1, strString, "%")
        strEnvVar = Mid(strString, intFirstPercentPos + 1, intSecondPercentPos - intFirstPercentPos - 1)
        strString = Replace(strString, "%" & strEnvVar & "%", objShell.Environment("PROCESS").Item(strEnvVar))
        intFirstPercentPos = InStr(1, strString, "%")
    Wend
    ReplaceEnvVars = strString
End Function

Function AddtoArray(arrSourceArray, arrArrayToAdd)
    On Error Resume Next
    Dim y, varFirstMember
    
    If IsEmpty(arrSourceArray) Then
        If Not IsArray(arrArrayToAdd) Then
            ReDim arrSourceArray(0)
            arrSourceArray(0) = arrArrayToAdd
        Else
            arrSourceArray = arrArrayToAdd
        End If
    Else
        If Not IsArray(arrSourceArray) Then
            varFirstMember = arrSourceArray
            ReDim arrSourceArray(0)
            arrSourceArray(0) = varFirstMember
        End If
        If Not IsEmpty(arrArrayToAdd) Then
            If IsArray(arrArrayToAdd) Then
                For y = 0 To UBound(arrArrayToAdd)
                    ReDim Preserve arrSourceArray(UBound(arrSourceArray) + 1)
                    arrSourceArray(UBound(arrSourceArray)) = arrArrayToAdd(y)
                Next
            Else
                ReDim Preserve arrSourceArray(UBound(arrSourceArray) + 1)
                arrSourceArray(UBound(arrSourceArray)) = arrArrayToAdd
            End If
        End If
    End If
    AddtoArray = arrSourceArray
End Function

Sub AddXMLAlert(intAlertType, strAlertCategory, strAlertMessage, strAlertRecommendation, intPriority)
    
    Dim strAlertType, strAlertXML
    
    Select Case intAlertType
        Case ALERT_INFORMATION
            strAlertType = "Information"
        Case ALERT_WARNING
            strAlertType = "Warning"
        Case ALERT_ERROR
            strAlertType = "Error"
    End Select
    
    strAlertXML = "<AlertType>" & strAlertType & "</AlertType>" & _
                  "<AlertCategory>" & strAlertCategory & "</AlertCategory>" & _
                  "<AlertMessage><!" & Chr(91) & "CDATA" & Chr(91) & strAlertMessage & Chr(93) & Chr(93) & "></AlertMessage>" & _
                  iif(Len(strAlertRecommendation) > 0, "<AlertRecommendation><!" & Chr(91) & "CDATA" & Chr(91) & strAlertRecommendation & Chr(93) & Chr(93) & "></AlertRecommendation>", "") & _
                  "<AlertPriority>" & CStr(intPriority) & "</AlertPriority>"
                  
    AddtoArray arrAlertsXML, strAlertXML
    
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
    ' On Error Resume Next
    'Alerts in txt file needs to be in top of file
    Dim strTempTXTFilePath, objTempTXTFile, x, strAlertType
    Dim objOutputTXTFile
    
    If Not IsEmpty(arrAlertsTXTType) Then
    
        strTempTXTFilePath = objFSO.BuildPath(objFSO.GetSpecialFolder(2), "_PrintInfo.TXT")
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
            If Len(arrAlertsTXTRecommendation(x)) > 0 Then
                objTempTXTFile.WriteLine "     Recommendation:"
                objTempTXTFile.WriteLine "     ---------------"
                objTempTXTFile.WriteLine "     " & arrAlertsTXTRecommendation(x)
                objTempTXTFile.WriteLine ""
            End If
        Next
        
        objTempTXTFile.WriteLine "***************************************************"
        
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

Sub ListPrintProcessors(HIVE, strSpoolerKey, strDriversPath)
    
    On Error Resume Next
    Err.Clear
    
    Dim arrSubKeys, strDLLName, strDLLFullPath, x, strProcessorName
    Dim arrPrintProcessorsKeyNames, arrPrintProcessorsArch, strRegKey
    Dim ClsVI, VI, strProcessorDLLCompanyName, strProcessorType, strProcessorCompany
    
    wscript.Echo ""
    LineOut "************************************************", "", True, False, True, ""
    LineOut "Print Processors", "", True, False, False, ""
    LineOut "================", "", True, False, False, ""
    LineOut "", "", True, False, False, ""
    
    OpenTag ("PrintProcessors")
    
    GetPrintProcessorSubkeyNames HKEY_LOCAL_MACHINE, strSpoolerKey, arrPrintProcessorsKeyNames, arrPrintProcessorsArch
    
    If IsArray(arrPrintProcessorsKeyNames) Then
        For x = 0 To UBound(arrPrintProcessorsKeyNames)
            strProcessorType = ""
            strProcessorCompany = ""
            strProcessorDLLCompanyName = ""
            
            OpenTag ("PrintProcessor")

            strDLLName = GetRegValue(HIVE, arrPrintProcessorsKeyNames(x), "Driver")
            strProcessorName = Right(arrPrintProcessorsKeyNames(x), Len(arrPrintProcessorsKeyNames(x)) - InStrRev(arrPrintProcessorsKeyNames(x), "\"))
            LineOut " -- " & strProcessorName, "", False, False, False, "ProcessorName"
            LineOut "Bookmark", "Processor" & GenerateUniqueBookmark, False, True, True, "Bookmark"
            LineOut "    " & String(Len(strProcessorName), "-"), "", True, False, True, ""
            strDLLFullPath = BuildPrintProcessorDLLPath(strDriversPath, arrPrintProcessorsArch(x), strDLLName)
            
            If objFSO.FileExists(strDLLFullPath) Then
                
                Set ClsVI = New CVersionInfo
                Set VI = ClsVI.GetFileVersionInfo(strDLLFullPath)
                
                Select Case VI.State
                    Case 0
                        strProcessorDLLCompanyName = VI.Value("CompanyName")
                    Case Else
                        strProcessorDLLCompanyName = ""
                End Select
            End If
            
            BuildPrintProcessorProviderType strProcessorDLLCompanyName, strProcessorName, strProcessorType, strProcessorCompany
            
            LineOut "    Type         : ", strProcessorType, False, False, True, "Item"
            LineOut "    Provider     : ", strProcessorCompany, False, False, True, "Item"
            
            If Len(strDLLFullPath) <> 0 Then
                LineOut "    Processor DLL: ", strDLLFullPath, False, False, True, "Item"
                ListFileInfo strDLLFullPath, 4, True
            Else
                LineOut "    Processor DLL: ", strDLLName, False, False, True, "Item"
            End If
            strRegKey = arrPrintProcessorsKeyNames(x)
            
            If HIVE = HKEY_LOCAL_MACHINE Then
                strRegKey = "HKLM\" & arrPrintProcessorsKeyNames(x)
            End If
            LineOut "    Registry Key : ", strRegKey, False, False, True, "Item"
            
            'LineOut "    Registry key : ", "HKLM\" & arrPrintProcessorsKeyNames(x), False, False, True, "Item"
            LineOut "", "", True, False, True, ""
            CloseTag ("PrintProcessor")
        Next
    Else
        LineOut "    -- There are no print processors configured on this resource.", "", True, False, False, """"
    End If
    CloseTag ("PrintProcessors")
    
    If Err.Number <> 0 Then
        DisplayError "Listing print processors. Spooler key: " & strSpoolerKey & ". Drivers path: " & strDriversPath & ". Last processor name: " & strProcessorName & ". Last DLL: " & strDLLName, Err.Number, Err.Source, Err.Description
    End If
    
End Sub


Sub ListPrintMonitors(HIVE, strPrinterKey, strDriversPath)
    
    On Error Resume Next
    Err.Clear
    
    Dim arrSubKeys, strSubkey, strDLLName, strDLLFullPath, strRegKey
    Dim ClsVI, VI, strMonitorDLLCompanyName, strMonitorType, strMonitorCompany
    
    wscript.Echo ""
    LineOut "************************************************", "", True, False, True, ""
    LineOut "Print Monitors", "", True, False, False, ""
    LineOut "==============", "", True, False, False, ""
    LineOut "", "", True, False, False, ""
    
    OpenTag ("PrintMonitors")
    objWMIReg.EnumKey HIVE, strPrinterKey & "\Monitors", arrSubKeys
     
    For Each strSubkey In arrSubKeys
        OpenTag ("PrintMonitor")
        strMonitorType = ""
        strMonitorCompany = ""
        strMonitorDLLCompanyName = ""

        strDLLName = GetRegValue(HIVE, strPrinterKey & "\Monitors\" & strSubkey, "Driver")
        LineOut " -- " & strSubkey, "", False, False, False, "MonitorName"
        LineOut "Bookmark", "Monitor" & GenerateUniqueBookmark, False, True, True, "Bookmark"
        LineOut "    " & String(Len(strSubkey), "-"), "", True, False, True, ""
        strDLLFullPath = FindPrintMonitorFullPath(strDLLName, strDriversPath)
        
        If objFSO.FileExists(strDLLFullPath) Then
            
            Set ClsVI = New CVersionInfo
            Set VI = ClsVI.GetFileVersionInfo(strDLLFullPath)
            
            Select Case VI.State
                Case 0
                    strMonitorDLLCompanyName = VI.Value("CompanyName")
                Case Else
                    strMonitorDLLCompanyName = ""
            End Select
        End If
        
        BuildPrintMonitorProviderType strMonitorDLLCompanyName, strSubkey, strMonitorType, strMonitorCompany
        
        LineOut "    Type         : ", strMonitorType, False, False, True, "Item"
        LineOut "    Provider     : ", strMonitorCompany, False, False, True, "Item"

        If Len(strDLLFullPath) <> 0 Then
            LineOut "    Monitor DLL  : ", strDLLFullPath, False, False, True, "Item"
        Else
            LineOut "    Monitor DLL  : ", strDLLName, False, False, True, "Item"
        End If
        
        If Len(strDLLFullPath) <> 0 Then
            ListFileInfo strDLLFullPath, 4, True
        End If
        
        strRegKey = strPrinterKey & "\Monitors\" & strSubkey
        If HIVE = HKEY_LOCAL_MACHINE Then
            strRegKey = "HKLM\" & strRegKey
        End If
        LineOut "    Registry Key : ", strRegKey, False, False, True, "Item"

        LineOut "", "", True, False, True, ""
        
        If Err.Number <> 0 Then
            DisplayError "Listing print Monitor. Printer Key: " & strPrinterKey & ". Last DLL: " & strDLLName, Err.Number, Err.Source, Err.Description
        End If
        
        CloseTag ("PrintMonitor")
    Next
    CloseTag ("PrintMonitors")
    
End Sub

Sub ListFileInfo(ByVal strFilePath, intNumberofSpaces, bShowDescriptioninXML)

    Dim ClsVI, VI
    Dim strVersion, strModifiedDate, strCreatedDate, strManufacturer, strDescription

    If ListFileInfoUsingFSO(strFilePath, intNumberofSpaces) Then

        Set ClsVI = New CVersionInfo
        Set VI = ClsVI.GetFileVersionInfo(strFilePath)
        
        Select Case VI.State
            Case 0
                strVersion = VI.Value("FileVersion")
                strManufacturer = VI.Value("CompanyName")
                If IsVistaOrNewer Then
                    strDescription = GetFileDescriptionUsingShell(strFilePath)
                    If strDescription = "" Then strDescription = VI.Value("FileDescription")
                    'Obtaining description using the tradional method in longhorn retrieves invalid strings for some DLLs
                    'I am using shell as preferred method for Vista and newer
                Else
                    strDescription = VI.Value("FileDescription")
                End If
               
                If Len(strVersion) > 0 Then
                    LineOut Space(intNumberofSpaces) & "Version      : ", strVersion, False, False, True, "Item"
                Else
                    LineOut Space(intNumberofSpaces) & "Version      : ", "", False, True, True, "Item"
                End If
                
                If Len(strDescription) > 0 Then
                  LineOut Space(intNumberofSpaces) & "Description  : ", strDescription, True, False, True, ""
                  If bShowDescriptioninXML Then
                    LineOut "Description  : ", ConvertToASCII(strDescription), False, True, True, "Item"
                  End If
                End If
                
                If Len(strManufacturer) > 0 Then
                  LineOut Space(intNumberofSpaces) & "Manufacturer : ", ConvertToASCII(strManufacturer), False, False, True, "Item"
                Else
                  LineOut Space(intNumberofSpaces) & "Manufacturer : ", "(Unknown)", False, True, True, "Item"
                End If
            Case 1
               strVersion = "(Invalid file path.)"
               LineOut Space(intNumberofSpaces) & "Version       : ", strVersion, False, False, True, "Item"
            Case 2
               Rem strVersion = "(No .rsrc table listed in section table.)"
               Rem LineOut Space(intNumberofSpaces) & "Version       : ", strVersion, False, False, True, "Item"
            Case 3
               strVersion = "(Failed to find version info.)"
               LineOut Space(intNumberofSpaces) & "Version       : ", strVersion, False, False, True, "Item"
            Case 4
               Rem strVersion = "(File is not a PE file.)"
               Rem LineOut Space(intNumberofSpaces) & "Version       : ", strVersion, False, False, True, "Item"
            Case 5
               strVersion = "(File is a 16-bit executable. There is no file version info. for 16-bit.)"
               LineOut Space(intNumberofSpaces) & "Version       : ", strVersion, False, False, True, "Item"
        End Select
   End If
End Sub

Function GetFileDescriptionUsingShell(strFileName)

    On Error Resume Next
    
    Dim arrHeaders(34), objShellApp, objFolder, objFolderItem
    
    Set objShellApp = CreateObject("Shell.Application")
    Set objFolder = objShellApp.Namespace(objFSO.GetParentFolderName(strFileName))
    
    If Err.Number <> 0 Then
        GetFileDescriptionUsingShell = ""
    Else
        Set objFolderItem = objFolder.ParseName(objFSO.GetFileName(strFileName))
    
        If (Not objFolderItem Is Nothing) Then
            GetFileDescriptionUsingShell = objFolder.GetDetailsOf(objFolderItem, 34)
        End If
    End If
End Function

Function ConvertToASCII(strValue)
    Dim x, intAsc
    ConvertToASCII = ""
    For x = 1 To Len(strValue)
        intAsc = Asc(Mid(strValue, x, 1))
        If ((intAsc >= 40) And (intAsc <= 59)) Or ((intAsc >= 64) And (intAsc <= 122)) Or (intAsc = 32) Or (intAsc = 38) Then
            ConvertToASCII = ConvertToASCII + Mid(strValue, x, 1)
        End If
    Next
End Function

Function ListFileInfoUsingFSO(ByVal strFilePath, intNumberofSpaces)
    
    Dim strModifiedDate
    Dim strCreatedDate, objFile

    On Error Resume Next

    If objFSO.FileExists(strFilePath) Then
        Set objFile = objFSO.GetFile(strFilePath)
        If Err.Number <> 0 Then
            ListFileInfoUsingFSO = False
            Exit Function
        End If
        strModifiedDate = objFile.DateLastModified
        strCreatedDate = objFile.DateCreated
        
        LineOut Space(intNumberofSpaces) & "Modified date: ", strModifiedDate, False, False, True, "Item"
        LineOut Space(intNumberofSpaces) & "Created date : ", strCreatedDate, False, False, True, "Item"
        ListFileInfoUsingFSO = True
    Else
        ListFileInfoUsingFSO = False
    End If
End Function

Sub CreateHTMFile()
    On Error Resume Next
    Dim strErrText
    Err.Clear
    
    Dim strHTMLFileName, objHTMLFile, xmlStylesheet, xmlStylesheetPath, xmlFile, strXmlFilePath
        
    strXmlFilePath = objFSO.GetAbsolutePathName(".") & "\" & objShell.Environment("PROCESS").Item("COMPUTERNAME") & _
                     "_PrintInfo.XML"
        
    strHTMLFileName = objFSO.GetAbsolutePathName(".") & "\" & objShell.Environment("PROCESS").Item("COMPUTERNAME") & _
                                                    "_PrintInfo" & ".htm"
        
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
        objFSO.DeleteFile strXmlFilePath, True
        If Err.Number <> 0 Then
            DisplayError "Error deleting files " & strXmlFilePath & "/ " & xmlStylesheetPath & ".", Err.Number, Err.Source, Err.Description
            Exit Sub
        End If
    End If
End Sub


Function ConvertWMIDateTime(ByVal WmiDatetime)
    On Error Resume Next
    
    Dim dtUTCDateTime, dtLocalDateTime, hr, ampm, mn, sec, intCurrentBiasfromWMIDateTime, strDate, strTime
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
    
    strDate = Right("0" & Month(dtLocalDateTime), 2) & "/" & Right("0" & Day(dtLocalDateTime), 2) & "/" & CStr(Year(dtLocalDateTime))
    strTime = hr & ":" & mn & ":" & sec & " " & ampm
    ConvertWMIDateTime = strDate & " " & strTime
    
End Function

Sub OpenWMIService()
    On Error Resume Next
    Err.Clear
    If IsEmpty(objWMIService) Then
        'wscript.Echo ("   Opening WMI Service")
        Set objWMIService = GetObject("winmgmts:" & _
        "{impersonationLevel=impersonate, (Backup, Security)}!\\" & _
        ".\root\cimv2")
        Set objWMIReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\." & _
                         "\root\default:StdRegProv")
        If Err.Number <> 0 Then
           wscript.Echo "Error 0x" & HexFormat(Err.Number) & ": binding to WMI Service"
           wscript.Echo Err.Source & " - " & Err.Description
           wscript.Quit
        End If
    End If
End Sub

Function HexFormat(intNumber)
    HexFormat = Right("00000000" & CStr(Hex(intNumber)), 8)
End Function

Sub LineOut(strName, strValue, bDoNotWriteToXML, bDoNotWritetoTXT, bDoNotWritetoConsole, strXMLTag)
    If Not bDoNotWritetoConsole Then
        wscript.Echo strName & strValue
    End If

    If Not bDoNotWritetoTXT Then
        objTXTFile.WriteLine strName & strValue
    End If

    If Not bDoNotWriteToXML Then
                
        If Right(strName, 2) = ": " Then
            strName = Left(strName, Len(strName) - 2)
        End If
        If Left(strName, 4) = " -- " Then
            strName = Right(strName, Len(strName) - 4)
        End If
        strName = Trim(strName)
        
        WriteToXML strName, strValue, strXMLTag
    End If
    
End Sub

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

Function StringToArray(strString, strSeparator)
    On Error Resume Next
    Dim arrArray()
    ReDim arrArray(0)
    Dim intCommaPosition, intPreviousCommaPosition
    intPreviousCommaPosition = 1
    
    intCommaPosition = InStr(intPreviousCommaPosition, strString, strSeparator)
    
    Do While intCommaPosition <> 0
        arrArray(UBound(arrArray)) = Trim(Replace(Mid(strString, intPreviousCommaPosition, intCommaPosition - intPreviousCommaPosition), Chr(34), ""))
        intPreviousCommaPosition = intCommaPosition + 1
        intCommaPosition = InStr(intPreviousCommaPosition, strString, strSeparator)
        ReDim Preserve arrArray(UBound(arrArray) + 1)
    Loop
    arrArray(UBound(arrArray)) = Trim(Replace(Mid(strString, intPreviousCommaPosition, Len(strString)), Chr(34), ""))
    
    StringToArray = arrArray
    
    If Err.Number <> 0 Then
        DisplayError "Converting String " & strString & " to Array", Err.Number, Err.Source, Err.Description
        Exit Function
    End If
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

Function ExtractEmbeddedXSL(ByRef strXSLPath)
    Dim objScriptFile
    Dim objXSL
    Dim bolXSLExtracted, strLine, bCDataBegin
    
    On Error Resume Next
    
    wscript.Echo "Building XSLT File..."
    
    Set objScriptFile = objFSO.OpenTextFile(wscript.ScriptFullName, ForReading, False, OpenFileMode)
    
    If Err.Number <> 0 Then
        DisplayError "Error opening script file to extract XSL file" & wscript.ScriptFullName & ".", Err.Number, Err.Source, Err.Description
        ExtractEmbeddedXSL = False
        Exit Function
    End If
    
    strXSLPath = objFSO.GetSpecialFolder(2) & "\PrintInfoXSL.XSL"
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
    Else
        objXSL.Close
        objScriptFile.Close
        ExtractEmbeddedXSL = True
    End If
    
    Set objXSL = Nothing
    Set objScriptFile = Nothing
    
End Function

Sub EmbeddedXSL()
'<?xml version="1.0"?>
'<!-- 2008 Microsoft Corporation - Andre Teixeira-->
'<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
'<xsl:output method="html"/>
'<xsl:key name="PrintProviderType" match="Driver" use="Item[@name = 'Type']/text()" />
'<xsl:key name="PrintProvider" match="Driver" use="concat(Item[@name = 'Type']/text(), '|' , Item[@name = 'Provider']/text())" />
'<xsl:key name="ProcessorProviderType" match="PrintProcessor" use="Item[@name = 'Type']/text()" />
'<xsl:key name="ProcessorProvider" match="PrintProcessor" use="concat(Item[@name = 'Type']/text(), '|' , Item[@name = 'Provider']/text())" />
'<xsl:key name="MonitorProviderType" match="PrintMonitor" use="Item[@name = 'Type']/text()" />
'<xsl:key name="PrintMonitorNameKey" match="PrintMonitor" use="MonitorName" />
'<xsl:key name="MonitorProvider" match="PrintMonitor" use="concat(Item[@name = 'Type']/text(), '|' , Item[@name = 'Provider']/text())" />
'
'  <xsl:template match="/Root">
'<html dir="ltr" xmlns:v="urn:schemas-microsoft-com:vml" gpmc_reportInitialized="false">
'<head>
'<!-- Styles -->
'<style type="text/css">
'  body    { background-color:#FFFFFF; border:1px solid #666666; color:#000000; font-size:68%; font-family:MS Shell Dlg; margin:0,0,10px,0; word-break:normal; word-wrap:break-word; }
'
'  table   { font-size:100%; table-layout:fixed; width:100%; }
'
'  td,th   { overflow:visible; text-align:left; vertical-align:top; white-space:normal; }
'
'  .title  { background:#FFFFFF; border:none; color:#333333; display:block; height:24px; margin:0px,0px,-1px,0px; padding-top:4px; position:relative; table-layout:fixed; width:100%; z-index:5; }
'
'  .he0_expanded    { background-color:#FEF7D6; border:1px solid #BBBBBB; color:#3333CC; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:120%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he0a   { background-color:#D9E7F2; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:5px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he0a_expanded { background-color:#D9E7F2; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:5px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he0b_expanded { background-color:#AAD5D5; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:120%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:5px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he1_expanded    { background-color:#A0BACB; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he1a_expanded    { background-color:#B3C7D5; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:15px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he1b_expanded    { background-color:#C5DCDE; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:20px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he15_expanded   { background-color:#D9E3EA; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he4_expanded { background-color:#7EA0B8; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; font-weight:bold; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he5_expanded { background-color:#C4C4C4; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:15px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he6_expanded { background-color:#DFDFDF; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:25px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he7_expanded { background-color:#F0F0F0; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:40px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he1    { background-color:#A0BACB; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he2    { background-color:#E8E8E8; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:30px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he3    { background-color:#F1F1F1; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:40px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he3noexpand { background-color:#E8E8E8; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:30px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he4    { background-color:#E8E8E8; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:40px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he4h   { background-color:#E8E8E8; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:45px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he4i   { background-color:#F9F9F9; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; margin-bottom:-1px; margin-left:45px; margin-right:0px; padding-bottom:5px; padding-left:21px; padding-top:4px; position:relative; width:100%; }
'
'  .he4ib  { background-color:#F9F9F9; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-bottom:5px; padding-left:21px; padding-top:4px; position:relative; width:100%; }
'
'  .he4ic  { background-color:#F9F9F9; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; margin-bottom:-1px; margin-left:15px; margin-right:0px; padding-bottom:5px; padding-left:21px; padding-top:4px; position:relative; width:100%; }
'
'  .he5    { background-color:#E8E8E8; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:50px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
'
'  .he5h   { background-color:#E8E8E8; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; padding-right:5em; padding-top:4px; margin-bottom:-1px; margin-left:55px; margin-right:0px; position:relative; width:100%; }
'
'  .he5i   { background-color:#F9F9F9; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; margin-bottom:-1px; margin-left:55px; margin-right:0px; padding-left:21px; padding-bottom:5px; padding-top: 4px; position:relative; width:100%; }
'
'  DIV .expando { color:#000000; text-decoration:none; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:normal; position:absolute; right:10px; text-decoration:underline; z-index: 0; }
'
'  .he0 .expando { font-size:100%; }
'
'  .infoFirstCol                     { padding-right:10px; width:20%; }
'  .infoSecondCol                     { padding-right:10px; width:80%; }
'
'  .info, .info0th, .info3, .info4, .disalign  { line-height:1.6em; padding:0px,0px,0px,0px; margin:0px,0px,0px,0px; }
'
'  .disalign TD                      { padding-bottom:5px; padding-right:10px; }
'
'  .info5filename                    { padding-right:10px; width:30%; border-bottom:1px solid #CCCCCC; padding-right:10px;}
'
'  .info0th                          { padding-right:10px; width:12%; border-bottom:1px solid #CCCCCC; padding-right:10px;}
'
'  .info0thsm                        { padding-right:10px; width:5%; border-bottom:1px solid #CCCCCC; padding-right:10px;}
'
'  .info TD                          { padding-right:10px; width:50%; }
'
'  .info3 TD                         { padding-right:10px; width:33%; }
'
'  .info4 TD, .info4 TH              { padding-right:10px; width:25%; }
'
'  .info TH, .info0th, .info0thsm, .info3 TH, .info4 TH, .disalign TH { border-bottom:1px solid #CCCCCC; padding-right:10px; }
'
'  .subtable, .subtable3             { border:1px solid #CCCCCC; margin-left:0px; background:#FFFFFF; margin-bottom:10px; }
'
'  .subtable TD, .subtable3 TD       { padding-left:10px; padding-right:5px; padding-top:3px; padding-bottom:3px; line-height:1.1em; width:10%; }
'
'  .subtable TH, .subtable3 TH       { border-bottom:1px solid #CCCCCC; font-weight:normal; padding-left:10px; line-height:1.6em;  }
'
'  .subtable .footnote               { border-top:1px solid #CCCCCC; }
'
'  .subtable3 .footnote, .subtable .footnote { border-top:1px solid #CCCCCC; }
'
'  .subtable_frame     { background:#D9E3EA; border:1px solid #CCCCCC; margin-bottom:1px; margin-left:10px; }
'
'  .subtable_frame TD  { line-height:1.1em; padding-bottom:3px; padding-left:10px; padding-right:15px; padding-top:3px; }
'
'  .subtable_frame TH  { border-bottom:1px solid #CCCCCC; font-weight:normal; padding-left:10px; line-height:1.6em; }
'
'  .subtableInnerHead { border-bottom:1px solid #CCCCCC; border-top:1px solid #CCCCCC; }
'
'  .explainlink            { color:#000000; text-decoration:none; cursor:hand; }
'
'  .explainlink:hover      { color:#0000FF; text-decoration:underline; }
'
'  .spacer { background:transparent; border:1px solid #BBBBBB; color:#FFFFFF; display:block; font-family:MS Shell Dlg; font-size:100%; height:10px; margin-bottom:-1px; margin-left:43px; margin-right:0px; padding-top: 4px; position:relative; }
'
'  .filler { background:transparent; border:none; color:#FFFFFF; display:block; font:100% MS Shell Dlg; line-height:8px; margin-bottom:-1px; margin-left:43px; margin-right:0px; padding-top:4px; position:relative; }
'
'  .container { display:block; position:relative; }
'
'  .rsopheader { background-color:#A0BACB; border-bottom:1px solid black; color:#333333; font-family:MS Shell Dlg; font-size:130%; font-weight:bold; padding-bottom:5px; text-align:center; }
'
'  .rsopname { color:#333333; font-family:MS Shell Dlg; font-size:130%; font-weight:bold; padding-left:11px; }
'
'  .gponame{ color:#333333; font-family:MS Shell Dlg; font-size:130%; font-weight:bold; padding-left:11px; }
'
'  .gpotype{ color:#333333; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; padding-left:11px; }
'
'  #uri    { color:#333333; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; }
'
'  #dtstamp{ color:#333333; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; text-align:left; width:30%; }
'
'  #objshowhide { color:#000000; cursor:hand; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; margin-right:0px; padding-right:10px; text-align:right; text-decoration:underline; z-index:2; word-wrap:normal; }
'
'  #gposummary { display:block; }
'
'  #gpoinformation { display:block; }
'
'  @media print {
'
'  #objshowhide{ display:none; }
'
'  body    { color:#000000; border:1px solid #000000; }
'
'  .title  { color:#000000; border:1px solid #000000; }
'
'  .he0_expanded    { color:#000000; border:1px solid #000000; }
'
'  .he1_expanded    { color:#000000; border:1px solid #000000; }
'
'  .he1    { color:#000000; border:1px solid #000000; }
'
'  .he2    { color:#000000; background:#EEEEEE; border:1px solid #000000; }
'
'  .he3    { color:#000000; border:1px solid #000000; }
'
'  .he4    { color:#000000; border:1px solid #000000; }
'
'  .he4h   { color:#000000; border:1px solid #000000; }
'
'  .he4i   { color:#000000; border:1px solid #000000; }
'
'  .he5    { color:#000000; border:1px solid #000000; }
'
'  .he5h   { color:#000000; border:1px solid #000000; }
'
'  .he5i   { color:#000000; border:1px solid #000000; }
'
'  }
'
'  v\:* {behavior:url(#default#VML);}
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
'Function IsSectionHeader(obj)
'    IsSectionHeader = (obj.className = "he0_expanded") Or (obj.className = "he0b_expanded") Or (obj.className = "he0a") Or (obj.className = "he0a_expanded") or (obj.className = "he5_expanded") Or (obj.className = "he6_expanded") Or (obj.className = "he7_expanded") Or (obj.className = "he1_expanded") Or (obj.className = "he1a_expanded") Or (obj.className = "he1b_expanded") Or (obj.className = "he1") Or (obj.className = "he2") Or (obj.className = "he3") Or (obj.className = "he4") Or (obj.className = "he4h") Or (obj.className = "he5") Or (obj.className = "he5h")  or (obj.className = "he4_expanded")
'End Function
'
'
'Function IsSectionExpandedByDefault(objHeader)
'    IsSectionExpandedByDefault = (Right(objHeader.className, Len("_expanded")) = "_expanded")
'End Function
'
'
'' strState must be show | hide | toggle
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
'            rem objExpando.innerText = strHide
'            rem objExpando.innerHTML = "<v:group id=" & chr(34) & "Show" & chr(34) & " class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:15px;height:15px;vertical-align:middle" & chr(34) & " coordsize=" & chr(34) & "100,100" & chr(34) & " alt=" & chr(34) & "Hide" & chr(34) & "><v:shape class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:100; height:100; z-index:0" & chr(34) & " fillcolor=" & chr(34) & "green" & chr(34) & " strokecolor=" & chr(34) & "green" & chr(34) & "><v:path v=" & chr(34) & "m 30,50 l 70,50 x e" & chr(34) & " /></v:shape></v:group>"
'            objExpando.innerHTML =   "<v:group class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:15px;height:15px;vertical-align:middle" & chr(34) & " coordsize=" & chr(34) & "100,100" & chr(34) & " alt=" & chr(34) & "Show" & chr(34) & "><v:rect " & chr(34) & " stroked=" & chr(34) & "False" & chr(34) & "fillcolor=" & chr(34) & "#808080" & chr(34) & " style=" & chr(34) & "top:47;left:25;width:50;height:5" & chr(34) & " /></v:group>"
'        ElseIf strState = "hide" Then
'            objContainer.style.display = "none"
'            rem objExpando.innerText = strShow
'            rem objExpando.outerHTML = "<v:group class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:15px;height:15px;vertical-align:middle" & chr(34) & " coordsize=" & chr(34) & "100,100" & chr(34) & " alt=" & chr(34) & "Show" & chr(34) & "><v:shape class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:100; height:100; z-index:0" & chr(34) & " fillcolor=" & chr(34) & "black" & chr(34) & " strokecolor=" & chr(34) & "red" & chr(34) & "><v:path v=" & chr(34) & "m 99,1 l 1,1 50,50 x e" & chr(34) & " /></v:shape></v:group>"
'            objExpando.innerHTML =   "<v:group class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:15px;height:15px;vertical-align:middle" & chr(34) & " coordsize=" & chr(34) & "100,100" & chr(34) & " alt=" & chr(34) & "Show" & chr(34) & "><v:rect fillcolor=" & chr(34) & "#808080" & chr(34) & " stroked=" & chr(34) & "False" & chr(34) & " style=" & chr(34) & "top:47;left:25;width:50;height:5" & chr(34) & " /><v:rect fillcolor=" & chr(34) & "#808080" & chr(34) & " stroked=" & chr(34) & "False" & chr(34) & " style=" & chr(34) & "top:25;left:47;width:5;height:50" & chr(34) & " /></v:group>"
'        End If
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
''========================================================he3========================
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
'
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
'<body>
'
'   <table class="title" cellpadding="0" cellspacing="0">
'   <tr><td colspan="2" class="rsopheader">Printers and Print Drivers Information</td></tr>
'   <tr><td colspan="2" class="rsopname">Machine name: <xsl:value-of select="Title"/></td></tr>
'   <tr><td id="dtstamp">Data collected on: <xsl:value-of select="TimeField"/></td><td><div id="objshowhide" tabindex="0"></div></td></tr>
'   </table>
'  <div class="filler"></div>
'
'  <div class="container">
'    <div class="he0_expanded">
'      <span class="sectionTitle" tabindex="0">Alerts</span>
'      <a class="expando" href="#"></a>
'    </div>
'    <xsl:for-each select="./Alerts/Alert">
'      <xsl:sort select="AlertPriority" order="descending" data-type="number"/>
'      <div class="he0a_expanded">
'        <span class="sectionTitle" tabindex="0">
'          <xsl:choose>
'            <xsl:when test="AlertType = 'Information'">
'              <v:group id="Inf1" class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Information">
'                <v:oval class="vmlimage" style="width:100;height:100;z-index:0" fillcolor="white" strokecolor="#336699" />
'                <v:line class="vmlimage" style="z-index:1" from="50,15" to="50,25" strokecolor="#336699" strokeweight="3px" />
'                <v:line class="vmlimage" style="z-index:2" from="50,35" to="50,80" strokecolor="#336699" strokeweight="3px" />
'              </v:group>
'            </xsl:when>
'            <xsl:when test="AlertType = 'Warning'">
'              <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Warning">
'                <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="yellow" strokecolor="yellow">
'                  <v:path v="m 50,0 l 0,99 99,99 x e" />
'                </v:shape>
'                <v:rect class="vmlimage" style="top:35; left:45; width:10; height:35; z-index:1" fillcolor="black" strokecolor="black">
'                </v:rect>
'                <v:rect class="vmlimage" style="top:85; left:45; width:10; height:5; z-index:1" fillcolor="black" strokecolor="black">
'                </v:rect>
'              </v:group>
'            </xsl:when>
'            <xsl:when test="AlertType = 'Error'">
'              <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Error">
'                <v:oval class="vmlimage" style='width:100;height:100;z-index:0' fillcolor="red" strokecolor="red">
'                </v:oval>
'                <v:line class="vmlimage" style="z-index:1" from="25,25" to="75,75" strokecolor="white" strokeweight="3px">
'                </v:line>
'                <v:line class="vmlimage" style="z-index:2" from="75,25" to="25,75" strokecolor="white" strokeweight="3px">
'                </v:line>
'              </v:group>
'            </xsl:when>
'          </xsl:choose>
'          <xsl:text>  </xsl:text>
'          <xsl:value-of select="AlertType"/>
'        </span>
'        <a class="expando" href="#"></a>
'      </div>
'      <div class="container">
'        <div class="he4ic">
'          <table cellpadding="0" class="info0">
'            <tr>
'              <td class="infoFirstCol">Category: </td>
'              <td class="infoSecondCol">
'                <xsl:value-of disable-output-escaping="yes" select="AlertCategory"/>
'              </td>
'              <td></td>
'            </tr>
'            <tr>
'              <td class="infoFirstCol">Message: </td>
'              <td class="infoSecondCol">
'                <xsl:value-of disable-output-escaping="yes" select="AlertMessage"/>
'              </td>
'              <td></td>
'            </tr>
'            <xsl:if test="AlertRecommendation">
'              <tr>
'                <td class="infoFirstCol">Recommendation: </td>
'                <td class="infoSecondCol">
'                  <xsl:value-of disable-output-escaping="yes" select="AlertRecommendation"/>
'                </td>
'                <td></td>
'              </tr>
'            </xsl:if>
'          </table>
'        </div>
'      </div>
'    </xsl:for-each>
'
'    <div class="filler"></div>
'    <xsl:if test="(count(//Driver) &gt; 0) or (count(//PrintProcessor) &gt; 0) or (count(//PrintMonitors) &gt; 0)">
'    <div class="rsopsettings">
'      <div class="he0_expanded">
'        <span class="sectionTitle" tabindex="0">Printers and Print Drivers Summary</span>
'        <a class="expando" href="#"></a>
'      </div>
'      <div class="container">
'
'        <div class="he0a">
'          <span class="sectionTitle" tabindex="0">
'            <a name="#PrintersByProvider">Printers by Provider</a>
'          </span>
'          <a class="expando" href="#"></a>
'        </div>
'        <div class="container">
'          <div class="he4ic">
'            <xsl:for-each select="//Driver[count(. | key('PrintProviderType', Item[@name = 'Type'])[1]) = 1]">
'
'              <xsl:variable name="PrintProviderType" select="Item[@name = 'Type']/text()"/>
'
'              <div class="rsopsummary">
'                <div class="he1a_expanded">
'                  <span class="sectionTitle" tabindex="0">
'                    Type: <xsl:value-of select="Item[@name = 'Type']"/>
'                  </span>
'                  <a class="expando" href="#"></a>
'                </div>
'                <div class="container">
'                  <xsl:for-each select="key('PrintProviderType', $PrintProviderType)[count(. | key('PrintProvider', concat($PrintProviderType, '|', Item[@name = 'Provider']/text()))[1]) = 1]">
'                    <xsl:variable name="PrintProviderName" select="Item[@name = 'Provider']/text()"/>
'                    <xsl:variable name="CountPrinters" select="count(//Printer[(../../Item[@name='Provider']=$PrintProviderName) and (../../Item[@name='Type'] = $PrintProviderType) and (Item[@name='Driver Name'])])"/>
'                    <div class="rsopsummary">
'                      <div class="he1b_expanded">
'                        <span class="sectionTitle" tabindex="0">
'                          Provider: <xsl:value-of select="Item[@name = 'Provider']"/>
'                        </span>
'                        <a class="expando" href="#"></a>
'                      </div>
'                      <div class="container">
'                            <div class="he3">
'                              <span class="sectionTitle" tabindex="0">
'                                Printers (<xsl:value-of select="$CountPrinters"/>)
'                              </span>
'                              <a class="expando" href="#"></a>
'                            </div>
'                        <div class="container">
'                          <div class="he4i">
'                            <xsl:for-each select="//Resource[Environment[Version[Drivers[Driver[Printers[Printer[(../../Item[@name='Provider']=$PrintProviderName) and (../../Item[@name='Type']= $PrintProviderType)]]]]]]]">
'                              <div class="he1_expanded">
'                                <span class="sectionTitle" tabindex="0">
'                                  <xsl:if test="Name">
'                                    <xsl:value-of select="Name"/> -
'                                  </xsl:if>
'                                  <xsl:value-of select="../LocationName"/>
'                                </span>
'                                <a class="expando" href="#"></a>
'                              </div>
'                              <div class="container">
'                                <xsl:for-each select="Environment[Version[Drivers[Driver[Printers[Printer[(../../Item[@name='Provider']=$PrintProviderName) and (../../Item[@name='Type'] = $PrintProviderType)]]]]]]">
'                                  <div class="he5_expanded">
'                                    <span class="sectionTitle" tabindex="0">
'                                      Environment: <xsl:value-of select="EnvironmentName"/>
'                                    </span>
'                                    <a class="expando" href="#"></a>
'                                  </div>
'                                  <div class="container">
'                                    <xsl:for-each select="Version[Drivers[Driver[Printers[Printer[(../../Item[@name='Provider']=$PrintProviderName) and (../../Item[@name='Type'] = $PrintProviderType)]]]]]">
'                                      <div class="he6_expanded">
'                                        <span class="sectionTitle" tabindex="0">
'                                          Version:
'                                          <xsl:value-of select="VersionName"/> (<xsl:value-of select="count(Drivers/Driver/Printers/Printer[(../../Item[@name='Provider'] = $PrintProviderName) and (../../Item[@name='Type'] = $PrintProviderType) and (Item[@name='Driver Name'])])"/>)
'                                        </span>
'                                        <a class="expando" href="#"></a>
'                                      </div>
'                                      <div class="container">
'
'                                        <xsl:for-each select="Drivers/Driver[Printers[Printer[(../../Item[@name='Provider'] = $PrintProviderName) and (../../Item[@name='Type'] = $PrintProviderType)]]]">
'                                          <div class="he7_expanded">
'                                            <span class="sectionTitle" tabindex="0">
'                                              Driver: <a href="#{Bookmark}">
'                                                <xsl:value-of select="DriverName"/>
'                                              </a> (<xsl:value-of select="count(Printers/Printer[Item[@name='Driver Name']])"/>)
'                                            </span>
'                                            <a class="expando" href="#"></a>
'                                          </div>
'                                          <div class="container">
'                                            <div class="he4i">
'                                              <table cellpadding="0" cellspacing="4">
'                                                <xsl:for-each select="Printers/Printer">
'                                                  <tr>
'                                                    <td>
'                                                      <xsl:value-of select="SessionTitle"/>
'                                                    </td>
'                                                  </tr>
'                                                </xsl:for-each>
'                                              </table>
'                                            </div>
'                                          </div>
'                                        </xsl:for-each>
'                                      </div>
'                                      <div class="filler"></div>
'                                    </xsl:for-each>
'                                  </div>
'                                </xsl:for-each>
'                              </div>
'                            </xsl:for-each>
'                          </div>
'                        </div>
'                      </div>
'                    </div>
'                  </xsl:for-each>
'                </div>
'                <div class="filler"></div>
'              </div>
'            </xsl:for-each>
'          </div>
'        </div>
'        <div class="filler"></div>
'        <div class="he0a">
'          <span class="sectionTitle" tabindex="0">
'            <a name="PrintProcessorsByProvider">Print Processors by Provider</a>
'          </span>
'          <a class="expando" href="#"></a>
'        </div>
'        <div class="container">
'          <div class="he4i">
'            <xsl:for-each select="//PrintProcessors/PrintProcessor[count(. | key('ProcessorProviderType', Item[@name = 'Type'])[1]) = 1]">
'
'              <xsl:variable name="ProcessorProviderType" select="Item[@name = 'Type']/text()"/>
'
'              <div class="rsopsummary">
'                <div class="he1a_expanded">
'                  <span class="sectionTitle" tabindex="0">
'                    Type: <xsl:value-of select="Item[@name = 'Type']"/>
'                  </span>
'                  <a class="expando" href="#"></a>
'                </div>
'                <div class="container">
'                  <xsl:for-each select="key('ProcessorProviderType', $ProcessorProviderType)[count(. | key('ProcessorProvider', concat($ProcessorProviderType, '|', Item[@name = 'Provider']/text()))[1]) = 1]">
'                    <xsl:variable name="ProcessorProviderName" select="Item[@name = 'Provider']/text()"/>
'                    <xsl:variable name="CountProcessors" select="count(//PrintProcessor[(Item[@name='Provider']=$ProcessorProviderName) and (Item[@name='Type'] = $ProcessorProviderType)])"/>
'                    <div class="rsopsummary">
'                      <div class="he1b_expanded">
'                        <span class="sectionTitle" tabindex="0">
'                          Provider: <xsl:value-of select="Item[@name = 'Provider']"/>
'                        </span>
'                        <a class="expando" href="#"></a>
'                      </div>
'                      <div class="container">
'                        <xsl:choose>
'                          <xsl:when test="$CountProcessors &gt; 0">
'                            <div class="he3">
'                              <span class="sectionTitle" tabindex="0">
'                                Print Processors (<xsl:value-of select="$CountProcessors"/>)
'                              </span>
'                              <a class="expando" href="#"></a>
'                            </div>
'                            <div class="container">
'                              <div class="he4i">
'                                <table>
'                                  <xsl:for-each select="//PrintProcessor[(Item[@name='Provider']=$ProcessorProviderName) and (Item[@name='Type']= $ProcessorProviderType)]">
'                                    <div>
'                                      <tr>
'                                        <td>
'                                          <a href="#{Bookmark}" title="{Item[@name='Description']}">
'                                            <xsl:value-of select="ProcessorName "/>
'                                          </a>
'                                        </td>
'                                      </tr>
'                                    </div>
'                                  </xsl:for-each>
'                                </table>
'                              </div>
'                            </div>
'                          </xsl:when>
'                          <xsl:otherwise>
'                            <div class="he3noexpand">
'                              <span tabindex="0">No printers are configured to use this print processor</span>
'                            </div>
'                          </xsl:otherwise>
'                        </xsl:choose>
'                      </div>
'                    </div>
'                  </xsl:for-each>
'
'                </div>
'                <div class="filler"></div>
'              </div>
'            </xsl:for-each>
'          </div>
'        </div>
'        <div class="filler"></div>
'        <div class="he0a">
'          <span class="sectionTitle" tabindex="0">
'            <a name="PrintMonitorsByProvider">Print Monitors by Provider</a>
'          </span>
'          <a class="expando" href="#"></a>
'        </div>
'        <div class="container">
'          <div class="he4i">
'            <xsl:for-each select="//PrintMonitor[count(. | key('MonitorProviderType', Item[@name = 'Type'])[1]) = 1]">
'              <xsl:variable name="MonitorProviderType" select="Item[@name = 'Type']/text()"/>
'
'              <div class="rsopsummary">
'                <div class="he1a_expanded">
'                  <span class="sectionTitle" tabindex="0">
'                    Type: <xsl:value-of select="Item[@name = 'Type']"/>
'                  </span>
'                  <a class="expando" href="#"></a>
'                </div>
'                <div class="container">
'                  <xsl:for-each select="key('MonitorProviderType', $MonitorProviderType)[count(. | key('MonitorProvider', concat($MonitorProviderType, '|', Item[@name = 'Provider']/text()))[1]) = 1]">
'
'                    <xsl:variable name="MonitorProviderName" select="Item[@name = 'Provider']/text()"/>
'
'                    <xsl:variable name="CountMonitors" select="count(//PrintMonitor[(Item[@name='Provider']=$MonitorProviderName) and (Item[@name='Type'] = $MonitorProviderType) and (count(. | key('PrintMonitorNameKey', MonitorName)[1]) = 1)])"/>
'                    <div class="rsopsummary">
'                      <div class="he1b_expanded">
'                        <span class="sectionTitle" tabindex="0">
'                          Monitor: <xsl:value-of select="Item[@name = 'Provider']"/>
'                        </span>
'                        <a class="expando" href="#"></a>
'                      </div>
'                      <div class="container">
'                        <xsl:choose>
'                          <xsl:when test="$CountMonitors &gt; 0">
'                            <div class="he3">
'                              <span class="sectionTitle" tabindex="0">
'                                Print Monitors (<xsl:value-of select="$CountMonitors"/>)
'                              </span>
'                              <a class="expando" href="#"></a>
'                            </div>
'                            <div class="container">
'                              <div class="he4i">
'                                <table>
'                                  <xsl:for-each select="//PrintMonitor[(Item[@name='Provider']=$MonitorProviderName) and (Item[@name='Type']= $MonitorProviderType) and (count(. | key('PrintMonitorNameKey', MonitorName)[1]) = 1)]">
'                                    <div>
'                                      <tr>
'                                        <td>
'                                          <a href="#{Bookmark}" title="{Item[@name='Description']}">
'                                            <xsl:value-of select="MonitorName "/>
'                                          </a>
'                                        </td>
'                                      </tr>
'                                    </div>
'                                  </xsl:for-each>
'                                </table>
'                              </div>
'                            </div>
'                          </xsl:when>
'                          <xsl:otherwise>
'                            <div class="he3noexpand">
'                              <span tabindex="0">No printers are configured to use this print monitor</span>
'                            </div>
'                          </xsl:otherwise>
'                        </xsl:choose>
'                      </div>
'                    </div>
'                  </xsl:for-each>
'
'                </div>
'                <div class="filler"></div>
'              </div>
'            </xsl:for-each>
'          </div>
'        </div>
'      </div>
'    </div>
'    </xsl:if>
'  </div>
'
'  <div class="filler"></div>
'
'  <xsl:for-each select="./PrinterLocation">
'       <div class="rsopsummary">
'       <div class="he0_expanded"><span class="sectionTitle" tabindex="0"><xsl:value-of select="LocationName"/> Printers</span><a class="expando" href="#"></a></div>
'      <div class="container">
'        <xsl:if test="LocationDetailsMsg">
'        <table class="subtable_frame" cellpadding="0" cellspacing="0">
'          <xsl:for-each select="LocationDetailsMsg">
'            <tr>
'              <td>
'                <xsl:if test="@name = 'Warning'">
'                  <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Warning">
'                    <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="yellow" strokecolor="yellow">
'                      <v:path v="m 50,0 l 0,99 99,99 x e" />
'                    </v:shape>
'                    <v:rect class="vmlimage" style="top:35; left:45; width:10; height:35; z-index:1" fillcolor="black" strokecolor="black">
'                    </v:rect>
'                    <v:rect class="vmlimage" style="top:85; left:45; width:10; height:5; z-index:1" fillcolor="black" strokecolor="black">
'                    </v:rect>
'                  </v:group>
'                </xsl:if>
'                <xsl:if test="@name = 'Error'">
'                  <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Error">
'                    <v:oval class="vmlimage" style='width:100;height:100;z-index:0' fillcolor="red" strokecolor="red">
'                    </v:oval>
'                    <v:line class="vmlimage" style="z-index:1" from="25,25" to="75,75" strokecolor="white" strokeweight="3px">
'                    </v:line>
'                    <v:line class="vmlimage" style="z-index:2" from="75,25" to="25,75" strokecolor="white" strokeweight="3px">
'                    </v:line>
'                  </v:group>
'                </xsl:if>
'                <xsl:if test="@name = 'Information'">
'                  <v:group id="Inf1" class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Information">
'                    <v:oval class="vmlimage" style="width:100;height:100;z-index:0" fillcolor="#336699" strokecolor="black" />
'                    <v:line class="vmlimage" style="z-index:1" from="50,15" to="50,25" strokecolor="white" strokeweight="3px" />
'                    <v:line class="vmlimage" style="z-index:2" from="50,35" to="50,80" strokecolor="white" strokeweight="3px" />
'                  </v:group>
'                </xsl:if>
'                <span>&#160;<xsl:value-of select="."/></span>
'              </td>
'            </tr>
'          </xsl:for-each>
'        </table>
'      </xsl:if>
'
'        <xsl:for-each select="./Resource">
'          <xsl:if test="Name">
'            <div class="he0b_expanded">
'              <span class="sectionTitle" tabindex="0">
'                Print Spooler Resource: <xsl:value-of select="Name"/>
'              </span>
'              <a class="expando" href="#"></a>
'            </div>
'          </xsl:if>
'          <xsl:if test="LocationDetailsMsg">
'            <table class="subtable_frame" cellpadding="0" cellspacing="0">
'              <xsl:for-each select="LocationDetailsMsg">
'                <tr>
'                  <td>
'                    <xsl:if test="@name = 'Warning'">
'                      <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Warning">
'                        <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="yellow" strokecolor="yellow">
'                          <v:path v="m 50,0 l 0,99 99,99 x e" />
'                        </v:shape>
'                        <v:rect class="vmlimage" style="top:35; left:45; width:10; height:35; z-index:1" fillcolor="black" strokecolor="black">
'                        </v:rect>
'                        <v:rect class="vmlimage" style="top:85; left:45; width:10; height:5; z-index:1" fillcolor="black" strokecolor="black">
'                        </v:rect>
'                      </v:group>
'                    </xsl:if>
'                    <xsl:if test="@name = 'Error'">
'                      <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Error">
'                        <v:oval class="vmlimage" style='width:100;height:100;z-index:0' fillcolor="red" strokecolor="red">
'                        </v:oval>
'                        <v:line class="vmlimage" style="z-index:1" from="25,25" to="75,75" strokecolor="white" strokeweight="3px">
'                        </v:line>
'                        <v:line class="vmlimage" style="z-index:2" from="75,25" to="25,75" strokecolor="white" strokeweight="3px">
'                        </v:line>
'                      </v:group>
'                    </xsl:if>
'                    <xsl:if test="@name = 'Information'">
'                      <v:group id="Inf1" class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Information">
'                        <v:oval class="vmlimage" style="width:100;height:100;z-index:0" fillcolor="#336699" strokecolor="black" />
'                        <v:line class="vmlimage" style="z-index:1" from="50,15" to="50,25" strokecolor="white" strokeweight="3px" />
'                        <v:line class="vmlimage" style="z-index:2" from="50,35" to="50,80" strokecolor="white" strokeweight="3px" />
'                      </v:group>
'                    </xsl:if>
'                    <span>
'                      &#160;<xsl:value-of select="."/>
'                    </span>
'                  </td>
'                </tr>
'              </xsl:for-each>
'            </table>
'          </xsl:if>
'
'          <div class="container">
'            <div class="he4ib">
'              <table class="info4" cellpadding="0" cellspacing="0">
'                <xsl:for-each select="LocationDetails">
'                  <tr>
'                    <td>
'                      <xsl:value-of select="@name"/>
'                    </td>
'                    <td>
'                      <xsl:value-of select="."/>
'                    </td>
'                    <td></td>
'                    <td></td>
'                  </tr>
'                </xsl:for-each>
'              </table>
'            </div>
'            <div class="filler"></div>
'            <xsl:for-each select="./Environment">
'              <xsl:variable name="EnvironmentName" select="EnvironmentName"/>
'              <div class="he1_expanded">
'                <span class="sectionTitle" tabindex="0">
'                  Platform: <xsl:value-of select="EnvironmentName"/>
'                </span>
'                <a class="expando" href="#"></a>
'              </div>
'              <div class="container">
'
'                <xsl:for-each select="./Version">
'                  <xsl:variable name="VersionName" select="VersionName"/>
'                  <div class="he1a_expanded">
'                    <span class="sectionTitle" tabindex="0">
'                      Version: <a name="{VersionName}">
'                        <xsl:value-of select="VersionName"/>
'                      </a>
'                    </span>
'                    <a class="expando" href="#"></a>
'                  </div>
'                  <div class="container">
'
'                    <xsl:for-each select="./Drivers/Driver">
'                      <div class="he1b_expanded">
'                        <span class="sectionTitle" tabindex="0">
'                          <a name="{Bookmark}">
'                            Driver: <xsl:value-of select="DriverName"/>
'                          </a>
'                        </span>
'                        <a class="expando" href="#"></a>
'                      </div>
'                      <div class="container">
'                        <div class="he2">
'                          <span class="sectionTitle" tabindex="0">Driver Properties</span>
'                          <a class="expando" href="#"></a>
'                        </div>
'                        <div class="container">
'                          <div class="he4i">
'                            <table>
'                              <xsl:for-each select="./Item">
'                                <xsl:variable name="name" select="@name"/>
'                                <xsl:variable name="namevalue" select="translate(../Item[@name=$name], 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"/>
'                                <tr>
'                                  <td>
'                                    <xsl:value-of select="@name"/>
'                                  </td>
'                                  <td colspan="5">
'                                    <xsl:choose>
'                                      <xsl:when test="($name='Print Monitor') and not ($namevalue = '(not found)')">
'                                        <a href='#{$namevalue}'>
'                                          <xsl:value-of select="../Item[@name=$name]"/>
'                                        </a>
'                                      </xsl:when>
'                                      <xsl:otherwise>
'                                        <xsl:value-of select="../Item[@name=$name]"/>
'                                      </xsl:otherwise>
'                                    </xsl:choose>
'                                  </td>
'                                </tr>
'                              </xsl:for-each>
'                            </table>
'                          </div>
'                        </div>
'
'                        <div class="he2">
'                          <span class="sectionTitle" tabindex="0">Driver Files</span>
'                          <a class="expando" href="#"></a>
'                        </div>
'                        <div class="container">
'                          <div class="he4i">
'                            <table cellpadding="0" cellspacing="4">
'                              <tr>
'                                <th class="info0thsm">Type</th>
'                                <th scope="col" class="info5filename">File Path</th>
'                                <th class="info0th">Modified Date</th>
'                                <th class="info0th">Created Date</th>
'                                <th class="info0th">Version</th>
'                                <th class="info0th">Manufacturer</th>
'                              </tr>
'                              <xsl:for-each select="./File">
'                                <tr>
'                                  <td>
'                                    <xsl:value-of select="FilePath/@name"/>
'                                  </td>
'                                  <td>
'                                    <xsl:choose>
'                                      <xsl:when test="Item[@name='Description']">
'                                        <span style="cursor:pointer" title="{Item[@name='Description']}">
'                                          <xsl:value-of select="FilePath"/>
'                                        </span>
'                                      </xsl:when>
'                                      <xsl:otherwise>
'                                        <xsl:value-of select="FilePath"/>
'                                      </xsl:otherwise>
'                                    </xsl:choose>
'                                  </td>
'                                  <td>
'                                    <xsl:value-of select="Item[@name='Modified date']"/>
'                                  </td>
'                                  <td>
'                                    <xsl:value-of select="Item[@name='Created date']"/>
'                                  </td>
'                                  <td>
'                                    <xsl:value-of select="Item[@name='Version']"/>
'                                  </td>
'                                  <td>
'                                    <xsl:value-of select="Item[@name='Manufacturer']"/>
'                                  </td>
'                                </tr>
'                              </xsl:for-each>
'                            </table>
'                          </div>
'                        </div>
'                        <div class="container">
'                          <div class="he2">
'                            <span class="sectionTitle" tabindex="0">
'                              Printers (<xsl:value-of select="count(./Printers/Printer/Item[@name='Driver Name'])"/>)
'                            </span>
'                            <a class="expando" href="#"></a>
'                          </div>
'                          <xsl:for-each select="./Printers/Printer">
'                            <div class="he3">
'                              <span class="sectionTitle" tabindex="0">
'                                Printer Name: <xsl:value-of select="SessionTitle"/>
'                              </span>
'                              <a class="expando" href="#"></a>
'                            </div>
'
'                            <div class="container">
'                              <div class="he4i">
'                                <table>
'                                  <xsl:for-each select="./Item">
'                                    <xsl:variable name="name" select="@name"/>
'                                    <xsl:variable name="namevalue" select="translate(../Item[@name=$name], 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"/>
'                                    <tr>
'                                      <td>
'                                        <xsl:value-of select="@name"/>
'                                      </td>
'                                      <td>
'                                        <xsl:choose>
'                                          <xsl:when test="($name='Print Processor') and not ($namevalue = '(unknown)')">
'                                            <a href='#{$namevalue}'>
'                                              <xsl:value-of select="../Item[@name=$name]"/>
'                                            </a>
'                                          </xsl:when>
'                                          <xsl:otherwise>
'                                            <xsl:value-of select="../Item[@name=$name]"/>
'                                          </xsl:otherwise>
'                                        </xsl:choose>
'                                      </td>
'                                      <td></td>
'                                      <td></td>
'                                    </tr>
'                                  </xsl:for-each>
'                                </table>
'                              </div>
'                            </div>
'                          </xsl:for-each>
'                          <div class="filler"></div>
'                        </div>
'                      </div>
'                    </xsl:for-each>
'                  </div>
'                </xsl:for-each>
'              </div>
'            </xsl:for-each>
'          </div>
'        </xsl:for-each>
'        <div class="filler"></div>
'           </div>
'        </div>
'    <div class="filler"></div>
'  </xsl:for-each>
'
'<div class="rsopsettings">
'<div class="he0_expanded"><span class="sectionTitle" tabindex="0">Print Monitors</span><a class="expando" href="#"></a></div>
'<div class="container">
'   <xsl:for-each select="//PrintMonitors/PrintMonitor[count(. | key('PrintMonitorNameKey', MonitorName)[1]) = 1]">
'       <xsl:variable name="PrintMonitorName" select="translate(MonitorName, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"/>
'       <xsl:variable name="CountDrivers" select="count(//Driver[translate(Item[@name='Print Monitor'], 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')=$PrintMonitorName])"/>
'    <div class="rsopsummary">
'      <div class="he1b_expanded">
'        <span class="sectionTitle" tabindex="0">
'           Monitor Name: <a name="{$PrintMonitorName}">
'            <a name="{Bookmark}">
'              <xsl:value-of select="MonitorName"/>
'            </a>
'          </a>
'        </span>
'        <a class="expando" href="#"></a>
'      </div>
'
'      <div class="he2">
'        <span class="sectionTitle" tabindex="0">
'          Print Monitor Properties
'        </span>
'        <a class="expando" href="#"></a>
'      </div>
'      <div class="container">
'          <div class="he4i">
'            <table >
'              <xsl:for-each select="./Item">
'                <tr>
'                  <xsl:choose>
'                  <xsl:when test="@name = 'Registry Key'">
'                    <td>
'                      Registry Key(s)
'                    </td>
'                    <td colspan="4">
'                      <xsl:for-each select="//PrintMonitor[translate(MonitorName, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')=$PrintMonitorName]">
'                        <span>
'                          <xsl:value-of select="Item[@name='Registry Key']"/>
'                          <br/>
'                        </span>
'                      </xsl:for-each>
'                    </td>
'                  </xsl:when>
'                  <xsl:otherwise>
'                    <xsl:variable name="name" select="@name"/>
'                      <td>
'                        <xsl:value-of select="@name"/>
'                      </td>
'                      <td colspan="4">
'                        <xsl:value-of select="../Item[@name=$name]"/>
'                      </td>
'                  </xsl:otherwise>
'                 </xsl:choose>
'                <td></td>
'                <td></td>
'                </tr>
'              </xsl:for-each>
'            </table>
'          </div>
'      </div>
'        <xsl:choose>
'          <xsl:when test="$CountDrivers &gt; 0">
'            <div class="he2">
'              <span class="sectionTitle" tabindex="0">
'                Print drivers configured to use this print monitor (<xsl:value-of select="$CountDrivers"/>)
'              </span>
'              <a class="expando" href="#"></a>
'            </div>
'
'            <div class="container">
'              <div class="he4i">
'                <table cellpadding="0" cellspacing="4">
'                  <xsl:for-each select="//Driver[translate(Item[@name='Print Monitor'], 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')=$PrintMonitorName]">
'                    <tr>
'                      <td>
'                        <a href="#{Bookmark}">
'                          <xsl:value-of select="DriverName"/>
'                        </a> (<xsl:value-of select="../../../../../LocationName"/>)
'                      </td>
'                    </tr>
'                  </xsl:for-each>
'                </table>
'              </div>
'            </div>
'          </xsl:when>
'          <xsl:otherwise>
'            <div class="he3noexpand">
'              <span tabindex="0" style="font:">No print drivers are configured to use this print monitor</span>
'            </div>
'          </xsl:otherwise>
'        </xsl:choose>
'      </div>
'      <div class="filler"></div>
'   </xsl:for-each>
'</div>
'<div class="filler"></div>
'
'<div class="rsopsettings">
'<div class="he0_expanded"><span class="sectionTitle" tabindex="0">Print Processors</span><a class="expando" href="#"></a></div>
'<div class="container">
'   <xsl:for-each select="//PrintProcessors/PrintProcessor">
'       <xsl:variable name="PrintProcessorName" select="translate(ProcessorName, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')"/>
'       <xsl:variable name="CountPrinters" select="count(//Printer[(translate(Item[@name='Print Processor'], 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')=$PrintProcessorName) and (Item[@name='Driver Name'])])"/>
'       <div class="rsopsummary">
'           <div class="he1b_expanded"><span class="sectionTitle" tabindex="0">
'        <a name="{Bookmark}">
'          <a name="{ProcessorName}">
'            Processor Name: <xsl:value-of select="ProcessorName"/>
'          </a>
'        </a>
'      </span><a class="expando" href="#"></a></div>
'
'      <div class="he2">
'        <span class="sectionTitle" tabindex="0">
'          Print Processor Properties
'        </span>
'        <a class="expando" href="#"></a>
'      </div>
'      <div class="container">
'               <div class="he4i"><table><xsl:for-each select="./Item"><xsl:variable name="name" select="@name"/><tr><td><xsl:value-of select="@name"/></td><td colspan="4"><xsl:value-of select="../Item[@name=$name]"/></td><td></td></tr></xsl:for-each></table>
'               </div>
'           </div>
'               <xsl:choose>
'               <xsl:when test="$CountPrinters &gt; 0">
'                   <div class="he2"><span class="sectionTitle" tabindex="0">Printers configured to use this print processor (<xsl:value-of select="$CountPrinters"/>)</span><a class="expando" href="#"></a></div>
'                   <div class="container"><div class="he4i">
'                       <xsl:for-each select="//Resource[Environment[Version[Drivers[Driver[Printers[Printer[translate(Item[@name='Print Processor'], 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')=$PrintProcessorName]]]]]]]">
'                           <div class="he15_expanded"><span class="sectionTitle" tabindex="0">
'                               <xsl:if test="Name"><xsl:value-of select="Name"/> - </xsl:if><xsl:value-of select="../LocationName"/>
'                           </span><a class="expando" href="#"></a></div>
'                           <xsl:for-each select="Environment/Version/Drivers/Driver[Printers[Printer[translate(Item[@name='Print Processor'], 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')=$PrintProcessorName]]]">
'                               <div class="he6_expanded"><span class="sectionTitle" tabindex="0">
'                                   Driver: <a href="#{Bookmark}">
'                  <xsl:value-of select="DriverName"/>
'                </a> (<xsl:value-of select="count(Printers/Printer[translate(Item[@name='Print Processor'], 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')=$PrintProcessorName])"/>)
'                               </span><a class="expando" href="#"></a></div>
'
'                               <div class="container"><div class="he4i"><table cellpadding="0" cellspacing="4">
'                                   <xsl:for-each select="Printers/Printer[translate(Item[@name='Print Processor'], 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')=$PrintProcessorName]">
'                                       <tr><td>
'                                           <xsl:value-of select="SessionTitle"/>
'                                       </td></tr>
'                                   </xsl:for-each></table>
'                               </div></div>
'                           </xsl:for-each>
'                           <div class="filler"></div>
'                       </xsl:for-each>
'                   </div></div>
'               </xsl:when>
'                   <xsl:otherwise><div class="he3noexpand"><span tabindex="0">No printers are configured to use this print processor</span></div></xsl:otherwise>
'               </xsl:choose>
'               </div>
'       <div class="filler"></div>
'   </xsl:for-each>
'</div>
'</div>
'</div>
'  <!-- Just some extra spaces here to be able to make the bookmark systems to better work -->
'  <br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/>
'</body>
'</html>
'</xsl:template>
'</xsl:stylesheet>
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
		           For iOffSet = 0 To 3
		                A4cvi(iOffSet) = A1cvi(iOffSet)
		           Next
		             VLocRes = GetNumFromBytes(A4cvi)
		           For iOffSet = 0 To 3
		                A4cvi(iOffSet) = A1cvi(iOffSet + 4)
		           Next
		             SizeRes = GetNumFromBytes(A4cvi) '--size of resource section in bytes.
		           For iOffSet = 0 To 3
		                A4cvi(iOffSet) = A1cvi(iOffSet + 8)
		           Next
		              LocRes = GetNumFromBytes(A4cvi)    '-- offset location of resource section.
		          Pt1cvi = InStr(1, sBcvi, ".aspack")   '-- find .rsrc table.
		             If (Pt1cvi > 0) Then
		                  BooAspack = True
		                      Pt1cvi = Pt1cvi + 12    '--  virtual offset is first 4 bytes; raw offset is bytes 9-12.
		                      A1cvi = GetArray(Mid(s1cvi, Pt1cvi, 12))
		                   For iOffSet = 0 To 3
		                      A4cvi(iOffSet) = A1cvi(iOffSet)
		                   Next
		                     VLocAspack = GetNumFromBytes(A4cvi)
		                   For iOffSet = 0 To 3
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
		        For iOffSet = 1 To iNum2cvi
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
		       For iNum1cvi = 0 To 2  '-- get offset number to next level from 2nd 4 bytes of entry structure.
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
		       For iNum1cvi = 0 To 3
		         A4cvi(iNum1cvi) = A1cvi(iNum1cvi)
		       Next
		           VIOffset = GetNumFromBytes(A4cvi)  '--offset of version info. given in .rsrc section.
		           ReadOffset = ((VIOffset - VLocRes) + LocRes)
		       For iNum1cvi = 0 To 3
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
		       ReDim A2cvi(Len(sStr) - 1)
		        For iLen = 1 To Len(sStr)
		            iA = Asc(Mid(sStr, iLen, 1))
		              If iA = 0 Then iA = 42  '-- converts 0-byte to *
		            A2cvi(iLen - 1) = Chr(iA)
		        Next
		   Else
		      ReDim A2cvi((Len(sStr) \ 2) - 1)
		       For iLen = 1 To Len(sStr) Step 2
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
		     For iA = 1 To Len1
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
		    If (Err.Number = 0) Then GetNumFromBytes = Num1
		End Function
End Class

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

'' SIG '' Begin signature block
'' SIG '' MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' ifLuHcYrBKXTki2sFMWz0T2A5Irda2xTmZjVz/Esi0mg
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
'' SIG '' ghl1MIIZcQIBATCBlTB+MQswCQYDVQQGEwJVUzETMBEG
'' SIG '' A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
'' SIG '' ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
'' SIG '' MSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5n
'' SIG '' IFBDQSAyMDExAhMzAAACU+OD3pbexW7MAAAAAAJTMA0G
'' SIG '' CWCGSAFlAwQCAQUAoIGwMBkGCSqGSIb3DQEJAzEMBgor
'' SIG '' BgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
'' SIG '' AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAaR8nqEbywuj+Q
'' SIG '' PyomW+pIAJ9l/UOFYloH8i+EgJaAxjBEBgorBgEEAYI3
'' SIG '' AgEMMTYwNKAUgBIATQBpAGMAcgBvAHMAbwBmAHShHIAa
'' SIG '' aHR0cHM6Ly93d3cubWljcm9zb2Z0LmNvbSAwDQYJKoZI
'' SIG '' hvcNAQEBBQAEggEAA23WXNslU+7T45jhu9G5JCKXL9U7
'' SIG '' cvqrKT/rPCssOJDjMPj93OEJDLEKrpValu2eQf3TKuF9
'' SIG '' cAXm/33R5CG4nKSElvCa+jgE/N2f2a5TVgz3BEcfRf7W
'' SIG '' o6xQAhPPzsczs9wVVDyIOQoeGS0hBoGOJlW0+1l15R4t
'' SIG '' KDrEL0EtbksTxgX7xIVrpoWggkUyeL2nw2fGB8vvA0Z2
'' SIG '' LQnKdSDRRaOyLhiZWamm4DhloBomcpDlybOopm6m9TgZ
'' SIG '' s4pB/3Bo3Mi72ItnnvL0EkGuUcHyImVLfzytCIUt0jJA
'' SIG '' TzYh13i6BBVCl1vICjeM4k8wWX8IKI/jhncERCPadaVW
'' SIG '' p8NfO6GCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCCFuUG
'' SIG '' CSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUD
'' SIG '' BAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIB
'' SIG '' OAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUA
'' SIG '' BCAna324W9hZSPZ+985i+/b+eY8IxTYJB7HtHJ2XPp6i
'' SIG '' 4QIGYhZfq3YVGBMyMDIyMDMyODE2NTU0Ny40MDFaMASA
'' SIG '' AgH0oIHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UE
'' SIG '' CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
'' SIG '' MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUw
'' SIG '' IwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRp
'' SIG '' b25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpFQUNF
'' SIG '' LUUzMTYtQzkxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
'' SIG '' bWUtU3RhbXAgU2VydmljZaCCEVQwggcMMIIE9KADAgEC
'' SIG '' AhMzAAABmsB1osQhbT6FAAEAAAGaMA0GCSqGSIb3DQEB
'' SIG '' CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
'' SIG '' aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
'' SIG '' ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
'' SIG '' HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4X
'' SIG '' DTIxMTIwMjE5MDUxN1oXDTIzMDIyODE5MDUxN1owgcox
'' SIG '' CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
'' SIG '' MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
'' SIG '' b3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jv
'' SIG '' c29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsT
'' SIG '' HVRoYWxlcyBUU1MgRVNOOkVBQ0UtRTMxNi1DOTFEMSUw
'' SIG '' IwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
'' SIG '' aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
'' SIG '' AgEA2nIGrCort2RhFP5q+gObfaFwIG7AiatDZzrvueM2
'' SIG '' T7fWP7axB0k5aRNp+I7muFZ2nROLH9jYPMX1MQ0DzuFW
'' SIG '' /91B4YXR4gpy6FCLFt8LRNjj8xxYQHFDc8bkqZOuu6Ju
'' SIG '' KPxnGj5cIiDeGXQ8Ujs+qI0jU/Ws7Cl8EBQHLuHPbbL1
'' SIG '' 4rpffbInwt7NnRBCdPwYch4iQMLHFODdp5tVA3+LjAHw
'' SIG '' tQe0gUGS99LLD8olI1O4CIo69SEZQQHQWJoskdBe0Sb8
'' SIG '' 8vnYsI5tCLI93/G7FSKvYGZFFscRZCmS3wcpXhKOATJk
'' SIG '' TGRPfgH06a0J3upnI7VQHQS0Sl714y0lz0eoeeKbbbEo
'' SIG '' SmldyD+g6em10X9hm9gn3VUsbctxxwFMmV7hcILiFdjl
'' SIG '' t4Bd5BUCt7i+kGbzfGuigdIbaNOlffDrXstTkzr59ZkZ
'' SIG '' wL1buFo/H9XXPvXDj3T4LRc+HHd+5kUTxJAHV9mGnk4K
'' SIG '' XDRMWvowmzkjfvlbTUnMcLuAIz6E30I7kPi9afEjGX4I
'' SIG '' E/JIWl2llmfby7zuzyMCGeG9kit/15lqZNAJmk4WuUBt
'' SIG '' H7ubr3eGGf8S7iP5IsB1nE8pL4gGTpcJK57KGGSSdN0b
'' SIG '' CAFr+lB52IwCPBt1IAhRZQJtJ4LkN6yF+eKZro0vN5YK
'' SIG '' 5tWKmy9i65YZovfDJNpLQhwlykcCAwEAAaOCATYwggEy
'' SIG '' MB0GA1UdDgQWBBRftp5Z8JzbUemlWb0KlcitNivRcDAf
'' SIG '' BgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
'' SIG '' BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jv
'' SIG '' c29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
'' SIG '' aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
'' SIG '' KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8v
'' SIG '' d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01p
'' SIG '' Y3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEw
'' SIG '' KDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoG
'' SIG '' CCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4ICAQAAE7uH
'' SIG '' zEbUR9tPpzcxgFxcXVxKUT032zNCyQ3jXuEAsY9BTPsK
'' SIG '' yXbulCqzNsELjt9VA3EOJ61CQXvNTeltkbxGvMTV42zt
'' SIG '' KszYrcFHzlS3maeh1RnDU7WBDALyvZP/9HWgRcW6dOAc
'' SIG '' zGiMmh0cu8vyv82fXJBMO4xfVbCapa8KpMfR6iPyAbAq
'' SIG '' SXZU7SgZf/i0Ww/LVr8OhQ60pL/yA4inGqzxNAVOv/2x
'' SIG '' V72ef4e3YhNd3ar+Qz1OSp+PfR71DgHBxt9YK/0yTxH7
'' SIG '' aqiuNHX6QftWwT0swHn+fKycUSVzSeutRmzmeXuuBLsi
'' SIG '' EL9FaOWabWlmYn7UOaYJs7WmQrjSCL8TxwsryAI5kn0b
'' SIG '' l+1MpHtJNva0k67kbAVSLInxt/YJXbG8ozr5Aze0t6Sb
'' SIG '' U8CVdE6AuFVoNNJKbp5O9jzkbqd9WoVvfX1N48QYdnx4
'' SIG '' 4nn42VGtPHf50EHS1gs2nbbaZGbwoB/3XPDLbNgsK3MQ
'' SIG '' j2eafVbhnKshYStiOj0tDzpzLn+9Ed5a5eWPO3TvH+Cr
'' SIG '' /N25IauYPiK2OSry3CBBEeZLebrqK6VsyZgTRgfutjlT
'' SIG '' TM/dmCRZfy7fjb5BhU7hmcvekyzD3S3KzUqTxleah6px
'' SIG '' 5a/8FM/VAFYkyiQK70m75P7IlO5otvaKkcW9GoQeKGFT
'' SIG '' zbr+3HB0wRqjTRqJeDCCB3EwggVZoAMCAQICEzMAAAAV
'' SIG '' xedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgx
'' SIG '' CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
'' SIG '' MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
'' SIG '' b3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jv
'' SIG '' c29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAy
'' SIG '' MDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIy
'' SIG '' NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
'' SIG '' bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
'' SIG '' FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
'' SIG '' TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIi
'' SIG '' MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM
'' SIG '' 57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/
'' SIG '' bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1
'' SIG '' jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhx
'' SIG '' XFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41
'' SIG '' JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP
'' SIG '' 1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3j
'' SIG '' tIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF
'' SIG '' 50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg
'' SIG '' 3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F
'' SIG '' 37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0
'' SIG '' lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlM
'' SIG '' jgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLX
'' SIG '' pyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJ
'' SIG '' YfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzF
'' SIG '' ER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+e
'' SIG '' FnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYB
'' SIG '' BAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS
'' SIG '' /mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0A
'' SIG '' XmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYB
'' SIG '' BAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93
'' SIG '' d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBv
'' SIG '' c2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZ
'' SIG '' BgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8E
'' SIG '' BAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAW
'' SIG '' gBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBN
'' SIG '' MEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20v
'' SIG '' cGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAx
'' SIG '' MC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsG
'' SIG '' AQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
'' SIG '' cGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIz
'' SIG '' LmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4Swf
'' SIG '' ZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518Jx
'' SIG '' Nj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6
'' SIG '' th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9I
'' SIG '' dQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq
'' SIG '' 95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBew
'' SIG '' VIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7
'' SIG '' bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa
'' SIG '' 2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzH
'' SIG '' VG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZ
'' SIG '' c9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakUR
'' SIG '' R6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+Crvs
'' SIG '' QWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKi
'' SIG '' excdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+AN
'' SIG '' uOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/
'' SIG '' OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQd
'' SIG '' VTNYs6FwZvKhggLLMIICNAIBATCB+KGB0KSBzTCByjEL
'' SIG '' MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
'' SIG '' EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
'' SIG '' c29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9z
'' SIG '' b2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMd
'' SIG '' VGhhbGVzIFRTUyBFU046RUFDRS1FMzE2LUM5MUQxJTAj
'' SIG '' BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZp
'' SIG '' Y2WiIwoBATAHBgUrDgMCGgMVAAG6rjJ1Ampv5uzsdVL/
'' SIG '' xjbNY5rvoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
'' SIG '' BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
'' SIG '' bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
'' SIG '' bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
'' SIG '' UENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDl7F60MCIY
'' SIG '' DzIwMjIwMzI5MDAyMDA0WhgPMjAyMjAzMzAwMDIwMDRa
'' SIG '' MHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOXsXrQCAQAw
'' SIG '' BwIBAAICAIUwBwIBAAICEiswCgIFAOXtsDQCAQAwNgYK
'' SIG '' KwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
'' SIG '' AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUF
'' SIG '' AAOBgQBJnAIEFXxRN0CfEk4JBngcVXskokmJIZHhCcqS
'' SIG '' GZDhqq05ixXO3b6smx/RMbW4cimyyGrznlRzaWc0pjw4
'' SIG '' NRTv4UuMA2oQQw+KndNzmHA6xi1k9NyDQtKjT7zEciO5
'' SIG '' xtZX+lAUKfVYyFGPDXGoun6StUqS3Kp+uuT640MndHsV
'' SIG '' 0DGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMw
'' SIG '' EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
'' SIG '' b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
'' SIG '' b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
'' SIG '' IFBDQSAyMDEwAhMzAAABmsB1osQhbT6FAAEAAAGaMA0G
'' SIG '' CWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYL
'' SIG '' KoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIAaIUi9y
'' SIG '' 1qwI5ola/4goF8VfQXP6fDm0IKICDfXx5UbcMIH6Bgsq
'' SIG '' hkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgAU5A4zgRFH2Z
'' SIG '' 5YoCYi+d/S8fp7K/zRVU5yhV9N9IjWAwgZgwgYCkfjB8
'' SIG '' MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
'' SIG '' bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
'' SIG '' cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
'' SIG '' b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAZrA
'' SIG '' daLEIW0+hQABAAABmjAiBCCVbFmvMKV/Li8Pi37OAn9v
'' SIG '' GawKdwu1GFqPZXnZd8f2dzANBgkqhkiG9w0BAQsFAASC
'' SIG '' AgC0CbZ2xSrUtn1HZwzEeUFk9wWxyylYgfdJ+Fi97h59
'' SIG '' zmXHZqJpknEeDMi7HDNTc5cmXnYRpaRYpb2HNfgkviNe
'' SIG '' FEpHJz1EINF5rxU+YT0vfN0srb41NJTbSPXCs6LjNhWH
'' SIG '' E0vUchhl9NGJayPWgCybClDxaxOjyByZSSx9Trk1FccQ
'' SIG '' t15UoiriT8qX8EXH4OOLwlZDC+hL3Xy5L552bJM7vFHx
'' SIG '' ynRzjwVDjSjBRFbbcrYkJd0JhqsOQTngm1E4a+vxPqTX
'' SIG '' X13caghI6bXLa2o9VeZV7Eyky6EKyBCBANJgU/JRSjsm
'' SIG '' TrewxB3JBJ+uGyO+pfKpAU6wVwi5u9yIB1F3TJpAQ0i1
'' SIG '' pezHRV/717sFgO0NFoGeDu1x+hzeEaRxR5jrNQohkCqL
'' SIG '' CCaSAV/EZil/TJnnsHmP/BMB4i9X5Ol5DewQUPgwGNPO
'' SIG '' Lg689ByGiLDQlOEemqXtJbPIcIYwBFQL+JmjcEQDChgX
'' SIG '' 7C1wCKoNFCLDAedPk0TrPPEsoO6Tba9VVhLCeoFFQc8M
'' SIG '' nkaAyhmMSdMx1d4t4vzyIRdTf3iuOa9M3+IVXr30EhjX
'' SIG '' uAv1/Ii6d+a40GKMJLr9/k1VAstem2iasPkp2RDm27x3
'' SIG '' TDokwxiTcUX1vC0Ng6EjLcslez2pSrGl5ecVu9VnGa6+
'' SIG '' uudkoicwkTAfBfwswN33Ki/NOw==
'' SIG '' End signature block
