'************************************************
'Autoruns.VBS
'Version 1.2.3
'Date: 03-14-2011
'Author: Andre Teixeira - andret@microsoft.com
'************************************************

Option Explicit
Dim objShell
Dim objFSO
Dim XMLOutputFileName, CSVOutputFileName
Dim UID
Dim OutputFormat

Const ForReading = 1, ForWriting = 2
Const OpenFileMode = -2

Main

Sub Main()
    
    On Error Resume Next
    
    wscript.Echo ""
    wscript.Echo "Autoruns Script"
    wscript.Echo "Revision 1.2.3"
    wscript.Echo "2008-2011 Microsoft Corporation"
    wscript.Echo ""
   
    Set objShell = CreateObject("WScript.Shell")
    Set objFSO = CreateObject("Scripting.FileSystemObject")
    If Len(objShell.Environment("PROCESS").Item("PROCESSOR_ARCHITEW6432")) > 0 Then 'Running in WOW, we need to make sure we start the 64 bit version
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
       
    Dim strTXTFile, strXMLFile, strOutputFolder, strArgument, strAutorunscPath, x
    
    On Error Resume Next
    
    strOutputFolder = objFSO.GetAbsolutePathName(".")
    XMLOutputFileName = objFSO.BuildPath(strOutputFolder, objShell.ExpandEnvironmentStrings("%COMPUTERNAME%") + "_Autoruns.XML")
    CSVOutputFileName = objFSO.BuildPath(strOutputFolder, objShell.ExpandEnvironmentStrings("%COMPUTERNAME%") + "_Autoruns.csv")
    
    strAutorunscPath = objFSO.GetAbsolutePathName(objFSO.BuildPath(objFSO.GetParentFolderName(wscript.ScriptFullName), "autorunsc.exe"))
    
    If wscript.Arguments.Count > 0 Then
        Dim bAutorunscPathFound
        bAutorunscPathFound = False
        For x = 0 To (wscript.Arguments.Count - 1)
            strArgument = wscript.Arguments(x)
            If objFSO.FolderExists(strArgument) Then
                If (objFSO.FileExists(objFSO.BuildPath(strArgument, "autorunsc.exe")) And (bAutorunscPathFound = False)) Then
                    strAutorunscPath = objFSO.GetAbsolutePathName(objFSO.BuildPath(strArgument, "autorunsc.exe"))
                    wscript.Echo "AutoRuns Path: '" + strAutorunscPath + "'"
                    bAutorunscPathFound = True
                Else
                    strOutputFolder = objFSO.GetAbsolutePathName(strArgument)
                    XMLOutputFileName = objFSO.BuildPath(strOutputFolder, objShell.ExpandEnvironmentStrings("%COMPUTERNAME%") + "_Autoruns.XML")
                    wscript.Echo "Output path: '" + strOutputFolder + "'"
                End If
            ElseIf (InStr(1, strArgument, "format:", vbTextCompare) > 0) Then
                OutputFormat = LCase(Right(strArgument, Len(strArgument) - InStr(strArgument, ":")))
            Else
                DisplayError "DoWork", 2, "Path does not exist: " + strArgument, "Error accessing ouput folder. Output folder set to local path."
                wscript.Echo "Output path: '" + strOutputFolder + "'"
            End If
        Next
    End If
    
    wscript.Echo "Running Sysinternals AutoRunsC..."
    If RunAutoRunsC(strAutorunscPath, "XML") Then
        wscript.Echo "Editing XML..."
        AddMissingXMLInfo
        If OutputFormat = "html" Then
            wscript.Echo "Editing Creating HTML file..."
            CreateHTMFile strOutputFolder
        End If
    End If
    
    If OutputFormat = "csv" Then
        wscript.Echo "Creating CSV file..."
        CreateCSVFile strAutorunscPath, strOutputFolder
    End If
    
End Function

Function CreateCSVFile(strAutorunscPath, strOutputFolder)
    RunAutoRunsC strAutorunscPath, "csv"
End Function

Function RunAutoRunsC(AutorunscExePath, OutputFormat)
    On Error Resume Next
    Dim intReturn, intEulaAccepted
    Dim strCommandLine, objXMLFile, strStdout
        
    Err.Clear
    intEulaAccepted = 0
    intEulaAccepted = objShell.RegRead("HKCU\Software\Sysinternals\AutoRuns\EulaAccepted")
    If (intEulaAccepted = 0) Then
        wscript.Echo "Creating EULA Key..."
        objShell.RegWrite "HKCU\Software\Sysinternals\AutoRuns\EulaAccepted", 1, "REG_DWORD"
    End If
    
    Err.Clear
    If objFSO.FileExists(AutorunscExePath) Then
        If OutputFormat = "csv" Then
            strCommandLine = objShell.ExpandEnvironmentStrings("%windir%\System32\CMD.EXE") + " /s /c " & Chr(34) & Chr(34) & AutorunscExePath & Chr(34) & " -a -c > " & Chr(34) & CSVOutputFileName & Chr(34) & Chr(34)
        Else
            strCommandLine = objShell.ExpandEnvironmentStrings("%windir%\System32\CMD.EXE") + " /s /c " & Chr(34) & Chr(34) & AutorunscExePath & Chr(34) & " -a -x -v > " & Chr(34) & XMLOutputFileName & Chr(34) & Chr(34)
        End If
        wscript.Echo "Running autorunsc.exe..."
        intReturn = objShell.Run(strCommandLine, 0, True)
        If intReturn <> 0 Then
            RunAutoRunsC = False
            DisplayError "RunAutorunsC", intReturn, "Run AutoRunsSC", "An error ocurred running: " + strCommandLine
        Else
            RunAutoRunsC = True
        End If
    Else
        RunAutoRunsC = False
        DisplayError "RunAutorunsC", 2, "Run AutoRunsSC", "Path not found: " + AutorunscExePath
    End If
    
    If (intEulaAccepted = 0) Then
        'Delete EulaAccepted value since it did not exist before
        objShell.RegDelete "HKCU\Software\Sysinternals\AutoRuns\EulaAccepted"
        wscript.Echo "Removing EULA Key..."
    End If

End Function

Function HexFormat(intNumber)
    HexFormat = Right("00000000" & CStr(Hex(intNumber)), 8)
End Function

Sub AddMissingXMLInfo()
    Dim XMLDoc
    Dim XMLDoc2
    Dim objDataElement, objAutorunsElement
    
    On Error Resume Next
    
    Set XMLDoc = CreateObject("Microsoft.XMLDOM")
    XMLDoc.Load XMLOutputFileName
    If CheckForXMLError(XMLDoc) = 0 Then
        Set objAutorunsElement = XMLDoc.selectNodes("/autoruns").Item(0)
        
        Set XMLDoc2 = CreateObject("Microsoft.XMLDOM")
        XMLDoc2.async = "false"
        XMLDoc2.loadXML "<?xml version=""1.0""?><DiagInfo><MachineName>" & objShell.ExpandEnvironmentStrings("%COMPUTERNAME%") & "</MachineName><TimeField>" & Now & "</TimeField></DiagInfo>"
        Set objDataElement = XMLDoc2.selectNodes("/DiagInfo").Item(0)
        
        objAutorunsElement.appendChild objDataElement
        XMLDoc.Save XMLOutputFileName
    End If
End Sub

Function CheckForXMLError(xmlFile)
    Dim strErrText
        If (Err.Number <> 0) Or (xmlFile.parseError.errorCode <> 0) Then
            If Err.Number <> 0 Then
                DisplayError "Adding PLA Alert.", Err.Number, Err.Source, Err.Description
                CheckForXMLError = Err.Number
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
                    CheckForXMLError = .errorCode
                End With
                DisplayError "Processing or loading XML File.", 5000, "BuildingXML", strErrText
            End If
        Else
            CheckForXMLError = 0
        End If
End Function

Function RunScriptin64BitMode()
    On Error Resume Next
    Dim strCmdArguments
    Dim strStdOutFilename
    Dim objStdOutFile
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
        ProcessCreate objShell.ExpandEnvironmentStrings("%windir%\System32\CMD.EXE"), strCmdArguments
        If objFSO.FileExists(strStdOutFilename) Then
            Set objStdOutFile = objFSO.OpenTextFile(strStdOutFilename, ForReading, False, OpenFileMode)
            While Not objStdOutFile.AtEndOfStream
                wscript.Echo objStdOutFile.ReadLine
            Wend
            objStdOutFile.Close
            Set objStdOutFile = Nothing
            objFSO.DeleteFile strStdOutFilename, True
            If Err.Number = 0 Then
                RunScriptin64BitMode = True
            End If
        Else
            wscript.Echo "An error ocurred running the command and resulting file was not created:"
            wscript.Echo objShell.ExpandEnvironmentStrings("%windir%\System32\CMD.EXE") & strCmdArguments
            wscript.Echo ""
            wscript.Echo ""
            RunScriptin64BitMode = False
        End If
    Else
        RunScriptin64BitMode = False
    End If
End Function


Sub DisplayError(strErrorLocation, errNumber, errSource, errDescription)
    On Error Resume Next
    wscript.Echo ""
    If errNumber <> 0 Then
        wscript.Echo "Error 0x" & HexFormat(errNumber) & iif(Len(strErrorLocation) > 0, ": " & strErrorLocation, "")
        wscript.Echo errSource & " - " & errDescription
    Else
        wscript.Echo "An error has ocurred!. " & iif(Len(strErrorLocation) > 0, ": " & strErrorLocation, "")
    End If
    wscript.Echo ""
End Sub

Function iif(Expression, Truepart, Falsepart)
    If Expression Then
        iif = Truepart
    Else
        iif = Falsepart
    End If
End Function

Function ShellExec(strCommandLine, ByRef strStdout)
        
    Dim objStdOutFile, strLine, intNumLines, objExec
    
    On Error Resume Next
    Set objExec = objShell.Exec(strCommandLine)
    
    While objExec.Status = 0
        wscript.Sleep 400
    Wend
    
    strStdout = objExec.StdOut.ReadAll
    
    ShellExec = objExec.ExitCode
    
    If Err.Number <> 0 Then
        DisplayError "Running command line '" & strCommandLine & "'", Err.Number, "ShellExec", Err.Description
        ShellExec = Err.Number
    ElseIf (ShellExec <> 0) Then
        DisplayError "Running command line '" & strCommandLine & "'", ShellExec, "ShellExec", objExec.StdErr.ReadAll
    ElseIf strStdout = "" Then
        DisplayError "Running command line '" & strCommandLine & "'", ShellExec, "ShellExec", "Command Did not return any results"
    End If
        
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

Sub CreateHTMFile(strOutputFolderName)
    On Error Resume Next
    Dim strErrText
    Err.Clear
    
    Dim strHTMLFileName, objHTMLFile, xmlStylesheet, xmlStylesheetPath, xmlFile, strXmlFilePath
        
    strXmlFilePath = XMLOutputFileName
        
    strHTMLFileName = objFSO.BuildPath(objFSO.GetAbsolutePathName(strOutputFolderName), objShell.Environment("PROCESS").Item("COMPUTERNAME") & _
                                                    "_Autoruns.htm")
        
    If ExtractEmbeddedXSL(xmlStylesheetPath) Then
    
        Set xmlStylesheet = CreateObject("Microsoft.XMLDOM")
        Set xmlFile = CreateObject("Microsoft.XMLDOM")
        
        xmlFile.Load strXmlFilePath
        
        If CheckForXMLError(xmlFile) = 0 Then
    
            xmlStylesheet.Load xmlStylesheetPath
        
            If CheckForXMLError(xmlStylesheet) <> 0 Then
                objFSO.DeleteFile xmlStylesheetPath, True
                Exit Sub
            End If
        Else
            Exit Sub
        End If
        
        wscript.Echo "Building file: '" & objFSO.GetFileName(strHTMLFileName) & "'"
        Set objHTMLFile = objFSO.OpenTextFile(strHTMLFileName, ForWriting, True, OpenFileMode)
    
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
        
        objFSO.DeleteFile xmlStylesheetPath, True
        'objFSO.DeleteFile strXmlFilePath, True
        If Err.Number <> 0 Then
            DisplayError "Error deleting files " & strXmlFilePath & "/ " & xmlStylesheetPath & ".", Err.Number, Err.Source, Err.Description
            Exit Sub
        End If
    End If
End Sub

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
'<xsl:key name="LocationKey" match="item" use="location" />
'
'<xsl:template match="/autoruns">
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
'  .he0_expanded    { background-color:#FEF7D6; border:1px solid #BBBBBB; color:#3333CC; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:120%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%;
'  filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=1,StartColorStr='#FEF7D6',EndColorStr='white');}}
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
'  .rsopheader { background-color:#A0BACB; border-bottom:1px solid black; color:#333333; font-family:MS Shell Dlg; font-size:130%; font-weight:bold; padding-bottom:5px; text-align:center;
'  filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=0,StartColorStr='#FFFFFF',EndColorStr='#A0BACB')}
'
'  .lines0                           {background-color: #F5F5F5;}
'  .lines1                           {background-color: #F9F9F9;}
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
'  #showhideMS { color:#000000; cursor:pointer; font-family:MS Shell Dlg; font-size:100%; margin-right:0px; padding-right:10px; text-align:right; z-index:2; word-wrap:normal;}
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
'strShowHide = 0
'
''Localized strings
'strShow = "show"
'strHide = "hide"
'strShowAll = "expand all"
'strHideAll = "collapse all"
'strShown = "shown"
'strHidden = "hidden"
'strExpandoNumPixelsFromEdge = "10px"
'
'Function IsSectionHeader(obj)
'    IsSectionHeader = (obj.className = "showHideMS") Or (obj.className = "he0a") Or (obj.className = "he0a_expanded") or (obj.className = "he5_expanded") Or (obj.className = "he6_expanded") Or (obj.className = "he7_expanded") Or (obj.className = "he1_expanded") Or (obj.className = "he1a_expanded") Or (obj.className = "he1b_expanded") Or (obj.className = "he1") Or (obj.className = "he2") Or (obj.className = "he3") Or (obj.className = "he4") Or (obj.className = "he4h") Or (obj.className = "he5") Or (obj.className = "he5h")  or (obj.className = "he4_expanded")
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
'    While (strsrc.className = "sectionTitle" Or strsrc.className = "expando" Or strsrc.className = "vmlimage" or strsrc.className = "showhideMS")
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
'Function CheckboxMS_Toggle()
'    Set objBody = document.body.all
'    Select Case CheckboxMS.checked
'        Case false
'            For Each obji In objBody
'                If (instr(1, obji.className, "MSSignedtrue") > 0) Then
'                    obji.style.display = "none"
'                End If
'            Next
'            For each obji in objBody
'                If (obji.className = "he1b_expanded") Then
'                        i = obji.sourceIndex
'                        Set objChildren = obji.parentElement.GetElementsByTagName ("*")
'                        HasVisibleItem = false
'                        for each objContainer in objChildren
'                          if (instr(1, objContainer.className, "MSSignedfalse") > 0) then
'                                HasVisibleItem = true
'                          end if
'                        next
'                        if not HasVisibleItem then 
'                          set objToHide = obji.parentElement
'                          objToHide.style.display = "none"
'                        end if
'                End If
'            Next
'        Case true
'            For Each obji In objBody
'                If (instr(1, obji.className, "MSSignedtrue") > 0) Then
'                    obji.style.display = "block"
'                End If
'                If obji.className = "rsopsummary" then
'                  if obji.style.display = "none" then
'                    obji.style.display = "block"
'                  end if
'                end if 
'            Next
'    End Select
'End Function
'
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
'        objshowhide.innerText = strHideAll
'        showhideMS.style.visibility = "visible"
'        CheckboxMS.checked = true
'
'        document.documentElement.setAttribute "gpmc_reportInitialized", "true"
'    End If
'End Function
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
'                    Case "#objshowhide", "#showhideMS"
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
'Function showhideMS_onClick()
'  CheckboxMS.checked = not (CheckboxMS.checked)
'  CheckboxMS_Toggle()
'End Function
'
'Function CheckboxMS_onClick()
'  CheckboxMS.checked = not (CheckboxMS.checked)
'  CheckboxMS_Toggle()
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
'  <table class="title" cellpadding="0" cellspacing="0">
'	<tr><td colspan="2" class="rsopheader">AutoRuns information</td></tr>
'	<tr><td class="rsopname">Machine name: <xsl:value-of select="DiagInfo/MachineName"/></td>
'    <td id="showhideMS" style="visibility:hidden;cursor:pointer;">
'      <div>
'      Show Signed Microsoft Components<input id="CheckboxMS" type="checkbox" checked="true" ReadOnly="true"/>
'      </div>
'    </td>
'  </tr>
'	<tr><td id="dtstamp">Data collected on: <xsl:value-of select="DiagInfo/TimeField"/></td>
'    <td><div id="objshowhide" tabindex="0" /></td></tr>
'	</table>
'  <div class="filler"></div>
'
'  <div class="container">
'
'<div class="rsopsettings">
'<div class="he0_expanded"><span class="sectionTitle" tabindex="0">Auto Run Information</span>
'  <a class="expando" href="#"></a>
'</div>
'<div class="container">
'  <xsl:for-each select="//item[generate-id(.)=generate-id(key('LocationKey',location))]">
'    <xsl:variable name="CurrentLocation" select="location" />
'    <div class="rsopsummary">
'      <div class="he1b_expanded">
'        <span class="sectionTitle" tabindex="0">
'          <a name="{Bookmark}">
'            <a name="{ProcessorName}">
'              <xsl:value-of select="location"/>
'            </a>
'          </a>
'        </span>
'        <a class="expando" href="#"></a>
'      </div>
'
'      <div class="container">
'        <div class="he4i">
'          <table cellpadding="0" class="info4">
'            <table cellpadding="0" class="infoqfe" >
'              <tr>
'                <th>Name</th>
'                <th>Path</th>
'                <th>Version</th>
'                <th>Company</th>
'                <th>Signer</th>
'              </tr>
'              <xsl:for-each select="//item[location=$CurrentLocation]">
'                <xsl:variable name="SignedByMS" select="(contains (signer, 'Microsoft')) and (contains (signer, '(Verified)'))" />
'                <xsl:variable name="pos" select="position()" />
'                <xsl:variable name="mod" select="($pos mod 2)"/>
'                <tr class="MSSigned{$SignedByMS}" title="{description}">
'                  <td class="lines{$mod}">
'                    <xsl:value-of select="itemname"/>
'                  </td>
'                  <td class="lines{$mod}">
'                    <xsl:value-of select="launchstring"/>
'                  </td>
'                  <td class="lines{$mod}">
'                    <xsl:value-of select="version"/>
'                  </td>
'                  <td class="lines{$mod}">
'                    <xsl:value-of select="company"/>
'                  </td>
'                  <td class="lines{$mod}">
'                    <xsl:value-of select="signer"/>
'                  </td>
'                </tr>
'              </xsl:for-each>
'            </table>
'          </table>
'        </div>
'      </div>
'      <div class="filler"></div>
'    </div>
'	</xsl:for-each>
'</div>
'</div>
'</div>
'</body>
'</html>
'</xsl:template>
'</xsl:stylesheet>
End Sub

'' SIG '' Begin signature block
'' SIG '' MIInvgYJKoZIhvcNAQcCoIInrzCCJ6sCAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' Gya0Rl0aIxAahqA2yWvxgmlwzRYL9IB607DsM726tMSg
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
'' SIG '' ghmRMIIZjQIBATCBlTB+MQswCQYDVQQGEwJVUzETMBEG
'' SIG '' A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
'' SIG '' ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
'' SIG '' MSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5n
'' SIG '' IFBDQSAyMDExAhMzAAACU+OD3pbexW7MAAAAAAJTMA0G
'' SIG '' CWCGSAFlAwQCAQUAoIGwMBkGCSqGSIb3DQEJAzEMBgor
'' SIG '' BgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
'' SIG '' AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCB4fUPu29YNaWXE
'' SIG '' qFOXyeN57EAJvXfJBUhosaR+QNGh7jBEBgorBgEEAYI3
'' SIG '' AgEMMTYwNKAUgBIATQBpAGMAcgBvAHMAbwBmAHShHIAa
'' SIG '' aHR0cHM6Ly93d3cubWljcm9zb2Z0LmNvbSAwDQYJKoZI
'' SIG '' hvcNAQEBBQAEggEAE0Q7LdjvpASTKs4jcCkY+rKsPc9T
'' SIG '' jeEAIoHU/C0VXImH721iKHddK/KJAy4/01OigtKzN2U8
'' SIG '' 4QGDB4wLR0UXCRNhfueYzmq20/YWlNqgUnylLw7zGq3z
'' SIG '' p3doWHd6YognAT+Ikny/uARKn8bALB2QaBTMVI2eUznj
'' SIG '' HPf+uQqO0dXoHIPQm+Vx+0bU5Fb3jEnjX0AmQs0fitGz
'' SIG '' dUQql1zV7JxZjlcoFSietYjCXq+Ta12nPYOFevs2NrP/
'' SIG '' xVXFeC7N27FEewnLjd2E79dAjpt4tbCFDkJjSltE4R5f
'' SIG '' oYzCa0Ne00yFfCmt0aszoru4BHG0NpguvbbNFmrBrBlH
'' SIG '' MIFFb6GCFxkwghcVBgorBgEEAYI3AwMBMYIXBTCCFwEG
'' SIG '' CSqGSIb3DQEHAqCCFvIwghbuAgEDMQ8wDQYJYIZIAWUD
'' SIG '' BAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIB
'' SIG '' QAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUA
'' SIG '' BCAjBougT8LUwyk4+A8Mbhqmbo7aUzsNJnfVWcakZXYV
'' SIG '' XwIGYheYMQY8GBMyMDIyMDMyODE2NTUwNy40MDlaMASA
'' SIG '' AgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UE
'' SIG '' CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
'' SIG '' MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0w
'' SIG '' KwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRp
'' SIG '' b25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
'' SIG '' RVNOOkZDNDEtNEJENC1EMjIwMSUwIwYDVQQDExxNaWNy
'' SIG '' b3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIRaDCCBxQw
'' SIG '' ggT8oAMCAQICEzMAAAGOWdtGAKgQlMwAAQAAAY4wDQYJ
'' SIG '' KoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNV
'' SIG '' BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
'' SIG '' HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
'' SIG '' MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
'' SIG '' IDIwMTAwHhcNMjExMDI4MTkyNzQ1WhcNMjMwMTI2MTky
'' SIG '' NzQ1WjCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
'' SIG '' c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
'' SIG '' BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UE
'' SIG '' CxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBM
'' SIG '' aW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpG
'' SIG '' QzQxLTRCRDQtRDIyMDElMCMGA1UEAxMcTWljcm9zb2Z0
'' SIG '' IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcN
'' SIG '' AQEBBQADggIPADCCAgoCggIBAKojAqujjMy2ucK7XH+w
'' SIG '' X/X9Vl1vZKamzgc4Dyb2hi62Ru7cIMKk0Vn9RZI6SSgT
'' SIG '' huUDyEcu2uiBVQMtFvrQWhV+CJ+A2wX9rRrm8mPfoUVP
'' SIG '' oUXsDyR+QmDr6T4e+xXxjOt/jpcEV6eWBEerQtFkSp95
'' SIG '' q8lqbeAsAA7hr9Cw9kI54YYLUVYnbIg55/fmi4zLjWqV
'' SIG '' IbLRqgq+yXEGbdGaz1B1v06kycpnlNXqoDaKxG03nelE
'' SIG '' Mi2k1QJoVzUFwwoX2udup1u0UOy+LV1/S3NKILogkpD5
'' SIG '' buXazQOjTPM/lF0DgB8VXyEF5ovmN0ldoa9nXMW8vZ5U
'' SIG '' 82L3+GQ6+VqXMLe7U3USCYm1x7F1jCq5js4pYhg06C8d
'' SIG '' +Gv3LWRODTi55aykFjfWRvjsec0WqytRIUoWoTNLkDYW
'' SIG '' +gSY6d/nNHjczBSdqi2ag6dv92JeUPuJPjAxy04qT+lQ
'' SIG '' XcXHVX3eJoK1U8d2nzuSjX4DJ4Bhn4UmsBq2kVtvBIay
'' SIG '' zrKZiMYovdhO7453CdrXI4SwowQK1aT4d3GRuYN2VcuY
'' SIG '' ogGqA2rMKTYJzBQCuVJ9a3ivjBYT4vYjJ71D8LUwwybe
'' SIG '' WBA+QwE95gVMaeUB97e0YWcACTS1i7aU3hhe7m/NbEim
'' SIG '' L9mq3WswHvVy0tdLVdqDj63J4hic5V1u1T78akDcXvJQ
'' SIG '' gwNtAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQU7EH5M/YE
'' SIG '' +ODf+RvLzR2snqfmleQwHwYDVR0jBBgwFoAUn6cVXQBe
'' SIG '' Yl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZO
'' SIG '' aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
'' SIG '' cmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
'' SIG '' MDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggr
'' SIG '' BgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
'' SIG '' L3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0
'' SIG '' YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/
'' SIG '' BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
'' SIG '' 9w0BAQsFAAOCAgEANVCvccyHk5SoUmy59G3pEeYGIemw
'' SIG '' dV0KZbgqggNebJGd+1IpWhScPPhpJQy85TYUj9pjojs1
'' SIG '' cgqvJJKap31HNNWWgXs0MYO+6nr49ojMoN/WCX3ogiIc
'' SIG '' WDhboMHqWKzzvDJQf6Lnv1YSIg29XjWE5T0pr96WpbIL
'' SIG '' ZK29KKNBdLlpl+BEFRikaNFBDbWXrVSMWtCfQ6VHY0Fj
'' SIG '' 3hIfXBDPkYBNuucOVgFW/ljcdIloheIk2wpq1mlRDl/d
'' SIG '' nTagZvW09VO5xsDeQsoKTQIBGmJ60zMdTeAI8TmwAgze
'' SIG '' Q3bxpbvztA3zFlXOqpOoigxQulqV0EpDJa5VyCPzYaft
'' SIG '' Pp6FOrXxKRyi7e32JvaH+Yv0KJnAsKP3pIjgo2JLad/d
'' SIG '' 6L6AtTtri7Wy5zFZROa2gSwTUmyDWekC8YgONZV51VSy
'' SIG '' Mw4oVC/DFPQjLxuLHW4ZNhV/M767D+T3gSMNX2npzGbs
'' SIG '' 9Fd1FwrVOTpMeX5oqFooi2UgotZY2sV/gRMEIopwovrx
'' SIG '' OfW02CORW7kfLQ7hi4lbvyUqVRV681jD9ip9dbAiwBhI
'' SIG '' 6iWFJjtbUWNvSnex3CI9p4kgdD0Dgo2JZwp8sJw4p6kt
'' SIG '' Ql70bIrI1ZUtUaeE5rpLPqRsYjBsxefM3G/oaBSsjjbi
'' SIG '' 92/rYMUwM97BdwVV/bpPTORfjhKHsi8hny3pDQIwggdx
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
'' SIG '' U02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC1zCCAkAC
'' SIG '' AQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEG
'' SIG '' A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
'' SIG '' ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
'' SIG '' MS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVy
'' SIG '' YXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBU
'' SIG '' U1MgRVNOOkZDNDEtNEJENC1EMjIwMSUwIwYDVQQDExxN
'' SIG '' aWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEw
'' SIG '' BwYFKw4DAhoDFQA9YivqT04R6oKWucbD5omK7llbjKCB
'' SIG '' gzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
'' SIG '' YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
'' SIG '' VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
'' SIG '' BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
'' SIG '' MA0GCSqGSIb3DQEBBQUAAgUA5exETjAiGA8yMDIyMDMy
'' SIG '' ODIyMjcyNloYDzIwMjIwMzI5MjIyNzI2WjB3MD0GCisG
'' SIG '' AQQBhFkKBAExLzAtMAoCBQDl7EROAgEAMAoCAQACAgo4
'' SIG '' AgH/MAcCAQACAhFQMAoCBQDl7ZXOAgEAMDYGCisGAQQB
'' SIG '' hFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMH
'' SIG '' oSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEA
'' SIG '' A8yvgm6GlZk68pvEacpS376mrQc8Y5goxpjbyK5Ond74
'' SIG '' OdYSQAquyR2DxSXOdQ21QxFClYqU8kBD1Bc3OY7RD3cH
'' SIG '' /n355oVSTuRDuN02H1Lcnye7dl0R3gQoqSySjopbFJDZ
'' SIG '' 3X1IA/8Dnue7zoOQDw7C6qDcP6b4YuBAv77pldsxggQN
'' SIG '' MIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UE
'' SIG '' CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
'' SIG '' MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
'' SIG '' JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
'' SIG '' MjAxMAITMwAAAY5Z20YAqBCUzAABAAABjjANBglghkgB
'' SIG '' ZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3
'' SIG '' DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCDoIAw48StH5LBV
'' SIG '' 2BPNsI2sBjfc48Og9ZAn/rSuDZYkITCB+gYLKoZIhvcN
'' SIG '' AQkQAi8xgeowgecwgeQwgb0EIL0FjyE74oGlLlefn/5V
'' SIG '' rNwV2cCf5dZn/snpbuZ15sQlMIGYMIGApH4wfDELMAkG
'' SIG '' A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
'' SIG '' BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
'' SIG '' dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
'' SIG '' IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGOWdtGAKgQ
'' SIG '' lMwAAQAAAY4wIgQgKpW6BS2JXlhKfuttWGpsE4a3KjXE
'' SIG '' q0i2d1X7VodoO20wDQYJKoZIhvcNAQELBQAEggIAeF+u
'' SIG '' 2rJOm+gMt5RDfqtDIwMqqd1cJskJgDENQ/unkyvb6GCv
'' SIG '' +C/JLehdFBzNgiqobO32sXH1VDstYey6icG0RjzcamAJ
'' SIG '' w0t9xVNPqdM1LT3WrtbLSbnZLynGyblEHKstL4Udq66O
'' SIG '' 3V0WRj1AXSqu0cRRjgtheQYGa9Xa7mMlzOi6kiD1H8cZ
'' SIG '' NKVny5v/wuYsPqwVUfSOr7sGi+kn7Mnxh+F04q323lub
'' SIG '' QCmeiVbhgMTzq/QY5240lrfGsA8U9r6KiApuWOiUlGo0
'' SIG '' BdhaMhWkq+s9KaciY10ZNalBgKX93EpKHuQj1NkArWYd
'' SIG '' XmU4aZLWd6FWqQENFp3jGaZK9aGleixYT2U4vXPCZ7hi
'' SIG '' 86PDU5d6WRPTN/7/+elHFg4X2/MeOvpg5SHjZmYkDbXp
'' SIG '' WbDfm6kfYpVJyHNdQXW28b74EnztOtxOoxn+0h499L19
'' SIG '' xsP5OJ0vnX/KUhe17LUD0b1QrY+LD1kx5N1bidQeVv27
'' SIG '' bgY2rN/LEowPhjHHLEwE9JY/tDVPKEkXxxebKAybRmKQ
'' SIG '' m/QIMNj8LH6hPQg+j6k7y01FyBauyQBmkjUXvdnvnQjt
'' SIG '' YUK4SzwuPeMO8kchgSD5EnZMc/vUjYbJuH8NIDmQXOLi
'' SIG '' 9i5xeClSvVQSHr9gcjb5n+bReJKIjVUQatajHI+iiExE
'' SIG '' GC3gZX0Yuz0rSYCiHLQ=
'' SIG '' End signature block
