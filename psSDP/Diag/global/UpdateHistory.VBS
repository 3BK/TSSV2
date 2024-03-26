'************************************************
'UpdateHistory.VBS
'Version 2.4.5
'Date: 02-05-2011
'Author: Andre Teixeira - andret@microsoft.com
'************************************************
'Last Updated Date: 05-23-2012
'Updated By: Alec Yao     v-alyao@microsoft.com
'Description: The FileName(CSV,XML,TXT) was hardcode in the vbscripts.It could not match the name in DC_UpdateHistory.ps1
'Change the logic and put in an argument which can identifiy the filename.
'************************************************

Option Explicit
Dim objShell
Dim objFSO
Dim objWMIService, objWMIReg

Dim objXMLFile
Dim objCSVFile

Dim objTXTFile, intCurrentTzBias

Const adDBTimeStamp = 135
Const adVarChar = 200

Const Fixed = 2, Removable = 1, ForReading = 1, ForWriting = 2

Const adWriteLine = 1, adTypeText = 2, adSaveCreateOverWrite = 2

Dim colQFEItems
Dim arrQFEFixesListed

Main

Sub Main()

    wscript.Echo ""
    wscript.Echo "Update History Script"
    wscript.Echo "Revision 2.4.5"
    wscript.Echo "2008-2011 Microsoft Corporation"
    wscript.Echo ""
    
    Set objShell = CreateObject("WScript.Shell")
    Set objFSO = CreateObject("Scripting.FileSystemObject")
        
    If ValidateArguments Then
        wscript.Echo "Querying a list of updates installed..."
        intCurrentTzBias = ObtainTimeZoneBias
        
        wscript.Echo ""
        
        Dim strCSVFileName, strTXTFilename, strXMLFile

'************************************************
'Get the argument
'************************************************
        Dim objArgs 
        Set objArgs = WScript.Arguments
        Dim ArguFileName
        If (objArgs.Count >= 1) Then
            ArguFileName = objArgs(0)
            strCSVFileName = ArguFileName & ".CSV"                                
            strTXTFilename = ArguFileName & ".TXT"
            strXMLFile = objFSO.GetAbsolutePathName(".") & "\" &ArguFileName & ".XML"
        Else
            strCSVFileName = objShell.Environment("PROCESS").Item("COMPUTERNAME") & _
                                                "_Hotfixes.CSV"                        
            strTXTFilename = objShell.Environment("PROCESS").Item("COMPUTERNAME") & _
                                                "_Hotfixes.TXT"
            strXMLFile = objFSO.GetAbsolutePathName(".") & "\" & objShell.Environment("PROCESS").Item("COMPUTERNAME") & _
             "_Hotfixes.XML"
        End If
'************************************************

        Set objCSVFile = CreateADODBStream()
        Set objTXTFile = CreateADODBStream()
        
        'Adding header to CSV file
        objCSVFile.WriteText Chr(34) & "Category" & Chr(34) & "," & _
                            Chr(34) & "Level" & Chr(34) & "," & _
                            Chr(34) & "ID" & Chr(34) & "," & _
                            Chr(34) & "Operation" & Chr(34) & "," & _
                            Chr(34) & "Date" & Chr(34) & "," & _
                            Chr(34) & "Client" & Chr(34) & "," & _
                            Chr(34) & "By" & Chr(34) & "," & _
                            Chr(34) & "Result" & Chr(34) & "," & _
                            Chr(34) & "Title" & Chr(34) & vbCrLf

        Set objXMLFile = objFSO.CreateTextFile(strXMLFile, True, True)
        
        objXMLFile.WriteLine "<?xml version='1.0' encoding='UTF-16'?>"
        objXMLFile.WriteLine "<Root>"
        
        OpenTag ("Updates")
        OpenWMIService
        wscript.Echo "   Querying IUpdateSession Interface..."
        DumpHistoryInformation
        wscript.Echo "   Querying Win32_QuickFixEngineering to obtain updates that are not on update history..."
        DumpNonHistoryQFEFixes
        wscript.Echo ""
        CloseTag ("Updates")

        objXMLFile.WriteLine "</Root>"
        objXMLFile.Close
        Set objXMLFile = Nothing
        
        GenerateHTMFile
        
        wscript.Echo ("Writing file '" & strCSVFileName & "'.")
        CloseSaveADODBStream objCSVFile, strCSVFileName
        
        wscript.Echo ("Writing file '" & strTXTFilename & "'.")
        CloseSaveADODBStream objTXTFile, strTXTFilename
        
        Set objTXTFile = Nothing
        Set objCSVFile = Nothing
        
    Else
        MissingParameters
    End If

    wscript.Echo ""
    wscript.Echo "****** Script Finished ******"
End Sub

Sub OpenTag(strTag)
    objXMLFile.WriteLine "<" & strTag & ">"
End Sub

Sub CloseTag(strTag)
    objXMLFile.WriteLine "</" & strTag & ">"
End Sub

Function TranslateXMLChars(strRAWString)
    strRAWString = Replace(strRAWString, "&", "&amp;")
    strRAWString = Replace(strRAWString, "<", "&lt;")
    strRAWString = Replace(strRAWString, ">", "&gt;")
    strRAWString = Replace(strRAWString, "'", "&apos;")
    strRAWString = Replace(strRAWString, Chr(34), "&quot;")
    TranslateXMLChars = strRAWString
End Function


Function CreateADODBStream()
    Dim objStream
    Set objStream = CreateObject("ADODB.Stream")
    objStream.Open
    objStream.Position = 0
    objStream.Type = adTypeText
    objStream.Charset = "UTF-8"
    Set CreateADODBStream = objStream
End Function

Function CloseSaveADODBStream(objStream, strFilename)
    objStream.SaveToFile strFilename, adSaveCreateOverWrite
    objStream.Close
End Function

Function ValidateArguments()
    ValidateArguments = True
End Function

Sub MissingParameters()

End Sub

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

Function GetDateInstallDateFromRegistry(HotfixID)
    'Try to obtain Information from Install Date in Registry from a given Hotfix ID. This happens usually in Windows 2000
    
    On Error Resume Next
    Const UpdatesKEY = "SOFTWARE\Microsoft\Updates"
    Dim arrProducts, strProduct, arrSPLevel, strSPLevel, arrFixes, strFix
    
    GetDateInstallDateFromRegistry = ""
    objWMIReg.EnumKey &H80000002, UpdatesKEY, arrProducts
    If Not IsNull(arrProducts) Then
        For Each strProduct In arrProducts
            objWMIReg.EnumKey &H80000002, UpdatesKEY & "\" & strProduct, arrSPLevel
            If Not IsNull(arrSPLevel) Then
                For Each strSPLevel In arrSPLevel
                    objWMIReg.EnumKey &H80000002, UpdatesKEY & "\" & strProduct & "\" & strSPLevel, arrFixes
                    If Not IsNull(arrFixes) Then
                        For Each strFix In arrFixes
                            If strFix = HotfixID Then
                                GetDateInstallDateFromRegistry = objShell.RegRead("HKLM\" & UpdatesKEY & "\" & strProduct & "\" & strSPLevel & "\" & strFix & "\InstalledDate")
                                Exit Function
                            End If
                        Next
                    End If
                Next
            End If
        Next
    End If
End Function

Function GetCategoryFromRegistry(strHotfixID)
    'Try to obtain Information from Product in Registry from a given Hotfix ID. This happens usually in Windows 2000/2003
    
    On Error Resume Next
    Const UpdatesKEY = "SOFTWARE\Microsoft\Updates"
    Dim arrProducts, strProduct, arrSPLevel, strSPLevel, arrFixes, strFix
    
    GetCategoryFromRegistry = ""
    objWMIReg.EnumKey &H80000002, UpdatesKEY, arrProducts
    If Not IsNull(arrProducts) Then
        For Each strProduct In arrProducts
            objWMIReg.EnumKey &H80000002, UpdatesKEY & "\" & strProduct, arrSPLevel
            If Not IsNull(arrSPLevel) Then
                For Each strSPLevel In arrSPLevel
                    objWMIReg.EnumKey &H80000002, UpdatesKEY & "\" & strProduct & "\" & strSPLevel, arrFixes
                    If Not IsNull(arrFixes) Then
                        For Each strFix In arrFixes
                            If strFix = strHotfixID Then
                                GetCategoryFromRegistry = strProduct
                                Exit Function
                            End If
                        Next
                    End If
                Next
            End If
        Next
    End If
    
End Function

Function DumpNonHistoryQFEFixes()

   'If the Windows Update database is corrupted, some hotfixes will not be listed in history information
   'List these hotfixes base in Win32_QuickFixEngineering class
    On Error Resume Next
    Err.Clear
    
    Dim objItem, x, bFixAlreadyListed, strInstalledBy, strDateTime, strStatus, strDescription, strCategory
    
    If Not IsNull(colQFEItems) Then
        If Not IsEmpty(colQFEItems) Then
            For Each objItem In colQFEItems
                If Err.Number <> 0 Then Exit Function
                x = 0
                bFixAlreadyListed = False
                If IsArray(arrQFEFixesListed) Then
                    If Not IsEmpty(arrQFEFixesListed) Then
                        While (x <= UBound(arrQFEFixesListed)) And Not bFixAlreadyListed
                            bFixAlreadyListed = (arrQFEFixesListed(x) = objItem.HotfixID)
                            x = x + 1
                        Wend
                    End If
                End If
                If Not bFixAlreadyListed Then
                    OpenTag ("Update")
                    
                    strInstalledBy = ConvertSIDToUser(objItem.InstalledBy)
                    If Len(objItem.InstalledOn) > 0 Then _
                        strDateTime = FormatDateTime(FormatQFEDateTime(objItem.InstalledOn))
                        
                    If Len(strDateTime) = 0 Then
                        strDateTime = GetDateInstallDateFromRegistry(objItem.HotfixID)
                    End If
                    
                    strDescription = objItem.Description
                    
                    If IsNull(objItem.Status) Then
                        strStatus = "Completed successfully"
                    Else
                        strStatus = objItem.Status
                    End If
                    
                    strCategory = GetCategoryFromRegistry(objItem.HotfixID)
                    
                    If strCategory = "" Then strCategory = "QFE hotfix"
                    
                    objCSVFile.WriteText Chr(34) & strCategory & Chr(34) & "," & _
                            Chr(34) & objItem.ServicePackInEffect & Chr(34) & "," & _
                            Chr(34) & objItem.HotfixID & Chr(34) & "," & _
                            Chr(34) & "" & Chr(34) & "," & _
                            Chr(34) & strDateTime & Chr(34) & "," & _
                            Chr(34) & "" & Chr(34) & "," & _
                            Chr(34) & strInstalledBy & Chr(34) & "," & _
                            Chr(34) & strStatus & Chr(34) & "," & _
                            Chr(34) & objItem.Description & Chr(34) & vbCrLf
                            
                    
                    LineOut FormatStr(strCategory, 20) & " " & _
                            FormatStr(objItem.ServicePackInEffect, 6) & _
                            FormatStr(objItem.HotfixID, 10) & _
                            FormatStr("", 11) & _
                            FormatStr(strDateTime, 23) & _
                            FormatStr("", 18) & _
                            FormatStr(strInstalledBy, 28) & _
                            FormatStr(strStatus, 23) & _
                            objItem.Description, "", True, False, ""
                    
                    If strCategory = "QFE hotfix" Then strCategory = "Other updates not listed in history"
                    
                    LineOut "", strCategory, False, True, "Category"
                    
                    If Len(objItem.ServicePackInEffect) > 0 Then LineOut "", objItem.ServicePackInEffect, False, True, "SPLevel"
                    If Len(objItem.HotfixID) > 0 Then
                        LineOut "", objItem.HotfixID, False, True, "ID"
                        If Len(CStr(ToNumber(objItem.HotfixID))) > 5 Then
                            LineOut "", "http://support.microsoft.com/kb/" & ToNumber(objItem.HotfixID), False, True, "SupportLink"
                        End If
                    End If
                    LineOut "", "Hotfix Installed", False, True, "Operation"
                    LineOut "", strDateTime, False, True, "Date"
                    LineOut "", FormatSortableDateTime(FormatQFEDateTime(objItem.InstalledOn)), False, True, "SortableDate"
                    LineOut "", "", False, True, "ClientID"
                    LineOut "", strInstalledBy, False, True, "InstalledBy"
                    LineOut "", strStatus, False, True, "OperationResult"
                    LineOut "", Trim(strDescription), False, True, "Title"
                    If Len(objItem.Caption) > 0 Then LineOut "", Trim(objItem.Caption), False, True, "Description"
                                
                    CloseTag ("Update")
                End If
            Next
        End If
    End If
End Function

Function FormatQFEDateTime(strQFEDateTime)
    Dim lngHigh, lngLow, dtmDate
    If IsDate(strQFEDateTime) Then
        FormatQFEDateTime = strQFEDateTime
    Else
        On Error Resume Next
        'Datatype is a 64-bit FILETIME structure string. We need to convert it
        lngHigh = CLng("&H" & Left(strQFEDateTime, 8))
        lngLow = CLng("&H" & Right(strQFEDateTime, 8))
            
        If Err.Number <> 0 Then
            FormatQFEDateTime = ""
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
            FormatQFEDateTime = CStr(dtmDate)
        End If
    End If
End Function

Sub OpencolQFEItems()
    Set colQFEItems = objWMIService.ExecQuery("Select * from Win32_QuickFixEngineering where description <> ''", , 0)
End Sub

Function ObtainQFEProperties(ByVal strFixID, ByVal strFixTitle, ByRef strSPInEffect, ByRef strInstalledBy)
    Dim objItem
    strInstalledBy = ""
    strSPInEffect = ""
    
    If IsEmpty(colQFEItems) Then
        OpencolQFEItems
    End If

    For Each objItem In colQFEItems
        Dim bQFEPropFound
        
        bQFEPropFound = (LCase(strFixID) = LCase(objItem.HotfixID))
        If Not bQFEPropFound Then bQFEPropFound = (LCase(strFixTitle) = LCase(objItem.Description))
        If Not bQFEPropFound Then bQFEPropFound = (ToNumber(strFixID) = ToNumber(objItem.HotfixID))
        If bQFEPropFound Then
            strInstalledBy = ConvertSIDToUser(objItem.InstalledBy)
            strSPInEffect = objItem.ServicePackInEffect
            AddtoArray arrQFEFixesListed, objItem.HotfixID
            Exit For
        End If
    Next
End Function

Function AddtoArray(arrSourceArray, arrArrayToAdd)
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

Function ToNumber(strString)
    Dim x, intChar, bolStarted
    bolStarted = False
    ToNumber = ""
    For x = 1 To Len(strString)
        intChar = Asc(Mid(strString, x, 1))
        If (intChar >= 48) And (intChar <= 57) Then
            ToNumber = ToNumber & Mid(strString, x, 1)
            bolStarted = True
        Else
            If bolStarted Then Exit For
        End If
    Next
End Function

Function ConvertSIDToUser(strSID) 'Query SID of an object using WMI and return the account name
    On Error Resume Next
    Dim objAccount
    Set objAccount = objWMIService.Get("Win32_SID.SID='" & strSID & "'")
    If Err.Number = 0 Then
        If Len(objAccount.AccountName) > 0 Then
            ConvertSIDToUser = objAccount.ReferencedDomainName & "\" & objAccount.AccountName
        Else
            ConvertSIDToUser = strSID
        End If
    Else
        ConvertSIDToUser = strSID
    End If
End Function

Function GetFixID(strUpdateTitle)

    On Error Resume Next

    Dim regEx
    Dim myMatches
    Set regEx = new RegExp
    regEx.Pattern = "(KB|Q)\d*"
    Set myMatches = regEx.Execute(strUpdateTitle)
    if(myMatches.Count > 0) then
	    GetFixID=myMatches(0).Value
    end if
    Set myMatches = Nothing
    Set regEx = Nothing

End Function
'Function GetFixID(strUpdateTitle)

'    On Error Resume Next

'    Dim intStart, intEnd
'    
'    intStart = InStrRev(strUpdateTitle, "KB", -1, 0)
'    If intStart = 0 Then intStart = InStrRev(strUpdateTitle, "Q", -1, 0)
'    If intStart <> 0 Then
'        intEnd = InStr(intStart, strUpdateTitle, " ", 0)
'        If intEnd = 0 Then
'            intEnd = InStr(intStart, strUpdateTitle, ")", 0)
'        End If
'        If intEnd = 0 Then
'            GetFixID = ""
'        Else
'            GetFixID = Mid(strUpdateTitle, intStart, intEnd - intStart)
'            If Len(GetFixID) < 5 Then
'                GetFixID = ""
'            End If
'        End If
'    Else
'        GetFixID = ""
'    End If
'End Function

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

Function FormatSortableDateTime(dtLocalDateTime) 'Obtain dates on yyyymmdddhhmmss

    Dim hr, ampm
    FormatSortableDateTime = CStr(Year(dtLocalDateTime)) & _
                    Right(0 & CStr(Month(dtLocalDateTime)), 2) & _
                    Right(0 & CStr(Day(dtLocalDateTime)), 2)

    hr = Hour(dtLocalDateTime)
    hr = Right("0" & hr, 2)
    
    FormatSortableDateTime = FormatSortableDateTime & hr & Right(0 & CStr(Minute(dtLocalDateTime)), 2) & Right(0 & CStr(Second(dtLocalDateTime)), 2)
End Function


Function GetOS()
    Dim strSP, colItems, objItem, strSKU
    Set colItems = objWMIService.ExecQuery("Select * from Win32_OperatingSystem", , 48)
    strSP = ""
    
    For Each objItem In colItems

        GetOS = objItem.Caption
        
        If Not IsNull(objItem.CSDVersion) Then
            strSP = objItem.CSDVersion
        Else
            strSP = "Service Pack not installed"
        End If
        
        On Error Resume Next
        
        strSKU = ""
        strSKU = objItem.OperatingSystemSKU
        
        GetOS = GetOS + " - " + strSP
        
        If Len(strSKU) > 0 Then
            strSKU = GetOSSKU(strSKU)
            If Len(strSKU) > 0 Then
                GetOS = GetOS & " (" & strSKU & ")"
            End If
        End If
    Next
End Function

Function GetOSSKU(intSKU)
    
    Select Case intSKU
        Case 0
            GetOSSKU = ""
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

Sub DumpHistoryInformation()
    
    On Error Resume Next

    LineOut "QFE Information from : ", objShell.Environment("PROCESS").Item("COMPUTERNAME"), False, True, "Title"
    LineOut "Operating System : ", GetOS, False, True, "OSVersion"
    LineOut "Local time : ", FormatDateTime(Now), False, True, "TimeField"
    
    Dim objSession
    Dim objSearcher
    Dim colHistory
    Dim objEntry
    Dim strOperation, intHistoryCount, strFixID, strSPLevel, strInstalledBy, strResult, strCategory
        
    ' ** Header
    LineOut FormatStr("Category", 20) & " " & _
                FormatStr("Level", 6) & _
                FormatStr("ID", 10) & _
                FormatStr("Operation", 11) & _
                FormatStr("Date", 23) & _
                FormatStr("Client", 18) & _
                FormatStr("By", 28) & _
                FormatStr("Result", 23) & _
                "Title", "", True, False, ""
    LineOut "", String(200, "-"), True, False, ""
    
    objCSVFile.WriteLine Chr(34) & "Category" & Chr(34) & "," & _
                Chr(34) & "Level" & Chr(34) & "," & _
                Chr(34) & "ID" & Chr(34) & "," & _
                Chr(34) & "Operation" & Chr(34) & "," & _
                Chr(34) & "Date" & Chr(34) & "," & _
                Chr(34) & "Client" & Chr(34) & "," & _
                Chr(34) & "By" & Chr(34) & "," & _
                Chr(34) & "Results" & Chr(34) & "," & _
                Chr(34) & "Title" & Chr(34), adWriteLine
    
    Err.Clear
    
    Set objSession = CreateObject("Microsoft.Update.Session")
    Set objSearcher = objSession.CreateUpdateSearcher
    intHistoryCount = objSearcher.GetTotalHistoryCount
    Set colHistory = objSearcher.QueryHistory(0, intHistoryCount)
    
    If Err.Number = 0 Then
    
        For Each objEntry In colHistory
            OpenTag ("Update")
            
            strFixID = ""
            strInstalledBy = ""
            strSPLevel = ""
            
            strFixID = GetFixID(objEntry.Title)
            
            If (strFixID <> "") And (objEntry.ResultCode = 1) Or (objEntry.ResultCode = 2) Then
                ObtainQFEProperties strFixID, objEntry.Title, strSPLevel, strInstalledBy
            End If
                   
            Select Case objEntry.Operation
                Case 1
                    strOperation = "Install"
                Case 2
                    strOperation = "Uninstall"
                Case Else
                    strOperation = "Unknown(" & CStr(objEntry.Operation) & ")"
            End Select
           
            Select Case objEntry.ResultCode
                Case 0
                    strResult = "Not started"
                Case 1
                    strResult = "In progress"
                Case 2
                    strResult = "Completed successfully"
                Case 3
                    strResult = "Completed with errors"
                Case 4
                    strResult = "Failed to complete"
                Case 5
                    strResult = "Operation was aborted"
                Case Else
                    strResult = "Unknown (" & CStr(objEntry.ResultCode) & ")"
            End Select
           
            If objEntry.Categories.Count > 0 Then
                strCategory = objEntry.Categories(0)
            Else
                strCategory = ""
            End If
            
            LineOut FormatStr(strCategory, 20) & " " & _
                    FormatStr(strSPLevel, 6) & _
                    FormatStr(strFixID, 10) & _
                    FormatStr(strOperation, 11) & _
                    FormatStr(FormatDateTime(objEntry.Date), 23) & _
                    FormatStr(objEntry.ClientApplicationID, 18) & _
                    FormatStr(strInstalledBy, 28) & _
                    FormatStr(strResult, 23) & _
                    objEntry.Title, "", True, False, ""
            
            objCSVFile.WriteText Chr(34) & strCategory & Chr(34) & "," & _
                    Chr(34) & strSPLevel & Chr(34) & "," & _
                    Chr(34) & strFixID & Chr(34) & "," & _
                    Chr(34) & strOperation & Chr(34) & "," & _
                    Chr(34) & FormatDateTime(objEntry.Date) & Chr(34) & "," & _
                    Chr(34) & objEntry.ClientApplicationID & Chr(34) & "," & _
                    Chr(34) & strInstalledBy & Chr(34) & "," & _
                    Chr(34) & strResult & Chr(34) & "," & _
                    Chr(34) & objEntry.Title & Chr(34), adWriteLine
                    
            If Len(strCategory) > 0 Then
                LineOut "", strCategory, False, True, "Category"
            Else
                LineOut "", "(None)", False, True, "Category"
            End If
            
            If Len(strSPLevel) > 0 Then LineOut "", strSPLevel, False, True, "SPLevel"
            If Len(strFixID) > 0 Then
                LineOut "", strFixID, False, True, "ID"
                If Len(CStr(ToNumber(strFixID))) > 5 Then
                    LineOut "", "http://support.microsoft.com/kb/" & ToNumber(strFixID), False, True, "SupportLink"
                End If
            End If
            LineOut "", strOperation, False, True, "Operation"
            LineOut "", FormatDateTime(objEntry.Date), False, True, "Date"
            LineOut "", FormatSortableDateTime(objEntry.Date), False, True, "SortableDate"
            LineOut "", objEntry.ClientApplicationID, False, True, "ClientID"
            LineOut "", strInstalledBy, False, True, "InstalledBy"
            LineOut "", strResult, False, True, "OperationResult"
            LineOut "", Trim(objEntry.Title), False, True, "Title"
            LineOut "", Trim(objEntry.Description), False, True, "Description"
        
            CloseTag ("Update")
        Next
    Else
        'If we are here, it means 'Microsoft.Update.Session' does not exist
        'In this case, we need to obtain only the QFE hotfixes
        OpencolQFEItems
        ReDim arrQFEFixesListed(0)
    End If
    
End Sub

Function FormatStr(strValue, NumberofChars)
    If Len(strValue) > NumberofChars Then
        FormatStr = Left(strValue, NumberofChars)
    Else
        FormatStr = strValue + Space(NumberofChars - Len(strValue))
    End If
End Function

Function ReplaceEnvVars(strString)
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

Sub GenerateHTMFile()

    On Error Resume Next
    Dim strHTMLFileName, objHTMLFile, xmlStylesheet, xmlStylesheetPath, xmlFile, strXmlFilePath
    
    strXmlFilePath = objFSO.GetAbsolutePathName(".") & "\" & objShell.Environment("PROCESS").Item("COMPUTERNAME") & _
                     "_Hotfixes.XML"
    
    If ExtractEmbeddedXSL(xmlStylesheetPath) Then
    
        strHTMLFileName = objFSO.GetAbsolutePathName(".") & "\" & objShell.Environment("PROCESS").Item("COMPUTERNAME") & _
                                                        "_Hotfixes" & ".htm"
                                                        
        wscript.Echo "Building file: '" & objFSO.GetFileName(strHTMLFileName) & "'"
        
        Set objHTMLFile = objFSO.CreateTextFile(strHTMLFileName, ForWriting, True)
    
        Set xmlStylesheet = CreateObject("Microsoft.XMLDOM")
        Set xmlFile = CreateObject("Microsoft.XMLDOM")
        
        Err.Clear
        
        xmlFile.Load strXmlFilePath
        xmlStylesheet.Load xmlStylesheetPath
        
        objHTMLFile.Write xmlFile.transformNode(xmlStylesheet)
        
        If (Err.Number <> 0) Or (xmlFile.parseError <> 0) Then
            wscript.Echo ""
            wscript.Echo " - Error generating HTML file. File not generated."
            If Err.Number <> 0 Then
                wscript.Echo "   Error 0x" & HexFormat(Err.Number) & ":"
                wscript.Echo "   " & Err.Source & " - " & Err.Description
            End If
            If xmlFile.parseError <> 0 Then
                wscript.Echo "   XML parser error : 0x" & HexFormat(xmlFile.parseError.errorCode) & " - " & xmlFile.parseError.reason
            End If
            objHTMLFile.Close
            Set objHTMLFile = Nothing
            objFSO.DeleteFile strHTMLFileName, True
        Else
            objHTMLFile.Close
            Set objHTMLFile = Nothing
        End If
        

        Set xmlFile = Nothing
        Set xmlStylesheet = Nothing
        Set objXMLFile = Nothing
        
        objFSO.DeleteFile xmlStylesheetPath, True
        If Err.Number = 0 Then
            objFSO.DeleteFile strXmlFilePath, True
        end if
    End If
    
End Sub

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

Sub LineOut(strName, strValue, bDoNotWriteToXML, bDoNotWritetoTXT, strXMLTag)

    If Not bDoNotWritetoTXT Then
        objTXTFile.WriteText strName & strValue, adWriteLine
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
    strValue = TranslateXMLChars(strValue)
    If Len(strXMLTag) = 0 And Len(strValue) = 0 Then
        objXMLFile.WriteLine strName
    ElseIf Len(strName) = 0 Then
        objXMLFile.WriteLine "<" & strXMLTag & ">" & strValue & "</" & strXMLTag & ">"
    Else 'If Len(strValue) > 0 Then
        objXMLFile.WriteLine "<" & strXMLTag & " name=" & Chr(34) & strName & Chr(34) & ">" & strValue & "</" & strXMLTag & ">"
    End If
End Function

Function iif(Expression, Truepart, Falsepart)
    If Expression Then
        iif = Truepart
    Else
        iif = Falsepart
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
    
    Err.Clear
    wscript.Echo "Building XSLT File..."
    
    Set objScriptFile = objFSO.OpenTextFile(wscript.ScriptFullName, ForReading, False, -2)
    strXSLPath = objFSO.GetSpecialFolder(2) & "\HotfixHistoryXSL.XSL"
    
    Set objXSL = objFSO.OpenTextFile(strXSLPath, ForWriting, True, -1)
    
    bolXSLExtracted = False
    
    If Err.Number <> 0 Then
        wscript.Echo ""
        wscript.Echo "Error 0x" & HexFormat(Err.Number) & ": extracting XSL file. File not generated."
        wscript.Echo Err.Source & " - " & Err.Description
        ExtractEmbeddedXSL = False
        Exit Function
    End If
    
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
    
    objXSL.Close
    objScriptFile.Close
    
    Set objXSL = Nothing
    Set objScriptFile = Nothing
    
    ExtractEmbeddedXSL = True

End Function

Sub EmbeddedXSL()
'<?xml version="1.0"?>
'<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
'<xsl:output method="html" />
'<xsl:key name="Updates" match="Update" use="Category" />
'
'<xsl:template match="/Root">
'
'<html dir="ltr" xmlns:v="urn:schemas-microsoft-com:vml" gpmc_reportInitialized="false">
'<head>
'<base target="_blank" />
'<title><xsl:value-of select="Updates/Title"/> Update History</title>
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
'  .he1    { background-color:#FEF7D6; border:1px solid #BBBBBB; color:#3333CC; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:120%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%;
'  filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=1,StartColorStr='#FEF7D6',EndColorStr='white');}
'
'  .he4i   { background-color:#F9F9F9; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; margin-bottom:-1px; margin-left:15px; margin-right:0px; padding-bottom:5px; padding-left:12px; padding-top:4px; position:relative; width:100%; }
'
'  DIV .expando { color:#000000; text-decoration:none; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:normal; position:absolute; right:10px; text-decoration:underline; z-index: 0; }
'
'  .he0 .expando { font-size:100%; }
'
'  .info, .info0th, .info3, .info4, .disalign, .infoqfe { line-height:1.6em; padding:0px,0px,0px,0px; margin:0px,0px,0px,0px; }
'
'  .disalign TD                      { padding-bottom:5px; padding-right:10px; }
'
'  .info5filename                    { padding-right:10px; width:30%; border-bottom:1px solid #CCCCCC; padding-right:10px;}
'
'  .info0th                          { padding-right:10px; width:12%; border-bottom:1px solid #CCCCCC; padding-right:10px;}
'
'  .info TD                          { padding-right:10px; width:50%; }
'
'  .infoqfe                          { table-layout:auto; }
'
'  .infoqfe TD, .infoqfe TH          { padding-right:10px;}
'
'  .info3 TD                         { padding-right:10px; width:33%; }
'
'  .info4 TD, .info4 TH              { padding-right:10px; width:25%; }
'
'  .info TH, .info0th, .info3 TH, .info4 TH, .disalign TH, .infoqfe TH { border-bottom:1px solid #CCCCCC; padding-right:10px; }
'
'  .subtable, .subtable3             { border:1px solid #CCCCCC; margin-left:0px; background:#FFFFFF; margin-bottom:10px; }
'
'  .subtable TD, .subtable3 TD       { padding-left:10px; padding-right:5px; padding-top:3px; padding-bottom:3px; line-height:1.1em; width:10%; }
'
'  .subtable TH, .subtable3 TH       { border-bottom:1px solid #CCCCCC; font-weight:normal; padding-left:10px; line-height:1.6em;  }
'
'  .subtable .footnote               { border-top:1px solid #CCCCCC; }
'
'  .lines0                           {background-color: #F5F5F5;}
'  .lines1                           {background-color: #F9F9F9;}
'
'  .subtable3 .footnote, .subtable .footnote { border-top:1px solid #CCCCCC; }
'
'  .subtable_frame     { background:#D9E3EA; border:1px solid #CCCCCC; margin-bottom:10px; margin-left:15px; }
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
'  .rsopname { color:#333333; font-family:MS Shell Dlg; font-size:130%; font-weight:bold; padding-left:11px; }
'
'  #uri    { color:#333333; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; }
'
'  #dtstamp{ color:#333333; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; text-align:left; width:30%; }
'
'  #objshowhide { color:#000000; cursor:hand; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; margin-right:0px; padding-right:10px; text-align:right; text-decoration:underline; z-index:2; word-wrap:normal; }
'
'  v\:* {behavior:url(#default#VML);}
'
'</style>
'<!-- Script 1 -->
'
'<script language="vbscript" type="text/vbscript">
'<![CDATA[
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
'    IsSectionHeader = (obj.className = "he0_expanded") Or (obj.className = "he1_expanded") Or (obj.className = "he1") Or (obj.className = "he2") Or (obj.className = "he3") Or (obj.className = "he4") Or (obj.className = "he4h") Or (obj.className = "he5") Or (obj.className = "he5h")  or (obj.className = "he4_expanded")
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
'        x = 0
'        bFound = false
'        while ((not bFound) and (x < objHeader.children.length))
'          x = x + 1
'          if x < objHeader.children.length then
'            Set objExpando = objHeader.children(x)
'            if objExpando.className = "expando" then bFound = true
'            rem msgbox objExpando.outerHTML + vbCrLf + "bFound: " + cstr(bFound) + vbCrLf + "x: " + cstr(x)
'          end if
'        wend
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
']]>
'</script>
'</head>
'
'<body>
'	<table class="title" cellpadding="0" cellspacing="0">
'	<tr><td colspan="2" class="rsopheader">Update History for <xsl:value-of select="Updates/Title"/></td></tr>
'	<tr><td colspan="2" class="rsopname">Operating System: <xsl:value-of select="Updates/OSVersion"/></td></tr>
'	<tr><td id="dtstamp">Data collected on: <xsl:value-of select="Updates/TimeField"/></td><td><div id="objshowhide" tabindex="0"></div></td></tr>
'	</table>
'	<div class="filler"></div>
'
'	<xsl:variable name="ReportHasSPLevel" select="not(count(//SPLevel) = 0)"/>
'  <xsl:variable name="ReportContainsUpdates" select="not(count(//Update) = 0)"/>
'  <xsl:if test="$ReportContainsUpdates">
'	  <xsl:for-each select="//Update[generate-id(.)=generate-id(key('Updates',Category))]">
'    <xsl:sort select="SortableDate" order="descending" data-type="number"/>
'    <xsl:variable name="Category" select="Category"/>
'      
'	  <div class="he1"><span class="sectionTitle" tabindex="0">
'      <xsl:value-of select="Category"/> (<xsl:value-of select="count(//Update[Category = $Category])"/>)
'    </span><a class="expando" href="#"></a></div>
'
'		  <div class="container"><div class="he4i"><table cellpadding="0" class="infoqfe">
'      <tr>
'        <th>Results</th><th>Date</th><th>Operation</th><th>By</th><xsl:if test="$ReportHasSPLevel"><th>Level</th></xsl:if><th>Client</th><th>ID</th><th style="width:auto">Description</th>
'      </tr>
'
'		  <xsl:for-each select="key('Updates',Category)">
'		  <xsl:variable name="pos" select="position()" />
'		  <xsl:variable name="mod" select="($pos mod 2)" />
'
'		  <tr>
'        <td class="lines{$mod}" style="text-align: center">
'          <xsl:choose>
'            <xsl:when test="OperationResult = 'Completed successfully'">
'              <v:group id="Inf1" class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Completed successfully">
'                <v:oval class="vmlimage" style="width:100;height:100;z-index:0" fillcolor="#009933" strokecolor="#C0C0C0" />
'              </v:group>
'            </xsl:when>
'
'            <xsl:when test="OperationResult = 'In progress'">
'              <v:group class="vmlimage" style="width:14px;height:14px;vertical-align:middle" coordsize="100,100" title="In progress">
'                <v:roundrect class="vmlimage" arcsize="10" style="width:100;height:100;z-index:0" fillcolor="#00FF00" strokecolor="#C0C0C0" />
'                <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="white" strokecolor="white">
'                  <v:path v="m 40,25 l 75,50 40,75 x e" />
'                </v:shape>
'              </v:group>
'            </xsl:when>
'
'            <xsl:when test="OperationResult = 'Operation was aborted'">
'              <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Operation was aborted">
'                <v:roundrect class="vmlimage" arcsize="20" style="width:100;height:100;z-index:0" fillcolor="#290000" strokecolor="#C0C0C0" />
'                <v:line class="vmlimage" style="z-index:2" from="52,30" to="52,75" strokecolor="white" strokeweight="8px" />
'              </v:group>
'            </xsl:when>
'
'            <xsl:when test="OperationResult = 'Completed with errors'">
'              <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Completed with errors">
'                <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="yellow" strokecolor="#C0C0C0">
'                  <v:path v="m 50,0 l 0,99 99,99 x e" />
'                </v:shape>
'                <v:rect class="vmlimage" style="top:35; left:45; width:10; height:35; z-index:1" fillcolor="black" strokecolor="black">
'                </v:rect>
'                <v:rect class="vmlimage" style="top:85; left:45; width:10; height:5; z-index:1" fillcolor="black" strokecolor="black">
'                </v:rect>
'              </v:group>
'            </xsl:when>
'
'            <xsl:when test="OperationResult = 'Failed to complete'">
'              <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Failed to complete">
'                <v:oval class="vmlimage" style='width:100;height:100;z-index:0' fillcolor="red" strokecolor="#C0C0C0">
'                </v:oval>
'                <v:line class="vmlimage" style="z-index:1" from="25,25" to="75,75" strokecolor="white" strokeweight="3px">
'                </v:line>
'                <v:line class="vmlimage" style="z-index:2" from="75,25" to="25,75" strokecolor="white" strokeweight="3px">
'                </v:line>
'              </v:group>
'            </xsl:when>
'
'            <xsl:otherwise>
'              <v:group id="Inf1" class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="{OperationResult}">
'                <v:oval class="vmlimage" style="width:100;height:100;z-index:0" fillcolor="#FF9933" strokecolor="#C0C0C0" />
'              </v:group>
'            </xsl:otherwise>
'
'          </xsl:choose>
'        </td>
'        <td class="lines{$mod}" style="white-space: nowrap;">
'          <xsl:value-of select="Date"/>
'          <td class="lines{$mod}" style="text-align: center">
'            <xsl:value-of select="Operation"/>
'          </td>
'          <td class="lines{$mod}" style="white-space: nowrap;">
'            <xsl:value-of select="InstalledBy"/>
'          </td>
'		  <xsl:if test="$ReportHasSPLevel"><td class="lines{$mod}" style="white-space: nowrap;"><xsl:value-of select="SPLevel"/></td></xsl:if></td><td class="lines{$mod}" style="white-space: nowrap;"><xsl:value-of select="ClientID"/></td><td class="lines{$mod}" style="white-space: nowrap;"><xsl:if test="SupportLink"><a href="{SupportLink}"><xsl:value-of select="ID"/></a></xsl:if><xsl:if test="string-length(SupportLink) = 0"><xsl:value-of select="ID"/></xsl:if></td><td class="lines{$mod}"><xsl:if test="not (string-length(Description) = 0)"><span style="cursor:pointer" title="{Description}"><xsl:value-of select="Title"/></span></xsl:if><xsl:if test="string-length(Description) = 0"><xsl:value-of select="Title"/></xsl:if></td></tr>
'		  </xsl:for-each>
'		  </table>
'		  </div></div>
'	  <div class="filler"></div>
'
'	  </xsl:for-each>
'  </xsl:if>
'  <xsl:if test="not ($ReportContainsUpdates)">
'    <div class="he1">
'      <span class="sectionTitle" tabindex="0">
'        There are no hotfixes or updates installed on this machine
'      </span>
'    </div>
'    <div class="container"></div>
'    <div class="filler"></div>
'  </xsl:if>  
'    
'</body>
'</html>
'</xsl:template>
'</xsl:stylesheet>
End Sub
'' SIG '' Begin signature block
'' SIG '' MIInoAYJKoZIhvcNAQcCoIInkTCCJ40CAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' g2brASt4G7NXVNJo2XegP5bxsqwfLurZ8iwmxWiKWu6g
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
'' SIG '' ghlzMIIZbwIBATCBlTB+MQswCQYDVQQGEwJVUzETMBEG
'' SIG '' A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
'' SIG '' ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
'' SIG '' MSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5n
'' SIG '' IFBDQSAyMDExAhMzAAACU+OD3pbexW7MAAAAAAJTMA0G
'' SIG '' CWCGSAFlAwQCAQUAoIGwMBkGCSqGSIb3DQEJAzEMBgor
'' SIG '' BgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
'' SIG '' AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD5vbmWBJV0mSFf
'' SIG '' +pPO4JYU2FutqodwrMMsXheDiELBQDBEBgorBgEEAYI3
'' SIG '' AgEMMTYwNKAUgBIATQBpAGMAcgBvAHMAbwBmAHShHIAa
'' SIG '' aHR0cHM6Ly93d3cubWljcm9zb2Z0LmNvbSAwDQYJKoZI
'' SIG '' hvcNAQEBBQAEggEABGwuc4HHF6gIQ/na6LxmQn7iZbp/
'' SIG '' i/UzhVQnHRzERveluFPWjv9PpDVkGi9PEW4Nx6DCk+eI
'' SIG '' fVimqAjXmlpJJCmssQmv8InrXZ49ryFLekka5MgvaaMi
'' SIG '' R/powQlEzkBDhFSqW1J6u+9dl0S6ZeEARJVSLDtoc4aZ
'' SIG '' Xxu+PjARh//9gxok4EohZjvyR/85v2JESwI8NPB5xySa
'' SIG '' m7QRlzfpsMYdz2q2+DK5yHYdabdcXgHmVUcMKlqqX996
'' SIG '' O4MB6kzLjfLeFchjz/cn5QNyVzpv62iRfzyUlH2wZIwa
'' SIG '' kOjlPbaEJ9hHhpM4gCDLYD5AUgMFmZkCFvPVYpwNYaaa
'' SIG '' Fuxji6GCFvswghb3BgorBgEEAYI3AwMBMYIW5zCCFuMG
'' SIG '' CSqGSIb3DQEHAqCCFtQwghbQAgEDMQ8wDQYJYIZIAWUD
'' SIG '' BAIBBQAwggFPBgsqhkiG9w0BCRABBKCCAT4EggE6MIIB
'' SIG '' NgIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUA
'' SIG '' BCCUNiuayMsETjGGBW7XPxG2/qlccx+sMGLylpp00Gd9
'' SIG '' HAIGYhZtksjiGBEyMDIyMDMyODE2NTYwNy4xWjAEgAIB
'' SIG '' 9KCB0KSBzTCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
'' SIG '' Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
'' SIG '' BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMG
'' SIG '' A1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
'' SIG '' czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046N0JGMS1F
'' SIG '' M0VBLUI4MDgxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
'' SIG '' LVN0YW1wIFNlcnZpY2WgghFUMIIHDDCCBPSgAwIBAgIT
'' SIG '' MwAAAZ8rRTUVCC5LXQABAAABnzANBgkqhkiG9w0BAQsF
'' SIG '' ADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
'' SIG '' Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
'' SIG '' TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
'' SIG '' aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
'' SIG '' MTEyMDIxOTA1MjJaFw0yMzAyMjgxOTA1MjJaMIHKMQsw
'' SIG '' CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
'' SIG '' MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
'' SIG '' b2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3Nv
'' SIG '' ZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1U
'' SIG '' aGFsZXMgVFNTIEVTTjo3QkYxLUUzRUEtQjgwODElMCMG
'' SIG '' A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
'' SIG '' ZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
'' SIG '' AKT1eXxNUbKJkC/Oby0Hh8s/TOcvzzdgMgbTeOzX9bMJ
'' SIG '' ogJcOzSReUnf05RnB4EVr9XyXbuaUGPItkO1ODdbx1A5
'' SIG '' EO6d+ftLNkSgWaVdpJhxCHIMxXmCHGLqWHzLc1XVM0cZ
'' SIG '' gvNqhCa0F64VKUQf3CnqsL+xErsY+s6fXtcAbOj7/IXL
'' SIG '' sN9aAhDjdffm63bRNKFR5gOuzkY5Wkenui6pBhFOm76U
'' SIG '' BoId+ry2v4sWojKOmS/HFvcdzHpWO17Q08foacgJPzg/
'' SIG '' FZgrt6hrkDFuxNSpZDKJa2sajJDJc/jIgp9NRg+2xMUK
'' SIG '' LXiK4k2vfJEaOjhTU4dlTbIaZZ4Kt1xwmCRvLqTY3kCF
'' SIG '' Fi8oet48+HmhYdjTWDxNyTFXiHiKWiq9ppgaHccM9Y/D
'' SIG '' gqgrITLtAca5krWoCSF5aIpfaoTR41Fa6aYIo+F1wXd1
'' SIG '' xWJUj1opeG3LjMzvq2xSNx0K2cblUgjp5Tp3NwvpgWnS
'' SIG '' 8yXsk8jfL0ivH2wESJWZKKAzZMNlThFQhsUi0PrQMljM
'' SIG '' 0fSsa7YO/f0//Q7CjHfs/dl+8HmMB6DoH5IFIPRrCL5/
'' SIG '' rUkWtVz9Rnzdb7m2Aj/TFwsZYcE10SJtIXU0V+tXQo8I
'' SIG '' p+L2IPYGRCAxiLTYJjwTe6z5TJgDg0VhxYmmNpwEoAF4
'' SIG '' MF2RjUE98aDOyRoqEgaF2jH1AgMBAAGjggE2MIIBMjAd
'' SIG '' BgNVHQ4EFgQUYjTy1R4TFitIDi7o39lqx9YdyGEwHwYD
'' SIG '' VR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYD
'' SIG '' VR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3Nv
'' SIG '' ZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGlt
'' SIG '' ZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsG
'' SIG '' AQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3
'' SIG '' dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNy
'' SIG '' b3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
'' SIG '' KS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggr
'' SIG '' BgEFBQcDCDANBgkqhkiG9w0BAQsFAAOCAgEAHYooKTw7
'' SIG '' 6Rnz6b1s9dAgCaj7rFsoNoqQxHf/zYDxdUAxr1Gki1gm
'' SIG '' R2S1r4LpkhUGxkQBEmQqdalgmKLIYFXc+Y+ggw/nMVuv
'' SIG '' QFgsyiUMlky0fcyJ9UEP02Sdg0qD4ZtbJoA+zxVnpQPc
'' SIG '' JHOOhVnY9sdEf5Q6XZhz9ybUhHcGW+OVw3DKSnMEZSd0
'' SIG '' BF5+7ON9FJ8H50HOaUVj50wTz4nc6+94ytohzOdKuWvj
'' SIG '' oZcyhYYm3SEEk1/gbklmrJd7yfzPbJHmmgva6IxHOohd
'' SIG '' fWvAIheFws8WBIo3+8nGvEeIX0HJWKi5/iMJwPw7aY73
'' SIG '' i2gJKosRG6h1J711DuqspUGicOhhYDH5bRcYBfapqhma
'' SIG '' oS6ftBvyGfI3JWsnYLZ9nABjbKJfdkyAsZSukNGglZ0/
'' SIG '' 61zlJLopnV/DKEv8oCCOI0+9QGK7s8XgsfHlNEVTsdle
'' SIG '' +ClkOfnGS2RdmJ0DhLbo1mwxLKDHRHWddXfJtjcl2U19
'' SIG '' ERO3pIh9B0LFFflhRsjk12+5UyLLmgHduV+E+A0nKjSp
'' SIG '' 2aQcoTak3hzyLD1KtqOdZwzRtQTGsOQ2pzBqrXUPPBzS
'' SIG '' UMZfXiCeMZFuCGXocuwPuPHHT5u7Mkcpk/MZ1MswUqhJ
'' SIG '' 0l5XilT+3d09t1TbUdLrQTHYinZN0Z+C1L087NVpMDhS
'' SIG '' 5y6SVuNmRCKF+DYwggdxMIIFWaADAgECAhMzAAAAFcXn
'' SIG '' a54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQsw
'' SIG '' CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
'' SIG '' MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
'' SIG '' b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3Nv
'' SIG '' ZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAx
'' SIG '' MDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVa
'' SIG '' MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
'' SIG '' dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
'' SIG '' aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
'' SIG '' Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjAN
'' SIG '' BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0
'' SIG '' ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK
'' SIG '' 4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0T
'' SIG '' z3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxR
'' SIG '' MTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk
'' SIG '' 2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bs
'' SIG '' hVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SH
'' SIG '' JMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedG
'' SIG '' bsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74
'' SIG '' kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2
'' SIG '' ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQc
'' SIG '' NIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4C
'' SIG '' vEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg
'' SIG '' 8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHz
'' SIG '' NgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREd
'' SIG '' cu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZy
'' SIG '' acaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQB
'' SIG '' gjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5k
'' SIG '' xJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5i
'' SIG '' XYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQB
'' SIG '' gjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3
'' SIG '' Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3Np
'' SIG '' dG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJ
'' SIG '' KwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQD
'' SIG '' AgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
'' SIG '' 1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBL
'' SIG '' oEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3Br
'' SIG '' aS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAt
'' SIG '' MDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEF
'' SIG '' BQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
'' SIG '' aS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5j
'' SIG '' cnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cB
'' SIG '' MSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/
'' SIG '' 2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYe
'' SIG '' eNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB
'' SIG '' 2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveV
'' SIG '' tihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSF
'' SIG '' QrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/
'' SIG '' LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW
'' SIG '' 9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1Rt
'' SIG '' nWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPX
'' SIG '' fx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep
'' SIG '' 8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFm
'' SIG '' PWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsX
'' SIG '' HRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjm
'' SIG '' jJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhw
'' SIG '' RNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUz
'' SIG '' WLOhcGbyoYICyzCCAjQCAQEwgfihgdCkgc0wgcoxCzAJ
'' SIG '' BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
'' SIG '' DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
'' SIG '' ZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29m
'' SIG '' dCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRo
'' SIG '' YWxlcyBUU1MgRVNOOjdCRjEtRTNFQS1CODA4MSUwIwYD
'' SIG '' VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
'' SIG '' oiMKAQEwBwYFKw4DAhoDFQB0Xa6YH/LLDEUsVMLysn0W
'' SIG '' /1z2t6CBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
'' SIG '' VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
'' SIG '' MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
'' SIG '' JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
'' SIG '' QSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5evDijAiGA8y
'' SIG '' MDIyMDMyODEzMTgwMloYDzIwMjIwMzI5MTMxODAyWjB0
'' SIG '' MDoGCisGAQQBhFkKBAExLDAqMAoCBQDl68OKAgEAMAcC
'' SIG '' AQACAgHNMAcCAQACAhOEMAoCBQDl7RUKAgEAMDYGCisG
'' SIG '' AQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEA
'' SIG '' AgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQAD
'' SIG '' gYEAwrF4sb+wrIPK6Li5XZuJKoFx1mp1C6uRETzEiX1F
'' SIG '' DhPo70eNOpggr12CQmxc1LilTKTqFmVUrbJn3Ot7FR39
'' SIG '' f6/JIY+WtdvnPxTsOk8dTbvgsSwLK0vhemETJ8v94/yB
'' SIG '' zBPoipaeem1UYgLL8h8Ij5Z2uVIa6+cEuFBV7xx1HP0x
'' SIG '' ggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEG
'' SIG '' A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
'' SIG '' ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
'' SIG '' MSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
'' SIG '' Q0EgMjAxMAITMwAAAZ8rRTUVCC5LXQABAAABnzANBglg
'' SIG '' hkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqG
'' SIG '' SIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCBCa2Xck70Z
'' SIG '' aFHJREnxL5MitxPzzLkowVB4B2Eyin20uzCB+gYLKoZI
'' SIG '' hvcNAQkQAi8xgeowgecwgeQwgb0EIIbxXimiJ4mepedX
'' SIG '' PA1R6N4qAsl8Qfs/6OynLDdLfFzaMIGYMIGApH4wfDEL
'' SIG '' MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
'' SIG '' EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
'' SIG '' c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
'' SIG '' b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGfK0U1
'' SIG '' FQguS10AAQAAAZ8wIgQgW/nmidmaXYX3hUGNkCgREUeF
'' SIG '' 8bB7U/6vh2sQUeWvQ0gwDQYJKoZIhvcNAQELBQAEggIA
'' SIG '' bdNPvoyJyy2yEbhNTlWbJ4oph/u4cFf+G8EZJqbXLye5
'' SIG '' rYkbDXdO3+3BuMAn/YOhaAGg+dLrXGqbdCGFV1gb8yfz
'' SIG '' C1QuHr983f7GJ43cAzb2Fezti1IeQq2b40GjY+4gkPf4
'' SIG '' s0ADJZ2ABRUTImb3LNnsgsvuUndqHRrPu/h8TjI+b0hI
'' SIG '' yaQpyF45jGKwXiCIIYj67+sko82fiJrFzgJFMiEenCaz
'' SIG '' 00PesLbnHqPB534VLO9ir/JIg+UezkcPC+UhlYLoCN0L
'' SIG '' OgG6OBRUF1B3xKXKQblJvXvl2sAbfFYmOz9LISEJWdiP
'' SIG '' M52ZAwRn+To5VzGkzFyzi6Gd+tVVBHfGzPAgAWmt3dyF
'' SIG '' /tdsB3hK6j4dRgc4kZiIzKJr73my8B/8m4Glnsu0Isqs
'' SIG '' azcByt/4vQcsTlnVsnUQU40njzTNLofkicMKqqGoUFq6
'' SIG '' IUUjHG9TEB3IyZIAgmNBUgbqEn1XNXPC2VAGwFWeO+4m
'' SIG '' iQpqFjGzAl8P60TNwx3c3cBTtjxR7bqaITw1iw35JCX0
'' SIG '' lmgtQ4eezDcn7sF0cEdKzbvUY5VxiBfydYsPKX+fzpA6
'' SIG '' jlz2apOtvUCQYaPxz3lzT4CdKnFfsdeq2RYNkYwkDgvw
'' SIG '' LXoq6Oyx3zGXrUcE5jKizd6G/EJlNakyJ+uaNJRKrIe8
'' SIG '' eaqrCbdkloqzzO9yn3mQH5Q=
'' SIG '' End signature block
