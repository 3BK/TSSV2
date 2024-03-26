' ------------------------------------------------------------------------------
'
' File:   FindSQLInstalls.vbs
'  Creation Date:  02/27/09 by Dwhitney@Microsoft.com
'  Last Modified:  09/10/11 by Shonh@microsoft.com
'  Version: 1.19
'  Purpose: Used to discover the existence of packages on both the installation
'           paths and in the installer cache. Once invalid Installer path found
'           restore the missing path for that product code.
'
'  Command line Syntax:
'
'       cscript findsqlinstalls.vbs > %computername%_sql_install_details.txt
'
' Author - dwhitney@microsoft.com, johnbu@microsoft.com, shonh@microsoft.com
'
' ------------------------------------------------------------------------------


On Error Resume Next

Dim arrSubKeys, arrSubKeys2
Dim objFSO, objShell, objFile, objReg, objConn
Dim strComputer, strKeyPath, strNewSource
Dim strWorkstationName, strDBPath, strSubKey, strSubKey2(), strKeyPath02,  strRetValue00
Dim strRetValue01, strRetValue02, strRetValNew02, strRetValNew03, strRetValNew04, strRetValNew05, strRetValNew06, strRetValNew07, strRetValNew08, strRetValNew09, strRetValue10, strRetValNew10, strRetValNew11, strRetValNew12

Const HKCR = &H80000000 'HKEY_CLASSES_ROOT
Const HKLM = &H80000002 'HKEY_LOCAL_MACHINE
Const ForReading = 1, ForWriting = 2, ForAppEnding = 8

'
' Leaving strNewSource will result in no search path updating.
' Currently DO NOT EDIT these.
strNewSource = ""
strNewRTMSource = ""

' Define string values
strComputer = "."
strSQLName = "SQL"
strDotNetName = ".NET"
strVStudioName = "Visual Studio"
strXML = "XML"
strOWC = "Microsoft Office 2003 Web Components"
strKeyPath = "Installer\Products"
strKeyPath2 = "SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products"
strNValue00 = "ProductName"
strNValue01 = "PackageName"
strNValue02 = "LastUsedSource"
strNValue03 = "InstallSource"
strNValue04 = "LocalPackage"
strNValue05 = "DisplayVersion"
strNValue06 = "InstallDate"
strNValue07 = "UninstallString"
strNValue08 = "PackageCode"
strNValue09 = "MediaPackage"
strNValue10 = "InstallSource"
strNValue11 = "AllPatches"
strNValue12 = "NoRepair"
strNValue13 = "MoreInfoURL"
strNValue14 = "PackageName"
strNValue15 = "LastUsedSource"
strNValue16 = "Uninstallable"
strNValue17 = "DisplayName"
strNValue18 = "Installed"


WScript.echo "Products installed on the local system"
WScript.echo "found using FindSQLInstalls.vbs "
WScript.echo " Version: 1.19 "

Set fso = CreateObject("Scripting.FileSystemObject")
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objShell = WScript.CreateObject("WScript.Shell")

'--Set up the registry provider.
Set objReg = GetObject("winmgmts:\\" & strComputer & _
"\root\default:StdRegProv")

Set wiInstaller = CreateObject("WindowsInstaller.Installer")

'--Enumerate the "installer\products" key on HKCR
objReg.EnumKey HKCR, strKeyPath, arrSubKeys

For Each strSubKey In arrSubKeys

' Define the various registry paths
strProduct01 = "Installer\Products\" & strSubKey
strKeyPath02 = "Installer\Products\" & strSubKey & "\SourceList"
strKeyPath03 = "Installer\Products\" & strSubKey & "\SourceList\Media"
strInstallSource = "SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\" & strSubKey & "\InstallProperties\"
strInstallSource2 = "SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\" & strSubKey & "\patches\"
strInstallSource3 = "SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Patches"
strInstallSource5 = "SOFTWARE\Classes\Installer\Patches\"
strInstallSource6 = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
strInstallSource7 = "SOFTWARE\Microsoft\Microsoft SQL Server\"
strInstallSource8 = "SOFTWARE\Wow6432Node\Microsoft\Microsoft SQL Server\"

' Pull the intial values
objReg.GetStringValue HKCR, strProduct01, strNValue00, strRetValue00
objReg.GetStringValue HKCR, strKeyPath02, strNValue01, strRetValue01
objReg.GetStringValue HKCR, strKeyPath02, strNValue02, strRetValue02
strRetValNew02 = Mid(strRetValue02, 5)
objReg.GetStringValue HKCR, strKeyPath03, strNValue09, strRetValue09
strRetValue10 = strNewRTMSource & strRetValue09
objReg.GetStringValue HKLM, strInstallSource, strNValue03, strRetValNew03
objReg.GetStringValue HKLM, strInstallSource, strNValue04, strRetValNew04
objReg.GetStringValue HKLM, strInstallSource, strNValue05, strRetValNew05
objReg.GetStringValue HKLM, strInstallSource, strNValue06, strRetValNew06
objReg.GetStringValue HKLM, strInstallSource, strNValue07, strRetValNew07
objReg.GetStringValue HKLM, strInstallSource, strNValue10, strRetValNew10
objReg.GetStringValue HKLM, strInstallSource, strNValue12, strRetValNew12
objReg.GetStringValue HKLM, strInstallSource, strNValue13, strRetValNew13
objReg.GetStringValue HKLM, strInstallSource2, strNValue11, strRetValNew11

' Pull the Product Code from the Uninstall String
strProdCode = strRetValNew07
  ProdCodeLen = Len(strProdCode)
  ProdCodeLen = ProdCodeLen - 14
strRetValNew08 = Right(strProdCode, ProdCodeLen)

' Pull out path from LastUsedSource
strGetRealPath = strRetValue02
  GetRealPath = Len(strRetValue02)
strRealPath = Mid(strRetValue02, 5, GetRealPath)

' Identifie the string in the ProductName
If instr(1, strRetValue00, strSQLName, 1) Then
' Start the log output
    WScript.echo "================================================================================"
    WScript.echo "PRODUCT NAME   : " & strRetValue00
    WScript.echo "================================================================================"
    WScript.echo "  Product Code: " & strRetValNew08
    WScript.echo "  Version     : " & strRetValNew05
    WScript.echo "  Most Current Install Date: " & strRetValNew06
    WScript.echo "  Target Install Location: "  & strRetValNew13
    WScript.echo "  Registry Path: "
    WScript.echo "   HKEY_CLASSES_ROOT\" & strKeyPath02
    WScript.echo "     Package    : " & strRetValue01
    WScript.echo "  Install Source: " & strRetValue10
    WScript.echo "  LastUsedSource: " & strRetValue02
'   WScript.echo "Does this file on this path exist? " & strRetValNew02 & "\" & strRetValue01
    If fso.fileexists(strRetValNew02 & "\" & strRetValue01) Then
    WScript.echo  " "
        WScript.echo "    " & strRetValue01 & " exists on the LastUsedSource path, no actions needed."
    Else
        WScript.echo " "
        WScript.echo " !!!! " & strRetValue01 & " DOES NOT exist on the path in the path " & strRealPath & " !!!!"
        WScript.echo " "
        WScript.echo " Action needed, re-establish the path to " & strRealPath
' Placeholder for altering the LastUsedSource by adding source location and Forcing search of list
'        If strNewSource <> "" Then
'        WScript.echo "      New Install Source Path Added: " & strNewSource
'        wiInstaller.AddSource strRetValNew08, "", strNewSource
'        Else
'        If strNewRTMSource <> "" Then
'        wiInstaller.AddSource strRetValNew08, "", strNewRTMSource
'        WScript.echo "      Forcing SourceList Resolution For: " & strRetValNew08
'        wiInstaller.ForceSourceListResolution strRetValNew08, ""
'        End If
'        End If
    End If
        WScript.echo " "
        WScript.echo "Installer Cache File: " & strRetValNew04
    If fso.fileexists(strRetValNew04) Then
        WScript.echo " "
        WScript.echo "    Package exists in the Installer cache, no actions needed."
        WScript.echo "    Any missing packages will update automatically if needed assuming that"
        WScript.echo "    the LastUsedSource exists."
        WScript.echo " "
        WScript.echo "    Should you get errors about " & strRetValNew04 & " or " & strRealPath & strRetValue01 & " then you"
        WScript.echo "    may need to manually copy the file, if file exists replace the problem file, " 
        WScript.echo "    Copy and paste the following command line into an administrative command prompt:"
        WScript.echo " "
        WScript.echo "     Copy " & chr(34) & strRealPath  & strRetValue01 & chr(34) & " " &strRetValNew04
        WScript.echo " "
    Else
        WScript.echo " "
        WScript.echo " !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        WScript.echo " !!!! " & strRetValNew04 & " DOES NOT exist in the Installer cache. !!!!"
        WScript.echo " !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        WScript.echo " "
        WScript.echo "     Action needed, recreate or re-establish path to the directory:"
        WScript.echo "       " & strRealPath & "then rerun this script to update installer cache and results"
        WScript.echo "     The path on the line above must exist at the root location to resolve"
        WScript.echo "     this problem with your msi/msp file not being found or corrupted,"
        WScript.echo "     In some cases you may need to manually copy the missing file or manually"
        WScript.echo "     replace the problem file overwriting it is exist: " 
        WScript.echo " "
        WScript.echo "     Copy " & chr(34) & strRealPath  & strRetValue01 & chr(34) & " " &strRetValNew04
        WScript.echo " "
        WScript.echo "     Replace the existing file if prompted to do so."
        WScript.echo " "
    End If
    WScript.echo " "
    WScript.echo strRetValue00 & " Patches Installed "
    WScript.echo "--------------------------------------------------------------------------------"

    err.clear
    objReg.EnumKey HKLM, strInstallSource2, arrSubKeys2
    uUpperBounds = UBound(arrSubKeys2,1)
     If err.number = 0  Then
        For Each strSubKey2 in arrSubKeys2
    '    WScript.echo "value = " & strSubKey2

strKeyPath04 = "Installer\Patches\" & strSubKey2 & "\SourceList"

     objReg.GetDWORDValue HKLM, strInstallSource2 & "\" & strSubKey2 & "\", strNValue16, strRetValue16
     objReg.GetStringValue HKCR, strKeyPath04, strNValue15, strRetValue15a
     objReg.GetStringValue HKCR, strKeyPath04, strNValue14, strRetValue14a
     objReg.GetStringValue HKCR, strKeyPath02, strNValue15, strRetValue15b
     objReg.GetStringValue HKCR, strKeyPath02, strNValue14, strRetValue14b
     objReg.GetStringValue HKLM, strInstallSource2 & "\" & strSubKey2 & "\", strNValue17, strRetValue17
     objReg.GetStringValue HKLM, strInstallSource2 & "\" & strSubKey2 & "\", strNValue18, strRetValue18
     objReg.GetStringValue HKLM, strInstallSource2 & "\" & strSubKey2 & "\", strNValue13, strRetValue13a
     objReg.GetStringValue HKLM, strInstallSource3 & "\" & strSubKey2 & "\", strNValue04, strRetValue04a

' Pull the URL from the MoreInfoURL String
strMoreInfoURL = strRetValue13a
  MoreInfoURLLen = Len(strMoreInfoURL)
  'MoreInfoURLLen = MoreInfoURLLen - 15
strRetValue13b = Right(strMoreInfoURL, 42)

' Pull the URL from the LastUsedPath String
strLastUsedPath = strRetValue15a
  LastUsedPathLen = Len(strLastUsedPath)
  'LastUsedPathLen = LastUsedPathLen - 15
strRetValue15c = Mid(strLastUsedPath, 5)

      	WScript.echo " Display Name:    " & strRetValue17 
      	WScript.echo " KB Article URL:  " & strRetValue13b
      	WScript.echo " Install Date:    " & strRetValue18 
       	WScript.echo "   Uninstallable:   " & strRetValue16 
      	WScript.echo " Patch Details: "
      	WScript.echo "   HKEY_CLASSES_ROOT\Installer\Patches\" & strSubKey2
       	WScript.echo "   PackageName:   " & strRetValue14a
' Determine if someone has modified the Uninstallable state from 0 to 1 allowing possible unexpected uninstalls
       	WScript.echo "    Patch LastUsedSource: " & strRetValue15a 
'       WScript.echo "    LastUsedSource RTM: " & strRetValue15b 'strResultLastUsed
'      	WScript.echo strInstallSource3 & "\" & strSubKey2 & "\" & "LocalPackage"
       	WScript.echo "   Installer Cache File Path:     " & strRetValue04a 
        WScript.echo "     Per " & strInstallSource3 & "\" & strSubKey2 & "\" & strNValue04
' Testing output
'       WScript.echo " Original Product Package Name: " & strRetValue14b
' WScript.echo "Installer: " & strResultLocalPackage
        	mspFileName = (strRetValue15c  & strRetValue14a)
' Condition 1 not empty
      If strRetValue14a <> "" Then
' Condition 2 if cached file does exist
      If fso.fileexists(strRetValue04a) Then
        WScript.echo " "
        WScript.echo "    Package exists in the Installer cache, no actions needed."
        WScript.echo "    Package will update automatically if needed assuming that"
        WScript.echo "    the LastUsedSource exists."
        WScript.echo " "
        WScript.echo "    Should you get errors about " & strRetValue04a & " or " & strRetValue15c  & strRetValue14a & " then you"
        WScript.echo "    may need to manually copy the file, if file exists replace the problem file, " 
        WScript.echo "    Copy and paste the following command line into an administrative command prompt:"
        WScript.echo " "
        WScript.echo "     Copy " & chr(34) & strRetValue15c  & strRetValue14a & chr(34) & " " & strRetValue04a
        WScript.echo " "
      Else
        WScript.echo " "
        WScript.echo "!!!! " & strRetValue04a & " package DOES NOT exist in the Installer cache. !!!!"
        WScript.echo " "
        WScript.echo "     Action needed, recreate or re-establish path to the directory:"
        WScript.echo "       " & strRetValue15c & " then rerun this script to update installer cache and results"
        WScript.echo "     The path on the line above must exist at the root location to resolve"
        WScript.echo "     this problem with your msi/msp file not being found or corrupted,"
        WScript.echo "     In some cases you may need to manually copy the missing file or manually"
        WScript.echo "     replace the problem file overwriting it is exist: " 
        WScript.echo " "
        WScript.echo "     Copy " & chr(34) & strRetValue15c  & strRetValue14a & chr(34) & " " & strRetValue04a
        WScript.echo " "
        WScript.echo "     Replace the existing file if prompted to do so."
        WScript.echo " "
        WScript.echo "     Use the following URL to assist with downloading the patch:"
'        WScript.echo "      " & strRetValue13a ' RAW values
        WScript.echo "      " & strRetValue13b
        WScript.echo " "
        WScript.echo " "
      End If
       Else
        WScript.echo " "
     End If
        next
     Else
        WScript.echo " "
        WScript.echo "  No Patches Found"
        WScript.echo " "
    End If

' Get the uninstall string from the registry
strKeyPath04 = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" & strRetValNew08
strKeyPath05 = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" & strRetValNew08

   	objReg.GetStringValue HKLM, strKeyPath04, "InstanceId", strResultInstanceId
 	  objReg.GetStringValue HKLM, strKeyPath05, "InstanceId", strResultInstanceIdx86

   	If IsNull(strResultInstanceId) and IsNull(strResultInstanceIdx86) Then   		
        WScript.echo " "
    WScript.echo  "==================================================================================="
    WScript.echo  "*** WARNING **** This command line is not meant to be used under normal conditions."
    WScript.echo  " "
    WScript.echo  "Un-install string if exists = " & strRetValNew07
    WScript.echo  " "
    WScript.echo  "==================================================================================="
    WScript.echo  " "
  ElseIf IsNull(strResultInstanceId) Then
' Gather additional information about the SQL Server engine installations
    WScript.echo  " "
    WScript.echo "####################################################################################"
    WScript.echo "SQL Server Instance ID: " & strResultInstanceIdx86
    WScript.echo "SQL Server Instance " & strResultInstanceIdx86 & " Location Details, Binary Location and Data Paths"
    WScript.echo "=============================================================="
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "Edition", strSqlEdition
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "SqlProgramDir", strSqlProgramDir
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "SQLPath", strSQLPath
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "SQLDataRoot", strSQLDataRoot
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "SQLBinRoot", strSQLBinRoot
    objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "FullTextDefaultPath", strFullTextDefaultPath
'   WScript.echo "Instance path: " & strInstallSource8 & strResultInstanceIdx86 & "\Setup"
    WScript.echo " SQL Server Edition: " & strSqlEdition
    WScript.echo "   SqlProgramDir:  " & strSqlProgramDir
    WScript.echo "   SQLPath:        " & strSQLPath
    WScript.echo "   SQLDataRoot:    " & strSQLDataRoot
    WScript.echo "   SQLBinRoot:     " & strSQLBinRoot
    WScript.echo "   Full Text Path: " & strFullTextDefaultPath
    WScript.echo  " "
    WScript.echo  "*** WARNING **** This command line is not meant to be used under normal conditions."
    WScript.echo  " "
    WScript.echo  "Un-install string if exists = " & strRetValNew07
    WScript.echo " "
    WScript.echo "####################################################################################"
    WScript.echo  " "
Else
' Gather additional information about the SQL Server engine installations
    WScript.echo  " "
    WScript.echo "####################################################################################"
    WScript.echo "SQL Server Instance ID: " & strResultInstanceId
    WScript.echo "SQL Server Instance Location Details" & strResultInstanceId & " Binary and Data Paths"
    WScript.echo "=============================================================="
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "Edition", strSqlEdition
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "SqlProgramDir", strSqlProgramDir
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "SQLPath", strSQLPath
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "SQLDataRoot", strSQLDataRoot
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "SQLBinRoot", strSQLBinRoot
    objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "FullTextDefaultPath", strFullTextDefaultPath
    WScript.echo " SQL Server Edition: " & strSqlEdition
    WScript.echo "   SqlProgramDir:  " & strSqlProgramDir
    WScript.echo "   SQLPath:        " & strSQLPath
    WScript.echo "   SQLDataRoot:    " & strSQLDataRoot
    WScript.echo "   SQLBinRoot:     " & strSQLBinRoot
    WScript.echo "   Full Text Path: " & strFullTextDefaultPath
    WScript.echo  " "
    WScript.echo  "*** WARNING **** This command line is not meant to be used under normal conditions."
    WScript.echo  " "
    WScript.echo  "Un-install string if exists = " & strRetValNew07
    WScript.echo " "
    WScript.echo "####################################################################################"
    WScript.echo  " "
    End If
     End If

If instr(1, strRetValue00, strDotNetName, 1) Then
' Start the log output
    WScript.echo "================================================================================"
    WScript.echo "PRODUCT NAME   : " & strRetValue00
    WScript.echo "================================================================================"
    WScript.echo "  Product Code: " & strRetValNew08
    WScript.echo "  Version     : " & strRetValNew05
    WScript.echo "  Most Current Install Date: " & strRetValNew06
    WScript.echo "  Target Install Location: "  & strRetValNew13
    WScript.echo "  Registry Path: "
    WScript.echo "   HKEY_CLASSES_ROOT\" & strKeyPath02
    WScript.echo "     Package    : " & strRetValue01
    WScript.echo "  Install Source: " & strRetValue10
    WScript.echo "  LastUsedSource: " & strRetValue02
'   WScript.echo "Does this file on this path exist? " & strRetValNew02 & "\" & strRetValue01
    If fso.fileexists(strRetValNew02 & "\" & strRetValue01) Then
    WScript.echo  " "
        WScript.echo "    " & strRetValue01 & " exists on the LastUsedSource path, no actions needed."
    Else
        WScript.echo " "
        WScript.echo " !!!! " & strRetValue01 & " DOES NOT exist on the path in the path " & strRealPath & " !!!!"
        WScript.echo " "
        WScript.echo " Action needed, re-establish the path to " & strRealPath
' Placeholder for altering the LastUsedSource by adding source location and Forcing search of list
'        If strNewSource <> "" Then
'        WScript.echo "      New Install Source Path Added: " & strNewSource
'        wiInstaller.AddSource strRetValNew08, "", strNewSource
'        Else
'        If strNewRTMSource <> "" Then
'        wiInstaller.AddSource strRetValNew08, "", strNewRTMSource
'        WScript.echo "      Forcing SourceList Resolution For: " & strRetValNew08
'        wiInstaller.ForceSourceListResolution strRetValNew08, ""
'        End If
'        End If
    End If
        WScript.echo " "
        WScript.echo "Installer Cache File: " & strRetValNew04
    If fso.fileexists(strRetValNew04) Then
        WScript.echo " "
        WScript.echo "    Package exists in the Installer cache, no actions needed."
        WScript.echo "    Any missing packages will update automatically if needed assuming that"
        WScript.echo "    the LastUsedSource exists."
        WScript.echo " "
        WScript.echo "    Should you get errors about " & strRetValNew04 & " or " & strRealPath & strRetValue01 & " then you"
        WScript.echo "    may need to manually copy the file, if file exists replace the problem file, " 
        WScript.echo "    Copy and paste the following command line into an administrative command prompt:"
        WScript.echo " "
        WScript.echo "     Copy " & chr(34) & strRealPath  & strRetValue01 & chr(34) & " " &strRetValNew04
        WScript.echo " "
    Else
        WScript.echo " "
        WScript.echo " !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        WScript.echo " !!!! " & strRetValNew04 & " DOES NOT exist in the Installer cache. !!!!"
        WScript.echo " !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        WScript.echo " "
        WScript.echo "     Action needed, recreate or re-establish path to the directory:"
        WScript.echo "       " & strRealPath & "then rerun this script to update installer cache and results"
        WScript.echo "     The path on the line above must exist at the root location to resolve"
        WScript.echo "     this problem with your msi/msp file not being found or corrupted,"
        WScript.echo "     In some cases you may need to manually copy the missing file or manually"
        WScript.echo "     replace the problem file overwriting it is exist: " 
        WScript.echo " "
        WScript.echo "     Copy " & chr(34) & strRealPath  & strRetValue01 & chr(34) & " " &strRetValNew04
        WScript.echo " "
        WScript.echo "     Replace the existing file if prompted to do so."
        WScript.echo " "
    End If
    WScript.echo " "
    WScript.echo strRetValue00 & " Patches Installed "
    WScript.echo "--------------------------------------------------------------------------------"

    err.clear
    objReg.EnumKey HKLM, strInstallSource2, arrSubKeys2
    uUpperBounds = UBound(arrSubKeys2,1)
     If err.number = 0  Then
        For Each strSubKey2 in arrSubKeys2
    '    WScript.echo "value = " & strSubKey2

strKeyPath04 = "Installer\Patches\" & strSubKey2 & "\SourceList"

     objReg.GetDWORDValue HKLM, strInstallSource2 & "\" & strSubKey2 & "\", strNValue16, strRetValue16
     objReg.GetStringValue HKCR, strKeyPath04, strNValue15, strRetValue15a
     objReg.GetStringValue HKCR, strKeyPath04, strNValue14, strRetValue14a
     objReg.GetStringValue HKCR, strKeyPath02, strNValue15, strRetValue15b
     objReg.GetStringValue HKCR, strKeyPath02, strNValue14, strRetValue14b
     objReg.GetStringValue HKLM, strInstallSource2 & "\" & strSubKey2 & "\", strNValue17, strRetValue17
     objReg.GetStringValue HKLM, strInstallSource2 & "\" & strSubKey2 & "\", strNValue18, strRetValue18
     objReg.GetStringValue HKLM, strInstallSource2 & "\" & strSubKey2 & "\", strNValue13, strRetValue13a
     objReg.GetStringValue HKLM, strInstallSource3 & "\" & strSubKey2 & "\", strNValue04, strRetValue04a

' Pull the URL from the MoreInfoURL String
strMoreInfoURL = strRetValue13a
  MoreInfoURLLen = Len(strMoreInfoURL)
  'MoreInfoURLLen = MoreInfoURLLen - 15
strRetValue13b = Right(strMoreInfoURL, 42)

' Pull the URL from the LastUsedPath String
strLastUsedPath = strRetValue15a
  LastUsedPathLen = Len(strLastUsedPath)
  'LastUsedPathLen = LastUsedPathLen - 15
strRetValue15c = Mid(strLastUsedPath, 5)

      	WScript.echo " Display Name:    " & strRetValue17 
      	WScript.echo " KB Article URL:  " & strRetValue13b
      	WScript.echo " Install Date:    " & strRetValue18 
       	WScript.echo "   Uninstallable:   " & strRetValue16 
      	WScript.echo " Patch Details: "
      	WScript.echo "   HKEY_CLASSES_ROOT\Installer\Patches\" & strSubKey2
       	WScript.echo "   PackageName:   " & strRetValue14a
' Determine if someone has modified the Uninstallable state from 0 to 1 allowing possible unexpected uninstalls
       	WScript.echo "    Patch LastUsedSource: " & strRetValue15a 
'       WScript.echo "    LastUsedSource RTM: " & strRetValue15b 'strResultLastUsed
'      	WScript.echo strInstallSource3 & "\" & strSubKey2 & "\" & "LocalPackage"
       	WScript.echo "   Installer Cache File Path:     " & strRetValue04a 
        WScript.echo "     Per " & strInstallSource3 & "\" & strSubKey2 & "\" & strNValue04
' Testing output
'       WScript.echo " Original Product Package Name: " & strRetValue14b
' WScript.echo "Installer: " & strResultLocalPackage
        	mspFileName = (strRetValue15c  & strRetValue14a)
' Condition 1 not empty
      If strRetValue14a <> "" Then
' Condition 2 if cached file does exist
      If fso.fileexists(strRetValue04a) Then
        WScript.echo " "
        WScript.echo "    Package exists in the Installer cache, no actions needed."
        WScript.echo "    Package will update automatically if needed assuming that"
        WScript.echo "    the LastUsedSource exists."
        WScript.echo " "
        WScript.echo "    Should you get errors about " & strRetValue04a & " or " & strRetValue15c  & strRetValue14a & " then you"
        WScript.echo "    may need to manually copy the file, if file exists replace the problem file, " 
        WScript.echo "    Copy and paste the following command line into an administrative command prompt:"
        WScript.echo " "
        WScript.echo "     Copy " & chr(34) & strRetValue15c  & strRetValue14a & chr(34) & " " & strRetValue04a
        WScript.echo " "
      Else
        WScript.echo " "
        WScript.echo "!!!! " & strRetValue04a & " package DOES NOT exist in the Installer cache. !!!!"
        WScript.echo " "
        WScript.echo "     Action needed, recreate or re-establish path to the directory:"
        WScript.echo "       " & strRetValue15c & " then rerun this script to update installer cache and results"
        WScript.echo "     The path on the line above must exist at the root location to resolve"
        WScript.echo "     this problem with your msi/msp file not being found or corrupted,"
        WScript.echo "     In some cases you may need to manually copy the missing file or manually"
        WScript.echo "     replace the problem file overwriting it is exist: " 
        WScript.echo " "
        WScript.echo "     Copy " & chr(34) & strRetValue15c  & strRetValue14a & chr(34) & " " & strRetValue04a
        WScript.echo " "
        WScript.echo "     Replace the existing file if prompted to do so."
        WScript.echo " "
        WScript.echo "     Use the following URL to assist with downloading the patch:"
'        WScript.echo "      " & strRetValue13a ' RAW values
        WScript.echo "      " & strRetValue13b
        WScript.echo " "
        WScript.echo " "
      End If
       Else
        WScript.echo " "
     End If
        next
     Else
        WScript.echo " "
        WScript.echo "  No Patches Found"
        WScript.echo " "
    End If

' Get the uninstall string from the registry
strKeyPath04 = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" & strRetValNew08
strKeyPath05 = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" & strRetValNew08

   	objReg.GetStringValue HKLM, strKeyPath04, "InstanceId", strResultInstanceId
 	  objReg.GetStringValue HKLM, strKeyPath05, "InstanceId", strResultInstanceIdx86

   	If IsNull(strResultInstanceId) and IsNull(strResultInstanceIdx86) Then   		
        WScript.echo " "
    WScript.echo  "==================================================================================="
    WScript.echo  "*** WARNING **** This command line is not meant to be used under normal conditions."
    WScript.echo  " "
    WScript.echo  "Un-install string if exists = " & strRetValNew07
    WScript.echo  " "
    WScript.echo  "==================================================================================="
    WScript.echo  " "
  ElseIf IsNull(strResultInstanceId) Then
' Gather additional information about the SQL Server engine installations
    WScript.echo  " "
    WScript.echo "####################################################################################"
    WScript.echo "SQL Server Instance ID: " & strResultInstanceIdx86
    WScript.echo "SQL Server Instance " & strResultInstanceIdx86 & " Location Details, Binary Location and Data Paths"
    WScript.echo "=============================================================="
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "Edition", strSqlEdition
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "SqlProgramDir", strSqlProgramDir
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "SQLPath", strSQLPath
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "SQLDataRoot", strSQLDataRoot
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "SQLBinRoot", strSQLBinRoot
    objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "FullTextDefaultPath", strFullTextDefaultPath
'   WScript.echo "Instance path: " & strInstallSource8 & strResultInstanceIdx86 & "\Setup"
    WScript.echo " SQL Server Edition: " & strSqlEdition
    WScript.echo "   SqlProgramDir:  " & strSqlProgramDir
    WScript.echo "   SQLPath:        " & strSQLPath
    WScript.echo "   SQLDataRoot:    " & strSQLDataRoot
    WScript.echo "   SQLBinRoot:     " & strSQLBinRoot
    WScript.echo "   Full Text Path: " & strFullTextDefaultPath
    WScript.echo  " "
    WScript.echo  "*** WARNING **** This command line is not meant to be used under normal conditions."
    WScript.echo  " "
    WScript.echo  "Un-install string if exists = " & strRetValNew07
    WScript.echo " "
    WScript.echo "####################################################################################"
    WScript.echo  " "
Else
' Gather additional information about the SQL Server engine installations
    WScript.echo  " "
    WScript.echo "####################################################################################"
    WScript.echo "SQL Server Instance ID: " & strResultInstanceId
    WScript.echo "SQL Server Instance Location Details" & strResultInstanceId & " Binary and Data Paths"
    WScript.echo "=============================================================="
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "Edition", strSqlEdition
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "SqlProgramDir", strSqlProgramDir
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "SQLPath", strSQLPath
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "SQLDataRoot", strSQLDataRoot
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "SQLBinRoot", strSQLBinRoot
    objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "FullTextDefaultPath", strFullTextDefaultPath
    WScript.echo " SQL Server Edition: " & strSqlEdition
    WScript.echo "   SqlProgramDir:  " & strSqlProgramDir
    WScript.echo "   SQLPath:        " & strSQLPath
    WScript.echo "   SQLDataRoot:    " & strSQLDataRoot
    WScript.echo "   SQLBinRoot:     " & strSQLBinRoot
    WScript.echo "   Full Text Path: " & strFullTextDefaultPath
    WScript.echo  " "
    WScript.echo  "*** WARNING **** This command line is not meant to be used under normal conditions."
    WScript.echo  " "
    WScript.echo  "Un-install string if exists = " & strRetValNew07
    WScript.echo " "
    WScript.echo "####################################################################################"
    WScript.echo  " "
    End If
     End If

If instr(1, strRetValue00, strVStudioName, 1) Then
' Start the log output
    WScript.echo "================================================================================"
    WScript.echo "PRODUCT NAME   : " & strRetValue00
    WScript.echo "================================================================================"
    WScript.echo "  Product Code: " & strRetValNew08
    WScript.echo "  Version     : " & strRetValNew05
    WScript.echo "  Most Current Install Date: " & strRetValNew06
    WScript.echo "  Target Install Location: "  & strRetValNew13
    WScript.echo "  Registry Path: "
    WScript.echo "   HKEY_CLASSES_ROOT\" & strKeyPath02
    WScript.echo "     Package    : " & strRetValue01
    WScript.echo "  Install Source: " & strRetValue10
    WScript.echo "  LastUsedSource: " & strRetValue02
'   WScript.echo "Does this file on this path exist? " & strRetValNew02 & "\" & strRetValue01
    If fso.fileexists(strRetValNew02 & "\" & strRetValue01) Then
    WScript.echo  " "
        WScript.echo "    " & strRetValue01 & " exists on the LastUsedSource path, no actions needed."
    Else
        WScript.echo " "
        WScript.echo " !!!! " & strRetValue01 & " DOES NOT exist on the path in the path " & strRealPath & " !!!!"
        WScript.echo " "
        WScript.echo " Action needed, re-establish the path to " & strRealPath
' Placeholder for altering the LastUsedSource by adding source location and Forcing search of list
'        If strNewSource <> "" Then
'        WScript.echo "      New Install Source Path Added: " & strNewSource
'        wiInstaller.AddSource strRetValNew08, "", strNewSource
'        Else
'        If strNewRTMSource <> "" Then
'        wiInstaller.AddSource strRetValNew08, "", strNewRTMSource
'        WScript.echo "      Forcing SourceList Resolution For: " & strRetValNew08
'        wiInstaller.ForceSourceListResolution strRetValNew08, ""
'        End If
'        End If
    End If
        WScript.echo " "
        WScript.echo "Installer Cache File: " & strRetValNew04
    If fso.fileexists(strRetValNew04) Then
        WScript.echo " "
        WScript.echo "    Package exists in the Installer cache, no actions needed."
        WScript.echo "    Any missing packages will update automatically if needed assuming that"
        WScript.echo "    the LastUsedSource exists."
        WScript.echo " "
        WScript.echo "    Should you get errors about " & strRetValNew04 & " or " & strRealPath & strRetValue01 & " then you"
        WScript.echo "    may need to manually copy the file, if file exists replace the problem file, " 
        WScript.echo "    Copy and paste the following command line into an administrative command prompt:"
        WScript.echo " "
        WScript.echo "     Copy " & chr(34) & strRealPath  & strRetValue01 & chr(34) & " " &strRetValNew04
        WScript.echo " "
    Else
        WScript.echo " "
        WScript.echo " !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        WScript.echo " !!!! " & strRetValNew04 & " DOES NOT exist in the Installer cache. !!!!"
        WScript.echo " !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        WScript.echo " "
        WScript.echo "     Action needed, recreate or re-establish path to the directory:"
        WScript.echo "       " & strRealPath & "then rerun this script to update installer cache and results"
        WScript.echo "     The path on the line above must exist at the root location to resolve"
        WScript.echo "     this problem with your msi/msp file not being found or corrupted,"
        WScript.echo "     In some cases you may need to manually copy the missing file or manually"
        WScript.echo "     replace the problem file overwriting it is exist: " 
        WScript.echo " "
        WScript.echo "     Copy " & chr(34) & strRealPath  & strRetValue01 & chr(34) & " " &strRetValNew04
        WScript.echo " "
        WScript.echo "     Replace the existing file if prompted to do so."
        WScript.echo " "
    End If
    WScript.echo " "
    WScript.echo strRetValue00 & " Patches Installed "
    WScript.echo "--------------------------------------------------------------------------------"

    err.clear
    objReg.EnumKey HKLM, strInstallSource2, arrSubKeys2
    uUpperBounds = UBound(arrSubKeys2,1)
     If err.number = 0  Then
        For Each strSubKey2 in arrSubKeys2
    '    WScript.echo "value = " & strSubKey2

strKeyPath04 = "Installer\Patches\" & strSubKey2 & "\SourceList"

     objReg.GetDWORDValue HKLM, strInstallSource2 & "\" & strSubKey2 & "\", strNValue16, strRetValue16
     objReg.GetStringValue HKCR, strKeyPath04, strNValue15, strRetValue15a
     objReg.GetStringValue HKCR, strKeyPath04, strNValue14, strRetValue14a
     objReg.GetStringValue HKCR, strKeyPath02, strNValue15, strRetValue15b
     objReg.GetStringValue HKCR, strKeyPath02, strNValue14, strRetValue14b
     objReg.GetStringValue HKLM, strInstallSource2 & "\" & strSubKey2 & "\", strNValue17, strRetValue17
     objReg.GetStringValue HKLM, strInstallSource2 & "\" & strSubKey2 & "\", strNValue18, strRetValue18
     objReg.GetStringValue HKLM, strInstallSource2 & "\" & strSubKey2 & "\", strNValue13, strRetValue13a
     objReg.GetStringValue HKLM, strInstallSource3 & "\" & strSubKey2 & "\", strNValue04, strRetValue04a

' Pull the URL from the MoreInfoURL String
strMoreInfoURL = strRetValue13a
  MoreInfoURLLen = Len(strMoreInfoURL)
  'MoreInfoURLLen = MoreInfoURLLen - 15
strRetValue13b = Right(strMoreInfoURL, 42)

' Pull the URL from the LastUsedPath String
strLastUsedPath = strRetValue15a
  LastUsedPathLen = Len(strLastUsedPath)
  'LastUsedPathLen = LastUsedPathLen - 15
strRetValue15c = Mid(strLastUsedPath, 5)

      	WScript.echo " Display Name:    " & strRetValue17 
      	WScript.echo " KB Article URL:  " & strRetValue13b
      	WScript.echo " Install Date:    " & strRetValue18 
       	WScript.echo "   Uninstallable:   " & strRetValue16 
      	WScript.echo " Patch Details: "
      	WScript.echo "   HKEY_CLASSES_ROOT\Installer\Patches\" & strSubKey2
       	WScript.echo "   PackageName:   " & strRetValue14a
' Determine if someone has modified the Uninstallable state from 0 to 1 allowing possible unexpected uninstalls
       	WScript.echo "    Patch LastUsedSource: " & strRetValue15a 
'       WScript.echo "    LastUsedSource RTM: " & strRetValue15b 'strResultLastUsed
'      	WScript.echo strInstallSource3 & "\" & strSubKey2 & "\" & "LocalPackage"
       	WScript.echo "   Installer Cache File Path:     " & strRetValue04a 
        WScript.echo "     Per " & strInstallSource3 & "\" & strSubKey2 & "\" & strNValue04
' Testing output
'       WScript.echo " Original Product Package Name: " & strRetValue14b
' WScript.echo "Installer: " & strResultLocalPackage
        	mspFileName = (strRetValue15c  & strRetValue14a)
' Condition 1 not empty
      If strRetValue14a <> "" Then
' Condition 2 if cached file does exist
      If fso.fileexists(strRetValue04a) Then
        WScript.echo " "
        WScript.echo "    Package exists in the Installer cache, no actions needed."
        WScript.echo "    Package will update automatically if needed assuming that"
        WScript.echo "    the LastUsedSource exists."
        WScript.echo " "
        WScript.echo "    Should you get errors about " & strRetValue04a & " or " & strRetValue15c  & strRetValue14a & " then you"
        WScript.echo "    may need to manually copy the file, if file exists replace the problem file, " 
        WScript.echo "    Copy and paste the following command line into an administrative command prompt:"
        WScript.echo " "
        WScript.echo "     Copy " & chr(34) & strRetValue15c  & strRetValue14a & chr(34) & " " & strRetValue04a
        WScript.echo " "
      Else
        WScript.echo " "
        WScript.echo "!!!! " & strRetValue04a & " package DOES NOT exist in the Installer cache. !!!!"
        WScript.echo " "
        WScript.echo "     Action needed, recreate or re-establish path to the directory:"
        WScript.echo "       " & strRetValue15c & " then rerun this script to update installer cache and results"
        WScript.echo "     The path on the line above must exist at the root location to resolve"
        WScript.echo "     this problem with your msi/msp file not being found or corrupted,"
        WScript.echo "     In some cases you may need to manually copy the missing file or manually"
        WScript.echo "     replace the problem file overwriting it is exist: " 
        WScript.echo " "
        WScript.echo "     Copy " & chr(34) & strRetValue15c  & strRetValue14a & chr(34) & " " & strRetValue04a
        WScript.echo " "
        WScript.echo "     Replace the existing file if prompted to do so."
        WScript.echo " "
        WScript.echo "     Use the following URL to assist with downloading the patch:"
'        WScript.echo "      " & strRetValue13a ' RAW values
        WScript.echo "      " & strRetValue13b
        WScript.echo " "
        WScript.echo " "
      End If
       Else
        WScript.echo " "
     End If
        next
     Else
        WScript.echo " "
        WScript.echo "  No Patches Found"
        WScript.echo " "
    End If

' Get the uninstall string from the registry
strKeyPath04 = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" & strRetValNew08
strKeyPath05 = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" & strRetValNew08

   	objReg.GetStringValue HKLM, strKeyPath04, "InstanceId", strResultInstanceId
 	  objReg.GetStringValue HKLM, strKeyPath05, "InstanceId", strResultInstanceIdx86

   	If IsNull(strResultInstanceId) and IsNull(strResultInstanceIdx86) Then   		
        WScript.echo " "
    WScript.echo  "==================================================================================="
    WScript.echo  "*** WARNING **** This command line is not meant to be used under normal conditions."
    WScript.echo  " "
    WScript.echo  "Un-install string if exists = " & strRetValNew07
    WScript.echo  " "
    WScript.echo  "==================================================================================="
    WScript.echo  " "
  ElseIf IsNull(strResultInstanceId) Then
' Gather additional information about the SQL Server engine installations
    WScript.echo  " "
    WScript.echo "####################################################################################"
    WScript.echo "SQL Server Instance ID: " & strResultInstanceIdx86
    WScript.echo "SQL Server Instance " & strResultInstanceIdx86 & " Location Details, Binary Location and Data Paths"
    WScript.echo "=============================================================="
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "Edition", strSqlEdition
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "SqlProgramDir", strSqlProgramDir
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "SQLPath", strSQLPath
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "SQLDataRoot", strSQLDataRoot
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "SQLBinRoot", strSQLBinRoot
    objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "FullTextDefaultPath", strFullTextDefaultPath
'   WScript.echo "Instance path: " & strInstallSource8 & strResultInstanceIdx86 & "\Setup"
    WScript.echo " SQL Server Edition: " & strSqlEdition
    WScript.echo "   SqlProgramDir:  " & strSqlProgramDir
    WScript.echo "   SQLPath:        " & strSQLPath
    WScript.echo "   SQLDataRoot:    " & strSQLDataRoot
    WScript.echo "   SQLBinRoot:     " & strSQLBinRoot
    WScript.echo "   Full Text Path: " & strFullTextDefaultPath
    WScript.echo  " "
    WScript.echo  "*** WARNING **** This command line is not meant to be used under normal conditions."
    WScript.echo  " "
    WScript.echo  "Un-install string if exists = " & strRetValNew07
    WScript.echo " "
    WScript.echo "####################################################################################"
    WScript.echo  " "
Else
' Gather additional information about the SQL Server engine installations
    WScript.echo  " "
    WScript.echo "####################################################################################"
    WScript.echo "SQL Server Instance ID: " & strResultInstanceId
    WScript.echo "SQL Server Instance Location Details" & strResultInstanceId & " Binary and Data Paths"
    WScript.echo "=============================================================="
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "Edition", strSqlEdition
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "SqlProgramDir", strSqlProgramDir
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "SQLPath", strSQLPath
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "SQLDataRoot", strSQLDataRoot
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "SQLBinRoot", strSQLBinRoot
    objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "FullTextDefaultPath", strFullTextDefaultPath
    WScript.echo " SQL Server Edition: " & strSqlEdition
    WScript.echo "   SqlProgramDir:  " & strSqlProgramDir
    WScript.echo "   SQLPath:        " & strSQLPath
    WScript.echo "   SQLDataRoot:    " & strSQLDataRoot
    WScript.echo "   SQLBinRoot:     " & strSQLBinRoot
    WScript.echo "   Full Text Path: " & strFullTextDefaultPath
    WScript.echo  " "
    WScript.echo  "*** WARNING **** This command line is not meant to be used under normal conditions."
    WScript.echo  " "
    WScript.echo  "Un-install string if exists = " & strRetValNew07
    WScript.echo " "
    WScript.echo "####################################################################################"
    WScript.echo  " "
    End If
     End If

If instr(1, strRetValue00, strXML, 1) Then
' Start the log output
    WScript.echo "================================================================================"
    WScript.echo "PRODUCT NAME   : " & strRetValue00
    WScript.echo "================================================================================"
    WScript.echo "  Product Code: " & strRetValNew08
    WScript.echo "  Version     : " & strRetValNew05
    WScript.echo "  Most Current Install Date: " & strRetValNew06
    WScript.echo "  Target Install Location: "  & strRetValNew13
    WScript.echo "  Registry Path: "
    WScript.echo "   HKEY_CLASSES_ROOT\" & strKeyPath02
    WScript.echo "     Package    : " & strRetValue01
    WScript.echo "  Install Source: " & strRetValue10
    WScript.echo "  LastUsedSource: " & strRetValue02
'   WScript.echo "Does this file on this path exist? " & strRetValNew02 & "\" & strRetValue01
    If fso.fileexists(strRetValNew02 & "\" & strRetValue01) Then
    WScript.echo  " "
        WScript.echo "    " & strRetValue01 & " exists on the LastUsedSource path, no actions needed."
    Else
        WScript.echo " "
        WScript.echo " !!!! " & strRetValue01 & " DOES NOT exist on the path in the path " & strRealPath & " !!!!"
        WScript.echo " "
        WScript.echo " Action needed, re-establish the path to " & strRealPath
' Placeholder for altering the LastUsedSource by adding source location and Forcing search of list
'        If strNewSource <> "" Then
'        WScript.echo "      New Install Source Path Added: " & strNewSource
'        wiInstaller.AddSource strRetValNew08, "", strNewSource
'        Else
'        If strNewRTMSource <> "" Then
'        wiInstaller.AddSource strRetValNew08, "", strNewRTMSource
'        WScript.echo "      Forcing SourceList Resolution For: " & strRetValNew08
'        wiInstaller.ForceSourceListResolution strRetValNew08, ""
'        End If
'        End If
    End If
        WScript.echo " "
        WScript.echo "Installer Cache File: " & strRetValNew04
    If fso.fileexists(strRetValNew04) Then
        WScript.echo " "
        WScript.echo "    Package exists in the Installer cache, no actions needed."
        WScript.echo "    Any missing packages will update automatically if needed assuming that"
        WScript.echo "    the LastUsedSource exists."
        WScript.echo " "
        WScript.echo "    Should you get errors about " & strRetValNew04 & " or " & strRealPath & strRetValue01 & " then you"
        WScript.echo "    may need to manually copy the file, if file exists replace the problem file, " 
        WScript.echo "    Copy and paste the following command line into an administrative command prompt:"
        WScript.echo " "
        WScript.echo "     Copy " & chr(34) & strRealPath  & strRetValue01 & chr(34) & " " &strRetValNew04
        WScript.echo " "
    Else
        WScript.echo " "
        WScript.echo " !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        WScript.echo " !!!! " & strRetValNew04 & " DOES NOT exist in the Installer cache. !!!!"
        WScript.echo " !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        WScript.echo " "
        WScript.echo "     Action needed, recreate or re-establish path to the directory:"
        WScript.echo "       " & strRealPath & "then rerun this script to update installer cache and results"
        WScript.echo "     The path on the line above must exist at the root location to resolve"
        WScript.echo "     this problem with your msi/msp file not being found or corrupted,"
        WScript.echo "     In some cases you may need to manually copy the missing file or manually"
        WScript.echo "     replace the problem file overwriting it is exist: " 
        WScript.echo " "
        WScript.echo "     Copy " & chr(34) & strRealPath  & strRetValue01 & chr(34) & " " &strRetValNew04
        WScript.echo " "
        WScript.echo "     Replace the existing file if prompted to do so."
        WScript.echo " "
    End If
    WScript.echo " "
    WScript.echo strRetValue00 & " Patches Installed "
    WScript.echo "--------------------------------------------------------------------------------"

    err.clear
    objReg.EnumKey HKLM, strInstallSource2, arrSubKeys2
    uUpperBounds = UBound(arrSubKeys2,1)
     If err.number = 0  Then
        For Each strSubKey2 in arrSubKeys2
    '    WScript.echo "value = " & strSubKey2

strKeyPath04 = "Installer\Patches\" & strSubKey2 & "\SourceList"

     objReg.GetDWORDValue HKLM, strInstallSource2 & "\" & strSubKey2 & "\", strNValue16, strRetValue16
     objReg.GetStringValue HKCR, strKeyPath04, strNValue15, strRetValue15a
     objReg.GetStringValue HKCR, strKeyPath04, strNValue14, strRetValue14a
     objReg.GetStringValue HKCR, strKeyPath02, strNValue15, strRetValue15b
     objReg.GetStringValue HKCR, strKeyPath02, strNValue14, strRetValue14b
     objReg.GetStringValue HKLM, strInstallSource2 & "\" & strSubKey2 & "\", strNValue17, strRetValue17
     objReg.GetStringValue HKLM, strInstallSource2 & "\" & strSubKey2 & "\", strNValue18, strRetValue18
     objReg.GetStringValue HKLM, strInstallSource2 & "\" & strSubKey2 & "\", strNValue13, strRetValue13a
     objReg.GetStringValue HKLM, strInstallSource3 & "\" & strSubKey2 & "\", strNValue04, strRetValue04a

' Pull the URL from the MoreInfoURL String
strMoreInfoURL = strRetValue13a
  MoreInfoURLLen = Len(strMoreInfoURL)
  'MoreInfoURLLen = MoreInfoURLLen - 15
strRetValue13b = Right(strMoreInfoURL, 42)

' Pull the URL from the LastUsedPath String
strLastUsedPath = strRetValue15a
  LastUsedPathLen = Len(strLastUsedPath)
  'LastUsedPathLen = LastUsedPathLen - 15
strRetValue15c = Mid(strLastUsedPath, 5)

      	WScript.echo " Display Name:    " & strRetValue17 
      	WScript.echo " KB Article URL:  " & strRetValue13b
      	WScript.echo " Install Date:    " & strRetValue18 
       	WScript.echo "   Uninstallable:   " & strRetValue16 
      	WScript.echo " Patch Details: "
      	WScript.echo "   HKEY_CLASSES_ROOT\Installer\Patches\" & strSubKey2
       	WScript.echo "   PackageName:   " & strRetValue14a
' Determine if someone has modified the Uninstallable state from 0 to 1 allowing possible unexpected uninstalls
       	WScript.echo "    Patch LastUsedSource: " & strRetValue15a 
'       WScript.echo "    LastUsedSource RTM: " & strRetValue15b 'strResultLastUsed
'      	WScript.echo strInstallSource3 & "\" & strSubKey2 & "\" & "LocalPackage"
       	WScript.echo "   Installer Cache File Path:     " & strRetValue04a 
        WScript.echo "     Per " & strInstallSource3 & "\" & strSubKey2 & "\" & strNValue04
' Testing output
'       WScript.echo " Original Product Package Name: " & strRetValue14b
' WScript.echo "Installer: " & strResultLocalPackage
        	mspFileName = (strRetValue15c  & strRetValue14a)
' Condition 1 not empty
      If strRetValue14a <> "" Then
' Condition 2 if cached file does exist
      If fso.fileexists(strRetValue04a) Then
        WScript.echo " "
        WScript.echo "    Package exists in the Installer cache, no actions needed."
        WScript.echo "    Package will update automatically if needed assuming that"
        WScript.echo "    the LastUsedSource exists."
        WScript.echo " "
        WScript.echo "    Should you get errors about " & strRetValue04a & " or " & strRetValue15c  & strRetValue14a & " then you"
        WScript.echo "    may need to manually copy the file, if file exists replace the problem file, " 
        WScript.echo "    Copy and paste the following command line into an administrative command prompt:"
        WScript.echo " "
        WScript.echo "     Copy " & chr(34) & strRetValue15c  & strRetValue14a & chr(34) & " " & strRetValue04a
        WScript.echo " "
      Else
        WScript.echo " "
        WScript.echo "!!!! " & strRetValue04a & " package DOES NOT exist in the Installer cache. !!!!"
        WScript.echo " "
        WScript.echo "     Action needed, recreate or re-establish path to the directory:"
        WScript.echo "       " & strRetValue15c & " then rerun this script to update installer cache and results"
        WScript.echo "     The path on the line above must exist at the root location to resolve"
        WScript.echo "     this problem with your msi/msp file not being found or corrupted,"
        WScript.echo "     In some cases you may need to manually copy the missing file or manually"
        WScript.echo "     replace the problem file overwriting it is exist: " 
        WScript.echo " "
        WScript.echo "     Copy " & chr(34) & strRetValue15c  & strRetValue14a & chr(34) & " " & strRetValue04a
        WScript.echo " "
        WScript.echo "     Replace the existing file if prompted to do so."
        WScript.echo " "
        WScript.echo "     Use the following URL to assist with downloading the patch:"
'        WScript.echo "      " & strRetValue13a ' RAW values
        WScript.echo "      " & strRetValue13b
        WScript.echo " "
        WScript.echo " "
      End If
       Else
        WScript.echo " "
     End If
        next
     Else
        WScript.echo " "
        WScript.echo "  No Patches Found"
        WScript.echo " "
    End If

' Get the uninstall string from the registry
strKeyPath04 = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" & strRetValNew08
strKeyPath05 = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" & strRetValNew08

   	objReg.GetStringValue HKLM, strKeyPath04, "InstanceId", strResultInstanceId
 	  objReg.GetStringValue HKLM, strKeyPath05, "InstanceId", strResultInstanceIdx86

   	If IsNull(strResultInstanceId) and IsNull(strResultInstanceIdx86) Then   		
        WScript.echo " "
    WScript.echo  "==================================================================================="
    WScript.echo  "*** WARNING **** This command line is not meant to be used under normal conditions."
    WScript.echo  " "
    WScript.echo  "Un-install string if exists = " & strRetValNew07
    WScript.echo  " "
    WScript.echo  "==================================================================================="
    WScript.echo  " "
  ElseIf IsNull(strResultInstanceId) Then
' Gather additional information about the SQL Server engine installations
    WScript.echo  " "
    WScript.echo "####################################################################################"
    WScript.echo "SQL Server Instance ID: " & strResultInstanceIdx86
    WScript.echo "SQL Server Instance " & strResultInstanceIdx86 & " Location Details, Binary Location and Data Paths"
    WScript.echo "=============================================================="
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "Edition", strSqlEdition
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "SqlProgramDir", strSqlProgramDir
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "SQLPath", strSQLPath
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "SQLDataRoot", strSQLDataRoot
   	objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "SQLBinRoot", strSQLBinRoot
    objReg.GetStringValue HKLM, strInstallSource8 & strResultInstanceIdx86 & "\Setup", "FullTextDefaultPath", strFullTextDefaultPath
'   WScript.echo "Instance path: " & strInstallSource8 & strResultInstanceIdx86 & "\Setup"
    WScript.echo " SQL Server Edition: " & strSqlEdition
    WScript.echo "   SqlProgramDir:  " & strSqlProgramDir
    WScript.echo "   SQLPath:        " & strSQLPath
    WScript.echo "   SQLDataRoot:    " & strSQLDataRoot
    WScript.echo "   SQLBinRoot:     " & strSQLBinRoot
    WScript.echo "   Full Text Path: " & strFullTextDefaultPath
    WScript.echo  " "
    WScript.echo  "*** WARNING **** This command line is not meant to be used under normal conditions."
    WScript.echo  " "
    WScript.echo  "Un-install string if exists = " & strRetValNew07
    WScript.echo " "
    WScript.echo "####################################################################################"
    WScript.echo  " "
Else
' Gather additional information about the SQL Server engine installations
    WScript.echo  " "
    WScript.echo "####################################################################################"
    WScript.echo "SQL Server Instance ID: " & strResultInstanceId
    WScript.echo "SQL Server Instance Location Details" & strResultInstanceId & " Binary and Data Paths"
    WScript.echo "=============================================================="
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "Edition", strSqlEdition
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "SqlProgramDir", strSqlProgramDir
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "SQLPath", strSQLPath
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "SQLDataRoot", strSQLDataRoot
   	objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "SQLBinRoot", strSQLBinRoot
    objReg.GetStringValue HKLM, strInstallSource7 & "\" & strResultInstanceId & "\Setup", "FullTextDefaultPath", strFullTextDefaultPath
    WScript.echo " SQL Server Edition: " & strSqlEdition
    WScript.echo "   SqlProgramDir:  " & strSqlProgramDir
    WScript.echo "   SQLPath:        " & strSQLPath
    WScript.echo "   SQLDataRoot:    " & strSQLDataRoot
    WScript.echo "   SQLBinRoot:     " & strSQLBinRoot
    WScript.echo "   Full Text Path: " & strFullTextDefaultPath
    WScript.echo  " "
    WScript.echo  "*** WARNING **** This command line is not meant to be used under normal conditions."
    WScript.echo  " "
    WScript.echo  "Un-install string if exists = " & strRetValNew07
    WScript.echo " "
    WScript.echo "####################################################################################"
    WScript.echo  " "
    End If
     End If
NEXT
Set fso = Nothing
'' SIG '' Begin signature block
'' SIG '' MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' TJ6vpeoAvjjk7p4+U8N+FZ1ZdiUJWxFjemkMbJJRDYWg
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
'' SIG '' AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCA0SxuPisaMLc/p
'' SIG '' 6P4mit/XehjKgiVAyR90/CtYbgLVyDBEBgorBgEEAYI3
'' SIG '' AgEMMTYwNKAUgBIATQBpAGMAcgBvAHMAbwBmAHShHIAa
'' SIG '' aHR0cHM6Ly93d3cubWljcm9zb2Z0LmNvbSAwDQYJKoZI
'' SIG '' hvcNAQEBBQAEggEAEdZSAFNLZgu3UFw5lIzW/VmFpKV6
'' SIG '' DfjyRvp3G40lZEkwOkThxrDmbod80kPFF2gQTlSQt9Kl
'' SIG '' 3lCPZ9qzht18WPmJ9lc6HHdHfr0F1DfXMiA8O2/+1MSb
'' SIG '' TftRWIVwSWr4OVWkp3OX7c1gBLCh9rd9p5T/mUsee8qr
'' SIG '' i+oTXNw7UNhlcRcUYI0tEwdb2Odgj0bXp8FFSdwoenhl
'' SIG '' AyPqq9pBfqSuUPFQ2YWusx4FbbVkxPZB64MzY6e1Iv40
'' SIG '' hTax4XFjnMtwmL2xkntJyvVBuz9aC+FpnZOtgjfGsp/e
'' SIG '' dAC+Svpg8P7iDIQhYtE3/sg/THaweoHK/JslSZU9auxR
'' SIG '' WwO+xqGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCCFuUG
'' SIG '' CSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUD
'' SIG '' BAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIB
'' SIG '' OAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUA
'' SIG '' BCAcOqtYJn40z+EElxFdSeqMH9nHpYaBgs36Plkw/6F7
'' SIG '' lwIGYhZtNsXrGBMyMDIyMDMyODE2NTUzMC43OTRaMASA
'' SIG '' AgH0oIHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UE
'' SIG '' CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
'' SIG '' MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUw
'' SIG '' IwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRp
'' SIG '' b25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozRTdB
'' SIG '' LUUzNTktQTI1RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
'' SIG '' bWUtU3RhbXAgU2VydmljZaCCEVQwggcMMIIE9KADAgEC
'' SIG '' AhMzAAABoOm7jLsOotF6AAEAAAGgMA0GCSqGSIb3DQEB
'' SIG '' CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
'' SIG '' aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
'' SIG '' ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
'' SIG '' HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4X
'' SIG '' DTIxMTIwMjE5MDUyM1oXDTIzMDIyODE5MDUyM1owgcox
'' SIG '' CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
'' SIG '' MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
'' SIG '' b3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jv
'' SIG '' c29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsT
'' SIG '' HVRoYWxlcyBUU1MgRVNOOjNFN0EtRTM1OS1BMjVEMSUw
'' SIG '' IwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
'' SIG '' aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
'' SIG '' AgEAv9riDmhxnQDo9mL4YSOgvIhQKu8K5f+VqT449HxB
'' SIG '' wouiL8fyNNibLPx1YZHxkzBrbUeY0YYayV8nVg5zps0V
'' SIG '' NweBuduU+6cJBTRQV7pjP/fJeZNFNl4mmfm7pVx3ueMe
'' SIG '' ro/+r+VRhb/tB4dXcoxlEz2kRMEu8ffE3ubRRxIpj2vg
'' SIG '' LBtpjPp/TcH0EY3dS4hAm3AmRZIMG5YkP2pIjK9bWZo5
'' SIG '' A28bbtmkHF4xHw52vCR/sGZn3btF+5OnSeVhkRcM2Yiz
'' SIG '' iVuEIQBKXodnNZpm7QHwZ4UjzfhOclC36X009sF/EWx+
'' SIG '' l3wIOrGcfPPesatPoFA/Zh8vGbaXRHhNWQNB4Acg1tqy
'' SIG '' Qm0wCQIbe9Qe0c9qT0JoOUd/r0gq4vAXnEgfmfJsGC97
'' SIG '' jkt0em3lASe4hOKz0vVgtcNX2UeyuOGUpntnSPjvf54Y
'' SIG '' G9zC2IJus8dx4bS6BoRlTy/lqA5DJ7fdyBqDupDQQjNl
'' SIG '' /grNtqpdrT45CEcscMRekbF4f0B54SiYAc3zvnvOCN02
'' SIG '' GyNItvcwEy+shzr+bBLNc2jTIoduyMH1oOEO/uNC+3uv
'' SIG '' Lgusg/BFBKWg9rNk+fTYUmrk8whJwKeWK0rHHPTEFSIu
'' SIG '' 4PuRgHQvKQr/tIkWu0CL2pVPvZVoJMgAVP54hR1j48hq
'' SIG '' AeMdys6N7Vwemgt8mf3U0V6SZ2kCAwEAAaOCATYwggEy
'' SIG '' MB0GA1UdDgQWBBRyuS5Q2ClOkbiRbBQvRM8LYYzQ6DAf
'' SIG '' BgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
'' SIG '' BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jv
'' SIG '' c29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
'' SIG '' aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
'' SIG '' KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8v
'' SIG '' d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01p
'' SIG '' Y3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEw
'' SIG '' KDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoG
'' SIG '' CCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4ICAQAxfcYC
'' SIG '' q/jfrJQJpW3BKkAZaS+T3wTKnC5EusknhiYxviyl91qL
'' SIG '' +acoK4Sn7V2fdDWFlH7SGac3WLOHoUeUZWhN3mLm1pXD
'' SIG '' ZcLCpHKxkgySmsG2wxn7zuIf9S9d7IOuoT4m+u5hvegg
'' SIG '' KkVRdHOTANcIio45f+YH623TSx4LUREPMwqWyuPuupdR
'' SIG '' XdLqfZsXDhBKYYSa/FN8IcBcKCvkCf5MVqIBrXw4mquk
'' SIG '' cqBVoT/Liki1Q1fjExEx2W96djsJwVhNVutO9VwyncUZ
'' SIG '' Df6QBGdeRNSyTb/YmKNZdT/0XRfiM6TCxgwH/z5Vb01M
'' SIG '' N1ax/bmqm2K/q0cbYvmzN2m9cL/b98US3PsD6J4ksVtq
'' SIG '' evQzeFqPeiAxWSJC0fh3Fgoqh1cBV54JAlH3THt8Zrzi
'' SIG '' F2EZEytD+sDy3wvjrO6HlUXjI9kwNUDDJIGfq4TztO4l
'' SIG '' uzee8wAbzIhyUHR0THitxQYEeH2hL041AHSkUJChVfNr
'' SIG '' hO8NFDJ7HiX1+xCw2PU+GlsdqsBKmpvZexh1+ANmZtJ5
'' SIG '' 9aGmv2MXMye4CFREUhkjli8BDMXBagRj5vUEkO6IDAZ+
'' SIG '' Vh8JHU05JmpwW/2dnA6cQcXdbzo8iJuAThZS4weKYrwp
'' SIG '' TtmZLFih+6gWJaGGtO1NTtwvI7W8xlHR8iwmlRgVfA3w
'' SIG '' +YfHjp8o62gRuzzTWTCCB3EwggVZoAMCAQICEzMAAAAV
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
'' SIG '' VGhhbGVzIFRTUyBFU046M0U3QS1FMzU5LUEyNUQxJTAj
'' SIG '' BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZp
'' SIG '' Y2WiIwoBATAHBgUrDgMCGgMVABMGuI1o2nGzmFPvvecn
'' SIG '' Se4UgouYoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
'' SIG '' BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
'' SIG '' bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
'' SIG '' bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
'' SIG '' UENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDl68N9MCIY
'' SIG '' DzIwMjIwMzI4MTMxNzQ5WhgPMjAyMjAzMjkxMzE3NDla
'' SIG '' MHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOXrw30CAQAw
'' SIG '' BwIBAAICB5gwBwIBAAICEcYwCgIFAOXtFP0CAQAwNgYK
'' SIG '' KwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
'' SIG '' AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUF
'' SIG '' AAOBgQBm88k+5S0pGfWlxZINvK1yRJM0sgeKw2hptlM5
'' SIG '' cLEtZ1ZCchPBWVbzQdtT0NDOrm7V+SpATArWR0s02fql
'' SIG '' voLT9XSBNTjMXlOuqF11UU6Okb7r7cdWgAGj6HQybLzq
'' SIG '' wwCC0lJuR/q+wWpCPPppIy6qXpll7zSbKvPehLMpV2nz
'' SIG '' XTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMw
'' SIG '' EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
'' SIG '' b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
'' SIG '' b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
'' SIG '' IFBDQSAyMDEwAhMzAAABoOm7jLsOotF6AAEAAAGgMA0G
'' SIG '' CWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYL
'' SIG '' KoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIDasneVo
'' SIG '' NqKyJx4HJHZ17T+bnzdp+wbjq4pbuma6WnCXMIH6Bgsq
'' SIG '' hkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgL0eKPGhlBCIS
'' SIG '' Ld0RL7MdPrL5zOlomoGuUj2iuIOvtNMwgZgwgYCkfjB8
'' SIG '' MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
'' SIG '' bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
'' SIG '' cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
'' SIG '' b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAaDp
'' SIG '' u4y7DqLRegABAAABoDAiBCDCtSCuPCqs1Kk0l8J8nxSj
'' SIG '' 2nLldk5IGk2KETKKTnUrLTANBgkqhkiG9w0BAQsFAASC
'' SIG '' AgB8VgQLaTlC18g/gIW7TglY7Jipt71MxE4LK7Rznu8+
'' SIG '' TV7JurL3z3vqGT4QWLLuSIe3EF4KZ9SpS6RhLfwwnBxK
'' SIG '' RrIEVR6Q4DMUnEo/zoG28KoQMDwvLPwYxFOJtcEEqXnm
'' SIG '' Sg70VXuAAtqLFSx8TrF4AAuP9HI3tz6erfSNaOHqRm9L
'' SIG '' nw5NfLFBW3GgJdbHufX9PoJxjSmYbRUt9DXri+kBzP5w
'' SIG '' Xr5AHJQqkc3xsp1prM3LqaNBiym7KKCMCdihLabx0aQA
'' SIG '' FXvFgcftz7v9znOdYW8dv0Rde1WyoUfH9xYMsI2pywub
'' SIG '' taX0f32ghbaZapE9rEGU3jQPudGtjbad4OhiSgWKLjmp
'' SIG '' 0RZCOQ0VUzNFL9ivg1WovWzWqmoR5DzbOLT9U50kgO0o
'' SIG '' f6GDR4zVgc16Gw0skviTlm7UC2DJ73fbl0OYnKtEYVco
'' SIG '' gTYAuOwNxeA/mn9HfXOjuQzzU98Wwh0OHScBGIHg+erU
'' SIG '' ciadNEKFGo4W1v3/N4KXI1HHgMmEs1nG32zE4FNDhmTK
'' SIG '' RYuYovKFkLGVs5+1OGvkGa9kOrPMIZfO7ApfndTi7IZj
'' SIG '' SO1yoy3dLjzqY4sw0MPPFim1IzBV7W2xeRffRcYjZ6QR
'' SIG '' PCdVOEXyLtnQGmPuGvOEPsogGiwcnClnxJfqrVhaHH5o
'' SIG '' XxqiLWIw+NXCTvE61uUUX2oFXg==
'' SIG '' End signature block
