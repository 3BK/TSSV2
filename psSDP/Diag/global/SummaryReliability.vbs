' THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
' OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR
' FITNESS FOR A PARTICULAR PURPOSE.
'
' Copyright (c) Microsoft Corporation. All rights reserved
'
' This script is not supported under any Microsoft standard support program or service.
' The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
' implied warranties including, without limitation, any implied warranties of merchantability
' or of fitness for a particular purpose. The entire risk arising out of the use or performance
' of the scripts and documentation remains with you. In no event shall Microsoft, its authors,
' or anyone else involved in the creation, production, or delivery of the script be liable for
' any damages whatsoever (including, without limitation, damages for loss of business profits,
' business interruption, loss of business information, or other pecuniary loss) arising out of
' the use of or inability to use the script or documentation, even if Microsoft has been advised
' of the possibility of such damages.

' last modified: #we# 2022.07.05

Option Explicit

' Globally and within each function the script checks blnErrorHandling to see if On Error Resume Next should be set
' Setting On Error Resume Next globally does not enable it within the scope of a function.

Const wbemFlagReturnImmediately = 16
Const wbemFlagForwardOnly = 32

Dim blnErrorHandling
Dim blnTextOutput
Dim intLocation
Dim blnDebug
Dim blnSDP

Const TO_SCREEN = 1
Const TO_FILE = 2
Const NO_TIME = 4
Const OUTPUT = False
Const TASK = True

blnErrorHandling = True
blnTextOutput = True
intLocation = TO_SCREEN + TO_FILE
blnDebug = True
blnSDP = True

If blnErrorHandling Then On Error Resume Next

' --------------------------------------------------------------------------------------------------------

Const SAMPLE_OUTPUT_MACHINE = "" ' for internal testing only
Const SAMPLE_OUTPUT_FOLDER = "" ' for internal testing only
Const NUM_LAST_REBOOTS = 5
Const ALLSERVICES = TRUE
Const AUTONOTSTARTED = FALSE
Const adUseClient = 3
Const adSingle = 4
Const adDouble = 5
Const adVarChar = 200
Const adFldMayBeNull = &H00000040
Const SCRIPT_NAME = "REL.VBS"
Const SCRIPT_VERSION = "2012.03.23"
Const SCRIPT_AUTHOR = "Craig Landis clandis@microsoft.com"
Const SCRIPT_DESCRIPTION = "This script displays information specific to troubleshooting Windows performance issues and related components."
Const FILENAME_STRING_LENGTH = 16
Const VERSION_STRING_LENGTH = 15
Const DATE_STRING_LENGTH = 10
Const SUMMARY_STRING_LENGTH = 33
Const COUNTER_STRING_LENGTH = 39
Const PADLEFT = 1
Const PADRIGHT = 0
Const PADZERO = 2
Const GB = 1073741824
Const MB = 1048576
Const KB = 1024
Const ForReading = 1
Const ForWriting = 2
Const ForAppending = 8
Const HKCR = &H80000000
Const HKCU = &H80000001
Const HKLM = &H80000002
Const HKU  = &H80000003
Const REG_SZ        = 1
Const REG_EXPAND_SZ = 2
Const REG_BINARY    = 3
Const REG_DWORD     = 4
Const REG_MULTI_SZ  = 7
Const MINUTES_IN_DAY = 1440
Const MINUTES_IN_HOUR = 60
Const HEADING_WIDTH = 147

' --------------------------------------------------------------------------------------------------------

Dim blnSetupSDPManifest
Dim objDNSServer
Dim strOutputTempLog
Dim strOutputLog
Dim strHostName
Dim strBootINIPath
Dim dtmInstallDate
Dim strError
Dim arrSystemStartupOptions
Dim strDomain
Dim strDomainRole
Dim blnVirtualized
Dim colVMToolsService
Dim objVMToolsService
Dim colVMToolsdFile
Dim objVMToolsdFile
Dim strVirtualization
Dim strTime
Dim blnTask
Dim intType
Dim rsTasks
Dim dtmFunctionStart
Dim dtmFunctionEnd
Dim strFunctionName
Dim strFunction
Dim strErrText
Dim intOutputLocation
Dim blnFirstRun
Dim objOutputLog
Dim blnAllServices
Dim strOSShortName
Dim intValueData
Dim strReturnValue
Dim strType
Dim strKey
Dim	strOutputTxt
Dim	strOutputPath
Dim arrBytes
Dim arrComponentAndFileName
Dim arrFiles
Dim arrFileVersion
Dim arrFileVersionNumberParts
Dim arrOutput()
Dim arrPageFiles()
Dim arrPnPAllocatedResources()
Dim arrTypes
Dim arrValueNames
Dim arrValues
Dim blnLocation
Dim blnMultipleColumns
Dim blnExcelOutput
Dim blnReturnVersionNumber
Dim colBIOS
Dim colCIMDataFiles
Dim colComputerSystem
Dim colDriverFiles
Dim colFiles
Dim colLogicalMemoryConfiguration
Dim colCounters
Dim colNetworkAdapterDrivers
Dim colNetworkAdapters
Dim colOperatingSystems
Dim colPageFileSetting
Dim colPageFileUsage
Dim colProcessor
Dim colRegistry
Dim colSystemDrivers
Dim colTimeZone
Dim colWindowsProductActivation
Dim colWMIRepository
Dim colWMISetting
Dim dtmDate
Dim dtmEndTime
Dim dtmLastBootUpTime
Dim dtmStartTime
Dim dtmString
Dim dtmTime
Dim errReturn
Dim hDefKey
Dim i
Dim intAvailablePhysicalMemory
Dim intAvailableVirtualMemory
Dim intBytes
Dim intDays
Dim intHours
Dim intMaxProcessMemorySize
Dim intMemoryAvailableBytes
Dim intMemoryCommitLimit
Dim intMemoryCommittedBytes
Dim intMemoryFreeSystemPageTableEntries
Dim intMemoryPercentCommittedBytesInUse
Dim intMemoryPoolNonPagedBytes
Dim intMemoryPoolPagedBytes
Dim intMemorySystemCacheResidentBytes
Dim intMemorySystemResidentBytes
Dim intMinutes
Dim intMinutesUptime
Dim intNumberOfCores
Dim intNumberOfLogicalProcessors
Dim intNumberOfProcessors
Dim intPageFileSpace
Dim intRegistryCurrentSize
Dim intRegistryMaximumSize
Dim intRegistryProposedSize
Dim intSeconds
Dim intSpaces
Dim intTotalPhysicalMemory
Dim intTotalVirtualMemory
Dim intWMIRepositorySize
Dim objBIOS
Dim objBootINI
Dim objCIMDataFile
Dim objComputerSystem
Dim objCounter
Dim objDriver
Dim objDriverFile
Dim objExcel
Dim objFile
Dim objFSO
Dim objIPAddress
Dim objIPSubnet
Dim objNetwork
Dim objNetworkAdapter
Dim objNetworkAdapterDriver
Dim objOperatingSystem
Dim objPageFileSetting
Dim objPageFileUsage
Dim objProcessor
Dim objReg
Dim objRegistry
Dim objRegValues
Dim objShell
Dim objSWbemLocator
Dim objSystemCounter
Dim objOutputTxt
Dim objTimeZone
Dim objWMIRepository
Dim objWMIService
Dim objWMISetting
Dim objWorkbook
Dim objWorksheet
Dim strAMPM
Dim strAvailablePhysicalMemory
Dim strBIOSVersion
Dim strBuildNumber
Dim strBytes
Dim strCommand1
Dim strCommand2
Dim strComponentName
Dim strComputer
Dim strComputerName
Dim strDatabaseDirectory
Dim strFileName
Dim strFiles
Dim strFileVersionBuildNumber
Dim strFileVersionNumber
Dim strFormat
Dim strHeading
Dim strIPAddresses
Dim strKeyPath
Dim strLangID
Dim strLocale
Dim strOSManufacturer
Dim strOSName
Dim strOSVersion
Dim strOtherOSDescription
Dim strPageFiles
Dim strPassword
Dim strPath
Dim strProcessor
Dim strRegValueName
Dim strServicePackMajorVersion
Dim strServicePack
Dim strServicingBranch
Dim strSMBIOSVersion
Dim strChaff
Dim strSystemDrive
Dim strSystemManufacturer
Dim strSystemModel
Dim strSystemName
Dim strBitness
Dim strTimeZone
Dim strUser
Dim strUserName
Dim strValue
Dim strValueName
Dim strWMIFileName
Dim strWMIPath
Dim strWMIRepositoryFile
Dim uByte
Dim uValue
Dim varname

' --------------------------------------------------------------------------------------------------------
' ---- #we# 2022.07.05 bail out to avoid indefinitely hang : https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ms692877(v=vs.85)
On Error Resume Next
dim rsTest
Set rsTest = CreateObject("ADODB.Recordset")
rsTest.Fields.Append "Test", adVarChar, 255, adFldMayBeNull
rsTest.Open
If Err Then
      Wscript.Echo "Error: " & Err.Number & " " & Err.Description
      Wscript.Echo "This error may be due to security hardening, for example if the C:\Program Files\Common Files\System\msadc folder was removed or its DLLs unregistered"
      Wscript.Quit 1
End If
On Error GoTo 0
' ---- #we# 2022.07.05

strComputer = "."
dtmStartTime = Timer
dtmDate = Now
dtmTime = Time
blnFirstRun = True
Redim Preserve arrOutput(1)

strFiles = 	"BASE;c:\\windows\\system32\\ADVAPI32.DLL," &_
			"BASE;c:\\windows\\system32\\CSRSS.EXE," &_
			"BASE;c:\\windows\\system32\\HAL.DLL," &_
			"BASE;c:\\windows\\system32\\NTDLL.DLL," &_
			"BASE;c:\\windows\\system32\\NTOSKRNL.EXE," &_
			"BASE;c:\\windows\\system32\\SVCHOST.EXE," &_
			"BASE;c:\\windows\\system32\\WIN32K.SYS," &_
			"BASE;c:\\windows\\system32\\WINSRV.DLL," &_
			"EVENT LOG;c:\\windows\\system32\\EVENTLOG.DLL," &_
			"MSI;c:\\windows\\system32\\MSI.DLL," &_
			"NETWORK;c:\\windows\\system32\\drivers\\AFD.SYS," &_
			"NETWORK;c:\\windows\\system32\\BROWSER.DLL," &_
			"NETWORK;c:\\windows\\system32\\drivers\\DFS.SYS," &_
			"NETWORK;c:\\windows\\system32\\drivers\\DFSC.SYS," &_
			"NETWORK;c:\\windows\\system32\\FDWNET.DLL," &_
			"NETWORK;c:\\windows\\system32\\drivers\\FWPKCLNT.SYS," &_
			"NETWORK;c:\\windows\\system32\\drivers\\HTTP.SYS," &_
			"NETWORK;c:\\windows\\system32\\MPR.DLL," &_
			"NETWORK;c:\\windows\\system32\\drivers\\MRXSMB.SYS," &_
			"NETWORK;c:\\windows\\system32\\drivers\\MRXSMB10.SYS," &_
			"NETWORK;c:\\windows\\system32\\drivers\\MRXSMB20.SYS," &_
			"NETWORK;c:\\windows\\system32\\drivers\\MUP.SYS," &_
			"NETWORK;c:\\windows\\system32\\drivers\\NDIS.SYS," &_
			"NETWORK;c:\\windows\\system32\\drivers\\NETBIOS.SYS," &_
			"NETWORK;c:\\windows\\system32\\drivers\\RDBSS.SYS," &_
			"NETWORK;c:\\windows\\system32\\drivers\\SRV.SYS," &_
			"NETWORK;c:\\windows\\system32\\drivers\\SRV2.SYS," &_
			"NETWORK;c:\\windows\\system32\\drivers\\SRVNET.SYS," &_
			"NETWORK;c:\\windows\\system32\\drivers\\TCPIP.SYS," &_
			"NETWORK;c:\\windows\\system32\\WS2_32.DLL," &_
			"NETWORK;c:\\windows\\system32\\WSOCK32.DLL," &_
			"PERFORMANCE MONITOR;c:\\windows\\system32\\PDH.DLL," &_
			"PERFORMANCE MONITOR;c:\\windows\\system32\\wbem\WMIPERFCLASS.DLL," &_
			"PRINT;c:\\windows\\system32\\LOCALSPL.DLL," &_
			"PRINT;c:\\windows\\system32\\WINPRINT.DLL," &_
			"RDS;c:\\windows\\system32\\drivers\\RDPWD.SYS," &_
			"RDS;c:\\windows\\system32\\drivers\\TERMDD.SYS," &_
			"REGISTRY;c:\\windows\\system32\\REG.EXE," &_
			"REGISTRY;c:\\windows\\system32\\REGSVC.DLL," &_
			"RPC;c:\\windows\\system32\\RPCRT4.DLL," &_
			"SHELL;c:\\windows\\system32\\SHELL32.DLL," &_
			"STORAGE;c:\\windows\\system32\\drivers\\CLASSPNP.SYS," &_
			"STORAGE;c:\\windows\\system32\\drivers\\DISK.SYS," &_
			"STORAGE;c:\\windows\\system32\\drivers\\DISKDUMP.SYS," &_
			"STORAGE;c:\\windows\\system32\\drivers\\NTFS.SYS," &_
			"STORAGE;c:\\windows\\system32\\drivers\\PARTMGR.SYS," &_
			"STORAGE;c:\\windows\\system32\\drivers\\STORPORT.SYS," &_
			"STORAGE;c:\\windows\\system32\\drivers\\VOLMGR.SYS," &_
			"STORAGE;c:\\windows\\system32\\drivers\\VOLMGRX.SYS," &_
			"STORAGE;c:\\windows\\system32\\drivers\\VOLSNAP.SYS," &_
			"STORAGE;c:\\windows\\system32\\VSSADMIN.EXE," &_
			"STORAGE;c:\\windows\\system32\\VSSAPI.DLL," &_
			"STORAGE;c:\\windows\\system32\\VSSVC.EXE," &_
			"WINRM;c:\\windows\\system32\\WSMSVC.DLL," &_
			"WMI;c:\\windows\\system32\\wbem\\CIMWIN32.DLL," &_
			"WMI;c:\\windows\\system32\\wbem\\REPDRVFS.DLL," &_
			"WMI;c:\\windows\\system32\\wbem\\WMIPERFCLASS.DLL"

arrFiles = Split(strFiles, ",")

Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objShell = CreateObject("Wscript.Shell")
Set objNetwork = Wscript.CreateObject("Wscript.Network")

strComputerName = objNetwork.ComputerName

Set objReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\default:StdRegProv")

' This needs to be earlier than the GetArgs() function so the debug log is written to the right location.
If WScript.Arguments.Named.Exists("SDP") Then blnSDP = True

If WScript.Arguments.Named.Exists("SetupSDPManifest") Then

	blnSetupSDPManifest = True

Else

	blnSetupSDPManifest = False

End if

Print SCRIPT_NAME & " " & SCRIPT_VERSION & " " & SCRIPT_AUTHOR, OUTPUT, intLocation
Print "blnErrorHandling = " & blnErrorHandling, OUTPUT, intLocation
Print "blnSDP = " & blnSDP, OUTPUT, intLocation
Print "blnSetupSDPManifest = " & blnSetupSDPManifest, OUTPUT, intLocation

Main()

If Not blnSDP Then

	If Ping(SAMPLE_OUTPUT_MACHINE) Then

		Wscript.Echo "Copying " & strOutputTxt & " to " & SAMPLE_OUTPUT_FOLDER
		objFSO.CopyFile strOutputTxt, SAMPLE_OUTPUT_FOLDER

		If Err Then
			Wscript.Echo "ERROR: " & Err.Number & " " & Err.Description
		End If

		Wscript.Echo "Copying " & strOutputTempLog & " to " & SAMPLE_OUTPUT_FOLDER
		objFSO.CopyFile strOutputTempLog, SAMPLE_OUTPUT_FOLDER & strSystemName & "__SUMMARY_" & strOSShortName & "_" & strServicePack & "_" & strBitness & ".log"

		If Err Then
			Wscript.Echo "ERROR: " & Err.Number & " " & Err.Description
		End If

	End If

End If

If blnDebug Then

	rsTasks.Sort = "Duration DESC"
	rsTasks.MoveFirst

	Print "", OUTPUT, intLocation + NO_TIME
	Print Pad("Time", 5, PADLEFT) & "  Operation" & vbCrLf, OUTPUT, intLocation + NO_TIME

	Do Until rsTasks.EOF
		Print Pad(FormatNumber(rsTasks.Fields.Item("Duration"), 1), 5, PADLEFT) & "  " & rsTasks.Fields.Item("Name"), OUTPUT, intLocation + NO_TIME
		rsTasks.MoveNext
	Loop

End If

Print vbCrLf & Pad(intSeconds, 5, PADLEFT) & "  Total" & vbCrLf, OUTPUT, intLocation + NO_TIME

Function Main()

	If blnErrorHandling Then On Error Resume Next

	GetScriptEngine()
	GetArgs()
	GetSummary()
	GetImportantDrivers()
	GetReboots()
	GetServices(AUTONOTSTARTED)
	GetPerfData()
	GetBootInfo()
	GetDrives()
	GetNICs
	GetRunningDrivers()
	GetRunningProcesses()
	GetPrograms()
	GetServices(ALLSERVICES)
	GetRegKeys()
	GetFileSummary()

	WriteOutput()

End Function

Function GetRegKeys()

	If blnErrorHandling Then On Error Resume Next

	Print "GetRegKeys()", TASK, intLocation

	GetRegKey("HKLM\SYSTEM\CurrentControlSet\Control")
	GetRegKey("HKLM\SYSTEM\CurrentControlSet\Control\CrashControl")
	If (not blnSetupSDPManifest) Then
		GetRegKey("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug")
		GetRegKey("HKLM\SOFTWARE\WoW6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug")
	End If
	GetRegKey("HKLM\SYSTEM\CurrentControlSet\Control\FileSystem")
	GetRegKey("HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management")
	If (not blnSetupSDPManifest) Then
		GetRegKey("HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive")
		GetRegKey("HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System")
		' Need to read subkeys from this key
		' GetRegKey("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
		GetRegKey("HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")
		GetRegKey("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")
		GetRegKey("HKLM\Software\Microsoft\ASP.NET\2.0.50727.0\Parameters")
		GetRegKey("HKLM\SOFTWARE\Microsoft\OLE")
		GetRegKey("HKLM\SOFTWARE\Microsoft\Rpc")
		GetRegKey("HKLM\SOFTWARE\Microsoft\Terminal Server Gateway")
		GetRegKey("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks")
		GetRegKey("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability")
		GetRegKey("HKLM\SOFTWARE\Microsoft\WBEM\CIMOM")
		GetRegKey("HKLM\SYSTEM\CurrentControlSet\Services\Http\Parameters")
		GetRegKey("HKLM\SYSTEM\CurrentControlSet\Services\InetInfo\Parameters")
		GetRegKey("HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters")
		GetRegKey("HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters")
		GetRegKey("HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters")
		GetRegKey("HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")
	End If
	Print "GetRegKeys()", TASK, intLocation

End Function

Function GetScriptEngine()

	If blnErrorHandling Then On Error Resume Next

	If InStr(1, UCase(Wscript.FullName), "CSCRIPT.EXE", vbTextCompare) = 0 Then
		Print "This script must be run with CSCRIPT.EXE (not WSCRIPT.EXE)." & vbCRLF & vbCRLF &_
                   "You can either:" & vbCRLF & vbCRLF & _
                   "1. Set CSCRIPT as the default:  " & Chr(34) & "cscript.exe /h:cscript" & Chr(34) & vbCRLF & vbCrLf & _
                   "2. Run the script with CSCRIPT: " & Chr(34) & "cscript.exe " & UCase(Wscript.ScriptName) & Chr(34), OUTPUT, TO_SCREEN

		Wscript.Quit(-1)
'	Else
'		Print "blnErrorHandling = " & blnErrorHandling, False, intLocation
	End If

End Function

Function GetPrograms()

	If blnErrorHandling Then On Error Resume Next

	Print "GetPrograms()", TASK, intLocation

	' Right now this just parses the Uninstall keys which is very close to what Add/Remove Programs shows.
	' To get an exact match for Add/Remove programs involves several more steps beyond parsing the Uninstall keys
	' This is a good overview of what's involved in getting an exact match:
	' http://forum.sysinternals.com/finding-all-installed-programs-from-the-registry_topic21312.html

	Dim strKeyPath
	Dim arrSubKeys
	Dim strSubKey
	Dim strValueType
	Dim strValueData
	Dim strSubKeyPath
	Dim rsPrograms
	Dim strDisplayName
	Dim strDisplayVersion
	Dim strInstallDate
	Dim strPublisher
	Dim strInstallLocation
	Dim strInstallSource
	Dim strProductCode
	Dim strReleaseType
	Dim blnReleaseType
	Dim strUninstallString
	Dim blnUninstallString
	Dim strSystemComponent

	hDefKey = HKLM

	Set rsPrograms = CreateObject("ADODB.Recordset")

	rsPrograms.Fields.Append "DisplayName", adVarChar, 255, adFldMayBeNull
	rsPrograms.Fields.Append "DisplayVersion", adVarChar, 255, adFldMayBeNull
	rsPrograms.Fields.Append "Publisher", adVarChar, 255, adFldMayBeNull
	rsPrograms.Fields.Append "ProductCode", adVarChar, 255, adFldMayBeNull
	'InstallDate is useful but you can have identical software versions installed on different dates whichs throws off the compare if you are comparing software between two machines

	rsPrograms.Open

	Dim arrKeyPaths()
	Dim j
	ReDim Preserve arrKeyPaths(0)
	arrKeyPaths(0) = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
	If strBitness = "x64" Then
		ReDim Preserve arrKeyPaths(1)
		arrKeyPaths(1) = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
	End If

	For j = 0 to UBound(arrKeyPaths)

	objReg.EnumKey hDefKey, arrKeyPaths(j), arrSubKeys

	Dim objRegEx
	Set objRegEx = New RegExp
	objRegEx.Global = True
	objRegEx.IgnoreCase = True
	objRegEx.Pattern = "kb\d{6}"

	For Each strSubKey In arrSubKeys
		If Not objRegEx.Test(strSubKey) Then
			'Print "Match: " & strSubKey, OUTPUT, intLocation
			strSubKeyPath = arrKeyPaths(j) & "\" & strSubKey
			'AddOutput strSubKeyPath
			objReg.EnumValues hDefKey, strSubKeyPath, arrValueNames, arrTypes
	'		GetVarInfo arrValueNames
	'		Wscript.Echo "LBound(arrValueNames) = " & LBound(arrValueNames)
	'		Wscript.Echo "UBound(arrValueNames) = " & UBound(arrValueNames)
			If IsArray(arrValueNames) Then
				For i = 0 To UBound(arrValueNames)
					strValueName = arrValueNames(i)

					Select Case arrTypes(i)

						Case REG_SZ
							strValueType = "REG_SZ"
							objReg.GetStringValue hDefKey, strSubKeyPath, strValueName, strValueData
							'GetVarInfo strValueData
							'AddOutput strValueData
							'Wscript.Quit
						Case REG_EXPAND_SZ
							strValueType = "REG_EXPAND_SZ"
							objReg.GetExpandedStringValue hDefKey, strSubKeyPath, strValueName, strValueData
						Case REG_BINARY
							strValueType = "REG_BINARY"
							objReg.GetBinaryValue hDefKey, strSubKeyPath, strValueName, arrBytes
							strValueData = Null
							For Each uByte in arrBytes
								'strValueData = strValueData & Hex(uByte) & " "
								If uByte < &H10 Then
									strValueData = strValueData & "0" & Hex(uByte)
								Else
									strValueData = strValueData & Hex(uByte)
								End If
							Next
						Case REG_DWORD
							strValueType = "REG_DWORD"
							objReg.GetDWORDValue hDefKey, strSubKeyPath, strValueName, strValueData
							'strValueData = 	"0x" & Pad(Hex(intValueData), 8, PADZERO) & " (" & intValueData & ")"
						Case REG_MULTI_SZ
							strValueType = "REG_MULTI_SZ"
							strValueData = Null
							objReg.GetMultiStringValue hDefKey, strSubKeyPath, strValueName, arrValues
							If IsArray(arrValues) Then
								For Each strValue in arrValues
									If IsNull(strValueData) Then
										strValueData = strValue
									Else
										strValueData = strValueData & "\0" & strValue
									End If
								Next
							End If


						End Select

					strValueData = Trim(strValueData)

					Select Case UCase(strValueName)

						Case "SYSTEMCOMPONENT"
							If strValueData = "1" Then
								Exit For
							End If
						Case "HELPLINK"
							If InStr(LCase(strValueData), "support.microsoft.com") Then
								Exit For
							End If
						Case "PARENTKEYNAME"
							Exit For
						Case "RELEASETYPE"
							Exit For
						Case "DISPLAYNAME"
							strDisplayName = strValueData
						Case "DISPLAYVERSION"
							If InStr(strValueData, " ") Then
								Dim arrVersion
								arrVersion = Split(strValueData, " ")
								strDisplayVersion = arrVersion(1)
							Else
								strDisplayVersion = strValueData
							End If
						Case "PUBLISHER"
							strPublisher = strValueData
						Case "WINDOWSINSTALLER"
							If strValueData = "1" Then
								strProductCode = strSubKey
							End If
						Case "UNINSTALLSTRING"
							strUninstallString = strValueData
					End Select

					Next

					If Not IsNull(strUninstallString) And Not IsNull(strDisplayName) And strDisplayName <> "" Then

						'If IsNull(strDisplayVersion) Then strDisplayVersion = ""

						rsPrograms.AddNew

						rsPrograms("DisplayName").Value = strDisplayName
						rsPrograms("DisplayVersion").Value = strDisplayVersion
						rsPrograms("Publisher").Value = strPublisher
						rsPrograms("ProductCode").Value = strProductCode

						rsPrograms.Update

						strDisplayName = Null
						strDisplayVersion = Null
						strPublisher = Null
						strProductCode	= Null
						strUninstallString = Null

					End If

				End If

			End If

		Next

	Next

	Heading "INSTALLED PROGRAMS: " & rsPrograms.RecordCount
	AddOutput Pad("Name", 65, PADRIGHT) & Pad("Version", 16, PADRIGHT) & Pad("Publisher", 28, PADRIGHT) & "Windows Installer Product Code"
	AddOutput String(HEADING_WIDTH, "-")

	rsPrograms.Sort = "DisplayName ASC"
	rsPrograms.MoveFirst

	Do Until rsPrograms.EOF
		AddOutput Pad(Left(rsPrograms.Fields.Item("DisplayName"), 63), 65, PADRIGHT) & Pad(Left(rsPrograms.Fields.Item("DisplayVersion"), 14), 16, PADRIGHT) & Pad(Left(rsPrograms.Fields.Item("Publisher"), 26), 28, PADRIGHT) & rsPrograms.Fields.Item("ProductCode")
		rsPrograms.MoveNext
	Loop

	Print "GetPrograms()", TASK, intLocation

End Function

Function GetArgs()

	If blnErrorHandling Then On Error Resume Next

	Print "GetArgs()", TASK, intLocation

	If WScript.Arguments.Named.Exists("S") Then
		strComputer = Wscript.Arguments.Named("S")
		strComputerName = UCase(strComputer)
	End If
	If WScript.Arguments.Named.Exists("U") And WScript.Arguments.Named.Exists("P") Then
		strUser = Wscript.Arguments.Named("U")
		strPassword = Wscript.Arguments.Named("P")
		Set objSWbemLocator = CreateObject("WbemScripting.SWbemLocator")
		Set objWMIService = objSWbemLocator.ConnectServer(strComputer, "root\cimv2", strUser, strPassword)
	Else
		Set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate, (debug)}!\\" & strComputer & "\root\cimv2")
	End If

	Print "GetArgs()", TASK, intLocation

End Function

Function GetSummary()

	If blnErrorHandling Then On Error Resume Next

	Print "GetSummary()", TASK, intLocation

	Set colPageFileUsage = objWMIService.ExecQuery("SELECT Name,AllocatedBaseSize,CurrentUsage,PeakUsage FROM Win32_PageFileUsage")
	Set colPageFileSetting = objWMIService.ExecQuery("SELECT Name,InitialSize,MaximumSize FROM Win32_PageFileSetting")
	Set colWindowsProductActivation = objWMIService.ExecQuery("SELECT RemainingGracePeriod, ActivationRequired FROM Win32_WindowsProductActivation", , wbemFlagReturnImmediately + wbemFlagForwardOnly)
	Set colProcessor = objWMIService.ExecQuery("SELECT * FROM Win32_Processor", , wbemFlagReturnImmediately + wbemFlagForwardOnly)
	Set colBIOS = objWMIService.ExecQuery("SELECT Manufacturer, Version, SMBIOSPresent, SMBIOSBIOSVersion, ReleaseDate, BIOSVersion FROM Win32_BIOS", , wbemFlagReturnImmediately + wbemFlagForwardOnly)
	Set colTimeZone = objWMIService.ExecQuery("SELECT StandardName FROM Win32_TimeZone", , wbemFlagReturnImmediately + wbemFlagForwardOnly)

	' Is Win32_LogicalMemoryConfiguration on XP/2003 only?
	Set colLogicalMemoryConfiguration = objWMIService.ExecQuery("SELECT TotalPhysicalMemory FROM Win32_LogicalMemoryConfiguration", , wbemFlagReturnImmediately + wbemFlagForwardOnly)

	Print "Query Win32_Registry", TASK, intLocation
	Set colRegistry = objWMIService.ExecQuery("SELECT CurrentSize,MaximumSize,ProposedSize FROM Win32_Registry", , wbemFlagReturnImmediately + wbemFlagForwardOnly)
	For Each objRegistry in colRegistry
		intRegistryCurrentSize = objRegistry.CurrentSize
		intRegistryMaximumSize = objRegistry.MaximumSize
		intRegistryProposedSize = objRegistry.ProposedSize
	Next
	Print "Query Win32_Registry", TASK, intLocation

	Print "Query Win32_OperatingSystem", TASK, intLocation
	Set colOperatingSystems = objWMIService.ExecQuery("Select BuildNumber,Caption,SystemDrive,Version,CSDVersion,OtherTypeDescription,ServicePackMajorVersion,LastBootUptime,InstallDate,MaxProcessMemorySize,Manufacturer,Locale,FreePhysicalMemory,TotalVirtualMemorySize,SizeStoredInPagingFiles,FreeVirtualMemory From Win32_OperatingSystem", , wbemFlagReturnImmediately + wbemFlagForwardOnly)
	For Each objOperatingSystem in colOperatingSystems

		strBuildNumber = objOperatingSystem.BuildNumber
		strOSName = RemoveChaff(objOperatingSystem.Caption)
		strOSVersion = objOperatingSystem.Version & " " & objOperatingSystem.CSDVersion & " Build " & objOperatingSystem.BuildNumber

		If IsNull(objOperatingSystem.OtherTypeDescription) Then
			strOtherOSDescription = "Not Available"
		Else
			strOtherOSDescription = objOperatingSystem.OtherTypeDescription
		End If

		strServicePackMajorVersion = objOperatingSystem.ServicePackMajorVersion

		If strServicePackMajorVersion = 0 Then
			If InStr(strOSName, "Windows 8") Then
				strOSShortName = "WIN8_CLIENT"
				strServicePack = strBuildNumber
			ElseIf InStr(strOSName, "Windows Server 8") Then
				strOSShortName = "WIN8_SERVER"
				strServicePack = strBuildNumber
			Else
				strServicePack = "RTM"
			End If
		Else
			strServicePack = "SP" & strServicePackMajorVersion
		End If

		dtmLastBootUpTime = WMIDateStringToDate2(objOperatingSystem.LastBootUpTime)
		'WMIDateStringToDate2 led to switched month/day display depending on configured regional format
		dtmInstallDate = WMIDateStringToDate3(objOperatingSystem.InstallDate)
		intMinutesUptime = DateDiff("n", dtmLastBootUpTime, Now)
		intMaxProcessMemorySize = objOperatingSystem.MaxProcessMemorySize
		strOSManufacturer = objOperatingSystem.Manufacturer
		strSystemDrive = objOperatingSystem.SystemDrive
		strLocale = ConvertLocale(objOperatingSystem.Locale)
		intAvailablePhysicalMemory = objOperatingSystem.FreePhysicalMemory
		intTotalVirtualMemory = objOperatingSystem.TotalVirtualMemorySize
		intPageFileSpace = objOperatingSystem.SizeStoredInPagingFiles
		intAvailableVirtualMemory = objOperatingSystem.FreeVirtualMemory
	Next
	Print "Query Win32_OperatingSystem", TASK, intLocation

	Print "Query Win32_WMISetting", TASK, intLocation
	Set colWMISetting = objWMIService.ExecQuery("SELECT DatabaseDirectory FROM Win32_WMISetting", , wbemFlagReturnImmediately + wbemFlagForwardOnly)
	For Each objWMISetting in colWMISetting
		strDatabaseDirectory = Replace(objWMISetting.DatabaseDirectory, "\", "\\", 1, -1, 1)
		If strBuildNumber = "3790" Or strBuildNumber = "2600" Then
			Set colWMIRepository = objWMIService.ExecQuery("Select FileSize From CIM_DataFile Where Name='" & strDatabaseDirectory & "\\FS\\OBJECTS.DATA" & "'", , wbemFlagReturnImmediately + wbemFlagForwardOnly)
		Else
			Set colWMIRepository = objWMIService.ExecQuery("Select FileSize From CIM_DataFile Where Name='" & strDatabaseDirectory & "\\OBJECTS.DATA" & "'", , wbemFlagReturnImmediately + wbemFlagForwardOnly)
		End If
		For Each objWMIRepository in colWMIRepository
			intWMIRepositorySize = objWMIRepository.FileSize
			strWMIRepositoryFile = objWMIRepository.Name
		Next
	Next
	Print "Query Win32_WMISetting", TASK, intLocation

	Print "Query Win32_ComputerSystem", TASK, intLocation
	Set colComputerSystem = objWMIService.ExecQuery("SELECT SystemStartupOptions,Domain,DomainRole,Name,NumberOfProcessors,Manufacturer,Model,SystemType,TotalPhysicalMemory,UserName,Workgroup,DaylightInEffect FROM Win32_ComputerSystem", , wbemFlagReturnImmediately + wbemFlagForwardOnly)
	For Each objComputerSystem in colComputerSystem
		strSystemName = UCase(objComputerSystem.Name)
		strSystemManufacturer = objComputerSystem.Manufacturer
		strSystemModel = objComputerSystem.Model
		strBitness = LCase(Left(objComputerSystem.SystemType, 3))
		intNumberOfProcessors = objComputerSystem.NumberOfProcessors
		arrSystemStartupOptions = objComputerSystem.SystemStartupOptions
		If IsNull(objComputerSystem.UserName) Then
			strUserName = "Not Available"
		Else
			strUserName = objComputerSystem.UserName
		End If

		Select Case objComputerSystem.DomainRole
			Case 0
				strDomainRole = "Standalone Workstation"
			Case 1
				strDomainRole = "Member Workstation"
			Case 2
				strDomainRole = "Standalone Server"
			Case 3
				strDomainRole = "Member Server"
			Case 4
				strDomainRole = "Backup Domain Controller"
			Case 5
				strDomainRole = "Primary Domain Controller"
		End Select

		If IsNull(objComputerSystem.Workgroup) Then
			strDomain = Pad("Domain",SUMMARY_STRING_LENGTH, PADRIGHT) & objComputerSystem.Domain
		Else
			strDomain = Pad("Workgroup",SUMMARY_STRING_LENGTH, PADRIGHT) & objComputerSystem.Workgroup
		End If

		intTotalPhysicalMemory = objComputerSystem.TotalPhysicalMemory
	Next
	Print "Query Win32_ComputerSystem", TASK, intLocation

	If InStr(UCase(strSystemManufacturer), "VMWARE") Then

		blnVirtualized = True

		Print "Query Win32_Service for VMTools", TASK, intLocation
		Set colVMToolsService = objWMIService.ExecQuery("Select Name,PathName,StartMode,State From Win32_Service Where Name='VMTOOLS'")
		Print "Query Win32_Service Where Name=VMTOOLS", TASK, intLocation

		If colVMToolsService.Count Then
			For Each objVMToolsService in colVMToolsService

			Print "Query CIM_DataFile for Vmtoolsd.exe", TASK, intLocation
				Set colVMToolsdFile = objWMIService.ExecQuery("Select Name,Version From CIM_DataFile Where Name='" & Replace(Replace(objVMToolsService.PathName, "\", "\\"), Chr(34), "") & "'")
				Print "Query CIM_DataFile for Vmtoolsd.exe", TASK, intLocation

				If colVMToolsdFile.Count Then
					For Each objVMToolsdFile in colVMToolsdFile
						'strVirtualization = Pad("VMWare Tools", SUMMARY_STRING_LENGTH, PADRIGHT) & "Version: " & objVMToolsdFile.Version & " VMWare Tools (VMTools) service: " & objVMToolsService.State & ", " & objVMToolsService.StartMode
						strVirtualization = "VMWare, VMWare Tools " & objVMToolsdFile.Version & ", VMWare Tools (VMTools) service: " & objVMToolsService.State & ", " & objVMToolsService.StartMode
					Next
				End If
			Next
		Else
			'strVirtualization = Pad("VMWare Tools", SUMMARY_STRING_LENGTH, PADRIGHT) & "<VMWare Tools (VMTools) service not present>"
			strVirtualization = "VMWare (VMWare Tools (VMTools) service not present)"
		End If

	ElseIf InStr(UCase(strSystemManufacturer), "MICROSOFT") Then

		blnVirtualized = True

		Dim colVMBusFile
		Dim objVMBusFile

		Print "Query CIM_DataFile for Vmbus.sys", TASK, intLocation
		Set colVMBusFile = objWMIService.ExecQuery("Select Name,Version From CIM_DataFile Where Name='" & Replace(objShell.ExpandEnvironmentStrings("%WINDIR%"), "\", "\\") & "\\System32\\Drivers\\Vmbus.sys" & "'")
		Print "Query CIM_DataFile for Vmbus.sys", TASK, intLocation

		If colVMBusFile.Count Then
			For Each objVMBusFile in colVMBusFile
				'strVirtualization = Pad("Hyper-V Integration Services", SUMMARY_STRING_LENGTH, PADRIGHT) & "Version: " & objVMBusFile.Version & " (Vmbus.sys file version)"
				strVirtualization = "Hyper-V, Integration Services " & objVMBusFile.Version & " (Vmbus.sys file version)"
			Next
		End If
	Else

		blnVirtualized = False
		strVirtualization = "No"

	End If

	i = 0

	If colPageFileSetting.Count Then
		Redim Preserve arrPageFiles(colPageFileSetting.Count)
		For Each objPageFileUsage in colPageFileUsage
			arrPageFiles(i) = objPageFileUsage.Name & " Current: " & objPageFileUsage.AllocatedBaseSize & " MB"
			'strPageFiles = strPageFiles & objPageFileUsage.Name & " Current Size: " & objPageFileUsage.AllocatedBaseSize & " MB " & vbCrLf & String(33, " ")
			i = i + 1
		Next
		i = 0
		For Each objPageFileSetting in colPageFileSetting
			arrPageFiles(i) = arrPageFiles(i) & " Initial: " & objPageFileSetting.InitialSize & " MB Maximum: " & objPageFileSetting.MaximumSize & " MB"
			'strPageFiles = strPageFiles & objPageFileSetting.Name & " Initial " & objPageFileSetting.InitialSize & " MB Maximum " & objPageFileSetting.MaximumSize & " MB" & vbCrLf & String(33, " ")
			i = i + 1
		Next
	Else
		Redim Preserve arrPageFiles(colPageFileUsage.Count)
		For Each objPageFileUsage in colPageFileUsage
			arrPageFiles(i) = objPageFileUsage.Name & " Current: " & objPageFileUsage.AllocatedBaseSize & " MB Initial: <system managed> Maximum: <system managed>"
			'strPageFiles = strPageFiles & objPageFileUsage.Name & " Current Size: " & objPageFileUsage.AllocatedBaseSize & " MB " & vbCrLf & String(33, " ")
			i = i + 1
		Next
	End If
	'strPageFiles = Trim(strPageFiles)

	For Each objTimeZone in colTimeZone
		strTimeZone = objTimeZone.StandardName
	Next

	' Is Win32_LogicalMemoryConfiguration on XP/2003 only?
	'For Each objLogicalMemoryConfiguration in colLogicalMemoryConfiguration
	'	strTotalPhysicalMemory = objComputerSystem.TotalPhysicalMemory
	'Next

	'Set colFiles = objWMIService.ExecQuery("Select Extension,FileName,FileSize,LastModified,Version From CIM_DataFile Where Name='c:\\windows\\system32\\HAL.DLL'", , wbemFlagReturnImmediately + wbemFlagForwardOnly)
	'For Each objFile in colFiles
	'	strHardwareAbstractionLayer = objFile.Version
	'Next

	For Each objProcessor in colProcessor
		If InStr(1,UCase(objProcessor.Name),"GHZ",1) Or InStr(1,UCase(objProcessor.Name),"MHZ",1) Then
			strProcessor = RemoveChaff(objProcessor.Name)
		Else
			strProcessor = RemoveChaff(objProcessor.Name) & " " & objProcessor.MaxClockSpeed & " Mhz"
		End If
		On Error Resume Next
		' Requirements for Win32_Processor.NumberOfCores and Win32_Processor.NumberOfLogicalProcessors to be available:
		' Hotfix 932370 required for 2003 (all versions) and XP 64-bit
		' SP3 or SP2+936235 required for XP 32-bit
        ' Vista and later support these properties natively with no SP or hotfixes needed.
		' If the property is missing, Err.Number will be 438 and Err.Description will be "Object doesn't support this property or method"
		intNumberOfCores = objProcessor.NumberOfCores
		If Err.Number Then
			If strBuildNumber = "3790" Then
				strProcessor = strProcessor & " " & intNumberOfProcessors & " Physical Processor(s)" & " (hyperthreading information unavailable until hotfix 932370 is installed)"
			ElseIf strBuildNumber = "2600" Then
				strProcessor = strProcessor & " " & intNumberOfProcessors & " Physical Processor(s)" & " (hyperthreading information unavailable until hotfix 936235 is installed)"
			End If
			Err.Clear
		Else
			intNumberOfLogicalProcessors = objProcessor.NumberOfLogicalProcessors
			strProcessor = strProcessor & " " & intNumberOfProcessors & " Physical Processor(s)" & " " & intNumberOfCores & " Physical Core(s) " & intNumberOfLogicalProcessors & " Logical Processor(s)"
		End If
		On Error Goto 0
'		If strBuildNumber = "7601" Then
'			strProcessor = strProcessor & " " & intNumberOfProcessors & " Physical Processor(s)" & " " & objProcessor.NumberOfCores & " Core(s) " & objProcessor.NumberOfLogicalProcessors & " Logical Processor(s)"
'		ElseIf strBuildNumber = "6002" Then
'			strProcessor = strProcessor & " " & objProcessor.NumberOfCores & " Core(s) " & objProcessor.NumberOfLogicalProcessors & " Logical Processor(s)"
'		ElseIf strBuildNumber = "3790" Then
			'strProcessor = objProcessor.Description & " " & objProcessor.Manufacturer & " ~" & objProcessor.MaxClockSpeed & " Mhz"
'			strProcessor = strProcessor
'		ElseIf strBuildNumber = "2600" Then
			'strProcessor = objProcessor.Description & " " & objProcessor.Manufacturer & " ~" & objProcessor.MaxClockSpeed & " Mhz"
'			strProcessor = strProcessor
'		End If
	Next

	For Each objBIOS in colBIOS
		strBIOSVersion = objBIOS.Manufacturer & " " & objBIOS.SMBIOSBIOSVersion & ", " & WMIDateStringToDate(objBIOS.ReleaseDate)
		'strSMBIOSVersion = objBIOS.SMBIOSMajorVersion & "." & objBIOS.SMBIOSMinorVersion
	Next

	AddOutput Pad("Date",SUMMARY_STRING_LENGTH,PADRIGHT) & Left(WeekDayName(WeekDay(dtmDate)), 3) & " " & Left(MonthName(Month(dtmDate)), 3) & " " & Pad(CStr(DatePart("d", dtmDate)), 2, PADZERO) & " " & DatePart("yyyy", dtmDate) & " " & Get12HourTime(dtmDate)
	AddOutput Pad("Last Restart", SUMMARY_STRING_LENGTH, PADRIGHT) & Left(WeekDayName(WeekDay(dtmLastBootupTime)), 3) & " " & Left(MonthName(Month(dtmLastBootupTime)), 3) & " " & Pad(CStr(DatePart("d", dtmLastBootupTime)), 2, PADZERO) & " " & DatePart("yyyy", dtmLastBootupTime) & " " & Get12HourTime(dtmLastBootupTime) & " (uptime " & FormatUptime(intMinutesUptime) & ")"
	AddOutput Pad("Original Install Date", SUMMARY_STRING_LENGTH, PADRIGHT) & Left(WeekDayName(WeekDay(dtmInstallDate)), 3) & " " & Left(MonthName(Month(dtmInstallDate)), 3) & " " & Pad(CStr(DatePart("d", dtmInstallDate)), 2, PADZERO) & " " & DatePart("yyyy", dtmInstallDate) & " " & Get12HourTime(dtmInstallDate)
	AddOutput Pad("OS Name",SUMMARY_STRING_LENGTH, PADRIGHT) & strOSName & " " & strServicePack & " " & strBitness
	' AddOutput Pad("Version",SUMMARY_STRING_LENGTH, PADRIGHT) & strOSVersion
	' Exclude "Other OS Description" on XP since MSInfo32 on XP doesn't show it all either.
	' If strBuildNumber <> "2600" Then
	' 	AddOutput Pad("Other OS Description",SUMMARY_STRING_LENGTH, PADRIGHT) & strOtherOSDescription
	' End If
	' AddOutput Pad("OS Manufacturer",SUMMARY_STRING_LENGTH, PADRIGHT) & strOSManufacturer
	AddOutput Pad("System Name",SUMMARY_STRING_LENGTH, PADRIGHT) & strSystemName
	AddOutput Pad("Virtualized",SUMMARY_STRING_LENGTH, PADRIGHT) & strVirtualization
	AddOutput Pad("System Model",SUMMARY_STRING_LENGTH, PADRIGHT) & strSystemManufacturer & " " & strSystemModel
	AddOutput Pad("BIOS Version/Date",SUMMARY_STRING_LENGTH, PADRIGHT) & RemoveChaff(strBIOSVersion)
	AddOutput Pad("Processor",SUMMARY_STRING_LENGTH, PADRIGHT) & strProcessor
	AddOutput strDomain
	AddOutput Pad("Role",SUMMARY_STRING_LENGTH, PADRIGHT) & strDomainRole
	AddOutput Pad("Locale",SUMMARY_STRING_LENGTH, PADRIGHT) & strLocale
	'AddOutput Pad("User Name",SUMMARY_STRING_LENGTH, PADRIGHT) & strUserName
	AddOutput Pad("Time Zone",SUMMARY_STRING_LENGTH, PADRIGHT) & strTimeZone
	' Need to confirm how Installed Physical Memory is determined
	If strBuildNumber = "2600" or strBuildNumber = "3790" Then
		AddOutput Pad("Total Physical Memory",SUMMARY_STRING_LENGTH, PADRIGHT) & FormatNumber(Round(intTotalPhysicalMemory/GB, 1), 2) & " GB"
	Else
		AddOutput Pad("Installed Physical Memory (RAM)",SUMMARY_STRING_LENGTH, PADRIGHT) & FormatNumber(Round(intTotalPhysicalMemory/GB, 1), 2) & " GB"
		AddOutput Pad("Total Physical Memory",SUMMARY_STRING_LENGTH, PADRIGHT) & FormatNumber(Round(intTotalPhysicalMemory/GB, 1), 2) & " GB"
	End If
	AddOutput Pad("Available Physical Memory", SUMMARY_STRING_LENGTH, PADRIGHT) & FormatNumber(intAvailablePhysicalMemory/MB,2) & " GB"
	AddOutput Pad("Total Virtual Memory", SUMMARY_STRING_LENGTH, PADRIGHT) & FormatNumber(intTotalVirtualMemory/MB,2) & " GB"
	AddOutput Pad("Available Virtual Memory", SUMMARY_STRING_LENGTH, PADRIGHT) & FormatNumber(intAvailableVirtualMemory/MB,2) & " GB"
	AddOutput Pad("Maximum Process Memory Size", SUMMARY_STRING_LENGTH, PADRIGHT) & FormatNumber(intMaxProcessMemorySize/MB,2) & " GB"
	If strBuildNumber = "2600" or strBuildNumber = "3790" Then
		If Not IsNull(arrSystemStartupOptions) Then
			For i = 0 To UBound(arrSystemStartupOptions)
				If i = 0 Then
					AddOutput Pad("System Startup Options", SUMMARY_STRING_LENGTH, PADRIGHT) & arrSystemStartupOptions(i)
				Else
					AddOutput Pad(" ", SUMMARY_STRING_LENGTH, PADRIGHT) & arrSystemStartupOptions(i)
				End If
			Next
		End If
	End If
	AddOutput Pad("Registry", SUMMARY_STRING_LENGTH, PADRIGHT) & "Current size: " & intRegistryCurrentSize & " MB Percent In Use: " & Left((intRegistryCurrentSize/intRegistryMaximumSize) * 100, 1) & "% Limit: " & intRegistryMaximumSize & " MB RegistrySizeLimit: " & GetRegValue("HKLM\SYSTEM\CurrentControlSet\Control","RegistrySizeLimit",REG_DWORD)
	AddOutput Pad("WMI Repository", SUMMARY_STRING_LENGTH, PADRIGHT) & "Current size: " & Round(intWMIRepositorySize/MB,2) & " MB (" & strWMIRepositoryFile & ")"
	For i = 0 to Ubound(arrPageFiles)
		If i = 0 Then
			AddOutput Pad("Page Files", SUMMARY_STRING_LENGTH, PADRIGHT) & arrPageFiles(i)
		Else
			If arrPageFiles(i) <> "" then
				AddOutput Pad(" ", SUMMARY_STRING_LENGTH, PADRIGHT) & arrPageFiles(i)
			End If
		End If
	Next

	Print "GetSummary()", TASK, intLocation

End Function

Function GetNICs()

	If blnErrorHandling Then On Error Resume Next

	Print "GetNICs()", TASK, intLocation

	Set colNetworkAdapters = objWMIService.ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled='True'", , wbemFlagReturnImmediately + wbemFlagForwardOnly)

	Heading("NETWORK ADAPTERS")

	For Each objNetworkAdapter in colNetworkAdapters
		AddOutput String(HEADING_WIDTH, "-")
		AddOutput objNetworkAdapter.Description
		AddOutput String(HEADING_WIDTH, "-")

		i = 0
		For Each objIPAddress in objNetworkAdapter.IPAddress
			If i = 0 Then
				AddOutput Pad("IP Address", 15, PADRIGHT) & Trim(objIPAddress)
				i = i + 1
			Else
				AddOutput String(15, " ") & objIPAddress
			End If
		Next
		For Each objIPSubnet in objNetworkAdapter.IPSubnet
			If InStr(1, objIPSubnet, ".", 1) Then
				AddOutput Pad("Subnet mask", 15, PADRIGHT) & Trim(objIPSubnet)
			End If
		Next

		AddOutput Pad("DHCP Enabled", 15, PADRIGHT) & objNetworkAdapter.DHCPEnabled

		i = 0
		If Not IsNull(objNetworkAdapter.DNSServerSearchOrder) Then

			For Each objDNSServer in objNetworkAdapter.DNSServerSearchOrder

				If i = 0 Then
					AddOutput Pad("DNS Server", 15, PADRIGHT) & objDNSServer
					i = i + 1
				Else
					AddOutput String(15, " ") & objDNSServer
				End If

			Next
		Else

			AddOutput Pad("DNS Server", 15, PADRIGHT) & "<no DNS servers configured>"

		End If

		AddOutput Pad("MAC Address", 15, PADRIGHT) & objNetworkAdapter.MacAddress

		Set colNetworkAdapterDrivers = objWMIService.ExecQuery("SELECT * FROM Win32_SystemDriver WHERE Name='" & objNetworkAdapter.ServiceName & "'", , wbemFlagReturnImmediately + wbemFlagForwardOnly)
		For Each objNetworkAdapterDriver in colNetworkAdapterDrivers
			Set colCIMDataFiles = objWMIService.ExecQuery("Select * From CIM_DataFile Where Name='" & Replace(objNetworkAdapterDriver.PathName, "\", "\\") & "'", , wbemFlagReturnImmediately + wbemFlagForwardOnly)
			For Each objCIMDataFile in colCIMDataFiles
				AddOutput Pad("Driver", 15, PADRIGHT) & objCIMDataFile.FileName & "." & objCIMDataFile.Extension & " " & GetBranch(objCIMDataFile.Version, True) & " " & WMIDateStringToDate(objCIMDataFile.LastModified) & " " & FormatNumber(Round(objCIMDataFile.FileSize/1024), 0, , vbTrue) & " KB " & "(" & FormatNumber(objCIMDataFile.FileSize, 0, , vbTrue) & " bytes)" & vbCrLf
			Next
		Next
	Next

	Print "GetNICs()", TASK, intLocation

End Function

Function GetFileSummary()

	If blnErrorHandling Then On Error Resume Next

	Print "GetFileSummary()", TASK, intLocation

	Heading("FILE VERSION INFORMATION")

	For i = 0 To Ubound(arrFiles)
		arrComponentAndFileName = Split(arrFiles(i), ";")
		strFileName = arrComponentAndFileName(1)
		Set colFiles = objWMIService.ExecQuery("Select Extension,FileName,FileSize,LastModified,Version From CIM_DataFile Where Name='" & strFileName & "'", , wbemFlagReturnImmediately + wbemFlagForwardOnly)
		For Each objFile in colFiles
			If strComponentName <> arrComponentAndFileName(0) Then
				strComponentName = arrComponentAndFileName(0)
				If i = 0 Then
					AddOutput String(HEADING_WIDTH, "-") & vbCrLf & strComponentName
				Else
					AddOutput String(HEADING_WIDTH, "-") & vbCrLf & strComponentName
				End If
				AddOutput String(HEADING_WIDTH, "-")
			End If
			If Instr(GetBranch(objFile.Version, False), "LDR") Then
				AddOutput Pad(GetBranch(objFile.Version, False), 6, PADRIGHT) & " " & Pad((UCase(objFile.Filename) & "." & UCase(objFile.Extension)), FILENAME_STRING_LENGTH, PADRIGHT) & "  " & Pad(GetBranch(objFile.Version, True),VERSION_STRING_LENGTH, PADRIGHT) & "  " & Pad(WMIDateStringToDate(objFile.LastModified),DATE_STRING_LENGTH, PADRIGHT) & "  " & Pad(FormatNumber(Round(objFile.FileSize/1024), 0, , vbTrue), 6, PADLEFT) & " KB (" & FormatNumber(objFile.FileSize, 0, , vbTrue) & " bytes)"
			Else
				AddOutput Pad(GetBranch(objFile.Version, False), 6, PADLEFT) & " " & Pad((UCase(objFile.Filename) & "." & UCase(objFile.Extension)), FILENAME_STRING_LENGTH, PADRIGHT) & "  " & Pad(GetBranch(objFile.Version, True),VERSION_STRING_LENGTH, PADRIGHT) & "  " & Pad(WMIDateStringToDate(objFile.LastModified),DATE_STRING_LENGTH, PADRIGHT) & "  " & Pad(FormatNumber(Round(objFile.FileSize/1024), 0, , vbTrue), 6, PADLEFT) & " KB (" & FormatNumber(objFile.FileSize, 0, , vbTrue) & " bytes)"
			End If
		Next
	Next

	Print "GetFileSummary()", TASK, intLocation

End Function

Function GetRegValue(strKey,strValueName,intValueType)

	If blnErrorHandling Then On Error Resume Next

 	Select Case Left(strKey, 4)
		Case "HKLM"
			hDefKey = HKLM
		Case "HKCU"
			hDefKey = HKLM
		Case "HKCR"
			hDefKey = HKCR
		Case "HKU"
			hDefKey = HKU
		Case "HKLM"
			hDefKey = HKLM
	End Select

	strKeyPath = Mid(strKey, 6)

	Select Case intValueType
		Case REG_DWORD
			errReturn = objReg.GetDWORDValue(hDefKey,strKeyPath,strValueName,intValueData)
			If errReturn = 0 Then
				GetRegValue = "0x" & Pad(Hex(intValueData), 8, PADZERO)  & " (" & intValueData & ")"
			Else
				GetRegValue = "<value not present>"
			End If
			Exit Function
		Case REG_SZ
			errReturn = objReg.GetStringValue(hDefKey,strKeyPath,strValueName,strValueData)
			If errReturn = 0 Then
				GetRegValue = strValueData
			Else
				GetRegValue = "<value not present>"
			End If
			Exit Function
	End Select

End Function

Function GetRegKey(strKey)

	If blnErrorHandling Then On Error Resume Next

	Print "GetRegKey( " & strKey & " )", OUTPUT, intLocation

	Set objRegValues = CreateObject("ADODB.Recordset")

	objRegValues.Fields.Append "Value", adVarChar, 255, adFldMayBeNull
	objRegValues.Fields.Append "Type", adVarChar, 255, adFldMayBeNull
	objRegValues.Fields.Append "Data", adVarChar, 500, adFldMayBeNull

	objRegValues.Open

	If Err.Number Then
		Wscript.Echo "[ERROR] Unable to connect to registry: " & Err.Number
		Err.Clear
		Exit Function
	End If

	Select Case Left(strKey, 4)
		Case "HKLM"
			hDefKey = HKLM
		Case "HKCU"
			hDefKey = HKLM
		Case "HKCR"
			hDefKey = HKCR
		Case "HKU"
			hDefKey = HKU
		Case "HKLM"
			hDefKey = HKLM
	End Select

	strKeyPath = Mid(strKey, 6)
	Dim strValues
	Dim strValueData
	Dim strValueType
	Dim intValueLength

	Heading(strKey)

	errReturn = objReg.EnumValues(hDefKey, strKeyPath, arrValueNames, arrTypes)
	If errReturn Then
		AddOutput String(4, " ") & "<key not present>"
		errReturn = 0
		Exit Function
	End If

	If Not objRegValues.BOF Then objRegValues.MoveFirst

	intValueLength = 0

	If Not IsNull(arrValueNames) Then
		For i = LBound(arrValueNames) To UBound(arrValueNames)
			strValueName = arrValueNames(i)

			' Find out which value name has the most characters
			If Len(strValueName) > intValueLength Then
				intValueLength = Len(strValueName)
			End If

			' I've seen REG_SZ values show up with a blank name and value.
			' Empty values are common, but regedit won't let you create a value with a blank name.
			' You can create a value name with only spaces however, so maybe that is where these are coming from.

			Select Case arrTypes(i)
				Case REG_SZ
					strValueType = "REG_SZ"
					objReg.GetStringValue hDefKey, strKeyPath, strValueName, strValueData
				Case REG_EXPAND_SZ
					strValueType = "REG_EXPAND_SZ"
					objReg.GetExpandedStringValue hDefKey, strKeyPath, strValueName, strValueData
				Case REG_BINARY
					strValueType = "REG_BINARY"
					objReg.GetBinaryValue hDefKey, strKeyPath, strValueName, arrBytes
					strValueData = Null
					For Each uByte in arrBytes
						'strValueData = strValueData & Hex(uByte) & " "
						If uByte < &H10 Then
							strValueData = strValueData & "0" & Hex(uByte)
						Else
							strValueData = strValueData & Hex(uByte)
						End If
					Next
				Case REG_DWORD
					strValueType = "REG_DWORD"
					objReg.GetDWORDValue hDefKey, strKeyPath, strValueName, intValueData
					strValueData = 	"0x" & Pad(Hex(intValueData), 8, PADZERO) & " (" & intValueData & ")"
				Case REG_MULTI_SZ
					strValueType = "REG_MULTI_SZ"
					strValueData = Null
					objReg.GetMultiStringValue hDefKey, strKeyPath, strValueName, arrValues
					For Each strValue in arrValues
						If IsNull(strValueData) Then
							strValueData = strValue
						Else
							strValueData = strValueData & "\0" & strValue
						End If
					Next
			End Select

			objRegValues.AddNew
			objRegValues("Value").Value = strValueName
			objRegValues("Type").Value = strValueType
			objRegValues("Data").Value = strValueData
			objRegValues.Update
		Next

		objRegValues.Sort = "Value ASC"
		objRegValues.MoveFirst

		Do Until objRegValues.EOF
			AddOutput String(4, " ") & Pad(objRegValues.Fields.Item("Value"), intValueLength + 2, PADRIGHT) & Pad(objRegValues.Fields.Item("Type"), 15, PADRIGHT) & objRegValues.Fields.Item("Data")
			objRegValues.MoveNext
		Loop
	Else
		AddOutput String(4, " ") & "<key is present but has no values>"
	End If

End Function

Function GetPerfData()

	If blnErrorHandling Then On Error Resume Next

	Print "GetPerfData()", TASK, intLocation

	Heading("PERFORMANCE INFORMATION")

	Print "GetPerfData() MEMORY object (Win32_PerfFormattedData_PerfOS_Memory)", TASK, intLocation
	Set colCounters = objWMIService.ExecQuery("Select AvailableBytes,PoolNonpagedBytes,PoolPagedBytes,PoolPagedResidentBytes,SystemCacheResidentBytes,CommitLimit,CommittedBytes,PercentCommittedBytesInUse,FreeSystemPageTableEntries From Win32_PerfFormattedData_PerfOS_Memory")

	' This PRINT has to stay here so the collection is enumerated and allowed to fail.
	Print "colCounters.Count = " & colCounters.Count, OUTPUT, intLocation

	If Err Then
		Print "[ERROR] " & Err.Number, OUTPUT, TO_FILE
		Err.Clear
		objShell.Run "wmiadap.exe /f"
		Wscript.Sleep 3000
		Set colCounters = objWMIService.ExecQuery("Select AvailableBytes,PoolNonpagedBytes,PoolPagedBytes,PoolPagedResidentBytes,SystemCacheResidentBytes,CommitLimit,CommittedBytes,PercentCommittedBytesInUse,FreeSystemPageTableEntries From Win32_PerfFormattedData_PerfOS_Memory")
	End If

	AddOutput "MEMORY object (Win32_PerfFormattedData_PerfOS_Memory)"
	AddOutput String(HEADING_WIDTH, "-")

	For Each objCounter in colCounters
		If Err Then
			AddOutput "<Memory object not present>"
			Err.Clear
			Exit For
		End If
		AddOutput Pad("Total Physical Memory*", COUNTER_STRING_LENGTH, PADRIGHT) & ConvertBytes(intTotalPhysicalMemory, "ALL")
		AddOutput Pad("Memory\Available Bytes", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(ConvertBytes(objCounter.AvailableBytes, "ALL"), 15, PADRIGHT)
		' Base value for PercentCommittedBytesInUse. XP/2003 do not expose this value. http://msdn.microsoft.com/en-us/library/windows/desktop/aa394314(v=VS.85).aspx
		' AddOutput Pad("PercentCommittedBytesInUse_Base", 35, PADRIGHT) & Pad(objCounter.PercentCommittedBytesInUse_Base, 15, PADRIGHT)
		AddOutput Pad("Memory\Pool Non Paged Bytes", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(ConvertBytes(objCounter.PoolNonPagedBytes, "ALL"), 15, PADRIGHT)
		AddOutput Pad("Memory\Pool Paged Bytes", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(ConvertBytes(objCounter.PoolPagedBytes, "ALL"), 15, PADRIGHT)
		AddOutput Pad("Memory\Pool Paged Resident Bytes", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(ConvertBytes(objCounter.PoolPagedResidentBytes, "ALL"), 15, PADRIGHT)
		AddOutput Pad("Memory\System Cache Resident Bytes", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(ConvertBytes(objCounter.SystemCacheResidentBytes, "ALL"), 15, PADRIGHT)
		AddOutput Pad("Memory\Commit Limit", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(ConvertBytes(objCounter.CommitLimit, "ALL"), 15, PADRIGHT)
		AddOutput Pad("Memory\Committed Bytes", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(ConvertBytes(objCounter.CommittedBytes, "ALL"), 15, PADRIGHT)
		AddOutput "Memory\% Committed Bytes In Use" & Pad(CStr(objCounter.PercentCommittedBytesInUse), 18, PADLEFT) & " %"
		AddOutput "Memory\Free System Page Table Entries" & Pad(FormatNumber(objCounter.FreeSystemPageTableEntries, 0, , True), 12, PADLEFT)
	Next

	AddOutput vbCrLf & "* From Win32_ComputerSystem.TotalPhysicalMemory, since no performance counter exists for total physical memory."

	Print "GetPerfData() MEMORY object (Win32_PerfFormattedData_PerfOS_Memory)", TASK, intLocation

	' SQL Server, Memory Manager Object
	' http://msdn.microsoft.com/en-us/library/ms190924.aspx

	Print "GetPerfData() SYSTEM object (Win32_PerfFormattedData_PerfOS_System)", TASK, intLocation
	Set colCounters = objWMIService.ExecQuery("Select * From Win32_PerfFormattedData_PerfOS_System", , wbemFlagReturnImmediately + wbemFlagForwardOnly)

	AddOutput vbCrLf & String(HEADING_WIDTH, "-")
	AddOutput "SYSTEM object (Win32_PerfFormattedData_PerfOS_System)"
	AddOutput String(HEADING_WIDTH, "-")

	For Each objCounter in colCounters
		If Err Then
			AddOutput "<System object not present>"
			Err.Clear
			Exit For
		End If
		AddOutput Pad("System\Processes", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.Processes, 10, PADLEFT)
		AddOutput Pad("System\Threads", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(FormatNumber(objCounter.Threads, 0, , True), 10, PADLEFT)
		AddOutput Pad("System\% Registry Quota In Use", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.PercentRegistryQuotaInUse, 10, PADLEFT) & " % (current: " & intRegistryCurrentSize & "MB limit: " & intRegistryMaximumSize & "MB RegistrySizeLimit: " & GetRegValue("HKLM\SYSTEM\CurrentControlSet\Control","RegistrySizeLimit",REG_DWORD) & ")"
	Next

	Print "GetPerfData() SYSTEM object (Win32_PerfFormattedData_PerfOS_System)", TASK, intLocation

	If InStr(UCase(strSystemManufacturer), "VMWARE") Then

		Print "GetPerfData() VM PROCESSOR object (Win32_PerfRawData_vmGuestLib_VCPU)", TASK, intLocation

		AddOutput vbCrLf & String(HEADING_WIDTH, "-")
		AddOutput "VM PROCESSOR object (Win32_PerfRawData_vmGuestLib_VCPU)"
		AddOutput String(HEADING_WIDTH, "-")

		Set colCounters = objWMIService.ExecQuery("Select CpuLimitMHz,CpuReservationMHz,CpuShares,CpuStolenMs,CpuTimePercents,EffectiveVMSpeedMHz,HostProcessorSpeedMHz From Win32_PerfRawData_vmGuestLib_VCPU")

		' This PRINT has to stay here so the collection is enumerated and allowed to fail.
		Print "colCounters.Count = " & colCounters.Count, OUTPUT, intLocation

		If Err Then
			Print "[ERROR] " & Err.Number, OUTPUT, TO_FILE
			Err.Clear
			If objFSO.FileExists(objShell.ExpandEnvironmentStrings("%WINDIR%") & "\System32\WBEM\vmStatsProvider.mof") Then
				Print "vmStatsProvider.mof exists", OUTPUT, intLocation
				objShell.Run "wmiadap.exe /f" ' This makes sure the Win32_PerfRawData class is present. If it is missing, the mofcomp for vmStatsProvider.mof will fail because it is registering subclasses of Win32_PerfRawData
                objShell.Run objShell.ExpandEnvironmentStrings("%WINDIR%") & "\System32\Mofcomp.exe " & objShell.ExpandEnvironmentStrings("%WINDIR%") & "\System32\WBEM\vmStatsProvider.mof"
				objShell.Run "wmiadap.exe /f" ' Run it again to refresh the perf classes
			End If
			Wscript.Sleep 3000
			Set colCounters = objWMIService.ExecQuery("Select CpuLimitMHz,CpuReservationMHz,CpuShares,CpuStolenMs,CpuTimePercents,EffectiveVMSpeedMHz,HostProcessorSpeedMHz From Win32_PerfRawData_vmGuestLib_VCPU")
		End If

		For Each objCounter in colCounters
			If Err Then
				AddOutput "<VM Processor object not present>"
				Err.Clear
				Exit For
			End If
			AddOutput Pad("VM Processor\Limit in MHz", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.CpuLimitMHz, 10, PADLEFT)
			AddOutput Pad("VM Processor\Effective VM Speed MHz", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.EffectiveVMSpeedMHz, 10, PADLEFT)
			AddOutput Pad("VM Processor\Host Processor Speed MHz", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.HostProcessorSpeedMHz, 10, PADLEFT)
			AddOutput Pad("VM Processor\Reservation in MHz", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.CpuReservationMHz, 10, PADLEFT)
			AddOutput Pad("VM Processor\Shares", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.CpuShares, 10, PADLEFT)
			AddOutput Pad("VM Processor\CPU Stolen Time", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.CpuStolenMs, 10, PADLEFT)
			AddOutput Pad("VM Processor\% Processor Time", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.CpuTimePercents, 10, PADLEFT)
		Next

		Print "GetPerfData() VM PROCESOR object (Win32_PerfRawData_vmGuestLib_VCPU)", TASK, intLocation

		AddOutput vbCrLf & String(HEADING_WIDTH, "-")
		AddOutput "VM MEMORY object (Win32_PerfRawData_vmGuestLib_VMEM)"
		AddOutput String(HEADING_WIDTH, "-")

		Print "GetPerfData() VM MEMORY object (Win32_PerfRawData_vmGuestLib_VMEM)", TASK, intLocation
		Set colCounters = objWMIService.ExecQuery("Select MemActiveMB,MemBalloonedMB,MemLimitMB,MemMappedMB,MemOverheadMB,MemReservationMB,MemSharedMB,MemSharedSavedMB,MemShares,MemSwappedMB,MemTargetSizeMB,MemUsedMB From Win32_PerfRawData_vmGuestLib_VMEM", , wbemFlagReturnImmediately + wbemFlagForwardOnly)

		For Each objCounter in colCounters
			If Err Then
				AddOutput "<VM Memory object not present>"
				Err.Clear
				Exit For
			End If
			If objCounter.MemBalloonedMB > 0 Then
				AddOutput Pad("VM Memory\Memory Ballooned in MB", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.MemBalloonedMB, 10, PADLEFT) & " IMPORTANT: Ballooning in effect, stop with SC STOP VMMEMCTL, disable with SC CONFIG VMMEMCTL START= DISABLED"
			Else
				AddOutput Pad("VM Memory\Memory Ballooned in MB", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.MemBalloonedMB, 10, PADLEFT)
			End If
			AddOutput Pad("VM Memory\Memory Active in MB", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.MemActiveMB, 10, PADLEFT)
			AddOutput Pad("VM Memory\Memory Limit in MB", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.MemLimitMB, 10, PADLEFT)
			AddOutput Pad("VM Memory\Memory Mapped in MB", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.MemMappedMB, 10, PADLEFT)
			AddOutput Pad("VM Memory\Memory Overhead in MB", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.MemOverheadMB, 10, PADLEFT)
			AddOutput Pad("VM Memory\Memory Reservation in MB", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.MemReservationMB, 10, PADLEFT)
			AddOutput Pad("VM Memory\Memory Shared in MB", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.MemSharedMB, 10, PADLEFT)
			AddOutput Pad("VM Memory\Memory Shared Saved in MB", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.MemSharedSavedMB, 10, PADLEFT)
			AddOutput Pad("VM Memory\Memory Shares", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.MemShares, 10, PADLEFT)
			AddOutput Pad("VM Memory\Memory Swapped in MB", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.MemSwappedMB, 10, PADLEFT)
			AddOutput Pad("VM Memory\Memory Target Size", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.MemTargetSizeMB, 10, PADLEFT)
			AddOutput Pad("VM Memory\Memory Used in MB", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.MemUsedMB, 10, PADLEFT)
		Next

		Print "GetPerfData() VM MEMORY object (Win32_PerfRawData_vmGuestLib_VMEM)", TASK, intLocation

	End If

' There are multiple Server Work Queue instances, one for each CPU plus others, not sure if we want to include some or all.
' gwmi Win32_PerfFormattedData_PerfNet_ServerWorkQueues | select name
' 0
' 1
' Blocking Queue
' SMB2 NonBlocking 0
' SMB2 NonBlocking 1
' SMB2 Blocking 0
' SMB2 Blocking 1

'	Set colCounters = objWMIService.ExecQuery("Select PoolNonpagedFailures,FilesOpen,FilesOpenedTotal,ActiveThreads,AvailableWorkItems,BorrowedWorkItems,PoolPagedFailures,WorkItemShortages From Win32_PerfFormattedData_PerfNet_ServerWorkQueues", , wbemFlagReturnImmediately + wbemFlagForwardOnly)
'	    For Each objCounter in colCounters
'		    AddOutput vbCrLf & Pad("Server Work Queues\Work Item Shortages", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.WorkItemShortages, 10, PADLEFT)
'		    AddOutput Pad("Server Work Queues\Pool Paged Failures", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.PoolPagedFailures, 10, PADLEFT)
'		    AddOutput Pad("Server Work Queues\Pool Nonpaged Failures", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.PoolNonpagedFailures, 10, PADLEFT)
'		    AddOutput Pad("Server Work Queues\Current Clients", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.FilesOpen, 10, PADLEFT)
'		    AddOutput Pad("Server Work Queues\Queue Length", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.FilesOpenedTotal, 10, PADLEFT)
'		    AddOutput Pad("Server Work Queues\Active Threads", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.ActiveThreads, 10, PADLEFT)
'		    AddOutput Pad("Server Work Queues\Available Threads", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.AvailableWorkItems, 10, PADLEFT)
'		    AddOutput Pad("Server Work Queues\Active Threads", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.BorrowedWorkItems, 10, PADLEFT)
'	    Next
	If (not blnSetupSDPManifest) Then

		Print "GetPerfData() SERVER object (Win32_PerfFormattedData_PerfNet_Server)", TASK, intLocation

		AddOutput vbCrLf & String(HEADING_WIDTH, "-")
		AddOutput "SERVER object (Win32_PerfFormattedData_PerfNet_Server)"
		AddOutput String(HEADING_WIDTH, "-")

		Set colCounters = objWMIService.ExecQuery("Select SessionsTimedOut,SessionsLoggedOff,SessionsForcedOff,SessionsErroredOut,BlockingRequestsRejected,ErrorsAccessPermissions,ErrorsGrantedAccess,ErrorsLogon,ErrorsSystem,FileDirectorySearches,FilesOpen,FilesOpenedTotal,LogonTotal,PoolNonpagedFailures,PoolPagedFailures,ServerSessions,WorkItemShortages From Win32_PerfFormattedData_PerfNet_Server", , wbemFlagReturnImmediately + wbemFlagForwardOnly)

		For Each objCounter in colCounters
			If Err Then
				AddOutput "<Server object not present>"
				Err.Clear
				Exit For
			End If
			AddOutput Pad("Server\Work Item Shortages", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.WorkItemShortages, 10, PADLEFT)
			AddOutput Pad("Server\Pool Paged Failures", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.PoolPagedFailures, 10, PADLEFT)
			AddOutput Pad("Server\Pool Nonpaged Failures", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.PoolNonpagedFailures, 10, PADLEFT)
			AddOutput Pad("Server\Blocking Requests Rejected", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.BlockingRequestsRejected, 10, PADLEFT)
			AddOutput Pad("Server\Files Open", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.FilesOpen, 10, PADLEFT)
			AddOutput Pad("Server\Files Opened Total", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.FilesOpenedTotal, 10, PADLEFT)
			AddOutput Pad("Server\File Directory Searches", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.FileDirectorySearches, 10, PADLEFT)
			AddOutput Pad("Server\Logon Total", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.LogonTotal, 10, PADLEFT)
			AddOutput Pad("Server\Server Sessions", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.ServerSessions, 10, PADLEFT)
			AddOutput Pad("Server\Sessions Logged Off", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.SessionsLoggedOff, 10, PADLEFT)
			AddOutput Pad("Server\Sessions Errored Out", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.SessionsErroredOut, 10, PADLEFT)
			AddOutput Pad("Server\Sessions Timed Out", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.SessionsTimedOut, 10, PADLEFT)
			AddOutput Pad("Server\Sessions Forced Off", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.SessionsForcedOff, 10, PADLEFT)
			AddOutput Pad("Server\Errors Access Permissions", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.ErrorsAccessPermissions, 10, PADLEFT)
			AddOutput Pad("Server\Errors Granted Access", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.ErrorsGrantedAccess, 10, PADLEFT)
			AddOutput Pad("Server\Errors Logon", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.ErrorsLogon, 10, PADLEFT)
			AddOutput Pad("Server\Errors System", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.ErrorsSystem, 10, PADLEFT)
		Next

		Print "GetPerfData() SERVER object (Win32_PerfFormattedData_PerfNet_Server)", TASK, intLocation

		AddOutput vbCrLf & String(HEADING_WIDTH, "-")
		AddOutput "REDIRECTOR object (Win32_PerfFormattedData_PerfNet_Redirector)"
		AddOutput String(HEADING_WIDTH, "-")

		Print "GetPerfData() REDIRECTOR object (Win32_PerfFormattedData_PerfNet_Redirector)", TASK, intLocation

		Set colCounters = objWMIService.ExecQuery("Select ServerSessions,ServerDisconnects,ServerReconnects,ServerSessionsHung From Win32_PerfFormattedData_PerfNet_Redirector", , wbemFlagReturnImmediately + wbemFlagForwardOnly)

		For Each objCounter in colCounters
			If Err Then
				AddOutput "<Redirector object not present>"
				Err.Clear
				Exit For
			End If
			AddOutput Pad("Redirector\Server Sessions", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.ServerSessions, 10, PADLEFT)
			AddOutput Pad("Redirector\Server Disconnects", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.ServerDisconnects, 10, PADLEFT)
			AddOutput Pad("Redirector\Server Reconnects", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.ServerReconnects, 10, PADLEFT)
			AddOutput Pad("Redirector\Server Sessions Hung", COUNTER_STRING_LENGTH, PADRIGHT) & Pad(objCounter.ServerSessionsHung, 10, PADLEFT)
		Next

		Print "GetPerfData() REDIRECTOR object (Win32_PerfFormattedData_PerfNet_Redirector)", TASK, intLocation

		Print "GetPerfData()", TASK, intLocation
End If
End Function

Function GetBranch(strFileVersion, blnReturnVersionNumber)

	If blnErrorHandling Then On Error Resume Next

	If InStr(strFileVersion, ",") Then
		Wscript.Echo vbCrLf & strFileVersion & vbCrLf
	End If

	strServicingBranch = ""
	arrFileVersion = ""
	strFileVersionNumber = ""
	arrFileVersionNumberParts = ""

	If IsNull(strFileVersion) Or strFileVersion = "" Then
		GetBranch = ""
		Exit Function
	End If

	If Instr(strFileVersion, ".") = 0 Then
		GetBranch = strFileVersion
		Exit Function
	End If

	If Instr(1, strFileVersion, "(") Then
		arrFileVersion = Split(strFileVersion, "(", -1, 1)
	Else
		arrFileVersion = Split(strFileVersion, " ", -1, 1)
	End If

	strFileVersionNumber = Trim(arrFileversion(0))

	If blnReturnVersionNumber Then
		GetBranch = strFileVersionNumber
		Exit Function
	End If

	arrFileVersionNumberParts = Split(strFileVersion, ".", -1, 1)

	If InStr(strFileVersionNumber, "5.2.3790") Or InStr(strFileVersionNumber, "5.1.2600") Then
		If InStr(UCase(arrFileVersion(1)), "GDR") Then
			strServicingBranch = "GDR"
		ElseIf InStr(UCase(arrFileVersion(1)), "QFE") Then
			strServicingBranch = "LDR"
		ElseIf strFileVersionNumber = "5.2.3790.3959" Then
			strServicingBranch = "SP2" '2003 SP2
		ElseIf strFileVersionNumber = "5.2.3790.1830" Then
			strServicingBranch = "SP1" '2003 SP1
		ElseIf strFileVersionNumber = "5.2.3790.0" Then
			strServicingBranch = "RTM" '2003 RTM
		ElseIf strFileVersionNumber = "5.1.2600.5512" Then
			strServicingBranch = "SP3" 'XP SP3
		ElseIf strFileVersionNumber = "5.1.2600.2180" Then
			strServicingBranch = "SP2" 'XP SP2
		ElseIf strFileVersionNumber = "5.1.2600.1106" Then
			strServicingBranch = "SP1" 'XP SP1
		ElseIf strFileVersionNumber = "5.1.2600.0" Then
			strServicingBranch = "RTM" 'XP RTM
		End If
	ElseIf InStr(strFileVersionNumber, "6.1.760") Or InStr(strFileVersionNumber, "6.0.600") Then
		If strFileVersionNumber = "6.1.7601.17514" Then
			strServicingBranch = "SP1"
		ElseIf strFileVersionNumber = "6.1.7600.16385" Then
			strServicingBranch = "RTM"
		ElseIf strFileVersionNumber = "6.0.6002.18005" Then
			strServicingBranch = "SP2"
		ElseIf strFileVersionNumber = "6.0.6001.18000" Then
			strServicingBranch = "SP1"
		ElseIf strFileVersionNumber = "6.0.6000.16386" Then
			strServicingBranch = "SP1"
		ElseIf UBound(arrFileVersionNumberParts) > 2 Then
			If InStr(strFileVersionNumber, "6.1.760") Or InStr(strFileVersionNumber, "6.0.600") Then
				If Left(arrFileVersionNumberParts(3),1) = "2" Then
					strServicingBranch = "LDR"
				Else
					strServicingBranch = "GDR"
				End If
			End If
		End If
	End If

	GetBranch = strServicingBranch

End Function

Function WMIDateStringToDate(ByVal dtmDate)

    If blnErrorHandling Then On Error Resume Next

	WMIDateStringToDate = Mid(dtmDate, 5, 2) & "/" & Mid(dtmDate, 7, 2) & "/" & Left(dtmDate, 4)
	'WMIDateStringToDate = CDate(Mid(dtmDate, 5, 2) & "/" & Mid(dtmDate, 7, 2) & "/" & Left(dtmDate, 4) & " " & Mid (dtmDate, 9, 2) & ":" & Mid(dtmDate, 11, 2) & ":" & Mid(dtmDate, 13, 2))

End Function

Function WMIDateStringToDate3(ByVal dtmDate)

    If blnErrorHandling Then On Error Resume Next

	Dim dtmInstallDate
	Set dtmInstallDate = CreateObject("WbemScripting.SWbemDateTime")
	dtmInstallDate.Value = dtmDate
	WMIDateStringToDate3 = dtmInstallDate.GetVarDate(True)

End Function

Function WMIDateStringToDate2(ByVal dtmDate)

	If blnErrorHandling Then On Error Resume Next

    'WMIDateStringToDate = Mid(dtmDate, 5, 2) & "/" & Mid(dtmDate, 7, 2) & "/" & Left(dtmDate, 4)
	WMIDateStringToDate2 = Mid(dtmDate, 5, 2) & "/" & Mid(dtmDate, 7, 2) & "/" & Left(dtmDate, 4) & " " & Mid (dtmDate, 9, 2) & ":" & Mid(dtmDate, 11, 2) & ":" & Mid(dtmDate, 13, 2)

End Function

Function ConvertBytes(intBytes, strFormat)

	If blnErrorHandling Then On Error Resume Next

	If IsNull(intBytes) Then
		ConvertBytes = ""
		Exit Function
	End If
	If strFormat = "ALL" Then
		ConvertBytes = Pad((FormatNumber(Round(intBytes/GB, 2), 2)), 10, PADLEFT) & " GB " & Pad("(" & FormatNumber(Round(intBytes/MB, 2), 2), 10, PADLEFT) & " MB) " & Pad("(" & intBytes, 12, PADLEFT) & " bytes)"
	ElseIf strFormat = "GB" Then
		ConvertBytes = FormatNumber(Round(intBytes/GB, 2), 2) & " GB"
	ElseIf strFormat = "KB" Then
		ConvertBytes = FormatNumber(Round(intBytes/GB, 2), 2) & " GB"
	End If

End Function

Function Pad(strString,intDesiredLength,blnLocation)

	If blnErrorHandling Then On Error Resume Next

	If IsNull(strString) Then strString = ""

	intSpaces = intDesiredLength - Len(strString)
	If intSpaces > 0 Then
		If blnLocation = PADLEFT Then
			strString = String(intSpaces, " ") & strString
		ElseIf blnLocation = PADZERO Then
			strString = String(intSpaces, "0") & strString
		Else
			strString = strString & String(intSpaces," ")
		End If
	End If
	Pad = strString

End Function

Function AddOutput(strString)

	If blnErrorHandling Then On Error Resume Next
	'GetVarInfo strString
	If IsNull(strString) Then
		strString = ""
	End If
	'Wscript.Echo strString
	ReDim Preserve arrOutput(UBound(arrOutput)+1)
	arrOutput(UBound(arrOutput)) = strString

End Function

Function ConvertLocale(strLangID)

	If blnErrorHandling Then On Error Resume Next

	Select Case strLangID
		Case 0436 ConvertLocale = "Afrikaans (South Africa)"
		Case 041c ConvertLocale = "Albanian (Albania)"
		Case 0401 ConvertLocale = "Arabic (Saudi Arabia)"
		Case 1401 ConvertLocale = "Arabic (Algeria)"
		Case 3c01 ConvertLocale = "Arabic (Bahrain)"
		Case 0c01 ConvertLocale = "Arabic (Egypt)"
		Case 0801 ConvertLocale = "Arabic (Iraq)"
		Case 2c01 ConvertLocale = "Arabic (Jordan)"
		Case 3401 ConvertLocale = "Arabic (Kuwait)"
		Case 3001 ConvertLocale = "Arabic (Lebanon)"
		Case 1001 ConvertLocale = "Arabic (Libya)"
		Case 1801 ConvertLocale = "Arabic (Morocco)"
		Case 2001 ConvertLocale = "Arabic (Oman)"
		Case 4001 ConvertLocale = "Arabic (Qatar)"
		Case 2801 ConvertLocale = "Arabic (Syria)"
		Case 1c01 ConvertLocale = "Arabic (Tunisia)"
		Case 3801 ConvertLocale = "Arabic (U.A.E.)"
		Case 2401 ConvertLocale = "Arabic (Yemen)"
		Case 042b ConvertLocale = "Armenian (Armenia)"
		Case 044d ConvertLocale = "Assamese"
		Case 082c ConvertLocale = "Azeri (Cyrillic)"
		Case 042c ConvertLocale = "Azeri (Latin)"
		Case 042d ConvertLocale = "Basque"
		Case 0423 ConvertLocale = "Belarusian"
		Case 0445 ConvertLocale = "Bengali (India)"
		Case 0845 ConvertLocale = "Bengali (Bangladesh)"
		Case 141A ConvertLocale = "Bosnian (Bosnia/Herzegovina)"
		Case 0402 ConvertLocale = "Bulgarian"
		Case 0455 ConvertLocale = "Burmese"
		Case 0403 ConvertLocale = "Catalan"
		Case 045c ConvertLocale = "Cherokee (United States)"
		Case 0804 ConvertLocale = "Chinese (PRC)"
		Case 1004 ConvertLocale = "Chinese (Singapore)"
		Case 0404 ConvertLocale = "Chinese (Taiwan)"
		Case 0c04 ConvertLocale = "Chinese (Hong Kong SAR)"
		Case 1404 ConvertLocale = "Chinese (Macao SAR)"
		Case 041a ConvertLocale = "Croatian"
		Case 101a ConvertLocale = "Croatian (Bosnia/Herzegovina)"
		Case 0405 ConvertLocale = "Czech"
		Case 0406 ConvertLocale = "Danish"
		Case 0465 ConvertLocale = "Divehi"
		Case 0413 ConvertLocale = "Dutch (Netherlands)"
		Case 0813 ConvertLocale = "Dutch (Belgium)"
		Case 0466 ConvertLocale = "Edo"
		Case 0409 ConvertLocale = "United States"
		Case 0809 ConvertLocale = "English (United Kingdom)"
		Case 0c09 ConvertLocale = "English (Australia)"
		Case 2809 ConvertLocale = "English (Belize)"
		Case 1009 ConvertLocale = "English (Canada)"
		Case 2409 ConvertLocale = "English (Caribbean)"
		Case 3c09 ConvertLocale = "English (Hong Kong SAR)"
		Case 4009 ConvertLocale = "English (India)"
		Case 3809 ConvertLocale = "English (Indonesia)"
		Case 1809 ConvertLocale = "English (Ireland)"
		Case 2009 ConvertLocale = "English (Jamaica)"
		Case 4409 ConvertLocale = "English (Malaysia)"
		Case 1409 ConvertLocale = "English (New Zealand)"
		Case 3409 ConvertLocale = "English (Philippines)"
		Case 4809 ConvertLocale = "English (Singapore)"
		Case 1c09 ConvertLocale = "English (South Africa)"
		Case 2c09 ConvertLocale = "English (Trinidad)"
		Case 3009 ConvertLocale = "English (Zimbabwe)"
		Case 0425 ConvertLocale = "Estonian"
		Case 0438 ConvertLocale = "Faroese"
		Case 0429 ConvertLocale = "Farsi"
		Case 0464 ConvertLocale = "Filipino"
		Case 040b ConvertLocale = "Finnish"
		Case 040c ConvertLocale = "French (France)"
		Case 080c ConvertLocale = "French (Belgium)"
		Case 2c0c ConvertLocale = "French (Cameroon)"
		Case 0c0c ConvertLocale = "French (Canada)"
		Case 240c ConvertLocale = "French (DRC)"
		Case 300c ConvertLocale = "French (Cote d'Ivoire)"
		Case 3c0c ConvertLocale = "French (Haiti)"
		Case 140c ConvertLocale = "French (Luxembourg)"
		Case 340c ConvertLocale = "French (Mali)"
		Case 180c ConvertLocale = "French (Monaco)"
		Case 380c ConvertLocale = "French (Morocco)"
		Case e40c ConvertLocale = "French (North Africa)"
		Case 200c ConvertLocale = "French (Reunion)"
		Case 280c ConvertLocale = "French (Senegal)"
		Case 100c ConvertLocale = "French (Switzerland)"
		Case 1c0c ConvertLocale = "French (West Indies)"
		Case 0462 ConvertLocale = "Frisian (Netherlands)"
		Case 0467 ConvertLocale = "Fulfulde (Nigeria)"
		Case 042f ConvertLocale = "FYRO Macedonian"
		Case 083c ConvertLocale = "Gaelic (Ireland)"
		Case 043c ConvertLocale = "Gaelic (Scotland)"
		Case 0456 ConvertLocale = "Galician"
		Case 0437 ConvertLocale = "Georgian"
		Case 0407 ConvertLocale = "German (Germany)"
		Case 0c07 ConvertLocale = "German (Austria)"
		Case 1407 ConvertLocale = "German (Liechtenstein)"
		Case 1007 ConvertLocale = "German (Luxembourg)"
		Case 0807 ConvertLocale = "German (Switzerland)"
		Case 0408 ConvertLocale = "Greek"
		Case 0474 ConvertLocale = "Guarani (Paraguay)"
		Case 0447 ConvertLocale = "Gujarati"
		Case 0468 ConvertLocale = "Hausa (Nigeria)"
		Case 0475 ConvertLocale = "Hawaiian (United States)"
		Case 040d ConvertLocale = "Hebrew"
		Case 0439 ConvertLocale = "Hindi"
		Case 0469 ConvertLocale = "Ibibio (Nigeria)"
		Case 040f ConvertLocale = "Icelandic"
		Case 0470 ConvertLocale = "Igbo (Nigeria)"
		Case 0421 ConvertLocale = "Indonesian"
		Case 045d ConvertLocale = "Inuktitut"
		Case 0410 ConvertLocale = "Italian (Italy)"
		Case 0810 ConvertLocale = "Italian (Switzerland)"
		Case 0411 ConvertLocale = "Japanese"
		Case 044b ConvertLocale = "Kannada"
		Case 0471 ConvertLocale = "Kanuri (Nigeria)"
		Case 0860 ConvertLocale = "Kashmiri"
		Case 0460 ConvertLocale = "Kashmiri (Arabic)"
		Case 043f ConvertLocale = "Kazakh"
		Case 0453 ConvertLocale = "Khmer"
		Case 0457 ConvertLocale = "Konkani"
		Case 0412 ConvertLocale = "Korean"
		Case 0440 ConvertLocale = "Kyrgyz (Cyrillic)"
		Case 0454 ConvertLocale = "Lao"
		Case 0476 ConvertLocale = "Latin"
		Case 0426 ConvertLocale = "Latvian"
		Case 0427 ConvertLocale = "Lithuanian"
		Case 044c ConvertLocale = "Malayalam"
		Case 043a ConvertLocale = "Maltese"
		Case 0458 ConvertLocale = "Manipuri"
		Case 0481 ConvertLocale = "Maori (New Zealand)"
		Case 0450 ConvertLocale = "Mongolian (Cyrillic)"
		Case 0850 ConvertLocale = "Mongolian (Mongolian)"
		Case 0461 ConvertLocale = "Nepali"
		Case 0861 ConvertLocale = "Nepali (India)"
		Case 0414 ConvertLocale = "Norwegian (Bokmål)"
		Case 0814 ConvertLocale = "Norwegian (Nynorsk)"
		Case 0448 ConvertLocale = "Oriya"
		Case 0472 ConvertLocale = "Oromo"
		Case 0479 ConvertLocale = "Papiamentu"
		Case 0463 ConvertLocale = "Pashto"
		Case 0415 ConvertLocale = "Polish"
		Case 0416 ConvertLocale = "Portuguese (Brazil)"
		Case 0816 ConvertLocale = "Portuguese (Portugal)"
		Case 0446 ConvertLocale = "Punjabi"
		Case 0846 ConvertLocale = "Punjabi (Pakistan)"
		Case 046B ConvertLocale = "Quecha (Bolivia)"
		Case 086B ConvertLocale = "Quecha (Ecuador)"
		Case 0C6B ConvertLocale = "Quecha (Peru)"
		Case 0417 ConvertLocale = "Rhaeto-Romanic"
		Case 0418 ConvertLocale = "Romanian"
		Case 0818 ConvertLocale = "Romanian (Moldava)"
		Case 0419 ConvertLocale = "Russian"
		Case 0819 ConvertLocale = "Russian (Moldava)"
		Case 043b ConvertLocale = "Sami (Lappish)"
		Case 044f ConvertLocale = "Sanskrit"
		Case 046c ConvertLocale = "Sepedi"
		Case 0c1a ConvertLocale = "Serbian (Cyrillic)"
		Case 081a ConvertLocale = "Serbian (Latin)"
		Case 0459 ConvertLocale = "Sindhi (India)"
		Case 0859 ConvertLocale = "Sindhi (Pakistan)"
		Case 045b ConvertLocale = "Sinhalese (Sri Lanka)"
		Case 041b ConvertLocale = "Slovak"
		Case 0424 ConvertLocale = "Slovenian"
		Case 0477 ConvertLocale = "Somali"
		Case 0c0a ConvertLocale = "Spanish (Spain - Modern Sort)"
		Case 040a ConvertLocale = "Spanish (Spain - Traditional Sort)"
		Case 2c0a ConvertLocale = "Spanish (Argentina)"
		Case 400a ConvertLocale = "Spanish (Bolivia)"
		Case 340a ConvertLocale = "Spanish (Chile)"
		Case 240a ConvertLocale = "Spanish (Colombia)"
		Case 140a ConvertLocale = "Spanish (Costa Rica)"
		Case 1c0a ConvertLocale = "Spanish (Dominican Republic)"
		Case 300a ConvertLocale = "Spanish (Ecuador)"
		Case 440a ConvertLocale = "Spanish (El Salvador)"
		Case 100a ConvertLocale = "Spanish (Guatemala)"
		Case 480a ConvertLocale = "Spanish (Honduras)"
		Case 580a ConvertLocale = "Spanish (Latin America)"
		Case 080a ConvertLocale = "Spanish (Mexico)"
		Case 4c0a ConvertLocale = "Spanish (Nicaragua)"
		Case 180a ConvertLocale = "Spanish (Panama)"
		Case 3c0a ConvertLocale = "Spanish (Paraguay)"
		Case 280a ConvertLocale = "Spanish (Peru)"
		Case 500a ConvertLocale = "Spanish (Puerto Rico)"
		Case 540a ConvertLocale = "Spanish (United States)"
		Case 380a ConvertLocale = "Spanish (Uruguay)"
		Case 200a ConvertLocale = "Spanish (Venezuela)"
		Case 0430 ConvertLocale = "Sutu"
		Case 0441 ConvertLocale = "Swahili"
		Case 041d ConvertLocale = "Swedish"
		Case 081d ConvertLocale = "Swedish (Finland)"
		Case 045a ConvertLocale = "Syriac"
		Case 0428 ConvertLocale = "Tajik"
		Case 045f ConvertLocale = "Tamazight (Arabic)"
		Case 085f ConvertLocale = "Tamazight (Latin)"
		Case 0449 ConvertLocale = "Tamil"
		Case 0444 ConvertLocale = "Tatar"
		Case 044a ConvertLocale = "Telugu"
		Case 0851 ConvertLocale = "Tibetan (Bhutan)"
		Case 0451 ConvertLocale = "Tibetan (PRC)"
		Case 0873 ConvertLocale = "Tigrigna (Eritrea)"
		Case 0473 ConvertLocale = "Tigrigna (Ethiopia)"
		Case 0431 ConvertLocale = "Tsonga"
		Case 0432 ConvertLocale = "Tswana"
		Case 041f ConvertLocale = "Turkish"
		Case 0442 ConvertLocale = "Turkmen"
		Case 0480 ConvertLocale = "Uighur (China)"
		Case 0422 ConvertLocale = "Ukrainian"
		Case 0420 ConvertLocale = "Urdu"
		Case 0820 ConvertLocale = "Urdu (India)"
		Case 0843 ConvertLocale = "Uzbek (Cyrillic)"
		Case 0443 ConvertLocale = "Uzbek (Latin)"
		Case 0433 ConvertLocale = "Venda"
		Case 042a ConvertLocale = "Vietnamese"
		Case 0452 ConvertLocale = "Welsh"
		Case 0434 ConvertLocale = "Xhosa"
		Case 0478 ConvertLocale = "Yi"
		Case 043d ConvertLocale = "Yiddish"
		Case 046a ConvertLocale = "Yoruba"
		Case 0435 ConvertLocale = "Zulu"
		Case 04ff ConvertLocale = "HID (Human Interface Device)"
		Case Else
		ConvertLocale = strLangID
	End Select

End Function

Function RemoveChaff(strChaff)

	If blnErrorHandling Then On Error Resume Next

	' Remove insignificant characters for readability
	Dim objRegEx
	Set objRegEx = New RegExp
	objRegEx.Global = True
	objRegEx.IgnoreCase = True
	objRegEx.Pattern = "\s{2,}"
	strChaff = Replace(strChaff, "x64", "", 1, -1, 1)
	strChaff = Replace(strChaff, "?", "", 1, -1, 1)
	strChaff = Replace(strChaff, "Ghz", " Ghz", 1, -1, 1)
	strChaff = Replace(strChaff, "Mhz", " Mhz", 1, -1, 1)
	strChaff = Replace(strChaff, "Edition", "", 1, -1, 1)
	strChaff = Replace(strChaff, "@", " ", 1, -1, 1)
	strChaff = Replace(strChaff, "CPU", "", 1, -1, 1)
	strChaff = Replace(strChaff, Chr(169), "", 1, -1, 1)
	strChaff = Replace(strChaff, Chr(174), "", 1, -1, 1)
	strChaff = Replace(strChaff, "(C)", "", 1, -1, 1)
	strChaff = Replace(strChaff, "(R)", "", 1, -1, 1)
	strChaff = Replace(strChaff, "(TM)", " ", 1, -1, 1)
	strChaff = Replace(strChaff, ",", "", 1, -1, 1)
	strChaff = Replace(strChaff, "Microsoft", "", 1, -1, 1)
	strChaff = Trim(objRegEx.Replace(strChaff, " "))
	RemoveChaff = strChaff

End Function

Function GetImportantDrivers()

	If blnErrorHandling Then On Error Resume Next

	Print "GetImportantDrivers()", TASK, intLocation

	Dim dctPnPAllocatedResources
	Dim strDeviceID
	Dim colPnPAllocatedResources
	Dim objPnPAllocatedResource
	Dim colSCSIControllers
	Dim objSCSIController
	Dim colIDEControllers
	Dim objIDEController
	Dim colCIMLogicalDeviceCIMDataFiles
	Dim objCIMLogicalDeviceCIMDataFiles
	Dim colCIMDataFiles
	Dim objCIMDataFile
	Dim strDriver

	Dim dctDrivers
	Set dctDrivers = CreateObject("Scripting.Dictionary")

	Heading("STORAGE/NETWORK/AUDIO/VIDEO DRIVERS (currently using hardware resources)")

	AddOutput Pad("Type", 15, PADRIGHT) & Pad("Name", 19, PADRIGHT) & Pad("Manufacturer", 29, PADRIGHT) & Pad("Version", 20, PADRIGHT) & Pad("Date", 11, PADRIGHT) & Pad(Pad("Size", 12, PADLEFT), 27, PADRIGHT) & Pad("Description", 16, PADLEFT)
	'AddOutput Pad("STORAGE (IDE)", 15, PADRIGHT) & Pad(UCase(objCIMDataFile.FileName & "." & objCIMDataFile.Extension), 12, PADRIGHT) & " " & Pad(Trim(objCIMDataFile.Manufacturer), 29, PADRIGHT) & Pad(GetBranch(objCIMDataFile.Version, True), 14, PADRIGHT) & " " & WMIDateStringToDate(objCIMDataFile.LastModified) & " " & Pad(FormatNumber(Round(objCIMDataFile.FileSize/1024), 0, , vbTrue), 6, PADLEFT) & " KB " & Pad("(" & FormatNumber(objCIMDataFile.FileSize, 0, , vbTrue), 11, PADLEFT) & " bytes) " & RemoveChaff(objIDEController.Name)

	AddOutput String(HEADING_WIDTH, "-")

	Set colPnPAllocatedResources = objWMIService.ExecQuery("Select Dependent From Win32_PnPAllocatedResource")

	If colPnPAllocatedResources.Count Then

		' Create dictionary of allocated resources to prevent repeated WMI queries when checking if a device is using a resource
		Set dctPnPAllocatedResources = CreateObject("Scripting.Dictionary")
		dctPnPAllocatedResources.CompareMode = 1 ' use textmode compare so items are case-insensitive, avoiding duplicates and making lookups easier

		For Each objPnPAllocatedResource in colPnPAllocatedResources
			'arrPnPAllocatedResources(i) = Replace(UCase(objPnPAllocatedResource.Dependent), "\\", "\", 1, -1, 1)
			'arrPnPAllocatedResources(i) = objPnPAllocatedResource.Dependent
			'i = i + 1

			strDeviceID = Replace(Replace(Mid(objPnPAllocatedResource.Dependent, InStr(1, objPnPAllocatedResource.Dependent, "=", 1) + 1), Chr(34), "", 1, -1, 1), "\\", "\", 1, -1, 1)

			If Not dctPnPAllocatedResources.Exists(strDeviceID) Then
				If InStr(1,strDeviceID, "IDECHANNEL", 1) = 0 Then
					dctPnPAllocatedResources.Add strDeviceID, objPnPAllocatedResource.Antecedent
				End If
			End If

		Next
		Dim arrTempArray
		Dim strPrefix
		'arrTempArray = Split(arrPnPAllocatedResources(0), "=")
		'strPrefix = arrTempArray(0)

		Dim colKeys
		Dim colItems
		Dim strKey
		Dim strItem
		colKeys = dctPnPAllocatedResources.Keys
		For Each strKey in colKeys
			'Wscript.Echo strKey
		Next

		colItems = dctPnPAllocatedResources.Items
		For Each strItem in colItems
			'Wscript.Echo strItem
		Next
	Else
		Wscript.Echo "colPnPAllocatedResources.Count = " & colPnPAllocatedResources.Count
	End If

	'Wscript.Quit

	' Get all the SCSI controllers on the box
	Set colSCSIControllers = objWMIService.ExecQuery("Select Name,PNPDeviceId From Win32_SCSIController")
	' If there is at least one SCSI controller, match their PNPID with one in the array of PNP resources
	If colSCSIControllers.Count Then
		For Each objSCSIController in colSCSIControllers
			'For i = 0 to UBound(arrPnPAllocatedResources)
				'Wscript.Echo arrPnPAllocatedResources(i) & vbTab & UCase(objSCSIController.PnpDeviceId)
				If dctPnPAllocatedResources.Exists(objSCSIController.PNPDeviceID) Then
				'If InStr(1,arrPnPAllocatedResources(i),Replace(UCase(objSCSIController.PnpDeviceId), "\", "\\", 1, -1, 1),1) Then

					'Set colCIMLogicalDeviceCIMDataFiles = objWMIService.ExecQuery("Select Antecedent,Dependent From Win32_CIMLogicalDeviceCIMDataFile Where Antecedent='" & Replace(strPrefix, "\", "\\", 1, -1, 1) & "=" & Chr(34) & Chr(34) & Replace(objSCSIController.PnpDeviceId, "\", "\\\\", 1, -1, 1) & Chr(34) & Chr(34) & "'")
					Set colCIMLogicalDeviceCIMDataFiles = objWMIService.ExecQuery("Select * From Win32_CIMLogicalDeviceCIMDataFile")
					If colCIMLogicalDeviceCIMDataFiles.Count Then
						For Each objCIMLogicalDeviceCIMDataFiles in colCIMLogicalDeviceCIMDataFiles
							If InStr(1,objCIMLogicalDeviceCIMDataFiles.Antecedent,Replace(objSCSIController.PNPDeviceId, "\", "\\", 1, -1, 1),1) Then
								arrTempArray = Split(objCIMLogicalDeviceCIMDataFiles.Dependent, "=")
								strPrefix = Replace(arrTempArray(1), Chr(34), "", 1, -1, 1)
								Set colCIMDataFiles = objWMIService.ExecQuery("Select * From CIM_DataFile Where Name='" & strPrefix & "'")
								For Each objCIMDataFile in colCIMDataFiles
									strDriver = Pad("STORAGE (SCSI)", 15, PADRIGHT) & Pad(UCase(objCIMDataFile.FileName & "." & objCIMDataFile.Extension), 18, PADRIGHT) & " " & Pad(Trim(objCIMDataFile.Manufacturer), 29, PADRIGHT) & Pad(GetBranch(objCIMDataFile.Version, True), 20, PADRIGHT) & Pad(WMIDateStringToDate(objCIMDataFile.LastModified), 14, PADRIGHT) & Pad(FormatNumber(Round(objCIMDataFile.FileSize/1024), 0, , vbTrue), 6, PADLEFT) & " KB " & Pad("(" & FormatNumber(objCIMDataFile.FileSize, 0, , vbTrue), 11, PADLEFT) & " bytes) " & RemoveChaff(objSCSIController.Name)
									If Not dctDrivers.Exists(strDriver) Then
										dctDrivers.Add strDriver, "SCSI"
									End If
'									Wscript.Echo "objCIMLogicalDeviceCIMDataFiles.Dependent = " & objCIMLogicalDeviceCIMDataFiles.Dependent
'									Wscript.Echo "objCIMLogicalDeviceCIMDataFiles.Antecedent = " & objCIMLogicalDeviceCIMDataFiles.Antecedent
'									Wscript.Echo "objCIMLogicalDeviceCIMDataFiles.Purpose = " & objCIMLogicalDeviceCIMDataFiles.Purpose
'									Wscript.Echo "objCIMLogicalDeviceCIMDataFiles.PurposeDescription = " & objCIMLogicalDeviceCIMDataFiles.PurposeDescription
								Next
							End If
						Next
					Else
						Wscript.Echo "colCIMLogicalDeviceCIMDataFiles.Count = " & colCIMLogicalDeviceCIMDataFiles.Count
					End If
				End If
			'Next
		Next
	Else
		'Wscript.Echo "colSCSIControllers.Count = " & colSCSIControllers.Count
		'AddOutput Pad("SCSI", SUMMARY_STRING_LENGTH, PADRIGHT) & "N/A"
	End If

	Set colIDEControllers = objWMIService.ExecQuery("Select Name,PNPDeviceId From Win32_IDEController")
	If colIDEControllers.Count Then
		For Each objIDEController in colIDEControllers
			If dctPnPAllocatedResources.Exists(objIDEController.PNPDeviceID) Then
				Set colCIMLogicalDeviceCIMDataFiles = objWMIService.ExecQuery("Select * From Win32_CIMLogicalDeviceCIMDataFile")
				If colCIMLogicalDeviceCIMDataFiles.Count Then
					For Each objCIMLogicalDeviceCIMDataFiles in colCIMLogicalDeviceCIMDataFiles
						If InStr(1,objCIMLogicalDeviceCIMDataFiles.Antecedent,Replace(objIDEController.PNPDeviceId, "\", "\\", 1, -1, 1),1) Then
							arrTempArray = Split(objCIMLogicalDeviceCIMDataFiles.Dependent, "=")
							strPrefix = Replace(arrTempArray(1), Chr(34), "", 1, -1, 1)
							Set colCIMDataFiles = objWMIService.ExecQuery("Select * From CIM_DataFile Where Name='" & strPrefix & "'")
							For Each objCIMDataFile in colCIMDataFiles
								If objCIMDataFile.FileName <> "pciide" Then
									strDriver = Pad("STORAGE (IDE)", 15, PADRIGHT) & Pad(UCase(objCIMDataFile.FileName & "." & objCIMDataFile.Extension), 18, PADRIGHT) & " " & Pad(Trim(objCIMDataFile.Manufacturer), 29, PADRIGHT) & Pad(GetBranch(objCIMDataFile.Version, True), 20, PADRIGHT) & Pad(WMIDateStringToDate(objCIMDataFile.LastModified), 14, PADRIGHT) & Pad(FormatNumber(Round(objCIMDataFile.FileSize/1024), 0, , vbTrue), 6, PADLEFT) & " KB " & Pad("(" & FormatNumber(objCIMDataFile.FileSize, 0, , vbTrue), 11, PADLEFT) & " bytes) " & RemoveChaff(objIDEController.Name)
									If Not dctDrivers.Exists(strDriver) Then
										dctDrivers.Add strDriver, "IDE"
									End If
	'								Wscript.Echo "objCIMLogicalDeviceCIMDataFiles.Dependent = " & objCIMLogicalDeviceCIMDataFiles.Dependent
	'								Wscript.Echo "objCIMLogicalDeviceCIMDataFiles.Antecedent = " & objCIMLogicalDeviceCIMDataFiles.Antecedent
	'								Wscript.Echo "objCIMLogicalDeviceCIMDataFiles.Purpose = " & objCIMLogicalDeviceCIMDataFiles.Purpose
	'								Wscript.Echo "objCIMLogicalDeviceCIMDataFiles.PurposeDescription = " & objCIMLogicalDeviceCIMDataFiles.PurposeDescription
								End If
							Next
						End If
					Next
				Else
					Wscript.Echo "colCIMLogicalDeviceCIMDataFiles.Count = " & colCIMLogicalDeviceCIMDataFiles.Count
				End If
			End If
		Next
	Else
		'Wscript.Echo "colIDEControllers.Count = " & colIDEControllers.Count
		'AddOutput Pad("IDE", SUMMARY_STRING_LENGTH, PADRIGHT) & "N/A"
	End If

	Dim colNetworkAdapters
	Dim objNetworkAdapter

	Set colNetworkAdapters = objWMIService.ExecQuery("Select Name,PNPDeviceId From Win32_NetworkAdapter")
	If colNetworkAdapters.Count Then
		For Each objNetworkAdapter in colNetworkAdapters
			If dctPnPAllocatedResources.Exists(objNetworkAdapter.PNPDeviceID) Then
				Set colCIMLogicalDeviceCIMDataFiles = objWMIService.ExecQuery("Select * From Win32_CIMLogicalDeviceCIMDataFile")
				If colCIMLogicalDeviceCIMDataFiles.Count Then
					For Each objCIMLogicalDeviceCIMDataFiles in colCIMLogicalDeviceCIMDataFiles
						If InStr(1,objCIMLogicalDeviceCIMDataFiles.Antecedent,Replace(objNetworkAdapter.PNPDeviceId, "\", "\\", 1, -1, 1),1) Then
							arrTempArray = Split(objCIMLogicalDeviceCIMDataFiles.Dependent, "=")
							strPrefix = Replace(arrTempArray(1), Chr(34), "", 1, -1, 1)
							Set colCIMDataFiles = objWMIService.ExecQuery("Select * From CIM_DataFile Where Name='" & strPrefix & "'")
							For Each objCIMDataFile in colCIMDataFiles
								strDriver = Pad("NETWORK", 15, PADRIGHT) & Pad(UCase(objCIMDataFile.FileName & "." & objCIMDataFile.Extension), 18, PADRIGHT) & " " & Pad(Trim(objCIMDataFile.Manufacturer), 29, PADRIGHT) & Pad(GetBranch(objCIMDataFile.Version, True), 20, PADRIGHT) & Pad(WMIDateStringToDate(objCIMDataFile.LastModified), 14, PADRIGHT) & Pad(FormatNumber(Round(objCIMDataFile.FileSize/1024), 0, , vbTrue), 6, PADLEFT) & " KB " & Pad("(" & FormatNumber(objCIMDataFile.FileSize, 0, , vbTrue), 11, PADLEFT) & " bytes) " & RemoveChaff(objNetworkAdapter.Name)
								If Not dctDrivers.Exists(strDriver) Then
									dctDrivers.Add strDriver, "NETWORK"
								End If
							Next
						End If
					Next
				Else
					Wscript.Echo "colCIMLogicalDeviceCIMDataFiles.Count = " & colCIMLogicalDeviceCIMDataFiles.Count
				End If
			End If
		Next
	Else
		'Wscript.Echo "colNetworkAdapters.Count = " & colNetworkAdapters.Count
		'AddOutput Pad("NETWORK", SUMMARY_STRING_LENGTH, PADRIGHT) & "N/A"
	End If

	Dim colVideoControllers
	Dim objVideoController

	Set colVideoControllers = objWMIService.ExecQuery("Select Name,PNPDeviceId From Win32_VideoController")
	If colVideoControllers.Count Then
		For Each objVideoController in colVideoControllers
			If dctPnPAllocatedResources.Exists(objVideoController.PNPDeviceID) Then
				Set colCIMLogicalDeviceCIMDataFiles = objWMIService.ExecQuery("Select * From Win32_CIMLogicalDeviceCIMDataFile")
				If colCIMLogicalDeviceCIMDataFiles.Count Then
					For Each objCIMLogicalDeviceCIMDataFiles in colCIMLogicalDeviceCIMDataFiles
						If InStr(1,objCIMLogicalDeviceCIMDataFiles.Antecedent,Replace(objVideoController.PNPDeviceId, "\", "\\", 1, -1, 1),1) Then
							arrTempArray = Split(objCIMLogicalDeviceCIMDataFiles.Dependent, "=")
							strPrefix = Replace(arrTempArray(1), Chr(34), "", 1, -1, 1)
							Set colCIMDataFiles = objWMIService.ExecQuery("Select * From CIM_DataFile Where Name='" & strPrefix & "'")
							For Each objCIMDataFile in colCIMDataFiles
								strDriver = Pad("VIDEO", 15, PADRIGHT) & Pad(UCase(objCIMDataFile.FileName & "." & objCIMDataFile.Extension), 18, PADRIGHT) & " " & Pad(Trim(objCIMDataFile.Manufacturer), 29, PADRIGHT) & Pad(GetBranch(objCIMDataFile.Version, True), 20, PADRIGHT) & Pad(WMIDateStringToDate(objCIMDataFile.LastModified), 14, PADRIGHT) & Pad(FormatNumber(Round(objCIMDataFile.FileSize/1024), 0, , vbTrue), 6, PADLEFT) & " KB " & Pad("(" & FormatNumber(objCIMDataFile.FileSize, 0, , vbTrue), 11, PADLEFT) & " bytes) " & RemoveChaff(objVideoController.Name)
								If Not dctDrivers.Exists(strDriver) Then
									dctDrivers.Add strDriver, "VIDEO"
								End If
							Next
						End If
					Next
				Else
					Wscript.Echo "colCIMLogicalDeviceCIMDataFiles.Count = " & colCIMLogicalDeviceCIMDataFiles.Count
				End If
			End If
		Next
	Else
		'Wscript.Echo "colVideoControllers.Count = " & colVideoControllers.Count
		'AddOutput Pad("VIDEO", SUMMARY_STRING_LENGTH, PADRIGHT) & "N/A"
	End If

	Dim colSoundDevices
	Dim objSoundDevice

	Set colSoundDevices = objWMIService.ExecQuery("Select Name,PNPDeviceId From Win32_SoundDevice")
	If colSoundDevices.Count Then
		For Each objSoundDevice in colSoundDevices
			' On Win7 (and probably Vista and later), sound devices may not be using physical resources, so we can't use that to determine sound cards that are "in use" versus ones that may be ghosted devices.
			' May need to revisit this if some machines return lots of ghosted sound cards.
			' Msinfo32 does not just show the default audio device anyway. For example one Win7 machine had a AMD HD audio (from a Radeon card) and two HD sound devices - all showing up in Msinfo32.
			'If dctPnPAllocatedResources.Exists(objSoundDevice.PNPDeviceID) Then
				Set colCIMLogicalDeviceCIMDataFiles = objWMIService.ExecQuery("Select * From Win32_CIMLogicalDeviceCIMDataFile")
				If colCIMLogicalDeviceCIMDataFiles.Count Then
					For Each objCIMLogicalDeviceCIMDataFiles in colCIMLogicalDeviceCIMDataFiles
						If InStr(1,objCIMLogicalDeviceCIMDataFiles.Antecedent,Replace(objSoundDevice.PNPDeviceId, "\", "\\", 1, -1, 1),1) Then
							arrTempArray = Split(objCIMLogicalDeviceCIMDataFiles.Dependent, "=")
							strPrefix = Replace(arrTempArray(1), Chr(34), "", 1, -1, 1)
							Set colCIMDataFiles = objWMIService.ExecQuery("Select * From CIM_DataFile Where Name='" & strPrefix & "'")
							For Each objCIMDataFile in colCIMDataFiles
								strDriver = Pad("AUDIO", 15, PADRIGHT) & Pad(UCase(objCIMDataFile.FileName & "." & objCIMDataFile.Extension), 18, PADRIGHT) & " " & Pad(Trim(objCIMDataFile.Manufacturer), 29, PADRIGHT) & Pad(GetBranch(objCIMDataFile.Version, True), 20, PADRIGHT) & Pad(WMIDateStringToDate(objCIMDataFile.LastModified), 14, PADRIGHT) & Pad(FormatNumber(Round(objCIMDataFile.FileSize/1024), 0, , vbTrue), 6, PADLEFT) & " KB " & Pad("(" & FormatNumber(objCIMDataFile.FileSize, 0, , vbTrue), 11, PADLEFT) & " bytes) " & RemoveChaff(objSoundDevice.Name)
								If Not dctDrivers.Exists(strDriver) Then
									dctDrivers.Add strDriver, "AUDIO"
								End If
							Next
						End If
					Next
				Else
					Wscript.Echo "colCIMLogicalDeviceCIMDataFiles.Count = " & colCIMLogicalDeviceCIMDataFiles.Count
				End If
			'End If
		Next
	Else
		'Wscript.Echo "colSoundDevices.Count = " & colSoundDevices.Count
		'AddOutput Pad("AUDIO", SUMMARY_STRING_LENGTH, PADRIGHT) & "N/A"
	End If

	Dim objDriver

	For Each objDriver In dctDrivers
		AddOutput objDriver
	Next

	Print "GetImportantDrivers()", TASK, intLocation

End Function

Function Get12HourTime(dtmString)

	If blnErrorHandling Then On Error Resume Next

	intHours = DatePart("h", dtmString)
	intMinutes = DatePart("n", dtmString)
	If intHours >= 12 Then
		strAMPM = "PM"
	Else
		strAMPM = "AM"
	End If
	intHours = intHours Mod 12
	If intHours = 0 Then
		intHours = 12
	End If
	If intMinutes < 10 Then
		intMinutes = Right("00" & intMinutes, 2)
	End If
	Get12HourTime = Pad(intHours, 2, PADLEFT) & ":" & intMinutes & " " & strAMPM

End Function

Function FormatUptime(intMinutes)

	If blnErrorHandling Then On Error Resume Next

	If intMinutes >= MINUTES_IN_DAY Then
		intDays = intMinutes / MINUTES_IN_DAY
		intHours = (intMinutes MOD MINUTES_IN_DAY) / MINUTES_IN_HOUR
		intMinutes = (intMinutes MOD MINUTES_IN_DAY) MOD MINUTES_IN_HOUR
		FormatUptime = Int(intDays) & " days " & Int(intHours) & " hours " & intMinutes & " minutes"
    ElseIf intMinutes >= MINUTES_IN_HOUR Then
		intHours = intMinutes / MINUTES_IN_HOUR
		intMinutes = intMinutes MOD MINUTES_IN_HOUR
		FormatUptime = Int(intHours) & " hours " & intMinutes & " minutes"
    Else
        FormatUptime = intMinutes & " minutes"
	End If

End Function

Function GetReboots()

	If blnErrorHandling Then On Error Resume Next

	Print "GetReboots()", TASK, intLocation

	Dim blnEventsFromCSV
	Dim objEvent
	Dim colEvents

	blnEventsFromCSV = False

	Heading("LAST " & NUM_LAST_REBOOTS & " RESTARTS (6005 after 6006 = CLEAN, 6005 after 6008 = DIRTY, 6005 after 41 = DIRTY)")

	AddOutput Pad("Type", 11, PADRIGHT) & Pad("Date/Time", 27, PADRIGHT) & Pad("ID", 7, PADRIGHT) & Pad("Source", 11, PADRIGHT) & "Description"
	AddOutput String(HEADING_WIDTH, "-")

	If Not blnEventsFromCSV Then

		i = 0
		Dim strEvent
		Dim bln6005
		Dim str6005
		Dim strMessage
		bln6005 = False
		Set colEvents = objWMIService.ExecQuery("Select TimeGenerated,LogFile,EventCode,SourceName,Message From Win32_NTLogEvent Where Logfile='System' And (SourceName='EventLog' Or SourceName='Save Dump' Or SourceName='Microsoft-Windows-WER-SystemErrorReporting' Or SourceName='Microsoft-Windows-Kernel-Power') And (EventCode='6005' Or EventCode='6008' Or EventCode='6006' Or EventCode='1001' Or EventCode='41')", , wbemFlagReturnImmediately + wbemFlagForwardOnly)

		For Each objEvent in colEvents

			' Removes the carriage return (ASCII 13) and line feed (ASCII 10) that XP/2003 include in some event messages.
			strMessage = Replace(Replace(objEvent.Message, Chr(13) & Chr(10), " ", 1, -1, 1), "  ", " ", 1, -1, 1)

			If objEvent.EventCode = 6005 Then
				bln6005 = True
				str6005 = Pad(Left(WeekDayName(WeekDay(WMIDateStringToDate3(objEvent.TimeGenerated))), 3), 4, PADRIGHT) & Left(MonthName(Month(WMIDateStringToDate3(objEvent.TimeGenerated))), 3) & " " & Pad(CStr(DatePart("d", WMIDateStringToDate3(objEvent.TimeGenerated))), 2, PADZERO) & " " & DatePart("yyyy", WMIDateStringToDate3(objEvent.TimeGenerated)) & " " & Pad(Get12HourTime(WMIDateStringToDate3(objEvent.TimeGenerated)), 11, PADRIGHT) & Pad(objEvent.EventCode, 7, PADRIGHT) & Pad(objEvent.SourceName, 11, PADRIGHT) & strMessage
			ElseIf objEvent.EventCode = 6006 Then
				If bln6005 Then
					AddOutput Pad("CLEAN", 11, PADRIGHT) & str6005
					bln6005 = False
					i = i + 1
				End If
				AddOutput Pad("     ", 11, PADRIGHT) & Pad(Left(WeekDayName(WeekDay(WMIDateStringToDate3(objEvent.TimeGenerated))), 3), 4, PADRIGHT) & Left(MonthName(Month(WMIDateStringToDate3(objEvent.TimeGenerated))), 3) & " " & Pad(CStr(DatePart("d", WMIDateStringToDate3(objEvent.TimeGenerated))), 2, PADZERO) & " " & DatePart("yyyy", WMIDateStringToDate3(objEvent.TimeGenerated)) & " " & Pad(Get12HourTime(WMIDateStringToDate3(objEvent.TimeGenerated)), 11, PADRIGHT) & Pad(objEvent.EventCode, 7, PADRIGHT) & Pad(objEvent.SourceName, 11, PADRIGHT) & strMessage
			ElseIf objEvent.EventCode = 6008 Then
				If bln6005 Then
					AddOutput Pad("DIRTY", 11, PADRIGHT) & str6005
					bln6005 = False
					i = i + 1
				End If
				AddOutput Pad("     ", 11, PADRIGHT) & Pad(Left(WeekDayName(WeekDay(WMIDateStringToDate3(objEvent.TimeGenerated))), 3), 4, PADRIGHT) & Left(MonthName(Month(WMIDateStringToDate3(objEvent.TimeGenerated))), 3) & " " & Pad(CStr(DatePart("d", WMIDateStringToDate3(objEvent.TimeGenerated))), 2, PADZERO) & " " & DatePart("yyyy", WMIDateStringToDate3(objEvent.TimeGenerated)) & " " & Pad(Get12HourTime(WMIDateStringToDate3(objEvent.TimeGenerated)), 11, PADRIGHT) & Pad(objEvent.EventCode, 7, PADRIGHT) & Pad(objEvent.SourceName, 11, PADRIGHT) & strMessage
			ElseIf objEvent.EventCode = 41 Then
				If bln6005 Then
					AddOutput Pad("DIRTY", 11, PADRIGHT) & str6005
					bln6005 = False
					i = i + 1
				End If
				AddOutput Pad("     ", 11, PADRIGHT) & Pad(Left(WeekDayName(WeekDay(WMIDateStringToDate3(objEvent.TimeGenerated))), 3), 4, PADRIGHT) & Left(MonthName(Month(WMIDateStringToDate3(objEvent.TimeGenerated))), 3) & " " & Pad(CStr(DatePart("d", WMIDateStringToDate3(objEvent.TimeGenerated))), 2, PADZERO) & " " & DatePart("yyyy", WMIDateStringToDate3(objEvent.TimeGenerated)) & " " & Pad(Get12HourTime(WMIDateStringToDate3(objEvent.TimeGenerated)), 11, PADRIGHT) & Pad(objEvent.EventCode, 7, PADRIGHT) & Pad(objEvent.SourceName, 11, PADRIGHT) & strMessage
			ElseIf objEvent.EventCode = 1001 Then
				AddOutput Pad("BUGCHECK", 11, PADRIGHT) & Pad(Left(WeekDayName(WeekDay(WMIDateStringToDate3(objEvent.TimeGenerated))), 3), 4, PADRIGHT) & Left(MonthName(Month(WMIDateStringToDate3(objEvent.TimeGenerated))), 3) & " " & Pad(CStr(DatePart("d", WMIDateStringToDate3(objEvent.TimeGenerated))), 2, PADZERO) & " " & DatePart("yyyy", WMIDateStringToDate3(objEvent.TimeGenerated)) & " " & Pad(Get12HourTime(WMIDateStringToDate3(objEvent.TimeGenerated)), 11, PADRIGHT) & Pad(objEvent.EventCode, 7, PADRIGHT) & Pad("BugCheck", 11, PADRIGHT) & strMessage
			End If

			AddOutput strEvent

			If i = NUM_LAST_REBOOTS Then
				Exit For
			End If

		Next

	Else

		Dim arrLineParts
		Dim strLine
		Dim strFileName
		strFileName = ""

		If objFSO.FileExists(strFileName) Then
			Set objOutputTxt = objFSO.OpenTextFile(strFileName, ForReading)
			i = 0
			Do While objOutputTxt.AtEndOfStream <> True
				strLine = objOutputTxt.Readline

				' Maybe compute the time BETWEEN reboots also?

				If (inStr(strLine, "6005") Or inStr(strLine, "6008")) And inStr(strLine, "EventLog") Then
					'If inStr(strLine, "Date,Time,Type/Level,Computer Name,Event Code,Source,Task Category,Username,Description") = 0 Then
					'Date,Time,Type/Level,Computer Name,Event Code,Source,Task Category,Username,Description
					' 0    1    2          3             4          5      6             7        8
					arrLineParts = Split(strLine, ",")
					strLine = Replace(strLine, ",", " ", 1, -1, 1)

					If inStr(strLine, "6005") Then
						AddOutput Pad("CLEAN", 8, PADRIGHT) & Pad(WeekDayName(WeekDay(arrLineParts(0))), 11, PADRIGHT) & Pad(arrLineParts(0), 12, PADRIGHT) & Pad(arrLineParts(1), 13, PADRIGHT) & Pad(arrLineParts(4), 6, PADRIGHT) & Pad(arrLineParts(5), 11, PADRIGHT) & arrLineParts(8)
					ElseIf inStr(strLine, "6008") Then
						AddOutput "DIRTY  " & Pad(WeekDayName(WeekDay(arrLineParts(0))), 9, PADRIGHT) & " " & arrLineParts(0) & " " & arrLineParts(1) & " " & arrLineParts(4) & " " & arrLineParts(5) & " " & arrLineParts(8)
					End If
					i = i + 1
					If i = NUM_LAST_REBOOTS Then
						Exit Do
					End If
				Else
					objOutputTxt.Skipline
				End If
			Loop
			objOutputTxt.Close
			Set objOutputTxt = Nothing
		Else
			AddOutput "File not found: " & strFileName
		End If
	End If

	Print "GetReboots()", TASK, intLocation

End Function

Function GetBootInfo()

	If blnErrorHandling Then On Error Resume Next

	Print "GetBootInfo()", TASK, intLocation

		If strBuildNumber = "3790" or strBuildNumber = "2600" Then

			If strBitness = "x86" Then

				If FormatNumber(intMaxProcessMemorySize/MB) > 2 And FormatNumber(intMaxProcessMemorySize/MB) <= 3 Then

					Heading("BOOT INFORMATION - BOOT.INI" & String(4, " ") & "*** /3GB IS in effect. *** MaxProcessMemorySize = " & FormatNumber(intMaxProcessMemorySize, 0, , vbTrue) & " bytes (" & FormatNumber(intMaxProcessMemorySize/MB, 2) & " GB)")

				ElseIf FormatNumber(intMaxProcessMemorySize/MB) = 2 Then

					Heading("BOOT INFORMATION - BOOT.INI" & String(4, " ") & "/3GB is NOT in effect. MaxProcessMemorySize = " & FormatNumber(intMaxProcessMemorySize, 0, , vbTrue) & " bytes (" & FormatNumber(intMaxProcessMemorySize/MB, 2) & " GB)")

				End If

			Else

				Heading("BOOT INFORMATION - BOOT.INI" & String(4, " ") & "MaxProcessMemorySize = " & FormatNumber(intMaxProcessMemorySize, 0, , vbTrue) & " bytes (" & FormatNumber(intMaxProcessMemorySize/MB, 2) & " GB)")

			End If

			strBootINIPath = strSystemDrive & "\BOOT.INI"
			If objFSO.FileExists(strBootINIPath) Then
				Set objBootINI = objFSO.OpenTextFile(strBootINIPath, ForReading)
				Do Until objBootINI.AtEndOfStream
					AddOutput objBootINI.Readline
				Loop
			End If
		Else
			Dim objExec
			Dim strStdErr, strStdOut, objStdOut, strBCDEDIT
			Dim strWindir
			strWindir = objShell.ExpandEnvironmentStrings("%WINDIR%")

			If (blnSetupSDPManifest) Then
				Heading("BOOT INFORMATION - " & Chr(34) & "bcdedit.exe /enum all" & Chr(34) & " output")
				strBCDEDIT = strWindir & "\System32\Bcdedit.exe /enum all"
			Else
				Heading("BOOT INFORMATION - " & Chr(34) & "bcdedit.exe /enum" & Chr(34) & " output")
				strBCDEDIT = strWindir & "\System32\Bcdedit.exe /enum"
			End If

		        Set objExec = objShell.Exec(strBCDEDIT)
			Do While objExec.Status = 0
				strStdOut = objExec.StdOut.ReadAll
				strStdErr = objExec.StdErr.ReadAll
				WScript.Sleep 10
			Loop

			If strStdErr <> "" Then
				AddOutput Trim(strStdErr)
			Else
				AddOutput Trim(strStdOut)
        	End if
	End If

	Print "GetBootInfo()", TASK, intLocation

End Function

Function GetDrives()

	If blnErrorHandling Then On Error Resume Next

	Print "GetDrives()", TASK, intLocation

	Dim colDrives
	Dim objDrive
	Dim strDriveType
	Dim strPageFile
	Set colDrives = objWMIService.ExecQuery("Select Name, FileSystem, MediaType, Drivetype, FreeSpace, Size, VolumeName, VolumeSerialNumber  From Win32_LogicalDisk Where DriveType='3'", , wbemFlagReturnImmediately + wbemFlagForwardOnly)

	Heading("LOGICAL DRIVES")

	AddOutput Pad("Drive", 7, PADRIGHT) & Pad("Total Size", 12, PADLEFT) & Pad("Free Space", 12, PADLEFT) & "  " & "File System" & " " & "Page File"
	AddOutput String(HEADING_WIDTH, "-")

	For Each objDrive in colDrives
		strPageFile = ""
		For i = 0 to UBound(arrPageFiles)
			If InStr(arrPageFiles(i),objDrive.Name) Then
				strPageFile = arrPageFiles(i)
			End If
		Next
		AddOutput Pad(objDrive.Name, 7, PADRIGHT) & Pad(ConvertBytes(objDrive.Size, "GB"), 12, PADLEFT) & Pad(ConvertBytes(objDrive.FreeSpace, "GB"), 12, PADLEFT) & "  " & Pad(objDrive.FileSystem, 12, PADRIGHT) & strPageFile
	Next

	Print "GetDrives()", TASK, intLocation

End Function

Function GetVarInfo(varname)

	' Error handling should always be on in this function because IsObject will throw an error if a variable is not an object.

	On Error Resume Next

    Wscript.Echo ""
    Wscript.Echo "VarType   = " & VarType(varname)
    Wscript.Echo "TypeName  = " & TypeName(varname)
    Wscript.Echo "IsArray   = " & IsArray(varname)
    Wscript.Echo "IsDate    = " & IsDate(varname)
    Wscript.Echo "IsEmpty   = " & IsEmpty(varname)
    Wscript.Echo "IsNull    = " & IsNull(varname)
    Wscript.Echo "IsNumeric = " & IsNumeric(varname)
    Wscript.Echo "IsObject  = " & IsObject(varname)
    GetVarInfo = "Count     = " & varname.count
    Wscript.Echo ""

	On Error Goto 0

End Function

Function GetRunningDrivers()

	If blnErrorHandling Then On Error Resume Next

	Print "GetRunningDrivers()", TASK, intLocation

	Dim blnUseFSO
	blnUseFSO = False

	Set colSystemDrivers = objWMIService.ExecQuery("Select State,PathName From Win32_SystemDriver Where State='Running'", , wbemFlagReturnImmediately + wbemFlagForwardOnly)

	Dim rsRunningDrivers
	Set rsRunningDrivers = CreateObject("ADODB.Recordset")

	rsRunningDrivers.Fields.Append "FileName", adVarChar, 255, adFldMayBeNull
	rsRunningDrivers.Fields.Append "FileSize", adDouble
	rsRunningDrivers.Fields.Append "LastModified", adVarChar, 255, adFldMayBeNull
	rsRunningDrivers.Fields.Append "Manufacturer", adVarChar, 255, adFldMayBeNull
	rsRunningDrivers.Fields.Append "Version", adVarChar, 255, adFldMayBeNull
	rsRunningDrivers.Fields.Append "Branch", adVarChar, 255, adFldMayBeNull

	rsRunningDrivers.Open

	If Not rsRunningDrivers.BOF Then rsRunningDrivers.MoveFirst

	For Each objDriver in colSystemDrivers
		If Not IsNull(objDriver.PathName) Then
			If blnUseFSO Then
				Set objFSOFile = objFSO.GetFile(objDriver.PathName)
				AddOutput Pad(UCase(objFSOFile.Name), 30, PADRIGHT) & Pad(objFSO.GetFileVersion(Replace(objDriver.PathName, "\??\", "", 1, -1, 1)), 30, PADRIGHT) & Pad(objFSOFile.DateLastModified, 30, PADRIGHT)
			Else
				'Set colDriverFiles = objWMIService.ExecQuery("Select Extension,FileName,FileSize,LastModified,Manufacturer,Version From CIM_DataFile Where Not Manufacturer Like '%Microsoft%' And Name='" & Replace(Replace(objDriver.PathName, "\??\", "", 1, -1, 1), "\", "\\", 1, -1, 1) & "'")
				Set colDriverFiles = objWMIService.ExecQuery("Select Extension,FileName,FileSize,LastModified,Manufacturer,Version From CIM_DataFile Where Name='" & Replace(Replace(objDriver.PathName, "\??\", "", 1, -1, 1), "\", "\\", 1, -1, 1) & "'")
				For Each objDriverFile in colDriverFiles

					rsRunningDrivers.AddNew
					'rsRunningDrivers("FileName").Value = UCase(objDriverFile.FileName & "." & objDriverFile.Extension)
					rsRunningDrivers("FileName").Value = UCase(Left(objDriverFile.FileName & "." & objDriverFile.Extension, 1)) & Mid(LCase(objDriverFile.FileName & "." & objDriverFile.Extension), 2)
					rsRunningDrivers("FileSize").Value = objDriverFile.FileSize
					rsRunningDrivers("Manufacturer").Value = objDriverFile.Manufacturer
					rsRunningDrivers("LastModified").Value = WMIDateStringToDate(objDriverFile.LastModified)
					rsRunningDrivers("Version").Value = GetBranch(objDriverFile.Version, True)
					rsRunningDrivers("Branch").Value = GetBranch(objDriverFile.Version, False)
					rsRunningDrivers.Update

					'AddOutput Pad(Left(UCase(objDriverFile.FileName & "." & objDriverFile.Extension), 28), 30, PADRIGHT) & Pad(Left(objDriverFile.Manufacturer, 28), 30, PADRIGHT) & Pad(Left(objDriverFile.Version, 18), 20, PADRIGHT) & Pad(WMIDateStringToDate(objDriverFile.LastModified), 10, PADRIGHT) & Pad(FormatNumber(Round(objDriverFile.FileSize/1024), 0, , vbTrue), 8, PADLEFT) & " KB" & Pad("(" & FormatNumber(objDriverFile.FileSize, 0, , vbTrue) & " bytes)", 20, PADLEFT)
				Next
				Set colDriverFiles = Nothing
			End If
		End If
	Next

	rsRunningDrivers.Sort = "FileName ASC"
	rsRunningDrivers.MoveFirst

	Heading("3RD-PARTY RUNNING DRIVERS")
	AddOutput Pad("File Name", 30, PADRIGHT) & Pad("Manufacturer", 30, PADRIGHT) & Pad("Version", 20, PADRIGHT) & Pad("Date", 10, PADRIGHT) & Pad("Size", 11, PADLEFT)
	AddOutput String(HEADING_WIDTH, "-")

	'rsRunningDrivers.Filter = " Manufacturer !LIKE *Microsoft* "

	Do Until rsRunningDrivers.EOF
		If Instr(UCase(rsRunningDrivers.Fields.Item("Manufacturer")), "MICROSOFT") = 0 Then
			AddOutput Pad(Left(rsRunningDrivers.Fields.Item("FileName"), 28), 30, PADRIGHT) & Pad(Left(rsRunningDrivers.Fields.Item("Manufacturer"), 28), 30, PADRIGHT) & Pad(Left(rsRunningDrivers.Fields.Item("Version"), 18), 20, PADRIGHT) & Pad(rsRunningDrivers.Fields.Item("LastModified"), 10, PADRIGHT) & Pad(FormatNumber(Round(rsRunningDrivers.Fields.Item("FileSize")/1024), 0, , vbTrue), 8, PADLEFT) & " KB" & Pad("(" & FormatNumber(rsRunningDrivers.Fields.Item("FileSize"), 0, , vbTrue) & " bytes)", 20, PADLEFT)
			'AddOutput String(4, " ") & Pad(rsRunningDrivers.Fields.Item("Value"), intValueLength + 2, PADRIGHT) & Pad(rsRunningDrivers.Fields.Item("Type"), 15, PADRIGHT) & rsRunningDrivers.Fields.Item("Data")

		End IF
		rsRunningDrivers.MoveNext
	Loop

	Heading("MICROSOFT RUNNING DRIVERS")
	AddOutput Pad("Branch", 8, PADRIGHT) & Pad("File Name", 30, PADRIGHT) & Pad("Manufacturer", 30, PADRIGHT) & Pad("Version", 20, PADRIGHT) & Pad("Date", 10, PADRIGHT) & Pad("Size", 11, PADLEFT)
	AddOutput String(HEADING_WIDTH, "-")

	rsRunningDrivers.MoveFirst

	Do Until rsRunningDrivers.EOF
		If Instr(UCase(rsRunningDrivers.Fields.Item("Manufacturer")), "MICROSOFT") Then
			If Instr(rsRunningDrivers.Fields.Item("Branch"), "LDR") Then
				AddOutput Pad(rsRunningDrivers.Fields.Item("Branch"), 6, PADRIGHT) & "  " & Pad(Left(rsRunningDrivers.Fields.Item("FileName"), 28), 30, PADRIGHT) & Pad(Left(rsRunningDrivers.Fields.Item("Manufacturer"), 28), 30, PADRIGHT) & Pad(Left(rsRunningDrivers.Fields.Item("Version"), 18), 20, PADRIGHT) & Pad(rsRunningDrivers.Fields.Item("LastModified"), 10, PADRIGHT) & Pad(FormatNumber(Round(rsRunningDrivers.Fields.Item("FileSize")/1024), 0, , vbTrue), 8, PADLEFT) & " KB" & Pad("(" & FormatNumber(rsRunningDrivers.Fields.Item("FileSize"), 0, , vbTrue) & " bytes)", 20, PADLEFT)
			Else
				AddOutput Pad(rsRunningDrivers.Fields.Item("Branch"), 6, PADLEFT) & "  " & Pad(Left(rsRunningDrivers.Fields.Item("FileName"), 28), 30, PADRIGHT) & Pad(Left(rsRunningDrivers.Fields.Item("Manufacturer"), 28), 30, PADRIGHT) & Pad(Left(rsRunningDrivers.Fields.Item("Version"), 18), 20, PADRIGHT) & Pad(rsRunningDrivers.Fields.Item("LastModified"), 10, PADRIGHT) & Pad(FormatNumber(Round(rsRunningDrivers.Fields.Item("FileSize")/1024), 0, , vbTrue), 8, PADLEFT) & " KB" & Pad("(" & FormatNumber(rsRunningDrivers.Fields.Item("FileSize"), 0, , vbTrue) & " bytes)", 20, PADLEFT)
			End If
			'AddOutput String(4, " ") & Pad(rsRunningDrivers.Fields.Item("Value"), intValueLength + 2, PADRIGHT) & Pad(rsRunningDrivers.Fields.Item("Type"), 15, PADRIGHT) & rsRunningDrivers.Fields.Item("Data")
		End IF
		rsRunningDrivers.MoveNext
	Loop

	REM Exit Function

	REM For Each objDriver in colSystemDrivers
		REM If Not IsNull(objDriver.PathName) Then
			REM If blnUseFSO Then
				REM Set objFSOFile = objFSO.GetFile(objDriver.PathName)
				REM AddOutput Pad(UCase(objFSOFile.Name), 30, PADRIGHT) & Pad(objFSO.GetFileVersion(Replace(objDriver.PathName, "\??\", "", 1, -1, 1)), 30, PADRIGHT) & Pad(objFSOFile.DateLastModified, 30, PADRIGHT)
			REM Else
				REM Set colDriverFiles = objWMIService.ExecQuery("Select Extension,FileName,FileSize,LastModified,Manufacturer,Version From CIM_DataFile Where Manufacturer Like '%Microsoft%' And Name='" & Replace(Replace(objDriver.PathName, "\??\", "", 1, -1, 1), "\", "\\", 1, -1, 1) & "'")
				REM For Each objDriverFile in colDriverFiles
					REM AddOutput Pad(GetBranch(objDriverFile.Version, False), 6, PADLEFT) & "  " & Pad(Left(UCase(objDriverFile.FileName & "." & objDriverFile.Extension), 28), 30, PADRIGHT) & Pad(Left(objDriverFile.Manufacturer, 28), 30, PADRIGHT) & Pad(GetBranch(objDriverFile.Version, True), 20, PADRIGHT) & Pad(WMIDateStringToDate(objDriverFile.LastModified), 10, PADRIGHT)  & Pad(FormatNumber(Round(objDriverFile.FileSize/1024), 0, , vbTrue), 8, PADLEFT) & " KB" & Pad("(" & FormatNumber(objDriverFile.FileSize, 0, , vbTrue) & " bytes)", 20, PADLEFT)
				REM Next
				REM Set colDriverFiles = Nothing
			REM End If
		REM End If
	REM Next

	Print "GetRunningDrivers()", TASK, intLocation

End Function

Function GetRunningProcesses()

	If blnErrorHandling Then On Error Resume Next

	Print "GetRunningProcesses()", TASK, intLocation

	Dim blnUseFSO
	Dim objFSOFile

	Set objFSO = CreateObject("Scripting.FileSystemObject")

	blnUseFSO = False

	Dim colProcesses
	Dim objProcess
	Dim colProcessFiles
	Dim objProcessFile

	Set colProcesses = objWMIService.ExecQuery("Select Name,ExecutablePath From Win32_Process", , wbemFlagReturnImmediately + wbemFlagForwardOnly)
	'Set colProcesses = objWMIService.ExecQuery("Select Name,ExecutablePath,Priority,HandleCount,CommandLine,CreationDate,KernelModeTime,OtherOperationCount,OtherTransferCount,ReadOperationCount,ReadTransferCount,SessionId,ThreadCount,UserModeTime,VirtualSize,WorkingSetSize,WriteOperationCount,WriteTransferCount From Win32_Process", , wbemFlagReturnImmediately + wbemFlagForwardOnly)

	Dim rsRunningProcesses
	Set rsRunningProcesses = CreateObject("ADODB.Recordset")

	rsRunningProcesses.Fields.Append "FileName", adVarChar, 255, adFldMayBeNull
	rsRunningProcesses.Fields.Append "Count", adDouble
	rsRunningProcesses.Fields.Append "FileSize", adDouble
	rsRunningProcesses.Fields.Append "LastModified", adVarChar, 255, adFldMayBeNull
	rsRunningProcesses.Fields.Append "Manufacturer", adVarChar, 255, adFldMayBeNull
	rsRunningProcesses.Fields.Append "Version", adVarChar, 255, adFldMayBeNull
	rsRunningProcesses.Fields.Append "Branch", adVarChar, 255, adFldMayBeNull

    ' Future - include additional process stats since I'm already querying Win32_Process where they live

	'rsRunningProcesses.Fields.Append "HandleCount", adDouble
	'rsRunningProcesses.Fields.Append "ThreadCount", adDouble
	'rsRunningProcesses.Fields.Append "WorkingSetSize", adDouble
	'rsRunningProcesses.Fields.Append "KernelModeTime", adDouble
	'rsRunningProcesses.Fields.Append "UserModeTime", adDouble
	'rsRunningProcesses.Fields.Append "Priority", adDouble
	'rsRunningProcesses.Fields.Append "CreationDate", adDate
	'rsRunningProcesses.Fields.Append "CommandLine", adVarChar, 255, adFldMayBeNull

	rsRunningProcesses.Open

	If Not rsRunningProcesses.BOF Then rsRunningDrivers.MoveFirst

	For Each objProcess in colProcesses

		If Not IsNull(objProcess.ExecutablePath) Then

			If blnUseFSO Then

				Set objFSOFile = objFSO.GetFile(objProcess.ExecutablePath)

				AddOutput Pad(UCase(objFSOFile.Name), 30, PADRIGHT) & Pad(objFSO.GetFileVersion(Replace(objProcess.ExecutablePath, "\??\", "", 1, -1, 1)), 30, PADRIGHT) & Pad(objFSOFile.DateLastModified, 30, PADRIGHT)

			Else

				Set colProcessFiles = objWMIService.ExecQuery("Select Extension,FileName,FileSize,LastModified,Manufacturer,Version From CIM_DataFile Where Name='" & Replace(Replace(objProcess.ExecutablePath, "\??\", "", 1, -1, 1), "\", "\\", 1, -1, 1) & "'")', , wbemFlagReturnImmediately + wbemFlagForwardOnly)

				Dim blnProcessInRecordSet

				blnProcessInRecordSet = False

				For Each objProcessFile in colProcessFiles

					If rsRunningProcesses.RecordCount Then
						'Print "Before MoveFirst: CursorLocation = " & rsTasks.CursorLocation & " AbsolutePosition = " & rsTasks.AbsolutePosition & " RecordCount = " & rsTasks.RecordCount & " BOF = " & rsTasks.BOF & " EOF = " & rsTasks.EOF, intLocation
						rsRunningProcesses.MoveFirst
						'Print "After MoveFirst: CursorLocation = " & rsTasks.CursorLocation & " AbsolutePosition = " & rsTasks.AbsolutePosition & " RecordCount = " & rsTasks.RecordCount & " BOF = " & rsTasks.BOF & " EOF = " & rsTasks.EOF, intLocation
						Do

							rsRunningProcesses.Find("FileName = '" & UCase(Left(objProcessFile.FileName & "." & objProcessFile.Extension, 1)) & Mid(LCase(objProcessFile.FileName & "." & objProcessFile.Extension), 2) & "'")
							'Print "After Find: CursorLocation = " & rsRunningProcesses.CursorLocation & " AbsolutePosition = " & rsRunningProcesses.AbsolutePosition & " RecordCount = " & rsRunningProcesses.RecordCount & " BOF = " & rsRunningProcesses.BOF & " EOF = " & rsRunningProcesses.EOF, OUTPUT, intLocation

							If rsRunningProcesses.EOF Then

								Exit Do

							Else

								If (rsRunningProcesses("FileSize").Value = CDbl(objProcessFile.FileSize)) And (rsRunningProcesses("Manufacturer").Value = objProcessFile.Manufacturer) And (rsRunningProcesses("LastModified").Value = WMIDateStringToDate(objProcessFile.LastModified)) And (rsRunningProcesses("Version").Value = GetBranch(objProcessFile.Version, True)) Then

									rsRunningProcesses("Count").Value = rsRunningProcesses("Count").Value + 1
									blnProcessInRecordSet = True
									Exit Do

								End If

							End If

							rsRunningProcesses.MoveNext

						Loop Until rsRunningProcesses.EOF

						If blnProcessInRecordSet Then

							blnProcessInRecordSet = False

						Else

							rsRunningProcesses.AddNew

							rsRunningProcesses("FileName").Value = UCase(Left(objProcessFile.FileName & "." & objProcessFile.Extension, 1)) & Mid(LCase(objProcessFile.FileName & "." & objProcessFile.Extension), 2)
							rsRunningProcesses("Count").Value = 1
							rsRunningProcesses("FileSize").Value = objProcessFile.FileSize
							rsRunningProcesses("Manufacturer").Value = objProcessFile.Manufacturer
							rsRunningProcesses("LastModified").Value = WMIDateStringToDate(objProcessFile.LastModified)
							rsRunningProcesses("Version").Value = GetBranch(objProcessFile.Version, True)
							rsRunningProcesses("Branch").Value = GetBranch(objProcessFile.Version, False)

							rsRunningProcesses.Update

						End If

					Else

						rsRunningProcesses.AddNew

						rsRunningProcesses("FileName").Value = UCase(Left(objProcessFile.FileName & "." & objProcessFile.Extension, 1)) & Mid(LCase(objProcessFile.FileName & "." & objProcessFile.Extension), 2)
						rsRunningProcesses("Count").Value = 1
						rsRunningProcesses("FileSize").Value = objProcessFile.FileSize
						rsRunningProcesses("Manufacturer").Value = objProcessFile.Manufacturer
						rsRunningProcesses("LastModified").Value = WMIDateStringToDate(objProcessFile.LastModified)
						rsRunningProcesses("Version").Value = GetBranch(objProcessFile.Version, True)
						rsRunningProcesses("Branch").Value = GetBranch(objProcessFile.Version, False)

						rsRunningProcesses.Update

					End If

					'rsRunningProcesses("HandleCount").Value = objProcess.HandleCount
					'rsRunningProcesses("ThreadCount").Value = objProcess.ThreadCount
					'rsRunningProcesses("WorkingSetSize").Value = objProcess.WorkingSetSize
					'rsRunningProcesses("KernelModeTime").Value = objProcess.KernelModeTime
					'rsRunningProcesses("UserModeTime").Value = objProcess.UserModeTime
					'rsRunningProcesses("Priority").Value = objProcess.Priority
					'rsRunningProcesses("CreationDate").Value = objProcess.CreationDate
					'rsRunningProcesses("CommandLine").Value = objProcess.CommandLine

				Next

				Set colProcessFiles = Nothing

			End If

		End If

	Next

	rsRunningProcesses.Sort = "FileName ASC"
	rsRunningProcesses.MoveFirst

	Heading("3RD-PARTY RUNNING PROCESSES")
	AddOutput Pad("File Name", 30, PADRIGHT) & Pad("Count", 7, PADRIGHT) & Pad("Manufacturer", 30, PADRIGHT) & Pad("Version", 20, PADRIGHT) & Pad("Date", 10, PADRIGHT) & Pad("Size", 11, PADLEFT)
	AddOutput String(HEADING_WIDTH, "-")

	Do Until rsRunningProcesses.EOF
		If Instr(UCase(rsRunningProcesses.Fields.Item("Manufacturer")), "MICROSOFT") = 0 Then
			AddOutput Pad(Left(rsRunningProcesses.Fields.Item("FileName"), 28), 30, PADRIGHT) & Pad(rsRunningProcesses.Fields.Item("Count"), 7, PADRIGHT) & Pad(Left(rsRunningProcesses.Fields.Item("Manufacturer"), 28), 30, PADRIGHT) & Pad(Left(rsRunningProcesses.Fields.Item("Version"), 18), 20, PADRIGHT) & Pad(rsRunningProcesses.Fields.Item("LastModified"), 10, PADRIGHT) & Pad(FormatNumber(Round(rsRunningProcesses.Fields.Item("FileSize")/1024), 0, , vbTrue), 8, PADLEFT) & " KB" & Pad("(" & FormatNumber(rsRunningProcesses.Fields.Item("FileSize"), 0, , vbTrue) & " bytes)", 20, PADLEFT)
		End IF
		rsRunningProcesses.MoveNext
	Loop

	Heading("MICROSOFT RUNNING PROCESSES")
	AddOutput Pad("Branch", 8, PADRIGHT) & Pad("File Name", 30, PADRIGHT) & Pad("Count", 7, PADRIGHT) & Pad("Manufacturer", 30, PADRIGHT) & Pad("Version", 20, PADRIGHT) & Pad("Date", 10, PADRIGHT) & Pad("Size", 11, PADLEFT)
	AddOutput String(HEADING_WIDTH, "-")

	rsRunningProcesses.MoveFirst

	Do Until rsRunningProcesses.EOF
		If Instr(UCase(rsRunningProcesses.Fields.Item("Manufacturer")), "MICROSOFT") Then
			If Instr(rsRunningProcesses.Fields.Item("Branch"), "LDR") Then
				AddOutput Pad(rsRunningProcesses.Fields.Item("Branch"), 6, PADRIGHT) & "  " & Pad(Left(rsRunningProcesses.Fields.Item("FileName"), 28), 30, PADRIGHT) & Pad(rsRunningProcesses.Fields.Item("Count"), 7, PADRIGHT) & Pad(Left(rsRunningProcesses.Fields.Item("Manufacturer"), 28), 30, PADRIGHT) & Pad(Left(rsRunningProcesses.Fields.Item("Version"), 18), 20, PADRIGHT) & Pad(rsRunningProcesses.Fields.Item("LastModified"), 10, PADRIGHT) & Pad(FormatNumber(Round(rsRunningProcesses.Fields.Item("FileSize")/1024), 0, , vbTrue), 8, PADLEFT) & " KB" & Pad("(" & FormatNumber(rsRunningProcesses.Fields.Item("FileSize"), 0, , vbTrue) & " bytes)", 20, PADLEFT)
			Else
				AddOutput Pad(rsRunningProcesses.Fields.Item("Branch"), 6, PADLEFT) & "  " & Pad(Left(rsRunningProcesses.Fields.Item("FileName"), 28), 30, PADRIGHT) & Pad(rsRunningProcesses.Fields.Item("Count"), 7, PADRIGHT) & Pad(Left(rsRunningProcesses.Fields.Item("Manufacturer"), 28), 30, PADRIGHT) & Pad(Left(rsRunningProcesses.Fields.Item("Version"), 18), 20, PADRIGHT) & Pad(rsRunningProcesses.Fields.Item("LastModified"), 10, PADRIGHT) & Pad(FormatNumber(Round(rsRunningProcesses.Fields.Item("FileSize")/1024), 0, , vbTrue), 8, PADLEFT) & " KB" & Pad("(" & FormatNumber(rsRunningProcesses.Fields.Item("FileSize"), 0, , vbTrue) & " bytes)", 20, PADLEFT)
			End If
		End If
		rsRunningProcesses.MoveNext
	Loop

	Print "GetRunningProcesses()", TASK, intLocation

	'Heading("Top 5 Handle Count")
	'AddOutput Pad("File Name", 30, PADRIGHT) & "Handle Count"

	'rsRunningProcesses.Sort = "HandleCount DESC"
	'rsRunningProcesses.MoveFirst

	'i = 0
	'Do Until i = 5
	'	AddOutput Pad(Left(rsRunningProcesses.Fields.Item("FileName"), 28), 30, PADRIGHT) & rsRunningProcesses.Fields.Item("HandleCount") & " " & rsRunningProcesses.Fields.Item("CommandLine")
	'	rsRunningProcesses.MoveNext
	'	i = i + 1
	'Loop

End Function

Function GetServices(blnAllServices)

	If blnErrorHandling Then On Error Resume Next

	Print "GetServices(" & blnAllServices & ")", TASK, intLocation

	Dim colServices
	Dim objService
	Dim rsServices
	Dim blnAutomaticNotStartedServices
	blnAutomaticNotStartedServices = False

	Set rsServices = CreateObject("ADODB.Recordset")

	rsServices.Fields.Append "DisplayName", adVarChar, 255, adFldMayBeNull
	rsServices.Fields.Append "Name", adVarChar, 255, adFldMayBeNull
	rsServices.Fields.Append "StartMode", adVarChar, 255, adFldMayBeNull
	rsServices.Fields.Append "Started", adVarChar, 255, adFldMayBeNull
	rsServices.Fields.Append "StartName", adVarChar, 255, adFldMayBeNull
	rsServices.Fields.Append "ServiceType", adVarChar, 255, adFldMayBeNull
	rsServices.Fields.Append "ExitCode", adVarChar, 255, adFldMayBeNull
	rsServices.Fields.Append "PathName", adVarChar, 255, adFldMayBeNull

	rsServices.Open

	If Not rsServices.BOF Then rsServices.MoveFirst

	If blnAllServices Then
		Set colServices = objWMIService.ExecQuery("Select DisplayName,ExitCode,Name,ServiceType,StartMode,Started,StartName,Status,PathName From Win32_Service", , wbemFlagReturnImmediately + wbemFlagForwardOnly)
	Else
		Set colServices = objWMIService.ExecQuery("Select DisplayName,ExitCode,Name,ServiceType,StartMode,Started,StartName,Status,PathName From Win32_Service WHERE StartMode='Auto' AND Started='False'", , wbemFlagReturnImmediately + wbemFlagForwardOnly)
	End If

	For Each objService in colServices
		rsServices.AddNew
		rsServices("DisplayName").Value = objService.DisplayName
		rsServices("Name").Value = objService.Name
		rsServices("StartMode").Value = objService.StartMode
		rsServices("Started").Value = objService.Started
		rsServices("StartName").Value = objService.StartName
		rsServices("ExitCode").Value = objService.ExitCode
		rsServices("ServiceType").Value = objService.ServiceType
		rsServices("PathName").Value = LCase(objService.PathName)
		rsServices.Update
	Next

	rsServices.Sort = "DisplayName ASC"
	rsServices.MoveFirst

	If blnAllServices Then

		Heading("SERVICES - ALL")
		AddOutput Pad("Display Name", 60, PADRIGHT) & Pad("Started", 10, PADRIGHT) & Pad("Startup", 10, PADRIGHT) & Pad("Log On As", 30, PADRIGHT) & Pad("Type", 15, PADRIGHT) & "PathName"
		AddOutput String(HEADING_WIDTH, "-")

		Do Until rsServices.EOF
			AddOutput Pad(Left(rsServices.Fields.Item("DisplayName"), 59), 60, PADRIGHT) & Pad(rsServices.Fields.Item("Started"), 10, PADRIGHT) & Pad(rsServices.Fields.Item("StartMode"), 10, PADRIGHT) & Pad(rsServices.Fields.Item("StartName"), 30, PADRIGHT) & Pad(rsServices.Fields.Item("ServiceType"), 15, PADRIGHT) & rsServices.Fields.Item("PathName")
			rsServices.MoveNext
		Loop

	Else

		Heading("SERVICES - AUTOMATIC BUT NOT STARTED")
		AddOutput Pad("Display Name", 60, PADRIGHT) & Pad("Started", 10, PADRIGHT) & Pad("Startup", 10, PADRIGHT) & Pad("Log On As", 30, PADRIGHT) & Pad("Type", 15, PADRIGHT) & "PathName"
		AddOutput String(HEADING_WIDTH, "-")

		Err.Clear ' Clear it to make sure it doesn't contain an earlier error that might throw a false-positive when checking below.

		rsServices.MoveFirst

		If Err Then
			AddOutput "<all automatic startup services are running>"
			Err.Clear
		Else
			Do Until rsServices.EOF
				AddOutput Pad(Left(rsServices.Fields.Item("DisplayName"), 59), 60, PADRIGHT) & Pad(rsServices.Fields.Item("Started"), 10, PADRIGHT) & Pad(rsServices.Fields.Item("StartMode"), 10, PADRIGHT) & Pad(rsServices.Fields.Item("StartName"), 30, PADRIGHT) & Pad(rsServices.Fields.Item("ServiceType"), 15, PADRIGHT) & rsServices.Fields.Item("PathName")
				rsServices.MoveNext
			Loop
		End If

	End If

	Print "GetServices(" & blnAllServices & ")", TASK, intLocation

End Function

Function Heading(strHeading)

	If blnErrorHandling Then On Error Resume Next

	' Only add a blank line if one doesn't exist already, so there is exactly one blank line between sections
	If Trim(arrOutput(UBound(arrOutput))) = "" Or Right(arrOutput(UBound(arrOutput)), 1) <> Chr(10) Then AddOutput " "

	AddOutput String(HEADING_WIDTH, "=")
	AddOutput strHeading
	AddOutput String(HEADING_WIDTH, "=")

End Function

Function WriteOutput()

	If blnErrorHandling Then On Error Resume Next

    ' Future - output to Excel (not for SDP, just standalone script execution)
	'blnExcelOutput = False

	'If blnExcelOutput Then
	'	Set objExcel = CreateObject("Excel.Application")
	'	objExcel.Visible = True
	'	Set objWorkbook = objExcel.Workbooks.Add()
	'	Set objWorksheet = objWorkbook.Worksheets(1)
	'End If

    dtmEndTime = Timer
    intSeconds = FormatNumber(Round(dtmEndTime - dtmStartTime, 2), 2)

	AddOutput vbCrLf & vbCrLf & "Script completed in " & intSeconds & "s"

	If blnTextOutput Then
		If blnSDP Then
			strOutputPath = objShell.CurrentDirectory & "\"
		Else
			strOutputPath = objShell.ExpandEnvironmentStrings("%TEMP%") & "\"
		End If

		If InStr(strOSName, "Windows 8") Then
			strOSShortName = "WIN8_CLIENT"
			strServicePack = strBuildNumber
		ElseIf InStr(strOSName, "Windows Server 8") Then
			strOSShortName = "WIN8_SERVER"
			strServicePack = strBuildNumber
		ElseIf InStr(strOSName, "Windows 7") Then
			strOSShortName = "WIN7"
		ElseIf InStr(strOSName, "Windows Server 2008 R2") Then
			strOSShortName = "2008R2"
		ElseIf InStr(strOSName, "Windows Vista") Then
			strOSShortName = "VISTA"
		ElseIf InStr(strOSName, "Windows Server 2008") Then
			strOSShortName = "2008"
		ElseIf InStr(strOSName, "Windows XP") Then
			strOSShortName = "WINXP"
		ElseIf InStr(strOSName, "Windows Server 2003") Then
			strOSShortName = "2003"
		Else
			strOSShortName = ""
		End If
		strOutputTxt = strOutputPath & strSystemName & "__SUMMARY_" & strOSShortName & "_" & strServicePack & "_" & strBitness & ".txt"
		strOutputLog = strOutputPath & strSystemName & "__SUMMARY_" & strOSShortName & "_" & strServicePack & "_" & strBitness & ".log"

		If objFSO.FileExists(strOutputTxt) Then
			objFSO.DeleteFile strOutputTxt, True
		End If

		Set objOutputTxt = objFSO.OpenTextFile(strOutputTxt, ForWriting, True, -1)
	End If

	For i = 0 to UBound(arrOutput)
		If IsEmpty(arrOutput(i)) = False Then
			'If blnExcelOutput Then
			'	objWorksheet.Cells(i+1,1) = arrOutput(i)
			'Else
				'Wscript.Echo arrOutput(i)
			'	If blnTextOutput Then
				objOutputTxt.WriteLine(arrOutput(i))
			'	End If
			'End If
		End If
	Next

	If blnTextOutput Then
		objOutputTxt.Close
		If Not blnSDP Then
			strCommand1 = "cmd /c start " & strOutputTxt
			'strCommand1 = "explorer.exe /select," & strOutputTxt
			objShell.Run strCommand1
			'objShell.Run strCommand2
		End If
	End If

End Function

Function GetError()

	'If blnErrorHandling Then On Error Resume Next

    If Err Then
        Print "[ERROR] " & Err.Source & " " & Err.Number & " " & Err.Description, OUTPUT, intLocation
        Err.Clear
    End If

End Function

Function LogFunction(strFunction)

	If blnErrorHandling Then On Error Resume Next

	If Not IsObject(rsTasks) Then
		Set rsTasks = CreateObject("ADODB.Recordset")
		rsTasks.CursorLocation = adUseClient
		rsTasks.Fields.Append "Name", adVarChar, 255, adFldMayBeNull
		rsTasks.Fields.Append "Start", adSingle
		rsTasks.Fields.Append "End", adSingle
		rsTasks.Fields.Append "Duration", adSingle
		rsTasks.Open
		'Print "CursorLocation = " & rsTasks.CursorLocation & " AbsolutePosition = " & rsTasks.AbsolutePosition & " RecordCount = " & rsTasks.RecordCount & " BOF = " & rsTasks.BOF & " EOF = " & rsTasks.EOF, intLocation
		'GetVarInfo rsTasks
	End If

	If rsTasks.RecordCount Then
		'Print "Before MoveFirst: CursorLocation = " & rsTasks.CursorLocation & " AbsolutePosition = " & rsTasks.AbsolutePosition & " RecordCount = " & rsTasks.RecordCount & " BOF = " & rsTasks.BOF & " EOF = " & rsTasks.EOF, intLocation
		rsTasks.MoveFirst
		'Print "After MoveFirst: CursorLocation = " & rsTasks.CursorLocation & " AbsolutePosition = " & rsTasks.AbsolutePosition & " RecordCount = " & rsTasks.RecordCount & " BOF = " & rsTasks.BOF & " EOF = " & rsTasks.EOF, intLocation
		rsTasks.Find("Name = '" & strFunction & "'")
		'Print "After Find: CursorLocation = " & rsTasks.CursorLocation & " AbsolutePosition = " & rsTasks.AbsolutePosition & " RecordCount = " & rsTasks.RecordCount & " BOF = " & rsTasks.BOF & " EOF = " & rsTasks.EOF, intLocation
	End If

	If rsTasks.EOF Then
		rsTasks.AddNew
		rsTasks("Name").Value = strFunction
		rsTasks("Start").Value = Timer
		rsTasks.Update
		'Print "CursorLocation = " & rsTasks.CursorLocation & " AbsolutePosition = " & rsTasks.AbsolutePosition & " RecordCount = " & rsTasks.RecordCount & " BOF = " & rsTasks.BOF & " EOF = " & rsTasks.EOF, intLocation
		'Print "[ENTER FUNCTION] " & strFunction, True, intLocation
	Else
		'Print rsTasks.Fields.Item("Start"), intLocation
		rsTasks("Duration").Value = Timer - rsTasks("Start").Value
		rsTasks("End").Value = Timer
		rsTasks.Update
		'Print "[EXIT FUNCTION]  " & "Function Name: " & rsTasks.Fields.Item("Name") & " Start: " & rsTasks.Fields.Item("Start") & " End: " & rsTasks.Fields.Item("End") & " Duration: " & rsTasks.Fields.Item("Duration"), intLocation
	End If

End Function

Function Print(strErrText, blnTask, intOutputLocation)

	If blnErrorHandling Then On Error Resume Next

    If blnDebug Then

		If blnTask Then

			If Not IsObject(rsTasks) Then
				Set rsTasks = CreateObject("ADODB.Recordset")
				rsTasks.CursorLocation = adUseClient
				rsTasks.Fields.Append "Name", adVarChar, 255, adFldMayBeNull
				rsTasks.Fields.Append "Start", adSingle
				rsTasks.Fields.Append "End", adSingle
				rsTasks.Fields.Append "Duration", adSingle
				rsTasks.Open
			End If

			If rsTasks.RecordCount Then
				rsTasks.MoveFirst
				rsTasks.Find("Name = '" & strErrText & "'")
			End If
			If rsTasks.EOF Then
				rsTasks.AddNew
				rsTasks("Name").Value = strErrText
				rsTasks("Start").Value = Timer
				rsTasks.Update
			Else
				rsTasks("Duration").Value = Timer - rsTasks("Start").Value
				rsTasks("End").Value = Timer
				rsTasks.Update
				strErrText = rsTasks.Fields.Item("Name") & " completed in " & FormatNumber(rsTasks.Fields.Item("Duration"), 1) & "s"
			End If

		Else

			If (intOutputLocation And NO_TIME) = False Then
				strErrText = strErrText
			End If

		End If

		strTime = Pad(Month(Now), 2, PADZERO) & "\" & Pad(Day(Now), 2, PADZERO) & "\" & Year(Now) & " " & Pad(Hour(Now), 2, PADZERO) & ":" & Pad(Minute(Now), 2, PADZERO) & ":" & Pad(Second(Now), 2, PADZERO) & "  "

		If intOutputLocation And TO_SCREEN Then

			If intOutputLocation And NO_TIME Then
				Wscript.Echo strErrText
			Else
				Wscript.Echo strTime & strErrText
			End If

		End If

		If intOutputLocation And TO_FILE Then

			If Not blnSDP Then

				If blnFirstRun Then

					strOutputTempLog = objShell.ExpandEnvironmentStrings("%TEMP%") & "\Progress.log"

					If objFSO.FileExists(strOutputTempLog) Then
						objFSO.DeleteFile strOutputTempLog, True
					End If
					Set objOutputLog = objFSO.OpenTextFile(strOutputTempLog, ForAppending, True, -1)
					If Err Then
						Wscript.Echo "ERROR: Could not create/open " & strOutputTempLog
						Err.Clear
					End If
					objOutputLog.WriteLine strTime & strErrText
					blnFirstRun = False
					objOutputLog.Close

				Else

					Set objOutputLog = objFSO.OpenTextFile(strOutputTempLog, ForAppending, True, -1)

					If intOutputLocation And NO_TIME Then
						objOutputLog.WriteLine strErrText
					Else
						objOutputLog.WriteLine strTime & strErrText
					End If
					objOutputLog.Close
				End If
			End If
		End If
	End If

End Function

Function Ping(strHostName)

    Dim colPing
	Dim objPing

    Set colPing = GetObject("winmgmts://./root/cimv2").ExecQuery("SELECT * FROM Win32_PingStatus WHERE Address = '" & strHostName & "'")

    For Each objPing In colPing
        If Not IsObject(objPing) Then
            Ping = False
			Print "Ping failed: " & strHostname, OUTPUT, intLocation
        ElseIf objPing.StatusCode = 0 Then
            Ping = True
			Print "Ping successful: " & strHostname, OUTPUT, intLocation
        Else
            Ping = False
			Print "Ping failed: " & strHostname, OUTPUT, intLocation
        End If
    Next

    Set colPing = Nothing

End Function
'' SIG '' Begin signature block
'' SIG '' MIInwgYJKoZIhvcNAQcCoIInszCCJ68CAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' fzCFJOJ3TtvzKwuFd7t4aviCysyCukmAFPdQkD7NcROg
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
'' SIG '' a/15n8G9bW1qyVJzEw16UM0xghmkMIIZoAIBATCBlTB+
'' SIG '' MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
'' SIG '' bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
'' SIG '' cm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNy
'' SIG '' b3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExAhMzAAAC
'' SIG '' y7d1OfsCcUI2AAAAAALLMA0GCWCGSAFlAwQCAQUAoIGw
'' SIG '' MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
'' SIG '' AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3
'' SIG '' DQEJBDEiBCDGI57u9QWUw6Qpp7SOqXp62DnBBxUU15me
'' SIG '' u6ZLmbfgeTBEBgorBgEEAYI3AgEMMTYwNKAUgBIATQBp
'' SIG '' AGMAcgBvAHMAbwBmAHShHIAaaHR0cHM6Ly93d3cubWlj
'' SIG '' cm9zb2Z0LmNvbSAwDQYJKoZIhvcNAQEBBQAEggEABbII
'' SIG '' 6woGsBwMR4KmFTAAP8lX7gJ/KRC3cfkj7PyXrplqWpKN
'' SIG '' 57ct9sNC5KRuy32QdEZRJCrWlYwLrgK9K4J3GCLqLz2+
'' SIG '' mH+8ktHtYI3GbofzL4UGSMf3rarNEOEoSrS+14nbPMos
'' SIG '' 5+zzofmGb8TyndEtCB61MtbF2C2tH89adr2NWzDu7cdx
'' SIG '' vQZsoD6pX2e+0X3jDR10FhXcRFamHNglYgiEAYNcHbPC
'' SIG '' UpcKHYOUoIlrlzB8VQNQTFHB686LCQ8Vzmf6kOwgqTc0
'' SIG '' tji4R+sIgHUx4kmE5GllEFlQy2L9QA8W4adk4ZMtOd5p
'' SIG '' e99ezIW1ElSeNcWAnwPgUyx1aF7y+qGCFywwghcoBgor
'' SIG '' BgEEAYI3AwMBMYIXGDCCFxQGCSqGSIb3DQEHAqCCFwUw
'' SIG '' ghcBAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsqhkiG
'' SIG '' 9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGEWQoD
'' SIG '' ATAxMA0GCWCGSAFlAwQCAQUABCBRPiZCHYmMvP5btmoX
'' SIG '' AVmQB+0cXST24ltB9qXv+kwIzAIGZD/RIBAJGBMyMDIz
'' SIG '' MDQyMTEwNDUwOC4zNTVaMASAAgH0oIHYpIHVMIHSMQsw
'' SIG '' CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
'' SIG '' MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
'' SIG '' b2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3Nv
'' SIG '' ZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAk
'' SIG '' BgNVBAsTHVRoYWxlcyBUU1MgRVNOOkEyNDAtNEI4Mi0x
'' SIG '' MzBFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
'' SIG '' cCBTZXJ2aWNloIIRezCCBycwggUPoAMCAQICEzMAAAG4
'' SIG '' CNTBuHngUUkAAQAAAbgwDQYJKoZIhvcNAQELBQAwfDEL
'' SIG '' MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
'' SIG '' EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
'' SIG '' c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
'' SIG '' b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIwOTIw
'' SIG '' MjAyMjE2WhcNMjMxMjE0MjAyMjE2WjCB0jELMAkGA1UE
'' SIG '' BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
'' SIG '' BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
'' SIG '' b3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IEly
'' SIG '' ZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQL
'' SIG '' Ex1UaGFsZXMgVFNTIEVTTjpBMjQwLTRCODItMTMwRTEl
'' SIG '' MCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
'' SIG '' dmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
'' SIG '' ggIBAJwbsfwRHERn5C95QPGn37tJ5vOiY9aWjeIDxpga
'' SIG '' XaYGiqsw0G0cvCK3YulrqemEf2CkGSdcOJAF++EqhOSq
'' SIG '' rO13nGcjqw6hFNnsGwKANyzddwnOO0jz1lfBIIu77Tbf
'' SIG '' NvnaWbwSRu0DTGHA7n7PR0MYJ9bC/HopStpbFf606LKc
'' SIG '' TWnwaUuEdAhx6FAqg1rkgugiuuaaxKyxRkdjFZLKFXEX
'' SIG '' L9p01PtwS0fG6vZiRVnEKgeal2TeLvdAIqapBwltPYif
'' SIG '' gqnp7Z4VJMcPo0TWmRNVFOcHRNwWHehN9xg6ugIGXPo7
'' SIG '' hMpWrPgg4moHO2epc0T36rgm9hlDrl28bG5TakmV7NJ9
'' SIG '' 8kbF5lgtlrowT6ecwEVtuLd4a0gzYqhanW7zaFZnDft5
'' SIG '' yMexy59ifETdzpwArj2nJAyIsiq1PY3XPm2mUMLlACks
'' SIG '' qelHKfWihK/Fehw/mziovBVwkkr/G0F19OWgR+MBUKif
'' SIG '' wpOyQiLAxrqvVnfCY4QjJCZiHIuS15HCQ/TIt/Qj4x1W
'' SIG '' vRa1UqjnmpLu4/yBYWZsdvZoq8SXI7iOs7muecAJeEkY
'' SIG '' lM6iOkMighzEhjQK9ThPpoAtluXbL7qIHGrfFlHmX/4s
'' SIG '' oc7jj1j8uB31U34gJlB2XphjMaT+E+O9SImk/6GRV9Sm
'' SIG '' 8C88Fnmm2VdwMluCNAUzPFjfvHx3AgMBAAGjggFJMIIB
'' SIG '' RTAdBgNVHQ4EFgQUxP1HJTeFwzNYo1njfucXuUfQaW4w
'' SIG '' HwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIw
'' SIG '' XwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNy
'' SIG '' b3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
'' SIG '' VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwG
'' SIG '' CCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDov
'' SIG '' L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9N
'' SIG '' aWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAx
'' SIG '' MCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8E
'' SIG '' DDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJ
'' SIG '' KoZIhvcNAQELBQADggIBAJ9uk8miwpMoKw3D996piEzb
'' SIG '' egAGxkABHYn2vP2hbqnkS9U97s/6QlyZOhGFsVudaiLe
'' SIG '' RZZTsaG5hR0oCuBINZ/lelo5xzHc+mBOpBXpxSaW1hqo
'' SIG '' xaCLsVH1EBtz7in25Hjy+ejuBcilH6EZ0ZtNxmWGIQz8
'' SIG '' R0AuS0Tj4VgJXHIlXP9dVOiyGo9Velrk+FGx/BC+iEuC
'' SIG '' aKd/IsypHPiCUCh52DGc91s2S7ldQx1H4CljOAtanDfb
'' SIG '' vSejASWLo/s3w0XMAbDurWNns0XidAF2RnL1PaxoOyz9
'' SIG '' VYakNGK4F3/uJRZnVgbsCYuwNX1BmSwM1ZbPSnggNSGT
'' SIG '' Zx/FQ20Jj/ulrK0ryAbvNbNb4kkaS4a767ifCqvUOFLl
'' SIG '' UT8PN43hhldxI6yHPMOWItJpEHIZBiTNKblBsYbIrghb
'' SIG '' 1Ym9tfSsLa5ZJDzVZNndRfhUqJOyXF+CVm9OtVmFDG9k
'' SIG '' IwM6QAX8Q0if721z4VOzZNvD8ktg1lI+XjXgXDJVs3h4
'' SIG '' 7sMu9GXSYzky+7dtgmc3iRPkda3YVRdmPJtNFN0NLybc
'' SIG '' ssE7vhFCij75eDGQBFq0A4KVG6uBdr6UTWwE0VKHxBz2
'' SIG '' BpGvn7BCs+5yxnF+HV6CUickDqqPi/II7Zssd9EbP9uz
'' SIG '' j4luldXDAPrWGtdGq+wK0odlGNVuCMxsL3hn8+KiO9Ui
'' SIG '' MIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAA
'' SIG '' FTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMx
'' SIG '' EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
'' SIG '' ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
'' SIG '' dGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2Vy
'' SIG '' dGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMw
'' SIG '' MTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQG
'' SIG '' EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
'' SIG '' BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
'' SIG '' cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
'' SIG '' ZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEB
'' SIG '' BQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
'' SIG '' 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xP
'' SIG '' x2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpS
'' SIG '' g0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/Y
'' SIG '' JlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+
'' SIG '' jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GP
'' SIG '' sjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6
'' SIG '' BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyzi
'' SIG '' YrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31B
'' SIG '' mkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn42
'' SIG '' 7DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n
'' SIG '' 6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLR
'' SIG '' vWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2
'' SIG '' ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9
'' SIG '' stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8
'' SIG '' FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6t
'' SIG '' AgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
'' SIG '' MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q
'' SIG '' /y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ
'' SIG '' 6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/
'' SIG '' BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQu
'' SIG '' Y29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMG
'' SIG '' A1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQM
'' SIG '' HgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMB
'' SIG '' Af8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjR
'' SIG '' PZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6
'' SIG '' Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
'' SIG '' Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBa
'' SIG '' BggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
'' SIG '' Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWlj
'' SIG '' Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3
'' SIG '' DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/q
'' SIG '' XBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
'' SIG '' 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOw
'' SIG '' Bb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1Tk
'' SIG '' eFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8Z
'' SIG '' thISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/AL
'' SIG '' aoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99J
'' SIG '' o3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32
'' SIG '' THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEU
'' SIG '' BHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsN
'' SIG '' n6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQ
'' SIG '' THa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+
'' SIG '' y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10Cga
'' SIG '' iQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0l
'' SIG '' lOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghi
'' SIG '' f9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtcw
'' SIG '' ggJAAgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMx
'' SIG '' EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
'' SIG '' ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
'' SIG '' dGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQg
'' SIG '' T3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFs
'' SIG '' ZXMgVFNTIEVTTjpBMjQwLTRCODItMTMwRTElMCMGA1UE
'' SIG '' AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIj
'' SIG '' CgEBMAcGBSsOAwIaAxUAcGteVqFx/IbTKXHLeuXCPRPM
'' SIG '' D7uggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
'' SIG '' CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
'' SIG '' MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
'' SIG '' JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
'' SIG '' MjAxMDANBgkqhkiG9w0BAQUFAAIFAOfsSXcwIhgPMjAy
'' SIG '' MzA0MjEwNzI5NTlaGA8yMDIzMDQyMjA3Mjk1OVowdzA9
'' SIG '' BgorBgEEAYRZCgQBMS8wLTAKAgUA5+xJdwIBADAKAgEA
'' SIG '' AgIX0QIB/zAHAgEAAgITbzAKAgUA5+2a9wIBADA2Bgor
'' SIG '' BgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIB
'' SIG '' AAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUA
'' SIG '' A4GBAElINonPpZzcBK3fzuMNF1ySPIO58l9ptAIcta7d
'' SIG '' 9Z/F3i4WtTJ9LZ4Ed367zR2hU2RM0A14GU+Fm5Xp53Tk
'' SIG '' 3iI2pXyP+K6pjhLWYBciVeTvxBYx8LkHglC3mPB1PuJ1
'' SIG '' 69u2JMMPHZ5EwfjZuULnZ9mclGTnMSqfEwu1cqSoZa7U
'' SIG '' MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzAR
'' SIG '' BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
'' SIG '' bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
'' SIG '' bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
'' SIG '' UENBIDIwMTACEzMAAAG4CNTBuHngUUkAAQAAAbgwDQYJ
'' SIG '' YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsq
'' SIG '' hkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQghmGyn69Q
'' SIG '' pTooMXK8gqyXnL/oaJ53jf8OhVHyfNJ0snYwgfoGCyqG
'' SIG '' SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAo69Y4oHA7Q4pS
'' SIG '' +Y1NsBfrpIYTeWsPeGTami0X0PD7HzCBmDCBgKR+MHwx
'' SIG '' CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
'' SIG '' MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
'' SIG '' b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
'' SIG '' c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABuAjU
'' SIG '' wbh54FFJAAEAAAG4MCIEINmSyl7KEmyHDtg7ztysaKZu
'' SIG '' T2CMHc5SgmZvS7Ae2UceMA0GCSqGSIb3DQEBCwUABIIC
'' SIG '' AIyvw4W2jY2tQxakZyZu05ed2KD6uPGSfQCa2KoRDejV
'' SIG '' giGLWUcpDmdel2u47YsP9nFCKYZwxvX4KzAqStsHic4l
'' SIG '' GK68seC+Uq6saYTBW1UwXOVTRkBUUPDiwx9JqA1+qqfX
'' SIG '' QDz6Z8bYlV2rC0F+V+I6MzxqlBdVE6QpecSV15ANILea
'' SIG '' ae5m9FFcXSHBHOq+ptd6TB2/a8lrhUKg2BtU2NmY5iEt
'' SIG '' /AZTqwFiTsPa61K1P76/HRQup6pTKg7ZSdTJjw58d9xD
'' SIG '' bwsKVXOkUkwyBWyQk5ruL2AlrujW8Bp0WMCRj7XWaGOG
'' SIG '' 0p4mxCIQMajqjYjYyA3alJ+olRpwhy62gtRkpCdofEM3
'' SIG '' ha4nfD5nJtppt4OTd0Xvqpd06xywQO5CoOnwnXYMqUHU
'' SIG '' E2yQ2bkUost1sJzo2z9vhnw1Mk8zXlNMMM807n1/olwv
'' SIG '' l8T+mTCCHYnx5Z1Xwi8BhfgDFoZ5SlLGmlp7pyHgAHdt
'' SIG '' 8sMuihfdyRokjImymw+/SJ1E3VOIAbpropjclD45S8PC
'' SIG '' UeDBvzjmFmc5kC0hBM+Pnpkg0HPc0rPN/GeoueGYYcuz
'' SIG '' ijUZ9K5lBGAU+OD+drx/cWvnZb0HEhTNnJStDlnK6QqQ
'' SIG '' oa9c2mzq5VpYcOrs3GtgRx3D70TfYq3rgWByDXTCKVEN
'' SIG '' PJRZJ2NG1yxjIyXgaDyBh6z4
'' SIG '' End signature block
