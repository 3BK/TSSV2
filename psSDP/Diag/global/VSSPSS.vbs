On Error Resume Next

Dim ERRArray : Set ERRArray = CreateObject("Scripting.Dictionary")
ElevateThisScript()	

strComputer = "."
strVersion = "Modified VSSPSS from original"

If WScript.Arguments.Count = 1 Then strComputer = WScript.Arguments.Item(0)

If strComputer = "." Then
   	Dim network : Set network = CreateObject("Wscript.network")
  	strComputer = network.ComputerName
End If  

'*********************************************************************************
'	Subroutine: ElevateThisScript()	
'
'	Purpose: (Intended for Vista and Windows Server 2008)
'	Forces the currently running script to prompt for UAC elevation if it detects
'	that the current user credentials do not have administrative privileges
'
'	If run on Windows XP this script will cause the RunAs dialog to appear if the user
'	does not have administrative rights, giving the opportunity to run as an administrator  
'
'	This Sub Attempts to call the script with its original arguments.  Arguments that contain a space
'	will be wrapped in double quotes when the script calls itself again.
'
'	Usage:  Add a call to this sub (ElevateThisScript) to the beginning of your script to ensure
'	        that the script gets an administrative token
'**********************************************************************************		
Sub ElevateThisScript()
	
	Const HKEY_CLASSES_ROOT  = &H80000000
	Const HKEY_CURRENT_USER  = &H80000001
	Const HKEY_LOCAL_MACHINE = &H80000002
	Const HKEY_USERS         = &H80000003
	const KEY_QUERY_VALUE	  = 1
	Const KEY_SET_VALUE		  = 2

	Dim scriptEngine, engineFolder, argString, arg, Args, scriptCommand, HasRequiredRegAccess
	Dim objShellApp : Set objShellApp = CreateObject("Shell.Application")
		
	
	scriptEngine = Ucase(Mid(Wscript.FullName,InstrRev(Wscript.FullName,"\")+1))
	engineFolder = Left(Wscript.FullName,InstrRev(Wscript.FullName,"\"))
	argString = ""
	
	Set Args = Wscript.Arguments
	
	For each arg in Args						'loop though argument array as a collection to rebuild argument string
		If instr(arg," ") > 0 Then arg = """" & arg & """"	'if the argument contains a space wrap it in double quotes
		argString = argString & " " & Arg
	Next

	scriptCommand = engineFolder & scriptEngine
		
	Dim strComputer : strComputer = "."
		
	Dim objReg, bHasAccessRight
	Set objReg=GetObject("winmgmts:"_
		& "{impersonationLevel=impersonate}!\\" &_ 
		strComputer & "\root\default:StdRegProv")
	

	'Check for administrative registry access rights
	objReg.CheckAccess HKEY_LOCAL_MACHINE, "System\CurrentControlSet\Control\CrashControl", _
		KEY_SET_VALUE, bHasAccessRight
	
	If bHasAccessRight = True Then
	
		HasRequiredRegAccess = True
		Exit Sub
		
	Else
		
		HasRequiredRegAccess = False
		objShellApp.ShellExecute scriptCommand, " """ & Wscript.ScriptFullName & """" & argString, "", "runas"
		WScript.Quit
	End If
		
	
End Sub


'*************************************************************************************
' Show service status.
'*************************************************************************************
Sub ListServiceStatus(ByVal ServiceName, ByVal ExpectedStartType)

	Set objWMIService = GetObject( "winmgmts:\\" & strComputer & "\root\CIMV2") 
	Set colItems = objWMIService.ExecQuery( "SELECT * FROM Win32_Service where Name = '" & ServiceName &"'",,48) 
	
	Found = 0 

	For Each objItem in colItems 
               Found = 1
	       WScript.Echo("Service Name: " & objItem.DisplayName & VBNewLine & "       State: " & objItem.State & _
                      "   StartType: " & objItem.StartMode & VBNewLine & VBNewLine)

               If (ExpectedStartType <> objItem.StartMode) Then
                     ERRCount = ERRCount + 1
                     ERRArray.Add Cstr(ERRCount), "SERVICE ERROR: " & objItem.DisplayName & " service start type should be " & ExpectedStartType
               End If
	Next

	'
	' If the service name wasn't found, report that as an error.
	'
	If Found <> 1 Then
               ERRCount = ERRCount + 1
               ERRArray.Add Cstr(ERRCount), "SERVICE ERROR: " & ServiceName & " is not installed as a service."
	End If
End Sub

'
' If the service start type is not correct, report that as an error. 
'

Sub ListServiceStatusApps(ByVal ServiceName, ByVal ExpectedStartType)

	Set objWMIService = GetObject( "winmgmts:\\" & strComputer & "\root\CIMV2") 
	Set colItems = objWMIService.ExecQuery( "SELECT * FROM Win32_Service where Name = '" & ServiceName &"'",,48) 
	
	Found = 0 

	For Each objItem in colItems 
               Found = 1
	       WScript.Echo("Service Name: " & objItem.DisplayName & VBNewLine & "       State: " & objItem.State & _
                      "   StartType: " & objItem.StartMode & VBNewLine & VBNewLine)

               If (ExpectedStartType <> objItem.StartMode) Then
                     ERRCount = ERRCount + 1
                     ERRArray.Add Cstr(ERRCount), "SERVICE ERROR: " & objItem.DisplayName & " service start type should be " & ExpectedStartType
               End If
	Next
End Sub


'*************************************************************************************
'
'
' Main function of the program.
'
'
'*************************************************************************************

ERRCount = 0
' Print Version of VSSPSS
WScript.Echo strversion

Set objWMIService = GetObject("winmgmts:" _
 & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
 
Set colOSes = objWMIService.ExecQuery("Select * from Win32_OperatingSystem")

WScript.Echo 
WScript.Echo "----------------------------------------------------------"
WScript.Echo "Physical Disk Information"
WScript.Echo "----------------------------------------------------------"

Set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_DiskDrive")

   For Each objItem In colItems 
      WScript.Echo "Model:           " & objItem.Model 
      WScript.Echo "Name:            " & objItem.Name 
      WScript.Echo "BytesPerSector:  " & objItem.BytesPerSector
      WScript.Echo "Signature:       " & Hex(objItem.Signature)
      WScript.Echo 
    If (objItem.BytesPerSector = "4096") then
	ERRCount = ERRCount + 1
                ERRArray.Add Cstr(ERRCount), " 4k Advanced Format Disks are not supported as backup destination. (See KB2510009). "
    End If

Next

WScript.Echo 
WScript.Echo "----------------------------------------------------------"
WScript.Echo "MountVol Information"
WScript.Echo "----------------------------------------------------------"

SSet SWBemlocator = CreateObject("WbemScripting.SWbemLocator")
Set objWMIService = SWBemlocator.ConnectServer(strComputer,"root\CIMV2",UserName,Password)
Set colItems = objWMIService.ExecQuery("Select * from Win32_Mountpoint")
For Each objItem in colItems
     WScript.Echo "Directory    : " & objItem.Directory
     WScript.Echo "Free Space: " & objItem.FreeSpace
     strVol = Right(objItem.volume,Len(objItem.volume)-23)
     strVol = Left(strVol,Len(strVol)-1)
     WScript.Echo "strVol=" & strVol

     Set colVolItems = objWMIService.ExecQuery("Select * from Win32_Volume where DeviceID = '" & strVol & "'")
     For Each objvItem in colVolItems
          
          WScript.Echo "Drive Letter : " & objvItem.DriveLetter
          WScript.Echo "Device ID    : " & objvItem.DeviceID
          
     Next
     
     WScript.Echo
     
Next

'
' Listing VSS providers 
'
WScript.Echo 
WScript.Echo "----------------------------------------------------------"
WScript.Echo "VSS Providers"
WScript.Echo "----------------------------------------------------------"

Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
Set colItems = objWMIService.ExecQuery("Select * from Win32_ShadowProvider",,48)
For Each objItem in colItems
    WScript.Echo "Provider Name  : " & objItem.Name    
    WScript.Echo "Provider CLSID : " & objItem.CLSID
    WScript.Echo "Provider ID    : " & objItem.ID
    WScript.Echo "Description    : " & objItem.Description
    srtCLSID = objItem.CLSID
    If (Ucase (srtCLSID) <> "{65EE1DBA-8FF4-4A58-AC1C-3470EE2F376A}") then
	ERRCount = ERRCount + 1
                ERRArray.Add Cstr(ERRCount), " Configure the backup utility to use the in-box Volume Shadow Copy provider (see KB941956) "
    End If

Next 

WScript.Echo 
WScript.Echo "----------------------------------------------------------"
WScript.Echo "Listing Shadow Copy Storage"
WScript.Echo "----------------------------------------------------------"

Set objWMIService = GetObject("winmgmts:" & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")

Set colItems = objWMIService.ExecQuery("Select * from Win32_ShadowStorage")

For Each objItem in colItems
    WScript.Echo "Volume              : " & objItem.Volume
    WScript.Echo "Allocated space     : " & objItem.AllocatedSpace
    WScript.Echo "Differential volume : " & objItem.DiffVolume
    WScript.Echo "Maximum space       : " & objItem.MaxSpace
    WScript.Echo "Used space          : " & objItem.UsedSpace
	WScript.Echo 
Next

WScript.Echo 
WScript.Echo "----------------------------------------------------------"
WScript.Echo "Service Status"
WScript.Echo "----------------------------------------------------------"

call ListServiceStatus("VSS", "Manual")
call ListServiceStatus("SWPRV", "Manual")
call ListServiceStatus("EventSystem", "Auto")
call ListServiceStatus("COMSysApp", "Manual")
call ListServiceStatus("CryptSvc", "Auto")
call ListServiceStatus("VDS", "Manual")
call ListServiceStatus("DpmWriter", "Auto")
call ListServiceStatusApps("SQLWriter", "Auto")

WScript.Echo 
WScript.Echo "----------------------------------------------------------"
WScript.Echo "Virtualization"
WScript.Echo "----------------------------------------------------------"


Set objWMIService = GetObject("winmgmts:" & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\virtualization")

Set VmList = objWMIService.ExecQuery("Select * from Msvm_ComputerSystem")

For Each vm in VmList
    WScript.Echo "MachineType  : " & vm.Description
    WScript.Echo "Name         : " & vm.ElementName
    WScript.Echo 
Next

WScript.Echo 
WScript.Echo "----------------------------------------------------------"
WScript.Echo "Disk Events"
WScript.Echo "----------------------------------------------------------"

Set objWMIService = GetObject("winmgmts:" & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
call ListErrorEvents(9, objWMIService)
call ListErrorEvents(11, objWMIService)
call ListErrorEvents(15, objWMIService)
call ListErrorEvents(50, objWMIService)
call ListErrorEvents(51, objWMIService)
call ListErrorEvents(55, objWMIService)
call ListErrorEvents(57, objWMIService)

' Close Progress bar

pb.Close() 

'' SIG '' Begin signature block
'' SIG '' MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' MUmq92fAzGuKfxgwdQx6MqJ3nrBMKHWDrNA3JU+nlqeg
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
'' SIG '' AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCsOq9uTLbceoOr
'' SIG '' DTYEGYmRoX2JD7CnIvwlrehOHt0bWTBEBgorBgEEAYI3
'' SIG '' AgEMMTYwNKAUgBIATQBpAGMAcgBvAHMAbwBmAHShHIAa
'' SIG '' aHR0cHM6Ly93d3cubWljcm9zb2Z0LmNvbSAwDQYJKoZI
'' SIG '' hvcNAQEBBQAEggEAIiUuOl66ZVGrLAmhoz7vl5xZUpWo
'' SIG '' 4H8jf1hphTGYpLz7MThMZYYHdaouG8U2owk7P1g9NCaL
'' SIG '' LDMr/zQ57SI/KiAj5h3NknTewNDbipM+tEHHK72pPhqb
'' SIG '' MtmyBfVyGcUMKt5Yt8jbdeAStCDqHVcEyTMKhh0aVFBP
'' SIG '' PImz+jiDelze6wrsDND13aRp/OEmTmeKhjwRVwv4af8f
'' SIG '' SCUD5/5Ysh1o2AtQJMwXh84pIat/IeXWqn3Olzt0SWlC
'' SIG '' TkZh1Gai37HBcnk4QfeNTxDbrLrkRDmQge6I1LXcDZhH
'' SIG '' ePBSShK2y4ANNUxJIyOw8/8Fjp6QAbdCk2vKw7HzdSUe
'' SIG '' So7Rc6GCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCCFuUG
'' SIG '' CSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUD
'' SIG '' BAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIB
'' SIG '' OAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUA
'' SIG '' BCBXUk+VCCwem3ymWqo18gUwcUpvCzdyttOcHGGu8XDP
'' SIG '' mAIGYhZtksmHGBMyMDIyMDMyODE2NTYwOS4yMjlaMASA
'' SIG '' AgH0oIHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UE
'' SIG '' CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
'' SIG '' MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUw
'' SIG '' IwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRp
'' SIG '' b25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo3QkYx
'' SIG '' LUUzRUEtQjgwODElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
'' SIG '' bWUtU3RhbXAgU2VydmljZaCCEVQwggcMMIIE9KADAgEC
'' SIG '' AhMzAAABnytFNRUILktdAAEAAAGfMA0GCSqGSIb3DQEB
'' SIG '' CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
'' SIG '' aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
'' SIG '' ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
'' SIG '' HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4X
'' SIG '' DTIxMTIwMjE5MDUyMloXDTIzMDIyODE5MDUyMlowgcox
'' SIG '' CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
'' SIG '' MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
'' SIG '' b3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jv
'' SIG '' c29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsT
'' SIG '' HVRoYWxlcyBUU1MgRVNOOjdCRjEtRTNFQS1CODA4MSUw
'' SIG '' IwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
'' SIG '' aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
'' SIG '' AgEApPV5fE1RsomQL85vLQeHyz9M5y/PN2AyBtN47Nf1
'' SIG '' swmiAlw7NJF5Sd/TlGcHgRWv1fJdu5pQY8i2Q7U4N1vH
'' SIG '' UDkQ7p35+0s2RKBZpV2kmHEIcgzFeYIcYupYfMtzVdUz
'' SIG '' RxmC82qEJrQXrhUpRB/cKeqwv7ESuxj6zp9e1wBs6Pv8
'' SIG '' hcuw31oCEON19+brdtE0oVHmA67ORjlaR6e6LqkGEU6b
'' SIG '' vpQGgh36vLa/ixaiMo6ZL8cW9x3MelY7XtDTx+hpyAk/
'' SIG '' OD8VmCu3qGuQMW7E1KlkMolraxqMkMlz+MiCn01GD7bE
'' SIG '' xQoteIriTa98kRo6OFNTh2VNshplngq3XHCYJG8upNje
'' SIG '' QIUWLyh63jz4eaFh2NNYPE3JMVeIeIpaKr2mmBodxwz1
'' SIG '' j8OCqCshMu0BxrmStagJIXloil9qhNHjUVrppgij4XXB
'' SIG '' d3XFYlSPWil4bcuMzO+rbFI3HQrZxuVSCOnlOnc3C+mB
'' SIG '' adLzJeyTyN8vSK8fbARIlZkooDNkw2VOEVCGxSLQ+tAy
'' SIG '' WMzR9Kxrtg79/T/9DsKMd+z92X7weYwHoOgfkgUg9GsI
'' SIG '' vn+tSRa1XP1GfN1vubYCP9MXCxlhwTXRIm0hdTRX61dC
'' SIG '' jwin4vYg9gZEIDGItNgmPBN7rPlMmAODRWHFiaY2nASg
'' SIG '' AXgwXZGNQT3xoM7JGioSBoXaMfUCAwEAAaOCATYwggEy
'' SIG '' MB0GA1UdDgQWBBRiNPLVHhMWK0gOLujf2WrH1h3IYTAf
'' SIG '' BgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
'' SIG '' BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jv
'' SIG '' c29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
'' SIG '' aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
'' SIG '' KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8v
'' SIG '' d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01p
'' SIG '' Y3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEw
'' SIG '' KDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoG
'' SIG '' CCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4ICAQAdiigp
'' SIG '' PDvpGfPpvWz10CAJqPusWyg2ipDEd//NgPF1QDGvUaSL
'' SIG '' WCZHZLWvgumSFQbGRAESZCp1qWCYoshgVdz5j6CDD+cx
'' SIG '' W69AWCzKJQyWTLR9zIn1QQ/TZJ2DSoPhm1smgD7PFWel
'' SIG '' A9wkc46FWdj2x0R/lDpdmHP3JtSEdwZb45XDcMpKcwRl
'' SIG '' J3QEXn7s430UnwfnQc5pRWPnTBPPidzr73jK2iHM50q5
'' SIG '' a+OhlzKFhibdIQSTX+BuSWasl3vJ/M9skeaaC9rojEc6
'' SIG '' iF19a8AiF4XCzxYEijf7yca8R4hfQclYqLn+IwnA/Dtp
'' SIG '' jveLaAkqixEbqHUnvXUO6qylQaJw6GFgMfltFxgF9qmq
'' SIG '' GZqhLp+0G/IZ8jclaydgtn2cAGNsol92TICxlK6Q0aCV
'' SIG '' nT/rXOUkuimdX8MoS/ygII4jT71AYruzxeCx8eU0RVOx
'' SIG '' 2V74KWQ5+cZLZF2YnQOEtujWbDEsoMdEdZ11d8m2NyXZ
'' SIG '' TX0RE7ekiH0HQsUV+WFGyOTXb7lTIsuaAd25X4T4DScq
'' SIG '' NKnZpByhNqTeHPIsPUq2o51nDNG1BMaw5DanMGqtdQ88
'' SIG '' HNJQxl9eIJ4xkW4IZehy7A+48cdPm7syRymT8xnUyzBS
'' SIG '' qEnSXleKVP7d3T23VNtR0utBMdiKdk3Rn4LUvTzs1Wkw
'' SIG '' OFLnLpJW42ZEIoX4NjCCB3EwggVZoAMCAQICEzMAAAAV
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
'' SIG '' VGhhbGVzIFRTUyBFU046N0JGMS1FM0VBLUI4MDgxJTAj
'' SIG '' BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZp
'' SIG '' Y2WiIwoBATAHBgUrDgMCGgMVAHRdrpgf8ssMRSxUwvKy
'' SIG '' fRb/XPa3oIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
'' SIG '' BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
'' SIG '' bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
'' SIG '' bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
'' SIG '' UENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDl68OKMCIY
'' SIG '' DzIwMjIwMzI4MTMxODAyWhgPMjAyMjAzMjkxMzE4MDJa
'' SIG '' MHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOXrw4oCAQAw
'' SIG '' BwIBAAICAc0wBwIBAAICE4QwCgIFAOXtFQoCAQAwNgYK
'' SIG '' KwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
'' SIG '' AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUF
'' SIG '' AAOBgQDCsXixv7Csg8rouLldm4kqgXHWanULq5ERPMSJ
'' SIG '' fUUOE+jvR406mCCvXYJCbFzUuKVMpOoWZVStsmfc63sV
'' SIG '' Hf1/r8khj5a12+c/FOw6Tx1Nu+CxLAsrS+F6YRMny/3j
'' SIG '' /IHME+iKlp56bVRiAsvyHwiPlna5Uhrr5wS4UFXvHHUc
'' SIG '' /TGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMw
'' SIG '' EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
'' SIG '' b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
'' SIG '' b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
'' SIG '' IFBDQSAyMDEwAhMzAAABnytFNRUILktdAAEAAAGfMA0G
'' SIG '' CWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYL
'' SIG '' KoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIMho/LQX
'' SIG '' KTtLupRRdb1Ukb8fLyK3q0V2sl78SyuU2ElVMIH6Bgsq
'' SIG '' hkiG9w0BCRACLzGB6jCB5zCB5DCBvQQghvFeKaIniZ6l
'' SIG '' 51c8DVHo3ioCyXxB+z/o7KcsN0t8XNowgZgwgYCkfjB8
'' SIG '' MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
'' SIG '' bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
'' SIG '' cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
'' SIG '' b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAZ8r
'' SIG '' RTUVCC5LXQABAAABnzAiBCBb+eaJ2ZpdhfeFQY2QKBER
'' SIG '' R4XxsHtT/q+HaxBR5a9DSDANBgkqhkiG9w0BAQsFAASC
'' SIG '' AgCN6AxlzEARXYf4/8pW9nSwdW1QtX/f2V6fjE8JqiyF
'' SIG '' eCG3csPZVVcbm/FpOKrXdSSP3H8aNNiasDC2xkCYwz2u
'' SIG '' 7bScbp6Jl/H2d82D2CdW7TL2tl/taFRJhaaMirttJKIF
'' SIG '' MfxR/mcOoDgtTSBBlbWCUlZwP1UaPm1wS0ydgbdItbEM
'' SIG '' lYGoaZxA9Q6IFHApEb1mcK5mKAuZhFGMAZf1Fps0ndZv
'' SIG '' gc0nAb5BF5R109oCZrllSElYnM3WTzSmf9TRN5M02Twq
'' SIG '' U24nS8F0Sedeqz1DUbS//w94+7or41ue0XzyN+3y+j1J
'' SIG '' THKSXbgTaV7o0hsdWjDMT4L23MMEJqWf+z9gZck17lEm
'' SIG '' YCV5gJCXk/Zr/2w6LV7Mxd1xOIkiwg/oBhjL9yWiD2iB
'' SIG '' wKgRgv2i9z703N7c5YymyDqrFm9Fo8WrMrSXmsrY7mXh
'' SIG '' 8WyY+qkQJh814ja+1wbi7dAUd+Y6qcXTLZP6nDcBexNm
'' SIG '' rPkoVcIECW96gnVNcGELqj2UDp63Na2Xb3OaYOisEiSe
'' SIG '' KLaBsWSerUKHGxWnv0LaIoUIe/Tc9T8b5JKPPvbQ/Vno
'' SIG '' MHh5dhMVAOB+n/ZzlG3zAMY5qfi7BuHpFRMWgLQitCKB
'' SIG '' UiVZbJ8nUb3KfRbzl2Hta9fyeG7oVH31pRFkgRYqRuFR
'' SIG '' 5tuKp//T8ei9gtTXhYhsDLS3Xg==
'' SIG '' End signature block
