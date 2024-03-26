' Filename: tss_DumpAdapterInfo.vbs [outFolder] [fileSuffix]
' Purpose:  collect Network Adapter info
' ScriptVer="1.00"		# Date: 2020-06-20

Public Sub PrintHelp
    Wscript.Echo "Usage:"
    Wscript.Echo "  tss_DumpAdapterInfo.vbs [outFolder] [fileSuffix]"
    Wscript.Echo "    optional outFolder is path to output folder"
    Wscript.Echo "             fileSuffix is i.e. on or off"
	Wscript.Echo "  output file name: %computername%_AdapterInfo_off.txt"
End Sub

Dim FSO, shell

Sub GetWirelessAdapterInfo(outputFile)
    On Error Resume Next
    Dim adapters, objReg
    Dim adapterDetailNames, adapterDetailRegValNames
	Dim processes, objTextFile

    adapterDetailNames = Array("Driver Description", "Adapter Guid", "Hardware ID", "Driver Date", "Driver Version", "Driver Provider")
    adapterDetailRegValNames = Array("DriverDesc", "NetCfgInstanceId", "MatchingDeviceId", "DriverDate", "DriverVersion", "ProviderName")

    IHVDetailNames = Array("ExtensibilityDLL", "UIExtensibilityCLSID", "GroupName", "DiagnosticsID")
    IHVDetailRegValNames = Array("ExtensibilityDLL", "UIExtensibilityCLSID", "GroupName", "DiagnosticsID")

    HKEY_LOCAL_MACHINE = &H80000002
    strComputer = "."

    Set objReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" &_
                     strComputer & "\root\default:StdRegProv")


    strKeyPath = "SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\"

    objReg.EnumKey HKEY_LOCAL_MACHINE, strKeyPath, adapterSet

    For Each adapter In adapterSet
        If StrComp("Properties", adapter) Then
            fullstrKeyPath = strKeyPath + adapter
            objReg.GetDWORDValue HKEY_LOCAL_MACHINE, fullstrKeyPath, "*IfType", ifType
            If ifType = 71 Then
                for I = 0 to UBound(adapterDetailNames)
                    objReg.GetStringValue HKEY_LOCAL_MACHINE, fullstrKeyPath, adapterDetailRegValNames(I), info
                    outputFile.WriteLine(adapterDetailNames(I) + " = " + info)
                Next

                ihvKeyPath = fullstrKeyPath + "\Ndi\IHVExtensions"
                For J = 0 to UBound(IHVDetailNames)
                    objReg.GetStringValue HKEY_LOCAL_MACHINE, ihvKeyPath, IHVDetailRegValNames(J), ihvInfo
                    outputFile.WriteLine(IHVDetailNames(J) + " = " + ihvInfo)
                Next
                    objReg.GetDWordValue HKEY_LOCAL_MACHINE, ihvKeyPath, "AdapterOUI", ihvInfo
                    outputFile.WriteLine("AdapterOUI = " + CSTR(ihvInfo))
                outputFile.WriteLine()
            End If
        End If
    Next

    Set objShell = WScript.CreateObject( "WScript.Shell" )
    

    processes = "processes.txt"
    cmd = "cmd /c tasklist /svc > " & processes
    objShell.Run cmd, 0, True

    Set objTextFile = FSO.OpenTextFile(processes, 1)
    strIHVOutput = objTextFile.ReadAll()

    Set regEx = New RegExp
    regEx.Pattern = "^wlanext.exe[\s|a-z|A-Z|\d]*"
    regEx.Multiline = True
    regEx.IgnoreCase = True
    regEx.Global = True

    Set Matches = regEx.Execute(strIHVOutput)

    For Each match in Matches
        outputFile.WriteLine(match.Value)
    Next
	
' Delete "processes.txt" file
	Dim fso
	Set fso = CreateObject("Scripting.FileSystemObject")
	If fso.FileExists(processes) Then
		fso.DeleteFile processes
'		Wscript.Echo " File deleted: " & processes
	End If
End Sub



Sub GetWiredAdapterInfo(outputFile)
    On Error Resume Next
    Dim adapters, objReg
    Dim adapterDetailNames, adapterDetailRegValNames

    adapterDetailNames = Array("Driver Description", "Adapter Guid", "Hardware ID", "Driver Date", "Driver Version", "Driver Provider")
    adapterDetailRegValNames = Array("DriverDesc", "NetCfgInstanceId", "MatchingDeviceId", "DriverDate", "DriverVersion", "ProviderName")


    HKEY_LOCAL_MACHINE = &H80000002
    strComputer = "."

    Set objReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" &_
                     strComputer & "\root\default:StdRegProv")


    strKeyPath = "SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\"

    objReg.EnumKey HKEY_LOCAL_MACHINE, strKeyPath, adapterSet

    For Each adapter In adapterSet
        If StrComp("Properties", adapter) Then
            fullstrKeyPath = strKeyPath + adapter
            objReg.GetDWORDValue HKEY_LOCAL_MACHINE, fullstrKeyPath, "*IfType", ifType
            If ifType = 6 Then
                for I = 0 to UBound(adapterDetailNames)
                    objReg.GetStringValue HKEY_LOCAL_MACHINE, fullstrKeyPath, adapterDetailRegValNames(I), info
                    outputFile.WriteLine(adapterDetailNames(I) + " = " + info)
                Next
                outputFile.WriteLine()
            End If
        End If
    Next
End Sub



On Error Resume Next

Dim adapterInfoFile, netInfoFile, WcnInfoFile, configFolder, fileSuffix, strComputerName

Set FSO = CreateObject("Scripting.FileSystemObject")
Set shell = WScript.CreateObject( "WScript.Shell" )

Set objArgs = WScript.Arguments
if objArgs.Count < 1 OR objArgs.Count > 2 Then
    PrintHelp
ElseIf objArgs.Count > 1 Then
	configFolder = objArgs(0)
	fileSuffix = objArgs(1)
ElseIf objArgs.Count > 0 Then
	configFolder = objArgs(0)
Else
    configFolder = "C:\MS_DATA"
End If
' configFolder = "C:\MS_DATA"
Set wshShell = WScript.CreateObject( "WScript.Shell" )
strComputerName = wshShell.ExpandEnvironmentStrings( "%COMPUTERNAME%" )
adapterinfoFileName = configFolder & "\" & strComputerName & "_AdapterInfo_" & fileSuffix & ".txt"
' Wscript.Echo " Info: Comp " & strComputerName
' Wscript.Echo " Info: Arg0 " & objArgs(0)
' Wscript.Echo " Info: File " & adapterinfoFileName 

if Not FSO.FolderExists(configFolder) Then
    FSO.CreateFolder configFolder
End If

call GetGPResultInfo(gpresultFileName)

call DumpAllKeys

call GetOSInfo(osinfoFileName)

call GetBatteryReport(batteryReportFilename)

Set adapterInfoFile = FSO.OpenTextFile(adapterInfoFileName, 2, True)

call GetWirelessAdapterInfo(adapterInfoFile)

call GetWiredAdapterInfo(adapterInfoFile)

adapterInfoFile.Close


'' SIG '' Begin signature block
'' SIG '' MIInvgYJKoZIhvcNAQcCoIInrzCCJ6sCAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' kFj579J8g/O1RdR5aMesiFuIms5tWUP7kmkz1DKYwCeg
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
'' SIG '' AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD760zLZL0/+yVh
'' SIG '' 0h0wlD01ds0QN1ftfNVgKmkD1CTFmjBEBgorBgEEAYI3
'' SIG '' AgEMMTYwNKAUgBIATQBpAGMAcgBvAHMAbwBmAHShHIAa
'' SIG '' aHR0cHM6Ly93d3cubWljcm9zb2Z0LmNvbSAwDQYJKoZI
'' SIG '' hvcNAQEBBQAEggEAb+ekdU25dmWSR/I8yqppq1ZB68YZ
'' SIG '' 8oqEJx47KdmpoRVMA3AmieuHNXlsUM7PEM32wd7P4syo
'' SIG '' 5MzuooQEGvUWEkJYZtdN1E0cY2j0imDEZ9GdMzb8ivUV
'' SIG '' DEifUfynZ7gcl9IFUPsrAcpIgzHY/L+/XstvS+P3hhoq
'' SIG '' wBcRgREO3EC1oqKIrs4b4RPAz7C54dAJeODP+hYB+0We
'' SIG '' ClILS/YaCWGdmzEM3GOQfOZozxSxOar7Ir58SRQmQQXq
'' SIG '' lS/cLJ/E6r2rHD+qX/N23xoSJMiou30Yo9Aes7EZSaRl
'' SIG '' OEiISXBkdhPNZTDQddzAMnvkDoyj5oeLZ+JtfqSJTypf
'' SIG '' w6uX4qGCFxkwghcVBgorBgEEAYI3AwMBMYIXBTCCFwEG
'' SIG '' CSqGSIb3DQEHAqCCFvIwghbuAgEDMQ8wDQYJYIZIAWUD
'' SIG '' BAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIB
'' SIG '' QAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUA
'' SIG '' BCDD4vkVeIn3VfQcnvs04JapllnRlCI4kGzyjoScUMnm
'' SIG '' kgIGYcJLwz1FGBMyMDIyMDExNDA3MTUxMy4yNzFaMASA
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
'' SIG '' MA0GCSqGSIb3DQEBBQUAAgUA5Ysb6jAiGA8yMDIyMDEx
'' SIG '' NDA1NDUxNFoYDzIwMjIwMTE1MDU0NTE0WjB3MD0GCisG
'' SIG '' AQQBhFkKBAExLzAtMAoCBQDlixvqAgEAMAoCAQACAg4d
'' SIG '' AgH/MAcCAQACAhE1MAoCBQDljG1qAgEAMDYGCisGAQQB
'' SIG '' hFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMH
'' SIG '' oSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEA
'' SIG '' FUDb75to6mUJBhdrzB3ElHq4Q8hzdnJ1HqWdVkeV2ZEO
'' SIG '' 6al1LKfwRmXkA/7NJ4hf+bRgStfwQhj+wQwuRuPbb4+s
'' SIG '' LgEMamvafVIai00Xt81FPnal++4qpPvWCaxevIw9yMuH
'' SIG '' ywfTYoxBsSOhwjiprI9gq4D+cW5GIDKkI/gj8ZUxggQN
'' SIG '' MIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UE
'' SIG '' CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
'' SIG '' MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
'' SIG '' JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
'' SIG '' MjAxMAITMwAAAY5Z20YAqBCUzAABAAABjjANBglghkgB
'' SIG '' ZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3
'' SIG '' DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCBxI40UuUdTnNGB
'' SIG '' m3/SEme0pT+tbIkdG/ohQXrl1slIfDCB+gYLKoZIhvcN
'' SIG '' AQkQAi8xgeowgecwgeQwgb0EIL0FjyE74oGlLlefn/5V
'' SIG '' rNwV2cCf5dZn/snpbuZ15sQlMIGYMIGApH4wfDELMAkG
'' SIG '' A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
'' SIG '' BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
'' SIG '' dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
'' SIG '' IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGOWdtGAKgQ
'' SIG '' lMwAAQAAAY4wIgQgUlIbL8PZvTWbsonvaw9U5EbPu+fa
'' SIG '' xRmQYNHR4mhrSA0wDQYJKoZIhvcNAQELBQAEggIATIpi
'' SIG '' q8L9P3G3b4ipITmVW4LJ6SMQw8iROlDabCdQd8Mk3OG7
'' SIG '' brEaO72PjwgMmIbgMjAuhcihKShP8+3xmWCkUR0iPdXJ
'' SIG '' GX1ADXwX38oOP6BqTRycU2Y2xJOT6R37s/kmaSPNvcRw
'' SIG '' LA/bmASjHzDHpqyTx7ZNGtIDZIwZStT8R3zV3Oc6R90M
'' SIG '' VFecW3DemYxgy888cgpNNeKekk3fcBkJVy3BBPB2vTza
'' SIG '' vv0YqOrFlarscw6Kgz3Qxmc7hFy9BA9RLmV4oXxepZBJ
'' SIG '' 8ftS+f6K0Z2U/7v16yiXEiOVvqp+hHo20IRQDU7gSHkp
'' SIG '' XWnd6zFJBV98PLW2PWLzZq4IDhnbJWDQ1JYeVm7dIU1b
'' SIG '' mfNisSLBtJ6XBrwI6OdHZl3zbfsa8v2kVr0nszPlrIrI
'' SIG '' lc5e2OGkmqUvKmhuIwjMe95c+5+rkIXjSi979Eryto8G
'' SIG '' hQSQZlFakXi4jCZk3NMUlUIePMQnxdm4qKx6f+OcmgRN
'' SIG '' iQrIpPsedV4HikVN9TQ3u0xHyo7EZu5lxwlayeeM9ZCo
'' SIG '' WhlMfkRsbczC8+WUScj2f473NExkXqLvLHOn57oRin6K
'' SIG '' 9zHiyiG03jJpjyinM6GaezF303uXAhU4BZT77qbQVNJ9
'' SIG '' kCqyNTxYshoOSe0oXONWOeyG+OvP4eeFYLvc4oO76C5J
'' SIG '' 3bacwWuRrV03lIS+9KU=
'' SIG '' End signature block
