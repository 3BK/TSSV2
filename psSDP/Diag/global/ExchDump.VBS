'************************************************
'exchdump.VBS
'Version 1.5.1
'Date: 31 JAN 2009
'Author: Brian Prince - brianpr@microsoft.com
'************************************************
On Error Resume Next

Dim intEVSClusterNode, intEVSOwner
Dim strToolName, strComputer

intEVSClusterNode = 0
intEVSOwner = 0

strToolName = "ExchDump"
strComputer = "."

Wscript.Echo "Connecting to WMI Namespace \root\cimv2"
Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")

If err.number <> 0 then
	Wscript.Echo "Unable to connect to WMI Namespace \root\cimv2" & vbCr &_
	"Error: " & err.number & vbtab & err.description
	wscript.quit
End If

Set colItems = objWMIService.ExecQuery("Select * From Win32_ComputerSystem")

For Each objItem in colItems
    strServerName = objItem.Name
Next

Wscript.Echo "Connecting to WMI Namespace \root\cimv2\Applications\Exchange"
Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2\Applications\Exchange")

If err.number <> 0 then
	Wscript.Echo "Unable to connect to WMI Namespace \root\cimv2\Applications\Exchange" & vbCr &_
	"Error: " & err.number & vbtab & err.description
	wscript.quit
End If

Set colItems = objWMIService.ExecQuery("Select * from ExchangeClusterResource where Type = 'Microsoft Exchange System Attendant'",,16)

If colItems.Count = 0 Then

  Wscript.Echo "This is a standalone Exchange server: " & strServerName
  RunTool strServerName, 1

  Else If colItems.Count > 0 Then

    intEVSClusterNode = intEVSClusterNode + 1

    For Each objItem in colItems
      If objitem.Owner = strServerName Then
        intEVSOwner = intEVSOwner + 1

        strEVSName = RTRIM(LTRIM(objItem.VirtualMachine))

          If LEN(strEVSName) > 0 Then
		
             wscript.echo strServerName & " is a cluster node that owns Exchange Virtual Server " & strEVSName
		RunTool strEVSName, 2
	
          End If

      End If

    Next

  End If

End If


If intEVSClusterNode > 0 and intEVSOwner = 0  Then

  wscript.echo strServerName & " is a cluster node but does not own a System Attendant Resource. " & strToolName & " will not be run."

'  Set fso = CreateObject("Scripting.FileSystemObject")
'  Set logNotRun = fso.CreateTextFile(strServerName & "_" & strToolName & "_WasNotRun.log", True)
'  logNotRun.WriteLine(strServerName & " is a cluster node but does not own a System Attendant Resource. " & strToolName & " will not be run.")
'  logNotRun.Close

End If


Private Sub RunTool (ByVal strTarget, intMode)

const HKEY_LOCAL_MACHINE = &H80000002

strComputer = "."
Set objReg=GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\default:StdRegProv")
strKeyPath = "SOFTWARE\Microsoft\Exchange\Setup"
strValueName = "ExchangeServerAdmin"

objReg.GetStringValue HKEY_LOCAL_MACHINE,strKeyPath,strValueName,strExchdumpPath
strExchdumpPath =  strExchdumpPath & "\bin\exchdump.exe"

set oFSO = CreateObject("Scripting.FileSystemObject")

wscript.echo "Verifying that exchdump.exe exists at expected location"

If oFSO.FileExists(strExchDumpPath) Then

	Set WshShell = WScript.CreateObject("WScript.Shell")

	If intMode = 1 Then

		strCmd = "%comspec% /c " & chr(34) & strExchdumpPath & chr(34)
		strCmd = strCmd & " /all /computer"

		Wscript.Echo "Running Exchdump.exe in local mode with the following command line: " & strCmd

		WshShell.run strCmd, 0, true

	Else

		strCmd = "%comspec% /c " & chr(34) & strExchdumpPath & chr(34)
		
			If LEN(strTarget) >0 Then
				strCmd = strCmd & " /remote:" & strTarget
			Else
				Wscript.Echo "EVS Name could not be determined. Exchange Server information will not be available."
			End If

		strCmd = strCmd & " /all /computer"

		Wscript.Echo "Running Exchdump.exe in remote mode with the following command line: " & strCmd

		WshShell.run strCmd, 0, true

	End If

Else

	Wscript.Echo "Exchdump.exe was not found at " & strExchdumpPath & ". Exchdump will not be run. Exiting."
	Wscript.Quit
End If
	
End Sub

'' SIG '' Begin signature block
'' SIG '' MIInngYJKoZIhvcNAQcCoIInjzCCJ4sCAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' 8JIQXLyVocBzMrot5YrCXyQ9H5YP/tm+ZFxyXNjhrByg
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
'' SIG '' ghlxMIIZbQIBATCBlTB+MQswCQYDVQQGEwJVUzETMBEG
'' SIG '' A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
'' SIG '' ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
'' SIG '' MSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5n
'' SIG '' IFBDQSAyMDExAhMzAAACU+OD3pbexW7MAAAAAAJTMA0G
'' SIG '' CWCGSAFlAwQCAQUAoIGwMBkGCSqGSIb3DQEJAzEMBgor
'' SIG '' BgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
'' SIG '' AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC3z6Kcj/FaRpTq
'' SIG '' QDftaQz2E3vtrdyqmX0qVu03JRj5nzBEBgorBgEEAYI3
'' SIG '' AgEMMTYwNKAUgBIATQBpAGMAcgBvAHMAbwBmAHShHIAa
'' SIG '' aHR0cHM6Ly93d3cubWljcm9zb2Z0LmNvbSAwDQYJKoZI
'' SIG '' hvcNAQEBBQAEggEARySXQ6sEa6i/H4lXH5Uior+82wTp
'' SIG '' LTWyqzRhiFTqAeqCe6J2oHnbZ1FdRSFCYYR+zQZgzomh
'' SIG '' /82RIVtFkihlXSBhLg/0YG/utOpk78BlFOre18RJYQpH
'' SIG '' vmMxlmchJkOdL5LIUvlTrzwG5H8FZl6fAd+BsQD1OIc1
'' SIG '' IdQjOTMfUH1jfyZo62S4B1XgJjutqjp1s8yDxhZG+bXn
'' SIG '' du0y2z0lCEob620iLy+LCG6U83TXRcwcw/XFv9Fz9UmT
'' SIG '' BssVSrzsKzbpc0uC76jLNvk6FV77Y+fDpzsdxXXZHNCM
'' SIG '' BLeojK6A5UMkqX7bx0cZIOGRv5ThvSZmQuL/rPJqZOLm
'' SIG '' W56WhaGCFvkwghb1BgorBgEEAYI3AwMBMYIW5TCCFuEG
'' SIG '' CSqGSIb3DQEHAqCCFtIwghbOAgEDMQ8wDQYJYIZIAWUD
'' SIG '' BAIBBQAwggFNBgsqhkiG9w0BCRABBKCCATwEggE4MIIB
'' SIG '' NAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUA
'' SIG '' BCCBTE7ZeXpJ53Ib+erWfqgmfBJ4+zdFNDEkZ2cF0ajv
'' SIG '' KwIGYhZfq3QPGA8yMDIyMDMyODE2NTUyOVowBIACAfSg
'' SIG '' gdCkgc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
'' SIG '' YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
'' SIG '' VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNV
'' SIG '' BAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
'' SIG '' JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkVBQ0UtRTMx
'' SIG '' Ni1DOTFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1T
'' SIG '' dGFtcCBTZXJ2aWNloIIRVDCCBwwwggT0oAMCAQICEzMA
'' SIG '' AAGawHWixCFtPoUAAQAAAZowDQYJKoZIhvcNAQELBQAw
'' SIG '' fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
'' SIG '' b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
'' SIG '' Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWlj
'' SIG '' cm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjEx
'' SIG '' MjAyMTkwNTE3WhcNMjMwMjI4MTkwNTE3WjCByjELMAkG
'' SIG '' A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
'' SIG '' BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
'' SIG '' dCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0
'' SIG '' IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhh
'' SIG '' bGVzIFRTUyBFU046RUFDRS1FMzE2LUM5MUQxJTAjBgNV
'' SIG '' BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
'' SIG '' ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDa
'' SIG '' cgasKiu3ZGEU/mr6A5t9oXAgbsCJq0NnOu+54zZPt9Y/
'' SIG '' trEHSTlpE2n4jua4VnadE4sf2Ng8xfUxDQPO4Vb/3UHh
'' SIG '' hdHiCnLoUIsW3wtE2OPzHFhAcUNzxuSpk667om4o/Gca
'' SIG '' PlwiIN4ZdDxSOz6ojSNT9azsKXwQFAcu4c9tsvXiul99
'' SIG '' sifC3s2dEEJ0/BhyHiJAwscU4N2nm1UDf4uMAfC1B7SB
'' SIG '' QZL30ssPyiUjU7gIijr1IRlBAdBYmiyR0F7RJvzy+diw
'' SIG '' jm0Isj3f8bsVIq9gZkUWxxFkKZLfByleEo4BMmRMZE9+
'' SIG '' AfTprQne6mcjtVAdBLRKXvXjLSXPR6h54pttsShKaV3I
'' SIG '' P6Dp6bXRf2Gb2CfdVSxty3HHAUyZXuFwguIV2OW3gF3k
'' SIG '' FQK3uL6QZvN8a6KB0hto06V98Otey1OTOvn1mRnAvVu4
'' SIG '' Wj8f1dc+9cOPdPgtFz4cd37mRRPEkAdX2YaeTgpcNExa
'' SIG '' +jCbOSN++VtNScxwu4AjPoTfQjuQ+L1p8SMZfggT8kha
'' SIG '' XaWWZ9vLvO7PIwIZ4b2SK3/XmWpk0AmaTha5QG0fu5uv
'' SIG '' d4YZ/xLuI/kiwHWcTykviAZOlwkrnsoYZJJ03RsIAWv6
'' SIG '' UHnYjAI8G3UgCFFlAm0nguQ3rIX54pmujS83lgrm1Yqb
'' SIG '' L2Lrlhmi98Mk2ktCHCXKRwIDAQABo4IBNjCCATIwHQYD
'' SIG '' VR0OBBYEFF+2nlnwnNtR6aVZvQqVyK02K9FwMB8GA1Ud
'' SIG '' IwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1Ud
'' SIG '' HwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0
'' SIG '' LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUt
'' SIG '' U3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEF
'' SIG '' BQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cu
'' SIG '' bWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9z
'' SIG '' b2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSku
'' SIG '' Y3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYB
'' SIG '' BQUHAwgwDQYJKoZIhvcNAQELBQADggIBAAATu4fMRtRH
'' SIG '' 20+nNzGAXFxdXEpRPTfbM0LJDeNe4QCxj0FM+wrJdu6U
'' SIG '' KrM2wQuO31UDcQ4nrUJBe81N6W2RvEa8xNXjbO0qzNit
'' SIG '' wUfOVLeZp6HVGcNTtYEMAvK9k//0daBFxbp04BzMaIya
'' SIG '' HRy7y/K/zZ9ckEw7jF9VsJqlrwqkx9HqI/IBsCpJdlTt
'' SIG '' KBl/+LRbD8tWvw6FDrSkv/IDiKcarPE0BU6//bFXvZ5/
'' SIG '' h7diE13dqv5DPU5Kn499HvUOAcHG31gr/TJPEftqqK40
'' SIG '' dfpB+1bBPSzAef58rJxRJXNJ661GbOZ5e64EuyIQv0Vo
'' SIG '' 5ZptaWZiftQ5pgmztaZCuNIIvxPHCyvIAjmSfRuX7Uyk
'' SIG '' e0k29rSTruRsBVIsifG39gldsbyjOvkDN7S3pJtTwJV0
'' SIG '' ToC4VWg00kpunk72PORup31ahW99fU3jxBh2fHjiefjZ
'' SIG '' Ua08d/nQQdLWCzadttpkZvCgH/dc8Mts2CwrcxCPZ5p9
'' SIG '' VuGcqyFhK2I6PS0POnMuf70R3lrl5Y87dO8f4Kv83bkh
'' SIG '' q5g+IrY5KvLcIEER5kt5uuorpWzJmBNGB+62OVNMz92Y
'' SIG '' JFl/Lt+NvkGFTuGZy96TLMPdLcrNSpPGV5qHqnHlr/wU
'' SIG '' z9UAViTKJArvSbvk/siU7mi29oqRxb0ahB4oYVPNuv7c
'' SIG '' cHTBGqNNGol4MIIHcTCCBVmgAwIBAgITMwAAABXF52ue
'' SIG '' AptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkG
'' SIG '' A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
'' SIG '' BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
'' SIG '' dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
'' SIG '' IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAw
'' SIG '' HhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8
'' SIG '' MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
'' SIG '' bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
'' SIG '' cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
'' SIG '' b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJ
'' SIG '' KoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIh
'' SIG '' C3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDi
'' SIG '' vbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893
'' SIG '' MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3
'' SIG '' oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqY
'' SIG '' O7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVW
'' SIG '' Te/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD
'' SIG '' 4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7K
'' SIG '' MtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKR
'' SIG '' Hh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
'' SIG '' 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSC
'' SIG '' D/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxC
'' SIG '' aC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC
'' SIG '' +hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYG
'' SIG '' NRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLv
'' SIG '' jflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnG
'' SIG '' rnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3
'' SIG '' FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSa
'' SIG '' voKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D
'' SIG '' 9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3
'' SIG '' TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5t
'' SIG '' aWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRv
'' SIG '' cnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsG
'' SIG '' AQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIB
'' SIG '' hjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2
'' SIG '' VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
'' SIG '' oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv
'' SIG '' Y3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2
'' SIG '' LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUH
'' SIG '' MAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kv
'' SIG '' Y2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0
'' SIG '' MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEk
'' SIG '' W+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pk
'' SIG '' bHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjY
'' SIG '' Ni6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY
'' SIG '' 3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYo
'' SIG '' VSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz
'' SIG '' /AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJ
'' SIG '' eBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP
'' SIG '' 9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1j
'' SIG '' dEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138e
'' SIG '' W0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
'' SIG '' rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p
'' SIG '' /cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0V
'' SIG '' iY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ
'' SIG '' 1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETR
'' SIG '' kPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1iz
'' SIG '' oXBm8qGCAsswggI0AgEBMIH4oYHQpIHNMIHKMQswCQYD
'' SIG '' VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
'' SIG '' A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
'' SIG '' IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQg
'' SIG '' QW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFs
'' SIG '' ZXMgVFNTIEVTTjpFQUNFLUUzMTYtQzkxRDElMCMGA1UE
'' SIG '' AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIj
'' SIG '' CgEBMAcGBSsOAwIaAxUAAbquMnUCam/m7Ox1Uv/GNs1j
'' SIG '' mu+ggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
'' SIG '' CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
'' SIG '' MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
'' SIG '' JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
'' SIG '' MjAxMDANBgkqhkiG9w0BAQUFAAIFAOXsXrQwIhgPMjAy
'' SIG '' MjAzMjkwMDIwMDRaGA8yMDIyMDMzMDAwMjAwNFowdDA6
'' SIG '' BgorBgEEAYRZCgQBMSwwKjAKAgUA5exetAIBADAHAgEA
'' SIG '' AgIAhTAHAgEAAgISKzAKAgUA5e2wNAIBADA2BgorBgEE
'' SIG '' AYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAID
'' SIG '' B6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GB
'' SIG '' AEmcAgQVfFE3QJ8STgkGeBxVeySiSYkhkeEJypIZkOGq
'' SIG '' rTmLFc7dvqybH9ExtbhyKbLIavOeVHNpZzSmPDg1FO/h
'' SIG '' S4wDahBDD4qd03OYcDrGLWT03INC0qNPvMRyI7nG1lf6
'' SIG '' UBQp9VjIUY8Ncai6fpK1SpLcqn665PrjQyd0exXQMYIE
'' SIG '' DTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNV
'' SIG '' BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
'' SIG '' HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
'' SIG '' MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
'' SIG '' IDIwMTACEzMAAAGawHWixCFtPoUAAQAAAZowDQYJYIZI
'' SIG '' AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG
'' SIG '' 9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgkW85ZjHnshFU
'' SIG '' xdoAchEZG7e+lvJSgeqc9qSG5ptEVRkwgfoGCyqGSIb3
'' SIG '' DQEJEAIvMYHqMIHnMIHkMIG9BCABTkDjOBEUfZnligJi
'' SIG '' L539Lx+nsr/NFVTnKFX030iNYDCBmDCBgKR+MHwxCzAJ
'' SIG '' BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
'' SIG '' DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
'' SIG '' ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
'' SIG '' dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABmsB1osQh
'' SIG '' bT6FAAEAAAGaMCIEIJVsWa8wpX8uLw+Lfs4Cf28ZrAp3
'' SIG '' C7UYWo9ledl3x/Z3MA0GCSqGSIb3DQEBCwUABIICAAa1
'' SIG '' OOu8DX+/gRbuqIrdbWt1BHZ5y6eNpsm5B1+xpygeduX6
'' SIG '' FhTzh7BAZUd50DeBjSKME6/0+rlH32M6wLdAHFnMG++X
'' SIG '' OHVJHFemYCQqUs5TBf7pWPUwxgo79rOZGHPyaCUpefJP
'' SIG '' Q9g4jhmJem8bT5mAzvkN+dgtylFRIDXJY16ILJVyUtK0
'' SIG '' 6QF2z8ylxjF769DYzfacZ/M3e4+WSNGXdYBGxJaTQLSK
'' SIG '' uUQ09TI1O4Mh9LmthxMrg8tafzZN7NwdcMF0RauySkp3
'' SIG '' vK2KiOUBuuS3oO2ndexXK4WQ9ZrbpbtIja8xZsnU1voo
'' SIG '' +mIrMOXhnXoTIHQJYt82NHIJwUBCGGTOF8c0qHpsARQ7
'' SIG '' SGDc6jpKaCNPutCPizrbq9EnoTL3RPJrWHRpfzGFt+ER
'' SIG '' j9JNDuK9y1ralBfHHuYCEfAnmowrdrZR95dBq5n7Sijl
'' SIG '' O6ezwl4z0Blv/ZMCnEBZed5MgCusykUhnw4GrvxYaeFH
'' SIG '' umr6lnrXrj8drTDrdKk60s/cDChc7yFE0c1LHsDTF7m7
'' SIG '' 5Rb7EcPMEcsvaJzHwCYdMyPPbu1wUfMvPNCNcIH1PbNM
'' SIG '' 9W8ho2Prjzgvk91VqG76uuSeWZo+wBuMvGtZhl8K43w/
'' SIG '' bCoLMS8zysK1S6ZGF1MtNedKReLm+K9XxaGn6x+/dJUg
'' SIG '' zsdZ1v1qfm/80iN4ssUg
'' SIG '' End signature block
