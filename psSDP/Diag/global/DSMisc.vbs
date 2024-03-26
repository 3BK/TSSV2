Set objShell = CreateObject("Wscript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objNetwork = WScript.CreateObject("WScript.Network")
Set objRootDSE = GetObject("LDAP://RootDSE")
Set objDefaultNC = GetObject("LDAP://" & objRootDSE.get("defaultNamingContext"))

strComputerName = objNetwork.ComputerName
Set objFile = objFSO.OpenTextFile(strComputerName & "_DSMisc.txt", 2, True)
objFile.WriteLine "Functional Level Information"
objFile.WriteLine "============================" & vbCrLf
objFile.WriteLine "Domain Controller = " & vbTab & objRootDSE.get("dnsHostName")
objFile.WriteLine "Domain = " & vbTab & objRootDSE.get("defaultNamingContext")
objFile.WriteLine "Forest Root = " & vbTab & objRootDSE.get("rootDomainNamingContext")
objFile.Write "Domain Type = " & vbTab 
Select Case objDefaultNC.get("nTMixedDomain")
  Case 0 objFile.WriteLine "Native Mode"
  Case 1 objFile.WriteLine "Mixed Mode"
  Case Else	objFile.WriteLine "Mixed Mode"
End Select
On Error Resume Next
domainFunctionality = objRootDSE.get("domainFunctionality")
If err.number <> 0 Then
  If err.number = -2147463155 Then
     domainFunctionality = 0
  else
     domainFunctionality = err.number
     err.clear
  End If
End If
objFile.Write "Domain Functional Level = " & vbTab
Select Case domainFunctionality
  Case 0 objFile.WriteLine "Windows 2000"
  Case 1 objFile.WriteLine "Windows Server 2003 Interim"
  Case 2 objFile.WriteLine "Windows Server 2003"
  Case 3 objFile.WriteLine "Windows Server 2008"
  Case 4 objFile.WriteLine "Windows Server 2008 R2"
  Case Else	objFile.WriteLine "Error " & domainFunctionality
End Select
forestFunctionality = objRootDSE.get("forestFunctionality")
If err.number <> 0 Then
  If err.number = -2147463155 Then
     forestFunctionality = 0
  else
     forestFunctionality = err.number
     err.clear
  End If
End If
objFile.Write "Forest Functional Level = " & vbTab
Select Case forestFunctionality
  Case 0 objFile.WriteLine "Windows 2000"
  Case 1 objFile.WriteLine "Windows Server 2003 Interim"
  Case 2 objFile.WriteLine "Windows Server 2003"
  Case 3 objFile.WriteLine "Windows Server 2008"
  Case 4 objFile.WriteLine "Windows Server 2008 R2"
  Case Else	objFile.WriteLine "Error " & forestFunctionality
End Select
objFile.WriteLine vbCrLf
objFile.WriteLine "Group Membership Information"
objFile.WriteLine "============================" & vbCrLf
On Error GoTo 0
objFile.Close

errReturn = objShell.Run("Cmd /D /C net localgroup Administrators >> " & strComputerName & "_DSMisc.txt", 0, TRUE)
errReturn = objShell.Run("Cmd /D /C net localgroup " & Chr(34) & "Remote Desktop Users" & Chr(34) & " >> " & strComputerName & "_DSMisc.txt", 0, TRUE)
errReturn = objShell.Run("Cmd /D /C net localgroup " & Chr(34) & "Pre-Windows 2000 Compatible Access" & Chr(34) & " >> " & strComputerName & "_DSMisc.txt", 0, True)
'' SIG '' Begin signature block
'' SIG '' MIInugYJKoZIhvcNAQcCoIInqzCCJ6cCAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' eOcphDxiLpK5zKqaa7eMWY+M5JsKCPDwo8UdWAKjGASg
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
'' SIG '' ghmNMIIZiQIBATCBlTB+MQswCQYDVQQGEwJVUzETMBEG
'' SIG '' A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
'' SIG '' ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
'' SIG '' MSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5n
'' SIG '' IFBDQSAyMDExAhMzAAACU+OD3pbexW7MAAAAAAJTMA0G
'' SIG '' CWCGSAFlAwQCAQUAoIGwMBkGCSqGSIb3DQEJAzEMBgor
'' SIG '' BgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
'' SIG '' AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCnqZh4/i1uy8cK
'' SIG '' Iy5SLD+Iyxn/oNRCcfmyORQxtXdU6TBEBgorBgEEAYI3
'' SIG '' AgEMMTYwNKAUgBIATQBpAGMAcgBvAHMAbwBmAHShHIAa
'' SIG '' aHR0cHM6Ly93d3cubWljcm9zb2Z0LmNvbSAwDQYJKoZI
'' SIG '' hvcNAQEBBQAEggEApDmiTo/nmaNxB3iMG13IDlAuhgUN
'' SIG '' aK8WQemwe3FwtWTiv2yUQBqfcTjYMV7x+pCn1g6Ozimg
'' SIG '' 5FJ+kRbe13K4humEqjivDd9R4M1BJxWFgirODDhIOfJF
'' SIG '' 7tYahPhWkQ026nrkRmMKE3rphn0CDDVh471JMnpjw/j9
'' SIG '' b5uTyOSWAPE39G1MovYXLVGQ+HvKq9wRBC0N0Yj1Xzjx
'' SIG '' /2du/gJPTiEIKe1lKsOlur5gwYh6X5wQ95qTFZ4gyv4M
'' SIG '' PifBDfNrxn2p1jZuz/2KizLiZz06XBtSw686MwacNETB
'' SIG '' ZnRbrSUkFPkFYBOSzyOxSVwu49z25+4bPHZTgbFOQzeS
'' SIG '' CavwM6GCFxUwghcRBgorBgEEAYI3AwMBMYIXATCCFv0G
'' SIG '' CSqGSIb3DQEHAqCCFu4wghbqAgEDMQ8wDQYJYIZIAWUD
'' SIG '' BAIBBQAwggFYBgsqhkiG9w0BCRABBKCCAUcEggFDMIIB
'' SIG '' PwIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUA
'' SIG '' BCBhgDLtbTjiUpEMVIYRq0qZ65trEyionaoDr5KQ+1Nw
'' SIG '' KgIGYhe2LJR6GBIyMDIyMDMyODE2NTUxOS42MVowBIAC
'' SIG '' AfSggdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
'' SIG '' EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
'' SIG '' HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTAr
'' SIG '' BgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlv
'' SIG '' bnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
'' SIG '' U046MTc5RS00QkIwLTgyNDYxJTAjBgNVBAMTHE1pY3Jv
'' SIG '' c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghFlMIIHFDCC
'' SIG '' BPygAwIBAgITMwAAAYo+OI3SDgL66AABAAABijANBgkq
'' SIG '' hkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UE
'' SIG '' CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
'' SIG '' MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
'' SIG '' JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
'' SIG '' MjAxMDAeFw0yMTEwMjgxOTI3NDJaFw0yMzAxMjYxOTI3
'' SIG '' NDJaMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
'' SIG '' aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
'' SIG '' ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQL
'' SIG '' EyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExp
'' SIG '' bWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjE3
'' SIG '' OUUtNEJCMC04MjQ2MSUwIwYDVQQDExxNaWNyb3NvZnQg
'' SIG '' VGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0B
'' SIG '' AQEFAAOCAg8AMIICCgKCAgEAt/+ut6GDAyAZvegBhagW
'' SIG '' d0GoqT8lFHMepoWNOLPPEEoLuya4X3n+K14FvlZwFmKw
'' SIG '' qap6B+6EkITSjkecTSB6QRA4kivdJydlLvKrg8udtBu6
'' SIG '' 7LKyjQqwRzDQTRhECxpU30tdBE/AeyP95k7qndhIu/Op
'' SIG '' T4QGyGJUiMDlmZAiDPY5FJkitUgGvwMBHwogJz8FVEBF
'' SIG '' nViAURTJ4kBDiU6ppbv4PI97+vQhpspDK+83gayaiRC3
'' SIG '' gNTGy3iOie6Psl03cvYIiFcAJRP4O0RkeFlv/SQoomz3
'' SIG '' JtsMd9ooS/XO0vSN9h2DVKONMjaFOgnN5Rk5iCqwmn6q
'' SIG '' sme+haoR/TrCBS0zXjXsWTgkljUBtt17UBbW8RL+9LNw
'' SIG '' 3cjPJ8EYRglMNXCYLM6GzCDXEvE9T//sAv+k1c84tmoi
'' SIG '' ZDZBqBgr/SvL+gVsOz3EoDZQ26qTa1bEn/npxMmXctoZ
'' SIG '' Se8SRDqgK0JUWhjKXgnyaOADEB+FtfIi+jdcUJbpPtAL
'' SIG '' 4kWvVSRKipVv8MEuYRLexXEDEBi+V4tfKApZhE4ga0p+
'' SIG '' QCiawHLBZNoj3UQNzM5QVmGai3MnQFbZkhqbUDypo9va
'' SIG '' WEeVeO35JfdLWjwRgvMX3VKZL57d7jmRjiVlluXjZFLx
'' SIG '' +rhJL7JYVptOPtF1MAtMYlp6OugnOpG+4W4MGHqj7YYf
'' SIG '' P0UCAwEAAaOCATYwggEyMB0GA1UdDgQWBBQj2kPY/WwZ
'' SIG '' 1Jeup0lHhD4xkGkkAzAfBgNVHSMEGDAWgBSfpxVdAF5i
'' SIG '' XYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
'' SIG '' dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
'' SIG '' bC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIw
'' SIG '' MjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsG
'' SIG '' AQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
'' SIG '' cGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3Rh
'' SIG '' bXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8E
'' SIG '' AjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3
'' SIG '' DQEBCwUAA4ICAQDF9MESsPXDeRtfFo1f575iPfF9ARWb
'' SIG '' euuNfM583IfTxfzZf2dv/me3DNi/KcNNEnR1TKbZtG7L
'' SIG '' sg0cy/pKIEQOJG2fYaWwIIKYwuyDJI2Q4kVi5mzbV/0C
'' SIG '' 5+vQQsQcCvfsM8K5X2ffifJi7tqeG0r58Cjgwe7xBYvg
'' SIG '' uPmjUNxwTWvEjZIPfpjVUoaPCl6qqs0eFUb7bcLhzTEE
'' SIG '' YBnAj8MENhiP5IJd4Pp5lFqHTtpec67YFmGuO/uIA/Tj
'' SIG '' PBfctM5kUI+uzfyh/yIdtDNtkIz+e/xmXSFhiQER0uBj
'' SIG '' RobQZV6c+0TNtvRNLayU4u7Eekd7OaDXzQR0RuWGaSiw
'' SIG '' tN6Xc/PoNP0rezG6Ovcyow1qMoUkUEQ7qqD0Qq8QFwK0
'' SIG '' DKCdZSJtyBKMBpjUYCnNUZbYvTTWm4DXK5RYgf23bVBJ
'' SIG '' W4Xo5w490HHo4TjWNqz17PqPyMCTnM8HcAqTnPeME0dP
'' SIG '' YvbdwzDMgbumydbJaq/06FImkJ7KXs9jxqDiE2PTeYna
'' SIG '' j82n6Q//PqbHuxxJmwQO4fzdOgVqAEkG1XDmppVKW/rJ
'' SIG '' xBN3IxyVr6QP9chY2MYVa0bbACI2dvU+R2QJlE5AjoMK
'' SIG '' y68WI1pmFT3JKBrracpy6HUjGrtV+/1U52brrElClVy5
'' SIG '' Fb8+UZWZLp82cuCztJMMSqW+kP5zyVBSvLM+4DCCB3Ew
'' SIG '' ggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJ
'' SIG '' KoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYD
'' SIG '' VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
'' SIG '' MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
'' SIG '' MjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmlj
'' SIG '' YXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIy
'' SIG '' NVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMx
'' SIG '' EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
'' SIG '' ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
'' SIG '' dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
'' SIG '' bXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4IC
'' SIG '' DwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3u
'' SIG '' nAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VT
'' SIG '' cVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aO
'' SIG '' RmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlh
'' SIG '' AnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S
'' SIG '' /rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc
'' SIG '' 6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1o
'' SIG '' O5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbni
'' SIG '' jYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3E
'' SIG '' XzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYr
'' SIG '' bqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M
'' SIG '' 269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFph
'' SIG '' AXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6Cm
'' SIG '' gyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr
'' SIG '' 9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfH
'' SIG '' CBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQAB
'' SIG '' o4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkr
'' SIG '' BgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4w
'' SIG '' HQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwG
'' SIG '' A1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYB
'' SIG '' BQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
'' SIG '' a2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUE
'' SIG '' DDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMA
'' SIG '' dQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUw
'' SIG '' AwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvX
'' SIG '' zpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3Js
'' SIG '' Lm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9N
'' SIG '' aWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYB
'' SIG '' BQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3
'' SIG '' Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0Nl
'' SIG '' ckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsF
'' SIG '' AAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5O
'' SIG '' R2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts
'' SIG '' 0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp
'' SIG '' 4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRX
'' SIG '' ud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFd
'' SIG '' PSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZ
'' SIG '' QhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzs
'' SIG '' kYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCr
'' SIG '' dTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5
'' SIG '' JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxn
'' SIG '' GSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdU
'' SIG '' CbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3
'' SIG '' Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzba
'' SIG '' ukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRb
'' SIG '' atGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNT
'' SIG '' TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLUMIICPQIB
'' SIG '' ATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYD
'' SIG '' VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
'' SIG '' MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
'' SIG '' LTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
'' SIG '' dGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRT
'' SIG '' UyBFU046MTc5RS00QkIwLTgyNDYxJTAjBgNVBAMTHE1p
'' SIG '' Y3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAH
'' SIG '' BgUrDgMCGgMVAIDw82OvG1MFBB2n/4weVqpzV8ShoIGD
'' SIG '' MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
'' SIG '' c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
'' SIG '' BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
'' SIG '' AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAw
'' SIG '' DQYJKoZIhvcNAQEFBQACBQDl7GROMCIYDzIwMjIwMzI5
'' SIG '' MDA0MzU4WhgPMjAyMjAzMzAwMDQzNThaMHQwOgYKKwYB
'' SIG '' BAGEWQoEATEsMCowCgIFAOXsZE4CAQAwBwIBAAICDUgw
'' SIG '' BwIBAAICEScwCgIFAOXttc4CAQAwNgYKKwYBBAGEWQoE
'' SIG '' AjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEK
'' SIG '' MAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQAt2bqN
'' SIG '' 6E4TZQAjmDcwlRgcLi/FLaHAErQ+Lbb4/1zVhLyaK1d9
'' SIG '' lbavQR0vwdQY2jwWVXlRh8XF8TS7A2X6l5OAhhP7MXSk
'' SIG '' uNSXyutkvpKv86wCiTVDkiumvS79kuWWd/+XOZD4WfzU
'' SIG '' DMjfSMFVXkAHn0gjvn+fpWqJP8DeUPbAXTGCBA0wggQJ
'' SIG '' AgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
'' SIG '' YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
'' SIG '' VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
'' SIG '' BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
'' SIG '' AhMzAAABij44jdIOAvroAAEAAAGKMA0GCWCGSAFlAwQC
'' SIG '' AQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
'' SIG '' AQQwLwYJKoZIhvcNAQkEMSIEIJ5yOmOfx5tyYARW0g+o
'' SIG '' gQMCClccBCmUz+jjfkcISlStMIH6BgsqhkiG9w0BCRAC
'' SIG '' LzGB6jCB5zCB5DCBvQQg9L3gq3XfSr5+879/MPgxtZCF
'' SIG '' BoTtEeQ4foCSOU1UKb0wgZgwgYCkfjB8MQswCQYDVQQG
'' SIG '' EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
'' SIG '' BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
'' SIG '' cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
'' SIG '' ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYo+OI3SDgL66AAB
'' SIG '' AAABijAiBCBDFyxKjr7lqspp8H8AWshwKjf7Oc3ONxMn
'' SIG '' n9XF3iVszzANBgkqhkiG9w0BAQsFAASCAgBngeO/pJDA
'' SIG '' ba5FP9Ie/DjPvFQ1xcR9R83dECq020P06zI+mp4Iab+Y
'' SIG '' aAFO6XskmDM532/j2gPXMsfbgPsirZXKmIICQLXR+gHw
'' SIG '' dElQP+LwV2oBe17UH6ieniZxP7RSVsUq+WxD9O7W6M3j
'' SIG '' k9Yv1JUUc0rpHhBYGSDFlwRCCPREE+LRfiCIVc6aT8bE
'' SIG '' SqxOtwDaa1erZ2OddD1d8Cutf7gTZkpM/S+sTGWvOAng
'' SIG '' fP8Xpw4hpoLCr7Cz39mH/lDmAHWHx91CU4lAVimoowoj
'' SIG '' hhGDlL1xldWmAXHFkMTIS3rzGNvR5rrROvVYpa1XIJiZ
'' SIG '' +hxH1noyaYBVLqka5TyJq6iuwYsDbAtdVY8MQfG1jHJt
'' SIG '' 8TGOWyOBbUYc9+DUvGjNrfXasY8M3Jl8kXqB3vox4Zfw
'' SIG '' M3jBZC8RPwKZA3vBejNnMnrZJg3D0YRpVuFIh6akWCpq
'' SIG '' XAcyHyUTuVmJoV97NZ13VZDCBI+KgaVeTRbNqAesTvob
'' SIG '' 3XQwbdRL3L0UcqrM9tfHxm1O4eP/GsUe74VyYi14pM75
'' SIG '' W1m/Ja10gscPSNb4cetZdHpK0DUbF4QHMiINRKTGed23
'' SIG '' nuvsHFvdMz/2uyeDaeEC0EUAszreMbibPP9FAty98y+X
'' SIG '' UU6NTIxUpgilgmrH7Hcb95f/+enu7t/3+ntqzBE+jOo4
'' SIG '' 7xl0+VUqxigtZg==
'' SIG '' End signature block
