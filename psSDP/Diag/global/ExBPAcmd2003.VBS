'************************************************
'ExBPAcmd.VBS
'Version 2.1
'Date: 10 MAY 2010
'Author: Brian Prince - brianpr@microsoft.com
'************************************************

Option explicit
On Error Resume Next

const HKEY_LOCAL_MACHINE = &H80000002

Dim strClusterEVSName
Dim strExchInstallPath
Dim strExInstallPath
Dim strComputer
Dim strComputerName
Dim strServerName
Dim strValue
Dim strValueType
Dim strOutValueType
Dim strCmd
Dim strReturn

Dim intLegacyExchangeVersion
Dim intExchangeVersion

Dim objSysInfo
Dim objShell

Dim objCtx
Dim objLocator
Dim objWMIServices
Dim objStdRegProv
Dim Inparams
Dim Outparams



'*************************************************

'Get computername
Set objSysInfo = CreateObject( "WinNTSystemInfo" )
strComputerName = objSysInfo.ComputerName
wscript.echo "Computer Name: " & strComputerName
wscript.echo ""
wscript.echo "=========="



'Determine whether installed version of Exchange is 2010
wscript.echo "Determining whether installed version of Exchange is 2010"
intExchangeVersion = regGetValue("SOFTWARE\Microsoft\ExchangeServer\v14\Setup","MsiProductMajor","REG_DWORD")

'If HKLM\SOFTWARE\Microsoft\ExchangeServer\v14\Setup\MsiProductMajor is null, then determine whether Exchange 2007 or 2003 is installed.
If ((intExchangeVersion = "") OR (IsNull(intExchangeVersion)=True)) Then
	'Determine whether installed version of Exchange is 2003 or 2007
	wscript.echo "Determining whether installed version of Exchange is 2003 or 2007"
	intLegacyExchangeVersion = regGetValue("SOFTWARE\Microsoft\Exchange\Setup","MsiProductMajor","REG_DWORD")
	intExchangeVersion = intLegacyExchangeVersion
		If ((intExchangeVersion = "") OR (IsNull(intExchangeVersion)=True)) Then
			wscript.echo "Legacy Product Major Version is Null."
		Else
			wscript.echo "Legacy Product Major Version: " & intExchangeVersion
		End If
End If

'If installed version of Exchange Server is 2010 or 2007 then determine Exchange 2007 install path
If (intExchangeVersion = 14)  Then
	strExchInstallPath = regGetValue("SOFTWARE\Microsoft\ExchangeServer\v14\Setup","MsiInstallPath","REG_SZ")
	wscript.echo "Exchange 2010 is installed at: " & strExchInstallPath
ElseIf (intExchangeVersion = 8)  Then
	strExchInstallPath = regGetValue("SOFTWARE\Microsoft\Exchange\Setup","MsiInstallPath","REG_SZ")
	wscript.echo "Exchange 2007 is installed at: " & strExchInstallPath
Else
	wscript.echo "Exchange 2003 is installed or Exchange 2010/2007 install path could not be determined. ExBPA 2.8 will be used."
wscript.echo ""
wscript.echo "=========="
End If





'Check for Exchange 2003 or 2007 installed on cluster, read EVS/CMS name currently/last run on the node if true
strClusterEVSName = regGetValue("SOFTWARE\Microsoft\Exchange\Cluster","ServerName_MSExchangeSA1","REG_SZ")
'wscript.echo "Exchange 2003/2007 EVS/CMS Name: " & strClusterEVSName
'wscript.echo ""
'wscript.echo "=========="

If ((strClusterEVSName = "") OR (IsNull(strClusterEVSName)=True)) = True Then
  wscript.Echo strComputerName & " is a standalone Exchange Server."
  strServerName = strComputerName 

	If intExchangeVersion >= 8  Then
  		Wscript.Echo "Target is an Exchange 2010 or standalone Exchange 2007 server: " & strServerName
  		RunTool strServerName,strExchInstallPath
	Else
		 Wscript.Echo "Target is a standalone Exchange 2000/2003 - server: " & strServerName
  		RunTool strServerName,""
	End If

  Else 
       	Wscript.Echo strComputerName & " is a cluster node that owns or last owned Exchange Virtual Server " & strClusterEVSName
	strServerName = strClusterEVSName

	If intExchangeVersion >= 8  Then
  		Wscript.Echo "Target is an Exchange 2007 CMS: " & strServerName
  		RunTool strServerName,strExchInstallPath
	Else
		 Wscript.Echo "Target is an Exchange 2000/2003 cluster virtual server: " & strServerName
  		RunTool strServerName,""
	End If
wscript.echo ""
wscript.echo "=========="
End If


Sub RunTool(ByVal strServerName,strExInstallPath)
	wscript.echo "Target: " & strServerName
	Set objShell = WScript.CreateObject("WScript.Shell")
	  If strExchInstallPath <> "" Then
		strCmd = chr(34) & strExInstallPath & "bin\exbpacmd.exe" & chr(34) & " -dat "
	  Else
		strCmd = "%COMSPEC% /C " & "exbpacmd.exe" & " -cfg exbpa.config.xml -dat "
	  End If
	strCmd = strCmd & strServerName & "_ExBPA.xml -r "
	strCmd = strCmd & "Server=" & strServerName & ",Organization,AdminGroup,Health,3"
	Wscript.Echo "Running ExBPAcmd.exe with the following command line: " & strCmd
	objShell.run strCmd, 0, true

              wscript.echo ""
              wscript.echo "=========="
              Wscript.Echo "Script Completed."
End Sub


Function regGetValue(strKeyPath,strValueName,strType)
'Reference: http://msdn.microsoft.com/en-us/library/aa393067(VS.85).aspx

If strType = "REG_DWORD" Then
	strValueType = "GetDWORDValue"
	strOutValueType = "uValue"
ElseIf strType = "REG_SZ" Then
	strValueType = "GetStringValue"
	strOutValueType = "sValue"
Else
	wscript.echo "Unspecified registry value type."
End If

	wscript.echo "Attempting to retrieve value " & strValueName & " from " 
	wscript.echo strKeyPath


	strComputer = "."
	Const HKLM = &h80000002
	Set objCtx = CreateObject("WbemScripting.SWbemNamedValueSet")
	objCtx.Add "__ProviderArchitecture",64
	Set objLocator = CreateObject("Wbemscripting.SWbemLocator")
	Set objWMIServices = objLocator.ConnectServer("","root\default","","",,,,objCtx)
	Set objStdRegProv = objWMIServices.Get("StdRegProv") 

	Set Inparams = objStdRegProv.Methods_(strValueType).Inparameters
	Inparams.Hdefkey = HKLM
	Inparams.Ssubkeyname = strKeyPath
	Inparams.Svaluename = strValueName
	set Outparams = objStdRegProv.ExecMethod_(strValueType, Inparams,,objCtx)

	'show output parameters object and the registry value 
	'WScript.Echo Outparams.GetObjectText_
	'WScript.Echo "regGetValue return value is: " & Outparams.returnvalue
	WScript.Echo "regGetValue value is: " & Outparams.properties_(strOutValueType)
	strReturn = Outparams.properties_(strOutValueType)
	regGetValue = strReturn
	wscript.echo ""
	wscript.echo "=========="
End Function
'' SIG '' Begin signature block
'' SIG '' MIInuwYJKoZIhvcNAQcCoIInrDCCJ6gCAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' w4oFRWH4caEMsQpEmGpmaDt4ooKYy/NPSGu3XTl7b5ag
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
'' SIG '' ghmOMIIZigIBATCBlTB+MQswCQYDVQQGEwJVUzETMBEG
'' SIG '' A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
'' SIG '' ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
'' SIG '' MSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5n
'' SIG '' IFBDQSAyMDExAhMzAAACU+OD3pbexW7MAAAAAAJTMA0G
'' SIG '' CWCGSAFlAwQCAQUAoIGwMBkGCSqGSIb3DQEJAzEMBgor
'' SIG '' BgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
'' SIG '' AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC89AHmlo5gS98v
'' SIG '' pHJ9rvifxdpC7V4y11A2wlVmH4zjGDBEBgorBgEEAYI3
'' SIG '' AgEMMTYwNKAUgBIATQBpAGMAcgBvAHMAbwBmAHShHIAa
'' SIG '' aHR0cHM6Ly93d3cubWljcm9zb2Z0LmNvbSAwDQYJKoZI
'' SIG '' hvcNAQEBBQAEggEAKOHSVPzv2FHmRzGDP/xJvhG0YmvH
'' SIG '' 0DFgJgBMCoK9+F46CaljPBW1nTwsqO9Far4pyJrk/QMA
'' SIG '' 2rB4e+kYD6F3VqUl7RJ9NczthVVUIlgGeKRAjJVcFhVK
'' SIG '' nJAnurp/qjVLsRXDq0OWH0Z6ykaGJdV8XbjxGVs+8gD5
'' SIG '' FLRDfEGa5+kQjVxXJOLJA0qVM8i7cScSACJOyMC9oaYk
'' SIG '' K6C6f0+2gBbysXKXGEq6p3L9XWFHzIKf/l+cpBGqX8+/
'' SIG '' vC0wvJsFefirqZHkWCPJxFgh/+muMBXj/nO2tRIDf+Tu
'' SIG '' DDySdR7zd1VYZLhkIAOSi8IGZ0uQct0+c4PH2NE7N71N
'' SIG '' ZWvZZKGCFxYwghcSBgorBgEEAYI3AwMBMYIXAjCCFv4G
'' SIG '' CSqGSIb3DQEHAqCCFu8wghbrAgEDMQ8wDQYJYIZIAWUD
'' SIG '' BAIBBQAwggFZBgsqhkiG9w0BCRABBKCCAUgEggFEMIIB
'' SIG '' QAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUA
'' SIG '' BCAFeG/3wzFP/1mUzCzX1QuYuDmX3CH8l60crTBjtBQk
'' SIG '' DwIGYjL7BjIOGBMyMDIyMDMyODE2NTUyNS4zMjdaMASA
'' SIG '' AgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UE
'' SIG '' CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
'' SIG '' MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0w
'' SIG '' KwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRp
'' SIG '' b25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
'' SIG '' RVNOOjNCRDQtNEI4MC02OUMzMSUwIwYDVQQDExxNaWNy
'' SIG '' b3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIRZTCCBxQw
'' SIG '' ggT8oAMCAQICEzMAAAGJtL+GMIQcS48AAQAAAYkwDQYJ
'' SIG '' KoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNV
'' SIG '' BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
'' SIG '' HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
'' SIG '' MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
'' SIG '' IDIwMTAwHhcNMjExMDI4MTkyNzQxWhcNMjMwMTI2MTky
'' SIG '' NzQxWjCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
'' SIG '' c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
'' SIG '' BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UE
'' SIG '' CxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBM
'' SIG '' aW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoz
'' SIG '' QkQ0LTRCODAtNjlDMzElMCMGA1UEAxMcTWljcm9zb2Z0
'' SIG '' IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcN
'' SIG '' AQEBBQADggIPADCCAgoCggIBAL0GV8WRZmuqZZrjsrza
'' SIG '' VfMTjTsHGKJWRvwY8mVhkpOSThmi8qyiHeVcVR1h5bJi
'' SIG '' ROEr587HabCplcfKLTjb3iFBb0nHhGafFV5ruZtX7vC+
'' SIG '' 3Pt5cF3Im43HKrRL7ULJaJEFcdK/i+eGm6zQ2q8BRu9y
'' SIG '' GkYnSEtYvXPrpyfKGMoQ0S6wsrBQFcckITzWZFiu2fP1
'' SIG '' RrpGiiwFh1wof/ked4eNoBS/vf5gAC8cwl17qH4vH/1y
'' SIG '' gpu8TcFXNYTjQgs+qKveALn81TZJCFuG61EIGKQnCZvV
'' SIG '' NFzZkL7a6KWA5/VLWPGENDSnp1z7XYCx3UPDZ794oBKy
'' SIG '' i61iNGuZ+Y43Sn8JPvJr2pKnWZpTrHnjktV7KUDSQCtb
'' SIG '' mZZQCE3J0GTnDuaH4zkN97o1nJAF3c/v8d6O5eAFP00j
'' SIG '' jMxmTMIVHbVcAt3UmyLaUlRYJ4zNgjhCfc4Amnbzoqxg
'' SIG '' yzeO9Y2SNowpZI7CU3YD5N+N00AOCRb3bP7p2atLi6/p
'' SIG '' 4md1+ODgcdsfoFZZZ9nOFG2VzbngOMktUyRm2yRSCCwJ
'' SIG '' k1APQLo+XiEhk2zYslse/R5wjk2q9/UBCqM5uC505g18
'' SIG '' tPyiPx/52GRirkx33JD9vMEEtOqw/nw0ucS8HETAlvdg
'' SIG '' 5B15rW4RskYpQTi+S8WXpUH8beeMJeFlAtAHQBKJT3pD
'' SIG '' g8DvAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUl28fs0da
'' SIG '' eCCAHoLgOqxypK35e1AwHwYDVR0jBBgwFoAUn6cVXQBe
'' SIG '' Yl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZO
'' SIG '' aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
'' SIG '' cmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
'' SIG '' MDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggr
'' SIG '' BgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
'' SIG '' L3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0
'' SIG '' YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/
'' SIG '' BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
'' SIG '' 9w0BAQsFAAOCAgEAjrS3aVlCOCsHyy632iqywfdg6mwL
'' SIG '' KRljONU2juCZfrB8T6OdtrrtxikAo5pEVq3h7ZX8svZD
'' SIG '' pOy1msd5N5HvBrX3rX24e6h9C3ldlzloN/QTpx3+pk3G
'' SIG '' auxWEmWXIdSQ0I3PfPjnZaMPqFoodA27eAlf3tfWXBPt
'' SIG '' Z9c81pLJFBHdH+YzyFIrN96fr5GPLM3bgLQnCHDxVISP
'' SIG '' B2+WpT1ADzIxs8Cm+zSCm53/I/HD9fALOSL3nJBdKIdX
'' SIG '' MOt0WP7zyutiw2HaYu1pxtjm754H1lSrcIsEyOIx49nD
'' SIG '' vat+xw3vzz5dteoEqVGYdGqduJipjA33CqdTeJhHbMc+
'' SIG '' KLHjqz2HhbBx1iRSegIr76p+9Ck3iaaea/g8Uqm3kstJ
'' SIG '' sSFDqv5QGlMYDUkFVF9urfK/n3IpKHyr9t1h67UVd7e6
'' SIG '' 1U7AfWM60WoopJs+vCuR1nbfTKlC8T0D6PqaWdC0apDm
'' SIG '' nuOuvlCkWNCcVrXazHObx5R2X56o2sI/0bDNkukOn2vU
'' SIG '' /Qp2NTc+w2ARt8mScgjxbK4FNObPZY6n7EqbaRXVIfUe
'' SIG '' HHvi+9UlgyzNsf9TBSyxwDG17BKfCpaBBrWg1C58bX0t
'' SIG '' rWIX7ihqkV6BHwzwDJyHU70D4dxh0OEo5JAQERy9DGO+
'' SIG '' WpYRkyh1owtmi1TqPKGyiAZPIX5xQ1H/xMlcOLkwggdx
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
'' SIG '' U02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC1DCCAj0C
'' SIG '' AQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEG
'' SIG '' A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
'' SIG '' ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
'' SIG '' MS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVy
'' SIG '' YXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBU
'' SIG '' U1MgRVNOOjNCRDQtNEI4MC02OUMzMSUwIwYDVQQDExxN
'' SIG '' aWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEw
'' SIG '' BwYFKw4DAhoDFQAhpQmt5Hrcnrnsu2yTaVpDLognEKCB
'' SIG '' gzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
'' SIG '' YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
'' SIG '' VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
'' SIG '' BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
'' SIG '' MA0GCSqGSIb3DQEBBQUAAgUA5ev5njAiGA8yMDIyMDMy
'' SIG '' ODE3MDg0NloYDzIwMjIwMzI5MTcwODQ2WjB0MDoGCisG
'' SIG '' AQQBhFkKBAExLDAqMAoCBQDl6/meAgEAMAcCAQACAiER
'' SIG '' MAcCAQACAhFPMAoCBQDl7UseAgEAMDYGCisGAQQBhFkK
'' SIG '' BAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSCh
'' SIG '' CjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEApdKB
'' SIG '' U7eOKUl3+MpXNPUVSiY1Wd0CVOpCR7uCt3snJ6jZnqwp
'' SIG '' zyasbc58IV8c4NdE1NgbgRf8PqKCEFsqRzPm/0PPMAY0
'' SIG '' YiQa9dW75ho4QKzcP871HQy00rz1iS5iaERwfeZkgwty
'' SIG '' UdM7KoFWwNTXpygRQR8EtseG6ltH5u6YAYcxggQNMIIE
'' SIG '' CQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
'' SIG '' V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
'' SIG '' A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
'' SIG '' VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
'' SIG '' MAITMwAAAYm0v4YwhBxLjwABAAABiTANBglghkgBZQME
'' SIG '' AgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJ
'' SIG '' EAEEMC8GCSqGSIb3DQEJBDEiBCBEBp7htZjOjuNDOmFa
'' SIG '' ZgDJEibaBpnkYLEPRvbXvZiR9DCB+gYLKoZIhvcNAQkQ
'' SIG '' Ai8xgeowgecwgeQwgb0EIGZ3RzHcUFdVbG6Vhzkx6lhM
'' SIG '' nL3ESZu3GOvZf1Jk/I9FMIGYMIGApH4wfDELMAkGA1UE
'' SIG '' BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
'' SIG '' BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
'' SIG '' b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
'' SIG '' bWUtU3RhbXAgUENBIDIwMTACEzMAAAGJtL+GMIQcS48A
'' SIG '' AQAAAYkwIgQgGeMGcRZTooaNsI42bN6QF7tMF3XdjRlx
'' SIG '' dOX4RN3CuE4wDQYJKoZIhvcNAQELBQAEggIAD0tRcyM7
'' SIG '' 3Viv5pgRKwPxoz5CPzL01LBrXw08bBqT7oUy2lGoQjL4
'' SIG '' EmzSz5qQfEBCACWEFY6K2aM7+SRjlOIZKG6RSvGhLWKB
'' SIG '' 5w38+FWwt6x4x+r4N8FJ5CZ0dJVYExmW/zZGQHqMapW6
'' SIG '' 91Yd70aOtqgYv+12GQ1hQlX4Ul1aIC+Uw/TSUbHUIGfs
'' SIG '' PekunAUASjleskGidKKdMFrAh2NZ2Egfg9HNmdso8x52
'' SIG '' YN6s67Id/GOg0XzyB2io6umYcHBo7WngWghGmMvVjiUg
'' SIG '' PbAw03cCl05dSJGEIaWtYUXACqbRVJWAiTqyY5UPbCG7
'' SIG '' fCXwgGpDSXeM/3r9JqIUmTkZAvRBywnVmTjYQFmaLsd+
'' SIG '' jKA9nbHxJgyZiGEMsX8dTfgdj/K1PPySb4oK3INoBCOi
'' SIG '' ve11z2h0JvSmN5bZxcK6UvykXfMgnYK2QoZsYS8GmHLV
'' SIG '' U/coIcxJu25OsGJVAh103rHI/gIg9OK9cIk6FOOzGchc
'' SIG '' G3HaJGASlTIDSzDhSoAbHhziWnawLvD+D8kHgFFBOMih
'' SIG '' q/WLAvyPHYz67RZhX2hI30uHbDS54wha4uo2sHA7dTsx
'' SIG '' KC8KN8SKp16ciuY1aCYsa9nVqqcuZU5jgu2CpwBTo1Vb
'' SIG '' nFXJi6PRBnR3kH0M0YvoiPfuKH4uVG+7Rg0s/Mob+r+b
'' SIG '' PCQhG6rUmL3VSb8=
'' SIG '' End signature block
