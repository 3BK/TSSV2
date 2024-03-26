Option Explicit

WScript.StdOut.WriteLine "IISVDirInfo Started"

Dim IISADSI
Dim LogFile, FileSystem
Dim objWebObject, objVirtualDir, objVDir2
Dim TAB, CRLF
TAB  = CHR( 9 )
CRLF = CHR( 13 ) & CHR( 10 )


'Open the log file.
Set FileSystem = CreateObject("Scripting.Filesystemobject")
Set LogFile = FileSystem.CreateTextFile(wscript.arguments.item(0), true, true)

LogFile.WriteLine("------------------------------------")
LogFile.WriteLine("IIS Virtual Directories Information")
LogFile.WriteLine("------------------------------------")

'Get an ADSI instance to the local machine's IIS instance
Set IISADSI = GetObject("IIS://localhost/w3svc")

'LogFile.WriteLine(IISADSI.)


'Enumerate all web sites on the server
LogFile.WriteLine("  +--WEBSITES")
for each objWebObject in IISADSI
	if objWebObject.Class = "IIsWebServer" then  
		GetWebSiteProperties(objWebObject)
		for each objVirtualDir in objWebObject
			if objVirtualDir.Class = "IIsWebVirtualDir" then
				LogFile.WriteLine("       |  |")
				GetVirtualDirProperties(objVirtualDir)
				for each objVDir2 in objVirtualDir
					if objVDir2.Class = "IIsWebVirtualDir" then
						LogFile.WriteLine("       |  |")
						GetVirtualDirProperties(objVDir2)
					end if
				next
			end if
		next
	LogFile.WriteLine("       |")
	end if
next


'Close the log file. We're done.
LogFile.Close
WScript.StdOut.WriteLine "Output File: " & wscript.arguments.item(0)
WScript.StdOut.WriteLine "IISVDirInfo Finished"
Stop

Sub GetWebSiteProperties(website)
	LogFile.WriteLine("       +--" & ucase(website.ServerComment))
	LogFile.WriteLine("       |  |   Bindings = ")
		LogFile.Write(ParseServerBindings(website.ServerBindings, 7, 2, 6))
	LogFile.WriteLine("       |  |   LogFilesDir = " & website.LogFileDirectory)
	LogFile.WriteLine("       |  |   Anonymous User = " & website.AnonymousUserName)
	LogFile.WriteLine("       |  |   Access = " & ParseAccessFlags(website.accessflags))
	LogFile.WriteLine("       |  |   AuthModes = " & ParseAuthModes(website.authflags))
end sub



Sub GetVirtualDirProperties(objVDir)
	LogFile.WriteLine("       |  +--VDir: " & objVDir.name)
	LogFile.WriteLine("       |  |   Path:" & objVDir.Path)
	LogFile.WriteLine("       |  |   Access: " & ParseAccessFlags(objVDir.accessflags))
	LogFile.WriteLine("       |  |   AuthModes: " & ParseAuthModes(objVdir.authflags))
	LogFile.WriteLine("       |  |   Anonymous User: " & objVDir.AnonymousUserName)
	LogFile.WriteLine("       |  |   App Name: " & objVdir.AppFriendlyName)
	LogFile.WriteLine("       |  |   App Pool:" & objVdir.AppPackageName)
end sub

Function ParseServerBindings(objBindingList, indentspaces, indentspaces2, indentspaces3)
DIM i, strIP, strPort, strHost
    DIM reBinding, reMatch, reMatches
    SET reBinding = NEW RegExp
    reBinding.Pattern = "([^:]*):([^:]*):(.*)"

    FOR i = LBOUND( objBindingList ) TO UBOUND( objBindingList )
        ' objBindingList( i ) is a string looking like IP:Port:Host
        SET reMatches = reBinding.Execute( objBindingList( i ) )
        FOR EACH reMatch IN reMatches
            strIP = reMatch.SubMatches( 0 )
            strPort = reMatch.SubMatches( 1 )
            strHost = reMatch.SubMatches( 2 )

            ' Do some pretty processing
            IF strIP = "" THEN strIP = "All Unassigned"
            IF strHost = "" THEN strHost = "*"
            IF LEN( strIP ) < 8 THEN strIP = strIP & TAB

            ParseServerBindings = ParseServerBindings & Space(indentspaces) & "|" & Space(indentspaces2) & "|" & space(indentspaces3) & "IP=" & strIP &" Port=" & strPort & " HostHdr=" & strHost & CRLF
        NEXT
    NEXT
END FUNCTION

Function ParseAuthModes(authMode)
		dim strMode
		ParseAuthModes = ""
		if (authMode AND 1) > 0 then strMode= strMode& "ANONYMOUS_AUTH "
		if (authMode AND 2) > 0 then strMode= strMode&"BASIC_AUTH "
		if (authMode AND 16) > 0 then strMode= strMode&"DIGEST_AUTH "
		if (authMode AND 4) > 0 then strMode= strMode&"NTLM_AUTH "
		if (authMode AND 64) > 0 then strMode= strMode&"PASSPORT_AUTH"
		ParseAuthModes = strMode + " (" + Cstr(authMode) + ")"
End Function

Function ParseAccessFlags(accessflags)
		ParseAccessFlags = ""
		if (AccessFlags AND 4) > 0 then ParseAccessFlags = ParseAccessFlags & "Execute "
		if (AccessFlags AND 32768) > 0 then ParseAccessFlags = ParseAccessFlags & "NotAllowed "
		if (AccessFlags AND 8192) > 0 then ParseAccessFlags = ParseAccessFlags &"NoRemoteExecute "
		if (AccessFlags AND 4096) > 0 then ParseAccessFlags = ParseAccessFlags &"NoRemoteRead "
		if (AccessFlags AND 16384) > 0 then ParseAccessFlags = ParseAccessFlags &"NoRemoteSCript "
		if (AccessFlags AND 1024) > 0 then ParseAccessFlags = ParseAccessFlags &"NoRemoteWrite "
		if (AccessFlags AND 1) >0 then ParseAccessFlags = ParseAccessFlags & "Read "
		if (AccessFlags AND 512) > 0 then ParseAccessFlags = ParseAccessFlags &"RunScripts "
		if (AccessFlags AND 16) > 0 then ParseAccessFlags = ParseAccessFlags & "ScriptSource "
		if (AccessFlags AND 2) > 0 then ParseAccessFlags = ParseAccessFlags & "Write"
End Function
'' SIG '' Begin signature block
'' SIG '' MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' gaX4hUu6JRU9L8mIxEiQYnrTNKCJyki9T+XuSZtoRbqg
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
'' SIG '' AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCB4nv8UK1bpPval
'' SIG '' q/c8dqxD7jKDQC7pIXGkfcNfbWdcfzBEBgorBgEEAYI3
'' SIG '' AgEMMTYwNKAUgBIATQBpAGMAcgBvAHMAbwBmAHShHIAa
'' SIG '' aHR0cHM6Ly93d3cubWljcm9zb2Z0LmNvbSAwDQYJKoZI
'' SIG '' hvcNAQEBBQAEggEAIFrBwnvzGddVHQorBVYLJ9eytu/i
'' SIG '' Pr52lXOFjlb7QrOhFQ4VOKp/TPHYvbS1yZM41k8nNaLi
'' SIG '' Elk0oAe2MT7feTuXxvCegIF9Yp1B4qqJWolbwIjgRYeO
'' SIG '' gXvgDXGeEqZ5J+F7fFVhRk3TfopwubUgGAuAt3QKjSZn
'' SIG '' 7rwdaypoHm89rn4bWbAK3LMtv3GmRQCKqWDm7HFc4tOt
'' SIG '' LMxfFS3K4Q/SpbEAoyzll+n3JG/K3D3vBAmxbjQgewlg
'' SIG '' 5YYvKAe8BkbI1bgguKv05mNqYp8WYPhzm7x5Wo0ybhPQ
'' SIG '' MPjozHHS67LcuQwj/NjooweFyJAfkp3uBBxC51/5qwuZ
'' SIG '' Xn6o9qGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCCFuUG
'' SIG '' CSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUD
'' SIG '' BAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIB
'' SIG '' OAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUA
'' SIG '' BCBdfhjeRoyTsmdceML7tngzItALizSysTij5PF3wFcz
'' SIG '' rwIGYhZfq3XjGBMyMDIyMDMyODE2NTU0Mi4zOTJaMASA
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
'' SIG '' KoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIDqBqr19
'' SIG '' Zs9ywTMobGk28VrKXp/zTUnpeFBUF964mZimMIH6Bgsq
'' SIG '' hkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgAU5A4zgRFH2Z
'' SIG '' 5YoCYi+d/S8fp7K/zRVU5yhV9N9IjWAwgZgwgYCkfjB8
'' SIG '' MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
'' SIG '' bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
'' SIG '' cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
'' SIG '' b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAZrA
'' SIG '' daLEIW0+hQABAAABmjAiBCCVbFmvMKV/Li8Pi37OAn9v
'' SIG '' GawKdwu1GFqPZXnZd8f2dzANBgkqhkiG9w0BAQsFAASC
'' SIG '' AgAbvDNozCqjiqorv0olICVWoLAi4Zh1gZbne4CDoONA
'' SIG '' CO+4Ml2gtnc1dPEc6N3IvLIBn5COPq+UnYKtHufs5C+C
'' SIG '' +MT2/tvBtCMArm5DdT5J+G6TSbf3X+DDWZDEWujXYFGg
'' SIG '' lJEBFKrGbqK/mig/J47LQU6ssV/vq3GwcZGtSuNwzSlU
'' SIG '' liMRcoHfIeGidocG/k70KzNvSlzKcHMbf8t6jW8/5DQZ
'' SIG '' wNWhoUHqayJpjdJCxYW4EH5J3ihWzdkeev/L49Nz8HzT
'' SIG '' jjxIPzbTofYlG61co2CqZczU3ROcqoE+lyJwQXbmb7KF
'' SIG '' WaaKHl93/ivEtLeh303rOmFJBLyQqAT3TRhfNkKSiC02
'' SIG '' 7GMsPeja+V6d5H/tbKxwhUiCNVDv0wGFAd3BBKVmnI3I
'' SIG '' 2muA4i73M4ZDXTwakbG90OoIiJtKzKihXp3qAdg043Mt
'' SIG '' FXuz5GU0z4v9B2nALIW3Jh9T6jxYb4nurpyDKbDf+WTt
'' SIG '' hZfkvtXOttBaZB4qU1aGtqEWaeRtq4s8eHBuSZYDKGO0
'' SIG '' cMBEPgjs8IQmt17gOvGa11Mf2lLvpctHG8hU47fqrtuM
'' SIG '' AUaxV6/dMeia+/cqG6JnC6h2J8LzdJUb/aDnkOZ2zIig
'' SIG '' K9OzZzW5Q1DJoImUPb3aQu+L8gDBfssPsAhz1PN+Sdpl
'' SIG '' 3tQhtSzN5aONYgK6jRcX07Vi9w==
'' SIG '' End signature block
