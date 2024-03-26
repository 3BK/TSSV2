''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' perfos_stats.vbs script v1.0 by seanw@microsoft.com 11/19/2007
'    This script get some basic performance counters
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
on error resume next
strComputer = "."
' WMI constants - values can be ORed together
Const wbemFlagReturnImmediately = &H10 ' Causes the call to return immediately.
Const wbemFlagForwardOnly       = &H20 ' Causes a forward-only enumerator to be returned (faster).

wbemFlags = (wbemFlagReturnImmediately or wbemFlagForwardOnly)

Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\CIMV2")
wbemQuery = "SELECT * FROM Win32_PerfRawData_PerfOS_Memory"
Set colItems = objWMIService.ExecQuery(wbemQuery, "WQL", wbemFlags)

Wscript.Echo "======================================================="
Wscript.Echo "Current time is: " & Now()
Wscript.Echo "Memory Statistics"
Wscript.Echo "=======================================================" & vbcrlf

For Each objItem In colItems
   for each prop in objItem.Properties_
      if (not isNull(prop.value) and not isEmpty(prop.value)) then
         wscript.echo prop.name & space(35-len(prop.name)) & prop.value
      end if
   next
next
wscript.echo

Wscript.Echo "=======================================================" 
Wscript.Echo "System Statistics"
Wscript.Echo "=======================================================" & vbCrLf

wbemQuery = "SELECT * FROM Win32_PerfRawData_PerfOS_Objects"
Set colItems = objWMIService.ExecQuery(wbemQuery, "WQL", wbemFlags)

For Each objItem In colItems
   for each prop in objItem.Properties_
      if (not isNull(prop.value) and not isEmpty(prop.value)) then
         wscript.echo prop.name & space(35-len(prop.name)) & prop.value
      end if
   next
Next
wscript.echo

wbemQuery = "SELECT * FROM Win32_PerfFormattedData_PerfProc_Process"
Set colItems = objWMIService.ExecQuery(wbemQuery, "WQL", wbemFlags)
Wscript.Echo "=======================================================" 
Wscript.Echo "Current Process Statistics"
Wscript.Echo "=======================================================" & vbCrLf

For Each objItem In colItems
   Wscript.Echo "------------------------------------------------" 
   wscript.echo "Name" & space(31) & objItem.Name
   Wscript.Echo "------------------------------------------------" 
   for each prop in objItem.Properties_
      if (not isNull(prop.value) and not isEmpty(prop.value) and not prop.name="Name") then
         wscript.echo prop.name & space(35-len(prop.name)) & prop.value
      end if
   next
   Wscript.Echo VBCrLf
Next
'' SIG '' Begin signature block
'' SIG '' MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' ImZb+6j+hzusfe6IX/SR6mFNyV/80oxRsomc1nC7ugmg
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
'' SIG '' AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCZ1w0xJ+vvU+hi
'' SIG '' JbBabENHXTxdjrkb0paE/S33dXP+0TBEBgorBgEEAYI3
'' SIG '' AgEMMTYwNKAUgBIATQBpAGMAcgBvAHMAbwBmAHShHIAa
'' SIG '' aHR0cHM6Ly93d3cubWljcm9zb2Z0LmNvbSAwDQYJKoZI
'' SIG '' hvcNAQEBBQAEggEAJb7MrNkfVUX0cEatofGOgYDucFi4
'' SIG '' q1EsGs6ek4CTgvE5R2MD5Sz+oZprPmOHATItnzJGcNnr
'' SIG '' tcEbUK4YJkQPoQ1dGAGwL5IvURc9u+CkHQBzBOEEnX8b
'' SIG '' YlPamo3KZ16MJ0GhRONEP+bWbSXTH/j3E/jZYEWBzNBT
'' SIG '' ttTLfBpArTwdWtgHTCFzpBn2XU6hOaLCBIN5hFc8cD1w
'' SIG '' 34tqcYWiTqeYGRe0tOTEsuYJN6Cy0BK6CTxcQU/1scdd
'' SIG '' j2dEWKg9Ua7fFBonkyXntt8vs4swfbULfZLFyOAV6urE
'' SIG '' T6jPe8cRQiyDEIER8TaZGLC/Dg+szY5wwh5y+pWEyx5Y
'' SIG '' 70vsTqGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCCFuUG
'' SIG '' CSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUD
'' SIG '' BAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIB
'' SIG '' OAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUA
'' SIG '' BCCsS651PYHohrRMbambp4MpZJLPtahgVOhyw0m35Vx7
'' SIG '' XQIGYhZtksOoGBMyMDIyMDMyODE2NTU0NC40NzJaMASA
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
'' SIG '' KoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIJxDpGaT
'' SIG '' 6YWvdZtMsySYS0aLPs6KkomiCCa/5Ah1reptMIH6Bgsq
'' SIG '' hkiG9w0BCRACLzGB6jCB5zCB5DCBvQQghvFeKaIniZ6l
'' SIG '' 51c8DVHo3ioCyXxB+z/o7KcsN0t8XNowgZgwgYCkfjB8
'' SIG '' MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
'' SIG '' bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
'' SIG '' cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
'' SIG '' b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAZ8r
'' SIG '' RTUVCC5LXQABAAABnzAiBCBb+eaJ2ZpdhfeFQY2QKBER
'' SIG '' R4XxsHtT/q+HaxBR5a9DSDANBgkqhkiG9w0BAQsFAASC
'' SIG '' AgCisjk0jzLIsbex25tcKs5oDkLW8HxHhXWD/oL4qUd1
'' SIG '' qIjTfN1l7OWg5IUIaCx2+fyHKhK6dpXX2KPYDG4m8mCr
'' SIG '' VD/D+EQW8uDdN03moApLiZ/Op8qSKg/cD2j9v5xGAH29
'' SIG '' XJZ0bvA2Bj34fyRmwc17+vtUi9ohyIFtPNNUdz6e2s6t
'' SIG '' j1nqxEEBRg/BgcSA/D/AjAn2c2cOVWsj9QdVIwJykaoE
'' SIG '' WYqyYVUabX7oeI2MyogTMCW+CCEkDxrw8Hr8LG3duXQM
'' SIG '' 3hprsdo25ezbXnQqmkf9ViKuJELZIOZnSykIrCHs6IYU
'' SIG '' VBMZPLrWcdYUYLqWu+kv5yX86B0ulGK/b19GfC7fq1JX
'' SIG '' VVCWgAIv68uxTJYn6gzCZr8TDO2Un9OL0Ym6JVb+SEjy
'' SIG '' /VBAvoXZn9mZX+S4ii90BkUbdUpxtf2MBDLYZsZpQG2/
'' SIG '' C0QQuET6tj5TcfAYkgjl5QaRmD2ByP5E41i2MA63lCeD
'' SIG '' X8AxAYaiDXyRvYspWUuI6e6ehtJnZUbgqSwxS67EmW4O
'' SIG '' DPUUme1IbI/QicpKzehet4ZC8TOJolVrZLIGffJ99EJu
'' SIG '' v46OAzyIcuoXSMzrvR6QzmyqVzQkw6Z6n9h6YpSIvFqt
'' SIG '' Vr3g6KuMygcIu9jsyw8QHMrsP1IT0gDIkA4WTdyf8pY3
'' SIG '' o69z3kXkCsbAXWMtq9pBrbLzAQ==
'' SIG '' End signature block
