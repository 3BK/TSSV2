''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' sysinfo.vbs script v1.1 by seanw@microsoft.com 4/9/2008
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
on error resume next
Const SCRIPT_VERSION = "v1.2 - 16-Jul-2008"
Const SCRIPT_AUTHOR = "seanw@microsoft.com"
Const MAX_WIDTH = 79
Dim SCRIPT_NAME : SCRIPT_NAME = wscript.scriptname
SKUList = array("Undefined","Ultimate Edition","Home Basic Edition","Home Basic Premium Edition","Enterprise Edition", _
                "Home Basic N Edition","Business Edition","Standard Server Edition","Datacenter Server Edition", _
                "Small Business Server Edition","Enterprise Server Edition","Starter Edition","Datacenter Server Core Edition", _
                "Standard Server Core Edition","Enterprise Server Core Edition","Enterprise Server IA64 Edition","Business N Edition", _
                "Web Server Edition","Cluster Server Edition","Home Server Edition","Storage Express Server Edition", _
                "Storage Standard Server Edition","Storage Workgroup Server Edition","Storage Enterprise Server Edition", _
                "Server For Small Business Edition","Small Business Server Premium Edition")

strComputer = "." 
if wscript.arguments.count <> 0 then
   strComputer = ucase(wscript.arguments(0))
end if

Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\CIMV2") 

Dim msg : msg = ""
msg = msg & string(MAX_WIDTH,&H3D) & vbcrlf
msg = msg & SCRIPT_NAME & " " & SCRIPT_VERSION _
      & space(MAX_WIDTH-len(SCRIPT_NAME)-len(SCRIPT_AUTHOR)-len(SCRIPT_VERSION)-1) _
      & SCRIPT_AUTHOR & vbcrlf
msg = msg & "Copyright (C) Microsoft Corporation 2001-2007               All rights reserved" & vbcrlf
msg = msg & string(MAX_WIDTH,&H3D)
wscript.echo msg

wbemQuery = "SELECT * FROM Win32_ComputerSystem"
Set colCompSys = objWMIService.ExecQuery(wbemQuery,,48) 
for each obj in colCompSys
   wscript.echo "Host Name                     : " & obj.Caption
   wscript.echo "System Manufacturer           : " & obj.Manufacturer
   wscript.echo "System Model                  : " & obj.Model
   wscript.echo "System Type                   : " & obj.SystemType
   wscript.echo "Startup Options               : " & obj.SystemStartupOptions(obj.SystemStartupSetting)
   roles = roles & "{" & join(obj.Roles,",") & "}"
   cpuinfo = " - " & obj.NumberOfProcessors & " Core(s), " & obj.NumberOfLogicalProcessors & " Logical Processor(s)"
next
wscript.echo

wbemQuery = "SELECT *FROM Win32_TimeZone"
Set colTZ = objWMIService.ExecQuery(wbemQuery,,48) 
wbemQuery = "SELECT * FROM Win32_OperatingSystem" 
Set colOS = objWMIService.ExecQuery(wbemQuery,,48)
wscript.echo "Operating System Information"
for each obj in colOS
   wscript.echo space(4) & "Product Name              : " & split(obj.Name,"|")(0)
   wscript.echo space(4) & "Product SKU               : " & SKUList(obj.OperatingSystemSKU)
   BuildNumber = obj.BuildNumber
   wscript.echo space(4) & "Version - SP - Build      : " & obj.Version & " - " & obj.CSDVersion & " - " & BuildNumber
   wscript.echo space(4) & "Build Type                : " & obj.BuildType
   wscript.echo space(4) & "Registered Owner          : " & obj.RegisteredUser
   wscript.echo space(4) & "Registered Organization   : " & obj.Organization
   wscript.echo space(4) & "Product ID                : " & obj.SerialNumber
   wscript.echo space(4) & "Install Date              : " & ConvertWMIDate(obj.InstallDate)
   wscript.echo space(4) & "System Up Time            : " & Uptime(obj.LastBootUpTime, obj.LocalDateTime)
   wscript.echo space(4) & "Windows Directory         : " & obj.WindowsDirectory
   wscript.echo space(4) & "Boot Device               : " & obj.BootDevice
   
   wscript.echo space(4) & "Locale (Language ID)      : " & obj.Locale & " (" & obj.OSLanguage  & ")"
   for each tz in colTZ
      wscript.echo space(4) & "Time Zone                 : " & tz.Description
   next
   wscript.echo space(4) & "Installed Roles           : " & roles
   wscript.echo

   wscript.echo "Memory Information"
   wscript.echo space(4) & "PAE Enabled               : " & obj.PAEEnabled
   wscript.echo space(4) & "3GB Enabled               : " & (obj.MaxProcessMemorySize > 2097024)
   wscript.echo space(4) & "Physical Memory"
   wscript.echo space(8) & "Total                 : " & int(obj.TotalVisibleMemorySize/1024) & " MB"
   wscript.echo space(8) & "Available             : " & int(obj.FreePhysicalMemory/1024) & " MB"
   wscript.echo space(4) & "Virtual Memory"
   wscript.echo space(8) & "Total                 : " & int(obj.TotalVirtualMemorySize/1024) & " MB"
   wscript.echo space(8) & "Available             : " & int(obj.FreeVirtualMemory/1024) & " MB"
next
wscript.echo

wbemQuery = "SELECT * FROM Win32_BIOS"
Set colBIOS = objWMIService.ExecQuery(wbemQuery,,48) 
wscript.echo "BIOS Information"
for each obj in colBIOS
   wscript.echo space(4) & "Name                      : " & obj.Name
   wscript.echo space(4) & "Version                   : " & "{" & obj.Version & "," & obj.SMBIOSBIOSVersion & "}"
   wscript.echo space(4) & "SMBIOS Version            : " & obj.SMBIOSMajorVersion & "." & obj.SMBIOSMinorVersion
   wscript.echo space(4) & "Date                      : " & ConvertWMIDate(obj.ReleaseDate)
next
wscript.echo

wbemQuery = "SELECT * FROM Win32_Processor"
Set colCPU = objWMIService.ExecQuery(wbemQuery,,48) 
wscript.echo "Processor Information" & cpuinfo
for each obj in colCPU
   wscript.echo "[" & obj.DeviceID & "]"
   wscript.echo space(4) & "Manufacturer              : " & obj.Manufacturer
   wscript.echo space(4) & "Name                      : " & obj.Name
   wscript.echo space(4) & "Description               : " & obj.Description
   wscript.echo space(4) & "Clock Speed - Max(Current): " & obj.MaxClockSpeed & "MHz (" & obj.CurrentClockSpeed & "MHz)"
   wscript.echo space(4) & "External Clock Speed      : " & obj.ExtClock & "MHz"
   wscript.echo space(4) & "L2 Cache Size             : " & obj.L2CacheSize & " KB"
   edx = clng("&H" & left(obj.ProcessorId,8))
   select case obj.Manufacturer
      case "AuthenticAMD"
         if (edx and &H10000000) = &H10000000 then
            wscript.echo space(4) & "ProcessorId               : " & obj.ProcessorId & " - This processor is Multi-core or supports Hyperthreading."
         else
            wscript.echo space(4) & "ProcessorId               : " & obj.ProcessorId & " - This processor does not support Hyperthreading."
         end if
      case "GenuineIntel"
         if edx = 0 then
            wscript.echo space(4) & "ProcessorId               : " & obj.ProcessorId & " - This appears to be a logical processor."
         else 
            if (edx and &H10000000) = &H10000000 then
               wscript.echo space(4) & "ProcessorId               : " & obj.ProcessorId & " - This processor supports Hyperthreading."
            else
               wscript.echo space(4) & "ProcessorId               : " & obj.ProcessorId & " - This processor does not support Hyperthreading."
            end if
         end if
   end select   
next 
wscript.echo

wbemQuery = "SELECT * FROM Win32_PageFileUsage"
Set colPageFile = objWMIService.ExecQuery(wbemQuery,,48) 
wscript.echo "Pagefile Information"
for each obj in colPageFile
   wscript.echo space(4) & "Allocated Size            : " & obj.AllocatedBaseSize & " MB"
   wscript.echo space(4) & "Current Usage             : " & obj.CurrentUsage & " MB"
   wscript.echo space(4) & "Peak Usage                : " & obj.PeakUsage & " MB"
   wscript.echo space(4) & "File name                 : " & obj.Name
next

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' Function     ConvertWMIDate(byval wmiDate)
' Description  reformat a WMI date
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
Function ConvertWMIDate(byval wmiDate)
   tmpstr = Mid(wmiDate,5,2) & "/"  & Mid(wmiDate,7,2) & "/"  & Mid(wmiDate,1,4)
   if Mid(wmiDate,9,2) <> "**" then
      tmpstr = tmpstr & " " &  Mid(wmiDate,9,2) & ":" & Mid(wmiDate,11,2) & ":" & Mid(wmiDate,13,2)
   end if
   ConvertWMIDate = cdate(tmpstr)
end function

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' Function     Uptime(byval boottime, byval current)
' Description  reformat a WMI date
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
Function Uptime(byval boottime, byval current)
   diff = datediff("s",ConvertWMIDate(boottime),ConvertWMIDate(current))
   secs = diff mod 60
   mins = (diff \ 60) mod 60
   hours = (diff \ 60*60) mod 24
   days =  diff \ (60*60*24)
   Uptime = days & " day(s) " & hours & " hour(s) " & mins & " minute(s) " & secs & " second(s)"
end function

'' SIG '' Begin signature block
'' SIG '' MIInoQYJKoZIhvcNAQcCoIInkjCCJ44CAQExDzANBglg
'' SIG '' hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
'' SIG '' BgEEAYI3AgEeMCQCAQEEEE7wKRaZJ7VNj+Ws4Q8X66sC
'' SIG '' AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
'' SIG '' /gnyTrN68PbucpC8eLiQyyVib+KQEvntzudtSimgdCeg
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
'' SIG '' ghl0MIIZcAIBATCBlTB+MQswCQYDVQQGEwJVUzETMBEG
'' SIG '' A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
'' SIG '' ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
'' SIG '' MSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5n
'' SIG '' IFBDQSAyMDExAhMzAAACU+OD3pbexW7MAAAAAAJTMA0G
'' SIG '' CWCGSAFlAwQCAQUAoIGwMBkGCSqGSIb3DQEJAzEMBgor
'' SIG '' BgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
'' SIG '' AYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCA7DAHNe6nZkEE
'' SIG '' NUObFYQ78j4kgVEzRDTEL+OK+UcfATBEBgorBgEEAYI3
'' SIG '' AgEMMTYwNKAUgBIATQBpAGMAcgBvAHMAbwBmAHShHIAa
'' SIG '' aHR0cHM6Ly93d3cubWljcm9zb2Z0LmNvbSAwDQYJKoZI
'' SIG '' hvcNAQEBBQAEggEAhboyj5a/sYjRxExpa8ViQVAk1jCr
'' SIG '' bpDDQD9uvDMoYL+GT0KBcj54OJgDT+bAaJWlFJYm4OEP
'' SIG '' izd7bsPlbParCQvwcdabShbIPQtO85iE0b3hQ5Yk6LXd
'' SIG '' YmI+uHjKZn9rt6h267ioz8SYiQGo3ZFynMhier1kk4dg
'' SIG '' vmZUP+sKXH8gaEyS6djDnrXbGoR0UOsdpRcHRRYdyxd3
'' SIG '' 40pW6BvOadUe0v6p2lopMHFWE3uqInFSu0114AZEFPhL
'' SIG '' TqA8LbgsO60yeTr4m7G7pK4hoCuhRe5AXM/Jxgd1+ZA6
'' SIG '' yYhaCaF8fc1wci+kXF/ddXl7vXvX27N1YlU4UvH+EIwN
'' SIG '' en7M/KGCFvwwghb4BgorBgEEAYI3AwMBMYIW6DCCFuQG
'' SIG '' CSqGSIb3DQEHAqCCFtUwghbRAgEDMQ8wDQYJYIZIAWUD
'' SIG '' BAIBBQAwggFQBgsqhkiG9w0BCRABBKCCAT8EggE7MIIB
'' SIG '' NwIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUA
'' SIG '' BCDML75hF1jIJtjH/GUVUfQlYSRhwA+r/irtyUbVZuub
'' SIG '' dQIGYhZtkseVGBIyMDIyMDMyODE2NTYwMi42NFowBIAC
'' SIG '' AfSggdCkgc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
'' SIG '' EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
'' SIG '' HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAj
'' SIG '' BgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
'' SIG '' bnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjdCRjEt
'' SIG '' RTNFQS1CODA4MSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
'' SIG '' ZS1TdGFtcCBTZXJ2aWNloIIRVDCCBwwwggT0oAMCAQIC
'' SIG '' EzMAAAGfK0U1FQguS10AAQAAAZ8wDQYJKoZIhvcNAQEL
'' SIG '' BQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
'' SIG '' bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
'' SIG '' FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
'' SIG '' TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
'' SIG '' MjExMjAyMTkwNTIyWhcNMjMwMjI4MTkwNTIyWjCByjEL
'' SIG '' MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
'' SIG '' EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
'' SIG '' c29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9z
'' SIG '' b2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMd
'' SIG '' VGhhbGVzIFRTUyBFU046N0JGMS1FM0VBLUI4MDgxJTAj
'' SIG '' BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZp
'' SIG '' Y2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
'' SIG '' AQCk9Xl8TVGyiZAvzm8tB4fLP0znL883YDIG03js1/Wz
'' SIG '' CaICXDs0kXlJ39OUZweBFa/V8l27mlBjyLZDtTg3W8dQ
'' SIG '' ORDunfn7SzZEoFmlXaSYcQhyDMV5ghxi6lh8y3NV1TNH
'' SIG '' GYLzaoQmtBeuFSlEH9wp6rC/sRK7GPrOn17XAGzo+/yF
'' SIG '' y7DfWgIQ43X35ut20TShUeYDrs5GOVpHp7ouqQYRTpu+
'' SIG '' lAaCHfq8tr+LFqIyjpkvxxb3Hcx6Vjte0NPH6GnICT84
'' SIG '' PxWYK7eoa5AxbsTUqWQyiWtrGoyQyXP4yIKfTUYPtsTF
'' SIG '' Ci14iuJNr3yRGjo4U1OHZU2yGmWeCrdccJgkby6k2N5A
'' SIG '' hRYvKHrePPh5oWHY01g8TckxV4h4iloqvaaYGh3HDPWP
'' SIG '' w4KoKyEy7QHGuZK1qAkheWiKX2qE0eNRWummCKPhdcF3
'' SIG '' dcViVI9aKXhty4zM76tsUjcdCtnG5VII6eU6dzcL6YFp
'' SIG '' 0vMl7JPI3y9Irx9sBEiVmSigM2TDZU4RUIbFItD60DJY
'' SIG '' zNH0rGu2Dv39P/0Owox37P3ZfvB5jAeg6B+SBSD0awi+
'' SIG '' f61JFrVc/UZ83W+5tgI/0xcLGWHBNdEibSF1NFfrV0KP
'' SIG '' CKfi9iD2BkQgMYi02CY8E3us+UyYA4NFYcWJpjacBKAB
'' SIG '' eDBdkY1BPfGgzskaKhIGhdox9QIDAQABo4IBNjCCATIw
'' SIG '' HQYDVR0OBBYEFGI08tUeExYrSA4u6N/ZasfWHchhMB8G
'' SIG '' A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8G
'' SIG '' A1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9z
'' SIG '' b2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRp
'' SIG '' bWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggr
'' SIG '' BgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93
'' SIG '' d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWlj
'' SIG '' cm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAo
'' SIG '' MSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYI
'' SIG '' KwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBAB2KKCk8
'' SIG '' O+kZ8+m9bPXQIAmo+6xbKDaKkMR3/82A8XVAMa9RpItY
'' SIG '' Jkdkta+C6ZIVBsZEARJkKnWpYJiiyGBV3PmPoIMP5zFb
'' SIG '' r0BYLMolDJZMtH3MifVBD9NknYNKg+GbWyaAPs8VZ6UD
'' SIG '' 3CRzjoVZ2PbHRH+UOl2Yc/cm1IR3BlvjlcNwykpzBGUn
'' SIG '' dARefuzjfRSfB+dBzmlFY+dME8+J3OvveMraIcznSrlr
'' SIG '' 46GXMoWGJt0hBJNf4G5JZqyXe8n8z2yR5poL2uiMRzqI
'' SIG '' XX1rwCIXhcLPFgSKN/vJxrxHiF9ByViouf4jCcD8O2mO
'' SIG '' 94toCSqLERuodSe9dQ7qrKVBonDoYWAx+W0XGAX2qaoZ
'' SIG '' mqEun7Qb8hnyNyVrJ2C2fZwAY2yiX3ZMgLGUrpDRoJWd
'' SIG '' P+tc5SS6KZ1fwyhL/KAgjiNPvUBiu7PF4LHx5TRFU7HZ
'' SIG '' XvgpZDn5xktkXZidA4S26NZsMSygx0R1nXV3ybY3JdlN
'' SIG '' fRETt6SIfQdCxRX5YUbI5NdvuVMiy5oB3blfhPgNJyo0
'' SIG '' qdmkHKE2pN4c8iw9SrajnWcM0bUExrDkNqcwaq11Dzwc
'' SIG '' 0lDGX14gnjGRbghl6HLsD7jxx0+buzJHKZPzGdTLMFKo
'' SIG '' SdJeV4pU/t3dPbdU21HS60Ex2Ip2TdGfgtS9POzVaTA4
'' SIG '' UucuklbjZkQihfg2MIIHcTCCBVmgAwIBAgITMwAAABXF
'' SIG '' 52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDEL
'' SIG '' MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
'' SIG '' EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
'' SIG '' c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9z
'' SIG '' b2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIw
'' SIG '' MTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1
'' SIG '' WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
'' SIG '' Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
'' SIG '' TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
'' SIG '' aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIw
'' SIG '' DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzn
'' SIG '' tHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9s
'' SIG '' SuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWN
'' SIG '' E893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFc
'' SIG '' UTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUm
'' SIG '' ZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W
'' SIG '' 7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0
'' SIG '' hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0Xn
'' SIG '' Rm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De
'' SIG '' +JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXf
'' SIG '' tnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SU
'' SIG '' HDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyO
'' SIG '' ArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
'' SIG '' IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh
'' SIG '' 8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMUR
'' SIG '' HXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54W
'' SIG '' cmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEE
'' SIG '' AYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+
'' SIG '' ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBe
'' SIG '' Yl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEE
'' SIG '' AYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3
'' SIG '' dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9z
'' SIG '' aXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkG
'' SIG '' CSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQE
'' SIG '' AwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaA
'' SIG '' FNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0w
'' SIG '' S6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9w
'' SIG '' a2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEw
'' SIG '' LTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
'' SIG '' BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
'' SIG '' a2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMu
'' SIG '' Y3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9n
'' SIG '' ATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2
'' SIG '' P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2
'' SIG '' HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1
'' SIG '' AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3
'' SIG '' lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BU
'' SIG '' hUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tu
'' SIG '' PywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZ
'' SIG '' lvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdU
'' SIG '' bZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz
'' SIG '' 138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFH
'' SIG '' qfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xB
'' SIG '' Zj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7
'' SIG '' Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
'' SIG '' 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784
'' SIG '' cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1V
'' SIG '' M1izoXBm8qGCAsswggI0AgEBMIH4oYHQpIHNMIHKMQsw
'' SIG '' CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
'' SIG '' MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
'' SIG '' b2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3Nv
'' SIG '' ZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1U
'' SIG '' aGFsZXMgVFNTIEVTTjo3QkYxLUUzRUEtQjgwODElMCMG
'' SIG '' A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
'' SIG '' ZaIjCgEBMAcGBSsOAwIaAxUAdF2umB/yywxFLFTC8rJ9
'' SIG '' Fv9c9reggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
'' SIG '' A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
'' SIG '' ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
'' SIG '' MSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
'' SIG '' Q0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOXrw4owIhgP
'' SIG '' MjAyMjAzMjgxMzE4MDJaGA8yMDIyMDMyOTEzMTgwMlow
'' SIG '' dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5evDigIBADAH
'' SIG '' AgEAAgIBzTAHAgEAAgIThDAKAgUA5e0VCgIBADA2Bgor
'' SIG '' BgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIB
'' SIG '' AAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUA
'' SIG '' A4GBAMKxeLG/sKyDyui4uV2biSqBcdZqdQurkRE8xIl9
'' SIG '' RQ4T6O9HjTqYIK9dgkJsXNS4pUyk6hZlVK2yZ9zrexUd
'' SIG '' /X+vySGPlrXb5z8U7DpPHU274LEsCytL4XphEyfL/eP8
'' SIG '' gcwT6IqWnnptVGICy/IfCI+WdrlSGuvnBLhQVe8cdRz9
'' SIG '' MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzAR
'' SIG '' BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
'' SIG '' bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
'' SIG '' bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
'' SIG '' UENBIDIwMTACEzMAAAGfK0U1FQguS10AAQAAAZ8wDQYJ
'' SIG '' YIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsq
'' SIG '' hkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgKcBTq5NK
'' SIG '' 0v+wqNPg+2WJuZX+mHOBiOx05YD0TPUy644wgfoGCyqG
'' SIG '' SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCG8V4poieJnqXn
'' SIG '' VzwNUejeKgLJfEH7P+jspyw3S3xc2jCBmDCBgKR+MHwx
'' SIG '' CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
'' SIG '' MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
'' SIG '' b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
'' SIG '' c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABnytF
'' SIG '' NRUILktdAAEAAAGfMCIEIFv55onZml2F94VBjZAoERFH
'' SIG '' hfGwe1P+r4drEFHlr0NIMA0GCSqGSIb3DQEBCwUABIIC
'' SIG '' AGCZUhFYlg24V36Zgd8huv2L7gjsS+Xft4OSOHJ/xJ5Y
'' SIG '' oPs3YwIcCd0yBi95U6GCiEEP/rRqRCy78oFeDrnmbzTV
'' SIG '' Vm0gytGS55xqTyeAITOQhAWyZO1xg403/ymnRwPG0ix6
'' SIG '' 62svDULk40ygpiQ6+og6sf1McfWa322bK6niYGDbAbDP
'' SIG '' J4SryTwx/lOBEelIlk2y3gPATNfN7PEwc6kCtuC0bAde
'' SIG '' a/eQfle0VkIHVTlDztfijvvKrQSi2AeyDkZ8FFiulRuU
'' SIG '' 34KNGW2HWlqPBrF0qM9YbHP8YpoGZnshOHeKXyWpbWPE
'' SIG '' 4YftcpjWP8P5gtUAJPM0op8+MtBe3ieaydDAt1w7c/22
'' SIG '' GqgsnbE0DjrfJ7gEicCQ7tFhbGFxwdaOAMDMOojI+9zf
'' SIG '' K1of7zuyF/zRE7er5qMmC/DX/gOzsD2Cp/G2Pqp9eeSS
'' SIG '' cx6DviwTaB3jYhXQAMV2Jie811Oqs2yZtxbFdR+Xhvft
'' SIG '' NrTJ/UsXzUOjRSdK7PvQL1yBokI0Jgk5IyKiJST+lZeg
'' SIG '' CoP53EaL8ZMKM/mYfYJ+8SCyHdcDhkVsDemIelLgHt0U
'' SIG '' w7dqigMKHfEwwEf/nW8ChSKI5ztJUXL5eWJXOZBh1Hk5
'' SIG '' MnUCOoUe6xV0HeFdZMwLKn66lWdLCZuQyaQ6XuBEk5fL
'' SIG '' AXoNwd6cesb218sbvepQ/g+S
'' SIG '' End signature block
