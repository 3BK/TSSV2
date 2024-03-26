param( [string]$DataPath, `
       [switch]$AcceptEula, `
       [switch]$Trace, `
       [switch]$Logs, `
       [switch]$Activity, `
       [switch]$Fwd, `
       [switch]$FwdCli, `
       [switch]$RemShell, `
       [switch]$HTTPSYS, `
       [switch]$WinHTTP, `
       [switch]$CAPI, `
       [switch]$Kerberos, `
       [switch]$NTLM, `
       [switch]$PKU2U, `
       [switch]$Schannel, `
       [switch]$EventLog, `
       [switch]$WMI, `
       [switch]$Network, `
       [switch]$PerfMon, `
       [switch]$Kernel 
)

$version = "WinRM-Collect (20230516)"
$DiagVersion = "WinRM-Diag (20230515)"

# by Gianni Bragante - gbrag@microsoft.com

Function Write-Diag {
  param( [string] $msg )
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg
  $msg | Out-File -FilePath $diagfile -Append
}

Function WinRMTraceCapture {
  Invoke-CustomCommand ("logman create trace 'WinRM-Trace' -ow -o '" + $TracesDir + "\WinRM-Trace-$env:COMPUTERNAME.etl" + "' -p 'Microsoft-Windows-WinRM' 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets")  
  
  Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{04C6E16D-B99F-4A3A-9B3E-B8325BBC781E}' 0xffffffffffffffff 0xff -ets" # Windows Remote Management Trace

  if (-not $Activity -or $Fwd) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{699E309C-E782-4400-98C8-E21D162D7B7B}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Forwarding
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{B977CF02-76F6-DF84-CC1A-6A4B232322B6}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-EventCollector
  }

  if (-not $Activity -or $RemShell) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{F1CAB2C0-8BEB-4FA2-90E1-8F17E0ACDD5D}' 0xffffffffffffffff 0xff -ets" # RemoteShellClient
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{03992646-3DFE-4477-80E3-85936ACE7ABB}' 0xffffffffffffffff 0xff -ets" # RemoteShell
  }
  if (-not $Activity -or $HTTPSYS) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{72B18662-744E-4A68-B816-8D562289A850}' 0xffffffffffffffff 0xff -ets" # Windows HTTP Services
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{DD5EF90A-6398-47A4-AD34-4DCECDEF795F}' 0xffffffffffffffff 0xff -ets" # HTTP Service Trace
  }
  if ($HTTPSYS) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{20F61733-57F1-4127-9F48-4AB7A9308AE2}' 0xffffffffffffffff 0xff -ets" # HttpSysGuid
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{B1945E15-4933-460F-8103-AA611DDB663A}' 0xffffffffffffffff 0xff -ets" # HttpSysProvider
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{C42A2738-2333-40A5-A32F-6ACC36449DCC}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-HttpLog
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{7B6BC78C-898B-4170-BBF8-1A469EA43FC5}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-HttpEvent
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{F5344219-87A4-4399-B14A-E59CD118ABB8}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Http-SQM-Provider
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{08F93B14-1608-4A72-9CFA-457EECEDBBA7}' 0xffffffffffffffff 0xff -ets" # WebIo
  }
  if (-not $Activity -or $WinHTTP) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{7D44233D-3055-4B9C-BA64-0D47CA40A232}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-WinHttp
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{B3A7698A-0C45-44DA-B73D-E181C9B5C8E6}' 0xffffffffffffffff 0xff -ets" # WinHttp
  }
  if (-not $Activity -or $CAPI) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-CAPI2
  }
  if (-not $Activity -or $Kerberos) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{6B510852-3583-4E2D-AFFE-A67F9F223438}' 0xffffffffffffffff 0xff -ets" # Kerberos Authentication
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4}' 0xffffffffffffffff 0xff -ets" # Kerberos Client
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Security-Kerberos
  }
  if (-not $Activity -or $CredSSP) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{6165F3E2-AE38-45D4-9B23-6B4818758BD9}' 0xffffffffffffffff 0xff -ets" # TSPkg
  }
  if (-not $Activity -or $NTLM) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{AC43300D-5FCC-4800-8E99-1BD3F85F0320}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-NTLM
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{C92CF544-91B3-4DC0-8E11-C580339A0BF8}' 0xffffffffffffffff 0xff -ets" # NTLM Security Protocol
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{5BBB6C18-AA45-49B1-A15F-085F7ED0AA90}' 0xffffffffffffffff 0xff -ets" # NTLM Authentication
  }
  if ($PKU2U) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{2A6FAF47-5449-4805-89A3-A504F3E221A6}' 0xffffffffffffffff 0xff -ets" # Pku2u Authentication
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{B1108F75-3252-4B66-9239-80FD47E06494}' 0xffffffffffffffff 0xff -ets" # IdentityCommonLib
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{D93FE84A-795E-4608-80EC-CE29A96C8658}' 0xffffffffffffffff 0xff -ets" # IdentityListenerControlGuid
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{82C7D3DF-434D-44FC-A7CC-453A8075144E}' 0xffffffffffffffff 0xff -ets" # IDStore
  }
  if (-not $Activity -or $Schannel) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{1F678132-5938-4686-9FDC-C8FF68F15C85}' 0xffffffffffffffff 0xff -ets" # Schannel
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{37D2C3CD-C5D4-4587-8531-4696C44244C8}' 0xffffffffffffffff 0xff -ets" # SchannelWppGuid
  }

  if ($FwdCli) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{9D11915C-C654-4D73-A6D6-591570E011A0}' 0xffffffffffffffff 0xff -ets" # EvtFwdrWpp
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{6FCDF39A-EF67-483D-A661-76D715C6B008}' 0xffffffffffffffff 0xff -ets" # ForwarderTrace
  }
  if ($FwdCli -or $EventLog) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{FC65DDD8-D6EF-4962-83D5-6E5CFE9CE148}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Eventlog
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{B0CA1D82-539D-4FB0-944B-1620C6E86231}' 0xffffffffffffffff 0xff -ets" # EventlogTrace
  }
  if ($WMI) {
    Invoke-CustomCommand "logman update trace 'WinRM-Trace' -p '{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}' 0xffffffffffffffff 0xff -ets" # WMI-Activity
  }
  if ($Network) {
    Invoke-CustomCommand ("netsh trace start capture=yes scenario=netconnection maxsize=2048 report=disabled tracefile='" + $TracesDir + "NETCAP-" + $env:COMPUTERNAME + ".etl'")
  }  
  if ($Kernel) {
    Invoke-CustomCommand ("logman create trace 'NT Kernel Logger' -ow -o '" + $TracesDir + "\WinRM-Trace-kernel-$env:COMPUTERNAME.etl" + "' -p '{9E814AAD-3204-11D2-9A82-006008A86939}' 0x1 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 512 -ets")
  }
  if ($PerfMon) {
    Invoke-CustomCommand ("Logman create counter 'WinRM-Trace-PerfMon' -f bincirc  -max 2048 -c '\Process(*)\*' '\Processor(*)\*' '\PhysicalDisk(*)\*' '\Event Tracing for Windows Session(EventLog-*)\Events Lost' '\Event Tracing for Windows Session(EventLog-*)\Events Logged per sec' '\HTTP Service Request Queues(*)\*' -si 00:00:01 -o '" + $TracesDir + "WinRM-trace-$env:COMPUTERNAME.blg'")
    Invoke-CustomCommand ("logman start 'WinRM-Trace-PerfMon'")
  }

  Write-Log "Trace capture started"
  read-host "Press ENTER to stop the capture"
  Invoke-CustomCommand "logman stop 'WinRM-Trace' -ets"
  if ($Network) {
    Invoke-CustomCommand "netsh trace stop"
  }  
  if ($Kernel) {
    Invoke-CustomCommand "logman stop 'NT Kernel Logger' -ets"
  }
  if ($PerfMon) {
    Invoke-CustomCommand ("logman stop 'WinRM-Trace-PerfMon'")
    Invoke-CustomCommand ("logman delete 'WinRM-Trace-PerfMon'")
  }


  Invoke-CustomCommand "tasklist /svc" -DestinationFile ("Traces\tasklist-$env:COMPUTERNAME.txt")
}
Function GetPlugins{
  # This function is a contribution from Ga�tan Rabier
  param(
    [string] $WinRMPluginPath = "WSMan:\localhost\plugin"
  )
  Write-Log ("Parsing plugins from path " + $WinRMPluginPath)
  $WinRMPlugins = Get-ChildItem $WinRMPluginPath

  foreach ($Plugin in $WinRMPlugins) {
    $PluginName = $Plugin.Name
    $PluginURIs = (Get-ChildItem $WinRMPluginPath\$PluginName\Resources).Name
    $PluginDLL = (Get-ChildItem $WinRMPluginPath\$PluginName\Filename).Value
    $PluginName  | Out-File -FilePath ($resDir + "\Plugins.txt") -Append
    ("  DLL: " + $PluginDLL) | Out-File -FilePath ($resDir + "\Plugins.txt") -Append
    foreach ($PluginURI in $PluginURIs) {
      $Capability = (Get-ChildItem $WinRMPluginPath\$PluginName\Resources\$PluginURI\Capability).Value
      $SecurityContainerName = (Get-ChildItem $WinRMPluginPath\$PluginName\Resources\$PluginURI\Security).Name
      $SecurityContainer = Get-ChildItem $WinRMPluginPath\$PluginName\Resources\$PluginURI\Security\$SecurityContainerName
      $SecuritySddl = ($SecurityContainer |Where-Object {$_.Name -eq 'Sddl'}).Value
      $SecuritySddlConverted = (ConvertFrom-SddlString $SecuritySddl).DiscretionaryAcl
      $ResourceURI = ($SecurityContainer | Where-Object {$_.Name -eq 'ParentResourceUri'}).Value

      ("  URI: " + $ResourceURI) | Out-File -FilePath ($resDir + "\Plugins.txt") -Append
      ("    Capabilities: " + $Capability) | Out-File -FilePath ($resDir + "\Plugins.txt") -Append
      ("    Security descriptor : " + $SecuritySddlConverted) | Out-File -FilePath ($resDir + "\Plugins.txt") -Append
      " " | Out-File -FilePath ($resDir + "\Plugins.txt") -Append
      Remove-Variable SecurityContainerName,SecurityContainer,ResourceURI,Capability,SecuritySddlConverted,SecuritySddl
    }
  }
}

Function EvtLogDetails {
  param(
    [string] $LogName
  )
  Write-Log ("Collecting the details for the " + $LogName + " log")
  $cmd = "wevtutil gl " + $logname + " >>""" + $resDir + "\EventLogs.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

  Write-Log ("Collecting the details for the " + $LogName + " log")
  $cmd = "wevtutil gli " + $logname + " >>""" + $resDir + "\EventLogs.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

  "" | Out-File -FilePath ($resDir + "\EventLogs.txt") -Append

  if ($logname -ne "ForwardedEvents") {
    $evt = (Get-WinEvent -Logname $LogName -MaxEvents 1 -Oldest)
    "Oldest " + $evt.TimeCreated + " (" + $evt.RecordID + ")" | Out-File -FilePath ($resDir + "\EventLogs.txt") -Append
    $evt = (Get-WinEvent -Logname $LogName -MaxEvents 1)
    "Newest " + $evt.TimeCreated + " (" + $evt.RecordID + ")" | Out-File -FilePath ($resDir + "\EventLogs.txt") -Append
    "" | Out-File -FilePath ($resDir + "\EventLogs.txt") -Append
  }
}

Function GetStore($store) {
  $certlist = Get-ChildItem ("Cert:\LocalMachine\" + $store)

  foreach ($cert in $certlist) {
    $EKU = ""
    foreach ($item in $cert.EnhancedKeyUsageList) {
      if ($item.FriendlyName) {
        $EKU += $item.FriendlyName + " / "
      } else {
        $EKU += $item.ObjectId + " / "
      }
    }

    $row = $tbcert.NewRow()

    foreach ($ext in $cert.Extensions) {
      if ($ext.oid.value -eq "2.5.29.14") {
        $row.SubjectKeyIdentifier = $ext.SubjectKeyIdentifier.ToLower()
      } elseif (($ext.oid.value -eq "2.5.29.35") -or ($ext.oid.value -eq "2.5.29.1")) { 
        $asn = New-Object Security.Cryptography.AsnEncodedData ($ext.oid,$ext.RawData)
        $aki = $asn.Format($true).ToString().Replace(" ","")
        $aki = (($aki -split '\n')[0]).Replace("KeyID=","").Trim()
        $row.AuthorityKeyIdentifier = $aki
      } elseif (($ext.oid.value -eq "1.3.6.1.4.1.311.21.7") -or ($ext.oid.value -eq "1.3.6.1.4.1.311.20.2")) { 
        $asn = New-Object Security.Cryptography.AsnEncodedData ($ext.oid,$ext.RawData)
        $tmpl = $asn.Format($true).ToString().Replace(" ","")
        $template = (($tmpl -split '\n')[0]).Replace("Template=","").Trim()
        $row.Template = $template
      }
    }
    if ($EKU) {$EKU = $eku.Substring(0, $eku.Length-3)} 
    $row.Store = $store
    $row.Thumbprint = $cert.Thumbprint.ToLower()
    $row.Subject = $cert.Subject
    $row.Issuer = $cert.Issuer
    $row.NotAfter = $cert.NotAfter
    $row.EnhancedKeyUsage = $EKU
    $row.SerialNumber = $cert.SerialNumber.ToLower()
    $tbcert.Rows.Add($row)
  } 
}

Function ChkCert($cert, $store, $descr) {
  $cert = $cert.ToLower()
  if ($cert) {
    if ("0123456789abcdef".Contains($cert[0])) {
      $aCert = $tbCert.Select("Thumbprint = '" + $cert + "' and $store")
      if ($aCert.Count -gt 0) {
        Write-Diag ("[INFO] The $descr certificate was found, the subject is " + $aCert[0].Subject)
        if (($aCert[0].NotAfter) -gt (Get-Date)) {
          Write-Diag ("[INFO] The $descr certificate will expire on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
        } else {
          Write-Diag ("[ERROR] The $descr certificate expired on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
        }
      }  else {
        Write-Diag "[ERROR] The certificate with thumbprint $cert was not found in $store"
      }
    } else {
      Write-Diag "[ERROR] Invalid character in the $cert certificate thumbprint $cert"
    }
  } else {
    Write-Diag "[ERROR] The thumbprint of $descr certificate is empty"
  }
}

Function GetSubVal {
  param( [string]$SubName, [string]$SubValue)
  $SubProp = (Get-Item -Path ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions\" + $SubName) | Get-ItemProperty)
  if ($SubProp.($SubValue)) {
    return $SubProp.($SubValue)
  } else {
    $cm = $SubProp.ConfigurationMode
    $subVal = (Get-Item -Path ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\ConfigurationModes\" + $cm) | Get-ItemProperty)
    return $SubVal.($SubValue)
  }
}

Function GetOwnerCim{
  param( $prc )
  $ret = Invoke-CimMethod -InputObject $prc -MethodName GetOwner
  return ($ret.Domain + "\" + $ret.User)
}

Function GetOwnerWmi{
  param( $prc )
  $ret = $prc.GetOwner()
  return ($ret.Domain + "\" + $ret.User)
}

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

$global:Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path
$resName = "WinRM-Results-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
if ($DataPath) {
  if (-not (Test-Path $DataPath)) {
    Write-Host "The folder $DataPath does not exist"
    exit
  }
  $global:resDir = $DataPath + "\" + $resName
} else {

  $global:resDir = $global:Root + "\" + $resName
} if ($DataPath) {
  if (-not (Test-Path $DataPath)) {
    Write-Host "The folder $DataPath does not exist"
    exit
  }
  $global:resDir = $DataPath + "\" + $resName
} else {

  $global:resDir = $global:Root + "\" + $resName
}

$diagfile = $global:resDir + "\WinRM-Diag.txt"
$global:outfile = $global:resDir + "\script-output.txt"
$global:errfile = $global:resDir + "\script-errors.txt"

Import-Module ($global:Root + "\Collect-Commons.psm1") -Force -DisableNameChecking

if (-not $Trace -and -not $Logs) {
  Write-Host "WinRM-Collect: a data collection tools for WinRM troubleshooting"
  Write-Host ""
  Write-Host "Usage:"
  Write-Host "WinRM-Collect -Logs"
  Write-Host "  Collects dumps, logs, registry keys, command outputs"
  Write-Host ""
  Write-Host "WinRM-Collect -Trace [[-Activity][-Fwd][-RemShell][-HTTP][-CAPI][-Kerberos][-CredSSP][-NTLM][-Schannel]] [-FwdCli][-EventLog][-Network][-Kernel][-PerfMon]"
  Write-Host "  Collects live trace"
  Write-Host ""
  Write-Host "WinRM-Collect -Logs -Trace [[-Activity][-Fwd][-RemShell][-HTTP][-CAPI][-Kerberos][-CredSSP][-NTLM][-Schannel]] [-FwdCli][-EventLog][-Network][-Kernel][-PerfMon]"
  Write-Host "  Collects live trace then -Logs data"
  Write-Host ""
  Write-Host "Parameters for -Trace :"
  Write-Host "  -Activity : Only trace WinRM basic log, less detailed and less noisy)"
  Write-Host "    -Fwd : Event Log Forwarding (enabled by default without -Activity)"
  Write-Host "    -RemShell : Remote Shell (enabled by default without -Activity)"
  Write-Host "    -HTTPSYS : HTTP.SYS tracing"
  Write-Host "     o If specified advanced HTTP.SYS tracing is enabled"
  Write-Host "     o If not specified basic HTTP.SYS tracing is enabled"
  Write-Host "     o With -Activity no HTTPS.SYS tracing, unless specified"
  Write-Host "    -WinHTTP : WinHTTP (enabled by default without -Activity)"
  Write-Host "    -CAPI : CAPI (enabled by default without -Activity)"
  Write-Host "    -Kerberos : Kerberos (enabled by default without -Activity)"
  Write-Host "    -CredSSP : CredSSP (enabled by default without -Activity)"
  Write-Host "    -NTLM : NTLM (enabled by default without -Activity)"
  Write-Host "    -Schannel : Schannel (enabled by default without -Activity)"
  Write-Host "    -WMI : WMI activity"
  Write-Host ""
  Write-Host "  -FwdCli : Additional client side treacing for EventLog forwarding"
  Write-Host "  -EventLog : Event Log tracing (included in -FwdCli)"
  Write-Host "  -Network : Network capture"
  Write-Host "  -Kernel : Kernel Trace for process start and stop"
  Write-Host "  -PerfMon : Performance counters"
  Write-Host ""
  exit
}
$RdrOut =  " >>""" + $global:outfile + """"
$RdrErr =  " 2>>""" + $global:errfile + """"
$fqdn = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName

$OSVer = ([environment]::OSVersion.Version.Major) + ([environment]::OSVersion.Version.Minor) /10

New-Item -itemtype directory -path $global:resDir | Out-Null

Write-Log $version
if ($AcceptEula) {
  Write-Log "AcceptEula switch specified, silently continuing"
  $eulaAccepted = ShowEULAIfNeeded "WinRM-Collect" 2
} else {
  $eulaAccepted = ShowEULAIfNeeded "WinRM-Collect" 0
  if($eulaAccepted -ne "Yes")
   {
     Write-Log "EULA declined, exiting"
     exit
   }
 }
Write-Log "EULA accepted, continuing"

if ($Trace) {
  $TracesDir = $global:resDir + "\Traces\"
  New-Item -itemtype directory -path $TracesDir | Out-Null
  WinRMTraceCapture
  if (-not $Logs) {
    exit
  }
}

"Logman create counter FwdEvtPerf -o """ + $global:resDir + "\FwdEvtPerf.blg"" -f bin -v mmddhhmm -c ""\Process(*)\*"" ""\Processor(*)\*"" ""\PhysicalDisk(*)\*"" ""\Event Tracing for Windows Session(EventLog-*)\Events Lost"" ""\Event Tracing for Windows Session(EventLog-*)\Events Logged per sec"" ""\HTTP Service Request Queues(*)\*"" -si 00:00:01" | Out-File -FilePath ($global:resDir + "\WEF-Perf.bat") -Append -Encoding ascii
"Logman start FwdEvtPerf" | Out-File -FilePath ($global:resDir + "\WEF-Perf.bat") -Append -Encoding ascii
"timeout 60" | Out-File -FilePath ($global:resDir + "\WEF-Perf.bat") -Append -Encoding ascii
"Logman stop FwdEvtPerf" | Out-File -FilePath ($global:resDir + "\WEF-Perf.bat") -Append -Encoding ascii
"Logman delete FwdEvtPerf" | Out-File -FilePath ($global:resDir + "\WEF-Perf.bat") -Append -Encoding ascii

$cmd = $global:resDir + "\WEF-Perf.bat"
Write-Log $cmd
Start-Process $cmd -WindowStyle Minimized

Write-Log "Retrieving WinRM configuration"
$config = Get-ChildItem WSMan:\localhost\ -Recurse -ErrorAction Continue 2>>$global:errfile
if (!$config) {
  Write-Log ("Cannot connect to localhost, trying with FQDN " + $fqdn)
  Connect-WSMan -ComputerName $fqdn -ErrorAction Continue 2>>$global:errfile
  $config = Get-ChildItem WSMan:\$fqdn -Recurse -ErrorAction Continue 2>>$global:errfile
  GetPlugins -WinRMPluginPath (WSMan:\$fqdn\Plugin)
  Disconnect-WSMan -ComputerName $fqdn -ErrorAction Continue 2>>$global:errfile
} else {
  GetPlugins
}

$config | out-string -Width 500 | out-file -FilePath ($global:resDir + "\WinRM-config.txt")

Write-Log "winrm get winrm/config"
$cmd = "winrm get winrm/config >>""" + $global:resDir + "\WinRM-config.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "winrm e winrm/config/listener"
$cmd = "winrm e winrm/config/listener >>""" + $global:resDir + "\WinRM-config.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "winrm enum winrm/config/service/certmapping"
$cmd = "winrm enum winrm/config/service/certmapping >>""" + $global:resDir + "\WinRM-config.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Collecting dump of the svchost process hosting the WinRM service"
$pidWinRM = FindServicePid "WinRM"
if ($pidWinRM) {
  CreateProcDump $pidWinRM $global:resDir "svchost-WinRM"
}

Write-Log "Collecing the dumps of wsmprovhost.exe processes"
$list = get-process -Name "wsmprovhost" -ErrorAction SilentlyContinue 2>>$global:errfile
if (($list | Measure-Object).count -gt 0) {
  foreach ($proc in $list)
  {
    Write-Log ("Found wsmprovhost.exe with PID " + $proc.Id)
    CreateProcDump $proc.id $global:resDir
  }
} else {
  Write-Log "No wsmprovhost.exe processes found"
}

if ($pidWinRM) {
  Write-Log ("The PID of the WinRM service is: " + $pidWinRM)
  $pidWEC = FindServicePid "WecSvc"
  if ($pidWEC) {
    Write-Log ("The PID of the WecSvc service is: " + $pidWEC)
    if ($pidWinRM -ne $pidWEC) {
      Write-Log "WinRM and WecSvc are not in the same process"
      CreateProcDump $pidWEC $global:resDir "scvhost-WEC"
    }
  }
}

Write-Log "Collecting dump of the SME.exe process"
$proc = get-process "SME" -ErrorAction SilentlyContinue
if ($proc) {
  Write-Log "Process SME.EXE found with PID $proc.id"
  CreateProcDump $proc.id $global:resDir
}

FileVersion -Filepath ($env:windir + "\system32\wsmsvc.dll") -Log $true
FileVersion -Filepath ($env:windir + "\system32\pwrshplugin.dll") -Log $true

if (Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions) {
  Write-Log "Retrieving subscriptions configuration"
  $cmd = "wecutil es 2>>""" + $global:errfile + """"
  Write-log $cmd
  $subList = Invoke-Expression $cmd

  if ($subList -gt "") {
    foreach($sub in $subList) {
      Write-Log "Subscription: " + $sub
      ("Subscription: " + $sub) | out-file -FilePath ($global:resDir + "\Subscriptions.txt") -Append
      "-----------------------" | out-file -FilePath ($global:resDir + "\Subscriptions.txt") -Append
      $cmd = "wecutil gs """ + $sub + """ /f:xml" + $RdrErr
      Write-Log $cmd
      Invoke-Expression ($cmd) | out-file -FilePath ($global:resDir + "\Subscriptions.txt") -Append

      $cmd = "wecutil gr """ + $sub + """" + $RdrErr
      Write-Log $cmd
      Invoke-Expression ($cmd) | out-file -FilePath ($global:resDir + "\Subscriptions.txt") -Append

      " " | out-file -FilePath ($global:resDir + "\Subscriptions.txt") -Append
    }
  }
}

Write-Log "Listing members of Event Log Readers group"
$cmd = "net localgroup ""Event Log Readers"" >>""" + $global:resDir + "\Groups.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

if ($OSVer -le 6.3) {
  Write-Log "Listing members of WinRMRemoteWMIUsers__ group"
  $cmd = "net localgroup ""WinRMRemoteWMIUsers__"" >>""" + $global:resDir + "\Groups.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append
} else {
  Write-Log "Listing members of Remote Management Users group"
  $cmd = "net localgroup ""Remote Management Users"" >>""" + $global:resDir + "\Groups.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append
}

Write-Log "Listing members of Windows Admin Center CredSSP Administrators group"
$cmd = "net localgroup ""Windows Admin Center CredSSP Administrators"" >>""" + $global:resDir + "\Groups.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

(" ") | Out-File -FilePath ($global:resDir + "\Groups.txt") -Append
($group + " = " + $strSID) | Out-File -FilePath ($global:resDir + "\Groups.txt") -Append

Write-Log "Getting the output of WHOAMI /all"
$cmd = "WHOAMI /all >>""" + $global:resDir + "\WHOAMI.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Get-Culture output"
"Get-Culture" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-Culture | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Exporting registry key HKEY_USERS\S-1-5-20\Control Panel\International"
$cmd = "reg export ""HKEY_USERS\S-1-5-20\Control Panel\International"" """ + $global:resDir + "\InternationalNetworkService.reg.txt"" /y " + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Get-WinSystemLocale output"
"Get-WinSystemLocale" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-WinSystemLocale | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Get-WinHomeLocation output"
"Get-WinHomeLocation" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-WinHomeLocation | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Get-WinUILanguageOverride output"
"Get-WinUILanguageOverride" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-WinUILanguageOverride | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Get-WinUserLanguageList output"
"Get-WinUserLanguageList" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-WinUserLanguageList | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Get-WinAcceptLanguageFromLanguageListOptOut output"
"Get-WinAcceptLanguageFromLanguageListOptOut" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-WinAcceptLanguageFromLanguageListOptOut | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Get-WinCultureFromLanguageListOptOut output"
"Get-Get-WinCultureFromLanguageListOptOut" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-WinCultureFromLanguageListOptOut | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Get-WinDefaultInputMethodOverride output"
"Get-WinDefaultInputMethodOverride" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-WinDefaultInputMethodOverride | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Get-WinLanguageBarOption output"
"Get-WinLanguageBarOption" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-WinLanguageBarOption | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Get-NetConnectionProfile output"
Get-NetConnectionProfile | Out-File -FilePath ($global:resDir + "\NetConnectionProfile.txt") -Append

Write-Log "Get-WSManCredSSP output"
Get-WSManCredSSP | Out-File -FilePath ($global:resDir + "\WSManCredSSP.txt") -Append

Write-Log "Exporting firewall rules"
$cmd = "netsh advfirewall firewall show rule name=all >""" + $global:resDir + "\FirewallRules.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Invoke-CustomCommand -Command "netstat -anob" -DestinationFile "netstat.txt"
Invoke-CustomCommand -Command "ipconfig /all" -DestinationFile "ipconfig.txt"
Invoke-CustomCommand -Command "auditpol /get /category:*" -DestinationFile "auditpol.txt"

Write-Log "Copying hosts and lmhosts"
if (Test-path -path C:\Windows\system32\drivers\etc\hosts) {
  Copy-Item C:\Windows\system32\drivers\etc\hosts $global:resDir\hosts.txt -ErrorAction Continue 2>>$global:errfile
}
if (Test-Path -Path C:\Windows\system32\drivers\etc\lmhosts) {
  Copy-Item C:\Windows\system32\drivers\etc\lmhosts $global:resDir\lmhosts.txt -ErrorAction Continue 2>>$global:errfile
}

$dir = $env:windir + "\system32\logfiles\HTTPERR"
if (Test-Path -path $dir) {
  $last = Get-ChildItem -path ($dir) | Sort-Object CreationTime -Descending | Select-Object Name -First 1 
  Copy-Item ($dir + "\" + $last.name) $global:resDir\httperr.log -ErrorAction Continue 2>>$global:errfile
}

Write-Log "WinHTTP proxy configuration"
$cmd = "netsh winhttp show proxy >""" + $global:resDir + "\WinHTTP-Proxy.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "NSLookup WPAD"
"------------------" | Out-File -FilePath ($global:resDir + "\WinHTTP-Proxy.txt") -Append
"NSLookup WPAD" | Out-File -FilePath ($global:resDir + "\WinHTTP-Proxy.txt") -Append
"" | Out-File -FilePath ($global:resDir + "\WinHTTP-Proxy.txt") -Append
$cmd = "nslookup wpad >>""" + $global:resDir + "\WinHTTP-Proxy.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM"
$cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM """ + $global:resDir + "\WinRM.reg.txt"" /y " + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN """+ $global:resDir + "\WSMAN.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

if (Test-Path HKLM:\Software\Policies\Microsoft\Windows\WinRM) {
  Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM"
  $cmd = "reg export HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM """+ $global:resDir + "\WinRM-Policies.reg.txt"" /y" + $RdrOut + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd
} else {
  Write-Log "The registry key HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM is not present"
}

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System """+ $global:resDir + "\System-Policies.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector """+ $global:resDir + "\EventCollector.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventForwarding"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EventForwarding """+ $global:resDir + "\EventForwarding.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog """+ $global:resDir + "\EventLog-Policies.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
$cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL """+ $global:resDir + "\SCHANNEL.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography"
$cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography """+ $global:resDir + "\Cryptography.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography """+ $global:resDir + "\Cryptography-Policy.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
$cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa """+ $global:resDir + "\LSA.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP"
$cmd = "reg export HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP """+ $global:resDir + "\HTTP.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials) {
  Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials"
  $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials """+ $global:resDir + "\AllowFreshCredentials.reg.txt"" /y" + $RdrOut + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd
} else {
  Write-Log "The registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials is not present"
}

Export-EventLog "System"
Export-EventLog "Application"
Export-EventLog "Microsoft-Windows-CAPI2/Operational"
Export-EventLog "Microsoft-Windows-WinRM/Operational"
Export-EventLog "Microsoft-Windows-EventCollector/Operational"
Export-EventLog "Microsoft-Windows-Forwarding/Operational"
Export-EventLog "Microsoft-Windows-PowerShell/Operational"
Export-EventLog "Windows PowerShell"
Export-EventLog "PowerShellCore/Operational"
Export-EventLog "Microsoft-Windows-GroupPolicy/Operational"
Export-EventLog "Microsoft-Windows-Kernel-EventTracing/Admin"
Export-EventLog "Microsoft-ServerManagementExperience"
Export-EventLog "Microsoft-Windows-ServerManager-ConfigureSMRemoting/Operational"
Export-EventLog "Microsoft-Windows-ServerManager-DeploymentProvider/Operational"
Export-EventLog "Microsoft-Windows-ServerManager-MgmtProvider/Operational"
Export-EventLog "Microsoft-Windows-ServerManager-MultiMachine/Operational"
Export-EventLog "Microsoft-Windows-FileServices-ServerManager-EventProvider/Operational"

EvtLogDetails "Application"
EvtLogDetails "System"
EvtLogDetails "Security"
EvtLogDetails "ForwardedEvents"

Write-Log "Autologgers configuration"
Get-AutologgerConfig -Name EventLog-ForwardedEvents -ErrorAction SilentlyContinue | Out-File -FilePath ($global:resDir + "\AutoLoggersConfiguration.txt") -Append
Get-AutologgerConfig -Name EventLog-System -ErrorAction SilentlyContinue | Out-File -FilePath ($global:resDir + "\AutoLoggersConfiguration.txt") -Append
Get-AutologgerConfig -Name EventLog-Security -ErrorAction SilentlyContinue | Out-File -FilePath ($global:resDir + "\AutoLoggersConfiguration.txt") -Append
Get-AutologgerConfig -Name EventLog-Application -ErrorAction SilentlyContinue | Out-File -FilePath ($global:resDir + "\AutoLoggersConfiguration.txt") -Append

if ($OSVer -gt 6.1 ) {
  Write-Log "Copying ServerManager configuration"
  copy-item $env:APPDATA\Microsoft\Windows\ServerManager\ServerList.xml $global:resDir\ServerList.xml -ErrorAction Continue 2>>$global:errfile
  
  Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache"
  $cmd = "reg export ""HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache"" """ + $global:resDir + "\ServerComponentCache.reg.txt"" /y " + $RdrOut + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd
}

Write-Log "Get-Module output"
Get-Module -ListAvailable | Out-File -FilePath ($global:resDir + "\Get-Module.txt")

Write-Log "Exporting netsh http settings"
$cmd = "netsh http show sslcert >>""" + $global:resDir + "\netsh-http.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

$cmd = "netsh http show urlacl >>""" + $global:resDir + "\netsh-http.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

$cmd = "netsh http show servicestate >>""" + $global:resDir + "\netsh-http.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

$cmd = "netsh http show iplisten >>""" + $global:resDir + "\netsh-http.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

if (Test-Path HKLM:\SOFTWARE\Microsoft\InetStp) {
  Write-Log "Exporting IIS configuration"
  $cmd = $env:SystemRoot + "\system32\inetsrv\APPCMD list app >>""" + $global:resDir + "\iisconfig.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd

  $cmd = $env:SystemRoot + "\system32\inetsrv\APPCMD list apppool >>""" + $global:resDir + "\iisconfig.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd

  $cmd = $env:SystemRoot + "\system32\inetsrv\APPCMD list site >>""" + $global:resDir + "\iisconfig.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd

  $cmd = $env:SystemRoot + "\system32\inetsrv\APPCMD list module >>""" + $global:resDir + "\iisconfig.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd

  $cmd = $env:SystemRoot + "\system32\inetsrv\APPCMD list wp >>""" + $global:resDir + "\iisconfig.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd

  $cmd = $env:SystemRoot + "\system32\inetsrv\APPCMD list vdir >>""" + $global:resDir + "\iisconfig.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd

  $cmd = $env:SystemRoot + "\system32\inetsrv\APPCMD list config >>""" + $global:resDir + "\iisconfig.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd
} else { 
  Write-Log "IIS is not installed"
}

if (Test-Path -Path ($env:windir + "\System32\inetsrv\Config\ApplicationHost.config")) {
  Write-Log "IIS ApplicationHost.config"
  Copy-Item "C:\Windows\System32\inetsrv\Config\ApplicationHost.config" ($global:resDir + "\ApplicationHost.config")
}

$cmd = "setspn -L " + $env:computername + " >>""" + $global:resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($global:resDir + "\SPN.txt") -Append

"Searching HTTP/" + $env:computername + " in the domain" | Out-File ($global:resDir + "\SPN.txt") -Append
$cmd = "setspn -Q HTTP/" + $env:computername + " >>""" + $global:resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($global:resDir + "\SPN.txt") -Append

"Searching HTTP/" + $fqdn + " in the domain" | Out-File ($global:resDir + "\SPN.txt") -Append
$cmd = "setspn -Q HTTP/" + $fqdn + " >>""" + $global:resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($global:resDir + "\SPN.txt") -Append

"Searching HTTP/" + $env:computername + " in the forest" | Out-File ($global:resDir + "\SPN.txt") -Append
$cmd = "setspn -F -Q HTTP/" + $env:computername + " >>""" + $global:resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($global:resDir + "\SPN.txt") -Append

"Searching HTTP/" + $fqdn + " in the forest" | Out-File ($global:resDir + "\SPN.txt") -Append
$cmd = "setspn -F -Q HTTP/" + $fqdn + " >>""" + $global:resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($global:resDir + "\SPN.txt") -Append

"Searching WSMAN/" + $env:computername + " in the domain" | Out-File ($global:resDir + "\SPN.txt") -Append
$cmd = "setspn -Q WSMAN/" + $env:computername + " >>""" + $global:resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($global:resDir + "\SPN.txt") -Append

"Searching WSMAN/" + $fqdn + " in the domain" | Out-File ($global:resDir + "\SPN.txt") -Append
$cmd = "setspn -Q WSMAN/" + $fqdn + " >>""" + $global:resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($global:resDir + "\SPN.txt") -Append

"Searching WSMAN/" + $env:computername + " in the forest" | Out-File ($global:resDir + "\SPN.txt") -Append
$cmd = "setspn -F -Q WSMAN/" + $env:computername + " >>""" + $global:resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($global:resDir + "\SPN.txt") -Append

"Searching WSMAN/" + $fqdn + " in the forest" | Out-File ($global:resDir + "\SPN.txt") -Append
$cmd = "setspn -F -Q WSMAN/" + $fqdn + " >>""" + $global:resDir + "\SPN.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd
" " | Out-File ($global:resDir + "\SPN.txt") -Append

Write-Log "Collecting certificates details"
$cmd = "Certutil -verifystore -v MY > """ + $global:resDir + "\Certificates-My.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

$cmd = "Certutil -verifystore -v ROOT > """ + $global:resDir + "\Certificates-Root.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

$cmd = "Certutil -verifystore -v CA > """ + $global:resDir + "\Certificates-Intermediate.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

$tbCert = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Store,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn Thumbprint,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn Subject,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn Issuer,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn NotAfter,([DateTime]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn IssuerThumbprint,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn EnhancedKeyUsage,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn SerialNumber,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn SubjectKeyIdentifier,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn AuthorityKeyIdentifier,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn Template,([string]); $tbCert.Columns.Add($col)

GetStore "My"
GetStore "CA"
GetStore "Root"

Write-Log "Matching issuer thumbprints"
$aCert = $tbCert.Select("Store = 'My' or Store = 'CA'")
foreach ($cert in $aCert) {
  $aIssuer = $tbCert.Select("SubjectKeyIdentifier = '" + ($cert.AuthorityKeyIdentifier).tostring() + "'")
  if ($aIssuer.Count -gt 0) {
    $cert.IssuerThumbprint = ($aIssuer[0].Thumbprint).ToString()
  }
}
$tbcert | Export-Csv ($global:resDir + "\certificates.tsv") -noType -Delimiter "`t"

Write-Log "PowerShell version"
$PSVersionTable | Out-File -FilePath ($global:resDir + "\PSVersion.txt") -Append

Write-Log "Collecting details about running processes"
if (ListProcsAndSvcs) {
  CollectSystemInfoWMI
  ExecQuery -Namespace "root\cimv2" -Query "select * from Win32_Product" | Sort-Object Name | Format-Table -AutoSize -Property Name, Version, Vendor, InstallDate | Out-String -Width 400 | Out-File -FilePath ($global:resDir + "\products.txt")

  Write-Log "Collecting the list of installed hotfixes"
  Get-HotFix -ErrorAction SilentlyContinue 2>>$global:errfile | Sort-Object -Property InstalledOn -ErrorAction Ignore | Out-File $global:resDir\hotfixes.txt

  Write-Log "Collecing GPResult output"
  $cmd = "gpresult /h """ + $global:resDir + "\gpresult.html""" + $RdrErr
  write-log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

  $cmd = "gpresult /r >""" + $global:resDir + "\gpresult.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append
} else {
  Write-Log "WMI is not working"
  $proc = Get-Process | Where-Object {$_.Name -ne "Idle"}
  $proc | Format-Table -AutoSize -property id, name, @{N="WorkingSet";E={"{0:N0}" -f ($_.workingset/1kb)};a="right"},
  @{N="VM Size";E={"{0:N0}" -f ($_.VirtualMemorySize/1kb)};a="right"},
  @{N="Proc time";E={($_.TotalProcessorTime.ToString().substring(0,8))}}, @{N="Threads";E={$_.threads.count}},
  @{N="Handles";E={($_.HandleCount)}}, StartTime, Path | 
  Out-String -Width 300 | Out-File -FilePath ($global:resDir + "\processes.txt")
  CollectSystemInfoNoWMI
}

Write-Diag ("[INFO] " + $DiagVersion)

# Diag start

function New-UrlAcl {
    New-Object psobject -Property @{
        Protocol = ''
        Host = ''
        Port = 0
        Path = ''
        Url = ''
        Users = @()
    }
}

function New-UrlAclUser {
    New-Object psobject -Property @{
        Name = ''
        Listen = $false
        Delegate = $false
        SSDL = ''
    }
}

function Get-UrlAcl {  # Taken from https://www.powershellgallery.com/packages/HttpSys/1.0.1/Content/Get-UrlAcl.ps1 and modified to also run on PowerShell 4
    [CmdletBinding()]
    param(
        [parameter(Position=0)]
        [string]$Url,
        [parameter()]
        [int[]]$Port,
        [string]$HostName,
        [string]$Protocol
    )

    $cmd = "netsh http show urlacl"
    if (-not [string]::IsNullOrWhiteSpace($Url)){
        $cmd += " url=$Url"
    }

    $result = Invoke-Expression $cmd

    $result = $result | Select-Object -Skip 4

    $items = @()
    $item = New-UrlAcl
    $user = New-UrlAclUser
    for ($i = 0; $i -lt $result.Length; $i++){
        $line = $result[$i]
        if ([string]::IsNullOrWhiteSpace($line)){
            continue;
        }
        $splitIndex = $line.IndexOf(": ");
        $key = $line.Substring(0,$splitIndex).Trim();
        $value = $line.Substring($splitIndex + 2);
        
        if ($key -eq "Reserved Url"){
            $item = New-UrlAcl
            $protocolSplitIndex = $value.IndexOf("://");
            $item.Protocol = $value.Substring(0, $protocolSplitIndex)
            $remainder = $value.Substring($protocolSplitIndex + 3)

            $pathSplitIndex = $remainder.IndexOf("/")

            $hostDetails = $remainder.Substring(0, $pathSplitIndex)
            
            $hostParts = $hostDetails.Split(':')

            $item.Host = $hostParts[0]
            $item.Port = $hostParts[1]

            $item.Path = $remainder.Substring($pathSplitIndex)

            $item.Url = $value
            $items += $item
        }
        if ($key -eq "User"){            
            $user = New-UrlAclUser
            $user.Name = $value
            $item.Users += $user
        }
        if ($key -eq "Listen"){
            $user.Listen = if ($value -eq "Yes") { $true } else { $false }
        }
        if ($key -eq "Delegate"){
            $user.Delegate = if ($value -eq "Yes") { $true } else { $false }
        }
        if ($key -eq "SDDL"){
            $user.SSDL = $value
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($HostName)){
        $items = $items | Where-Object { $_.Host -eq $HostName }
    }
    if (-not [string]::IsNullOrWhiteSpace($Protocol)){
        $items = $items | Where-Object { $_.Protocol -eq $Protocol }
    }

    if ($null -ne $Port){
        if ($Port -isnot [System.Array]){
            $Port = @($Port)
        }
        if ($Port.Length -ge 0){
            $items = $items | Where-Object { $Port -contains $_.Port }
        }
    }

    return $items
}

Write-Diag "Retrieving URLACL information"
$urlACL = Get-UrlAcl

Write-Diag "[INFO] Checking HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\ClientAuthTrustMode"
$ClientAuthTrustMode = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel" | Select-Object -ExpandProperty "ClientAuthTrustMode" -ErrorAction SilentlyContinue)

if ($ClientAuthTrustMode -eq $null -or $ClientAuthTrustMode -eq 0) {
  Write-Diag "[WARNING]   0 Machine Trust (default) - Requires that the client certificate is issued by a certificate in the Trusted Issuers list."  
} elseif ($ClientAuthTrustMode -eq 1) {
  Write-Diag "[WARNING]   1 Exclusive Root Trust - Requires that a client certificate chains to a root certificate contained in the caller-specified trusted issuer store. The certificate must also be issued by an issuer in the Trusted Issuers list"  
} elseif ($ClientAuthTrustMode -eq 2) {
  Write-Diag "[INFO]   2 Exclusive CA Trust - Requires that a client certificate chain to either an intermediate CA certificate or root certificate in the caller-specified trusted issuer store."  
} else {
  Write-Diag ("[ERROR]   Invalid value " + $ClientAuthTrustMode)
}

$OSVer = [environment]::OSVersion.Version.Major + [environment]::OSVersion.Version.Minor * 0.1

$subDom = $false
$subWG = $false
$Subscriptions = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventCollector\Subscriptions
foreach ($sub in $Subscriptions) {
  Write-Diag ("[INFO] Found subscription " + $sub.PSChildname)
  $SubProp = ($sub | Get-ItemProperty)
  Write-Diag ("[INFO]    SubscriptionType = " + $SubProp.SubscriptionType + ", ConfigurationMode = " + $SubProp.ConfigurationMode)
  Write-Diag ("[INFO]    MaxLatencyTime = " + (GetSubVal $sub.PSChildname "MaxLatencyTime") + ", HeartBeatInterval = " + (GetSubVal $sub.PSChildname "HeartBeatInterval"))
  
  $logFile = (GetSubVal $sub.PSChildname "LogFile")
  if ($logFile -ne "ForwardedEvents") {
    Write-Diag ("[WARNING] LogFile = " + $logFile + ", this is a CUSTOM LOG")
  } else { 
    Write-Diag ("[INFO]    LogFile = " + $logFile)
  }

  if ($SubProp.AllowedSourceDomainComputers) {
    Write-Diag "[INFO]    AllowedSourceDomainComputers"
    $ACL = (FindSep -FindIn $SubProp.AllowedSourceDomainComputers -Left ":P" -Right ")S:").replace(")(", ",").Split(",")
    foreach ($ACE in $ACL) {
      $SID = FindSep -FindIn $ACE -left ";;;"
      $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
      $group = $objSID.Translate( [System.Security.Principal.NTAccount]).Value
      Write-Diag "[INFO]       $group ($SID)"
    }
  }

  if ($SubProp.Locale) {
    if ($SubProp.Locale -eq "en-US") {
      Write-Diag "[INFO]    The subscription's locale is set to en-US"
    } else {
      Write-Diag ("[WARNING] The subscription's locale is set to " + $SubProp.Locale)
    }
  } else {
   Write-Diag "[INFO]    The subscription's locale is not set, the default locale will be used."    
  }

  if ($SubProp.AllowedSubjects) {
    $subWG = $true
    Write-Diag "[INFO]    Listed non-domain computers:"
    $list = $SubProp.AllowedSubjects -split ","
    foreach ($item in $list) {
      Write-Diag ("[INFO]    " + $item)
    }
  } else {
    Write-Diag "[INFO]    No non-domain computers listed, that's ok if this is not a collector in workgroup environment"
  }

  if ($SubProp.AllowedIssuerCAs) {
    $subWG = $true
    Write-Diag "[INFO]    Listed Issuer CAs:"
    $list = $SubProp.AllowedIssuerCAs -split ","
    foreach ($item in $list) {
      Write-Diag ("[INFO]    " + $item)
      ChkCert -cert $item -store "(Store = 'CA' or Store = 'Root')" -descr "Issuer CA"
    }
  } else {
    Write-Diag "[INFO]   No Issuer CAs listed, that's ok if this is not a collector in workgroup environment"
  }

  $RegKey = (($sub.Name).replace("HKEY_LOCAL_MACHINE\","HKLM:\") + "\EventSources")
  if (Test-Path -Path $RegKey) {
    $sources = Get-ChildItem -Path $RegKey
    if ($sources.Count -gt 4000) {
      Write-Diag ("[WARNING] There are " + $sources.Count + " sources for this subscription")
    } else {
      Write-Diag ("[INFO]   There are " + $sources.Count + " sources for this subscription")
    }
  } else {
    Write-Diag ("[INFO]   No sources found for the subscription " + $sub.Name)
  }
}

if ($Subscriptions) {
 $EventLost = (Get-Counter "\\$env:computername\Event Tracing for Windows Session(EventLog-ForwardedEvents)\Events Lost").CounterSamples[0].CookedValue
  if ($EventLost -gt 100) {
    Write-Diag ("[WARNING] " + $EventLost + " events lost for EventLog-ForwardedEvents")
  } else {
    Write-Diag ("[INFO] " + $EventLost + " events lost for EventLog-ForwardedEvents")
  }
}


if ($OSVer -gt 6.1) {
  Write-Diag "[INFO] Retrieving machine's IP addresses"
  $iplist = Get-NetIPAddress
}

$pol = Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service  -Name HttpCompatibilityListener -ErrorAction SilentlyContinue
if ($pol) {
  if ($pol.HttpCompatibilityListener -eq 1) {
    Write-Diag ("[WARNING] HTTP Compatibility listener (port 80) is enabled")
  }
}

$pol = Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service  -Name HttpsCompatibilityListener -ErrorAction SilentlyContinue
if ($pol) {
  if ($pol.HttpsCompatibilityListener -eq 1) {
    Write-Diag ("[WARNING] HTTPS Compatibility listener (port 443) is enabled")
  }
}

Write-Diag "[INFO] Browsing listeners"
$HTTPListenerFound = $false
$listeners = Get-ChildItem WSMan:\localhost\Listener
foreach ($listener in $listeners) {
  Write-Diag ("[INFO] Inspecting listener " + $listener.Name)
  $prop = Get-ChildItem $listener.PSPath
  if ($listener.keys[0] -eq "Transport=HTTP") {
    $HTTPListenerFound = $true
  }
  foreach ($value in $prop) {
    if ($value.Name -eq "CertificateThumbprint") {
      if ($listener.keys[0].Contains("HTTPS")) {
        $HTTPSListenerFound = $true
        Write-Diag "[INFO] Found HTTPS listener"
        $listenerThumbprint = $value.Value.ToLower()
        Write-Diag "[INFO] Found listener certificate $listenerThumbprint"
        if ($listenerThumbprint) {
          ChkCert -cert $listenerThumbprint -descr "listener" -store "Store = 'My'"
        }
      }
    }
    if ($value.Name.Contains("ListeningOn")) {
      $ip = ($value.value).ToString()
      Write-Diag "[INFO] Listening on $ip"
      if ($OSVer -gt 6.1) {
        if (($iplist | Where-Object {$_.IPAddress -eq $ip } | measure-object).Count -eq 0 ) {
          Write-Diag "[ERROR] IP address $ip not found"
        }
      }
    }
  } 
} 

if ($HTTPListenerFound) {
  Write-Diag ("[INFO] HTTP listener found")
  $HTTPURLACL = ($urlACL | Where-Object Port -eq 5985)
  if ($HTTPURLACL) {
    Write-Diag "[INFO] URLACL for port 5985 is present"
    if ($HTTPURLACL.Protocol -ne "http") {
      Write-Diag ("[ERROR] The protocol for port 5985 is not HTTP (" + $HTTPURLACL.Protocol + ")")
    }
    if ($HTTPURLACL.Users | Where-Object Name -eq "NT SERVICE\WinRM") {
      Write-Diag ("[INFO] NT SERVICE\WinRM has permissions on port 5985")
    } else {
      Write-Diag ("[ERROR] NT SERVICE\WinRM is missing permissions on port 5985")
    }
    if ($HTTPURLACL.Users | Where-Object Name -eq "NT SERVICE\Wecsvc") {
      Write-Diag ("[INFO] NT SERVICE\Wecsvc has permissions on port 5985")
    } else {
      Write-Diag ("[ERROR] NT SERVICE\Wecsvc is missing permissions on port 5985")
    }
  } else {
    Write-Diag "[ERROR] HTTP Listener found but URLACL for port 5985 is missing"
  }
} else {
  Write-Diag ("[ERROR] The HTTP listener is missing")
}

if ($HTTPSListenerFound) {
  Write-Diag ("[INFO] HTTP listener found")
  $HTTPSURLACL = ($urlACL | Where-Object Port -eq 5986)
  if ($HTTPSURLACL) {
    Write-Diag "[INFO] URLACL for port 5986 is present"
    if ($HTTPSURLACL.Protocol -ne "https") {
      Write-Diag ("[ERROR] The protocol for port 5986 is not HTTPS (" + $HTTPSURLACL.Protocol + ")")
    }
    if ($HTTPSURLACL.Users | Where-Object Name -eq "NT SERVICE\WinRM") {
      Write-Diag ("[INFO] NT SERVICE\WinRM has permissions on port 5986")
    } else {
      Write-Diag ("[ERROR] NT SERVICE\WinRM is missing permissions on port 5986")
    }
    if ($HTTPSURLACL.Users | Where-Object Name -eq "NT SERVICE\Wecsvc") {
      Write-Diag ("[INFO] NT SERVICE\Wecsvc has permissions on port 5986")
    } else {
      Write-Diag ("[ERROR] NT SERVICE\Wecsvc is missing permissions on port 5986")
    }
  } else {
    Write-Diag "[ERROR] HTTPS Listener found but URLACL for port 5986 is missing"
  }
}

$svccert = Get-Item WSMan:\localhost\Service\CertificateThumbprint
if ($svccert.value ) {
  Write-Diag ("[INFO] The Service Certificate thumbprint is " + $svccert.value)
  ChkCert -cert $svccert.value -descr "Service" -store "Store = 'My'"
}

$remoteaccess = Get-Item WSMan:\localhost\Service\AllowRemoteAccess
if ($remoteaccess.Value -eq "true") {
  Write-Diag "[INFO] AllowRemoteAccess = true"
} elseif ($remoteaccess.Value -eq "false") {
  Write-Diag "[ERROR] AllowRemoteAccess = false, this machine will not accept remote WinRM connections"
} else {
  Write-Diag "[ERROR] AllowRemoteAccess has an invalid value"
}

$ipfilter = Get-Item WSMan:\localhost\Service\IPv4Filter
if ($ipfilter.Value) {
  if ($ipfilter.Value -eq "*") {
    Write-Diag "[INFO] IPv4Filter = *"
  } else {
    Write-Diag ("[WARNING] IPv4Filter = " + $ipfilter.Value)
  }
} else {
  Write-Diag ("[WARNING] IPv4Filter is empty, WinRM will not listen on IPv4")
}

$ipfilter = Get-Item WSMan:\localhost\Service\IPv6Filter
if ($ipfilter.Value) {
  if ($ipfilter.Value -eq "*") {
    Write-Diag "[INFO] IPv6Filter = *"
  } else {
    Write-Diag ("[WARNING] IPv6Filter = " + $ipfilter.Value)
  }
} else {
  Write-Diag ("[WARNING] IPv6Filter is empty, WinRM will not listen on IPv6")
}

if (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager") {
  $isForwarder = $True

  $MaxFwd = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding').MaxForwardingRate
  if ($MaxFwd) {
    Write-Diag ("[ERROR] HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\MaxForwardingRate is set to " + $MaxFwd + ". This functionality is broken, see Bug 33554568. Remove the setting Configure Forwarder Resource Usage from the GPO to avoid performance issues")
  }

  $RegKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager')

  Write-Diag "[INFO] Enumerating SubscriptionManager URLs at HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager"
  $RegKey.PSObject.Properties | ForEach-Object {
    If($_.Name -notlike '*PS*'){
      Write-Diag ("[INFO] " + $_.Name + " " + $_.Value)
      $IssuerCA = (FindSep -FindIn $_.Value -Left "IssuerCA=" -Right ",").ToLower()
      if (-not $IssuerCA) {
        $IssuerCA = (FindSep -FindIn $_.Value -Left "IssuerCA=" -Right "").ToLower()
      }
      if ($IssuerCA) {
        if ("0123456789abcdef".Contains($IssuerCA[0])) {
          Write-Diag ("[INFO] Found issuer CA certificate thumbprint " + $IssuerCA)
          $aCert = $tbCert.Select("Thumbprint = '" + $IssuerCA + "' and (Store = 'CA' or Store = 'Root')")
          if ($aCert.Count -eq 0) {
            Write-Diag "[ERROR] The Issuer CA certificate was not found in CA or Root stores"
          } else {
            Write-Diag ("[INFO] Issuer CA certificate found in store " + $aCert[0].Store + ", subject = " + $aCert[0].Subject)
            if (($aCert[0].NotAfter) -gt (Get-Date)) {
              Write-Diag ("[INFO] The Issuer CA certificate will expire on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
            } else {
              Write-Diag ("[ERROR] The Issuer CA certificate expired on " + $aCert[0].NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
            }
          }

          $aCliCert = $tbCert.Select("IssuerThumbprint = '" + $IssuerCA + "' and Store = 'My'")
          if ($aCliCert.Count -eq 0) {
            Write-Diag "[ERROR] Cannot find any certificate issued by this Issuer CA"
          } else {
            if ($PSVersionTable.psversion.ToString() -ge "3.0") {
              Write-Diag "[INFO] Listing available client certificates from this IssuerCA"
              $num = 0
              foreach ($cert in $aCliCert) {
                if ($cert.EnhancedKeyUsage.Contains("Client Authentication")) {
                  Write-Diag ("[INFO]   Found client certificate " + $cert.Thumbprint + " " + $cert.Subject)
                  if (($Cert.NotAfter) -gt (Get-Date)) {
                    Write-Diag ("[INFO]   The client certificate will expire on " + $cert.NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
                  } else {
                    Write-Diag ("[ERROR]   The client certificate expired on " + $cert.NotAfter.ToString("yyyyMMdd HH:mm:ss.fff") )
                  }
                  $certobj = Get-Item ("CERT:\Localmachine\My\" + $cert.Thumbprint)
                  $keypath = [io.path]::combine("$env:ProgramData\microsoft\crypto\rsa\machinekeys", $certobj.privatekey.cspkeycontainerinfo.uniquekeycontainername)
                  if ([io.file]::exists($keypath)) {
                    $acl = ((get-acl -path $keypath).Access | Where-Object {$_.IdentityReference -eq "NT AUTHORITY\NETWORK SERVICE"})
                    if ($acl) {
                      $rights = $acl.FileSystemRights.ToString()
                      if ($rights.contains("Read") -or $rights.contains("FullControl") ) {
                        Write-Diag ("[INFO]   The NETWORK SERVICE account has permissions on the private key of this certificate: " + $rights)
                      } else {
                        Write-Diag ("[ERROR]  Incorrect permissions for the NETWORK SERVICE on the private key of this certificate: " + $rights)
                      }
                    } else {
                      Write-Diag "[ERROR]  Missing permissions for the NETWORK SERVICE account on the private key of this certificate"
                    }
                  } else {
                    Write-Diag "[ERROR]  Cannot find the private key"
                  } 
                  $num++
                }
              }
              if ($num -eq 0) {
                Write-Diag "[ERROR] Cannot find any client certificate issued by this Issuer CA"
              } elseif ($num -gt 1) {
                Write-Diag "[WARNING] More than one client certificate issued by this Issuer CA, the first certificate will be used by WinRM"
              }
            }
          }
        } else {
         Write-Diag "[ERROR] Invalid character for the IssuerCA certificate in the SubscriptionManager URL"
        }
      }
    } 
  }
  $RegKey = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding')
  if ($regkey.MaxForwardingRate) {
    Write-Diag "[ERROR] MaxForwardingRate is configured, this feature does not work. Please remove this setting and see bug 33554568"
  }
} else {
  $isForwarder = $false
  Write-Diag "[INFO] No SubscriptionManager URL configured. It's ok if this machine is not supposed to forward events."
}

if ((Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain) {
  $search = New-Object DirectoryServices.DirectorySearcher([ADSI]"GC://$env:USERDNSDOMAIN") # The SPN is searched in the forest connecting to a Global catalog

  $SPNReg = ""
  $SPN = "HTTP/" + $env:COMPUTERNAME
  Write-Diag ("[INFO] Searching for the SPN $SPN")
  $search.filter = "(servicePrincipalName=$SPN)"
  $results = $search.Findall()
  if ($results.count -gt 0) {
    foreach ($result in $results) {
      Write-Diag ("[INFO] The SPN HTTP/$env:COMPUTERNAME is registered for DNS name = " + $result.properties.dnshostname + ", DN = " + $result.properties.distinguishedname + ", Category = " + $result.properties.objectcategory)
      if ($result.properties.objectcategory[0].Contains("Computer")) {
        if (-not $result.properties.dnshostname[0].Contains($env:COMPUTERNAME)) {
          Write-Diag ("[ERROR] The The SPN $SPN is registered for different DNS host name: " + $result.properties.dnshostname[0])
          $SPNReg = "OTHER"
        }
      } else {
        Write-Diag "[ERROR] The The SPN $SPN is NOT registered for a computer account"
        $SPNReg = "OTHER"
      }
    }
    if ($results.count -gt 1) {
      Write-Diag "[ERROR] The The SPN $SPN is duplicate"
    }
  } else {
    Write-Diag "[INFO] The The SPN $SPN was not found. That's ok, the SPN HOST/$env:COMPUTERNAME will be used"
  }

  $SPN = "HTTP/" + $env:COMPUTERNAME + ":5985"
  Write-Diag ("[INFO] Searching for the SPN $SPN")
  $search.filter = "(servicePrincipalName=$SPN)"
  $results = $search.Findall()
  if ($results.count -gt 0) {
    foreach ($result in $results) {
      Write-Diag ("[INFO] The SPN HTTP/$env:COMPUTERNAME is registered for DNS name = " + $result.properties.dnshostname + ", DN = " + $result.properties.distinguishedname + ", Category = " + $result.properties.objectcategory)
      if ($result.properties.objectcategory[0].Contains("Computer")) {
        if (-not $result.properties.dnshostname[0].Contains($env:COMPUTERNAME)) {
          Write-Diag ("[ERROR] The The SPN $SPN is registered for different DNS host name: " + $result.properties.dnshostname[0])
        }
      } else {
        Write-Diag "[ERROR] The The SPN $SPN is NOT registered for a computer account"
      }
    }
    if ($results.count -gt 1) {
      Write-Diag "[ERROR] The The SPN $SPN is duplicate"
    }
  } else {
    if ($SPNReg -eq "OTHER") {
      Write-Diag "[WARNING] The The SPN $SPN was not found. It is required to accept WinRM connections since the HTTP/$env:COMPUTERNAME is reqistered to another name"
    }
  }

  if ($OSVer -le 6.3) {
    Write-Diag "[INFO] Checking the WinRMRemoteWMIUsers__ group"
    $search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")  # This is a Domain local group, therefore we need to collect to a non-global catalog
    $search.filter = "(samaccountname=WinRMRemoteWMIUsers__)"
    $results = $search.Findall()
    if ($results.count -gt 0) {
      Write-Diag ("[INFO] Found " + $results.Properties.distinguishedname)
      if ($results.Properties.grouptype -eq  -2147483644) {
        Write-Diag "[INFO] WinRMRemoteWMIUsers__ is a Domain local group"
      } elseif ($results.Properties.grouptype -eq -2147483646) {
        Write-Diag "[WARNING] WinRMRemoteWMIUsers__ is a Global group"
      } elseif ($results.Properties.grouptype -eq -2147483640) {
        Write-Diag "[WARNING] WinRMRemoteWMIUsers__ is a Universal group"
      }
      if (Get-CimInstance -Query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
        Write-Diag "[INFO] The group WinRMRemoteWMIUsers__ is also present as machine local group"
      }
    } else {
      Write-Diag "[WARNING] The WinRMRemoteWMIUsers__ was not found in the domain" 
      if (Get-CimInstance -Query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
        Write-Diag "[INFO] The group WinRMRemoteWMIUsers__ is present as machine local group"
      } else {
        Write-Diag "[ERROR] The group WinRMRemoteWMIUsers__ is not even present as machine local group"
      }
    }
  }
  if ((Get-ChildItem WSMan:\localhost\Service\Auth\Kerberos).value -eq "true") {
    Write-Diag "[INFO] Kerberos authentication is enabled for the service"
  }  else {
    Write-Diag "[WARNING] Kerberos authentication is disabled for the service"
  }
} else {
  Write-Diag "[INFO] The machine is not joined to a domain"
  if (Get-CimInstance -Query "select * from Win32_Group where Name = 'WinRMRemoteWMIUsers__' and Domain = '$env:computername'") {
    Write-Diag "[INFO] The group WinRMRemoteWMIUsers__ is present as machine local group"
  } else {
    Write-Diag "[ERROR] The group WinRMRemoteWMIUsers__ is not present as machine local group"
  }
  if ((Get-ChildItem WSMan:\localhost\Service\Auth\Certificate).value -eq "false") {
    Write-Diag "[WARNING] Certificate authentication is disabled for the service"
  }  else {
    Write-Diag "[INFO] Certificate authentication is enabled for the service"
  }
}

$HHTPParam = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"
if (($HHTPParam.MaxFieldLength -gt 0) -and ($HHTPParam.MaxRequestBytes -gt 0)) {
  Write-Diag ("[INFO] HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\MaxFieldLength = " + $HHTPParam.MaxFieldLength)
  Write-Diag ("[INFO] HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\MaxRequestBytes = " + $HHTPParam.MaxRequestBytes)
} else {
  Write-Diag ("[WARNING] MaxFieldLength and/or MaxRequestBytes are not defined in HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters. This may cause the request to fail with error 400 in complex AD environemnts. See KB 820129")
}

$iplisten = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" | Select-Object -ExpandProperty "ListenOnlyList" -ErrorAction SilentlyContinue)
if ($iplisten) {
  Write-Diag ("[WARNING] The IPLISTEN list is not empty, the listed addresses are " + $iplisten)
} else {
  Write-Diag "[INFO] The IPLISTEN list is empty. That's ok: WinRM will listen on all IP addresses"
}

$binval = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name WinHttpSettings).WinHttPSettings            
$proxylength = $binval[12]            
if ($proxylength -gt 0) {
  $proxy = -join ($binval[(12+3+1)..(12+3+1+$proxylength-1)] | % {([char]$_)})            
  Write-Diag ("[WARNING] A NETSH WINHTTP proxy is configured: " + $proxy)
  $bypasslength = $binval[(12+3+1+$proxylength)]            
  if ($bypasslength -gt 0) {            
    $bypasslist = -join ($binval[(12+3+1+$proxylength+3+1)..(12+3+1+$proxylength+3+1+$bypasslength)] | % {([char]$_)})            
    Write-Diag ("[WARNING] Bypass list: " + $bypasslist)
   } else {            
    Write-Diag "[WARNING] No bypass list is configured"
  }            
  Write-Diag "[WARNING] WinRM does not work very well through proxies, make sure that the target machine is in the bypass list or remove the proxy"
} else {
  Write-Diag "[INFO] No NETSH WINHTTP proxy is configured"
}

$th = (get-item WSMan:\localhost\Client\TrustedHosts).value
if ($th) {
  Write-Diag ("[INFO] TrustedHosts contains: $th")
} else {
  Write-Diag ("[INFO] TrustedHosts is not configured, it's ok it this machine is not supposed to connect to other machines using NTLM")
}

$psver = $PSVersionTable.PSVersion.Major.ToString() + $PSVersionTable.PSVersion.Minor.ToString()
if ($psver -eq "50") {
  Write-Diag ("[WARNING] Windows Management Framework version " + $PSVersionTable.PSVersion.ToString() + " is no longer supported")
} else { 
  Write-Diag ("[INFO] Windows Management Framework version is " + $PSVersionTable.PSVersion.ToString() )
}

$clientcert = Get-ChildItem WSMan:\localhost\ClientCertificate
if ($clientcert.Count -gt 0) {
  Write-Diag "[INFO] Client certificate mappings"
  foreach ($certmap in $clientcert) {
    Write-Diag ("[INFO] Certificate mapping " + $certmap.Name)
    $prop = Get-ChildItem $certmap.PSPath
    foreach ($value in $prop) {
      Write-Diag ("[INFO]   " + $value.Name + " " + $value.Value)
      if ($value.Name -eq "Issuer") {
        ChkCert -cert $value.Value -descr "mapping" -store "(Store = 'Root' or Store = 'CA')"
      } elseif ($value.Name -eq "UserName") {
        $usr = Get-CimInstance -ClassName Win32_UserAccount | Where-Object {$_.Name -eq $value.value}
        if ($usr) {
          if ($usr.Disabled) {
            Write-Diag ("[ERROR]    The local user account " + $value.value + " is disabled")
          } else {
            Write-Diag ("[INFO]     The local user account " + $value.value + " is enabled")
          }
        } else {
          Write-Diag ("[ERROR]    The local user account " + $value.value + " does not exist")
        }
      } elseif ($value.Name -eq "Subject") {
        if ($value.Value[0] -eq '"') {
          Write-Diag "[ERROR]    The subject does not have to be included in double quotes"
        }
      }
    }
  }
} else {
  if ($subWG) {
    Write-Diag "[ERROR] No client certificate mapping configured"
  }
}

$aCert = $tbCert.Select("Store = 'Root' and Subject <> Issuer")
if ($aCert.Count -gt 0) {
  Write-Diag "[ERROR] Found for non-Root certificates in the Root store"
  foreach ($cert in $acert) {
    Write-Diag ("[ERROR]  Misplaced certificate " + $cert.Subject)
  }
}

if ($isForwarder) {
  $evtLogReaders = (Get-CimInstance -Query ("Associators of {Win32_Group.Domain='" + $env:COMPUTERNAME + "',Name='Event Log Readers'} where Role=GroupComponent") | Where {$_.Name -eq "NETWORK SERVICE"} | Measure-Object)
  if ($evtLogReaders.Count -gt 0) {
    Write-Diag "[INFO] The NETWORK SERVICE account is member of the Event Log Readers group"
  } else {
    Write-Diag "[WARNING] The NETWORK SERVICE account is NOT member of the Event Log Readers group, the events in the Security log cannot be forwarded"
  }
}

$fwrules = (Get-NetFirewallPortFilter -Protocol TCP | Where { $_.localport -eq "5986" } | Get-NetFirewallRule)
if ($fwrules.count -eq 0) {
  Write-Diag "[INFO] No firewall rule for port 5986"
} else {
  Write-Diag "[INFO] Found firewall rule for port 5986"
}

$dir = $env:windir + "\system32\logfiles\HTTPERR"
if (Test-Path -path $dir) {
  $httperrfiles = Get-ChildItem -path ($dir)
  if ($httperrfiles.Count -gt 100) {
    Write-Diag ("[WARNING] There are " + $httperrfiles.Count + " files in the folder " + $dir)
  } else {
   Write-Diag ("[INFO] There are " + $httperrfiles.Count + " files in the folder " + $dir)
  }
  $size = 0 
  foreach ($file in $httperrfiles) {
    $size += $file.Length
  }
  $size = [System.Math]::Ceiling($size / 1024 / 1024) # Convert to MB
  if ($size -gt 100) {
    Write-Diag ("[WARNING] The folder " + $dir + " is using " + $size.ToString() + " MB of disk space")
  } else {
    Write-Diag ("[INFO] The folder " + $dir + " is using " + $size.ToString() + " MB of disk space")
  }
}


# SIG # Begin signature block
# MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCVbxMnYh1FDMJX
# w+HExLVHFovsh6NCL0IpT4C5pq8jAaCCDYUwggYDMIID66ADAgECAhMzAAADTU6R
# phoosHiPAAAAAANNMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI4WhcNMjQwMzE0MTg0MzI4WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDUKPcKGVa6cboGQU03ONbUKyl4WpH6Q2Xo9cP3RhXTOa6C6THltd2RfnjlUQG+
# Mwoy93iGmGKEMF/jyO2XdiwMP427j90C/PMY/d5vY31sx+udtbif7GCJ7jJ1vLzd
# j28zV4r0FGG6yEv+tUNelTIsFmmSb0FUiJtU4r5sfCThvg8dI/F9Hh6xMZoVti+k
# bVla+hlG8bf4s00VTw4uAZhjGTFCYFRytKJ3/mteg2qnwvHDOgV7QSdV5dWdd0+x
# zcuG0qgd3oCCAjH8ZmjmowkHUe4dUmbcZfXsgWlOfc6DG7JS+DeJak1DvabamYqH
# g1AUeZ0+skpkwrKwXTFwBRltAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUId2Img2Sp05U6XI04jli2KohL+8w
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzUwMDUxNzAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# ACMET8WuzLrDwexuTUZe9v2xrW8WGUPRQVmyJ1b/BzKYBZ5aU4Qvh5LzZe9jOExD
# YUlKb/Y73lqIIfUcEO/6W3b+7t1P9m9M1xPrZv5cfnSCguooPDq4rQe/iCdNDwHT
# 6XYW6yetxTJMOo4tUDbSS0YiZr7Mab2wkjgNFa0jRFheS9daTS1oJ/z5bNlGinxq
# 2v8azSP/GcH/t8eTrHQfcax3WbPELoGHIbryrSUaOCphsnCNUqUN5FbEMlat5MuY
# 94rGMJnq1IEd6S8ngK6C8E9SWpGEO3NDa0NlAViorpGfI0NYIbdynyOB846aWAjN
# fgThIcdzdWFvAl/6ktWXLETn8u/lYQyWGmul3yz+w06puIPD9p4KPiWBkCesKDHv
# XLrT3BbLZ8dKqSOV8DtzLFAfc9qAsNiG8EoathluJBsbyFbpebadKlErFidAX8KE
# usk8htHqiSkNxydamL/tKfx3V/vDAoQE59ysv4r3pE+zdyfMairvkFNNw7cPn1kH
# Gcww9dFSY2QwAxhMzmoM0G+M+YvBnBu5wjfxNrMRilRbxM6Cj9hKFh0YTwba6M7z
# ntHHpX3d+nabjFm/TnMRROOgIXJzYbzKKaO2g1kWeyG2QtvIR147zlrbQD4X10Ab
# rRg9CpwW7xYxywezj+iNAc+QmFzR94dzJkEPUSCJPsTFMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGXMwghlvAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAANNTpGmGiiweI8AAAAA
# A00wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKmo
# 9ObtlCGldjhb69C5Jf99FMS5ZBNFjWa8Q9T954uAMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAkoLehFwrL2ea5RyHC3+Kh5uCwUyu6EpJPTmi
# DZeichzvemSHgUN5Vejldr+oDyfd6Zsh2Rv1SUX8KvYc1cjn+JPOdu/UfEeVVt0E
# 84IA7215cGBTDhMyBVFHgKwP+QLtFhPxtuQXPdCCZ9EiEEdooxh6+pCSggmOhOpJ
# 1rnd5Eo7a3vp5aoNWBXrYlYS9XOB51NVHRUqXJTVPrvEgtVQGHg0yWNOeu3vTDqg
# Gu7WXFO9vLUUQGSIFhhX+P1fPRq5SG/LtW5x9Znd5ji0BXEHL3Fgyu9CuRHxxqSs
# NRta199lk6u5i24LrtqvUctVsnI31WHmEVWKT1vhkgxUA7GDfqGCFv0wghb5Bgor
# BgEEAYI3AwMBMYIW6TCCFuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCDZez0UnbR7ZWu1NCNnt9PSkLHx8BbDgHCJ
# FDeokEJgyQIGZGzWag6qGBMyMDIzMDYwNjExNDU1NC4yMzJaMASAAgH0oIHQpIHN
# MIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjozRTdBLUUzNTktQTI1RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEVQwggcMMIIE9KADAgECAhMzAAAByfrVjiUgdAJeAAEA
# AAHJMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMTEwNDE5MDEzOFoXDTI0MDIwMjE5MDEzOFowgcoxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNFN0EtRTM1
# OS1BMjVEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1nLi5Y5vz8K+Woxhk7qGW/vC
# xi5euTM01TiEbFOG8g7SFB0VMjYgo6TiRzgOQ+CN53OBOKlyMHWzRL4xvaS03ZlI
# getIILYiASogsEtljzElRHO7fDGDFWcdz+lCNYmJoztbG3PMrnxblUHHUkr4C7EB
# Hb2Y07Gd5GJBgP8+5AZNsTlsHGczHs45mmP7rUgcMn//c8Q/GYSqdT4OXELp53h9
# 9EnyF4zcsd2ZFjxdj1lP8QGwZZS4F82JBGe2pCrSakyFjTxzFKUOwcQerwBR/YaQ
# ly7mtCra4PNcyEQm+n/LDce/VViQa8OM2nBZHKw6CyMqEzFJJy5Hizz8Z6xrqqLK
# ti8viJUQ0FtqkTXSR3//w8PAKyBlvIYTFF/Ly3Jh3cbVeOgSmubOVwv8nMehcQb2
# AtxcU/ldyEUqy8/thEHIWNabzHXx5O9D4btS6oJdgLmHxrTBtGscVQqx0z5/fUIk
# LE7tbwfoq84cF/URLEyw3q57KV2U4gOhc356XYEVQdJXo6VFWBQDYbzanQ25zY21
# UCkj821CyD90gqrO3rQPlcQo6erwW2DF2fsmgAbVqzQsz6Rkmafz4re17km7qe09
# PuwHw5e3x5ZIGEoVlfNnJv6+851uwKX6ApZFxPzeQo7W/5BtaTmkZEhwY5AdCPgP
# v0aaIEQn2qF7MvFwCcsCAwEAAaOCATYwggEyMB0GA1UdDgQWBBQFb51nRsI8ob54
# OhTFeVF7RC4yyzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
# KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4ICAQA2qLqcZt9HikIHcj7AlnHhjouxSjOeBaTE+EK8aXcV
# Lm9cA8D2/ZY2OUpYvOdhuDEV9hElVmzopiJuk/xBYh6dWJTRhmS7hVjrGtqzSFW0
# LffsRysjxkpuqyhHiBDxMXMGZ6GdzUfqVP2Zd2O+J/BYQJgs9NHYz/CM4XaRP+T2
# VM3JE1mSO1qLa+mfB427QiLj/JC7TUYgh4RY+oLMFVuQJZvXYl/jITFfUppJoAak
# Br0Vc2r1kP5DiJaNvZWJ/cuYaiWQ4k9xpw6wGz3qq7xAWnlGzsawwFhjtwq5EH/s
# 37LCfehyuCw8ZRJ9W3tgSFepAVM7sUE+Pr3Uu+iPvBV4TsTDNFL0CVIPX+1XOJ6Y
# RGYJ2kHGpoGc/5sgA2IKQcl97ZDYJIqixgwKNftyN70O0ATbpTVhsbN01FVli0H+
# vgcGhyzk6jpAywHPDSQ/xoEeGU4+6PFTXMRO/fMzGcUcf0ZHqZMm0UhoH8tOtk18
# k6B75KJXTtY3ZM7pTfurSv2Qrv5zzCBiyystOPw/IJI+k9opTgatrC39L69/Kwyt
# D0x7t0jmTXtlLZaGvoSljdyyr6QDRVkqsCaLUSSsAiWeav5qg64U3mLmeeko0E9T
# J5yztN/jcizlHx0XsgOuN6sub3CPV7AAMMiKopdQYqiPXu9IxvqXT7CE/SMC2pcN
# yTCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQEL
# BQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNV
# BAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4X
# DTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM
# 57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm
# 95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzB
# RMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBb
# fowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCO
# Mcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYw
# XE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW
# /aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/w
# EPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPK
# Z6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2
# BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfH
# CBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYB
# BAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8v
# BO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYM
# KwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEF
# BQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBW
# BgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUH
# AQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# L2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsF
# AAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518Jx
# Nj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+
# iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2
# pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefw
# C2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7
# T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFO
# Ry3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhL
# mm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3L
# wUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5
# m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE
# 0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLLMIICNAIB
# ATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UE
# CxMdVGhhbGVzIFRTUyBFU046M0U3QS1FMzU5LUEyNUQxJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAH3pi8v+HgGb
# jVQs4G36dRxWBt0OoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwDQYJKoZIhvcNAQEFBQACBQDoKR8aMCIYDzIwMjMwNjA2MTA1NzMwWhgPMjAy
# MzA2MDcxMDU3MzBaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOgpHxoCAQAwBwIB
# AAICFicwBwIBAAICEeMwCgIFAOgqcJoCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYK
# KwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUF
# AAOBgQAwd+aEcACrJansvBLpKWf51UWV4An/sKpNi4fkqX7jijcQD0SZ3ZM9qgkG
# H/fFPOikMesIWe6O9orTwm4rV1kTB7WYQL/XTx8gO6iUi0KBT0QZL12QBeP7jpCA
# nKddXAjb86uHrVO7ZZUMVM3vibO190xOWGPWu0cgpVxTCsKEkTGCBA0wggQJAgEB
# MIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAByfrVjiUgdAJe
# AAEAAAHJMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwLwYJKoZIhvcNAQkEMSIEIHzra+1ZVfwJlva0qyxVFaoeQ+BZ+kzfbCZv
# m//wkLcXMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQggXXOf1LdUUsQJ3gp
# 2H9gDSMhiQD/zX3hXXzh2Tl2/YEwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAcn61Y4lIHQCXgABAAAByTAiBCBLGLI4zWV3F5jZP8Na
# XN3MMvXjnRy2BkvxARRPxfD72jANBgkqhkiG9w0BAQsFAASCAgBVqafL1NBmmwoH
# OHegfVBU/aLaZZPFYruuU23DnhRlvzVrLiSx6pzcH+AZm2hFLcrAm69Gd+WByjDV
# W3lEnpzw85xojuZ/7moPNRXXUqCymbkXTcHv+dHVJrl/R32WdyHIkRNZSn3AyPd3
# fqM4yb/NGeQiOZJ8ZVWqS+HUuD8vNCoYYiono1/o3VuPTA5ihzsL15uilLrQViM5
# 2Iq1gWesxza4zVIXZ06pnqGvVntC5JxFTotbUpNuJ8jHL1Mna5mCYXOIAl62vI0y
# 1bE8iAUxNYG+3IRTJahL8QWflhw2tfhyDSfr/VqLxIyRaS50boX7ZlIc0aGJ2NcP
# T3t3DpWTEUf3CdaDuSmqWhk+7+z2Qgz4X4YYWtWc/Cp07vNTDx7esYxZn4wEvlLf
# THGzFWn16ZOwbDL877yUiIjTqaHygNvsNj3CyucLM3xRZ2nfokAv8vmxHwZ0emUv
# xCG812kgFRAjF0OM2xRc16CTw4vOuLeF4pzeFIr6R5UUSRd3Uxm/NsKFFCw0grTG
# Yq+hDn0WJvF4B86Wg2UF7kjdXRJxVhfsrpinKOvUoXwnnxiLtXEAa2ehfE9e1G77
# dvd19UZvRZt9I3aAP2nGAaooA0/XgngGzoJRAFX1ycfq7xPcxAySlStFHKcJqr6g
# KWfEG0O3d07XN5RR1YIOzj4/ZAbokw==
# SIG # End signature block
