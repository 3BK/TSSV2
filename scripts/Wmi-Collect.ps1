param( [string]$DataPath, `
       [switch]$AcceptEula, `
       [switch]$Logs, `
       [switch]$Trace, `
       [switch]$Activity, `
       [switch]$Storage, `
       [switch]$Cluster, `
       [switch]$DCOM, `
       [switch]$RPC, `
       [switch]$MDM, `
       [switch]$Perf, `
       [switch]$RDMS, `
       [switch]$RDSPub, `
       [switch]$SCM, `
       [switch]$PerfMonWMIPrvSE, `
       [switch]$Network, `
       [switch]$WPR, `
       [switch]$Kernel
     )

$version = "WMI-Collect (20230504)"
# by Gianni Bragante - gbrag@microsoft.com

$DiagVersion = "WMI-RPC-DCOM-Diag (20230309)"
# by Marius Porcolean maporcol@microsoft.com

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

Function Write-LogMessage {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Message,

        [Parameter()]
        [ValidateSet('Error', 'Warning', 'Pass', 'Info')]
        [string] $Type = $null
    )
    
    $Color = $null
    switch ($Type) {
        "Error" {
            $Message = (Get-Date).ToString("yyyyMMdd-HH:mm:ss.fff") + "    " + "[ERROR]   " + $Message
            $Color = 'Magenta'
        }
        "Warning" {
            $Message = (Get-Date).ToString("yyyyMMdd-HH:mm:ss.fff") + "    " + "[WARNING] " + $Message
            $Color = 'Yellow'
        }
        "Pass" {
            $Message = (Get-Date).ToString("yyyyMMdd-HH:mm:ss.fff") + "    " + "[PASS]    " + $Message
            $Color = 'Green'
        }
        Default {
            $Message = (Get-Date).ToString("yyyyMMdd-HH:mm:ss.fff") + "    " + "[INFO]    " + $Message
        }
    }
    if ([string]::IsNullOrEmpty($Color)) {
        Write-Host $Message
    } 
    else {
        Write-Host $Message -ForegroundColor $Color
    }
    if (!($NoLogFile)) {
        $Message | Out-File -FilePath $diagfile -Append
    }
}

Function WMITraceCapture {
  $cmd =  ("logman create trace 'wmi-trace' -ow -o '" + $TracesDir + "WMI-Trace-$env:COMPUTERNAME.etl" + "' -p 'Microsoft-Windows-WMI' 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets")
  Write-Log $cmd
  while ($true) {
    $out = Invoke-Expression $cmd
    if ($out -match "Error") {
      Write-Log ("Waiting for the WMI etw provider to become available" + $out)
      Sleep 1
    } else {
      Write-Log "Trace created"
      break
    }
  }
  #Invoke-CustomCommand ("logman create trace 'wmi-trace' -ow -o '" + $TracesDir + "WMI-Trace-$env:COMPUTERNAME.etl" + "' -p 'Microsoft-Windows-WMI' 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets")

  Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}' 0xffffffffffffffff 0xff -ets" # WMI-Activity

  if (-not $Activity) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{2CF953C0-8DF7-48E1-99B9-6816A2FBDC9F}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-WMIAdapter
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{1FF6B227-2CA7-40F9-9A66-980EADAA602E}' 0xffffffffffffffff 0xff -ets" # WMI_Tracing
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{8E6B6962-AB54-4335-8229-3255B919DD0E}' 0xffffffffffffffff 0xff -ets" # WMI_Tracing_Client_Operations_Info_Guid
  }
  if ($Storage) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{595F33EA-D4AF-4F4D-B4DD-9DACDD17FC6E}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-StorageManagement-WSP-Host
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{88C09888-118D-48FC-8863-E1C6D39CA4DF}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-StorageManagement-WSP-Spaces
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{C6281CF0-7253-4185-9A91-486327931BDC}' 0xffffffffffffffff 0xff -ets" # SxControlGuid
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{9282168F-2432-45F0-B91C-3AF363C149DD}' 0xffffffffffffffff 0xff -ets" # TRACELOG_PROVIDER_NAME_STORAGEWMI
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{7E58E69A-E361-4F06-B880-AD2F4B64C944}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-StorageManagement
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{88B892C2-FCCD-4881-946A-032897F954B0}' 0xffffffffffffffff 0xff -ets" # Provider Passthru
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{E14DCDD9-D1EC-4DC3-8395-A606DF8EF115}' 0xffffffffffffffff 0xff -ets" # virtdisk
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{4D20DF22-E177-4514-A369-F1759FEEDEB3}' 0xffffffffffffffff 0xff -ets" # virtdisk
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{C24D82FA-8E22-46C8-9D79-4D763EA059D0}' 0xffffffffffffffff 0xff -ets" # storagewmi
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{80DF111F-178D-44FB-AFB4-5D179DE9D4EC}' 0xffffffffffffffff 0xff -ets" # storagewmi
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{4FA1102E-CC1D-4509-A69F-121E2CC96F9C}' 0xffffffffffffffff 0xff -ets" # SDDC
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{7F8DA3B5-A58F-481E-9637-D41435AE6D8B}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-SDDC-Management
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{6D09BA4F-D4D0-49DD-8BDD-DEB59A33DFA8}' 0xffffffffffffffff 0xff -ets" # TRACELOG_PROVIDER_NAME_SMPHOST
  }
  
  if ($Cluster) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{0461BE3C-BC15-4BAD-9A9E-51F3FADFEC75}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-FailoverClustering-WMIProvider
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{FF3E7036-643F-430F-B015-2933466FF0FD}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-FailoverClustering-WMI
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{D82DBA12-8B70-49EE-B844-44D0885951D2}' 0xffffffffffffffff 0xff -ets" # CSVFLT
  }  
  if ($DCOM) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{B46FA1AD-B22D-4362-B072-9F5BA07B046D}' 0xffffffffffffffff 0xff -ets" # comsvcs
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{A0C4702B-51F7-4ea9-9C74-E39952C694B8}' 0xffffffffffffffff 0xff -ets" # comadmin
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{9474a749-a98d-4f52-9f45-5b20247e4f01}' 0xffffffffffffffff 0xff -ets" # dcomscm
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{bda92ae8-9f11-4d49-ba1d-a4c2abca692e}' 0xffffffffffffffff 0xff -ets" # ole32
    Invoke-CustomCommand "reg add HKEY_LOCAL_MACHINE\Software\Microsoft\OLE\Tracing /v ExecutablesToTrace /t REG_MULTI_SZ /d * /f"
  }  
  if ($RPC) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{6AD52B32-D609-4BE9-AE07-CE8DAE937E39}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-RPC
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{F4AED7C7-A898-4627-B053-44A7CAA12FCD}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-RPC-Events
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{D8975F88-7DDB-4ED0-91BF-3ADF48C48E0C}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-RPCSS
  }  
  if ($MDM) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{0A8E17FD-ED19-4C54-A1E7-5A2829BF507F}' 0xffffffffffffffff 0xff -ets" # DMCmnUtils
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{F1201B5A-E170-42B6-8D20-B57AC57E6416}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-DeviceManagement-Pushrouter
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{9FBF7B95-0697-4935-ADA2-887BE9DF12BC}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-DM-Enrollment-Provider
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{3DA494E4-0FE2-415C-B895-FB5265C5C83B}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{E74EFD1A-B62D-4B83-AB00-66F4A166A2D3}' 0xffffffffffffffff 0xff -ets" # Microsoft.Windows.EMPS.Enrollment
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{F9E3B648-9AF1-4DC3-9A8E-BF42C0FBCE9A}' 0xffffffffffffffff 0xff -ets" # Microsoft.Windows.EnterpriseManagement.Enrollment
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{86625C04-72E1-4D36-9C86-CA142FD0A946}' 0xffffffffffffffff 0xff -ets" # Microsoft.Windows.DeviceManagement.OmaDmApiProvider
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{7D85C2D0-6490-4BB4-BAC1-247D0BD06F10}' 0xffffffffffffffff 0xff -ets" # Microsoft-WindowsPhone-OMADMAPI-Provider
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{EF614386-F019-4323-85A1-D6EBAF9CDE12}' 0xffffffffffffffff 0xff -ets" # WPPCtrlGuid
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{A76DBA2C-9683-4BA7-8FE4-C82601E117BB}' 0xffffffffffffffff 0xff -ets" # WMIBRIDGE_TRACE_LOGGING_PROVIDER
  }  
  if ($Perf) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{BFFB9DBD-5983-4197-BB1A-243798DDBEC7}' 0xffffffffffffffff 0xff -ets" # WMIPerfClass
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{970406AD-6475-45DA-AA30-57E0037770E4}' 0xffffffffffffffff 0xff -ets" # WMIPerfInst	
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{62841F33-387A-4674-94A4-485C418C57EE}' 0xffffffffffffffff 0xff -ets" # Pdh
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{04D66358-C4A1-419B-8023-23B73902DE2C}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-PDH
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{E1A5FA6F-2E74-4C70-B292-D34C4338D54C}' 0xffffffffffffffff 0xff -ets" # LoadperfDll
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{BC44FFCD-964B-5B85-8662-0BA87EDAF07A}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Perflib
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{13B197BD-7CEE-4B4E-8DD0-59314CE374CE}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Perflib
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{970407AD-6485-45DA-AA30-58E0037770E4}' 0xffffffffffffffff 0xff -ets" # PerfLib
  }  
  if ($RDMS) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{FB750AD9-8544-427F-B284-8ED9C6C221AE}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Rdms-UI
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{05DA6B40-219E-4F17-92E6-D663FD87CBA8}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Remote-Desktop-Management-Service
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{1B9B72FC-678A-41C1-9365-824658F887E9}' 0xffffffffffffffff 0xff -ets" # RDMSTrace
  }  
  if ($RDSPub) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{81B84BCE-06B4-40AE-9840-8F04DD7A8DF7}' 0xffffffffffffffff 0xff -ets" # TSCPubWmiProvider
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{0CEA2AEE-1A4C-4DE7-B11F-161F3BE94669}' 0xffffffffffffffff 0xff -ets" # TSPublishingIconHelperTrace
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{1B9B72FC-678A-41C1-9365-824658F887E9}' 0xffffffffffffffff 0xff -ets" # TSPublishingAppFilteringTrace
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{7ADA0B31-F4C2-43F4-9566-2EBDD3A6B604}' 0xffffffffffffffff 0xff -ets" # TSCentralPublishingTrace
  }  
  if ($SCM) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{EBCCA1C2-AB46-4A1D-8C2A-906C2FF25F39}' 0xffffffffffffffff 0xff -ets" # ScReg
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{0063715B-EEDA-4007-9429-AD526F62696E}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Services
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{06184C97-5201-480E-92AF-3A3626C5B140}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Services-Svchost
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{555908D1-A6D7-4695-8E1E-26931D2012F4}' 0xffffffffffffffff 0xff -ets" # Service Control Manager
  }  
  if ($PerfMonWMIPrvSE) {
    #Invoke-CustomCommand ("Logman create counter 'WMI-Trace-PerfMonWMIPrvSE' -f bincirc -max 512 -c '\WMIPrvSE Health Status(*)\*' -si 00:00:01 -o '" + $TracesDir + "WMI-Trace-PerfMonWMIPrvSE-$env:COMPUTERNAME.blg'")
    Invoke-CustomCommand ("Logman create counter 'WMI-Trace-PerfMonWMIPrvSE' -f bincirc -max 512 -c '\Process(WmiPrvSE*)\ID Process' '\Process(WmiPrvSE*)\Thread Count' '\Process(WmiPrvSE*)\Handle Count' '\Process(WmiPrvSE*)\Working Set' '\Process(WmiPrvSE*)\% Processor Time' -si 00:00:01 -o '" + $TracesDir + "WMI-Trace-PerfMonWMIPrvSE-$env:COMPUTERNAME.blg' -ow --v")
    Invoke-CustomCommand ("logman start 'WMI-Trace-PerfMonWMIPrvSE'")
  }

  if ($Network) {
    Invoke-CustomCommand ("netsh trace start capture=yes scenario=netconnection maxsize=2048 report=disabled tracefile='" + $TracesDir + "NETCAP-" + $env:COMPUTERNAME + ".etl'")
  }  
  if ($Kernel) {
    Invoke-CustomCommand ("logman create trace 'NT Kernel Logger' -ow -o '" + $TracesDir + "WMI-Trace-kernel-$env:COMPUTERNAME.etl" + "' -p '{9E814AAD-3204-11D2-9A82-006008A86939}' 0x1 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 512 -ets")
  }
  if ($WPR) {
    Invoke-CustomCommand ("wpr -start GeneralProfile -start CPU")
  }

  Write-Log "Trace capture started"
  read-host "Press ENTER to stop the capture"
  Invoke-CustomCommand "logman stop 'wmi-trace' -ets"
  
  if ($DCOM) {
    Invoke-CustomCommand "reg delete HKEY_LOCAL_MACHINE\Software\Microsoft\OLE\Tracing /v ExecutablesToTrace /f"
  }  
  if ($PerfMonWMIPrvSE) {
    Invoke-CustomCommand ("logman stop 'WMI-Trace-PerfMonWMIPrvSE'")
    Invoke-CustomCommand ("logman delete 'WMI-Trace-PerfMonWMIPrvSE'")
  }
  if ($Network) {
    Invoke-CustomCommand "netsh trace stop"
  }  
  if ($Kernel) {
    Invoke-CustomCommand "logman stop 'NT Kernel Logger' -ets"
  }  
  Invoke-CustomCommand "tasklist /svc" -DestinationFile "Traces\tasklist-$env:COMPUTERNAME.txt"
  if ($WPR) {
    Invoke-CustomCommand ("wpr -stop '"+ $TracesDir + $env:COMPUTERNAME + "_GenProf.etl'")
  }
}

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

$global:Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path
$resName = "WMI-Results-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)

if ($DataPath) {
  if (-not (Test-Path $DataPath)) {
    Write-Host "The folder $DataPath does not exist"
    exit
  }
  $global:resDir = $DataPath + "\" + $resName
} else {
  $global:resDir = $global:Root + "\" + $resName
}

Import-Module ($global:Root + "\Collect-Commons.psm1") -Force -DisableNameChecking

if (-not $Trace -and -not $Logs) {
    Write-Host "$version, a data collection tool for WMI troubleshooting"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "WMI-Collect -Logs"
    Write-Host "  Collects dumps, logs, registry keys, command outputs"
    Write-Host ""
    Write-Host "WMI-Collect -Trace [-Activity][-Storage][-Cluster][-DCOM][-RPC][-MDM][-RDMS][-RDSPUB][-Network][-Kernel][-WPR]"
    Write-Host "  Collects live trace"
    Write-Host ""
    Write-Host "WMI-Collect -Logs -Trace [-Activity][-Storage][-Cluster][-DCOM][-RPC][-MDM][-RDMS][-RDSPub][-Network][-Kernel][-WPR]"
    Write-Host "  Collects live trace then -Logs data"
    Write-Host ""
    Write-Host "Parameters for -Trace :"
    Write-Host "  -Activity : Only trace WMI-Activity, less detailed"
    Write-Host "  -Storage : Storage providers"
    Write-Host "  -Cluster : Cluster providers"
    Write-Host "  -DCOM : OLE, COM and DCOM tracing"
    Write-Host "  -RPC : Remote Procedure Call"
    Write-Host "  -MDM : Mobile Device Manager"
    Write-Host "  -RDMS : Remote Desktop Management"
    Write-Host "  -RDSPub : Remote Desktop Publishing"
    Write-Host "  -Network : Network capture"
    Write-Host "  -Kernel : Kernel Trace for process start and stop"
    Write-Host "  -WPR: Windows Performance Recorder trace (GeneralProfile CPU)"
    Write-Host "  -PerfMonWMIPrvSE: Performance monitor data for WMIPrvSE processes"
    Write-Host ""
    exit
}

New-Item -itemtype directory -path $global:resDir | Out-Null

$global:outfile = $global:resDir + "\script-output.txt"
$global:errfile = $global:resDir + "\script-errors.txt"
$diagfile = $global:resDir + "\WMI-RPC-DCOM-Diag.txt"

Write-Log $version
if ($AcceptEula) {
  Write-Log "AcceptEula switch specified, silently continuing"
  $eulaAccepted = ShowEULAIfNeeded "WMI-Collect" 2
} else {
  $eulaAccepted = ShowEULAIfNeeded "WMI-Collect" 0
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
  WMITraceCapture
  if (-not $Logs) {
    exit
  }
}

$subDir = $global:resDir + "\Subscriptions"
New-Item -itemtype directory -path $subDir | Out-Null

Write-Log "Collecting dump of the svchost process hosting the WinMgmt service"
$pidsvc = FindServicePid "winmgmt"
if ($pidsvc) {
  Write-Log "Found the PID using FindServicePid"
  CreateProcDump $pidsvc $global:resDir "svchost-WinMgmt"
} else {
  Write-Log "Cannot find the PID using FindServicePid, looping through processes"
  $list = Get-Process
  $found = $false
  if (($list | Measure-Object ).count -gt 0) {
    foreach ($proc in $list) {
      $prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmisvc.dll"} 
      if (($prov | Measure-Object).count -gt 0) {
        Write-Log "Found the PID having wmisvc.dll loaded"
        CreateProcDump $proc.id $global:resDir "svchost-WinMgmt"
        $found = $true
        break
      }
    }
  }
  if (-not $found) {
    Write-Log "Cannot find any process having wmisvc.dll loaded, probably the WMI service is not running"
  }
}

Write-Log "Collecing the dumps of WMIPrvSE.exe processes"
$list = get-process -Name "WmiPrvSe" -ErrorAction SilentlyContinue 2>>$global:errfile
if (($list | Measure-Object).count -gt 0) {
  foreach ($proc in $list)
  {
    Write-Log ("Found WMIPrvSE.exe with PID " + $proc.Id)
    CreateProcDump $proc.id $global:resDir
  }
} else {
  Write-Log "No WMIPrvSE.exe processes found"
}

Write-Log "Collecing the dumps of decoupled WMI providers"
$list = Get-Process
if (($list | Measure-Object).count -gt 0) {
  foreach ($proc in $list)
  {
    $prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmidcprv.dll"} 
    if (($prov | Measure-Object).count -gt 0) {
      Write-Log ("Found " + $proc.Name + "(" + $proc.id + ")")
      CreateProcDump $proc.id $global:resDir
    }
  }
}

$proc = get-process "WmiApSrv" -ErrorAction SilentlyContinue
if ($proc) {
  Write-Log "Collecting dump of the WmiApSrv.exe process"
  CreateProcDump $proc.id $global:resDir
}

Write-Log "Collecing the dumps of scrcons.exe processes"
$list = get-process -Name "scrcons" -ErrorAction SilentlyContinue 2>>$global:errfile
if (($list | Measure-Object).count -gt 0) {
  foreach ($proc in $list)
  {
    CreateProcDump $proc.id $global:resDir
  }
} else {
  Write-Log "No scrcons.exe processes found"
}

Write-Log "Collecting Autorecover MOFs content"
$mof = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM")).'Autorecover MOFs'
if ($mof.length -eq 0) {
  Write-Log ("The registry key ""HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM\Autorecover MOFs"" is missing or empty")
  exit
}
$mof | Out-File ($global:resDir + "\Autorecover MOFs.txt")

Write-Log "Listing WBEM folder"
Get-ChildItem $env:windir\system32\wbem -Recurse | Out-File $global:resDir\wbem.txt

Write-Log "Exporting WMIPrvSE AppIDs and CLSIDs registration keys"
$cmd = "reg query ""HKEY_CLASSES_ROOT\AppID\{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}"" >> """ + $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
$cmd = "reg query ""HKEY_CLASSES_ROOT\AppID\{1F87137D-0E7C-44d5-8C73-4EFFB68962F2}"" >> """+ $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
$cmd = "reg query ""HKEY_CLASSES_ROOT\Wow6432Node\AppID\{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}"" >> """+ $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
$cmd = "reg query ""HKEY_CLASSES_ROOT\Wow6432Node\AppID\{1F87137D-0E7C-44d5-8C73-4EFFB68962F2}"" >> """+ $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
$cmd = "reg query ""HKEY_CLASSES_ROOT\CLSID\{4DE225BF-CF59-4CFC-85F7-68B90F185355}"" >> """+ $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole """+ $global:resDir + "\Ole.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Rpc"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Rpc """+ $global:resDir + "\Rpc.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Invoke-Expression $cmd

if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc") {
  Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
  $cmd = "reg export ""HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"" """ + $global:resDir + "\Rpc-policies.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $global:errfile + """"
  Invoke-Expression $cmd
}

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Wbem"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Wbem """+ $global:resDir + "\wbem.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Invoke-Expression $cmd

# SCCM automatic remediation exclusion, see https://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/configure-client-status#automatic-remediation-exclusion
Export-RegistryKey -KeyPath "HKLM:\Software\Microsoft\CCM\CcmEval" -DestinationFile "CCMEval.txt"

Write-Log "Getting the output of WHOAMI /all"
$cmd = "WHOAMI /all >>""" + $global:resDir + "\WHOAMI.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Listing members of Remote Management Users group"
$cmd = "net localgroup ""Remote Management Users"" >>""" + $global:resDir + "\Groups.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Exporting Application log"
$cmd = "wevtutil epl Application """+ $global:resDir + "\" + $env:computername + "-Application.evtx"" >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "Application"

Write-Log "Exporting System log"
$cmd = "wevtutil epl System """+ $global:resDir + "\" + $env:computername + "-System.evtx"" >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "System"

Write-Log "Exporting WMI-Activity/Operational log"
$cmd = "wevtutil epl Microsoft-Windows-WMI-Activity/Operational """+ $global:resDir + "\" + $env:computername + "-WMI-Activity.evtx"" >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "WMI-Activity"

if ($PSVersionTable.psversion.ToString() -ge "3.0") {
  $actLog = Get-WinEvent -logname Microsoft-Windows-WMI-Activity/Operational -Oldest -ErrorAction Continue 2>>$global:errfile
  if (($actLog  | Measure-Object).count -gt 0) {
    Write-Log "Exporting WMI-Activity log"
    $actLog | Out-String -width 1000 | Out-File -FilePath ($global:resDir + "\WMI-Activity.txt")
  }
}

Write-Log "Exporting netstat output"
$cmd = "netstat -anob >""" + $global:resDir + "\netstat.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Exporting ipconfig /all output"
$cmd = "ipconfig /all >""" + $global:resDir + "\ipconfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Exporting firewall rules"
$cmd = "netsh advfirewall firewall show rule name=all >""" + $global:resDir + "\FirewallRules.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Enumerating services with SC query"
$cmd = "sc.exe query >>""" + $global:resDir + "\Services-SCQuery.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Exporting service configuration"
$cmd = "sc.exe queryex winmgmt >>""" + $global:resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "sc.exe qc winmgmt >>""" + $global:resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "sc.exe enumdepend winmgmt 3000 >>""" + $global:resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "sc.exe sdshow winmgmt >>""" + $global:resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

FileVersion -Filepath ($env:windir + "\system32\wbem\wbemcore.dll") -Log $true
FileVersion -Filepath ($env:windir + "\system32\wbem\repdrvfs.dll") -Log $true
FileVersion -Filepath ($env:windir + "\system32\wbem\WmiPrvSE.exe") -Log $true
FileVersion -Filepath ($env:windir + "\system32\wbem\WmiPerfClass.dll") -Log $true
FileVersion -Filepath ($env:windir + "\system32\wbem\WmiApRpl.dll") -Log $true

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

  Write-Log "COM Security"
  $Reg = [WMIClass]"\\.\root\default:StdRegProv"
  $DCOMMachineLaunchRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction").uValue
  $DCOMMachineAccessRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineAccessRestriction").uValue
  $DCOMDefaultLaunchPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultLaunchPermission").uValue
  $DCOMDefaultAccessPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultAccessPermission").uValue

  # Convert the current permissions to SDDL
  $converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
  "Default Access Permission = " + ($converter.BinarySDToSDDL($DCOMDefaultAccessPermission)).SDDL | Out-File -FilePath ($global:resDir + "\COMSecurity.txt") -Append
  "Default Launch Permission = " + ($converter.BinarySDToSDDL($DCOMDefaultLaunchPermission)).SDDL | Out-File -FilePath ($global:resDir + "\COMSecurity.txt") -Append
  "Machine Access Restriction = " + ($converter.BinarySDToSDDL($DCOMMachineAccessRestriction)).SDDL | Out-File -FilePath ($global:resDir + "\COMSecurity.txt") -Append
  "Machine Launch Restriction = " + ($converter.BinarySDToSDDL($DCOMMachineLaunchRestriction)).SDDL | Out-File -FilePath ($global:resDir + "\COMSecurity.txt") -Append

  Write-Log "Collecting details of provider hosts"
  New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR -ErrorAction SilentlyContinue | Out-Null

  "Coupled providers (WMIPrvSE.exe processes)" | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
  "" | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append

  $totMem = 0
  $prov = ExecQuery -NameSpace "root\cimv2" -Query "select HostProcessIdentifier, Provider, Namespace, User from MSFT_Providers"
  if ($prov) {
    $proc = ExecQuery -NameSpace "root\cimv2" -Query "select ProcessId, HandleCount, ThreadCount, PrivatePageCount, CreationDate, KernelModeTime, UserModeTime from Win32_Process where name = 'wmiprvse.exe'"
    foreach ($prv in $proc) {
      $provhost = $prov | Where-Object {$_.HostProcessIdentifier -eq $prv.ProcessId}

      if (($provhost | Measure-Object).count -gt 0) {
        if ($PSVersionTable.psversion.ToString() -ge "3.0") {
          $ut = New-TimeSpan -Start $prv.CreationDate
        } else {
          $ut = New-TimeSpan -Start $prv.ConvertToDateTime($prv.CreationDate)
        }

        $uptime = ($ut.Days.ToString() + "d " + $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00"))

        $ks = $prv.KernelModeTime / 10000000
        $kt = [timespan]::fromseconds($ks)
        $kh = $kt.Hours.ToString("00") + ":" + $kt.Minutes.ToString("00") + ":" + $kt.Seconds.ToString("00")

        $us = $prv.UserModeTime / 10000000
        $ut = [timespan]::fromseconds($us)
        $uh = $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00")

        "PID" + " " + $prv.ProcessId + " (" + [String]::Format("{0:x}", $prv.ProcessId) + ") Handles:" + $prv.HandleCount +" Threads:" + $prv.ThreadCount + " Private KB:" + ($prv.PrivatePageCount/1kb) + " KernelTime:" + $kh + " UserTime:" + $uh + " Uptime:" + $uptime + " " + (Get-ProcBitness($prv.ProcessId)) | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
        $totMem = $totMem + $prv.PrivatePageCount
      } else {
        Write-Log ("No provider found for the WMIPrvSE process with PID " +  $prv.ProcessId)
      }

      foreach ($provname in $provhost) {
        $provdet = ExecQuery -NameSpace $provname.Namespace -Query ("select * from __Win32Provider where Name = """ + $provname.Provider + """")
        $hm = $provdet.hostingmodel
        $clsid = $provdet.CLSID
        $dll = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKCR:\CLSID\" + $clsid + "\InprocServer32")).'(default)' 2>>$global:errfile
        $dll = $dll.Replace("""","")
        $file = Get-Item ($dll)
        $dtDLL = $file.CreationTime
        $verDLL = $file.VersionInfo.FileVersion

        $provname.Namespace + " " + $provname.Provider + " " + $dll + " " + $hm + " " + $provname.user + " " + $dtDLL + " " + $verDLL 2>>$global:errfile | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
      }
      " " | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
    }
  }
  "Total memory used by coupled providers: " + ($totMem/1kb) + " KB" | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
  " " | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append

  # Details of decoupled providers
  $list = Get-Process
  foreach ($proc in $list) {
    $prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmidcprv.dll"} 
    if (($prov | Measure-Object).count -gt 0) {
      if (-not $hdr) {
        "Decoupled providers" | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
        " " | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
        $hdr = $true
      }

      $prc = ExecQuery -Namespace "root\cimv2" -Query ("select ProcessId, CreationDate, HandleCount, ThreadCount, PrivatePageCount, ExecutablePath, KernelModeTime, UserModeTime from Win32_Process where ProcessId = " +  $proc.id)
      if ($PSVersionTable.psversion.ToString() -ge "3.0") {
        $ut= New-TimeSpan -Start $prc.CreationDate
      } else {
        $ut= New-TimeSpan -Start $prc.ConvertToDateTime($prc.CreationDate)
      }

      $uptime = ($ut.Days.ToString() + "d " + $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00"))

      $ks = $prc.KernelModeTime / 10000000
      $kt = [timespan]::fromseconds($ks)
      $kh = $kt.Hours.ToString("00") + ":" + $kt.Minutes.ToString("00") + ":" + $kt.Seconds.ToString("00")

      $us = $prc.UserModeTime / 10000000
      $ut = [timespan]::fromseconds($us)
      $uh = $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00")

      $svc = ExecQuery -Namespace "root\cimv2" -Query ("select Name from Win32_Service where ProcessId = " +  $prc.ProcessId)
      $svclist = ""
      if ($svc) {
        foreach ($item in $svc) {
          $svclist = $svclist + $item.name + " "
        }
        $svc = " Service: " + $svclist
      } else {
        $svc = ""
      }

      ($prc.ExecutablePath + $svc) | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
      "PID " + $prc.ProcessId  + " (" + [String]::Format("{0:x}", $prc.ProcessId) + ")  Handles: " + $prc.HandleCount + " Threads: " + $prc.ThreadCount + " Private KB: " + ($prc.PrivatePageCount/1kb) + " KernelTime:" + $kh + " UserTime:" + $uh + " Uptime:" + $uptime + " " + (Get-ProcBitness($prv.ProcessId)) | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append

      $Keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Wbem\Transports\Decoupled\Client
      $Items = $Keys | Foreach-Object {Get-ItemProperty $_.PsPath }
      ForEach ($key in $Items) {
        if ($key.ProcessIdentifier -eq $prc.ProcessId) {
          ($key.Scope + " " + $key.Provider) | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
        }
      }
      " " | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
    }
  }

  Write-Log "Collecting quota details"
  $quota = ExecQuery -Namespace "Root" -Query "select * from __ProviderHostQuotaConfiguration"
  if ($quota) {
    ("ThreadsPerHost : " + $quota.ThreadsPerHost + "`r`n") + `
    ("HandlesPerHost : " + $quota.HandlesPerHost + "`r`n") + `
    ("ProcessLimitAllHosts : " + $quota.ProcessLimitAllHosts + "`r`n") + `
    ("MemoryPerHost : " + $quota.MemoryPerHost + "`r`n") + `
    ("MemoryAllHosts : " + $quota.MemoryAllHosts + "`r`n") | Out-File -FilePath ($global:resDir + "\ProviderHostQuotaConfiguration.txt")
  }

  ExecQuery -Namespace "root\subscription" -Query "select * from ActiveScriptEventConsumer" | Export-Clixml -Path ($subDir + "\ActiveScriptEventConsumer.xml")
  ExecQuery -Namespace "root\subscription" -Query "select * from __eventfilter" | Export-Clixml -Path ($subDir + "\__eventfilter.xml")
  ExecQuery -Namespace "root\subscription" -Query "select * from __IntervalTimerInstruction" | Export-Clixml -Path ($subDir + "\__IntervalTimerInstruction.xml")
  ExecQuery -Namespace "root\subscription" -Query "select * from __AbsoluteTimerInstruction" | Export-Clixml -Path ($subDir + "\__AbsoluteTimerInstruction.xml")
  ExecQuery -Namespace "root\subscription" -Query "select * from __FilterToConsumerBinding" | Export-Clixml -Path ($subDir + "\__FilterToConsumerBinding.xml")

  Write-Log "Exporting driverquery /v output"
  $cmd = "driverquery /v >""" + $global:resDir + "\drivers.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append
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

Write-LogMessage ($DiagVersion)

####################################################################################
#################################### Diag start ####################################
####################################################################################

# Check OS version & get IPs
$OSVer = [environment]::OSVersion.Version.Major + [environment]::OSVersion.Version.Minor * 0.1
if ($OSVer -gt 6.1) {

    $versionRegKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    Write-LogMessage "Host: $($env:COMPUTERNAME)"
    Write-LogMessage "Running on: $($versionRegKey.ProductName)"
    Write-LogMessage "Current build number: $($versionRegKey.CurrentBuildNumber).$($versionRegKey.UBR)"
    Write-LogMessage "Build details: $($versionRegKey.BuildLabEx)"

    # TODO - try to determine when the last CU was installed...not the best option...
    # tried getting the last write time of the build number in the registry, but that's not possible... 
    # can only get a LastWriteTime for a regkey, not for a regvalue
    # https://devblogs.microsoft.com/scripting/use-powershell-to-access-registry-last-modified-time-stamp/
    $xmlQuery = @'
    <QueryList>
        <Query Id="0" Path="Setup">
            <Select Path="Setup">*[System[(EventID=2)]][UserData[CbsPackageChangeState[(Client='UpdateAgentLCU' or Client='WindowsUpdateAgent') and (ErrorCode='0x0')]]]</Select>
        </Query>
    </QueryList>
'@
    $lastSuccessfulCU = Get-WinEvent -MaxEvents 1 -FilterXml $xmlQuery  -ErrorAction SilentlyContinue
    if ($lastSuccessfulCU) {
        if ($lastSuccessfulCU.TimeCreated -le ((Get-Date).AddDays(-90))) {
            Write-LogMessage -Type Warning "This device looks like it may not have had cumulative updates installed recently. Check current build number ($($versionRegKey.UBR)) vs the build number in the latest KBs for this OS."
        }
        Write-LogMessage "The most recent successfully installed cumulative update was $($lastSuccessfulCU.Properties[0].Value), $(((Get-Date) - $lastSuccessfulCU.TimeCreated).Days) days ago @ $($lastSuccessfulCU.TimeCreated)."
    }
    else {
        Write-LogMessage -Type Warning "Could not detect any successful cumulative update installation events. Check current build number ($($versionRegKey.UBR)) vs the build number in the latest KBs for this OS."
    }

    $psver = $PSVersionTable.PSVersion.Major.ToString() + $PSVersionTable.PSVersion.Minor.ToString()
    if ($psver -lt "51") {
        Write-LogMessage -Type Warning "Windows Management Framework version $($PSVersionTable.PSVersion.ToString()) is no longer supported"
    }
    else { 
        Write-LogMessage "Windows Management Framework version is $($PSVersionTable.PSVersion.ToString())"
    }
    Write-LogMessage "Running PowerShell build $($PSVersionTable.BuildVersion.ToString())"

    $iplist = Get-NetIPAddress
    Write-LogMessage "IP addresses of this machine: $(foreach ($ip in $iplist) {$ip.ToString() +' |'})"
}
else {
    Write-LogMessage -Type Warning "This is a legacy OS, please consider updating to a newer supported version."
}

Write-LogMessage "-------------------------"
Write-LogMessage "Checking domain / workgroup settings..."

# Check if machine is part of a domain or not
$computerSystem = Get-CimInstance -ClassName "Win32_ComputerSystem"
switch ($computerSystem.DomainRole) {
    0 { $role = "Standalone Workstation" }
    1 { $role = "Member Workstation" }
    2 { $role = "Standalone Server" }
    3 { $role = "Member Server" }
    4 { $role = "Backup Domain Controller" }
    5 { $role = "Primary Domain Controller" }
    Default { $role = "Unknown" }
}
if ($computerSystem.PartOfDomain) {
    Write-LogMessage "The machine is part of domain: '$($computerSystem.Domain)', having the role of '$($role)'."

    # TODO - more checks for domain joined machines

}
else {
    Write-LogMessage -Type Warning "The machine is not joined to a domain, it is a '$($role)'."

    # TODO - more checks for non-domain joined (WORKGROUP) machines

}

Write-LogMessage "-------------------------"
Write-LogMessage "Checking services..."

# check WMI, RPCSS, DcomLaunch services
$services = Get-Service EventSystem, COMSysApp, RPCSS, RpcEptMapper, DcomLaunch, Winmgmt
if ($services) {
    foreach ($service in $Services) {
        $msg = "The '$($service.DisplayName)' service is $($service.Status)."
        if ($service.Status -eq 'Running') {
            Write-LogMessage -Type Pass $msg
        }
        else {
            Write-LogMessage -Type Error $msg
        }
        if (($service.Name -eq 'COMSysApp') -and ($service.StartType -ne 'Manual')) {
            Write-LogMessage -Type Warning "The service also does not have its default StartupType. Default: Manual. Current setting: $($service.StartType)."
        }
        elseif (($service.Name -ne 'COMSysApp') -and ($service.StartType -ne 'Automatic')) {
            Write-LogMessage -Type Warning "The service also does not have its default StartupType. Default: Automatic. Current setting: $($service.StartType)."
        }
    }
}
else {
    Write-LogMessage -Type Error "Could not check the status of the services, please look into this!"
}   


Write-LogMessage "-------------------------"
Write-LogMessage "Checking COM+ settings..."

# Check if COM+ is on
$enableComPlus = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\COM3").'Com+Enabled'
if ([string]::IsNullOrEmpty($enableComPlus)) {
    Write-LogMessage -Type Warning "Could not check COM+, please check manually @ HKLM:\SOFTWARE\Microsoft\COM3."
}
else {
    if ($enableComPlus -eq 1) {
        Write-LogMessage -Type Pass "COM+ is enabled."
    }
    elseif ($enableComPlus -eq 0) {
        Write-LogMessage -Type Error "COM+ is NOT enabled."
    }
}

# Check if COM+ remote access is on
$remoteComPlus = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\COM3").RemoteAccessEnabled
if ([string]::IsNullOrEmpty($remoteComPlus)) {
    Write-LogMessage -Type Warning "Could not check COM+ remote access, please check manually @ HKLM:\SOFTWARE\Microsoft\COM3."
}
else {
    if ($remoteComPlus -eq 1) {
        Write-LogMessage -Type Warning "COM+ remote access is enabled. By default it is off."
    }
    elseif ($remoteComPlus -eq 0) {
        Write-LogMessage -Type Pass "COM+ remote access is not enabled. This is ok, by default it is off."
    }
}


Write-LogMessage "-------------------------"
Write-LogMessage "Checking RPC settings..."

# Check if the Restrict Unauthenticated RPC clients policy is on or not
$restrictRpcClients = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -ErrorAction SilentlyContinue).RestrictRemoteClients
if ([string]::IsNullOrEmpty($restrictRpcClients)) {
    Write-LogMessage -Type Pass "RPC restrictions via policy are not in place."
}
else {
    switch ($restrictRpcClients) {
        0 { Write-LogMessage "The RPC restriction policy is set to 'None', so all connections are allowed." }
        1 { Write-LogMessage "The RPC restriction policy is set to 'Authenticated', so only Authenticated RPC Clients are allowed. Exemptions are granted to interfaces that have requested them." }
        2 { Write-LogMessage -Type Warning "The RPC restriction policy is set to 'Authenticated without exceptions', so only Authenticated RPC Clients are allowed, with NO exceptions. This is known to cause on the client some very tricky to investigate 'access denied' errors." }
        Default { Write-LogMessage -Type Error "The RPC restriction policy seems to be present, but its value seems to be wrong. It should be 0, 1 or 2, but is actually $($restrictRpcClients)." }
    }
}

# Check if RPC Endpoint Mapper Client Authentication is on or not
$authEpResolution = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -ErrorAction SilentlyContinue).EnableAuthEpResolution
if (([string]::IsNullOrEmpty($authEpResolution)) -or ($authEpResolution -eq 0)) {
    Write-LogMessage -Type Pass "RPC Endpoint Mapper Client Authentication is not configured or disabled."
}
elseif ($authEpResolution -eq 1) {
    Write-LogMessage -Type Warning "RPC Endpoint Mapper Client Authentication is enabled, which may cause some issues with applications/components that do not know how to handle this."
}

# Check internet settings for RPC to see if there's a restricted port range
$rpcPortsRestriction = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Rpc\Internet" -ErrorAction SilentlyContinue).UseInternetPorts
if (([string]::IsNullOrEmpty($rpcPortsRestriction)) -or ($rpcPortsRestriction -eq "N")) {
    Write-LogMessage -Type Pass "RPC ports are not restricted."
}
elseif ($rpcPortsRestriction -eq "Y") {
    $rpcPorts = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Rpc\Internet" -ErrorAction SilentlyContinue).Ports
    Write-LogMessage -Type Warning "RPC ports are restricted. This may cause issues with RPC/DCOM connections. The usable port range is defined to '$($rpcPorts.ToString())'."
}

# Check actual dynamic port range
$intSettings = Get-NetTCPSetting -SettingName Internet
if ($null -eq $intSettings) {
    Write-LogMessage -Type Warning "The Internet TCP dynamic port range could not be read, please have a close look."
}
elseif ($intSettings.DynamicPortRangeStartPort -eq 49152 -and $intSettings.DynamicPortRangeNumberOfPorts -eq 16384) {
    Write-LogMessage -Type Pass "The Internet TCP dynamic port range is the default."
}
else {
    Write-LogMessage -Type Warning "The Internet TCP dynamic port range is NOT the default, please have a closer look."
}


Write-LogMessage "-------------------------"
Write-LogMessage "Checking DCOM settings..."

# Check if DCOM is enabled 
$ole = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole"
if ($ole.EnableDCOM -eq "Y") {
    Write-LogMessage -Type Pass "DCOM is enabled."
}
else {
    Write-LogMessage -Type Error "DCOM is NOT enabled! Check the settings."
}

# Check default DCOM Launch & Activation / Access permissions
$defaultPermissions = @(
    @{
        name   = 'Everyone'
        short  = 'WD'
        sid    = 'S-1-1-0'
        launch = 'A;;CCDCSW;;;' 
        access = 'A;;CCDCLC;;;'
    }
    @{
        name   = 'Administrators'
        short  = 'BA'
        sid    = 'S-1-5-32-544'
        launch = 'A;;CCDCLCSWRP;;;'
    }
    @{
        name   = 'Distributed COM Users'
        short  = 'CD'
        sid    = 'S-1-5-32-562'
        launch = 'A;;CCDCLCSWRP;;;'
        access = 'A;;CCDCLC;;;'
    }
    @{
        name   = 'Performance Log Users'
        short  = 'LU'
        sid    = 'S-1-5-32-559'
        launch = 'A;;CCDCLCSWRP;;;'
        access = 'A;;CCDCLC;;;'
    }
    @{
        name   = 'All Application Packages'
        short  = 'AC'
        sid    = 'S-1-15-2-1'
        launch = 'A;;CCDCSW;;;'
        access = 'A;;CCDC;;;'
    }
)

# Get current permissions from registry
$launchRestriction = (([wmiclass]"Win32_SecurityDescriptorHelper").BinarySDToSDDL($ole.MachineLaunchRestriction)).SDDL
$accessRestriction = (([wmiclass]"Win32_SecurityDescriptorHelper").BinarySDToSDDL($ole.MachineAccessRestriction)).SDDL

# Compare current vs default permissions
foreach ($permission in $defaultPermissions.GetEnumerator()) {
    if ($permission.launch) {
        if ($launchRestriction.Contains($permission.launch + $permission.short) -or $launchRestriction.Contains($permission.launch + $permission.sid)) {
            Write-LogMessage -Type Pass "The '$($permission.name)' group is present in Launch & Activation with default permissions."
        }
        else {
            Write-LogMessage -Type Error "The '$($permission.name)' group is NOT present in Launch & Activation with default permissions, please verify."
        }
    }

    if ($permission.access) {
        if ($accessRestriction.Contains($permission.access + $permission.short) -or $accessRestriction.Contains($permission.access + $permission.sid)) {
            Write-LogMessage -Type Pass "The '$($permission.name)' group is present in Access with default permissions."
        }
        else {
            Write-LogMessage -Type Error "The '$($permission.name)' group is NOT present in Access with default permissions, please verify."
        }
    }

    $localGroup = Get-LocalGroup -SID $permission.sid -ErrorAction SilentlyContinue
    if ($localGroup -and !($localGroup.Name -eq $permission.name)) {
        Write-LogMessage -Type Warning "The name of the group is not the original English one (current name: '$($localGroup.Name)'). This is usually because the OS is in a different language & it can cause confusion in some situations, so please be aware / keep this in mind."
    }
}

# Check enabled DCOM protocols
$protocols = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Rpc" -ErrorAction SilentlyContinue).'DCOM Protocols'
if ([string]::IsNullOrEmpty($protocols)) {
    Write-LogMessage -Type Warning "No protocols specified for DCOM."
}
else {
    Write-LogMessage "Enabled protocols: $($protocols)"
    if ($protocols.Contains("ncacn_ip_tcp")) {
        Write-LogMessage -Type Pass "The list of enabled protocols contains 'ncacn_ip_tcp', which should be present by default."
    }
    else {
        Write-LogMessage -Type Error "The list of enabled protocols does NOT contain 'ncacn_ip_tcp', which should be present by default."
    }
}

# Check DcomScmRemoteCallFlags
if ([string]::IsNullOrEmpty($ole.DCOMSCMRemoteCallFlags)) {
    Write-LogMessage -Type Pass "DCOMSCMRemoteCallFlags is not configured in the registry and by default it should not be there. That is ok."
}
else {
    Write-LogMessage -Type Warning "DCOMSCMRemoteCallFlags is configured in the registry with value '$($ole.DCOMSCMRemoteCallFlags)', while it should not be there by default. This does not necessarily mean there is a problem, nevertheless, please check the documentation:`nhttps://learn.microsoft.com/en-us/windows/win32/com/dcomscmremotecallflags"
}

# Check LegacyAuthenticationLevel
if ([string]::IsNullOrEmpty($ole.LegacyAuthenticationLevel)) {
    Write-LogMessage -Type Pass "LegacyAuthenticationLevel is not configured in the registry, so the default is used. That is ok."
}
else {
    Write-LogMessage -Type Warning "LegacyAuthenticationLevel is configured in the registry with value '$($ole.LegacyAuthenticationLevel)', while it should not be there by default. This should not be a problem, though, as we are raising the authentication level in the OS anyway, due to the DCOM hardening. Nevertheless, please check the documentation:`nhttps://learn.microsoft.com/en-us/windows/win32/com/legacyauthenticationlevel"
}

# Check LegacyImpersonationLevel
if ([string]::IsNullOrEmpty($ole.LegacyImpersonationLevel) -or ($ole.LegacyImpersonationLevel -eq 2)) {
    Write-LogMessage -Type Pass "LegacyImpersonationLevel is using the default value. That is ok."
}
else {
    Write-LogMessage -Type Warning "LegacyImpersonationLevel is configured in the registry with value '$($ole.LegacyImpersonationLevel)', while it should be '2' by default. Please check the documentation:`nhttps://learn.microsoft.com/en-us/windows/win32/com/legacyimpersonationlevel"
}

# Check DCOM hardening registry keys
$requireIntegrityAuthLevel = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole\AppCompat" -ErrorAction SilentlyContinue).RequireIntegrityActivationAuthenticationLevel
if ([string]::IsNullOrEmpty($requireIntegrityAuthLevel)) {
    Write-LogMessage -Type Pass "RequireIntegrityActivationAuthenticationLevel is not set in the registry. That is ok."
}
else {
    Write-LogMessage -Type Warning "RequireIntegrityActivationAuthenticationLevel is set in the registry to '$requireIntegrityAuthLevel'. Check info in public KB5004442.`nhttps://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c"
}

$raiseAuthLevel = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole\AppCompat" -ErrorAction SilentlyContinue).RaiseActivationAuthenticationLevel
if ([string]::IsNullOrEmpty($raiseAuthLevel)) {
    Write-LogMessage -Type Pass "RaiseActivationAuthenticationLevel is not set in the registry. That is ok."
}
else {
    Write-LogMessage -Type Warning "RaiseActivationAuthenticationLevel is set in the registry to '$raiseAuthLevel'. Check info in public KB5004442.`nhttps://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c"
}

$disableHardeningLogging = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole\AppCompat" -ErrorAction SilentlyContinue).DisableAuthenticationLevelHardeningLog
if ([string]::IsNullOrEmpty($disableHardeningLogging) -or ($disableHardeningLogging -eq 0)) {
    Write-LogMessage -Type Pass "Hardening related logging is turned on. That is ok, it should be on by default."
}
else {
    Write-LogMessage -Type Error "Hardening related logging is turned off. This is a problem, because you may have failing DCOM calls which you are not aware of. Please turn the logging back on by removing the DisableAuthenticationLevelHardeningLog entry from regkey 'HKLM:\SOFTWARE\Microsoft\Ole\AppCompat'."
}

# Check for any DCOM hardening events (IDs 10036/10037/10038)
$sysEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    ID      = 10036, 10037, 10038
} -ErrorAction SilentlyContinue
if (!$sysEvents) {
    Write-LogMessage -Type Pass "Did not detect any DCOM hardening related events (10036, 10037, 10038) in the System log."
}
else {
    if ($sysEvents.Id.Contains(10036)) {
        Write-LogMessage -Type Warning "Events with ID 10036 detected in the System event log. This device seems to be acting as a DCOM server & is rejecting some incoming connections, please check."
        
        # Print the most recent 5 of them
        Write-LogMessage "Here are the most recent ones:"
        foreach ($event in ($sysEvents | Where-Object { $_.Id -eq 10036 } | Select-Object -First 5)) {
            Write-LogMessage "$($event.TimeCreated) - $($event.Message)"
        }
    }
    if ($sysEvents.Id.Contains(10037)) {
        Write-LogMessage -Type Warning "Events with ID 10037 detected in the System event log. This device seems to be acting as a DCOM client with explicitly set auth level & failing, please check."
          
        # Print the most recent 5 of them
        Write-LogMessage "Here are the most recent ones:"
        foreach ($event in ($sysEvents | Where-Object { $_.Id -eq 10037 } | Select-Object -First 5)) {
            Write-LogMessage "$($event.TimeCreated) - $($event.Message)"
        }
    }
    if ($sysEvents.Id.Contains(10038)) {
        Write-LogMessage -Type Warning "Events with ID 10038 detected in the System event log. This device seems to be acting as a DCOM client with default auth level & failing, please check."
    
        # Print the most recent 5 of them
        Write-LogMessage "Here are the most recent ones:"
        foreach ($event in ($sysEvents | Where-Object { $_.Id -eq 10038 } | Select-Object -First 5)) {
            Write-LogMessage "$($event.TimeCreated) - $($event.Message)"
        }
    }
}


Write-LogMessage "-------------------------"
Write-LogMessage "Checking WMI settings..."

# Check WMI object permissions
New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR -ErrorAction SilentlyContinue | Out-Null
$comWmiObj = Get-ItemProperty -Path "HKCR:\AppID\{8BC3F05E-D86B-11D0-A075-00C04FB68820}" -ErrorAction SilentlyContinue
if (!$comWmiObj) {
    Write-LogMessage -Type Warning "Could not read the permissions for the WMI COM object, please check manually."
}
else {
    $launchWmiPermission = (([wmiclass]"Win32_SecurityDescriptorHelper").BinarySDToSDDL($comWmiObj.LaunchPermission)).SDDL

    $defaultWmiPermissions = @(
        @{
            name   = 'Administrators'
            short  = 'BA'
            sid    = 'S-1-5-32-544'
            launch = 'A;;CCDCLCSWRP;;;'
        }
        @{
            name   = 'Authenticated Users'
            short  = 'AU'
            sid    = 'S-1-5-11'
            launch = 'A;;CCDCSWRP;;;'
        }
    )

    foreach ($permission in $defaultWmiPermissions.GetEnumerator()) {
        if ($launchWmiPermission.Contains($permission.launch + $permission.short) -or $launchWmiPermission.Contains($permission.launch + $permission.sid)) {
            Write-LogMessage -Type Pass "The '$($permission.name)' group is present with default permissions."
        }
        else {
            Write-LogMessage -Type Error "The '$($permission.name)' group is NOT present with default permissions, please verify."
        }

        $localGroup = Get-LocalGroup -SID $permission.sid -ErrorAction SilentlyContinue
        if ($localGroup -and !($localGroup.Name -eq $permission.name)) {
            Write-LogMessage -Type Warning "The name of the group is not the original English one (current name: '$($localGroup.Name)'). This is usually because the OS is in a different language & it can cause confusion in some situations, so please be aware / keep this in mind."
        }
    }
}

# Check event logs for known WMI events in the last 30 days
$cutoffDate = (Get-Date).AddDays(-30)
$wmiProvEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Application'
    ID        = 5612
    StartTime = $cutoffDate
} -ErrorAction SilentlyContinue
if ($wmiProvEvents) {
    Write-LogMessage -Type Warning "Detected $($wmiProvEvents.Count) events with ID 5612 detected in the Application event log in the last 30 days. This means that WmiPrvSE processes are exceeding some quota(s), please check."

    # Print the most recent 5 of them
    Write-LogMessage "Here are the most recent ones:"
    foreach ($event in ($wmiProvEvents | Select-Object -First 5)) {
        Write-LogMessage "$($event.TimeCreated) - $($event.Message)"
    }
}
else {
    Write-LogMessage -Type Pass "Did not detect any WMI Provider Host quota violation events in the Application log."
}

# Check WMI provider host quotas
$defaultQuotas = @(
    @{
        name  = 'ThreadsPerHost'
        value = '256'
    }
    @{
        name  = 'HandlesPerHost'
        value = '4096'
    }
    @{
        name  = 'MemoryPerHost'
        value = '536870912'
    }
    @{
        name  = 'MemoryAllHosts'
        value = '1073741824'
    }
    @{
        name  = 'ProcessLimitAllHosts'
        value = '32'
    }
)
$quotas = Get-CimInstance -Namespace "Root" -ClassName "__ProviderHostQuotaConfiguration"
if ($null -ne $quotas) {
    foreach ($defQuota in $defaultQuotas.GetEnumerator()) {
        if ($defQuota.value -eq $quotas.($defQuota.name)) {
            Write-LogMessage -Type Pass "The WMI provider host quota '$($defQuota.name)' is set to its default value: $($quotas.($defQuota.name))."
        }
        else {
            Write-LogMessage -Type Warning "The WMI provider host quota '$($defQuota.name)' is NOT set to its default value. Default value: '$($defQuota.value)'. Current value: '$($quotas.($defQuota.name))'"
        }
    }
}
else {
    Write-LogMessage -Type Error "Could not read the WMI provider host quotas configuration."
}

# Check for Corrupted.rec file
$corruptionSign = Get-ItemProperty "$env:SystemRoot\System32\wbem\repository\Corrupted.rec" -ErrorAction SilentlyContinue
if ($corruptionSign) {
    Write-LogMessage -Type Warning "Found 'Corrupted.rec' file. This means that the WMI repository could have been corrupted at some point & was restored/reset @ '$($corruptionSign.CreationTimeUtc)'."
    
    # check SCCM client auto remediation setting
    $ccmEval = Get-ItemProperty -Path "HKLM:\Software\Microsoft\CCM\CcmEval" -ErrorAction SilentlyContinue
    if ($ccmEval) {
        if ($ccmEval.NotifyOnly -eq 'TRUE') {
            Write-LogMessage -Type Pass "SCCM client automatic remediation is turned OFF. This should prevent it from automatically resetting the WMI repository."
        }
        else {
            Write-LogMessage -Type Warning "SCCM client automatic remediation is turned ON. This could be an explanation for the repository restore/reset. You can turn this OFF & see if the problem persists, check out this page `nhttps://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/configure-client-status#automatic-remediation-exclusion"
        }
    }
}
else {
    Write-LogMessage -Type Pass "Did not find a 'Corrupted.rec' file. This means that the WMI repository is probably healthy & was not restored/reset recently."
}

# Check repository file size
$repoFile = Get-ItemProperty "$env:SystemRoot\System32\wbem\repository\OBJECTS.DATA" -ErrorAction SilentlyContinue
if ($repoFile) {
    $size = $repoFile.Length / 1024 / 1024
    if ($size -lt 500) {
        Write-LogMessage -Type Pass "The WMI repository file is smaller than 500 MB ($size MB). This seems healthy."
    }
    else {
        if ($size -gt 1000) {
            Write-LogMessage -Type Error "The WMI repository file is larger than 1 GB ($size MB). This may cause issues like slow boot/logon."
        }
        else {
            Write-LogMessage -Type Warning "The WMI repository file is larger than 500 MB ($size MB). This may be a sign of repository bloating."
        }

        # check for RSOP logging reg key
        $rsopLogging = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue).RSoPLogging
        if ($rsopLogging -and $rsopLogging -eq 0) {
            Write-LogMessage -Type Pass "RSOP logging seems to be turned off, this is probably not why the repository is bloated."
        }
        else {
            Write-LogMessage -Type Warning "RSOP logging is turned on and this may be why the repository is so big. You can turn off RSOP logging via policy or registry:`nhttps://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.GroupPolicy::RSoPLogging"
        }
    }
}
else {
    Write-LogMessage -Type Warning "Could not get information about the WMI repository file."
}


Write-LogMessage "-------------------------"
Write-LogMessage "Checking networking settings..."

# check firewall remote administration exception policy
$admException = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\RemoteAdminSettings" -ErrorAction SilentlyContinue).Enabled
if (([string]::IsNullOrEmpty($admException)) -or ($admException -eq 0)) {
    Write-LogMessage -Type Pass "The RemoteAdministrationException policy is not configured or disabled. That is ok."
}
elseif ($admException -eq 1) {
    Write-LogMessage -Type Warning "The RemoteAdministrationException policy is turned on."
    $admExceptionList = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\RemoteAdminSettings" -ErrorAction SilentlyContinue).RemoteAddresses
    if ($admExceptionList) {
        Write-LogMessage -Type Warning "These are the addresses that are allowed through: $($admExceptionList)"
    }
}


# check default Firewall rules for WMI 
$fwRules = Show-NetFirewallRule -PolicyStore ActiveStore | Where-Object { ($_.DisplayGroup -like '*WMI*') -and ($_.Direction -eq 'Inbound') }
if ($fwRules) {
    foreach ($rule in $fwRules) {
        if ($rule.Enabled -eq 'True') {
            Write-LogMessage -Type Pass "Firewall rule '$($rule.DisplayName) - Profile: $($rule.Profile)' is enabled."
        }
        else {
            Write-LogMessage -Type Warning "Firewall rule '$($rule.DisplayName) - Profile: $($rule.Profile)' is not enabled."
        }
    }
}
else {
    Write-LogMessage -Type Error "Could not find any relevant Firewall rules, please look into this, as it is not normal!"
}


# Check IP listen filtering
$iplisten = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -ErrorAction SilentlyContinue).ListenOnlyList
if ($iplisten) {
    Write-LogMessage -Type Warning "The IPLISTEN list is not empty, the listed addresses are $(foreach ($ip in $iplisten) {$ip.ToString() +' |'})."
}
else {
    Write-LogMessage -Type Pass "The IPLISTEN list is empty. That's ok: we should listen on all IP addresses by default."
}


# Check winhttp proxy
$binval = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -ErrorAction SilentlyContinue).WinHttPSettings            
$proxylength = $binval[12]            
if ($proxylength -gt 0) {
    $proxy = -join ($binval[(12 + 3 + 1)..(12 + 3 + 1 + $proxylength - 1)] | ForEach-Object { ([char]$_) })            
    Write-LogMessage -Type Warning "A NETSH WINHTTP proxy is configured: $($proxy)"
    $bypasslength = $binval[(12 + 3 + 1 + $proxylength)]            
    if ($bypasslength -gt 0) {            
        $bypasslist = -join ($binval[(12 + 3 + 1 + $proxylength + 3 + 1)..(12 + 3 + 1 + $proxylength + 3 + 1 + $bypasslength)] | ForEach-Object { ([char]$_) })            
        Write-LogMessage -Type Warning "Bypass list: $($bypasslist)"
    }
    else {            
        Write-LogMessage -Type Warning "No bypass list is configured"
    }            
    Write-LogMessage -Type Warning "Remote WMI over DCOM does not work very well through proxies, make sure that the target machine is in the bypass list or remove the proxy"
}
else {
    Write-LogMessage -Type Pass "No NETSH WINHTTP proxy is configured"
}

# Check other kinds of proxy
$userSettings = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
if ($userSettings.AutoConfigUrl) {
    Write-LogMessage -Type Warning "The user has a proxy auto configuration (PAC) file setup: $($userSettings.AutoConfigUrl)"
}
if ($userSettings.ProxyServer) {
    if ($userSettings.ProxyEnable -eq 1) {
        Write-LogMessage -Type Warning "The user has an explicitly configured proxy server which is enabled: $($userSettings.ProxyServer)"
    }
    else {
        Write-LogMessage -Type Info "The user has an explicitly configured proxy server, but it is not enabled: $($userSettings.ProxyServer)"
    }
}

if (!(Test-Path 'HKU:\S-1-5-18')) {
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
}
$systemSettings = Get-ItemProperty "HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
if ($systemSettings.AutoConfigUrl) {
    Write-LogMessage -Type Warning "The system has a proxy auto configuration (PAC) file setup: $($systemSettings.AutoConfigUrl)"
}
if ($systemSettings.ProxyServer) {
    if ($systemSettings.ProxyEnable -eq 1) {
        Write-LogMessage -Type Warning "The system has an explicitly configured proxy server which is enabled: $($systemSettings.ProxyServer)"
    }
    else {
        Write-LogMessage -Type Info "The system has an explicitly configured proxy server, but it is not enabled: $($systemSettings.ProxyServer)"
    }
}

# Check HTTPERR buildup
$dir = $env:windir + "\system32\logfiles\HTTPERR"
if (Test-Path -path $dir) {
    $httperrfiles = Get-ChildItem -path ($dir)
    $msg = "There are $($httperrfiles.Count) files in the folder $dir"
    if ($httperrfiles.Count -gt 100) {
        Write-LogMessage -Type Warning $msg
    }
    else {
        Write-LogMessage $msg
    }
    $size = 0 
    foreach ($file in $httperrfiles) {
        $size += $file.Length
    }
    $size = [System.Math]::Ceiling($size / 1024 / 1024) # Convert to MB
    $msg = "The folder $dir is using $($size.ToString()) MB of disk space."
    if ($size -gt 100) {
        Write-LogMessage -Type Warning $msg
    }
    else {
        Write-LogMessage $msg
    }
}

# SIG # Begin signature block
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB5Y9WQtEKKBVoR
# ghX29lx1OXaQ3Xj3XtgiS0VKtG/x8KCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
# esGEb+srAAAAAANOMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI5WhcNMjQwMzE0MTg0MzI5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDdCKiNI6IBFWuvJUmf6WdOJqZmIwYs5G7AJD5UbcL6tsC+EBPDbr36pFGo1bsU
# p53nRyFYnncoMg8FK0d8jLlw0lgexDDr7gicf2zOBFWqfv/nSLwzJFNP5W03DF/1
# 1oZ12rSFqGlm+O46cRjTDFBpMRCZZGddZlRBjivby0eI1VgTD1TvAdfBYQe82fhm
# WQkYR/lWmAK+vW/1+bO7jHaxXTNCxLIBW07F8PBjUcwFxxyfbe2mHB4h1L4U0Ofa
# +HX/aREQ7SqYZz59sXM2ySOfvYyIjnqSO80NGBaz5DvzIG88J0+BNhOu2jl6Dfcq
# jYQs1H/PMSQIK6E7lXDXSpXzAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnMc7Zn/ukKBsBiWkwdNfsN5pdwAw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMDUxNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAD21v9pHoLdBSNlFAjmk
# mx4XxOZAPsVxxXbDyQv1+kGDe9XpgBnT1lXnx7JDpFMKBwAyIwdInmvhK9pGBa31
# TyeL3p7R2s0L8SABPPRJHAEk4NHpBXxHjm4TKjezAbSqqbgsy10Y7KApy+9UrKa2
# kGmsuASsk95PVm5vem7OmTs42vm0BJUU+JPQLg8Y/sdj3TtSfLYYZAaJwTAIgi7d
# hzn5hatLo7Dhz+4T+MrFd+6LUa2U3zr97QwzDthx+RP9/RZnur4inzSQsG5DCVIM
# pA1l2NWEA3KAca0tI2l6hQNYsaKL1kefdfHCrPxEry8onJjyGGv9YKoLv6AOO7Oh
# JEmbQlz/xksYG2N/JSOJ+QqYpGTEuYFYVWain7He6jgb41JbpOGKDdE/b+V2q/gX
# UgFe2gdwTpCDsvh8SMRoq1/BNXcr7iTAU38Vgr83iVtPYmFhZOVM0ULp/kKTVoir
# IpP2KCxT4OekOctt8grYnhJ16QMjmMv5o53hjNFXOxigkQWYzUO+6w50g0FAeFa8
# 5ugCCB6lXEk21FFB1FdIHpjSQf+LP/W2OV/HfhC3uTPgKbRtXo83TZYEudooyZ/A
# Vu08sibZ3MkGOJORLERNwKm2G7oqdOv4Qj8Z0JrGgMzj46NFKAxkLSpE5oHQYP1H
# tPx1lPfD7iNSbJsP6LiUHXH1MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGXMwghlvAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEICSxCrs6FGYOZU3oXk5DsP4m
# TM4pC0INZn183RbdvxYsMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAAxCUnGOXSjz+Auj8JFn8HK2yVqm4lCrw/cDPMhVBHfUY8m+2KVBIgWwE
# vIY7gBcmU8ljDHIvPUwCDtSkw3u0SkvFx7vI8OT49P+K6BcNjDOreI/z1xvLfjsV
# QVFVpVR12bC0wX717TXr82il5c8/PI9n5d8YS88h8dD5oVDY5ZIHZB/55X/3YV+c
# FpbT+yS5zU6ETyamZ+2y3b9bLnyuVOVGaJd52c+K/pXuRog4zsO4W0TyM6LyKAuy
# MFycXQeFz/uGxRzONQkzRh9QPdZnC6LsX/8Xp6TV0fElLQ4gE24qwHcP0Gn1qXrw
# tPRNFMYKe5WY+blZmPR/uA/aKwwkqqGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCC
# FuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCDE/zo/H0bs/2r63qf4NLlWu0/e7EpASu98o9kliDz6cwIGZGzWag6g
# GBMyMDIzMDYwNjExNDU1NC4xMDFaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozRTdBLUUz
# NTktQTI1RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVQwggcMMIIE9KADAgECAhMzAAAByfrVjiUgdAJeAAEAAAHJMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEz
# OFoXDTI0MDIwMjE5MDEzOFowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNFN0EtRTM1OS1BMjVEMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEA1nLi5Y5vz8K+Woxhk7qGW/vCxi5euTM01TiEbFOG8g7S
# FB0VMjYgo6TiRzgOQ+CN53OBOKlyMHWzRL4xvaS03ZlIgetIILYiASogsEtljzEl
# RHO7fDGDFWcdz+lCNYmJoztbG3PMrnxblUHHUkr4C7EBHb2Y07Gd5GJBgP8+5AZN
# sTlsHGczHs45mmP7rUgcMn//c8Q/GYSqdT4OXELp53h99EnyF4zcsd2ZFjxdj1lP
# 8QGwZZS4F82JBGe2pCrSakyFjTxzFKUOwcQerwBR/YaQly7mtCra4PNcyEQm+n/L
# Dce/VViQa8OM2nBZHKw6CyMqEzFJJy5Hizz8Z6xrqqLKti8viJUQ0FtqkTXSR3//
# w8PAKyBlvIYTFF/Ly3Jh3cbVeOgSmubOVwv8nMehcQb2AtxcU/ldyEUqy8/thEHI
# WNabzHXx5O9D4btS6oJdgLmHxrTBtGscVQqx0z5/fUIkLE7tbwfoq84cF/URLEyw
# 3q57KV2U4gOhc356XYEVQdJXo6VFWBQDYbzanQ25zY21UCkj821CyD90gqrO3rQP
# lcQo6erwW2DF2fsmgAbVqzQsz6Rkmafz4re17km7qe09PuwHw5e3x5ZIGEoVlfNn
# Jv6+851uwKX6ApZFxPzeQo7W/5BtaTmkZEhwY5AdCPgPv0aaIEQn2qF7MvFwCcsC
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBQFb51nRsI8ob54OhTFeVF7RC4yyzAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQA2qLqcZt9HikIHcj7AlnHhjouxSjOeBaTE+EK8aXcVLm9cA8D2/ZY2OUpYvOdh
# uDEV9hElVmzopiJuk/xBYh6dWJTRhmS7hVjrGtqzSFW0LffsRysjxkpuqyhHiBDx
# MXMGZ6GdzUfqVP2Zd2O+J/BYQJgs9NHYz/CM4XaRP+T2VM3JE1mSO1qLa+mfB427
# QiLj/JC7TUYgh4RY+oLMFVuQJZvXYl/jITFfUppJoAakBr0Vc2r1kP5DiJaNvZWJ
# /cuYaiWQ4k9xpw6wGz3qq7xAWnlGzsawwFhjtwq5EH/s37LCfehyuCw8ZRJ9W3tg
# SFepAVM7sUE+Pr3Uu+iPvBV4TsTDNFL0CVIPX+1XOJ6YRGYJ2kHGpoGc/5sgA2IK
# Qcl97ZDYJIqixgwKNftyN70O0ATbpTVhsbN01FVli0H+vgcGhyzk6jpAywHPDSQ/
# xoEeGU4+6PFTXMRO/fMzGcUcf0ZHqZMm0UhoH8tOtk18k6B75KJXTtY3ZM7pTfur
# Sv2Qrv5zzCBiyystOPw/IJI+k9opTgatrC39L69/KwytD0x7t0jmTXtlLZaGvoSl
# jdyyr6QDRVkqsCaLUSSsAiWeav5qg64U3mLmeeko0E9TJ5yztN/jcizlHx0XsgOu
# N6sub3CPV7AAMMiKopdQYqiPXu9IxvqXT7CE/SMC2pcNyTCCB3EwggVZoAMCAQIC
# EzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoX
# DTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC
# 0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VG
# Iwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP
# 2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/P
# XfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361
# VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwB
# Sru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9
# X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269e
# wvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDw
# wvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr
# 9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+e
# FnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAj
# BgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+n
# FV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBH
# hkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
# BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4Swf
# ZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTC
# j/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu
# 2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/
# GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3D
# YXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbO
# xnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqO
# Cb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I
# 6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0
# zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaM
# mdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNT
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLLMIICNAIBATCB+KGB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046M0U3QS1FMzU5LUEyNUQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAH3pi8v+HgGbjVQs4G36dRxWBt0OoIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoKR8aMCIYDzIwMjMwNjA2MTA1NzMwWhgPMjAyMzA2MDcxMDU3MzBaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOgpHxoCAQAwBwIBAAICFicwBwIBAAICEeMw
# CgIFAOgqcJoCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQAwd+aEcACrJans
# vBLpKWf51UWV4An/sKpNi4fkqX7jijcQD0SZ3ZM9qgkGH/fFPOikMesIWe6O9orT
# wm4rV1kTB7WYQL/XTx8gO6iUi0KBT0QZL12QBeP7jpCAnKddXAjb86uHrVO7ZZUM
# VM3vibO190xOWGPWu0cgpVxTCsKEkTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAByfrVjiUgdAJeAAEAAAHJMA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIPE/pn3nyxMUptp3YnFgpZx75a+nWG3LD7E3Saod7sXGMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQggXXOf1LdUUsQJ3gp2H9gDSMhiQD/zX3hXXzh
# 2Tl2/YEwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# Acn61Y4lIHQCXgABAAAByTAiBCBLGLI4zWV3F5jZP8NaXN3MMvXjnRy2BkvxARRP
# xfD72jANBgkqhkiG9w0BAQsFAASCAgA8pwbypKgHl4hwQQvWKOBHPtqEK6xNiR4K
# +LAnrP9/0lbPf2gI9SRoW2jVZk5ZqzyZO0FhjrGgqGRvIiEVw8jav0iI5FJJ+XmX
# Ope+751hQHvpRG2tUvWlLB4sJ1ke/yrpVKrYp616ryh2UBe/7ElEpNmHywoMDHa/
# U/m+AMmqVOkN0TpF2M+iWtSH3O4wLPWZwimDZxK0sQoPaDUnVxLQF/r3jIhqDRUu
# nONcKF5ydajllWfFziXbvQRQWXJNVK4fUglYyfU40On72ZpeGmE3WC+We6wHI/La
# VwwqE5QYCdi06U4pIt64QvLZ6ZH98+fUz2tAm5cmikpCT2g3wRSZOE+1RzWIv7YJ
# A6lAV0lHwpZEzJT3GyjQt7Z43FbxWyuXs6Bw5+kSkMDBggwAL69kA7bz+kGUDYOu
# Y3Nl/QFNrgdKCXc9Np+1owU9082QO1Ulj7bFCZVHKkStNMGblox0tFYJgwvcCRn2
# 9yqPQLpgCw3lFu0zAsz9MFU7g5O/JaCdaxp4FK+Bi6IXFgpI+5It0GJqIBVaw0Fc
# 0F9jXWAnj5OCKV49EgkvvtAJ3FxF77cGm0TbTZNY5nB0S8EkGYrI0XtMSX7xgJLq
# 4ILDNKuVcqLMvucllbZCFP+bvdGeFNaqzY8TCrX33MZNAFhydS/TdnCxRaQ1sAEE
# Y6/fplWugw==
# SIG # End signature block
