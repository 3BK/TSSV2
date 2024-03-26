param( [string]$DataPath, `
       [switch]$AcceptEula, `
       [switch]$Logs, `
       [switch]$Trace, `
       [string]$StartAt, `
       [string]$Duration
     )

$version = "Sched-Collect (20230515)"
# by Gianni Bragante - gbrag@microsoft.com

Function SchedTraceCapture {
  if ($DateStart) {
    $diff = New-TimeSpan -Start (Get-Date) -End $DateStart # Recalculating the difference because the user may have been taking time to read the EULA
    if ($diff.TotalSeconds -lt 0) {
      $waitSeconds = 0
    } else {
      $waitSeconds = [int]$diff.TotalSeconds
    }
    Write-Log ("Waiting " + $waitSeconds + " seconds until $DateStart")
    Start-Sleep -Seconds $waitSeconds
  }

  Invoke-CustomCommand ("logman create trace 'Sched-Trace' -ow -o '" + $TracesDir + "Sched-Trace-$env:COMPUTERNAME.etl" + "' -p '{6A187A25-2325-45F4-A928-B554329EBD51}' 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets")

  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{A7C8D6F2-1088-484B-A516-1AE0C3BF8216}' 0xffffffffffffffff 0xff -ets" # SchedWmiGuid
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{10FF35F4-901F-493F-B272-67AFB81008D4}' 0xffffffffffffffff 0xff -ets" # Microsoft.Windows.TaskScheduler
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{1D665082-C852-4AB0-A1B2-C26488454C41}' 0xffffffffffffffff 0xff -ets" # UBPM
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{047311A9-FA52-4A68-A1E4-4E289FBB8D17}' 0xffffffffffffffff 0xff -ets" # JobCtlGuid
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-TaskScheduler
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{42695762-EA50-497A-9068-5CBBB35E0B95}' 0xffffffffffffffff 0xff -ets" # Windows Notification Facility Provider
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{0657ADC1-9AE8-4E18-932D-E6079CDA5AB3}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-TimeBroker
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{E8109B99-3A2C-4961-AA83-D1A7A148ADA8}' 0xffffffffffffffff 0xff -ets" # BrokerCommon
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{19043218-3029-4BE2-A6C1-B6763CECB3CC}' 0xffffffffffffffff 0xff -ets" # EventAggregation
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{077E5C98-2EF4-41D6-937B-465A791C682E}' 0xffffffffffffffff 0xff -ets" # DAB/Desktop Activity Broker
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{B6BFCC79-A3AF-4089-8D4D-0EECB1B80779}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-SystemEventsBroker
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{E6835967-E0D2-41FB-BCEC-58387404E25A}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-BrokerInfrastructure

  Write-Log "Trace capture started"
  if ($Duration) {
    Write-Log ("The capture will be stopped in " + $durSec + " seconds")
    Start-Sleep $durSec
  } else {
    read-host "Press ENTER to stop the capture"
  }
  Invoke-CustomCommand "logman stop 'Sched-Trace' -ets"  
  Invoke-CustomCommand "tasklist /svc" -DestinationFile "Traces\tasklist-$env:COMPUTERNAME.txt"
}

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

$global:Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path
$resName = "Sched-Results-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)

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
    Write-Host "$version, a data collection tool for Task Scheduler troubleshooting"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "Sched-Collect -Logs"
    Write-Host "  Collects dumps, logs, registry keys, command outputs"
    Write-Host ""
    Write-Host "Sched-Collect -Trace [-StartAt <YYYYMMDD-HHMMSS>] [-Duration <seconds>]"
    Write-Host "  Collects live trace"
    Write-Host ""
    Write-Host "Sched-Collect -Logs -Trace"
    Write-Host "  Collects live trace then -Logs data"
    Write-Host ""
    Write-Host "Parameters for -Trace"
    Write-Host "  -StartAt : Will start the trace at the specified date/time"
    Write-Host "  -Duration : Stops the trace after the specified numner of seconds"
    exit
}

if ($Trace -and $StartAt) {
  try {
    $DateStart = Get-Date -Year $StartAt.Substring(0,4) -Month $StartAt.Substring(4,2) -Day $StartAt.Substring(6,2) -Hour $StartAt.Substring(9,2) -Minute $StartAt.Substring(11,2) -Second $StartAt.Substring(13,2)
    Write-Host $DateStart
  }
  catch {
    Write-Host "Invalid date $StartAt"
    exit
  }
  $diff = New-TimeSpan -Start (Get-Date) -End $DateStart
  if ($diff.TotalSeconds -lt 0) {
    Write-Host "The specified date $DateStart is in the past"
    exit
  }
}

if ($Trace -and $Duration) {
  try {
    $durSec = [int]$Duration
  }
  catch {
    Write-Host "Invalid value for duration : $duration"
    exit
  }
  if ($durSec -lt 0) {
    Write-Host "Specified value for duration is less than 0"
    exit
  }
}

New-Item -itemtype directory -path $global:resDir | Out-Null

$global:outfile = $global:resDir + "\script-output.txt"
$global:errfile = $global:resDir + "\script-errors.txt"

Write-Log $version
if ($AcceptEula) {
  Write-Log "AcceptEula switch specified, silently continuing"
  $eulaAccepted = ShowEULAIfNeeded "Sched-Collect" 2
} else {
  $eulaAccepted = ShowEULAIfNeeded "Sched-Collect" 0
  if($eulaAccepted -ne "Yes") {
    Write-Log "EULA declined, exiting"
    exit
  }
}
Write-Log "EULA accepted, continuing"

if ($Trace) {
  $TracesDir = $global:resDir + "\Traces\"
  New-Item -itemtype directory -path $TracesDir | Out-Null
  SchedTraceCapture
  if (-not $Logs) {
    exit
  }
}

$pidsvc = (ExecQuery -Namespace "root\cimv2" -Query "select ProcessID from win32_service where Name='Schedule'").ProcessId
if ($pidsvc) {
  Write-Log "Collecting dump of the svchost process hosting the Schedule service"
  CreateProcDump $pidsvc $global:resDir "scvhost-Schedule"
} else {
  Write-Log "Schedule service PID not found"
}

$pidsvc = (ExecQuery -Namespace "root\cimv2" -Query "select ProcessID from win32_service where Name='SystemEventsBroker'").ProcessId
if ($pidsvc) {
  Write-Log "Collecting dump of the svchost process hosting the System Events Broker service"
  CreateProcDump $pidsvc $global:resDir "scvhost-SystemEventsBroker"
} else {
  Write-Log "System Events Broker service PID not found"
}

$tasks = Get-ScheduledTask
$tasks | Out-File -FilePath ($global:resDir + "\Tasks.txt" )

Write-Log "Copying C:\Windows\Tasks"
Copy-Item "C:\Windows\Tasks" -Recurse ($global:resDir + "\Windows-Tasks")

Write-Log "Copying C:\Windows\System32\Tasks"
Copy-Item "C:\Windows\System32\Tasks" -Recurse ($global:resDir + "\System32-Tasks")

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule"
$cmd = "reg export ""HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule"" """+ $global:resDir + "\Schedule.reg.txt"" /y >>""" + $global:outfile + """ 2>>""" + $global:errfile + """"
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications\Data"
$cmd = "reg export ""HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications\Data"" """+ $global:resDir + "\NotificationsData.reg.txt"" /y >>""" + $global:outfile + """ 2>>""" + $global:errfile + """"
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State"
$cmd = "reg export ""HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State"" """+ $global:resDir + "\SetupState.reg.txt"" /y >>""" + $global:outfile + """ 2>>""" + $global:errfile + """"
Invoke-Expression $cmd

ExpRegFeatureManagement

Invoke-CustomCommand -Command "WHOAMI /all" -DestinationFile "WHOAMI.txt"
Invoke-CustomCommand -Command "cmdkey /list" -DestinationFile "cmdkeyList.txt"

Write-Log "Exporting Application log"
$cmd = "wevtutil epl Application """+ $global:resDir + "\" + $env:computername + "-Application.evtx"" >>""" + $global:outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "Application"

Write-Log "Exporting System log"
$cmd = "wevtutil epl System """+ $global:resDir + "\" + $env:computername + "-System.evtx"" >>""" + $global:outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "System"

Write-Log "Exporting TaskScheduler/Maintenance log"
$cmd = "wevtutil epl Microsoft-Windows-TaskScheduler/Maintenance """+ $global:resDir + "\" + $env:computername + "-TaskScheduler-Maintenance.evtx"" >>""" + $global:outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "TaskScheduler-Maintenance"

Write-Log "Exporting TaskScheduler/Operational log"
$cmd = "wevtutil epl Microsoft-Windows-TaskScheduler/Operational """+ $global:resDir + "\" + $env:computername + "-TaskScheduler-Operational.evtx"" >>""" + $global:outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "TaskScheduler-Operational"

Write-Log "Exporting netstat output"
$cmd = "netstat -anob >""" + $global:resDir + "\netstat.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Exporting ipconfig /all output"
$cmd = "ipconfig /all >""" + $global:resDir + "\ipconfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Exporting service configuration"
$cmd = "sc.exe queryex Schedule >>""" + $global:resDir + "\ScheduleServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

$cmd = "sc.exe qc Schedule >>""" + $global:resDir + "\ScheduleServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

$cmd = "sc.exe enumdepend Schedule 3000 >>""" + $global:resDir + "\ScheduleServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

$cmd = "sc.exe sdshow Schedule >>""" + $global:resDir + "\ScheduleServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Collecting details about running processes"
if (ListProcsAndSvcs) {
  CollectSystemInfoWMI
  ExecQuery -Namespace "root\cimv2" -Query "select * from Win32_Product" | Sort-Object Name | Format-Table -AutoSize -Property Name, Version, Vendor, InstallDate | Out-String -Width 400 | Out-File -FilePath ($global:resDir + "\products.txt")

  Write-Log "Collecting the list of installed hotfixes"
  Get-HotFix -ErrorAction SilentlyContinue 2>>$global:errfile | Sort-Object -Property InstalledOn | Out-File $global:resDir\hotfixes.txt

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


# SIG # Begin signature block
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAAqz1PDpp5XU4+
# 1oaKeu+AH2KJWvDd8pYQX9l4NVkHP6CCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEID3RT/wGq5SVWySmTsKONNdn
# +qFBqGM8Hrn/Hn2HlYSTMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEADZrhvr2Ih0jSlypUsoMLQZzPVuIupIj1T9OPpv1vs4chJGWx2tYh7P07
# nupwtkd9dmNW1FF0Pq5Btofk0+vUCJ96sK216oQWIjRh/eE4/Xk9lI8AGT/E2mFh
# LTAgr6RUDJfBhi2JeFORlPZdPrQXVcMZ20xGxBiTQaPvNfZPRjdsp9qiAxVJuYi6
# mcKldzKzc0QjxnoVjADNef7FdJLj8MZa/AhQwg/Lf6Ayveial4Re4hjZ2Q2NxCfE
# /pDyX1CA6Wy1S3NRRNtg6UvmvJVkD2UYcgKUMXAkcaoNbPTBBSKbmXWwA/EgG1HM
# N4kwnSQFUvVwMdM4c4RE3AnCbte0iqGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCC
# FuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCUhgmwKY14081z8zYonsx1Hq364Djr5HkGPiKlvxPWeQIGZGzaWyF7
# GBMyMDIzMDYwNjExNDU1MC44NDJaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpFQUNFLUUz
# MTYtQzkxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVQwggcMMIIE9KADAgECAhMzAAABw4tv00i/DpFdAAEAAAHDMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEy
# OVoXDTI0MDIwMjE5MDEyOVowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkVBQ0UtRTMxNi1DOTFEMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAu+u86s3R/q+ikos80aD42Ym21NDOZtldNRxMFUxm4o9k
# VWkSh2c8jOCxJXwV2KFodCTxpGQs9jy5nUI+Lq/bt0HWtSYPMPPtet420gzwM1Es
# R26kbpwlBHxFY4hk3y3AH+1YKf9bhvPs7kPbXbH7gdaciteB+F7FoORt9e0D/dsB
# eG80GZAF2y6LWAj6C2mMqlafXkwbfTyQanuX65Yu+xMpyJ1fAREpuR766rePrqlE
# 0KaaeD0nqOgGrTkSZeCMDPH6OtJ00jXMwbIDyH7l4fYReIsTfzN5Gf3Uairsjea+
# KFy22lU8elnIXjoeyx3pcesH+q5arY1c6HPfeSnkeMok/gxnB7P1Mjt7I9EI9thQ
# tMvy/1SUmLG12rBR/DfheE/VJpcm/TYeoV11NfQQnl/jBbPbSRBp0HGqTIcWDpY6
# MgSdBoQET1DvpE4PX4sndNGc1wGyg45pH62ZMfUF/CzGZ7iV637RtnQFXDzTxoSE
# EkdXMdWDJG+jjxoC16lRk1xFnfkA4uoma4mKso7qvE6d27+K6yzISWQ7TjutYLKJ
# nSzNvfiNiuyv/0xxCASSARvOQ3v9cegvM/pnuU9c6s+4gmK3+5jhcvnWGQqJE0tp
# YHmk3bmmBL1gHm9TjBJz5m/8rvHM3Rw3OUhV4/wmAL32KmPR5Ubb4ww5HNGiuY0C
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBQcGL7N2NdvAaK8TcLrxMTsa8aB1jAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQDd8qZbHBqdBFRDxGGwDollnRyd0WmUnjqoP+5QCH4vMPBt4umHVhJuyeRkDELk
# TWZuWqK3U1z2HnGatbnETcHUlywlH+3I7R7fU0zKYw2PLA+VawCcrnsICgE3242E
# sEC/Z0YU740NJ/xbuzrGtTEtUIiQvr2ACPJyhsPote8ItTf4uNW4Mbo1QP0tjcBK
# CgEezIC4DYUM0BYCWCmeZmNwAlxfpTliOFEKB9UaSqHSs51cH8JY0gqL3LwI9LYf
# jEO77++HY/nMqXCMi9ihUKoIp2Tfjfzdm5Ng5V+yw8+wXl29RcW4Q4CvHntNfKxT
# 9oQ3J7YBQQEHWJPg8TNR9w4B82FzmrDd8sL6ETvGux5hFcwmF+Q2rT5Ma8dYUSdC
# Sg/ihoEYUGJZnZL9nyDp1snflSVX7FpLyALzDDlHBW1CJhYVffJRoqz1D4kRooqR
# BNRaMFMPingywwbEghMheJKNoda7AGgq+1HH1afRlE+9qYW9FKMezxeQmf8gcuAu
# hr9IAXyaF9DF0PJ5f4uhzOSvIC1BkJtzF6op45UYaI7V+9X8dcwXbZJnIIAH1cjV
# O8KEChxKIkpk4Qgy0PocgUwaGWqmLWRu1hQ1WJWnQXvvBYeYDGWbj/PtSlywv6m8
# mujLepfMvJcU25KWklSP2FuNx6aOVfeje+pgbwIQIVQ1nTCCB3EwggVZoAMCAQIC
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
# U046RUFDRS1FMzE2LUM5MUQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAPEdL+Ps+h03e+SLXdGzuY7tLu7OoIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoKSSoMCIYDzIwMjMwNjA2MTEyMTEyWhgPMjAyMzA2MDcxMTIxMTJaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOgpJKgCAQAwBwIBAAICIvIwBwIBAAICErMw
# CgIFAOgqdigCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQBp8ZzZpk9oKL9m
# iFQYhKcHDClbBTgaRngybDpfoZfUJ7nlT4q8j64IhTvQsVt6LyhnStwjVhBSZy9E
# hbU12qqtfEOWumv1r8Ch3vOGoYCELmaJz1dqh4TrgoG4Rra20vXJ4VybGGSmT30D
# q73BAnV530E+bJ0NPdZUQu//N/MAFzGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABw4tv00i/DpFdAAEAAAHDMA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIH8jmqS+QbCkb7Vm9eHLVeLq4VfB1XD9gRjdWqpxA6jGMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQg0vtTm2+SSerh1KiAkwrJTALxTfJotlPcDZ2Z
# Sn78KkkwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AcOLb9NIvw6RXQABAAABwzAiBCACyaGC+OQSu+v+yoFUp//mVUSR2QV28khiB4fX
# zZIuszANBgkqhkiG9w0BAQsFAASCAgAFKGMBOmYJ1sLguRBVIYOHV0Ul/z5yNxsR
# M5ZatTLfzCOBHK38sx9F2YjKd2YsvLH2gYov8rxircGU/wKsHavGzAi8itKQGzNi
# qOVQcNpp/79oyuR2bCiI0h9pTKwszNqny0Zfgj9bi+lt+WlZm4UTlTuQTfMt9Ve+
# giWHJpVHrjXHNc41GRqGYWZFFdFki+e+qnY7psa08VWwGUaNoWuhWeNzZVVLuyVQ
# /2Z0EFbWr1FLRUKnHDOWGXkUcMbkjuE1qDZS+lYxYa+OBf/hul8XR1WsnqvjnexU
# OQWZx0k6zThXW0h4spNMVU8jdXWfNLjpssNcvPSRkUvlMWHt6mkxN2rb/b7PMqCa
# 9jZn0zDRWUhSJiUszfIIS1fNIvwkeM7dc88qC1LrIUigF1gGL5AlN4ltXX2q+A2D
# sZIFBR9AKG1fXVZsQohQHdtl79EOZ3iUkEGyreffg2wuWt0U8g2vG+zvabQkX7ct
# PD0tVZwx3vrqGt3vfXLPzaNWmzqQP4iBaTu2x1aWMwMUyPlgQ61n4YMBQd7aYrPG
# tVic7YU/UmdVTTfP9KV3KRje1MkBPUHnJBvdfXptOQmwtzdL5H+AZ7fhKrgHqU5I
# zVUEYpbIlMA7+dqUSlT2pegED1tQbjA717JABSsU6iqKLKAD3Qq2FK/bdkiqnH/t
# xZCao06chQ==
# SIG # End signature block
