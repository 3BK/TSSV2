param( 
  [string]$DataPath,
  [switch]$AcceptEula,
  [switch]$NoDumps = $false
)

$global:Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path
Import-Module ($global:Root + "\Collect-Commons.psm1") -Force -DisableNameChecking
$toolName = "Print-Collect"
$version = $toolName + " 2021-Dec-08"
# maintained by Marius Porcolean (maporcol) using Gianni Bragante's (gbrag) framework

Deny-IfNotAdmin

# Initialize some global variables & output folder
$resName = "$($ToolName -replace "Collect","Results")-" + $env:computername + "-" + $(get-date -f yyyyMMdd_HHmmss)
# Check if a destination folder was explicitly requested
if ($DataPath) {
  if (-not (Test-Path $DataPath)) {
    $answer = Read-Host "The destination folder ${DataPath} does not exist. Do you want to create it now? y/n"
    if ($answer -eq 'y') {
      New-Item -ItemType "directory" -Path $DataPath -Force
    }
    else {
      exit
    }
  }
  $global:resDir = $DataPath + "\" + $resName
}
else {
  $global:resDir = $global:Root + "\" + $resName
}
New-Item -ItemType "directory" -Path $global:resDir | Out-Null

$global:outfile = $global:resDir + "\script-output.txt"
$global:errfile = $global:resDir + "\script-errors.txt"
$global:RdrOut = " >>""" + $global:outfile + """"
$global:RdrErr = " 2>>""" + $global:errfile + """"
# $fqdn = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
# $OSVer = ([environment]::OSVersion.Version.Major) + ([environment]::OSVersion.Version.Minor) / 10

Write-Log $version

# License Agreement
if ($AcceptEula) {
  Write-Log "AcceptEula switch specified, silently continuing"
  $eula = ShowEULAIfNeeded $ToolName 2
}
else {
  $eula = ShowEULAIfNeeded $ToolName 0
  if ($eula -ne "Yes") {
    Write-Log "EULA declined, exiting"
    exit
  }
}
Write-Log "EULA accepted, continuing"

# Collect dumps if not disabled
if ($NoDumps) {
  Write-Log "We have the NoDumps flag, skipping collection of process dumps."
}
else {
  Write-Log "Collecting dump of the Spooler service"
  $pidSpooler = FindServicePid "Spooler"
  if ($pidSpooler) {
    CreateProcDump $pidSpooler $global:resDir "spoolsv"
  }

  Write-Log "Collecing the dumps of splwow64 if they exist"
  $list = get-process -Name "splwow64" -ErrorAction SilentlyContinue 2>>$global:errfile
  if (($list | Measure-Object).count -gt 0) {
    foreach ($proc in $list) {
      Write-Log ("Found splwow64.exe with PID " + $proc.Id)
      CreateProcDump $proc.Id $global:resDir "splwow64-$($proc.Id)"
    }
  }
  else {
    Write-Log "No splwow64 process found"
  }

  Write-Log "Collecing the dumps of PrintIsolationHost.exe processes"
  $list = get-process -Name "PrintIsolationHost.exe" -ErrorAction SilentlyContinue 2>>$global:errfile
  if (($list | Measure-Object).count -gt 0) {
    foreach ($proc in $list) {
      Write-Log ("Found PrintIsolationHost.exe with PID " + $proc.Id)
      CreateProcDump $proc.Id $global:resDir "PrintIsolationHost-$($proc.Id)"
    }
  }
  else {
    Write-Log "No PrintIsolationHost.exe process found"
  }
}

# Export relevant User registry settings
Export-RegistryKey -KeyPath "HKCU:\Printers" -DestinationFile "User-printer-connections.reg.txt"
Export-RegistryKey -KeyPath "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Devices" -DestinationFile "User-devices.reg.txt"
Export-RegistryKey -KeyPath "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\PrinterPorts" -DestinationFile "User-printer-ports.reg.txt"

# Export relevant Machine registry settings
Export-RegistryKey -KeyPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print" -DestinationFile "Print-main.reg.txt"
Export-RegistryKey -KeyPath "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -DestinationFile "Print-policies.reg.txt"
Export-RegistryKey -KeyPath "HKLM:\System\CurrentControlSet\Control\Print" -DestinationFile "Print-service.reg.txt"
Export-RegistryKey -KeyPath "HKLM:\System\CurrentControlSet\Enum\USBPRINT" -DestinationFile "Print-enum-usbprint.reg.txt"
Export-RegistryKey -KeyPath "HKLM:\SYSTEM\CurrentControlSet\Enum\SWD\PRINTENUM" -DestinationFile "Print-enum-swd-printenum.reg.txt"

# Get any KIR overrides configured on this device
Export-RegistryKey -KeyPath "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides" -DestinationFile "KIR-Overrides.reg.txt"

# Export relevant event logs
Export-EventLog -LogName "Application"
Export-EventLog -LogName "System"
Export-EventLog -LogName "Microsoft-Windows-PrintService/Operational"
Export-EventLog -LogName "Microsoft-Windows-PrintService/Admin"
Export-EventLog -LogName "Microsoft-Windows-DeviceSetupManager/Admin"
Export-EventLog -LogName "Microsoft-Windows-DeviceSetupManager/Operational"

# Get some additional information (Spooler service config, setupapi, netstat, ipconfig, gpresult)
Write-Log "Exporting setupapi.dev.log"
Copy-Item "C:\Windows\INF\setupapi.dev.log" -Destination $global:resDir
Invoke-CustomCommand -Command "sc.exe queryex spooler" -DestinationFile "Spooler_ServiceConfig.txt"
Invoke-CustomCommand -Command "netstat -anob" -DestinationFile "netstat.txt"
Invoke-CustomCommand -Command "ipconfig /all" -DestinationFile "ipconfig.txt"
# Notice that for gpresult /h we don't specify a Destinationfile, because it has a dedicated output file
# no need to redirect the console output stream, which in this case doesn't work anyway
Invoke-CustomCommand -Command "gpresult /h ""${global:resDir}\gpresult.html"""
Invoke-CustomCommand -Command "gpresult /r" -DestinationFile "gpresult.txt"
Invoke-CustomCommand -Command "driverquery /v" -DestinationFile "drivers.txt"

# Check version of some relevant print-related files
FileVersion -Filepath ($env:windir + "\System32\localspl.dll") -Log $true
FileVersion -Filepath ($env:windir + "\system32\spoolsv.exe") -Log $true
FileVersion -Filepath ($env:windir + "\system32\win32spl.dll") -Log $true
FileVersion -Filepath ($env:windir + "\system32\spoolss.dll") -Log $true 
FileVersion -Filepath ($env:windir + "\system32\PrintIsolationProxy.dll") -Log $true 
FileVersion -Filepath ($env:windir + "\system32\winspool.drv") -Log $true 

# Get running processes
Write-Log "Collecting details about running processes"
$proc = ExecQuery -Namespace "root\cimv2" -Query "select Name, CreationDate, ProcessId, ParentProcessId, WorkingSetSize, UserModeTime, KernelModeTime, ThreadCount, HandleCount, CommandLine, ExecutablePath from Win32_Process"
if ($PSVersionTable.psversion.ToString() -ge "3.0") {
  $StartTime = @{e = { $_.CreationDate.ToString("yyyyMMdd HH:mm:ss") }; n = "Start time" }
  $Owner = @{N = "User"; E = { (GetOwnerCim($_)) } }
}
else {
  $StartTime = @{n = 'StartTime'; e = { $_.ConvertToDateTime($_.CreationDate) } }
  $Owner = @{N = "User"; E = { (GetOwnerWmi($_)) } }
}

if ($proc) {
  $proc | Sort-Object Name |
  Format-Table -AutoSize -property @{e = { $_.ProcessId }; Label = "PID" }, @{e = { $_.ParentProcessId }; n = "Parent" }, Name,
  @{N = "WorkingSet"; E = { "{0:N0}" -f ($_.WorkingSetSize / 1kb) }; a = "right" },
  @{e = { [DateTime]::FromFileTimeUtc($_.UserModeTime).ToString("HH:mm:ss") }; n = "UserTime" }, @{e = { [DateTime]::FromFileTimeUtc($_.KernelModeTime).ToString("HH:mm:ss") }; n = "KernelTime" },
  @{N = "Threads"; E = { $_.ThreadCount } }, @{N = "Handles"; E = { ($_.HandleCount) } }, $StartTime, $Owner, CommandLine |
  Out-String -Width 500 | Out-File -FilePath ($global:resDir + "\processes.txt")

  Write-Log "Retrieving file version of running binaries"
  $binlist = $proc | Group-Object -Property ExecutablePath
  foreach ($file in $binlist) {
    if ($file.Name) {
      FileVersion -Filepath ($file.name) -Log $true
    }
  }

  Write-Log "Collecting services details"
  $svc = ExecQuery -NameSpace "root\cimv2" -Query "select  ProcessId, DisplayName, StartMode,State, Name, PathName, StartName from Win32_Service"

  if ($svc) {
    $svc | Sort-Object DisplayName | Format-Table -AutoSize -Property ProcessId, DisplayName, StartMode, State, Name, PathName, StartName |
    Out-String -Width 400 | Out-File -FilePath ($global:resDir + "\services.txt")
  }

  CollectSystemInfoWMI
  ExecQuery -Namespace "root\cimv2" -Query "select * from Win32_Product" | Sort-Object Name | Format-Table -AutoSize -Property Name, Version, Vendor, InstallDate | Out-String -Width 400 | Out-File -FilePath ($global:resDir + "\products.txt")
}
else {
  $proc = Get-Process | Where-Object { $_.Name -ne "Idle" }
  $proc | Format-Table -AutoSize -property id, name, @{N = "WorkingSet"; E = { "{0:N0}" -f ($_.workingset / 1kb) }; a = "right" },
  @{N = "VM Size"; E = { "{0:N0}" -f ($_.VirtualMemorySize / 1kb) }; a = "right" },
  @{N = "Proc time"; E = { ($_.TotalProcessorTime.ToString().substring(0, 8)) } }, @{N = "Threads"; E = { $_.threads.count } },
  @{N = "Handles"; E = { ($_.HandleCount) } }, StartTime, Path | 
  Out-String -Width 300 | Out-File -FilePath ($global:resDir + "\processes.txt")
  CollectSystemInfoNoWMI
  Write-Log "Exiting since WMI is not working"
}

Write-Log "Collecting the list of installed hotfixes"
Get-HotFix -ErrorAction SilentlyContinue 2>>$global:errfile | Sort-Object -Property InstalledOn -ErrorAction SilentlyContinue | Out-File $global:resDir\hotfixes.txt
# SIG # Begin signature block
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAKLAuUo0eP1Ee5
# GvIm+aHkSHslQdLi4GOj0j8Bbaus7qCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEICyLFDb83m/tEc28S/D975fg
# YmDVwF9UBH5W5JhjAmhxMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAjTyGs2OsU7lPjeRDa251kAnwMg6+VlxfPC+82lpjtQFT45iVGVVGO1ZW
# DqkZIGJ1U/uJGj6x4/lzMQNZ0l12W2kDGgxnbgdz5GzM77kYAP5H0Tl3iGRksIs9
# XuoPj11ai9IQMZFSqk70BwCo0/CKXlh1NFz0YcnClQHvCzM18u0XgPaD8y29p4PA
# 0RV/gSuSAM4KEh0dACsJLZ/EE7Mlbg9dARkzfFgsNISEB95uZgMCcS5y7Dohyvt/
# bjqowmYTsBYewbeWqFYfzwnginqDyqVEw9rTR62tAo7xvPhSTY0mfeLNpjSUekvP
# SRqHaPoMtoxTdYdDIeSoGlEeoCj7f6GCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCC
# FuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCBesU5eLlGn0a6JqgOSbL6ZNNaEoHMqD0E029C7Ep/CxAIGZGzU9N5F
# GBMyMDIzMDYwNjExNDU1Mi43MDhaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoxMkJDLUUz
# QUUtNzRFQjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVQwggcMMIIE9KADAgECAhMzAAAByk/Cs+0DDRhsAAEAAAHKMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDE0
# MFoXDTI0MDIwMjE5MDE0MFowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjEyQkMtRTNBRS03NEVCMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAwwGcq9j50rWEkcLSlGZLweUVfxXRaUjiPsyaNVxPdMRs
# 3CVe58siu/EkaVt7t7PNTPko/s8lNtusAeLEnzki44yxk2c9ekm8E1SQ2YV9b8/L
# OxfKapZ8tVlPyxw6DmFzNFQjifVm8EiZ7lFRoY448vpcbBD18qjYNF/2Z3SQchcs
# dV1N9Y6V2WGl55VmLqFRX5+dptdjreBXzi3WW9TsoCEWcYCBK5wYgS9tT2SSSTza
# e3jmdw40g+LOIyrVPF2DozkStv6JBDPvwahXWpKGpO7rHrKF+o7ECN/ViQFMZyp/
# vxePiUABDNqzEUI8s7klYmeHXvjeQOq/CM3C/Y8bj3fJObnZH7eAXvRDnxT8R6W/
# uD1mGUJvv9M9BMu3nhKpKmSxzzO5LtcMEh2tMXxhMGGNMUP3DOEK3X+2/LD1Z03u
# sJTk5pHNoH/gDIvbp787Cw40tsApiAvtrHYwub0TqIv8Zy62l8n8s/Mv/P764CTq
# rxcXzalBHh+Xy4XPjmadnPkZJycp3Kczbkg9QbvJp0H/0FswHS+efFofpDNJwLh1
# hs/aMi1K/ozEv7/WLIPsDgK16fU/axybqMKk0NOxgelUjAYKl4wU0Y6Q4q9N/9Pw
# AS0csifQhY1ooQfAI0iDCCSEATslD8bTO0tRtqdcIdavOReqzoPdvAv3Dr1XXQ8C
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBT6x/6lS4ESQ8KZhd0RgU7RYXM8fzAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQDY0HkqCS3KuKefFX8/rm/dtD9066dKEleNqriwZqsM4Ym8Ew4QiqOqO7mWoYYY
# 4K5y8eXSOHKNXOfpO6RbaYj8jCOcJAB5tqLl5hiMgaMbAVLrl1hlix9sloO45LON
# 0JphKva3D6AVKA7P78mA9iRHZYUVrRiyfvQjWxmUnxhis8fom92+/RHcEZ1Dh5+p
# 4gzeeL84Yl00Wyq9EcgBKKfgq0lCjWNSq1AUG1sELlgXOSvKZ4/lXXH+MfhcHe91
# WLIaZkS/Hu9wdTT6I14BC97yhDsZWXAl0IJ801I6UtEFpCsTeOyZBJ7CF0rf5lxJ
# 8tE9ojNsyqXJKuwVn0ewCMkZqz/cEwv9FEx8QmsZ0ZNodTtsl+V9dZm+eUrMKZk6
# PKsKArtQ+jHkfVsHgKODloelpOmHqgX7UbO0NVnIlpP55gQTqV76vU7wRXpUfz7K
# hE3BZXNgwG05dRnCXDwrhhYz+Itbzs1K1R8I4YMDJjW90ASCg9Jf+xygRKZGKHjo
# 2Bs2XyaKuN1P6FFCIVXN7KgHl/bZiakGq7k5TQ4OXK5xkhCHhjdgHuxj3hK5AaOy
# +GXxO/jbyqGRqeSxf+TTPuWhDWurIo33RMDGe5DbImjcbcj6dVhQevqHClR1OHSf
# r+8m1hWRJGlC1atcOWKajArwOURqJSVlThwVgIyzGNmjzjCCB3EwggVZoAMCAQIC
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
# U046MTJCQy1FM0FFLTc0RUIxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAKOO55cMT4syPP6nClg2IWfajMqkoIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoKR9BMCIYDzIwMjMwNjA2MTA1ODA5WhgPMjAyMzA2MDcxMDU4MDlaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOgpH0ECAQAwBwIBAAICIy4wBwIBAAICEgsw
# CgIFAOgqcMECAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQDRNNjjGjEYz32T
# Ofh5I8sHa4qiu6NLwBftfIOCl5LP0wcBDTmCfr4dyfjpZoCeC1Ojb6nddHWIbWx5
# AudZnt9er8THVBY9u32a3hX3m/kD1U7gsn6w0mfiFZkyhm8mRDkGJL3wv/bTgpgf
# ic5pFdJGik5HUou4egx20B1FopXkqDGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAByk/Cs+0DDRhsAAEAAAHKMA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIKdHf3VdI1nC5feEe3SjPnW31rAiuQ9+FGhDkrUn6k+sMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQgEz0b85vrVU2slZAk4jt1SDEk6IzZAwVCoWwF
# 3KzcGuAwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AcpPwrPtAw0YbAABAAAByjAiBCBhxfTvPeeoGFiWVKmd5xKcdHVcjRKYrLUlkh/s
# KecATzANBgkqhkiG9w0BAQsFAASCAgBc4/FHgor6Ho4fldhSZj+q3QAIypQCJDwg
# A4XCuGOBdMf+V3eQ2bN1O6retDa6FTamIfLMf0O1fOVEnWwKj96cJ/xr0Kfjz7kZ
# udLAuuuPK+oqkQC+bkZ8UWwHiZHhYNJOeRd7etGPKffVYU19Tn0hAgxAiEE74CKh
# qq8+zUFp48WnLTjGMkKtv2ySE98Ohq/k1egPpg2OTQy5qKXpEPjfhniBdhOFZtks
# DE/4qcYv40ZpMjX/cc1mFRK8/DyJ+W8/XicHFmkoadcYNeFJLspuPS3qHZUp09UL
# f/ndSWOMg3e45wbt+CdERvFzVvt4EAqsQbNQYblVbt6u281QuWQ/n0Z+yd5DV7Nw
# rdR+ZGbvAy9M4JE7llY1sNY9HOBL1Ajbz/hD6OTHyjxSiVddQby6zrDHK+otY/cD
# s2Y+zH1PlfZEJFUAffcy4114Z0zeoEVWQgWL0AzdzENerCyP5MBusmqQiCbXUyfi
# ppS3Z0/EM108M6iqGLgtzeKs0DQcjv52Rw4fMqPOikohRdarUxvl1XO2wbe0Hone
# 8bzJEsS3TEntyn+6n6EcmN+q7PbNO8FRpxnakIJvVBV7l0uW8EsJSRirfGiUgdUG
# MAHUoSsktkZ4EuwxMDtH9ezZ8dOfNO28lbiflj6sy5ztLBCBD4g3lZL6csY1Lddl
# J59k1Rfunw==
# SIG # End signature block
