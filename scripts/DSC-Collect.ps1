param( [string]$DataPath, [switch]$AcceptEula )

$version = "DSC-Collect (20230419)"
# by Gianni Bragante - gbrag@microsoft.com

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

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

$global:Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path
$resName = "DSC-Results-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)

if ($DataPath) {
  if (-not (Test-Path $DataPath)) {
    Write-Host "The folder $DataPath does not exist"
    exit
  }
  $global:resDir = $DataPath + "\" + $resName
} else {
  $global:resDir = $global:Root + "\" + $resName
}
New-Item -itemtype directory -path $global:resDir | Out-Null

$global:outfile = $global:resDir + "\script-output.txt"
$global:errfile = $global:resDir + "\script-errors.txt"

Import-Module ($global:Root + "\Collect-Commons.psm1") -Force -DisableNameChecking

Write-Log $version
if ($AcceptEula) {
  Write-Log "AcceptEula switch specified, silently continuing"
  $eulaAccepted = ShowEULAIfNeeded "DSC-Collect" 2
} else {
  $eulaAccepted = ShowEULAIfNeeded "DSC-Collect" 0
  if($eulaAccepted -ne "Yes")
   {
     Write-Log "EULA declined, exiting"
     exit
   }
 }
Write-Log "EULA accepted, continuing"

Write-Log "PowerShell version"
$PSVersionTable | Out-File -FilePath ($global:resDir + "\PSVersion.txt") -Append

if (Test-Path -Path "C:\Program Files\WindowsPowerShell\DscService\RegistrationKeys.txt") {
  Write-Log "Registration keys"
  Copy-Item "C:\Program Files\WindowsPowerShell\DscService\RegistrationKeys.txt" ($global:resDir + "\RegistrationKeys.txt")
}

Write-Log "Collecing the dumps of the WMIPrvSE process having dsccore.dll or dsctimer.dll loaded"
try {
  $list = Get-Process -Name "WmiPrvSe" -ErrorAction SilentlyContinue 2>>$global:errfile
}
catch {
  Write-Log "Can't find any running WMIPrvSE process"
}
if (($list | measure).count -gt 0) {
  foreach ($proc in $list)
  {
    #$prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {($_.ModuleName -eq "dsccore.dll") -or ($_.ModuleName -eq "dsctimer.dll") } 
    if ((Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "dsccore.dll" } | Measure).Count -gt 0) {
      Write-Log ("Found " + $proc.Name + "(" + $proc.id + ")")
      CreateProcDump $proc.id $global:resDir "WMIPrvSE-DSCCore"
    }
    if ((Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "dsctimer.dll" } | Measure).Count -gt 0) {
      Write-Log ("Found " + $proc.Name + "(" + $proc.id + ")")
      CreateProcDump $proc.id $global:resDir "WMIPrvSE-DSCTimer"
    }
  }
}

$DSCDb = "C:\Program Files\WindowsPowerShell\DscService\Devices.edb"
if (Test-Path -Path ($env:windir + "\System32\inetsrv\Config\ApplicationHost.config")) {
  Write-Log "IIS ApplicationHost.config"
  Copy-Item "C:\Windows\System32\inetsrv\Config\ApplicationHost.config" ($global:resDir + "\ApplicationHost.config")

  $doc = (Get-content ($env:windir + "\System32\inetsrv\Config\ApplicationHost.config")) -as [xml]
  $logdir = ($doc.configuration.'system.applicationHost'.log.ChildNodes[1].directory).Replace("%SystemDrive%", $env:SystemDrive)
  
  foreach ($site in $doc.configuration.'system.applicationHost'.sites.site) {
    Write-Log ("Copying web.config and logs for the website " + $site.name)
    $sitedir = $global:resDir + "\websites\" + $site.name
    New-Item -itemtype directory -path $sitedir | Out-Null
    write-host $site.name, $site.application.ChildNodes[0].physicalpath
    $path = ($site.application.ChildNodes[0].physicalpath).Replace("%SystemDrive%", $env:SystemDrive)
    if (Test-Path -Path ($path + "\web.config")) {
      Copy-Item -path ($path + "\web.config") -destination $sitedir -ErrorAction Continue 2>>$global:errfile

      $siteLogDir = ($logdir + "\W3SVC" + $site.id)
      $last = Get-ChildItem -path ($siteLogDir) | Sort CreationTime -Descending | Select Name -First 1 
      Copy-Item ($siteLogDir + "\" + $last.name) $sitedir -ErrorAction Continue 2>>$global:errfile

      if ($site.name -eq "PSDSCPullServer") {
        FileVersion -Filepath ($path + "\bin\Microsoft.Powershell.DesiredStateConfiguration.Service.dll") -Log $true
        # GetFileVersion ($path + "\bin\Microsoft.Powershell.DesiredStateConfiguration.Service.dll")
        $docDSC = (Get-content ($path + "\web.config")) -as [xml]
        foreach ($conf in $docDSC.configuration.appSettings.add) {
          if ($conf.key -eq "dbconnectionstr") {
            $DSCDb = $conf.value
            Write-Log ("DSC dbconnectionstr = " + $DSCDb )
          }
        }
      }
    }
  }
 }

if (Test-Path -Path "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config") {
  Write-Log "Globabl web.config"
  Copy-Item "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config" ($global:resDir + "\global-web.config")
}

$dir = $env:windir + "\system32\logfiles\HTTPERR"
if (Test-Path -path $dir) {
  $last = Get-ChildItem -path ($dir) | Sort CreationTime -Descending | Select Name -First 1 
  Copy-Item ($dir + "\" + $last.name) $global:resDir\httperr.log -ErrorAction Continue 2>>$global:errfile
}

Write-Log "DISM logs"
Compress-Archive -Path ($env:windir + "\Logs\DISM") -DestinationPath ($global:resDir + "\dism.zip")

Write-Log "CBS logs"
Compress-Archive -Path ($env:windir + "\Logs\CBS") -DestinationPath ($global:resDir + "\cbs.zip")

if (Test-Path -Path "C:\Program Files\WindowsPowerShell\DscService\Devices.edb") {
  $cmd = "cmd.exe /c esentutl.exe /y """ + $DSCDb +  """ /vssrec"
  Write-Log $cmd
  Invoke-Expression $cmd
  Move-Item .\Devices.edb $global:resDir
}

Write-Log "DSC Configuration"
Copy-Item "C:\Windows\System32\Configuration" -Recurse $global:resDir

if (Test-Path -Path "C:\WindowsAzure\Logs\WaAppAgent.log") {
  Write-Log "Windows Azure Guest Agent log"
  Copy-Item "C:\WindowsAzure\Logs\WaAppAgent.log" ($global:resDir + "\WaAppAgent.log")
}

if (Test-Path -Path "C:\WindowsAzure\Logs\Plugins\Microsoft.Powershell.DSC") {
  Write-Log "Azure DSC Extension Logs"
  Copy-Item "C:\WindowsAzure\Logs\Plugins\Microsoft.Powershell.DSC" -Recurse ($global:resDir + "\AzureDSCLogs")
}

if (Test-Path -Path "C:\Packages\Plugins\Microsoft.Powershell.DSC") {
  Write-Log "Azure DSC Extension Package"
  Copy-Item "C:\Packages\Plugins\Microsoft.Powershell.DSC" -Recurse ($global:resDir + "\AzureDSCPackage")
}

if (Test-Path -Path "C:\Windows\Temp\ScriptLog.log") {
  Write-Log "Windows Virtual Desktop log"
  Copy-Item "C:\Windows\Temp\ScriptLog.log" ($global:resDir + "\WVD-ScriptLog.log")
}

if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Azure\DSC") {
  Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure\DSC"
  $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure\DSC """+ $global:resDir + "\AzureDSC.reg.txt"" /y >>""" + $global:outfile + """ 2>>""" + $global:errfile + """"
  Invoke-Expression $cmd
}

if (Test-Path -Path "C:\Program Files\WindowsPowerShell\DscService\Configuration") {
  Write-Log "DSC Service Configuration"
  New-Item -itemtype directory -path ($global:resDir + "\DscService") | Out-Null
  Copy-Item "C:\Program Files\WindowsPowerShell\DscService\Configuration" -Recurse ($global:resDir + "\DscService")
}

Write-Log "Installed certificates"
Get-ChildItem Cert:\LocalMachine\My\ | Out-File -FilePath ($global:resDir + "\CertLocalMachineMy.txt")

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

Write-Log "Get-Module output"
Get-Module -ListAvailable | Out-File -FilePath ($global:resDir + "\Get-Module.txt")

Write-Log "Get-DscResource output"
Get-DscResource | Out-File -FilePath ($global:resDir + "\Get-DscResource.txt")

Write-Log "Get-DscLocalConfigurationManager output"
$lcm = Get-DscLocalConfigurationManager 
$lcm | Out-File -FilePath ($global:resDir + "\Get-DscLocalConfigurationManager.txt")
("ConfigurationDownloadManagers.serverURL = " + $lcm.ConfigurationDownloadManagers.serverURL) | Out-File -FilePath ($global:resDir + "\Get-DscLocalConfigurationManager.txt") -Append
("ReportManagers.serverURL = " + $lcm.ReportManagers.serverURL) | Out-File -FilePath ($global:resDir + "\Get-DscLocalConfigurationManager.txt") -Append

try {
  Write-Log "Get-DscConfiguration output"
  Get-DscConfiguration | Out-File -FilePath ($global:resDir + "\Get-DscConfiguration.txt")
} 
catch {
  Write-Log "Get-DscConfiguration failed, DSC not configured on this machine?"
}

Write-Log "Get-DscConfigurationStatus output"
Get-DscConfigurationStatus -all 2>>$global:errfile | Out-File -FilePath ($global:resDir + "\Get-DscConfigurationStatus.txt")

$dir = $env:windir + "\system32\inetsrv"
if (Test-Path -Path ($dir + "\appcmd.exe")) {
  $cmd = $dir + "\appcmd list wp >""" + $global:resDir + "\IIS-WorkerProcesses.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append  

  $lines = Get-Content ($global:resDir + "\IIS-WorkerProcesses.txt")
  foreach ($line in $lines) {
    $aLine = $line.Split("""")
    if ($aLine[2] -match "applicationPool:PSWS") {
      CreateProcDump $aLine[1] $global:resDir "W3WP"
    }
  }
}

Write-Log "Get-WinSystemLocale output"
"Get-WinSystemLocale" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-WinSystemLocale | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP"
$cmd = "reg export HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP """+ $global:resDir + "\HTTP.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting ipconfig /all output"
$cmd = "ipconfig /all >""" + $global:resDir + "\ipconfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Export-EventLog "Application"
Export-EventLog "System"
Export-EventLog "Microsoft-Windows-WMI-Activity/Operational"
Export-EventLog "Microsoft-Windows-DSC/Operational"
Export-EventLog "Microsoft-Windows-CAPI2/Operational"
Export-EventLog "Microsoft-Windows-Powershell-DesiredStateConfiguration-PullServer/Operational"
Export-EventLog "Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Operational"
Export-EventLog "Microsoft-Windows-ManagementOdataService/Operational"
Export-EventLog "Microsoft-Windows-PowerShell/Operational"
Export-EventLog "Microsoft-Windows-WinRM/Operational"

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
# MIInkgYJKoZIhvcNAQcCoIIngzCCJ38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAoPhUXbwmRuXCf
# YKddOGdxkA3tOdgoMrzNasNmMf3HQKCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXIwghluAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIP1G8ZBJd3xiYQHnl3mwNjIl
# U2fvVpKpFrCKXEzMVbcAMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAs8aGlUINDm/8HgVbEp0vbcD/m9LUeaa0LZptFe/3WXn3vFfepjin2hyg
# 5Am7ppiv1hXlg3EPczoM3FSY2XFuGMrPigcIokAG29pIfI6qoG+W16SEWOcq5XvK
# 9iK9/4QTI1oZFer+29ze8yDUu1FJ8PrELB0zEKZEIHXRHjcH7MHlO/y5ZsTYyqQ2
# f+TWyX+fSKAyvMS+P4r0tiideXFPyJHMnegjcNzUmvSNyug9HTfVT2l/bPgjS5tt
# luXg/Ur0jNgN03ttMqLWXT7eDjX5T+R9QMp2o1nNAc1hEUNcs6pMXLDffn5GxmMV
# wpKU+EnsTuueXLEFpEwK+HOxOo15+6GCFvwwghb4BgorBgEEAYI3AwMBMYIW6DCC
# FuQGCSqGSIb3DQEHAqCCFtUwghbRAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCAUTUIA9DSIn60kF9X1Drj9VXm6utHjdmh9wbbzVl3dfgIGZGzY6Lu4
# GBMyMDIzMDYwNjExNDU1Mi4zMzJaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4QTgyLUUz
# NEYtOUREQTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVMwggcMMIIE9KADAgECAhMzAAABwvp9hw5UU0ckAAEAAAHCMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEy
# OFoXDTI0MDIwMjE5MDEyOFowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhBODItRTM0Ri05RERBMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAtfEJvPKOSFn3petp9wco29/UoJmDDyHpmmpRruRVWBF3
# 7By0nvrszScOV/K+LvHWWWC4S9cme4P63EmNhxTN/k2CgPnIt/sDepyACSkya4uk
# qc1sT2I+0Uod0xjy9K2+jLH8UNb9vM3yH/vCYnaJSUqgtqZUly82pgYSB6tDeZIY
# cQoOhTI+M1HhRxmxt8RaAKZnDnXgLdkhnIYDJrRkQBpIgahtExtTuOkmVp2y8YCo
# FPaUhUD2JT6hPiDD7qD7A77PLpFzD2QFmNezT8aHHhKsVBuJMLPXZO1k14j0/k68
# DZGts1YBtGegXNkyvkXSgCCxt3Q8WF8laBXbDnhHaDLBhCOBaZQ8jqcFUx8ZJSXQ
# 8sbvEnmWFZmgM93B9P/JTFTF6qBVFMDd/V0PBbRQC2TctZH4bfv+jyWvZOeFz5yl
# tPLRxUqBjv4KHIaJgBhU2ntMw4H0hpm4B7s6LLxkTsjLsajjCJI8PiKi/mPKYERd
# mRyvFL8/YA/PdqkIwWWg2Tj5tyutGFtfVR+6GbcCVhijjy7l7otxa/wYVSX66Lo0
# alaThjc+uojVwH4psL+A1qvbWDB9swoKla20eZubw7fzCpFe6qs++G01sst1SaA0
# GGmzuQCd04Ue1eH3DFRDZPsN+aWvA455Qmd9ZJLGXuqnBo4BXwVxdWZNj6+b4P8C
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBRGsYh76V41aUCRXE9WvD++sIfGajAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQARdu3dCkcLLPfaJ3rR1M7D9jWHvneffkmXvFIJtqxHGWM1oqAh+bqxpI7HZz2M
# eNhh1Co+E9AabOgj94Sp1seXxdWISJ9lRGaAAWzA873aTB3/SjwuGqbqQuAvUzBF
# CO40UJ9anpavkpq/0nDqLb7XI5H+nsmjFyu8yqX1PMmnb4s1fbc/F30ijaASzqJ+
# p5rrgYWwDoMihM5bF0Y0riXihwE7eTShak/EwcxRmG3h+OT+Ox8KOLuLqwFFl1si
# TeQCp+YSt4J1tWXapqGJDlCbYr3Rz8+ryTS8CoZAU0vSHCOQcq12Th81p7QlHZv9
# cTRDhZg2TVyg8Gx3X6mkpNOXb56QUohI3Sn39WQJwjDn74J0aVYMai8mY6/WOurK
# MKEuSNhCiei0TK68vOY7sH0XEBWnRSbVefeStDo94UIUVTwd2HmBEfY8kfryp3Rl
# A9A4FvfUvDHMaF9BtvU/pK6d1CdKG29V0WN3uVzfYETJoRpjLYFGq0MvK6QVMmuN
# xk3bCRfj1acSWee14UGjglxWwvyOfNJe3pxcNFOd8Hhyp9d4AlQGVLNotaFvopgP
# LeJwUT3dl5VaAAhMwvIFmqwsffQy93morrprcnv74r5g3ejC39NYpFEoy+qmzLW1
# jFa1aXE2Xb/KZw2yawqldSp0Hu4VEkjGxFNc+AztIUWwmTCCB3EwggVZoAMCAQIC
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
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLKMIICMwIBATCB+KGB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046OEE4Mi1FMzRGLTlEREExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAMp1N1VLhPMvWXEoZfmF4apZlnRUoIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoKSM0MCIYDzIwMjMwNjA2MTExNTAwWhgPMjAyMzA2MDcxMTE1MDBaMHMw
# OQYKKwYBBAGEWQoEATErMCkwCgIFAOgpIzQCAQAwBgIBAAIBOjAHAgEAAgIS6jAK
# AgUA6Cp0tAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIB
# AAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAFZgOS2cxWNlQU+4
# EZz0CkCAdj8jOK0VCt616ZxB/RSkwQu1gYys+dyc/C+DeUyErTeHYowikr04gslf
# WRLPEkOfd4kBYS0BG1bbzPyjWQKTjE1Y98psjLFzKPK4MPJrAb6CPaY5/V26SQwW
# d/zAwsp4HwXLCdbQUdX51nHRNjacMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTACEzMAAAHC+n2HDlRTRyQAAQAAAcIwDQYJYIZIAWUD
# BAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0B
# CQQxIgQgOOK5B8YYvKxwMj4SZaJxRovUG2SSBk3N2Q+BFhD0UrUwgfoGCyqGSIb3
# DQEJEAIvMYHqMIHnMIHkMIG9BCDKk2Bbx+mwxXnuvQXlt5S6IRU5V7gF2Zo757by
# YYNQFjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB
# wvp9hw5UU0ckAAEAAAHCMCIEIDDBI//YST+Fp/fjuVy77UL0wSXXqmJxBSLupCWj
# Jxz9MA0GCSqGSIb3DQEBCwUABIICAIVA3QsRBcCEYCydoQaUI26OIm5mm2BpGXTK
# QLq4zW7Bvw7xNsZqZjyReXcKFeJxcwLnOv/ofSYXCUZMesoX3wXEttrVGkJUZTiU
# dLEFkULYI4rYh17rp4Eykro2NM4AeGKnNw09uMUHT80zSMGQ7JIk/jG4M4fcGp+n
# OPI6XXhKWFEfgN9mfnHf7mM7yrM3B1aRZLFb7xS9NoiP6sYMpqp83800TxZlOmlj
# gXSonoo7kw7nn4ONbF7n7PiVULJjF8QmCF+vqUmWGdI20c9uLgwrBcSg3XT22Adh
# 9p/1JKCbtLAVIunrc9N3WwVC8JLdoTs52PFkNuikDVyTgxSkCJKaIP+lIKDGTy3A
# S0SHqpjwQxmBS2gltg4Np59e2HDWOh7laadBVwlz9Ir7ndDoRVTeqPkw2W4czTH6
# yESYgT6xRomoFlQVDSQLVwAy/CiurT8sWWyWjhKxpraK/PAgXhWt/AvFPbBV3XoC
# /JJ6cpEuMdpMMYcpo9Vz5GUUhBR7ORLgBOElcdYArFiOa7JaRl27sC1ocm2JwNBV
# fRHwtBZt01IK9uAFN/ky2tzcsjLfw5CKzCiSXoNA0EzXRe8uJK1UEK1Jl5zxI/h7
# Ujbq79HveBSP61wVgARRISpUvbKGWGzLAKANmsBJxAgCrFmpTcz+VB763Zo3Cimx
# yJ2ix3Gj
# SIG # End signature block
