# GetSmsLogs.psm1 https://github.com/nedpyle/storagemigrationservicehelper
# https://raw.githubusercontent.com/nedpyle/storagemigrationservicehelper/master/StorageMigrationServiceHelper.psm1
# Date: Jun 15, 2020

# Windows Server Storage Migration Service Helper

# Copyright (c) Microsoft Corporation. All rights reserved.

# MIT License

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


Function GetSmsLogsFolder($Path, [ref]$SmsLogsFolder)
{
    $suffix = $null
    $folderNamePrefix = "StorageMigrationLog_$targetComputerName"
    
    do
    {
        $p = $Path + "\$folderNamePrefix"
        if ($null -ne $suffix)
        {
            $p += "_$suffix"
            $suffix += 1
        }
        else
        {
            $suffix = 1
        }
    } while (Test-Path $p -erroraction 'silentlycontinue')
    
    $SmsLogsFolder.value = $p
}

Function LogAction($message)
{
    Write-Output "==> $message"
}

Function GetSmsEventLogs($SmsLogsFolder)
{
    $names = @{
        "Microsoft-Windows-StorageMigrationService/Debug" = "$($targetComputerName)_Sms_Debug.log"
        "Microsoft-Windows-StorageMigrationService-Proxy/Debug" ="$($targetComputerName)_Proxy_Debug.log"
    }

    foreach ($key in $names.Keys)
    {
        $outFile = $names[$key]
        LogAction "Collecting traces for $($key) (outFile=$outFile)"
        
        $outFullFile = "$SmsLogsFolder\$outFile"
        
        if (! $computerNameWasProvided)
        {
            get-winevent -logname $key -oldest -ea SilentlyContinue | foreach-object {$_.Message} > "$outFullFile"
        }
        else
        {
            if ($null -eq $Credential)
            {
                Get-WinEvent -ComputerName $targetComputerName -logname $key -oldest -ea SilentlyContinue | foreach-object {$_.Message} > "$outFullFile"
            }
            else
            {
                Get-WinEvent -ComputerName $targetComputerName -Credential $Credential -logname $key -oldest -ea SilentlyContinue | foreach-object {$_.Message} > "$outFullFile"
            }
        }
    }
}

Function GetSmsEventLogs2($SmsLogsFolder)
{
    $names = @{
    "Microsoft-Windows-StorageMigrationService/Admin" = "$($targetComputerName)_Sms_Admin.log"
    "Microsoft-Windows-StorageMigrationService/Operational" = "$($targetComputerName)_Sms_Operational.log"

    "Microsoft-Windows-StorageMigrationService-Proxy/Admin" = "$($targetComputerName)_Proxy_Admin.log"
    "Microsoft-Windows-StorageMigrationService-Proxy/Operational" = "$($targetComputerName)_Proxy_Operational.log"
    }

    foreach ($key in $names.Keys)
    {
        $outFile = $names[$key]
        LogAction "Collecting traces for $($key) (outFile=$outFile)"
        
        $outFullFile = "$SmsLogsFolder\$outFile"
        
        if (! $computerNameWasProvided)
        {
            get-winevent -logname $key -oldest -ea SilentlyContinue | foreach-object { #write "$_.TimeCreated $_.Id $_.LevelDisplayName $_.Message"} > "$outFullFile"
                $id=$_.Id;
                $l = (0, (6 - $id.Length) | Measure-Object -Max).Maximum
                $m = "$($_.TimeCreated) {0,$l} $($_.LevelDisplayName) " -f $id
                $m += $_.Message
                $m
            } > "$outFullFile"

        }
        else
        {
            if ($null -eq $Credential)
            {
                Get-WinEvent -ComputerName $targetComputerName -logname $key -oldest -ea SilentlyContinue | foreach-object {#write "$_.TimeCreated $_.Id $_.LevelDisplayName $_.Message"} > "$outFullFile"
                    $id=$_.Id;
                    $l = (0, (6 - $id.Length) | Measure-Object -Max).Maximum
                    $m = "$($_.TimeCreated) {0,$l} $($_.LevelDisplayName) " -f $id
                    $m += $_.Message
                    $m
                } > "$outFullFile"
            }
            else
            {
                Get-WinEvent -ComputerName $targetComputerName -Credential $Credential -logname $key -oldest -ea SilentlyContinue | foreach-object {#write "$_.TimeCreated $_.Id $_.LevelDisplayName $_.Message"} > "$outFullFile"
                    $id=$_.Id;
                    $l = (0, (6 - $id.Length) | Measure-Object -Max).Maximum
                    $m = "$($_.TimeCreated) {0,$l} $($_.LevelDisplayName) " -f $id
                    $m += $_.Message
                    $m
                } > "$outFullFile"
            }
        }
    }
}


Function GetSystemEventLogs($SmsLogsFolder)
{
    $outFile = "$($targetComputerName)_System.log"
    $outFullFile = "$SmsLogsFolder\$outFile"
    
    if (! $computerNameWasProvided)
    {
        get-winevent -logname System -oldest -ea SilentlyContinue | foreach-object {
            $id=$_.Id;
            $l = (0, (6 - $id.Length) | Measure-Object -Max).Maximum
            $m = "$($_.TimeCreated) {0,$l} $($_.LevelDisplayName) " -f $id
            $m += $_.Message
            $m
        } > "$outFullFile"
    }
    else
    {
        if ($null -eq $Credential)
        {
            get-winevent -ComputerName $targetComputerName -logname System -oldest -ea SilentlyContinue | foreach-object {
                $id=$_.Id;
                $l = (0, (6 - $id.Length) | Measure-Object -Max).Maximum
                $m = "$($_.TimeCreated) {0,$l} $($_.LevelDisplayName) " -f $id
                $m += $_.Message
                $m
            } > "$outFullFile"
        }
        else
        {
            get-winevent -ComputerName $targetComputerName -Credential $Credential -logname System -oldest -ea SilentlyContinue | foreach-object {
                $id=$_.Id;
                $l = (0, (6 - $id.Length) | Measure-Object -Max).Maximum
                $m = "$($_.TimeCreated) {0,$l} $($_.LevelDisplayName) " -f $id
                $m += $_.Message
                $m
            } > "$outFullFile"
        }
    }
}

Function GetSystemInfo($SmsLogsFolder)
{
    if (! $computerNameWasProvided)
    {
        $remoteFeatures = Get-WindowsFeature
        
        $windows = $env:systemroot
	    $orcver = Get-ChildItem $windows\sms\* | Format-List versioninfo
	    $proxyver = Get-ChildItem $windows\smsproxy\* | Format-List versioninfo
        
    }
    else
    {
        if ($null -eq $Credential)
        {
            $remoteFeatures = Get-WindowsFeature -ComputerName $targetComputerName
        }
        else
        {
            $remoteFeatures = Get-WindowsFeature -ComputerName $targetComputerName -Credential $Credential
        }
    }
    
    $remoteFeatures | Format-Table -AutoSize
    
    if ($computerNameWasProvided)
    {
        # We want to find out whether SMS cmdlets are present on the local computer
        $features = Get-WindowsFeature *SMS*
    }
    else
    {
        $features = $remoteFeatures
    }

    $areSmsCmdletsAvailable = $false
    $isSmsInstalled = $false
    Write-Output $orcver
    Write-Output $proxyver
    
    foreach ($feature in $features)
    {
        if ($feature.Name -eq "RSAT-SMS")
        {
            $areSmsCmdletsAvailable = $feature.Installed
            break
        }
    }
    
    foreach ($feature in $remoteFeatures)
    {
        if ($feature.Name -eq "SMS")
        {
            $isSmsInstalled = $feature.Installed
            break
        }
    }
    
    Write-Output "areSmsCmdletsAvailable: $areSmsCmdletsAvailable"
    Write-Output "isSmsInstalled: $isSmsInstalled"

    if ($areSmsCmdletsAvailable -and $isSmsInstalled)
    {
        if (! $computerNameWasProvided)
        {
            $smsStates = Get-SmsState
        }
        else
        {
            if ($null -eq $Credential)
            {
                $smsStates = Get-SmsState -OrchestratorComputerName $targetComputerName
            }
            else
            {
                $smsStates = Get-SmsState -OrchestratorComputerName $targetComputerName -Credential $Credential
            }
        }
        
        Write-Output $smsStates
Write-Output "After ###################"

        foreach ($state in $smsStates)
        {
            $job = $state.Job
            Write-Output "+++"
            Write-Output "Inventory summary for job: $job"
            
            if (! $computerNameWasProvided)
            {
                $inventorySummary = Get-SmsState -Name $job -InventorySummary
            }
            else
            {
                if ($null -eq $Credential)
                {
                    $inventorySummary = Get-SmsState -OrchestratorComputerName $targetComputerName -Name $job -InventorySummary
                }
                else
                {
                    $inventorySummary = Get-SmsState -OrchestratorComputerName $targetComputerName -Credential $Credential -Name $job -InventorySummary
                }
            }
            
            Write-Output $inventorySummary

            foreach ($entry in $inventorySummary)
            {
                $device = $entry.Device
                Write-Output "!!!"
                Write-Output "Inventory config detail for device: $device"

                if (! $computerNameWasProvided)
                {
                    $detail = Get-SmsState -Name $job -ComputerName $device -InventoryConfigDetail
                }
                else
                {
                    if ($null -eq $Credential)
                    {
                        $detail = Get-SmsState -OrchestratorComputerName $targetComputerName -Name $job -ComputerName $device -InventoryConfigDetail
                    }
                    else
                    {
                        $detail = Get-SmsState -OrchestratorComputerName $targetComputerName -Credential $Credential -Name $job -ComputerName $device -InventoryConfigDetail
                    }
                }

                Write-Output $detail

                Write-Output "!!!"
                Write-Output "Inventory SMB detail for device: $device"

                if (! $computerNameWasProvided)
                {
                    $detail = Get-SmsState -Name $job -ComputerName $device -InventorySMBDetail
                }
                else
                {
                    if ($null -eq $Credential)
                    {
                        $detail = Get-SmsState -OrchestratorComputerName $targetComputerName -Name $job -ComputerName $device -InventorySMBDetail
                    }
                    else
                    {
                        $detail = Get-SmsState -OrchestratorComputerName $targetComputerName -Credential $Credential -Name $job -ComputerName $device -InventorySMBDetail
                    }
                }

                Write-Output $detail
            }

            if ($state.LastOperation -ne "Inventory")
            {
                Write-Output "+++"
                Write-Output "Transfer summary for job: $job"

                if (! $computerNameWasProvided)
                {
                    $transferSummary = Get-SmsState -Name $job -TransferSummary
                }
                else
                {
                    if ($null -eq $Credential)
                    {
                        $transferSummary = Get-SmsState -OrchestratorComputerName $targetComputerName -Name $job -TransferSummary
                    }
                    else
                    {
                        $transferSummary = Get-SmsState -OrchestratorComputerName $targetComputerName -Credential $Credential -Name $job -TransferSummary
                    }
                }
                
                Write-Output $transferSummary

                foreach ($entry in $inventorySummary)
                {
                    $device = $entry.Device
                    Write-Output "!!!"
                    Write-Output "Transfer SMB detail for device: $device"

                    if (! $computerNameWasProvided)
                    {
                        $detail = Get-SmsState -Name $job -ComputerName $device -TransferSMBDetail
                    }
                    else
                    {
                        if ($null -eq $Credential)
                        {
                            $detail = Get-SmsState -OrchestratorComputerName $targetComputerName -Name $job -ComputerName -ComputerName $device $device -TransferSMBDetail
                        }
                        else
                        {
                            $detail = Get-SmsState -OrchestratorComputerName $targetComputerName -Credential $Credential -Name $job -ComputerName $device -ComputerName $device -TransferSMBDetail
                        }
                    }

                    Write-Output $detail
                }
                
                Write-Output "+++"
                Write-Output "Cutover summary for job: $job"

                if (! $computerNameWasProvided)
                {
                    $cutoverSummary = Get-SmsState -Name $job -CutoverSummary
                }
                else
                {
                    if ($null -eq $Credential)
                    {
                        $cutoverSummary = Get-SmsState -OrchestratorComputerName $targetComputerName -Name $job -CutoverSummary
                    }
                    else
                    {
                        $cutoverSummary = Get-SmsState -OrchestratorComputerName $targetComputerName -Credential $Credential -Name $job -CutoverSummary
                    }
                }

                Write-Output $cutoverSummary
            }
            Write-Output "==="
        }

    }
}

Function Get-SmsLogs (
    [string] $ComputerName = $null,
    [System.Management.Automation.PSCredential] $Credential = $null,
    [string] $Path = (Get-Item -Path ".\").FullName
)
{
    $error.Clear()
    
    if ($null -eq $ComputerName -or $ComputerName -eq "")
    {
        $computerNameWasProvided = $false
        $targetComputerName = "$env:ComputerName"
    }
    else
    {
        $computerNameWasProvided = $true
        $targetComputerName = $ComputerName
    }

    [string]$smsLogsFolder = ""
    
    GetSmsLogsFolder -Path $path -SmsLogsFolder ([ref]$smsLogsFolder)

    LogAction "Creating directory '$smsLogsFolder'"
    $null = New-Item -Path $smsLogsFolder -Type Directory
    
    Start-Transcript -Path "$smsLogsFolder\$($targetComputerName)_Get-SmsLogs.log" -Confirm:0
    
    $date = Get-Date
    Write-Output "Get-SmsLogs started on $date"
    
    Write-Output "ComputerName: '$ComputerName'"
    Write-Output "TargetComputerName: '$targetComputerName'"
    Write-Output "Path: '$Path'"

    GetSmsEventLogs  -SmsLogsFolder $SmsLogsFolder
    GetSmsEventLogs2 -SmsLogsFolder $SmsLogsFolder
    GetSystemEventLogs -SmsLogsFolder $SmsLogsFolder
    GetSystemInfo -SmsLogsFolder $SmsLogsFolder
    
    $date = Get-Date
    Write-Output "Get-SmsLogs finished on $date"
    
    Stop-Transcript

    Compress-Archive -Path $SmsLogsFolder -DestinationPath $SmsLogsFolder -CompressionLevel Optimal
    
    LogAction "ZIP file containing the logs: '$($SmsLogsFolder).zip'"
}

Export-ModuleMember -Function Get-SmsLogs
# SIG # Begin signature block
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAgAAgg6UHeKdKQ
# FmD/T3zaovgmvApsGFatBo3dSqTRmKCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIAKypfTRyOd3mBYBUeWsQLCo
# udc0FfOo+f3LEkZc7GwoMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAMau5T3LcdXPFQmUxD09x4suVHRNuYlMi0WgLz/UFb+Hjl3m87UboeH+i
# MBI1S3JG5tN/yy493o+TDu80d0sGoomjGYRvsRYVxxM/a4T4yJeHHJTtJ1NZWDz9
# 65y7LOzq4m5H4/TG+OlHLaifxKwte+2z1b3gTUUWk3kg9ThzXLxr8LJbq65Jh+qA
# kVXqTHZghak6ex95a49m1PFO5Xezudp385EBwuE5vDYIp7NYRM5pUcfjOOph8jWs
# hrREABXncf05eam+klupMoujdCkak5eOmksmVTMrqZh1Rs4dch2zvpAmsk/ksCed
# 0dX5Fw9uyT2hNQxL8AS8KeWsrnzvSaGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCC
# FuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCBT4HCwj4mRURE2Cs1XX7e8ei/KUfb5BlXRX6r/4B/PuQIGZGzYtBmG
# GBMyMDIzMDYwNjExNDU1MC4yNjNaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0OUJDLUUz
# N0EtMjMzQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVQwggcMMIIE9KADAgECAhMzAAABwFWkjcNkFcVLAAEAAAHAMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEy
# NVoXDTI0MDIwMjE5MDEyNVowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjQ5QkMtRTM3QS0yMzNDMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAvO1g+2NhhmBQvlGlCTOMaFw3jbIhUdDTqkaQhRpdHVb+
# huU/0HNhLmoRYvrp7z5vIoL1MPAkVBFWJIkrcG7sSrednyZwreY207C9n8XivL9Z
# BOQeiUeL/TMlJ6VinrcafbhdnkNO5JDlPozC9dGySiubryds5GKtu69D1wNat9DI
# Ql6alFO6pncZK4RIzfv+KzkM7RkY3vHphV0C8EFUpF+lysaGJXFf9QsUUHwj9XKW
# Hfc9BfhLoCReXUzvgrspdFmVnA9ATYXmidSjrshf8A+E0/FpTdhXPI9XXqsZDHBq
# r7DlYoSCU3lvrVDRu1p5pHHf7s3kM16HpK6arDtY3ai1soASmEpv3C2N/y5MDBAp
# Dd4SpSkLMa7+6es/daeS7zdH1qdCa2RoJPM6Eh/6YmBfofhfLQofKPJl34ALlZWK
# 5AzVtFRNOXacoj6MAG2dT8Rc5fpKCH1E3n7Zje0dK24QVfSv/YOxw52ECaMLlW5P
# hHT3ZINNaCmRgcHCTClOKzC2FOr03YBc2zPOW6bIVdXloPmBMVaE+thXqPmANBw0
# YsncaOkVggjDb5O5VqOp98MklHpJoJI6pk5zAlx8/OtC7FutrdtYNUC6ykXzMAPF
# uYkWGgx/W7A0itKW8WzYzwO3bAhprwznouGZmRiw2k8pen80BzqzdyPvbzTxQsMC
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBQARMZ480jwpK3P6quVWUEJ0c30hTAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQCtTh0EQn16kKQyCeVk9Vc10m6L0EwLRo3ATRouP7Yd2hWeEB2Y4ZF4CJKe9qfX
# WGJKzV7tMUm6DAsBKYH/nT+8ybI8uJiHGnfnVi6Sh7gFjnTpfh1j1T90H/uLeoFj
# pOn/+eoCoJmorW5Gb2ezlTlo5I0kNAubxtCxqbLizuPNPob8kRAKQgv+4/CC1Jmi
# UFG0uKINlKj9SsHcrWeBBQHX62nNgziIwT44JqHrA02I6cmQAi9BZcsf57OOLpRY
# lzoPH3x/+ldSySXAmyLq2uSbWtQuD84I/0ZgS/B5L3ewqTdiE1KbKX89MW5JqCK/
# yI/mAIQammAlHPqU9eZZTMPOHQs0XrpCijlk+qyo2JaHiySww6nuPqXzU3sEj3VW
# 00YiVSayKEu1IrRzzX3La8qe6OqLTvK/6gu5XdKq7TT852nB6IP0QM+Budtr4Fbx
# 4/svpKHGpK9/zBuaHHDXX5AoSksh/kSDYKfefQIhIfQJJzoE3X+MimMJrgrwZXlt
# b6j1IL0HY3qCpa03Ghgi0ITzqfkw3Man3G8kB1Ql+SeNciPUj73Kn2veJenGLtT8
# JkUM9RUi0woO0iuY4tJnYuS+SeqavXUOWqUYVY19FIr1PLqpmWkbrO5xKjkyOHoA
# mLxjNbKjOnkAwft+1G00kulKqzqPbm+Sn+47JsGQFhNGbTCCB3EwggVZoAMCAQIC
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
# U046NDlCQy1FMzdBLTIzM0MxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVABAQ7ExF19KkwVL1E3Ad8k0Peb6doIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoKSL1MCIYDzIwMjMwNjA2MTExMzU3WhgPMjAyMzA2MDcxMTEzNTdaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOgpIvUCAQAwBwIBAAICBTUwBwIBAAICEngw
# CgIFAOgqdHUCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQAVRtyOICsPsOH1
# +kjCU+8mF5lgPZqJOgWfhisosAob5TWM8o5Wrgz0/8aG22FKVZLzgwtWbb50rGxu
# F85TC5iF9bQxX37OZ9JDAjZpRS6VwH97pXrZgIu30ceRq3lK9J/IKmQApr3yI4dm
# TGltSgTUx3bF86nYMhR1h2qST4akHTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABwFWkjcNkFcVLAAEAAAHAMA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEILwUpkBYAK6TPw83d6Zfp4gtbBC2nHEowpPPja/jcTkrMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQgWvFYolIIXME0zK/W6XsCkkYX7lYNb9yA8Jxw
# Y04Pk08wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AcBVpI3DZBXFSwABAAABwDAiBCAat2Lywv2wa22F5tQkIY5+YIjZ0j0GIcCZ9ZZL
# hqkiUTANBgkqhkiG9w0BAQsFAASCAgAqXr6/xfAECniZvccAz1rgRMBmbbxuUuVa
# w+2iOU+Z3huMXPQ7cx+fuQupVWyUURRFeYo9xzaAIr6tMPcaRFTSOHBvJSuUdChs
# pppda6L5huEAWK2VJrZgBPYoL78sv4zAh4D8FloclAKnQ8Xi4BKrNaWyPL4pRAk1
# oXZ0ow13qzZNofiJOdBDsNmDR3LRCwhfjV1aczSZ7TmmO71rHgkvWH87UXL/mpPD
# JsO1vdnrQksAMpZaZbW0QDl1+0sdaoqkEQyznEEikC2BCFZpSuR1nyUZfjT7oWxt
# oEy7NDheP43yCQlpyaZFr4H+2RlNBWJ1sy8pBWxCgsvBy6vfYmWXvXqEQaiH1T0p
# 6dpvDDosYWHyEWQE6bVt/DtGBMCasZJN0r+lwceuXKhON/bLb/hSOI2gPImx6Xfr
# /zK0rz4nTOz8ZIAgYuQ5SbPPyKUQFZPOK5d22a0prOFCZ4HGT4Iak5LzSNM04wIH
# M3JzP3Chpon2+t94RtIjlsZitMbat5rBwZK3qNslzsIdmhIobewqiy7HAXq2D2V/
# qFhxBGT1TjVBi7HupyKRDZReGGAdRVlf404b5Rhll1PmSqQuNtwTIWDHIrLpJgJt
# hsBUGQqzta9EE5umSjusvCLYJXeSOwKqfAob08n10KYBLjeHc5LDeh71veEtxFgc
# Rq+wsIuH5g==
# SIG # End signature block
