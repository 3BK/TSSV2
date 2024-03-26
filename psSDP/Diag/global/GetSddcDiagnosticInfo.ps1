# Script: GetSddcDiagnosticInfo.ps1 PrivateCloud.DiagnosticInfo
# https://github.com/PowerShell/PrivateCloud.DiagnosticInfo 
<#
Overview
This module contains the comprehensive diagnostic information gatherer for Microsoft Software Defined Datacenter solutions. It assumes deployment with compute and/or storage clusters running Windows Server 2016 or newer. The module has the diagnostic commands Get-SDDCDiagnosticInfo (previously Get-PCStorageDiagnosticInfo), which gathers triage payload, and Show-SDDCDiagnosticReport, which provides a number of reports & health checks for Failover Clustering (Cluster, Resources, Networks, Nodes), Storage and Storage Spaces Direct (Physical Disks, Enclosures, Virtual Disks), Cluster Shared Volumes, SMB File Shares, and Deduplication. Sources available at GitHub ( http://github.com/Powershell/PrivateCloud.DiagnosticInfo) and download available via Powershell Gallery at (https://www.powershellgallery.com/packages/PrivateCloud.DiagnosticInfo)
The Get-SDDCDiagnosticInfo command in this module includes several sections, including:
1. Gathering of cluster, cluster Health service and event logs from all cluster nodes to a ZIP archive
2. Reporting of Storage Health, plus details on unhealthy components.
3. Reporting of Storage Capacity by Pool, Volume and Deduplicated volumes.
4. Reporting of Storage Performance with IOPS and Latency per Volume
#>

    [CmdletBinding(DefaultParameterSetName="WriteC")]
    [OutputType([String])]

    param(
        [parameter(ParameterSetName="WriteC", Position=0, Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Position=0, Mandatory=$false)]
        [alias("WriteToPath")]
        [ValidateNotNullOrEmpty()]
        [string] $TemporaryPath = $($env:userprofile + "\HealthTest\"),

        [parameter(ParameterSetName="M", Position=1, Mandatory=$false)]
        [parameter(ParameterSetName="WriteC", Position=1, Mandatory=$false)]
        [string] $ClusterName = ".",

        [parameter(ParameterSetName="WriteN", Position=1, Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]] $Nodelist = @(),

        [parameter(ParameterSetName="Read", Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $ReadFromPath = "",

        [parameter(ParameterSetName="WriteC", Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [bool] $IncludePerformance = $true,

        [parameter(ParameterSetName="WriteC", Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Mandatory=$false)]
        [ValidateRange(1,3600)]
        [int] $PerfSamples = 30,

        [parameter(ParameterSetName="WriteC", Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Mandatory=$false)]
        [switch] $ProcessCounter,

        [parameter(ParameterSetName="M", Mandatory=$true)]
        [switch] $MonitoringMode,

        [parameter(ParameterSetName="WriteC", Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [int] $HoursOfEvents = -1,

        [parameter(ParameterSetName="WriteC", Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Mandatory=$false)]
        [ValidateRange(-1,365)]
        [int] $DaysOfArchive = 8,

        [parameter(ParameterSetName="WriteC", Position=2, Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Position=2, Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string] $ZipPrefix = $($env:userprofile + "\HealthTest"),

        [parameter(ParameterSetName="WriteC", Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Mandatory=$false)]
        [ValidateRange(1,1000)]
        [int] $ExpectedNodes,

        [parameter(ParameterSetName="WriteC", Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Mandatory=$false)]
        [ValidateRange(1,1000)]
        [int] $ExpectedNetworks,

        [parameter(ParameterSetName="WriteC", Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Mandatory=$false)]
        [ValidateRange(0,1000)]
        [int] $ExpectedVolumes,

        [parameter(ParameterSetName="WriteC", Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Mandatory=$false)]
        [ValidateRange(0,1000)]
        [int] $ExpectedDedupVolumes,

        [parameter(ParameterSetName="WriteC", Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Mandatory=$false)]
        [ValidateRange(1,10000)]
        [int] $ExpectedPhysicalDisks,

        [parameter(ParameterSetName="WriteC", Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Mandatory=$false)]
        [ValidateRange(1,1000)]
        [int] $ExpectedPools,

        [parameter(ParameterSetName="WriteC", Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Mandatory=$false)]
        [ValidateRange(1,10000)]
        [int] $ExpectedEnclosures,

        [parameter(ParameterSetName="WriteC", Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Mandatory=$false)]
        [switch] $IncludeAssociations,

        [parameter(ParameterSetName="WriteC", Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Mandatory=$false)]
        [switch] $IncludeDumps,

        [parameter(ParameterSetName="WriteC", Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Mandatory=$false)]
        [switch] $IncludeGetNetView,

        [parameter(ParameterSetName="WriteC", Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Mandatory=$false)]
        [switch] $IncludeHealthReport,

        [parameter(ParameterSetName="WriteC", Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Mandatory=$false)]
        [switch] $IncludeLiveDump,

        [parameter(ParameterSetName="WriteC", Mandatory=$false)]
        [parameter(ParameterSetName="WriteN", Mandatory=$false)]
        [switch] $IncludeReliabilityCounters
        )
	
# This gets the current path and name of the script.
  $invocation = (Get-Variable MyInvocation).Value
	$invocationLine= $($MyInvocation.Line)
  $scriptPath = Split-Path $invocation.MyCommand.Path
	$ScriptParentPath 	= Split-Path $MyInvocation.MyCommand.Path -Parent
	#$SDDCversion = ( Get-content -Path "$ScriptParentPath\PrivateCloud.DiagnosticInfo\version_SDDC.dat")[0] #"1.1.37" as of 2021/12/09
	#Write-Verbose "scriptPath:  $scriptPath - ScriptParentPath: $ScriptParentPath"

# https://github.com/PowerShell/PrivateCloud.DiagnosticInfo
$module = 'PrivateCloud.DiagnosticInfo'
if (Test-Path $env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\$module) {
       rm -Recurse $env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\$module -ErrorAction Stop
       Remove-Module $module -ErrorAction SilentlyContinue
} else {
       Import-Module $module -ErrorAction SilentlyContinue
}
if (-not ($m = Get-Module $module -ErrorAction SilentlyContinue)) {
       $md = "$env:ProgramFiles\WindowsPowerShell\Modules"
} else {
       $md = (gi $m.ModuleBase -ErrorAction SilentlyContinue).PsParentPath
       Remove-Module $module -ErrorAction SilentlyContinue
       rm -Recurse $m.ModuleBase -ErrorAction Stop
}
cp -Recurse $ScriptParentPath\$module $md -Force -ErrorAction Stop

Import-Module $module -Force  
#Get-Command -Module PrivateCloud.DiagnosticInfo

<#
if ( -not (Test-Path $env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\$module)) {
	Copy-Item -Recurse $ScriptParentPath\$module $env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\$module -Force -ErrorAction Stop
}

#Import-Module -Name $ScriptParentPath\PrivateCloud.DiagnosticInfo.psm1
Import-Module $module -Force 
#>

$SDDCversion =(Get-Module $module).version.ToString()
	Write-Verbose "scriptPath:  $scriptPath - ScriptParentPath: $ScriptParentPath"
	#Write-Host "____ $(Get-Date -Format 'HH:mm:ss') scriptPath:  $scriptPath - ScriptParentPath: $ScriptParentPath - verPath: $ScriptParentPath\PrivateCloud.DiagnosticInfo\version_SDDC.dat" 

Write-Host -ForegroundColor White -BackgroundColor DarkGreen "$(Get-Date -Format 'HH:mm:ss') Collecting PrivateCloud.DiagnosticInfo (ModuleVersion = $SDDCversion):"

Get-SddcDiagnosticInfo @PSBoundParameters 


# SIG # Begin signature block
# MIIjiQYJKoZIhvcNAQcCoIIjejCCI3YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBoDVQjekkqhSZd
# NFVOkU6KOuTqGzfLV2dtEkRd7+Wuf6CCDYUwggYDMIID66ADAgECAhMzAAACU+OD
# 3pbexW7MAAAAAAJTMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjEwOTAyMTgzMzAwWhcNMjIwOTAxMTgzMzAwWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDLhxHwq3OhH+4J+SX4qS/VQG8HybccH7tnG+BUqrXubfGuDFYPZ29uCuHfQlO1
# lygLgMpJ4Geh6/6poQ5VkDKfVssn6aA1PCzIh8iOPMQ9Mju3sLF9Sn+Pzuaie4BN
# rp0MuZLDEXgVYx2WNjmzqcxC7dY9SC3znOh5qUy2vnmWygC7b9kj0d3JrGtjc5q5
# 0WfV3WLXAQHkeRROsJFBZfXFGoSvRljFFUAjU/zdhP92P+1JiRRRikVy/sqIhMDY
# +7tVdzlE2fwnKOv9LShgKeyEevgMl0B1Fq7E2YeBZKF6KlhmYi9CE1350cnTUoU4
# YpQSnZo0YAnaenREDLfFGKTdAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUlZpLWIccXoxessA/DRbe26glhEMw
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzQ2NzU5ODAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AKVY+yKcJVVxf9W2vNkL5ufjOpqcvVOOOdVyjy1dmsO4O8khWhqrecdVZp09adOZ
# 8kcMtQ0U+oKx484Jg11cc4Ck0FyOBnp+YIFbOxYCqzaqMcaRAgy48n1tbz/EFYiF
# zJmMiGnlgWFCStONPvQOBD2y/Ej3qBRnGy9EZS1EDlRN/8l5Rs3HX2lZhd9WuukR
# bUk83U99TPJyo12cU0Mb3n1HJv/JZpwSyqb3O0o4HExVJSkwN1m42fSVIVtXVVSa
# YZiVpv32GoD/dyAS/gyplfR6FI3RnCOomzlycSqoz0zBCPFiCMhVhQ6qn+J0GhgR
# BJvGKizw+5lTfnBFoqKZJDROz+uGDl9tw6JvnVqAZKGrWv/CsYaegaPePFrAVSxA
# yUwOFTkAqtNC8uAee+rv2V5xLw8FfpKJ5yKiMKnCKrIaFQDr5AZ7f2ejGGDf+8Tz
# OiK1AgBvOW3iTEEa/at8Z4+s1CmnEAkAi0cLjB72CJedU1LAswdOCWM2MDIZVo9j
# 0T74OkJLTjPd3WNEyw0rBXTyhlbYQsYt7ElT2l2TTlF5EmpVixGtj4ChNjWoKr9y
# TAqtadd2Ym5FNB792GzwNwa631BPCgBJmcRpFKXt0VEQq7UXVNYBiBRd+x4yvjqq
# 5aF7XC5nXCgjbCk7IXwmOphNuNDNiRq83Ejjnc7mxrJGMIIHejCCBWKgAwIBAgIK
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
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCFVowghVWAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAAJT44Pelt7FbswAAAAA
# AlMwDQYJYIZIAWUDBAIBBQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEII7t
# +4KhrcU/7kmjKD+SfzZfAfwRt2I0u3uw+Ql3pSuyMEQGCisGAQQBgjcCAQwxNjA0
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQu
# Y29tIDANBgkqhkiG9w0BAQEFAASCAQCpP6sHYubIGyvb5gv08hgWqzhb5CqK4cCQ
# NUQbnsJATaorin8eAp5ADmeimC6tLEkOhKe5v0ydNKxiiwCWDUMObkIHOAdKn+TO
# A0C+6LhW8beC2x6mpmbxfUh+71L075QU15Ug524olS4qVfQres2k7kRzgf2/d/C2
# mPOU13/haaxzETeBZg5vYFANngZ4kgYekpOS1HhOFa08nTeidEgEBiivzXwyUIuv
# eRP7ixX0DQbgMkl4vYnXHHKCyRjUa/RV1tte8JHs3hmUav7sTpk74C85jXpczDI/
# VsFRxKnuErzLqT85ms7sDn4u0cQSx8hlORSZY0dmb/vHACfl39xHoYIS4jCCEt4G
# CisGAQQBgjcDAwExghLOMIISygYJKoZIhvcNAQcCoIISuzCCErcCAQMxDzANBglg
# hkgBZQMEAgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEE
# AYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIJRob+Zho+zKMbdUhSl/evD6Bk4XO2Q5
# ufV30choG5LVAgZhkuGsRQYYEzIwMjExMjEzMTMyMDExLjA3OFowBIACAfSggdCk
# gc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNV
# BAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxl
# cyBUU1MgRVNOOkQ2QkQtRTNFNy0xNjg1MSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloIIOOTCCBPEwggPZoAMCAQICEzMAAAFQWKLUp5sLMOsA
# AAAAAVAwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwHhcNMjAxMTEyMTgyNjAzWhcNMjIwMjExMTgyNjAzWjCByjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFt
# ZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDZCRC1F
# M0U3LTE2ODUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDnen+UeypZwycbVpoN8zNS
# AqnZl40+RjRTx17gsPvVYNxvPe6PzruS/J5X2mON6BRt+XaJATJJvkCgHvViJqrU
# 7Q39T0qTf02fOTTzkBR1zhB2ihL3XSaEpRE/L2wSa7vgL8jhPFi0dZ8nnqcj96bV
# LaRvPs7ANXeDF3xpZNgUSKL2EegBcmRUse+92uWk/NYsj8Y3ECv2qPnSCNESqdQ9
# 7JS4K3R5PzHSCG2xYvRRLp+b90FVI2JCQr1IAj92UNke2wKHbQs5VdyJE+/vgg6t
# yZdaxW7AVojIq5KcfM3+QahNKpsdOHm37IwYmD1LfTsb0tVhXLjbh7o4T6cCKiWb
# AgMBAAGjggEbMIIBFzAdBgNVHQ4EFgQUglUZHxlF261kL0PBAEM7t+ufRX4wHwYD
# VR0jBBgwFoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZF
# aHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGlt
# U3RhUENBXzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcw
# AoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQ
# Q0FfMjAxMC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEF
# BQcDCDANBgkqhkiG9w0BAQsFAAOCAQEAUT9odHKO/uPj08AeL5P2HixMOqHK3oPk
# 9JAdmlgf2Xt8xF7Y9BHiFQNWYMKd/HI2ryYOu3SAAs3txZaRpalvY0R16WWIQzC9
# G9oqSD7QNN0RMxsiiCMM65/nq9xSPIrmYh6aTXFgIMuh4GLNk7gMQFybUbg2ZlLZ
# sn9r5RzxX/x8aK17ggEWKmiij1lgb/6AE+bAPUuEyy50ua6U9Zs0+bi8/HvnZs6P
# iMwGhtXz/sRrZaAYjbLvaCXOk+DbRvHBoYHQQm35QrPUIfiNcw30giIMRy7xYHji
# ml/IxakMFUJ56mLE3SvnbSGxaKwppPlkIsw5HhemdSGHs5SlrQTbXjCCBnEwggRZ
# oAMCAQICCmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1
# MDcwMTIxNDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ
# 1aUKAIKF++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP
# 8WCIhFRDDNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRh
# Z5FfgVSxz5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39
# dx898Fd1rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2
# iAg16HgcsOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGj
# ggHmMIIB4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xG
# G8UzaFqFbVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGG
# MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186a
# GMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3Br
# aS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsG
# AQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB
# /wSBlTCBkjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUF
# BwICMDQeMiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0A
# ZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFv
# s+umzPUxvs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5
# U4zM9GASinbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFS
# AK84Dxf1L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1V
# ry/+tuWOM7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6
# f32WapB4pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35j
# WSUPei45V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHa
# sFAeb73x4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLN
# HfS4hQEegPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4
# sanblrKnQqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHX
# odLFVeNp3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUe
# CLraNtvTX4/edIhJEqGCAsswggI0AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpENkJELUUz
# RTctMTY4NTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIj
# CgEBMAcGBSsOAwIaAxUAIw17n3LxNWtGEZtallmkMZYeoBKggYMwgYCkfjB8MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy
# b3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOVhoL0w
# IhgPMjAyMTEyMTMxODM2NDVaGA8yMDIxMTIxNDE4MzY0NVowdDA6BgorBgEEAYRZ
# CgQBMSwwKjAKAgUA5WGgvQIBADAHAgEAAgIcsjAHAgEAAgIRXDAKAgUA5WLyPQIB
# ADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQow
# CAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBABKifpnnZWCVg3tS4rrpA3plm8zL
# UKzxbTpN52D0hx7v3gGCtnZYq29ViYDMy6lHEmIERw8lykUofwVvbll99dHiZsFv
# 203VhbcocEndH8yNdBrRZJIcJKqkmR9G2kNrnOw3n4xSuLqnPRdoXOMuVLF55Mlv
# W08ooZB+87IZjdWoMYIDDTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTACEzMAAAFQWKLUp5sLMOsAAAAAAVAwDQYJYIZIAWUDBAIBBQCgggFK
# MBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgysw1
# Nr+KPFlvoHmPlhdk6ua+XceUfqFcEV8sR7KSXQUwgfoGCyqGSIb3DQEJEAIvMYHq
# MIHnMIHkMIG9BCBs9D6fL5rCThgXJmGIhdXS6IY1Zg6op47dkKJ8L/Kj9jCBmDCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABUFii1KebCzDr
# AAAAAAFQMCIEIEiWSkoluVCrItALFeYfyM5VB2q9M2OQvd1tPj1kvdqaMA0GCSqG
# SIb3DQEBCwUABIIBAFE2USzMY1HLXkYMUuDaKjV17T2lhs/1AhOdwdX+u4P6U4vy
# HKBUwuylgEPXk4uRhsjeX1bMJ9oLuPJE+r5ODFpFNOdQo3YOl8j0TKRqgUMUT1ny
# IqznquBI22v4n89i0y3oMnmy+p5jkdOVNp3Q3y8z9bI9VxC4fU1EsllopJ/lw4sd
# vMLdyfO8reGj1A+7bq/pvW7gpbwtRe6IYMkhRrMtKJoLJEFNRmsX7FnYOZqdAVVj
# 6KV4SITCWd7arcqYf65D6c2t3QwGPwQg3lek14CpblmANCX6uwfzUAypIlytvhMg
# LAX6ymq6r2HTczSmwTvs0LZ20Fm2JFXalT5kRIo=
# SIG # End signature block
