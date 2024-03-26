<#

.SYNOPSIS
Collects basic information about the installed instance of WSUS Server

.DESCRIPTION
Collects basic information about the installed instance of WSUS Server and generates two files:
COMPUTERNAME_WSUS_BasicInfo.txt
(Optional) COMPUTERNAME_WSUS_UpdateApprovals.txt

.PARAMETER GetApprovedUpdates
(Optional) Collects a list of updates approved in the last 90 days.

.PARAMETER OutputDirectory
(Optional) Specify the output directory. If this is blank, the current working directory location is used.

.PARAMETER SilentExecution
(Optional) Use this to prevent any messages to get printed to the console host

.EXAMPLE
Get-WsusBasicInfo

.NOTES
10/04/2016 - Version 1.0 - Initial Version of the script

#>

[CmdletBinding()]
Param(
  [Parameter(Mandatory=$false)]
   [switch]$GetApprovedUpdates,
  [Parameter(Mandatory=$false)]
   [string]$OutputDirectory,
  [Parameter(Mandatory=$false)]
   [switch]$SilentExecution
)

if (-not $OutputDirectory) {
    $OutputDirectory = $PWD.Path
}

$BasicOutputFile = Join-Path $OutputDirectory ($env:COMPUTERNAME + "_WSUS_BasicInfo.txt")
$ApprovalOutputFile = Join-Path $OutputDirectory ($env:COMPUTERNAME + "_WSUS_UpdateApprovals.txt")

$null | Out-File -FilePath $BasicOutputFile # Overwrite to empty file

if ($GetApprovedUpdates) {
    $null | Out-File -FilePath $ApprovalOutputFile # Overwrite to empty file
}

Function Write-Out {
    Param(
      [string] $text,
      [switch] $NoWriteHost,
      [switch] $IsErrorMessage,
      [string] $OutputFile
    )

    if ($OutputFile -eq $null -or $OutputFile -eq "") {
        $OutputFile = $BasicOutputFile
    }

    $text | Out-File -FilePath $OutputFile -Append

    if ($SilentExecution) {
        return
    }

    if (-not $NoWriteHost) {
        if ($IsErrorMessage) {
            Write-Host $text -ForegroundColor Red
        }
        else {
            Write-Host $text -ForegroundColor Cyan
        }
    }
}

Function Get-OSInfo()
{
    Write-Out
    Write-Out "WSUS SERVER INFORMATION:"
    Write-Out
    Write-Out "Server Name: $env:COMPUTERNAME"
    Write-Out "Operating System: $([environment]::OSVersion)"
    Write-Out "WSUS Version: $($updateServer.Version)"
    Write-Out
    Write-Out "Date of Report: $(Get-Date)"
    Write-Out "User Running Report: $([environment]::UserDomainName)\$([environment]::UserName)"
}

Function Get-WSUSStatus()
{
    Write-Out
    Write-Out "===="

    $status = $updateServer.GetStatus()
    Write-Out "  Updates: $($status.UpdateCount)"
    Write-Out "    Approved Updates: $($status.ApprovedUpdateCount)"
    Write-Out "    Not Approved Updates: $($status.NotApprovedUpdateCount)"
    Write-Out "    Declined Updates: $($status.DeclinedUpdateCount)"
	Write-Out "    Expired Updates: $($status.ExpiredUpdateCount)"
    Write-Out "  Client Computer Count: $($status.ComputerTargetCount)"
    Write-Out "  Client Computers Needing Updates: $($status.ComputerTargetsNeedingUpdatesCount)"
    Write-Out "  Client Computers with Errors: $($status.ComputertargetsWithUpdateErrorsCount)"
    Write-Out "  Critical/Security Updates Not Approved: $($status.CriticalOrSecurityUpdatesNotApprovedForInstallCount)"
    Write-Out "  WSUS Infrastructure Updates Not Approved: $($status.WsusInfrastructureUpdatesNotApprovedForInstallCount)"
    Write-Out "  Number of Computer Target Groups: $($status.CustomComputerTargetGroupCount)"

    Write-Out "  Updates Needed by Computers: $($status.UpdatesNeededByComputersCount)"
    Write-Out "  Updates Needing Files: $($status.UpdatesNeedingFilesCount)"
}

Function Get-ComponentsWithErrors
{
    Write-Out
    Write-Out "===="
    Write-Out "COMPONENTS WITH ERRORS"
    Write-Out

    $componentsWithErrors = $updateServer.GetComponentsWithErrors()
    if ($componentsWithErrors.Count -gt 0) {
        foreach($component in $componentsWithErrors)
        {
            Write-Out "  $component"
        }
    }
    else {
        Write-Out "  None."
    }
}

Function Get-WSUSConfiguration
{
    Write-Out
    Write-Out "===="
    Write-Out "WSUS SERVER CONFIGURATION INFORMATION"
    Write-Out

    $database = $updateServer.GetDatabaseConfiguration()
    Write-Out "Database Settings"
    Write-Out "  Database Server: $($database.ServerName)"
    Write-Out "  Database Name: $($database.DatabaseName)"
    Write-Out "  Using Windows Internal Database: $($database.IsUsingWindowsInternalDatabase)"
    Write-Out

    $config = $updateServer.GetConfiguration()
    Write-Out "Proxy Settings:"
    Write-Out "  Use Proxy: $($config.UseProxy)"
    Write-Out "  Allow Proxy Credentials to be sent over non-SSL links: $($config.AllowProxyCredentialsOverNonSsl)"
    Write-Out "  Anonymous Proxy Access: $($config.AnonymousProxyAccess)"
    Write-Out "  Proxy Name: $($config.ProxyName)"
    Write-Out "  Proxy Server Port: $($config.ProxyServerPort)"
    Write-Out "  Proxy User Domain: $($config.ProxyUserDomain)"
    Write-Out "  Proxy User Name: $($config.ProxyUserName)"
    Write-Out "  Has Proxy Password: $($config.HasProxyPassword)"
    Write-Out

    $enabledLanguages = $config.GetEnabledUpdateLanguages()
    Write-Out "Updates Settings:"
    Write-Out "  Auto Approve WSUS Infrastructure Updates: $($config.AutoApproveWsusInfrastructureUpdates)"
    Write-Out "  Auto Refresh Update Approvals: $($config.AutoRefreshUpdateApprovals)"
    Write-Out "  Download Express Packages: $($config.DownloadExpressPackages)"
    Write-Out "  Download Update Binaries As Needed: $($config.DownloadUpdateBinariesAsNeeded)"
    Write-Out "  Host Binaries on Microsoft Update: $($config.HostBinariesOnMicrosoftUpdate)"
    Write-Out "  Local Content Cache Path: $($config.LocalContentCachePath)"
    Write-Out "  All Update Languages Enabled: $($config.AllUpdateLanguagesEnabled)"
    $temp = "  Enabled Update Languages:"
    foreach($language in $enabledLanguages)
    {
        $temp = $temp + " $language"
    }
    Write-Out $temp
    Write-Out

    Write-Out "Synchronization Settings:"
    Write-Out "  Sync from Microsoft Update: $($config.SyncFromMicrosoftUpdate)"
    Write-Out "  Upstream WSUS Server Name: $($config.UpstreamWsusServerName)"
    Write-Out "  Upstream WSUS Server Port: $($config.UpstreamWsusServerPortNumber)"
    Write-Out "  Upstream WSUS Server, Use SSL: $($config.UpstreamWsusServerUseSsl)"
    Write-Out "  Is Replica Server: $($config.IsReplicaServer)"
    Write-Out

    Write-Out "Miscellaneous Settings:"
    Write-Out "  Client Event Expiration Time: $($config.ClientEventExpirationTime)"
    Write-Out "  Expired Event Detection Period: $($config.ExpiredEventDetectionPeriod)"
    Write-Out "  Last Configuration Change: $($config.LastConfigChange)"
    Write-Out "  Server Event Expiration Time: $($config.ServerEventExpirationTime)"
    Write-Out "  Server ID: $($config.ServerId)"
    Write-Out "  Targeting Mode: $($config.TargetingMode)"
}

Function Get-SubscriptionList
{
    Write-Out
    Write-Out "===="
    Write-Out "SUBSCRIPTIONS"

    $subscription = $updateServer.GetSubscription()
    $categories = $subscription.GetUpdateCategories()
    $classifications = $subscription.GetUpdateClassifications()

    Write-Out
    Write-Out "  Update Categories:"
    Write-Out
    foreach ($category in $categories)
    {
        Write-Out "    $($category.Title)"
    }

    Write-Out
    Write-Out "  Update Classifications:"
    Write-Out
    foreach ($classification in $classifications)
    {
        Write-Out "    $($classification.Title)"
    }
}

Function Get-SubscriptionInfo
{
    Param(
      [int] $NumberOfDays
    )

    Write-Out
    Write-Out "===="
    Write-Out "WSUS SUBSCRIPTION INFORMATION"
    Write-Out

    $subscription = $updateServer.GetSubscription()
    $lastSyncInfo = $subscription.GetLastSynchronizationInfo()
    Write-Out "  Last synch start time: $($lastSyncInfo.StartTime)"
    Write-Out "  Last synch end time: $($lastSyncInfo.EndTime)"
    Write-Out "  Last synch error: $($lastSyncInfo.Error)"
    Write-Out "  Last synch error text: $($lastSyncInfo.ErrorText)"
    Write-Out "  Last synch result: $($lastSyncInfo.Result)"
    Write-Out "  Last synch was manual: $($lastSyncInfo.StartedManually)"

    $updateErrors = $lastSyncInfo.UpdateErrors
    if ($updateErrors.Count -lt 1)
    {
        Write-Out "  Last synch got all updates!"
    }
    else
    {
        Write-Out
        Write-Out "Last synch failed to get following updates:"
        foreach($updateErrorInfo in $updateErrors)
        {
            $update = $updateServer.GetUpdate($updateErrorInfo.UpdateId)
            Write-Out "  Update ID: $($update.Title)"
            Write-Out "  Error: $($updateErrorInfo.Error)"
            Write-Out "  Error Text: $($updateErrorInfo.ErrorText)"
        }
    }

    $since = [DateTime]::Now.AddDays(-$NumberOfDays)
    Write-Out
    Write-Out "===="
    Write-Out "WSUS SUBSCRIPTION HISTORY FOR LAST $NumberOfDays DAYS (since $since):"
    Write-Out
    $eventHistory = $subscription.GetEventHistory($since, [DateTime]::Now)

    if ($eventHistory.Count -lt 1)
    {
        Write-Out "  None."
        return
    }

    foreach($event in $eventHistory)
    {
        Write-Out "  $($event.CreationDate) - $($event.Message)"
    }
}

Function Get-ComputersNotCheckingIn
{
    Param(
      [int] $NumberOfDays
    )

    $since = [DateTime]::Now.AddDays(-$NumberOfDays)
    Write-Out
    Write-Out "===="
    Write-Out "COMPUTERS THAT HAVE NOT CONTACTED THE WSUS SERVER FOR $NumberOfDays DAYS OR MORE (since $since):"
    Write-Out
    $computerTargets = $updateServer.GetComputerTargets()
    $count = 0
    foreach ($computerTarget in $computerTargets)
    {
        if ($computerTarget.LastReportedStatusTime -lt $since)
        {
            Write-Out "  $($computerTarget.FullDomainName) last checked in: $($computerTarget.LastReportedStatusTime)"
            $count++
        }
    }

    if ($count -eq 0)
    {
        Write-Out "  None."
    }
    else
    {
        Write-Out
        Write-Out "  Total: $count"
    }
}

Function Get-TargetGroupList
{
    Param(
      [switch] $ListComputersInGroup
    )

    Write-Out
    Write-Out "===="

    if ($ListComputersInGroup)
    {
        Write-Out "CLIENT COMPUTER LIST"
    }
    else
    {
        Write-Out "COMPUTER TARGETING GROUPS"
    }

    Write-Out
    $computerTargetGroups = $updateServer.GetComputerTargetGroups()
    if ($computerTargetGroups.Count -lt 1)
    {
        Write-Out "  None."
        return
    }

    foreach($targetGroup in $computerTargetGroups)
    {
        $targets = $targetGroup.GetComputerTargets()
        Write-Out "  ----"
        Write-Out "  Target Group: $($targetGroup.Name)"
        Write-Out "    Number of computers in group: $($targets.Count)"

        if ($ListComputersInGroup)
        {
            foreach($computer in $targets)
            {
                $temp = "      Computer: $($computer.FullDomainName)`t"
                #$temp += " ($($computer.IPAddresss))"
                $temp += " LastStatus: $($computer.LastReportedStatusTime)"
                $temp += " LastSync: $($computer.LastSyncTime)"
                $temp += " (OS Build $($computer.OSInfo.Version.Build)"
                $temp += " Version $($computer.OSInfo.Version.Major).$($computer.OSInfo.Version.Minor) SP$($computer.OSInfo.Version.ServicePackMajor))"
                Write-Out $temp
            }
        }

        Write-Out
    }
}

Function Get-ApprovedUpdates
{
    Param(
      [int] $NumberOfDays
    )

    $since = [DateTime]::Now.AddDays(-$NumberOfDays)

    Write-Out -OutputFile $ApprovalOutputFile
    Write-Out "====" -OutputFile $ApprovalOutputFile
    Write-Out "UPDATES (LATEST REVISION) APPROVED IN LAST $NumberOfDays DAYS (since $since)" -OutputFile $ApprovalOutputFile
    Write-Out -OutputFile $ApprovalOutputFile

    $updateScope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
    $updateScope.FromArrivalDate = $since
    $updateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::LatestRevisionApproved
    $approvedUpdates = $updateServer.GetUpdateApprovals($updateScope)

    if ($approvedUpdates.Count -lt 1)
    {
        Write-Out "  None." -OutputFile $ApprovalOutputFile
        return
    }

    foreach($updateApproval in $approvedUpdates)
    {
        $updateInfo = $updateServer.GetUpdate($updateApproval.UpdateId)
        Write-Out -OutputFile $ApprovalOutputFile
        Write-Out "Update ID: $($updateInfo.Id.UpdateId), Revision Number: $($updateInfo.Id.RevisionNumber), Title: $($updateInfo.Title)" -OutputFile $ApprovalOutputFile
        Write-Out "  Classification: $($updateInfo.UpdateClassificationTitle)" -OutputFile $ApprovalOutputFile
        Write-Out "  Action: $($updateApproval.Action), State: $($updateApproval.State), ComputerTargetGroup: $($updateApproval.GetComputerTargetGroup().Name)" -OutputFile $ApprovalOutputFile
        Write-Out "  ApprovalDate: $($updateApproval.CreationDate), GoLiveTime: $($updateApproval.GoLiveTime), Deadline: $($updateApproval.Deadline)" -OutputFile $ApprovalOutputFile
    }
}

# Main script

try {
    [reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration") | out-null
    $updateServer = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer()
}
catch [Exception]
{
    Write-Out
    Write-Out "  Failed to connect to the WSUS Server." -IsErrorMessage
    Write-Out "  Error: $($_.Exception.Message)" -IsErrorMessage
    Write-Out
    exit 2
}

try {
    Get-OSInfo
    Get-WSUSStatus
    Get-ComponentsWithErrors
    Get-WSUSConfiguration
    Get-SubscriptionList
    Get-SubscriptionInfo -NumberOfDays 7
    Get-ComputersNotCheckingIn -NumberOfDays 7
    Get-ComputersNotCheckingIn -NumberOfDays 30
    Get-TargetGroupList
    Get-TargetGroupList -ListComputersInGroup
    if ($GetApprovedUpdates) { Get-ApprovedUpdates -NumberOfDays 30 }
}
catch [Exception]
{
    Write-Out "An unexpected error occurred during execution." -IsErrorMessage
    Write-Out "Exception: $($_.Exception.Message)" -IsErrorMessage
    if ($_.Exception.ErrorRecord -ne $null) {
        if ((Get-Member -InputObject $_.Exception.ErrorRecord -Name ScriptStackTrace) -ne $null)
        {
            Write-Out "Stack Trace: " -IsErrorMessage
            Write-Out $($_.Exception.ErrorRecord.ScriptStackTrace) -IsErrorMessage
        }
    }
}

Write-Out
# SIG # Begin signature block
# MIIjiAYJKoZIhvcNAQcCoIIjeTCCI3UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCOyz1eoL+VMFfo
# 9j/1tDy952Snz4QE2uxDn5KNtUWaz6CCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVXTCCFVkCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBpDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgOHuI2Q+5
# ZJJKCiPXiCkb0BZfmSoGgiyUjkvPincPfBAwOAYKKwYBBAGCNwIBDDEqMCigCIAG
# AFQAUwBToRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20gMA0GCSqGSIb3DQEB
# AQUABIIBAAlLNZVLi/J3t3X2yWrhIrnFld/orCIOxgbMuKfZAex881Biz2cOHzQm
# FKPEnyCTX+GzfByI7dZ5yUdJxB+yvpXQnhw1ILAY70fWFlo8CEIkZ480zve5u6Ni
# DlOZDgZe7QjKgNhhb3I5wCVz9mk5Y3/dmF8P80vFjRmWhax2J/lxJ0Fubf5diSZw
# K8pHSWLUmsX8dPe+7YblNyfQ90Og0OPMhw8IIPvbDKtUilYdNJc64p+l7yEKG1DE
# hrADh2KKNA6bPr9gyAEdOY05GplW4OQJG6BTxVwfTZ8XWU0C546FuUts9L9mDJBl
# ud/fMk2qN5SVRNftCkh6lbkf02iK3EyhghLxMIIS7QYKKwYBBAGCNwMDATGCEt0w
# ghLZBgkqhkiG9w0BBwKgghLKMIISxgIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBVQYL
# KoZIhvcNAQkQAQSgggFEBIIBQDCCATwCAQEGCisGAQQBhFkKAwEwMTANBglghkgB
# ZQMEAgEFAAQg12KGaF704aO5ATqmILivcT3FuAtiXWmrmuIab+NuJKACBmGBv6X+
# +RgTMjAyMTExMTExNjUzMzQuMTI5WjAEgAIB9KCB1KSB0TCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjBB
# NTYtRTMyOS00RDREMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloIIORDCCBPUwggPdoAMCAQICEzMAAAFbfLC6NGc3wacAAAAAAVswDQYJKoZI
# hvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjEwMTE0
# MTkwMjE2WhcNMjIwNDExMTkwMjE2WjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVl
# cnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjBBNTYtRTMyOS00RDRE
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyCR/pez12qF6y6YuW2eXqXCOIPWOH4in
# P/qPmrkJDNKdtpW6jgqIKJKmvla2qpWUPudP/dZfpXq9yk1BXlx21VXBp82kuffI
# X59E2hRaHVD27xcaJJfxjNVLyrrwk8WJE7gczMyksJpKNx9Bkh3oKK6TItCu4qdI
# XB0aEzETsYJrJpDxkPIQ8ez8LbHgABgwWxU6yxJ1HyNvx/MB6TdI2Vm1Up3QpvyK
# j7deRDngy9RdX1xUvX94N1dVUEGo6EfOgmzL5zbL+zdb6ARfxBv079uMGRHqEho7
# AQDDs27jT9MxV/BcnuDlH8c1cK3tzghqM03hb4K6B7KwudhupGZb6QIDAQABo4IB
# GzCCARcwHQYDVR0OBBYEFGXnLTWIbbdTIF1Mf/XlOcmYuqsuMB8GA1UdIwQYMBaA
# FNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8y
# MDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAt
# MDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJ
# KoZIhvcNAQELBQADggEBAKczazumExqZzhB1WiWs7VldGIMxRV2C73/KryDuQhWX
# 5+SVRXZWWi63r5+k6oAad7Ay3B6cW1qBWFUnwdq7w3CT4gCEHQHTgOhs0PDu/goR
# MBF/wo3yBMfoHtGMeGt4wNaDuJxXQOyiPwwgDwCKtaXB/ievykofSfasROx4EkNZ
# zd1tTQhMkQfVHMWEaRbsjM09AI7XrlOns0udeniZpnOhXHw/KI407p/INmvTKpW6
# H06pYf589lhD9hgXKHHL6EdY66pilzzc+GfW8DQB7X5afhud7pkaM/FEjqzGwwiR
# 0FcPQckvI3th9Kts5UBjCNhY4et6wZm6+gRoSANFZSswggZxMIIEWaADAgECAgph
# CYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2
# NTVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvt
# fGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzX
# Tbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+T
# TJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9
# ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDp
# mc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIw
# EAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1V
# MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMB
# Af8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1Ud
# HwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3By
# b2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQRO
# MEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2Vy
# dHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIw
# gY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIg
# HQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4g
# HTANBgkqhkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7P
# BeKp/vpXbRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2
# zEBAQZvcXBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95
# gWXZqbVr5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7
# Yl+a21dA6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt
# 0uGc+R38ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2
# onGqBooPiRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA
# 3+cxB6STOvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7
# G4kqVDmyW9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Ki
# yc8ZQU3ghvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5X
# wdHeMMD9zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P
# 3nSISRKhggLSMIICOwIBATCB/KGB1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMg
# UHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjBBNTYtRTMyOS00
# RDREMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEw
# BwYFKw4DAhoDFQAKu0FupjLSv5gYu1RoVVFb9iHupqCBgzCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5TdydjAiGA8y
# MDIxMTExMTE0NDQwNloYDzIwMjExMTEyMTQ0NDA2WjB3MD0GCisGAQQBhFkKBAEx
# LzAtMAoCBQDlN3J2AgEAMAoCAQACAhtwAgH/MAcCAQACAhFtMAoCBQDlOMP2AgEA
# MDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAI
# AgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAQJZn5jXYGKSWn0E81/DqPoy2XjjY
# JvjMds0tFVjhLh0J4rwu1duVBgRqzX7LlTHh+YtKazpAO4gkv6gF08PoXLAUZgoj
# CTXeShHaF7A/OYfLAwJHmtbjTalrL8HmT+OPstt0rOJOLFpRlZNBn/YBtdtBbPiy
# DESDdwwd5vvk0vsxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAVt8sLo0ZzfBpwAAAAABWzANBglghkgBZQMEAgEFAKCCAUow
# GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCChKrQB
# ymGMHwPPI+foRRdkvm0a3+iBodml6giKSr+tIzCB+gYLKoZIhvcNAQkQAi8xgeow
# gecwgeQwgb0EIMki4KkoYxGHiUIa5wY8cI0nuOr0xNt7eZDYW1JksIUZMIGYMIGA
# pH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFbfLC6NGc3wacA
# AAAAAVswIgQguUKyTgbae6yobZxgygv4VCyPFhLo6Lb4Gr8iBn+0dwUwDQYJKoZI
# hvcNAQELBQAEggEAgHy2bGtkFcAYfVMi8fyW28GRK4ZkL/0+iC0dEWJhmAF7uEe3
# ioBjEChCMmvzScWjCry7tsYtAKY7Kx3NgDXLIrEf7fzrr5VXwEn/Zpo+dIZaM7qz
# 0FiUO60V2wgmaYO0hFuV5FuqPIVQ5eFwzJFRCP7ZvwS5ZVBpHvJl+o7lHhlIMtdX
# 8Pv2iA0Md1mjpKshkULt9uxoHswihwUyXmtPnV7EVVHwKxZ5L3xyYUCAmTNohHWp
# /Y9PQJ2RFGbE2CFPe6Z/hGV1fu/MzdHs3awtpuP4GVw+9uAnfHgn37pT3zH3k9DD
# IHgidb4oCFEkfkPUjumfzxEicAYNdBbs+bKkqA==
# SIG # End signature block
