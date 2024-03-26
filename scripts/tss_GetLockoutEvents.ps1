# Name tss_GetLockoutEvents.ps1

<# 
.SYNOPSIS
 Script to find Account Lockout: PowerShell script collects Security events from all DCs related with Bad Password attempts

.DESCRIPTION
 PowerShell script sample to assist in troubleshooting account lockout issues. It can be used to collect Security Events from all DCs in a given forest or domain.
 It collects events like 4625, 4771, 4776 with error codes 0x18 and c000006a respectively.
 You do not have to run the script elevated. However you have to run it with *domain admin* privileges.
 It can be run against any domain in the forest you logon to run the script. Running against a different domain may need you to run the script with other domain admin privileges or Enterprise Admin.
 Script can also detect trusted domains and collect events from remote DCs. Make sure that the domain admin running the script has the permission to collect events remotely from trusted domains.

.PARAMETER UserName
 Please enter the UserName (sAMAccountName)
 
.PARAMETER DomainName
 Please enter the NetBIOS or FQDN of any domain in the forest
 
.PARAMETER DataPath
 This switch determines the path for output files
 
.EXAMPLE
 .\tss_GetLockoutEvents.ps1 -UserName "User1" -DomainName "Contoso" -DataPath "C:\MS_DATA" 
 Example 1:  for User1 in domain Contoso
 
.LINK
 https://internal.support.services.microsoft.com/en-us/help/4498703
 https://microsoft.sharepoint.com/teams/HybridIdentityPOD/_layouts/15/Doc.aspx?sourcedoc={5bec59af-bf31-4073-9111-a63486fcdf0c}&action=view&wd=target%28Account%20Lockouts.one%7C9a46c4f5-38af-4648-93f2-8a976a91c463%2FWorkflow%20Account%20Lockout%20Data%20Collection%20-%20Reactive%7Cdc03d719-fff5-4bdf-b46e-15456c2521f1%2F%29
 
 Author: Ahmed Fouad (v-ahfoua@microsoft.com)
#>


# Version 1.4 - 2020.03.25 WalterE

[CmdletBinding()]
PARAM (
    [Parameter(Mandatory=$True,Position=0,HelpMessage='Enter user sAMAccountName')]
	[string]$UserName
	,
	[Parameter(Mandatory=$True,Position=1,HelpMessage='Enter DomainName')]
	[string]$DomainName
	,
	[string]$DataPath = (Split-Path $MyInvocation.MyCommand.Path -Parent)
)

#region helper functions
function CheckDomain
{	# Check domain and user variables
	try 
	{
	  Write-Host "..Checking whether domain $DomainName exists" 
	  if (Get-ADDomain $DomainName) 
	   {
		Write-Host "Domain '$DomainName' exists" -fore Green
	   }

	}
	catch 
	{
		 Write-Host $_.Exception.Message -fore Red
		 break 
	}
}

function CheckUser
{	# Check whether the user exist or not
	try
	{
	   Write-Host "..Checking whether AD user $UserName exists" 
	   if (Get-ADUser -Identity $UserName -Server $DomainName) 
		{
		 Write-Host "AD user '$UserName' exists in '$DomainName' domain" -fore Green
		}
	}
	catch 
	{
		Write-Host  $_.Exception.Message -fore Red
		break 
	}
}

function CheckDomainAdmin
{
	Write-Host "..Checking whether the current user $env:Username has domain admin privilege" 

	if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("$DomainName\Domain Admins") -and  (-not  ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Enterprise Admins") ) ) 
	  {
		Write-Host "Sorry you '$env:Username' don't have domain admin privilege to run this script" -fore Red
		Break
	  }
	Else 
	  {
		Write-Host "User '$UserName' is member of '$DomainName\Domain Admins'" -fore Green 
	  }
}
#endregion helper functions


#region variables

[xml]$xmlfilter = "<QueryList> 
           <Query Id='0'> 
              <Select Path='Security'> 
                 *[EventData[Data[@Name='TargetUserName'] and (Data='$username')]] 
                  and 
                 *[EventData[Data[@Name='status'] and (Data='0x18')]] 
                 and
                 *[System[(EventID='4771' or EventID='4768' or EventID='4769' )]]
              </Select> 
           </Query> 
<Query Id='1'> 
              <Select Path='Security'> 
               *[EventData[Data[@Name='TargetUserName'] and (Data='$username')]] 
               and  
               *[EventData[Data[@Name='substatus'] and (Data='0xc000006a')]] 
                  and
               *[System[(EventID='4625' )]] 
               </Select> 
           </Query> 
<Query Id='2'> 
              <Select Path='Security'> 
               *[EventData[Data[@Name='TargetUserName'] and (Data='$username')]] 
                  and
               *[System[(EventID='4740' or EventID='4767' )]] 
               </Select> 
           </Query> 
<Query Id='3'> 
              <Select Path='Security'> 
               *[EventData[Data[@Name='TargetUserName'] and (Data='$username')]] 
               and  
               *[EventData[Data[@Name='Status'] and (Data='0xc000006a')]] 
                  and
               *[System[(EventID='4776' )]] 
               </Select> 
           </Query> 

</QueryList>"

#_# $DataPath = read-host "Please enter the path of the report (leave it blank to use the default path)"

if ($DataPath)
    {
      $fullpath = $DataPath
      New-Item -ItemType Directory -Path $fullpath\LockoutLogs -ErrorAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null
    }
Else 
    {
     $fullpath = (get-location).path
     New-Item -ItemType Directory -Path $fullpath\LockoutLogs -ErrorAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null
    
    }

$CSVPath = $fullpath + "\LockoutLogs\Report.csv" 


$AllEvents = @()
$SourceMachines = @()
$ExchangeServersIPv4 = @()

foreach ($ExchangeServer in $ExchangeServers ) 
{
   $ExchangeServersIPv4 += (Resolve-DnsName $ExchangeServer.name).IPAddress

}

#endregion variables

function GetEventsFromAllDCs
{
	$Dcs = Get-ADDomainController -Filter * -Server $DomainName
	#get events from all domain controllers
	foreach ($dc in $Dcs)
	{
	$serverName = $dc.HostName
	Write-Host "Checking connectivity to DC:" $serverName 
	$PingStatus = Get-WmiObject win32_pingStatus -Filter "Address = '$serverName'"

	if ($PingStatus.StatusCode -eq 0)
		{  
		  Write-Host $serverName  " is Online" -fore Green
		  Write-Host "Collecting logs from:" $serverName
		  $Events = get-winevent -FilterXml $xmlfilter -ComputerName $serverName -ErrorAction SilentlyContinue  
		  foreach ($event in $events)
		  {
		   $eventxml = [xml]$event.ToXml()

		   if ($event.Id -eq "4771")
			 {
			  $ipv4 = ($eventxml.Event.EventData.Data[6].'#text').Split(":")
			  $myObject = New-Object System.Object
			  $myObject | Add-Member -type NoteProperty -name "Source Machine" -Value $ipv4[($ipv4.length -1 )]
			  $myObject | Add-Member -type NoteProperty -name "Event ID" -Value "4771"
			  $SourceMachines += $myObject
			 } 
		   if ($event.Id -eq "4776")
			 {
			  $ipv4 = Resolve-DnsName ($eventxml.Event.EventData.Data[2].'#text')
			  $myObject = New-Object System.Object
			  $myObject | Add-Member -type NoteProperty -name "Source Machine" -Value $ipv4.IPAddress
			  $myObject | Add-Member -type NoteProperty -name "Event ID" -Value "4776"
			  $SourceMachines += $myObject
			   
			 }
		   if ($event.Id -eq "4625")
			 {
			  $ipv4 = Resolve-DnsName ($eventxml.Event.EventData.Data[2].'#text')
			  $myObject = New-Object System.Object
			  $myObject | Add-Member -type NoteProperty -name "Source Machine" -Value $ipv4.IPAddress
			  $myObject | Add-Member -type NoteProperty -name "Event ID" -Value "4625"
			  $SourceMachines += $myObject
			 }
		  }
		  if ($($Events.count) -eq 0) {
			Write-Host "[Info] Found $($Events.count) Events on $serverName for $UserName" -ForegroundColor Cyan
		  } else { Write-Host "[Warning] Found $($Events.count) Events on $serverName for $UserName" -BackgroundColor Red}
 		  
		  $AllEvents += $Events
		}
	Else 
	   {
		 Write-Host "$serverName is offline" -fore Red
	   }
	}

	# save the report 
	if ($AllEvents -ne 0)
	   { 
		 $AllEvents | Select-Object MachineName,TimeCreated,ProviderName,Id,@{n='Message';e={$_.Message -replace '\s+', " "}} | Export-Csv -Path  $CSVPath -NoTypeInformation
	   }
	if ($($AllEvents.count) -eq 0) {
		Write-Host "[Info] $($AllEvents.count) events found on all domain controllers `n" -ForegroundColor green
	} else { Write-Host "[Warning] $($AllEvents.count) events found on all domain controllers `n" -BackgroundColor Red}
	Write-Verbose "$AllEvents"

	if ($SourceMachines.Count -gt 0 )
	  {
		Write-Host "Summary of source machines for the bad password `n" -BackgroundColor Green -ForegroundColor Red
		$SourceMachines | Group-Object "Source Machine","Event ID"  -NoElement   | Sort-Object -Property Count -Descending
		$ExchangeServersIncluded = Compare-Object -ReferenceObject $SourceMachines."Source Machine"  -DifferenceObject $ExchangeServersIPv4  -IncludeEqual -ExcludeDifferent
		if ($ExchangeServersIncluded.InputObject.Length -gt 0 ) 
		   { 
			 Write-Host "`n Below Exchange Servers included in bad password source machines list `n" -BackgroundColor Green -ForegroundColor Red
			 $ExchangeServersIncluded.InputObject

			 $ExportExchangeLogs = read-host "`nDo you want to export IIS logs from mentioned Exchange servers (Yes/No)" 
			 if ($ExportExchangeLogs = "yes ")
				{
				  foreach ($ip in $ExchangeServersIncluded.InputObject)
					{
					  New-Item -ItemType Directory -Path "$fullpath\Exchange_$ip" -InformationAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
					  Copy-Item -Path \\$ip\c$\inetpub\logs\LogFiles -Destination "$fullpath\LockoutLogs\Exchange_$ip" -Recurse -Force
					}
				}
		   }
	  }
} # end GetEventsFromAllDCs

# MAIN 
CheckDomainAdmin
CheckDomain
CheckUser
GetEventsFromAllDCs

# SIG # Begin signature block
# MIInkgYJKoZIhvcNAQcCoIIngzCCJ38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCuyXxhWWTLwUiy
# ufbAHBcPVkt5DxCzOjZF8//7kFu1/6CCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJqrkRo8ETKfXRzABN1RgHFd
# wJPSvfA/OJViSv1NAPOKMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEA1t0R84lQlXUeiWIr32fRTxXDjvQe0ZlTQevmUF/h/01T6/4sRgi4TcRi
# kIG+zh4uz6O+ssGJaFjut8f70sDspWDDG/mBKvM713B+7kevAgJ6h7B2omZPSsbT
# vwxmhlQ7DsDYLbfubWRxAxJjV787ANaG0VvksOCBFFpqmSEeY3T2xIDjAmZucCKY
# FY3gKwCZsJkrF1b6LjdFpg6LODGn7RzkmFMXQw9UMiuIPwhZeBSqRXZWUL/JBmpl
# hoClqooiIiejukMyNdmyq6H5xrldCqIbexnaOBnhWzCqdWBF0ueSTktbtbgLIS7m
# 3twWp53CJK8j1IqFUaB98I+4goPOM6GCFvwwghb4BgorBgEEAYI3AwMBMYIW6DCC
# FuQGCSqGSIb3DQEHAqCCFtUwghbRAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFQBgsq
# hkiG9w0BCRABBKCCAT8EggE7MIIBNwIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCAUID6Wav55WRIuo6uHMJzVYFv5AcK4qSZohrxkSe4OuQIGZGzaWyFS
# GBIyMDIzMDYwNjExNDU1MC4zMVowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkVBQ0UtRTMx
# Ni1DOTFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIR
# VDCCBwwwggT0oAMCAQICEzMAAAHDi2/TSL8OkV0AAQAAAcMwDQYJKoZIhvcNAQEL
# BQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkwMTI5
# WhcNMjQwMjAyMTkwMTI5WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEm
# MCQGA1UECxMdVGhhbGVzIFRTUyBFU046RUFDRS1FMzE2LUM5MUQxJTAjBgNVBAMT
# HE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQC767zqzdH+r6KSizzRoPjZibbU0M5m2V01HEwVTGbij2RV
# aRKHZzyM4LElfBXYoWh0JPGkZCz2PLmdQj4ur9u3Qda1Jg8w8+163jbSDPAzUSxH
# bqRunCUEfEVjiGTfLcAf7Vgp/1uG8+zuQ9tdsfuB1pyK14H4XsWg5G317QP92wF4
# bzQZkAXbLotYCPoLaYyqVp9eTBt9PJBqe5frli77EynInV8BESm5Hvrqt4+uqUTQ
# ppp4PSeo6AatORJl4IwM8fo60nTSNczBsgPIfuXh9hF4ixN/M3kZ/dRqKuyN5r4o
# XLbaVTx6WcheOh7LHelx6wf6rlqtjVzoc995KeR4yiT+DGcHs/UyO3sj0Qj22FC0
# y/L/VJSYsbXasFH8N+F4T9Umlyb9Nh6hXXU19BCeX+MFs9tJEGnQcapMhxYOljoy
# BJ0GhARPUO+kTg9fiyd00ZzXAbKDjmkfrZkx9QX8LMZnuJXrftG2dAVcPNPGhIQS
# R1cx1YMkb6OPGgLXqVGTXEWd+QDi6iZriYqyjuq8Tp3bv4rrLMhJZDtOO61gsomd
# LM29+I2K7K//THEIBJIBG85De/1x6C8z+me5T1zqz7iCYrf7mOFy+dYZCokTS2lg
# eaTduaYEvWAeb1OMEnPmb/yu8czdHDc5SFXj/CYAvfYqY9HlRtvjDDkc0aK5jQID
# AQABo4IBNjCCATIwHQYDVR0OBBYEFBwYvs3Y128BorxNwuvExOxrxoHWMB8GA1Ud
# IwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRp
# bWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYI
# KwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMv
# TWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1Ud
# EwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIB
# AN3yplscGp0EVEPEYbAOiWWdHJ3RaZSeOqg/7lAIfi8w8G3i6YdWEm7J5GQMQuRN
# Zm5aordTXPYecZq1ucRNwdSXLCUf7cjtHt9TTMpjDY8sD5VrAJyuewgKATfbjYSw
# QL9nRhTvjQ0n/Fu7Osa1MS1QiJC+vYAI8nKGw+i17wi1N/i41bgxujVA/S2NwEoK
# AR7MgLgNhQzQFgJYKZ5mY3ACXF+lOWI4UQoH1RpKodKznVwfwljSCovcvAj0th+M
# Q7vv74dj+cypcIyL2KFQqginZN+N/N2bk2DlX7LDz7BeXb1FxbhDgK8ee018rFP2
# hDcntgFBAQdYk+DxM1H3DgHzYXOasN3ywvoRO8a7HmEVzCYX5DatPkxrx1hRJ0JK
# D+KGgRhQYlmdkv2fIOnWyd+VJVfsWkvIAvMMOUcFbUImFhV98lGirPUPiRGiipEE
# 1FowUw+KeDLDBsSCEyF4ko2h1rsAaCr7UcfVp9GUT72phb0Uox7PF5CZ/yBy4C6G
# v0gBfJoX0MXQ8nl/i6HM5K8gLUGQm3MXqinjlRhojtX71fx1zBdtkmcggAfVyNU7
# woQKHEoiSmThCDLQ+hyBTBoZaqYtZG7WFDVYladBe+8Fh5gMZZuP8+1KXLC/qbya
# 6Mt6l8y8lxTbkpaSVI/YW43Hpo5V96N76mBvAhAhVDWdMIIHcTCCBVmgAwIBAgIT
# MwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJv
# b3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcN
# MzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT
# /e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYj
# DLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/Y
# JlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d
# 9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVU
# j9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFK
# u75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231f
# gLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C
# 89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC
# +hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2
# XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54W
# cmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMG
# CSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cV
# XQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/
# BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2Nz
# L1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcU
# AgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8G
# A1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeG
# RWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jv
# b0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUH
# MAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2Vy
# QXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9n
# ATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP
# +2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27Y
# P0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8Z
# thISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNh
# cy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7G
# dP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4J
# vbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjo
# iV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TO
# PqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ
# 1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NN
# je6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAsswggI0AgEBMIH4oYHQpIHNMIHKMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNy
# b3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# TjpFQUNFLUUzMTYtQzkxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaIjCgEBMAcGBSsOAwIaAxUA8R0v4+z6HTd75Itd0bO5ju0u7s6ggYMw
# gYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUF
# AAIFAOgpJKgwIhgPMjAyMzA2MDYxMTIxMTJaGA8yMDIzMDYwNzExMjExMlowdDA6
# BgorBgEEAYRZCgQBMSwwKjAKAgUA6CkkqAIBADAHAgEAAgIi8jAHAgEAAgISszAK
# AgUA6Cp2KAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIB
# AAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAGnxnNmmT2gov2aI
# VBiEpwcMKVsFOBpGeDJsOl+hl9QnueVPiryPrgiFO9CxW3ovKGdK3CNWEFJnL0SF
# tTXaqq18Q5a6a/WvwKHe84ahgIQuZonPV2qHhOuCgbhGtrbS9cnhXJsYZKZPfQOr
# vcECdXnfQT5snQ091lRC7/838wAXMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgUENBIDIwMTACEzMAAAHDi2/TSL8OkV0AAQAAAcMwDQYJYIZIAWUD
# BAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0B
# CQQxIgQgCCDYGOg+bCFJIh+X8waAG+Yyn4jiINtPC/q2HWdNF2UwgfoGCyqGSIb3
# DQEJEAIvMYHqMIHnMIHkMIG9BCDS+1Obb5JJ6uHUqICTCslMAvFN8mi2U9wNnZlK
# fvwqSTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB
# w4tv00i/DpFdAAEAAAHDMCIEIALJoYL45BK76/7KgVSn/+ZVRJHZBXbySGIHh9fN
# ki6zMA0GCSqGSIb3DQEBCwUABIICAAVI3RZLdveOnPDzNC/llKCtWlMaVuUhdEM9
# AU/ARKGGu01Q5TYAL84cqCguQCoNf8lVTda37wIK10Brl2IrXRzRP7gqovfw0wq3
# ghnO0J56AAJ85dkQxN7knXMd82GKZ8VvB+iJK9jf8hfWPfxk5MOMLHImqQs5p1D1
# DkJ7zqdJzKCXuVePQRFnYABqmHEUsu8fvBS1+0voEi3KMf0q3xqMK0rO78CAEC3v
# Ys5FQ91Ilwu7ElPTU+Bw62wHrhUfx2dlkpTH2KyXzF4+dE1voIKlWCUGm9yT9tCl
# 4LroRhoPqwFANq/FcqzEg5iTjyVgiZDqLw6vzPKRXAYRCRfb+tDtj5jOGZr8lcXa
# hmHVN22eqXB0DwEgUAAU7sukLFiFRMT1A8XdVgn2D6Qa4nyFgmlEPEHtbNbKfMwx
# iwbFHAHhNaiQ5vYAy+4nkqMddsv3nBWu2hx9NXQY9uun7S09yIPqTdDls/5FF0Sa
# alFNGu182k5H4Iwlo4u7axeYLDDc/+5jXLXWxJMIdUIMvfzQ9siRT2PDcC7zRIS/
# KhoQVaOnAKb3zLaFv2o+pGdyp0EfC5kSxn4bjXjR3Ubx2jw6RdPyz/Oy7McGmwNX
# trpPhC8cgte+NN9Um8VbLVK1mc/yzcOfNuR4EcfyrCR9lg163Qh5cpiMkmRW5Tf7
# w7K6CT0T
# SIG # End signature block
