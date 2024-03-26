#************************************************ 
# DC_TrustList.ps1 
# Version 1.0 
# Date: 1/14/2014 
# Author: Tim Springston [MS] 
# Description:  This script queries for the user and computer domain
#  and returns details about those domains.
#************************************************ 
Import-LocalizedData -BindingVariable ADInfoStrings
Write-DiagProgress -Activity $AdInfoStrings.ID_ADInfo_Status -Status   $AdInfoStrings.ID_ADInfo_Wait
#| WriteTo-StdOut -shortformat

Trap [Exception]
		{
		 #Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 WriteTo-StdOut "[info]:An exception occurred." -shortformat
		 WriteTo-StdOut "[info]: Exception.Message $ExceptionMessage."
		 WriteTo-ErrorDebugReport -ErrorRecord $_
		 $Error.Clear()
		 continue
		}

#Define output file.
$FileDescription = "Text File containing a detailed export of all trusts in the forest."
$SectionDescription = "Active Directory Forest Trusts List (TXT)"
$ExportFile = Join-Path $Pwd.Path ($ComputerName + "_TrustList.txt")

$global:FormatEnumerationLimit = -1

"This text file contains information on all trusts: Forest, External, Shortcut and ParentChild." | Out-File $ExportFile -encoding UTF8

$ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$ForestString = $ForestInfo.Name.ToString()	
#_ToDo:# $Trusts = $ForestInfo.GetAllTrustRelationships()														#_#<-  currently we fail and exit here
$ContextType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain
$DirContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($ContextType,$ForestString)
$Forest = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DirContext)
	
"List of All Trusts in Forest $ForestInfo" | Out-File $ExportFile -Append -encoding UTF8
"****************************************" | Out-File $ExportFile -Append -encoding UTF8
"ForestString: $ForestString " | Out-File $ExportFile -Append -encoding UTF8 									#_#
"`n*** skip  Trusts info for now here, Forest: $ForestString ***" | Out-File $ExportFile -Append -encoding UTF8 #_#
"****************************************`n" | Out-File $ExportFile -Append -encoding UTF8 						#_#
<#
ForEach ($Trust in $Trusts)
	{
	$TrustObject = New-Object PSObject
	Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Trust Source' -Value $Trust.SourceName
	Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Trust Target' -Value $Trust.TargetName
	Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Trust Type' -Value $Trust.TrustType
	Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Trust Direction' -Value $Trust.TrustDirection
	if ($Trust.TrustedDomainInformation -ne $null)
		{
		add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Forest Trusted Domain Information' -Value ($Trust.get_TrustedDomainInformation())
		}
		else
		{add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Forest Trusted Domain Information' -Value "None Defined"}
	if ($Trust.TopLevelNames -ne $null)
		{
		add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Forest Trust TopLevelNames' -Value ($Trust.get_TopLevelNames())
		}
		else
		{add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Forest Trust TopLevelNames' -Value "None Defined"}
	if ($Trust.ExcludedTopLevelNames -ne $null)
		{
		$Trust.ExcludedTopLevelNames
		add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Forest Trust Excluded TopLevelNames' -Value ($Trust.get_ExcludedTopLevelNames())
		}
		else
		{add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Forest Trust Excluded TopLevelNames' -Value "None Defined"}
	Try {
		$TrustingDomainString = $Trust.Targetname.ToString()
		$SidFilteringStatus = $Forest.GetSidFilteringStatus($TrustingDomainString)
		$SelectiveAuthStatus = $Forest.GetSelectiveAuthenticationStatus($TrustingDomainString)
		WriteTo-StdOut "Testing Security options for trusted domain $DomainString for trusting domain $TrustingDomainString"
		Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'SID Filtering Enabled' -Value $SidFilteringStatus
		Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Selective Authentication Enabled' -Value $SelectiveAuthStatus
		}
		Catch {
			Trap [Exception]
				{
				#Handle exception and throw it to the stdout log file. Then continue with function and script.
				$Script:ExceptionMessage = $_
		 		WriteTo-StdOut "[info]:An exception occurred." -shortformat
		 		WriteTo-StdOut "[info]: Exception.Message $ExceptionMessage."
		 		WriteTo-ErrorDebugReport -ErrorRecord $_
				$Error.Clear()
				continue
				}
			}
	$TrustTitleString = 'Trust Details for ' + $TrustObject.'Trust Source' + '-' + $TrustObject.'Trust Target'
	$TrustTitleString | Out-File $ExportFile -Append -encoding UTF8
	#"****************************" | Out-File $ExportFile -Append -encoding UTF8
	$TrustObject | Out-File $ExportFile -Append -encoding UTF8
	$TrustTitleString = $null
	$TrustObject = $null
	}
if ($Trusts.count -lt 1)
	{
	"No trusts found." | Out-File $ExportFile -Append -encoding UTF8
	}
#> #_#

$DomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$DomainString = $DomainInfo.Name.ToString()
$ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$InternalDomains = $ForestInfo.Domains
$ContextType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain
$DirContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($ContextType,$DomainString)
$Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DirContext)
$Trusts = @()
foreach ($Sibling in $InternalDomains)
	{
	if ($Sibling.Name -ne $DomainInfo.Name)
		{$Trusts += $Sibling.Name}
	}
"List of All Internal Trusts For Domain $DomainString" | Out-File $ExportFile -Append -encoding UTF8
"****************************************" | Out-File $ExportFile -Append -encoding UTF8

ForEach ($Trust in $Trusts)
	{
	$Trust =  $DomainInfo.GetTrustRelationship($Trust)
	$TrustObject = New-Object PSObject
	Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Trust Source' -Value $Trust.SourceName
	Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Trust Target' -Value $Trust.TargetName
	Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Trust Type' -Value $Trust.TrustType
	Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Trust Direction' -Value $Trust.TrustDirection
	Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Trusted Domain Information' -Value "Not Applicable"
	Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Trust TopLevelNames' -Value "Not Applicable"
	Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Trust Excluded TopLevelNames' -Value "Not Applicable"

	Try {
		$TrustingDomainString = $Trust.Targetname.ToString()
		$SidFilteringStatus = $Domain.GetSidFilteringStatus($TrustingDomainString)
		$SelectiveAuthStatus = $Domain.GetSelectiveAuthenticationStatus($TrustingDomainString)
		WriteTo-StdOut "Testing Security options for trusted domain $DomainString for trusting domain $TrustingDomainString"
		Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'SID Filtering Enabled' -Value $SidFilteringStatus
		Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Selective Authentication Enabled' -Value $SelectiveAuthStatus
		}
		Catch {
			Trap [Exception]
				{
				#Handle exception and throw it to the stdout log file. Then continue with function and script.
				$Script:ExceptionMessage = $_
		 		WriteTo-StdOut "[info]:An exception occurred." -shortformat
		 		WriteTo-StdOut "[info]: Exception.Message $ExceptionMessage."
		 		WriteTo-ErrorDebugReport -ErrorRecord $_
				$Error.Clear()
				continue
				}
			}
	$TrustTitleString = 'Trust Details for ' + $TrustObject.'Trust Source' + '-' + $TrustObject.'Trust Target'
	$TrustTitleString | Out-File $ExportFile -Append -encoding UTF8
	#"****************************" | Out-File $ExportFile -Append  -encoding UTF8
	$TrustObject | Out-File $ExportFile -Append -encoding UTF8
	$TrustTitleString = $null
	$TrustObject = $null
	}

if ($Trusts.count -lt 1)
	{
	"No trusts found." | Out-File $ExportFile -Append -encoding UTF8
	}

$DomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$ContextType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain
$DirContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($ContextType,$DomainString)
$Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DirContext)
$DomainString = $DomainInfo.Name.ToString()
$Trusts = $DomainInfo.GetAllTrustRelationships()
"List of All External Trusts For Domain $DomainString" | Out-File $ExportFile -Append  -encoding UTF8
"****************************************" | Out-File $ExportFile -Append -encoding UTF8

ForEach ($Trust in $Trusts)
	{
	$TrustObject = New-Object PSObject
	Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Trust Source' -Value $Trust.SourceName
	Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Trust Target' -Value $Trust.TargetName
	Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Trust Type' -Value $Trust.TrustType
	Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Trust Direction' -Value $Trust.TrustDirection
	Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Trusted Domain Information' -Value "Not Applicable"
	Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Trust TopLevelNames' -Value "Not Applicable"
	Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Trust Excluded TopLevelNames' -Value "Not Applicable"
	Try {
		$TrustingDomainString = $Trust.Targetname.ToString()
		$SidFilteringStatus = $Domain.GetSidFilteringStatus($TrustingDomainString)
		$SelectiveAuthStatus = $Domain.GetSelectiveAuthenticationStatus($TrustingDomainString)
		WriteTo-StdOut "Testing Security options for trusted domain $DomainString for trusting domain $TrustingDomainString"
		Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'SID Filtering Enabled' -Value $SidFilteringStatus
		Add-Member -InputObject $TrustObject -MemberType NoteProperty -Name 'Selective Authentication Enabled' -Value $SelectiveAuthStatus
		}
		Catch {
			Trap [Exception]
				{
				#Handle exception and throw it to the stdout log file. Then continue with function and script.
				$Script:ExceptionMessage = $_
		 		WriteTo-StdOut "[info]:An exception occurred." -shortformat
		 		WriteTo-StdOut "[info]: Exception.Message $ExceptionMessage."
		 		WriteTo-ErrorDebugReport -ErrorRecord $_
				$Error.Clear()
				continue
				}
			}
	$TrustTitleString = 'Trust Details for ' + $TrustObject.'Trust Source' + '-' + $TrustObject.'Trust Target'
	$TrustTitleString | Out-File $ExportFile -Append -encoding UTF8
	#"****************************" | Out-File $ExportFile -Append  -encoding UTF8
	$TrustObject | Out-File $ExportFile -Append  -encoding UTF8
	$TrustTitleString = $null
	$TrustObject = $null
	}

if ($Trusts.count -lt 1)
	{
	"No trusts found." | Out-File $ExportFile -Append -encoding UTF8
	}
CollectFiles -filesToCollect $ExportFile -fileDescription $FileDescription -sectionDescription $SectionDescription -renameOutput $false


# SIG # Begin signature block
# MIInugYJKoZIhvcNAQcCoIInqzCCJ6cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDyfB1hQjQ/A8ha
# jeAM/iGNPrFzRuyK4OAMUzRG9kEzX6CCDYEwggX/MIID56ADAgECAhMzAAACUosz
# qviV8znbAAAAAAJSMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjEwOTAyMTgzMjU5WhcNMjIwOTAxMTgzMjU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDQ5M+Ps/X7BNuv5B/0I6uoDwj0NJOo1KrVQqO7ggRXccklyTrWL4xMShjIou2I
# sbYnF67wXzVAq5Om4oe+LfzSDOzjcb6ms00gBo0OQaqwQ1BijyJ7NvDf80I1fW9O
# L76Kt0Wpc2zrGhzcHdb7upPrvxvSNNUvxK3sgw7YTt31410vpEp8yfBEl/hd8ZzA
# v47DCgJ5j1zm295s1RVZHNp6MoiQFVOECm4AwK2l28i+YER1JO4IplTH44uvzX9o
# RnJHaMvWzZEpozPy4jNO2DDqbcNs4zh7AWMhE1PWFVA+CHI/En5nASvCvLmuR/t8
# q4bc8XR8QIZJQSp+2U6m2ldNAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUNZJaEUGL2Guwt7ZOAu4efEYXedEw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDY3NTk3MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAFkk3
# uSxkTEBh1NtAl7BivIEsAWdgX1qZ+EdZMYbQKasY6IhSLXRMxF1B3OKdR9K/kccp
# kvNcGl8D7YyYS4mhCUMBR+VLrg3f8PUj38A9V5aiY2/Jok7WZFOAmjPRNNGnyeg7
# l0lTiThFqE+2aOs6+heegqAdelGgNJKRHLWRuhGKuLIw5lkgx9Ky+QvZrn/Ddi8u
# TIgWKp+MGG8xY6PBvvjgt9jQShlnPrZ3UY8Bvwy6rynhXBaV0V0TTL0gEx7eh/K1
# o8Miaru6s/7FyqOLeUS4vTHh9TgBL5DtxCYurXbSBVtL1Fj44+Od/6cmC9mmvrti
# yG709Y3Rd3YdJj2f3GJq7Y7KdWq0QYhatKhBeg4fxjhg0yut2g6aM1mxjNPrE48z
# 6HWCNGu9gMK5ZudldRw4a45Z06Aoktof0CqOyTErvq0YjoE4Xpa0+87T/PVUXNqf
# 7Y+qSU7+9LtLQuMYR4w3cSPjuNusvLf9gBnch5RqM7kaDtYWDgLyB42EfsxeMqwK
# WwA+TVi0HrWRqfSx2olbE56hJcEkMjOSKz3sRuupFCX3UroyYf52L+2iVTrda8XW
# esPG62Mnn3T8AuLfzeJFuAbfOSERx7IFZO92UPoXE1uEjL5skl1yTZB3MubgOA4F
# 8KoRNhviFAEST+nG8c8uIsbZeb08SeYQMqjVEmkwggd6MIIFYqADAgECAgphDpDS
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZjzCCGYsCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAlKLM6r4lfM52wAAAAACUjAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg4X/ot8Gr
# PNNKc1rTZT2TtVdS01cOoteHEZPk+5R7RvgwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCNkizuBaI/cbSHozXQTF6RYaGiOpuCvdReGXy8M+K+
# 5b0C3jqteNQdxBGQL1OmxxIzaZOuSrh4JScsB1Hb/QG3JIg2v1crwQUhl53IzPIP
# kjSsN8d7nEjiGrFv3Agmynv+jWbHokxudz/86SO7s1tFzFStdvfiUSBHRNFpnSq6
# OwCTWqWcIfFYpfQdCZdIl9564r58bS0PEg9aTqvRkGSUwtRWwu9Iq5BquF5I0854
# bjQjLr3RiK4Ovx9sCW/SrIgX+/LhNtLPD1RrkgmeqfIqQaRX4aCULhgbjCjVjrHE
# Oc0fUPTmW5W5xi0QKJO2iz/EM7eDQQOnpn0t41ns8T0uoYIXGTCCFxUGCisGAQQB
# gjcDAwExghcFMIIXAQYJKoZIhvcNAQcCoIIW8jCCFu4CAQMxDzANBglghkgBZQME
# AgEFADCCAVkGCyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIAk+gqex3S+An78fIvwdXXo/7NMK5Z8JUL8d+Sc6
# FPZKAgZhwh7GbOUYEzIwMjIwMTE0MTYzMzU3LjIzOFowBIACAfSggdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046M0JENC00QjgwLTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WgghFoMIIHFDCCBPygAwIBAgITMwAAAYm0v4YwhBxL
# jwABAAABiTANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDAeFw0yMTEwMjgxOTI3NDFaFw0yMzAxMjYxOTI3NDFaMIHSMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQg
# SXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjNCRDQtNEI4MC02OUMzMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvQZXxZFm
# a6plmuOyvNpV8xONOwcYolZG/BjyZWGSk5JOGaLyrKId5VxVHWHlsmJE4Svnzsdp
# sKmVx8otONveIUFvSceEZp8VXmu5m1fu8L7c+3lwXcibjccqtEvtQslokQVx0r+L
# 54abrNDarwFG73IaRidIS1i9c+unJ8oYyhDRLrCysFAVxyQhPNZkWK7Z8/VGukaK
# LAWHXCh/+R53h42gFL+9/mAALxzCXXuofi8f/XKCm7xNwVc1hONCCz6oq94AufzV
# NkkIW4brUQgYpCcJm9U0XNmQvtropYDn9UtY8YQ0NKenXPtdgLHdQ8Nnv3igErKL
# rWI0a5n5jjdKfwk+8mvakqdZmlOseeOS1XspQNJAK1uZllAITcnQZOcO5ofjOQ33
# ujWckAXdz+/x3o7l4AU/TSOMzGZMwhUdtVwC3dSbItpSVFgnjM2COEJ9zgCadvOi
# rGDLN471jZI2jClkjsJTdgPk343TQA4JFvds/unZq0uLr+niZ3X44OBx2x+gVlln
# 2c4UbZXNueA4yS1TJGbbJFIILAmTUA9Auj5eISGTbNiyWx79HnCOTar39QEKozm4
# LnTmDXy0/KI/H/nYZGKuTHfckP28wQS06rD+fDS5xLwcRMCW92DkHXmtbhGyRilB
# OL5LxZelQfxt54wl4WUC0AdAEolPekODwO8CAwEAAaOCATYwggEyMB0GA1UdDgQW
# BBSXbx+zR1p4IIAeguA6rHKkrfl7UDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAx
# MCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3Rh
# bXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4ICAQCOtLdpWUI4KwfLLrfaKrLB92Dq
# bAspGWM41TaO4Jl+sHxPo522uu3GKQCjmkRWreHtlfyy9kOk7LWax3k3ke8Gtfet
# fbh7qH0LeV2XOWg39BOnHf6mTcZq7FYSZZch1JDQjc98+Odlow+oWih0Dbt4CV/e
# 19ZcE+1n1zzWkskUEd0f5jPIUis33p+vkY8szduAtCcIcPFUhI8Hb5alPUAPMjGz
# wKb7NIKbnf8j8cP18As5IveckF0oh1cw63RY/vPK62LDYdpi7WnG2ObvngfWVKtw
# iwTI4jHj2cO9q37HDe/PPl216gSpUZh0ap24mKmMDfcKp1N4mEdsxz4oseOrPYeF
# sHHWJFJ6Aivvqn70KTeJpp5r+DxSqbeSy0mxIUOq/lAaUxgNSQVUX26t8r+fciko
# fKv23WHrtRV3t7rVTsB9YzrRaiikmz68K5HWdt9MqULxPQPo+ppZ0LRqkOae466+
# UKRY0JxWtdrMc5vHlHZfnqjawj/RsM2S6Q6fa9T9CnY1Nz7DYBG3yZJyCPFsrgU0
# 5s9ljqfsSptpFdUh9R4ce+L71SWDLM2x/1MFLLHAMbXsEp8KloEGtaDULnxtfS2t
# YhfuKGqRXoEfDPAMnIdTvQPh3GHQ4SjkkBARHL0MY75alhGTKHWjC2aLVOo8obKI
# Bk8hfnFDUf/EyVw4uTCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUw
# DQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhv
# cml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg
# 4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aO
# RmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41
# JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5
# LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL
# 64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9
# QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj
# 0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqE
# UUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0
# kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435
# UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB
# 3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTE
# mr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwG
# A1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNV
# HSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNV
# HQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo
# 0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29m
# dC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5j
# cmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDAN
# BgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4
# sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th54
# 2DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRX
# ud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBew
# VIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0
# DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+Cljd
# QDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFr
# DZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFh
# bHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7n
# tdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+
# oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6Fw
# ZvKhggLXMIICQAIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JENC00Qjgw
# LTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoB
# ATAHBgUrDgMCGgMVACGlCa3ketyeuey7bJNpWkMuiCcQoIGDMIGApH4wfDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDli5faMCIY
# DzIwMjIwMTE0MTQzNDAyWhgPMjAyMjAxMTUxNDM0MDJaMHcwPQYKKwYBBAGEWQoE
# ATEvMC0wCgIFAOWLl9oCAQAwCgIBAAICBo4CAf8wBwIBAAICET4wCgIFAOWM6VoC
# AQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEK
# MAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQCBwf6745bSLh6K3eR8xNhFjv/S
# T2e/mpaKq1F7guPFCCZSu+elA2FoPWVGzz0vH2YywAf3/V/fXSGgL4nRbAcwgXVj
# 7rpCU95R5dHtshekLwP7PW8rdSLqA7duqeBKDrv+mclq3q5Ofsz6IPJFXLvIrfQf
# VZagfiFqY0Yg4omEazGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABibS/hjCEHEuPAAEAAAGJMA0GCWCGSAFlAwQCAQUAoIIB
# SjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEILXj
# z386ddS5JRBFutExiYHcr4MVS0UwnJeBLU+lC9z0MIH6BgsqhkiG9w0BCRACLzGB
# 6jCB5zCB5DCBvQQgZndHMdxQV1VsbpWHOTHqWEycvcRJm7cY69l/UmT8j0UwgZgw
# gYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYm0v4YwhBxL
# jwABAAABiTAiBCAtzZQTFxySbA+g2uO2zdionOxQt1feEbpWgediu8L0ijANBgkq
# hkiG9w0BAQsFAASCAgCo5k5QunlbPeiwA4SeRGaJ37Ct0GOhjXdSy0kwz7uKG+7C
# tdshHo5/qB425W3g1lM1z538fkj6EIKRI3GZPpNa7xn/nTaN78yOaAhUj/QACll9
# H+3PZNxGeGA/YKmzLmuoJu6kjsfZe7MC+9b/WnR0UhpgDuU1vav+xexl4JUoF3eT
# kHSXEo+pT48NHfDuQeWdI9mvKbhfjhDQhI+EDulAtoaanHqZA1vkz4arINRORp41
# uA3BUX0rK9xfydC0dn6/PhWtNE498rem8zXB9wklkpEAaDXlbmRuirVas0rNHSVd
# iZFsgFpFobZUBQ3+DZG3uv+1SpfmmhF5MKlDdgHH1VNtVpm6o33StVM6vvh96xHK
# kB6+CSv8IFCmTiaWIUEqHyJyHElZ3RwKb/QWWwU1s2Jtjna8OdFSvm6cwvdXt3n1
# VjdpUHVkxnPn55YcxyZF1PUdl0wcttkuLID+Y7lYj1X/l+U7OLAkYkMRvFLo9/b6
# s8bT2+zNXHshmLxXzcAaNqHzZ3da5adEeFKDr71Gns2Bg0THmxZtxZTHrQojx8Fw
# m0AqwqwW4tYQs+WvKXSC4j6EgEuMcnqyrKgij0rPqzBIWpfGAxMVcG4oXaLt/K0h
# jXgFsZW34GjoKA6Ra4yCazCx4YQyPc6Qu1t2egCww6p3vJrk5S9v7f6TQa41FA==
# SIG # End signature block
