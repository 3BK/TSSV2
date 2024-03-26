New-Variable OLAP_SERVICE_KEY_MASK  -Value "HKLM:\System\CurrentControlSet\Services\*OLAP*"   -Option ReadOnly
New-Variable OLAP_CONFIG_FILE       -Value "MSMDSRV.INI"                                      -Option ReadOnly

function Get-SsasConfigFilePath([object]$OlapServiceKey)
{
	$Error.Clear()           
	trap 
	{
		"[Get-SsasConfigFilePath] : [ERROR] Trapped exception ..." | WriteTo-StdOut
		Report-Error
	}
    
    [string]$ConfigFilePath=$null
    
    if ($null -ne $OlapServiceKey)
    {
        $ImagePath =  (Get-ItemProperty -Path $OlapServiceKey.PSPath).ImagePath
        
        if ($null -ne $ImagePath)
        {    
            # The configu file path follows the -s command line parameter imbedded in the image path
            # Example Image Path:
            # "C:\Program Files\Microsoft SQL Server\MSAS10_50.SQL2008R2\OLAP\bin\msmdsrv.exe" -s "C:\Program Files\Microsoft SQL Server\MSAS10_50.SQL2008R2\OLAP\Config"
            $ConfigFilePath = ($ImagePath.Substring($ImagePath.IndexOf("-s")+3)).Trim("`"")
        }
        else
        {
            '[Get-SsasConfigFilePath] : [ERROR] Get-ItemProperty returned a null image path for the OLAP service' | WriteTo-StdOut
        }
        
    }
    else
    {
        '[Get-SsasConfigFilePath] : [ERROR] Required parameter -OlapServiceKey was not specified' | WriteTo-StdOut
    }
    
    return $ConfigFilePath
}

function Get-SsasInstanceName([string]$ServiceName)
{
	$Error.Clear()           
	trap 
	{
		'[Get-SsasInstanceName] : [ERROR] Trapped exception ...' | WriteTo-StdOut
		Report-Error 
	}
	
    if (($null -ne $ServiceName) -and (0 -lt $ServiceName.Length))
    {   
        
        # If named instance split the service name at the $ to get the instance name ...
        if ($ServiceName.Contains("$"))
        {
            $InstanceName = ($ServiceName.Split("$"))[1]
        }
        else
        {
            $InstanceName = $ServiceName
        }   
   }
   else
   {
        '[Get-SsasInstanceName] : [ERROR] Required parameter -ServiceName was not specified.' | WriteTo-StdOut
   }
   
   return $InstanceName
}

function CopyAndCollectSsasConfiguration([object]$OlapServiceKey)
{
	$Error.Clear()           
	trap 
	{
		"[CopyAndCollectSsasConfiguration] : [ERROR] Trapped exception ..." | WriteTo-StdOut
		Report-Error 
	}
	
    if ($null -ne $OlapServiceKey) 
    {
        # Get the instance name from the service name
        $InstanceName = Get-SsasInstanceName $OlapService.PSChildName
    	
    	if (($null -ne $InstanceName) -and (0 -lt $InstanceName.Length))
        {
            # Update msdt dialog that's displayed to user
        	Write-DiagProgress -Activity $ssasConfigurationCollectorStrings.ID_SSAS_CollectSSASConfigFile -Status ($ssasConfigurationCollectorStrings.ID_SSAS_CollectSSASConfigFileDesc + ": " + $InstanceName)
                
            # Extract the path to the config file from the imagepath
            $ConfigFilePath = Get-SsasConfigFilePath $OlapServiceKey
            
            if ($null -ne $ConfigFilePath)
            {
                # Test Config file path retrieved from the ImagePath in the registry
                if (Test-Path $ConfigFilePath -PathType "Container")
                {    
                    $FileFilters = @($OLAP_CONFIG_FILE)
                    
                    $OlapConfigFile = @()
				    $OlapConfigFile = Copy-FileSql -SourcePath $ConfigFilePath `
                         -FileFilters $FileFilters `
                         -FilePolicy $global:SQL:FILE_POLICY_CONFIGURATION_FILE `
                         -InstanceName $InstanceName `
                         -RenameCollectedFiles `
                         -LCID '1033' `
                         -SectionDescription ("OLAP Configuration File for instance: {0} on server: {1}" -f $InstanceName, $env:ComputerName)
                   
				    "[CopyAndCollectConfiguration] : [INFO] Collected OLAP configuration file: [{0}] file for instance: [{1}]" -f $OlapConfigFile, $InstanceName | WriteTo-StdOut      

                } 
                else
                {
                    "[CopyAndCollectConfiguration] : Invalid path to configuration file: [{0}]" -f $ConfigFilePath | WriteTo-StdOut
                    if ($true -eq (Check-IsSsasDiskResourceOnline $ConfigFilePath))
                    {
                        "[CopyAndCollectSsasConfiguration] : [ERROR] Path to SSAS Configuration file: [{0}] for instance: {1} is invalid" -f $DumpDir, $InstanceToCollect | WriteTo-StdOut
                    }
                }
				
			} #if ($null -ne $ConfigFilePath)
			else
			{
				'[CopyAndCollectSsasConfiguration] : [ERROR] Path to the OLAP config path collected was invalid' | WriteTo-StdOut
			}
			
        } # if ($null -ne $InstanceName)
        else
        {
            '[CopyAndCollectSsasConfiguration] : [ERROR] Get-SsasInstanceName returned a null value' | WriteTo-StdOut
        }
    } # if ($null -ne $OlapService)
    else
    {
        '[CopyAndCollectSsasConfiguration] : [ERROR} Required parameter -OlapService was not specified' |WriteTo-Stdout
    }
	
} # function CopyAndCollectSsasConfiguration()


$Error.Clear()           
trap 
{
	"[Get-OlapServerConfigurationFiles] : Trapped error ..." | WriteTo-StdOut
	Show-ErrorDetails $error[0] 
}

Import-LocalizedData -BindingVariable ssasConfigurationCollectorStrings

# Get a list of the installed SSAS services from the HKLM:\SYSTEM\CurrentControlSet key
$OlapServices = @(get-childitem $OLAP_SERVICE_KEY_MASK)

if (0 -lt $OlapServices.Count)
{
	"[DC-GetOlapServerConfigFiles] : Discovered {0} SSAS Service(s)" -f $OlapServices.Count | WriteTo-StdOut
	
    foreach ($OlapService in $OlapServices)
    {      
        "[DC-GetOlapServerConfigFiles] : Collecting server configuration for service: {0}" -f $OlapService.PsChildName | WriteTo-StdOut
        
        CopyAndCollectSsasConfiguration -OlapServiceKey $OlapService
    }
}
else
{
    "[DC_GetOlapConfig] : No OLAP services were found on server: [{0}]" -f $env:COMPUTERNAME | WriteTo-StdOut
}
 
# SIG # Begin signature block
# MIIjiAYJKoZIhvcNAQcCoIIjeTCCI3UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAblzQ8diYWfxkB
# y/0TVGJjKPru+HbESjDu8nTI03scCaCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgMH27KW72
# jhcroCRBb3W+mXBqk4qbcFxS9NICVcF+aKMwOAYKKwYBBAGCNwIBDDEqMCigCIAG
# AFQAUwBToRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20gMA0GCSqGSIb3DQEB
# AQUABIIBACNhhOs02Io45g69cmXvwN2PuN/bGu9HdCDp/Xkn0WIdXi4sqifiC4cS
# Q0EU+e384dQUs+b4/mTYc+fzwIEmi44vCd1nVp33DpzHnHvzg0smsqQ7pZnC6F2G
# zFvKC/TWiYgv/PTZ7ZPWMpD7S9VCywOTTmeXirnFG5ED/ey2mOlsJYn7+GrqCil1
# 7uoZ7pqXvKVi9tDf5h/SYlV7t7+dyYm1xQEx+rJDbN119VtCkZrRDndstWQNKCr1
# 23DN4vH9moqmUMiErLCeVj/BvAPSEI6k4HkKL3zD3VAx5bPncc+jEwy4htEsFR0S
# 2QN+ylqUUhRzmD8jS1aMr9E1VicjOC6hghLxMIIS7QYKKwYBBAGCNwMDATGCEt0w
# ghLZBgkqhkiG9w0BBwKgghLKMIISxgIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBVQYL
# KoZIhvcNAQkQAQSgggFEBIIBQDCCATwCAQEGCisGAQQBhFkKAwEwMTANBglghkgB
# ZQMEAgEFAAQgX+YTzC6YQm2l2SzzY6NT4XIu6/1CFDNm3nNma4Dv8WkCBmGCBVHy
# 2hgTMjAyMTExMTExNjUzMzYuMTg1WjAEgAIB9KCB1KSB0TCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjMy
# QkQtRTNENS0zQjFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloIIORDCCBPUwggPdoAMCAQICEzMAAAFi0P4C8wHlzUkAAAAAAWIwDQYJKoZI
# hvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjEwMTE0
# MTkwMjIyWhcNMjIwNDExMTkwMjIyWjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVl
# cnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjMyQkQtRTNENS0zQjFE
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA74ah1Pa5wvcyvYNCy/YQs1tK8rIGlh1Q
# q1QFaJmYVXLXykb+m5yCStzmL227wJjsalZX8JA2YcbaZV5Icwm9vAJz8AC/sk/d
# sUK3pmDvkhtVI04YDV6otuZCILpQB9Ipcs3d0e1Dl2KKFvdibOk0/0rRxU9l+/Yx
# eb5lVTRERLxzI+Rd6Xv5QQYT6Sp2IE0N1vzIFd3yyO773T5XifNgL5lZbtIUnYUV
# mUBKlVoemO/54aiFeVBpIG+YzhDTF7cuHNAzxWIbP1wt4VIqAV9JjuqLMvvBSD56
# pi8NTKM9fxrERAeaTS2HbfBYfmnRZ27Czjeo0ijQ5DSZGi0ErvWfKQIDAQABo4IB
# GzCCARcwHQYDVR0OBBYEFMvEShFgSkO3OnzgHlaVk3aQ/iprMB8GA1UdIwQYMBaA
# FNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8y
# MDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAt
# MDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJ
# KoZIhvcNAQELBQADggEBAC1BrcOhdhtb9xcAJtxVIUZ7iALwZewXFIdPcmDAVT81
# 0k5xuRwVNW9Onq+WZO8ebqwiOSdEEHReLU0FOo/DbS7q79PsKdz/PSBPqZ/1ysjR
# VH0L5HUK2N7NgpkR1lnt+41BaOzJ+00OFDL5GqeqvK3RWh7MtqWF6KKcfNkP/hji
# Flg9/S7xNK/Vl8q10HB5YbdBTQun8j1Jsih6YMb3tFQsxw++ra5+FSnc4yJhAYvV
# aqTKRKepEmwzYhwDiXh2ag80/p0uDkOvs1WhgogwidpBVmNLAMxmFavK9+LNfRKv
# PIuCQw+EsxWR8vFBBJDfs14WTsXVF94CQ1YCHqYI5EEwggZxMIIEWaADAgECAgph
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
# UHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjMyQkQtRTNENS0z
# QjFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEw
# BwYFKw4DAhoDFQCas/oKGtvPRrHuznufk+indULyDKCBgzCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5Te4SjAiGA8y
# MDIxMTExMTE5NDIwMloYDzIwMjExMTEyMTk0MjAyWjB3MD0GCisGAQQBhFkKBAEx
# LzAtMAoCBQDlN7hKAgEAMAoCAQACAiHFAgH/MAcCAQACAhLGMAoCBQDlOQnKAgEA
# MDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAI
# AgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEASlWfw+kc9QPidqQu5ud3kPZfUgvL
# vhF64qnQh6v7VplHDJN9y5j9FUH4NCkl9y9OYxGU1UtJJhxNya9189MoCXytYR1S
# XQZWN4NOlG+MUgeoDtk6bbE1vIDZaTr/Rqbj6D5gHePQpd9KPFIxd4mCMSHqqYij
# fmeXDBwu2f4rsrcxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAWLQ/gLzAeXNSQAAAAABYjANBglghkgBZQMEAgEFAKCCAUow
# GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCAvwBrn
# IDLbtBmyg1rr+sXi4TrntPrvO+OoGdaFBAGJ/TCB+gYLKoZIhvcNAQkQAi8xgeow
# gecwgeQwgb0EIIqqGJX7PA0OulTsNEHsyLnvGLoYE1iwaOBmqrapUwoyMIGYMIGA
# pH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFi0P4C8wHlzUkA
# AAAAAWIwIgQgfGSBnJ6w9YR8AGFaxMapl/Ts8QcWeJ59EyJVJ8qeHb4wDQYJKoZI
# hvcNAQELBQAEggEAeH6/326yyLZtJ1Xr126Pjayo6ZjyIo7S4JeBmTeT7YtkB84r
# KuECci/bNEjFNpRVv7beEDxDmD52+Ja7gj0U1HcfFdLw+YWS6maw9IIZJHthRVTd
# sGWZGVK0sBqBFEryD7ZXuVseLS0rwDPJDTqiwpp9nWw5+wyIczcbL6CcyRZsQOTo
# xF35o3tJeF7UPV9S2WOXF6p/loWXq0xnVTYt7TBw16X8bxcFC2vYmq0aWtfpZ8L1
# m6ZoIbQ5+iEI+fVNGH9ES8yXYJXATYlwf/w4HaqP61QjtBXWDHs4oXbA4WKx9zbS
# sf96K1bTTUoRfPEgmQhfIa+y4N3SRu7zABTBpQ==
# SIG # End signature block
