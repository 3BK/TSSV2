#************************************************
# utils_loadex2013powershell.ps1
# Version 2.0.1
# Date: 4/12/2013
# Author: Brad Hughes - bradhugh@microsoft.com
# Description:  Utility functions specific to Exchange 2007 2010
#************************************************

# Out-of-process powershell runspace for running remote powershell commands
$script:_ExchangeRemoteRunspace = $null

# Out-of-process powershell runspace for running local powershell commands
$script:_ExchangeLocalRunspace = $null


# <summary>
# Executes a command using an Exchange Runspace
# </summary>
# <returns>The results of the command execution</returns>
Function Invoke-ExchangeCommand(
	[string]$commandText,
	[switch]$Local = $false,
	$Runspace = $null)
{
	# If the runspace isn't explicitly provided, load either remote (default), or local based on the switch
	if ($Runspace -eq $null) {
		if ($Local) {
			$Runspace = Get-ExchangeLocalRunspace
		}
		else {
			$Runspace = Get-ExchangeRemoteRunspace
		}
	}

	
	$pl = $Runspace.CreatePipeline()
	#$pl.Commands.AddScript("Set-Variable FormatEnumerationLimit -Value 128 -Scope Global")
	$pl.Commands.AddScript($commandText)
	try {
		# This will return data to the pipeline
		Write-Debuglog ("INFO:Cmdlet Started: " + $commandText)
		$pl.Invoke()
		Write-Debuglog ("INFO:Cmdlet Ended  : " + $commandText)

	}
	finally {
		$pl.Dispose()
		$pl = $null
	}


}

# <summary>
# Gets and if needed initializes the Exchange Local Runspace
# <summary>
# <returns>The Exchange Remote Powershell Runspace</returns>
Function Get-ExchangeLocalRunspace {
	if ($script:_ExchangeLocalRunspace -eq $null) {
		Initialize-ExchangeLocalRunspace
	}
	
	return $script:_ExchangeLocalRunspace
}

# <summary>
# Gets and if needed initializes the Exchange Remote Runspace
# <summary>
# <returns>The Exchange Remote Powershell Runspace</returns>
Function Get-ExchangeRemoteRunspace {
	if ($script:_ExchangeRemoteRunspace -eq $null) {
		Initialize-ExchangeRemoteRunspace
	}
	
	return $script:_ExchangeRemoteRunspace
}



# <summary>
# Releases the Exchange Local and Remote Runspaces
# </summary>
Function Release-ExchangeRunspaces {

	# Clean up runspaces
	if ($script:_ExchangeRemoteRunspace -ne $null) {
		$script:_ExchangeRemoteRunspace.Dispose()
		$script:_ExchangeRemoteRunspace = $null
	}
	
	if ($script:_ExchangeLocalRunspace -ne $null) {
		$script:_ExchangeLocalRunspace.Dispose()
		$script:_ExchangeLocalRunspace = $null
	}
}

# <summary>
# Initializes the Exchange Remote Powershell Runspace
# <summary>
Function Initialize-ExchangeLocalRunspace {
	
	$rs = New-DotNet40Runspace
	
	# Change to current Directory
	Invoke-ExchangeCommand "cd $PWD" -Runspace $rs | Out-Null
	
	# Add the Exchange snap-in
	Invoke-ExchangeCommand "Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010" -Runspace $rs

	# Set fomatenumerationlimit to 128
	#Invoke-ExchangeCommand "Set-Variable FormatEnumerationLimit -Value 128 -Scope Global" -Runspace $rs | Out-Null
	
	$script:_ExchangeLocalRunspace = $rs
}

# <summary>
# Initializes the Exchange Remote Powershell Runspace
# <summary>
Function Initialize-ExchangeRemoteRunspace {

	$rs = New-DotNet40Runspace
	
	# Change to current Directory
	Invoke-ExchangeCommand "cd $PWD" -Runspace $rs | Out-Null
	
	# Load the Exchange Shell Utility Script
	Invoke-ExchangeCommand ". .\Initialize-ExchangeShell.ps1" -Runspace $rs | Out-Null
	
	# Load the shell
	Invoke-ExchangeCommand "Connect-ExchangeManagementShell" -Runspace $rs | Out-Null

	# Set fomatenumerationlimit to 128
	#Invoke-ExchangeCommand "Set-Variable FormatEnumerationLimit -Value 128 -Scope Global" -Runspace $rs | Out-Null
	
	$script:_ExchangeRemoteRunspace = $rs
}

# <summary>
# Creates a new out-of-process runspace for Powershell
# </summary>
# <returns>The unopened out-of-process runspace</returns>
Function New-OutOfProcessRunspace {

	# Load the powershell Assembly
	$automationDll = [System.Reflection.Assembly]::Load("System.Management.Automation")
	
	# Get the NewProcesConnectionInfo type and create a default instance
	$ncpiType = $automationDll.GetType("System.Management.Automation.Runspaces.NewProcessConnectionInfo")
	$ncpi = $ncpiType.InvokeMember("","NonPublic,CreateInstance,Instance", $null, $null, @($null))
	
	# Create a new out of process runspace, but don't open it yet
	$rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($ncpi)
	
	return $rs
}

# <summary>
# Creates a new out-of-process runspace with .NET 4.0 Loaded
# </summary>
# <returns>The unopened out-of-process .NET 4.0 runspace</returns>
Function New-DotNet40Runspace {
	
	# Create an out-of-process runspace
	$rs = New-OutOfProcessRunspace
	
	# Create a temp file for runspace activation using .NET 4.0
	$RunActivationConfigPath = $Env:TEMP | Join-Path -ChildPath ([Guid]::NewGuid())
    New-Item -Path $RunActivationConfigPath -ItemType Container | Out-Null
	
	$configFileXml = @"
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <startup useLegacyV2RuntimeActivationPolicy="true">
    <supportedRuntime version="v4.0"/>
  </startup>
</configuration>
"@
	# Write the config XML to the file
	$configFileXml | Set-Content -Path $RunActivationConfigPath\powershell.exe.activation_config -Encoding UTF8
	
    $EnvVarName = 'COMPLUS_ApplicationMigrationRuntimeActivationConfigPath'
    $EnvVarOld = [Environment]::GetEnvironmentVariable($EnvVarName)
    [Environment]::SetEnvironmentVariable($EnvVarName, $RunActivationConfigPath)

    try {
		# Open the out of process runspace
        $rs.Open()
		
		# Return the runspace object
		return $rs
    } finally {
		# Restore the existing activation configuration
        [Environment]::SetEnvironmentVariable($EnvVarName, $EnvVarOld)
		
		# Remove the Activation Config temp folder
        $RunActivationConfigPath | Remove-Item -Recurse
    }
}

# keeping this current code in place "in case" but should probably need a review if we like to use it as it is not using Invoke-ExchangeCommand as it should do
Function IsExchangePSSnapinInstalled
{
	$Script:ExchPSSnapinAdded = $true
	#======================================
	# Set global variables and load Powershell snapin for version of Exchange installed
	#======================================	
		
		# If the Get-ExchangeServer Command exists, the snapin is loaded or remote PS is connected
		if ((gcm get-exchangeserver -ErrorAction SilentlyContinue) -eq $null) {
		
			# We first try to connect the Shell through Remote PS
			if (Connect-ExchangeManagementShell) {
				$Script:ExchPSSnapinAdded = $true
			}
			elseif ((Get-PSSnapin -Name "Microsoft.Exchange.Management.PowerShell.E2010" -ErrorAction SilentlyContinue) -eq $null) {
				# Otherwise, if the snapin is available, we just load that
				("Add-PSSnapin 'Microsoft.Exchange.Management.PowerShell.E2010'") | WriteTo-StdOut
				Add-PSSnapin -Name "Microsoft.Exchange.Management.PowerShell.E2010" -ErrorAction SilentlyContinue
				
				# Now sanity check that it actually loaded
				If ((Get-PSSnapin -Name "Microsoft.Exchange.Management.PowerShell.E2010" -ErrorAction SilentlyContinue) -ne $null) {
					$Script:ExchPSSnapinAdded = $true
				}
			}
		}
		else {
			# In this case Get-ExchangeServer already exists, so we'll assume it's loaded.
			$Script:ExchPSSnapinAdded = $true
		}
}
# SIG # Begin signature block
# MIIjiAYJKoZIhvcNAQcCoIIjeTCCI3UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC3VchdTjKteB6W
# OVRtG/nth9ncaJyFUz1wDK1vlS/mA6CCDYEwggX/MIID56ADAgECAhMzAAAB32vw
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgh6fyFfcs
# bdKVg6/GY2R4LjU+engSN0cLTQ0hnAJOM2EwOAYKKwYBBAGCNwIBDDEqMCigCIAG
# AFQAUwBToRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20gMA0GCSqGSIb3DQEB
# AQUABIIBAJ5i7bNKfJx2g65GKaH3Yv/U9ZYnr4pHGyYcZKVJKKc+1JX4ZLf4cpuD
# KMOt7uKVvNp6KYciUQalEXs8VF4dM+jjmyCKmiZOsHFUzOYVH5YBEnOyzAgKxVMo
# Lokx5Yb/K1O3WDpoPAHAoaMsl33K2+xGldx+OpqJdWVEHsPz040/AASMk27FQB8T
# PgEqERn/010tHiZ21thJ0dIsk85jzucqwpf+Q41MsRtw3pD/pFhGLg6KTKkTvcst
# kxHM8ygfSgZ/FPbagSwJHLVM+x4rsPQNpq/ooLCg9wICJzw4AYnzFnji6N8YNyQ7
# tjwX/xBI2ArZVcmA+B9kX9xZdmYIInmhghLxMIIS7QYKKwYBBAGCNwMDATGCEt0w
# ghLZBgkqhkiG9w0BBwKgghLKMIISxgIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBVQYL
# KoZIhvcNAQkQAQSgggFEBIIBQDCCATwCAQEGCisGAQQBhFkKAwEwMTANBglghkgB
# ZQMEAgEFAAQgQFObpXlWnd3dTZd1mWd4gG1E/caXVisk09gawIksy/4CBmGCAKQz
# BRgTMjAyMTExMTExNjUzMzUuMTU4WjAEgAIB9KCB1KSB0TCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQ5
# REUtRTM5QS00M0ZFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloIIORDCCBPUwggPdoAMCAQICEzMAAAFh9aIzXqAqJGkAAAAAAWEwDQYJKoZI
# hvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjEwMTE0
# MTkwMjIxWhcNMjIwNDExMTkwMjIxWjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVl
# cnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQ5REUtRTM5QS00M0ZF
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl4idqEGtT/8bNOqHFTIALxRdy3pQkKRv
# bERkpXeCOCCYsCF4GvEmTu0f4/Da1NzJqstF+ZXbGjmgGTmlb85wNz+f9NxN5BTo
# kg3k+VNyfQL1GUpDq3065T9YDIDEZOMoTgQ2dSNe3GI2UP8rZkYwu+OlE4EqHtO2
# RQkrpkZbD+5NFps0HFGDXdO+OQYdcRQQMnyKZpzD0EJ5H0vq6d2vfa2Ph244UgcP
# ybV6zdI033xmrggME/cJxv4dCDGlt4chSUrTLrObMiS983vdnHB8a8W/T8xrHv1Y
# ljRwPymgKdkWKNyJat/R4PVPb/7seB7DOt3E91IWhyRRDxCi8gMhiQIDAQABo4IB
# GzCCARcwHQYDVR0OBBYEFFYemp3WG/vVJWPksB0980Ts+EsvMB8GA1UdIwQYMBaA
# FNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8y
# MDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAt
# MDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJ
# KoZIhvcNAQELBQADggEBABBMD1upUGbHlNMyHOP5DzNaQ9BeAJxJCKrLZhhYXSFa
# vkYSI3Yu0D4RZ27XLyjKxlq7gI/tLMzxVNKrfUIsmI7Lf1nhG8SraavQR+0W+ZfY
# LFDtnLOuSFYxlplAuRhsfmhpsgXCd1bfieH3zQE5jf3m1+c1L9jo3R/6Nd2gWft8
# jZzjdMVixSog9aM4cmWgx6S2UPr+5LpmfjGx7+Ui0Wb59Y5wHYDHJcQHdlER5KD2
# Pv4agSXXFP+Im5X9KjtOVZ3DJpxC7iW/cwGy/HNEhsqFnCsNiiCajIn6vCBAHyYp
# Lj8zVING0im1qahMUnnpOToO5RfHUm51Oh6WCMRk9rkwggZxMIIEWaADAgECAgph
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
# UHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQ5REUtRTM5QS00
# M0ZFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEw
# BwYFKw4DAhoDFQAVblKEDDl6RMRe8v/hXWzStsPPeaCBgzCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5TezsDAiGA8y
# MDIxMTExMTE5MjIyNFoYDzIwMjExMTEyMTkyMjI0WjB3MD0GCisGAQQBhFkKBAEx
# LzAtMAoCBQDlN7OwAgEAMAoCAQACAghLAgH/MAcCAQACAhHYMAoCBQDlOQUwAgEA
# MDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAI
# AgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAh1mmFsBeQFa+0TXcxMoBknIOVsFZ
# E13Ln2sObjkCjM4DkGSnxwOCDxUcdrIZpujlgqB5S0Yx5b3bK+fsx5ahRXu1BPCT
# 3USVaLoN8/dCUWcDJw1Xio7HuJcXZaKa8RAHUv7n/UagdfsUqt8hg0PUxt+Uldam
# msSFNrt74+dca9cxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAWH1ojNeoCokaQAAAAABYTANBglghkgBZQMEAgEFAKCCAUow
# GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCDMSLHN
# iWBomcPFg4+ZbEK3DN2XSBIe7tMCej5vz/FsHTCB+gYLKoZIhvcNAQkQAi8xgeow
# gecwgeQwgb0EIGHPi6fqaRIt3/MD7Q3lgsMani9b9UG01b+WmaG0CThvMIGYMIGA
# pH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFh9aIzXqAqJGkA
# AAAAAWEwIgQgqllnulSb2IvXWMChA37lhxBjRg41zrGQVTZWH4Srg3kwDQYJKoZI
# hvcNAQELBQAEggEAMNbRQY2Ojw6U5vBaJyjDVOX3dtuRWtZht/OTCnlf+R/t8/IZ
# tGLWPMsSu37n4Xj/xQNHTI/8tkpa0/86RDBMwvxnrn8WksNF1NWCFoRhs1Bo+uD+
# 0Wuws06dgWHMvCjyixHgtwdeucGuClONks+3FMt6mveDImSMXTOawe7Z49vgh7LB
# 6iPjyGxdoVG+Q+6yEAeCo0KlDccc3JyJQZsQc28GRcJi4q9YZlHeob9Njbm+2dp9
# uoyuMczPJ0IwnM/7OtaIr+yQpSrzh58vd+r8TZNxpSIYfolJzZpYjcHQra31m4W+
# lYBOfMLo+ryJWTx1G85RD29d8MifSR6EKd1Ljg==
# SIG # End signature block
