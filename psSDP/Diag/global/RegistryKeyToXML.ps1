# Copyright ?2010, Microsoft Corporation. All rights reserved.

# You may use this code and information and create derivative works of it,
# provided that the following conditions are met:
# 1. This code and information and any derivative works may only be used for
# troubleshooting a) Windows and b) products for Windows, in either case using
# the Windows Troubleshooting Platform
# 2. Any copies of this code and information
# and any derivative works must retain the above copyright notice, this list of
# conditions and the following disclaimer.
# 3. THIS CODE AND INFORMATION IS PROVIDED ``AS IS'' WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. IF THIS CODE AND
# INFORMATION IS USED OR MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN CONNECTION
# WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.
#************************************************

#************************************************
# RegistryKeyToXML.ps1
# Version 1.0.0
# Date: 05-04-2011
# Author: Jeremy LaBorde - jlaborde@microsoft.com
# Description: This script provides functionality for gathering a registry key in
#  XML format, including data entries and permissions, along with functions
#  to navigate said XML data
#
# Note: do NOT use this format for large keys ( ex. HKCR ), as this
#  script uses get-item, which is considerably slower then other
#  methods to dump the registry
#
#************************************************


###########################################################
#
# Last Update: 5-3-2011
# Author: jlaborde
#
# Description:
#  convert from the type of entry returned in powershell for a registry entry to a REG_* type
#
# Usage:
#  Get-REG_Type <PS_type>
#
# Example:
#  Get-REG_Type "String"
#   returns "REG_SZ"
#
###########################################################

function Get-REG_Type( [string] $local:PS_Type )
{	switch( $local:PS_Type )
	{	"String"		{ return "REG_SZ" }
		"Binary"		{ return "REG_BINARY" }
		"DWord"			{ return "REG_DWORD" }
		"QWord"			{ return "REG_QWORD" }
		"MultiString"	{ return "REG_MULTI_SZ" }
		"ExpandString"	{ return "REG_EXPAND_SZ" }
	}
	return "REG_SZ"
}

###########################################################
#
# Last Update: 4-26-2011
# Author: jlaborde
#
# Description:
#  recusive function to dump a reg key & to an XML file
#
# Notes:
#  should always wrap data returned in an external XML tag for well-formatted XML
#  see Get-MSDTCRegistryKeysAsXML for an example in DC_MSDTC_Collector.ps1
#
# Usage:
#  Get-RegistryKeyAsXML <path> <recurse subkeys> <tab characters to prepend>
#
# Example:
#  Get-RegistryKeyAsXML "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" $true "`t"
#
###########################################################

function Get-RegistryKeyAsXML( [string]$local:path, [bool]$local:recurse, [string]$local:tabs )
{
	#name / header output
	$local:lpath	= "registry::" + $local:path
	$local:_retv	= $local:tabs + "<RegistryKey Name=`"" + $local:path + "`" >`r`n"

	#check to see if we can open the key...
	if( Test-Path( $local:lpath ) )
	{
		$local:regkey	= Get-Item( $local:lpath )


		#list the rights
		$local:perms			= ((Get-Acl $local:lpath).Access)
		$local:_retv			= $local:_retv + $local:tabs + "`t<Permissions>`r`n"
		foreach( $local:perm in $local:perms )
		{
			$local:_retv		= $local:_retv + $local:tabs + "`t`t<PermEntry ID=`""

			foreach( $local:t1 in $local:perm )
			{
				$local:_retv	= $local:_retv + $local:t1.IdentityReference + "`">`r`n"
				$local:_retv	= $local:_retv + $local:tabs + "`t`t`t<Type>" + $local:t1.AccessControlType + "</Type>`r`n"
				$local:_retv	= $local:_retv + $local:tabs + "`t`t`t<Rights>" + $local:t1.RegistryRights + "</Rights>`r`n"
			}

			$local:_retv		= $local:_retv + $local:tabs + "`t`t</PermEntry>`r`n"
		}
		$local:_retv			= $local:_retv + $local:tabs + "`t</Permissions>`r`n"


		#if there is a default value, save it
		$local:_retv		= $local:_retv + $local:tabs + "`t<Value>"
		$local:default		= ($local:regkey).GetValue( "", $null )
		if( $local:default -ne $null )
		{	$local:_retv	= $local:_retv + $local:default
		}
		$local:_retv		= $local:_retv + "</Value>`r`n"


		#save (Default) type ( which should always be REG_SZ... right? )
		$local:regentries	= ($local:regkey).GetValueNames( )
		$local:_retv		= $local:_retv + $local:tabs + "`t<Type>"
		# if a null value, just hardcode a REG_SZ
		if( $local:default -ne $null )
		{	$local:_retv		= $local:_retv + (Get-REG_Type $($local:regkey.GetValueKind( "" )) )
		} else
		{	$local:_retv		= $local:_retv + "REG_SZ"
		}
		$local:_retv		= $local:_retv + "</Type>`r`n"


		#list any entries in this key
		$local:_retv	= $local:_retv + $local:tabs + "`t<Entries>`r`n"
		if( $local:regentries -ne $null )
		{	foreach( $local:regentry in $local:regentries )
			{	if( $local:regentry -eq "" )
				{	continue;}
				$local:regvalue	= (Get-ItemProperty $local:lpath $local:regentry).$local:regentry
				$local:_retv	= $local:_retv + $local:tabs + "`t`t"   + "<Entry Name=`"" + $local:regentry + "`">`r`n"
				$local:_retv	= $local:_retv + $local:tabs + "`t`t"   + "<Type>" + (Get-REG_Type $($regkey.GetValueKind( $local:regentry )) ) + "</Type>`r`n"
				$local:_retv	= $local:_retv + $local:tabs + "`t`t`t" + "<Value>" + $local:regvalue + "</Value>`r`n"
				$local:_retv	= $local:_retv + $local:tabs + "`t`t"   + "</Entry>`r`n"
			}
		}
		$local:_retv	= $local:_retv + $local:tabs + "`t</Entries>`r`n"

		
		#recurse subkeys
		if( $local:recurse -eq $true )
		{	$local:regsubkeys		= Get-Item( $local:lpath + "\*" ) -ErrorAction SilentlyContinue
			if( $local:regsubkeys -ne $null )
			{	foreach( $local:subkey in $local:regsubkeys )
				{	$local:_retv	= $local:_retv + (Get-RegistryKeyAsXML $local:subkey $local:recurse (($local:tabs + "`t")) )
				}
			}
		}

	}
	else
	{	return ($local:tabs + "<KeyNotFound>" + $local:path + "</KeyNotFound>`r`n")
	}	

	$local:_retv	= $local:_retv + $local:tabs + "</RegistryKey>`r`n"

	return $local:_retv
}

###########################################################
#
# Last Update: 4-26-2011
# Author: jlaborde
#
# Description:
#  return the value from XML representation of a registry hive entry
#
# Usage:
#  Get-XMLRegistryEntryValue <XMLElement> <Entry Name>
#
# Example:
#  Get-XMLRegistryEntryValue $local:security "AccountName"
#   where $local:security == [XMLElement] set to "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC\Security"
#
###########################################################

function Get-XMLRegistryEntryValue( [System.Xml.XmlElement]$local:node, [string]$local:item )
{	#null or the value
	$local:entry	= $local:node.Entries.Entry | Where-Object { $_.Name -like $local:item }
	if( $local:entry -eq $null )
	{	return $null
	}
	return $local:entry.Value
}

###########################################################
#
# Last Update: 5-3-2011
# Author: jlaborde
#
# Description:
#  return the type from XML representation of a registry hive entry
#
# Usage:
#  Get-XMLRegistryEntryType <XMLElement> <Entry Name>
#
# Example:
#  Get-XMLRegistryEntryType $local:security "AccountName"
#   where $local:security == [XMLElement] set to "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC\Security"
#
###########################################################

function Get-XMLRegistryEntryType( [System.Xml.XmlElement]$local:node, [string]$local:item )
{	#null or the value
	$local:entry	= $local:node.Entries.Entry | Where-Object { $_.Name -like $local:item }
	if( $local:entry -eq $null )
	{	return $null
	}
	return $local:entry.Type
}

###########################################################
#
# Last Update: 4-26-2011
# Author: jlaborde
#
# Description:
#  return true or false from XML representation of a registry hive entry
#
# Usage:
#  Get-XMLRegistryEntryOnOrOff <XMLElement> <Entry Name>
#
# Example:
#  Get-XMLRegistryEntryOnOrOff $local:security "NetworkDtcAccess"
#   where $local:security == [XMLElement] set to "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC\Security"
#
###########################################################

function Get-XMLRegistryEntryOnOrOff( [System.Xml.XmlElement]$local:node, [string]$local:item )
{	#0 or null == false, else true
	$local:value	= Get-XMLRegistryEntryValue $local:node $local:item
	if( $local:value -eq $null -or $local:value -eq 0 )
	{	return $false
	}
	return $true
}

###########################################################
#
# Last Update: 3-31-2012
# Author: jlaborde
#
# Description:
#  return true or false from XML representation of a registry hive entry to see if it exists
#
# Usage:
#  Get-XMLRegistryEntryExists <XMLElement> <Entry Name>
#
# Example:
#  Get-XMLRegistryEntryOnOrOff $local:security "NetworkDtcAccess"
#   where $local:security == [XMLElement] set to "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC\Security"
#
###########################################################

function Get-XMLRegistryEntryExists( [System.Xml.XmlElement]$local:node, [string]$local:item )
{	#null == false, else true
	$local:value	= Get-XMLRegistryEntryValue $local:node $local:item
	if( $local:value -eq $null )
	{	return $false
	}
	return $true
}

###########################################################
#
# Last Update: 4-26-2011
# Author: jlaborde
#
# Description:
#  return the XML element representing the registry key
#
# Usage:
#  Get-XMLRegistryKey <XMLElement> <Full Key Name>
#
# Example:
#  Get-XMLRegistryKey $local:node "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC\Security"
#   where $local:node == [XMLElement] set to "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC"
#
###########################################################

function Get-XMLRegistryKey( [System.Xml.XmlElement]$local:node, [string]$local:item )
{	#null or the XMLElement
	$local:entry	= $local:node.RegistryKey | Where-Object { $_.Name -like $local:item }
	return $local:entry
}

###########################################################
#
# Last Update: 4-27-2011
# Author: jlaborde
#
# Description:
#  find XML node /subkey based on presence of an inner subkey, possibly at a certain default value
#
# Usage:
#  Get-XMLRegistryKeyBasedOnSubkey [System.Xml.XmlElement]$local:node, [string]$local:subkeyname, [string]$local:subkeyvalue
#
# Example:
#  Get-XMLRegistryKeyBasedOnSubkey $local:node, "Description", "MSDTC"
#   where $local:node is set to HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CID & 
#    we're looking for the subkey who contains a subkey name Description set to default value MSDTC
#
###########################################################

function Get-XMLRegistryKeyBasedOnSubkey( [System.Xml.XmlElement]$local:node, [string]$local:subkeyname, [string]$local:subkeyvalue )
{
	# loop through this node's subkeys
	foreach( $local:subnode in $local:node.RegistryKey )
	{
		# find the subkey off the looping subkey
		$local:s2	= Get-XMLRegistryKey $local:subnode ($local:subnode.Name + "\" + $local:subkeyname)
		if( $local:s2 -ne $null )
		{	# if we don't care about the default value, return this key
			if( $local:subkeyvalue -eq $null -or $local:subkeyvalue -eq "" )
			{	return $local:subnode
			}
			# if we do care about the default value, make sure we have one and compare it
			if( $local:s2.Value -ne $null -and $local:s2.Value.CompareTo( $local:subkeyvalue ) -eq 0 )
			{	return $local:subnode
			}
		}
	}
	return $null
}

# SIG # Begin signature block
# MIIjiAYJKoZIhvcNAQcCoIIjeTCCI3UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAWvLqsFCkshbie
# EmNZg2k09Aqq24y7L8xYjxwM6nlBdqCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgmhIsEbRH
# rcQrQnViEedsLzIn6x7pU/E5CIEP8+HmfMgwOAYKKwYBBAGCNwIBDDEqMCigCIAG
# AFQAUwBToRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20gMA0GCSqGSIb3DQEB
# AQUABIIBAJW/RSRTnJ8KvO4icflpn8wGy2Coeiga8lRptuvK4JuqK7NB8yS6Uy+q
# dRT9r7XMx1KoLf4zRklXS/ZD2XU5jc3+HwyLkp6CQHPt5mTZuiAFcZ+Up6yT3qGf
# VOqwux0r+SuiuByxtk+6EBXHWGOCRu4rNrMj328kW1Nf9FGF26VtbZp467gVq6tE
# 1hBq+HHtXPaWTuJ28Bnm0oA5i7Ej4VGlTDwIsoqO885ewYcyY83rfoovI1HCnDw0
# H8o5IUdjtsUH6z7J6xtq5U+OnjH5NzwM+DUS76ZAhokcE1qa9MOjPTvsBg5qOt0Z
# kenu4wZ9oTqIFT9Yt8OYeTm4/0i9W02hghLxMIIS7QYKKwYBBAGCNwMDATGCEt0w
# ghLZBgkqhkiG9w0BBwKgghLKMIISxgIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBVQYL
# KoZIhvcNAQkQAQSgggFEBIIBQDCCATwCAQEGCisGAQQBhFkKAwEwMTANBglghkgB
# ZQMEAgEFAAQgljh7x6Cv7P6877U6mffAFIP7BEh8kz7nnxFiGnD7+vMCBmGBshkU
# oRgTMjAyMTExMTExNjUzMzQuMTUxWjAEgAIB9KCB1KSB0TCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkM0
# QkQtRTM3Ri01RkZDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloIIORDCCBPUwggPdoAMCAQICEzMAAAFXRAdi3G/ovioAAAAAAVcwDQYJKoZI
# hvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjEwMTE0
# MTkwMjEzWhcNMjIwNDExMTkwMjEzWjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVl
# cnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkM0QkQtRTM3Ri01RkZD
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3m0Dp1Rm+efAv2pC1dzA8A2EHh7P7kJC
# t4+n9nxMfg0Gvm8B8YyjSVX+WJ0Fq0pOAcSs64ofXXFUB8F6Ecm8f1P86E5zzcIm
# z1vMOGuV3Ql3Ld4nILTIF3FV65xL7ZrZkF3nTAGD/n/ZiNDbKV8PR3Eorq1AvF04
# NO5p1Axt1rTmU8adYbBneeJKAgpVGCqoJWWEfPA21GHUAf5nFt9J7u3zPegQoB1M
# DLtKw/zKSG3eyuN2HQHKQ8V2loCCrBYIkkmYaTSACtK8cLz69e0ajcwmFZBF7km3
# N0PmR1oof25z2CdKGxfIMSEZmPHf5vxy6oQ7xse/RY9f0xER+t/G+QIDAQABo4IB
# GzCCARcwHQYDVR0OBBYEFF0xe7voOCGdT+Q9Mwp0WRH2gKnZMB8GA1UdIwQYMBaA
# FNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8y
# MDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAt
# MDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJ
# KoZIhvcNAQELBQADggEBACV3eQCAbpdaJnK92JstGZavvJvpFLJyNUODy1wKK1LT
# WxNWnhPwB3ZB5h8lZ8roMwSTtBEF8qB03ugTx1e2ZBUv4lzEuPSlS7Lg0HlFyFy1
# 4Pl1GdN8qVGLy+ApRrENygUjM0RTPUQemil5qANvj+4j1SPm0i7CWKT+qu/+wcDD
# uQziAQss06B16/1n/vGjUkjB97R6hAzfDFwIUu5/xL06dy21oUBYe0QRHwi+BECA
# sn9aeW4XPrz6GsN9HJf+qpZI8gTS+gTqoXHXPxS8vAqmbrlA3I0NEyn9WYKmpFmv
# EHWjRFjs/6fiNI0a9uTZtHvSQq392iAUVEEdVW5TF/4wggZxMIIEWaADAgECAgph
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
# UHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkM0QkQtRTM3Ri01
# RkZDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEw
# BwYFKw4DAhoDFQARLfhJYnsN9tIb+BshDBOvOBnw8qCBgzCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5TdlHjAiGA8y
# MDIxMTExMTEzNDcxMFoYDzIwMjExMTEyMTM0NzEwWjB3MD0GCisGAQQBhFkKBAEx
# LzAtMAoCBQDlN2UeAgEAMAoCAQACAhSBAgH/MAcCAQACAhFZMAoCBQDlOLaeAgEA
# MDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAI
# AgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAQwP/FLlP0S6Lacsq9xG2lBweZT5R
# ezSzHoLThU+4k2RT3bM+CAmABoNt/6nLHOgeJDHXhbgW9wJjT60FbnvPSBIAC7ja
# kyZ5OdxjwglYEo4kHJio7o8ZXZyE9IEWHDeSGCEcQt2SWYRtbpf7LY7RkG9eF7Ot
# Oh851qk29jGksuAxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAVdEB2Lcb+i+KgAAAAABVzANBglghkgBZQMEAgEFAKCCAUow
# GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCAKeYu7
# nkweFZWb6r5h6rspcmYcZXs73rj8XkM87EA2ZDCB+gYLKoZIhvcNAQkQAi8xgeow
# gecwgeQwgb0EICxajQ1Dq/O666lSxkQxInhSxGO1DDZ0XFlaQe2pHKATMIGYMIGA
# pH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFXRAdi3G/ovioA
# AAAAAVcwIgQgUNTL42zabPo8iEdkSC2WiPOhDovoZWUW0VMosB1AYt0wDQYJKoZI
# hvcNAQELBQAEggEApCUYMBcCVFbu/iWgxG6gWlnNKYo4jHBsHpS6++aZgyilGKZt
# dQVCcseWF7pc7wZ+uvsdyNFfpOE659wVF7G6RB+Bm/6WyL2zekoML5QFQftzr/Jt
# /GKL0uf24Ttzw36fkbVR5UqQWq1pwlGUHoVinvYBtxXE1zUtgdY59pIVYB5D4K1M
# PmvYGlJtTQr2bY9fbpWaPuylynPIG1Eeaei2gNobIGIJvijcTk/QoNMBg04UmW68
# mn87Kh9AMjPAUUr2DSCI4+NE823C4+H9Q26qGU0qz97i5RpCKw8zn+cMP8KBsjl/
# 4SgQxDEIOKQrjLuWymhrZ52lgHJZDhk8sOPNhA==
# SIG # End signature block
