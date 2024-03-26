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
# DistSvcs_Utils.ps1
# Version 1.0.0
# Date: 05-09-2011
# Author: Jeremy LaBorde - jlaborde@microsoft.com
# Description: This script provides gathers MSDTC registry keys in XML format,
#  generates a summary report, and a XAML representation of the local DTC settings
#
# This is the main SDP package for MSDTC
#************************************************




###########################################################
#
# Last Update: 5-9-2011
# Author: jlaborde
#
# Description:
#  returns string representing the OS version
#
# Usage:
#  Get-OSVersionString
#
# Example:
#  Get-OSVersionString
#
# Needs to be moved to a utils / globally accessible location
#
###########################################################

function Get-OSVersionString( )
{	$local:version	= ([Environment]::OSVersion.Version.Major.ToString()) + "." + ([Environment]::OSVersion.Version.Minor.ToString())
	switch( $local:version )
	{
		"6.2"	{ return "Windows 8 / 2012" }
		"6.1"	{ return "Windows 7 / 2008 R2" }
		"6.0"	{ return "Windows Vista / 2008" }
		"5.2"	{ return "Windows XP 64 / 2003" }
		"5.1"	{ return "Windows XP" }
		"5.0"	{ return "Windows 2000" }
	}
	return ""
}



###########################################################
#
# Last Update: 5-9-2011
# Author: jlaborde
#
# Description:
#  collect Distributed Services application event logs of interest
#
# Usage:
#  Get-DistSvcsAppLogsAsCSV [string]$local:outputfile
#   where $local:outputfile will be a csv file
#
# Example:
#  Get-DistSvcsAppLogsAsCSV "ApplicationLogs.csv"
#
###########################################################

function Get-DistSvcsAppLogsAsCSV( [string]$local:outputfile )
{
	if( (Get-Host).version.major -eq "1" )
	{
		$Logs = Get-EventLog -LogName application | Select-Object -Property EntryType, EventID, Source, TimeWritten, Message
	} else
	{
		$Logs = get-eventlog -logname application -Source "*Windows Error Reporting*",
														"*SideBySide*",
														"*Application Error*",
														"*Application Hang*",
														"*Application Popup*",
														"*User Profile Service*",
														"*MsiInstaller*",
														"*DNS*",
														"*VSS*",
														"*SQL*",
														"*Cluster*",
														"*MSDTC*",
														"*COM*",
														"*Complus*",
														"*gupdate*",
														"*Userenv*"`
														| Select-Object `
															-property EntryType, EventID, Source, TimeWritten, Message 
	}
	$Logs | Export-Csv $local:outputfile
}

###########################################################
#
# Last Update: 5-9-2011
# Author: jlaborde
#
# Description:
#  collect Distributed Services system event logs of interest
#
# Usage:
#  Get-DistSvcsSysLogsAsCSV [string]$local:outputfile
#   where $local:outputfile will be a csv file
#
# Example:
#  Get-DistSvcsSysLogsAsCSV "SystemLogs.csv"
#
###########################################################

function Get-DistSvcsSysLogsAsCSV( [string]$local:outputfile )
{
	if( (Get-Host).version.major -eq "1" )
	{
		$Logs = Get-EventLog -LogName system | Select-Object -Property EntryType, EventID, Source, TimeWritten, Message
	} else
	{
		$Logs = get-eventlog -logname system -Source "*Windows Error Reporting*",
													"*VSS*",
													"*SQL*",
													"*Cluster*",
													"*MSDTC*",
													"*Complus*",
													"*DistributedCOM*",
													"*Kerberos*",
													"*GroupPolicy*",
													"*SMSvcHost*",
													"*DnsApi*"`
													| Select-Object `
														-property EntryType, EventID, Source, TimeWritten, Message 
	}
	$Logs | Export-Csv $local:outputfile
}



###########################################################
#
# Last Update: 5-9-2011
# Author: jlaborde
# Inspired By: Joe Mansfield ( http://helvick.blogspot.com/2007/08/checking-service-permissions-with.html )
#
# Description:
#  output permissions on a service
#
# Usage:
#  Get-ServicePermission [string]$local:ServiceNameMask
#
# Example:
#  Get-ServicePermission "*msdtc*"
#
###########################################################

function Get-ServicePermission( [string]$local:ServiceNameMask )
{	$local:retv	= ""

	# get the services
	$local:services	= Get-CimInstance -query 'select * from win32_service'

	# loop through each, looking for the ones of interest
	foreach( $local:service in $local:services )
	{	if( $local:service.Name -like $local:ServiceNameMask )
		{	$local:retv	+= "Display Name: " + $local:service.DisplayName + "`r`n"
			$local:retv	+= "Name: " + $local:service.Name + "`r`n"
			$local:retv	+= "Path: " + $local:service.PathName + "`r`n"

			# get the permissions on the object
			$local:path		= $local:service.PathName.Substring( 0, $local:service.PathName.IndexOf( "." ) ) + ".exe"
			$local:secure	= get-acl $local:path
			# output permissions
			foreach( $local:item in $local:secure.Access )
			{	$local:retv	+= "`r`n"
				$local:retv	+= "`t" + $item.IdentityReference.Value + "`r`n"
				$local:retv	+= "`t" + $item.AccessControlType.ToString() + "`r`n"
				$local:retv	+= "`t" + $item.FileSystemRights.ToString() + "`r`n"
			}

			$local:retv	+= "`r`n"
			$local:retv	+= "`r`n"
		}
	}
	return $local:retv
}



###########################################################
#
# Last Update: 5-24-2011
# Author: jlaborde
#
# Description:
#  return a reg key value
#
# Usage:
#  Get-RegKeyValue [string]$local:regkey, [string]$local:regvalue
#
# Example:
#  $local:binSD	= Get-RegKeyValue "HKEY_LOCAL_MACHINE\software\microsoft\ole" "MachineLaunchRestriction"
#
###########################################################

function Get-RegKeyValue( [string]$local:regkey, [string]$local:regvalue )
{	if( (Test-Path ("registry::" + $local:regkey)) -eq $false )
	{	return $null
	}
	$local:reg	= Get-Item ("registry::" + $local:regkey)

	if( $local:regvalue -eq $null -or $local:regvalue -eq "" )
	{	return ( ($local:reg).GetValue( "", $null ) )
	}

	$local:val	= Get-ItemProperty $reg.PSPath
	if( $local:val -eq $null )
	{	return $null
	}
	return $local:val.$local:regvalue
}

###########################################################
#
# Last Update: 3-31-2012
# Author: jlaborde
#
# Description:
#  test if a registry value exists
#
# Usage:
#  Get-RegKeyValueExists [string]$local:regkey, [string]$local:regvalue
#
# Example:
#  if( ( Get-RegKeyValue "HKEY_LOCAL_MACHINE\software\microsoft\ole" "MachineLaunchRestriction" ) )
#
###########################################################

function Get-RegKeyValueExists( [string]$local:regkey, [string]$local:regvalue )
{	if( (Test-Path ("registry::" + $local:regkey)) -eq $false )
	{	return $false
	}
	$local:reg	= Get-Item ("registry::" + $local:regkey)

	if( $local:regvalue -eq $null -or $local:regvalue -eq "" )
	{	return $true
	}

	$local:val	= Get-ItemProperty $reg.PSPath
	if( $local:val -eq $null )
	{	return $false
	}
	return $true
}

###########################################################
#
# Last Update: 10-6-2011
# Author: jlaborde
#
# Description:
#  return a reg key value as true or false
#
# Usage:
#  Get-RegKeyBool [string]$local:regkey, [string]$local:regvalue
#
# Example:
#  $local:bool	= Get-RegKeyValue "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC\Security" "NetworkDtcAccess"
#
###########################################################

function Get-RegKeyBool( [string]$local:regkey, [string]$local:regvalue )
{	$local:bool	= Get-RegKeyValue $local:regkey $local:regvalue
	if( $local:bool -eq $null -or $local:bool -eq $false -or $local:bool -eq 0 )
	{	return $false
	}
	return $true
}

###########################################################
#
# Last Update: 10-6-2011
# Author: jlaborde
#
# Description:
#  find subkey based on presence of an inner subkey, possibly at a certain default value
#
# Usage:
#  Get-RegistryKeyBasedOnSubkey [string]$local:keyname, [string]$local:subkeyname, [string]$local:subkeyvalue
#
# Example:
#  Get-RegistryKeyBasedOnSubkey "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CID" "Description" "MSDTC"
#   we're looking for the subkey who contains a subkey name Description set to default value MSDTC
#
###########################################################

function Get-RegistryKeyBasedOnSubkey( [string]$local:keyname, [string]$local:subkeyname, [string]$local:subkeyvalue )
{
	# get the subkeys for this key
	$local:ChildKeys	= Get-Item ("registry::" + $local:keyname + "\*") -ErrorAction SilentlyContinue

	# loop through the root's subkeys
	foreach( $local:subkey in $local:ChildKeys )
	{
		# find the subkey off the looping subkey
		$local:s2	= Get-Item ("registry::" + $local:subkey.Name + "\" + $local:subkeyname) -ErrorAction SilentlyContinue
		if( $local:s2 -ne $null )
		{	# if we don't care about the default value, return this key
			if( $local:subkeyvalue -eq $null -or $local:subkeyvalue -eq "" )
			{	return $local:subkey
			}
			# if we do care about the default value, make sure we have one and compare it
			$local:default		= ($local:s2).GetValue( "", $null )
			if( $local:default -ne $null )
			{	if( $local:default.CompareTo( $local:subkeyvalue ) -eq 0 )
				{	return $local:subkey
				}
			}
		}
	}
	return $null
}

###########################################################
#
# Last Update: 10-6-2011
# Author: jlaborde
#
# Description:
#  find subkey based on presence of an entry
#
# Usage:
#  Get-RegistrySubKeyBasedOnEntry [string]$local:keyname [string]$local:entryname [string]$local:entryvalue
#
# Example:
#  Get-RegistrySubKeyBasedOnEntry "HKEY_LOCAL_MACHINE\Cluster\Resources\{GUID}" "MSDTC" ""
#   we're looking for the subkey who contains an entry name MSDTC set to any value
#
###########################################################

function Get-RegistrySubKeyBasedOnEntry( [string]$local:keyname, [string]$local:entryname, [string]$local:entryvalue )
{
	# get the subkeys for this key
	$local:ChildKeys	= Get-Item ("registry::" + $local:keyname + "\*") -ErrorAction SilentlyContinue

	# loop through the root's subkeys
	foreach( $local:subkey in $local:ChildKeys )
	{
		# try to find the entry name
		$local:regentries	= ($local:subkey).GetValueNames( )
		if( $local:regentries -ne $null )
		{
			foreach( $local:entry in $local:regentries )
			{	if( $local:entry -eq $local:entryname )
				{	if( $local:entryvalue -eq $null -or $local:entryvalue -eq "" )
					{	return $local:subkey
					}
					if( (Get-RegKeyValue $local:subkey.Name $local:entryname) -eq $local:entryvalue )
					{	return $local:subkey
					}
					return $null
				}
			}
		}
	}
	return $null
}



###########################################################
#
# Last Update: 5-24-2011
# Author: jlaborde
#
# Description:
#  create a basic 'permissions' class
#
# Usage:
#  Get-PermissionsClass
#
# Example:
#  $local:Perms = Get-PermissionsClass
#
###########################################################



function Get-PermissionsClass( )
{	$local:strings	= @()

	$local:object	= New-Object Object |
		Add-Member -MemberType NoteProperty -Name Account -Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name Type    -Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name Rights  -Value 0 -PassThru
	return $local:object
}

###########################################################
#
# Last Update: 5-24-2011
# Author: jlaborde
#
# Description:
#  create a a permission object based on a binary representation of a SID
#
# Usage:
#  Get-PermissionsFromBinarySID $local:binary
#
# Example:
#  $local:Perm		= Get-PermissionsFromBinarySID $local:binSD
#
###########################################################

function Get-PermissionsFromBinarySID( $local:binary )
{	$local:array	= @()

	# not supported pre-Vista
	#if( $OSVersion.Major -lt 6 )
	#{	return $local:array
	#}

	#$converter	= new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
	#$SDDL		= $converter.BinarySDToSDDL( $local:binary )
	#$CSD		= New-Object System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList $false, $false, $SDDL.SDDL
	$CSD		= New-Object System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList $false, $false, $local:binary, 0

	foreach( $dacl_ in $CSD.DiscretionaryAcl )
	{	$local:Perms	= Get-PermissionsClass

		$AccountSID		= New-Object System.Security.Principal.SecurityIdentifier ( $dacl_.SecurityIdentifier )
		$local:RealSID	= $AccountSID.Translate( [System.Security.Principal.NTAccount] )

		if( $local:RealSID -ne $null )
		{
			$local:Perms.Account	= $local:RealSID.Value
			$local:Perms.Type		= $dacl_.AceType
			$local:Perms.Rights		= $dacl_.AccessMask

			$local:array	= $local:array + $local:Perms
		}
	}
	return $local:array
}

function Get-CombinePermissionsClass( )
{	$local:objects1	= @()
	$local:objects2	= @()
	

	$local:object	= New-Object Object |
		Add-Member -MemberType NoteProperty -Name Account -Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name aAllow  -Value $local:objects1 -PassThru |
		Add-Member -MemberType NoteProperty -Name aDeny   -Value $local:objects2 -PassThru
	return $local:object
}

function Get-CombinedPermFromListByAccount( [Object]$local:CombPermsArray, [string]$local:account )
{	foreach( $local:perm in $local:CombPermsArray )
	{	if( $local:perm.Account.ToUpper( ) -eq $local:account.ToUpper( ) )
		{	return $local:perm }
	}
	return $null
}

function Get-CombinedPermissionsFromPermissionsList( $local:PermsArray )
{	$local:CombPerms	= @()

	foreach( $local:perm in $local:PermsArray )
	{	$local:cp	= Get-CombinedPermFromListByAccount $local:CombPerms $local:perm.Account
		if( $local:cp -eq $null )
		{	$local:cp	= Get-CombinePermissionsClass
			$local:cp.Account	= $local:perm.Account
			$local:CombPerms	= $local:CombPerms + $local:cp
		}
		if( $local:perm.Type -eq "AccessAllowed" )
		{	$local:cp.aAllow	= $local:cp.aAllow + $local:perm
		} else
		{	$local:cp.aDeny	= $local:cp.aDeny + $local:perm
		}
	}
	
	return $local:CombPerms
}



###########################################################
#
# Last Update: 6-21-2011
# Author: jlaborde
#
# Description:
#  generate a GUID with { } around it
#
# Usage:
#  Get-GUID
#
# Example:
#  $local:guid		= Get-GUID
#
###########################################################
function Get-GUID( )
{	return ( "{" + ([System.Guid]::NewGuid()).ToString( ) + "}" )
}



# functions used to output SDDL information

# use Format-SDDL for full text output

# returns a string of the SID / Account
function Get-SDDL_WellKnown( [string] $code )
{
	if( $code.Length -gt 2 )
	{	return $code
	}

	switch( $code )
	{
		"AN"	{ return "Anonymous" }
		"AO"	{ return "Account Operators" }
		"AU"	{ return "Authenticated Users" }
		"BA"	{ return "Built-In Administrators" }
		"BG"	{ return "Built-In Guests" }
		"BO"	{ return "Backup Operators" }
		"BU"	{ return "Built-In Users" }
		"CA"	{ return "Certificate Publishers" }
		"CD"	{ return "Users Cert DCOM" }
		"CG"	{ return "Creator Group" }
		"CO"	{ return "Creator Owner" }
		"DA"	{ return "Domain Administrators" }
		"DC"	{ return "Domain Computers" }
		"DD"	{ return "Domain Controllers" }
		"DG"	{ return "Domain Guests" }
		"DU"	{ return "Domain Users" }
		"EA"	{ return "Enterprise Administrators" }
		"ED"	{ return "Enterprise DCs" }
		"HI"	{ return "High Integrity Level" }
		"IU"	{ return "Interactively Logged-On User" }
		"LA"	{ return "Local Administrator" }
		"LG"	{ return "Local Guest" }
		"LS"	{ return "Local Service Account" }
		"LW"	{ return "Low Integrity Level" }
		"ME"	{ return "Medium Integrity Level" }
		"MU"	{ return "Performance Monitor Users" }
		"NO"	{ return "Network Configuration Operators" }
		"NS"	{ return "Network Service Account" }
		"NU"	{ return "Network Logon User" }
		"PA"	{ return "Group Policy Administrators" }
		"PO"	{ return "Printer Operators" }
		"PS"	{ return "Principal Self" }
		"PU"	{ return "Power Users" }
		"RC"	{ return "Restricted Code" }
		"RD"	{ return "Terminal Server Users" }
		"RE"	{ return "Replicator" }
		"RO"	{ return "Enterprise Read-only DCs" }
		"RS"	{ return "RAS Servers Group" }
		"RU"	{ return "Alias PreWin2K" }
		"SA"	{ return "Schema Administrators" }
		"SI"	{ return "System Integrity Level" }
		"SO"	{ return "Server Operators" }
		"SU"	{ return "Service Logon User" }
		"SY"	{ return "Local System" }
		"WD"	{ return "Everyone" }
	}
	return "unknown SDDL group ( " + $code + " )"
}
# returns a string name of the Owner
function Get-SDDL_Owner( [string] $SDDLString )
{	$indexOwner	= $SDDLString.IndexOf( "O:" )
	$indexGroup	= $SDDLString.IndexOf( "G:" )
	
	if( $indexOwner -eq -1 -or $indexGroup -eq -1 )
	{	return "error parsing owner (1)"
	}
	if( $indexGroup -lt $indexOwner )
	{	return "error parsing owner (2)"
	}
	
	$substring	= $SDDLString.Substring( $indexOwner +2, $indexGroup -2 )

	return Get-SDDL_WellKnown $substring
}
# returns a string name of the Group
function Get-SDDL_Group( [string] $SDDLString )
{	$indexGroup	= $SDDLString.IndexOf( "G:" )
	$indexDACL	= $SDDLString.IndexOf( "D:" )
	
	if( $indexDACL -eq -1 -or $indexGroup -eq -1 )
	{	return "error parsing group (1)"
	}
	if( $indexDACL -lt $indexOwner )
	{	return "error parsing group (2)"
	}
	
	$substring	= $SDDLString.Substring( $indexGroup +2, $indexDACL -2 -$indexGroup )

	return Get-SDDL_WellKnown $substring
}
# returns a string name of ACE type
function Get-SDDL_Ace_Type( [string] $code )
{	if( $code -eq $null -or $code -eq "" )
	{	return ""
	}

	switch( $code )
	{
		"A"		{ return "Access Allowed" }
		"D"		{ return "Access Denied" }
		"OA"	{ return "Access Allowed Object" }
		"OD"	{ return "Access Denied Object" }
		"AU"	{ return "Audit" }
		"AL"	{ return "Alarm" }
		"OU"	{ return "Audit Object" }
		"OL"	{ return "Alaram Object" }
		"ML"	{ return "Mandatory Label" }
	}
	return "Unknown ACE Type: " + $code
}
# returns a string array of ACE flags
function Get-SDDL_Ace_Flags( [string] $code )
{	$retstring	= @()
	if( $code -eq $null -or $code -eq "" )
	{	return $retstring
	}


	while( $code.Length -gt 0 )
	{	if( $code.Length -gt 1 )
		{	$tempcode	= $code.Substring( 0, 2 )
			$code		= $code.Substring( 2 )
		} else
		{	$tempcode	= $code
			$code		= ""
		}


		switch( $tempcode )
		{
			"CI"	{ $retstring	+= "Container Inherit" }
			"OI"	{ $retstring	+= "Object Inherit" }
			"NP"	{ $retstring	+= "No Propagate Inherit" }
			"IO"	{ $retstring	+= "Inherit Only" }
			"ID"	{ $retstring	+= "Inherited" }
			"SA"	{ $retstring	+= "Audit Successful" }
			"FA"	{ $retstring	+= "Audit Failure" }
		}
	}
	return $retstring
}
# returns a string array of ACE rights
function Get-SDDL_Ace_Rights( [string] $code )
{	$retstring	= @()
	if( $code -eq $null -or $code -eq "" )
	{	return $retstring
	}

	while( $code.Length -gt 0 )
	{	if( $code.Length -gt 1 )
		{	$tempcode	= $code.Substring( 0, 2 )
			$code		= $code.Substring( 2 )
		} else
		{	$tempcode	= $code
			$code		= ""
		}

		if( $tempcode.StartsWith( "0x" ) )
		{	$tempcode	= $code.Substring( 0, 6 )
			$code		= $code.Substring( 6 )
			$retstring	+= ( "0x" + $tempcode ).ToString( )
		}

		switch( $tempcode )
		{
			"GA"	{ $retstring	+= "Generic All" }
			"GR"	{ $retstring	+= "Generic Read" }
			"GW"	{ $retstring	+= "Generic Write" }
			"GX"	{ $retstring	+= "Generic Execute" }
			"RC"	{ $retstring	+= "Read" }
			"SD"	{ $retstring	+= "Delete" }
			"WD"	{ $retstring	+= "Write DAC" }
			"WO"	{ $retstring	+= "Write Owner" }
			"RP"	{ $retstring	+= "Read Property" }
			"WP"	{ $retstring	+= "Write Property" }
			"CC"	{ $retstring	+= "Create Child" }
			"DC"	{ $retstring	+= "Delete Child" }
			"LC"	{ $retstring	+= "List Children" }
			"SW"	{ $retstring	+= "Self Write" }
			"LO"	{ $retstring	+= "List Object" }
			"DT"	{ $retstring	+= "Delete Tree" }
			"CR"	{ $retstring	+= "Control Access" }
			"FA"	{ $retstring	+= "File All" }
			"FR"	{ $retstring	+= "File Read" }
			"FW"	{ $retstring	+= "File Write" }
			"FX"	{ $retstring	+= "File Execute" }
			"KA"	{ $retstring	+= "Reg Key All" }
			"KR"	{ $retstring	+= "Reg Key Read" }
			"KW"	{ $retstring	+= "Reg Key Write" }
			"KX"	{ $retstring	+= "Reg Key Execute" }
			"NR"	{ $retstring	+= "No Read Up" }
			"NW"	{ $retstring	+= "No Write Up" }
			"NX"	{ $retstring	+= "No Execute Up" }
		}
	}
	return $retstring
}
# returns a string of the SID / Account
function Get-SDDL_Ace_ObjectGUID( [string] $code )
{	if( $code -eq $null -or $code -eq "" )
	{	return ""
	}

	switch( $code )
	{
		"CR;ab721a53-1e2f-11d0-9819-00aa0040529b"	{ return "Change Password" }
		"CR;00299570-246d-11d0-a768-00aa006e0529"	{ return "Reset Password" }
	}
	return Get-SDDL_WellKnown $code
}
# returns a string of the SID / Account
function Get-SDDL_Ace_InheritObjectGUID( [string] $code )
{	if( $code -eq $null -or $code -eq "" )
	{	return ""
	}

	return Get-SDDL_WellKnown $code
}
# returns a string of the SID / Account
function Get-SDDL_Ace_SID( [string] $code )
{	if( $code -eq $null -or $code -eq "" )
	{	return ""
	}

	return Get-SDDL_WellKnown $code
}
# returns a string of full ACE info
function Get-SDDL_Ace( [string] $Ace )
{	$Ace	= $Ace.TrimStart( '(' )
	$Ace	= $Ace.TrimEnd( ')' )
	$array	= $Ace.Split( ';' )
	
	$ret		= ""
	$acetype	= Get-SDDL_Ace_Type $array[0]
	$aceflags	= Get-SDDL_Ace_Flags $array[1]
	$acerights	= Get-SDDL_Ace_Rights $array[2]
	$aceobjg	= Get-SDDL_Ace_ObjectGUID $array[3]
	$aceiobjg	= Get-SDDL_Ace_InheritObjectGUID $array[4]
	$acesid		= Get-SDDL_Ace_SID $array[5]
	
	$ret		+= "Type:`t" + $acetype + "`r`n"
	if( $aceflags -ne $null -and $aceflags.Count -gt 0 )
	{	$ret	+= "Flags:`t"
		foreach( $flag in $aceflags )
		{	$ret	+= $flag + "`r`n"
		}
	}
	if( $acerights -ne $null -and $acerights.Count -gt 0 )
	{	$ret	+= "Rights:`t"
		foreach( $right in $acerights )
		{	$ret	+= $right + "`r`n"
		}
	}
	if( $aceobjg -ne $null -and $aceobjg -ne "" )
	{	$ret	+= "Ace Obj:`t" + $aceobjg + "`r`n"
	}
	if( $aceiobjg -ne $null -and $aceiobjg -ne "" )
	{	$ret	+= "Ace IObj:`t" + $aceiobjg + "`r`n"
	}
	if( $acesid -ne $null -and $acesid -ne "" )
	{	$ret	+= "Ace SID:`t" + $acesid + "`r`n"
	}
	return $ret
}
# returns a string array of the flags for a DACL or SACL
function Get-ACL_Flags( [string] $flags )
{	$ret	= @()

	if( $flags -eq $null -or $flags -eq "" )
	{	return $ret
	}

	while( $flags.Length -gt 0 )
	{
		switch( $flags.SubString( 0, 1 ) )
		{
			"P"	{	$ret	+= "Protected"
				}
			"A"	{	switch( $flags.SubString( 1, 1 ) )
					{
						"R"	{	$ret	+= "Auto Inherit Req"
							}
						"I"	{	$ret	+= "Auto Inherit"
							}
					}
					$flags	= $flags.Substring( 1 )
				}
		}
		$flags	= $flags.Substring( 1 )
	}
	return $ret
}
function Get-SDDL_DACL( [string] $SDDLString )
{	$indexDACL	= $SDDLString.IndexOf( "D:" )
	$indexSACL	= $SDDLString.IndexOf( "S:" )
	
	if( $indexDACL -eq -1 )
	{	return "error parsing DACL (1)"
	}
	if( $indexSACL -ne -1 -and $indexSACL -lt $indexDACL )
	{	return "error parsing DACL (2)"
	}
	
	if( $indexSACL -ne -1 )
	{	$substring	= $SDDLString.Substring( $indexDACL +2, $indexSACL -2 -$indexDACL )
	} else
	{	$substring	= $SDDLString.Substring( $indexDACL +2 )
	}

	$ret	= "DACL:`r`n"
	$array	= $substring.Split( '(' )
	$index	= 0
	if( -not $array[0].EndsWith( ')' ) )
	{	$dflags	= Get-ACL_Flags $array[0]
		if( $dflags -ne $null -and $dflags.Count -gt 0 )
		{	$ret	+= "Flags:`t"
			foreach( $dflag in $dflags )
			{	$ret	+= $dflag + "`r`n"
			}
		}

		$index++
	}
	while( $index -lt $array.Count )
	{
		$rAce	= Get-SDDL_Ace $array[ $index ]
		$ret	+= $rAce + "`r`n"
		$index++
	}

	return $ret
}
function Get-SDDL_SACL( [string] $SDDLString )
{	$indexSACL	= $SDDLString.IndexOf( "S:" )
	
	if( $indexSACL -eq -1 )
	{	return ""
	}
	
	$substring	= $SDDLString.Substring( $indexSACL +2 )

	$ret	= "SACL:`r`n"
	$array	= $substring.Split( '(' )
	$index	= 0
	if( -not $array[0].EndsWith( ')' ) )
	{	$sflags	= Get-ACL_Flags $array[0]
		if( $sflags -ne $null -and $sflags.Count -gt 0 )
		{	$ret	+= "Flags:`t"
			foreach( $dflag in $dflags )
			{	$ret	+= $dflag + "`r`n"
			}
		}

		$index++
	}
	while( $index -lt $array.Count )
	{
		$rAce	= Get-SDDL_Ace $array[ $index ]
		$ret	+= $rAce + "`r`n"
		$index++
	}

	return $ret
}

# main interface
#ex. Format-SDDL "O:BAG:DUD:(A;ID;FA;;;BA)(A;ID;FA;;;SY)(A;ID;0x1301bf;;;AU)(A;ID;0x1200a9;;;BU)"
function Format-SDDL( [string] $SDDLString )
{	$ret	= ""
	$ret	+= "Owner: " + (Get-SDDL_Owner $SDDLString) + "`r`n"
	$ret	+= "Group: " + (Get-SDDL_Group $SDDLString) + "`r`n"
	$ret	+= (Get-SDDL_DACL $SDDLString) + "`r`n"
	$ret	+= (Get-SDDL_SACL $SDDLString) + "`r`n"
	return $ret
}

###########################################################
#
# Last Update: 5-11-2011
# Author: jlaborde
#
# Description:
#  retrieve EnableDOCM key
#
# Usage:
#  Get-EnableDCOM
#
# Example:
#  $local:OnOrOff = Get-EnableDCOM
#   returns $true or $false
#
###########################################################

function Get-EnableDCOM(  )
{	$local:value	= (Get-ItemProperty "registry::HKEY_LOCAL_MACHINE\Software\Microsoft\OLE" EnableDCOM).EnableDCOM.ToUpper( )
	if( $local:value -eq "Y" )
	{	return $true
	}
	return $false
}


###########################################################
#
# Last Update: 3-20-2012
# Author: jlaborde
#
# Description:
#  used to log a 'root cause' message
#
# Usage:
#  AlertKnownIssue $true / $false "RootCauseID" "Description of error" "FTE Only" / "Partners" / "Internal" / "Public"
#
###########################################################

# Visibility = FTE Only, Partners, Internal, or Public
function AlertKnownIssue( [string]$sRootCauseID, [string]$sStatement, [string]$sVisibility )
{
	switch( $sVisibility )
	{
		"FTE Only"	{ $vis	= 1 }
		"Partners"	{ $vis	= 2 }
		"Internal"	{ $vis	= 3 }
		"Public"	{ $vis	= 4 }
		default		{ $vis	= 1 }
	}

	if( $global:gDebugSDPOn )
	{	Update-DiagRootCause -Id $sRootCauseID -Detected $true
		Write-GenericMessage -RootCauseID $sRootCauseID -Visibility $vis -SolutionTitle $sStatement
	} else
	{	"Issue detected: " + $sRootCauseID + ", " + $vis + ", " + $sStatement
	}
}

# SIG # Begin signature block
# MIIjiAYJKoZIhvcNAQcCoIIjeTCCI3UCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAzPoqinxv9sJh5
# RAjDS9ymd3yg5ZT5JlYD5qz4bd1mfaCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgLHrynAQE
# r35IzOW3LmlAG2x53q0QDlGdjaVGwEQQbhEwOAYKKwYBBAGCNwIBDDEqMCigCIAG
# AFQAUwBToRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20gMA0GCSqGSIb3DQEB
# AQUABIIBALQoe4jnIjXZzZeo28e+0uMpWXGTqNJAlOBRYXd9eQpzVSGm6KYcFbhg
# fP3NjcvUnHEyr6fRbiJhEfCZHNWVhwbWrL5fBm7lbw7ayKXEw8Ct6o9o+DhyFAZ1
# dPp9oEdbcrtzJCEmdjO+FOOPjzsvvIcTJd+cSWxeS7gZzY8I5l/tRopPzeQkojQS
# DAPPw/Rixt9smDiTE5J+EN3BJ7HJoqB15n2s4zPJh1zn88pwrOvPMPkIzjsJKHIS
# xp4EYBV31kDVteeWslcx55xPJv+mPQwM8mnEkntd9f/T/0E+5ipYPWB/LOMzdtcw
# YFPjlTjKQCReZxwLaTtIeitguoOB/x+hghLxMIIS7QYKKwYBBAGCNwMDATGCEt0w
# ghLZBgkqhkiG9w0BBwKgghLKMIISxgIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBVQYL
# KoZIhvcNAQkQAQSgggFEBIIBQDCCATwCAQEGCisGAQQBhFkKAwEwMTANBglghkgB
# ZQMEAgEFAAQgYoLuXLhHoOcXhxW9Wsas2UB26H3HQC16GNBuGnZNKNACBmGB56/O
# exgTMjAyMTExMTExNjUzMzQuMDE1WjAEgAIB9KCB1KSB0TCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjc4
# ODAtRTM5MC04MDE0MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloIIORDCCBPUwggPdoAMCAQICEzMAAAFchtLj7Dn2izgAAAAAAVwwDQYJKoZI
# hvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjEwMTE0
# MTkwMjE3WhcNMjIwNDExMTkwMjE3WjCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVl
# cnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjc4ODAtRTM5MC04MDE0
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0CorPq8qH2JAsmgS8lwJTB3l+dq3BBeY
# hkyUnzi/iewy5+d8lsbrbd/9Tw4G7WzI5c5ntXMc54L/6shmvNwlBpDyvmUJCOf1
# +IbeOT6mo9IVGXfD1gYWOi7L8XG5IDqz8y/tvQZLRtodOUkWBG4MoGAGxNqAZHhJ
# GYecV2tKFPe2TVPdYBItMYhJ4YbHiLQPIO7PzNBWamkvz4FTKI+KvRb9dk6y4DoU
# TGPeBO/JMt+INWGY1zDM+/ktCWshWKvSbb7tQNNjyKfMeX/YKUfg3ja6ptaT0fYj
# iukIJxRZIHDWbwN7iFOxMZARPuqJH4V8js9CUlD715/sA0B+U9I2GwIDAQABo4IB
# GzCCARcwHQYDVR0OBBYEFF/zFKw5KHKAkAV/uJp7LWMYwbo+MB8GA1UdIwQYMBaA
# FNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9j
# cmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8y
# MDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAt
# MDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJ
# KoZIhvcNAQELBQADggEBAHh5TPbXfiBzDhwj9TLZ7aOQ7u16krtPlZe3vpr8DP+l
# 00I3oHUPpBhFEcv3QmYaVkx1S3Ab8DoT1Go2oO/1odDz/YUsVyus05OANDRyNn/0
# zHyy2jXuTitbbZC9Ng5AEHXii40CwOWhn1qpz9C2aLwkUd3oxzu8TmgOB5UabfLx
# 6vtSAufiCRMhifyV5M9j0fbK6gt9dtDxeuXRZYUFuZmbq3cMQb6vqtoiY0ns+sFA
# eel1fEKOMXlY08xg14oRYD5GTIDkUPlgDS4pe2U13keC/Bxaj8AIbK4+W7HBgFwM
# JlAUVq2i/S42M6xDEQxGADOkDm+oQ47H9NQRgWRxEEkwggZxMIIEWaADAgECAgph
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
# UHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjc4ODAtRTM5MC04
# MDE0MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEw
# BwYFKw4DAhoDFQCe4qWjxp8oR5Wcfl3rI/ieTmnwTKCBgzCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5TeaszAiGA8y
# MDIxMTExMTE3MzU0N1oYDzIwMjExMTEyMTczNTQ3WjB3MD0GCisGAQQBhFkKBAEx
# LzAtMAoCBQDlN5qzAgEAMAoCAQACAiFfAgH/MAcCAQACAhIKMAoCBQDlOOwzAgEA
# MDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAI
# AgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAVXAdKn/lMW/gnsO2JEUsF6mB+jVg
# poyQ/hEO/28e1Au/U5H4FmntnWQIq4D1vxPgSbBupOIyq2QvLrBWuHISKG4/0dyT
# Fxk3t4wBO3LTRbE3hbqitkULxYxAxzzb4mvZC+3fWy+P2FtNdXSJwQ76uV3YY9eO
# WjcF77irx2hv+3UxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMAITMwAAAVyG0uPsOfaLOAAAAAABXDANBglghkgBZQMEAgEFAKCCAUow
# GgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCACUN10
# 3DVwRxNcEao49AzUklpPxsHDh1Wo1jGTDX2PdjCB+gYLKoZIhvcNAQkQAi8xgeow
# gecwgeQwgb0EIE8tZFfCIE9sADBJzKQgK1A99C4giEZvFe+0XI8MGea1MIGYMIGA
# pH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFchtLj7Dn2izgA
# AAAAAVwwIgQgqSv4EQvpBzWF6zocglBNqyq/V0k68HrqFqM/DvcP7LYwDQYJKoZI
# hvcNAQELBQAEggEAd4rR1QErX2e3GFfuS7kk1diK3DmFXYGdPnucaAqUenkEOiy0
# sozV+Grbd+6W+vLA3yuPK/8p6da9p5wFBx0XFOerb3W+AXBfFdanhxBm8so67rGW
# yqO2qwpGv38XLDwuNuLHwfvdNVMdKf6rC/Fe9KCelE5AhKcZ/vkQ/5xydDjAde52
# YdoLOdreYOajoHeg9v9x4bA/flGrEW1w37m98ZPk5KNqL5ttGDmcGdLUm/8WpRhu
# GL8ZBX3t80Luz49Gl2Wf/u1q1JWHeKJNu4IcRKlJXLQHZ7wx04ivZzUCGfQCB0NL
# CZj5r3yQ8/GJ0DWIImSmTJ8l8zcoYNtO5d4f2w==
# SIG # End signature block
