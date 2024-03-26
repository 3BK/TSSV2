#************************************************
# DC_DnsDhcpDynamicUpdates.ps1
# Version 1.0
# Date: 2014
# Author: Boyd Benson (bbenson@microsoft.com); Joel Christiansen (joelch@microsoft.com)
# Description: Collects information about DNS and DHCP Dynamic Updates.
# Called from: Networking Diags
#*******************************************************

Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
		 # later use return to return the exception message to an object:   return $Script:ExceptionMessage
	}

Import-LocalizedData -BindingVariable ScriptVariable
Write-DiagProgress -Activity $ScriptVariable.ID_CTSDHCPServer -Status $ScriptVariable.ID_CTSDHCPServerDescription

function RunNetSH ([string]$NetSHCommandToExecute="")
{
	Write-DiagProgress -Activity $ScriptVariable.ID_CTSDHCPServer -Status "netsh $NetSHCommandToExecute"
	
	$NetSHCommandToExecuteLength = $NetSHCommandToExecute.Length + 6
	"-" * ($NetSHCommandToExecuteLength) + "`r`n" + "netsh $NetSHCommandToExecute" + "`r`n" + "-" * ($NetSHCommandToExecuteLength) | Out-File -FilePath $OutputFile -append

	$CommandToExecute = "cmd.exe /c netsh.exe " + $NetSHCommandToExecute + " >> $OutputFile "
	RunCmD -commandToRun $CommandToExecute  -CollectFiles $false
}


function RunPS ([string]$RunPScmd="", [switch]$ft)
{
	$RunPScmdLength = $RunPScmd.Length
	"-" * ($RunPScmdLength)		| Out-File -FilePath $OutputFile -append
	"$RunPScmd"  				| Out-File -FilePath $OutputFile -append
	"-" * ($RunPScmdLength)  	| Out-File -FilePath $OutputFile -append
	
	if ($ft)
	{
		# This format-table expression is useful to make sure that wide ft output works correctly
		Invoke-Expression $RunPScmd	|format-table -autosize -outvariable $FormatTableTempVar | Out-File -FilePath $outputFile -Width 500 -append
	}
	else
	{
		Invoke-Expression $RunPScmd	| Out-File -FilePath $OutputFile -append
	}
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append
	"`n"	| Out-File -FilePath $OutputFile -append	
}


$sectionDescription = "Dynamic DNS Updates (Server side)"


#----------W8/WS2012 powershell cmdlets
# detect OS version and SKU
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber

$outputFile= $Computername + "_DnsDhcpDynamicUpdates_info.TXT"

"========================================"	| Out-File -FilePath $OutputFile -append
"Dynamic DNS Update Troubleshooting"		| Out-File -FilePath $OutputFile -append
"========================================"	| Out-File -FilePath $OutputFile -append
"Questions:"	| Out-File -FilePath $OutputFile -append
"[1] Q: What configuration settings does the DHCP Server have for DNS Registrations?"	| Out-File -FilePath $OutputFile -append
"      A: Review the section `"DHCP Server DNS Settings`""	| Out-File -FilePath $OutputFile -append
"  "	| Out-File -FilePath $OutputFile -append
"[2] Q: Is the DHCP Server configured for DNS Credentials?"	| Out-File -FilePath $OutputFile -append
"      A: Review the section named `"DHCP Server DNS Credentials`""	| Out-File -FilePath $OutputFile -append
"  "	| Out-File -FilePath $OutputFile -append
"[3] Q: What accounts are members of the DnsUpdateProxy group?"	| Out-File -FilePath $OutputFile -append
"      A: Review the section named `"DnsUpdateProxy Group Members`""	| Out-File -FilePath $OutputFile -append
"  "	| Out-File -FilePath $OutputFile -append
"[4] Q: How is the DHCP Server configured for the registry values DynamicDNSQueueLength and DatabaseCleanupInterval?"	| Out-File -FilePath $OutputFile -append
"      A: Review the section named `"DHCP Server registry values`""	| Out-File -FilePath $OutputFile -append
"  "	| Out-File -FilePath $OutputFile -append
"[5] Q: What DNS Reverse Lookup Zones exist?"	| Out-File -FilePath $OutputFile -append
"      A: Review the section named `"DNS Reverse Lookup Zones`""	| Out-File -FilePath $OutputFile -append
"  "	| Out-File -FilePath $OutputFile -append
"[6] Q: What access does the permissions entry for `"Authenticated Users`" have on each Active Directory Integrated Zone"	| Out-File -FilePath $OutputFile -append
"    A: Review the section named `"DNS Permissions for `"Authenticated Users`" on each Active Directory Integrated Zone`""	| Out-File -FilePath $OutputFile -append
"  "	| Out-File -FilePath $OutputFile -append
"[7] Q: What are the DHCP Server DNS Settings on all the Scopes?"	| Out-File -FilePath $OutputFile -append
"    A: Review the section named `"DHCP Scope DNS Settings`""	| Out-File -FilePath $OutputFile -append
"  "	| Out-File -FilePath $OutputFile -append
"========================================"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append


"========================================"	| Out-File -FilePath $OutputFile -append
"[1] DHCP Server DNS Settings" 	| Out-File -FilePath $OutputFile -append
"========================================"	| Out-File -FilePath $OutputFile -append

$dhcpServerServiceStatus = get-service * | Where-Object {$_.name -eq "DHCPserver"}	
if ($null -ne $dhcpServerServiceStatus)
{
	if ((Get-Service "DHCPserver").Status -eq 'Running')
	{		
		if ($bn -ge 9200)
		{
			RunPS "Get-DhcpServerv4DnsSetting" 						# W8/WS2012, W8.1/WS2012R2	#fl
			"`n"	| Out-File -FilePath $OutputFile -append

			$DhcpServerv4DnsSettings = Get-DhcpServerv4DnsSetting
			"====================" 	| Out-File -FilePath $OutputFile -append
			"Representation of the User Interface with Current Settings"	| Out-File -FilePath $OutputFile -append
			"====================" 	| Out-File -FilePath $OutputFile -append

			"---------------------------------------------------------------------------"	| Out-File -FilePath $OutputFile -append
			"                        IPv4 Properties"	| Out-File -FilePath $OutputFile -append
			"---------------------------------------------------------------------------"	| Out-File -FilePath $OutputFile -append
			"           DNS tab"	| Out-File -FilePath $OutputFile -append
			"---------------------------------------------------------------------------"	| Out-File -FilePath $OutputFile -append
			"  You can setup the DHCP server to automatically update authoritative DNS" | Out-File -FilePath $OutputFile -append
			"  servers with the host (A) and pointer (PTR) records of DHCP clients." | Out-File -FilePath $OutputFile -append
			
			if ($DhcpServerv4DnsSettings.DynamicUpdates -eq "OnClientRequest")
			{
				"  [X] Enable DNS Dynamic updates according to the settings below:"	| Out-File -FilePath $OutputFile -append
				"     [X] Dynamically update DNS records only if requested by the DHCP"	| Out-File -FilePath $OutputFile -append
				"         clients"	| Out-File -FilePath $OutputFile -append
				"     [ ] Always dynamically update DNS records"	| Out-File -FilePath $OutputFile -append
			}
			elseif ($DhcpServerv4DnsSettings.DynamicUpdates -eq "Always")
			{
				"  [X] Enable DNS Dynamic updates according to the settings below:"	| Out-File -FilePath $OutputFile -append
				"     [ ] Dynamically update DNS records only if requested by the DHCP"	| Out-File -FilePath $OutputFile -append
				"         clients"	| Out-File -FilePath $OutputFile -append
				"     [X] Always dynamically update DNS records"	| Out-File -FilePath $OutputFile -append
			}
			if ($DhcpServerv4DnsSettings.DeleteDnsRROnLeaseExpiry -eq $true)
			{
				"  [X] Discard A and PTR records when lease is deleted"	| Out-File -FilePath $OutputFile -append
			}
			else
			{
				"  [ ] Discard A and PTR records when lease is deleted"	| Out-File -FilePath $OutputFile -append
			}
			if ($DhcpServerv4DnsSettings.UpdateDnsRRForOlderClients -eq $false)	
			{
				"  [ ] Dynamically update DNS records for DHCP clients that do not request"	| Out-File -FilePath $OutputFile -append
				"      updates (for example, clients running NT 4.0)"	| Out-File -FilePath $OutputFile -append
			}
			else
			{
				"  [X] Dynamically update DNS records for DHCP clients that do not request"	| Out-File -FilePath $OutputFile -append
				"      updates (for example, clients running NT 4.0)"	| Out-File -FilePath $OutputFile -append
			}
			if ($DhcpServerv4DnsSettings.DisableDnsPtrRRUpdate -eq $false)
			{
				#default: WS2012 R2
				"  [ ] Disable dynamic updates for DNS PTR records"	| Out-File -FilePath $OutputFile -append
			}
			else
			{
				"  [X] Disable dynamic updates for DNS PTR records"	| Out-File -FilePath $OutputFile -append
			}
			if ($DhcpServerv4DnsSettings.NameProtection -eq $false)
			{
				#default: WS2012 R2
				"  -------------------------------------------------------"	| Out-File -FilePath $OutputFile -append
				"   Name Protection"	| Out-File -FilePath $OutputFile -append
				"     DHCP name protection is disabled at the server level"	| Out-File -FilePath $OutputFile -append
				"     Configure button"	| Out-File -FilePath $OutputFile -append
				"       [ ] Enable Name Protection"	| Out-File -FilePath $OutputFile -append
				"  -------------------------------------------------------"	| Out-File -FilePath $OutputFile -append
			}
			else
			{
				#default: WS2012 R2
				"  -------------------------------------------------------"	| Out-File -FilePath $OutputFile -append
				"   Name Protection"	| Out-File -FilePath $OutputFile -append
				"     DHCP name protection is enabled at the server level"	| Out-File -FilePath $OutputFile -append
				"     Configure button"	| Out-File -FilePath $OutputFile -append
				"       [X] Enable Name Protection"	| Out-File -FilePath $OutputFile -append
				"  -------------------------------------------------------"	| Out-File -FilePath $OutputFile -append
			}
			"---------------------------------------------------------------------------"	| Out-File -FilePath $OutputFile -append
		}
		else
		{
			"This section is only available in WS2012/WS2012R2. Not collecting output since this is an earlier version of the OS."  | Out-File -FilePath $OutputFile -append
			"Please refer to the other DhcpServer and DnsServer output files."  | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{ "The `"DHCP Server`" service is not Running. Not running pscmdlets." 	| Out-File -FilePath $OutputFile -append }
}
else
{ "The `"DHCP Server`" service does not exist. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append }
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append



"========================================"	| Out-File -FilePath $OutputFile -append
"[2] DHCP Server DNS Credentials" 	| Out-File -FilePath $OutputFile -append
"========================================"	| Out-File -FilePath $OutputFile -append
if ($null -ne $dhcpServerServiceStatus)
{
	if ((Get-Service "DHCPserver").Status -eq 'Running')
	{		
		if ($bn -ge 9200)
		{
			$DhcpDnsCreds = Get-DhcpServerDnsCredential
			if ($DhcpDnsCreds.UserName -eq "")
			{
				"This DHCP Server is NOT configured for DNS Credentials." 	| Out-File -FilePath $OutputFile -append
			}
			else
			{
				"This DHCP Server is configured for DNS Credentials:" 	| Out-File -FilePath $OutputFile -append
				"UserName : " + ($DhcpDnsCreds).UserName 	| Out-File -FilePath $OutputFile -append
				"DomanName: " + ($DhcpDnsCreds).DomainName 	| Out-File -FilePath $OutputFile -append
			}
		}
		else
		{
			"This section is only available in WS2012/WS2012R2. Not collecting output since this is an earlier version of the OS."  | Out-File -FilePath $OutputFile -append
			"Please refer to the other DhcpServer and DnsServer output files."  | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{ "The `"DHCP Server`" service is not Running. Not running pscmdlets." 	| Out-File -FilePath $OutputFile -append }
}
else
{ "The `"DHCP Server`" service does not exist. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append }
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append

		
"========================================" 	| Out-File -FilePath $OutputFile -append
"[3] DnsUpdateProxy Group Members" 	| Out-File -FilePath $OutputFile -append
"========================================" 	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
if ($null -ne $dhcpServerServiceStatus)
{
	if ((Get-Service "DHCPserver").Status -eq 'Running')
	{		
		if ($bn -ge 9200)
		{
			# Alternate method using Get-ADGroupMember relies on the AD module, so not using this
			# $DnsUpdateProxyMembers = Get-ADGroupMember -identity DnsUpdateProxy
			
			Add-Type -AssemblyName System.DirectoryServices.AccountManagement
			$ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
			$DnsUpdateProxy = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($ContextType ,"DnsUpdateProxy")
			$DnsUpdateProxyMembers = $DnsUpdateProxy.GetMembers($true)
			"Members of the DnsUpdateProxy group:"	| Out-File -FilePath $OutputFile -append
			"------------------------------------"	| Out-File -FilePath $OutputFile -append
			$i=0
			foreach ($attribute in $DnsUpdateProxyMembers)
			{
				if ($null -ne ($attribute).SamAccountName)
				{
					$i++
					($attribute).SamAccountName	| Out-File -FilePath $OutputFile -append
				}
			}
			"There are $i members of the DnsUpdateProxy group."	| Out-File -FilePath $OutputFile -append
		}
		else
		{
			"This section is only available in WS2012/WS2012R2. Not collecting output since this is an earlier version of the OS."  | Out-File -FilePath $OutputFile -append
			"Please refer to the other DhcpServer and DnsServer output files."  | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{ "The DHCP Server service is not Running. Not running pscmdlets." 	| Out-File -FilePath $OutputFile -append }
}
else
{ "The `"DHCP Server`" service does not exist. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append }
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append



"========================================" 	| Out-File -FilePath $OutputFile -append
"[4] DHCP Server registry values" 	| Out-File -FilePath $OutputFile -append
"========================================" 	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
if ($null -ne $dhcpServerServiceStatus)
{
	if ((Get-Service "DHCPserver").Status -eq 'Running')
	{		
		if ($bn -ge 9200)
		{
			$keyPath = "HKLM:\SYSTEM\CurrentControlSet\services\DHCPServer\Parameters"
			if (Test-Path $keyPath)
			{
				$DynamicDNSQueueLength = (Get-ItemProperty -Path $keyPath).DynamicDNSQueueLength
				$DatabaseCleanupInterval = (Get-ItemProperty -Path $keyPath).DatabaseCleanupInterval

				"--------------------------------------------------" 	| Out-File -FilePath $OutputFile -append
				"DHCP Server regvalue DynamicDNSQueueLength" 	| Out-File -FilePath $OutputFile -append
				"--------------------------------------------------" 	| Out-File -FilePath $OutputFile -append
				"RegKey   : $keyPath" 	| Out-File -FilePath $OutputFile -append

				if ($null -ne $DynamicDNSQueueLength)
				{
					"RegValue : DynamicDNSQueueLength" 	| Out-File -FilePath $OutputFile -append
					"RegData  : $DynamicDNSQueueLength" 	| Out-File -FilePath $OutputFile -append
					"`n"	| Out-File -FilePath $OutputFile -append
					"The DynamicDNSQueueLength registry value exists in the registry with a value of $DynamicDNSQueueLength minutes." 	| Out-File -FilePath $OutputFile -append
					"By default, the DynamicDNSQueueLength registry value does NOT exist." 	| Out-File -FilePath $OutputFile -append
				}
				else
				{
					"RegValue : Does not exist" 	| Out-File -FilePath $OutputFile -append
					"`n"	| Out-File -FilePath $OutputFile -append
					"The DynamicDNSQueueLength registry value does not exist. This is the default configuration." 	| Out-File -FilePath $OutputFile -append
					"It may be necessary to increase this value." 	| Out-File -FilePath $OutputFile -append
				}
				"`n"	| Out-File -FilePath $OutputFile -append

				"--------------------------------------------------" 	| Out-File -FilePath $OutputFile -append
				"DHCP Server regvalue DatabaseCleanupInterval" 	| Out-File -FilePath $OutputFile -append
				"--------------------------------------------------" 	| Out-File -FilePath $OutputFile -append
				"RegKey   : $keyPath" 	| Out-File -FilePath $OutputFile -append
				if ($null -ne $DatabaseCleanupInterval)
				{
					"RegValue : DatabaseCleanupInterval" 	| Out-File -FilePath $OutputFile -append
					"RegData  : $DatabaseCleanupInterval" 	| Out-File -FilePath $OutputFile -append
					"`n"	| Out-File -FilePath $OutputFile -append
					"The DatabaseCleanupInterval registry value is set to $DatabaseCleanupInterval minutes." 	| Out-File -FilePath $OutputFile -append
				}
				else
				{
					"RegValue : Does not exist" 	| Out-File -FilePath $OutputFile -append
					"`n"	| Out-File -FilePath $OutputFile -append
					"The DatabaseCleanupInterval registry value does not exist." 	| Out-File -FilePath $OutputFile -append
				}
			}
			else
			{
				"The DHCP Service registry value does not exist. Not doing registry queries."	| Out-File -FilePath $OutputFile -append
			}
		}
		else
		{
			"This section is only available in WS2012/WS2012R2. Not collecting output since this is an earlier version of the OS."  | Out-File -FilePath $OutputFile -append
			"Please refer to the other DhcpServer and DnsServer output files."  | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{ "The `"DHCP Server`" service is not Running. Not running pscmdlets." 	| Out-File -FilePath $OutputFile -append }
}
else
{ "The `"DHCP Server`" service does not exist. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append }
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append



"========================================" 	| Out-File -FilePath $OutputFile -append
"[5] DNS Reverse Lookup Zones" 	| Out-File -FilePath $OutputFile -append
"========================================" 	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
if ($null -ne $dhcpServerServiceStatus)
{
	if ((Get-Service "DHCPserver").Status -eq 'Running')
	{		
		if ($bn -ge 9200)
		{
			$DnsServerReverseZonesAuto = new-object PSObject
			$DnsServerReverseZonesAdmin = new-object PSObject
			$DnsReverseZonesCount=0
			$DnsReverseZonesAutoCount = 0
			$DnsReverseZonesAdminCount = 0
			$DnsServerZones = Get-DnsServerZone
			foreach ($Zone in $DnsServerZones)
			{
				if (($Zone).IsReverseLookupZone -eq "True")
				{
					$DnsReverseZonesCount++
					if (($Zone).IsAutoCreated -eq $true) 	#((($Zone).ZoneName -eq "0.in-addr.arpa") -or (($Zone).ZoneName -eq "127.in-addr.arpa") -or (($Zone).ZoneName -eq "255.in-addr.arpa"))
					{
						$DnsReverseZonesAutoCount++
						$ZoneName = ($Zone).ZoneName
						add-member -inputobject $DnsServerReverseZonesAuto -membertype noteproperty -name "Auto $DnsReverseZonesAutoCount" -value $ZoneName
					}
					else
					{
						$DnsReverseZonesAdminCount++
						$ZoneName = ($Zone).ZoneName
						add-member -inputobject $DnsServerReverseZonesAdmin -membertype noteproperty -name "Admin $DnsReverseZonesAdminCount" -value $ZoneName
					}
				}
			}

			"`n"	| Out-File -FilePath $OutputFile -append
			"DNS Reverse Lookup Zones : $DnsReverseZonesCount" 	| Out-File -FilePath $OutputFile -append
			"--------------------------"	| Out-File -FilePath $OutputFile -append
			"Automatically created    : $DnsReverseZonesAutoCount" 	| Out-File -FilePath $OutputFile -append
			"--------------------------"	| Out-File -FilePath $OutputFile -append
			for ($i=1;$i -le $DnsReverseZonesAutoCount;$i++)
			{
				$DnsServerReverseZonesAuto.("Auto $i")		| Out-File -FilePath $OutputFile -append
			}
			"`n"	| Out-File -FilePath $OutputFile -append
			"--------------------------"	| Out-File -FilePath $OutputFile -append
			"Administrator created    : $DnsReverseZonesAdminCount" 	| Out-File -FilePath $OutputFile -append
			"--------------------------"	| Out-File -FilePath $OutputFile -append
			for ($i=1;$i -le $DnsReverseZonesAdminCount;$i++)
			{
				$DnsServerReverseZonesAdmin.("Admin $i")		| Out-File -FilePath $OutputFile -append
			}

			if ($DnsReverseZonesAdminCount -eq 0)
			{
				"*****"	| Out-File -FilePath $OutputFile -append
				"*****ALERT*****"	| Out-File -FilePath $OutputFile -append
				"*****"	| Out-File -FilePath $OutputFile -append
				"No Reverse Lookup Zones have been added by an Administrator."	| Out-File -FilePath $OutputFile -append
				"This is a known cause of failed registration attempts by the DHCP Server that leads to blocking in the DHCP Queue used for DNS registrations."	| Out-File -FilePath $OutputFile -append
			}
		}
		else
		{
			"This section is only available in WS2012/WS2012R2. Not collecting output since this is an earlier version of the OS."  | Out-File -FilePath $OutputFile -append
			"Please refer to the other DhcpServer and DnsServer output files."  | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{ "The `"DHCP Server`" service is not Running. Not running pscmdlets." 	| Out-File -FilePath $OutputFile -append }
}
else
{ "The `"DHCP Server`" service does not exist. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append }
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append

	


"========================================" 	| Out-File -FilePath $OutputFile -append
"[6] DNS Permissions for `"Authenticated Users`" on each Active Directory Integrated Zone" 	| Out-File -FilePath $OutputFile -append
"========================================" 	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
if ($null -ne $dhcpServerServiceStatus)
{
	if ((Get-Service "DHCPserver").Status -eq 'Running')
	{		
		if ($bn -ge 9200)
		{
			$dnsZones = get-dnsserverzone

			foreach ($dnsZone in $dnsZones)
			{
				$dnsZoneName = $dnsZone.ZoneName
				$dnsZoneDistinguishedName = $dnsZone.DistinguishedName
				$dnsZoneProperties = get-dnsserverzone -name $dnsZoneName
				$dnsZoneReplicationScope = $dnsZoneProperties.ReplicationScope
				if ($dnsZoneReplicationScope -eq "Forest")
				{
					# example: DC=ToAllDNSserversInThisForest.com,CN=MicrosoftDNS,DC=ForestDnsZones,DC=contoso,DC=com
					$dnsZoneLDAP = [ADSI]"LDAP://$dnsZoneDistinguishedName"
				}
				elseif ($dnsZoneReplicationScope -eq "Domain")
				{
					# example: DC=ToAllDNSserversInThisForest.com,CN=MicrosoftDNS,DC=ForestDnsZones,DC=contoso,DC=com
					$dnsZoneLDAP = [ADSI]"LDAP://$dnsZoneDistinguishedName"
				}
				elseif ($dnsZoneReplicationScope -eq "Legacy")
				{
					# $dnsZone = "ToAllDNSServersInThisDomainW2000"
					$dnsZoneLDAP = [ADSI]"LDAP://$dnsZoneDistinguishedName"
				}
				else
				{
					$dnsZoneLDAP = "NotADIntegrated"
				}

				if ($dnsZoneLDAP -ne "NotADIntegrated")
				{
					$dnsZoneObjectSecurityAccess = $dnsZoneLDAP.ObjectSecurity.Access

					foreach ($dnsZoneObject in $dnsZoneObjectSecurityAccess)
					{
					  $dnsZoneIdentityReference = $dnsZoneObject.IdentityReference
					  $dnsZoneActiveDirectoryRights = $dnsZoneObject.ActiveDirectoryRights

					  if ($dnsZoneIdentityReference -eq "NT AUTHORITY\Authenticated Users")
					  {
						if ($dnsZoneActiveDirectoryRights -eq "CreateChild")
						{
						"-" * 52								| Out-File -FilePath $outputFile -append
						"DNS Zone               : $dnsZoneName" | Out-File -FilePath $OutputFile -append
						"Distinguished Name     : $dnsZoneDistinguishedName" | Out-File -FilePath $OutputFile -append
						"Identity               : $dnsZoneIdentityReference" | Out-File -FilePath $OutputFile -append
						"ActiveDirectoryRights  : $dnsZoneActiveDirectoryRights" | Out-File -FilePath $OutputFile -append
						"This is the default setting."	| Out-File -FilePath $OutputFile -append
						"`n" | Out-File -FilePath $OutputFile -append
						"`n" | Out-File -FilePath $OutputFile -append
						}
						else
						{
						"-" * 52								| Out-File -FilePath $outputFile -append
						"DNS Zone               : $dnsZoneName" | Out-File -FilePath $OutputFile -append
						"Distinguished Name     : $dnsZoneDistinguishedName" | Out-File -FilePath $OutputFile -append
						"Identity               : $dnsZoneIdentityReference" | Out-File -FilePath $OutputFile -append
						"ActiveDirectoryRights  : $dnsZoneActiveDirectoryRights" | Out-File -FilePath $OutputFile -append
						"*****"	| Out-File -FilePath $OutputFile -append
						"*****ALERT*****"	| Out-File -FilePath $OutputFile -append
						"*****"	| Out-File -FilePath $OutputFile -append
						"This is NOT the default setting." | Out-File -FilePath $OutputFile -append
						"`n" | Out-File -FilePath $OutputFile -append
						"`n" | Out-File -FilePath $OutputFile -append
						}
					  }
					}
				}
			}
		}
		else
		{
			"This section is only available in WS2012/WS2012R2. Not collecting output since this is an earlier version of the OS."  | Out-File -FilePath $OutputFile -append
			"Please refer to the other DhcpServer and DnsServer output files."  | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{ "The `"DHCP Server`" service is not Running. Not running pscmdlets." 	| Out-File -FilePath $OutputFile -append }
}
else
{ "The `"DHCP Server`" service does not exist. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append }
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append





"========================================" 	| Out-File -FilePath $OutputFile -append
"[7] DHCP Scope DNS Settings" 	| Out-File -FilePath $OutputFile -append
"========================================" 	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
if ($null -ne $dhcpServerServiceStatus)
{
	if ((Get-Service "DHCPserver").Status -eq 'Running')
	{		
		if ($bn -ge 9200)
		{
			$dhcpServerScopes = Get-DhcpServerv4Scope
			foreach ($scope in $dhcpServerScopes)
			{
				"DNS Settings for DHCP Scope: " + $scope.ScopeId | Out-File -FilePath $OutputFile -append
				"----------------------------"  | Out-File -FilePath $OutputFile -append
				$scopeDnsSettings = Get-DhcpServerv4DnsSetting -ScopeId $scope.ScopeId

				"DynamicUpdates             : " + $scopeDnsSettings.DynamicUpdates | Out-File -FilePath $OutputFile -append
				"DeleteDnsRROnLeaseExpiry   : " + $scopeDnsSettings.DeleteDnsRROnLeaseExpiry | Out-File -FilePath $OutputFile -append
				"UpdateDnsRRForOlderClients : " + $scopeDnsSettings.UpdateDnsRRForOlderClients | Out-File -FilePath $OutputFile -append
				"DisableDnsPtrRRUpdate      : " + $scopeDnsSettings.DisableDnsPtrRRUpdate | Out-File -FilePath $OutputFile -append
				"NameProtection             : " + $scopeDnsSettings.NameProtection | Out-File -FilePath $OutputFile -append
				
				if (
					($scopeDnsSettings.DynamicUpdates -eq "OnClientRequest") -and
					($scopeDnsSettings.DeleteDnsRROnLeaseExpiry -eq $true) -and
					($scopeDnsSettings.UpdateDnsRRForOlderClients -eq $false) -and
					($scopeDnsSettings.DisableDnsPtrRRUpdate -eq $false) -and
					($scopeDnsSettings.NameProtection -eq $false)
					)
				{
					"These are the default settings."	| Out-File -FilePath $OutputFile -append
				}
				else
				{
					"**********"	| Out-File -FilePath $OutputFile -append
					"These are NOT the default settings."	| Out-File -FilePath $OutputFile -append
					"**********"	| Out-File -FilePath $OutputFile -append
				} 
				"`n"	| Out-File -FilePath $OutputFile -append
				"`n"	| Out-File -FilePath $OutputFile -append
			}
		}
		else
		{
			"This section is only available in WS2012/WS2012R2. Not collecting output since this is an earlier version of the OS."  | Out-File -FilePath $OutputFile -append
			"Please refer to the other DhcpServer and DnsServer output files."  | Out-File -FilePath $OutputFile -append
		}
	}
	else
	{ "The `"DHCP Server`" service is not Running. Not running pscmdlets." 	| Out-File -FilePath $OutputFile -append }
}
else
{ "The `"DHCP Server`" service does not exist. Not running ps cmdlets."	| Out-File -FilePath $OutputFile -append }
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append
"`n"	| Out-File -FilePath $OutputFile -append


CollectFiles -filesToCollect $OutputFile -fileDescription "Dynamic DNS Updates Server" -SectionDescription $sectionDescription
	

# SIG # Begin signature block
# MIInoQYJKoZIhvcNAQcCoIInkjCCJ44CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDRCehlp4WZAE1y
# TqZIJXqoWMOL9CW9Ibwh3UVRQy9bb6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
# OfsCcUI2AAAAAALLMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NTU5WhcNMjMwNTExMjA0NTU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC3sN0WcdGpGXPZIb5iNfFB0xZ8rnJvYnxD6Uf2BHXglpbTEfoe+mO//oLWkRxA
# wppditsSVOD0oglKbtnh9Wp2DARLcxbGaW4YanOWSB1LyLRpHnnQ5POlh2U5trg4
# 3gQjvlNZlQB3lL+zrPtbNvMA7E0Wkmo+Z6YFnsf7aek+KGzaGboAeFO4uKZjQXY5
# RmMzE70Bwaz7hvA05jDURdRKH0i/1yK96TDuP7JyRFLOvA3UXNWz00R9w7ppMDcN
# lXtrmbPigv3xE9FfpfmJRtiOZQKd73K72Wujmj6/Su3+DBTpOq7NgdntW2lJfX3X
# a6oe4F9Pk9xRhkwHsk7Ju9E/AgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUrg/nt/gj+BBLd1jZWYhok7v5/w4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQ3MDUyODAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAJL5t6pVjIRlQ8j4dAFJ
# ZnMke3rRHeQDOPFxswM47HRvgQa2E1jea2aYiMk1WmdqWnYw1bal4IzRlSVf4czf
# zx2vjOIOiaGllW2ByHkfKApngOzJmAQ8F15xSHPRvNMmvpC3PFLvKMf3y5SyPJxh
# 922TTq0q5epJv1SgZDWlUlHL/Ex1nX8kzBRhHvc6D6F5la+oAO4A3o/ZC05OOgm4
# EJxZP9MqUi5iid2dw4Jg/HvtDpCcLj1GLIhCDaebKegajCJlMhhxnDXrGFLJfX8j
# 7k7LUvrZDsQniJZ3D66K+3SZTLhvwK7dMGVFuUUJUfDifrlCTjKG9mxsPDllfyck
# 4zGnRZv8Jw9RgE1zAghnU14L0vVUNOzi/4bE7wIsiRyIcCcVoXRneBA3n/frLXvd
# jDsbb2lpGu78+s1zbO5N0bhHWq4j5WMutrspBxEhqG2PSBjC5Ypi+jhtfu3+x76N
# mBvsyKuxx9+Hm/ALnlzKxr4KyMR3/z4IRMzA1QyppNk65Ui+jB14g+w4vole33M1
# pVqVckrmSebUkmjnCshCiH12IFgHZF7gRwE4YZrJ7QjxZeoZqHaKsQLRMp653beB
# fHfeva9zJPhBSdVcCW7x9q0c2HVPLJHX9YCUU714I+qtLpDGrdbZxD9mikPqL/To
# /1lDZ0ch8FtePhME7houuoPcMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGYEwghl9AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIAuWgHVr8YYgGxEegxyfYhH
# B7Pt6Q4O3Myf+idH5cadMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCKbVEWgvEMpVANHRZblMqDAmU7oPSkCH0tkj8XK9apysQsFRy/35nL
# 8oFxsbNrrCqsNy7KM2sXyJFQRjG83BG5lgmUY2zyWN2DpTKW4ASrJ5fM+aW9mFFn
# efFj8FtXNbbMEHKCaLz2PhGAe3Mg1DlaEbM3Wrys8faAlZ7vrPi4u7XefzM4HbwE
# rIsNMxxJtn+Wa1lorlZ5wlbtUoktToEmN3QsVutNlem42NOng8dV8tZRI3GxiSNa
# Ry4GqKhbgN5Q66pk5Yx7uK1OHGdXl3cQjDkizTeZVfAn3fixk6js5zl9NrAwGQrN
# HOcnFcYHvNMDvyAIi7xVEz+85GRa0E/aoYIXCTCCFwUGCisGAQQBgjcDAwExghb1
# MIIW8QYJKoZIhvcNAQcCoIIW4jCCFt4CAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIAPpB5TsopkCkpHKVVOZgC8aaF2etLLbkPFcNcCCHhFnAgZi2xAP
# QoAYEzIwMjIwODAxMDczNjQzLjk5NFowBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4
# OTdBLUUzNTYtMTcwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaCCEVwwggcQMIIE+KADAgECAhMzAAABqwkJ76tj1OipAAEAAAGrMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMDMw
# MjE4NTEyOFoXDTIzMDUxMTE4NTEyOFowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4OTdBLUUzNTYtMTcw
# MTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmdS1o5dehASUsscLqyx2wm/WirNUfq
# kGBymDItYzEnoKtkhrd7wNsJs4g+BuM3uBX81WnO270lkrC0e1mmDqQt420Tmb8l
# wsjQKM6mEaNQIfXDronrVN3aw1lx9bAf7VZEA3kHFql6YAO3kjQ6PftA4iVHX3JV
# v98ntjkbtqzKeJMaNWd8dBaAD3RCliMoajTDGbyYNKTvxBhWILyJ8WYdJ/NBDpqP
# zQl+pxm6ZZVSeBQAIOubZjU0vfpECxHC5vI1ErrqapG+0oBhhON+gllVklPAWZv2
# iv0mgjCTj7YNKX7yL2x2TvrvHVq5GPNa5fNbpy39t5cviiYqMf1RZVZccdr+2vAp
# k5ib5a4O8SiAgPSUwYGoOwbZG1onHij0ATPLkgKUfgaPzFfd5JZSbRl2Xg347/Lj
# WQLR+KjAyACFb06bqWzvHtQJTND8Y0j5Y2SBnSCqV2zNHSVts4+aUfkUhsKS+GAX
# S3j5XUgYA7SMNog76Nnss5l01nEX7sHDdYykYhzuQKFrT70XVTZeX25tSBfy3Vac
# zYd1JSI/9wOGqbFU52NyrlsA1qimxOhsuds7Pxo+jO3RjV/kC+AEOoVaXDdminsc
# 3PtlBCVh/sgYno9AUymblSRmee1gwlnlZJ0uiHKI9q2HFgZWM10yPG5gVt0prXnJ
# Fi1Wxmmg+BH/AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUFFvO8o1eNcSCIQZMvqGf
# dNL+pqowHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgw
# VjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWlj
# cm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUF
# BwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
# KS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQsFAAOCAgEAykuUgTc1KMszMgsHbhgjgEGv/dCHFf0by99C45SR770/udCN
# NeqlT610Ehz13xGFU6Hci+TLUPUnhvUnSuz7xkiWRru5RjZZmSonEVv8npa3z1Qv
# eUfngtyi0Jd6qlSykoEVJ6tDuR1Kw9xU9yvthZWhQs/ymyOwh+mxt0C9wbeLJ92e
# r2vc9ly12pFxbCNDJ+mQ7v520hAvreWqZ02GOJhw0R4c1iP39iNBzHOoz+DsO0sY
# jwhaz9HrvYMEzOD1MJdLPWfUFsZ//iTd3jzEykk02WjnZNzIe2ENfmQ/KblGXHeS
# e8JYqimTFxl5keMfLUELjAh0mhQ1vLCJZ20BwC4O57Eg7yO/YuBno+4RrV0CD2gp
# 4BO10KFW2SQ/MhvRWK7HbgS6Bzt70rkIeSUto7pRkHMqrnhubITcXddky6GtZsmw
# M3hvqXuStMeU1W5NN3HA8ypjPLd/bomfGx96Huw8OrftcQvk7thdNu4JhAyKUXUP
# 7dKMCJfrOdplg0j1tE0aiE+pDTSQVmPzGezCL42slyPJVXpu4xxE0hpACr2ua0LH
# v/LB6RV5C4CO4Ms/pfal//F3O+hJZe5ixevzKNkXXbxPOa1R+SIrW/rHZM6RIDLT
# JxTGFDM1hQDyafGu9S/a7umkvilgBHNxZfk0IYE7RRWJcG7oiY+FGdx1cs0wggdx
# MIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGI
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylN
# aWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5
# MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciEL
# eaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa
# 4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxR
# MTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEByd
# Uv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi9
# 47SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJi
# ss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+
# /NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY
# 7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtco
# dgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH
# 29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94
# q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcV
# AQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0G
# A1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQB
# gjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# GQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB
# /wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0f
# BE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJv
# ZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4w
# TDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIB
# AJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRs
# fNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6
# Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveV
# tihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKB
# GUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoy
# GtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQE
# cb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFU
# a2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+
# k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0
# +CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cir
# Ooo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICzzCCAjgCAQEwgfyh
# gdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAn
# BgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjo4OTdBLUUzNTYtMTcwMTElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAW6h6/24WCo7W
# Zz6CEVAeLztcmD6ggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQUFAAIFAOaRa9gwIhgPMjAyMjA4MDEwMTAwMDhaGA8yMDIy
# MDgwMjAxMDAwOFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5pFr2AIBADAHAgEA
# AgIG1DAHAgEAAgIRNzAKAgUA5pK9WAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUA
# A4GBAAEU+pL+fVXcuqgydyRS2xu0KXbaAiTD3MltCnjkn3ekNvFgcP+4OrTJe4DA
# punTRCb4bvJrYifK/egPCUPI67+Obaj9M50cuVtH9NzEUFs8QheQObEU6tG04X/B
# v0cqzEG3yZKdp0O0h1k6MMtIrIccKN3JPMbdFmEHAeb7w1TAMYIEDTCCBAkCAQEw
# gZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGrCQnvq2PU6KkA
# AQAAAaswDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0B
# CRABBDAvBgkqhkiG9w0BCQQxIgQgXxKEt3y+wKFv+n2r2m3tUO3/RKxM3geHV0QM
# 2VVvevEwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAOHK/6sIVgEVSVD3Ar
# vk6OyQKvRxFHKyraUzbN1/AKVzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABqwkJ76tj1OipAAEAAAGrMCIEIHI+RQKHTZ2Id7/ufvKq
# /DQk+dqQy1YkmvsPNzOkpL0iMA0GCSqGSIb3DQEBCwUABIICAAjnkgjyDTE5jyx4
# F4wC0vSp6ak+aARtjGlr1S6n1vpJsdTx43Ru2VjMHm+IZoV69d63fRaZ/C2iosJ5
# Ti0nXNWcBtH0Tjrc8AxEAnoJHUrZmpGCTNOwMi/7NjXpogtMImZMWyh7ca5dRSF3
# FTgQdPdruzNs8kLPAFomLpRyTWY/uISkqjCB5IA5IaNRMwuSVbmkDfrZaLHd1hWW
# 16Hh4dFwGZbBgVIfG9h7ygwdccZo1BzIdZwnzBVClAwNDnaKAaw2T1dAzq18+pBQ
# RkS7DbIPBa6HGpj30/CeTM4xJC5XW7/UM90yW5YBD6KWclakBUsrXzor0dpoQ4bK
# JOzf+lNfJh/ooRhX9xSQuwD4i9ZNdRYOukS8AIi6M3G+e0L+fnIvxq8Y6jwzDXg8
# 19A8tLZjNuPngycpcHlXHeqFj6aSLnF26G3wFIAXWb5PGIEJuVrLrEYr+KNLfhzT
# hOIoUCrBQCRO+yIDUIjUVg2befucLcNgqOQSJCWTIEHy+nkE0GemYDeEu2yHyXBC
# qH+hJzMSpIvs770PzGOXW4NcTttehY2cuKjn3tYYfL0pGnjLhEUEu54pBPDO4W8z
# YBuJchqvSX1xHW1EUabv2xSZXwhPxhs4OENIE2wzmxMVv5lierHgPwFoypCr1pPO
# yvJ5g9WejQnHc9SnyMAVoPi9JBmY
# SIG # End signature block
