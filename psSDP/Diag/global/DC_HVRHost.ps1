#************************************************
# DC_HVRHost.ps1
# Version 1.0 - 7/24/14
# Author: jasonf
#*******************************************************

param ([array]$vmNames)

Function ObtainHVRBrokerHostName()
{
	if(test-path "HKLM:System/CurrentControlSet/Services/Clussvc")
	{
		$HVRBrokerHostName = ((Get-ClusterResource | Where-Object {$_.ResourceType -eq "Virtual Machine Replication Broker"}).OwnerNode).name
		return $HVRBrokerHostName
	}
	else
	{
		return $null
	}
}

Function ObtainHVRBrokerProperties()
{
	"`n" | Out-File $outputfilename -Append
	"---------------------------------------------------" | Out-File $outputfilename -Append
	"Failover Cluster Hyper-V Replica broker information" | Out-File $outputfilename -Append
	"---------------------------------------------------" | Out-File $outputfilename -Append
	"`n" | Out-File $outputfilename -Append
	
	if(test-path "HKLM:System/CurrentControlSet/Services/Clussvc")
	{
		$brokerResources = Get-ClusterResource | Where-Object {$_.ResourceType -eq "Virtual Machine Replication Broker"} 
		if ($brokerResources.length -gt 0)
		{
			foreach ($resource in $brokerResources)
			{
				$resource | Format-List | Out-File $outputfilename -Append
				if ($resource.state -ne "Online")
				{
					"[Error]: resource is not online `n" | Out-File $outputfilename -Append
					$resourceStatus = "red"
				}
				else
				{
					if ($resourceStatus -ne "red")
					{
						$resourceStatus = "green"
					}
				}
			}
		}
		else
		{
			"[Error]: $ComputerName is a cluster node but no broker resource is configured `n" | Out-File $outputfilename -Append
			$resourceStatus = "red"
		}
		$TableString += "`t<tr><td>" + $Image.$resourceStatus + "Hyper-V Replica Resource State " + "</td></tr>`r`n"
	}
	else
	{
		"$ComputerName is not a cluster node" | Out-File $outputfilename -Append
	}
}

Function ObtainCertificateProperties()
{
	"`n" | Out-File $outputfilename -Append
	"--------------------------------------" | Out-File $outputfilename -Append
	"certificate information" | Out-File $outputfilename -Append
	"--------------------------------------" | Out-File $outputfilename -Append
	"`n" | Out-File $outputfilename -Append
	$CertificateThumbPrint = (Get-VMReplication $vm).CertificateThumbprint
	$certs = Get-ChildItem cert: -recurse | Where-Object{$_.Thumbprint -eq $CertificateThumbprint}
	
	if ($null -ne $certs)
	{
	foreach ($certificate in $certs)
	{
		$certificate | Format-List | Out-File $outputfilename -Append
	}
	}
	else
	{
		"[error]:  no certificate with thumbprint $CertificateThumbPrint found in certificate store" | Out-File $outputfilename -Append
	}
}

Function RunPing ([string]$PingCmd="")
{	
	$PingCmd.Replace(":", "_")
	$PingCmdLength = $PingCmd.Length + 5
	$pingOutputFileName = Join-Path $PWD.Path "ping.txt"
	
	#"`n" 					| Out-File -FilePath $pingOutputFileName -encoding ASCII -append
	"-" * ($PingCmdLength)	| Out-File -FilePath $pingOutputFileName -encoding ASCII -append
	"Ping $PingCmd"		| Out-File -FilePath $pingOutputFileName -encoding ASCII -append
	"-" * ($PingCmdLength)	| Out-File -FilePath $pingOutputFileName -encoding ASCII -append
	#"`n" 					| Out-File -FilePath $pingOutputFileName -encoding ASCII -append

	$ProcessName = "cmd.exe"
	$Arguments = "/c ping.exe " + $PingCmd + " >> `"$pingOutputFileName`""
	BackgroundProcessCreate -Process $ProcessName -Arguments $Arguments -CollectFiles $false | out-null
	waitforbackgroundprocesses 
	#because of encoding issues with ping.exe, output to temporary file, then get content of temporary file, then delete file. 
	$pingOutput = Get-Content $pingOutputFileName
	$pingOutput | Out-File $outputfilename -Append
	Remove-Item $pingOutputFileName -Force
	#check ping output for a reply, e.g. "time=264ms" or "time<1ms"
	$pingReplyReceived = $false
	$regex = ".*?(time).*?\d+(ms)"
	if (($pingOutput | Where-Object{$_ -match $regex}).count -gt 0)
	{
		#we received a reply
		$pingReplyReceived = $true
	}
	else
	{
		#we didn't receive a reply
	}
	return $pingReplyReceived
}

#use http://msdn.microsoft.com/en-us/library/hh850306(v=vs.85).aspx to test replictation:
#RecoveryConnectionPoint - server name
#RecoveryServerPortNumber - port number
#AuthenticationType - 1 Kerberos, 2 Certificate
#CertificateThumbPrint - Certificate thumbprint to use when the AuthenticationType parameter is certificate based authentication
#BypassProxyServer - Bypass the proxy server when connecting to the replica server

Function TestReplicationConnection ([string]$RecoveryConnectionPoint, [int]$RecoveryServerPortNumber, [int]$AuthenticationType, [string]$CertificateThumbPrint, [bool]$BypassProxyServer)
{
	$MSVMReplicationServiceClass = Get-CimInstance -Namespace 'root\virtualization\v2' -Class 'Msvm_ReplicationService'

	$job = [WMI]$MSVMReplicationServiceClass.TestReplicationConnection($RecoveryConnectionPoint,$RecoveryServerPortNumber,$AuthenticationType,$CertificateThumbPrint,$BypassProxyServer).Job

	$TestVMReplicationSucceeded = $false
	for ($i = 0; $i -lt 5; $i++)
	{
	    if ($job.ErrorCode -ne 0)
	    {
	        start-sleep 1
	    }
	    else
	    {
	        $i=5
	        $TestVMReplicationSucceeded = $true
	    }    
	}

	if ($TestVMReplicationSucceeded)
	{
	    "VM replication test succeeded" | Out-File $outputfilename -Append
	}
	else
	{
	    "[error] VM replication test failed using http://msdn.microsoft.com/en-us/library/hh850306(v=vs.85).aspx.  Dumping job information:`n" | Out-File $outputfilename -Append
	    $job | Out-File $outputfilename -Append
	}
	return $TestVMReplicationSucceeded
}

# Red/Yellow/Green status indicator
$Image = @{ 
"Red" = "<font face=`"Webdings`" color=`"Red`">n </font>"; 
"Yellow" = "<font face=`"Webdings`" color=`"Orange`">n </font>"; 
"Green" = "<font face=`"Webdings`" color=`"Green`">n </font>"; 
}

foreach ($vm in $vmNames)
{	
	$vmReplication = get-vmreplication $vm
	$primaryServer = $vmReplication.PrimaryServer
	$replicaServer = $vmReplication.ReplicaServer
	$authType = $vmReplication.AuthenticationType
	$replicaServerPort = $vmReplication.ReplicaServerPort
	$VMReplicationAuthorizationEntry = Get-VMReplicationAuthorizationEntry 
	$Item_Summary = new-object PSObject
	$outputfilename = join-path $pwd.Path ($ComputerName + "_Hyper-V_Replica_" + $vm) 

	$HVRBrokerHostName = ObtainHVRBrokerHostName
	$isPrimaryClusterNode = $false
	$isReplicaClusterNode = $false
	if ($null -ne $HVRBrokerHostName)
	{
		"[info]:  HVR broker host name:  $HVRBrokerHostName" | WriteTo-StdOut
		if (($primaryServer -ne $ComputerName) -and ($replicaServer -ne $ComputerName))
		{
			$dependencyExpression = (Get-ClusterResourceDependency ((Get-ClusterResource | Where-Object {$_.ResourceType -eq "Virtual Machine Replication Broker"}).Name)).DependencyExpression
			if (((($primaryServer).split("."))[0]).ToString() -match ($dependencyExpression.replace("([","")).replace("])",""))
			{
				$isPrimaryClusterNode = $true
			}
			elseif (((($replicaServer).split("."))[0]).ToString() -match ($dependencyExpression.replace("([","")).replace("])",""))
			{
				$isReplicaClusterNode = $true
			}
		}
	}
	
	if (((($primaryServer).split("."))[0] -eq $ComputerName) -or $isPrimaryClusterNode)
	{
		$outputfilename += "_primary.txt"
		
		"--------------------------------------" + ("-" * $ComputerName.length) | Out-File $outputfilename -Append
		"Hyper-V Replica information for host: $ComputerName" | Out-File $outputfilename -Append
		"--------------------------------------" + ("-" * $ComputerName.length) | Out-File $outputfilename -Append
		
		#Primary server configuration
		$vmReplication | Format-List | Out-File $outputfilename  -Append
		
		#Primary server tests
		
		#################################################
		#Test 3 - Ping replica server from primary server
		#################################################
		$pingReplyReceived = RunPing -PingCmd $replicaServer
		if ($pingReplyReceived -eq $true)
		{
			#green - we were able to get a reply from $replicaserver
			$pingStatus = "green"
		}
		else
		{
			#yellow - we didn't get a reply from $replicaserver when we attempted to ping it
			$pingStatus = "yellow"
		}
		
		#output
		$TableString += "`t<tr><td>" + $Image.$pingStatus + "Ping $replicaServer from $primaryServer " + "</td></tr>`r`n"
	
		
		###########
		#end Test 3
		###########
		
		###################################################
		#Test 4 - Verify that proxy servers are not present
		###################################################
		"`n" | Out-File $outputfilename -Append
		"--------------------------------------" | Out-File $outputfilename -Append
		"Proxy server configuration information" | Out-File $outputfilename -Append
		"--------------------------------------" | Out-File $outputfilename -Append
		"`n" | Out-File $outputfilename -Append
		invoke-expression "Netsh winhttp show proxy" | Out-File $outputfilename -Append
		#todo table
		###########
		#end Test 4
		###########
		
		#########################################
		#test 5 - Primary Server is Authenticated
		#########################################
		"`n" | Out-File $outputfilename -Append
		"-----------------------------------------------------------------------------------------------" | Out-File $outputfilename -Append
		"Test VM replication connectivity using Msvm_ReplicationService.TestReplicationConnection method" | Out-File $outputfilename -Append
		"http://msdn.microsoft.com/en-us/library/hh850306(v=vs.85).aspx" | Out-File $outputfilename -Append
		"-----------------------------------------------------------------------------------------------" | Out-File $outputfilename -Append
		"`n" | Out-File $outputfilename -Append
		
		#todo - logic to decide whether to bypass proxy server
		$BypassProxyServer = $false
		if ($authType -match "Kerberos")
		{
			$intAuthType = 1
		}
		else
		{
			$intAuthType = 2
			$CertificateThumbPrint = (Get-VMReplication $vm).CertificateThumbprint
		}
		$TestReplicationConnection = TestReplicationConnection -RecoveryConnectionPoint $replicaServer -RecoveryServerPortNumber $replicaServerPort -AuthenticationType $intAuthType -CertificateThumbprint $CertificateThumbPrint -BypassProxyServer $BypassProxyServer
		
		if ($TestReplicationConnection -eq $true)
		{
			$TestReplicationConnectionStatus = "green"
		}
		else
		{
			$TestReplicationConnectionStatus = "red"
		}
		$TableString += "`t<tr><td>" + $Image.$TestReplicationConnectionStatus + "Test replication connectivity from $primaryServer to $replicaServer " + "</td></tr>`r`n"
		###########
		#end Test 5
		###########
		
		####################################################################################################
		#Test 10 - If Kerberos authentication is chosen, make sure that both machines are in trusted domains
		####################################################################################################
		if ($authType -match "Kerberos")
		{
			"`n" | Out-File $outputfilename -Append
			"--------------------------------------" | Out-File $outputfilename -Append
			"nltest /domain_trusts output" | Out-File $outputfilename -Append
			"--------------------------------------" | Out-File $outputfilename -Append
			"`n" | Out-File $outputfilename -Append
			invoke-expression "nltest /domain_trusts" | Out-File $outputfilename -Append
			$replicaDomainName = (Get-CimInstance -computername $replicaServer WIN32_ComputerSystem).Domain
			$primaryDomainName = (Get-CimInstance WIN32_ComputerSystem).Domain
			$replicaDomainTrustedStatus = "red"
			if ($primaryDomainName -match $replicaDomainName)
			{
				$replicaDomainTrustedStatus = "green"
			}
			else
			{
				$domainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
				$domainTrusts = $DomainInfo.GetAllTrustRelationships()
				foreach ($trust in $domainTrusts)
				{
					if ($trust.TargetName -match $replicaDomainName)
					{
						if ($trust.TrustDirection -eq "Bidirectional")
						{
							$replicaDomainTrustedStatus = "green"	
						}
					}
				}
				$forestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
				$forestTrusts = $ForestInfo.GetAllTrustRelationships()
				foreach ($trust in $forestTrusts)
				{
					if ($trust.TargetName -match $replicaDomainName)
					{
						if ($trust.TrustDirection -eq "Bidirectional")
						{
							$replicaDomainTrustedStatus = "green"
						}
					}
				}
			}
			$TableString += "`t<tr><td>" + $Image.$replicaDomainTrustedStatus + "Check if Domain is trusted" + "</td></tr>`r`n"
		}
		############
		#end Test 10
		############
		
		####################################################################################################
		#Test 11 - If Kerberos authentication is chosen, check if the SPN registration is successful 
		####################################################################################################
		if ($authType -match "Kerberos")
		{
			"`n" | Out-File $outputfilename -Append
			"------------------------------" | Out-File $outputfilename -Append
			"setspn /l $computername output" | Out-File $outputfilename -Append
			"------------------------------" | Out-File $outputfilename -Append
			invoke-expression "setspn /l $computername" | Out-File $outputfilename -Append
			"`n" | Out-File $outputfilename -Append
		}
		############
		#end Test 11
		############
		
		####################################################################################################
		#Test 12 - If Certificate authentication is chosen, check certificate properties
		####################################################################################################
		if ($authType -match "Certificate")
		{
			ObtainCertificateProperties
		}
		############
		#end Test 12
		############
		
		####################################################################################################
		#Test 13 - Check if any third-party monitoring tool is running in the environment
		####################################################################################################
		#todo - revisit QnA
		############
		#end Test 13
		############
		
		#########
		#Cluster
		#########
		ObtainHVRBrokerProperties
		############
		#end cluster
		############
		
		$TableString = ("<table>`r`n" + $TableString + "</table>") 
		add-member -inputobject $Item_Summary -membertype noteproperty -name "Tests Performed" -value $TableString
		$Item_Summary | ConvertTo-Xml2 | update-diagreport -id ("11") -name "Hyper-V Replica Tests for $vm" -verbosity informational
		$TableString = $null	
		$Item_Summary = $null
	}
	elseif (((($replicaServer).split("."))[0] -eq $ComputerName) -or $isReplicaClusterNode)
	{
		$outputfilename += "_replica.txt"

		
		"--------------------------------------" + ("-" * $ComputerName.length) | Out-File $outputfilename -Append
		"Hyper-V Replica information for host: $ComputerName" | Out-File $outputfilename -Append
		"--------------------------------------" + ("-" * $ComputerName.length) | Out-File $outputfilename -Append

		#Replica server configuration
		$vmReplication | Format-List | Out-File $outputfilename -Append
		
		#Replica server tests

		##############################################################
		#Test 1 - Verify that recovery server is configured as replica
		##############################################################

		"`n" | Out-File $outputfilename -Append
		"--------------------------------------" + ("-" * $vm.length) | Out-File $outputfilename -Append
		"Replication state for virtual machine:  $vm" | Out-File $outputfilename -Append
		"--------------------------------------" + ("-" * $vm.length) | Out-File $outputfilename -Append
		"`n" | Out-File $outputfilename -Append
		(get-vm $vm).ReplicationState | Out-File $outputfilename -Append
		###########
		#end Test 1
		###########	
		
		############################################
		#Test 2 - Verify network listener on replica 
		############################################
		"`n" | Out-File $outputfilename -Append
		"---------------------------------------------------------" | Out-File $outputfilename -Append
		"Hyper-V Replica Network Listener information"
		"`"Netsh http show servicestate | findstr HVRROOT`" output" | Out-File $outputfilename -Append
		"---------------------------------------------------------" | Out-File $outputfilename -Append
		"`n" | Out-File $outputfilename -Append
		
		Invoke-Expression "Netsh http show servicestate | findstr HVRROOT" | Out-File $outputfilename -Append
				
		###########
		#end Test 2
		###########		
		
		###################################################
		#Test 4 - Verify that proxy servers are not present
		###################################################
		"`n" | Out-File $outputfilename -Append
		"--------------------------------------" | Out-File $outputfilename -Append
		"Proxy server configuration information" | Out-File $outputfilename -Append
		"--------------------------------------" | Out-File $outputfilename -Append
		"`n" | Out-File $outputfilename -Append
		invoke-expression "Netsh winhttp show proxy" | Out-File $outputfilename -Append
		###########
		#end Test 4
		###########
		
		#######################################################################
		#Test 6 - Verify that primary server is authorized to write to recovery
		#######################################################################
		"`n" | Out-File $outputfilename -Append
		"------------------------------------------" | Out-File $outputfilename -Append
		"Get-VMReplicationAuthorizationEntry output" | Out-File $outputfilename -Append
		"------------------------------------------" | Out-File $outputfilename -Append
		"`n" | Out-File $outputfilename -Append
		$VMReplicationAuthorizationEntry | Out-File $outputfilename -Append
		###########
		#end Test 6
		###########
		
		################################################################################
		#Test 7 - Verify that the folder given in Hyper-V settings is readable/writeable
		################################################################################
		"`n" | Out-File $outputfilename -Append
		"--------------------------------------" | Out-File $outputfilename -Append
		"Storage location ACL information" | Out-File $outputfilename -Append
		"--------------------------------------" | Out-File $outputfilename -Append
		"`n" | Out-File $outputfilename -Append
		get-acl $VMReplicationAuthorizationEntry.storageloc | Format-List | Out-File $outputfilename -Append		
		###########
		#end Test 7
		###########
		
		################################################
		#Test 8 - Verify that Firewall rules are enabled
		################################################
		$HVRHTTPListenerRuleStatus = "red"
		if ($authType -match "Kerberos")
		{
			"`n" | Out-File $outputfilename -Append
			"-----------------------------------------------------" | Out-File $outputfilename -Append
			"firewall rule configuration (kerberos authentication)" | Out-File $outputfilename -Append
			"-----------------------------------------------------" | Out-File $outputfilename -Append
			$netshOutput = invoke-expression "netsh advfirewall firewall show rule name=`"Hyper-V Replica HTTP Listener (TCP-In)`"" 
			$netshOutput | Out-File $outputfilename -Append
			$netshOutput | ForEach-Object {if ($_ -match "Yes"){$HVRHTTPListenerRuleStatus = "green"}}
			"`n" | Out-File $outputfilename -Append
		}
		else
		{
			"`n" | Out-File $outputfilename -Append
			"--------------------------------------------------------------" | Out-File $outputfilename -Append
			"firewall rule configuration (certificate-based authentication)" | Out-File $outputfilename -Append
			"--------------------------------------------------------------" | Out-File $outputfilename -Append
			$netshOutput = invoke-expression "netsh advfirewall firewall show rule name=`"Hyper-V Replica HTTPS Listener (TCP-In)`"" 
			$netshOutput | Out-File $outputfilename -Append
			$netshOutput | ForEach-Object{if ($_ -match "Yes"){$HVRHTTPListenerRuleStatus = "green"}}
			"`n" | Out-File $outputfilename -Append
		}
		$TableString += "`t<tr><td>" + $Image.$HVRHTTPListenerRuleStatus + "Verify that firewall rules are enabled" + "</td></tr>`r`n"
		###########
		#end Test 8
		###########
		
		############################################################
		#Test 9 - Check if there are any WAN optimizers in the setup
		############################################################
		#todo - revisit QnA
		###########
		#end Test 9
		###########
		
		####################################################################################################
		#Test 11 - If Kerberos authentication is chosen, check if the SPN registration is successful 
		####################################################################################################
		if ($authType -match "Kerberos")
		{
			"`n" | Out-File $outputfilename -Append
			"------------------------------" | Out-File $outputfilename -Append
			"setspn /l $computername output" | Out-File $outputfilename -Append
			"------------------------------" | Out-File $outputfilename -Append
			invoke-expression "setspn /l $computername" | Out-File $outputfilename -Append
			"`n" | Out-File $outputfilename -Append
		}
		############
		#end Test 11
		############
		
		####################################################################################################
		#Test 12 - If Certificate authentication is chosen, check certificate properties
		####################################################################################################
		if ($authType -match "Certificate")
		{
			ObtainCertificateProperties
		}
		############
		#end Test 12
		############
		
		####################################################################################################
		#Test 13 - Check if any third-party monitoring tool is running in the environment
		####################################################################################################
		#todo - revisit QnA
		############
		#end Test 13
		############
		
		####################################################################################################
		#Test 14 - Check antivirus exclusions for replica directories
		####################################################################################################
		#todo - revisit QnA
		############
		#end Test 14
		############
		
		####################################################################################################
		#Test 15 - Verify that the replica storage location has enough space to accommodate the primary VHDs
		####################################################################################################
		#todo - validate detection logic for this case
		"`n" | Out-File $outputfilename -Append
		"--------------------------------------" | Out-File $outputfilename -Append
		"Free space information" | Out-File $outputfilename -Append
		"--------------------------------------" | Out-File $outputfilename -Append
		"`n" | Out-File $outputfilename -Append
		$vmStorageDrive = split-path ($VMReplicationAuthorizationEntry.storageloc) -qualifier
		$FreeSpace = (Get-CimInstance -Query "Select * from Win32_LogicalDisk where Name =`'$vmStorageDrive`'").FreeSpace /1GB
		"$FreeSpace GB available free space on $vmStorageDrive" | Out-File $outputfilename -Append
		############
		#end Test 15
		############
		
		####################################################################################################
		#Test 16 - Check the replication state of the VM
		####################################################################################################
		############
		#end Test 16
		############
		
		#########
		#Cluster
		#########
		ObtainHVRBrokerProperties
		############
		#end cluster
		############
		
		$TableString = ("<table>`r`n" + $TableString + "</table>") 
		add-member -inputobject $Item_Summary -membertype noteproperty -name "Tests Performed" -value $TableString
		$Item_Summary | ConvertTo-Xml2 | update-diagreport -id ("11") -name "Hyper-V Replica Tests for $vm" -verbosity informational
		$TableString = $null	
		$Item_Summary = $null
	}
	else
	{
		"this host is not primary or replica for the VM:  $vm" | WriteTo-StdOut
	}
	$fileDescription = "$vm replication information"
	$sectionDescription = "Hyper-V Replica Information" 
	collectfiles -filesToCollect $outputfilename -fileDescription $fileDescription -sectionDescription $sectionDescription -noFileExtensionsOnDescription
	$outputfilename = $null
	$fileDescription = $null
	$sectionDescription = $null
}


# SIG # Begin signature block
# MIInoQYJKoZIhvcNAQcCoIInkjCCJ44CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCrmYdF/ZTZslpy
# 1oXgWAx0QttXtRVxQfPubTtytmPfxKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHPc1o6NKeWdnemO2ljGDAlm
# 69YCO2pAa2gch9xi+uPdMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQC1KCCr8ihgDYuJCS4wUVjfvAoV8Ars36p/sLXf0lPZNEip968FEcr7
# yR0k6PNcUy4CGoYHOMo0B+nfHTsQ3E7Q2WKtZ6P+b2I8mXTQknnZceff1AG3cqIK
# 25iYanQk/okFT4MO/rzRIB/e7Iqtpj4GaMttLkOrIp35/x0Kt2cjVQLlN1q5yjnf
# UX/a3wlgozGqksIUW13gT8s99woMoDLSlFm5HjWseK7poyY5VQDZgupELcI3m/Z6
# Ea1y0LWhG5no9L9l08aigJzMzhSrerDMCgivcZvYA9Ft8dw2/AcDQLRWxEqXwZ6r
# fwCZsPF2EpIEJS6kbTgXbWWlWhwnr+5aoYIXCTCCFwUGCisGAQQBgjcDAwExghb1
# MIIW8QYJKoZIhvcNAQcCoIIW4jCCFt4CAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIOiVNSjLN9HQQ4iOpJLRM/wGAq7+mPeIgMVivwSG8SCRAgZi2xAP
# ScwYEzIwMjIwODAxMDc0MDMyLjc2MVowBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
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
# CRABBDAvBgkqhkiG9w0BCQQxIgQgm2RK/YEE9U3DxEVCw8neHOXW5tx5b8cfBMzL
# P+dmne0wgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAOHK/6sIVgEVSVD3Ar
# vk6OyQKvRxFHKyraUzbN1/AKVzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABqwkJ76tj1OipAAEAAAGrMCIEIHI+RQKHTZ2Id7/ufvKq
# /DQk+dqQy1YkmvsPNzOkpL0iMA0GCSqGSIb3DQEBCwUABIICAKVn8tRdL5h0kK/w
# WegNmHsee+78tE7RKckUTcgJWNSvv0/3F0/u0Bv/GU7IjPdCISagqeLSN0nToZzI
# mYoDTypCd8EkOvdgyFNtc/fOcrHFu5tUTmBG+QaesixWKOvYcaHYZ4SF577Q7Epy
# T2wBS4SJnvAwvIff67UJyRY9HAedidi3wDK256SANzQV7Y58ehvBNFaCfHxjsoPD
# wyggerWto/Jdgs4Jj0+mbyCFWXMEzaKW0dgXniYSOvSNnULR96ZwE2Yy4foWfgCU
# Ve+MCKQ8Ai7dTXWyhSQ0opf8EqlnKouftwW7bdT5y1L1jlI+G37ySU9qVo5CSv0A
# swhaxRlJJI1QHHAKNhUrqHQQapnwEo2DGx5/wMrG2bL4Cnk2SLp6P+FqyK1hxwuK
# pWrCGm85jWfc3p6/k4JzvrZvwMN0kozSVzQ2YPQbbpO4LrqODQe1lPjqlh4lUSQw
# ynzC44EjzXxDINugBnFbEExmyWFIEeIU/9jUWBHaPcxaPovUdGAuJSBvH/WBk+xw
# HomomF6VCDO7k+U+gqIgTiQUcCf1kui1lUQnIlabXenSG2c8dA8fx0lrRtPR1eCf
# 7WMaCSZKjHtsgCfwVGp3No47jt4ytIOu/fMmUhEcEPZwjtnj5oF84qbz9cPwUdgr
# 8LJmjPeGSV2Hz2rIDlMNSHV1fDCH
# SIG # End signature block
