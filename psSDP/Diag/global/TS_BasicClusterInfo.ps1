#************************************************
# DC_BasicClusterInfo.ps1
# Version 2.0.3
# Date: 03-28-2010
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script writes to the report basic information regarding 
#              the cluster (Cluster Info, Nodes and Groups)
#************************************************


#Troubleshooter:

PARAM([switch] $IncludeCoreGroups)

# 2023-02-20 WalterE mod Trap #we#
trap [Exception]{
	WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; continue
	Write-Host "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_"
}
	
$ClusterSvcKey = "HKLM:\SYSTEM\CurrentControlSet\services\ClusSvc"

if (Test-Path $ClusterSvcKey){
	Import-LocalizedData -BindingVariable ClusterBasicInfo 
	Write-DiagProgress -activity $ClusterBasicInfo.ID_ClusterInfo -status $ClusterBasicInfo.ID_ClusterInfoObtaining

	$StartupType = (get-itemproperty -Path $ClusterSvcKey -Name "Start").Start
	if (($StartupType -eq 2) -or ($StartupType -eq 3)){  # Auto or Manual
		if ($StartupType -eq 2) {$StartupTypeDisplay = "Auto"}
		if ($StartupType -eq 3) {$StartupTypeDisplay = "Manual"}
		$ClusterSvc = Get-Service -Name ClusSvc
		if ($ClusterSvc.Status.Value__ -ne 4){ #Cluster Service is not running
			Update-DiagRootCause -id "RC_ClusterSvcDown" -Detected $true 
			$InformationCollected = @{"Service State"=$ClusterSvc.Status; "Startup Type"=$StartupTypeDisplay}
			Write-GenericMessage -RootCauseID "RC_ClusterSvcDown" -Component "FailoverCluster" -InformationCollected $InformationCollected -Verbosity "Error" -PublicContentURL "http://blogs.technet.com/b/askcore/archive/2010/06/08/windows-server-2008-and-2008r2-failover-cluster-startup-switches.aspx" -SupportTopicsID 8001 -MessageVersion 2 -Visibility 4
		}else{
			Update-DiagRootCause -Id "RC_ClusterSvcDown" -Detected $false
			$ClusterKey="HKLM:\Cluster"
			
			#   Win2K8 R2
			if ((Test-Path $ClusterKey) -and ($OSVersion.Build -gt 7600)){
				Import-Module FailoverClusters
				$Cluster = Get-Cluster
				$Cluster_Summary = new-object PSObject
				add-member -inputobject $Cluster_Summary -membertype noteproperty -name $ClusterBasicInfo.ID_ClusterName -value $cluster.Name
				add-member -inputobject $Cluster_Summary -membertype noteproperty -name $ClusterBasicInfo.ID_ClusterDomain -value $cluster.Domain
				add-member -inputobject $Cluster_Summary -membertype noteproperty -name $ClusterBasicInfo.ID_ClusterCSV -value $cluster.EnableSharedVolumes
				if ($cluster.EnableSharedVolumes -eq "Enabled"){
					add-member -inputobject $Cluster_Summary -membertype noteproperty -name $ClusterBasicInfo.ID_ClusterCSVRoot -value $cluster.SharedVolumesRoot
				}
				
				$Cluster_Summary | convertto-xml | update-diagreport -id 02_ClusterSummary -name $ClusterBasicInfo.ID_ClusterInfo -verbosity informational
				$ClusterQuorum_Summary = new-object PSObject
				$ClusterQuorum = Get-ClusterQuorum

				add-member -inputobject $ClusterQuorum_Summary -membertype noteproperty -name "Quorum Type" -value $ClusterQuorum.QuorumType
				if ($null -ne $ClusterQuorum.QuorumResource){
					add-member -inputobject $ClusterQuorum_Summary -membertype noteproperty -name "Quorum Resource" -value $ClusterQuorum.QuorumResource.Name
						switch ($ClusterQuorum.QuorumResource.State.value__){
							2 {$Color = "Green"} #ClusterResourceOnline 
							3 {$Color = "Black"} #ClusterResourceOffline
							4 {$Color = "Red"}   #ClusterResourceFailed
							default { $Color = "Orange" } #Other state
						}
						$State = "<font face=`"Webdings`" color=`"$Color`">n</font> " + $ClusterQuorum.QuorumResource.State
						$ResourceStateDisplay = $State + " - Owner: " + $ClusterQuorum.QuorumResource.OwnerNode
						add-member -inputobject $ClusterQuorum_Summary -membertype noteproperty -name "State" -value $ResourceStateDisplay
				}

				$ClusterQuorum_Summary | convertto-xml2 | update-diagreport -id 03_ClusterQuorumSummary -name "Quorum Information" -verbosity informational
				$ClusterNodes_Summary = new-object PSObject
				$ClusterNodesNotUp_Summary = new-object PSObject
				
				Write-DiagProgress -activity $ClusterBasicInfo.ID_ClusterInfo -status "Cluster Nodes"
				$Error.Clear()
				$ClusterNodes = Get-ClusterNode -ErrorAction SilentlyContinue #_# -EA added 2020-08-20
				
				if ($Error.Count -ne 0){
					$errorMessage = $Error[0].Exception.Message
					$errorCode = "0x{0:X}" -f $Error[0].Exception.ErrorCode
					$ServiceState = $ClusterSvc.Status
					Update-DiagRootCause -id "RC_ClusterInfoErr" -Detected 
					$InformationCollected = @{"Error Message"=$errorMessage; "Error Code"=$errorCode; "Service State" = $ServiceState}
					Write-GenericMessage -RootCauseID "RC_ClusterInfoErr" -InformationCollected $InformationCollected -Verbosity "Warning" -Component "FailoverCluster"  -SupportTopicsID 8001 -MessageVersion 2 -Visibility 3
				}
				
				if ($Null -ne $ClusterNodes){
					$ReportNodeNotUpNames=""
					foreach ($ClusterNode in $ClusterNodes){
						switch ($ClusterNode.State.value__){
							0 {$Color = "Green"} # Up
							1 {$Color = "Red"}   #Down
							default { $Color = "Orange" }
						}
						$State = "<font face=`"Webdings`" color=`"$Color`">n</font> " + $ClusterNode.State
						$NodeName = $ClusterNode.NodeName
						if ($NodeName -eq "$ComputerName") {$NodeName += "*"}
						add-member -inputobject $ClusterNodes_Summary -membertype noteproperty -name $NodeName -value $State
						if ($ClusterNode.State.value__ -ne 0 ){ 
							if ($ReportNodeNotUpNames -ne ""){
								$ReportNodeNotUpNames += ", "
							}
							$ReportNodeNotUpNames += $ClusterNode.NodeName + "/ " + $ClusterNode.State
							add-member -inputobject $ClusterNodesNotUp_Summary -membertype noteproperty -name $NodeName -value ($ClusterNode.State)
						}
					}
		
					if ($ReportNodeNotUpNames -ne ""){
						$XMLFile = "..\ClusterNodesDown.XML"
						#$XMLObj = $ClusterNodesNotUp_Summary | ConvertTo-Xml2 
						#$XMLObj.Save($XMLFile)
						Update-DiagRootCause -id "RC_ClusterNodeDown" -Detected $true #-Parameter @{"NotUpNodesXML"=$XMLFile}
						#$InformationCollected = @{"Cluster Node(s)/ State"= $ReportNodeNotUpNames}
						Write-GenericMessage -RootCauseID "RC_ClusterNodeDown" -InformationCollected $ClusterNodesNotUp_Summary -SupportTopicsID 8001 -MessageVersion 2 -Visibility 3
					}else{
						Update-DiagRootCause -Id "RC_ClusterNodeDown" -Detected $false
					}
					
					$ClusterNodes_Summary | ConvertTo-Xml2 | update-diagreport -id 04_ClusterNodes -name "Cluster Nodes" -verbosity informational
					Write-DiagProgress -activity $ClusterBasicInfo.ID_ClusterInfo -status "Cluster Groups"
					$ClusterGroups_Summary = new-object PSObject
					$ClusterGroupNotOnline_Summary = new-object PSObject
					if ($IncludeCoreGroups.IsPresent){
						$ClusterGroups = Get-ClusterGroup
					}else{
						$ClusterGroups = Get-ClusterGroup | Where-Object {$_.IsCoreGroup -eq $false}
					}
					
					if ($null -ne $ClusterGroups){
						$GroupNamesNotOnline = ""
						foreach ($ClusterGroup in $ClusterGroups) {
							switch ($ClusterGroup.State.value__) {
								0 {$Color = "Green"} #Online
								1 {$Color = "Black"}   #ClusterGroupOffline
								2 {$Color = "Red"} #ClusterGroupFailed
								3 {$Color = "Orange"} #ClusterGroupPartialOnline
								4 {$Color = "Yellow"} #ClusterGroupPending
								default { $Color = "Orange" } #Pending
							}

							$State = "<font face=`"Webdings`" color=`"$Color`">n</font> " + $ClusterGroup.State
							$GroupStateDisplay = $State + " - Owner: " + $ClusterGroup.OwnerNode
							if (($IncludeCoreGroups.IsPresent) -and ($ClusterGroup.IsCoreGroup)) {
								$ClusterGroupDisplay = $ClusterGroup.Name + " (Core Group)"
							}else{
								$ClusterGroupDisplay = $ClusterGroup.Name
							}
							add-member -inputobject $ClusterGroups_Summary -membertype noteproperty -name $ClusterGroupDisplay -value $GroupStateDisplay
							
							if (($ClusterGroup.State.value__ -eq 1) -or ($ClusterGroup.State.value__ -eq 2)){ 
								if ($GroupNamesNotOnline -ne ""){
									$GroupNamesNotOnline += ", "
								}
								$GroupNamesNotOnline += $ClusterGroup.Name + "/ " + $ClusterGroup.State
								add-member -inputobject $ClusterGroupNotOnline_Summary -membertype noteproperty -name $ClusterGroup.Name -value $GroupStateDisplay 
							}
						}

						if ($GroupNamesNotOnline -ne ""){
							$XMLFileName = "..\ClusterGroupsProblem.XML"
							#$XMLObj = $ClusterGroupNotOnline_Summary | ConvertTo-Xml2 
							#$XMLObj.Save($XMLFileName)
							Update-DiagRootCause -id "RC_ClusterGroupDown" -Detected $true #-Parameter @{"XMLFilename"=$XMLFileName}
							$InformationCollected = @{"Cluster Group(s)" = $ClusterGroupNotOnline_Summary}
							Write-GenericMessage -RootCauseID "RC_ClusterGroupDown" -InformationCollected $InformationCollected -Verbosity "Warning" -Component "FailoverCluster" -PublicContentURL "http://technet.microsoft.com/en-us/library/cc757139(WS.10).aspx"
						}else{
							Update-DiagRootCause -id "RC_ClusterGroupDown" -Detected $false
						}

						$ClusterGroups_Summary | ConvertTo-Xml2 | update-diagreport -id 05_ClusterGroup -name "Cluster Groups" -verbosity informational
						
						if ($clusterGroups.Length -le 50){
							foreach ($ClusterGroup in $ClusterGroups){
								$ClusterGroup_Summary = new-object PSObject
								$GroupName = $ClusterGroup.Name
								Write-DiagProgress -activity $ClusterBasicInfo.ID_ClusterInfo -status "Cluster Group $GroupName - Querying resources"
								foreach ($ClusterResourceType in get-clusterResource | Where-Object {$_.OwnerGroup.Name -eq $ClusterGroup.Name} | Select-Object ResourceType -Unique) {
									$ResourceTypeDisplayName = $ClusterResourceType.ResourceType.DisplayName
									Write-DiagProgress -activity $ClusterBasicInfo.ID_ClusterInfo -status "Cluster Group $GroupName - Querying $ResourceTypeDisplayName resources"
									$ResourceLine = ""
									foreach ($ClusterResource in get-clusterResource | Where-Object {($_.ResourceType.Name -eq $ClusterResourceType.ResourceType.Name) -and ($_.OwnerGroup.Name -eq $ClusterGroup.Name)}){
										switch ($ClusterResource.State.value__) {
											2 {$Color = "Green"} #Online
											3 {$Color = "Black"} #Offline
											4 {$Color = "Red"}   #ClusterResourceFailed
											default { $Color = "Orange" } #Pending or other state
										}
										$State = "<font face=`"Webdings`" color=`"$Color`">n</font> " + $ClusterResource.State
										if ($ResourceLine -ne "") { $ResourceLine += "<br/>" }
										$ResourceLine += $State + " - " + $ClusterResource.Name
									}			
									add-member -inputobject $ClusterGroup_Summary -membertype noteproperty -name $ResourceTypeDisplayName -value $ResourceLine
								}
								$strID = "05a_" + $GroupName + "_ClusterGroup"
								$ClusterGroup_Summary | ConvertTo-Xml2 | update-diagreport -id $strID -name "Cluster Group $GroupName" -verbosity informational
							}	
						}else{
							$ClusterGroup_Summary = new-object PSObject
							$ClusterGroup_Summary | ConvertTo-Xml2 | update-diagreport -id "05a" -name "A large number of cluster groups were detected on this system.  Detailed cluster group information is not available in Resultreport.xml" -verbosity informational
						}
						Write-DiagProgress -activity $ClusterBasicInfo.ID_ClusterInfo -status $ClusterBasicInfo.ID_ClusterInfoObtaining
					}
				}
				
				$ClusterNetWorks = get-clusternetwork
				if($null -ne $ClusterNetWorks){
					foreach($Psnetwork in $ClusterNetWorks){
					    $PSClusterNetWork = New-Object PSObject
						$AutoMetric = ""
						$RoleDescription = ""
						$IPv6Addresses = ""
						$State = ""
						$Ipv4Addresses = ""
						if($Psnetwork.IPv6Addresses.Count -eq 0){
							$IPv6Addresses = "None/0"
						}else{
							for($c =0 ;$c -lt $Psnetwork.IPv6Addresses.Count; $c++ ){
								if($c -eq $Psnetwork.IPv6Addresses.Count-1){
									$IPv6Addresses += $Psnetwork.IPv6Addresses[$c] + " / " + $Psnetwork.Ipv6PrefixLengths[$c]
								}else{
									$IPv6Addresses += $Psnetwork.IPv6Addresses[$c] + " / " + $Psnetwork.Ipv6PrefixLengths[$c] +"<br/>"
								}
							}
						}
						
						if($Psnetwork.Ipv4Addresses.Count -eq 0){
							$Ipv4Addresses = "None / None"
						}else{
							for($i =0 ;$i -lt $Psnetwork.Ipv4Addresses.Count; $i++ ){
								if($i -eq $Psnetwork.Ipv4Addresses.Count-1){
									$Ipv4Addresses += $Psnetwork.Ipv4Addresses[$i] + " / " +$Psnetwork.AddressMask[$i]
								}else{
									$Ipv4Addresses += $Psnetwork.Ipv4Addresses[$i] + " / " +$Psnetwork.AddressMask[$i] +"<br/>"
								}
							}
						}
						
						if($Psnetwork.AutoMetric){
							$AutoMetric = " [AutoMetric]"
						}
						switch ($Psnetwork.Role){
								0 {$RoleDescription = " (Do not allow cluster network communications on this network)"}
								1 {$RoleDescription = " (Allow cluster network communications on this network"}
								3 {$RoleDescription = " (Allow clients to connect through this network)"}
						   default{$RoleDescription = ' (Unknown)' }
						}

						$color = $null
						switch ($Psnetwork.State.value__){
										1 {$Color = "Black"} #down
										2 {$Color = "Red"} #partitioned 
										3 {$Color = "Green"} #up
										default { $Color = "Orange" } #unavailable  or unknow
						}
						$State = "<font face=`"Webdings`" color=`"$Color`">n</font> " + $Psnetwork.State
						Add-member -InputObject $PSClusterNetWork -Membertype Noteproperty -Name "State" -Value $State
						Add-member -InputObject $PSClusterNetWork -Membertype Noteproperty -Name "IPv6 Addresses" -Value $IPv6Addresses
						Add-member -InputObject $PSClusterNetWork -Membertype Noteproperty -Name "IPv4 Addresses" -Value $Ipv4Addresses
						Add-member -InputObject $PSClusterNetWork -Membertype Noteproperty -Name "Metric" -Value ($Psnetwork.Metric.ToString() + $AutoMetric)
						Add-member -InputObject $PSClusterNetWork -Membertype Noteproperty -Name "Role" -Value ($Psnetwork.Role.ToString() + $RoleDescription)
	
						$PsClusterNetworkInfo = Convert-PSObjectToHTMLTable -PSObject $PSClusterNetWork
						$ClusterNetWorkInfoSection = New-Object PSObject
						Add-member -InputObject $ClusterNetWorkInfoSection -Membertype Noteproperty -Name $Psnetwork.Name -Value $PsClusterNetworkInfo
						$ClusterNetWorkName = $Psnetwork.Name
						$ClusterNetWorkCluster = $Psnetwork.Cluster
						$SectionName = "Cluster Networks - $ClusterNetWorkCluster"
						$ClusterNetWorkInfoSection | ConvertTo-Xml2 | update-diagreport -id  "06_$ClusterNetWorkName" -name $SectionName -verbosity informational -Description "Cluster Networks"
						Write-DiagProgress -activity $ClusterBasicInfo.ID_ClusterInfo -status "Cluster Network Information"
					}
				}
			}
			
			#   Win2K8 & 2003
			if ((Test-Path "HKLM:\Cluster") -and ($OSVersion.Build -lt 7600)){
				$CommandToRun = "`"" + $pwd.Path  + "\clusmps.exe`" /S /G /P:`"" + $pwd.Path + "`""
				$FileTocollect = $pwd.Path  + "\" + $Computername + "_cluster_mps_information.txt"
				$fileDescription = "Cluster Information"
				$Null = Runcmd -commandToRun $CommandToRun -fileDescription $fileDescription -sectionDescription "Cluster Basic Information" -filesToCollect $FileTocollect -useSystemDiagnosticsObject
			}
		}
	}
}

# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCzWiaYUSGcwPGl
# m2/2EGIjIntHx2rhSqS12UiY/gAYiaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXUwghlxAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIH2yJz1M5vPBbFOfYpO3MoLc
# N0nbvew0KftdBD3DSop+MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQCV8IUV5++6v4cJ4b35kBDnCVT5dvu/5Xj1DeZr/FrMBuxntjUNsdHH
# ASxXurAprPP6adxahwklpcqOLVj8/pNrzoJFlvlVWK4E6sX/ZB1KcjTxdfbiTH0E
# sItfYEeq7rKbNQpZYBe53lgGuHzjEMsjJwU2GtIMyEMNbchdip2Nt9NKoCX5s8V6
# tclwy9zKD43v8VBap76wB+XrgwBeC7Nr4av1HUhBakLGM7Q46rc+lZ7UhleBxN7W
# g0yf0QN4tVU3l3E+YV7Ezk56RIhWFKNiLQrnPQHJ9ROtFcmEvdxkjH79jxYS5EB5
# vogyfzpM9uaStNYRp3SgmaDDMSG8xOU5oYIW/TCCFvkGCisGAQQBgjcDAwExghbp
# MIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEICkiyilJpKMKjO8405kraHq+YFZw6NQbbaSWJklBAnaJAgZj7pq6
# bQMYEzIwMjMwMjIwMTUwNTEyLjI0N1owBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkVBQ0Ut
# RTMxNi1DOTFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVDCCBwwwggT0oAMCAQICEzMAAAHDi2/TSL8OkV0AAQAAAcMwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkw
# MTI5WhcNMjQwMjAyMTkwMTI5WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RUFDRS1FMzE2LUM5MUQxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC767zqzdH+r6KSizzRoPjZibbU0M5m2V01HEwVTGbi
# j2RVaRKHZzyM4LElfBXYoWh0JPGkZCz2PLmdQj4ur9u3Qda1Jg8w8+163jbSDPAz
# USxHbqRunCUEfEVjiGTfLcAf7Vgp/1uG8+zuQ9tdsfuB1pyK14H4XsWg5G317QP9
# 2wF4bzQZkAXbLotYCPoLaYyqVp9eTBt9PJBqe5frli77EynInV8BESm5Hvrqt4+u
# qUTQppp4PSeo6AatORJl4IwM8fo60nTSNczBsgPIfuXh9hF4ixN/M3kZ/dRqKuyN
# 5r4oXLbaVTx6WcheOh7LHelx6wf6rlqtjVzoc995KeR4yiT+DGcHs/UyO3sj0Qj2
# 2FC0y/L/VJSYsbXasFH8N+F4T9Umlyb9Nh6hXXU19BCeX+MFs9tJEGnQcapMhxYO
# ljoyBJ0GhARPUO+kTg9fiyd00ZzXAbKDjmkfrZkx9QX8LMZnuJXrftG2dAVcPNPG
# hIQSR1cx1YMkb6OPGgLXqVGTXEWd+QDi6iZriYqyjuq8Tp3bv4rrLMhJZDtOO61g
# somdLM29+I2K7K//THEIBJIBG85De/1x6C8z+me5T1zqz7iCYrf7mOFy+dYZCokT
# S2lgeaTduaYEvWAeb1OMEnPmb/yu8czdHDc5SFXj/CYAvfYqY9HlRtvjDDkc0aK5
# jQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFBwYvs3Y128BorxNwuvExOxrxoHWMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAN3yplscGp0EVEPEYbAOiWWdHJ3RaZSeOqg/7lAIfi8w8G3i6YdWEm7J5GQM
# QuRNZm5aordTXPYecZq1ucRNwdSXLCUf7cjtHt9TTMpjDY8sD5VrAJyuewgKATfb
# jYSwQL9nRhTvjQ0n/Fu7Osa1MS1QiJC+vYAI8nKGw+i17wi1N/i41bgxujVA/S2N
# wEoKAR7MgLgNhQzQFgJYKZ5mY3ACXF+lOWI4UQoH1RpKodKznVwfwljSCovcvAj0
# th+MQ7vv74dj+cypcIyL2KFQqginZN+N/N2bk2DlX7LDz7BeXb1FxbhDgK8ee018
# rFP2hDcntgFBAQdYk+DxM1H3DgHzYXOasN3ywvoRO8a7HmEVzCYX5DatPkxrx1hR
# J0JKD+KGgRhQYlmdkv2fIOnWyd+VJVfsWkvIAvMMOUcFbUImFhV98lGirPUPiRGi
# ipEE1FowUw+KeDLDBsSCEyF4ko2h1rsAaCr7UcfVp9GUT72phb0Uox7PF5CZ/yBy
# 4C6Gv0gBfJoX0MXQ8nl/i6HM5K8gLUGQm3MXqinjlRhojtX71fx1zBdtkmcggAfV
# yNU7woQKHEoiSmThCDLQ+hyBTBoZaqYtZG7WFDVYladBe+8Fh5gMZZuP8+1KXLC/
# qbya6Mt6l8y8lxTbkpaSVI/YW43Hpo5V96N76mBvAhAhVDWdMIIHcTCCBVmgAwIB
# AgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1
# WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
# 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZn
# hUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t
# 1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxq
# D89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmP
# frVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSW
# rAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
# 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zb
# r17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
# IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQc
# xWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17a
# j54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3h
# LB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
# 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74p
# y27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1A
# oL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbC
# HcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB
# 9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNt
# yo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
# rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcV
# v7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
# 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lw
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAsswggI0AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjpFQUNFLUUzMTYtQzkxRDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA8R0v4+z6HTd75Itd0bO5ju0u7s6g
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOedtnIwIhgPMjAyMzAyMjAxNzA1NTRaGA8yMDIzMDIyMTE3MDU1NFow
# dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5522cgIBADAHAgEAAgIhPDAHAgEAAgIR
# 4DAKAgUA558H8gIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAC/kPPE9WTq9
# SK8LAtZZJiqVnjebLC5cp8ZESSBQlPiR81KB8IK/ggGC2B6W38Eh9BqpfbZxAZ1Q
# LM3AjknTnvCHaa/o/GFcDbYScY61ITvakVgRfeGJIkvC/KzUHS1yvDPhUgz1i1m+
# 7ZZW4tQBVeqGxTH7zunAVKdqDeoHjVXaMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHDi2/TSL8OkV0AAQAAAcMwDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgdbMLDb2Lrp2Grgltgs7//K8p2foVbZc4jkh78ZkdHjIwgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCDS+1Obb5JJ6uHUqICTCslMAvFN8mi2U9wN
# nZlKfvwqSTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABw4tv00i/DpFdAAEAAAHDMCIEIPRfm1EIfg346xkqejfCfzdVfWRi/PnrXyix
# 1RsRVP61MA0GCSqGSIb3DQEBCwUABIICALgP7xbSk9P27wGwDCFDfWuFqZY071Ft
# wGlc4+1/lHm2HnzZ+j01txG6vawD+gfGPTCqM+u6Uyxxdx5d8KSnKPxjYW4A6UY2
# vTqgIAaTzsGiIwpQZVe1tnYDCLMxqcn8eeYWA8ssSQUT6HCIQHCqbpmpeVrwoq9P
# d3cJOrKFp0sZN2sDjGMnfQi0sHIqduQeO5wBNLF2PbAZVLDxPPbVm5+SisLm1Xq2
# kMQaNsBWhaSEEVuY8KbXkQM/NjpfBd/B+m0cMyFg/L7BemwCNzDhCWvdwjxNpuYq
# 7nTtSA+FPbXvxgPizoPjrTHZA0A1Qumca1Ym5JC1TuLSz3LwY1WQX0YbjvL9tCBl
# 1pEiUOln3kjjLY62WP0gefgjOUJjwwED317OlWaNxrxsuvCTghESGqTLuosjO3pk
# OdJRiQHx6eRr9IlOQ1JOY0Mhm2YA3W8ioHwokTJHXctMKw/+zXfkO6/OUzph0CT5
# +uUr1mJhkz97fFLh9NtiSf/wFCWGZySQmeLEIiLImfCXQqgDEfP+eqTpmy99rMme
# oooEBXRkZWWu+1qbMnBtiq61k+rHGeH/CujlDFTB+l6wut5BPrGqGY+76eGMAaRu
# 6jEwprb0fXlHe/AeQ8KjzHJPNZBkKYbPafcTtInJzfuJ8fA2FIyDSKt+AZC1jujk
# GZzhvicbkQFS
# SIG # End signature block
