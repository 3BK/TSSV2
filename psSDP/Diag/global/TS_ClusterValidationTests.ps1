#************************************************
# TS_ClusterValidationTests.ps1
# Version 1.0.1
# Date: 07-24-2009
# Author: Andre Teixeira - andret@microsoft.com
# Hacked by Jacques Boulet - jaboulet@microsoft.com - 2019-02-21
# Description: This script is used to obtain cluster validation report.
#              Before validation, script also confirms it is able to connect to remote systems via SCM
#************************************************
# 2021-05-13 add skipHang

# 2023-02-20 WalterE mod Trap #we#
trap [Exception]{
	WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; continue
	Write-Host "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_"
}

"__ value of Switch skipHang: $Global:skipHang  - 'True' will suppress ClusterValidationTests `n`n"	| WriteTo-StdOut

if ($Global:skipHang -ne $true) {	
if ($OSVersion.Build -ge 7600){
    # Okay, so Validation tests have changed over different versions of Windows. Some test were added and 
    # some got removed via previous versions. So what we are going to do is just seperate this into two 
    # differnt if statements so the correct tests get set. 

    # TODO: Test if the changes I have made will work in Server 2008 through 2012 R2

    # Let's first set an empty array that we will use in our definfing of the tests. 
    $ValidationTests = @()

    # If we are greater than or equal to Server 2008 R2 and LE Server 2012 R2 then we set the test to the old way of doing things. 
    # if (($OSVersion.Build -ge 7600) -and ($OSVersion.Build -le 9600)){
    	    $ValidationTests = "List BIOS Information", 
		    "List Fibre Channel Host Bus Adapters", 
		    "List iSCSI Host Bus Adapters", 
		    "List Memory Information", 
		    "List Operating System Information", 
		    "List Plug and Play Devices", 
		    "List SAS Host Bus Adapters", 
		    "List Services Information", 
		    "List Software Updates", 
		    "List System Drivers", 
		    "List System Information", 
		    "List All Disks", 
		    "Validate Network Communication",
		    "Validate Windows Firewall Configuration",
		    "Validate Cluster Network Configuration",
		    "Validate IP Configuration",
		    "Validate Active Directory Configuration", 
		    "Validate Cluster Service and Driver Settings", 
		    "Validate Service Pack Levels", 
		    "Validate Same Processor Architecture", 
		    "Validate Software Update Levels", 
		    "Validate System Drive Variable", 
		    "Validate Required Services", 
		    "Validate Operating System Installation Option"
	#_#}
	if (($OSVersion.Build -ge 7600) -and ($OSVersion.Build -le 9600)){ $ValidationTests +="List Network Binding Order"}
	if ($OSVersion.Build -gt 9600 ){ $ValidationTests +="List Network Metric Order"} #_# likely not needed
					
    # If we are newer to Server 2012 R2 then we do things the new way. 
    if ($OSVersion.Build -gt 9600 ){
        #
        # Default Tests we will test these no matter the circumstances:
        # System Configuration, Network, Inventory, Cluster Configuration
        # There might be some fails in these because it's a blanket test. We are testing EVERYTHING in these categories 

        # We make our Array of test we will start off with. 
        $ValidationTests = "System Configuration", "Network", "Inventory", "Cluster Configuration"
        #_# $ignore = "Storage" # I don't think I need this. 

        # Now for some simple tests to determine if we are running Hyper-V and or S2D then add those tests to the $validation array
        Try{ $HV = Get-VM }
		Catch [System.Management.Automation.CommandNotFoundException] 
			{ Write-Host " [Info] No Hyper-V Detected" }

        # Test for Hyper-V. So I realize that someone, somewhere out in the world might have Hyper-V and Failover Cluster installed side by side but do not actually have a Hyper-V cluster. We need to detect if that is the case. 
        if ($null -ne $hv){ 
            Write-DiagProgress -activity $ClusterValidationStrings.ID_ClusterValidationDetectHyperV
            # Write-Host "Detected Hyper-V, Checking for clustered VMs"
            # We're going to do a loop and if IsClustered returns true then we will add Hyper-V tests to the list and break the loop. 
            foreach ($cvm in $hv.IsClustered){
                if ($cvm -eq $true){
                    Write-DiagProgress -activity $ClusterValidationStrings.ID_ClusterValidationAddHyperV
                    # Write-Host "Found a clustered VM, adding Hyper-V to the cluster tests"
                    $ValidationTests += "Hyper-V"
                    Break
                }
            }
        }else{
            Write-Verbose "Hyper-V not detected"
        }

        # Now we Test for S2D
		$SSD = Get-StorageEnclosure
        if ($null -ne $SSD){
            Write-DiagProgress -activity $ClusterValidationStrings.ID_ClusterValidationDetectS2D
            #Write-Host "S2D detected, adding the S2D tests to the list"
            $ValidationTests += "Storage Spaces Direct"
        }else{
            # IF Get-VM is null then there are no VMs, Hyper-V could still be instaled though. 
            Write-Verbose "S2D not detected"
        }
    }

    # Back to business as usual before my hack
    # TODO: I don't think pinging a server is the best way to go about determining if the server is alive or not. 
    # Cluster has some required ports that must be open if we are going to work correclty, I think testing a 
    # connection to one or more of those ports is better. 

	Import-LocalizedData -BindingVariable ClusterValidationStrings
	Write-DiagProgress -activity $ClusterValidationStrings.ID_ClusterValidationReport -status $ClusterValidationStrings.ID_ClusterValidationReportObtaining
	$ClusterServiceKey="HKLM:\Cluster"
	if (Test-Path $ClusterServiceKey){
		Import-Module FailoverClusters
		$ClusterNodes = Get-ClusterNode
		$ServersWithValidCommunication = $null
		$OnlineServersWithSCMIssues = ""
		foreach ($ClusterNode in $ClusterNodes){
			#Try to connect to Cluster node using SCM.
			#Validation tests fail if remote server is not accessible via SCM
			$Status = $ClusterValidationStrings.ID_ClusterValidationReportStatus -replace("%Node%", $ClusterNode.Name)
			Write-DiagProgress -activity $ClusterValidationStrings.ID_ClusterValidationReport -status $Status 
			
			##First - Ping remote server to check if it is alive:
			$ping = new-object System.Net.NetworkInformation.Ping
			$pingResults = $ping.Send($ClusterNode.Name)
			if ($pingResults.Status.value__ -eq 0) { #Success
				$Error.Clear()
				$ServerName = ($ClusterNode.Name)
				
				##Try to query serive status of each node
				$CluServiceForNode = Get-Service -ComputerName $ServerName | Where-Object {$_.Name -eq "ClusSvc"}
				if ($null -eq $CluServiceForNode){
					if ($ClusterNode.State.Value__ -ne 1){ #Down
						if ($OnlineServersWithSCMIssues -ne "") {$OnlineServersWithSCMIssues += " and "}
						$OnlineServersWithSCMIssues += $ClusterNode.Name
					}
				}else{
					$ServersWithValidCommunication += [array] $ClusterNode.Name
				}
				if ($Error.Count -ne 0){
					"[TS_ClusterValidationTests.ps1] Error Obtaining status from ClusSvc service: " + $Error[0].Exception.Message | WriteTo-StdOut
				}
			}
		}
		if ($OnlineServersWithSCMIssues -ne ""){
			#Disabling this for now
			#Update-DiagRootCause -id "RC_ClusterSCMError" -Detected $true -Parameter @{"NodeName"=$OnlineServersWithSCMIssues;}
		}
		if ($ServersWithValidCommunication.Count -gt 0){
			Write-DiagProgress -activity $ClusterValidationStrings.ID_ClusterValidationReport -status $ClusterValidationStrings.ID_ClusterValidationReportTestNet
			$OutputfileName = $PWD.Path + "\" + $Computername + "_ValidationReport.mht.htm"
			$Error.Clear()
			$TestMHTFile = Test-Cluster -include $ValidationTests -node $ServersWithValidCommunication
			if ($Error.Count -gt 0){
				$ValidationError_Summary = new-object PSObject
				$ID = 0
				ForEach ($Err in $Error){
					$Name = "Error [" + $ID.ToString() + "]"
					$ID += 1
					$ErrorString = $Err.Exception.Message
					add-member -inputobject $ValidationError_Summary -membertype noteproperty -name $Name -value $ErrorString
				}
				$XMLFileName = "..\ValidationErrors.XML"
				$XMLObj = $ValidationError_Summary | ConvertTo-Xml2 
				
				#Disabling below as root cause for now
				#$XMLObj.Save($XMLFileName)		
				#Update-DiagRootCause -id "RC_ClusterValidationError" -Detected $true -Parameter @{"XMLFileName"=$XMLFileName}			
			}
			
			If ($TestMHTFile){
				If (Test-Path $TestMHTFile.FullName){
				$ValidationXMLFileName = $TestMHTFile.DirectoryName + "\" + $TestMHTFile.BaseName + ".xml"
				$TestMHTFile | Move-Item -Destination $outputfileName
				CollectFiles -filesToCollect $outputfileName -fileDescription "Validation Report" -sectionDescription "Cluster Validation Test Report"
				#Open the XML version to look for Warnings and Errors. If any found, create alerts.
				if (Test-Path $ValidationXMLFileName){
					[xml] $ValidationXMLDoc = Get-Content -Path $ValidationXMLFileName
					if ($null -ne $ValidationXMLDoc){
						$WarningNode = $ValidationXMLDoc.SelectNodes("//Channel/Message[@Level=`'Warn`']").Item(0)
						$ErrNode = $ValidationXMLDoc.SelectNodes("//Channel/Message[@Level=`'Fail`']").Item(0)
						if (($null -ne $WarningNode) -or ($null -ne $ErrNode)){
							Update-DiagRootCause -id "RC_ClusterValidationTests" -Detected $true -Parameter @{"XMLFileName"=$ValidationXMLFileName}
						}
					}
				}
			}else{
				    "[TS_ClusterValidationTests.ps1] Error: " + $TestMHTFile.FullName + " does not exist." | WriteTo-StdOut
			    }
            }
		}
	}else{
		"[TS_ClusterValidationTests.ps1] Info: Machine $Computername is not a cluster" | WriteTo-StdOut
	}
}else{
	"[TS_ClusterValidationTests.ps1] OS Build " + $OSVersion.Build + " does not support validation tests" | WriteTo-StdOut
	}
} #end of SkipHang

# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCoqG96/kTM7xfA
# xVv7QGoPkOLeJ/RDMr+MKrGgfzXTV6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIE96C+TZrCR1HaswbKTERoAY
# 73dWR+IfIgkPTLFpsVuBMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQA1etHy5KAkPrbNWUrzbJh7NUVjymru0UqV8u/vPoRW2GHzvkKqGoO6
# qon2oK1kY4W6pDTmvcwPeSDtEVbbbDwI0KEeq5ExMf+TxUS+UHgs82Az3Tkbyc+U
# hKN64ZnfcRGiQ/NMOsdc4k268wlMSwsndYp5tjjrPEKbxNNY9xKfGly8M3BB249v
# cWP7DnyFrhoR4ItqsDwcde8fqnqR/gr5zuX5TiAreuwRwwgmFRi/eqs++uNLFxrD
# PPrRE6ZDx96MZPeOfbA0A8sze2WrDBZ4VS2InK7O170KA9MxqAAXwqIqy8nNIfiM
# zRe4c2ZUEvBbKUH/ygwvgBwpZBnrbQGroYIW/TCCFvkGCisGAQQBgjcDAwExghbp
# MIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIFLcMf5e6pZFUDGkuUkMRCWNJ1UxpS4VUVMQCk925EGSAgZj7k8Y
# ZlMYEzIwMjMwMjIwMTUwNTIwLjE3N1owBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjEyQkMt
# RTNBRS03NEVCMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVDCCBwwwggT0oAMCAQICEzMAAAHKT8Kz7QMNGGwAAQAAAcowDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIxMTA0MTkw
# MTQwWhcNMjQwMjAyMTkwMTQwWjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MTJCQy1FM0FFLTc0RUIxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDDAZyr2PnStYSRwtKUZkvB5RV/FdFpSOI+zJo1XE90
# xGzcJV7nyyK78SRpW3u3s81M+Sj+zyU226wB4sSfOSLjjLGTZz16SbwTVJDZhX1v
# z8s7F8pqlny1WU/LHDoOYXM0VCOJ9WbwSJnuUVGhjjjy+lxsEPXyqNg0X/ZndJBy
# Fyx1XU31jpXZYaXnlWYuoVFfn52m12Ot4FfOLdZb1OygIRZxgIErnBiBL21PZJJJ
# PNp7eOZ3DjSD4s4jKtU8XYOjORK2/okEM+/BqFdakoak7usesoX6jsQI39WJAUxn
# Kn+/F4+JQAEM2rMRQjyzuSViZ4de+N5A6r8IzcL9jxuPd8k5udkft4Be9EOfFPxH
# pb+4PWYZQm+/0z0Ey7eeEqkqZLHPM7ku1wwSHa0xfGEwYY0xQ/cM4Qrdf7b8sPVn
# Te6wlOTmkc2gf+AMi9unvzsLDjS2wCmIC+2sdjC5vROoi/xnLraXyfyz8y/8/vrg
# JOqvFxfNqUEeH5fLhc+OZp2c+RknJyncpzNuSD1Bu8mnQf/QWzAdL558Wh+kM0nA
# uHWGz9oyLUr+jMS/v9Ysg+wOArXp9T9rHJuowqTQ07GB6VSMBgqXjBTRjpDir03/
# 0/ABLRyyJ9CFjWihB8AjSIMIJIQBOyUPxtM7S1G2p1wh1q85F6rOg928C/cOvVdd
# DwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFPrH/qVLgRJDwpmF3RGBTtFhczx/MB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBANjQeSoJLcq4p58Vfz+ub920P3Trp0oSV42quLBmqwzhibwTDhCKo6o7uZah
# hhjgrnLx5dI4co1c5+k7pFtpiPyMI5wkAHm2ouXmGIyBoxsBUuuXWGWLH2yWg7jk
# s43QmmEq9rcPoBUoDs/vyYD2JEdlhRWtGLJ+9CNbGZSfGGKzx+ib3b79EdwRnUOH
# n6niDN54vzhiXTRbKr0RyAEop+CrSUKNY1KrUBQbWwQuWBc5K8pnj+Vdcf4x+Fwd
# 73VYshpmRL8e73B1NPojXgEL3vKEOxlZcCXQgnzTUjpS0QWkKxN47JkEnsIXSt/m
# XEny0T2iM2zKpckq7BWfR7AIyRmrP9wTC/0UTHxCaxnRk2h1O2yX5X11mb55Sswp
# mTo8qwoCu1D6MeR9WweAo4OWh6Wk6YeqBftRs7Q1WciWk/nmBBOpXvq9TvBFelR/
# PsqETcFlc2DAbTl1GcJcPCuGFjP4i1vOzUrVHwjhgwMmNb3QBIKD0l/7HKBEpkYo
# eOjYGzZfJoq43U/oUUIhVc3sqAeX9tmJqQaruTlNDg5crnGSEIeGN2Ae7GPeErkB
# o7L4ZfE7+NvKoZGp5LF/5NM+5aENa6sijfdEwMZ7kNsiaNxtyPp1WFB6+ocKVHU4
# dJ+v7ybWFZEkaULVq1w5YpqMCvA5RGolJWVOHBWAjLMY2aPOMIIHcTCCBVmgAwIB
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
# IEVTTjoxMkJDLUUzQUUtNzRFQjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAo47nlwxPizI8/qcKWDYhZ9qMyqSg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOedasswIhgPMjAyMzAyMjAxMTQzMDdaGA8yMDIzMDIyMTExNDMwN1ow
# dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA551qywIBADAHAgEAAgInljAHAgEAAgIR
# qzAKAgUA5568SwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBABE4uFgk5z5U
# LwrTCr76tHEElOEfvGK1hpvlKszbVa/CVUg2oRekUzHUkl05+rJMciNotjSO2Q8P
# fTSrBvCfxyKzYMl1cSoPKFKVfwWIbt2WR/qwXqkJ5iAXRXI1Xj0hklT1HEO0T1Dw
# hOXwpfwIIsAQEqrkdMDaOFV8pVbNMUY9MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHKT8Kz7QMNGGwAAQAAAcowDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgqc8scdohXnfUstw7XNcLwCbDj6cqxfZZ3Py3USljGx0wgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCATPRvzm+tVTayVkCTiO3VIMSTojNkDBUKh
# bAXcrNwa4DCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAAByk/Cs+0DDRhsAAEAAAHKMCIEIIZKNW8rK20jbK1NDV2CWMYd9WW+bBVIuhEQ
# rseCWyC6MA0GCSqGSIb3DQEBCwUABIICAKIWo6JAhehJaRJnyzxBKZWueCFybpgt
# Dz0q1AiZXBazLJLIzVCA343VWm9TDu54nJsIwT0+2YcQcm4lBvgWGe8TiR8pjTJ6
# zObfzjeiBpSw523Dd+y/lR3T/YzFARp+n7BOxqJpGK3s4GjCEp2Im63OoRHvs74x
# A9ErdaaX+q8ucBEd9mezvcVWCDGl0ig0Kv6L+Fh3GCzIjXZ6+he8yYQl072D28Od
# fgBYkw6oSaLd+VBxlTysYtCVNHj0jFNFPjGNkFFOYFOB0AN24On0zsA9sZidmKQY
# VKXcmjB0+GOnNan1SLBbUASNaY2OrrXECcID01rzjbgSprjD+FCfcmIWE7a7BBHk
# YpMKFnjHCyUSL9/GFvcvH9Z9WtHPWAMbBvOv1pOFPlFql11Fn3TsuvyR28VrNIZ6
# cC9B4YbMkiayE2nRyAcCzz0MubKePMIlNwuGg5qdnCrWQrdxAxVxWlRpj9YQrNEj
# z2t1aUaJLKenPttygKGoE/4YRzq2j0vtErOu0O7Sq4M4raWy4/6IYKTn1prO00dD
# oi77oBq+yxtEPkNzmFLq80j4a5m2OCzEPBFLMRwZPYiFsxBFu5lX7vhRHF62nPer
# OSpveqZVf5DT+eWbps8cnwQJ5hYk0uvYof962p3b/5LDfJgsUgxwpRDIE5keGTln
# 4LA8OuwnUCZI
# SIG # End signature block
