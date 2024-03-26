#************************************************
# TS_ADReplCheck.ps1
# Version 1.0.2
# Date: 03-23-2011
# Author:      Craig Landis - clandis@microsoft.com
# Description: This script detects and report AD Replication problems
#************************************************

Function GetFailedReplicationStatus($LastSyncResultToQuery) 
{
	Get-CimInstance -Class MSAD_ReplNeighbor -namespace root\microsoftactivedirectory | 
		Where-Object {($_.LastSyncResult -ne 0)} | 
		Sort-Object TimeOfLastSyncAttempt
}

#Check if machine is a DC (http://msdn.microsoft.com/en-us/library/aa394239(VS.85).aspx)

Function GetRootCauseInfo([long] $LastSyncResult)
{
	$ReturnObject = New-Object PSObject
	switch ($LastSyncResult)
	{
		8606 
		{
			$RootCauseID = "RC_ADReplLingeringObjects"
			$PublicContentURL = "http://go.microsoft.com/fwlink/?LinkId=211872"
		}
		8614 
		{
			$RootCauseID = "RC_ADReplADQuarantine"
			$PublicContentURL = "http://go.microsoft.com/fwlink/?LinkId=211875"
		}
		5 
		{
			$RootCauseID = "RC_ADReplError5"
			$PublicContentURL = "http://go.microsoft.com/fwlink/?LinkId=229679"
		}
		1753 
		{
			$RootCauseID = "RC_ADReplError1753"
			$PublicContentURL = "http://go.microsoft.com/fwlink/?LinkId=229691"
		}
		1256 
		{
			$RootCauseID = "RC_ADReplError1256"
			$PublicContentURL = "http://support.microsoft.com/kb/2200187"
		}
		1127 
		{
			$RootCauseID = "RC_ADReplError1127"
			$PublicContentURL = "http://support.microsoft.com/kb/2025726"
		}
		2146893022
		{
			$RootCauseID = "RC_ADReplError-2146893022"
			$PublicContentURL = "http://go.microsoft.com/fwlink/?LinkId=229714"
		}
		8524 
		{
			$RootCauseID = "RC_ADReplError8524"
			$PublicContentURL = "http://go.microsoft.com/fwlink/?LinkId=229715"
		}		
		1396 
		{
			$RootCauseID = "RC_ADReplError1396"
			$PublicContentURL = "http://go.microsoft.com/fwlink/?LinkId=229719"
		}
		8453 
		{
			$RootCauseID = "RC_ADReplError8453"
			$PublicContentURL = "http://go.microsoft.com/fwlink/?LinkId=229720"
		}
		1722 
		{
			$RootCauseID = "RC_ADReplError1722"
			$PublicContentURL = "http://go.microsoft.com/fwlink/?LinkId=229721"
		}
		8452 
		{
			$RootCauseID = "RC_ADReplError8452"
			$PublicContentURL = "http://go.microsoft.com/fwlink/?LinkId=229725"
		}
		8451
		{
			$RootCauseID = "RC_ADReplError8451"
			$PublicContentURL = "http://support.microsoft.com/kb/2645996"
		}
		1818
		{
			$RootCauseID = "RC_ADReplError1818"
			$PublicContentURL = "http://support.microsoft.com/kb/2694215"
		}
		{@(8456, 8457) -contains $_}
  		{
   			$RootCauseID = "RC_ADReplError8456or8457"
  			$PublicContentURL = "http://support.microsoft.com/kb/2023007"
 		}
		8589
		{
			$RootCauseID = "RC_ADReplError8589"
			$PublicContentURL = "http://support.microsoft.com/kb/2703028"
		}
		8333
		{
			$RootCauseID = "RC_ADReplError8333"
			$PublicContentURL = "http://support.microsoft.com/kb/2703708"
		}
		8446
		{
			$RootCauseID = "RC_ADReplError8446"
			$PublicContentURL = "http://support.microsoft.com/kb/2693500"
		}
		8240
		{
			$RootCauseID = "RC_ADReplError8240"
			$PublicContentURL = "http://support.microsoft.com/kb/2680976"			
		}
		1783
		{
			$RootCauseID = "RC_ADReplError1783"
			$PublicContentURL = "http://support.microsoft.com/kb/2015644"				
		}
		8477 
		{
			$RootCauseID = "RC_ADReplError8477"
			$PublicContentURL = "http://support.microsoft.com/kb/2758780"
		}
		Default 
		{
			$RootCauseID = "RC_ADGenericReplicationError"
			$PublicContentURL = "http://go.microsoft.com/fwlink/?LinkId=211874"
			$Script:SolutionTitle = $ReplCheckStrings.ID_ADGenericReplicationErrorST
		}
	}
	
	$ReturnObject | Add-Member -MemberType NoteProperty -Name "RootCauseID" -Value $RootCauseID
	$ReturnObject | Add-Member -MemberType NoteProperty -Name "PublicContentURL" -Value $PublicContentURL
	
	return $ReturnObject
}

$IsMachineDC = ((Get-CimInstance -Class Win32_OperatingSystem).ProductType -eq 2)

if ($IsMachineDC)
{
	Import-LocalizedData -BindingVariable ReplCheckStrings

	Write-DiagProgress -Activity $ReplCheckStrings.ID_ADReplCheck -Status $ReplCheckStrings.ID_ADReplCheckDesc
	
	$RootCauseDetected=$false
	$Script:SolutionTitle = $null

	$ReplNeighbor = GetFailedReplicationStatus
		
	If ($null -ne $ReplNeighbor) 
	{
		$RootCauseDetected = $true
		
		foreach ($ReplNeighborSourceDsa in $ReplNeighbor | Group-Object ("SourceDsaCN", "LastSyncResult"))
		{
			$NumOccurrences = 0
			$OtherPartitions=@()
			foreach ($Neighbor in $ReplNeighborSourceDsa.Group)
			{
				if ($NumOccurrences -eq 0)
				{
					$SectionDescription = "SourceDsa: " + $Neighbor.SourceDsaCN + " / LastSyncResult: 0x" + ("{0:X}" -f $Neighbor.LastSyncResult)
					$RootCauseInfo = New-Object PSObject
					$RootCauseInfo = GetRootCauseInfo -LastSyncResult ($Neighbor.LastSyncResult)

					$InformationCollected = @{"SourceDsaCN" = $Neighbor.SourceDsaCN}
					$InformationCollected += @{"SourceDsaDN" = $Neighbor.SourceDsaDN}
					$InformationCollected += @{"SourceDsaSite" = $Neighbor.SourceDsaSite}
					$InformationCollected += @{"NamingContextDN" = $Neighbor.NamingContextDN}
					$InformationCollected += @{"LastSyncResult" = $Neighbor.LastSyncResult}
					$InformationCollected += @{"NumConsecutiveSyncFailures" = $Neighbor.NumConsecutiveSyncFailures}
					$InformationCollected += @{"TimeOfLastSyncAttempt" = [management.managementDateTimeConverter]::ToDateTime($Neighbor.TimeOfLastSyncAttempt).AddMinutes([System.TimeZoneInfo]::Local.BaseUtcOffset.TotalMinutes * -1)}
					$InformationCollected += @{"TimeOfLastSyncSuccess" = [management.managementDateTimeConverter]::ToDateTime($Neighbor.TimeOfLastSyncSuccess).AddMinutes([System.TimeZoneInfo]::Local.BaseUtcOffset.TotalMinutes * -1)}
					$InformationCollected += @{"USNLastObjChangeSynced" = $Neighbor.USNLastObjChangeSynced}
					$InformationCollected += @{"Writeable" = $Neighbor.Writeable}
				} 
				else 
				{
					$OtherPartitions += $Neighbor.NamingContextDN
				}
				$NumOccurrences++
			}
			
			$InformationCollected += @{"Other Naming Context" = [string]::Join("; ", $OtherPartitions)}
		 	Update-DiagRootCause -id ($RootCauseInfo.RootCauseID) -Detected $true
			Write-GenericMessage -RootCauseID ($RootCauseInfo.RootCauseID) -PublicContentURL ($RootCauseInfo.PublicContentURL) -Verbosity "Error" -InformationCollected $InformationCollected -sectionDescription $SectionDescription -SupportTopicsID 7981 -Visibility 4 -Component "ActiveDirectory" -SolutionTitle $Script:SolutionTitle -MessageVersion 3
		}		
	}
	else
	{
		"No replication problems detected" | WriteTo-StdOut -ShortFormat
		Update-DiagRootCause -id "RC_ADGenericReplicationError" -Detected $false

	}
}

Trap{WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;Continue}


# SIG # Begin signature block
# MIInrQYJKoZIhvcNAQcCoIInnjCCJ5oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBliY3zVhcb7wtk
# MkvSk0fdEv2rqIExPgu08BBli2mCJqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGY0wghmJAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIEuw1ZnOXvbYjTj6d/m5uqxz
# oRBmzlSLV6ZumQc9HPXhMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBVfaIfw/giDo3jpfJEHb6ZXR7rIulUUaPsBx6D+IocdgJKUBu+HGQ4
# t8POA2ooEzeImTt6j4NfE7fv09CJ8fnejImWio20tWiCczJfZed1WJJwuxtEPaBO
# HuVAwYQGnbYm8FSx6cyl1sEsMj6R+USua/GwAZ5TcEDjMcxgaMRS01r3emvpZbxa
# gNIWmIc7n4sa+43gAHS6VgOJZC1eqwl2x/OjV2xIQAbqMy2AqAHPmkL0EsOTd0DC
# j3K32G2HV7BPRWhi84vSD+auqqLoIKt5ltq4vddvfiSBTJspI+I0S+Z9c5+qJUZv
# CwDlPlwrPygXRAowvBuX//elUaBmoOcvoYIXFTCCFxEGCisGAQQBgjcDAwExghcB
# MIIW/QYJKoZIhvcNAQcCoIIW7jCCFuoCAQMxDzANBglghkgBZQMEAgEFADCCAVgG
# CyqGSIb3DQEJEAEEoIIBRwSCAUMwggE/AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIMUXajfnc641Ox5IB8HckMcvbWk+LKL3+GVwiRcAma3VAgZi3n81
# BRQYEjIwMjIwODAxMDc1NTUyLjA2WjAEgAIB9KCB2KSB1TCB0jELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IEly
# ZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# TjozQkQ0LTRCODAtNjlDMzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaCCEWUwggcUMIIE/KADAgECAhMzAAABibS/hjCEHEuPAAEAAAGJMA0G
# CSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIx
# MTAyODE5Mjc0MVoXDTIzMDEyNjE5Mjc0MVowgdIxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9w
# ZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JENC00
# QjgwLTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC9BlfFkWZrqmWa47K82lXz
# E407BxiiVkb8GPJlYZKTkk4ZovKsoh3lXFUdYeWyYkThK+fOx2mwqZXHyi04294h
# QW9Jx4RmnxVea7mbV+7wvtz7eXBdyJuNxyq0S+1CyWiRBXHSv4vnhpus0NqvAUbv
# chpGJ0hLWL1z66cnyhjKENEusLKwUBXHJCE81mRYrtnz9Ua6RoosBYdcKH/5HneH
# jaAUv73+YAAvHMJde6h+Lx/9coKbvE3BVzWE40ILPqir3gC5/NU2SQhbhutRCBik
# Jwmb1TRc2ZC+2uilgOf1S1jxhDQ0p6dc+12Asd1Dw2e/eKASsoutYjRrmfmON0p/
# CT7ya9qSp1maU6x545LVeylA0kArW5mWUAhNydBk5w7mh+M5Dfe6NZyQBd3P7/He
# juXgBT9NI4zMZkzCFR21XALd1Jsi2lJUWCeMzYI4Qn3OAJp286KsYMs3jvWNkjaM
# KWSOwlN2A+TfjdNADgkW92z+6dmrS4uv6eJndfjg4HHbH6BWWWfZzhRtlc254DjJ
# LVMkZtskUggsCZNQD0C6Pl4hIZNs2LJbHv0ecI5Nqvf1AQqjObgudOYNfLT8oj8f
# +dhkYq5Md9yQ/bzBBLTqsP58NLnEvBxEwJb3YOQdea1uEbJGKUE4vkvFl6VB/G3n
# jCXhZQLQB0ASiU96Q4PA7wIDAQABo4IBNjCCATIwHQYDVR0OBBYEFJdvH7NHWngg
# gB6C4DqscqSt+XtQMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8G
# A1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBs
# BggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# DQYJKoZIhvcNAQELBQADggIBAI60t2lZQjgrB8sut9oqssH3YOpsCykZYzjVNo7g
# mX6wfE+jnba67cYpAKOaRFat4e2V/LL2Q6TstZrHeTeR7wa19619uHuofQt5XZc5
# aDf0E6cd/qZNxmrsVhJllyHUkNCNz3z452WjD6haKHQNu3gJX97X1lwT7WfXPNaS
# yRQR3R/mM8hSKzfen6+RjyzN24C0Jwhw8VSEjwdvlqU9QA8yMbPApvs0gpud/yPx
# w/XwCzki95yQXSiHVzDrdFj+88rrYsNh2mLtacbY5u+eB9ZUq3CLBMjiMePZw72r
# fscN788+XbXqBKlRmHRqnbiYqYwN9wqnU3iYR2zHPiix46s9h4WwcdYkUnoCK++q
# fvQpN4mmnmv4PFKpt5LLSbEhQ6r+UBpTGA1JBVRfbq3yv59yKSh8q/bdYeu1FXe3
# utVOwH1jOtFqKKSbPrwrkdZ230ypQvE9A+j6mlnQtGqQ5p7jrr5QpFjQnFa12sxz
# m8eUdl+eqNrCP9GwzZLpDp9r1P0KdjU3PsNgEbfJknII8WyuBTTmz2WOp+xKm2kV
# 1SH1Hhx74vvVJYMszbH/UwUsscAxtewSnwqWgQa1oNQufG19La1iF+4oapFegR8M
# 8Aych1O9A+HcYdDhKOSQEBEcvQxjvlqWEZModaMLZotU6jyhsogGTyF+cUNR/8TJ
# XDi5MIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0B
# AQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAG
# A1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAw
# HhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOTh
# pkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xP
# x2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ
# 3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOt
# gFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYt
# cI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXA
# hjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0S
# idb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSC
# D/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEB
# c8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh
# 8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8Fdsa
# N8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkr
# BgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q
# /y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBR
# BgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsG
# AQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
# BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjE
# MFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv
# Y3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEF
# BQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEB
# CwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnX
# wnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOw
# Bb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jf
# ZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ
# 5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+
# ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgs
# sU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6
# OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p
# /cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6
# TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784
# cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtQwggI9
# AgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1p
# dGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozQkQ0LTRCODAtNjlDMzElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIa
# AxUAIaUJreR63J657Ltsk2laQy6IJxCggYMwgYCkfjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOaRjzEwIhgPMjAyMjA4MDEw
# NzMwNTdaGA8yMDIyMDgwMjA3MzA1N1owdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA
# 5pGPMQIBADAHAgEAAgIlGzAHAgEAAgIRczAKAgUA5pLgsQIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBBQUAA4GBACueThL1sR3EJ2/qW8CoMkue6yHFuNJ2IHuxU4IV6CbW
# EjKI6WCeA3hghnLnBhcVOdtRxOF2Kt/9pY70qCrvKbniicJRvxdj1Hq8FsnPiHjl
# P/Awgo1UajakjIEQbJguCaxdJg/mki+DMWFsa99PKdK0C8UH/87Cz9xKiDhXmo4l
# MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGJtL+GMIQcS48AAQAAAYkwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQg7tO72/Y1YB2d1/1QlVXT
# Q1eX05lPfRNAzIhMT2cbpLIwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBm
# d0cx3FBXVWxulYc5MepYTJy9xEmbtxjr2X9SZPyPRTCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABibS/hjCEHEuPAAEAAAGJMCIEICS3
# jkmWtW+jecW0AZBbxAq256f5xxy6ayfO2D9phUoRMA0GCSqGSIb3DQEBCwUABIIC
# AJtiXZa1EI2PunUVCTBLA/2KbSGPJBBwFeNGxZYqiZFjm+VnGld24SbWw/8f1uJN
# mROFCnKkHObbS5NFLyiaqxaT4+yGtVi5J8HSeIJ1KvgsytIB4XEmsxGcE3oI0awZ
# GqaVdiQ+xmRINY2FBct7/6oyLb5/w4O95Og7XRcLqE0Dmo7Fpifu6EANxwZNUw1r
# nDamKl1vnmSDSzIu7XaGaASZFtHYqeVlfh6YdnRtRlQ4Dl4Qm5rFS9et2G/M/RLG
# nZKzyR5pHXn8buYknsMcf8qAariihsXHee/qssws6+wI1JK0kei8zC3Oqz3tTv0R
# hkoeFS9y2QzuJ60A24Bb3jnTKbzs99U5Io+7V0oxT2KDbOf8XVid5LY5ic+72dSS
# ejS/fvfOCx2xYcc47U8EGCL1NqbWuUPoAW6Bzf/aSnFcSnsCQAuQzyBMxUgziHnE
# 1mqfnx6Etvmjw/JTCnqdTf4eb6N0b4YUd32v0Wh9uD3zfbZqO/BuGMadOg1+BPRD
# kSM7lulzCQiX8BR4IWkU8VVikf0jT+/MfgLjiA/FGKJXfbdUIcpPyILWLnjkx5Qw
# 5VZdU2xWDMY4AcWR0NuWdyUmrEGcjZAYEBBziHjv/xZ45tcETZmL5IAWN9/FqbNc
# VCYv9cdpm95Hph5dalwy8mGQHyK+nV27nsfro2fi6//O
# SIG # End signature block
