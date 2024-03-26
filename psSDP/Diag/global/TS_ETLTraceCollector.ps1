#************************************************
# TS_ETLTraceCollector.ps1
# Version 1.2.2
# Date: 10-31-2010
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script is a universal ETL Trace collector. Caller has to inform a Data Collector Set XML for the ETL and additional data. 
#              Script will collect ETL information after asking customer to reproduce the issue.
#************************************************
# invoked in DC_DirectAccessDiag.ps1
# Last Modified: 2023-02-23 by #we# - added trap in functions

PARAM(	[string] $DataCollectorSetXMLName = "", 
		$OutputFileName,
		[string] $ComponentName = "Component",
		$FileDescription = "ETL trace file", 
		$SectionDescription = "ETL Traces", 
		[string] $ReproTitle = "",
		[string] $ReproDescription = "",
		[string] $StopTitle = "",
		[string] $StopDescription = "",
		[switch] $DoNotPromptUser,
		[switch] $StartTrace,
		[switch] $StopTrace,
		$DataCollectorSetObject = $null,
		[switch] $DisableRootCauseDetected,
		[string] $DestinationFolder = ($PWD.Path + "\Perfmon")
		)

Import-LocalizedData -BindingVariable EvtTraceStrings
Write-DiagProgress -Activity ($EvtTraceStrings.ID_ETLTraceEnable -replace "%Component%", $ComponentName) -Status ($EvtTraceStrings.ID_ETLTraceEnableDesc -replace "%Component%", $ComponentName)

if ($ReproTitle -eq ""){
	$ReproTitle = $EvtTraceStrings.ID_ETLTraceReproTitle
}
if ($ReproDescription -eq ""){
	$ReproDescription = $EvtTraceStrings.ID_ETLTraceReproDescription
}
if ($StopTitle -eq ""){
	$StopTitle = $EvtTraceStrings.ID_ETLTraceStopTitle
}
if ($StopDescription -eq ""){
	$StopDescription = $EvtTraceStrings.ID_ETLTraceStopDescription
}


Function StartDataCollectorSetFromXML{
	param( [string] $PathToXML,
		[string] $DestinationFolder)
	if (Test-Path $PathToXML){
		trap [Exception]{
			WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("Starting Data Collector Set $PathToXML")
			if ($null -ne $_.Exception) {"[Exception]: $($_.Exception.Message)"}			
			continue
		}
		$Error.Clear()
		
		"Obtaining DSC XML Content..." | WriteTo-StdOut -ShortFormat
		[xml] $DataCollectorXML = Get-Content $PathToXML
		$DataCollectorXML.DataCollectorSet.RootPath = $DestinationFolder
		"Root Path: $DestinationFolder" | WriteTo-StdOut -ShortFormat
		if ($OutputFileName -is [array]){
			$X = 0
			foreach ($TraceCollectorSet in $DataCollectorXML.DataCollectorSet.TraceDataCollector){
				if ($TraceCollectorSet.FileName -ne "NtKernel"){
					if ($X -lt $OutputFileName.Length){
						$FileName = $OutputFileName[$X]
						$TraceCollectorSet.FileName = $FileName
						$CollectionName = $TraceCollectorSet.Name
						$SectionName = $TraceCollectorSet.Name
						"Setting Output to TraceDataCollector [$CollectionName] to [$FileName]" | WriteTo-StdOut -ShortFormat
					}else{
						"Error: OutputFileName contains less members than TraceCollectorSet sections." | WriteTo-StdOut -ShortFormat
					}
					$X++
				}
			}
		}else{
			foreach ($TraceCollectorSet in $DataCollectorXML.DataCollectorSet.TraceDataCollector){
				if ($TraceCollectorSet.FileName -ne "NtKernel"){
					$TraceCollectorSet.FileName = $OutputFileName
					"Setting Output to [$OutputFileName]" | WriteTo-StdOut -ShortFormat
				}
			}
		}
		$Name = $DataCollectorXML.DataCollectorSet.Name
		"DSC Name: $Name" | WriteTo-StdOut -ShortFormat
		"Creating PLA Object and Setting Up DataCollector" | WriteTo-StdOut -ShortFormat
		
		$DataCollectorSet = New-Object -ComObject PLA.DatacollectorSet
		$DataCollectorSet.SetXml($DataCollectorXML.get_InnerXml()) | WriteTo-StdOut -ShortFormat
		$DataCollectorSet.Commit($Name, $null , 0x0003) | WriteTo-StdOut -ShortFormat
		$DataCollectorSet.Query($Name,$null) | WriteTo-StdOut -ShortFormat

		"Starting DCS" | WriteTo-StdOut -ShortFormat
		$DataCollectorSet.start($false) | WriteTo-StdOut -ShortFormat
		
		If (($null -ne $DataCollectorSet) -and ($null -ne $DataCollectorSet.status)){
			if ($DataCollectorSet.Status -eq 0){
				"DCS was not started. Trying again in 5 seconds"  | WriteTo-StdOut -ShortFormat
				#Timming issue. Wait 5 seconds and try again
				Start-Sleep -Seconds 5
				if ($DataCollectorSet.Status -eq 0){
					$DataCollectorSet.start($false)
				}
				if ($DataCollectorSet.Status -ne 1){
					"DCS Current Status is " + $DataCollectorSet.Status | WriteTo-StdOut -ShortFormat
				}else{
					"DCS is now started"  | WriteTo-StdOut -ShortFormat
				}
			}
			return $DataCollectorSet
		}else{
			"An error has ocurred to create the following Data Collector Set:"  | WriteTo-StdOut -ShortFormat
			"Name: $Name"  | WriteTo-StdOut -ShortFormat
			"XML: $PathToXML"  | WriteTo-StdOut -ShortFormat
		}
	}else{
		$PathToXML + " does not exist. Exiting..." | WriteTo-StdOut -ShortFormat
	}
}

Function StopDataCollectorSet ($DataCollectorSet){
	trap [Exception]{
		WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("Stopping DataCollectorSet")
		continue
	}

	"Stopping Data Collector Set. Current Status is: " + $DataCollectorSet.Status | writeto-stdout -ShortFormat
	if ($null -ne $DataCollectorSet.Status){
		trap [Exception]{
			WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("Stopping DataCollectorSet")
			continue
		}
		$retries = 0
		do{
			trap [Exception]{
				continue
			}
			$retries++
			Start-Sleep -Milliseconds 500
			if ($DataCollectorSet.Status -ne 0){
				$DataCollectorSet.Stop($false)
			}
		} while (($DataCollectorSet.Status -ne 0) -and ($retries -lt 900)) #Wait for up to 7.5 minutes for the report to finish
		if ($retries -lt 900){
			"Data Collector Set was stopped. Current Status is: " + $DataCollectorSet.Status | writeto-stdout -ShortFormat
		}else{
			"Current Status of Data Collector Set is: " + $DataCollectorSet.Status | writeto-stdout -ShortFormat
		}
		$OutputLocation = $DataCollectorSet.OutputLocation
		"Deleting DataCollectorSet..." | writeto-stdout -ShortFormat
		$DataCollectorSet.Delete()
		return $OutputLocation
	}
}

Function CleanDataCollectorSetTrace{	
	"Diagnostic package ends unexpectedly. Stopping DataCollectorSet [ToBeDetermined]" | WriteTo-StdOut -ShortFormat
	trap [Exception]{		
		continue
	}
	$DataCollectorSet = New-Object -ComObject PLA.DatacollectorSet	
	$DCSName = "ToBeDetermined"
	$DataCollectorSet.Query($DCSName,$null) | WriteTo-StdOut -ShortFormat
	"Current Status is: " + $DataCollectorSet.Status | writeto-stdout -ShortFormat
	if ($null -ne $DataCollectorSet.Status){
		trap [Exception]{			
			continue
		}
		$retries = 0
		do{
			trap [Exception]{
				continue
			}
			$retries++
			Start-Sleep -Milliseconds 500
			if ($DataCollectorSet.Status -ne 0){
				$DataCollectorSet.Stop($false)
			}
		} while (($DataCollectorSet.Status -ne 0) -and ($retries -lt 900)) #Wait for up to 7.5 minutes for the report to finish		
		if ($retries -lt 900){
			"Data Collector Set was stopped. Current Status is: " + $DataCollectorSet.Status | writeto-stdout -ShortFormat
		}else{
			"Current Status of Data Collector Set is: " + $DataCollectorSet.Status | writeto-stdout -ShortFormat
		}
		$OutputLocation = $DataCollectorSet.OutputLocation
		if(Test-Path -Path $OutputLocation){
			"Delete DataCollectorSet output folder [$OutputLocation]" | writeto-stdout -ShortFormat
			Remove-Item -Path $OutputLocation -Recurse -Force -Confirm:$false 
		}
		"Deleting DataCollectorSet..." | writeto-stdout -ShortFormat
		$DataCollectorSet.Delete()
	}
}

## Main ##
if ($DataCollectorSetXMLName.Length -gt 0){
	if (Test-Path -Path $DataCollectorSetXMLName){
		$DataCollectorSetXMLName = [System.IO.Path]::GetFullPath($DataCollectorSetXMLName)
	}	
	if ((Test-Path ($DestinationFolder)) -ne $true){ 
		$null = mkdir $DestinationFolder 
	} 
	if (-not ($DoNotPromptUser.IsPresent)){
		$Results = Get-DiagInput -Id "ETLTraceCollectorStopper" -Parameter @{"Title"=$ReproTitle; "Description"=$ReproDescription}
	}
	if (-not ($StopTrace.IsPresent)){
		$TraceTimeStarted = Get-Date
		$DataCollectorSet = StartDataCollectorSetFromXML -DestinationFolder $DestinationFolder -PathToXML $DataCollectorSetXMLName
		if (($null -ne $DataCollectorSet) -and (-not ($DataCollectorSet -is [System.__ComObject]))){
			#Probably an array
			$ArrayDCS = $DataCollectorSet
			foreach ($Member in $ArrayDCS){
				if ($Member -is [System.__ComObject]){
					$DataCollectorSet = $Member
				}
			}
		}	
	}
}
if ($null -ne $DataCollectorSetObject){
	$DataCollectorSet = $DataCollectorSetObject 
}

if ($DataCollectorSet -is [System.__ComObject]){	
	$DataCollectorSetName = $DataCollectorSet.Name
	if ((-not ($StopTrace.IsPresent)) -and ($null -ne $DataCollectorSet)){
		"Starting Monitoring Session for DCS $DataCollectorSetName" | WriteTo-StdOut -ShortFormat
		.\TS_MonitorDiagExecution.ps1 -SessionName "PLACollector_$($DataCollectorSetName)" -ScriptBlockToExecute (($Function:CleanDataCollectorSetTrace) -Replace ("ToBeDetermined", $DataCollectorSetName)) 
	}
	elseif ($null -ne $DataCollectorSet){
		"[Warning] DataCollectorSet [$DataCollectorSetName] is null" | WriteTo-StdOut -ShortFormat
	}
	if (-not ($DoNotPromptUser.IsPresent)){
		$Results = Get-DiagInput -Id "ETLTraceCollectorStopper" -Parameter @{"Title"=$StopTitle; "Description"=$StopDescription}
		$TraceTimeDisplay = (GetAgeDescription(New-TimeSpan $TraceTimeStarted))
	}
	
	Write-DiagProgress -Activity ($EvtTraceStrings.ID_ETLTraceStopping -replace "%Component%", $ComponentName) -Status ($EvtTraceStrings.ID_ETLTraceStoppingDesc -replace "%Component%", $ComponentName)

	if (($StopTrace.IsPresent) -or (($StopTrace.IsPresent -eq $false) -and ($StartTrace.IsPresent -eq $false))){
		$OutputFolder = StopDataCollectorSet $DataCollectorSet
		#end the TS_MonitorDiagExecution
		.\TS_MonitorDiagExecution.ps1 -EndMonitoring -SessionName "PLACollector_$($DataCollectorSetName)"
		Write-DiagProgress -Activity ($EvtTraceStrings.ID_ETLTraceCollecting -replace "%Component%", $ComponentName) -Status ($EvtTraceStrings.ID_ETLTraceCollectingDesc -replace "%Component%", $ComponentName)

		if ($OutputFileName -is [array]){
			$X = 0
			ForEach ($OutputFile in $OutputFileName){
				if ($FileDescription -is [Array]){
					$FDescription = $FileDescription[$x]
				}else{
					$FDescription = $FileDescription
				}
				if ($sectionDescription -is [Array]){
					$SDescription = $sectionDescription[$x]
				}else{
					$SDescription = $sectionDescription
				}
				CollectFiles -filesToCollect ([System.IO.Path]::Combine($OutputFolder, $OutputFile)) -fileDescription $FDescription -sectionDescription $SDescription
				$X++
			}
		}else{
			CollectFiles -filesToCollect ([System.IO.Path]::Combine($OutputFolder, $OutputFileName)) -fileDescription $FileDescription -sectionDescription $sectionDescription
		}
		if (-not ($DisableRootCauseDetected.IsPresent)){
			if (Test-Path -Path ([System.IO.Path]::Combine($OutputFolder, $OutputFileName))){
				$XMLFileName = "..\ETLCollected.XML"
				$MSG_Summary = new-object PSObject
				add-member -inputobject $MSG_Summary -membertype noteproperty -name "More Information" -value ("A $TraceTimeDisplay $ComponentName ETL trace was collected for and saved to <a href= `"`#" + $OutputFileName + "`">$OutputFileName</a>.")
				($MSG_Summary | ConvertTo-Xml2).Save($XMLFileName)
				Update-DiagRootCause -Id RC_ETLCollected -Detected $true -Parameter @{"XMLFileName"=$XMLFileName; "Verbosity"="Informational"; "SectionTitle"="Additional Information"; "Component"=$ComponentName}
			}
		}
	}
}else{
	"An error has occurred when setting Data Collector Set. Aborting" | WriteTo-StdOut -ShortFormat
	if ($null -ne $DataCollectorSet){
		"DataCollectorSet Type Information: " | WriteTo-StdOut -ShortFormat
		$DataCollectorSet | Get-Member | Out-String | WriteTo-StdOut -ShortFormat
		"DataCollectorSet: " | WriteTo-StdOut -ShortFormat
		$DataCollectorSet | WriteTo-StdOut -ShortFormat
	}else{
		"DataCollectorSet is Null" | WriteTo-StdOut -ShortFormat
	}
}

if ($null -ne $DataCollectorSet.Status){
	return $DataCollectorSet
}


# SIG # Begin signature block
# MIInwwYJKoZIhvcNAQcCoIIntDCCJ7ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB5/MSEqRhM/998
# vuki6uZlf1a/4CjlQ29+LoZYZ1kseaCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGaMwghmfAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFFwbGqBBLIpaNuz0A8iJcBk
# FHo78TWRzZRsge00CteKMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBgTDQ0XPu0YUst+6JjbyGlH4ZgslaNF2picMs8bD71FJ3K9bHiA0S1
# vCjGKvREi3MEkTA5Ir3AaoKZ4Cv0A4uQpsmRy6MPd1vDMxkim9y6E8fy2a/HQtK7
# dm85RgoXgYb49lheKoDXuUz6glIHfaLI9Rpk348+8//tp6UXEuaqfzpTNTTEnJnL
# KWcUWP1Bx1KXgRCQYU0W065SlTGSRcLDU5nKhD3X2kYQK2YAuabWWDh5ruxJ1h8k
# QwIEPnvWZ30coU0xCMWRsar0dxw7Ku4JOX6VhtZsyQEgnlZLC34etU9oVUROfkNd
# vGuNLasdSdAOe3xhJR5eRgwAiC5zNyaLoYIXKzCCFycGCisGAQQBgjcDAwExghcX
# MIIXEwYJKoZIhvcNAQcCoIIXBDCCFwACAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEILkWXqsjHONvQMP/aAqGVo1+hTGPgNyqq7/c3XWhXQkkAgZj91j0
# HY8YEzIwMjMwMjI0MTIxMDA3LjkyMlowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046OEQ0MS00QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF6MIIHJzCCBQ+gAwIBAgITMwAAAbP+Jc4pGxuKHAABAAABszAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MjA5MjAyMDIyMDNaFw0yMzEyMTQyMDIyMDNaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhENDEt
# NEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHwPuuYYgK4ssGCCsr2N
# 7eElKlz0JPButr/gpvZ67kNlHqgKAW0JuKAy4xxjfVCUev/eS5aEcnTmfj63fvs8
# eid0MNvP91T6r819dIqvWnBTY4vKVjSzDnfVVnWxYB3IPYRAITNN0sPgolsLrCYA
# KieIkECq+EPJfEnQ26+WTvit1US+uJuwNnHMKVYRri/rYQ2P8fKIJRfcxkadj8CE
# PJrN+lyENag/pwmA0JJeYdX1ewmBcniX4BgCBqoC83w34Sk37RMSsKAU5/BlXbVy
# Du+B6c5XjyCYb8Qx/Qu9EB6KvE9S76M0HclIVtbVZTxnnGwsSg2V7fmJx0RP4bfA
# M2ZxJeVBizi33ghZHnjX4+xROSrSSZ0/j/U7gYPnhmwnl5SctprBc7HFPV+BtZv1
# VGDVnhqylam4vmAXAdrxQ0xHGwp9+ivqqtdVVDU50k5LUmV6+GlmWyxIJUOh0xzf
# Qjd9Z7OfLq006h+l9o+u3AnS6RdwsPXJP7z27i5AH+upQronsemQ27R9HkznEa05
# yH2fKdw71qWivEN+IR1vrN6q0J9xujjq77+t+yyVwZK4kXOXAQ2dT69D4knqMlFS
# sH6avnXNZQyJZMsNWaEt3rr/8Nr9gGMDQGLSFxi479Zy19aT/fHzsAtu2ocBuTqL
# VwnxrZyiJ66P70EBJKO5eQECAwEAAaOCAUkwggFFMB0GA1UdDgQWBBTQGl3CUWdS
# DBiLOEgh/14F3J/DjTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAWoa7N86wCbjA
# Al8RGYmBZbS00ss+TpViPnf6EGZQgKyoaCP2hc01q2AKr6Me3TcSJPNWHG14pY4u
# hMzHf1wJxQmAM5Agf4aO7KNhVV04Jr0XHqUjr3T84FkWXPYMO4ulQG6j/+/d7gqe
# zjXaY7cDqYNCSd3F4lKx0FJuQqpxwHtML+a4U6HODf2Z+KMYgJzWRnOIkT/od0oI
# Xyn36+zXIZRHm7OQij7ryr+fmQ23feF1pDbfhUSHTA9IT50KCkpGp/GBiwFP/m1d
# rd7xNfImVWgb2PBcGsqdJBvj6TX2MdUHfBVR+We4A0lEj1rNbCpgUoNtlaR9Dy2k
# 2gV8ooVEdtaiZyh0/VtWfuQpZQJMDxgbZGVMG2+uzcKpjeYANMlSKDhyQ38wboAi
# vxD4AKYoESbg4Wk5xkxfRzFqyil2DEz1pJ0G6xol9nci2Xe8LkLdET3u5RGxUHam
# 8L4KeMW238+RjvWX1RMfNQI774ziFIZLOR+77IGFcwZ4FmoteX1x9+Bg9ydEWNBP
# 3sZv9uDiywsgW40k00Am5v4i/GGiZGu1a4HhI33fmgx+8blwR5nt7JikFngNuS83
# jhm8RHQQdFqQvbFvWuuyPtzwj5q4SpjO1SkOe6roHGkEhQCUXdQMnRIwbnGpb/2E
# sxadokK8h6sRZMWbriO2ECLQEMzCcLAwggdxMIIFWaADAgECAhMzAAAAFcXna54C
# m0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMy
# MjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51
# yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY
# 6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9
# cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN
# 7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDua
# Rr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74
# kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2
# K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5
# TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZk
# i1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9Q
# BXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3Pmri
# Lq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUC
# BBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9y
# eS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUA
# YgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
# 1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIw
# MTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/yp
# b+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulm
# ZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM
# 9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECW
# OKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4
# FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3Uw
# xTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPX
# fx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVX
# VAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGC
# onsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU
# 5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEG
# ahC0HVUzWLOhcGbyoYIC1jCCAj8CAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjhENDEtNEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBxi0Tolt0eEqXCQl4qgJXUkiQOYaCBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA56HXFzAiGA8yMDIzMDIyMzIwMTQxNVoYDzIwMjMwMjI0MjAxNDE1WjB2MDwG
# CisGAQQBhFkKBAExLjAsMAoCBQDnodcXAgEAMAkCAQACAQECAf8wBwIBAAICEVww
# CgIFAOejKJcCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQCsfpLBQz8bcvst
# 7d596PhpU6SyrUqfEoKLO5ejwwJhcKoBxcnz39Mh+K95K+Y8qDZwNItxjJHtHr/s
# 7JHauPqWu9efhOpknA4PsWLMwWguwsZoamPAPPZybjkQd4D/bW01h4dYVkR0Ye5S
# 6Y0fComwvNKtztT577rjFaYv3Cc9lzGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABs/4lzikbG4ocAAEAAAGzMA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIF8XR+aLkP4uojtQVJCByn9doFkbHqeDU5Ax3BTG2cMIMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQghqEz1SoQ0ge2RtMyUGVDNo5P5ZdcyRoeijoZ
# ++pPv0IwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AbP+Jc4pGxuKHAABAAABszAiBCAWr8PWTfcZypPyi/V7eToJal2jgijvomf9+YAW
# f9n4DTANBgkqhkiG9w0BAQsFAASCAgArL6Hm3pvGSYX5ShVXq8ywH8ZVYAq67lKQ
# NG8dKe1ODQ3v4VqapMcXlFFJIQUDmLO4SQpn1SCUfzqNhuYRYndkovWRN94chIyb
# QQ6AWG9q33pR5kYsBILSbgqU9AeM+zD+3g4s5kEJwFiEh0JlATsNGHwtjRpR6ecW
# crPxokQDXVayDAnqMJux3ydx5DCUJ4NfOy2xIIVD2qQlxhp7GJaR1+OOCpJa3nfx
# owBK4bk2S2ZXHEzSQGkV73hwS0S4Ti8c9S9jsvOPU1m180F5pvpSVKghXhvmA2Es
# TJlzK0/3RxtLl5p6fcTztG4Av6Zv5jLHDuFOatddJ1kH04/jL4mUlffQ5+479kiD
# LNR1kH6Xq3JT9s3cjBn90v96PvlLx+soTyU0mIkak+3SU8DIVaijudhWg7LKMUda
# JW8lQyAn5E6LZo5YLPPxxeo8SFQP1fRZNK09rikohW/rVDYu76et/bRxdDngjMk6
# OUPwSj1KykYZ4E24uDkt/roBcT2DXovfdfJpSI5aXAzUKgy3jydPGUSo61e6HEGU
# GxLWNikTVtgY4uP6bTbHpqwsrEPjFL76Z1DfcC3QWDE8AhcqEWNDCSqd87E18Vkl
# ijP1YqKI9IEIoeIkT54Mzj4yjDARm97gnKWOJ2umqjntsgmuZCwcGqM+nNAAp0vv
# G5kovoJGmg==
# SIG # End signature block
