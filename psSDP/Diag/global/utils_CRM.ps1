
$ComputerName = $Env:computername
$OSMajorVersion = [Environment]::OSVersion.Version
$shell = New-Object -comobject WScript.Shell
$Global:TraceRefreshClient = $null
$Global:TraceRefreshServer = $null

Import-LocalizedData -BindingVariable LocalizedMessages1 

#region IIS Functions
function GetIISVersion(){   
    if (Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters){
	  $parameters = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters
      $majorVersion = $parameters.MajorVersion
	  return $majorVersion;
	}else{
	   return $null
	}
}
#endregion IIS Functions
#region CRM Platforms Trace
function Enable-CRMDevErrors{
	$installDir =(Get-ItemProperty hklm:\software\microsoft\mscrm).CRM_Server_InstallDir
	$xml = [xml](Get-Content "$($installDir)\CRMWeb\web.config")
	$node = $xml.SelectSingleNode("/configuration/appSettings/add[@key='DevErrors']")
	$node.Value="On"
	#Save the record
	$xml.Save("$($installDir)\CRMWeb\web.config")
}
function Disable-CRMDevErrors{
	$installDir =(Get-ItemProperty hklm:\software\microsoft\mscrm).CRM_Server_InstallDir
	$xml = [xml](Get-Content "$($installDir)\CRMWeb\web.config")
	$node = $xml.SelectSingleNode("/configuration/appSettings/add[@key='DevErrors']")
	$node.Value="Off"
	#Save the record
	$xml.Save("$($installDir)\CRMWeb\web.config")
}
function Enable-CRMPlatformTrace{
	#This function enables CRM platform tracing. The default parameter values where taken from the kb http://support.microsoft.com/kb/907490
	PARAM(
		[int]$TraceEnabled = 1,
		[int]$TraceCallStack = 1,
		[string]$TraceCategories = "*:Verbose",
		[int]$TraceFileSizeLimit = 100
		#[string]$TraceDirectory = ($env:TEMP + "\" + [System.Guid]::NewGuid() + "\CRMClientTrace"),
	)
	trap [Exception]{
	   WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; continue	   
	}	
	Write-DiagProgress -Activity $LocalizedMessages1.ID_CRMPlatfromTraceEnable -Status $LocalizedMessages1.ID_CRMPlatfromTraceEnableDesc
	#The Microsoft CRM client for Outlook tracing registry entries are located in the following registry subkey:
	#HKEY_CURRENT_USER\SOFTWARE\MICROSOFT\MSCRMClient
	if (Test-Path "HKCU:\SOFTWARE\Microsoft\MSCRMClient"){
		$CRMClient = get-Item -path "HKCU:\SOFTWARE\Microsoft\MSCRMClient"
		$Global:TraceRefreshClient = $CRMClient.GetValue("TraceRefresh")
		if($Global:TraceRefreshClient -ne $null){
			$Global:TraceRefreshClient = $Global:TraceRefreshClient + 1
		}
		else{
			$Global:TraceRefreshClient = 1
		}
		set-itemproperty -path "HKCU:\SOFTWARE\Microsoft\MSCRMClient" -type DWORD -name "TraceEnabled" -value $TraceEnabled 
		set-itemproperty -path "HKCU:\SOFTWARE\Microsoft\MSCRMClient" -type DWORD -name "TraceCallStack" -value $TraceCallStack
		set-itemproperty -path "HKCU:\SOFTWARE\Microsoft\MSCRMClient" -type DWORD -name "TraceRefresh" -value $Global:TraceRefreshClient
		set-itemproperty -path "HKCU:\SOFTWARE\Microsoft\MSCRMClient" -name "TraceCategories" -value $TraceCategories
		set-itemproperty -path "HKCU:\SOFTWARE\Microsoft\MSCRMClient" -name "TraceFileSizeLimit" -value $TraceFileSizeLimit
		"Platforms registry keys set at HKEY_CURRENT_USER\SOFTWARE\MICROSOFT\MSCRMClient" | WriteTo-StdOut
		("TraceEnabled")  | WriteTo-StdOut
		("TraceCallStack=" + $TraceCallStack)  | WriteTo-StdOut
		("TraceRefresh=" + $Global:TraceRefreshClient)  | WriteTo-StdOut
		("TraceCategories=" + $TraceCategories)  | WriteTo-StdOut
		("TraceFileSizeLimit=" + $TraceFileSizeLimit)  | WriteTo-StdOut
		"MSCRM Client Platform trace enabled" | WriteTo-StdOut
	}
	else{
		"the reg key HKEY_CURRENT_USER\SOFTWARE\MICROSOFT\MSCRMClient  was not found on this machine make sure this is the CRM client machine" | WriteTo-StdOut
	}
	#The Microsoft CRM server tracing registry entries are located in the following registry subkey:
	#HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\MSCRM
	if (Test-Path "HKLM:\SOFTWARE\Microsoft\MSCRM"){
		$CRMServer = get-Item -path "HKLM:\SOFTWARE\Microsoft\MSCRM"
		$Global:TraceRefreshServer = $CRMClient.GetValue("TraceRefresh")
		if($Global:TraceRefreshServer -ne $null){
			$Global:TraceRefreshServer = $Global:TraceRefreshServer + 1
		}else{
			$Global:TraceRefreshServer = 1
		}
		set-itemproperty -path "HKLM:\SOFTWARE\Microsoft\MSCRM" -type DWORD -name "TraceEnabled" -value $TraceEnabled
		set-itemproperty -path "HKLM:\SOFTWARE\Microsoft\MSCRM" -type DWORD -name "TraceCallStack" -value $TraceCallStack
		set-itemproperty -path "HKLM:\SOFTWARE\Microsoft\MSCRM" -type DWORD -name "TraceRefresh" -value $Global:TraceRefreshServer
		set-itemproperty -path "HKLM:\SOFTWARE\Microsoft\MSCRM" -name "TraceCategories" -value $TraceCategories
		set-itemproperty -path "HKLM:\SOFTWARE\Microsoft\MSCRM" -name "TraceFileSizeLimit" -value $TraceFileSizeLimit
		"Platforms registry keys set at HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\MSCRM" | WriteTo-StdOut
		("TraceEnabled")  | WriteTo-StdOut
		("TraceCallStack=" + $TraceCallStack)  | WriteTo-StdOut
		("TraceRefresh=" + $Global:TraceRefreshServer)  | WriteTo-StdOut
		("TraceCategories=" + $TraceCategories)  | WriteTo-StdOut
		("TraceFileSizeLimit=" + $TraceFileSizeLimit)  | WriteTo-StdOut
		"MSCRM Server Platform trace enabled" | WriteTo-StdOut
		
		#Forcing tracing cache to update
		$installDir =(Get-ItemProperty hklm:\software\microsoft\mscrm).CRM_Server_InstallDir
		$xml = [xml](Get-Content "$($installDir)\CRMWeb\web.config")
		$xml.Save("$($installDir)\CRMWeb\web.config")
	}else{
		"the reg key HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\MSCRM  was not found on this machine make sure this is the CRM server machine" | WriteTo-StdOut
	}
}
function Get-CRMPlatformTrace{
	PARAM(	[string]$Clientpath = ($Env:USERPROFILE + "\Local Settings\Application Data\Microsoft\MSCRM\Traces"),
			[string]$Serverpath = ($Env:ProgramFiles + "\Microsoft Dynamics CRM\Trace")
		 )
	trap [Exception]{
	   WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; 
	}
	"entered Get-CRMPlatformTrace function" | WriteTo-StdOut
	Write-DiagProgress -Activity $LocalizedMessages1.ID_CRMPlatfromCollecting -Status $LocalizedMessages1.ID_CRMPlatfromCollectingDesc
	#get client logs
	if (Test-Path $Clientpath){
		$Platformslogs = Get-ChildItem -Path $Clientpath -Filter *.log | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)} | Sort-Object -property @{Expression="LastWriteTime";Descending=$true} 	
		if ($Platformslogs -ne $null){
			foreach ($file in $Platformslogs){
				CollectFiles -filesToCollect ($Clientpath + "\" + $file) -fileDescription "CRM Client Platform Traces" -sectionDescription "CRM Client Platform Traces" 
				("Collected Files for client File:" + $Clientpath + "\" + $file) | WriteTo-StdOut
			}
		}
	}
	#get server logs
	"The server path is being set to $($Serverpath)" | WriteTo-StdOut
	if (Test-Path $Serverpath){
		$file_count = (dir $serverpath).count
		"There are $($file_count) files located in the $($Serverpath) folder" | WriteTo-StdOut
		$ServerPlatformslogs = Get-ChildItem -Path $Serverpath -Filter *.log | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)} | Sort-Object -property @{Expression="LastWriteTime";Descending=$true} 
		if ($ServerPlatformslogs -ne $null){
			foreach($file in $ServerPlatformslogs){
				CollectFiles -filesToCollect ($Serverpath + "\" + $file) -fileDescription "CRM Server Platform Traces" -sectionDescription "CRM Server Platform Traces" 
				("Collected Files for Server File:" + $Serverpath + "\" + $file) | WriteTo-StdOut
			}
		}
	}
	"exited Get-CRMPlatformTrace function" | WriteTo-StdOut
}
function Set-CRMPlatformTraceOff{
	PARAM(	)
	Write-DiagProgress -Activity $LocalizedMessages1.ID_CRMPlatfromTraceOff -Status $LocalizedMessages1.ID_CRMPlatfromTraceOffDesc
	#turn off client trace
	if (Test-Path "HKCU:\SOFTWARE\Microsoft\MSCRMClient"){
		set-itemproperty -path "HKCU:\SOFTWARE\Microsoft\MSCRMClient" -type DWORD -name "TraceEnabled" -value 0
		set-itemproperty -path "HKCU:\SOFTWARE\Microsoft\MSCRMClient" -type DWORD -name "TraceRefresh" -value ($Global:TraceRefreshClient -1)
		"Turned off trace for Client" | WriteTo-StdOut
	}
	#turn off server trace
	if (Test-Path "HKLM:\SOFTWARE\Microsoft\MSCRM"){
		set-itemproperty -path "HKLM:\SOFTWARE\Microsoft\MSCRM" -type DWORD -name "TraceEnabled" -value 0
		set-itemproperty -path "HKLM:\SOFTWARE\Microsoft\MSCRM" -type DWORD -name "TraceRefresh" -value ($Global:TraceRefreshServer -1)
		"Turned off trace for Server" | WriteTo-StdOut
		#Forcing tracing cache to update
		$installDir =(Get-ItemProperty hklm:\software\microsoft\mscrm).CRM_Server_InstallDir
		$xml = [xml](Get-Content "$($installDir)\CRMWeb\web.config")
		$xml.Save("$($installDir)\CRMWeb\web.config")
	}
}
#endregion CRM Platforms Trace
#region Internet Functions
function Get-InternetTime(){
	Param( [string]$ComputerName = "time.nist.gov", [int]$Port = 13, [switch]$Adjust, [switch]$Difference, [Switch]$Verbose)
	if($Verbose){$VerbosePreference = "Continue"}
	$TcpClient = New-Object System.Net.Sockets.TcpClient
	[byte[]]$buffer = ,0 * 64  
	$TcpClient.Connect($ComputerName,$Port)
	$TcpStream = $TcpClient.GetStream()
	#The received time is adjusted to the server's guess
	# at client arrival time, so we get the time NOW for ref.
	$LocalTime = Get-Date
	$length = $TcpStream.Read($buffer, 0, $buffer.Length);
	[void]$TcpClient.Close()
	;#53994 06-09-16 14:51:53 50 0 0 334.4 UTC(NIST) *
	$response = [Text.Encoding]::ASCII.GetString($buffer)
	[DateTime]::ParseExact($response.SubString(7,17), 'yy-MM-dd HH:mm:ss', $null).toLocalTime()
}
#endregion
#region CRM Server Functions
function Test-CRMServerKey(){
	Get-ItemProperty 'HKLM:\Software\Microsoft\MSCRM' -ErrorAction SilentlyContinue | Out-Null
	$?
}
function Get-CRMServerVersion(){
	trap [Exception]{
	   WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
	   return 0
	}
	$crmVersion =(Get-ItemProperty hklm:\software\microsoft\mscrm).CRM_Server_Serviceability_Version
	if ($crmVersion -ne $null){
		return [int]$crmVersion.Substring(0,1)
	}else{
		return 0
	}
}
#endregion CRM Server Functions
#region CRM Crash Dump Functions
function Enable-GCBreakOnOOM{
    trap [Exception]{
	   WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
	   return ""
	}
	if (Test-Path "HKLM:\SOFTWARE\Microsoft\.NETFramework"){
		set-itemproperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework" -type DWORD -name "GCBreakOnOOM" -value 2
	}
}
function Disable-GCBreakOnOOM{
    trap [Exception]{
	   WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
	   return ""
	}
	if (Test-Path "HKLM:\SOFTWARE\Microsoft\.NETFramework"){
		set-itemproperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework" -type DWORD -name "GCBreakOnOOM" -value 0
		#Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework" -Name "GCBreakOnOOM"
	}
}
#endregion CRM Crash Dump Functions
#region Shared CRM Functions
function Get-WindowsPowerPlan{
	trap [Exception]{
	   WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
	   return ""
	}
	return (Get-CimInstance -Class win32_powerplan -Namespace root\cimv2\power -Filter "isActive='true'").ElementName
}
function Get-TempDirectoryFileCount{
     trap [Exception]{
	   WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;
	   return -1
	  }
	return (dir $env:windir\temp\*.*).count
	#IF ((dir $env:temp\*.*).count -ge 50,000) {"Some temp files should be deleted to prevent performance problems or potential crashes if you reach the limit of 65535 files in the Temp folder at $env:temp}
}
#endregion Shared CRM Functions


# SIG # Begin signature block
# MIInwwYJKoZIhvcNAQcCoIIntDCCJ7ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDIjTLMgQ0wofVB
# TepkQZ0IJKl/UDpn1H7er1aVN61/R6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIL6Vz27c14Q9E4CFVlqKpty5
# zggc11+vyJx+ctDIFkFnMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBz3LK6oqjot5UCFCwHk2y5/US/OKtEuxmXXcJycFTedF+5ij760RXz
# l+ajSr/5v3uFwPwytDU0fHvB7QRps84fHQlWNdRMmMlqqH5fZhz+cWaWz529JiXi
# O64Fcsw4pxLZvKpPmJqcDp14Q0kWcmvZTdRc1d4+gMDOtbhbV67aCh9lnNoVE5rp
# +pqiCzF4uw0s+vM6nK4vOQNWOvv5AVbzALPmxaFe8Km/p30Bjg5CvSQ8KTGiM5eZ
# Yxq8miyRgpUJYcPJv1Z/Zg4IYPDaNU4qiWj+umMoxeTSAc7Mq87Nklq/mePCILOl
# tFn9DESmD5FyvA9pF06kk1xMJ339j3yNoYIXKzCCFycGCisGAQQBgjcDAwExghcX
# MIIXEwYJKoZIhvcNAQcCoIIXBDCCFwACAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIAFHMOu5q53j1UBbo4zG0JNofrQeq4skTklXF7jgRjVyAgZj91jp
# ad4YEzIwMjMwMjI0MDg0MzE1Ljc5OVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
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
# AQkEMSIEIPeLRcHQNvh4SarTXHEZqpji4Y9cNmzJChaJPBxUMsTSMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQghqEz1SoQ0ge2RtMyUGVDNo5P5ZdcyRoeijoZ
# ++pPv0IwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AbP+Jc4pGxuKHAABAAABszAiBCAWr8PWTfcZypPyi/V7eToJal2jgijvomf9+YAW
# f9n4DTANBgkqhkiG9w0BAQsFAASCAgA90TWHv0hYWuYifhwRB7qtl7rwtPSaahTY
# P2qnT1IIxCbmLUtoA498xVpOXvTWU8WXGul0d+A0Uet4pGA/RuYLTEBJAI6A37Ac
# +6QOjlaEBhJL5IbB6yQWQiP2N5RmdTGXnaKCXbPDdUx9fRhjoJCr4HcRpri8ssMS
# X1ihAJOpZ3vJHtLRORELBtIUpzbstTHX/rWib5tUBr+pPUfFLViERnBmufFkRSDv
# VmzLGWD7WBumHrzJ0XMjetcerzWD7i13f83YF7S1olTsR1ZJy9xQkatUytQu+Wcb
# xz4KC8iXTh3UmJ3D0lakuoq6p92qXWHG3GgJ91BnpmdKjV6C7W9X2VrCmJEVQDRq
# OdFfGhI2BQ+7umMOTx7dKbfiMm26QeWL9JLp1Fv6ke2FlxpnHa++CzOkwYMAs9Xl
# O1SX36Bc50rbKxHCOhYiTBtvrAQbqxZivx67C2bEirZfRpQ+/Q1UzVCJVvQZxEd3
# akUemnqwu19LhVPsfQQj5agI9Occkx1JjO9AgOaJdbEt318cjYZzu7jcfLkgOxIm
# sB33xNliIXGuirk9EtDbXYO+Kk87SMUD/tnpCLZqOJDjigV3txRfK0btd6KpkvdI
# 1yaqmn9jx1GTSJCsycACzvBHjRED7G5gtmKIRnI9Hyv9+ko5OvinZtYy4w42ri+d
# bbRqE+Xfbg==
# SIG # End signature block
