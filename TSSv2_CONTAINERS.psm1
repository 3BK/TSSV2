<#
.SYNOPSIS
	This module is part of TSS FW and implements support for tracing Container scenarios


.DESCRIPTION
	This module is part of TSS FW and implements support for tracing Container scenarios


.NOTES
	Dev. Lead: wiaftrin, milanmil
	Authors		: wiaftrin, milanmil
	Requires	: PowerShell V4(Supported from Windows 8.1/Windows Server 2012 R2)
	Version		: see $global:TssVerDateCONTAINERS

.LINK
	TSSv2 https://internal.support.services.microsoft.com/en-us/help/4619187

#>

[cmdletbinding(PositionalBinding = $false, DefaultParameterSetName = "Default")]
param(
[Parameter(ParameterSetName = "Default")]
[string]$containerId
)

$global:TssVerDateCON= "2023.03.03.0"

#region event_logs_registry

	$_EVENTLOG_LIST_START = @(
		# LOGNAME!FLAG1|FLAG2|FLAG3
		"Application!NONE"
		"System!NONE"
		"Microsoft-Windows-CAPI2/Operational!CLEAR|SIZE|EXPORT"
		"Microsoft-Windows-Kerberos/Operational!CLEAR"
		"Microsoft-Windows-Kerberos-key-Distribution-Center/Operational!DEFAULT"
		"Microsoft-Windows-Kerberos-KdcProxy/Operational!DEFAULT"
		"Microsoft-Windows-WebAuth/Operational!DEFAULT"
		"Microsoft-Windows-WebAuthN/Operational!EXPORT"
		"Microsoft-Windows-CertPoleEng/Operational!CLEAR"
		"Microsoft-Windows-IdCtrls/Operational!EXPORT"
		"Microsoft-Windows-User Control Panel/Operational!EXPORT"
		"Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController!DEFAULT"
		"Microsoft-Windows-Authentication/ProtectedUser-Client!DEFAULT"
		"Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController!DEFAULT"
		"Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController!DEFAULT"
		"Microsoft-Windows-Biometrics/Operational!EXPORT"
		"Microsoft-Windows-LiveId/Operational!EXPORT"
		"Microsoft-Windows-AAD/Analytic!DEFAULT"
		"Microsoft-Windows-AAD/Operational!EXPORT"
		"Microsoft-Windows-User Device Registration/Debug!DEFAULT"
		"Microsoft-Windows-User Device Registration/Admin!EXPORT"
		"Microsoft-Windows-HelloForBusiness/Operational!EXPORT"
		"Microsoft-Windows-Shell-Core/Operational!DEFAULT"
		"Microsoft-Windows-WMI-Activity/Operational!DEFAULT"
		"Microsoft-Windows-GroupPolicy/Operational!DEFAULT"
		"Microsoft-Windows-Crypto-DPAPI/Operational!EXPORT"
		"Microsoft-Windows-Containers-CCG/Admin!NONE"
	)
	$_EVENTLOG_LIST_STOP = @(
	# LOGNAME!FLAGS
	"Application!DEFAULT"
	"System!DEFAULT"
	"Microsoft-Windows-CAPI2/Operational!NONE"
	"Microsoft-Windows-Kerberos/Operational!NONE"
	"Microsoft-Windows-Kerberos-key-Distribution-Center/Operational!NONE"
	"Microsoft-Windows-Kerberos-KdcProxy/Operational!NONE"
	"Microsoft-Windows-WebAuth/Operational!NONE"
	"Microsoft-Windows-WebAuthN/Operational!ENABLE"
	"Microsoft-Windows-CertPoleEng/Operational!NONE"
	"Microsoft-Windows-IdCtrls/Operational!ENABLE"
	"Microsoft-Windows-User Control Panel/Operational!NONE"
	"Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController!NONE"
	"Microsoft-Windows-Authentication/ProtectedUser-Client!NONE"
	"Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController!NONE"
	"Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController!NONE"
	"Microsoft-Windows-Biometrics/Operational!ENABLE"
	"Microsoft-Windows-LiveId/Operational!ENABLE"
	"Microsoft-Windows-AAD/Analytic!NONE"
	"Microsoft-Windows-AAD/Operational!ENABLE"
	"Microsoft-Windows-User Device Registration/Debug!NONE"
	"Microsoft-Windows-User Device Registration/Admin!ENABLE"
	"Microsoft-Windows-HelloForBusiness/Operational!ENABLE"
	"Microsoft-Windows-Shell-Core/Operational!ENABLE"
	"Microsoft-Windows-WMI-Activity/Operational!ENABLE"
	"Microsoft-Windows-GroupPolicy/Operational!DEFAULT"
	"Microsoft-Windows-Crypto-DPAPI/Operational!ENABLE"
	"Microsoft-Windows-Containers-CCG/Admin!ENABLE"
	"Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational!ENABLE"
	"Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational!ENABLE"
)

$_REG_ADD_START = @(
	# KEY!NAME!TYPE!VALUE
	"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NegoExtender\Parameters!InfoLevel!REG_DWORD!0xFFFF"
	"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Pku2u\Parameters!InfoLevel!REG_DWORD!0xFFFF"
	"HKLM\SYSTEM\CurrentControlSet\Control\LSA!SPMInfoLevel!REG_DWORD!0xC43EFF"
	"HKLM\SYSTEM\CurrentControlSet\Control\LSA!LogToFile!REG_DWORD!1"
	"HKLM\SYSTEM\CurrentControlSet\Control\LSA!NegEventMask!REG_DWORD!0xF"
	"HKLM\SYSTEM\CurrentControlSet\Control\LSA!LspDbgInfoLevel!REG_DWORD!0x41C24800"
	"HKLM\SYSTEM\CurrentControlSet\Control\LSA!LspDbgTraceOptions!REG_DWORD!0x1"
)




# Reg Delete
$_REG_DELETE = @(
	# KEY!NAME
	"HKLM\SYSTEM\CurrentControlSet\Control\LSA!SPMInfoLevel"
	"HKLM\SYSTEM\CurrentControlSet\Control\LSA!LogToFile"
	"HKLM\SYSTEM\CurrentControlSet\Control\LSA!NegEventMask"
	"HKLM\SYSTEM\CurrentControlSet\Control\LSA\NegoExtender\Parameters!InfoLevel"
	"HKLM\SYSTEM\CurrentControlSet\Control\LSA\Pku2u\Parameters!InfoLevel"
	"HKLM\SYSTEM\CurrentControlSet\Control\LSA!LspDbgInfoLevel"
	"HKLM\SYSTEM\CurrentControlSet\Control\LSA!LspDbgTraceOptions"
	"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics!GPSvcDebugLevel"
)

# Reg Query
$_REG_QUERY = @(
	# KEY!CHILD!FILENAME
	# File will be written ending with <FILENAME>-key.txt
	# If the export already exists it will be appended
	"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa!CHILDREN!Lsa"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies!CHILDREN!Polices"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System!CHILDREN!SystemGP"
	"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer!CHILDREN!Lanmanserver"
	"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation!CHILDREN!Lanmanworkstation"
	"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon!CHILDREN!Netlogon"
	"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL!CHILDREN!Schannel"
	"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography!CHILDREN!Cryptography-HKLMControl"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography!CHILDREN!Cryptography-HKLMSoftware"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography!CHILDREN!Cryptography-HKLMSoftware-Policies"
	"HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Cryptography!CHILDREN!Cryptography-HKCUSoftware-Policies"
	"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Cryptography!CHILDREN!Cryptography-HKCUSoftware"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider!CHILDREN!SCardCredentialProviderGP"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication!CHILDREN!Authentication"
	"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Authentication!CHILDREN!Authentication-Wow64"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon!CHILDREN!Winlogon"
	"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Winlogon!CHILDREN!Winlogon-CCS"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityStore!CHILDREN!Idstore-Config"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityCRL!CHILDREN!Idstore-Config"
	"HKEY_USERS\.Default\Software\Microsoft\IdentityCRL!CHILDREN!Idstore-Config"
	"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc!CHILDREN!KDC"
	"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KPSSVC!CHILDREN!KDCProxy"
	"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CloudDomainJoin!CHILDREN!RegCDJ"
	"HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin!CHILDREN!RegWPJ"
	"HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\AADNGC!CHILDREN!RegAADNGC"
	"HKEY_LOCAL_MACHINE\Software\Policies\Windows\WorkplaceJoin!CHILDREN!REGWPJ-Policy"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Winbio!CHILDREN!Wbio"
	"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc!CHILDREN!Wbiosrvc"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics!CHILDREN!Wbio-Policy"
	"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\EAS\Policies!CHILDREN!EAS"
	"HKEY_CURRENT_USER\SOFTWARE\Microsoft\SCEP!CHILDREN!Scep"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient!CHILDREN!MachineId"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork!CHILDREN!NgcPolicyIntune"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork!CHILDREN!NgcPolicyGp"
	"HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\PassportForWork!CHILDREN!NgcPolicyGpUser"
	"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc!CHILDREN!NgcCryptoConfig"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock!CHILDREN!DeviceLockPolicy"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Policies\PassportForWork\SecurityKey!CHILDREN!FIDOPolicyIntune"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FIDO!CHILDREN!FIDOGp"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc!CHILDREN!RpcGP"
	"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters!CHILDREN!NTDS"
	"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP!CHILDREN!LdapClient"
	"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard!CHILDREN!DeviceGuard"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CCMSetup!CHILDREN!CCMSetup"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CCM!CHILDREN!CCM"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v2.0.50727!NONE!DotNET-TLS"
	"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319!NONE!DotNET-TLS"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319!NONE!DotNET-TLS"
	"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727!NONE!DotNET-TLS"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedPC!NONE!SharedPC"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess!NONE!Passwordless"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Authz!CHILDREN!Authz"
	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp!NONE!WinHttp-TLS"
	"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp!NONE!WinHttp-TLS"
	"HKEY_LOCAL_MACHINE\Software\Microsoft\Enrollments!CHILDREN!MDMEnrollments"
	"HKEY_LOCAL_MACHINE\Software\Microsoft\EnterpriseResourceManager!CHILDREN!MDMEnterpriseResourceManager"
	"HKEY_CURRENT_USER\Software\Microsoft\SCEP!CHILDREN!MDMSCEP-User"
	"HKEY_CURRENT_USER\S-1-5-18\Software\Microsoft\SCEP!CHILDREN!MDMSCEP-SystemUser"
)

#endregion event_logs_registry

#region container_functions

function Invoke-Container {

	[Cmdletbinding(DefaultParameterSetName = "Default")]
	param(
		[Parameter(Mandatory = $true)]
		[string]$ContainerId,
		[switch]$Nano,
		[Parameter(ParameterSetName = "PreTraceDir")]
		[switch]$PreTrace,
		[Parameter(ParameterSetName = "AuthDir")]
		[switch]$AuthDir,
		[switch]$UseCmd,
		[switch]$Record,
		[switch]$Silent,
		[Parameter(Mandatory = $true)]
		[string]$Command,
		[string]$WorkingFolder
	)

	<#
	$Workingdir = $_BASE_LOG_DIR #"C:\AuthScripts"
	if ($PreTrace) {
		$Workingdir += "\authlogs\PreTraceLogs"
	}

	if ($AuthDir) {
		$Workingdir += "\authlogs"
	}
	#>

	If($PSBoundParameters.ContainsKey("WorkingFolder")) {
		$Workingdir = $WorkingFolder
	}
	else {
		$Workingdir = "c:\TSS" #in TSS all commands, by default, run in TSS, otherwise use $WorkingFolder
	}




	Write-Verbose "Running Container command: $Command"
	if ($Record) {
		if ($Nano) {
			docker exec -u Administrator -w $Workingdir $ContainerId cmd /c "$Command" *>> $_CONTAINER_DIR\container-output.txt
		}
		elseif ($UseCmd) {
			docker exec -w $Workingdir $ContainerId cmd /c "$Command" *>> $_CONTAINER_DIR\container-output.txt
		}
		else {
			docker exec -w $Workingdir $ContainerId powershell -ExecutionPolicy Unrestricted "$Command" *>> $_CONTAINER_DIR\container-output.txt
		}
	}
	elseif ($Silent) {
		if ($Nano) {
			docker exec -u Administrator -w $Workingdir $ContainerId cmd /c "$Command" *>> Out-Null
		}
		elseif ($UseCmd) {
			docker exec -w $Workingdir $ContainerId cmd /c "$Command" *>> Out-Null
		}
		else {
			docker exec -w $Workingdir $ContainerId powershell -ExecutionPolicy Unrestricted "$Command" *>> Out-Null
		}
	}
	else {
		$Result = ""
		if ($Nano) {
			$Result = docker exec -u Administrator -w $Workingdir $ContainerId cmd /c "$Command"
		}
		elseif ($UseCmd) {
			$Result = docker exec -w $Workingdir $ContainerId cmd /c "$Command"
		}
		else {
			$Result = docker exec -w $Workingdir $ContainerId powershell -ExecutionPolicy Unrestricted "$Command"
		}
		return $Result
	}
}

function Check-ContainerIsNano {
	param($ContainerId)

	# This command is finicky and cannot use a powershell variable for the command
	$ContainerBase = Invoke-Container -ContainerId $containerId -UseCmd -Command "reg query `"hklm\software\microsoft\windows nt\currentversion`" /v EditionID"
	Write-Verbose "Container Base: $ContainerBase"
	# We only check for nano server as it is the most restrictive
	if ($ContainerBase -like "*Nano*") {
		return $true
	}
	else {
		return $false
	}
}

function Get-ContainersInfo {

	param($ContainerId)
	Get-NetFirewallProfile > $_CONTAINER_DIR\firewall_profile.txt
	Get-NetConnectionProfile >> $_CONTAINER_DIR\firewall_profile.txt
	netsh advfirewall firewall show rule name=* > $_CONTAINER_DIR\firewall_rules.txt
	netsh wfp show filters file=$_CONTAINER_DIR\wfpfilters.xml 2>&1 | Out-Null
	docker ps > $_CONTAINER_DIR\container-info.txt
	docker inspect $(docker ps -q) >> $_CONTAINER_DIR\container-info.txt
	docker network ls > $_CONTAINER_DIR\container-network-info.txt
	docker network inspect $(docker network ls -q) >> $_CONTAINER_DIR\container-network-info.txt

	docker top $containerId > $_CONTAINER_DIR\container-top.txt
	docker logs $containerId > $_CONTAINER_DIR\container-logs.txt

	wevtutil.exe set-log "Microsoft-Windows-Containers-CCG/Admin" /enabled:false 2>&1 | Out-Null
	wevtutil.exe export-log "Microsoft-Windows-Containers-CCG/Admin" $_CONTAINER_DIR\Containers-CCG_Admin.evtx /overwrite:true 2>&1 | Out-Null
	wevtutil.exe set-log "Microsoft-Windows-Containers-CCG/Admin" /enabled:true /rt:false /q:true 2>&1 | Out-Null
	Get-EventLog -LogName Application -Source Docker -After (Get-Date).AddMinutes(-30)  | Sort-Object Time | Export-CSV $_CONTAINER_DIR\docker_events.csv

}

function Check-ContainsScripts {
	param(
		$ContainerId,
		[switch]$IsNano
	)

	if ($IsNano) {
		$Result = Invoke-Container -ContainerId $containerId -Nano -Command "if exist auth.wprp (echo true)"

		if ($Result -eq "True") {

			$Result = Invoke-Container -ContainerId $containerId -Nano -Command "type auth.wprp"
			$Result = $Result[1]
			if (!$Result.Contains($_Authscriptver)) {
				$InnerScriptVersion = $Result.Split(" ")[1].Split("=")[1].Trim("`"")
				Write-Host "$ContainerId Script Version mismatch" Yellow
				Write-Host "Container Host Version: $_Authscriptver" Yellow
				Write-Host "Container Version: $InnerScriptVersion" Yellow
				return $false
			}
			Out-File -FilePath $_CONTAINER_DIR\script-info.txt -InputObject "SCRIPT VERSION: $_Authscriptver"
			return $true
		}
		else {
			return $false
		}
	}
	else {
		$StartResult = Invoke-Container -ContainerId $containerId -Command "Test-Path TSSv2.ps1" -WorkingFolder "C:\TSS\TSSv2"
		$StopResult = Invoke-Container -ContainerId $containerId -Command "Test-Path TSSv2.ps1" -WorkingFolder "C:\TSS\TSSv2"
		if ($StartResult -eq "True" -and $StopResult -eq "True") {
			# Checking script version
			<#
			$InnerScriptVersion = Invoke-Container -ContainerId $containerId -Command ".\start-auth.ps1 -accepteula -version"
			if ($InnerScriptVersion -ne $_Authscriptver) {
				Write-Host "$ContainerId Script Version mismatch" -ForegroundColor Yellow
				Write-Host "Container Host Version: $_Authscriptver" -ForegroundColor Yellow
				Write-Host "Container Version: $InnerScriptVersion" -ForegroundColor Yellow
				return $false
			}
			else {
				Out-File -FilePath $_CONTAINER_DIR\script-info.txt -InputObject "SCRIPT VERSION: $_Authscriptver"
				return $true
			}#>			
			return $true
		}
		else {
			#Write-Host "Container: $ContainerId missing tracing scripts!" -ForegroundColor Yellow
			return $false
		}
	}
}

function Check-GMSA-Stop {
	param($ContainerId)

	$CredentialString = docker inspect -f "{{ .HostConfig.SecurityOpt }}" $ContainerId

	if ($CredentialString -ne "[]") {
		Write-Verbose "GMSA Credential String: $CredentialString"
		# NOTE(will): We need to check if we have RSAT installed
		if ((Get-Command "Test-ADServiceAccount" -ErrorAction "SilentlyContinue") -ne $null) {
			$ServiceAccountName = $(docker inspect -f "{{ .Config.Hostname }}" $ContainerId)
			$Result = "`nSTOP:`n`nRunning Test-ADServiceAccount $ServiceAccountName`nResult:"
			try {
				$Result += Test-ADServiceAccount -Identity $ServiceAccountName -Verbose -ErrorAction SilentlyContinue
			}
			catch {
				$Result += "Unable to find object with identity $containerId"
			}

			Out-File $_CONTAINER_DIR\gMSATest.txt -InputObject $Result -Append
		}

		$CredentialName = $CredentialString.Replace("[", "").Replace("]", "")
		$CredentialName = $CredentialName.Split("//")[-1]
		$CredentialObject = Get-CredentialSpec | Where-Object { $_.Name -eq $CredentialName }
		Copy-Item $CredentialObject.Path $_CONTAINER_DIR
	}
}

function Check-GMSA-Start {
	param($ContainerId)

	$CredentialString = docker inspect -f "{.HostConfig.SecurityOpt}" $ContainerId
	if ($CredentialString -ne "[]") {
		Write-Verbose "GMSA Credential String: $CredentialString"
		# We need to check if we have Test-ADServiceAccount
		if ((Get-Command "Test-ADServiceAccount" -ErrorAction "SilentlyContinue") -ne $null) {
			$ServiceAccountName = $(docker inspect -f "{{ .Config.Hostname }}" $ContainerId)
			$Result = "START:`n`nRunning: Test-ADServiceAccount $ServiceAccountName`nResult:"

			try {
				$Result += Test-ADServiceAccount -Identity $ServiceAccountName -Verbose -ErrorAction SilentlyContinue
			}
			catch {
				$Result += "Unable to find object with identity $containerId"
			}

			Out-File $_CONTAINER_DIR\gMSATest.txt -InputObject $Result
		}
	}
}

function Generate-WPRP {
	param($ContainerId)
	$Header = @"
<?xml version="1.0" encoding="utf-8"?>
<WindowsPerformanceRecorder Version="$_Authscriptver" Author="Microsoft Corporation" Copyright="Microsoft Corporation" Company="Microsoft Corporation">
  <Profiles>

"@
	$Footer = @"
  </Profiles>
</WindowsPerformanceRecorder>
"@


	$Netmon = "{2ED6006E-4729-4609-B423-3EE7BCD678EF}"

	$ProviderList = (("NGC", $NGC),
	 ("Biometric", $Biometric),
	 ("LSA", $LSA),
	 ("Ntlm_CredSSP", $Ntlm_CredSSP),
	 ("Kerberos", $Kerberos),
	 ("KDC", $KDC),
	 ("SSL", $SSL),
	 ("WebAuth", $WebAuth),
	 ("Smartcard", $Smartcard),
	 ("CredprovAuthui", $CredprovAuthui),
	 ("AppX", $AppX),
	 ("SAM", $SAM),
	 ("kernel", $Kernel),
	 ("Netmon", $Netmon))

	# NOTE(will): Checking if Client SKU
	$ClientSKU = Invoke-Container -ContainerId $ContainerId -Nano -Command "reg query HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions /v ProductType | findstr WinNT"
	if ($ClientSKU -ne $null) {
		$ProviderList.Add(("CryptNcryptDpapi", $CryptNcryptDpapi))
	}

	foreach ($Provider in $ProviderList) {
		$ProviderName = $Provider[0]
		$Header += @"
	<EventCollector Id="EventCollector$ProviderName" Name="EventCollector$ProviderName">
	  <BufferSize Value="64" />
	  <Buffers Value="4" />
	</EventCollector>

"@
	}

	$Header += "`n`n"

	# Starting on provider generation

	foreach ($Provider in $ProviderList) {
		$ProviderCount = 0
		$ProviderName = $Provider[0]

		foreach ($ProviderItem in $Provider[1]) {
			$ProviderParams = $ProviderItem.Split("!")
			$ProviderGuid = $ProviderParams[0].Replace("{", '').Replace("}", '')
			$ProviderFlags = $ProviderParams[1]

			$Header += @"
	<EventProvider Id="$ProviderName$ProviderCount" Name="$ProviderGuid"/>

"@
			$ProviderCount++
		}
	}

	# Generating profiles
	foreach ($Provider in $ProviderList) {
		$ProviderName = $Provider[0]
		$Header += @"
  <Profile Id="$ProviderName.Verbose.File" Name="$ProviderName" Description="$ProviderName.1" LoggingMode="File" DetailLevel="Verbose">
	<Collectors>
	  <EventCollectorId Value="EventCollector$ProviderName">
		<EventProviders>

"@
		$ProviderCount = 0
		for ($i = 0; $i -lt $Provider[1].Count; $i++) {
			$Header += "`t`t`t<EventProviderId Value=`"$ProviderName$ProviderCount`" />`n"
			$ProviderCount++
		}

		$Header += @"
		</EventProviders>
	  </EventCollectorId>
	</Collectors>
  </Profile>
  <Profile Id="$ProviderName.Light.File" Name="$ProviderName" Description="$ProviderName.1" Base="$ProviderName.Verbose.File" LoggingMode="File" DetailLevel="Light" />
  <Profile Id="$ProviderName.Verbose.Memory" Name="$ProviderName" Description="$ProviderName.1" Base="$ProviderName.Verbose.File" LoggingMode="Memory" DetailLevel="Verbose" />
  <Profile Id="$ProviderName.Light.Memory" Name="$ProviderName" Description="$ProviderName.1" Base="$ProviderName.Verbose.File" LoggingMode="Memory" DetailLevel="Light" />

"@

		# Keep track of the providers that are currently running
		Out-File -FilePath "$_CONTAINER_DIR\RunningProviders.txt" -InputObject "$ProviderName" -Append
	}


	$Header += $Footer

	# Writing to a file
	Out-file -FilePath "auth.wprp" -InputObject $Header -Encoding ascii

}

function Start-NanoTrace {
	param($ContainerId)

	# Event Logs
	foreach ($EventLog in $_EVENTLOG_LIST_START) {
		$EventLogParams = $EventLog.Split("!")
		$EventLogName = $EventLogParams[0]
		$EventLogOptions = $EventLogParams[1]

		$ExportLogName += ".evtx"

		if ($EventLogOptions -ne "NONE") {
			Invoke-Container -ContainerId $ContainerId -Nano -Record -Command "wevtutil set-log $EventLogName /enabled:true /rt:false /q:true"

			if ($EventLogOptions.Contains("EXPORT")) {
				$ExportName = $EventLogName.Replace("Microsoft-Windows-", "").Replace(" ", "_").Replace("/", "_")
				Invoke-Container -ContainerId $ContainerId -Nano -Record -PreTrace -Command "wevtutil export-log $EventLogName $ExportName /overwrite:true"
			}
			if ($EventLogOptions.Contains("CLEAR")) {
				Invoke-Container -ContainerId $ContainerId -Nano -Record -Command "wevtutil clear-log $EventLogName"
			}
			if ($EventLogOptions.Contains("SIZE")) {
				Invoke-Container -ContainerId $ContainerId -Nano -Record -Command "wevtutil set-log $EventLogName /ms:102400000"
			}
		}
	}

	# Reg Add
	foreach ($RegAction in $_REG_ADD_START) {
		$RegParams = $RegAction.Split("!")
		$RegKey = $RegParams[0]
		$RegName = $RegParams[1]
		$RegType = $RegParams[2]
		$RegValue = $RegParams[3]

		Invoke-Container -ContainerId $ContainerId -Nano -Record -Command "reg add $RegKey /v $RegName /t $RegType /d $RegValue /f"
	}

	Get-Content "$_CONTAINER_DIR\RunningProviders.txt" | ForEach-Object {
		Invoke-Container -ContainerId $ContainerId -Nano -Record -Command "wpr -start auth.wprp!$_ -instancename $_"
	}


}

function Stop-NanoTrace {
	param($ContainerId)

	Get-Content "$_CONTAINER_DIR\RunningProviders.txt" | ForEach-Object {
		Invoke-Container -ContainerId $ContainerId -Nano -AuthDir -Record -Command "wpr -stop $_`.etl -instancename $_"
	}

	# Cleaning up registry keys
	foreach ($RegDelete in $_REG_DELETE) {
		$DeleteParams = $RegDelete.Split("!")
		$DeleteKey = $DeleteParams[0]
		$DeleteValue = $DeleteParams[1]
		Invoke-Container -ContainerId $ContainerId -Nano -Record -Command "reg delete `"$DeleteKey`" /v $DeleteValue /f"
	}

	# Querying registry keys
	foreach ($RegQuery in $_REG_QUERY) {
		$QueryParams = $RegQuery.Split("!")
		$QueryKey = $QueryParams[0]
		$QueryOptions = $QueryParams[1]
		$QueryOutput = $QueryParams[2]

		$QueryOutput = "$QueryOutput`-key.txt"
		$AppendFile = Invoke-Container -ContainerId $ContainerId -AuthDir -Nano -Command "if exist $QueryOutput (echo True)"

		Write-Verbose "Append Result: $AppendFile"
		$Redirect = "> $QueryOutput"

		if ($AppendFile -eq "True") {
			$Redirect = ">> $QueryOutput"
		}


		if ($QueryOptions -eq "CHILDREN") {
			Invoke-Container -ContainerId $ContainerId -AuthDir -Nano -Record -Command "reg query `"$QueryKey`" /s $Redirect"
		}
		else {
			Invoke-Container -ContainerId $ContainerId -AuthDir -Nano -Record -Command "reg query `"$QueryKey`" $Redirect"
		}

	}

	foreach ($EventLog in $_EVENTLOG_LIST_STOP) {
		$EventLogParams = $EventLog.Split("!")
		$EventLogName = $EventLogParams[0]
		$EventLogOptions = $EventLogParams[1]

		$ExportName = $EventLogName.Replace("Microsoft-Windows-", "").Replace(" ", "_").Replace("/", "_")

		if ($EventLogOptions -ne "DEFAULT") {
			Invoke-Container -ContainerId $ContainerId -Nano -Record -Command "wevtutil set-log $EventLogName /enabled:false"
		}

		Invoke-Container -ContainerId $ContainerId -Nano -Record -AuthDir -Command "wevtutil export-log $EventLogName $ExportName.evtx /overwrite:true"

		if ($EventLogOptions -eq "ENABLE") {
			Invoke-Container -ContainerId $ContainerId -Nano -Record -Command "wevtutil set-log $EventLogName /enabled:true /rt:false" *>> $_CONTAINER_DIR\container-output.txt
		}
	}
}
#endregion container_functions

#region FW_functions

function FWStart-ContainerTracing
{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$containerId,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$TSSScriptsSourceFolderonHost,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$TSSScriptTargetFolderInContainer,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$TSSStartCommandToExecInContainer,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$TSSWorkingFolderInContainer
	)
	EnterFunc $MyInvocation.MyCommand.Name

	# Confirm that docker is in our path
	$DockerExists = (Get-Command "docker.exe" -ErrorAction SilentlyContinue) -ne $null
	if ($DockerExists) {
		LogInfo "Docker.exe found"
		$RunningContainers = $(docker ps -q)
		if ($containerId -in $RunningContainers) {
			LogInfo "$containerId found"
			$_CONTAINER_DIR = "$_BASE_C_DIR`-$containerId"
			if ((Test-Path $_CONTAINER_DIR\started.txt)) {
				LogInfo "Container tracing already started. Please run Tssv2.ps1 -stop to stop the tracing and start tracing again"
					exit
				}
			New-Item $_CONTAINER_DIR -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
			Remove-Item $_CONTAINER_DIR\* -Recurse -ErrorAction SilentlyContinue | Out-Null

			# Confirm the running container base image
			if (Check-ContainerIsNano -ContainerId $containerId) {

				LogInfo "Container Image is NanoServer"
				Out-File -FilePath $_CONTAINER_DIR\container-base.txt -InputObject "Nano"

				# We need to use the wprp for the auth data collection
				if (!(Test-Path "$_CONTAINER_DIR\auth.wprp") -and !(Test-Path "$_CONTAINER_DIR\RunningProviders.txt")) {
					Generate-WPRP -ContainerId $containerId
				}

				# Checking if the container has the tracing scripts
				if (Check-ContainsScripts -ContainerId $containerId -IsNano) {
					LogInfo "Starting container tracing - please wait..."
					Start-NanoTrace -ContainerId $containerId
				}
				else {
					LogInfo "Container: $containerId missing tracing script!" Yellow
					# $_BASE_LOG_DIR could be used insted of C:\authscripts
					LogInfo "Please copy the auth.wprp into the $TSSScriptTargetFolderInContainer\TSSv2 directory in the container then run TSSv2.ps1 -containerId $containerId $TSSCommand again
	Example:
	`tdocker stop $containerId
	`tdocker cp auth.wprp $containerId`:\$TSSScriptTargetFolderInContainer
	`tdocker start $containerId
	`t.\TSSv2.ps1 -containerId $containerId $TSSStartCommandToExecInContainer" Yellow
						return
				}

			}
			else {
				LogInfo "Container Image is Standard"
				Out-File -FilePath $_CONTAINER_DIR\container-base.txt -InputObject "Standard"

				if (Check-ContainsScripts -ContainerId $containerId) {
					LogInfo "Starting container tracing - please wait..."
					Invoke-Container -ContainerId $ContainerId -Record -Command "TSSv2\TSSv2.ps1 $TSSStartCommandToExecInContainer"
				}
				else {

				LogInfo "Copy TSS script to container started."
				docker stop $containerId 2>&1 | Out-Null
				docker cp $TSSScriptsSourceFolderonHost $containerId`:\$TSSScriptTargetFolderInContainer 2>&1 | Out-Null
				docker start $containerId 2>&1 | Out-Null
				LogInfo "Copy TSS script to container completed."
				LogInfo "Starting trace command TSSv2.ps1 $TSSStartCommandToExecInContainer"
				Invoke-Container -ContainerId $ContainerId -Record -Command "TSSv2\TSSv2.ps1 $TSSStartCommandToExecInContainer"
				LogInfo "TSS Tracing started, tracing runs, please use TSSv2.ps1 -Stop command to stop tracing"
				<#
					LogInfo "Please copy $TSSScriptsSourceFolderonHost into the $TSSScriptTargetFolderInContainer directory in the container and run TSSv2.ps1 -containerId $containerId $TSSStartCommandToExecInContainer again
	Example:
	`tdocker stop $containerId
	`tdocker cp $TSSScriptsSourceFolderonHost $containerId`:\$TSSScriptTargetFolderInContainer
	`tdocker start $containerId
	`tdocker exec -w $TSSWorkingFolderInContainer $containerId powershell -ExecutionPolicy Unrestricted `".\tssv2.ps1 $TSSStartCommandToExecInContainer`"" Yellow
	#>
					exit #return
				}
			}
		}
		else {
			LogInfo "Failed to find $containerId"
			return
		}
	}
	else {
		LogInfo "Unable to find docker.exe in system path."
		return
	}

	Check-GMSA-Start -ContainerId $containerId

	# Start Container Logging
	$installedBuildVer = New-Object System.Version([version]$Global:OS_Version)
	$minPktMonBuildVer = New-Object System.Version([version]("10.0.17763.1852"))
	if ($($installedBuildVer.CompareTo($minPktMonBuildVer)) -ge 0) { # if installed Build version is greater than OS Build 17763.1852 from KB5000854
		pktmon start --capture -f $_CONTAINER_DIR\Pktmon.etl -s 4096 2>&1 | Out-Null
	}
	else {
		netsh trace start capture=yes persistent=yes report=disabled maxsize=4096 scenario=NetConnection traceFile=$_CONTAINER_DIR\netmon.etl | Out-Null
	}

	Add-Content -Path $_CONTAINER_DIR\script-info.txt -Value ("Data collection started on: " + (Get-Date -Format "yyyy/MM/dd HH:mm:ss"))
	Add-Content -Path $_CONTAINER_DIR\started.txt -Value "Started"

	return	
}

function FWStop-ContainerTracing
{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$containerId,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$TSSStopCommandToExecInContainer,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$TSSWorkingFolderInContainer
	)
	EnterFunc $MyInvocation.MyCommand.Name

	$_CONTAINER_DIR = "$_BASE_C_DIR`-$containerId"

   # no need to check this again
   # if (!(Test-Path "$_CONTAINER_DIR\started.txt")) {
   #		 LogInfo "Container tracing already started. Please run Tssv2.ps1 $TSSStopCommandToExecInContainer to stop the tracing and start tracing again"
   #		 return
   #  }

	LogInfo "Stopping Container tracing"
	$RunningContainers = $(docker ps -q)
	if ($containerId -in $RunningContainers) {
		LogInfo "$containerId Found"
		LogInfo "Stopping data collection..."
		if ((Get-Content $_CONTAINER_DIR\container-base.txt) -eq "Nano") {
			LogInfo "Stopping Nano container data collection"
			# NOTE(will) Stop the wprp
			Stop-NanoTrace -ContainerId $containerId
		}
		else {
			LogInfo "Stopping Standard container data collection"
			Invoke-Container -ContainerId $containerId -Record -Command "TSSv2\Tssv2.ps1 $($TSSStopCommandToExecInContainer)"
		}
	}
	else {
		LogInfo "Failed to find $containerId"
		return
	}

	LogInfo "`Collecting Container Host Device configuration information, please wait..."
	Check-GMSA-Stop -ContainerId $containerId
	Get-ContainersInfo -ContainerId $containerId

	# Stop Pktmon
	if ((Get-HotFix | Where-Object { $_.HotFixID -gt "KB5000854" -and $_.Description -eq "Update" } | Measure-object).Count -ne 0) { #we# better check for OS Build 17763.1852 or higher!
		pktmon stop 2>&1 | Out-Null
		pktmon list -a > $_CONTAINER_DIR\pktmon_components.txt
	}
	else {
		# consider removing it and using TSS FW for network trace 
		netsh trace stop | Out-Null
	}

	Add-Content -Path $_CONTAINER_DIR\script-info.txt -Value ("Data collection stopped on: " + (Get-Date -Format "yyyy/MM/dd HH:mm:ss"))
	if ((Test-Path $_CONTAINER_DIR\started.txt)) {
		Remove-Item -Path $_CONTAINER_DIR\started.txt -Force | Out-Null
		}



	LogInfo "The tracing is stopping, please wait..."
	docker stop $containerId 2>&1 | Out-Null
	docker cp $containerId`:\MS_DATA $_CONTAINER_DIR 2>&1 | Out-Null
	docker start $containerId 2>&1 | Out-Null
	LogInfo "Data copied to $_CONTAINER_DIR"
	docker exec --privileged $containerId cmd /c rd /s /q C:\TSS
	docker exec --privileged $containerId cmd /c rd /s /q c:\MS_DATA
	LogInfo "The tracing has been completed, please find the data in $_CONTAINER_DIR on the host machine."

	<#Please copy the collected data to the logging directory"
		LogInfo "Example:
	`tdocker stop $containerId
	`tdocker cp $containerId`:\MS_DATA $_CONTAINER_DIR
	`tdocker start $containerId" Yellow
	 #>
	 return

}


function global:FWEnter-ContainerTracing
{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$fwcontainerId,
		[parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[String]$fwTSSScriptsSourceFolderonHost,
		[parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[String]$fwTSSScriptTargetFolderInContainer,
		[parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[String]$fwTSSStartCommandToExecInContainer,
		[parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[String]$fwTSSStopCommandToExecInContainer
	)
	EnterFunc $MyInvocation.MyCommand.Name


	$_BASE_LOG_DIR = "C:\MS_DATA" #$global:LogFolder #".\authlogs"
	$_LOG_DIR = $_BASE_LOG_DIR
	$_CH_LOG_DIR = "$_BASE_LOG_DIR\container-host"
	$_BASE_C_DIR = "$_BASE_LOG_DIR`-container"
	$_C_LOG_DIR = "$_BASE_LOG_DIR\container"

	$TSScontainerId = $fwcontainerId 
	$TSSScriptsSourceFolderonHost = (Get-Location).Path #Split-Path (Get-Location).Path -parent
	$TSSScriptTargetFolderInContainer =  "TSS" # we should always use "TSS", if required use $fwTSSScriptTargetFolderInContainer
	$TSSWorkingFolderInContainer = "$fwTSSScriptTargetFolderInContainer\TSSv2"
	$TSSStartCommandToExecInContainer = $fwTSSStartCommandToExecInContainer
	$TSSStopCommandToExecInContainer = $fwTSSStopCommandToExecInContainer

	if (($TSSStartCommandToExecInContainer -ne "") -and ($TSSStopCommandToExecInContainer -ne ""))
	{
		LogInfo ("Invalid Call to FWEnter-ContainerTracing: please specify start or stop tracing command, not both of them at the same time")
		Exit
	}

	if ($TSSStartCommandToExecInContainer -ne "")
	{
	FWStart-ContainerTracing -containerId $TSScontainerId -TSSScriptsSourceFolderonHost $TSSScriptsSourceFolderonHost `
			-TSSScriptTargetFolderInContainer $TSSScriptTargetFolderInContainer -TSSStartCommandToExecInContainer $TSSStartCommandToExecInContainer -TSSWorkingFolderInContainer $TSSWorkingFolderInContainer
	}
	elseif ($TSSStopCommandToExecInContainer -ne "")
	{
		FWStop-ContainerTracing -containerId $TSScontainerId -TSSStopCommandToExecInContainer $TSSStopCommandToExecInContainer -TSSWorkingFolderInContainer $TSSWorkingFolderInContainer
	}
	else
	{
		LogInfo ("Please specify either start or stop command")
	}

}

#endregion FW_functions

Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias *


# SIG # Begin signature block
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB2TzukiKh7Fizm
# xCeVRcqIxR19TFS6AWFyUFbQsN7TQKCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
# esGEb+srAAAAAANOMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI5WhcNMjQwMzE0MTg0MzI5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDdCKiNI6IBFWuvJUmf6WdOJqZmIwYs5G7AJD5UbcL6tsC+EBPDbr36pFGo1bsU
# p53nRyFYnncoMg8FK0d8jLlw0lgexDDr7gicf2zOBFWqfv/nSLwzJFNP5W03DF/1
# 1oZ12rSFqGlm+O46cRjTDFBpMRCZZGddZlRBjivby0eI1VgTD1TvAdfBYQe82fhm
# WQkYR/lWmAK+vW/1+bO7jHaxXTNCxLIBW07F8PBjUcwFxxyfbe2mHB4h1L4U0Ofa
# +HX/aREQ7SqYZz59sXM2ySOfvYyIjnqSO80NGBaz5DvzIG88J0+BNhOu2jl6Dfcq
# jYQs1H/PMSQIK6E7lXDXSpXzAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnMc7Zn/ukKBsBiWkwdNfsN5pdwAw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMDUxNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAD21v9pHoLdBSNlFAjmk
# mx4XxOZAPsVxxXbDyQv1+kGDe9XpgBnT1lXnx7JDpFMKBwAyIwdInmvhK9pGBa31
# TyeL3p7R2s0L8SABPPRJHAEk4NHpBXxHjm4TKjezAbSqqbgsy10Y7KApy+9UrKa2
# kGmsuASsk95PVm5vem7OmTs42vm0BJUU+JPQLg8Y/sdj3TtSfLYYZAaJwTAIgi7d
# hzn5hatLo7Dhz+4T+MrFd+6LUa2U3zr97QwzDthx+RP9/RZnur4inzSQsG5DCVIM
# pA1l2NWEA3KAca0tI2l6hQNYsaKL1kefdfHCrPxEry8onJjyGGv9YKoLv6AOO7Oh
# JEmbQlz/xksYG2N/JSOJ+QqYpGTEuYFYVWain7He6jgb41JbpOGKDdE/b+V2q/gX
# UgFe2gdwTpCDsvh8SMRoq1/BNXcr7iTAU38Vgr83iVtPYmFhZOVM0ULp/kKTVoir
# IpP2KCxT4OekOctt8grYnhJ16QMjmMv5o53hjNFXOxigkQWYzUO+6w50g0FAeFa8
# 5ugCCB6lXEk21FFB1FdIHpjSQf+LP/W2OV/HfhC3uTPgKbRtXo83TZYEudooyZ/A
# Vu08sibZ3MkGOJORLERNwKm2G7oqdOv4Qj8Z0JrGgMzj46NFKAxkLSpE5oHQYP1H
# tPx1lPfD7iNSbJsP6LiUHXH1MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXMwghlvAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGJB3VXSBMzAFjVHqtu1U73V
# bFZl7C49l5RQEuXsVju3MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAqlMj/SbJt6ELmh+65a9t6gpqODyKdAAfJ04lsWjRDwi92CxZMPKUAAnC
# 0Ru82gqRGFzBnSSX8iWaKGzCsB7j1S468kAWNhrm931dZjw3FjkFTogh9BTWcVcI
# sqyruFY4LTGhypgjWAgW9oFYgkVNHPoo/U2XFzglWLsHAZZ2Rrg1EYTuOlC8QvBk
# YL9bmwAoVuF6d3KqbJpy7qbsrEmVnj/O+xz4+bV5+g/uY32pBI6Ziqmcm6mZGWT9
# mQxtu5JxenUzqu1iGrwqwSUmNAO9AQVbT4YOjSZs226PWlqCZEis72rw8gitNg7S
# 0jptnIoALHGKu9Ps36so4ya9qLvkaqGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCC
# FuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCC7oi7d7+/8ImpEgndgFBH3sXAK9Wxu53cae1E8tDG+bgIGZGzYtBQF
# GBMyMDIzMDYwNjExNDQxNi4wNjhaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0OUJDLUUz
# N0EtMjMzQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVQwggcMMIIE9KADAgECAhMzAAABwFWkjcNkFcVLAAEAAAHAMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEy
# NVoXDTI0MDIwMjE5MDEyNVowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjQ5QkMtRTM3QS0yMzNDMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAvO1g+2NhhmBQvlGlCTOMaFw3jbIhUdDTqkaQhRpdHVb+
# huU/0HNhLmoRYvrp7z5vIoL1MPAkVBFWJIkrcG7sSrednyZwreY207C9n8XivL9Z
# BOQeiUeL/TMlJ6VinrcafbhdnkNO5JDlPozC9dGySiubryds5GKtu69D1wNat9DI
# Ql6alFO6pncZK4RIzfv+KzkM7RkY3vHphV0C8EFUpF+lysaGJXFf9QsUUHwj9XKW
# Hfc9BfhLoCReXUzvgrspdFmVnA9ATYXmidSjrshf8A+E0/FpTdhXPI9XXqsZDHBq
# r7DlYoSCU3lvrVDRu1p5pHHf7s3kM16HpK6arDtY3ai1soASmEpv3C2N/y5MDBAp
# Dd4SpSkLMa7+6es/daeS7zdH1qdCa2RoJPM6Eh/6YmBfofhfLQofKPJl34ALlZWK
# 5AzVtFRNOXacoj6MAG2dT8Rc5fpKCH1E3n7Zje0dK24QVfSv/YOxw52ECaMLlW5P
# hHT3ZINNaCmRgcHCTClOKzC2FOr03YBc2zPOW6bIVdXloPmBMVaE+thXqPmANBw0
# YsncaOkVggjDb5O5VqOp98MklHpJoJI6pk5zAlx8/OtC7FutrdtYNUC6ykXzMAPF
# uYkWGgx/W7A0itKW8WzYzwO3bAhprwznouGZmRiw2k8pen80BzqzdyPvbzTxQsMC
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBQARMZ480jwpK3P6quVWUEJ0c30hTAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQCtTh0EQn16kKQyCeVk9Vc10m6L0EwLRo3ATRouP7Yd2hWeEB2Y4ZF4CJKe9qfX
# WGJKzV7tMUm6DAsBKYH/nT+8ybI8uJiHGnfnVi6Sh7gFjnTpfh1j1T90H/uLeoFj
# pOn/+eoCoJmorW5Gb2ezlTlo5I0kNAubxtCxqbLizuPNPob8kRAKQgv+4/CC1Jmi
# UFG0uKINlKj9SsHcrWeBBQHX62nNgziIwT44JqHrA02I6cmQAi9BZcsf57OOLpRY
# lzoPH3x/+ldSySXAmyLq2uSbWtQuD84I/0ZgS/B5L3ewqTdiE1KbKX89MW5JqCK/
# yI/mAIQammAlHPqU9eZZTMPOHQs0XrpCijlk+qyo2JaHiySww6nuPqXzU3sEj3VW
# 00YiVSayKEu1IrRzzX3La8qe6OqLTvK/6gu5XdKq7TT852nB6IP0QM+Budtr4Fbx
# 4/svpKHGpK9/zBuaHHDXX5AoSksh/kSDYKfefQIhIfQJJzoE3X+MimMJrgrwZXlt
# b6j1IL0HY3qCpa03Ghgi0ITzqfkw3Man3G8kB1Ql+SeNciPUj73Kn2veJenGLtT8
# JkUM9RUi0woO0iuY4tJnYuS+SeqavXUOWqUYVY19FIr1PLqpmWkbrO5xKjkyOHoA
# mLxjNbKjOnkAwft+1G00kulKqzqPbm+Sn+47JsGQFhNGbTCCB3EwggVZoAMCAQIC
# EzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoX
# DTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC
# 0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VG
# Iwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP
# 2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/P
# XfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361
# VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwB
# Sru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9
# X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269e
# wvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDw
# wvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr
# 9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+e
# FnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAj
# BgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+n
# FV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBH
# hkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
# BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4Swf
# ZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTC
# j/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu
# 2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/
# GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3D
# YXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbO
# xnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqO
# Cb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I
# 6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0
# zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaM
# mdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNT
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLLMIICNAIBATCB+KGB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046NDlCQy1FMzdBLTIzM0MxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVABAQ7ExF19KkwVL1E3Ad8k0Peb6doIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoKSL1MCIYDzIwMjMwNjA2MTExMzU3WhgPMjAyMzA2MDcxMTEzNTdaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOgpIvUCAQAwBwIBAAICBTUwBwIBAAICEngw
# CgIFAOgqdHUCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQAVRtyOICsPsOH1
# +kjCU+8mF5lgPZqJOgWfhisosAob5TWM8o5Wrgz0/8aG22FKVZLzgwtWbb50rGxu
# F85TC5iF9bQxX37OZ9JDAjZpRS6VwH97pXrZgIu30ceRq3lK9J/IKmQApr3yI4dm
# TGltSgTUx3bF86nYMhR1h2qST4akHTGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABwFWkjcNkFcVLAAEAAAHAMA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIBNPh9QYX1zs+vu0XfRIiwBbpjxzepgzJygTLClKDKbcMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQgWvFYolIIXME0zK/W6XsCkkYX7lYNb9yA8Jxw
# Y04Pk08wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# AcBVpI3DZBXFSwABAAABwDAiBCAat2Lywv2wa22F5tQkIY5+YIjZ0j0GIcCZ9ZZL
# hqkiUTANBgkqhkiG9w0BAQsFAASCAgApCQDZF/EtXWCrankyLvEPSBXLSbfp7hLC
# KN480neT6g7snwpxHBTa4Vupb6l8iGRKhbpIh3pnWSVcALU3De+BmEf2MKrFQT05
# 7990pKKGww31wv+gBCu0KxfBK2hSonJKsp3WzreDmPF5seJL2b64hNBKH85CUVda
# imAEQsTYr/yKtihaZTtMD7m46n7cQzgQZUI4+ndjarikxMs8VXCwI6fzvvoTEbgp
# xKSd5egf/aZWyLGUv7MZQcgK+6CurmPZJOtM502C/6Rjm2+0MFkprM23DjJXfWzh
# TKEKH27QT8nWvK690t23cQmLYJuF6FZiVX1QQqC41Admnw/KGQBiimvkHp16j8G/
# G+hCuREvRucdT02X5/rAw3Y0MPoOWbq0sZOBBLt1+h/tNunQyE0Ze5UB0Zu9Dt8W
# sJDgRj+g9Z0rOSKFl4ZVyduhx+P+sbS4gPwM/m8DwonhKHfNPfoJgcyzwxrY8Iw+
# ld39/salGkZowlSu1WUkMAepTNZSrBERy4+xHTKCGVKvGio39ZZKlhwZjxvWp63Y
# sEi6bkZidSIqYH2VIBtzhjzCVP/VafGp2HcDEVvM2a9utIb/V5CsHS8MOnXq48/N
# MmxcrQqaG0RRr30EzXwfZugQOfL+xQxqJyQ53D8pBLcGed/i6heWkaJhsgG8KXKi
# eBt1EZZY6w==
# SIG # End signature block
