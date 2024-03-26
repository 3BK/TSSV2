PARAM ([array]$Principals = ($env:USERNAME), $OSEmulation)
#************************************************
# TS_MaxTokenSizeChecks.ps1
# Version 1.0
# Date: 9-4-2013
# Author: Tspring
# Description: Script to detect user token sizing problems which may effect
#  use of domain services which require authentication.
# Update 10/2014 to add support for claims and parameters for checking multiple users token sizes. 
#************************************************
$global:FormatEnumerationLimit = -1
"Within TS_MaxTokenSizeChecks script prior to trap." | WriteTo-StdOut -ShortFormat
"OSEmulation is set to $OSEmulation" | WriteTo-StdOut -ShortFormat
$OSEmType = $OSEmulation.GetType()
"OSEmulation type is $OSEmType" | WriteTo-StdOut -ShortFormat

Trap [Exception]
		{
		 #Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 WriteTo-StdOut "[info]:An exception occurred." -shortformat
		 WriteTo-StdOut "[info]: Exception.Message $ExceptionMessage."
		 WriteTo-ErrorDebugReport -ErrorRecord $_
		 $Error.Clear()
		 continue
		}

#Define output file for token details outputs
$MaxTokenfileDescription = "Text file export of token information for groups and migrated SIDs for the user."
$DomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$DomainName = $DomainInfo.name
$MaxTokenSettingssectionDescription = "User Token Size Details"
$ExportFile = Join-Path $Pwd.Path ($DomainName  + "_KerberosTokenDetails.txt")
# | Out-File -Encoding UTF8 -FilePath $MaxTokenSettingsOutput -Append


function RC_MaxTokenSize
{	PARAM( $InformationCollected )
	
	$RootCauseName = "RC_MaxTokenSize"
	Update-DiagRootCause -id $RootCauseName -Detected $true
	$Verbosity = "Error"
	$Visibility = "4"
	$SupportTopicsID = "18628"
	$PublicContent = "http://support.microsoft.com/kb/327825"
	Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL $PublicContent -InformationCollected $InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID 
}

function RC_MaxTokenSizeWarn
{	PARAM( $InformationCollected )
	
	$RootCauseName = "RC_MaxTokenSizeWarn"
	Update-DiagRootCause -id $RootCauseName -Detected $true
	$Verbosity = "Error"
	$Visibility = "4"
	$SupportTopicsID = "18628"
	$PublicContent = "http://support.microsoft.com/kb/327825"
	Write-GenericMessage -RootCauseId $RootCauseName -PublicContentURL $PublicContent -InformationCollected $InformationCollected -Verbosity $Verbosity -Visibility $Visibility -SupportTopicsID $SupportTopicsID 
}


(Get-Date)  | Out-File $ExportFile -Encoding utf8  

#If OS is not specified to hyptohesize token size let's find the local OS and computer role
if (($OSEmulation -ne "12K") -and ($OSEmulation -ne "48K"))
      {
      $OS = Get-CimInstance -Class Win32_OperatingSystem
      $cs =  Get-CimInstance -Namespace "root\cimv2" -class win32_computersystem
      $DomainRole = $cs.domainrole
      switch -regex ($DomainRole) {
            [0-1]{
                  #Workstation.
                  $RoleString = "client"
                  if ($OS.BuildNumber -eq 3790)                                                 
                  {
                  $OperatingSystem = "Windows XP"
                  $OSBuild = $OS.BuildNumber
                  }
                        elseif (($OS.BuildNumber -eq 6001) -or ($OS.BuildNumber -eq 6002))
                              {
                              $OperatingSystem = "Windows Vista"
                              $OSBuild = $OS.BuildNumber
                              }
                                    elseif (($OS.BuildNumber -eq 7600) -or ($OS.BuildNumber -eq 7601))
                                                {
                                                $OperatingSystem = "Windows 7"
                                                $OSBuild = $OS.BuildNumber
                                                }
                                          elseif ($OS.BuildNumber -eq 9200)
                                                {
                                                $OperatingSystem =  "Windows 8"
                                                $OSBuild = $OS.BuildNumber
                                                }
                                                elseif ($OS.BuildNumber -eq 9600)
                                                      {
                                                      $OperatingSystem = "Windows 8.1"
                                                      $OSBuild = $OS.BuildNumber
                                                      }
                  }
            [2-3]{
                  #Member server.
                  $RoleString = "member server"
                  if ($OS.BuildNumber -eq 3790)
                       {
                        $OperatingSystem =  "Windows Server 2003"
                        $OSBuild = $OS.BuildNumber
                        }
                        elseif (($OS.BuildNumber -eq 6001) -or ($OS.BuildNumber -eq 6002))
                              {
                              $OperatingSystem =  "Windows Server 2008 RTM"
                              $OSBuild = $OS.BuildNumber
                              }
                              elseif (($OS.BuildNumber -eq 7600) -or ($OS.BuildNumber -eq 7601))
                                    {
                                    $OperatingSystem =  "Windows Server 2008 R2"
                                    $OSBuild = $OS.BuildNumber
                                    }
                                    elseif ($OS.BuildNumber -eq 9200)
                                          {
                                          $OperatingSystem = "Windows Server 2012"
                                          $OSBuild = $OS.BuildNumber
                                          }
                                          elseif ($OS.BuildNumber -eq 9600)
                                                {
                                                $OperatingSystem = "Windows Server 2012 R2"
                                                $OSBuild = $OS.BuildNumber
                                                }
                  }
            [4-5]{
                  #Domain Controller
                  $RoleString = "domain controller"
                  if ($OS.BuildNumber -eq 3790)
                       {
                        $OperatingSystem =  "Windows Server 2003"
                        $OSBuild = $OS.BuildNumber
                        }
                        elseif (($OS.BuildNumber -eq 6001) -or ($OS.BuildNumber -eq 6002))
                              {
                              $OperatingSystem =  "Windows Server 2008"
                              $OSBuild = $OS.BuildNumber
                              }
                              elseif (($OS.BuildNumber -eq 7600) -or ($OS.BuildNumber -eq 7601))
                                    {
                                    $OperatingSystem =  "Windows Server 2008 R2"
                                    $OSBuild = $OS.BuildNumber
                                    }
                                    elseif ($OS.BuildNumber -eq 9200)
                                          {
                                          $OperatingSystem = "Windows Server 2012"
                                          $OSBuild = $OS.BuildNumber}
                                          elseif ($OS.BuildNumber -eq 9600)
                                          {
                                          $OperatingSystem = "Windows Server 2012 R2"
                                          $OSBuild = $OS.BuildNumber
                                          }
                  }
            }
      }

if (($OSEmulation -eq "12K") -or ($OSEmulation -eq "48K"))
      {
      #Prompt user to choose which OS since they chose to emulate.
	  if ($OSEmulation -match "12K")
		{
		$OSBuild = "7600"
		"Gauging Kerberos token size using the Windows 7/Windows Server 2008 R2 and earlier default token size of 12K." | Out-File $ExportFile -Encoding utf8 -Append  
		}
		elsif ($OSEmulation -match "48K")
			{
			$OSBuild = "9200"
			"Gauging Kerberos token size using the Windows 8/Windows Server 2012 and later default token size of 48K. Note: The 48K setting is optionally configurable for many earlier Windows versions." | Out-File $ExportFile -Encoding utf8 -Append 
			}

      }
      else
            {
            "The computer is $OperatingSystem and is a $RoleString." | Out-File $ExportFile -Encoding utf8 -Append 
            }
	
function GetSIDHistorySIDs
      {     param ([string]$objectname)
      Trap [Exception] 
      {$Script:ExceptionMessage = $_
      $Error.Clear()
     continue}
     $DomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
      $RootString = "LDAP://" + $DomainInfo.Name
      $Root = New-Object  System.DirectoryServices.DirectoryEntry($RootString)
      $searcher = New-Object DirectoryServices.DirectorySearcher($Root)
      #$searcher.Filter="(&(userprincipalname=$objectname))"
	  $searcher.Filter="(|(userprincipalname=$objectname)(name=$objectname))"
      $results=$searcher.findone()
      if ($null -ne $results)
            {
            $SIDHistoryResults = $results.properties.sidhistory
            }
      #Clean up the SIDs so they are formatted correctly
      $SIDHistorySids = @()
      foreach ($SIDHistorySid in $SIDHistoryResults)
            {
            $SIDString = (New-Object System.Security.Principal.SecurityIdentifier($SIDHistorySid,0)).Value
            $SIDHistorySids += $SIDString
            }
      return $SIDHistorySids
}

#Fix up list if needed
"Principal list is $Principals" | WriteTo-StdOut -ShortFormat
$Users = @()
foreach ($Principal in $Principals)
	{
	"Within Principals foreach. Current one is $Principal" | WriteTo-StdOut -ShortFormat
	if ($Principal -match " " )
		{
		[array]$TempUserList = $Principal.Split(" ")
		foreach ($TempUser in $TempUserList)
			{
			if ($TempUser -notmatch " " )
				{$Users += $TempUser}
			}
		}
		else
		{$Users += $Principal}

	}

"Users array is $users" | WriteTo-StdOut -ShortFormat

if (($Principals.GetType()) -ne [System.String])
	{
	$NumberofPrincipals = $Users.count
	$UserCountdown = $NumberofPrincipals
	"Within Principals ne string" | WriteTo-StdOut -ShortFormat
	"Principals count for usercountdown is $Usercountdown" | WriteTo-StdOut -ShortFormat
	}
	else
		{
		$NumberofPrincipals = "1"
		"in else statement indicating the principals is a string" | WriteTo-StdOut -ShortFormat
		"PRincipals count for usercountdown is $Usercountdown" | WriteTo-StdOut -ShortFormat
		}


Import-LocalizedData -BindingVariable MaxTokenSizeStrings		
$Activity = $MaxTokenSizeStrings.ID_TokenSizeCheck_Activity -replace("%allusers%", $NumberofPrincipals)

foreach ($Principal in $Users)
      {
	 "Within token checking Foreach. Current user is $Principal" | WriteTo-StdOut -ShortFormat
	  $UpdatedSeconds = $UserCountdown * 120
	  $EstimatedTime = New-TimeSpan -seconds $UpdatedSeconds
	  $Minutes = $EstimatedTime.minutes
	  $Seconds = $EstimatedTime.seconds
	  $Status = $MaxTokenSizeStrings.ID_TokenSizeCheck_Status -replace("%userstogo%", $UserCountdown)
	  $Status = $Status.replace("%minutes%", $Minutes)
	  Write-DiagProgress -Activity $Activity -Status $Status

    Trap [Exception]
		{
		 #Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 WriteTo-StdOut "[info]:An exception occurred." -shortformat
		 WriteTo-StdOut "[info]: Exception.Message $ExceptionMessage."
		 WriteTo-ErrorDebugReport -ErrorRecord $_
		 $Error.Clear()
		 $UserCountdown--
		 continue
		}
	
      #Obtain domain SID for group SID comparisons.
      $UserIdentity = New-Object System.Security.Principal.WindowsIdentity($Principal)
      $Groups = $UserIdentity.get_Groups()
      $DomainSID = $UserIdentity.AccountDomainSid
      $GroupCount = $Groups.Count
	  $GroupDetails = New-Object PSObject
      $AllGroupSIDHistories = @()
      $SecurityGlobalScope  = 0
      $SecurityDomainLocalScope = 0
      $SecurityUniversalInternalScope = 0
      $SecurityUniversalExternalScope = 0
      
      foreach ($GroupSid in $Groups) 
            {     
            $Group = [adsi]"LDAP://<SID=$GroupSid>"
            $GroupType = $Group.groupType
              if ($null -ne $Group.name)
                  {
                  $SIDHistorySids = GetSIDHistorySIDs $Group.name
                  $AllGroupSIDHistories += $SIDHistorySids
                  $GroupName = $Group.name.ToString()
                  
                  #Resolve SIDHistories if possible to give more detail.
                  if ($null -ne $SIDHistorySids)
                        {
                        $GroupSIDHistoryDetails = New-Object PSObject
                        foreach ($GroupSIDHistory in $AllGroupSIDHistories)
                              {
                              #$SIDHistGroup = [adsi]"LDAP://<SID=$GroupSIDHistory>"
                              $SIDHistGroup = New-Object System.Security.Principal.SecurityIdentifier($GroupSIDHistory)
                              $SIDHistGroupName = $SIDHistGroup.Translate([System.Security.Principal.NTAccount])
                              #$SIDHistGroupName = ($SIDHistGroup.displayname).ToString()
                              $GroupSIDHISTString = $GroupName + "--> " + $SIDHistGroupName
                              add-Member -InputObject $GroupSIDHistoryDetails -MemberType NoteProperty -Name $GroupSIDHistory  -Value $GroupSIDHISTString -force
                              }
                        }
                  }
              
            #Count number of security groups in different scopes.
            switch -exact ($GroupType)
                  {"-2147483646"    {
                                    #Domain Global scope
                                    $SecurityGlobalScope++
                                    $GroupNameString = $GroupName + " (" + ($GroupSID.ToString()) + ")"
                                    add-Member -InputObject $GroupDetails -MemberType NoteProperty -Name $GroupNameString  -Value "Domain Global Group"
                                    $GroupNameString = $null
                                    }
                  "-2147483644"     {
                                    #Domain Local scope
                                    $SecurityDomainLocalScope++
                                    $GroupNameString = $GroupName + " (" + ($GroupSID.ToString()) + ")"
                                    Add-Member -InputObject $GroupDetails -MemberType NoteProperty -Name $GroupNameString  -Value "Domain Local Group"
                                    $GroupNameString = $null
                                   }
                  "-2147483640"   {
                                  #Universal scope; must separate local
                                  #domain universal groups from others.
                                  if ($GroupSid -match $DomainSID)
									 {
									 $SecurityUniversalInternalScope++
                                     $GroupNameString = $GroupName + " (" + ($GroupSID.ToString()) + ")"
                                     Add-Member -InputObject $GroupDetails -MemberType NoteProperty -Name  $GroupNameString -Value "Local Universal Group"
                                     $GroupNameString = $null
                                     }
									 else
                                       {
                                       $SecurityUniversalExternalScope++
                                       $GroupNameString =  $GroupName + " (" + ($GroupSID.ToString()) + ")"
                                       Add-Member -InputObject $GroupDetails -MemberType NoteProperty -Name  $GroupNameString -Value "External Universal Group"
                                       $GroupNameString = $null
                                       }
								}

				}

      #Look for claims if OS supports it
      if ($OSBuild -ge 9200)
            {
            $ClaimCounter = 0 #Set to zero in case the script is *gasp* ran twice in the same PS.
            $ClaimsTable = @{}
            $UserIdentity = New-Object System.Security.Principal.WindowsIdentity($Principal)
            if ($null -ne $UserIdentity.Claims)
                  {
                  foreach ($Claim in $UserIdentity.Claims) 
                        {   
                        $ClaimCounter++
                        $LastSlash = $Claim.Type.LastIndexOf('/')
                        $ClaimName = $Claim.Value + " (" + ($Claim.Type.Substring($LastSlash+1)) + ")"
                        $ClaimsTable.Add($ClaimName,$Claim.Value)
                        }
                  }
            }

	}
      #Get user object SIDHistories
      $SIDHistoryResults = GetSIDHistorySIDs $Principal
      $SIDHistoryCounter = $SIDHistoryResults.count
      
      #Resolve SIDHistories if possible to give more detail.
      if ($null -ne $SIDHistoryResults)
            {
            $UserSIDHistoryDetails = New-Object PSObject
            foreach ($SIDHistory in $SIDHistoryResults)
                  {
                  $SIDHist = New-Object System.Security.Principal.SecurityIdentifier($SIDHistory)
                  $SIDHistName = $SIDHist.Translate([System.Security.Principal.NTAccount])
                  add-Member -InputObject $UserSIDHistoryDetails -MemberType NoteProperty -Name $SIDHistName  -Value $SIDHistory -force
                  }
            }
                        
      $GroupSidHistoryCounter = $AllGroupSIDHistories.Count 
      $AllSIDHistories = $SIDHistoryCounter  + $GroupSidHistoryCounter

      #Calculate the current token size.
      $TokenSize = 0 #Set to zero in case the script is *gasp* ran twice in the same PS.
      $TokenSize = 1200 + (40 * ($SecurityDomainLocalScope + $SecurityUniversalExternalScope + $AllSIDHistories + $ClaimCounter)) + (8 * ($SecurityGlobalScope  + $SecurityUniversalInternalScope))
      $DelegatedTokenSize = 2 * (1200 + (40 * ($SecurityDomainLocalScope + $SecurityUniversalExternalScope + $AllSIDHistories + $ClaimCounter)) + (8 * ($SecurityGlobalScope  + $SecurityUniversalInternalScope)))
      
	  #Begin output of details regarding the user into prompt and outfile.
      "`n"  | Out-File $ExportFile -Encoding utf8 -Append 
      "Token Details for user $Principal"  | Out-File $ExportFile -Encoding utf8 -Append 
      "**********************************" | Out-File $ExportFile -Encoding utf8 -Append 
      $Username = $UserIdentity.name
      $PrincipalsDomain = $Username.Split('\')[0]

      $KerbKey = get-item -Path Registry::HKLM\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters
      $MaxTokenSizeValue = $KerbKey.GetValue('MaxTokenSize')
	  if ($null -eq $MaxTokenSizeValue)
	  	{
		if ($OSBuild -lt 9200)
			{$MaxTokenSizeValue = 12000}
		if ($OSBuild -ge 9200)
			{$MaxTokenSizeValue = 48000}
		}


      #Assess OS so we can alert based on default for proper OS version. Windows 8 and Server 2012 allow for a larger token size safely.
      $ProblemDetected = $false
	  $PotentialProblemDetected = $false
      if (($OSBuild -lt 9200) -and (($Tokensize -ge 12000) -or ((($Tokensize -gt $MaxTokenSizeValue) -or ($DelegatedTokenSize -gt $MaxTokenSizeValue)) -and ($null -ne $MaxTokenSizeValue))))
            {
            #Write-Host "Problem detected. The token was too large for consistent authorization. Alter the maximum size per KB http://support.microsoft.com/kb/327825 and consider reducing direct and transitive group memberships." -backgroundcolor "red"
			$ProblemDetected = $true
			}
      elseif (($OSBuild -ge 9200) -and (($Tokensize -ge 48000) -or ((($Tokensize -gt $MaxTokenSizeValue) -or ($DelegatedTokenSize -gt $MaxTokenSizeValue)) -and ($null -ne $MaxTokenSizeValue))))
            {
            #Write-Host "Problem detected. The token was too large for consistent authorization. Alter the maximum size per KB http://support.microsoft.com/kb/327825 and consider reducing direct and transitive group memberships." -backgroundcolor "red"
			$ProblemDetected = $true
			}
      elseif (($OSBuild -lt 9200) -and (($Tokensize -ge 6000) -or ($DelegatedTokenSize -ge 6000)))
            {
            #Write-Host "WARNING: The token was large enough that it may have problems when being used for Kerberos delegation or for access to Active Directory domain controller services. Alter the maximum size per KB http://support.microsoft.com/kb/327825 and consider reducing direct and transitive group memberships." -backgroundcolor "yellow"
            $PotentialProblemDetected = $true
			}
            else
                {
                #Write-Host "Problem not detected." -backgroundcolor "green"
				$ProblemDetected = $false
				$PotentialProblemDetected = $false
                }

	#####Test Root Cause Triggers - COMMENT IN PROD 
	#####$ProblemDetected = $true
	#####$PotentialProblemDetected = $true
		
        $InformationCollected = New-Object PSObject
		Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Date" -Value (Get-Date)
		if (($ProblemDetected -eq $true) -or ($PotentialProblemDetected -eq $true))
			{Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Problem Detected" -Value $true}
			else
			{Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Problem Detected" -Value $false}
		Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "User Name" -Value  $principal
		Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Domain" -Value (($UserIdentity.name).split("\")[0])
		$TokenSizePropertyName = $principal + "'s Estimated Token Size"
		Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name $TokenSizePropertyName -Value $Tokensize
		$DelegTokenSizePropertyName = $principal + "'s Estimated Delegation Token Size"
		Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name $DelegTokenSizePropertyName -Value $DelegatedTokenSize
		Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Domain Local Groups Count" -Value $SecurityDomainLocalScope 
		Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Domain Global Groups Count" -Value $SecurityGlobalScope
		Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Universal Groups Count (Local Domain)" -Value  $SecurityUniversalInternalScope		
		Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Universal Groups Count (External Domain)" -Value $SecurityUniversalExternalScope
		Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "User SidHistory SIDs in Token" -Value $SIDHistoryCounter
		Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Group SidHistory SIDs in Token" -Value $GroupSidHistoryCounter
		if ($null -eq $ClaimCounter)
			{add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Windows Claims in Token" -Value "Not Applicable"}
			else
			{add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Windows Claims in Token" -Value $ClaimCounter}
		if ($OSEmulation -eq "12K")
			{Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Tested Maximum Token Size"  -Value $MaxTokenSize}
		if   ($OSEmulation -eq "48K")
			{Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Tested Maximum Token Size" -Value $MaxTokenSize}
		if (($OSEmulation -ne "12K") -and ($OSEmulation -ne "48K"))
			{Add-Member -InputObject $InformationCollected -MemberType NoteProperty -Name "Tested Maximum Token Size" -Value $Maxtokensizevalue}

		$InformationCollected | Out-File -Encoding UTF8 -Width 500 -FilePath $ExportFile -append
		
        if ($OSBuild -ge 9200)
              {
              "There are $ClaimCounter total claims for the user in the token."  | Out-File $ExportFile -Encoding utf8 -Append 
              "`n"  | Out-File $ExportFile -Encoding utf8 -Append 
              "Claim Details" | Out-File $ExportFile -Encoding utf8 -Append 
              $ClaimsTable.Keys | Out-File $ExportFile -Encoding utf8 -Append 
              }
        "`n" | Out-File $ExportFile -Encoding utf8 -Append 
        "Group Details" | Out-File $ExportFile -Encoding utf8 -Append 
        $GroupDetails | Out-File $ExportFile -encoding utf8 -Width 500 -Append
        "`n"  | Out-File $ExportFile -Encoding utf8 -Append 
        
        "Group SIDHistory Details" | Out-File $ExportFile -Encoding utf8 -Append 
        if ($null -eq $GroupSIDHistoryDetails)
              {"[NONE FOUND]" | Out-File $ExportFile -Encoding utf8 -Append }
              else
              {$GroupSIDHistoryDetails | Out-File $ExportFile -encoding utf8 -Width 500 -Append}
        "`n"  | Out-File $ExportFile -Encoding utf8 -Append 
        "User SIDHistory Details" | Out-File $ExportFile -Encoding utf8 -Append 
        if ($null -eq $UserSIDHistoryDetails)
              {"[NONE FOUND]" | Out-File $ExportFile -Encoding utf8 -Append }
              else
              {$UserSIDHistoryDetails | Out-File $ExportFile -encoding utf8 -Width 500 -Append}
        "`n"  | Out-File $ExportFile -Encoding utf8 -Append 
        
        #insert RC firing here
		if ($ProblemDetected -eq $true)
			{
			#Root cause found
			#Trigger the root cause.
			RC_MaxTokenSize $InformationCollected
			}
			elseif ($PotentialProblemDetected -eq $true)
				{
				RC_MaxTokenSizeWarn $InformationCollected
				}
				else
				{
				#Green light.
				#$RootCauseName = "RC_MaxTokenSize"
				#Update-DiagRootCause -id $RootCauseName -Detected $false
				}
		$UserCountdown--
      }


CollectFiles -filesToCollect $ExportFile  -fileDescription $MaxTokenfileDescription  -sectionDescription $MaxTokenSettingssectionDescription  -renameOutput $false


# SIG # Begin signature block
# MIInoQYJKoZIhvcNAQcCoIInkjCCJ44CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBOjwwfZBywAg0i
# dGAUzyFBnPQHgD+aXHQn2+cQo4KIVKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEICwMhBDC+xn7m8+p8SUCrL++
# BlL5G8NhbeVex46Do95pMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAsbtO6tJisydRr5C5mD1JdbJBFnCpTsilwfVBuvijkDs3EaqUY9Uyk
# xg9CcnO8Z9HjFlulTQ6D23xMIRC+HH9h5FQS9dRXc5js7TZjkdFMa5jnNiD0hrMt
# EogHTV4Wvwo2JU7zebKRSFimJqvEiKUTI8RfI5s53eFQxBsXQS4hLYJqnAEggmk+
# bY846xxMORRmXUR31jsCRFxbhpHt6GmGLy4x3Q1551S33Ptzb34f7jn/LrZMAe51
# 5r4hVGruQ6baq9+M5PVqFoJoSkegud2CckaoC7F9303Yr0ECFfMiQa2I4DZ6Lqr0
# fko1e7fFAFcmaBxj/f5VMBrDck3+6jQloYIXCTCCFwUGCisGAQQBgjcDAwExghb1
# MIIW8QYJKoZIhvcNAQcCoIIW4jCCFt4CAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIJYkMfI5IgQzYmDZ3Bc5H/ePdnMdHJlVRIHL4qYIIDQPAgZi2xAP
# TY4YEzIwMjIwODAxMDc0MjA4LjI2N1owBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
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
# CRABBDAvBgkqhkiG9w0BCQQxIgQgMiFODUhHoWb90cg4pkzmIBLpSLMmndwWfDKR
# ydfbm+gwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAOHK/6sIVgEVSVD3Ar
# vk6OyQKvRxFHKyraUzbN1/AKVzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABqwkJ76tj1OipAAEAAAGrMCIEIHI+RQKHTZ2Id7/ufvKq
# /DQk+dqQy1YkmvsPNzOkpL0iMA0GCSqGSIb3DQEBCwUABIICAEt+9sedDkfsbZ+t
# B+YKCqiJK05GBzw1MTTSbSWducTyse7CXRVWt1U3GsKtBUHMdlTt4O5XWLKptNxY
# 9xw6Yfe6tJQ46CT4vsLla1v30NMxZJtAb9VCvapYGM3I1enorRBASRnEjJa7oWv0
# jW+/bi4Ee/8JogWAKJbG/LJNmSJ3gLP5u7hEDPqsW/CAOoAqT2hNvrm7qk/65n+1
# 7OJR9VLxLRVcJOdzZjS/klMyqL0pOpNRjnHTkdLLCoEntxJkdNI8Q9ttrTkxmvVK
# cyGu1IKIvKreQNnD9HmGkHjB5saoiXR7JAeLtov2cNOP2oWv4KtTSjsm25AhdkKG
# NvusYeEsI4h8kEar8ifC1jmKiRgeDSYrGDeYh2Y9idaBaNAMVyhQBbYda/9LJXG7
# f8jKpjA78xV30bC5alxc7AxtrYf+RPspsZqPdD/cu9R1+dkfNpOA53OANoG/gvrD
# Gg7Dy3bASGTKCBOIMmhfEZBdIIo0mdSFskxm8icoIiF9zDzSF5ZqRtLaDDWZIQ5a
# BQf3ONFCdxBunYO1nbQEwBxxokwxB/HSP+9rxKLQfvQt8clxMRZEQlFEgVhp+wP6
# d6Of6vEBLeMo2PUVPWherj2PZvJU+I0OfbopkaVZIxvD9cJazPekXa1f1RpFvRkn
# esmjLalVqbn2+CyRU0+u6WyfTcWj
# SIG # End signature block
