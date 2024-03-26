#requires -RunAsAdministrator
#requires -Version 5
#requires -Modules SmbShare,NetAdapter

<#	# File: tss_SMB_Fix-SmbBindings.ps1
	# Version: 2022.12.30.0
	
    .SYNOPSIS

    Repairs missing ms_server (SMB Server) bindings for network adapters. Fixes LanmanServer (SMB Server), LanmanWorkstation (SMB Client), NetBT (NetBIOS over TCP/IP) binding balance.

    .DESCRIPTION

    Fix-SvrBinding (the "script") was built in association with KBxxx, which is an issue discovered after the adapter binding for 
    the SMB subsystem in Windows was moved to a new API. The RASMAN (VPN) subsystem has not been migrated, which causes unbalanced
    bindings in the Linkage registry keys for the following services:

       - LanmanServer (Server service, which is the SMB server in Windows)
       - LanmanWorkstation (LanmanWorkstation service, which is the SMB client in Windows)
       - NetBT (NetBIOS over TCP/IP driver, which is needed for legacy SMBv1 over NetBIOS support)

    The script performs the following checks and repairs, when an issue is found on a Windows system.

       Fix 1:
       - Finds network adapter bindings where ms_server (SMB Server) is bound/installed and Enabled == True
       - Compares the list of ms_server bound adapters to the bindings in the Linkage registry keys using the adapter's DeviceID GUID
       - Bindings are automatically generated and added to the registry for any network adapter missing bindings
       - The Server service is then restarted; unless, the noSvrRestart parameter was set when the script was run
       - This fixes currently installed network adapters that should be bound to ms_server, but are not binding at boot due to the bug

       Fix 2:
       - The bindings in each Linkage registry key are scanned and compared
       - Any missing bindings are added to the appropriate Linkage registry value
       - This fix balances the Linkage bindings to prevent future network adapter additions or reinstallations from experiencing the binding bug

    Please note that this does not fix the fundamental code defect in Windows. The code defect will be addressed in a future update to Windows.
    The script is meant to restore functionality to Windows systems affected by the issue.

    IMPORTANT NOTE:

    The script needs to be run after installing a new VPN adapter, or any new VPN-based software that installs a VPN virtual adapter.
    The code defect is caused by the VPN subsystem (RASMAN) using a legacy set of APIs that does not create all the necessary
    bindings needed to bind a network adapter to SMB server. The issue could, therefore, reappear until the code defect is patched.

    .PARAMETER noSvrRestart
    
    Prevents the Server service (LanmanServer, or the SMB Server service) from being restarted after a network adapter bindings is added. The default is FALSE, when the parameter is not present, and the Server service is restarted as a result.

    .EXAMPLE

     .\tss_SMB_Fix-SmbBindings.ps1

    Runs the script normally. The Server service will be restarted if network adapter bindings are added.
    
    .EXAMPLE

     .\tss_SMB_Fix-SmbBindings.ps1 -noSvrRestart

    Runs the script, but will prevent the Server service from being restarted if a network adapter bindings is added.

    .INPUTS

    None.

    .OUTPUTS

    A log file is created on the user desktop.

#>

[CmdletBinding()]
param (
    # The Server service is restarted, by default, when an adapter binding is added/fixed. 
    # Adding this parameter will prevent the Server service restart. 
    # The Server service must be manually restarted, or the system rebooted, for adapter binding changes to take effect when this parameter is set.
    [switch]$noSvrRestart,
	[string]$DataPath = $global:LogFolder,
	[switch]$AcceptEula 
)

$FixSmbBindingsVer = "2022.12.30.0"			# dated version number
if ([String]::IsNullOrEmpty($DataPath)) {$DataPath="c:\MS_DATA"}

############################
###                      ###
###     DECLARATIONS     ###
###                      ###
############################
#region

# set logging options
$script:dataPath = $DataPath	#"$env:USERPROFILE\Desktop"
$script:logName = "$env:ComputerName`_Fix_SmbBindings_$(Get-Date -format "yyyyMMdd_HHmmss")`.log"

# the three registry paths to search
[string[]]$linkagePaths =   'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Linkage',
                            'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Linkage',
                            'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Linkage'

# initial order and list of linkage values to test against
[string[]]$testOrder = "Bind","Export","Route"

#endregion

############################
###                      ###
###       FUNCTIONS      ###
###                      ###
############################
#region 

# FUNCTION: Get-TimeStamp
# PURPOSE:  Returns a timestamp string

function Get-TimeStamp 
{
    return "$(Get-Date -format "yyyyMMdd_HHmmss_ffff")"
} # end Get-TimeStamp


# FUNCTION: Write-Log
# PURPOSE:  Writes script information to a log file and to the screen when -Verbose is set.

function Write-Log {
    param ([string]$text, [switch]$tee = $false, [string]$foreColor = $null)

    $foreColors = "Black","Blue","Cyan","DarkBlue","DarkCyan","DarkGray","DarkGreen","DarkMagenta","DarkRed","DarkYellow","Gray","Green","Magenta","Red","White","Yellow"
	$LogFilePath = "$script:dataPath\$script:logName"
	
    # check the log file, create if missing
    $isPath = Test-Path $LogFilePath
    if (!$isPath) {
        "$(Get-TimeStamp): Log started" | Out-File $LogFilePath -Force
        "$(Get-TimeStamp): Local log file path: $($LogFilePath)" | Out-File $LogFilePath -Force
        Write-Verbose "Local log file path: $($LogFilePath)"
    }
    
    # write to log
    "$(Get-TimeStamp): $text" | Out-File $LogFilePath -Append

    # write text verbosely
    Write-Verbose $text

    if ($tee)
    {
        # make sure the foreground color is valid
        if ($foreColors -contains $foreColor -and $foreColor)
        {
            Write-Host -ForegroundColor $foreColor $text
        } else {
            Write-Host $text
        }        
    }
} # end Write-Log


# FUNCTION: Update-LinkBinding
# PURPOSE:  Updates a Linkage binding list, given a path path, list name (Bind, Export, Route), and the binding(s) to add.

function Update-LinkBinding
{
    param ( [string]$regPath,
            [string[]]$arrAdd, 
            [string]$listName)
    
    Write-Log "Updating linakge binding:`nPath: $regPath`nAdditions: $($arrAdd | Out-String)`nList: $listName"
    
    # get the route list
    [string[]]$routeList = (Get-ItemProperty -Path $regPath -Name $listName)."$listName"

    foreach ($strAdd in $arrAdd)
    {
        # update the string[]
        $routeList += $strAdd
    }

    # update the registry
    try {
        Set-ItemProperty -Path $regPath -Name $listName -Value $routeList -ErrorAction Stop    
    }
    catch {
        Write-Log "ERROR: Could not update $regPath\$listName`: $($Error[0].ToString())"
        return $false
    }

    
    # check that the add was successful
    $routeList = (Get-ItemProperty -Path $regPath -Name $listName)."$listName"
    if ($routeList -contains $strAdd)
    {
        # hurray, it worked!
        Write-Log "Updates were successful."
        return $true
    } else {
        # oops, something done broke
        Write-Log "Updates failed for an unknown reason."
        return $false
    }

    # if we get here then something went horribly wrong and false is returned
    return $false
} #end Update-LinkBinding


# FUNCTION: Add-NetBindLink
# PURPOSE:  Adds network adapter bindings to a Bind linkage list, give the Linkage reg path, adapter GUID, and list name (which should be Bind)
function Add-NetBindLink
{
    param ($regPath, $guid, $listName)
    
    Write-Log "Building new bindings for $guid in $regPath\$listName`."

    # get the service
    $serviceName = $regPath.Split('\')[-2]

    if ($serviceName -eq "NetBT")
    {
        [string[]]$arrAdd = "\Device\Tcpip6_$guid",
                            "\Device\Tcpip_$guid"
    } else {
        [string[]]$arrAdd = "\Device\Tcpip_$guid",
                            "\Device\NetBT_Tcpip_$guid",
                            "\Device\Tcpip6_$guid",
                            "\Device\NetBT_Tcpip6_$guid"
    }
    
    return (Update-LinkBinding -regPath $regPath -arrAdd $arrAdd -listName $listName)
} #end Add-NetBindLink


# FUNCTION: Add-NetExportLink
# PURPOSE:  Adds network adapter bindings to a Bind linkage list, give the Linkage reg path, adapter GUID, and list name (which should be Export)

function Add-NetExportLink
{
    param ($regPath, $guid, $listName)

    Write-Log "Building new bindings for $guid in $regPath\$listName`."

    # get the service
    $serviceName = $regPath.Split('\')[-2]

    if ($serviceName -eq "NetBT")
    {
        [string[]]$arrAdd = "\Device\$serviceName`_Tcpip6_$guid",
                            "\Device\$serviceName`_Tcpip_$guid"
    } else {
        [string[]]$arrAdd = "\Device\$serviceName`_Tcpip_$guid",
                            "\Device\$serviceName`_NetBT_Tcpip_$guid",
                            "\Device\$serviceName`_Tcpip6_$guid",
                            "\Device\$serviceName`_NetBT_Tcpip6_$guid"
    }
    
    return (Update-LinkBinding -regPath $regPath -arrAdd $arrAdd -listName $listName)
} #end Add-NetExportLink


# FUNCTION: Add-NetRouteLink
# PURPOSE:  Adds network adapter bindings to a Bind linkage list, give the Linkage reg path, adapter GUID, and list name (which should be Route)

function Add-NetRouteLink
{
    param ($regPath, $guid, $listName)

    Write-Log "Building new bindings for $guid in $regPath\$listName`."

    # get the service
    $serviceName = $regPath.Split('\')[-2]

    if ($serviceName -eq "NetBT")
    {
        [string[]]$arrAdd = "`"Tcpip6`" `"$guid`"",
                            "`"Tcpip`" `"$guid`""
    } else {
        [string[]]$arrAdd = "`"Tcpip`" `"$guid`"",
                            "`"NetBT`" `"Tcpip`" `"$guid`"",
                            "`"Tcpip6`" `"$guid`"",
                            "`"NetBT`" `"Tcpip6`" `"$guid`""
    }
    
    return (Update-LinkBinding -regPath $regPath -arrAdd $arrAdd -listName $listName)
} #end Add-NetRouteLink


# FUNCTION: Get-Bind2Obj 
# PURPOSE:  Converts the Bind linkage lists into a custome set of PSObjects used to compare and update linkage lists

function Get-Bind2Obj 
{
    param ($bindObj)

    $results = @()

    foreach ($obj in $bindObj)
    {
        if ($obj -match '_')
        {
            $guid = $obj.Split('_')[-1]
            $provider = $obj.Split('\')[-1].Split('{')[0]
            $comparand = "$provider$guid"
        } else {
            $guid = $provider = $comparand = $obj.Split('\')[-1]
        }

        <#
            Each object contains the structure needed to compare, update, or diagnose binding issues.

            List = The list name where the object was created from
            FullName = The unmodified binding string
            Guid = The adapter DeviceID Guid associated with the binding, or the network provider name when no GUID is listed
            Proiver = Protocol(s) in the binding, in a common format since each list has a unique format. _<prot>[_<prot>]_  Examples: _Tcpip_, _NetBT_Tcpip6_
            Comparand = A combination of provider and GUID that makes the binding unique, but in a common format: <provider><guid>, NetbiosSmb
        #>
        
        $tmpObj = [PSCustomObject]@{
            List = "Bind"
            FullName = $obj
            Guid = $guid
            Provider = $provider
            Comparand = $comparand
        }
        $results  += $tmpObj
    }

    return $results 
} #end Get-Bind2Obj 


# FUNCTION: Get-Export2Obj 
# PURPOSE:  Converts the Export linkage lists into a custome set of PSObjects used to compare and update linkage lists

function Get-Export2Obj 
{
    param ($exportObj,$linkName)

    $results = @()

    foreach ($obj in $exportObj)
    {
        if ($obj -notmatch 'NetbiosSmb')
        {
            $guid = $obj.Split('_')[-1]
            
            switch -Regex ($obj)
            {
                "^.*NetBT.*$" {
                    $provider = $obj.Split('\')[-1].Split('{')[0] -replace "NetBT_",""        
                }

                "^.*LanmanServer.*$" {
                    $provider = $obj.Split('\')[-1].Split('{')[0] -replace "LanmanServer_",""        
                }

                "^.*LanmanWorkstation_.*$" {
                    $provider = $obj.Split('\')[-1].Split('{')[0] -replace "LanmanWorkstation_",""        
                }

                default {
                    $provider = $obj.Split('\')[-1].Split('{')[0]
                }
            }
            
            $comparand = "$provider$guid"
        } else {
            switch -Regex ($obj)
            {
                "^.*NetBT.*$" {
                    $guid = $provider = $comparand = $obj.Split('\')[-1].Split('{')[0] -replace "NetBT_",""        
                }

                "^.*LanmanServer.*$" {
                    $guid = $provider = $comparand = $obj.Split('\')[-1].Split('{')[0] -replace "LanmanServer_",""        
                }

                "^.*LanmanWorkstation_.*$" {
                    $guid = $provider = $comparand = $obj.Split('\')[-1].Split('{')[0] -replace "LanmanWorkstation_",""        
                }

                default {
                    $provider = $obj.Split('\')[-1].Split('{')[0]
                }
            }
        }

        <#
            Each object contains the structure needed to compare, update, or diagnose binding issues.

            List = The list name where the object was created from
            FullName = The unmodified binding string
            Guid = The adapter DeviceID Guid associated with the binding, or the network provider name when no GUID is listed
            Proiver = Protocol(s) in the binding, in a common format since each list has a unique format. _<prot>[_<prot>]_  Examples: _Tcpip_, _NetBT_Tcpip6_
            Comparand = A combination of provider and GUID that makes the binding unique, but in a common format: <provider><guid>, NetbiosSmb
        #>

        $tmpObj = [PSCustomObject]@{
            List = "Export"
            FullName = $obj
            Guid = $guid
            Provider = $provider
            Comparand = $comparand
        }
        $results += $tmpObj
    }

    return $results 
} #end Get-Export2Obj


# FUNCTION: Get-Route2Obj 
# PURPOSE:  Converts the Route linkage lists into a custome set of PSObjects used to compare and update linkage lists

function Get-Route2Obj 
{
    param ($routeObj)

    # stores the resulting object array
    $results = @()

    # loop through each Route binding
    foreach ($obj in $routeObj)
    {
        # bindings with a { have a GUID, and need parsing
        if ($obj -match '{')
        {
            # the last object is the DeviceID GUID
            $guid = $obj.Split(' ')[-1].Trim('"')
            $values = $obj.Split(' ')

            # generate a common provider string
            $provider = ($values | Where-Object {$_ -notmatch $guid} | ForEach-Object {$_.Trim('"')}) -join "_"
            $provider = "$provider`_"

            # create the comparand
            $comparand = ($obj.Split(' ') | ForEach-Object {$_.Trim('"')}) -join '_'

        } else {
            $guid = $provider = $comparand = $obj.Trim('"')
        }

        <#
            Each object contains the structure needed to compare, update, or diagnose binding issues.

            List = The list name where the object was created from
            FullName = The unmodified binding string
            Guid = The adapter DeviceID Guid associated with the binding, or the network provider name when no GUID is listed
            Proiver = Protocol(s) in the binding, in a common format since each list has a unique format. _<prot>[_<prot>]_  Examples: _Tcpip_, _NetBT_Tcpip6_
            Comparand = A combination of provider and GUID that makes the binding unique, but in a common format: <provider><guid>, NetbiosSmb
        #>

        $tmpObj = [PSCustomObject]@{
            List = "Route"
            FullName = $obj
            Guid = $guid
            Provider = $provider
            Comparand = $comparand
        }
        $results += $tmpObj
    }

    # return the array of objects
    return $results 
} #end Get-Route2Obj


# FUNCTION: Add-BindLinkage
# PURPOSE:  Adds a missing binding to a Bind Linkage list, given a path and a difference object from Get-Link

function Add-BindLinkage
{
    param ($regPath, $diffObj)

    ## generate the string to add
    if ($diffObj.MissingObj.Provider -eq 'NetbiosSmb')
    {
        $strAdd = "\Device\NetbiosSmb"
    } else {
        $strAdd = "\Device\$($diffObj.MissingObj.Comparand)"
    }
    
    # update the binding and return the result
    return (Update-LinkBinding -regPath $regPath -arrAdd $strAdd -listName "$($diffObj.MissingFrom)")
} #end Add-BindLinkage


# FUNCTION: Add-ExportLinkage
# PURPOSE:  Adds a missing binding to a Export Linkage list, given a path and a difference object from Get-Link

function Add-ExportLinkage
{
    param ($regPath, $diffObj)

    ## generate the string to add
    # get the service
    $serviceName = $regPath.Split('\')[-2]

    if ($diffObj.MissingObj.Provider -eq 'NetbiosSmb')
    {
        $strAdd = "\Device\$serviceName`_NetbiosSmb"
    } else {
        $strAdd = "\Device\$serviceName`_$($diffObj.MissingObj.Comparand)"
    }
    
    # update the binding and return the result
    return (Update-LinkBinding -regPath $regPath -arrAdd $strAdd -listName "$($diffObj.MissingFrom)")
} #end Add-ExportLinkage


# FUNCTION: Add-RouteLinkage
# PURPOSE:  Adds a missing binding to a Route Linkage list, given a path and a difference object from Get-Link

function Add-RouteLinkage
{
    param ($regPath, $diffObj)

    ## generate the string to add
    if ($diffObj.MissingObj.Provider -eq 'NetbiosSmb')
    {
        $strAdd = '"NetbiosSmb"'
    } else {
        $tmpProvider = ($diffObj.MissingObj.Provider.Split('_') | Where-Object {$_ -ne ""} | ForEach-Object {"`"$_`""}) -join ' '
        $strAdd = "$tmpProvider `"$($diffObj.MissingObj.Guid)`""
        $strAdd = $strAdd.Trim(" ")
    }

    # update the binding and return the result
    return (Update-LinkBinding -regPath $regPath -arrAdd $strAdd -listName "$($diffObj.MissingFrom)")
} #end Add-RouteLinkage


# FUNCTION: Get-Link 
# PURPOSE:  Gets a difference object for a Linkage list, given a reg path to a Linkage key.

function Get-Link 
{
    param ($link)

    # get the type of linkage value
    $linkName = $link | Get-Member -Type NoteProperty | Where-Object Name -notmatch "^PS.*$" | ForEach-Object {$_.Name}
    
    # call the appropriate Get-Bind2xxxxx function and return the result
    switch ($linkName) {
        "bind" {  
            # parse the bind list
            return (Get-Bind2Obj $link."$linkName" $linkName)

            break
        }

        "Export" {
            # parse the export list
            return (Get-Export2Obj $link."$linkName" $linkName)

            break
        }

        "Route" {
            # parse the route list
            return (Get-Route2Obj $link."$linkName" $linkName)

            break
        }
        default {
            Write-Host "Unknown link type: $linkName" 
            return $false
        }
    }

    # just in case something went wrong
    return $false
} #end Get-Link 


# FUNCTION: Get-ListDiff
# PURPOSE:  Compares link1 to link2, and returns a list of missing bindings that are not in link2 but are in link1. Accepts two difference objects from Get-Link.

function Get-ListDiff
{
    param ($link1, $link2)

    # convert the raw value to objects
    $list1 = Get-Link $link1
    $list2 = Get-Link $link2

    # stores a list of differences
    $diffList = @()

    # search through each value in list1 and see if it exists in list 2
    foreach ($item in $list1)
    {
        if ($list2.Comparand -notcontains $item.Comparand)
        {
            # add to diffList
            $tmpObj = [PSCustomObject]@{
                MissingFrom = $($list2[0].List)
                MissingObj = $item
            }

            $diffList += $tmpObj
        }
    }

    # return the diffList, if populated; otherwise, return $false
    if ($diffList)
    {
        #Write-Host "`nSource list:$($list2 | Format-List | Out-String)"
        return $diffList
    } else {
        return $false
    }
} #end Get-ListDiff

function ShowEULAIfNeeded($toolName, $mode) {
	$eulaRegPath = "HKCU:Software\Microsoft\CESDiagnosticTools"
	$eulaAccepted = "No"
	$eulaValue = $toolName + " EULA Accepted"
	if (Test-Path $eulaRegPath) {
		$eulaRegKey = Get-Item $eulaRegPath
		$eulaAccepted = $eulaRegKey.GetValue($eulaValue, "No")
	}
	else {
		$eulaRegKey = New-Item $eulaRegPath
	}
	if ($mode -eq 2) {
		# silent accept
		$eulaAccepted = "Yes"
		$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
	}
	else {
		if ($eulaAccepted -eq "No") {
			$eulaAccepted = ShowEULAPopup($mode)
			if ($eulaAccepted -eq [System.Windows.Forms.DialogResult]::Yes) {
				$eulaAccepted = "Yes"
				$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
			}
		}
	}
	return $eulaAccepted
}

#endregion FUNCTIONS


############################
###                      ###
###         MAIN         ###
###                      ###
############################
#  region MAIN   =====================================

## EULA
# Show EULA if needed.
If ($AcceptEULA.IsPresent) {
	$eulaAccepted = ShowEULAIfNeeded "SMB_Fix-SmbBindings" 2  # Silent accept mode.
}
Else {
	$eulaAccepted = ShowEULAIfNeeded "SMB_Fix-SmbBindings" 0  # Show EULA popup at first run.
}
if ($eulaAccepted -eq "No") {
	Write-Error "EULA not accepted, exiting!"
	exit -1
}

##### NIC BINDING #####
#region

<#
if ($AcceptEula) {
  Write-Log "AcceptEula switch specified, silently continuing"
  $eulaAccepted = ShowEULAIfNeeded "SMB_Fix-SmbBindings" 2
} else {
  $eulaAccepted = ShowEULAIfNeeded "SMB_Fix-SmbBindings" 0
  if($eulaAccepted -ne "Yes")
   {
     Write-Log "EULA declined, exiting"
     exit
   }
 }
Write-Log "EULA accepted, continuing"
#>

# get all net adapters, excluding adapters that are not bound to ms_server (Enabled = False)
$svrBingings = Get-NetAdapterBinding -ComponentID ms_server | Where-Object Enabled
$srvNetAdptrs =  Get-NetAdapter | Where-Object {$svrBingings.InterfaceAlias -contains $_.InterfaceAlias}
Write-Log "Net adapters bound to ms_server:`n$(($srvNetAdptrs | Sort-Object | Select-Object Name,InterfaceDescription,InterfaceAlias,InterfaceIndex,DeviceID) | Out-String)`n"

# get all net adapters, excluding adapters that are not bound to ms_msclient (Enabled = False). This is currently for monitoring purposes only.
$cliBingings = Get-NetAdapterBinding -ComponentID ms_msclient | Where-Object Enabled
$cliNetAdptrs =  Get-NetAdapter | Where-Object {$cliBingings.InterfaceAlias -contains $_.InterfaceAlias}
Write-Log "Net adapters bound to ms_msclient:`n$(($cliNetAdptrs | Sort-Object | Select-Object Name,InterfaceDescription,InterfaceAlias,InterfaceIndex,DeviceID) | Out-String)`n"

Write-Log "Checking bindings for net adapters." -tee -foreColor Green

# monitors whether a link was updated. Needed for logging and restarting Server.
$wasNicBindUpdated = $false

# lopp through each Linkage key location
foreach ($link in $linkagePaths)
{
    Write-Log "Testing NICs against: $link" -foreColor Yellow -tee

    # backup the reg value
    $backupReg = Get-Item $link
    $serviceName = $link.Split('\')[-2]
    $backupTimeStamp = Get-TimeStamp
    reg export $($backupReg.Name) "$PSScriptRoot\$serviceName`_$backupTimeStamp`.reg" /y | Out-Null

    # verify that the backup completed in a manner that is compatible with non-English localizations of Windows
    $isRegBackup = Get-Item "$PSScriptRoot\$serviceName`_$backupTimeStamp`.reg" -EA SilentlyContinue
    #create a regex pattern for the link. With -replace, the matching pattern is a regex expression, the replacement string is literal, so -replace '\\','\\' replaces a single backslash (\) with the double backslash (\\) needed for the select-string match later on
    [regex]$regLink = "^\[$(($link -replace "HKLM:", "HKEY_LOCAL_MACHINE") -replace '\\','\\')\]$"

    # make sure the file exists
    if (-not $isRegBackup)
    {
        Write-Log "CRITICAL: Failed to backup the $serviceName registry key." -tee -foreColor Red
        exit
    } 
    # 0-2 bytes is the size of an empty TXT doc, fail if it seems empty
    elseif ($isRegBackup.Length -le 2) 
    {
        Write-Log "CRITICAL: Failed to write data to the $serviceName registry file: $PSScriptRoot\$serviceName`_$backupTimeStamp`.reg" -tee -foreColor Red
        exit
    }
    # make sure the right link is in the content of the reg file. Key names are not localized so this is a safe operation.
    elseif (-NOT (Get-Content $isRegBackup | Select-String $regLink))
    {
        Write-Log "CRITICAL: Could not validate the $serviceName registry backup: $PSScriptRoot\$serviceName`_$backupTimeStamp`.reg" -tee -foreColor Red
        exit
    }
    

    # loop through each list in the testOrder
    foreach ($list in $testOrder)
    {
        # get the linkage list        
        $bndLinkage = Get-ItemProperty -Path $link -Name $list
        
        Write-Log "All bindings for $list`:`n`r$(($bndLinkage."$list" | Sort-Object) -join "`n`r")`n`r"

        # loop through list of adapters to find missing bindings
        foreach ($adapter in $srvNetAdptrs)
        {
            Write-Log "Checking bindings for $($adapter.Name) `n`rDescription: $($adapter.InterfaceDescription) `n`rGUID: $($adapter.DeviceID) `n`rStatus: $($adapter.Status)"
            
            # this looks for the DeviceID GUID in the linkage list
            $tmpBnd = $bndLinkage."$list" | Where-Object {$_ -match $adapter.DeviceID}

            # no results means the DeviceID GUID is missing and needs to be added...
            if (-not $tmpBnd)
            {
                Write-Log "$($adapter.Name) was not found on the $serviceName $list list.`n" -tee -foreColor Red

                # this switch is used to make the correct function call, based on which linkage list is being tested
                switch ($list)
                {
                    "Export" {
                        Write-Log "Adding Export link(s) for $($adapter.Name)."
                        $result = Add-NetExportLink -regPath $link -guid "$($adapter.DeviceID)" -listName $list

                        break
                    }

                    "Route" {
                        Write-Log "Adding Route link(s) for $($adapter.Name)."
                        $result = Add-NetRouteLink -regPath $link -guid "$($adapter.DeviceID)" -listName $list

                        break
                    }

                    "Bind" {
                        Write-Log "Adding Bind link(s) for $($adapter.Name)."
                        $result = Add-NetBindLink -regPath $link -guid "$($adapter.DeviceID)" -listName $list

                        break
                    }

                    default { Write-Log "`nSomething didn't work right...time to bail."; exit }
                } #end switch list

                # writes logging based on the result of adding the missing binding
                if ($result)
                {
                    Write-Log "Successfully added link(s) for $($adapter.Name) in $list" -tee -foreColor Green
                    # set wasNicBindUpdated to true so the Server service can be restarted
                    $wasNicBindUpdated = $true
                } else {
                    Write-Log "ERROR: Could not add link(s) for $($adapter.Name) in $list." -tee -foreColor Red
                }
            # ... a tmpBnd result means the binding is on the list
            } else
            {
                Write-Log "$($adapter.Name) was found on the $serviceName $list list.`n"
            } #end if (-not $tmpBnd)
        } #end adapter-srvNetAdptrs foreach
    } #end list-TestOrder foreach
} #end link-Linkage foreach

# check whether the Server service needs to be restarted
if ($wasNicBindUpdated)
{
    # test whether noSvrRestart was set and log accordingly
    if (-not $noSvrRestart)
    {
        Write-Log "Restarting the Server service."
        Restart-Service LanmanServer -Force
    } else {
        Write-Log "`nnoSvrRestart was set from the command line and a network adapter binding was added. The Server service was not restarted.`n`nThe server service must be manually restarted, or the system rebooted, for the fix to take effect.`n`n" -tee -foreColor Yellow
    }
} else {
    Write-Log "There were no missing network adapter bindings found - no modifications were necessary." -tee -foreColor Green
}
#endregion


##### RESYNC LINKAGE #####
#region

### make sure all the linkage bindings are synced ###

Write-Log "Testing whether the linkage lists are balanced." -tee -foreColor Yellow

# was a link updated? needed for logging purposes. A reboot is not needed after linkage bindings are balanced.
[bool]$wasLinkUpdated = $false

# loop through all Linkage paths
foreach ($link in $linkagePaths)
{
    Write-Log "`nValidating linkage lists for: $link" -ForegroundColor Green
    
    # loop throug the three binding lists
    foreach ($list in $testOrder)
    {
        #Write-Host "`nTest order:`n$($testOrder | fl | out-string)"
        for($i = 1; $i -lt $testOrder.Count; $i++)
        {
            # get the linkage values of the first list in testOrder, and then either the second or last list
            $sourceList = Get-ItemProperty -Path $link -Name $list
            $destList = Get-ItemProperty -Path $link -Name $testOrder[$i]

            Write-Log "`nComparing $list to $($testOrder[$i])"

            # look for differences in the two lists
            $difference = Get-ListDiff $sourceList $destList

            # add missing bindings when differences are found
            if ($difference)
            {
                Write-Log "`nThe following differences between $list and $($testOrder[$i]) were found:`n$($difference | Format-List | Out-String)" -tee

                # there could be more than one difference, so loop through all of them
                foreach ($diff in $difference)
                {
                    # call the appropriae function to add the missing binding, bases on the MissingFrom value in the difference object
                    switch ($diff.MissingFrom)
                    {
                        "Export" {
                            Write-Log "Updating Export link."
                            $result = Add-ExportLinkage $link $diff

                            break
                        }

                        "Route" {
                            Write-Log "Updating Route link."
                            $result = Add-RouteLinkage $link $diff

                            break
                        }

                        "Bind" {
                            Write-Log "Updating Bind link."
                            $result = Add-BindLinkage $link $diff

                            break
                        }

                        default { Write-Log "`nSomething didn't work right...time to bail."; exit }
                    } #end switch ($diff.MissingFrom)

                    # log based on results
                    if ($result)
                    {
                        Write-Log "Updated $($diff.MissingFrom) link successfully." -tee -foreColor Green
                        $wasLinkUpdated = $true
                    } else {
                        Write-Log "ERROR: Updating $($diff.MissingFrom) link failed." -tee -foreColor Red
                    }
                } #end foreach ($diff in $difference)
            } else {
                Write-Log "`nNo differences between $list and $($testOrder[$i]) were found"
            }
        } #end for($i = 1; $i -lt $testOrder.Count; $i++)

        ## Rotate the test order.
        ## This algorithm modifies the testOrder so that all linkage list combinations for each Linkage key is tested without duplication.
        # put the middle list into the first (0th) position in tmpTestOrder
        [string[]]$tmpTestOrder = $testOrder[1]
        
        # this loop puts the last testOrder item second and the first testOrder time last in the tmpTestOrder array
        for($i = 2; $i -le $testOrder.Count; $i++)
        {
            if ($i -eq $testOrder.Count)
            {
                $x = 0
            } else {
                $x = $i
            }

            $tmpTestOrder += $testOrder[$x]
        }

        # make tmpTestOrder the new testOrder
        $testOrder = $tmpTestOrder

        #set tmpTestOrder to null
        $tmpTestOrder = $null
    } #end foreach ($list in $testOrder)
} #end foreach ($link in $linkagePaths)

# log to console that there were no binding issues if wasLinkUpdated is still false
if (-not $wasLinkUpdated)
{
    Write-Log "System linkage is balanced - no modifications were necessary." -tee -foreColor Green
}

#endregion

# New final step. 
# We use PowerShell to "wiggle" the binding. RS2 seems to lose the binding on reboot unless PowerShell is used to disable/enable the binding.
# This code is run only when there was a need to fix a NIC binding, and after everything has been balanced/fixed.
if ($wasNicBindUpdated)
{
    Write-Log "Resetting the ms_server bindings with PowerShell to ensure the changes work after a reboot."
    
    # loop through list of adapters to find missing bindings
    foreach ($adapter in $srvNetAdptrs)
    {
        Disable-NetAdapterBinding -Name $($adapter.Name) -ComponentID ms_server -PassThru | Out-String | Write-Log
        Enable-NetAdapterBinding -Name $($adapter.Name) -ComponentID ms_server -PassThru | Out-String | Write-Log
    }
}

Write-Log "=> Please upload $script:dataPath\$script:logName to our upload site (MS workspace) for analysis." -tee -foreColor Cyan


# SIG # Begin signature block
# MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD1A6lfGNxnOaNk
# EC/ZnjFSsJFoHV6y2MdCY+wKReZfZaCCDYUwggYDMIID66ADAgECAhMzAAADTU6R
# phoosHiPAAAAAANNMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI4WhcNMjQwMzE0MTg0MzI4WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDUKPcKGVa6cboGQU03ONbUKyl4WpH6Q2Xo9cP3RhXTOa6C6THltd2RfnjlUQG+
# Mwoy93iGmGKEMF/jyO2XdiwMP427j90C/PMY/d5vY31sx+udtbif7GCJ7jJ1vLzd
# j28zV4r0FGG6yEv+tUNelTIsFmmSb0FUiJtU4r5sfCThvg8dI/F9Hh6xMZoVti+k
# bVla+hlG8bf4s00VTw4uAZhjGTFCYFRytKJ3/mteg2qnwvHDOgV7QSdV5dWdd0+x
# zcuG0qgd3oCCAjH8ZmjmowkHUe4dUmbcZfXsgWlOfc6DG7JS+DeJak1DvabamYqH
# g1AUeZ0+skpkwrKwXTFwBRltAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUId2Img2Sp05U6XI04jli2KohL+8w
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzUwMDUxNzAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# ACMET8WuzLrDwexuTUZe9v2xrW8WGUPRQVmyJ1b/BzKYBZ5aU4Qvh5LzZe9jOExD
# YUlKb/Y73lqIIfUcEO/6W3b+7t1P9m9M1xPrZv5cfnSCguooPDq4rQe/iCdNDwHT
# 6XYW6yetxTJMOo4tUDbSS0YiZr7Mab2wkjgNFa0jRFheS9daTS1oJ/z5bNlGinxq
# 2v8azSP/GcH/t8eTrHQfcax3WbPELoGHIbryrSUaOCphsnCNUqUN5FbEMlat5MuY
# 94rGMJnq1IEd6S8ngK6C8E9SWpGEO3NDa0NlAViorpGfI0NYIbdynyOB846aWAjN
# fgThIcdzdWFvAl/6ktWXLETn8u/lYQyWGmul3yz+w06puIPD9p4KPiWBkCesKDHv
# XLrT3BbLZ8dKqSOV8DtzLFAfc9qAsNiG8EoathluJBsbyFbpebadKlErFidAX8KE
# usk8htHqiSkNxydamL/tKfx3V/vDAoQE59ysv4r3pE+zdyfMairvkFNNw7cPn1kH
# Gcww9dFSY2QwAxhMzmoM0G+M+YvBnBu5wjfxNrMRilRbxM6Cj9hKFh0YTwba6M7z
# ntHHpX3d+nabjFm/TnMRROOgIXJzYbzKKaO2g1kWeyG2QtvIR147zlrbQD4X10Ab
# rRg9CpwW7xYxywezj+iNAc+QmFzR94dzJkEPUSCJPsTFMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGXMwghlvAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAANNTpGmGiiweI8AAAAA
# A00wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINHa
# doU3FGtezQ5k3MnA64GkCVkPv9Ndk7T/zfR3Rw4lMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEA0FVH9td42PtMQTXxX+tB6v56LaLimzR0ku7g
# kAx/WwEf5RciRfRhJjdQZxDZjM4TLbSurl5o/eLUtS7E4WIc4I5fuATT/4eqwmsa
# uuxeS/2DBq5cKEcXZLod/RAepm4hyIylMlGOIaZACRtHH1khRkNR4BU8ELUHL+wH
# PFJAWAqcZlDuR1CDkSKhFgTSVz4r1V9Sh0pxtpmKRjuC4+i/Gxzzq+hOswTNMzR+
# gGFdoNJ0lOuBNhfHlAPvrJI5nyJMIjR3Dum+Rx5VjgnstxNJb9PBnl1XTjSY4cVU
# FSeY68salYDw9og4/KFJSvC+hhSx4cMEv9yMsz9e7P+PmQwz36GCFv0wghb5Bgor
# BgEEAYI3AwMBMYIW6TCCFuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCB+tZpv9AAeJ5+JKpISlQc7B5xyYw37VALp
# C3VNzHY2bQIGZGzRLuVBGBMyMDIzMDYwNjExNDU1NS41MTVaMASAAgH0oIHQpIHN
# MIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjpENkJELUUzRTctMTY4NTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEVQwggcMMIIE9KADAgECAhMzAAABx/sAoEpb8ifcAAEA
# AAHHMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMTEwNDE5MDEzNVoXDTI0MDIwMjE5MDEzNVowgcoxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQ2QkQtRTNF
# Ny0xNjg1MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr0LcVtnatNFMBrQTtG9P8ISA
# PyyGmxNfhEzaOVlt088pBUFAIasmN/eOijE6Ucaf3c2bVnN/02ih0smSqYkm5P3Z
# wU7ZW202b6cPDJjXcrjJj0qfnuccBtE3WU0vZ8CiQD7qrKxeF8YBNcS+PVtvsqhd
# 5YW6AwhWqhjw1mYuLetF5b6aPif/3RzlyqG3SV7QPiSJends7gG435Rsy1HJ4Xnq
# ztOJR41I0j3EQ05JMF5QNRi7kT6vXTT+MHVj27FVQ7bef/U+2EAbFj2X2AOWbvgl
# YaYnM3m/I/OWDHUgGw8KIdsDh3W1eusnF2D7oenGgtahs+S1G5Uolf5ESg/9Z+38
# rhQwLgokY5k6p8k5arYWtszdJK6JiIRl843H74k7+QqlT2LbAQPq8ivQv0gdclW2
# aJun1KrW+v52R3vAHCOtbUmxvD1eNGHqGqLagtlq9UFXKXuXnqXJqruCYmfwdFMD
# 0UP6ii1lFdeKL87PdjdAwyCiVcCEoLnvDzyvjNjxtkTdz6R4yF1N/X4PSQH4Flgs
# lyBIXggaSlPtvPuxAtuac/ITj4k0IRShGiYLBM2Dw6oesLOoxe07OUPO+qXXOcJM
# VHhE0MlhhnxfN2B1JWFPWwQ6ooWiqAOQDqzcDx+79shxA1Cx0K70eOBplMog27gY
# oLpBv7nRz4tHqoTyvA0CAwEAAaOCATYwggEyMB0GA1UdDgQWBBQFUNLdHD7BAF/V
# U/X/eEHLiUSSIDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
# KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4ICAQDQy5c8ogP0y8xAsLVca07wWy1mT+nqYgAFnz2972kN
# O+KJ7AE4f+SVbvOnkeeuOPq3xc+6TS8g3FuKKYEwYqvnRHxX58tjlscZsZeKnu7f
# GNUlpNT9bOQFHWALURuoXp8TLHhxj3PEq9jzFYBP2YNMLol70ojY1qpze3nMMJfp
# durdBBpaOLlJmRNTLhxd+RJGJQbY1XAcx6p/FigwqBasSDUxp+0yFPEBB9uBE3KI
# LAtq6fczGp4EMeon6YmkyCGAtXMKDFQQgdP/ITe7VghAVbPTVlP3hY1dFgc+t8YK
# 2obFSFVKslkASATDHulCMht+WrIsukclEUP9DaMmpq7S0RLODMicI6PtqqGOhdna
# RltA0d+Wf+0tPt9SUVtrPJyO7WMPKbykCRXzmHK06zr0kn1YiUYNXCsOgaHF5ImO
# 2ZwQ54UE1I55jjUdldyjy/UPJgxRm9NyXeO7adYr8K8f6Q2nPF0vWqFG7ewwaAl5
# ClKerzshfhB8zujVR0d1Ra7Z01lnXYhWuPqVZayFl7JHr6i6huhpU6BQ6/VgY0cB
# iksX4mNM+ISY81T1RYt7fWATNu/zkjINczipzbfg5S+3fCAo8gVB6+6A5L0vBg39
# dsFITv6MWJuQ8ZZy7fwlFBZE4d5IFbRudakNwKGdyLGM2otaNq7wm3ku7x41UGAm
# kDCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQEL
# BQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNV
# BAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4X
# DTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM
# 57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm
# 95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzB
# RMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBb
# fowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCO
# Mcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYw
# XE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW
# /aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/w
# EPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPK
# Z6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2
# BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfH
# CBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYB
# BAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8v
# BO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYM
# KwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEF
# BQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBW
# BgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUH
# AQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# L2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsF
# AAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518Jx
# Nj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+
# iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2
# pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefw
# C2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7
# T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFO
# Ry3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhL
# mm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3L
# wUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5
# m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE
# 0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLLMIICNAIB
# ATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UE
# CxMdVGhhbGVzIFRTUyBFU046RDZCRC1FM0U3LTE2ODUxJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAOIASP0JSbv5
# R23wxciQivHyckYooIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwDQYJKoZIhvcNAQEFBQACBQDoKRpeMCIYDzIwMjMwNjA2MTAzNzE4WhgPMjAy
# MzA2MDcxMDM3MThaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOgpGl4CAQAwBwIB
# AAICG7EwBwIBAAICEg0wCgIFAOgqa94CAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYK
# KwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUF
# AAOBgQAN/sbdqt6Euw5+b1xA9b0gSFo2L0qCNsSxqd5mDpaOYz0+yO7c9VQjBiOD
# 193NMF3+mCcFPpeL8pfyULP82YxAQdIC/WB/lJvq6TIW1MA6JfBgVLH3nmNcq5Rx
# jdsZcevX5/Uin8j+EnQTGzhcCCPwFJL5KHT4rTuCPILqmPNWAzGCBA0wggQJAgEB
# MIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABx/sAoEpb8ifc
# AAEAAAHHMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwLwYJKoZIhvcNAQkEMSIEIA5MEWQTwWaQG3I8EqV1MvS8A2B7P+OURUgC
# ey0PiS2vMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgR+fl2+JSskULOeVY
# LbeMgk7HdIbREmAsjwtcy6MJkskwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAcf7AKBKW/In3AABAAABxzAiBCBw0BsC2W4cUKa1LQsP
# 5LlDtvdkG/ilOXoncaeUUhzlXjANBgkqhkiG9w0BAQsFAASCAgBckS3cRxvypDBk
# IbC3RFRvk2ACYDbcyfXLdsun63dOzxyWVfqltgJ1xIAnKb7UyZhGCgEh3SYiLC75
# VqJ4TXprxvCVJgn4P5woU/Fi3L+KRwKJls33B1QEAC1XontG8qo/8Fp+1SDoEyU8
# Awv7400OVXLuQGevDAxYJxpGrP52D/W4+Hh55THX+fNDXQCb52hwtS/7XXHKZTJQ
# X+cddr12owQ4tYD/422+MveKe1/3cSlar6CYm5ptu9O6p2JSz2gXZmALdBA7vvbz
# YwtaDhqImkRd5j+D0eSy7eR57bwtf3ZgN00LZnpiE9M4YIs/oH39lkJ1LUzjQZRe
# dAsdC3nZ/OrvkWucLq2E2zw8hRoFpiiaMTcXu6dKDWypnyrrxFL+82JNha7xv8Z9
# 6uCCxiGfnI/mhQTRZWCanq0uS29mfUpcQMofiB5DvZIK512Da6fyCRmv2pNwf5pM
# oQdk5+GimBNSW/aucdTSZiaNr/PuycT2xyNVSw1HiDgxKfqslJacyXV9+OkqCl58
# mq6apuXIsB94vUXrjkbGQwdjXX3swL2qiUr5Fpf+yGytGn7yg8h4grCLgkGK07Sk
# Aca1qkmKoNZcv+/dcC4NMCck7gTuuOa84bB7MChC+olDTlEPdRN6CKu8Mg817hFW
# o8Us9P7YXiGojdj09cOdibbK6SyMXA==
# SIG # End signature block
