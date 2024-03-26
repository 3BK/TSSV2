# diag_api.psm1
# by tdimli
# March 2020
# API/helper functions

# errors reported by these diagnostics won't be shown on screen to user
# only saved to xray_ISSUES-FOUND_*.txt report file
$Global:BETA_DIAGS = "
net_802dot1x_KB4556307,
net_firewall_KB4561854,
net_wlan_KB4557342,
net_dnscli_KB4562541,
net_dasrv_KB4504598,
net_netio_KB4563820,
net_srv_KB4562940,
net_hyphost_KB4562593,
net_vpn_KB4553295,
net_vpn_KB4550202,
net_proxy_KB4569506,
net_branchcache_KB4565457,
net_dnssrv_KB4561750,
net_dnssrv_KB4569509,
net_dnscli_KB4617560,
net_ncsi_KB4648334,
net_srv_KB4612362
"

# constants
# return codes
$Global:RETURNCODE_SUCCESS = 0
$Global:RETURNCODE_SKIPPED = 1
$Global:RETURNCODE_FAILED = 2
$Global:RETURNCODE_EXCEPTION = 3

# issue types
$Global:ISSUETYPE_INFO = 0
$Global:ISSUETYPE_WARNING = 1
$Global:ISSUETYPE_ERROR = 2

# value could not be retrieved
$Global:VALUE_NA = "<error!>"

# time format
$Global:TIME_FORMAT = "yyMMdd-HHmmss"

# xray registry path
$xrayRegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\xray"

# wmi data
$Global:wmi_Win32_ComputerSystem
$Global:wmi_Win32_OperatingSystem

# poolmon data
$Global:poolmonData

# globals
$version

$xrayStartTime
$timestamp

$dataPath
$logFile
$infoFile
$issuesFile
$xmlRptFile

$currDiagFn

$xmlReport
$xmlNsMgr
$nodeXray
$xmlTechAreas
$xmlParameters
$xmlSystemInfo
$xmlDiagnostics

# counters
$Global:numDiagsRun = 0
$Global:numDiagsSuccess = 0
$Global:numDiagsSkipped = 0
$Global:numDiagsFailed = 0
$Global:numIssues = 0

$Global:issueShown = $false

# To report an issue if one was identified by a diagnostic function
# Diagnostic functions use this function to report the issue they have identified 
# $issueType: 0 (Info), 1 (Warning) or 2 (Error)
function ReportIssue 
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [string]
            $issueMsg,

            [Parameter(Mandatory=$true,
            Position=1)]
            [Int]
            $issueType
        )

    $Global:numIssues++
    $onScreenMsg = $true

    # get caller/diagnostic details
    $loc = $VALUE_NA
    $diagFn = $VALUE_NA
    $callStack = Get-PSCallStack
    if ($callStack.Count -gt 1) {
        $loc = (Split-Path -Path $callStack[1].ScriptName -Leaf).ToString() + ":" +  $callStack[1].ScriptLineNumber
        $diagFn = $callStack[1].FunctionName
        if (($loc -eq "") -or ($loc -eq $null)) {
            $loc = $VALUE_NA
        }
        if (($diagFn -eq "") -or ($diagFn -eq $null)) {
            if ($Global:currDiagFn -ne $null) {
                $diagFn = $Global:currDiagFn
            }
            else {
                $diagFn = $loc
            }
            LogWrite "Diagnostic name uncertainty: No on screen message"
            $onScreenMsg = $false
        }
    }

    XmlDiagnosticUpdateIssue $diagFn $IssueType
    LogWrite "Issue (type:$issueType) reported by diagnostic $diagFn [$loc]"

    $outFile = $issuesFile

    # reported issue not an error
    if ($issueType -lt $ISSUETYPE_ERROR) {
        LogWrite "Issue type is not error: No on screen message, saving to info file instead"
        $outFile = $infoFile
        $onScreenMsg = $false
    }

    # diagnostic in beta, no on-screen message
    if ($BETA_DIAGS.Contains($diagFn)) {
        LogWrite "Diagnostic in beta: No on screen message"
        $onScreenMsg = $false
    }

    if(!(Test-Path -Path $outFile)){
        "xray by tdimli, v$version">$outFile
        "Diagnostic check run on $timestamp UTC`r`n">>$outFile
    }
    else {
        # add separator
        "`r`n* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *`r`n">>$outFile
    }
        
    "**">>$outFile
    "** Issue $numIssues`tFound a potential issue (reported by $diagFn):">>$outFile
    "**">>$outFile
    $issueMsg>>$outFile
    
    # show message on screen
    if ($onScreenMsg) {
        $Global:issueShown = $true
        Write-Host ("
**
** Issue $numIssues`tFound a potential issue (reported by $diagFn):
**") -ForegroundColor red
        IndentMsg $issueMsg
    }
}

# Wraps a filename with "xray_" prefix and timestamp & computername suffix for consistency
# Ensures all files created have the same name format, same run of xray script uses the same timestamp-suffix
# Also prepends $dataPath to ensure all files are created in the designated folder
function MakeFilename
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [string]
            $name,

            [Parameter(Mandatory=$true,
            Position=1)]
            [string]
            $extension
        )

    $computer = hostname
    $filename = "xray_" + $name + "_" + $timestamp + "_" + $computer + "." + $extension
    return Join-Path -Path $dataPath -ChildPath $filename
}

# Logs to activity log with timestamp
function LogWrite
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [string]
            $msg
        )

    $callStack = Get-PSCallStack
    $caller = $VALUE_NA
    if ($callStack.Count -gt 1) {
        $caller = $callStack[1].FunctionName + " " + (Split-Path -Path $callStack[1].ScriptName -Leaf).ToString() + ":" +  $callStack[1].ScriptLineNumber
    }
    $time = (Get-Date).ToUniversalTime().ToString("yyMMdd-HHmmss.fffffff")
    "$time [$caller] $msg" >> $logFile
}

# returns summary data from poolmon
# if multiple poolmon data sets are available one set for each will be returned
# each returned set will contain two list items with a string[7] in following format
# Example:
# For sample summary:
#  Memory:33356024K Avail:19399488K  PageFlts:400263915   InRam Krnl:12672K P:935188K
#  Commit:15680004K Limit:40433912K Peak:15917968K            Pool N:629240K P:1004712K
# it will return string array(s) containing:
#  Summary1,22/05/2020 22:35:55.53,33356024,19399488,400263915,12672,935188
#  Summary2,22/05/2020 22:35:55.53,15680004,40433912,15917968,629240,1004712
function GetPoolUsageSummary
{
    [System.Collections.Generic.List[string[]]] $poolmonInfo = New-Object "System.Collections.Generic.List[string[]]"

    foreach ($entry in $poolmonData) {
        if ($entry.Contains("Summary")) {
            $poolmonInfo.Add($entry -split ',')
        }
    }

    return $poolmonInfo
}

# returns pool usage info from poolmon for specified pool tag and type
# pooltag has to be 4 characters (case-sensitive), pooltype can be "Nonp" or "Paged" (case-sensitive)
# if multiple poolmon data sets are available all matching entries will be returned
# returns $null if no entry for specified item
# return data type is list of Int64 arrays
# Example:
# For sample entry:
#  Ntfx Nonp    1127072   1037111     89961 26955808        299        
# it will return an Int64 array containing:
#  1127072, 1037111, 89961, 26955808, 299
function GetPoolUsageByTag
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [ValidatePattern(“.{4}”)]
            [string]
            $poolTag,

            [Parameter(Mandatory=$true,
            Position=1)]
            [ValidatePattern(“(Nonp|Paged)")]
            [string]
            $poolType
        )

    [System.Collections.Generic.List[Int64[]]] $poolmonInfo = New-Object "System.Collections.Generic.List[Int64[]]"

    foreach ($entry in $poolmonData) {
        if ($entry.Contains("$poolTag,$poolType")) {
            $pmEntry = $entry -split ','
            [Int[]] $intArr = New-Object Int[] 5
            for ($i =0; $i -lt 5; $i++) {
                $intArr[$i] = [Convert]::ToInt64($pmEntry[$i + 2])
            }

            $poolmonInfo.Add($intArr)
        }
    }

    return ,$poolmonInfo # unary operator comma is to force the output type to array
}

<#
 Checks if one of the required updates ($reqUpdates) or a later update is present
 Returns 
  true if a required update or later is installed (or if none of the required updates do 
  not apply to current OS version)
   or
  false if a required update is not present (and one of the required updates applies to 
  current OS version)
 $required has a list of updates that specifies the minimum required update for any OS versions 
 to be checked
#>
function HasRequiredUpdate
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string[]]
        $reqUpdates
    )

    $unknownUpdates = $true
    $knownUpdateSeen = $false

    foreach ($minReqUpd in $reqUpdates) {
        foreach($name in $updateLists) {
            $updateList = (Get-Variable -Name $name -ErrorVariable ErrorMsg -ErrorAction SilentlyContinue).Value
            $minReqIdx = $updateList.id.IndexOf($minReqUpd)
            if ($minReqIdx -ge 0) {
                $unknownUpdates = $false
                foreach($installedUpdate in $installedUpdates) {
                    # look for $minReqUpd or later update
                    $instIdx = $updateList.id.IndexOf($installedUpdate.HotFixID)
                    if ($instIdx -ge 0) {
                        $knownUpdateSeen = $true
                        if ($instIdx -le $minReqIdx) { # updates in $updateList are in reverse chronological order, with most recent at idx=0
                            return $true
                        }
                    }
                }
            }
        }
    }

    if ($unknownUpdates) {
        LogWrite "Required update(s) not known"
        throw
    }

    if ($knownUpdateSeen) {
        return $false
    }

    return $true
}

<#
 Checks if all available Windows updates are installed
 Returns n where
  n=0 latest available update is installed, system up-to-date
  n>0 number of missing updates, i.e. updates that are available but not installed
  n<0 update status cannot be determined
#>
function CheckUpdateStatus
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [Boolean]
        $offline
    )

    $errMsg = @"
This system is missing many important updates. 

The last update installed on this system was:
  {0}

Following {1} update(s) have been released since then:
{2}
Resolution
Please install below update as a matter of urgency:
  {3}
"@
    $Global:NumMissingUpdates = -1
    Clear-Variable -Name MissingUpdates -Scope Global -ErrorVariable ErrorMsg -ErrorAction Ignore
    
    if($offline) {
        LogWrite "Cannot run offline, skipping"
        return $RETURNCODE_SKIPPED
    }

    # Look for missing updates
	try	{
        if ($installedUpdates.Count -eq 0) {
            LogWrite "installedUpdates empty!"
            return $RETURNCODE_FAILED
        }
        
        # identify updateList
        $updateFound = $false
        foreach ($installedUpdate in $installedUpdates) {
            LogWrite $installedUpdate.HotfixId
            foreach ($name in $updateLists) {
                $updateList = (Get-Variable -Name $name -ErrorVariable ErrorMsg -ErrorAction SilentlyContinue).Value
                $idxMRUI = $updateList.id.IndexOf($installedUpdate.HotfixId)
                if ($idxMRUI -ge 0) {
                    $updateFound = $true
                    LogWrite "Relevant update list is $name"
                    break
                }
            }
            if ($updateFound) {
                break
            }
        }

        # identify latest update installed
        if ($updateFound -eq $true) {
            foreach ($update in $updateList) {
                $idxIU = $installedUpdates.HotfixId.IndexOf($update.id)
                if ($idxIU -ge 0) {
                    $idxMRUI = $updateList.id.IndexOf($update.id)
                    $Global:NumMissingUpdates = $idxMRUI
                    $Global:MissingUpdates = $updateList[0..($idxMRUI - 1)]
                    LogWrite "$($updateList[$idxMRUI].id): installedUpdates[$idxIU] is a match for $name[$idxMRUI]"
                    break
                }
            }
        }

        # check results and report
        if ($NumMissingUpdates -lt 0) {
            # failure
            LogWrite "Error: None of the installed updates match update data, update status could not be determined."
            return $RETURNCODE_FAILED
        }
        elseif ($NumMissingUpdates -gt 2) {
            # missing too many updates
            foreach ($upd in $MissingUpdates.heading) {
                $mUpd += "  $upd`r`n"
            }
            $issueType = $ISSUETYPE_ERROR
            $issueMsg = [string]::Format($errMsg, $updateList[$NumMissingUpdates].heading, $NumMissingUpdates, $mUpd, $MissingUpdates[0].heading)
            ReportIssue $issueMsg $issueType
        }
	}
	catch {
		LogWrite "Failed - exiting! (Error: $_)"
        return $RETURNCODE_FAILED
    }

    return $RETURNCODE_SUCCESS
}

# Shows message on screen indented for readability
function IndentMsg
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [string]
            $msg
        )

    $newMsg = $msg -split "`n"
    foreach ($line in $newMsg) {
        Write-Host "   $line"
    }
}

function InitGlobals
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [string]
            $ver,

            [Parameter(Mandatory=$true,
            Position=1)]
            [string]
            $path
        )

    $Global:version = $ver
    $Global:dataPath = $path
    $Global:xrayStartTime = (Get-Date).ToUniversalTime()
    $Global:timestamp = $xrayStartTime.ToString($TIME_FORMAT)
    $Global:logFile = MakeFilename "log" "txt"
    $Global:infoFile = MakeFilename "INFO" "txt"
    $Global:issuesFile = MakeFilename "ISSUES-FOUND" "txt"
    $Global:xmlRptFile = MakeFilename "report" "xml"
    $Global:issueShown = $false

    # add and populate root node: nodeXray
    $Global:xmlReport = New-Object System.XML.XMLDocument
    $Global:nodeXray = $xmlReport.CreateElement("xray")
    [void] $xmlReport.appendChild($nodeXray)
    $nodeXray.SetAttribute("Version", $version)
    $nodeXray.SetAttribute("Complete", $false)
    $nodeXray.SetAttribute("StartTime", $timestamp)
    $nodeXray.SetAttribute("Complete", $false)
        
    # add nodes
    $Global:xmlTechAreas = $nodeXray.AppendChild($xmlReport.CreateElement("TechAreas"))
    $Global:xmlParameters = $nodeXray.AppendChild($xmlReport.CreateElement("Parameters"))
    $Global:xmlSystemInfo = $nodeXray.AppendChild($xmlReport.CreateElement("SystemInfo"))
    $Global:xmlDiagnostics = $nodeXray.AppendChild($xmlReport.CreateElement("Diagnostics"))

    # namespace manager
    $Global:xmlNsMgr = New-Object System.Xml.XmlNamespaceManager($xmlReport.NameTable)
    $xmlNsMgr.AddNamespace("xrayNS", $xmlReport.DocumentElement.NamespaceURI)
}

function AddSysInfo
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [bool]
            $offline
        )

    if ($offline) {
        # if offline retrieve from data
        LogWrite "Offline system info collection not yet implemented"
        return
    }

    # PSVersionTable
    $PSVer = ($PSVersionTable)
    if ($PSVer -ne $null) {
        XmlAddSysInfo "PSVersionTable" "PSVersion" $PSVer.PSVersion
        XmlAddSysInfo "PSVersionTable" "WSManStackVersion" $PSVer.WSManStackVersion
        XmlAddSysInfo "PSVersionTable" "SerializationVersion" $PSVer.SerializationVersion
        XmlAddSysInfo "PSVersionTable" "CLRVersion" $PSVer.CLRVersion
        XmlAddSysInfo "PSVersionTable" "BuildVersion" $PSVer.BuildVersion
    }

    # installedUpdates
    $Global:installedUpdates = Get-HotFix | Sort-Object -Property InstalledOn -Descending -ErrorAction SilentlyContinue

    # Win32_ComputerSystem
    $Global:wmi_Win32_ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($wmi_Win32_ComputerSystem -ne $null) {
        XmlAddSysInfo "Win32_ComputerSystem" "BootupState" $wmi_Win32_ComputerSystem.BootupState
        XmlAddSysInfo "Win32_ComputerSystem" "PowerState" $wmi_Win32_ComputerSystem.PowerState
        XmlAddSysInfo "Win32_ComputerSystem" "DomainRole" $wmi_Win32_ComputerSystem.DomainRole
        XmlAddSysInfo "Win32_ComputerSystem" "Manufacturer" $wmi_Win32_ComputerSystem.Manufacturer
        XmlAddSysInfo "Win32_ComputerSystem" "Model" $wmi_Win32_ComputerSystem.Model
        XmlAddSysInfo "Win32_ComputerSystem" "NumberOfLogicalProcessors" $wmi_Win32_ComputerSystem.NumberOfLogicalProcessors
        XmlAddSysInfo "Win32_ComputerSystem" "NumberOfProcessors" $wmi_Win32_ComputerSystem.NumberOfProcessors
        XmlAddSysInfo "Win32_ComputerSystem" "OEMStringArray" $wmi_Win32_ComputerSystem.OEMStringArray
        XmlAddSysInfo "Win32_ComputerSystem" "PartOfDomain" $wmi_Win32_ComputerSystem.PartOfDomain
        XmlAddSysInfo "Win32_ComputerSystem" "PCSystemType" $wmi_Win32_ComputerSystem.PCSystemType
        XmlAddSysInfo "Win32_ComputerSystem" "SystemType" $wmi_Win32_ComputerSystem.SystemType
        XmlAddSysInfo "Win32_ComputerSystem" "TotalPhysicalMemory" $wmi_Win32_ComputerSystem.TotalPhysicalMemory
        XmlAddSysInfo "Win32_ComputerSystem" "HypervisorPresent" $wmi_Win32_ComputerSystem.HypervisorPresent
    }

    # Win32_OperatingSystem
    $Global:wmi_Win32_OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($wmi_Win32_OperatingSystem -ne $null) {
        XmlAddSysInfo "Win32_OperatingSystem" "Caption" $wmi_Win32_OperatingSystem.Caption
        XmlAddSysInfo "Win32_OperatingSystem" "Version" $wmi_Win32_OperatingSystem.Version
        XmlAddSysInfo "Win32_OperatingSystem" "BuildType" $wmi_Win32_OperatingSystem.BuildType
        XmlAddSysInfo "Win32_OperatingSystem" "BuildNumber" $wmi_Win32_OperatingSystem.BuildNumber
        XmlAddSysInfo "Win32_OperatingSystem" "ProductType" $wmi_Win32_OperatingSystem.ProductType
        XmlAddSysInfo "Win32_OperatingSystem" "OperatingSystemSKU" $wmi_Win32_OperatingSystem.OperatingSystemSKU
        XmlAddSysInfo "Win32_OperatingSystem" "OSArchitecture" $wmi_Win32_OperatingSystem.OSArchitecture
        XmlAddSysInfo "Win32_OperatingSystem" "OSType" $wmi_Win32_OperatingSystem.OSType
        XmlAddSysInfo "Win32_OperatingSystem" "InstallDate" $wmi_Win32_OperatingSystem.InstallDate
        XmlAddSysInfo "Win32_OperatingSystem" "LocalDateTime" $wmi_Win32_OperatingSystem.LocalDateTime
        XmlAddSysInfo "Win32_OperatingSystem" "LastBootUpTime" $wmi_Win32_OperatingSystem.LastBootUpTime
    }
    
    XmlSave
} 

function XmlAddTechArea
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string]
        $name,

        [Parameter(Mandatory=$true,
        Position=1)]
        [string]
        $ver
    )

    [System.XML.XMLElement]$xmlTechArea = $xmlTechAreas.AppendChild($xmlReport.CreateElement("TechArea"))
    $xmlTechArea.SetAttribute("Name", $name)
    $xmlTechArea.SetAttribute("Version", $ver)
}

function XmlAddParameters
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [AllowEmptyString()]
        [AllowNull()]
        [string[]]
        $areas,

        [Parameter(Mandatory=$true,
        Position=1)]
        [AllowEmptyString()]
        [AllowNull()]
        [string[]]
        $components,

        [Parameter(Mandatory=$true,
        Position=2)]
        [AllowEmptyString()]
        [AllowNull()]
        [string[]]
        $diagnostics,

        [Parameter(Mandatory=$true,
        Position=3)]
        [bool]
        $offline,

        [Parameter(Mandatory=$true,
        Position=4)]
        [bool]
        $waitBeforeClose,

        [Parameter(Mandatory=$true,
        Position=5)]
        [bool]
        $skipDiags,

        [Parameter(Mandatory=$true,
        Position=6)]
        [bool]
        $DevMode
    )

    foreach ($area in $areas) {
        [System.XML.XMLElement] $xmlArea = $xmlParameters.AppendChild($xmlReport.CreateElement("Area"))
        $xmlArea.SetAttribute("Name", $area)
    }
    foreach ($component in $components) {
        [System.XML.XMLElement] $xmlComponent = $xmlParameters.AppendChild($xmlReport.CreateElement("Component"))
        $xmlComponent.SetAttribute("Name", $component)
    }
    foreach ($diagnostic in $diagnostics) {
        [System.XML.XMLElement] $xmlComponent = $xmlParameters.AppendChild($xmlReport.CreateElement("Diagnostic"))
        $xmlComponent.SetAttribute("Name", $diagnostic)
    }
    [System.XML.XMLElement] $xmlOffline = $xmlParameters.AppendChild($xmlReport.CreateElement("Offline"))
    $xmlOffline.SetAttribute("Value", $offline)
    [System.XML.XMLElement] $xmlOffline = $xmlParameters.AppendChild($xmlReport.CreateElement("WaitBeforeClose"))
    $xmlOffline.SetAttribute("Value", $waitBeforeClose)
    [System.XML.XMLElement] $xmlOffline = $xmlParameters.AppendChild($xmlReport.CreateElement("SkipDiags"))
    $xmlOffline.SetAttribute("Value", $skipDiags)
    [System.XML.XMLElement] $xmlOffline = $xmlParameters.AppendChild($xmlReport.CreateElement("DevMode"))
    $xmlOffline.SetAttribute("Value", $DevMode)

    # save
    XmlSave
}

# to add a single attribute from a WMI class
function XmlAddSysInfo
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string]
        $valueName,

        [Parameter(Mandatory=$true,
        Position=1)]
        [string]
        $attribName,

        [Parameter(Mandatory=$true,
        Position=2)]
        [AllowNull()]
        [System.Object]
        $propertyValue
    )

    if ($propertyValue -ne $null) {

        [System.XML.XMLElement] $wmidata = $nodeXray.SelectSingleNode("/xray/SystemInfo/$valueName")
        if ((!$xmlSystemInfo.HasChildNodes) -or ($wmidata -eq $null)) {
            # doesn't exist, need to add
            $wmidata = $xmlSystemInfo.AppendChild($xmlReport.CreateElement($valueName))
        }
        $wmidata.SetAttribute($attribName, $propertyValue)
    }
}

# to add multiple/all attributes of a WMI class
function XmlAddSysInfoMulti
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string]
        $valueName,

        [Parameter(Mandatory=$true,
        Position=1)]
        [System.Object[]]
        $attributes
    )

    [System.XML.XMLElement] $wmidata = $nodeXray.SelectSingleNode("/xray/SystemInfo/$valueName")
    if ((!$xmlSystemInfo.HasChildNodes) -or ($wmidata -eq $null)) {
        # doesn't exist, need to add
        $wmidata = $xmlSystemInfo.AppendChild($xmlReport.CreateElement($valueName))
    }
    foreach($attribute in $attributes) {
        $wmidata.SetAttribute($attribute.Name, $attribute.Value)
    }
    XmlSave
}

function XmlAddDiagnostic
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string]
        $name)

    [System.XML.XMLElement] $xmlDiagnostic = $xmlDiagnostics.AppendChild($xmlReport.CreateElement("Diagnostic"))
    $xmlDiagnostic.SetAttribute("Name", $name)
    $xmlDiagnostic.SetAttribute("Result", -1)
    $xmlDiagnostic.SetAttribute("Duration", -1)
    XmlSave 
}

function XmlDiagnosticComplete
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string]
        $name,

        [Parameter(Mandatory=$true,
        Position=1)]
        [Int]
        $result,

        [Parameter(Mandatory=$true,
        Position=2)]
        [UInt64]
        $duration
    )

    $xmlDiagnostic = $xmlReport.SelectSingleNode("//xrayNS:Diagnostics/Diagnostic[@Name='$name']", $xmlNsMgr)

    if ($xmlDiagnostic -ne $null) {
        $xmlDiagnostic.SetAttribute("Result", $result)
        $xmlDiagnostic.SetAttribute("Duration", $duration)
        XmlSave 
    }
}

function XmlDiagnosticUpdateIssue
{
    param(
        [Parameter(Mandatory=$true,
        Position=0)]
        [string]
        $name,

        [Parameter(Mandatory=$true,
        Position=1)]
        [Int]
        $issueType
    )

    $xmlDiagnostic = $xmlReport.SelectSingleNode("//xrayNS:Diagnostic[@Name='$name']", $xmlNsMgr)

    if ($xmlDiagnostic -ne $null) {
        $xmlDiagnostic.SetAttribute("Reported", $issueType)
        XmlSave 
    }
}

function XmlMarkComplete
{
    $nodeXray.SetAttribute("Complete", $true)
    XmlSave 
}

function XmlSave
{
    $finishTime = (Get-Date).ToUniversalTime()
    $nodeXray.SetAttribute("EndTime", $finishTime.ToString($TIME_FORMAT))
    [UInt64] $timeTaken = ($finishTime - $xrayStartTime).TotalMilliseconds
    $nodeXray.SetAttribute("Duration", $timeTaken)
    $xmlReport.Save($xmlRptFile)
}

function InitPoolmonData
{
    param(
            [Parameter(Mandatory=$true,
            Position=0)]
            [bool]
            $offline
        )

    $file = Get-ChildItem -Path "$dataPath\*_poolmon.txt" -Name
    if ($file.Count -gt 1) {
        $file = $file[0]
    }

    if ($file -ne $null) {

        $Global:poolmonData = New-Object "System.Collections.Generic.List[string]"
        $pmTimestamp = $VALUE_NA

        $summary1 = "^\s+Memory:\s*(?<memory>[-0-9]+)K Avail:\s*(?<avail>[-0-9]+)K  PageFlts:\s*(?<pageflts>[-0-9]+)   InRam Krnl:\s*(?<inRamKrnl>[-0-9]+)K P:\s*(?<inRamP>[-0-9]+)K"
        $summary2 = "^\s+Commit:\s*(?<commit>[-0-9]+)K Limit:\s*(?<limit>[-0-9]+)K Peak:\s*(?<peak>[-0-9]+)K            Pool N:\s*(?<poolN>[-0-9]+)K P:\s*(?<poolP>[-0-9]+)K"
        $tagentry = "^\s+(?<tag>.{4})\s+(?<type>\w+)\s+(?<allocs>[-0-9]+)\s+(?<frees>[-0-9]+)\s+(?<diff>[-0-9]+)\s+(?<bytes>[-0-9]+)\s+(?<perAlloc>[-0-9]+)\s+$"
        $markerDT = "^\s*===== (?<datetime>(.){22}) ====="
        
        Get-Content "$dataPath\$file" |
        Select-String -Pattern $summary1, $summary2, $tagentry, $markerDT |
        Foreach-Object {

            if ($_.Matches[0].Groups['datetime'].Value -ne "") {
                $pmTimestamp =  $_.Matches[0].Groups['datetime'].Value
            }

            if ($_.Matches[0].Groups['memory'].Value -ne "") {
                #$memory, $avail, $pageflts, $inRamKrnl, $inRamP = $_.Matches[0].Groups['memory', 'avail', 'pageflts', 'inRamKrnl', 'inRamP'].Value
                $memory = $_.Matches[0].Groups['memory'].Value
                $avail = $_.Matches[0].Groups['avail'].Value
                $pageflts = $_.Matches[0].Groups['pageflts'].Value
                $inRamKrnl = $_.Matches[0].Groups['inRamKrnl'].Value
                $inRamP = $_.Matches[0].Groups['inRamP'].Value

                $poolmonData.Add("Summary1,$pmTimestamp,$memory,$avail,$pageflts,$inRamKrnl,$inRamP")
            }

            if ($_.Matches[0].Groups['commit'].Value -ne "") {
                #$commit, $limit, $peak, $poolN, $poolP = $_.Matches[0].Groups['commit', 'limit', 'peak', 'poolN', 'poolP'].Value
                $commit = $_.Matches[0].Groups['commit'].Value
                $limit = $_.Matches[0].Groups['limit'].Value
                $peak = $_.Matches[0].Groups['peak'].Value
                $poolN = $_.Matches[0].Groups['poolN'].Value
                $poolP = $_.Matches[0].Groups['poolP'].Value

                $poolmonData.Add("Summary2,$pmTimestamp,$commit,$limit,$peak,$poolN,$poolP")
                $pmTimestamp = $VALUE_NA
            }

            if ($_.Matches[0].Groups['tag'].Value -ne "") {
                #$tag, $type, $allocs, $frees, $diff, $bytes, $perAlloc = $_.Matches[0].Groups['tag', 'type', 'allocs', 'frees', 'diff', 'bytes', 'perAlloc'].Value
                $tag = $_.Matches[0].Groups['tag'].Value
                $type = $_.Matches[0].Groups['type'].Value
                $allocs = $_.Matches[0].Groups['allocs'].Value
                $frees = $_.Matches[0].Groups['frees'].Value
                $diff = $_.Matches[0].Groups['diff'].Value
                $bytes = $_.Matches[0].Groups['bytes'].Value
                $perAlloc = $_.Matches[0].Groups['perAlloc'].Value 

                $poolmonData.Add("$tag,$type,$allocs,$frees,$diff,$bytes,$perAlloc")
            }
        }
    }
    else {
        LogWrite "Poolmon data not found: $dataPath\*_poolmon.txt"
    }
}

Export-ModuleMember -Function * -Variable *
# SIG # Begin signature block
# MIInvwYJKoZIhvcNAQcCoIInsDCCJ6wCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB8sbLfieEZzykX
# /Xq867iv7EJW4/UVOjwoqgGhVAwObaCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGZ8wghmbAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIANpecZRLOuG7BOLez3izE5m
# IMKZqKyfMN1sm7LBz2J0MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEATvD3YSBB8afQ2/Wa6zrmaHn48I94U3y8lf5WXw6aFmz1VHlDW7qWp9KO
# IbX2046tbE41mUKQ6nlJWPCrwaRittqH6TgR+O/XXP95aigo8hTHoeBQOZ5VApLf
# MpS0NQpNyEG6UzHoJvF+4z4XoxpmOImVG+Fakbciw4BWWYOlikzINc1VCum5gXvW
# O9G7oARE0hk9OqM/SDw95Ia+eT9h1rG8DvIk0yKmU58jtouuviOfSxEkUtDosB/n
# m+Fvv/AGTuw/yyokFnQP0DckKE879UBKYI0v3SLsUnzbQbgLjBb30vnU0owJhEKx
# uBwMgbYZqy1aV9wtUWEgpEcmgp9RQqGCFykwghclBgorBgEEAYI3AwMBMYIXFTCC
# FxEGCSqGSIb3DQEHAqCCFwIwghb+AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsq
# hkiG9w0BCRABBKCCAUgEggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCBpoWZIcdAnsc1g2Ncs5WbnvSd+taTLmGALLZwSMY4b4AIGZGzyr5di
# GBMyMDIzMDYwNjExNDQxNi43NzhaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OkZDNDEtNEJENC1EMjIwMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloIIReDCCBycwggUPoAMCAQICEzMAAAG59gANZVRPvAMAAQAAAbkwDQYJ
# KoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjIw
# OTIwMjAyMjE3WhcNMjMxMjE0MjAyMjE3WjCB0jELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3Bl
# cmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpGQzQxLTRC
# RDQtRDIyMDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAONJPslh9RbHyQECbUIINxMF
# 5uQkyN07VIShITXubLpWnANgBCLvCcJl7o/2HHORnsRcmSINJ/qclAmLIrOjnYnr
# bocAnixiMEXC+a1sZ84qxYWtEVY7VYw0LCczY+86U/8shgxqsaezKpWriPOcpV1S
# h8SsOxf30yO7jvld/IBA3T6lHM2pT/HRjWk/r9uyx0Q4atx0mkLVYS9y55/oTlKL
# E00h792S+maadAdy3VgTweiwoEOXD785wv3h+fwH/wTQtC9lhAxhMO4p+OP9888W
# xkbl6BqRWXud54RTzqp2Vr+yen1Q1A6umyMB7Xq0snIYG5B1Acc4UgJlPQ/ZiMkq
# gxQNFCWQvz0G9oLgSPD8Ky0AkX22PcDOboPuNT4RceWPX0UVZUsX9IUgs7QF41Hi
# QSwEeOOHGyrfQdmSslATrbmH/18M5QrsTM5JINjct9G42xqN8VF9Z8WOiGMjNbvl
# pcEmmysYl5QyhrEDoFnQTU7bFrD3JX0fIfu1sbLWeBqXwbp4Z8yACTtphK2VbzOv
# i4vc0RCmRNzvYQQ2PjZ7NaTXE4Gu3vggAJ+rtzUTAfJotvOSqcMgNwLZa1Y+ET/l
# b0VyjrYwFuHtg0QWyQjP5350LTpv086pyVUh4A3w/Os5hTGFZgFe5bCyMnpY09M0
# yPdHaQ/56oYUsSIcyKyVAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUt7A4cdtYQ5oJ
# jE1ZqrSonp41RFIwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYD
# VR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# cmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwG
# CCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIw
# MjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcD
# CDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBAM3cZ7NFUHRMsLKz
# jl7rJPIkv7oJ+s9kkut0hZif9WSt60SzYGULp1zmdPqc+w8eHTkhqX0GKCp2TTqS
# zBXBhwHOm8+p6hUxNlDewGMZUos952aTXblAT3OKBnfVBLQyUavrSjuJGZAW30cN
# Y3rjVDUlGD+VygQHySaDaviJQbK6/6fQvUUFoqIk3ldGfjnAtnebsVlqh6WWamVc
# 5AZdpWR1jSzN/oxKYqc1BG4SxxlPtcfrAdBz/cU4bxVXqAAf02NZscvJNpRnOALf
# 5kVo2HupJXCsk9TzP5PNW2sTS3TmwhIQmPxr0E0UqOojUrBJUOhbITAxcnSa/IMl
# uL1HXRtLQZI+xs2eRtuPOUsKUW71/1YeqsYCLHLvu82ceDVQQvP7GHEEkp2kEjio
# fbjYErBo2iCEaxxeX4Z9HvAgA4MsQkbn6e4EFQf13sP+Kn3XgMIvJbqLJeFcQja+
# SUeOXu5cfkxe0GzTNojdyIwzaHlhOflVRZNrxee3B+yZwd3JHDIvv71uSI/SIzzt
# 9cU2GyHQVqxBSrRtKW6W8Vw7zpVvoVsIv3ljxg+7NiGSlXX1s7zbBNDMUj9OnzOl
# HK/3mrOU8YEuRf6RwakW5UCeGamy5MiKu2YuyKiGBCv4OGhPstNe7ALkEOh8BX12
# t4ntuYu+gw9L6yCPY0jWYaQtzAP9MIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJ
# mQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1
# WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjK
# NVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhg
# fWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJp
# rx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/d
# vI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka9
# 7aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKR
# Hh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9itu
# qBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyO
# ArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItb
# oKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6
# bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6t
# AgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQW
# BBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacb
# UzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYz
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnku
# aHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIA
# QwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2
# VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwu
# bWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEw
# LTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYt
# MjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/q
# XBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6
# U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVt
# I1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis
# 9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTp
# kbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0
# sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138e
# W0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJ
# sWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7
# Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0
# dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQ
# tB1VM1izoXBm8qGCAtQwggI9AgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxh
# bmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpG
# QzQxLTRCRDQtRDIyMDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaIjCgEBMAcGBSsOAwIaAxUAx2IeGHhk58MQkzzSWknGcLjfgTqggYMwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIF
# AOgpPGIwIhgPMjAyMzA2MDYxMzAyMjZaGA8yMDIzMDYwNzEzMDIyNlowdDA6Bgor
# BgEEAYRZCgQBMSwwKjAKAgUA6Ck8YgIBADAHAgEAAgICJDAHAgEAAgISVDAKAgUA
# 6CqN4gIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAID
# B6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAMKree/ijHEHZB2qMHdk
# yaekxx0PB6Reb/u36NIGhCYhfhJhEykfmfkoRvT2VlnrfCqRWEA24gsCeMr4WL/P
# lsBUxSMekzadDorNsAiPlDk3ABW7EpI4A94ZgP8K3jRntPw0WvJnhLfX2pROW+/v
# qgdbuOhpZZqNmW2bN4MG2IHcMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTACEzMAAAG59gANZVRPvAMAAQAAAbkwDQYJYIZIAWUDBAIB
# BQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQx
# IgQgX5rr+ONhNQ0cPW4rLjp6GSC/1SHQ1Uhnw/YjJmLH6uwwgfoGCyqGSIb3DQEJ
# EAIvMYHqMIHnMIHkMIG9BCBk60bO8W85uTAfJVEO3vX2aLaQFcgcGpdwsOoi+foP
# 9DCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABufYA
# DWVUT7wDAAEAAAG5MCIEIIiUQFOD/DfPKzh2HUCNc6L4hy56TKlgS0d/vmUR/IOe
# MA0GCSqGSIb3DQEBCwUABIICAF/9R5zn/SKUinYRYMA70cyEkxwr4Yg25Eq0wsz6
# 25waF6nbrTNg6v78siwi9pvFACLPbTCiL2NjUaONxeNstZf7vviXaWvRYOXEn/vp
# LKiHxjFx7qsXHVKEjs0wffM7++FIF/jfF0uycSZ35VgGaf4KcRmfF+1gvMdPwCLH
# 4XcmP7ojFuVnOe0IPT64rtdwC9ETo5qZHYVTke+dObOWEZKg6sjB96crshkBLs3R
# Rt0w4HQNEfJIjLFayqkz2DvFYin+22PboG7nCeM3kiltpdjp+wXTCeeN+3qtgqNe
# 2OV7YHZl0DH5c1ZUsg2ZpK4dujGOWDFK9EPRoWlSEN9JT8Pf4sJYr9b+PMzo5Swo
# 3uxdyxCcIinYzRamRme6HN0hFxjvVcMMsrnvjLaxZpTJce8WX6viIYDlYthvf/Io
# 0TROVcD5sK30FpT6+83Wnppi7PgFN1AZ3/EKUIKrBep5GxC8wFcH29+Mq/Ke3jkY
# j6eFxwRQ1Ms+qEyfPISHnviAFb9kwa9dICtU87u4dEVhSIYXIF/g++UcBuDw2RJb
# Uy8+mrXhKFMiMyYfPyw6QGkKQ6Myc2wbdYTjiFaPd9DssUbsmEcL8R2qYmPdojGb
# 3ZbNwkKEgWz5MMCytZew+sKc5KjJYu+jab2Gv8Lv6hSx/BekisidCLyXJSwNlHzS
# ANiP
# SIG # End signature block
