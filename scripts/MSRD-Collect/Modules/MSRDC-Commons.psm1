<#
.SYNOPSIS
   MSRD-Collect global functions

.DESCRIPTION
   Module for the MSRD-Collect global functions

.NOTES
   Authors    : Robert Klemencz (Microsoft) & Alexandru Olariu (Microsoft)
   Requires   : At least PowerShell 5.1 (This module is not for stand-alone use. It is used automatically from within the main MSRD-Collect.ps1 script)
   Version    : See MSRD-Collect.ps1 version
   Feedback   : Send an e-mail to MSRDCollectTalk@microsoft.com
#>

enum LogLevel {
    Normal = 0
    Info = 1
    Warning = 2
    Error = 3
    ErrorLogFileOnly = 4
    WarnLogFileOnly = 5
    DiagFileOnly = 7
}

#region initialization
function msrdInitScript {
    param ([string]$Type, $isTSS)

    if (!($isTSS)) {
        $initValues = @(
            "$(msrdGetLocalizedText initvalues1) $global:msrdScriptpath",
            "$(msrdGetLocalizedText initvalues2)",
            "$(msrdGetLocalizedText initvalues3) $global:msrdLogRoot",
            "$(msrdGetLocalizedText initvalues4) $global:msrdUserprof`n"
        )
    }

    $initValues | ForEach-Object { if ($type -eq 'GUI') { msrdAdd-OutputBoxLine $_ } else { msrdLogMessage Info $_ } }

    $unsupportedBuilds = 7601, 9200, 9600, 10240, 10586, 15063, 16299, 17134, 18362, 18363, 19041
    $unsupportedOSMessage = "This Windows release is no longer supported. Please upgrade the machine to a more current, in-service, and supported Windows release."

    if ($unsupportedBuilds -contains $global:WinVerBuild) {
        if ($type -eq 'GUI') { 
            msrdAdd-OutputBoxLine $unsupportedOSMessage -Color "Yellow"
        } else {
            Write-Warning $unsupportedOSMessage
        }
    }

    $unsupportedOSMessageExt = @{
        "*Server 2008 R2*" = "The Windows Server 2008 R2 Extended Security Update (ESU) Program ended on January 10, 2023. 'Azure only' ESU will end on January 9, 2024. See: <a href='https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2008-r2' target='_blank'>Windows Server 2008 R2</a>. Please upgrade the machine to a more current, in-service, and supported Windows release.`n";
    }

    if ($unsupportedOSMessageExt.ContainsKey($global:msrdOSVer)) {
        if ($type -eq 'GUI') { 
            msrdAdd-OutputBoxLine $unsupportedOSMessageExt[$global:msrdOSVer] -Color "Yellow"
        } else { 
            Write-Warning $unsupportedOSMessageExt[$global:msrdOSVer]
        }
    }
}

function msrdInitScenarioVars {
    
    $vars = "vProfiles", "vActivation", "vMSRA", "vSCard", "vIME", "vTeams", "vMSIXAA", "vHCI"
    foreach ($var in $vars) { $var = $script:varsNO }

    $script:dumpProc = $False; $script:pidProc = ""
    $script:traceNet = $False; $script:onlyDiag = $false
}

Function msrdInitFolders {

    if ($global:TSSinUse) {
        $global:msrdLogFolder = "MSRD-Results-" + $env:computername
    } else {
        $global:msrdLogFolder = "MSRD-Results-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
    }
    
    $global:msrdLogDir = "$global:msrdLogRoot\$global:msrdLogFolder\"
    $global:msrdLogFilePrefix = $env:computername + "_"
    $global:msrdBasicLogFolder = $global:msrdLogDir + $global:msrdLogFilePrefix
    $global:msrdErrorLogFile = $global:msrdBasicLogFolder + "MSRD-Collect-Error.txt"
    $global:msrdTempCommandErrorFile = $global:msrdBasicLogFolder + "MSRD-Collect-CommandError.txt"
    $global:msrdOutputLogFile = $global:msrdBasicLogFolder + "MSRD-Collect-Log.txt"
    $global:msrdEventLogFolder = $global:msrdBasicLogFolder + "EventLogs\"
    $global:msrdNetLogFolder = $global:msrdBasicLogFolder + "Networking\"
    $global:msrdRDSLogFolder = $global:msrdBasicLogFolder + "RDS\"
    $global:msrdAVDLogFolder = $global:msrdBasicLogFolder + "AVD\"
    $global:msrdRegLogFolder = $global:msrdBasicLogFolder + "RegistryKeys\"
    $global:msrdSchtaskFolder = $global:msrdBasicLogFolder + "ScheduledTasks\"
    $global:msrdSysInfoLogFolder = $global:msrdBasicLogFolder + "SystemInfo\"
    $global:msrdGenevaLogFolder = $global:msrdBasicLogFolder + "AVD\Monitoring\"

    if ($global:msrdAVD) { $global:msrdTechFolder = $global:msrdAVDLogFolder } else { $global:msrdTechFolder = $global:msrdRDSLogFolder }

    try {
        $createfolder = New-Item -itemtype directory -path $global:msrdLogDir -ErrorAction Stop
    }
    catch {
        $failedCommand = $_.InvocationInfo.Line.TrimStart()
        $errorMessage = $_.Exception.Message.TrimStart()
        msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
    }
}

Function msrdCreateLogFolder {
    Param([string]$msrdLogFolder, $TimeStamp)

    If (!(Test-Path -Path $msrdLogFolder)) {
        Try {
            if ($TimeStamp -eq "No") {
                $LogMessage = "$(msrdGetLocalizedText "logfoldermsg") $msrdLogFolder"
            } else {
                $LogMessage = (Get-Date).ToString("yyyyMMdd HH:mm:ss.fff") + " $(msrdGetLocalizedText "logfoldermsg") $msrdLogFolder"
            }

            if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                msrdAdd-OutputBoxLine $LogMessage "Yellow"
            } else {
                Write-Host $LogMessage -ForegroundColor Yellow
            }

            if ($global:msrdCollecting -or $global:msrdDiagnosing) {
                $LogMessage | Out-File -Append $global:msrdOutputLogFile
            }

            New-Item -Path $msrdLogFolder -ItemType Directory -ErrorAction Stop | Out-Null
        } Catch {
            $failedCommand = $_.InvocationInfo.Line.TrimStart()
            $errorMessage = $_.Exception.Message.TrimStart()
            msrdLogException ("$(msrdGetLocalizedText "errormsg") $failedCommand") -ErrObj $_ $fLogFileOnly
            if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
            } else {
                msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
            }
        }
    } else {
        msrdLogMessage WarnLogFileOnly "$msrdLogFolder $(msrdGetLocalizedText "logfolderexistmsg")"
    }
}

function msrdGetLocalizedText ($textID) {

    $textIDlang = $textID + $global:msrdLangID
	$LangTextNode = $global:msrdLangText.LangV1.lang | Where-Object {$_.id -eq $textIDlang}

	if($LangTextNode -ne $null) {
		$LangTextCode = @()
		$LangTextCode += $LangTextNode."#text"
        if ($LangTextCode -like "*&amp;*") { $LangTextCode = $LangTextCode.replace("&amp;","&") }
		return $LangTextCode
	} else {
        $textIDlang = $textID + "EN"
	    $LangTextNode = $global:msrdLangText.LangV1.lang | Where-Object {$_.id -eq $textIDlang}
        if($LangTextNode -ne $null) {
		    $LangTextCode = @()
		    $LangTextCode += $LangTextNode."#text"
            if ($LangTextCode -like "*&amp;*") { $LangTextCode = $LangTextCode.replace("&amp;","&") }
		    return $LangTextCode
        }
    }
	return $null
}

function msrdGetSysInternalsProcDump {

    try {
        $PDurl = 'https://github.com/MicrosoftDocs/sysinternals/blob/main/sysinternals/downloads/procdump.md'
            
        $PDWSProxy = New-object System.Net.WebProxy
        $PDWSWebSession = new-object Microsoft.PowerShell.Commands.WebRequestSession
        $PDWSWebSession.Proxy = $PDWSProxy
        $PDWSWebSession.Credentials = [System.Net.CredentialCache]::DefaultCredentials
        $PDresponse = Invoke-WebRequest -Uri $PDurl -WebSession $PDWSWebSession -UseBasicParsing -TimeoutSec 30

        if ($PDresponse) {
            $PDhtml = New-Object -ComObject "HTMLFile"
            Try {
                $PDhtml.IHTMLDocument2_write($PDresponse.Content)
            } catch {
                $PDsrc = [System.Text.Encoding]::Unicode.GetBytes($PDresponse.Content)
                $PDhtml.write($PDsrc)
            }

            # Define the regular expression pattern to match the Procdump version
            $regexPattern = 'ProcDump v([\d\.]+)'

            # Find all <h1> elements in the HTML document
            $h1Elements = $PDhtml.getElementsByTagName('h1')

            # Find the first <h1> element that contains the string "ProcDump"
            $h1Element = $h1Elements | Where-Object { $_.innerText.Contains('ProcDump') } | Select-Object -First 1

            # Extract the text content of the <h1> element
            $h1Text = $h1Element.innerText

            # Use the regular expression to extract the Procdump version from the <h1> text
            $matches = [regex]::Matches($h1Text, $regexPattern)

            # The version number should be in the first capturing group of the first match
            $PDonlineVersion = $matches[0].Groups[1].Value

            if ($PDonlineVersion -and ([version]$PDonlineVersion -gt [version]$global:msrdProcDumpVer)) {

                if ($global:msrdProcDumpVer -eq "1.0") {
                    $PDnotice = "This MSRD-Collect version is missing ProcDump.exe.`nIt is recommended to redownload the full MSRD-Collect (or TSSv2) package or download the latest version of ProcDump ($PDonlineVersion) from SysInternals.`nDo you want to download ProcDump from SysInternals now?"
                } else {
                    $PDnotice = "This MSRD-Collect version comes with ProcDump version $global:msrdProcDumpVer.`nA newer version of ProcDump ($PDonlineVersion) from SysInternals is available for download.`nDo you want to update the local ProcDump version now?"
                }
                
                $PDresult = [System.Windows.Forms.MessageBox]::Show($PDnotice, "New ProcDump version available", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    
                if ($PDresult -eq [System.Windows.Forms.DialogResult]::Yes) {
                    $PDzipFile = Join-Path $env:TEMP 'Procdump.zip'
                    $PDdownloadUrl = 'https://download.sysinternals.com/files/Procdump.zip'
                    Invoke-WebRequest -Uri $PDdownloadUrl -OutFile $PDzipFile
                    $PDunzippedFolder = Join-Path $env:TEMP 'Procdump'
                    Expand-Archive -Path $PDzipFile -DestinationPath $PDunzippedFolder -Force
                    msrdCreateLogFolder -msrdLogFolder "$global:msrdScriptpath\Tools" -TimeStamp No

                    Copy-Item -Path (Join-Path $PDunzippedFolder "procdump.exe") -Destination $global:msrdToolsFolder -Force
                    $global:msrdProcDumpExe = "$global:msrdScriptpath\Tools\procdump.exe"
                    Remove-Item $PDzipFile
                    Remove-Item $PDunzippedFolder -Recurse -Force

                    #update procdump version in .cfg file
                    msrdUpdateConfigFile -configFile "MSRD-Collect.cfg" -key "ProcDumpVersion" -value $PDonlineVersion
                    $global:msrdProcDumpVer = $PDonlineVersion

                    $PDdownloadmsg = "ProcDump version $PDonlineVersion has been downloaded and extracted to $global:msrdToolsFolder`nConfig file has been updated"
                    if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                        msrdAdd-OutputBoxLine $PDdownloadmsg -Color Yellow
                    } else {
                        msrdLogMessage Info $PDdownloadmsg
                    }
                } else {
                    if ($global:msrdProcDumpVer -eq "1.0") {
                        $noPDdownloadmsg = "You have chosen not to download the latest available ProcDump version ($PDonlineVersion) from SysInternals. It will not be possible to collect process dumps using MSRD-Collect"
                    } else {
                        $noPDdownloadmsg = "You have chosen not to download the latest available ProcDump version ($PDonlineVersion) from SysInternals. The current, local version $global:msrdProcDumpVer will be used when needed"
                    }
                    if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                        msrdAdd-OutputBoxLine $noPDdownloadmsg -Color Yellow
                    } else {
                        msrdLogMessage Info $noPDdownloadmsg
                    }
                }

            } else {
                if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                    msrdAdd-OutputBoxLine ("ProcDump version is up to date ($global:msrdProcDumpVer)") -Color Yellow
                } else {
                    msrdLogMessage Info ("ProcDump version is up to date ($global:msrdProcDumpVer)")
                }
            }
        } else {
            $global:msrdSetWarning = $true
            msrdLogMessage DiagFileOnly -Type "Text" -col 3 -Message "ProcDump version information could not be retrieved." -circle "red"
        }
    } catch {
        $global:aucfail = $true
        $failedCommand = $_.InvocationInfo.Line.TrimStart()
        $errorMessage = $_.Exception.Message.TrimStart()
        if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
        } else {
            msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
        }
    }
}

function msrdProcDumpVerCheck {

    if ($global:msrdProcDumpExe -eq "") {
        $noPDmsg = "ProcDump.exe could not be found. It will not be possible to collect a Process Dump through MSRD-Collect unless ProcDump.exe is available."
        if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            msrdAdd-OutputBoxLine $noPDmsg -Color Yellow
        } else {
            msrdLogMessage Info $noPDmsg
        }
    }

    msrdGetSysInternalsProcDump

    if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) { msrdAdd-OutputBoxLine ("`n") } else { Write-Host "`n" }
}
#endregion initialization

#region messages
Function msrdLogMessage {
    param([LogLevel] $Level = [LogLevel]::Normal, [string] $Message, [string] $Color)
    
    If (!(Test-Path -Path $global:msrdLogDir)) { msrdCreateLogFolder $global:msrdLogDir }

    $global:msrdPerc = "{0:P}" -f ($global:msrdProgress/100)

    $LogConsole = $True

    switch ($Level) {
        ([LogLevel]::Normal) { $MessageColor = 'White' }
        ([LogLevel]::Info) { $MessageColor = 'Yellow' }
        ([LogLevel]::Warning) { $MessageColor = 'Magenta' }
        ([LogLevel]::Error) { $MessageColor = 'Red'; $LogConsole = $False }
        ([LogLevel]::ErrorLogFileOnly) { $LogConsole = $False }
        ([LogLevel]::WarnLogFileOnly) { $LogConsole = $False }
    }

    if ($Color) { $MessageColor = $Color }

    # In case of Warning/Error/Debug, add line and function name to message.
    If($Level -eq 'Warning' -or $Level -eq 'Error' -or $Level -eq 'Debug' -or $Level -eq 'ErrorLogFileOnly' -or $Level -eq 'WarnLogFileOnly'){
        $CallStack = Get-PSCallStack
        $CallerInfo = $CallStack[0]
        if ($CallerInfo.FunctionName -like "*msrdLogMessage") { $CallerInfo = $CallStack[1] }
        if ($CallerInfo.FunctionName -like "*msrdLogException") { $CallerInfo = $CallStack[2] }
        $FuncName = $CallerInfo.FunctionName
        If ($FuncName -eq "<ScriptBlock>") { $FuncName = "Main" }

        $LogMessage = ((Get-Date).ToString("yyyyMMdd HH:mm:ss.fff") + ': [' + $FuncName + '(' + $CallerInfo.ScriptLineNumber + ')] ' + $Message)
    } else {
        $LogMessage = (Get-Date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $Message
    }

    if ($Level -eq 'Normal') {
        [decimal]$global:msrdProgress = $global:msrdProgress + $global:msrdProgstep

        if (!(($global:msrdGUIform -and $global:msrdGUIform.Visible)) -and ($global:msrdCollecting -or $global:msrdDiagnosing)) {
            Write-Progress -Activity "$(msrdGetLocalizedText "collecting1") $global:msrdProgScenario $(msrdGetLocalizedText "collecting2")" -Status "$global:msrdPerc complete:" -PercentComplete $global:msrdProgress
        } elseif (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            if (($global:msrdCollecting) -and !($global:msrdDiagnosing)) {
                $global:msrdProgbar.PerformStep()
                $global:msrdStatusBar.Text = "$(msrdGetLocalizedText "collecting1") $global:msrdProgScenario $(msrdGetLocalizedText "collecting2")"
            } elseif ($global:msrdVersioncheck) {
                $global:msrdStatusBar.Text = msrdGetLocalizedText "checkupd"
            }

            if (!($global:msrdCollecting) -and !($global:msrdDiagnosing) -and !($global:msrdVersioncheck)) {
                $global:msrdStatusBar.Text = msrdGetLocalizedText "Ready"
            }
        }
    }

    # In case of Error, log to error file
    If(($Level -eq 'Error') -or ($Level -eq 'ErrorLogFileOnly')) {
        $LogMessage | Out-File -Append $global:msrdErrorLogFile
    }

    if ($LogConsole) {
        If (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            $global:msrdPsBox.SelectionStart = $global:msrdPsBox.TextLength
            $global:msrdPsBox.SelectionLength = 0
            $global:msrdPsBox.SelectionColor = $MessageColor
            $global:msrdPsBox.AppendText("$LogMessage`r`n")
            $global:msrdPsBox.ScrollToCaret()
        } else {
            Write-Host $LogMessage -ForegroundColor $MessageColor
        }
        $LogMessage | Out-File -Append $global:msrdOutputLogFile
    }

    if ($Level -eq 'WarnLogFileOnly') { $LogMessage | Out-File -Append $global:msrdOutputLogFile }

}

Function msrdLogException {
    param([parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][String]$Message, [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][System.Management.Automation.ErrorRecord]$ErrObj, [Bool]$fErrorLogFileOnly)

    $ErrorCode = "0x" + [Convert]::ToString($ErrObj.Exception.HResult,16)
    $ExternalException = [System.ComponentModel.Win32Exception]$ErrObj.Exception.HResult
    $ErrorMessage = $Message + "`n" `
        + "Command/Function: " + $ErrObj.CategoryInfo.Activity + " failed with $ErrorCode => " + $ExternalException.Message + "`n" `
        + $ErrObj.CategoryInfo.Reason + ": " + $ErrObj.Exception.Message + "`n" `
        + "ScriptStack:" + "`n" `
        + $ErrObj.ScriptStackTrace `
        + "`n`n"

    If ($fErrorLogFileOnly) { msrdLogMessage ErrorLogFileOnly $ErrorMessage } Else { msrdLogMessage Error $ErrorMessage }
}
#endregion messages

#region progress
Function msrdProgressStatusInit {
    Param($global:msrdDivider)

    $global:msrdProgress = 1
    $global:msrdProgstep = 99/$msrdDivider
    $global:msrdPerc = 1
    if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
        $global:msrdProgbar.Value = 1
        $global:msrdProgbar.Minimum = 1
        $global:msrdProgbar.Maximum = $msrdDivider
    }
}

Function msrdProgressStatusEnd {

    $global:msrdProgress = 100
    $global:msrdPerc = 100
}
#endregion progress

#region versioncheck
Function msrdVersionInt($verString) {
    $verSplit = $verString -split '\.'
    $vFull = 0
    for ($i = 0; $i -lt $verSplit.Count; $i++) {
        $vFull = ($vFull * 256) + [int]$verSplit[$i]
    }
    return $vFull
}

Function msrdCheckVersion($verCurrent) {
    $global:aucfail = $false

    if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
        $global:msrdStatusBar.Text = msrdGetLocalizedText "wait"
        msrdAdd-OutputBoxLine "$(msrdGetLocalizedText "vercheck1")"
    } else {
        msrdLogMessage Normal "Checking if a new version is available (please wait)"
    }
    try {
        $global:msrdVersioncheck = $true
        $WebClient = New-Object System.Net.WebClient
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $verNew = $WebClient.DownloadString('https://cesdiagtools.blob.core.windows.net/windows/MSRD-Collect.ver')
        $verNew = $verNew.TrimEnd([char]0x0a, [char]0x0d)
        [long] $lNew = msrdVersionInt($verNew)
        [long] $lCur = msrdVersionInt($verCurrent)
        if($lNew -gt $lCur) {
            if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                $global:msrdGUIform.Text = 'MSRD-Collect (v' + $verCurrent + ') - $(msrdGetLocalizedText "vercheck2")'
            }

            $updnotice = "$(msrdGetLocalizedText "vercheck3"): v"+$verNew+" ($(msrdGetLocalizedText "vercheck4") v"+$verCurrent+").`n`n$(msrdGetLocalizedText "vercheck5")"
            $wshell = New-Object -ComObject Wscript.Shell
            $answer = $wshell.Popup("$updnotice",0,"$(msrdGetLocalizedText "vercheck6")",4+32)
            if ($answer -eq 6) {
                Write-Host "$(msrdGetLocalizedText "vercheck7")"
                Start-Process https://aka.ms/MSRD-Collect
                msrdCleanUpandExit
            } else {
                if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                    msrdAdd-OutputBoxLine ("$(msrdGetLocalizedText "vercheck8")") -Color Yellow
                } else {
                    msrdLogMessage Info ("$(msrdGetLocalizedText "vercheck8")")
                }
            }
        } else {
            if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                msrdAdd-OutputBoxLine ("$(msrdGetLocalizedText "vercheck9") (v"+$verCurrent+")") -Color Yellow
            } else {
                msrdLogMessage Info  ("$(msrdGetLocalizedText "vercheck9") (v"+$verCurrent+")")
            }
        }
    } catch {
        $global:aucfail = $true
        $failedCommand = $_.InvocationInfo.Line.TrimStart()
        $errorMessage = $_.Exception.Message.TrimStart()
        if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
            msrdAdd-OutputBoxLine ("Error in $failedCommand $errorMessage") "Magenta"
        } else {
            msrdLogMessage Warning ("Error in $failedCommand $errorMessage")
        }
    }

    msrdProcDumpVerCheck

    if ($global:aucfail) {
        $disupd = "Automatic update check failed, possibily due to limited or no internet connection.`n`nWould you like to disable automatic update check?`n`nYou can always enabled it again from the Tools menu (Check for Update on launch)."
        $dushell = New-Object -ComObject Wscript.Shell
        $duanswer = $dushell.Popup("$disupd",0,"Disable automatic update check",4+48)
        if ($duanswer -eq 6) {
            msrdUpdateConfigFile -configFile "MSRD-Collect.cfg" -key "AutomaticVersionCheck" -value 0
            $global:msrdAutoVerCheck = 0
            if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                msrdAdd-OutputBoxLine "Automatic update check on script launch is Disabled`n"
                $global:AutoVerCheckMenuItem.Checked = $false
            } else {
                msrdLogMessage Info ("Automatic update check on script launch is Disabled`n")
            }
        } else {
            msrdUpdateConfigFile -configFile "MSRD-Collect.cfg" -key "AutomaticVersionCheck" -value 1
            $global:msrdAutoVerCheck = 1
            if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                msrdAdd-OutputBoxLine "Automatic update check on script launch is Enabled`n"
                $global:AutoVerCheckMenuItem.Checked = $true
            } else {
                msrdLogMessage Info ("Automatic update check on script launch is Enabled`n")
            }
        }
    }

    if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
        $global:msrdStatusBar.Text = msrdGetLocalizedText "Ready"
    }

    $global:msrdVersioncheck = $false
}
#endregion versioncheck

#region collecting
Function msrdTestRegistryValue {
    param ([parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Path, [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Value)

    try {
        return (Get-ItemProperty -Path $Path -ErrorAction Stop).$Value -ne $null
    }
    catch {
        return $false
    }
}

Function msrdRunCommands {
    param($LogPrefix, $CmdletArray, [Bool]$ThrowException, [Bool]$ShowMessage, [Bool]$ShowError = $False)

    ForEach($CommandLine in $CmdletArray){
        $tmpMsg = $CommandLine -replace "\| Out-File.*$","" -replace "\| Out-Null.*$","" -replace "\-ErrorAction Stop","" -replace "\-ErrorAction SilentlyContinue",""
        $CmdlineForDisplayMessage = $tmpMsg -replace "2>&1",""
        Try{
            If ($ShowMessage) { msrdLogMessage Normal ("[$LogPrefix] $CmdlineForDisplayMessage") }

            # There are some cases where Invoke-Expression does not reset $LASTEXITCODE and $LASTEXITCODE has old error value. Hence initialize the powershell managed value manually...
            $LASTEXITCODE = 0

            # Run actual command here. Redirect all streams to temporary error file as some commands output an error to warning stream(3) and others are to error stream(2).
            Invoke-Expression -Command $CommandLine -ErrorAction Stop *> $global:msrdTempCommandErrorFile

            # It is possible $LASTEXITCODE becomes null in some sucessful case, so perform null check and examine error code.
            if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
                $Message = "An error happened during running `'$CommandLine` " + '(Error=0x' + [Convert]::ToString($LASTEXITCODE,16) + ')'
                msrdLogMessage ErrorLogFileOnly $Message
                If (Test-Path -Path $global:msrdTempCommandErrorFile) {
                    # Always log error to error file.
                    Get-Content $global:msrdTempCommandErrorFile -ErrorAction SilentlyContinue | Out-File -Append $global:msrdErrorLogFile
                    # If -ShowError:$True, show the error to console.
                    If ($ShowError) {
                        Write-Host ("Error happened in $CommandLine.") -ForegroundColor Red
                        Write-Host ('---------- ERROR MESSAGE ----------')
                        Get-Content $global:msrdTempCommandErrorFile -ErrorAction SilentlyContinue
                        Write-Host ('-----------------------------------')
                    }
                }
                Remove-Item $global:msrdTempCommandErrorFile -Force -ErrorAction SilentlyContinue | Out-Null
                If ($ThrowException) { Throw($Message) }
            } Else {
                Remove-Item $global:msrdTempCommandErrorFile -Force -ErrorAction SilentlyContinue | Out-Null
            }

        } Catch {
            If ($ThrowException) {
                Throw $_   # Leave the error handling to upper function.
            } Else {
                $Message = "An error happened in Invoke-Expression with $CommandLine"
                msrdLogException ($Message) -ErrObj $_ $fLogFileOnly
                If ($ShowError){
                    Write-Host ("ERROR: $Message") -ForegroundColor Red
                    Write-Host ('---------- ERROR MESSAGE ----------')
                    Write-Host $_
                    Write-Host ('-----------------------------------')
                }
                Continue
            }
        }
    }
}

function msrdCollectData {
    param([bool[]]$varsCore, [bool[]]$varsProfiles, [bool[]]$varsActivation, [bool[]]$varsMSRA, [bool[]]$varsSCard, [bool[]]$varsIME, [bool[]]$varsTeams, [bool[]]$varsMSIXAA, [bool[]]$varsHCI, [bool]$traceNet, [bool]$onlyDiag, [bool]$dumpProc, [int]$pidProc)

    if (!($onlyDiag)) {
        Import-Module -Name "$global:msrdScriptpath\Modules\MSRDC-CommonsCollect" -DisableNameChecking -Force -Scope Global

        $global:msrdCollecting = $True
        $global:msrdDiagnosing = $False

        if ($traceNet) {
            $global:msrdProgScenario = "Tracing"
            Import-Module -Name "$global:msrdScriptpath\Modules\MSRDC-Tracing" -DisableNameChecking -Force
            msrdRunUEX_NetTracing
            Remove-Module MSRDC-Tracing
        }

        if ($true -in $varsCore) {
            $global:msrdProgScenario = "Core"
            Import-Module -Name "$global:msrdScriptpath\Modules\MSRDC-Html" -DisableNameChecking -Force -Scope Global
            Import-Module -Name "$global:msrdScriptpath\Modules\MSRDC-Core" -DisableNameChecking -Force
            msrdCloseMSRDC
            msrdCollectUEX_AVDCoreLog -varsCore $varsCore -dumpProc $dumpProc -pidProc $pidProc
            Remove-Module MSRDC-Core
        }

        if ($true -in $varsProfiles) {
            $global:msrdProgScenario = "Profiles"
            Import-Module -Name "$global:msrdScriptpath\Modules\MSRDC-Profiles" -DisableNameChecking -Force
            msrdCollectUEX_AVDProfilesLog -varsProfiles $varsProfiles
            Remove-Module MSRDC-Profiles
        }
        if ($true -in $varsActivation) {
            $global:msrdProgScenario = "Activation"
            Import-Module -Name "$global:msrdScriptpath\Modules\MSRDC-Activation" -DisableNameChecking -Force
            msrdCollectUEX_AVDActivationLog -varsActivation $varsActivation
            Remove-Module MSRDC-Activation
        }
        if ($true -in $varsMSRA) {
            $global:msrdProgScenario = "Remote Assistance"
            Import-Module -Name "$global:msrdScriptpath\Modules\MSRDC-MSRA" -DisableNameChecking -Force
            msrdCollectUEX_AVDMSRALog -varsMSRA $varsMSRA
            Remove-Module MSRDC-MSRA
        }
        if ($true -in $varsSCard) {
            $global:msrdProgScenario = "Smart Card"
            Import-Module -Name "$global:msrdScriptpath\Modules\MSRDC-SCard" -DisableNameChecking -Force
            msrdCollectUEX_AVDSCardLog -varsSCard $varsSCard
            Remove-Module MSRDC-SCard
        }
        if ($true -in $varsIME) {
            $global:msrdProgScenario = "IME"
            Import-Module -Name "$global:msrdScriptpath\Modules\MSRDC-IME" -DisableNameChecking -Force
            msrdCollectUEX_AVDIMELog -varsIME $varsIME
            Remove-Module MSRDC-IME
        }
        if ($true -in $varsTeams) {
            $global:msrdProgScenario = "Teams"
            Import-Module -Name "$global:msrdScriptpath\Modules\MSRDC-Teams" -DisableNameChecking -Force
            msrdCollectUEX_AVDTeamsLog -varsTeams $varsTeams
            Remove-Module MSRDC-Teams
        }
        if ($true -in $varsMSIXAA) {
            $global:msrdProgScenario = "MSIX App Attach"
            Import-Module -Name "$global:msrdScriptpath\Modules\MSRDC-MSIXAA" -DisableNameChecking -Force
            msrdCollectUEX_AVDMSIXAALog -varsMSIXAA $varsMSIXAA
            Remove-Module MSRDC-MSIXAA
        }
        if ($true -in $varsHCI) {
            $global:msrdProgScenario = "Azure Stack HCI"
            Import-Module -Name "$global:msrdScriptpath\Modules\MSRDC-HCI" -DisableNameChecking -Force
            msrdCollectUEX_AVDHCILog -varsHCI $varsHCI
            Remove-Module MSRDC-HCI
        }

        msrdLogMessage Info -Message "$(msrdGetLocalizedText "fdcmsg")`n" -Color "Cyan"
        Remove-Module MSRDC-CommonsCollect
    }

    [System.GC]::Collect()

    $global:msrdCollecting = $False
}

Function msrdCollectDataDiag {
    param ([bool[]]$varsSystem, [bool[]]$varsAVDRDS, [bool[]]$varsInfra, [bool[]]$varsAD, [bool[]]$varsNET, [bool[]]$varsLogSec, [bool[]]$varsIssues, [bool[]]$varsOther)

    if (-not (Get-Module -Name MSRDC-Html)) {
        Import-Module -Name "$global:msrdScriptpath\Modules\MSRDC-Html" -DisableNameChecking -Force -Scope Global
    }

    $global:msrdDiagnosing = $True
    $global:msrdProgScenario = "Diagnostics"
    Import-Module -Name "$global:msrdScriptpath\Modules\MSRDC-Diag" -DisableNameChecking -Force
    msrdRunUEX_RDDiag -varsSystem $varsSystem -varsAVDRDS $varsAVDRDS -varsInfra $varsInfra -varsAD $varsAD -varsNET $varsNET -varsLogSec $varsLogSec -varsIssues $varsIssues -varsOther $varsOther

    "`n`n" | Out-File -Append $global:msrdOutputLogFile
    
    msrdLogMessage Info "$(msrdGetLocalizedText "fdiagmsg")`n" -Color "Cyan"

    $global:msrdDiagnosing = $False
    if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
        $global:msrdProgbar.Value = $global:msrdProgbar.Maximum;
        $global:msrdStatusBar.Text = "$(msrdGetLocalizedText "wait")"
    }

    Remove-Module MSRDC-Html
}

Function msrdArchiveData {
    param( [bool[]]$varsCore )

    $mspathnfo = $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "Msinfo32.nfo"
    $dllpath = $global:msrdSysInfoLogFolder + $global:msrdLogFilePrefix + "System32_DLL.txt"
    $acttime = 0
    $waittime = 20000
    $maxtime = 180000
    $nfoproc = Get-Process msinfo32 -ErrorAction SilentlyContinue

    if (!($onlyDiag)) {
        $global:msrdDiagnosing = $True

        while ($varsCore[7] -and (!(Test-Path $mspathnfo) -or !(Test-Path $dllpath) -or ($nfoproc))) {
            if ($acttime -lt $maxtime) {
                msrdLogMessage Normal -Message "$(msrdGetLocalizedText "bgjob1msg")" -Color "White"
                Start-Sleep -m $waittime
                $acttime += $waittime
                $nfoproc = Get-Process msinfo32 -ErrorAction SilentlyContinue
            } else {
                msrdLogMessage Warning -Message "$(msrdGetLocalizedText "bgjob2msg")`n"
                $nfoproc = Get-Process msinfo32 -ErrorAction SilentlyContinue
                if ($nfoproc) {
                    $nfoproc.CloseMainWindow() | Out-Null
                }
                Start-Sleep 5
                if (!$nfoproc.HasExited) { $nfoproc | Stop-Process -Force }
                Break
            }
        }
        Get-Job | Wait-Job | Remove-Job
        $global:msrdDiagnosing = $False
    }

    $destination = $global:msrdLogRoot + "\" + $msrdLogFolder + ".zip"

    msrdLogMessage Info "$(msrdGetLocalizedText "archmsg")" -Color "Cyan"

    Try {
        Compress-Archive -Path $global:msrdLogDir -DestinationPath $destination -CompressionLevel Optimal -Force
    } Catch {
		$ErrorMessage = 'An exception occurred during log folder compression' + "`n" + $_.Exception.Message
		msrdLogException $ErrorMessage $_ $fLogFileOnly
		Return
	}

    if (Test-path -path $destination) {
            if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
                msrdLogMessage Normal "$(msrdGetLocalizedText "zipmsg") $destination`n" -Color "#00ff00"
            } else {
                msrdLogMessage Normal "$(msrdGetLocalizedText "zipmsg") $destination`n" -Color "Green"
            }
        } else {
            msrdLogMessage Warning "$(msrdGetLocalizedText "ziperrormsg") $global:msrdLogRoot\$msrdLogFolder`n"
        }
        msrdLogMessage Normal "$(msrdGetLocalizedText "dtmmsg")`n" -Color "White"

    Remove-Module MSRDC-Diag -ErrorAction SilentlyContinue

    explorer $global:msrdLogRoot

    if (($global:msrdGUIform -and $global:msrdGUIform.Visible)) {
        $global:msrdStatusBar.Text = msrdGetLocalizedText "Ready"
        $global:msrdCollectcount = 1
    }

    [System.GC]::Collect()
}

function msrdUpdateConfigFile {
    Param([string]$configFile,[string]$key,[string]$value)

    (Get-Content $configFile) | ForEach-Object {
        if ($_ -like "$key=*") {
            $_ = "$key=" + $value
        }
        $_
    } | Set-Content $configFile
}

#endregion collecting

Export-ModuleMember -Function *
# SIG # Begin signature block
# MIInoQYJKoZIhvcNAQcCoIInkjCCJ44CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBuYeXp5peS7Eu2
# ateBOThdWZC8nDS+xJbfZV1LwAytM6CCDYUwggYDMIID66ADAgECAhMzAAADTU6R
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
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGXIwghluAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAANNTpGmGiiweI8AAAAA
# A00wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINre
# dN+eOywGBfBg19GaPny/flh2IQzzfTs+ZE9sWAmcMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAJWb7sCIUF/UAxXhFO/c1MVal7fjy8/pNw3Z1
# MxFEmv0iomDpxKIaui0Zr62bkDOr5rYlSZHDnyH4Wy+27D2q1y4nlbyqOmkDlBLx
# hDaFXU4HSosIybWo5YZXJnpvx3L34RHFlJ40RwBEGp5QE2babPq09gVxJlFr0Gp/
# v6lID4asRp85Cxx2WiCn/5K8XAUDpsUIAWu3BAZunmYJatASTEYtyG5jpPQSmgWE
# szc6g/VkxPDamlxx6n+qE1qsJk3ylfcZwykiHo6C1YcVCCimUYnLLrSKFrUSqg5m
# soGgEZ/Etty3tmgaHqA5r3HT3MUXQ35eiUy5A7vhtbjGWkfR/aGCFvwwghb4Bgor
# BgEEAYI3AwMBMYIW6DCCFuQGCSqGSIb3DQEHAqCCFtUwghbRAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFPBgsqhkiG9w0BCRABBKCCAT4EggE6MIIBNgIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCAVTlQAPBYDbeLPnIK4okF4WLef6VQ/dOOa
# s0CUJxAgUgIGZGzBYiTqGBEyMDIzMDUyMzE0NDQ1MS45WjAEgAIB9KCB0KSBzTCB
# yjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMc
# TWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRT
# UyBFU046REQ4Qy1FMzM3LTJGQUUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFNlcnZpY2WgghFVMIIHDDCCBPSgAwIBAgITMwAAAcUDzc0hofTvOQABAAAB
# xTANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAe
# Fw0yMjExMDQxOTAxMzJaFw0yNDAyMDIxOTAxMzJaMIHKMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmlj
# YSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpERDhDLUUzMzct
# MkZBRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKtIXbO9Hl9tye6WqaWil0Yc/k0+
# ySdzr1X9/jfHzacUbOY2OIRL9wVf8ORFl22XTuJt8Y9NZUyP8Q5KvsrY7oj3vMRl
# 7GcQ57b+y9RMzHeYyEqifnmLvJIFdOepqrPHQaOecWTzz3MX+btfc59OGjEBeT11
# fwuGS0oxWvSBTXK4m3Tpt5Rlta0ERWto1LLqeoL+t+KuVMB9PVhhrtM/PUW7W8jO
# eb5gYFlfHnem2Qma3KGCIzC/BUU7xpc56puh7cGXVzMCh092v5C1Ej4hgLKyIBM8
# +zaQaXjrILPU68Mlk2QTWwcMiAApkN+I/rkeHrdoWZPjR+PSoRCcmA9vnTiGgxgd
# hFDRUmHMtTJILWbdXkagQdJvmD2M+x46HD8pCmDUGe07/s4JTn3womsdYzm9LuiG
# AuV9Sa/AME3LGg8rt6gIcfHBUDfQw4IlWcPlERWfKMqA5OrCFdZ8ec2S8voTbWpH
# j1/Uu2PJ9alnwI6FzxOitP3W08POxDiS/wZSRnCqBU8ra9Mz4PzDSUm+n9mv8A5F
# 6BghliYkKxk8Yzj/kfev5yCBtOXhNS6ZMthTnWDDweA4Vu7QXWWrrXqU07koZoJ/
# hihEfAKANYEkpNRAuWV+HKaVZ4CaW5TAbvK/7QoXx1XV74mOoQ0oR8EApmamXm4E
# mB5x5eLqxPuCumQvAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUVOq7OL9ZsTWBv67a
# S8K1cHpNBWswHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0f
# BFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwv
# TWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsG
# AQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAx
# MCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkq
# hkiG9w0BAQsFAAOCAgEAjKjefH6zBzknHIivgnZ6+nSvH07IEA3mfW70IwrsTSCW
# SfdvsaXikQn916uO6nUcpJClJ2QunR4S8LdX4cMosvy33VUPcn9YWGf0aU0vs9IZ
# 2qCvj/yAwIlDZt9jVy4QwbtD+Em/7gleIzrjVHJiYaaQUIEFYRcf+eyWJNSwnYyH
# nv/xq3H25ELYmKG/Tmvdw0o27A9Y6monBJ5HJVDf5hJvWbJwpwNfvzkA6f/EOHD3
# x/eCzOCel9DbTQXlcsL1h9MLjGjicx4AywniVJBRPRxPLAQ1XnZo+szyQCPu6My4
# 2KsO4uERW4krX1mUho8LfpSyUGUVlAnE92h2L06NWFg2bJKIVoO+8PXxdkG4jvQ3
# 56qGe0KMx4u0Yj6W44JCTAIa4aXk3/2rdnvfh2JCjm1JoDwKx9Vo4r8JtXez2FrG
# qy+7uambpN+hm9ZhE0taANl19/gt64Lc0aIT/PamVX+/ZVb45oN+DbSAiv6TJPfU
# gbrYIbYqRUjEHW11J0tqHi7fXCrr9TCbvoCfN6l0zZENkKocbTUb2xPUKpqiUMOV
# Vv+Emc3taT18cjkzucg6vokSFLm6nkM5lHApIsjbgix1ofDiwiOZiDgtYi7VQ39p
# cPXlq6KcLuUgybU/2cKiFNam9lPjY5DXI9YWzgwURC2k01nfdUSYlCPZ3CZBoP4w
# ggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUA
# MIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQD
# EylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0y
# MTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0
# ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveV
# U3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTI
# cVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36M
# EBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHI
# NSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxP
# LOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2l
# IH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDy
# t0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymei
# XtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1
# GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgV
# GD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQB
# gjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTu
# MB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsG
# AQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUH
# AwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
# EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQAD
# ggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/
# 2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvono
# aeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRW
# qveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8Atq
# gcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7
# hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkct
# wRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu
# +yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FB
# SX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/
# Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ
# 8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICzDCCAjUCAQEw
# gfihgdCkgc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOkREOEMtRTMzNy0yRkFFMSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQAhABr2F2SSu3FK
# Otvi7xGEBMe/56CBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MA0GCSqGSIb3DQEBBQUAAgUA6Bc/4jAiGA8yMDIzMDUyMzIxMzYzNFoYDzIwMjMw
# NTI0MjEzNjM0WjB1MDsGCisGAQQBhFkKBAExLTArMAoCBQDoFz/iAgEAMAgCAQAC
# AwOUQjAHAgEAAgISDDAKAgUA6BiRYgIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUA
# A4GBAAMvUTXNS1bqdS0fNIvo+Li+9Ob3E5JRt2y/F0Y4Vkb9CMv7YQiuiiS5+MyZ
# ZSWcoSm+d1V6YAfce/nDfeY71l5c81Z05/IhCZKxcI1Y+PcFFpu4KBGM7LHzEcLz
# bU/HCwCoYHNoJs4p5TmCKXsII+gM4NJ4ytXtvP3OjllkoFJXMYIEDTCCBAkCAQEw
# gZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHFA83NIaH07zkA
# AQAAAcUwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0B
# CRABBDAvBgkqhkiG9w0BCQQxIgQgXQamGWo8c4ujK6tpN3sI8IsUIuj3BF9tluzW
# +eVNtpgwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAZAbGR9iR3TAr5XT3A
# 7Sw76ybyAAzKPkS4o+q81D98sTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABxQPNzSGh9O85AAEAAAHFMCIEIJATfDCQ9fxxPtBEGH1M
# ffotRlgpBN3Va/XoWjRk4ZgaMA0GCSqGSIb3DQEBCwUABIICAC/uOzc8JSxh209w
# +hN+LTpLSz3/3feQ3hjpJG08P+zETqGC3LW/ckoKao0Vriz7Q1kradxNrjYQ8Xim
# IGsbOpAmPgmkFV4vrNuS0WXNftjQZxy2y6Vp/XI+LbQSM9c9TWmvF+7ggRiuCVGv
# Z4j1zjJFno58Q5kWFjjBbimK1M++g/RBg2BKRzx8XSdd0ehrUyH9J/GCosvpj5SQ
# LFLBcehZV7CgSuk6uSyvWf4DzBJYfcCXM5QUXyq+W7PP+k7WDEgbp+XkAMD6C6WW
# mIvYSdRBuNOfcl7yZP3XI8kHF5XvRodtPqTQCMXsdgKXeXvmW7iM8hGxTa1hGp4n
# yuenz7ZtkYkOX1SXmLCYOVekvQYWmVewWvuw9GR8ps7ubOGQscz/tjjvV6rrvlbz
# 7fY3lfNyxINYNO5XVrVEZnxU8+pvlNgQ7i7BIvBEPu6J+Jfwf2p+T7F1h01KUKC9
# FNh3UUlTXzBg0+zQGVtCQI4Auf3di/rTOLJefjsEDxC9GwgRSCHctqM3YtQ622Od
# SRQlltJPGcuphfJgk0L0jwjWZCbO2GwYZn+xYSltZ2X1VJWkeSaw8V0U07Bl5t7e
# +0mudGF0UzNNSGK7fgwGUd9Jnx9qX3n+weZS/IDoKNXy1yluLhL/8QcEDaJ+IvcL
# AfpB6x+0JziS3Q9WiMH4uhgUVgZx
# SIG # End signature block
