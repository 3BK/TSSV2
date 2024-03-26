<#
.SYNOPSIS
   MSRD-Collect graphical user interface

.DESCRIPTION
   Module for the MSRD-Collect graphical user interface

.NOTES
   Authors    : Robert Klemencz (Microsoft) & Alexandru Olariu (Microsoft)
   Requires   : At least PowerShell 5.1 (This module is not for stand-alone use. It is used automatically from within the main MSRD-Collect.ps1 script)
   Version    : See MSRD-Collect.ps1 version
   Feedback   : Send an e-mail to MSRDCollectTalk@microsoft.com
#>


#region config variables
$varsCore = @(,$true * 9)
$vCore = $varsCore

$varsProfiles = @(,$true * 4)
$varsActivation = @(,$true * 3)
$varsMSRA = @(,$true * 5)
$varsSCard = @(,$true * 3)
$varsIME = @(,$true * 2)
$varsTeams = @(,$true * 2)
$varsMSIXAA = @(,$true * 1)
$varsHCI = @(,$true * 1)

$varsNO = $false

$varsSystem = @(,$true * 11)
$varsAVDRDS = @(,$true * 10)
$varsInfra = @(,$true * 6)
$varsAD = @(,$true * 2)
$varsNET = @(,$true * 5)
$varsLogSec = @(,$true * 2)
$varsIssues = @(,$true * 2)
$varsOther = @(,$true * 4)

$dumpProc = $False; $pidProc = ""
$traceNet = $False; $onlyDiag = $false

Function msrdInitMachines {
    param ([bool[]]$Types = @($false, $false, $false))

    if ($Types[0]) { $global:msrdSource = $true; $global:msrdAVD = $False; $global:msrdRDS = $False }
    elseif ($Types[1]) { $global:msrdSource = $False; $global:msrdAVD = $true; $global:msrdRDS = $False }
    elseif ($Types[2]) { $global:msrdSource = $False; $global:msrdAVD = $False; $global:msrdRDS = $true }
    else {
        $global:msrdSource = $false; $global:msrdAVD = $false; $global:msrdRDS = $false
        if ($script:pidProc) {
            msrdAdd-OutputBoxLine "Previous PID selection reset - no process dump will be generated`n" "Yellow"
            $dumppidBox.SelectedValue = ""
            $script:pidProc = ""
        }
    }
}

Function msrdInitScenarioBtns {
    param ([System.Windows.Forms.ToolStripButton[]]$buttons,[bool]$isEnabled = $false,[bool]$isChecked = $false)

    foreach ($button in $buttons) {
        $button.Enabled = $isEnabled
        $button.BackColor = if ($isEnabled) {[System.Drawing.Color]::Lightblue} else {[System.Drawing.Color]::Lightgray}
        $button.CheckOnClick = $true
        $button.Checked = $isChecked
    }
}

function msrdToggleLangChecked($selectedLang) {

    $buttonList = @($TbLangEN, $TbLangDE, $TbLangFR, $TbLangHU, $TbLangIT, $TbLangPT, $TbLangRO)
    
    foreach ($button in $buttonList) {
        if ($button -ne $selectedLang) { $button.Checked = $false }
    }
    
    $selectedButton = $buttonList | where { $_ -eq $selectedLang }
    $selectedButton.Checked = $true
}
#endregion config variables


#region code
#Load dlls into context of the current console session
 Add-Type -Name Window -Namespace Console -MemberDefinition '
    [DllImport("Kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'

#icon extractor
$code = @"
using System;
using System.Runtime.InteropServices;

namespace System
{
    public class IconExtractor
    {
        public static System.Drawing.Icon Extract(string file, int number, bool largeIcon)
        {
            IntPtr large;
            IntPtr small;
            ExtractIconEx(file, number, out large, out small, 1);
            try
            {
                #if PSv5
                    return (System.Drawing.Icon)System.Drawing.Icon.FromHandle(largeIcon ? large : small).Clone();
                #else
                    var iconType = typeof(System.Drawing.Icon);
                    if (iconType.Assembly.GetType(iconType.FullName) == null)
                    {
                        var drawingCommonAssembly = System.Reflection.Assembly.Load("System.Drawing.Common");
                        iconType = drawingCommonAssembly.GetType("System.Drawing.Icon");
                    }
                    return (System.Drawing.Icon)System.Drawing.Icon.FromHandle(largeIcon ? large : small).Clone();
                #endif
            }
            catch
            {
                return null;
            }
        }

        [DllImport("Shell32.dll", EntryPoint = "ExtractIconExW", CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        private static extern int ExtractIconEx(string sFile, int iIndex, out IntPtr piLargeVersion, out IntPtr piSmallVersion, int amountIcons);
    }
}
"@

if ($PSVersionTable.PSVersion.Major -eq 5) {
    Add-Type -TypeDefinition $code -ReferencedAssemblies System.Drawing
} else {
    Add-Type -TypeDefinition $code -ReferencedAssemblies System.Drawing.Common,System.Drawing
}
#endregion code

#region GUI functions
Add-Type -AssemblyName System.Windows.Forms

Function msrdAdd-OutputBoxLine {
    param ([string[]]$Message,[System.Drawing.Color]$Color = [System.Drawing.Color]::White)

    foreach ($msg in $Message) {
        $line = "$msg`r`n"
        $global:msrdPsBox.SelectionStart = $global:msrdPsBox.TextLength
        $global:msrdPsBox.SelectionLength = 0
        $global:msrdPsBox.SelectionColor = $Color
        $global:msrdPsBox.AppendText($line)
        $global:msrdPsBox.ScrollToCaret()
        $global:msrdPsBox.Refresh()
    }
}

function msrdInitHowTo {

    # How To Steps
    $howToSteps = @("howtouse1", "howtouse2", "howtouse3") | ForEach-Object { msrdGetLocalizedText $_ }
    msrdAdd-OutputBoxLine ($howToSteps -join "`n`n")
    $global:msrdPsBox.ReadOnly = $true
}

function msrdResetOutputBox {
    $global:msrdPsBox.Clear()
    msrdInitScript -Type GUI
    msrdInitHowTo
    $global:msrdPsBox.Refresh()
    $global:msrdPsBox.ScrollToCaret()
}

function msrdStartShowConsole {
    param ($nocfg)

    try {
        $PSConsole = [Console.Window]::GetConsoleWindow()
        [Console.Window]::ShowWindow($PSConsole, 5) | Out-Null
        msrdAdd-OutputBoxLine "Console window is visible`n"
        $ConsoleMenuItem.Checked = $true
        if (!($nocfg)) {
            msrdUpdateConfigFile -configFile "MSRD-Collect.cfg" -key "ShowConsoleWindow" -value 1
        }
    } catch {
        msrdAdd-OutputBoxLine "Error showing console window: $($_.Exception.Message)"
    }
}

function msrdStartHideConsole {
    try {
        $PSConsole = [Console.Window]::GetConsoleWindow()
        [Console.Window]::ShowWindow($PSConsole, 0) | Out-Null
        msrdAdd-OutputBoxLine "Console window is hidden`n"
        $ConsoleMenuItem.Checked = $false
        msrdUpdateConfigFile -configFile "MSRD-Collect.cfg" -key "ShowConsoleWindow" -value 0
    } catch {
        msrdAdd-OutputBoxLine "Error hiding console window: $($_.Exception.Message)"
    }
}

Function msrdFind-Folder {
    Param ([ValidateScript({Test-Path $_ -PathType Container})][string]$DefaultFolder = 'C:\MSDATA\')

    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null

    $browse = New-Object System.Windows.Forms.FolderBrowserDialog
    $browse.SelectedPath = $DefaultFolder
    $browse.ShowNewFolderButton = $true
    $browse.Description = msrdGetLocalizedText "location1"

    $result = $browse.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $global:msrdLogRoot = $browse.SelectedPath
        msrdAdd-OutputBoxLine "$(msrdGetLocalizedText "location2") $global:msrdLogRoot`n" -Color Yellow
    }
    else {
        msrdAdd-OutputBoxLine "$(msrdGetLocalizedText "location2") $global:msrdLogRoot`n" -Color Yellow
        return
    }

    $browse.SelectedPath
    $browse.Dispose()
}

function msrdStartBtnCollect {
    if ($TbTeams.Checked) {
        $TeamsLogs = msrdGetLocalizedText "teamsnote"
        $wshell = New-Object -ComObject Wscript.Shell
        $teamstitle = msrdGetLocalizedText "teamstitle"
        $answer = $wshell.Popup("$TeamsLogs",0,"$teamstitle",5+48)
        if ($answer -eq 4) { $GetTeamsLogs = $false } else { $GetTeamsLogs = $true; $TbStart.Checked = $false }
    } else {
        $GetTeamsLogs = $false
    }

    if (-not $GetTeamsLogs) {
        $TbStart.Text = msrdGetLocalizedText "Running"
        msrdInitFolders

        msrdLogMessage WarnLogFileOnly "Script running from: $($global:msrdScriptpath)"
        msrdLogMessage WarnLogFileOnly "EULA accepted"
        msrdLogMessage WarnLogFileOnly "Notice accepted"
        msrdLogMessage WarnLogFileOnly "Output location: $($global:msrdLogRoot)"
        msrdLogMessage WarnLogFileOnly "User context: $($global:msrdUserprof)"
        msrdLogMessage WarnLogFileOnly "PID selected for process dump: $($script:pidselected)`n"

        switch ($true) {
            {$global:msrdRDS} { msrdLogMessage WarnLogFileOnly "'RDS' type selected`n" }
            {$global:msrdAVD} { msrdLogMessage WarnLogFileOnly "'AVD' type selected`n" }
            {$global:msrdSource} { msrdLogMessage WarnLogFileOnly "'Source' type selected`n" }
        }

        msrdCollectData -varsCore $script:vCore -varsProfiles $script:vProfiles -varsActivation $script:vActivation -varsMSRA $script:vMSRA -varsSCard $script:vSCard -varsIME $script:vIME -varsTeams $script:vTeams -varsMSIXAA $script:vMSIXAA -varsHCI $script:vHCI -traceNet $script:traceNet -onlyDiag $script:onlyDiag -dumpProc $script:dumpProc -pidProc $script:pidProc
        msrdCollectDataDiag -varsSystem $script:varsSystem -varsAVDRDS $script:varsAVDRDS -varsInfra $script:varsInfra -varsAD $script:varsAD -varsNET $script:varsNET -varsLogSec $script:varsLogSec -varsIssues $script:varsIssues -varsOther $script:varsOther
        msrdArchiveData -varsCore $script:vCore
        $TbStart.Text = msrdGetLocalizedText "Start"
        $TbStart.Checked = $false
    }
}

Function msrdRefreshUILang {
    Param ($id)

    $global:msrdLangID = $id

    $FileMenu.Text = msrdGetLocalizedText "FileMenu"
        $RunMenuItem.Text = msrdGetLocalizedText "RunMenu"
        $CheckUpdMenuItem.Text = msrdGetLocalizedText "UpdateMenu"
        $ExitMenuItem.Text = msrdGetLocalizedText "ExitMenu"

    $ViewMenu.Text = msrdGetLocalizedText "ViewMenu"
        $ConsoleMenuItem.Text = msrdGetLocalizedText "HideConsole"
        $ResultsMenuItem.Text = msrdGetLocalizedText "OutputLocation"

    $ToolsMenu.Text = msrdGetLocalizedText "ToolsMenu"
        $OutputMenuItem.Text = msrdGetLocalizedText "SetOutputLocation"
        $UserContextMenuItem.Text = msrdGetLocalizedText "SetUserContext"
        $ConfigCollectMenuItem.Text = msrdGetLocalizedText "ConfigDataCollection"
        $ConfigDiagMenuItem.Text = msrdGetLocalizedText "ConfigDiag"

    $HelpMenu.Text = msrdGetLocalizedText "HelpMenu"
        $ReadMeMenuItem.Text =  msrdGetLocalizedText "ReadMe"
        $WhatsNewMenuItem.Text = msrdGetLocalizedText "WhatsNew"
        $DownloadMenuItem.Text =  msrdGetLocalizedText "Download"
        $DocsMenuItem.Text = msrdGetLocalizedText "MSDocs"
        $DocsMenuItemAVD.Text = msrdGetLocalizedText "AVD"
        $DocsMenuItemRDS.Text = msrdGetLocalizedText "RDS"
        $DocsMenuItemW365.Text = msrdGetLocalizedText "365"
        $AzureMenuItem.Text = msrdGetLocalizedText "AzureMenu"
        $AzureMenuItemStatus.Text = msrdGetLocalizedText "AzStatus"
        $Feedback1MenuItem.Text = msrdGetLocalizedText "FeedbackEmail"
        $Feedback2MenuItem.Text = msrdGetLocalizedText "FeedbackSurvey"
        $AboutMenuItem.Text = msrdGetLocalizedText "About"

    $TbCore.Text = msrdGetLocalizedText "btnCore"
    $TbProfiles.Text = msrdGetLocalizedText "btnProfiles"
    $TbActivation.Text = msrdGetLocalizedText "btnActivation"
    $TbMSRA.Text = msrdGetLocalizedText "btnMSRA"
    $TbSCard.Text = msrdGetLocalizedText "btnSCard"
    $TbIME.Text = msrdGetLocalizedText "btnIME"
    $TbTeams.Text = msrdGetLocalizedText "btnTeams"
    $TbMSIXAA.Text = msrdGetLocalizedText "btnMSIXAA"
    $TbHCI.Text = msrdGetLocalizedText "btnHCI"
    $TbProcDump.Text = msrdGetLocalizedText "btnProcDump"
    $TbNetTrace.Text = msrdGetLocalizedText "btnNetTrace"
    $TbDiagOnly.Text = msrdGetLocalizedText "btnDiagOnly"
    $TbStart.Text = msrdGetLocalizedText "Start"

    $script:howtouse = msrdGetLocalizedText "howtouse"
    $script:initvalues1 = msrdGetLocalizedText "initvalues1"
    $script:initvalues2 = msrdGetLocalizedText "initvalues2"
    $script:initvalues3 = msrdGetLocalizedText "initvalues3"
    $script:initvalues4 = msrdGetLocalizedText "initvalues4"

    $surveyLink.Text = msrdGetLocalizedText "surveyLink1"
    $global:msrdStatusBar.Text = msrdGetLocalizedText "Ready"

    $dumppidForm.Text = msrdGetLocalizedText "dpidtext1"
    $script:defaultProc = msrdGetLocalizedText "dpidtext2"

    $userContextForm.Text = msrdGetLocalizedText "context1"
    $userContextLabel.Text = msrdGetLocalizedText "context2"

    $selectCollectForm.Text = msrdGetLocalizedText "selectCollect1"
    $selectCollectLabel.Text = msrdGetLocalizedText "selectCollect2"

    $selectDiagForm.Text = msrdGetLocalizedText "selectDiag1"
    $selectDiagLabel.Text = msrdGetLocalizedText "selectDiag2"

    $AzureMenuItemOutageNote.Text = msrdGetLocalizedText "AzOutageNotification"
    $AzureMenuItemStatus.Text = msrdGetLocalizedText "AzStatus"
    $AzureMenuItemStatusHist.Text = msrdGetLocalizedText "AzStatusHist"
    $AzureMenuItemServHealth.Text = msrdGetLocalizedText "AzServHealth"

    $DownloadMenuItem.Text = msrdGetLocalizedText "Download"
    $DownloadMenuItemMSRDC.Text = msrdGetLocalizedText "DownloadMSRDC"
    $DownloadMenuItemRDSTr.Text = msrdGetLocalizedText "DownloadRDSTracing"
    $DownloadMenuItemTSSv2.Text = msrdGetLocalizedText "DownloadTSSv2"

    $global:AutoVerCheckMenuItem.Text = msrdGetLocalizedText "AutoVerCheck"

    $ReportsMenuItem.Text = msrdGetLocalizedText "DiagReports"
}
#endregion GUI functions

Function msrdAVDCollectGUI {

    $global:msrdGUIform = New-Object System.Windows.Forms.Form

    $global:msrdGUIform.Width = 1000
    $global:msrdGUIform.Height = 730
    $global:msrdGUIform.StartPosition = "CenterScreen"
    $global:msrdGUIform.BackColor = "#eeeeee"
    $global:msrdGUIform.Icon = [System.IconExtractor]::Extract("mstsc.exe", 9, $true)
    $global:msrdGUIform.Text = 'MSRD-Collect (v' + $global:msrdVersion + ')'
    $global:msrdGUIform.TopLevel = $true
    $global:msrdGUIform.TopMost = $false

    $global:msrdGUIformMenu = new-object System.Windows.Forms.MenuStrip

    function msrdCreateMenu([string]$Text) {

        $Menu = New-Object System.Windows.Forms.ToolStripMenuItem
        $Menu.Text = msrdGetLocalizedText $Text
        $Menu.Add_MouseEnter({ $this.Owner.Cursor = [System.Windows.Forms.Cursors]::Hand })
        $Menu.Add_MouseLeave({ $this.Owner.Cursor = [System.Windows.Forms.Cursors]::Default })

        return $Menu
    }

    function msrdCreateMenuItem([System.Windows.Forms.ToolStripMenuItem]$Menu, [string]$Text, [System.Drawing.Icon]$Icon = $null) {

        if ($Text -eq "---") {
            $MenuItem = New-Object System.Windows.Forms.ToolStripSeparator
        } else {
            $MenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
            $MenuItem.Text = msrdGetLocalizedText $Text
            $MenuItem.Add_MouseEnter({ $this.Owner.Cursor = [System.Windows.Forms.Cursors]::Hand })
            $MenuItem.Add_MouseLeave({ $this.Owner.Cursor = [System.Windows.Forms.Cursors]::Default })   
            if ($Icon) { $MenuItem.Image = $Icon.ToBitmap() }
        }
        
        [void]$Menu.DropDownItems.Add($MenuItem)

        return $menuItem
    }

    #region File menu
    $FileMenu = msrdCreateMenu -Text "FileMenu"
    
    $RunMenuItem = msrdCreateMenuItem -Menu $FileMenu -Text "RunMenu" -Icon ([System.IconExtractor]::Extract("shell32.dll", 137, $true))
    $RunMenuItem.Enabled = $false
    $RunMenuItem.Add_Click({ msrdStartBtnCollect })

    $FileSeparator1 = msrdCreateMenuItem -Menu $FileMenu -Text "---"
    
    $CheckUpdMenuItem = msrdCreateMenuItem -Menu $FileMenu -Text "UpdateMenu" -Icon ([System.IconExtractor]::Extract("shell32.dll", 209, $true))
    $CheckUpdMenuItem.Add_Click({ msrdCheckVersion($msrdVersion) })

    $FileSeparator2 = msrdCreateMenuItem -Menu $FileMenu -Text "---"
    
    $ExitMenuItem = msrdCreateMenuItem -Menu $FileMenu -Text "ExitMenu" -Icon ([System.IconExtractor]::Extract("shell32.dll", 27, $true))
    $ExitMenuItem.Add_Click({
        $global:msrdCollectcount = 0
        If (($Null -ne $global:msrdTempCommandErrorFile) -and (Test-Path -Path $global:msrdTempCommandErrorFile)) { Remove-Item $global:msrdTempCommandErrorFile -Force | Out-Null }
        If ($fQuickEditCodeExist) { [DisableConsoleQuickEdit]::SetQuickEdit($False) | Out-Null }
        $global:msrdGUIform.Close()
    })
    #endregion File menu

    #region View menu
    $ViewMenu = msrdCreateMenu -Text "ViewMenu"

    $ConsoleMenuItem = msrdCreateMenuItem -Menu $ViewMenu -Text "HideConsole" -Icon ([System.IconExtractor]::Extract("shell32.dll", 76, $true))
    $ConsoleMenuItem.CheckOnClick = $True
    $ConsoleMenuItem.Add_Click({ if ($ConsoleMenuItem.Checked) { msrdStartShowConsole } else { msrdStartHideConsole } })

    $OnTopMenuItem = msrdCreateMenuItem -Menu $ViewMenu -Text "AlwaysOnTop" -Icon ([System.IconExtractor]::Extract("shell32.dll", 263, $true))
    $OnTopMenuItem.CheckOnClick = $True
    $OnTopMenuItem.Checked = $false
    $OnTopMenuItem.Add_Click({
        if ($OnTopMenuItem.Checked) {
            $global:msrdGUIform.TopMost = $true
            msrdAdd-OutputBoxLine "MSRD-Collect is set to be on top of other windows`n"
        } else {
            $global:msrdGUIform.TopMost = $false
            msrdAdd-OutputBoxLine "MSRD-Collect is no longer set to be on top of other windows`n"
        }
    })

    $ResultsMenuItem = msrdCreateMenuItem -Menu $ViewMenu -Text "OutputLocation" -Icon ([System.IconExtractor]::Extract("shell32.dll", 4, $true))
    $ResultsMenuItem.Add_Click({
        If (Test-Path $global:msrdLogRoot) {
            explorer $global:msrdLogRoot
        } else {
            msrdAdd-OutputBoxLine "`n[WARNING] The selected output location could not be found." "Yellow"
        }
    })

    $ViewSeparator1 = msrdCreateMenuItem -Menu $ViewMenu -Text "---"

    #diagnostic reports
    $ReportsMenuItem = msrdCreateMenuItem -Menu $ViewMenu -Text "DiagReports" -Icon ([System.IconExtractor]::Extract("imageres.dll", 350, $true))    
    
    function addReportItems {
        if (Test-Path $global:msrdLogRoot -PathType Container) {
            $RepFiles = Get-ChildItem $global:msrdLogRoot -Recurse -Include *MSRD-Diag.html* | ForEach-Object { $_.FullName }
            # add file names to menu
            if ($RepFiles) {
                $RepMenuItems = @()
                foreach ($RepFile in $RepFiles) {
                    $RepFolderName = Split-Path $RepFile -Parent | Split-Path -Leaf
                    if ($RepFolderName -match "^MSRD-Results-(.+)$") {
                        $RepMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
                        $RepMenuItem.Text = $Matches[1]
                        $RepMenuItem.Tag = $RepFile
                        $RepMenuItem.Image = ([System.IconExtractor]::Extract("imageres.dll", 350, $true))
                        $RepMenuItem.Add_Click({
                        
                            if (Test-Path -Path $this.Tag) {
                                Invoke-Item $this.Tag
                            } else {
                                msrdAdd-OutputBoxLine "`n[WARNING] The selected output location no longer exists. Click on 'View\Diagnostic Reports' to refresh the list and try again." "Red"
                            }
                        })
                        $RepMenuItems += $RepMenuItem
                        $RepMenuItems | Sort-Object -Descending Text | ForEach-Object { [void] $ReportsMenuItem.DropDownItems.Add($_) }
                    }
                }
            } else {
                msrdAdd-OutputBoxLine "`nNo reports have been found under the current output location ($global:msrdLogRoot).`nGenerate some diagnostic reports first, to populate this list." "Yellow"
            }
        } else {
            msrdAdd-OutputBoxLine "`nThe current output location ($global:msrdLogRoot) does not exist.`nGenerate some diagnostic reports first, to populate this list." "Yellow"
        }
    }

    $ReportsMenuItem.Add_MouseEnter({
        $ReportsMenuItem.DropDownItems.Clear()
        addReportItems
    })

    #endregion View menu

    #region Tools menu
    $ToolsMenu = msrdCreateMenu -Text "ToolsMenu"

    $OutputMenuItem = msrdCreateMenuItem -Menu $ToolsMenu -Text "SetOutputLocation" -Icon ([System.IconExtractor]::Extract("shell32.dll", 4, $true))
    $OutputMenuItem.Add_Click({ msrdFind-Folder "C:\" })

    $UserContextMenuItem = msrdCreateMenuItem -Menu $ToolsMenu -Text "SetUserContext" -Icon ([System.IconExtractor]::Extract("shell32.dll", 160, $true))
    $UserContextMenuItem.Add_Click({ $userContextForm.ShowDialog() | Out-Null })
    
    $ToolsSeparator1 = msrdCreateMenuItem -Menu $ToolsMenu -Text "---"

    $ConfigCollectMenuItem = msrdCreateMenuItem -Menu $ToolsMenu -Text "ConfigDataCollection" -Icon ([System.IconExtractor]::Extract("shell32.dll", 90, $true))
    $ConfigCollectMenuItem.Add_Click({ $selectCollectForm.ShowDialog() | Out-Null })

    $ConfigDiagMenuItem = msrdCreateMenuItem -Menu $ToolsMenu -Text "ConfigDiag" -Icon ([System.IconExtractor]::Extract("shell32.dll", 90, $true))
    $ConfigDiagMenuItem.Add_Click({ $selectDiagForm.ShowDialog() | Out-Null })
    
    $ToolsSeparator2 = msrdCreateMenuItem -Menu $ToolsMenu -Text "---"

    $global:AutoVerCheckMenuItem = msrdCreateMenuItem -Menu $ToolsMenu -Text "AutoVerCheck" -Icon ([System.IconExtractor]::Extract("shell32.dll", 238, $true))
    $global:AutoVerCheckMenuItem.CheckOnClick = $True
    if ($global:msrdAutoVerCheck -eq 1) {
        $global:AutoVerCheckMenuItem.Checked = $True
    }
    $AutoVerCheckMenuItem.Add_Click({
        #update version check in .cfg file
        if ($global:AutoVerCheckMenuItem.Checked) {
            msrdUpdateConfigFile -configFile "MSRD-Collect.cfg" -key "AutomaticVersionCheck" -value 1
            $global:msrdAutoVerCheck = 1
            msrdAdd-OutputBoxLine "Automatic update check on script launch is Enabled`n"
        } else {
            msrdUpdateConfigFile -configFile "MSRD-Collect.cfg" -key "AutomaticVersionCheck" -value 0
            $global:msrdAutoVerCheck = 0
            msrdAdd-OutputBoxLine "Automatic update check on script launch is Disabled`n"
        }
    })

    #endregion Tools menu

    #region Help menu
    $HelpMenu = msrdCreateMenu -Text "HelpMenu"

    $ReadMeMenuItem = msrdCreateMenuItem -Menu $HelpMenu -Text "ReadMe" -Icon ([System.Drawing.SystemIcons]::Information)
    $ReadMeMenuItem.Add_Click({
        $readmepath = (Get-Item .).FullName + "\MSRD-Collect-ReadMe.txt"
        notepad $readmepath
    })
    
    $WhatsNewMenuItem = msrdCreateMenuItem -Menu $HelpMenu -Text "WhatsNew" -Icon ([System.Drawing.SystemIcons]::Question)
    $WhatsNewMenuItem.Add_Click({
        $readmepath = (Get-Item .).FullName + "\MSRD-Collect-RevisionHistory.txt"
        notepad $readmepath
    })

    #download menu
    $DownloadMenuItem = msrdCreateMenuItem -Menu $HelpMenu -Text "Download" -Icon ([System.IconExtractor]::Extract("imageres.dll", 175, $true))
    $DownloadMenuItemMSRDC = msrdCreateMenuItem -Menu $DownloadMenuItem -Text "DownloadMSRDC" -Icon ([System.IconExtractor]::Extract("imageres.dll", 175, $true))
    $DownloadMenuItemMSRDC.Add_Click({ [System.Diagnostics.Process]::start("https://aka.ms/MSRD-Collect") })
    $DownloadMenuItemRDSTr = msrdCreateMenuItem -Menu $DownloadMenuItem -Text "DownloadRDSTracing" -Icon ([System.IconExtractor]::Extract("imageres.dll", 175, $true))
    $DownloadMenuItemRDSTr.Add_Click({ [System.Diagnostics.Process]::start("http://aka.ms/RDSTracing") })
    $DownloadMenuItemTSSv2 = msrdCreateMenuItem -Menu $DownloadMenuItem -Text "DownloadTSSv2" -Icon ([System.IconExtractor]::Extract("imageres.dll", 175, $true))
    $DownloadMenuItemTSSv2.Add_Click({ [System.Diagnostics.Process]::start("https://aka.ms/getTSS") })

    $HelpSeparator1 = msrdCreateMenuItem -Menu $HelpMenu -Text "---"
    
    #azure submenu
    $AzureMenuItem = msrdCreateMenuItem -Menu $HelpMenu -Text "AzureMenu" -Icon ([System.IconExtractor]::Extract("imageres.dll", 221, $true))

    $AzureMenuItemOutageNote = msrdCreateMenuItem -Menu $AzureMenuItem -Text "AzOutageNotification" -Icon ([System.IconExtractor]::Extract("imageres.dll", 221, $true))
    $AzureMenuItemOutageNote.Add_Click({ Start-Process https://docs.microsoft.com/azure/azure-monitor/platform/alerts-activity-log-service-notifications })

    $AzureMenuItemStatus = msrdCreateMenuItem -Menu $AzureMenuItem -Text "AzStatus" -Icon ([System.IconExtractor]::Extract("imageres.dll", 221, $true))
    $AzureMenuItemStatus.Add_Click({ Start-Process https://status.azure.com })

    $AzureMenuItemStatusHist = msrdCreateMenuItem -Menu $AzureMenuItem -Text "AzStatusHist" -Icon ([System.IconExtractor]::Extract("imageres.dll", 221, $true))
    $AzureMenuItemStatusHist.Add_Click({ Start-Process https://azure.status.microsoft/en-us/status/history/ })

    $AzureMenuItemServHealth = msrdCreateMenuItem -Menu $AzureMenuItem -Text "AzServHealth" -Icon ([System.IconExtractor]::Extract("imageres.dll", 221, $true))
    $AzureMenuItemServHealth.Add_Click({ Start-Process https://portal.azure.com/#blade/Microsoft_Azure_Health/AzureHealthBrowseBlade })
    
    $HelpSeparator2 = msrdCreateMenuItem -Menu $HelpMenu -Text "---"

    #docs submenu
    $DocsMenuItem = msrdCreateMenuItem -Menu $HelpMenu -Text "MSDocs" -Icon ([System.IconExtractor]::Extract("shell32.dll", 1, $true))
    $DocsMenuItemAVD = msrdCreateMenuItem -Menu $DocsMenuItem -Text "AVD" -Icon ([System.IconExtractor]::Extract("shell32.dll", 1, $true))
    $DocsMenuItemAVD.Add_Click({ Start-Process https://aka.ms/avddocs })

    $DocsMenuItemFSLogix = msrdCreateMenuItem -Menu $DocsMenuItem -Text "FSLogix" -Icon ([System.IconExtractor]::Extract("shell32.dll", 1, $true))
    $DocsMenuItemFSLogix.Add_Click({ Start-Process https://aka.ms/fslogix })

    $DocsMenuItemRDS = msrdCreateMenuItem -Menu $DocsMenuItem -Text "RDS" -Icon ([System.IconExtractor]::Extract("shell32.dll", 1, $true))
    $DocsMenuItemRDS.Add_Click({ Start-Process https://aka.ms/rds })

    $DocsMenuItemW365 = msrdCreateMenuItem -Menu $DocsMenuItem -Text "365" -Icon ([System.IconExtractor]::Extract("shell32.dll", 1, $true))
    $DocsMenuItemW365.Add_Click({ Start-Process https://aka.ms/w365docs })
    
    #techcommunity submenu
    $TCMenuItem = msrdCreateMenuItem -Menu $HelpMenu -Text "TechCommunity" -Icon ([System.IconExtractor]::Extract("shell32.dll", 1, $true))
    $TCMenuItemAVD = msrdCreateMenuItem -Menu $TCMenuItem -Text "TCAVD" -Icon ([System.IconExtractor]::Extract("shell32.dll", 1, $true))
    $TCMenuItemAVD.Add_Click({ Start-Process https://aka.ms/avdtechcommunity })

    $TCMenuItemW365 = msrdCreateMenuItem -Menu $TCMenuItem -Text "TC365" -Icon ([System.IconExtractor]::Extract("shell32.dll", 1, $true))
    $TCMenuItemW365.Add_Click({ Start-Process https://aka.ms/Community/Windows365 })

    $HelpSeparator4 = msrdCreateMenuItem -Menu $HelpMenu -Text "---"

    $Feedback1MenuItem = msrdCreateMenuItem -Menu $HelpMenu -Text "FeedbackEmail" -Icon ([System.IconExtractor]::Extract("imageres.dll", 15, $true))
    $Feedback1MenuItem.Add_Click({ [System.Diagnostics.Process]::start("mailto:MSRDCollectTalk@microsoft.com?subject=MSRD-Collect%20Feedback") })

    $Feedback2MenuItem = msrdCreateMenuItem -Menu $HelpMenu -Text "FeedbackSurvey" -Icon ([System.IconExtractor]::Extract("imageres.dll", 15, $true))
    $Feedback2MenuItem.Add_Click({ [System.Diagnostics.Process]::start("https://aka.ms/MSRD-Collect-Survey") })

    $HelpSeparator3 = msrdCreateMenuItem -Menu $HelpMenu -Text "---"

    $AboutMenuItem = msrdCreateMenuItem -Menu $HelpMenu -Text "About" -Icon ([System.Drawing.SystemIcons]::Application)
    $AboutMenuItem.Add_Click({
    [Windows.Forms.MessageBox]::Show("Microsoft CSS
Remote Desktop Data Collection and Diagnostics Script`n
Version:
        $msrdVersion`n
Authors:
        Robert Klemencz (Microsoft)
        Alexandru Olariu (Microsoft)`n
Contact:
        MSRDCollectTalk@microsoft.com
        https://aka.ms/MSRD-Collect-Survey", “About”, [Windows.Forms.MessageBoxButtons]::OK, [Windows.Forms.MessageBoxIcon]::Information)
    })
    #endregion Help menu

    $global:msrdGUIformMenu.Items.AddRange(@($FileMenu, $ViewMenu, $ToolsMenu, $HelpMenu))
    $global:msrdGUIformMenu.Location = new-object System.Drawing.Point(0, 0)
    $global:msrdGUIformMenu.Size = new-object System.Drawing.Size(200, 24)
    $global:msrdGUIformMenu.BackColor = [System.Drawing.Color]::White

    #region OptionToolbar
    $msrdOptionsToolbar = new-object System.Windows.Forms.MenuStrip
    $msrdOptionsToolbar.Cursor = [System.Windows.Forms.Cursors]::Hand

    function msrdCreateToolbarItem([string]$Text, [System.Drawing.Icon]$Icon = $null, [bool]$Enabled, [bool]$Checked, [bool]$CheckOnClick) {

        if ($Text -eq "---") {
            $TbItem = New-Object System.Windows.Forms.ToolStripSeparator
        } else {
            $TbItem = new-object System.Windows.Forms.ToolStripButton
            $TbItem.Text = msrdGetLocalizedText $Text
            $TbItem.Add_MouseEnter({ $this.Owner.Cursor = [System.Windows.Forms.Cursors]::Hand })
            $TbItem.Add_MouseLeave({ $this.Owner.Cursor = [System.Windows.Forms.Cursors]::Default })
            if ($Icon) { $TbItem.Image = $Icon.ToBitmap() }
            if ($Checked) { $TbItem.Checked = $Checked }
            if ($Enabled) { $TbItem.Enabled = $Enabled }
            if ($CheckOnClick) { $TbItem.CheckOnClick = $CheckOnClick }
        }

        return $TbItem
    }

    $TbSource = msrdCreateToolbarItem -Text "btnSource" -CheckOnClick $true
    $TbSource.BackColor = [System.Drawing.Color]::Lightblue
    $TbSource.Add_Click({
        if ($TbSource.Checked) {
            msrdInitMachines -Types @($true, $false, $false)
            msrdInitScenarioVars
            msrdInitScenarioBtns -buttons $TbProcDump, $TbDiagOnly, $TbNetTrace, $TbStart -isEnabled $true
            msrdInitScenarioBtns -buttons $TbAVD, $TbRDS, $TbProfiles, $TbActivation, $TbMSRA, $TbSCard, $TbIME, $TbTeams, $TbMSIXAA, $TbHCI -isEnabled $false
            msrdInitScenarioBtns -buttons $TbCore -isChecked $true
            $RunMenuItem.Enabled = $True
        } else {
            msrdInitMachines
            msrdInitScenarioVars
            msrdInitScenarioBtns -buttons $TbCore, $TbProcDump, $TbDiagOnly, $TbNetTrace, $TbStart, $TbProfiles, $TbActivation, $TbMSRA, $TbSCard, $TbIME, $TbTeams, $TbMSIXAA, $TbHCI -isEnabled $false
            msrdInitScenarioBtns -buttons $TbSource, $TbAVD, $TbRDS -isEnabled $true
            $RunMenuItem.Enabled = $false
        }
    })

    $TbAVD = msrdCreateToolbarItem -Text "btnAVD" -CheckOnClick $true
    $TbAVD.BackColor = [System.Drawing.Color]::Lightblue
    $TbAVD.Add_Click({
        if ($TbAVD.Checked) {
            msrdInitMachines -Types @($false, $true, $false)
            msrdInitScenarioVars
            msrdInitScenarioBtns -buttons $TbProcDump, $TbDiagOnly, $TbNetTrace, $TbStart, $TbProfiles, $TbActivation, $TbMSRA, $TbSCard, $TbIME, $TbTeams, $TbMSIXAA, $TbHCI -isEnabled $true
            msrdInitScenarioBtns -buttons $TbSource, $TbRDS -isEnabled $false
            msrdInitScenarioBtns -buttons $TbCore -isChecked $true
            $RunMenuItem.Enabled = $True
        } else {
            msrdInitMachines
            msrdInitScenarioVars
            msrdInitScenarioBtns -buttons $TbCore, $TbProcDump, $TbDiagOnly, $TbNetTrace, $TbStart, $TbProfiles, $TbActivation, $TbMSRA, $TbSCard, $TbIME, $TbTeams, $TbMSIXAA, $TbHCI -isEnabled $false
            msrdInitScenarioBtns -buttons $TbSource, $TbAVD, $TbRDS -isEnabled $true
            $RunMenuItem.Enabled = $False
        }
    })

    $TbRDS = msrdCreateToolbarItem -Text "btnRDS" -CheckOnClick $true
    $TbRDS.BackColor = [System.Drawing.Color]::Lightblue
    $TbRDS.Add_Click({
        if ($TbRDS.Checked) {
            msrdInitMachines -Types @($false, $false, $true)
            msrdInitScenarioVars
            msrdInitScenarioBtns -buttons $TbProcDump, $TbDiagOnly, $TbNetTrace, $TbStart, $TbProfiles, $TbActivation, $TbMSRA, $TbSCard, $TbIME -isEnabled $true
            msrdInitScenarioBtns -buttons $TbSource, $TbAVD, $TbTeams, $TbMSIXAA, $TbHCI -isEnabled $false
            msrdInitScenarioBtns -buttons $TbCore -isChecked $true
            $RunMenuItem.Enabled = $True
        } else {
            msrdInitMachines
            msrdInitScenarioVars
            msrdInitScenarioBtns -buttons $TbCore, $TbProcDump, $TbDiagOnly, $TbNetTrace, $TbStart, $TbProfiles, $TbActivation, $TbMSRA, $TbSCard, $TbIME, $TbTeams, $TbMSIXAA, $TbHCI -isEnabled $false 
            msrdInitScenarioBtns -buttons $TbSource, $TbAVD, $TbRDS -isEnabled $true
            $RunMenuItem.Enabled = $False
        }
    })

    $TbSeparator1 = msrdCreateToolbarItem -Text "---"

    $TbCore = msrdCreateToolbarItem -Text "btnCore" -Enabled $False -Checked $False -CheckOnClick $true

    $TbProfiles = msrdCreateToolbarItem -Text "btnProfiles" -Enabled $False -Checked $False -CheckOnClick $true
    $TbProfiles.Add_Click({
        if ($TbProfiles.Checked) { $script:vProfiles = $varsProfiles } else { $script:vProfiles = $varsProfilesNo }
    })

    $TbActivation = msrdCreateToolbarItem -Text "btnActivation" -Enabled $False -Checked $False -CheckOnClick $true
    $TbActivation.Add_Click({
        if ($TbActivation.Checked) { $script:vActivation = $varsActivation } else { $script:vActivation = $varsActivationNo }
    })

    $TbMSRA = msrdCreateToolbarItem -Text "btnMSRA" -Enabled $False -Checked $False -CheckOnClick $true
    $TbMSRA.Add_Click({
        if ($TbMSRA.Checked) { $script:vMSRA = $script:varsMSRA } else { $script:vMSRA = $varsMSRANo }
    })

    $TbSCard = msrdCreateToolbarItem -Text "btnSCard" -Enabled $False -Checked $False -CheckOnClick $true
    $TbSCard.Add_Click({
        if ($TbSCard.Checked) { $script:vSCard = $varsSCard } else { $script:vSCard = $varsSCardNo }
    })

    $TbIME = msrdCreateToolbarItem -Text "btnIME" -Enabled $False -Checked $False -CheckOnClick $true
    $TbIME.Add_Click({
        if ($TbIME.Checked) { $script:vIME = $varsIME } else { $script:vIME = $varsIMENo }
    })

    $TbTeams = msrdCreateToolbarItem -Text "btnTeams" -Enabled $False -Checked $False -CheckOnClick $true
    $TbTeams.Add_Click({
        if ($TbTeams.Checked) { $script:vTeams = $varsTeams } else { $script:vTeams = $varsTeamsNo }
    })

    $TbMSIXAA = msrdCreateToolbarItem -Text "btnMSIXAA" -Enabled $False -Checked $False -CheckOnClick $true
    $TbMSIXAA.Add_Click({
        if ($TbMSIXAA.Checked) { $script:vMSIXAA = $varsMSIXAA } else { $script:vMSIXAA = $varsMSIXAANo }
    })

    $TbHCI = msrdCreateToolbarItem -Text "btnHCI" -Enabled $False -Checked $False -CheckOnClick $true
    $TbHCI.Add_Click({
        if ($TbHCI.Checked) { $script:vHCI = $varsHCI } else { $script:vHCI = $varsHCINo }
    })

    $TbProcDump = msrdCreateToolbarItem -Text "btnProcDump" -Enabled $False -CheckOnClick $True
    $TbProcDump.Add_Click({
        GetProcDumpPID
        $dumppidForm.ShowDialog() | Out-Null
        if ($TbProcDump.Checked) { $script:dumpProc = $True } else { $script:dumpProc = $False }
    })

    $TbDiagOnly = msrdCreateToolbarItem -Text "btnDiagOnly" -Enabled $False -CheckOnClick $true
    $TbDiagOnly.Add_Click({
        if ($TbDiagOnly.Checked) {
            msrdInitScenarioVars
            msrdInitScenarioBtns -buttons $TbStart -isEnabled $true
            msrdInitScenarioBtns -buttons $TbCore, $TbProcDump, $TbNetTrace, $TbProfiles, $TbActivation, $TbMSRA, $TbSCard, $TbIME, $TbTeams, $TbMSIXAA, $TbHCI -isEnabled $false
            $script:onlyDiag = $true
            $script:vCore = $script:varsNO
        } else {
            msrdInitScenarioVars
            if ($TbSource.Checked) {
                msrdInitScenarioBtns -buttons $TbProcDump, $TbDiagOnly, $TbNetTrace, $TbStart -isEnabled $true
                msrdInitScenarioBtns -buttons $TbProfiles, $TbActivation, $TbMSRA, $TbSCard, $TbIME, $TbTeams, $TbMSIXAA, $TbHCI -isEnabled $false
            } elseif ($TbAVD.Checked) {
                msrdInitScenarioBtns -buttons $TbProcDump, $TbDiagOnly, $TbNetTrace, $TbStart, $TbProfiles, $TbActivation, $TbMSRA, $TbSCard, $TbIME, $TbTeams, $TbMSIXAA, $TbHCI -isEnabled $true
            } elseif ($TbRDS.Checked) {
                msrdInitScenarioBtns -buttons $TbProcDump, $TbDiagOnly, $TbNetTrace, $TbStart, $TbProfiles, $TbActivation, $TbMSRA, $TbSCard, $TbIME -isEnabled $true
                msrdInitScenarioBtns -buttons $TbTeams, $TbMSIXAA, $TbHCI -isEnabled $false
            }
            msrdInitScenarioBtns -buttons $TbCore -checked $true
            $script:onlyDiag = $false
            $script:vCore = $script:varsCore
        }
    })

    $TbNetTrace = msrdCreateToolbarItem -Text "btnNetTrace" -Enabled $False -CheckOnClick $true
    $TbNetTrace.Add_Click({
        if ($TbNetTrace.Checked) { $script:traceNet = $True } else { $script:traceNet = $False }
    })

    $TbSeparator2 = msrdCreateToolbarItem -Text "---"
    
    $TbStart = msrdCreateToolbarItem -Text "Start" -Icon ([System.IconExtractor]::Extract("shell32.dll", 137, $true)) -Enabled $False -CheckOnClick $True
    $TbStart.ForeColor = "Blue"
    $TbStart.Add_Click({ msrdStartBtnCollect })

    $TbLang = new-object System.Windows.Forms.ToolStripDropDown
    $TbLangBtn = new-object System.Windows.Forms.ToolStripDropDownButton
    $TbLangBtn.DropDown = $TbLang
    $TbLangBtn.Text = "EN"
    $TbLangBtn.Alignment = "right"

    $TbLangEN = msrdCreateToolbarItem -Text "eng"
    $TbLangEN.Checked = $true
    $TbLangEN.Add_Click({
        $TbLangBtn.Text = $TbLangEN.Text
        msrdRefreshUILang -id "EN"
        msrdToggleLangChecked $TbLangEN
        msrdResetOutputBox
    })

    $TbLangDE = msrdCreateToolbarItem -Text "ger"
    $TbLangDE.Add_Click({
        $TbLangBtn.Text = $TbLangDE.Text
        msrdRefreshUILang -id "DE"
        msrdToggleLangChecked $TbLangDE
        msrdResetOutputBox
    })

    $TbLangHU = msrdCreateToolbarItem -Text "hun"
    $TbLangHU.Add_Click({
        $TbLangBtn.Text = $TbLangHU.Text
        msrdRefreshUILang -id "HU"
        msrdToggleLangChecked $TbLangHU
        msrdResetOutputBox
    })

    $TbLangRO = msrdCreateToolbarItem -Text "rom"
    $TbLangRO.Add_Click({
        $TbLangBtn.Text = $TbLangRO.Text
        msrdRefreshUILang -id "RO"
        msrdToggleLangChecked $TbLangRO
        msrdResetOutputBox
    })

    $TbLangFR = msrdCreateToolbarItem -Text "fra"
    $TbLangFR.Add_Click({
        $TbLangBtn.Text = $TbLangFR.Text
        msrdRefreshUILang -id "FR"
        msrdToggleLangChecked $TbLangFR
        msrdResetOutputBox
    })

    $TbLangIT = msrdCreateToolbarItem -Text "ita"
    $TbLangIT.Add_Click({
        $TbLangBtn.Text = $TbLangIT.Text
        msrdRefreshUILang -id "IT"
        msrdToggleLangChecked $TbLangIT
        msrdResetOutputBox
    })

    $TbLangPT = msrdCreateToolbarItem -Text "por"
    $TbLangPT.Add_Click({
        $TbLangBtn.Text = $TbLangPT.Text
        msrdRefreshUILang -id "PT"
        msrdToggleLangChecked $TbLangPT
        msrdResetOutputBox
    })

    $TbLang.Items.AddRange(@($TbLangDE,$TbLangEN,$TbLangFR,$TbLangHU,$TbLangIT,$TbLangPT,$TbLangRO))

    $msrdOptionsToolbar.Items.AddRange(@($TbSource, $TbAVD, $TbRDS, $TbSeparator1, $TbCore, $TbProfiles, $TbActivation, $TbMSRA, $TbSCard, $TbIME, $TbTeams, $TbMSIXAA, $TbHCI, $TbProcDump, $TbNetTrace, $TbDiagOnly, $TbSeparator2, $TbStart, $TbLangBtn))
    $msrdOptionsToolbar.BackColor = [System.Drawing.Color]::Lightgray
    $global:msrdGUIform.Controls.Add($msrdOptionsToolbar)
    #endregion OptionToolbar

    $global:msrdGUIform.Controls.Add($global:msrdGUIformMenu)
    $global:msrdGUIform.MainMenuStrip = $global:msrdGUIformMenu

    #region dump
    function GetProcDumpPID {
        $script:datatable = New-Object system.Data.DataTable

        $col1 = New-Object system.Data.DataColumn "ProcPid",([string])
        $col2 = New-Object system.Data.DataColumn "ProcName",([string])
        $script:datatable.columns.add($col1)
        $script:datatable.columns.add($col2)
        $ddlist = Get-Process
        foreach ($dditem in $ddlist) {
            if (($dditem.Name -ne "Idle") -and ($dditem.Name -ne "System") -and ($dditem.Name -ne "Registry")) {
                $datarow = $script:datatable.NewRow()
                $test = $dditem.Name + " (" + $dditem.Id + ")"
                $datarow.ProcPid = $dditem.Id
                $datarow.ProcName = $test
                $script:datatable.Rows.Add($datarow)
            }
        }

        $datarow0 = $script:datatable.NewRow()
        $datarow0.ProcPid = ""
        $defaultProc = msrdGetLocalizedText "dpidtext2"
        $datarow0.ProcName = $script:defaultProc
        $script:datatable.Rows.InsertAt($datarow0,0)

        $dumppidBox.Datasource = $script:datatable
        $dumppidBox.ValueMember = "ProcPid"
        $dumppidBox.DisplayMember = "ProcName"
    }

    #region PsBox
    $global:MsrdPsBox = New-Object System.Windows.Forms.RichTextBox
    $global:MsrdPsBox.Location = New-Object System.Drawing.Point(10, 60)
    $global:MsrdPsBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    $global:MsrdPsBox.Size = New-Object System.Drawing.Point(965, 580)
    $global:MsrdPsBox.Multiline = $True
    $global:MsrdPsBox.ScrollBars = "Vertical"
    $global:MsrdPsBox.BackColor = "#012456"
    $global:MsrdPsBox.ForeColor = "White"
    $global:msrdPsBox.Anchor = 'Top,Left,Bottom,Right'
    $global:msrdPsBox.SelectionIndent = 10
    $global:msrdPsBox.SelectionRightIndent = 10
    $global:msrdGUIform.Controls.Add($MsrdPsBox)
    #endregion PsBox

    #region DumpPID
    $dumppidForm = New-Object System.Windows.Forms.Form
    $dumppidForm.Width = 480
    $dumppidForm.Height = 110
    $dumppidForm.StartPosition = "CenterScreen"
    $dumppidForm.ControlBox = $False
    $dumppidForm.BackColor = "#eeeeee"
    $dumppidForm.Text = msrdGetLocalizedText "dpidtext1" #Select the running process to dump

    $dumppidBox = New-Object System.Windows.Forms.ComboBox
    $dumppidBox.Location  = New-Object System.Drawing.Point(25,25)
    $dumppidBox.Size  = New-Object System.Drawing.Point(250,30)
    $dumppidBox.DropDownWidth = 250
    $dumppidBox.DropDownStyle = "DropDownList"
    $dumppidBox.Items.Clear()
    $dumppidBox.Cursor = [System.Windows.Forms.Cursors]::Hand
    $dumppidBoxToolTip = New-Object System.Windows.Forms.ToolTip
    $dumppidBoxToolTip.SetToolTip($dumppidBox, "$(msrdGetLocalizedText "dpidtext1")")
    $dumppidForm.Controls.Add($dumppidBox)

    $dumppidOK = New-Object System.Windows.Forms.Button
    $dumppidOK.Location = New-Object System.Drawing.Size(300,21)
    $dumppidOK.Size = New-Object System.Drawing.Size(60,30)
    $dumppidOK.Text = "OK"
    $dumppidOK.BackColor = "#e6e6e6"
    $dumppidOK.Cursor = [System.Windows.Forms.Cursors]::Hand
    $dumppidForm.Controls.Add($dumppidOK)
    $dumppidOK.Add_Click({
        $dumppidForm.Close()
        if ($dumppidBox.SelectedValue -ne "") {
            $TbProcDump.Checked = $true
            $script:pidProc = $dumppidBox.SelectedValue
            $selectedIndex = $dumppidBox.SelectedIndex
            $nameProc = $script:datatable.Rows[$selectedIndex][1]
            msrdAdd-OutputBoxLine "$(msrdGetLocalizedText "dpidtext3") $nameProc`n" "Yellow"
        } else {
            $TbProcDump.Checked = $False
            $script:pidProc = ""
            msrdAdd-OutputBoxLine "$(msrdGetLocalizedText "dpidtext4")`n" "Yellow"
        }
    })

    $dumppidCancel = New-Object System.Windows.Forms.Button
    $dumppidCancel.Location = New-Object System.Drawing.Size(370,21)
    $dumppidCancel.Size = New-Object System.Drawing.Size(60,30)
    $dumppidCancel.Text = "Cancel"
    $dumppidCancel.BackColor = "#e6e6e6"
    $dumppidCancel.Cursor = [System.Windows.Forms.Cursors]::Hand
    $dumppidForm.Controls.Add($dumppidCancel)
    $dumppidCancel.Add_Click({
        $dumppidForm.Close()
        if ($script:pidProc -ne "") {
            $TbProcDump.Checked = $true
            $dumppidBox.SelectedValue = $script:pidProc
            $selectedIndex = $dumppidBox.SelectedIndex
            $nameProc = $script:datatable.Rows[$selectedIndex][1]
            msrdAdd-OutputBoxLine "$(msrdGetLocalizedText "dpidtext3") $nameProc`n" "Yellow"
        } else {
            $TbProcDump.Checked = $False
            $script:pidProc = ""
            $dumppidBox.SelectedValue = $script:pidProc
            msrdAdd-OutputBoxLine "$(msrdGetLocalizedText "dpidtext4")`n" "Yellow"
        }
    })

    #endregion DumpPID

    #region granular collection

    #data collection configuration form
    $selectCollectForm = New-Object System.Windows.Forms.Form
    $selectCollectForm.Width = 480
    $selectCollectForm.Height = 340
    $selectCollectForm.StartPosition = "CenterScreen"
    $selectCollectForm.MinimizeBox = $False
    $selectCollectForm.MaximizeBox = $False
    $selectCollectForm.BackColor = "#eeeeee"
    $selectCollectForm.Text = msrdGetLocalizedText "selectCollect1"

    $selectCollectLabel = New-Object System.Windows.Forms.Label
    $selectCollectLabel.Location  = New-Object System.Drawing.Point(10,10)
    $selectCollectLabel.Size  = New-Object System.Drawing.Point(470,30)
    $selectCollectLabel.Text = msrdGetLocalizedText "selectCollect2"
    $selectCollectForm.Controls.Add($selectCollectLabel)

    # Tab master control
    $MainCollectTab = New-Object System.Windows.Forms.TabControl
    $MainCollectTab.Location = New-Object System.Drawing.Size(10,40)
    $MainCollectTab.Size = New-Object System.Drawing.Size(445,240)
    $MainCollectTab.Multiline = $true
    $MainCollectTab.AutoSize = $true
    $MainCollectTab.Anchor = 'Top,Left,Bottom,Right'

    # Tab pages
    function msrdAddCfgCheckbox {
        param( $cboxtab, [string]$text, [int]$locX, [int]$locY )

        $cbox = New-Object System.Windows.Forms.CheckBox
        $cbox.Location = New-Object System.Drawing.Size($locX,$locY)
        $cbox.Size = New-Object System.Drawing.Size(200,30)
        $cbox.Text = $text
        $cbox.Cursor = [System.Windows.Forms.Cursors]::Hand
        $cbox.Checked = $true
        $cboxtab.Controls.Add($cbox)

        return $cbox
    }

    $CollectTabCore = New-Object System.Windows.Forms.TabPage
    $CollectTabCore.Text = 'Core'

        $core1cb = msrdAddCfgCheckbox -cboxtab $CollectTabCore -text "Core AVD/RDS Information" -locX 20 -locY 20
        $core1cb.Add_CheckStateChanged({ if ($core1cb.Checked) { $script:varsCore[0] = $true } else { $script:varsCore[0] = $false } })

        $core2cb = msrdAddCfgCheckbox -cboxtab $CollectTabCore -text "Event Logs" -locX 20 -locY 50
        $core2cb.Add_CheckStateChanged({
            if ($core2cb.Checked) {
                $script:varsCore[1] = $true; $core2Acb.Checked = $true; $script:varsCore[2] = $true
            } else {
                $script:varsCore[1] = $false; $core2Acb.Checked = $false; $script:varsCore[2] = $false
            }
        })

        $core2Acb = msrdAddCfgCheckbox -cboxtab $CollectTabCore -text "Security Event Logs" -locX 40 -locY 75
        $core2Acb.Add_CheckStateChanged({ if ($core2Acb.Checked) { $script:varsCore[2] = $true } else { $script:varsCore[2] = $false } })
        
        $core3cb = msrdAddCfgCheckbox -cboxtab $CollectTabCore -text "Registry Keys" -locX 20 -locY 110
        $core3cb.Add_CheckStateChanged({ if ($core3cb.Checked) { $script:varsCore[3] = $true } else { $script:varsCore[3] = $false } })

        $core4cb = msrdAddCfgCheckbox -cboxtab $CollectTabCore -text "RDP, Network and AD Information" -locX 20 -locY 140
        $core4cb.Add_CheckStateChanged({
            if ($core4cb.Checked) {
                $script:varsCore[4] = $true; $core4Acb.Checked = $true; $script:varsCore[5] = $true
            } else { 
                $script:varsCore[4] = $false; $core4Acb.Checked = $false; $script:varsCore[5] = $false
            }
        })

        $core4Acb = msrdAddCfgCheckbox -cboxtab $CollectTabCore -text "'dsregcmd /status' Information" -locX 40 -locY 165    
        $core4Acb.Add_CheckStateChanged({ if ($core4Acb.Checked) { $script:varsCore[5] = $true } else { $script:varsCore[5] = $false } })
        
        $core5cb = msrdAddCfgCheckbox -cboxtab $CollectTabCore -text "Scheduled Tasks Information" -locX 240 -locY 20
        $core5cb.Add_CheckStateChanged({ if ($core5cb.Checked) { $script:varsCore[6] = $true } else { $script:varsCore[6] = $false } })
        
        $core6cb = msrdAddCfgCheckbox -cboxtab $CollectTabCore -text "System Information" -locX 240 -locY 50
        $core6cb.Add_CheckStateChanged({ if ($core6cb.Checked) { $script:varsCore[7] = $true } else { $script:varsCore[7] = $false } })
        
        $core7cb = msrdAddCfgCheckbox -cboxtab $CollectTabCore -text "RDS Roles Information" -locX 240 -locY 80
        $core7cb.Add_CheckStateChanged({ if ($core7cb.Checked) { $script:varsCore[8] = $true } else { $script:varsCore[8] = $false } })

    $CollectTabProfiles = New-Object System.Windows.Forms.TabPage
    $CollectTabProfiles.Text = 'Profiles'

        $profiles1cb = msrdAddCfgCheckbox -cboxtab $CollectTabProfiles -text "Event Logs" -locX 20 -locY 20
        $profiles1cb.Add_CheckStateChanged({ if ($profiles1cb.Checked) { $script:profiles1 = $true } else { $script:profiles1 = $false } })
        
        $profiles2cb = msrdAddCfgCheckbox -cboxtab $CollectTabProfiles -text "Registry Keys" -locX 20 -locY 50
        $profiles2cb.Add_CheckStateChanged({ if ($profiles2cb.Checked) { $script:profiles2 = $true } else { $script:profiles2 = $false } })
        
        $profiles3cb = msrdAddCfgCheckbox -cboxtab $CollectTabProfiles -text "WhoAmI Information" -locX 20 -locY 80
        $profiles3cb.Add_CheckStateChanged({ if ($profiles3cb.Checked) { $script:profiles3 = $true } else { $script:profiles3 = $false } })
        
        $profiles4cb = msrdAddCfgCheckbox -cboxtab $CollectTabProfiles -text "FSLogix Information" -locX 20 -locY 110
        $profiles4cb.Add_CheckStateChanged({ if ($profiles4cb.Checked) { $script:profiles4 = $true } else { $script:profiles4 = $false } })

    $CollectTabActivation = New-Object System.Windows.Forms.TabPage
    $CollectTabActivation.Text = 'Activation'

        $activation1cb = msrdAddCfgCheckbox -cboxtab $CollectTabActivation -text "'licensingdiag' Information" -locX 20 -locY 20
        $activation1cb.Add_CheckStateChanged({ if ($activation1cb.Checked) { $script:activation1 = $true } else { $script:activation1 = $false } })    
        
        $activation2cb = msrdAddCfgCheckbox -cboxtab $CollectTabActivation -text "'slmgr /dlv' Information" -locX 20 -locY 50
        $activation2cb.Add_CheckStateChanged({ if ($activation2cb.Checked) { $script:activation2 = $true } else { $script:activation2 = $false } })

        $activation3cb = msrdAddCfgCheckbox -cboxtab $CollectTabActivation -text "List of domain KMS servers" -locX 20 -locY 80
        $activation3cb.Add_CheckStateChanged({ if ($activation3cb.Checked) { $script:activation3 = $true } else { $script:activation3 = $false } })

    $CollectTabMSRA = New-Object System.Windows.Forms.TabPage
    $CollectTabMSRA.Text = 'MSRA'

        $msra1cb = msrdAddCfgCheckbox -cboxtab $CollectTabMSRA -text "Event Logs" -locX 20 -locY 20
        $msra1cb.Add_CheckStateChanged({ if ($msra1cb.Checked) { $script:msra1 = $true } else { $script:msra1 = $false } })    
    
        $msra2cb = msrdAddCfgCheckbox -cboxtab $CollectTabMSRA -text "Registry Keys" -locX 20 -locY 50
        $msra2cb.Add_CheckStateChanged({ if ($msra2cb.Checked) { $script:msra2 = $true } else { $script:msra2 = $false } })

        $msra3cb = msrdAddCfgCheckbox -cboxtab $CollectTabMSRA -text "Groups Membership Information" -locX 20 -locY 80
        $msra3cb.Add_CheckStateChanged({ if ($msra3cb.Checked) { $script:msra3 = $true } else { $script:msra3 = $false } })

        $msra4cb = msrdAddCfgCheckbox -cboxtab $CollectTabMSRA -text "Permissions" -locX 20 -locY 110
        $msra4cb.Add_CheckStateChanged({ if ($msra4cb.Checked) { $script:msra4 = $true } else { $script:msra4 = $false } })

        $msra5cb = msrdAddCfgCheckbox -cboxtab $CollectTabMSRA -text "Scheduled Task Information" -locX 20 -locY 140
        $msra5cb.Add_CheckStateChanged({ if ($msra5cb.Checked) { $script:msra5 = $true } else { $script:msra5 = $false } })

    $CollectTabSCard = New-Object System.Windows.Forms.TabPage
    $CollectTabSCard.Text = 'SCard'

        $scard1cb = msrdAddCfgCheckbox -cboxtab $CollectTabSCard -text "Event Logs" -locX 20 -locY 20
        $scard1cb.Add_CheckStateChanged({ if ($scard1cb.Checked) { $script:scard1 = $true } else { $script:scard1 = $false } })

        $scard2cb = msrdAddCfgCheckbox -cboxtab $CollectTabSCard -text "'certutil' Information" -locX 20 -locY 50
        $scard2cb.Add_CheckStateChanged({ if ($scard2cb.Checked) { $script:scard2 = $true } else { $script:scard2 = $false } })

        $scard3cb = msrdAddCfgCheckbox -cboxtab $CollectTabSCard -text "KDCProxy / RD Gateway Information" -locX 20 -locY 80
        $scard3cb.Add_CheckStateChanged({ if ($scard3cb.Checked) { $script:scard3 = $true } else { $script:scard3 = $false } })

    $CollectTabIME = New-Object System.Windows.Forms.TabPage
    $CollectTabIME.Text = 'IME'

        $ime1cb = msrdAddCfgCheckbox -cboxtab $CollectTabIME -text "Registry Keys" -locX 20 -locY 20
        $ime1cb.Add_CheckStateChanged({ if ($ime1cb.Checked) { $script:ime1 = $true } else { $script:ime1 = $false } })

        $ime2cb = msrdAddCfgCheckbox -cboxtab $CollectTabIME -text "Tree Output of IME Folders" -locX 20 -locY 50
        $ime2cb.Add_CheckStateChanged({ if ($ime2cb.Checked) { $script:ime2 = $true } else { $script:ime2 = $false } })

    $CollectTabTeams = New-Object System.Windows.Forms.TabPage
    $CollectTabTeams.Text = 'Teams'

        $teams1cb = msrdAddCfgCheckbox -cboxtab $CollectTabTeams -text "Registry Keys" -locX 20 -locY 20
        $teams1cb.Add_CheckStateChanged({ if ($teams1cb.Checked) { $script:teams1 = $true } else { $script:teams1 = $false } })

        $teams2cb = msrdAddCfgCheckbox -cboxtab $CollectTabTeams -text "Teams Logs" -locX 20 -locY 50
        $teams2cb.Add_CheckStateChanged({ if ($teams2cb.Checked) { $script:teams2 = $true } else { $script:teams2 = $false } })

    $CollectTabMSIXAA = New-Object System.Windows.Forms.TabPage
    $CollectTabMSIXAA.Text = 'MSIXAA'

        $msixaa1cb = msrdAddCfgCheckbox -cboxtab $CollectTabMSIXAA -text "Event Logs" -locX 20 -locY 20    
        $msixaa1cb.Add_CheckStateChanged({ if ($msixaa1cb.Checked) { $script:msixaa1 = $true } else { $script:msixaa1 = $false } })
    
    $CollectTabHCI = New-Object System.Windows.Forms.TabPage
    $CollectTabHCI.Text = 'HCI'

        $hci1cb = msrdAddCfgCheckbox -cboxtab $CollectTabHCI -text "HCI Logs" -locX 20 -locY 20    
        $hci1cb.Add_CheckStateChanged({ if ($hci1cb.Checked) { $script:hci1 = $true } else { $script:hci1 = $false } })

    # Add tabs to tab control
    $MainCollectTab.Controls.AddRange(@($CollectTabCore,$CollectTabProfiles,$CollectTabActivation,$CollectTabMSRA,$CollectTabSCard,$CollectTabIME,$CollectTabTeams,$CollectTabMSIXAA,$CollectTabHCI))
    $selectCollectForm.Controls.Add($MainCollectTab)

    #diagnostics configuration form
    $selectDiagForm = New-Object System.Windows.Forms.Form
    $selectDiagForm.Width = 580
    $selectDiagForm.Height = 340
    $selectDiagForm.StartPosition = "CenterScreen"
    $selectDiagForm.MinimizeBox = $False
    $selectDiagForm.MaximizeBox = $False
    $selectDiagForm.BackColor = "#eeeeee"
    $selectDiagForm.Text = msrdGetLocalizedText "selectDiag1"

    $selectDiagLabel = New-Object System.Windows.Forms.Label
    $selectDiagLabel.Location  = New-Object System.Drawing.Point(10,10)
    $selectDiagLabel.Size  = New-Object System.Drawing.Point(470,30)
    $selectDiagLabel.Text = msrdGetLocalizedText "selectDiag2"
    $selectDiagForm.Controls.Add($selectDiagLabel)

    # Tab master control
    $MainDiagTab = New-Object System.Windows.Forms.TabControl
    $MainDiagTab.Location = New-Object System.Drawing.Size(10,40)
    $MainDiagTab.Size = New-Object System.Drawing.Size(545,240)
    $MainDiagTab.Multiline = $true
    $MainDiagTab.AutoSize = $true
    $MainDiagTab.Anchor = 'Top,Left,Bottom,Right'

    # Tab pages
    $DiagTabSystem = New-Object System.Windows.Forms.TabPage
    $DiagTabSystem.Text = 'System'

        $system1cb = msrdAddCfgCheckbox -cboxtab $DiagTabSystem -text "Core" -locX 20 -locY 20
        $system1cb.Add_CheckStateChanged({ if ($system1cb.Checked) { $script:varsSystem[0] = $true } else { $script:varsSystem[0] = $false } })

        $system2cb = msrdAddCfgCheckbox -cboxtab $DiagTabSystem -text "CPU Utilization" -locX 20 -locY 50
        $system2cb.Add_CheckStateChanged({ if ($system2cb.Checked) { $script:varsSystem[1] = $true } else { $script:varsSystem[1] = $false } })

        $system3cb = msrdAddCfgCheckbox -cboxtab $DiagTabSystem -text "Drives" -locX 20 -locY 80
        $system3cb.Add_CheckStateChanged({ if ($system3cb.Checked) { $script:varsSystem[2] = $true } else { $script:varsSystem[2] = $false } })

        $system4cb = msrdAddCfgCheckbox -cboxtab $DiagTabSystem -text "Graphics" -locX 20 -locY 110
        $system4cb.Add_CheckStateChanged({ if ($system4cb.Checked) { $script:varsSystem[3] = $true } else { $script:varsSystem[3] = $false } })

        $system5cb = msrdAddCfgCheckbox -cboxtab $DiagTabSystem -text "OS Activation / Licensing" -locX 20 -locY 140
        $system5cb.Add_CheckStateChanged({ if ($system5cb.Checked) { $script:varsSystem[4] = $true } else { $script:varsSystem[4] = $false } })

        $system6cb = msrdAddCfgCheckbox -cboxtab $DiagTabSystem -text "SSL / TLS" -locX 20 -locY 170
        $system6cb.Add_CheckStateChanged({ if ($system6cb.Checked) { $script:varsSystem[5] = $true } else { $script:varsSystem[5] = $false } })

        $system7cb = msrdAddCfgCheckbox -cboxtab $DiagTabSystem -text "Windows Installer" -locX 240 -locY 20
        $system7cb.Add_CheckStateChanged({ if ($system7cb.Checked) { $script:varsSystem[6] = $true } else { $script:varsSystem[6] = $false } })

        $system8cb = msrdAddCfgCheckbox -cboxtab $DiagTabSystem -text "Windows Search" -locX 240 -locY 50
        $system8cb.Add_CheckStateChanged({ if ($system8cb.Checked) { $script:varsSystem[7] = $true } else { $script:varsSystem[7] = $false } })

        $system9cb = msrdAddCfgCheckbox -cboxtab $DiagTabSystem -text "Windows Updates" -locX 240 -locY 80
        $system9cb.Add_CheckStateChanged({ if ($system9cb.Checked) { $script:varsSystem[8] = $true } else { $script:varsSystem[8] = $false } })

        $system10cb = msrdAddCfgCheckbox -cboxtab $DiagTabSystem -text "User Access Control (UAC)" -locX 240 -locY 110
        $system10cb.Add_CheckStateChanged({ if ($system10cb.Checked) { $script:varsSystem[9] = $true } else { $script:varsSystem[9] = $false } })

        $system11cb = msrdAddCfgCheckbox -cboxtab $DiagTabSystem -text "WinRM / PowerShell" -locX 240 -locY 140
        $system11cb.Add_CheckStateChanged({ if ($system11cb.Checked) { $script:varsSystem[10] = $true } else { $script:varsSystem[10] = $false } })

        $systemAllcb = msrdAddCfgCheckbox -cboxtab $DiagTabSystem -text "All" -locX 480 -locY 170
        $systemAllcb.Add_CheckStateChanged({ if ($systemAllcb.Checked) { 
            $script:varsSystem = @(,$true * 11)
            $system1cb.Checked = $true; $system2cb.Checked = $true; $system3cb.Checked = $true; $system4cb.Checked = $true; 
            $system5cb.Checked = $true; $system6cb.Checked = $true; $system7cb.Checked = $true; $system8cb.Checked = $true; 
            $system9cb.Checked = $true; $system10cb.Checked = $true; $system11cb.Checked = $true
        } else { 
            $script:varsSystem = @(,$false * 11)
            $system1cb.Checked = $false; $system2cb.Checked = $false; $system3cb.Checked = $false; $system4cb.Checked = $false; 
            $system5cb.Checked = $false; $system6cb.Checked = $false; $system7cb.Checked = $false; $system8cb.Checked = $false; 
            $system9cb.Checked = $false; $system10cb.Checked = $false; $system11cb.Checked = $false
        } })


    $DiagTabAVDRDS = New-Object System.Windows.Forms.TabPage
    $DiagTabAVDRDS.Text = 'AVD/RDS'

        $avdrds1cb = msrdAddCfgCheckbox -cboxtab $DiagTabAVDRDS -text "Redirection" -locX 20 -locY 20
        $avdrds1cb.Add_CheckStateChanged({ if ($avdrds1cb.Checked) { $script:varsAVDRDS[0] = $true } else { $script:varsAVDRDS[0] = $false } })

        $avdrds2cb = msrdAddCfgCheckbox -cboxtab $DiagTabAVDRDS -text "FSLogix" -locX 20 -locY 50
        $avdrds2cb.Add_CheckStateChanged({ if ($avdrds2cb.Checked) { $script:varsAVDRDS[1] = $true } else { $script:varsAVDRDS[1] = $false } })

        $avdrds3cb = msrdAddCfgCheckbox -cboxtab $DiagTabAVDRDS -text "Multimedia" -locX 20 -locY 80
        $avdrds3cb.Add_CheckStateChanged({ if ($avdrds3cb.Checked) { $script:varsAVDRDS[2] = $true } else { $script:varsAVDRDS[2] = $false } })

        $avdrds4cb = msrdAddCfgCheckbox -cboxtab $DiagTabAVDRDS -text "Quick Assist" -locX 20 -locY 110
        $avdrds4cb.Add_CheckStateChanged({ if ($avdrds4cb.Checked) { $script:varsAVDRDS[3] = $true } else { $script:varsAVDRDS[3] = $false } })

        $avdrds5cb = msrdAddCfgCheckbox -cboxtab $DiagTabAVDRDS -text "RDP / Listener" -locX 20 -locY 140
        $avdrds5cb.Add_CheckStateChanged({ if ($avdrds5cb.Checked) { $script:varsAVDRDS[4] = $true } else { $script:varsAVDRDS[4] = $false } })

        $avdrds6cb = msrdAddCfgCheckbox -cboxtab $DiagTabAVDRDS -text "RDS Roles" -locX 20 -locY 170
        $avdrds6cb.Add_CheckStateChanged({ if ($avdrds6cb.Checked) { $script:varsAVDRDS[5] = $true } else { $script:varsAVDRDS[5] = $false } })

        $avdrds7cb = msrdAddCfgCheckbox -cboxtab $DiagTabAVDRDS -text "Remote Desktop Client" -locX 240 -locY 20
        $avdrds7cb.Add_CheckStateChanged({ if ($avdrds7cb.Checked) { $script:varsAVDRDS[6] = $true } else { $script:varsAVDRDS[6] = $false } })

        $avdrds8cb = msrdAddCfgCheckbox -cboxtab $DiagTabAVDRDS -text "Remote Desktop Licensing" -locX 240 -locY 50
        $avdrds8cb.Add_CheckStateChanged({ if ($avdrds8cb.Checked) { $script:varsAVDRDS[7] = $true } else { $script:varsAVDRDS[7] = $false } })

        $avdrds9cb = msrdAddCfgCheckbox -cboxtab $DiagTabAVDRDS -text "Session Time Limits" -locX 240 -locY 80
        $avdrds9cb.Add_CheckStateChanged({ if ($avdrds9cb.Checked) { $script:varsAVDRDS[8] = $true } else { $script:varsAVDRDS[8] = $false } })

        $avdrds10cb = msrdAddCfgCheckbox -cboxtab $DiagTabAVDRDS -text "Teams media optimization" -locX 20 -locY 110
        $avdrds10cb.Add_CheckStateChanged({ if ($avdrds10cb.Checked) { $script:varsAVDRDS[9] = $true } else { $script:varsAVDRDS[9] = $false } })

        $avdrdsAllcb = msrdAddCfgCheckbox -cboxtab $DiagTabAVDRDS -text "All" -locX 480 -locY 170
        $avdrdsAllcb.Add_CheckStateChanged({ if ($avdrdsAllcb.Checked) { 
            $script:varsAVDRDS = @(,$true * 10)
            $avdrds1cb.Checked = $true; $avdrds2cb.Checked = $true; $avdrds3cb.Checked = $true; $avdrds4cb.Checked = $true; 
            $avdrds5cb.Checked = $true; $avdrds6cb.Checked = $true; $avdrds7cb.Checked = $true; $avdrds8cb.Checked = $true; 
            $avdrds9cb.Checked = $true; $avdrds10cb.Checked = $true;
        } else { 
            $script:varsAVDRDS = @(,$false * 10)
            $avdrds1cb.Checked = $false; $avdrds2cb.Checked = $false; $avdrds3cb.Checked = $false; $avdrds4cb.Checked = $false; 
            $avdrds5cb.Checked = $false; $avdrds6cb.Checked = $false; $avdrds7cb.Checked = $false; $avdrds8cb.Checked = $false; 
            $avdrds9cb.Checked = $false; $avdrds10cb.Checked = $false;
        } })


    $DiagTabAVDInfra = New-Object System.Windows.Forms.TabPage
    $DiagTabAVDInfra.Text = 'AVD Infra'

        $infra1cb = msrdAddCfgCheckbox -cboxtab $DiagTabAVDInfra -text "AVD Agent/Stack" -locX 20 -locY 20
        $infra1cb.Add_CheckStateChanged({ if ($infra1cb.Checked) { $script:varsInfra[0] = $true } else { $script:varsInfra[0] = $false } })

        $infra2cb = msrdAddCfgCheckbox -cboxtab $DiagTabAVDInfra -text "AVD Host Pool" -locX 20 -locY 50
        $infra2cb.Add_CheckStateChanged({ if ($infra2cb.Checked) { $script:varsInfra[1] = $true } else { $script:varsInfra[1] = $false } })

        $infra3cb = msrdAddCfgCheckbox -cboxtab $DiagTabAVDInfra -text "AVD Required URLs" -locX 20 -locY 80
        $infra3cb.Add_CheckStateChanged({ if ($infra3cb.Checked) { $script:varsInfra[2] = $true } else { $script:varsInfra[2] = $false } })

        $infra4cb = msrdAddCfgCheckbox -cboxtab $DiagTabAVDInfra -text "AVD Service URI Health" -locX 20 -locY 110
        $infra4cb.Add_CheckStateChanged({ if ($infra4cb.Checked) { $script:varsInfra[3] = $true } else { $script:varsInfra[3] = $false } })

        $infra5cb = msrdAddCfgCheckbox -cboxtab $DiagTabAVDInfra -text "Azure Stack HCI" -locX 20 -locY 140
        $infra5cb.Add_CheckStateChanged({ if ($infra5cb.Checked) { $script:varsInfra[4] = $true } else { $script:varsInfra[4] = $false } })

        $infra6cb = msrdAddCfgCheckbox -cboxtab $DiagTabAVDInfra -text "RDP Shortpath" -locX 20 -locY 170
        $infra6cb.Add_CheckStateChanged({ if ($infra6cb.Checked) { $script:varsInfra[5] = $true } else { $script:varsInfra[5] = $false } })

        $infraAllcb = msrdAddCfgCheckbox -cboxtab $DiagTabAVDInfra -text "All" -locX 480 -locY 170
        $infraAllcb.Add_CheckStateChanged({ if ($infraAllcb.Checked) { 
            $script:varsInfra = @(,$true * 6)
            $infra1cb.Checked = $true; $infra2cb.Checked = $true; $infra3cb.Checked = $true; $infra4cb.Checked = $true; 
            $infra5cb.Checked = $true; $infra6cb.Checked = $true
        } else { 
            $script:varsInfra = @(,$false * 6)
            $infra1cb.Checked = $false; $infra2cb.Checked = $false; $infra3cb.Checked = $false; $infra4cb.Checked = $false; 
            $infra5cb.Checked = $false; $infra6cb.Checked = $false
        } })


    $DiagTabAD = New-Object System.Windows.Forms.TabPage
    $DiagTabAD.Text = 'Active Directory'

        $ad1cb = msrdAddCfgCheckbox -cboxtab $DiagTabAD -text "Azure AD Join" -locX 20 -locY 20
        $ad1cb.Add_CheckStateChanged({ if ($ad1cb.Checked) { $script:varsAD[0] = $true } else { $script:varsAD[0] = $false } })

        $ad2cb = msrdAddCfgCheckbox -cboxtab $DiagTabAD -text "Domain Controller" -locX 20 -locY 50
        $ad2cb.Add_CheckStateChanged({ if ($ad2cb.Checked) { $script:varsAD[1] = $true } else { $script:varsAD[1] = $false } })

        $adAllcb = msrdAddCfgCheckbox -cboxtab $DiagTabAD -text "All" -locX 480 -locY 170
        $adAllcb.Add_CheckStateChanged({ if ($adAllcb.Checked) { 
            $script:varsAD = @(,$true * 7)
            $ad1cb.Checked = $true; $ad2cb.Checked = $true
        } else { 
            $script:varsAD = @(,$false * 7)
            $ad1cb.Checked = $false; $ad2cb.Checked = $false
        } })


    $DiagTabNet = New-Object System.Windows.Forms.TabPage
    $DiagTabNet.Text = 'Networking'

        $net1cb = msrdAddCfgCheckbox -cboxtab $DiagTabNet -text "DNS" -locX 20 -locY 20
        $net1cb.Add_CheckStateChanged({ if ($net1cb.Checked) { $script:varsNET[0] = $true } else { $script:varsNET[0] = $false } })

        $net2cb = msrdAddCfgCheckbox -cboxtab $DiagTabNet -text "Firewall" -locX 20 -locY 50
        $net2cb.Add_CheckStateChanged({ if ($net2cb.Checked) { $script:varsNET[1] = $true } else { $script:varsNET[1] = $false } })

        $net3cb = msrdAddCfgCheckbox -cboxtab $DiagTabNet -text "Proxy / Route" -locX 20 -locY 80
        $net3cb.Add_CheckStateChanged({ if ($net3cb.Checked) { $script:varsNET[2] = $true } else { $script:varsNET[2] = $false } })

        $net4cb = msrdAddCfgCheckbox -cboxtab $DiagTabNet -text "Public IP" -locX 20 -locY 110
        $net4cb.Add_CheckStateChanged({ if ($net4cb.Checked) { $script:varsNET[3] = $true } else { $script:varsNET[3] = $false } })

        $net5cb = msrdAddCfgCheckbox -cboxtab $DiagTabNet -text "VPN" -locX 20 -locY 140
        $net5cb.Add_CheckStateChanged({ if ($net5cb.Checked) { $script:varsNET[4] = $true } else { $script:varsNET[4] = $false } })

        $netAllcb = msrdAddCfgCheckbox -cboxtab $DiagTabNet -text "All" -locX 480 -locY 170
        $netAllcb.Add_CheckStateChanged({ if ($netAllcb.Checked) { 
            $script:varsNET = @(,$true * 7)
            $net1cb.Checked = $true; $net2cb.Checked = $true; $net3cb.Checked = $true; $net4cb.Checked = $true; 
            $net5cb.Checked = $true
        } else { 
            $script:varsNET = @(,$false * 7)
            $net1cb.Checked = $false; $net2cb.Checked = $false; $net3cb.Checked = $false; $net4cb.Checked = $false; 
            $net5cb.Checked = $false
        } })


    $DiagTabLogSec = New-Object System.Windows.Forms.TabPage
    $DiagTabLogSec.Text = 'Logon/Security'

        $logsec1cb = msrdAddCfgCheckbox -cboxtab $DiagTabLogSec -text "Authentication / Logon" -locX 20 -locY 20
        $logsec1cb.Add_CheckStateChanged({ if ($logsec1cb.Checked) { $script:varsLogSec[0] = $true } else { $script:varsLogSec[0] = $false } })
    
        $logsec2cb = msrdAddCfgCheckbox -cboxtab $DiagTabLogSec -text "Security" -locX 20 -locY 50
        $logsec2cb.Add_CheckStateChanged({ if ($logsec2cb.Checked) { $script:varsLogSec[1] = $true } else { $script:varsLogSec[1] = $false } })

        $logsecAllcb = msrdAddCfgCheckbox -cboxtab $DiagTabLogSec -text "All" -locX 480 -locY 170
        $logsecAllcb.Add_CheckStateChanged({ if ($logsecAllcb.Checked) { 
            $script:varsLogSec = @(,$true * 2)
            $logsec1cb.Checked = $true; $logsec2cb.Checked = $true
        } else { 
            $script:varsLogSec = @(,$false * 2)
            $logsec1cb.Checked = $false; $logsec2cb.Checked = $false
        } })


    $DiagTabIssues = New-Object System.Windows.Forms.TabPage
    $DiagTabIssues.Text = 'Known Issues'

        $issues1cb = msrdAddCfgCheckbox -cboxtab $DiagTabIssues -text "Known Issues: Event Logs" -locX 20 -locY 20
        $issues1cb.Add_CheckStateChanged({ if ($issues1cb.Checked) { $script:varsIssues[0] = $true } else { $script:varsIssues[0] = $false } })

        $issues2cb = msrdAddCfgCheckbox -cboxtab $DiagTabIssues -text "Known Issues: Logon" -locX 20 -locY 50
        $issues2cb.Add_CheckStateChanged({ if ($issues2cb.Checked) { $script:varsIssues[1] = $true } else { $script:varsIssues[1] = $false } })

        $issuesAllcb = msrdAddCfgCheckbox -cboxtab $DiagTabIssues -text "All" -locX 480 -locY 170
        $issuesAllcb.Add_CheckStateChanged({ if ($issuesAllcb.Checked) { 
            $script:varsIssues = @(,$true * 2)
            $issues1cb.Checked = $true; $issues2cb.Checked = $true
        } else { 
            $script:varsIssues = @(,$false * 2)
            $issues1cb.Checked = $false; $issues2cb.Checked = $false
        } })

    
    $DiagTabOther = New-Object System.Windows.Forms.TabPage
    $DiagTabOther.Text = 'Other'

        $other1cb = msrdAddCfgCheckbox -cboxtab $DiagTabOther -text "Microsoft Office" -locX 20 -locY 20
        $other1cb.Add_CheckStateChanged({ if ($other1cb.Checked) { $script:varsOther[0] = $true } else { $script:varsOther[0] = $false } })

        $other2cb = msrdAddCfgCheckbox -cboxtab $DiagTabOther -text "Microsoft OneDrive" -locX 20 -locY 50
        $other2cb.Add_CheckStateChanged({ if ($other2cb.Checked) { $script:varsOther[1] = $true } else { $script:varsOther[1] = $false } })

        $other3cb = msrdAddCfgCheckbox -cboxtab $DiagTabOther -text "Printing" -locX 20 -locY 80
        $other3cb.Add_CheckStateChanged({ if ($other3cb.Checked) { $script:varsOther[2] = $true } else { $script:varsOther[2] = $false } })

        $other4cb = msrdAddCfgCheckbox -cboxtab $DiagTabOther -text "Third Party" -locX 20 -locY 110
        $other4cb.Add_CheckStateChanged({ if ($other4cb.Checked) { $script:varsOther[3] = $true } else { $script:varsOther[3] = $false } })

        $otherAllcb = msrdAddCfgCheckbox -cboxtab $DiagTabOther -text "All" -locX 480 -locY 170
        $otherAllcb.Add_CheckStateChanged({ if ($otherAllcb.Checked) { 
            $script:varsOther = @(,$true * 7)
            $other1cb.Checked = $true; $other2cb.Checked = $true; $other3cb.Checked = $true; $other4cb.Checked = $true
        } else { 
            $script:varsOther = @(,$false * 7)
            $other1cb.Checked = $false; $other2cb.Checked = $false; $other3cb.Checked = $false; $other4cb.Checked = $false
        } })

    # Add tabs to tab control
    $MainDiagTab.Controls.AddRange(@($DiagTabSystem,$DiagTabAVDRDS,$DiagTabAVDInfra,$DiagTabAD,$DiagTabNet,$DiagTabLogSec,$DiagTabIssues,$DiagTabOther))
    $selectDiagForm.Controls.Add($MainDiagTab)

    #endregion granular collection

    #region UserContext
    $userContextForm = New-Object System.Windows.Forms.Form
    $userContextForm.Width = 400
    $userContextForm.Height = 150
    $userContextForm.StartPosition = "CenterScreen"
    $userContextForm.ControlBox = $False
    $userContextForm.BackColor = "#eeeeee"
    $userContextForm.Text = msrdGetLocalizedText "context1"

    $userContextLabel = New-Object System.Windows.Forms.Label
    $userContextLabel.Location  = New-Object System.Drawing.Point(20,20)
    $userContextLabel.Size  = New-Object System.Drawing.Point(350,30)
    $userContextLabel.Text = msrdGetLocalizedText "context2"
    $userContextForm.Controls.Add($userContextLabel)

    $userContextBox = New-Object System.Windows.Forms.TextBox
    $userContextBox.Location  = New-Object System.Drawing.Point(20,60)
    $userContextBox.Size  = New-Object System.Drawing.Point(170,30)
    $userContextBox.Cursor = [System.Windows.Forms.Cursors]::Hand
    if ($global:msrdUserprof) {
        $userContextBox.Text = $global:msrdUserprof
    } else {
        $userContextBox.Text = [System.Environment]::UserName; $global:msrdUserprof = [System.Environment]::UserName
    }
    $userContextForm.Controls.Add($userContextBox)

    $userContextOK = New-Object System.Windows.Forms.Button
    $userContextOK.Location = New-Object System.Drawing.Size(230,58)
    $userContextOK.Size = New-Object System.Drawing.Size(60,25)
    $userContextOK.Text = "OK"
    $userContextOK.BackColor = "white"
    $userContextOK.Cursor = [System.Windows.Forms.Cursors]::Hand
    $userContextForm.Controls.Add($userContextOK)
    $userContextOK.Add_Click({
        if ($userContextBox.Text) {
            $tempUserprof = $userContextBox.Text
            if (Test-Path -Path ("C:\Users\" + $tempUserprof)) {
                $global:msrdUserprof = $userContextBox.Text
            } else {
                if ($global:msrdUserprof) {
                    $userContextBox.Text = $global:msrdUserprof
                } else {
                    $userContextBox.Text = [System.Environment]::UserName; $global:msrdUserprof = [System.Environment]::UserName
                }
                [System.Windows.Forms.MessageBox]::Show("No local profile found for the specificed '$tempUserprof' user.`nUser context has been reset to: $($userContextBox.Text)", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                return
            }
        } else {
            $userContextBox.Text = [System.Environment]::UserName; $global:msrdUserprof = [System.Environment]::UserName
        }
        $userContextForm.Close()
        msrdAdd-OutputBoxLine "$(msrdGetLocalizedText "context3") $($userContextBox.Text)`n" "Yellow"
    })

    $userContextCancel = New-Object System.Windows.Forms.Button
    $userContextCancel.Location = New-Object System.Drawing.Size(300,58)
    $userContextCancel.Size = New-Object System.Drawing.Size(60,25)
    $userContextCancel.Text = "Cancel"
    $userContextCancel.BackColor = "white"
    $userContextCancel.Cursor = [System.Windows.Forms.Cursors]::Hand
    $userContextForm.Controls.Add($userContextCancel)
    $userContextCancel.Add_Click({
        if ($global:msrdUserprof) {
            $userContextBox.Text = $global:msrdUserprof
        } else {
            $userContextBox.Text = [System.Environment]::UserName; $global:msrdUserprof = [System.Environment]::UserName
        }
        $userContextForm.Close()
        msrdAdd-OutputBoxLine "$(msrdGetLocalizedText "context3") $($userContextBox.Text)`n" "Yellow"
    })
    #endregion UserContext

    #region BottomOptions

    $global:msrdStatusBarMain = New-Object System.Windows.Forms.StatusStrip
    $global:msrdStatusBar = New-Object System.Windows.Forms.ToolStripStatusLabel
    $global:msrdStatusBar.Text = "Ready"
    $global:msrdStatusBarMain.Items.Add($global:msrdStatusBar) | Out-Null
    $global:msrdGUIform.Controls.Add($global:msrdStatusBarMain)

    $global:msrdProgbar = New-Object System.Windows.Forms.ProgressBar
    $global:msrdProgbar.Location  = New-Object System.Drawing.Point(10,645)
    $global:msrdProgbar.Size = New-Object System.Drawing.Size(300,15)
    $global:msrdProgbar.Anchor = 'Left,Bottom'
    $global:msrdProgbar.DataBindings.DefaultDataSourceUpdateMode = 0
    $global:msrdProgbar.Step = 1
    $global:msrdGUIform.Controls.Add($global:msrdProgbar)

    $surveyLink = New-Object System.Windows.Forms.LinkLabel
    $surveyLink.Location = [System.Drawing.Point]::new(790, 645)
    $surveyLink.Size = [System.Drawing.Point]::new(180, 20)
    $surveyLink.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $surveyLink.LinkColor = [System.Drawing.Color]::Blue
    $surveyLink.ActiveLinkColor = [System.Drawing.Color]::Red
    $surveyLink.Text = msrdGetLocalizedText "surveyLink1"
    $surveyLink.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
    $surveyLink.Add_Click({ [System.Diagnostics.Process]::Start('https://aka.ms/MSRD-Collect-Survey') })
    $surveyLinkToolTip = New-Object System.Windows.Forms.ToolTip
    $surveyLinkToolTip.SetToolTip($surveyLink, '$(msrdGetLocalizedText "surveyLink1")')
    $global:msrdGUIform.Controls.Add($surveyLink)

    #endregion BottomOptions
    
    $global:msrdGUIform.Add_Shown({

        msrdInitMachines
        msrdInitScenarioVars
        msrdInitScenarioBtns -buttons $TbProcDump, $TbDiagOnly, $TbNetTrace, $TbStart, $TbCore, $TbProfiles, $TbActivation, $TbMSRA, $TbSCard, $TbIME, $TbTeams, $TbMSIXAA, $TbHCI -isEnabled $false        

        #check tools
        if ($global:avdnettestpath -eq "") {
            msrdAdd-OutputBoxLine ("avdnettest.exe could not be found. Information on RDP Shortpath for AVD availability will be incomplete. Make sure you download and unpack the full package of MSRD-Collect or TSSv2`n") -Color "Red"
        }

        if ($global:msrdAutoVerCheck -eq 1) { msrdCheckVersion($msrdVersion) } else { msrdAdd-OutputBoxLine "Automatic update check on script launch is Disabled" }

        msrdInitScript -Type GUI
        msrdInitHowTo
    })

    if ($global:msrdShowConsole -eq 1) { msrdStartShowConsole } else { msrdStartHideConsole }
    msrdRefreshUILang "EN"

    $global:msrdGUIform.ShowDialog() | Out-Null
    msrdStartShowConsole -nocfg $true
}


Export-ModuleMember -Function msrdAdd-OutputBoxLine, msrdFind-Folder, msrdAVDCollectGUI
# SIG # Begin signature block
# MIInlAYJKoZIhvcNAQcCoIInhTCCJ4ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDxlpN4gepDY7vQ
# A+fCwaEsV2WtViLz2x9PnvHimIuaTqCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXQwghlwAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILqtVU0Awpplx7SC8tf/b5uB
# yIkvlLhhfmHnLEkqwTccMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAUH4BN7RdVTRK00eso/V+3q9w88nfcWhNpFgsgwHFDHZ7JmgZdeGXwXSR
# 9Ic0WMudUz5ABttSa44jkHJsfVJtL60JYjgq2B/u5uWDdj/JKktqmFuIfOZ76qcG
# nslCuW/e43v+jML5uJwY5itpN8NIeDi/mlz8ZLzpuVCan4T79EbjAWcC0DC9t7ib
# qT4Z8S2D2IUK4fizpUF5yRwgcLPU1C0erBNP8SsUqaxT2ES5fsG6mU+S2pM7W5WI
# FyTIS2LyzvybJQoa+0Sm0kwLPSS9mv1fLYlwdtErpZgruirrXltZ7XmcciGBYvE3
# wpjmP+ywe5k25QxeF4ltJjn1tzToaaGCFv4wghb6BgorBgEEAYI3AwMBMYIW6jCC
# FuYGCSqGSIb3DQEHAqCCFtcwghbTAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCCLnqbv40ZVMOf6oyFKYP0DdB/miL9SS6x37/wrJoO5zgIGZGzBYiT+
# GBMyMDIzMDUyMzE0NDQ1Mi40NDNaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpERDhDLUUz
# MzctMkZBRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVUwggcMMIIE9KADAgECAhMzAAABxQPNzSGh9O85AAEAAAHFMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEz
# MloXDTI0MDIwMjE5MDEzMlowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkREOEMtRTMzNy0yRkFFMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAq0hds70eX23J7pappaKXRhz+TT7JJ3OvVf3+N8fNpxRs
# 5jY4hEv3BV/w5EWXbZdO4m3xj01lTI/xDkq+ytjuiPe8xGXsZxDntv7L1EzMd5jI
# SqJ+eYu8kgV056mqs8dBo55xZPPPcxf5u19zn04aMQF5PXV/C4ZLSjFa9IFNcrib
# dOm3lGW1rQRFa2jUsup6gv634q5UwH09WGGu0z89RbtbyM55vmBgWV8ed6bZCZrc
# oYIjML8FRTvGlznqm6HtwZdXMwKHT3a/kLUSPiGAsrIgEzz7NpBpeOsgs9TrwyWT
# ZBNbBwyIACmQ34j+uR4et2hZk+NH49KhEJyYD2+dOIaDGB2EUNFSYcy1MkgtZt1e
# RqBB0m+YPYz7HjocPykKYNQZ7Tv+zglOffCiax1jOb0u6IYC5X1Jr8AwTcsaDyu3
# qAhx8cFQN9DDgiVZw+URFZ8oyoDk6sIV1nx5zZLy+hNtakePX9S7Y8n1qWfAjoXP
# E6K0/dbTw87EOJL/BlJGcKoFTytr0zPg/MNJSb6f2a/wDkXoGCGWJiQrGTxjOP+R
# 96/nIIG05eE1Lpky2FOdYMPB4DhW7tBdZautepTTuShmgn+GKER8AoA1gSSk1EC5
# ZX4cppVngJpblMBu8r/tChfHVdXviY6hDShHwQCmZqZebgSYHnHl4urE+4K6ZC8C
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBRU6rs4v1mxNYG/rtpLwrVwek0FazAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQCMqN58frMHOScciK+Cdnr6dK8fTsgQDeZ9bvQjCuxNIJZJ92+xpeKRCf3Xq47q
# dRykkKUnZC6dHhLwt1fhwyiy/LfdVQ9yf1hYZ/RpTS+z0hnaoK+P/IDAiUNm32NX
# LhDBu0P4Sb/uCV4jOuNUcmJhppBQgQVhFx/57JYk1LCdjIee//GrcfbkQtiYob9O
# a93DSjbsD1jqaicEnkclUN/mEm9ZsnCnA1+/OQDp/8Q4cPfH94LM4J6X0NtNBeVy
# wvWH0wuMaOJzHgDLCeJUkFE9HE8sBDVedmj6zPJAI+7ozLjYqw7i4RFbiStfWZSG
# jwt+lLJQZRWUCcT3aHYvTo1YWDZskohWg77w9fF2QbiO9DfnqoZ7QozHi7RiPpbj
# gkJMAhrhpeTf/at2e9+HYkKObUmgPArH1Wjivwm1d7PYWsarL7u5qZuk36Gb1mET
# S1oA2XX3+C3rgtzRohP89qZVf79lVvjmg34NtICK/pMk99SButghtipFSMQdbXUn
# S2oeLt9cKuv1MJu+gJ83qXTNkQ2QqhxtNRvbE9QqmqJQw5VW/4SZze1pPXxyOTO5
# yDq+iRIUubqeQzmUcCkiyNuCLHWh8OLCI5mIOC1iLtVDf2lw9eWropwu5SDJtT/Z
# wqIU1qb2U+NjkNcj1hbODBRELaTTWd91RJiUI9ncJkGg/jCCB3EwggVZoAMCAQIC
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
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLMMIICNQIBATCB+KGB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046REQ4Qy1FMzM3LTJGQUUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVACEAGvYXZJK7cUo62+LvEYQEx7/noIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoFz/iMCIYDzIwMjMwNTIzMjEzNjM0WhgPMjAyMzA1MjQyMTM2MzRaMHUw
# OwYKKwYBBAGEWQoEATEtMCswCgIFAOgXP+ICAQAwCAIBAAIDA5RCMAcCAQACAhIM
# MAoCBQDoGJFiAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAI
# AgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAAy9RNc1LVup1
# LR80i+j4uL705vcTklG3bL8XRjhWRv0Iy/thCK6KJLn4zJllJZyhKb53VXpgB9x7
# +cN95jvWXlzzVnTn8iEJkrFwjVj49wUWm7goEYzssfMRwvNtT8cLAKhgc2gmzinl
# OYIpewgj6Azg0njK1e28/c6OWWSgUlcxggQNMIIECQIBATCBkzB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAcUDzc0hofTvOQABAAABxTANBglghkgB
# ZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3
# DQEJBDEiBCBhiSx7uel0TFmSw1o1IF9oz4kUYsPXCc3oz94xXw8/TjCB+gYLKoZI
# hvcNAQkQAi8xgeowgecwgeQwgb0EIBkBsZH2JHdMCvldPcDtLDvrJvIADMo+RLij
# 6rzUP3yxMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAHFA83NIaH07zkAAQAAAcUwIgQgkBN8MJD1/HE+0EQYfUx9+i1GWCkE3dVr9eha
# NGThmBowDQYJKoZIhvcNAQELBQAEggIAMLFLQC3NNC9Hnt+0j1HgLpMrMAKmnpVt
# O1qavO8SgmudEYWaU+KgcOHE5Wdu5RfQq3XEYPhwafpWtiz854rMbylGJnjb1a+v
# cRw0y9Ax6XJOrNwcE6zJsbXh9xOQgvX6atjHXNhdTX7LYTaD7IsHrE593nCyODdf
# AinIO891Fd9jAw86FQ0b/FBXxu/vqw1p0bf4cz12J4WZbp4N+qero+mQooqlTtNH
# 7an6/9vkT8+q8KS6PDmGfNaSrkJz2vcKrJ505CGDhZ3B4meALUEpdvMt137oOQNA
# C8sW5gJzDAN/cl4TO+l4x63tnUri9fhtS6Tvy4+L/pLwzdFIFktXyZbNBzQ7qzsY
# mzp2ZCAg/ZQaiWrykJpiG9U1QtTun+bpd/Nrk3LXiCr6rXOMCn7RwqrYuuZFc/YF
# JtOcgYcpqXUu44m390gsyJc4MYdGz+oLNNqlqEwaBR7n4q87OSkqI6u+RHcIFhT+
# qb2JxJXI3Q1DAr8m9cMFXLcHUhALt8rl/uZiAUb4C89BMVpaHIshkr6PZxX1VdUN
# c2MEZRJpECVPm48DhrtswTaktfoX33OkRxFjyBPiN0WS0HBYh9zx+ikr2ZjCtvlL
# 8qc41jT6MTivsbJ2lWX4V2XtLQDRogr3x72yfaoGBxdY1WfYHx5bZQhl3e+/nnqm
# 0Evc4I0DfAk=
# SIG # End signature block
