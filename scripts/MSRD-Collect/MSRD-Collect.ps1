<#
.SYNOPSIS
    Simplify data collection and diagnostics for troubleshooting Microsoft Remote Desktop (RDP/RDS/AVD/W365) related issues and a convenient method for submitting and following quick & easy action plans.

.DESCRIPTION
    This script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Microsoft Remote Desktop solutions.
    The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses; PC names; and user names.
    The script will save the collected data in a folder (default C:\MSDATA) and also compress the results into a ZIP file.
    This folder and its contents or the ZIP file are not automatically sent to Microsoft.
    You can send the ZIP file to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have.
    Find our privacy statement here: https://privacy.microsoft.com/en-US/privacystatement

    Run 'Get-Help .\MSRD-Collect.ps1 -Full' for more details.

    USAGE SUMMARY:
    The script must be run with elevated permissions in order to collect all required data.
    Run the script on session host VMs and/or on Windows based devices from where you connect to the hosts, as needed.

    The script has multiple module (.psm1) files located in a "Modules" folder. This folder (with its underlying .psm1 files) must stay in the same folder as the main MSRD-Collect.ps1
    file for the script to work properly.
    The script will import the required module(s) on the fly when specific data is being invoked. You do not need to manually import the modules.

    When launched without any command line parameters, the script will start in GUI mode where you can select one or more data collection or diagnostics scenarios.
    If you prefer to run the script without a GUI or to automate data collection/diagnostics, use command line parameters.
    Diagnostics will run regardless if other data collection scenarios have been selected.

.NOTES
    Authors          : Robert Klemencz (Microsoft) & Alexandru Olariu (Microsoft)
    Requires         : At least PowerShell 5.1 and to be run elevated
    Version          : 230523.3 (May 23, 2023)

.LINK
    Download: https://aka.ms/MSRD-Collect
    Feedback: mailto:MSRDCollectTalk@microsoft.com
    Survey:   https://aka.ms/MSRD-Collect-Survey

.PARAMETER Machine
    Indicates the type of machine from where data is collected. This is a mandatory parameter when not using the GUI
    Based on the provided value, only data specific to that machine type will be collected
    Available values are:
        isSource   : Source (client) machine that connects to other machines through a Remote Desktop client
        isAVD      : Target (host) machine in an Azure Virtual Desktop or Windows 365 deployment
        isRDS      : RDS server running any RDS roles or target machine for a direct (non-AVD) RDP connection

.PARAMETER Core
    Collect basic AVD/RDS troubleshooting data (without Profiles/Teams/MSIX App Attach/MSRA/Smart Card/IME/Azure Stack HCI related data). Diagnostics will run at the end.

.PARAMETER Profiles
    Collect Core + Profiles troubleshooting data. Diagnostics will run at the end.

.PARAMETER Activation
    Collect Core + OS Licensing/Activation troubleshooting data. Diagnostics will run at the end.

.PARAMETER MSRA
    Collect Core + Remote Assistance troubleshooting data. Diagnostics will run at the end.

.PARAMETER SCard
    Collect Core + Smart Card troubleshooting data. Diagnostics will run at the end.

.PARAMETER IME
    Collect Core + input method troubleshooting data. Diagnostics will run at the end.

.PARAMETER Teams
    Collect Core + Microsoft Teams troubleshooting data. Diagnostics will run at the end. (AVD specific)

.PARAMETER MSIXAA
    Collect Core + MSIX App Attach troubleshooting data. Diagnostics will run at the end. (AVD specific)

.PARAMETER HCI
    Collect Core + Azure Stack HCI troubleshooting data. Diagnostics will run at the end. (AVD specific)

.PARAMETER DumpPID
    Collect Core troubleshooting data + Collect a process dump based on the provided PID. Diagnostics will run at the end.

.PARAMETER NetTrace
    Collect a netsh network trace (netsh trace start scenario=netconnection maxsize=2048 filemode=circular overwrite=yes report=yes)

.PARAMETER DiagOnly
    Skip collecting troubleshooting data (even if any other parameters are specificed) and will only perform diagnostics. The results of the diagnostics will be stored in the 'MSRD-Diag.txt' and 'MSRD-Diag.html' files.
    Depending on the issues found during the diagnostic, additional files may be generated with exported event log entries coresponding to those identified issues.

.PARAMETER AcceptEula
    Silently accepts the Microsoft Diagnostic Tools End User License Agreement.

.PARAMETER AcceptNotice
    Silently accepts the Important Notice message displayed when the script is launched.

.PARAMETER OutputDir
    ​​​​​​Specify a custom directory where to store the collected files. By default, if this parameter is not specified, the script will store the collected data under "C:\MSDATA". If the path specified does not exit, the script will attempt to create it.

.PARAMETER UserContext
    Define the user in whose context some of the data (e.g. RDClientAutoTrace, Teams settings) will be collected

.PARAMETER SkipAutoUpdate
    Skips the automatic update check on launch for the current instance of the script (can be used for both GUI and command line mode)


.OUTPUTS
    By default, all collected data are stored in a subfolder under C:\MSDATA. You can change this location by using the "-OutputDir" command line parameter.

#>

param ([ValidateSet('isSource', 'isAVD', 'isRDS')][string]$Machine, 
    [switch]$Core = $false, [switch]$Profiles = $false, [switch]$Activation = $false, [switch]$MSRA = $false, [switch]$SCard = $false, [switch]$IME = $false,
    [switch]$Teams = $false, [switch]$MSIXAA = $false, [switch]$HCI = $false, [int]$DumpPID, [switch]$DiagOnly = $false, [switch]$NetTrace = $false,
    [switch]$AcceptEula, [switch]$AcceptNotice = $false, [string]$OutputDir, [string]$UserContext, [switch]$SkipAutoUpdate = $false,
    [switch]$isTSS = $false, [switch]$msrdSkipCore = $false, [switch]$msrdSkipDiag = $false)

$global:msrdVersion = "230523.3"
$global:msrdVersioncheck = $false
$global:msrdCollectcount = 0
$global:msrdProgress = 0
$global:msrdScriptpath = $PSScriptRoot
$global:msrdLangID = "EN"

# Check if the script is running as part of TSSv2
if ($isTSS) {
    $global:TSSinUse = $true
    $AcceptNotice = $true
    $global:msrdSkipArchive = $true
} else {
    $global:TSSinUse = $false
    $global:msrdSkipArchive = $false
}

# Check if the current user is an administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Warning "This script needs to be run as Administrator"
    Exit 1
}

# Check if the 'Modules' folder exists in the script root
if (-not (Test-Path -Path "$PSScriptRoot\Modules" -PathType Container)) {
    Write-Warning "'Modules' folder not found. Please make sure you are using the official MSRD-Collect package from https://aka.ms/MSRD-Collect, with all included files. Launch MSRD-Collect.ps1 from within the same folder that contains the script's 'Modules' subfolder. See MSRD-Collect-ReadMe.txt for more details."
    Exit 1
}

# Check if the script is running in PowerShell ISE
if ($host.Name -eq 'Windows PowerShell ISE Host') {
    Write-Warning "MSRD-Collect is running in PowerShell ISE. Running MSRD-Collect in PowerShell ISE is not supported. Please run the script in a regular elevated/admin PowerShell window."
    Exit 1
}

#check tools
if ($global:TSSinUse) {
    $global:msrdToolsFolder = "$global:ScriptFolder\BIN"

    if (Test-Path -Path "$global:msrdToolsFolder\avdnettest.exe") {
        $global:avdnettestpath = "$global:msrdToolsFolder\avdnettest.exe"
    } else {
        $global:avdnettestpath = ""
    }

    if (Test-Path -Path "$global:msrdToolsFolder\procdump.exe") {
        $global:msrdProcDumpExe = "$global:msrdToolsFolder\procdump.exe"
    } else {
        $global:msrdProcDumpExe = ""
    }

} else {
    if (Test-Path -Path "$global:msrdScriptpath\Tools\avdnettest.exe") {
        $global:avdnettestpath = "$global:msrdScriptpath\Tools\avdnettest.exe"
    } else {
        $tssPathAVD = $global:msrdScriptpath -ireplace [regex]::Escape("\scripts\MSRD-Collect"), "\BIN"
        if (Test-Path -Path "$tssPathAVD\avdnettest.exe") {
            $global:avdnettestpath = "$tssPathAVD\avdnettest.exe"
        } else {
            $global:avdnettestpath = ""
        }
    }

    if (Test-Path -Path "$global:msrdScriptpath\Tools\procdump.exe") {
        $global:msrdToolsFolder = "$global:msrdScriptpath\Tools\"
        $global:msrdProcDumpExe = $global:msrdToolsFolder + "procdump.exe"
    } else {
        $tssPathPD = $global:msrdScriptpath -ireplace [regex]::Escape("\scripts\MSRD-Collect"), "\BIN"
        if (Test-Path -Path "$tssPathPD\procdump.exe") {
            $global:msrdToolsFolder = "$tssPathPD\"
            $global:msrdProcDumpExe = $global:msrdToolsFolder + "procdump.exe"
        } else {
            $global:msrdToolsFolder = "$global:msrdScriptpath\Tools\"
            $global:msrdProcDumpExe = ""
        }
    }
}

# Read config file
$msrdConfigFile = "$PSScriptRoot\MSRD-Collect.cfg"
$msrdConfigData = Get-Content $msrdConfigFile | Out-String
$msrdConfig = ConvertFrom-StringData $msrdConfigData

if ($global:msrdProcDumpExe -eq "") {
    $global:msrdProcDumpVer = "1.0"
} else {
    $global:msrdProcDumpVer = $msrdConfig.ProcDumpVersion
}

$global:msrdShowConsole = $msrdConfig.ShowConsoleWindow

# Check if auto update check should be performed
if ($SkipAutoUpdate) {
    $global:msrdAutoVerCheck = 0
    Write-Output "Parameter '-SkipAutoUpdate' has been specified. Automatic update check on script launch will be skipped."
} else { 
    $global:msrdAutoVerCheck = $msrdConfig.AutomaticVersionCheck
}

# Initialize localization
$localizationFilePath = Join-Path $global:msrdScriptpath "Modules\MSRDC-Localization.xml"
if (Test-Path -Path $localizationFilePath) {
	try {
		[xml] $global:msrdLangText = Get-Content -Path $localizationFilePath -ErrorAction Stop
	}
	catch {
		Write-Warning "[Error]: Could not read the MSRDC-Localization.xml file: $_. Can not load display text messages. Make sure you download and unpack the full package of MSRD-Collect from https://aka.ms/MSRD-Collect"
		Exit
	}
} else {
	Write-Warning "[Error]: Could not find the MSRDC-Localization.xml file, can not load display text messages. Make sure you download and unpack the full package of MSRD-Collect from https://aka.ms/MSRD-Collect"
	Exit
}

# Unlock module files after initial download, if needed
Get-ChildItem -Recurse -Path $PSScriptRoot\Modules\MSRDC*.psm1 | ForEach-Object {
    Try {
        Unblock-File $_.FullName -Confirm:$false -ErrorAction Stop
        Write-Verbose "Unblocked file: $($_.FullName)"
    } Catch {
        Write-Warning "Failed to unblock file: $($_.FullName) - $($_.Exception.Message)"
    }
}

# Set initial output folder
If ($OutputDir) {
    $global:msrdLogRoot = $OutputDir
} else {
    if ($global:TSSinUse) {
        $global:msrdLogRoot = $global:LogFolder
    } else {
        $global:msrdLogRoot = "C:\MSDATA"
    }
}

# Check if local user profile for the provided user context exists
if ($UserContext) {
        if (Test-Path -Path ("C:\Users\" + $UserContext)) {
            $global:msrdUserprof = $UserContext
        } else {
            [System.Windows.Forms.MessageBox]::Show("No local profile found for the specificed '$UserContext' user.`nExiting.", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            Exit
        }
} else {
    $global:msrdUserprof = $env:USERNAME
}

$global:msrdOSVer = (Get-CimInstance Win32_OperatingSystem).Caption
$global:msrdFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName

[int]$global:WinVerBuild = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' CurrentBuild).CurrentBuild

$global:msrdCollecting = $False
$global:msrdDiagnosing = $False

Set-Variable -Name 'fLogFileOnly' -Value $True -Scope Global

$drawingAssembly = [System.Reflection.Assembly]::Load('System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
$formsAssembly = [System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')

#region ### Main Functions ###

function msrdShowEULAPopup($mode) {
    $EULA = New-Object -TypeName System.Windows.Forms.Form
    $richTextBox1 = New-Object System.Windows.Forms.RichTextBox
    $btnAcknowledge = New-Object System.Windows.Forms.Button
    $btnCancel = New-Object System.Windows.Forms.Button

    $EULA.SuspendLayout()
    $EULA.Name = "EULA"
    $EULA.Text = "Microsoft Diagnostic Tools End User License Agreement"

    $richTextBox1.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $richTextBox1.Location = New-Object System.Drawing.Point(12,12)
    $richTextBox1.Name = "richTextBox1"
    $richTextBox1.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
    $richTextBox1.Size = New-Object System.Drawing.Size(776, 397)
    $richTextBox1.TabIndex = 0
    $richTextBox1.ReadOnly=$True
    $richTextBox1.Add_LinkClicked({Start-Process -FilePath $_.LinkText})
    $richTextBox1.Rtf = @"
{\rtf1\ansi\ansicpg1252\deff0\nouicompat{\fonttbl{\f0\fswiss\fprq2\fcharset0 Segoe UI;}{\f1\fnil\fcharset0 Calibri;}{\f2\fnil\fcharset0 Microsoft Sans Serif;}}
{\colortbl ;\red0\green0\blue255;}
{\*\generator Riched20 10.0.19041}{\*\mmathPr\mdispDef1\mwrapIndent1440 }\viewkind4\uc1
\pard\widctlpar\f0\fs19\lang1033 MICROSOFT SOFTWARE LICENSE TERMS\par
Microsoft Diagnostic Scripts and Utilities\par
\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}These license terms are an agreement between you and Microsoft Corporation (or one of its affiliates). IF YOU COMPLY WITH THESE LICENSE TERMS, YOU HAVE THE RIGHTS BELOW. BY USING THE SOFTWARE, YOU ACCEPT THESE TERMS.\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}\par
\pard
{\pntext\f0 1.\tab}{\*\pn\pnlvlbody\pnf0\pnindent0\pnstart1\pndec{\pntxta.}}
\fi-360\li360 INSTALLATION AND USE RIGHTS. Subject to the terms and restrictions set forth in this license, Microsoft Corporation (\ldblquote Microsoft\rdblquote ) grants you (\ldblquote Customer\rdblquote  or \ldblquote you\rdblquote ) a non-exclusive, non-assignable, fully paid-up license to use and reproduce the script or utility provided under this license (the "Software"), solely for Customer\rquote s internal business purposes, to help Microsoft troubleshoot issues with one or more Microsoft products, provided that such license to the Software does not include any rights to other Microsoft technologies (such as products or services). \ldblquote Use\rdblquote  means to copy, install, execute, access, display, run or otherwise interact with the Software. \par
\pard\widctlpar\par
\pard\widctlpar\li360 You may not sublicense the Software or any use of it through distribution, network access, or otherwise. Microsoft reserves all other rights not expressly granted herein, whether by implication, estoppel or otherwise. You may not reverse engineer, decompile or disassemble the Software, or otherwise attempt to derive the source code for the Software, except and to the extent required by third party licensing terms governing use of certain open source components that may be included in the Software, or remove, minimize, block, or modify any notices of Microsoft or its suppliers in the Software. Neither you nor your representatives may use the Software provided hereunder: (i) in a way prohibited by law, regulation, governmental order or decree; (ii) to violate the rights of others; (iii) to try to gain unauthorized access to or disrupt any service, device, data, account or network; (iv) to distribute spam or malware; (v) in a way that could harm Microsoft\rquote s IT systems or impair anyone else\rquote s use of them; (vi) in any application or situation where use of the Software could lead to the death or serious bodily injury of any person, or to physical or environmental damage; or (vii) to assist, encourage or enable anyone to do any of the above.\par
\par
\pard\widctlpar\fi-360\li360 2.\tab DATA. Customer owns all rights to data that it may elect to share with Microsoft through using the Software. You can learn more about data collection and use in the help documentation and the privacy statement at {{\field{\*\fldinst{HYPERLINK https://aka.ms/privacy }}{\fldrslt{https://aka.ms/privacy\ul0\cf0}}}}\f0\fs19 . Your use of the Software operates as your consent to these practices.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 3.\tab FEEDBACK. If you give feedback about the Software to Microsoft, you grant to Microsoft, without charge, the right to use, share and commercialize your feedback in any way and for any purpose.\~ You will not provide any feedback that is subject to a license that would require Microsoft to license its software or documentation to third parties due to Microsoft including your feedback in such software or documentation. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 4.\tab EXPORT RESTRICTIONS. Customer must comply with all domestic and international export laws and regulations that apply to the Software, which include restrictions on destinations, end users, and end use. For further information on export restrictions, visit {{\field{\*\fldinst{HYPERLINK https://aka.ms/exporting }}{\fldrslt{https://aka.ms/exporting\ul0\cf0}}}}\f0\fs19 .\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 5.\tab REPRESENTATIONS AND WARRANTIES. Customer will comply with all applicable laws under this agreement, including in the delivery and use of all data. Customer or a designee agreeing to these terms on behalf of an entity represents and warrants that it (i) has the full power and authority to enter into and perform its obligations under this agreement, (ii) has full power and authority to bind its affiliates or organization to the terms of this agreement, and (iii) will secure the permission of the other party prior to providing any source code in a manner that would subject the other party\rquote s intellectual property to any other license terms or require the other party to distribute source code to any of its technologies.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 6.\tab DISCLAIMER OF WARRANTY. THE SOFTWARE IS PROVIDED \ldblquote AS IS,\rdblquote  WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL MICROSOFT OR ITS LICENSORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\par
\pard\widctlpar\qj\par
\pard\widctlpar\fi-360\li360\qj 7.\tab LIMITATION ON AND EXCLUSION OF DAMAGES. IF YOU HAVE ANY BASIS FOR RECOVERING DAMAGES DESPITE THE PRECEDING DISCLAIMER OF WARRANTY, YOU CAN RECOVER FROM MICROSOFT AND ITS SUPPLIERS ONLY DIRECT DAMAGES UP TO U.S. $5.00. YOU CANNOT RECOVER ANY OTHER DAMAGES, INCLUDING CONSEQUENTIAL, LOST PROFITS, SPECIAL, INDIRECT, OR INCIDENTAL DAMAGES. This limitation applies to (i) anything related to the Software, services, content (including code) on third party Internet sites, or third party applications; and (ii) claims for breach of contract, warranty, guarantee, or condition; strict liability, negligence, or other tort; or any other claim; in each case to the extent permitted by applicable law. It also applies even if Microsoft knew or should have known about the possibility of the damages. The above limitation or exclusion may not apply to you because your state, province, or country may not allow the exclusion or limitation of incidental, consequential, or other damages.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 8.\tab BINDING ARBITRATION AND CLASS ACTION WAIVER. This section applies if you live in (or, if a business, your principal place of business is in) the United States.  If you and Microsoft have a dispute, you and Microsoft agree to try for 60 days to resolve it informally. If you and Microsoft can\rquote t, you and Microsoft agree to binding individual arbitration before the American Arbitration Association under the Federal Arbitration Act (\ldblquote FAA\rdblquote ), and not to sue in court in front of a judge or jury. Instead, a neutral arbitrator will decide. Class action lawsuits, class-wide arbitrations, private attorney-general actions, and any other proceeding where someone acts in a representative capacity are not allowed; nor is combining individual proceedings without the consent of all parties. The complete Arbitration Agreement contains more terms and is at {{\field{\*\fldinst{HYPERLINK https://aka.ms/arb-agreement-4 }}{\fldrslt{https://aka.ms/arb-agreement-4\ul0\cf0}}}}\f0\fs19 . You and Microsoft agree to these terms. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 9.\tab LAW AND VENUE. If U.S. federal jurisdiction exists, you and Microsoft consent to exclusive jurisdiction and venue in the federal court in King County, Washington for all disputes heard in court (excluding arbitration). If not, you and Microsoft consent to exclusive jurisdiction and venue in the Superior Court of King County, Washington for all disputes heard in court (excluding arbitration).\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 10.\tab ENTIRE AGREEMENT. This agreement, and any other terms Microsoft may provide for supplements, updates, or third-party applications, is the entire agreement for the software.\par
\pard\sa200\sl276\slmult1\f1\fs22\lang9\par
\pard\f2\fs17\lang2057\par
}
"@
    $richTextBox1.BackColor = [System.Drawing.Color]::White
    $btnAcknowledge.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnAcknowledge.Location = New-Object System.Drawing.Point(544, 415)
    $btnAcknowledge.Name = "btnAcknowledge";
    $btnAcknowledge.Size = New-Object System.Drawing.Size(119, 23)
    $btnAcknowledge.TabIndex = 1
    $btnAcknowledge.Text = "Accept"
    $btnAcknowledge.UseVisualStyleBackColor = $True
    $btnAcknowledge.Add_Click({$EULA.DialogResult=[System.Windows.Forms.DialogResult]::Yes})

    $btnCancel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnCancel.Location = New-Object System.Drawing.Point(669, 415)
    $btnCancel.Name = "btnCancel"
    $btnCancel.Size = New-Object System.Drawing.Size(119, 23)
    $btnCancel.TabIndex = 2
    if($mode -ne 0)
    {
	    $btnCancel.Text = "Close"
    }
    else
    {
	    $btnCancel.Text = "Decline"
    }
    $btnCancel.UseVisualStyleBackColor = $True
    $btnCancel.Add_Click({$EULA.DialogResult=[System.Windows.Forms.DialogResult]::No})

    $EULA.AutoScaleDimensions = New-Object System.Drawing.SizeF(6.0, 13.0)
    $EULA.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
    $EULA.ClientSize = New-Object System.Drawing.Size(800, 450)
    $EULA.Controls.Add($btnCancel)
    $EULA.Controls.Add($richTextBox1)
    if($mode -ne 0)
    {
	    $EULA.AcceptButton=$btnCancel
    }
    else
    {
        $EULA.Controls.Add($btnAcknowledge)
	    $EULA.AcceptButton=$btnAcknowledge
        $EULA.CancelButton=$btnCancel
    }
    $EULA.ResumeLayout($false)
    $EULA.Size = New-Object System.Drawing.Size(800, 650)

    Return ($EULA.ShowDialog())
}

function msrdShowEULAIfNeeded($toolName, $mode) {
	$eulaRegPath = "HKCU:Software\Microsoft\CESDiagnosticTools"
	$eulaAccepted = "No"
	$eulaValue = $toolName + " EULA Accepted"
	if(Test-Path $eulaRegPath)
	{
		$eulaRegKey = Get-Item $eulaRegPath
		$eulaAccepted = $eulaRegKey.GetValue($eulaValue, "No")
	}
	else
	{
		$eulaRegKey = New-Item $eulaRegPath
	}
	if($mode -eq 2) # silent accept
	{
		$eulaAccepted = "Yes"
       		$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
	}
	else
	{
		if($eulaAccepted -eq "No")
		{
			$eulaAccepted = msrdShowEULAPopup($mode)
			if($eulaAccepted -eq [System.Windows.Forms.DialogResult]::Yes)
			{
	        		$eulaAccepted = "Yes"
	        		$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
			}
		}
	}
	return $eulaAccepted
}

function msrdCleanUpandExit {
    if (($global:msrdTempCommandErrorFile -ne $null) -and (Test-Path -Path $global:msrdTempCommandErrorFile)) {
        Remove-Item -Path $global:msrdTempCommandErrorFile -Force -ErrorAction SilentlyContinue
    }
    
    if ($fQuickEditCodeExist) { [msrdDisableConsoleQuickEdit]::SetQuickEdit($false) | Out-Null }
    if ($global:msrdGUIform) { $global:msrdGUIform.Close() }
    Exit
}

#endregion ### Main Functions ###


#region Other

# This function disable quick edit mode. If the mode is enabled, console output will hang when key input or strings are selected.
# So disable the quick edit mode during running script and re-enable it after script is finished.
$QuickEditCode=@"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Runtime.InteropServices;


public static class msrdDisableConsoleQuickEdit
{

    const uint ENABLE_QUICK_EDIT = 0x0040;

    // STD_INPUT_HANDLE (DWORD): -10 is the standard input device.
    const int STD_INPUT_HANDLE = -10;

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll")]
    static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [DllImport("kernel32.dll")]
    static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    public static bool SetQuickEdit(bool SetEnabled)
    {

        IntPtr consoleHandle = GetStdHandle(STD_INPUT_HANDLE);

        // get current console mode
        uint consoleMode;
        if (!GetConsoleMode(consoleHandle, out consoleMode))
        {
            // ERROR: Unable to get console mode.
            return false;
        }

        // Clear the quick edit bit in the mode flags
        if (SetEnabled)
        {
            consoleMode &= ~ENABLE_QUICK_EDIT;
        }
        else
        {
            consoleMode |= ENABLE_QUICK_EDIT;
        }

        // set the new mode
        if (!SetConsoleMode(consoleHandle, consoleMode))
        {
            // ERROR: Unable to set console mode
            return false;
        }

        return true;
    }
}
"@

Try {
    $QuickEditMode = add-type -TypeDefinition $QuickEditCode -Language CSharp -ErrorAction Stop
    $fQuickEditCodeExist = $True
} Catch {
    $fQuickEditCodeExist = $False
}

#endregion Other


#region ##### MAIN #####

[System.Windows.Forms.Application]::EnableVisualStyles()

# Disabling quick edit mode as somethimes this causes the script stop working until enter key is pressed.
If ($fQuickEditCodeExist) { [msrdDisableConsoleQuickEdit]::SetQuickEdit($True) | Out-Null }

Import-Module -Name "$PSScriptRoot\Modules\MSRDC-Commons" -DisableNameChecking -Force -Scope Global

$notice = "========= Microsoft CSS Diagnostics Script =========`n
This Data Collection is for troubleshooting reported issues for the given scenarios.
Once you have started this script please wait until all data has been collected.`n`n
============= IMPORTANT NOTICE =============`n
This script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Microsoft Remote Desktop solutions.`n
The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses; PC names; and user names.`n
The script will save the collected data in a folder (default C:\MS_DATA) and also compress the results into a ZIP file.
This folder and its contents or the ZIP file are not automatically sent to Microsoft.`n
You can send the ZIP file to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have.`n
Find our privacy statement at: https://privacy.microsoft.com/en-US/privacystatement`n
"

if (!($global:TSSinUse)) {
    if ($AcceptEula) {
        Write-Output "AcceptEula switch specified, silently continuing"
        $eulaAccepted = msrdShowEULAIfNeeded "MSRD-Collect" 2
    } else {
        $eulaAccepted = msrdShowEULAIfNeeded "MSRD-Collect" 0
        if ($eulaAccepted -ne "Yes") {
            Write-Output "EULA declined, exiting"
            msrdCleanUpandExit
        }
        Write-Output "EULA accepted, continuing"
    }

    if ($AcceptNotice) {
        Write-Output "AcceptNotice switch specified, silently continuing`n"
    } else {
        $wshell = New-Object -ComObject Wscript.Shell
        $answer = $wshell.Popup("$notice",0,"Are you sure you want to continue?",4+32)
        if ($answer -eq 7) {
            Write-Warning "Script execution not approved by the admin user, exiting.`n"
            msrdCleanUpandExit
        }
        Write-Output "Notice accepted, continuing`n"
    }
}

if (($Core) -or ($Profiles) -or ($Activation) -or ($MSIXAA) -or ($MSRA) -or ($IME) -or ($HCI) -or ($Teams) -or ($SCard) -or ($DiagOnly) -or ($NetTrace) -or ($DumpPID)) {
    if ($Machine) {
        msrdInitFolders

        if ($global:avdnettestpath -eq "") {
            if ($global:TSSinUse) {
                Write-Warning "avdnettest.exe could not be found. Information on RDP Shortpath for AVD availability will be incomplete. If you are using TSSlite, consider using the full TSS instead, which is shipped with additional binaries.`n"
            } else {
                Write-Warning "avdnettest.exe could not be found. Information on RDP Shortpath for AVD availability will be incomplete. Make sure you download and unpack the full package of MSRD-Collect or TSSv2.`n"
            }
        }

        if (!($global:TSSinUse)) {
            msrdLogMessage Info "Starting MSRD-Collect - v$msrdVersion`n" -Color "Cyan"
            if ($global:msrdAutoVerCheck -eq 1) { msrdCheckVersion($msrdVersion) } else { Write-Output "Automatic update check on script launch is Disabled" }
        }

        if ($UserContext) { msrdLogMessage Info "Parameter '-UserContext $UserContext' has been specified`n" }

        if ($global:TSSinUse) {
            msrdInitScript -isTSS Yes
        } else {
            msrdInitScript
        }
        
        switch($Machine) {
            'isSource' { $global:msrdRDS = $false; $global:msrdAVD = $false; $global:msrdSource = $true }
            'isRDS' { $global:msrdRDS = $true; $global:msrdAVD = $false; $global:msrdSource = $false }
            'isAVD' { $global:msrdRDS = $false; $global:msrdAVD = $true; $global:msrdSource = $false }
        }
        
        $varsNO = @(,$false * 1)

        msrdInitScenarioVars
        $traceNet = $false
        $onlyDiag = $false
        $dumpProc = $false
        $pidProc = ""

        if ($msrdSkipCore) { $vCore = $varsNO } else { $vCore = @(,$true * 9) }

        if ($Profiles) { $vProfiles = @(,$true * 4) }
        if ($Activation) { $vActivation = @(,$true * 3) }
        if ($MSRA) { $vMSRA = @(,$true * 5) }
        if ($SCard) { $vSCard = @(,$true * 3) }
        if ($IME) { $vIME = @(,$true * 2) }
        if ($Teams) { $vTeams = @(,$true * 2) }
        if ($MSIXAA) { $vMSIXAA = @(,$true * 1) }
        if ($HCI) { $vHCI = @(,$true * 1) }
        if ($DumpPID) { $pidProc = $DumpPID; $dumpProc = $true }
        if ($NetTrace) { $traceNet = $true }
        if ($DiagOnly) { 
            $onlyDiag = $true; $vCore = $varsNO; $traceNet = $false
            if (($Core) -or ($Profiles) -or ($Activation) -or ($MSIXAA) -or ($MSRA) -or ($IME) -or ($HCI) -or ($Teams) -or ($SCard) -or ($NetTrace) -or ($DumpPID)) {
                Write-Warning "Scenario 'DiagOnly' has been specified together with other scenarios. All scenarios will be ignored and only Diagnostics will run."
            }
        }

        $varsSystem = @(,$true * 11)
        $varsAVDRDS = @(,$true * 10)
        $varsInfra = @(,$true * 6)
        $varsAD = @(,$true * 2)
        $varsNET = @(,$true * 5)
        $varsLogSec = @(,$true * 2)
        $varsIssues = @(,$true * 2)
        $varsOther = @(,$true * 4)

        msrdCollectData -varsCore $vCore -varsProfiles $vProfiles -varsActivation $vActivation -varsMSRA $vMSRA -varsSCard $vSCard -varsIME $vIME -varsTeams $vTeams -varsMSIXAA $vMSIXAA -varsHCI $vHCI -traceNet $traceNet -onlyDiag $onlyDiag -dumpProc $dumpProc -pidProc $pidProc
        if (!($msrdSkipDiag)) { 
            msrdCollectDataDiag -varsSystem $varsSystem -varsAVDRDS $varsAVDRDS -varsInfra $varsInfra -varsAD $varsAD -varsNET $varsNET -varsLogSec $varsLogSec -varsIssues $varsIssues -varsOther $varsOther
        }
        if (!($global:msrdSkipArchive)) {
            msrdArchiveData -varsCore $vCore
        }
    } else {
        Write-Warning "Please include the '-Machine' parameter to indicate the type of environment from where data should be collected, or run the script without any parameters (= GUI mode).`nSupported values for the '-Machine' parameter: 'isSource', 'isAVD', 'isRDS'.`nSee MSRD-Collect-ReadMe.txt for more details.`nExiting..."
        Exit
    }

} else {
    Import-Module -Name "$PSScriptRoot\Modules\MSRDC-GUI" -DisableNameChecking -Force
    msrdAVDCollectGUI
    Remove-Module MSRDC-GUI
}

#endregion ##### MAIN #####

# SIG # Begin signature block
# MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCtNbLrce65beS1
# 9TKKk+fsLCz0urreXNX2jAEv9AP3qKCCDYUwggYDMIID66ADAgECAhMzAAADTU6R
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHAl
# Ea6A/M4bB9wzj9DPDeOvBuNGx2IRCkF/Uv4jBK20MEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAnPhS6GLVBdXXA/wEQXU9T++On2MbNN1TLVBL
# ezc4aM7HLnml5Fz40e05YFImvacofpJYwePCdGSbPcLWSkRnezTssVzBmQcoPy/V
# lHNJacMIA9APxywR+evPtzv0voVVuY8aQEQLX/TFM9anFIohkNnGC+n6Z8lnkpWZ
# kuD1Ooaw0EJS6KRDDM7v7nUyIlg9B3RUb1xV95KYuGPqioXBWdRIJKJTwBrldv6/
# BZfYWMsZtNQBcP0MD3WS8LUctEcAwxd9+i/RaP503PKeuJnxa3u5o8/3QOwMaeu2
# 5TGuDYd7qmrJ3h/t3G5TvQK4EYV6VCzEmMiJTFgR+gGnJS83EaGCFv0wghb5Bgor
# BgEEAYI3AwMBMYIW6TCCFuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFQBgsqhkiG9w0BCRABBKCCAT8EggE7MIIBNwIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCDVwWLfGyyDfRt4yLV8Nqd0cgHaZM4zNqp/
# R2oaI2w1PwIGZGzBYiUXGBIyMDIzMDUyMzE0NDQ1My41OVowBIACAfSggdCkgc0w
# gcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsT
# HE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBU
# U1MgRVNOOkREOEMtRTMzNy0yRkFFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1T
# dGFtcCBTZXJ2aWNloIIRVTCCBwwwggT0oAMCAQICEzMAAAHFA83NIaH07zkAAQAA
# AcUwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAw
# HhcNMjIxMTA0MTkwMTMyWhcNMjQwMjAyMTkwMTMyWjCByjELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJp
# Y2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046REQ4Qy1FMzM3
# LTJGQUUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCrSF2zvR5fbcnulqmlopdGHP5N
# Psknc69V/f43x82nFGzmNjiES/cFX/DkRZdtl07ibfGPTWVMj/EOSr7K2O6I97zE
# ZexnEOe2/svUTMx3mMhKon55i7ySBXTnqaqzx0GjnnFk889zF/m7X3OfThoxAXk9
# dX8LhktKMVr0gU1yuJt06beUZbWtBEVraNSy6nqC/rfirlTAfT1YYa7TPz1Fu1vI
# znm+YGBZXx53ptkJmtyhgiMwvwVFO8aXOeqboe3Bl1czAodPdr+QtRI+IYCysiAT
# PPs2kGl46yCz1OvDJZNkE1sHDIgAKZDfiP65Hh63aFmT40fj0qEQnJgPb504hoMY
# HYRQ0VJhzLUySC1m3V5GoEHSb5g9jPseOhw/KQpg1BntO/7OCU598KJrHWM5vS7o
# hgLlfUmvwDBNyxoPK7eoCHHxwVA30MOCJVnD5REVnyjKgOTqwhXWfHnNkvL6E21q
# R49f1LtjyfWpZ8COhc8TorT91tPDzsQ4kv8GUkZwqgVPK2vTM+D8w0lJvp/Zr/AO
# RegYIZYmJCsZPGM4/5H3r+cggbTl4TUumTLYU51gw8HgOFbu0F1lq616lNO5KGaC
# f4YoRHwCgDWBJKTUQLllfhymlWeAmluUwG7yv+0KF8dV1e+JjqENKEfBAKZmpl5u
# BJgeceXi6sT7grpkLwIDAQABo4IBNjCCATIwHQYDVR0OBBYEFFTquzi/WbE1gb+u
# 2kvCtXB6TQVrMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1Ud
# HwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3Js
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggr
# BgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIw
# MTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJ
# KoZIhvcNAQELBQADggIBAIyo3nx+swc5JxyIr4J2evp0rx9OyBAN5n1u9CMK7E0g
# lkn3b7Gl4pEJ/derjup1HKSQpSdkLp0eEvC3V+HDKLL8t91VD3J/WFhn9GlNL7PS
# Gdqgr4/8gMCJQ2bfY1cuEMG7Q/hJv+4JXiM641RyYmGmkFCBBWEXH/nsliTUsJ2M
# h57/8atx9uRC2Jihv05r3cNKNuwPWOpqJwSeRyVQ3+YSb1mycKcDX785AOn/xDhw
# 98f3gszgnpfQ200F5XLC9YfTC4xo4nMeAMsJ4lSQUT0cTywENV52aPrM8kAj7ujM
# uNirDuLhEVuJK19ZlIaPC36UslBlFZQJxPdodi9OjVhYNmySiFaDvvD18XZBuI70
# N+eqhntCjMeLtGI+luOCQkwCGuGl5N/9q3Z734diQo5tSaA8CsfVaOK/CbV3s9ha
# xqsvu7mpm6TfoZvWYRNLWgDZdff4LeuC3NGiE/z2plV/v2VW+OaDfg20gIr+kyT3
# 1IG62CG2KkVIxB1tdSdLah4u31wq6/Uwm76AnzepdM2RDZCqHG01G9sT1CqaolDD
# lVb/hJnN7Wk9fHI5M7nIOr6JEhS5up5DOZRwKSLI24IsdaHw4sIjmYg4LWIu1UN/
# aXD15auinC7lIMm1P9nCohTWpvZT42OQ1yPWFs4MFEQtpNNZ33VEmJQj2dwmQaD+
# MIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsF
# ADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UE
# AxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcN
# MjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzn
# tHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3
# lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFE
# yHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+
# jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4x
# yDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBc
# TyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9
# pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ
# 8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pn
# ol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYG
# NRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cI
# FRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEE
# AYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E
# 7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwr
# BgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNV
# HRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYG
# A1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3Js
# L3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcB
# AQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kv
# Y2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUA
# A4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2
# P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J
# 6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfak
# Vqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/AL
# aoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtP
# u4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5H
# LcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEua
# bvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvB
# QUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb
# /wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETR
# kPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAswwggI1AgEB
# MIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjpERDhDLUUzMzctMkZBRTElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAIQAa9hdkkrtx
# Sjrb4u8RhATHv+eggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQUFAAIFAOgXP+IwIhgPMjAyMzA1MjMyMTM2MzRaGA8yMDIz
# MDUyNDIxMzYzNFowdTA7BgorBgEEAYRZCgQBMS0wKzAKAgUA6Bc/4gIBADAIAgEA
# AgMDlEIwBwIBAAICEgwwCgIFAOgYkWICAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYK
# KwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUF
# AAOBgQADL1E1zUtW6nUtHzSL6Pi4vvTm9xOSUbdsvxdGOFZG/QjL+2EIrookufjM
# mWUlnKEpvndVemAH3Hv5w33mO9ZeXPNWdOfyIQmSsXCNWPj3BRabuCgRjOyx8xHC
# 821PxwsAqGBzaCbOKeU5gil7CCPoDODSeMrV7bz9zo5ZZKBSVzGCBA0wggQJAgEB
# MIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABxQPNzSGh9O85
# AAEAAAHFMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwLwYJKoZIhvcNAQkEMSIEIKbMDBvouyZlkOpNTT1g1RJhs51r6zYJuFgg
# u9Gm3dcpMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgGQGxkfYkd0wK+V09
# wO0sO+sm8gAMyj5EuKPqvNQ/fLEwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAcUDzc0hofTvOQABAAABxTAiBCCQE3wwkPX8cT7QRBh9
# TH36LUZYKQTd1Wv16Fo0ZOGYGjANBgkqhkiG9w0BAQsFAASCAgB62o40M6bYSjs+
# jzlPTMFjXA+pTb4AmIiLUyBLq41j6SIlh70t4KeaimJHyl9bs46JKqT6RB2HWnWv
# VxTci5xLpkFt0Yps80d1XZnkKmRuhdhkCsPc1m5wXuAByeutyd+5TRlgzDO9Q+Jb
# R3fVEUHpAsYBlQuP9dSjkDzRAG4wDRrdqA65/3su/eK9IwvxaPqGMbqHztfBWtrn
# PqniHlDYp3e9HP/poQsB3Cqaj2XbDaeLu1j6w9kDEMAT0nF7+bXNHyAv3o0R0I0p
# By8kYwUqwDhsweBj4Hk1P0v+/N5+Poemf8UoKy0+bGAXjOgxU0dpsgT/E+G9gk9J
# um3R7iFJHlc5reGBbt92BvT3MVZRiZwZaSqbnIx1BNZuA+5YtNlCBSkfU58fgn8v
# CbHzViviOUtFWTGzM4frTOFa3ouI/mtHNyvjHpmkxDwa/6SZKixJZIJwAEAduO5y
# o8ZiJ+i47/tUTZrzFbqvAj29fuYKURo9OV3GwaHnVs9QDLFUQ7y/ZKYSfUbZNdxw
# wA0NbP9q1tZEi7U5NvGfJXx3eYq8onxSfiVsn/q9pgon1tDs7cA4T3A6pSlKN+F3
# 623tjEYlUWhxVcc/fuYuWzkiTVQYJGXsmAuwhxyaIWO5Ald6EbCajuI6ZY9t3RBA
# pxVpTo0MS2LMPWm4tXdadAMG0jqttw==
# SIG # End signature block
