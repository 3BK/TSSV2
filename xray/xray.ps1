<#
.SYNOPSIS
Detects known issues and helps resolve them.

.DESCRIPTION
xray aims to automate detection of known issues and help resolve them with minimal time and effort.
It consists of multiple diagnostic functions each looking for a known issue.

.PARAMETER Area
Which technology area xray should run diagnostics for. 
Specify either Area or Component to check or Diagnostic to run (they are mutually exclusive), multiple items can be specified (comma-separated).
When area(s) specified, all components within the specified area(s) are checked
"-Area all" or "-Area *" checks all areas

.PARAMETER Conponent
Which conponent xray should run diagnostics for. 
Specify either Area or Component to check or Diagnostic to run (they are mutually exclusive), multiple items can be specified (comma-separated).
When component(s) specified, all diagnostics within the specified component(s) are run
No wildcards allowed, to run diagnostics for all components, use -Area parameter instead.

.PARAMETER Diagnostic
Which conponent xray should run diagnostics for. 
Specify either Area or Component to check or Diagnostic to run (they are mutually exclusive), multiple items can be specified (comma-separated).
When diagnostic(s) specified, only the specified diagnostics are run
No wildcards allowed, to run all diagnostics, consider using -Area or -Component parameter instead.

.PARAMETER DataPath
Path for input/output files

.PARAMETER Offline
Indicates xray is not running on the actual machine being examined (some -not all- diagnostics can use data files to search for issues)

.PARAMETER WaitBeforeClose
If any known issues are detected, pauses just before script terminates/window closes
Used to ensure detected issues shown on screen are not missed (they are always saved to report file)

.PARAMETER SkipDiags
Do not run diagnostics, only do the minimum essential work, like checking Windows update status etc.
Use carefully, any known issues present will go undetected when this switch is specified.

.PARAMETER DevMode
For diagnostic developers, to be used only whilst developing a diagnostic function. 
When specified, error messages for diagnostics are not suppressed.

.PARAMETER AcceptEULA
Do not display EULA at start

.EXAMPLE
PS> xray.ps1 -Component dhcpsrv,dnssrv -DataPath c:\xray -WaitBeforeClose

This command runs all diagnostics for both dhcpsrv and dnssrv components, saves results to specified path c:\xray and waits for user before terminating if any issues found.

.EXAMPLE
PS> .\xray.ps1 -Area * -DataPath c:\MS_DATA

This command runs all diagnostics for all components in all technology areas and saves results to data path specified.
#>

Param(
    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [ValidateSet("All", "*", "ADS", "DND", "NET", "PRF", "SHA", "UEX")]
    [String[]]
    $Area,

    [Parameter(Mandatory=$true,
    ParameterSetName="Components")]
    [String[]]
    $Component,

    [Parameter(Mandatory=$true,
    ParameterSetName="Diagnostics")]
    [String[]]
    $Diagnostic,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [String]
    $DataPath,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [switch]
    $Offline,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [switch]
    $WaitBeforeClose,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [switch]
    $SkipDiags,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [switch]
    $DevMode,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [switch]
    $AcceptEULA
)

Import-Module -Name .\xray_WU.psm1 -Force
Import-Module -Name .\diag_api.psm1 -Force

Import-Module -Name .\diag_ads.psm1 -Force
Import-Module -Name .\diag_dnd.psm1 -Force
Import-Module -Name .\diag_net.psm1 -Force
Import-Module -Name .\diag_prf.psm1 -Force
Import-Module -Name .\diag_sha.psm1 -Force
Import-Module -Name .\diag_uex.psm1 -Force

# used for diagnostic development only
if ($DevMode) {
    Import-Module -Name .\diag_test.psm1 -Force
}

# version
$version = "1.0.230531.0"

# Area and Area/Component arrays
$TechAreas = @("ADS", "DND", "NET", "PRF", "SHA", "UEX")
#endregion globals

#region helpers

# Processes provided area(s) with all its components & checks
function RunDiagForArea($areas)
{
    foreach ($area in $areas) {
        LogWrite "Processing area:$area"

        try {
            $components = (Get-Variable -Name $area -ErrorVariable ErrorMsg -ErrorAction SilentlyContinue).Value
        }
        catch {
            LogWrite $Error[0].Exception
        }

        if($ErrorMsg) {
            LogWrite $ErrorMsg
        }
        else {
            RunDiagForComponent $components
        }
    }
}

# Processes provided components and runs corresponding diags
function RunDiagForComponent($components)
{
    if($components.Count -eq 0){
        LogWrite "No components!"
        return
    }

    foreach ($component in $components) {
        LogWrite "Processing component: $component"

        try {
            $diags = (Get-Variable -Name $component -ErrorVariable ErrorMsg -ErrorAction SilentlyContinue).Value
        }
        catch {
            LogWrite $Error[0].Exception
        }

        if($ErrorMsg) {
            LogWrite $ErrorMsg
        }
        else {
            RunDiag $diags
        }
    }
}

# Runs specified diagnostics
function RunDiag($diagnostics)
{
    if($diagnostics.Count -eq 0){
        LogWrite "No diagnostics!"
        return
    }

    foreach ($diag in $diagnostics) {
        if($executedDiags.Contains($diag)) {
            LogWrite "Skipping duplicate instance: $diag"
            continue
        }
        $Global:currDiagFn = $diag
        $executedDiags.Add($diag)
        LogWrite "Running diagnostic: $diag"
        XmlAddDiagnostic $diag
        Write-Host "." -NoNewline
        $time1 = (Get-Date).ToUniversalTime()

        $Global:numDiagsRun++
        if ($DevMode) {
            # no error/exception protection
            $result = & $diag $Offline
        }
        else {
            # to prevent failure messages from diag functions
            $ErrorActionPreference = "Stop"
            try {
                $result = & $diag $Offline
            }
            catch {
                $result = $RETURNCODE_EXCEPTION
                LogWrite $Error[0].Exception.Message
            }
            # revert to normal error handling 
            $ErrorActionPreference = "Continue"
        }

        LogWrite "$diag returned: $result"
        $time2 = (Get-Date).ToUniversalTime()
        [UInt64] $timeTaken = ($time2 - $time1).TotalMilliseconds
        XmlDiagnosticComplete $diag $result $timeTaken

        if($result -eq $RETURNCODE_SUCCESS){
            $Global:numDiagsSuccess++
        }
        elseif($result -eq $RETURNCODE_SKIPPED){
            $Global:numDiagsSkipped++
        }
        else {
            $Global:numDiagsFailed++
        }
        $Global:currDiagFn = $null
    }
}

# 'Translates' TSS scenarios to xray components 
function ValidateTssComponents
{
    param(
        [Parameter(Mandatory=$true)]
        [String[]]
        $TssComponents
    )

    $tssComps  = @("802Dot1x", "WLAN",     "Auth", "BITS", "BranchCache", "Container", "CSC", "DAcli", "DAsrv", "DFScli", "DFSsrv", "DHCPcli", "DhcpSrv", "DNScli", "DNSsrv", "Firewall", "General", "HypHost", "HypVM", "IIS", "IPAM", "MsCluster", "MBAM", "MBN", "Miracast", "NCSI", "NetIO", "NFScli", "NFSsrv", "NLB", "NPS", "Proxy", "RAS", "RDMA", "RDScli", "RDSsrv", "SDN", "SdnNC", "SQLtrace", "SBSL", "UNChard", "VPN", "WFP", "Winsock", "WIP", "WNV", "Workfolders")
    $xrayComps = @("802Dot1x", "802Dot1x", "Auth", "BITS", "BranchCache", "Container", "CSC", "DAcli", "DAsrv", "DFScli", "DFSsrv", "DHCPcli", "DhcpSrv", "DNScli", "DNSsrv", "Firewall", "General", "HypHost", "HypVM", "IIS", "IPAM", "MsCluster", "MBAM", "MBN", "Miracast", "NCSI", "NetIO", "NFScli", "NFSsrv", "NLB", "NPS", "Proxy", "RAS", "RDMA", "RDScli", "RDSsrv", "SDN", "SdnNC", "SQLtrace", "SBSL", "UNChard", "VPN", "WFP", "Winsock", "WIP", "WNV", "Workfolders")

    for ($i = 0; $i -lt $tssComps.Count; $i++) {
        $tssComps[$i] = $tssComps[$i].ToLower()
        $xrayComps[$i] = $xrayComps[$i].ToLower()
    }
    for ($i = 0; $i -lt $TssComponents.Count; $i++) {
        $TssComponents[$i] = $TssComponents[$i].ToLower()
    }
    [System.Collections.Generic.List[String]] $newComps = $TssComponents

    for ($i = 0; $i -lt $TssComponents.Count; $i++) {
        $index = -1
        for ($j = 0; $j -lt $tssComps.Count; $j++) {
            if ($tssComps[$j] -eq $TssComponents[$i]) {
                $index = $j
                break
            }
        }
        if($index -lt 0) {
            continue
        }
        if($TssComponents[$i] -ne $xrayComps[$index]) {
            # remove
            $newComps.RemoveAt($i)
            if(!$newComps.Contains($xrayComps[$index])) {
                # replace
                $newComps.Insert($i, $xrayComps[$index])
            }
        }
    }
    return [String[]] $newComps
}

# Displays help/usage info
function ShowHelp
{
    "
No parameters specified, nothing do. 

For usage info, run:
    Get-Help .\xray.ps1

List of available diagnostic areas/components to scan for issues:

Area (version):  `tComponents:
=================`t==========="

    foreach ($techarea in $TechAreas) {
        $version_name = $techarea + "_version"
        $techarea_version = (Get-Variable -Name $version_name).Value
        $components = (Get-Variable -Name $techarea).Value
        "$techarea ($techarea_version)`t$components"
    }
    ""
}
#endregion helpers

#region EULA
[void][System.Reflection.Assembly]::Load('System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
[void][System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')

function ShowEULAPopup($mode)
{
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

function ShowEULAIfNeeded($toolName, $mode)
{
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
			$eulaAccepted = ShowEULAPopup($mode)
			if($eulaAccepted -eq [System.Windows.Forms.DialogResult]::Yes)
			{
	        		$eulaAccepted = "Yes"
	        		$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
			}
		}
	}
	return $eulaAccepted
}
#endregion EULA

#region main
# main script

Write-Host "xray by tdimli, v$version"

# validate cmdline
if (($Area -eq $null) -and ($Component -eq $null) -and ($Diagnostic -eq $null) -and ($SkipDiags -eq $false)) {
    ShowHelp
    return
}

# EULA
if ($AcceptEULA -eq $false) {
    $eulaAccepted = ShowEULAIfNeeded "xray" 0
    if($eulaAccepted -ne "Yes") {
        "EULA Declined"
        exit
    }
}

# validate DataPath, do it here before any file operations
$origDataPath = $DataPath
if(($DataPath.Length -eq 0) -or -not(Test-Path -Path $DataPath)) {
    $DataPath = (Get-Location).Path
}
else {
    $DataPath = Convert-Path $DataPath
}

InitGlobals $version $DataPath

LogWrite "xray by tdimli, v$version"

Write-Host "`r`nInitialising..."
foreach ($techarea in $TechAreas) {
    $version_name = $techarea + "_version"
    $techarea_version = (Get-Variable -Name $version_name).Value
    LogWrite " $techarea $techarea_version"
    XmlAddTechArea $techarea $techarea_version
}

# these splits are needed for TSS interoperability
if ($Area -ne $null) {
    $Area = $Area -split ","
    if (($Area -eq "all") -or ($Area -eq "*")) {
        $Area = $TechAreas
    }
}
if ($Component -ne $null) {
    $Component = $Component -split ","
    for ($i = 0; $i -lt $Component.Count; $i++) {
        $Component[$i] = $Component[$i].Replace(' ', '')
    }
}
if ($Diagnostic -ne $null) {
    $Diagnostic = $Diagnostic -split ","
}

# log parameters
LogWrite "Parameters:"
LogWrite " Area(s): $Area"
LogWrite " Component(s): $Component"
if(($Component -ne $null) -and ($Component.Count -gt 0)) {
    $ConvertedComponent = ValidateTssComponents $Component
    LogWrite "  after conversion: $ConvertedComponent"
    $Component = $ConvertedComponent
}
# handle "-component general"
for ($i = 0; $i -lt $Component.Count; $i++) {
    $Component[$i] = $Component[$i].Replace(' ', '')
    if ($Component[$i].ToLower() -eq "general") {
        $Area = $TechAreas
        $Components = $null
        LogWrite "  general specified, running with -Area All instead"
    }
}
LogWrite " Diagnostic(s): $Diagnostic"
LogWrite " Datapath: $DataPath"
if (!$DataPath.Equals($origDataPath)) {
    LogWrite "  Original Datapath: $origDataPath"
}
LogWrite " Offline: $Offline"
LogWrite " WaitBeforeClose: $WaitBeforeClose"
LogWrite " SkipDiags: $SkipDiags"
LogWrite " DevMode: $DevMode"
XmlAddParameters $Area $Component $Diagnostic $Offline $WaitBeforeClose $SkipDiags $DevMode

LogWrite "Log file: $logFile"
LogWrite "XML report: $xmlRptFile"

# collect basic system info
LogWrite "Collecting system info..."
AddSysInfo $Offline

# collect poolmon info
LogWrite "Collecting poolmon info..."
InitPoolmonData $Offline

# diagnostics
[System.Collections.Generic.List[String]] $executedDiags = New-Object "System.Collections.Generic.List[string]"

# check for Windows updates
$updateListsLastUpdatedDate = [datetime]::ParseExact($updateListsLastUpdated, "yyyyMMdd", $null)
Write-Host "Checking Windows Update status using update data v$updateListsLastUpdated "
LogWrite "Checking Windows Update status using update data v$updateListsLastUpdated"
$updateListsGracePeriod = 14 # days
if ((New-TimeSpan -Start $updateListsLastUpdatedDate -End $xrayStartTime).Days -gt $updateListsGracePeriod) {
    Write-Host "The update data is more than $updateListsGracePeriod days old, update status report may not be accurate." -ForegroundColor yellow
    LogWrite "The update data is more than $updateListsGracePeriod days old, update status report may not be accurate."
}
Write-Host "Looking for missing updates... " -NoNewline
LogWrite "Looking for missing updates..."
RunDiag CheckUpdateStatus
Write-Host ""
if ($NumMissingUpdates -eq 0) {
    Write-Host "System up-to-date (last installed update: $($installedUpdates[0].HotfixId))`r`n"
    LogWrite "System up-to-date (last installed update: $($installedUpdates[0].HotfixId))"
}
elseif ($NumMissingUpdates -lt 0) {
    Write-Host "Update status cannot be determined, please check that you have latest updates installed.`r`n" -ForegroundColor yellow
    LogWrite "Update status cannot be determined, please check that you have latest updates installed."
}
elseif ($numIssues -eq 0) {
    Write-Host "This system is missing $NumMissingUpdates update(s), please install below Windows update to resolve:" -ForegroundColor yellow
    Write-Host "  $($MissingUpdates[0].heading)`r`n"
    LogWrite "This system is missing $NumMissingUpdates update(s), please install Windows update $($MissingUpdates[0].id) to resolve."
}

if ($SkipDiags) {
    LogWrite "Diagnostics skipped on user request"
}
else {
    # run diagnostics
    Write-Host "Starting diagnostics, checking for known issues..."
    LogWrite "Starting diagnostics, checking for known issues..."
    if ($Area) {
        RunDiagForArea $Area
    } elseif ($Component) {
        RunDiagForComponent $Component
    } elseif ($Diagnostic) {
        RunDiag $Diagnostic
    }
}

XmlMarkComplete

# log/show summary
$stats1 = "$numDiagsRun diagnostic check(s) run (R:$numDiagsSuccess S:$numDiagsSkipped F:$numDiagsFailed)"
$stats2 = "$numIssues issue(s) found"
if(Test-Path -Path $issuesFile){
    $stats2 += ", details saved to $issuesFile"
}
elseif(Test-Path -Path $infoFile) {
    $stats2 += ", details saved to $infoFile"
}

LogWrite $stats1
LogWrite $stats2
LogWrite "Diagnostics completed."

Write-Host
Write-Host $stats1
Write-Host $stats2
Write-Host "Diagnostics completed.`r`n"

if($WaitBeforeClose -and $issueShown) {
    # wait for user
    pause
}
#endregion main

# SIG # Begin signature block
# MIInogYJKoZIhvcNAQcCoIInkzCCJ48CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBqN0BqXWCkZWXn
# k/qtb56nlQRTKZes1lH+63tvzVseMKCCDYUwggYDMIID66ADAgECAhMzAAADTU6R
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJdG
# GZoI5vhSAaJfh+lrGMWtItTNhNtl4WrMkRxNohPVMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAAEqHyHC1iP3w7smGCFxlw3+2v+5Y43dsoo8h
# o6CqWIFERECJf8xQH2QeoKb1pdO6Fej/t6D5j35KjdrKI67dFeaVAmmDkpJWZzei
# pTzVjpNeSKurhrH1bukXoonT5FerMcFRfru8j+krRRzjEmLWG7LwZTDUIl6WfCG/
# iKCEFBWWlNPsFMYD3dSsKCPqvrmDM8v9hmw36cKWGdFlv0KoxEfqY8hsJbgd/oZt
# hTwEzxwz5KLru/ImiHOIayJCrjhoha2g5d7Wxb04P71Jfthil5NvXmZTN5PqGhRx
# O6YYbjA4fjDOAj1rezsVhDkKesrrfkTN30YPXRK9q/5tl/15RKGCFv0wghb5Bgor
# BgEEAYI3AwMBMYIW6TCCFuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCAyI+8yhkWWSZA0Asb7wycha8XXwnB8v6z0
# U/ck7PDvWAIGZGzWaf2JGBMyMDIzMDYwNjExNDQxNi41NzJaMASAAgH0oIHQpIHN
# MIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjozRTdBLUUzNTktQTI1RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEVQwggcMMIIE9KADAgECAhMzAAAByfrVjiUgdAJeAAEA
# AAHJMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMTEwNDE5MDEzOFoXDTI0MDIwMjE5MDEzOFowgcoxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNFN0EtRTM1
# OS1BMjVEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1nLi5Y5vz8K+Woxhk7qGW/vC
# xi5euTM01TiEbFOG8g7SFB0VMjYgo6TiRzgOQ+CN53OBOKlyMHWzRL4xvaS03ZlI
# getIILYiASogsEtljzElRHO7fDGDFWcdz+lCNYmJoztbG3PMrnxblUHHUkr4C7EB
# Hb2Y07Gd5GJBgP8+5AZNsTlsHGczHs45mmP7rUgcMn//c8Q/GYSqdT4OXELp53h9
# 9EnyF4zcsd2ZFjxdj1lP8QGwZZS4F82JBGe2pCrSakyFjTxzFKUOwcQerwBR/YaQ
# ly7mtCra4PNcyEQm+n/LDce/VViQa8OM2nBZHKw6CyMqEzFJJy5Hizz8Z6xrqqLK
# ti8viJUQ0FtqkTXSR3//w8PAKyBlvIYTFF/Ly3Jh3cbVeOgSmubOVwv8nMehcQb2
# AtxcU/ldyEUqy8/thEHIWNabzHXx5O9D4btS6oJdgLmHxrTBtGscVQqx0z5/fUIk
# LE7tbwfoq84cF/URLEyw3q57KV2U4gOhc356XYEVQdJXo6VFWBQDYbzanQ25zY21
# UCkj821CyD90gqrO3rQPlcQo6erwW2DF2fsmgAbVqzQsz6Rkmafz4re17km7qe09
# PuwHw5e3x5ZIGEoVlfNnJv6+851uwKX6ApZFxPzeQo7W/5BtaTmkZEhwY5AdCPgP
# v0aaIEQn2qF7MvFwCcsCAwEAAaOCATYwggEyMB0GA1UdDgQWBBQFb51nRsI8ob54
# OhTFeVF7RC4yyzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
# KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4ICAQA2qLqcZt9HikIHcj7AlnHhjouxSjOeBaTE+EK8aXcV
# Lm9cA8D2/ZY2OUpYvOdhuDEV9hElVmzopiJuk/xBYh6dWJTRhmS7hVjrGtqzSFW0
# LffsRysjxkpuqyhHiBDxMXMGZ6GdzUfqVP2Zd2O+J/BYQJgs9NHYz/CM4XaRP+T2
# VM3JE1mSO1qLa+mfB427QiLj/JC7TUYgh4RY+oLMFVuQJZvXYl/jITFfUppJoAak
# Br0Vc2r1kP5DiJaNvZWJ/cuYaiWQ4k9xpw6wGz3qq7xAWnlGzsawwFhjtwq5EH/s
# 37LCfehyuCw8ZRJ9W3tgSFepAVM7sUE+Pr3Uu+iPvBV4TsTDNFL0CVIPX+1XOJ6Y
# RGYJ2kHGpoGc/5sgA2IKQcl97ZDYJIqixgwKNftyN70O0ATbpTVhsbN01FVli0H+
# vgcGhyzk6jpAywHPDSQ/xoEeGU4+6PFTXMRO/fMzGcUcf0ZHqZMm0UhoH8tOtk18
# k6B75KJXTtY3ZM7pTfurSv2Qrv5zzCBiyystOPw/IJI+k9opTgatrC39L69/Kwyt
# D0x7t0jmTXtlLZaGvoSljdyyr6QDRVkqsCaLUSSsAiWeav5qg64U3mLmeeko0E9T
# J5yztN/jcizlHx0XsgOuN6sub3CPV7AAMMiKopdQYqiPXu9IxvqXT7CE/SMC2pcN
# yTCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQEL
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
# CxMdVGhhbGVzIFRTUyBFU046M0U3QS1FMzU5LUEyNUQxJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAH3pi8v+HgGb
# jVQs4G36dRxWBt0OoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwDQYJKoZIhvcNAQEFBQACBQDoKR8aMCIYDzIwMjMwNjA2MTA1NzMwWhgPMjAy
# MzA2MDcxMDU3MzBaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOgpHxoCAQAwBwIB
# AAICFicwBwIBAAICEeMwCgIFAOgqcJoCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYK
# KwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUF
# AAOBgQAwd+aEcACrJansvBLpKWf51UWV4An/sKpNi4fkqX7jijcQD0SZ3ZM9qgkG
# H/fFPOikMesIWe6O9orTwm4rV1kTB7WYQL/XTx8gO6iUi0KBT0QZL12QBeP7jpCA
# nKddXAjb86uHrVO7ZZUMVM3vibO190xOWGPWu0cgpVxTCsKEkTGCBA0wggQJAgEB
# MIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAByfrVjiUgdAJe
# AAEAAAHJMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwLwYJKoZIhvcNAQkEMSIEILkG6tUVzMppBSjb1YpFCf2aMc0KesDb+yLN
# mtH+ZO/PMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQggXXOf1LdUUsQJ3gp
# 2H9gDSMhiQD/zX3hXXzh2Tl2/YEwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAcn61Y4lIHQCXgABAAAByTAiBCBLGLI4zWV3F5jZP8Na
# XN3MMvXjnRy2BkvxARRPxfD72jANBgkqhkiG9w0BAQsFAASCAgCqRWxBv5gqrrEY
# Niy5ZpWk7Ec0gvzZLBT1ixoL4/VAyxJcJrSTYWSGJfMzOjJzEc91fxEUvvSi4+pC
# Ya/Jt3aLHH4EL175e3nToTmvWXY00W1ogPTNNNqX+MF6Fmf98P2x+906/HInsfRv
# CZAoTH0PvcjNErb6dRSf42yIKLy5xzikDi2Q8LRVQXGyeZ0U40pszhltpgwG7k/E
# oYbVZJEAi1ZLXW+2q1oRGh5DAKAnz3B6nWzGqdH3sGRmjP1s5vJDjEU/CHUrNWYq
# RJu0aOw2uRlUvjujuGaodFNzMHLa3gJdLDGNifzpxbj4OCSEYWMnyYC7WAvrfhNt
# RnCmFxQFQfRD41UIBE4bpS32f8OuPuLuhYzhBp7xAGjS4sA7774sEZ1o7sD5xWM2
# E7VsS8bhBk1P6HBpFklu4XzMpdg5PX94R5hh8edocm8XivjoHI2pSX2Vzhy2yhBt
# PUEbJMcpXe/CpLjcKxEnUZ0nLWHJiqhB5y2JWC3Qy6jaKVkNKNyORUjBoQCD4YsD
# LnNQr9lDSp0BPl/VI4M1xQPwxp7XbUspQTgKfduOE347Mb4N/K5NxuA0wd76CQ6m
# 3c/tjFjaBP+eM0QKFjPImVWQAy3QIeC3VHiAzs35pTMylAO3yj7ZYYIuksFh0e45
# EZRiAzjJzYAoed6u5xF9VIT/WU8Ylw==
# SIG # End signature block
