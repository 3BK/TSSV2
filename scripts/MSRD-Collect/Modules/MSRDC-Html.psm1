<#
.SYNOPSIS
   MSRD-Collect HTML functions

.DESCRIPTION
   Module for the MSRD-Collect html functions

.NOTES
   Authors    : Robert Klemencz (Microsoft) & Alexandru Olariu (Microsoft)
   Requires   : At least PowerShell 5.1 (This module is not for stand-alone use. It is used automatically from within the main MSRD-Collect.ps1 script)
   Version    : See MSRD-Collect.ps1 version
   Feedback   : Send an e-mail to MSRDCollectTalk@microsoft.com
#>


#region HTML functions

Function msrdHtmlInit {
    param ($htmloutfile)

    #html report initialization
    msrdCreateLogFolder $global:msrdLogDir

    New-Item -Path $htmloutfile -ItemType File | Out-Null

    Set-Content $htmloutfile "<!DOCTYPE html>
<html>"
}

Function msrdHtmlHeader {
    param ($htmloutfile, $title, $fontsize)

    #html report header
Add-Content $htmloutfile "<head>
    <title>$title</title>
</head>
<style>
    .table-container { position: fixed; width: 100%; top: 0; left: 0; z-index: 1; background-color: white; }
    .WUtable-container { position: relative; display: inline-block; width: 100%; }
    BODY { font-family: Arial, Helvetica, sans-serif; font-size: $fontsize; }
    table { background-color: white; border: none; width: 100%; padding-left: 5px; padding-right: 5px; padding-bottom: 5px; }
    td { word-break: break-all; border: none; }
    th { border-bottom: solid 1px #CCCCCC; }

    .tduo { border: 1px solid #BBBBBB; background-color: white; vertical-align:top; border-radius: 5px; box-shadow: 1px 1px 2px 3px rgba(12,12,12,0.2); }
    .tduo tr:hover { background-color: #BBC3C6; }

    details > summary { background-color: #7D7E8C; color: white; cursor: pointer; padding: 5px; border:1px solid #BBBBBB; text-align: left; font-size: 13px; border-radius: 5px; }
    .detailsP { padding: 5px 5px 10px 15px; }

    .scroll { padding-top: 104px; box-sizing: border-box; }

    .cText { padding-left: 5px; }
    .cTable1-2 { padding-left: 5px; width: 12%; }
    .cTable1-3 { padding-left: 5px; width: 12%; }
    .cTable1-3b { width: 53%; }
    .cTable2-1 { padding-left: 5px; width: 65%; }
    .b2top a { color:white; float:right; text-decoration: none; }
    .menubutton { width: 150px; cursor: pointer; filter: drop-shadow(3px 3px 1px rgba(0, 0, 0, 0.25)) }

    .circle_green { vertical-align:top; padding-left: 5px; border: 1px solid #a1a1a1; padding: 5px 3px; background: #009933; border-radius: 100%; width: 5px; heigth: 5px }
    .circle_red { vertical-align:top; padding-left: 5px; border: 1px solid #a1a1a1; padding: 5px 3px; background: red; border-radius: 100%; width: 5px; heigth: 5px }
    .circle_blue { vertical-align:top; padding-left: 5px; border: 1px solid #a1a1a1; padding: 5px 3px; background: blue; border-radius: 100%; width: 5px; heigth: 5px }
    .circle_white { vertical-align:top; padding-left: 5px; border: 1px solid #a1a1a1; padding: 5px 3px; background: white; border-radius: 100%; width: 5px; heigth: 5px }
    .circle_no { vertical-align:top; padding-left: 5px; border: 1px solid white; padding: 5px 3px; background: white; border-radius: 100%; width: 5px; heigth: 5px }

    .dropdown-wrapper { background-color: white; position: fixed; cursor: pointer; display: flex; justify-content: center; left: 50%; transform: translateX(-50%); width: 100%; margin: 0 auto; padding-bottom: 30px; padding-top: 5px;}
    .dropdown { position: relative; margin-right: 5px; }
	.dropdown button { background-color: #7D7E8C; color: #fff; border: none; border-radius: 5px; padding: 8px 14px; line-height: 14px; cursor: pointer; transition: background-color 0.3s; }
	.dropdown-content { display: none; position: absolute; background-color: #fff; min-width: 160px; box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2); z-index: 1; white-space: nowrap; }
	.dropdown-content a { padding: 10px; text-decoration: none; display: block; color: #000; }
    .dropdown:hover button { background-color: #5b5b5b; }
    .dropdown:hover .dropdown-content { display: block; }
    .dropdown:hover .dropdown-content a:hover { background-color: #BBC3C6; color: #000; }    
</style>"
}

Function msrdHtmlMenu {
    Param ($htmloutfile, [string]$CatText, [System.Collections.Generic.Dictionary[String,String]]$BtnTextAndId)

    Add-Content $htmloutfile "<div class='dropdown'><button>$CatText</button><div class='dropdown-content'>"
    
    foreach ($txt in $BtnTextAndId.GetEnumerator()) {
        $btnLink = $txt.Value
        $btnText = $txt.Key
        Add-Content $htmloutfile "<a href='$btnLink'>$btnText</a>"
    }

    Add-Content $htmloutfile "</div></div>"

}

Function msrdHtmlBodyDiag {
    Param ($htmloutfile, $title, $feedback, [bool[]]$varsSystem, [bool[]]$varsAVDRDS, [bool[]]$varsInfra, [bool[]]$varsAD, [bool[]]$varsNET, [bool[]]$varsLogSec, [bool[]]$varsIssues, [bool[]]$varsOther)

    #html report body
    Add-Content $htmloutfile "
<body>
    <div class='table-container'>
        <div style='text-align:center;'><a name='TopDiag'></a><b><h3>$title</h3></b></div>
        <div class='dropdown-wrapper'>
"

#region menu
    #system
    if ($true -in $varsSystem) {
        $BtnsSystem = [System.Collections.Generic.Dictionary[String,String]]@{}

        if ($varsSystem[0]) { $BtnsSystem.Add("Core", "#DeploymentCheck") }
        if ($varsSystem[1]) { $BtnsSystem.Add("CPU Utilization", "#CPUCheck") }
        if ($varsSystem[2]) { $BtnsSystem.Add("Drives", "#DiskCheck") }
        if ($varsSystem[3]) { $BtnsSystem.Add("Graphics", "#GPUCheck") }
        if (!($global:msrdSource)) { if ($varsSystem[4]) { $BtnsSystem.Add("OS Activation / Licensing", "#KMSCheck") } }
        if ($varsSystem[5]) { $BtnsSystem.Add("SSL / TLS", "#SSLCheck") }
        if ($varsSystem[6]) { $BtnsSystem.Add("User Account Control", "#UACCheck") }
        if ($varsSystem[7]) { $BtnsSystem.Add("Windows Installer", "#InstallerCheck") }
        if (!($global:msrdSource)) { if ($varsSystem[8]) { $BtnsSystem.Add("Windows Search", "#SearchCheck") } }
        if ($varsSystem[9]) { $BtnsSystem.Add("Windows Updates", "#WUCheck") }
        if ($varsSystem[10]) { $BtnsSystem.Add("WinRM and PowerShell", "#WinRMPSCheck") }
        
        msrdHtmlMenu -htmloutfile $htmloutfile -CatText "System" -BtnTextAndId $BtnsSystem
    }

    #avd/rds
    if ($true -in $varsAVDRDS) {
        $BtnsAVDRDS = [System.Collections.Generic.Dictionary[String,String]]@{}

        if ($varsAVDRDS[0]) { $BtnsAVDRDS.Add("Device and Resource Redirection", "#RedirCheck") }
        if (!($global:msrdSource)) { if ($varsAVDRDS[1]) { $BtnsAVDRDS.Add("FSLogix", "#ProfileCheck") } }
        if ($varsAVDRDS[2]) { $BtnsAVDRDS.Add("Multimedia", "#MultiMedCheck") }
        if ($varsAVDRDS[3]) { $BtnsAVDRDS.Add("Quick Assist", "#QACheck") }
        if (!($global:msrdSource)) {
            if ($varsAVDRDS[4]) { $BtnsAVDRDS.Add("RDP / Listener", "#ListenerCheck") }
            if ($varsAVDRDS[5]) { $BtnsAVDRDS.Add("RDS Roles", "#RolesCheck") }
        }
        if ($varsAVDRDS[6]) { $BtnsAVDRDS.Add("Remote Desktop Clients", "#RDCCheck") }
        if (!($global:msrdSource)) {
            if ($varsAVDRDS[7]) { $BtnsAVDRDS.Add("Remote Desktop Licensing", "#LicCheck") }
            if ($varsAVDRDS[8]) { $BtnsAVDRDS.Add("Session Time Limits", "#STLCheck") }
        }
        if (!($global:msrdRDS)) { if ($varsAVDRDS[9]) { $BtnsAVDRDS.Add("Teams Media Optimization", "#TeamsCheck") } }

        if ($global:msrdAVD) {
            msrdHtmlMenu -htmloutfile $htmloutfile -CatText "AVD/RDS" -BtnTextAndId $BtnsAVDRDS
        } else {
            msrdHtmlMenu -htmloutfile $htmloutfile -CatText "RDS" -BtnTextAndId $BtnsAVDRDS
        }
    }

    #avd infra
    if (!($global:msrdRDS)) {
        if ($true -in $varsInfra) {
            $BtnsAVDInfra = [System.Collections.Generic.Dictionary[String,String]]@{}

            if ($global:msrdAVD) {
                if ($varsInfra[0]) { $BtnsAVDInfra.Add("AVD Agent / SxS Stack", "#AgentStackCheck") }
                if ($varsInfra[1]) { $BtnsAVDInfra.Add("AVD Host Pool", "#HPCheck") }
            }
            if ($varsInfra[2]) { $BtnsAVDInfra.Add("AVD Required URLs", "#URLCheck") }
            if ($global:msrdAVD) {
                if ($varsInfra[3]) { $BtnsAVDInfra.Add("AVD Services URI Health", "#BrokerURICheck") }
                if ($varsInfra[4]) { $BtnsAVDInfra.Add("Azure Stack HCI", "#HCICheck") }
            }
            if ($varsInfra[5]) { $BtnsAVDInfra.Add("RDP Shortpath", "#UDPCheck") }

            msrdHtmlMenu -htmloutfile $htmloutfile -CatText "AVD Infra" -BtnTextAndId $BtnsAVDInfra
        }
    }

    #ad
    if ($true -in $varsAD) {
        $BtnsAD = [System.Collections.Generic.Dictionary[String,String]]@{}

        if ($varsAD[0]) { $BtnsAD.Add("Azure AD Join", "#AADJCheck") }
        if ($varsAD[1]) { $BtnsAD.Add("Domain", "#DCCheck") }

        msrdHtmlMenu -htmloutfile $htmloutfile -CatText "Active Directory" -BtnTextAndId $BtnsAD
    }

    #networking
    if ($true -in $varsNET) {
        $BtnsNet = [System.Collections.Generic.Dictionary[String,String]]@{}

        if ($varsNET[0]) { $BtnsNet.Add("DNS", "#DNSCheck") }
        if ($varsNET[1]) { $BtnsNet.Add("Firewall", "#FWCheck") }
        if ($varsNET[2]) { $BtnsNet.Add("Proxy / Route", "#ProxyCheck") }
        if ($varsNET[3]) { $BtnsNet.Add("Public IP", "#PublicIPCheck") }
        if ($varsNET[4]) { $BtnsNet.Add("VPN", "#VPNCheck") }

        msrdHtmlMenu -htmloutfile $htmloutfile -CatText "Networking" -BtnTextAndId $BtnsNet
    }

    #logon/security
    if ($true -in $varsLogSec) {
        $BtnsLogSec = [System.Collections.Generic.Dictionary[String,String]]@{}

        if ($varsLogSec[0]) { $BtnsLogSec.Add("Authentication / Logon", "#AuthCheck") }
        if ($varsLogSec[1]) { $BtnsLogSec.Add("Security", "#SecCheck") }

        msrdHtmlMenu -htmloutfile $htmloutfile -CatText "Logon / Security" -BtnTextAndId $BtnsLogSec
    }

    #known issues
    if ($true -in $varsIssues) {
        $BtnsIssues = [System.Collections.Generic.Dictionary[String,String]]@{}

        if ($varsIssues[0]) { $BtnsIssues.Add("Issues found in Event Logs over the past 5 days", "#IssuesCheck") }
        if (!($global:msrdSource)) { if ($varsIssues[1]) { $BtnsIssues.Add("Potential Logon Issue Generators", "#BlackCheck") } }

        msrdHtmlMenu -htmloutfile $htmloutfile -CatText "Known Issues" -BtnTextAndId $BtnsIssues
    }

    #other
    if ($true -in $varsOther) {
        $BtnsOther = [System.Collections.Generic.Dictionary[String,String]]@{}

        if (!($global:msrdSource)) {
            if ($varsOther[0]) { $BtnsOther.Add("Office", "#MSOCheck") }
            if ($varsOther[1]) { $BtnsOther.Add("OneDrive", "#MSODCheck") }
        }
        if ($varsOther[2]) { $BtnsOther.Add("Printing", "#PrintCheck") }
        if ($varsOther[3]) { $BtnsOther.Add("Third Party Software", "#3pCheck") }

        msrdHtmlMenu -htmloutfile $htmloutfile -CatText "Other" -BtnTextAndId $BtnsOther
    }
#endregion menu

Add-Content $htmloutfile "
        </div>
    </div>
    <div class='scroll'>
    <div align='right'><a href='#/' id='expAll' class='col'>Hide/Show All</a></div>
    <table>
        <tr><td>"
}

Function msrdHtmlBodyWU {
    Param ($htmloutfile, $title)

	Add-Content $htmloutfile "<body>
	<div class='WUtable-container'>
	<table>
		<tr><td style='text-align:center; padding-bottom: 10px;' colspan='6'><a name='TopDiag'></a><b><h2>$title</h2></b>

			<table>
				<tr>
					<td style='text-align:center;'><a href='#COM'><button class='menubutton'>Updates (COM)</button></a>&nbsp;
					<a href='#QFE'><button class='menubutton'>Other (QFE)</button></a>&nbsp;
					<a href='#REG'><button class='menubutton'>Other (Registry)</button></a></td>
				</tr>
			</table>
		</td></tr>

	<tr><td style='text-align:left; font-size: 13px; padding-bottom: 5px'><b>Operating System: $msrdGetos</b></td><td align='right' style='height:5px;'><a href='#/' id='expAll' class='col'>Hide/Show All</a></td></tr>
	<tr><td colspan='2'>
	<details open>
		<summary>
			<a name='COM'></a><b>Microsoft.Update.Session</b><span class='b2top'><a href='#'>^top</a></span>
		</summary>
		<div class='detailsP'>
			<table class='tduo'>
				<tr style='text-align: left;'>
					<th width='10px'><div class='circle_no'></div></th><th style='padding-left: 5px;'>Category</th><th>Date/Time</th><th>Operation</th><th>Result</th><th>KB</th><th>Description</th>
				</tr>
	"
}

Function msrdHtmlEnd {
    Param ($htmloutfile)

    #html report footer
    Add-Content $htmloutfile "</tbody></table></div></details>
        </td></tr>
    </table>
    </div>

    <script type='text/javascript'>
        const xa = document.getElementById('expAll');

        xa.addEventListener('click', function(e) {
            e.currentTarget.classList.toggle('exp');
            e.currentTarget.classList.toggle('col');

            const details = document.querySelectorAll('details');

            Array.from(details).forEach(function(obj, idx) {
                if (e.currentTarget.classList.contains('exp')) {
                    obj.removeAttribute('open');
                } else {
                    obj.open = true;
                }
            });
        }, false);
    </script>

    <footer style='padding: 10px; font-size: 11px;'><i>Report finished at $(Get-Date) - Script version $msrdVersion (Get the latest version from <a href='https://aka.ms/MSRD-Collect' target='_blank'>https://aka.ms/MSRD-Collect</a> - For feedback visit <a href='https://aka.ms/MSRD-Collect-Survey' target='_blank'>https://aka.ms/MSRD-Collect-Survey</a>)</i>
    <table><tr><td colspan='2'>Legend<td><tr>
    <tr><td width='10px'><div class='circle_green'></div></td><td>Expected value/status</td></tr>
    <tr><td width='10px'><div class='circle_blue'></div></td><td>Value/status should be evaluated for relevance</td></tr>
    <tr><td width='10px'><div class='circle_red'></div></td><td>Value/status is unexpected, problematic or might cause problems in certain circumstances</td></tr>
    <tr><td width='10px'><div class='circle_white'></div></td><td>Value/status not found or generic information</td></tr>
    <tr><td width='10px'><div>&#9432;</div></td><td>Hover over the icon with the mouse cursor for additional information</td></tr></table>
    </footer>
    </body>
</html>"
}

Function msrdSetMenuWarning {
    param ($MenuCat, $MenuItem, $htmloutfile)

    #html report menu item warning
    if (Test-Path -path $htmloutfile) {

        $msrdDiagFileContent = Get-Content -Path $htmloutfile
        $msrdDiagFileReplace = foreach ($diagItem in $msrdDiagFileContent) {
            if ($diagItem -match "(.*>$MenuItem</a>)$") {
                $diagItem -replace $MenuItem, "$MenuItem <span style='color: red;'>&#9888;</span>"
            } elseif ($diagItem -match "(.*<button>$MenuCat</button>.*)") {
                $diagItem -replace $MenuCat, "$MenuCat <span style='color: red;'>&#9888;</span>"
            } else {
                $diagItem
            }
        }
        $msrdDiagFileReplace | Set-Content -Path $htmloutfile
    }
}

#endregion HTML functions

Export-ModuleMember -Function *

# SIG # Begin signature block
# MIInkwYJKoZIhvcNAQcCoIInhDCCJ4ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCLLgD4S7PFFJxD
# iaBQ82qe217TGZoXJfBDBbjXrjttIaCCDXYwggX0MIID3KADAgECAhMzAAADTrU8
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIE0UqKv8QRdPCeuu8DpuD7yr
# TtbMHL/MtcIKnROIu1ZDMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAU54h8cCPUOFACRs18dMhOwHPEDOnLgs9BcKkVpbfcbZAZj1Owz53nSDK
# ZvBmOYuDrsY/5ie1neH5d/ScHmoZa9xpfjaQ2rE5RLFOPrsQqfo4B5ixnJ4r52hW
# lxHw34nbXP7YCymYMM8doJjkv7iNBV4w6S58Q2BwzKwP9UV4ly1F+dUQrsFccn7K
# DGudh50YaLyHdnvpCgspx6aVKpBmdZXYHHgkH1IUuHNOSpkKV04hX2WH2BrqMHjS
# mXCrr3X6VErHO4DcgGW1hEiyA+Oum1dvH7CL8hNB63RG10AxzPeSBk7k1qxTHW4k
# fXIqpJd/GNeg28yw40S9prIfcgn+5qGCFv0wghb5BgorBgEEAYI3AwMBMYIW6TCC
# FuUGCSqGSIb3DQEHAqCCFtYwghbSAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCABCBxnKnnpV4fXTFpEQ1FTcoe2cnqFpyXtDi4gMTf2xAIGZF0U7BOP
# GBMyMDIzMDUyMzE0NDQ1NS4wODlaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpFNUE2LUUy
# N0MtNTkyRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVQwggcMMIIE9KADAgECAhMzAAABvvQgou6W1iDWAAEAAAG+MA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEy
# MloXDTI0MDIwMjE5MDEyMlowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkU1QTYtRTI3Qy01OTJFMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEApV/y2z7Da7nMu0tykLY8olh7Z03EqFNz3iFlMp9gOfVm
# ZABmheCc87RuPdQ2P+OHUJiqCQAWNuNSoI/Q1ixEw9AA657ldD8Z3/EktpmxKHHa
# vOhwQSFPcpTGFVXIxKCwoO824giyHPG84dfhdi6WU7f7D+85LaPB0dOsPHKKMGlC
# 9p66Lv9yQzvAhZGFmFhlusCy/egrz6JX/OHOT9qCwughrL0IPf47ULe1pQSEEihy
# 438JwS+rZU4AVyvQczlMC26XsTuDPgEQKlzx9ru7EvNV99l/KCU9bbFf5SnkN1mo
# UgKUq09NWlKxzLGEvhke2QNMopn86Jh1fl/PVevN/xrZSpV23rM4lB7lh7XSsCPe
# FslTYojKN2ioOC6p3By7kEmvZCh6rAsPKsARJISdzKQCMq+mqDuiP6mr/LvuWKin
# P+2ZGmK/C1/skvlTjtIehu50yoXNDlh1CN9B3QLglQY+UCBEqJog/BxAn3pWdR01
# o/66XIacgXI/d0wG2/x0OtbjEGAkacfQlmw0bDc02dhQFki/1Q9Vbwh4kC7VgAiJ
# A8bC5zEIYWHNU7C+He69B4/2dZpRjgd5pEpHbF9OYiAf7s5MnYEnHN/5o/bGO0aj
# Ab7VI4f9av62sC6xvhKTB5R4lhxEMWF0z4v7BQ5CHyMNkL+oTnzJLqnLVdXnuM0C
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBTrKiAWoYRBoPGtbwvbhhX6a2+iqjAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQDHlfu9c0ImhdBis1yj56bBvOSyGpC/rSSty+1F49Tf6fmFEeqxhwTTHVHOeIRN
# d8gcDLSz0d79mXCqq8ynq6gJgy2u4LyyAr2LmwzFVuuxoGVR8YuUnRtvsDH5J+un
# ye/nMkwHiC+G82h3uQ8fcGj+2H0nKPmUpUtfQruMUXvzLjV5NyRjDiCL5c/f5ecm
# z01dnpnCvE6kIz/FTpkvOeVJk22I2akFZhPz24D6OT6KkTtwBRpSEHDYqCQ4cZ+7
# SXx7jzzd7b+0p9vDboqCy7SwWgKpGQG+wVbKrTm4hKkZDzcdAEgYqehXz78G00mY
# ILiDTyUikwQpoZ7am9pA6BdTPY+o1v6CRzcneIOnJYanHWz0R+KER/ZRFtLCyBMv
# LzSHEn0sR0+0kLklncKjGdA1YA42zOb611UeIGytZ9VhNwn4ws5GJ6n6PJmMPO+y
# PEkOy2f8OBiuhaqlipiWhzGtt5UsC0geG0sW9qwa4QAW1sQWIrhSl24MOOVwNl/A
# m9/ZqvLRWr1x4nupeR8G7+DNyn4MTg28yFZRU1ktSvyBMUSvN2K99BO6p1gSx/wv
# SsR45dG33PDG5fKqHOgDxctjBU5bX49eJqjNL7S/UndLF7S0OWL9mdk/jPVHP2I6
# XtN0K4VjdRwvIgr3jNib3GZyGJnORp/ZMbY2Dv1mKcx7dTCCB3EwggVZoAMCAQIC
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
# U046RTVBNi1FMjdDLTU5MkUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAGitWlL3vPu8ENOAe+i2+4wfTMB7oIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoFrxpMCIYDzIwMjMwNTIzMTIxNTM3WhgPMjAyMzA1MjQxMjE1MzdaMHQw
# OgYKKwYBBAGEWQoEATEsMCowCgIFAOgWvGkCAQAwBwIBAAICFfEwBwIBAAICEbYw
# CgIFAOgYDekCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgC
# AQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQB3fN0+c48sj81M
# P5M2a+VaMcHV1G+A2bZYpPxjoLmVpFYPWCKzwlmr9urjZU78+KZsUFC5wKqddnGV
# XVG8mAORC5JQ9+Ft2+h2dGRKSr7PYMXvW2BsZ2j0QTBMw0pZm9WdgTrjifmHeOcA
# B9/sMNA8zrdyhAdCl0a/waq6O6CF7DGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABvvQgou6W1iDWAAEAAAG+MA0GCWCGSAFl
# AwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcN
# AQkEMSIEIKMnhie2w10jC92k549y4NCBugkz3Xu41TZt1Jw+rVrFMIH6BgsqhkiG
# 9w0BCRACLzGB6jCB5zCB5DCBvQQglO6Kr632/Oy9ZbXPrhEPidNAg/Fef7K3SZg+
# DxjhDC8wgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAA
# Ab70IKLultYg1gABAAABvjAiBCCd8JRvzTX0THpWOIGxsHMjBm7wnwd8sa+oSmZ7
# kHGR/DANBgkqhkiG9w0BAQsFAASCAgA9JpEClSCLbzj/NPA0FOU6eI73jr5HhigC
# H6/kU66IP9x1Bz667Yg40SbmQ5HxGmi86DrDdSgHktQdqOFlBPljFhXXF4MyPR3L
# z8z9RWM6rC0yeW8aNNMsht6ftwv87q6ifdkcbbmArO6Ane2k0bbvY9GfUp9D05mQ
# mukgS4DAo+Thst9BPeYA4t924OA5zxMRJ8lrpfsNQJcTOXXg/PpebdOgzHZoWplt
# fqr+9QCe7lfr+OFqkWElHb7fKO1iNEYA1tTXWDZf0Gqu39z0IjLmLKTrFdbf+suT
# 6s3RGB3Bmd3XqsVaio6Jstg94NZ4OURMGpHToDjxtDdFPcPyQ3uXWd8pBSC0v0sF
# vJMwkLlWc/lgpB0m+nB66bdul5aKFPFjLQViyEOhmur4eECAAXWsfLPhKnnNJFUX
# U0Rnr3JvNnVO23BT3ixW1hg/0NE5VbIqImPeVci93E7rw9k2MTQnp3C5FJ+wMEKM
# A+mBppYlZuzBPDby5Zl6OsXbmY1ktn56d4qNXLkL5oCB93Re0nH/Qfvc8unFDzeO
# Cz9ss3O5TThOrJzXgmfyBUpdL+VVQOx+GWYQMfWO4SS1ayLPTIWcRfXKirGnxayz
# S/FYFVCXsGZfXqGqHaQWnHmpcTU3HM3/jDR8b0RyEYrmykQgmg6yC4KjCTTH7e8a
# CNkxup7eqg==
# SIG # End signature block
