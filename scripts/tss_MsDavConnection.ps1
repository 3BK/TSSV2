# Source: https://github.com/edbarnes-msft/DrDAV/blob/master/Test_MsDavConnection.ps1
<# Script name: tss_MSDavConnection.ps1
Purpose: - check WebDAV/WebClient related settings and connectivity
#>

param(
	[Parameter(Mandatory=$False,Position=0,HelpMessage='Choose a writable output folder location, i.e. C:\Temp\ ')]
	[string]$DataPath = (Split-Path $MyInvocation.MyCommand.Path -Parent)
)

$ScriptVer="2020.07.06"

$deftesturl =  'https://www.myserver.com'

[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
[uri] $testurl = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the http target web folder", "Web Address", $deftesturl)

$logpath = $DataPath
#_#$logpath = $env:TEMP+"\_DavTest"
#_#New-Item -ItemType Directory -Force -Path $logpath > $null
#_#$logfile = $logpath +"\"+$env:COMPUTERNAME+"_"+(Get-Date -Format yyddMMhhmm)+".log"
#$logfile = [Microsoft.VisualBasic.Interaction]::InputBox("Specify the logging file", "Log File", $logfile)
$logfile = $logpath +"\_DavTest_"+$env:COMPUTERNAME+"_"+(Get-Date -Format yyddMMhhmm)+"_v"+$ScriptVer+".txt"

$outputverbose = $false

$WebClientTestSrc = @'
    [DllImport("ieframe.dll", CharSet = CharSet.Auto)]
    static extern int IEIsProtectedModeURL(string pszUrl);   
    public static int GetProtectedMode(string url)
    {
        return IEIsProtectedModeURL(url);
    }
    [DllImport("C:\\Windows\\System32\\wininet.dll", CharSet=CharSet.Auto, SetLastError=true)]
    static extern bool InternetSetCookie(string lpszUrl, string lpszCookieName, string lpszCookieData);
    public static bool SetCookieString(string url, string name, string value)
    {
        if (!InternetSetCookie(url, name, value)) { Console.Write( "Failed to set cookie. Error code: {0}. ", Marshal.GetLastWin32Error()); return false; }
        return true;
    }

    [DllImport("C:\\Windows\\System32\\wininet.dll", CharSet=CharSet.Auto, SetLastError=true)]
    static extern bool InternetGetCookieEx(string pchURL, string pchCookieName, System.Text.StringBuilder pchCookieData, ref System.UInt32 pcchCookieData, int dwFlags, IntPtr lpReserved);
    const int ERROR_NO_MORE_ITEMS = 259;
    const int flags = 0x00003000; // INTERNET_COOKIE_NON_SCRIPT  0x00001000, INTERNET_COOKIE_HTTPONLY 0x00002000
    public static string GetCookieString(string url)
    {
        // Determine the size of the cookie      
        UInt32 datasize = 256*1024; int iResult = 0; 
        System.Text.StringBuilder cookieData = new System.Text.StringBuilder(Convert.ToInt32(datasize));
        if (!InternetGetCookieEx(url, null, cookieData, ref datasize, flags, IntPtr.Zero)) {
            iResult = Marshal.GetLastWin32Error(); // Console.Write( "The request returned error {0}. ", iResult);
            if ((ERROR_NO_MORE_ITEMS == iResult) | (datasize < 0)) return null; // Console.Write( "Datasize {0}. ", datasize);
            // Allocate stringbuilder large enough to hold the cookie    
            cookieData = new System.Text.StringBuilder(Convert.ToInt32(datasize));
            if (!InternetGetCookieEx(url, null, cookieData, ref datasize, flags, IntPtr.Zero)) { Console.Write( "GetCookie request returned error {0}. ", iResult);return null;}
        }
        return cookieData.ToString();
    }

// referencing values from https://github.com/libgit2/libgit2/blob/master/deps/winhttp/winhttp.h
    [DllImport("winhttp.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern IntPtr WinHttpOpen( [MarshalAs(UnmanagedType.LPWStr)] string pwszAgent, int   dwAccessType,
            [MarshalAs(UnmanagedType.LPWStr)] string pwszProxy, [MarshalAs(UnmanagedType.LPWStr)] string pwszProxyBypass, int dwFlags );

    [DllImport("winhttp.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern IntPtr WinHttpOpenRequest( IntPtr hConnect, [MarshalAs(UnmanagedType.LPWStr)] string pwszVerb, [MarshalAs(UnmanagedType.LPWStr)] string pwszObjectName,
            [MarshalAs(UnmanagedType.LPWStr)] string pwszVersion, [MarshalAs(UnmanagedType.LPWStr)] string pwszReferrer, ref byte[] ppwszAcceptTypes, int dwFlags);

    [DllImport("winhttp.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern IntPtr WinHttpConnect(IntPtr hSession, [MarshalAs(UnmanagedType.LPWStr)] string pswzServerName, short nServerPort, int dwReserved);

    [DllImport("winhttp.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern bool WinHttpSetOption( IntPtr hInternet, int dwOption, byte[] lpBuffer, int dwBufferLength );

    [DllImport("winhttp.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern bool WinHttpSendRequest( IntPtr hRequest, string pwszHeaders, int dwHeadersLength, string lpOptional, uint dwOptionalLength, uint dwTotalLength, int dwContext );

    [DllImport("winhttp.dll", SetLastError=true)]
    static extern bool WinHttpReceiveResponse(IntPtr hRequest, int lpReserved);

    [DllImport("winhttp.dll", SetLastError=true)]
    static extern bool WinHttpCloseHandle(IntPtr hInternet);

    static int WINHTTP_FLAG_SECURE = 0x00800000;
    static int WINHTTP_OPTION_SECURE_PROTOCOLS = 84;
    public static int WINHTTP_FLAG_SECURE_PROTOCOL_SSL3 = 0x00000020;    // decimal 32
    public static int WINHTTP_FLAG_SECURE_PROTOCOL_TLS1 = 0x00000080;    // decimal 128
    public static int WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1 = 0x00000200;  // decimal 512
    public static int WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 = 0x00000800;  // decimal 2048

    static int WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0;
    //static int WINHTTP_ACCESS_TYPE_NO_PROXY = 1;
    //static int WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3;

    static int WINHTTP_OPTION_SECURITY_FLAGS = 31;
    static int SECURITY_FLAG_IGNORE_UNKNOWN_CA = 0x00000100;
    static int SECURITY_FLAG_IGNORE_CERT_DATE_INVALID = 0x00002000;
    static int SECURITY_FLAG_IGNORE_CERT_CN_INVALID = 0x00001000;
    static int SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE = 0x00000200;
    static int SECURITY_FLAG_IGNORE_ALL = SECURITY_FLAG_IGNORE_UNKNOWN_CA|SECURITY_FLAG_IGNORE_CERT_DATE_INVALID|SECURITY_FLAG_IGNORE_CERT_CN_INVALID|SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

    static byte[] WINHTTP_DEFAULT_ACCEPT_TYPES = null;
    static string WINHTTP_NO_ADDITIONAL_HEADERS = null;
    static string WINHTTP_NO_REQUEST_DATA = null;
    static string WINHTTP_NO_REFERER = null;
    static string WINHTTP_NO_PROXY_NAME = null;
    static string WINHTTP_NO_PROXY_BYPASS = null;

    public static int TestSsl(string url, short port, int ssl, bool bIgnoreBadCert)
    {
        int iResult = 0;
        IntPtr hSession = WinHttpOpen("WinHTTP SSL Test", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if( hSession != null ) {
            IntPtr hConnect = WinHttpConnect( hSession, url, port, 0 );
            if( hConnect != null ) {
                IntPtr hRequest = WinHttpOpenRequest( hConnect, "GET", "/", null, WINHTTP_NO_REFERER, ref WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
                if (!WinHttpSetOption( hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, BitConverter.GetBytes(ssl), sizeof(int) )) Console.WriteLine( "Failed to set SSL");
                if ( bIgnoreBadCert ) {
                    if (!WinHttpSetOption( hRequest, WINHTTP_OPTION_SECURITY_FLAGS, BitConverter.GetBytes(SECURITY_FLAG_IGNORE_ALL), sizeof(int) )) Console.WriteLine( "Failed to set Ignore Bad Cert");
                    };
                if (!WinHttpSendRequest( hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0 ) ){
                    iResult = Marshal.GetLastWin32Error();
                    Console.Write( "The request returned error {0}. ", iResult);
                    };
                if( hRequest != null ) WinHttpCloseHandle( hRequest );
                };
            if( hConnect != null ) WinHttpCloseHandle( hConnect );
            if( hSession != null ) WinHttpCloseHandle( hSession );
        };
        return iResult;
    }
'@ 

Add-Type -MemberDefinition $WebClientTestSrc  -Namespace WebClientTest -Name WinAPI 

[System.Management.Automation.PSCredential] $altcreds = $null
$auth_ntlm = $false; $auth_nego = $false; $auth_basic =$false; $auth_oauth = $false; $auth_fba = $false
$dblbar = "======================================================"
$wcshellminver7 = "6.1.7601.22498"; $wcminver7 = "6.1.7601.23542"; $winhttpminver7 = "6.1.7601.23375"
$wcminver8GDR = "6.2.9200.17428"; $wcminver8LDR = "6.2.9200.21538"; $winhttpminver8 = "6.2.9200.21797"
$wcminver81 = "6.3.9600.17923"; $wcrecver10 = "10.0.16299.334"
$newlocation = ""
$persistentcookies = ""
$propfindnodecount = 0

function Test-MsDavConnection {
    [CmdletBinding()] 
    param(
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true
            )][uri]$WebAddress 
        )
    begin {
        $ProgressPreference = 'SilentlyContinue'
        if ($PSVersionTable.PSVersion.Major -eq 2){ $osverstring = [environment]::OSVersion.Version.ToString() } 
        else { $osverstring = $(Get-CimInstance Win32_OperatingSystem).Version }
        $osver = [int] ([convert]::ToInt32($osverstring.Split('.')[0], 10) + [convert]::ToInt32($osverstring.Split('.')[1], 10))
        $osname = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
        if ($osver -eq 10) { $osname = $osname + " " + (Get-ComputerInfo).WindowsVersion }
        $defaultNPO = ('RDPNP,LanmanWorkstation,webclient')
        $WCfilesize = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").FileSizeLimitInBytes 
        $WCattribsize = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").FileAttributesLimitInBytes 
        $WCtimeout = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").SendReceiveTimeoutInSec  
        $npo = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order").ProviderOrder
        $hnpo = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\HwOrder").ProviderOrder
        $WCBasicauth = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").BasicAuthLevel
        $WCAFSL = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters").AuthForwardServerList
        if ($WCAFSL.length -eq 0 ) {$WCAFSLOut = "Not configured or empty" } else { $WCAFSLOut = $WCAFSL } 
        $sslprotocols=[string]::Join(" ",([enum]::GetNames([System.Security.Authentication.SslProtocols])|Where-Object{$_ -notmatch 'none|default|ssl2'} ) ) #ssl3|tls|tls11|tls12(|tls13)
        $IgnoreBadCert = $true
        $WCuseragent = "Microsoft-WebDAV-MiniRedir/" + $osverstring
        $fso = New-Object -comobject Scripting.FileSystemObject
        $Webclntdll = $fso.GetFileVersion('C:\Windows\System32\webclnt.dll')
        $Davclntdll = $fso.GetFileVersion('C:\Windows\System32\davclnt.dll')
        $Mrxdavsys = $fso.GetFileVersion('C:\Windows\System32\drivers\mrxdav.sys')
        $Shell32dll = $fso.GetFileVersion('C:\Windows\System32\shell32.dll')
        $WinHttpdll = $fso.GetFileVersion('C:\Windows\System32\winhttp.dll')
        $WebIOdll =  $fso.GetFileVersion('C:\Windows\System32\webio.dll')
        $ProgressPreference = 'Continue'
    }

    process {
        $MsDavConnection = @{
            ClientName=[environment]::MachineName
            ClientOS = $osname
            ClientOSVersion = $osverstring
            ClientWebIO=$WebIOdll
            ClientWinHttp=$WinHttpdll
            ClientShell32=$Shell32dll
            ClientWebclnt=$Webclntdll
            ClientDavclnt=$Davclntdll
            ClientMrxdav=$Mrxdavsys
            ClientNetProviders=$npo
            ServerName=$WebAddress.DnsSafeHost
            ServerPort=$WebAddress.Port
            ServerScheme=$WebAddress.Scheme
            TargetUrl=$WebAddress
            AuthForwardServerList = $WCAFSLOut
            BasicAuthLevel=$WCBasicauth
            FileSizeLimitInBytes = $WCfilesize.ToString("N0")
            FileAttributesLimitInBytes = $WCattribsize.ToString("N0")
            SendReceiveTimeoutInSec = $WCtimeout.ToString("N0")
            Currentuser=$([environment]::UserDomainName + "\" + [environment]::UserName)
            }    

            
            foreach ($i in $MsDavConnection.GetEnumerator()) { Write-ToLogVerbose $($i.Key + " : " + $i.Value).ToString() }
            Write-Host "Microsoft WebClient Service Diagnostic check" -ForegroundColor Yellow -BackgroundColor DarkBlue
            Write-Host ("Client Name =         " + [environment]::MachineName)
            Write-Host ("OS =                  " + $osname)
            Write-Host ("OS version =          " + $osverstring )
            Write-Host "Webclnt.dll version ="$Webclntdll
            Write-Host "Davclnt.dll version ="$Davclntdll
            Write-Host "Mrxdav.sys version = "$Mrxdavsys
            Write-Host "Shell32.dll version ="$Shell32dll
            Write-Host "WinHttp.dll version ="$WinHttpdll
            Write-Host "WebIO.dll version =  "$WebIOdll

            Write-Host
            if ($WebAddress.Host.Length -gt 0) {
                Write-Host "TargetUrl ="$WebAddress
                Write-Host "ServerName ="$WebAddress.DnsSafeHost
                Write-Host "ServerPort ="$WebAddress.Port
                Write-Host "ServerScheme ="$WebAddress.Scheme
                Write-Host
            }
            Write-Host "Network Provider Order =`n`t"$npo
            Write-Host "`nWebClient Parameters:`n`tBasicAuthLevel ="$WCBasicauth
            Write-Host "`tAuthForwardServerList ="$WCAFSL
 

            Write-ToLog ("`n" + $dblbar + "`n")
            

# Fail to Connect
#    1.	WebClient not installed or disabled
        $WCSvc = Get-Service | Where-Object { $_.Name -eq 'webclient' }
        if ($null -ne $WCSvc) 
            { 
                $WCStartNum = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\WebClient").Start 
                switch ($WCStartNum) {
                "2"  { $WCStartType = "Automatic" }
                "3"  { $WCStartType = "Manual" }
                "4"  { $WCStartType = "Disabled" }
                }
                Write-ToLog ("The WebClient service StartUp type is: " + $WCStartType)
                if ( ($WCStartType -ne "Manual" ) -and
                    ($WCStartType -ne "Automatic" ) )
                    { Write-ToLogWarning "WebClient service Start Type should be set to Manual or Automatic." }
                Write-ToLog "Manual is default but Automatic is preferred if the service is used frequently"
            } 
            else
            {
                Write-ToLogWarning "WebClient service is not present"
            }
# File version check
        if ( ($WebAddress.Scheme -eq "https") -and (($osver -eq 7) -or ($osver -eq 8)) ){ # https://support.microsoft.com/en-us/help/3140245
            if ($osver -eq 7) { 
                if ( !((Check-Version $WinHttpdll $winhttpminver7 ) -and (Check-Version $WinHttpdll $winhttpminver7 )) ){ 
                    Write-ToLogWarning ("WinHttp.Dll and WebIO.Dll should be updated to allow highest Secure Protocol versions - https://support.microsoft.com/en-us/help/3140245") 
                    }
                if ( !(Check-Version $Shell32dll $wcshellminver7 ) ){ Write-ToLogWarning ("Shell32.dll should be updated to address a known issue") }
                if ( !((Check-Version $Webclntdll $wcminver7 ) -and (Check-Version $Davclntdll $wcminver7 ) -and (Check-Version $Mrxdavsys $wcminver7 )) ){ 
                    Write-ToLogWarning ("The WebClient files should be updated to allow highest Secure Protocol versions") 
                    }
                }
            if ($osver -eq 8) { 
                if ( !((Check-Version $WinHttpdll $winhttpminver8 ) -and (Check-Version $WinHttpdll $winhttpminver8 )) ){ 
                    Write-ToLogWarning ("WinHttp.Dll and WebIO.Dll should be updated to allow highest Secure Protocol versions - https://support.microsoft.com/en-us/help/3140245") 
                    }
                if ( [convert]::ToInt32($Webclntdll.Split('.')[0], 10) -lt 20000 ) {
                    if ( !((Check-Version $Webclntdll $wcminver8GDR ) -and (Check-Version $Davclntdll $wcminver8GDR )) ){ 
                        Write-ToLogWarning ("The WebClient files should be updated to allow highest Secure Protocol versions") 
                        }
                    } 
                    else {
                        if ( !((Check-Version $Webclntdll $wcminver8LDR ) -and (Check-Version $Davclntdll $wcminver8LDR )) ){ 
                            Write-ToLogWarning ("The WebClient files should be updated to allow highest Secure Protocol versions") 
                        }
                    }
                }
            if ($osver -eq 9) { 
                if ( !((Check-Version $Webclntdll $wcminver81 ) -and (Check-Version $Davclntdll $wcminver81 )) ){ 
                            Write-ToLogWarning ("The WebClient files should be updated to allow highest Secure Protocol versions") 
                    }
                }
    
            }

        if (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" | Select-Object -ExpandProperty DefaultSecureProtocols -ErrorAction SilentlyContinue | Out-Null){
            $dsp = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp").DefaultSecureProtocols 
            if ($osver -eq 10) {
                if ($null -ne $dsp ) {Write-ToLogWarning "WinHttp registry entry is: " + $dsp.ToString('x2').ToUpper() }
            } else {
                if ($null -eq $dsp ) {Write-ToLogWarning "WinHttp registry entry is absent" } else { Write-ToLog ("WinHttp registry entry is: " + $dsp.ToString('x2').ToUpper() ) }
            }
        }
        if ([environment]::GetEnvironmentVariable("ProgramFiles(x86)").Length -gt 0){
            if (Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"){
                if (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" | Select-Object -ExpandProperty DefaultSecureProtocols -ErrorAction SilentlyContinue | Out-Null){
                    $dspwow = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp").DefaultSecureProtocols
                }
            }
            if ($osver -eq 10) {
                if ($null -ne $dspwow ) {Write-ToLogWarning "WinHttp WOW6432 registry entry is: " + $dspwow.ToString('x2').ToUpper() }
            } else {
                if ($null -eq $dspwow ) {Write-ToLogWarning "WinHttp WOW6432 registry entry is absent" } else { Write-ToLog ("WinHttp WOW6432 registry entry is: " + $dspwow.ToString('x2').ToUpper() ) }
            }
        }  
        
                                   
        $strongcrypt = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319").SchUseStrongCrypto
        if ($null -eq $strongcrypt ) {Write-ToLogVerbose "SchUseStrongCrypto registry entry is absent" } else { Write-ToLogVerbose ("SchUseStrongCrypto registry entry for v4 is: " + $strongcrypt) }
        if ([environment]::GetEnvironmentVariable("ProgramFiles(x86)").Length -gt 0){
            $strongcryptwow = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319").SchUseStrongCrypto
            if ($null -eq $strongcryptwow ) {Write-ToLogVerbose "SchUseStrongCrypto WOW6432 registry entry is absent" } else { Write-ToLogVerbose ("SchUseStrongCrypto WOW6432 registry entry for v4 is: " + $strongcryptwow) }
        }     
           
        $strongcrypt2 = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727").SchUseStrongCrypto
        if ($null -eq $strongcrypt2 ) {Write-ToLogVerbose "SchUseStrongCrypto registry entry is absent" } else { Write-ToLogVerbose ("SchUseStrongCrypto registry entry for v2 is: " + $strongcrypt2) }
        if ([environment]::GetEnvironmentVariable("ProgramFiles(x86)").Length -gt 0){
            $strongcryptwow2 = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727").SchUseStrongCrypto
            if ($null -eq $strongcryptwow2 ) {Write-ToLogVerbose "SchUseStrongCrypto WOW6432 registry entry is absent" } else { Write-ToLogVerbose ("SchUseStrongCrypto WOW6432 registry entry for v2 is: " + $strongcryptwow2) }
        }        
              
        $sysdeftlsver = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727").SystemDefaultTlsVersions
        if ($null -eq $sysdeftlsver ) {Write-ToLogVerbose "SystemDefaultTlsVersions registry entry is absent" } else { Write-ToLogVerbose ("SystemDefaultTlsVersions registry entry is: " + $sysdeftlsver) }
        if ([environment]::GetEnvironmentVariable("ProgramFiles(x86)").Length -gt 0){
            $sysdeftlsverwow = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727").SystemDefaultTlsVersions
            if ($null -eq $sysdeftlsverwow ) {Write-ToLogVerbose "SystemDefaultTlsVersions WOW6432 registry entry is absent" } else { Write-ToLogVerbose ("SystemDefaultTlsVersions WOW6432 registry entry is: " + $sysdeftlsverwow) }
        }          

        Write-ToLog ("Client Secure Protocols enabled for .Net: " + $sslprotocols.ToUpper() ) 
      
#    2.	Bad Network Provider order
#       a.	WebClient missing from provider order
        $npomsg = "`r`nNetwork Provider Order check: "
        $npocheck = 'Good'
        if ($npo.ToLower() -ne $hnpo.ToLower()) { 
            $npocheck = 'HwOrder doesn''t match Order' 
            Write-ToLogWarning ($npocheck +"`r`n`tOrder: " + $npo + "`r`n`tHwOrder: " + $hnpo)
            }
        if ( !("," + $hnpo +",").ToLower().Contains(",webclient,") -or !("," + $npo +",").ToLower().Contains(",webclient,") ) {
            $npocheck = 'WebClient is missing from provider list' 
            Write-ToLogWarning ($npomsg + $npocheck + "`r`n`tOrder: " + $npo )
            }
#       b.	Third-party providers interfering
        if ( ($npocheck -eq "Good") -and ($npo.ToLower() -ne $defaultnpo.ToLower()) ) { 
            $npocheck = 'Order doesn''t match Default' 
            Write-ToLog ($npomsg + $npocheck + "`r`n`tOrder: " + $npo + "`r`n`tDefault order: $defaultnpo")
            }
        if ( $npocheck -eq "Good") { Write-ToLog ($npomsg + $npocheck) }


        if ($WebAddress.Host.Length -eq 0) {Start-Process ($env:windir + "\explorer.exe")  -ArgumentList $((Get-ChildItem $logfile).DirectoryName) ;Exit}
#==========================================================================
#    Only test below if WebAddress is passed

        $rootweb = $WebAddress.Scheme + "://" + $WebAddress.DnsSafeHost; $matchfound = $false
            
#    3.	Port blocked
        $starttime = Get-Date
        # New-Object System.Net.Sockets.TcpClient($WebAddress.DnsSafeHost,$WebAddress.Port)
        $ns = New-Object System.Net.Sockets.TcpClient
        try { $ns.Connect($WebAddress.DnsSafeHost, $WebAddress.Port ) } catch {}
        $rtt = (New-TimeSpan $starttime $(Get-Date) ).Milliseconds
        if( $ns.Connected) {$testconnection = $true; $ns.Close()}
        $davport = $davport + "Connection to " + $WebAddress.DnsSafeHost + " on port " + $WebAddress.Port + " was " 
        if ($testconnection -eq $true ) { $davport = $davport + "successful and took " + $rtt + " milliseconds" }
        else { $davport = $davport + "not successful"; $rtt=0}
        Write-ToLog $davport

# Internet Settings Security Zone information
# https://support.microsoft.com/en-us/help/182569/internet-explorer-security-zones-registry-entries-for-advanced-users
        $IEZone = [System.Security.Policy.Zone]::CreateFromUrl($WebAddress).SecurityZone
        $IEPMode = [WebClientTest.WinAPI]::GetProtectedMode($WebAddress)
        if ( $IEPMode -eq 0 ) {$ProtectMode = "Enabled"}
        elseif ( $IEPMode -eq 1 ) {$ProtectMode = "Not Enabled"}
        else {$ProtectMode = "Unknown"}

        Write-ToLog ("$WebAddress is in the $IEZone Security Zone and Protect Mode value is " + $ProtectMode + "`r`n")

        $internettestzone = "http://doesntexist.edbarnes.net"
        if([System.Security.Policy.Zone]::CreateFromUrl($internettestzone).SecurityZone -eq "Internet"){
            if ( [WebClientTest.WinAPI]::GetProtectedMode($internettestzone) -ne 0 ) {
            Write-ToLogWarning ("The Internet Security Zone is not enabled for Protect Mode. This is a security risk!`r`n") }
        }
        
        $ActiveXCheck = $(Get-Item -Path ("HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\" + $IEZone.value__)).GetValue('2000')
        if ( $ActiveXCheck -eq 0 ) {$ActiveXEnabled = "Enabled"}
        elseif ( $ActiveXCheck -eq 1 ) {$ActiveXEnabled = "Prompt"}
        elseif ( $ActiveXCheck -eq 3 ) {$ActiveXEnabled = "Disabled"}
        else {$ActiveXEnabled = "Unknown"}
        Write-ToLogVerbose ("Checking if ActiveX is enabled. Value identified: " + $ActiveXEnabled)

        if ((Test-Path ("HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\" + $IEZone.value__)) -eq $false){
            Write-ToLogVerbose ("No ActiveX Policy found`n")
            }
            else {
            $ActiveXPolicyCheck = $(Get-Item -Path ("HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\" + $IEZone.value__)).GetValue('2000')
            if ( $ActiveXPolicyCheck -eq 0 ) {$ActiveXPolicyEnabled = "Enabled"}
            elseif ( $ActiveXPolicyCheck -eq 1 ) {$ActiveXPolicyEnabled = "Prompt"}
            elseif ( $ActiveXPolicyCheck -eq 3 ) {$ActiveXPolicyEnabled = "Disabled"}
            else {$ActiveXPolicyCheck = "Unknown"}
            Write-ToLogVerbose ("Checking if ActiveX Policy is enabled. Value identified: " + $ActiveXPolicyEnabled +"`n")
            }
      
#    3.	Version of SSL/TLS not supported by destination server
        if ( ($testconnection -eq $true) -and ($WebAddress.Scheme -eq "https") ) {
            $ServerProtocolsAccepted = $null; [int] $iBestSsl = 0;
            if ([WebClientTest.WinAPI]::TestSsl($WebAddress.DnsSafeHost, $WebAddress.Port, 32, $IgnoreBadCert ) -eq 0 ) 
                { Write-ToLogVerbose "The server supports SSL3"; $ServerProtocolsAccepted = $ServerProtocolsAccepted + " SSL3" ; $iBestSsl = 32 ; $sBestSsl = "SSL3" } 
            else { Write-ToLog "The server does not support SSL3" }

            if ([WebClientTest.WinAPI]::TestSsl($WebAddress.DnsSafeHost, $WebAddress.Port, 128, $IgnoreBadCert ) -eq 0 ) 
                { Write-ToLogVerbose "The server supports TLS 1.0"; $ServerProtocolsAccepted = $ServerProtocolsAccepted + " TLS1" ; $iBestSsl = 128 ; $sBestSsl = "TLS1" } 
            else { Write-ToLog "The server does not support TLS 1.0" }

            if ([WebClientTest.WinAPI]::TestSsl($WebAddress.DnsSafeHost, $WebAddress.Port, 512, $IgnoreBadCert ) -eq 0 ) 
                { Write-ToLogVerbose "The server supports TLS 1.1"; $ServerProtocolsAccepted = $ServerProtocolsAccepted + " TLS11" ; $iBestSsl = 512 ; $sBestSsl = "TLS11" } 
            else { Write-ToLog "The server does not support TLS 1.1" }

            if ([WebClientTest.WinAPI]::TestSsl($WebAddress.DnsSafeHost, $WebAddress.Port, 2048, $IgnoreBadCert ) -eq 0 ) 
                { Write-ToLogVerbose "The server supports TLS 1.2"; $ServerProtocolsAccepted = $ServerProtocolsAccepted + " TLS12" ; $iBestSsl = 2048 ; $sBestSsl = "TLS12" } 
            else { Write-ToLog "The server does not support TLS 1.2" }

            if ($null -eq $ServerProtocolsAccepted) {Write-ToLog "No attempted protocols succeeded"}
            else {$ServerProtocolsAccepted = $ServerProtocolsAccepted.Substring(1); Write-ToLog ( "Server supports: " + $ServerProtocolsAccepted.ToUpper() ) }


#    4.	Certificate is expired or doesn't match
            $certcheck = [WebClientTest.WinAPI]::TestSsl($WebAddress.DnsSafeHost, $WebAddress.Port, $iBestSsl, $false )
            if ($certcheck -eq 0 ) 
                { Write-ToLogVerbose "No certificate problem observed"} 
            else { 
                switch ($certcheck ) {
                    "12037"  { Write-ToLog "Certificate Error Invalid Date" }
                    "12038"  { Write-ToLog "Certificate Error Invalid Common Name" }
                    "12044"  { Write-ToLog "Client Authentication Certificate Needed" }
                    "12045"  { Write-ToLog "Certificate CA is Invalid" }
                    "12169"  { Write-ToLog "Invalid Certificate" }      
                    "12179"  { Write-ToLog "Invalid Usage for Certificate" }  
                    default  { Write-ToLog "Certificate failure: $certcheck`r`n"}                 
                    }
                }
            Test-SslCert $WebAddress.DnsSafeHost $WebAddress.Port $sBestSsl
            # Optional ToDo - Check cert chain
            }


#    5.	Bad proxy settings
            Write-ToLogVerbose "TODO: Check proxy config"
#        a.	Proxy misdirection
#        b.	Proxy authentication require
#        [net.httpwebRequest]::GetSystemWebProxy
#
# Failure after connect
#    1.	Failing Authentication
        if ( $testconnection ) {
            Write-ToLog ("`n`n" + $dblbar + "`r`n** Determining authentication mode **")
            $global:newlocation = $WebAddress
            $verb = "HEAD"
            $followredirect = $false
            $addcookies = $false
            $credtype = "Anonymous" # 3 choices = "Anonymous", "DefaultCreds", "AlternateCreds"
            $maxtry = 5
            do {
                $responseresult = SendWebRequest -url $global:newlocation -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect  -usecreds $credtype
                Write-ToLogVerbose ("Result: $responseresult `r`n")
                switch ($responseresult ) {
                    "SwitchToGET" { $verb = "GET" }
                    "AddCookies"  { $addcookies = $true }
                    "AddFollow302"{ $followredirect = $true }            
                    "AddDefCreds" { $credtype = "DefaultCreds" }
                    "AddAltCreds" { $credtype = "AlternateCreds" }
                    "AuthBasic"   { $authbasic = $true }
                    "AuthWinNego" { $authnego = $true }
                    "AuthWinNTLM" { $authntlm = $true }
                    "AuthFBA"     { $addcookies = $true }
                }
                $maxtry = $maxtry - 1
            } while ( ( $responseresult -notlike "Complete*"  ) -and ($maxtry -gt 0 ) )

            }

#        a.	NTLM or Kerberos - AuthForwardServerList
            if (($global:auth_ntlm -or $global:auth_nego) -and ($rootweb.Contains("."))) { 
            Write-ToLog ("`n`n" + $dblbar + "`r`nWindows Authentication accepted with FQDN url : Testing AuthForwardServerList")
                # Validate target url against AuthForwardServerList
                if ($WCAFSL.length -eq 0 ) {Write-ToLogWarning ("AuthForwardServerList registry value is not configured or empty") }
                    else { 
                        $WCAFSL | ForEach-Object -Process {
                                     if ( $rootweb -like $_ ) {
                                        $matchfound = $true
                                        Write-ToLog ("The path $rootweb was matched to " + $_ )
                                        }
                                     }
                        if ( $matchfound -eq $false ) { Write-ToLogWarning ("The path $rootweb was not matched in AuthForwardServerList.") }
                }
                Write-ToLog ($dblbar + "`r`n`n")
            }
#        b.	Basic - not over SSL
            if ($global:auth_basic) { 
                Write-ToLog ("`n`n" + $dblbar + "`r`nBasic Authentication accepted : Testing BasicAuthLevel`r`n")                
                switch ($WCBasicauth) {
                "0"  {Write-ToLogWarning ("BasicAuthLevel is 0; use of Basic Authentication is disabled" ) }
                "1"  {
                        if ($WebAddress.Scheme -eq "http") {
                            Write-ToLogWarning ("BasicAuthLevel is 1; use of Basic Authentication over HTTP is disabled" ) }
                            else { Write-ToLog ("BasicAuthLevel is 1; use of Basic Authentication over HTTPS is enabled" ) }
                        }
                "2"  {Write-ToLogWarning ("BasicAuthLevel is 2; use of Basic Authentication is enabled for both HTTP and HTTPS - This could be a security risk" ) }
                }
                Write-ToLog ("Note: If Basic Authentication is allowed and used, there will always be a credential prompt`r`n" + $dblbar + "`r`n") 
            }

#        c.	Claims/FBA - No persistent cookie passed
            if ($global:auth_fba) { 
                Write-ToLog ("`n`n" + $dblbar + "`r`nFBA or SAML Claims Authentication accepted : Testing Persistent cookies`r`n") 
                Write-ToLog ("This authentication mode requires a persistent, sharable authentication cookie be available") 
#            i.	Cookie not created persistent
#            ii.	Cookie not stored in shareable location
                if ( $IEPMode -eq 0 ) {Write-ToLogWarning ("Protect Mode is enabled for the $IEZone Security Zone so Persistent cookies cannot be shared.")}
                elseif ( $IEPMode -eq 1 )  {Write-ToLog ("Protect Mode is not enabled for the $IEZone Security Zone so Persistent cookies can be shared.")}
                $global:persistentcookies = [WebClientTest.WinAPI]::GetCookieString($WebAddress) 
                if ($global:persistentcookies.length ) {
                    Write-ToLog ("`r`nPersistent Cookies:`n===================")
                    $global:persistentcookies.split("; ") | ForEach-Object{ 
                         $cookie = $_
                         #if ($cookie.Length -gt 7){ if ($cookie.Substring(0,7) -eq "FedAuth") {$fedauth = $cookie.Substring(8)}  }
                         Write-ToLog "`t$cookie"
                    }
                } else { Write-ToLog "`tNo persistent cookies found" }
                Write-ToLog ( $dblbar + "`r`n")
            }

#    2.	OPTIONS and/or PROPFIND verb blocked
        if ( $testconnection ) {
            Write-ToLog ("`n`n" + $dblbar + "`r`n** Check if OPTIONS or PROPFIND are blocked **")
            $verb = "OPTIONS"
            $responseresult = SendWebRequest -url $WebAddress -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect  -usecreds $credtype
            $verb = "PROPFIND"
            $responseresult = SendWebRequest -url $WebAddress -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect  -usecreds $credtype
#    3.	PROPFIND returns bad results
#        a.	XML missing
#        b.	XML malformed/gzipped
#        Checked on every PROPFIND response    
#    4.	Custom header name with space 
#        Checked each time headers are read  
#    5.	Root site access
#        a.	No DAV at root
#        b.	No permissions at root
#        c.	Root site missing 
            if ($rootweb -ne $WebAddress ){
                Write-ToLog ("`n`r`n" + $dblbar + "`r`n** Checking root site access **")
                $verb = "PROPFIND"
                $responseresult = SendWebRequest -url $rootweb -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect  -usecreds $credtype
            }
        }


#
# Performance
            Write-ToLog ("`r`n" + $dblbar + "`r`n** Performance considerations **")
#    1.	Slow to browse
            $verb = "PROPFIND"
            $responseresult = SendWebRequest -url $WebAddress -verb $verb -useragent $WCuseragent -includecookies $addcookies -follow302 $followredirect -usecreds $credtype -depth 1
            Write-ToLog "Check browsing performance scenarios (by testing number of discovered items)"

#        a.	Read-Only Win32 attribute on SharePoint folders can cause unnecessary PROPFIND on contents.
#        b.	Too many items in the destination folder will result in slow response in Windows Explorer (may appear empty)
            Write-ToLog "`tNumber of items queried: $global:propfindnodecount `r`n"
            if ($global:propfindnodecount -gt 1000) {
                Write-ToLogWarning ("`tA high number of items in the folder have been detected")
                if (($global:propfindnodecount*1000) -gt $WCattribsize){Write-ToLogWarning ("`tIncrease the FileAttributesLimitInBytes value. See KB 912152")}
            Write-ToLog ("Current setting of FileAttributesLimitInBytes is: " + $WCattribsize.ToString("N0") + " bytes`r`n")
            }

#    2.	Uploads fail to complete or are very slow
#        a.	PUT requests are blocked
            # TODO Test PUT
#        b.	File exceeds file size limit
            Write-ToLog ("Current setting of FileSizeLimitInBytes is: " + $WCfilesize.ToString("N0") + " bytes")
#        c.	Upload takes longer than the Timeout setting
            Write-ToLog ("`tUpload throughput is limited to approximately (Filesize / 8kb * RTT)" )
            if ($rtt -gt 0 ) {
                Write-ToLog ("`tCurrent Round Trip Time estimate is: " + $rtt + " milliseconds")
                $WCesttimeupload = ($WCfilesize / 8192 * $rtt)
                Write-ToLog ("`tEstimated time needed to upload a max file size of " +  $WCfilesize.ToString("N0") + " bytes: " + ($WCesttimeupload/1000).ToString("N0") + " seconds" )
            }
            else { Write-ToLog "`tUnable to determine RTT. Consider using PsPing from SysInternals to find the RTT" }

            Write-ToLog ("The current client setting for SendReceiveTimeoutInSec is: " + $WCtimeout )
#        d.	Number of file causes total attribute to exceeds attribute size limit
#        	See 2b below

#    3.	Slow to connect
#        a.	The WebClient service was not already started
          if ($WCStartType -ne "Automatic") { Write-ToLog "For best performance, set the StartUp Type to 'Automatic'" }
#        b.	SMB attempts receive no response before falling through to WebClient
            Write-ToLog "`nTesting SMB and SMB2 connectivity - using UNC will try SMB before using WebDAV and can cause a delay if blocked improperly"

            # New-Object System.Net.Sockets.TcpClient($WebAddress.DnsSafeHost,$WebAddress.Port)
            $ns = New-Object system.net.sockets.tcpclient

			$starttime = Get-Date
            try { $ns.Connect($WebAddress.DnsSafeHost, 139 ) } catch {}
            $smbresponsetime = (New-TimeSpan $starttime $(Get-Date) ).Seconds
            $ns.Close()

            $smb = "`tSMB test connection took " + $smbresponsetime + " seconds"
			if ($smbresponsetime -gt 30) {Write-ToLogWarning ($smb) }
            else { Write-ToLog ($smb) }

            $ns2 = New-Object system.net.sockets.tcpclient
			$starttime2 = Get-Date
            try { $ns2.Connect($WebAddress.DnsSafeHost, 445 ) } catch {}
            $smb2responsetime = (New-TimeSpan $starttime2 $(Get-Date) ).Seconds
            $ns2.Close()

            $smb2 = "`tSMB2 test connection took " + $smb2responsetime + " seconds"
			if ($smb2responsetime -gt 30) {Write-ToLogWarning ($smb2) }
            else { Write-ToLog ($smb2) }


#        c.	Auto-detect proxy unnecessarily selected
            Write-ToLogVerbose "`nTODO: Auto-detect proxy`n"

#        return New-Object PsObject -Property $MsDavConnection
     }

}


function SendWebRequest([uri] $url, [string] $verb, [string] $useragent, $includecookies = $false, $follow302=$true, [SecureString] $usecreds, $depth=0)
{
    if ($depth){$depthnotice = " with Depth of 1"} else { $depthnotice = ""}
    Write-ToLog ($dblbar + "`r`n`r`n" + $verb + " test to $url" + $depthnotice)
    Write-ToLogVerbose ("`tUserAgent: " + $useragent + " Cookies:" + $includecookies + " Follow302:" + $follow302 + " CredType:" + $usecreds)

    [net.httpWebRequest] $req = [net.webRequest]::Create($url)

    $req.CookieContainer = New-Object System.Net.CookieContainer
    if ( $includecookies -eq $true ) {
        $gcresult = [WebClientTest.WinAPI]::GetCookieString($url); 
        if ($gcresult.Length ){ 
            $cookiesread = $gcresult.Split(";")
            $cookiesread | ForEach-Object { $req.CookieContainer.SetCookies($url,$_.Trim()) }
        }
    }

    switch ($usecreds) 
    { 
        "Anonymous" {$req.Credentials = $null }
        "DefaultCreds" {$req.UseDefaultCredentials = $true }
        "AlternateCreds" {
            if ($null -eq $global:altcreds){$global:altcreds = Get-Credential }

            $req.Credentials = $global:altcreds
            }
    }

	$req.AllowAutoRedirect = $follow302
	$req.Method = $verb
    if ( $useragent -ne $null ) {$req.UserAgent = $useragent}
    if ( $req.Method -eq "PROPFIND" ) { $req.Headers["Depth"] = $depth }

	#Get Response
	try {
		[net.httpWebResponse]$res = $req.GetResponse()
	}
	catch {
        if ( ($Error[0].Exception.InnerException).Status -eq 'ProtocolError' ) {
            [net.httpWebResponse]$res = $Error[0].Exception.InnerException.Response
        }
        else {
            $res = $null
            Write-ToLogWarning ( ($Error[0].Exception.InnerException).status)
        }
    }

    Write-ToLogVerbose ("Request Headers:")
    foreach ($h in $req.Headers) { Write-ToLogVerbose ("`t" + $h + ": " + $req.Headers.GetValues($h)) }

    if ($null -ne $res)
    {
        Write-ToLog ("`tResponse Status Code: " + $res.StatusCode.value__ + " " + $res.StatusCode)
        Write-ToLogVerbose ("`tResponse Cookies: " + $res.Cookies.Count)
        foreach ($c in $res.Cookies) { Write-ToLogVerbose ("`t`t" + $c.Name + " " + $c.Value) }

        Write-ToLogVerbose ("`tResponse Headers: " + $res.Headers.Count)
        foreach ($h in $res.Headers)
        {
            
            switch -Wildcard($h){
                "WWW-Authenticate" { 
                    Write-ToLogVerbose ("`t`t" + $h )
                    foreach ($a in $res.Headers.GetValues($h)) {
                        Write-ToLogVerbose "`t`t`t"$a
                        if ($a -like "NTLM*") { $global:auth_ntlm = $true }
                        if ($a -like "Nego*") { $global:auth_nego = $true }
                        if ($a -like "Basic*") { $global:auth_basic = $true }
                        # WWW-Authenticate: IDCRL Type="BPOSIDCRL", EndPoint="/sites/Classic/_vti_bin/idcrl.svc/", RootDomain="sharepoint.com", Policy="MBI"
                        if ($a -like "IDCRL*") { $global:auth_oauth = $true }
                        }
                    Break
                    }
                "MicrosoftSharePointTeamServices" { Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "Set-Cookie" { 
                    Write-ToLogVerbose ("`t`t" + $h)
                    foreach ($c in $res.Headers.GetValues($h)) {
                        Write-ToLogVerbose ("`t`t`t" + $c)
                        }
                    Break
                    }
                "Allow" { Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "Date" { Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "Location" { $newlocation = $res.Headers.GetValues($h) ;Write-ToLogVerbose ("`t`t" + $h + ":`t" + $newlocation) ; Break }
                "Content-Type" { Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "Content-Encoding" { Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "request-id" { Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                # X-MSDAVEXT_Error: 917656; Access+denied.+Before+opening+files+in+this+location%2c+you+must+first+browse+to+the+web+site+and+select+the+option+to+login+automatically.
                "X-MSDAVEXT_Error" { 
                    $global:auth_fba = $true ; 
                    if ($includecookies){
                        Write-ToLogWarning ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h))
                    }
                        Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h))
                    Break 
                    }
                "X-FORMS_BASED_AUTH_REQUIRED" { $global:auth_fba = $true ; Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "FORMS_BASED_AUTH_RETURN_URL" { $global:auth_fba = $true ; Write-ToLogVerbose ("`t`t" + $h + ":`t" + $res.Headers.GetValues($h)) ; Break }
                "*" { Write-ToLogVerbose ("`t`t? " + $h + ": " + $res.Headers.GetValues($h))}
            }
        }
        $statcode = $res.StatusCode.value__ 
        if ( ($verb -eq "PROPFIND") -and (($statcode -eq 200) -or ($statcode -eq 207) ) ) { ReturnBody($res) }

        $res.Close()
    } 

    #Set StatusCheck
    $statuscheck = $null
    if ($statcode -eq 404 ) {
        if ($verb = "HEAD") {$statuscheck = "SwitchToGET" }
        else {$statuscheck = "Complete-404" }
    }
    elseif ($statcode -eq 403 ) {
        if ($includecookies -eq $false ) {$statuscheck = "AddCookies" }
        else {$statuscheck = "Complete-403" }
    }
    elseif ($statcode -eq 401 ) {
        if ($usecreds -eq "Anonymous") {$statuscheck = "AddDefCreds" }
        elseif ($usecreds -eq "DefaultCreds") {$statuscheck = "AddAltCreds" }
        else {$statuscheck = "Complete-401" }
    }
    elseif ($statcode -eq 302 ) { 
        if ($follow302 -eq $false ) {$statuscheck = "AddFollow302" ; Write-ToLog ("Redirected to $newlocation")}
        else {$statuscheck = "Complete-302" }
    }
    elseif ($statcode -eq 200 ) {$statuscheck = "Complete-200" }
    elseif ($statcode -eq 207 ) {$statuscheck = "Complete-207" }
    else {$statuscheck = $("Complete-Unexpected-" + $statcode) }

    return $statuscheck
}


function ReturnBody($response)
{
  if ($response.ContentLength -ge 0) {
        $responsestream = $response.getResponseStream() 
        $streamreader = New-Object IO.StreamReader($responsestream) 
        $body = $streamreader.ReadToEnd() 
        Add-Content $($logpath + "\Response_" + (Get-Date -Format hhmmss) + ".txt")  -Value $body
    }
    # Test if body is valid XML

    # Check for Load or Parse errors when loading the XML file
    $xml = New-Object System.Xml.XmlDocument
    try {
        $xml.LoadXml($body)
        Write-ToLog "`tPROPFIND response is valid XML"
        $nodecnt = $xml.ChildNodes.response.Count - 1
        if ($nodecnt -gt $global:propfindnodecount){
            $global:propfindnodecount = $nodecnt
            Write-ToLogVerbose "`tNumber of items: $nodecnt"
        }
    }
    catch [System.Xml.XmlException] {
        Write-ToLogWarning "PROPFIND response is not valid XML: $($_.toString())"
    }

}

function Check-Version($tval, $bval)
{  $t = $tval.Split("."); $b = $bval.Split(".")
    if ($t[0] -ge $b[0]){
        if ($t[1] -ge $b[1]){
            if ($t[2] -ge $b[2]){
                if ($t[3] -ge $b[3]){ return $true }
            }
        }
    }
    return $false
}

function Test-SslCert {
    param(
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true,
            ValueFromPipeline=$true
        )]$destHostName,
        [Parameter(
            ValueFromPipelineByPropertyName=$true
        )][int]$destPort,
        [ValidateSet("SSL3", "TLS", "TLS11", "TLS12", IgnoreCase = $true)]
        [Parameter(
            ValueFromPipelineByPropertyName=$true
        )]$destProtocol 
    )

    $Callback = { param($sender, $cert, $chain, $errors) return $true }
    $Socket = New-Object System.Net.Sockets.Socket('Internetwork','Stream', 'Tcp')
    $Socket.Connect($destHostName, $destPort)
    try {
        $NetStream = New-Object System.Net.Sockets.NetworkStream($Socket, $true)
        $SslStream = New-Object System.Net.Security.SslStream($NetStream, $true, $Callback)
        $SslStream.AuthenticateAsClient($destHostName,  $null, $destProtocol, $false )
        $RemoteCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
        Write-ToLog  ('Cert info - Host name(s): ' + $RemoteCertificate.DnsNameList)
        Write-ToLog  ('Cert info - Not Before: ' + $RemoteCertificate.NotBefore )
        Write-ToLog  ('Cert info - Not After: ' + $RemoteCertificate.NotAfter )
        Write-ToLog  ('Cert info - Subject: ' + $RemoteCertificate.GetNameInfo(3,$false) )
        #Write-ToLog  ('Cert info - Distinguished Name: ' + $RemoteCertificate.SubjectName.Name )
        Write-ToLog  ('Cert info - Issuer: ' + $RemoteCertificate.GetNameInfo(3,$true) )
        Write-ToLog  ('Cert info - Issuer Distinguished Name: ' + $RemoteCertificate.IssuerName.Name )
        Write-ToLog  ('Cert info - Usage: ' + $RemoteCertificate.EnhancedKeyUsageList )
    } 
    catch {
        $_.Exception
    }
    finally {
        $SslStream.Close()
        $NetStream.Close()
    }
    
}

function Write-ToLog()
{   param( $msg = "`n" )
    Write-Host $msg
    Add-Content $logfile -Value $msg
}
function Write-ToLogVerbose()
{   param( $msg = "`n" )
    if ($global:outputverbose ) { Write-Verbose $msg}
    Add-Content $logfile -Value ("VERBOSE:`t"+$msg)
}
function Write-ToLogWarning()
{   param( $msg = " `n" )
    if ($msg) {	#_#
		Write-Warning $msg
		Add-Content $logfile -Value ($global:dblbar)
		Add-Content $logfile -Value ("WARNING:`n`t"+$msg)
		Add-Content $logfile -Value ($global:dblbar)
	}
}

#_# cls

if ($outputverbose) {
    Test-MsDavConnection -WebAddress $testurl -Verbose }
else { Test-MsDavConnection -WebAddress $testurl }


# SIG # Begin signature block
# MIInpQYJKoZIhvcNAQcCoIInljCCJ5ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBc+fufQ6aWHPz1
# CwSE+9YB7woyFl5qfH2MK/QXg9wiVaCCDYUwggYDMIID66ADAgECAhMzAAADTU6R
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
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGXYwghlyAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAANNTpGmGiiweI8AAAAA
# A00wDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGXL
# NT8ELSGRZT3ADHVA58gKVxTxTOd4GmxOmV0HrmaEMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAWSi+7Lp150jxjf3c3Spq9FUWtMmKv6ADuXZ+
# x9rmxFlpLKsRIgtKKaZNiB4G3nHXLf3QXf33E6Qim86fbv5QgOeEMXtAsW9DP7dZ
# LJ1XiCP179IjgSR8Acm+EqF3es8MS1D6BT6ebShVVvlXUrDY8nN9AKQL100L+cqy
# 9fgxUY652v2k1zxXEFn0YGMRTaYTEikXkts4BpeO/Ux777LFddTPNQEfI8b2QzJI
# Rbi8aHAW//l1hD/613pICgO61i3G0VfWAG97kqMB38f1S0lnUtW0/cxYd+ltPhrn
# X/8Jxk9T6irPaKnEQemr+bo5XiNog0E44kwDT3TT3jDe9SimWaGCFwAwghb8Bgor
# BgEEAYI3AwMBMYIW7DCCFugGCSqGSIb3DQEHAqCCFtkwghbVAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCDlUOWFpfD7XwhGseLnHJy3LenPp9SBAuCf
# 1Vc9ROT6SAIGZGzCbDxJGBMyMDIzMDYwNjExNDU1Mi40ODVaMASAAgH0oIHQpIHN
# MIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjpERDhDLUUzMzctMkZBRTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEVcwggcMMIIE9KADAgECAhMzAAABxQPNzSGh9O85AAEA
# AAHFMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMTEwNDE5MDEzMloXDTI0MDIwMjE5MDEzMlowgcoxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkREOEMtRTMz
# Ny0yRkFFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAq0hds70eX23J7pappaKXRhz+
# TT7JJ3OvVf3+N8fNpxRs5jY4hEv3BV/w5EWXbZdO4m3xj01lTI/xDkq+ytjuiPe8
# xGXsZxDntv7L1EzMd5jISqJ+eYu8kgV056mqs8dBo55xZPPPcxf5u19zn04aMQF5
# PXV/C4ZLSjFa9IFNcribdOm3lGW1rQRFa2jUsup6gv634q5UwH09WGGu0z89Rbtb
# yM55vmBgWV8ed6bZCZrcoYIjML8FRTvGlznqm6HtwZdXMwKHT3a/kLUSPiGAsrIg
# Ezz7NpBpeOsgs9TrwyWTZBNbBwyIACmQ34j+uR4et2hZk+NH49KhEJyYD2+dOIaD
# GB2EUNFSYcy1MkgtZt1eRqBB0m+YPYz7HjocPykKYNQZ7Tv+zglOffCiax1jOb0u
# 6IYC5X1Jr8AwTcsaDyu3qAhx8cFQN9DDgiVZw+URFZ8oyoDk6sIV1nx5zZLy+hNt
# akePX9S7Y8n1qWfAjoXPE6K0/dbTw87EOJL/BlJGcKoFTytr0zPg/MNJSb6f2a/w
# DkXoGCGWJiQrGTxjOP+R96/nIIG05eE1Lpky2FOdYMPB4DhW7tBdZautepTTuShm
# gn+GKER8AoA1gSSk1EC5ZX4cppVngJpblMBu8r/tChfHVdXviY6hDShHwQCmZqZe
# bgSYHnHl4urE+4K6ZC8CAwEAAaOCATYwggEyMB0GA1UdDgQWBBRU6rs4v1mxNYG/
# rtpLwrVwek0FazAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYI
# KwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAy
# MDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4ICAQCMqN58frMHOScciK+Cdnr6dK8fTsgQDeZ9bvQjCuxN
# IJZJ92+xpeKRCf3Xq47qdRykkKUnZC6dHhLwt1fhwyiy/LfdVQ9yf1hYZ/RpTS+z
# 0hnaoK+P/IDAiUNm32NXLhDBu0P4Sb/uCV4jOuNUcmJhppBQgQVhFx/57JYk1LCd
# jIee//GrcfbkQtiYob9Oa93DSjbsD1jqaicEnkclUN/mEm9ZsnCnA1+/OQDp/8Q4
# cPfH94LM4J6X0NtNBeVywvWH0wuMaOJzHgDLCeJUkFE9HE8sBDVedmj6zPJAI+7o
# zLjYqw7i4RFbiStfWZSGjwt+lLJQZRWUCcT3aHYvTo1YWDZskohWg77w9fF2QbiO
# 9DfnqoZ7QozHi7RiPpbjgkJMAhrhpeTf/at2e9+HYkKObUmgPArH1Wjivwm1d7PY
# WsarL7u5qZuk36Gb1mETS1oA2XX3+C3rgtzRohP89qZVf79lVvjmg34NtICK/pMk
# 99SButghtipFSMQdbXUnS2oeLt9cKuv1MJu+gJ83qXTNkQ2QqhxtNRvbE9QqmqJQ
# w5VW/4SZze1pPXxyOTO5yDq+iRIUubqeQzmUcCkiyNuCLHWh8OLCI5mIOC1iLtVD
# f2lw9eWropwu5SDJtT/ZwqIU1qb2U+NjkNcj1hbODBRELaTTWd91RJiUI9ncJkGg
# /jCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQEL
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
# 0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLOMIICNwIB
# ATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UE
# CxMdVGhhbGVzIFRTUyBFU046REQ4Qy1FMzM3LTJGQUUxJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVACEAGvYXZJK7
# cUo62+LvEYQEx7/noIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwDQYJKoZIhvcNAQEFBQACBQDoKQwjMCIYDzIwMjMwNjA2MDkzNjM1WhgPMjAy
# MzA2MDcwOTM2MzVaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOgpDCMCAQAwCgIB
# AAICC3ECAf8wBwIBAAICE+gwCgIFAOgqXaMCAQAwNgYKKwYBBAGEWQoEAjEoMCYw
# DAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0B
# AQUFAAOBgQDn/AVkinnxoW7oiA6JaC2aH8bU3EddsOkS5TGsob5xe6RIod8OpI8a
# 54rjAfuQhf1qET2KD8WWMLsMShcG8nbA0FcbGWIxShkZXeyzLAnna1i19M5dQVkj
# cXOqMKlDzAVCgDtwKKiyEjHbDPf7aPLNz0n1FfmEDmGOjZ5BhCG3ZzGCBA0wggQJ
# AgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABxQPNzSGh
# 9O85AAEAAAHFMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZI
# hvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIBa7fHvWn4g5U84EhzlyqMg9Sw8vJtxX
# 8qHvmnR0gHOSMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgGQGxkfYkd0wK
# +V09wO0sO+sm8gAMyj5EuKPqvNQ/fLEwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMAITMwAAAcUDzc0hofTvOQABAAABxTAiBCAUBiLXb89pWwpW
# fiLt7KCdsFZonG2R84rYVWZMvQb62DANBgkqhkiG9w0BAQsFAASCAgCGJs/+g022
# JhAheC6tlPk2yAYYUD/m7PS28tvxhf1hNCkbUg1P17sF4Ybi7GB1VAidAlWCGIAF
# 2YJ5b/pjdhvKHM0r3OJe/dDqxuAW7BZvu0w3/70hqhDqrdaqDrptlhFgzbUE4QPd
# 6bGRjs7G9p+gc4Js5AI1mggc3aZAY0F8H+4g2+YqEaPfR8K89ZgGvfG6aVsm7KUI
# CRJPkB+NKQ63eeno9gaxLiyG3YLmOl96kfsDUe98YvrhnkBa/zVucLuSVOea6YeU
# /GG7/ta+KEKIq7M4Qb2hrjnhhY55Y69bIQrRPt+wdBH3QrB1UFH8KpB+bMktmYEe
# WkQyGobHL0apkzQRuX+ip/fS4A8KCrPiwIbQGz0q0GlFqe8nrnv8SmrGToiDOsom
# Fy+jsbm2yEFOABuK/CaYi/5LNcWc12Rr6bveTb3lA/ZG53+3Lk00ybTxauvTTezG
# h3bPC05XuBxDGKR9w9qn+N4ZYkBGSfjcSVyM6CqHKRRP6jRDl5F6zl8eVkQRQXmQ
# jWGTwq844nFngn2OihRHDtVJDyCtedqfyPplFOGr5zzIqNKajKxWnOimIxKtr/A+
# FO16gSx0zQps3ZzbfMFznR9H9xmJzVmau8fFbEXB8PRko9bEhITstYdofnFbC6lt
# SvT91fikLRIgoFHwa92nRdh/Y5Ff+ZX4aQ==
# SIG # End signature block
