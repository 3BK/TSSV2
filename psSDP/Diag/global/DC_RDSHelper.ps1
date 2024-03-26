#************************************************
# DC_RDSHelper.ps1
# Version 1.0.1
# Date: 21-01-2012
# Author: Daniel Grund - dgrund@microsoft.com /#_# WalterE
# Description: 
#	RDS helper file 
# 1.0.0 Beta release
# 1.0.1 Added advapi32 to get userrightsassigments
#************************************************
PARAM(
    $RDSHelper,
	$RDSSDPStrings
)

$RDSHelper=@"
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security;
using System.ComponentModel;
using System.Collections;

public class RDSHelper
{
		public struct Collection
		{
			public string CollectionName;
			public string[] CollectionServers;
		}

		public struct ConnectionBroker
		{
			public string ConnectionBrokerName;
			public Collection[] Collections;
		}

        [StructLayout(LayoutKind.Sequential,Pack=1)]
        struct CertChain
        {
            public int Version;
            public int Count;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8000)]
            /*
            struct _Cert_Blob
            {
                public int cbCert;     // size of this certificate blob
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8000)]
                public byte[] abCert;    // beginning byte of this certificate

            }*/
            public byte[] Certs;

        }

        [StructLayout(LayoutKind.Sequential,Pack=1)]
        struct _Cert_Blob
        {
            public int cbCert;     // size of this certificate blob
            public byte[] abCert;    // beginning byte of this certificate

        }
    public static bool RDPTestPort(string HostName, int port)
    { 
        // 5985 will be new Win8 'remoting' port
        // Create a TCP/IP client socket.
        // machineName is the host running the server application.
        TcpClient client = new TcpClient(HostName,port);
        if (client.Connected) return true;
        return false;
    }    
    public static X509Certificate RDPGetCert(string HostName, int port, string SavePath)
    { 
        X509Certificate cert = null;
       // Create a TCP/IP client socket.
        // machineName is the host running the server application.
        TcpClient client = new TcpClient(HostName,port);
		// sets the time out for the read and write to 5 seconds.
		client.ReceiveTimeout =5000;
        client.SendTimeout = 5000;
        try 
        {
			// Create an SSL stream that will close the client's stream.
	        SslStream sslStream = new SslStream(
	            client.GetStream(), 
	            false,
	            // always accept certificate 
	            new RemoteCertificateValidationCallback (delegate {return true;}), 
	            null
	            );
			// Set timeouts for the read and write to 5 seconds.
		    sslStream.ReadTimeout = 5000;
			sslStream.WriteTimeout = 5000;
            sslStream.AuthenticateAsClient(HostName);
            cert = sslStream.RemoteCertificate ;
            FileStream FS = new FileStream(SavePath, FileMode.Create);
            byte[] certBytes = cert.Export(X509ContentType.Cert, "");
            FS.Write(certBytes, 0, certBytes.Length);
            FS.Close();
        } 
        catch (System.Security.Cryptography.CryptographicException e)
        {
            // must do something with e to satisfy compiler or compile with -ignorewarning
        }
        client.Close();
        return cert ;
    }

	public static X509CertificateCollection GetCertCollFromReg( byte[] Cert)
        {
            X509CertificateCollection CertColl = null;
            try
            {
                GCHandle Handle = GCHandle.Alloc(Cert, GCHandleType.Pinned);
                IntPtr Ptr = Handle.AddrOfPinnedObject();
                CertChain certChain = (CertChain) Marshal.PtrToStructure(Ptr,typeof (CertChain));
                CertColl = new X509CertificateCollection();
                byte[] sCert = ((CertChain)Marshal.PtrToStructure(Ptr, typeof(CertChain))).Certs;
                
                int SizeCert = 0, offset = 0 ;
                GCHandle CHandle = GCHandle.Alloc(sCert, GCHandleType.Pinned);
                IntPtr CPtr = CHandle.AddrOfPinnedObject();
                
                for (int x = 0; x < certChain.Count ;x++ )
                {
                
                    SizeCert = sCert[offset +3];
                    SizeCert = SizeCert *256 + sCert[offset +2];
                    SizeCert = SizeCert *256 + sCert[offset +1];
                    SizeCert = SizeCert * 256 + sCert[offset + 0];
                    byte[] Cert1 = new byte[SizeCert];
                    uint uPtr = (uint)CPtr;
                    uPtr += 4;
                    CPtr = (IntPtr)uPtr;
                    Marshal.Copy(CPtr, Cert1, 0 , SizeCert );
                   CertColl.Add(new X509Certificate(Cert1));
                   offset += 4 + SizeCert;
                   uPtr += (uint) SizeCert;
                   CPtr = (IntPtr)uPtr;
                   
                }
                Handle.Free();
                CHandle.Free();
                return CertColl;
            }
            catch( System.Security.Cryptography.CryptographicException e)
            {
                // must do something with e to satisfy compiler or compile with -ignorewarning
                 
                return CertColl;
            }
            
        }
        
        public static IPAddress[] DNSLookup(string HostName)
        {
            IPHostEntry rdhost = Dns.GetHostEntry(HostName);
            return rdhost.AddressList;
        }

		public static int GetHttpsCert(string HostName, string SavePath)
		{
			bool Success = false;
			string Error = "";
			int nError = 0;
			X509Certificate cert = null;
			string targetURL = "https://" + HostName + "/rpc";
            HttpWebRequest webreq = (HttpWebRequest)WebRequest.Create(targetURL);
            HttpWebResponse webresp;
			try
			{
				webreq.UseDefaultCredentials = true;
				// should be set automaticly when UseDefaultCredentials is set to true.. just to be sure
                webreq.Credentials = System.Net.CredentialCache.DefaultNetworkCredentials;
				// accept all certificates
				ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(delegate {return true;});
				Uri Host = new Uri(targetURL);
				webresp = (HttpWebResponse)webreq.GetResponse();
			}
			catch (Exception gwe)
            {
                Error = gwe.Message;
            }

			if (Error !="")
			{
				// first of all did we get to the Rpc page...?
				if (Error.Contains("401")) // auth error, page must exist
					nError = 1 ;  //Supplied credentials did not work

				if (Error.Contains("404")) // auth error, page must exist
					nError = 2; //There is no Rpc web site, required for SOAP calls to the AAEdge/Gateway

				if (Error.Contains("Unable to connect")) // no HTTPS
					nError = 3; //There is no HTTPS web service at the address

				if (Error.Contains("503")) 
                    nError = 4; //"The remote server returned an error: (503) Server Unavailable."
				
			}
			if (webreq.ServicePoint.Certificate != null)
            {
				// now save the retrieved certificate.
				cert = webreq.ServicePoint.Certificate;
				FileStream FS = new FileStream(SavePath, FileMode.Create);
				byte[] certBytes = cert.Export(X509ContentType.Cert, "");
				FS.Write(certBytes, 0, certBytes.Length);
				FS.Close();
				return 0; //Success
			}
			if (nError ==0) // only log error if we did not get certificate......
			return 5; //No certificate found.
			return nError;
		}
		
		    [StructLayout(LayoutKind.Sequential)]
    struct OBJECT_ATTRIBUTES
    {
        internal int Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal int Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct UNICODE_STRING
    {
        internal ushort Length;
        internal ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ENUMERATION_INFORMATION
    {
        internal IntPtr PSid;
    }

    sealed class advapi32
    {
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
        SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaOpenPolicy(
            UNICODE_STRING[] SystemName,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            int AccessMask,
            out IntPtr PolicyHandle);

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
        SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaEnumerateAccountsWithUserRight(
            IntPtr PolicyHandle,
            UNICODE_STRING[] UserRights,
            out IntPtr EnumerationBuffer,
            out int CountReturned);

        [DllImport("advapi32")]
        internal static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool ConvertSidToStringSid(
            IntPtr pSid, 
            out IntPtr strSid);

    }
    public class Lsa : IDisposable
    {
        IntPtr PolicyHandle;
        enum Access : int
        {
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }

        public Lsa()
            : this(null)
        { }

        public Lsa(string TargetHost)
        {
            OBJECT_ATTRIBUTES ObjectAttributes;
            ObjectAttributes.RootDirectory = IntPtr.Zero;
            ObjectAttributes.ObjectName = IntPtr.Zero;
            ObjectAttributes.Attributes = 0;
            ObjectAttributes.SecurityDescriptor = IntPtr.Zero;
            ObjectAttributes.SecurityQualityOfService = IntPtr.Zero;
            ObjectAttributes.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
            PolicyHandle = IntPtr.Zero;
            UNICODE_STRING[] SystemName = null;
            if (TargetHost != null)
            {
                SystemName = new UNICODE_STRING[1];
                SystemName[0] = InitUnicodeString(TargetHost);
            }

            uint ret = advapi32.LsaOpenPolicy(SystemName, ref ObjectAttributes, (int)Access.POLICY_ALL_ACCESS, out PolicyHandle);
            return;

        }

        public string[] ReadUserRightAssigment(string UserRight)
        {
            UNICODE_STRING[] UserRights = new UNICODE_STRING[1];
            UserRights[0] = InitUnicodeString(UserRight);
            IntPtr EnumerationBuffer;
            int CountReturned = 0;
            uint Status = advapi32.LsaEnumerateAccountsWithUserRight(PolicyHandle, UserRights, out EnumerationBuffer, out CountReturned);
            string[] SidStrings = new string[CountReturned];
            if (Status == 0)
            {

                ENUMERATION_INFORMATION[] EnumInfo = new ENUMERATION_INFORMATION[CountReturned];

                for (int i = 0, BufferOffset = (int)EnumerationBuffer; i < CountReturned; i++)
                {
                    IntPtr ptrSid;
                    EnumInfo[i] = (ENUMERATION_INFORMATION)Marshal.PtrToStructure(
                           (IntPtr)BufferOffset, typeof(ENUMERATION_INFORMATION));
                    advapi32.ConvertSidToStringSid(EnumInfo[i].PSid, out ptrSid);
                    SidStrings[i] = Marshal.PtrToStringAuto(ptrSid);
                    BufferOffset += Marshal.SizeOf(typeof(ENUMERATION_INFORMATION));
                }
            }
            return SidStrings;
        }

        public void Dispose()
        {
            if (PolicyHandle != IntPtr.Zero)
            {
                advapi32.LsaClose(PolicyHandle);
                PolicyHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~Lsa()
        {
            Dispose();
        }

        static UNICODE_STRING InitUnicodeString(string _string)
        {
            UNICODE_STRING UnicodeString = new UNICODE_STRING();
            UnicodeString.Buffer = _string;
            UnicodeString.Length = (ushort)(_string.Length * sizeof(char));
            UnicodeString.MaximumLength = (ushort)(UnicodeString.Length + sizeof(char));
            return UnicodeString;
        }
    }
	public static bool IsLocalPolicyAllowingNetwork()
	{
        using (RDSHelper.Lsa lsa = new RDSHelper.Lsa())
        {
            string Everyone = "S-1-1-0";
            string AuthenticatedUsers = "S-1-5-11";
            bool Found = false;
            string[] Users = lsa.ReadUserRightAssigment("SeNetworkLogonRight");
           if (((IList)Users).Contains(Everyone) || ((IList)Users).Contains(AuthenticatedUsers))
           {
               Found = true;
           }
		   return Found;
        }
	}
}
"@

Add-Type -TypeDefinition $RDSHelper -IgnoreWarnings

Function Get-RemoteRegistryKeyProperty {
    param(
      $ComputerName = $(throw "Please specify a computer name."),
      $Path = $(throw "Please specify a registry path"),
      $Property = "*"
      ) 


    ## Validate and extract out the registry key
    if($path -match "^HKLM:\\(.*)")
    {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
            "LocalMachine", $computername)
    }
    elseif($path -match "^HKCU:\\(.*)")
    {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
            "CurrentUser", $computername)
    }
    else
    {
        Write-Error ("Please specify a fully-qualified registry path " +
            "(i.e.: HKLM:\Software) of the registry key to open.")
        return
    } 

    ## Open the key
    $key = $baseKey.OpenSubKey($matches[1])
    $returnObject = New-Object PsObject 

    ## Go through each of the properties in the key
    foreach($keyProperty in $key.GetValueNames())
    {
        ## If the property matches the search term, add it as a
        ## property to the output
        if($keyProperty -like $property)
        {
            $returnObject |
                Add-Member NoteProperty $keyProperty $key.GetValue($keyProperty)
        }
    } 

    ## Return the resulting object
    $returnObject 

    ## Close the key and base keys
    $key.Close()
    $baseKey.Close()
}

Function GetLSConnectDesc {
    param(
        [int]$ConnectResult = 0
    )
    switch($ConnectResult){
    0{"The connectivity status cannot be determined."}
 
    1{"Remote Desktop Services can connect to the Windows Server 2008 R2 license server."}
 
    2{"Remote Desktop Services can connect to the Windows Server 2008 license server."}
 
    3{"Remote Desktop Services can connect to the license server, but one of the servers is running a beta version of the operating system."}
 
    4{"Remote Desktop Services can connect to the license server, but there is an incompatibility between the license server and the Remote Desktop Services host server."}
 
    5{"Security group policy is enabled in license server, but Remote Desktop Services is not a part of the group policy."}
 
    6{"Remote Desktop Services cannot connect to the license server."}
 
    7{"The license server can be connected to, but the validity of the connection cannot be determined."}
 
    8{"Remote Desktop Services can connect to the license server, but the user account does not have administrator privileges on the license server."}
    
    9{"Remote Desktop Services can connect to the Windows Server 2008 SP1 with VDI support license server."}

	10{"Feature not supported."}

	11{"The license server is valid"}
    }
 
}

Function TSLicensingType {
	param(
		[int]$Type = 5
	)
	switch($Type){
		0{"Personal RD Session Host server."}
		1{"Remote Desktop for Administration."}
		2{"Per Device. Valid for application servers."}
		3{"Invalid!!"}
		4{"Per User. Valid for application servers."}
		5{"Not configured."}

	}
}

Function TSProtocol {
    param(
        [int]$Protocol = 0
    )
    switch($Protocol){
    0{"This session is running on a physical console."}
 
    1{"A proprietary third-party protocol is used for this session."}
 
    2{"Remote Desktop Protocol (RDP) is used for this session."}
 
    }
 
}

Function SessionState {
    param(
        [int]$Session = 0
    )
    switch($Session){
    0{"The session is active."}
 
    1{"The session is disconnected."}
 
    }
 
}

Function ReportError
	{
		param(
			$RootCause = "No known error",
			$Solution = "No known solution",
			$RCNum,
			$Detected = $true
  		)

		$RootCauseName = "RC_RDS" + $RCNum
		"Found Rootcause: " + $RootCause + " Found Solution: " + $Solution | WriteTo-StdOut
		Update-DiagRootCause -Id $RootCauseName -Detected $Detected -Parameter @{"Error" = $RootCause; "Solution" = $Solution}

		# $InformationCollected = new-object PSObject
		# add-member -inputobject $InformationCollected -membertype noteproperty -name $RootCause + " found:"  -value  $RootCause
		# add-member -inputobject $InformationCollected -membertype noteproperty -name $RootCause + " solution: " -value  $Solution 
		# Write-GenericMessage -RootCauseId $RootCauseName  -InformationCollected $InformationCollected -Visibility 4 -Component "Windows Remote Desktop Services"
	}

Function UpdateAndMessage
	{
		param(
			$Id,
			$Detected,
			$RootCause = "",
			$Solution = ""
		)
		"Entering UpdateAnMessage() $Id $Detected" |  WriteTo-StdOut
		Update-DiagRootCause -Id $Id -Detected $Detected
		if ($Detected)
		{
			$InformationCollected = new-object PSObject
				
			if ($RootCause -ne "")
			{
				add-member -inputobject $InformationCollected -membertype noteproperty -name ($Id + " found:")  -value  $RootCause
				if ($Solution -ne "")
				{
					add-member -inputobject $InformationCollected -membertype noteproperty -name ($Id + " solution:") -value  $Solution 
				}
			}
				Add-GenericMessage -Id $Id  -InformationCollected $InformationCollected 

		}

	}

Function SaveAsXml
	{
		param(
			$Object,
			$FileName,
			[array]$OutputFileName
			)
		$PItext = "type='text/xsl' href='RDS.xslt'"
		$File = $PWD.Path  + "\" + $FileName
	    $xml = ConvertTo-Xml $Object
		if($xml.HasChildNodes)
        {
			$Objects = $xml.SelectNodes("Objects/Object/Property")
			if(($Objects -ne $null) -and ($xml.SelectSingleNode("Objects/Object").Attributes.GetNamedItem("Type")."#text" -eq "System.Object[]"))
			{
				foreach( $xmlnode in $Objects)
				{
					$start = ($xmlnode.SelectSingleNode("Property[@Name = 'ClassPath']"))."#text".indexof(':')
					$name = ($xmlnode.SelectSingleNode("Property[@Name = 'ClassPath']"))."#text".Substring($start+1)
					$xmlnode.Attributes.Item(0)."#text" = $name
					$xmlnode.SelectSingleNode("Property[@Name = 'ClassPath']").RemoveAll()
				}
			}
			else
			{
				$xml.SelectSingleNode("Objects/Object").Attributes.RemoveAll()
				$start = ($xml.SelectSingleNode("Objects/Object/Property[@Name = 'ClassPath']"))."#text".indexof(':')
				$name = ($xml.SelectSingleNode("Objects/Object/Property[@Name = 'ClassPath']"))."#text".Substring($start+1)
				$aatr = $xml.CreateAttribute("Type")
				$aatr.Value = $name
				$xml.SelectSingleNode("Objects/Object").Attributes.Append($aatr)
				$xml.SelectSingleNode("Objects/Object/Property[@Name = 'ClassPath']").RemoveAll()
			}
			$newPI = $xml.CreateProcessingInstruction("xml-stylesheet",$PItext)
			$xml.InsertAfter($newPI,$xml.FirstChild)
			$xml.save($File)
			[array]$OutputFileName += $File
			[xml] $xslContent = Get-Content ./rds.xslt
			$xslobject = New-Object system.Xml.Xsl.XslTransform
			$xslobject.Load($xslContent)
			$htmlfile =$File.substring(0,$File.length -4) + ".html"
			$xslobject.Transform($File,$htmlfile)
			[array]$OutputFileName += $htmlfile
		}
		$OutputFileName
	}

Function FilterWMIObject
	{
		param ($Object)
		$Object | Select-Object * -excludeproperty "_*",Options,Properties,Systemproperties,Path,Description,InstallDate,Caption,Scope,Qualifiers,Site,Container,Status
	}

Function SaveRDPFileContents
	{
		param ($Object,
			$ObjectName,
			[array]$OutputFileName)
		
		if ($Object -ne $null)
		{
			
			foreach ($remoteresource in $Object)
			{
				$savepath = $TargetHost +"_" + $remoteresource.Alias + "_" + $ObjectName + ".RDP"
				$remoteresource.RDPFileContents | Out-File $savepath
				[array]$OutputFileName += $savepath
				$remoteresource.RDPFileContents = "Saved as: " + $savepath
			}
			$OutputFileName = SaveAsXml $Object  ($TargetHost +"_" + $ObjectName + ".xml") $OutputFileName
			
		}
		$OutputFileName
	}

Function out-zip 
	{ 
	  Param([string]$ZipPath, $Files) 

	  if (-not $ZipPath.EndsWith('.zip')) {$ZipPath += '.zip'} 

	  if (-not (test-path $ZipPath)) { 
		set-content $ZipPath ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18)) 
	  } 
	  $ZipFile = (new-object -com shell.application).NameSpace($ZipPath) 
	  foreach ($File in $Files)
	  {
		"Saving $File in  $ZipPath"| WriteTo-StdOut
		$ZipFile.CopyHere($File, 1052)
	  } 

	}

Function IsEventLogged
	{
		param($EventLog,
			$EventId)
		$output = wevtutil qe $EventLog "/q:*[System [(EventID = $EventId)]]" /c:1
		if($output -ne $null)
		{
			$true
		}else
		{
			$false
		}
	}

Function WMISecGroupsNotPresent
	{
		$security = Get-CimInstance -Namespace root/cimv2/terminalservices -Class __SystemSecurity
		$converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
		$binarySD = @($null)
		$result = $security.PsBase.InvokeMethod("GetSD",$binarySD)
		$WMIDescriptor = ($converter.BinarySDToWin32SD($binarySD[0])).Descriptor
		$RDSGroup = "RDS Management Servers","RDS Remote Access Servers","RDS Endpoint Servers"
		$Count = 0
		foreach ($DACL in $WMIDescriptor.dacl)
		{
			if ($DACL.Trustee.Name -eq "TS Web Access Computers") {return $false}
			if ($RDSGroup.Contains($DACL.Trustee.Name)){ $Count++}
			if ($Count -eq 3) {return $false}
		}
		$true
	}

function CheckNode
	{
	 Param( $Node, $Checked)
	 if($Node -ne $null)
	 {
	  foreach ($ChildNode in $Node.Nodes)
	  {
		$ChildNode.Checked = $Checked
		if( $ChildNode.Nodes.Count -gt 0)
		{
			CheckNode -Node $ChildNode -Checked $Checked
		}
	   }  
	  }
	}

function GetNodesChecked
	{
		Param ($objTreeView, [array]$ServersToCollect)
		if($objTreeView -ne $null)
		{
			for($x=0; $x -lt $objTreeView.Nodes.GetNodeCount($false);$x++)
			{
				for($y = 0;$y -lt $objTreeView.Nodes.Nodes[$x].GetNodeCount($True); $y++)
				{
					if($objTreeView.Nodes.Nodes[$x].Nodes[$y].Checked -eq $true)
					{
						[array]$ServersToCollect+= $objTreeView.Nodes.Nodes[$x].Nodes[$y].Text
					}

				}
			}
        
		}else
		{
			$ServersToCollect = $null
		}
		$ServersToCollect
	}

function AddCBtoTreeView
	{
		param ($objTreeView, $ConnectionBroker)
		$objTreeNode = New-Object System.Windows.Forms.TreeNode($ConnectionBroker.ConnectionBrokerName)
		$objTreeNode.Name = $ConnectionBroker.ConnectionBrokerName
		$objTreeView.Nodes.Add($objTreeNode)
		foreach($Collect in $ConnectionBroker.Collections)
		{
			$objChildNode = New-Object System.Windows.Forms.TreeNode($Collect.CollectionName);
			$objChildNode.Name = $Collect.CollectionName;
			$objTreeView.Nodes[$ConnectionBroker.ConnectionBrokerName].Nodes.Add($objChildNode);
			foreach($Server in  $Collect.CollectionServers)
			{
				$objServer = New-Object System.Windows.Forms.TreeNode($Server);
				$Server.Name = $Server
				$objTreeView.Nodes[$ConnectionBroker.ConnectionBrokerName].Nodes[$Collect.CollectionName].Nodes.Add($Server);
			}
		}
		$objTreeView.add_AfterCheck({
			if($_.Action -ne [System.Windows.Forms.TreeViewAction]::Unknown)
			{
				if($_.Node.Nodes.Count -gt 0)
				{
    
					CheckNode -Node $_.Node -Checked $_.Node.Checked
				}
			}
		 })
	}


Function CreateTreeViewUI
	{
		param ($ConnectionBroker)
		[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
		[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
		$objForm = New-Object System.Windows.Forms.Form 
		$objForm.Text = "Select a Computer"
		$objForm.Size = New-Object System.Drawing.Size(500,200) 
		$objForm.StartPosition = "CenterScreen"


		$OKButton = New-Object System.Windows.Forms.Button
		$OKButton.Location = New-Object System.Drawing.Size(320,120)
		$OKButton.Size = New-Object System.Drawing.Size(75,23)
		$OKButton.Text = "OK"
		$OKButton.Add_Click({$objForm.Close()})
		$objForm.Controls.Add($OKButton)

		$CancelButton = New-Object System.Windows.Forms.Button
		$CancelButton.Location = New-Object System.Drawing.Size(395,120)
		$CancelButton.Size = New-Object System.Drawing.Size(75,23)
		$CancelButton.Text = "Cancel"
		$CancelButton.Add_Click({$objForm.Close()})
		$objForm.Controls.Add($CancelButton)

		$objLabel = New-Object System.Windows.Forms.Label
		$objLabel.Location = New-Object System.Drawing.Size(10,20) 
		$objLabel.Size = New-Object System.Drawing.Size(480,20) 
		$objLabel.Text = "Please check Computers or Collection to collect data from."
		$objForm.Controls.Add($objLabel) 

		$objTreeView = New-Object System.Windows.Forms.TreeView 
		$objTreeView.Location = New-Object System.Drawing.Size(10,40) 
		$objTreeView.Size = New-Object System.Drawing.Size(460,20) 
		$objTreeView.Height = 80
		$objTreeView.CheckBoxes = $True
	
		AddCBtoTreeView -objTreeView $objTreeView -ConnectionBroker $ConnectionBroker
	
		$objForm.Controls.Add($objTreeView) 
		$objForm.Topmost = $True
		$objForm.Add_Shown({$objForm.Activate()})
		[void] $objForm.ShowDialog()
		$objTreeView
	}

    Function IsRDPDDAccelerated
    {
		if((Get-Item HKLM:SYSTEM\CurrentControlSet\services\rdpdd -EA SilentlyContinue) -ne $null) #_# -EA
		{
			"IsRDPDDAccelerated () Found rdpdd " | WriteTo-StdOut
            foreach($key in Get-ChildItem HKLM:SYSTEM\CurrentControlSet\services\rdpdd)
	       {
                if($key.Name.Contains("Device"))
                {
				"IsRDPDDAccelerated () Found rdpdd\Device " | WriteTo-StdOut
					foreach($property in $key.Property)
					{
						if ($property.Contains("Acceleration.Level"))
                        {
						"IsRDPDDAccelerated () Found rdpdd\Device\Acceleration.Level " | WriteTo-StdOut
                        return $True
                        }
					}
				}
			}              
         }
      return $False
    }

# code for reg permisions checking  on the LICENSE keys
	Function CheckRegPerm
	{
		Param ( $RegPath, $Rights)
		 ((get-acl $RegPath).Access | where-object -Property IdentityReference -Like $Users| where-object -Property RegistryRights -Contains $Rights) -ne $null
	}

	Function IsRegPermIssue
	{
		$RegRights=[System.Security.AccessControl.RegistryRights]("SetValue, CreateSubKey, ReadKey")
		$RegDelRights = [System.Security.AccessControl.RegistryRights]("Delete")
		$Users = [System.Security.Principal.NTAccount]("BUILTIN\Users") 
		if((CheckRegPerm -RegPath "HKLM:\SOFTWARE\Microsoft\MSLicensing\Store"-Rights $RegRights) -eq $false)
		{return $true}

		if( $Licenses = (Get-ChildItem HKLM:\SOFTWARE\Microsoft\MSLicensing\Store).Name.Replace("HKEY_LOCAL_MACHINE", "HKLM:"))
		{
			[array]$Results = $null
			Foreach( $License in $Licenses){ [array]$Results+= CheckRegPerm -RegPath $License -Rights $RegDelRights}
			return $Results.Contains($false) -eq $true
		}
		$false
	}


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBZuYfFrgUIxSG+
# vH38/hBQ6z+DfMwV2GdzxByBgsLlNKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGY4wghmKAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGqKuUx82J8+t5qTjbzQ7f9T
# zsyCkiurUpU4NQ4hfxGrMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQABspoQBKelBzVttAxkq3s8zvaoK2lZVMFgzVNmFg5s8Jgv79nq+cno
# 3H/oj7AqEftftYQzFgJ9hBJ9P8Kn+ZQD65K/TDKczxArPKcp1s8QdapAZhoSs1tT
# OEmVEpEmN/fcxjrA+MqpT+Z/WYt1nup3K0WBITfUskuMoW67HJ2vFhqe9pgO37Cc
# 7A5c2WIl7scI6BFnvHBGaZKBtyxaDP+MPf0NFxmfaAMQE7rRTcXjMz9KcP8by3zV
# ItD3jeSA4e5RwQ/FaV2gx2Mn0CQXZI7zOqf+zUBct9yLBs4mErqwkPZNzCwkONuY
# t19Iilxa5ikIxT42OECHHtvaAQGLIVgxoYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIEYHUOmXj3DACyXOqjMm3FV9JVmUEFVVNQCQEhUA+1rvAgZi3mrX
# 8kwYEzIwMjIwODAxMDc1MDE4LjQyNFowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046MDg0Mi00QkU2LUMyOUExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAYdCFmYEXPP0jQABAAABhzAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3MzlaFw0yMzAxMjYxOTI3MzlaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjA4NDIt
# NEJFNi1DMjlBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvml4GWM9A6PREQiHgZAA
# PK6n+Th6m+LYwKYLaQFlZXbTqrodhsni7HVIRkqBFuG8og1KZry02xEmmbdp89O4
# 0xCIQfW8FKW7oO/lYYtUAQW2kp0uMuYEJ1XkZ6eHjcMuqEJwC47UakZx3AekakP+
# GfGuDDO9kZGQRe8IpiiJ4Qkn6mbDhbRpgcUOdsDzmNz6kXG7gfIfgcs5kzuKIP6n
# N4tsjPhyF58VU0ZfI0PSC+n5OX0hsU8heWe3pUiDr5gqP16a6kIjFJHkgNPYgMiv
# GTQKcjNxNcXnnymT/JVuNs7Zvk1P5KWf8G1XG/MtZZ5/juqsg0QoUmQZjVh0XRku
# 7YpMpktW7XfFA3y+YJOG1pVzizB3PzJXUC8Ma8AUywtUuULWjYT5y7/EwwHWmn1R
# T0PhYp9kmpfS6HIYfEBboYUvULW2HnGNfx65f4Ukc7kgNSQbeAH6yjO5dg6MUwPf
# zo/rBdNaZfJxZ7RscTByTtlxblfUT46yPHCXACiX/BhaHEY4edFgp/cIb7XHFJbu
# 4mNDAPzRlAkIj1SGuO9G4sbkjM9XpNMWglj2dC9QLN/0geBFXoNI8F+HfHw4Jo+p
# 6iSP8hn43mkkWKSGOiT4hLJzocErFntK5i9PebXSq2BvMgzVc+BBvCN35DfD0mok
# RKxam2tQM060SORy3S7ucesCAwEAAaOCATYwggEyMB0GA1UdDgQWBBQiUcAWukEt
# YYF+3WFzmZA/DaWNIDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQC5q35T2RKjAFRN/3cYjnPFztPa7KeqJKJnKgvi
# Uj9IMfC8/FQ2ox6Uwyd40TS7zKvtuMl11FFlfWkEncN3lqihiSAqIDPOdVvr1oJY
# 4NFQBOHzLpetepHnMg0UL2UXHzvjKg24VOIzb0dtdP69+QIy7SDpcVh9KI0EXKG2
# bolpBypqRttGTDd0JQkOtMdiSpaDpOHwgCMNXE8xIu48hiuT075oIqnHJha378/D
# pugI0DZjYcZH1cG84J06ucq5ygrod9szr19ObCZJdJLpyvJWCy8PRDAkRjPJglSm
# fn2UR0KvnoyCOzjszAwNCp/JJnkRp20weItzm97iNg+FZF1J9E16eWIB1sCr7Vj9
# QD6Kt+z81rOcLRfxhlO2/sK09Uw+DiQkPbu6OZ3TsDvLsr8yG9W2A8yXcggNqd4X
# pLtdEkf52OIN0GgRLSY1LNDB4IKY+Zj34IwMbDbs2sCig5Li2ILWEMV/6gyL37J7
# 1NbW7Vzo7fcGrNne9OqxgFC2WX5degxyJ3Sx2bKw6lbf04KaXnTBOSz0QC+RfJuz
# 8nOpIf28+WmMPicX2l7gs/MrC5anmyK/nbeKkaOx+AXhwYLzETNg+1Icygjdwnbq
# WKafLdCNKfhsb/gM5SFbgD5ATEX1bAxwUFVxKvQv0dIRAm5aDjF3DZpgvy3mSojS
# rBN/8zCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
# AQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAw
# BgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEw
# MB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk
# 4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9c
# T8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWG
# UNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6Gnsz
# rYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2
# LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLV
# wIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTd
# EonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0
# gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFph
# AXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJ
# YfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXb
# GjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJ
# KwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnP
# EP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMw
# UQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggr
# BgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYw
# DwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoY
# xDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
# L2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYB
# BQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0B
# AQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U5
# 18JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgAD
# sAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo
# 32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZ
# iefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZK
# PmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RI
# LLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgk
# ujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9
# af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzba
# ukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/
# OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLUMIIC
# PQIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MDg0Mi00QkU2LUMyOUExJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAHh3k1QEKAZEhsLGYGHtf/6DG4PzoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmkXrqMCIYDzIwMjIwODAx
# MDYwNDI2WhgPMjAyMjA4MDIwNjA0MjZaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaReuoCAQAwBwIBAAICHj8wBwIBAAICES4wCgIFAOaSzGoCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQCF/hfbIZQ0IEk6Kh2lseeEtTISZpszbfBnEeumjmWO
# 0hdqTDaefoW0+b7u5tEPoWvT2Y26R/5PThTeB8JmkwcqCENPZii9O+oZLx+a5Iou
# 6CKUmF9a1B/JSMc0nzpCTZddlgNPs96jeJuJfSrQ0BGHRHmxERqh1JwzqpL2X6pr
# 5TGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABh0IWZgRc8/SNAAEAAAGHMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIJg0Bfp49VAq4S49JEQv
# uPe6yKalSsHqS+XTnRVfq6kfMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# xCzwoBNuoB92wsC2SxZhz4HVGyvCZnwYNuczpGyam1gwgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAYdCFmYEXPP0jQABAAABhzAiBCDA
# p3m7l8Nc7DlqiRsVc7ZPNSsKmHhdZilO6Ifx7KEsVTANBgkqhkiG9w0BAQsFAASC
# AgBzBEav3bBFacWQPPQ2kU9j9nqwYLXLRXZoJiab4XPsj0sJAtEv8dUuQoODAlGH
# IbbwlZrFkkPDLDxO993ZhgR9aQBVtUMkArYhoJhH79g96O0i3n91STFzJnYETVqh
# cpXP7AmbFVouJmsjlpzCabHNKZJsD8hlPjKEQ/aC70UpVOEU50/0Eu0omOCl+T8h
# e69vB3fK+zfbeFmKeLe8+kFNlTtwkW6WLC/NacOj+5C0h6u1ACvwqjXCDPRMDWt5
# dLxevvoznyNT+mCO/ftba2jNOzCaHO4k8smdPxemDuuDouEga1waeShCb3UYxANR
# zK6wW+lvctxhu0e74mEc8tIh/WRjAKwtbyECXiu6uCHv2ueU8hLXLKhDaMyCICnr
# 4CoS6S/9jKqgDaEDifO3JlaqTlYZGBhms1NJyIV+KqlND0MBMZwLfdcvrQ6urZYI
# m31KNfavDxN8Ftfn59n5RqdIrPnEN7MxQ5a7kbAW2yO+htR95A8c0ueA7tUNlVH7
# PlCgexShs0fPFcpLnFz15yDzUOd87P7SgsJKDIyOVzfzEzhuS/7kMNzYoItyEAuS
# EBTfc2bcs4TcJogSaR0x/yCnI4d058QGAVmeZ0mBA7ztHKNXQTg6jpJ23535F1sI
# jp1IpG5s4qjNOUU/1Ll+pfxQktDl7YFqMXg63pPq5cc7nA==
# SIG # End signature block
