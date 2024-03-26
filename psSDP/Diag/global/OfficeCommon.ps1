if($Debug)
{
	if($global:OffCommRun -eq $true) {return}
}
$global:OffCommRun = $true

Import-LocalizedData -BindingVariable LocalsOfficeCommon -UICulture en-us -FileName OfficeCommon -ErrorAction SilentlyContinue
Function Add-AsArray{
	param($parentArrayObj, $valueToAdd)
	if($parentArrayObj -is [array])
	{
		$parentArrayObj += $valueToAdd
	}
	else{
		$parentArrayObj = $parentArrayObj,$valueToAdd
	}
	return $parentArrayObj
}
function Pad-Left{
param($padChar = " ",[int]$length=20)
	Process
	{
		$wholeStr = $padChar * $length + $_
		$wholeStr.Substring($wholeStr.Length-$length)
	}
}
function Pad-Right{
param($padChar = " ",[int]$length=20)
	Process
	{
		$wholeStr =$_ + $padChar * $length
		$wholeStr.Substring(0,$length)
	}
}

#Convert null string to empty string.
function Change-NullToEmpty
{
	param([string]$instr)
	$outstr = $instr
	if($outstr -eq $null){$outstr = [string]::Empty}
	return $outstr
}
Set-Alias -Name N2E -Value Change-NullToEmpty

function Test-Condition
{
	param($condition, $valueIfTrue, $valueIfFalse)
	if($condition)
	{
		return $valueIfTrue
	}
	else
	{
		return $valueIfFalse 
	}
}
Set-Alias -name IIF -value Test-Condition

function Return-ValueIfNull
{
	param($inputValue,$valueIfNull)
	return (IIF ($null -eq $inputValue) $valueIfNull $inputValue)
}
Set-Alias -name RVIN -value Return-ValueIfNull

function Return-FirstNonNullValue
{
	begin{$valueToReturn = $null}
	process{
		if($null -eq $valueToReturn){
			if($null -eq $_){}else{$valueToReturn = $_;}
		}
	}
	end{
		return $valueToReturn
	}
}
function Transform-XmlDoc
{
	param($XmlDoc,$XslPath,$OutFile="$PWD\results.html")

	if(-not [IO.File]::Exists($XslPath))
	{
		"XmlPath or XslPath not found (XslPath = $XslPath)" | Trace
		return
	}
	$tmpXmlPath = [IO.Path]::GetTempFileName();
	$XmlDoc.get_OuterXml() | Out-File $tmpXmlPath -Encoding UTF8

	Transform-Xml $tmpXmlPath $XslPath $OutFile

	[IO.File]::Delete($tmpXmlPath) | Out-Null
}
function Transform-Xml{
	param($XmlPath,$XslPath,$OutFile="$PWD\results.html")

	if((-not [IO.File]::Exists($XmlPath)) -or (-not [IO.File]::Exists($XslPath)))
	{
		"XmlPath or XslPath not found (XmlPath = $XmlPath) (XslPath = $XslPath)" | Trace
		return
	}
	[xml]$resultsXml = [xml](GC $XmlPath)

	[System.Xml.Xsl.XslTransform] $xslT = New-Object System.Xml.Xsl.XslTransform
	$xslT.Load($XslPath) | Out-Null

	$xslT.Transform($XmlPath,$OutFile) | Out-Null
}
function Find-Type
{
	param([string]$TypeName)
	foreach($asm in [AppDomain]::CurrentDomain.GetAssemblies())
	{
		if((-not $asm.IsDynamic) -and ($asm.FullName -notlike "PSEventHandler*")){ #dynamic assemblies don't support GetExportedTypes
			
			foreach($t in $asm.GetExportedTypes())
			{
				if($t.FullName -eq $TypeName)
				{
					return $true
				}
			}
		}
	}
	return $false

}

$msiExecute = @"
using System;
using System.Text;
using System.Runtime.InteropServices;


    public class QueryMsi
    {

       [DllImport("MSI.DLL", CharSet = CharSet.Auto)]
        public static extern Int32 MsiLocateComponent(string component, StringBuilder path, ref int pathLength);
        
          public static string  GetMSIInstallPath (string ComponentID)
   		  {
              
            int pathLength = 1024;
            StringBuilder path = new StringBuilder(pathLength);
            MsiLocateComponent(ComponentID, path, ref pathLength);
            return path.ToString() ;
   		  }			   
      
    }

"@

if (-not (Find-Type  "QueryMsi"))
{
Add-Type  -TypeDefinition $msiExecute -ErrorAction SilentlyContinue 
}

$TouchQuery = @"
using System;
using System.Text;
using System.Runtime.InteropServices;


    public class QueryTouchInput
    {
     [DllImport("user32.dll")]
        public static extern int GetSystemMetrics(int smIndex);
        
          public static int GetTouchType()
        { 
            const int SM_DIGITIZER = 94;
            int TouchType = GetSystemMetrics(SM_DIGITIZER);
            return TouchType;
        }   
      
    }

"@

if (-not (Find-Type  "QueryTouchInput"))
{
Add-Type  -TypeDefinition $TouchQuery -ErrorAction SilentlyContinue 
}



$global:CachedSkipApp = New-Object System.Collections.ArrayList

function Can-RunVirtual { return $false }

function Get-TimestampOfKeyFromProductName{
	param ([string]$productName)
	
	$allSubkeyTimestamps = Get-SubKeyTimestamps "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
	$allSubkeyTimestamps += Get-SubKeyTimestamps "HKLM" "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
	
	foreach($oKeyTS in $allSubkeyTimestamps){
		
		$displayName = (Get-ItemProperty -Path ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($oKeyTS.Key)", `
						"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$($oKeyTS.Key)") `
						-ErrorAction SilentlyContinue | Select -First 1).DisplayName
		
		if($displayName -eq $productName){
			return $oKeyTS.LastWriteTime
		}
	}
}

function Get-SubKeyTimestamps
{
	param (	[string] $Key, [string] $SubKey )

	switch ($Key) {
	    "HKCR" { $searchKey = 0x80000000} #HK Classes Root
	    "HKCU" { $searchKey = 0x80000001} #HK Current User
	    "HKLM" { $searchKey = 0x80000002} #HK Local Machine
	    "HKU"  { $searchKey = 0x80000003} #HK Users
	    "HKCC" { $searchKey = 0x80000005} #HK Current Config
	    default { 
	        throw "Invalid Key. Use one of the following options HKCR, HKCU, HKLM, HKU, HKCC"
	    }
	}


	$KEYQUERYVALUE = 0x1
	$KEYREAD = 0x19
	$KEYALLACCESS = 0x3F

$sig1 = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class Win32Utils{
	[DllImport("advapi32.dll", CharSet = CharSet.Auto)]
	  public static extern int RegOpenKeyEx(
	    int hKey,
	    string subKey,
	    int ulOptions,
	    int samDesired,
	    out int hkResult);
	[DllImport("advapi32.dll", EntryPoint = "RegEnumKeyEx")]
	extern public static int RegEnumKeyEx(
	    int hkey,
	    int index,
	    StringBuilder lpName,
	    ref int lpcbName,
	    int reserved,
	    int lpClass,
	    int lpcbClass,
	    out long lpftLastWriteTime);
	[DllImport("advapi32.dll", SetLastError=true)]
	public static extern int RegCloseKey(
	    int hKey);
}
'@
	$regkeyType = Add-Type -TypeDefinition $sig1 -PassThru


	$returnObjects = @()
	$hKey = new-object int
	$result = $regkeyType::RegOpenKeyEx($searchKey, $SubKey, 0, $KEYREAD, [ref] $hKey)
	if($result -ne 0) {return $returnObjects}
	
	#initialize variables
	$builder = New-Object System.Text.StringBuilder 1024
	$index = 0
	$length = [int] 1024
	$time = New-Object Long

	#234 means more info, 0 means success. Either way, keep reading
	while ( 0,234 -contains $regkeyType::RegEnumKeyEx($hKey, $index++, `
	    $builder, [ref] $length, $null, $null, $null, [ref] $time) )
	{
	    #create output object
	    $o = "" | Select Key, LastWriteTime
	    $o.Key = $builder.ToString()
	    $o.LastWriteTime = (Get-Date $time).AddYears(1600)
	    $returnObjects += $o

	    #reinitialize for next time through the loop  
	    $length = [int] 1024
	    $builder = New-Object System.Text.StringBuilder 1024
	}

	$result = $regkeyType::RegCloseKey($hKey); 
	return $returnObjects
}

function Get-OfficeProgramsInstalled
{
	param([Switch]$Refresh)
	
	if(-not $Refresh -and ($global:AllOfficeProducts -ne $null)){return $global:AllOfficeProducts}
	
	$msiExec = @"
using System;
using System.Text;
using System.Runtime.InteropServices;


    public class MsiMethods
    {

        [DllImport("msi.dll", CharSet = CharSet.Auto)]
        public static extern UInt32 MsiProvideQualifiedComponent(
            string szComponent,
            string szQualifier,
            UInt32 dwInstallMode,
            [Out] StringBuilder lpPathBuf,
            ref UInt32 pcchPathBuf);

        [DllImport("msi.dll", CharSet = CharSet.Auto)]
        public static extern UInt32 MsiProvideQualifiedComponent(
            string szComponent,
            string szQualifier,
            UInt32 dwInstallMode,
            IntPtr lpPathBuf,
            ref UInt32 pcchPathBuf);

        [DllImport("msi.dll", SetLastError = false, CharSet = CharSet.Auto)]
        static extern UInt32 MsiGetFileVersion(
            string szFilePath,
            StringBuilder lpVersionBuf,
            ref UInt32 pcchVersionBuf,
            StringBuilder lpLangBuf,
            ref UInt32 pcchLangBuf);

        [DllImport("msi.dll", SetLastError = false, CharSet = CharSet.Auto)]
        static extern UInt32 MsiGetFileVersion(
            string szFilePath,
            StringBuilder lpVersionBuf,
            ref UInt32 pcchVersionBuf,
            StringBuilder lpLangBuf,
            IntPtr pcchLangBuf);


        public static string[] GetOfficeAppVersion(string qualifiedComponentId, string qualifier)
        {

            const UInt32 INSTALLMODE_DEFAULT = 0;
            const UInt32 INSTALLMODE_EXISTING = 0xFFFFFFFF; //-1
            const UInt32 ERROR_SUCCESS = 0;

            UInt32 dwValueBuf = 255;
            UInt32 ret = ERROR_SUCCESS;
            StringBuilder pszTempPath = null;



            ret = MsiProvideQualifiedComponent(
                qualifiedComponentId,
                qualifier,
                INSTALLMODE_DEFAULT,
                IntPtr.Zero,
                ref dwValueBuf);

                
            

            if (ret == ERROR_SUCCESS)
            {
                dwValueBuf += 1;
                pszTempPath = new StringBuilder((int)dwValueBuf);

                if (pszTempPath != null)
                {
                    if ((ret = MsiProvideQualifiedComponent(
                        qualifiedComponentId,
                        qualifier,
                        INSTALLMODE_EXISTING,
                        pszTempPath,
                        ref dwValueBuf)) != ERROR_SUCCESS)
                    {
                        return null;
                    }

                    StringBuilder pszTempVer = new StringBuilder();
                    if ((ret = MsiGetFileVersion(pszTempPath.ToString(),
                        pszTempVer,
                        ref dwValueBuf,
                        null,
                        IntPtr.Zero)) != ERROR_SUCCESS)
                    {
                        return null;
                    }

                    return new string[] { pszTempVer.ToString(), pszTempPath.ToString()};
                }
            }
            return null;


        }

    }


"@


	Add-Type  -TypeDefinition $msiExec -ErrorAction SilentlyContinue 
	
	$coreproducts = ("outlook","msaccess","excel","winword","infopath","onenote","powerpnt","mspub","groove","spdesign","winproj","visio","frontpg")
	$productCodeId = ((0x1A,0xE0),0x15,0x16,0x1B,0x44,(0xA1,0xA3),0x18,0x19,0xBA,0x17,(0x3A,0x3B),(0x51,0x52,0x53),0x17)
	
	$products = @() 

    $QualifiedComponents = (
				"{E83B4360-C208-4325-9504-0D23003A74A5}", # Office 2013
                "{1E77DE88-BCAB-4C37-B9E5-073AF52DFD7A}", # Office 2010
                "{24AAE126-0911-478F-A019-07B875EB9996}", # Office 2007
                "{BC174BAD-2F53-4855-A1D5-0D575C19B1EA}")  # Office 2003
	$productCodePattern = (
				"\{{\d{{2}}150000-{0:x4}-\d{{4}}-{1}000-0000000FF1CE\}}",
				"\{{\d{{2}}140000-{0:x4}-\d{{4}}-{1}000-0000000FF1CE\}}",
				"\{{\d{{2}}120000-{0:x4}-\d{{4}}-{1}000-0000000FF1CE\}}",
				"\{(\d{{2}}{0:x2}\d{{4}}-6000-11D3-8CFE-0150048383C9\}}")
				
	$bitnesses = @("x86")
	if($OSArchitecture -match "64"){$bitnesses += "x64"}
	$prId = -1
	foreach($prod in $coreproducts)
	{
		"Looking for $prod" | Trace -DebugOnly
		$prId++
		foreach($bitness in $bitnesses)
		{
			"Looking for $prod $bitness" | Trace -DebugOnly
			$qId = -1
			foreach($qualifiedCompID in $QualifiedComponents)
			{
				#GetProductCodePattern
#				$bitnessBit = "0"
#				$qId++
#				if($bitness -eq "x64"){$bitnessBit = "1"}
#				$productCodePatterns = $productCodeId[$prId] | %{$productCodePattern[$qId] -f $_,$bitnessBit}
#				if($productCodePatterns -isnot [System.Array])
#				{
#					$productCodePatterns = ,$productCodePatterns
#				}
				
				
				
				if($prod -eq "spdesign")
				{
					$qualifier = "SPD";
				}
				elseif($prod -eq "outlook")
				{
	              	$qualifier = `
						"{0}{1}.exe" -f $prod,(IIF ($bitness -eq "x64") ".x64" ([string]::Empty))
				}
				else{
					$qualifier = "$($prod).exe"
				}
			 	"Calling GetOfficeAppVersion with $qualifiedCompID,$qualifier" | Trace -DebugOnly
				$productFound = $false
				$prodInfo = [MsiMethods]::GetOfficeAppVersion($qualifiedCompID,$qualifier)
				if($prodInfo -ne $null)
				{
					[PEHeaders.PEHeaderReader] $peHeader = New-Object PEHeaders.PEHeaderReader("$($prodInfo[1])")
					$productFound = ($peHeader.Is32BitHeader -eq ($bitness -eq "x86"))
				}
				if($productFound)
				{
					"Product found." | Trace -DebugOnly 
					$prodHT = @{ExeName = $prod; Version=$prodInfo[0];InstallPath=$prodInfo[1];Bitness=$bitness}
					
					#Bitness can't be trusted for spdesign because it has the same qualifier for both bitnesses
					if($prod -eq "spdesign")
					{
						[PEHeaders.PEHeaderReader] $peHeader = New-Object PEHeaders.PEHeaderReader($prodHT.InstallPath)
						$spdIs32Bit = $peHeader.Is32BitHeader
						if($bitness -ne (IIF $spdIs32Bit "x86" "x64"))
						{
							continue; #false positive
						}
							
					}
					
					$products += ,$prodHT
				}
			}
		}
	}
#	if((Get-Command -Verb "Get" -noun "AdditionalProductsInstalled" -ErrorAction SilentlyContinue) -ne $null)
#	{
#		$additionalProducts = Get-AdditionalProductsInstalled
#		if(($additionalProducts -ne $null) -and ($additionalProducts.Count -gt 0))	{$products += $additionalProducts}
#	}
	
	for($i=0;$i -lt $products.Length;$i++)
	{
		"Adding data to $i = $($products[$i].ExeName)" | Trace -DebugOnly
		$additionalInfo = $global:OfficeProducts | Where-Object {($_.ProcName -ieq ($products[$i].ExeName + ".exe")) -and ($_.VersionsSupported -contains [int]($products[$i].Version.Split(".")[0]))} 
		if($additionalInfo -ne $null){	$products[$i] += $additionalInfo }
		

	}

	$global:AllOfficeProducts = @()
	for($i=0;$i -lt $products.Length;$i++)
	{
		if($products[$i].ProcName -eq $null){continue}
		$thisProduct =New-Object PSObject
		foreach($key in $products[$i].Keys)
		{
			$thisProduct | Add-Member -MemberType NoteProperty -Name $key -Value ($products[$i][$key])
		}
		$thisProduct | Add-Member -MemberType ScriptProperty -Name "MajorVersion" -Value {return [int]($this.Version.Split(".")[0]);}
		$thisProduct | Add-Member -MemberType ScriptProperty -Name "Is64Bit" -Value {return ($this."Bitness" -eq "x64");}
		$thisProduct | Add-Member -MemberType ScriptProperty -Name "DisplayVersion" -Value {
			if($this.Version -eq $null) {return $null}
			switch($this.MajorVersion)
			{
				9{return "2000"}
				10{return "XP"}
				11{return "2003"}
				12{return "2007"}
				14{return "2010"}
				15{return "2013"}
				default{return "'{0}'" -f ($this.Version.Split(".")[0]);}
			}
		}
		if((Get-Command -Verb "Is" -noun "ClickToRun" -ErrorAction SilentlyContinue) -ne $null)
		{
			$thisProduct | Add-Member -MemberType NoteProperty -Name "ClickToRun" -Value (Is-ClickToRun $thisProduct)
		}
		else
		{
			$thisProduct | Add-Member -MemberType NoteProperty -Name "ClickToRun" -Value $false
		}
		$thisProduct | Add-Member -MemberType NoteProperty -Name Index -Value $i

		$global:AllOfficeProducts += $thisProduct
	}
	
	return $global:AllOfficeProducts
	
}

Function Is-64Bit
{
	param($Application="Outlook", [int]$MajorVersion)
	return (Get-OfficeProgramsInstalled | ?{
		(($_.ProcName -ieq $Application) -or
		($_.ExeName -ieq $Application) -or
		($_.Name -ieq $Application) -or
		($_.FriendlyName -ieq $Application)) -and 
		($_.VersionsSupported -contains $MajorVersion)} | 
		Select -first 1 -ErrorAction SilentlyContinue)."Bitness" -eq "x64"
}
function Is-ClickToRun
{
	PARAM($prod)
	
	$c2rPath = 'REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\15.0\ClickToRun\ProductReleaseIDs\Active\*\x-none';
	if(($prod.MajorVersion -ge 15) -and ($true -eq (Test-Path $c2rPath -ErrorAction SilentlyContinue)))
	{
		$regNameMapToExeName = @{"Access"="msaccess";"PowerPoint"="powerpnt";"Project"="winproj";"Publisher"="mspub";"SharePointDesigner"="spdesign";"Word"="winword"};
		$c2rProducts = Get-ChildItem $c2rPath -Recurse -ErrorAction SilentlyContinue
		foreach($c2rProduct in $c2rProducts )
		{
			$offAppNameFromReg = $c2rProduct.PSChildName.Split('.')[0]
			if($regNameMapToExeName.ContainsKey($offAppNameFromReg))
			{
				$exeName = $regNameMapToExeName[$offAppNameFromReg];
			}
			else
			{
				$exeName = $offAppNameFromReg;
			}
			if($exeName -eq $prod.ExeName){return $true}
		}
		return $false
	}
	else{
		return $false
	}
}
function Get-PSVersion{
    if(test-path variable:psversiontable){$PSVersionTable.PSVersion}else{New-Object System.Version(1,0,0,0)}
}
function Is-PSv1{
	$psVer = Get-PSVersion
	#"Host Info: $($Host | FL * | Out-String)" | Trace -DebugOnly
	return ($psVer.Major -lt 2)

}
function Start-OfficeApp
{
	param($ProcName,[switch]$IgnoreCached)
	if($IgnoreCached -or (-not $global:CachedSkipApp.Contains($ProcName)))
	{
    	$result = get-diaginput -Id "StartupApp" -Parameter @{"appName"=$ProcName}
		if($result -eq "Skip")
		{
			$global:CachedSkipApp.Add($ProcName)
		}
	}
	else
	{
		$result = "Skip"
	}
	return $result
}
Function Close-OfficeApp
{
	param([string]$officeProcName,[int]$timeToClose)
	"--> Entered Close-OfficeApp with $officeProcName and $timeToClose" | Trace
	$Error.Clear() > $null
	trap [Exception] {
		$errorMessage = $Error[0].Exception.Message
		"Error running Close-OfficeApp: $errorMessage" | Trace -IsError
		$Error[0].InvocationInfo | fl | out-string | Trace -IsError
		$Error.Clear()
		continue
	}
	
	$offProcess = Get-Process $officeProcName -ErrorAction SilentlyContinue 
	if($offProcess -ne $null){
		$offAppClosed = $false
		while((-not $offAppClosed) -and ($timeToClose -ge 0))
		{
			Write-DiagProgress -Activity ($LocalsOfficeCommon.ID_OfficeAppStillOpen.Replace("`$offApp",$officeProcName)) -Status ($LocalsOfficeCommon.ID_ClosingOfficeAppCountdown.Replace("`$offApp",$officeProcName).Replace("`$timeToClose",$timeToClose))
			$offAppClosed = $offProcess.WaitForExit(1000)
			$timeToClose -= 1
		}
		$timesThrough = 0
		while((-not $offAppClosed) -and ($offProcess -ne $null) -and ($timesThrough -lt 10))
		{
			$offProcess = $null
			$offProcess = Get-Process $officeProcName -ErrorAction SilentlyContinue 
			if($offProcess -ne $null)
			{
				$offProcess.CloseMainWindow() | Out-Null
				$offAppClosed = $offProcess.WaitForExit(5000)
				if(-not $offAppClosed)
				{
					"Killing $officeProcName" | Trace 
					$offProcess | Stop-Process -ErrorAction SilentlyContinue 
				}
			}
			$timesThrough += 1
		}
		$offProcess = Get-Process $officeProcName -ErrorAction SilentlyContinue
		if($offProcess -ne $null)
		{
			"Killing $officeProcName" | Trace 
			$offProcess | Stop-Process -ErrorAction SilentlyContinue 
			$offProcess.WaitForExit(5000) > $null
		}
	}
	"Exit Close-OfficeApp" | Trace
}
Function Get-AdditionalFoldersToChkSym
{
}
Function Get-MSOPath
{
	$offVersion = $global:SelectedOfficeExe.MajorVersion
	$offBitness = $global:SelectedOfficeExe.Bitness
	$filesPathsKey = "HKLM:\Software\Microsoft\Office\$($offVersion).0\Common\FilesPaths"
	if(($offBitness -eq "x86") -and ($env:PROCESSOR_ARCHITECTURE -ne "x86")){
		$filesPathsKey = "HKLM:\Software\Wow6432Node\Microsoft\Office\$($offVersion).0\Common\FilesPaths"
	}
	$msoPath = Get-ItemProperty $filesPathsKey -Name "mso.dll" -ErrorAction SilentlyContinue 
	if($null -ne $msoPath)
	{
		return $msoPath.PSObject.Properties["mso.dll"].Value
	}
	else
	{
		if(($offVersion -ge 15) -and ($global:SelectedOfficeExe.ClickToRun -eq $true))
		{
			$packageFolder = (Get-ItemProperty "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\$($offVersion).0\ClickToRun").PackageFolder
			return Join-Path $packageFolder "root\vfs\ProgramFilesCommonX86\Microsoft Shared\OFFICE$($offVersion)\mso.dll"
		}
	}
}
function Ensure-EWSFolders
{
	if(-not (Test-Path "$PWD\x86\Microsoft.Exchange.WebServices.dll"))
	{
		New-Item -ItemType Directory -Path "$PWD" -Name "x86" -ErrorAction SilentlyContinue
		Copy-Item "$PWD\Microsoft.Exchange.WebServices32.dll" -Destination "$PWD\x86\" -ErrorAction SilentlyContinue
		Rename-Item -Path "$PWD\x86\Microsoft.Exchange.WebServices32.dll" -NewName "Microsoft.Exchange.WebServices.dll" -ErrorAction SilentlyContinue

		New-Item -ItemType Directory -Path "$PWD" -Name "x64" -ErrorAction SilentlyContinue
		Copy-Item "$PWD\Microsoft.Exchange.WebServices64.dll" -Destination "$PWD\x64\" -ErrorAction SilentlyContinue
		Rename-Item -Path "$PWD\x64\Microsoft.Exchange.WebServices64.dll" -NewName "Microsoft.Exchange.WebServices.dll" -ErrorAction SilentlyContinue
	}
}
function Get-DisableBootToOfficeStart
{
	PARAM($prod = "$($global:SelectedOfficeExe.RegName)")
	$policyOptionsKey = "REGISTRY::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\15.0\$prod\Options"
	$optionsKey = "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\$prod\Options"
	if($prod -eq "Visio")
	{	
		$policyOptionsKey = "REGISTRY::HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\15.0\$prod\Application"
		$optionsKey = "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\$prod\Application"
	}
	$valueName = "DisableBootToOfficeStart"

	if(($true -eq (Test-Path $policyOptionsKey -erroraction SilentlyContinue)) -and ($null -ne (Get-itemProperty $policyOptionsKey -Name $valueName -ErrorAction SilentlyContinue )))
	{
		$keyToUse=$policyOptionsKey
		$nameToUse = "$valueName (Policies)"
	}
	elseif(($true -eq (Test-Path $optionsKey -ErrorAction SilentlyContinue )) -and ($null -ne (Get-itemProperty $optionsKey -Name $valueName -ErrorAction SilentlyContinue)))
	{
		$keyToUse = $optionsKey
		$nameToUse = "$valueName"
	}
	else
	{
		return @{ "$valueName" = "(not found)"}
	}
	$disableBootToOfficeStartValue = (GP $keyToUse).$valueName
	$valueToWrite = "(not found)"
	switch($disableBootToOfficeStartValue)
	{
		0{$valueToWrite = "0 (default) - User will be shown start screen when launching $prod";break;}
		1{$valueToWrite = "1 (not default) - User will not be shown start screen when launching $prod";break;}
	}
	return @{"$nameToUse" = $valueToWrite}

}
function Get-SelectedAppConfiguration
{
	if($null -ne $global:SelectedOfficeExe)
	{
		return $global:SelectedOfficeExe | 
			Select Bitness,ClickToRun,@{Name="Install Path";Expression={$_.InstallPath}} | 
			Add-Member NoteProperty "$($global:SelectedOfficeExe.ProcName) Version" $global:SelectedOfficeExe.Version -PassThru 
	}
}

#This function will wait for the ROIScan background process to complete
function Wait-ROIScan{
	"Current running diag background processes:`r`n $($DiagProcesses | ?{$_.HasExited -eq $false} | FL | Out-String)" | WriteTo-StdOut -ShortFormat 
	"Waiting..." | Trace
	if(Is-PSv1)
	{
		"Calling WaitForBackgroundProcesses 0" | WriteTo-StdOut -ShortFormat 
		
		WaitForBackgroundProcesses 0
	}
	else
	{
		"WaitForExit() called"  | WriteTo-StdOut -ShortFormat 
		$DiagProcesses | ?{$_.StartInfo.Arguments -like "*Roiscan.vbs*"} | %{ $_.WaitForExit() }
	}
	"Done Waiting" | Trace

}

#This function can be used to check if a patch (KB)is installed in the user machine for a specific office version 
# For Example IsPatchInstalled "14" "2687508" will check for patch 2687508 installed for office 14 
Function IsPatchInstalled([string]$productVersion, [string]$KB)
{
	if($global:RoiScanXml -eq $null)
	{
    	. .\DC_ROISCAN.ps1
    	Wait-ROIScan
    	Start-Sleep -Seconds 2
	}


	
	$ROIScanKBSearch = $global:RoiScanXml.OFFICEINVENTORY.SelectNodes("SKU[starts-with(@ProductVersion,$productVersion)]/PatchData/Patch") |? {($_.KB -eq  $KB) -and (($_.State -eq "Applied") -or (($_.State -eq "SuperSeded")))}      

	if($null -ne $ROIScanKBSearch)
	{
  		return $true
	}
	else
	{
 		return $false
	}
}

#This function will return a list of all the SKUs in side loaded scneario from ROIScan.xml. It returns $null if sxs not detected

function GetSxSProducts

{
    if($null -eq $global:RoiScanXml)
	{
    	Wait-ROIScan
    	Start-Sleep -Seconds 2
		
		if($null -eq $global:RoiScanXml)
		{
			. .\DC_ROISCAN.ps1
			Wait-ROIScan
    		Start-Sleep -Seconds 2
		}
	} 

	$OfficeExes =  	"MSACCESS.EXE", `
					"EXCEL.EXE", `
					"SPDESIGN.EXE", `
					"GROOVE.EXE", `
					"LYNC.EXE", `
					"ONENOTE.EXE", `
					"OUTLOOK.EXE", `
					"POWERPNT.EXE", `
					"WINPROJ.EXE", `
					"MSPUB.EXE", `
					"INFOPATH.EXE", `
					"VISIO.EXE", `
					"WINWORD.EXE"


	
	
	$Script:InstalledSKUS =@()
	$Script:MultipleVersionsDetected = $false

	$OfficeExes | % {
                  		$OfficeExe = $_  
				  		$CurrentKeyComponentData = ($global:RoiScanXml.OFFICEINVENTORY.SelectNodes("SKU/KeyComponents/Application[@ExeName = '$OfficeExe' ]")) 
				  		if ( $CurrentKeyComponentData.Count -gt 1 ) 
				  		{
				     			$Script:MultipleVersionsDetected = $true 
				 		}
				  
				  		$Script:InstalledSKUS += ($CurrentKeyComponentData | %{
				  																if( $_.ParentNode.ParentNode.InstallType -eq "C2R")
																				{
				  														     		$_.ParentNode.ParentNode.ProductName + "(Click to Run)"
																				}																			
																				else
																				{
																			 		$_.ParentNode.ParentNode.ProductName
																				}
																			
				    														 }
												)		
					}
				
                 
			
	if ($Script:MultipleVersionsDetected -eq $true )  
	{
	
			return ($Script:InstalledSKUS | select -Unique) 
    } 
	else
	{
			return $null 
	}
}			

#Check if RDS Role/ Terminal Services app mode is installed
function IsRDSEnabled
{
	$RDSEnabled = $false

	"Detecting Server OS" | Trace -DebugOnly
	if ((Get-CimInstance -Class Win32_OperatingSystem -Property ProductType).ProductType -ne 1) #Server
	{
		if (($OSVersion.Major -eq 5) -and ($OSVersion.Minor -eq 2))
		{
			"Legacy Server OS detected" | Trace -DebugOnly
			$NameSpace = 'root\CIMV2'
		}
		else
		{
			"Modern Server OS detected" | Trace -DebugOnly
			$NameSpace = 'root\CIMV2\TerminalServices'
}			

		$TSSetting = (Get-CimInstance -Class Win32_TerminalServiceSetting  -Namespace $NameSpace -ErrorAction SilentlyContinue).TerminalServerMode

		if (($TSSetting -ne $null) -and ($TSSetting -eq 1))
		{
			$RDSEnabled = $true
		}
	}
	"Returning $RDSEnabled" | Trace -DebugOnly
	return $RDSEnabled
}

#region Config Data
Function Ensure-ConfigObject
{
	param([switch]$Reset)
	
	if(($Reset) -or ($global:ConfigData -eq $null))
	{
		"Creating Configuration Object" | Trace -DebugOnly 
		$global:ConfigData = New-Object PSObject
		$global:ConfigData | Add-Member -MemberType NoteProperty -Name "ConfigPropertyOrders" -Value @{}
		$global:ConfigData | Add-Member -MemberType NoteProperty -Name "ConfigPublishOrder" -Value (New-Object System.Collections.ArrayList)
		$global:ConfigData | Add-Member -MemberType NoteProperty -Name "ConfigDataSets" -Value @{}
		$global:ConfigData | Add-Member -MemberType ScriptMethod -name "ContainsConfig" -Value {
			param([string]$configName)
			if(Is-PSv1)
			{
				$configName = $args[0];
			}
			return $this.ConfigDataSets.ContainsKey($configName)
		}
		$global:ConfigData | Add-Member -MemberType ScriptMethod -Name "GetConfig" -Value {
			param([string]$configName)
			if(Is-PSv1)
			{
				$configName = $args[0];
			}
			if(-not $this.ContainsConfig($configName))
			{
				[Void]$this.ConfigDataSets.Add($configName , (New-Object PSObject))
				[Void]$this.ConfigPropertyOrders.Add($configName , @())
			}
			return $this.ConfigDataSets[$configName]
		}
		$global:ConfigData | Add-Member -MemberType NoteProperty -Name "PublishList" -Value @{}
		$global:ConfigData | Add-Member -MemberType ScriptMethod -Name "PublishConfig" -Value {
			param([string]$configName,[Hashtable]$configProperties)
			if(Is-PSv1)
			{
				$configName = $args[0];
				$configProperties = $args[1];
			}
			if($this.PublishList.ContainsKey($configName))
			{
				$this.PublishList[$configName] = $configProperties;
			}
			else
			{
				$this.PublishList.Add($configName,$configProperties);
				$this.ConfigPublishOrder.Add($configName);
			}
		}
		$global:ConfigData | Add-Member -MemberType ScriptMethod -Name "UnpublishConfig" -Value {
			param([string]$configName)
			if(Is-PSv1)
			{
				$configName = $args[0];
			}
			if($this.PublishList.ContainsKey($configName))
			{
				$this.PublishList.Remove($configName);
				$this.ConfigPublishOrder.Remove($configName)
			}
		}		
	}
}
$m_mostRecentConfigName = "Configuration Summary"
Function Set-ConfigurationData
{
	param([string]$configName=$script:m_mostRecentConfigName,[string]$settingName=(throw "No setting name defined"),$settingValue)
	
	Ensure-ConfigObject
	
	$configurationData = $global:ConfigData.GetConfig($configName)
	
	if((Get-Member -InputObject $configurationData -Name $settingName -ErrorAction SilentlyContinue) -eq $null)
	{
		"Adding $settingName to $configName to $($settingValue | Out-String)" | Trace
		$configurationData | Add-member -MemberType NoteProperty -Name $settingName -Value $settingValue
		$global:ConfigData.ConfigPropertyOrders[$configName] += $settingName
	}
	else
	{
		"Setting $settingName on $configName to $($settingValue | Out-String)" | Trace
		$configurationData.$settingName = $settingValue
	}
	
	if($script:m_mostRecentConfigName -ne $configName)
	{
		$script:m_mostRecentConfigName = $configName
	}
}
Function Merge-ConfigurationValues
{
	param([string]$configName=$script:m_mostRecentConfigName,[HashTable]$HashTable,[PSObject]$Object,[array]$propOrderedList)
	
	if($propOrderedList -eq $null)
	{
		if($HashTable -ne $null)
		{
			$propOrderedList = [array]($HashTable.Keys);
			[array]::Sort($propOrderedList);
		}
		else
		{
			$propOrderedList = [array]($Object | Get-Member -MemberType NoteProperty -ErrorAction SilentlyContinue | Sort Name | %{$_.Name})
		}
	}
	
	$myObj = $Object
	if($HashTable -ne $null)
	{
		$myObj = $HashTable
	}

	foreach($keyName in $propOrderedList)
	{
		Set-ConfigurationData $configName $keyName ($myObj.$keyName)
	}

}
Function Get-ConfigurationValue
{
	param([string]$configName=$script:m_mostRecentConfigName,[string]$settingName=(throw "No setting name defined"))

	Ensure-ConfigObject
	$configurationData = $global:ConfigData.GetConfig($configName)
	
	if($script:m_mostRecentConfigName -ne $configName)
	{
		$script:m_mostRecentConfigName = $configName
	}
	
	return $configurationData.$settingName
	
}
Function Get-Configuration
{
	param([string]$configName=$script:m_mostRecentConfigName,[switch]$AsXml,[switch]$AsText)
	if($script:m_mostRecentConfigName -ne $configName)
	{
		$script:m_mostRecentConfigName = $configName
	}
	Ensure-ConfigObject
	$configurationData = $global:ConfigData.GetConfig($configName)
	if($AsXml)
	{
		"Getting Configuration Data as Xml" | Trace -DebugOnly 
		return ($configurationData | Select-Object -Property ($global:ConfigData.ConfigPropertyOrders[$configName]) | ConvertTo-Xml2 )
	}
	elseif($AsText)
	{
		"Getting Configuration Data as Text" | Trace -DebugOnly 
		return ($configName + "`r`n" + ("="*($configName.Length)) + ($configurationData | Select-Object -Property ($global:ConfigData.ConfigPropertyOrders[$configName]) | FL * | Out-String -Width 150))
	}
	else
	{	
		"Getting Configuration Data" | Trace -DebugOnly 
		return $configurationData
	}
}


Function Publish-Configuration {
# .SYNOPSIS
# Marks a configuration object for publication
# .PARAMETER configName
#	The name of the configuration to publish
# .PARAMETER Properties
#	Description [string] - used in Update-DiagReport
#	ReportPath [string] - path and filename of txt file to generate and collect.
#	ReportHeader [string] - added above the report dump (Requires ReportPath)
#	ReportFooter [string] - added beneath the report in txt file (requires ReportPath)
#	FileDescription [string] - used in CollectFiles (requires ReportPath)
#	SectionDescription [string] - used in CollectFiles (requires ReportPath)
#	DelayCollection [bool] - if set to true, will delay collection of the report file until all configs have been published. If false or missing, file is collected immediately.
# .PARAMETER Unpublish
#	Specify this parameter if you wish to remove the publication.

	param(
	[string]$configName=$script:m_mostRecentConfigName,
	[hashtable]$Properties,
	[switch]$Unpublish,
	[string]$Description, #  - used in Update-DiagReport
	[string]$ReportPath, #  - path and filename of txt file to generate and collect.
	[string]$ReportHeader , # - added above the report dump (Requires ReportPath)
	[string]$ReportFooter , # - added beneath the report in txt file (requires ReportPath)
	[string]$FileDescription , # - used in CollectFiles (requires ReportPath)
	[string]$SectionDescription , # - used in CollectFiles (requires ReportPath)
	[bool]$DelayCollection=$true  # - if set to true, will delay collection of the report file until all configs have been published. If false or missing, file is collected immediately.
)
	
	if($script:m_mostRecentConfigName -ne $configName)
	{
		$script:m_mostRecentConfigName = $configName
	}
	
	Ensure-ConfigObject 
	if($Properties -eq $null)
	{
		$Properties = @{
			Description=$Description; 
			ReportPath=$ReportPath; 
			ReportHeader=$ReportHeader; 
			ReportFooter=$ReportFooter;
			FileDescription=$FileDescription; 
			SectionDescription=$SectionDescription;
			DelayCollection=$DelayCollection}
	}
	if($Unpublish)
	{
		$global:ConfigData.UnpublishConfig($configName);
	}
	else
	{
		$global:ConfigData.PublishConfig($configName,$Properties);
	}
}

Function Do-ConfigCollection
{
	$delayedReports = @()
	foreach($configName in $global:ConfigData.ConfigPublishOrder)
	{
		if([string]::IsNullOrEmpty("$configName") ){continue}
		if($global:ConfigData.PublishList -eq $null){Continue}
		if(-not ($global:ConfigData.PublishList.ContainsKey($configName))){continue}
		"Collecting $configName" | Trace
		$tpublishData = $global:ConfigData.PublishList["$configName"]
		"Got publication data: $($tpublishData | FL | Out-String)" | Trace
		$tconfigData = $global:ConfigData.GetConfig("$configName")
		
		Get-Configuration -AsXml -configName $configName | Update-DiagReport -Id "$($configName)_Data" -Name $configName -Description ($tpublishData["Description"])
		
		if($tpublishData.ContainsKey("ReportPath"))
		{
			if($tpublishData.ContainsKey("ReportHeader")){$tpublishData["ReportHeader"] | Out-File -FilePath ($tpublishData["ReportPath"]) -Append }
			Get-Configuration -AsText -configName $configName | Out-File -FilePath ($tpublishData["ReportPath"]) -Append
			if($tpublishData.ContainsKey("ReportFooter")){$tpublishData["ReportFooter"] | Out-File -FilePath ($tpublishData["ReportPath"]) -Append }
			
			if($tpublishData.ContainsKey("DelayCollection") -and ($tpublishData["DelayCollection"] -eq $true))
			{
				if($null -eq ($delayedReports | ?{$_["ReportPath"] -eq $tpublishData["ReportPath"]}))
				{
					$delayedReports += $tpublishData
				}
			}
			else
			{
				CollectFiles -fileDescription ($tpublishData["FileDescription"]) -sectionDescription ($tpublishData["SectionDescription"]) -filesToCollect ($tpublishData["ReportPath"]) -noFileExtensionsOnDescription -renameOutput $true -Verbosity "Informational"
			}
		}
	}
	foreach($delayedReport in $delayedReports)
	{
		if(($delayedReport -ne $null) -and ($delayedReport -is [hashtable])){
			CollectFiles -fileDescription ($delayedReport["FileDescription"]) -sectionDescription ($delayedReport["SectionDescription"]) -filesToCollect ($delayedReport["ReportPath"]) -noFileExtensionsOnDescription -renameOutput $true -Verbosity "Informational"
		}
	}
}
#endregion

#region Outlook
########## Outlook #############
Function Get-DefaultProfileName
{
	param($OutlookMajorVersion)
	if($OutlookMajorVersion -le 14)
	{
		$profileName = Get-ItemProperty -Path "REGISTRY::HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles" -Name DefaultProfile -ErrorAction SilentlyContinue
	}
	elseif($OutlookMajorVersion -ge 15)
	{
		$profileName = Get-ItemProperty -Path "REGISTRY::HKCU\Software\Microsoft\Office\$($OutlookMajorVersion).0\Outlook" -Name DefaultProfile -ErrorAction SilentlyContinue
	}
	return $profileName.DefaultProfile
}
Function Get-MAPIProfilesKeyPath
{
	param($OutlookMajorVersion)

	if($OutlookMajorVersion -ge 15)
	{
		return "REGISTRY::HKCU\Software\Microsoft\Office\$($OutlookMajorVersion).0\Outlook\Profiles"
	}
	else
	{
		return "REGISTRY::HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles"
	}
}
Function Get-OffCatResultsPath
{
	if($global:OffCatResultsPath -eq $null)
	{
		$global:OffCatResultsPath = "$env:appdata\Microsoft\Offcat\$($ComputerName)_OffCAT_Results_$([Guid]::NewGuid().ToString('N').Substring(0,8)).xml"
	}
	return $global:OffCatResultsPath
}
Function Ensure-OffCATResults
{
	"Ensuring OffCAT results." | Trace
    if($global:OffcatResultsXml -eq $null)
    {
	  $offcatResultFilePath = Get-OffCatResultsPath
      if([io.File]::Exists($offcatResultFilePath) -and ([IO.File]::GetLastWriteTime($offcatResultFilePath) -gt [DateTime]::Now.AddMinutes(-30)))
      {
	  	"OffCAT Results found. Creating global variable." | Trace
        New-Variable -Name OffcatResultsXml -Scope Global -Value ([xml](GC $offcatResultFilePath))
      }
      else
      {
	  	"No OffCAT results found - running again." | Trace
        Run-DiagExpression .\DC_OffCAT.ps1
      }
    }
	
	if($null -eq $global:OcatRulesDetected)
	{
		if($null -ne $global:OffcatResultsXml)
		{
			"Creating global:OCatRulesDetected" | Trace
			#Leave as OCATRulesDetected for back-compat
			New-variable -Scope Global -name OcatRulesDetected -Value ($OffcatResultsXml.ObjectCollector.SelectNodes("//Rule[@SSID and @Pass='True']"))
		}
	}
}
Function Get-OffCATResultsXml
{
	Ensure-OffCATResults
	return $global:OffcatResultsXml
}
function Get-OffCATRuleExists
{
	param($SSID)
	$offCatXml = Get-OffCATResultsXml
	$ruleExists = $false
	if(($null -ne $offCatXml) -and ($null -ne $offCatXml.ObjectCollector))
	{
		$ruleExists = ($null -ne ($offCatXml.ObjectCollector.SelectSingleNode("//Rule[@SSID='$SSID']")))
	}
	"Get-OffCATRuleExists returning $ruleExists" | Trace
	return $ruleExists
}
Function Get-OffCATRuleFired
{
	param($SSID)
	if(-not ($global:FirstTimeExecution)){"[Get-OffCATRuleFired] Second execution. Returning false" | Trace; return $false}
	Ensure-OffCATResults
	"Get-OffCatRuleFired returning $($null -ne ($global:OcatRulesDetected | ?{$_.SSID -ieq $SSID}))" | Trace
	return ($null -ne ($global:OcatRulesDetected | ?{$_.SSID -ieq $SSID}))

}
Set-Alias Get-OCATRuleFired Get-OffCATRuleFired

Function New-OffCATReport
{
	param([string]$xpath = ".", [string]$XslPath, [string]$ReportFileName)
	
	if($null -eq $XslPath)
	{
		return
	}
	
	if($null -eq $ReportFileName)
	{
		$ReportFileName = "$($ComputerName)_OffCat_Report.html"
	}
	
	$offCatXml = Get-OffCATResultsXml
	
	if($null -ne $offCatXml)
	{
		Transform-XmlDoc ($offCatXml.SelectSingleNode($xpath)) $XslPath $ReportFileName
	}
	
}
########## End Outlook #########
#endregion

#region PE Code
$peCode = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.IO;

namespace PEHeaders {

  // Reads in the header information of the Portable Executable format.
  // Provides information such as the date the assembly was compiled.
  public class PeHeaderReader {
    #region File Header Structures

    public struct IMAGE_DOS_HEADER {      // DOS .EXE header
      public UInt16 e_magic;              // Magic number
      public UInt16 e_cblp;               // Bytes on last page of file
      public UInt16 e_cp;                 // Pages in file
      public UInt16 e_crlc;               // Relocations
      public UInt16 e_cparhdr;            // Size of header in paragraphs
      public UInt16 e_minalloc;           // Minimum extra paragraphs needed
      public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
      public UInt16 e_ss;                 // Initial (relative) SS value
      public UInt16 e_sp;                 // Initial SP value
      public UInt16 e_csum;               // Checksum
      public UInt16 e_ip;                 // Initial IP value
      public UInt16 e_cs;                 // Initial (relative) CS value
      public UInt16 e_lfarlc;             // File address of relocation table
      public UInt16 e_ovno;               // Overlay number
      public UInt16 e_res_0;              // Reserved words
      public UInt16 e_res_1;              // Reserved words
      public UInt16 e_res_2;              // Reserved words
      public UInt16 e_res_3;              // Reserved words
      public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
      public UInt16 e_oeminfo;            // OEM information; e_oemid specific
      public UInt16 e_res2_0;             // Reserved words
      public UInt16 e_res2_1;             // Reserved words
      public UInt16 e_res2_2;             // Reserved words
      public UInt16 e_res2_3;             // Reserved words
      public UInt16 e_res2_4;             // Reserved words
      public UInt16 e_res2_5;             // Reserved words
      public UInt16 e_res2_6;             // Reserved words
      public UInt16 e_res2_7;             // Reserved words
      public UInt16 e_res2_8;             // Reserved words
      public UInt16 e_res2_9;             // Reserved words
      public UInt32 e_lfanew;             // File address of new exe header
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER32 {
      public UInt16 Magic;
      public Byte MajorLinkerVersion;
      public Byte MinorLinkerVersion;
      public UInt32 SizeOfCode;
      public UInt32 SizeOfInitializedData;
      public UInt32 SizeOfUninitializedData;
      public UInt32 AddressOfEntryPoint;
      public UInt32 BaseOfCode;
      public UInt32 BaseOfData;
      public UInt32 ImageBase;
      public UInt32 SectionAlignment;
      public UInt32 FileAlignment;
      public UInt16 MajorOperatingSystemVersion;
      public UInt16 MinorOperatingSystemVersion;
      public UInt16 MajorImageVersion;
      public UInt16 MinorImageVersion;
      public UInt16 MajorSubsystemVersion;
      public UInt16 MinorSubsystemVersion;
      public UInt32 Win32VersionValue;
      public UInt32 SizeOfImage;
      public UInt32 SizeOfHeaders;
      public UInt32 CheckSum;
      public UInt16 Subsystem;
      public UInt16 DllCharacteristics;
      public UInt32 SizeOfStackReserve;
      public UInt32 SizeOfStackCommit;
      public UInt32 SizeOfHeapReserve;
      public UInt32 SizeOfHeapCommit;
      public UInt32 LoaderFlags;
      public UInt32 NumberOfRvaAndSizes;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER64 {
      public UInt16 Magic;
      public Byte MajorLinkerVersion;
      public Byte MinorLinkerVersion;
      public UInt32 SizeOfCode;
      public UInt32 SizeOfInitializedData;
      public UInt32 SizeOfUninitializedData;
      public UInt32 AddressOfEntryPoint;
      public UInt32 BaseOfCode;
      public UInt64 ImageBase;
      public UInt32 SectionAlignment;
      public UInt32 FileAlignment;
      public UInt16 MajorOperatingSystemVersion;
      public UInt16 MinorOperatingSystemVersion;
      public UInt16 MajorImageVersion;
      public UInt16 MinorImageVersion;
      public UInt16 MajorSubsystemVersion;
      public UInt16 MinorSubsystemVersion;
      public UInt32 Win32VersionValue;
      public UInt32 SizeOfImage;
      public UInt32 SizeOfHeaders;
      public UInt32 CheckSum;
      public UInt16 Subsystem;
      public UInt16 DllCharacteristics;
      public UInt64 SizeOfStackReserve;
      public UInt64 SizeOfStackCommit;
      public UInt64 SizeOfHeapReserve;
      public UInt64 SizeOfHeapCommit;
      public UInt32 LoaderFlags;
      public UInt32 NumberOfRvaAndSizes;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_FILE_HEADER {
      public UInt16 Machine;
      public UInt16 NumberOfSections;
      public UInt32 TimeDateStamp;
      public UInt32 PointerToSymbolTable;
      public UInt32 NumberOfSymbols;
      public UInt16 SizeOfOptionalHeader;
      public UInt16 Characteristics;
    }

    #endregion File Header Structures

    #region Private Fields

    // The DOS header
    private IMAGE_DOS_HEADER dosHeader;
    // The file header
    private IMAGE_FILE_HEADER fileHeader;
    // Optional 32 bit file header
    private IMAGE_OPTIONAL_HEADER32 optionalHeader32;
    // Optional 64 bit file header
    private IMAGE_OPTIONAL_HEADER64 optionalHeader64;

    #endregion Private Fields

    #region Public Methods

    public PeHeaderReader(string filePath) {
      // Read in the DLL or EXE and get the timestamp
      using (FileStream stream = new FileStream(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read)) {
        BinaryReader reader = new BinaryReader(stream);
        dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

        // Add 4 bytes to the offset
        stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

        UInt32 ntHeadersSignature = reader.ReadUInt32();
        fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
        if (this.Is32BitHeader) {
          optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
        }
        else {
          optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
        }
      }
    }

    // Gets the header of the .NET assembly that called this function
    public static PeHeaderReader GetCallingAssemblyHeader() {
      string pathCallingAssembly = System.Reflection.Assembly.GetCallingAssembly().Location;

      // Get the path to the calling assembly, which is the path to the
      // DLL or EXE that we want the time of
      string filePath = System.Reflection.Assembly.GetCallingAssembly().Location;

      // Get and return the timestamp
      return new PeHeaderReader(filePath);
    }

    // Reads in a block from a file and converts it to the struct
    // type specified by the template parameter
    public static T FromBinaryReader<T>(BinaryReader reader) {
      // Read in a byte array
      byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

      // Pin the managed memory while, copy it out the data, then unpin it
      GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
      T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
      handle.Free();

      return theStructure;
    }

    #endregion Public Methods

    #region Properties

    // Gets if the file header is 32 bit or not
    public bool Is32BitHeader {
      get {
        UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
        return (IMAGE_FILE_32BIT_MACHINE & FileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
      }
    }

    // Gets the file header
    public IMAGE_FILE_HEADER FileHeader {
      get {
        return fileHeader;
      }
    }

    // Gets the optional header
    public IMAGE_OPTIONAL_HEADER32 OptionalHeader32 {
      get {
        return optionalHeader32;
      }
    }

    // Gets the optional header
    public IMAGE_OPTIONAL_HEADER64 OptionalHeader64 {
      get {
        return optionalHeader64;
      }
    }

    // Gets the timestamp from the file header
    public DateTime TimeStamp {
      get {
        // Timestamp is a date offset from 1970
        DateTime returnValue = new DateTime(1970, 1, 1, 0, 0, 0);

        // Add in the number of seconds since 1970/1/1
        returnValue = returnValue.AddSeconds(fileHeader.TimeDateStamp);
        // Adjust to local timezone
        returnValue += TimeZone.CurrentTimeZone.GetUtcOffset(returnValue);

        return returnValue;
      }
    }

    #endregion Properties
  }
}
'@

Add-Type -TypeDefinition $peCode
#endregion

#region Run tokens
Add-Type -TypeDefinition @"
	using System;
	public enum DiagRunFlags
	{
		LITE = 0x1,
		MEDIUM = 0x2,
		FULL = 0x8
	}
	public enum DiagMask
	{
		LITE = DiagRunFlags.LITE,
		MEDIUM = DiagRunFlags.MEDIUM | DiagRunFlags.LITE,
		FULL = DiagRunFlags.FULL | DiagRunFlags.MEDIUM | DiagRunFlags.LITE		
	}
"@
function Get-RunTokenObject
{
	return $global:g_runToken
}
function Run-DiagExpressionChecked
{
	$line = [string]::join(" ", $MyInvocation.Line.Trim().Split(" ")[1..($MyInvocation.Line.Trim().Split(" ").Count)])
	$runToken = Get-RunTokenObject
	$shouldRun = $true
	if($null -ne $runToken)
	{
		$shouldRun = ($runToken | %{$line -match $_}) -contains $true
	}
	if($shouldRun)
	{
		"Found token for $line" | Trace
		Invoke-Expression "Run-DiagExpression $line"
	}
	else
	{
		"No token found that matches '$line'. Skipping." | Trace
	}
}
function Add-RunToken
{
	PARAM([String[]]$Token)
	if($null -eq $global:g_runToken)
	{
		$global:g_runToken = New-Object System.Collections.ArrayList
	}
	$Token | %{
		if(-not $global:g_runToken.Contains($_))
		{
			$global:g_runToken.Add($_) | Out-Null 
		}
	}
}
#endregion

#region RunAsUser
$runasCode = @"
using System;
using System.Runtime.InteropServices;


    public class RunAsUser
    {

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle,
            UInt32 DesiredAccess, out IntPtr TokenHandle);

        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY = 0x0008;
        public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
        public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
        public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
        public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
        public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();


        public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
        public const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;
        public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;
        private const Int32 ANYSIZE_ARRAY = 1;

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }



        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }



        public struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = ANYSIZE_ARRAY)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        public const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool LookupPrivilegeValueW(string lpSystemName, string lpName,
            out LUID lpLuid);
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
           [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges,
           ref TOKEN_PRIVILEGES NewState,
           UInt32 BufferLengthInBytes,
           ref TOKEN_PRIVILEGES PreviousState,
           out UInt32 ReturnLengthInBytes);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);
        public const int ERROR_SUCCESS = 0;
        public const int ERROR_SUCCESS_REBOOT_INITIATED = 1641;
        public const int ERROR_SUCCESS_REBOOT_REQUIRED = 3010;
        public const int ERROR_SUCCESS_RESTART_REQUIRED = 3011;
        [DllImport("user32.dll")]
        public static extern IntPtr GetShellWindow();
        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        // When you don't want the ProcessId, use this overload and pass IntPtr.Zero for the second parameter
        [DllImport("user32.dll")]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, IntPtr ProcessId);
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);
			
        #region Enumerations
        public enum ProcessAccessTypes
        {
            PROCESS_TERMINATE = 0x00000001,
            PROCESS_CREATE_THREAD = 0x00000002,
            PROCESS_SET_SESSIONID = 0x00000004,
            PROCESS_VM_OPERATION = 0x00000008,
            PROCESS_VM_READ = 0x00000010,
            PROCESS_VM_WRITE = 0x00000020,
            PROCESS_DUP_HANDLE = 0x00000040,
            PROCESS_CREATE_PROCESS = 0x00000080,
            PROCESS_SET_QUOTA = 0x00000100,
            PROCESS_SET_INFORMATION = 0x00000200,
            PROCESS_QUERY_INFORMATION = 0x00000400,
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            SYNCHRONIZE = 0x00100000,
            PROCESS_ALL_ACCESS = PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION |
              PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | PROCESS_CREATE_PROCESS | PROCESS_SET_QUOTA |
              PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION | STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE
        }
        #endregion
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpTokenAttributes,
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            TOKEN_TYPE TokenType,
            out IntPtr phNewToken);
			
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }
        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }
        public enum LogonFlags
        {
            /// <summary>
            /// Log on, then load the user's profile in the HKEY_USERS registry key. The function
            /// returns after the profile has been loaded. Loading the profile can be time-consuming,
            /// so it is best to use this value only if you must access the information in the 
            /// HKEY_CURRENT_USER registry key. 
            /// NOTE: Windows Server 2003: The profile is unloaded after the new process has been
            /// terminated, regardless of whether it has created child processes.
            /// </summary>
            /// <remarks>See LOGON_WITH_PROFILE</remarks>
            WithProfile = 1,
            /// <summary>
            /// Log on, but use the specified credentials on the network only. The new process uses the
            /// same token as the caller, but the system creates a new logon session within LSA, and
            /// the process uses the specified credentials as the default credentials.
            /// This value can be used to create a process that uses a different set of credentials
            /// locally than it does remotely. This is useful in inter-domain scenarios where there is
            /// no trust relationship.
            /// The system does not validate the specified credentials. Therefore, the process can start,
            /// but it may not have access to network resources.
            /// </summary>
            /// <remarks>See LOGON_NETCREDENTIALS_ONLY</remarks>
            NetCredentialsOnly


        }



        public static bool RunAsDesktopUser(
   string szApp,
     string szCmdLine,
    string szCurrDir,
     STARTUPINFO si, out PROCESS_INFORMATION pi)
        {
            IntPtr hShellProcess = IntPtr.Zero, hShellProcessToken = IntPtr.Zero, hPrimaryToken = IntPtr.Zero;
            IntPtr hwnd = IntPtr.Zero;
            UInt32 dwPID = 0;
            bool ret;
            UInt32 dwLastErr;
            pi = new PROCESS_INFORMATION();
            // Enable SeIncreaseQuotaPrivilege in this process.  (This won't work if current process is not elevated.)
            IntPtr hProcessToken = IntPtr.Zero;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, out hProcessToken))
            {
                dwLastErr = (uint)Marshal.GetLastWin32Error();

                return false;
            }
            else
            {
                TOKEN_PRIVILEGES tkp = new TOKEN_PRIVILEGES();
                tkp.PrivilegeCount = 1;
                tkp.Privileges = new LUID_AND_ATTRIBUTES[1];
                LookupPrivilegeValueW(null, SE_INCREASE_QUOTA_NAME, out tkp.Privileges[0].Luid);
                tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                TOKEN_PRIVILEGES previoustkp = new TOKEN_PRIVILEGES();
                uint outBytes;
                AdjustTokenPrivileges(hProcessToken, false, ref tkp, 0, ref previoustkp, out outBytes);
                dwLastErr = (uint)Marshal.GetLastWin32Error();
                CloseHandle(hProcessToken);
                //if (ERROR_SUCCESS != dwLastErr)
                //{

                //    return false;
                //}
            }

            // Get an HWND representing the desktop shell.
            // CAVEATS:  This will fail if the shell is not running (crashed or terminated), or the default shell has been
            // replaced with a custom shell.  This also won't return what you probably want if Explorer has been terminated and
            // restarted elevated.
            hwnd = GetShellWindow();
            if (IntPtr.Zero == hwnd)
            {
                return false;
            }

            // Get the PID of the desktop shell process.
            GetWindowThreadProcessId(hwnd, out dwPID);
            if (0 == dwPID)
            {
                return false;
            }

            // Open the desktop shell process in order to query it (get the token)
            hShellProcess = OpenProcess((int)ProcessAccessTypes.PROCESS_QUERY_INFORMATION, false, dwPID);
            if (hShellProcess.ToInt32() == 0)
            {
                dwLastErr = (uint)Marshal.GetLastWin32Error();
                return false;
            }

            // From this point down, we have handles to close, so make sure to clean up.

            bool retval = false;
            // Get the process token of the desktop shell.
            ret = OpenProcessToken(hShellProcess, TOKEN_DUPLICATE, out hShellProcessToken);
            if (!ret)
            {
                dwLastErr = (uint)Marshal.GetLastWin32Error();
                //sErrorInfo << L"Can't get process token of desktop shell:  " << SysErrorMessageWithCode(dwLastErr);
                goto cleanup;
            }

            // Duplicate the shell's process token to get a primary token.
            // Based on experimentation, this is the minimal set of rights required for CreateProcessWithTokenW (contrary to current documentation).
            const UInt32 dwTokenRights = TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_IMPERSONATE;

            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
            ret = DuplicateTokenEx(hShellProcessToken, dwTokenRights, ref sa, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, out hPrimaryToken);
            if (!ret)
            {
                dwLastErr = (uint)Marshal.GetLastWin32Error();
                //sErrorInfo << L"Can't get primary token:  " << SysErrorMessageWithCode(dwLastErr);
                goto cleanup;
            }

            // Start the target process with the new token.
           ret = CreateProcessWithTokenW(
                hPrimaryToken,
                0,
                szApp,
                szCmdLine,
                0,
                IntPtr.Zero,
                szCurrDir,
                ref si,
                out pi);
            //SECURITY_ATTRIBUTES lpProcessAttributes = new SECURITY_ATTRIBUTES();
            //SECURITY_ATTRIBUTES lpThreadAttributes = new SECURITY_ATTRIBUTES();     
            //ret = CreateProcessAsUser(
            //    hPrimaryToken,
            //    szApp,
            //    szCmdLine,
            //    ref lpProcessAttributes,
            //    ref lpThreadAttributes,
            //    false,
            //    0,
            //    IntPtr.Zero,
            //    szCurrDir,
            //    ref si,
            //    out pi); 
            if (!ret)
            {
                dwLastErr = (uint)Marshal.GetLastWin32Error();
                //sErrorInfo << L"CreateProcessWithTokenW failed:  " << SysErrorMessageWithCode(dwLastErr);
                goto cleanup;
            }

            retval = true;

        cleanup:
            // Clean up resources
            CloseHandle(hShellProcessToken);
            CloseHandle(hPrimaryToken);
            CloseHandle(hShellProcess);
            return retval;
        }
		
 		public static void DoRunAs(string cmdLine)
        {
            RunAsUser.PROCESS_INFORMATION pi;
            RunAsUser.STARTUPINFO si = new RunAsUser.STARTUPINFO();
            si.dwFlags = 1;
            si.wShowWindow = 0;
            RunAsUser.RunAsDesktopUser(null, cmdLine, null, si, out pi);
            if (pi.dwProcessId > 0)
            {
                System.Diagnostics.Process myProc = null;
                try
                {
                    myProc = System.Diagnostics.Process.GetProcessById(pi.dwProcessId);
                }
                catch { }
                if (myProc != null)
                {
                    myProc.WaitForExit();
                }
                RunAsUser.CloseHandle(pi.hProcess);
            }
        }
    }

"@
Add-Type -TypeDefinition $runasCode

function RunAs-DesktopUser{
	param([string]$cmdLine,[string]$expressionIfElevated)
	[System.Security.Principal.WindowsIdentity] $wi = [System.Security.Principal.WindowsIdentity]::GetCurrent();
    [System.Security.Principal.WindowsPrincipal] $wp = New-Object system.Security.Principal.WindowsPrincipal($wi);

    if( $wp.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
	{
		if($OSVersion.Major -lt 6)
		{
			RunCmd -commandToRun $cmdLine
		}
		else
		{
			[RunAsUser]::DoRunAs($cmdLine)
		}
	}
	else
	{
		if(-not [String]::IsNullOrEmpty($expressionIfElevated))
		{
			Invoke-Expression $expressionIfElevated
		}
		else{
			RunCmd -commandToRun $cmdLine
		}
	}
}
#endregion

function Get-CurrentPatchLevel
{
	param($patchFamily, $patchTargetArray, $productVersion)
	$versionArray = @()

	if($global:RoiScanXml –eq $null) 
	{
		"RoiScanXml is null" | Trace
		return $versionArray
	}

	foreach($Sku in $global:RoiScanXml.SelectNodes("OFFICEINVENTORY/SKU"))
	{
		if($Sku.ProductVersion.StartsWith($productVersion))
		{
			#find based on PatchFamily name
			$sequenceAttribute = $Sku.SelectSingleNode("PatchData/PatchBaseline/PostBaseline[@PatchFamily='$patchFamily']/@Sequence")
			if($null -ne $sequenceAttribute)
			{
				#must use .get_Value() instead of .Value for PS1 compatibility
				$versionArray += $sequenceAttribute.get_Value()
			}
			else
			{
				#find based on applicable patch targets
				foreach($patchTarget in $patchTargetArray)
				{
					$sequenceAttribute = $Sku.SelectSingleNode("ChildPackages/ChildPackage[contains(@ProductCode,'-$patchTarget-')]/@ProductVersion")
					
					#handling Office 2000 - 2003 ProductCodes
					if($productVersion -lt 12) 
					{
						$sequenceAttribute = $Sku.SelectSingleNode("ChildPackages/ChildPackage[substring(@ProductCode,4,2)='$patchTarget']/@ProductVersion")
					}
					
					if($null -ne $sequenceAttribute)
					{
						#must use .get_Value() instead of .Value for PS1 compatibility
						$versionArray += $sequenceAttribute.get_Value()
					}
				}
			}
		}
	}
	return $versionArray
}

function Get-WindowsExplorerProperties
{
	$ExplorerPreviewPaneEnabled = "Not Enabled"
	$ExplorerDetailsPaneEnabled = "Not Enabled"
	$OffileFileDialogPreviewPaneEnabled = "Not Enabled"
	$OffileFileDialogDetailsPaneEnabled = "Not Enabled"
	$PreviewPaneDisabledByPolicy = "No"
	$DetailsPaneDisabledByPolicy = "No"
	
	$ret = @()

	$ExporerSizerRegKeyPath = "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Modules\GlobalSettings\Sizer"
	
	if((Test-Path $ExporerSizerRegKeyPath) -eq $true)
	{

		$ExporerSizerRegKey = Get-Item  $ExporerSizerRegKeyPath
		$ReadinPaneKeyValue = $ExporerSizerRegKey.GetValue("ReadingPaneSizer") 
		$PreviewPaneKeyValue = $ExporerSizerRegKey.GetValue("PreviewPaneSizer")

		if ( $null -ne $ReadinPaneKeyValue)
		{
			if($ReadinPaneKeyValue[4] -eq 1)
			{
				$ExplorerDetailsPaneEnabled = "Enabled"
			}
		}
		if ( $null -ne $PreviewPaneKeyValue)
		{
			if(($PreviewPaneKeyValue[4] -eq 1 ))
			{
				$ExplorerPreviewPaneEnabled = "Enabled"
			}
		}
	}
	
	if($OSVersion -ge (New-Object System.Version(6,2)))
	{
		$panesEnabledKey = "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Modules\GlobalSettings\DetailsContainer"
		$detailsContainerValue = Get-ItemProperty $panesEnabledKey -Name "DetailsContainer" -ErrorAction SilentlyContinue
		if($detailsContainerValue -ne $null)
		{
			$ExplorerDetailsPaneEnabled = IIF (($detailsContainerValue.DetailsContainer)[0] -eq 1) "Enabled" "Not Enabled"
			$ExplorerPreviewPaneEnabled = IIF (($detailsContainerValue.DetailsContainer)[4] -eq 1) "Enabled" "Not Enabled"
		}
	}
	

	# Collect the office File Dialog status on the Preview Pane and Details Pane
	$OffileFileDialogSizerRegKeyPath = "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\CIDOpen\Modules\GlobalSettings\Sizer"

	if( (Test-Path $OffileFileDialogSizerRegKeyPath) -eq $true)
	{
		$OffileFileDialogSizerRegKey = Get-Item  $OffileFileDialogSizerRegKeyPath
		$OffileFileDialogReadinPaneKeyValue = $OffileFileDialogSizerRegKey.GetValue("ReadingPaneSizer")
		$OffileFileDialogPreviewPaneKeyValue = $OffileFileDialogSizerRegKey.GetValue("PreviewPaneSizer")

		if($null -ne $OffileFileDialogReadinPaneKeyValue)
		{
			if(($OffileFileDialogReadinPaneKeyValue.Length -ge 5) -and ($OffileFileDialogReadinPaneKeyValue[4] -eq 1))
			{
				$OffileFileDialogPreviewPaneEnabled = "Enabled"
			}
		}

		if($null -ne $OffileFileDialogPreviewPaneKeyValue)
		{
			if(($OffileFileDialogPreviewPaneKeyValue.Length -ge 5) -and ($OffileFileDialogPreviewPaneKeyValue[4] -eq 1))
			{
				$OffileFileDialogDetailsPaneEnabled = "Enabled"
			}
		}

	}
	
	$DisabledByPolicyKeyPath = "REGISTRY::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

	if( (Test-Path $DisabledByPolicyKeyPath) -eq $true)
	{
	    $DisabledByPolicyKey = Get-Item $DisabledByPolicyKeyPath
		
		if ( $null -ne $DisabledByPolicyKey.GetValue("NoReadingPane")) 
		{
			if($DisabledByPolicyKey.GetValue("NoReadingPane") -ge 1)
			{
				$PreviewPaneDisabledByPolicy = "Yes"
				$ExplorerDetailsPaneEnabled += " (Blocked by Policy)"
				$OffileFileDialogDetailsPaneEnabled += " (Blocked by Policy)"
			}
		}
		 
		if ($null -ne $DisabledByPolicyKey.GetValue("NoPreviewPane")) 
		{
			if($DisabledByPolicyKey.GetValue("NoPreviewPane") -ge 1)
			{
				$DetailsPaneDisabledByPolicy = "Yes"
				$ExplorerPreviewPaneEnabled += " (Blocked by Policy)"
				$OffileFileDialogPreviewPaneEnabled += " (Blocked by Policy)"
			}
		}
		
	}
	
	$ret += $PreviewPaneDisabledByPolicy
	$ret += $DetailsPaneDisabledByPolicy
	$ret += $ExplorerPreviewPaneEnabled
	$ret += $OffileFileDialogPreviewPaneEnabled
	$ret += $ExplorerDetailsPaneEnabled
	$ret += $OffileFileDialogDetailsPaneEnabled	
	return $ret
}

function Get-HardwareAccelerationInfo
{
	param($Version)
	# 252584 O15 Hardware Acceleration Issue detection
	$ret = @()
	if($Version -eq 15)
	{
		$ret += $true
		$fBlackListed = Get-OffCATRuleFired "bfdda70c-a464-4222-afaa-1407a69b3cb8"
		$LocalDHA = "HKCU:\software\microsoft\office\15.0\common\graphics"
		$PolicyDHA = "HKCU:\software\Policies\microsoft\office\15.0\common\graphics"
		$ValueNameDHA = "DisableHardwareAcceleration"
		$PolicyKeyDHA = Get-ItemProperty $PolicyDHA -name $ValueNameDHA -ErrorAction SilentlyContinue
		$LocalKeyDHA = Get-ItemProperty $LocalDHA -name $ValueNameDHA -ErrorAction SilentlyContinue
		if($PolicyKeyDHA -ne $null)
		{
			$PolicyKeyDHA = $PolicyKeyDHA.DisableHardwareAcceleration
		}
		if($LocalKeyDHA -ne $null)
		{
			$LocalKeyDHA = $LocalKeyDHA.DisableHardwareAcceleration
		}
		if($fBlackListed)
		{
			$Result = "The video configuration is on the block list, so hardware acceleration is automatically disabled in all Office programs. Any related non-policy and policy data in the registry is ignored by Office programs."
		}
		else
		{
			$Result = "The video is not on the block list. "
			if($PolicyKeyDHA)
			{
				$Result += "Policy registry data is controlling hardware acceleration in Office programs, and hardware acceleration is disabled. Non-policy registry data, if found, is ignored because the same setting is configured by policy."
			}
			elseif($PolicyKeyDHA -eq $null)
			{
				$Result += "Policy is not configured for this setting. "
				$PolicyKeyDHA = "Not Found"
				if($LocalKeyDHA)
				{
					$Result += "Only non-policy registry data is controlling hardware acceleration in Office programs, and hardware acceleration is disabled."
				}
				else
				{
					$Result += "If found, only non-policy registry data is controlling hardware acceleration in Office programs, and hardware acceleration is enabled."
				}
			}
			else
			{
				$Result += "Policy registry data is controlling hardware acceleration in Office programs, and hardware acceleration is enabled. Non-policy registry data, if found, is ignored because the same setting is configured by policy."
			}
		}
		
		if($LocalKeyDHA -eq $null)
		{
			$LocalKeyDHA = "Not Found"
		}
		$ret += $fBlackListed
		$ret += $LocalDHA
		$ret += $PolicyDHA
		$ret += $ValueNameDHA
		$ret += $PolicyKeyDHA
		$ret += $LocalKeyDHA
		$ret += $Result
	}
	else
	{
		$ret += $false
	}
	return $ret
}

$global:OfficeProducts = @(
	@{Name = $LocalsOfficeCommon.ID_AccessName;		ProgId="Access.Application";				ProcName="msaccess.exe";	VersionsSupported = 10,11,12,14,15;	FriendlyName=$LocalsOfficeCommon.ID_AccessNameShort;		RegName="Access"},
	@{Name = $LocalsOfficeCommon.ID_ExcelName;		ProgId="Excel.Application";					ProcName="excel.exe";		VersionsSupported = 10,11,12,14,15;	FriendlyName=$LocalsOfficeCommon.ID_ExcelNameShort;			RegName="Excel"},
	@{Name = $LocalsOfficeCommon.ID_InfoPathName;	ProgId="Infopath.Application";				ProcName="infopath.exe";	VersionsSupported = 11,12,14,15;	FriendlyName=$LocalsOfficeCommon.ID_InfoPathNameShort;		RegName="InfoPath"},
	@{Name = $LocalsOfficeCommon.ID_OneNoteName;	ProgId="Onenote.Application";				ProcName="onenote.exe";		VersionsSupported = 11,12,14,15;	FriendlyName=$LocalsOfficeCommon.ID_OneNoteNameShort;		RegName="OneNote"},
	@{Name = $LocalsOfficeCommon.ID_OutlookName;	ProgId="Outlook.Application";				ProcName="outlook.exe";		VersionsSupported = 10,11,12,14,15;	FriendlyName=$LocalsOfficeCommon.ID_OutlookNameShort;		RegName="Outlook"},
	@{Name = $LocalsOfficeCommon.ID_PowerpointName;	ProgId="Powerpoint.Application";			ProcName="powerpnt.exe";	VersionsSupported = 10,11,12,14,15;	FriendlyName=$LocalsOfficeCommon.ID_PowerpointNameShort;	RegName="PowerPoint"},
	@{Name = $LocalsOfficeCommon.ID_ProjectName;	ProgId="MSProject.Application";				ProcName="winproj.exe";		VersionsSupported = 10,11,12,14,15;	FriendlyName=$LocalsOfficeCommon.ID_ProjectNameShort;		RegName="Project"},
	@{Name = $LocalsOfficeCommon.ID_PublisherName;	ProgId="Publisher.Application";				ProcName="mspub.exe";		VersionsSupported = 10,11,12,14,15;	FriendlyName=$LocalsOfficeCommon.ID_PublisherNameShort;		RegName="Publisher"},
	@{Name = $LocalsOfficeCommon.ID_VisioName;		ProgId="Visio.Application";					ProcName="visio.exe";		VersionsSupported = 10,11,12,14,15;	FriendlyName=$LocalsOfficeCommon.ID_VisioNameShort;			RegName="Visio"},
	@{Name = $LocalsOfficeCommon.ID_WordName;		ProgId="Word.Application";					ProcName="winword.exe";		VersionsSupported = 10,11,12,14,15;	FriendlyName=$LocalsOfficeCommon.ID_WordNameShort;			RegName="Word"},
 	@{Name = $LocalsOfficeCommon.ID_FrontPageName;	ProgId="Frontpage.Application";				ProcName="frontpg.exe";		VersionsSupported = 10,11;			FriendlyName=$LocalsOfficeCommon.ID_FrontPageNameShort;		RegName="FrontPage"},
	@{Name = $LocalsOfficeCommon.ID_SPDesignerName;	ProgId="SharepointDesigner.Application";	ProcName="spdesign.exe";	VersionsSupported = 12,14,15;		FriendlyName=$LocalsOfficeCommon.ID_SPDesignerNameShort;	RegName="SharePoint Designer"},
	@{Name = $LocalsOfficeCommon.ID_GrooveName;		ProgId="Groove.Application";				ProcName="groove.exe";		VersionsSupported = ,12;			FriendlyName=$LocalsOfficeCommon.ID_GrooveNameShort;		RegName="Groove"},
	@{Name = $LocalsOfficeCommon.ID_SPWorkspaceName;ProgId="Groove.Application";				ProcName="groove.exe";		VersionsSupported = ,14;			FriendlyName=$LocalsOfficeCommon.ID_SPWorkspaceNameShort;	RegName="Groove"},
	@{Name = $LocalsOfficeCommon.ID_SkyDriveProName;ProgId="Groove.Application";				ProcName="groove.exe";		VersionsSupported = ,15;			FriendlyName=$LocalsOfficeCommon.ID_SkyDriveProNameShort;	RegName="Groove"}
);


# SIG # Begin signature block
# MIInlAYJKoZIhvcNAQcCoIInhTCCJ4ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBJcktDmCWiaoJK
# 7+YpHQoTr6MBwKvdHFpMfCR5D7z6W6CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXQwghlwAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKlclgD7Jm6FxNd4HkB/xe5E
# dNQkqvNO1FDolIpRLPj8MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQARB36MXs60riY8Mby6Jkwjd1yFrF2sRs/RsDB0AYAfBkD3wn6hsuVE
# tFivuspsTcKUedvcl0RjqLbgCq9yMcKcQHonigZXOvPYIx/C3H0TNr4cq0M7V1uH
# 5NK4klR1Sw+t7kFaQUYDGXR4Gqkubxb+TVxCG9nGnlIaZxZ8NBRaA9OTchwYsQH6
# WhyaNu5XGlniH6XdHr5MDJ98Ax7mNetEJBdSjy4646mdC5XA4oBUzIXSnmhRZWan
# /W81SPydnyO7fGAM2on84JFcIWAfhUNNclByTo/22VKxTpgQFIm+bGiL5lwXUF2u
# IzLGsf1EHM2+R7o69ydVVXoGygnz6jctoYIW/DCCFvgGCisGAQQBgjcDAwExghbo
# MIIW5AYJKoZIhvcNAQcCoIIW1TCCFtECAQMxDzANBglghkgBZQMEAgEFADCCAVAG
# CyqGSIb3DQEJEAEEoIIBPwSCATswggE3AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIHtMBYidy3j6cy4sau6u7CykVcAoCt6AJ953AXT2XR9XAgZj7j47
# rjgYEjIwMjMwMjI3MDkxMDIxLjU4WjAEgAIB9KCB0KSBzTCByjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFt
# ZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0U3QS1F
# MzU5LUEyNUQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wg
# ghFUMIIHDDCCBPSgAwIBAgITMwAAAcn61Y4lIHQCXgABAAAByTANBgkqhkiG9w0B
# AQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMjExMDQxOTAx
# MzhaFw0yNDAyMDIxOTAxMzhaMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozRTdBLUUzNTktQTI1RDElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBANZy4uWOb8/CvlqMYZO6hlv7wsYuXrkzNNU4hGxThvIO
# 0hQdFTI2IKOk4kc4DkPgjedzgTipcjB1s0S+Mb2ktN2ZSIHrSCC2IgEqILBLZY8x
# JURzu3wxgxVnHc/pQjWJiaM7WxtzzK58W5VBx1JK+AuxAR29mNOxneRiQYD/PuQG
# TbE5bBxnMx7OOZpj+61IHDJ//3PEPxmEqnU+DlxC6ed4ffRJ8heM3LHdmRY8XY9Z
# T/EBsGWUuBfNiQRntqQq0mpMhY08cxSlDsHEHq8AUf2GkJcu5rQq2uDzXMhEJvp/
# yw3Hv1VYkGvDjNpwWRysOgsjKhMxSScuR4s8/Gesa6qiyrYvL4iVENBbapE10kd/
# /8PDwCsgZbyGExRfy8tyYd3G1XjoEprmzlcL/JzHoXEG9gLcXFP5XchFKsvP7YRB
# yFjWm8x18eTvQ+G7UuqCXYC5h8a0wbRrHFUKsdM+f31CJCxO7W8H6KvOHBf1ESxM
# sN6ueyldlOIDoXN+el2BFUHSV6OlRVgUA2G82p0Nuc2NtVApI/NtQsg/dIKqzt60
# D5XEKOnq8Ftgxdn7JoAG1as0LM+kZJmn8+K3te5Ju6ntPT7sB8OXt8eWSBhKFZXz
# Zyb+vvOdbsCl+gKWRcT83kKO1v+QbWk5pGRIcGOQHQj4D79GmiBEJ9qhezLxcAnL
# AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUBW+dZ0bCPKG+eDoUxXlRe0QuMsswHwYD
# VR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZO
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBc
# BggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYD
# VR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOC
# AgEANqi6nGbfR4pCB3I+wJZx4Y6LsUozngWkxPhCvGl3FS5vXAPA9v2WNjlKWLzn
# YbgxFfYRJVZs6KYibpP8QWIenViU0YZku4VY6xras0hVtC337EcrI8ZKbqsoR4gQ
# 8TFzBmehnc1H6lT9mXdjvifwWECYLPTR2M/wjOF2kT/k9lTNyRNZkjtai2vpnweN
# u0Ii4/yQu01GIIeEWPqCzBVbkCWb12Jf4yExX1KaSaAGpAa9FXNq9ZD+Q4iWjb2V
# if3LmGolkOJPcacOsBs96qu8QFp5Rs7GsMBYY7cKuRB/7N+ywn3ocrgsPGUSfVt7
# YEhXqQFTO7FBPj691Lvoj7wVeE7EwzRS9AlSD1/tVziemERmCdpBxqaBnP+bIANi
# CkHJfe2Q2CSKosYMCjX7cje9DtAE26U1YbGzdNRVZYtB/r4HBocs5Oo6QMsBzw0k
# P8aBHhlOPujxU1zETv3zMxnFHH9GR6mTJtFIaB/LTrZNfJOge+SiV07WN2TO6U37
# q0r9kK7+c8wgYssrLTj8PyCSPpPaKU4Grawt/S+vfysMrQ9Me7dI5k17ZS2Whr6E
# pY3csq+kA0VZKrAmi1EkrAIlnmr+aoOuFN5i5nnpKNBPUyecs7Tf43Is5R8dF7ID
# rjerLm9wj1ewADDIiqKXUGKoj17vSMb6l0+whP0jAtqXDckwggdxMIIFWaADAgEC
# AhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQg
# Um9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVa
# Fw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7V
# gtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeF
# RiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3X
# D9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoP
# z130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+
# tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5Jas
# AUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/b
# fV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuv
# XsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg
# 8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzF
# a/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqP
# nhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEw
# IwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSf
# pxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBB
# MD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0Rv
# Y3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGC
# NxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8w
# HwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmg
# R4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWlj
# Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEF
# BQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29D
# ZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEs
# H2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHk
# wo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinL
# btg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCg
# vxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsId
# w2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2
# zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23K
# jgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beu
# yOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/
# tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjm
# jJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBj
# U02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICyzCCAjQCAQEwgfihgdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjNFN0EtRTM1OS1BMjVEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQB96YvL/h4Bm41ULOBt+nUcVgbdDqCB
# gzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAk
# BgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEB
# BQUAAgUA56aTcDAiGA8yMDIzMDIyNzEwMjY1NloYDzIwMjMwMjI4MTAyNjU2WjB0
# MDoGCisGAQQBhFkKBAExLDAqMAoCBQDnppNwAgEAMAcCAQACAgv7MAcCAQACAhHA
# MAoCBQDnp+TwAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAI
# AgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAMfEMd/gMAkSY
# 4Lz0Eo5zUkY5Jpqsd+kLFSqONN4iKV3e9Uc7c917H5hLmFJZ9iqFI9bbtbPTQ2oi
# 0JwENqL//e1myQR2DHeuMssDwvM7VxPB1/vWkCWEZEWvTKTukCd5uzbVZzwbQwTD
# fQonkieThfXUI17aRnnjdtcP6O5x7QExggQNMIIECQIBATCBkzB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAcn61Y4lIHQCXgABAAAByTANBglghkgB
# ZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3
# DQEJBDEiBCC5COVWpmu3X6S2zWKpB6Q+ipWWDFHlIrug//SzjxzGDDCB+gYLKoZI
# hvcNAQkQAi8xgeowgecwgeQwgb0EIIF1zn9S3VFLECd4Kdh/YA0jIYkA/8194V18
# 4dk5dv2BMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAHJ+tWOJSB0Al4AAQAAAckwIgQgq/mhIgWlF3VqpINsjMqgSZ13FBR17sRVelsg
# XXA+UXgwDQYJKoZIhvcNAQELBQAEggIAdoROYUvZasy7/+uB9/sMNrsVc19DN50g
# ko2D2gXCwOB1PSSd6NPnWdT+0ua4LXvqC9+XOewaS3UWj70m0J2BB2bI0hXzdPYy
# qPXDVFDvmfPl08sIYoPTKOmw0TB6YV/2/gl8UIEmF7sXJN3YR1+0lKWxczJh0m4w
# b7FSLnt01JJHe1wSUo9+Gglx2LreynC4aUHuTjHV2plgt6i2JahEFq+2ArkwTMkE
# mQiGNnE/yamACpLoblKfVS5tM8lCXEYk04qsz4v8bkwDmSYTZcky2bJStFPmcoyG
# BTIIhWX0/Nu+pSGrrGyla1lHYUGXKVq3fxUUb0qUmobgdTbQfH57Sm0to/rKqkSc
# t+dTnQ5ImBbNj7qpCcfOrvhAfIMhdFZ6t8P+8wsC8PTBONFCNDeF+3RveQUaut4d
# zVslH3zcapE0szpOIJKNwZ3AotrB1hCIG6ChL7MqAYKVnfq7KmE9JGc0IgiRGqoZ
# fg4BIFiqdHjmsU92JuuvCgv9lnraU0YRlNEUL4EmP8stYDB5IaW9RZm8wmUS/x0U
# a9MrAcgi4LEj9bEvTK9T3/+DECQSb7hxeEmEd81uLEJsZ6HoZDQLtHptP8h3U9bI
# SADWvbAR92POp0Bx1hWQ7+NVA4Zd+goJiUYoOzaCZZqI6r/eD5bcCYPuKYD451vj
# zsKRhbZuRD0=
# SIG # End signature block
