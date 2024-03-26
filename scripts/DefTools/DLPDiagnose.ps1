<#PSScriptInfo

.VERSION 
    2.2

.DATE LAST UPDATED
    06/09/2020
    07/13/2021
	08/05/2021

.AUTHOR 
    prmarri

.COMPANYNAME 
    Microsoft Corporation

.COPYRIGHT 
    Copyright (C) Microsoft Corporation. All rights reserved.

.TAGS
    WindowsDefender,DLP

.LICENSEURI 
    //*********************************************************
    //
    //    Copyright (c) Microsoft Corporation. All rights reserved.
    //    This code is licensed under the Microsoft Public License.
    //    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
    //    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
    //    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
    //    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
    //
    //*********************************************************

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


#>

<# 

.DESCRIPTION
   DLP Self Diagnosing Tool

#> 



### LOGGING RELATED. 
[string]$global:DLP_DIAGNOSE_LOGPATH = join-path ($env:systemdrive) DLPDiagnoseLogs
[string]$global:DLP_DIAGNOSE_FILENAME = "DLPDiagnosing.log"
[string]$global:LogFileName = ""
[string]$global:DLPBackPortFile = "FeatureToastDlpImg.png"
[int]$global:OSBuildNum = 0

[string]$global:CurEngVer = ""
[string]$global:CurMoCAMPVer=""
[string]$global:MIN_MOCAMPVER_NEEDED = "4.18.2005.3"
[string]$global:MIN_ENGINEVER_NEEDED = "1.1.17046.0"


[boolean]$global:bDLPMinReqOS = $true


############################################################################################

### FUNCTION: WRITE CONSOLE OUTPUT IN COLOR

############################################################################################

function Write-ColorOutput($foregroundColor)
{

    LogToFile $args
    # save the current color
    $fc = $host.UI.RawUI.ForegroundColor

    # set the new color
    $host.UI.RawUI.ForegroundColor = $foregroundColor

    # output
    if ($args)
    {
        Write-Output $args
    }
    else
    {
        $input | Write-Output
    }

    # restore the original color
    $host.UI.RawUI.ForegroundColor = $fc
}




############################################################################################

# GENERIC FUNCTION: TO LOG MESSAGES TO A CONFIGURED LOG FILE

############################################################################################

function LogToFile
{
    param($message);

    if (($global:LogFileName -ne "") -and (Test-Path ($global:LogFileName)))
    {
        $currenttime = Get-Date -format u;
        $outputstring = "[" +  $currenttime + "] " + $message;
        $outputstring | Out-File $global:LogFileName -Append;
    }        
}


############################################################################################

### FUNCTION: CHECKS IF DEFENDER AND WD FILTER ARE ACTUALLY RUNNING OR NOT 

############################################################################################
function DisplayMachineInfo
{
    
    Write-ColorOutput Cyan "SYSTEM INFO:"    
    Write-ColorOutput White " "
    
    try
    {
        $MachineInfo = Get-ComputerInfo
        
    }
    catch [system.exception]
    {
        Write-ColorOutput Red "    Exception while querying computer Info. Skipping it..."  
        return
    }

    $tmp = $MachineInfo.CsDNSHostName
    Write-ColorOutput Yellow "   Computer Name:        $tmp  "
    
    $tmp = $MachineInfo.CsDomain
    Write-ColorOutput White "   Domain:               $tmp  "
    
    $tmp = $MachineInfo.WindowsBuildLabEx
    Write-ColorOutput White "   OS Build Name:        $tmp  "
    
    $tmp = $MachineInfo.WindowsProductName 
    Write-ColorOutput White "   Product Name:         $tmp  "
    
    #$tmp = $MachineInfo.OsHotFixes
    #Write-ColorOutput White "   Hot fix (KB):    $tmp  "    
    
    $tmp = $MachineInfo.CsSystemType
    Write-ColorOutput White "   Device Arch:          $tmp  "
    
    $tmp = $MachineInfo.CsModel
    Write-ColorOutput White "   Model:                $tmp  "
    
    $tmp = $MachineInfo.OsName
    Write-ColorOutput White "   OS Name:              $tmp  "

    $tmp = $MachineInfo.CsPrimaryOwnerName
    Write-ColorOutput White "   Primary User:         $tmp  "
    
    $tmp = $MachineInfo.CsPartOfDomain
    Write-ColorOutput White "   PartOfDomain?:        $tmp  "

}


############################################################################################

### FUNCTION: CHECKS IF DEFENDER AND WD FILTER ARE ACTUALLY RUNNING OR NOT 

############################################################################################

function CheckWDRunning
{

    Write-ColorOutput Cyan "CHECKING IF DEFENDER SERVICE RUNNING:"    
    Write-ColorOutput White " "
        
    try 
    { 
        $defenderOptions = Get-MpComputerStatus -ErrorAction SilentlyContinue
 
        if([string]::IsNullOrEmpty($defenderOptions)) 
        { 
            Write-ColorOutput Red "   Microsoft Defender Service not running. DLP won't work without Defender"   
            $global:bDLPMinReqOS = $false                       

        } 
        else 
        { 
            
            if($defenderOptions.AntivirusEnabled -eq $true)
            {
                Write-ColorOutput Green "    Microsoft Defender Service running. Looks Good"             
            }
            else
            {
                Write-ColorOutput Red "    Microsoft Defender Service not running. DLP won't work without Defender..."  
                $global:bDLPMinReqOS = $false            
            }
        } 
    } 
    catch [System.Exception]
    {

        Write-ColorOutput Red "Unable to query Microsoft Defender service status "        
    }
    
}

############################################################################################

### FUNCTION: CHECK THE OFFICE VERSION (Need this for Office Enlightenment feature)

############################################################################################

function GetOfficeVersion
{

    Write-ColorOutput Cyan "CHECKING OFFICE VERSION:" 
    Write-ColorOutput White " "   

    [string]$OfficeInstVer = ""    
    ## It is observed that diff machines has diff reg key to check for office version
    [string]$keyreg1 = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
    [string]$keyreg2 = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\O365*"
    [string]$keyreg3 = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Office*"
   
    if(Test-Path $keyreg1)
    {
        try
        {
            $OfficeInstVer = (Get-ItemProperty -Path $keyreg1).VersionToReport       
        }
        catch [System.Exception]
        {
            Write-ColorOutput red "    ERROR: Exception while querying the Office installation version (1). Exiting..."
            Write-ColorOutput White " "
    
            return
        }
    }
   elseif(Test-Path $keyreg2)
   {
       try
        {
            $OfficeInstVer = (Get-ItemProperty -Path $keyreg2).DisplayVersion       
        }
        catch [System.Exception]
        {
            Write-ColorOutput red "    ERROR: Exception while querying the Office installation version (2). Exiting..."
            Write-ColorOutput White " "
    
            return
        }
   }
   elseif(Test-Path $keyreg3)
   {
       try
        {
            $OfficeInstVer = (Get-ItemProperty -Path $keyreg3).DisplayVersion       
        }
        catch [System.Exception]
        {
            Write-ColorOutput red "    ERROR: Exception while querying the Office installation version (3). Exiting..."
            Write-ColorOutput White " "
    
            return
        }
   }
   else
   {
      Write-ColorOutput Yellow "    INFO: Unable to Query the Office version. Please check if Office is installed"
      return
   }    

   Write-ColorOutput Yellow "    Current Office version is ==> $OfficeInstVer"
   Write-ColorOutput White " "

}


############################################################################################

### FUNCTION: CHECK IF THE OFFICE-ENLIGHTENMENT FEATURE IS ENABELD OR NOT

############################################################################################
function CheckOfficeEnlightenmentReg
{

    Write-ColorOutput Cyan "CHECKING OFFICE ENLIGHTENMENT CONFIGURATION:" 
    Write-ColorOutput White " "   
   [string]$keyreg = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
   
    if(Test-Path $keyreg)
    {
        try
        {
            $a = (Get-ItemProperty -Path $keyreg).DlpAppEnlightenmentSettings       
        }
        catch [System.Exception]
        {
            Write-ColorOutput red "    ERROR: Exception while querying the Office installation version (1). Exiting..."
            Write-ColorOutput White " "
    
            return
        }
    }
   

   if($a -eq $null)
   {
       Write-ColorOutput White "    DlpAppEnlightenmentSettings registry missing. Goes with default"
   }
   elseif($a -eq 1)
   {
       Write-ColorOutput Green "    DlpAppEnlightenmentSettings is 1. Office Enlightenment Feature is enabled"
   }
   elseif($a -eq 0)
   {
      Write-ColorOutput Yellow "    DlpAppEnlightenmentSettings is 0. Office Enlightenment Feature is disabled"
   }   

    Write-ColorOutput White " "

}

############################################################################################

### FUNCTION: GET THE CURRENT INSTALLED MoCAMP VERSION 

############################################################################################

function GetCurrentMoCAMPVersion
{

    Write-ColorOutput Cyan "CHECKING MOCAMP VERSION:" 
    Write-ColorOutput White " "   
    [string]$MoCAMPInstPath = ""
    [string]$MoCAMPInstVer = ""
    [string]$keyreg = "HKLM:\SOFTWARE\Microsoft\Windows Defender"
    
    
    ## query the MoCAMP installation path
    try
    {
        $MoCAMPInstPath = (Get-ItemProperty -Path $keyreg).InstallLocation       
    }
    catch [System.Exception]
    {
        Write-ColorOutput red "    ERROR: Exception while querying the MoCAMP installation path. Exiting..."
        Write-ColorOutput White " "
    
        return
    }

    ## If NULL string, then something went wrong with the above query. Log and Exit...
    if( $MoCAMPInstPath -eq "" -or $MoCAMPInstPath -eq " ")
    {
        Write-ColorOutput Red "    WARN: Unable to query MoCAMP installation path: $MoCAMPInstPath. Exiting..."
        Write-ColorOutput White " "    
        return
    }


    #Write-ColorOutput Yellow "    INFO: MoCAMP Install path is-> $MoCAMPInstPath"
    ##Check if it has inbox version or installed MoCAMP version    
    if($MoCAMPInstPath.ToLower().contains('platform'))
    {
        $ArrStr = $MoCAMPInstPath.Split("\")
        
        if(-Not($ArrStr.Count -lt 2))
        {
            $MoCAMPInstVer = $ArrStr[$ArrStr.Count-2]
        }

        #Write-ColorOutput White "    MoCAMP version read: $MoCAMPInstVer"
        
        ### strip off the multi install number for the same version
        if($MoCAMPInstVer.Contains("-"))
        {
            $MoCAMPInstVer = $MoCAMPInstVer.Substring(0, $MoCAMPInstVer.IndexOf("-"))
        }
        
        Write-ColorOutput Yellow "    Current MoCAMP version ==> $MoCAMPInstVer"
        $global:CurMoCAMPVer = $MoCAMPInstVer        
    }
    else
    {
        Write-ColorOutput Green "    It has an inbox MoCAMP version"
    }
 
    IsMoCAMPUpdateNeeded
    
}




############################################################################################

### FUNCTION: NOTIFIES USER IF MOCAMP UPDATE IS NEEDED

############################################################################################

function IsMoCAMPUpdateNeeded
{
    
    Write-ColorOutput White "    Min MoCAMP version needed : $global:MIN_MOCAMPVER_NEEDED"

    $ArrCurVer = ($global:CurMoCAMPVer).Split(".")
    $ArrMinMoCAMPVer = ($global:MIN_MOCAMPVER_NEEDED).Split(".")

    if(-Not($ArrCurVer.Count -eq $ArrMinMoCAMPVer.count) -or ($ArrCurVer.Count -lt 4))
    {
        Write-ColorOutput Red "    ERROR: SubPart count for Cur-> $ArrCurrVer.count  MinMoCAMPVer->$ArrMinMoCAMPVer.count. Skipping update..."
        return
    }
    

      if( ( [int]$ArrCurVer[0] -lt [int]$ArrMinMoCAMPVer[0]) -or 
         ( ([int]$ArrCurVer[0] -eq [int]$ArrMinMoCAMPVer[0]) -and ([int]$ArrCurVer[1] -lt [int]$ArrMinMoCAMPVer[1])) -or 
         ( ([int]$ArrCurVer[0] -eq [int]$ArrMinMoCAMPVer[0]) -and ([int]$ArrCurVer[1] -eq [int]$ArrMinMoCAMPVer[1]) -and ([int]$ArrCurVer[2] -lt [int]$ArrMinMoCAMPVer[2])) -or
         ( ([int]$ArrCurVer[0] -eq [int]$ArrMinMoCAMPVer[0]) -and ([int]$ArrCurVer[1] -eq [int]$ArrMinMoCAMPVer[1]) -and ([int]$ArrCurVer[2] -eq [int]$ArrMinMoCAMPVer[2]) -and ([int]$ArrCurVer[3] -lt [int]$ArrMinMoCAMPVer[3]) ))
    {
        Write-ColorOutput Red "    INFO: Current MoCAMP version is old. Might need update for DLP feature to work"
    
    }
    else
    {
        Write-ColorOutput White " "
        Write-ColorOutput Green "    INFO: Min MoCAMP Version requirements met. Looks Good"
    }
}




############################################################################################

### FUNCTION: GET THE CURRENT ENGINE VERSION 

############################################################################################

function GetCurrentEngVersion
{

    Write-ColorOutput Cyan "CHECKING ENGINE VERSION:"    
    Write-ColorOutput White " "
    
    [string]$EngInstPath = ""
    [string]$EngRegKey = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates"

    try
    {
        $EngInstPath = (Get-ItemProperty -Path $EngRegKey).SignatureLocation
    }
    catch [System.Exception]
    {
        Write-ColorOutput Red "    ERROR: Exception while querying the Engine installation path.Exiting...."
        return
    }

    [string]$EngInstDll = $EngInstPath + "\mpengine.dll"
    
    #Write-ColorOutput White "    Curr Eng Dll full Path-> $EngInstDll"
    
    if(-Not(Test-Path($EngInstDll)))
    {
        Write-ColorOutput Red "    WARN: Unable to findout the current engine dll. Can't find the Engine version "
        Write-ColorOutput Red "    WARN: Path-> $EngInstDll"        
        $global:bDLPMinReqOS = $false            
        return
    }
    
    try
    {
        $global:CurEngVer = (get-command $EngInstDll).FileVersionInfo.Productversion        
    }
    catch [System.Exception]
    { 
        Write-ColorOutput Red "    ERROR: Exception while querying the engine version. Exiting...."
        return
    }

    Write-ColorOutput Yellow "    Current Installed Engine Version is ===> $global:CurEngVer"
    IsEngineUpdateNeeded
    

}




############################################################################################

### FUNCTION: NOTIFIES USER IF ENGINE UPDATE IS NEEDED

############################################################################################

function IsEngineUpdateNeeded
{
    
    Write-ColorOutput White "    Min MoCAMP version needed : $global:MIN_ENGINEVER_NEEDED"

    $ArrCurrEngVer = ($global:CurEngVer).Split(".")
    $ArrMinEngVer = ($global:MIN_ENGINEVER_NEEDED).Split(".")

    if(-Not($ArrCurrEngVer.Count -eq $ArrMinEngVer.count) -or ($ArrCurrEngVer.Count -ne 4))
    {
        Write-ColorOutput Red "    ERROR:Engine ver check. SubPart count for Cur-> $ArrCurrEngVer.count Min-> $ArrMinEngVer.count. Skipping update"
        return
    }

    
    if( ([int]$ArrCurrEngVer[0] -lt [int]$ArrMinEngVer[0]) -or  
        ([int]$ArrCurrEngVer[1] -lt [int]$ArrMinEngVer[1]) -or 
        ([int]$ArrCurrEngVer[2] -lt [int]$ArrMinEngVer[2]) -or 
        ([int]$ArrCurrEngVer[3] -lt [int]$ArrMinEngVer[3]) )
    {
        
        Write-ColorOutput Red "    INFO: Current Engine version is old. Might need update for DLP feature to work"
        $global:bDLPMinReqOS = $false 
    
    }
    else
    {
        Write-ColorOutput White " "
        Write-ColorOutput Green "    INFO: Min Engine Version requirements met. Looks Good"
        
    }
}





############################################################################################

### FUNCTION: CHECKS THE OS VERISON 

############################################################################################

function GetOSBuildNum
{
    
    Write-ColorOutput Cyan "CHECKING OS BUILD VERSION:"
    Write-ColorOutput White " "
    
    try
    {
        $global:OSBuildNum = Invoke-Expression "([System.Environment]::OSVersion.Version).Build"
    }
    catch [system.exception]
    {
        Write-ColorOutput Red "  Exception while querying the OS build version number $Error"
    }
        

    if($OSBuildNum -lt 17763)
    {
        Write-ColorOutput Red "   Build version Num:$global:OSBuildNum  Min OS needed is RS5. Current OS does not support DLP"     
        $global:bDLPMinReqOS = $false       
    }
    elseif($OSBuildNum -eq 17763)
    {
        Write-ColorOutput Green "   Build version Num:$global:OSBuildNum  OS: RS5 Release"            
    }
    elseif($OSBuildNum -eq 18362)
    {
        Write-ColorOutput Green "   Build version Num:$global:OSBuildNum  OS: 19H1 Release"            
            
    }
    elseif($OSBuildNum -eq 18363)
    {
        Write-ColorOutput Green "   Build version Num:$global:OSBuildNum  OS: 19H2 Release"                        
    }
    elseif($OSBuildNum -eq 19041)
    {
        Write-ColorOutput Green "   Build version Num:$global:OSBuildNum  OS: VB Release"                        
    }
    else
    {
        Write-ColorOutput Green "   Build version Num:$global:OSBuildNum  OS: Mn or Fe Release"
    } 
    
}




############################################################################################

### FUNCTION: CHECKS THE SENSE ONBOARD REG ARE ALREADY PRESENT OR NOT

############################################################################################

function CheckSenseOnBoardReg
{
    Write-ColorOutput Cyan "CHECKING SENSE ONBOARDING REGS:"
    Write-ColorOutput White " "
    
    Write-ColorOutput White "   Reg1 check-->"
    ### MDE Reg1 check
    try
    {  
        $a = Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" | Select-Object -ExpandProperty "GroupIds" -ErrorAction SilentlyContinue 

        if($a -eq $null)
        {
            Write-ColorOutput Yellow "   Missing MDE Reg entry. Key='GroupIds' Value='EnableDlpEnforcement' under 'HKLM:SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'"
            Write-ColorOutput Red "   Please add above mentioned Registry entry without which DLP feature may not work for older OS [RS5 or 19H1]"
            
        }
        else
        {
            if($a -eq "EnableDlpEnforcement")
            {
                Write-ColorOutput Green "   Reg1->GroupIds (MDE)Regkey set properly for EnableDlpEnforcement. Looks Good"
            }
            else
            {
                Write-ColorOutput Yellow "   GroupIds (MDE)Regkey exists but not properly set as EnableDlpEnforcement"
            }
        }
    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying or adding reg keys to onboard SENSE OS"
    }


    Write-ColorOutput White " "
    Write-ColorOutput White "   Reg2 check-->"
    ### ATP Reg2 check
    try
    {
        if(-Not(Test-Path("HKLM:SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging")))
        {
            
            Write-ColorOutput Yellow "   Missing MDE Reg Entry: Key='DLP' Value='EnableDlpEnforcement' under 'HKLM:SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging'"
            Write-ColorOutput Red "   Please add above mentioned Registry entry without which DLP feature may not work for older OS [RS5 or 19H1]"
            return
        }
        
        
        $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging" | Select-Object -ExpandProperty "DLP" -ErrorAction SilentlyContinue 
        if($b -eq $null)
        {
            Write-ColorOutput Yellow "   Missing MDE Reg Entry: Key='DLP' Value='EnableDlpEnforcement' under 'HKLM:SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging'"
            Write-ColorOutput Red "   Please add above mentioned Registry entry without which DLP feature may not work"
            
        }
        else
        {
            if($b -eq "EnableDlpEnforcement")
            {
                Write-ColorOutput Green "   Reg2->DLP (MDE)Regkey set properly for EnableDlpEnforcement. Looks Good"
            }
            else
            {
                Write-ColorOutput Green "   DLP (MDE)Regkey exists but not properly as EnableDlpEnforcement"
            }
        }
    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying or adding reg keys to onboard SENSE OS"
    }

}





############################################################################################

### FUNCTION: CHECKS IF DLP FEATURE IS ENABLED ON THIS MACHINE

############################################################################################

function CheckDLPEnabled
{

    Write-ColorOutput Cyan "CHECK REG IF DLP FEATURE IS ENABLED:"
    Write-ColorOutput White " "
        
    try
    {
        if(-Not(Test-Path("HKLM:SOFTWARE\Microsoft\Windows Defender\Features")))
        {
            
            Write-ColorOutput Red "   ERROR: Did not find the reg path 'SOFTWARE\Microsoft\Windows Defender\Features'"
            return
        }
        
        #SenseEnabled reg check
        $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Defender\Features" | Select-Object -ExpandProperty "SenseEnabled" -ErrorAction SilentlyContinue 
        if($b -ne $null)
        {

            if($b -eq 1)
            {
                Write-ColorOutput Green "   SenseEnabled is set to TRUE. Looks Good"
            }
            else
            {
                Write-ColorOutput Red "   SenseEnabled is not enabled. Please contact your administrator"
                $global:bDLPMinReqOS = $false
            }

        }
        else
        {
           Write-ColorOutput Red "  The reg key SenseEnabled does not exists"
           $global:bDLPMinReqOS = $false         
        }

        
        #SenseDlpEnabled reg check
        $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Defender\Features" | Select-Object -ExpandProperty "SenseDlpEnabled" -ErrorAction SilentlyContinue 
        if($b -ne $null)
        {

            if($b -eq 1)
            {
                Write-ColorOutput Green "   SenseDlpEnabled is enabled. Looks Good"
            }
            else
            {
                Write-ColorOutput Red "   SenseDlpEnabled is not enabled for the DLP feature. Please contact your administrator"
                $global:bDLPMinReqOS = $false
            }

        }
        else
        {
           Write-ColorOutput Red "  The reg key SenseDlpEnabled does not exists"
           $global:bDLPMinReqOS = $false         
        }


        #Dlp Show bypass reason UX reg check
        $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Defender\Features" | Select-Object -ExpandProperty "SenseDlpShowBypassReasonUx" -ErrorAction SilentlyContinue 
        if($b -ne $null)
        {

            Write-ColorOutput Yellow "   SenseDlpShowBypassReasonUx is: $b"            

        }
        else
        {
           Write-ColorOutput Yellow "  The reg key SenseDlpShowBypassReasonUx does not exists"           
        }
        

        #Sense org id check
        $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Defender\Features" | Select-Object -ExpandProperty "SenseOrgId" -ErrorAction SilentlyContinue 
        if($b -ne $null)
        {
            
            Write-ColorOutput Yellow "   SenseOrgId is: $b"            

        }
        else
        {
           Write-ColorOutput Red "  The reg key SenseOrgId does not exists"
           $global:bDLPMinReqOS = $false
        }

        #MpCapability reg check
        $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Defender\Features" | Select-Object -ExpandProperty "MpCapability" -ErrorAction SilentlyContinue
         if($b -ne $null)
        {
            
            Write-ColorOutput Yellow "   MpCapability is: $b"            

        }
        else
        {
           Write-ColorOutput Yellow "  The reg key MpCapability does not exists"
           Write-ColorOutput Yellow "  The DLP experience may not be as expected"                 
        }

    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying or adding reg keys to onboard SENSE OS"
    }

}



############################################################################################

### FUNCTION: CHECKS IF UX CONFIGURATION SETTINGS ARE ENABLED OR DISABLED

############################################################################################

function CheckUXConfiguraitonSettings
{

    Write-ColorOutput Cyan "CHECKING UX CONFIGURATION REG SETTINGS:"
    Write-ColorOutput White " "
    

    ### Post June 2020 MoCAMP, these GP controlled registries will not impact DLP toast display
    ## However, have them checked and display info to the user 
    ## Below is for UILockdown registry
    try
    {
        if(Test-Path("HKLM:SOFTWARE\Policies\Microsoft\Microsoft Antimalware\UX Configuration"))
        {
            Write-ColorOutput White "   Checking the reg: UILockdown..."            
            $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Microsoft Antimalware\UX Configuration" | Select-Object -ExpandProperty "UILockdown" -ErrorAction SilentlyContinue 
            if($b -eq $null)
            {
                Write-ColorOutput Yellow "   INFO: Did not find 'UILockdown' under 'HKLM:SOFTWARE\Policies\Microsoft\Microsoft Antimalware\UX Configuration'. Goes with default"                
            
            }
            else
            {
               if($b -eq 0)
               {

                    Write-ColorOutput Green "   Group Policy Notification settings for UI lockdown is disabled. Looks Good"                                
                
               }
               else
               {
                    Write-ColorOutput Yellow "   WARNING: Group policy settings for UILockdown is enabled. "                 
                    Write-ColorOutput Yellow "   Please contact your administrator in case no DLP toast is seen"
                
               }
            }


            ### Post June 2020 MoCAMP, these GP controlled registries will not impact DLP toast display
            ## However, have them checked and display info to the user 
            ## Below is for Notification_Suppress registry
            Write-ColorOutput White "   Checking the reg: Notification_Suppress..."            
            $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Microsoft Antimalware\UX Configuration" | Select-Object -ExpandProperty "Notification_Suppress" -ErrorAction SilentlyContinue 
            if($b -eq $null)
            {
                Write-ColorOutput Yellow "   INFO: Did not find 'Notification_Suppress' under 'HKLM:SOFTWARE\Policies\Microsoft\Microsoft Antimalware\UX Configuration'. Goes with default"                
            }
            else
            {
               if($b -eq 0)
               {

                    Write-ColorOutput Green "   Group Policy Notification settings for Notification supress is disabled. Looks Good"                
               }
               else
               {
                    Write-ColorOutput Yellow "   WARNING: Group policy settings for Notification Supress is enabled "                 
                    Write-ColorOutput Yellow "   Please contact your administrator in case no DLP toast is observed"
                
               }
            }

        }
        else
        {            
            Write-ColorOutput Yellow "   INFO: Did not find the reg path 'HKLM:SOFTWARE\Policies\Microsoft\Microsoft Antimalware\UX Configuration'. Goes with default"            
        }
       
    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying the GPM UILockdown/Notification_Suppress reg settings "
        return
    }


    Write-ColorOutput White " "
    Write-ColorOutput White " "
        
    ### Do the same reg check but this time under WDAV reg path
    try
    {
        if(Test-Path("HKLM:SOFTWARE\Microsoft\Windows Defender\UX Configuration"))
        {

            $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Defender\UX Configuration" | Select-Object -ExpandProperty "UILockdown" -ErrorAction SilentlyContinue 
            if($b -eq $null)
            {
                Write-ColorOutput Yellow "   INFO: Did not find 'UILockdown' under 'HKLM:SOFTWARE\Microsoft\Windows Defender\UX Configuration'. Goes with default"                
            
            }
            else
            {
               if($b -eq 0)
               {
                    Write-ColorOutput Green "   WDAV settings for UI lockdown is disabled. Looks Good"                                                
               }
               else
               {
                    Write-ColorOutput Yellow "   WARNING: WDAV settings for UILockdown is enabled. "                 
                    Write-ColorOutput Yellow "   Please contact your administrator in case no DLP toast is observed"                
               }
            }
        }
        else
        {            
            Write-ColorOutput Yellow "   INFO: Did not find the reg path 'HKLM:SOFTWARE\Microsoft\Windows Defender\UX Configuration'. Goes with default"                    
        }


        $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows Defender\UX Configuration" | Select-Object -ExpandProperty "Notification_Suppress" -ErrorAction SilentlyContinue 
        if($b -eq $null)
        {
            Write-ColorOutput Yellow "   Did not find 'Notification_Suppress' under 'HKLM:SOFTWARE\Microsoft\Windows Defender\UX Configuration'. Goes with default"            
            
        }
        else
        {
           if($b -eq 0)
           {

                Write-ColorOutput Green "   WDAV Notification settings for Notification supress is disabled. Looks Good"                                
                
           }
           else
           {
                Write-ColorOutput Yellow "   WARNING: WDAV settings for Notification Supress is enabled "                 
                Write-ColorOutput Yellow "   Please contact your administrator in case no DLP toast is observed"
                
           }
        }

    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying the WDAV UILockdown reg settings "
    }

    Write-ColorOutput White " "
    Write-ColorOutput White " "

}




############################################################################################

### FUNCTION: CHECKS IF TOAST SETTINGS ARE ENABLED OR DISABLED

############################################################################################

function CheckNotificationSettings
{

    Write-ColorOutput Cyan "CHECKING NOTIFICATION SETTINGS:"
    Write-ColorOutput White " "
        

    #### ToastEnabled reg check    
    try
    {
        if(Test-Path("HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications"))
        {
            Write-ColorOutput White "   Checking ToastEnabled reg key settings..."
            $b = Get-ItemProperty -Path "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" | Select-Object -ExpandProperty "ToastEnabled" -ErrorAction SilentlyContinue 
            if($b -eq $null)
            {
                Write-ColorOutput Yellow "   INFO: Missing 'ToastEnabled' under 'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications'. Goes with default"
                Write-ColorOutput Yellow "   INFO: If still no toast, please try enabling 'Settings->System->Notification & Action->Get notifications from apps'"                           
            
            }
            else
            {
               if($b -eq 1)
               {
                    Write-ColorOutput Green "   Notification settings (ToastEnabled) is enabled. Looks Good"                
               }
               else
               {
                    Write-ColorOutput Yellow "   WARNING: Notification settings for toast not enabled. You may not see DLP toasts for  block/warn operations"                 
                    Write-ColorOutput Yellow "   Goto Settings -> System -> Notification & Action -> Enable the Notification button for better DLP experience"
               }
            }
            
        }
        else
        {
            Write-ColorOutput Yellow "   INFO: Did not find the reg path 'HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications' for 'ToastEnabled'"            
        }
        
    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying the toast settings "
    }

    
    Write-ColorOutput White " "
        
    try
    {
        
        if(Test-Path("HKCU:SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"))
        {

            Write-ColorOutput White "   Checking NoToastApplicationNotification reg key settings..."

            $b = Get-ItemProperty -Path "HKCU:SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" | Select-Object -ExpandProperty "NoToastApplicationNotification" -ErrorAction SilentlyContinue 
            if($b -eq $null)
            {
                Write-ColorOutput Yellow "   Missing NoToastApplicationNotification registry under the path 'HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'"
                Write-ColorOutput Green "   INFO: Policy not set to disable DLP toasts, looks good. If still issue with toasts, please contact your administrator"           
                            
            }
            else
            {

                if($b -eq 1)
               {
                    Write-ColorOutput Yellow "   WARN: Notification settings NoToastApplicationNotification is enabled"    
                    Write-ColorOutput Yellow "   Policies set to disable toast notification. You may not see DLP toasts for block/warn operations. Please contact your administrator"                                             
               }
               else
               {
                    Write-ColorOutput Yellow "   Policies set to enabled toast the notification. Looks Good."                                             
               }
            }
        }
        else
        {
            Write-ColorOutput Yellow "   INFO: Did not find the reg path 'HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' for 'NoToastApplicationNotification'"           
            
        }
    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying the toast settings "
    }

}




############################################################################################

### FUNCTION: CHECKS IF DLP SHOW DIALOG REG IS ENABLED OR NOT 

############################################################################################

function CheckDLPShowDialog
{

    Write-ColorOutput Cyan "CHECKING DLP DIALOG BOX SETTINGS:"
    Write-ColorOutput White " "
    
    try
    {
        if(-Not(Test-Path("HKLM:software\microsoft\windows defender\Miscellaneous Configuration")))
        {
            
            Write-ColorOutput Red "   ERROR: Reg path not found. HKLM:software\microsoft\windows defender\Miscellaneous Configuration'"
            return
        }
        
        
        $b = Get-ItemProperty -Path "HKLM:software\microsoft\windows defender\Miscellaneous Configuration" | Select-Object -ExpandProperty "DlpShowDialogs" -ErrorAction SilentlyContinue 
        if( ($b -eq $null) -or ($b -eq 1) )
        {

            if($b -eq $null)
            {
                Write-ColorOutput Yellow "   INFO: DlpShowDialogs is missing. Default behavior is to show error dialog boxes for DLP operations "            
            }
            else
            {
                Write-ColorOutput Yellow "   INFO: DlpShowDialogs is set to 1. Shows the error dialog boxes for DLP operations "            
            }
            return
        }
        else
        {
            Write-ColorOutput Yellow "   INFO: DlpShowDialogs reg is set to 0. Error dialog box will be suppressed for DLP operations "                                 
           
        }
    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying the toast settings "
    }

}




############################################################################################

### FUNCTION: CHECKS IF INBOX OS BACKPORT CHANGES ARE AVAILABLE OR MISSING ON THIS PC

############################################################################################

function DLPInboxChangesBackportedToOS
{
    Write-ColorOutput Cyan "DLP INBOX BACKPORT CHANGE VERIFICATION:"
    Write-ColorOutput White " "
    
    [string]$BackPortFile = join-path $env:windir "System32"
    $BackPortFile = join-path $BackPortFile $global:DLPBackPortFile 


    #Write-ColorOutput White " Filepath is: $BackPortFile "
    if(Test-Path($BackPortFile))
    {        
        Write-ColorOutput Green "   DLP Inbox backport changes. Looks good"
        Write-ColorOutput White " "   
        
    }
    else
    {
        Write-ColorOutput Red "   DLP Inbox backport changes seems missing on this PC. DLP user experience may not be as expected on this device"
        Write-ColorOutput Yellow "   Windows Upgrade might be helpful"
    }
    
 }




############################################################################################

### FUNCTION: CHECKS THE CONFIGURATION FOR BEHAVIOUR MONITORING UNDER POLICY MANAGER

############################################################################################

function CheckBMConfig_PolManager
{

    Write-ColorOutput Cyan "BEHAVIOR MONITORING CONFIGURATION CHECK [POLICY MANAGER]:"
    Write-ColorOutput White " "
    
    try
    {

        Write-ColorOutput White "   Checking Behavior and Realtime Monitoring registry settings under policy manager "

        if(-Not(Test-Path("HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager")))
        {
            
            Write-ColorOutput Red "   INFO: Did not find the reg path 'SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'"
            return
        }
        
        
        $a = Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" | Select-Object -ExpandProperty "AllowBehaviorMonitoring" -ErrorAction SilentlyContinue 
        if($a -eq $null)
        {
            Write-ColorOutput Yellow "   INFO: Missing Allow Behavior Monitoring regkey under the path 'HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'"
            
        }
        else
        {
           if($a -eq 1)
           {

                Write-ColorOutput Green "   Behavior Monitoring settings under policy manager is enabled. Looks Good"                                
                
           }
           else
           {
                Write-ColorOutput Red "   WARN: Behavior Monitoring settings under policy manager is disabled"                                 
                
           }
        }
        Write-ColorOutput White " "
        

        $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" | Select-Object -ExpandProperty "AllowRealtimeMonitoring" -ErrorAction SilentlyContinue 
        if($b -eq $null)
        {
            Write-ColorOutput Yellow "   INFO: Missing Allow RealTime Monitoring regkey under the path 'HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'"            
        }
        else
        {
           if($a -eq 1)
           {

                Write-ColorOutput Green "   Realtime Monitoring settings under policy manager is enabled. Looks Good"                                
                
           }
           else
           {
                Write-ColorOutput Red "   WARN: Realtime Monitoring settings under policy manager is disabled"                                 
                
           }
        }
        Write-ColorOutput White " "
        Write-ColorOutput White " "

        
        
    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying or adding reg keys to onboard SENSE OS"
    }    
}



############################################################################################

### FUNCTION: CHECKS THE POLICY CONFIGURATION FOR BEHAVIOUR MONITORING

############################################################################################

function CheckBMConfig
{

    Write-ColorOutput Cyan "BEHAVIOR MONITORING CONFIGURATION CHECK:"
    Write-ColorOutput White " "
    
    try
    {

        Write-ColorOutput White "   Checking Behavior and Realtime Monitoring registry settings under RTP policies..."

        if(-Not(Test-Path("HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\real-time protection")))
        {
            
            Write-ColorOutput Yellow "   INFO: Did not find the reg path 'SOFTWARE\Policies\Microsoft\Windows Defender\real-time protection'"
            return            
        }
        
        
        $a = Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\real-time protection" | Select-Object -ExpandProperty "DisableBehaviorMonitoring" -ErrorAction SilentlyContinue 
        if($a -eq $null)
        {
            Write-ColorOutput Yellow "   Missing Behavior Monitoring regkey under the path 'HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\real-time protection'"
            Write-ColorOutput Yellow "   DLP user experience may not be as expected "            
        }

        $b = Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\real-time protection" | Select-Object -ExpandProperty "DisableRealTimeMonitoring" -ErrorAction SilentlyContinue 
        if($b -eq $null)
        {
            Write-ColorOutput Yellow "   Missing RealTime Monitoring regkey under the path 'HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\real-time protection'"
            Write-ColorOutput Red "   DLP toasts may not work on this PC"
            $global:bDLPMinReqOS = $false            
            return
        }
        
        Write-ColorOutput Green "   Reg settings for Behaviour and Realtime Monitoring are enabled. Looks Good "           
        
    }
    catch [System.exception]
    {
        Write-ColorOutput Red "   Exception while querying or adding reg keys to onboard SENSE OS"
    }
}




# function to read Registry Value
function Get-RegistryValue { param (
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]$Path,
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]$Value
    )

    if (Test-Path -path $Path) {
        return Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction silentlycontinue
    } else {
        return $false
    }
}





############################################################################################

### FUNCTION: CHECKS IF DLP POLICIES CONFIGURED FOR A SPECIFIC DLP ACTION TYPE

############################################################################################

function policychecker($CheckPolicyLogFile, $StrB, $StrW, $StrA, $Category)
{

    if ( (Get-Content -Path $CheckPolicyLogFile).Contains($StrB) -and
         (Get-Content -Path $CheckPolicyLogFile).Contains($StrW) -and
         (Get-Content -Path $CheckPolicyLogFile).Contains($StrA) )
            
    {
        Write-ColorOutput Yellow "   DLP Feature: $Category"
        Write-ColorOutput Green "    -- All Block/Warn/Audit policies found"
    }
    elseif(
            (Get-Content -Path $CheckPolicyLogFile).Contains($StrB) -or
            (Get-Content -Path $CheckPolicyLogFile).Contains($StrW) -or
            (Get-Content -Path $CheckPolicyLogFile).Contains($StrA) )
             
    {
    
        Write-ColorOutput Yellow "   DLP Feature: $Category"
        if(-Not((Get-Content -Path $CheckPolicyLogFile).Contains($StrB)))
       {
            
            Write-ColorOutput Yellow "   -- Block policy not found"
       }
       else
       {
            Write-ColorOutput Green "   -- Block policy found"
       }

       if(-Not((Get-Content -Path $CheckPolicyLogFile).Contains($StrW)))
       {
            Write-ColorOutput Yellow "   -- Warn policy not found"
            
       }
       else
       {
            Write-ColorOutput Green "   -- Warn policy found"
       }


       if(-Not((Get-Content -Path $CheckPolicyLogFile).Contains($StrA)))
       {
            Write-ColorOutput Yellow "   -- Audit policy not found"
       }
       else
       {
            Write-ColorOutput Green "   -- Audit policy found"
       }           

    }
    else
    {   
        Write-ColorOutput Yellow "    DLP Feature: $Category "
        Write-ColorOutput Red "    -- No policies found for this feature"
    }
}





############################################################################################

### FUNCTION: FUNCTION TO CHECK MACHINE LEVEL DLP POLICES

############################################################################################

function CheckDeviceDLPPolicies($CheckPolicyLogFile)
{
        
        if(Test-Path $CheckPolicyLogFile)
        {
            $USBBlock = 'CopyToRemovableMedia":{"EnforcementMode":3}'
            $USBWarn = 'CopyToRemovableMedia":{"EnforcementMode":2}'
            $USBAudit = 'CopyToRemovableMedia":{"EnforcementMode":1}'
            policychecker $CheckPolicyLogFile $USBBlock $USBWarn $USBAudit "CopyToRemovableMedia"
            Write-ColorOutput White " "
            

            $NetworkBlock = 'CopyToNetworkShare":{"EnforcementMode":3}'
            $NetworkWarn = 'CopyToNetworkShare":{"EnforcementMode":2}'
            $NetworkAudit = 'CopyToNetworkShare":{"EnforcementMode":1}'
            policychecker $CheckPolicyLogFile $NetworkBlock $NetworkWarn $NetworkAudit "CopyToNetworkShare"
            Write-ColorOutput White " " 

            
            $ClipboardBlock = 'CopyToClipboard":{"EnforcementMode":3}'
            $ClipboardWarn = 'CopyToClipboard":{"EnforcementMode":2}'
            $ClipboardAudit = 'CopyToClipboard":{"EnforcementMode":1}'
            policychecker $CheckPolicyLogFile $ClipboardBlock $ClipboardWarn $ClipboardAudit "CopyToClipboard"
            Write-ColorOutput White " "


            $PrintBlock = 'Print":{"EnforcementMode":3}'
            $PrintWarn = 'Print":{"EnforcementMode":2}'
            $PrintAudit = 'Print":{"EnforcementMode":1}'
            policychecker $CheckPolicyLogFile $PrintBlock $PrintWarn $PrintAudit "Print"
            Write-ColorOutput White " "


            $UnallAppBlock = 'AccessByUnallowedApps":{"EnforcementMode":3}'
            $UnallAppWarn = 'AccessByUnallowedApps":{"EnforcementMode":2}'
            $UnallAppAudit = 'AccessByUnallowedApps":{"EnforcementMode":1}'
            policychecker $CheckPolicyLogFile $UnallAppBlock $UnallAppWarn $UnallAppAudit "AccessByUnallowedApps"
            Write-ColorOutput White " "
            
            $BluetoothAppBlock = 'UnallowedBluetoothTransferApps":{"EnforcementMode":3}'
            $BluetoothAppWarn = 'UnallowedBluetoothTransferApps":{"EnforcementMode":2}'
            $BluetoothAppAudit = 'UnallowedBluetoothTransferApps":{"EnforcementMode":1}'
            policychecker $CheckPolicyLogFile $BluetoothAppBlock $BluetoothAppWarn $BluetoothAppAudit "AccessByBluetoothApp"
            Write-ColorOutput White " "

            $RDPAppBlock = 'RemoteDesktopAccess":{"EnforcementMode":3}'
            $RDPAppWarn = 'RemoteDesktopAccess":{"EnforcementMode":2}'
            $RDPAppAudit = 'RemoteDesktopAccess":{"EnforcementMode":1}'
            policychecker $CheckPolicyLogFile $RDPAppBlock $RDPAppWarn $RDPAppAudit "RemoteDesktopAccess"
            Write-ColorOutput White " "            
           
        }
        else
        {
            Write-ColorOutput "    WARN: DLP device policy log not generated "
            return
        }
}




###############################################################################################################

### FUNCTION: FUNCTION TO POPULATE MACHINE LEVEL DLP RULES AND POLICES (PARSE REG SETTING AS PLAIN STRING)

#############################################################################################################

function PopulateDLPPolicies($CheckPolicyLogFile)
{

    Write-ColorOutput Cyan "POPULATE DLP POLICES:"
    if(-Not(Test-Path($CheckPolicyLogFile)))
    {
        Write-ColorOutput Red "dlp policy file not found. Can't popluate policies. Skipping..."
        return        
    }


    $line = Get-Content $CheckPolicyLogFile    
    
    
    ## PARSE ENLIGHTENED APPS LIST  
    $indx = $line.IndexOf("EnlightenedApplications")    
    if($indx -ge 0)
    {
        Write-ColorOutput white " "
        Write-ColorOutput yellow "ENLIGHTENED APPLICATIONS:"
        Write-ColorOutput white "------------------------"
        $line = $line.Substring($indx)        
        $startIndx = $line.IndexOf('[')
        $endIndx = $line.IndexOf(']')

        $enlightenStr = $line.Substring($startIndx+1, $endIndx - $startIndx + 1)
        $line = $line.Substring($endIndx)        
        #Write-ColorOutput yellow "enlighten string is $enlightenStr "
        
        $arr = $enlightenStr.Split('}')       
        for($i = 0; $i -lt $arr.count -1; $i++) 
        {
            if($i -eq 0) 
            {
                $temp = $arr[$i].Substring(1)
            }
            else
            {
                $temp = $arr[$i].Substring(2)
            }
            Write-ColorOutput white " $temp"
        }
    }


      
    ## PARSE UNALLOWED APPS LIST    
    Write-ColorOutput white " "  
    $indx = $line.IndexOf("UnallowedApplications")    
    if($indx -ge 0)
    {
        Write-ColorOutput white " "
        Write-ColorOutput yellow "UNALLOWED APPLICATIONS:"
        Write-ColorOutput white "--------------------"
    
        $line = $line.Substring($indx)        
        $startIndx = $line.IndexOf('[')
        $endIndx = $line.IndexOf(']')

       
        $unallowedStr = $line.Substring($startIndx+1, $endIndx - $startIndx + 1)
        $line = $line.Substring($endIndx)          
        
        #Write-ColorOutput yellow "Unallowed apps string is $unallowedStr "
                       
        $arr = $unallowedStr.Split('}')
        for($i = 0; $i -lt $arr.count - 1; $i++) 
        {
            if($i -eq 0) 
            {
                $temp = $arr[$i].Substring(1)
            }
            else
            {
                $temp = $arr[$i].Substring(2)
            }
            Write-ColorOutput white " $temp"
        }    
    }      

         
    ## PARSE UNALLOWED BROWSERS LIST
    Write-ColorOutput white " "
    $indx = $line.IndexOf("UnallowedBrowsers")    
    if($indx -ge 0)
    {
        Write-ColorOutput white " "
        Write-ColorOutput yellow "UNALLOWED BROWSERS:"
        Write-ColorOutput white "------------------"
        $line = $line.Substring($indx)        
        $startIndx = $line.IndexOf('[')
        $endIndx = $line.IndexOf(']')

        $unallowedBrowserStr = $line.Substring($startIndx+1, $endIndx - $startIndx + 1)
        $line = $line.Substring($endIndx)        

        #Write-ColorOutput yellow "Unallowed browser string is $unallowedBrowserStr "
        
        $arr = $unallowedBrowserStr.Split('}')
        for($i = 0; $i -lt $arr.count - 1; $i++) 
        {
            if($i -eq 0) 
            {
                $temp = $arr[$i].Substring(1)
            }
            else
            {
                $temp = $arr[$i].Substring(2)
            }
            Write-ColorOutput white " $temp"
        }            
    }


    ## PARSE CLOUD APP DOMAINS LIST
    Write-ColorOutput white " "
    $indx = $line.IndexOf("Domains")    
    if($indx -ge 0)
    {
        Write-ColorOutput white " "
        Write-ColorOutput yellow "CLOUD APP DOMAINS INFO:"
        Write-ColorOutput white "------------------"
        
        $line = $line.Substring($indx)        
        $startIndx = $line.IndexOf('[')
        $endIndx = $line.IndexOf(']')

        $CloudAppsDomainsStr = $line.Substring($startIndx+1, $endIndx - $startIndx + 1)
        $line = $line.Substring($endIndx)        

        #Write-ColorOutput yellow "Unallowed cloud app domains string is $unallowedDomainsStr "
        
        $arr = $CloudAppsDomainsStr.Split('}')
         
        for($i = 0; $i -lt $arr.count - 2; $i++) 
        {
            if($i -eq 0) 
            {
                $temp = $arr[$i].Substring(1)
            }
            else
            {
                $temp = $arr[$i].Substring(2)
            }
            Write-ColorOutput white " $temp"
        }            
    }



    ## PARSE BLUETOOTH APPS LIST 
    Write-ColorOutput white " "
    $indx = $line.IndexOf("UnallowedBluetoothApps")    
    if($indx -ge 0)
    {
        Write-ColorOutput white " "
        Write-ColorOutput yellow "UNALLOWED BLUETOOTH APPS:"
        Write-ColorOutput white "--------------------"
    
        $line = $line.Substring($indx)        
        $startIndx = $line.IndexOf('[')
        $endIndx = $line.IndexOf(']')

       
        $unallowedBtStr = $line.Substring($startIndx+1, $endIndx - $startIndx + 1)
        $line = $line.Substring($endIndx)          
        
        #Write-ColorOutput yellow "Unallowed apps string is $unallowedStr "
                       
        $arr = $unallowedBtStr.Split('}')
        for($i = 0; $i -lt $arr.count - 1; $i++) 
        {
            if($i -eq 0) 
            {
                $temp = $arr[$i].Substring(1)
            }
            else
            {
                $temp = $arr[$i].Substring(2)
            }
            Write-ColorOutput white " $temp"
        }    
    }
    
    ## PARSE UNALLOWED CLOUD SYNC APPS LIST
    Write-ColorOutput white " "
    $indx = $line.IndexOf("UnallowedCloudSyncApps")    
    if($indx -ge 0)
    {
        Write-ColorOutput white " "
        Write-ColorOutput yellow "UNALLOWED CLOUDSYNC APPS:"
        Write-ColorOutput white "--------------------"
    
        $line = $line.Substring($indx)        
        $startIndx = $line.IndexOf('[')
        $endIndx = $line.IndexOf(']')

       
        $unallowedCloudSyncStr = $line.Substring($startIndx+1, $endIndx - $startIndx + 1)
        $line = $line.Substring($endIndx)          
        
        #Write-ColorOutput yellow "Unallowed apps string is $unallowedStr "
                       
        $arr = $unallowedCloudSyncStr.Split('}')
        for($i = 0; $i -lt $arr.count - 1; $i++) 
        {
            if($i -eq 0) 
            {
                $temp = $arr[$i].Substring(1)
            }
            else
            {
                $temp = $arr[$i].Substring(2)
            }
            Write-ColorOutput white " $temp"
        }    
    }



    ## PARSE Quarantine Settings
    Write-ColorOutput white " "
    $indx = $line.IndexOf("QuarantineSettings")    
    if($indx -ge 0)
    {
        Write-ColorOutput white " "
        Write-ColorOutput yellow "QUARANTINE SETTINGS:"
        Write-ColorOutput white "--------------------"
    
        $line = $line.Substring($indx)        
        $startIndx = $line.IndexOf('{')
        $endIndx = $line.IndexOf('}')

       
        $QuarantineStr = $line.Substring($startIndx+1, $endIndx - $startIndx + 1)
        $line = $line.Substring($endIndx)          
        
        #Write-ColorOutput yellow "Quarantine settings string is -> $QuarantineStr "
                       

        $arr = $QuarantineStr.Split(',')
        $replacementStr = ""
        $replacementExists = $false
        for($i = 0; $i -lt $arr.count - 1; $i++) 
        {
            $temp = $arr[$i]
            if($i -le 2)
            {
                Write-ColorOutput white " $temp"
            }
            else
            {
                $replacementExists = $true
                $replacementStr = $replacementStr + $temp + ","               
            }
        }

        if($replacementExists -eq $true)
        {
            $temp = $replacementStr.Substring(0, $replacementStr.Length-2)
            Write-ColorOutput white " $temp"
        }          
        
    }


    ## PARSE DLP POLICIES 
    $indx = $line.IndexOf('"Policies":')    
    if($indx -ge 0)
    {

        $line = $line.Substring($indx)        
        $startIndx = $line.IndexOf('"Id"')
        $endIndx = $line.IndexOf(']')

        $PoliciesStr = $line.Substring($startIndx, $endIndx - $startIndx + 1)
        $line = $line.Substring($endIndx)        

        #Write-ColorOutput yellow "Unallowed browser string is $PoliciesStr "
        
        $arr = $PoliciesStr.Split(',')
        if($arr.count -gt 0)
        {
            Write-ColorOutput white " "
            Write-ColorOutput white " "
            Write-ColorOutput yellow "CURRENT POLICIES APPLIED:" 
            Write-ColorOutput white "------------------------"                      
        }


        foreach($aaa in $arr) 
        {
            if($aaa.contains('"Id"')) 
            {
                Write-ColorOutput white " "                
                Write-ColorOutput white "   ---------------------"                
                $aaa = $aaa.substring(1)
                Write-ColorOutput white "   $aaa"
                
            }
            elseif($aaa.contains('PolicyName')) 
            {
                Write-ColorOutput yellow "   $aaa"                                        
            }
            elseif($aaa.contains('RuleName')) 
            {
                Write-ColorOutput white "   $aaa"
                Write-ColorOutput white " "                
                
            }            
            else
            {
                if($aaa.contains('"Actions":{')) 
                {
                    $aaa = $aaa.replace('"Actions":{', '')
                    Write-ColorOutput white "   -> $aaa"                    
                }
                else
                {
                    Write-ColorOutput white "   -> $aaa"
                }
            }
        }            
    }
   
    
    if(Test-Path($CheckPolicyLogFile))
    {
        Remove-Item $CheckPolicyLogFile -Force -ErrorAction SilentlyContinue
    }

    Write-ColorOutput Cyan "POPULATE DLP POLICES COMPLETE:"    

}



###################################################################################################

### FUNCTION: FUNCTION TO POPULATE MACHINE LEVEL DLP RULES AND POLICES (PARSE REG SETTING AS JSON)

###################################################################################################

function PopulateDLPPolicies-Json($policyBodyCmd) 
{

    $params = $policyBodyCmd.paramsstr | ConvertFrom-Json	
	#$PolicyJson = $params | ConvertTo-Json -Depth 20
    $PolicyJson = $params.policy 	
    
     Write-ColorOutput Cyan "POPULATE DLP POLICES:"
   
    
    #####
    #####  SECTION 1 - Englightened apps info
    ##### 
    $enlightenedList = $PolicyJson.EnlightenedApplications
    $ItemCount = $enlightenedList.Count

     Write-ColorOutput white " "
     Write-ColorOutput yellow "ENLIGHTENED APPLICATIONS:"
     Write-ColorOutput white "--------------------------"    
 
    if($ItemCount -gt 0)
     {
       
        for($i=0; $i -lt $ItemCount; $i++){

            $CurItem = $enlightenedList.item($i)
            Write-ColorOutput white " $CurItem"

        }
     }
     else
     {
         Write-ColorOutput white " NONE"
     }


    
    #####
    #####  SECTION 2 - Unallowed apps info
    #####     
    $unallowedAppsList = $PolicyJson.UnallowedApplications
    $ItemCount = $unallowedAppsList.Count

     Write-ColorOutput white " "
     Write-ColorOutput yellow "UNALLOWED APPLICATIONS:"
     Write-ColorOutput white "--------------------------"    
 
    if($ItemCount -gt 0)
     {
       
        for($i=0; $i -lt $ItemCount; $i++){

            $CurItem = $unallowedAppsList.item($i)
            Write-ColorOutput white " $CurItem"

        }
     }
     else
     {
         Write-ColorOutput white " NONE"
     }


    #####
    #####  SECTION 3 - Unallowed browsers info
    ##### 
    $unallowedBrowsersList = $PolicyJson.UnallowedBrowsers
    $ItemCount = $unallowedBrowsersList.Count

     Write-ColorOutput white " "
     Write-ColorOutput yellow "UNALLOWED BROWSERS:"
     Write-ColorOutput white "--------------------------"    
 
    if($ItemCount -gt 0)
     {
       
        for($i=0; $i -lt $ItemCount; $i++){

            $CurItem = $unallowedBrowsersList.item($i)
            Write-ColorOutput white " $CurItem"

        }
     }
     else
     {
         Write-ColorOutput white " NONE"
     }



    #####
    #####  SECTION 4 - Cloud Apps Domain Info
    ##### 
    $CloudAppDomainsJson = $PolicyJson.CloudAppDomains
    $CloudAppDomainsList = $CloudAppDomainsJson.Domains

    Write-ColorOutput white " "
    Write-ColorOutput yellow "CLOUD APP DOMAINS INFO:"
    Write-ColorOutput white "------------------------"

    $ItemCount = $CloudAppDomainsList.Count
     if($ItemCount -gt 0)
     {       

        for($i=0; $i -lt $ItemCount; $i++){

            $CurItem = $CloudAppDomainsList.item($i)
            Write-ColorOutput white " $CurItem"

        }
     }
     else
     {
         Write-ColorOutput white " NONE"
     }
   

    #####
    #####  SECTION 5 - Unallowed Bluetooth apps info
    ##### 
    $unallowedBTList = $PolicyJson.UnallowedBluetoothApps
    $ItemCount = $unallowedBTList.Count

     Write-ColorOutput white " "
     Write-ColorOutput yellow "UNALLOWED BLUETOOTH APPS:"
     Write-ColorOutput white "--------------------------"    
 
    if($ItemCount -gt 0)
     {
       
        for($i=0; $i -lt $ItemCount; $i++){

            $CurItem = $unallowedBTList.item($i)
            Write-ColorOutput white " $CurItem"

        }
     }
     else
     {
         Write-ColorOutput white " NONE"
     }


    #####
    #####  SECTION 6 - Unallowed Cloud sync apps info
    ##### 
    $cloudSyncAppsList = $PolicyJson.UnallowedCloudSyncApps
    $ItemCount = $cloudSyncAppsList.Count

     Write-ColorOutput white " "
     Write-ColorOutput yellow "UNALLOWED CLOUD SYNC APPS:"
     Write-ColorOutput white "--------------------------"    
 
    if($ItemCount -gt 0)
     {
       
        for($i=0; $i -lt $ItemCount; $i++){

            $CurItem = $cloudSyncAppsList.item($i)
            Write-ColorOutput white " $CurItem"

        }
     }
     else
     {
         Write-ColorOutput white " NONE"
     }

    #####
    #####  SECTION 7 - Quarantine Settings Info
    ##### 
    $QuarantineSettings = $PolicyJson.QuarantineSettings
    Write-ColorOutput white " "
    Write-ColorOutput yellow "QUARANTINE SETTINGS:"
    Write-ColorOutput white "--------------------------"    
    if($QuarantineSettings -ne $null)
    {
        $a = $QuarantineSettings.EnableForCloudSyncApps
        Write-ColorOutput white "EnableForCloudSyncApps: $a"

        $a = $QuarantineSettings.QuarantinePath        
        Write-ColorOutput white "QuarantinePath: $a"

        $a = $QuarantineSettings.ShouldReplaceFile        
        Write-ColorOutput white "ShouldReplaceFile: $a"
        
        $a = $QuarantineSettings.FileReplacementText        
        Write-ColorOutput white "FileReplacementText: $a"

    }
    else
    {
        Write-ColorOutput white " NONE"
    }


    #####
    #####  SECTION 8 - DLP POLICIES 
    ##### 

    $dlpPoliciesList = $PolicyJson.Policies
    $ItemCount = $dlpPoliciesList.Count

     Write-ColorOutput white " "
     Write-ColorOutput yellow "CURRENT POLICIES APPLIED:"
     Write-ColorOutput white "--------------------------"    
 
    if($ItemCount -gt 0)
     {
       
        for($i=0; $i -lt $ItemCount; $i++){

            $CurItem = $dlpPoliciesList.item($i)

            Write-ColorOutput white " -------------------------------"      

            $a = $CurItem.Id
            Write-ColorOutput white "    Id: $a"

            $a = $CurItem.PolicyName
            Write-ColorOutput white "    PolicyName: $a"

            $a = $CurItem.RuleName
            Write-ColorOutput white "    RuleName: $a"
           
            $a = $CurItem.RequireBusinessJustificationOverride
            Write-ColorOutput white "    RequireBusinessJustificationOverride: $a"

            $a = $CurItem.PolicyTipTitleList
            Write-ColorOutput white "    PolicyTipTitleList: $a"

            $a = $CurItem.PolicyTipContentList
            Write-ColorOutput white "    PolicyTipContentList: $a"

            
            Write-ColorOutput white " "  
            Write-ColorOutput white "    Actions:"  
            
            $a = $CurItem.Actions.CopyToRemovableMedia.EnforcementMode
            Write-ColorOutput white "    -> CopyToRemovableMedia: $a"            
            $a = $CurItem.Actions.CopyToNetworkShare.EnforcementMode
            Write-ColorOutput white "    -> CopyToNetworkShare: $a"            
            $a = $CurItem.Actions.CopyToClipboard.EnforcementMode
            Write-ColorOutput white "    -> CopyToClipboard: $a"            
            $a = $CurItem.Actions.Print.EnforcementMode
            Write-ColorOutput white "    -> Print: $a"            
            $a = $CurItem.Actions.Screenclip.EnforcementMode
            Write-ColorOutput white "    -> Screenclip: $a"     
            $a = $CurItem.Actions.AccessByUnallowedApps.EnforcementMode
            Write-ColorOutput white "    -> AccessByUnallowedApps: $a"            
            $a = $CurItem.Actions.CloudEgress.EnforcementMode
            Write-ColorOutput white "    -> CloudEgress: $a"            
            $a = $CurItem.Actions.UnallowedBluetoothTransferApps.EnforcementMode
            Write-ColorOutput white "    -> UnallowedBluetoothTransferApps: $a"            
            $a = $CurItem.Actions.RemoteDesktopAccess.EnforcementMode
            Write-ColorOutput white "    -> RemoteDesktopAccess: $a"            
            
            Write-ColorOutput white " -------------------------------"      

        }
     }
     else
     {
         Write-ColorOutput white " NONE"
     }
	
}


############################################################################################

### FUNCTION: READ DLP POLICY FROM REG KEY ON THE DEVICE AND THEN DECOMPRESSES IT

############################################################################################

function ReadDlpPolicy($policyName)
{
    $byteArray = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection' -Name $policyName
    $memoryStream = New-Object System.IO.MemoryStream(,$byteArray)
    $deflateStream = New-Object System.IO.Compression.DeflateStream($memoryStream,  [System.IO.Compression.CompressionMode]::Decompress)
    $streamReader =  New-Object System.IO.StreamReader($deflateStream, [System.Text.Encoding]::Unicode)
    $policyStr = $streamReader.ReadToEnd()
    $policy = $policyStr | ConvertFrom-Json

    
    $policyBodyCmd = ($policy.body | ConvertFrom-Json).cmd 

    Set-Content -Path "dlppol.txt" $policyBodyCmd 
    CheckDeviceDLPPolicies("dlppol.txt")
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White ""
    
    Write-ColorOutput White ""
    Write-ColorOutput White "------------------------------------"
    
    
    
    ## Populate all the dlp policies and rules
    <# There are two ways to to populate policies
        1. Using display tool, redirect output to a text file and finally parse the string from that text file
        2. Directly read dlp policies from registry, convert it to json string and then parse the json        
        Adding option2 and disabling/commenting option1 as maintaining option1 will be difficult as new features gets adde    
    #>

    #PopulateDLPPolicies("dlppol.txt") 
    PopulateDLPPolicies-Json($policyBodyCmd)   
    
}


############################################################################################

### FUNCTION: CHECKS THE BEHAVIOUR MONITOR CONFIGUREAITON 

############################################################################################

function CheckDLPPolices
{

    Write-ColorOutput Cyan "CHECK IF DLP POLICIES ARE SET ON THIS DEVICE:"
    Write-ColorOutput White " "
    
    # Dump DLP related policy information from registry
    if (Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -Value dlpPolicy) 
    {
        ReadDlpPolicy dlppolicy
		#ReadDlpPolicy dlpSensitiveInfoTypesPolicy
	} 
    else 
    {
		Write-Coloroutput Red "    INFO: No DLP polices found in the registry of this machine"
	}
}




############################################################################################

### FUNCTION: CHECK IF THE BUILD IS PR SIGNED OR NOT 

############################################################################################

function CheckBuildPRSigned
{
    Write-ColorOutput Cyan "CHECK IF OS BUILD IS SIGNED OR NOT:"
    Write-ColorOutput White " "

    [string]$Sys32Path = join-path $env:windir "System32"
    $File1 = $Sys32Path + "\services.exe"
    $File2 = $Sys32Path + "\crypt32.dll"
    $File3 = $Sys32Path + "\wow64.dll"   
    $TargetFile = ""
    
    if(Test-Path($File1))
    {
        $TargetFile = $File1
    }
    
    if(($TargetFile -eq "") -and (Test-Path($File2)))
    {
        $TargetFile = $File2
    }
    if(($TargetFile -eq "") -and (Test-Path($File3)))
    {
        $TargetFile = $File3
    }



    if(($TargetFile -ne "") -and (Test-Path($TargetFile)))
    {
        
        $SignedBuild = Get-AuthenticodeSignature $TargetFile
        $SignMsg = $SignedBuild.StatusMessage
        Write-ColorOutput White "   Checking sign on file -> $TargetFile"

        
        if($SignMsg.contains("Signature verified"))
        {
            Write-ColorOutput Green "   The OS Build is signed. Looks Good"            
            
        }
        else
        {
            Write-ColorOutput Red "   The OS Build is does not seem to be signed. DLP may not work"            
            $global:bDLPMinReqOS = $false            
        }
        return
    }
    else
    {
        Write-ColorOutput Yellow "   Samples files taken from System32 does not exists. Try from Windows folder"
        Write-ColorOutput White " "
    }


    ### If can't be verified due to missing bins in System32 folder, then try few more in Windows folder
    $File1 = $env:windir + "\explorer.exe"
    $File2 = $env:windir + "\splwow64.exe"    
    $File3 = $env:windir + "\win.ini"
    $TargetFile = ""
    
    if(Test-Path($File1))
    {
        $TargetFile = $File1
    }
    
    if(($TargetFile -eq "") -and (Test-Path($File2)))
    {
        $TargetFile = $File2
    }
    if(($TargetFile -eq "") -and (Test-Path($File3)))
    {
        $TargetFile = $File3
    }


    if(($TargetFile -ne "") -and (Test-Path($TargetFile)))
    {
        Write-ColorOutput White "   Checking sign on file -> $TargetFile"
        $SignedBuild = Get-AuthenticodeSignature $TargetFile
        $SignMsg = $SignedBuild.StatusMessage
        
        if($SignMsg.contains("Signature verified"))
        {
            Write-ColorOutput Green "   The OS Build is signed. Looks Good"                    
        }
        else
        {
            Write-ColorOutput Red "   The OS Build is does not seem to be signed. DLP may not work"            
            $global:bDLPMinReqOS = $false            
        }
        return
    }
    else
    {
        Write-ColorOutput Yellow "   Samples files taken from Windows folder does not exists "
    }

    Write-ColorOutput Red "   Can't verify if Windows Build is signed or not"    

}




############################################################################################

### FUNCTION: PUTS A FINAL HELP MESSAGE 

############################################################################################

function PrintFinalMessage
{
    
    Write-ColorOutput White " "
    Write-ColorOutput Cyan "ADDITIONAL HELP NOTES:"
    Write-ColorOutput White " "    
    Write-ColorOutput Cyan "********************************************************************************************"
    Write-ColorOutput Yellow "  ==> If issues with DLP still persist after fixing all the above, follow the below steps"
    Write-ColorOutput White " "

    Write-ColorOutput White '   1. Download the MDE Client Analyzer Tool from http://aka.ms/betamdeanalyzer'
    Write-ColorOutput White '   2. Extract the downloaded zip file to any local folder'
    Write-ColorOutput White '   2. Open CMD prompt as admin in above path and run the command "MDEClientAnalyzer.cmd -t"'
    Write-ColorOutput White '   3. Reproduce the issue'
    Write-ColorOutput White '   4. Stop the trace collection'
    Write-ColorOutput White '   5. Share the created MDEClientAnalyzerResult.zip file with the DLP support team'
    Write-ColorOutput White " "
    Write-ColorOutput Cyan "*********************************************************************************************"
    Write-ColorOutput White " "
    Write-ColorOutput White " "
    
    
    Write-ColorOutput White "**********************************************************************************************"
    Write-ColorOutput Yellow "  ==> To check the extended attributes on individual files "
    Write-ColorOutput White " "
    Write-ColorOutput White '   1. Download the MDE Client Analyzer Tool from http://aka.ms/betamdeanalyzer'
    Write-ColorOutput White '   2. Extract the downloaded zip file which contains the tool DisplayExtendedAttributes.exe'
    Write-ColorOutput White '   3. Open cmd as admin and run the command "DisplayExtendedAttributes.exe <filename>"'
    Write-ColorOutput White " "
    Write-ColorOutput White "**********************************************************************************************"
    
    Write-ColorOutput White " "
    
}



function DLPMinReqFromOS
{

    ## Check if Windows Defender and Wd filter are actually running
    Write-ColorOutput White "------------------------------------"
    CheckWDRunning
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 

    
    ## Get Defender Engine version.
    Write-ColorOutput White "------------------------------------"
    GetCurrentEngVersion                     
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " "
    Write-ColorOutput White " " 
    
    
    ## Get Defender MoCAMP version.
    Write-ColorOutput White "------------------------------------"
    GetCurrentMoCAMPVersion
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 
        
    ## Check DLP feature enabled from end client
    Write-ColorOutput White "------------------------------------"
    CheckDLPEnabled
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 
    
    ## Check the OS version 
    Write-ColorOutput White "------------------------------------"
    GetOSBuildNum
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 


    ## Check if reg entries are present to onboard SENSE 
    ## This check is no longer needed for Public Preview phase. 
    <#
    Write-ColorOutput White "------------------------------------"
    CheckSenseOnBoardReg
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 
    #>

    ## Check if BM and RTM flags are set properly
    #Write-ColorOutput White "------------------------------------"
    #CheckBMConfig
    #Write-ColorOutput White "------------------------------------"
    #Write-ColorOutput White " " 
    #Write-ColorOutput White " " 

    ## Check if BM and RTM flags are set properly under policy manager reg path
    #Write-ColorOutput White "------------------------------------"
    #CheckBMConfig_PolManager
    #Write-ColorOutput White "------------------------------------"
    #Write-ColorOutput White " " 
    #Write-ColorOutput White " " 


    ## Check if the build is PR signed
    #Write-ColorOutput White "------------------------------------"
    #CheckBuildPRSigned
    #Write-ColorOutput White "------------------------------------"
    #Write-ColorOutput White " " 
    #Write-ColorOutput White " "     
    
}


############################################################################################

### MAIN: ENTRY POINT TO THE SCRIPT

############################################################################################

try
{

    $arch = ($env:PROCESSOR_ARCHITECTURE)    # Get the OS architecture.
    
    
    ## LOGGING RELATED   
    ############################################  
    if ( -Not(Test-Path -Path $global:DLP_DIAGNOSE_LOGPATH) )
    {
        try
        {
            New-Item -Path $global:DLP_DIAGNOSE_LOGPATH -ItemType Directory | Out-Null
            Start-Sleep -s 2
            #Write-ColorOutput Yellow ("    INFO: Folder created $global:DLP_DIAGNOSE_LOGPATH")   
        }
        catch [System.Exception]
        {
            Write-ColorOutput Red  "    ERROR: Failed to create the directory: $global:DLP_DIAGNOSE_OUTPUT_LOG "
            Write-ColorOutput Yellow  "    WARN: Continuing the script without logging to a file "            
        }
    }

    [string]$OutputLogFileName = "DLPDiagnosing" + (Get-Date -Format "MMddyyyy-HHmmss").ToString() + ".log"
    #Write-ColorOutput Yellow "    File name is --> $OutputLogFileName"

    $global:LogFileName = join-path $global:DLP_DIAGNOSE_LOGPATH  $OutputLogFileName     
    #Write-ColorOutput Yellow "    File path is -->  $global:LogFileName"

    try
    {
        $logF = New-Item $global:LogFileName 
        #Write-ColorOutput Yellow "    Logging to a file started: $global:LogFileName"
    }
    catch [System.Exception]
    {
        Write-ColorOutput Red ("ERROR: Failed to create the log file. Exiting")   
        return
    }
    ############################################
        
    
    Write-ColorOutput White " "   
    Write-ColorOutput cyan "DLP Quick diagnosis ($arch) started..."


    Write-ColorOutput White " " 
    Write-ColorOutput White " " 

    ## Displays machine information 
    Write-ColorOutput White "------------------------------------"
    DisplayMachineInfo
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 
    

    ## Check the mandatory requisites for DLP
    DLPMinReqFromOS

    ## If min requisites does not meet, no need of checking additional stuff
    if($global:bDLPMinReqOS -eq $false)
    {
        Write-ColorOutput Red "   ERROR: Does not meet the minimum requisites needed for DLP. Feature may not work without fixing them. Continue checking..."           
    }

    # Check if the device is part of a domain.
    Write-ColorOutput White " " 
    Write-ColorOutput White "------------------"
    Write-ColorOutput Cyan "CHECKING DOMAIN:"
    Write-ColorOutput White " " 
    [string] $machineDomain = 'Machine domain: ' + (Get-WmiObject Win32_ComputerSystem).Domain
    
    if ((gwmi win32_computersystem).partofdomain -eq $true)   
    {

        Write-ColorOutput Green "   Device is part of the domain $machineDomain"        
    }
    else
    {
        Write-ColorOutput Yellow "   Device is not part of the domain"        
    }

    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 

    ## Check if reg entries are present to onboard SENSE 
    Write-ColorOutput White "------------------------------------"
    CheckNotificationSettings
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 


    ## Check if UX configuration settings controlled by Group Policy are set correctly for toast display
    Write-ColorOutput White "------------------------------------"
    CheckUXConfiguraitonSettings
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 


    ## Check if OS back port changes have been available in this OS    
    Write-ColorOutput White "------------------------------------"
    DLPInboxChangesBackportedToOS
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 

	## Check the Office version installed on the machine
    Write-ColorOutput White "------------------------------------"
    GetOfficeVersion
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 

    ## Check if Office enlightenment feature is configured
    Write-ColorOutput White "------------------------------------------"
    CheckOfficeEnlightenmentReg
    Write-ColorOutput White "------------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " "

    ## Check if device and file polices are set properly
    Write-ColorOutput White "------------------------------------"
    CheckDLPPolices
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 

    
    

    ## Check if dlp show dialog reg settings
    ## Decided not to have this check as it will be controlled by signs
    <#
    Write-ColorOutput White "------------------------------------"
    CheckDLPShowDialog
    Write-ColorOutput White "------------------------------------"
    Write-ColorOutput White " " 
    Write-ColorOutput White " " 
    #>    
    
    PrintFinalMessage
    
    
    Write-ColorOutput Cyan "DLP quick diagnosis complete"
    Write-ColorOutput White " "
    Write-Output " => Log saved at: $global:LogFileName"

}
catch [System.Exception]
{
    Write-ColorOutput Magenta $Error
}


# SIG # Begin signature block
# MIInngYJKoZIhvcNAQcCoIInjzCCJ4sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCACKRviSdOH359C
# KGSjC17OmRYZsKyEUm9aKDUNjIUnGKCCDYEwggX/MIID56ADAgECAhMzAAACUosz
# qviV8znbAAAAAAJSMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjEwOTAyMTgzMjU5WhcNMjIwOTAxMTgzMjU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDQ5M+Ps/X7BNuv5B/0I6uoDwj0NJOo1KrVQqO7ggRXccklyTrWL4xMShjIou2I
# sbYnF67wXzVAq5Om4oe+LfzSDOzjcb6ms00gBo0OQaqwQ1BijyJ7NvDf80I1fW9O
# L76Kt0Wpc2zrGhzcHdb7upPrvxvSNNUvxK3sgw7YTt31410vpEp8yfBEl/hd8ZzA
# v47DCgJ5j1zm295s1RVZHNp6MoiQFVOECm4AwK2l28i+YER1JO4IplTH44uvzX9o
# RnJHaMvWzZEpozPy4jNO2DDqbcNs4zh7AWMhE1PWFVA+CHI/En5nASvCvLmuR/t8
# q4bc8XR8QIZJQSp+2U6m2ldNAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUNZJaEUGL2Guwt7ZOAu4efEYXedEw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDY3NTk3MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAFkk3
# uSxkTEBh1NtAl7BivIEsAWdgX1qZ+EdZMYbQKasY6IhSLXRMxF1B3OKdR9K/kccp
# kvNcGl8D7YyYS4mhCUMBR+VLrg3f8PUj38A9V5aiY2/Jok7WZFOAmjPRNNGnyeg7
# l0lTiThFqE+2aOs6+heegqAdelGgNJKRHLWRuhGKuLIw5lkgx9Ky+QvZrn/Ddi8u
# TIgWKp+MGG8xY6PBvvjgt9jQShlnPrZ3UY8Bvwy6rynhXBaV0V0TTL0gEx7eh/K1
# o8Miaru6s/7FyqOLeUS4vTHh9TgBL5DtxCYurXbSBVtL1Fj44+Od/6cmC9mmvrti
# yG709Y3Rd3YdJj2f3GJq7Y7KdWq0QYhatKhBeg4fxjhg0yut2g6aM1mxjNPrE48z
# 6HWCNGu9gMK5ZudldRw4a45Z06Aoktof0CqOyTErvq0YjoE4Xpa0+87T/PVUXNqf
# 7Y+qSU7+9LtLQuMYR4w3cSPjuNusvLf9gBnch5RqM7kaDtYWDgLyB42EfsxeMqwK
# WwA+TVi0HrWRqfSx2olbE56hJcEkMjOSKz3sRuupFCX3UroyYf52L+2iVTrda8XW
# esPG62Mnn3T8AuLfzeJFuAbfOSERx7IFZO92UPoXE1uEjL5skl1yTZB3MubgOA4F
# 8KoRNhviFAEST+nG8c8uIsbZeb08SeYQMqjVEmkwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZczCCGW8CAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAlKLM6r4lfM52wAAAAACUjAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg0uLqCrAI
# PpwVJPclWBbqVW5TC9W2ZHPJKSM0dIs5vacwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBijdAWOoQD6SkqOyRU3NHZMnTR2dkcD3FLIYrRnEgg
# Uo7eNKabsawfCyQ5uYZ/VB3dVbpT7msHgdX78sJSVWvuQbsjxwjneViur7rGV2P5
# qiixRAznqslIR1n843lqmKkbdVFr29CzR0uYyONkTTWGPQyuz7hhlajzBrSDG2ql
# 86OLoOroVzUcygVMlGvoLh7x2xXhfNcYrOg4zQfp92J0sYVELZnV1sNLnSPPf7kM
# HnVS72ZcLKSuKpRrf1kM1hp0xrI0mZNeMW7cKe4Yso4q053KNU6Y19hc4SFm4nrQ
# cJsEUgq423q+rjcMPWCF0lmVBVfgqPfByo3oWvaaRqjqoYIW/TCCFvkGCisGAQQB
# gjcDAwExghbpMIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEINM9zv9FzyQDQkAuE+9hb2Ci1U2haYzAOYT23cHs
# PZHXAgZiglt5xmoYEzIwMjIwNTE3MTE1NjM4LjgxNVowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjNFN0EtRTM1OS1BMjVEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIRVDCCBwwwggT0oAMCAQICEzMAAAGg6buMuw6i0XoAAQAAAaAw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjExMjAyMTkwNTIzWhcNMjMwMjI4MTkwNTIzWjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0U3QS1FMzU5LUEy
# NUQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/2uIOaHGdAOj2YvhhI6C8iFAq7wrl
# /5WpPjj0fEHCi6Ivx/I02Jss/HVhkfGTMGttR5jRhhrJXydWDnOmzRU3B4G525T7
# pwkFNFBXumM/98l5k0U2XiaZ+bulXHe54x6uj/6v5VGFv+0Hh1dyjGUTPaREwS7x
# 98Te5tFHEimPa+AsG2mM+n9NwfQRjd1LiECbcCZFkgwbliQ/akiMr1tZmjkDbxtu
# 2aQcXjEfDna8JH+wZmfdu0X7k6dJ5WGRFwzZiLOJW4QhAEpeh2c1mmbtAfBnhSPN
# +E5yULfpfTT2wX8RbH6XfAg6sZx8896xq0+gUD9mHy8ZtpdEeE1ZA0HgByDW2rJC
# bTAJAht71B7Rz2pPQmg5R3+vSCri8BecSB+Z8mwYL3uOS3R6beUBJ7iE4rPS9WC1
# w1fZR7K44ZSme2dI+O9/nhgb3MLYgm6zx3HhtLoGhGVPL+WoDkMnt93IGoO6kNBC
# M2X+Cs22ql2tPjkIRyxwxF6RsXh/QHnhKJgBzfO+e84I3TYbI0i29zATL6yHOv5s
# Es1zaNMih27IwfWg4Q7+40L7e68uC6yD8EUEpaD2s2T59NhSauTzCEnAp5YrSscc
# 9MQVIi7g+5GAdC8pCv+0iRa7QIvalU+9lWgkyABU/niFHWPjyGoB4x3Kzo3tXB6a
# C3yZ/dTRXpJnaQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFHK5LlDYKU6RuJFsFC9E
# zwthjNDoMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRY
# MFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01p
# Y3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEF
# BQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAo
# MSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQELBQADggIBADF9xgKr+N+slAmlbcEqQBlpL5PfBMqcLkS6ySeGJjG+LKX3
# Wov5pygrhKftXZ90NYWUftIZpzdYs4ehR5RlaE3eYubWlcNlwsKkcrGSDJKawbbD
# GfvO4h/1L13sg66hPib67mG96CAqRVF0c5MA1wiKjjl/5gfrbdNLHgtREQ8zCpbK
# 4+66l1Fd0up9mxcOEEphhJr8U3whwFwoK+QJ/kxWogGtfDiaq6RyoFWhP8uKSLVD
# V+MTETHZb3p2OwnBWE1W6071XDKdxRkN/pAEZ15E1LJNv9iYo1l1P/RdF+IzpMLG
# DAf/PlVvTUw3VrH9uaqbYr+rRxti+bM3ab1wv9v3xRLc+wPoniSxW2p69DN4Wo96
# IDFZIkLR+HcWCiqHVwFXngkCUfdMe3xmvOIXYRkTK0P6wPLfC+Os7oeVReMj2TA1
# QMMkgZ+rhPO07iW7N57zABvMiHJQdHRMeK3FBgR4faEvTjUAdKRQkKFV82uE7w0U
# MnseJfX7ELDY9T4aWx2qwEqam9l7GHX4A2Zm0nn1oaa/YxczJ7gIVERSGSOWLwEM
# xcFqBGPm9QSQ7ogMBn5WHwkdTTkmanBb/Z2cDpxBxd1vOjyIm4BOFlLjB4pivClO
# 2ZksWKH7qBYloYa07U1O3C8jtbzGUdHyLCaVGBV8DfD5h8eOnyjraBG7PNNZMIIH
# cTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCB
# iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMp
# TWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEw
# OTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIh
# C3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNx
# WuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFc
# UTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAc
# nVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUo
# veO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyzi
# YrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9
# fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdH
# GO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7X
# KHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiE
# R9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/
# eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3
# FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAd
# BgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEE
# AYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMB
# Af8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1Ud
# HwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3By
# b2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQRO
# MEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2Vy
# dHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4IC
# AQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pk
# bHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gng
# ugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3
# lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHC
# gRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6
# MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEU
# BHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvsh
# VGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+
# fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrp
# NPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHI
# qzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAsswggI0AgEBMIH4
# oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUw
# IwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjozRTdBLUUzNTktQTI1RDElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAEwa4jWjacbOYU++9
# 5ydJ7hSCi5iggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAN
# BgkqhkiG9w0BAQUFAAIFAOYtgq8wIhgPMjAyMjA1MTcxMDEwNTVaGA8yMDIyMDUx
# ODEwMTA1NVowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5i2CrwIBADAHAgEAAgIZ
# MTAHAgEAAgJVNzAKAgUA5i7ULwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEE
# AYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GB
# AFZ8SCFhWpbHEG71LScVk3BBvKv0dasoQDebsa50W3RoYuJoLhz6mz2jY0Z9ExvJ
# bJkOQT9BaAMx02IeTCxV3KwQPM5LSHoND3DoQG+2AfDuGY0uvms9PmwO7rylDBQr
# 6vCVOh4XinCCLsH4hRD/hMcC7H7uugJG9GcbXStsd/FfMYIEDTCCBAkCAQEwgZMw
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGg6buMuw6i0XoAAQAA
# AaAwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAvBgkqhkiG9w0BCQQxIgQg5MUhdAY7s7QHntVituMJekh7AV5ThDSyMMZC6bA0
# gzwwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAvR4o8aGUEIhIt3REvsx0+
# svnM6Wiaga5SPaK4g6+00zCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABoOm7jLsOotF6AAEAAAGgMCIEIKTdMmM8BNqeI8O/+mbjxKJr
# qhCUHlEL8e2HojkiDOa2MA0GCSqGSIb3DQEBCwUABIICAES5l2h9wtVXKZJ1B6Ze
# MSyHKp4Ffp2+Ah0DxbgbP9bYKFHn0I8Pp8Z84F4hswz5juz2p0gC5elKSgHho+Y5
# EfU1LNeo6vqtrRYhB3V4YQKXb9NimXvwXOs/zDG33wF2RxIAwywImhe45LlP7JnU
# J5kA8YZFZmRoirb09ONWC+INsQ4QDyyGPySZvZleZA6cc2LFk6Yx5hbH6DqURCTY
# 4w6Ssbbg+YEC7q/jbs87TCU5sc63F11uhtL45vjmIFx3Bj5F0m0uybHmyK4gITK1
# ripo31192f0iHfI7bpEjteS3xzAHBTWF6TkLwQvibSE5VK2Spwj9iLy4pfNQzsR3
# Cq4N5OeTgw9GMURWOXzG4duYLOld7/Zjd6woE5xW9iXpVx5tdbJwpid5PIx8FjnE
# hgDbC43iDE8gBf5q7xQopBuywXWb4a9jLfG93MiQ2Pfjmw7Me2V64VIP/liH4eeg
# 4OBwP01KAD3ghdycT6JUAbu1dCSGbilX2i/CLOZhsz4hsFjcbaRtTp24q2syUjGa
# LwKNCZ2c09vXFwwNhPn9keeZ7A/Ff8U3Px/+zuLdSSqSQv/bhFtqLfExBiIdeGqI
# 3UfG1CDOZqbVnlPrlvhjtDO/rsO+Q3WgySfP+UTVkTdzict00IAMKi40GqfHIL4C
# /cC28EHRGjFtZ37aJILVaTZi
# SIG # End signature block
