README:
=======
Public download: https://cesdiagtools.blob.core.windows.net/windows/psSDP.zip

To start SDP data collection, run in an elevated PowerShell CMD
 .\get-psSDP.ps1 [Net|Dom|CTS|Print|HyperV|Setup|Cluster|Mini|Nano]
 
 Example for collecting SDP Networking Diagnostic:
  .\get-psSDP.ps1 Net

 Example for SDP Basic data collection:
  .\get-psSDP.ps1 Mini
 
 Example for SDP Net without zipping results:
  .\get-psSDP.ps1 Net NoCab
   
If you encounter an error that running scripts is disabled, run 
Method#1
  Set-ExecutionPolicy -ExecutionPolicy Bypass -force -Scope Process
and verify with 'Get-ExecutionPolicy -List' that no ExecutionPolicy with higher precedence is blocking execution of this script.
Then run ".\Get-psSDP.ps1 <speciality-of-SDP>" again.

Alternate method#2: run in elevated CMD: "tss_PS1sign.cmd Get-psSDP"

Alternate method#3a: if scripts are blocked by MachinePolicy, run in elevated Powershell: 
  Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Name ExecutionPolicy -Value ByPass
  Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Name EnableScripts  -Value 1 -Type DWord
Alternate method#3b: if scripts are blocked by UserPolicy, run in elevated Powershell: 
  Set-ItemProperty -Path HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell -Name ExecutionPolicy -Value ByPass
  Set-ItemProperty -Path HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell -Name EnableScripts  -Value 1 -Type DWord
  
Note, method#3a is only a workaround for Policy "MachinePolicy - RemoteSigned", if you also see "UserPolicy - RemoteSigned", please ask the domain admin for temporary GPO exemption.


[Action:] 
-------
Send us the resulting file psSDP_<tec>_%computername%_<date>.zip


Powershell ExecutionPolicy
--------------------------
.	Make sure script execution is allowed in PowerShell
a.	Run: 

  Get-ExecutionPolicy  (gets the effective execution policy)
  or
  Get-ExecutionPolicy -List

b.	If the policy comes back AllSigned, Default, or Restricted then scripting needs to be enabled.
c.	Save the above output to restore the policy when troubleshooting is complete
d.	Run: 

  Set-ExecutionPolicy -ExecutionPolicy Unrestricted

More Information:
 - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7
 - in PS> get-help about_Execution_Policies

More Help
---------
run the command below to get more help
  get-help .\get-psSDP.ps1 -detailed


Hints:
  -noNetAdapters [<SwitchParameter>]
        This switch will skip NetAdapters data collection in network section of SDPs
=>	This is helpful if you try to get an SDP of a VPN/DirectAccess Client, which sometimes fails/is stuck at this stage

  -skipBPA [<SwitchParameter>]
        This switch will skip all Best Practice Analyzer (BPA) TroubleShooter
=>	This might help on ServerCORE systems, where script seems to halt at stage 'runing Best Practice Analyzer (BPA)'

  -Transcript [<SwitchParameter>]
        use -Transcript:$true to start PS Transcription, sometimes you may see error 'Transcription cannot be started.'
=>	Get a PowerShell transcript log file up to stage where script ‘hangs’ (similar on what you see on-screen)

If you try to get a mini SDP for performing later RFLcheck, you can run (undocumented) parameter RFL
  PS> .\get-psSDP RFL
  
  
Note: For older OS: Download and install Windows PowerShell 5.1
https://docs.microsoft.com/en-us/skypeforbusiness/set-up-your-computer-for-windows-powershell/download-and-install-windows-powershell-5-1
Download and install the WMF 5.1 package https://docs.microsoft.com/en-us/powershell/wmf/setup/install-configure

For Server 2008 SP2: https://www.microsoft.com/en-us/download/details.aspx?id=34595