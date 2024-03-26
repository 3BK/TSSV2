File: _WinPE_README(Instructions).txt
=====================================

0. Download https://aka.ms/getTSS and extract the TSSv2.zip on Disk C:\TSSv2

Create a bootable WindowPE USB drive
------------------------------------
1.	Refer to the link below and create a WinPE USB drive

	https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/download-winpe--windows-pe?view=windows-11

Please make sure that you can boot using the WinPE USB drive. You may need to change the boot order in BIOS/UEFI settings to boot with WinPE USB drive.

2.	Copy folder C:\TSSv2\scripts\WinPE to the WinPE USB drive
 Content: PROCMON24.SYS, Enable_Wlan_BootLog.cmd, Collect_Logs.cmd

3.	On Windows 10/11 current version machine, start upgrade to next version.
After the first reboot of the upgrade process, you will see messages on screen like below:

Å Working on updates  xx%Å

Note: Before the third reboot, insert the WinPE USB drive to the machine before the machine restarts, then it will boot into WinPE.
When the percentage shows around 70% to 80% your PC will be restarted for the third time.

Now in WindowPE environment
---------------------------
4.	In the WinPE command prompt window, check your Windows drive which is being upgraded and memorize the drive letter.
i.e. using >DiskPart.exe
  DISKPART> list volume
  Volume ###  Ltr  Label        Fs     Type        Size     Status     Info
  ----------  ---  -----------  -----  ----------  -------  ---------  --------
  Volume 0         System Rese  NTFS   Partition    500 MB  Healthy    System
  Volume 1     D   Windows      NTFS   Partition    126 GB  Healthy    Boot
 
In most cases the drive letter will be D
 
5.	Run Enable_Wlan_BootLog.cmd <drive_letter> with the drive letter as a parameter.
(Example) 
 > Enable_Wlan_BootLog D

     In this example, the drive letter on which \Windows\ folder exists is Ådrive D:

6.	Unplug the USB drive and exit the WinPE command prompt window to restart the machine.

7.	Let the Windows finish the rest of the upgrade process.

First Logon after upgrade stage
-------------------------------
8.	After upgrade is complete, logon to the machine.

9.	Confirm if Wi-Fi is available (at this time, the issue must be reproduced, so Wi-Fi should be unavailable.)

10.	Access the folder C:\TSSv2\scripts\WinPE and run as an Administrator the script 'Collect_Logs.cmd'
Logs are collected and saved under Output_<machine name>_<YYYYMMDD> folder.

	  Rename the folder so that we can start next log collection, i.e. First-Logon_<machine name>_<YYYYMMDD>
	  Compress the renamed foleder into a .zip file

Following steps 11.-16. are only necessary if the issue is known to be resolved after subsequent reboots
--------------------------------------------------------------------------------------------------------
11. Open an elevated (Admin) PowerShell window and start TSS with the following command-line
 C:\TSSv2\> .\TSSv2.ps1 -StartAutoLogger -NET_WLAN

12. Restart the machine.

Second Logon after machine had been upgraded
---------------------------------------------
13.	Logon to the machine.

14.	Confirm if Wi-Fi is available (at this time Wi-Fi should be available.)

15.	Open an elevated (Admin) PowerShell window and start TSS with the following command-line
 C:\TSSv2\> .\TSSv2.ps1 -Stop
Logs are collected and saved as a .zip file in C:\MS_DATA folder.

Upload resulting data sets
--------------------------
16.	Compress the folder First-Logon_<machine name>_<YYYYMMDD> and upload both .zip files to MS workspace (File transfer location).