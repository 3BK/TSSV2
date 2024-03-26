@echo off
REM File: Enable_Wlan_BootLog.cmd
REM using CMD script, because WinPE would require installation of PowerShell optional component
echo.
echo This scripts enables ETW boot logging for WLAN components and Procmon Boot logging, 
echo it stores registry changes in original Windows drive which is being upgraded.
echo One input parameter is required: 'Drive Letter', example: X:\ Enable_Wlan_BootLog.cmd D
echo To locate the correct drive letter (Ltr) you can use Diskpart.exe with command DISKPART list volume
echo.
echo To stop boot logging after reboot, run: X:\ Collect_Logs.cmd


if '%1' == '' goto error_message

REG LOAD HKLM\SYSTEM_OfflineReg %1:\Windows\System32\config\system
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Services\PROCMON24 /v SupportedFeatures /t REG_DWORD /d 3 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Services\PROCMON24 /v Group /t REG_SZ /d "FSFilter Activity Monitor" /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Services\PROCMON24 /v Start /t REG_DWORD /d 0 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Services\PROCMON24 /v Type /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Services\PROCMON24 /v ImagePath /t REG_EXPAND_SZ /d "System32\drivers\PROCMON24.SYS" /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Services\PROCMON24\Instances /v DefaultInstance /t REG_SZ /d "Process Monitor 24 Instance" /f
REG ADD "HKLM\SYSTEM_OfflineReg\ControlSet001\Services\PROCMON24\Instances\Process Monitor 24 Instance" /v Altitude /t REG_SZ /d "385200" /f
REG ADD "HKLM\SYSTEM_OfflineReg\ControlSet001\Services\PROCMON24\Instances\Process Monitor 24 Instance" /v Flags /t REG_DWORD /d 0 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan /v FileName /t REG_SZ /d C:\net_wlan.etl /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan /v Start /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan /v LogFileMode /t REG_DWORD /d 2 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan /v GUID /t REG_SZ /d {1AC55562-D4FF-4BC5-8EF3-A18E07C4668E} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan /v MaxFileSize /t REG_DWORD /d 4096 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan /v FileMax /t REG_DWORD /d 10 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{1AC55562-D4FF-4BC5-8EF3-A18E07C4668E} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{1AC55562-D4FF-4BC5-8EF3-A18E07C4668E} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{1AC55562-D4FF-4BC5-8EF3-A18E07C4668E} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{1AC55562-D4FF-4BC5-8EF3-A18E07C4668E} /v EnableLevel /t REG_DWORD /d 0xff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{36DFF693-C097-438B-B3CA-62E80D15D227} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{36DFF693-C097-438B-B3CA-62E80D15D227} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{36DFF693-C097-438B-B3CA-62E80D15D227} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{36DFF693-C097-438B-B3CA-62E80D15D227} /v EnableLevel /t REG_DWORD /d 0xff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{8A3CF0B5-E0BC-450B-AE4B-61728FFA1D58} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{8A3CF0B5-E0BC-450B-AE4B-61728FFA1D58} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{8A3CF0B5-E0BC-450B-AE4B-61728FFA1D58} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{8A3CF0B5-E0BC-450B-AE4B-61728FFA1D58} /v EnableLevel /t REG_DWORD /d 0xff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{E2EB5B52-08B1-4391-B670-F58317376247} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{E2EB5B52-08B1-4391-B670-F58317376247} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{E2EB5B52-08B1-4391-B670-F58317376247} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{E2EB5B52-08B1-4391-B670-F58317376247} /v EnableLevel /t REG_DWORD /d 0xff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{F860141E-94E0-418E-A8A6-2321623C3018} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{F860141E-94E0-418E-A8A6-2321623C3018} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{F860141E-94E0-418E-A8A6-2321623C3018} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{F860141E-94E0-418E-A8A6-2321623C3018} /v EnableLevel /t REG_DWORD /d 0xff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{D905AC1D-65E7-4242-99EA-FE66A8355DF8} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{D905AC1D-65E7-4242-99EA-FE66A8355DF8} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{D905AC1D-65E7-4242-99EA-FE66A8355DF8} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{D905AC1D-65E7-4242-99EA-FE66A8355DF8} /v EnableLevel /t REG_DWORD /d 0xff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{0C5A3172-2248-44FD-B9A6-8389CB1DC56A} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{0C5A3172-2248-44FD-B9A6-8389CB1DC56A} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{0C5A3172-2248-44FD-B9A6-8389CB1DC56A} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{0C5A3172-2248-44FD-B9A6-8389CB1DC56A} /v EnableLevel /t REG_DWORD /d 0xff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{6DA4DDCA-0901-4BAE-9AD4-7E6030BAB531} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{6DA4DDCA-0901-4BAE-9AD4-7E6030BAB531} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{6DA4DDCA-0901-4BAE-9AD4-7E6030BAB531} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{6DA4DDCA-0901-4BAE-9AD4-7E6030BAB531} /v EnableLevel /t REG_DWORD /d 0xff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{2E8D9EC5-A712-48C4-8CE0-631EB0C1CD65} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{2E8D9EC5-A712-48C4-8CE0-631EB0C1CD65} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{2E8D9EC5-A712-48C4-8CE0-631EB0C1CD65} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{2E8D9EC5-A712-48C4-8CE0-631EB0C1CD65} /v EnableLevel /t REG_DWORD /d 0xff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{637A0F36-DFF5-4B2F-83DD-B106C1C725E2} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{637A0F36-DFF5-4B2F-83DD-B106C1C725E2} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{637A0F36-DFF5-4B2F-83DD-B106C1C725E2} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{637A0F36-DFF5-4B2F-83DD-B106C1C725E2} /v EnableLevel /t REG_DWORD /d 0xff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{253F4CD1-9475-4642-88E0-6790D7A86CDE} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{253F4CD1-9475-4642-88E0-6790D7A86CDE} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{253F4CD1-9475-4642-88E0-6790D7A86CDE} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{253F4CD1-9475-4642-88E0-6790D7A86CDE} /v EnableLevel /t REG_DWORD /d 0xff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{20644520-D1C2-4024-B6F6-311F99AA51ED} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{20644520-D1C2-4024-B6F6-311F99AA51ED} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{20644520-D1C2-4024-B6F6-311F99AA51ED} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{20644520-D1C2-4024-B6F6-311F99AA51ED} /v EnableLevel /t REG_DWORD /d 0xff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{ED092A80-0125-4403-92AC-4C06632420F8} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{ED092A80-0125-4403-92AC-4C06632420F8} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{ED092A80-0125-4403-92AC-4C06632420F8} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{ED092A80-0125-4403-92AC-4C06632420F8} /v EnableLevel /t REG_DWORD /d 0xff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{1BF7FE18-A798-4FF3-A054-4A31A959D381} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{1BF7FE18-A798-4FF3-A054-4A31A959D381} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{1BF7FE18-A798-4FF3-A054-4A31A959D381} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{1BF7FE18-A798-4FF3-A054-4A31A959D381} /v EnableLevel /t REG_DWORD /d 0xff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{D905AC1C-65E7-4242-99EA-FE66A8355DF8} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{D905AC1C-65E7-4242-99EA-FE66A8355DF8} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{D905AC1C-65E7-4242-99EA-FE66A8355DF8} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{D905AC1C-65E7-4242-99EA-FE66A8355DF8} /v EnableLevel /t REG_DWORD /d 0xff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{4CEAB604-4A19-48C9-B9FD-43A7465AAAC7} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{4CEAB604-4A19-48C9-B9FD-43A7465AAAC7} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{4CEAB604-4A19-48C9-B9FD-43A7465AAAC7} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{4CEAB604-4A19-48C9-B9FD-43A7465AAAC7} /v EnableLevel /t REG_DWORD /d 0xff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{520319A9-B932-4EC7-943C-61E560939101} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{520319A9-B932-4EC7-943C-61E560939101} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{520319A9-B932-4EC7-943C-61E560939101} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{520319A9-B932-4EC7-943C-61E560939101} /v EnableLevel /t REG_DWORD /d 0xff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{1F6C35EE-9294-4721-9413-FB3394247DAC} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{1F6C35EE-9294-4721-9413-FB3394247DAC} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{1F6C35EE-9294-4721-9413-FB3394247DAC} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{1F6C35EE-9294-4721-9413-FB3394247DAC} /v EnableLevel /t REG_DWORD /d 0xff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{F96AFBA0-22D3-4EB7-9E3D-53A79C0135C4} /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{F96AFBA0-22D3-4EB7-9E3D-53A79C0135C4} /v Enabled /t REG_DWORD /d 1 /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{F96AFBA0-22D3-4EB7-9E3D-53A79C0135C4} /v EnableFlags /t REG_DWORD /d 0xffffffff /f
REG ADD HKLM\SYSTEM_OfflineReg\ControlSet001\Control\WMI\Autologger\net_wlan\{F96AFBA0-22D3-4EB7-9E3D-53A79C0135C4} /v EnableLevel /t REG_DWORD /d 0xff /f
REG UNLOAD HKLM\SYSTEM_OfflineReg
COPY PROCMON24.SYS %1:\Windows\System32\drivers\PROCMON24.SYS
PAUSE
goto :eof

:error_message
echo.
echo.  WinPE: Please run script with the drive letter of disk with Windows Installation.
echo.  for example: Enable_Wlan_BootLog.cmd D
