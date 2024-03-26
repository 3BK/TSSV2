@echo off
REM File: Collect_Logs.cmd
REM Purpose: Collect Logs during Windows inplace Upgrade (for WLAN)
REM using CMD script, because WinPE would require installation of PowerShell optional component https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-adding-powershell-support-to-windows-pe?view=windows-11

echo. Collecting WLAN boot logs ... please be patient ...
echo. =========================================================

for /f %%a in ('wmic os get LocalDateTime ^| findstr \.') DO set dateD=%%a
set outfolder=%~dp0Output_%COMPUTERNAME%_%dateD:~0,8%
md %outfolder%

cd /d %outfolder%

REM ----- Disable ETW Traces, which had been enabled by script Enable_Wlan_BootLog.cmd

logman stop "net_wlan" -ets

REG DELETE HKLM\SYSTEM\CurrentControlSet\Services\PROCMON24 /f
REG DELETE HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\net_wlan /f

copy c:\Windows\PROCMON.pmb
copy c:\net_wlan.* 


REM ----- Wlan Profiles

md netsh-wlan-export
netsh wlan export profile folder=.\netsh-wlan-export\ key=clear
netsh wlan show all > netsh-wlan-show-all.txt
netsh wlan show allowexplicitcreds > netsh-wlan-show-allowexplicitcreds.txt
netsh wlan show autoconfig > netsh-wlan-show-autoconfig.txt
netsh wlan show blockednetworks > netsh-wlan-show-.txt
netsh wlan show createalluserprofile > netsh-wlan-show-blockednetworks.txt
netsh wlan show drivers > netsh-wlan-show-drivers.txt
netsh wlan show filters > netsh-wlan-show-filters.txt
netsh wlan show hostednetwork > netsh-wlan-show-hostednetwork.txt
netsh wlan show interfaces > netsh-wlan-show-interfaces.txt
netsh wlan show networks > netsh-wlan-show-networks.txt
netsh wlan show onlyUseGPProfilesforAllowedNetworks > netsh-wlan-show-onlyUseGPProfilesforAllowedNetworks.txt
netsh wlan show settings > netsh-wlan-show-settings.txt
netsh wlan show wirelesscapabilities > netsh-wlan-show-wirelesscapabilities.txt
netsh wlan show wlanreport > netsh-wlan-show-wlanreport.txt

REM ----- Eventlog

wevtutil epl System wevtutil-System.evtx
wevtutil qe System /f:text > wevtutil-System.txt
wevtutil epl Application wevtutil-Application.evtx
wevtutil qe Application /f:text > wevtutil-Application.txt
wevtutil epl Security wevtutil-Security.evtx

wevtutil epl Microsoft-Windows-GroupPolicy/Operational wevtutil-GroupPolicy-Operational.evtx
wevtutil epl Microsoft-Windows-NCSI/Operational wevtutil-NCSI.evtx
wevtutil epl Microsoft-Windows-NlaSvc/Operational wevtutil-NlaSvc.evtx
wevtutil epl Microsoft-Windows-NetworkProfile/Operational wevtutil-NetworkProfile.evtx
wevtutil epl Microsoft-Windows-Dhcp-Client/Admin wevtutil-DHCPClient-Admin.evtx
wevtutil epl Microsoft-Windows-Dhcp-Client/Operational wevtutil-DHCPClient-Operational.evtx
wevtutil epl Microsoft-Windows-TaskScheduler/Operational wevtutil-TaskScheduler-Operational.evtx
wevtutil epl Microsoft-Windows-WLAN-AutoConfig/Operational wevtutil-WLAN-AutoConfig-Operational.evtx

REM ----- Registry

reg export HKLM\SOFTWARE\Microsoft\WlanSvc reg_WlanSvc.txt
reg export HKLM\SOFTWARE\Microsoft\PolicyManager reg_PolicyManager.txt
reg export HKLM\SOFTWARE\Policies\Microsoft\Windows\Wireless\GPTWirelessPolicy reg_GPTWirelessPolicy.txt


REM ----- Files

xcopy C:\ProgramData\Microsoft\WlanSvc file_ProgramData_WlanSvc /S /E /C /I /Q /H /R
xcopy C:\Windows\wlansvc file-Windows_WlanSvc /S /E /C /I /Q /H /R
xcopy C:\Windows\Panther file-Panther /S /E /C /I /Q /H /R


REM ----- Command

msinfo32.exe /nfo msinfo32.nfo
gpresult /H gpresult.htm
gpresult /z > gpresult.txt
auditpol /get /category:* > auditpol.txt
ipconfig /all > ipconfig-all.txt
ipconfig /displaydns > ipconfig-displaydns.txt
netstat -r > netstat-r.txt
netstat -s > netstat-s.txt
netstat -anob > netstat-anob.txt
netsh interface ipv4 show offload > netsh-int-ipv4-offload.txt
fltmc instances > fltmc_instances.txt
fltmc filters > fltmc_filters.txt
driverquery /fo csv /v > driverquery.csv
wmic nic get * /format:htable > wmi_nic.html
wmic nicconfig get * /format:htable > wmi_nicconfig.html
wmic qfe get * /format:htable > wmi_qfe.html
wmic partition get * /format:htable > wmi_partition.html
wmic logicaldisk get * /format:htable > wmi_logicaldisk.html
wmic volume get * /format:htable > wmi_volume.html
wmic diskdrive get * /format:htable > wmi_diskdrive.html
copy %windir%\inf\Setupapi.* .\ >nul
copy %WinDir%\System32\LogFiles\SCM\*.EVM* .\ >nul
whoami /all > whoami-all-%USERNAME%.txt
tasklist -svc > tasklist-svc.txt
tasklist -v > tasklist-v.txt
schtasks /Query /V > schtasks.txt
dism /Online /Get-intl > Get_intl.log
dism /Online /Get-Packages /Format:Table > Get-Packages.log
dism /Online /Get-Features /Format:Table > Get-Features.log

echo.
echo. =================== Done ================================
echo.  Resulting logs are located in folder %outfolder%
echo. =========================================================
cd ..
pause
