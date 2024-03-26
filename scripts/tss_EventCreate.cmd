@echo off
:: Filename: tss_EventCreate.cmd [Event ID] [EvtLogName] [Rem_computername]
:: Purpose:  create an Event log entry in [EvtLogName] with [Event ID]
::           the tss.cmd script has a switch to stop data collection upon such event.
:: Example: tss_EventCreate.cmd 999 System
::
::  Copyright ^(C^) Microsoft. All rights reserved.
::  THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
::  IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
::
:: Last-Update by waltere: 2018-02-27

:: Alternately in Powershell 
::   do this once: New-EventLog -LogName "System" -Source 'TSS'
::   Write-EventLog -LogName "System" -Source "TSS" -EventID 15004 -EntryType Information -Message "TSS added this EventID as stop trigger." -Category 1 -RawData 10,20 -ComputerName $Env:Computername
:: in CMD script: Powershell "Write-EventLog -LogName 'System' -Source 'TSS' -EventID 999 -EntryType Information -Message 'TSS added this EventID as stop trigger.' -Category 1 -RawData 10,20 -ComputerName $Env:Computername"
:: for testing it is sufficient to specify an exiting "Source", i.e. Write-EventLog -LogName "System" -Source "Outlook" -EventID 59 -EntryType Information -Message "Test this EventID as stop trigger." -Category 1 -RawData 10,20 -ComputerName $Env:Computername

set ScriptVersion=v1.00
setlocal enabledelayedexpansion
REM : for testing purpose use EVENTCREATE [/S system [/U username [/P [password]]]] /ID eventid [/L logname] [/SO srcname] /T type /D description
:: Note: /ID Specifies the event ID for the event. A valid custom message ID is in the range of 1 - 1000.
SET _Evt_ID=%1
 If '%1' EQU '' SET _Evt_ID=999
SET _EvtLogName=%2
 If '%2' EQU '' SET _EvtLogName=System
SET _Rem_computername=%3
 If '%3' EQU '' SET _Rem_computername=%computername%
SET _DomUsername=%4
 If '%4' EQU '' SET _DomUsername=%USERDOMAIN%\%USERNAME%
SET _EvtDefaults=y

echo .. for testing purpose, with default answers: Creating an Event on machine !_Rem_computername! in !_EvtLogName! Eventlog with ID !_Evt_ID!, Source: %~n0, Type: INFORMATION

SET /P _EvtDefaults=[Do you want to continue with default answers {Event ID:!_Evt_ID!, Eventlog:!_EvtLogName!, Computer:!_Rem_computername!}?  {CR=}Y=yes N=no] 
if /i '!_EvtDefaults!' equ 'Y' (
	echo ... using defaults: Event ID: !_Evt_ID!, EvtLogName: !_EvtLogName!, Computer: !_Rem_computername!
) else (
	SET /P _Evt_ID=[Input your desired Event ID 1 - 1000 ^(def:!_Evt_ID!^)] 
	echo ... using Event ID: !_Evt_ID!
	SET /P _EvtLogName=[Input your desired Eventlog, i.e. System ^| System ^| ... ^(def:!_EvtLogName!^) ] 
	echo ... using Event-Log: '!_EvtLogName!'
	SET /P _Rem_computername=[Input your desired remote System ^(def:%computername%^) ] 
	echo ... to remote computer: '!_Rem_computername!'
	SET /P _DomUsername=[Input your Domain\Username ^(def:%_DomUsername%^) ] 
	echo ... using Domain\Username: '!_DomUsername!'	
	)
EVENTCREATE /S !_Rem_computername! /U !_DomUsername! /ID !_Evt_ID! /L !_EvtLogName!   /T INFORMATION /D "This is an Event ID: !_Evt_ID! test from script %~n0 on computer %computername% at %time% in order to stop data collection."	
	if !errorlevel! equ 0 ( echo .. Created EventID !_Evt_ID! in '!_EvtLogName!' EventLog of computer '!_Rem_computername!' at %time%) else ( echo .. Failed to Create EventID !_Evt_ID! on remote computer '!_Rem_computername!' from script %~n0 on local computer %computername%)

REM echo ... done %~n0
