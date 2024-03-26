# Copyright ?2010, Microsoft Corporation. All rights reserved.

# You may use this code and information and create derivative works of it,
# provided that the following conditions are met:
# 1. This code and information and any derivative works may only be used for
# troubleshooting a) Windows and b) products for Windows, in either case using
# the Windows Troubleshooting Platform
# 2. Any copies of this code and information
# and any derivative works must retain the above copyright notice, this list of
# conditions and the following disclaimer.
# 3. THIS CODE AND INFORMATION IS PROVIDED ``AS IS'' WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. IF THIS CODE AND
# INFORMATION IS USED OR MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN CONNECTION
# WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.
#************************************************

#************************************************
# DC_MSDTC_Collector.ps1
# Version 1.0.0
# Date: 05-04-2011
# Author: Jeremy LaBorde - jlaborde@microsoft.com
# Description: This script gathers MSDTC diagnostic data, including
#  registry keys in XML format, a summary report, event logs,
#  ipconfig data, service permissions, and a XAML
#  representation of DTC settings
#
# This is the main SDP package for MSDTC
#************************************************





# includes
. .\RegistryKeyToXML.ps1
. .\DC_Zip2.ps1
. .\DistSvcs_Utils.ps1


# debug key to output contents to C:\ for testing
#$global:gDebugOutput = $true
$global:gDebugOutput = $false
# debug key to turn off SDP options ( for testing outside SDP environment )
$global:gDebugSDPOn  = $true
#$global:gDebugSDPOn  = $false

# debug options to focus troubleshooting one area of the code
$global:gDebugDTC_DoAnalyzeLocal		= $true
$global:gDebugDTC_DoAnalyzeCluster		= $true
$global:gDebugDTC_DoXAMLLocal			= $true
$global:gDebugDTC_DoGeneralData			= $true
$global:gDebugDTC_DoEventLogs			= $true
$global:gDebugDTC_DoTraceFile			= $true
$global:gDebugDTC_DoCMTraceFile			= $true
$global:gDebugDTC_DoDiagTraceFile		= $true

#$global:gDebugDTC_DoAnalyzeLocal		= $false
#$global:gDebugDTC_DoAnalyzeCluster		= $false
#$global:gDebugDTC_DoXAMLLocal			= $false
#$global:gDebugDTC_DoGeneralData			= $false
#$global:gDebugDTC_DoEventLogs			= $false
#$global:gDebugDTC_DoTraceFile			= $false
#$global:gDebugDTC_DoCMTraceFile			= $false
#$global:gDebugDTC_DoDiagTraceFile		= $false

#global array of all DTC settings
$global:DTCSettingsArray				= @()


# localization
if( $global:gDebugSDPOn )
{	Import-LocalizedData -BindingVariable MSDTCDataStrings
}


# global collection strings
$global:DTCGeneralOutput	= "MSDTC_"														# general MSDTC SDP file out prefix
$global:DTCXMLRegFile		= "MSDTC_Registry_Data.xml"										# registry keys
$global:DTCSummaryFile		= "MSDTC_Summary.txt"											# summary data
$global:DTCXAMLFile			= "MSDTC_Dialog.xaml"											# XAML dialog of local dtc settings
$global:DTCZipFileTrace		= ($env:COMPUTERNAME + "_") + "SDP_MSDTC_TraceData.zip"			# trae data
$global:DTCZipFile			= ($env:COMPUTERNAME + "_") + "SDP_MSDTC_DiagData.zip"			# diagnostic data
$global:DTCOutputFolder		= "MSDTC"														# output folder
$global:DTCServicePerms		= "MSDTC_Service_Permissions.txt"								# service permissions via powershell
if( $PWD.Path.EndsWith( "\" ) ){															# full output folder path
$global:DTCOutputPath		= ($PWD.Path) + $global:DTCOutputFolder } else{
$global:DTCOutputPath		= ($PWD.Path) + "\" + $global:DTCOutputFolder }
$global:DCOMEnabled			= $false														# is DCOM enabled?





###########################################################
#
# Last Update: 5-4-2011
# Author: jlaborde
#
# Description:
#  create a custom object of all DTC settings
#  this helps group data and extend to multiple instances
#
# Usage:
#  Get-NewDTCSettingsClass
#
# Example:
#  $obj = Get-NewDTCSettingsClass
#
###########################################################

function Get-NewDTCSettingsClass( )
{	# construct a collection of DTC properties

	$local:object	=	New-Object Object |
		# run as
		Add-Member -MemberType NoteProperty -Name AccountName							-Value "" -PassThru |
		# network access controls
		Add-Member -MemberType NoteProperty -Name NetworkDTCAccessOn					-Value $false -PassThru |
		Add-Member -MemberType NoteProperty -Name NetworkDTCAccessTransactionsOn		-Value $false -PassThru |
		Add-Member -MemberType NoteProperty -Name NetworkDTCAccessInboundOn				-Value $false -PassThru |
		Add-Member -MemberType NoteProperty -Name NetworkDTCAccessOutboundOn			-Value $false -PassThru |
		Add-Member -MemberType NoteProperty -Name AllowRemoteClientsOn					-Value $false -PassThru |
		Add-Member -MemberType NoteProperty -Name AllowRemoteAdministrationOn			-Value $false -PassThru |
		Add-Member -MemberType NoteProperty -Name AllowInbound					 		-Value $false -PassThru |
		Add-Member -MemberType NoteProperty -Name AllowOutbound					 		-Value $false -PassThru |
		# XA / LU transactions
		Add-Member -MemberType NoteProperty -Name XATransactionsOn				 		-Value $false -PassThru |
		Add-Member -MemberType NoteProperty -Name LuTransactionsOn				 		-Value $true  -PassThru |
		# Authentication
		Add-Member -MemberType NoteProperty -Name AllowOnlySecureRpcCallsOn				-Value $true  -PassThru |
		Add-Member -MemberType NoteProperty -Name FallbackToUnsecureRPCIfNecessaryOn	-Value $false -PassThru |
		Add-Member -MemberType NoteProperty -Name TurnOffRpcSecurityOn					-Value $false -PassThru |
		Add-Member -MemberType NoteProperty -Name MutualAuthRequired					-Value $true  -PassThru |
		Add-Member -MemberType NoteProperty -Name IncomingCallerAuthRequired			-Value $false -PassThru |
		Add-Member -MemberType NoteProperty -Name NoAuthRequired					 	-Value $false -PassThru |
		# Transaction tracing
		Add-Member -MemberType NoteProperty -Name ControlFlags					 		-Value 0 -PassThru |
		Add-Member -MemberType NoteProperty -Name TraceOutputOn					 		-Value $true  -PassThru |
		Add-Member -MemberType NoteProperty -Name TraceTransactionsOn					-Value $true  -PassThru |
		Add-Member -MemberType NoteProperty -Name TraceAllTransActionsOn				-Value $false -PassThru |
		Add-Member -MemberType NoteProperty -Name TraceAllAbortedTransactionsOn			-Value $true  -PassThru |
		Add-Member -MemberType NoteProperty -Name TraceLongLivedTransactionsOn			-Value $true  -PassThru |
		# log
		Add-Member -MemberType NoteProperty -Name MaxBuffers					 		-Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name LogPath					 			-Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name LogSize					 			-Value "" -PassThru |
		# CM Tracing
		Add-Member -MemberType NoteProperty -Name TraceCMErrOn					 		-Value $false -PassThru |
		Add-Member -MemberType NoteProperty -Name TraceCMErrLogName					 	-Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name CM_Tracing_LogFileMask				-Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name CM_Tracing_LogFolder					-Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name CMTracingOn					 		-Value $false -PassThru |

		# 5-6-2011
		
		# service permissions ???
		Add-Member -MemberType NoteProperty -Name SMServicePermissions			 		-Value $false -PassThru |
		Add-Member -MemberType NoteProperty -Name DTCServicePermissions			 		-Value $false -PassThru |
		# timeouts
		Add-Member -MemberType NoteProperty -Name Timeout						 		-Value "" -PassThru |
		# cluster
		Add-Member -MemberType NoteProperty -Name IsClusterInstance				 		-Value $false -PassThru |
		Add-Member -MemberType NoteProperty -Name ClusterResourceName			 		-Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name UsingLocalDTCSettings		 			-Value $false -PassThru |
		Add-Member -MemberType NoteProperty -Name UsingLocalSecuritySettings	 		-Value $false -PassThru |
		# TIP ( http://support.microsoft.com/kb/908620 )
		Add-Member -MemberType NoteProperty -Name NetworkDtcAccessTipOn		 			-Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name DisableTipTmIdVerificationOn	 		-Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name DisableTipTmIdPortVerificationOn 		-Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name DisableTipBeginCheckOn	 			-Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name DisableTipPassThruCheckOn	 			-Value "" -PassThru |
		# Vista+ tracing options
		Add-Member -MemberType NoteProperty -Name NewDiagnosticTracingOn				-Value $false -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_DebugOutEnabled			-Value $false -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_TraceFilePath			-Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_MemoryBufferSize			-Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_Trace_Misc				-Value 0 -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_Trace_CM					-Value 0 -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_Trace_Trace				-Value 0 -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_Trace_SVC				-Value 0 -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_Trace_Gateway			-Value 0 -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_Trace_UI					-Value 0 -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_Trace_Contact			-Value 0 -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_Trace_Util				-Value 0 -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_Trace_Cluster			-Value 0 -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_Trace_Resource			-Value 0 -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_Trace_TIP				-Value 0 -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_Trace_XA					-Value 0 -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_Trace_Log				-Value 0 -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_Trace_MTXOCI				-Value 0 -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_Trace_ETWTrace			-Value 0 -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_Trace_Proxy				-Value 0 -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_Trace_KTMRM				-Value 0 -PassThru |
		Add-Member -MemberType NoteProperty -Name VistaTracing_Trace_VSSBackup	 		-Value 0 -PassThru |
		# 10-7-2011
		# remote host name
		Add-Member -MemberType NoteProperty -Name RemoteHostName	 					-Value "" -PassThru |


		Add-Member -MemberType NoteProperty -Name Dummy							 		-Value $false -PassThru

	return $local:object
}

###########################################################
#
# Last Update: 5-6-2011
# Author: jlaborde
#
# Description:
#  create a custom object of DTC instance application mappings
#  this helps group data and extend to multiple instances
#
# Usage:
#  Get-NewDTCApplicationMapping [System.Xml.XmlElement]$local:MappingNode [System.Xml.XmlElement]$local:ClusterResourcesNode
#
# Example:
#  $obj = Get-NewDTCApplicationMapping Mappings Resources
#  where
#   Mappings is an [System.Xml.XmlElement] set to the XML representation of the current registry mapping
#    ex. HKEY_LOCAL_MACHINE\Cluster\MSDTC\TMMapping\Service\Mapping1
#   Resources is an [System.Xml.XmlElement] set to the XML representation of the current registry mapping
#    ex. HKEY_LOCAL_MACHINE\Cluster\Resources
#
###########################################################

function Get-NewDTCApplicationMapping( [System.Xml.XmlElement]$local:MappingNode, [System.Xml.XmlElement]$local:ClusterResourcesNode )
{	# construct a collection of DTC TMMapping settings

	$local:object	=	New-Object Object |
		# run as
		Add-Member -MemberType NoteProperty -Name Name							-Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name ClusterResourceID				-Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name ApplicationType				-Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name CR_Name						-Value "" -PassThru |
		Add-Member -MemberType NoteProperty -Name CR_Type						-Value "" -PassThru |

		Add-Member -MemberType NoteProperty -Name Dummy							-Value $false -PassThru

	return $local:object
}

###########################################################
#
# Last Update: 5-9-2011
# Author: jlaborde
#
# Description:
#  get trace flag name from value, per http://support.microsoft.com/default.aspx?scid=kb;en-us;926099
#  only applies to Vista or above
#
# Usage:
#  Get-DTCTraceFlag [byte]$local:flagvalue
#
# Example:
#  Get-DTCTraceFlag 0xFF
#
###########################################################

function Get-DTCTraceFlag( [byte]$local:flagvalue )
{
	switch( $local:flagvalue )
	{
		0x00	{ return "TRACE_OFF" }
		0x01	{ return "TRACE_ERROR" }
		0x02	{ return "TRACE_WARNING" }
		0x03	{ return "TRACE_INFO" }
		0x04	{ return "TRACE_VERBOSE" }
		0x05	{ return "TRACE_VERY_VERBOSE" }
		0x06	{ return "TRACE_INOUT" }
		0xF0	{ return "TRACE_OBSCURE" }
		0xFF	{ return "TRACE_EVERYTHING" }
	}
	return "TRACE_invalid_flag"
}

###########################################################
#
# Last Update: 4-26-2011
# Author: jlaborde
#
# Description:
#  dump MSDTC registry keys to XML data stream
#
# Usage:
#  Get-MSDTCRegistryKeysAsXML
#
# Example:
#  Get-MSDTCRegistryKeysAsXML
#
###########################################################

function Get-MSDTCRegistryKeysAsXML( )
{	$local:data		= "<?xml version=`"1.0`" ?>`r`n<SDP_MSDTC_Registry_Data>`r`n"
	$local:data		+= Get-RegistryKeyAsXML "HKEY_LOCAL_MACHINE\Cluster\MSDTC" $true "`t"
	$local:data		+= Get-RegistryKeyAsXML "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC" $true "`t"
	$local:data		+= Get-RegistryKeyAsXML "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CID" $true "`t"
	$local:data		+= Get-RegistryKeyAsXML "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CID.Local" $true "`t"
	$local:data		+= Get-RegistryKeyAsXML "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Rpc\Internet" $true "`t"
	$local:data		+= Get-RegistryKeyAsXML "HKEY_LOCAL_MACHINE\Cluster\Resources" $true "`t"
	$local:data		+= Get-RegistryKeyAsXML "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\MSDTC" $true "`t"
	$local:data		+= Get-RegistryKeyAsXML "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Rpc\Internet" $true "`t"
	$local:data		+= Get-RegistryKeyAsXML "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" $true "`t"
	$local:data		+= Get-RegistryKeyAsXML "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows NT\Rpc" $true "`t"
	$local:data		+= Get-RegistryKeyAsXML "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\MSDTC" $true "`t"
	$local:data		+= Get-RegistryKeyAsXML "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole" $true "`t"
	$local:data		+= "</SDP_MSDTC_Registry_Data>`r`n"
	return $local:data
}

###########################################################
#
# Last Update: 5-5-2011
# Author: jlaborde
#
# Description:
#  analyze XML representation of the DTC keys in XML format and report on the settings
#   focuses on local DTC
#
# Usage:
#  Analyze-LocalDTCRegistryKeysXML "file.xml" [DTCSettingsClass]
#
# Example:
#  Analyze-LocalDTCRegistryKeysXML "C:\\msdtc.xml" $myDTCSettings
#   where $myDTCSettings is an instance of Get-NewDTCSettingsClass
#
###########################################################

function Analyze-LocalDTCRegistryKeysXML( [string]$local:file, [Object]$local:DTCSettingsClass )
{	#process XML file
	$local:xmldata			= [xml](Get-Content $local:file)
	# process look up the keys we'll need
	$local:dtckey			= Get-XMLRegistryKey $local:xmldata.SDP_MSDTC_Registry_Data "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC"
	$local:security			= Get-XMLRegistryKey $local:dtckey "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC\Security"
	$local:tracingkey		= Get-XMLRegistryKey $local:xmldata.SDP_MSDTC_Registry_Data "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\MSDTC"
	$local:trLogOptionskey	= Get-XMLRegistryKey $local:tracingkey "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\MSDTC\LoggingOptions"
	$local:trmoduleskey		= Get-XMLRegistryKey $local:tracingkey "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\MSDTC\Modules"
	$local:trmdttkey		= Get-XMLRegistryKey $local:trmoduleskey "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\MSDTC\Modules\Transaction_Transitions"
	$local:vistatracekey	= Get-XMLRegistryKey $local:dtckey "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC\Tracing"
	$local:vistaoutputkey	= Get-XMLRegistryKey $local:vistatracekey "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC\Tracing\Output"
	$local:vistasourceskey	= Get-XMLRegistryKey $local:vistatracekey "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC\Tracing\Sources"
	$local:olekey			= Get-XMLRegistryKey $local:xmldata.SDP_MSDTC_Registry_Data "HKEY_LOCAL_MACHINE\Software\Microsoft\OLE"


	# read settings
	$local:DTCSettingsClass.AccountName							= Get-XMLRegistryEntryValue   $local:security			"AccountName"
	# network access controls
	$local:DTCSettingsClass.NetworkDTCAccessOn					= Get-XMLRegistryEntryOnOrOff $local:security			"NetworkDtcAccess"
	$local:DTCSettingsClass.NetworkDTCAccessTransactionsOn		= Get-XMLRegistryEntryOnOrOff $local:security			"NetworkDtcAccessTransactions"
	$local:DTCSettingsClass.NetworkDTCAccessInboundOn			= Get-XMLRegistryEntryOnOrOff $local:security			"NetworkDTCAccessInbound"
	$local:DTCSettingsClass.NetworkDTCAccessOutboundOn			= Get-XMLRegistryEntryOnOrOff $local:security			"NetworkDTCAccessOutbound"
	$local:DTCSettingsClass.AllowRemoteClientsOn				= Get-XMLRegistryEntryOnOrOff $local:security			"NetworkDtcAccessClients"
	$local:DTCSettingsClass.AllowRemoteAdministrationOn			= Get-XMLRegistryEntryOnOrOff $local:security			"NetworkDtcAccessAdmin"
	# XA / LU transactions
	$local:DTCSettingsClass.XATransactionsOn					= Get-XMLRegistryEntryOnOrOff $local:security			"XaTransactions"
	$local:DTCSettingsClass.LuTransactionsOn					= Get-XMLRegistryEntryOnOrOff $local:security			"LuTransactions"
	# Authentication
	$local:DTCSettingsClass.AllowOnlySecureRpcCallsOn			= Get-XMLRegistryEntryOnOrOff $local:dtckey				"AllowOnlySecureRpcCalls"
	$local:DTCSettingsClass.FallbackToUnsecureRPCIfNecessaryOn	= Get-XMLRegistryEntryOnOrOff $local:dtckey				"FallbackToUnsecureRPCIfNecessary"
	$local:DTCSettingsClass.TurnOffRpcSecurityOn				= Get-XMLRegistryEntryOnOrOff $local:dtckey				"TurnOffRpcSecurity"
	# CM tracing
	$local:DTCSettingsClass.TraceCMErrOn						= Get-XMLRegistryEntryOnOrOff $local:dtckey				"TraceCMErr"
	$local:DTCSettingsClass.TraceCMErrLogName					= Get-XMLRegistryEntryValue   $local:dtckey				"TraceCMErrLogName"
	# Transaction tracing
	$local:DTCSettingsClass.ControlFlags						= Get-XMLRegistryEntryValue   $local:trmdttkey			"ControlFlags"
	$local:DTCSettingsClass.TraceOutputOn						= Get-XMLRegistryEntryOnOrOff $local:trmoduleskey		"Active"
	$local:DTCSettingsClass.TraceTransactionsOn					= Get-XMLRegistryEntryOnOrOff $local:trmdttkey			"Active"
	$local:DTCSettingsClass.MaxBuffers							= Get-XMLRegistryEntryValue   $local:trLogOptionskey	"MaxBuffers"
	# TIP
	$local:DTCSettingsClass.NetworkDtcAccessTipOn				= Get-XMLRegistryEntryOnOrOff $local:security			"NetworkDtcAccessTip"
	$local:DTCSettingsClass.DisableTipTmIdVerificationOn		= Get-XMLRegistryEntryOnOrOff $local:dtckey				"DisableTipTmIdVerification"
	$local:DTCSettingsClass.DisableTipTmIdPortVerificationOn	= Get-XMLRegistryEntryOnOrOff $local:dtckey				"DisableTipTmIdPortVerification"
	$local:DTCSettingsClass.DisableTipBeginCheckOn				= Get-XMLRegistryEntryOnOrOff $local:dtckey				"DisableTipBeginCheck"
	$local:DTCSettingsClass.DisableTipPassThruCheckOn			= Get-XMLRegistryEntryOnOrOff $local:dtckey				"DisableTipPassThruCheck"
	# read vista+ trace keys
	$local:DTCSettingsClass.VistaTracing_DebugOutEnabled		= Get-XMLRegistryEntryValue $local:vistaoutputkey "DebugOutEnabled"
	$local:DTCSettingsClass.VistaTracing_TraceFilePath			= Get-XMLRegistryEntryValue $local:vistaoutputkey "TraceFilePath"
	$local:DTCSettingsClass.VistaTracing_MemoryBufferSize		= Get-XMLRegistryEntryValue $local:vistaoutputkey "MemoryBufferSize"
	$local:DTCSettingsClass.VistaTracing_Trace_Misc				= Get-XMLRegistryEntryValue $local:vistasourceskey "TRACE_MISC"
	$local:DTCSettingsClass.VistaTracing_Trace_CM				= Get-XMLRegistryEntryValue $local:vistasourceskey "TRACE_CM"
	$local:DTCSettingsClass.VistaTracing_Trace_Trace			= Get-XMLRegistryEntryValue $local:vistasourceskey "TRACE_TRACE"
	$local:DTCSettingsClass.VistaTracing_Trace_SVC				= Get-XMLRegistryEntryValue $local:vistasourceskey "TRACE_SVC"
	$local:DTCSettingsClass.VistaTracing_Trace_Gateway			= Get-XMLRegistryEntryValue $local:vistasourceskey "TRACE_GATEWAY"
	$local:DTCSettingsClass.VistaTracing_Trace_UI				= Get-XMLRegistryEntryValue $local:vistasourceskey "TRACE_UI"
	$local:DTCSettingsClass.VistaTracing_Trace_Contact			= Get-XMLRegistryEntryValue $local:vistasourceskey "TRACE_CONTACT"
	$local:DTCSettingsClass.VistaTracing_Trace_Util				= Get-XMLRegistryEntryValue $local:vistasourceskey "TRACE_UTIL"
	$local:DTCSettingsClass.VistaTracing_Trace_Cluster			= Get-XMLRegistryEntryValue $local:vistasourceskey "TRACE_CLUSTER"
	$local:DTCSettingsClass.VistaTracing_Trace_Resource			= Get-XMLRegistryEntryValue $local:vistasourceskey "TRACE_RESOURCE"
	$local:DTCSettingsClass.VistaTracing_Trace_TIP				= Get-XMLRegistryEntryValue $local:vistasourceskey "TRACE_TIP"
	$local:DTCSettingsClass.VistaTracing_Trace_XA				= Get-XMLRegistryEntryValue $local:vistasourceskey "TRACE_XA"
	$local:DTCSettingsClass.VistaTracing_Trace_Log				= Get-XMLRegistryEntryValue $local:vistasourceskey "TRACE_LOG"
	$local:DTCSettingsClass.VistaTracing_Trace_MTXOCI			= Get-XMLRegistryEntryValue $local:vistasourceskey "TRACE_MTXOCI"
	$local:DTCSettingsClass.VistaTracing_Trace_ETWTrace			= Get-XMLRegistryEntryValue $local:vistasourceskey "TRACE_ETWTRACE"
	$local:DTCSettingsClass.VistaTracing_Trace_Proxy			= Get-XMLRegistryEntryValue $local:vistasourceskey "TRACE_PROXY"
	$local:DTCSettingsClass.VistaTracing_Trace_KTMRM			= Get-XMLRegistryEntryValue $local:vistasourceskey "TRACE_KTMRM"
	$local:DTCSettingsClass.VistaTracing_Trace_VSSBackup		= Get-XMLRegistryEntryValue $local:vistasourceskey "TRACE_VSSBACKUP"
	# ole keys
	$global:DCOMEnabled											= Get-XMLRegistryEntryValue $local:olekey "EnableDCOM"




	# look up log file info
	$local:clsidkey				= Get-XMLRegistryKey $local:xmldata.SDP_MSDTC_Registry_Data "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CID"
	$local:clsidkey				= Get-XMLRegistryKeyBasedOnSubkey $local:clsidkey "Description" "MSDTC"
	if( $null -eq $local:clsidkey )
	{	$local:DTCSettingsClass.LogPath	= ""
		$local:DTCSettingsClass.LogSize	= 0
	} else
	{	$local:clsidkey2		= Get-XMLRegistryKey $local:clsidkey  ($local:clsidkey.Name + "\CustomProperties")
		$local:clsidkey2		= Get-XMLRegistryKey $local:clsidkey2 ($local:clsidkey.Name + "\CustomProperties\LOG")
		$local:clsidkey3		= Get-XMLRegistryKey $local:clsidkey2 ($local:clsidkey.Name + "\CustomProperties\LOG\Path")
		$local:DTCSettingsClass.LogPath	= $local:clsidkey3.Value

		$local:clsidkey3		= Get-XMLRegistryKey $local:clsidkey2 ($local:clsidkey.Name + "\CustomProperties\LOG\Size")
		$local:DTCSettingsClass.LogSize	= $local:clsidkey3.Value
	}


	#checks for allow inbound
	if( $local:DTCSettingsClass.NetworkDtcAccessOn -and $local:DTCSettingsClass.NetworkDtcAccessTransactionsOn -and $local:DTCSettingsClass.NetworkDtcAccessInboundOn )
	{	$local:DTCSettingsClass.AllowInbound	= $true		} else
	{	$local:DTCSettingsClass.AllowInbound	= $false	}
	#checks for allow outbound
	if( $local:DTCSettingsClass.NetworkDtcAccessOn -and $local:DTCSettingsClass.NetworkDtcAccessTransactionsOn -and $local:DTCSettingsClass.NetworkDtcAccessOutboundOn )
	{	$local:DTCSettingsClass.AllowOutbound	= $true		} else
	{	$local:DTCSettingsClass.AllowOutbound	= $false	}


	#get authentication method
	$local:DTCSettingsClass.MutualAuthRequired				= $false
	$local:DTCSettingsClass.IncomingCallerAuthRequired		= $false
	$local:DTCSettingsClass.NoAuthRequired					= $false

	if( $local:DTCSettingsClass.AllowOnlySecureRpcCallsOn -and !$local:DTCSettingsClass.FallbackToUnsecureRPCIfNecessaryOn -and !$local:DTCSettingsClass.TurnOffRpcSecurityOn )
	{	$local:DTCSettingsClass.MutualAuthRequired			= $true
	}
	if( !$local:DTCSettingsClass.AllowOnlySecureRpcCallsOn -and $local:DTCSettingsClass.FallbackToUnsecureRPCIfNecessaryOn -and !$local:DTCSettingsClass.TurnOffRpcSecurityOn )
	{	$local:DTCSettingsClass.IcnomingCallerAuthRequired	= $true
	}
	if( !$local:DTCSettingsClass.AllowOnlySecureRpcCallsOn -and !$local:DTCSettingsClass.FallbackToUnsecureRPCIfNecessaryOn -and $local:DTCSettingsClass.TurnOffRpcSecurityOn )
	{	$local:DTCSettingsClass.NoAuthRequired				= $true
	}


	#cracking the control flags & active states
	switch( [int] $local:DTCSettingsClass.ControlFlags )
	{
		0			{	$local:DTCSettingsClass.TraceAllTransActionsOn			= $false
						$local:DTCSettingsClass.TraceAllAbortedTransactionsOn	= $false
						$local:DTCSettingsClass.TraceLongLivedTransactionsOn	= $false	}
		1			{	$local:DTCSettingsClass.TraceAllTransActionsOn			= $false
						$local:DTCSettingsClass.TraceAllAbortedTransactionsOn	= $true
						$local:DTCSettingsClass.TraceLongLivedTransactionsOn	= $false	}
		2			{	$local:DTCSettingsClass.TraceAllTransActionsOn			= $false
						$local:DTCSettingsClass.TraceAllAbortedTransactionsOn	= $false
						$local:DTCSettingsClass.TraceLongLivedTransactionsOn	= $true		}
		3			{	$local:DTCSettingsClass.TraceAllTransActionsOn			= $false
						$local:DTCSettingsClass.TraceAllAbortedTransactionsOn	= $true
						$local:DTCSettingsClass.TraceLongLivedTransactionsOn	= $true		}
		16777215	{	$local:DTCSettingsClass.TraceAllTransActionsOn			= $true
						$local:DTCSettingsClass.TraceAllAbortedTransactionsOn	= $true
						$local:DTCSettingsClass.TraceLongLivedTransactionsOn	= $true		}
	}


	# setup data to collect CM traces, if present
	if( $local:DTCSettingsClass.TraceCMErrOn )
	{	# easy case - its set
		if( $null -ne $local:DTCSettingsClass.TraceCMErrLogName )
		{	# actual log will be the one specified, plus a pid, plus .txt
			# we're going to collect them all
			# check to see if this points to a folder
			if( (Test-Path $local:DTCSettingsClass.TraceCMErrLogName) )
			{	# if it exist, it must be a folder as we add the pid and .txt to the end, so set up for default name
				$local:DTCSettingsClass.CM_Tracing_LogFolder	= $local:DTCSettingsClass.TraceCMErrLogName
				$local:DTCSettingsClass.CM_Tracing_LogFileMask	= $local:DTCSettingsClass.TraceCMErrLogName + "\MsDtcCMErr*"
			} else
			{	# try to treat the end of it as a file name
				$local:DTCSettingsClass.CM_Tracing_LogFolder	= $local:DTCSettingsClass.TraceCMErrLogName.SubString( 0, $local:DTCSettingsClass.TraceCMErrLogName.LastIndexOf( "\" ) )
				# if the previous letter is ':', its a drive
				if( $local:DTCSettingsClass.CM_Tracing_LogFolder.EndsWith( ":" ) )
				{	$local:DTCSettingsClass.CM_Tracing_LogFolder += "\"
				}
				# see if this exists
				if( (Test-Path $local:DTCSettingsClass.CM_Tracing_LogFolder) )
				{	# set our mask
					$local:DTCSettingsClass.CM_Tracing_LogFileMask	= $local:DTCSettingsClass.TraceCMErrLogName + "*"
				} else
				{	# its just not there
					$local:DTCSettingsClass.CM_Tracing_LogFileMask	= ""
				}
			}
		}
		else
		{	# folder depends on OS & user account msdtc is ran under
			# lets get the OS folder type of the temp directory like so... ( here's hoping no one moves their temp folder )
			$local:temp		= $Env:TEMP
			$local:tIndex1	= $local:temp.IndexOf( "\" ) +1
			$local:tIndex2	= $local:temp.IndexOf( "\", $local:tIndex1 )
			$local:tempP1	= $local:temp.Substring( 0, $local:tIndex2 +1 )
			# $local:tempP1 should now be something like C:\Users or C:\Documents & Settings
			# now get the second part of the temp path, past the user name
			$local:tIndex1	= $local:temp.IndexOf( "\", $local:tIndex2 +1 )
			$local:tempP2	= $local:temp.Substring( $local:tIndex1 )
			# $local:tempP2 should now be something like \AppData\Local\Temp or \Local Settings\Temp
			# now let's get just the account name
			if( $null -eq $local:DTCSettingsClass.AccountName )
			{	$local:tAccount	= "NetworkService"		# our default
			} else
			{	$local:tIndex1	= $local:DTCSettingsClass.AccountName.IndexOf( "\" )
				if( $local:tIndex1 -eq -1 )
				{	$local:tAccount	= "NetworkService"	# our default
				} else
				{	$local:tAccount	= $local:DTCSettingsClass.AccountName.Substring( $local:tIndex1 +1 )
				}
			}
			# $local:tAccount should now be our plain account name
			# lets put all the pieces together now...
			$local:DTCSettingsClass.CM_Tracing_LogFolder	= $local:tempP1 + $local:tAccount + $local:tempP2
			$local:DTCSettingsClass.CM_Tracing_LogFileMask	= $local:tempP1 + $local:tAccount + $local:tempP2 + "MsDtcCMErr*"
			# while we're here, see if the path exists...
			if( (Test-Path $local:DTCSettingsClass.CM_Tracing_LogFolder) -eq $false )
			{	# clear them out
				$local:DTCSettingsClass.CM_Tracing_LogFileMask	= ""
			}
		}
	}


	#cm tracing on?
	if( $local:DTCSettingsClass.TraceCMErrOn )
	{	# check that folder exists
		if( $local:DTCSettingsClass.CM_Tracing_LogFolder -ne "" -and (Test-Path $local:DTCSettingsClass.CM_Tracing_LogFolder) -eq $true )
		{	# CM tracing is on and should be functioning
			$local:DTCSettingsClass.CMTracingOn	= $true
		} else
		{	# CM tracing is on but not functioning since the folder does not exist
			$local:DTCSettingsClass.CMTracingOn	= $false
		}
	} else
	{	$local:DTCSettingsClass.CMTracingOn		= $false
	}
	
	# vista+ diagnostic tracing on?
	if( $null -eq $local:DTCSettingsClass.VistaTracing_TraceFilePath -or
		$local:DTCSettingsClass.VistaTracing_TraceFilePath -eq "" -or
		$null -eq $local:DTCSettingsClass.VistaTracing_MemoryBufferSize -or
		$local:DTCSettingsClass.VistaTracing_MemoryBufferSize -eq 0 )
	{
		$local:DTCSettingsClass.NewDiagnosticTracingOn	= $false
	} else
	{	$local:DTCSettingsClass.NewDiagnosticTracingOn	= $true
	}
}
function Analyze-2K3_LocalDTCRegistryKeysXML( [string]$local:file, [Object]$local:DTCSettingsClass )
{	#ignore XML file pre-Win7
	#$local:xmldata			= [xml](Get-Content $local:file)
	# strings to the keys we'll need
	$local:dtckey			= "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC"
	$local:security			= "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC\Security"
	$local:tracingkey		= "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\MSDTC"
	$local:trLogOptionskey	= "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\MSDTC\LoggingOptions"
	$local:trmoduleskey		= "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\MSDTC\Modules"
	$local:trmdttkey		= "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\MSDTC\Modules\Transaction_Transitions"
	$local:vistatracekey	= "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC\Tracing"
	$local:vistaoutputkey	= "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC\Tracing\Output"
	$local:vistasourceskey	= "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC\Tracing\Sources"
	$local:olekey			= "HKEY_LOCAL_MACHINE\Software\Microsoft\OLE"


	# read settings
	$local:DTCSettingsClass.AccountName							= Get-RegKeyValue $local:security			"AccountName"
	# network access controls
	$local:DTCSettingsClass.NetworkDTCAccessOn					= Get-RegKeyBool $local:security			"NetworkDtcAccess"
	$local:DTCSettingsClass.NetworkDTCAccessTransactionsOn		= Get-RegKeyBool $local:security			"NetworkDtcAccessTransactions"
	$local:DTCSettingsClass.NetworkDTCAccessInboundOn			= Get-RegKeyBool $local:security			"NetworkDTCAccessInbound"
	$local:DTCSettingsClass.NetworkDTCAccessOutboundOn			= Get-RegKeyBool $local:security			"NetworkDTCAccessOutbound"
	$local:DTCSettingsClass.AllowRemoteClientsOn				= Get-RegKeyBool $local:security			"NetworkDtcAccessClients"
	$local:DTCSettingsClass.AllowRemoteAdministrationOn			= Get-RegKeyBool $local:security			"NetworkDtcAccessAdmin"
	# XA transactions
	$local:DTCSettingsClass.XATransactionsOn					= Get-RegKeyBool $local:security			"XaTransactions"
	# Authentication
	$local:DTCSettingsClass.AllowOnlySecureRpcCallsOn			= Get-RegKeyBool $local:dtckey				"AllowOnlySecureRpcCalls"
	$local:DTCSettingsClass.FallbackToUnsecureRPCIfNecessaryOn	= Get-RegKeyBool $local:dtckey				"FallbackToUnsecureRPCIfNecessary"
	$local:DTCSettingsClass.TurnOffRpcSecurityOn				= Get-RegKeyBool $local:dtckey				"TurnOffRpcSecurity"
	# CM tracing
	$local:DTCSettingsClass.TraceCMErrOn						= Get-RegKeyBool 	$local:dtckey			"TraceCMErr"
	$local:DTCSettingsClass.TraceCMErrLogName					= Get-RegKeyValue   $local:dtckey			"TraceCMErrLogName"
	# Transaction tracing
	$local:DTCSettingsClass.ControlFlags						= Get-RegKeyValue   $local:trmdttkey		"ControlFlags"
	$local:DTCSettingsClass.TraceOutputOn						= Get-RegKeyBool 	$local:trmoduleskey		"Active"
	$local:DTCSettingsClass.TraceTransactionsOn					= Get-RegKeyBool 	$local:trmdttkey		"Active"
	$local:DTCSettingsClass.MaxBuffers							= Get-RegKeyValue   $local:trLogOptionskey	"MaxBuffers"
	# TIP
	$local:DTCSettingsClass.NetworkDtcAccessTipOn				= Get-RegKeyBool $local:security			"NetworkDtcAccessTip"
	# read vista+ trace keys
	$local:DTCSettingsClass.VistaTracing_DebugOutEnabled		= Get-RegKeyValue $local:vistaoutputkey  "DebugOutEnabled"
	$local:DTCSettingsClass.VistaTracing_TraceFilePath			= Get-RegKeyValue $local:vistaoutputkey  "TraceFilePath"
	$local:DTCSettingsClass.VistaTracing_MemoryBufferSize		= Get-RegKeyValue $local:vistaoutputkey  "MemoryBufferSize"
	$local:DTCSettingsClass.VistaTracing_Trace_Misc				= Get-RegKeyValue $local:vistasourceskey "TRACE_MISC"
	$local:DTCSettingsClass.VistaTracing_Trace_CM				= Get-RegKeyValue $local:vistasourceskey "TRACE_CM"
	$local:DTCSettingsClass.VistaTracing_Trace_Trace			= Get-RegKeyValue $local:vistasourceskey "TRACE_TRACE"
	$local:DTCSettingsClass.VistaTracing_Trace_SVC				= Get-RegKeyValue $local:vistasourceskey "TRACE_SVC"
	$local:DTCSettingsClass.VistaTracing_Trace_Gateway			= Get-RegKeyValue $local:vistasourceskey "TRACE_GATEWAY"
	$local:DTCSettingsClass.VistaTracing_Trace_UI				= Get-RegKeyValue $local:vistasourceskey "TRACE_UI"
	$local:DTCSettingsClass.VistaTracing_Trace_Contact			= Get-RegKeyValue $local:vistasourceskey "TRACE_CONTACT"
	$local:DTCSettingsClass.VistaTracing_Trace_Util				= Get-RegKeyValue $local:vistasourceskey "TRACE_UTIL"
	$local:DTCSettingsClass.VistaTracing_Trace_Cluster			= Get-RegKeyValue $local:vistasourceskey "TRACE_CLUSTER"
	$local:DTCSettingsClass.VistaTracing_Trace_Resource			= Get-RegKeyValue $local:vistasourceskey "TRACE_RESOURCE"
	$local:DTCSettingsClass.VistaTracing_Trace_TIP				= Get-RegKeyValue $local:vistasourceskey "TRACE_TIP"
	$local:DTCSettingsClass.VistaTracing_Trace_XA				= Get-RegKeyValue $local:vistasourceskey "TRACE_XA"
	$local:DTCSettingsClass.VistaTracing_Trace_Log				= Get-RegKeyValue $local:vistasourceskey "TRACE_LOG"
	$local:DTCSettingsClass.VistaTracing_Trace_MTXOCI			= Get-RegKeyValue $local:vistasourceskey "TRACE_MTXOCI"
	$local:DTCSettingsClass.VistaTracing_Trace_ETWTrace			= Get-RegKeyValue $local:vistasourceskey "TRACE_ETWTRACE"
	$local:DTCSettingsClass.VistaTracing_Trace_Proxy			= Get-RegKeyValue $local:vistasourceskey "TRACE_PROXY"
	$local:DTCSettingsClass.VistaTracing_Trace_KTMRM			= Get-RegKeyValue $local:vistasourceskey "TRACE_KTMRM"
	$local:DTCSettingsClass.VistaTracing_Trace_VSSBackup		= Get-RegKeyValue $local:vistasourceskey "TRACE_VSSBACKUP"
	# ole keys
	$global:DCOMEnabled											= Get-RegKeyValue $local:olekey			 "EnableDCOM"




	# look up log file info
	$local:clsidkey				= Get-RegistryKeyBasedOnSubkey "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CID" "Description" "MSDTC"
	if( $null -eq $local:clsidkey )
	{	$local:DTCSettingsClass.LogPath	= ""
		$local:DTCSettingsClass.LogSize	= 0
	} else
	{	$local:clsidkey3		= ($local:clsidkey.Name + "\CustomProperties\LOG\Path")
		$local:DTCSettingsClass.LogPath	= Get-RegKeyValue $local:clsidkey3 ""

		$local:clsidkey3		= ($local:clsidkey.Name + "\CustomProperties\LOG\Size")
		$local:DTCSettingsClass.LogSize	= Get-RegKeyValue $local:clsidkey3 ""
	}
	# look up the remote host, if present
	$local:clsidkey				= Get-RegistryKeyBasedOnSubkey "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CID" "Description" "MSDTC Default"
	if( $null -ne $local:clsidkey )
	{	$local:clsidkey3		= ($local:clsidkey.Name + "\CustomProperties\LOG\Path")
		$local:DTCSettingsClass.LogPath					= Get-RegKeyValue $local:clsidkey3 ""

		$local:clsidkey3		= ($local:clsidkey.Name + "\CustomProperties\LOG\Size")
		$local:DTCSettingsClass.LogSize					= Get-RegKeyValue $local:clsidkey3 ""

		$local:clsidkey3		= ($local:clsidkey.Name + "\Host")
		$local:DTCSettingsClass.RemoteHostName			= Get-RegKeyValue $local:clsidkey3 ""
		$local:DTCSettingsClass.UsingLocalDTCSettings	= $false
	} else
	{	$local:DTCSettingsClass.UsingLocalDTCSettings	= $true
	}



	#checks for allow inbound
	if( $local:DTCSettingsClass.NetworkDtcAccessOn -and $local:DTCSettingsClass.NetworkDtcAccessTransactionsOn -and $local:DTCSettingsClass.NetworkDtcAccessInboundOn )
	{	$local:DTCSettingsClass.AllowInbound	= $true		} else
	{	$local:DTCSettingsClass.AllowInbound	= $false	}
	#checks for allow outbound
	if( $local:DTCSettingsClass.NetworkDtcAccessOn -and $local:DTCSettingsClass.NetworkDtcAccessTransactionsOn -and $local:DTCSettingsClass.NetworkDtcAccessOutboundOn )
	{	$local:DTCSettingsClass.AllowOutbound	= $true		} else
	{	$local:DTCSettingsClass.AllowOutbound	= $false	}


	#get authentication method
	$local:DTCSettingsClass.MutualAuthRequired				= $false
	$local:DTCSettingsClass.IncomingCallerAuthRequired		= $false
	$local:DTCSettingsClass.NoAuthRequired					= $false

	if( $local:DTCSettingsClass.AllowOnlySecureRpcCallsOn -and !$local:DTCSettingsClass.FallbackToUnsecureRPCIfNecessaryOn -and !$local:DTCSettingsClass.TurnOffRpcSecurityOn )
	{	$local:DTCSettingsClass.MutualAuthRequired			= $true
	}
	if( !$local:DTCSettingsClass.AllowOnlySecureRpcCallsOn -and $local:DTCSettingsClass.FallbackToUnsecureRPCIfNecessaryOn -and !$local:DTCSettingsClass.TurnOffRpcSecurityOn )
	{	$local:DTCSettingsClass.IcnomingCallerAuthRequired	= $true
	}
	if( !$local:DTCSettingsClass.AllowOnlySecureRpcCallsOn -and !$local:DTCSettingsClass.FallbackToUnsecureRPCIfNecessaryOn -and $local:DTCSettingsClass.TurnOffRpcSecurityOn )
	{	$local:DTCSettingsClass.NoAuthRequired				= $true
	}


	#cracking the control flags & active states
	switch( [int] $local:DTCSettingsClass.ControlFlags )
	{
		0			{	$local:DTCSettingsClass.TraceAllTransActionsOn			= $false
						$local:DTCSettingsClass.TraceAllAbortedTransactionsOn	= $false
						$local:DTCSettingsClass.TraceLongLivedTransactionsOn	= $false	}
		1			{	$local:DTCSettingsClass.TraceAllTransActionsOn			= $false
						$local:DTCSettingsClass.TraceAllAbortedTransactionsOn	= $true
						$local:DTCSettingsClass.TraceLongLivedTransactionsOn	= $false	}
		2			{	$local:DTCSettingsClass.TraceAllTransActionsOn			= $false
						$local:DTCSettingsClass.TraceAllAbortedTransactionsOn	= $false
						$local:DTCSettingsClass.TraceLongLivedTransactionsOn	= $true		}
		3			{	$local:DTCSettingsClass.TraceAllTransActionsOn			= $false
						$local:DTCSettingsClass.TraceAllAbortedTransactionsOn	= $true
						$local:DTCSettingsClass.TraceLongLivedTransactionsOn	= $true		}
		16777215	{	$local:DTCSettingsClass.TraceAllTransActionsOn			= $true
						$local:DTCSettingsClass.TraceAllAbortedTransactionsOn	= $true
						$local:DTCSettingsClass.TraceLongLivedTransactionsOn	= $true		}
	}


	# setup data to collect CM traces, if present
	if( $local:DTCSettingsClass.TraceCMErrOn )
	{	# easy case - its set
		if( $null -ne $local:DTCSettingsClass.TraceCMErrLogName )
		{	# actual log will be the one specified, plus a pid, plus .txt
			# we're going to collect them all
			# check to see if this points to a folder
			if( (Test-Path $local:DTCSettingsClass.TraceCMErrLogName) )
			{	# if it exist, it must be a folder as we add the pid and .txt to the end, so set up for default name
				$local:DTCSettingsClass.CM_Tracing_LogFolder	= $local:DTCSettingsClass.TraceCMErrLogName
				$local:DTCSettingsClass.CM_Tracing_LogFileMask	= $local:DTCSettingsClass.TraceCMErrLogName + "\MsDtcCMErr*"
			} else
			{	# try to treat the end of it as a file name
				$local:DTCSettingsClass.CM_Tracing_LogFolder	= $local:DTCSettingsClass.TraceCMErrLogName.SubString( 0, $local:DTCSettingsClass.TraceCMErrLogName.LastIndexOf( "\" ) )
				# if the previous letter is ':', its a drive
				if( $local:DTCSettingsClass.CM_Tracing_LogFolder.EndsWith( ":" ) )
				{	$local:DTCSettingsClass.CM_Tracing_LogFolder += "\"
				}
				# see if this exists
				if( (Test-Path $local:DTCSettingsClass.CM_Tracing_LogFolder) )
				{	# set our mask
					$local:DTCSettingsClass.CM_Tracing_LogFileMask	= $local:DTCSettingsClass.TraceCMErrLogName + "*"
				} else
				{	# its just not there
					$local:DTCSettingsClass.CM_Tracing_LogFileMask	= ""
				}
			}
		}
		else
		{	# folder depends on OS & user account msdtc is ran under
			# lets get the OS folder type of the temp directory like so... ( here's hoping no one moves their temp folder )
			$local:temp		= $Env:TEMP
			$local:tIndex1	= $local:temp.IndexOf( "\" ) +1
			$local:tIndex2	= $local:temp.IndexOf( "\", $local:tIndex1 )
			$local:tempP1	= $local:temp.Substring( 0, $local:tIndex2 +1 )
			# $local:tempP1 should now be something like C:\Users or C:\Documents & Settings
			# now get the second part of the temp path, past the user name
			$local:tIndex1	= $local:temp.IndexOf( "\", $local:tIndex2 +1 )
			$local:tempP2	= $local:temp.Substring( $local:tIndex1 )
			# $local:tempP2 should now be something like \AppData\Local\Temp or \Local Settings\Temp
			# now let's get just the account name
			if( $null -eq $local:DTCSettingsClass.AccountName )
			{	$local:tAccount	= "NetworkService"		# our default
			} else
			{	$local:tIndex1	= $local:DTCSettingsClass.AccountName.IndexOf( "\" )
				if( $local:tIndex1 -eq -1 )
				{	$local:tAccount	= "NetworkService"	# our default
				} else
				{	$local:tAccount	= $local:DTCSettingsClass.AccountName.Substring( $local:tIndex1 +1 )
				}
			}
			# $local:tAccount should now be our plain account name
			# lets put all the pieces together now...
			$local:DTCSettingsClass.CM_Tracing_LogFolder	= $local:tempP1 + $local:tAccount + $local:tempP2
			$local:DTCSettingsClass.CM_Tracing_LogFileMask	= $local:tempP1 + $local:tAccount + $local:tempP2 + "MsDtcCMErr*"
			# while we're here, see if the path exists...
			if( (Test-Path $local:DTCSettingsClass.CM_Tracing_LogFolder) -eq $false )
			{	# clear them out
				$local:DTCSettingsClass.CM_Tracing_LogFileMask	= ""
			}
		}
	}


	#cm tracing on?
	if( $local:DTCSettingsClass.TraceCMErrOn )
	{	# check that folder exists
		if( $local:DTCSettingsClass.CM_Tracing_LogFolder -ne "" -and (Test-Path $local:DTCSettingsClass.CM_Tracing_LogFolder) -eq $true )
		{	# CM tracing is on and should be functioning
			$local:DTCSettingsClass.CMTracingOn	= $true
		} else
		{	# CM tracing is on but not functioning since the folder does not exist
			$local:DTCSettingsClass.CMTracingOn	= $false
		}
	} else
	{	$local:DTCSettingsClass.CMTracingOn		= $false
	}
	
	# vista+ diagnostic tracing on?
	if( $null -eq $local:DTCSettingsClass.VistaTracing_TraceFilePath -or
		$local:DTCSettingsClass.VistaTracing_TraceFilePath -eq "" -or
		$null -eq $local:DTCSettingsClass.VistaTracing_MemoryBufferSize -or
		$local:DTCSettingsClass.VistaTracing_MemoryBufferSize -eq 0 )
	{
		$local:DTCSettingsClass.NewDiagnosticTracingOn	= $false
	} else
	{	$local:DTCSettingsClass.NewDiagnosticTracingOn	= $true
	}
}

###########################################################
#
# Last Update: 5-5-2011
# Author: jlaborde
#
# Description:
# produce summary data based on DTC settings
#
# Usage:
#  Get-MSDTCSummaryInfo [DTCSettingsClass]
#
# Example:
#  Get-MSDTCSummaryInfo $myDTCSettings
#   where $myDTCSettings is an instance of Get-NewDTCSettingsClass
#
###########################################################

function Get-MSDTCSummaryInfo( [Object]$local:DTCSettingsClass )
{	$local:retv	= ""

	# output OS version
	$local:retv		+= $Env:COMPUTERNAME + " (" + ( Get-OSVersionString ) + ")`r`n"
	if( $global:DCOMEnabled -ne "Y" )
	{	$local:retv		+= "DCOM is NOT enabled!`r`n"
	}
	
	#get authentication method
	$local:DTCAuthentication					= ""
	if( $local:DTCSettingsClass.MutualAuthRequired )
	{	$local:DTCAuthentication				= "Mutual Authentication Required"	}
	if( $local:DTCSettingsClass.IcnomingCallerAuthRequired )
	{	$local:DTCAuthentication				= "Incoming Caller Authentication Required"	}
	if( $local:DTCSettingsClass.NoAuthRequired )
	{	$local:DTCAuthentication				= "No Authentication Required"	}

	#network access settings
	if( $local:DTCSettingsClass.NetworkDTCAccessOn )
	{	$local:retv		+= "Network DTC is ON`r`n"
		if( $local:DTCSettingsClass.AllowInbound )
		{	$local:retv	+= "`tAllow Inbound is ON`r`n"		} else {
			$local:retv	+= "`tAllow Inbound is OFF`r`n"		}
		if( $local:DTCSettingsClass.AllowOutbound )
		{	$local:retv	+= "`tAllow Outbound is ON`r`n"		} else {
			$local:retv	+= "`tAllow Outbound is OFF`r`n"	}
	} else {
		$local:retv		+= "Network DTC is OFF`r`n"
	}

	#account DTC runs as
	$local:retv	+= "MSDTC is running as " + $local:DTCSettingsClass.AccountName + "`r`n"

	#auth mode
	if( $local:DTCAuthentication -eq "" )
	{	$local:retv	+= "DTC Authentication is NOT set`r`n"
	} else {
		$local:retv	+= "DTC Authentication is set to " + $local:DTCAuthentication + "`r`n"
	}
	
	#using XA transaction?
	if( $local:DTCSettingsClass.XATransactionsOn )
	{	$local:retv	+= "DTC IS using XA Transactions`r`n"
	} else {
		$local:retv	+= "DTC is NOT using XA Transactions`r`n"
	}
	
	#cm tracing on?
	if( $local:DTCSettingsClass.TraceCMErrOn )
	{	$local:retv	+= "CM Tracing is turned ON`r`n"

		if( $local:DTCSettingsClass.CMTracingOn -eq $false )
		{	$local:retv	+= " but the output folder, " + $local:DTCSettingsClass.CM_Tracing_LogFolder + ", does NOT EXIST and tracing will NOT function!`r`n"
		}
		else
		{	$local:retv	+= " CM Tracing is logging to " + $local:DTCSettingsClass.CM_Tracing_LogFileMask + "`r`n"
		}
	} else
	{	$local:retv	+= "CM Tracing is not turned on`r`n"
	}
	
	#new diagnostic tracing on?
	if( $local:DTCSettingsClass.NewDiagnosticTracingOn )
	{	$local:retv += "Vista+ Diagnostic Tracing is turned ON`r`n"
	}

	
	return $local:retv
}

###########################################################
#
# Last Update: 5-5-2011
# Author: jlaborde
#
# Description:
#  produce static XAML representing DTC settings
#
# Usage:
#  Get-DTCSettingsAsXAML [DTCSettingsClass] [string]$local:Title
#
# Example:
#  Get-DTCSettingsAsXAML $myDTCSettings "Local"
#   where $myDTCSettings is an instance of Get-NewDTCSettingsClass
#    and $local:Title is an identity string
#
###########################################################

function Get-DTCSettingsAsXAML( [Object]$local:DTCSettingsClass, [string]$local:Title )
{
	#hardcode XAML doc:
	$local:XAML_DTC_Dialog = @"
<Canvas
   xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
   xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
   x:Name="Window"
   Width="420" Height="500"
   Background="#E0E0F0">

   <Canvas Top="5" Left="10"
      Width="400" Height="20"
      Background="#E0E0F0" >

      <TextBlock>DTC Properties (*gDTC_Title*)</TextBlock>

   </Canvas>

   <Canvas Top="25" Left="5"
      Width="410" Height="465"
      Background="#D0D0D0" >

      <Canvas Top="10" Left="10"
         Width="395" Height="430"
         Background="#D0D0D0" >

         <TabControl Width="390" Height="410" >

            <!-- Tracing -->
            <TabItem Header="Tracing">
               <Canvas>

               <!-- Output Options -->
               <Canvas Top="15" Left="10" >
                  <GroupBox
                     x:Name="Output_Options"
                     Header="Output Options"
                     Width="360" Height="150" >

                     <Canvas>
                        <Canvas Top="10" Left="0" >
                           <CheckBox Name="cbTraceOutput" IsChecked="*gDTC_TraceOutputOn*" >Trace Output</CheckBox>
                        </Canvas>

                        <Canvas Top="35" Left="10" >
                           <CheckBox Name="cbTraceTransactions" IsChecked="*gDTC_TraceTransactionsOn*" >Trace Transactions</CheckBox>
                        </Canvas>

                        <Canvas Top="60" Left="20" >
                           <CheckBox Name="cbTraceAllTransactions" IsChecked="*gDTC_TraceAllTransactionsOn*" >Trace All Transactions</CheckBox>
                        </Canvas>

                        <Canvas Top="85" Left="20" >
                           <CheckBox Name="cbTraceAbortedTransactions" IsChecked="*gDTC_TraceAbortedTransactionsOn*" >Trace Aborted Transactions</CheckBox>
                        </Canvas>

                        <Canvas Top="110" Left="20" >
                           <CheckBox Name="cbTraceLongLivedTransactions" IsChecked="*gDTC_TraceLongLivedTransactionsOn*" >Trace Long-Lived Transactions</CheckBox>
                        </Canvas>
                     </Canvas>

                  </GroupBox>
               </Canvas>
               <!-- End Output Options -->

               <!-- Logging Options -->
               <Canvas Top="170" Left="10" >
                  <GroupBox
                     x:Name="Logging_Options"
                     Header="Logging Options"
                     Width="360" Height="100" >

                     <Canvas>
                        <Canvas Top="10" Left="10" >
                           <Button Name="bNewSession" Width="80" Height="25" IsEnabled="false" >New Session</Button>
                        </Canvas>

                        <Canvas Top="10" Left="100" >
                           <Button Name="bStopSession" Width="80" Height="25" IsEnabled="false" >Stop Session</Button>
                        </Canvas>

                        <Canvas Top="10" Left="190" >
                           <Button Name="bFlushData" Width="80" Height="25" IsEnabled="false" >Flush Data</Button>
                        </Canvas>

                        <Canvas Top="45" Left="10" >
                           <TextBox Name="tbTraceTransactions" Width="40" Height="25" >*gDTC_MaxBuffers*</TextBox>
                        </Canvas>

                        <Canvas Top="45" Left="50" >
                           <Label>Max. Num. Of Memory Buffers (size PageSize)</Label>
                        </Canvas>
                     </Canvas>

                  </GroupBox>
               </Canvas>
               <!-- End Logging Options -->

               </Canvas>
            </TabItem>
            <!-- End Tracing -->

            <!-- Logging -->
            <TabItem Header="Logging">
               <Canvas Top="15" Left="10" >
                  <GroupBox
                     x:Name="Log_Information"
                     Header="Log Information"
                     Width="380" Height="100" >

                     <Canvas>
                        <Canvas Top="10" Left="0" >
                           <Label>Location:</Label>
                        </Canvas>
                        <Canvas Top="10" Left="110" >
                           <TextBox Name="tbLocation" Width="220" Height="20" IsEnabled="true" >*gDTC_LogPath*</TextBox>
                        </Canvas>

                        <Canvas Top="40" Left="0" >
                           <Label>Capacity:</Label>
                        </Canvas>
                        <Canvas Top="40" Left="110" >
                           <TextBox Name="tbCapacity" Width="80" Height="20" IsEnabled="true" >*gDTC_LogSize*</TextBox>
                        </Canvas>
                        <Canvas Top="40" Left="200" >
                           <Label>MB</Label>
                        </Canvas>
                     </Canvas>

                  </GroupBox>
               </Canvas>
            </TabItem>
            <!-- End Logging -->

            <!-- Security -->
            <TabItem Header="Security">
               <Canvas>

                  <!-- Security Settings -->
                  <Canvas Top="0" Left="0" >
                     <GroupBox
                        x:Name="Security_Settings"
                        Header="Security Settings"
                        Width="380" Height="260" >

                        <Canvas>
                           <!-- Network DTC Access -->
                           <Canvas Top="10" Left="5" >
                              <CheckBox Name="cbNetworkDTCAccess" IsChecked="*gDTC_NetworkDTCAccessOn*" >Network DTC Access</CheckBox>
                           </Canvas>

                           <!-- Client And Administration -->
                           <Canvas Top="30" Left="10" >
                              <GroupBox
                                 x:Name="Client_And_Administration"
                                 Header="Client And Administration"
                                 Width="350" Height="40" >

                                 <Canvas>
                                    <Canvas Top="5" Left="5" >
                                       <CheckBox Name="cbAllowRemoteClients" IsChecked="*gDTC_AllowRemoteClientsOn*" IsEnabled="*gDTC_NetworkDTCAccessOn*" >Allow Remote Clients</CheckBox>
                                    </Canvas>

                                    <Canvas Top="5" Left="180" >
                                       <CheckBox Name="cbAllowRemoteAdministration" IsChecked="*gDTC_AllowRemoteAdministrationOn*" IsEnabled="*gDTC_NetworkDTCAccessOn*" >Allow Remote Administration</CheckBox>
                                    </Canvas>
                                 </Canvas>

                              </GroupBox>
                           </Canvas>
                           <!-- End Client And Administration -->

                           <!-- Transaction Manager Communication -->
                           <Canvas Top="80" Left="10" >
                              <GroupBox
                                 x:Name="Transaction_Manager_Communication"
                                 Header="Transaction Manager Communication"
                                 Width="350" Height="130" >

                                 <Canvas>
                                    <Canvas Top="5" Left="5" >
                                       <CheckBox Name="cbAllowInbound" IsChecked="*gDTC_AllowInboundOn*" IsEnabled="*gDTC_NetworkDTCAccessOn*" >Allow Inbound</CheckBox>
                                    </Canvas>

                                    <Canvas Top="5" Left="180" >
                                       <CheckBox Name="cbAllowOutbound" IsChecked="*gDTC_AllowOutboundOn*" IsEnabled="*gDTC_NetworkDTCAccessOn*" >Allow Outbound</CheckBox>
                                    </Canvas>

                                    <Canvas Top="35" Left="20" >
                                       <RadioButton Name="rbMutualAuth" IsChecked="*gDTC_MutualAuthRequired*" IsEnabled="*gDTC_NetworkDTCAccessOn*" >Mutual Authentication Required</RadioButton>
                                    </Canvas>

                                    <Canvas Top="55" Left="20" >
                                       <RadioButton Name="rbIncomingCallerAuth" IsChecked="*gDTC_IncomingCallerAuthRequired*" IsEnabled="*gDTC_NetworkDTCAccessOn*" >Incoming Caller Authentication Required</RadioButton>
                                    </Canvas>

                                    <Canvas Top="75" Left="20" >
                                       <RadioButton Name="rbNoAuth" IsChecked="*gDTC_NoAuthRequired*" IsEnabled="*gDTC_NetworkDTCAccessOn*" >No Authentication Required</RadioButton>
                                    </Canvas>
                                 </Canvas>

                              </GroupBox>
                           </Canvas>
                           <!-- End Transaction Manager Communication -->

                           <!-- XA / SNA -->
                           <Canvas Top="220" Left="5" >
                              <CheckBox Name="cbEnableXATransactions" IsChecked="*gDTC_XATransactionsOn*" >Enable XA Transactions</CheckBox>
                           </Canvas>

                           <Canvas Top="220" Left="180" >
                              <CheckBox Name="cbEnableSNALU62Transactions" IsChecked="*gDTC_LuTransactionsOn*" >Enable SNA LU 6.2 Transactions</CheckBox>
                           </Canvas>
                           <!-- End XA / SNA -->

                        </Canvas>

                     </GroupBox>

                  </Canvas>
                  <!-- End Security Settings -->

                  <!-- DTC Logon Account -->
                  <Canvas Top="260" Left="0" >
                     <GroupBox
                        x:Name="DTC_Logon_Account"
                        Header="DTC Logon Account"
                        Width="380" Height="120" >

                        <Canvas>
                           <Canvas Top="10" Left="0" >
                              <Label>Account:</Label>
                           </Canvas>
                           <Canvas Top="10" Left="130" >
                              <TextBox Name="tbAccountName" Width="200" Height="20" >*gDTC_AccountName*</TextBox>
                           </Canvas>

                           <Canvas Top="40" Left="0" >
                              <Label>Password:</Label>
                           </Canvas>
                           <Canvas Top="40" Left="130" >
                              <TextBox Name="tbPassword1" Width="200" Height="20" IsEnabled="false" ></TextBox>
                           </Canvas>

                           <Canvas Top="70" Left="0" >
                              <Label>Confirm password:</Label>
                           </Canvas>
                           <Canvas Top="70" Left="130" >
                              <TextBox Name="tbPassword2" Width="200" Height="20" IsEnabled="false" ></TextBox>
                           </Canvas>
                        </Canvas>

                     </GroupBox>
                  </Canvas>
                  <!-- End DTC Logon Account -->

               </Canvas>
            </TabItem>
            <!-- End Security -->

         </TabControl>

      </Canvas>


      <!-- To Implement - ways to revert data or save to regkey to send to customer -->
      <Canvas Top="430" Left="310" >
         <!-- Button Name="bSave" Width="90" Height="25" IsEnabled="false" >Save To Regkey</Button -->
      </Canvas>

   </Canvas>

</Canvas>
"@
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_Title*",							$local:Title )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_TraceOutputOn*",					$local:DTCSettingsClass.TraceOutputOn )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_TraceTransactionsOn*",				$local:DTCSettingsClass.TraceTransactionsOn )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_TraceAllTransactionsOn*",			$local:DTCSettingsClass.TraceAllTransactionsOn )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_TraceAbortedTransactionsOn*",		$local:DTCSettingsClass.TraceAllAbortedTransactionsOn )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_TraceLongLivedTransactionsOn*",	$local:DTCSettingsClass.TraceLongLivedTransactionsOn )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_MaxBuffers*",						$local:DTCSettingsClass.MaxBuffers )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_LogPath*",							$local:DTCSettingsClass.LogPath )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_LogSize*",							$local:DTCSettingsClass.LogSize )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_NetworkDTCAccessOn*",				$local:DTCSettingsClass.NetworkDTCAccessOn )

	if( $local:DTCSettingsClass.NetworkDTCAccessOn )
	{	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_AllowRemoteClientsOn*",			$local:DTCSettingsClass.AllowRemoteClientsOn )
		$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_AllowRemoteAdministrationOn*",		$local:DTCSettingsClass.AllowRemoteAdministrationOn )
		$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_AllowInboundOn*",					$local:DTCSettingsClass.AllowInbound )
		$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_AllowOutboundOn*",					$local:DTCSettingsClass.AllowOutbound )
	} else
	{	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_AllowRemoteClientsOn*",			$false )
		$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_AllowRemoteAdministrationOn*",		$false )
		$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_AllowInboundOn*",					$false )
		$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_AllowOutboundOn*",					$false )
	}
	
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_MutualAuthRequired*",				$local:DTCSettingsClass.MutualAuthRequired )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_IncomingCallerAuthRequired*",		$local:DTCSettingsClass.IncomingCallerAuthRequired )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_NoAuthRequired*",					$local:DTCSettingsClass.NoAuthRequired )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_XATransactionsOn*",				$local:DTCSettingsClass.XATransactionsOn )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_LuTransactionsOn*",				$local:DTCSettingsClass.LuTransactionsOn )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTC_AccountName*",						$local:DTCSettingsClass.AccountName )
	return $local:XAML_DTC_Dialog
}
###########################################################
#
# Last Update: 10-7-2011
# Author: jlaborde
#
# Description:
#  set of functions to produce static XAML representing DTC settings on 2K3
#
###########################################################
function Get-2K3_DTCSettingsTracingAsXAML( [Object]$local:DTCSettingsClass, [string]$local:Title )
{
	#hardcode XAML doc:
	$local:XAML_DTC_Dialog = @"
<Canvas
   xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
   xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
   Width="333" Height="321"
   Background="#E0E0F0">

   <Canvas Top="5" Left="10"
      Width="323" Height="20"
      Background="#E0E0F0" >

      <TextBlock>Tracing Options (*gDTCTitle*)</TextBlock>

   </Canvas>

   <Canvas Top="25" Left="5" Width="313" Height="286" Background="#D0D0D0" >

      <Canvas Top="0" Left="10" Width="313" Height="286" Background="#D0D0D0" >

         <Canvas Top="6" Left="0">
            <GroupBox Width="306" Height="145" Header="Output Options" xml:space="preserve" FontSize="11" Visibility="Visible" >
               <Canvas>

                  <Canvas Top="3" Left="16">
                     <CheckBox Width="279" Height="15" IsChecked="*gDTCTraceOutput*" xml:space="preserve" FontSize="11" Visibility="Visible" >Trace Output</CheckBox>
                  </Canvas>

                  <Canvas Top="27" Left="31">
                     <CheckBox Width="266" Height="15" IsChecked="*gDTCTraceTransactions*" xml:space="preserve" FontSize="11" Visibility="Visible" >Trace Transactions</CheckBox>
                  </Canvas>

                  <Canvas Top="51" Left="46">
                     <CheckBox Width="251" Height="15" IsChecked="*gDTCTraceAllTransactions*" xml:space="preserve" FontSize="11" Visibility="Visible" >Trace All Transactions</CheckBox>
                  </Canvas>

                  <Canvas Top="76" Left="46">
                     <CheckBox Width="251" Height="15" IsChecked="*gDTCTraceAbortedTransactions*" xml:space="preserve" FontSize="11" Visibility="Visible" >Trace Aborted Transactions</CheckBox>
                  </Canvas>

                  <Canvas Top="100" Left="46">
                     <CheckBox Width="249" Height="15" IsChecked="*gDTCTraceLongLivedTransactions*" xml:space="preserve" FontSize="11" Visibility="Visible" >Trace Long-Lived Transactions</CheckBox>
                  </Canvas>


               </Canvas>
            </GroupBox>
         </Canvas>

         <Canvas Top="162" Left="0">
            <GroupBox Width="306" Height="89" Header="Logging Options" xml:space="preserve" FontSize="11" Visibility="Visible" >
               <Canvas>

                  <Canvas Top="7" Left="19">
                     <Button Width="84" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >New Session&#x0d;</Button>
                  </Canvas>

                  <Canvas Top="7" Left="111">
                     <Button Width="81" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >Stop Session&#x0d;</Button>
                  </Canvas>

                  <Canvas Top="7" Left="199">
                     <Button Width="84" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >Flush Data&#x0d;</Button>
                  </Canvas>

                  <Canvas Top="37" Left="19">
                     <TextBox Width="38" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >*gDTCBufferSize*&#x0d;</TextBox>
                  </Canvas>

                  <Canvas Top="37" Left="66">
                     <Label xml:space="preserve" FontSize="11" Visibility="Visible" >Max. Num. Of Memory Buffers (size PageSize)&#x0d;</Label>
                  </Canvas>


               </Canvas>
            </GroupBox>
         </Canvas>

         <Canvas Top="257" Left="129">
            <Button Width="75" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >OK&#x0d;</Button>
         </Canvas>

         <Canvas Top="257" Left="231">
            <Button Width="75" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >Cancel&#x0d;</Button>
         </Canvas>

      </Canvas>
   </Canvas>
</Canvas>
"@
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCTitle*",						$local:Title )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCTraceOutput*",					$local:DTCSettingsClass.TraceOutputOn )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCTraceTransactions*",			$local:DTCSettingsClass.TraceTransactionsOn )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCTraceAllTransactions*",			$local:DTCSettingsClass.TraceAllTransactionsOn )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCTraceAbortedTransactions*",		$local:DTCSettingsClass.TraceAllAbortedTransactionsOn )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCTraceLongLivedTransactions*",	$local:DTCSettingsClass.TraceLongLivedTransactionsOn )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCBufferSize*",					$local:DTCSettingsClass.MaxBuffers )
	return $local:XAML_DTC_Dialog
}
function Get-2K3_DTCSettingsSecurityAsXAML( [Object]$local:DTCSettingsClass, [string]$local:Title )
{
	#hardcode XAML doc:
	$local:XAML_DTC_Dialog = @"
<Canvas
   xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
   xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
   Width="432" Height="422"
   Background="#E0E0F0">

   <Canvas Top="5" Left="10"
      Width="422" Height="20"
      Background="#E0E0F0" >

      <TextBlock>Security Configuration (*gDTCTitle*)</TextBlock>

   </Canvas>

   <Canvas Top="25" Left="5" Width="412" Height="387" Background="#D0D0D0" >

      <Canvas Top="0" Left="10" Width="412" Height="387" Background="#D0D0D0" >

         <Canvas Top="3" Left="-2">
            <GroupBox Width="411" Height="229" Header="Security Settings" xml:space="preserve" FontSize="11" Visibility="Visible" >
               <Canvas>

                  <Canvas Top="3" Left="6">
                     <CheckBox Width="128" Height="16" IsChecked="*gDTCNetworkAccess*" xml:space="preserve" FontSize="11" Visibility="Visible" >Network DTC Access</CheckBox>
                  </Canvas>

                  <Canvas Top="20" Left="10">
                     <GroupBox Width="381" Height="37" Header="Client and Administration" xml:space="preserve" FontSize="11" Visibility="Visible" >
                        <Canvas>

                           <Canvas Top="3" Left="7">
                              <CheckBox Width="165" Height="16" IsChecked="*gDTCAllowRemoteClients*" xml:space="preserve" FontSize="11" Visibility="Visible" >Allow Remote Clients</CheckBox>
                           </Canvas>

                           <Canvas Top="3" Left="181">
                              <CheckBox Width="194" Height="16" IsChecked="*gDTCAllowRemoteAdministration*" xml:space="preserve" FontSize="11" Visibility="Visible" >Allow Remote Administration</CheckBox>
                           </Canvas>


                        </Canvas>
                     </GroupBox>
                  </Canvas>

                  <Canvas Top="63" Left="10">
                     <GroupBox Width="381" Height="127" Header="Transaction Manager Communication" xml:space="preserve" FontSize="11" Visibility="Visible" >
                        <Canvas>

                           <Canvas Top="3" Left="7">
                              <CheckBox Width="128" Height="16" IsChecked="*gDTCAllowInbound*" xml:space="preserve" FontSize="11" Visibility="Visible" >Allow Inbound</CheckBox>
                           </Canvas>

                           <Canvas Top="3" Left="181">
                              <CheckBox Width="128" Height="16" IsChecked="*gDTCAllowOutbound*" xml:space="preserve" FontSize="11" Visibility="Visible" >Allow Outbound</CheckBox>
                           </Canvas>

                           <Canvas Top="27" Left="24">
                              <RadioButton Width="173" Height="16" IsChecked="*gDTCMutualAuth*" xml:space="preserve" FontSize="11" Visibility="Visible" >Mutual Authentication Required</RadioButton>
                           </Canvas>

                           <Canvas Top="47" Left="24">
                              <RadioButton Width="210" Height="16" IsChecked="*gDTCIncomingCaller*" xml:space="preserve" FontSize="11" Visibility="Visible" >Incoming Caller Authentication Required</RadioButton>
                           </Canvas>

                           <Canvas Top="66" Left="24">
                              <RadioButton Width="150" Height="16" IsChecked="*gDTCNoAuth*" xml:space="preserve" FontSize="11" Visibility="Visible" >No Authentication Required</RadioButton>
                           </Canvas>

                           <Canvas Top="89" Left="6">
                              <CheckBox Width="366" Height="16" IsChecked="*gDTCTIPOn*" xml:space="preserve" FontSize="11" Visibility="Visible" >Enable Transaction Internet Protocol (TIP) Transactions</CheckBox>
                           </Canvas>


                        </Canvas>
                     </GroupBox>
                  </Canvas>

                  <Canvas Top="193" Left="5">
                     <CheckBox Width="183" Height="16" IsChecked="*gDTCXAOn*" xml:space="preserve" FontSize="11" Visibility="Visible" >Enable XA Transactions</CheckBox>
                  </Canvas>


               </Canvas>
            </GroupBox>
         </Canvas>

         <Canvas Top="236" Left="-2">
            <GroupBox Width="411" Height="114" Header="DTC Logon Account" xml:space="preserve" FontSize="11" Visibility="Visible" >
               <Canvas>

                  <Canvas Top="3" Left="102">
                     <TextBox Width="158" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >*gDTCAccount*&#x0d;</TextBox>
                  </Canvas>

                  <Canvas Top="3" Left="272">
                     <Button Width="75" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >Browse&#x0d;</Button>
                  </Canvas>

                  <Canvas Top="8" Left="6">
                     <Label xml:space="preserve" FontSize="11" Visibility="Visible" >Account:&#x0d;</Label>
                  </Canvas>

                  <Canvas Top="34" Left="102">
                     <TextBox Width="158" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" IsEnabled="false" ></TextBox>
                  </Canvas>

                  <Canvas Top="39" Left="6">
                     <Label xml:space="preserve" FontSize="11" Visibility="Visible" >Password:&#x0d;</Label>
                  </Canvas>

                  <Canvas Top="65" Left="102">
                     <TextBox Width="158" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" IsEnabled="false" ></TextBox>
                  </Canvas>

                  <Canvas Top="68" Left="6">
                     <Label xml:space="preserve" FontSize="11" Visibility="Visible" >Confirm password:&#x0d;</Label>
                  </Canvas>


               </Canvas>
            </GroupBox>
         </Canvas>

         <Canvas Top="361" Left="-3">
            <Button Width="75" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >OK&#x0d;</Button>
         </Canvas>

         <Canvas Top="361" Left="87">
            <Button Width="75" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >Cancel&#x0d;</Button>
         </Canvas>

      </Canvas>
   </Canvas>
</Canvas>
"@
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCTitle*",							$local:Title )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCNetworkAccess*",					$local:DTCSettingsClass.NetworkDTCAccessOn )

	if( $local:DTCSettingsClass.NetworkDTCAccessOn )
	{	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCAllowRemoteClients*",			$local:DTCSettingsClass.AllowRemoteClientsOn )
		$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCAllowRemoteAdministration*",	$local:DTCSettingsClass.AllowRemoteAdministrationOn )
		$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCAllowInbound*",					$local:DTCSettingsClass.AllowInbound )
		$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCAllowOutbound*",				$local:DTCSettingsClass.AllowOutbound )
	} else
	{	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCAllowRemoteClients*",			$false )
		$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCAllowRemoteAdministration*",	$false )
		$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCAllowInbound*",					$false )
		$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCAllowOutbound*",				$false )
	}
	
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCMutualAuth*",						$local:DTCSettingsClass.MutualAuthRequired )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCIncomingCaller*",					$local:DTCSettingsClass.IncomingCallerAuthRequired )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCNoAuth*",							$local:DTCSettingsClass.NoAuthRequired )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCXAOn*",								$local:DTCSettingsClass.XATransactionsOn )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCTIPOn*",							$local:DTCSettingsClass.NetworkDtcAccessTipOn )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCAccount*",							$local:DTCSettingsClass.AccountName )
	return $local:XAML_DTC_Dialog
}
function Get-2K3_DTCSettingsMainAsXAML( [Object]$local:DTCSettingsClass, [string]$local:Title, [string]$local:SecConfigFile, [string]$local:TraceConfigFile )
{
	#hardcode XAML doc:
	$local:XAML_DTC_Dialog = @"
<Canvas
   xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
   xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
   Width="404" Height="466"
   Background="#E0E0F0">

   <Canvas Top="5" Left="10"
      Width="394" Height="20"
      Background="#E0E0F0" >

      <TextBlock>DTC Properties (*gDTCTitle*)</TextBlock>

   </Canvas>

   <Canvas Top="25" Left="5" Width="384" Height="431" Background="#D0D0D0" >

      <Canvas Top="0" Left="10" Width="384" Height="431" Background="#D0D0D0" >

         <Canvas Top="2" Left="-5">
            <TabControl Width="386" Height="398" Visibility="Visible" >

               <TabItem Header="MSDTC" FontSize="11" Visibility="Visible" >
                  <Canvas>

                     <Canvas Top="5" Left="8">
                        <GroupBox Width="360" Height="67" Header="Default Coordinator" xml:space="preserve" FontSize="11" Visibility="Visible" >
                           <Canvas>

                              <Canvas Top="3" Left="15">
                                 <CheckBox Width="302" Height="16" IsChecked="*gDTCUseLocalCoordinator*" xml:space="preserve" FontSize="11" Visibility="Visible" >Use local coordinator</CheckBox>
                              </Canvas>

                              <Canvas Top="22" Left="13">
                                 <Label xml:space="preserve" FontSize="11" Visibility="Visible" >Remote Host:&#x0d;</Label>
                              </Canvas>

                              <Canvas Top="22" Left="88">
                                 <TextBox Width="173" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >*gDTCRemoteHost*</TextBox>
                              </Canvas>

                              <Canvas Top="22" Left="264">
                                 <Button Width="83" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >Select...&#x0d;</Button>
                              </Canvas>


                           </Canvas>
                        </GroupBox>
                     </Canvas>

                     <Canvas Top="75" Left="8">
                        <GroupBox Width="360" Height="75" Header="Log Information (Currently owned by JLAB2K3X86)" xml:space="preserve" FontSize="11" Visibility="Visible" >
                           <Canvas>

                              <Canvas Top="3" Left="13">
                                 <Label xml:space="preserve" FontSize="11" Visibility="Visible" >Location:&#x0d;</Label>
                              </Canvas>

                              <Canvas Top="3" Left="88">
                                 <TextBox Width="173" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >*gDTCLogLocation*&#x0d;</TextBox>
                              </Canvas>

                              <Canvas Top="3" Left="264">
                                 <Button Width="83" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >Browse...&#x0d;</Button>
                              </Canvas>

                              <Canvas Top="29" Left="13">
                                 <Label xml:space="preserve" FontSize="11" Visibility="Visible" >Capacity:&#x0d;</Label>
                              </Canvas>

                              <Canvas Top="29" Left="88">
                                 <TextBox Width="60" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >*gDTCLogSize*&#x0d;</TextBox>
                              </Canvas>

                              <Canvas Top="29" Left="264">
                                 <Button Width="83" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >Reset log&#x0d;</Button>
                              </Canvas>

                              <Canvas Top="32" Left="155">
                                 <Label xml:space="preserve" FontSize="11" Visibility="Visible" >MB&#x0d;</Label>
                              </Canvas>


                           </Canvas>
                        </GroupBox>
                     </Canvas>

                     <Canvas Top="154" Left="8">
                        <GroupBox Width="360" Height="47" Header="Client Network Protocol Configuration" xml:space="preserve" FontSize="11" Visibility="Visible" >
                           <Canvas>

                              <Canvas Top="3" Left="4">
                                 <ComboBox Width="344" Height="21" SelectedIndex="0" xml:space="preserve" FontSize="11" Visibility="Visible" IsEnabled="false" >
                                    <!-- <ComboBoxItem FontSize="11" >TCP/IP</ComboBoxItem> -->
                                    <!-- <ComboBoxItem FontSize="11" >SPX</ComboBoxItem> -->
                                 </ComboBox>
                              </Canvas>


                           </Canvas>
                        </GroupBox>
                     </Canvas>

                     <Canvas Top="205" Left="8">
                        <GroupBox Width="360" Height="72" Header="Service Control Status for MSDTC version *gDTCVersion*" xml:space="preserve" FontSize="11" Visibility="Hidden" >
                           <Canvas>

                              <Canvas Top="3" Left="7">
                                 <Label xml:space="preserve" FontSize="11" Visibility="Hidden" >Status: Started at *gDTCStartTime* - *gDTCStartDate*&#x0d;</Label>
                              </Canvas>

                              <Canvas Top="3" Left="240">
                                 <Label xml:space="preserve" FontSize="11" Visibility="Hidden" >*gDTCStartTime*&#x0d;</Label>
                              </Canvas>

                              <Canvas Top="3" Left="300">
                                 <Label xml:space="preserve" FontSize="11" Visibility="Hidden" >*gDTCStartDate*&#x0d;</Label>
                              </Canvas>

                              <Canvas Top="26" Left="7">
                                 <Button Width="77" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >Start&#x0d;</Button>
                              </Canvas>

                              <Canvas Top="26" Left="90">
                                 <Button Width="77" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >Stop&#x0d;</Button>
                              </Canvas>

                              <Canvas Top="26" Left="190">
                                 <Button Width="159" Height="23" xml:space="preserve" FontSize="11" Visibility="Hidden" >Take Ownership&#x0d;</Button>
                              </Canvas>


                           </Canvas>
                        </GroupBox>
                     </Canvas>

                     <Canvas Top="278" Left="8">
                        <GroupBox Width="177" Height="42" Header="Transaction Configuration" xml:space="preserve" FontSize="11" Visibility="Visible" >
                           <Canvas>

                              <Canvas Top="3" Left="4">
                                 <Button Width="159" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >
								    <Label Height="20" xml:space="preserve" FontSize="9" Visibility="Visible" ><Hyperlink NavigateUri="*gDTCThisSecurityConfig*" TargetName="properties" xml:space="preserve" FontSize="9" >Security Configuration...&#x0d;</Hyperlink></Label>
								 </Button>
                              </Canvas>


                           </Canvas>
                        </GroupBox>
                     </Canvas>

                     <Canvas Top="278" Left="191">
                        <GroupBox Width="177" Height="42" Header="Tracing Options" xml:space="preserve" FontSize="11" Visibility="Visible" >
                           <Canvas>

                              <Canvas Top="3" Left="4">
                                 <Button Width="159" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >
								    <Label Height="20" xml:space="preserve" FontSize="9" Visibility="Visible" ><Hyperlink NavigateUri="*gDTCThisTracingConfig*" TargetName="properties" xml:space="preserve" FontSize="9" >Tracing Options...&#x0d;</Hyperlink></Label>
								 </Button>
                              </Canvas>


                           </Canvas>
                        </GroupBox>
                     </Canvas>


                  </Canvas>
               </TabItem>

            </TabControl>
         </Canvas>

         <Canvas Top="406" Left="144">
            <Button Width="75" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >OK&#x0d;</Button>
         </Canvas>

         <Canvas Top="406" Left="225">
            <Button Width="75" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >Cancel&#x0d;</Button>
         </Canvas>

         <Canvas Top="406" Left="306">
            <Button Width="75" Height="23" xml:space="preserve" FontSize="11" Visibility="Visible" >Apply&#x0d;</Button>
         </Canvas>

      </Canvas>
   </Canvas>
</Canvas>
"@
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCTitle*",							$local:Title )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCUseLocalCoordinator*",				$local:DTCSettingsClass.UsingLocalDTCSettings )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCRemoteHost*",						$local:DTCSettingsClass.RemoteHostName )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCLogLocation*",						$local:DTCSettingsClass.LogPath )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCLogSize*",							$local:DTCSettingsClass.LogSize )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCThisSecurityConfig*",				$local:SecConfigFile )
	$local:XAML_DTC_Dialog	= $local:XAML_DTC_Dialog.Replace( "*gDTCThisTracingConfig*",				$local:TraceConfigFile )

	return $local:XAML_DTC_Dialog
}


###########################################################
#
# Last Update: 5-6-2011
# Author: jlaborde
#
# Description:
#  analyze XML representation of the DTC keys in XML format and report on the settings
#   focuses on a cluster instance of DTC
#
# Usage:
#  Analyze-ClusteredDTCRegistryKeysXML [System.Xml.XmlElement]$local:ResourceChildNode, [Object]$local:DTCSettingsClass, [object]$local:DTCLocalSettings
#
# Example:
#  Analyze-ClusteredDTCRegistryKeysXML DTC_Resource_Node $myDTCSettings, $DTCLocalSettings
#   where 
#    DTC_Resource_Node is a [System.Xml.XmlElement]$local:ResourceChildNode set to a known DTC cluster resource node
#     ex. HKEY_LOCAL_MACHINE\Cluster\Resources\00c27da4-0844-4d48-8a59-3d6512d6876f ( where Type field = "Distributed Transaction Coordinator" )
#    $myDTCSettings is an instance of Get-NewDTCSettingsClass
#    $local:DTCLocalSettings is the collection of local DTC settings
#
# UPDATE 3/31/2012
# code change - default values are used if keys are missing, NOT the local settings!!!
#
###########################################################

function Analyze-ClusteredDTCRegistryKeysXML( [System.Xml.XmlElement]$local:ResourceChildNode, [Object]$local:DTCSettingsClass, [object]$local:DTCLocalSettings )
{	# set that this is a cluster instance
	$local:DTCSettingsClass.IsClusterInstance	= $true
	$local:DTCSettingsClass.ClusterResourceName	= Get-XMLRegistryEntryValue $local:ResourceChildNode "Name"

	# look up log file info, as it should always be custom
	$local:kMSDTCPrivate		= Get-XMLRegistryKey $local:ResourceChildNode ($local:ResourceChildNode.Name + "\MSDTCPRIVATE")
		$local:kCID					= Get-XMLRegistryKey $local:kMSDTCPrivate ($local:ResourceChildNode.Name + "\MSDTCPRIVATE\CID")
		$local:clsidkey				= Get-XMLRegistryKeyBasedOnSubkey $local:kCID "Description" "MSDTC"

		if( $null -eq $local:clsidkey )
		{	$local:DTCSettingsClass.LogPath	= ""
			$local:DTCSettingsClass.LogSize	= 0
		} else
		{	$local:clsidkey2		= Get-XMLRegistryKey $local:clsidkey  ($local:clsidkey.Name + "\CustomProperties")
			$local:clsidkey2		= Get-XMLRegistryKey $local:clsidkey2 ($local:clsidkey.Name + "\CustomProperties\LOG")
			$local:clsidkey3		= Get-XMLRegistryKey $local:clsidkey2 ($local:clsidkey.Name + "\CustomProperties\LOG\Path")
			$local:DTCSettingsClass.LogPath	= $local:clsidkey3.Value

			$local:clsidkey3		= Get-XMLRegistryKey $local:clsidkey2 ($local:clsidkey.Name + "\CustomProperties\LOG\Size")
			$local:DTCSettingsClass.LogSize	= $local:clsidkey3.Value
		}

	# see if there are custom settings
	# caller should enum resources for DTC instances and call this function x number of times
	
	$local:dtckey			= Get-XMLRegistryKey $local:kMSDTCPrivate	($local:kMSDTCPrivate.Name + "\MSDTC")
	$local:security			= Get-XMLRegistryKey $local:dtckey			($local:kMSDTCPrivate.Name + "\MSDTC\Security")

	# dtc key
		# Authentication
		if( ( Get-XMLRegistryEntryExists $local:dtckey "AllowOnlySecureRpcCalls" ) )
		{	$local:DTCSettingsClass.AllowOnlySecureRpcCallsOn = Get-XMLRegistryEntryOnOrOff $local:dtckey "AllowOnlySecureRpcCalls"
		}
		if( ( Get-XMLRegistryEntryExists $local:dtckey "FallbackToUnsecureRPCIfNecessary" ) )
		{	$local:DTCSettingsClass.FallbackToUnsecureRPCIfNecessaryOn	= Get-XMLRegistryEntryOnOrOff $local:dtckey "FallbackToUnsecureRPCIfNecessary"
		}
		if( ( Get-XMLRegistryEntryExists $local:dtckey "TurnOffRpcSecurity" ) )
		{	$local:DTCSettingsClass.TurnOffRpcSecurityOn				= Get-XMLRegistryEntryOnOrOff $local:dtckey "TurnOffRpcSecurity"
		}
		# CM tracing
		if( ( Get-XMLRegistryEntryExists $local:dtckey "TraceCMErr" ) )
		{	$local:DTCSettingsClass.TraceCMErrOn						= Get-XMLRegistryEntryOnOrOff $local:dtckey "TraceCMErr"
		}
		if( ( Get-XMLRegistryEntryExists $local:dtckey "TraceCMErrLogName" ) )
		{	$local:DTCSettingsClass.TraceCMErrLogName					= Get-XMLRegistryEntryValue   $local:dtckey "TraceCMErrLogName"
		}
		# TIP
		if( ( Get-XMLRegistryEntryExists $local:dtckey "DisableTipTmIdVerification" ) )
		{	$local:DTCSettingsClass.DisableTipTmIdVerificationOn		= Get-XMLRegistryEntryOnOrOff $local:dtckey "DisableTipTmIdVerification"
		}
		if( ( Get-XMLRegistryEntryExists $local:dtckey "DisableTipTmIdPortVerification" ) )
		{	$local:DTCSettingsClass.DisableTipTmIdPortVerificationOn	= Get-XMLRegistryEntryOnOrOff $local:dtckey "DisableTipTmIdPortVerification"
		}
		if( ( Get-XMLRegistryEntryExists $local:dtckey "DisableTipBeginCheck" ) )
		{	$local:DTCSettingsClass.DisableTipBeginCheckOn				= Get-XMLRegistryEntryOnOrOff $local:dtckey "DisableTipBeginCheck"
		}
		if( ( Get-XMLRegistryEntryExists $local:dtckey "DisableTipPassThruCheck" ) )
		{	$local:DTCSettingsClass.DisableTipPassThruCheckOn			= Get-XMLRegistryEntryOnOrOff $local:dtckey "DisableTipPassThruCheck"
		}

	# security
		# network access controls
		if( ( Get-XMLRegistryEntryExists $local:security "NetworkDtcAccess" ) )
		{	$local:DTCSettingsClass.NetworkDTCAccessOn					= Get-XMLRegistryEntryOnOrOff $local:security "NetworkDtcAccess"
		}
		if( ( Get-XMLRegistryEntryExists $local:security "NetworkDtcAccessTransactions" ) )
		{	$local:DTCSettingsClass.NetworkDTCAccessTransactionsOn		= Get-XMLRegistryEntryOnOrOff $local:security "NetworkDtcAccessTransactions"
		}
		if( ( Get-XMLRegistryEntryExists $local:security "NetworkDTCAccessInbound" ) )
		{	$local:DTCSettingsClass.NetworkDTCAccessInboundOn			= Get-XMLRegistryEntryOnOrOff $local:security "NetworkDTCAccessInbound"
		}
		if( ( Get-XMLRegistryEntryExists $local:security "NetworkDTCAccessOutbound" ) )
		{	$local:DTCSettingsClass.NetworkDTCAccessOutboundOn			= Get-XMLRegistryEntryOnOrOff $local:security "NetworkDTCAccessOutbound"
		}
		if( ( Get-XMLRegistryEntryExists $local:security "NetworkDtcAccessClients" ) )
		{	$local:DTCSettingsClass.AllowRemoteClientsOn				= Get-XMLRegistryEntryOnOrOff $local:security "NetworkDtcAccessClients"
		}
		if( ( Get-XMLRegistryEntryExists $local:security "NetworkDtcAccessAdmin" ) )
		{	$local:DTCSettingsClass.AllowRemoteAdministrationOn			= Get-XMLRegistryEntryOnOrOff $local:security "NetworkDtcAccessAdmin"
		}
		# XA / LU transactions
		if( ( Get-XMLRegistryEntryExists $local:security "XaTransactions" ) )
		{	$local:DTCSettingsClass.XATransactionsOn					= Get-XMLRegistryEntryOnOrOff $local:security "XaTransactions"
		}
		if( ( Get-XMLRegistryEntryExists $local:security "LuTransactions" ) )
		{	$local:DTCSettingsClass.LuTransactionsOn					= Get-XMLRegistryEntryOnOrOff $local:security "LuTransactions"
		}
		# TIP
		if( ( Get-XMLRegistryEntryExists $local:security "NetworkDtcAccessTip" ) )
		{	$local:DTCSettingsClass.NetworkDtcAccessTipOn				= Get-XMLRegistryEntryOnOrOff $local:security "NetworkDtcAccessTip"
		}

	
	# tracing appears to be universal betweeb a node and its local dtc; copying the transaction tracing bits here
	$local:DTCSettingsClass.ControlFlags					= $local:DTCLocalSettings.ControlFlags
	$local:DTCSettingsClass.TraceOutputOn					= $local:DTCLocalSettings.TraceOutputOn
	$local:DTCSettingsClass.TraceTransactionsOn				= $local:DTCLocalSettings.TraceTransactionsOn
	$local:DTCSettingsClass.MaxBuffers						= $local:DTCLocalSettings.MaxBuffers
	$local:DTCSettingsClass.TraceAllTransActionsOn			= $local:DTCLocalSettings.TraceAllTransActionsOn
	$local:DTCSettingsClass.TraceAllAbortedTransactionsOn	= $local:DTCLocalSettings.TraceAllAbortedTransactionsOn
	$local:DTCSettingsClass.TraceLongLivedTransactionsOn	= $local:DTCLocalSettings.TraceLongLivedTransactionsOn


	#checks for allow inbound
	if( $local:DTCSettingsClass.NetworkDtcAccessOn -and $local:DTCSettingsClass.NetworkDtcAccessTransactionsOn -and $local:DTCSettingsClass.NetworkDtcAccessInboundOn )
	{	$local:DTCSettingsClass.AllowInbound	= $true		} else
	{	$local:DTCSettingsClass.AllowInbound	= $false	}
	#checks for allow outbound
	if( $local:DTCSettingsClass.NetworkDtcAccessOn -and $local:DTCSettingsClass.NetworkDtcAccessTransactionsOn -and $local:DTCSettingsClass.NetworkDtcAccessOutboundOn )
	{	$local:DTCSettingsClass.AllowOutbound	= $true		} else
	{	$local:DTCSettingsClass.AllowOutbound	= $false	}


	#get authentication method
	$local:DTCSettingsClass.MutualAuthRequired				= $false
	$local:DTCSettingsClass.IncomingCallerAuthRequired		= $false
	$local:DTCSettingsClass.NoAuthRequired					= $false

	if( $local:DTCSettingsClass.AllowOnlySecureRpcCallsOn -and !$local:DTCSettingsClass.FallbackToUnsecureRPCIfNecessaryOn -and !$local:DTCSettingsClass.TurnOffRpcSecurityOn )
	{	$local:DTCSettingsClass.MutualAuthRequired			= $true
	}
	if( !$local:DTCSettingsClass.AllowOnlySecureRpcCallsOn -and $local:DTCSettingsClass.FallbackToUnsecureRPCIfNecessaryOn -and !$local:DTCSettingsClass.TurnOffRpcSecurityOn )
	{	$local:DTCSettingsClass.IcnomingCallerAuthRequired	= $true
	}
	if( !$local:DTCSettingsClass.AllowOnlySecureRpcCallsOn -and !$local:DTCSettingsClass.FallbackToUnsecureRPCIfNecessaryOn -and $local:DTCSettingsClass.TurnOffRpcSecurityOn )
	{	$local:DTCSettingsClass.NoAuthRequired				= $true
	}
}
function Analyze-2K3_ClusteredDTCRegistryKeysXML( [string]$local:ResourceChildNode, [Object]$local:DTCSettingsClass, [object]$local:DTCLocalSettings )
{	# set that this is a cluster instance
	$local:DTCSettingsClass.IsClusterInstance	= $true
	$local:DTCSettingsClass.ClusterResourceName	= Get-RegKeyValue $local:ResourceChildNode "Name"

	# have to find the subkey that has a REG_SZ named MSDTC
	$local:clusternode	= Get-RegistrySubKeyBasedOnEntry $local:ResourceChildNode "MSDTC" ""
	if( $null -eq $local:clusternode )
	{	return $null
	}

	$local:dtckey	= $local:clusternode.Name
	$local:security	= ($local:dtckey + "\Security")

	$local:DTCSettingsClass.LogPath	= Get-RegKeyValue $local:dtckey "DtcLogPath"
	$local:DTCSettingsClass.LogSize	= Get-RegKeyValue $local:dtckey "DtcLogSize"


	$local:DTCSettingsClass.AccountName							= Get-RegKeyValue $local:security				"AccountName"
	# Authentication
	$local:DTCSettingsClass.AllowOnlySecureRpcCallsOn			= Get-RegKeyBool $local:security				"AllowOnlySecureRpcCalls"
	$local:DTCSettingsClass.FallbackToUnsecureRPCIfNecessaryOn	= Get-RegKeyBool $local:security				"FallbackToUnsecureRPCIfNecessary"
	$local:DTCSettingsClass.TurnOffRpcSecurityOn				= Get-RegKeyBool $local:security				"TurnOffRpcSecurity"
	# CM tracing
	$local:DTCSettingsClass.TraceCMErrOn						= Get-RegKeyBool 	"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC"	"TraceCMErr"
	$local:DTCSettingsClass.TraceCMErrLogName					= Get-RegKeyValue   "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSDTC"	"TraceCMErrLogName"
	# network access controls
	$local:DTCSettingsClass.NetworkDTCAccessOn					= Get-RegKeyBool $local:security			"NetworkDtcAccess"
	$local:DTCSettingsClass.NetworkDTCAccessTransactionsOn		= Get-RegKeyBool $local:security			"NetworkDtcAccessTransactions"
	$local:DTCSettingsClass.NetworkDTCAccessInboundOn			= Get-RegKeyBool $local:security			"NetworkDTCAccessInbound"
	$local:DTCSettingsClass.NetworkDTCAccessOutboundOn			= Get-RegKeyBool $local:security			"NetworkDTCAccessOutbound"
	$local:DTCSettingsClass.AllowRemoteClientsOn				= Get-RegKeyBool $local:security			"NetworkDtcAccessClients"
	$local:DTCSettingsClass.AllowRemoteAdministrationOn			= Get-RegKeyBool $local:security			"NetworkDtcAccessAdmin"
	# XA transactions
	$local:DTCSettingsClass.XATransactionsOn					= Get-RegKeyBool $local:security			"XaTransactions"
	# TIP
	$local:DTCSettingsClass.NetworkDtcAccessTipOn				= Get-RegKeyBool $local:security			"NetworkDtcAccessTip"

	
	# tracing appears to be universal betweeb a node and its local dtc; copying the transaction tracing bits here
	$local:DTCSettingsClass.ControlFlags					= $local:DTCLocalSettings.ControlFlags
	$local:DTCSettingsClass.TraceOutputOn					= $local:DTCLocalSettings.TraceOutputOn
	$local:DTCSettingsClass.TraceTransactionsOn				= $local:DTCLocalSettings.TraceTransactionsOn
	$local:DTCSettingsClass.MaxBuffers						= $local:DTCLocalSettings.MaxBuffers
	$local:DTCSettingsClass.TraceAllTransActionsOn			= $local:DTCLocalSettings.TraceAllTransActionsOn
	$local:DTCSettingsClass.TraceAllAbortedTransactionsOn	= $local:DTCLocalSettings.TraceAllAbortedTransactionsOn
	$local:DTCSettingsClass.TraceLongLivedTransactionsOn	= $local:DTCLocalSettings.TraceLongLivedTransactionsOn


	#checks for allow inbound
	if( $local:DTCSettingsClass.NetworkDtcAccessOn -and $local:DTCSettingsClass.NetworkDtcAccessTransactionsOn -and $local:DTCSettingsClass.NetworkDtcAccessInboundOn )
	{	$local:DTCSettingsClass.AllowInbound	= $true		} else
	{	$local:DTCSettingsClass.AllowInbound	= $false	}
	#checks for allow outbound
	if( $local:DTCSettingsClass.NetworkDtcAccessOn -and $local:DTCSettingsClass.NetworkDtcAccessTransactionsOn -and $local:DTCSettingsClass.NetworkDtcAccessOutboundOn )
	{	$local:DTCSettingsClass.AllowOutbound	= $true		} else
	{	$local:DTCSettingsClass.AllowOutbound	= $false	}


	#get authentication method
	$local:DTCSettingsClass.MutualAuthRequired				= $false
	$local:DTCSettingsClass.IncomingCallerAuthRequired		= $false
	$local:DTCSettingsClass.NoAuthRequired					= $false

	if( $local:DTCSettingsClass.AllowOnlySecureRpcCallsOn -and !$local:DTCSettingsClass.FallbackToUnsecureRPCIfNecessaryOn -and !$local:DTCSettingsClass.TurnOffRpcSecurityOn )
	{	$local:DTCSettingsClass.MutualAuthRequired			= $true
	}
	if( !$local:DTCSettingsClass.AllowOnlySecureRpcCallsOn -and $local:DTCSettingsClass.FallbackToUnsecureRPCIfNecessaryOn -and !$local:DTCSettingsClass.TurnOffRpcSecurityOn )
	{	$local:DTCSettingsClass.IcnomingCallerAuthRequired	= $true
	}
	if( !$local:DTCSettingsClass.AllowOnlySecureRpcCallsOn -and !$local:DTCSettingsClass.FallbackToUnsecureRPCIfNecessaryOn -and $local:DTCSettingsClass.TurnOffRpcSecurityOn )
	{	$local:DTCSettingsClass.NoAuthRequired				= $true
	}
}


###########################################################
#
# Last Update: 5-9-2011
# Author: jlaborde
#
# Description:
#  loop through the cluster resources keys in XML registry and analyze settings
#
# Usage:
#  Get-ClusteredDTCInstancesData [string]$local:file [string]$local:outputpath [object]$local:DTCLocalSettings
#
# Example:
#  Get-ClusteredDTCInstancesData "C:\\msdtc.xml" "C:\\outputfolder" $local:DTCLocalSettings
#   where 
#    "C:\\msdtc.xml" is the XML registry exports file
#    "C:\\outputfolder" is a folder to write the data out to
#    $local:DTCLocalSettings is a DTC settings object for the local DTC
#
###########################################################

function Get-ClusteredDTCInstancesData( [string]$local:file, [string]$local:outputfolder, [object]$local:DTCLocalSettings )
{	$local:xmldata			= [xml](Get-Content $local:file)
	$local:clusterkey		= Get-XMLRegistryKey $local:xmldata.SDP_MSDTC_Registry_Data "HKEY_LOCAL_MACHINE\Cluster\Resources"
	# 8-22-2011, jlaborde
	# add in counter to distinguish data sets
	# add in zip of cluster log folder
	$local:counter			= 1

	# loop through each resource, looking for DTC ones
	foreach( $local:subkey in $local:clusterkey.RegistryKey )
	{	$local:type	= Get-XMLRegistryEntryValue $local:subkey "Type"
		$local:name	= Get-XMLRegistryEntryValue $local:subkey "Name"

		if( $null -ne $local:type -and $local:type -eq "Distributed Transaction Coordinator" )
		{
			$local:DTCSettingsClass1	= (Get-NewDTCSettingsClass)
			(Analyze-ClusteredDTCRegistryKeysXML $local:subkey $local:DTCSettingsClass1 $local:DTCLocalSettings)
			(Get-MSDTCSummaryInfo $local:DTCSettingsClass1) | Out-File ($local:outputfolder + "\(Cluster_Resource_" + $local:name + "_" + $local:counter.ToString( ) + ")_" + $DTCSummaryFile)
			(Get-DTCSettingsAsXAML $local:DTCSettingsClass1 $local:name) | Out-File ($local:outputfolder + "\(Cluster_Resource_" + $local:name + "_" + $local:counter.ToString( ) + ")_" + $DTCXAMLFile)

			# add to global array
			$global:DTCSettingsArray	= $global:DTCSettingsArray + $local:DTCSettingsClass1

			# zip up the trace folder
			$local:FolderToZip			= get-item $local:DTCSettingsClass1.LogPath
			$local:dtczipfile			= out-zip -FilePath $local:FolderToZip -zipFileName ("(Cluster_Traces_" + $local:name + "_" + $local:counter.ToString( ) + ")") -activity $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Activity -status $MSDTCDataStrings.ID_DSI_DistSvcs_CompressData

			if( $global:gDebugSDPOn -eq $true )
			{	$local:SectionDescription	= $MSDTCDataStrings.ID_DSI_DistSvcs_Analysis
				$local:filesDescription		= $MSDTCDataStrings.ID_DSI_DistSvcs_Analysis
				CollectFiles -filesToCollect ($local:outputfolder + "\(Cluster_Resource_" + $local:name + ")_" + $DTCSummaryFile) -fileDescription $local:filesDescription -sectionDescription $local:SectionDescription -renameOutput $true -noFileExtensionsOnDescription
				$local:SectionDescription	= $MSDTCDataStrings.ID_DSI_DistSvcs_Settings
				$local:filesDescription		= $MSDTCDataStrings.ID_DSI_DistSvcs_Settings
				CollectFiles -filesToCollect ($local:outputfolder + "\(Cluster_Resource_" + $local:name + ")_" + $DTCXAMLFile) -fileDescription $local:filesDescription -sectionDescription $local:SectionDescription -renameOutput $true -noFileExtensionsOnDescription

				CollectFiles -filesToCollect $local:dtczipfile -fileDescription $MSDTCDataStrings.ID_DSI_DistSvcs_Desc_Trace -sectionDescription $MSDTCDataStrings.ID_DSI_DistSvcs_Sect_Trace -renameOutput $true -noFileExtensionsOnDescription
			}
			$local:counter++
		}
	}

}
function Get-2K3_ClusteredDTCInstancesData( [string]$local:file, [string]$local:outputfolder, [object]$local:DTCLocalSettings )
{	#$local:xmldata			= [xml](Get-Content $local:file)
	$local:clusterkeys		= Get-Item "registry::HKEY_LOCAL_MACHINE\Cluster\Resources\*" -ErrorAction SilentlyContinue
	# 8-22-2011, jlaborde
	# add in counter to distinguish data sets
	# add in zip of cluster log folder
	$local:counter			= 1

	# loop through each resource, looking for DTC ones
	foreach( $local:subkey in $local:clusterkeys )
	{	$local:type	= Get-RegKeyValue $local:subkey.Name "Type"
		$local:name	= Get-RegKeyValue $local:subkey.Name "Name"

		if( $null -ne $local:type -and $local:type -eq "Distributed Transaction Coordinator" )
		{
			$local:DTCSettingsClass1	= (Get-NewDTCSettingsClass)
			(Analyze-2K3_ClusteredDTCRegistryKeysXML $local:subkey.Name $local:DTCSettingsClass1 $local:DTCLocalSettings)
			(Get-MSDTCSummaryInfo $local:DTCSettingsClass1) | Out-File ($local:outputfolder + "\(Cluster_Resource_" + $local:name + "_" + $local:counter.ToString( ) + ")_" + $DTCSummaryFile)
			(Get-2K3_DTCSettingsTracingAsXAML $local:DTCSettingsClass1 $local:name) | Out-File ($local:outputfolder + "\(Cluster_Resource_" + $local:name + "_" + $local:counter.ToString( ) + ")_Tracing_" + $DTCXAMLFile)
			(Get-2K3_DTCSettingsSecurityAsXAML $local:DTCSettingsClass1 $local:name) | Out-File ($local:outputfolder + "\(Cluster_Resource_" + $local:name + "_" + $local:counter.ToString( ) + ")_Security_" + $DTCXAMLFile)
			(Get-2K3_DTCSettingsMainAsXAML $local:DTCSettingsClass1 $local:name ("(Cluster_Resource_" + $local:name + "_" + $local:counter.ToString( ) + ")_Security_" + $DTCXAMLFile) ("(Cluster_Resource_" + $local:name + "_" + $local:counter.ToString( ) + ")_Tracing_" + $DTCXAMLFile)) | Out-File ($local:outputfolder + "\(Cluster_Resource_" + $local:name + "_" + $local:counter.ToString( ) + ")_" + $DTCXAMLFile)

			# add to global array
			$global:DTCSettingsArray	= $global:DTCSettingsArray + $local:DTCSettingsClass1

			# zip up the trace folder
			$local:FolderToZip			= get-item $local:DTCSettingsClass1.LogPath
			$local:dtczipfile			= out-zip -FilePath $local:FolderToZip -zipFileName ("(Cluster_Traces_" + $local:name + "_" + $local:counter.ToString( ) + ")") -activity $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Activity -status $MSDTCDataStrings.ID_DSI_DistSvcs_CompressData

			if( $global:gDebugSDPOn -eq $true )
			{	$local:SectionDescription	= $MSDTCDataStrings.ID_DSI_DistSvcs_Analysis
				$local:filesDescription		= $MSDTCDataStrings.ID_DSI_DistSvcs_Analysis
				CollectFiles -filesToCollect ($local:outputfolder + "\(Cluster_Resource_" + $local:name + ")_" + $DTCSummaryFile) -fileDescription $local:filesDescription -sectionDescription $local:SectionDescription -renameOutput $true -noFileExtensionsOnDescription
				$local:SectionDescription	= $MSDTCDataStrings.ID_DSI_DistSvcs_Settings
				$local:filesDescription		= $MSDTCDataStrings.ID_DSI_DistSvcs_Settings
				CollectFiles -filesToCollect ($local:outputfolder + "\(Cluster_Resource_" + $local:name + ")_" + $DTCXAMLFile) -fileDescription $local:filesDescription -sectionDescription $local:SectionDescription -renameOutput $true -noFileExtensionsOnDescription

				CollectFiles -filesToCollect $local:dtczipfile -fileDescription $MSDTCDataStrings.ID_DSI_DistSvcs_Desc_Trace -sectionDescription $MSDTCDataStrings.ID_DSI_DistSvcs_Sect_Trace -renameOutput $true -noFileExtensionsOnDescription
			}
			$local:counter++
		}
	}

}


# General data collection functions ( ie. run command output )
	function Get-DTC_IPConfigData( )
	{	$local:path		= $global:DTCOutputPath + "\" + $global:DTCGeneralOutput + "IPConfig.txt"
		$Null	= (RunCMD -commandToRun  ("cmd.exe /c ipconfig.exe >> " + $local:path) -filesToCollect $local:path -fileDescription $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_IPConfig -sectionDescription $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_IPConfig)
	}
	function Get-DTC_ServicePermissions( )
	{	$local:path		= $global:DTCOutputPath + "\" + $global:DTCGeneralOutput + "SCManagerServicePerms.txt"
		$Null	= (RunCMD -commandToRun  ("cmd.exe /c sc sdshow scmanager >> " + $local:path) -filesToCollect $local:path -fileDescription $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_SC -sectionDescription $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_SC)
		$local:path		= $global:DTCOutputPath + "\" + $global:DTCGeneralOutput + "MSDTCServicePerms.txt"
		$Null	= (RunCMD -commandToRun  ("cmd.exe /c sc sdshow msdtc >> " + $local:path) -filesToCollect $local:path -fileDescription $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_SC -sectionDescription $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_SC)
	}
	function Get-DTC_RunningProcesses( )
	{	$local:path		= $global:DTCOutputPath + "\" + $global:DTCGeneralOutput + "RunningProcesses.txt"
		$Null	= (RunCMD -commandToRun  ("cmd.exe /c tasklist.exe /V >> " + $local:path) -filesToCollect $local:path -fileDescription $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_TaskList -sectionDescription $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_TaskList)
		$local:path		= $global:DTCOutputPath + "\" + $global:DTCGeneralOutput + "MSDTCProxyProcesses.txt"
		$Null	= (RunCMD -commandToRun  ("cmd.exe /c tasklist.exe /M msdtcprx.dll >> " + $local:path) -filesToCollect $local:path -fileDescription $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_TaskList -sectionDescription $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_TaskList)
	}
# end general data collection functions

###########################################################
#
# Deprecated!
#  see DistSvcs_Utils for implementation
#
# Last Update: 5-10-2011
# Author: jlaborde
#
# Description:
#  retrieve EnableDOCM key
#
# Usage:
#  Get-EnableDCOM "file.xml"
#
# Example:
#  Get-EnableDCOM "C:\\msdtc.xml"
#   returns the string value
#
###########################################################

#function Get-EnableDCOM( [string]$local:file )
#{	$local:xmldata			= [xml](Get-Content $local:file)
#	$local:olekey			= Get-XMLRegistryKey $local:xmldata.SDP_MSDTC_Registry_Data "HKEY_LOCAL_MACHINE\Software\Microsoft\OLE"
#	return (Get-XMLRegistryEntryValue $local:olekey "EnableDCOM")
#}

###########################################################
#
# Last Update: 4-28-2011
# Author: jlaborde
#
# Description:
#  produce DTC troubleshooting files ( XML registry keys, Summary note, XAML representation )
#
# Usage:
#  Get-MSDTC_SDP_Data
#
# Notes:
#  this calls all other DTC related collection functions and produces the appropriate fiels
#
# Example:
#  Get-MSDTC_SDP_Data
#
###########################################################

function Get-MSDTC_SDP_Data( )
{
	# create MSDTC output folder to put stuff in
	if( (Test-Path $global:DTCOutputPath) -eq $false ){
		$Null = New-Item $global:DTCOutputPath -type directory | Out-Null #_#
	}
	if( (Test-Path $global:DTCOutputPath) -eq $false )
	{	if( $global:gDebugSDPOn -eq $true )
		{	WriteTo-StdOut ("Failed to create directory " + $global:DTCOutputPath + "`r`n")
		}
	}

	# collect registry keys as XML
	if( $global:gDebugSDPOn -eq $true )
	{	Write-DiagProgress -Activity $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Activity -Status $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Registry
	}
	(Get-MSDTCRegistryKeysAsXML) | Out-File ($global:DTCOutputPath + "\" + $DTCXMLRegFile)
	if( $global:gDebugSDPOn -eq $true )
	{	$local:SectionDescription	= $MSDTCDataStrings.ID_DSI_DistSvcs_RegKeys
		$local:filesDescription		= $MSDTCDataStrings.ID_DSI_DistSvcs_RegKeys
		CollectFiles -filesToCollect ($global:DTCOutputPath + "\" + $DTCXMLRegFile) -fileDescription $local:filesDescription -sectionDescription $local:SectionDescription -renameOutput $true -noFileExtensionsOnDescription
	}

	# analyze the local MSDTC settings and set the member flags
	if( $global:gDebugDTC_DoAnalyzeLocal )
	{	if( $global:gDebugSDPOn -eq $true )
		{	Write-DiagProgress -Activity $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Activity -Status $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Analyze
		}
		$global:LocalDTCSettingsClass	= (Get-NewDTCSettingsClass)
		
		# add to global array
		$global:DTCSettingsArray	= $global:DTCSettingsArray + $local:DTCSettingsClass1

		if( (Get-OSVersionString) -eq "Windows 7 / 2008 R2" -or (Get-OSVersionString) -eq "Windows 8 / 2012" )
		{	(Analyze-LocalDTCRegistryKeysXML ($global:DTCOutputPath + "\" + $DTCXMLRegFile) $global:LocalDTCSettingsClass)
		}
		if( (Get-OSVersionString) -eq "Windows XP 64 / 2003" )
		{	(Analyze-2K3_LocalDTCRegistryKeysXML ($global:DTCOutputPath + "\" + $DTCXMLRegFile) $global:LocalDTCSettingsClass)
		}
		
		(Get-MSDTCSummaryInfo $global:LocalDTCSettingsClass) | Out-File ($global:DTCOutputPath + "\" + $DTCSummaryFile)
		if( $global:gDebugSDPOn -eq $true )
		{	$local:SectionDescription	= $MSDTCDataStrings.ID_DSI_DistSvcs_Analysis
			$local:filesDescription		= $MSDTCDataStrings.ID_DSI_DistSvcs_Analysis
			CollectFiles -filesToCollect ($global:DTCOutputPath + "\" + $DTCSummaryFile) -fileDescription $local:filesDescription -sectionDescription $local:SectionDescription -renameOutput $true -noFileExtensionsOnDescription
		}
	}

	# create XAML representation of local DTC settings
	if( $global:gDebugDTC_DoXAMLLocal )
	{	if( $global:gDebugSDPOn -eq $true )
		{	Write-DiagProgress -Activity $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Activity -Status $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_XAML
		}

		if( (Get-OSVersionString) -eq "Windows 7 / 2008 R2" -or (Get-OSVersionString) -eq "Windows 8 / 2012" )
		{	(Get-DTCSettingsAsXAML $global:LocalDTCSettingsClass "Local") | Out-File ($global:DTCOutputPath + "\(Local)_" + $DTCXAMLFile)
		}
		if( (Get-OSVersionString) -eq "Windows XP 64 / 2003" )
		{	(Get-2K3_DTCSettingsTracingAsXAML $local:DTCSettingsClass1 "Local") | Out-File ($global:DTCOutputPath + "\(Local)_Tracing_" + $DTCXAMLFile)
			(Get-2K3_DTCSettingsSecurityAsXAML $local:DTCSettingsClass1 "Local") | Out-File ($global:DTCOutputPath + "\(Local)_Security_" + $DTCXAMLFile)
			(Get-2K3_DTCSettingsMainAsXAML $local:DTCSettingsClass1 "Local" ("(Local)_Security_" + $DTCXAMLFile) ("(Local)_Tracing_" + $DTCXAMLFile)) | Out-File ($global:DTCOutputPath + "\(Local)_" + $DTCXAMLFile)
		}
		if( $global:gDebugSDPOn -eq $true )
		{	$local:SectionDescription	= $MSDTCDataStrings.ID_DSI_DistSvcs_Settings
			$local:filesDescription		= $MSDTCDataStrings.ID_DSI_DistSvcs_Settings
			CollectFiles -filesToCollect ($global:DTCOutputPath + "\(Local)_" + $DTCXAMLFile) -fileDescription $local:filesDescription -sectionDescription $local:SectionDescription -renameOutput $true -noFileExtensionsOnDescription
		}
	}

	# update 5-9-2011 jlaborde
	# get 2K8 R2 cluster data
	if( $global:gDebugDTC_DoAnalyzeCluster )
	{	if( $global:gDebugSDPOn -eq $true )
		{	Write-DiagProgress -Activity $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Activity -Status $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Analyze_Cluster
		}
		if( (Get-OSVersionString) -eq "Windows 7 / 2008 R2" -or (Get-OSVersionString) -eq "Windows 8 / 2012" )
		{	(Get-ClusteredDTCInstancesData ($global:DTCOutputPath + "\" + $DTCXMLRegFile) $global:DTCOutputPath $global:LocalDTCSettingsClass)
		}
		if( (Get-OSVersionString) -eq "Windows XP 64 / 2003" )
		{	(Get-2K3_ClusteredDTCInstancesData ($global:DTCOutputPath + "\" + $DTCXMLRegFile) $global:DTCOutputPath $global:LocalDTCSettingsClass)
		}
	}

	# update 5-9-2011 jlaborde
	# get event log data
	if( $global:gDebugDTC_DoEventLogs )
	{	if( $global:gDebugSDPOn -eq $true )
		{	Write-DiagProgress -Activity $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Activity -Status $MSDTCDataStrings.ID_DSI_DistSvcs_GetAppLogs
		}
		$Null	= (Get-DistSvcsAppLogsAsCSV ($global:DTCOutputPath + "\" + $global:DTCGeneralOutput + "ApplicationLog.csv"))
		if( $global:gDebugSDPOn -eq $true )
		{	Write-DiagProgress -Activity $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Activity -Status $MSDTCDataStrings.ID_DSI_DistSvcs_GetSysLogs
		}
		$Null	= (Get-DistSvcsSysLogsAsCSV ($global:DTCOutputPath + "\" + $global:DTCGeneralOutput + "SystemLog.csv"))
		if( $global:gDebugSDPOn -eq $true )
		{	$local:SectionDescription	= $MSDTCDataStrings.ID_DSI_DistSvcs_EventLogs
			$local:filesDescription		= $MSDTCDataStrings.ID_DSI_DistSvcs_EventLogs
			CollectFiles -filesToCollect ($global:DTCOutputPath + "\" + $global:DTCGeneralOutput + "ApplicationLog.csv") -fileDescription $local:filesDescription -sectionDescription $local:SectionDescription -renameOutput $true -noFileExtensionsOnDescription
			CollectFiles -filesToCollect ($global:DTCOutputPath + "\" + $global:DTCGeneralOutput + "SystemLog.csv") -fileDescription $local:filesDescription -sectionDescription $local:SectionDescription -renameOutput $true -noFileExtensionsOnDescription
		}
	}

	# update 5-9-2011 jlaborde
	# collect general run-command type data
	if( $global:gDebugDTC_DoGeneralData )
	{	if( $global:gDebugSDPOn -eq $true )
		{
			$Null	= (Get-DTC_IPConfigData)
			$Null	= (Get-DTC_ServicePermissions)
			$Null	= (Get-DTC_RunningProcesses)
		}
	}

	# update 5-10-2011 jlaborde
	# dump service permissions ( verbose )
	if( $global:gDebugSDPOn -eq $true )
	{	Write-DiagProgress -Activity $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Activity -Status $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_SC
	}
	(Get-ServicePermission "*msdtc*") | Out-File ($global:DTCOutputPath + "\" + $global:DTCServicePerms)
	if( $global:gDebugSDPOn -eq $true )
	{	$local:SectionDescription	= $MSDTCDataStrings.ID_DSI_DistSvcs_Permissions
		$local:filesDescription		= $MSDTCDataStrings.ID_DSI_DistSvcs_Permissions
		CollectFiles -filesToCollect ($global:DTCOutputPath + "\" + $global:DTCServicePerms) -fileDescription $local:filesDescription -sectionDescription $local:SectionDescription -renameOutput $true -noFileExtensionsOnDescription
	}


	# zip up & collect the data
	# zip functionality here copied from Robert Bugner & Louis Shanks - thanks guys!
		if( $global:gDebugSDPOn -eq $true )
		{	Write-DiagProgress -Activity $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Activity -Status $MSDTCDataStrings.ID_DSI_DistSvcs_CompressData
		}

		# update 1
		# 5-4-11
		# adding support to zip MSDTC directory ( so we gather trace logs )
		# make sure we have the trace logging path
		if( $global:gDebugDTC_DoTraceFile )
		{	if( $global:LocalDTCSettingsClass.LogPath -ne "" )
			{	$local:FolderToZip					= get-item $global:LocalDTCSettingsClass.LogPath
				if( $global:gDebugSDPOn -eq $true )
				{	$global:DTCZipFileTraceFullPath	= out-zip -FilePath $local:FolderToZip -zipFileName ( $global:DTCOutputFolder + "\" + $global:DTCZipFileTrace ) -activity $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Activity -status $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_GatherTraceLogs
				} else
				{	$global:DTCZipFileTraceFullPath	= out-zip -FilePath $local:FolderToZip -zipFileName ( $global:DTCOutputFolder + "\" + $global:DTCZipFileTrace ) -activity "Activity" -status "Status"
				}
			}
		}
		# end update 1

		# update 2
		# 5-4-11
		# adding support to add CM trace data, if present, to the trace zip
		if( $global:gDebugDTC_DoCMTraceFile )
		{	if( $global:LocalDTCSettingsClass.CMTracingOn )
			{	# we'll get a list of all the files and add them 1 by 1
				$local:CMTraceFiles		= Get-Item $global:LocalDTCSettingsClass.CM_Tracing_LogFileMask
				if( $null -ne $local:CMTraceFiles )
				{	foreach( $local:cmfile in $local:CMTraceFiles )
					{	if( $global:gDebugSDPOn -eq $true )
						{	$Null	= AddTo-Zip -FileToAdd $local:cmfile.FullName -ZipFileName ( $global:DTCOutputPath + "\" + $global:DTCZipFileTrace ) -activity $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Activity -status $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_GatherTraceLogs
						} else
						{	$Null	= AddTo-Zip -FileToAdd $local:cmfile.FullName -ZipFileName ( $global:DTCOutputPath + "\" + $global:DTCZipFileTrace ) -activity "Activity" -status "Status"
						}
					}
				}
				# done adding CM trace files, if any were present
			}
		}
		# end update 2

		# update 3
		# 5-9-11
		# adding support to add new diagnostic trace data, if present, to the trace zip
		if( $global:gDebugDTC_DoDiagTraceFile )
		{	if( $local:DTCSettingsClass.NewDiagnosticTracingOn )
			{	# we'll get a list of all the files and add them 1 by 1
				$local:DiagTraceFiles		= Get-Item ( $local:DTCSettingsClass.VistaTracing_TraceFilePath + "\msdtc-*.log" )
				if( $null -ne $local:DiagTraceFiles )
				{	foreach( $local:diagfile in $local:DiagTraceFiles )
					{	if( $global:gDebugSDPOn -eq $true )
						{	$Null	= AddTo-Zip -FileToAdd $local:diagfile.FullName -ZipFileName ( $global:DTCOutputPath + "\" + $global:DTCZipFileTrace ) -activity $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Activity -status $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_GatherTraceLogs
						} else
						{	$Null	= AddTo-Zip -FileToAdd $local:diagfile.FullName -ZipFileName ( $global:DTCOutputPath + "\" + $global:DTCZipFileTrace ) -activity "Activity" -status "Status"
						}
					}
				}
				# done adding diagnostic trace files, if any were present
			}
		}
		# end update 3


		# zip up the entire output folder
		$local:FolderToZip				= get-item $global:DTCOutputFolder
		if( $global:gDebugSDPOn -eq $true )
		{	$global:DTCZipFileFullPath	= out-zip -FilePath $local:FolderToZip -zipFileName $global:DTCZipFile -activity $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Activity -status $MSDTCDataStrings.ID_DSI_DistSvcs_CompressData
		} else
		{	$global:DTCZipFileFullPath	= out-zip -FilePath $local:FolderToZip -zipFileName $global:DTCZipFile -activity "Activity" -status "Status"
		}

		# test option to output to C:\
		if( $global:gDebugOutput -eq $true )
		{	# for testing purposes only
			if( $global:gDebugSDPOn -eq $true )
			{	WriteTo-StdOut ("Copying " + $global:DTCZipFileFullPath + " to " + "C:\" + $global:DTCZipFile)
			}
			Copy-Item ($global:DTCZipFileFullPath) ("C:\" + $global:DTCZipFile)
		}

		# Need to delay before we can pickup the ZIP via CollectFiles, not desired but appears we attempt to collect before
		# ZIP file has settled down enough to copy.
		Start-Sleep -s 1

		# have MSDT collect the data
		if( $global:gDebugSDPOn -eq $true )
		{	$local:SectionDescription	= $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Data_Description
			$local:filesDescription		= $MSDTCDataStrings.ID_DSI_DistSvcs_MSDTC_Data_Description
			CollectFiles -filesToCollect $global:DTCZipFile -fileDescription $local:filesDescription -sectionDescription $local:SectionDescription -renameOutput $true -noFileExtensionsOnDescription
		}
	# end zip & collection code	
}



# 'main'
if( $global:gDebugSDPOn -eq $false )
{	Clear-Host
	"Running..."
}

Get-MSDTC_SDP_Data

if( $global:gDebugSDPOn -eq $false )
{	"Done."
}


# SIG # Begin signature block
# MIInrQYJKoZIhvcNAQcCoIInnjCCJ5oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDJzCNHN3rW39EF
# LI4Wb+FwfP6nCz3JtK5OJnCQ38KPTKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGY0wghmJAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJEx+ZFWsaA10xwqZAiN54G0
# CooBxFd7eeKLCWGUek+5MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAaWEri98a3yMDEq/IL51DsFDs/24ulaL1I0t3V9pzYUDsD3UPWxkNz
# QhlI8Q88FEu05NiG96fL56Vl8Rz373b5ROHASoX205Gi67z641RngUVZdpnah+59
# XlrzHGSOU1J2pf+Fic8vUT5dQxJSh4/Ba0fAwF/zhVMKdw+dD4ObHfcldh/wA+To
# enx8HZCg8t6/z34eGlxEROo9boBrto6qWsVR6B+Tr+PwxWQIU+XEbYQhm/902Yk1
# FxD4vaQgd62dcMoWBFCJ+9rvglroEG4rFXcuc9cfV/KWJ10s9o9QAV4Lz76fcmmu
# ZOLTN86F1Rq8xCg1G2QHjoIYhG8SVS3eoYIXFTCCFxEGCisGAQQBgjcDAwExghcB
# MIIW/QYJKoZIhvcNAQcCoIIW7jCCFuoCAQMxDzANBglghkgBZQMEAgEFADCCAVgG
# CyqGSIb3DQEJEAEEoIIBRwSCAUMwggE/AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIFaKJ87Zcnkq1AZo/H/mkVoz/wlUOKBGdhdDAftxf2AgAgZi3n80
# 358YEjIwMjIwODAxMDc0MDU0LjM5WjAEgAIB9KCB2KSB1TCB0jELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IEly
# ZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# TjozQkQ0LTRCODAtNjlDMzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaCCEWUwggcUMIIE/KADAgECAhMzAAABibS/hjCEHEuPAAEAAAGJMA0G
# CSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIx
# MTAyODE5Mjc0MVoXDTIzMDEyNjE5Mjc0MVowgdIxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9w
# ZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046M0JENC00
# QjgwLTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC9BlfFkWZrqmWa47K82lXz
# E407BxiiVkb8GPJlYZKTkk4ZovKsoh3lXFUdYeWyYkThK+fOx2mwqZXHyi04294h
# QW9Jx4RmnxVea7mbV+7wvtz7eXBdyJuNxyq0S+1CyWiRBXHSv4vnhpus0NqvAUbv
# chpGJ0hLWL1z66cnyhjKENEusLKwUBXHJCE81mRYrtnz9Ua6RoosBYdcKH/5HneH
# jaAUv73+YAAvHMJde6h+Lx/9coKbvE3BVzWE40ILPqir3gC5/NU2SQhbhutRCBik
# Jwmb1TRc2ZC+2uilgOf1S1jxhDQ0p6dc+12Asd1Dw2e/eKASsoutYjRrmfmON0p/
# CT7ya9qSp1maU6x545LVeylA0kArW5mWUAhNydBk5w7mh+M5Dfe6NZyQBd3P7/He
# juXgBT9NI4zMZkzCFR21XALd1Jsi2lJUWCeMzYI4Qn3OAJp286KsYMs3jvWNkjaM
# KWSOwlN2A+TfjdNADgkW92z+6dmrS4uv6eJndfjg4HHbH6BWWWfZzhRtlc254DjJ
# LVMkZtskUggsCZNQD0C6Pl4hIZNs2LJbHv0ecI5Nqvf1AQqjObgudOYNfLT8oj8f
# +dhkYq5Md9yQ/bzBBLTqsP58NLnEvBxEwJb3YOQdea1uEbJGKUE4vkvFl6VB/G3n
# jCXhZQLQB0ASiU96Q4PA7wIDAQABo4IBNjCCATIwHQYDVR0OBBYEFJdvH7NHWngg
# gB6C4DqscqSt+XtQMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8G
# A1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBs
# BggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# DQYJKoZIhvcNAQELBQADggIBAI60t2lZQjgrB8sut9oqssH3YOpsCykZYzjVNo7g
# mX6wfE+jnba67cYpAKOaRFat4e2V/LL2Q6TstZrHeTeR7wa19619uHuofQt5XZc5
# aDf0E6cd/qZNxmrsVhJllyHUkNCNz3z452WjD6haKHQNu3gJX97X1lwT7WfXPNaS
# yRQR3R/mM8hSKzfen6+RjyzN24C0Jwhw8VSEjwdvlqU9QA8yMbPApvs0gpud/yPx
# w/XwCzki95yQXSiHVzDrdFj+88rrYsNh2mLtacbY5u+eB9ZUq3CLBMjiMePZw72r
# fscN788+XbXqBKlRmHRqnbiYqYwN9wqnU3iYR2zHPiix46s9h4WwcdYkUnoCK++q
# fvQpN4mmnmv4PFKpt5LLSbEhQ6r+UBpTGA1JBVRfbq3yv59yKSh8q/bdYeu1FXe3
# utVOwH1jOtFqKKSbPrwrkdZ230ypQvE9A+j6mlnQtGqQ5p7jrr5QpFjQnFa12sxz
# m8eUdl+eqNrCP9GwzZLpDp9r1P0KdjU3PsNgEbfJknII8WyuBTTmz2WOp+xKm2kV
# 1SH1Hhx74vvVJYMszbH/UwUsscAxtewSnwqWgQa1oNQufG19La1iF+4oapFegR8M
# 8Aych1O9A+HcYdDhKOSQEBEcvQxjvlqWEZModaMLZotU6jyhsogGTyF+cUNR/8TJ
# XDi5MIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0B
# AQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAG
# A1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAw
# HhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOTh
# pkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xP
# x2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ
# 3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOt
# gFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYt
# cI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXA
# hjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0S
# idb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSC
# D/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEB
# c8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh
# 8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8Fdsa
# N8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkr
# BgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q
# /y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBR
# BgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsG
# AQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
# BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjE
# MFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv
# Y3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEF
# BQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEB
# CwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnX
# wnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOw
# Bb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jf
# ZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ
# 5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+
# ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgs
# sU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6
# OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p
# /cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6
# TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784
# cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtQwggI9
# AgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1p
# dGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozQkQ0LTRCODAtNjlDMzElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIa
# AxUAIaUJreR63J657Ltsk2laQy6IJxCggYMwgYCkfjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOaRjzEwIhgPMjAyMjA4MDEw
# NzMwNTdaGA8yMDIyMDgwMjA3MzA1N1owdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA
# 5pGPMQIBADAHAgEAAgIlGzAHAgEAAgIRczAKAgUA5pLgsQIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBBQUAA4GBACueThL1sR3EJ2/qW8CoMkue6yHFuNJ2IHuxU4IV6CbW
# EjKI6WCeA3hghnLnBhcVOdtRxOF2Kt/9pY70qCrvKbniicJRvxdj1Hq8FsnPiHjl
# P/Awgo1UajakjIEQbJguCaxdJg/mki+DMWFsa99PKdK0C8UH/87Cz9xKiDhXmo4l
# MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGJtL+GMIQcS48AAQAAAYkwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQg4fDgXbSKlB+SUrWzcQHl
# xbnxc46+ktnSAOD6FkVcN68wgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBm
# d0cx3FBXVWxulYc5MepYTJy9xEmbtxjr2X9SZPyPRTCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABibS/hjCEHEuPAAEAAAGJMCIEICS3
# jkmWtW+jecW0AZBbxAq256f5xxy6ayfO2D9phUoRMA0GCSqGSIb3DQEBCwUABIIC
# AIMHhgamywg8RbanOj2ZNxqCxvvCoTD2z6+ou7bGZekjCy22mZePAs173fgtP4Ro
# annKDeb9OShrRaVOk8Q69faJMrethM7+TcrFuf3DCuXm2YvSlCZ2wJYEumA+73g4
# DeSGPOVR+LZfpxVpbI421IFvUlSu/lVyIQotaUFtmi0oDkTxXVMYYoJ5f72ThUIY
# NkX4Qy1aU25RiMR0/mYHHAbEqdS/2t3cfbtovmK+hKdh36AkBVNOflKH18GxS4Iu
# qNRSMK+DGti/FW+6iqXLG+2Nw++sL5V8wBVpCQtuhzuIrZiaNrlFn9reHTKTVje+
# thSWcb2U2Y6RUCqz0AIcPuUXaYAdL3Wyalw7eDrNYbNqZ+fbpfy+LZH1S5L3FI/o
# X6ZEWk+KgrLYQy9eOlNEWTG+AZSgVOIp8Lewm/TECOWvZb+RaRVqzAu0+H64h8M4
# /rHUvR38Hmm7DCKnNFeBnqSwlYGQSSZipNpG8l7E9dPId81auvl2fmhoTZlSldqd
# gjPBk8AOFTnn/YPgIPWWrhBRvfXcfcsEf0JoIG5pxInjac0BWGHSyTtXVqSyrctp
# 7URdv7RuSplNNnaMSuWfIcrCyJPGuGaGXQPNDW2/hu2BxTQBcn02PofN+08/V4sd
# 19Ckyh8OemRnbYwECIHd5as/onAfIGT2vydoqkp6zbdB
# SIG # End signature block
