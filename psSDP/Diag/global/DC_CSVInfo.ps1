#************************************************
# DC_CSVinfo.ps1
# 2019-03-17 WalterE added Trap #_# , 2020-09-28 add skipCsvSMB

# 2023-02-20 WalterE mod Trap #we#
trap [Exception]{
	WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat; continue
	Write-Host "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_"
}

$FileName = $Env:COMPUTERNAME + "_CSVInfo.HTM"

Function OpenSection ([string] $name="", $xpath="/Root", $title="")
{
	[System.Xml.XmlElement] $rootElement=$xmlDoc.SelectNodes($xpath).Item(0)
	[System.Xml.XmlElement] $section = $xmlDoc.CreateElement("Section")
	$section.SetAttribute("name",$name)
	$rootElement.AppendChild($section)
	AddXMLElement -ElementName "SectionTitle" -value $title -xpath "/Root/Section[@name=`'$name`']"

}

Function AddXMLElement ([string] $ElementName="Item", 
						[string] $Value,
						[string] $AttributeName="name", 
						[string] $attributeValue,
						[string] $xpath="/Root")
{
	[System.Xml.XmlElement] $rootElement=$xmlDoc.SelectNodes($xpath).Item(0)
	if ($null -ne $rootElement) { 
		[System.Xml.XmlElement] $element = $xmlDoc.CreateElement($ElementName)
		if ($attributeValue.lenght -ne 0) {$element.SetAttribute($AttributeName, $attributeValue)}
		if ($Value.lenght -ne 0) {$element.innerXML = $Value}
		$rootElement.AppendChild($element)
	}else{
		"Error. Path $xpath returned a null value. Current XML document: `n" + $xmlDoc.OuterXml
	}
}

Function TestCSV ($SharedVolume)
{
	#This function perform 2 tests: 
	#   1. Checks the state of a ClusterSharedVolume.
	#   2. Checks if volume is accessible locally
	#   3. Checks if volume is accessible via SMB
	
	# 1st test:
	if ($SharedVolume.State -ne "Online")
	{
		$AlertMessage = "Cluster Shared Volume <b>" + $SharedVolume.Name + "</b> has <b><font color=`'red`'>" + $SharedVolume.State + "</font></b> state."
		AddXMLAlert -AlertType $ALERT_WARNING -AlertCategory "CSV State" -AlertMessage $AlertMessage
	}else{
		# 2nd test:
		$LocalCSVStoragePath = $SharedVolume.SharedVolumeInfo[0].FriendlyVolumeName
		if (-not (Test-Path $LocalCSVStoragePath))
		{
			$AlertMessage = "Cluster Shared Volume <b>" + $SharedVolume.Name + "</b> is Online, but access to the path <b>$LocalCSVStoragePath</b> returns an error. This usually indicates a network communication problem or that the resource is in <i>Maintenance Mode</i>."
			$AlertRecommendation = ""
			if ($SharedVolume.OwnerNode.Name -ne $Env:COMPUTERNAME) 
			{
				$AlertRecommendation = "The " + $SharedVolume.Name + " is now owned by node <b>" + $SharedVolume.OwnerNode.Name.ToUpper() + "</b>. Please check if there is SMB connectivity between nodes $Env:COMPUTERNAME and " + $SharedVolume.OwnerNode.Name.ToUpper() + "<br/>"  
				$AlertRecommendation += "Common ways to test SMB connectivity are: Running <b>net view \\" + $SharedVolume.OwnerNode.Name +"</b>, <b>net view \\{IP Address of " + $SharedVolume.OwnerNode.Name.ToUpper() +"}</b> or using explorer locally to try to access the shares on remote node." 
			}
			
			AddXMLAlert -AlertType $ALERT_WARNING -AlertCategory "Local CSV Access" -AlertMessage $AlertMessage -alertRecommendation $AlertRecommendation
			
			$InformationCollected = New-Object PSObject
			$InformationCollected | Add-Member -MemberType NoteProperty -Name "Cluster Shared Volume" -Value $SharedVolume.Name
			$InformationCollected | Add-Member -MemberType NoteProperty -Name "Local CSV Path" -Value $LocalCSVStoragePath
			$InformationCollected | Add-Member -MemberType NoteProperty -Name "Current Owner" -Value $SharedVolume.OwnerNode.Name.ToUpper()
			
			Write-GenericMessage -RootCauseID "RC_CSVLocalAccess" -InformationCollected $InformationCollected -PublicContentURL "http://blogs.technet.com/b/askcore/archive/2010/12/16/troubleshooting-redirected-access-on-a-cluster-shared-volume-csv.aspx" -Visibility 4 -Component "FailoverCluster" -SupportTopicsID 8003 -SDPFileReference $FileName
			
			if ($CSVLocalAccessIssueDisplay -ne "") 
			{
				$CSVVolumeNames += " and "
				$CSVLocalAccessIssueDisplay += "<br/><br/>"
			}
			$CSVLocalAccessIssueDisplay += $AlertMessage
			$CSVVolumeNames += $SharedVolume.Name 
		}
		
		if ($null -ne $CSVLocalAccessArray) 
		{
			Update-DiagRootCause -id "RC_CSVLocalAccess" -Detected $true
		}
		
		# 3rd test:
		#_# adding knob to skipt 3rd test
		if ($Global:skipCsvSMB -ne $true) {
		if ($SharedVolume.OwnerNode.Name -ne $Env:COMPUTERNAME) {
			"Testing accessing shares via SMB..."
			$CSVCommunicationNetworks = GetInternalIPAdressesForCommunicationWithNode $SharedVolume.OwnerNode.Name
			$CSVStorageShare = $SharedVolume.Id + "-" + $SharedVolume.SharedVolumeInfo[0].VolumeOffset
			$RC_CSVNetworkAccess = $false
			Foreach ($CSVNetwork in $CSVCommunicationNetworks) 
			{
				
				"Testing $IPAdress..."
				$IPAdress = $CSVNetwork.Address
				$ShareURL = "\\$IPAdress\$CSVStorageShare" + "$"
				
				#It is expected that user receive Access Denied from share
				#Since it does not have permissions for user access the share. 
	
				$Error.Clear
				&{
					"Test" | Out-File $ShareURL -ErrorAction SilentlyContinue
				}
				trap 
				{
					$CSVVolumeNames = ""
					$ExceptionToAccessShare = $_.Exception.GetType().FullName
					if ($ExceptionToAccessShare -ne "System.UnauthorizedAccessException") 
					{
						$ExceptionToAccessShare += ": " + $_.Exception.Message
						$AlertMessage = "Unable to access <b>" + $SharedVolume.Name + "</b> volume on node <b>" + $SharedVolume.OwnerNode.Name.ToUpper() + "</b> via SMB using address \\$IPAdress. The exception to access the share is <b><font color=`'red`'>$ExceptionToAccessShare</font></b>"
						$AlertRecommendation = ""
						
						if ($SharedVolume.OwnerNode.Name -ne $Env:COMPUTERNAME) 
						{
							$NetworkName = $CSVNetwork.Name
							$AlertRecommendation = "The " + $SharedVolume.Name + " is now owned by node <b>" + $SharedVolume.OwnerNode.Name + "</b>. Please check if there is SMB connection between node $Env:COMPUTERNAME and " + $SharedVolume.OwnerNode.Name.ToUpper() + "<br/>"  
							$AlertRecommendation += "Common ways to test SMB connectivity are: Running <b>net view \\" + $IPAdress +"</b> or using explorer locally to try to access the shares on remote node.<br/>"
							$AlertRecommendation += "Please also check if the <i>Client For Microsoft Networks</i> is enabled on $Env:COMPUTERNAME. Also check if the <i>File and Print Sharing for Microsoft Networks</i> is enabled on " + $SharedVolume.OwnerNode.Name + "'s <b>$NetworkName</b> network connection."
						}
						
						AddXMLAlert -AlertType $ALERT_WARNING -AlertCategory "Remote CSV Access" -AlertMessage $AlertMessage -AlertRecommendation $AlertRecommendation 
						if ($CSVNetworkAccessIssueDisplay -ne "") 
						{
							$CSVVolumeNames += " and "
							$CSVNetworkAccessIssueDisplay += "<br/><br/>"
						}
						
						$InformationCollected = @{"Shared volume" = $SharedVolume.Name; "Current Owner" = $SharedVolume.OwnerNode.Name; "State" = $SharedVolume.State; "Volume Path" = $SharedVolume.SharedVolumeInfo[0].Partition.Name; "CSV Network Name" = $CSVNetwork.Name}
						Write-GenericMessage -RootCauseID "RC_CSVNetworkAccess" -InformationCollected $InformationCollected -PublicContentURL "http://blogs.technet.com/b/askcore/archive/2010/12/16/troubleshooting-redirected-access-on-a-cluster-shared-volume-csv.aspx" -Visibility 4 -Component "FailoverCluster" -SupportTopicsID 8003 -SDPFileReference $FileName
						$RC_CSVNetworkAccess = $true
						
						$CSVNetworkAccessIssueDisplay += $AlertMessage
						$CSVVolumeNames += $SharedVolume.Name
					}

					continue; 
				}
			}
			if ($RC_CSVNetworkAccess) 
			{
				Update-DiagRootCause -id "RC_CSVNetworkAccess" -Detected $true
			}

		} #_# and 3rd test
		}
	}
}

Function GetInternalIPAdressesForCommunicationWithNode ([string] $NodeName)
{
	Return Get-ClusterNetworkInterface | Where-Object {($_.Network.Role -ne 0) -and ($_.Node -eq $NodeName)}
}

Function AddXMLAlert([int] $AlertType = $ALERT_INFORMATION, 
					[string] $AlertCategory="",
					[string] $AlertMessage="",
					[string] $AlertRecommendation="",
					[int] $AlertPriority=50)
{
	switch ($AlertType)	{
		$ALERT_INFORMATION {$strAlertType = "Information"}
		$ALERT_WARNING {$strAlertType = "Warning"}
		$ALERT_ERROR {$strAlertType = "Error"}
	}
	# Try to find the <Alerts> node. Create it if does not exist.	
	[System.Xml.XmlElement] $alertsElement=$xmlDoc.SelectNodes("/Root/Alerts").Item(0)
	if ($null -eq $alertsElement) {
		AddXMLElement -ElementName "Alerts"
	}
	
	$XMLAlert =   "<AlertType>$strAlertType</AlertType>" +
                  "<AlertCategory>$AlertCategory</AlertCategory>" +
                  "<AlertMessage>$AlertMessage</AlertMessage>" +
	              "<AlertPriority>$AlertPriority</AlertPriority>"
	if ($AlertRecommendation.Length -ne 0) {
		$XMLAlert += "<AlertRecommendation>$AlertRecommendation</AlertRecommendation>"
	}
    	
	AddXMLElement -ElementName "Alert" -xpath "/Root/Alerts" -value $XMLAlert 
}

Function GenerateHTMLFile(){
	$HTMLFilename = $PWD.Path + "\" + $Env:COMPUTERNAME + "_CSVInfo.HTM"
	$XSLFilename = $Env:COMPUTERNAME + "_CSVInfo.XSL"
	$XMLFilename = $Env:TEMP + "\CSVInfo.XML"
	$xmlDoc.Save($XMLFilename)
	[xml] $XSLContent = (EmbeddedXSL $XSLFilename)
	$XSLObject = New-Object system.Xml.Xsl.XslTransform
	$XSLObject.Load($XSLContent)
	$XSLObject.Transform($XMLFilename, $HTMLFilename)
	Remove-Item $XMLFilename
	return $HTMLFilename
    "Output saved at $HTMLFilename"
}

Function EmbeddedXSL($XSLFilename){
	$PSScriptName = $myInvocation.ScriptName
	
	Get-Content $PSScriptName | ForEach-Object {
		if ($insideXSL) {
			if ($_ -eq "}") {$insideXSL = $true}
		}
		if ($insideXSL) {
			$XSLContent += $_.Substring(1)
		}
		if ($_ -eq "Function EmbeddedXSL(){"){$insideXSL = $true}
	}
	return $XSLContent
}

#region: MAIN
Set-Variable -Name ALERT_INFORMATION -Value 1 -Option Constant
Set-Variable -Name ALERT_WARNING -Value 2 -Option Constant
Set-Variable -Name ALERT_ERROR -Value 3 -Option Constant

$ClusterKey="HKLM:\Cluster"
$xmlDoc = [xml] "<?xml version=""1.0""?><Root/>"
$ClusterKey="HKLM:\Cluster"

if (($OSVersion.Build -ge 7600) -and (Test-Path $ClusterKey)) 
{

	Import-LocalizedData -BindingVariable ScriptVariables
	Write-DiagProgress -activity $ScriptVariables.ID_ClusterCSVD -status $ScriptVariables.ID_ClusterCSVDesc
	
	Import-Module FailoverClusters
	
	$SharedVolumes = Get-ClusterSharedVolume
	
	if ($null -ne $SharedVolumes) {
		AddXMLElement -ElementName "Title" -Value $Env:COMPUTERNAME
		$CurrentDate = Get-Date
		AddXMLElement -ElementName "TimeField" -Value $CurrentDate 
		
		OpenSection -name "SharedVolumes" -title "Cluster Shared Volumes"
		AddXMLElement -attributeValue "CSV Enabled" -Value "True" -xpath "/Root/Section[@name=`'SharedVolumes`']"
		$RC_CSVMaint = $false
		foreach ($SharedVolume in $SharedVolumes) 
		{
			$sharedVolumeID = $SharedVolume.Id
			AddXMLElement -ElementName "SubSection" -attributeValue $SharedVolumeID -xpath "/Root/Section[@name=`'SharedVolumes`']"
			$csvVolumeSectionTitle = "Volume: " + $SharedVolume.Name
			AddXMLElement -ElementName "SectionTitle" -value $csvVolumeSectionTitle  -xpath "/Root/Section/SubSection[@name=`'$SharedVolumeId`']"
			AddXMLElement -attributeValue "State" -value $SharedVolume.State -xpath "/Root/Section/SubSection[@name=`'$SharedVolumeId`']"
			AddXMLElement -attributeValue "Current Owner" -value $SharedVolume.OwnerNode.Name -xpath "/Root/Section/SubSection[@name=`'$SharedVolumeId`']"
			AddXMLElement -attributeValue "ID" -value $SharedVolume.Id -xpath "/Root/Section/SubSection[@name=`'$SharedVolumeId`']"
			AddXMLElement -attributeValue "Volume Name" -value $SharedVolume.SharedVolumeInfo[0].FriendlyVolumeName -xpath "/Root/Section/SubSection[@name=`'$SharedVolumeId`']"
			$VolumeSize = '{0:N2}' -f ($SharedVolume.SharedVolumeInfo[0].Partition.Size / 1024 /1024)
			$VolumeSize += " MB"
			AddXMLElement -attributeValue "Volume Size" -value $VolumeSize  -xpath "/Root/Section/SubSection[@name=`'$SharedVolumeId`']"
			AddXMLElement -attributeValue "Volume Path" -value $SharedVolume.SharedVolumeInfo[0].Partition.Name -xpath "/Root/Section/SubSection[@name=`'$SharedVolumeId`']"
			AddXMLElement -attributeValue "Maintenance mode" -value $SharedVolume.SharedVolumeInfo[0].MaintenanceMode -xpath "/Root/Section/SubSection[@name=`'$SharedVolumeId`']"
			AddXMLElement -attributeValue "Redirected access" -value $SharedVolume.SharedVolumeInfo[0].RedirectedAccess -xpath "/Root/Section/SubSection[@name=`'$SharedVolumeId`']"
			if ($SharedVolume.SharedVolumeInfo[0].MaintenanceMode) 
			{
				$AlertMessage = "Shared Volume <b> " + $SharedVolume.Name + "</b> owned by node <b>" + $SharedVolume.OwnerNode.Name + "</b> is now on Maintenance Mode"
				$InformationCollected = @{"Shared volume" = $SharedVolume.Name; "Current Owner" = $SharedVolume.OwnerNode.Name; "State" = $SharedVolume.State; "Volume Path" = $SharedVolume.SharedVolumeInfo[0].Partition.Name}
				
				AddXMLAlert -AlertType $ALERT_INFORMATION -AlertCategory "Maintenance Mode" -AlertMessage $AlertMessage -AlertPriority 60
				Write-GenericMessage -RootCauseID "RC_CSVMaint" -Component "FailoverCluster" -InformationCollected $InformationCollected -PublicContentURL "http://blogs.technet.com/b/askcore/archive/2010/12/16/troubleshooting-redirected-access-on-a-cluster-shared-volume-csv.aspx" -Visibility 4 -SupportTopicsID 8003 -SDPFileReference $FileName
				
				$RC_CSVMaint = $true
			}
			
			if ($SharedVolume.SharedVolumeInfo[0].RedirectedAccess) 
			{
				$AlertMessage = "Shared Volume <b>" + $SharedVolume.Name + "</b> owned by node <b>" + $SharedVolume.OwnerNode.Name + "</b> has now Redirected Access enabled"
				AddXMLAlert -AlertType $ALERT_INFORMATION -AlertCategory "Redirected Access" -AlertMessage $AlertMessage -AlertPriority 60
				
				$RC_CSVRedirect = $true
				$InformationCollected = @{"Shared volume" = $SharedVolume.Name; "Current Owner" = $SharedVolume.OwnerNode.Name}
				Write-GenericMessage -RootCauseID "RC_CSVRedirect" -Component "FailoverCluster" -InformationCollected $InformationCollected -PublicContentURL "http://blogs.technet.com/b/askcore/archive/2010/12/16/troubleshooting-redirected-access-on-a-cluster-shared-volume-csv.aspx" -Visibility 4 -SupportTopicsID 8003 -SDPFileReference $FileName
				
			}			
			TestCSV $SharedVolume	
		}
		
		if ($null -ne $RC_CSVMaint)  { Update-DiagRootCause -id "RC_CSVMaint" -Detected $RC_CSVMaint}
		if ($null -ne $RC_CSVRedirect)   { Update-DiagRootCause -id "RC_CSVRedirect" -Detected $RC_CSVRedirect }
		
		$fileToCollect = GenerateHTMLFile
		CollectFiles -filesToCollect $fileToCollect -fileDescription "CSV Information" -sectionDescription "Cluster Shared Volumes"
        
	}else{
		"There are no Cluster Shared Volumes on this cluster" | writeto-stdout
	}
}else{
	"Cluster registry key does not exist or OS does not support CSVs" | WriteTo-StdOut
}

#endregion: MAIN

Function EmbeddedXSL(){
#<?xml version="1.0"?>
#<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
#<xsl:output method="html" />
#<xsl:template match="/Root">
#<html dir="ltr" xmlns:v="urn:schemas-microsoft-com:vml" gpmc_reportInitialized="false">
#<head>
#<!-- Styles -->
#  <style type="text/css">
#    body    { background-color:#FFFFFF; border:1px solid #666666; color:#000000; font-size:68%; font-family:MS Shell Dlg; margin:0,0,10px,0; word-break:normal; word-wrap:break-word; }
#
#    table   { font-size:100%; table-layout:fixed; width:100%; }
#
#    td,th   { overflow:visible; text-align:left; vertical-align:top; white-space:normal; }
#
#    .title  { background:#FFFFFF; border:none; color:#333333; display:block; height:24px; margin:0px,0px,-1px,0px; padding-top:4px; position:relative; table-layout:fixed; width:100%; z-index:5; }
#
#    .he0_expanded    { background-color:#FEF7D6; border:1px solid #BBBBBB; color:#3333CC; cursor:hand; display:block; font-family:Verdana; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%;
#    filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=1,StartColorStr='#FEF7D6',EndColorStr='white');}
#
#    .he3_expanded { background-color:#C0D2DE; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; font-weight:bold; margin-left:0px; margin-right:0px; padding-left:4px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
#
#    .he1old { background-color:#A0BACB; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
#
#    .he1    { background-color:#FEF7D6; border:1px solid #BBBBBB; color:#3333CC; cursor:hand; display:block; font-family:Segoe UI, Verdana; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
#
#    .he2    { background-color:#C0D2DE; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
#
#    .he2b    { background-color:#C0D2DE; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
#
#    .he4i   { background-color:#F9F9F9; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; margin-bottom:-1px; margin-left:15px; margin-right:0px; padding-bottom:5px; padding-left:12px; padding-top:4px; position:relative; width:100%; }
#
#    DIV .expando { color:#000000; text-decoration:none; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:normal; position:absolute; right:10px; text-decoration:underline; z-index: 0; }
#
#    .info4 TD, .info4 TH              { padding-right:10px; width:25%;}
#
#    .infoFirstCol                     { padding-right:10px; width:20%; }
#    .infoSecondCol                     { padding-right:10px; width:80%; }
#
#
#    .subtable, .subtable3             { border:1px solid #CCCCCC; margin-left:0px; background:#FFFFFF; margin-bottom:10px; }
#
#    .subtable TD, .subtable3 TD       { padding-left:10px; padding-right:5px; padding-top:3px; padding-bottom:3px; line-height:1.1em; width:10%; }
#
#    .subtable TH, .subtable3 TH       { border-bottom:1px solid #CCCCCC; font-weight:normal; padding-left:10px; line-height:1.6em;  }
#
#    .explainlink:hover      { color:#0000FF; text-decoration:underline; }
#
#    .filler { background:transparent; border:none; color:#FFFFFF; display:block; font:100% MS Shell Dlg; line-height:8px; margin-bottom:-1px; margin-left:43px; margin-right:0px; padding-top:4px; position:relative; }
#
#    .container { display:block; position:relative; }
#
#    .rsopheader { background-color:#A0BACB; border-bottom:1px solid black; color:#333333; font-family:MS Shell Dlg; font-size:130%; font-weight:bold; padding-bottom:5px; text-align:center;
#    filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=0,StartColorStr='#FFFFFF',EndColorStr='#A0BACB')}
#
#    .rsopname { color:#333333; font-family:MS Shell Dlg; font-size:130%; font-weight:bold; padding-left:11px; }
#
#    #uri    { color:#333333; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; }
#
#    #dtstamp{ color:#333333; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; text-align:left; width:30%; }
#
#    #objshowhide { color:#000000; cursor:hand; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; margin-right:0px; padding-right:10px; text-align:right; text-decoration:underline; z-index:2; word-wrap:normal; }
#
#
#    @media print {
#
#    #objshowhide{ display:none; }
#
#    body    { color:#000000; border:1px solid #000000; }
#
#    .title  { color:#000000; border:1px solid #000000; }
#
#    .he0_expanded    { color:#000000; border:1px solid #000000; }
#
#    }
#
#    v\:* {behavior:url(#default#VML);}
#
#  </style>
#<!-- Script 1 -->
#
#<script language="vbscript" type="text/vbscript">
#<![CDATA[
#<!--
#'================================================================================
#' String "strShowHide(0/1)"
#' 0 = Hide all mode.
#' 1 = Show all mode.
#strShowHide = 1
#
#'Localized strings
#strShow = "show"
#strHide = "hide"
#strShowAll = "show all"
#strHideAll = "hide all"
#strShown = "shown"
#strHidden = "hidden"
#strExpandoNumPixelsFromEdge = "10px"
#
#
#Function IsSectionHeader(obj)
#    IsSectionHeader = (obj.className = "he0_expanded") Or (obj.className = "he1_expanded") Or (obj.className = "he1") Or (obj.className = "he2") Or (obj.className = "he2g") Or (obj.className = "he2c") or (obj.className = "he3") Or (obj.className = "he4") Or (obj.className = "he4h") Or (obj.className = "he5") Or (obj.className = "he5h")  or (obj.className = "he4_expanded")
#End Function
#
#
#Function IsSectionExpandedByDefault(objHeader)
#    IsSectionExpandedByDefault = (Right(objHeader.className, Len("_expanded")) = "_expanded")
#End Function
#
#
#' strState must be show | hide | toggle
#Sub SetSectionState(objHeader, strState)
#    ' Get the container object for the section.  It's the first one after the header obj.
#
#    i = objHeader.sourceIndex
#    Set all = objHeader.parentElement.document.all
#    While (all(i).className <> "container")
#        i = i + 1
#    Wend
#
#    Set objContainer = all(i)
#
#    If strState = "toggle" Then
#        If objContainer.style.display = "none" Then
#            SetSectionState objHeader, "show"
#        Else
#            SetSectionState objHeader, "hide"
#        End If
#
#    Else
#        Set objExpando = objHeader.children(1)
#
#        If strState = "show" Then
#            objContainer.style.display = "block"
#            rem objExpando.innerText = strHide
#            rem objExpando.innerHTML = "<v:group id=" & chr(34) & "Show" & chr(34) & " class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:15px;height:15px;vertical-align:middle" & chr(34) & " coordsize=" & chr(34) & "100,100" & chr(34) & " alt=" & chr(34) & "Hide" & chr(34) & "><v:shape class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:100; height:100; z-index:0" & chr(34) & " fillcolor=" & chr(34) & "green" & chr(34) & " strokecolor=" & chr(34) & "green" & chr(34) & "><v:path v=" & chr(34) & "m 30,50 l 70,50 x e" & chr(34) & " /></v:shape></v:group>"
#            objExpando.innerHTML =   "<v:group class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:15px;height:15px;vertical-align:middle" & chr(34) & " coordsize=" & chr(34) & "100,100" & chr(34) & " alt=" & chr(34) & "Show" & chr(34) & "><v:rect " & chr(34) & " stroked=" & chr(34) & "False" & chr(34) & "fillcolor=" & chr(34) & "#808080" & chr(34) & " style=" & chr(34) & "top:47;left:25;width:50;height:5" & chr(34) & " /></v:group>"
#        ElseIf strState = "hide" Then
#            objContainer.style.display = "none"
#            rem objExpando.innerText = strShow
#            rem objExpando.outerHTML = "<v:group class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:15px;height:15px;vertical-align:middle" & chr(34) & " coordsize=" & chr(34) & "100,100" & chr(34) & " alt=" & chr(34) & "Show" & chr(34) & "><v:shape class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:100; height:100; z-index:0" & chr(34) & " fillcolor=" & chr(34) & "black" & chr(34) & " strokecolor=" & chr(34) & "red" & chr(34) & "><v:path v=" & chr(34) & "m 99,1 l 1,1 50,50 x e" & chr(34) & " /></v:shape></v:group>"
#            objExpando.innerHTML =   "<v:group class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:15px;height:15px;vertical-align:middle" & chr(34) & " coordsize=" & chr(34) & "100,100" & chr(34) & " alt=" & chr(34) & "Show" & chr(34) & "><v:rect fillcolor=" & chr(34) & "#808080" & chr(34) & " stroked=" & chr(34) & "False" & chr(34) & " style=" & chr(34) & "top:47;left:25;width:50;height:5" & chr(34) & " /><v:rect fillcolor=" & chr(34) & "#808080" & chr(34) & " stroked=" & chr(34) & "False" & chr(34) & " style=" & chr(34) & "top:25;left:47;width:5;height:50" & chr(34) & " /></v:group>"
#        End If
#
#    End If
#End Sub
#
#
#Sub ShowSection(objHeader)
#    SetSectionState objHeader, "show"
#End Sub
#
#
#Sub HideSection(objHeader)
#    SetSectionState objHeader, "hide"
#End Sub
#
#
#Sub ToggleSection(objHeader)
#    SetSectionState objHeader, "toggle"
#End Sub
#
#
#'================================================================================
#' When user clicks anywhere in the document body, determine if user is clicking
#' on a header element.
#'================================================================================
#Function document_onclick()
#    Set strsrc    = window.event.srcElement
#
#    While (strsrc.className = "sectionTitle" Or strsrc.className = "expando" Or strsrc.className = "vmlimage")
#        Set strsrc = strsrc.parentElement
#    Wend
#
#    ' Only handle clicks on headers.
#    If Not IsSectionHeader(strsrc) Then Exit Function
#
#    ToggleSection strsrc
#
#    window.event.returnValue = False
#End Function
#
#'================================================================================
#' link at the top of the page to collapse/expand all collapsable elements
#'================================================================================
#Function objshowhide_onClick()
#    Set objBody = document.body.all
#    Select Case strShowHide
#        Case 0
#            strShowHide = 1
#            objshowhide.innerText = strShowAll
#            For Each obji In objBody
#                If IsSectionHeader(obji) Then
#                    HideSection obji
#                End If
#            Next
#        Case 1
#            strShowHide = 0
#            objshowhide.innerText = strHideAll
#            For Each obji In objBody
#                If IsSectionHeader(obji) Then
#                    ShowSection obji
#                End If
#            Next
#    End Select
#End Function
#
#'================================================================================
#' onload collapse all except the first two levels of headers (he0, he1)
#'================================================================================
#Function window_onload()
#    ' Only initialize once.  The UI may reinsert a report into the webbrowser control,
#    ' firing onLoad multiple times.
#    If UCase(document.documentElement.getAttribute("gpmc_reportInitialized")) <> "TRUE" Then
#
#        ' Set text direction
#        Call fDetDir(UCase(document.dir))
#
#        ' Initialize sections to default expanded/collapsed state.
#        Set objBody = document.body.all
#
#        For Each obji in objBody
#            If IsSectionHeader(obji) Then
#                If IsSectionExpandedByDefault(obji) Then
#                    ShowSection obji
#                Else
#                    HideSection obji
#                End If
#            End If
#        Next
#
#        objshowhide.innerText = strShowAll
#
#        document.documentElement.setAttribute "gpmc_reportInitialized", "true"
#    End If
#End Function
#
#
#
#
#'================================================================================
#' When direction (LTR/RTL) changes, change adjust for readability
#'================================================================================
#Function document_onPropertyChange()
#    If window.event.propertyName = "dir" Then
#        Call fDetDir(UCase(document.dir))
#    End If
#End Function
#Function fDetDir(strDir)
#    strDir = UCase(strDir)
#    Select Case strDir
#        Case "LTR"
#            Set colRules = document.styleSheets(0).rules
#            For i = 0 To colRules.length -1
#                Set nug = colRules.item(i)
#                strClass = nug.selectorText
#                If nug.style.textAlign = "right" Then
#                    nug.style.textAlign = "left"
#                End If
#                Select Case strClass
#                    Case "DIV .expando"
#                        nug.style.Left = ""
#                        nug.style.right = strExpandoNumPixelsFromEdge
#                    Case "#objshowhide"
#                        nug.style.textAlign = "right"
#                End Select
#            Next
#        Case "RTL"
#            Set colRules = document.styleSheets(0).rules
#            For i = 0 To colRules.length -1
#                Set nug = colRules.item(i)
#                strClass = nug.selectorText
#                If nug.style.textAlign = "left" Then
#                    nug.style.textAlign = "right"
#                End If
#                Select Case strClass
#                    Case "DIV .expando"
#                        nug.style.Left = strExpandoNumPixelsFromEdge
#                        nug.style.right = ""
#                    Case "#objshowhide"
#                        nug.style.textAlign = "left"
#                End Select
#            Next
#    End Select
#End Function
#
#'================================================================================
#'When printing reports, if a given section is expanded, let's says "shown" (instead of "hide" in the UI).
#'================================================================================
#Function window_onbeforeprint()
#    For Each obji In document.all
#        If obji.className = "expando" Then
#            If obji.innerText = strHide Then obji.innerText = strShown
#            If obji.innerText = strShow Then obji.innerText = strHidden
#        End If
#    Next
#End Function
#
#'================================================================================
#'If a section is collapsed, change to "hidden" in the printout (instead of "show").
#'================================================================================
#Function window_onafterprint()
#    For Each obji In document.all
#        If obji.className = "expando" Then
#            If obji.innerText = strShown Then obji.innerText = strHide
#            If obji.innerText = strHidden Then obji.innerText = strShow
#        End If
#    Next
#End Function
#
#'================================================================================
#' Adding keypress support for accessibility
#'================================================================================
#Function document_onKeyPress()
#    If window.event.keyCode = "32" Or window.event.keyCode = "13" Or window.event.keyCode = "10" Then 'space bar (32) or carriage return (13) or line feed (10)
#        If window.event.srcElement.className = "expando" Then Call document_onclick() : window.event.returnValue = false
#        If window.event.srcElement.className = "sectionTitle" Then Call document_onclick() : window.event.returnValue = false
#        If window.event.srcElement.id = "objshowhide" Then Call objshowhide_onClick() : window.event.returnValue = false
#    End If
#End Function
#
#-->
#]]>
#</script>
#
#<!-- Script 2 -->
#
#<script language="javascript"><![CDATA[
#<!--
#function getExplainWindowTitle()
#{
#        return document.getElementById("explainText_windowTitle").innerHTML;
#}
#
#function getExplainWindowStyles()
#{
#        return document.getElementById("explainText_windowStyles").innerHTML;
#}
#
#function getExplainWindowSettingPathLabel()
#{
#        return document.getElementById("explainText_settingPathLabel").innerHTML;
#}
#
#function getExplainWindowExplainTextLabel()
#{
#        return document.getElementById("explainText_explainTextLabel").innerHTML;
#}
#
#function getExplainWindowPrintButton()
#{
#        return document.getElementById("explainText_printButton").innerHTML;
#}
#
#function getExplainWindowCloseButton()
#{
#        return document.getElementById("explainText_closeButton").innerHTML;
#}
#
#function getNoExplainTextAvailable()
#{
#        return document.getElementById("explainText_noExplainTextAvailable").innerHTML;
#}
#
#function getExplainWindowSupportedLabel()
#{
#        return document.getElementById("explainText_supportedLabel").innerHTML;
#}
#
#function getNoSupportedTextAvailable()
#{
#        return document.getElementById("explainText_noSupportedTextAvailable").innerHTML;
#}
#
#function showExplainText(srcElement)
#{
#    var strSettingName = srcElement.getAttribute("gpmc_settingName");
#    var strSettingPath = srcElement.getAttribute("gpmc_settingPath");
#    var strSettingDescription = srcElement.getAttribute("gpmc_settingDescription");
#
#    if (strSettingDescription == "")
#    {
#                strSettingDescription = getNoExplainTextAvailable();
#    }
#
#    var strSupported = srcElement.getAttribute("gpmc_supported");
#
#    if (strSupported == "")
#    {
#        strSupported = getNoSupportedTextAvailable();
#    }
#
#    var strHtml = "<html>\n";
#    strHtml += "<head>\n";
#    strHtml += "<title>" + getExplainWindowTitle() + "</title>\n";
#    strHtml += "<style type='text/css'>\n" + getExplainWindowStyles() + "</style>\n";
#    strHtml += "</head>\n";
#    strHtml += "<body>\n";
#    strHtml += "<div class='head'>" + strSettingName +"</div>\n";
#    strHtml += "<div class='path'><b>" + getExplainWindowSettingPathLabel() + "</b><br/>" + strSettingPath +"</div>\n";
#    strHtml += "<div class='path'><b>" + getExplainWindowSupportedLabel() + "</b><br/>" + strSupported +"</div>\n";
#    strHtml += "<div class='info'>\n";
#    strHtml += "<div class='hdr'>" + getExplainWindowExplainTextLabel() + "</div>\n";
#    strHtml += "<div class='bdy'>" + strSettingDescription + "</div>\n";
#    strHtml += "<div class='btn'>";
#    strHtml += getExplainWindowPrintButton();
#    strHtml += getExplainWindowCloseButton();
#    strHtml += "</div></body></html>";
#
#    var strDiagArgs = "height=360px, width=630px, status=no, toolbar=no, scrollbars=yes, resizable=yes ";
#    var expWin = window.open("", "expWin", strDiagArgs);
#    expWin.document.write("");
#    expWin.document.close();
#    expWin.document.write(strHtml);
#    expWin.document.close();
#    expWin.focus();
#
#    //cancels navigation for IE.
#    if(navigator.userAgent.indexOf("MSIE") > 0)
#    {
#        window.event.returnValue = false;
#    }
#
#    return false;
#}
#-->
#]]>
#</script>
#
#</head>
#
#<body>
#
#	<table class="title" cellpadding="0" cellspacing="0">
#	<tr><td colspan="2" class="rsopheader">Cluster Shared Volume Information</td></tr>
#	<tr><td colspan="2" class="rsopname">Machine name: <xsl:value-of select="Title"/></td></tr>
#	<tr><td id="dtstamp">Data collected on: <xsl:value-of select="TimeField"/></td><td><div id="objshowhide" tabindex="0"></div></td></tr>
#	</table>
#	<div class="filler"></div>
#
#  <xsl:if test="./Alerts/Alert">
#    <div class="container">
#      <div class="he0_expanded">
#        <span class="sectionTitle" tabindex="0">Alerts</span>
#        <a class="expando" href="#"></a>
#      </div>
#      <div class="container">
#        <xsl:for-each select="./Alerts/Alert">
#          <xsl:sort select="AlertPriority" order="descending" data-type="number"/>
#          <div class="he2b">
#            <span class="sectionTitle" tabindex="0">
#              <xsl:choose>
#                <xsl:when test="AlertType = 'Information'">
#                  <v:group id="Inf1" class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Information">
#                    <v:oval class="vmlimage" style="width:100;height:100;z-index:0" fillcolor="white" strokecolor="#336699" />
#                    <v:line class="vmlimage" style="z-index:1" from="50,15" to="50,25" strokecolor="#336699" strokeweight="3px" />
#                    <v:line class="vmlimage" style="z-index:2" from="50,35" to="50,80" strokecolor="#336699" strokeweight="3px" />
#                  </v:group>
#                </xsl:when>
#                <xsl:when test="AlertType = 'Warning'">
#                  <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Warning">
#                    <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="yellow" strokecolor="#C0C0C0">
#                      <v:path v="m 50,0 l 0,99 99,99 x e" />
#                    </v:shape>
#                    <v:rect class="vmlimage" style="top:35; left:45; width:10; height:35; z-index:1" fillcolor="black" strokecolor="black">
#                    </v:rect>
#                    <v:rect class="vmlimage" style="top:85; left:45; width:10; height:5; z-index:1" fillcolor="black" strokecolor="black">
#                    </v:rect>
#                  </v:group>
#                </xsl:when>
#                <xsl:when test="AlertType = 'Error'">
#                  <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Error">
#                    <v:oval class="vmlimage" style='width:100;height:100;z-index:0' fillcolor="red" strokecolor="red">
#                    </v:oval>
#                    <v:line class="vmlimage" style="z-index:1" from="25,25" to="75,75" strokecolor="white" strokeweight="3px">
#                    </v:line>
#                    <v:line class="vmlimage" style="z-index:2" from="75,25" to="25,75" strokecolor="white" strokeweight="3px">
#                    </v:line>
#                  </v:group>
#                </xsl:when>
#                <xsl:when test="AlertType = 'Memory Dump'">
#                  <v:group class="vmlimage" style="width:14px;height:14px;vertical-align:middle" coordsize="100,100" title="Memory Dump">
#                    <v:roundrect class="vmlimage" arcsize="0.3" style="width:100;height:100;z-index:0" fillcolor="#008000" strokecolor="#66665B" />
#                    <v:line class="vmlimage" style="z-index:2" from="50,15" to="50,60" strokecolor="white" strokeweight="3px" />
#                    <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="white" strokecolor="white">
#                      <v:path v="m 50,85 l 75,60 25,60 x e" />
#                    </v:shape>
#                  </v:group>
#                  <xsl:text>&#160;</xsl:text>
#                </xsl:when>
#              </xsl:choose>
#              <xsl:value-of select="AlertType"/>
#            </span>
#            <a class="expando" href="#"></a>
#          </div>
#          <div class="container">
#            <div class="he4i">
#              <table cellpadding="0" class="info0">
#                <tr>
#                  <td class="infoFirstCol">Category: </td>
#                  <td class="infoSecondCol">
#                    <xsl:value-of disable-output-escaping="yes" select="AlertCategory"/>
#                  </td>
#                  <td></td>
#                </tr>
#                <tr>
#                  <td class="infoFirstCol">Message: </td>
#                  <td class="infoSecondCol">
#                    <xsl:copy-of select="AlertMessage"/>
#                  </td>
#                  <td></td>
#                </tr>
#                <xsl:if test="AlertRecommendation">
#                  <tr>
#                    <td class="infoFirstCol">Recommendation: </td>
#                    <td class="infoSecondCol">
#                      <xsl:copy-of select="AlertRecommendation"/>
#                    </td>
#                    <td></td>
#                  </tr>
#                </xsl:if>
#              </table>
#            </div>
#          </div>
#        </xsl:for-each>
#      </div>
#    </div>
#  </xsl:if>
#	<div class="filler"></div>
#	
#	<xsl:for-each select="./Section">
#
#	<div class="he0_expanded"><span class="sectionTitle" tabindex="0"><xsl:value-of select="SectionTitle"/></span><a class="expando" href="#"></a></div>
#	
#		<div class="container"><div class="he4i"><table cellpadding="0" class="info4" >
#		<tr><td></td><td></td><td></td><td></td><td></td></tr>
#		<xsl:for-each select="./Item">
#		<xsl:variable name="pos" select="position()" />
#		<xsl:variable name="mod" select="($pos mod 2)" />
#		<tr><td><xsl:value-of select="@name"/></td><td colspan="4"><xsl:value-of select="."/></td></tr>
#		</xsl:for-each>
#		</table>
#		<xsl:for-each select="./SubSection">
#			<div class="container">
#			<div class="he3_expanded"><span class="sectionTitle" tabindex="0"><xsl:value-of select="SectionTitle/@name"/><xsl:text> </xsl:text><a name="{SectionTitle}"><xsl:value-of select="SectionTitle"/></a></span><a class="expando" href="#"></a></div>
#			<div class="container"><div class="he4i"><table cellpadding="0" class="info4">
#				<tr><td></td><td></td><td></td><td></td><td></td></tr>
#				<xsl:for-each select="./Item">
#				<xsl:variable name="pos" select="position()" />
#				<xsl:variable name="mod" select="($pos mod 2)" />
#          <xsl:choose>
#            <xsl:when test="@name='State'">
#              <tr>
#                <td>
#                  <xsl:value-of select="@name"/>
#                </td>
#                <td colspan="4">
#                  <xsl:choose>
#                    <xsl:when test=". = 'Online'">
#                      <v:group class="vmlimage" style="width:14px;height:14px;vertical-align:middle" coordsize="100,100" title="Memory Dump">
#                        <v:roundrect class="vmlimage" arcsize="20" style="width:100;height:100;z-index:0" fillcolor="#00D700" strokecolor="#66665B" />
#                        <v:line class="vmlimage" style="z-index:2" from="50,50" to="50,85" strokecolor="white" strokeweight="3px" />
#                        <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="white" strokecolor="white">
#                          <v:path v="m 50,15 l 75,60 25,60 x e" />
#                        </v:shape>
#                      </v:group>
#                      <xsl:text>&#160;</xsl:text>
#                    </xsl:when>
#                    <xsl:when test=". = 'Offline'">
#                      <v:group class="vmlimage" style="width:14px;height:14px;vertical-align:middle" coordsize="100,100" title="Memory Dump">
#                        <v:roundrect class="vmlimage" arcsize="20" style="width:100;height:100;z-index:0" fillcolor="#EC0000" strokecolor="#66665B" />
#                        <v:line class="vmlimage" style="z-index:2" from="50,15" to="50,60" strokecolor="white" strokeweight="3px" />
#                        <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="white" strokecolor="white">
#                          <v:path v="m 50,85 l 75,60 25,60 x e" />
#                        </v:shape>
#                      </v:group>
#                      <xsl:text>&#160;</xsl:text>
#                    </xsl:when>
#                  </xsl:choose>
#                  <xsl:value-of disable-output-escaping="yes" select="."/>
#                </td>
#                <td></td>
#              </tr>
#            </xsl:when>
#            <xsl:otherwise>
#              <tr>
#                <td>
#                  <xsl:value-of select="@name"/>
#                </td>
#                <td colspan="4">
#                  <xsl:value-of disable-output-escaping="yes" select="."/>
#                </td>
#                <td></td>
#              </tr>
#            </xsl:otherwise>
#          </xsl:choose>
#				</xsl:for-each>
#				</table>
#			</div></div>
#					</div>
#		</xsl:for-each>
#
#    </div></div>
#	<div class="filler"></div>
#
#	</xsl:for-each>
#
#</body>
#</html>
#</xsl:template>
#</xsl:stylesheet>
}


# SIG # Begin signature block
# MIInwQYJKoZIhvcNAQcCoIInsjCCJ64CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDriSf1cDNgo5at
# +nJwjWJVnecpOX4nvbusfqeilDbc4KCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGaEwghmdAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIG4ouGQA5x7FgY1PBi4IMVzq
# K/FgkTHVXHSM4CBwG9nPMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQBkDurfsvaUwCpuVIoCeYDOG4aI2upIoe0c25w33rLGUbcvIJ4GGVPi
# SkEXd7Jr4zlOsu0+rfAO59DoxEEvlfyrkxG9ztVRakFWG7K4jVu9NqCzYiBQclpM
# 6NUrCkV/RfpheGzpTSR1r33iQrXWrnv0c2RuY6FfVdv8o23Kf5Fc5+uASQWe+e2o
# cbv+ZSI7GReCrpUAid7XZdGoYa5sjD/JZPJCLSRVbLqDY+2kX1XB8Tg01ck3TxoO
# TFdIZNqJFHqSSpATnbAn771CS8/zo+PfIPUhDpC4Rup8cf5JtYLGlPh4FFPNqaAR
# xWVD3MVkL0hEe4irKCX94q2aIDfEnfCIoYIXKTCCFyUGCisGAQQBgjcDAwExghcV
# MIIXEQYJKoZIhvcNAQcCoIIXAjCCFv4CAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEID4LPuUD1waBW2rv08ZuRSDCDyDFvS1/YMCIVPKfEr6PAgZj5Yvj
# 1c0YEzIwMjMwMjIwMTUwMDI0LjMxMVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046M0JENC00QjgwLTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF4MIIHJzCCBQ+gAwIBAgITMwAAAbT7gAhEBdIt+gABAAABtDAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MjA5MjAyMDIyMDlaFw0yMzEyMTQyMDIyMDlaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNCRDQt
# NEI4MC02OUMzMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtEemnmUHMkIfvOiu27K8
# 6ZbwWhksGwV72Dl1uGdqr2pKm+mfzoT+Yngkq9aLEf+XDtADyA+2KIZU0iO8WG79
# eJjzz29flZpBKbKg8xl2P3O9drleuQw3TnNfNN4+QIgjMXpE3txPF7M7IRLKZMiO
# t3FfkFWVmiXJAA7E3OIwJgphg09th3Tvzp8MT8+HOtG3bdrRd/y2u8VrQsQTLZiV
# wTZ6qDYKNT8PQZl7xFrSSO3QzXa91LipZnYOl3siGJDCee1Ba7X1i13dQFHxKl5F
# f4JzDduOBZ85e2VrpyFy1a3ayGUzBrIw59jhMbjIw9YVcQt9kUWntyCmNk15WybC
# S+hXpEDDLVj1X5W9snmoW1qu03+unprQjWQaVuO7BfcvQdNVdyKSqAeKy1eT2Hcc
# 5n1aAVeXFm6sbVJmZzPQEQR3Jr7W8YcTjkqC5hT2qrYuIcYGOf3Pj4OqdXm1Qqhu
# wtskxviv7yy3Z+PxJpxKx+2e6zGRaoQmIlLfg/a42XNVHTf6Wzr5k7Q1w7v0uA/s
# FsgyKmI7HzKHX08xDDSmJooXA5btD6B0lx/Lqs6Qb4KthnA7N2IEdJ5sjMIhyHZw
# Br7fzDskU/+Sgp2UnfqrN1Vda/gb+pmlbJwi8MphvElYzjT7PZK2Dm4eorcjx7T2
# QVe3EIelLuGbxzybblZoRTkCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBTLRIXl8ZS4
# Opy7Eii3Tt44zDLZfjAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAEtEPBYwpt4Ji
# oSq0joGzwqYX6SoNH7YbqpgArdlnrdt6u3ukKREluKEVqS2XajXxx0UkXGc4Xi9d
# p2bSxpuyQnTkq+IQwkg7p1dKrwAa2vdmaNzz3mrSaeUEu40yCThHwquQkweoG4eq
# RRZe19OtVSmDDNC3ZQ6Ig0qz79vivXgy5dFWk4npxA5LxSGR4wBaXaIuVhoEa06v
# d/9/2YsQ99bCiR7SxJRt1XrQ5kJGHUi0Fhgz158qvXgfmq7qNqfqfTSmsQRrtbe4
# Zv/X+qPo/l6ae+SrLkcjRfr0ONV0vFVuNKx6Cb90D5LgNpc9x8V/qIHEr+JXbWXW
# 6mARVVqNQCmXlVHjTBjhcXwSmadR1OotcN/sKp2EOM9JPYr86O9Y/JAZC9zug9ql
# jKTroZTfYA7LIdcmPr69u1FSD/6ivL6HRHZd/k2EL7FtZwzNcRRdFF/VgpkOxHIf
# qvjXambwoMoT+vtGTtqgoruhhSk0bM1F/pBpi/nPZtVNLGTNaK8Wt6kscbC9G6f0
# 9gz/wBBJOBmvTLPOOT/3taCGSoJoDABWnK+De5pie4KX8BxxKQbJvxz7vRsVJ5R6
# mGx+Bvav5AjsxvZZw6eQmkI0vPRckxL9TCVCfWS0uyIKmyo6TdosnbBO/osre7r0
# jS9AH8spEqVlhFcpQNfOg/CvdS2xNVMwggdxMIIFWaADAgECAhMzAAAAFcXna54C
# m0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMy
# MjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51
# yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY
# 6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9
# cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN
# 7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDua
# Rr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74
# kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2
# K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5
# TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZk
# i1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9Q
# BXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3Pmri
# Lq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUC
# BBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9y
# eS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUA
# YgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
# 1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIw
# MTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/yp
# b+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulm
# ZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM
# 9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECW
# OKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4
# FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3Uw
# xTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPX
# fx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVX
# VAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGC
# onsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU
# 5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEG
# ahC0HVUzWLOhcGbyoYIC1DCCAj0CAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjNCRDQtNEI4MC02OUMzMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBlnNiQ85uX9nN4KRJt/gHkJx4JCKCBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA553hojAiGA8yMDIzMDIyMDIwMTAxMFoYDzIwMjMwMjIxMjAxMDEwWjB0MDoG
# CisGAQQBhFkKBAExLDAqMAoCBQDnneGiAgEAMAcCAQACAgYkMAcCAQACAhKPMAoC
# BQDnnzMiAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEA
# AgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEANKAVvT9uB9REC+hq
# Amhnv7/EyVjuwdoVJCDKceLgycKC+XQgLbl7f09K8mD87cb8sEPTeA1YzbDnbxuj
# ZbUiDBOO1gPMGooVnMl/md8u1IdnirhGtr3lJjYdss4jggrgZGkBBh2ipQgn9I8u
# YVglpBobjOZKky6EJ19vhVvqAqMxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAbT7gAhEBdIt+gABAAABtDANBglghkgBZQME
# AgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJ
# BDEiBCCamwHNr2yAFO0Zx3d7BFGkVoupOY3NP9/rHPR92q+l9zCB+gYLKoZIhvcN
# AQkQAi8xgeowgecwgeQwgb0EINPI93vmozBwBlFxvfr/rElreFPR4ux7vXKx2ni3
# AfcGMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAG0
# +4AIRAXSLfoAAQAAAbQwIgQgQVu0CYhlCBgSsh7M2STbE2ojFmBAmsogLXp0d75N
# ahgwDQYJKoZIhvcNAQELBQAEggIAQOT36IK9F3kgoyA+LDVktdUkc3xjGkUqASqL
# v3ecYALqi+vIL7b3tleQIZpHfK/+J3U8NvFuHSZ5Qh/H69gO7z3CAdzwNJtYT8QE
# xPHuJ6i7WtfNAcjTmKS4DWK6sHo3RKrF55rmJltEziOBMvMUqVXaOpLxDDOlj9KY
# qDBT9ijpHzo2eqT4Bs5WpmDaPKX8GH/Z5i8cbu+FOBa3F3C7c8Va0s0GlrAAju16
# rkorCk5pQzDCkMOKi7mfrciwq7NH/SSqJyS1OZuzMeCiKYpulTTPdSUd/asFK3a4
# 9YOaTMRubLMFOVB2UKip+N/wUljxhJjZCnAGlJRI7WE5KvMjDzNmHv/C5TuRnAKc
# RbjVBLdMClkeBzuLADPqNNEk6hj4juYWZmFQdQ6By9CMgou/n9Rv8i4eihl/BqGX
# IY6EuRwxFWQu5oUdLHqR9qy3WRJ/TumtzfGCqHmqFGHk3d6HgljtL+kFr/Ze/RRI
# nGSp52yH/XGIVOK8S0cvmxAtsqOawHR2Bmqat2mBDnZd0ZSGGoJ5kLFB/OPOH/sW
# hopoRKYJT5cL09hoxaT/3Pz1/St89wyFZ0qiYBegsPwkLHfeAdIoskcUicVdMcD0
# 8249klCXOnopyvVtfzkl3xlQp3RFI9OlJ+G+tav2wOOAmv6SgTpy89TKTByt2hYS
# tF1lhZ8=
# SIG # End signature block
