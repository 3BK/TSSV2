<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:output method="html" />
<xsl:key name="Updates" match="Update" use="Category" />

<xsl:template match="/eventlog">

<html dir="ltr" xmlns:v="urn:schemas-microsoft-com:vml" gpmc_reportInitialized="false">
<head>
<base target="_blank" />
<title>Storage Related Events</title>
<!-- Styles -->
<style type="text/css">
  body    { background-color:#FFFFFF; border:1px solid #666666; color:#000000; font-size:68%; font-family:MS Shell Dlg; margin:0,0,10px,0; word-break:normal; word-wrap:break-word; }

  table   { font-size:100%; table-layout:fixed; width:100%; }

  td,th   { overflow:visible; text-align:left; vertical-align:top; white-space:normal; }

  .title  { background:#FFFFFF; border:none; color:#333333; display:block; height:24px; margin:0px,0px,-1px,0px; padding-top:4px; position:relative; table-layout:fixed; width:100%; z-index:5; }

  .he0_expanded    { background-color:#FEF7D6; border:1px solid #BBBBBB; color:#3333CC; cursor:hand; display:block; font-family:Verdana; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }

  .he1_expanded    { background-color:#D9E3EA; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }

  .he4_expanded { background-color:#84A5BB; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; font-weight:bold; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }

  .he1old { background-color:#A0BACB; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }

  .he1    { background-color:#FEF7D6; border:1px solid #BBBBBB; color:#3333CC; cursor:hand; display:block; font-family:Verdana; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }

  .he2    { background-color:#C0D2DE; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:20px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }

  .he3    { background-color:#D9E3EA; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:30px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }

  .he4    { background-color:#E8E8E8; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }

  .he4h   { background-color:#E8E8E8; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:45px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }

  .he4i   { background-color:#F9F9F9; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; margin-bottom:-1px; margin-left:15px; margin-right:0px; padding-bottom:5px; padding-left:12px; padding-top:4px; position:relative; width:100%; }

  .he5    { background-color:#E8E8E8; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:50px; margin-right:0px; padding-left:11px; padding-right:5em; padding-top:4px; position:relative; width:100%; }

  .he5h   { background-color:#E8E8E8; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; padding-right:5em; padding-top:4px; margin-bottom:-1px; margin-left:55px; margin-right:0px; position:relative; width:100%; }

  .he5i   { background-color:#F9F9F9; border:1px solid #BBBBBB; color:#000000; display:block; font-family:MS Shell Dlg; font-size:100%; margin-bottom:-1px; margin-left:55px; margin-right:0px; padding-left:21px; padding-bottom:5px; padding-top: 4px; position:relative; width:100%; }

  DIV .expando { color:#000000; text-decoration:none; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:normal; position:absolute; right:10px; text-decoration:underline; z-index: 0; }

  .he0 .expando { font-size:100%; }

  .info, .info0th, .info3, .info4, .disalign, .infoqfe { line-height:1.6em; padding:0px,0px,0px,0px; margin:0px,0px,0px,0px; }

  .disalign TD                      { padding-bottom:5px; padding-right:10px; }

  .info5filename                    { padding-right:10px; width:30%; border-bottom:1px solid #CCCCCC; padding-right:10px;}

  .info0th                          { padding-right:10px; width:12%; border-bottom:1px solid #CCCCCC; padding-right:10px;}

  .info TD                          { padding-right:10px; width:50%; }

  .infoqfe                          { table-layout:auto; }

  .infoqfe TD, .infoqfe TH          { padding-right:10px;}

  .info3 TD                         { padding-right:10px; width:33%; }

  .info4 TD, .info4 TH              { padding-right:10px; width:25%; }

  .info TH, .info0th, .info3 TH, .info4 TH, .disalign TH, .infoqfe TH { border-bottom:1px solid #CCCCCC; padding-right:10px; }

  .subtable, .subtable3             { border:1px solid #CCCCCC; margin-left:0px; background:#FFFFFF; margin-bottom:10px; }

  .subtable TD, .subtable3 TD       { padding-left:10px; padding-right:5px; padding-top:3px; padding-bottom:3px; line-height:1.1em; width:10%; }

  .subtable TH, .subtable3 TH       { border-bottom:1px solid #CCCCCC; font-weight:normal; padding-left:10px; line-height:1.6em;  }

  .subtable .footnote               { border-top:1px solid #CCCCCC; }

  .OrangeFont				          {color: #FF9900; font-size:160%; font-weight:900; cursor:default; }
  .lines0                           {background-color: #F5F5F5;}
  .lines1                           {background-color: #F9F9F9;}

  .rawdata {
  font-family: Consolas, "Courier New", Courier, monospace;;
  font-size: x-small;
  background-color: #F4F4F4;
  }


  .subtable3 .footnote, .subtable .footnote { border-top:1px solid #CCCCCC; }

  .subtable_frame     { background:#D9E3EA; border:1px solid #CCCCCC; margin-bottom:10px; margin-left:15px; }

  .subtable_frame TD  { line-height:1.1em; padding-bottom:3px; padding-left:10px; padding-right:15px; padding-top:3px; }

  .subtable_frame TH  { border-bottom:1px solid #CCCCCC; font-weight:normal; padding-left:10px; line-height:1.6em; }

  .subtableInnerHead { border-bottom:1px solid #CCCCCC; border-top:1px solid #CCCCCC; }

  .explainlink            { color:#000000; text-decoration:none; cursor:hand; }

  .explainlink:hover      { color:#0000FF; text-decoration:underline; }

  .spacer { background:transparent; border:1px solid #BBBBBB; color:#FFFFFF; display:block; font-family:MS Shell Dlg; font-size:100%; height:10px; margin-bottom:-1px; margin-left:43px; margin-right:0px; padding-top: 4px; position:relative; }

  .filler { background:transparent; border:none; color:#FFFFFF; display:block; font:100% MS Shell Dlg; line-height:8px; margin-bottom:-1px; margin-left:43px; margin-right:0px; padding-top:4px; position:relative; }

  .container { display:block; position:relative; }

  .rsopheader { background-color:#A0BACB; border-bottom:1px solid black; color:#333333; font-family:MS Shell Dlg; font-size:130%; font-weight:bold; padding-bottom:5px; text-align:center; }

  .rsopname { color:#333333; font-family:MS Shell Dlg; font-size:130%; font-weight:bold; padding-left:11px; }

  .gponame{ color:#333333; font-family:MS Shell Dlg; font-size:130%; font-weight:bold; padding-left:11px; }

  .gpotype{ color:#333333; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; padding-left:11px; }

  #uri    { color:#333333; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; }

  #dtstamp{ color:#333333; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; text-align:left; width:30%; }

  #objshowhide { color:#000000; cursor:hand; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; margin-right:0px; padding-right:10px; text-align:right; text-decoration:underline; z-index:2; word-wrap:normal; }

  #gposummary { display:block; }

  #gpoinformation { display:block; }



  @media print {

  #objshowhide{ display:none; }

  body    { color:#000000; border:1px solid #000000; }

  .title  { color:#000000; border:1px solid #000000; }

  .he0_expanded    { color:#000000; border:1px solid #000000; }

  .he1_expanded    { color:#000000; border:1px solid #000000; }

  .he1    { color:#000000; border:1px solid #000000; }

  .he2    { color:#000000; background:#EEEEEE; border:1px solid #000000; }

  .he3    { color:#000000; border:1px solid #000000; }

  .he4    { color:#000000; border:1px solid #000000; }

  .he4h   { color:#000000; border:1px solid #000000; }

  .he4i   { color:#000000; border:1px solid #000000; }

  .he5    { color:#000000; border:1px solid #000000; }

  .he5h   { color:#000000; border:1px solid #000000; }

  .he5i   { color:#000000; border:1px solid #000000; }

  }

  v\:* {behavior:url(#default#VML);}

</style>
<!-- Script 1 -->

<script language="vbscript" type="text/vbscript">
<![CDATA[
<!--
'================================================================================
' String "strShowHide(0/1)"
' 0 = Hide all mode.
' 1 = Show all mode.
strShowHide = 1

'Localized strings
strShow = "show"
strHide = "hide"
strShowAll = "show all"
strHideAll = "hide all"
strShown = "shown"
strHidden = "hidden"
strExpandoNumPixelsFromEdge = "10px"


Function IsSectionHeader(obj)
    IsSectionHeader = (obj.className = "he0_expanded") Or (obj.className = "he1_expanded") Or (obj.className = "he1") Or (obj.className = "he2") Or (obj.className = "he3") Or (obj.className = "he4") Or (obj.className = "he4h") Or (obj.className = "he5") Or (obj.className = "he5h")  or (obj.className = "he4_expanded")
End Function


Function IsSectionExpandedByDefault(objHeader)
    IsSectionExpandedByDefault = (Right(objHeader.className, Len("_expanded")) = "_expanded")
End Function


' strState must be show | hide | toggle
Sub SetSectionState(objHeader, strState)
    ' Get the container object for the section.  It's the first one after the header obj.

    i = objHeader.sourceIndex
    Set all = objHeader.parentElement.document.all
    While (all(i).className <> "container")
        i = i + 1
    Wend

    Set objContainer = all(i)

    If strState = "toggle" Then
        If objContainer.style.display = "none" Then
            SetSectionState objHeader, "show"
        Else
            SetSectionState objHeader, "hide"
        End If

    Else
        Set objExpando = objHeader.children(1)

        If strState = "show" Then
            objContainer.style.display = "block"
            objExpando.innerText = strHide

        ElseIf strState = "hide" Then
            objContainer.style.display = "none"
            objExpando.innerText = strShow
        End If
    End If
End Sub


Sub ShowSection(objHeader)
    SetSectionState objHeader, "show"
End Sub


Sub HideSection(objHeader)
    SetSectionState objHeader, "hide"
End Sub


Sub ToggleSection(objHeader)
    SetSectionState objHeader, "toggle"
End Sub


'================================================================================
' When user clicks anywhere in the document body, determine if user is clicking
' on a header element.
'================================================================================
Function document_onclick()
    Set strsrc    = window.event.srcElement

    While (strsrc.className = "sectionTitle" Or strsrc.className = "expando" Or strsrc.className = "vmlimage")
        Set strsrc = strsrc.parentElement
    Wend

    ' Only handle clicks on headers.
    If Not IsSectionHeader(strsrc) Then Exit Function

    ToggleSection strsrc

    window.event.returnValue = False
End Function

'================================================================================
' link at the top of the page to collapse/expand all collapsable elements
'================================================================================
Function objshowhide_onClick()
    Set objBody = document.body.all
    Select Case strShowHide
        Case 0
            strShowHide = 1
            objshowhide.innerText = strShowAll
            For Each obji In objBody
                If IsSectionHeader(obji) Then
                    HideSection obji
                End If
            Next
        Case 1
            strShowHide = 0
            objshowhide.innerText = strHideAll
            For Each obji In objBody
                If IsSectionHeader(obji) Then
                    ShowSection obji
                End If
            Next
    End Select
End Function

'================================================================================
' onload collapse all except the first two levels of headers (he0, he1)
'================================================================================
Function window_onload()
    ' Only initialize once.  The UI may reinsert a report into the webbrowser control,
    ' firing onLoad multiple times.
    If UCase(document.documentElement.getAttribute("gpmc_reportInitialized")) <> "TRUE" Then

        ' Set text direction
        Call fDetDir(UCase(document.dir))

        ' Initialize sections to default expanded/collapsed state.
        Set objBody = document.body.all

        For Each obji in objBody
            If IsSectionHeader(obji) Then
                If IsSectionExpandedByDefault(obji) Then
                    ShowSection obji
                Else
                    HideSection obji
                End If
            End If
        Next

        objshowhide.innerText = strShowAll

        document.documentElement.setAttribute "gpmc_reportInitialized", "true"
    End If
End Function




'================================================================================
' When direction (LTR/RTL) changes, change adjust for readability
'================================================================================
Function document_onPropertyChange()
    If window.event.propertyName = "dir" Then
        Call fDetDir(UCase(document.dir))
    End If
End Function
Function fDetDir(strDir)
    strDir = UCase(strDir)
    Select Case strDir
        Case "LTR"
            Set colRules = document.styleSheets(0).rules
            For i = 0 To colRules.length -1
                Set nug = colRules.item(i)
                strClass = nug.selectorText
                If nug.style.textAlign = "right" Then
                    nug.style.textAlign = "left"
                End If
                Select Case strClass
                    Case "DIV .expando"
                        nug.style.Left = ""
                        nug.style.right = strExpandoNumPixelsFromEdge
                    Case "#objshowhide"
                        nug.style.textAlign = "right"
                End Select
            Next
        Case "RTL"
            Set colRules = document.styleSheets(0).rules
            For i = 0 To colRules.length -1
                Set nug = colRules.item(i)
                strClass = nug.selectorText
                If nug.style.textAlign = "left" Then
                    nug.style.textAlign = "right"
                End If
                Select Case strClass
                    Case "DIV .expando"
                        nug.style.Left = strExpandoNumPixelsFromEdge
                        nug.style.right = ""
                    Case "#objshowhide"
                        nug.style.textAlign = "left"
                End Select
            Next
    End Select
End Function

'================================================================================
'When printing reports, if a given section is expanded, let's says "shown" (instead of "hide" in the UI).
'================================================================================
Function window_onbeforeprint()
    For Each obji In document.all
        If obji.className = "expando" Then
            If obji.innerText = strHide Then obji.innerText = strShown
            If obji.innerText = strShow Then obji.innerText = strHidden
        End If
    Next
End Function

'================================================================================
'If a section is collapsed, change to "hidden" in the printout (instead of "show").
'================================================================================
Function window_onafterprint()
    For Each obji In document.all
        If obji.className = "expando" Then
            If obji.innerText = strShown Then obji.innerText = strHide
            If obji.innerText = strHidden Then obji.innerText = strShow
        End If
    Next
End Function

'================================================================================
' Adding keypress support for accessibility
'================================================================================
Function document_onKeyPress()
    If window.event.keyCode = "32" Or window.event.keyCode = "13" Or window.event.keyCode = "10" Then 'space bar (32) or carriage return (13) or line feed (10)
        If window.event.srcElement.className = "expando" Then Call document_onclick() : window.event.returnValue = false
        If window.event.srcElement.className = "sectionTitle" Then Call document_onclick() : window.event.returnValue = false
        If window.event.srcElement.id = "objshowhide" Then Call objshowhide_onClick() : window.event.returnValue = false
    End If
End Function

-->
]]>
</script>

<!-- Script 2 -->

<script language="javascript"><![CDATA[
<!--
function getExplainWindowTitle()
{
        return document.getElementById("explainText_windowTitle").innerHTML;
}

function getExplainWindowStyles()
{
        return document.getElementById("explainText_windowStyles").innerHTML;
}

function getExplainWindowSettingPathLabel()
{
        return document.getElementById("explainText_settingPathLabel").innerHTML;
}

function getExplainWindowExplainTextLabel()
{
        return document.getElementById("explainText_explainTextLabel").innerHTML;
}

function getExplainWindowPrintButton()
{
        return document.getElementById("explainText_printButton").innerHTML;
}

function getExplainWindowCloseButton()
{
        return document.getElementById("explainText_closeButton").innerHTML;
}

function getNoExplainTextAvailable()
{
        return document.getElementById("explainText_noExplainTextAvailable").innerHTML;
}

function getExplainWindowSupportedLabel()
{
        return document.getElementById("explainText_supportedLabel").innerHTML;
}

function getNoSupportedTextAvailable()
{
        return document.getElementById("explainText_noSupportedTextAvailable").innerHTML;
}

function showExplainText(srcElement)
{
    var strSettingName = srcElement.getAttribute("gpmc_settingName");
    var strSettingPath = srcElement.getAttribute("gpmc_settingPath");
    var strSettingDescription = srcElement.getAttribute("gpmc_settingDescription");

    if (strSettingDescription == "")
    {
                strSettingDescription = getNoExplainTextAvailable();
    }

    var strSupported = srcElement.getAttribute("gpmc_supported");

    if (strSupported == "")
    {
        strSupported = getNoSupportedTextAvailable();
    }

    var strHtml = "<html>\n";
    strHtml += "<head>\n";
    strHtml += "<title>" + getExplainWindowTitle() + "</title>\n";
    strHtml += "<style type='text/css'>\n" + getExplainWindowStyles() + "</style>\n";
    strHtml += "</head>\n";
    strHtml += "<body>\n";
    strHtml += "<div class='head'>" + strSettingName +"</div>\n";
    strHtml += "<div class='path'><b>" + getExplainWindowSettingPathLabel() + "</b><br/>" + strSettingPath +"</div>\n";
    strHtml += "<div class='path'><b>" + getExplainWindowSupportedLabel() + "</b><br/>" + strSupported +"</div>\n";
    strHtml += "<div class='info'>\n";
    strHtml += "<div class='hdr'>" + getExplainWindowExplainTextLabel() + "</div>\n";
    strHtml += "<div class='bdy'>" + strSettingDescription + "</div>\n";
    strHtml += "<div class='btn'>";
    strHtml += getExplainWindowPrintButton();
    strHtml += getExplainWindowCloseButton();
    strHtml += "</div></body></html>";

    var strDiagArgs = "height=360px, width=630px, status=no, toolbar=no, scrollbars=yes, resizable=yes ";
    var expWin = window.open("", "expWin", strDiagArgs);
    expWin.document.write("");
    expWin.document.close();
    expWin.document.write(strHtml);
    expWin.document.close();
    expWin.focus();

    //cancels navigation for IE.
    if(navigator.userAgent.indexOf("MSIE") > 0)
    {
        window.event.returnValue = false;
    }

    return false;
}
-->
]]>
</script>

</head>

<body>
	<table class="title" cellpadding="0" cellspacing="0">
	<tr><td colspan="2" class="rsopheader">
    Storage related events for <xsl:value-of select="//event/@computer"/>
  </td>
    <td class="rsopheader">
	<div id="objshowhide" tabindex="0"></div>
    </td>
  </tr>
	</table>
	<div class="filler"></div>

	<div class="he0_expanded"><span class="sectionTitle" tabindex="0">Storage Related Events on System Log</span><a class="expando" href="#"></a></div>

		<div class="container">
      <div class="he4i">
        <xsl:for-each select="event">
          <xsl:sort select="@time" order="descending" data-type="number"/>
          <xsl:variable name="pos" select="position()" />
          <xsl:variable name="mod" select="($pos mod 2)" />
          <div class="he1_expanded">
            <span class="sectionTitle" tabindex="0">
              <table>
                <tr>
                  <td style="white-space: nowrap;">
                    <xsl:choose>
                      <xsl:when test="@type = 'information'">
                        <v:group id="Inf1" class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Information">
                          <v:oval class="vmlimage" style="width:100;height:100;z-index:0" fillcolor="#336699" strokecolor="black" />
                          <v:line class="vmlimage" style="z-index:1" from="50,15" to="50,25" strokecolor="white" strokeweight="3px" />
                          <v:line class="vmlimage" style="z-index:2" from="50,35" to="50,80" strokecolor="white" strokeweight="3px" />
                        </v:group>
                      </xsl:when>
                      <xsl:when test="@type = 'warning'">
                        <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Warning">
                          <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="yellow" strokecolor="black">
                            <v:path v="m 50,0 l 0,99 99,99 x e" />
                          </v:shape>
                          <v:rect class="vmlimage" style="top:35; left:45; width:10; height:35; z-index:1" fillcolor="black" strokecolor="black">
                          </v:rect>
                          <v:rect class="vmlimage" style="top:85; left:45; width:10; height:5; z-index:1" fillcolor="black" strokecolor="black">
                          </v:rect>
                        </v:group>
                      </xsl:when>
                      <xsl:when test="@type = 'error'">
                        <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Error">
                          <v:oval class="vmlimage" style='width:100;height:100;z-index:0' fillcolor="red" strokecolor="red">
                          </v:oval>
                          <v:line class="vmlimage" style="z-index:1" from="25,25" to="75,75" strokecolor="white" strokeweight="3px">
                          </v:line>
                          <v:line class="vmlimage" style="z-index:2" from="75,25" to="25,75" strokecolor="white" strokeweight="3px">
                          </v:line>
                        </v:group>
                      </xsl:when>
                    </xsl:choose>
                    Time: <b><xsl:value-of select="@time"/>
                    </b>
                  </td>
                  <td style="white-space: nowrap;">
                    ID: <b><xsl:value-of select="@id"/></b>
                  </td>
                  <td style="white-space: nowrap;">
                    Source: <b>
                      <xsl:value-of select="@source"/>
                    </b>
                  </td>
                  <td style="white-space: nowrap;">
                    Category: <b>
                      <xsl:value-of select="@category"/>
                    </b>
                  </td>
                </tr>
              </table>
            </span>
            <a class="expando" href="#"></a>
          </div>
          <div class="container">
            <div class="he4i">
              <xsl:if test="description">
                <table class="infoqfe">
                  <tr>
                    <td>
                      Computer:
                    </td>
                    <td>
                      <xsl:value-of select="@computer"/>
                    </td>
                  </tr>
                  <tr>
                    <td>
                      Description:
                    </td>
                    <td>
                      <xsl:value-of select="description"/>
                    </td>
                  </tr>
                </table>
              </xsl:if>
            <xsl:if test="IOError">
              <div>
                <div class="he4">
                  <span class="sectionTitle" tabindex="0">Event Details</span>
                  <a class="expando" href="#"></a>
                </div>
                <div class="container">
                  <div class="he4i">
                    <table cellpadding="0" class="infoqfe">
                      <xsl:if test="IOError/@Type">
                        <tr >
                          <td>IOError Type:</td>
                          <td>
                            <b>
                              <xsl:value-of select="IOError/@Type"/>
                            </b>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@DeviceNumber">
                        <tr >
                          <td>DeviceNumber:</td>
                          <td>
                            <xsl:value-of select="IOError/@DeviceNumber"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@Path">
                        <tr >
                          <td>Path:</td>
                          <td>
                            <xsl:value-of select="IOError/@Path"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@Target">
                        <tr >
                          <td>Target:</td>
                          <td>
                            <xsl:value-of select="IOError/@Target"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@Lun">
                        <tr >
                          <td>Lun:</td>
                          <td>
                            <xsl:value-of select="IOError/@Lun"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@OpCode">
                        <tr >
                          <td>OpCode:</td>
                          <td>
                            <xsl:value-of select="IOError/@OpCode"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@Paging">
                        <tr >
                          <td>Paging:</td>
                          <td>
                            <xsl:value-of select="IOError/@Paging"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@Retried">
                        <tr >
                          <td>Retried:</td>
                          <td>
                            <xsl:value-of select="IOError/@Retried"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@Unhandled">
                        <tr >
                          <td>Unhandled:</td>
                          <td>
                            <xsl:value-of select="IOError/@Unhandled"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@PortNumber">
                        <tr >
                          <td>PortNumber:</td>
                          <td>
                            <xsl:value-of select="IOError/@PortNumber"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@TLogicalBlockAddressype">
                        <tr>
                          <td>LogicalBlockAddress:</td>
                          <td>
                            <xsl:value-of select="IOError/@LogicalBlockAddress"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@NumSectors">
                        <tr >
                          <td>NumSectors:</td>
                          <td>
                            <xsl:value-of select="IOError/@NumSectors"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@SenseCode">
                        <tr >
                          <td>SenseCode:</td>
                          <td>
                            <xsl:value-of select="IOError/@SenseCode"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@AdditionalSenseCode">
                        <tr >
                          <td>AdditionalSenseCode:</td>
                          <td>
                            <xsl:value-of select="IOError/@AdditionalSenseCode"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@AdditionalSenseCodeQualifier">
                        <tr >
                          <td>AdditionalSenseCodeQualifier:</td>
                          <td>
                            <xsl:value-of select="IOError/@AdditionalSenseCodeQualifier"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@EndOfMedia">
                        <tr >
                          <td>EndOfMedia:</td>
                          <td>
                            <xsl:value-of select="IOError/@EndOfMedia"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@FileMark">
                        <tr >
                          <td>FileMark:</td>
                          <td>
                            <xsl:value-of select="IOError/@FileMark"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@IncorrectLength">
                        <tr >
                          <td>IncorrectLength:</td>
                          <td>
                            <xsl:value-of select="IOError/@IncorrectLength"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@Valid">
                        <tr >
                          <td>Valid:</td>
                          <td>
                            <xsl:value-of select="IOError/@Valid"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@SegmentNumber">
                        <tr >
                          <td>SegmentNumber:</td>
                          <td>
                            <xsl:value-of select="IOError/@SegmentNumber"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@ErrorCode">
                        <tr >
                          <td>ErrorCode:</td>
                          <td>
                            <xsl:value-of select="IOError/@ErrorCode"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@FieldReplacableUnitCode">
                        <tr >
                          <td>FieldReplacableUnitCode:</td>
                          <td>
                            <xsl:value-of select="IOError/@FieldReplacableUnitCode"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@CommandSpecificInformation">
                        <tr >
                          <td>CommandSpecificInformation:</td>
                          <td>
                            <xsl:value-of select="IOError/@CommandSpecificInformation"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@SenseKeySpecific">
                        <tr >
                          <td>SenseKeySpecific:</td>
                          <td>
                            <xsl:value-of select="IOError/@SenseKeySpecific"/>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@SRBStatus">
                        <tr >
                          <td>SRBStatus:</td>
                          <td>
                            <b>
                              <xsl:value-of select="IOError/@SRBStatus"/>
                            </b>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@SCSIStatus">
                        <tr >
                          <td>SCSIStatus:</td>
                          <td>
                            <b>
                            <xsl:value-of select="IOError/@SCSIStatus"/>
                            </b>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="IOError/@NTStatus">
                        <tr >
                          <td>NTStatus:</td>
                          <td>
                            <b>
                            <xsl:value-of select="IOError/@NTStatus"/>
                            </b>
                          </td>
                        </tr>
                      </xsl:if>
                      <xsl:if test="binary">
                        <tr >
                          <td colspan="2">Raw Binary Data:</td>
                        </tr >
                        <tr>
                          <td colspan="2" class="rawdata">
                            <xsl:value-of select="binary"/>
                          </td>
                        </tr>
                      </xsl:if>
                    </table>
                  </div>
                </div>
              </div>
            </xsl:if>
          </div>
      </div>
    </xsl:for-each>
		</div></div>

  <div class="filler"></div>

</body>
</html>
</xsl:template>
</xsl:stylesheet>