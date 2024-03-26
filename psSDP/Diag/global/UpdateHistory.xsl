<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:output method="html" />
<xsl:key name="Updates" match="Update" use="Category" />

<xsl:template match="/Root">

<html dir="ltr" xmlns:v="urn:schemas-microsoft-com:vml" reportInitialized="false">
  <meta http-equiv="X-UA-Compatible" content="IE=EmulateIE8" />
<head>
<base target="_blank" />
<title><xsl:value-of select="Updates/Title"/> Update History</title>
<!-- Styles -->
<style type="text/css">
  body    { background-color:#FFFFFF; border:1px solid #666666; color:#000000; font-size:68%; font-family:MS Shell Dlg; margin:0,0,10px,0; word-break:normal; word-wrap:break-word; }

  table   { font-size:100%; table-layout:fixed; width:100%; }

  td,th   { overflow:visible; text-align:left; vertical-align:top; white-space:normal; }

  .title  { background:#FFFFFF; border:none; color:#333333; display:block; height:24px; margin:0px,0px,-1px,0px; padding-top:4px; position:relative; table-layout:fixed; width:100%; z-index:5; }

  .header1    { background-color:#FEF7D6; border:1px solid #BBBBBB; color:#3333CC; cursor:hand; display:block; font-family:Segoe UI, MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:18px; padding-right:5em; padding-top:4px; position:relative; width:100%;
  filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=1,StartColorStr='#FEF7D6',EndColorStr='white');}

  .he4i   { background-color:#F9F9F9; border:1px solid #BBBBBB; color:#000000; display:block; font-family:Segoe UI, MS Shell Dlg; fnt-size:100%; margin-bottom:-1px; margin-top:1px; margin-left:15px; margin-right:0px; padding-bottom:5px; padding-left:12px; padding-top:4px; position:relative; width:100%; }

  DIV .expando { color:#000000; text-decoration:none; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:normal; position:absolute; right:10px; text-decoration:underline; z-index: 0; }

  .he0 .expando { font-size:100%; }

  .info, .info0th, .info3, .info4, .disalign, .infoqfe { line-height:1.6em; padding:0px,0px,0px,0px; margin:0px,0px,0px,0px; }

  .disalign TD                      { padding-bottom:5px; padding-right:10px; }

  .info5filename                    { padding-right:10px; width:30%; border-bottom:1px solid #CCCCCC; padding-right:10px;}

  .info0th                          { padding-right:10px; width:2%; border-bottom:1px solid #CCCCCC; padding-right:10px;}
  .info1th                          { padding-right:10px; width:10%; border-bottom:1px solid #CCCCCC; padding-right:10px;}

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

  .lines0                           {background-color: #F5F5F5;}
  .lines1                           {background-color: #F9F9F9;}
  .lineserr                         {background-color: #FFFFDD; color:gray}

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

  .rsopheader { background-color:#A0BACB; border-bottom:1px solid black; color:#333333; font-family:MS Shell Dlg; font-size:130%; font-weight:bold; padding-bottom:5px; text-align:center;
  filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=0,StartColorStr='#FFFFFF',EndColorStr='#A0BACB')}

  .rsopname { color:#333333; font-family:MS Shell Dlg; font-size:130%; font-weight:bold; padding-left:11px; }

  #uri    { color:#333333; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; }

  #dtstamp{ color:#333333; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; text-align:left; width:30%; }

  #objshowhide { color:#000000; cursor:hand; font-family:MS Shell Dlg; font-size:100%; font-weight:bold; margin-right:0px; padding-right:10px; text-align:right; text-decoration:underline; z-index:2; word-wrap:normal; }

  v\:* {behavior:url(#default#VML);}

</style>
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
strExpandoNumPixelsFromEdge = "5px"


Function IsSectionHeader(obj)
    IsSectionHeader = (Left(obj.className, 6) = "header")
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
        x = 0
        bFound = false
        while ((not bFound) and (x < objHeader.children.length))
          x = x + 1
          if x < objHeader.children.length then
            Set objExpando = objHeader.children(x)
            if objExpando.className = "expando" then bFound = true
          end if
        wend

        If strState = "show" Then
            objContainer.style.display = "block"
            objExpando.innerHTML =  "<v:group class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:5px;height:5px;vertical-align:middle" & chr(34) & " coordsize=" & chr(34) & "100,100" & chr(34) & " title=" & chr(34) & "Collapse" & chr(34) & ">" &_
                                    "  <v:shape class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:100; height:100; z-index:0" & chr(34) & " fillcolor=" & chr(34) & "#808080" & chr(34) & " strokecolor=" & chr(34) & "#303030" & chr(34) & ">" &_
                                    "    <v:path v=" & chr(34) & "m 100,0 l 0,99 99,99 x e" & chr(34) & " />" &_
                                    "  </v:shape>" &_
                                    "</v:group>"
        ElseIf strState = "hide" Then
            objContainer.style.display = "none"
            objExpando.innerHTML = "<v:group class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:9px;height:9px;vertical-align:middle" & chr(34) & " coordsize=" & chr(34) & "100,100" & chr(34) & " title=" & chr(34) & "Expand" & chr(34) & ">" &_
                                   "  <v:shape class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:100; height:100; z-index:0" & chr(34) & " fillcolor=" & chr(34) & "white" & chr(34) & " strokecolor=" & chr(34) & "#A0A0A0" & chr(34) & " name='Test'>" &_
                                   "    <v:path v=" & chr(34) & "m 0,0 l 0,99 50,50 x e" & chr(34) & " />" &_
                                   "  </v:shape>" &_
                                   "</v:group>"
        end if
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
    If UCase(document.documentElement.getAttribute("reportInitialized")) <> "TRUE" Then

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

        document.documentElement.setAttribute "reportInitialized", "TRUE"
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
                        nug.style.Left = strExpandoNumPixelsFromEdge
                        nug.style.right = ""
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
                        nug.style.textAlign = "right"
                End Select
            Next
    End Select
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
  
</head>

<body>
	<table class="title" cellpadding="0" cellspacing="0">
	<tr><td colspan="2" class="rsopheader">Update History for <xsl:value-of select="Updates/Title"/></td></tr>
	<tr><td colspan="2" class="rsopname">Operating System: <xsl:value-of select="Updates/OSVersion"/></td></tr>
	<tr><td id="dtstamp">Data collected on: <xsl:value-of select="Updates/TimeField"/></td><td><div id="objshowhide" tabindex="0"></div></td></tr>
	</table>
	<div class="filler"></div>

	<xsl:variable name="ReportHasSPLevel" select="not(count(//SPLevel) = 0)"/>
  <xsl:variable name="ReportContainsUpdates" select="not(count(//Update) = 0)"/>
  <xsl:if test="$ReportContainsUpdates">
	  <xsl:for-each select="//Update[generate-id(.)=generate-id(key('Updates',Category))]">
    <xsl:sort select="SortableDate" order="descending" data-type="number"/>
    <xsl:variable name="Category" select="Category"/>
      
	  <div class="header1"><span class="sectionTitle" tabindex="0">
      <xsl:value-of select="Category"/> (<xsl:value-of select="count(//Update[Category = $Category])"/>)
    </span><a class="expando" href="#"></a></div>

		  <div class="container"><div class="he4i"><table cellpadding="0" class="infoqfe">
      <tr>
        <th class="info0th">Results</th><th class="info1th">Date</th><th class="info1th">Operation</th><th class="info1th">By</th><xsl:if test="$ReportHasSPLevel"><th class="info1th">Level</th></xsl:if><th class="info1th">Client</th><th class="info1th">ID</th><th style="width:auto">Description</th>
      </tr>

		  <xsl:for-each select="key('Updates',Category)">
		  <xsl:variable name="pos" select="position()" />
		  <xsl:variable name="mod" select="($pos mod 2)" />

        <tr>
          <td class="lines{$mod}" style="text-align: center">
            <xsl:choose>
              <xsl:when test="OperationResult = 'Completed successfully'">
                <v:group id="Inf1" class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Completed successfully">
                  <v:oval class="vmlimage" style="width:100;height:100;z-index:0" fillcolor="#009933" strokecolor="#C0C0C0" />
                </v:group>
              </xsl:when>

              <xsl:when test="OperationResult = 'In progress'">
                <v:group class="vmlimage" style="width:14px;height:14px;vertical-align:middle" coordsize="100,100" title="In progress">
                  <v:roundrect class="vmlimage" arcsize="10" style="width:100;height:100;z-index:0" fillcolor="#00FF00" strokecolor="#C0C0C0" />
                  <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="white" strokecolor="white">
                    <v:path v="m 40,25 l 75,50 40,75 x e" />
                  </v:shape>
                </v:group>
              </xsl:when>

              <xsl:when test="OperationResult = 'Operation was aborted'">
                <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Operation was aborted">
                  <v:roundrect class="vmlimage" arcsize="20" style="width:100;height:100;z-index:0" fillcolor="#290000" strokecolor="#C0C0C0" />
                  <v:line class="vmlimage" style="z-index:2" from="52,30" to="52,75" strokecolor="white" strokeweight="8px" />
                </v:group>
              </xsl:when>

              <xsl:when test="OperationResult = 'Completed with errors'">
                <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Completed with errors">
                  <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="yellow" strokecolor="#C0C0C0">
                    <v:path v="m 50,0 l 0,99 99,99 x e" />
                  </v:shape>
                  <v:rect class="vmlimage" style="top:35; left:45; width:10; height:35; z-index:1" fillcolor="black" strokecolor="black">
                  </v:rect>
                  <v:rect class="vmlimage" style="top:85; left:45; width:10; height:5; z-index:1" fillcolor="black" strokecolor="black">
                  </v:rect>
                </v:group>
              </xsl:when>

              <xsl:when test="OperationResult = 'Failed to complete'">
                <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Failed to complete">
                  <v:oval class="vmlimage" style='width:100;height:100;z-index:0' fillcolor="red" strokecolor="#C0C0C0">
                  </v:oval>
                  <v:line class="vmlimage" style="z-index:1" from="25,25" to="75,75" strokecolor="white" strokeweight="3px">
                  </v:line>
                  <v:line class="vmlimage" style="z-index:2" from="75,25" to="25,75" strokecolor="white" strokeweight="3px">
                  </v:line>
                </v:group>
              </xsl:when>

              <xsl:otherwise>
                <v:group id="Inf1" class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="{OperationResult}">
                  <v:oval class="vmlimage" style="width:100;height:100;z-index:0" fillcolor="#FF9933" strokecolor="#C0C0C0" />
                </v:group>
              </xsl:otherwise>

            </xsl:choose>
          </td>
          <td class="lines{$mod}" style="white-space: nowrap;">
            <xsl:value-of select="Date"/>
            <td class="lines{$mod}" style="white-space: nowrap">
              <xsl:value-of select="Operation"/>
            </td>
            <td class="lines{$mod}" style="white-space: nowrap;">
              <xsl:value-of select="InstalledBy"/>
            </td>
            <xsl:if test="$ReportHasSPLevel">
              <td class="lines{$mod}" style="white-space: nowrap;">
                <xsl:value-of select="SPLevel"/>
              </td>
            </xsl:if>
          </td>
          <td class="lines{$mod}" style="white-space: nowrap;">
            <xsl:value-of select="ClientID"/>
          </td>
          <td class="lines{$mod}" style="white-space: nowrap;">
            <xsl:if test="SupportLink">
              <a href="{SupportLink}">
                <xsl:value-of select="ID"/>
              </a>
            </xsl:if>
            <xsl:if test="string-length(SupportLink) = 0">
              <xsl:value-of select="ID"/>
            </xsl:if>
          </td>
          <td class="lines{$mod}">
            <xsl:if test="not (string-length(Description) = 0)">
              <span style="cursor:pointer" title="{Description}">
                <xsl:value-of select="Title"/>
              </span>
            </xsl:if>
            <xsl:if test="string-length(Description) = 0">
              <xsl:value-of select="Title"/>
            </xsl:if>
          </td>
        </tr>
        <xsl:if test="HResult">
          <tr >
            <td></td><td colspan="6" class="lineserr">Error Code: <xsl:value-of select="HResult/HEX" /> (<xsl:value-of select="HResult/Constant" />) - <xsl:value-of select="HResult/Description" /> <xsl:if test="UnmappedResultCode">[<xsl:value-of select="UnmappedResultCode" />]</xsl:if>
          </td>
          </tr>
        </xsl:if>
		  </xsl:for-each>
		  </table>
		  </div></div>
	  <div class="filler"></div>

	  </xsl:for-each>
  </xsl:if>
  <xsl:if test="not ($ReportContainsUpdates)">
    <div class="he1">
      <span class="sectionTitle" tabindex="0">
        There are no hotfixes or updates installed on this machine
      </span>
    </div>
    <div class="container"></div>
    <div class="filler"></div>
  </xsl:if>  
    
</body>
</html>
</xsl:template>
</xsl:stylesheet>