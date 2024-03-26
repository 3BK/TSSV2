<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:output method="html" />
<xsl:template match="/Objects">
<html dir="ltr" xmlns:v="urn:schemas-microsoft-com:vml" reportInitialized="false">
  <meta http-equiv="X-UA-Compatible" content="IE=EmulateIE8" />
<head>
<!-- Styles -->
  <style type="text/css">
    body    { background-color:#FFFFFF; border:1px solid #666666; color:#000000; font-size:68%; font-family:MS Shell Dlg; margin:0,0,10px,0; word-break:normal; word-wrap:break-word; }

    table   { font-size:100%; table-layout:fixed; width:100%; }

    td,th   { overflow:visible; text-align:left; vertical-align:top; white-space:normal; }

    .title  { font-family:Segoe UI, MS Shell Dlg; background:#FFFFFF; border:none; color:#333333; display:block; height:24px; margin:0px,0px,-1px,0px; padding-top:4px; position:relative; table-layout:fixed; width:100%; z-index:5; }

    .header0False_expanded { background-color:#FEF7D6; border:1px solid #BBBBBB; color:#3333CC; cursor:hand; display:block; font-family:Verdana; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:18px; padding-right:5em; padding-top:4px; position:relative; width:100%;
    filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=1,StartColorStr='#FEF7D6',EndColorStr='white');}

    .header0True_expanded { background-color:#D8D8D8; border:1px solid #BBBBBB; color:gray; cursor:hand; display:block; font-family:Verdana; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:18px; padding-right:5em; padding-top:4px; position:relative; width:100%;
    filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=1,StartColorStr='#D8D8D8',EndColorStr='white');}

    .header0_expanded   { background-color:#FEF7D6; border:1px solid #BBBBBB; color:#3333CC; cursor:hand; display:block; font-family:Verdana; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%;
    filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=1,StartColorStr='#FEF7D6',EndColorStr='white');}

    .hev    { background-color:#CCDFFF; border:1px solid #BBBBBB; color:#3333CC; display:block; font-family:Verdana; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%;
    filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=1,StartColorStr='white',EndColorStr='#CCDFFF');}
    .he4i   { background-color:#F9F9F9; border:1px solid #BBBBBB; color:#000000; display:block; font-family:Segoe UI, MS Shell Dlg; fnt-size:100%; margin-bottom:-1px; margin-top:1px; margin-left:15px; margin-right:0px; padding-bottom:5px; padding-left:12px; padding-top:4px; position:relative; width:100%; }

    DIV .expando { color:#000000; text-decoration:none; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:normal; position:absolute; left:2px; text-decoration:underline; z-index: 0; padding-top:2px;}

    .info4 TD, .info4 TH              { padding-right:10px; width:25%;}

    .infoFirstCol                     { padding-right:10px; width:20%; }
    .infoSecondCol                     { padding-right:10px; width:80%; }

    .lines0                           {background-color: #F5F5F5;}
    .lines1                           {background-color: #F9F9F9;}

    .subtable, .subtable3             { border:1px solid #CCCCCC; margin-left:0px; background:#FFFFFF; margin-bottom:10px; }

    .subtable TD, .subtable3 TD       { padding-left:10px; padding-right:5px; padding-top:3px; padding-bottom:3px; line-height:1.1em; width:10%; }

    .subtable TH, .subtable3 TH       { border-bottom:1px solid #CCCCCC; font-weight:normal; padding-left:10px; line-height:1.6em;  }

    .explainlink:hover      { color:#0000FF; text-decoration:underline; }

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
	<tr><td colspan="2" class="rsopheader"><xsl:value-of select="ReportTitle"/></td></tr>
	<tr><td colspan="2" class="rsopname">Machine name: <xsl:value-of select="Machine"/></td></tr>
	<tr><td id="dtstamp">Data collected on: <xsl:value-of select="TimeField"/></td><td><div id="objshowhide" tabindex="0"></div></td></tr>
	</table>
	<div class="filler"></div>

  <div class="hev">
    <span class="sectionTitle" tabindex="0">
      Messages
    </span>
  </div>
  <div class="filler"></div>

  <xsl:for-each select="./Object">
    <xsl:sort order="ascending" select="./Property[@Name = 'Severity'] = 'Information'" data-type="text"/>
    <xsl:sort order="ascending" select="./Property[@Name = 'Severity'] = 'Warning'" data-type="text"/>
    <xsl:sort order="ascending" select="./Property[@Name = 'Severity'] = 'Error'" data-type="text"/>
    <xsl:variable name="excluded" select="./Property[@Name='Excluded']" />
    <div class="header0{$excluded}_expanded">
      <span class="sectionTitle" tabindex="0">
        <xsl:choose>
      <xsl:when test="./Property[@Name='Severity'] = 'Error'">
        <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Error">
          <v:oval class="vmlimage" style='width:100;height:100;z-index:0' fillcolor="red" strokecolor="red">
          </v:oval>
          <v:line class="vmlimage" style="z-index:1" from="25,25" to="75,75" strokecolor="white" strokeweight="3px">
          </v:line>
          <v:line class="vmlimage" style="z-index:2" from="75,25" to="25,75" strokecolor="white" strokeweight="3px">
          </v:line>
        </v:group>
        <xsl:text>&#160;</xsl:text>
      </xsl:when>
      <xsl:when test="./Property[@Name='Severity'] = 'Warning'">
        <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Warning">
          <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="yellow" strokecolor="black">
            <v:path v="m 50,0 l 0,99 99,99 x e" />
          </v:shape>
          <v:rect class="vmlimage" style="top:35; left:45; width:10; height:35; z-index:1" fillcolor="black" strokecolor="black">
          </v:rect>
          <v:rect class="vmlimage" style="top:85; left:45; width:10; height:5; z-index:1" fillcolor="black" strokecolor="black">
          </v:rect>
        </v:group>
        <xsl:text>&#160;</xsl:text>
      </xsl:when>
      <xsl:when test="./Property[@Name='Severity'] = 'Information'">
        <v:group id="Inf1" class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Information">
          <v:oval class="vmlimage" style="width:100;height:100;z-index:0" fillcolor="#336699" strokecolor="black" />
          <v:line class="vmlimage" style="z-index:1" from="50,15" to="50,25" strokecolor="white" strokeweight="3px" />
          <v:line class="vmlimage" style="z-index:2" from="50,35" to="50,80" strokecolor="white" strokeweight="3px" />
        </v:group>
        <xsl:text>&#160;</xsl:text>
      </xsl:when>
    </xsl:choose>
    <xsl:value-of select="./Property[@Name='Title']"/></span><a class="expando" href="#"></a></div>
	
		<div class="container"><div class="he4i"><table cellpadding="0" class="info4" >
		<tr><td></td><td></td><td></td><td></td><td></td></tr>
		<xsl:variable name="pos" select="position()" />
		<xsl:variable name="mod" select="($pos mod 2)" />
    <xsl:if test="./Property[@Name='Category']"><tr class="lines1"><td>Category</td><td colspan="4"><xsl:value-of select="./Property[@Name='Category']"/></td></tr></xsl:if>
    <xsl:if test="string-length(./Property[@Name='Problem']) > 0"><tr class="lines0"><td>Problem</td><td colspan="4"><b><xsl:value-of select="./Property[@Name='Problem']"/></b></td></tr></xsl:if>
    <xsl:if test="string-length(./Property[@Name='Impact']) > 0"><tr class="lines1"><td>Impact</td><td colspan="4"><xsl:value-of select="./Property[@Name='Impact']"/></td></tr></xsl:if>
    <xsl:if test="string-length(./Property[@Name='Resolution']) > 0"><tr class="lines0"><td>Resolution</td><td colspan="4"><xsl:value-of select="./Property[@Name='Resolution']"/></td></tr></xsl:if>
    <xsl:if test="string-length(./Property[@Name='Compliance']) > 0"><tr class="lines0"><td>Compliance</td><td colspan="4"><b><xsl:value-of select="./Property[@Name='Compliance']"/></b></td></tr></xsl:if>
    <xsl:if test="./Property[@Name='Help']"><tr class="lines1"><td>Additional Help</td><td colspan="4"><a href="{./Property[@Name='Help']}"><xsl:value-of select="./Property[@Name='Help']"/></a></td></tr></xsl:if>
    <xsl:if test="./Property[@Name='Excluded']"><tr class="lines0"><td>Excluded</td><td colspan="4"><xsl:value-of select="./Property[@Name='Excluded']"/></td></tr></xsl:if>
    <xsl:if test="./Property[@Name='RuleId']"><tr class="lines1"><td>Rule ID</td><td colspan="4"><xsl:value-of select="./Property[@Name='RuleId']"/></td></tr></xsl:if>
    <xsl:if test="./Property[@Name='ResultId']"><tr class="lines0"><td>Result ID</td><td colspan="4"><xsl:value-of select="./Property[@Name='ResultId']"/></td></tr></xsl:if>
		</table>

    </div></div>
	<div class="filler"></div>

	</xsl:for-each>

</body>
</html>
</xsl:template>
</xsl:stylesheet>