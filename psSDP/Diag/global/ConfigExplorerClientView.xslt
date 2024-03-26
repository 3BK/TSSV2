<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:msxsl="urn:schemas-microsoft-com:xslt" exclude-result-prefixes="msxsl">
  <xsl:output method="html" indent="yes"/>
  <xsl:key name="EntityMemberTable" match="Member" use="@ParentMemberID" />
  <xsl:key name="EntityMemberTableGroup" match="Member" use="concat(@ID/text(), '|' , @ParentMemberID/text())" />
  <xsl:template match="/Root">
    <html dir="ltr" xmlns:v="urn:schemas-microsoft-com:vml" reportInitialized="false">

      <meta http-equiv="X-UA-Compatible" content="IE=EmulateIE8" />
      <head>
        <!-- Styles -->
        <style type="text/css">
          body    { background-color:#FFFFFF; border:1px solid #666666; color:#000000; font-size:68%; font-family:Segoe UI, MS Shell Dlg; margin:0,0,10px,0; word-break:normal; word-wrap:break-word; }

          table   { font-size:100%; table-layout:fixed; width:100%; }

          td,th   { overflow:visible; text-align:left; vertical-align:top; white-space:normal; }

          .title  { font-family:Segoe UI, MS Shell Dlg; background:#FFFFFF; border:none; color:#333333; display:block; height:24px; margin:0px,0px,-1px,0px; padding-top:4px; position:relative; table-layout:fixed; width:100%; z-index:5; }

          .header_0    { background-color:#FEF7D6; border:1px solid #BBBBBB; color:#3333CC; cursor:hand; display:block; font-family:Verdana; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:18px; padding-right:5em; padding-top:4px; position:relative; width:100%;
          filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=1,StartColorStr='#FEF7D6',EndColorStr='white');}

          .header_0_expanded   { background-color:#FEF7D6; border:1px solid #BBBBBB; cursor:hand; display:block; font-family:Segoe UI, Verdana; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:20px; padding-right:5em; padding-top:4px; position:relative; width:100%;
          filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=1,StartColorStr='#FEF7D6',EndColorStr='white');}

          .Section_GrayLight0 { background-color:#FAFAFA; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:Segoe UI, MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; font-weight:bold; margin-left:2px; margin-right:0px; padding-left:10px; padding-right:0em; padding-top:4px; position:relative; width:100%; }
          .Section_GrayLight1 { background-color:#F5F5F5; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:Segoe UI, MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; font-weight:bold; margin-left:10px; margin-right:0px; padding-left:20px; padding-right:0em; padding-top:4px; position:relative; width:100%; }
          .Section_GrayLight1_Ident { background-color:#E5E5E5; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:Segoe UI, MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; font-weight:bold; margin-left:40px; margin-right:0px; padding-left:20px; padding-right:0em; padding-top:0px; position:relative; width:100%; }
          .Section_GrayLight2 { background-color:#F3F5F5; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:Segoe UI, MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; font-weight:bold; margin-left:10px; margin-right:0px; padding-left:20px; padding-right:0em; padding-top:0px; position:relative; width:100%; }

          .header_1    { background-color:#F0F8FF; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:Segoe UI, MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; font-weight:bold; margin-left:0px; margin-right:0px; padding-left:20px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
          .header_1_expanded    { background-color:#F0F8FF; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:Segoe UI, MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; font-weight:bold; margin-left:0px; margin-right:0px; padding-left:20px; padding-right:5em; padding-top:4px; position:relative; width:100%; }

          .header_2    { background-color:#E1F8FF; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:Segoe UI, MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; font-weight:bold; margin-left:30px; margin-right:0px; padding-left:20px; padding-right:5em; padding-top:4px; position:relative; width:100%; }

          .header_file  { background-color:#E5E5E5; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:Segoe UI, MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; font-weight:bold; margin-left:0px; margin-right:0px; padding-left:20px; padding-right:5em; padding-top:4px; position:relative; width:100%; }
          .header_fileversion  { background-color:#F3F5F5; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:Segoe UI, MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; font-weight:bold; margin-left:-20px; margin-right:0px; padding-left:20px; padding-right:5em; padding-top:4px; position:relative; width:100%; }

          .info0th                          { padding-right:10px; border-bottom:1px solid #CCCCCC; padding-right:10px;}
          .info0thsmall                     { padding-right:10px; border-bottom:1px solid #CCCCCC; padding-right:10px;width:15%;}
          .info0thsmallest                  { padding-right:10px; border-bottom:1px solid #CCCCCC; padding-right:10px;width:10%}

          DIV .expando { color:#000000; text-decoration:none; display:block; font-family:MS Shell Dlg; font-size:100%; font-weight:normal; position:absolute; left:2px; text-decoration:underline; z-index: 0; padding-top:2px;}

          .explainlink:hover      { color:#0000FF; text-decoration:underline; }

          .filler { background:transparent; border:none; color:#FFFFFF; display:block; font:100% MS Shell Dlg; line-height:8px; margin-bottom:-1px; margin-left:43px; margin-right:0px; padding-top:4px; position:relative; }

          .container { display:block; position:relative; }

          .vmlimage:hover
          {color:#0000FF; strokecolor:yellow; }

          .rsopheader { background-color:#A0BACB; border-bottom:1px solid #A0A0A0; color:#333333; font-family: Segoe UI, MS Shell Dlg; font-size:140%; padding-bottom:5px; text-align:center;
          filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=0,StartColorStr='#FFFFFF',EndColorStr='#7DAEFF')}

          #uri    { color:#333333; font-family:MS Shell Dlg; font-size:100%; padding-left:11px; }

          #objshowhide { color:#000000; cursor:hand; font-family: Segoe UI, MS Shell Dlg; font-size:100%; font-weight:bold; margin-right:0px; padding-right:10px; text-align:right; text-decoration:underline; z-index:2; word-wrap:normal; }

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
    IsSectionHeader = (Left(obj.className, Len("header_")) = "header_")
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
      <title>
        Configuration Explorer Debug Report
      </title>
      <xsl:comment>saved from url=(0024)http://www.microsoft.com</xsl:comment>
      <body>
        <xsl:for-each select="/Root/Schema/Schema">
          <xsl:variable name="RootGuid" select="@Root" />
          <xsl:for-each select="DiscoverySet[@Guid = $RootGuid]">
            <xsl:call-template name="DiscoverySet">
              <xsl:with-param name="Guid" select="@Guid"/>
            </xsl:call-template>
          </xsl:for-each>
        </xsl:for-each>
        <div class="filler"></div>
        <xsl:if test="/Root/FileSystemData">
          <div class="header_0_expanded">
            <span class="sectionTitle" tabindex="0">
              File Explorer
            </span>
            <a class="expando" href="#"></a>
          </div>
          <xsl:for-each select="/Root/FileSystemData">
            <xsl:variable name="ComputerName" select="@ComputerName"/>
            <div class="container">
              <div class="Section_GrayLight1">
                <xsl:for-each select="/Root/FileSystemData[@ComputerName=$ComputerName]/Root">
                  <xsl:call-template name="DisplayFolder" />
                </xsl:for-each>
              </div>
            </div>
          </xsl:for-each>
        </xsl:if>
        <xsl:if test="/Root/RegistryData">
          <div class="filler" />
          <div class="header_0_expanded">
            <span class="sectionTitle" tabindex="0">
              Registry Explorer
            </span>
            <a class="expando" href="#"></a>
          </div>
          <xsl:for-each select="//Root/RegistryData">
            <xsl:variable name="ComputerName" select="@ComputerName"/>
            <div class="container">
              <div class="Section_GrayLight1">
                <xsl:for-each select="/Root/RegistryData[@ComputerName=$ComputerName]/Root">
                  <xsl:call-template name="DisplayRegistryKey" />
                </xsl:for-each>
              </div>
            </div>
          </xsl:for-each>
        </xsl:if>

      </body>
    </html>
  </xsl:template>

  <xsl:template name="DiscoverySet">
    <xsl:variable name="DiscoverySetGuid" select="@Guid" />
    <div class="header_0_expanded">
      <span class="sectionTitle" tabindex="0">
        <xsl:value-of select="@Name"/>
      </span>
      <a class="expando" href="#"/>
    </div>
    <div class="container">
      <xsl:for-each select="Entities/Entity[not (@Parent)]">
        <xsl:call-template name="Entity">
          <xsl:with-param name="DiscoverySetGuid" select="$DiscoverySetGuid" />
        </xsl:call-template>
      </xsl:for-each>
      <div class="filler"></div>
    </div>
  </xsl:template>

  <xsl:template name="Entity">
    <xsl:param name="DiscoverySetGuid" />
    <xsl:variable name="EntityGuid" select="@Guid"/>
    <xsl:variable name="Entity" select="."/>
    <xsl:variable name="EntityData" select="(/Root/DiscoverySetData[@DiscoverySet = $DiscoverySetGuid]/EntityData[@Entity = $EntityGuid])"/>
    <div class="container">
      <xsl:choose>
        <xsl:when test="@Type = 'Section' ">
          <xsl:call-template name="Section">
            <xsl:with-param name="DiscoverySetGuid" select="$DiscoverySetGuid"/>
            <xsl:with-param name="EntityGuid" select="$EntityGuid"/>
            <xsl:with-param name="Entity" select="."/>
          </xsl:call-template>
        </xsl:when>
        <xsl:otherwise>
          <xsl:call-template name="Class">
            <xsl:with-param name="DiscoverySetGuid" select="$DiscoverySetGuid"/>
            <xsl:with-param name="EntityGuid" select="$EntityGuid"/>
            <xsl:with-param name="Entity" select="."/>
            <xsl:with-param name="EntityData" select="$EntityData"/>
            <xsl:with-param name="EntityDataMember" select="$EntityData/Data/Member"/>
          </xsl:call-template>
        </xsl:otherwise>
      </xsl:choose>
    </div>
  </xsl:template>

  <xsl:template name="Section">
    <xsl:param name="DiscoverySetGuid" />
    <xsl:param name="EntityGuid" />
    <xsl:param name="Entity" />
    <div class="header_1">
      <span class="sectionTitle" tabindex="0">
        Section: <xsl:value-of select="$Entity/@DisplayName"/>
      </span>
      <a class="expando" href="#"/>
    </div>
    <div class="container">
      <div class="Section_GrayLight1">
        <xsl:for-each select="/Root/Schema/Schema/DiscoverySet[@Guid = $DiscoverySetGuid]/Entities/Entity[@Parent = $EntityGuid]">
          <xsl:variable name="ChildEntityGuid" select="@Guid" />
          <xsl:variable name="ChildEntity" select="." />
          <xsl:choose>
            <xsl:when test="@Type = 'Section'">
              <xsl:call-template name="Section">
                <xsl:with-param name="DiscoverySetGuid" select="$DiscoverySetGuid"/>
                <xsl:with-param name="EntityGuid" select="$ChildEntityGuid"/>
                <xsl:with-param name="Entity" select="$ChildEntity"/>
              </xsl:call-template>
            </xsl:when>
            <xsl:otherwise>
              <xsl:variable name="EntityData" select="/Root/DiscoverySetData[@DiscoverySet = $DiscoverySetGuid]/EntityData[@Entity = $ChildEntityGuid]"/>
              <xsl:call-template name="Class">
                <xsl:with-param name="DiscoverySetGuid" select="$DiscoverySetGuid"/>
                <xsl:with-param name="Entity" select="$ChildEntity"/>
                <xsl:with-param name="EntityGuid" select="$ChildEntityGuid"/>
                <xsl:with-param name="EntityData" select="$EntityData"/>
                <xsl:with-param name="EntityDataMember" select="$EntityData/Data/Member"/>
              </xsl:call-template>
            </xsl:otherwise>
          </xsl:choose>
        </xsl:for-each>
        <xsl:for-each select="$Entity/DiscoverySetLink">
          <xsl:variable name="DiscoverySetLinkGuid" select="@Guid"/>
          <xsl:for-each select="/Root/Schema/Schema/DiscoverySet[@Guid = $DiscoverySetLinkGuid]">
            <xsl:call-template name="DiscoverySet">
              <xsl:with-param name="Guid" select="@Guid"/>
            </xsl:call-template>
          </xsl:for-each>
        </xsl:for-each>
      </div>
    </div>
  </xsl:template>

  <xsl:template name="TableRows">
    <xsl:param name="EntityDataMembers" />
    <xsl:param name="Entity" />
    <xsl:for-each select="$EntityDataMembers">
      <xsl:variable name="EntityDataMember" select="."/>
      <tr>
        <xsl:for-each select="$Entity/Properties/Property">
          <xsl:sort order="ascending" data-type="number" select="Order"/>
          <xsl:variable name="PropertyName" select="@Name" />
          <xsl:variable name="MemberValueNode" select="$EntityDataMember/child::node()[name() = $PropertyName]"/>
          <td>
            <xsl:choose>
              <xsl:when test="$MemberValueNode/@FormattedValue">
                <xsl:value-of select="$MemberValueNode/@FormattedValue"/>
              </xsl:when>
              <xsl:otherwise>
                <xsl:value-of select="$MemberValueNode"/>
              </xsl:otherwise>
            </xsl:choose>
          </td>
        </xsl:for-each>
      </tr>
    </xsl:for-each>
  </xsl:template>

  <xsl:template name="Class">
    <xsl:param name="DiscoverySetGuid" />
    <xsl:param name="EntityGuid" />
    <xsl:param name="Entity" />
    <xsl:param name="EntityData" />
    <xsl:param name="EntityDataMember" />
    <xsl:choose>
      <xsl:when test="$Entity/@ViewMode = 'Table'">
        <xsl:if test="$EntityDataMember">
          <xsl:for-each select="key('EntityMemberTable', $EntityDataMember/@ID)">
            <xsl:variable name="ChildMember" select="." />
            <xsl:variable name="ChildMemberEntityGUID" select="$ChildMember/../../@Entity" />
            <div class="Section_GrayLight0">
              <table>
                <xsl:for-each select="$Entity/Properties/Property">
                  <xsl:sort order="ascending" data-type="number" select="Order"/>
                  <th class="info0th">
                    <xsl:value-of select="@Name"/>
                  </th>
                </xsl:for-each>
                <xsl:call-template name="TableRows">
                  <xsl:with-param name="Entity" select="$Entity" />
                  <xsl:with-param name="EntityDataMembers" select="$EntityDataMember[@ID=$ChildMember/@ParentMemberID]" />
                </xsl:call-template>
              </table>
              <xsl:for-each select="/Root/Schema/Schema/DiscoverySet[@Guid = $DiscoverySetGuid]/Entities/Entity[@Guid = $ChildMemberEntityGUID]">
                <xsl:call-template name="Class">
                  <xsl:with-param name="DiscoverySetGuid" select="$DiscoverySetGuid"/>
                  <xsl:with-param name="EntityGuid" select="$ChildMemberEntityGUID"/>
                  <xsl:with-param name="Entity" select="."/>
                  <xsl:with-param name="EntityData" select="$ChildMember/../.."/>
                  <xsl:with-param name="EntityDataMember" select="$ChildMember"/>
                </xsl:call-template>
              </xsl:for-each>
            </div>
          </xsl:for-each>
          <div class="Section_GrayLight0">
            <table>
              <xsl:for-each select="$Entity/Properties/Property">
                <xsl:sort order="ascending" data-type="number" select="Order"/>
                <th class="info0th">
                  <xsl:value-of select="@Name"/>
                </th>
              </xsl:for-each>
              <xsl:for-each select="$EntityDataMember">
                <xsl:variable name="MemberId" select="@ID" />
                <xsl:variable name="Member" select="." />
                <xsl:if test="count(/Root/DiscoverySetData[@DiscoverySet = $DiscoverySetGuid]/EntityData[@Entity = $EntityGuid and Data/Member[@ParentMemberID = $MemberId]]) = 0">
                  <tr>
                    <xsl:for-each select="$Entity/Properties/Property">
                      <xsl:sort order="ascending" data-type="number" select="Order"/>
                      <xsl:variable name="PropertyName" select="@Name" />
                      <xsl:variable name="MemberValueNode" select="$Member/child::node()[name() = $PropertyName]"/>
                      <td>
                        <xsl:choose>
                          <xsl:when test="$MemberValueNode/@FormattedValue">
                            <xsl:value-of select="$MemberValueNode/@FormattedValue"/>
                          </xsl:when>
                          <xsl:otherwise>
                            <xsl:value-of select="$MemberValueNode"/>
                          </xsl:otherwise>
                        </xsl:choose>
                      </td>
                    </xsl:for-each>
                  </tr>
                </xsl:if>
              </xsl:for-each>
            </table>
          </div>
        </xsl:if>
      </xsl:when>
      <xsl:otherwise>
        <xsl:for-each select="$EntityDataMember">
          <xsl:variable name="MemberId" select="@ID" />
          <xsl:call-template name="EntityDataMember">
            <xsl:with-param name="DiscoverySetGuid" select="$DiscoverySetGuid"/>
            <xsl:with-param name="EntityGuid" select="$EntityGuid"/>
            <xsl:with-param name="Entity" select="$Entity"/>
            <xsl:with-param name="Member" select="."/>
          </xsl:call-template>
          <xsl:for-each select="/Root/Schema/Schema/DiscoverySet[@Guid = $DiscoverySetGuid]/Entities/Entity[@Parent = $EntityGuid]">
            <xsl:sort data-type="text" order="ascending" select="@Type"/>
            <xsl:variable name="ChildEntity" select="." />
            <xsl:variable name="ChildEntityGuid" select="@Guid" />
            <xsl:variable name="ChildEntityData" select="(/Root/DiscoverySetData[@DiscoverySet = $DiscoverySetGuid]/EntityData[@Entity = $ChildEntityGuid])"/>
            <xsl:choose>
              <xsl:when test="@Type = 'Section'">
                <xsl:if test="count(/Root/Schema/Schema/DiscoverySet[@Guid = $DiscoverySetGuid]/Entities/Entity[@Parent = $ChildEntityGuid]) > 0">
                  <xsl:call-template name="Section">
                    <xsl:with-param name="DiscoverySetGuid" select="$DiscoverySetGuid"/>
                    <xsl:with-param name="EntityGuid" select="$ChildEntityGuid"/>
                    <xsl:with-param name="Entity" select="$ChildEntity"/>
                  </xsl:call-template>
                </xsl:if>
              </xsl:when>
              <xsl:otherwise>
                <xsl:if test="$ChildEntityData">
                  <xsl:for-each select="/Root/DiscoverySetData[@DiscoverySet = $DiscoverySetGuid]/EntityData[@Entity = $ChildEntityGuid and Data/Member[@ParentMemberID = $MemberId]]">
                    <xsl:variable name="ChildDataEntityGuid" select="@Entity" />
                    <xsl:variable name="ChildDataEntity" select="/Root/Schema/Schema/DiscoverySet[@Guid = $DiscoverySetGuid]/Entities/Entity[@Guid = $ChildDataEntityGuid]" />
                    <xsl:variable name="ChildDataEntityDisplayName" select="$ChildDataEntity/@DisplayName"/>
                    <div class="header_2">
                      <span class="sectionTitle" tabindex="0">
                        <xsl:value-of select="$ChildDataEntityDisplayName"/>
                      </span>
                      <a class="expando" href="#"/>
                    </div>
                    <div class="container">
                      <div class="Section_GrayLight1_Ident">
                        <xsl:call-template name="Class">
                          <xsl:with-param name="DiscoverySetGuid" select="$DiscoverySetGuid"/>
                          <xsl:with-param name="EntityGuid" select="$ChildDataEntityGuid"/>
                          <xsl:with-param name="Entity" select="$ChildDataEntity"/>
                          <xsl:with-param name="EntityData" select="."/>
                          <xsl:with-param name="EntityDataMember" select="./Data/Member[@ParentMemberID = $MemberId]"/>
                        </xsl:call-template>
                      </div>
                    </div>
                  </xsl:for-each>
                </xsl:if>
              </xsl:otherwise>
            </xsl:choose>
          </xsl:for-each>
        </xsl:for-each>
      </xsl:otherwise>
    </xsl:choose>

    <xsl:text>&#160;</xsl:text>
  </xsl:template>

  <xsl:template name="EntityDataMember">
    <xsl:param name="DiscoverySetGuid" />
    <xsl:param name="EntityGuid" />
    <xsl:param name="Entity" />
    <xsl:param name="Member" />
    <xsl:variable name="EntityDisplayName" select="$Entity/@DisplayName"/>
    <div class="header_1">
      <span class="sectionTitle" tabindex="0">
        <xsl:choose>
          <xsl:when test="$Member/child::node()[@Order = 0]">
            <xsl:copy-of select="$Member/child::node()[@Order = 0]"/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="$EntityDisplayName"/>
          </xsl:otherwise>
        </xsl:choose>
      </span>
      <a class="expando" href="#"/>
    </div>
    <div class="container">
      <div class="Section_GrayLight1">
        <table cellpadding="0" cellspacing="4">
          <xsl:for-each select="child::node()[@Order]">
            <xsl:sort data-type="number" order="ascending" select="@Order"/>
            <tr>
              <td>
                <xsl:call-template name="DisplayNameForProperty">
                  <xsl:with-param name="Entity" select="$Entity" />
                  <xsl:with-param name="PropertyName" select="name()" />
                </xsl:call-template>
              </td>
              <td>
                <xsl:choose>
                  <xsl:when test="@FormattedValue">
                    <xsl:value-of select="@FormattedValue"/>
                  </xsl:when>
                  <xsl:otherwise>
                    <xsl:value-of select="."/>
                  </xsl:otherwise>
                </xsl:choose>
              </td>
            </tr>
          </xsl:for-each>
        </table>
      </div>
    </div>
  </xsl:template>

  <xsl:template name="DisplayNameForProperty">
    <xsl:param name="PropertyName" />
    <xsl:param name="Entity" />
    <xsl:for-each select="$Entity/Properties/Property[@Name=$PropertyName]">
      <xsl:value-of select="@DisplayName"/>
      <xsl:if test="@Visibility = 'Public'">*</xsl:if>
    </xsl:for-each>
  </xsl:template>

  <xsl:template name="DisplayFolder">
    <div class="header_1">
      <span class="sectionTitle" tabindex="0">
        <xsl:value-of select="@Name"/>
      </span>
      <a class="expando" href="#"></a>
    </div>
    <div class="container">
      <div class="Section_GrayLight2">
        <xsl:for-each select="Folder">
          <xsl:call-template name="DisplayFolder" />
        </xsl:for-each>
        <xsl:for-each select="File">
          <xsl:call-template name="DisplayFile" />
        </xsl:for-each>
      </div>
    </div>
  </xsl:template>

  <xsl:template name="DisplayRegistryKey">
    <div class="header_1">
      <span class="sectionTitle" tabindex="0">
        <xsl:value-of select="@Name"/>
      </span>
      <a class="expando" href="#"></a>
    </div>
    <div class="container">
      <div class="Section_GrayLight2">
        <xsl:for-each select="RegistryKey">
          <xsl:call-template name="DisplayRegistryKey" />
        </xsl:for-each>
        <xsl:if test="RegistryValue">
          <xsl:call-template name="DisplayRegistryValue" />
        </xsl:if>
      </div>
    </div>
  </xsl:template>

  <xsl:template name="DisplayRegistryValue">
    <div class="hefile">
      <div class="Section_GrayLight1">
        <table cellpadding="0" cellspacing="4">
          <tr>
            <th class="info0thsmall">Name</th>
            <th class="info0thsmallest">Type</th>
            <th class="info0th">Data</th>
          </tr>
          <xsl:for-each select="RegistryValue">
            <tr>
              <td>
                <xsl:value-of select="@Name"/>
              </td>
              <td>
                <xsl:value-of select="@Type"/>
              </td>
              <td>
                <xsl:value-of select="@Data"/>
              </td>
            </tr>
          </xsl:for-each>
        </table>
      </div>
    </div>
  </xsl:template>

  <xsl:template name="DisplayFile">
    <div class="header_file">
      <span class="sectionTitle" tabindex="0">
        <xsl:value-of select="@Name"/>
      </span>
      <a class="expando" href="#"></a>
    </div>
    <div class="container">
      <div class="Section_GrayLight1">
        <xsl:call-template name="DisplayFileProperties" />
      </div>
    </div>
  </xsl:template>

  <xsl:template name="DisplayFileProperties">
    <table cellpadding="0" cellspacing="4">
      <xsl:for-each select="@*">
        <xsl:variable name="PropertyName" select="name()" />
        <tr>
          <td>
            <xsl:value-of select="$PropertyName"/>
          </td>
          <td>
            <xsl:value-of select="."/>
          </td>
        </tr>
      </xsl:for-each>
    </table>
    <xsl:if test="FileVersionInfo">
      <xsl:for-each select="FileVersionInfo">
        <div class="header_fileversion">
          <span class="sectionTitle" tabindex="0">
            Version Information
          </span>
          <a class="expando" href="#"></a>
        </div>
        <div class="container">
          <!--div class="he2i"-->
          <table>
            <xsl:for-each select="@*">
              <xsl:variable name="PropertyName" select="name()" />
              <tr>
                <td>
                  <xsl:value-of select="$PropertyName"/>
                </td>
                <td>
                  <xsl:choose>
                    <xsl:when test="@FormattedValue">
                      <xsl:value-of select="@FormattedValue"/>
                    </xsl:when>
                    <xsl:otherwise>
                      <xsl:value-of select="."/>
                    </xsl:otherwise>
                  </xsl:choose>
                </td>
              </tr>
            </xsl:for-each>
          </table>
          <!--/div -->
        </div>
      </xsl:for-each>
    </xsl:if>
  </xsl:template>


</xsl:stylesheet>
