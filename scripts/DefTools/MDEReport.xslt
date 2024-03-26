<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:template match="/">
		<html>
			<head>
				<title>MDE Client Analyzer Results</title>
				<style>
					h1 { font-family: "Segoe UI", Frutiger, "Frutiger Linotype", "Dejavu Sans", "Helvetica Neue", Arial, sans-serif; font-size: 32px; font-style: normal; font-variant: normal; font-weight: 700; line-height: 26.4px; }
					h2 { font-family: "Segoe UI", Frutiger, "Frutiger Linotype", "Dejavu Sans", "Helvetica Neue", Arial, sans-serif; font-size: 24px; font-style: normal; font-variant: normal; font-weight: 700; line-height: 20.9px; }
					h3 { font-family: "Segoe UI", Frutiger, "Frutiger Linotype", "Dejavu Sans", "Helvetica Neue", Arial, sans-serif; font-size: 20px; font-style: normal; font-variant: normal; font-weight: 700; line-height: 15.4px; }
					p { font-family: "Segoe UI", Frutiger, "Frutiger Linotype", "Dejavu Sans", "Helvetica Neue", Arial, sans-serif; font-size: 14px; font-style: normal; font-variant: normal; font-weight: 400; line-height: 20px; }

					table {
					display: table;
					font-family: Segoe UI,Frutiger,Frutiger Linotype,Dejavu Sans,Helvetica Neue,Arial,sans-serif;
					font-size: 14px;
					padding: 10px;
					border: 1px solid black;
					border-collapse: collapse;
					border-collapse: collapse;
					border-spacing: 0;
					border: 1px solid #ddd;
					width: 90%;
					}

					th, td {
					text-align: left;
					padding: 8px;
					}
					tr:nth-child(even){background-color: #f2f2f2}

					*, :after, :before {
					box-sizing: border-box;
					}
					.event-severity {
					position: relative;
					padding-left: 34px;
					display: inline-block;
					line-height: 14px;
					height: 14px;
					}
					.event-severity:before {
					content: '';
					display: block;
					position: absolute;
					left: 0;
					top: 0;
					height: 8px;
					transform: translateY(50%);
					width: 26px;
					background: repeating-linear-gradient(to right,#d9d9d9,#d9d9d9 8px,transparent 8px,transparent 9px);
					}
					.event-severity:after {
					content: '';
					display: block;
					position: absolute;
					left: 0;
					top: 0;
					height: 8px;
					transform: translateY(50%);
					}
					.event-severity.event-severity-high:after {
					width: 26px;
					background: repeating-linear-gradient(to right,#900,#900 8px,transparent 8px,transparent 9px);
					}
					.event-severity.event-severity-low:after {
					width: 8px;
					background: repeating-linear-gradient(to right,#f56a00,#f56a00 8px,transparent 8px,transparent 9px);
					}
					.event-severity.event-severity-informational:after {
					width: -1px;
					background: repeating-linear-gradient(to right,#d9d9d9,#d9d9d9 8px,transparent 8px,transparent 9px);
					}
					.event-severity.event-severity-medium:after {
					width: 17px;
					background: repeating-linear-gradient(to right,#f56a00,#f56a00 8px,transparent 8px,transparent 9px);
					}
					.collapsible{
					background-color: #FFFFFF;
					cursor: pointer;
					padding: 18px;
					border: none;
					text-align: left;
					outline: none;
					height: 80px;
					width: 400px;
					}
          .container{
          width: 100%;
					clear: both;
					float: left;
					}
					.childContainer{
					width: 50%;
					float: left;
					}
					.beforeResult{
					width: 300px;
					}
					.collapsible:after {
					content: '&#813;';
					float: right;
					margin-top: -80px;
					font-size: 50px;
					}
					.collapsible.active:after {
					content: '&#812;';
					}
					.results{
					width:98%;
					}
					.details{
					width:97%;
					}

				</style>
			</head>
			<body>
				<h1>MDE Client Analyzer Results</h1>
				<xsl:apply-templates/>
				<script type="text/javascript" defer="true">
					<xsl:comment>
					<![CDATA[
					var collapsible = document.getElementsByClassName("collapsible");
					for (var i = 0; i < collapsible.length; i++){
						collapsible[i].addEventListener("click", function() {
							this.classList.toggle("active");
							var content = this.nextElementSibling;
							if (content.style.display === "block") {
								content.style.display = "none";
							} else {
								content.style.display = "block";
							}
						});
					}
					]]>
					</xsl:comment>
				</script>
			</body>
		</html>
	</xsl:template>
	<xsl:template match = "MDEResults">
		<xsl:apply-templates select = "general" />
		<button type="button" class="collapsible">
			<h2>Device Information</h2>
		</button>
		<div style="display: block;">
      <div class="container">
				<div class="childContainer" >
					<xsl:apply-templates select = "devInfo" />
				</div>
				<div class="childContainer">
          <xsl:apply-templates select = "MDEDevConfig" />
        </div>
      </div>
      <div class="container">
        <div class="childContainer">
          <xsl:apply-templates select = "AVCompInfo" />
        </div>
				<div class="childContainer" >
          <xsl:apply-templates select = "EDRCompInfo" />
        </div>
      </div>
		</div>
    <div>
			<xsl:apply-templates select = "events" />
    </div>
	</xsl:template>
	<xsl:template match="general">
		<div>
			<p>
				<b>
					<xsl:value-of select="scriptVersion/@displayName"/>
				</b><xsl:value-of select="scriptVersion"/> | <b>
					<xsl:value-of select="scriptRunTime/@displayName"/>
				</b><xsl:value-of select="scriptRunTime"/> | <b>
          <xsl:value-of select="traceStartTime/@displayName"/>
        </b><xsl:value-of select="traceStartTime"/> | <b>
          <xsl:value-of select="traceStopTime/@displayName"/>
        </b><xsl:value-of select="traceStopTime"/>
			</p>
		</div>
	</xsl:template>
	<xsl:template match="devInfo">
			<h3>General Device Details</h3>
			<table class="details">
				<xsl:for-each select="./*">
					<tr>
						<th width="350px">
							<xsl:value-of select="./@displayName"/>
						</th>
						<td>
							<xsl:choose>
								<xsl:when test="alert = 'High'">
									<span style="color:red">
                    <xsl:value-of select="value"/>
									</span>
								</xsl:when>
                <xsl:when test="alert = 'Medium'">
									<span style="color:orange">
                    <xsl:value-of select="value"/>
									</span>
								</xsl:when>
                <xsl:when test="alert = 'None'">
									<span style="color:green">
                    <xsl:value-of select="value"/>
									</span>
								</xsl:when>
								<xsl:otherwise>
                  <xsl:value-of select="value"/>
								</xsl:otherwise>
							</xsl:choose>
						</td>
					</tr>
				</xsl:for-each>
			</table>
		<br></br>
	</xsl:template>
  <xsl:template match="EDRCompInfo">
    <h3>EDR Component Details</h3>
    <table class="details">
      <xsl:for-each select="./*">
        <tr>
          <th width="350px">
            <xsl:value-of select="./@displayName"/>
          </th>
          <td>
            <xsl:choose>
              <xsl:when test="alert = 'High'">
                <span style="color:red">
                  <xsl:value-of select="value"/>
                </span>
              </xsl:when>
              <xsl:when test="alert = 'Medium'">
                <span style="color:orange">
                  <xsl:value-of select="value"/>
                </span>
              </xsl:when>
              <xsl:when test="alert = 'None'">
                <span style="color:green">
                  <xsl:value-of select="value"/>
                </span>
              </xsl:when>
              <xsl:otherwise>
                <xsl:value-of select="value"/>
              </xsl:otherwise>
            </xsl:choose>
          </td>
        </tr>
      </xsl:for-each>
    </table>
    <br></br>
  </xsl:template>
  <xsl:template match="MDEDevConfig">
    <h3>Device Configuration Management Details</h3>
    <table class="details">
      <xsl:for-each select="./*">
        <tr>
          <th width="350px">
            <xsl:value-of select="./@displayName"/>
          </th>
          <td>
            <xsl:choose>
              <xsl:when test="alert = 'High'">
                <span style="color:red">
                  <xsl:value-of select="value"/>
                </span>
              </xsl:when>
              <xsl:when test="alert = 'Medium'">
                <span style="color:orange">
                  <xsl:value-of select="value"/>
                </span>
              </xsl:when>
              <xsl:when test="alert = 'None'">
                <span style="color:green">
                  <xsl:value-of select="value"/>
                </span>
              </xsl:when>
              <xsl:otherwise>
                <xsl:value-of select="value"/>
              </xsl:otherwise>
            </xsl:choose>
          </td>
        </tr>
      </xsl:for-each>
    </table>
    <br></br>
  </xsl:template>
  <xsl:template match="AVCompInfo">
    <h3>AV Component Details</h3>
    <table class="details">
      <xsl:for-each select="./*">
        <tr>
          <th width="350px">
            <xsl:value-of select="./@displayName"/>
          </th>
          <td>
            <xsl:choose>
              <xsl:when test="alert = 'High'">
                <span style="color:red">
                  <xsl:value-of select="value"/>
                </span>
              </xsl:when>
              <xsl:when test="alert = 'Medium'">
                <span style="color:orange">
                  <xsl:value-of select="value"/>
                </span>
              </xsl:when>
              <xsl:when test="alert = 'None'">
                <span style="color:green">
                  <xsl:value-of select="value"/>
                </span>
              </xsl:when>
              <xsl:otherwise>
                <xsl:value-of select="value"/>
              </xsl:otherwise>
            </xsl:choose>
          </td>
        </tr>
      </xsl:for-each>
    </table>
    <br></br>
  </xsl:template>
	<xsl:template match="events">
		<hr></hr>
		<div>
			<button type="button" class="collapsible">
				<h2>Check Results Summary</h2>
			</button>
			<div style="display: block;">
				<table class="beforeResult">
					<tr>
						<th width="120px">
							<span class="event-severity event-severity-high">
								<span>Error</span>
							</span>
						</th>
						<th width="120px">
							<span class="event-severity event-severity-medium">
								<span>Warning</span>
							</span>
						</th>
						<th width="120px">
							<span class="event-severity event-severity-informational">
								<span>Informational</span>
							</span>
						</th>
					</tr>
					<tr>
						<td>
							<xsl:value-of select="count(event[severity='Error'])"/>
						</td>
						<td>
							<xsl:value-of select="count(event[severity='Warning'])"/>
						</td>
						<td>
							<xsl:value-of select="count(event[severity='Informational'])"/>
						</td>
					</tr>
				</table>
			</div>
			<br></br>
			<button type="button" class="collapsible">
				<h2>Detailed Results</h2>
			</button>
			<div style="display: block;">
				<table class="results">
					<tr>
						<th width="120px">Category</th>
						<th width="120px">Severity</th>
						<th width="80px">Id</th>
						<th width="200px">Test Name</th>
						<th>Results</th>
						<th>Guidance</th>
					</tr>
					<xsl:for-each select="event">
						<xsl:sort select="substring(@id,3,1)" order="descending"/>
						<tr>
							<td>
								<xsl:value-of select="category"/>
							</td>
							<td width="120px">
								<xsl:choose>
									<xsl:when test="severity = 'Error'">
										<span class="event-severity event-severity-high">
											<span>Error</span>
										</span>
									</xsl:when>
								</xsl:choose>
								<xsl:choose>
									<xsl:when test="severity = 'Warning'">
										<span class="event-severity event-severity-medium">
											<span>Warning</span>
										</span>
									</xsl:when>
								</xsl:choose>
								<xsl:choose>
									<xsl:when test="severity = 'Informational'">
										<span class="event-severity event-severity-informational">
											<span>Informational</span>
										</span>
									</xsl:when>
								</xsl:choose>
							</td>
							<td>
								<xsl:value-of select="@id"/>
							</td>
							<td width="180px">
								<xsl:value-of select="check"/>
							</td>
							<td>
								<xsl:value-of select="checkresult" disable-output-escaping = "yes"/>
							</td>
							<td width="400px">
								<xsl:value-of select="guidance" disable-output-escaping = "yes"/>
							</td>
						</tr>
					</xsl:for-each>
				</table>
			</div>
		</div>
	</xsl:template>
</xsl:stylesheet>