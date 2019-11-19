<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.1" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
	xmlns:oval-res="http://oval.mitre.org/XMLSchema/oval-results-5" xmlns:oval-sc="http://oval.mitre.org/XMLSchema/oval-system-characteristics-5"
	xmlns:oval-def="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:apache-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#apache"
	xmlns:ind-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent" xmlns:windows-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#windows"
	xmlns:unix-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix" xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"
	exclude-result-prefixes="oval oval-def oval-res oval-sc ind-def windows-def unix-def linux-def apache-def">
	<xsl:output method="text" omit-xml-declaration="yes" indent="no"/>
	<xsl:key name="definition-index" use="@id" match="//oval-def:oval_definitions/oval-def:definitions/oval-def:definition"/>
	<xsl:param name="showAll" select="'false'"/>
	<xsl:param name="priority" select="'all'"/>

	<!-- Gets the top level node -->
	<xsl:template match="oval-res:oval_results">
		<xsl:for-each select="./oval-res:results/oval-res:system">
			<xsl:call-template name="DefinitionsResults">
				<xsl:with-param name="definitionsElm" select="./oval-res:definitions"/>
			</xsl:call-template>
			<xsl:text>&#xa;</xsl:text>
		</xsl:for-each>
	</xsl:template>

	<!-- Process a system's definition results in the specified order -->
	<xsl:template name="DefinitionsResults">
		<xsl:param name="definitionsElm"/>
			<xsl:for-each select="$definitionsElm/oval-res:definition[@result='true'][key('definition-index', ./@definition_id)[@class='patch' or @class='vulnerability']]|$definitionsElm/oval-res:definition[@result='false'][key('definition-index', ./@definition_id)[@class='compliance']]">
				<xsl:sort select="@id" data-type="text" order="descending"/>
				<xsl:call-template name="Definition">
					<xsl:with-param name="definitionElm" select="."/>
				</xsl:call-template>
			</xsl:for-each>

			<!-- process unknown results -->
			<xsl:for-each select="$definitionsElm/oval-res:definition[@result='unknown']">
				<xsl:sort select="@id" data-type="text" order="descending"/>
				<xsl:call-template name="Definition">
					<xsl:with-param name="definitionElm" select="."/>
				</xsl:call-template>
			</xsl:for-each>

			<!-- process error results -->
			<xsl:for-each select="$definitionsElm/oval-res:definition[@result='error']">
				<xsl:sort select="@id" data-type="text" order="descending"/>
				<xsl:call-template name="Definition">
					<xsl:with-param name="definitionElm" select="."/>
				</xsl:call-template>
			</xsl:for-each>

			<!-- process other results -->
			<xsl:for-each select="$definitionsElm/oval-res:definition[@result='not applicable' or @result='not evaluated']|$definitionsElm/oval-res:definition[@result='true' or @result='false'][key('definition-index', ./@definition_id)[@class='inventory' or @class='miscellaneous']]">
				<xsl:sort select="@id" data-type="text" order="descending"/>
				<xsl:call-template name="Definition">
					<xsl:with-param name="definitionElm" select="."/>
				</xsl:call-template>
			</xsl:for-each>

			<!-- process Compliant/Non-Vulnerable/Patched results -->
			<xsl:for-each select="$definitionsElm/oval-res:definition[@result='false'][key('definition-index', ./@definition_id)[@class='patch' or @class='vulnerability']]|$definitionsElm/oval-res:definition[@result='true'][key('definition-index', ./@definition_id)[@class='compliance']]">
				<xsl:sort select="@id" data-type="text" order="descending"/>
				<xsl:call-template name="Definition">
					<xsl:with-param name="definitionElm" select="."/>
				</xsl:call-template>
			</xsl:for-each>
	</xsl:template>

	<!-- Add information about a single definition to a new row -->
	<xsl:template name="Definition">
		<xsl:param name="definitionElm"/>
		<xsl:variable name="defClass"><xsl:value-of select="key('definition-index', @definition_id)/@class"/></xsl:variable>
		<xsl:variable name="defResult"><xsl:value-of select="$definitionElm/@result"/></xsl:variable>
		<xsl:variable name="criterionComment"><xsl:value-of select="key('definition-index', @definition_id)/oval-def:criteria/oval-def:criterion/@comment"/></xsl:variable>
		<xsl:variable name="defTitle"><xsl:value-of select="key('definition-index', @definition_id)/oval-def:metadata/oval-def:title"/></xsl:variable>
		<!-- if there is a CVE -->
		<xsl:if test="$defResult='true'">
			<xsl:for-each select="key('definition-index', @definition_id)/oval-def:metadata/oval-def:reference">
				<xsl:if test="$showAll='true' or contains($criterionComment, 'has been fixed')">
					<xsl:if test="$priority='all' or 
						(contains($defTitle, ' - medium.') and $priority='medium') or
						(contains($defTitle, ' - high.')      and ($priority='medium' or $priority='high')) or
						(contains($defTitle, ' - critical.')    and ($priority='critical' or $priority='high' or $priority='medium'))">
						<xsl:value-of select="@ref_id"/>
						<!-- <xsl:text> - </xsl:text>
						<xsl:value-of select="$defTitle"/> -->
						<xsl:text>&#xa;</xsl:text>
					</xsl:if>
				</xsl:if>
			</xsl:for-each>
		</xsl:if>
	</xsl:template>
</xsl:stylesheet>
