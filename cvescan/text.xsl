<?xml version="1.0" encoding="UTF-8"?>
<!--

****************************************************************************************
 Copyright (c) 2002-2012, The MITRE Corporation
 All rights reserved.

 Redistribution and use in source and binary forms, with or without modification, are
 permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice, this list
       of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright notice, this
       list of conditions and the following disclaimer in the documentation and/or other
       materials provided with the distribution.
     * Neither the name of The MITRE Corporation nor the names of its contributors may be
       used to endorse or promote products derived from this software without specific
       prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

****************************************************************************************

        AUTHOR:Matt Burton, The Mitre Corporation
        DATE: 02 May 2005

        Modified by Loren Bandiera, MMG Security
           * Updating for v5 results
        DATE: 10 May 2006

        Reimplemented by Jon Baker, The Mitre Corporation
        DATE: 12 October 2006

        Modified by Vladimir Giszpenc, DSCI Contractor Supporting CERDEC S&TCD IAD
           * Allowing for references other than CVE such as Red Hat patches
        DATE: 18 May 2007
       Modified by Vladimir Giszpenc, DSCI Contractor Supporting CERDEC S&TCD IAD
           * Added some aggregate data in the Systems Analysed section
        DATE: 20 Aug 2007

        Modified by David Rothenberg, The Mitre Corporation
                * Updated CSS style, updated groupings based on positive/negative implication rather than OVAL result enumeration
        DATE: 24 September 2012

        Modified by Simon Lukasik, Red Hat, Inc.
                * Removed overabundant whitespaces
        DATE: 05 August 2013

        The results_to_html stylesheet converts an OVAL Results document into a more readable html format.
        General information about the source of the OVAL Definitions being reported on, and the OVAL Results
        producer is displayed. Next general information about each system analyzed is presented including a
        table or result information. The table displays true results then all other results sorted in
        descending order by result. If the OVAL Results document has results for multiple systems a set
        of links will be generated near the top of the resulting html to allow users to easily jump to the
        each system's results.

-->

<!--
Copyright (C) 2019 Canonical, Ltd.
Author: Mark Morlino <mark.morlino@canonical.com>
License: GPLv3

This file is a derivative of https://github.com/OpenSCAP/openscap/blob/1.2.8/xsl/oval-results-report.xsl
the original file has been modified to produce plain text output and allow some simple filtering.

There may be some general purpose uses but the filtering was created to work with OVAL files produced
by Ubuntu Security https://people.canonical.com/~ubuntu-security/oval/
-->

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
