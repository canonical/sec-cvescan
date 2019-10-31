# Using OVAL from the Ubuntu Security Team

The Ubuntu Security Team produces OVAL files that can be used to help determine how vulnerable a system is.

The OVAL files are available from [here](https://people.canonical.com/~ubuntu-security/oval). The files are release-specific.

More background on [OVAL](https://oval.mitre.org/) and [OSCAP](http://www.open-scap.org/).

Traditionally, OVAL would be used by downloading it, running a scan and reviewing the generated report. This method certainly has it's place. However, I thought there needed to be a quicker and faster way of getting some specific information. 
Specifically, I wanted to see if there was anything vulnerable on my system that could be fixed by a package update and I wanted a way to determine if my system was vulnerable to a specific CVE.

In order to accomplish this I needed a reliable way to parse the oscap results XML into something more easily digestable than the default HTML report output. I fumbled around with some grep/awk/perl/python scripts. Finally I stumbled upon the XSLT file that oscap uses to create the HTML report from the XML results. On my system it gets installed as /usr/share/openscap/xsl/oval-results-report.xsl by the libopenscap8 package. I changed it to output text instead of HTML and started stripping away what I did not need. There might be more that can still be removed from the XSLT or other optimizations that can be made... I make know claims of knowing anything about XML or related tools.

Since the intial creation of the script, functionality has been added to scan Ubuntu Offical Cloud Image manifest files (it scans the manifest instead of the system it is running on). 

## Contents 
* README.md - this file
* text.xsl - modified version of oscap xslt file to output cve list in text format
* cvescan - script to download oval and scan your system (or an image manifest)

## Prereqs

sudo apt-get install -y libopenscap8 xsltproc 

## Using cvescan

./cvescan -? will display complete usage

Below are some examples:

./cvescan       # display a list of CVEs affecting this system that can be fixed with package updates
./cvescan -a    # display ALL CVEs affecting this system instead of just CVEs with package fixes
./cvescan -c CVE-2019-54321    # output "vulnerable" and exit 1 if vulnerable. Output "not vulnerable" and exit 0 if not vulnerable
./cvescan -c CVE-2019-54321 -s # similar to above but no output, only exit values
./cvescan -m bionic            # scan the OCI manifest for bionic
