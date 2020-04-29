# Using OVAL from the Ubuntu Security Team

The Ubuntu Security Team produces OVAL files that can be used to help
determine how vulnerable a system is to CVEs.

The OVAL files are available from
[here](https://people.canonical.com/~ubuntu-security/oval).
These files are specific to a series/release of ubuntu.
Files with an `oci.` prefix are for use with Ubuntu Offical Cloud Image
manifest files.
Files without the `oci.` prefix are used to scan a running Ubuntu system.

More background on [OVAL](https://oval.mitre.org/)
and
[OpenSCAP](http://www.open-scap.org/).

Traditionally, OVAL would be used by downloading it, running a scan and
reviewing the generated HTML report. This method certainly has it's value
However, there needed to be a quicker and faster way of getting some specific
information. 
Specifically, an easy to see if any vulnerabilities on a system could be fixed
by a package update. And, an easy way to determine if a system is vulnerable
to a specific CVE.

The OVAL results in their default XML format and final HTML report format
are not easily consumable by scripts.
The /usr/share/openscap/xsl/oval-results-report.xsl file provided by
the libopenscap8 package was modified to become the text.xsl file included 
here in this repo.

The `text.xsl` file can be used with the xsltproc command to turn OVAL XML
results into text. It also allows for filtering the results.

## Contents 
* README.md                    - this file
* snapcraft.yaml               - snap packaging metadata, this can work as a snap
                                 or as a bash script
* snapcraft                    - actual code and related files live in here
* text.xsl                     - symlink to modified version of oscap xslt file to output
                                 cve list in text format
* cvescan                      - symlink to script to download oval and scan your system
                                 or an image manifest
* com.ubuntu.test.cve.oval.xml - symlink to test OVAL file, used with `cvescan -t`
                                 to validate that oscap functions correcty in the snap

## Snap usage
Install with:
```
sudo snap install cvescan
```
View help/usage message:
```
cvescan -h
```

## Prereqs id not using the snap
If you want to use cvescan as downloaded from github rather than as a snap then you
have to install some required prerequisite packages:
```
sudo apt-get install -y libopenscap8 xsltproc curl
```

## Below are some simple examples of using cvescan:

usage/help
```cvescan -?```

display a list of high and critical priority CVEs affecting this system
that can be fixed with package updates
```cvescan```

display a list of high and critical priority CVEs affecting this system
including those that cannot be fixed by updating packages
```cvescan -a```


Output "patch available to install" and exit 1 if vulnerable to the specified CVE and there is a patch.
Output "patch not available" and exit 1 if vulnerable to the specified CVE and there is no patch.
Output "patch applied or system not known to be affected" and exit 0 if not vulnerable to the specified CVE.
```cvescan -c CVE-2019-54321```


Similar to above but no printed output, only exit values
```cvescan -c CVE-2019-54321 -s```
