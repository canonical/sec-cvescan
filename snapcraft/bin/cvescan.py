#!/usr/bin/env python3

import sys
import os
import configparser
import time
import math
import argparse as ap
import re
from shutil import which,copyfile
import pycurl #TODO: Is curl on the system still necessary?
import bz2

class DistribIDError(Exception):
    pass

def error_exit(msg, code=4):
    print("Error: %s" % msg, file=sys.stderr)
    sys.exit(code)

def download(base_url, filename):
    try:
        target_file = open(filename, "wb")
        curl = pycurl.Curl()
        curl.setopt(pycurl.URL, "%s/%s" % (base_url.rstrip('/'), filename.lstrip('/')))
        curl.setopt(pycurl.WRITEDATA, target_file)
        curl.perform()
        curl.close()
        target_file.close()
    except:
        error_exit("Downloading %s/%s failed.", (base_url.rstrip('/'), filename.lstrip('/')))

def bz2decompress(bz2_archive, target):
    try:
        opened_archive = open(bz2_archive, "rb")
        opened_target = open(target, "wb")
        opened_target.write(bz2.decompress(opened_archive.read()))
        opened_archive.close()
        opened_target.close()
    except:
        error_exit("Decompressing %s to %s failed.", (bz2_archive, target))

def rmfile(filename):
    if os.path.exists(filename):
        if os.path.isfile(filename):
            os.remove(filename)

def get_lsb_release_info():
    with open("/etc/lsb-release", "rt") as lsb_file:
        lsb_file_contents = lsb_file.read()

    # ConfigParser needs section headers, so adding a header.
    lsb_file_contents = "[lsb]\n" + lsb_file_contents
    lsb_config = configparser.ConfigParser()
    lsb_config.read_string(lsb_file_contents)

    return lsb_config

def get_ubuntu_codename():
    lsb_config = get_lsb_release_info()
    distrib_id = lsb_config.get("lsb","DISTRIB_ID")

    # Compare /etc/lsb-release to acceptable environment.
    if distrib_id != "Ubuntu":
        raise DistribIDError("DISTRIB_ID in /etc/lsb-release must be Ubuntu (DISTRIB_ID=%s)" % distrib_id)

    return lsb_config.get("lsb","DISTRIB_CODENAME")

def main():
    acceptable_codenames = ["xenial","bionic","disco","eoan"]

    cvescan_ap = ap.ArgumentParser(description="Use this script to use the Ubuntu security OVAL files.", formatter_class=ap.RawTextHelpFormatter)
    cvescan_ap.add_argument("-c", "--cve", metavar="CVE-IDENTIFIER", help="Report if this system is vulnerable to a specific CVE.")
    cvescan_ap.add_argument("-p", "--priority", help="'critical' = show only critical CVEs.\n'high'     = show critical and high CVEs (default)\n'medium'   = show critical and high and medium CVEs\n'all'      = show all CVES (no filtering based on priority)",choices=["critical","high","medium","all"], default="high")
    cvescan_ap.add_argument("-s", "--silent", action="store_true", default=False, help="Enable script/Silent mode: To be used with '-c <cve-identifier>'.\nDo not print text output; exit 0 if not vulnerable, exit 1 if vulnerable.")
    cvescan_ap.add_argument("-m", "--manifest", help="Enable manifest mode. Do not scan localhost.\nInstead run a scan against a Ubuntu Official Cloud Image package manifest file.\nThe script will use a server manifest file.",choices=acceptable_codenames)
    cvescan_ap.add_argument("-f", "--file", metavar="manifest-file", help="Used with '-m' option to override the default behavior. Specify\n a manifest file to scan instead of downloading an OCI manifest.\n The file needs to be readable under snap confinement.\n User's home will likely work, /tmp will likely not work.")
    cvescan_ap.add_argument("-n", "--nagios", action="store_true", default=False, help="Enable Nagios mode for use with NRPE.\nTypical nagios-style \"OK|WARNING|CRITICAL|UNKNOWN\" messages\n and exit codes of 0, 1, 2, or 3.\n0/OK = not vulnerable to any known and patchable CVEs of the\n specified priority or higher.\n1/WARNING = vulnerable to at least one known CVE of the specified\n priority or higher for which there is no available update.\n2/CRITICAL = vulnerable to at least one known and patchable CVE of\n the specified priority or higher.\n3/UNKNOWN = something went wrong with the script, or oscap.")
    cvescan_ap.add_argument("-l", "--list", action="store_true", default=False, help="Disable links. Show only CVE IDs instead of URLs.\nDefault is to output URLs linking to the Ubuntu CVE tracker.")
    cvescan_ap.add_argument("-r", "--reuse", action="store_true", default=False, help="re-use zip, oval, xml, and htm files from cached versions if possible.\nDefault is to redownload and regenerate everything.\nWarning: this may produce inaccurate results.")
    cvescan_ap.add_argument("-t", "--test", action="store_true", default=False, help="Test mode, use test OVAL data to validate that cvescan and oscap are\n working as expected. In test mode, files are not downloaded.\nIn test mode, the remove and verbose options are enabled automatically.")
    cvescan_ap.add_argument("-u", "--updates", action="store_true", default=False, help="Only show CVEs affecting packages if there is an update available.\nDefault: show only CVEs affecting this system or manifest file.")
    cvescan_ap.add_argument("-v", "--verbose", action="store_true", default=False, help="Enable verbose messages.")
    cvescan_ap.add_argument("-x", "--experimental", action="store_true", default=False, help="Enable eXperimental mode.\nUse experimental (also called \"alpha\") OVAL data files.\nThe alpha OVAL files include information about package updates\n available for users of Ubuntu Advantage running systems with ESM\n Apps enabled.")
    cvescan_args = cvescan_ap.parse_args()

    try:
        distrib_codename = get_ubuntu_codename()
    except (FileNotFoundError, PermissionError) as err:
        error_exit("Failed to determine the correct Ubuntu codename: %s" % err)
    except DistribIDError as di:
        error_exit("Invalid distribution: %s" % di)

    # Block of variables.
    cve = None
    if cvescan_args.cve != None:
        if re.match("^CVE-[0-9]{4}-[0-9]{1,6}$", cvescan_args.cve):
            cve = cvescan_args.cve
        else:
            error_exit("CVE argument not formatted correctly.")
    oval_base_url = "https://people.canonical.com/~ubuntu-security/oval"
    results = "results.xml"
    report = "report.htm"
    log = "oval.log"
    verbose = cvescan_args.verbose
    remove = not cvescan_args.reuse
    silent = cvescan_args.silent
    nagios = cvescan_args.nagios
    oval_file = str("com.ubuntu.%s.cve.oval.xml" % distrib_codename)
    oval_zip = str("%s.bz2" % oval_file)
    manifest = False
    manifest_url = None
    if cvescan_args.manifest != None:
        manifest = True
        release = cvescan_args.manifest
        oval_file = str("oci.%s" % oval_file)
        oval_zip = str("%s.bz2" % oval_file)
        manifest_url = str("https://cloud-images.ubuntu.com/%s/current/%s-server-cloudimg-amd64.manifest" % (release, release))
    manifest_file = "manifest"
    if cvescan_args.file != None:
        if os.path.isfile(cvescan_args.file):
            if cvescan_args.file[0] == "/":
                manifest_file = cvescan_args.file
            else:
                manifest_file = str("%s/%s", (os.path.abspath(os.path.dirname(sys.argv[0])),cvescan_args.file))
        else:
            error_exit("Cannot find manifest file \"%s\". Current directory is \"%s\"." % ( cvescan_args.f, os.path.abspath(os.path.dirname(sys.argv[0]))))
    all_cve = not cvescan_args.updates
    priority = cvescan_args.priority
    now = math.trunc(time.time()) # Transcription of `date +%s`
    expire = 86400
    scriptdir = os.path.abspath(os.path.dirname(sys.argv[0]))
    xslt_file = str("%s/text.xsl" % scriptdir)
    verbose_oscap_options = ""
    curl_options = "--fail --silent --show-error" #TODO: Is this necessary still?
    testmode = cvescan_args.test
    testcanaryfile = "cvescan.test"
    experimental = cvescan_args.experimental
    package_count = int(os.popen("dpkg -l | grep -E -c '^ii'").read())
    # TODO: does extra_sed need updating?
    extra_sed = "-e s@^@http://people.canonical.com/~ubuntu-security/cve/@"
    if cvescan_args.list == True:
        extra_sed = ""

    verboseprint = print if verbose else lambda *args, **kwargs: None


    ###########
    snap_user_common = None
    try:
        snap_user_common = os.environ["SNAP_USER_COMMON"]
        verboseprint("Running as a snap, changing to '%s' directory.\nDownloaded files, log files and temporary reports will be in '%s'" % (snap_user_common, snap_user_common))
        try:
            os.chdir(snap_user_common)
        except:
            error_exit("failed to cd to %s" % snap_user_common)
    except KeyError:
        pass

    if snap_user_common == None:
        for i in [["oscap", "libopenscap8"], ["xsltproc", "xsltproc"], ["curl", "curl"]]:
            if which(i[0]) == None:
                error_exit("Missing %s command. Run 'sudo apt install %s'" % (i[0], i[1]))

    if not os.path.isfile(xslt_file):
        error_exit("Missing text.xsl file at '%s', this file should have installed with cvescan" % xslt_file)

    if os.path.isfile("/var/log/dpkg.log") and os.path.isfile(results):
        package_change_ts = math.trunc(os.path.getmtime("/var/log/dpkg.log"))
        results_ts = math.trunc(os.path.getmtime(results))
        if package_change_ts > results_ts:
            verboseprint("Removing %s file because it is older than /var/log/dpkg.log" % results)
            rmfile(results)

    if testmode:
        verbose = True
        print("Running in test mode.")
        manifest = False
        print("Disabling manifest mode (test mode uses test OVAL files distributed with cvescan)")
        remove = True
        print("Setting flag to remove all cache files")
        experimental = False
        print("Disabling experimental mode (test mode uses test OVAL files distributed with cvescan)")
        priority = "all"
        print("Setting priority filter to 'all'")
        extra_sed = ""
        print("Disabling URLs in output")
        oval_file = "%s/com.ubuntu.test.cve.oval.xml" % scriptdir
        if os.path.isfile(oval_file):
            print("Using OVAL file %s to test oscap" % oval_file)
        else:
            error_exit("Missing test OVAL file at '%s', this file should have installed with cvescan" % oval_file)
    elif os.path.isfile(testcanaryfile):
        verboseprint("Detected previous run in test mode, cleaning up\nRemoving file: '%s'" % testcanaryfile)
        rmfile(testcanaryfile)
        remove = True

    if testmode:
      verboseprint("Running in TEST MODE")
    if all_cve:
      verboseprint("Reporting on ALL CVEs, not just those that can be fixed by updates")
    if nagios:
      verboseprint("Running in Nagios Mode")
    verboseprint("CVE Priority filter is '%s'\nInstalled package count is %s" % (priority, package_count))

    if manifest:
        verboseprint("Removing cached report and results files")
        rmfile(report)
        rmfile(results)
        if manifest_url != None and len(manifest_url) != 0:
            verboseprint("Removing cached manifest file")
            rmfile(manifest_file) # Research suggests that this should be equal to `rm -f file`
    else:
        verboseprint("Removing cached manifest file")
        rmfile(manifest_file)

    if experimental:
        oval_base_url = "%s/alpha" % oval_base_url
        oval_file = "alpha.%s" % oval_file
        oval_zip = "%s.bz2" % oval_file
        verboseprint("Running in experimental mode, using 'alpha' OVAL file from %s/%s" % (oval_base_url, oval_zip))

    if remove and not testmode:
        verboseprint("Removing file: %s" % oval_file)
        rmfile(oval_file)
    if remove:
        verboseprint("Removing files: %s %s %s %s debug.log" % (oval_zip, report, results, log))
        for i in [oval_zip, report, results, log, "debug.log"]:
            rmfile(i)

    if not testmode and ((not os.path.isfile(oval_file)) or ((now - math.trunc(os.path.getmtime(oval_file))) > expire)):
        for i in [results, report, log, "debug.log"]:
            rmfile(i)
        verboseprint("Downloading %s/%s" % (oval_base_url, oval_zip))
        download(oval_base_url, oval_zip)
        verboseprint("Unzipping %s" % oval_zip)
        bz2decompress(oval_zip, oval_file)

    if manifest:
        for i in [results, report, log, "debug.log"]:
            rmfile(i)
        if manifest_url != None and len(manifest_url) != 0:
            verboseprint("Downloading %s" % manifest_url)
            download(manifest_url, manifest_file)
        else:
            verboseprint("Using manifest file %s\ncp %s manifest (in %s)" % (manifest_file, manifest_file, scriptdir))
            copyfile(manifest_file, "%s/manifest" % scriptdir)
        package_count = int(os.popen("wc -l %s | cut -f1 -d' '" % manifest_file).read())
        verboseprint("Manifest package count is %s" % package_count)

    if not os.path.isfile(results) or ((now - math.trunc(os.path.getmtime(results))) > expire):
        verboseprint("Running oval scan oscap oval eval %s --results %s %s (output logged to %s/%s)" % (verbose_oscap_options, results, oval_file, scriptdir, log))
        try:
            os.system("oscap oval eval %s --results \"%s\" \"%s\" >%s 2>&1" % (verbose_oscap_options, results, oval_file, log)) #TODO: less Bash-y?
        except:
            error_exit("Failed to run oval scan")

    if not os.path.isfile(report) or ((now - math.trunc(os.path.getmtime(report))) > expire):
        verboseprint("Generating html report %s/%s from results xml %s/%s (output logged to %s/%s)" % (scriptdir, report, scriptdir, results, scriptdir, log))
        verboseprint("Open %s/%s in a browser to see complete and unfiltered scan results" % (os.getcwd(), report))
        try:
            os.system("oscap oval generate report --output %s %s >>%s 2>&1" % (report, results, log)) #TODO: less Bash-y?
        except:
            error_exit("Failed to generate oval report")

    verboseprint("Running xsltproc to generate CVE list - fixable/unfixable and filtered by priority")
    cve_list_all_filtered = os.popen("xsltproc --stringparam showAll true --stringparam priority \"%s\" \"%s\" \"%s\" | sed -e /^$/d %s" % (priority, xslt_file, results, extra_sed)).read().split('\n')
    while("" in cve_list_all_filtered):
        cve_list_all_filtered.remove("")
    cve_count_all_filtered = len(cve_list_all_filtered)

    verboseprint("%s vulnerabilities found with priority of %s or higher:\n%s" % (cve_count_all_filtered, priority, cve_list_all_filtered))
    verboseprint("Running xsltproc to generate CVE list - fixable and filtered by priority")

    cve_list_fixable_filtered = os.popen("xsltproc --stringparam showAll false --stringparam priority \"%s\" \"%s\" \"%s\" | sed -e /^$/d %s" % (priority, xslt_file, results, extra_sed)).read().split('\n')
    while("" in cve_list_fixable_filtered):
        cve_list_fixable_filtered.remove("")
    cve_count_fixable_filtered = len(cve_list_fixable_filtered)

    verboseprint("%s CVEs found with priority of %s or higher that can be fixed with package updates:\n%s" % (cve_count_fixable_filtered, priority, cve_list_fixable_filtered))
    if snap_user_common == None or len(snap_user_common) == 0:
      verboseprint("Full HTML report available in %s/%s" % (scriptdir, report))

    if testmode:
        print("Writing test canary file %s/%s" % (scriptdir, testcanaryfile))
        if os.path.exists(testcanaryfile):
            os.utime(testcanaryfile, None)
        else:
            open(testcanaryfile, "a").close()
        # FIRST TEST
        if (cve_count_all_filtered == 2) and ("CVE-1970-0300" in cve_list_all_filtered) and ("CVE-1970-0400" in cve_list_all_filtered) and ("CVE-1970-0200" not in cve_list_all_filtered) and ("CVE-1970-0500" not in cve_list_all_filtered):
            print("first test passed")
        else:
            error_exit("first test failed")
        # SECOND TEST
        if (cve_count_fixable_filtered == 1) and ("CVE-1970-0400" in cve_list_fixable_filtered):
            print("second test passed")
        else:
            error_exit("second test failed")

    verboseprint("Normal non-verbose output will appear below\n")

    if nagios:
        if cve_list_fixable_filtered == None or len(cve_list_fixable_filtered) == 0:
            print("OK: no known %s or higher CVEs that can be fixed by updating" % priority)
            sys.exit(0)
        elif cve_list_fixable_filtered != None and len(cve_list_fixable_filtered) != 0:
            print("CRITICAL: %s CVEs with priority %s or higher that can be fixed with package updates\n%s" % (cve_count_fixable_filtered, priority, '\n'.join(cve_list_fixable_filtered)))
            sys.exit(2)
        elif cve_list_all_filtered != None and len(cve_list_all_filtered) != 0:
            print("WARNING: %s CVEs with priority %s or higher\n%s" % (cve_count_all_filtered, priority, '\n'.join(cve_list_all_filtered)))
            sys.exit(1)
        else:
            print("UNKNOWN: something went wrong with %s" % sys.args[0])
            sys.exit(3)
    elif cve != None and len(cve) != 0:
        if cve in cve_list_fixable_filtered:
            if not silent:
                print("%s patch available to install" % cve)
            sys.exit(1)
        elif cve in cve_list_all_filtered:
            if not silent:
                print("%s patch not available" % cve)
            sys.exit(1)
        else:
            if not silent:
                print("%s patch applied or system not known to be affected" % cve)
            sys.exit(0)
    else:
        if all_cve:
            if not silent:
                print("Inspected %s packages. Found %s CVEs" % (package_count, cve_count_all_filtered))
            if cve_list_all_filtered != None and len(cve_list_all_filtered) != 0:
                print('\n'.join(cve_list_all_filtered))
                sys.exit(1)
            else:
                sys.exit(0)
        else:
            if not silent:
                print("Inspected %s packages. Found %s CVEs" % (package_count, cve_count_fixable_filtered))
            if cve_list_fixable_filtered != None and len(cve_list_fixable_filtered) != 0:
                print('\n'.join(cve_list_fixable_filtered))
                sys.exit(1)
            else:
                sys.exit(0)

if __name__ == "__main__":
    main()
