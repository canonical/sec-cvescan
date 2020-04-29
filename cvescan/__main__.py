#!/usr/bin/env python3

import sys
import os
import configparser
import time
import math
import argparse as ap
import re
from shutil import which,copyfile
import pycurl
import bz2
import cvescan.constants as const
from cvescan.errors import ArgumentError, DistribIDError, OpenSCAPError
import logging

def get_default_logger():
    logger = logging.getLogger("cvescan.stdout")
    logger.setLevel(logging.INFO)

    log_formatter = logging.Formatter("%(message)s")
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(log_formatter)
    logger.addHandler(stream_handler)

    return logger

def get_null_logger():
    logger = logging.getLogger("cvescan.null")
    logger.addHandler(logging.NullHandler())

    return logger

LOGGER = get_default_logger()

DEBUG_LOG = "debug.log"
DEFAULT_MANIFEST_FILE = "manifest"
DPKG_LOG = "/var/log/dpkg.log"
EXPIRE = 86400
MANIFEST_URL_TEMPLATE = "https://cloud-images.ubuntu.com/%s/current/%s-server-cloudimg-amd64.manifest"
OVAL_LOG = "oval.log"
REPORT = "report.htm"
RESULTS = "results.xml"

FMT_CVE_OPTION = "-c|--cve"
FMT_EXPERIMENTAL_OPTION = "-x|--experimental"
FMT_FILE_OPTION = "-f|--file"
FMT_MANIFEST_OPTION = "-m|--manifest"
FMT_NAGIOS_OPTION = "-n|--nagios"
FMT_PRIORITY_OPTION = "-p|priority"
FMT_REUSE_OPTION = "-r|--reuse"
FMT_SILENT_OPTION = "-s|--silent"
FMT_TEST_OPTION = "-t|--test"
FMT_UPDATES_OPTION = "-u|--updates"
FMT_VERBOSE_OPTION = "-v|--verbose"


def error_exit(msg, code=4):
    LOGGER.error("Error: %s" % msg)
    sys.exit(code)

def download(download_url, filename):
    try:
        target_file = open(filename, "wb")
        curl = pycurl.Curl()
        curl.setopt(pycurl.URL, download_url)
        curl.setopt(pycurl.WRITEDATA, target_file)
        curl.perform()
        curl.close()
        target_file.close()
    except:
        error_exit("Downloading %s failed." % download_url)

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

def parse_args():
    # TODO: Consider a more flexible solution than storing this in code (e.g. config file or launchpad query)
    acceptable_codenames = ["xenial","bionic","disco","eoan","focal"]

    cvescan_ap = ap.ArgumentParser(description=const.CVESCAN_DESCRIPTION, formatter_class=ap.RawTextHelpFormatter)
    cvescan_ap.add_argument("-c", "--cve", metavar="CVE-IDENTIFIER", help=const.CVE_HELP)
    cvescan_ap.add_argument("-p", "--priority", help=const.PRIORITY_HELP, choices=["critical","high","medium","all"], default="high")
    cvescan_ap.add_argument("-s", "--silent", action="store_true", default=False, help=const.SILENT_HELP)
    cvescan_ap.add_argument("-m", "--manifest", help=const.MANIFEST_HELP,choices=acceptable_codenames)
    cvescan_ap.add_argument("-f", "--file", metavar="manifest-file", help=const.FILE_HELP)
    cvescan_ap.add_argument("-n", "--nagios", action="store_true", default=False, help=const.NAGIOS_HELP)
    cvescan_ap.add_argument("-l", "--list", action="store_true", default=False, help=const.LIST_HELP)
    cvescan_ap.add_argument("-r", "--reuse", action="store_true", default=False, help=const.REUSE_HELP)
    cvescan_ap.add_argument("-t", "--test", action="store_true", default=False, help=const.TEST_HELP)
    cvescan_ap.add_argument("-u", "--updates", action="store_true", default=False, help=const.UPDATES_HELP)
    cvescan_ap.add_argument("-v", "--verbose", action="store_true", default=False, help=const.VERBOSE_HELP)
    cvescan_ap.add_argument("-x", "--experimental", action="store_true", default=False, help=const.EXPERIMENTAL_HELP)

    return cvescan_ap.parse_args()

def raise_on_invalid_args(args):
    raise_on_invalid_cve(args)
    raise_on_invalid_combinations(args)

def raise_on_invalid_cve(args):
    if (args.cve is not None) and (not re.match("^CVE-[0-9]{4}-[0-9]{4,}$", args.cve)):
        raise ValueError("Invalid CVE ID (%s)" % args.cve)

def raise_on_invalid_combinations(args):
    raise_on_invalid_manifest_options(args)
    raise_on_invalid_nagios_options(args)
    raise_on_invalid_test_options(args)
    raise_on_invalid_silent_options(args)

def raise_on_invalid_manifest_options(args):
    if args.manifest and args.reuse:
        raise_incompatible_arguments_error(FMT_MANIFEST_OPTION, FMT_REUSE_OPTION)

    if args.manifest and args.test:
        raise_incompatible_arguments_error(FMT_MANIFEST_OPTION, FMT_TEST_OPTION)

    if args.file and not args.manifest:
        raise ArgumentError("Cannot specify -f|--file argument without -m|--manifest.")

def raise_on_invalid_nagios_options(args):
    if not args.nagios:
        return

    if args.cve:
        raise_incompatible_arguments_error(FMT_NAGIOS_OPTION, FMT_CVE_OPTION)

    if args.silent:
        raise_incompatible_arguments_error(FMT_NAGIOS_OPTION, FMT_SILENT_OPTION)

    if args.updates:
        raise_incompatible_arguments_error(FMT_NAGIOS_OPTION, FMT_UPDATES_OPTION)

def raise_on_invalid_test_options(args):
    if not args.test:
        return

    if args.cve:
        raise_incompatible_arguments_error(FMT_TEST_OPTION, FMT_CVE_OPTION)

    if args.experimental:
        raise_incompatible_arguments_error(FMT_TEST_OPTION, FMT_EXPERIMENTAL_OPTION)

    if args.file:
        raise_incompatible_arguments_error(FMT_TEST_OPTION, FMT_FILE_OPTION)

    if args.manifest:
        raise_incompatible_arguments_error(FMT_TEST_OPTION, FMT_MANIFEST_OPTION)

    if args.nagios:
        raise_incompatible_arguments_error(FMT_TEST_OPTION, FMT_NAGIOS_OPTION)

    if args.reuse:
        raise_incompatible_arguments_error(FMT_TEST_OPTION, FMT_REUSE_OPTION)

    if args.silent:
        raise_incompatible_arguments_error(FMT_TEST_OPTION, FMT_SILENT_OPTION)

    if args.updates:
        raise_incompatible_arguments_error(FMT_TEST_OPTION, FMT_UPDATES_OPTION)

def raise_on_invalid_silent_options(args):
    if not args.silent:
        return

    if not args.cve:
        raise ArgumentError("Cannot specify %s argument without %s." % (FMT_SILENT_OPTION, FMT_CVE_OPTION))

    if args.verbose:
        raise_incompatible_arguments_error(FMT_SILENT_OPTION, FMT_VERBOSE_OPTION)

def raise_incompatible_arguments_error(arg1, arg2):
    raise ArgumentError("The %s and %s options are incompatible and may not " \
            "be specified together." % (arg1, arg2))

def scan_for_cves(current_time, verbose_oscap_options, oval_file, scriptdir, xslt_file, extra_sed, priority):
    try:
        run_oscap_eval(current_time, verbose_oscap_options, oval_file, scriptdir)
        run_oscap_generate_report(current_time, scriptdir)
    except OpenSCAPError as ose:
        error_exit("Failed to run oscap: %s" % ose)
    except Exception as ex:
        error_exit(ex)

    cve_list_all_filtered = run_xsltproc_all(priority, xslt_file, extra_sed)
    LOGGER.debug("%d vulnerabilities found with priority of %s or higher:" % (len(cve_list_all_filtered), priority))
    LOGGER.debug(cve_list_all_filtered)

    cve_list_fixable_filtered = run_xsltproc_fixable(priority, xslt_file, extra_sed)
    LOGGER.debug("%s CVEs found with priority of %s or higher that can be " \
            "fixed with package updates:" % (len(cve_list_fixable_filtered), priority))
    LOGGER.debug(cve_list_fixable_filtered)

    return (cve_list_all_filtered, cve_list_fixable_filtered)

def run_oscap_eval(current_time, verbose_oscap_options, oval_file, scriptdir):
    if not os.path.isfile(RESULTS) or ((current_time - math.trunc(os.path.getmtime(RESULTS))) > EXPIRE):
        LOGGER.debug("Running oval scan oscap oval eval %s --results %s %s (output logged to %s/%s)" % \
                (verbose_oscap_options, RESULTS, oval_file, scriptdir, OVAL_LOG))

        # TODO: use openscap python binding instead of os.system
        return_val = os.system("oscap oval eval %s --results \"%s\" \"%s\" >%s 2>&1" % \
                (verbose_oscap_options, RESULTS, oval_file, OVAL_LOG))
        if return_val != 0:
            # TODO: improve error message
            raise OpenSCAPError("Failed to run oval scan: returned %d" % return_val)

def run_oscap_generate_report(current_time, scriptdir):
    if not os.path.isfile(REPORT) or ((current_time - math.trunc(os.path.getmtime(REPORT))) > EXPIRE):
        LOGGER.debug("Generating html report %s/%s from results xml %s/%s " \
                "(output logged to %s/%s)" % (scriptdir, REPORT, scriptdir, RESULTS, scriptdir, OVAL_LOG))

        # TODO: use openscap python binding instead of os.system
        return_val = os.system("oscap oval generate report --output %s %s >>%s 2>&1" % (REPORT, RESULTS, OVAL_LOG))
        if return_val != 0:
            # TODO: improve error message
            raise OpenSCAPError("Failed to generate oval report: returned %d" % return_val)

        LOGGER.debug("Open %s/%s in a browser to see complete and unfiltered scan results" % (os.getcwd(), REPORT))

def run_xsltproc_all(priority, xslt_file, extra_sed):
    LOGGER.debug("Running xsltproc to generate CVE list - fixable/unfixable and filtered by priority")

    cmd = "xsltproc --stringparam showAll true --stringparam priority \"%s\"" \
          " \"%s\" \"%s\" | sed -e /^$/d %s" % (priority, xslt_file, RESULTS, extra_sed)
    cve_list_all_filtered = os.popen(cmd).read().split('\n')

    while("" in cve_list_all_filtered):
        cve_list_all_filtered.remove("")

    return cve_list_all_filtered

def run_xsltproc_fixable(priority, xslt_file, extra_sed):
    LOGGER.debug("Running xsltproc to generate CVE list - fixable and filtered by priority")

    cmd = "xsltproc --stringparam showAll false --stringparam priority \"%s\"" \
          " \"%s\" \"%s\" | sed -e /^$/d %s" % (priority, xslt_file, RESULTS, extra_sed)
    cve_list_fixable_filtered = os.popen(cmd).read().split('\n')

    while("" in cve_list_fixable_filtered):
        cve_list_fixable_filtered.remove("")

    return cve_list_fixable_filtered

def cleanup_all_files_from_past_run(oval_file, oval_zip, manifest_file):
    cleanup_files([oval_file, oval_zip, manifest_file, REPORT, RESULTS,
                   OVAL_LOG, DEBUG_LOG])

def cleanup_oscap_files_from_past_run():
    cleanup_files([REPORT, RESULTS, OVAL_LOG, DEBUG_LOG])

def cleanup_files(files):
    LOGGER.debug("Removing files: %s" % (" ".join(files)))
    for i in files:
        rmfile(i)

def run_testmode(scriptdir, verbose_oscap_options, current_time, xslt_file):
    LOGGER.info("Running in test mode.")
    cleanup_oscap_files_from_past_run()

    LOGGER.info("Setting priority filter to 'all'")
    priority = "all"

    LOGGER.info("Disabling URLs in output")
    extra_sed = ""

    oval_file = "%s/com.ubuntu.test.cve.oval.xml" % scriptdir

    if os.path.isfile(oval_file):
        LOGGER.info("Using OVAL file %s to test oscap" % oval_file)
    else:
        error_exit("Missing test OVAL file at '%s', this file should have installed with cvescan" % oval_file)

    (cve_list_all_filtered, cve_list_fixable_filtered) = \
        scan_for_cves(current_time, verbose_oscap_options, oval_file, scriptdir, xslt_file, extra_sed, priority)

    success_1 = test_filter_active_cves(cve_list_all_filtered)
    success_2 = test_identify_fixable_cves(cve_list_fixable_filtered)

    # TODO: scan_for_cves shouldn't error_exit, otherwise cleanup may not occur
    # clean up after tests
    cleanup_oscap_files_from_past_run()

    if not (success_1 and success_2):
        sys.exit(4)

    sys.exit(0)

def test_filter_active_cves(cve_list_all_filtered):
    if ((len(cve_list_all_filtered) == 2)
            and ("CVE-1970-0300" in cve_list_all_filtered)
            and ("CVE-1970-0400" in cve_list_all_filtered)
            and ("CVE-1970-0200" not in cve_list_all_filtered)
            and ("CVE-1970-0500" not in cve_list_all_filtered)):
        LOGGER.info("SUCCESS: Filter Active CVEs")
        return True

    LOGGER.error("FAILURE: Filter Active CVEs")
    return False

def test_identify_fixable_cves(cve_list_fixable_filtered):
    if ((len(cve_list_fixable_filtered) == 1)
            and ("CVE-1970-0400" in cve_list_fixable_filtered)):
        LOGGER.info("SUCCESS: Identify Fixable/Updatable CVEs")
        return True

    LOGGER.error("FAILURE: Identify Fixable/Updatable CVEs")
    return False

def retrieve_oval_file(oval_base_url, oval_zip, oval_file):
    LOGGER.debug("Downloading %s/%s" % (oval_base_url, oval_zip))
    download(os.path.join(oval_base_url, oval_zip), oval_zip)

    LOGGER.debug("Unzipping %s" % oval_zip)
    bz2decompress(oval_zip, oval_file)

def should_download_cached_file(filename, current_time):
    return (not os.path.isfile(filename)) or cached_file_expired(filename, current_time)

def cached_file_expired(filename, current_time):
    return (current_time - math.trunc(os.path.getmtime(filename))) > EXPIRE

def main():
    global LOGGER
    cvescan_args = parse_args()
    try:
        raise_on_invalid_args(cvescan_args)
    except (ArgumentError, ValueError) as err:
        error_exit("Invalid option or argument: %s" % err)

    try:
        if cvescan_args.manifest:
            distrib_codename = cvescan_args.manifest
        else:
            distrib_codename = get_ubuntu_codename()
    except (FileNotFoundError, PermissionError) as err:
        error_exit("Failed to determine the correct Ubuntu codename: %s" % err)
    except DistribIDError as di:
        error_exit("Invalid distribution: %s" % di)

    testmode = cvescan_args.test

    # Block of variables.
    cve = cvescan_args.cve
    oval_base_url = "https://people.canonical.com/~ubuntu-security/oval"
    oval_file = str("com.ubuntu.%s.cve.oval.xml" % distrib_codename)
    oval_zip = str("%s.bz2" % oval_file)
    remove = not cvescan_args.reuse
    nagios = cvescan_args.nagios
    manifest = False
    manifest_url = None
    manifest_file = cvescan_args.file if cvescan_args.file else DEFAULT_MANIFEST_FILE
    download_manifest = False if cvescan_args.file else True
    if cvescan_args.verbose:
        LOGGER.setLevel(logging.DEBUG)
    elif cvescan_args.silent:
        LOGGER = get_null_logger()
    if cvescan_args.manifest != None:
        manifest = True
        remove = True
        release = cvescan_args.manifest
        oval_file = str("oci.%s" % oval_file)
        oval_zip = str("%s.bz2" % oval_file)
        manifest_url = str(MANIFEST_URL_TEMPLATE % (release, release))
        manifest_file = os.path.abspath(manifest_file)
        if cvescan_args.file and not os.path.isfile(manifest_file):
            # TODO: mention snap confinement in error message
            error_exit("Cannot find manifest file \"%s\". Current directory is \"%s\"." % (manifest_file, os.getcwd()))
    if cvescan_args.experimental:
        oval_base_url = "%s/alpha" % oval_base_url
        oval_file = "alpha.%s" % oval_file
        oval_zip = "%s.bz2" % oval_file
        LOGGER.debug("Running in experimental mode, using 'alpha' OVAL file from %s/%s" % (oval_base_url, oval_zip))
    all_cve = not cvescan_args.updates
    priority = cvescan_args.priority
    now = math.trunc(time.time()) # Transcription of `date +%s`
    scriptdir = os.path.abspath(os.path.dirname(sys.argv[0]))
    # TODO: Find a better way to locate this file than relying on it being in the
    #       same directory as this script
    xslt_file = str("%s/text.xsl" % scriptdir)
    verbose_oscap_options = "" if not cvescan_args.verbose else "--verbose WARNING --verbose-log-file %s" % DEBUG_LOG
    package_count = int(os.popen("dpkg -l | grep -E -c '^ii'").read())
    # TODO: does extra_sed need updating?
    extra_sed = "-e s@^@http://people.canonical.com/~ubuntu-security/cve/@"
    if cvescan_args.list == True:
        extra_sed = ""



    ###########
    snap_user_common = None
    try:
        snap_user_common = os.environ["SNAP_USER_COMMON"]
        LOGGER.debug("Running as a snap, changing to '%s' directory." % snap_user_common)
        LOGGER.debug("Downloaded files, log files and temporary reports will " \
                "be in '%s'" % snap_user_common)

        try:
            os.chdir(snap_user_common)
        except:
            error_exit("failed to cd to %s" % snap_user_common)
    except KeyError:
        pass

    if snap_user_common == None:
        for i in [["oscap", "libopenscap8"], ["xsltproc", "xsltproc"]]:
            if which(i[0]) == None:
                error_exit("Missing %s command. Run 'sudo apt install %s'" % (i[0], i[1]))

    if not os.path.isfile(xslt_file):
        error_exit("Missing text.xsl file at '%s', this file should have installed with cvescan" % xslt_file)

    if os.path.isfile(DPKG_LOG) and os.path.isfile(RESULTS):
        package_change_ts = math.trunc(os.path.getmtime(DPKG_LOG))
        results_ts = math.trunc(os.path.getmtime(RESULTS))
        if package_change_ts > results_ts:
            LOGGER.debug("Removing %s file because it is older than %s" % (RESULTS, DPKG_LOG))
            rmfile(RESULTS)

    if testmode:
        run_testmode(scriptdir, verbose_oscap_options, now, xslt_file)

    if all_cve:
      LOGGER.debug("Reporting on ALL CVEs, not just those that can be fixed by updates")
    if nagios:
      LOGGER.debug("Running in Nagios Mode")

    LOGGER.debug("CVE Priority filter is '%s'" % priority)
    LOGGER.debug("Installed package count is %s" % package_count)

    if remove:
        LOGGER.debug("Removing cached report, results, and manifest files")
        cleanup_all_files_from_past_run(oval_file, oval_zip, DEFAULT_MANIFEST_FILE)

    if should_download_cached_file(oval_file, now):
        cleanup_oscap_files_from_past_run()
        retrieve_oval_file(oval_base_url, oval_zip, oval_file)

    if manifest:
        if download_manifest:
            LOGGER.debug("Downloading %s" % manifest_url)
            download(manifest_url, DEFAULT_MANIFEST_FILE)
        else:
            copyfile(manifest_file, "manifest")

        package_count = int(os.popen("wc -l %s | cut -f1 -d' '" % manifest_file).read())
        LOGGER.debug("Manifest package count is %s" % package_count)

    (cve_list_all_filtered, cve_list_fixable_filtered) = \
        scan_for_cves(now, verbose_oscap_options, oval_file, scriptdir, xslt_file, extra_sed, priority)

    if snap_user_common == None or len(snap_user_common) == 0:
      LOGGER.debug("Full HTML report available in %s/%s" % (scriptdir, REPORT))

    LOGGER.debug("Normal non-verbose output will appear below\n")

    if nagios:
        if cve_list_fixable_filtered == None or len(cve_list_fixable_filtered) == 0:
            LOGGER.info("OK: no known %s or higher CVEs that can be fixed by updating" % priority)
            sys.exit(0)
        elif cve_list_fixable_filtered != None and len(cve_list_fixable_filtered) != 0:
            LOGGER.info("CRITICAL: %d CVEs with priority %s or higher that can be " \
                    "fixed with package updates" % (len(cve_list_fixable_filtered), priority))
            LOGGER.info('\n'.join(cve_list_fixable_filtered))
            sys.exit(2)
        elif cve_list_all_filtered != None and len(cve_list_all_filtered) != 0:
            LOGGER.info("WARNING: %s CVEs with priority %s or higher" % (len(cve_list_all_filtered), priority))
            LOGGER.info('\n'.join(cve_list_all_filtered))
            sys.exit(1)
        else:
            LOGGER.info("UNKNOWN: something went wrong with %s" % sys.args[0])
            sys.exit(3)
    elif cve != None and len(cve) != 0:
        if cve in cve_list_fixable_filtered:
            LOGGER.info("%s patch available to install" % cve)
            sys.exit(1)
        elif cve in cve_list_all_filtered:
            LOGGER.info("%s patch not available" % cve)
            sys.exit(1)
        else:
            LOGGER.info("%s patch applied or system not known to be affected" % cve)
            sys.exit(0)
    else:
        if all_cve:
            LOGGER.info("Inspected %s packages. Found %s CVEs" % (package_count, len(cve_list_all_filtered)))
            if cve_list_all_filtered != None and len(cve_list_all_filtered) != 0:
                LOGGER.info('\n'.join(cve_list_all_filtered))
                sys.exit(1)
            else:
                sys.exit(0)
        else:
            LOGGER.info("Inspected %s packages. Found %s CVEs" % (package_count, len(cve_list_fixable_filtered)))
            if cve_list_fixable_filtered != None and len(cve_list_fixable_filtered) != 0:
                LOGGER.info('\n'.join(cve_list_fixable_filtered))
                sys.exit(1)
            else:
                sys.exit(0)

if __name__ == "__main__":
    main()
