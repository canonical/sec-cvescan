#!/usr/bin/env python3

import sys
import os
import math
import argparse as ap
from shutil import which,copyfile
import pycurl
import bz2
import cvescan.constants as const
from cvescan.options import Options
from cvescan.errors import ArgumentError, DistribIDError, OpenSCAPError
from cvescan.sysinfo import SysInfo
import logging

def set_output_verbosity(args):
    if args.silent:
        return get_null_logger()

    logger = logging.getLogger("cvescan.stdout")

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
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

LOGGER = get_null_logger()

DPKG_LOG = "/var/log/dpkg.log"
EXPIRE = 86400
OVAL_LOG = "oval.log"
REPORT = "report.htm"
RESULTS = "results.xml"

def error_exit(msg, code=4):
    print("Error: %s" % msg, file=sys.stderr)
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

def scan_for_cves(sysinfo, opt):
    try:
        run_oscap_eval(sysinfo, opt)
        run_oscap_generate_report(sysinfo.process_start_time, sysinfo.scriptdir)
    except OpenSCAPError as ose:
        error_exit("Failed to run oscap: %s" % ose)
    except Exception as ex:
        error_exit(ex)

    cve_list_all_filtered = run_xsltproc_all(opt.priority, sysinfo.xslt_file, opt.extra_sed)
    LOGGER.debug("%d vulnerabilities found with priority of %s or higher:" % (len(cve_list_all_filtered), opt.priority))
    LOGGER.debug(cve_list_all_filtered)

    cve_list_fixable_filtered = run_xsltproc_fixable(opt.priority, sysinfo.xslt_file, opt.extra_sed)
    LOGGER.debug("%s CVEs found with priority of %s or higher that can be " \
            "fixed with package updates:" % (len(cve_list_fixable_filtered), opt.priority))
    LOGGER.debug(cve_list_fixable_filtered)

    return (cve_list_all_filtered, cve_list_fixable_filtered)

def run_oscap_eval(sysinfo, opt):
    if not os.path.isfile(RESULTS) or ((sysinfo.process_start_time - math.trunc(os.path.getmtime(RESULTS))) > EXPIRE):
        LOGGER.debug("Running oval scan oscap oval eval %s --results %s %s (output logged to %s/%s)" % \
                (opt.verbose_oscap_options, RESULTS, opt.oval_file, sysinfo.scriptdir, OVAL_LOG))

        # TODO: use openscap python binding instead of os.system
        return_val = os.system("oscap oval eval %s --results \"%s\" \"%s\" >%s 2>&1" % \
                (opt.verbose_oscap_options, RESULTS, opt.oval_file, OVAL_LOG))
        if return_val != 0:
            # TODO: improve error message
            raise OpenSCAPError("Failed to run oval scan: returned %d" % return_val)

def run_oscap_generate_report(process_start_time, scriptdir):
    if not os.path.isfile(REPORT) or ((process_start_time - math.trunc(os.path.getmtime(REPORT))) > EXPIRE):
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
                   OVAL_LOG, const.DEBUG_LOG])

def cleanup_oscap_files_from_past_run():
    cleanup_files([REPORT, RESULTS, OVAL_LOG, const.DEBUG_LOG])

def cleanup_files(files):
    LOGGER.debug("Removing files: %s" % (" ".join(files)))
    for i in files:
        rmfile(i)

def run_testmode(sysinfo, opt):
    LOGGER.info("Running in test mode.")
    cleanup_oscap_files_from_past_run()

    # TODO: Log the state of all options at initialization and get rid of these.
    LOGGER.info("Setting priority filter to 'all'")
    LOGGER.info("Disabling URLs in output")

    if os.path.isfile(opt.oval_file):
        LOGGER.info("Using OVAL file %s to test oscap" % opt.oval_file)
    else:
        error_exit("Missing test OVAL file at '%s', this file should have installed with cvescan" % oval_file)

    (cve_list_all_filtered, cve_list_fixable_filtered) = \
        scan_for_cves(sysinfo, opt)

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

def should_replace_cached_file(filename, current_time):
    return (not os.path.isfile(filename)) or cached_file_expired(filename, current_time)

def cached_file_expired(filename, current_time):
    return (current_time - math.trunc(os.path.getmtime(filename))) > EXPIRE

def main():
    global LOGGER

    args = parse_args()

    # Configure debug logging as early as possible
    LOGGER = set_output_verbosity(args)

    try:
        sysinfo = SysInfo(LOGGER)
    except (FileNotFoundError, PermissionError) as err:
        error_exit("Failed to determine the correct Ubuntu codename: %s" % err)
    except DistribIDError as di:
        error_exit("Invalid linux distribution detected, CVEScan must be run on Ubuntu: %s" % di)

    try:
        opt = Options(args, sysinfo)
    except (ArgumentError, ValueError) as err:
        error_exit("Invalid option or argument: %s" % err)

    #LOGGER.debug("Running in experimental mode, using 'alpha' OVAL file from %s/%s" % (oval_base_url, oval_zip))

    ###########
    if sysinfo.is_snap:
        LOGGER.debug("Running as a snap, changing to '%s' directory." % sysinfo.snap_user_common)
        LOGGER.debug("Downloaded files, log files and temporary reports will " \
                "be in '%s'" % sysinfo.snap_user_common)

        try:
            os.chdir(sysinfo.snap_user_common)
        except:
            error_exit("failed to cd to %s" % sysinfo.snap_user_common)

    # TODO: Consider moving this check to SysInfo, though it may be moot if we
    #       can use python bindings for oscap and xsltproc
    if not sysinfo.is_snap:
        for i in [["oscap", "libopenscap8"], ["xsltproc", "xsltproc"]]:
            if which(i[0]) == None:
                error_exit("Missing %s command. Run 'sudo apt install %s'" % (i[0], i[1]))

    if not os.path.isfile(sysinfo.xslt_file):
        error_exit("Missing text.xsl file at '%s', this file should have installed with cvescan" % sysinfo.xslt_file)

    if os.path.isfile(DPKG_LOG) and os.path.isfile(RESULTS):
        package_change_ts = math.trunc(os.path.getmtime(DPKG_LOG))
        results_ts = math.trunc(os.path.getmtime(RESULTS))
        if package_change_ts > results_ts:
            LOGGER.debug("Removing %s file because it is older than %s" % (RESULTS, DPKG_LOG))
            rmfile(RESULTS)

    if opt.test_mode:
        run_testmode(sysinfo, opt)

    if opt.all_cve:
      LOGGER.debug("Reporting on ALL CVEs, not just those that can be fixed by updates")
    if opt.nagios:
      LOGGER.debug("Running in Nagios Mode")

    LOGGER.debug("CVE Priority filter is '%s'" % opt.priority)

    if opt.remove:
        LOGGER.debug("Removing cached report, results, and manifest files")
        cleanup_all_files_from_past_run(opt.oval_file, opt.oval_zip, const.DEFAULT_MANIFEST_FILE)

    if should_replace_cached_file(opt.oval_file, sysinfo.process_start_time):
        cleanup_oscap_files_from_past_run()
        retrieve_oval_file(opt.oval_base_url, opt.oval_zip, opt.oval_file)

    if not opt.manifest_mode:
        package_count = int(os.popen("dpkg -l | grep -E -c '^ii'").read())
        LOGGER.debug("Installed package count is %s" % package_count)
    else:
        if not opt.manifest_file:
            LOGGER.debug("Downloading %s" % opt.manifest_url)
            download(opt.manifest_url, const.DEFAULT_MANIFEST_FILE)
        else:
            copyfile(opt.manifest_file,const.DEFAULT_MANIFEST_FILE)

        package_count = int(os.popen("wc -l %s | cut -f1 -d' '" % const.DEFAULT_MANIFEST_FILE).read())
        LOGGER.debug("Manifest package count is %s" % package_count)

    (cve_list_all_filtered, cve_list_fixable_filtered) = \
        scan_for_cves(sysinfo, opt)

    if not sysinfo.is_snap:
      LOGGER.debug("Full HTML report available in %s/%s" % (sysinfo.scriptdir, REPORT))

    LOGGER.debug("Normal non-verbose output will appear below\n")

    if opt.nagios:
        if cve_list_fixable_filtered == None or len(cve_list_fixable_filtered) == 0:
            LOGGER.info("OK: no known %s or higher CVEs that can be fixed by updating" % opt.priority)
            sys.exit(0)
        elif cve_list_fixable_filtered != None and len(cve_list_fixable_filtered) != 0:
            LOGGER.info("CRITICAL: %d CVEs with priority %s or higher that can be " \
                    "fixed with package updates" % (len(cve_list_fixable_filtered), opt.priority))
            LOGGER.info('\n'.join(cve_list_fixable_filtered))
            sys.exit(2)
        elif cve_list_all_filtered != None and len(cve_list_all_filtered) != 0:
            LOGGER.info("WARNING: %s CVEs with priority %s or higher" % (len(cve_list_all_filtered), opt.priority))
            LOGGER.info('\n'.join(cve_list_all_filtered))
            sys.exit(1)
        else:
            LOGGER.info("UNKNOWN: something went wrong with %s" % sys.args[0])
            sys.exit(3)
    elif opt.cve != None and len(opt.cve) != 0:
        if opt.cve in cve_list_fixable_filtered:
            LOGGER.info("%s patch available to install" % opt.cve)
            sys.exit(1)
        elif opt.cve in cve_list_all_filtered:
            LOGGER.info("%s patch not available" % opt.cve)
            sys.exit(1)
        else:
            LOGGER.info("%s patch applied or system not known to be affected" % opt.cve)
            sys.exit(0)
    else:
        if opt.all_cve:
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
