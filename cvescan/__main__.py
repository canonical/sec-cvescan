#!/usr/bin/env python3

import argparse as ap
import bz2
import cvescan.constants as const
from cvescan.errors import ArgumentError, DistribIDError, OpenSCAPError
from cvescan.options import Options
from cvescan.sysinfo import SysInfo
import logging
import math
import pycurl
import os
from shutil import which,copyfile
import sys
from tabulate import tabulate

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

def scan_for_cves(opt, sysinfo):
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

def cleanup_cached_files(opt, sysinfo):
    if os.path.isfile(DPKG_LOG) and os.path.isfile(RESULTS):
        package_change_ts = math.trunc(os.path.getmtime(DPKG_LOG))
        results_ts = math.trunc(os.path.getmtime(RESULTS))
        if package_change_ts > results_ts:
            LOGGER.debug("Removing %s file because it is older than %s" % (RESULTS, DPKG_LOG))
            rmfile(RESULTS)

    if opt.remove:
        LOGGER.debug("Removing cached report, results, and manifest files")
        cleanup_all_files_from_past_run(opt.oval_file, opt.oval_zip, const.DEFAULT_MANIFEST_FILE)

    if os.path.isfile(opt.oval_file) and is_cached_file_expired(opt.oval_file, sysinfo.process_start_time):
        cleanup_oscap_files_from_past_run()

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

    if not os.path.isfile(opt.oval_file):
        error_exit("Missing test OVAL file at '%s', this file should have installed with cvescan" % oval_file)

    (cve_list_all_filtered, cve_list_fixable_filtered) = scan_for_cves(opt, sysinfo)

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

def is_cached_file_expired(filename, current_time):
    return (current_time - math.trunc(os.path.getmtime(filename))) > EXPIRE

def log_config_options(opt):
    LOGGER.debug("Config Options")
    table = [
        ["Test Mode", opt.test_mode],
        ["Manifest Mode", opt.manifest_mode],
        ["Experimental Mode", opt.experimental_mode],
        ["Nagios Output Mode", opt.nagios],
        ["Target Ubuntu Codename", opt.distrib_codename],
        ["OVAL File Path", opt.oval_file],
        ["OVAL URL", opt.oval_base_url],
        ["Manifest File", opt.manifest_file],
        ["Manifest URL", opt.manifest_url],
        ["Check Specific CVE", opt.cve],
        ["CVE Priority", opt.priority],
        ["Only Show Updates Available", (not opt.all_cve)],
        ["Reuse Cached Files", (not opt.remove)]]

    LOGGER.debug(tabulate(table))
    LOGGER.debug("")

def log_system_info(sysinfo):
    LOGGER.debug("System Info")
    table = [
        ["Local Ubuntu Codename", sysinfo.distrib_codename],
        ["Installed Package Count", sysinfo.package_count],
        ["CVEScan is a Snap", sysinfo.is_snap],
        ["$SNAP_USER_COMMON", sysinfo.snap_user_common],
        ["Scripts Directory", sysinfo.scriptdir],
        ["XSLT File", sysinfo.xslt_file]]

    LOGGER.debug(tabulate(table))
    LOGGER.debug("")

def run_manifest_mode(opt, sysinfo):
    if not opt.manifest_file:
        LOGGER.debug("Downloading %s" % opt.manifest_url)
        download(opt.manifest_url, const.DEFAULT_MANIFEST_FILE)
    else:
        copyfile(opt.manifest_file,const.DEFAULT_MANIFEST_FILE)

    # TODO: Find a better way of doing this or at least check return code
    package_count = int(os.popen("wc -l %s | cut -f1 -d' '" % const.DEFAULT_MANIFEST_FILE).read())
    LOGGER.debug("Manifest package count is %s" % package_count)

    return run_cvescan(opt, sysinfo, package_count)

def run_cvescan(opt, sysinfo, package_count):
    if not os.path.isfile(opt.oval_file):
        retrieve_oval_file(opt.oval_base_url, opt.oval_zip, opt.oval_file)

    (cve_list_all_filtered, cve_list_fixable_filtered) = \
        scan_for_cves(opt, sysinfo)

    LOGGER.debug("Full HTML report available in %s/%s" % (sysinfo.scriptdir, REPORT))

    return analyze_results(cve_list_all_filtered, cve_list_fixable_filtered, opt, package_count)

def analyze_results(cve_list_all_filtered, cve_list_fixable_filtered, opt, package_count):
    if opt.nagios:
        return analyze_nagios_results(cve_list_fixable_filtered, opt.priority)

    if opt.cve:
        return analyze_single_cve_results(cve_list_all_filtered, cve_list_fixable_filtered, opt.cve)

    if opt.all_cve:
        return analyze_cve_list_results(cve_list_all_filtered, package_count)

    return analyze_cve_list_results(cve_list_fixable_filtered, package_count)

def analyze_nagios_results(cve_list_fixable_filtered, priority):
    if cve_list_fixable_filtered == None or len(cve_list_fixable_filtered) == 0:
        return("OK: no known %s or higher CVEs that can be fixed by updating" % priority, 0)

    if cve_list_fixable_filtered != None and len(cve_list_fixable_filtered) != 0:
        results_msg = ("CRITICAL: %d CVEs with priority %s or higher that can " \
                "be fixed with package updates\n%s"
                % (len(cve_list_fixable_filtered), priority, '\n'.join(cve_list_fixable_filtered)))
        # TODO: This exit code conflicts with the error code returned by
        #       argparse if the CLI syntax is invalid.
        return (results_msg, 2)

    if cve_list_all_filtered != None and len(cve_list_all_filtered) != 0:
        results_msg = ("WARNING: %s CVEs with priority %s or higher\n%s"
            % (len(cve_list_all_filtered), priority, '\n'.join(cve_list_all_filtered)))
        return (results_msg, 1)
    
    return ("UNKNOWN: something went wrong with %s" % sys.args[0], 3)

def analyze_single_cve_results(cve_list_all_filtered, cve_list_fixable_filtered, cve):
    if cve in cve_list_fixable_filtered:
        return ("%s patch available to install" % cve, 1)

    if cve in cve_list_all_filtered:
        return ("%s patch not available" % cve, 1)

    return ("%s patch applied or system not known to be affected" % cve, 0)

def analyze_cve_list_results(cve_list, package_count):
    results_msg = "Inspected %s packages. Found %s CVEs" % (package_count, len(cve_list))

    if cve_list != None and len(cve_list) != 0:
        results_msg = results_msg + '\n'.join(cve_list)
        return (results_msg, 1)

    return (results_msg, 0)

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

    log_config_options(opt)
    log_system_info(sysinfo)

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

    if opt.test_mode:
        run_testmode(sysinfo, opt)

    cleanup_cached_files(opt, sysinfo)

    if opt.manifest_mode:
        (results, return_code) = run_manifest_mode(opt, sysinfo)
    else:
        (results, return_code) = run_cvescan(opt, sysinfo, sysinfo.package_count)

    LOGGER.info(results)
    sys.exit(return_code)

if __name__ == "__main__":
    main()
