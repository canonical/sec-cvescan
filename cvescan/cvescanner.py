import cvescan.constants as const
import cvescan.downloader as downloader
from cvescan.errors import OpenSCAPError
import os
from shutil import copyfile
import sys

OVAL_LOG = "oval.log"
REPORT = "report.htm"
RESULTS = "results.xml"

class CVEScanner:
    def __init__(self, sysinfo, logger):
        self.sysinfo = sysinfo
        self.logger = logger

    def scan(self, opt):
        if opt.test_mode:
            return self._run_test_mode(opt)

        if opt.manifest_mode:
            return self._run_manifest_mode(opt)

        return self._run_cvescan(opt, self.sysinfo.package_count)

    def _run_test_mode(self, opt):
        self.logger.info("Running in test mode.")

        if not os.path.isfile(opt.oval_file):
            raise FileNotFoundError("Missing test OVAL file at '%s', this file " \
                    "should have installed with cvescan" % oval_file)

        (cve_list_all_filtered, cve_list_fixable_filtered) = self._scan_for_cves(opt)

        (results_1, success_1) = self._test_filter_active_cves(cve_list_all_filtered)
        (results_2, success_2) = self._test_identify_fixable_cves(cve_list_fixable_filtered)

        results = "%s\n%s" % (results_1, results_2)

        if not (success_1 and success_2):
            return (results, const.ERROR_RETURN_CODE)

        return (results, 0)

    def _test_filter_active_cves(self, cve_list_all_filtered):
        if ((len(cve_list_all_filtered) == 2)
                and ("CVE-1970-0300" in cve_list_all_filtered)
                and ("CVE-1970-0400" in cve_list_all_filtered)
                and ("CVE-1970-0200" not in cve_list_all_filtered)
                and ("CVE-1970-0500" not in cve_list_all_filtered)):
            return ("SUCCESS: Filter Active CVEs", True)

        return ("FAILURE: Filter Active CVEs", False)

    def _test_identify_fixable_cves(self, cve_list_fixable_filtered):
        if ((len(cve_list_fixable_filtered) == 1)
                and ("CVE-1970-0400" in cve_list_fixable_filtered)):
            return ("SUCCESS: Identify Fixable/Updatable CVEs", True)

        return ("FAILURE: Identify Fixable/Updatable CVEs", False)

    def _run_manifest_mode(self, opt):
        if not opt.manifest_file:
            self.logger.debug("Downloading %s" % opt.manifest_url)
            downloader.download(opt.manifest_url, const.DEFAULT_MANIFEST_FILE)
        else:
            copyfile(opt.manifest_file, const.DEFAULT_MANIFEST_FILE)

        package_count = _count_packages_in_manifest_file(const.DEFAULT_MANIFEST_FILE)
        self.logger.debug("Manifest package count is %s" % package_count)

        return self._run_cvescan(opt, package_count)

    def _run_cvescan(self, opt, package_count):
        if opt.download_oval_file:
            self._retrieve_oval_file(opt)

        (cve_list_all_filtered, cve_list_fixable_filtered) = \
            self._scan_for_cves(opt)

        self.logger.debug("Full HTML report available in %s/%s" % (self.sysinfo.scriptdir, REPORT))

        return _analyze_results(cve_list_all_filtered, cve_list_fixable_filtered, opt, package_count)

    def _retrieve_oval_file(self, opt):
        self.logger.debug("Downloading %s/%s" % (opt.oval_base_url, opt.oval_zip))
        downloader.download(os.path.join(opt.oval_base_url, opt.oval_zip), opt.oval_zip)

        self.logger.debug("Unzipping %s" % opt.oval_zip)
        downloader.bz2decompress(opt.oval_zip, opt.oval_file)

    def _scan_for_cves(self, opt):
        self._run_oscap_eval(opt)

        cve_list_all_filtered = self._run_xsltproc_all(opt)
        self.logger.debug("%d vulnerabilities found with priority of %s or higher:" % (len(cve_list_all_filtered), opt.priority))
        self.logger.debug(cve_list_all_filtered)

        cve_list_fixable_filtered = self._run_xsltproc_fixable(opt)
        self.logger.debug("%s CVEs found with priority of %s or higher that can be " \
                "fixed with package updates:" % (len(cve_list_fixable_filtered), opt.priority))
        self.logger.debug(cve_list_fixable_filtered)

        return (cve_list_all_filtered, cve_list_fixable_filtered)

    def _run_oscap_eval(self, opt):
        cmd = ("oscap oval eval %s --results \"%s\" --report \"%s\" \"%s\" >%s 2>&1"
                % (opt.verbose_oscap_options, RESULTS, REPORT, opt.oval_file, OVAL_LOG))
        self.logger.debug("Running '%s'" % cmd)
        self.logger.debug("Output logged to %s/%s" % (self.sysinfo.scriptdir, OVAL_LOG))

        # TODO: use openscap python binding instead of os.system
        return_val = os.system(cmd)
        if return_val != 0:
            # TODO: improve error message
            raise OpenSCAPError("Failed to run oval scan: returned %d" % return_val)

    # TODO: Use python libxml2 bindings instead of os.popen()
    def _run_xsltproc_all(self, opt):
        self.logger.debug("Running xsltproc to generate CVE list - fixable/unfixable and filtered by priority")

        cmd = "xsltproc --stringparam showAll true --stringparam priority \"%s\"" \
              " \"%s\" \"%s\" | sed -e /^$/d %s" % (opt.priority, self.sysinfo.xslt_file, RESULTS, opt.extra_sed)
        cve_list_all_filtered = os.popen(cmd).read().split('\n')

        while("" in cve_list_all_filtered):
            cve_list_all_filtered.remove("")

        return cve_list_all_filtered

    def _run_xsltproc_fixable(self, opt):
        self.logger.debug("Running xsltproc to generate CVE list - fixable and filtered by priority")

        cmd = "xsltproc --stringparam showAll false --stringparam priority \"%s\"" \
              " \"%s\" \"%s\" | sed -e /^$/d %s" % (opt.priority, self.sysinfo.xslt_file, RESULTS, opt.extra_sed)
        cve_list_fixable_filtered = os.popen(cmd).read().split('\n')

        while("" in cve_list_fixable_filtered):
            cve_list_fixable_filtered.remove("")

        return cve_list_fixable_filtered

def _count_packages_in_manifest_file(manifest_file):
    with open(manifest_file) as mf:
        package_count = len(mf.readlines())

    return package_count

# TODO: create a new module that is responsible for analysing and formatting output
def _analyze_results(cve_list_all_filtered, cve_list_fixable_filtered, opt, package_count):
    if opt.nagios_mode:
        return _analyze_nagios_results(cve_list_all_filtered, cve_list_fixable_filtered, opt.priority)

    if opt.cve:
        return _analyze_single_cve_results(cve_list_all_filtered, cve_list_fixable_filtered, opt.cve)

    return _analyze_cve_list_results(opt, cve_list_all_filtered, cve_list_fixable_filtered, package_count)

def _analyze_nagios_results(cve_list_all_filtered, cve_list_fixable_filtered, priority):
    if len(cve_list_all_filtered) == 0:
        results_msg = "OK: no known %s or higher CVEs that can be fixed by updating" % priority
        return_code = const.NAGIOS_OK_RETURN_CODE
    elif len(cve_list_all_filtered) != 0 and len(cve_list_fixable_filtered) == 0:
        results_msg = ("WARNING: %s CVEs with priority %s or higher affect this system\n%s"
            % (len(cve_list_all_filtered), priority, '\n'.join(cve_list_all_filtered)))
        return_code = const.NAGIOS_WARNING_RETURN_CODE
    else:
        results_msg = ("CRITICAL: %d CVEs with priority %s or higher affect "
                "this system and can be fixed with package updates\n%s"
                % (len(cve_list_fixable_filtered), priority, '\n'.join(cve_list_fixable_filtered)))
        return_code = const.NAGIOS_CRITICAL_RETURN_CODE

    return (results_msg, return_code)

def _analyze_single_cve_results(cve_list_all_filtered, cve_list_fixable_filtered, cve):
    if cve in cve_list_fixable_filtered:
        return ("A patch is available to fix %s." % cve, const.PATCH_AVAILABLE_RETURN_CODE)

    if cve in cve_list_all_filtered:
        return ("%s affects this system, but no patch is available." % cve, const.SYSTEM_VULNERABLE_RETURN_CODE)

    return ("This system is not known to be affected by %s." % cve, const.SUCCESS_RETURN_CODE)

def _analyze_cve_list_results(opt, cve_list_all_filtered, cve_list_fixable_filtered, package_count):
    inspected_msg = "Inspected %d packages." % package_count

    if len(cve_list_all_filtered) == 0:
        results_msg = "%s No CVEs of priority \"%s\" or higher affect this system" % (inspected_msg, opt.priority)
        return_code = const.SUCCESS_RETURN_CODE
    else:
        results_msg = ("%s %d CVEs of priority \"%s\" or higher affect this system."
            % (inspected_msg, len(cve_list_all_filtered), opt.priority))

        if opt.all_cve:
            results_msg = ("%s\n\nAll CVEs affecting this system:\n\t%s"
                % (results_msg, '\n\t'.join(cve_list_all_filtered)))

        if len(cve_list_fixable_filtered) != 0:
            results_msg = ("%s\n\nThe following %d CVEs can be fixed by installing updates:\n\t%s"
                % (results_msg, len(cve_list_fixable_filtered), '\n\t'.join(cve_list_fixable_filtered)))
            return_code = const.PATCH_AVAILABLE_RETURN_CODE
        else:
            return_code = const.SYSTEM_VULNERABLE_RETURN_CODE

    return (results_msg, return_code)
