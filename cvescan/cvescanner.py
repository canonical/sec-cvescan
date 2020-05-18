import json
import os
import re
from shutil import copyfile

import apt_pkg

import cvescan.constants as const
import cvescan.downloader as downloader

ESM_VERSION_RE = re.compile(r"[+~]esm\d+")


class CVEScanner:
    def __init__(self, sysinfo, logger):
        apt_pkg.init_system()

        self.sysinfo = sysinfo
        self.logger = logger

    def scan(self, opt):
        if opt.manifest_mode:
            return self._run_manifest_mode(opt)

        return self._run_cvescan(opt, self.sysinfo.package_count)

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

        with open(opt.oval_file) as oval_file:
            cve_status = json.load(oval_file)

        affected_cves = self._scan_for_cves(cve_status, opt)
        # TODO: get correct priority filter
        (cve_list_all_filtered, cve_list_fixable_filtered) = self.apply_filters(
            affected_cves, opt
        )

        cve_list_all_filtered = [cve[0] for cve in cve_list_all_filtered]
        cve_list_fixable_filtered = [cve[0] for cve in cve_list_fixable_filtered]

        # TODO: This removes duplicates. It can go away once output is overhauled.
        cve_list_all_filtered = list(set(cve_list_all_filtered))
        cve_list_fixable_filtered = list(set(cve_list_fixable_filtered))

        # TODO: This should be handled by whatever handles the output. It should
        #       also sort numerically so that CVE-2020-12826 is after CVE-2020-1747.
        cve_list_all_filtered.sort()
        cve_list_fixable_filtered.sort()

        return _analyze_results(
            cve_list_all_filtered, cve_list_fixable_filtered, opt, package_count
        )

    def _retrieve_oval_file(self, opt):
        self.logger.debug("Downloading %s/%s" % (opt.oval_base_url, opt.oval_zip))
        downloader.download(os.path.join(opt.oval_base_url, opt.oval_zip), opt.oval_zip)

        self.logger.debug("Unzipping %s" % opt.oval_zip)
        downloader.bz2decompress(opt.oval_zip, opt.oval_file)

    def _scan_for_cves(self, cve_status, opt):
        affected_cves = list()

        for (cve_id, uct_record) in cve_status.items():
            if self.sysinfo.distrib_codename not in uct_record["releases"]:
                continue

            for (src_pkg, src_pkg_record) in uct_record["releases"][
                self.sysinfo.distrib_codename
            ].items():
                if src_pkg_record["status"][0] in {"DNE", "not-affected"}:
                    continue

                for b in src_pkg_record["binaries"]:
                    if b not in self.sysinfo.installed_packages:
                        continue

                    if src_pkg_record["status"][0] in ["released", "released-esm"]:
                        vc = apt_pkg.version_compare(
                            self.sysinfo.installed_packages[b],
                            src_pkg_record["status"][1],
                        )
                        if vc >= 0:
                            continue

                        fixed_version = src_pkg_record["status"][1]
                        repository = src_pkg_record["repository"]
                    else:
                        fixed_version = "Unresolved"
                        repository = "N/A"

                    affected_cves.append(
                        [cve_id, uct_record["priority"], b, fixed_version, repository]
                    )

        return affected_cves

    def apply_filters(self, affected_cves, opt):
        priority_filter = {
            "untriaged",
            "negligible",
            "low",
            "medium",
            "high",
            "critical",
        }

        cve_list_all_filtered = []
        cve_list_fixable_filtered = []
        for cve in affected_cves:
            if cve[1] in priority_filter:
                cve_list_all_filtered.append(cve)
                if cve[3] != "Unresolved":
                    cve_list_fixable_filtered.append(cve)

        return (cve_list_all_filtered, cve_list_fixable_filtered)


def _count_packages_in_manifest_file(manifest_file):
    with open(manifest_file) as mf:
        package_count = len(mf.readlines())

    return package_count


# TODO: create a new module that is responsible for analysing and formatting output
def _analyze_results(
    cve_list_all_filtered, cve_list_fixable_filtered, opt, package_count
):
    if opt.nagios_mode:
        return _analyze_nagios_results(
            cve_list_all_filtered, cve_list_fixable_filtered, opt.priority
        )

    if opt.cve:
        return _analyze_single_cve_results(
            cve_list_all_filtered, cve_list_fixable_filtered, opt.cve
        )

    return _analyze_cve_list_results(
        opt, cve_list_all_filtered, cve_list_fixable_filtered, package_count
    )


def _analyze_nagios_results(cve_list_all_filtered, cve_list_fixable_filtered, priority):
    if len(cve_list_all_filtered) == 0:
        results_msg = (
            "OK: no known %s or higher CVEs that can be fixed by updating" % priority
        )
        return_code = const.NAGIOS_OK_RETURN_CODE
    elif len(cve_list_all_filtered) != 0 and len(cve_list_fixable_filtered) == 0:
        results_msg = (
            "WARNING: %s CVEs with priority %s or higher affect this system\n%s"
            % (len(cve_list_all_filtered), priority, "\n".join(cve_list_all_filtered))
        )
        return_code = const.NAGIOS_WARNING_RETURN_CODE
    else:
        results_msg = (
            "CRITICAL: %d CVEs with priority %s or higher affect "
            "this system and can be fixed with package updates\n%s"
            % (
                len(cve_list_fixable_filtered),
                priority,
                "\n".join(cve_list_fixable_filtered),
            )
        )
        return_code = const.NAGIOS_CRITICAL_RETURN_CODE

    return (results_msg, return_code)


def _analyze_single_cve_results(cve_list_all_filtered, cve_list_fixable_filtered, cve):
    if cve in cve_list_fixable_filtered:
        return (
            "A patch is available to fix %s." % cve,
            const.PATCH_AVAILABLE_RETURN_CODE,
        )

    if cve in cve_list_all_filtered:
        return (
            "%s affects this system, but no patch is available." % cve,
            const.SYSTEM_VULNERABLE_RETURN_CODE,
        )

    return (
        "This system is not known to be affected by %s." % cve,
        const.SUCCESS_RETURN_CODE,
    )


def _analyze_cve_list_results(
    opt, cve_list_all_filtered, cve_list_fixable_filtered, package_count
):
    inspected_msg = "Inspected %d packages." % package_count

    if len(cve_list_all_filtered) == 0:
        results_msg = '%s No CVEs of priority "%s" or higher affect this system' % (
            inspected_msg,
            opt.priority,
        )
        return_code = const.SUCCESS_RETURN_CODE
    else:
        results_msg = '%s %d CVEs of priority "%s" or higher affect this system.' % (
            inspected_msg,
            len(cve_list_all_filtered),
            opt.priority,
        )

        if opt.all_cve:
            results_msg = "%s\n\nAll CVEs affecting this system:\n\t%s" % (
                results_msg,
                "\n\t".join(cve_list_all_filtered),
            )

        if len(cve_list_fixable_filtered) != 0:
            results_msg = (
                "%s\n\nThe following %d CVEs can be fixed by installing updates:\n\t%s"
                % (
                    results_msg,
                    len(cve_list_fixable_filtered),
                    "\n\t".join(cve_list_fixable_filtered),
                )
            )
            return_code = const.PATCH_AVAILABLE_RETURN_CODE
        else:
            return_code = const.SYSTEM_VULNERABLE_RETURN_CODE

    return (results_msg, return_code)
