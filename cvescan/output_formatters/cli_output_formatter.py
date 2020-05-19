from typing import List

import cvescan.constants as const
from cvescan.output_formatters import AbstractOutputFormatter
from cvescan.scan_result import ScanResult


class CLIOutputFormatter(AbstractOutputFormatter):
    def format_output(self, scan_results: List[ScanResult]) -> (str, int):
        (cve_list_all_filtered, cve_list_fixable_filtered) = self._apply_filters(
            scan_results
        )

        return self._analyze_results(cve_list_all_filtered, cve_list_fixable_filtered)

    def _apply_filters(self, scan_results):
        priority_filtered_scan_results = self._filter_on_priority(scan_results)
        fixable_filtered_scan_results = self._filter_on_fixable(
            priority_filtered_scan_results
        )

        cve_list_all_filtered = [sr.cve_id for sr in priority_filtered_scan_results]
        cve_list_fixable_filtered = [sr.cve_id for sr in fixable_filtered_scan_results]

        # TODO: This removes duplicates. It can go away once output is overhauled.
        cve_list_all_filtered = list(set(cve_list_all_filtered))
        cve_list_fixable_filtered = list(set(cve_list_fixable_filtered))

        # TODO: This should be handled by whatever handles the output. It should
        #       also sort numerically so that CVE-2020-12826 is after CVE-2020-1747.
        cve_list_all_filtered.sort()
        cve_list_fixable_filtered.sort()

        return (cve_list_all_filtered, cve_list_fixable_filtered)

    def _analyze_results(self, cve_list_all_filtered, cve_list_fixable_filtered):
        if self.opt.nagios_mode:
            return self._analyze_nagios_results(
                cve_list_all_filtered, cve_list_fixable_filtered, self.opt.priority
            )

        if self.opt.cve:
            return self._analyze_single_cve_results(
                cve_list_all_filtered, cve_list_fixable_filtered, self.opt.cve
            )

        return self._analyze_cve_list_results(
            cve_list_all_filtered, cve_list_fixable_filtered
        )

    def _analyze_nagios_results(
        self, cve_list_all_filtered, cve_list_fixable_filtered, priority
    ):
        if len(cve_list_all_filtered) == 0:
            results_msg = (
                "OK: no known %s or higher CVEs that can be fixed by updating"
                % priority
            )
            return_code = const.NAGIOS_OK_RETURN_CODE
        elif len(cve_list_all_filtered) != 0 and len(cve_list_fixable_filtered) == 0:
            results_msg = (
                "WARNING: %s CVEs with priority %s or higher affect this system\n%s"
                % (
                    len(cve_list_all_filtered),
                    priority,
                    "\n".join(cve_list_all_filtered),
                )
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

    def _analyze_single_cve_results(
        self, cve_list_all_filtered, cve_list_fixable_filtered, cve
    ):
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
        self, cve_list_all_filtered, cve_list_fixable_filtered
    ):
        package_count = self._get_package_count()

        inspected_msg = "Inspected %d packages." % package_count

        if len(cve_list_all_filtered) == 0:
            results_msg = '%s No CVEs of priority "%s" or higher affect this system' % (
                inspected_msg,
                self.opt.priority,
            )
            return_code = const.SUCCESS_RETURN_CODE
        else:
            results_msg = (
                '%s %d CVEs of priority "%s" or higher affect this system.'
                % (inspected_msg, len(cve_list_all_filtered), self.opt.priority,)
            )

            if self.opt.all_cve:
                results_msg = "%s\n\nAll CVEs affecting this system:\n\t%s" % (
                    results_msg,
                    "\n\t".join(cve_list_all_filtered),
                )

            if len(cve_list_fixable_filtered) != 0:
                results_msg = (
                    "%s\n\nThe following %d CVEs can be fixed by installing "
                    "updates:\n\t%s"
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

    def _get_package_count(self):
        if self.opt.manifest_mode:
            package_count = _count_packages_in_manifest_file(
                const.DEFAULT_MANIFEST_FILE
            )
            self.logger.debug("Manifest package count is %s" % package_count)
        else:
            package_count = self.sysinfo.package_count

        return package_count


def _count_packages_in_manifest_file(manifest_file):
    with open(manifest_file) as mf:
        package_count = len(mf.readlines())

    return package_count
