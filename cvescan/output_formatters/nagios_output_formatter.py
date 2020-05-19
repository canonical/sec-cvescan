from typing import List

import cvescan.constants as const
from cvescan.output_formatters import AbstractOutputFormatter
from cvescan.scan_result import ScanResult


class NagiosOutputFormatter(AbstractOutputFormatter):
    def format_output(self, scan_results: List[ScanResult]) -> (str, int):
        (priority_filtered_cves, fixable_cves) = self._apply_filters(scan_results)

        if self.opt.priority == const.ALL:
            return self._format_all_priorities_output(
                priority_filtered_cves, fixable_cves
            )

        return self._format_filtered_priorities_output(
            priority_filtered_cves, fixable_cves
        )

    def _format_all_priorities_output(self, priority_filtered_cves, fixable_cves):
        num_pfc = len(priority_filtered_cves)
        num_fc = len(fixable_cves)

        if num_pfc == 0:
            results_msg = "OK: Not affected by any known CVEs."
            return_code = const.NAGIOS_OK_RETURN_CODE
        elif num_pfc != 0 and num_fc == 0:
            pfc_list = "\n".join(priority_filtered_cves)
            results_msg = "WARNING: Affected by %s CVEs.\n%s" % (num_pfc, pfc_list)
            return_code = const.NAGIOS_WARNING_RETURN_CODE
        else:
            fc_list = "\n".join(fixable_cves)
            results_msg = (
                "CRITICAL: Affected by %d CVEs. %d CVEs can be fixed with "
                "package updates.\n%s" % (num_pfc, num_fc, fc_list)
            )
            return_code = const.NAGIOS_CRITICAL_RETURN_CODE

        return (results_msg, return_code)

    def _format_filtered_priorities_output(self, priority_filtered_cves, fixable_cves):
        num_pfc = len(priority_filtered_cves)
        num_fc = len(fixable_cves)

        if num_pfc == 0:
            results_msg = (
                'OK: Not affected by any known CVEs of "%s" or higher priority.'
                % self.opt.priority
            )
            return_code = const.NAGIOS_OK_RETURN_CODE
        elif num_pfc != 0 and num_fc == 0:
            pfc_list = "\n".join(priority_filtered_cves)
            results_msg = (
                'WARNING: Affected by %s CVEs with "%s" or higher priority.\n%s'
                % (num_pfc, self.opt.priority, pfc_list)
            )
            return_code = const.NAGIOS_WARNING_RETURN_CODE
        else:
            fc_list = "\n".join(fixable_cves)
            results_msg = (
                'CRITICAL: Affected by %d CVEs with "%s" or higher priority.'
                "%d CVEs can be fixed with package updates\n%s"
                % (num_pfc, self.opt.priority, num_fc, fc_list)
            )
            return_code = const.NAGIOS_CRITICAL_RETURN_CODE

        return (results_msg, return_code)

    def _apply_filters(self, scan_results):
        priority_filtered_scan_results = self._filter_on_priority(scan_results)
        fixable_scan_results = self._filter_on_fixable(priority_filtered_scan_results)

        priority_filtered_cves = [sr.cve_id for sr in priority_filtered_scan_results]
        fixable_cves = [sr.cve_id for sr in fixable_scan_results]

        priority_filtered_cves = _remove_duplicate_cves(priority_filtered_cves)
        fixable_cves = _remove_duplicate_cves(fixable_cves)

        # TODO: This should be handled in AbstractOutputFormatter. It should
        #       also sort numerically so that CVE-2020-12826 is after CVE-2020-1747.
        priority_filtered_cves.sort()
        fixable_cves.sort()

        return (priority_filtered_cves, fixable_cves)


def _remove_duplicate_cves(cve_list):
    return list(set(cve_list))
