from typing import List

import cvescan.constants as const
from cvescan import TargetSysInfo
from cvescan.output_formatters import AbstractOutputFormatter
from cvescan.scan_result import ScanResult


class CSVOutputFormatter(AbstractOutputFormatter):
    def format_output(
        self, scan_results: List[ScanResult], sysinfo: TargetSysInfo
    ) -> (str, int):
        scan_results = self._filter_on_experimental(scan_results)

        priority_results = self._filter_on_priority(scan_results)
        fixable_results = self._filter_on_fixable(priority_results)

        if self.opt.unresolved:
            self.sort(priority_results)
            results = priority_results
        else:
            self.sort(fixable_results)
            results = fixable_results

        csv = self._results_as_csv(results)

        return_code = CSVOutputFormatter._determine_return_code(
            priority_results, fixable_results
        )

        return csv, return_code

    def _results_as_csv(self, scan_results: List[ScanResult]):
        csv_results = "CVE ID,PRIORITY,PACKAGE,FIXED_VERSION,REPOSITORY"
        if self.opt.show_links:
            csv_results += ",URL"

        for sr in scan_results:
            fixed_version = sr.fixed_version if sr.fixed_version else ""
            repository = sr.repository if sr.repository else ""

            result = [
                sr.cve_id,
                sr.priority,
                sr.package_name,
                fixed_version,
                repository,
            ]
            if self.opt.show_links:
                result.append(const.UCT_URL % sr.cve_id)

            csv_results += "\n" + ",".join(result)

        return csv_results
