from typing import List

import cvescan.constants as const
from cvescan import TargetSysInfo
from cvescan.output_formatters import AbstractOutputFormatter
from cvescan.scan_result import ScanResult


class CVEOutputFormatter(AbstractOutputFormatter):
    def format_output(
        self, scan_results: List[ScanResult], _: TargetSysInfo
    ) -> (str, int):
        scan_results = self._filter_on_experimental(scan_results)
        cve_results = self._get_results_for_cve(scan_results)

        if len(cve_results) == 0:
            msg = "Not affected by %s." % self.opt.cve
            return (msg, const.SUCCESS_RETURN_CODE)

        fixable_results = self._filter_on_fixable(cve_results)
        if len(fixable_results) == 0:
            msg = "Vulnerable to %s. There is no fix available, yet." % self.opt.cve
            return (msg, const.SYSTEM_VULNERABLE_RETURN_CODE)

        repo_str = self._build_repository_availability_string(fixable_results)
        msg = "Vulnerable to %s, but fixes are available from %s." % (
            self.opt.cve,
            repo_str,
        )
        return (msg, const.PATCH_AVAILABLE_RETURN_CODE)

    def _get_results_for_cve(self, scan_results):
        return [sr for sr in scan_results if sr.cve_id == self.opt.cve]

    def _build_repository_availability_string(self, fixable_results):
        repositories = set(
            [sr.repository for sr in fixable_results if sr.repository is not None]
        )
        repo_str = ""

        if const.UA_APPS in repositories:
            repo_str = "UA for Apps"

        if const.UA_INFRA in repositories:
            if len(repositories) == 2 and const.UA_APPS in repositories:
                repo_str += " and "
            elif len(repositories) == 3:
                repo_str += ", "

            repo_str += "UA for Infra"

        if const.UBUNTU_ARCHIVE in repositories:
            if len(repositories) == 2:
                repo_str += " and "
            elif len(repositories) == 3:
                repo_str += ", and "

            repo_str += "the Ubuntu Archive"

        return repo_str
