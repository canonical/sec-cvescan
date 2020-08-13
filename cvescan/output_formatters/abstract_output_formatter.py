from abc import ABC, abstractmethod
from collections import namedtuple
from typing import List

import cvescan.constants as const
import cvescan.target_sysinfo as TargetSysInfo
from cvescan.output_formatters import AbstractStackableScanResultSorter
from cvescan.scan_result import ScanResult

ScanStats = namedtuple(
    "OutputSummary",
    [
        "installed_pkgs",
        "fixable_packages",
        "fixable_cves",
        "fixable_vulns",
        "apps_vulns",
        "infra_vulns",
        "upgrade_vulns",
        "missing_fixes",
    ],
)


class AbstractOutputFormatter(ABC):
    def __init__(self, opt, logger, sorter: AbstractStackableScanResultSorter = None):
        self.opt = opt
        self.logger = logger
        self.sorter = sorter
        super().__init__()

    @abstractmethod
    def format_output(
        self, scan_results: List[ScanResult], sysinfo: TargetSysInfo
    ) -> (str, int):
        pass

    def _filter_on_experimental(self, scan_results):
        if self.opt.experimental_mode:
            return scan_results

        filtered_scan_results = []

        for sr in scan_results:
            if sr.repository in {const.UA_APPS, const.UA_INFRA}:
                new_sr = ScanResult(sr.cve_id, sr.priority, sr.package_name, None, None)
                filtered_scan_results.append(new_sr)
            else:
                filtered_scan_results.append(sr)

        return filtered_scan_results

    def _filter_on_priority(self, scan_results):
        if self.opt.priority == const.ALL:
            return scan_results

        priority_index = const.PRIORITIES.index(self.opt.priority)
        priority_filter = set(const.PRIORITIES[priority_index:])

        return [sr for sr in scan_results if sr.priority in priority_filter]

    def _filter_on_fixable(self, scan_results):
        return [sr for sr in scan_results if sr.fixed_version is not None]

    # Sorts scan_results in place
    def sort(self, scan_results: List[ScanResult]) -> None:
        if self.sorter is None:
            return

        self.sorter.sort(scan_results)

    def _get_scan_stats(
        self, scan_results: List[ScanResult], sysinfo: TargetSysInfo
    ) -> ScanStats:
        priority_results = self._filter_on_priority(scan_results)
        fixable_results = self._filter_on_fixable(priority_results)

        fixable_packages = len(set([r.package_name for r in fixable_results]))
        fixable_cves = len(set([r.cve_id for r in fixable_results]))
        fixable_vulns = len(fixable_results)
        apps_vulns = sum([1 for r in fixable_results if r.repository == const.UA_APPS])
        infra_vulns = sum(
            [1 for r in fixable_results if r.repository == const.UA_INFRA]
        )

        upgrade_vulns = fixable_vulns
        if not sysinfo.esm_apps_enabled:
            upgrade_vulns -= apps_vulns
        if not sysinfo.esm_infra_enabled:
            upgrade_vulns -= infra_vulns

        missing_fixes = fixable_vulns - upgrade_vulns
        return ScanStats(
            sysinfo.pkg_count,
            fixable_packages,
            fixable_cves,
            fixable_vulns,
            apps_vulns,
            infra_vulns,
            upgrade_vulns,
            missing_fixes,
        )

    @staticmethod
    def _determine_return_code(priority_results, fixable_results):
        if len(fixable_results) > 0:
            return const.PATCH_AVAILABLE_RETURN_CODE

        if len(priority_results) > 0:
            return const.SYSTEM_VULNERABLE_RETURN_CODE

        return const.SUCCESS_RETURN_CODE
