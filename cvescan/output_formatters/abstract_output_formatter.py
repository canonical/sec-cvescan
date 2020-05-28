from abc import ABC, abstractmethod
from collections import namedtuple
from typing import List

import cvescan.constants as const
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
    def __init__(
        self, opt, sysinfo, logger, sorter: AbstractStackableScanResultSorter = None
    ):
        self.opt = opt
        self.sysinfo = sysinfo
        self.logger = logger
        self.sorter = sorter
        super().__init__()

    @abstractmethod
    def format_output(self, scan_results: List[ScanResult]) -> (str, int):
        pass

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

    def _get_scan_stats(self, scan_results: List[ScanResult]) -> ScanStats:
        priority_results = self._filter_on_priority(scan_results)
        fixable_results = self._filter_on_fixable(priority_results)

        installed_pkgs = self._get_package_count()
        fixable_packages = len(set([r.package_name for r in fixable_results]))
        fixable_cves = len(set([r.cve_id for r in fixable_results]))
        fixable_vulns = len(fixable_results)
        apps_vulns = sum([1 for r in fixable_results if r.repository == const.UA_APPS])
        infra_vulns = sum(
            [1 for r in fixable_results if r.repository == const.UA_INFRA]
        )

        upgrade_vulns = fixable_vulns
        if not self.sysinfo.esm_apps_enabled:
            upgrade_vulns -= apps_vulns
        if not self.sysinfo.esm_infra_enabled:
            upgrade_vulns -= infra_vulns

        missing_fixes = fixable_vulns - upgrade_vulns
        return ScanStats(
            installed_pkgs,
            fixable_packages,
            fixable_cves,
            fixable_vulns,
            apps_vulns,
            infra_vulns,
            upgrade_vulns,
            missing_fixes,
        )

    def _get_package_count(self):
        if self.opt.manifest_mode:
            package_count = AbstractOutputFormatter._count_packages_in_manifest_file(
                const.DEFAULT_MANIFEST_FILE
            )
            self.logger.debug("Manifest package count is %s" % package_count)
        else:
            package_count = self.sysinfo.pkg_count

        return package_count

    # TODO: fix manifest mode
    @staticmethod
    def _count_packages_in_manifest_file(manifest_file):
        with open(manifest_file) as mf:
            package_count = len(mf.readlines())

        return package_count

    def _get_scanned_system_codename(self):
        return self.sysinfo.codename
