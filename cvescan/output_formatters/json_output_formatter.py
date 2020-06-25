import json
from typing import List

import cvescan.constants as const
from cvescan import TargetSysInfo
from cvescan.output_formatters import AbstractOutputFormatter
from cvescan.scan_result import ScanResult


class JSONOutputFormatter(AbstractOutputFormatter):
    def format_output(
        self, scan_results: List[ScanResult], sysinfo: TargetSysInfo
    ) -> (str, int):
        scan_results = self._filter_on_experimental(scan_results)

        output = {}
        output["summary"] = self._get_summary(scan_results, sysinfo)

        priority_results = self._filter_on_priority(scan_results)
        fixable_results = self._filter_on_fixable(priority_results)

        if self.opt.unresolved:
            self.sort(priority_results)
            results = priority_results
        else:
            self.sort(fixable_results)
            results = fixable_results

        output["cves"] = self._get_cve_results(results)

        return_code = JSONOutputFormatter._determine_return_code(
            priority_results, fixable_results
        )

        return json.dumps(output, indent=4, sort_keys=False), return_code

    def _get_summary(self, scan_results: List[ScanResult], sysinfo: TargetSysInfo):
        stats = self._get_scan_stats(scan_results, sysinfo)

        summary = {}

        summary["ubuntu_release"] = sysinfo.codename
        summary["num_installed_packages"] = stats.installed_pkgs
        summary["num_cves"] = stats.fixable_cves
        summary["num_affected_packages"] = stats.fixable_packages
        summary["num_patchable_vulnerabilities"] = stats.fixable_vulns

        return summary

    def _get_cve_results(self, scan_results: List[ScanResult]):
        cve_results = {}
        for sr in scan_results:
            fixed_version = sr.fixed_version if sr.fixed_version else ""
            repository = sr.repository if sr.repository else ""
            vuln_info = {
                "priority": sr.priority,
                "fixed_version": fixed_version,
                "repository": repository,
            }

            cve_results.setdefault(sr.cve_id, {})
            cve_results[sr.cve_id].setdefault("url", const.UCT_URL % sr.cve_id)
            cve_results[sr.cve_id].setdefault("packages", {})
            cve_results[sr.cve_id]["packages"][sr.package_name] = vuln_info

        return cve_results
