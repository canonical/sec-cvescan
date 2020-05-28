from sys import stdout
from typing import List

from tabulate import tabulate

import cvescan.constants as const
from cvescan.output_formatters import (
    AbstractOutputFormatter,
    AbstractStackableScanResultSorter,
    ScanStats,
)
from cvescan.scan_result import ScanResult


class CLIOutputFormatter(AbstractOutputFormatter):
    NOT_APPLICABLE = "N/A"

    # TODO: These colors don't all show clearly on a light background
    priority_to_color_code = {
        const.UNTRIAGED: 5,
        const.NEGLIGIBLE: 193,
        const.LOW: 228,
        const.MEDIUM: 3,
        const.HIGH: 208,
        const.CRITICAL: 1,
    }

    def __init__(
        self, opt, sysinfo, logger, sorter: AbstractStackableScanResultSorter = None
    ):
        super().__init__(opt, sysinfo, logger, sorter)
        # Currently, this setting is only enabled/disabled by the test suite
        self._show_summary = True

    def format_output(self, scan_results: List[ScanResult]) -> (str, int):
        priority_results = self._filter_on_priority(scan_results)
        fixable_results = self._filter_on_fixable(priority_results)

        stats = self._get_scan_stats(scan_results)

        summary_msg = self._format_summary(stats)
        table_msg = self._format_table(priority_results, fixable_results)
        msg = "\n%s\n\n%s" % (summary_msg, table_msg)

        return_code = CLIOutputFormatter._get_return_code(
            priority_results, fixable_results
        )

        return (msg, return_code)

    def _format_summary(self, stats: ScanStats):
        apps_enabled = self._format_esm_enabled(self.sysinfo.esm_apps_enabled)
        infra_enabled = self._format_esm_enabled(self.sysinfo.esm_infra_enabled)
        fixable_vulns = CLIOutputFormatter._colorize_fixes(stats.fixable_vulns, True)
        apps_vulns = CLIOutputFormatter._colorize_fixes(
            stats.apps_vulns, self.sysinfo.esm_apps_enabled
        )
        infra_vulns = CLIOutputFormatter._colorize_fixes(
            stats.infra_vulns, self.sysinfo.esm_infra_enabled
        )
        upgrade_vulns = CLIOutputFormatter._colorize_fixes(stats.upgrade_vulns, True)
        missing_fixes = CLIOutputFormatter._colorize_fixes(stats.missing_fixes, False)

        summary = list()
        summary.append(["Ubuntu Release", self.sysinfo.codename])
        summary.append(["Installed Packages", stats.installed_pkgs])
        summary.append(["CVE Priority", self._format_summary_priority()])
        summary.append(["Unique Packages Fixable by Patching", stats.fixable_packages])
        summary.append(["Unique CVEs Fixable by Patching", stats.fixable_cves])
        summary.append(["Vulnerabilities Fixable by Patching", fixable_vulns])
        summary.append(["Vulnerabilities Fixable by ESM Apps", apps_vulns])
        summary.append(["Vulnerabilities Fixable by ESM Infra", infra_vulns])
        summary.append(["ESM Apps Enabled", apps_enabled])
        summary.append(["ESM Infra Enabled", infra_enabled])
        summary.append(["Fixes Available by `apt-get upgrade`", upgrade_vulns])
        summary.append(
            ["Available Fixes Not Applied by `apt-get upgrade`", missing_fixes]
        )
        return "Summary\n" + tabulate(summary)

    def _format_summary_priority(self):
        if self.opt.priority == const.ALL:
            return "All"

        return "%s or higher" % self.opt.priority

    def _format_esm_enabled(self, enabled):
        yes_no = "No"
        if enabled:
            yes_no = "Yes"

        return CLIOutputFormatter._colorize_yes_no(yes_no)

    def _format_table(self, priority_results, fixable_results):
        if self.opt.unresolved:
            self.sort(priority_results)
            formatted_results = self._transform_results(priority_results)
        else:
            self.sort(fixable_results)
            formatted_results = self._transform_results(fixable_results)

        headers = ["CVE ID", "PRIORITY", "PACKAGE", "FIXED VERSION", "ARCHIVE"]
        if self.opt.uct_links:
            headers.append("URL")

        return tabulate(formatted_results, headers, tablefmt="plain")

    def _transform_results(self, scan_results):
        for sr in scan_results:
            fixed_version = sr.fixed_version if sr.fixed_version else "Unresolved"
            priority = CLIOutputFormatter._colorize_priority(sr.priority)
            repository = self._transform_repository(sr.repository)

            result = [sr.cve_id, priority, sr.package_name, fixed_version, repository]
            if self.opt.uct_links:
                uct_link = const.UCT_URL % sr.cve_id
                result.append(uct_link)

            yield result

    @classmethod
    def _colorize_priority(cls, priority):
        priority_color_code = cls.priority_to_color_code[priority]
        return cls._colorize(priority_color_code, priority)

    def _colorize_repository(self, repository):
        if not repository:
            return repository

        if repository == const.ARCHIVE:
            color_code = const.ARCHIVE_ENABLED_COLOR_CODE
        elif repository == const.UA_APPS:
            if self.sysinfo.esm_apps_enabled:
                color_code = const.ARCHIVE_ENABLED_COLOR_CODE
            else:
                color_code = const.ARCHIVE_DISABLED_COLOR_CODE
        elif repository == const.UA_INFRA:
            if self.sysinfo.esm_infra_enabled:
                color_code = const.ARCHIVE_ENABLED_COLOR_CODE
            else:
                color_code = const.ARCHIVE_DISABLED_COLOR_CODE
        else:
            self.logger.warning("Unknown repository %s" % repository)
            color_code = const.ARCHIVE_DISABLED_COLOR_CODE

        return CLIOutputFormatter._colorize(color_code, repository)

    def _transform_repository(self, repository):
        if repository:
            return self._colorize_repository(repository)

        return CLIOutputFormatter.NOT_APPLICABLE

    @classmethod
    def _colorize_yes_no(cls, yes_no):
        if yes_no.lower() == "yes":
            return cls._colorize(const.YES_COLOR_CODE, yes_no)

        return cls._colorize(const.NO_COLOR_CODE, yes_no)

    @classmethod
    def _colorize_fixes(cls, fixes, enabled):
        if fixes == 0:
            return str(fixes)

        if enabled:
            return cls._colorize(const.ARCHIVE_ENABLED_COLOR_CODE, fixes)

        return cls._colorize(const.ARCHIVE_DISABLED_COLOR_CODE, fixes)

    @staticmethod
    def _colorize(color_code, value):
        if not stdout.isatty():
            return str(value)

        return "\u001b[38;5;%dm%s\u001b[0m" % (color_code, str(value))

    @staticmethod
    def _get_return_code(priority_results, fixable_results):
        if len(fixable_results) > 0:
            return const.PATCH_AVAILABLE_RETURN_CODE

        if len(priority_results) > 0:
            return const.SYSTEM_VULNERABLE_RETURN_CODE

        return const.SUCCESS_RETURN_CODE
