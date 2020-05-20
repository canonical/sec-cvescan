from sys import stdout
from typing import List

import cvescan.constants as const
from cvescan.output_formatters import AbstractOutputFormatter
from cvescan.scan_result import ScanResult
from tabulate import tabulate


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
    repository_to_color_code = {const.ARCHIVE: 2, const.UA_INFRA: 3, const.UA_APPS: 3}

    def format_output(self, scan_results: List[ScanResult]) -> (str, int):
        self.sort(scan_results)
        priority_results = self._filter_on_priority(scan_results)
        fixable_results = self._filter_on_fixable(priority_results)

        if self.opt.unresolved:
            formatted_results = CLIOutputFormatter._transform_results(priority_results)
        else:
            formatted_results = CLIOutputFormatter._transform_results(fixable_results)

        msg = tabulate(
            formatted_results,
            headers=["CVE ID", "PRIORITY", "PACKAGE", "FIXED VERSION", "ARCHIVE"],
            tablefmt="plain",
        )
        return_code = CLIOutputFormatter._get_return_code(
            priority_results, fixable_results
        )

        return (msg, return_code)

    @classmethod
    def _transform_results(cls, scan_results):
        for sr in scan_results:
            (priority, repository) = cls._colorize(sr)

            fixed_version = cls._transform_fixed_version(sr.fixed_version)
            repository = cls._transform_repository(repository)

            yield [sr.cve_id, priority, sr.package_name, fixed_version, repository]

    @classmethod
    def _colorize(cls, scan_result):
        if not stdout.isatty():
            return (scan_result.priority, scan_result.repository)

        priority = cls._colorize_priority(scan_result.priority)
        repository = cls._colorize_repository(scan_result.repository)

        return priority, repository

    @classmethod
    def _colorize_priority(cls, priority):
        priority_color_code = cls.priority_to_color_code[priority]
        return "\u001b[38;5;%dm%s\u001b[0m" % (priority_color_code, priority)

    # TODO: Test whether or not UA enabled (in SysInfo()), colorize output based
    #       on which repos are enabled.
    @classmethod
    def _colorize_repository(cls, repository):
        if not repository:
            return repository

        repository_color_code = cls.repository_to_color_code[repository]
        return "\u001b[38;5;%dm%s\u001b[0m" % (repository_color_code, repository)

    @staticmethod
    def _transform_fixed_version(fixed_version):
        return fixed_version if fixed_version else "Unresolved"

    @classmethod
    def _transform_repository(cls, repository):
        return repository if repository else cls.NOT_APPLICABLE

    @staticmethod
    def _get_return_code(priority_results, fixable_results):
        if len(fixable_results) > 0:
            return const.PATCH_AVAILABLE_RETURN_CODE

        if len(priority_results) > 0:
            return const.SYSTEM_VULNERABLE_RETURN_CODE

        return const.SUCCESS_RETURN_CODE

    def _get_package_count(self):
        if self.opt.manifest_mode:
            package_count = _count_packages_in_manifest_file(
                const.DEFAULT_MANIFEST_FILE
            )
            self.logger.debug("Manifest package count is %s" % package_count)
        else:
            package_count = self.sysinfo.package_count

        return package_count


# TODO: fix manifest mode
def _count_packages_in_manifest_file(manifest_file):
    with open(manifest_file) as mf:
        package_count = len(mf.readlines())

    return package_count
