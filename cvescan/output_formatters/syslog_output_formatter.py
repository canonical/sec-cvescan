from typing import List

from cvescan import TargetSysInfo
from cvescan.output_formatters import AbstractOutputFormatter, JSONOutputFormatter
from cvescan.scan_result import ScanResult


class SyslogOutputFormatter(AbstractOutputFormatter):
    def __init__(self, opt, logger, json_output_formatter: JSONOutputFormatter):
        super().__init__(opt, logger)
        self.json_output_formatter = json_output_formatter

    def format_output(
        self, scan_results: List[ScanResult], sysinfo: TargetSysInfo
    ) -> (str, int):
        json_output, return_code = self.json_output_formatter.format_output(
            scan_results, sysinfo
        )

        if not self.opt.syslog_light:
            return json_output, return_code

        stats = self._get_scan_stats(scan_results, sysinfo)

        return (
            f"{stats.fixable_vulns} vulnerabilites can be fixed by running `sudo apt upgrade`",
            return_code,
        )
