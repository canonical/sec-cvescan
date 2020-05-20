from typing import List

from cvescan.output_formatters import AbstractScanResultSorter
from cvescan.scan_result import ScanResult


class CVEScanResultSorter(AbstractScanResultSorter):
    def sort(self, scan_results: List[ScanResult]) -> None:
        scan_results.sort(key=CVEScanResultSorter._cve_to_tuple, reverse=self.reverse)

    @staticmethod
    def _cve_to_tuple(scan_result):
        year, cve_num = scan_result.cve_id.split("-")[-2:]
        return (int(year), int(cve_num))
