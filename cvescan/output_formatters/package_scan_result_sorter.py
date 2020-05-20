from typing import List

from cvescan.output_formatters import AbstractScanResultSorter
from cvescan.scan_result import ScanResult


class PackageScanResultSorter(AbstractScanResultSorter):
    def sort(self, scan_results: List[ScanResult]) -> None:
        scan_results.sort(key=lambda sr: sr.package_name, reverse=self.reverse)
