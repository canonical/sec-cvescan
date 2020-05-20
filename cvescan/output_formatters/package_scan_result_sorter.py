from cvescan.output_formatters import AbstractStackableScanResultSorter
from cvescan.scan_result import ScanResult


class PackageScanResultSorter(AbstractStackableScanResultSorter):
    def _key_fn(self, scan_result: ScanResult):
        return scan_result.package_name
