from cvescan.output_formatters import AbstractStackableScanResultSorter
from cvescan.scan_result import ScanResult


class CVEScanResultSorter(AbstractStackableScanResultSorter):
    def _key_fn(self, scan_result: ScanResult):
        year, cve_num = scan_result.cve_id.split("-")[-2:]
        return (int(year), int(cve_num))
