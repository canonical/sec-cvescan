import cvescan.constants as const
from cvescan.output_formatters import AbstractStackableScanResultSorter
from cvescan.scan_result import ScanResult


class PriorityScanResultSorter(AbstractStackableScanResultSorter):
    priority_to_int = {
        const.UNTRIAGED: 0,
        const.NEGLIGIBLE: 1,
        const.LOW: 2,
        const.MEDIUM: 3,
        const.HIGH: 4,
        const.CRITICAL: 5,
    }

    def _key_fn(self, scan_result: ScanResult):
        return PriorityScanResultSorter.priority_to_int[scan_result.priority]
