from abc import ABC, abstractmethod
from typing import List

from cvescan.scan_result import ScanResult


# Sorts a list of Scan Results in place
class AbstractScanResultSorter(ABC):
    def __init__(self, reverse=False):
        self.reverse = reverse
        super().__init__()

    @abstractmethod
    def sort(self, scan_result: List[ScanResult]) -> None:
        pass
