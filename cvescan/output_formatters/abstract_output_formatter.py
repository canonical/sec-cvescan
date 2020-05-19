from abc import ABC, abstractmethod
from typing import List

from cvescan.scan_result import ScanResult


class AbstractOutputFormatter(ABC):
    def __init__(self, opt, sysinfo, logger):
        self.opt = opt
        self.sysinfo = sysinfo
        self.logger = logger
        super().__init__()

    @abstractmethod
    def format_output(self, cvescan_results: List[ScanResult]):
        pass
