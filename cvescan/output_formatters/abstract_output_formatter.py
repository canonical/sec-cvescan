from abc import ABC, abstractmethod
from typing import List

import cvescan.constants as const
from cvescan.scan_result import ScanResult


class AbstractOutputFormatter(ABC):
    def __init__(self, opt, sysinfo, logger):
        self.opt = opt
        self.sysinfo = sysinfo
        self.logger = logger
        super().__init__()

    def _filter_on_priority(self, scan_results):
        if self.opt.priority == const.ALL:
            return scan_results

        priority_index = const.PRIORITIES.index(self.opt.priority)
        priority_filter = set(const.PRIORITIES[priority_index:])

        return [sr for sr in scan_results if sr.priority in priority_filter]

    def _filter_on_fixable(self, scan_results):
        return [sr for sr in scan_results if sr.fixed_version is not None]

    @abstractmethod
    def format_output(self, cvescan_results: List[ScanResult]) -> (str, int):
        pass
