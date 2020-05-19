import logging

import pytest

import cvescan.constants as const
from cvescan.scan_result import ScanResult


def null_logger():
    logger = logging.getLogger("cvescan.null")
    if not logger.hasHandlers():
        logger.addHandler(logging.NullHandler())

    return logger


class MockSysInfo:
    def __init__(self):
        self.distrib_codename = "bionic"
        self.package_count = 100


class MockOpt:
    def __init__(self):
        self.manifest_mode = False
        self.manifest_file = None
        self.cve = None
        self.unresolved = True
        self.priority = "all"


@pytest.fixture
def priority_scan_results():
    return [
        ScanResult("CVE-2020-1000", const.MEDIUM, "pkg4", None, None),
        ScanResult("CVE-2020-1001", const.NEGLIGIBLE, "pkg5", None, None),
        ScanResult("CVE-2020-1002", const.CRITICAL, "pkg6", None, None),
        ScanResult("CVE-2020-1003", const.UNTRIAGED, "pkg7", None, None),
        ScanResult("CVE-2020-1004", const.LOW, "pkg1", None, None),
        ScanResult("CVE-2020-1005", const.HIGH, "pkg2", None, None),
    ]


def format_with_priority(formatterType, priority, scan_results):
    opt = MockOpt()
    opt.priority = priority
    formatter = formatterType(opt, MockSysInfo(), null_logger())

    return formatter.format_output(scan_results)


@pytest.fixture
def run_priority_filter_all_test(priority_scan_results):
    def run_test(formatterType):
        (results_msg, return_code) = format_with_priority(
            formatterType, const.ALL, priority_scan_results
        )

        assert priority_scan_results[0].cve_id in results_msg
        assert priority_scan_results[1].cve_id in results_msg
        assert priority_scan_results[2].cve_id in results_msg
        assert priority_scan_results[3].cve_id in results_msg
        assert priority_scan_results[4].cve_id in results_msg
        assert priority_scan_results[5].cve_id in results_msg

    return run_test


@pytest.fixture
def run_priority_filter_negligible_test(priority_scan_results):
    def run_test(formatterType):
        (results_msg, return_code) = format_with_priority(
            formatterType, const.NEGLIGIBLE, priority_scan_results
        )

        assert priority_scan_results[0].cve_id in results_msg
        assert priority_scan_results[1].cve_id in results_msg
        assert priority_scan_results[2].cve_id in results_msg
        assert priority_scan_results[3].cve_id not in results_msg
        assert priority_scan_results[4].cve_id in results_msg
        assert priority_scan_results[5].cve_id in results_msg

    return run_test


@pytest.fixture
def run_priority_filter_low_test(priority_scan_results):
    def run_test(formatterType):
        (results_msg, return_code) = format_with_priority(
            formatterType, const.LOW, priority_scan_results
        )

        assert priority_scan_results[0].cve_id in results_msg
        assert priority_scan_results[1].cve_id not in results_msg
        assert priority_scan_results[2].cve_id in results_msg
        assert priority_scan_results[3].cve_id not in results_msg
        assert priority_scan_results[4].cve_id in results_msg
        assert priority_scan_results[5].cve_id in results_msg

    return run_test


@pytest.fixture
def run_priority_filter_medium_test(priority_scan_results):
    def run_test(formatterType):
        (results_msg, return_code) = format_with_priority(
            formatterType, const.MEDIUM, priority_scan_results
        )

        assert priority_scan_results[0].cve_id in results_msg
        assert priority_scan_results[1].cve_id not in results_msg
        assert priority_scan_results[2].cve_id in results_msg
        assert priority_scan_results[3].cve_id not in results_msg
        assert priority_scan_results[4].cve_id not in results_msg
        assert priority_scan_results[5].cve_id in results_msg

    return run_test


@pytest.fixture
def run_priority_filter_high_test(priority_scan_results):
    def run_test(formatterType):
        (results_msg, return_code) = format_with_priority(
            formatterType, const.HIGH, priority_scan_results
        )

        assert priority_scan_results[0].cve_id not in results_msg
        assert priority_scan_results[1].cve_id not in results_msg
        assert priority_scan_results[2].cve_id in results_msg
        assert priority_scan_results[3].cve_id not in results_msg
        assert priority_scan_results[4].cve_id not in results_msg
        assert priority_scan_results[5].cve_id in results_msg

    return run_test


@pytest.fixture
def run_priority_filter_critical_test(priority_scan_results):
    def run_test(formatterType):
        (results_msg, return_code) = format_with_priority(
            formatterType, const.CRITICAL, priority_scan_results
        )

        assert priority_scan_results[0].cve_id not in results_msg
        assert priority_scan_results[1].cve_id not in results_msg
        assert priority_scan_results[2].cve_id in results_msg
        assert priority_scan_results[3].cve_id not in results_msg
        assert priority_scan_results[4].cve_id not in results_msg
        assert priority_scan_results[5].cve_id not in results_msg

    return run_test
