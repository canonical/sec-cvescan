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
        self.codename = "bionic"
        self.pkg_count = 100
        self.esm_apps_enabled = False
        self.esm_infra_enabled = False


class MockOpt:
    def __init__(self):
        self.manifest_mode = False
        self.manifest_file = None
        self.cve = None
        self.unresolved = True
        self.priority = "all"
        self.uct_links = None


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


@pytest.fixture
def shuffled_scan_results():
    return [
        ScanResult(
            "CVE-2020-1002", const.CRITICAL, "pkg4", "2.0.0-1+deb9u1", const.UA_INFRA
        ),
        ScanResult("CVE-2020-1000", const.MEDIUM, "pkg4", "1.2.3-4", const.UA_APPS),
        ScanResult("CVE-2020-1005", const.HIGH, "pkg2", "2.0.0-2", const.ARCHIVE),
        ScanResult(
            "CVE-2020-1002", const.CRITICAL, "pkg6", "2.0.0-1+deb9u1", const.UA_APPS
        ),
        ScanResult("CVE-2020-1001", const.MEDIUM, "pkg4", None, None),
        ScanResult(
            "CVE-2020-10000", const.UNTRIAGED, "pkg7", "2.2.19-1", const.UA_APPS
        ),
        ScanResult(
            "CVE-2020-1002", const.CRITICAL, "pkg3", "2.0.0-1+deb9u1", const.UA_APPS
        ),
        ScanResult("CVE-2020-1003", const.NEGLIGIBLE, "pkg5", None, None),
        ScanResult("CVE-2020-2000", const.LOW, "pkg1", "1.0.0-2", const.ARCHIVE),
    ]


def format_with_priority(formatter_type, priority, scan_results):
    opt = MockOpt()
    opt.priority = priority
    formatter = formatter_type(opt, MockSysInfo(), null_logger())

    return formatter.format_output(scan_results)


def run_format(formatter_type, scan_results):
    return format_with_priority(formatter_type, "all", scan_results)


@pytest.fixture
def run_priority_filter_all_test(priority_scan_results):
    def run_test(formatter_type):
        (results_msg, return_code) = format_with_priority(
            formatter_type, const.ALL, priority_scan_results
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
    def run_test(formatter_type):
        (results_msg, return_code) = format_with_priority(
            formatter_type, const.NEGLIGIBLE, priority_scan_results
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
    def run_test(formatter_type):
        (results_msg, return_code) = format_with_priority(
            formatter_type, const.LOW, priority_scan_results
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
    def run_test(formatter_type):
        (results_msg, return_code) = format_with_priority(
            formatter_type, const.MEDIUM, priority_scan_results
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
    def run_test(formatter_type):
        (results_msg, return_code) = format_with_priority(
            formatter_type, const.HIGH, priority_scan_results
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
    def run_test(formatter_type):
        (results_msg, return_code) = format_with_priority(
            formatter_type, const.CRITICAL, priority_scan_results
        )

        assert priority_scan_results[0].cve_id not in results_msg
        assert priority_scan_results[1].cve_id not in results_msg
        assert priority_scan_results[2].cve_id in results_msg
        assert priority_scan_results[3].cve_id not in results_msg
        assert priority_scan_results[4].cve_id not in results_msg
        assert priority_scan_results[5].cve_id not in results_msg

    return run_test


def misc_scan_results():
    return [
        ScanResult("CVE-2020-1000", "low", "pkg3", None, None),
        ScanResult(
            "CVE-2020-1001", "high", "pkg1", "1:1.2.3-4+deb9u2ubuntu0.2", const.ARCHIVE
        ),
        ScanResult(
            "CVE-2020-1001", "high", "pkg2", "1:1.2.3-4+deb9u2ubuntu0.2", const.ARCHIVE
        ),
        ScanResult(
            "CVE-2020-1002", "low", "pkg4", "2.0.0+dfsg-1ubuntu1.1", const.UA_APPS
        ),
        ScanResult(
            "CVE-2020-1002", "low", "pkg5", "2.0.0+dfsg-1ubuntu1.1", const.UA_APPS
        ),
        ScanResult(
            "CVE-2020-1002", "low", "pkg6", "2.0.0+dfsg-1ubuntu1.1", const.UA_APPS
        ),
        ScanResult("CVE-2020-1003", "medium", "pkg4", None, None),
        ScanResult("CVE-2020-1003", "medium", "pkg5", None, None),
        ScanResult("CVE-2020-1003", "medium", "pkg6", None, None),
        ScanResult("CVE-2020-1004", "medium", "pkg7", None, None),
        ScanResult("CVE-2020-1005", "low", "pkg1", "1:1.2.3-4+deb9u3", const.UA_APPS),
        ScanResult("CVE-2020-1005", "low", "pkg2", "1:1.2.3-4+deb9u3", const.UA_APPS),
        ScanResult("CVE-2020-1005", "low", "pkg3", "10.2.3-2ubuntu0.1", const.UA_INFRA),
        ScanResult("CVE-2020-1006", "untriaged", "pkg5", None, None),
        ScanResult("CVE-2020-1007", "critical", "pkg4", None, None),
        ScanResult("CVE-2020-1008", "negligible", "pkg1", None, None),
        ScanResult("CVE-2020-1009", "low", "pkg2", "1:1.2.3-4+deb9u3", const.UA_APPS),
        ScanResult("CVE-2020-1010", "low", "pkg3", "10.2.3-2ubuntu0.1", const.UA_INFRA),
        ScanResult(
            "CVE-2020-1011", "low", "pkg3", "10.2.3-2ubuntu0.1", "INVALID_ARCHIVE"
        ),
    ]


def filter_scan_results_by_cve_ids(cve_ids):
    return [sr for sr in misc_scan_results() if sr.cve_id in cve_ids]


@pytest.fixture
def run_success_return_code_test():
    def run_test(formatter_type):
        (results_msg, return_code) = run_format(formatter_type, list())

        assert return_code == const.SUCCESS_RETURN_CODE

    return run_test


@pytest.fixture
def run_vulnerable_return_code_test():
    def run_test(formatter_type):
        sr = filter_scan_results_by_cve_ids(["CVE-2020-1000", "CVE-2020-1003"])
        (results_msg, return_code) = run_format(formatter_type, sr)

        assert return_code == const.SYSTEM_VULNERABLE_RETURN_CODE

    return run_test


@pytest.fixture
def run_patch_available_return_code_test():
    def run_test(formatter_type):
        sr = filter_scan_results_by_cve_ids(["CVE-2020-1002"])
        (results_msg, return_code) = run_format(formatter_type, sr)

        assert return_code == const.PATCH_AVAILABLE_RETURN_CODE

    return run_test


@pytest.fixture
def run_no_unresolved_shown_test():
    def run_test(formatter_type):
        sr = filter_scan_results_by_cve_ids(["CVE-2020-1004", "CVE-2020-1005"])
        opt = MockOpt()
        opt.unresolved = False
        formatter = formatter_type(opt, MockSysInfo(), null_logger())

        (results_msg, return_code) = formatter.format_output(sr)

        assert "Unresolved" not in results_msg
        assert "N/A" not in results_msg
        assert "CVE-2020-1004" not in results_msg
        assert "CVE-2020-1005" in results_msg

    return run_test


@pytest.fixture
def run_unresolved_shown_test():
    def run_test(formatter_type):
        sr = filter_scan_results_by_cve_ids(["CVE-2020-1004", "CVE-2020-1005"])
        opt = MockOpt()
        opt.unresolved = True
        formatter = formatter_type(opt, MockSysInfo(), null_logger())

        (results_msg, return_code) = formatter.format_output(sr)

        assert "Unresolved" in results_msg
        assert "N/A" in results_msg
        assert "CVE-2020-1004" in results_msg
        assert "CVE-2020-1005" in results_msg

    return run_test


@pytest.fixture
def run_uct_links_test():
    def run_test(formatter_type):
        sr = filter_scan_results_by_cve_ids(["CVE-2020-1004", "CVE-2020-1005"])
        opt = MockOpt()
        opt.unresolved = True
        opt.uct_links = True
        formatter = formatter_type(opt, MockSysInfo(), null_logger())

        (results_msg, return_code) = formatter.format_output(sr)

        assert const.UCT_URL % "CVE-2020-1004" in results_msg
        assert const.UCT_URL % "CVE-2020-1005" in results_msg

    return run_test


@pytest.fixture
def run_no_uct_links_test():
    def run_test(formatter_type):
        sr = filter_scan_results_by_cve_ids(["CVE-2020-1004", "CVE-2020-1005"])
        opt = MockOpt()
        opt.unresolved = True
        opt.uct_links = False
        formatter = formatter_type(opt, MockSysInfo(), null_logger())

        (results_msg, return_code) = formatter.format_output(sr)

        assert const.UCT_URL % "CVE-2020-1004" not in results_msg
        assert const.UCT_URL % "CVE-2020-1005" not in results_msg

    return run_test
