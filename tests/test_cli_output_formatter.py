import logging

import pytest

import cvescan.constants as const
from cvescan.cli_output_formatter import CLIOutputFormatter
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
        self.nagios_mode = False
        self.cve = None
        self.all_cve = True
        self.priority = "all"


@pytest.fixture
def scan_results():
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
    ]


def filter_scan_results_by_cve_ids(scan_results, cve_ids):
    return [sr for sr in scan_results if sr.cve_id in cve_ids]


@pytest.fixture
def cli_output_formatter():
    return CLIOutputFormatter(MockOpt(), MockSysInfo(), null_logger())


def test_no_cves(cli_output_formatter):
    (results_msg, return_code) = cli_output_formatter.format_output(list())

    assert "No CVEs" in results_msg
    assert return_code == const.SUCCESS_RETURN_CODE


def test_all_cves_no_fixable(cli_output_formatter, scan_results):
    sr = filter_scan_results_by_cve_ids(
        scan_results, ["CVE-2020-1000", "CVE-2020-1003"]
    )
    (results_msg, return_code) = cli_output_formatter.format_output(sr)

    assert "All CVEs" in results_msg
    assert "can be fixed by installing" not in results_msg
    assert return_code == const.SYSTEM_VULNERABLE_RETURN_CODE


# TODO: Don't spend time making the rest of these tests pass since we're going to
#       completely change the output. Remove these now empty tests and replace with
#       tests that better test the new output formatter.
def test_all_cves_fixable():
    pass


#   cve_scanner = MockCVEScanner(test_cve_list_all, test_cve_list_fixable)
#   (results_msg, return_code) = cve_scanner.scan(MockOpt())

#   assert "All CVEs" in results_msg
#   assert "can be fixed by installing" in results_msg
#   assert return_code == const.PATCH_AVAILABLE_RETURN_CODE


def test_updates_no_cves():
    pass


#   cve_scanner = MockCVEScanner(list(), list())
#   opt = MockOpt()
#   opt.all_cve = False
#   (results_msg, return_code) = cve_scanner.scan(opt)

#   assert "No CVEs" in results_msg
#   assert return_code == const.SUCCESS_RETURN_CODE


def test_updates_no_fixable():
    pass


#   cve_scanner = MockCVEScanner(test_cve_list_all, list())
#   opt = MockOpt()
#   opt.all_cve = False
#   (results_msg, return_code) = cve_scanner.scan(opt)

#   assert "All CVEs" not in results_msg
#   assert return_code == const.SYSTEM_VULNERABLE_RETURN_CODE


def test_updates_fixable():
    pass


#   cve_scanner = MockCVEScanner(test_cve_list_all, test_cve_list_fixable)
#   opt = MockOpt()
#   opt.all_cve = False
#   (results_msg, return_code) = cve_scanner.scan(opt)

#    assert "All CVEs" not in results_msg
#    assert "can be fixed by installing" in results_msg
#    assert return_code == const.PATCH_AVAILABLE_RETURN_CODE


def test_specific_cve_not_vulnerable():
    pass


#    cve_scanner = MockCVEScanner(test_cve_list_all, test_cve_list_fixable)
#    opt = MockOpt()
#    opt.cve = "CVE-2020-2000"
#    (results_msg, return_code) = cve_scanner.scan(opt)

#    assert return_code == const.SUCCESS_RETURN_CODE


def test_specific_cve_vulnerable():
    pass


#    cve_scanner = MockCVEScanner(test_cve_list_all, test_cve_list_fixable)
#    opt = MockOpt()
#    opt.cve = "CVE-2020-1000"
#    (results_msg, return_code) = cve_scanner.scan(opt)

#    assert return_code == const.SYSTEM_VULNERABLE_RETURN_CODE


def test_specific_cve_fixable():
    pass


#    cve_scanner = MockCVEScanner(test_cve_list_all, test_cve_list_fixable)
#    opt = MockOpt()
#    opt.cve = "CVE-2020-1001"
#    (results_msg, return_code) = cve_scanner.scan(opt)

#    assert return_code == const.PATCH_AVAILABLE_RETURN_CODE


def test_nagios_no_cves():
    pass


#    cve_scanner = MockCVEScanner(list(), list())
#    opt = MockOpt()
#    opt.nagios_mode = True
#    (results_msg, return_code) = cve_scanner.scan(opt)

#    assert return_code == const.NAGIOS_OK_RETURN_CODE


def test_nagios_no_fixable_cves():
    pass


#    cve_scanner = MockCVEScanner(test_cve_list_all, list())
#    opt = MockOpt()
#    opt.nagios_mode = True
#    (results_msg, return_code) = cve_scanner.scan(opt)

#    assert return_code == const.NAGIOS_WARNING_RETURN_CODE


def test_nagios_fixable_cves():
    pass


#    cve_scanner = MockCVEScanner(test_cve_list_all, test_cve_list_fixable)
#    opt = MockOpt()
#    opt.nagios_mode = True
#    (results_msg, return_code) = cve_scanner.scan(opt)

# assert return_code == const.NAGIOS_CRITICAL_RETURN_CODE
