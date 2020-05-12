import cvescan.constants as const
from cvescan.cvescanner import CVEScanner
import logging
import pytest

def null_logger():
    logger = logging.getLogger("cvescan.null")
    if not logger.hasHandlers():
        logger.addHandler(logging.NullHandler())

    return logger

class MockSysInfo:
    def __init__(self):
        self.package_count = 100
        self.scriptdir = "."

class MockOpt:
    def __init__(self):
        self.test_mode = False
        self.manifest_mode = False
        self.manifest_file = None
        self.download_oval_file = False
        self.nagios_mode = False
        self.cve = None
        self.all_cve = True
        self.priority = "high"

class MockCVEScanner(CVEScanner):
    def __init__(self, cve_list_all, cve_list_fixable):
        super().__init__(MockSysInfo(), null_logger())
        self.cve_list_all = cve_list_all
        self.cve_list_fixable = cve_list_fixable

    def _retrieve_oval_file(self, opt):
        pass

    def _scan_for_cves(self, opt):
        return (self.cve_list_all, self.cve_list_fixable)

@pytest.fixture
def test_cve_list_all():
    return ["CVE-2020-1000", "CVE-2020-1001", "CVE-2020-1002", "CVE-2020-1003"]

@pytest.fixture
def test_cve_list_fixable():
    return ["CVE-2020-1001", "CVE-2020-1003"]

@pytest.fixture
def default_cve_scanner(test_cve_list_all, test_cve_list_fixable):
    return MockCVEScanner(test_cve_list_all, test_cve_list_fixable)

def test_no_cves():
    cve_scanner = MockCVEScanner(list(), list())
    (results_msg, return_code) = cve_scanner.scan(MockOpt())

    assert "No CVEs" in results_msg
    assert return_code == const.SUCCESS_RETURN_CODE

def test_all_cves_no_fixable(test_cve_list_all):
    cve_scanner = MockCVEScanner(test_cve_list_all, list())
    (results_msg, return_code) = cve_scanner.scan(MockOpt())

    assert "All CVEs" in results_msg
    assert "can be fixed by installing" not in results_msg
    assert return_code == const.SYSTEM_VULNERABLE_RETURN_CODE

def test_all_cves_fixable(test_cve_list_all, test_cve_list_fixable):
    cve_scanner = MockCVEScanner(test_cve_list_all, test_cve_list_fixable)
    (results_msg, return_code) = cve_scanner.scan(MockOpt())

    assert "All CVEs" in results_msg
    assert "can be fixed by installing" in results_msg
    assert return_code == const.PATCH_AVAILABLE_RETURN_CODE

def test_updates_no_cves():
    cve_scanner = MockCVEScanner(list(), list())
    opt = MockOpt()
    opt.all_cve = False
    (results_msg, return_code) = cve_scanner.scan(opt)

    assert "No CVEs" in results_msg
    assert return_code == const.SUCCESS_RETURN_CODE

def test_updates_no_fixable(test_cve_list_all):
    cve_scanner = MockCVEScanner(test_cve_list_all, list())
    opt = MockOpt()
    opt.all_cve = False
    (results_msg, return_code) = cve_scanner.scan(opt)

    assert "All CVEs" not in results_msg
    assert return_code == const.SYSTEM_VULNERABLE_RETURN_CODE

def test_updates_fixable(test_cve_list_all, test_cve_list_fixable):
    cve_scanner = MockCVEScanner(test_cve_list_all, test_cve_list_fixable)
    opt = MockOpt()
    opt.all_cve = False
    (results_msg, return_code) = cve_scanner.scan(opt)

    assert "All CVEs" not in results_msg
    assert "can be fixed by installing" in results_msg
    assert return_code == const.PATCH_AVAILABLE_RETURN_CODE

def test_specific_cve_not_vulnerable(test_cve_list_all, test_cve_list_fixable):
    cve_scanner = MockCVEScanner(test_cve_list_all, test_cve_list_fixable)
    opt = MockOpt()
    opt.cve = "CVE-2020-2000"
    (results_msg, return_code) = cve_scanner.scan(opt)

    assert return_code == const.SUCCESS_RETURN_CODE

def test_specific_cve_vulnerable(test_cve_list_all, test_cve_list_fixable):
    cve_scanner = MockCVEScanner(test_cve_list_all, test_cve_list_fixable)
    opt = MockOpt()
    opt.cve = "CVE-2020-1000"
    (results_msg, return_code) = cve_scanner.scan(opt)

    assert return_code == const.SYSTEM_VULNERABLE_RETURN_CODE

def test_specific_cve_fixable(test_cve_list_all, test_cve_list_fixable):
    cve_scanner = MockCVEScanner(test_cve_list_all, test_cve_list_fixable)
    opt = MockOpt()
    opt.cve = "CVE-2020-1001"
    (results_msg, return_code) = cve_scanner.scan(opt)

    assert return_code == const.PATCH_AVAILABLE_RETURN_CODE

def test_nagios_no_cves():
    cve_scanner = MockCVEScanner(list(), list())
    opt = MockOpt()
    opt.nagios_mode = True
    (results_msg, return_code) = cve_scanner.scan(opt)

    assert return_code == const.NAGIOS_OK_RETURN_CODE

def test_nagios_no_fixable_cves(test_cve_list_all):
    cve_scanner = MockCVEScanner(test_cve_list_all, list())
    opt = MockOpt()
    opt.nagios_mode = True
    (results_msg, return_code) = cve_scanner.scan(opt)

    assert return_code == const.NAGIOS_WARNING_RETURN_CODE

def test_nagios_fixable_cves(test_cve_list_all, test_cve_list_fixable):
    cve_scanner = MockCVEScanner(test_cve_list_all, test_cve_list_fixable)
    opt = MockOpt()
    opt.nagios_mode = True
    (results_msg, return_code) = cve_scanner.scan(opt)

    assert return_code == const.NAGIOS_CRITICAL_RETURN_CODE
