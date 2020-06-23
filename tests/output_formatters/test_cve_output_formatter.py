import pytest
from conftest import MockOpt, MockSysInfo, filter_scan_results_by_cve_ids, null_logger

import cvescan.constants as const
from cvescan.output_formatters import CVEOutputFormatter
from cvescan.scan_result import ScanResult


@pytest.fixture
def cve_output_formatter():
    opt = MockOpt()
    opt.cve = "CVE-2020-1000"
    opt.priority = "medium"
    return CVEOutputFormatter(opt, null_logger())


def test_not_vulnerable(cve_output_formatter):
    sr = filter_scan_results_by_cve_ids(["CVE-2020-1001", "CVE-2020-1003"])
    msg, rc = cve_output_formatter.format_output(sr, MockSysInfo())

    assert msg == "Not affected by CVE-2020-1000."
    assert rc == 0


def test_vulnerable_no_patch(cve_output_formatter):
    sr = filter_scan_results_by_cve_ids(["CVE-2020-1000", "CVE-2020-1003"])
    msg, rc = cve_output_formatter.format_output(sr, MockSysInfo())

    assert msg == "Vulnerable to CVE-2020-1000. There is no fix available, yet."
    assert rc == 3


def test_vulnerable_patch_available_repository(cve_output_formatter):
    sr = filter_scan_results_by_cve_ids(["CVE-2020-1001", "CVE-2020-1003"])
    sr.append(
        ScanResult("CVE-2020-1000", "low", "pkg3", "1.2.3-4", const.UBUNTU_ARCHIVE),
    )
    msg, rc = cve_output_formatter.format_output(sr, MockSysInfo())

    expected_msg = (
        "Vulnerable to CVE-2020-1000, but fixes are available from "
        "the Ubuntu Archive."
    )

    assert msg == expected_msg
    assert rc == 4


def test_vulnerable_patch_available_apps(cve_output_formatter):
    sr = filter_scan_results_by_cve_ids(["CVE-2020-1001", "CVE-2020-1003"])
    sr.append(ScanResult("CVE-2020-1000", "low", "pkg3", "1.2.3-4", const.UA_APPS))
    msg, rc = cve_output_formatter.format_output(sr, MockSysInfo())

    assert (
        msg == "Vulnerable to CVE-2020-1000, but fixes are available from UA for Apps."
    )
    assert rc == 4


def test_vulnerable_patch_available_infra(cve_output_formatter):
    sr = filter_scan_results_by_cve_ids(["CVE-2020-1001", "CVE-2020-1003"])
    sr.append(ScanResult("CVE-2020-1000", "low", "pkg3", "1.2.3-4", const.UA_INFRA),)
    msg, rc = cve_output_formatter.format_output(sr, MockSysInfo())

    assert (
        msg == "Vulnerable to CVE-2020-1000, but fixes are available from UA for Infra."
    )


def test_no_patch_available_infra_experimental(cve_output_formatter):
    sr = filter_scan_results_by_cve_ids(["CVE-2020-1001", "CVE-2020-1003"])
    sr.append(ScanResult("CVE-2020-1000", "low", "pkg3", "1.2.3-4", const.UA_INFRA),)
    cve_output_formatter.opt.experimental_mode = False
    msg, rc = cve_output_formatter.format_output(sr, MockSysInfo())

    assert msg == "Vulnerable to CVE-2020-1000. There is no fix available, yet."
    assert rc == 3


def test_vulnerable_patch_available_apps_infra(cve_output_formatter):
    sr = filter_scan_results_by_cve_ids(["CVE-2020-1001", "CVE-2020-1003"])
    sr = sr + [
        ScanResult("CVE-2020-1000", "low", "pkg4", "1.2.3-4", const.UA_INFRA),
        ScanResult("CVE-2020-1000", "low", "pkg5", "1.2.3-4", const.UA_APPS),
    ]

    msg, rc = cve_output_formatter.format_output(sr, MockSysInfo())

    expected_msg = (
        "Vulnerable to CVE-2020-1000, but fixes are available from "
        "UA for Apps and UA for Infra."
    )

    assert msg == expected_msg
    assert rc == 4


def test_vulnerable_patch_available_apps_repository(cve_output_formatter):
    sr = filter_scan_results_by_cve_ids(["CVE-2020-1001", "CVE-2020-1003"])
    sr = sr + [
        ScanResult("CVE-2020-1000", "low", "pkg3", "1.2.3-4", const.UBUNTU_ARCHIVE),
        ScanResult("CVE-2020-1000", "low", "pkg5", "1.2.3-4", const.UA_APPS),
    ]

    msg, rc = cve_output_formatter.format_output(sr, MockSysInfo())
    expected_msg = (
        "Vulnerable to CVE-2020-1000, but fixes are available from "
        "UA for Apps and the Ubuntu Archive."
    )

    assert msg == expected_msg
    assert rc == 4


def test_vulnerable_patch_available_infra_repository(cve_output_formatter):
    sr = filter_scan_results_by_cve_ids(["CVE-2020-1001", "CVE-2020-1003"])
    sr = sr + [
        ScanResult("CVE-2020-1000", "low", "pkg3", "1.2.3-4", const.UBUNTU_ARCHIVE),
        ScanResult("CVE-2020-1000", "low", "pkg5", "1.2.3-4", const.UA_INFRA),
    ]

    msg, rc = cve_output_formatter.format_output(sr, MockSysInfo())
    expected_msg = (
        "Vulnerable to CVE-2020-1000, but fixes are available from "
        "UA for Infra and the Ubuntu Archive."
    )

    assert msg == expected_msg
    assert rc == 4


def test_vulnerable_patch_available_all(cve_output_formatter):
    sr = filter_scan_results_by_cve_ids(["CVE-2020-1001", "CVE-2020-1003"])
    sr = sr + [
        ScanResult("CVE-2020-1000", "low", "pkg3", "1.2.3-4", const.UBUNTU_ARCHIVE),
        ScanResult("CVE-2020-1000", "low", "pkg4", "1.2.3-4", const.UA_INFRA),
        ScanResult("CVE-2020-1000", "low", "pkg5", "1.2.3-4", const.UA_APPS),
    ]

    msg, rc = cve_output_formatter.format_output(sr, MockSysInfo())
    expected_msg = (
        "Vulnerable to CVE-2020-1000, but fixes are available from "
        "UA for Apps, UA for Infra, and the Ubuntu Archive."
    )

    assert msg == expected_msg
    assert rc == 4


def test_vulnerable_patch_available_infra_repository_duplicates(cve_output_formatter):
    sr = filter_scan_results_by_cve_ids(["CVE-2020-1001", "CVE-2020-1003"])
    sr = sr + [
        ScanResult("CVE-2020-1000", "low", "pkg3", "1.2.3-4", const.UBUNTU_ARCHIVE),
        ScanResult("CVE-2020-1000", "low", "pkg5", "1.2.3-4", const.UA_INFRA),
        ScanResult("CVE-2020-1000", "low", "pkg6", "1.2.3-4", const.UA_INFRA),
    ]

    msg, rc = cve_output_formatter.format_output(sr, MockSysInfo())
    expected_msg = (
        "Vulnerable to CVE-2020-1000, but fixes are available from "
        "UA for Infra and the Ubuntu Archive."
    )

    assert msg == expected_msg
    assert rc == 4
