import pytest
from conftest import MockOpt

import cvescan.constants as const
from cvescan.output_formatters import CVEScanResultSorter, NagiosOutputFormatter
from cvescan.scan_result import ScanResult


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


def test_priority_filter_all(run_priority_filter_all_test):
    run_priority_filter_all_test(NagiosOutputFormatter)


def test_priority_filter_negligible(run_priority_filter_negligible_test):
    run_priority_filter_negligible_test(NagiosOutputFormatter)


def test_priority_filter_low(run_priority_filter_low_test):
    run_priority_filter_low_test(NagiosOutputFormatter)


def test_priority_filter_medium(run_priority_filter_medium_test):
    run_priority_filter_medium_test(NagiosOutputFormatter)


def test_priority_filter_high(run_priority_filter_high_test):
    run_priority_filter_high_test(NagiosOutputFormatter)


def test_priority_filter_critical(run_priority_filter_critical_test):
    run_priority_filter_critical_test(NagiosOutputFormatter)


def test_nagios_no_cves_all():
    opt = MockOpt()
    opt.priority = "all"

    nof = NagiosOutputFormatter(opt, None)
    (results_msg, return_code) = nof.format_output(list(), None)

    assert "priority" not in results_msg
    assert return_code == const.NAGIOS_OK_RETURN_CODE


def test_nagios_no_cves_medium():
    opt = MockOpt()
    opt.priority = "medium"

    nof = NagiosOutputFormatter(opt, None)
    (results_msg, return_code) = nof.format_output(list(), None)

    assert '"medium" or higher priority' in results_msg
    assert return_code == const.NAGIOS_OK_RETURN_CODE


def test_nagios_warning_all():
    opt = MockOpt()
    opt.priority = "all"

    sr = [ScanResult("CVE-2020-1000", "medium", "pkg1", None, None)]

    nof = NagiosOutputFormatter(opt, None)
    (results_msg, return_code) = nof.format_output(sr, None)

    assert "priority" not in results_msg
    assert return_code == const.NAGIOS_WARNING_RETURN_CODE


def test_nagios_warning_medium():
    opt = MockOpt()
    opt.priority = "medium"

    sr = [ScanResult("CVE-2020-1000", "medium", "pkg1", None, None)]

    nof = NagiosOutputFormatter(opt, None)
    (results_msg, return_code) = nof.format_output(sr, None)

    assert '"medium" or higher priority' in results_msg
    assert return_code == const.NAGIOS_WARNING_RETURN_CODE


def test_nagios_critical_all():
    opt = MockOpt()
    opt.priority = "all"

    sr = [ScanResult("CVE-2020-1000", "medium", "pkg1", "1.2.3-2", const.ARCHIVE)]

    nof = NagiosOutputFormatter(opt, None)
    (results_msg, return_code) = nof.format_output(sr, None)

    assert "priority" not in results_msg
    assert return_code == const.NAGIOS_CRITICAL_RETURN_CODE


def test_nagios_critical_medium():
    opt = MockOpt()
    opt.priority = "medium"

    sr = [ScanResult("CVE-2020-1000", "medium", "pkg1", "1.2.3-2", const.ARCHIVE)]

    nof = NagiosOutputFormatter(opt, None)
    (results_msg, return_code) = nof.format_output(sr, None)

    assert '"medium" or higher priority' in results_msg
    assert return_code == const.NAGIOS_CRITICAL_RETURN_CODE


def test_nagios_cves_sorted(shuffled_scan_results):
    opt = MockOpt()
    opt.unresolved = True
    opt.priority = "all"

    cve_list = (
        "CVE-2020-1000\nCVE-2020-1002\nCVE-2020-1005\nCVE-2020-2000\n" "CVE-2020-10000"
    )

    nof = NagiosOutputFormatter(opt, None, CVEScanResultSorter())
    (results_msg, return_code) = nof.format_output(shuffled_scan_results, None)

    assert cve_list in results_msg
    assert return_code == const.NAGIOS_CRITICAL_RETURN_CODE
