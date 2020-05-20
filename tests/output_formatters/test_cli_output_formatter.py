import logging
import sys

import pytest

import cvescan.constants as const
from cvescan.output_formatters import CLIOutputFormatter
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
        self.unresolved = False
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
        ScanResult("CVE-2020-1006", "untriaged", "pkg5", None, None),
        ScanResult("CVE-2020-1007", "critical", "pkg4", None, None),
        ScanResult("CVE-2020-1008", "negligible", "pkg1", None, None),
    ]


def filter_scan_results_by_cve_ids(scan_results, cve_ids):
    return [sr for sr in scan_results if sr.cve_id in cve_ids]


@pytest.fixture
def cli_output_formatter():
    return CLIOutputFormatter(MockOpt(), MockSysInfo(), null_logger())


def test_no_cves_return_code(cli_output_formatter):
    (results_msg, return_code) = cli_output_formatter.format_output(list())

    assert return_code == const.SUCCESS_RETURN_CODE


def test_unresolved_no_fixable_return_code(cli_output_formatter, scan_results):
    sr = filter_scan_results_by_cve_ids(
        scan_results, ["CVE-2020-1000", "CVE-2020-1003"]
    )
    (results_msg, return_code) = cli_output_formatter.format_output(sr)

    assert return_code == const.SYSTEM_VULNERABLE_RETURN_CODE


def test_unresolved_fixable_return_code(cli_output_formatter, scan_results):
    sr = filter_scan_results_by_cve_ids(scan_results, ["CVE-2020-1002"])
    (results_msg, return_code) = cli_output_formatter.format_output(sr)

    assert return_code == const.PATCH_AVAILABLE_RETURN_CODE


def test_no_unresolved_shown(cli_output_formatter, scan_results):
    cli_output_formatter.opt.unresolved = False
    sr = filter_scan_results_by_cve_ids(
        scan_results, ["CVE-2020-1004", "CVE-2020-1005"]
    )
    (results_msg, return_code) = cli_output_formatter.format_output(sr)

    assert "Unresolved" not in results_msg
    assert "N/A" not in results_msg
    assert "CVE-2020-1004" not in results_msg


def test_unresolved_shown(cli_output_formatter, scan_results):
    cli_output_formatter.opt.unresolved = True
    sr = filter_scan_results_by_cve_ids(
        scan_results, ["CVE-2020-1004", "CVE-2020-1005"]
    )
    (results_msg, return_code) = cli_output_formatter.format_output(sr)

    assert "Unresolved" in results_msg
    assert "N/A" in results_msg
    assert "CVE-2020-1004" in results_msg
    assert "CVE-2020-1005" in results_msg


def test_priority_filter_all(run_priority_filter_all_test):
    run_priority_filter_all_test(CLIOutputFormatter)


def test_priority_filter_negligible(run_priority_filter_negligible_test):
    run_priority_filter_negligible_test(CLIOutputFormatter)


def test_priority_filter_low(run_priority_filter_low_test):
    run_priority_filter_low_test(CLIOutputFormatter)


def test_priority_filter_medium(run_priority_filter_medium_test):
    run_priority_filter_medium_test(CLIOutputFormatter)


def test_priority_filter_high(run_priority_filter_high_test):
    run_priority_filter_high_test(CLIOutputFormatter)


def test_priority_filter_critical(run_priority_filter_critical_test):
    run_priority_filter_critical_test(CLIOutputFormatter)


def test_no_tty_no_color(monkeypatch, cli_output_formatter, scan_results):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    sr = filter_scan_results_by_cve_ids(scan_results, ["CVE-2020-1001"])

    (results_msg, return_code) = cli_output_formatter.format_output(sr)

    assert "\u001b" not in results_msg


def run_priority_color_test(
    monkeypatch, cli_output_formatter, scan_results, cve_id, priority_name
):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)

    expected_color = (
        "38;5;%d" % CLIOutputFormatter.priority_to_color_code[priority_name]
    )

    cli_output_formatter.opt.unresolved = True
    sr = filter_scan_results_by_cve_ids(scan_results, [cve_id])

    (results_msg, return_code) = cli_output_formatter.format_output(sr)

    assert expected_color in results_msg


def test_untriaged_color(monkeypatch, cli_output_formatter, scan_results):
    run_priority_color_test(
        monkeypatch,
        cli_output_formatter,
        scan_results,
        "CVE-2020-1006",
        const.UNTRIAGED,
    )


def test_negligible_color(monkeypatch, cli_output_formatter, scan_results):
    run_priority_color_test(
        monkeypatch,
        cli_output_formatter,
        scan_results,
        "CVE-2020-1008",
        const.NEGLIGIBLE,
    )


def test_low_color(monkeypatch, cli_output_formatter, scan_results):
    run_priority_color_test(
        monkeypatch, cli_output_formatter, scan_results, "CVE-2020-1005", const.LOW
    )


def test_medium_color(monkeypatch, cli_output_formatter, scan_results):
    run_priority_color_test(
        monkeypatch, cli_output_formatter, scan_results, "CVE-2020-1003", const.MEDIUM
    )


def test_high_color(monkeypatch, cli_output_formatter, scan_results):
    run_priority_color_test(
        monkeypatch, cli_output_formatter, scan_results, "CVE-2020-1001", const.HIGH
    )


def test_critical_color(monkeypatch, cli_output_formatter, scan_results):
    run_priority_color_test(
        monkeypatch, cli_output_formatter, scan_results, "CVE-2020-1007", const.CRITICAL
    )


# TODO: Test ubuntu archive colors after UA detection is enabled
