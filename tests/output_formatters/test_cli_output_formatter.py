import sys

import pytest
from conftest import MockOpt, MockSysInfo, filter_scan_results_by_cve_ids, null_logger

import cvescan.constants as const
from cvescan.output_formatters import CLIOutputFormatter


@pytest.fixture
def cli_output_formatter():
    return CLIOutputFormatter(MockOpt(), MockSysInfo(), null_logger())


def test_no_cves_return_code(run_success_return_code_test):
    run_success_return_code_test(CLIOutputFormatter)


def test_unresolved_no_fixable_return_code(run_vulnerable_return_code_test):
    run_vulnerable_return_code_test(CLIOutputFormatter)


def test_unresolved_fixable_return_code(run_patch_available_return_code_test):
    run_patch_available_return_code_test(CLIOutputFormatter)


def test_no_unresolved_shown(run_no_unresolved_shown_test):
    run_no_unresolved_shown_test(CLIOutputFormatter)


def test_unresolved_shown(run_unresolved_shown_test):
    run_unresolved_shown_test(CLIOutputFormatter)


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


def test_no_tty_no_color(monkeypatch, cli_output_formatter):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    sr = filter_scan_results_by_cve_ids(["CVE-2020-1001"])

    (results_msg, return_code) = cli_output_formatter.format_output(sr)

    assert "\u001b" not in results_msg


def run_priority_color_test(monkeypatch, cli_output_formatter, cve_id, priority_name):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)

    expected_color = (
        "38;5;%d" % CLIOutputFormatter.priority_to_color_code[priority_name]
    )

    cli_output_formatter.opt.unresolved = True
    sr = filter_scan_results_by_cve_ids([cve_id])

    (results_msg, return_code) = cli_output_formatter.format_output(sr)

    assert expected_color in results_msg


def test_untriaged_color(monkeypatch, cli_output_formatter):
    run_priority_color_test(
        monkeypatch, cli_output_formatter, "CVE-2020-1006", const.UNTRIAGED,
    )


def test_negligible_color(monkeypatch, cli_output_formatter):
    run_priority_color_test(
        monkeypatch, cli_output_formatter, "CVE-2020-1008", const.NEGLIGIBLE,
    )


def test_low_color(monkeypatch, cli_output_formatter):
    run_priority_color_test(
        monkeypatch, cli_output_formatter, "CVE-2020-1005", const.LOW
    )


def test_medium_color(monkeypatch, cli_output_formatter):
    run_priority_color_test(
        monkeypatch, cli_output_formatter, "CVE-2020-1003", const.MEDIUM
    )


def test_high_color(monkeypatch, cli_output_formatter):
    run_priority_color_test(
        monkeypatch, cli_output_formatter, "CVE-2020-1001", const.HIGH
    )


def test_critical_color(monkeypatch, cli_output_formatter):
    run_priority_color_test(
        monkeypatch, cli_output_formatter, "CVE-2020-1007", const.CRITICAL
    )


# TODO: Test ubuntu archive colors after UA detection is enabled
