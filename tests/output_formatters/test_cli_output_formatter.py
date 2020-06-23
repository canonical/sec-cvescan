import re
import sys

import pytest
from conftest import MockOpt, MockSysInfo, filter_scan_results_by_cve_ids, null_logger

import cvescan.constants as const
from cvescan import TargetSysInfo
from cvescan.output_formatters import CLIOutputFormatter, ScanStats


class NoSummaryCLIOutputFormatter(CLIOutputFormatter):
    def _format_summary(self, stats: ScanStats, sysinfo: TargetSysInfo):
        return ""


class NoTableCLIOutputFormatter(CLIOutputFormatter):
    def _format_table(self, priority_results, fixable_results, sysinfo: TargetSysInfo):
        return ""


@pytest.fixture
def no_summary_cli_output_formatter():
    return NoSummaryCLIOutputFormatter(MockOpt(), null_logger())


@pytest.fixture
def no_table_cli_output_formatter():
    return NoTableCLIOutputFormatter(MockOpt(), null_logger())


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


def test_no_tty_no_color(monkeypatch, no_summary_cli_output_formatter):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    sr = filter_scan_results_by_cve_ids(["CVE-2020-1001"])

    (results_msg, return_code) = no_summary_cli_output_formatter.format_output(
        sr, MockSysInfo()
    )

    assert "\u001b" not in results_msg


def run_priority_color_test(
    monkeypatch, no_summary_cli_output_formatter, sysinfo, cve_id, priority_name
):
    priority_color_code = CLIOutputFormatter.priority_to_color_code[priority_name]
    run_color_test(
        monkeypatch,
        no_summary_cli_output_formatter,
        sysinfo,
        cve_id,
        priority_color_code,
    )


def run_repository_color_test(
    monkeypatch, no_summary_cli_output_formatter, sysinfo, cve_id, enabled
):
    if enabled:
        repository_color_code = const.REPOSITORY_ENABLED_COLOR_CODE
    elif enabled is None:
        repository_color_code = const.REPOSITORY_UNKNOWN_COLOR_CODE
    else:
        repository_color_code = const.REPOSITORY_DISABLED_COLOR_CODE
    run_color_test(
        monkeypatch,
        no_summary_cli_output_formatter,
        sysinfo,
        cve_id,
        repository_color_code,
    )


def run_color_test(
    monkeypatch, no_summary_cli_output_formatter, sysinfo, cve_id, color_code
):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)

    expected_color = "38;5;%dm" % color_code

    no_summary_cli_output_formatter.opt.unresolved = True
    sr = filter_scan_results_by_cve_ids([cve_id])

    (results_msg, return_code) = no_summary_cli_output_formatter.format_output(
        sr, sysinfo
    )

    assert expected_color in results_msg


def test_untriaged_color(monkeypatch, no_summary_cli_output_formatter):
    run_priority_color_test(
        monkeypatch,
        no_summary_cli_output_formatter,
        MockSysInfo(),
        "CVE-2020-1006",
        const.UNTRIAGED,
    )


def test_negligible_color(monkeypatch, no_summary_cli_output_formatter):
    run_priority_color_test(
        monkeypatch,
        no_summary_cli_output_formatter,
        MockSysInfo(),
        "CVE-2020-1008",
        const.NEGLIGIBLE,
    )


def test_low_color(monkeypatch, no_summary_cli_output_formatter):
    run_priority_color_test(
        monkeypatch,
        no_summary_cli_output_formatter,
        MockSysInfo(),
        "CVE-2020-1005",
        const.LOW,
    )


def test_medium_color(monkeypatch, no_summary_cli_output_formatter):
    run_priority_color_test(
        monkeypatch,
        no_summary_cli_output_formatter,
        MockSysInfo(),
        "CVE-2020-1003",
        const.MEDIUM,
    )


def test_high_color(monkeypatch, no_summary_cli_output_formatter):
    run_priority_color_test(
        monkeypatch,
        no_summary_cli_output_formatter,
        MockSysInfo(),
        "CVE-2020-1001",
        const.HIGH,
    )


def test_critical_color(monkeypatch, no_summary_cli_output_formatter):
    sysinfo = MockSysInfo()
    sysinfo.esm_apps_enabled = True
    sysinfo.esm_infra_enabled = True
    run_priority_color_test(
        monkeypatch,
        no_summary_cli_output_formatter,
        sysinfo,
        "CVE-2020-1007",
        const.CRITICAL,
    )


def test_ua_apps_enabled_color(monkeypatch, no_summary_cli_output_formatter):
    sysinfo = MockSysInfo()
    sysinfo.esm_apps_enabled = True
    run_repository_color_test(
        monkeypatch, no_summary_cli_output_formatter, sysinfo, "CVE-2020-1009", True
    )


def test_ua_apps_disabled_color(monkeypatch, no_summary_cli_output_formatter):
    sysinfo = MockSysInfo()
    sysinfo.esm_apps_enabled = False
    sysinfo.esm_infra_enabled = True
    run_repository_color_test(
        monkeypatch, no_summary_cli_output_formatter, sysinfo, "CVE-2020-1009", False
    )


def test_ua_apps_unknown_color(monkeypatch, no_summary_cli_output_formatter):
    sysinfo = MockSysInfo()
    sysinfo.esm_apps_enabled = None
    run_repository_color_test(
        monkeypatch, no_summary_cli_output_formatter, sysinfo, "CVE-2020-1009", None
    )


def test_ua_infra_enabled_color(monkeypatch, no_summary_cli_output_formatter):
    sysinfo = MockSysInfo()
    sysinfo.esm_infra_enabled = True
    run_repository_color_test(
        monkeypatch, no_summary_cli_output_formatter, sysinfo, "CVE-2020-1010", True
    )


def test_ua_infra_disabled_color(monkeypatch, no_summary_cli_output_formatter):
    sysinfo = MockSysInfo()
    sysinfo.esm_apps_enabled = True
    sysinfo.esm_infra_enabled = False
    run_repository_color_test(
        monkeypatch, no_summary_cli_output_formatter, sysinfo, "CVE-2020-1010", False
    )


def test_ua_infra_unknown_color(monkeypatch, no_summary_cli_output_formatter):
    sysinfo = MockSysInfo()
    sysinfo.esm_infra_enabled = None
    run_repository_color_test(
        monkeypatch, no_summary_cli_output_formatter, sysinfo, "CVE-2020-1010", None
    )


def test_ubuntu_repository_enabled_color(monkeypatch, no_summary_cli_output_formatter):
    run_repository_color_test(
        monkeypatch,
        no_summary_cli_output_formatter,
        MockSysInfo(),
        "CVE-2020-1001",
        True,
    )


def test_invalid_repository_disabled_color(
    monkeypatch, no_summary_cli_output_formatter
):
    no_summary_cli_output_formatter.opt.unresolved = True

    sysinfo = MockSysInfo()
    sysinfo.esm_infra_enabled = True

    run_repository_color_test(
        monkeypatch, no_summary_cli_output_formatter, sysinfo, "CVE-2020-1011", False
    )


def test_summary_nounresolved(monkeypatch, no_table_cli_output_formatter):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    cof = no_table_cli_output_formatter

    cof.opt.priority = const.LOW
    cof.opt.unresolved = False

    sysinfo = MockSysInfo()
    sysinfo.esm_apps_enabled = False
    sysinfo.esm_infra_enabled = False

    sr = filter_scan_results_by_cve_ids(
        [
            "CVE-2020-1001",
            "CVE-2020-1002",
            "CVE-2020-1003",
            "CVE-2020-1005",
            "CVE-2020-1009",
            "CVE-2020-1010",
        ]
    )

    (results_msg, return_code) = cof.format_output(sr, sysinfo)

    assert re.search(r"Ubuntu Release\s+bionic", results_msg)
    assert re.search(r"Installed Packages\s+100", results_msg)
    assert re.search(r"CVE Priority\s+low or higher", results_msg)
    assert re.search(r"Unique Packages Fixable by Patching\s+6", results_msg)
    assert re.search(r"Unique CVEs Fixable by Patching\s+5", results_msg)
    assert re.search(r"Vulnerabilities Fixable by Patching\s+10", results_msg)
    assert re.search(r"Vulnerabilities Fixable by ESM Apps\s+6", results_msg)
    assert re.search(r"Vulnerabilities Fixable by ESM Infra\s+2", results_msg)
    # Disabling for now
    # assert re.search(r"ESM Apps Enabled\s+No", results_msg)
    # assert re.search(r"ESM Infra Enabled\s+No", results_msg)
    assert re.search(r"Fixes Available by `apt-get upgrade`\s+2", results_msg)
    assert re.search(
        r"Available Fixes Not Applied by `apt-get upgrade`\s+8", results_msg
    )


def test_summary_priority_all(monkeypatch, no_table_cli_output_formatter):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    cof = no_table_cli_output_formatter

    sr = filter_scan_results_by_cve_ids(["CVE-2020-1001"])

    (results_msg, return_code) = cof.format_output(sr, MockSysInfo())

    assert re.search(r"CVE Priority\s+All", results_msg)


# Disabling for now
# def test_summary_infra_enabled(monkeypatch, no_table_cli_output_formatter):
# monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
# cof = no_table_cli_output_formatter
# sysinfo = MockSysInfo()
# sysinfo.esm_apps_enabled = False
# sysinfo.esm_infra_enabled = True

# sr = filter_scan_results_by_cve_ids(["CVE-2020-1001"])

# (results_msg, return_code) = cof.format_output(sr, sysinfo)

# assert re.search(r"ESM Apps Enabled\s+No", results_msg)
# assert re.search(r"ESM Infra Enabled\s+Yes", results_msg)


# def test_summary_apps_enabled(monkeypatch, no_table_cli_output_formatter):
# monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
# cof = no_table_cli_output_formatter
# sysinfo = MockSysInfo()
# sysinfo.esm_apps_enabled = True
# sysinfo.esm_inra_enabled = False

# sr = filter_scan_results_by_cve_ids(["CVE-2020-1001"])

# (results_msg, return_code) = cof.format_output(sr, sysinfo)

# assert re.search(r"ESM Apps Enabled\s+Yes", results_msg)
# assert re.search(r"ESM Infra Enabled\s+No", results_msg)


def run_esm_color_code_test(
    monkeypatch, output_formatter, sysinfo, repository_color_code, yn
):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)

    sr = filter_scan_results_by_cve_ids(["CVE-2020-1005"])

    (results_msg, return_code) = output_formatter.format_output(sr, sysinfo)

    fixable_color_code = r"\u001b\[38;5;%dm" % repository_color_code
    assert re.search(
        r"Vulnerabilities Fixable by ESM Apps\s+%s2" % fixable_color_code, results_msg
    )
    assert re.search(
        r"Vulnerabilities Fixable by ESM Infra\s+%s1" % fixable_color_code, results_msg
    )

    # Disabling for now
    # esm_color_code = r"\u001b\[38;5;%dm" % repository_color_code
    # assert re.search(r"ESM Apps Enabled\s+%s%s" % (esm_color_code, yn), results_msg)
    # assert re.search(r"ESM Infra Enabled\s+%s%s" % (esm_color_code, yn), results_msg)


def test_summary_esm_enabled_color(monkeypatch, no_table_cli_output_formatter):
    sysinfo = MockSysInfo()
    sysinfo.esm_apps_enabled = True
    sysinfo.esm_infra_enabled = True

    run_esm_color_code_test(
        monkeypatch,
        no_table_cli_output_formatter,
        sysinfo,
        const.REPOSITORY_ENABLED_COLOR_CODE,
        "Yes",
    )


def test_summary_esm_disabled_color(monkeypatch, no_table_cli_output_formatter):
    sysinfo = MockSysInfo()
    sysinfo.esm_apps_enabled = False
    sysinfo.esm_infra_enabled = False

    run_esm_color_code_test(
        monkeypatch,
        no_table_cli_output_formatter,
        sysinfo,
        const.REPOSITORY_DISABLED_COLOR_CODE,
        "No",
    )


def test_summary_manifest_esm_unknown_color(monkeypatch, no_table_cli_output_formatter):
    sysinfo = MockSysInfo()
    sysinfo.esm_apps_enabled = None
    sysinfo.esm_infra_enabled = None

    run_esm_color_code_test(
        monkeypatch,
        no_table_cli_output_formatter,
        sysinfo,
        const.REPOSITORY_UNKNOWN_COLOR_CODE,
        "Unknown",
    )


def run_fixes_not_applied_color_code_test(
    monkeypatch, output_formatter, sysinfo, repository_color_code, num_fixes
):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)

    sr = filter_scan_results_by_cve_ids(["CVE-2020-1005"])

    (results_msg, return_code) = output_formatter.format_output(sr, sysinfo)

    fixable_color_code = ""
    if num_fixes != 0:
        fixable_color_code = r"\u001b\[38;5;%dm" % repository_color_code
    assert re.search(
        r"Available Fixes Not Applied by `apt-get upgrade`\s+%s%d"
        % (fixable_color_code, num_fixes),
        results_msg,
    )


def test_summary_fixes_not_applied_color(monkeypatch, no_table_cli_output_formatter):
    sysinfo = MockSysInfo()
    sysinfo.esm_apps_enabled = False
    sysinfo.esm_infra_enabled = True

    run_fixes_not_applied_color_code_test(
        monkeypatch,
        no_table_cli_output_formatter,
        sysinfo,
        const.REPOSITORY_DISABLED_COLOR_CODE,
        2,
    )

    sysinfo.esm_apps_enabled = True
    sysinfo.esm_infra_enabled = False

    run_fixes_not_applied_color_code_test(
        monkeypatch,
        no_table_cli_output_formatter,
        sysinfo,
        const.REPOSITORY_DISABLED_COLOR_CODE,
        1,
    )


def test_summary_fixes_applied_color(monkeypatch, no_table_cli_output_formatter):
    sysinfo = MockSysInfo()
    sysinfo.esm_apps_enabled = True
    sysinfo.esm_infra_enabled = True

    run_fixes_not_applied_color_code_test(
        monkeypatch,
        no_table_cli_output_formatter,
        sysinfo,
        const.REPOSITORY_ENABLED_COLOR_CODE,
        0,
    )


def test_summary_fixes_unknown_color(monkeypatch, no_table_cli_output_formatter):
    sysinfo = MockSysInfo()
    sysinfo.esm_apps_enabled = None
    sysinfo.esm_infra_enabled = None

    run_fixes_not_applied_color_code_test(
        monkeypatch,
        no_table_cli_output_formatter,
        sysinfo,
        const.REPOSITORY_UNKNOWN_COLOR_CODE,
        3,
    )


def test_show_links(run_show_links_test):
    run_show_links_test(NoSummaryCLIOutputFormatter)


def test_no_show_links(run_no_show_links_test):
    run_no_show_links_test(NoSummaryCLIOutputFormatter)


def test_experimental_filter(run_non_experimental_filter_test_cli):
    run_non_experimental_filter_test_cli(CLIOutputFormatter)


def test_summary_experimental_filter(monkeypatch, no_table_cli_output_formatter):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    cof = no_table_cli_output_formatter
    sysinfo = MockSysInfo()
    sysinfo.esm_apps_enabled = False
    sysinfo.esm_infra_enabled = True

    cof.opt.experimental_mode = False

    sr = filter_scan_results_by_cve_ids(["CVE-2020-1001"])

    (results_msg, return_code) = cof.format_output(sr, sysinfo)

    assert "Vulnerabilities Fixable by ESM" not in results_msg
    assert "ESM Apps Enabled" not in results_msg
    assert "ESM Infra Enabled" not in results_msg
    assert "Available Fixes Not Applied" not in results_msg


def test_no_results_no_header(monkeypatch):
    header_regex = r"CVE ID\s+PRIORITY\s+PACKAGE\s+FIXED VERSION\s+REPOSITORY"

    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    cof = CLIOutputFormatter(MockOpt(), null_logger())
    sysinfo = MockSysInfo()

    cof.opt.experimental_mode = True
    cof.opt.unresolved = False

    sr = filter_scan_results_by_cve_ids(["CVE-2020-1003"])

    (results_msg, return_code) = cof.format_output(sr, sysinfo)

    assert not re.search(header_regex, results_msg)
