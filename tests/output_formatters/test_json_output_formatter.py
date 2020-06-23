import json

from conftest import MockOpt, MockSysInfo, filter_scan_results_by_cve_ids, null_logger

import cvescan.constants as const
from cvescan.output_formatters import JSONOutputFormatter


def test_priority_filter_all(run_priority_filter_all_test):
    run_priority_filter_all_test(JSONOutputFormatter)


def test_priority_filter_negligible(run_priority_filter_negligible_test):
    run_priority_filter_negligible_test(JSONOutputFormatter)


def test_priority_filter_low(run_priority_filter_low_test):
    run_priority_filter_low_test(JSONOutputFormatter)


def test_priority_filter_medium(run_priority_filter_medium_test):
    run_priority_filter_medium_test(JSONOutputFormatter)


def test_priority_filter_high(run_priority_filter_high_test):
    run_priority_filter_high_test(JSONOutputFormatter)


def test_priority_filter_critical(run_priority_filter_critical_test):
    run_priority_filter_critical_test(JSONOutputFormatter)


def test_no_unresolved_shown(run_no_unresolved_shown_test):
    run_no_unresolved_shown_test(JSONOutputFormatter)


def test_success_return_code(run_success_return_code_test):
    run_success_return_code_test(JSONOutputFormatter)


def test_vulnerable_return_code(run_vulnerable_return_code_test):
    run_vulnerable_return_code_test(JSONOutputFormatter)


def test_patch_available_return_code(run_patch_available_return_code_test):
    run_patch_available_return_code_test(JSONOutputFormatter)


def test_show_links(run_show_links_test):
    run_show_links_test(JSONOutputFormatter)


def test_always_show_links():
    sr = filter_scan_results_by_cve_ids(["CVE-2020-1004", "CVE-2020-1005"])
    opt = MockOpt()
    opt.unresolved = True
    opt.show_links = False
    formatter = JSONOutputFormatter(opt, null_logger())

    (results_msg, return_code) = formatter.format_output(sr, MockSysInfo())

    assert const.UCT_URL % "CVE-2020-1004" in results_msg
    assert const.UCT_URL % "CVE-2020-1005" in results_msg


def test_json_format():
    sr = filter_scan_results_by_cve_ids(
        ["CVE-2020-1000", "CVE-2020-1001", "CVE-2020-1005"]
    )

    opt = MockOpt()
    opt.priority = "all"
    opt.unresolved = True

    formatter = JSONOutputFormatter(opt, null_logger())

    (results_msg, return_code) = formatter.format_output(sr, MockSysInfo())

    expected_output = json.dumps(
        {
            "summary": {
                "ubuntu_release": "bionic",
                "num_installed_packages": 100,
                "num_cves": 2,
                "num_affected_packages": 3,
                "num_patchable_vulnerabilities": 5,
            },
            "CVE-2020-1000": {
                "url": "https://people.canonical.com/~ubuntu-security/cve/CVE-2020-1000",
                "packages": {
                    "pkg3": {"priority": "low", "fixed_version": "", "repository": ""}
                },
            },
            "CVE-2020-1001": {
                "url": "https://people.canonical.com/~ubuntu-security/cve/CVE-2020-1001",
                "packages": {
                    "pkg1": {
                        "priority": "high",
                        "fixed_version": "1:1.2.3-4+deb9u2ubuntu0.2",
                        "repository": "Ubuntu Archive",
                    },
                    "pkg2": {
                        "priority": "high",
                        "fixed_version": "1:1.2.3-4+deb9u2ubuntu0.2",
                        "repository": "Ubuntu Archive",
                    },
                },
            },
            "CVE-2020-1005": {
                "url": "https://people.canonical.com/~ubuntu-security/cve/CVE-2020-1005",
                "packages": {
                    "pkg1": {
                        "priority": "low",
                        "fixed_version": "1:1.2.3-4+deb9u3",
                        "repository": "UA for Apps",
                    },
                    "pkg2": {
                        "priority": "low",
                        "fixed_version": "1:1.2.3-4+deb9u3",
                        "repository": "UA for Apps",
                    },
                    "pkg3": {
                        "priority": "low",
                        "fixed_version": "10.2.3-2ubuntu0.1",
                        "repository": "UA for Infra",
                    },
                },
            },
        },
        indent=4,
        sort_keys=False,
    )

    assert results_msg == expected_output
