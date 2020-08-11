import json
from typing import List

from conftest import MockOpt, MockSysInfo, null_logger

import cvescan.constants as const
from cvescan import TargetSysInfo
from cvescan.output_formatters import ScanStats, SyslogOutputFormatter
from cvescan.scan_result import ScanResult

expected_output = json.dumps(
    {
        "summary": {
            "ubuntu_release": "bionic",
            "num_installed_packages": 100,
            "num_cves": 2,
            "num_affected_packages": 3,
            "num_patchable_vulnerabilities": 5,
        },
        "cves": {
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
                        "repository": "Ubuntu Archive",
                    },
                    "pkg2": {
                        "priority": "low",
                        "fixed_version": "1:1.2.3-4+deb9u3",
                        "repository": const.UA_APPS,
                    },
                    "pkg3": {
                        "priority": "low",
                        "fixed_version": "10.2.3-2ubuntu0.1",
                        "repository": const.UA_INFRA,
                    },
                },
            },
        },
    },
    indent=4,
    sort_keys=False,
)


class MockJSONOutputFormatter:
    def __init__(self):
        self.return_code = 0
        self.output = expected_output

    def format_output(
        self, scan_results: List[ScanResult], sysinfo: TargetSysInfo
    ) -> (str, int):
        return self.output, self.return_code


class MockSyslogOutputFormatter(SyslogOutputFormatter):
    def _get_scan_stats(
        self, scan_results: List[ScanResult], sysinfo: TargetSysInfo
    ) -> ScanStats:
        return ScanStats(0, 0, 0, 5, 0, 0, 0, 0)


def test_returns_json():
    opt = MockOpt()
    opt.syslog = True

    formatter = SyslogOutputFormatter(opt, null_logger(), MockJSONOutputFormatter())
    (results_msg, return_code) = formatter.format_output([], MockSysInfo())

    assert results_msg == expected_output
    assert return_code == 0


def test_returns_json_light():
    opt = MockOpt()
    opt.syslog_light = True

    formatter = MockSyslogOutputFormatter(opt, null_logger(), MockJSONOutputFormatter())
    (results_msg, return_code) = formatter.format_output([], MockSysInfo())

    assert results_msg == "5 vulnerabilites can be fixed by running `sudo apt upgrade`"
    assert return_code == 0


def test_return_code():
    opt = MockOpt()

    json_output_formatter = MockJSONOutputFormatter()
    json_output_formatter.return_code = 1
    formatter = SyslogOutputFormatter(opt, null_logger(), json_output_formatter)
    (results_msg, return_code) = formatter.format_output([], MockSysInfo())

    assert return_code == 1
