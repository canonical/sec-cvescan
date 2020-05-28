import json
import logging

import pytest

import cvescan.constants as const
from cvescan.cvescanner import CVEScanner
from cvescan.scan_result import ScanResult


def null_logger():
    logger = logging.getLogger("cvescan.null")
    if not logger.hasHandlers():
        logger.addHandler(logging.NullHandler())

    return logger


@pytest.fixture
def default_cve_scanner():
    return CVEScanner(null_logger())


@pytest.fixture(scope="module")
def uct_data():
    with open("tests/assets/uct.json") as json_file:
        return json.load(json_file)


@pytest.fixture
def default_installed_pkgs():
    return {
        "pkg1": "1:1.2.3-4+deb9u2ubuntu0.1",
        "pkg2": "1:1.2.3-4+deb9u2ubuntu0.1",
        "pkg3": "10.2.3-2",
        "pkg4": "2.0.0+dfsg-1ubuntu1",
        "pkg5": "2.0.0+dfsg-1ubuntu1",
        "pkg6": "2.0.0+dfsg-1ubuntu1",
        "pkg7": "1.2.0-1",
    }


def test_no_cves(default_cve_scanner, default_installed_pkgs):
    results = default_cve_scanner.scan("bionic", dict(), default_installed_pkgs)
    assert len(results) == 0


def test_no_fix_available(default_cve_scanner, uct_data):
    cve_id = "CVE-2020-1000"
    installed_pkgs = {"pkg3": "10.2.3-2"}
    tmp_uct_data = {cve_id: uct_data[cve_id]}

    results = default_cve_scanner.scan("bionic", tmp_uct_data, installed_pkgs)

    assert len(results) == 1
    assert results[0].cve_id == cve_id
    assert results[0].fixed_version is None
    assert results[0].repository is None


def test_fix_available_infra(default_cve_scanner, uct_data):
    cve_id = "CVE-2020-1005"
    installed_pkgs = {"pkg3": "10.2.3-2"}
    tmp_uct_data = {cve_id: uct_data[cve_id]}

    results = default_cve_scanner.scan("bionic", tmp_uct_data, installed_pkgs)

    assert len(results) == 1
    assert results[0].cve_id == cve_id
    assert results[0].fixed_version == "10.2.3-2ubuntu0.1"
    assert results[0].repository == const.UA_INFRA


def test_fix_available_apps(default_cve_scanner, uct_data):
    cve_id = "CVE-2020-1002"
    installed_pkgs = {"pkg6": "2.0.0+dfsg-1ubuntu1"}
    tmp_uct_data = {cve_id: uct_data[cve_id]}

    results = default_cve_scanner.scan("bionic", tmp_uct_data, installed_pkgs)

    assert len(results) == 1
    assert results[0].cve_id == cve_id
    assert results[0].fixed_version == "2.0.0+dfsg-1ubuntu1.1"
    assert results[0].repository == const.UA_APPS


def test_fix_available_archive(default_cve_scanner, uct_data):
    cve_id = "CVE-2020-1006"
    installed_pkgs = {"pkg5": "2.0.0+dfsg-1"}
    tmp_uct_data = {cve_id: uct_data[cve_id]}

    results = default_cve_scanner.scan("bionic", tmp_uct_data, installed_pkgs)

    assert len(results) == 1
    assert results[0].cve_id == cve_id
    assert results[0].fixed_version == "2.0.0+dfsg-1ubuntu1"
    assert results[0].repository == const.ARCHIVE


def test_DNE(default_cve_scanner, uct_data):
    cve_id = "CVE-2020-1007"
    installed_pkgs = {"pkg7": "1.2.0-1"}
    tmp_uct_data = {cve_id: uct_data[cve_id]}

    results = default_cve_scanner.scan("bionic", tmp_uct_data, installed_pkgs)

    assert len(results) == 0


def test_codename_missing(default_cve_scanner, uct_data):
    cve_id = "CVE-2020-1008"
    installed_pkgs = {"pkg7": "1.2.0-1"}
    tmp_uct_data = {cve_id: uct_data[cve_id]}

    results = default_cve_scanner.scan("bionic", tmp_uct_data, installed_pkgs)

    assert len(results) == 0


def test_cve_affects_mulitple_binaries(default_cve_scanner, uct_data):
    cve_id = "CVE-2020-1002"
    installed_pkgs = {"pkg4": "2.0.0+dfsg-1ubuntu1", "pkg6": "2.0.0+dfsg-1ubuntu1"}
    tmp_uct_data = {cve_id: uct_data[cve_id]}

    results = default_cve_scanner.scan("bionic", tmp_uct_data, installed_pkgs)

    assert len(results) == 2

    assert results[0].cve_id == cve_id
    assert results[0].package_name == "pkg4"
    assert results[0].fixed_version == "2.0.0+dfsg-1ubuntu1.1"
    assert results[0].repository == const.UA_APPS

    assert results[1].cve_id == cve_id
    assert results[1].package_name == "pkg6"
    assert results[1].fixed_version == "2.0.0+dfsg-1ubuntu1.1"
    assert results[1].repository == const.UA_APPS


def test_already_patched(default_cve_scanner, uct_data):
    cve_id = "CVE-2020-1002"
    installed_pkgs = {"pkg4": "2.0.+dfsg-1ubuntu1.1"}
    tmp_uct_data = {cve_id: uct_data[cve_id]}

    results = default_cve_scanner.scan("bionic", tmp_uct_data, installed_pkgs)

    assert len(results) == 0


def test_installed_version_later_than_patched(default_cve_scanner, uct_data):
    cve_id = "CVE-2020-1002"
    installed_pkgs = {"pkg4": "2.0.+dfsg-1ubuntu1.2"}
    tmp_uct_data = {cve_id: uct_data[cve_id]}

    results = default_cve_scanner.scan("bionic", tmp_uct_data, installed_pkgs)

    assert len(results) == 0


def test_multiple_source_pkgs(default_cve_scanner, uct_data):
    cve_id = "CVE-2020-1005"
    installed_pkgs = {"pkg1": "1:1.2.3-4", "pkg3": "10.2.3-2"}
    tmp_uct_data = {cve_id: uct_data[cve_id]}

    results = default_cve_scanner.scan("bionic", tmp_uct_data, installed_pkgs)

    assert len(results) == 2

    assert results[0].cve_id == cve_id
    assert results[0].priority == "low"
    assert results[0].package_name == "pkg1"
    assert results[0].fixed_version == "1:1.2.3-4+deb9u3"
    assert results[0].repository == const.UA_APPS

    assert results[1].cve_id == cve_id
    assert results[1].priority == "low"
    assert results[1].package_name == "pkg3"
    assert results[1].fixed_version == "10.2.3-2ubuntu0.1"
    assert results[1].repository == const.UA_INFRA


def test_whole_uct_json_file(default_cve_scanner, uct_data, default_installed_pkgs):
    expected_results = [
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

    results = default_cve_scanner.scan("bionic", uct_data, default_installed_pkgs)

    assert results == expected_results
