import logging
import subprocess

import pytest

import cvescan.dpkg_parser as dpkg_parser
from cvescan.errors import PkgCountError

TEST_MANIFEST_FILE = "tests/assets/manifests/%s.manifest"


@pytest.fixture
def null_logger():
    logger = logging.getLogger("cvescan.null")
    if not logger.hasHandlers():
        logger.addHandler(logging.NullHandler())

    return logger


class MockSubprocess:
    def __init__(self):
        self.out = (
            "Desired=Unknown/Install/Remove/Purge/Hold\n"
            "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n"  # noqa: E501
            "|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n"  # noqa: E501
            "||/ Name                                            Version                                     Architecture Description\n"  # noqa: E501
            "+++-===============================================-===========================================-============-===============================================================================\n"  # noqa: E501
            "ii  2to3                                            3.7.5-1                                     all          2to3 binary using python3\n"  # noqa: E501
            "ii  accountsservice                                 0.6.55-0ubuntu10                            amd64        query and manipulate user account information\n"  # noqa: E501
            "ii  accountwizard:i386                              4:19.04.3-0ubuntu1                          amd64        wizard for KDE PIM applications account setup\n"  # noqa: E501
            "ii  acl                                             2.2.53-4                                    amd64        access control list - utilities\n"  # noqa: E501
            "ii  acpi-support                                    0.143                                       amd64        scripts for handling many ACPI events\n"  # noqa: E501
            "rc  acpid                                           1:2.0.31-1ubuntu2                           amd64        Advanced Configuration and Power Interface event daemon\n"  # noqa: E501
            "ii  adduser:amd64                                   3.118ubuntu1                                all          add and remove users and groups\n"  # noqa: E501
            "ii  adwaita-icon-theme                              3.34.0-1ubuntu1                             all          default icon theme of GNOME (small subset)\n"  # noqa: E501
            "ui  afl                                             2.52b-5ubuntu1                              amd64        instrumentation-driven fuzzer for binary formats\n"  # noqa: E501
            "ii  afl-clang                                       2.52b-5ubuntu1                              amd64        instrumentation-driven fuzzer for binary formats - clang support\n"  # noqa: E501
            "hi  afl-cov                                         0.6.2-1                                     all          code coverage for afl (American Fuzzy Lop)\n"  # noqa: E501
            "ii  afl-doc                                         2.52b-5ubuntu1                              all          instrumentation-driven fuzzer for binary formats - documentation\n"  # noqa: E501
            "ii  akonadi-backend-mysql                           4:19.04.3-0ubuntu3                          all          MySQL storage backend for Akonadi\n"  # noqa: E501
            "ri  akonadi-server                                  4:19.04.3-0ubuntu3                          amd64        Akonadi PIM storage service\n"  # noqa: E501
            "pi  akregator                                       4:19.04.3-0ubuntu1                          amd64        RSS/Atom feed aggregator\n"  # noqa: E501
            "iH  alsa-base                                       1.0.25+dfsg-0ubuntu5                        all          ALSA driver configuration files\n"  # noqa: E501
            "in  alsa-tools-gui                                  1.1.7-1                                     amd64        GUI based ALSA utilities for specific hardware\n "  # noqa: E501
        )
        self.error = None
        self.returncode = 0

    def communicate(self):
        return (self.out, self.error)


def mock_subprocess(monkeypatch, mock_subprocess):
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: mock_subprocess)


def test_package_count_error(monkeypatch, null_logger):
    ms = MockSubprocess()
    ms.returncode = 1
    mock_subprocess(monkeypatch, ms)

    with pytest.raises(PkgCountError):
        dpkg_parser.get_installed_pkgs_from_dpkg_list(null_logger)


def test_installed_pkgs_dpkg_list(monkeypatch, null_logger):
    mock_subprocess(monkeypatch, MockSubprocess())

    installed_pkgs = dpkg_parser.get_installed_pkgs_from_dpkg_list(null_logger)
    expected_installed_pkgs = {
        "2to3": "3.7.5-1",
        "accountsservice": "0.6.55-0ubuntu10",
        "accountwizard": "4:19.04.3-0ubuntu1",
        "acl": "2.2.53-4",
        "acpi-support": "0.143",
        "adduser": "3.118ubuntu1",
        "adwaita-icon-theme": "3.34.0-1ubuntu1",
        "afl": "2.52b-5ubuntu1",
        "afl-clang": "2.52b-5ubuntu1",
        "afl-cov": "0.6.2-1",
        "afl-doc": "2.52b-5ubuntu1",
        "akonadi-backend-mysql": "4:19.04.3-0ubuntu3",
        "akonadi-server": "4:19.04.3-0ubuntu3",
        "akregator": "4:19.04.3-0ubuntu1",
    }
    assert installed_pkgs == expected_installed_pkgs


def test_parse_manifest_installed_pkgs():
    with open(TEST_MANIFEST_FILE % "bionic") as f:
        installed_pkgs = dpkg_parser.get_installed_pkgs_from_manifest(f)

    assert len(installed_pkgs) == 11
    assert installed_pkgs.get("accountsservice", None) == "0.6.45-1ubuntu1"
    assert installed_pkgs.get("acl", None) == "2.2.52-3build1"
    assert installed_pkgs.get("acpid", None) == "1:2.0.28-1ubuntu1"
    assert installed_pkgs.get("adduser", None) == "3.116ubuntu1"
    assert installed_pkgs.get("apparmor", None) == "2.12-4ubuntu5.1"
    assert installed_pkgs.get("apport", None) == "2.20.9-0ubuntu7.14"
    assert installed_pkgs.get("apport-symptoms", None) == "0.20"
    assert installed_pkgs.get("apt", None) == "1.6.12"
    assert installed_pkgs.get("base-files", None) == "10.1ubuntu2.8"
    assert installed_pkgs.get("python3-gdbm", None) == "3.6.9-1~18.04"
    assert installed_pkgs.get("update-manager-core", None) == "1:18.04.11.12"
