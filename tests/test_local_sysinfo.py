import logging
import os
import sys
from unittest.mock import MagicMock

import pytest

import cvescan.constants as const
import cvescan.dpkg_parser as dpkg_parser
from cvescan.errors import DistribIDError, PkgCountError
from cvescan.local_sysinfo import LocalSysInfo

DEFAULT_INSTALLED_PKGS = {
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
sys.path.append("tests/assets/syslibs")


class MockResponses:
    def __init__(self):
        self.sys_argv = list("cvescan")
        self.os_path_dirname = "/test"
        self.os_path_abspath = "/test"
        self.environ_snap_user_common = None
        self.get_distro_information_raises = False
        self.get_distro_information = {"ID": "Ubuntu", "CODENAME": "trusty"}
        self.lsb_release_file = "tests/assets/lsb-release"
        self.ua_status_file = "tests/assets/ubuntu-advantage-status-disabled.json"
        self.installed_pkgs = lambda logger: DEFAULT_INSTALLED_PKGS


def apply_mock_responses(monkeypatch, mock_responses):
    monkeypatch.setattr(sys, "argv", mock_responses.sys_argv)
    monkeypatch.setattr(os.path, "dirname", lambda x: mock_responses.os_path_dirname)
    monkeypatch.setattr(os.path, "abspath", lambda x: mock_responses.os_path_abspath)
    if mock_responses.environ_snap_user_common is None:
        monkeypatch.delenv("SNAP_USER_COMMON", raising=False)
    else:
        monkeypatch.setenv("SNAP_USER_COMMON", mock_responses.environ_snap_user_common)

    import lsb_release

    if mock_responses.get_distro_information_raises is True:
        monkeypatch.setattr(lsb_release, "get_distro_information", raise_mock_exception)
    else:
        monkeypatch.setattr(
            lsb_release,
            "get_distro_information",
            lambda: mock_responses.get_distro_information,
        )

    monkeypatch.setattr(const, "LSB_RELEASE_FILE", mock_responses.lsb_release_file)
    monkeypatch.setattr(const, "UA_STATUS_FILE", mock_responses.ua_status_file)
    monkeypatch.setattr(
        dpkg_parser, "get_installed_pkgs_from_dpkg_list", mock_responses.installed_pkgs
    )


def raise_mock_exception():
    raise Exception("Mock Exception")


@pytest.fixture
def null_logger():
    logger = logging.getLogger("cvescan.null")
    if not logger.hasHandlers():
        logger.addHandler(logging.NullHandler())

    return logger


class MockLocalSysInfo(LocalSysInfo):
    def __init__(self, logger):
        self._get_raw_ua_status = MagicMock()
        super().__init__(logger)


def test_is_snap_false(monkeypatch, null_logger):
    mock_responses = MockResponses()
    apply_mock_responses(monkeypatch, mock_responses)

    sysinfo = LocalSysInfo(null_logger)
    assert not sysinfo.is_snap
    assert sysinfo.snap_user_common is None


def test_is_snap_true(monkeypatch, null_logger):
    mock_responses = MockResponses()
    mock_responses.environ_snap_user_common = "/home/test/snap"
    apply_mock_responses(monkeypatch, mock_responses)

    sysinfo = LocalSysInfo(null_logger)
    assert sysinfo.is_snap
    assert sysinfo.snap_user_common == "/home/test/snap"


def test_get_codename_lsb_module(monkeypatch, null_logger):
    mock_responses = MockResponses()
    apply_mock_responses(monkeypatch, mock_responses)

    sysinfo = LocalSysInfo(null_logger)
    assert sysinfo.codename == "trusty"


def test_get_codename_lsb_module_empty(monkeypatch, null_logger):
    mock_responses = MockResponses()
    mock_responses.get_distro_information = {}
    apply_mock_responses(monkeypatch, mock_responses)

    with pytest.raises(DistribIDError) as di:
        sysinfo = LocalSysInfo(null_logger)
        # This property is lazy-loaded
        sysinfo.codename

    assert "UNKNOWN" in str(di)


def test_get_codename_lsb_module_other(monkeypatch, null_logger):
    mock_responses = MockResponses()
    mock_responses.get_distro_information = {"ID": "something_else"}
    apply_mock_responses(monkeypatch, mock_responses)

    with pytest.raises(DistribIDError) as di:
        sysinfo = LocalSysInfo(null_logger)
        # This property is lazy-loaded
        sysinfo.codename

    assert "something_else" in str(di)


def test_get_codename_from_file(monkeypatch, null_logger):
    mock_responses = MockResponses()
    mock_responses.get_distro_information_raises = True
    apply_mock_responses(monkeypatch, mock_responses)

    sysinfo = LocalSysInfo(null_logger)
    assert sysinfo.codename == "trusty"


def test_get_codename_from_not_ubuntu(monkeypatch, null_logger):
    mock_responses = MockResponses()
    mock_responses.get_distro_information_raises = True
    mock_responses.lsb_release_file = "tests/assets/lsb-release-not-ubuntu"
    apply_mock_responses(monkeypatch, mock_responses)

    with pytest.raises(DistribIDError) as di:
        sysinfo = LocalSysInfo(null_logger)
        # This property is lazy-loaded
        sysinfo.codename

    assert "not-ubuntu" in str(di)


def test_package_count(monkeypatch, null_logger):
    mock_responses = MockResponses()
    apply_mock_responses(monkeypatch, mock_responses)

    sysinfo = LocalSysInfo(null_logger)
    # This property is lazy-loaded
    assert sysinfo.package_count == 14


def test_package_count_error(monkeypatch, null_logger):
    mock_responses = MockResponses()
    mock_responses.installed_pkgs = lambda logger: raise_mock_exception()
    apply_mock_responses(monkeypatch, mock_responses)

    with pytest.raises(PkgCountError):
        sysinfo = LocalSysInfo(null_logger)
        # This property is lazy-loaded
        sysinfo.package_count


def test_installed_pkgs_list(monkeypatch, null_logger):
    mock_responses = MockResponses()
    apply_mock_responses(monkeypatch, mock_responses)

    sysinfo = LocalSysInfo(null_logger)
    assert sysinfo.installed_pkgs == DEFAULT_INSTALLED_PKGS


def test_esm_infra_enabled(monkeypatch, null_logger):
    mock_responses = MockResponses()
    mock_responses.ua_status_file = "tests/assets/ubuntu-advantage-status-enabled.json"
    apply_mock_responses(monkeypatch, mock_responses)
    sysinfo = LocalSysInfo(null_logger)

    assert sysinfo.esm_infra_enabled is True


def test_esm_infra_disabled(monkeypatch, null_logger):
    mock_responses = MockResponses()
    mock_responses.ua_status_file = "tests/assets/ubuntu-advantage-status-disabled.json"
    apply_mock_responses(monkeypatch, mock_responses)
    sysinfo = LocalSysInfo(null_logger)

    assert sysinfo.esm_infra_enabled is False


def test_esm_apps_enabled(monkeypatch, null_logger):
    mock_responses = MockResponses()
    mock_responses.ua_status_file = "tests/assets/ubuntu-advantage-status-enabled.json"
    apply_mock_responses(monkeypatch, mock_responses)
    sysinfo = LocalSysInfo(null_logger)

    assert sysinfo.esm_apps_enabled is True


def test_esm_apps_disabled(monkeypatch, null_logger):
    mock_responses = MockResponses()
    mock_responses.ua_status_file = "tests/assets/ubuntu-advantage-status-disabled.json"
    apply_mock_responses(monkeypatch, mock_responses)
    sysinfo = LocalSysInfo(null_logger)

    assert sysinfo.esm_apps_enabled is False


def test_esm_apps_missing(monkeypatch, null_logger):
    mock_responses = MockResponses()
    mock_responses.ua_status_file = "tests/assets/ubuntu-advantage-status-missing.json"
    apply_mock_responses(monkeypatch, mock_responses)
    sysinfo = LocalSysInfo(null_logger)

    assert sysinfo.esm_apps_enabled is False
    assert sysinfo.esm_infra_enabled is False


def test_esm_apps_missing_status_field(monkeypatch, null_logger):
    mock_responses = MockResponses()
    mock_responses.ua_status_file = (
        "tests/assets/ubuntu-advantage-status-malformed.json"
    )
    apply_mock_responses(monkeypatch, mock_responses)
    sysinfo = LocalSysInfo(null_logger)

    assert sysinfo.esm_apps_enabled is False
    assert sysinfo.esm_infra_enabled is False


def test_esm_apps_malformed_json(monkeypatch, null_logger):
    mock_responses = MockResponses()
    mock_responses.ua_status_file = (
        "tests/assets/ubuntu-advantage-status-malformed-json.json"
    )
    apply_mock_responses(monkeypatch, mock_responses)
    sysinfo = LocalSysInfo(null_logger)

    assert sysinfo.esm_apps_enabled is False
    assert sysinfo.esm_infra_enabled is False


def test_no_snap_ua_status_path(monkeypatch, null_logger):
    mock_responses = MockResponses()
    mock_responses.ua_status_file = "tests/assets/ubuntu-advantage-status-missing.json"
    apply_mock_responses(monkeypatch, mock_responses)
    sysinfo = MockLocalSysInfo(null_logger)

    # This property is lazy-loaded
    sysinfo.esm_apps_enabled

    sysinfo._get_raw_ua_status.assert_called_with(const.UA_STATUS_FILE)


def test_snap_ua_status_path(monkeypatch, null_logger):
    mock_responses = MockResponses()
    mock_responses.environ_snap_user_common = "/home/test/snap"
    mock_responses.ua_status_file = const.UA_STATUS_FILE
    apply_mock_responses(monkeypatch, mock_responses)
    sysinfo = MockLocalSysInfo(null_logger)

    # This property is lazy-loaded
    sysinfo.esm_infra_enabled

    sysinfo._get_raw_ua_status.assert_called_with(
        "/var/lib/snapd/hostfs/var/lib/ubuntu-advantage/status.json"
    )


def test_ua_fnf(monkeypatch, null_logger):
    def raise_(x):
        raise x

    mock_responses = MockResponses()
    mock_responses.ua_status_file = "tests/assets/ubuntu-advantage-status-enabled.json"
    apply_mock_responses(monkeypatch, mock_responses)
    monkeypatch.setattr(
        LocalSysInfo,
        "_get_raw_ua_status",
        lambda *args, **kwargs: raise_(FileNotFoundError()),
    )
    sysinfo = LocalSysInfo(null_logger)

    assert sysinfo.esm_apps_enabled is False
    assert sysinfo.esm_infra_enabled is False


def test_ua_permission_denied(monkeypatch, null_logger):
    def raise_(x):
        raise x

    mock_responses = MockResponses()
    mock_responses.ua_status_file = "tests/assets/ubuntu-advantage-status-enabled.json"
    apply_mock_responses(monkeypatch, mock_responses)
    monkeypatch.setattr(
        LocalSysInfo,
        "_get_raw_ua_status",
        lambda *args, **kwargs: raise_(PermissionError()),
    )
    sysinfo = LocalSysInfo(null_logger)

    assert sysinfo.esm_apps_enabled is False
    assert sysinfo.esm_infra_enabled is False
