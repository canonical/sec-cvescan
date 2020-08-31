import pytest

from cvescan import manifest_parser as mp
from cvescan.target_sysinfo import TargetSysInfo


class MockOpt:
    def __init__(self, manifest_mode):
        self.manifest_mode = manifest_mode
        self.manifest_file = "/tmp/manifest" if manifest_mode else None


class MockLocalSysInfo:
    def __init__(self):
        self.installed_pkgs = {"pkg1": "1.1.0-1", "pkg2": "2.2.0-3.1"}
        self.codename = "bionic"
        self.esm_apps_enabled = False
        self.esm_infra_enabled = True


@pytest.fixture(scope="module")
def manifest_data():
    return ({"pkg3": "3.0.1-2", "pkg4": "4.1.1-1", "pkg5": "1.2.3-9"}, "focal")


@pytest.fixture
def patch_manifest_parser(monkeypatch, manifest_data):
    monkeypatch.setattr(mp, "parse_manifest_file", lambda file_path: manifest_data)


def test_no_manifest():
    manifest_mode = False
    opt = MockOpt(manifest_mode)
    local_sysinfo = MockLocalSysInfo()

    target_sys_info = TargetSysInfo(opt, local_sysinfo)

    assert target_sys_info.installed_pkgs == local_sysinfo.installed_pkgs
    assert target_sys_info.codename == local_sysinfo.codename
    assert target_sys_info.esm_apps_enabled is False
    assert target_sys_info.esm_infra_enabled is True
    assert target_sys_info.pkg_count == 2


def test_installed_pkgs_and_codename_with_manifest(
    patch_manifest_parser, manifest_data
):
    manifest_mode = True
    opt = MockOpt(manifest_mode)
    local_sysinfo = MockLocalSysInfo()

    target_sys_info = TargetSysInfo(opt, local_sysinfo)

    assert target_sys_info.installed_pkgs == manifest_data[0]
    assert target_sys_info.codename == manifest_data[1]
    assert target_sys_info.esm_apps_enabled is None
    assert target_sys_info.esm_apps_enabled is None
    assert target_sys_info.pkg_count == 3
