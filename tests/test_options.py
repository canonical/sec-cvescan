import os

import pytest

from cvescan.errors import ArgumentError
from cvescan.options import Options

SCRIPTDIR = "fakedir/"
BASE_URL = "https://people.canonical.com/~ubuntu-security/oval"


class MockArgs:
    def __init__(self):
        self.cve = None
        self.priority = "high"
        self.silent = False
        self.oval_file = None
        self.manifest = None
        self.file = None
        self.nagios = False
        self.list = False
        self.test = False
        self.updates = False
        self.verbose = False
        self.experimental = False


class MockSysInfo:
    def __init__(self):
        self.scriptdir = SCRIPTDIR
        self.distrib_codename = "focal"


@pytest.fixture
def mock_args():
    return MockArgs()


@pytest.fixture
def mock_sysinfo():
    return MockSysInfo()


def test_set_no_modes(mock_args, mock_sysinfo):
    opt = Options(mock_args, mock_sysinfo)

    assert opt.experimental_mode is False
    assert opt.manifest_mode is False
    assert opt.nagios_mode is False


def test_set_experimental(mock_args, mock_sysinfo):
    mock_args.experimental = True
    opt = Options(mock_args, mock_sysinfo)

    assert opt.experimental_mode is True
    assert opt.manifest_mode is False
    assert opt.nagios_mode is False


def test_set_manifest_mode(mock_args, mock_sysinfo):
    mock_args.manifest = True
    opt = Options(mock_args, mock_sysinfo)

    assert opt.experimental_mode is False
    assert opt.manifest_mode is True
    assert opt.nagios_mode is False


def test_set_nagios_mode(mock_args, mock_sysinfo):
    mock_args.nagios = True
    opt = Options(mock_args, mock_sysinfo)

    assert opt.experimental_mode is False
    assert opt.manifest_mode is False
    assert opt.nagios_mode is True


def test_set_experimental_nagios_manifest(mock_args, mock_sysinfo):
    mock_args.experimental = True
    mock_args.manifest = True
    mock_args.nagios = True
    opt = Options(mock_args, mock_sysinfo)

    assert opt.experimental_mode is True
    assert opt.manifest_mode is True
    assert opt.nagios_mode is True


def test_set_distrib_codename(mock_args, mock_sysinfo):
    opt = Options(mock_args, mock_sysinfo)

    assert opt.distrib_codename == "focal"


def test_set_distrib_codename_manifest(mock_args, mock_sysinfo):
    mock_args.manifest = "bionic"
    opt = Options(mock_args, mock_sysinfo)

    assert opt.distrib_codename == "bionic"


def test_set_oval_file_default(monkeypatch, mock_args, mock_sysinfo):
    opt = Options(mock_args, mock_sysinfo)

    assert opt.oval_file == "com.ubuntu.focal.cve.oval.xml"


def test_set_oval_file_user_specified(monkeypatch, mock_args, mock_sysinfo):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)

    mock_args.oval_file = "/my/path/fakefile.xml"
    opt = Options(mock_args, mock_sysinfo)

    assert opt.oval_file == "/my/path/fakefile.xml"


def test_set_oval_file_manifest(mock_args, mock_sysinfo):
    mock_args.manifest = "xenial"
    opt = Options(mock_args, mock_sysinfo)

    assert opt.oval_file == "oci.com.ubuntu.xenial.cve.oval.xml"


def test_set_oval_file_experimental(mock_args, mock_sysinfo):
    mock_args.experimental = True
    opt = Options(mock_args, mock_sysinfo)

    assert opt.oval_file == "alpha.com.ubuntu.focal.cve.oval.xml"


def test_set_oval_file_experimental_manifest(mock_args, mock_sysinfo):
    mock_args.experimental = True
    mock_args.manifest = "focal"
    opt = Options(mock_args, mock_sysinfo)

    assert opt.oval_file == "alpha.oci.com.ubuntu.focal.cve.oval.xml"


def test_set_oval_url_default(monkeypatch, mock_args, mock_sysinfo):
    opt = Options(mock_args, mock_sysinfo)

    assert opt.oval_base_url == BASE_URL


def test_set_oval_url_user_specified(monkeypatch, mock_args, mock_sysinfo):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)

    mock_args.oval_file = "/my/path/fakefile.xml"
    opt = Options(mock_args, mock_sysinfo)

    assert opt.oval_base_url is None


def test_set_oval_url_manifest(mock_args, mock_sysinfo):
    mock_args.manifest = "xenial"
    opt = Options(mock_args, mock_sysinfo)

    assert opt.oval_base_url == BASE_URL


def test_set_oval_url_experimental(mock_args, mock_sysinfo):
    mock_args.experimental = True
    opt = Options(mock_args, mock_sysinfo)

    assert opt.oval_base_url == BASE_URL + "/alpha"


def test_set_oval_url_experimental_manifest(mock_args, mock_sysinfo):
    mock_args.experimental = True
    mock_args.manifest = "focal"
    opt = Options(mock_args, mock_sysinfo)

    assert opt.oval_base_url == BASE_URL + "/alpha"


def test_set_download_oval_file_default(monkeypatch, mock_args, mock_sysinfo):
    opt = Options(mock_args, mock_sysinfo)

    assert opt.download_oval_file is True


def test_set_download_oval_file_user_specified(monkeypatch, mock_args, mock_sysinfo):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)

    mock_args.oval_file = "/my/path/fakefile.xml"
    opt = Options(mock_args, mock_sysinfo)

    assert opt.download_oval_file is False


def test_set_download_oval_file_manifest(mock_args, mock_sysinfo):
    mock_args.manifest = "xenial"
    opt = Options(mock_args, mock_sysinfo)

    assert opt.download_oval_file is True


def test_set_download_oval_file_experimental(mock_args, mock_sysinfo):
    mock_args.experimental = True
    opt = Options(mock_args, mock_sysinfo)

    assert opt.download_oval_file is True


def test_set_download_oval_file_experimental_manifest(mock_args, mock_sysinfo):
    mock_args.experimental = True
    mock_args.manifest = "focal"
    opt = Options(mock_args, mock_sysinfo)

    assert opt.download_oval_file is True


def test_set_manifest_file(mock_args, mock_sysinfo):
    opt = Options(mock_args, mock_sysinfo)

    assert opt.manifest_file is None


def test_set_manifest_file_default(mock_args, mock_sysinfo):
    mock_args.manifest = "bionic"
    opt = Options(mock_args, mock_sysinfo)

    assert opt.manifest_file is None


def test_set_manifest_file_user_specified(monkeypatch, mock_args, mock_sysinfo):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)

    mock_args.manifest = "bionic"
    mock_args.file = "/tmp/testmanifest"
    opt = Options(mock_args, mock_sysinfo)

    assert opt.manifest_file == "/tmp/testmanifest"


def test_set_manifest_file_abspath(monkeypatch, mock_args, mock_sysinfo):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)
    monkeypatch.setattr(os.path, "abspath", lambda x: "/tmp/testmanifest")

    mock_args.manifest = "bionic"
    mock_args.file = "../../../../../../../../../../../../tmp/testmanifest"
    opt = Options(mock_args, mock_sysinfo)

    assert opt.manifest_file == "/tmp/testmanifest"


def test_set_not_verbose(mock_args, mock_sysinfo):
    opt = Options(mock_args, mock_sysinfo)

    assert opt.verbose_oscap_options == ""


def test_set_verbose(mock_args, mock_sysinfo):
    mock_args.verbose = True
    opt = Options(mock_args, mock_sysinfo)

    assert "--verbose" in opt.verbose_oscap_options


def test_set_cve_default(mock_args, mock_sysinfo):
    opt = Options(mock_args, mock_sysinfo)

    assert opt.cve is None


def test_set_cve(mock_args, mock_sysinfo):
    mock_args.cve = "CVE-2020-1234"
    opt = Options(mock_args, mock_sysinfo)

    assert opt.cve == "CVE-2020-1234"


def test_set_priority_default(mock_args, mock_sysinfo):
    opt = Options(mock_args, mock_sysinfo)

    assert opt.priority == "high"


def test_set_priority(mock_args, mock_sysinfo):
    mock_args.priority = "low"
    opt = Options(mock_args, mock_sysinfo)

    assert opt.priority == "low"


def test_set_all_cve_false(mock_args, mock_sysinfo):
    mock_args.updates = True
    opt = Options(mock_args, mock_sysinfo)

    assert opt.all_cve is False


def test_set_all_cve_true(mock_args, mock_sysinfo):
    mock_args.updates = False
    opt = Options(mock_args, mock_sysinfo)

    assert opt.all_cve is True


@pytest.mark.parametrize(
    "invalid_cve", ["CE-2020-1234", "CVE-202-1234", "CVE-2020-123", "random_string"]
)
def test_invalid_cve(invalid_cve, mock_args, mock_sysinfo):
    with pytest.raises(ValueError) as ve:
        mock_args.cve = invalid_cve
        Options(mock_args, mock_sysinfo)

    assert "Invalid CVE ID" in str(ve)


def test_invalid_manifest_file_missing_manifest(monkeypatch, mock_args, mock_sysinfo):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)
    with pytest.raises(ArgumentError) as ae:
        mock_args.file = "testfile"
        Options(mock_args, mock_sysinfo)

    assert "Cannot specify" in str(ae)


def test_invalid_nagios_and_cve(mock_args, mock_sysinfo):
    with pytest.raises(ArgumentError) as ae:
        mock_args.nagios = True
        mock_args.cve = "CVE-2020-1234"
        Options(mock_args, mock_sysinfo)

    assert "options are incompatible" in str(ae)


def test_invalid_nagios_and_silent(mock_args, mock_sysinfo):
    with pytest.raises(ArgumentError) as ae:
        mock_args.nagios = True
        mock_args.silent = True
        Options(mock_args, mock_sysinfo)

    assert "options are incompatible" in str(ae)


def test_invalid_nagios_and_updates(mock_args, mock_sysinfo):
    with pytest.raises(ArgumentError) as ae:
        mock_args.nagios = True
        mock_args.updates = True
        Options(mock_args, mock_sysinfo)

    assert "options are incompatible" in str(ae)


def test_invalid_silent_without_cve(monkeypatch, mock_args, mock_sysinfo):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)
    with pytest.raises(ArgumentError) as ae:
        mock_args.silent = True
        Options(mock_args, mock_sysinfo)

    assert "Cannot specify" in str(ae)


def test_invalid_verbose_and_silent(mock_args, mock_sysinfo):
    with pytest.raises(ArgumentError):
        mock_args.cve = "CVE-2020-1234"
        mock_args.verbose = True
        mock_args.silent = True
        Options(mock_args, mock_sysinfo)


def test_invalid_manifest_file_not_found(monkeypatch, mock_args, mock_sysinfo):
    monkeypatch.setattr(os.path, "isfile", lambda x: False)

    with pytest.raises(ArgumentError) as ae:
        mock_args.manifest = True
        mock_args.file = "test"
        Options(mock_args, mock_sysinfo)

    assert "Cannot find file" in str(ae)


def test_invalid_oval_file_not_found(monkeypatch, mock_args, mock_sysinfo):
    monkeypatch.setattr(os.path, "isfile", lambda x: False)

    with pytest.raises(ArgumentError) as ae:
        mock_args.oval_file = "test"
        Options(mock_args, mock_sysinfo)

    assert "Cannot find file" in str(ae)
