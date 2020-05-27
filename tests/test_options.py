import os

import pytest

from cvescan.errors import ArgumentError
from cvescan.options import Options

SCRIPTDIR = "fakedir/"
BASE_URL = "https://people.canonical.com/~ubuntu-security/uct/json"


class MockArgs:
    def __init__(self):
        self.cve = None
        self.priority = "high"
        self.silent = False
        self.oval_file = None
        self.manifest_file = None
        self.nagios = False
        self.uct_links = False
        self.test = False
        self.unresolved = False
        self.verbose = False
        self.experimental = False


@pytest.fixture
def mock_args():
    return MockArgs()


def test_set_no_modes(mock_args):
    opt = Options(mock_args)

    assert opt.experimental_mode is False
    assert opt.manifest_mode is False
    assert opt.nagios_mode is False


def test_set_experimental(mock_args):
    mock_args.experimental = True
    opt = Options(mock_args)

    assert opt.experimental_mode is True
    assert opt.manifest_mode is False
    assert opt.nagios_mode is False


def test_set_manifest_mode(monkeypatch, mock_args):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)
    monkeypatch.setattr(os.path, "abspath", lambda x: "/tmp/testmanifest")
    mock_args.manifest_file = "tests/assets/manifest/bionic.manifest"
    opt = Options(mock_args)

    assert opt.experimental_mode is False
    assert opt.manifest_mode is True
    assert opt.nagios_mode is False


def test_set_nagios_mode(mock_args):
    mock_args.nagios = True
    opt = Options(mock_args)

    assert opt.experimental_mode is False
    assert opt.manifest_mode is False
    assert opt.nagios_mode is True


def test_set_experimental_nagios_manifest(monkeypatch, mock_args):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)
    monkeypatch.setattr(os.path, "abspath", lambda x: "/tmp/testmanifest")

    mock_args.experimental = True
    mock_args.manifest_file = "tests/assets/manifest/bionic.manifest"
    mock_args.nagios = True
    opt = Options(mock_args)

    assert opt.experimental_mode is True
    assert opt.manifest_mode is True
    assert opt.nagios_mode is True


def test_set_oval_file_default(monkeypatch, mock_args):
    opt = Options(mock_args)

    assert opt.oval_file == "uct.json"


def test_set_oval_file_user_specified(monkeypatch, mock_args):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)

    mock_args.oval_file = "/my/path/fakefile.json"
    opt = Options(mock_args)

    assert opt.oval_file == "/my/path/fakefile.json"


def test_set_oval_file_experimental(mock_args):
    mock_args.experimental = True
    opt = Options(mock_args)

    assert opt.oval_file == "alpha.uct.json"


def test_set_oval_url_default(monkeypatch, mock_args):
    opt = Options(mock_args)

    assert opt.oval_base_url == BASE_URL


def test_set_oval_url_user_specified(monkeypatch, mock_args):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)

    mock_args.oval_file = "/my/path/fakefile.json"
    opt = Options(mock_args)

    assert opt.oval_base_url is None


def test_set_download_oval_file_default(monkeypatch, mock_args):
    opt = Options(mock_args)

    assert opt.download_oval_file is True


def test_set_download_oval_file_user_specified(monkeypatch, mock_args):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)

    mock_args.oval_file = "/my/path/fakefile.xml"
    opt = Options(mock_args)

    assert opt.download_oval_file is False


def test_set_download_oval_file_experimental(mock_args):
    mock_args.experimental = True
    opt = Options(mock_args)

    assert opt.download_oval_file is True


def test_set_manifest_file_none(mock_args):
    opt = Options(mock_args)

    assert opt.manifest_file is None


def test_set_manifest_file_user_specified(monkeypatch, mock_args):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)

    mock_args.manifest_file = "/tmp/testmanifest"
    opt = Options(mock_args)

    assert opt.manifest_file == "/tmp/testmanifest"


def test_set_manifest_file_abspath(monkeypatch, mock_args):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)
    monkeypatch.setattr(os.path, "abspath", lambda x: "/tmp/testmanifest")

    mock_args.manifest_file = "../../../../../../../../../../../../tmp/testmanifest"
    opt = Options(mock_args)

    assert opt.manifest_file == "/tmp/testmanifest"


def test_set_cve_default(mock_args):
    opt = Options(mock_args)

    assert opt.cve is None


def test_set_cve(mock_args):
    mock_args.cve = "CVE-2020-1234"
    mock_args.priority = "all"
    opt = Options(mock_args)

    assert opt.cve == "CVE-2020-1234"


def test_set_priority_default(mock_args):
    opt = Options(mock_args)

    assert opt.priority == "high"


def test_set_priority(mock_args):
    mock_args.priority = "low"
    opt = Options(mock_args)

    assert opt.priority == "low"


def test_set_unresolved_false(mock_args):
    mock_args.unresolved = False
    opt = Options(mock_args)

    assert opt.unresolved is False


def test_set_unresolved_true(mock_args):
    mock_args.unresolved = True
    opt = Options(mock_args)

    assert opt.unresolved is True


@pytest.mark.parametrize(
    "invalid_cve", ["CE-2020-1234", "CVE-202-1234", "CVE-2020-123", "random_string"]
)
def test_invalid_cve(invalid_cve, mock_args):
    with pytest.raises(ValueError) as ve:
        mock_args.cve = invalid_cve
        Options(mock_args)

    assert "Invalid CVE ID" in str(ve)


def test_invalid_nagios_and_cve(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.nagios = True
        mock_args.cve = "CVE-2020-1234"
        Options(mock_args)

    assert "options are incompatible" in str(ae)


def test_invalid_nagios_and_silent(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.nagios = True
        mock_args.silent = True
        Options(mock_args)

    assert "options are incompatible" in str(ae)


def test_invalid_nagios_and_unresolved(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.nagios = True
        mock_args.unresolved = True
        Options(mock_args)

    assert "options are incompatible" in str(ae)


def test_invalid_nagios_and_links(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.nagios = True
        mock_args.uct_links = True
        Options(mock_args)

    assert "options are incompatible" in str(ae)


def test_invalid_silent_without_cve(monkeypatch, mock_args):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)
    with pytest.raises(ArgumentError) as ae:
        mock_args.silent = True
        Options(mock_args)

    assert "Cannot specify" in str(ae)


def test_invalid_silent_and_links(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.uct_links = True
        mock_args.cve = "CVE-2020-1234"
        mock_args.silent = True
        Options(mock_args)

    assert "options are incompatible" in str(ae)


def test_invalid_verbose_and_silent(mock_args):
    with pytest.raises(ArgumentError):
        mock_args.cve = "CVE-2020-1234"
        mock_args.verbose = True
        mock_args.silent = True
        Options(mock_args)


def test_invalid_manifest_file_not_found(monkeypatch, mock_args):
    monkeypatch.setattr(os.path, "isfile", lambda x: False)

    with pytest.raises(ArgumentError) as ae:
        mock_args.manifest_file = "test"
        Options(mock_args)

    assert "Cannot find file" in str(ae)


def test_invalid_oval_file_not_found(monkeypatch, mock_args):
    monkeypatch.setattr(os.path, "isfile", lambda x: False)

    with pytest.raises(ArgumentError) as ae:
        mock_args.oval_file = "test"
        Options(mock_args)

    assert "Cannot find file" in str(ae)


def test_invalid_cve_and_unresolved(mock_args):
    with pytest.raises(ArgumentError):
        mock_args.cve = "CVE-2020-1234"
        mock_args.unresolved = True
        Options(mock_args)


def test_invalid_cve_and_priority(mock_args):
    with pytest.raises(ArgumentError):
        mock_args.cve = "CVE-2020-1234"
        mock_args.priority = "medium"
        Options(mock_args)

    with pytest.raises(ArgumentError):
        mock_args.cve = "CVE-2020-1234"
        mock_args.priority = "high"
        Options(mock_args)

    with pytest.raises(ArgumentError):
        mock_args.cve = "CVE-2020-1234"
        mock_args.priority = "critical"
        Options(mock_args)


def test_invalid_cve_and_uct_links(mock_args):
    with pytest.raises(ArgumentError):
        mock_args.cve = "CVE-2020-1234"
        mock_args.priority = "all"
        mock_args.uct_links = True
        Options(mock_args)
