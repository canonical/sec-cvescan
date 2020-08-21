import io
import os

import pytest

import cvescan.constants as const
from cvescan.errors import ArgumentError
from cvescan.options import Options

SCRIPTDIR = "fakedir/"
BASE_URL = "https://people.canonical.com/~ubuntu-security/cvescan"


class MockArgs:
    def __init__(self):
        self.csv = False
        self.cve = None
        self.json = False
        self.syslog = None
        self.syslog_light = None
        self.priority = None
        self.silent = False
        self.db = None
        self.manifest = None
        self.nagios = False
        self.show_links = False
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
    mock_args.manifest = "tests/assets/manifest/bionic.manifest"
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
    mock_args.manifest = "tests/assets/manifest/bionic.manifest"
    mock_args.nagios = True
    opt = Options(mock_args)

    assert opt.experimental_mode is True
    assert opt.manifest_mode is True
    assert opt.nagios_mode is True


def test_set_csv(mock_args):
    mock_args.csv = True
    opt = Options(mock_args)

    assert opt.csv

    mock_args.csv = False
    opt = Options(mock_args)

    assert not opt.csv


def test_set_json(mock_args):
    mock_args.json = True
    opt = Options(mock_args)

    assert opt.json

    mock_args.json = False
    opt = Options(mock_args)

    assert not opt.json


def test_set_syslog(mock_args):
    mock_args.syslog = "localhost:514"
    opt = Options(mock_args)

    assert opt.syslog
    assert opt.syslog_host == "localhost"
    assert opt.syslog_port == 514

    mock_args.syslog = None
    opt = Options(mock_args)

    assert not opt.syslog
    assert opt.syslog_host is None
    assert opt.syslog_port is None


def test_set_syslog_ip(mock_args):
    mock_args.syslog = "192.168.1.50:514"
    opt = Options(mock_args)

    assert opt.syslog
    assert opt.syslog_host == "192.168.1.50"
    assert opt.syslog_port == 514


def test_set_syslog_light(mock_args):
    mock_args.syslog_light = "localhost:514"
    opt = Options(mock_args)

    assert opt.syslog_light
    assert opt.syslog_host == "localhost"
    assert opt.syslog_port == 514

    mock_args.syslog_light = None
    opt = Options(mock_args)

    assert not opt.syslog_light
    assert opt.syslog_host is None
    assert opt.syslog_port is None


def test_set_syslog_light_ip(mock_args):
    mock_args.syslog_light = "192.168.1.50:514"
    opt = Options(mock_args)

    assert opt.syslog_light
    assert opt.syslog_host == "192.168.1.50"
    assert opt.syslog_port == 514


def test_set_db_file_default(monkeypatch, mock_args):
    opt = Options(mock_args)

    assert opt.db_file == "uct.json"


def test_set_db_file_user_specified(monkeypatch, mock_args):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)

    mock_args.db = "/my/path/fakefile.json"
    opt = Options(mock_args)

    assert opt.db_file == "/my/path/fakefile.json"


def test_set_download_uct_db_file_default(monkeypatch, mock_args):
    opt = Options(mock_args)

    assert opt.download_uct_db_file is True


def test_set_download_uct_db_file_user_specified(monkeypatch, mock_args):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)

    mock_args.db = "/my/path/fakefile.xml"
    opt = Options(mock_args)

    assert opt.download_uct_db_file is False


def test_set_manifest_file_none(mock_args):
    opt = Options(mock_args)

    assert opt.manifest_file is None


def test_set_manifest_file_user_specified(monkeypatch, mock_args):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)

    mock_args.manifest = "/tmp/testmanifest"
    opt = Options(mock_args)

    assert opt.manifest_file == "/tmp/testmanifest"


def test_set_manifest_file_abspath(monkeypatch, mock_args):
    monkeypatch.setattr(os.path, "isfile", lambda x: True)
    monkeypatch.setattr(os.path, "abspath", lambda x: "/tmp/testmanifest")

    mock_args.manifest = "../../../../../../../../../../../../tmp/testmanifest"
    opt = Options(mock_args)

    assert opt.manifest_file == "/tmp/testmanifest"


def test_set_manifest_file_stdin(monkeypatch, mock_args):
    mock_stdin = io.StringIO()
    monkeypatch.setattr("sys.stdin", mock_stdin)
    mock_args.manifest = const.MANIFEST_STDIN_FLAG
    opt = Options(mock_args)
    assert opt.manifest_file == mock_stdin


def test_set_cve_default(mock_args):
    opt = Options(mock_args)

    assert opt.cve is None


def test_set_cve(mock_args):
    mock_args.cve = "CVE-2020-1234"
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


def test_set_silent(mock_args):
    mock_args.cve = "CVE-2020-1945"
    opt = Options(mock_args)
    assert opt.silent is False

    mock_args.silent = True
    opt = Options(mock_args)
    assert opt.silent is True


def test_set_verbose(mock_args):
    opt = Options(mock_args)
    assert opt.verbose is False

    mock_args.verbose = True
    opt = Options(mock_args)
    assert opt.verbose is True


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
        mock_args.show_links = True
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
        mock_args.show_links = True
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
        mock_args.manifest = "test"
        Options(mock_args)

    assert "Cannot find file" in str(ae)


def test_invalid_db_file_not_found(monkeypatch, mock_args):
    monkeypatch.setattr(os.path, "isfile", lambda x: False)
    monkeypatch.setattr(os.path, "expanduser", lambda x: "/home/user")

    with pytest.raises(ArgumentError) as ae:
        mock_args.db = "/home/user/test"
        Options(mock_args)

    assert "Cannot find file" in str(ae)
    assert "$HOME" not in str(ae)


def test_invalid_db_file_not_found_snap_warning(monkeypatch, mock_args):
    monkeypatch.setattr(os.path, "isfile", lambda x: False)
    monkeypatch.setattr(os.path, "expanduser", lambda x: "/home/user")

    with pytest.raises(ArgumentError) as ae:
        mock_args.db = "/tmp/test"
        Options(mock_args)

    assert "Cannot find file" in str(ae)
    assert "$HOME" in str(ae)


def test_invalid_cve_and_unresolved(mock_args):
    with pytest.raises(ArgumentError):
        mock_args.cve = "CVE-2020-1234"
        mock_args.unresolved = True
        Options(mock_args)


@pytest.mark.parametrize("priority", ["medium", "high", "critical", "all"])
def test_invalid_cve_and_priority(mock_args, priority):
    with pytest.raises(ArgumentError):
        mock_args.cve = "CVE-2020-1234"
        mock_args.priority = priority
        Options(mock_args)


def test_invalid_cve_and_show_links(mock_args):
    with pytest.raises(ArgumentError):
        mock_args.cve = "CVE-2020-1234"
        mock_args.show_links = True
        Options(mock_args)


def test_invalid_cve_and_json(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.cve = "CVE-2020-1000"
        mock_args.json = True
        Options(mock_args)

    assert "options are incompatible" in str(ae)


def test_invalid_csv_and_cve(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.csv = True
        mock_args.cve = "CVE-2020-1000"
        Options(mock_args)

    assert "options are incompatible" in str(ae)


def test_invalid_csv_and_json(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.csv = True
        mock_args.json = True
        Options(mock_args)

    assert "options are incompatible" in str(ae)


def test_invalid_csv_and_nagios(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.csv = True
        mock_args.nagios = True
        Options(mock_args)

    assert "options are incompatible" in str(ae)


def test_invalid_json_and_nagios(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.json = True
        mock_args.nagios = True
        Options(mock_args)

    assert "options are incompatible" in str(ae)


invalid_syslog_servers = [
    "local-.com:500",
    "localhost",
    "514",
    "mike@mike.com:514",
    "localhost:514a",
]


@pytest.mark.parametrize("invalid_syslog", invalid_syslog_servers)
def test_invalid_syslog(invalid_syslog, mock_args):
    with pytest.raises(ValueError) as ve:
        mock_args.syslog = invalid_syslog
        Options(mock_args)

    assert "Invalid syslog server" in str(ve)


@pytest.mark.parametrize("invalid_syslog", invalid_syslog_servers)
def test_invalid_syslog_light(invalid_syslog, mock_args):
    with pytest.raises(ValueError) as ve:
        mock_args.syslog_light = invalid_syslog
        Options(mock_args)

    assert "Invalid syslog server" in str(ve)


def test_invalid_syslog_and_csv(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.syslog = "localhost:514"
        mock_args.csv = True
        Options(mock_args)

    assert "options are incompatible" in str(ae)


def test_invalid_syslog_and_cve(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.syslog = "localhost:514"
        mock_args.cve = "CVE-2020-1000"
        Options(mock_args)

    assert "options are incompatible" in str(ae)


def test_invalid_syslog_and_json(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.syslog = "localhost:514"
        mock_args.json = True
        Options(mock_args)

    assert "options are incompatible" in str(ae)


def test_invalid_syslog_and_nagios(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.syslog = "localhost:514"
        mock_args.nagios = True
        Options(mock_args)

    assert "options are incompatible" in str(ae)


def test_invalid_syslog_light_and_csv(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.syslog_light = "localhost:514"
        mock_args.csv = True
        Options(mock_args)

    assert "options are incompatible" in str(ae)


def test_invalid_syslog_light_and_cve(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.syslog_light = "localhost:514"
        mock_args.cve = "CVE-2020-1000"
        Options(mock_args)

    assert "options are incompatible" in str(ae)


def test_invalid_syslog_light_and_json(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.syslog_light = "localhost:514"
        mock_args.json = True
        Options(mock_args)

    assert "options are incompatible" in str(ae)


def test_invalid_syslog_light_and_nagios(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.syslog_light = "localhost:514"
        mock_args.nagios = True
        Options(mock_args)

    assert "options are incompatible" in str(ae)


def test_invalid_syslog_light_and_syslog(mock_args):
    with pytest.raises(ArgumentError) as ae:
        mock_args.syslog = "localhost:514"
        mock_args.syslog_light = "localhost:515"
        Options(mock_args)

    assert "options are incompatible" in str(ae)
