import logging

from cvescan import __main__ as main
from cvescan import constants as const
from cvescan.output_formatters import (
    CLIOutputFormatter,
    CSVOutputFormatter,
    CVEOutputFormatter,
    JSONOutputFormatter,
    NagiosOutputFormatter,
    SyslogOutputFormatter,
)


def null_logger(name="test.null"):
    logger = logging.getLogger(name)
    print("1" + str(logger.hasHandlers()))
    if not logger.hasHandlers():
        logger.addHandler(logging.NullHandler())

    return logger


class MockOpt:
    def __init__(self):
        self.download_uct_db_file = False
        self.db_file = "tests/assets/cache_uct.json"
        self.cve = False
        self.csv = False
        self.json = False
        self.nagios_mode = False
        self.syslog = False
        self.syslog_light = False
        self.syslog_host = "localhost"
        self.syslog_port = 514
        self.silent = False
        self.verbose = False


class MockTargetSysInfo:
    def __init__(self):
        self.codename = "focal"


class MockDownloadCache:
    def get_data_from_url(self, url):
        return {"CVE-2019-1000": "0"}


def test_set_output_verbosity_info():
    opt = MockOpt()
    logger = main.set_output_verbosity(opt)

    assert logger.level == logging.INFO


def test_set_output_verbosity_silent():
    opt = MockOpt()
    opt.silent = True
    logger = main.set_output_verbosity(opt)

    assert len(logger.handlers) == 1
    assert isinstance(logger.handlers[0], logging.NullHandler)
    assert logger.name == const.NULL_LOGGER_NAME


def test_set_output_verbosity_debug():
    opt = MockOpt()
    opt.verbose = True
    logger = main.set_output_verbosity(opt)

    assert logger.level == logging.DEBUG


def test_load_uct_data_file():
    target_sysinfo = MockTargetSysInfo()
    opt = MockOpt()
    opt.download_uct_db_file = False

    download_cache = MockDownloadCache()

    data = main.load_uct_data(opt, download_cache, target_sysinfo)

    assert len(data.keys()) == 3
    assert "CVE-2020-1000" in data
    assert "CVE-2020-1001" in data
    assert "CVE-2020-1002" in data


def test_load_uct_data_cache():
    target_sysinfo = MockTargetSysInfo()
    opt = MockOpt()
    opt.download_uct_db_file = True

    download_cache = MockDownloadCache()

    data = main.load_uct_data(opt, download_cache, target_sysinfo)

    assert len(data.keys()) == 1
    assert "CVE-2019-1000" in data


def test_uct_data_url_has_codename():
    url = main.get_uct_data_url(MockTargetSysInfo())

    assert (
        url
        == "https://people.canonical.com/~ubuntu-security/cvescan/ubuntu-vuln-db-focal.json.bz2"
    )


def test_cve_output_formatter():
    opt = MockOpt()
    opt.cve = True

    output_formatter = main.load_output_formatter(opt, null_logger())

    assert isinstance(output_formatter, CVEOutputFormatter)


def test_nagios_output_formatter():
    opt = MockOpt()
    opt.nagios_mode = True

    output_formatter = main.load_output_formatter(opt, null_logger())

    assert isinstance(output_formatter, NagiosOutputFormatter)


def test_cli_output_formatter():
    opt = MockOpt()
    opt.cve = False
    opt.nagios_mode = False

    output_formatter = main.load_output_formatter(opt, null_logger())

    assert isinstance(output_formatter, CLIOutputFormatter)


def test_csv_output_formatter():
    opt = MockOpt()
    opt.csv = True

    output_formatter = main.load_output_formatter(opt, null_logger())

    assert isinstance(output_formatter, CSVOutputFormatter)


def test_json_output_formatter():
    opt = MockOpt()
    opt.json = True

    output_formatter = main.load_output_formatter(opt, null_logger())

    assert isinstance(output_formatter, JSONOutputFormatter)


def test_syslog_output_formatter():
    opt = MockOpt()
    opt.syslog = True

    output_formatter = main.load_output_formatter(opt, null_logger())

    assert isinstance(output_formatter, SyslogOutputFormatter)


def test_syslog_light_output_formatter():
    opt = MockOpt()
    opt.syslog_light = True

    output_formatter = main.load_output_formatter(opt, null_logger())

    assert isinstance(output_formatter, SyslogOutputFormatter)


def test_get_output_logger_null():
    logger = main.get_output_logger(MockOpt(), null_logger())
    assert logger.name == "test.null"


def test_get_output_logger_syslog():
    opt = MockOpt()
    opt.syslog = True

    logger = main.get_output_logger(opt, null_logger())

    assert logger.name == const.SYSLOG_LOGGER_NAME


def test_get_output_logger_syslog_light():
    opt = MockOpt()
    opt.syslog_light = True

    logger = main.get_output_logger(opt, null_logger())

    assert logger.name == const.SYSLOG_LOGGER_NAME


class MockLogger:
    def __init__(self):
        self.reset()

    def reset(self):
        self._warn = 0
        self._info = 0

    @property
    def warn_count(self):
        return self._warn

    @property
    def info_count(self):
        return self._info

    def warning(self, _):
        self._warn += 1

    def info(self, _):
        self._info += 1


def test_output_info(monkeypatch):
    logger = MockLogger()
    main.output(logger, "hello", 0)

    assert logger.warn_count == 0
    assert logger.info_count == 1


def test_output_warn(monkeypatch):
    logger = MockLogger()
    main.output(logger, "hello", 1)
    main.output(logger, "hello", 2)
    main.output(logger, "hello", 3)
    main.output(logger, "hello", 4)

    assert logger.warn_count == 4
    assert logger.info_count == 0
