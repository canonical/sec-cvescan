#!/usr/bin/env python3

import argparse as ap
import json
import logging
import sys

from tabulate import tabulate
from ust_download_cache import USTDownloadCache

import cvescan.constants as const
from cvescan import TargetSysInfo
from cvescan.cvescanner import CVEScanner
from cvescan.errors import ArgumentError, DistribIDError, PkgCountError
from cvescan.local_sysinfo import LocalSysInfo
from cvescan.options import Options
from cvescan.output_formatters import (
    CLIOutputFormatter,
    CVEOutputFormatter,
    CVEScanResultSorter,
    NagiosOutputFormatter,
    PackageScanResultSorter,
)


def set_output_verbosity(args):
    if args.silent:
        return get_null_logger()

    logger = logging.getLogger("cvescan.stdout")

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    log_formatter = logging.Formatter("%(message)s")
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(log_formatter)
    logger.addHandler(stream_handler)

    return logger


def get_null_logger():
    logger = logging.getLogger("cvescan.null")
    if not logger.hasHandlers():
        logger.addHandler(logging.NullHandler())

    return logger


LOGGER = get_null_logger()


def error_exit(msg, code=const.ERROR_RETURN_CODE):
    print("Error: %s" % msg, file=sys.stderr)
    sys.exit(code)


def parse_args():
    cvescan_ap = ap.ArgumentParser(
        description=const.CVESCAN_DESCRIPTION, formatter_class=ap.RawTextHelpFormatter
    )
    cvescan_ap.add_argument(
        "-c", "--cve", metavar="CVE-IDENTIFIER", help=const.CVE_HELP
    )
    cvescan_ap.add_argument(
        "-p",
        "--priority",
        help=const.PRIORITY_HELP,
        choices=[const.CRITICAL, const.HIGH, const.MEDIUM, const.ALL],
        default=None,
    )
    cvescan_ap.add_argument(
        "-s", "--silent", action="store_true", default=False, help=const.SILENT_HELP
    )
    cvescan_ap.add_argument("--db", metavar="UBUNTU_DB_FILE", help=const.DB_FILE_HELP)
    cvescan_ap.add_argument(
        "-m", "--manifest", metavar="MANIFEST_FILE", help=const.MANIFEST_HELP
    )
    cvescan_ap.add_argument(
        "-n", "--nagios", action="store_true", default=False, help=const.NAGIOS_HELP
    )
    cvescan_ap.add_argument(
        "--show-links", action="store_true", default=False, help=const.UCT_LINKS_HELP
    )
    cvescan_ap.add_argument(
        "--unresolved", action="store_true", default=False, help=const.UNRESOLVED_HELP
    )
    cvescan_ap.add_argument(
        "-v", "--verbose", action="store_true", default=False, help=const.VERBOSE_HELP
    )
    cvescan_ap.add_argument(
        "-x",
        "--experimental",
        action="store_true",
        default=False,
        help=const.EXPERIMENTAL_HELP,
    )

    return cvescan_ap.parse_args()


def log_config_options(opt):
    LOGGER.debug("Config Options")
    table = [
        ["Manifest Mode", opt.manifest_mode],
        ["Experimental Mode", opt.experimental_mode],
        ["Nagios Output Mode", opt.nagios_mode],
        ["Ubuntu Vulnerability DB File Path", opt.db_file],
        ["Manifest File", opt.manifest_file],
        ["Check Specific CVE", opt.cve],
        ["CVE Priority", opt.priority],
        ["Show Unresolved CVEs", opt.unresolved],
    ]

    LOGGER.debug(tabulate(table))
    LOGGER.debug("")


def log_local_system_info(local_sysinfo, manifest_mode):
    LOGGER.debug("Local System Info")
    table = [
        ["CVEScan is a Snap", local_sysinfo.is_snap],
        ["$SNAP_USER_COMMON", local_sysinfo.snap_user_common],
    ]

    if not manifest_mode:
        table = [
            ["Local Ubuntu Codename", local_sysinfo.codename],
            ["Installed Package Count", local_sysinfo.package_count],
            # Disabling for now
            # ["ESM Apps Enabled", local_sysinfo.esm_apps_enabled],
            # ["ESM Infra Enabled", local_sysinfo.esm_infra_enabled],
        ] + table

    LOGGER.debug(tabulate(table))
    LOGGER.debug("")


def log_target_system_info(target_sysinfo):
    LOGGER.debug("Target System Info")

    table = [
        ["Local Ubuntu Codename", target_sysinfo.codename],
        ["Installed Package Count", target_sysinfo.pkg_count],
        # Disabling for now
        # ["ESM Apps Enabled", target_sysinfo.esm_apps_enabled],
        # ["ESM Infra Enabled", target_sysinfo.esm_infra_enabled],
    ]

    LOGGER.debug(tabulate(table))
    LOGGER.debug("")


def load_output_formatter(opt):
    if opt.cve:
        return CVEOutputFormatter(opt, LOGGER)

    sorter = load_output_sorter(opt)
    if opt.nagios_mode:
        return NagiosOutputFormatter(opt, LOGGER, sorter=sorter)

    return CLIOutputFormatter(opt, LOGGER, sorter=sorter)


def load_output_sorter(opt):
    pkg_sorter = PackageScanResultSorter()
    return CVEScanResultSorter(subsorters=[pkg_sorter])


def load_uct_data(opt, download_cache):
    db_file_path = opt.db_file

    if opt.download_uct_db_file:
        uct_data = download_cache.get_from_url(const.UCT_DATA_URL)["data"]

    else:
        with open(db_file_path) as db_file:
            uct_data = json.load(db_file)["data"]

    return uct_data


def main():
    global LOGGER

    args = parse_args()

    # Configure debug logging as early as possible
    LOGGER = set_output_verbosity(args)

    local_sysinfo = LocalSysInfo(LOGGER)

    try:
        opt = Options(args)
    except (ArgumentError, ValueError) as err:
        error_exit("Invalid option or argument: %s" % err, const.CLI_ERROR_RETURN_CODE)

    error_exit_code = (
        const.NAGIOS_UNKNOWN_RETURN_CODE if opt.nagios_mode else const.ERROR_RETURN_CODE
    )

    try:
        target_sysinfo = TargetSysInfo(opt, local_sysinfo)

        log_config_options(opt)
        log_local_system_info(local_sysinfo, opt.manifest_mode)
        log_target_system_info(target_sysinfo)
    except (FileNotFoundError, PermissionError) as err:
        error_exit("Failed to determine the correct Ubuntu codename: %s" % err)
    except DistribIDError as di:
        error_exit(
            "Invalid linux distribution detected, CVEScan must be run on Ubuntu: %s"
            % di
        )
    except PkgCountError as pke:
        error_exit("Failed to determine the local package count: %s" % pke)

    output_formatter = load_output_formatter(opt)

    try:
        download_cache = USTDownloadCache(LOGGER)
        uct_data = load_uct_data(opt, download_cache)
        cve_scanner = CVEScanner(LOGGER)
        scan_results = cve_scanner.scan(
            target_sysinfo.codename, uct_data, target_sysinfo.installed_pkgs
        )
        (results, return_code) = output_formatter.format_output(
            scan_results, target_sysinfo
        )
    except Exception as ex:
        error_exit(
            "An unexpected error occurred while running CVEScan: %s" % ex,
            error_exit_code,
        )

    LOGGER.info(results)
    sys.exit(return_code)


if __name__ == "__main__":
    main()
