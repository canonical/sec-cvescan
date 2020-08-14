import os
import re

import validators

from cvescan.arg_compatibility_map import arg_compatibility_map
from cvescan.errors import ArgumentError

MANIFEST_URL_TEMPLATE = (
    "https://cloud-images.ubuntu.com/%s/current/%s-server-cloudimg-amd64.manifest"
)


class Options:
    def __init__(self, args):
        raise_on_invalid_args(args)

        self._set_mode(args)
        self._set_db_file_options(args)
        self._set_manifest_file_options(args)
        self._set_syslog_options(args)

        self.csv = args.csv
        self.cve = args.cve
        self.json = args.json
        self.priority = args.priority if args.priority else "high"
        self.unresolved = args.unresolved

        self.show_links = args.show_links

        self.silent = args.silent
        self.verbose = args.verbose

    def _set_mode(self, args):
        self.manifest_mode = True if args.manifest else False
        self.experimental_mode = args.experimental
        self.nagios_mode = args.nagios

    def _set_db_file_options(self, args):
        if args.db:
            self.download_uct_db_file = False
            self.db_file = args.db
        else:
            self.download_uct_db_file = True
            self.db_file = "uct.json"

    def _set_manifest_file_options(self, args):
        self.manifest_file = os.path.abspath(args.manifest) if args.manifest else None

    def _set_syslog_options(self, args):
        self.syslog = args.syslog is not None
        self.syslog_light = args.syslog_light is not None

        if self.syslog or self.syslog_light:
            self.syslog_host, self.syslog_port = parse_syslog_args(args)
        else:
            self.syslog_host = None
            self.syslog_port = None


def raise_on_invalid_args(args):
    raise_on_invalid_combinations(args)
    raise_on_invalid_cve(args)
    raise_on_missing_manifest_file(args)
    raise_on_missing_db_file(args)
    raise_on_invalid_syslog(args)


def raise_on_invalid_combinations(args):
    specified_args = set()
    acm = arg_compatibility_map

    for arg_name, arg_value in vars(args).items():
        if not arg_value:
            continue

        formatted_arg_name = arg_name.replace("_", "-")
        raise_if_incompatible_arg_specified(formatted_arg_name, specified_args, acm)
        specified_args.add(formatted_arg_name)

    for arg in specified_args:
        raise_if_required_args_not_specified(arg, specified_args, acm)


def raise_if_incompatible_arg_specified(formatted_arg_name, specified_args, acm):
    incompatible_args = specified_args & acm[formatted_arg_name]["incompatible"]

    if len(incompatible_args) != 0:
        arg = list(incompatible_args)[0]
        raise ArgumentError(
            f"The {acm[formatted_arg_name]['flags']} and {acm[arg]['flags']} options "
            "are incompatible and may not be specified together."
        )


def raise_if_required_args_not_specified(arg, specified_args, acm):
    for required_arg in acm[arg]["required"]:
        if required_arg not in specified_args:
            raise ArgumentError(
                f"Cannot specify {acm[arg]['flags']} argument "
                f"without {acm[required_arg]['flags']}."
            )


def raise_on_invalid_cve(args):
    cve_regex = r"^CVE-[0-9]{4}-[0-9]{4,}$"
    if (args.cve is not None) and (not re.match(cve_regex, args.cve)):
        raise ValueError("Invalid CVE ID (%s)" % args.cve)


def raise_on_missing_manifest_file(args):
    raise_on_missing_file(args.manifest)


def raise_on_missing_db_file(args):
    raise_on_missing_file(args.db)


def raise_on_missing_file(file_path):
    if not file_path:
        return

    file_abs_path = os.path.abspath(file_path)
    if not os.path.isfile(file_abs_path):
        # TODO: mention snap confinement in error message
        raise ArgumentError(
            'Cannot find file "%s". Current '
            'working directory is "%s".' % (file_abs_path, os.getcwd())
        )


def raise_on_invalid_syslog(args):
    if not (args.syslog or args.syslog_light):
        return

    error_msg = "Invalid syslog server: syslog servers must be specified in the format HOST:PORT"

    try:
        # parse_syslog_args () raises a ValueError if port is not an integer
        host, port = parse_syslog_args(args)
    except ValueError:
        raise ValueError(error_msg)

    single_component_hostname = re.match(r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$", host)
    if not (
        single_component_hostname
        or validators.domain(host)
        or validators.ipv6(host)
        or validators.ipv4(host)
    ):
        raise ValueError(error_msg)


def parse_syslog_args(args):
    syslog = args.syslog if args.syslog else args.syslog_light

    (host, port) = syslog.strip().split(":")
    port = int(port)

    return (host, port)
