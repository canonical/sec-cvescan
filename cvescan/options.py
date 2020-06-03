import os
import re

from cvescan.errors import ArgumentError

FMT_CVE_OPTION = "-c|--cve"
FMT_EXPERIMENTAL_OPTION = "-x|--experimental"
FMT_FILE_OPTION = "-f|--file"
FMT_MANIFEST_OPTION = "-m|--manifest"
FMT_NAGIOS_OPTION = "-n|--nagios"
FMT_UCT_LINKS_OPTION = "--uct-links"
FMT_UCT_FILE_OPTION = "-u|--uct_file"
FMT_PRIORITY_OPTION = "-p|priority"
FMT_SILENT_OPTION = "-s|--silent"
FMT_UNRESOLVED_OPTION = "--unresolved"
FMT_VERBOSE_OPTION = "-v|--verbose"

MANIFEST_URL_TEMPLATE = (
    "https://cloud-images.ubuntu.com/%s/current/%s-server-cloudimg-amd64.manifest"
)


class Options:
    def __init__(self, args):
        raise_on_invalid_args(args)

        self._set_mode(args)
        self._set_uct_file_options(args)
        self._set_manifest_file_options(args)

        self.cve = args.cve
        self.priority = args.priority
        self.unresolved = args.unresolved

        self.uct_links = args.uct_links

    def _set_mode(self, args):
        self.manifest_mode = True if args.manifest_file else False
        self.experimental_mode = args.experimental
        self.nagios_mode = args.nagios

    def _set_uct_file_options(self, args):
        # TODO: This really isn't an option, it's a constant. In fact, the only
        #       "options" here ATM are whether or not use a user-specified file
        #       or to download a new version of the file. The planned
        #       cacher/downloader object should replace this.
        self.uct_base_url = None

        if args.uct_file:
            self.uct_file = args.uct_file
            return

        self.uct_base_url = "https://people.canonical.com/~ubuntu-security/cvescan"
        self.uct_file = "uct.json"

        self.uct_zip = "%s.bz2" % self.uct_file

    def _set_manifest_file_options(self, args):
        self.manifest_file = (
            os.path.abspath(args.manifest_file) if args.manifest_file else None
        )

    @property
    def download_uct_file(self):
        return self.uct_base_url is not None


def raise_on_invalid_args(args):
    raise_on_invalid_cve(args)
    raise_on_invalid_combinations(args)
    raise_on_missing_manifest_file(args)
    raise_on_missing_uct_file(args)


def raise_on_invalid_cve(args):
    cve_regex = r"^CVE-[0-9]{4}-[0-9]{4,}$"
    if (args.cve is not None) and (not re.match(cve_regex, args.cve)):
        raise ValueError("Invalid CVE ID (%s)" % args.cve)


def raise_on_invalid_combinations(args):
    raise_on_invalid_nagios_options(args)
    raise_on_invalid_silent_options(args)
    raise_on_invalid_unresolved_options(args)
    raise_on_invalid_cve_options(args)


def raise_on_invalid_nagios_options(args):
    if not args.nagios:
        return

    if args.cve:
        raise_incompatible_arguments_error(FMT_NAGIOS_OPTION, FMT_CVE_OPTION)

    if args.silent:
        raise_incompatible_arguments_error(FMT_NAGIOS_OPTION, FMT_SILENT_OPTION)

    if args.unresolved:
        raise_incompatible_arguments_error(FMT_NAGIOS_OPTION, FMT_UNRESOLVED_OPTION)

    if args.uct_links:
        raise_incompatible_arguments_error(FMT_NAGIOS_OPTION, FMT_UCT_LINKS_OPTION)


def raise_on_invalid_silent_options(args):
    if not args.silent:
        return

    if not args.cve:
        raise ArgumentError(
            "Cannot specify %s argument without %s."
            % (FMT_SILENT_OPTION, FMT_CVE_OPTION)
        )

    if args.verbose:
        raise_incompatible_arguments_error(FMT_SILENT_OPTION, FMT_VERBOSE_OPTION)

    if args.uct_links:
        raise_incompatible_arguments_error(FMT_SILENT_OPTION, FMT_UCT_LINKS_OPTION)


def raise_on_invalid_unresolved_options(args):
    if args.unresolved and args.cve:
        raise_incompatible_arguments_error(FMT_UNRESOLVED_OPTION, FMT_CVE_OPTION)

    if args.unresolved and args.nagios:
        raise_incompatible_arguments_error(FMT_UNRESOLVED_OPTION, FMT_NAGIOS_OPTION)


def raise_on_invalid_cve_options(args):
    if not args.cve:
        return

    if args.priority != "all":
        raise_incompatible_arguments_error(FMT_CVE_OPTION, FMT_PRIORITY_OPTION)

    if args.uct_links:
        raise_incompatible_arguments_error(FMT_CVE_OPTION, FMT_UCT_LINKS_OPTION)


def raise_incompatible_arguments_error(arg1, arg2):
    raise ArgumentError(
        "The %s and %s options are incompatible and may not "
        "be specified together." % (arg1, arg2)
    )


def raise_on_missing_manifest_file(args):
    raise_on_missing_file(args.manifest_file)


def raise_on_missing_uct_file(args):
    raise_on_missing_file(args.uct_file)


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
