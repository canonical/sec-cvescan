import io
import re
from contextlib import nullcontext

import cvescan.dpkg_parser as dpkg_parser
from cvescan.constants import SUPPORTED_RELEASES


def parse_manifest_file(manifest_file):
    codename = None

    try:
        manifest_file_context = (
            nullcontext(manifest_file)
            if isinstance(manifest_file, io.TextIOBase)
            else open(manifest_file, "r")
        )
        with manifest_file_context as manifest:
            first_line = manifest.readline().strip()
            manifest_pkgs = manifest.read().rstrip("\n").split("\n")
            if first_line in SUPPORTED_RELEASES:
                codename = first_line
            else:
                manifest_pkgs.insert(0, first_line)

            installed_pkgs = dpkg_parser.get_installed_pkgs_from_manifest(manifest_pkgs)
    except Exception as e:
        raise Exception(
            "Failed to parse installed files from manifest the provided input: %s" % e
        )

    if codename is None:
        codename = _get_codename_from_package_versions(installed_pkgs)

    return (installed_pkgs, codename)


# This function uses a hack to guess the ubuntu release codename based on the
# versions of certain packages. A better solution would be to include the
# codename in the manifest file and fall back on this version checking approach
# if the codename is missing.
def _get_codename_from_package_versions(installed_pkgs):
    try:
        trusty_regex = re.compile(r"1:0.196(.\d+)+")
        xenial_regex = re.compile(r"1:16.04(.\d+)+")
        bionic_regex = re.compile(r"1:18.04(.\d+)+")
        focal_regex = re.compile(r"1:20.04(.\d+)+")
        groovy_regex = re.compile(r"1:20.10(.\d+)+")

        update_manager_core_ver = installed_pkgs.get("update-manager-core", "")

        if trusty_regex.match(update_manager_core_ver):
            return "trusty"

        if xenial_regex.match(update_manager_core_ver):
            return "xenial"

        if bionic_regex.match(update_manager_core_ver):
            return "bionic"

        if focal_regex.match(update_manager_core_ver):
            return "focal"

        if groovy_regex.match(update_manager_core_ver):
            return "groovy"

        raise Exception("Could not match version to a supported release.")
    except Exception as e:
        raise Exception(
            "Failed to determine ubuntu release codename from the provided "
            "manifest file: %s" % e
        )
