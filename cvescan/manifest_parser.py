import io
import re
from contextlib import nullcontext

import cvescan.constants as const
import cvescan.dpkg_parser as dpkg_parser


def parse_manifest_file(manifest_file):
    codename = None

    try:
        manifest_contents = _get_manifest_contents(manifest_file)
        installed_pkgs = dpkg_parser.get_installed_pkgs_from_manifest(manifest_contents)
    except Exception as e:
        raise Exception(
            "Failed to parse installed files from manifest the provided input: %s" % e
        )

    codename = _get_codename(manifest_contents, installed_pkgs)

    return (installed_pkgs, codename)


def _get_manifest_contents(manifest_file):
    manifest_file_context = (
        nullcontext(manifest_file)
        if isinstance(manifest_file, io.TextIOBase)
        else open(manifest_file, "r")
    )

    with manifest_file_context as manifest:
        manifest_contents = manifest.read().rstrip("\n").split("\n")

    return manifest_contents


def _get_codename(manifest_contents, installed_pkgs):
    codename = _get_codename_from_manifest(manifest_contents)

    if codename is None:
        # Fall back on this function (which is a hack) only if the codename
        # wasn't explicitly specified on the first line of the manifest file.
        codename = _guess_codename_from_package_versions(installed_pkgs)

    return codename


def _get_codename_from_manifest(manifest_contents):
    if manifest_contents[0] in const.SUPPORTED_RELEASES:
        return manifest_contents[0]

    return None


def _guess_codename_from_package_versions(installed_pkgs):
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
