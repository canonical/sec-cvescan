import re

import cvescan.dpkg_parser as dpkg_parser


def parse_manifest_file(manifest_file_path):
    try:
        with open(manifest_file_path, "r") as mfp:
            manifest = mfp.read()

        installed_pkgs = dpkg_parser.get_installed_pkgs_from_manifest(manifest)
    except Exception as e:
        raise Exception(
            "Failed to parse installed files from manifest the provided file: %s" % e
        )

    return (installed_pkgs, _get_codename(installed_pkgs))


# This function uses a hack to guess the ubuntu release codename based on the
# versions of certain packages. A better solution would be to include the
# codename in the manifest file and fall back on this version checking approach
# if the codename is missing.
def _get_codename(installed_pkgs):
    try:
        trusty_regex = re.compile(r"1:0.196(.\d+)+")
        xenial_regex = re.compile(r"1:16.04(.\d+)+")
        bionic_regex = re.compile(r"1:18.04(.\d+)+")
        focal_regex = re.compile(r"1:20.04(.\d+)+")
        groovy_regex = re.compile(r"1:20.10(.\d+)+")
        jammy_regex = re.compile(r"1:22.04(.\d+)+")

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

        if jammy_regex.match(update_manager_core_ver):
            return "jammy"

        raise Exception("Could not match version to a supported release.")
    except Exception as e:
        raise Exception(
            "Failed to determine ubuntu release codename from the provided "
            "manifest file: %s" % e
        )
