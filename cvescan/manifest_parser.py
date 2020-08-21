import re

import cvescan.dpkg_parser as dpkg_parser


def parse_manifest_file(manifest_file_path, codename=None):
    try:
        with open(manifest_file_path) as mfp:
            manifest = mfp.read()

        installed_pkgs = dpkg_parser.get_installed_pkgs_from_manifest(manifest)
    except Exception as e:
        raise Exception(
            "Failed to parse installed files from manifest the provided file: %s" % e
        )

    if not codename:
        codename = _get_codename(installed_pkgs)

    return (installed_pkgs, codename)


# This function uses a hack to guess the ubuntu release codename based on the
# versions of certain packages. A better solution would be to include the
# codename in the manifest file and fall back on this version checking approach
# if the codename is missing.
def _get_codename(installed_pkgs):
    try:
        trusty_regex = re.compile(r"1:0.196(.\d+)+")
        xenial_regex = re.compile(r"1:16.04(.\d+)+")
        bionic_regex = re.compile(r"1:18.04(.\d+)+")
        eoan_regex = re.compile(r"1:19.04(.\d+)+")
        focal_regex = re.compile(r"1:20.04(.\d+)+")

        update_manager_core_ver = installed_pkgs.get("update-manager-core", "")

        if trusty_regex.match(update_manager_core_ver):
            return "trusty"

        if xenial_regex.match(update_manager_core_ver):
            return "xenial"

        if bionic_regex.match(update_manager_core_ver):
            return "bionic"

        import apt_pkg

        apt_pkg.init_system()

        # At the moment, groovy is a special case
        if focal_regex.match(update_manager_core_ver):
            base_files_ver = installed_pkgs.get("base-files", "")

            if apt_pkg.version_compare(base_files_ver, "11ubuntu7") >= 0:
                return "groovy"

            if apt_pkg.version_compare(base_files_ver, "11ubuntu5") >= 0:
                return "focal"

        # eoan is a special case
        if eoan_regex.match(update_manager_core_ver):
            if apt_pkg.version_compare(update_manager_core_ver, "1:19.04.8") >= 0:
                return "eoan"

        raise Exception("Could not match version to a supported release.")
    except Exception as e:
        raise Exception(
            "Failed to determine ubuntu release codename from the provided "
            "manifest file: %s" % e
        )
