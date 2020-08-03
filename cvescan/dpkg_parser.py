import re
import subprocess

from cvescan.errors import PkgCountError

INSTALLED_REGEX = re.compile(r"^[uihrp]i")


def get_installed_pkgs_from_manifest(manifest):
    installed_pkgs = {}
    for pkg in manifest.splitlines():
        (pkg, version) = pkg.split("\t")
        pkg = _strip_architecture_extension(pkg)
        installed_pkgs[pkg] = version

    return installed_pkgs


def get_installed_pkgs_from_dpkg_list(logger):
    installed_pkgs = {}
    dpkg_output = _get_dpkg_list(logger)

    for pkg in dpkg_output:
        if INSTALLED_REGEX.match(str(pkg)) is not None:
            pkg_info = pkg.split()
            pkg = _strip_architecture_extension(pkg_info[1])
            installed_pkgs[pkg] = pkg_info[2]

    return installed_pkgs


def _get_dpkg_list(logger):
    logger.debug("Running `dpkg -l` to get a list of locally installed packages")
    dpkg = subprocess.Popen(
        ["dpkg", "-l"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )
    out, outerr = dpkg.communicate()

    if dpkg.returncode != 0:
        raise PkgCountError("dpkg exited with code %d: %s" % (dpkg.returncode, outerr))

    return out.splitlines()


def _strip_architecture_extension(pkg):
    return pkg.split(":")[0]
