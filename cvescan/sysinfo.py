import configparser
import os
import re
import subprocess

import cvescan.constants as const
from cvescan.errors import DistribIDError, PkgCountError


class SysInfo:
    def __init__(self, logger):
        self.logger = logger

        self._set_snap_info()
        self.distrib_codename = self.get_ubuntu_codename()
        self.installed_packages = self._get_installed_packages()

    def _set_snap_info(self):
        self.is_snap = False
        self.snap_user_common = None

        if "SNAP_USER_COMMON" in os.environ:
            self.is_snap = True
            self.snap_user_common = os.environ["SNAP_USER_COMMON"]

    def get_ubuntu_codename(self):
        distrib_id, distrib_codename = self.get_lsb_release_info()

        # TODO: We probably don't care if distrib_id != ubuntu if --manifest is set.
        # Compare /etc/lsb-release to acceptable environment.
        if distrib_id != "Ubuntu":
            raise DistribIDError(
                "DISTRIB_ID in /etc/lsb-release must be Ubuntu (DISTRIB_ID=%s)"
                % distrib_id
            )

        return distrib_codename

    def get_lsb_release_info(self):
        try:
            import lsb_release

            self.logger.debug(
                "Using the lsb_release python module to determine ubuntu codename"
            )
            distro = lsb_release.get_distro_information()

            return (distro.get("ID", "UNKNOWN"), distro.get("CODENAME", "UNKNOWN"))
        except Exception:
            self.logger.debug(
                "The lsb_release python module is not installed or has failed"
            )
            return self.get_lsb_release_info_from_file()

    # Getting distro ID and codename from file beacuse the lsb_release python module
    # is not available. The lsb_release module is not installed in the snap package
    # because it causes the package to triple in size.
    def get_lsb_release_info_from_file(self):
        self.logger.debug(
            "Attempting to read %s to determine DISTRIB_ID and DISTRIB_CODENAME"
            % const.LSB_RELEASE_FILE
        )
        with open(const.LSB_RELEASE_FILE, "rt") as lsb_file:
            lsb_file_contents = lsb_file.read()

        # ConfigParser needs section headers, so adding a header.
        lsb_file_contents = "[lsb]\n" + lsb_file_contents

        lsb_config = configparser.ConfigParser()
        lsb_config.read_string(lsb_file_contents)

        return (
            lsb_config.get("lsb", "DISTRIB_ID"),
            lsb_config.get("lsb", "DISTRIB_CODENAME"),
        )

    @property
    def package_count(self):
        return len(self.installed_packages.keys())

    # TODO: We can skip this if --manifest is set. The simplest solution is
    #       probably to use a @property for self.installed_packages and
    #       "lazy load" it.
    def _get_installed_packages(self):
        installed_regex = re.compile(r"^[uihrp]i")
        installed_pkgs = {}
        try:
            self.logger.debug("Querying the local system for installed packages")
            dpkg_output = self._get_dpkg_list()

            for pkg in dpkg_output:
                if installed_regex.match(str(pkg)) is not None:
                    pkg_details = pkg.split()
                    installed_pkgs[pkg_details[1]] = pkg_details[2]

            return installed_pkgs
        except Exception as ex:
            raise PkgCountError(ex)

    def _get_dpkg_list(self):
        self.logger.debug(
            "Running `dpkg -l` to get a list of locally installed packages"
        )
        dpkg = subprocess.Popen(
            ["dpkg", "-l"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
        )
        out, outerr = dpkg.communicate()

        if dpkg.returncode != 0:
            raise PkgCountError(
                "dpkg exited with code %d: %s" % (dpkg.returncode, outerr)
            )

        return out.splitlines()
