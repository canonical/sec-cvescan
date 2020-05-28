import configparser
import json
import os
import re
import subprocess

import cvescan.constants as const
from cvescan.errors import DistribIDError, PkgCountError


class LocalSysInfo:
    def __init__(self, logger):
        self.logger = logger

        self._set_snap_info()
        self._esm_apps_enabled = None
        self._esm_infra_enabled = None
        self._codename = None
        self._installed_pkgs = None

    def _set_snap_info(self):
        self.is_snap = False
        self.snap_user_common = None

        if "SNAP_USER_COMMON" in os.environ:
            self.logger.debug("Detected that CVEScan is installed as a snap")
            self.is_snap = True
            self.snap_user_common = os.environ["SNAP_USER_COMMON"]

    @property
    def esm_apps_enabled(self):
        if self._esm_apps_enabled is None:
            self._set_esm_status()

        return self._esm_apps_enabled

    @property
    def esm_infra_enabled(self):
        if self._esm_infra_enabled is None:
            self._set_esm_status()

        return self._esm_infra_enabled

    def _set_esm_status(self):
        try:
            apps = False
            infra = False

            ua_status_file_path = self._get_ua_status_file_path()
            ua_status = self._get_raw_ua_status(ua_status_file_path)

            for entitlement in ua_status["services"]:
                if entitlement["name"] == "esm-apps":
                    apps = True if entitlement["status"] == "enabled" else False
                elif entitlement["name"] == "esm-infra":
                    infra = True if entitlement["status"] == "enabled" else False
        except (FileNotFoundError, PermissionError) as err:
            self.logger.debug("Failed to open UA Status JSON file: %s" % err)

        self._esm_apps_enabled = apps
        self._esm_infra_enabled = infra

    @property
    def codename(self):
        if not self._codename:
            self._codename = self._get_ubuntu_codename()

        return self._codename

    def _get_ubuntu_codename(self):
        distrib_id, codename = self.get_lsb_release_info()

        if distrib_id != "Ubuntu":
            raise DistribIDError(
                "DISTRIB_ID in /etc/lsb-release must be Ubuntu (DISTRIB_ID=%s)"
                % distrib_id
            )

        return codename

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
        return len(self.installed_pkgs.keys())

    @property
    def installed_pkgs(self):
        if not self._installed_pkgs:
            self._installed_pkgs = self._get_installed_pkgs()

        return self._installed_pkgs

    def _get_installed_pkgs(self):
        installed_regex = re.compile(r"^[uihrp]i")
        installed_pkgs = {}
        try:
            self.logger.debug("Querying the local system for installed packages")
            dpkg_output = self._get_dpkg_list()

            # TODO: This code is basically duplicated in manifest_parser.py.
            #       Replace duplicate code with a dpkg_parser module or similar.
            for pkg in dpkg_output:
                if installed_regex.match(str(pkg)) is not None:
                    pkg_details = pkg.split()
                    pkg = self.strip_architecture_extension(pkg_details[1])
                    installed_pkgs[pkg] = pkg_details[2]

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

    def strip_architecture_extension(self, pkg):
        return pkg.split(":")[0]

    def _get_ua_status_file_path(self):
        ua_status_file_path = const.UA_STATUS_FILE
        if self.is_snap:
            ua_status_file_path = "%s%s" % (const.SNAPD_HOSTFS, ua_status_file_path)

        return ua_status_file_path

    def _get_raw_ua_status(self, ua_status_file_path):
        self.logger.debug(
            "Attempting to read %s to determine the status of UA offerings"
            % ua_status_file_path
        )
        with open(ua_status_file_path) as ua_status_file:
            ua_status = json.load(ua_status_file)

        return ua_status
