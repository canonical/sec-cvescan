import configparser
import json
import os

import cvescan.constants as const
import cvescan.dpkg_parser as dpkg_parser
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
        except (KeyError) as ke:
            self.logger.debug(
                "The file '%s' is malformed and cannot be parsed: Missing key %s", ke
            )
        except json.decoder.JSONDecodeError:
            self.logger.debug(
                "The file '%s' contains malformed JSON and cannot be parsed."
            )

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
        try:
            self.logger.debug("Querying the local system for installed packages")
            installed_pkgs = dpkg_parser.get_installed_pkgs_from_dpkg_list(self.logger)
            return installed_pkgs
        except Exception as ex:
            raise PkgCountError(ex)

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
