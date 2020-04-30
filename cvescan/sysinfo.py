import configparser
import math
import os
import sys
import time

class SysInfo:
    def __init__(self, logger):
        self.logger = logger
        # TODO: Find a better way to locate this file than relying on it being in the
        #       same directory as this script
        self.scriptdir = os.path.abspath(os.path.dirname(sys.argv[0]))
        self.xslt_file = str("%s/text.xsl" % self.scriptdir)

        self._set_snap_info()
        self.distrib_codename = self.get_ubuntu_codename()
        self.process_start_time = math.trunc(time.time())

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
            raise DistribIDError("DISTRIB_ID in /etc/lsb-release must be Ubuntu (DISTRIB_ID=%s)" % distrib_id)

        return distrib_codename

    def get_lsb_release_info(self):
        try:
            import lsb_release

            self.logger.debug("Using the lsb_release python module to determine ubuntu codename")
            distro = lsb_release.get_distro_information()
            return (distro.get('ID', "UNKNOWN"), distro.get('CODENAME', "UNKNOWN"))
        except:
            self.logger.debug("The lsb_release python module is not installed or has failed")
            return self.get_lsb_release_info_from_file()

    # Getting distro ID and codename from file beacuse the lsb_release python module
    # is not available. The lsb_release module is not installed in the snap package
    # because it causes the package to tripple in size.
    def get_lsb_release_info_from_file(self):
        lsb_release_file = "/etc/lsb-release"

        self.logger.debug("Attempting to read %s to determine DISTRIB_ID and DISTRIB_CODENAME" % lsb_release_file)
        with open(lsb_release_file, "rt") as lsb_file:
            lsb_file_contents = lsb_file.read()

        # ConfigParser needs section headers, so adding a header.
        lsb_file_contents = "[lsb]\n" + lsb_file_contents

        lsb_config = configparser.ConfigParser()
        lsb_config.read_string(lsb_file_contents)

        return (lsb_config.get("lsb","DISTRIB_ID"), lsb_config.get("lsb","DISTRIB_CODENAME"))

