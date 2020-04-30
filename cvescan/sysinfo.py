import os
import sys

class SysInfo:
    def __init__(self):
        # TODO: Find a better way to locate this file than relying on it being in the
        #       same directory as this script
        self.scriptdir = os.path.abspath(os.path.dirname(sys.argv[0]))
        self.xslt_file = str("%s/text.xsl" % self.scriptdir)

        self._set_snap_info()

    def _set_snap_info(self):
        self.is_snap = False
        self.snap_user_common = None

        if "SNAP_USER_COMMON" in os.environ:
            self.is_snap = True
            self.snap_user_common = os.environ["SNAP_USER_COMMON"]
