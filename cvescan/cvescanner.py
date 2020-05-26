import json
import os
import re
from shutil import copyfile

import apt_pkg

import cvescan.constants as const
import cvescan.downloader as downloader
from cvescan.scan_result import ScanResult

ESM_VERSION_RE = re.compile(r"[+~]esm\d+")


class CVEScanner:
    def __init__(self, logger):
        apt_pkg.init_system()

        self.logger = logger

    def scan(self, opt, installed_pkgs):
        if opt.manifest_mode:
            return self._run_manifest_mode(opt, installed_pkgs)

        return self._run_cvescan(opt, installed_pkgs)

    def _run_manifest_mode(self, opt, installed_pkgs):
        if not opt.manifest_file:
            self.logger.debug("Downloading %s" % opt.manifest_url)
            downloader.download(opt.manifest_url, const.DEFAULT_MANIFEST_FILE)
        else:
            copyfile(opt.manifest_file, const.DEFAULT_MANIFEST_FILE)

        # TODO: Create dictionary of installed packages/versions from manifest file
        return self._run_cvescan(opt, installed_pkgs)

    # TODO: I don't think I want CVEScan to care about what files are in use or
    #       whether or not its in manifest mode. Ideally, we would just pass in
    #       the data parsed from UCT and a dictionary of installed packages and
    #       versions
    def _run_cvescan(self, opt, installed_pkgs):
        if opt.download_oval_file:
            self._retrieve_oval_file(opt)

        with open(opt.oval_file) as oval_file:
            cve_status = json.load(oval_file)

        return self._scan_for_cves(opt.distrib_codename, cve_status, installed_pkgs)

    def _retrieve_oval_file(self, opt):
        self.logger.debug("Downloading %s/%s" % (opt.oval_base_url, opt.oval_zip))
        downloader.download(os.path.join(opt.oval_base_url, opt.oval_zip), opt.oval_zip)

        self.logger.debug("Unzipping %s" % opt.oval_zip)
        downloader.bz2decompress(opt.oval_zip, opt.oval_file)

    # TODO: Add debug logging
    def _scan_for_cves(self, distrib_codename, cve_status, installed_pkgs):
        affected_cves = list()

        for (cve_id, uct_record) in cve_status.items():
            if distrib_codename not in uct_record["releases"]:
                continue

            affected_cves = affected_cves + self._scan_for_single_cve(
                cve_id, uct_record, distrib_codename, cve_status, installed_pkgs
            )

        return affected_cves

    def _scan_for_single_cve(
        self, cve_id, uct_record, distrib_codename, cve_status, installed_pkgs
    ):
        affected_cves = list()

        for src_pkg_details in uct_record["releases"][distrib_codename].values():
            if src_pkg_details["status"][0] in {"DNE", "not-affected"}:
                continue

            installed_binaries = [
                (b, installed_pkgs[b])
                for b in src_pkg_details["binaries"]
                if b in installed_pkgs
            ]
            vulnerable_binaries = self._find_vulnerable_binaries(
                src_pkg_details, installed_binaries
            )

            for vb in vulnerable_binaries:
                affected_cves.append(
                    ScanResult(cve_id, uct_record["priority"], vb[0], vb[1], vb[2])
                )

        return affected_cves

    def _find_vulnerable_binaries(self, src_pkg_details, installed_binaries):
        binary_statuses = list()

        if src_pkg_details["status"][0] in ["released", "released-esm"]:
            fixed_version = src_pkg_details["status"][1]
            repository = src_pkg_details["repository"]

            for b in installed_binaries:
                if not self._installed_pkg_is_patched(
                    b[1], src_pkg_details["status"][1]
                ):
                    binary_statuses.append([b[0], fixed_version, repository])
        else:
            binary_statuses = [[b[0], None, None] for b in installed_binaries]

        return binary_statuses

    def _installed_pkg_is_patched(self, installed_pkg_version, patched_version):
        version_compare = apt_pkg.version_compare(
            installed_pkg_version, patched_version
        )

        return version_compare >= 0
