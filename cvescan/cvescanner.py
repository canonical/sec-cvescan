import apt_pkg

import cvescan.constants as const
from cvescan.scan_result import ScanResult


class CVEScanner:
    def __init__(self, logger):
        apt_pkg.init_system()

        self.logger = logger

    # TODO: Add debug logging
    def scan(self, codename, uct_data, installed_pkgs):
        affected_cves = list()

        for (cve_id, uct_record) in uct_data.items():
            if codename not in uct_record["releases"]:
                continue

            affected_cves = affected_cves + self._scan_for_single_cve(
                cve_id, uct_record, codename, installed_pkgs
            )

        return affected_cves

    def _scan_for_single_cve(self, cve_id, uct_record, codename, installed_pkgs):
        affected_cves = list()

        for src_pkg_details in uct_record["releases"][codename].values():
            if src_pkg_details["status"][0] in {"DNE", "not-affected"}:
                continue

            # TODO: This is a temporary measure. The entire JSON should be
            #       validated prior to scanning. The "binaries" key should
            #       not be missing.
            if "binaries" not in src_pkg_details.keys():
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
                repo = vb[2]
                # TODO: This is a hack to work around the fact that the UA
                #       product names (presentation layer) are provided by the
                #       JSON database (data layer). Fix the root cause of this
                #       issue instead of working around it like this.
                if repo == "UA Apps":
                    repo = const.UA_APPS
                elif repo == "UA Infra":
                    repo = const.UA_INFRA
                affected_cves.append(
                    ScanResult(cve_id, uct_record["priority"], vb[0], vb[1], repo)
                )

        return affected_cves

    def _find_vulnerable_binaries(self, src_pkg_details, installed_binaries):
        if src_pkg_details["status"][0] not in ["released", "released-esm"]:
            return [[b[0], None, None] for b in installed_binaries]

        binary_statuses = list()
        fixed_version = src_pkg_details["status"][1]
        repository = src_pkg_details["repository"]

        for b in installed_binaries:
            if not self._installed_pkg_is_patched(b[1], fixed_version):
                binary_statuses.append([b[0], fixed_version, repository])

        return binary_statuses

    def _installed_pkg_is_patched(self, installed_version, patched_version):
        version_compare = apt_pkg.version_compare(installed_version, patched_version)

        return version_compare >= 0
