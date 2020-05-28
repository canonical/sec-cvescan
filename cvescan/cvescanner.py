import apt_pkg

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
