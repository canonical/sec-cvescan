import cvescan.manifest_parser as manifest_parser


class TargetSysInfo:
    def __init__(self, opt, local_sysinfo):
        if opt.manifest_mode:
            self._set_from_manifest_file(opt)
        else:
            self._set_from_local_sysinfo(local_sysinfo)

    def _set_from_manifest_file(self, opt):
        (installed_pkgs, codename) = manifest_parser.parse_manifest_file(
            opt.manifest_file
        )

        self.installed_pkgs = installed_pkgs
        self.codename = codename

        self.esm_apps_enabled = None
        self.esm_infra_enabled = None

    def _set_from_local_sysinfo(self, local_sysinfo):
        self.installed_pkgs = local_sysinfo.installed_pkgs
        self.codename = local_sysinfo.codename

        self.esm_apps_enabled = local_sysinfo.esm_apps_enabled
        self.esm_infra_enabled = local_sysinfo.esm_infra_enabled

    @property
    def pkg_count(self):
        return len(self.installed_pkgs)
