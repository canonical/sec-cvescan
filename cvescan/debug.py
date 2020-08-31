from tabulate import tabulate


def log_config_options(opt, logger):
    logger.debug("Config Options")
    table = [
        ["Manifest Mode", opt.manifest_mode],
        ["Experimental Mode", opt.experimental_mode],
        ["Nagios Output Mode", opt.nagios_mode],
        ["Ubuntu Vulnerability DB File Path", opt.db_file],
        ["Manifest File", opt.manifest_file],
        ["Check Specific CVE", opt.cve],
        ["CVE Priority", opt.priority],
        ["Show Unresolved CVEs", opt.unresolved],
    ]

    logger.debug(tabulate(table))
    logger.debug("")


def log_local_system_info(local_sysinfo, manifest_mode, logger):
    logger.debug("Local System Info")
    table = [
        ["CVEScan is a Snap", local_sysinfo.is_snap],
        ["$SNAP_USER_COMMON", local_sysinfo.snap_user_common],
    ]

    if not manifest_mode:
        table = [
            ["Local Ubuntu Codename", local_sysinfo.codename],
            ["Installed Package Count", local_sysinfo.package_count],
            # Disabling for now
            # ["ESM Apps Enabled", local_sysinfo.esm_apps_enabled],
            # ["ESM Infra Enabled", local_sysinfo.esm_infra_enabled],
        ] + table

    logger.debug(tabulate(table))
    logger.debug("")


def log_target_system_info(target_sysinfo, logger):
    logger.debug("Target System Info")

    table = [
        ["Local Ubuntu Codename", target_sysinfo.codename],
        ["Installed Package Count", target_sysinfo.pkg_count],
        # Disabling for now
        # ["ESM Apps Enabled", target_sysinfo.esm_apps_enabled],
        # ["ESM Infra Enabled", target_sysinfo.esm_infra_enabled],
    ]

    logger.debug(tabulate(table))
    logger.debug("")
