import cvescan.constants as const

VERBOSE_FLAGS = "-v|--verbose"
PRIORITY_FLAGS = "-p|priority"
DB_FLAGS = "--db"
MANIFEST_FLAGS = "-m|--manifest"
CSV_FLAGS = "--csv"
JSON_FLAGS = "--json"
SYSLOG_FLAGS = "--syslog"
SYSLOG_LIGHT_FLAGS = "--syslog-light"
SHOW_LINKS_FLAGS = "--show-links"
UNRESOLVED_FLAGS = "--unresolved"
EXPERIMENTAL_FLAGS = "-x|--experimental"
NAGIOS_FLAGS = "-n|--nagios"
CVE_FLAGS = "-c|--cve"
EXCLUDE_CVE_FLAGS = "-X|--exclude-cve"
SILENT_FLAGS = "-s|--silent"


arg_compatibility_map = {
    const.VERBOSE_ARG_NAME: {
        "flags": VERBOSE_FLAGS,
        "required": set(),
        "incompatible": {const.SILENT_ARG_NAME},
    },
    const.PRIORITY_ARG_NAME: {
        "flags": PRIORITY_FLAGS,
        "required": set(),
        "incompatible": {const.CVE_ARG_NAME},
    },
    const.DB_ARG_NAME: {"flags": DB_FLAGS, "required": set(), "incompatible": set()},
    const.MANIFEST_ARG_NAME: {
        "flags": MANIFEST_FLAGS,
        "required": set(),
        "incompatible": set(),
    },
    const.CSV_ARG_NAME: {
        "flags": CSV_FLAGS,
        "required": set(),
        "incompatible": {
            const.JSON_ARG_NAME,
            const.SYSLOG_ARG_NAME,
            const.SYSLOG_LIGHT_ARG_NAME,
            const.NAGIOS_ARG_NAME,
            const.CVE_ARG_NAME,
            const.SILENT_ARG_NAME,
        },
    },
    const.JSON_ARG_NAME: {
        "flags": JSON_FLAGS,
        "required": set(),
        "incompatible": {
            const.CSV_ARG_NAME,
            const.SYSLOG_ARG_NAME,
            const.SYSLOG_LIGHT_ARG_NAME,
            const.NAGIOS_ARG_NAME,
            const.CVE_ARG_NAME,
            const.SILENT_ARG_NAME,
        },
    },
    const.SYSLOG_ARG_NAME: {
        "flags": SYSLOG_FLAGS,
        "required": set(),
        "incompatible": {
            const.CSV_ARG_NAME,
            const.JSON_ARG_NAME,
            const.SYSLOG_LIGHT_ARG_NAME,
            const.NAGIOS_ARG_NAME,
            const.CVE_ARG_NAME,
            const.SILENT_ARG_NAME,
        },
    },
    const.SYSLOG_LIGHT_ARG_NAME: {
        "flags": SYSLOG_LIGHT_FLAGS,
        "required": set(),
        "incompatible": {
            const.CSV_ARG_NAME,
            const.JSON_ARG_NAME,
            const.SYSLOG_ARG_NAME,
            const.NAGIOS_ARG_NAME,
            const.CVE_ARG_NAME,
            const.SILENT_ARG_NAME,
        },
    },
    const.SHOW_LINKS_ARG_NAME: {
        "flags": SHOW_LINKS_FLAGS,
        "required": set(),
        "incompatible": {const.NAGIOS_ARG_NAME, const.CVE_ARG_NAME},
    },
    const.UNRESOLVED_ARG_NAME: {
        "flags": UNRESOLVED_FLAGS,
        "required": set(),
        "incompatible": {const.NAGIOS_ARG_NAME, const.CVE_ARG_NAME},
    },
    const.EXPERIMENTAL_ARG_NAME: {
        "flags": EXPERIMENTAL_FLAGS,
        "required": set(),
        "incompatible": set(),
    },
    const.NAGIOS_ARG_NAME: {
        "flags": NAGIOS_FLAGS,
        "required": set(),
        "incompatible": {
            const.CSV_ARG_NAME,
            const.JSON_ARG_NAME,
            const.SYSLOG_ARG_NAME,
            const.SYSLOG_LIGHT_ARG_NAME,
            const.SHOW_LINKS_ARG_NAME,
            const.UNRESOLVED_ARG_NAME,
            const.CVE_ARG_NAME,
            const.SILENT_ARG_NAME,
        },
    },
    const.CVE_ARG_NAME: {
        "flags": CVE_FLAGS,
        "required": {},
        "incompatible": {
            const.CSV_ARG_NAME,
            const.JSON_ARG_NAME,
            const.SYSLOG_ARG_NAME,
            const.SYSLOG_LIGHT_ARG_NAME,
            const.SHOW_LINKS_ARG_NAME,
            const.UNRESOLVED_ARG_NAME,
            const.NAGIOS_ARG_NAME,
        },
    },
    const.SILENT_ARG_NAME: {
        "flags": SILENT_FLAGS,
        "required": {const.CVE_ARG_NAME},
        "incompatible": {
            const.CSV_ARG_NAME,
            const.JSON_ARG_NAME,
            const.SYSLOG_ARG_NAME,
            const.SYSLOG_LIGHT_ARG_NAME,
            const.SHOW_LINKS_ARG_NAME,
            const.UNRESOLVED_ARG_NAME,
            const.NAGIOS_ARG_NAME,
            const.VERBOSE_ARG_NAME,
        },
    },
    const.EXCLUDE_CVE_ARG_NAME: {
        "flags": EXCLUDE_CVE_FLAGS,
        "required": set(),
        "incompatible": set(),
    },
}
