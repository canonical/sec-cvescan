CVESCAN_DESCRIPTION = "Scan an Ubuntu system for known vulnerabilities"

VERSION_ARG_NAME = "version"
VERSION_HELP = "Show CVEScan's version number and exit"

VERBOSE_ARG_NAME = "verbose"
VERBOSE_HELP = "enable verbose messages"


PRIORITY_ARG_NAME = "priority"
PRIORITY_HELP = "filter output by CVE priority"

DB_ARG_NAME = "db"
DB_FILE_HELP = (
    "Specify an Ubuntu vulnerability database file to use instead of downloading the"
    "  latest from people.canonical.com."
)

MANIFEST_ARG_NAME = "manifest"
MANIFEST_HELP = "scan a package manifest file instead of the local system"

CSV_ARG_NAME = "csv"
CSV_HELP = "format output as CSV"

JSON_ARG_NAME = "json"
JSON_HELP = "format output as JSON"


SYSLOG_ARG_NAME = "syslog"
SYSLOG_HELP = "send JSON formatted output to a syslog server specified by <host>:<port>"

SYSLOG_LIGHT_ARG_NAME = "syslog-light"
SYSLOG_LIGHT_HELP = (
    "send a simple log message to a syslog server specified by <host>:<port>"
)

SHOW_LINKS_ARG_NAME = "show-links"
SHOW_LINKS_HELP = "include links to the Ubuntu CVE Tracker in the output"

UNRESOLVED_ARG_NAME = "unresolved"
UNRESOLVED_HELP = "include CVEs that have not yet been resolved in the output"

EXPERIMENTAL_ARG_NAME = "experimental"
EXPERIMENTAL_HELP = (
    'for users of Ubuntu Advantage, include eXperimental (also called "alpha")'
    "  in the output"
)

NAGIOS_ARG_NAME = "nagios"
NAGIOS_HELP = "format output for use with  Nagios NRPE"

CVE_ARG_NAME = "cve"
CVE_HELP = "report whether or not this system is vulnerable to a specific CVE."

SILENT_ARG_NAME = "silent"
SILENT_HELP = "do not print any output (only used with --cve)"

EXCLUDE_CVE_ARG_NAME = "exclude-cve"
EXCLUDE_CVE_HELP = "exclude reports for specific CVEs."

DEBUG_LOG = "debug.log"
LSB_RELEASE_FILE = "/etc/lsb-release"
UA_STATUS_FILE = "/var/lib/ubuntu-advantage/status.json"
SNAPD_HOSTFS = "/var/lib/snapd/hostfs"

UBUNTU_ARCHIVE = "Ubuntu Archive"
UA_APPS = "ESM Apps"
UA_INFRA = "ESM Infra"

UA_INFRA_URL = "https://ubuntu.com/advantage"

REPOSITORY_ENABLED_COLOR_CODE = 2
REPOSITORY_DISABLED_COLOR_CODE = 1
REPOSITORY_UNKNOWN_COLOR_CODE = 3


SUCCESS_RETURN_CODE = 0
ERROR_RETURN_CODE = 1
CLI_ERROR_RETURN_CODE = 2
SYSTEM_VULNERABLE_RETURN_CODE = 3
PATCH_AVAILABLE_RETURN_CODE = 4

# Nagios return codes defined here:
# https://assets.nagios.com/downloads/nagioscore/docs/nagioscore/3/en/pluginapi.html
NAGIOS_OK_RETURN_CODE = 0
NAGIOS_WARNING_RETURN_CODE = 1
NAGIOS_CRITICAL_RETURN_CODE = 2
NAGIOS_UNKNOWN_RETURN_CODE = 3

UNTRIAGED = "untriaged"
ALL = "all"
NEGLIGIBLE = "negligible"
LOW = "low"
MEDIUM = "medium"
HIGH = "high"
CRITICAL = "critical"

PRIORITIES = [NEGLIGIBLE, LOW, MEDIUM, HIGH, CRITICAL]

UCT_URL = "https://people.canonical.com/~ubuntu-security/cve/%s"
UCT_DATA_URL = (
    "https://people.canonical.com/~ubuntu-security/cvescan/ubuntu-vuln-db-%s.json.bz2"
)

JSON_INDENT = 4

NULL_LOGGER_NAME = "cvescan.null"
STDOUT_LOGGER_NAME = "cvescan.stdout"
SYSLOG_LOGGER_NAME = "cvescan.syslog"
