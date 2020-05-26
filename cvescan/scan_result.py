from collections import namedtuple

ScanResult = namedtuple(
    "ScanResult", ["cve_id", "priority", "package_name", "fixed_version", "repository"]
)
