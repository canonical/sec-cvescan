from cvescan.output_formatters import CVEScanResultSorter, PackageScanResultSorter


def test_cve_package_scan_ascending(shuffled_scan_results):
    pkg_sorter = PackageScanResultSorter()
    cve_sorter = CVEScanResultSorter(subsorters=[pkg_sorter])

    cve_sorter.sort(shuffled_scan_results)

    assert shuffled_scan_results[0].cve_id == "CVE-2020-1000"
    assert shuffled_scan_results[0].package_name == "pkg4"
    assert shuffled_scan_results[1].cve_id == "CVE-2020-1001"
    assert shuffled_scan_results[1].package_name == "pkg4"
    assert shuffled_scan_results[2].cve_id == "CVE-2020-1002"
    assert shuffled_scan_results[2].package_name == "pkg3"
    assert shuffled_scan_results[3].cve_id == "CVE-2020-1002"
    assert shuffled_scan_results[3].package_name == "pkg4"
    assert shuffled_scan_results[4].cve_id == "CVE-2020-1002"
    assert shuffled_scan_results[4].package_name == "pkg6"
    assert shuffled_scan_results[5].cve_id == "CVE-2020-1003"
    assert shuffled_scan_results[5].package_name == "pkg5"
    assert shuffled_scan_results[6].cve_id == "CVE-2020-1005"
    assert shuffled_scan_results[6].package_name == "pkg2"
    assert shuffled_scan_results[7].cve_id == "CVE-2020-2000"
    assert shuffled_scan_results[7].package_name == "pkg1"
    assert shuffled_scan_results[8].cve_id == "CVE-2020-10000"
    assert shuffled_scan_results[8].package_name == "pkg7"


def test_cve_scan_descending(shuffled_scan_results):
    pkg_sorter = PackageScanResultSorter(reverse=True)
    cve_sorter = CVEScanResultSorter(reverse=True, subsorters=[pkg_sorter])

    cve_sorter.sort(shuffled_scan_results)

    assert shuffled_scan_results[0].cve_id == "CVE-2020-10000"
    assert shuffled_scan_results[0].package_name == "pkg7"
    assert shuffled_scan_results[1].cve_id == "CVE-2020-2000"
    assert shuffled_scan_results[1].package_name == "pkg1"
    assert shuffled_scan_results[2].cve_id == "CVE-2020-1005"
    assert shuffled_scan_results[2].package_name == "pkg2"
    assert shuffled_scan_results[3].cve_id == "CVE-2020-1003"
    assert shuffled_scan_results[3].package_name == "pkg5"
    assert shuffled_scan_results[4].cve_id == "CVE-2020-1002"
    assert shuffled_scan_results[4].package_name == "pkg6"
    assert shuffled_scan_results[5].cve_id == "CVE-2020-1002"
    assert shuffled_scan_results[5].package_name == "pkg4"
    assert shuffled_scan_results[6].cve_id == "CVE-2020-1002"
    assert shuffled_scan_results[6].package_name == "pkg3"
    assert shuffled_scan_results[7].cve_id == "CVE-2020-1001"
    assert shuffled_scan_results[7].package_name == "pkg4"
    assert shuffled_scan_results[8].cve_id == "CVE-2020-1000"
    assert shuffled_scan_results[8].package_name == "pkg4"


def test_cve_scan_ascending_descending(shuffled_scan_results):
    pkg_sorter = PackageScanResultSorter(reverse=True)
    cve_sorter = CVEScanResultSorter(reverse=False, subsorters=[pkg_sorter])

    cve_sorter.sort(shuffled_scan_results)

    assert shuffled_scan_results[0].cve_id == "CVE-2020-1000"
    assert shuffled_scan_results[0].package_name == "pkg4"
    assert shuffled_scan_results[1].cve_id == "CVE-2020-1001"
    assert shuffled_scan_results[1].package_name == "pkg4"
    assert shuffled_scan_results[2].cve_id == "CVE-2020-1002"
    assert shuffled_scan_results[2].package_name == "pkg6"
    assert shuffled_scan_results[3].cve_id == "CVE-2020-1002"
    assert shuffled_scan_results[3].package_name == "pkg4"
    assert shuffled_scan_results[4].cve_id == "CVE-2020-1002"
    assert shuffled_scan_results[4].package_name == "pkg3"
    assert shuffled_scan_results[5].cve_id == "CVE-2020-1003"
    assert shuffled_scan_results[5].package_name == "pkg5"
    assert shuffled_scan_results[6].cve_id == "CVE-2020-1005"
    assert shuffled_scan_results[6].package_name == "pkg2"
    assert shuffled_scan_results[7].cve_id == "CVE-2020-2000"
    assert shuffled_scan_results[7].package_name == "pkg1"
    assert shuffled_scan_results[8].cve_id == "CVE-2020-10000"
    assert shuffled_scan_results[8].package_name == "pkg7"


def test_cve_scan_descending_ascending(shuffled_scan_results):
    pkg_sorter = PackageScanResultSorter(reverse=False)
    cve_sorter = CVEScanResultSorter(reverse=True, subsorters=[pkg_sorter])

    cve_sorter.sort(shuffled_scan_results)

    assert shuffled_scan_results[0].cve_id == "CVE-2020-10000"
    assert shuffled_scan_results[0].package_name == "pkg7"
    assert shuffled_scan_results[1].cve_id == "CVE-2020-2000"
    assert shuffled_scan_results[1].package_name == "pkg1"
    assert shuffled_scan_results[2].cve_id == "CVE-2020-1005"
    assert shuffled_scan_results[2].package_name == "pkg2"
    assert shuffled_scan_results[3].cve_id == "CVE-2020-1003"
    assert shuffled_scan_results[3].package_name == "pkg5"
    assert shuffled_scan_results[4].cve_id == "CVE-2020-1002"
    assert shuffled_scan_results[4].package_name == "pkg3"
    assert shuffled_scan_results[5].cve_id == "CVE-2020-1002"
    assert shuffled_scan_results[5].package_name == "pkg4"
    assert shuffled_scan_results[6].cve_id == "CVE-2020-1002"
    assert shuffled_scan_results[6].package_name == "pkg6"
    assert shuffled_scan_results[7].cve_id == "CVE-2020-1001"
    assert shuffled_scan_results[7].package_name == "pkg4"
    assert shuffled_scan_results[8].cve_id == "CVE-2020-1000"
    assert shuffled_scan_results[8].package_name == "pkg4"
