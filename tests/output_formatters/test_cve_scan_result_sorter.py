from cvescan.output_formatters import CVEScanResultSorter


def test_cve_scan_ascending(shuffled_scan_results):
    cve_sorter = CVEScanResultSorter()

    cve_sorter.sort(shuffled_scan_results)

    assert shuffled_scan_results[0].cve_id == "CVE-2020-1000"
    assert shuffled_scan_results[1].cve_id == "CVE-2020-1001"
    assert shuffled_scan_results[2].cve_id == "CVE-2020-1002"
    assert shuffled_scan_results[3].cve_id == "CVE-2020-1002"
    assert shuffled_scan_results[4].cve_id == "CVE-2020-1002"
    assert shuffled_scan_results[5].cve_id == "CVE-2020-1003"
    assert shuffled_scan_results[6].cve_id == "CVE-2020-1005"
    assert shuffled_scan_results[7].cve_id == "CVE-2020-2000"
    assert shuffled_scan_results[8].cve_id == "CVE-2020-10000"


def test_cve_scan_descending(shuffled_scan_results):
    cve_sorter = CVEScanResultSorter(reverse=True)

    cve_sorter.sort(shuffled_scan_results)

    print(shuffled_scan_results[0].cve_id)
    assert shuffled_scan_results[0].cve_id == "CVE-2020-10000"
    assert shuffled_scan_results[1].cve_id == "CVE-2020-2000"
    assert shuffled_scan_results[2].cve_id == "CVE-2020-1005"
    assert shuffled_scan_results[3].cve_id == "CVE-2020-1003"
    assert shuffled_scan_results[4].cve_id == "CVE-2020-1002"
    assert shuffled_scan_results[5].cve_id == "CVE-2020-1002"
    assert shuffled_scan_results[6].cve_id == "CVE-2020-1002"
    assert shuffled_scan_results[7].cve_id == "CVE-2020-1001"
    assert shuffled_scan_results[8].cve_id == "CVE-2020-1000"
