from cvescan.output_formatters import PackageScanResultSorter


def test_package_scan_ascending(shuffled_scan_results):
    package_sorter = PackageScanResultSorter()

    package_sorter.sort(shuffled_scan_results)

    assert shuffled_scan_results[0].package_name == "pkg1"
    assert shuffled_scan_results[1].package_name == "pkg2"
    assert shuffled_scan_results[2].package_name == "pkg3"
    assert shuffled_scan_results[3].package_name == "pkg4"
    assert shuffled_scan_results[4].package_name == "pkg4"
    assert shuffled_scan_results[5].package_name == "pkg4"
    assert shuffled_scan_results[6].package_name == "pkg5"
    assert shuffled_scan_results[7].package_name == "pkg6"
    assert shuffled_scan_results[8].package_name == "pkg7"


def test_package_scan_descending(shuffled_scan_results):
    package_sorter = PackageScanResultSorter(reverse=True)

    package_sorter.sort(shuffled_scan_results)

    print(shuffled_scan_results[0].package_name)
    assert shuffled_scan_results[0].package_name == "pkg7"
    assert shuffled_scan_results[1].package_name == "pkg6"
    assert shuffled_scan_results[2].package_name == "pkg5"
    assert shuffled_scan_results[3].package_name == "pkg4"
    assert shuffled_scan_results[4].package_name == "pkg4"
    assert shuffled_scan_results[5].package_name == "pkg4"
    assert shuffled_scan_results[6].package_name == "pkg3"
    assert shuffled_scan_results[7].package_name == "pkg2"
    assert shuffled_scan_results[8].package_name == "pkg1"
