from conftest import MockOpt, MockSysInfo, filter_scan_results_by_cve_ids, null_logger

from cvescan.output_formatters import CSVOutputFormatter


def test_priority_filter_all(run_priority_filter_all_test):
    run_priority_filter_all_test(CSVOutputFormatter)


def test_priority_filter_negligible(run_priority_filter_negligible_test):
    run_priority_filter_negligible_test(CSVOutputFormatter)


def test_priority_filter_low(run_priority_filter_low_test):
    run_priority_filter_low_test(CSVOutputFormatter)


def test_priority_filter_medium(run_priority_filter_medium_test):
    run_priority_filter_medium_test(CSVOutputFormatter)


def test_priority_filter_high(run_priority_filter_high_test):
    run_priority_filter_high_test(CSVOutputFormatter)


def test_priority_filter_critical(run_priority_filter_critical_test):
    run_priority_filter_critical_test(CSVOutputFormatter)


def test_no_unresolved_shown(run_no_unresolved_shown_test):
    run_no_unresolved_shown_test(CSVOutputFormatter)


def test_success_return_code(run_success_return_code_test):
    run_success_return_code_test(CSVOutputFormatter)


def test_vulnerable_return_code(run_vulnerable_return_code_test):
    run_vulnerable_return_code_test(CSVOutputFormatter)


def test_patch_available_return_code(run_patch_available_return_code_test):
    run_patch_available_return_code_test(CSVOutputFormatter)


def test_show_links(run_show_links_test):
    run_show_links_test(CSVOutputFormatter)


def test_no_show_links(run_no_show_links_test):
    run_no_show_links_test(CSVOutputFormatter)


def test_csv():
    sr = filter_scan_results_by_cve_ids(
        ["CVE-2020-1000", "CVE-2020-1001", "CVE-2020-1005"]
    )

    opt = MockOpt()
    opt.priority = "all"
    opt.unresolved = True

    formatter = CSVOutputFormatter(opt, null_logger())
    (results_msg, return_code) = formatter.format_output(sr, MockSysInfo())

    expected_csv_results = "CVE ID,PRIORITY,PACKAGE,FIXED_VERSION,REPOSITORY"
    expected_csv_results += "\nCVE-2020-1000,low,pkg3,,"
    expected_csv_results += (
        "\nCVE-2020-1001,high,pkg1,1:1.2.3-4+deb9u2ubuntu0.2,Ubuntu Archive"
    )
    expected_csv_results += (
        "\nCVE-2020-1001,high,pkg2,1:1.2.3-4+deb9u2ubuntu0.2,Ubuntu Archive"
    )
    expected_csv_results += "\nCVE-2020-1005,low,pkg1,1:1.2.3-4+deb9u3,UA Apps"
    expected_csv_results += "\nCVE-2020-1005,low,pkg2,1:1.2.3-4+deb9u3,UA Apps"
    expected_csv_results += "\nCVE-2020-1005,low,pkg3,10.2.3-2ubuntu0.1,UA Infra"

    assert results_msg == expected_csv_results


def test_csv_show_links_header():
    opt = MockOpt()
    opt.priority = "all"
    opt.unresolved = True
    opt.show_links = True

    formatter = CSVOutputFormatter(opt, null_logger())
    (results_msg, return_code) = formatter.format_output([], MockSysInfo())

    assert "URL" in results_msg
