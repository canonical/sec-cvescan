# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Ability to read a manifest file from stdin.
- Manifests can include an explicit Ubuntu codename if the update-manager-core
  package is not installed.
- `dump_dpkg_manifest.sh` script as the preferred mechanism for generating
  manifest files.
- `cvescan.dump-dpkg-manifest` command to the snap. This command invokes the
  `dump_dpkg_manifest.sh` script.
### Changed
- Corrected spelling issues in `CHANGELOG.md` and `README.md`
- The snap to be based on core20 instead of core18.
- Minimum required python version to >=3.7.
- Replace dependency on python-apt with pydpkg.
### Removed
- The bash implementation of CVEScan (v1.0.10) from repository.
- cvescan.sh command from snap.

## [2.5.0] - 2020-08-27
### Added
- `--syslog` option that sends JSON output to a syslog server.
- `--syslog-light` option that sends simple log message to a syslog server.
- Progress indicators (spinners) that show when the vulnerability DB is being
  downloaded and when the scan is running.
### Changed
- The help and usage message to be more concise with cleaner formatting.
### Deprecated
- The bash implementation of CVEScan has been deprecated since `v2.0.0`. This is
  the last version of CVEScan in which the bash implementation will be available.

## [2.4.0] - 2020-08-03
### Added
- A `--version` argument that shows the version of CVEScan.
### Changed
- "UA Apps" and "UA Infra" to "ESM Apps" and "ESM Infra" respectively in all
  output formats (CLI, CSV, JSON, etc.).

## [2.3.1] - 2020-07-21
### Changed
- `USTDownloadCache` dependency from `v1.1.0` to `v2.0.0`.

## [2.3.0] - 2020-07-06
### Added
- The ability to install in a python virtual environment.
### Changed
- Download smaller vulnerability databases that are specific to an Ubuntu
  release. This improves performance by 2x-5x.
- `USTDownloadCache` dependency from `v1.0.1` to `v1.1.0` and install from `PyPI`. This
  removes CVEScan's dependency on `pycurl` and, consequently,
  `libcurl4-openssl-dev` and `libssl-dev`.
### Fixed
- Improved startup time for snap package.
- Catch `KeyError` and `JSONDecodeError` when parsing malformed
  `/var/lib/ubuntu-advantage/status.json`.

## [2.2.1] - 2020-06-24
### Changed
- Made ESM/UA language consistent in default output.

## [2.2.0] - 2020-06-24
### Added
- Security suggestions to the bottom of the default output.
- A "(disabled)" marker next to disabled repositories in the default output ([issue #43](https://github.com/canonical/sec-cvescan/issues/43)).
### Changed
- The ordering of the default output so that the summary is printed after the
  list of CVEs.
- The CVE keys in the JSON output are now sub-keys under a "cves" key.
- Since we can have no knowledge of the status of repositories in manifest
  mode, don't colorize repositories when in manifest mode.

## [2.1.0] - 2020-06-23
### Added
- A `--csv` flag to instruct CVEScan to format the output as CSV ([issue #32](https://github.com/canonical/sec-cvescan/issues/32)).
- A `--json` flag to instruct CVEScan to format the output as JSON ([issue #32](https://github.com/canonical/sec-cvescan/issues/32)).
- More unit tests for `main()`.
### Changed
- The "ARCHIVE" column header to "REPOSITORY" for accuracy and consistency.
### Fixed
- Minor copy/paste error in snap badge in README.md.
- CVE links/URLs use https instead of http.
### Removed
- ESM entitlement status from experimental and debug output ([issue #45](https://github.com/canonical/sec-cvescan/issues/45)).

## [2.0.0] - 2020-06-22
### Added
- A total rewrite of CVEScan in python.
- Unit test suite for python implementation.
- An ESM status check and report ([issue #8](https://github.com/canonical/sec-cvescan/issues/8)).
- A `--db` option to specify a local file containing an Ubuntu vulnerability database.
- Additional verbose output that is useful for debugging.
- Support for running on Focal.
- The `--show-links` option.
- The `--db` option.
- The `--unresolved` option.
- Colors to default output.
- Continuous integration with Travis-CI.
- The ability to use pip to install from source.
- Smart caching so that a new db/vulnerability file is only downloaded if the
  previously downloaded version is stale ([issue #40](https://github.com/canonical/sec-cvescan/issues/40)).
### Changed
- Certain options are fundamentally incompatible. Attempting to use these options
  together will result in an error message, whereas the previous version would
  ignore the incompatibilities and the behavior was undefined.
- Bash implementation is invoked using `cvescan.sh`.
- Python implementation is invoked using `cvescan`.
- Implement verbose logging using info/debug logger.
- Total overhaul of output formatting. Show a tabulated output that includes
  information such as the priority and packages each CVE affects ([issue #9](https://github.com/canonical/sec-cvescan/issues/9), [issue #11](https://github.com/canonical/sec-cvescan/issues/11),
  [issue #30](https://github.com/canonical/sec-cvescan/issues/30).)
- Use JSON generated from the Ubuntu CVE Tracker instead of OVAL data.
- Manifest mode checks package versions in the manifest file to determine the Ubuntu
  codename, so the `--manifest` option no longer expects an Ubuntu codename.
  Instead, it expects the path to the manifest file.
- The default behavior is to show only updatable packages. The `--updates` option
  is no longer included. The `--unresolved` option can be used to show CVEs that have
  not been patched.
- The default behavior is to show CVE IDs, not URLS. The `--list` option is no longer
  included. The `--show-links` option can be used to show links to the Ubuntu CVE Tracker.
### Deprecated
- The entire bash implementation of CVEScan
### Removed
- Test mode
- All file/download caching
- Dependencies on OSCAP/XSLTProc
- The `--list` option
- The `--updates` option
- The `--reuse` option
- The `--file` option
- Support for running on disco.
### Fixed
- Manifest mode does not check Ubuntu version and can be run on any version of Linux.
- CVEScan runs on Focal ([issue #37](https://github.com/canonical/sec-cvescan/issues/37))
- Correct version verbiage in python version ([issue #34](https://github.com/canonical/sec-cvescan/issues/34))
- Reduce the amount of CPU resources required to run CVEScan ([issue #31](https://github.com/canonical/sec-cvescan/issues/31).)
- CVEScan uses less memory and can run on lightweight AWS instances ([issue #2](https://github.com/canonical/sec-cvescan/issues/2).)
- Run 10x faster.

## [1.0.10] - 2020-04-13
### Added
- CVEScan implementation in bash
- `snapcraft.yaml` to package CVEScan as a snap
- Nagios output mode
- CVE output mode
- Priority filtering
- Experimental Mode
- Test Mode
- Manifest Mode

