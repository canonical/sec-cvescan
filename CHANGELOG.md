# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- A total rewrite of CVEScan in python.
- Unit test suite for python implementation.
- An ESM status check and report ([issue #8](https://github.com/canonical/sec-cvescan/issues/8)).
- A --db option to specify a local file containing an Ubuntu vulnerability database.
- Additional verbose output that is useful for debugging.
- Support for running on Focal.
- The --show-links option.
- The --db option.
- The --unresolved option.
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
  codename, so the --manifest option no longer expects an Ubuntu codename.
  Instead, it expects the path to the manifest file.
- The default behavior is to show only updatable packages. The --updates option
  is no longer included. The --unresolved option can be used to show CVEs that have
  not been patched.
- The default behavior is to show CVE IDs, not URLS. The --list option is no longer
  included. The --show-links option can be used to show links to the Ubuntu CVE Tracker.
### Deprecated
- The entire bash implementation of CVEScan
### Removed
- Test mode
- All file/download caching
- Dependencies on oscap/xsltproc
- The --list option
- The --updates option
- The --reuse option
- The --file option
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
- snapcraft.yaml to package CVEScan as a snap
- Nagios output mode
- CVE output mode
- Priority filtering
- Experimental Mode
- Test Mode
- Manifest Mode

