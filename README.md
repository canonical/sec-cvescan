# CVEScan

The Ubuntu Security Team at Canonical regularly publishes a JSON file containing
information about packages with security updates. The source of the information is 
the [Ubuntu CVE Tracker](https://launchpad.net/ubuntu-cve-tracker). The information
contained in the JSON file is similar to the information published in OVAL files but
the format is designed specifically to work with the CVEScan tool.

## About CVEScan

CVEScan is a python script that downloads the JSON file described above
and uses it to compare versions of packages with security fixes to version of packages
installed on your Ubuntu system or listed in a a package manifest file.

## Using CVEScan

The recommended way to use CVEScan is by using the snap.
```
sudo snap install cvescan
```
```
cvescan
```

There is more detailed usage information in the help.
```
cvescan -h
```

## Alternative method of Using CVEScan

If you have cloned this repo you can also run CVEScan as a python script.
```
python3 -m cvescan
```

Or, you can install it as a python module.
```
pip3 install --user .
```

## Development

### Installing precommit hooks
To install the precommit hooks, run

    pip3 install --user pre-commit
    ~/.local/bin/pre-commit install

### Running the test suite
You can run the automated test suite by running

    python3 setup.py test.

An HTML code coverage report will be generated at `./htmlcov`. You can view
this report by running

    firefox ./htmlcov/index.html
