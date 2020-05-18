import os

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

os.umask(0o022)

setuptools.setup(
    name="cvescan",
    version="2.0.0",
    author="Mark Morlino <mark.morlino@canonical.com>, Mike Salvatore <mike.salvatore@canonical.com>",
    description="A utility for using the Ubuntu Security Team's OVAL files to" \
        "determine which CVEs affect an Ubuntu system.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/canonical/sec-cvescan",
    packages=setuptools.find_packages(exclude=["tests"]),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
    ],
    install_requires=[
	"argparse",
	"configparser",
	"pycurl",
        "tabulate"
    ],
    python_requires=">=3.5",
    setup_requires=[
        'pytest-runner',
    ],
    tests_require=[
        'pytest',
        'pytest-cov',
    ],
    entry_points={'console_scripts': ['cvescan=cvescan.__main__:main']},
)
