import os

import setuptools

from cvescan.version import get_version

with open("README.md", "r") as fh:
    long_description = fh.read()

os.umask(0o022)

setuptools.setup(
    name="cvescan",
    version=get_version(),
    author=(
        "Mark Morlino <mark.morlino@canonical.com>,"
        "Mike Salvatore <mike.salvatore@canonical.com>"
    ),
    description="A utility determining which CVEs affect an Ubuntu system.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/canonical/sec-cvescan",
    packages=setuptools.find_packages(exclude=["tests"]),
    license="GPLv3",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
    ],
    install_requires=[
        "pydpkg",
        "tabulate",
        "ust-download-cache",
        "vistir[spinner]",
        "validators",
    ],
    python_requires=">=3.7",
    setup_requires=["pytest-runner"],
    tests_require=["pytest", "pytest-cov"],
    entry_points={"console_scripts": ["cvescan=cvescan.__main__:main"]},
)
