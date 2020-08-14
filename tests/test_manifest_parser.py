import pytest

import cvescan.manifest_parser as mp

TEST_MANIFEST_FILE = "tests/assets/manifests/%s.manifest"


def test_parse_manifest_installed_pkgs():
    (installed_pkgs, _) = mp.parse_manifest_file(TEST_MANIFEST_FILE % "bionic")

    assert len(installed_pkgs) == 11
    assert installed_pkgs.get("accountsservice", None) == "0.6.45-1ubuntu1"
    assert installed_pkgs.get("acl", None) == "2.2.52-3build1"
    assert installed_pkgs.get("acpid", None) == "1:2.0.28-1ubuntu1"
    assert installed_pkgs.get("adduser", None) == "3.116ubuntu1"
    assert installed_pkgs.get("apparmor", None) == "2.12-4ubuntu5.1"
    assert installed_pkgs.get("apport", None) == "2.20.9-0ubuntu7.14"
    assert installed_pkgs.get("apport-symptoms", None) == "0.20"
    assert installed_pkgs.get("apt", None) == "1.6.12"
    assert installed_pkgs.get("base-files", None) == "10.1ubuntu2.8"
    assert installed_pkgs.get("python3-gdbm", None) == "3.6.9-1~18.04"
    assert installed_pkgs.get("update-manager-core", None) == "1:18.04.11.12"


def test_parse_manifest_codename_trusty():
    (_, codename) = mp.parse_manifest_file(TEST_MANIFEST_FILE % "trusty")
    assert codename == "trusty"


def test_parse_manifest_codename_xenial():
    (_, codename) = mp.parse_manifest_file(TEST_MANIFEST_FILE % "xenial")
    assert codename == "xenial"


def test_parse_manifest_codename_bionic():
    (_, codename) = mp.parse_manifest_file(TEST_MANIFEST_FILE % "bionic")
    assert codename == "bionic"


def test_parse_manifest_codename_focal():
    (_, codename) = mp.parse_manifest_file(TEST_MANIFEST_FILE % "focal")
    assert codename == "focal"


def test_parse_manifest_codename_groovy():
    (_, codename) = mp.parse_manifest_file(TEST_MANIFEST_FILE % "groovy")
    assert codename == "groovy"


def test_parse_manifest_codename_failure():
    with pytest.raises(Exception):
        (_, codename) = mp.parse_manifest_file(TEST_MANIFEST_FILE % "disco")


def test_parse_manifest_codename_missing_key_package():
    with pytest.raises(Exception):
        (_, codename) = mp.parse_manifest_file("/dev/null")


def test_nonexistant_file():
    with pytest.raises(Exception):
        (pkgs, codename) = mp.parse_manifest_file("tests/assets/noexist")
