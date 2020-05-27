import collections
import logging

import pytest

from cvescan import __main__ as main
from cvescan import manifest_parser as mp

Args = collections.namedtuple("Args", "silent, verbose")


@pytest.fixture
def sys_codename():
    return "bionic"


@pytest.fixture
def sys_pkgs():
    return {"pkg1": "1.1.0-1", "pkg2": "2.2.0-3.1"}


@pytest.fixture(scope="module")
def manifest_data():
    return ({"pkg3": "3.0.1-2", "pkg4": "4.1.1-1"}, "focal")


@pytest.fixture
def patch_manifest_parser(monkeypatch, manifest_data):
    monkeypatch.setattr(mp, "parse_manifest_file", lambda file_path: manifest_data)


def test_set_output_verbosity_info():
    args = Args(silent=False, verbose=False)
    logger = main.set_output_verbosity(args)

    assert logger.level == logging.INFO


def test_set_output_verbosity_silent():
    args = Args(silent=True, verbose=False)
    logger = main.set_output_verbosity(args)
    assert len(logger.handlers) == 1
    assert isinstance(logger.handlers[0], logging.NullHandler)


def test_set_output_verbosity_debug():
    args = Args(silent=False, verbose=True)
    logger = main.set_output_verbosity(args)

    assert logger.level == logging.DEBUG


def test_installed_pkgs_and_codename_no_manifest(
    sys_pkgs, sys_codename,
):
    manifest_file = None
    installed_pkgs, codename = main.get_installed_pkgs_and_codename(
        sys_pkgs, sys_codename, manifest_file
    )

    assert installed_pkgs == sys_pkgs
    assert codename == sys_codename


def test_installed_pkgs_and_codename_with_manifest(
    sys_pkgs, sys_codename, patch_manifest_parser, manifest_data
):
    manifest_file = "/tmp/manifest"
    installed_pkgs, codename = main.get_installed_pkgs_and_codename(
        sys_pkgs, sys_codename, manifest_file
    )

    assert installed_pkgs == manifest_data[0]
    assert codename == manifest_data[1]
