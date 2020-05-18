import hashlib
import tempfile

import pycurl
import pytest

import cvescan.downloader as downloader
from cvescan.errors import BZ2Error, DownloadError


class MockCurl:
    def setopt(*args, **kwargs):
        pass

    def perform(self):
        pass

    def close(self):
        raise Exception("test")


def hash_file(filename):
    file_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        contents = f.read()
        file_hash.update(contents)

    return file_hash.hexdigest()


def test_download_raises_download_error(monkeypatch):
    monkeypatch.setattr(pycurl, "Curl", MockCurl)
    with pytest.raises(DownloadError):
        downloader.download("http://test", "/dev/null")


def test_bz2decompress():
    orig_file = "tests/assets/test.txt"
    tmpdir = tempfile.TemporaryDirectory()
    unzipped_file = "%s/unzipped.txt" % tmpdir.name

    downloader.bz2decompress("tests/assets/test.bz2", unzipped_file)

    orig_hash = hash_file(orig_file)
    new_hash = hash_file(unzipped_file)

    assert orig_hash == new_hash


def test_bz2decompress_raises_BZ2Error():
    with pytest.raises(BZ2Error):
        downloader.bz2decompress("tests/assets/nonexistant_file", "")
