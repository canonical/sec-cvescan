import bz2
import os

import pycurl

from cvescan.errors import BZ2Error, DownloadError


def download(download_url, filename):
    try:
        with open(filename, "wb") as target_file:
            curl = pycurl.Curl()
            curl.setopt(pycurl.URL, download_url)
            curl.setopt(pycurl.WRITEDATA, target_file)
            curl.perform()
            curl.close()
    except Exception as ex:
        raise DownloadError("Downloading %s failed: %s" % (download_url, ex))


def bz2decompress(bz2_archive, target):
    try:
        with open(bz2_archive, "rb") as archive:
            with open(target, "wb") as target:
                target.write(bz2.decompress(archive.read()))
    except Exception as ex:
        raise BZ2Error("Decompressing %s to %s failed: %s", (bz2_archive, target, ex))


def download_bz2_file(logger, base_url, zip_file, destination_file):
    logger.debug("Downloading %s/%s" % (base_url, zip_file))
    download(os.path.join(base_url, zip_file), zip_file)

    logger.debug("Unzipping %s" % zip_file)
    bz2decompress(zip_file, destination_file)
