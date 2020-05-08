import bz2
from cvescan.errors import BZ2Error, DownloadError
import pycurl

def download(download_url, filename):
    try:
        target_file = open(filename, "wb")
        curl = pycurl.Curl()
        curl.setopt(pycurl.URL, download_url)
        curl.setopt(pycurl.WRITEDATA, target_file)
        curl.perform()
        curl.close()
        target_file.close()
    except Exception as ex:
        raise DownloadError("Downloading %s failed: %s" % (download_url, ex))

def bz2decompress(bz2_archive, target):
    try:
        opened_archive = open(bz2_archive, "rb")
        opened_target = open(target, "wb")
        opened_target.write(bz2.decompress(opened_archive.read()))
        opened_archive.close()
        opened_target.close()
    except Exception as ex:
        raise BZ2Error("Decompressing %s to %s failed: %s", (bz2_archive, target, ex))
