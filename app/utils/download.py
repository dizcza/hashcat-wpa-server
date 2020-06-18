from collections import namedtuple

from app import lock_app
from app.logger import logger
from app.domain import WordList
from app.utils.file_io import calculate_md5
from app.utils.utils import subprocess_call

WordListUrl = namedtuple('WordListUrl', ('url', 'rate', 'checksum'))


WORDLIST_URLS = {
    WordList.TOP109M: WordListUrl("https://download.weakpass.com/wordlists/1852/Top109Million-probable-v2.txt.gz", rate=39, checksum="c0a26fd763d56a753a5f62c517796d09"),
    WordList.TOP29M: WordListUrl("https://download.weakpass.com/wordlists/1857/Top29Million-probable-v2.txt.gz", rate=30, checksum="4d86278a7946fe9ad7016440e85ff2b6"),
    WordList.TOP1M: WordListUrl("https://download.weakpass.com/wordlists/1855/Top1pt6Million-probable-v2.txt.gz", rate=19, checksum="2d45c4aa9f4a87ece9ebcbd542613f50"),
    WordList.TOP304K: WordListUrl("https://download.weakpass.com/wordlists/1859/Top304Thousand-probable-v2.txt.gz", rate=12, checksum="f99e6a581597cbdc76efc1bcc001a9ed"),
}


def get_wordlist_rate(wordlist: WordList):
    if wordlist not in WORDLIST_URLS:
        return None
    return WORDLIST_URLS[wordlist].rate


def download_wordlist(wordlist: WordList):
    if wordlist is None:
        return
    if wordlist.path.exists():
        return
    if wordlist not in WORDLIST_URLS:
        return
    url, rate, checksum = WORDLIST_URLS[wordlist]
    gzip_file = url.split('/')[-1]
    gzip_file = wordlist.path.with_name(gzip_file)
    logger.debug(f"Downloading {gzip_file}")
    while calculate_md5(gzip_file) != checksum:
        subprocess_call(['wget', url, '-O', gzip_file])
    with lock_app:
        subprocess_call(['gzip', '-d', gzip_file])
    logger.debug(f"Downloaded and extracted {wordlist.path}")
