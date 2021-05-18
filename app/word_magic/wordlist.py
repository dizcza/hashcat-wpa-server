import datetime
import re
from copy import deepcopy
from functools import lru_cache, wraps
from pathlib import Path
from threading import RLock
import shutil

from app import lock_app
from app.attack.hashcat_cmd import HashcatCmdStdout
from app.config import WORDLISTS_USER_DIR, WORDLISTS_DIR
from app.domain import WordListDefault, Rule, NONE_STR
from app.logger import logger
from app.utils import subprocess_call
from app.utils.file_io import calculate_md5, read_last_benchmark
from app.word_magic.digits.create_digits import read_mask


class WordList:
    fast_count = 700_000

    def __init__(self, path, rate=None, count=None, url=None, checksum=None):
        self.path = path
        self.rate = rate
        self.count = count
        self.url = url
        self.checksum = checksum
        self.update_count()

    def update_count(self):
        if self.custom:
            self.count = count_wordlist(self.path)

    @property
    def name(self):
        if self.custom:
            return f"user/{self.path.name}"
        return self.path.name

    @property
    def custom(self) -> bool:
        return str(self.path).startswith(str(WORDLISTS_USER_DIR))

    def __str__(self):
        extra = ""
        if self.rate is not None:
            extra = f"rate={self.rate}"
        if self.url is not None and not self.path.exists():
            extra = f"{extra}; requires downloading"
        if extra:
            return f"{self.name} [{extra}]"
        return self.name

    def download(self):
        if self.path is None or self.path.exists():
            return
        if self.url is None:
            return
        gzip_file = self.url.split('/')[-1]
        gzip_file = self.path.with_name(gzip_file)
        logger.debug(f"Downloading {gzip_file}")
        if calculate_md5(gzip_file) != self.checksum:
            subprocess_call(['wget', '-q', self.url, '-O', gzip_file])
        with lock_app:
            subprocess_call(['gzip', '-d', gzip_file])
        # the format of a gzip file is name.txt.gz
        txt_path = gzip_file.parent / gzip_file.stem
        shutil.move(txt_path, self.path)
        logger.debug(f"Downloaded and extracted {self.path}")


WORDLISTS_AVAILABLE = [
    WordList(
        path=WordListDefault.TOP109M.path,
        rate=39,
        count=109_438_614,
        url="https://download.weakpass.com/wordlists/1852/Top109Million-probable-v2.txt.gz",
        checksum="c0a26fd763d56a753a5f62c517796d09"
    ),
    WordList(
        path=WordListDefault.TOP29M.path,
        rate=30,
        count=29_040_646,
        url="https://download.weakpass.com/wordlists/1857/Top29Million-probable-v2.txt.gz",
        checksum="807ee2cf835660b474b6fd15bca962cf"
    ),
    WordList(
        path=WordListDefault.TOP1M.path,
        rate=19,
        count=1_667_462,
        url="https://download.weakpass.com/wordlists/1855/Top1pt6Million-probable-v2.txt.gz",
        checksum="2d45c4aa9f4a87ece9ebcbd542613f50"
    ),
    WordList(
        path=WordListDefault.TOP304K.path,
        rate=12,
        count=303_872,
        url="https://download.weakpass.com/wordlists/1859/Top304Thousand-probable-v2.txt.gz",
        checksum="f99e6a581597cbdc76efc1bcc001a9ed"
    ),
]

wlock = RLock()


def with_lock(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        with wlock:
            res = func(*args, **kwargs)
        return res

    return decorated


def download_wordlist(wordlist_path: Path):
    wordlist = find_wordlist_by_path(wordlist_path)
    if wordlist is None:
        # fast mode or does not exist
        return
    wordlist.download()


@lru_cache(maxsize=4)
def count_rules(rule: Rule):
    # counts the multiplier
    if rule is None:
        return 1
    rules = read_mask(rule.path)
    return len(rules)


def count_wordlist(wordlist_path):
    wordlist_path = str(wordlist_path)
    out, err = subprocess_call(['wc', '-l', wordlist_path])
    out = out.rstrip('\n')
    counter = 0
    if re.fullmatch(f"\d+ {wordlist_path}", out):
        counter, path = out.split(' ')
    return int(counter)


def estimate_runtime_fmt(wordlist_path: Path, rule: Rule) -> str:
    speed = int(read_last_benchmark().speed)
    if speed == 0:
        return "unknown"

    n_words = 0
    if wordlist_path == NONE_STR:
        wordlist_path = None
    if wordlist_path is not None:
        wordlist = find_wordlist_by_path(wordlist_path)
        if wordlist is None:
            return "unknown"
        n_words += wordlist.count

    n_candidates = n_words * count_rules(rule)

    # add extra words to account for the 'fast' run, which includes
    # 160k digits8, 120k top1k+best64 and ESSID manipulation
    # (300k hamming ball, 70k digits append mask)
    n_candidates += WordList.fast_count

    runtime = int(n_candidates / speed)  # in seconds
    runtime_ftm = str(datetime.timedelta(seconds=runtime))
    return runtime_ftm


def create_fast_wordlists():
    # note that dumping all combinations in a file is not equivalent to
    # directly adding top1k wordlist and best64 rule because hashcat ignores
    # patterns that are <8 chars _before_ expanding a candidate with the rule.
    if not WordListDefault.TOP1K_RULE_BEST64.path.exists():
        # it should be already created in a docker
        logger.warning(f"{WordListDefault.TOP1K_RULE_BEST64.name} does not exist. Creating")
        top1k_url = "https://download.weakpass.com/wordlists/1854/Top1575-probable2.txt.gz"
        wlist_top1k = WordList(path=WordListDefault.TOP1K.path, url=top1k_url,
                               checksum="070a10f5e7a23f12ec6fc8c8c0ccafe8")
        wlist_top1k.download()
        hashcat_stdout = HashcatCmdStdout(outfile=WordListDefault.TOP1K_RULE_BEST64.path)
        hashcat_stdout.add_wordlists(WordListDefault.TOP1K)
        hashcat_stdout.add_rule(Rule.BEST_64)
        subprocess_call(hashcat_stdout.build())
        with open(WordListDefault.TOP1K_RULE_BEST64.path) as f:
            unique = set(f.readlines())
        with open(WordListDefault.TOP1K_RULE_BEST64.path, 'w') as f:
            f.writelines(unique)


@with_lock
def find_wordlist_by_path(wordlist_path):
    if wordlist_path is None:
        return None
    wordlist_path = Path(wordlist_path)
    for wordlist in WORDLISTS_AVAILABLE:
        if wordlist.path == wordlist_path:
            return deepcopy(wordlist)
    return None


@with_lock
def wordlists_available():
    # return pairs of (id-value, display: str)
    deleted = []
    exist_paths = set()

    for wordlist in filter(lambda wlist: wlist.custom, WORDLISTS_AVAILABLE):
        if wordlist.path.exists():
            exist_paths.add(wordlist.path)
        else:
            deleted.append(wordlist)

    for wordlist in deleted:
        WORDLISTS_AVAILABLE.remove(wordlist)

    WORDLISTS_USER_DIR.mkdir(exist_ok=True)
    for custom_path in sorted(WORDLISTS_USER_DIR.iterdir()):
        if custom_path not in exist_paths:
            wordlist = WordList(path=custom_path)
            WORDLISTS_AVAILABLE.append(wordlist)

    for wordlist in WORDLISTS_AVAILABLE:
        wordlist.update_count()

    choices = [(NONE_STR, "(fast)")]
    choices.extend((str(wlist.path), str(wlist)) for wlist in WORDLISTS_AVAILABLE)

    return choices


if __name__ == '__main__':
    create_fast_wordlists()
