# encoding=utf-8

import subprocess
import threading
from urllib.parse import urlparse, urljoin

from flask import request

from app.domain import Rule, WordList


def count_rules(rule: Rule) -> int:
    with open(rule.get_path()) as f:
        rules = f.readlines()
    rules = [line[:-1] for line in rules]
    rules = filter(len, rules)
    rules = filter(lambda line: not line.startswith("#"), rules)
    return len(list(rules))


def count_words(wordlist: WordList) -> int:
    out, err_ignored = subprocess.Popen(["wc", "-l", wordlist.get_path()],
                                        universal_newlines=True,
                                        stdout=subprocess.PIPE).communicate()
    count = int(out.split(' ')[0])
    return count


def split_uppercase(word: str) -> set:
    pos_upper = [pos for pos, letter in enumerate(word) if letter.isupper()]
    pos_upper.append(len(word))
    simple_words = set([])
    for left, right in zip(pos_upper[:-1], pos_upper[1:]):
        simple_words.add(word[left: right])
    return simple_words


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


def log_request(logger):
    str_info = str(request.headers)
    for key in ('REMOTE_ADDR',):
        value = request.environ.get(key)
        str_info += "{}: {}\r\n".format(key, value)
    logger.debug(str_info)


class ProgressLock(object):
    def __init__(self):
        self._lock = threading.RLock()
        self.progress = 0
        self.status = "Running"
        self.key = None
        self.completed = False

    def __enter__(self):
        self._lock.acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._lock.release()
