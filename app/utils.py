# encoding=utf-8

import datetime
import os
import subprocess
from urllib.parse import urlparse, urljoin

from flask import request

from app import lock_app
from app.config import Config, BENCHMARK_FILE
from app.domain import Rule, WordList, Benchmark

DATE_FORMAT = "%Y-%m-%d %H:%M"


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


def read_plain_key(key_path) -> str:
    with open(key_path) as f:
        lines = f.readlines()
    found_keys = set()
    for hashcat_key in lines:
        parts = hashcat_key.split(':')
        if len(parts) != 5:
            # failed to extract essid:key
            found_keys.add(hashcat_key)
        essid, key = parts[3], parts[4]
        found_keys.add("{essid}:{key}".format(essid=essid, key=key))
    return ', '.join(found_keys)


def date_formatted() -> str:
    return datetime.datetime.now().strftime(DATE_FORMAT)


def str_to_date(date_str: str) -> datetime.datetime:
    return datetime.datetime.strptime(date_str, DATE_FORMAT)


def with_suffix(path: str, suffix: str) -> str:
    # todo use pathlib
    base = os.path.splitext(os.path.basename(path))[0]
    new_file = os.path.join(os.path.dirname(path), "{}.{}".format(base, suffix))
    return new_file


def is_mime_valid(file_path: str) -> bool:
    if not os.path.exists(file_path):
        return False
    with open(file_path, 'rb') as f:
        data = f.read()
    return data.startswith(Config.CAPTURE_MIME)


def read_last_benchmark():
    if not os.path.exists(BENCHMARK_FILE):
        return Benchmark(date="(Never)", speed=0)
    with lock_app, open(BENCHMARK_FILE) as f:
        last_line = f.readlines()[-1]
    date_str, speed = last_line.rstrip().split(',')
    return Benchmark(date=date_str, speed=speed)
