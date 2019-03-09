# encoding=utf-8

import datetime
import subprocess
from functools import wraps
from pathlib import Path
from typing import Union, List
from urllib.parse import urlparse, urljoin

from flask import request

from app import lock_app
from app.app_logger import logger
from app.config import Config, BENCHMARK_FILE
from app.domain import Benchmark
from app.nvidia_smi import NvidiaSmi

DATE_FORMAT = "%Y-%m-%d %H:%M"


def subprocess_call(args: List[str]):
    """
    :param args: shell args
    """
    args = list(map(str, args))
    logger.debug(">>> {}".format(' '.join(args)))
    process = subprocess.Popen(args,
                               universal_newlines=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    out, err = process.communicate()
    return out, err


def wlanhcxinfo(hcap_path: Union[Path, str], mode: str):
    """
    :param hcap_path: .hccapx file path
    :param mode: '-a' list access points
                 '-e' list essid
    :return: access points or essid list
    """
    out, err = subprocess_call(['wlanhcxinfo', '-i', hcap_path, mode])
    out = out.strip('\n')
    out = set(out.split('\n'))
    return out


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


def is_mime_valid(file_path: Union[str, Path]) -> bool:
    file_path = Path(file_path)
    if not file_path.exists():
        return False
    with open(file_path, 'rb') as f:
        data = f.read()
    return data.startswith(Config.CAPTURE_MIME)


def read_last_benchmark():
    if not BENCHMARK_FILE.exists():
        return Benchmark(date="(Never)", speed=0)
    with lock_app, open(BENCHMARK_FILE) as f:
        last_line = f.readlines()[-1]
    date_str, speed = last_line.rstrip().split(',')
    return Benchmark(date=date_str, speed=speed)


def wrap_render_template(render_template):
    @wraps(render_template)
    def wrapper(*args, **kwargs):
        kwargs.update(gpus=NvidiaSmi.get_gpus())
        return render_template(*args, **kwargs)
    return wrapper
