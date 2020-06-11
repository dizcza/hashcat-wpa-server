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
from app.config import BENCHMARK_FILE
from app.domain import Benchmark, InvalidFileError
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


def bssid_essid_from_22000(file_22000):
    if not Path(file_22000).exists():
        raise FileNotFoundError(file_22000)
    with open(file_22000) as f:
        lines = f.readlines()
    bssid_essids = set()
    for line in lines:
        info_split = line.split('*')
        if len(info_split) == 0:
            raise InvalidFileError("Not a 22000 file")
        bssid = info_split[3]
        essid = info_split[5]  # in hex format
        bssid_essids.add(f"{bssid}:{essid}")
    return iter(bssid_essids)
