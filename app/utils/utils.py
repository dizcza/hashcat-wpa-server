import datetime
import subprocess
from typing import List
from urllib.parse import urlparse, urljoin

from flask import request

from app.logger import logger


def subprocess_call(args: List[str]):
    """
    :param args: shell args
    """
    args = list(map(str, args))
    logger.debug(">>> {}".format(' '.join(args)))
    if not all(args):
        raise ValueError(f"Empty arg in {args}")
    completed = subprocess.run(args, universal_newlines=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if completed.stderr or completed.returncode != 0:
        logger.debug(completed.stdout)
        logger.error(completed.stderr)
    return completed.stdout, completed.stderr


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


def date_formatted() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
