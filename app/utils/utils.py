import datetime
import subprocess
from functools import wraps
from typing import List
from urllib.parse import urlparse, urljoin

from flask import request

from app.logger import logger
from app.utils.nvidia_smi import NvidiaSmi


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


def date_formatted() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")


def wrap_render_template(render_template):
    @wraps(render_template)
    def wrapper(*args, **kwargs):
        kwargs.update(gpus=NvidiaSmi.get_gpus())
        return render_template(*args, **kwargs)
    return wrapper
