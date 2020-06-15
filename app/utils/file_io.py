import hashlib
from pathlib import Path
import secrets

from app import lock_app
from app.logger import logger
from app.config import BENCHMARK_FILE, HASHCAT_BRAIN_PASSWORD_PATH
from app.domain import Benchmark, InvalidFileError


def read_plain_key(key_path):
    key_path = Path(key_path)
    if not key_path.exists():
        return None
    with open(key_path) as f:
        lines = f.read().splitlines()
    found_keys = set()
    for line in lines:
        essid, key = line.split(':')[-2:]
        found_keys.add("{essid}:{key}".format(essid=essid, key=key))
    if not found_keys:
        return None
    return ', '.join(found_keys)


def read_last_benchmark():
    if not BENCHMARK_FILE.exists():
        return Benchmark(date="(Never)", speed=0)
    with lock_app, open(BENCHMARK_FILE) as f:
        last_line = f.read().splitlines()[-1]
    date_str, speed = last_line.split(',')
    return Benchmark(date=date_str, speed=speed)


def read_hashcat_brain_password():
    if not HASHCAT_BRAIN_PASSWORD_PATH.exists():
        logger.error("Hashcat brain password file does not exist. Generating a random password.")
        HASHCAT_BRAIN_PASSWORD_PATH.write_text(secrets.token_hex(16))
    with open(HASHCAT_BRAIN_PASSWORD_PATH) as f:
        brain_password = f.readline().rstrip()
    return brain_password


def bssid_essid_from_22000(file_22000):
    if not Path(file_22000).exists():
        raise FileNotFoundError(file_22000)
    with open(file_22000) as f:
        lines = f.read().splitlines()
    bssid_essids = set()
    for line in lines:
        info_split = line.split('*')
        if len(info_split) == 0:
            raise InvalidFileError("Not a 22000 file")
        bssid = info_split[3]
        essid = info_split[5]  # in hex format
        bssid_essids.add(f"{bssid}:{essid}")
    return iter(bssid_essids)


def check_file_22000(file_22000):
    file_22000 = Path(file_22000)
    if file_22000.suffix != ".22000":
        raise InvalidFileError(f"Invalid capture file format: '{file_22000.suffix}'. Expected 22000.")


def calculate_md5(fpath, chunk_size=1024 * 1024):
    md5 = hashlib.md5()
    with open(fpath, 'rb') as f:
        for chunk in iter(lambda: f.read(chunk_size), b''):
            md5.update(chunk)
    return md5.hexdigest()
