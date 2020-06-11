import threading
from collections import namedtuple
from enum import Enum, unique
from pathlib import Path
from typing import Union

from app.config import WORDLISTS_DIR, RULES_DIR, MASKS_DIR

NONE_ENUM = str(None)
Benchmark = namedtuple('Benchmark', ('date', 'speed'))
JobLock = namedtuple('JobLock', ('job_id', 'lock'))


class InvalidFileError(Exception):
    # self-explanatory error
    pass


@unique
class Rule(Enum):
    BEST_64 = "best64.rule"
    ESSID = "essid.rule"

    @property
    def path(self):
        return RULES_DIR / self.value


@unique
class WordList(Enum):
    ROCKYOU = "rockyou.txt"
    PHPBB = "phpbb.txt"
    DIGITS_8 = "digits_8.txt"
    DIGITS_APPEND = "digits_append.txt"
    TOP1K = "Top1575-probable-v2.txt"
    TOP304K = "Top304Thousand-probable-v2.txt"
    KEYBOARD_WALK_EN = "kwp_en_2-to-10-max-3"
    KEYBOARD_WALK_RU = "kwp_ru_2-to-10-max-3"
    NAMES_UA_RU = "names_ua-ru.txt"
    NAMES_UA_RU_WITH_DIGITS = "names_ua-ru_with_digits.txt"

    @property
    def path(self):
        return WORDLISTS_DIR / self.value


@unique
class Mask(Enum):
    MOBILE_UA = "mobile.ua"

    @property
    def path(self):
        return MASKS_DIR / self.value


class HashcatMode:

    @staticmethod
    def valid_modes():
        return ("2500", "2501", "16800", "16801", "22000", "22001")

    @staticmethod
    def valid_suffixes():
        # valid file suffixes
        valid = ["cap", "pcapng", "hccapx", "pmkid"]
        valid.extend(HashcatMode.valid_modes())
        return valid

    @staticmethod
    def from_suffix(suffix: Union[str, Path]):
        suffix = str(suffix).lstrip('.')
        if suffix not in HashcatMode.valid_suffixes():
            raise ValueError(f"Invalid capture file suffix: '{suffix}'")
        if suffix == "cap":
            raise ValueError("Convert '.cap' to hccapx/2500 file with "
                             "'cap2hccapx' command.")
        if suffix == "pcapng":
            raise ValueError("Convert '.pcapng' to 22000 file with "
                             "'hcxpcapngtool' command.")
        if suffix == "hccapx":
            return "2500"
        if suffix == "pmkid":
            return "16800"
        return suffix


@unique
class Workload(Enum):
    Low = "1"
    Default = "2"
    High = "3"


class TaskInfoStatus:
    SCHEDULED = "Scheduled"  # added to tasks queue
    COMPETED = "Completed"  # all attacks run
    CANCELED = "Cancelled"  # user cancelled
    REJECTED = "Rejected"  # invalid request
    ABORTED = "Aborted"  # task was interrupted due to server issues


class ProgressLock:
    def __init__(self):
        self._lock = threading.RLock()
        self.progress = 0
        self.status = TaskInfoStatus.SCHEDULED
        self.key = None
        self.completed = False
        self.cancelled = False
        self.essid = None
        self.bssid = None

    def cancel(self):
        self.cancelled = True
        self.status = TaskInfoStatus.CANCELED
        return True

    def __enter__(self):
        self._lock.acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._lock.release()
