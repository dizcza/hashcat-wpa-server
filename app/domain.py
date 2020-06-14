import threading
from collections import namedtuple
from enum import Enum, unique
from pathlib import Path
from typing import Union
import datetime

from app.config import WORDLISTS_DIR, RULES_DIR, MASKS_DIR

NONE_ENUM = str(None)
Benchmark = namedtuple('Benchmark', ('date', 'speed'))


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
    KEYBOARD_WALK = "keyboard-walk"
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
        valid = ["cap", "pcap", "pcapng", "hccapx", "pmkid"]
        valid.extend(HashcatMode.valid_modes())
        return valid

    @staticmethod
    def from_suffix(suffix: Union[str, Path]):
        suffix = str(suffix).lstrip('.')
        if suffix not in HashcatMode.valid_suffixes():
            raise ValueError(f"Invalid capture file suffix: '{suffix}'")
        if suffix in ("cap", "pcap"):
            raise ValueError(f"Convert '{suffix}' to hccapx/2500 file with "
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
    COMPLETED = "Completed"  # all attacks run
    CANCELLED = "Cancelled"  # user cancelled
    REJECTED = "Rejected"  # invalid request
    ABORTED = "Aborted"  # task was interrupted due to server issues


class ProgressLock:
    def __init__(self, task_id: int):
        self.task_id = task_id
        self._lock = threading.RLock()
        self.future = None  # will be set next
        self.progress = 0
        self.status = TaskInfoStatus.SCHEDULED
        self.found_key = None
        self.cancelled = False  # needed in hashcat_cmd.run_with_status()
        self.completed = False  # checked in /progress
        self._start_time = datetime.datetime.now()

    def set_status(self, status):
        self.status = status

    def cancel(self):
        # cancellation will delete this lock from a pool of locks in HashcatWorker
        self.cancelled = self.completed = True
        self.set_status(TaskInfoStatus.CANCELLED)
        if self.future is None:
            return False
        if self.future.cancelled():
            return True
        return self.future.cancel()

    def finish(self):
        # called after the completion or cancellation
        self.completed = True
        self.progress = 100

    def update_dict(self):
        duration = datetime.datetime.now() - self._start_time
        return dict(found_key=self.found_key, duration=duration, completed=self.completed,
                    status=self.status)

    def __enter__(self):
        self._lock.acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._lock.release()
