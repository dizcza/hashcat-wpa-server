import datetime
import threading
import time
from collections import namedtuple
from enum import Enum, unique
from pathlib import Path
from typing import Union

from app.config import WORDLISTS_DIR, RULES_DIR, MASKS_DIR

NONE_STR = str(None)
Benchmark = namedtuple('Benchmark', ('date', 'speed'))


class InvalidFileError(Exception):
    # self-explanatory error
    pass


class Rule(Enum):
    BEST_64 = "best64.rule"
    ESSID = "essid.rule"

    @property
    def path(self):
        return RULES_DIR / self.value

    @staticmethod
    def to_form():
        # (id_value, description) pairs
        choices = [(NONE_STR, "(None)")]
        for path in sorted(RULES_DIR.iterdir()):
            # Essid rule is used in attack_essid only
            if path.name != Rule.ESSID:
                choices.append((path.name, path.name))
        return tuple(choices)

    @staticmethod
    def from_data(name: str):
        if name in (None, NONE_STR):
            return None
        return Rule(name)


@unique
class WordList(Enum):
    TOP109M = "Top109Million-probable-v2.txt"
    TOP29M = "Top29Million-probable-v2.txt"
    TOP1M = "Top1pt6Million-probable-v2.txt"
    TOP304K = "Top304Thousand-probable-v2.txt"
    TOP1K_RULE_BEST64 = "Top1575-probable-v2-rule-best64.txt"
    TOP1K = "Top1575-probable-v2.txt"
    DIGITS_8 = "digits_8.txt"
    DIGITS_APPEND = "digits_append.txt"
    DIGITS_APPEND_SHORT = "digits_append_short.txt"
    KEYBOARD_WALK = "keyboard-walk.txt"
    NAMES_UA_RU = "names_ua-ru.txt"
    NAMES_RU_CYRILLIC = "names_ru-cyrrilic.txt"
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


@unique
class BrainClientFeature(Enum):
    PASSWORDS = "1"
    POSITIONS = "2"
    PASSWORDS_AND_POSITIONS = "3"

    @staticmethod
    def to_form():
        # (id_value, description) pairs
        choices = (
            (BrainClientFeature.PASSWORDS.value, "Store tried passwords"),
            (BrainClientFeature.POSITIONS.value, "Store wordlist attack positions"),
            (BrainClientFeature.PASSWORDS_AND_POSITIONS.value, "Store tried passwords and attack positions"),
        )
        return choices


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

    @staticmethod
    def to_form():
        # (id_value, description) pairs
        choices = tuple((wl.value, wl.name) for wl in Workload)
        return choices


class TaskInfoStatus:
    SCHEDULED = "Scheduled"  # added to the tasks queue
    RUNNING = "Running"  # started execution
    COMPLETED = "Completed"  # all attacks run
    CANCELLED = "Cancelled"  # user cancelled
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
        self._start_time = time.time()

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

    @property
    def duration(self):
        duration = int(time.time() - self._start_time)
        duration = datetime.timedelta(seconds=duration)
        return duration

    def update_dict(self):
        return dict(found_key=self.found_key, duration=self.duration, completed=self.completed,
                    status=self.status)

    def __enter__(self):
        self._lock.acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._lock.release()
