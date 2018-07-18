import os
import threading
from enum import Enum, unique
from collections import namedtuple
from app.config import WORDLISTS_DIR, RULES_DIR


NONE_ENUM = str(None)
Benchmark = namedtuple('Benchmark', ('date', 'speed'))
JobLock = namedtuple('JobLock', ('job_id', 'lock'))


@unique
class Rule(Enum):
    BEST_64 = "best64.rule"

    def get_path(self):
        return os.path.join(RULES_DIR, self.value)


@unique
class WordList(Enum):
    ROCKYOU = "rockyou.txt"
    PHPBB = "phpbb.txt"
    DIGITS_8 = "digits_8.txt"
    DIGITS_APPEND = "digits_append.txt"
    TOP4K = "top4k.txt"
    TOP304k = "top304k.txt"
    ESSID = "essid.txt"

    def get_path(self):
        return os.path.join(WORDLISTS_DIR, self.value)


class ProgressLock(object):
    def __init__(self):
        self._lock = threading.RLock()
        self.progress = 0
        self.status = "Scheduled"
        self.key = None
        self.completed = False
        self.cancelled = False

    def cancel(self):
        self.cancelled = True
        self.status = "Cancelled"
        return True

    def __enter__(self):
        self._lock.acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._lock.release()
