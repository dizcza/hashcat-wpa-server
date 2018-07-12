import os
import threading
from enum import Enum, unique
from collections import namedtuple


NONE_ENUM = str(None)
Benchmark = namedtuple('Benchmark', ('date', 'speed'))


@unique
class Rule(Enum):
    BEST_64 = "best64.rule"

    def get_path(self):
        return os.path.join("rules", self.value)


@unique
class WordList(Enum):
    ROCKYOU = "rockyou.txt"
    PHPBB = "phpbb.txt"
    DIGITS_8 = "digits_8.txt"
    DIGITS_APPEND = "digits_append.txt"
    WEAK = "conficker_elitehacker_john_riskypass_top1000.txt"
    ESSID = "essid.txt"

    def get_path(self):
        return os.path.join("wordlists", self.value)


class ProgressLock(object):
    def __init__(self):
        self._lock = threading.RLock()
        self.progress = 0
        self.status = "Scheduled"
        self.key = None

    def __enter__(self):
        self._lock.acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._lock.release()
