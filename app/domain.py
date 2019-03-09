import threading
from collections import namedtuple
from enum import Enum, unique

from app.config import WORDLISTS_DIR, RULES_DIR, MASKS_DIR

NONE_ENUM = str(None)
Benchmark = namedtuple('Benchmark', ('date', 'speed'))
JobLock = namedtuple('JobLock', ('job_id', 'lock'))


@unique
class Rule(Enum):
    BEST_64 = "best64.rule"

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

    @property
    def path(self):
        return WORDLISTS_DIR / self.value


@unique
class Mask(Enum):
    MOBILE_UA = "mobile.ua"

    @property
    def path(self):
        return MASKS_DIR / self.value


class TaskInfoStatus(object):
    SCHEDULED = "Scheduled"  # added to tasks queue
    COMPETED = "Completed"  # all attacks run
    CANCELED = "Cancelled"  # user cancelled
    REJECTED = "Rejected"  # invalid request
    ABORTED = "Aborted"  # task was interrupted due to server issues


class ProgressLock(object):
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
