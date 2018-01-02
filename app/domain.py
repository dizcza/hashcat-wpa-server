import os
from enum import Enum, unique
from typing import Optional


@unique
class Rule(Enum):
    BEST_64 = "best64.rule"

    def get_path(self):
        return os.path.join("rules", self.value)


@unique
class WordList(Enum):
    ROCKYOU = "rockyou.txt"
    PHPBB = "phpbb.txt"
    CONFICKER = "conficker.txt"
    JOHN = "john.txt"
    DIGITS_8 = "digits_8.txt"
    DIGITS_APPEND = "digits_append.txt"
    ESSID = "essid.txt"

    def get_path(self):
        return os.path.join("wordlists", self.value)


class UploadForm(object):
    def __init__(self, capture_path: str, wordlist: WordList, rule: Optional[Rule], timeout_seconds: int):
        self.capture_path = capture_path
        self.wordlist = wordlist
        self.rule = rule
        self.timeout_seconds = timeout_seconds
