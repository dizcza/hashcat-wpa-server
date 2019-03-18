import collections
import itertools
import string
from datetime import date
from enum import Enum, unique
from pathlib import Path
from typing import Union, Iterable

from dateutil.rrule import rrule, DAILY

ROOT_DIR = Path(__file__).parent.parent
WORDLISTS_DIR = ROOT_DIR / "wordlists"
DIGITS_DIR = ROOT_DIR / "digits"

LETTER_ALPHABETS = (string.ascii_lowercase, string.ascii_uppercase, 'zxcvbnm', 'asdfghjkl', 'qwertyuiop')

# prepare
WORDLISTS_DIR.mkdir(exist_ok=True)
VERBOSE = 1


@unique
class Mask(Enum):
    MASK_1 = "mask_1-4.txt"
    MASK_5 = "mask_5-7.txt"
    MASK_8 = "mask_8-12.txt"

    @property
    def path(self):
        return DIGITS_DIR / self.value


def count_digits(digits_generator):
    def decorated(*args, **kwargs):
        digits = digits_generator(*args, **kwargs)
        if VERBOSE:
            print(f"{digits_generator.__name__}: {len(digits)} digits")
        return digits
    return decorated


def all_unique(passwords) -> bool:
    return len(set(passwords)) == len(passwords)


@count_digits
def create_days(flashback_years: int, date_fmt=("%m%d%Y", "%d%m%Y", "%Y%m%d", "%Y%d%m")) -> list:
    end_day = date.today()
    start_day = date(end_day.year - flashback_years, end_day.month, end_day.day)
    days = set()
    for date_formatted in date_fmt:
        for dt in rrule(DAILY, dtstart=start_day, until=end_day):
            days.add(dt.strftime(date_formatted))
    return sorted(days)


@count_digits
def create_digits_mask(masks: Iterable, alphabet=string.digits, alphabet_size_max=4) -> list:
    digits = []

    def convert(pattern: str, alphabet_mask: Iterable[str], code: Iterable[str]):
        mask_to_code = dict(zip(alphabet_mask, code))
        pattern_decoded = []
        for char_mask in pattern:
            pattern_decoded.append(mask_to_code[char_mask])
        return ''.join(pattern_decoded)

    for pattern in masks:
        alphabet_mask = sorted(set(pattern))
        alphabet_mask_size = len(alphabet_mask)
        if len(alphabet_mask) > alphabet_size_max:
            # only ascending order: 11223344
            for start in range(len(alphabet) + 1 - alphabet_mask_size):
                code = alphabet[start: start+alphabet_mask_size]
                sample = convert(pattern, alphabet_mask, code)
                digits.append(sample)
        else:
            for digits_perm in itertools.permutations(alphabet, alphabet_mask_size):
                sample = convert(pattern, alphabet_mask, code=digits_perm)
                digits.append(sample)
    assert all_unique(digits)
    return digits


@count_digits
def create_digits_cycle(password_length: int) -> list:
    digits = []
    for start in range(10):
        ascending = ''.join(str(d % 10) for d in range(start, start+password_length))
        digits.append(ascending)
        if password_length > 1:
            descending = ascending[::-1]
            digits.append(descending)
    assert all_unique(digits)
    return digits


def read_mask(mask_path: str) -> list:
    with open(mask_path) as f:
        lines = f.readlines()
    lines = [line.rstrip('\n') for line in lines]
    lines = filter(len, lines)
    lines = filter(lambda line: not line.startswith('#'), lines)
    return list(lines)


def write_digits(digits: Union[set, list], path_to: str):
    digits_count = len(digits)
    digits = '\n'.join(digits)
    with open(path_to, 'w') as f:
        f.write(digits)
    print(f"Wrote {digits_count} digits to {path_to}")


def generate_mask(mask_len: int, pattern_len: int):
    assert pattern_len <= len(string.ascii_lowercase), "Too large pattern length"
    pattern = string.ascii_lowercase[:pattern_len]
    for mask in itertools.product(pattern, repeat=mask_len):
        counts = list(collections.Counter(mask).values())
        max_count = max(counts)
        diffs = list(max_count - count for count in counts)
        if all(diff <= 1 for diff in diffs):
            print(''.join(mask))


def set_verbose(verbose: int):
    global VERBOSE
    VERBOSE = verbose
