import collections
import itertools
import string
from datetime import date
from enum import Enum, unique
from pathlib import Path
from typing import Union, Iterable

from dateutil.rrule import rrule, DAILY

from app.config import WORDLISTS_DIR
from app.logger import logger

DIGITS_DIR = Path(__file__).parent
WORDLISTS_DIR.mkdir(exist_ok=True)

LETTER_ALPHABETS = (string.ascii_lowercase, string.ascii_uppercase, 'zxcvbnm', 'asdfghjkl', 'qwertyuiop')


@unique
class Mask(Enum):
    MASK_1 = "mask_1-4.txt"
    MASK_5 = "mask_5-7.txt"
    MASK_8 = "mask_8-12.txt"

    @property
    def path(self):
        return DIGITS_DIR / self.value


def all_unique(passwords) -> bool:
    return len(set(passwords)) == len(passwords)


def create_days(flashback_years: int, date_fmt=("%m%d%Y", "%d%m%Y", "%Y%m%d", "%Y%d%m")) -> list:
    end_day = date.today()
    start_day = date(end_day.year - flashback_years, end_day.month, end_day.day)
    days = set()
    for date_formatted in date_fmt:
        for dt in rrule(DAILY, dtstart=start_day, until=end_day):
            days.add(dt.strftime(date_formatted))
    return sorted(days)


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
    logger.debug(f"Wrote {digits_count} digits to {path_to}")


def generate_mask_stdout(mask_len: int, pattern_len: int):
    # for debugging purpose
    assert pattern_len <= len(string.ascii_lowercase), "Too large pattern length"
    pattern = string.ascii_lowercase[:pattern_len]
    for mask in itertools.product(pattern, repeat=mask_len):
        counts = list(collections.Counter(mask).values())
        max_count = max(counts)
        diffs = list(max_count - count for count in counts)
        if all(diff <= 1 for diff in diffs):
            print(''.join(mask))


def create_digits_8(flashback_years=100, cycle_length_max=20):
    digits_wordlist_path = WORDLISTS_DIR / "digits_8.txt"
    digits = create_days(flashback_years)
    masks = read_mask(Mask.MASK_8.path)
    digits.extend(create_digits_mask(masks, alphabet=string.digits, alphabet_size_max=4))
    for alphabet in LETTER_ALPHABETS:
        digits.extend(create_digits_mask(masks, alphabet=alphabet, alphabet_size_max=2))
    for password_length in range(8, cycle_length_max + 1):
        digits.extend(create_digits_cycle(password_length))
    write_digits(digits, digits_wordlist_path)


def create_digits_append(flashback_years=100, cycle_length_max=4):
    """
    2019          year
    19            year[-2:]
    1503          %d%m
    0315          %m%d
    mask_1-4.txt  digits only
    234567890     digits cycle (left and right)
    """
    digits_wordlist_path = WORDLISTS_DIR / "digits_append.txt"
    digits = set()
    curr_year = date.today().year
    for year in range(curr_year, curr_year - flashback_years - 1, -1):
        year = str(year)
        digits.add(year)
        digits.add(year[-2:])
    digits.update(create_days(flashback_years=1, date_fmt=('%m%d', '%d%m')))
    masks = read_mask(Mask.MASK_1.path)
    digits.update(create_digits_mask(masks, alphabet=string.digits, alphabet_size_max=2))
    for password_length in range(1, max(cycle_length_max, 10) + 1):
        digits.update(create_digits_cycle(password_length))
    write_digits(digits, digits_wordlist_path)


def create_digits_short(flashback_years=50, cycle_length_max=10):
    digits = set()
    digits_wordlist_path = WORDLISTS_DIR / "digits_short.txt"
    masks = read_mask(Mask.MASK_8.path)
    digits.update(create_digits_mask(masks, alphabet=string.digits, alphabet_size_max=3))
    for alphabet in LETTER_ALPHABETS:
        digits.update(create_digits_mask(masks, alphabet=alphabet, alphabet_size_max=1))
    for password_length in range(8, cycle_length_max + 1):
        digits.update(create_digits_cycle(password_length))
    digits.update(create_days(flashback_years, date_fmt=("%d%m%Y",)))
    write_digits(digits, digits_wordlist_path)


def create_digits_wordlist():
    create_digits_8()
    create_digits_append()
    create_digits_short()


if __name__ == '__main__':
    create_digits_wordlist()
