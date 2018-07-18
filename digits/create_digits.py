import itertools
import os
import string
from datetime import date
from typing import Union, Iterable

from dateutil.rrule import rrule, DAILY

LETTER_ALPHABETS = (string.ascii_lowercase, string.ascii_uppercase, 'zxcvbnm', 'asdfghjkl', 'qwertyuiop')


def count_digits(digits_generator):
    def decorated(*args, **kwargs):
        digits = digits_generator(*args, **kwargs)
        print("{}: {} digits".format(digits_generator.__name__, len(digits)))
        return digits
    return decorated


def all_unique(passwords):
    return len(set(passwords)) == len(passwords)


@count_digits
def _create_days(flashback_years: int, date_fmt=("%m%d%Y", "%d%m%Y", "%Y%m%d", "%Y%d%m")) -> list:
    end_day = date.today()
    start_day = date(end_day.year - flashback_years, end_day.month, end_day.day)
    days = set()
    for date_formatted in date_fmt:
        for dt in rrule(DAILY, dtstart=start_day, until=end_day):
            days.add(dt.strftime(date_formatted))
    return sorted(days)


@count_digits
def _create_digits_mask(masks: Iterable, alphabet=string.digits, alphabet_size_max=4) -> list:
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
def _create_digits_cycle(password_length_max: int) -> list:
    digits = []
    for start in range(10):
        for password_length in range(8, password_length_max+1):
            right = [str(d % 10) for d in range(start, start+password_length)]
            left = right[::-1]
            for sample in (right, left):
                sample = ''.join(sample)
                digits.append(sample)
    assert all_unique(digits)
    return digits


def _read_mask(mask_path: str) -> list:
    with open(mask_path) as f:
        lines = f.readlines()
    lines = [line.rstrip('\n') for line in lines]
    lines = filter(len, lines)
    lines = filter(lambda line: not line.startswith('#'), lines)
    return list(lines)


def _save_digits(digits: Union[set, list], path_to: str):
    digits_count = len(digits)
    digits = '\n'.join(digits)
    with open(path_to, 'w') as f:
        f.write(digits)
    print("Wrote {} digits to {}".format(digits_count, path_to))


def create_digits_8(flashback_years=100, password_length_max=20):
    digits_wordlist_path = os.path.join("wordlists", "digits_8.txt")
    digits = _create_days(flashback_years)
    masks = _read_mask(os.path.join("digits", "mask_8.txt"))
    digits.extend(_create_digits_mask(masks, alphabet=string.digits, alphabet_size_max=4))
    for alphabet in LETTER_ALPHABETS:
        digits.extend(_create_digits_mask(masks, alphabet=alphabet, alphabet_size_max=2))
    digits.extend(_create_digits_cycle(password_length_max))
    _save_digits(digits, digits_wordlist_path)


def create_digits_append(flashback_years=50):
    digits_wordlist_path = os.path.join("wordlists", "digits_append.txt")
    digits = set()
    curr_year = date.today().year
    for year in range(curr_year, curr_year-flashback_years-1, -1):
        year = str(year)
        digits.add(year)
        digits.add(year[-2:])
    masks = _read_mask(os.path.join("digits", "mask_append.txt"))
    digits.update(_create_digits_mask(masks, alphabet=string.digits, alphabet_size_max=2))
    for alphabet in LETTER_ALPHABETS:
        digits.update(_create_digits_mask(masks, alphabet=alphabet, alphabet_size_max=1))
    _save_digits(digits, digits_wordlist_path)


def create_digits_mobile(flashback_years=50):
    digits = set()
    digits_wordlist_path = os.path.join("wordlists", "digits_mobile.txt")
    masks = _read_mask(os.path.join("digits", "mask_8.txt"))
    digits.update(_create_digits_mask(masks, alphabet=string.digits, alphabet_size_max=3))
    for alphabet in LETTER_ALPHABETS:
        digits.update(_create_digits_mask(masks, alphabet=alphabet, alphabet_size_max=1))
    digits.update(_create_digits_cycle(password_length_max=10))
    digits.update(_create_days(flashback_years, date_fmt=("%d%m%Y",)))
    with open(os.path.join('wordlists', 'top4k.txt')) as f:
        weak = f.read().splitlines()
        weak = filter(lambda password: len(password) >= 8, weak)
        digits.update(weak)
    _save_digits(digits, digits_wordlist_path)


if __name__ == '__main__':
    create_digits_8()
    create_digits_append()
    create_digits_mobile()
