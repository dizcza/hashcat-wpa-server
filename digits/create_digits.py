import os
from datetime import date
from dateutil.rrule import rrule, DAILY
import itertools
from typing import Union, Iterable


def count_digits(digits_generator):
    def decorated(*args, **kwargs):
        digits = digits_generator(*args, **kwargs)
        print("{}: {} digits".format(digits_generator.__name__, len(digits)))
        return digits
    return decorated


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
def _create_digits_mask(masks: Iterable, alphabet_size_max=5) -> list:
    digits_unique = tuple(range(10))
    digits = []

    def convert(pattern: str, alphabet: Iterable, code: Iterable):
        for (char_from, digit_to) in zip(alphabet, code):
            pattern = pattern.replace(char_from, str(digit_to))
        return pattern

    for pattern in masks:
        if pattern.endswith('1'):
            # try all 100 combinations of (a, b) pairs
            pattern_size = len(pattern) - 1
            formatter = "{:0>%dd}" % pattern_size
            digits.extend(map(formatter.format, range(10 ** pattern_size)))
        else:
            # take only different digits in (a, b) pairs (total 90 pairs)
            alphabet = sorted(set(pattern))
            alphabet_size = len(alphabet)
            if len(alphabet) > alphabet_size_max:
                # only ascending order: 11223344
                for start in range(11-alphabet_size):
                    code = range(start, start+alphabet_size)
                    sample = convert(pattern, alphabet, code)
                    digits.append(sample)
            else:
                for digits_perm in itertools.permutations(digits_unique, alphabet_size):
                    sample = convert(pattern, alphabet, code=digits_perm)
                    digits.append(sample)
    assert len(set(digits)) == len(digits)
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
    assert len(set(digits)) == len(digits)
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
    digits.extend(_create_digits_mask(masks))
    digits.extend(_create_digits_cycle(password_length_max))
    _save_digits(digits, digits_wordlist_path)


def create_digits_append(flashback_years=100):
    digits_wordlist_path = os.path.join("wordlists", "digits_append.txt")
    digits = set([])
    curr_year = date.today().year
    for year in range(curr_year, curr_year-flashback_years-1, -1):
        digits.add(str(year))
    masks = _read_mask(os.path.join("digits", "mask_append.txt"))
    digits.update(_create_digits_mask(masks))
    _save_digits(digits, digits_wordlist_path)


def create_digits_mobile(flashback_years=50):
    digits = []
    digits_wordlist_path = os.path.join("wordlists", "digits_mobile.txt")
    masks = _read_mask(os.path.join("digits", "mask_8.txt"))
    digits.extend(_create_digits_mask(masks, alphabet_size_max=3))
    digits.extend(_create_digits_cycle(password_length_max=10))
    digits.extend(_create_days(flashback_years, date_fmt=("%d%m%Y",)))
    _save_digits(digits, digits_wordlist_path)


if __name__ == '__main__':
    create_digits_8()
    create_digits_append()
    create_digits_mobile()
