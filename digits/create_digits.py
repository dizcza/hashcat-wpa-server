import string
from datetime import date

from digits.common import create_days, create_digits_cycle, create_digits_mask, read_mask, write_digits, \
    LETTER_ALPHABETS, WORDLISTS_DIR, Mask


def create_digits_8(flashback_years=100, cycle_length_max=20):
    digits_wordlist_path = WORDLISTS_DIR / "digits_8.txt"
    digits = create_days(flashback_years)
    masks = read_mask(Mask.MASK_8.path)
    digits.extend(create_digits_mask(masks, alphabet=string.digits, alphabet_size_max=4))
    for alphabet in LETTER_ALPHABETS:
        digits.extend(create_digits_mask(masks, alphabet=alphabet, alphabet_size_max=2))
    for password_length in range(8, cycle_length_max+1):
        digits.extend(create_digits_cycle(password_length))
    write_digits(digits, digits_wordlist_path)


def create_digits_append(flashback_years=50, cycle_length_max=4):
    digits_wordlist_path = WORDLISTS_DIR / "digits_append.txt"
    digits = set()
    curr_year = date.today().year
    for year in range(curr_year, curr_year-flashback_years-1, -1):
        year = str(year)
        digits.add(year)
        digits.add(year[-2:])
    masks = read_mask(Mask.MASK_1.path)
    digits.update(create_digits_mask(masks, alphabet=string.digits, alphabet_size_max=2))
    for password_length in range(1, cycle_length_max+1):
        digits.update(create_digits_cycle(password_length))
    for alphabet in LETTER_ALPHABETS:
        digits.update(create_digits_mask(masks, alphabet=alphabet, alphabet_size_max=1))
    write_digits(digits, digits_wordlist_path)


def create_digits_short(flashback_years=50, cycle_length_max=10):
    digits = set()
    digits_wordlist_path = WORDLISTS_DIR / "digits_short.txt"
    masks = read_mask(Mask.MASK_8.path)
    digits.update(create_digits_mask(masks, alphabet=string.digits, alphabet_size_max=3))
    for alphabet in LETTER_ALPHABETS:
        digits.update(create_digits_mask(masks, alphabet=alphabet, alphabet_size_max=1))
    for password_length in range(8, cycle_length_max+1):
        digits.update(create_digits_cycle(password_length))
    digits.update(create_days(flashback_years, date_fmt=("%d%m%Y",)))
    with open(WORDLISTS_DIR / 'top4k.txt') as f:
        weak = f.read().splitlines()
        weak = filter(lambda password: len(password) >= 8, weak)
        digits.update(weak)
    write_digits(digits, digits_wordlist_path)


if __name__ == '__main__':
    create_digits_8()
    create_digits_append()
    create_digits_short()
