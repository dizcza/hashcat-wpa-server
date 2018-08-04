import collections
import os
import re
import string
import tempfile
from typing import Dict, Set

from digits.common import create_digits_cycle, create_digits_mask, read_mask, write_digits, all_unique, \
    WORDLISTS_DIR, Mask, set_verbose


def read_digits() -> Dict[int, Set[str]]:
    masks_grouped = collections.defaultdict(list)
    digits = {}
    for mask_file in Mask:
        for mask_string in read_mask(mask_file.path):
            masks_grouped[len(mask_string)].append(mask_string)
    for mask_len, _mask_group in masks_grouped.items():
        digits_curr_len = create_digits_mask(masks=_mask_group, alphabet=string.digits, alphabet_size_max=1)
        digits_curr_len = set(digits_curr_len)
        digits_curr_len.update(create_digits_cycle(password_length=mask_len))
        digits[mask_len] = digits_curr_len
    return digits


def create_probable(digit_regex='0', min_occurrences=10):
    top1m_original_path = WORDLISTS_DIR / 'Top1pt6Million-probable-v2.txt'
    digit_compiled = re.compile("[0-9]")
    with tempfile.NamedTemporaryFile(mode='w') as f:
        os.system(f"grep '[0-9]' {top1m_original_path} | grep '[a-zA-Z]' > {f.name}")
        f.seek(0)
        with open(f.name) as f_read:
            top1m_candidates = f_read.read().splitlines()
    matched_lines = collections.defaultdict(list)
    for line_id, line in enumerate(top1m_candidates):
        word_regex = digit_compiled.sub(digit_regex, line)
        matched_lines[word_regex].append(line_id)
    matched_lines = {pattern: line_ids for pattern, line_ids in matched_lines.items()
                     if len(line_ids) >= min_occurrences}

    digits = read_digits()
    max_digit_count = max(digits.keys())
    words_extended = []
    for word_regex in matched_lines.keys():
        digit_count = word_regex.count(digit_regex)
        if digit_count > max_digit_count:
            continue
        for digit_replace in digits[digit_count]:
            digit_replace = iter(digit_replace)
            word_with_digits = []
            for char in word_regex:
                if char == digit_regex:
                    word_with_digits.append(next(digit_replace))
                else:
                    word_with_digits.append(char)
            words_extended.append(''.join(word_with_digits))
    assert all_unique(words_extended)

    words_extended = set(words_extended)
    for original_line_ids in matched_lines.values():
        words_extended.update(top1m_candidates[line_id] for line_id in original_line_ids)
    write_digits(words_extended, path_to=WORDLISTS_DIR / "top1m_with_digits.txt")


if __name__ == '__main__':
    set_verbose(0)
    create_probable()
