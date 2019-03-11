import re

import splitter

from app.config import ESSID_TRIED


def split_uppercase(word: str) -> set:
    """
    EverGreen -> Ever, Green
    """
    pos_upper = [pos for pos, letter in enumerate(word) if letter.isupper()]
    pos_upper.append(len(word))
    simple_words = set([])
    for left, right in zip(pos_upper[:-1], pos_upper[1:]):
        simple_words.add(word[left: right])
    return simple_words


def split_word_compounds(word: str):
    """
    catonsofa -> cat, on, sofa
    """
    compounds = splitter.split(word)
    compounds_merged = list(compounds)
    for start in range(len(compounds)):
        for end in range(start + 1, len(compounds)):
            merged_part = ''.join(compounds[start: end + 1])
            compounds_merged.append(merged_part)
    return compounds_merged


def collect_essid_parts(essid_origin: str):
    def modify_case(word: str):
        return {word, word.lower(), word.upper(), word.capitalize(), word.lower().capitalize()}

    regex_non_char = re.compile('[^a-zA-Z]')
    essid_parts = {essid_origin}
    regex_split_parts = regex_non_char.split(essid_origin)
    regex_split_parts = list(filter(len, regex_split_parts))

    for word in regex_split_parts:
        essid_parts.update(split_word_compounds(word))
        essid_parts.update(split_word_compounds(word.lower()))

    essid_parts.update(regex_split_parts)
    essid_parts.update(split_uppercase(essid_origin))
    essids_case_insensitive = set()
    for essid in essid_parts:
        essid = regex_non_char.sub('', essid)
        essids_case_insensitive.update(modify_case(essid))
    essids_case_insensitive.update(modify_case(essid_origin))
    essids_case_insensitive = set(word for word in essids_case_insensitive if len(word) > 1)
    essids_case_insensitive.update(modify_case(essid_origin))  # special case when ESSID is a single letter
    return essids_case_insensitive


if __name__ == '__main__':
    with open(ESSID_TRIED) as f:
        data = f.read().splitlines()
    for bssid_essid in data:
        essid = bssid_essid.split(':', maxsplit=1)[1]
        print(f"{essid} compounds: {split_word_compounds(essid)}")
        print(*collect_essid_parts(essid))
        input("Press enter.")
