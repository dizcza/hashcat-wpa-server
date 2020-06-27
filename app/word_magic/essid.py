import re
from itertools import permutations

import wordninja

MAX_COMPOUNDS = 8  # max compounds for rule best64 attack
MAX_COMPOUNDS_DIGITS_APPEND = 7  # max compounds for digits_append attack


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


def word_compounds(word: str, min_length=2):
    return [compound for compound in wordninja.split(word) if len(compound) >= min_length]


def word_compounds_permutation(word: str, max_compounds=MAX_COMPOUNDS, min_length=2, alpha_only=False):
    """
    catonsofa -> cat, on, sofa
    """
    compounds = word_compounds(word, min_length=min_length)
    if alpha_only:
        compounds = filter(re.compile("[a-z]", flags=re.IGNORECASE).match, compounds)
    compounds = sorted(compounds, key=len, reverse=True)[:max_compounds]
    compounds_perm = list(compounds)
    for r in range(2, len(compounds) + 1):
        compounds_perm.extend(map(''.join, permutations(compounds, r)))
    return compounds_perm


def collect_essid_parts(essid_origin: str, max_compounds=MAX_COMPOUNDS):
    def modify_case(word: str):
        return {word, word.lower(), word.upper(), word.capitalize(), word.lower().capitalize()}

    regex_non_char = re.compile('[^a-zA-Z]')
    essid_parts = {essid_origin}
    essid_parts.add(re.sub(r'\W+', '', essid_origin))
    essid_parts.add(re.sub('[^a-z]+', '', essid_origin, flags=re.IGNORECASE))
    essid_parts.update(word_compounds_permutation(essid_origin, max_compounds=max_compounds))
    regex_split_parts = regex_non_char.split(essid_origin)
    regex_split_parts = list(filter(len, regex_split_parts))

    for word in regex_split_parts:
        essid_parts.update(word_compounds_permutation(word, max_compounds=max_compounds))
        essid_parts.update(word_compounds_permutation(word.lower(), max_compounds=max_compounds))

    essid_parts.update(regex_split_parts)
    essid_parts.update(split_uppercase(essid_origin))
    for essid in list(essid_parts):
        essid = regex_non_char.sub('', essid)
        essid_parts.update(modify_case(essid))
    essid_parts.update(modify_case(essid_origin))
    essid_parts = set(word for word in essid_parts if len(word) > 1)
    essid_parts.update(modify_case(essid_origin))  # special case when ESSID is a single letter
    return essid_parts


if __name__ == '__main__':
    for essid in ["Tanya007", "My_rabbit", "Myrabbit", "MyRabbit", "PetitCafe2017"]:
        compounds = sorted(word_compounds_permutation(essid))
        candidates = sorted(collect_essid_parts(essid))
        print(f"'{essid}'\n\t{len(compounds)} compounds: {compounds}")
        print(f"\t{len(candidates)} candidates: {candidates}")
