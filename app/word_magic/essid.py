import math
import re
import shutil
import tempfile
from itertools import permutations
from pathlib import Path

import wordninja

from app.attack.hashcat_cmd import HashcatCmdStdout
from app.domain import Rule, WordListDefault
from app.logger import logger
from app.utils import subprocess_call
from app.word_magic.wordlist import count_wordlist, count_rules
from app.word_magic.hamming import hamming_ball

MAX_COMPOUNDS = 8  # max compounds for rule best64 attack
MAX_COMPOUNDS_DIGITS_APPEND = 7  # max compounds for digits_append attack


def _split_uppercase(word: str) -> set:
    """
    EverGreen -> Ever, Green
    """
    pos_upper = [pos for pos, letter in enumerate(word) if letter.isupper()]
    pos_upper.append(len(word))
    simple_words = set([])
    for left, right in zip(pos_upper[:-1], pos_upper[1:]):
        simple_words.add(word[left: right])
    return simple_words


def _word_compounds(word: str, min_length=2):
    return [compound for compound in wordninja.split(word) if len(compound) >= min_length]


def _word_compounds_permutation(word: str, max_compounds=MAX_COMPOUNDS, min_length=2, alpha_only=False):
    """
    catonsofa -> cat, on, sofa
    """
    compounds = _word_compounds(word, min_length=min_length)
    if alpha_only:
        compounds = filter(re.compile("[a-z]", flags=re.IGNORECASE).match, compounds)
    compounds = sorted(compounds, key=len, reverse=True)[:max_compounds]
    compounds_perm = list(compounds)
    for r in range(2, len(compounds) + 1):
        compounds_perm.extend(map(''.join, permutations(compounds, r)))
    return compounds_perm


def _collect_essid_parts(essid_origin: str, max_compounds=MAX_COMPOUNDS):
    def modify_case(word: str):
        return {word, word.lower(), word.upper(), word.capitalize(), word.lower().capitalize()}

    regex_non_char = re.compile('[^a-zA-Z]')
    essid_parts = {essid_origin}
    essid_parts.add(re.sub(r'\W+', '', essid_origin))
    essid_parts.add(re.sub('[^a-z]+', '', essid_origin, flags=re.IGNORECASE))
    essid_parts.update(_word_compounds_permutation(essid_origin, max_compounds=max_compounds))
    regex_split_parts = regex_non_char.split(essid_origin)
    regex_split_parts = list(filter(len, regex_split_parts))

    for word in regex_split_parts:
        essid_parts.update(_word_compounds_permutation(word, max_compounds=max_compounds))
        essid_parts.update(_word_compounds_permutation(word.lower(), max_compounds=max_compounds))

    essid_parts.update(regex_split_parts)
    essid_parts.update(_split_uppercase(essid_origin))
    for essid in list(essid_parts):
        essid = regex_non_char.sub('', essid)
        essid_parts.update(modify_case(essid))
    essid_parts.update(modify_case(essid_origin))
    essid_parts = set(word for word in essid_parts if len(word) > 1)
    essid_parts.update(modify_case(essid_origin))  # special case when ESSID is a single letter
    return essid_parts


def _collect_essid_hamming(essid: str, hamming_dist_max=2):
    essid_hamming = set()
    essid_hamming.update(hamming_ball(s=essid, n=hamming_dist_max))
    essid_hamming.update(hamming_ball(s=essid.lower(), n=hamming_dist_max))
    logger.debug(f"Essid {essid} -> {len(essid_hamming)} hamming cousins with dist={hamming_dist_max}")
    return essid_hamming


def _collect_essid_rule(essid_wordlist_path: Path):
    """
    Run ESSID + best64.rule attack.
    """
    with tempfile.NamedTemporaryFile(mode='w+b') as f:
        hashcat_stdout = HashcatCmdStdout(outfile=f.name)
        hashcat_stdout.add_wordlists(essid_wordlist_path)
        hashcat_stdout.add_rule(Rule.ESSID)
        subprocess_call(hashcat_stdout.build())
        with open(f.name) as f:
            candidates = f.readlines()
    return candidates


def _collect_essid_digits(essid_wordlist_path: Path):
    candidates = set()
    wordlist_order = [essid_wordlist_path, WordListDefault.DIGITS_APPEND]
    for reverse in range(2):
        with tempfile.NamedTemporaryFile(mode='w+b') as ftemp:
            hashcat_stdout = HashcatCmdStdout(outfile=ftemp.name)
            hashcat_stdout.add_wordlists(*wordlist_order, options=['-a1'])
            subprocess_call(hashcat_stdout.build())
            with open(ftemp.name) as f:
                candidates.update(f.readlines())
        wordlist_order = wordlist_order[::-1]
    return candidates


def get_password_candidates_count(essid: str, hamming_d=2):
    essid_parts = len(_collect_essid_parts(essid))
    n_rules = count_rules(Rule.ESSID)
    n_compounds = essid_parts * n_rules
    digits_append = count_wordlist(WordListDefault.DIGITS_APPEND.path)
    if len(_word_compounds(essid)) > MAX_COMPOUNDS_DIGITS_APPEND:
        n_digits_append = len(_collect_essid_parts(
            essid, max_compounds=MAX_COMPOUNDS_DIGITS_APPEND)) * digits_append
    else:
        n_digits_append = essid_parts * digits_append
    s = len(essid)
    n_hamming = math.comb(s, hamming_d) * s ** hamming_d * 3 * 2
    n_total = n_compounds + n_digits_append + n_hamming
    # print(f"{n_total=:.2e}: {n_compounds=:.2e}, {n_digits_append=:.2e}, {n_hamming=:.2e}")
    return n_total


def get_password_candidates(essid):
    password_candidates = set()
    essid_as_wordlist_dir = Path(tempfile.mkdtemp())

    # (1) Hamming ball attack
    password_candidates.update(_collect_essid_hamming(essid=essid))

    # (2) best64 rule attack
    # strip all except digits, letters and '_'
    essid_filepath = essid_as_wordlist_dir / re.sub(r'\W+', '', essid)
    with open(essid_filepath, 'w') as f:
        f.writelines(_collect_essid_parts(essid))
    password_candidates.update(_collect_essid_rule(essid_filepath))

    # (3) digits_append attack
    if len(_word_compounds(essid)) > MAX_COMPOUNDS_DIGITS_APPEND:
        # Rewrite the file to limit the no. of compounds
        with open(essid_filepath, 'w') as f:
            f.writelines(_collect_essid_parts(essid,
                                              max_compounds=MAX_COMPOUNDS_DIGITS_APPEND))
    password_candidates.update(_collect_essid_digits(essid_filepath))

    shutil.rmtree(essid_as_wordlist_dir)
    return password_candidates


if __name__ == '__main__':
    # get_password_candidates_count("lrtgn5s19b41e21f1202unc77i8093")
    for essid in ["Tanya007", "My_rabbit", "Myrabbit", "MyRabbit", "PetitCafe2017"]:
        compounds = sorted(_word_compounds_permutation(essid))
        candidates = sorted(_collect_essid_parts(essid))
        print(f"'{essid}'\n\t{len(compounds)} compounds: {compounds}")
        print(f"\t{len(candidates)} candidates: {candidates}")
