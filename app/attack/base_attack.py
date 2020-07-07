import argparse
import math
import re
import shutil
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Union

from tqdm import tqdm

from app.attack.convert import split_by_essid
from app.attack.hashcat_cmd import HashcatCmdCapture, HashcatCmdStdout
from app.config import ESSID_TRIED
from app.domain import Rule, WordListDefault, Mask
from app.logger import logger
from app.utils import read_plain_key, subprocess_call, bssid_essid_from_22000, check_file_22000
from app.word_magic.essid import collect_essid_parts, word_compounds, word_compounds_permutation, \
    MAX_COMPOUNDS_DIGITS_APPEND
from app.word_magic.hamming import hamming_ball
from app.word_magic.wordlist import count_rules, count_wordlist


def monitor_timer(func):
    def wrapped(*args, **kwargs):
        start = time.time()
        res = func(*args, **kwargs)
        elapsed_sec = time.time() - start
        timer = BaseAttack.timers[func.__name__]
        timer['count'] += 1
        timer['elapsed'] += elapsed_sec
        return res

    return wrapped


class BaseAttack:
    timers = defaultdict(lambda: dict(count=0, elapsed=1e-6))

    def __init__(self, file_22000: Union[str, Path], hashcat_args=(), verbose=True):
        """
        :param file_22000: .22000 hashcat capture file path
        :param verbose: show (True) or hide (False) tqdm
        """
        check_file_22000(file_22000)
        self.file_22000 = Path(file_22000)
        self.hashcat_args = tuple(hashcat_args)
        self.verbose = verbose
        self.key_file = self.file_22000.with_suffix('.key')
        self.session = self.file_22000.name

    def new_cmd(self, hcap_file: Union[str, Path] = None):
        if hcap_file is None:
            hcap_file = self.file_22000
        return HashcatCmdCapture(hcap_file=hcap_file, outfile=self.key_file, hashcat_args=self.hashcat_args,
                                 session=self.session)

    def run_essid_attack(self):
        """
        Run ESSID + digits_append.txt combinator attack.
        Run ESSID + best64.rule attack.
        """
        ESSID_TRIED.parent.mkdir(parents=True, exist_ok=True)
        split_by_essid_dir = Path(tempfile.mkdtemp())
        essid_as_wordlist_dir = Path(tempfile.mkdtemp())

        bssid_essid_tried = set()
        if ESSID_TRIED.exists():
            with open(ESSID_TRIED, 'r') as f:
                bssid_essid_tried = set(f.read().splitlines())

        bssid_essid_pairs = tuple(bssid_essid_from_22000(self.file_22000))
        if len(bssid_essid_pairs) > 1:
            split_by_essid(self.file_22000, to_folder=split_by_essid_dir)
            files_split_by_essid = list(split_by_essid_dir.iterdir())
        else:
            files_split_by_essid = [self.file_22000]

        for hcap_fpath_essid in tqdm(files_split_by_essid, desc="ESSID attack", disable=not self.verbose):
            bssid_essid = next(bssid_essid_from_22000(hcap_fpath_essid))
            if bssid_essid in bssid_essid_tried:
                continue
            bssid, essid = bssid_essid.split(':')
            essid = bytes.fromhex(essid).decode('utf-8')

            # (1) Hamming ball attack
            self._run_essid_hamming(hcap_fpath_essid=hcap_fpath_essid, essid=essid)

            # (2) best64 rule attack
            essid_filepath = essid_as_wordlist_dir / re.sub(r'\W+', '', essid)  # strip all except digits, letters and '_'
            with open(essid_filepath, 'w') as f:
                f.write('\n'.join(collect_essid_parts(essid)))
            self._run_essid_rule(hcap_fpath=hcap_fpath_essid, essid_wordlist_path=essid_filepath)

            # (3) digits_append attack
            if len(word_compounds(essid)) > MAX_COMPOUNDS_DIGITS_APPEND:
                with open(essid_filepath, 'w') as f:
                    f.write('\n'.join(collect_essid_parts(essid, max_compounds=MAX_COMPOUNDS_DIGITS_APPEND)))
            self._run_essid_digits(hcap_fpath_essid=hcap_fpath_essid, essid_wordlist_path=essid_filepath)

            with open(ESSID_TRIED, 'a') as f:
                f.write(bssid_essid + '\n')
        shutil.rmtree(essid_as_wordlist_dir)
        shutil.rmtree(split_by_essid_dir)

    @staticmethod
    def compute_essid_candidates_num(essid: str, hamming_d=2):
        essid_parts = len(collect_essid_parts(essid))
        n_rules = count_rules(Rule.ESSID)
        n_compounds = essid_parts * n_rules
        digits_append = count_wordlist(WordListDefault.DIGITS_APPEND.path)
        if len(word_compounds(essid)) > MAX_COMPOUNDS_DIGITS_APPEND:
            n_digits_append = len(collect_essid_parts(
                essid, max_compounds=MAX_COMPOUNDS_DIGITS_APPEND)) * digits_append
        else:
            n_digits_append = essid_parts * digits_append
        s = len(essid)
        n_hamming = math.comb(s, hamming_d) * s ** hamming_d * 3 * 2
        n_total = n_compounds + n_digits_append + n_hamming
        # print(f"{n_total=:.2e}: {n_compounds=:.2e}, {n_digits_append=:.2e}, {n_hamming=:.2e}")
        return n_total


    @monitor_timer
    def _run_essid_rule(self, hcap_fpath: Path, essid_wordlist_path: Path):
        """
        Run ESSID + best64.rule attack.
        """
        with tempfile.NamedTemporaryFile(mode='w') as f:
            hashcat_stdout = HashcatCmdStdout(outfile=f.name)
            hashcat_stdout.add_wordlists(essid_wordlist_path)
            hashcat_stdout.add_rule(Rule.ESSID)
            subprocess_call(hashcat_stdout.build())
            hashcat_cmd = self.new_cmd(hcap_file=hcap_fpath)
            hashcat_cmd.add_wordlists(f.name)
            subprocess_call(hashcat_cmd.build())

    @monitor_timer
    def _run_essid_digits(self, hcap_fpath_essid: Path, essid_wordlist_path: str):
        wordlist_order = [essid_wordlist_path, WordListDefault.DIGITS_APPEND.path]
        for reverse in range(2):
            with tempfile.NamedTemporaryFile(mode='w') as f:
                hashcat_stdout = HashcatCmdStdout(outfile=f.name)
                hashcat_stdout.add_wordlists(*wordlist_order, options=['-a1'])
                subprocess_call(hashcat_stdout.build())
                hashcat_cmd = self.new_cmd(hcap_file=hcap_fpath_essid)
                hashcat_cmd.add_wordlists(f.name)
                subprocess_call(hashcat_cmd.build())
            wordlist_order = wordlist_order[::-1]

    @monitor_timer
    def _run_essid_hamming(self, hcap_fpath_essid: Path, essid: str, hamming_dist_max=2):
        essid_hamming = set()
        essid_hamming.update(hamming_ball(s=essid, n=hamming_dist_max))
        essid_hamming.update(hamming_ball(s=essid.lower(), n=hamming_dist_max))
        logger.debug(f"Essid {essid} -> {len(essid_hamming)} hamming cousins with dist={hamming_dist_max}")
        with tempfile.NamedTemporaryFile(mode='w') as f:
            f.write('\n'.join(essid_hamming))
            hashcat_cmd = self.new_cmd(hcap_file=hcap_fpath_essid)
            hashcat_cmd.add_wordlists(f.name)
            subprocess_call(hashcat_cmd.build())

    @monitor_timer
    def run_digits8(self):
        """
        Run digits8+ attack. This includes:
        - birthdays 100 years backward
        - simple digits like 88888888, 12345678, etc.
        For more information refer to `digits/create_digits.py`
        """
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlists(WordListDefault.DIGITS_8)
        subprocess_call(hashcat_cmd.build())

    @monitor_timer
    def run_top1k(self):
        """
        - Top1575-probable-v2.txt with best64 rules
        """
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlists(WordListDefault.TOP1K_RULE_BEST64)
        subprocess_call(hashcat_cmd.build())

    @monitor_timer
    def run_phone_mobile(self):
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.set_mask(Mask.MOBILE_UA)
        subprocess_call(hashcat_cmd.build())

    @monitor_timer
    def run_keyboard_walk(self):
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlists(WordListDefault.KEYBOARD_WALK)
        subprocess_call(hashcat_cmd.build())

    @monitor_timer
    def run_names(self):
        with tempfile.NamedTemporaryFile(mode='w') as f:
            hashcat_stdout = HashcatCmdStdout(outfile=f.name)
            hashcat_stdout.add_wordlists(WordListDefault.NAMES_UA_RU)
            hashcat_stdout.add_rule(Rule.ESSID)
            subprocess_call(hashcat_stdout.build())
            hashcat_cmd = self.new_cmd()
            hashcat_cmd.add_wordlists(f.name)
            subprocess_call(hashcat_cmd.build())

    @monitor_timer
    def run_names_with_digits(self):
        # excluded from the fast run
        # for each case-changed <name> in (Name, name, NAME) do
        #  - append digits
        #  - prepend digits
        with open(WordListDefault.NAMES_UA_RU_WITH_DIGITS.path, 'w') as f:
            wordlist_order = [WordListDefault.NAMES_UA_RU, WordListDefault.DIGITS_APPEND]
            for left in ['left', 'right']:
                for rule_names in ['', 'T0', 'u']:
                    hashcat_stdout = HashcatCmdStdout(outfile=f.name)
                    hashcat_stdout.add_wordlists(*wordlist_order, options=['-a1', f'--rule-{left}={rule_names}'])
                    subprocess_call(hashcat_stdout.build())
                wordlist_order = wordlist_order[::-1]
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlists(WordListDefault.NAMES_UA_RU_WITH_DIGITS)
        subprocess_call(hashcat_cmd.build())

    def run_all(self):
        """
        Run all attacks.
        """
        self.run_essid_attack()
        self.run_top1k()
        self.run_digits8()
        self.run_keyboard_walk()
        self.run_names()


def crack_22000():
    """
    Crack .22000 in command line.
    """
    parser = argparse.ArgumentParser(description='Check weak passwords',
                                     usage="base_attack.py [-h] capture [hashcat-args]")
    parser.add_argument('capture', help='path to .22000')
    args, hashcat_args = parser.parse_known_args()
    print(f"Hashcat args: {hashcat_args}")
    attack = BaseAttack(file_22000=args.capture, hashcat_args=hashcat_args)
    attack.run_all()
    # attack.run_names_with_digits()
    key_password = read_plain_key(attack.key_file)
    if key_password:
        print("WPA key is found!\n", key_password)
    else:
        print("WPA key is not found.")


if __name__ == '__main__':
    # BaseAttack.compute_essid_candidates_num("lrtgn5s19b41e21f1202unc77i8093")
    crack_22000()
