import argparse
import os
import re
import subprocess
import time
from functools import partial
from pathlib import Path

from tqdm import trange

from app.config import WORDLISTS_DIR
from app.domain import Rule, WordList
from app.hashcat_cmd import HashcatCmd
from app.utils import split_uppercase, with_suffix

HCCAPX_BYTES = 393


def subprocess_call(args):
    """
    Called in background process.
    :param args: shell args
    """
    process = subprocess.Popen(args,
                               universal_newlines=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    out, err = process.communicate()
    return out, err


def monitor_timer(func):
    def wrapped(*args, **kwargs):
        start = time.time()
        res = func(*args, **kwargs)
        elapsed_sec = time.time() - start
        print(f"{func.__name__} elapsed {elapsed_sec} sec")
        return res
    return wrapped


class Attack(object):

    def __init__(self, hcap_file):
        self.hcap_file = hcap_file
        self.key_file = with_suffix(hcap_file, 'key')
        self.hcap_split_dir = Path(WORDLISTS_DIR) / 'split'
        self.hcap_split_dir.mkdir(parents=True, exist_ok=True)
        self.new_cmd = partial(HashcatCmd, hcap_file=self.hcap_file, outfile=self.key_file)

    @staticmethod
    def parse_essid(stdout: str):
        essid_key = "ESSID="
        for line in stdout.splitlines():
            if essid_key in line:
                start = line.index(essid_key) + len(essid_key)
                end = line.index(" (Length:", start)
                essid = line[start: end]
                return essid
        return None

    def run_essid_attack(self):
        """
        Run ESSID + digits_append.txt combinator attack.
        Run ESSID + best64.rule attack.
        """
        def modify_case(word):
            return {word, word.lower(), word.upper(), word.capitalize(), word.lower().capitalize()}
        with open(self.hcap_file, 'rb') as f:
            data = f.read()
        n_captures = len(data) // HCCAPX_BYTES
        assert n_captures * HCCAPX_BYTES == len(data), "Invalid .hccapx file"
        regex_non_char = re.compile('[^a-zA-Z]')
        for capture_id in trange(n_captures, desc="ESSID attack"):
            capture = data[capture_id * HCCAPX_BYTES: (capture_id + 1) * HCCAPX_BYTES]
            essid_len = capture[9]
            try:
                essid_unique = capture[10: 10 + essid_len].decode('ascii')
            except UnicodeDecodeError:
                # skip non-ascii ESSIDs
                continue
            print(f"ESSID {essid_unique}")
            essid_parts = {essid_unique}
            essid_parts.update(regex_non_char.split(essid_unique))
            essid_parts.update(split_uppercase(essid_unique))
            essids_case_insensitive = set()
            for essid in essid_parts:
                essid = regex_non_char.sub('', essid)
                essids_case_insensitive.update(modify_case(essid))
            essids_case_insensitive.update(modify_case(essid_unique))
            essids_case_insensitive = filter(len, essids_case_insensitive)
            with open(WordList.ESSID.get_path(), 'w') as f:
                f.writelines([essid + '\n' for essid in essids_case_insensitive])
            hcap_fpath_essid = self.hcap_split_dir.joinpath(essid_unique + '.hccapx')
            with open(hcap_fpath_essid, 'wb') as f:
                f.write(capture)
            self._run_essid_digits(hcap_fpath_essid)
            self._run_essid_rule(hcap_fpath_essid)

    @monitor_timer
    def _run_essid_digits(self, hcap_fpath_essid):
        """
        Run ESSID + digits_append.txt combinator attack.
        """
        hashcat_cmd = HashcatCmd(hcap_file=hcap_fpath_essid, outfile=hcap_fpath_essid.with_suffix('.key'))
        hashcat_cmd.add_wordlist(WordList.ESSID)
        hashcat_cmd.add_wordlist(WordList.DIGITS_APPEND)
        hashcat_cmd.add_custom_argument("-a1")
        subprocess_call(hashcat_cmd.build())

    @monitor_timer
    def _run_essid_rule(self, hcap_fpath_essid):
        """
        Run ESSID + best64.rule attack.
        """
        hashcat_cmd = HashcatCmd(hcap_file=hcap_fpath_essid, outfile=hcap_fpath_essid.with_suffix('.key'))
        hashcat_cmd.add_wordlist(WordList.ESSID)
        hashcat_cmd.add_rule(Rule.BEST_64)
        hashcat_cmd.pipe_word_candidates = True
        hashcat_cmd = ' '.join(hashcat_cmd.build())
        os.system(hashcat_cmd)

    def run_digits8(self):
        """
        Run digits8+ attack. This includes:
        - birthdays 100 years backward
        - simple digits like 88888888, 12345678, etc.
        For more information refer to `digits/create_digits.py`
        """
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlist(WordList.DIGITS_8)
        subprocess_call(hashcat_cmd.build())

    def run_weak_passwords(self):
        """
        Run weak password attack, using a very shallow yet commonly used dictionaries:
        - john.txt
        - conficker.txt
        """
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlist(WordList.WEAK)
        hashcat_cmd.add_rule(Rule.BEST_64)
        hashcat_cmd.pipe_word_candidates = True
        hashcat_cmd = ' '.join(hashcat_cmd.build())
        os.system(hashcat_cmd)


def crack_hccapx():
    """
    Check weak passwords in command line.
    """
    parser = argparse.ArgumentParser(description='Check weak passwords')
    parser.add_argument('hccapx', help='path to .hccapx')
    args = parser.parse_args()
    attack = Attack(hcap_file=args.hccapx)
    attack.run_essid_attack()
    attack.run_weak_passwords()
    attack.run_digits8()


if __name__ == '__main__':
    crack_hccapx()
