import argparse
import binascii
import os
import re
import shlex
import shutil
import tempfile
import time
from collections import defaultdict
from functools import partial
from pathlib import Path
from typing import Union, List, Dict, Iterable

from tqdm import tqdm

from app.app_logger import logger
from app.attack.hashcat_cmd import HashcatCmd
from app.domain import Rule, WordList, Mask
from app.utils import split_uppercase, read_plain_key, subprocess_call, wlanhcxinfo

HCCAPX_BYTES = 393


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


class BaseAttack(object):

    timers = defaultdict(lambda: dict(count=0, elapsed=1e-6))

    def __init__(self, hcap_file: Union[str, Path], verbose=True):
        """
        :param hcap_file: .hccapx hashcat capture file path
        :param verbose: show (True) or hide (False) tqdm
        """
        self.hcap_file = Path(shlex.quote(str(hcap_file)))
        assert self.hcap_file.suffix == '.hccapx'
        self.verbose = verbose
        self.key_file = self.hcap_file.with_suffix('.key')
        self.session = self.hcap_file.name
        self.new_cmd = partial(HashcatCmd, hcap_file=self.hcap_file, outfile=self.key_file, session=self.session)

    def run_essid_attack(self):
        """
        Run ESSID + digits_append.txt combinator attack.
        Run ESSID + best64.rule attack.
        """
        hcap_split_dir = Path(tempfile.mkdtemp())
        subprocess_call(['wlanhcx2ssid', '-i', self.hcap_file, '-p', hcap_split_dir, '-e'])
        files = list(hcap_split_dir.iterdir())
        for hcap_fpath_essid in tqdm(files, desc="ESSID attack", disable=not self.verbose):
            essid = wlanhcxinfo(hcap_fpath_essid, mode='-e')
            essid = next(iter(essid))  # should be only 1 item
            with tempfile.NamedTemporaryFile(mode='w') as f:
                if self.verbose:
                    logger.debug(f"ESSID={essid}, candidates={f.name}")
                essid_candidates = '\n'.join(self.collect_essid_parts(essid))
                f.write(essid_candidates)
                f.seek(0)
                self._run_essid_digits(hcap_fpath=hcap_fpath_essid, essid_wordlist_path=f.name)
                self._run_essid_rule(hcap_fpath=hcap_fpath_essid, essid_wordlist_path=f.name)
        shutil.rmtree(hcap_split_dir)

    def run_bssid_attack(self):
        """
        Some routers, for example, TP-LINK, use last 8 MAC AP characters as the default password.
        """
        bssids = wlanhcxinfo(self.hcap_file, mode='-a')
        password_len = 8
        mac_ap_candidates = set()
        for mac_ap in bssids:
            mac_ap_candidates.add(mac_ap)
            for start in range(len(mac_ap) - password_len):
                mac_ap_chunk = mac_ap[start: start + password_len]
                mac_ap_candidates.add(mac_ap_chunk)
        if self.verbose:
            logger.debug(f"BSSID candidates: {mac_ap_candidates}")
        hashcat_cmd = self.new_cmd()
        mac_ap_candidates = '\n'.join(mac_ap_candidates)
        with tempfile.NamedTemporaryFile(mode='w') as f:
            f.write(mac_ap_candidates)
            f.seek(0)
            hashcat_cmd.add_wordlist(f.name)
            subprocess_call(hashcat_cmd.build())

    @staticmethod
    def collect_essid_parts(essid_origin: str):
        def modify_case(word: str):
            return {word, word.lower(), word.upper(), word.capitalize(), word.lower().capitalize()}
        regex_non_char = re.compile('[^a-zA-Z]')
        essid_parts = {essid_origin}
        essid_parts.update(regex_non_char.split(essid_origin))
        essid_parts.update(split_uppercase(essid_origin))
        essids_case_insensitive = set()
        for essid in essid_parts:
            essid = regex_non_char.sub('', essid)
            essids_case_insensitive.update(modify_case(essid))
        essids_case_insensitive.update(modify_case(essid_origin))
        essids_case_insensitive = filter(len, essids_case_insensitive)
        return essids_case_insensitive

    @monitor_timer
    def _run_essid_digits(self, hcap_fpath: Path, essid_wordlist_path: str):
        """
        Run ESSID + digits_append.txt combinator attack.
        """
        hashcat_cmd = HashcatCmd(hcap_file=hcap_fpath, outfile=self.key_file, session=self.session)
        hashcat_cmd.add_custom_argument("-a1")
        wordlists_combine = (essid_wordlist_path, WordList.DIGITS_APPEND)

        def run_combined(wordlists=wordlists_combine, reverse=False):
            hashcat_cmd.wordlists.clear()
            if reverse:
                wordlists = reversed(wordlists)
            for wordlist in wordlists:
                hashcat_cmd.add_wordlist(wordlist)
            subprocess_call(hashcat_cmd.build())

        run_combined(reverse=False)
        run_combined(reverse=True)

    @monitor_timer
    def _run_essid_rule(self, hcap_fpath: Path, essid_wordlist_path: str):
        """
        Run ESSID + best64.rule attack.
        """
        hashcat_cmd = HashcatCmd(hcap_file=hcap_fpath, outfile=self.key_file, session=self.session)
        hashcat_cmd.add_wordlist(essid_wordlist_path)
        hashcat_cmd.add_rule(Rule.BEST_64)
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
        hashcat_cmd.add_wordlist(WordList.DIGITS_8)
        subprocess_call(hashcat_cmd.build())

    @monitor_timer
    def run_top1k(self):
        """
        - Top1575-probable-v2.txt with best64 rules
        """
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlist(WordList.TOP1K)
        hashcat_cmd.add_rule(Rule.BEST_64)
        subprocess_call(hashcat_cmd.build())

    @monitor_timer
    def run_top304k(self):
        """
        - Top1m-probable-v2.txt with digits
        """
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlist(WordList.TOP304K)
        subprocess_call(hashcat_cmd.build())

    @monitor_timer
    def run_phone_mobile(self):
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.set_mask(Mask.MOBILE_UA)
        subprocess_call(hashcat_cmd.build())

    def run_all(self):
        """
        Run all attacks.
        """
        self.run_essid_attack()
        self.run_bssid_attack()
        self.run_top1k()
        self.run_top304k()
        self.run_digits8()


def crack_hccapx():
    """
    Crack .hhcapx in command line.
    """
    parser = argparse.ArgumentParser(description='Check weak passwords')
    parser.add_argument('hccapx', help='path to .hccapx')
    args = parser.parse_args()
    attack = BaseAttack(hcap_file=args.hccapx)
    attack.run_all()
    # attack.run_phone_mobile()
    if attack.key_file.exists():
        key_password = read_plain_key(attack.key_file)
        print("WPA key is found!\n", key_password)
    else:
        print("WPA key is not found.")


if __name__ == '__main__':
    crack_hccapx()
