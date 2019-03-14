import argparse
import re
import shlex
import shutil
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Union

from tqdm import tqdm

from app.app_logger import logger
from app.attack.hashcat_cmd import HashcatCmdCapture, HashcatCmdStdout
from app.config import ESSID_TRIED
from app.domain import Rule, WordList, Mask
from app.utils import read_plain_key, subprocess_call, wlanhcxinfo
from app.word_magic import collect_essid_parts


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

    def __init__(self, hcap_file: Union[str, Path], hashcat_args=(), verbose=True):
        """
        :param hcap_file: .hccapx hashcat capture file path
        :param verbose: show (True) or hide (False) tqdm
        """
        self.hcap_file = Path(shlex.quote(str(hcap_file)))
        self.verbose = verbose
        self.hashcat_args = hashcat_args
        assert self.hcap_file.suffix == '.hccapx'
        self.key_file = self.hcap_file.with_suffix('.key')
        self.session = self.hcap_file.name

    def new_cmd(self, hcap_file: Union[str, Path] = None):
        if hcap_file is None:
            hcap_file = self.hcap_file
        return HashcatCmdCapture(hcap_file=hcap_file, outfile=self.key_file, hashcat_args=self.hashcat_args,
                                 session=self.session)

    def run_essid_attack(self):
        """
        Run ESSID + digits_append.txt combinator attack.
        Run ESSID + best64.rule attack.
        """
        ESSID_TRIED.parent.mkdir(parents=True, exist_ok=True)
        hcap_split_dir = Path(tempfile.mkdtemp())
        essid_split_dir = Path(tempfile.mkdtemp())
        subprocess_call(['wlanhcx2ssid', '-i', self.hcap_file, '-p', hcap_split_dir, '-e'])
        files = list(hcap_split_dir.iterdir())
        bssid_essid_tried = set()
        if ESSID_TRIED.exists():
            with open(ESSID_TRIED, 'r') as f:
                bssid_essid_tried = set(f.read().splitlines())
        for hcap_fpath_essid in tqdm(files, desc="ESSID attack", disable=not self.verbose):
            bssid_essid = wlanhcxinfo(hcap_fpath_essid, mode='-ae')
            if len(bssid_essid) > 1:
                logger.warn(f"Expected 1 unique BSSID:ESSID in {bssid_essid}.")
            bssid_essid = next(iter(bssid_essid))  # should be only 1 item
            if bssid_essid in bssid_essid_tried:
                continue
            bssid, essid = bssid_essid.split(':', maxsplit=1)
            essid_filepath = essid_split_dir / re.sub(r'\W+', '', essid)  # strip all except digits, letters and '_'
            with open(essid_filepath, 'w') as f:
                f.write('\n'.join(collect_essid_parts(essid)))
            self._run_essid_rule(hcap_fpath=hcap_fpath_essid, essid_wordlist_path=essid_filepath)
            wordlist_order = [essid_filepath, WordList.DIGITS_APPEND.path]
            for reverse in range(2):
                with tempfile.NamedTemporaryFile(mode='w') as f:
                    hashcat_cmd = HashcatCmdStdout(outfile=f.name)
                    hashcat_cmd.add_wordlists(*wordlist_order, combinator='-a1')
                    subprocess_call(hashcat_cmd.build())
                    hashcat_cmd = self.new_cmd(hcap_file=hcap_fpath_essid)
                    hashcat_cmd.add_wordlists(f.name)
                    subprocess_call(hashcat_cmd.build())
                wordlist_order = wordlist_order[::-1]
            with open(ESSID_TRIED, 'a') as f:
                f.write(bssid_essid + '\n')
        shutil.rmtree(essid_split_dir)
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
            hashcat_cmd.add_wordlists(f.name)
            subprocess_call(hashcat_cmd.build())

    @monitor_timer
    def _run_essid_rule(self, hcap_fpath: Path, essid_wordlist_path: Path):
        """
        Run ESSID + best64.rule attack.
        """
        with tempfile.NamedTemporaryFile(mode='w') as f:
            hashcat_cmd = HashcatCmdStdout(outfile=f.name)
            hashcat_cmd.add_wordlists(essid_wordlist_path)
            hashcat_cmd.add_rule(Rule.ESSID)
            subprocess_call(hashcat_cmd.build())
            hashcat_cmd = self.new_cmd(hcap_file=hcap_fpath)
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
        hashcat_cmd.add_wordlists(WordList.DIGITS_8)
        subprocess_call(hashcat_cmd.build())

    @monitor_timer
    def run_top1k(self):
        """
        - Top1575-probable-v2.txt with best64 rules
        """
        with tempfile.NamedTemporaryFile(mode='w') as f:
            hashcat_cmd = HashcatCmdStdout(outfile=f.name)
            hashcat_cmd.add_wordlists(WordList.TOP1K)
            hashcat_cmd.add_rule(Rule.BEST_64)
            subprocess_call(hashcat_cmd.build())
            hashcat_cmd = self.new_cmd()
            hashcat_cmd.add_wordlists(f.name)
            subprocess_call(hashcat_cmd.build())

    @monitor_timer
    def run_top304k(self):
        """
        - Top1m-probable-v2.txt with digits
        """
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlists(WordList.TOP304K)
        subprocess_call(hashcat_cmd.build())

    @monitor_timer
    def run_phone_mobile(self):
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.set_mask(Mask.MOBILE_UA)
        subprocess_call(hashcat_cmd.build())

    @monitor_timer
    def run_keyboard_walk(self):
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlists(WordList.KEYBOARD_WALK_EN, WordList.KEYBOARD_WALK_RU)
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
        self.run_keyboard_walk()


def crack_hccapx():
    """
    Crack .hhcapx in command line.
    """
    parser = argparse.ArgumentParser(description='Check weak passwords')
    parser.add_argument('hccapx', help='path to .hccapx')
    args, hashcat_args = parser.parse_known_args()
    attack = BaseAttack(hcap_file=args.hccapx, hashcat_args=hashcat_args)
    attack.run_all()
    # attack.run_phone_mobile()
    if attack.key_file.exists():
        key_password = read_plain_key(attack.key_file)
        print("WPA key is found!\n", key_password)
    else:
        print("WPA key is not found.")


if __name__ == '__main__':
    crack_hccapx()
