import argparse
import binascii
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from collections import defaultdict
from functools import partial
from pathlib import Path
from typing import Union, List, Dict

from tqdm import trange

from app.app_logger import logger
from app.attack.hashcat_cmd import HashcatCmd
from app.domain import Rule, WordList, Mask
from app.utils import split_uppercase, read_plain_key

HCCAPX_BYTES = 393


def subprocess_call(args):
    """
    Called in background process.
    :param args: shell args
    """
    logger.debug(">>> {}".format(' '.join(args)))
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
        timer = BaseAttack.timers[func.__name__]
        timer['count'] += 1
        timer['elapsed'] += elapsed_sec
        return res
    return wrapped


class BaseAttack(object):

    timers = defaultdict(lambda: dict(count=0, elapsed=1e-6))

    def __init__(self, hcap_file: Union[str, Path]):
        self.hcap_file = Path(shlex.quote(str(hcap_file)))
        self.key_file = self.hcap_file.with_suffix('.key')
        self.session = self.hcap_file.name
        self.new_cmd = partial(HashcatCmd, hcap_file=self.hcap_file, outfile=self.key_file, session=self.session)

    def run_essid_attack(self, verbose=False) -> Dict[str, str]:
        """
        Run ESSID + digits_append.txt combinator attack.
        Run ESSID + best64.rule attack.
        """
        with open(self.hcap_file, 'rb') as f:
            data = f.read()
        n_captures = len(data) // HCCAPX_BYTES
        assert n_captures > 0, "No hashes loaded"
        assert n_captures * HCCAPX_BYTES == len(data), "Invalid .hccapx file"
        hcap_split_dir = Path(tempfile.mkdtemp())
        mac_essid_dict = {}
        for capture_id in trange(n_captures, desc="ESSID attack", disable=not verbose):
            capture = data[capture_id * HCCAPX_BYTES: (capture_id + 1) * HCCAPX_BYTES]
            essid_len = capture[9]
            try:
                essid = capture[10: 10 + essid_len].decode('ascii')
                mac_ap = binascii.hexlify(capture[59: 65]).decode('ascii')
            except UnicodeDecodeError:
                # skip non-ascii ESSIDs
                continue
            mac_essid_dict[mac_ap] = essid
            print(f"BSSID={mac_ap} ESSID={essid}")
            hcap_fpath_essid = hcap_split_dir.joinpath(essid + '.hccapx')
            with open(hcap_fpath_essid, 'ab') as f:
                f.write(capture)
        for mac_ap, essid in mac_essid_dict.items():
            hcap_fpath_essid = hcap_split_dir.joinpath(essid + '.hccapx')
            with tempfile.NamedTemporaryFile(mode='w') as f:
                f.writelines(self.collect_essid_parts(essid))
                f.seek(0)
                self._run_essid_digits(hcap_fpath=hcap_fpath_essid, essid_wordlist_path=f.name)
                self._run_essid_rule(hcap_fpath=hcap_fpath_essid, essid_wordlist_path=f.name)
            self.run_bssid_attack(mac_ap=mac_ap, hcap_fpath=hcap_fpath_essid)
        shutil.rmtree(hcap_split_dir)
        return mac_essid_dict

    def run_bssid_attack(self, mac_ap: str, hcap_fpath: Path):
        """
        Some routers, for example, TP-LINK, use last 8 MAC AP characters as the default password.
        :param mac_ap: MAC AP (BSSID)
        :param hcap_fpath: path to .hccapx
        """
        mac_ap = mac_ap.strip(':\n')
        password_len = 8
        mac_ap_candidates = {mac_ap + '\n'}
        for start in range(len(mac_ap) - password_len):
            mac_ap_chunk = mac_ap[start: start + password_len]
            mac_ap_candidates.add(mac_ap_chunk + '\n')
        hashcat_cmd = HashcatCmd(hcap_file=hcap_fpath, outfile=self.key_file, session=self.session)
        with tempfile.NamedTemporaryFile(mode='w') as f:
            f.writelines(mac_ap_candidates)
            f.seek(0)
            hashcat_cmd.add_wordlist(f.name)
            subprocess_call(hashcat_cmd.build())

    @staticmethod
    def collect_essid_parts(essid_origin: str) -> List[str]:
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
        essids_new_line = list(essid + '\n' for essid in essids_case_insensitive)
        return essids_new_line

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
        hashcat_cmd.pipe_word_candidates = True
        hashcat_cmd = ' '.join(hashcat_cmd.build())
        os.system(hashcat_cmd)

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
    def run_top4k(self):
        """
        Run weak password attack, using a very shallow yet commonly used dictionaries:
        - john.txt
        - conficker.txt
        - elitehacker.txt
        - riskypass_top1000.txt
        - Top1575-probable-v2.txt
        """
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlist(WordList.TOP4K)
        hashcat_cmd.add_rule(Rule.BEST_64)
        hashcat_cmd.pipe_word_candidates = True
        hashcat_cmd = ' '.join(hashcat_cmd.build())
        os.system(hashcat_cmd)

    @monitor_timer
    def run_top1m(self):
        """
        - Top1m-probable-v2.txt with digits
        """
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlist(WordList.TOP1M_WITH_DIGITS)
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
        self.run_essid_attack(verbose=True)
        self.run_top4k()
        self.run_top1m()
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
    attack.run_phone_mobile()
    if attack.key_file.exists():
        key_password = read_plain_key(attack.key_file)
        print("WPA key is found!\n", key_password)
    else:
        print("WPA key is not found.")


if __name__ == '__main__':
    crack_hccapx()
