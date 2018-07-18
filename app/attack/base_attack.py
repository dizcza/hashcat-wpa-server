import os
import re
import subprocess
import time
from collections import defaultdict
from functools import partial
from pathlib import Path
from typing import Union

from app.app_logger import logger
from app.attack.hashcat_cmd import HashcatCmd
from app.domain import Rule
from app.domain import WordList
from app.utils import split_uppercase


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
        self.hcap_file = Path(hcap_file)
        self.key_file = self.hcap_file.with_suffix('.key')
        self.session = os.path.basename(self.hcap_file)
        self.new_cmd = partial(HashcatCmd, hcap_file=self.hcap_file, outfile=self.key_file, session=self.session)

    def run_essid_attack(self):
        """
        Run ESSID + digits_append.txt combinator attack.
        Run ESSID + best64.rule attack.
        """
        raise NotImplementedError()

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

    @staticmethod
    def write_essid_wordlist(essid_origin: str):
        essids_case_insensitive = BaseAttack.collect_essid_parts(essid_origin)
        with open(WordList.ESSID.get_path(), 'w') as f:
            f.writelines([essid + '\n' for essid in essids_case_insensitive])

    @monitor_timer
    def _run_essid_digits(self, hcap_fpath: Path):
        """
        Run ESSID + digits_append.txt combinator attack.
        """
        hashcat_cmd = HashcatCmd(hcap_file=hcap_fpath, outfile=hcap_fpath.with_suffix('.key'), session=self.session)
        hashcat_cmd.add_wordlist(WordList.ESSID)
        hashcat_cmd.add_wordlist(WordList.DIGITS_APPEND)
        hashcat_cmd.add_custom_argument("-a1")
        subprocess_call(hashcat_cmd.build())

    @monitor_timer
    def _run_essid_rule(self, hcap_fpath: Path):
        """
        Run ESSID + best64.rule attack.
        """
        hashcat_cmd = HashcatCmd(hcap_file=hcap_fpath, outfile=hcap_fpath.with_suffix('.key'), session=self.session)
        hashcat_cmd.add_wordlist(WordList.ESSID)
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
    def run_top304k(self):
        """
        - Top304Thousand-probable-v2.txt
        """
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlist(WordList.TOP304k)
        subprocess_call(hashcat_cmd.build())
