import os
import subprocess
import time
from pathlib import Path
from typing import Union

from app.config import HASHCAT_STATUS_TIMER
from app.domain import Rule, WordList, ProgressLock
from app.nvidia_smi import set_cuda_visible_devices

HASHCAT_WARNINGS = (
    "nvmlDeviceGetCurrPcieLinkWidth",
    "nvmlDeviceGetClockInfo",
    "nvmlDeviceGetTemperatureThreshold",
    "nvmlDeviceGetUtilizationRates",
    "nvmlDeviceGetPowerManagementLimit",
    "nvmlDeviceGetUtilizationRates",
)


def split_warnings_errors(stderr: str):

    def is_warning(line: str):
        for warn_pattern in HASHCAT_WARNINGS:
            if warn_pattern in line:
                return True
        return False

    warn = []
    err = []
    for line in stderr.splitlines():
        if line == '':
            continue
        if is_warning(line):
            warn.append(line)
        else:
            err.append(line)
    warn = '\n'.join(warn)
    err = '\n'.join(err)
    return warn, err


class HashcatCmd(object):
    def __init__(self, hcap_file: Union[str, Path], outfile: Union[str, Path], session=None):
        self.hcap_file = str(hcap_file)
        self.outfile = str(outfile)
        self.session = session
        self.rules = []
        self.wordlists = []
        self.custom_args = []
        self.pipe_word_candidates = False

    def build(self) -> list:
        set_cuda_visible_devices()
        command = ["hashcat"]
        for rule in self.rules:
            if rule is not None:
                command.append("--rules={}".format(rule.get_path()))
        if self.pipe_word_candidates:
            self._append_wordlists(command)
            command.extend(["--stdout", '|', "hashcat", "-w3"])
        command.append("-m2500")
        command.append("--weak-hash-threshold=0")
        command.append("--outfile={}".format(self.outfile))
        if not os.getenv('PRODUCTION', False):
            # localhost debug mode
            command.append("--potfile-disable")
        command.append("--status")
        command.append("--status-timer={}".format(HASHCAT_STATUS_TIMER))
        command.append("--machine-readable")
        if self.session is not None:
            command.append("--session={}".format(self.session))
        for arg in self.custom_args:
            command.append(arg)
        command.append(self.hcap_file)
        if not self.pipe_word_candidates:
            assert '|' not in command
            self._append_wordlists(command)
        return command

    def _append_wordlists(self, command: list):
        for word_list in self.wordlists:
            command.append(word_list)

    def add_rule(self, rule: Rule):
        self.rules.append(rule)

    def add_wordlist(self, wordlist: Union[WordList, str, Path]):
        if isinstance(wordlist, WordList):
            wordlist = wordlist.get_path()
        self.wordlists.append(str(wordlist))

    def add_custom_argument(self, argument: str):
        self.custom_args.append(argument)


def run_with_status(hashcat_cmd: HashcatCmd, lock: ProgressLock, timeout_minutes: int):
    timeout_seconds = timeout_minutes * 60
    start = time.time()
    hashcat_cmd_list = hashcat_cmd.build()
    process = subprocess.Popen(hashcat_cmd_list,
                               universal_newlines=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    for line in iter(process.stdout.readline, ''):
        with lock:
            if lock.cancelled:
                process.terminate()
                raise InterruptedError("Cancelled")
        time_spent = time.time() - start
        if time_spent > timeout_seconds:
            process.terminate()
            raise TimeoutError("Timed out {} sec".format(timeout_seconds))
        if line.startswith("STATUS"):
            parts = line.split()
            try:
                progress_index = parts.index("PROGRESS")
                tried_keys = parts[progress_index + 1]
                total_keys = parts[progress_index + 2]
                progress = 100. * int(tried_keys) / int(total_keys)
                with lock:
                    lock.progress = progress
            except ValueError or IndexError:
                # ignore this update
                pass
