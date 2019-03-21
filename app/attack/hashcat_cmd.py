import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import Union, List

from app.config import HASHCAT_STATUS_TIMER
from app.domain import Rule, WordList, ProgressLock, TaskInfoStatus, Mask
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


class HashcatCmd:
    def __init__(self, outfile: Union[str, Path], hashcat_args=(), session=None):
        self.outfile = str(outfile)
        self.session = session
        self.rules = []
        self.wordlists = []
        self.mask = None
        self.hashcat_args = hashcat_args

    def build(self) -> List[str]:
        set_cuda_visible_devices()
        hashcat_mode = os.getenv('HASHCAT_MODE', '2500')
        command = ["hashcat", f"-m{hashcat_mode}", *self.hashcat_args]
        for rule in self.rules:
            if rule is not None:
                rule_path = str(rule.path)
                command.append("--rules={}".format(shlex.quote(rule_path)))
        command.append("--outfile={}".format(shlex.quote(self.outfile)))
        if self.session is not None:
            command.append("--session={}".format(shlex.quote(self.session)))
        self._populate_class_specific(command)
        if self.mask is not None:
            # masks are not compatible with wordlists
            command.extend(['-a3', self.mask])
        else:
            for word_list in self.wordlists:
                command.append(shlex.quote(word_list))
        return command

    def add_rule(self, rule: Rule):
        self.rules.append(rule)

    def add_wordlists(self, *wordlists: Union[WordList, str, Path], speial_args: List[str] = ()):
        wordlists_new = list(speial_args)
        for wlist in wordlists:
            if isinstance(wlist, WordList):
                wlist = wlist.path
            wordlists_new.append(str(wlist))
        self.wordlists.extend(wordlists_new)

    def set_mask(self, mask: Mask):
        self.mask = str(mask.path)

    def _populate_class_specific(self, command: List[str]):
        pass


class HashcatCmdCapture(HashcatCmd):
    def __init__(self, hcap_file: Union[str, Path], outfile: Union[str, Path], hashcat_args=(), session=None):
        super().__init__(outfile=outfile, hashcat_args=hashcat_args, session=session)
        self.hcap_file = str(hcap_file)

    def _populate_class_specific(self, command: List[str]):
        if int(os.getenv('POTFILE_DISABLE', 0)):
            # localhost debug mode
            command.append("--potfile-disable")
        command.append("--status")
        command.append("--status-timer={}".format(HASHCAT_STATUS_TIMER))
        command.append("--machine-readable")
        command.append(self.hcap_file)


class HashcatCmdStdout(HashcatCmd):
    def _populate_class_specific(self, command: List[str]):
        command.append('--stdout')


def run_with_status(hashcat_cmd: HashcatCmdCapture, lock: ProgressLock, timeout_minutes: int):
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
                raise InterruptedError(TaskInfoStatus.CANCELED)
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
