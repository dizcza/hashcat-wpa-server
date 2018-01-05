import time
import os
import subprocess

from app.slack_sender import SlackSender
from app.nvidia_smi import set_cuda_visible_devices
from app.domain import Rule, WordList

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
    def __init__(self, hcap_file: str, outfile: str):
        self.hcap_file = hcap_file
        self.outfile = outfile
        self.status_timer = None
        self.rules = []
        self.wordlists = []
        self.custom_args = []
        self.is_machine_readable = False
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
        if self.status_timer is not None:
            self.is_machine_readable = True
            command.append("--status")
            command.append("--status-timer={}".format(self.status_timer))
        if self.is_machine_readable is True:
            command.append("--machine-readable")
        for arg in self.custom_args:
            command.append(arg)
        command.append(self.hcap_file)
        if not self.pipe_word_candidates:
            assert '|' not in command
            self._append_wordlists(command)
        return command

    def _append_wordlists(self, command: list):
        for word_list in self.wordlists:
            command.append(word_list.get_path())

    def set_status_timer(self, status_timer: int):
        self.status_timer = status_timer

    def add_rule(self, rule: Rule):
        self.rules.append(rule)

    def add_wordlist(self, wordlist: WordList):
        self.wordlists.append(wordlist)

    def add_custom_argument(self, argument: str):
        self.custom_args.append(argument)


class HashcatStatus(object):
    def __init__(self, slack_sender: SlackSender, timeout: int, status_timer: int):
        self.slack_sender = slack_sender
        self.timeout = timeout
        self.status_timer = status_timer
        self.status_log_path = os.path.join("logs", "status.txt")

    def run_with_status(self, hashcat_cmd: HashcatCmd):
        hashcat_cmd.set_status_timer(self.status_timer)
        start = time.time()
        hashcat_cmd_list = hashcat_cmd.build()
        process = subprocess.Popen(hashcat_cmd_list,
                                   universal_newlines=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        wordlist = ' '.join(wordl.value for wordl in hashcat_cmd.wordlists)
        progress = 0.
        logs = []
        for line in iter(process.stdout.readline, ''):
            time_spent = time.time() - start
            if time_spent > self.timeout:
                timedout_err = {
                    "progress": "{:.1f} %".format(progress * 100),
                    "reason": "timed-out ({} sec)".format(self.timeout),
                }
                self.slack_sender.send(timedout_err, "#errors")
                process.terminate()
                return
            if line.startswith("STATUS"):
                parts = line.split()
                try:
                    progress_index = parts.index("PROGRESS")
                    tried_keys = parts[progress_index + 1]
                    total_keys = parts[progress_index + 2]
                    progress = int(tried_keys) / int(total_keys)
                except ValueError or IndexError:
                    # ignore this update
                    pass
                status_message = {
                    hashcat_cmd.hcap_file: "[{:.1f} %] {}".format(progress * 100, ' '.join(parts)),
                    "wordlist": wordlist
                }
                self.slack_sender.send(status_message, "#status")
            elif line == '\n' or line.startswith("[s]tatus"):
                continue
            else:
                logs.append(line)
        if not os.getenv('PRODUCTION', False):
            out, err = process.communicate()
            warn, err = split_warnings_errors(err)
            logs.append(out)
            out = '\n'.join(logs)
            finished_message = {
                "command": "`{}`".format(' '.join(hashcat_cmd_list)),
                "warnings": warn,
                "errors": err,
                "progress": "{:.1f} %".format(progress * 100),
                "out": out
            }
            self.slack_sender.send(finished_message, "#hashcat")
