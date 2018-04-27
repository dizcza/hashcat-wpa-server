import concurrent.futures
import os
import re
import subprocess
import time
from collections import namedtuple, defaultdict
from functools import partial

from app import utils
from app.app_logger import logger
from app.domain import Rule, WordList, UploadForm
from app.hashcat_cmd import HashcatStatus, HashcatCmd
from app.nvidia_smi import set_cuda_visible_devices
from app.slack_sender import SlackSender
from app.utils import split_uppercase

Benchmark = namedtuple("Benchmark", ("speed", "gpus"))


def subprocess_call(args, slack_sender: SlackSender = None):
    """
    Called in background process.
    :param args: shell args
    :param slack_sender: SlackSender
    """
    logger.debug(">>> {}".format(' '.join(args)))
    process = subprocess.Popen(args,
                               universal_newlines=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    out, err = process.communicate()
    if slack_sender is not None:
        log_message = {
            "command": "`{}`".format(' '.join(args)),
            "out": out,
            "err": err,
        }
        channel = '#' + args[0]
        slack_sender.send(log_message, channel)
    return out, err


def monitor_timer(func):
    def wrapped(*args, **kwargs):
        start = time.time()
        res = func(*args, **kwargs)
        elapsed_sec = time.time() - start
        timer = Attack.timers[func.__name__]
        timer['count'] += 1
        timer['elapsed'] += elapsed_sec
        return res
    return wrapped


class Attack(object):

    timers = defaultdict(lambda: dict(count=0, elapsed=1e-6))

    def __init__(self, upload_form: UploadForm, status_timer: int):
        self.upload_form = upload_form
        self.slacker = SlackSender()
        self.hashcat_status = HashcatStatus(self.slacker, upload_form.timeout_seconds, status_timer)
        self.response = {
            'capture': upload_form.capture_path,
        }
        self.essid = None
        self.key_file = self.as_capture(".key")
        self.hcap_file = self.as_capture(".hccapx")
        self.new_cmd = partial(HashcatCmd, hcap_file=self.hcap_file, outfile=self.key_file)

    def as_capture(self, new_ext: str) -> str:
        """
        :param new_ext: new file extension path
        :return: capture filepath with the new extension
        """
        assert new_ext.startswith('.'), "Invalid new file extension"
        base = os.path.splitext(os.path.basename(self.upload_form.capture_path))[0]
        new_file = os.path.join(os.path.dirname(self.upload_form.capture_path), "{}{}".format(base, new_ext))
        return new_file

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

    def is_already_cracked(self):
        return os.path.exists(self.key_file)

    def is_attack_needed(self):
        return os.path.exists(self.hcap_file) and not self.is_already_cracked()

    def send_response(self):
        channel = "#general"
        if self.is_already_cracked():
            with open(self.key_file, 'r') as f:
                key_password = f.read()
            self.response['key'] = key_password
            channel = "#cracked"
        elif not os.path.exists(self.hcap_file) or self.essid is None:
            self.response['status'] = "0 WPA handshakes captured"
        else:
            self.response['status'] = "No key found"
        self.slacker.send(self.response, channel)

    def cap2hccapx(self):
        """
        Convert airodump's `.cap` to hashcat's `.hccapx`
        """
        out, err = subprocess_call(['cap2hccapx', self.upload_form.capture_path, self.hcap_file],
                                   slack_sender=self.slacker)
        self.essid = self.parse_essid(out)
        if not os.path.exists(self.hcap_file):
            self.response['reason'] = "cap2hccapx failed"
            self.slacker.send(self.response, channel="#errors")

    def run_essid_attack(self):
        """
        Run ESSID + digits_append.txt combinator attack.
        Run ESSID + best64.rule attack.
        """
        if self.essid is None:
            return
        if not self.is_attack_needed():
            return

        def modify_case(word):
            return {word, word.lower(), word.upper(), word.capitalize(), word.lower().capitalize()}

        essid_parts = {self.essid}
        regex_non_char = re.compile('[^a-zA-Z]')
        essid_parts.update(regex_non_char.split(self.essid))
        essid_parts.update(split_uppercase(self.essid))
        essids_case_insensitive = set()
        for essid in essid_parts:
            essid = regex_non_char.sub('', essid)
            essids_case_insensitive.update(modify_case(essid))
        essids_case_insensitive.update(modify_case(self.essid))
        essids_case_insensitive = filter(len, essids_case_insensitive)
        with open(WordList.ESSID.get_path(), 'w') as f:
            f.writelines([essid + '\n' for essid in essids_case_insensitive])
        self._run_essid_digits()
        self._run_essid_rule()

    @monitor_timer
    def _run_essid_digits(self):
        """
        Run ESSID + digits_append.txt combinator attack.
        """
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlist(WordList.ESSID)
        hashcat_cmd.add_wordlist(WordList.DIGITS_APPEND)
        hashcat_cmd.add_custom_argument("-a1")
        subprocess_call(hashcat_cmd.build(), self.slacker)

    @monitor_timer
    def _run_essid_rule(self):
        """
        Run ESSID + best64.rule attack.
        """
        hashcat_cmd = self.new_cmd()
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
        if not self.is_attack_needed():
            return
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlist(WordList.DIGITS_8)
        self.hashcat_status.run_with_status(hashcat_cmd)

    @monitor_timer
    def run_weak_passwords(self):
        """
        Run weak password attack, using a very shallow yet commonly used dictionaries:
        - john.txt
        - conficker.txt
        """
        if not self.is_attack_needed():
            return
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlist(WordList.WEAK)
        hashcat_cmd.add_rule(Rule.BEST_64)
        hashcat_cmd.pipe_word_candidates = True
        hashcat_cmd = ' '.join(hashcat_cmd.build())
        os.system(hashcat_cmd)

    @monitor_timer
    def run_main_wordlist(self):
        """
        Run main attack, specified by the user through the client app.
        """
        if self.upload_form.wordlist is None or not self.is_attack_needed():
            return
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlist(self.upload_form.wordlist)
        hashcat_cmd.add_rule(self.upload_form.rule)
        self.hashcat_status.run_with_status(hashcat_cmd)


def _crack_async(upload_form: UploadForm, status_timer: int):
    """
    Called in background process.
    :param upload_form: received upload form
    :param status_timer: delay to notify status, seconds
    """
    attack = Attack(upload_form, status_timer)
    attack.cap2hccapx()
    attack.run_essid_attack()
    attack.run_weak_passwords()
    attack.run_digits8()
    attack.run_main_wordlist()
    attack.send_response()
    logger.info("Finished cracking {}".format(upload_form.capture_path))
    for name, timer in attack.timers.items():
        logger.debug("Timer {}: {:.2f} sec".format(name, timer['elapsed'] / timer['count']))


def _hashcat_benchmark_async() -> Benchmark:
    """
    Called in background process.
    """
    gpus = set_cuda_visible_devices()
    out, err = subprocess_call(['hashcat', '-m2500', "-b", "--machine-readable"])
    pattern = re.compile("\d+:2500:.*:.*:\d+\.\d+:\d+")
    total_speed = 0
    for line in filter(pattern.fullmatch, out.splitlines()):
        device_speed = int(line.split(':')[-1])
        total_speed += device_speed
    benchmark = Benchmark(total_speed, gpus)
    return benchmark


class HashcatWorker(object):
    def __init__(self, app):
        """
        Called in main process.
        :param app: flask app
        """
        # we don't need more than 1 thread since hashcat utilizes all devices at once
        self.workers = 1
        self.app = app
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.workers)
        self.futures = []
        self.slack_sender = SlackSender()
        self.status_timer = self.app.config['HASHCAT_STATUS_TIMER']

    def exception_callback(self, future):
        """
        Called in main process.
        :param future:
        """
        exception = future.exception()
        if exception is None:
            return
        logger.error(exception)
        error_response = {
            "error": exception,
        }
        self.slack_sender.send(error_response, "#errors")

    def callback_benchmark(self, future: concurrent.futures.Future):
        """
        Called in main process.
        :param future: Future of total WPA crack speed (hashes per second)
        """
        if future.cancelled():
            return
        benchmark = future.result()
        logger.info(benchmark)
        utils.BENCHMARK_SPEED = benchmark.speed
        benchmark_message = {"speed": benchmark.speed, "gpus": benchmark.gpus}
        self.slack_sender.send(benchmark_message, channel="#benchmark")

    def crack_capture(self, upload_form: UploadForm):
        """
        Called in main process.
        Starts cracking .cap file in parallel process.
        :param upload_form: received upload form
        """
        future = self.executor.submit(_crack_async, upload_form, self.status_timer)
        future.add_done_callback(self.exception_callback)
        self.futures.append(future)

    def benchmark(self):
        """
        Run hashcat WPA benchmark.
        """
        future = self.executor.submit(_hashcat_benchmark_async)
        future.add_done_callback(self.exception_callback)
        future.add_done_callback(self.callback_benchmark)
        self.futures.append(future)

    def terminate(self):
        futures_active = iter(future for future in self.futures if not future.done())
        for future in futures_active:
            future.cancel()
        subprocess_call(["pkill", "hashcat"])

    def __del__(self):
        self.executor.shutdown(wait=False)
