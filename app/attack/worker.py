import concurrent.futures
import datetime
import os
import re
from pathlib import Path
from tempfile import NamedTemporaryFile

from app import db, lock_app
from app.app_logger import logger
from app.attack.base_attack import BaseAttack, subprocess_call, monitor_timer
from app.attack.hashcat_cmd import run_with_status
from app.config import BENCHMARK_FILE
from app.domain import Rule, WordList, NONE_ENUM, ProgressLock, JobLock
from app.nvidia_smi import set_cuda_visible_devices
from app.uploader import UploadedTask
from app.utils import read_plain_key, date_formatted


class CapAttack(BaseAttack):

    def __init__(self, uploaded_task: UploadedTask, lock: ProgressLock, timeout: int):
        capture_path = Path(uploaded_task.filepath)
        super().__init__(hcap_file=capture_path.with_suffix('.hccapx'))
        self.lock = lock
        self.timeout = timeout
        self.capture_path = capture_path
        self.wordlist = None if uploaded_task.wordlist == NONE_ENUM else WordList(uploaded_task.wordlist)
        self.rule = None if uploaded_task.rule == NONE_ENUM else Rule(uploaded_task.rule)
        self.bssid = None
        self.essid = None

    @staticmethod
    def parse_bssid_essid(stdout: str):
        essid_key = "ESSID="
        bssid_key = "BSSID="
        mac_ap_len = 17
        for line in stdout.splitlines():
            if bssid_key in line:
                bssid_start = line.index(bssid_key) + mac_ap_len
                bssid = line[bssid_start: bssid_start + mac_ap_len]
                essid_start = line.index(essid_key) + len(essid_key)
                essid = line[essid_start: line.index(" (Length:", essid_start)]
                return bssid, essid
        raise ValueError("Could not parse ESSID")

    def is_attack_needed(self) -> bool:
        key_already_found = os.path.exists(self.key_file)
        with self.lock:
            if self.lock.cancelled:
                raise InterruptedError("Cancelled")
        return not key_already_found

    def read_key(self):
        key_password = None
        if os.path.exists(self.key_file):
            key_password = read_plain_key(self.key_file)
        with self.lock:
            self.lock.key = key_password
            self.lock.status = "Completed"
            self.lock.progress = 100

    def cap2hccapx(self):
        """
        Convert airodump's `.cap` to hashcat's `.hccapx`
        """
        with self.lock:
            self.lock.status = "Converting .cap to .hccapx"
        out, err = subprocess_call(['cap2hccapx', str(self.capture_path), str(self.hcap_file)])
        self.bssid, self.essid = self.parse_bssid_essid(out)
        if not os.path.exists(self.hcap_file):
            raise FileNotFoundError("cap2hccapx failed")
        else:
            cap2hccapx_status = re.search("Written \d WPA Handshakes", out)
            if cap2hccapx_status:
                cap2hccapx_status = cap2hccapx_status.group()
                n_handshakes = int(cap2hccapx_status.split()[1])
                if n_handshakes == 0:
                    raise Exception("No hashes loaded")

    def run_essid_attack(self):
        """
        Run ESSID + digits_append.txt combinator attack.
        Run ESSID + best64.rule attack.
        """
        if not self.is_attack_needed():
            return
        with self.lock:
            self.lock.status = "Running ESSID attack"
        with NamedTemporaryFile(mode='w') as f:
            f.writelines(self.collect_essid_parts(self.essid))
            f.seek(0)
            self._run_essid_digits(hcap_fpath=self.hcap_file, essid_wordlist_path=f.name)
            self._run_essid_rule(hcap_fpath=self.hcap_file, essid_wordlist_path=f.name)

    @monitor_timer
    def run_top4k(self):
        if not self.is_attack_needed():
            return
        with self.lock:
            self.lock.status = "Running top4k with rules"
        super().run_top4k()

    @monitor_timer
    def run_top304k(self):
        if not self.is_attack_needed():
            return
        with self.lock:
            self.lock.status = "Running top304k"
        super().run_top304k()

    @monitor_timer
    def run_digits8(self):
        if not self.is_attack_needed():
            return
        with self.lock:
            self.lock.status = "Running digits8"
        super().run_digits8()

    @monitor_timer
    def run_main_wordlist(self):
        """
        Run main attack, specified by the user through the client app.
        """
        if self.wordlist is None or not self.is_attack_needed():
            return
        with self.lock:
            self.lock.status = "Running main wordlist"
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlist(self.wordlist)
        hashcat_cmd.add_rule(self.rule)
        run_with_status(hashcat_cmd, lock=self.lock, timeout_minutes=self.timeout)


def _crack_async(attack: CapAttack):
    """
    Called in background process.
    :param attack: hashcat attack to crack uploaded capture
    """
    attack.cap2hccapx()
    attack.run_essid_attack()
    attack.run_bssid_attack(mac_ap=attack.bssid, hcap_fpath=attack.hcap_file)
    attack.run_top4k()
    attack.run_top304k()
    attack.run_digits8()
    attack.run_main_wordlist()
    attack.read_key()
    logger.info("Finished cracking {}".format(attack.capture_path))
    for name, timer in attack.timers.items():
        logger.debug("Timer {}: {:.2f} sec".format(name, timer['elapsed'] / timer['count']))


def _hashcat_benchmark_async():
    """
    Called in background process.
    """
    set_cuda_visible_devices()
    out, err = subprocess_call(['hashcat', '-m2500', "-b", "--machine-readable", "--quiet"])
    pattern = re.compile("\d+:2500:.*:.*:\d+\.\d+:\d+")
    total_speed = 0
    for line in filter(pattern.fullmatch, out.splitlines()):
        device_speed = int(line.split(':')[-1])
        total_speed += device_speed
    if total_speed > 0:
        snapshot = "{date},{speed}\n".format(date=date_formatted(), speed=total_speed)
        with lock_app, open(BENCHMARK_FILE, 'a') as f:
            f.write(snapshot)


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
        self.futures = {}
        self.locks = {}
        self.last_benchmark_call = datetime.datetime.now()
        if not os.path.exists(BENCHMARK_FILE):
            self.benchmark()

    def find_task_and_lock(self, job_id_query: int):
        task_id, lock = None, None
        for task_id, (job_id, lock) in self.locks.items():
            if job_id == job_id_query:
                break
        return task_id, lock

    def callback_attack(self, future: concurrent.futures.Future):
        exception = future.exception()
        if exception is not None:
            logger.error(exception)
        job_id = id(future)
        task_id, lock = self.find_task_and_lock(job_id_query=job_id)
        if lock is None:
            logger.error("Could not find lock for job {}".format(job_id))
            return
        task = UploadedTask.query.get(task_id)
        with lock:
            if exception is not None:
                lock.status = repr(exception)
            task.status = lock.status
            task.progress = lock.progress
            task.found_key = lock.key
            task.completed = lock.completed = True
        task.duration = datetime.datetime.now() - task.uploaded_time
        db.session.commit()

    def crack_capture(self, uploaded_task: UploadedTask, timeout: int):
        """
        Called in main process.
        Starts cracking .cap file in parallel process.
        :param uploaded_task: uploaded .cap file task
        :param timeout: brute force timeout in minutes
        """
        lock = ProgressLock()
        attack = CapAttack(uploaded_task, lock=lock, timeout=timeout)
        future = self.executor.submit(_crack_async, attack=attack)
        job_id = id(future)
        self.locks[uploaded_task.id] = JobLock(job_id=job_id, lock=lock)
        future.add_done_callback(self.callback_attack)
        self.futures[job_id] = future

    def benchmark(self):
        """
        Run hashcat WPA benchmark.
        """
        self.last_benchmark_call = datetime.datetime.now()
        self.executor.submit(_hashcat_benchmark_async)

    def terminate(self):
        futures_active = iter(future for future in self.futures if not future.done())
        for future in futures_active:
            future.cancel()
        subprocess_call(["pkill", "hashcat"])

    def cancel(self, task_id: int):
        # todo terminate pid
        if task_id not in self.locks:
            return False
        job_id, lock = self.locks[task_id]
        future = self.futures.get(job_id, None)
        if future is None:
            return False
        cancelled = future.cancel()
        if lock is not None:
            with lock:
                cancelled = lock.cancel()
        return cancelled

    def __del__(self):
        self.executor.shutdown(wait=False)
