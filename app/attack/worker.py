import concurrent.futures
import datetime
import re
import shlex
from pathlib import Path

from app import db, lock_app
from app.app_logger import logger
from app.attack.base_attack import BaseAttack, monitor_timer
from app.attack.hashcat_cmd import run_with_status
from app.config import BENCHMARK_FILE, AIRODUMP_SUFFIX, HCCAPX_SUFFIX
from app.domain import Rule, WordList, NONE_ENUM, ProgressLock, JobLock, TaskInfoStatus
from app.nvidia_smi import set_cuda_visible_devices
from app.uploader import UploadedTask
from app.utils import read_plain_key, date_formatted, subprocess_call, wlanhcxinfo


class CapAttack(BaseAttack):

    def __init__(self, uploaded_task: UploadedTask, lock: ProgressLock, timeout: int):
        capture_path = Path(shlex.quote(uploaded_task.filepath))
        super().__init__(hcap_file=capture_path.with_suffix('.hccapx'), verbose=False)
        self.lock = lock
        self.timeout = timeout
        self.capture_path = capture_path
        self.wordlist = None if uploaded_task.wordlist == NONE_ENUM else WordList(uploaded_task.wordlist)
        self.rule = None if uploaded_task.rule == NONE_ENUM else Rule(uploaded_task.rule)

    def is_attack_needed(self) -> bool:
        key_already_found = self.key_file.exists()
        with self.lock:
            if self.lock.cancelled:
                raise InterruptedError(TaskInfoStatus.CANCELED)
        return not key_already_found

    def read_key(self):
        key_password = None
        if self.key_file.exists():
            key_password = read_plain_key(self.key_file)
        with self.lock:
            self.lock.key = key_password
            self.lock.status = TaskInfoStatus.COMPETED
            self.lock.progress = 100

    def cap2hccapx(self):
        """
        Convert airodump's `.cap` to hashcat's `.hccapx`
        """
        with self.lock:
            self.lock.status = "Converting .cap to .hccapx"

        if self.capture_path.suffix == AIRODUMP_SUFFIX:
            subprocess_call(['cap2hccapx', str(self.capture_path), str(self.hcap_file)])
        elif self.capture_path.suffix == HCCAPX_SUFFIX:
            self.hcap_file = self.capture_path
        else:
            raise ValueError("Invalid capture file extension")

        if not self.hcap_file.exists():
            raise FileNotFoundError("cap2hccapx failed")

    def check_hccapx(self):
        """
        Check .hccapx file for hashes.
        """
        file_size = self.hcap_file.stat().st_size
        if file_size == 0:
            raise Exception("No hashes found")

    def run_essid_attack(self):
        """
        Run ESSID + digits_append.txt combinator attack.
        Run ESSID + best64.rule attack.
        """
        if not self.is_attack_needed():
            return
        with self.lock:
            self.lock.status = "Running ESSID attack"
        super().run_essid_attack()
        bssid_essid_pairs = wlanhcxinfo(self.hcap_file, '-ae')
        bssids, essids = [], []
        for bssid_essid in bssid_essid_pairs:
            _bssid, _essid = bssid_essid.split(':')
            bssids.append(_bssid)
            essids.append(_essid)
        with self.lock:
            self.lock.bssid = ', '.join(bssids)
            self.lock.essid = ', '.join(essids)

    @monitor_timer
    def run_top1k(self):
        if not self.is_attack_needed():
            return
        with self.lock:
            self.lock.status = "Running top1k with rules"
        super().run_top1k()

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
        hashcat_cmd.add_wordlists(self.wordlist)
        hashcat_cmd.add_rule(self.rule)
        run_with_status(hashcat_cmd, lock=self.lock, timeout_minutes=self.timeout)

    def run_all(self):
        """
        Run all attacks.
        """
        super().run_all()
        self.run_main_wordlist()


def _crack_async(attack: CapAttack):
    """
    Called in background process.
    :param attack: hashcat attack to crack uploaded capture
    """
    attack.cap2hccapx()
    attack.check_hccapx()
    attack.run_all()
    attack.read_key()
    logger.info("Finished cracking {}".format(attack.capture_path))
    for name, timer in attack.timers.items():
        logger.debug("Timer {}: {:.2f} sec".format(name, timer['elapsed'] / timer['count']))


def _hashcat_benchmark_async():
    """
    Called in background process.
    """
    set_cuda_visible_devices()
    out, err = subprocess_call(['hashcat', '-m2500', "-b", "--machine-readable", "--quiet", "--force"])
    pattern = re.compile("\d+:2500:.*:.*:\d+\.\d+:\d+")
    total_speed = 0
    for line in filter(pattern.fullmatch, out.splitlines()):
        device_speed = int(line.split(':')[-1])
        total_speed += device_speed
    if total_speed > 0:
        snapshot = "{date},{speed}\n".format(date=date_formatted(), speed=total_speed)
        with lock_app, open(BENCHMARK_FILE, 'a') as f:
            f.write(snapshot)


class HashcatWorker:
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
        if not BENCHMARK_FILE.exists():
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
            task.essid = lock.essid
            task.bssid = lock.bssid
        task.duration = datetime.datetime.now() - task.uploaded_time
        db.session.commit()

    def submit_capture(self, uploaded_task: UploadedTask, timeout: int):
        """
        Called in main process.
        Starts cracking .cap file in parallel process.
        :param uploaded_task: uploaded .cap file task
        :param timeout: brute force timeout in minutes
        """
        lock = ProgressLock()
        try:
            attack = CapAttack(uploaded_task, lock=lock, timeout=timeout)
        except ValueError:
            uploaded_task.status = TaskInfoStatus.REJECTED
            uploaded_task.completed = True
            db.session.commit()
            return
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
        self.terminate()
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
                lock.completed = True
        return cancelled

    def __del__(self):
        self.executor.shutdown(wait=False)
