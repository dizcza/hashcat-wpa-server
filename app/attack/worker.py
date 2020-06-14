import concurrent.futures
import datetime
import re

from app import db, lock_app
from app.app_logger import logger
from app.attack.base_attack import BaseAttack, monitor_timer
from app.attack.hashcat_cmd import run_with_status, HashcatCmdCapture
from app.config import BENCHMARK_FILE, TIMEOUT_HASHCAT_MINUTES
from app.domain import Rule, WordList, NONE_ENUM, TaskInfoStatus, InvalidFileError, ProgressLock
from app.nvidia_smi import set_cuda_visible_devices
from app.uploader import UploadForm, UploadedTask
from app.utils import read_plain_key, date_formatted, subprocess_call


class CapAttack(BaseAttack):

    def __init__(self, file_22000, lock: ProgressLock, wordlist: WordList = None, rule: Rule = None, hashcat_args='', timeout=TIMEOUT_HASHCAT_MINUTES):
        super().__init__(file_22000=file_22000,
                         hashcat_args=hashcat_args.split(' '),
                         verbose=False)
        self.lock = lock
        self.timeout = timeout
        self.wordlist = wordlist
        self.rule = rule

    def is_attack_needed(self) -> bool:
        key_already_found = self.key_file.exists()
        with self.lock:
            if self.lock.cancelled:
                raise InterruptedError(TaskInfoStatus.CANCELLED)
        return not key_already_found

    def read_key(self):
        dump_keys_cmd = HashcatCmdCapture(self.file_22000, outfile=self.key_file, hashcat_args=['--show'])
        subprocess_call(dump_keys_cmd.build())
        key_password = read_plain_key(self.key_file)
        with self.lock:
            self.lock.found_key = key_password

    def check_not_empty(self):
        """
        Check .hccapx file for hashes.
        """
        file_size = self.file_22000.stat().st_size
        if file_size == 0:
            raise InvalidFileError("No hashes found")

    def run_essid_attack(self):
        """
        Run ESSID + digits_append.txt combinator attack.
        Run ESSID + best64.rule attack.
        """
        if not self.is_attack_needed():
            return
        with self.lock:
            self.lock.set_status("Running ESSID attack")
        super().run_essid_attack()

    @monitor_timer
    def run_top1k(self):
        if not self.is_attack_needed():
            return
        with self.lock:
            self.lock.set_status("Running top1k with rules")
        super().run_top1k()

    @monitor_timer
    def run_top304k(self):
        if not self.is_attack_needed():
            return
        with self.lock:
            self.lock.set_status("Running top304k")
        super().run_top304k()

    @monitor_timer
    def run_digits8(self):
        if not self.is_attack_needed():
            return
        with self.lock:
            self.lock.set_status("Running digits8")
        super().run_digits8()

    @monitor_timer
    def run_main_wordlist(self):
        """
        Run main attack, specified by the user through the client app.
        """
        if self.wordlist is None or not self.is_attack_needed():
            return
        with self.lock:
            self.lock.set_status(f"Running {self.wordlist.value}")
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
    attack.check_not_empty()
    attack.run_all()
    attack.read_key()
    logger.info("Finished cracking {}".format(attack.file_22000))
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
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.app = app
        self.locks = {}
        self.locks_onetime = []
        self.last_benchmark_call = datetime.datetime.now()
        if not BENCHMARK_FILE.exists():
            self.benchmark()

    def callback_attack(self, future: concurrent.futures.Future):
        # called when the future is done or cancelled
        try:
            exception = future.exception()
        except concurrent.futures.CancelledError as cancelled_error:
            exception = None
        if exception is not None:
            logger.exception(repr(exception), exc_info=False)
        job_id = id(future)
        lock = self.locks.pop(job_id, None)
        if lock is None:
            logger.error("Could not find lock for job {}".format(job_id))
            return
        with lock:
            if future.cancelled():
                lock.set_status(TaskInfoStatus.CANCELLED)
            else:
                lock.set_status(TaskInfoStatus.COMPLETED)
            if exception is not None:
                lock.set_status(repr(exception))
            lock.finish()
            update_dict = lock.update_dict()
            task_id = lock.task_id
        UploadedTask.query.filter_by(id=task_id).update(update_dict)
        db.session.commit()
        self.locks_onetime.append(lock)

    def submit_capture(self, file_22000, uploaded_form: UploadForm, task: UploadedTask):
        """
        Called in main process.
        Starts cracking .cap file in parallel process.
        :param uploaded_task: uploaded .cap file task
        :param timeout: brute force timeout in minutes
        """
        lock = ProgressLock(task_id=task.id)
        hashcat_args = task.hashcat_args
        wordlist = None if task.wordlist == NONE_ENUM else WordList(task.wordlist)
        rule = None if task.rule == NONE_ENUM else Rule(task.rule)
        try:
            attack = CapAttack(file_22000=file_22000, lock=lock, wordlist=wordlist, rule=rule, hashcat_args=hashcat_args, timeout=uploaded_form.timeout.data)
        except InvalidFileError:
            with lock:
                lock.cancel()
                lock.set_status(TaskInfoStatus.REJECTED)
            db.session.commit()
            return
        future = self.executor.submit(_crack_async, attack=attack)
        future.add_done_callback(self.callback_attack)
        with lock:
            lock.future = future
        self.locks[id(future)] = lock

    def benchmark(self):
        """
        Run hashcat WPA benchmark.
        """
        self.last_benchmark_call = datetime.datetime.now()
        self.executor.submit(_hashcat_benchmark_async)

    def terminate(self):
        for lock in tuple(self.locks.values()):
            with lock:
                lock.cancel()
        subprocess_call(["pkill", "hashcat"])
        self.locks.clear()

    def cancel(self, task_id: int):
        for job_id, lock in tuple(self.locks.items()):
            with lock:
                if lock.task_id == task_id:
                    return lock.cancel()
        return False

    def __del__(self):
        self.executor.shutdown(wait=False)
