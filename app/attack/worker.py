import concurrent.futures
import re
import time
from pathlib import Path

from app import db, lock_app
from app.attack.base_attack import BaseAttack, monitor_timer
from app.attack.hashcat_cmd import run_with_status, HashcatCmdCapture
from app.config import BENCHMARK_FILE
from app.domain import Rule, TaskInfoStatus, InvalidFileError, ProgressLock
from app.logger import logger
from app.uploader import UploadForm, UploadedTask
from app.utils import read_plain_key, date_formatted, subprocess_call, read_hashcat_brain_password


class CapAttack(BaseAttack):

    def __init__(self, file_22000, lock: ProgressLock, wordlist: Path = None, rule: Rule = None, hashcat_args='', timeout=None):
        super().__init__(file_22000=file_22000,
                         hashcat_args=hashcat_args.split(' '),
                         verbose=False)
        self.lock = lock
        self.timeout = timeout
        self.wordlist = wordlist
        self.rule = rule

    def cancel_if_needed(self):
        with self.lock:
            if self.lock.cancelled:
                raise InterruptedError(TaskInfoStatus.CANCELLED)

    def is_attack_needed(self) -> bool:
        self.cancel_if_needed()
        return not self.key_file.exists()

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
        if not self.wordlist.exists():
            with self.lock:
                self.lock.set_status("Downloading the wordlist")
            while not self.wordlist.exists():
                time.sleep(5)
                self.cancel_if_needed()
        with self.lock:
            self.lock.set_status(f"Running the main wordlist")
        hashcat_cmd = self.new_cmd()
        hashcat_cmd.add_wordlists(self.wordlist)
        hashcat_cmd.add_rule(self.rule)
        run_with_status(hashcat_cmd, lock=self.lock, timeout_minutes=self.timeout)

    def run_all(self):
        """
        Run all attacks.
        """
        with self.lock:
            task_id = self.lock.task_id
        with lock_app:
            task = UploadedTask.query.get(task_id)
            task.status = TaskInfoStatus.RUNNING
            db.session.commit()
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
    logger.info(f"Finished cracking {attack.file_22000}")
    for name, timer in attack.timers.items():
        elapsed = timer['elapsed'] / timer['count']
        logger.debug(f"Timer {name}: {elapsed:.2f} sec")


def _hashcat_benchmark_async():
    """
    Called in background process.
    """
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
        hashcat_args = f"--workload-profile={uploaded_form.workload.data} {task.hashcat_args}"
        if uploaded_form.brain.data:
            # --brain-client is already there
            hashcat_args = f"{hashcat_args} --brain-password={read_hashcat_brain_password()}"
        wordlist_path = uploaded_form.get_wordlist_path()
        rule = uploaded_form.get_rule()
        try:
            attack = CapAttack(file_22000=file_22000, lock=lock, wordlist=wordlist_path, rule=rule, hashcat_args=hashcat_args, timeout=uploaded_form.timeout.data)
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
