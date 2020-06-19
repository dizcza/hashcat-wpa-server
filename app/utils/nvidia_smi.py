import os
import subprocess
import time
from functools import wraps


class Cache:

    _caches = {}

    def __init__(self, name: str, timeout: int):
        """
        :param timeout: cache timeout in seconds
        """
        self.timeout = timeout
        self.last_call = float("-inf")
        self.cached_result = None
        self._caches[name] = self

    def reset(self):
        self.last_call = float("-inf")
        self.cached_result = None

    def need_update(self) -> bool:
        return time.time() > self.last_call + self.timeout

    def __call__(self, func):
        @wraps(func)
        def decorated(*args, **kwargs):
            if self.need_update():
                self.cached_result = func(*args, **kwargs)
                self.last_call = time.time()
            return self.cached_result

        return decorated

    @staticmethod
    def clear_cache(name: str):
        Cache._caches[name].reset()


class GpuInfo:
    def __init__(self, index, memory_total, memory_used, gpu_load):
        """
        :param index: GPU index
        :param memory_total: total GPU memory, Mb
        :param memory_used: GPU memory already in use, Mb
        :param gpu_load: gpu utilization load, percents
        """
        self.index = int(index)
        self.memory_total = int(memory_total)
        self.memory_used = int(memory_used)
        try:
            self.gpu_load = int(gpu_load) / 100.
        except ValueError:
            # gpu utilization load is not supported in current driver
            self.gpu_load = 0.

    def __repr__(self):
        return "GPU #{}: memory total={} Mb, used={} Mb ({:.1f} %), gpu.load={}".format(
            self.index, self.memory_total, self.memory_used, 100. * self.memory_used / self.memory_total, self.gpu_load)

    def get_available_memory_portion(self):
        return (self.memory_total - self.memory_used) / self.memory_total


class NvidiaSmi:

    @staticmethod
    @Cache(name="NvidiaSmi", timeout=10)
    def get_gpus(min_free_memory=0., max_load=1.):
        """
        :param min_free_memory: filter GPUs with free memory no less than specified, between 0 and 1
        :param max_load: max gpu utilization load, between 0 and 1
        :return: list of available GpuInfo's
        """
        command = "nvidia-smi --query-gpu=index,memory.total,memory.used,utilization.gpu --format=csv,noheader,nounits".split()
        gpus = []
        try:
            process = subprocess.Popen(command,
                                       universal_newlines=True,
                                       stdout=subprocess.PIPE)
            stdout, stderr_ignored = process.communicate()
            for line in stdout.splitlines():
                index, memory_total, memory_used, gpu_load = line.split(', ')
                gpu = GpuInfo(index, memory_total, memory_used, gpu_load)
                gpus.append(gpu)
        except FileNotFoundError:
            # No GPU is detected. Try running `nvidia-smi` in a terminal."
            pass

        gpus = [gpu for gpu in gpus if gpu.get_available_memory_portion() >= min_free_memory and
                gpu.gpu_load <= max_load]

        return gpus


def set_cuda_visible_devices(limit_devices=None, min_free_memory=0.4, max_load=0.6) -> list:
    """
    Automatically sets CUDA_VISIBLE_DEVICES env to first `limit_devices` available GPUs with least used memory.
    :param limit_devices: limit available GPU devices to use
    :param min_free_memory: filter GPUs with free memory no less than specified, between 0 and 1
    :param max_load: max gpu utilization load, between 0 and 1
    """
    Cache.clear_cache("NvidiaSmi")
    gpus = NvidiaSmi.get_gpus(min_free_memory, max_load)
    gpus.sort(key=lambda gpu: gpu.get_available_memory_portion(), reverse=True)
    if limit_devices:
        limit_devices = min(limit_devices, len(gpus))
        gpus = gpus[:limit_devices]
    gpus_id = [str(gpu.index) for gpu in gpus]
    os.environ["CUDA_VISIBLE_DEVICES"] = ','.join(gpus_id)
    return gpus
