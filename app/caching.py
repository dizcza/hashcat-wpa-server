import time
from functools import wraps


class Cache(object):

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
