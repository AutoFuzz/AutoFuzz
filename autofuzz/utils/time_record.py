# -*- coding: utf-8 -*-

# Modified the code from the link below:
#   https://python3-cookbook.readthedocs.io/zh_CN/latest/c13/p13_making_stopwatch_timer.html

import datetime
import time


class TimerError(RuntimeError):
    pass


class TimeRecord:
    def __init__(self, func=time.perf_counter, *, elapsed=0.0):
        self.elapsed = elapsed
        self._func = func
        self._start = None

    def start(self):
        if self._start is not None:
            return
        self._start = self._func()

    def stop(self):
        if self._start is None:
            return
        end = self._func()
        self.elapsed += end - self._start
        self._start = None

    def get_elapsed_without_stop(self):
        if self._start is None:
            return self.elapsed
        else:
            return self.elapsed + (self._func() - self._start)

    def reset(self):
        self.elapsed = 0.0

    @property
    def running(self):
        return self._start is not None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()

    def __float__(self):
        return self.elapsed

    def __int__(self):
        return int(self.elapsed)

    def __add__(self, other):
        if isinstance(other, TimeRecord):
            return TimeRecord(func=self._func, elapsed=(self.elapsed + float(other)))
        else:
            return NotImplemented

    def __sub__(self, other):
        if isinstance(other, TimeRecord):
            return TimeRecord(func=self._func, elapsed=(self.elapsed - float(other)))
        else:
            return NotImplemented

    def __str__(self):
        return '%s' % datetime.timedelta(seconds=int(self.elapsed))


def TimeRecordDecorator(time_record):
    def decorate(func):
        def wrapper(*args, **kwargs):
            with time_record:
                _result = func(*args, **kwargs)
            return _result

        return wrapper

    return decorate
