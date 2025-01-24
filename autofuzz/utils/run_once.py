# -*- coding: utf-8 -*-

# Modified the code from the link below:
#   https://stackoverflow.com/a/4104188

import threading


def RunOnce(f):
    def wrapper(*args, **kwargs):
        _return = None
        if wrapper.has_run.acquire(blocking=False):
            try:
                _return = f(*args, **kwargs)
            finally:
                wrapper.has_run.release()
        return _return

    wrapper.has_run = threading.Lock()
    return wrapper
