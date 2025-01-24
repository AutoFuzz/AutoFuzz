# -*- coding: utf-8 -*-

# Modified the code from the link below:
#   https://stackoverflow.com/a/45920584

from autofuzz.config import TaskQueueExit


def get_from_queue(q, *args, **kwargs):
    while True:
        _return = q.get(*args, **kwargs)
        try:
            if isinstance(_return, TaskQueueExit):
                q.put(TaskQueueExit())
                return
            else:
                yield _return
        finally:
            q.task_done()
