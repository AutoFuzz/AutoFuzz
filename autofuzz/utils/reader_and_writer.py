# -*- coding: utf-8 -*-

import threading


class ReaderAndWriterIdentity:
    def __init__(self):
        self.r_mutex = threading.Semaphore(1)
        self.w_mutex = threading.Semaphore(1)
        self.r_list = []


class Reader:
    def __init__(self, identity, name=''):
        self.identity = identity
        self.name = name

    def __enter__(self):
        self.identity.r_mutex.acquire()
        self.identity.r_list.append(self.name)
        if len(self.identity.r_list) == 1:
            self.identity.w_mutex.acquire()
        self.identity.r_mutex.release()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.identity.r_mutex.acquire()
        self.identity.r_list.remove(self.name)
        if len(self.identity.r_list) == 0:
            self.identity.w_mutex.release()
        self.identity.r_mutex.release()


class Writer:
    def __init__(self, identity):
        self.identity = identity

    def __enter__(self):
        self.identity.w_mutex.acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.identity.w_mutex.release()


def ReaderDecorator(identity):
    def decorate(func):
        def wrapper(*args, **kwargs):
            with Reader(identity, func.__name__):
                _result = func(*args, **kwargs)
            return _result

        return wrapper

    return decorate


def WriterDecorator(identity):
    def decorate(func):
        def wrapper(*args, **kwargs):
            with Writer(identity):
                _result = func(*args, **kwargs)
            return _result

        return wrapper

    return decorate
