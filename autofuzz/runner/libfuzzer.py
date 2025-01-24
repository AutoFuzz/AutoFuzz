# -*- coding: utf-8 -*-

import logging
import os
import shlex
import subprocess
import time
from distutils.dir_util import copy_tree

import psutil

import autofuzz.config as config
from autofuzz.base_runner import BaseRunner
from autofuzz.utils.placeholder_replacer import placeholder_replacer


class LibFuzzer(BaseRunner):
    force_disable_SIGUSR2 = True

    def __init__(self, name, shell_command, startup_time, additional_env, progress_recovery_path, cpu, seed_path):
        super().__init__(name, shell_command, startup_time, additional_env, progress_recovery_path, cpu, seed_path)

        self._seeds_path = os.path.join(progress_recovery_path, self.name, 'seeds')
        self._crash_path = os.path.join(progress_recovery_path, self.name, 'crashes')

        try:
            os.makedirs(self._seeds_path)
        except FileExistsError:
            pass
        try:
            os.makedirs(self._crash_path)
        except FileExistsError:
            pass

        logging.debug(f'Runner({self.name}) prepare init seed')
        copy_tree(seed_path, self._seeds_path)

        command = placeholder_replacer(shell_command, {'b': cpu, 'i': self._seeds_path, 'c': self._crash_path + '/'})

        logging.debug(f'Runner({self.name}) start run command: {command}')

        f = open(os.path.join(progress_recovery_path, self.name, 'stdout'), 'ab')

        try:
            x = subprocess.Popen(
                shlex.split(command),
                cwd=os.path.join(progress_recovery_path, self.name, 'cwd'),
                env={**os.environ, **additional_env},
                stdout=f,
                stderr=subprocess.STDOUT,
            )
            if x.pid > 0:
                self.pid = x.pid
            else:
                raise config.RunnerStartupFailed()

            class StartFinished(Exception):
                pass

            try:
                while startup_time != 0:
                    time.sleep(1)
                    if config.exit_prepare.is_set():
                        break
                    try:
                        pro = psutil.Process(self.pid)
                        if pro.status() == psutil.STATUS_ZOMBIE:
                            raise config.RunnerStartupFailed()
                    except psutil.NoSuchProcess:
                        raise config.RunnerStartupFailed()
                    try:
                        f.flush()
                        with open(os.path.join(progress_recovery_path, self.name, 'stdout')) as stats:
                            for line in stats.readlines():
                                if line.startswith('#'):
                                    logging.debug(f'{self.name} get started.')
                                    raise StartFinished()
                    except (FileNotFoundError, ValueError):
                        pass
                    if startup_time > 0:
                        startup_time -= 1
                else:
                    raise config.RunnerStartupFailed()
            except StartFinished:
                pass
        except FileNotFoundError as e:
            logging.warning(f'{self.name} failed to start!')
            logging.info(f'Could not found fuzzer: {e.filename}')
            raise config.RunnerStartupFailed()
        except config.RunnerStartupFailed:
            logging.warning(f'{self.name} failed to start!')
            x.kill()
            with open(os.path.join(progress_recovery_path, self.name, 'stdout'), 'r') as f:
                logging.info(f'\nCommand of {self.name}:\n{command}' f'\nOutput of {self.name}:\n{f.read()}')
            print('\033[0m', end='')
            raise config.RunnerStartupFailed()

    def add_seeds(self, seeds):
        pass  # Not implemented yet
