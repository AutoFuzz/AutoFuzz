# -*- coding: utf-8 -*-

import logging
import os
import shlex
import subprocess
import time
from collections import defaultdict
from copy import copy

import autofuzz.config as config
import psutil
from autofuzz.base_runner import BaseRunner
from autofuzz.utils.placeholder_replacer import placeholder_replacer


class AFL(BaseRunner):
    def __init__(self, name, shell_command, startup_time, additional_env, progress_recovery_path, cpu, seed_path):
        super().__init__(name, shell_command, startup_time, additional_env, progress_recovery_path, cpu, seed_path)

        self._seeds_path = os.path.join(progress_recovery_path, self.name, 'queue')
        self._crash_path = os.path.join(progress_recovery_path, self.name, 'crashes')
        self.__stats_path = os.path.join(progress_recovery_path, self.name, 'fuzzer_stats')
        self.__last_stats_data = defaultdict(float)

        self.get_seeds_increase()

        command = placeholder_replacer(
            shell_command,
            {
                'b': cpu,
                'n': self.name,
                'i': seed_path,
                'o': progress_recovery_path,
            },
        )

        logging.debug(f'Runner({self.name}) start run command: {command}')

        try:
            os.remove(self.__stats_path)
        except FileNotFoundError:
            pass

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
                        with open(self.__stats_path) as stats:
                            for line in stats.readlines():
                                if (line.split(':')[0].strip() == 'fuzzer_pid') and (
                                    int(line.split(':')[1].strip()) == self.pid
                                ):
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

    def get_data_from_stats(self):
        useful = ['execs_done']
        total_stats_data = defaultdict(str)
        with open(self.__stats_path) as stats:
            lines = stats.readlines()
            for line in lines:
                if ':' in line:
                    k = [i.strip() for i in line.split(':')]
                    total_stats_data[k[0]] = k[1]
        increase_stats_data = defaultdict(
            float,
            {
                k: float(float(v if v != '' else '0') - float(self.__last_stats_data[k]))
                for k, v in total_stats_data.items()
                if k in useful
            },
        )
        self.__last_stats_data = copy(total_stats_data)
        total_stats_data['New_Seeds'] = self._new_seeds_count
        total_stats_data['Total_Input_Analyzed_Crash'] = self._new_crashes_count
        self._new_seeds_count = 0
        self._new_crashes_count = 0
        return increase_stats_data, total_stats_data

    def list_all_seeds(self):
        try:
            return (os.path.join(self._seeds_path, f) for f in os.listdir(self._seeds_path) if f.startswith('id:'))
        except FileNotFoundError:
            return []

    def list_all_crashes(self):
        try:
            return (os.path.join(self._crash_path, f) for f in os.listdir(self._crash_path) if f != 'README.txt')
        except FileNotFoundError:
            return []

    def add_seeds(self, seeds):
        pass  # Seeds distribution between AFL is not needed.
