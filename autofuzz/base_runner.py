import abc
import os
import signal
from collections import defaultdict


class BaseRunner(abc.ABC):
    force_disable_SIGUSR2 = False

    @abc.abstractmethod
    def __init__(self, name, shell_command, startup_time, additional_env, progress_recovery_path, cpu, seed_path):
        """
        When startup fails, raise autofuzz.config.RunnerStartupFailed(),
        and you need to deal with placeholders.
        """
        self.name = name
        self.pid = None
        self._seeds_path = None
        self._crash_path = None
        self._existed_seeds = set()
        self._existed_crashes = set()
        self._new_seeds_count = 0
        self._new_crashes_count = 0
        try:
            os.makedirs(os.path.join(progress_recovery_path, self.name))
        except FileExistsError:
            pass
        try:
            os.makedirs(os.path.join(progress_recovery_path, self.name, 'cwd'))
        except FileExistsError:
            pass

    def get_data_from_stats(self):
        """
        Return two defaultdict(float) represent incremental and total respectively.
        """
        return defaultdict(float), defaultdict(float)

    def list_all_seeds(self):
        """
        Returns an iterable object containing all seeds.
        """
        try:
            return (os.path.join(self._seeds_path, f) for f in os.listdir(self._seeds_path))
        except FileNotFoundError:
            return []

    def list_all_crashes(self):
        """
        Returns an iterable object containing all crashes.
        """
        try:
            return (os.path.join(self._crash_path, f) for f in os.listdir(self._crash_path))
        except FileNotFoundError:
            return []

    def get_seeds_increase(self):
        """
        Returns an iterable object representing all new seeds added since the last time this method was run.
        """
        current_seeds = set(self.list_all_seeds())
        new_seeds = current_seeds - self._existed_seeds
        self._new_seeds_count += len(new_seeds)
        self._existed_seeds |= new_seeds
        return new_seeds

    def get_crashes_increase(self):
        """
        Returns an iterable object representing all new crashes added since the last time this method was run.
        """
        current_crashes = set(self.list_all_crashes())
        new_crashes = current_crashes - self._existed_crashes
        self._new_crashes_count += len(new_crashes)
        self._existed_crashes |= new_crashes
        return new_crashes

    def add_seeds(self, seeds):
        """
        Add seeds from other sources.
        """
        current_seeds = set(self.list_all_seeds())
        for seed in seeds:
            if (basename := os.path.basename(seed)) not in current_seeds:
                try:
                    os.link(seed, os.path.join(self._seeds_path, basename))
                    self._existed_seeds.add(os.path.join(self._seeds_path, basename))
                except OSError:
                    pass

    def kill(self):
        """
        Kill fuzzer process.
        """
        try:
            os.kill(self.pid, signal.SIGINT)
        except (AttributeError, ProcessLookupError):
            pass

    def __repr__(self):
        return f'Runner({self.name})'
