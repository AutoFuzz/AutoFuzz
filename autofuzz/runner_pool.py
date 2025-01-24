# -*- coding: utf-8 -*-

import csv
import json
import logging
import os
import signal
import threading
import time
from collections import defaultdict, namedtuple

import autofuzz.config as config
import autofuzz.cov_analysis as cov_analysis
import autofuzz.crash_analysis as crash_analysis
from autofuzz.utils.loop_timer import LoopTimer
from autofuzz.utils.reader_and_writer import Reader, ReaderDecorator
from autofuzz.utils.run_once import RunOnce
from autofuzz.utils.time_record import TimeRecord


class RunnerPool:
    def __init__(
        self,
        name,
        shell_command,
        runner_type,
        startup_time,
        additional_env,
        support_SIGUSR2_sync,
        support_SIGUSR2_stats,
        runner_thread,
        cpu_list,
        seed_path,
    ):
        logging.info(f'RunnerPool({name}) start init')

        self.name = name
        self.timer = TimeRecord()
        self.reward = namedtuple('reward_struct', 'crash cov')(0, 0)
        self.speed = 0
        self.total_crash_data = defaultdict(set)
        self.__runners = []
        self.__support_SIGUSR2_sync = support_SIGUSR2_sync
        self.support_SIGUSR2_stats = support_SIGUSR2_stats
        self.__last_timer_elapsed = 0
        self.__cov_timer = LoopTimer(5, self._prepare_cov_analysis, 'prepare_cov_analysis Timer')
        self.__crash_timer = LoopTimer(60, self._prepare_crash_analysis, 'prepare_crash_analysis Timer')

        error_count = 0

        def thread_main(self, n):
            nonlocal error_count
            with Reader(config.wait_needed, f'Startup {name + str(n)}'):
                try:
                    new_runner = runner_type(
                        **{
                            'name': name + str(n),
                            'shell_command': shell_command,
                            'startup_time': startup_time,
                            'additional_env': additional_env,
                            'progress_recovery_path': config.PROGRESS_RECOVERY_PATH,
                            'cpu': cpu_list[n] if cpu_list else None,
                            'seed_path': seed_path,
                        }
                    )
                    try:
                        os.kill(new_runner.pid, signal.SIGSTOP)
                    except ProcessLookupError:
                        raise config.RunnerStartupFailed()
                    self.__runners.append(new_runner)
                except config.RunnerStartupFailed:
                    error_count += 1

        config.fuzzer_running = True
        thread_obj = []
        for i in range(runner_thread):
            t = threading.Thread(target=thread_main, args=(self, i), name=f'Startup {self.name}{i}')
            t.start()
            thread_obj.append(t)
        [t.join() for t in thread_obj]
        if error_count == runner_thread:
            logging.error(f'All {runner_thread} runner%s of {name} failed to start!' % ('s' if error_count > 1 else ''))
            raise config.RunnerStartupFailed()
        elif error_count > 0:
            logging.error(f'{error_count} runner%s of {name} failed to start!' % ('s' if error_count > 1 else ''))
            raise config.RunnerStartupFailed()
        else:
            logging.info(f'All {runner_thread} runners started successfully!')

        self._prepare_cov_analysis()
        self._prepare_crash_analysis()
        config.analysis_queue.put((self.calc_reward,))
        config.analysis_queue.join()

        logging.info(f'RunnerPool({name}) startup done')

    def kill(self):
        self.__cov_timer.cancel()
        self.__crash_timer.cancel()
        self.send_signal(signal.SIGINT)
        [runner.kill() for runner in self.__runners]

    def list_all_seeds(self):
        all_seeds = set()
        for runner in self.__runners:
            all_seeds |= set(runner.list_all_seeds())
        return all_seeds

    def __repr__(self):
        return f'RunnerPool({self.name})'

    def send_signal(self, the_signal):
        for pid in set(runner.pid for runner in self.__runners if runner.pid != 0):
            try:
                os.kill(pid, the_signal)
            except ProcessLookupError:
                pass

    def continue_run(self):
        logging.info(f'Start fuzzing by {self.name}')
        config.fuzzer_running = True
        self.send_signal(signal.SIGCONT)
        self.timer.start()
        self.__cov_timer.start()
        self.__crash_timer.start()
        if self.__support_SIGUSR2_sync:
            self.send_signal(signal.SIGUSR2)
        config.prometheus_data['Time'].set(time.time())
        config.prometheus_data['TotalRunningTime'].set(config.total_timer.get_elapsed_without_stop())
        config.prometheus_data['Current'].labels(FuzzName=self.name).set(1)

    @RunOnce
    def pause_run(self):
        self.__cov_timer.cancel()
        self.__crash_timer.cancel()
        self.timer.stop()
        logging.info(f'Pause fuzzing by {self.name}')
        self.send_signal(signal.SIGSTOP)
        config.fuzzer_running = False

        config.analysis_after_pause_timer.start()
        self._prepare_cov_analysis()
        self._prepare_crash_analysis()
        config.analysis_queue.put((self.calc_reward,))
        config.analysis_queue.join()
        config.analysis_after_pause_timer.stop()
        config.prometheus_data['Current'].clear()

    @RunOnce
    @ReaderDecorator(config.wait_needed)
    def add_seeds(self, seeds):
        thread_obj = []
        for runner in self.__runners:
            t = threading.Thread(target=runner.add_seeds, args=(seeds,), name=f'Distribute seeds to {runner.name}')
            t.start()
            thread_obj.append(t)
        [t.join() for t in thread_obj]

    @RunOnce
    @ReaderDecorator(config.wait_needed)
    def _prepare_crash_analysis(self):
        crash_file = [file_name for runner in self.__runners for file_name in runner.get_crashes_increase()]
        if crash_file:
            logging.debug('Add crash list to task queue.')
            config.analysis_queue.put((crash_analysis.recieve_task, crash_file, self.name))

    @ReaderDecorator(config.wait_needed)
    def _get_data_from_crash_analysis(self):
        logging.debug('Start crash analysis.')
        increase_crash_data, analysis_type_counter = crash_analysis.get_report()
        for k, v in increase_crash_data[0].items():
            self.total_crash_data[k].update(v)
        logging.debug('Finish crash analysis.')
        return increase_crash_data, self.total_crash_data, analysis_type_counter

    @RunOnce
    @ReaderDecorator(config.wait_needed)
    @ReaderDecorator(config.seeds_distribution)
    def _prepare_cov_analysis(self):
        new_seeds = set()
        for runner in self.__runners:
            if runner_new_seeds := runner.get_seeds_increase():
                new_seeds |= runner_new_seeds
        if new_seeds:
            config.analysis_queue.put((cov_analysis.recieve_task, new_seeds))
        if config.FUZZING_STAGE >= 2:
            logging.debug('Start seed distribution.')
            for method in [i for i in config.methods if i is not self]:
                method.add_seeds(new_seeds)
            logging.debug('Finish seed distribution.')

    @ReaderDecorator(config.wait_needed)
    def _get_data_from_cov_analysis(self):
        logging.debug('Start coverage analysis.')
        increase_cov_data, total_cov_data, _, new_seeds_count = cov_analysis.get_report()
        logging.debug('Finish coverage analysis.')
        return increase_cov_data, total_cov_data, new_seeds_count

    @ReaderDecorator(config.wait_needed)
    def _get_data_from_stats(self):
        increase_stats_data = defaultdict(float)
        for runner in self.__runners:
            increase, total = runner.get_data_from_stats()
            with open(config.CSV_PATH, 'a', newline='') as f:
                csv.DictWriter(f, fieldnames=config.CSV_FIELDNAMES).writerow(
                    {'Time': time.time(), 'Type': 'Runner', 'Name': runner.name, **total}
                )
            for k, v in increase.items():
                increase_stats_data[k] += v
        return increase_stats_data

    @RunOnce
    def calc_reward(self, continuous_mode_round=-1):
        logging.debug('Reward calculation start.')
        if (not config.startup_timer.running) and (continuous_mode_round == -1):
            config.calculate_timer.start()
        crash_weight = defaultdict(lambda: 1, {'SEGV': 0.7, 'Direct leak': 0.01, 'Indirect leak': 0.01})
        increase_cov_data, total_cov_data, new_seeds_count = self._get_data_from_cov_analysis()
        increase_crash_data, total_crash_data, analysis_type_counter = self._get_data_from_crash_analysis()
        increase_stats_data = self._get_data_from_stats()
        timer_elapsed = self.timer.get_elapsed_without_stop()
        increase_new_crash_num = {k: len(v) for k, v in increase_crash_data[0].items()}
        increase_duplicate_crash_num = defaultdict(int)
        for index in range(1, len(increase_crash_data)):
            for k, v in increase_crash_data[index].items():
                increase_duplicate_crash_num[k] += len(v)
        total_crash_num = {k: len(v) for k, v in total_crash_data.items()}
        increase_cov_data_branch = increase_cov_data['branches']
        total_cov_data_branch = total_cov_data['branches']
        config.cov_history.append((config.total_timer.get_elapsed_without_stop(), increase_cov_data_branch.cover))
        logging.info(f'New Branches Cov: {increase_cov_data_branch.cover} / {total_cov_data_branch.total}')
        logging.info(f'Branches Cov Increase Rate: {(increase_cov_data_branch.cover/total_cov_data_branch.total):.5f}')
        logging.info(f'New Crash: {increase_new_crash_num}')
        logging.info(f'All Crash: {total_crash_num}')
        reward_crash_csv = 'N/A'
        if config.FUZZING_STAGE != 0:
            if increase_stats_data['execs_done'] > 0:
                self.speed = (
                    increase_stats_data['execs_done']
                    / len(self.__runners)
                    / (timer_elapsed - self.__last_timer_elapsed)
                )
            reward_crash_new = sum(increase_new_crash_num[key] * crash_weight[key] for key in increase_new_crash_num)
            reward_crash_duplicate = (
                sum(increase_duplicate_crash_num[key] * crash_weight[key] for key in increase_duplicate_crash_num) * 0.1
            )
            if config.REWARD_STAGE == 1:
                reward_crash = reward_crash_new + reward_crash_duplicate
                reward_crash_csv = min(reward_crash, 1)
            else:
                reward_crash = 0
            reward_cov = increase_cov_data_branch.cover / total_cov_data_branch.total * 500
            self.reward = namedtuple('reward_struct', 'crash cov')(min(reward_crash, 1), min(reward_cov, 1))
            logging.info(f'Current Speed: {self.speed:.5f}')
            if config.REWARD_STAGE == 1:
                logging.info(f'Get Reward: Crash - {self.reward.crash:.4f} ; Cov - {self.reward.cov:.4f}')
            else:
                logging.info(f'Get Reward: Crash - N/A ; Cov - {self.reward.cov:.4f}')
        current_time = time.time()
        with open(config.CSV_PATH, 'a', newline='') as f:
            row = {
                'Time': current_time,
                'Type': 'RunnerPool',
                'Name': self.name,
                'RunningTime': timer_elapsed,
                'Speed': self.speed,
                'Increase_Valid_Crash': sum(increase_new_crash_num.values()),
                'Total_Valid_Crash': sum(total_crash_num.values()),
                'Increase_Valid_Crash_Detail': json.dumps(
                    {k: {kk: list(vv) for kk, vv in v.items()} for k, v in increase_crash_data.items()}
                ),
                'Total_Valid_Crash_Detail': json.dumps({k: list(v) for k, v in total_crash_data.items()}),
                **analysis_type_counter,
                'Crash_Reward': reward_crash_csv,
                'Cov_Reward': self.reward.cov,
                'New_Seeds': new_seeds_count,
                'Increase_Branches_Cover': increase_cov_data['branches'].cover,
                'Total_Branches_Cover': total_cov_data['branches'].cover,
                'Total_Branches': total_cov_data['branches'].total,
                'Increase_Functions_Cover': increase_cov_data['functions'].cover,
                'Total_Functions_Cover': total_cov_data['functions'].cover,
                'Total_Functions': total_cov_data['functions'].total,
                'Increase_Instantiations_Cover': increase_cov_data['instantiations'].cover,
                'Total_Instantiations_Cover': total_cov_data['instantiations'].cover,
                'Total_Instantiations': total_cov_data['instantiations'].total,
                'Increase_Lines_Cover': increase_cov_data['lines'].cover,
                'Total_Lines_Cover': total_cov_data['lines'].cover,
                'Total_Lines': total_cov_data['lines'].total,
                'Increase_Regions_Cover': increase_cov_data['regions'].cover,
                'Total_Regions_Cover': total_cov_data['regions'].cover,
                'Total_Regions': total_cov_data['regions'].total,
            }
            csv.DictWriter(f, fieldnames=config.CSV_FIELDNAMES).writerow(row)
        config.prometheus_data['Time'].set(current_time)
        config.prometheus_data['TotalRunningTime'].set(config.total_timer.get_elapsed_without_stop())
        config.prometheus_data['RunningTime'].labels(FuzzName=self.name).set(timer_elapsed)
        config.prometheus_data['Speed'].set(self.speed)
        config.prometheus_data['Valid_Crash'].labels(FuzzName=self.name).set(sum(total_crash_num.values()))
        config.prometheus_data['Crash_Reward'].labels(FuzzName=self.name).set(self.reward.crash)
        config.prometheus_data['Cov_Reward'].labels(FuzzName=self.name).set(self.reward.cov)
        config.prometheus_data['New_Seeds'].set(new_seeds_count)
        config.prometheus_data['Covered_Branches'].set(total_cov_data['branches'].cover)
        config.prometheus_data['Total_Branches'].set(total_cov_data['branches'].total)
        if continuous_mode_round != -1:
            logging.info('')
            if continuous_mode_round != config.TARGET_ROUND:
                logging.info(f'Virtual Round {continuous_mode_round + 1}')
            else:
                logging.info('Final calculation')
        self.__last_timer_elapsed = timer_elapsed
        config.calculate_timer.stop()
        logging.debug('Reward calculation finished.')
