# -*- coding: utf-8 -*-

import csv
import datetime
import json
import logging
import math
import os
import threading
import time
from collections import defaultdict, namedtuple
from itertools import groupby, zip_longest
from signal import SIGUSR2

import prometheus_client
from SMPyBandits.Policies import Exp3

import autofuzz.config as config
import autofuzz.cov_analysis as cov_analysis
import autofuzz.crash_analysis as crash_analysis
from autofuzz.base_runner import BaseRunner
from autofuzz.runner_pool import RunnerPool
from autofuzz.utils.get_from_queue import get_from_queue
from autofuzz.utils.reader_and_writer import Writer
from autofuzz.utils.time_record import TimeRecord

LINE_LIMIT = 80
TIME_AFTER_SIGUSR2 = 1


def _print_table(*args):
    raw = []
    for arg in args[:-1]:
        raw_str = str(arg[0])
        length = arg[1] - 1
        raw.append([raw_str[i : i + length] + ' ' for i in range(0, len(raw_str), length)])
    raw.append([str(args[-1][0])[i : i + args[-1][1]] for i in range(0, len(str(args[-1][0])), args[-1][1])])
    for r in zip_longest(*raw, fillvalue=''):
        for index, value in enumerate(r):
            print(value.ljust(args[index][1]), end='')
        print()


def run_it(
    methods_info,
    crash_analysis_command,
    covelf_command,
    seed_path=None,
    startup_time=120,
    runner_type=None,
    method_additional_env=None,
    crash_analysis_command_additional_env=None,
    llvmprofdata_command='llvm-profdata',
    llvmcov_command='llvm-cov',
    runner_thread=3,
    analysis_thread=0,
    cycle_time=450,
    running_status_csv_path='data.csv',
    crashes_output_json_path=None,
    crashes_output_path='crashes',
    progress_recovery_path='output',
    support_SIGUSR2_sync=False,
    support_SIGUSR2_stats=False,
    run_round=0,
    reference_time=86400,
    cpu_list=None,
    round_robin=False,
    prometheus_port=None,
):
    config.total_timer.start()
    try:
        continuous_mode = len(methods_info) == 1
        if seed_path:
            seed_path = os.path.abspath(seed_path)
        else:
            seed_path = None
        crashes_output_path = os.path.abspath(crashes_output_path)
        crash_analysis.CRASHES_OUTPUT_PATH = crashes_output_path
        try:
            os.makedirs(crashes_output_path)
        except FileExistsError:
            pass
        progress_recovery_path = os.path.abspath(progress_recovery_path)
        config.PROGRESS_RECOVERY_PATH = progress_recovery_path
        try:
            os.makedirs(progress_recovery_path)
        except FileExistsError:
            pass
        if analysis_thread <= 0:
            analysis_thread = runner_thread
        cov_analysis.MAX_THREAD = analysis_thread + runner_thread

        covelf_command_struct = namedtuple('covelf_command_struct', ['command', 'additional_env', 'elf_path'])
        if type(covelf_command) is not tuple or len(covelf_command) == 1:
            cov_analysis.COVELF_COMMAND = covelf_command_struct(covelf_command, {}, '')
        elif len(covelf_command) == 2:
            if type(covelf_command[1]) is dict:
                cov_analysis.COVELF_COMMAND = covelf_command_struct(covelf_command[0], covelf_command[1], '')
            elif type(covelf_command[1]) is str:
                cov_analysis.COVELF_COMMAND = covelf_command_struct(covelf_command[0], {}, covelf_command[1])
        else:
            cov_analysis.COVELF_COMMAND = covelf_command_struct(*covelf_command)
        command_struct = namedtuple('command_struct', ['command', 'additional_env'])
        if type(llvmprofdata_command) is not tuple:
            cov_analysis.LLVMPROFDATA_COMMAND = command_struct(llvmprofdata_command, {})
        else:
            cov_analysis.LLVMPROFDATA_COMMAND = command_struct(*llvmprofdata_command)
        if type(llvmcov_command) is not tuple:
            cov_analysis.LLVMCOV_COMMAND = command_struct(llvmcov_command, {})
        else:
            cov_analysis.LLVMCOV_COMMAND = command_struct(*llvmcov_command)
        cov_analysis.PROFRAW_PATH = os.path.join(progress_recovery_path, 'profraw')
        try:
            os.makedirs(os.path.join(progress_recovery_path, 'profraw'))
        except FileExistsError:
            pass

        if method_additional_env is None:
            method_additional_env = {}

        running_status_csv_path = os.path.abspath(running_status_csv_path)
        config.CSV_PATH = running_status_csv_path
        try:
            os.makedirs(os.path.dirname(running_status_csv_path))
        except FileExistsError:
            pass
        if (not os.path.isfile(config.CSV_PATH)) or (os.stat(config.CSV_PATH).st_size == 0):
            with open(config.CSV_PATH, 'w', newline='') as f:
                csv.DictWriter(f, fieldnames=config.CSV_FIELDNAMES).writeheader()

        if crashes_output_json_path is None:
            crashes_output_json_path = os.path.join(crashes_output_path, 'summary.json')
        else:
            crashes_output_json_path = os.path.abspath(crashes_output_json_path)
        crash_analysis.JSON_PATH = crashes_output_json_path
        if crash_analysis_command_additional_env is None:
            crash_analysis_command_additional_env = {}
        for i in crash_analysis_command:
            if type(crash_analysis_command[i]) is not tuple:
                crash_analysis_command[i] = (crash_analysis_command[i], crash_analysis_command_additional_env)
        crash_analysis.TEST_ELF = crash_analysis_command

        backtracking_helper = list(range(len(crash_analysis.ORDER)))
        for i, v in enumerate(crash_analysis.ORDER):
            if v.type not in crash_analysis_command:
                crash_analysis.ORDER.remove(v)
                backtracking_helper[i] = -1
                for k in range(i + 1, len(backtracking_helper)):
                    backtracking_helper[k] -= 1
        crash_analysis.BACKTRACING_HELPER = backtracking_helper
        crash_analysis.MAX_TTL = len(crash_analysis.ORDER) + 10

        if run_round > 0:
            config.TARGET_ROUND = run_round

        if cpu_list and len(cpu_list) < (runner_thread + analysis_thread):
            logging.info('Length of CPU_List is lower than Runner_Thread + Analysis_Thread. CPU_List will be ignored.')
            cpu_list = None
        if cpu_list:
            runner_cpu = tuple(cpu_list[:runner_thread])
            analysis_cpu = tuple(cpu_list[runner_thread : runner_thread + analysis_thread])
            # Modified the code from https://stackoverflow.com/a/2154437
            runner_cpu_list_str = ','.join(
                f'{rng[0]}-{rng[-1]}' if len(rng := [i[1] for i in groups]) > 1 else str(rng[0])
                for _, groups in groupby(enumerate(cpu_list[:runner_thread]), lambda x: x[1] - x[0])
            )
            analysis_cpu_list_str = ','.join(
                f'{rng[0]}-{rng[-1]}' if len(rng := [i[1] for i in groups]) > 1 else str(rng[0])
                for _, groups in groupby(
                    enumerate(cpu_list[runner_thread : runner_thread + analysis_thread]), lambda x: x[1] - x[0]
                )
            )
            config.CPU_INFO = namedtuple('CPU_INFO_struct', 'analysis runner')(
                namedtuple('CPU_INFO_inner_struct', 'thread cpu')(analysis_thread, analysis_cpu),
                namedtuple('CPU_INFO_inner_struct', 'thread cpu')(runner_thread, runner_cpu),
            )
        else:
            runner_cpu = None
            config.CPU_INFO = namedtuple('CPU_INFO_struct', 'analysis runner')(
                namedtuple('CPU_INFO_inner_struct', 'thread cpu')(analysis_thread, None),
                namedtuple('CPU_INFO_inner_struct', 'thread cpu')(runner_thread, None),
            )

        def deal_with_analysis_queue():
            for func, *args in get_from_queue(config.analysis_queue):
                func(*args)

        threading.Thread(target=deal_with_analysis_queue, name='Analysis Task Queue').start()

        if prometheus_port:
            prometheus_client.start_http_server(prometheus_port)

        print('-' * LINE_LIMIT)
        _print_table(('Basic Info:', LINE_LIMIT))
        if continuous_mode:
            _print_table(('', 4), ('Mode:', 28), ('Continuous', LINE_LIMIT - 32))
        elif round_robin:
            _print_table(('', 4), ('Mode:', 28), ('Round Robin', LINE_LIMIT - 32))
        else:
            _print_table(('', 4), ('Mode:', 28), ('AutoFuzz', LINE_LIMIT - 32))
        if run_round > 0:
            _print_table(
                ('', 4), ('Running Round:', 28), (str(run_round) if run_round > 0 else 'Unlimited', LINE_LIMIT - 32)
            )
        else:
            days = reference_time // 86400
            reference_time_str = str(datetime.timedelta(seconds=reference_time % 86400))
            reference_time_str = (f'{days}d ' if days > 0 else '') + reference_time_str
            _print_table(
                ('', 4), ('Running Round:', 28), (f'Unlimited - Estimated {reference_time_str}', LINE_LIMIT - 32)
            )
        _print_table(('', 4), ('Crashes Output Path:', 28), (crashes_output_path, LINE_LIMIT - 32))
        _print_table(('', 4), ('Crashes Summary Path:', 28), (crashes_output_json_path, LINE_LIMIT - 32))
        _print_table(('', 4), ('Runner Data Path:', 28), (running_status_csv_path, LINE_LIMIT - 32))
        _print_table(('', 4), ('Progress Recovery Path:', 28), (progress_recovery_path, LINE_LIMIT - 32))
        _print_table(('', 4), ('Cycle Time:', 28), (cycle_time, LINE_LIMIT - 32))
        _print_table(('', 4), ('Runner Thread:', 28), (runner_thread, LINE_LIMIT - 32))
        _print_table(('', 4), ('Analysis Thread:', 28), (analysis_thread, LINE_LIMIT - 32))
        if cpu_list:
            _print_table(('', 4), ('Runner CPU List:', 28), (runner_cpu_list_str, LINE_LIMIT - 32))
            _print_table(('', 4), ('Analysis CPU List:', 28), (analysis_cpu_list_str, LINE_LIMIT - 32))
        if prometheus_port:
            _print_table(('', 4), ('Prometheus Port:', 28), (prometheus_port, LINE_LIMIT - 32))

        for method in methods_info:
            print()
            method['shell_command'] = method['shell_command'].strip()
            if 'seed_path' not in method:
                method['seed_path'] = seed_path
            if 'startup_time' not in method:
                method['startup_time'] = startup_time
            if 'method_additional_env' not in method:
                method['method_additional_env'] = method_additional_env
            if ('runner_type' not in method) or (not issubclass(method['runner_type'], BaseRunner)):
                if runner_type and issubclass(runner_type, BaseRunner):
                    method['runner_type'] = runner_type
                else:
                    logging.error(f"Runner Type of {method['name']} is not specified or invalid.")
                    raise config.RunnerStartupFailed()
            if method['runner_type'].force_disable_SIGUSR2:
                method['support_SIGUSR2_sync'] = False
                method['support_SIGUSR2_stats'] = False
            else:
                if 'support_SIGUSR2_sync' not in method:
                    method['support_SIGUSR2_sync'] = support_SIGUSR2_sync
                if 'support_SIGUSR2_stats' not in method:
                    method['support_SIGUSR2_stats'] = support_SIGUSR2_stats
            if not continuous_mode:
                _print_table(('', 8), (method['name'], LINE_LIMIT - 8))
            else:
                _print_table(('', 4), (f"Continuous fuzzing {method['name']}", LINE_LIMIT - 8))
            _print_table(('', 12), ('Runner Type:', 20), (method['runner_type'].__name__, LINE_LIMIT - 32))
            _print_table(('', 12), ('Shell Command:', 20), (method['shell_command'], LINE_LIMIT - 32))
            _print_table(('', 12), ('Seed Path:', 20), (method['seed_path'], LINE_LIMIT - 32))
            _print_table(('', 12), ('Startup Time:', 20), (method['startup_time'], LINE_LIMIT - 32))
            _print_table(
                ('', 12),
                ('Support SIGUSR2:', 20),
                ('For Stats', 12),
                (
                    'Force disabled by this runner type.'
                    if method['runner_type'].force_disable_SIGUSR2
                    else method['support_SIGUSR2_stats'],
                    LINE_LIMIT - 44,
                ),
            )
            if not continuous_mode:
                _print_table(
                    ('', 32),
                    ('For Sync', 12),
                    (
                        'Force disabled by this runner type.'
                        if method['runner_type'].force_disable_SIGUSR2
                        else method['support_SIGUSR2_sync'],
                        LINE_LIMIT - 44,
                    ),
                )
            if method['method_additional_env'] != {}:
                _print_table(('', 12), ('Additional Env:', 20), (method['method_additional_env'], LINE_LIMIT - 32))
        print('-' * LINE_LIMIT)
        remain_crash_file, stack_error = crash_analysis.prepare_file(crashes_output_json_path)
        if stack_error and crash_analysis.unique_crashes:
            logging.warning('The progress recovery file from the last analysis')
            logging.warning('does not exist or not in the correct format.')
            logging.warning('All crash files will be re-analysed.')
            all_crash_file = [
                os.path.join(crashes_output_path, f)
                for f in os.listdir(crashes_output_path)
                if os.path.isfile(os.path.join(crashes_output_path, f))
            ]
            if crashes_output_json_path in all_crash_file:
                all_crash_file.remove(crashes_output_json_path)
            config.analysis_queue.put((crash_analysis.recieve_task, all_crash_file, 'Repair'))
            config.analysis_queue.join()  # Wait repair complete
        elif remain_crash_file:
            if crash_analysis.unique_crashes == {}:
                logging.warning('The summary file from the last analysis')
                logging.warning('does not exist or not in the correct format.')
                logging.warning('All crash files will be re-analysed.')
            else:
                logging.warning('Some crashes have problems with the analysis results and will be re-analysed.')
            config.analysis_queue.put((crash_analysis.recieve_task, remain_crash_file, 'Repair'))
            config.analysis_queue.join()  # Wait repair complete
        crash_analysis.get_report()  # Old crash-analysis result don't belong to anyone.

        with TimeRecord() as config.startup_timer:
            for method in methods_info:
                config.methods.append(
                    RunnerPool(
                        **{
                            'name': method['name'],
                            'shell_command': method['shell_command'],
                            'runner_type': method['runner_type'],
                            'startup_time': method['startup_time'],
                            'additional_env': method['method_additional_env'],
                            'support_SIGUSR2_sync': method['support_SIGUSR2_sync'],
                            'support_SIGUSR2_stats': method['support_SIGUSR2_stats'],
                            'runner_thread': runner_thread,
                            'cpu_list': runner_cpu,
                            'seed_path': method['seed_path'],
                        }
                    )
                )
                logging.info('')

        if continuous_mode:
            first_seed_distribution = TimeRecord()
            logging.info('Startup completed. Start continuous fuzzing.')
            config.FUZZING_STAGE = 3
            config.REWARD_STAGE = 1
            round = 0

            chosen_method = config.methods[0]
            chosen_method.continue_run()
            logging.info('')
            logging.info('Virtual Round 1')
            while config.TARGET_ROUND < 0 or round < config.TARGET_ROUND:
                round += 1
                if chosen_method.support_SIGUSR2_stats:
                    time.sleep(max(cycle_time - TIME_AFTER_SIGUSR2, 0))
                    chosen_method.send_signal(SIGUSR2)
                    time.sleep(TIME_AFTER_SIGUSR2)
                else:
                    time.sleep(cycle_time)
                config.analysis_queue.put((chosen_method.calc_reward, round))

            chosen_method.pause_run()

        elif round_robin:
            first_seed_distribution = TimeRecord()
            logging.info('Startup completed. Start Round-Robin Mode fuzzing.')
            config.FUZZING_STAGE = 4
            config.REWARD_STAGE = 1
            round = 0

            while config.TARGET_ROUND < 0 or round < config.TARGET_ROUND:
                round += 1

                chosen_method = config.methods[(round - 1) % len(config.methods)]
                logging.info('')
                logging.info(f'Round {round}')

                chosen_method.continue_run()
                if chosen_method.support_SIGUSR2_stats:
                    time.sleep(max(cycle_time - TIME_AFTER_SIGUSR2, 0))
                    chosen_method.send_signal(SIGUSR2)
                    time.sleep(TIME_AFTER_SIGUSR2)
                else:
                    time.sleep(cycle_time)
                chosen_method.pause_run()

                with Writer(config.seeds_distribution):
                    pass  # Wait for seeds distribution finish

        else:
            logging.info('Startup completed. Start initialization round.')
            logging.info('')
            config.FUZZING_STAGE = 1

            for chosen_method in config.methods:
                chosen_method.continue_run()

                if chosen_method.support_SIGUSR2_stats:
                    time.sleep(max(cycle_time - TIME_AFTER_SIGUSR2, 0))
                    chosen_method.send_signal(SIGUSR2)
                    time.sleep(TIME_AFTER_SIGUSR2)
                else:
                    time.sleep(cycle_time)
                chosen_method.pause_run()
                logging.info('')

            logging.info('Start seed distribution.')
            with TimeRecord() as first_seed_distribution:
                for current_method in config.methods:
                    seeds = current_method.list_all_seeds()
                    for method in [i for i in config.methods if i is not current_method]:
                        method.add_seeds(seeds)
            logging.info('Finish seed distribution.')
            logging.info('')

            logging.info('Initialization completed. Start fuzzer scheduling.')
            config.FUZZING_STAGE = 2

            round = 0

            K = len(config.methods)
            T = (
                config.TARGET_ROUND
                if config.TARGET_ROUND > 0
                else int((reference_time - config.total_timer.get_elapsed_without_stop()) / cycle_time)
            )
            mab = Exp3(len(config.methods), gamma=min(1, math.sqrt((K * math.log10(K)) / ((math.e - 1) * 2 / 3 * T))))
            mab.startGame()
            for index, method in enumerate(config.methods):
                mab.getReward(index, min((method.reward.crash + method.reward.cov) / 2, 1))
            with open(config.CSV_PATH, 'a', newline='') as f:
                row = {
                    'Time': time.time(),
                    'Type': 'Bandits',
                    'Weights': json.dumps(dict(zip([i['name'] for i in methods_info], mab.weights))),
                }
                csv.DictWriter(f, fieldnames=config.CSV_FIELDNAMES).writerow(row)

            update_reward_stage_timer = None

            def update_reward_stage():
                nonlocal update_reward_stage_timer
                if config.TARGET_ROUND > 0:
                    total_time = config.TARGET_ROUND * cycle_time
                else:
                    total_time = reference_time
                if config.total_timer.get_elapsed_without_stop() > (total_time / 3):
                    config.REWARD_STAGE = 1
                else:
                    update_reward_stage_timer = threading.Timer(15, update_reward_stage)
                    update_reward_stage_timer.name = 'update_reward_stage Timer'
                    update_reward_stage_timer.start()

            while config.TARGET_ROUND < 0 or round < config.TARGET_ROUND:
                round += 1

                if round == 8:
                    update_reward_stage_timer = threading.Timer(15, update_reward_stage)
                    update_reward_stage_timer.name = 'update_reward_stage Timer'
                    update_reward_stage_timer.start()

                chosen_method_n = mab.choice()
                chosen_method = config.methods[chosen_method_n]
                logging.info('')
                logging.info(f'Round {round}')

                chosen_method.continue_run()
                if chosen_method.support_SIGUSR2_stats:
                    time.sleep(max(cycle_time - TIME_AFTER_SIGUSR2, 0))
                    chosen_method.send_signal(SIGUSR2)
                    time.sleep(TIME_AFTER_SIGUSR2)
                else:
                    time.sleep(cycle_time)
                chosen_method.pause_run()

                reward = (chosen_method.reward.crash + chosen_method.reward.cov) / 2
                mab.getReward(chosen_method_n, reward)
                with open(config.CSV_PATH, 'a', newline='') as f:
                    row = {
                        'Time': time.time(),
                        'Type': 'Bandits',
                        'Weights': json.dumps(dict(zip([i['name'] for i in methods_info], mab.weights))),
                    }
                    csv.DictWriter(f, fieldnames=config.CSV_FIELDNAMES).writerow(row)

                with Writer(config.seeds_distribution):
                    pass  # Wait for seeds distribution finish

    except KeyboardInterrupt:
        print()
        logging.info('KeyboardInterrupt')
        logging.warning('The program will exit as soon as possible,')
        logging.warning('but some cleanup work cannot be completed immediately,')
        logging.warning('please be patient.')
        t = threading.Timer(
            300,
            lambda: logging.warning(
                'The program may have encountered an uncorrectable error after waiting too long. Force quit if necessary.'
            ),
        )
        t.name = 'Exit-Time-Exceeded Warning Timer'
        t.start()
        try:
            chosen_method.send_signal(SIGUSR2)
            time.sleep(TIME_AFTER_SIGUSR2)
            chosen_method.pause_run()
        except (AttributeError, UnboundLocalError):
            pass
    except config.RunnerStartupFailed:
        pass
    finally:
        config.exit_prepare.set()
        try:
            config.analysis_queue.join()
            with Writer(config.wait_needed):
                try:
                    update_reward_stage_timer.cancel()
                except (UnboundLocalError, AttributeError):
                    pass
                try:
                    t.cancel()
                except UnboundLocalError:
                    pass
                config.total_timer.stop()
                fuzz_time = sum(float(method.timer) for method in config.methods)
                if fuzz_time > 0.0:
                    total_crashes = defaultdict(int)
                    try:
                        first_seed_distribution = first_seed_distribution.elapsed
                    except UnboundLocalError:
                        first_seed_distribution = 0
                    print('-' * LINE_LIMIT)
                    _print_table(('Data Report:', LINE_LIMIT))
                    _print_table(('', 4), ('Time usage:', LINE_LIMIT - 4))
                    _print_table(('', 8), ('Startup:', 24), (config.startup_timer, LINE_LIMIT - 32))
                    if int(first_seed_distribution) > 0:
                        _print_table(
                            ('', 8),
                            ('First Seed Distribute:', 24),
                            (datetime.timedelta(seconds=int(first_seed_distribution)), LINE_LIMIT - 32),
                        )
                    _print_table(
                        ('', 8), ('Init & Fuzzing:', 24), (datetime.timedelta(seconds=int(fuzz_time)), LINE_LIMIT - 32)
                    )
                    _print_table(
                        ('', 8),
                        ('Extra Time After Pause:', 24),
                        (datetime.timedelta(seconds=int(config.analysis_after_pause_timer)), LINE_LIMIT - 32),
                    )
                    if not continuous_mode:
                        _print_table(
                            ('', 31),
                            (
                                '(%s for reward calculate)' % datetime.timedelta(seconds=int(config.calculate_timer)),
                                LINE_LIMIT - 31,
                            ),
                        )
                    _print_table(('', 8), ('Total:', 24), (config.total_timer, LINE_LIMIT - 32))
                    _print_table(('', 4), ('For each fuzzer:', LINE_LIMIT - 4))
                    for method in config.methods:
                        crash_count = sum(len(i) for i in method.total_crash_data.values())
                        _print_table(
                            ('', 8),
                            (method.name, 24),
                            (
                                'Found %d crash%s in %d seconds:'
                                % (crash_count, 'es' if crash_count > 1 else '', int(method.timer)),
                                LINE_LIMIT - 32,
                            ),
                        )
                        _print_table(
                            ('', 32), ({k: len(v) for k, v in method.total_crash_data.items()}, LINE_LIMIT - 32)
                        )
                        for i in method.total_crash_data:
                            total_crashes[i] += len(method.total_crash_data[i])
                    crash_count = sum(total_crashes.values())
                    _print_table(
                        ('', 6),
                        ('--Total--', 26),
                        (
                            'Found %d crash%s in %d seconds:'
                            % (crash_count, 'es' if crash_count > 1 else '', int(fuzz_time)),
                            LINE_LIMIT - 32,
                        ),
                    )
                    _print_table(('', 32), (dict(total_crashes), LINE_LIMIT - 32))
                    print('-' * LINE_LIMIT)
                else:
                    _print_table(('Interrupted before starting fuzzing, unable to generate data report.', LINE_LIMIT))

                [method.kill() for method in config.methods]
                config.analysis_queue.put(config.TaskQueueExit())

        except KeyboardInterrupt:
            print()
            logging.error('Force quit! GC may not be completed and database may be miswritten! Might need more ^C')
            quit()
