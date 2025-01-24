# -*- coding: utf-8 -*-

import json
import logging
import os
import shlex
import subprocess
import threading
from collections import namedtuple
from copy import copy
from queue import Queue

import autofuzz.config as config
from autofuzz.utils.get_from_queue import get_from_queue
from autofuzz.utils.placeholder_replacer import placeholder_replacer

COVELF_COMMAND = None
LLVMPROFDATA_COMMAND = None
LLVMCOV_COMMAND = None
MAX_THREAD = None
PROFRAW_PATH = None
_task_queue = Queue()
_cov_result_struct = namedtuple('cov_result_struct', 'total cover')
_last_data = {k: _cov_result_struct(0, 0) for k in ['branches', 'functions', 'instantiations', 'lines', 'regions']}
_new_seeds_count = 0


def _run_files(run_id, command, additional_env):
    global _task_queue
    for files in get_from_queue(_task_queue):
        with open(f'{PROFRAW_PATH}/{run_id}.sh', 'w') as f:
            print('#!/bin/bash', file=f)
            for k, v in additional_env.items():
                print(f'export {k}={v}', file=f)
            if '@@' in command:
                print('\n'.join(command.replace('@@', file) for file in files), file=f)
            else:
                print('\n'.join((command + f' < {file}') for file in files), file=f)
        subprocess.run(['bash', f'{PROFRAW_PATH}/{run_id}.sh'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            os.remove(f'{PROFRAW_PATH}/{run_id}.sh')
        except FileNotFoundError:
            pass


def recieve_task(files):
    global _task_queue, _new_seeds_count
    logging.debug('Cov analyse start.')
    _new_seeds_count += len(files)

    cmd, additional_env, _ = COVELF_COMMAND
    if 'LLVM_PROFILE_FILE' not in additional_env:
        additional_env['LLVM_PROFILE_FILE'] = f'{PROFRAW_PATH}/%{MAX_THREAD}m.profraw'

    _task_queue = Queue()

    n_item = 200
    files = list(files)
    split_files = [files[i * n_item : (i + 1) * n_item] for i in range(len(files) // n_item + 1)]

    cmd = 'timeout -s 9 5s ' + cmd
    for split_file in split_files:
        _task_queue.put(split_file)

    if config.fuzzer_running:
        n_thread = config.CPU_INFO.analysis.thread
        available_cpu = config.CPU_INFO.analysis.cpu
    else:
        n_thread = config.CPU_INFO.analysis.thread + config.CPU_INFO.runner.thread
        if config.CPU_INFO.analysis.cpu and config.CPU_INFO.runner.cpu:
            available_cpu = config.CPU_INFO.analysis.cpu + config.CPU_INFO.runner.cpu
        else:
            available_cpu = None
    for run_id in range(n_thread):
        if available_cpu:
            command = placeholder_replacer(cmd, {'b': available_cpu[run_id]})
        else:
            command = cmd
        threading.Thread(
            target=_run_files, args=(run_id, command, additional_env), name=f'Cov-Analysis INNER Task Queue {run_id}'
        ).start()
    _task_queue.join()
    _task_queue.put(config.TaskQueueExit())
    logging.debug('Cov analyse finished.')


def get_report():
    global _last_data, _new_seeds_count
    if COVELF_COMMAND.elf_path:
        covelf_file = COVELF_COMMAND.elf_path
    else:
        covelf_file = shlex.split(COVELF_COMMAND.command)[0]
    subprocess.run(
        shlex.split(f'{LLVMPROFDATA_COMMAND.command} merge -o {PROFRAW_PATH}/cov.profdata')
        + [os.path.join(PROFRAW_PATH, file) for file in os.listdir(PROFRAW_PATH) if file.endswith('.profraw')],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={**os.environ, **LLVMPROFDATA_COMMAND.additional_env},
    )
    x = subprocess.run(
        shlex.split(
            f'{LLVMCOV_COMMAND.command} export -summary-only -skip-functions {covelf_file} '
            f'-instr-profile={PROFRAW_PATH}/cov.profdata {PROFRAW_PATH}/cov.profdata'
        ),
        capture_output=True,
        env={**os.environ, **LLVMCOV_COMMAND.additional_env},
    )
    out = x.stdout.decode('utf-8', errors='replace')
    try:
        out = json.loads(out)
    except json.JSONDecodeError:
        logging.warning('Failed to decode json from llvmcov.\n' + x.stderr.decode('utf-8', errors='replace'))
        empty_result = {
            k: _cov_result_struct(0, 0) for k in ['branches', 'functions', 'instantiations', 'lines', 'regions']
        }
        new_seeds_count = _new_seeds_count
        _new_seeds_count = 0
        return empty_result, empty_result, {}, new_seeds_count

    detail_result = {}
    for file in out['data'][0]['files']:
        detail_result[file['filename']] = {
            k: _cov_result_struct(v['count'], v['covered']) for k, v in file['summary'].items()
        }
    total_result = {k: _cov_result_struct(v['count'], v['covered']) for k, v in out['data'][0]['totals'].items()}
    increase_result = {
        k: _cov_result_struct(total_result[k].total, total_result[k].cover - _last_data[k].cover)
        for k in total_result.keys()
    }
    _last_data = copy(total_result)
    new_seeds_count = _new_seeds_count
    _new_seeds_count = 0
    return increase_result, total_result, detail_result, new_seeds_count
