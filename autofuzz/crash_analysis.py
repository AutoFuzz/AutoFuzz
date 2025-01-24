# -*- coding: utf-8 -*-

import json
import logging
import os
import re
import shutil
import subprocess
import threading
from collections import defaultdict, namedtuple
from copy import copy
from datetime import datetime
from hashlib import sha1

import autofuzz.config as config
from autofuzz.utils.placeholder_replacer import placeholder_replacer

_TEST_TIME = 5

_STACK_DEEP = 3
_existed_stack = {i: {} for i in range(1, _STACK_DEEP + 1)}
unique_crashes = {}
_analysis_type_counter = {
    'Total_Input_Analyzed_Crash': 0,
    'Duplicate_Crash': {i: 0 for i in range(1, _STACK_DEEP + 1)},
    'Timeout_Crash': 0,
    'Exit_Normally_Crash': 0,
    'Output_Nothing_Crash': 0,
    'Unexpected_Output_Crash': 0,
    'No_Stack_Crash': 0,
}
JSON_PATH = None
TEST_ELF = None
MAX_TTL = None
BACKTRACING_HELPER = None
CRASHES_OUTPUT_PATH = None
_analysis_result = defaultdict(lambda: namedtuple('analysis_result_struct', 'unique_crash error_token')(list(), set()))
_analysis_queue = []
_run_queue = []
_new_crashes = {i: defaultdict(set) for i in range(_STACK_DEEP + 1)}
_order_struct = namedtuple('order_struct', 'type env parse_func args')


def _parse_lsan(stderr):
    if 'detected memory leaks' not in stderr:
        return (('', '', []),)
    ret = []
    stderr = stderr.split(': LeakSanitizer:')[1]
    stderr = stderr.split('\n\n')
    for i in stderr[1:-1]:
        stack_hash = int(sha1(i.encode('utf-8')).hexdigest(), 16)
        res1 = re.search(r'(.*?) of (.*?) allocated from:', i)
        res2 = re.search(
            r'FUNCTIONSTART(.*?)FUNCTIONEND_LOCATIONSTART(.*?)LOCATIONEND_FRAMESTART(.*?)FRAMEEND', i.split('\n')[2]
        )
        ret.append(
            (
                res1.group(1),
                f'{res2.group(1)} at {res2.group(2)} [{res1.group(2)}]',
                ([hex(stack_hash)] if hex(stack_hash) != '0x0' else []),
            )
        )
    return ret


def _parse_default(stderr, search_str):
    res = re.search(search_str, stderr)
    try:
        vulntype = res.group(1)
    except AttributeError:
        return (('', '', []),)
    if vulntype.isnumeric():
        return (('', 0, []),)
    stack_hash = 0
    stack_hashes = []
    funcname = ''
    stack_deep = 0
    for line in stderr.split('\n'):
        res = re.search(r'FUNCTIONSTART(.*?)FUNCTIONEND_LOCATIONSTART(.*?)LOCATIONEND_FRAMESTART(.*?)FRAMEEND', line)
        if res:
            stack_deep += 1
            location = res.group(2)
            if funcname == '' and (
                (
                    location.startswith('/usr')
                    or location.startswith('b')
                    or location.startswith('b32')
                    or location.startswith('b64')
                    or location.startswith('ar')
                    or location.startswith('/bin')
                    or location == '<null>'
                )
            ):
                continue
            if funcname == '':
                funcname = res.group(1) + ' at ' + location
            if location != '<null>':
                stack_hash ^= int(sha1(location.encode('utf-8')).hexdigest(), 16)
                if hex(stack_hash) != '0x0':
                    stack_hashes.append(hex(stack_hash))
        if stack_deep >= _STACK_DEEP:
            break
    return ((vulntype, funcname, stack_hashes),)


ORDER = [
    # Use ASAN for LSAN check since LSAN always return 0
    # _order_struct(
    #     'ASAN',
    #     {
    #         'ASAN_OPTIONS': 'stack_trace_format="FUNCTIONSTART%fFUNCTIONEND_LOCATIONSTART%SLOCATIONEND_FRAMESTART%nFRAMEEND"'
    #     },
    #     _parse_lsan,
    #     (),
    # ),
    _order_struct(
        'ASAN',
        {
            'ASAN_OPTIONS': 'detect_leaks=0:stack_trace_format="FUNCTIONSTART%fFUNCTIONEND_LOCATIONSTART%SLOCATIONEND_FRAMESTART%nFRAMEEND"'
        },
        _parse_default,
        (r': AddressSanitizer: (.*?)[ \n]',),
    ),
    _order_struct(
        'MSAN',
        {
            'MSAN_OPTIONS': 'stack_trace_format="FUNCTIONSTART%fFUNCTIONEND_LOCATIONSTART%SLOCATIONEND_FRAMESTART%nFRAMEEND"'
        },
        _parse_default,
        (r': MemorySanitizer: (.*?)[ \n]',),
    ),
    _order_struct(
        'UBSAN',
        {
            'UBSAN_OPTIONS': 'stack_trace_format="FUNCTIONSTART%fFUNCTIONEND_LOCATIONSTART%SLOCATIONEND_FRAMESTART%nFRAMEEND"'
        },
        _parse_default,
        (r': UndefinedBehaviorSanitizer: (.*?)[ \n]',),
    ),
    _order_struct(
        'TSAN',
        {
            'ASAN_OPTIONS': 'stack_trace_format="FUNCTIONSTART%fFUNCTIONEND_LOCATIONSTART%SLOCATIONEND_FRAMESTART%nFRAMEEND"'
        },
        _parse_default,
        (r': ThreadSanitizer: (.*?)[ \n]',),
    ),
]


def _inner_run_files(files, run_id, cpu):
    global _analysis_queue
    with open(f'{CRASHES_OUTPUT_PATH}/{run_id}.sh', 'w') as f:
        print('#!/bin/bash', file=f)
        for crash_file, chosen_index, _, _ in files:
            cmd, additional_env = TEST_ELF[ORDER[chosen_index].type]
            cmd = placeholder_replacer(cmd, {'b': cpu})
            print('echo !!!@@@!!!###!!!', file=f)
            for k, v in {**ORDER[chosen_index].env, **additional_env}.items():
                print(f'{k}={v}', end=' ', file=f)
            if '@@' in cmd:
                print('timeout -s 9 5s ' + cmd.replace('@@', crash_file), file=f)
            else:
                print('timeout -s 9 5s ' + cmd + f' < {crash_file}', file=f)
            print('rtn=$?', file=f)
            print('echo !!!@@@###!!!', file=f)
            print('echo $rtn', file=f)
        print('unset rtn', file=f)
    x = subprocess.run(['bash', f'{CRASHES_OUTPUT_PATH}/{run_id}.sh'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        os.remove(f'{CRASHES_OUTPUT_PATH}/{run_id}.sh')
    except FileNotFoundError:
        pass
    rtn = x.stdout.decode(errors='replace').split('!!!@@@!!!###!!!')[1:]
    assert len(rtn) == len(files)
    for r, file in zip(rtn, files):
        r = r.split('!!!@@@###!!!')
        returncode = int(r[1])
        if returncode == 137:
            timeout = True
        else:
            timeout = False
        _analysis_queue.append((file, (timeout, r[0], returncode)))


def _run_files():
    global _run_queue
    if config.fuzzer_running:
        n_thread = config.CPU_INFO.analysis.thread
        available_cpu = config.CPU_INFO.analysis.cpu
    else:
        n_thread = config.CPU_INFO.analysis.thread + config.CPU_INFO.runner.thread
        if config.CPU_INFO.analysis.cpu and config.CPU_INFO.runner.cpu:
            available_cpu = config.CPU_INFO.analysis.cpu + config.CPU_INFO.runner.cpu
        else:
            available_cpu = None
    thread_obj = []
    for run_id in range(n_thread):
        if available_cpu:
            cpu = available_cpu[run_id]
        else:
            cpu = None
        t = threading.Thread(
            target=_inner_run_files,
            args=(_run_queue[run_id::n_thread], run_id, cpu),
            name=f'Crash-Analysis INNER Task Queue {run_id}',
        )
        t.start()
        thread_obj.append(t)
    [t.join() for t in thread_obj]
    _run_queue.clear()


def _analysis_files():
    global _analysis_result, _analysis_queue, _run_queue, _analysis_type_counter
    for (crash_file, chosen_index, last_SEGV, ttl), (timeout, stderr, returncode) in _analysis_queue:
        if timeout or (returncode == 0) or (stderr == ''):
            if (chosen_index < len(ORDER) - 1) and (ttl < MAX_TTL):
                _run_queue.append((crash_file, chosen_index + 1, last_SEGV, ttl + 1))
            elif last_SEGV is not None:
                # logging.debug(f'{crash_file} has SEGV.')
                _analysis_result[crash_file].unique_crash.append((last_SEGV.hash, 'SEGV', last_SEGV.location))
            else:
                if timeout:
                    # logging.debug(f'{crash_file} timeout.')
                    _analysis_type_counter['Timeout_Crash'] += 1
                    _analysis_result[crash_file].error_token.add('Timeout')
                elif returncode == 0:
                    # logging.debug(f'{crash_file} exit normally.')
                    _analysis_type_counter['Exit_Normally_Crash'] += 1
                    _analysis_result[crash_file].error_token.add('Exit_Normally')
                elif stderr == '':
                    # logging.debug(f'{crash_file} output nothing.')
                    _analysis_type_counter['Output_Nothing_Crash'] += 1
                    _analysis_result[crash_file].error_token.add('Output_Nothing')
            continue

        for vulntype, location, stack_hashes in ORDER[chosen_index].parse_func(stderr, *ORDER[chosen_index].args):
            if (vulntype == '') or (stack_hashes == []):
                try:
                    if BACKTRACING_HELPER[location] >= 0:
                        ORDER[BACKTRACING_HELPER[location]]
                        location = BACKTRACING_HELPER[location]
                except (TypeError, IndexError):
                    if chosen_index < len(ORDER) - 1:
                        location = chosen_index + 1
                    else:
                        location = None
                if (location is not None) and (ttl < MAX_TTL):
                    _run_queue.append((crash_file, chosen_index + 1, last_SEGV, ttl + 1))
                elif last_SEGV is not None:
                    # logging.debug(f'{crash_file} has SEGV.')
                    _analysis_result[crash_file].unique_crash.append((last_SEGV.hash, 'SEGV', last_SEGV.location))
                else:
                    if vulntype == '':
                        # logging.debug(f'Something unexpected happened during analysing {crash_file}')
                        _analysis_type_counter['Unexpected_Output_Crash'] += 1
                        _analysis_result[crash_file].error_token.add('Unexpected_Output')
                    elif stack_hashes == []:
                        # logging.debug(f'{crash_file} has no stack.')
                        _analysis_type_counter['No_Stack_Crash'] += 1
                        _analysis_result[crash_file].error_token.add('No_Stack')
            else:
                if (vulntype == 'SEGV') and (chosen_index < len(ORDER) - 1) and (ttl < MAX_TTL):
                    SEGV_detail = namedtuple('SEGV_detail_struct', 'hash location')(stack_hashes, location)
                    _run_queue.append((crash_file, chosen_index + 1, SEGV_detail, ttl + 1))
                else:
                    # logging.debug(f'{crash_file} has {vulntype}.')
                    _analysis_result[crash_file].unique_crash.append((stack_hashes, vulntype, location))
    _analysis_queue.clear()


def prepare_file(json_path):
    global unique_crashes, _existed_stack
    stack_error = False
    try:
        with open(os.path.join(config.PROGRESS_RECOVERY_PATH, 'crash_stack.json'), 'rb') as f:
            _existed_stack = json.loads(''.join(f.readlines()))
    except BaseException:
        stack_error = True
    else:
        if (len(_existed_stack) != _STACK_DEEP) or (any(type(i) is not dict for i in _existed_stack.values())):
            _existed_stack = {i: {} for i in range(1, _STACK_DEEP + 1)}
            stack_error = True
    try:
        with open(json_path, 'r') as f:
            unique_crashes = json.loads(''.join(f.readlines()))
    except BaseException:
        pass
    else:
        for name, bug in dict(unique_crashes).items():
            if len(bug) != 4:
                # logging.debug(f'{name} has invalid format.')
                unique_crashes.pop(name)
                continue
            for item in ['Vulntype', 'Location', 'FirstTime', 'Count']:
                if item not in bug:
                    # logging.debug(f'{name} has invalid format.')
                    unique_crashes.pop(name)
                    break
            else:
                try:
                    for count_item in bug['Count'].values():
                        if (type(count_item) is not int) and (type(count_item) is not float):
                            # logging.debug(f'{name} has invalid format.')
                            unique_crashes.pop(name)
                            break
                except BaseException:
                    # logging.debug(f'{name} has invalid format.')
                    unique_crashes.pop(name)
    remain_crash_file = [
        os.path.join(CRASHES_OUTPUT_PATH, f)
        for f in os.listdir(CRASHES_OUTPUT_PATH)
        if (f not in unique_crashes) and (os.path.isfile(os.path.join(CRASHES_OUTPUT_PATH, f)))
    ]
    if json_path in remain_crash_file:
        remain_crash_file.remove(json_path)
    return remain_crash_file, stack_error


def _result_analysis(source_name):
    global _analysis_result, unique_crashes
    for k in unique_crashes:
        unique_crashes[k]['Count'] = defaultdict(int, unique_crashes[k]['Count'])
    for crash_file, parse_result in _analysis_result.items():
        try:
            if parse_result.unique_crash == []:
                target_path = os.path.join(CRASHES_OUTPUT_PATH, 'Unanalyzable')
                try:
                    os.makedirs(target_path)
                except FileExistsError:
                    pass
                new_name = f"[{source_name}]({','.join(set(parse_result.error_token))}){os.path.basename(crash_file)}"
                shutil.move(crash_file, os.path.join(target_path, new_name))
                continue
            for stack_hashes, vulntype, location in parse_result.unique_crash:
                for index, its in enumerate(stack_hashes, 1):
                    if its in _existed_stack[index]:
                        _new_crashes[index][vulntype].add(its)
                        unique_crashes[_existed_stack[index][its]]['Count'][source_name] += 1
                        _analysis_type_counter['Duplicate_Crash'][index] += 1
                        # logging.debug(f'{crash_file} is a duplicate of {stack_hash} in level {index}.')
                        break
                else:
                    _new_crashes[0][vulntype].add(its)
                    for index, stack_hash in enumerate(stack_hashes, 1):
                        _existed_stack[index][stack_hash] = its
                    unique_crashes[its] = {
                        'Vulntype': vulntype,
                        'Location': location,
                        'FirstTime': datetime.fromtimestamp(os.path.getmtime(crash_file))
                        .replace(microsecond=0)
                        .isoformat()
                        + ' BY '
                        + source_name,
                        'Count': defaultdict(int),
                    }
                    name_new = os.path.join(CRASHES_OUTPUT_PATH, its)
                    if crash_file != name_new:
                        shutil.copy2(crash_file, name_new)
                        # logging.debug(f'{crash_file} renamed to {name_new}.')
            if os.path.basename(crash_file) not in unique_crashes:
                os.remove(crash_file)
        except FileNotFoundError:
            pass
    for k in unique_crashes:
        unique_crashes[k]['Count'] = dict(unique_crashes[k]['Count'])


def recieve_task(crash_file, source_name):
    global _analysis_queue, _run_queue, _analysis_result
    logging.debug(f'Crash analyse start. {len(crash_file)} new file%s in total.' % ('s' if len(crash_file) > 1 else ''))
    _analysis_type_counter['Total_Input_Analyzed_Crash'] += len(crash_file)
    _analysis_queue.clear()
    _run_queue.clear()
    _analysis_result = defaultdict(
        lambda: namedtuple('analysis_result_struct', 'unique_crash error_token')(list(), set())
    )
    for i in crash_file:
        for _ in range(_TEST_TIME):
            _run_queue.append((i, 0, None, 0))
    while _run_queue:
        _run_files()
        _analysis_files()
    _result_analysis(source_name)
    with open(JSON_PATH, 'w') as f:
        f.write(json.dumps(unique_crashes, sort_keys=True, indent=4, separators=(',', ': ')))
    with open(os.path.join(config.PROGRESS_RECOVERY_PATH, 'crash_stack.json'), 'w') as f:
        f.write(json.dumps(_existed_stack, sort_keys=True, indent=4, separators=(',', ': ')))
    logging.debug('Crash analyse finished.')


def get_report():
    global _new_crashes, _analysis_type_counter
    new_crashes = copy(_new_crashes)
    analysis_type_counter = copy(_analysis_type_counter)
    _new_crashes = {i: defaultdict(set) for i in range(_STACK_DEEP + 1)}
    _analysis_type_counter = _analysis_type_counter = {
        'Total_Input_Analyzed_Crash': 0,
        'Duplicate_Crash': {i: 0 for i in range(1, _STACK_DEEP + 1)},
        'Timeout_Crash': 0,
        'Exit_Normally_Crash': 0,
        'Output_Nothing_Crash': 0,
        'Unexpected_Output_Crash': 0,
        'No_Stack_Crash': 0,
    }
    return new_crashes, analysis_type_counter
