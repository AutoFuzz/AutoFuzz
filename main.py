#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# python3 -m pip install -U SMPyBandits psutil prometheus-client

import logging
import os
import sys

import psutil

import autofuzz.runner.afl
import autofuzz.runner.libfuzzer
from autofuzz import run_it

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(asctime)s\t%(levelname)s\t%(message)s')

testcase = sys.argv[1]
testcase_args = {
    'exiv2': '@@',
    'lame': '@@ /dev/null',
    'jq': '. @@',
    'mp3gain': '@@',
    'mp42aac': '@@ /dev/null',
    'pdftotext': '@@ /dev/null',
    'tiffsplit': '@@',
    'infotocap': '-o /dev/null @@',
    'flvmeta': '@@',
    'cflow': '@@',
    'tcpdump': '-e -vv -nr @@',
    'jhead': '@@',
    'mujs': '@@',
    'sqlite3': ' < @@',
    'wav2swf': '-o /dev/null @@',
}

raw_info = [
    {
        'name': 'AFLplusplus',
        'shell_command': f'/root/afl/fuzzer/AFLplusplus/afl-fuzz -i #i -o #o -S #n -b #b -m none -t 5000 -- /root/afl/testcase/{testcase}/afl++ {testcase_args[testcase]}',
    },
    {
        'name': 'AFLplusplus-ASAN',
        'shell_command': f'/root/afl/fuzzer/AFLplusplus/afl-fuzz -i #i -o #o -S #n -b #b -m none -t 5000 -- /root/afl/testcase/{testcase}/afl++_asan {testcase_args[testcase]}',
    },
    {
        'name': 'AFLplusplus-UBSAN',
        'shell_command': f'/root/afl/fuzzer/AFLplusplus/afl-fuzz -i #i -o #o -S #n -b #b -m none -t 5000 -- /root/afl/testcase/{testcase}/afl++_ubsan {testcase_args[testcase]}',
    },
    {
        'name': 'MOpt',
        'shell_command': f'/root/afl/fuzzer/MOpt-AFL/MOpt/afl-fuzz -i #i -o #o -S #n -c #b -m none -t 5000+ -- /root/afl/testcase/{testcase}/afl {testcase_args[testcase]}',
    },
    {
        'name': 'MOpt-ASAN',
        'shell_command': f'/root/afl/fuzzer/MOpt-AFL/MOpt/afl-fuzz -i #i -o #o -S #n -c #b -m none -t 5000 -- /root/afl/testcase/{testcase}/afl_asan {testcase_args[testcase]}',
    },
    {
        'name': 'MOpt-UBSAN',
        'shell_command': f'/root/afl/fuzzer/MOpt-AFL/MOpt/afl-fuzz -i #i -o #o -S #n -c #b -m none -t 5000 -- /root/afl/testcase/{testcase}/afl_ubsan {testcase_args[testcase]}',
    },
    {
        'name': 'libFuzzer',
        'shell_command': f'taskset -c #b /root/afl/testcase/{testcase}/libfuzzer -fork=1 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 -verbosity=1 -artifact_prefix=#c #i',
        'runner_type': autofuzz.runner.libfuzzer.LibFuzzer,
    },
    {
        'name': 'libFuzzer-ASAN',
        'shell_command': f'taskset -c #b /root/afl/testcase/{testcase}/libfuzzer_asan -fork=1 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 -verbosity=1 -artifact_prefix=#c #i',
        'runner_type': autofuzz.runner.libfuzzer.LibFuzzer,
    },
    {
        'name': 'libFuzzer-UBSAN',
        'shell_command': f'taskset -c #b /root/afl/testcase/{testcase}/libfuzzer_ubsan -fork=1 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 -verbosity=1 -artifact_prefix=#c #i',
        'runner_type': autofuzz.runner.libfuzzer.LibFuzzer,
    },
]

filename = {
    'AFLplusplus': 'afl++',
    'AFLplusplus-ASAN': 'afl++_asan',
    'AFLplusplus-UBSAN': 'afl++_ubsan',
    'MOpt': 'afl',
    'MOpt-ASAN': 'afl_asan',
    'MOpt-UBSAN': 'afl_ubsan',
    'libFuzzer': 'libfuzzer',
    'libFuzzer-ASAN': 'libfuzzer_asan',
    'libFuzzer-UBSAN': 'libfuzzer_ubsan',
}
methods_info = []
for i in raw_info:
    if os.path.exists(f'/root/afl/testcase/{testcase}/{filename[i["name"]]}'):
        methods_info.append(i)
raw_info = methods_info
try:
    methods_info = [i for i in raw_info if i['name'].lower() == sys.argv[2].lower()]
except IndexError:
    methods_info = []
if methods_info == []:
    methods_info = raw_info
if sys.argv[2].endswith('-NoMOpt'):
    methods_info = [i for i in methods_info if 'MOpt' not in i['name']]

try:
    job_id = sys.argv[3]
except IndexError:
    job_id = 0

runner_thread = 1
analysis_thread = 1

run_it(
    **{
        'runner_thread': runner_thread,
        'analysis_thread': analysis_thread,
        'seed_path': f'/root/afl/input/{testcase}',
        'startup_time': 180,
        'cycle_time': 480,
        'run_round': 0,
        'reference_time': 43200,
        'methods_info': methods_info,
        'cpu_list': [
            psutil.Process().cpu_affinity()[int(sys.argv[4])],
            psutil.Process().cpu_affinity()[int(sys.argv[5])],
        ],
        'crash_analysis_command': {
            'ASAN': f'taskset -c #b /root/afl/testcase/{testcase}/afl_asan {testcase_args[testcase]}',
            'UBSAN': f'taskset -c #b /root/afl/testcase/{testcase}/afl_ubsan {testcase_args[testcase]}',
        },
        'runner_type': autofuzz.runner.afl.AFL,
        'covelf_command': (
            f'taskset -c #b /root/afl/testcase/{testcase}/cov {testcase_args[testcase]}',
            f'/root/afl/testcase/{testcase}/cov',
        ),
        'running_status_csv_path': f'/root/afl/output/csv/{job_id}.csv',
        'progress_recovery_path': f'/root/afl/ramdisk/{job_id}',
        'crashes_output_path': f'/root/afl/output/crashes/{job_id}',
        'llvmprofdata_command': 'llvm-profdata-12',
        'llvmcov_command': 'llvm-cov-12',
        'support_SIGUSR2_sync': bool(int(sys.argv[6])) if len(sys.argv) >= 7 and sys.argv[6] else True,
        'support_SIGUSR2_stats': bool(int(sys.argv[6])) if len(sys.argv) >= 7 and sys.argv[6] else True,
        'round_robin': sys.argv[2].startswith('RoundRobin'),
    }
)
