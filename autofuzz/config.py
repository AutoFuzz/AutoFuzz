# -*- coding: utf-8 -*-

import threading
from queue import Queue

from prometheus_client import Gauge, Enum

from autofuzz.utils.reader_and_writer import ReaderAndWriterIdentity
from autofuzz.utils.time_record import TimeRecord

analysis_queue = Queue()
methods = []
seeds_distribution = ReaderAndWriterIdentity()
wait_needed = ReaderAndWriterIdentity()
exit_prepare = threading.Event()
fuzzer_running = False
cov_history = []

total_timer = TimeRecord()
calculate_timer = TimeRecord()
startup_timer = TimeRecord()
analysis_after_pause_timer = TimeRecord()

TARGET_ROUND = -1
FUZZING_STAGE = 0  # 0: startup, 1: init, 2: normal mode, 3: contious mode, 4: Round-Robin mode
REWARD_STAGE = 0  # 0: cov reward only, 1: cov and crash reward
CPU_INFO = None
CSV_PATH = None
PROGRESS_RECOVERY_PATH = None


class TaskQueueExit(Exception):
    pass


class RunnerStartupFailed(RuntimeError):
    pass


CSV_FIELDNAMES = [
    'Time',
    'Type',
    'Name',
    'RunningTime',
    'Speed',
    'Increase_Valid_Crash',
    'Total_Valid_Crash',
    'New_Seeds',
    'Crash_Reward',
    'Cov_Reward',
    'Weights',
    'Increase_Valid_Crash_Detail',
    'Total_Valid_Crash_Detail',
    'Total_Input_Analyzed_Crash',
    'Duplicate_Crash',
    'Exit_Normally_Crash',
    'Unexpected_Output_Crash',
    'Output_Nothing_Crash',
    'Timeout_Crash',
    'No_Stack_Crash',
    'Increase_Branches_Cover',
    'Total_Branches_Cover',
    'Total_Branches',
    'Increase_Functions_Cover',
    'Total_Functions_Cover',
    'Total_Functions',
    'Increase_Instantiations_Cover',
    'Total_Instantiations_Cover',
    'Total_Instantiations',
    'Increase_Lines_Cover',
    'Total_Lines_Cover',
    'Total_Lines',
    'Increase_Regions_Cover',
    'Total_Regions_Cover',
    'Total_Regions',
    'afl_banner',
    'afl_version',
    'auto_dict_entries',
    'bitmap_cvg',
    'command_line',
    'command_line',
    'corpus_count',
    'corpus_favored',
    'corpus_found',
    'corpus_imported',
    'corpus_variable',
    'cpu_affinity',
    'cur_item',
    'cur_path',
    'cycles_done',
    'cycles_wo_finds',
    'edges_found',
    'exec_timeout',
    'execs_done',
    'execs_per_sec',
    'execs_ps_last_min',
    'execs_since_crash',
    'fuzzer_pid',
    'havoc_expansion',
    'last_crash',
    'last_find',
    'last_hang',
    'last_path',
    'last_update',
    'max_depth',
    'paths_favored',
    'paths_found',
    'paths_imported',
    'paths_total',
    'peak_rss_mb',
    'pending_favs',
    'pending_total',
    'run_time',
    'saved_crashes',
    'saved_hangs',
    'slowest_exec_ms',
    'stability',
    'start_time',
    'target_mode',
    'testcache_count',
    'testcache_evict',
    'testcache_size',
    'total_edges',
    'unique_crashes',
    'unique_hangs',
    'var_byte_count',
    'variable_paths',
]
prometheus_data = {
    'Time': Gauge('Time', 'Current Timestamp'),
    'TotalRunningTime': Gauge('TotalRunningTime', 'Total Running Time'),
    'Current': Gauge('Current', 'Current Running Fuzzer', ['FuzzName']),
    'RunningTime': Gauge('RunningTime', 'Running Time for Each Fuzzer', ['FuzzName']),
    'Speed': Gauge('Speed', 'Current Running Speed'),
    'Valid_Crash': Gauge('Valid_Crash', 'Valid Crashes of Each Fuzzer', ['FuzzName']),
    'Crash_Reward': Gauge('Crash_Reward', 'Crash Reward of Each Fuzzer', ['FuzzName']),
    'Cov_Reward': Gauge('Cov_Reward', 'Coverage Reward of Each Fuzzer', ['FuzzName']),
    'New_Seeds': Gauge('New_Seeds', 'New Seeds Found in Last Round'),
    'Covered_Branches': Gauge('Total_Branches_Cover', 'Total Branches Coverage'),
    'Total_Branches': Gauge('Total_Branches', 'Total Branches'),
}
