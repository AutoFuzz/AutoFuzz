# AutoFuzz Runner

All available fuzzer types:

|   Type    | Applicable objects  |
| :-------: | ------------------- |
|    AFL    | All AFL-like fuzzer |
| LibFuzzer | libFuzzer           |

## How to adapt to other types of fuzzer

All Runners must be subclasses of [`autofuzz.base_runner.BaseRunner`](/autofuzz/base_runner.py). Although `BaseRunner` is an abstract base class, all methods except `__init__` have a default implementation that should be enough out of the box. This means that for the simplest cases, you only need to implement the `__init__` method.

For convenience, it is recommended to call `super().__init__()` in your own `__init__` method to define the basic properties of the Runner.

Main tasks in the `__init__` method include:

1. Set `_seeds_path` and `_crash_path`, and create the corresponding directories.
2. Construct the startup command. You can use the convenient function [`placeholder_replacer()`](/autofuzz/utils/placeholder_replacer.py).
3. Start the fuzzer process and record its PID in `_pid`.
4. Properly handle startup timeouts and failures.

For more details, please refer to the implementation of existing Runners.
