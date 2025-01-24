# -*- coding: utf-8 -*-


def placeholder_replacer(string, replace_list, *, start_char='#'):
    command = ''
    replace_list[start_char] = start_char
    for c in (it := iter(string)):
        if c != start_char:
            command += c
        elif (next_c := next(it)) in replace_list and (replace_list[next_c] is not None):
            command += str(replace_list[next_c])
        else:
            command += f'{start_char}{next_c}'
    return command
