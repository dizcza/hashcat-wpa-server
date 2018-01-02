# encoding=utf-8

import subprocess

from app.domain import Rule, WordList


def convert_ms_to_human_readable(seconds: float) -> str:
    minutes = int(seconds / 60)
    minutes = min(minutes, 1)
    hours = int(minutes / 60)
    days = int(hours / 24)
    hours %= 24
    minutes %= 60
    return "{:d} days {:d} hours {:d} minutes".format(days, hours, minutes)


def count_rules(rule: Rule) -> int:
    with open(rule.get_path()) as f:
        rules = f.readlines()
    rules = [line[:-1] for line in rules]
    rules = filter(len, rules)
    rules = filter(lambda line: not line.startswith("#"), rules)
    return len(list(rules))


def count_words(wordlist: WordList) -> int:
    out, err_ignored = subprocess.Popen(["wc", "-l", wordlist.get_path()],
                                        universal_newlines=True,
                                        stdout=subprocess.PIPE).communicate()
    count = int(out.split(' ')[0])
    return count
