# encoding=utf-8

import subprocess

from app.domain import Rule, WordList


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


def split_uppercase(word: str) -> set:
    pos_upper = [pos for pos, letter in enumerate(word) if letter.isupper()]
    pos_upper.append(len(word))
    simple_words = set([])
    for left, right in zip(pos_upper[:-1], pos_upper[1:]):
        simple_words.add(word[left: right])
    return simple_words
