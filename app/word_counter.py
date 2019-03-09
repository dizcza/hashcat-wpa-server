import re

from app.domain import WordList, Rule
from app.utils import subprocess_call
from digits.common import read_mask


class WordCounter(object):

    def __init__(self):
        self.wordlists = {}
        self.rules = {}
        self.masks = {}
        for wordlist in WordList:
            out, err = subprocess_call(['wc', '-l', str(wordlist.path)])
            out = out.rstrip('\n')
            if re.fullmatch(f"\d+ {wordlist.path}", out):
                counter, path = out.split(' ')
                self.wordlists[wordlist] = int(counter)
        for rule in Rule:
            rules_list = read_mask(rule.path)
            self.rules[rule] = len(rules_list)


if __name__ == '__main__':
    WordCounter()
