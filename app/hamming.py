import string
from collections import Counter
from itertools import chain, combinations, product
from typing import Union, List


def hamming_circle(s: str, n: int, alphabet: Union[str, List[str]]):
    """Generate strings over alphabet whose Hamming distance from s is
    exactly n.
    """
    for positions in combinations(range(len(s) - 1, -1, -1), n):
        for replacements in product(range(len(alphabet) - 1), repeat=n):
            cousin = list(s)
            cousin_insert = list(s)
            cousin_delete = list(s)
            for p, r in zip(positions, replacements):
                cousin_insert.insert(p, alphabet[r])
                cousin_delete[p] = ''
                if cousin[p] == alphabet[r]:
                    cousin[p] = alphabet[-1]
                else:
                    cousin[p] = alphabet[r]
            yield ''.join(cousin)
            yield ''.join(cousin_insert)
            yield ''.join(cousin_delete)


def hamming_ball(s: str, n: int, alphabet: Union[str, List[str]] = string.digits + string.ascii_letters):
    """Generate strings over alphabet whose Hamming distance from s is
    less than or equal to n.
    """
    return chain.from_iterable(hamming_circle(s, i, alphabet)
                               for i in range(n + 1))


if __name__ == '__main__':
    res = hamming_ball('Spartansky', n=2)
    res = list(set(res))
    print(Counter(map(len, res)))
    print(f"Total: {len(res)}")
    print(res[:100])
