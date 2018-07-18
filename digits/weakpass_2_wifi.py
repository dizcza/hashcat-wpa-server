import os
import re
from pathlib import Path

from tqdm import tqdm


def extend_years():
    unique_path = Path(__file__).parent.parent / 'wordlists' / 'weakpass_2_wifi' / 'aYEARa.unique'
    extended_path = unique_path.with_name('aYEARa.extended')
    if extended_path.exists():
        os.remove(extended_path)
    with open(unique_path) as f:
        data = f.readlines()
    pattern = re.compile('\d+')
    range_years = list(map(str, range(2008, 2019)))
    for line in tqdm(data, desc="Extending years"):
        year_old = pattern.search(line).group()
        lines_extended = [line.replace(year_old, year) for year in range_years]
        if line not in lines_extended:
            lines_extended.append(line)
        with open(extended_path, 'a') as f:
            f.writelines(lines_extended)


if __name__ == '__main__':
    extend_years()
