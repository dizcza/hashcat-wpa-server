import argparse
from pathlib import Path
from typing import Union

from tqdm import trange

from app.attack.base_attack import BaseAttack
from app.config import WORDLISTS_DIR

HCCAPX_BYTES = 393


class HccapxAttack(BaseAttack):

    def __init__(self, hcap_file: Union[str, Path]):
        super().__init__(hcap_file)
        self.hcap_split_dir = Path(WORDLISTS_DIR) / 'split'
        self.hcap_split_dir.mkdir(parents=True, exist_ok=True)

    def run_essid_attack(self):
        """
        Run ESSID + digits_append.txt combinator attack.
        Run ESSID + best64.rule attack.
        """
        with open(self.hcap_file, 'rb') as f:
            data = f.read()
        n_captures = len(data) // HCCAPX_BYTES
        assert n_captures * HCCAPX_BYTES == len(data), "Invalid .hccapx file"
        for capture_id in trange(n_captures, desc="ESSID attack"):
            capture = data[capture_id * HCCAPX_BYTES: (capture_id + 1) * HCCAPX_BYTES]
            essid_len = capture[9]
            try:
                essid_unique = capture[10: 10 + essid_len].decode('ascii')
            except UnicodeDecodeError:
                # skip non-ascii ESSIDs
                continue
            print(f"ESSID {essid_unique}")
            hcap_fpath_essid = self.hcap_split_dir.joinpath(essid_unique + '.hccapx')
            with open(hcap_fpath_essid, 'wb') as f:
                f.write(capture)
            self.write_essid_wordlist(essid_unique)
            self._run_essid_digits(hcap_fpath_essid)
            self._run_essid_rule(hcap_fpath_essid)


def crack_hccapx():
    """
    Check weak passwords in command line.
    """
    parser = argparse.ArgumentParser(description='Check weak passwords')
    parser.add_argument('hccapx', help='path to .hccapx')
    args = parser.parse_args()
    attack = HccapxAttack(hcap_file=args.hccapx)
    attack.run_essid_attack()
    attack.run_top4k()
    attack.run_top304k()
    attack.run_digits8()


if __name__ == '__main__':
    crack_hccapx()
