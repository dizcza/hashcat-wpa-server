import os
from pathlib import Path

from app.app_logger import logger
from app.domain import InvalidFileError
from app.utils import subprocess_call, check_file_22000, calculate_md5


def convert_to_22000(capture_path):
    """
    Convert airodump `.cap` to hashcat `.22000`
    """
    file_22000 = Path(capture_path).with_suffix(".22000")

    def convert_and_verify(cmd, path_verify=file_22000):
        subprocess_call(cmd)
        if not Path(path_verify).exists():
            raise FileNotFoundError(f"{cmd[0]} failed")

    if capture_path.suffix == ".pcapng":
        convert_and_verify(['hcxpcapngtool', '-o', str(file_22000),
                            str(capture_path)])
        capture_path = file_22000
    elif capture_path.suffix in (".cap", ".pcap"):
        hccapx_file = capture_path.with_suffix(".hccapx")
        convert_and_verify(['cap2hccapx', str(capture_path), str(hccapx_file)], path_verify=hccapx_file)
        capture_path = hccapx_file

    # TODO: add support for 22001 (2501, 16801) modes
    if capture_path.suffix in (".hccapx", ".2500"):
        convert_and_verify(['hcxmactool', f'--hccapxin={capture_path}', f'--pmkideapolout={file_22000}'])
    elif capture_path.suffix in (".pmkid", ".16800"):
        convert_and_verify(['hcxmactool', f'--pmkidin={capture_path}', f'--pmkideapolout={file_22000}'])
    elif capture_path.suffix != ".22000":
        raise InvalidFileError(f"Invalid file suffix: '{capture_path.suffix}'")

    return file_22000


def split_by_essid(file_22000, to_folder=None):
    file_22000 = Path(file_22000)
    check_file_22000(file_22000)
    if to_folder is None:
        checksum = calculate_md5(file_22000)
        to_folder = Path(f"{file_22000.with_suffix('')}_{checksum}")
        if to_folder.exists():
            # should never happen
            logger.warning(f"{to_folder} already exists")
    to_folder.mkdir(exist_ok=True)

    curdir = os.getcwd()
    os.chdir(to_folder)
    subprocess_call(['hcxhashtool', '-i', file_22000, '--essid-group'])
    os.chdir(curdir)

    return to_folder
