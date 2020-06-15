import logging
import os
import time

from app.config import LOGS_DIR


def create_logger(logging_level=logging.DEBUG):
    LOGS_DIR.mkdir(exist_ok=True)
    new_logger = logging.getLogger(__name__)
    new_logger.setLevel(logging_level)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s - %(funcName)s - %(message)s')

    if int(os.getenv('LOG_CONSOLE', 0)):
        # local mode: write to console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging_level)
        console_handler.setFormatter(formatter)
        new_logger.addHandler(console_handler)

    log_path = LOGS_DIR / time.strftime('%Y-%b-%d.log')
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(logging_level)
    file_handler.setFormatter(formatter)
    new_logger.addHandler(file_handler)

    new_logger.info("Initialized logger")

    return new_logger


logger = create_logger()
