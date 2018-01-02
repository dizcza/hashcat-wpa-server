import logging
import os
import time


def create_logger(logging_level=logging.DEBUG, logs_dir="logs"):
    new_logger = logging.getLogger(__name__)
    new_logger.setLevel(logging_level)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s - %(funcName)s - %(message)s')

    if not os.getenv('PRODUCTION', False):
        # local mode: write to console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging_level)
        console_handler.setFormatter(formatter)
        new_logger.addHandler(console_handler)

    log_path = os.path.join(logs_dir, time.strftime('%Y-%b-%d.log'))
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(logging_level)
    file_handler.setFormatter(formatter)
    new_logger.addHandler(file_handler)

    new_logger.info("Initialized logger")

    return new_logger


logger = create_logger()
