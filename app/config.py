import os
from pathlib import Path

import itsdangerous

APP_DIR = Path(__file__).parent
ROOT_DIR = APP_DIR.parent
WORDLISTS_DIR = ROOT_DIR / "wordlists"
RULES_DIR = ROOT_DIR / "rules"
MASKS_DIR = ROOT_DIR / "masks"
LOGS_DIR = ROOT_DIR / "logs"

DATABASE_DIR = ROOT_DIR / "database"
ESSID_TRIED = DATABASE_DIR / "essid_tried"
DATABASE_PATH = DATABASE_DIR / "hashcat_wpa.db"

# Hashcat
HASHCAT_STATUS_TIMER = 20  # seconds
BENCHMARK_FILE = APP_DIR / "benchmark.csv"
BENCHMARK_UPDATE_PERIOD = 60  # seconds


class Config:
    """ Flask application config """

    SECRET_KEY = os.urandom(24)

    # Flask-SQLAlchemy settings
    SQLALCHEMY_DATABASE_URI = "sqlite:///{}".format(DATABASE_PATH)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Airodump capture files
    CAPTURES_DIR = ROOT_DIR / "captures"
    CAPTURE_MIME = itsdangerous.base64_decode("1MOyoQIABAAAAAAAAAAAAP//AABpAAAA")
