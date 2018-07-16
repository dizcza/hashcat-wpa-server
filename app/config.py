import os
import itsdangerous


APP_DIR = os.path.dirname(__file__)
ROOT_DIR = os.path.dirname(APP_DIR)
WORDLISTS_DIR = os.path.join(ROOT_DIR, "wordlists")
RULES_DIR = os.path.join(ROOT_DIR, "rules")
DATABASE_PATH = os.path.join(ROOT_DIR, "database", "hashcat_wpa.db")

# Hashcat
HASHCAT_STATUS_TIMER = 20  # seconds
BENCHMARK_FILE = os.path.join(APP_DIR, "benchmark.csv")
BENCHMARK_UPDATE_PERIOD = 60  # seconds


class Config:
    """ Flask application config """

    SECRET_KEY = os.urandom(24)

    # Flask-SQLAlchemy settings
    SQLALCHEMY_DATABASE_URI = "sqlite:///{}".format(DATABASE_PATH)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Airodump capture files
    CAPTURES_DIR = os.path.join(ROOT_DIR, "captures")
    CAPTURE_MIME = itsdangerous.base64_decode("1MOyoQIABAAAAAAAAAAAAP//AABpAAAA")
