import os
import itsdangerous


APP_DIR = os.path.dirname(__file__)
ROOT_DIR = os.path.dirname(APP_DIR)
WORDLISTS_DIR = os.path.join(ROOT_DIR, "wordlists")
RULES_DIR = os.path.join(ROOT_DIR, "rules")


class Config:
    """ Flask application config """

    SECRET_KEY = os.urandom(24)

    # Flask-SQLAlchemy settings
    SQLALCHEMY_DATABASE_URI = "sqlite:///{}".format(os.path.join(APP_DIR, "users.db"))
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Airodump capture files
    CAPTURES_DIR = os.path.join(ROOT_DIR, "captures")
    CAPTURE_MIME = itsdangerous.base64_decode("1MOyoQIABAAAAAAAAAAAAP//AABpAAAA")

    # Hashcat
    HASHCAT_STATUS_TIMER = 20
    BENCHMARK_FILE = os.path.join(APP_DIR, "benchmark.csv")
    BENCHMARK_UPDATE_PERIOD = 60
