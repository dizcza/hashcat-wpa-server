import secrets
from pathlib import Path

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
HASHCAT_BRAIN_PASSWORD_PATH = APP_DIR / "hashcat_brain_password"


class Config:
    """ Flask application config """

    SECRET_KEY = secrets.token_bytes(64)

    # Flask-SQLAlchemy settings
    SQLALCHEMY_DATABASE_URI = "sqlite:///{}".format(DATABASE_PATH)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Airodump capture files
    CAPTURES_DIR = ROOT_DIR / "captures"
