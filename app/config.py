import secrets
from pathlib import Path

HASHCAT_WPA_CACHE_DIR = Path.home() / ".hashcat" / "wpa-server"
ROOT_PRIVATE_DIR = Path(__file__).parent.parent

WORDLISTS_DIR = ROOT_PRIVATE_DIR / "wordlists"
WORDLISTS_USER_DIR = HASHCAT_WPA_CACHE_DIR / "wordlists"  # user custom wordlists
RULES_DIR = HASHCAT_WPA_CACHE_DIR / "rules"
MASKS_DIR = ROOT_PRIVATE_DIR / "masks"
LOGS_DIR = HASHCAT_WPA_CACHE_DIR / "logs"

DATABASE_DIR = HASHCAT_WPA_CACHE_DIR / "database"
ESSID_TRIED = DATABASE_DIR / "essid_tried"
DATABASE_PATH = DATABASE_DIR / "hashcat_wpa.db"

# Hashcat
HASHCAT_STATUS_TIMER = 20  # seconds
BENCHMARK_FILE = HASHCAT_WPA_CACHE_DIR / "benchmark.csv"
HASHCAT_BRAIN_PASSWORD_PATH = HASHCAT_WPA_CACHE_DIR / "brain" / "hashcat_brain_password"

# mkdirs
HASHCAT_WPA_CACHE_DIR.mkdir(exist_ok=True)
WORDLISTS_USER_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
DATABASE_DIR.mkdir(exist_ok=True)
HASHCAT_BRAIN_PASSWORD_PATH.parent.mkdir(exist_ok=True)

class Config:
    """ Flask application config """

    SECRET_KEY = secrets.token_bytes(64)

    # Flask-SQLAlchemy settings
    SQLALCHEMY_DATABASE_URI = "sqlite:///{}".format(DATABASE_PATH)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Airodump capture files
    CAPTURES_DIR = HASHCAT_WPA_CACHE_DIR / "captures"
