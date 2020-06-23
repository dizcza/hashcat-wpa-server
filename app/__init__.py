import os
from threading import RLock

from flask import Flask
from flask_bootstrap import Bootstrap
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

from app.config import Config, DATABASE_PATH


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    os.makedirs(app.config['CAPTURES_DIR'], exist_ok=True)
    DATABASE_PATH.parent.mkdir(exist_ok=True)
    return app


app = create_app()
Bootstrap(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
lock_app = RLock()

from app import views
