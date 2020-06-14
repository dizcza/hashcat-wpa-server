import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from threading import RLock
from flask_migrate import Migrate
from app.config import Config, DATABASE_PATH


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    os.makedirs(app.config['CAPTURES_DIR'], exist_ok=True)
    DATABASE_PATH.parent.mkdir(exist_ok=True)
    return app


app = create_app()
# uncomment if you see the error that a task is not bounded to a session
# db = SQLAlchemy(app, session_options=dict(expire_on_commit=False))
db = SQLAlchemy(app)
migrate = Migrate(app, db)
lock_app = RLock()

from app import views
