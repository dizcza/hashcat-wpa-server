import os

import itsdangerous
from flask import Flask
from flask_sqlalchemy import SQLAlchemy


def create_app():
    app = Flask(__name__)

    app_dir = os.path.dirname(__file__)
    root_dir = os.path.dirname(app_dir)

    app.config['CAPTURES_DIR'] = os.path.join(root_dir, 'captures')
    app.config['CAPTURE_MIME'] = itsdangerous.base64_decode("1MOyoQIABAAAAAAAAAAAAP//AABpAAAA")
    app.config['SECRET_KEY'] = os.urandom(24)
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///{}".format(os.path.join(app_dir, 'users.db'))
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['HASHCAT_STATUS_TIMER'] = 20

    os.makedirs(app.config['CAPTURES_DIR'], exist_ok=True)
    return app


app = create_app()
db = SQLAlchemy(app)

from app import views
