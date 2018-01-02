from flask import Flask
from schema import Schema, And, Use
import itsdangerous
import os
import yaml


def create_app():
    app = Flask(__name__)

    app.config['CAPTURE_MIME'] = itsdangerous.base64_decode(os.environ.get('CAPTURE_MIME_ENCODED', ''))
    app.config['SECRET_KEY'] = os.urandom(24)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_AUTH_URL_RULE'] = None

    with open("config.yml", 'r') as f:
        config_dict = yaml.safe_load(f)
    config_schema = Schema({
        'HASHCAT_STATUS_TIMER': And(Use(int), lambda x: x > 0),
        'CAPTURES_DIR': Use(str),
        'SQLALCHEMY_DATABASE_URI': And(Use(str), lambda x: len(x) > 0),
    })
    config_schema.validate(config_dict)
    for key, value in config_dict.items():
        app.config[key] = value
    for dir_config_name in ('CAPTURES_DIR',):
        if not os.path.exists(app.config[dir_config_name]):
            os.makedirs(app.config[dir_config_name])
    return app


app = create_app()

from app import views
